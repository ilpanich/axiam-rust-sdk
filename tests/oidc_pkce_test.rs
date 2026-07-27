//! `oidc_begin` (CONTRACT.md §12.1) through the public API: PKCE/S256-only,
//! `state`/`nonce` entropy and uniqueness, and the exact eight-parameter
//! authorization URL. No network I/O — `oidc_begin` is pure.

#![cfg(feature = "rest")]

#[path = "oidc_support/mod.rs"]
mod oidc_support;

use axiam_sdk::client::AxiamClient;
use axiam_sdk::oidc::{OidcBeginParams, OidcConfiguration};
use std::collections::HashSet;

fn configuration() -> OidcConfiguration {
    serde_json::from_value(oidc_support::discovery_document("https://axiam-oidc.test"))
        .expect("valid configuration")
}

fn client() -> AxiamClient {
    AxiamClient::builder()
        .base_url("https://axiam-oidc.test")
        .expect("valid base url")
        .tenant_id(oidc_support::tenant_id())
        .oidc_client_id(oidc_support::CLIENT_ID)
        .build()
        .expect("client builds")
}

#[test]
fn builds_the_authorization_url_from_exactly_the_eight_mandated_parameters() {
    let client = client();
    let request = client
        .oidc_begin(
            &configuration(),
            OidcBeginParams::new(oidc_support::REDIRECT_URI),
        )
        .expect("oidc_begin succeeds");

    let url = url::Url::parse(&request.url).expect("valid url");
    assert_eq!(
        url.origin().unicode_serialization(),
        "https://axiam-oidc.test"
    );
    assert_eq!(url.path(), "/oauth2/authorize");

    let pairs: std::collections::HashMap<_, _> = url.query_pairs().into_owned().collect();
    assert_eq!(pairs.get("response_type").unwrap(), "code");
    assert_eq!(pairs.get("client_id").unwrap(), oidc_support::CLIENT_ID);
    assert_eq!(
        pairs.get("redirect_uri").unwrap(),
        oidc_support::REDIRECT_URI
    );
    assert_eq!(pairs.get("scope").unwrap(), "openid");
    assert_eq!(pairs.get("state").unwrap(), &request.state);
    assert_eq!(pairs.get("nonce").unwrap(), &request.nonce);
    assert_eq!(pairs.get("code_challenge_method").unwrap(), "S256");
    assert!(pairs.contains_key("code_challenge"));
    // Exactly eight parameters — S256-only, never `plain`, nothing extra.
    assert_eq!(pairs.len(), 8);
    assert_ne!(pairs.get("code_challenge_method").unwrap(), "plain");
}

#[test]
fn adds_openid_scope_automatically_when_omitted_and_preserves_caller_scope() {
    let client = client();
    let request = client
        .oidc_begin(
            &configuration(),
            OidcBeginParams::new(oidc_support::REDIRECT_URI).with_scope("profile email"),
        )
        .expect("oidc_begin succeeds");
    let url = url::Url::parse(&request.url).unwrap();
    let scope = url
        .query_pairs()
        .find(|(k, _)| k == "scope")
        .map(|(_, v)| v.into_owned())
        .unwrap();
    assert_eq!(scope, "openid profile email");
}

#[test]
fn extra_params_are_added_to_the_authorization_url() {
    let client = client();
    let ok = client.oidc_begin(
        &configuration(),
        OidcBeginParams::new(oidc_support::REDIRECT_URI).with_extra_param("prompt", "login"),
    );
    assert!(ok.is_ok());
    let url = url::Url::parse(&ok.unwrap().url).unwrap();
    assert!(
        url.query_pairs()
            .any(|(k, v)| k == "prompt" && v == "login")
    );
}

/// CONTRACT.md §12.1 rule 5 / addendum judgment call 9: trying to override one
/// of the eight SDK-owned parameters is a **programming error**, not a §2
/// taxonomy outcome, so it panics rather than returning `Err` — matching the
/// `IllegalArgumentException`/`ValueError`/`ArgumentException` the sibling SDKs
/// raise. (A missing/unresolvable *tenant*, by contrast, stays an
/// `AxiamError::Auth`; see `sso_start_requires_organization_context_client_side`
/// in `tests/oidc_sso_test.rs`.)
#[test]
#[should_panic(expected = "extra_params may not override the SDK-owned authorization parameter")]
fn overriding_an_sdk_owned_parameter_is_a_programming_error() {
    let client = client();
    let _ = client.oidc_begin(
        &configuration(),
        OidcBeginParams::new(oidc_support::REDIRECT_URI)
            .with_extra_param("client_id", "someone-else"),
    );
}

/// CONTRACT.md §12.1 rule 5: the eight parameters are **RFC 3986**
/// percent-encoded. A multi-valued `scope` must therefore read
/// `openid%20profile%20email` in the raw URL — not the
/// `application/x-www-form-urlencoded` `openid+profile+email` that
/// `url::Url::query_pairs_mut` produces by default, which is what every other
/// AXIAM SDK emits and what the server's own `?` decoding treats as canonical.
///
/// Asserted against the **raw** URL string on purpose: reading the value back
/// through `query_pairs()` decodes `+` to a space and so passes either way.
#[test]
fn spaces_in_query_values_are_percent_encoded_as_20_and_never_as_plus() {
    let client = client();
    let request = client
        .oidc_begin(
            &configuration(),
            OidcBeginParams::new("https://app.example.com/auth/cb?next=/a b")
                .with_scope("profile email offline_access")
                .with_extra_param("prompt", "consent select_account"),
        )
        .expect("oidc_begin succeeds");

    let raw = &request.url;
    assert!(
        raw.contains("scope=openid%20profile%20email%20offline_access"),
        "scope must be %20-joined: {raw}"
    );
    assert!(
        raw.contains("prompt=consent%20select_account"),
        "caller-supplied extra params are encoded the same way: {raw}"
    );
    assert!(
        !raw.contains('+'),
        "no '+' may appear anywhere in the authorization URL: {raw}"
    );
    assert!(
        !raw.contains("%2520"),
        "the percent signs must not be double-encoded: {raw}"
    );

    // Round-trips: the decoded values are exactly what was asked for.
    let url = url::Url::parse(raw).expect("valid url");
    let pairs: std::collections::HashMap<String, String> = url
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    assert_eq!(
        pairs.get("scope").unwrap(),
        "openid profile email offline_access"
    );
    assert_eq!(
        pairs.get("redirect_uri").unwrap(),
        "https://app.example.com/auth/cb?next=/a b"
    );
}

#[test]
fn state_nonce_and_code_verifier_are_at_least_128_bits_and_unique_across_calls() {
    let client = client();
    let mut states = HashSet::new();
    let mut nonces = HashSet::new();
    let mut verifiers = HashSet::new();

    for _ in 0..20 {
        let request = client
            .oidc_begin(
                &configuration(),
                OidcBeginParams::new(oidc_support::REDIRECT_URI),
            )
            .expect("oidc_begin succeeds");
        // base64url (no padding) of >= 16 bytes is >= 22 chars; this SDK
        // uses 32 bytes (43 chars) for all three values.
        assert!(request.state.len() >= 22);
        assert!(request.nonce.len() >= 22);
        assert!(request.code_verifier.expose().len() >= 43);
        assert!(!request.state.contains('='));
        assert!(!request.nonce.contains('='));

        assert!(
            states.insert(request.state),
            "state must be unique across calls"
        );
        assert!(
            nonces.insert(request.nonce),
            "nonce must be unique across calls"
        );
        assert!(
            verifiers.insert(request.code_verifier.expose().clone()),
            "code_verifier must be unique across calls"
        );
    }
}

#[test]
fn oidc_begin_performs_no_network_io() {
    // A base URL that nothing is listening on: if `oidc_begin` made a wire
    // call, this would hang or error. It must return synchronously and
    // successfully purely from the supplied `configuration`.
    let client = AxiamClient::builder()
        .base_url("https://127.0.0.1:1")
        .expect("valid base url")
        .tenant_id(oidc_support::tenant_id())
        .oidc_client_id(oidc_support::CLIENT_ID)
        .build()
        .expect("client builds");

    let request = client
        .oidc_begin(
            &configuration(),
            OidcBeginParams::new(oidc_support::REDIRECT_URI),
        )
        .expect("oidc_begin must succeed without ever touching the network");
    assert!(request.url.starts_with("https://axiam-oidc.test"));
}
