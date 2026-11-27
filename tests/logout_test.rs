//! RP-initiated and back-channel logout — CONTRACT.md §12.7.
//!
//! The §12.7.6 required tests. The `verify_logout_token` half carries the
//! security weight: its input arrives unsolicited, from the network, and
//! instructs the RP to terminate a session — so each rejection test names
//! the attack it prevents rather than merely asserting an error.

#![cfg(feature = "rest")]

#[path = "oidc_support/mod.rs"]
mod oidc_support;

use axiam_sdk::AxiamError;
use axiam_sdk::IdTokenFailureReason;
use axiam_sdk::Sensitive;
use axiam_sdk::oidc::{LogoutUrlParams, OidcConfiguration};
use axiam_sdk::token::JwksVerifier;
use std::collections::HashMap;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use oidc_support::{
    CLIENT_ID, ISSUER, IdTokenOptions, LOGOUT_JTI, LOGOUT_SID, LogoutTokenOptions, build_client,
    discovery_document, discovery_document_without_optional_endpoints, generate_signing_key,
    jwks_body, sign_id_token, sign_logout_token,
};

const ID_TOKEN: &str = "the-users-id-token";

fn query_of(url: &str) -> HashMap<String, String> {
    url::Url::parse(url)
        .expect("valid url")
        .query_pairs()
        .into_owned()
        .collect()
}

async fn configuration(server: &MockServer) -> OidcConfiguration {
    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(200).set_body_json(discovery_document(&server.uri())))
        .mount(server)
        .await;
    build_client(&server.uri(), false)
        .oidc_discover()
        .await
        .expect("discovery")
}

// ---------------------------------------------------------------------------
// §12.7.2 logout_url
// ---------------------------------------------------------------------------

#[tokio::test]
async fn logout_url_uses_the_discovered_endpoint_not_concatenation() {
    let server = MockServer::start().await;
    let configuration = configuration(&server).await;
    let client = build_client(&server.uri(), false);

    let url = client
        .logout_url(
            &configuration,
            LogoutUrlParams::new(Sensitive::new(ID_TOKEN.into())),
        )
        .expect("logout_url");

    // §12.7.2 rule 1. The fixture's issuer (https://iam.example.com) is
    // deliberately a DIFFERENT origin from the mock server, so a naive
    // `{issuer}/oauth2/end_session` would point at the wrong host — which is
    // exactly how concatenation breaks against a non-AXIAM OP.
    assert!(
        url.starts_with(&server.uri()),
        "the endpoint comes from discovery, not from the issuer: {url}"
    );
    assert!(!url.starts_with(ISSUER));
    assert!(url.contains("/oauth2/end_session"));
}

#[tokio::test]
async fn logout_url_carries_the_hint_and_omits_what_was_not_supplied() {
    let server = MockServer::start().await;
    let configuration = configuration(&server).await;
    let client = build_client(&server.uri(), false);

    let bare = client
        .logout_url(
            &configuration,
            LogoutUrlParams::new(Sensitive::new(ID_TOKEN.into())),
        )
        .expect("logout_url");
    let q = query_of(&bare);
    assert_eq!(q.get("id_token_hint").map(String::as_str), Some(ID_TOKEN));
    assert!(!q.contains_key("post_logout_redirect_uri"));
    assert!(!q.contains_key("state"));

    let full = client
        .logout_url(
            &configuration,
            LogoutUrlParams {
                id_token: Sensitive::new(ID_TOKEN.into()),
                post_logout_redirect_uri: Some("https://app.example.com/bye".into()),
                state: Some("caller-generated-state".into()),
            },
        )
        .expect("logout_url");
    let q = query_of(&full);
    assert_eq!(
        q.get("post_logout_redirect_uri").map(String::as_str),
        Some("https://app.example.com/bye")
    );
    assert_eq!(
        q.get("state").map(String::as_str),
        Some("caller-generated-state"),
        "§12.7.2 rule 2: state is passed through unmodified — the SDK never \
         invents one, because the value only means something to the caller"
    );
}

#[tokio::test]
async fn logout_url_does_not_prevalidate_the_redirect_against_a_local_list() {
    let server = MockServer::start().await;
    let configuration = configuration(&server).await;
    let client = build_client(&server.uri(), false);

    // §12.7.2 rule 3: the allow-list lives in the client's server-side
    // registration. A client-side copy would drift and reject a URI an
    // operator had just registered — so an arbitrary URI must pass through.
    let url = client
        .logout_url(
            &configuration,
            LogoutUrlParams {
                id_token: Sensitive::new(ID_TOKEN.into()),
                post_logout_redirect_uri: Some("https://somewhere-else.example/x".into()),
                state: None,
            },
        )
        .expect("the SDK does not second-guess the server's allow-list");

    assert_eq!(
        query_of(&url)
            .get("post_logout_redirect_uri")
            .map(String::as_str),
        Some("https://somewhere-else.example/x")
    );
}

#[tokio::test]
async fn logout_url_errors_when_the_server_advertises_no_end_session_endpoint() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(discovery_document_without_optional_endpoints(&server.uri())),
        )
        .mount(&server)
        .await;
    let client = build_client(&server.uri(), false);
    let configuration = client.oidc_discover().await.expect("discovery");

    let err = client
        .logout_url(
            &configuration,
            LogoutUrlParams::new(Sensitive::new(ID_TOKEN.into())),
        )
        .expect_err("no endpoint means no RP-initiated logout");

    assert!(matches!(err, AxiamError::Auth { .. }));
    assert!(
        err.to_string().contains("end_session_endpoint"),
        "the error names the missing endpoint rather than guessing a URL: {err}"
    );
}

// ---------------------------------------------------------------------------
// §12.7.3 verify_logout_token
// ---------------------------------------------------------------------------

/// Mount discovery + a JWKS publishing `key`, and return the configuration.
async fn logout_fixture(server: &MockServer, published_kid: &str) -> OidcConfiguration {
    let key = generate_signing_key(published_kid);
    Mock::given(method("GET"))
        .and(path("/oauth2/jwks"))
        .respond_with(ResponseTemplate::new(200).set_body_json(jwks_body(&[&key])))
        .mount(server)
        .await;
    configuration(server).await
}

#[tokio::test]
async fn a_valid_logout_token_verifies_and_surfaces_sid_sub_and_jti() {
    let server = MockServer::start().await;
    let configuration = logout_fixture(&server, "logout-key").await;
    let key = generate_signing_key("logout-key");
    let token = sign_logout_token(&key, LogoutTokenOptions::default());

    let client = build_client(&server.uri(), false);
    let verified = client
        .verify_logout_token(&token, &configuration)
        .await
        .expect("valid logout token");

    // §12.7.3: not a bare boolean. The RP has to know WHICH session to end,
    // and a verifier that only says "valid" forces the caller to re-parse the
    // token themselves with none of these checks.
    assert_eq!(verified.sid.as_deref(), Some(LOGOUT_SID));
    assert_eq!(verified.sub.as_deref(), Some("user-1"));
    assert_eq!(verified.jti, LOGOUT_JTI);
}

#[tokio::test]
async fn an_id_token_replayed_as_a_logout_token_is_rejected() {
    // The attack §12.7.3 rules 3 and 4 exist to stop, asserted with a real,
    // otherwise-valid ID token rather than a synthetic mutation: it is
    // correctly signed by a published key, names the right issuer and
    // audience, and is unexpired. Only the missing `events` member and the
    // present `nonce` distinguish it from a logout instruction.
    let server = MockServer::start().await;
    let configuration = logout_fixture(&server, "logout-key").await;
    let key = generate_signing_key("logout-key");
    let id_token = sign_id_token(&key, IdTokenOptions::default());

    let client = build_client(&server.uri(), false);
    let err = client
        .verify_logout_token(&id_token, &configuration)
        .await
        .expect_err("an ID token is not a logout token");

    assert!(matches!(err, AxiamError::Auth { .. }));
}

#[tokio::test]
async fn a_token_without_the_events_member_is_rejected() {
    let server = MockServer::start().await;
    let configuration = logout_fixture(&server, "logout-key").await;
    let key = generate_signing_key("logout-key");
    let token = sign_logout_token(
        &key,
        LogoutTokenOptions {
            omit_events: true,
            ..Default::default()
        },
    );

    let client = build_client(&server.uri(), false);
    let err = client
        .verify_logout_token(&token, &configuration)
        .await
        .expect_err("events is what makes it a logout token");
    assert!(err.to_string().contains("events"));
}

#[tokio::test]
async fn a_token_carrying_some_other_event_is_rejected() {
    let server = MockServer::start().await;
    let configuration = logout_fixture(&server, "logout-key").await;
    let key = generate_signing_key("logout-key");
    let token = sign_logout_token(
        &key,
        LogoutTokenOptions {
            wrong_event: true,
            ..Default::default()
        },
    );

    let client = build_client(&server.uri(), false);
    client
        .verify_logout_token(&token, &configuration)
        .await
        .expect_err("the events map must carry the back-channel-logout key specifically");
}

#[tokio::test]
async fn a_nonce_is_rejected_not_ignored() {
    let server = MockServer::start().await;
    let configuration = logout_fixture(&server, "logout-key").await;
    let key = generate_signing_key("logout-key");
    let token = sign_logout_token(
        &key,
        LogoutTokenOptions {
            nonce: Some("n-0S6_WzA2Mj"),
            ..Default::default()
        },
    );

    let client = build_client(&server.uri(), false);
    let err = client
        .verify_logout_token(&token, &configuration)
        .await
        .expect_err("Back-Channel Logout 1.0 §2.4 forbids nonce");
    assert!(err.to_string().contains("nonce"));
}

#[tokio::test]
async fn a_token_naming_neither_sid_nor_sub_is_rejected() {
    let server = MockServer::start().await;
    let configuration = logout_fixture(&server, "logout-key").await;
    let key = generate_signing_key("logout-key");
    let token = sign_logout_token(
        &key,
        LogoutTokenOptions {
            sid: Some(None),
            omit_sub: true,
            ..Default::default()
        },
    );

    let client = build_client(&server.uri(), false);
    client
        .verify_logout_token(&token, &configuration)
        .await
        .expect_err("a token naming neither identifies nothing");
}

#[tokio::test]
async fn sub_only_is_accepted_but_sid_is_preferred_when_present() {
    let server = MockServer::start().await;
    let configuration = logout_fixture(&server, "logout-key").await;
    let key = generate_signing_key("logout-key");

    let client = build_client(&server.uri(), false);

    let sub_only = sign_logout_token(
        &key,
        LogoutTokenOptions {
            sid: Some(None),
            ..Default::default()
        },
    );
    let verified = client
        .verify_logout_token(&sub_only, &configuration)
        .await
        .expect("sub alone still identifies something");
    assert!(verified.sid.is_none());
    assert_eq!(verified.sub.as_deref(), Some("user-1"));

    // With `sid` present the RP must end THAT session only — falling back to
    // "every session for sub" is over-reach the server itself refuses.
    let both = sign_logout_token(&key, LogoutTokenOptions::default());
    let verified = client
        .verify_logout_token(&both, &configuration)
        .await
        .expect("valid");
    assert_eq!(verified.sid.as_deref(), Some(LOGOUT_SID));
}

#[tokio::test]
async fn a_token_for_another_client_is_rejected() {
    let server = MockServer::start().await;
    let configuration = logout_fixture(&server, "logout-key").await;
    let key = generate_signing_key("logout-key");
    let token = sign_logout_token(
        &key,
        LogoutTokenOptions {
            audience: Some("some-other-rp"),
            ..Default::default()
        },
    );

    let client = build_client(&server.uri(), false);
    let err = client
        .verify_logout_token(&token, &configuration)
        .await
        .expect_err("aud names one client");
    assert!(err.to_string().contains("audience"));
    assert_ne!(CLIENT_ID, "some-other-rp");
}

#[tokio::test]
async fn a_token_from_another_issuer_is_rejected() {
    let server = MockServer::start().await;
    let configuration = logout_fixture(&server, "logout-key").await;
    let key = generate_signing_key("logout-key");
    let token = sign_logout_token(
        &key,
        LogoutTokenOptions {
            issuer: Some("https://evil.example.com"),
            ..Default::default()
        },
    );

    let client = build_client(&server.uri(), false);
    let err = client
        .verify_logout_token(&token, &configuration)
        .await
        .expect_err("issuer mismatch");
    assert!(err.to_string().contains("issuer"));
}

#[tokio::test]
async fn a_token_signed_by_an_unpublished_key_is_rejected() {
    let server = MockServer::start().await;
    let configuration = logout_fixture(&server, "logout-key").await;
    // Signed by a key the JWKS never published.
    let rogue = generate_signing_key("rogue-key");
    let token = sign_logout_token(&rogue, LogoutTokenOptions::default());

    let client = build_client(&server.uri(), false);
    client
        .verify_logout_token(&token, &configuration)
        .await
        .expect_err("the signature is what makes the token a statement");
}

#[tokio::test]
async fn an_expired_token_is_rejected() {
    let server = MockServer::start().await;
    let configuration = logout_fixture(&server, "logout-key").await;
    let key = generate_signing_key("logout-key");
    let token = sign_logout_token(
        &key,
        LogoutTokenOptions {
            expires_in_sec: Some(-600),
            issued_at_sec: Some(0),
            ..Default::default()
        },
    );

    let client = build_client(&server.uri(), false);
    client
        .verify_logout_token(&token, &configuration)
        .await
        .expect_err("a long-lived logout token is a replayable termination command");
}

#[tokio::test]
async fn verifying_the_same_token_twice_does_not_raise() {
    // §12.7.3 rule 7. Delivery is at-least-once with retry, so a valid token
    // legitimately arrives twice — that is a retry, not an attack. An SDK
    // that dedupped internally would have no durable store and would
    // silently drop a real second logout after a restart, so `jti` is
    // surfaced for the RP to dedup on and never consumed here.
    let server = MockServer::start().await;
    let configuration = logout_fixture(&server, "logout-key").await;
    let key = generate_signing_key("logout-key");
    let token = sign_logout_token(&key, LogoutTokenOptions::default());

    let client = build_client(&server.uri(), false);
    let first = client
        .verify_logout_token(&token, &configuration)
        .await
        .expect("first delivery");
    let second = client
        .verify_logout_token(&token, &configuration)
        .await
        .expect("a redelivery must still verify");

    assert_eq!(first, second);
    assert_eq!(first.jti, LOGOUT_JTI, "the dedup key is the RP's to track");
}

#[tokio::test]
async fn a_verification_failure_never_echoes_the_token() {
    let server = MockServer::start().await;
    let configuration = logout_fixture(&server, "logout-key").await;
    let rogue = generate_signing_key("rogue-key");
    let token = sign_logout_token(&rogue, LogoutTokenOptions::default());

    let client = build_client(&server.uri(), false);
    let err = client
        .verify_logout_token(&token, &configuration)
        .await
        .expect_err("rejected");

    let rendered = format!("{err}{err:?}");
    assert!(
        !rendered.contains(&token),
        "§12.7.5: the error must not echo the token"
    );
}

// ---------------------------------------------------------------------------
// Contract 1.69 (#880): the logout token carries its JWKS `kid`
// ---------------------------------------------------------------------------

/// Mount discovery and a JWKS publishing `keys` in order.
async fn jwks_fixture(
    server: &MockServer,
    keys: &[&oidc_support::SigningKeyFixture],
) -> OidcConfiguration {
    Mock::given(method("GET"))
        .and(path("/oauth2/jwks"))
        .respond_with(ResponseTemplate::new(200).set_body_json(jwks_body(keys)))
        .mount(server)
        .await;
    configuration(server).await
}

/// The decoded JOSE header of `token`.
fn header_of(token: &str) -> serde_json::Value {
    use base64::Engine;
    let b64 = token.split('.').next().expect("header segment");
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(b64)
        .expect("base64url header");
    serde_json::from_slice(&raw).expect("header json")
}

#[tokio::test]
async fn a_server_shaped_logout_token_verifies_against_a_two_key_jwks() {
    let server = MockServer::start().await;
    // A rotation: the signing key is NOT first, so a verifier that takes the
    // first (or the only) key fails here.
    let other = generate_signing_key("rotated-out-key");
    let signer = generate_signing_key("current-key");
    let configuration = jwks_fixture(&server, &[&other, &signer]).await;
    let token = sign_logout_token(&signer, LogoutTokenOptions::default());

    // The fixture adds nothing the server does not send.
    assert_eq!(
        header_of(&token),
        serde_json::json!({"alg": "EdDSA", "typ": "logout+jwt", "kid": "current-key"})
    );

    let verified = build_client(&server.uri(), false)
        .verify_logout_token(&token, &configuration)
        .await
        .expect("a server-shaped logout token verifies");
    assert_eq!(verified.sid.as_deref(), Some(LOGOUT_SID));
    assert_eq!(verified.jti, LOGOUT_JTI);
}

#[tokio::test]
async fn a_kidless_or_unknown_kid_logout_token_is_refused_as_unknown_kid() {
    let server = MockServer::start().await;
    let signer = generate_signing_key("only-key");
    let configuration = jwks_fixture(&server, &[&signer]).await;
    let client = build_client(&server.uri(), false);

    // The one-key JWKS holds the key that signed it: the fallback the rule
    // forbids would accept this.
    let kidless = sign_logout_token(
        &signer,
        LogoutTokenOptions {
            omit_kid: true,
            ..Default::default()
        },
    );
    assert!(header_of(&kidless).get("kid").is_none());
    let unknown = {
        let rogue = generate_signing_key("not-published");
        sign_logout_token(&rogue, LogoutTokenOptions::default())
    };
    for (name, token) in [("no kid", kidless), ("unknown kid", unknown)] {
        let err = client
            .verify_logout_token(&token, &configuration)
            .await
            .expect_err(name);
        assert_eq!(
            err.id_token_failure_reason(),
            Some(IdTokenFailureReason::UnknownKid),
            "{name}: {err}"
        );
    }
}

#[tokio::test]
async fn rules_10_and_11_stay_off_the_logout_path_and_stay_on_the_guard() {
    // §10.1 rules 10 (`typ`) and 11 (`purpose`) belong to the access-token
    // guard only. The server-shaped logout token (`typ: logout+jwt`), even
    // with a `purpose` claim, verifies as a logout token, and the guard that
    // shares the JWKS verifier refuses the same bytes.
    let server = MockServer::start().await;
    let signer = generate_signing_key("current-key");
    let configuration = jwks_fixture(&server, &[&signer]).await;
    let token = sign_logout_token(
        &signer,
        LogoutTokenOptions {
            extra_claims: vec![("purpose".into(), serde_json::json!("mfa_challenge"))],
            ..Default::default()
        },
    );
    build_client(&server.uri(), false)
        .verify_logout_token(&token, &configuration)
        .await
        .expect("rules 10 and 11 do not apply to a logout token");

    // The guard is configured for the fixtures' tenant, so rules 1-9 pass and
    // only rules 10 and 11 can be what refuses these tokens.
    let tenant = oidc_support::tenant_id();
    let tenant_claim = || {
        (
            "tenant_id".to_string(),
            serde_json::json!(tenant.to_string()),
        )
    };
    let guard = JwksVerifier::new(
        reqwest::Client::new(),
        &url::Url::parse(&server.uri()).unwrap(),
    )
    .unwrap()
    .expect_tenant_id(tenant);
    let logout = sign_logout_token(
        &signer,
        LogoutTokenOptions {
            extra_claims: vec![tenant_claim()],
            ..Default::default()
        },
    );
    let id_token = sign_id_token(
        &signer,
        IdTokenOptions {
            extra_claims: vec![tenant_claim()],
            ..Default::default()
        },
    );
    let typeless_purpose = sign_logout_token(
        &signer,
        LogoutTokenOptions {
            omit_typ: true,
            extra_claims: vec![
                tenant_claim(),
                ("purpose".into(), serde_json::json!("mfa_challenge")),
            ],
            ..Default::default()
        },
    );
    for (name, token, rule) in [
        ("logout token", &logout, "rule 10"),
        ("ID token (typ JWT)", &id_token, "rule 10"),
        ("typ-less token with purpose", &typeless_purpose, "rule 11"),
    ] {
        let err = guard.verify(token).await.expect_err(name);
        assert!(err.to_string().contains(rule), "{name}: {err}");
    }
}

/// §12.4 rule 2: an unknown `kid` causes at most one JWKS re-fetch per cooldown
/// window, and a FAILED re-fetch opens the window too: while the endpoint
/// fails, a stream of unknown-kid tokens must not become a stream of fetches.
#[tokio::test]
async fn a_failing_jwks_endpoint_is_fetched_once_per_window_for_unknown_kids() {
    let server = MockServer::start().await;
    let signer = generate_signing_key("only-key");
    // The first fetch succeeds; every later one fails.
    Mock::given(method("GET"))
        .and(path("/oauth2/jwks"))
        .respond_with(ResponseTemplate::new(200).set_body_json(jwks_body(&[&signer])))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/oauth2/jwks"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;
    let configuration = configuration(&server).await;
    let client = build_client(&server.uri(), false);

    for i in 0..50 {
        let rogue = generate_signing_key(&format!("unknown-{i}"));
        let token = sign_logout_token(&rogue, LogoutTokenOptions::default());
        client
            .verify_logout_token(&token, &configuration)
            .await
            .expect_err("an unknown kid is refused");
    }
    let fetches = server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .filter(|r| r.url.path() == "/oauth2/jwks")
        .count();
    assert!(
        fetches <= 2,
        "one initial fetch and at most one forced re-fetch, got {fetches}"
    );
}
