//! RFC 8705 §5 `mtls_endpoint_aliases` — CONTRACT.md §21.3 rule 2 (contract 1.40).
//!
//! The rule has one sentence and three named ways to get it wrong, and this
//! file is organised around them rather than around the SDK's method list:
//!
//!   * a call going over mTLS prefers the alias;
//!   * a call NOT going over mTLS keeps the top-level entry;
//!   * an ABSENT member means "no separate mTLS host", never "unsupported";
//!   * only the six listed endpoints are ever aliased — not
//!     `authorization_endpoint`, `end_session_endpoint` or `jwks_uri`;
//!   * `issuer` is not an endpoint, does not move, and still governs `iss`
//!     validation by exact string for a token minted at an alias host.
//!
//! Two `MockServer`s stand in for the two listeners a deployment runs. The
//! §6.1 client identity is minted with `rcgen`, exactly as
//! `tests/mtls_client_cert_test.rs` does; wiremock speaks plain HTTP, so no
//! handshake occurs — what is under test is which URL the SDK chooses, which
//! is decided by the configured identity and the document, not by the socket.

#![cfg(feature = "rest")]

#[path = "oidc_support/mod.rs"]
mod oidc_support;

use axiam_sdk::AxiamError;
use axiam_sdk::Sensitive;
use axiam_sdk::oidc::{
    DeviceAuthorizeParams, IntrospectParams, LogoutUrlParams, OidcBeginParams, OidcExchangeParams,
    OidcParParams, RevokeParams,
};
use serde_json::json;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use oidc_support::{
    CLIENT_ID, ISSUER, REDIRECT_URI, build_client, build_mtls_client, discovery_document,
    discovery_document_with_aliases, mtls_endpoint_aliases, token_response,
};

const CODE_VERIFIER: &str = "vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv";

/// Serve the discovery document from `origin`, describing `aliases`.
async fn mount_discovery(server: &MockServer, body: serde_json::Value) {
    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .mount(server)
        .await;
}

/// Mount every OAuth2 POST endpoint on `server`, each replying with a body
/// that endpoint's caller will accept. Both origins get the full set, so
/// choosing the wrong one is a *recorded* call rather than a 404 — the
/// assertion then names the host that was used.
async fn mount_oauth2_endpoints(server: &MockServer) {
    let bodies = [
        ("/oauth2/token", token_response(json!({}))),
        ("/oauth2/introspect", json!({ "active": true })),
        ("/oauth2/revoke", json!({})),
        (
            "/oauth2/device_authorization",
            json!({
                "device_code": "device-code-value",
                "user_code": "WDJB-MJHT",
                "verification_uri": "https://example.test/device",
                "expires_in": 30,
                "interval": 1,
            }),
        ),
        (
            "/oauth2/par",
            json!({ "request_uri": "urn:ietf:params:oauth:request_uri:x", "expires_in": 60 }),
        ),
    ];
    for (p, body) in bodies {
        Mock::given(method("POST"))
            .and(path(p))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .mount(server)
            .await;
    }
}

/// Which origin actually received a POST to `endpoint_path`: exactly one of
/// the two servers must have, and this returns its URI.
async fn receiving_origin(a: &MockServer, b: &MockServer, endpoint_path: &str) -> String {
    let hit = |s: &Vec<wiremock::Request>| {
        s.iter()
            .any(|r| r.method == http_types_method() && r.url.path() == endpoint_path)
    };
    let a_reqs = a.received_requests().await.unwrap_or_default();
    let b_reqs = b.received_requests().await.unwrap_or_default();
    match (hit(&a_reqs), hit(&b_reqs)) {
        (true, false) => a.uri(),
        (false, true) => b.uri(),
        (true, true) => panic!("{endpoint_path} was posted to BOTH origins"),
        (false, false) => panic!("{endpoint_path} was posted to NEITHER origin"),
    }
}

fn http_types_method() -> wiremock::http::Method {
    wiremock::http::Method::POST
}

fn exchange_params() -> OidcExchangeParams {
    OidcExchangeParams {
        code: "authorization-code-value".into(),
        code_verifier: Sensitive::new(CODE_VERIFIER.to_string()),
        redirect_uri: REDIRECT_URI.into(),
        nonce: "the-request-nonce".into(),
        tenant_id: None,
        configuration: None,
    }
}

// ── The document round-trips the member ────────────────────────────────────

#[tokio::test]
async fn discovery_exposes_the_aliases_when_the_server_publishes_them() {
    let conventional = MockServer::start().await;
    let mtls = MockServer::start().await;
    mount_discovery(
        &conventional,
        discovery_document_with_aliases(&conventional.uri(), &mtls.uri()),
    )
    .await;
    let client = build_client(&conventional.uri(), true);

    let configuration = client.oidc_discover().await.expect("discovery succeeds");

    let aliases = configuration
        .mtls_endpoint_aliases
        .as_ref()
        .expect("the member the server published must survive deserialization");
    assert_eq!(
        aliases.token_endpoint.as_deref(),
        Some(format!("{}/oauth2/token", mtls.uri()).as_str())
    );
    // Alongside, never instead of: the conventional entries are untouched.
    assert_eq!(
        configuration.token_endpoint,
        format!("{}/oauth2/token", conventional.uri())
    );
}

#[tokio::test]
async fn an_absent_member_deserializes_to_none_rather_than_failing() {
    let conventional = MockServer::start().await;
    mount_discovery(&conventional, discovery_document(&conventional.uri())).await;
    let client = build_mtls_client(&conventional.uri(), true);

    let configuration = client
        .oidc_discover()
        .await
        .expect("a document with no aliases is valid, not an error");

    assert!(configuration.mtls_endpoint_aliases.is_none());
}

#[tokio::test]
async fn the_member_round_trips_through_serialization() {
    let conventional = MockServer::start().await;
    let mtls = MockServer::start().await;
    mount_discovery(
        &conventional,
        discovery_document_with_aliases(&conventional.uri(), &mtls.uri()),
    )
    .await;
    let client = build_client(&conventional.uri(), true);

    let configuration = client.oidc_discover().await.expect("discovery succeeds");
    let round_tripped = serde_json::to_value(&configuration).expect("serializes");

    assert_eq!(
        round_tripped["mtls_endpoint_aliases"],
        mtls_endpoint_aliases(&mtls.uri())
    );
}

#[tokio::test]
async fn an_absent_member_serializes_as_absent_not_null() {
    let conventional = MockServer::start().await;
    mount_discovery(&conventional, discovery_document(&conventional.uri())).await;
    let client = build_client(&conventional.uri(), true);

    let configuration = client.oidc_discover().await.expect("discovery succeeds");
    let round_tripped = serde_json::to_value(&configuration).expect("serializes");

    // The server omits the key rather than writing `null`; so does this type.
    assert!(round_tripped.get("mtls_endpoint_aliases").is_none());
}

// ── A call over mTLS prefers the alias ─────────────────────────────────────

#[tokio::test]
async fn the_token_endpoint_call_goes_to_the_alias_host() {
    let conventional = MockServer::start().await;
    let mtls = MockServer::start().await;
    mount_discovery(
        &conventional,
        discovery_document_with_aliases(&conventional.uri(), &mtls.uri()),
    )
    .await;
    mount_oauth2_endpoints(&conventional).await;
    mount_oauth2_endpoints(&mtls).await;
    let client = build_mtls_client(&conventional.uri(), true);

    client
        .oidc_exchange(exchange_params())
        .await
        .expect("exchange succeeds");

    assert_eq!(
        receiving_origin(&conventional, &mtls, "/oauth2/token").await,
        mtls.uri()
    );
}

#[tokio::test]
async fn introspect_revoke_device_and_par_all_go_to_their_aliases() {
    let conventional = MockServer::start().await;
    let mtls = MockServer::start().await;
    mount_discovery(
        &conventional,
        discovery_document_with_aliases(&conventional.uri(), &mtls.uri()),
    )
    .await;
    mount_oauth2_endpoints(&conventional).await;
    mount_oauth2_endpoints(&mtls).await;
    let client = build_mtls_client(&conventional.uri(), true);

    client
        .introspect(IntrospectParams {
            token: Sensitive::new("access-token-value".into()),
            token_type_hint: None,
            tenant_id: None,
            configuration: None,
        })
        .await
        .expect("introspect succeeds");
    client
        .revoke(RevokeParams {
            token: Sensitive::new("access-token-value".into()),
            token_type_hint: None,
            tenant_id: None,
            configuration: None,
        })
        .await
        .expect("revoke succeeds");
    client
        .device_authorize(DeviceAuthorizeParams::default())
        .await
        .expect("device_authorize succeeds");

    let configuration = client.oidc_discover().await.expect("discovery succeeds");
    let request = client
        .oidc_begin(
            &configuration,
            OidcBeginParams {
                redirect_uri: REDIRECT_URI.into(),
                scope: Some("openid".into()),
                extra_params: Vec::new(),
            },
        )
        .expect("oidc_begin succeeds");
    client
        .oidc_par(OidcParParams {
            request,
            redirect_uri: REDIRECT_URI.into(),
            scope: Some("openid".into()),
            tenant_id: None,
            configuration: None,
            dpop_jkt: None,
        })
        .await
        .expect("oidc_par succeeds");

    for p in [
        "/oauth2/introspect",
        "/oauth2/revoke",
        "/oauth2/device_authorization",
        "/oauth2/par",
    ] {
        assert_eq!(
            receiving_origin(&conventional, &mtls, p).await,
            mtls.uri(),
            "{p} must go to the alias host"
        );
    }
}

// ── Consequence 1: absence means "no separate host" ────────────────────────

#[tokio::test]
async fn an_mtls_client_with_no_aliases_keeps_the_top_level_endpoints() {
    let conventional = MockServer::start().await;
    let mtls = MockServer::start().await;
    mount_discovery(&conventional, discovery_document(&conventional.uri())).await;
    mount_oauth2_endpoints(&conventional).await;
    mount_oauth2_endpoints(&mtls).await;
    let client = build_mtls_client(&conventional.uri(), true);

    // Not an error, and not the alias origin: a deployment running
    // `client_auth = optional` on one listener serves both populations at the
    // conventional endpoints and correctly publishes nothing.
    client
        .oidc_exchange(exchange_params())
        .await
        .expect("an mTLS client against an alias-free document must still work");

    assert_eq!(
        receiving_origin(&conventional, &mtls, "/oauth2/token").await,
        conventional.uri()
    );
}

#[tokio::test]
async fn a_client_not_doing_mtls_keeps_the_top_level_endpoints() {
    let conventional = MockServer::start().await;
    let mtls = MockServer::start().await;
    mount_discovery(
        &conventional,
        discovery_document_with_aliases(&conventional.uri(), &mtls.uri()),
    )
    .await;
    mount_oauth2_endpoints(&conventional).await;
    mount_oauth2_endpoints(&mtls).await;
    let client = build_client(&conventional.uri(), true);

    client
        .oidc_exchange(exchange_params())
        .await
        .expect("exchange succeeds");

    assert_eq!(
        receiving_origin(&conventional, &mtls, "/oauth2/token").await,
        conventional.uri()
    );
}

#[tokio::test]
async fn an_unsupported_grant_is_still_reported_when_neither_level_names_it() {
    let conventional = MockServer::start().await;
    let mtls = MockServer::start().await;
    let mut document = discovery_document_with_aliases(&conventional.uri(), &mtls.uri());
    let obj = document.as_object_mut().expect("object");
    obj.remove("device_authorization_endpoint");
    obj["mtls_endpoint_aliases"]
        .as_object_mut()
        .expect("aliases object")
        .remove("device_authorization_endpoint");
    mount_discovery(&conventional, document).await;
    let client = build_mtls_client(&conventional.uri(), true);

    // Neither level names the endpoint, so the answer is still "this server
    // does not support the device grant" — never a URL built by concatenation.
    let err = client
        .device_authorize(DeviceAuthorizeParams::default())
        .await
        .expect_err("a server advertising no device endpoint at either level");
    assert!(matches!(err, AxiamError::Auth { .. }), "got {err}");
}

#[tokio::test]
async fn a_partial_alias_object_falls_back_per_endpoint_instead_of_failing() {
    let conventional = MockServer::start().await;
    let mtls = MockServer::start().await;
    let mut document = discovery_document_with_aliases(&conventional.uri(), &mtls.uri());
    // RFC 8705 §5 does not require an OP to alias all six, and the shape of
    // this member must never be why a client stops working: an alias object
    // naming only `token_endpoint` is a valid document, and every endpoint it
    // does not name falls back to the top-level entry.
    document["mtls_endpoint_aliases"] = json!({
        "token_endpoint": format!("{}/oauth2/token", mtls.uri()),
    });
    mount_discovery(&conventional, document).await;
    mount_oauth2_endpoints(&conventional).await;
    mount_oauth2_endpoints(&mtls).await;
    let client = build_mtls_client(&conventional.uri(), true);

    client
        .oidc_exchange(exchange_params())
        .await
        .expect("a partial alias object is a valid document, not an error");
    client
        .introspect(IntrospectParams {
            token: Sensitive::new("access-token-value".into()),
            token_type_hint: None,
            tenant_id: None,
            configuration: None,
        })
        .await
        .expect("introspect succeeds");

    assert_eq!(
        receiving_origin(&conventional, &mtls, "/oauth2/token").await,
        mtls.uri(),
        "the one aliased endpoint uses its alias"
    );
    assert_eq!(
        receiving_origin(&conventional, &mtls, "/oauth2/introspect").await,
        conventional.uri(),
        "an endpoint the object does not name falls back to the top level"
    );
}

// ── Consequence 2: no alias is ever synthesised ────────────────────────────

#[tokio::test]
async fn the_front_channel_and_jwks_endpoints_are_never_aliased() {
    let conventional = MockServer::start().await;
    let mtls = MockServer::start().await;
    mount_discovery(
        &conventional,
        discovery_document_with_aliases(&conventional.uri(), &mtls.uri()),
    )
    .await;
    let client = build_mtls_client(&conventional.uri(), true);
    let configuration = client.oidc_discover().await.expect("discovery succeeds");

    // A browser sent to an mTLS host raises a native certificate-chooser
    // dialog most users cannot answer, and jwks_uri is public key material
    // that gains nothing from a handshake.
    let request = client
        .oidc_begin(
            &configuration,
            OidcBeginParams {
                redirect_uri: REDIRECT_URI.into(),
                scope: Some("openid".into()),
                extra_params: Vec::new(),
            },
        )
        .expect("oidc_begin succeeds");
    assert!(
        request
            .url
            .starts_with(&format!("{}/oauth2/authorize", conventional.uri())),
        "authorization_endpoint must stay on the conventional host: {}",
        request.url
    );

    let logout = client
        .logout_url(
            &configuration,
            LogoutUrlParams::new(Sensitive::new("not-a-real-token".into())),
        )
        .expect("logout_url succeeds");
    assert!(
        logout.starts_with(&format!("{}/oauth2/end_session", conventional.uri())),
        "end_session_endpoint must stay on the conventional host: {logout}"
    );

    assert_eq!(
        configuration.jwks_uri,
        format!("{}/oauth2/jwks", conventional.uri()),
        "jwks_uri must stay on the conventional host"
    );
}

// ── Consequence 3: issuer is never aliased ─────────────────────────────────

#[tokio::test]
async fn the_issuer_does_not_move_with_the_endpoints() {
    let conventional = MockServer::start().await;
    let mtls = MockServer::start().await;
    mount_discovery(
        &conventional,
        discovery_document_with_aliases(&conventional.uri(), &mtls.uri()),
    )
    .await;
    let client = build_mtls_client(&conventional.uri(), true);

    let configuration = client.oidc_discover().await.expect("discovery succeeds");

    // §12.4 rule 3 compares `iss` against THIS value by exact string, for
    // every token — including one minted at an alias endpoint. An SDK that
    // derived an expected issuer from the host it called would reject every
    // token it obtains over mTLS.
    assert_eq!(configuration.issuer, ISSUER);
    assert_ne!(configuration.issuer, mtls.uri());
    assert_ne!(configuration.issuer, conventional.uri());
}

#[tokio::test]
async fn an_id_token_from_the_alias_host_is_validated_against_the_unchanged_issuer() {
    let conventional = MockServer::start().await;
    let mtls = MockServer::start().await;
    let key = oidc_support::generate_signing_key("rp-kid-1");
    mount_discovery(
        &conventional,
        discovery_document_with_aliases(&conventional.uri(), &mtls.uri()),
    )
    .await;
    Mock::given(method("GET"))
        .and(path("/oauth2/jwks"))
        .respond_with(ResponseTemplate::new(200).set_body_json(oidc_support::jwks_body(&[&key])))
        .mount(&conventional)
        .await;

    // Accepted: `iss` is the document's issuer, though the token came from the
    // alias host.
    let good = oidc_support::sign_id_token(
        &key,
        oidc_support::IdTokenOptions {
            nonce: Some(Some("the-request-nonce")),
            ..Default::default()
        },
    );
    Mock::given(method("POST"))
        .and(path("/oauth2/token"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(token_response(json!({ "id_token": good }))),
        )
        .mount(&mtls)
        .await;
    let client = build_mtls_client(&conventional.uri(), true);

    let tokens = client
        .oidc_exchange(exchange_params())
        .await
        .expect("a token whose iss is the unchanged issuer must be accepted");
    assert_eq!(
        tokens.id_claims.as_ref().expect("id claims").iss,
        ISSUER,
        "the audience is {CLIENT_ID}"
    );
}

#[tokio::test]
async fn an_id_token_claiming_the_alias_host_as_issuer_is_rejected() {
    let conventional = MockServer::start().await;
    let mtls = MockServer::start().await;
    let key = oidc_support::generate_signing_key("rp-kid-1");
    mount_discovery(
        &conventional,
        discovery_document_with_aliases(&conventional.uri(), &mtls.uri()),
    )
    .await;
    Mock::given(method("GET"))
        .and(path("/oauth2/jwks"))
        .respond_with(ResponseTemplate::new(200).set_body_json(oidc_support::jwks_body(&[&key])))
        .mount(&conventional)
        .await;

    let mtls_uri = mtls.uri();
    let bad = oidc_support::sign_id_token(
        &key,
        oidc_support::IdTokenOptions {
            issuer: Some(&mtls_uri),
            nonce: Some(Some("the-request-nonce")),
            ..Default::default()
        },
    );
    Mock::given(method("POST"))
        .and(path("/oauth2/token"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(token_response(json!({ "id_token": bad }))),
        )
        .mount(&mtls)
        .await;
    let client = build_mtls_client(&conventional.uri(), true);

    let err = client
        .oidc_exchange(exchange_params())
        .await
        .expect_err("iss must equal the document's issuer, not the host that minted the token");
    assert!(matches!(err, AxiamError::Auth { .. }), "got {err}");
}

// ── §21.3.1 vector C — a malformed alias is REFUSED, never fallen back from ──
//
// Contract 1.43 publishes three vectors every SDK pins. A and B are covered
// above (`discovery_document_with_aliases` is A; `an_absent_member_…` and
// `an_mtls_client_with_no_aliases_…` are B). C is this section, and it is the
// one where the obvious implementation is the wrong one.
//
// Falling back to the top-level endpoint looks like the safe answer and is the
// dangerous one: the caller asked to authenticate with a certificate, the
// operator published something that cannot carry one, and quietly presenting
// the certificate to the front-channel host authenticates nothing while
// appearing to work. The call must fail and say why.

/// Vector C, first defect: a relative alias. It resolves against nothing a
/// client holds — and the one base that might seem obvious, the issuer's own
/// host, is precisely the host the alias exists to name a different one from.
#[tokio::test]
async fn a_relative_alias_is_refused_rather_than_fallen_back_from() {
    let conventional = MockServer::start().await;
    let mut doc = discovery_document(&conventional.uri());
    doc.as_object_mut().unwrap().insert(
        "mtls_endpoint_aliases".into(),
        json!({ "token_endpoint": "/oauth2/token" }),
    );
    mount_discovery(&conventional, doc).await;
    mount_oauth2_endpoints(&conventional).await;
    let client = build_mtls_client(&conventional.uri(), true);

    let err = client
        .oidc_exchange(exchange_params())
        .await
        .expect_err("a relative alias must fail the call");
    let message = err.to_string();
    assert!(
        message.contains("mtls_endpoint_aliases"),
        "the error must name the member so an operator knows what to fix: {message}"
    );

    // And the proof that it refused rather than fell back: the conventional
    // token endpoint was never called. A fallback would be a *successful*
    // exchange here, which is exactly the outcome this vector exists to
    // prevent.
    let requests = conventional.received_requests().await.unwrap_or_default();
    assert!(
        !requests.iter().any(|r| r.url.path() == "/oauth2/token"),
        "refusing means not calling the front-channel host with a certificate"
    );
}

/// Vector C, second defect: a scheme **weaker than the endpoint the alias
/// replaces**. An alias substitutes for exactly one top-level endpoint, so
/// that is what it is compared against.
///
/// The test is deliberately not "the alias must be `https`", and not "weaker
/// than the `issuer`" either. Both were tried and both failed correct tests:
/// AXIAM's own `build_mtls_aliases` accepts `http` for local development, this
/// file's harness is a wiremock server speaking plain HTTP, and the fixture
/// pairs a realistic `https` issuer string with loopback endpoints — exactly
/// as a deployment behind a TLS-terminating proxy may. Comparing like with
/// like is the only rule true in all three.
#[tokio::test]
async fn an_alias_weaker_than_the_endpoint_it_replaces_is_refused() {
    let conventional = MockServer::start().await;
    let mut doc = discovery_document(&conventional.uri());
    doc.as_object_mut().unwrap().insert(
        "token_endpoint".into(),
        json!("https://iam.example.test/oauth2/token"),
    );
    doc.as_object_mut().unwrap().insert(
        "mtls_endpoint_aliases".into(),
        json!({ "token_endpoint": "http://mtls.example.test/oauth2/token" }),
    );
    mount_discovery(&conventional, doc).await;
    mount_oauth2_endpoints(&conventional).await;
    let client = build_mtls_client(&conventional.uri(), true);

    let message = client
        .oidc_exchange(exchange_params())
        .await
        .expect_err("a downgrade alias must fail the call")
        .to_string();
    assert!(message.contains("downgrade"), "{message}");
}

/// The other side of the same rule, and the one that keeps the dev topologies
/// working: an `http` alias for an `http` endpoint is not a downgrade. A
/// deployment that is plaintext throughout is a development deployment rather
/// than a misconfiguration, and the whole of this file's harness is one.
#[tokio::test]
async fn an_alias_matching_a_plaintext_endpoint_is_accepted() {
    let conventional = MockServer::start().await;
    let mtls = MockServer::start().await;
    mount_discovery(
        &conventional,
        discovery_document_with_aliases(&conventional.uri(), &mtls.uri()),
    )
    .await;
    mount_oauth2_endpoints(&conventional).await;
    mount_oauth2_endpoints(&mtls).await;
    let client = build_mtls_client(&conventional.uri(), true);

    client
        .oidc_exchange(exchange_params())
        .await
        .expect("an http alias under an http issuer is not a downgrade");
    assert_eq!(
        receiving_origin(&conventional, &mtls, "/oauth2/token").await,
        mtls.uri()
    );
}

/// The non-regression that makes vector C safe to enforce: a client with **no
/// certificate configured** does not read the member at all — not even to
/// validate it. A deployment whose aliases are malformed must not break the
/// clients that never use them, and this is the assertion that proves the
/// validation sits at the point of use rather than at decode.
#[tokio::test]
async fn a_malformed_alias_does_not_break_a_client_with_no_certificate() {
    let conventional = MockServer::start().await;
    let mut doc = discovery_document(&conventional.uri());
    doc.as_object_mut().unwrap().insert(
        "mtls_endpoint_aliases".into(),
        json!({ "token_endpoint": "/oauth2/token" }),
    );
    mount_discovery(&conventional, doc).await;
    mount_oauth2_endpoints(&conventional).await;
    let client = build_client(&conventional.uri(), true);

    client
        .oidc_exchange(exchange_params())
        .await
        .expect("a client with no certificate never reads the aliases");

    let requests = conventional
        .received_requests()
        .await
        .expect("requests recorded");
    assert!(
        requests.iter().any(|r| r.url.path() == "/oauth2/token"),
        "the call went to the top-level endpoint, as it does when the document \
         publishes no aliases at all"
    );
}

// ── §21.3 rule 2 clause 4 — the query component ────────────────────────────
//
// AXIAM's aliases carry the tenant as a query component. Clause 4 forbids two
// things and permits a third that is easy to mistake for one of them:
//
//   * appending — `?tenant_id=A&tenant_id=B`, which the server cannot resolve
//     to one tenant;
//   * stripping — rebuilding the URL from host and path, dropping whatever
//     else the deployment put there;
//   * displacing the `tenant_id` value with the caller's own is CORRECT, and
//     is what a multi-tenant deployment requires, since its document names no
//     tenant at all.

/// The alias's other query parameters survive, and its `tenant_id` is
/// displaced rather than duplicated.
#[tokio::test]
async fn an_alias_query_component_is_displaced_and_never_duplicated() {
    let conventional = MockServer::start().await;
    let mtls = MockServer::start().await;

    let published_tenant = "00000000-0000-4000-8000-00000000dead";
    let mut doc = discovery_document(&conventional.uri());
    doc.as_object_mut().unwrap().insert(
        "mtls_endpoint_aliases".into(),
        json!({
            "token_endpoint": format!(
                "{}/oauth2/token?tenant_id={published_tenant}&deployment=eu-west",
                mtls.uri()
            ),
        }),
    );
    mount_discovery(&conventional, doc).await;
    mount_oauth2_endpoints(&conventional).await;
    mount_oauth2_endpoints(&mtls).await;
    let client = build_mtls_client(&conventional.uri(), true);

    client
        .oidc_exchange(exchange_params())
        .await
        .expect("exchange succeeds against the alias");

    let requests = mtls.received_requests().await.expect("requests recorded");
    let call = requests
        .iter()
        .find(|r| r.url.path() == "/oauth2/token")
        .expect("the alias host received the call");

    let tenants: Vec<String> = call
        .url
        .query_pairs()
        .filter(|(k, _)| k == "tenant_id")
        .map(|(_, v)| v.into_owned())
        .collect();
    assert_eq!(
        tenants.len(),
        1,
        "exactly one tenant_id — appending a second gives the server a value \
         it cannot resolve to one tenant: {}",
        call.url
    );
    assert_ne!(
        tenants[0], published_tenant,
        "the caller's own tenant displaces the published one"
    );

    // And nothing else the deployment put in the query was dropped.
    assert!(
        call.url
            .query_pairs()
            .any(|(k, v)| k == "deployment" && v == "eu-west"),
        "every other parameter must survive as the server wrote it: {}",
        call.url
    );
}
