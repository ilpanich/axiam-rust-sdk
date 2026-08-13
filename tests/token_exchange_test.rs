//! Token Exchange (RFC 8693) — CONTRACT.md §15.
//!
//! Most of §15 is a list of things an SDK must *not* helpfully do, so most of
//! these tests assert an absence: no defaulted `actor_token`, no auto-narrow
//! after `invalid_scope`, no synthesised refresh token, no adoption of the
//! exchanged token as the client's own credential.

#![cfg(feature = "rest")]

#[path = "oidc_support/mod.rs"]
mod oidc_support;

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use axiam_sdk::AxiamError;
use axiam_sdk::Sensitive;
use axiam_sdk::oidc::{JWT_TOKEN_TYPE, TokenExchangeParams};
use serde_json::json;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

use oidc_support::{CLIENT_SECRET, build_client, discovery_document};

const SUBJECT_TOKEN: &str = "subject-token-value";
const ACTOR_TOKEN: &str = "actor-token-value";
const ISSUED_TOKEN: &str = "issued-narrow-token";

fn parse_form(body: &[u8]) -> HashMap<String, String> {
    url::form_urlencoded::parse(body).into_owned().collect()
}

async fn mount_discovery(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(200).set_body_json(discovery_document(&server.uri())))
        .mount(server)
        .await;
}

fn exchange_response(overrides: serde_json::Value) -> serde_json::Value {
    let mut base = json!({
        "access_token": ISSUED_TOKEN,
        "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
        "token_type": "Bearer",
        "expires_in": 300,
        "scope": "orders:read",
    });
    if let (Some(b), Some(o)) = (base.as_object_mut(), overrides.as_object()) {
        for (k, v) in o {
            b.insert(k.clone(), v.clone());
        }
    }
    base
}

/// Mount the token endpoint, capturing the form body of every request.
async fn mount_exchange(
    server: &MockServer,
    response: ResponseTemplate,
) -> Arc<Mutex<Vec<HashMap<String, String>>>> {
    let forms: Arc<Mutex<Vec<HashMap<String, String>>>> = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&forms);
    Mock::given(method("POST"))
        .and(path("/oauth2/token"))
        .respond_with(move |req: &Request| {
            sink.lock().unwrap().push(parse_form(&req.body));
            response.clone()
        })
        .mount(server)
        .await;
    forms
}

fn oauth_error(code: &str) -> ResponseTemplate {
    ResponseTemplate::new(400).set_body_json(json!({
        "error": code,
        "error_description": format!("{code} description"),
    }))
}

// ---------------------------------------------------------------------------
// §15.1 wire shape
// ---------------------------------------------------------------------------

#[tokio::test]
async fn exchange_sends_the_rfc_8693_grant_and_authenticates() {
    let server = MockServer::start().await;
    mount_discovery(&server).await;
    let forms = mount_exchange(
        &server,
        ResponseTemplate::new(200).set_body_json(exchange_response(json!({}))),
    )
    .await;

    let client = build_client(&server.uri(), true);
    let result = client
        .token_exchange(TokenExchangeParams {
            scopes: Some(vec!["orders:read".into(), "orders:write".into()]),
            audience: Some("orders-service".into()),
            ..TokenExchangeParams::new(Sensitive::new(SUBJECT_TOKEN.into()))
        })
        .await
        .expect("exchange succeeds");

    let form = forms.lock().unwrap()[0].clone();
    assert_eq!(
        form.get("grant_type").map(String::as_str),
        Some("urn:ietf:params:oauth:grant-type:token-exchange")
    );
    assert_eq!(
        form.get("subject_token").map(String::as_str),
        Some(SUBJECT_TOKEN)
    );
    assert_eq!(
        form.get("subject_token_type").map(String::as_str),
        Some("urn:ietf:params:oauth:token-type:access_token")
    );
    assert_eq!(
        form.get("scope").map(String::as_str),
        Some("orders:read orders:write"),
        "scopes are space-delimited on the wire"
    );
    assert_eq!(
        form.get("audience").map(String::as_str),
        Some("orders-service")
    );
    assert_eq!(
        form.get("client_secret").map(String::as_str),
        Some(CLIENT_SECRET),
        "§15.1: the exchanging client is confidential and authenticates"
    );

    assert_eq!(result.access_token.expose(), ISSUED_TOKEN);
    assert_eq!(
        result.issued_token_type, "urn:ietf:params:oauth:token-type:access_token",
        "§15.2 rule 6: issued_token_type is surfaced, not dropped"
    );
}

#[tokio::test]
async fn a_public_client_fails_before_any_wire_call() {
    let server = MockServer::start().await;
    mount_discovery(&server).await;
    // No token-endpoint mock at all: reaching the wire would 404 the test.

    let client = build_client(&server.uri(), false);
    let err = client
        .token_exchange(TokenExchangeParams::new(Sensitive::new(
            SUBJECT_TOKEN.into(),
        )))
        .await
        .expect_err("a client with no secret cannot exchange");

    assert!(matches!(err, AxiamError::Auth { .. }));
    assert!(err.to_string().contains("client_secret"));
}

// ---------------------------------------------------------------------------
// §15.2 rule 1 — delegation vs impersonation
// ---------------------------------------------------------------------------

#[tokio::test]
async fn absent_actor_token_is_sent_as_absent_never_defaulted() {
    let server = MockServer::start().await;
    mount_discovery(&server).await;
    let forms = mount_exchange(
        &server,
        ResponseTemplate::new(200).set_body_json(exchange_response(json!({}))),
    )
    .await;

    let client = build_client(&server.uri(), true);
    client
        .token_exchange(TokenExchangeParams::new(Sensitive::new(
            SUBJECT_TOKEN.into(),
        )))
        .await
        .expect("exchange");

    let form = forms.lock().unwrap()[0].clone();
    assert!(
        !form.contains_key("actor_token"),
        "§15.2 rule 1: passing no actor token asks for IMPERSONATION. An SDK \
         that helpfully substituted its own session token would silently turn \
         that into a delegation — a different operation with different risk."
    );
    assert!(!form.contains_key("actor_token_type"));
}

#[tokio::test]
async fn actor_token_and_its_type_are_sent_as_a_pair() {
    let server = MockServer::start().await;
    mount_discovery(&server).await;
    let forms = mount_exchange(
        &server,
        ResponseTemplate::new(200).set_body_json(exchange_response(json!({}))),
    )
    .await;

    let client = build_client(&server.uri(), true);
    client
        .token_exchange(TokenExchangeParams {
            actor_token: Some(Sensitive::new(ACTOR_TOKEN.into())),
            ..TokenExchangeParams::new(Sensitive::new(SUBJECT_TOKEN.into()))
        })
        .await
        .expect("exchange");

    let form = forms.lock().unwrap()[0].clone();
    assert_eq!(
        form.get("actor_token").map(String::as_str),
        Some(ACTOR_TOKEN)
    );
    assert_eq!(
        form.get("actor_token_type").map(String::as_str),
        Some("urn:ietf:params:oauth:token-type:access_token"),
        "RFC 8693 §2.1 requires the pair; the type alone is a malformed request"
    );
}

// ---------------------------------------------------------------------------
// §15.2 rules 2/3 and §15.3 — refusals surface unchanged
// ---------------------------------------------------------------------------

#[tokio::test]
async fn invalid_scope_is_not_retried_with_fewer_scopes() {
    let server = MockServer::start().await;
    mount_discovery(&server).await;
    let calls = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&calls);
    Mock::given(method("POST"))
        .and(path("/oauth2/token"))
        .respond_with(move |_: &Request| {
            counter.fetch_add(1, Ordering::SeqCst);
            oauth_error("invalid_scope")
        })
        .mount(&server)
        .await;

    let client = build_client(&server.uri(), true);
    let err = client
        .token_exchange(TokenExchangeParams {
            scopes: Some(vec!["orders:read".into(), "orders:admin".into()]),
            ..TokenExchangeParams::new(Sensitive::new(SUBJECT_TOKEN.into()))
        })
        .await
        .expect_err("invalid_scope");

    assert_eq!(err.oauth_error_code(), Some("invalid_scope"));
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "§15.2 rule 3: the server refuses rather than silently narrowing so the \
         caller finds out HERE. Auto-narrowing and re-sending would hide it."
    );
}

#[tokio::test]
async fn unauthorized_client_is_surfaced_verbatim_and_not_downgraded() {
    let server = MockServer::start().await;
    mount_discovery(&server).await;
    let forms = mount_exchange(&server, oauth_error("unauthorized_client")).await;

    let client = build_client(&server.uri(), true);
    let err = client
        .token_exchange(TokenExchangeParams::new(Sensitive::new(
            SUBJECT_TOKEN.into(),
        )))
        .await
        .expect_err("unauthorized_client");

    assert_eq!(err.oauth_error_code(), Some("unauthorized_client"));
    let forms = forms.lock().unwrap();
    assert_eq!(forms.len(), 1, "no retry");
    assert!(
        !forms[0].contains_key("actor_token"),
        "§15.2 rule 2: an SDK that reworked the impersonation into a delegation \
         would be sending a request the caller did not write"
    );
}

#[tokio::test]
async fn the_six_error_codes_reach_the_caller_unchanged() {
    // §15.3. Including cross-tenant, which the server deliberately collapses
    // into `invalid_grant` — the SDK must not try to re-derive the
    // distinction it withheld (that is a tenant-enumeration signal).
    for code in [
        "invalid_request",
        "invalid_grant",
        "invalid_scope",
        "invalid_target",
        "unauthorized_client",
        "invalid_client",
    ] {
        let server = MockServer::start().await;
        mount_discovery(&server).await;
        mount_exchange(&server, oauth_error(code)).await;

        let client = build_client(&server.uri(), true);
        let err = client
            .token_exchange(TokenExchangeParams::new(Sensitive::new(
                SUBJECT_TOKEN.into(),
            )))
            .await
            .expect_err("refusal");

        assert_eq!(err.oauth_error_code(), Some(code));
        assert!(
            matches!(err, AxiamError::Auth { .. }),
            "§15.3 extends §2: an OAuth2ErrorResponse is an auth failure, not \
             the generic 400 mapping"
        );
    }
}

// ---------------------------------------------------------------------------
// §15.2 rules 4/5/7 — what the result is, and is not
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_server_sent_refresh_token_is_not_surfaced() {
    let server = MockServer::start().await;
    mount_discovery(&server).await;
    // Deliberately hostile fixture: the wire body carries a refresh_token
    // even though RFC 8693 issues none.
    mount_exchange(
        &server,
        ResponseTemplate::new(200).set_body_json(exchange_response(
            json!({ "refresh_token": "should-not-exist" }),
        )),
    )
    .await;

    let client = build_client(&server.uri(), true);
    let result = client
        .token_exchange(TokenExchangeParams::new(Sensitive::new(
            SUBJECT_TOKEN.into(),
        )))
        .await
        .expect("exchange");

    // §15.2 rule 4: the type has no refresh_token field at all, so there is
    // nothing to synthesise and nothing to feed the §9 refresh guard. This
    // test is really an assertion about the shape of `ExchangedToken` — that
    // it cannot represent a refresh token even when one is on the wire.
    let rendered = format!("{result:?}");
    assert!(!rendered.contains("should-not-exist"));
    assert!(!rendered.contains("refresh_token"));
}

#[tokio::test]
async fn the_exchanged_token_does_not_become_the_clients_own_credential() {
    let server = MockServer::start().await;
    mount_discovery(&server).await;
    mount_exchange(
        &server,
        ResponseTemplate::new(200).set_body_json(exchange_response(json!({}))),
    )
    .await;

    let captured: Arc<Mutex<Option<Option<String>>>> = Arc::new(Mutex::new(None));
    let sink = Arc::clone(&captured);
    Mock::given(method("POST"))
        .and(path("/api/v1/authz/check"))
        .respond_with(move |req: &Request| {
            *sink.lock().unwrap() = Some(
                req.headers
                    .get("authorization")
                    .map(|v| v.to_str().unwrap().to_string()),
            );
            ResponseTemplate::new(200).set_body_json(json!({ "allowed": true }))
        })
        .mount(&server)
        .await;

    let client = build_client(&server.uri(), true);
    let exchanged = client
        .token_exchange(TokenExchangeParams::new(Sensitive::new(
            SUBJECT_TOKEN.into(),
        )))
        .await
        .expect("exchange");
    assert_eq!(exchanged.access_token.expose(), ISSUED_TOKEN);

    // A subsequent call on the same client must not carry the exchanged
    // token. §15.2 rule 5 is a MUST NOT precisely because adopting it would
    // silently re-privilege every later call this client makes — and the
    // narrowed token would usually make them *fail*, far from here.
    let _ = client.can("read", uuid::Uuid::new_v4(), None).await;

    let sent = captured.lock().unwrap().clone().flatten();
    assert!(
        !sent.is_some_and(|h| h.contains(ISSUED_TOKEN)),
        "§15.2 rule 5: token_exchange MUST NOT adopt the issued token"
    );
}

#[tokio::test]
async fn the_granted_scope_is_readable_when_narrower_than_requested() {
    let server = MockServer::start().await;
    mount_discovery(&server).await;
    mount_exchange(
        &server,
        ResponseTemplate::new(200).set_body_json(exchange_response(json!({
            "scope": "orders:read",
        }))),
    )
    .await;

    let client = build_client(&server.uri(), true);
    let result = client
        .token_exchange(TokenExchangeParams {
            scopes: Some(vec!["orders:read".into(), "orders:write".into()]),
            ..TokenExchangeParams::new(Sensitive::new(SUBJECT_TOKEN.into()))
        })
        .await
        .expect("exchange");

    assert_eq!(
        result.scope.as_deref(),
        Some("orders:read"),
        "§15.2 rule 7: the response scope is the GRANTED set and may be \
         narrower than requested even on success — applications must be able \
         to read what they actually got"
    );
}

#[tokio::test]
async fn tokens_are_redacted_in_debug_output() {
    let server = MockServer::start().await;
    mount_discovery(&server).await;
    mount_exchange(
        &server,
        ResponseTemplate::new(200).set_body_json(exchange_response(json!({}))),
    )
    .await;

    let client = build_client(&server.uri(), true);
    let result = client
        .token_exchange(TokenExchangeParams::new(Sensitive::new(
            SUBJECT_TOKEN.into(),
        )))
        .await
        .expect("exchange");

    assert!(
        !format!("{result:?}").contains(ISSUED_TOKEN),
        "§15.5: the issued token is a bearer credential"
    );
}

#[tokio::test]
async fn a_failed_exchange_never_echoes_the_subject_token() {
    // §15.5 calls this out specifically: an exchange failure is exactly when
    // a naive implementation logs the request body.
    let server = MockServer::start().await;
    mount_discovery(&server).await;
    mount_exchange(&server, oauth_error("invalid_grant")).await;

    let client = build_client(&server.uri(), true);
    let err = client
        .token_exchange(TokenExchangeParams {
            actor_token: Some(Sensitive::new(ACTOR_TOKEN.into())),
            ..TokenExchangeParams::new(Sensitive::new(SUBJECT_TOKEN.into()))
        })
        .await
        .expect_err("invalid_grant");

    let rendered = format!("{err}{err:?}");
    assert!(!rendered.contains(SUBJECT_TOKEN));
    assert!(!rendered.contains(ACTOR_TOKEN));
}

// ---------------------------------------------------------------------------
// §15.7 — external-IdP subject tokens (X4)
//
// No new operation: the same `token_exchange` carries a partner IdP's token.
// What changes is which subject tokens the server accepts and what its
// refusals mean, so these tests are about not getting in the way of either.
// ---------------------------------------------------------------------------

/// A token minted by a partner's IdP. Opaque to the SDK — deliberately not a
/// well-formed JWT, because nothing here may decode it.
const EXTERNAL_SUBJECT_TOKEN: &str = "partner-idp-subject-token";

/// The one normative `error_description` (§15.7). It means "fix the AXIAM
/// trust configuration", not "fix your token".
const ISSUER_NOT_CONFIGURED: &str =
    "the subject token's issuer is not configured for token exchange";

fn oauth_error_with_description(code: &str, description: &str) -> ResponseTemplate {
    ResponseTemplate::new(400).set_body_json(json!({
        "error": code,
        "error_description": description,
    }))
}

#[tokio::test]
async fn an_external_subject_token_type_is_sent_verbatim() {
    let server = MockServer::start().await;
    mount_discovery(&server).await;
    let forms = mount_exchange(
        &server,
        ResponseTemplate::new(200).set_body_json(exchange_response(json!({
            "scope": "read:orders",
        }))),
    )
    .await;

    let client = build_client(&server.uri(), true);
    let result = client
        .token_exchange(TokenExchangeParams {
            subject_token_type: Some(JWT_TOKEN_TYPE.into()),
            scopes: Some(vec!["read:orders".into()]),
            audience: Some("https://orders.internal".into()),
            ..TokenExchangeParams::new(Sensitive::new(EXTERNAL_SUBJECT_TOKEN.into()))
        })
        .await
        .expect("exchange succeeds");

    let form = forms.lock().unwrap()[0].clone();
    // The caller named …:jwt, so …:jwt goes on the wire. §15.7: the SDK must
    // not inspect the subject token to pick this, and must not override it.
    assert_eq!(
        form.get("subject_token_type").map(String::as_str),
        Some("urn:ietf:params:oauth:token-type:jwt")
    );
    assert_eq!(
        form.get("subject_token").map(String::as_str),
        Some(EXTERNAL_SUBJECT_TOKEN)
    );
    // Delegation across a trust boundary is unsupported; nothing may add one.
    assert!(
        !form.contains_key("actor_token"),
        "§15.7: no actor_token may be invented for an external exchange"
    );

    // The cross-domain path is not a different result shape, and §15.2
    // rules 6-7 still hold.
    assert_eq!(result.access_token.expose(), ISSUED_TOKEN);
    assert_eq!(
        result.issued_token_type,
        "urn:ietf:params:oauth:token-type:access_token"
    );
    assert_eq!(result.scope.as_deref(), Some("read:orders"));
}

#[tokio::test]
async fn the_subject_token_type_is_never_inferred_from_the_token() {
    let server = MockServer::start().await;
    mount_discovery(&server).await;
    let forms = mount_exchange(
        &server,
        ResponseTemplate::new(200).set_body_json(exchange_response(json!({}))),
    )
    .await;

    // A subject token that *looks* exactly like a JWT. An SDK that sniffed
    // the token would send …:jwt here; §15.7 says it must not look, so the
    // caller's silence still means the §15.1 same-domain default.
    let jwt_shaped = "eyJhbGciOiJFZERTQSJ9.eyJpc3MiOiJodHRwczovL3BhcnRuZXIuZXhhbXBsZS8ifQ.sig";
    let client = build_client(&server.uri(), true);
    client
        .token_exchange(TokenExchangeParams::new(Sensitive::new(jwt_shaped.into())))
        .await
        .expect("exchange succeeds");

    assert_eq!(
        forms.lock().unwrap()[0]
            .get("subject_token_type")
            .map(String::as_str),
        Some("urn:ietf:params:oauth:token-type:access_token"),
        "§15.7: the token's shape must not pick the type"
    );
}

#[tokio::test]
async fn an_actor_token_with_an_external_subject_token_is_refused_without_retry() {
    let server = MockServer::start().await;
    mount_discovery(&server).await;
    let forms = mount_exchange(
        &server,
        oauth_error_with_description(
            "invalid_request",
            "actor_token is not supported for an external subject token",
        ),
    )
    .await;

    let client = build_client(&server.uri(), true);
    let err = client
        .token_exchange(TokenExchangeParams {
            subject_token_type: Some(JWT_TOKEN_TYPE.into()),
            actor_token: Some(Sensitive::new(ACTOR_TOKEN.into())),
            ..TokenExchangeParams::new(Sensitive::new(EXTERNAL_SUBJECT_TOKEN.into()))
        })
        .await
        .expect_err("refusal");

    assert_eq!(err.oauth_error_code(), Some("invalid_request"));

    // §15.7: no retry, and no rewriting. Dropping the actor token and
    // re-sending would turn a delegation the caller asked for into an
    // impersonation they did not.
    let forms = forms.lock().unwrap().clone();
    assert_eq!(forms.len(), 1, "exactly one request");
    assert_eq!(
        forms[0].get("actor_token").map(String::as_str),
        Some(ACTOR_TOKEN),
        "the request must be sent as written, actor token included"
    );
    assert_eq!(
        forms[0].get("subject_token_type").map(String::as_str),
        Some("urn:ietf:params:oauth:token-type:jwt"),
        "subject_token_type must not be rewritten"
    );
}

#[tokio::test]
async fn a_refused_subject_token_type_is_never_retried_as_another() {
    // A refresh token is a re-authentication credential and an ID token is an
    // assertion to a client about a login; neither is a bearer credential for
    // an API, so both are refused BY NAME. Retrying as …:jwt would present one
    // as if it were.
    for refused in [
        "urn:ietf:params:oauth:token-type:refresh_token",
        "urn:ietf:params:oauth:token-type:id_token",
    ] {
        let server = MockServer::start().await;
        mount_discovery(&server).await;
        let forms = mount_exchange(
            &server,
            oauth_error_with_description(
                "invalid_request",
                &format!("unsupported subject_token_type {refused}"),
            ),
        )
        .await;

        let client = build_client(&server.uri(), true);
        client
            .token_exchange(TokenExchangeParams {
                subject_token_type: Some(refused.into()),
                ..TokenExchangeParams::new(Sensitive::new(EXTERNAL_SUBJECT_TOKEN.into()))
            })
            .await
            .expect_err("refusal");

        let forms = forms.lock().unwrap().clone();
        assert_eq!(forms.len(), 1, "no retry after a refused type");
        assert_eq!(
            forms[0].get("subject_token_type").map(String::as_str),
            Some(refused),
            "§15.7: the refused type must be sent as named, not swapped"
        );
    }
}

#[tokio::test]
async fn the_issuer_not_configured_description_reaches_the_caller_intact() {
    let server = MockServer::start().await;
    mount_discovery(&server).await;
    mount_exchange(
        &server,
        oauth_error_with_description("invalid_grant", ISSUER_NOT_CONFIGURED),
    )
    .await;

    let client = build_client(&server.uri(), true);
    let err = client
        .token_exchange(TokenExchangeParams {
            subject_token_type: Some(JWT_TOKEN_TYPE.into()),
            ..TokenExchangeParams::new(Sensitive::new(EXTERNAL_SUBJECT_TOKEN.into()))
        })
        .await
        .expect_err("refusal");

    assert_eq!(err.oauth_error_code(), Some("invalid_grant"));
    // This is the ONLY distinguishable external failure, and the whole point
    // of it is that an integrator can tell "fix the AXIAM trust config" from
    // "fix your token". Truncating or rewording it destroys that.
    assert!(
        err.to_string().contains(ISSUER_NOT_CONFIGURED),
        "the normative description must reach the caller intact, got: {err}"
    );
}

#[tokio::test]
async fn no_helper_re_exchanges_an_externally_exchanged_token() {
    // Tokens minted from an external subject token carry `ext_exchange`, and
    // BOTH exchange paths refuse a subject token bearing it: exchanges do not
    // compose. The SDK's part is to never feed a result back in by itself.
    let server = MockServer::start().await;
    mount_discovery(&server).await;

    let exchanges = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&exchanges);
    Mock::given(method("POST"))
        .and(path("/oauth2/token"))
        .respond_with(move |_: &Request| {
            counter.fetch_add(1, Ordering::SeqCst);
            ResponseTemplate::new(200).set_body_json(exchange_response(json!({})))
        })
        .mount(&server)
        .await;

    let captured: Arc<Mutex<Option<Option<String>>>> = Arc::new(Mutex::new(None));
    let sink = Arc::clone(&captured);
    Mock::given(method("POST"))
        .and(path("/api/v1/authz/check"))
        .respond_with(move |req: &Request| {
            *sink.lock().unwrap() = Some(
                req.headers
                    .get("authorization")
                    .map(|v| v.to_str().unwrap().to_string()),
            );
            ResponseTemplate::new(200).set_body_json(json!({ "allowed": true }))
        })
        .mount(&server)
        .await;

    let client = build_client(&server.uri(), true);
    let exchanged = client
        .token_exchange(TokenExchangeParams {
            subject_token_type: Some(JWT_TOKEN_TYPE.into()),
            ..TokenExchangeParams::new(Sensitive::new(EXTERNAL_SUBJECT_TOKEN.into()))
        })
        .await
        .expect("exchange");
    assert_eq!(exchanged.access_token.expose(), ISSUED_TOKEN);

    let _ = client.can("read", uuid::Uuid::new_v4(), None).await;

    // Exactly one exchange happened: nothing looped the result back in.
    assert_eq!(
        exchanges.load(Ordering::SeqCst),
        1,
        "exactly one exchange — no helper re-exchanged the issued token"
    );
    // §15.2 rule 5 restated for the cross-domain path: had the result been
    // adopted, the next call would carry it — and the next exchange would
    // carry it as a *subject* token, which is exactly the re-exchange §15.7
    // forbids, arrived at by accident rather than by decision.
    let sent = captured.lock().unwrap().clone().flatten();
    assert!(
        !sent.is_some_and(|h| h.contains(ISSUED_TOKEN)),
        "an externally exchanged token must never become this client's credential"
    );
}
