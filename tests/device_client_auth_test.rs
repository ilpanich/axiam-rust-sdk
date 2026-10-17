//! Device Authorization Grant client authentication — CONTRACT.md §14.1 rules
//! 1–4, §14.2 rules 5 and 8, §14.6 (contract 1.62, maintainer 2026-10-16).
//!
//! Against a mocked server, per endpoint:
//!
//! * a client **configured with a secret** sends it as `client_secret` in the
//!   **form body** at `device_authorize` and at every `device_poll`, and sends
//!   **no `Authorization` header** at either — whichever of `client_secret_post`
//!   and `client_secret_basic` the client is registered for;
//! * a **public** client sends neither a secret nor any other credential, and is
//!   not refused client-side;
//! * an **mTLS** client (a certificate, no secret) sends no secret, and goes to
//!   the `mtls_endpoint_aliases` entry of each endpoint;
//! * `device_poll` sends `client_id` on every poll;
//! * a `401 {"error":"invalid_client"}` from either operation raises an
//!   `OAuthProtocolError` with that `error`, makes exactly one request (no
//!   retry) and does not enter the §9 refresh guard;
//! * a `token_type: DPoP` answer is surfaced as such. (This SDK verifies DPoP
//!   proofs and does not generate them, §21.7.3, so "a DPoP proof on every poll"
//!   is not applicable; a bound client's missing proof is the `401` above.)
//!
//! `private_key_jwt` is not tested because this SDK has no way to configure it.

#![cfg(feature = "rest")]

#[path = "oidc_support/mod.rs"]
mod oidc_support;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axiam_sdk::AxiamError;
use axiam_sdk::Sensitive;
use axiam_sdk::oidc::{DeviceAuthorizeParams, DeviceLoginParams, DevicePollParams};
use serde_json::{Value, json};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

use oidc_support::{
    CLIENT_ID, CLIENT_SECRET, build_client, build_mtls_client, discovery_document,
    discovery_document_with_aliases,
};

const DEVICE_CODE: &str = "device-code-value";

/// What one request carried.
#[derive(Debug, Clone)]
struct Seen {
    form: HashMap<String, String>,
    authorization: Option<String>,
}

type Log = Arc<Mutex<Vec<Seen>>>;

fn authorization_body() -> Value {
    json!({
        "device_code": DEVICE_CODE, "user_code": "WDJB-MJHT",
        "verification_uri": "https://iam.example.com/device",
        "expires_in": 30, "interval": 1,
    })
}

fn pending() -> ResponseTemplate {
    ResponseTemplate::new(400).set_body_json(json!({
        "error": "authorization_pending", "error_description": "not yet",
    }))
}

fn success(token_type: &str) -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_json(json!({
        "access_token": "device-access-token", "token_type": token_type, "expires_in": 900,
    }))
}

fn invalid_client() -> ResponseTemplate {
    ResponseTemplate::new(401).set_body_json(json!({
        "error": "invalid_client", "error_description": "client authentication failed",
    }))
}

async fn mount_discovery(server: &MockServer, document: Value) {
    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(200).set_body_json(document))
        .mount(server)
        .await;
}

/// Mount `route` on `server`, answering from `script` in order (the last entry
/// repeats), and recording what every request carried.
async fn mount_recording(server: &MockServer, route: &str, script: Vec<ResponseTemplate>) -> Log {
    let log: Log = Arc::default();
    let sink = Arc::clone(&log);
    let script = Arc::new(Mutex::new(script));
    let calls = Arc::new(Mutex::new(0usize));
    Mock::given(method("POST"))
        .and(path(route.to_string()))
        .respond_with(move |req: &Request| {
            sink.lock().unwrap().push(Seen {
                form: url::form_urlencoded::parse(&req.body)
                    .into_owned()
                    .collect(),
                authorization: req
                    .headers
                    .get("authorization")
                    .map(|v| v.to_str().unwrap().to_string()),
            });
            let mut n = calls.lock().unwrap();
            let script = script.lock().unwrap();
            let i = (*n).min(script.len() - 1);
            *n += 1;
            script[i].clone()
        })
        .mount(server)
        .await;
    log
}

fn snapshot(log: &Log) -> Vec<Seen> {
    log.lock().unwrap().clone()
}

fn poll_params() -> DevicePollParams {
    DevicePollParams {
        device_code: Sensitive::new(DEVICE_CODE.to_string()),
        tenant_id: None,
        configuration: None,
    }
}

/// Every credential-bearing member of a device request.
fn credential_members(seen: &Seen) -> Vec<&str> {
    ["client_secret", "client_assertion", "client_assertion_type"]
        .into_iter()
        .filter(|k| seen.form.contains_key(*k))
        .collect()
}

async fn refresh_requests(server: &MockServer) -> usize {
    server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .filter(|r| r.url.path().contains("refresh"))
        .count()
}

// ── a confidential client ───────────────────────────────────────────────────

/// Whichever method the client is registered for, a client configured with a
/// secret sends it in the **form body** at `device_authorize` and at every poll,
/// and sends no `Authorization` header at either.
#[tokio::test]
async fn a_configured_secret_is_in_the_form_body_at_both_endpoints_and_never_basic() {
    for registered in ["client_secret_post", "client_secret_basic"] {
        let server = MockServer::start().await;
        let mut document = discovery_document(&server.uri());
        document["token_endpoint_auth_methods_supported"] = json!([registered]);
        mount_discovery(&server, document).await;
        let authorize = mount_recording(
            &server,
            "/oauth2/device_authorization",
            vec![ResponseTemplate::new(200).set_body_json(authorization_body())],
        )
        .await;
        let polls = mount_recording(
            &server,
            "/oauth2/token",
            vec![pending(), pending(), success("Bearer")],
        )
        .await;

        let client = build_client(&server.uri(), true);
        let started = client
            .device_authorize(DeviceAuthorizeParams::default())
            .await
            .expect("device_authorize");
        assert_eq!(started.user_code, "WDJB-MJHT");
        for _ in 0..2 {
            let err = client.device_poll(poll_params()).await.unwrap_err();
            assert_eq!(err.oauth_error_code(), Some("authorization_pending"));
        }
        client.device_poll(poll_params()).await.expect("approved");

        let authorize = snapshot(&authorize);
        assert_eq!(authorize.len(), 1);
        let polls = snapshot(&polls);
        assert_eq!(polls.len(), 3, "every poll, not only the first");
        for seen in authorize.iter().chain(polls.iter()) {
            assert_eq!(
                seen.form.get("client_secret").map(String::as_str),
                Some(CLIENT_SECRET),
                "{registered}: the secret is a form member"
            );
            assert_eq!(
                seen.form.get("client_id").map(String::as_str),
                Some(CLIENT_ID)
            );
            assert_eq!(
                seen.authorization, None,
                "{registered}: no Authorization header at either endpoint (§12.1 rule 3)"
            );
        }
    }
}

/// `device_login` is the two operations composed: the same credential reaches
/// both, on every poll it makes.
#[tokio::test]
async fn device_login_authenticates_at_authorize_and_at_each_poll() {
    let server = MockServer::start().await;
    mount_discovery(&server, discovery_document(&server.uri())).await;
    let authorize = mount_recording(
        &server,
        "/oauth2/device_authorization",
        vec![ResponseTemplate::new(200).set_body_json(authorization_body())],
    )
    .await;
    let polls = mount_recording(&server, "/oauth2/token", vec![pending(), success("Bearer")]).await;

    let client = build_client(&server.uri(), true);
    let tokens = client
        .device_login(DeviceLoginParams::default(), |_| {})
        .await
        .expect("device_login");
    assert_eq!(tokens.token_type, "Bearer");

    for seen in snapshot(&authorize).iter().chain(snapshot(&polls).iter()) {
        assert_eq!(
            seen.form.get("client_secret").map(String::as_str),
            Some(CLIENT_SECRET)
        );
        assert_eq!(seen.authorization, None);
    }
    assert_eq!(snapshot(&polls).len(), 2);
}

// ── a public client ─────────────────────────────────────────────────────────

/// A client configured with no secret sends no credential at either endpoint,
/// is not refused client-side, and the poll still names its client.
#[tokio::test]
async fn a_public_client_sends_no_credential_and_is_not_refused() {
    let server = MockServer::start().await;
    mount_discovery(&server, discovery_document(&server.uri())).await;
    let authorize = mount_recording(
        &server,
        "/oauth2/device_authorization",
        vec![ResponseTemplate::new(200).set_body_json(authorization_body())],
    )
    .await;
    let polls = mount_recording(&server, "/oauth2/token", vec![pending(), success("Bearer")]).await;

    let client = build_client(&server.uri(), false);
    client
        .device_authorize(DeviceAuthorizeParams::default())
        .await
        .expect("not refused client-side");
    client.device_poll(poll_params()).await.unwrap_err();
    client.device_poll(poll_params()).await.expect("approved");

    let authorize = snapshot(&authorize);
    let polls = snapshot(&polls);
    assert_eq!((authorize.len(), polls.len()), (1, 2));
    for seen in authorize.iter().chain(polls.iter()) {
        assert!(credential_members(seen).is_empty(), "{seen:?}");
        assert_eq!(seen.authorization, None);
        assert_eq!(
            seen.form.get("client_id").map(String::as_str),
            Some(CLIENT_ID)
        );
    }
    for seen in &polls {
        assert_eq!(
            seen.form.get("grant_type").map(String::as_str),
            Some("urn:ietf:params:oauth:grant-type:device_code")
        );
    }
}

// ── an mTLS client ──────────────────────────────────────────────────────────

/// A client holding a certificate and no secret presents the certificate (here:
/// goes to the `mtls_endpoint_aliases` origin of each endpoint — the mock speaks
/// plain HTTP, so the handshake itself is not exercised) and sends no secret.
#[tokio::test]
async fn an_mtls_client_uses_the_aliases_and_sends_no_secret() {
    let front = MockServer::start().await;
    let mtls = MockServer::start().await;
    mount_discovery(
        &front,
        discovery_document_with_aliases(&front.uri(), &mtls.uri()),
    )
    .await;
    let front_authorize = mount_recording(
        &front,
        "/oauth2/device_authorization",
        vec![ResponseTemplate::new(200).set_body_json(authorization_body())],
    )
    .await;
    let front_poll = mount_recording(&front, "/oauth2/token", vec![success("Bearer")]).await;
    let authorize = mount_recording(
        &mtls,
        "/oauth2/device_authorization",
        vec![ResponseTemplate::new(200).set_body_json(authorization_body())],
    )
    .await;
    let polls = mount_recording(&mtls, "/oauth2/token", vec![pending(), success("Bearer")]).await;

    let client = build_mtls_client(&front.uri(), false);
    client
        .device_authorize(DeviceAuthorizeParams::default())
        .await
        .expect("device_authorize");
    client.device_poll(poll_params()).await.unwrap_err();
    client.device_poll(poll_params()).await.expect("approved");

    assert!(snapshot(&front_authorize).is_empty() && snapshot(&front_poll).is_empty());
    let authorize = snapshot(&authorize);
    let polls = snapshot(&polls);
    assert_eq!((authorize.len(), polls.len()), (1, 2), "both at the alias");
    for seen in authorize.iter().chain(polls.iter()) {
        assert!(credential_members(seen).is_empty(), "no secret: {seen:?}");
        assert_eq!(seen.authorization, None);
        assert_eq!(
            seen.form.get("client_id").map(String::as_str),
            Some(CLIENT_ID)
        );
    }
}

/// A certificate **and** a secret: the same rules as the client's other token
/// requests — the secret still rides in the form body.
#[tokio::test]
async fn an_mtls_client_with_a_secret_sends_both() {
    let front = MockServer::start().await;
    let mtls = MockServer::start().await;
    mount_discovery(
        &front,
        discovery_document_with_aliases(&front.uri(), &mtls.uri()),
    )
    .await;
    let authorize = mount_recording(
        &mtls,
        "/oauth2/device_authorization",
        vec![ResponseTemplate::new(200).set_body_json(authorization_body())],
    )
    .await;
    let polls = mount_recording(&mtls, "/oauth2/token", vec![success("Bearer")]).await;

    let client = build_mtls_client(&front.uri(), true);
    client
        .device_authorize(DeviceAuthorizeParams::default())
        .await
        .unwrap();
    client.device_poll(poll_params()).await.unwrap();

    for seen in snapshot(&authorize).iter().chain(snapshot(&polls).iter()) {
        assert_eq!(
            seen.form.get("client_secret").map(String::as_str),
            Some(CLIENT_SECRET)
        );
        assert_eq!(seen.authorization, None);
    }
}

// ── 401 invalid_client ──────────────────────────────────────────────────────

/// A `401 invalid_client` from `device_authorize` raises an `OAuthProtocolError`
/// with that `error`, after exactly one request, and does not enter the §9
/// refresh guard.
#[tokio::test]
async fn a_401_at_device_authorize_is_invalid_client_once() {
    let server = MockServer::start().await;
    mount_discovery(&server, discovery_document(&server.uri())).await;
    let authorize = mount_recording(
        &server,
        "/oauth2/device_authorization",
        vec![invalid_client()],
    )
    .await;

    let client = build_client(&server.uri(), true);
    let err = client
        .device_authorize(DeviceAuthorizeParams::default())
        .await
        .unwrap_err();

    assert!(matches!(err, AxiamError::Auth { .. }), "{err:?}");
    assert_eq!(err.oauth_error_code(), Some("invalid_client"));
    assert_eq!(snapshot(&authorize).len(), 1, "no retry");
    assert_eq!(refresh_requests(&server).await, 0, "not an expired session");
}

/// ... and from `device_poll`; and through `device_login` it is terminal on the
/// first poll that meets it.
#[tokio::test]
async fn a_401_at_the_poll_is_invalid_client_terminal_and_never_refreshed() {
    let server = MockServer::start().await;
    mount_discovery(&server, discovery_document(&server.uri())).await;
    let authorize = mount_recording(
        &server,
        "/oauth2/device_authorization",
        vec![ResponseTemplate::new(200).set_body_json(authorization_body())],
    )
    .await;
    let polls = mount_recording(&server, "/oauth2/token", vec![invalid_client()]).await;

    let client = build_client(&server.uri(), true);
    let err = client.device_poll(poll_params()).await.unwrap_err();
    assert!(matches!(err, AxiamError::Auth { .. }), "{err:?}");
    assert_eq!(err.oauth_error_code(), Some("invalid_client"));
    assert_eq!(snapshot(&polls).len(), 1, "no retry");

    let err = client
        .device_login(DeviceLoginParams::default(), |_| {})
        .await
        .unwrap_err();
    assert_eq!(err.oauth_error_code(), Some("invalid_client"));
    assert_eq!(snapshot(&authorize).len(), 1);
    assert_eq!(snapshot(&polls).len(), 2, "one more poll, then terminal");
    assert_eq!(refresh_requests(&server).await, 0);
}

// ── a DPoP-bound client ─────────────────────────────────────────────────────

/// A response whose `token_type` is `DPoP` is surfaced as the server said it —
/// never assumed to be `Bearer` (§14.2 rule 8, §21.7.1). This SDK generates no
/// proof, so a bound client's own poll meets the `401` of the test above.
#[tokio::test]
async fn a_dpop_token_type_is_surfaced_as_is() {
    let server = MockServer::start().await;
    mount_discovery(&server, discovery_document(&server.uri())).await;
    mount_recording(&server, "/oauth2/token", vec![success("DPoP")]).await;

    let client = build_client(&server.uri(), true);
    let tokens = client.device_poll(poll_params()).await.expect("approved");
    assert_eq!(tokens.token_type, "DPoP");
}
