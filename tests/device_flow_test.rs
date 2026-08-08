//! Device Authorization Grant — CONTRACT.md §14.
//!
//! The §14.6 required assertions split across two levels, deliberately:
//!
//! * **Interval arithmetic** — the interval comes from the response,
//!   `slow_down` raises it, the raise PERSISTS, polling stops at
//!   `expires_in` — is unit-tested against `PollSchedule` in
//!   `src/oidc/device.rs`. It is pure logic, so it is asserted exactly and
//!   instantly, including cases (a 30-minute grant, three cumulative
//!   `slow_down`s) that no wall-clock test could reach.
//!
//! * **Wire behaviour** lives here: which answers loop, which terminate,
//!   how many requests the loop actually sends, and the §14.3 rule 2
//!   ordering guarantee. Intervals in these fixtures are 1 s so the suite
//!   runs in seconds.
//!
//! A paused tokio clock cannot drive the second group: with time paused the
//! runtime auto-advances whenever every task is idle, including while one is
//! genuinely awaiting a socket, which fires `reqwest`'s own timeout before
//! the mock server can answer. That is why the split above is a design
//! choice rather than a convenience.

#![cfg(feature = "rest")]

#[path = "oidc_support/mod.rs"]
mod oidc_support;

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use axiam_sdk::AxiamError;
use axiam_sdk::Sensitive;
use axiam_sdk::oidc::{
    DEFAULT_POLL_INTERVAL_SECS, DeviceAuthorizeParams, DeviceLoginParams, DevicePollParams,
};
use serde_json::json;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

use oidc_support::{
    build_client, discovery_document, discovery_document_without_optional_endpoints,
};

const DEVICE_CODE: &str = "device-code-value";
const USER_CODE: &str = "WDJB-MJHT";

fn parse_form(body: &[u8]) -> HashMap<String, String> {
    url::form_urlencoded::parse(body).into_owned().collect()
}

/// What `device_authorize_is_unauthenticated_and_form_encoded` records off the
/// wire: the form body, the `Content-Type`, and the `tenant_id` query param.
struct CapturedRequest {
    form: HashMap<String, String>,
    content_type: Option<String>,
    tenant_id_query: Option<String>,
}

fn device_authorization_body(overrides: serde_json::Value) -> serde_json::Value {
    let mut base = json!({
        "device_code": DEVICE_CODE,
        "user_code": USER_CODE,
        "verification_uri": "https://iam.example.com/device",
        "verification_uri_complete": "https://iam.example.com/device?user_code=WDJB-MJHT",
        "expires_in": 30,
        "interval": 1,
    });
    if let (Some(b), Some(o)) = (base.as_object_mut(), overrides.as_object()) {
        for (k, v) in o {
            b.insert(k.clone(), v.clone());
        }
    }
    base
}

fn oauth_error(code: &str) -> serde_json::Value {
    json!({ "error": code, "error_description": format!("{code} description") })
}

async fn mount_discovery(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(200).set_body_json(discovery_document(&server.uri())))
        .mount(server)
        .await;
}

async fn mount_device_authorization(server: &MockServer, body: serde_json::Value) {
    Mock::given(method("POST"))
        .and(path("/oauth2/device_authorization"))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .mount(server)
        .await;
}

/// Mount `/oauth2/token` answering from a scripted sequence, recording how
/// many requests arrived. Interval *arithmetic* is unit-tested against
/// `PollSchedule` in `src/oidc/device.rs`; what these integration tests
/// assert is the wire behaviour — which answers loop, which terminate, and
/// how many requests the loop actually sends.
async fn mount_token_script(
    server: &MockServer,
    script: Vec<ResponseTemplate>,
) -> Arc<Mutex<Vec<tokio::time::Instant>>> {
    let calls = Arc::new(AtomicUsize::new(0));
    let stamps: Arc<Mutex<Vec<tokio::time::Instant>>> = Arc::new(Mutex::new(Vec::new()));
    let stamps_for_mock = Arc::clone(&stamps);
    let script = Arc::new(Mutex::new(script));

    Mock::given(method("POST"))
        .and(path("/oauth2/token"))
        .respond_with(move |_: &Request| {
            stamps_for_mock
                .lock()
                .unwrap()
                .push(tokio::time::Instant::now());
            let i = calls.fetch_add(1, Ordering::SeqCst);
            let script = script.lock().unwrap();
            script
                .get(i)
                .cloned()
                .unwrap_or_else(|| script.last().cloned().expect("non-empty script"))
        })
        .mount(server)
        .await;

    stamps
}

fn pending() -> ResponseTemplate {
    ResponseTemplate::new(400).set_body_json(oauth_error("authorization_pending"))
}
fn slow_down() -> ResponseTemplate {
    ResponseTemplate::new(400).set_body_json(oauth_error("slow_down"))
}
fn success() -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_json(json!({
        "access_token": "device-access-token",
        "token_type": "Bearer",
        "expires_in": 900,
        "refresh_token": "device-refresh-token",
    }))
}

// ---------------------------------------------------------------------------
// device_authorize
// ---------------------------------------------------------------------------

#[tokio::test]
async fn device_authorize_is_unauthenticated_and_form_encoded() {
    let server = MockServer::start().await;
    mount_discovery(&server).await;

    let captured: Arc<Mutex<Option<CapturedRequest>>> = Arc::new(Mutex::new(None));
    let sink = Arc::clone(&captured);

    Mock::given(method("POST"))
        .and(path("/oauth2/device_authorization"))
        .respond_with(move |req: &Request| {
            let form = parse_form(&req.body);
            let ct = req
                .headers
                .get("content-type")
                .map(|v| v.to_str().unwrap().to_string());
            let tenant_q = req
                .url
                .query_pairs()
                .find(|(k, _)| k == "tenant_id")
                .map(|(_, v)| v.to_string());
            *sink.lock().unwrap() = Some(CapturedRequest {
                form,
                content_type: ct,
                tenant_id_query: tenant_q,
            });
            ResponseTemplate::new(200).set_body_json(device_authorization_body(json!({})))
        })
        .mount(&server)
        .await;

    // Built WITHOUT a client secret: §14.1 says a device that cannot show a
    // browser cannot hold one, and the SDK must not refuse such a client.
    let client = build_client(&server.uri(), false);
    let auth = client
        .device_authorize(DeviceAuthorizeParams {
            scope: Some("openid profile".into()),
            ..Default::default()
        })
        .await
        .expect("device_authorize succeeds without a client secret");

    let captured = captured.lock().unwrap();
    let CapturedRequest {
        form,
        content_type,
        tenant_id_query,
    } = captured.as_ref().expect("captured");
    assert_eq!(
        content_type.as_deref(),
        Some("application/x-www-form-urlencoded"),
        "§12.1: form-encoded body"
    );
    assert!(
        tenant_id_query.is_some(),
        "§12.1 note 2: tenant_id is a QUERY param"
    );
    assert!(
        !form.contains_key("tenant_id"),
        "§12.1 note 2: tenant_id is never a body field"
    );
    assert!(
        !form.contains_key("client_secret"),
        "§14.1: device_authorize MUST NOT send client_secret"
    );
    assert_eq!(
        form.get("scope").map(String::as_str),
        Some("openid profile")
    );

    assert_eq!(auth.user_code, USER_CODE);
    assert_eq!(auth.interval, 1);
    assert_eq!(
        auth.verification_uri_complete.as_deref(),
        Some("https://iam.example.com/device?user_code=WDJB-MJHT")
    );
}

#[tokio::test]
async fn absent_interval_defaults_to_five_seconds_not_faster() {
    let server = MockServer::start().await;
    mount_discovery(&server).await;
    mount_device_authorization(
        &server,
        device_authorization_body(json!({ "interval": serde_json::Value::Null })),
    )
    .await;

    let client = build_client(&server.uri(), false);
    let auth = client
        .device_authorize(DeviceAuthorizeParams::default())
        .await
        .expect("device_authorize");

    assert_eq!(
        auth.interval, DEFAULT_POLL_INTERVAL_SECS,
        "§14.2 rule 2: absent interval defaults to 5 s; an SDK MUST NOT hard-code a faster floor"
    );
}

#[tokio::test]
async fn device_authorize_errors_when_server_advertises_no_endpoint() {
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
    let err = client
        .device_authorize(DeviceAuthorizeParams::default())
        .await
        .expect_err("no device_authorization_endpoint means no device grant");

    assert!(matches!(err, AxiamError::Auth { .. }));
    assert!(
        err.to_string().contains("device_authorization_endpoint"),
        "the error names the missing endpoint rather than guessing a URL: {err}"
    );
}

// ---------------------------------------------------------------------------
// §14.2 polling
// ---------------------------------------------------------------------------

#[tokio::test]
async fn authorization_pending_loops_rather_than_raising() {
    let server = MockServer::start().await;
    mount_discovery(&server).await;
    mount_device_authorization(&server, device_authorization_body(json!({}))).await;
    let stamps =
        mount_token_script(&server, vec![pending(), pending(), pending(), success()]).await;

    let client = build_client(&server.uri(), false);
    let tokens = client
        .device_login(DeviceLoginParams::default(), |_| {})
        .await
        .expect("authorization_pending is not an error");

    assert_eq!(stamps.lock().unwrap().len(), 4);
    assert_eq!(tokens.access_token.expose(), "device-access-token");
}

#[tokio::test]
async fn slow_down_loops_rather_than_raising() {
    // The *arithmetic* of the back-off is unit-tested (PollSchedule); what
    // matters here is that `slow_down` is not mistaken for a terminal answer.
    // An SDK that let it fall through to the terminal arm would abort a grant
    // the user is still in the middle of approving.
    let server = MockServer::start().await;
    mount_discovery(&server).await;
    mount_device_authorization(&server, device_authorization_body(json!({ "interval": 1 }))).await;
    let stamps = mount_token_script(&server, vec![slow_down(), pending(), success()]).await;

    let client = build_client(&server.uri(), false);
    let tokens = client
        .device_login(DeviceLoginParams::default(), |_| {})
        .await
        .expect("slow_down is not terminal");

    assert_eq!(stamps.lock().unwrap().len(), 3);
    assert_eq!(tokens.access_token.expose(), "device-access-token");
}

#[tokio::test]
async fn access_denied_and_expired_token_are_distinct_errors() {
    // §14.2 rule 3: "a human said no" and "nobody answered" are the only two
    // pieces of information the device can act on. Collapsing them loses it.
    for (code, other) in [
        ("access_denied", "expired_token"),
        ("expired_token", "access_denied"),
    ] {
        let server = MockServer::start().await;
        mount_discovery(&server).await;
        mount_device_authorization(&server, device_authorization_body(json!({}))).await;
        mount_token_script(
            &server,
            vec![ResponseTemplate::new(400).set_body_json(oauth_error(code))],
        )
        .await;

        let client = build_client(&server.uri(), false);
        let err = client
            .device_login(DeviceLoginParams::default(), |_| {})
            .await
            .expect_err("terminal");

        assert_eq!(
            err.oauth_error_code(),
            Some(code),
            "the RFC 8628 error code reaches the caller verbatim"
        );
        assert_ne!(
            err.oauth_error_code(),
            Some(other),
            "{code} must not be reported as {other}"
        );
    }
}

#[tokio::test]
async fn invalid_grant_is_terminal() {
    let server = MockServer::start().await;
    mount_discovery(&server).await;
    mount_device_authorization(&server, device_authorization_body(json!({}))).await;
    let stamps = mount_token_script(
        &server,
        vec![ResponseTemplate::new(400).set_body_json(oauth_error("invalid_grant"))],
    )
    .await;

    let client = build_client(&server.uri(), false);
    let err = client
        .device_login(DeviceLoginParams::default(), |_| {})
        .await
        .expect_err("invalid_grant is terminal");

    assert_eq!(err.oauth_error_code(), Some("invalid_grant"));
    assert_eq!(
        stamps.lock().unwrap().len(),
        1,
        "a terminal answer stops the loop immediately"
    );
}

#[tokio::test]
async fn polling_stops_at_expires_in() {
    let server = MockServer::start().await;
    mount_discovery(&server).await;
    // 12-second grant, 5-second interval: polls at t=5 and t=10, then the
    // t=15 tick is past the deadline and must not be sent.
    mount_device_authorization(
        &server,
        device_authorization_body(json!({ "expires_in": 2, "interval": 1 })),
    )
    .await;
    let stamps = mount_token_script(&server, vec![pending()]).await;

    let client = build_client(&server.uri(), false);
    let err = client
        .device_login(DeviceLoginParams::default(), |_| {})
        .await
        .expect_err("the grant expires");

    assert_eq!(
        err.oauth_error_code(),
        Some("expired_token"),
        "§14.2 rule 4: reported under the same code the server would have used, \
         so a caller's match arm does not care which side noticed first"
    );
    assert_eq!(
        stamps.lock().unwrap().len(),
        1,
        "§14.2 rule 4: the deadline is authoritative — no poll is sent past it \
         even though the server was still answering authorization_pending"
    );
}

#[tokio::test]
async fn server_error_mid_poll_is_retried_not_terminal() {
    let server = MockServer::start().await;
    mount_discovery(&server).await;
    mount_device_authorization(&server, device_authorization_body(json!({}))).await;
    let stamps = mount_token_script(
        &server,
        vec![
            pending(),
            ResponseTemplate::new(500).set_body_string("upstream restarting"),
            ResponseTemplate::new(503).set_body_string("still restarting"),
            success(),
        ],
    )
    .await;

    let client = build_client(&server.uri(), false);
    let tokens = client
        .device_login(DeviceLoginParams::default(), |_| {})
        .await
        .expect("§14.2 rule 6: a server restart must not lose an approved grant");

    assert_eq!(stamps.lock().unwrap().len(), 4);
    assert_eq!(tokens.access_token.expose(), "device-access-token");
}

// ---------------------------------------------------------------------------
// §14.3 device_login
// ---------------------------------------------------------------------------

#[tokio::test]
async fn device_login_surfaces_the_user_code_before_the_first_poll() {
    let server = MockServer::start().await;
    mount_discovery(&server).await;
    mount_device_authorization(&server, device_authorization_body(json!({}))).await;

    // Ordering, not just presence (§14.6). A shared log records both events;
    // an SDK that polled first would show "poll" ahead of "user_code".
    let log: Arc<Mutex<Vec<&'static str>>> = Arc::new(Mutex::new(Vec::new()));
    let log_for_mock = Arc::clone(&log);

    Mock::given(method("POST"))
        .and(path("/oauth2/token"))
        .respond_with(move |_: &Request| {
            log_for_mock.lock().unwrap().push("poll");
            success()
        })
        .mount(&server)
        .await;

    let log_for_cb = Arc::clone(&log);
    let seen: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let seen_for_cb = Arc::clone(&seen);

    let client = build_client(&server.uri(), false);
    client
        .device_login(DeviceLoginParams::default(), move |auth| {
            log_for_cb.lock().unwrap().push("user_code");
            *seen_for_cb.lock().unwrap() = Some(auth.user_code.clone());
        })
        .await
        .expect("device_login");

    assert_eq!(
        log.lock().unwrap().as_slice(),
        ["user_code", "poll"],
        "§14.3 rule 2: the caller must have had the chance to display the code \
         BEFORE polling begins"
    );
    assert_eq!(seen.lock().unwrap().as_deref(), Some(USER_CODE));
}

#[tokio::test]
async fn successful_device_login_returns_a_token_set_carrying_the_access_token() {
    let server = MockServer::start().await;
    mount_discovery(&server).await;
    mount_device_authorization(&server, device_authorization_body(json!({}))).await;
    mount_token_script(&server, vec![success()]).await;

    let client = build_client(&server.uri(), false);
    let tokens = client
        .device_login(DeviceLoginParams::default(), |_| {})
        .await
        .expect("device_login");

    // §14.6 as amended by the contract 1.7 errata: the assertion is on the
    // returned token set. This SDK does not adopt (§14.3 rule 4 defers to the
    // §12.1 login_client_credentials MAY, and Rust's settled posture there is
    // to leave the tokens with the caller), so asserting "the client is now
    // authenticated" would be asserting a behaviour this SDK deliberately
    // does not have.
    assert_eq!(tokens.access_token.expose(), "device-access-token");
    assert_eq!(tokens.token_type, "Bearer");
    assert!(tokens.refresh_token.is_some());
}

#[tokio::test]
async fn device_code_is_redacted_and_user_code_is_not() {
    let server = MockServer::start().await;
    mount_discovery(&server).await;
    mount_device_authorization(&server, device_authorization_body(json!({}))).await;

    let client = build_client(&server.uri(), false);
    let auth = client
        .device_authorize(DeviceAuthorizeParams::default())
        .await
        .expect("device_authorize");

    let rendered = format!("{auth:?}");
    assert!(
        !rendered.contains(DEVICE_CODE),
        "§14.5: device_code is a bearer credential and must never render"
    );
    assert!(
        rendered.contains(USER_CODE),
        "§14.5: user_code is NOT wrapped — it exists to be read aloud, and \
         wrapping it would defeat the one thing it is for"
    );
}

// ---------------------------------------------------------------------------
// device_poll standalone
// ---------------------------------------------------------------------------

#[tokio::test]
async fn device_poll_surfaces_pending_answers_for_hand_rolled_loops() {
    let server = MockServer::start().await;
    mount_discovery(&server).await;
    mount_token_script(&server, vec![pending()]).await;

    let client = build_client(&server.uri(), false);
    let err = client
        .device_poll(DevicePollParams {
            device_code: Sensitive::new(DEVICE_CODE.to_string()),
            tenant_id: None,
            configuration: None,
        })
        .await
        .expect_err("pending surfaces as an error the caller dispatches on");

    assert_eq!(
        err.oauth_error_code(),
        Some("authorization_pending"),
        "a hand-rolled loop sees exactly what device_login sees"
    );
}

#[tokio::test]
async fn device_poll_sends_the_device_code_grant_type() {
    let server = MockServer::start().await;
    mount_discovery(&server).await;

    let captured: Arc<Mutex<Option<HashMap<String, String>>>> = Arc::new(Mutex::new(None));
    let sink = Arc::clone(&captured);
    Mock::given(method("POST"))
        .and(path("/oauth2/token"))
        .respond_with(move |req: &Request| {
            *sink.lock().unwrap() = Some(parse_form(&req.body));
            success()
        })
        .mount(&server)
        .await;

    let client = build_client(&server.uri(), false);
    client
        .device_poll(DevicePollParams {
            device_code: Sensitive::new(DEVICE_CODE.to_string()),
            tenant_id: None,
            configuration: None,
        })
        .await
        .expect("device_poll");

    let form = captured.lock().unwrap().clone().expect("captured");
    assert_eq!(
        form.get("grant_type").map(String::as_str),
        Some("urn:ietf:params:oauth:grant-type:device_code")
    );
    assert_eq!(
        form.get("device_code").map(String::as_str),
        Some(DEVICE_CODE)
    );
}
