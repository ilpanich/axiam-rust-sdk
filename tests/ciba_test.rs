//! CIBA — CONTRACT.md §33.8's sixteen required tests (nine initiation and
//! polling, four ping, three signed request).
//!
//! No credential, key or token literal: the client secret, the
//! `auth_req_id`, the notification token and every signing key are generated
//! at run time.

#![cfg(feature = "rest")]

#[path = "oidc_support/mod.rs"]
mod oidc_support;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axiam_sdk::client::AxiamClient;
use axiam_sdk::oidc::{
    CibaAwaitParams, CibaClock, CibaDelivery, CibaInitiateParams, CibaInitiateResponse,
    CibaPollParams, CibaRequestSigner, CibaSigningAlg, CibaUserHint, OidcConfiguration,
};
use axiam_sdk::{AxiamError, Sensitive};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::{Value, json};
use uuid::Uuid;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

use oidc_support::{CLIENT_ID, ISSUER, discovery_document, tenant_id};

fn random() -> String {
    format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple())
}

fn assert_no_fragment(haystack: &str, secret: &str) {
    // The failure message names neither the fragment nor the haystack: a
    // failing redaction test must not itself print the secret it caught.
    for i in 0..=secret.len().saturating_sub(8) {
        assert!(
            !haystack.contains(&secret[i..i + 8]),
            "an 8-character fragment of the secret (offset {i}) appears in a rendering"
        );
    }
}

fn configuration(server: &MockServer) -> OidcConfiguration {
    serde_json::from_value(discovery_document(&server.uri())).unwrap()
}

/// A confidential client with a run-time secret, and that secret.
fn make_client(server: &MockServer) -> (AxiamClient, String) {
    let secret = random();
    let client = AxiamClient::builder()
        .base_url(server.uri())
        .unwrap()
        .tenant_id(tenant_id())
        .oidc_client_id(CLIENT_ID)
        .oidc_client_secret(secret.clone())
        .build()
        .unwrap();
    (client, secret)
}

#[derive(Clone, Debug)]
struct Seen {
    form: HashMap<String, String>,
    tenant_query: Option<String>,
    at: Duration,
}

fn form_of(req: &Request) -> HashMap<String, String> {
    url::form_urlencoded::parse(&req.body)
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect()
}

/// A clock that never sleeps: `sleep` advances it and records the wait.
struct TestClock {
    start: Instant,
    offset: Mutex<Duration>,
    sleeps: Mutex<Vec<Duration>>,
}

impl TestClock {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            start: Instant::now(),
            offset: Mutex::new(Duration::ZERO),
            sleeps: Mutex::new(Vec::new()),
        })
    }
    fn elapsed(&self) -> Duration {
        *self.offset.lock().unwrap()
    }
    fn sleeps(&self) -> Vec<u64> {
        self.sleeps
            .lock()
            .unwrap()
            .iter()
            .map(Duration::as_secs)
            .collect()
    }
}

impl CibaClock for TestClock {
    fn now(&self) -> Instant {
        self.start + self.elapsed()
    }
    fn sleep(
        &self,
        d: Duration,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>> {
        *self.offset.lock().unwrap() += d;
        self.sleeps.lock().unwrap().push(d);
        Box::pin(async {})
    }
}

/// Answer the token endpoint from `script`, one entry per request (the last
/// repeats), recording each request and the clock reading at it.
async fn token_script(
    server: &MockServer,
    clock: Option<Arc<TestClock>>,
    script: Vec<ResponseTemplate>,
) -> Arc<Mutex<Vec<Seen>>> {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&seen);
    Mock::given(method("POST"))
        .and(path("/oauth2/token"))
        .respond_with(move |req: &Request| {
            let mut s = sink.lock().unwrap();
            s.push(Seen {
                form: form_of(req),
                tenant_query: req
                    .url
                    .query_pairs()
                    .find(|(k, _)| k == "tenant_id")
                    .map(|(_, v)| v.into_owned()),
                at: clock.as_ref().map(|c| c.elapsed()).unwrap_or_default(),
            });
            script[(s.len() - 1).min(script.len() - 1)].clone()
        })
        .mount(server)
        .await;
    seen
}

async fn bc_authorize(server: &MockServer, template: ResponseTemplate) -> Arc<Mutex<Vec<Seen>>> {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&seen);
    Mock::given(method("POST"))
        .and(path("/oauth2/bc-authorize"))
        .respond_with(move |req: &Request| {
            sink.lock().unwrap().push(Seen {
                form: form_of(req),
                tenant_query: req
                    .url
                    .query_pairs()
                    .find(|(k, _)| k == "tenant_id")
                    .map(|(_, v)| v.into_owned()),
                at: Duration::ZERO,
            });
            template.clone()
        })
        .mount(server)
        .await;
    seen
}

fn oauth_error(status: u16, code: &str) -> ResponseTemplate {
    ResponseTemplate::new(status)
        .set_body_json(json!({"error": code, "error_description": format!("{code} here")}))
}

fn initiated(
    auth_req_id: &str,
    expires_in: u64,
    interval: u64,
    at: Instant,
) -> CibaInitiateResponse {
    CibaInitiateResponse {
        auth_req_id: Sensitive::new(auth_req_id.to_string()),
        expires_in,
        interval,
        received_at: at,
    }
}

fn params(server: &MockServer) -> CibaInitiateParams {
    let mut p = CibaInitiateParams::new("openid profile", CibaUserHint::LoginHint("ada".into()));
    p.configuration = Some(configuration(server));
    p
}

async fn tokens_with_id_token(server: &MockServer) -> ResponseTemplate {
    let key = oidc_support::generate_signing_key("ciba-id-token-key");
    Mock::given(method("GET"))
        .and(path("/oauth2/jwks"))
        .respond_with(ResponseTemplate::new(200).set_body_json(oidc_support::jwks_body(&[&key])))
        .mount(server)
        .await;
    let id_token = oidc_support::sign_id_token(
        &key,
        oidc_support::IdTokenOptions {
            nonce: Some(None),
            ..Default::default()
        },
    );
    ResponseTemplate::new(200).set_body_json(json!({
        "access_token": random(), "token_type": "Bearer", "expires_in": 900,
        "scope": "openid profile", "id_token": id_token,
    }))
}

// ── 1. Redaction ────────────────────────────────────────────────────────────

#[tokio::test]
async fn t01_the_three_values_are_on_the_wire_and_in_no_rendering() {
    let server = MockServer::start().await;
    let (client, _) = make_client(&server);
    let notification = random();
    let auth_req_id = random();
    let seen = bc_authorize(
        &server,
        ResponseTemplate::new(200)
            .set_body_json(json!({"auth_req_id": auth_req_id, "expires_in": 120, "interval": 5})),
    )
    .await;
    let mut p = params(&server);
    p.delivery = CibaDelivery::Ping {
        client_notification_token: Sensitive::new(notification.clone()),
    };
    assert_no_fragment(&format!("{p:?} {p:#?}"), &notification);
    let response = client.ciba_initiate(p.clone()).await.expect("initiate");
    assert_no_fragment(&format!("{response:?} {response:#?}"), &auth_req_id);
    assert_eq!(response.auth_req_id.expose(), &auth_req_id);
    assert_eq!(
        seen.lock().unwrap()[0].form["client_notification_token"],
        notification
    );

    server.reset().await;
    bc_authorize(&server, oauth_error(400, "invalid_binding_message")).await;
    let e = client.ciba_initiate(p).await.unwrap_err();
    assert_no_fragment(&format!("{e} {e:?}"), &notification);
}

// ── 2. Client authentication is mandatory ───────────────────────────────────

#[tokio::test]
async fn t02_no_credential_is_refused_locally_and_one_is_sent_with_tenant_in_the_query() {
    let server = MockServer::start().await;
    let initiate = bc_authorize(
        &server,
        ResponseTemplate::new(200)
            .set_body_json(json!({"auth_req_id": random(), "expires_in": 120})),
    )
    .await;
    let polls = token_script(
        &server,
        None,
        vec![oauth_error(400, "authorization_pending")],
    )
    .await;

    let public = oidc_support::build_client(&server.uri(), false);
    let e = public.ciba_initiate(params(&server)).await.unwrap_err();
    assert!(matches!(e, AxiamError::Auth { .. }), "{e}");
    let e = public
        .ciba_poll(CibaPollParams {
            auth_req_id: Sensitive::new(random()),
            tenant_id: None,
            configuration: Some(configuration(&server)),
        })
        .await
        .unwrap_err();
    assert!(matches!(e, AxiamError::Auth { .. }));
    assert!(initiate.lock().unwrap().is_empty() && polls.lock().unwrap().is_empty());

    let (client, secret) = make_client(&server);
    client
        .ciba_initiate(params(&server))
        .await
        .expect("initiate");
    let _ = client
        .ciba_poll(CibaPollParams {
            auth_req_id: Sensitive::new(random()),
            tenant_id: None,
            configuration: Some(configuration(&server)),
        })
        .await;
    for seen in [&initiate.lock().unwrap()[0], &polls.lock().unwrap()[0]] {
        assert_eq!(seen.form["client_id"], CLIENT_ID);
        assert_eq!(seen.form["client_secret"], secret);
        assert!(!seen.form.contains_key("tenant_id"), "never a body field");
        assert_eq!(
            seen.tenant_query.as_deref(),
            Some(tenant_id().to_string().as_str())
        );
    }

    // A tls_client_auth client: the certificate is the credential.
    let mtls = oidc_support::build_mtls_client(&server.uri(), false);
    mtls.ciba_initiate(params(&server))
        .await
        .expect("certificate client");
    let form = &initiate.lock().unwrap()[1].form;
    assert_eq!(form["client_id"], CLIENT_ID);
    assert!(!form.contains_key("client_secret"));
}

// ── 3. The initiate request ─────────────────────────────────────────────────

#[tokio::test]
async fn t03_exactly_the_members_set_are_sent() {
    let server = MockServer::start().await;
    let (client, _) = make_client(&server);
    let seen = bc_authorize(
        &server,
        ResponseTemplate::new(200)
            .set_body_json(json!({"auth_req_id": random(), "expires_in": 120})),
    )
    .await;

    client.ciba_initiate(params(&server)).await.unwrap();
    let mut full = params(&server);
    full.hint = CibaUserHint::IdTokenHint("an.id.token".into());
    full.binding_message = Some("W4SCT".into());
    full.requested_expiry = Some(120);
    full.acr_values = Some("urn:axiam:acr:mfa".into());
    full.resource = Some("https://api.example.test".into());
    let token = random();
    full.delivery = CibaDelivery::Ping {
        client_notification_token: Sensitive::new(token.clone()),
    };
    client.ciba_initiate(full).await.unwrap();

    {
        let sent = seen.lock().unwrap();
        let mut keys: Vec<&String> = sent[0].form.keys().collect();
        keys.sort();
        assert_eq!(keys, ["client_id", "client_secret", "login_hint", "scope"]);
        let mut keys: Vec<&String> = sent[1].form.keys().collect();
        keys.sort();
        assert_eq!(
            keys,
            [
                "acr_values",
                "binding_message",
                "client_id",
                "client_notification_token",
                "client_secret",
                "id_token_hint",
                "requested_expiry",
                "resource",
                "scope"
            ]
        );
        assert_eq!(sent[1].form["requested_expiry"], "120");
        assert_eq!(sent[1].form["client_notification_token"], token);
        for forbidden in ["login_hint_token", "user_code", "request_uri", "request"] {
            assert!(!sent[1].form.contains_key(forbidden), "{forbidden}");
        }
    }
    // `login_hint_token`, `user_code` and `request_uri` have no parameter, and
    // `CibaUserHint` holds one hint: both at once cannot be written. A ping
    // request with an empty token is refused before any request.
    let mut ping = params(&server);
    ping.delivery = CibaDelivery::Ping {
        client_notification_token: Sensitive::new(String::new()),
    };
    let e = client.ciba_initiate(ping).await.unwrap_err();
    assert!(e.validation().is_some(), "{e}");
    assert_eq!(seen.lock().unwrap().len(), 2);
}

// ── 4. No retry on initiate ─────────────────────────────────────────────────

#[tokio::test]
async fn t04_initiate_is_sent_once_on_503_429_and_a_dropped_connection() {
    for status in [503u16, 429] {
        let server = MockServer::start().await;
        let (client, _) = make_client(&server);
        let template = if status == 429 {
            oauth_error(429, "rate_limit_exceeded")
        } else {
            ResponseTemplate::new(503)
        };
        let seen = bc_authorize(&server, template).await;
        let e = client.ciba_initiate(params(&server)).await.unwrap_err();
        assert_eq!(
            seen.lock().unwrap().len(),
            1,
            "{status}: exactly one request"
        );
        if status == 503 {
            assert!(matches!(e, AxiamError::Network { .. }));
        } else {
            // §2's /oauth2 row: a body with an `error` member is an OAuthProtocolError.
            assert_eq!(e.oauth_error_code(), Some("rate_limit_exceeded"));
        }
    }

    // A listener that accepts and hangs up.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let accepts = Arc::new(Mutex::new(0usize));
    let count = Arc::clone(&accepts);
    tokio::spawn(async move {
        loop {
            let Ok((socket, _)) = listener.accept().await else {
                break;
            };
            *count.lock().unwrap() += 1;
            drop(socket);
        }
    });
    let server = MockServer::start().await;
    let (client, _) = make_client(&server);
    let mut p = params(&server);
    let mut doc = discovery_document(&server.uri());
    doc["backchannel_authentication_endpoint"] =
        json!(format!("http://{addr}/oauth2/bc-authorize"));
    p.configuration = Some(serde_json::from_value(doc).unwrap());
    let e = client.ciba_initiate(p).await.unwrap_err();
    assert!(matches!(e, AxiamError::Network { .. }), "{e}");
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(*accepts.lock().unwrap(), 1, "one connection, no retry");
}

// ── 5. Poll outcomes ────────────────────────────────────────────────────────

#[tokio::test]
async fn t05_pending_loops_slow_down_persists_and_the_terminal_answers_are_distinct() {
    let server = MockServer::start().await;
    let (client, _) = make_client(&server);
    let tokens = tokens_with_id_token(&server).await;
    let clock = TestClock::new();
    let seen = token_script(
        &server,
        Some(clock.clone()),
        vec![
            oauth_error(400, "slow_down"),
            oauth_error(400, "slow_down"),
            oauth_error(400, "authorization_pending"),
            tokens,
        ],
    )
    .await;
    let id = random();
    let set = client
        .ciba_await(
            &initiated(&id, 600, 5, clock.start),
            CibaAwaitParams {
                configuration: Some(configuration(&server)),
                clock: Some(clock.clone()),
                ..Default::default()
            },
        )
        .await
        .expect("tokens");
    assert!(set.id_claims.is_some());
    assert_eq!(
        clock.sleeps(),
        [5, 10, 15, 15],
        "+5 s twice, and pending lowers nothing"
    );
    assert!(seen.lock().unwrap().iter().all(|s| s.form["grant_type"]
        == "urn:openid:params:grant-type:ciba"
        && s.form["auth_req_id"] == id));

    for (code, check) in [
        (
            "access_denied",
            AxiamError::is_access_denied as fn(&AxiamError) -> bool,
        ),
        ("expired_token", AxiamError::is_expired_token),
        ("invalid_grant", |e: &AxiamError| {
            e.oauth_error_code() == Some("invalid_grant")
        }),
        ("a_code_nobody_defined", |e: &AxiamError| {
            matches!(e, AxiamError::Auth { .. })
                && e.oauth_error_code() == Some("a_code_nobody_defined")
        }),
    ] {
        let server = MockServer::start().await;
        let (client, _) = make_client(&server);
        let clock = TestClock::new();
        let seen = token_script(&server, Some(clock.clone()), vec![oauth_error(400, code)]).await;
        let e = client
            .ciba_await(
                &initiated(&random(), 600, 5, clock.start),
                CibaAwaitParams {
                    configuration: Some(configuration(&server)),
                    clock: Some(clock.clone()),
                    ..Default::default()
                },
            )
            .await
            .unwrap_err();
        assert!(check(&e), "{code}: {e}");
        assert_eq!(seen.lock().unwrap().len(), 1, "{code} is terminal");
    }
    let denied = AxiamError::oauth_protocol_error("access_denied", "x");
    assert!(!denied.is_expired_token(), "the two outcomes are distinct");
}

// ── 6. The first poll waits ─────────────────────────────────────────────────

#[tokio::test]
async fn t06_the_first_poll_waits_the_interval_or_five_seconds() {
    for (interval_in_response, expected) in [(Some(7u64), 7u64), (None, 5)] {
        let server = MockServer::start().await;
        let (client, _) = make_client(&server);
        let clock = TestClock::new();
        let mut body = json!({"auth_req_id": random(), "expires_in": 300});
        if let Some(i) = interval_in_response {
            body["interval"] = json!(i);
        }
        bc_authorize(&server, ResponseTemplate::new(200).set_body_json(body)).await;
        let seen = token_script(
            &server,
            Some(clock.clone()),
            vec![oauth_error(400, "access_denied")],
        )
        .await;
        let mut response = client.ciba_initiate(params(&server)).await.unwrap();
        assert_eq!(response.interval, expected);
        response.received_at = clock.start;
        let _ = client
            .ciba_await(
                &response,
                CibaAwaitParams {
                    configuration: Some(configuration(&server)),
                    clock: Some(clock.clone()),
                    ..Default::default()
                },
            )
            .await;
        assert_eq!(seen.lock().unwrap()[0].at, Duration::from_secs(expected));
    }
}

// ── 7. Deadline ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn t07_no_request_after_expires_in_and_expired_token_is_raised_locally() {
    let server = MockServer::start().await;
    let (client, _) = make_client(&server);
    let clock = TestClock::new();
    let seen = token_script(
        &server,
        Some(clock.clone()),
        vec![oauth_error(400, "authorization_pending")],
    )
    .await;
    let e = client
        .ciba_await(
            &initiated(&random(), 12, 5, clock.start),
            CibaAwaitParams {
                configuration: Some(configuration(&server)),
                clock: Some(clock.clone()),
                ..Default::default()
            },
        )
        .await
        .unwrap_err();
    assert!(e.is_expired_token(), "{e}");
    let at: Vec<u64> = seen
        .lock()
        .unwrap()
        .iter()
        .map(|s| s.at.as_secs())
        .collect();
    assert_eq!(at, [5, 10], "nothing at 15 s, past the 12 s deadline");
}

// ── 8. Transient failure is not terminal ────────────────────────────────────

#[tokio::test]
async fn t08_a_500_and_a_429_mid_loop_are_survived() {
    let server = MockServer::start().await;
    let (client, _) = make_client(&server);
    let tokens = tokens_with_id_token(&server).await;
    let clock = TestClock::new();
    let seen = token_script(
        &server,
        Some(clock.clone()),
        vec![
            oauth_error(400, "authorization_pending"),
            ResponseTemplate::new(500),
            oauth_error(429, "rate_limit_exceeded"),
            tokens,
        ],
    )
    .await;
    let set = client
        .ciba_await(
            &initiated(&random(), 600, 5, clock.start),
            CibaAwaitParams {
                configuration: Some(configuration(&server)),
                clock: Some(clock.clone()),
                ..Default::default()
            },
        )
        .await
        .expect("the loop succeeds after the transient failures");
    assert!(!set.access_token.expose().is_empty());
    assert!(set.id_token.is_some() && set.id_claims.is_some());
    assert_eq!(seen.lock().unwrap().len(), 4);
}

// ── 9. Single use ───────────────────────────────────────────────────────────

#[tokio::test]
async fn t09_a_second_redemption_is_invalid_grant_and_not_retried() {
    let server = MockServer::start().await;
    let (client, _) = make_client(&server);
    let tokens = tokens_with_id_token(&server).await;
    let seen = token_script(
        &server,
        None,
        vec![tokens, oauth_error(400, "invalid_grant")],
    )
    .await;
    let id = random();
    let poll = || CibaPollParams {
        auth_req_id: Sensitive::new(id.clone()),
        tenant_id: None,
        configuration: Some(configuration(&server)),
    };
    client.ciba_poll(poll()).await.expect("redeemed");
    let e = client.ciba_poll(poll()).await.unwrap_err();
    assert_eq!(e.oauth_error_code(), Some("invalid_grant"));
    assert_eq!(seen.lock().unwrap().len(), 2, "no retry of the second");
}

// ── 10–13. The ping ─────────────────────────────────────────────────────────

fn ping<'a>(auth: &'a [&'a str]) -> Vec<(&'a str, &'a [u8])> {
    let mut h: Vec<(&str, &[u8])> = vec![("content-type", b"application/json")];
    for a in auth {
        h.push(("Authorization", a.as_bytes()));
    }
    h
}

#[tokio::test]
async fn t10_a_valid_ping_returns_its_auth_req_id_in_any_scheme_case() {
    let server = MockServer::start().await;
    let (client, _) = make_client(&server);
    let token = random();
    let id = random();
    let body = json!({"auth_req_id": id}).to_string();
    for scheme in ["Bearer", "bearer", "BEARER"] {
        let header = format!("{scheme} {token}");
        let got = client
            .ciba_handle_ping(
                ping(&[&header]),
                body.as_bytes(),
                &Sensitive::new(token.clone()),
            )
            .expect("accepted");
        assert_eq!(got.expose(), &id);
        assert_no_fragment(&format!("{got:?}"), &id);
    }
}

#[tokio::test]
async fn t11_a_wrong_absent_empty_duplicate_or_basic_authorization_is_refused() {
    let server = MockServer::start().await;
    let (client, _) = make_client(&server);
    let token = random();
    let mut last_differs = token.clone();
    let last = last_differs.pop().unwrap();
    last_differs.push(if last == 'a' { 'b' } else { 'a' });
    let body = json!({"auth_req_id": random()}).to_string();
    let expected = Sensitive::new(token.clone());
    let cases: Vec<Vec<String>> = vec![
        vec![format!("Bearer {}", random())],
        vec![],
        vec![String::new()],
        vec!["Bearer ".into()],
        vec![format!("Bearer {token}"), format!("Bearer {token}")],
        vec![format!("Basic {token}")],
        vec![format!("Bearer {last_differs}")],
        vec![format!("Bearer  {token}")],
    ];
    for case in cases {
        let refs: Vec<&str> = case.iter().map(String::as_str).collect();
        let e = client
            .ciba_handle_ping(ping(&refs), body.as_bytes(), &expected)
            .unwrap_err();
        assert!(matches!(e, AxiamError::Auth { .. }), "{case:?}: {e}");
        assert_no_fragment(&format!("{e} {e:?}"), &token);
    }
    // The comparison is `subtle::ConstantTimeEq` (src/oidc/ciba.rs): Rust has
    // no timing harness here, so §33.8 test 11 is asserted structurally.
    let source = include_str!("../src/oidc/ciba.rs");
    assert!(source.contains("token.ct_eq(expected)"));
}

#[tokio::test]
async fn t12_a_malformed_body_is_a_validation_error_and_extras_are_ignored() {
    let server = MockServer::start().await;
    let (client, _) = make_client(&server);
    let token = random();
    let header = format!("Bearer {token}");
    let expected = Sensitive::new(token);
    for body in [
        "not json".to_string(),
        json!({}).to_string(),
        json!({"auth_req_id": ""}).to_string(),
        json!({"auth_req_id": 42}).to_string(),
        json!(["auth_req_id"]).to_string(),
    ] {
        let e = client
            .ciba_handle_ping(ping(&[&header]), body.as_bytes(), &expected)
            .unwrap_err();
        assert!(e.validation().is_some(), "{body}: {e}");
    }
    let id = random();
    let got = client
        .ciba_handle_ping(
            ping(&[&header]),
            json!({"auth_req_id": id, "status": "approved", "access_token": "x"})
                .to_string()
                .as_bytes(),
            &expected,
        )
        .expect("extras ignored");
    assert_eq!(got.expose(), &id);
}

#[tokio::test]
async fn t13_the_ping_helper_makes_no_network_call() {
    let server = MockServer::start().await;
    let (client, _) = make_client(&server);
    let token = random();
    let header = format!("Bearer {token}");
    client
        .ciba_handle_ping(
            ping(&[&header]),
            json!({"auth_req_id": random()}).to_string().as_bytes(),
            &Sensitive::new(token),
        )
        .unwrap();
    assert!(
        server.received_requests().await.unwrap().is_empty(),
        "the transport was never touched"
    );
}

// ── 14–16. The signed form ──────────────────────────────────────────────────

const ED25519_PKCS8_PREFIX: [u8; 16] = [
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];

/// A fresh Ed25519 key: (PEM private key, public `x`).
fn ed25519_key() -> (String, String) {
    let mut seed = [0u8; 32];
    seed[..16].copy_from_slice(Uuid::new_v4().as_bytes());
    seed[16..].copy_from_slice(Uuid::new_v4().as_bytes());
    let mut der = ED25519_PKCS8_PREFIX.to_vec();
    der.extend_from_slice(&seed);
    let b64 = base64::engine::general_purpose::STANDARD.encode(&der);
    let pem = format!("-----BEGIN PRIVATE KEY-----\n{b64}\n-----END PRIVATE KEY-----\n");
    let x = URL_SAFE_NO_PAD.encode(
        ed25519_dalek::SigningKey::from_bytes(&seed)
            .verifying_key()
            .to_bytes(),
    );
    (pem, x)
}

fn decode_part(part: &str) -> Value {
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(part).unwrap()).unwrap()
}

#[tokio::test]
async fn t14_the_signed_request_is_one_member_with_the_registered_alg_and_fresh_jti() {
    let server = MockServer::start().await;
    let (client, secret) = make_client(&server);
    let seen = bc_authorize(
        &server,
        ResponseTemplate::new(200)
            .set_body_json(json!({"auth_req_id": random(), "expires_in": 120})),
    )
    .await;
    let (pem, x) = ed25519_key();
    let signer = CibaRequestSigner::from_pem(
        CibaSigningAlg::EdDsa,
        &Sensitive::new(pem.into_bytes()),
        Some("client-key-1".into()),
    )
    .unwrap();
    let notification = random();
    let mut p = params(&server);
    p.binding_message = Some("W4SCT".into());
    p.requested_expiry = Some(90);
    p.delivery = CibaDelivery::Ping {
        client_notification_token: Sensitive::new(notification.clone()),
    };
    p.signer = Some(signer);
    client.ciba_initiate(p.clone()).await.unwrap();
    client.ciba_initiate(p).await.unwrap();

    let mut jtis = Vec::new();
    {
        let sent = seen.lock().unwrap();
        for s in sent.iter() {
            let mut keys: Vec<&String> = s.form.keys().collect();
            keys.sort();
            assert_eq!(
                keys,
                ["client_id", "client_secret", "request"],
                "nothing beside request"
            );
            assert_eq!(s.form["client_secret"], secret);
            let request = &s.form["request"];
            let parts: Vec<&str> = request.split('.').collect();
            let header = decode_part(parts[0]);
            assert_eq!(header["alg"], "EdDSA");
            assert_eq!(header["kid"], "client-key-1");
            // The caller's key signed it.
            let key = jsonwebtoken::DecodingKey::from_ed_components(&x).unwrap();
            let mut v = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::EdDSA);
            v.set_audience(&[ISSUER]);
            let claims = jsonwebtoken::decode::<Value>(request, &key, &v)
                .unwrap()
                .claims;
            assert_eq!(claims["iss"], CLIENT_ID);
            assert_eq!(claims["aud"], ISSUER);
            let (exp, nbf) = (
                claims["exp"].as_i64().unwrap(),
                claims["nbf"].as_i64().unwrap(),
            );
            assert!(claims["iat"].is_i64() && exp - nbf <= 3600 && exp > nbf);
            assert_eq!(claims["login_hint"], "ada");
            assert_eq!(claims["binding_message"], "W4SCT");
            assert_eq!(claims["requested_expiry"], 90);
            assert_eq!(claims["client_notification_token"], notification);
            jtis.push(claims["jti"].as_str().unwrap().to_string());
        }
    }
    assert_ne!(jtis[0], jtis[1], "a fresh jti per request");

    // ES256 signs under ES256 only.
    let ec = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let signer = CibaRequestSigner::from_pem(
        CibaSigningAlg::Es256,
        &Sensitive::new(ec.serialize_pem().into_bytes()),
        None,
    )
    .unwrap();
    assert_eq!(signer.alg(), CibaSigningAlg::Es256);
    let mut p = params(&server);
    p.signer = Some(signer);
    client.ciba_initiate(p).await.unwrap();
    let last = seen.lock().unwrap().last().unwrap().form["request"].clone();
    assert_eq!(decode_part(last.split('.').next().unwrap())["alg"], "ES256");
}

#[tokio::test]
async fn t15_no_key_or_a_key_for_another_alg_is_refused_before_any_request() {
    let server = MockServer::start().await;
    let seen = bc_authorize(&server, ResponseTemplate::new(200)).await;
    let (ed_pem, _) = ed25519_key();
    let ec = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    for (alg, pem) in [
        (CibaSigningAlg::EdDsa, String::new()),
        (CibaSigningAlg::Es256, ed_pem.clone()),
        (CibaSigningAlg::Ps256, ec.serialize_pem()),
        (CibaSigningAlg::EdDsa, ec.serialize_pem()),
    ] {
        let e =
            CibaRequestSigner::from_pem(alg, &Sensitive::new(pem.into_bytes()), None).unwrap_err();
        assert!(e.validation().is_some(), "{alg:?}: {e}");
    }
    // The algorithm and the key are the only constructor's two required
    // arguments, so "no algorithm" cannot be written; and with a signer set,
    // every member travels inside `request` — there is no channel for a form
    // parameter beside it (t14 asserts the form).
    assert!(seen.lock().unwrap().is_empty());
}

#[tokio::test]
async fn t16_the_key_and_the_request_appear_in_no_rendering() {
    let server = MockServer::start().await;
    let (client, _) = make_client(&server);
    let seen = bc_authorize(&server, oauth_error(400, "invalid_request")).await;
    let (pem, _) = ed25519_key();
    let body_line = pem.lines().nth(1).unwrap().to_string();
    let signer = CibaRequestSigner::from_pem(
        CibaSigningAlg::EdDsa,
        &Sensitive::new(pem.clone().into_bytes()),
        None,
    )
    .unwrap();
    let mut p = params(&server);
    p.signer = Some(signer.clone());
    let e = client.ciba_initiate(p.clone()).await.unwrap_err();
    let request = seen.lock().unwrap()[0].form["request"].clone();
    for rendering in [
        format!("{signer:?}"),
        format!("{p:?}"),
        format!("{p:#?}"),
        format!("{e} {e:?}"),
    ] {
        assert_no_fragment(&rendering, &body_line);
        assert_no_fragment(&rendering, &request);
    }
}
