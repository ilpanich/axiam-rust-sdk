//! Contract 1.65: native sign-in with a provider ID token (§37.9 tests 1-13),
//! `idp_hint` on `oidc_begin` and `oidc_par` (§12.1, §26.6), and the §9
//! confirmation that a rejected refresh is one wire call shared by every
//! waiter.

#![cfg(feature = "rest")]

#[path = "oidc_support/mod.rs"]
mod oidc_support;

use std::collections::{BTreeSet, HashMap};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axiam_sdk::client::AxiamClient;
use axiam_sdk::oidc::{
    OidcBeginParams, OidcConfiguration, OidcParParams, OidcRefreshParams,
    PROVIDER_ID_TOKEN_GRANT_TYPE, ProviderIdTokenOptions, native_nonce,
};
use axiam_sdk::telemetry::{TelemetryEvent, TelemetrySink};
use axiam_sdk::{AxiamError, IdTokenFailureReason, Sensitive};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use oidc_support::{IdTokenOptions, build_client, discovery_document, token_response};
use serde_json::json;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

const PROVIDER_TOKEN: &str = "provider-id-token-fixture-9f3a1c";
const RAW_NONCE: &str = "n-0S6_WzA2Mj";
const RAW_NONCE_SHA256: &str = "0823a09b54cb9381561068b00aaf4e539b3f54604631d3e6a820879b6b04cc19";
const GENERIC_DESCRIPTION: &str = "the provider ID token is not acceptable";

fn configuration(base: &str) -> OidcConfiguration {
    serde_json::from_value(discovery_document(base)).expect("discovery parses")
}

fn options(base: &str) -> ProviderIdTokenOptions {
    ProviderIdTokenOptions {
        configuration: Some(configuration(base)),
        ..Default::default()
    }
}

fn s(v: &str) -> Sensitive<String> {
    Sensitive::new(v.to_string())
}

#[derive(Clone, Debug)]
struct Seen {
    query: HashMap<String, String>,
    headers: HashMap<String, String>,
    body: String,
    form: HashMap<String, String>,
    form_keys: BTreeSet<String>,
}

type Recorder = Arc<Mutex<Vec<Seen>>>;

fn record(req: &Request, rec: &Recorder) {
    let query = req
        .url
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    let headers = req
        .headers
        .iter()
        .map(|(k, v)| {
            (
                k.as_str().to_lowercase(),
                v.to_str().unwrap_or("").to_string(),
            )
        })
        .collect();
    let body = String::from_utf8_lossy(&req.body).into_owned();
    let pairs: Vec<(String, String)> = url::form_urlencoded::parse(body.as_bytes())
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    rec.lock().unwrap().push(Seen {
        query,
        headers,
        body,
        form_keys: pairs.iter().map(|(k, _)| k.clone()).collect(),
        form: pairs.into_iter().collect(),
    });
}

/// Mount `/oauth2/token` answering with `template`, recording each request.
async fn mount_token(server: &MockServer, template: ResponseTemplate) -> Recorder {
    let rec: Recorder = Arc::default();
    let r = Arc::clone(&rec);
    Mock::given(method("POST"))
        .and(path("/oauth2/token"))
        .respond_with(move |req: &Request| {
            record(req, &r);
            template.clone()
        })
        .mount(server)
        .await;
    rec
}

fn error_body(status: u16, error: &str) -> ResponseTemplate {
    ResponseTemplate::new(status)
        .set_body_json(json!({"error": error, "error_description": format!("{error} desc")}))
}

async fn login(
    client: &AxiamClient,
    provider: &str,
    base: &str,
) -> Result<axiam_sdk::oidc::OidcTokenSet, AxiamError> {
    client
        .login_with_provider_id_token(provider, s(PROVIDER_TOKEN), s(RAW_NONCE), options(base))
        .await
}

async fn total(server: &MockServer) -> usize {
    server.received_requests().await.unwrap().len()
}

// 1 -------------------------------------------------------------------------

#[tokio::test]
async fn request_body_exact() {
    let server = MockServer::start().await;
    let rec = mount_token(
        &server,
        ResponseTemplate::new(200).set_body_json(token_response(json!({}))),
    )
    .await;
    let client = build_client(&server.uri(), false);

    // With scopes and resource.
    client
        .login_with_provider_id_token(
            "corp-okta",
            s(PROVIDER_TOKEN),
            s(RAW_NONCE),
            ProviderIdTokenOptions {
                scopes: Some(vec!["openid".into(), "profile".into()]),
                resource: Some("https://api.example.com".into()),
                configuration: Some(configuration(&server.uri())),
                ..Default::default()
            },
        )
        .await
        .expect("sign-in succeeds");
    // Without either.
    login(&client, "corp-okta", &server.uri())
        .await
        .expect("ok");

    let seen = rec.lock().unwrap().clone();
    assert_eq!(seen.len(), 2);
    let a = &seen[0];
    assert_eq!(
        a.query.get("tenant_id").map(String::as_str),
        Some(oidc_support::tenant_id().to_string().as_str())
    );
    assert!(
        !a.form.contains_key("tenant_id"),
        "tenant_id is a query parameter only"
    );
    assert_eq!(
        a.headers.get("content-type").map(String::as_str),
        Some("application/x-www-form-urlencoded")
    );
    let expected: BTreeSet<String> = [
        "grant_type",
        "client_id",
        "provider",
        "id_token",
        "nonce",
        "scope",
        "resource",
    ]
    .iter()
    .map(|k| k.to_string())
    .collect();
    assert_eq!(a.form_keys, expected);
    assert_eq!(a.form["grant_type"], PROVIDER_ID_TOKEN_GRANT_TYPE);
    assert_eq!(a.form["scope"], "openid profile");
    assert_eq!(a.form["resource"], "https://api.example.com");
    for h in ["authorization", "cookie", "x-csrf-token"] {
        assert!(!a.headers.contains_key(h), "{h} must not be sent");
    }

    let b = &seen[1];
    let minimal: BTreeSet<String> = ["grant_type", "client_id", "provider", "id_token", "nonce"]
        .iter()
        .map(|k| k.to_string())
        .collect();
    assert_eq!(
        b.form_keys, minimal,
        "no scope, no resource, and no openid added"
    );
}

// 2 -------------------------------------------------------------------------

#[tokio::test]
async fn raw_nonce_sent_not_hash() {
    let server = MockServer::start().await;
    let rec = mount_token(
        &server,
        ResponseTemplate::new(200).set_body_json(token_response(json!({}))),
    )
    .await;
    let client = build_client(&server.uri(), false);
    // A token whose own nonce claim carries the hash.
    let key = oidc_support::generate_signing_key("native-kid");
    let provider_token = oidc_support::sign_id_token(
        &key,
        IdTokenOptions {
            nonce: Some(Some(RAW_NONCE_SHA256)),
            ..Default::default()
        },
    );
    client
        .login_with_provider_id_token(
            "p",
            Sensitive::new(provider_token.clone()),
            s(RAW_NONCE),
            options(&server.uri()),
        )
        .await
        .expect("ok");
    let seen = rec.lock().unwrap().clone();
    assert_eq!(seen[0].form["nonce"], RAW_NONCE);
    assert!(
        !seen[0].body.contains(RAW_NONCE_SHA256),
        "the hash must not be sent"
    );
    assert!(!seen[0].body.contains("0823a09b"));
    assert_eq!(seen[0].form["id_token"], provider_token);
}

// 3 -------------------------------------------------------------------------

#[tokio::test]
async fn provider_sent_verbatim() {
    let server = MockServer::start().await;
    let rec = mount_token(
        &server,
        ResponseTemplate::new(200).set_body_json(token_response(json!({}))),
    )
    .await;
    let client = build_client(&server.uri(), false);
    let uuid = "0b9e6c74-1a2b-4c3d-8e4f-5a6b7c8d9e0f";
    for provider in [uuid, "Corp-Okta", "google", " padded "] {
        login(&client, provider, &server.uri()).await.expect("ok");
    }
    let seen = rec.lock().unwrap().clone();
    let sent: Vec<&str> = seen.iter().map(|r| r.form["provider"].as_str()).collect();
    assert_eq!(sent, vec![uuid, "Corp-Okta", "google", " padded "]);
    // One request per call: no sso_providers lookup, no discovery fetch.
    assert_eq!(total(&server).await, 4);
}

// 4 -------------------------------------------------------------------------

#[tokio::test]
async fn public_client_sends_client_id_only() {
    let server = MockServer::start().await;
    let rec = mount_token(
        &server,
        ResponseTemplate::new(200).set_body_json(token_response(json!({}))),
    )
    .await;
    let client = build_client(&server.uri(), false);
    login(&client, "p", &server.uri())
        .await
        .expect("a public client is not refused");
    let seen = rec.lock().unwrap().clone();
    assert_eq!(seen[0].form["client_id"], oidc_support::CLIENT_ID);
    assert!(!seen[0].form.contains_key("client_secret"));
    assert!(!seen[0].form.contains_key("client_assertion"));
    assert!(!seen[0].headers.contains_key("authorization"));
}

#[tokio::test]
async fn confidential_client_sends_its_credential() {
    for auth_method in ["client_secret_post", "client_secret_basic"] {
        let server = MockServer::start().await;
        let mut doc = discovery_document(&server.uri());
        doc["token_endpoint_auth_methods_supported"] = json!([auth_method]);
        let cfg: OidcConfiguration = serde_json::from_value(doc).unwrap();
        let rec = mount_token(
            &server,
            ResponseTemplate::new(200).set_body_json(token_response(json!({}))),
        )
        .await;
        let client = build_client(&server.uri(), true);
        client
            .login_with_provider_id_token(
                "p",
                s(PROVIDER_TOKEN),
                s(RAW_NONCE),
                ProviderIdTokenOptions {
                    configuration: Some(cfg),
                    ..Default::default()
                },
            )
            .await
            .expect("ok");
        let seen = rec.lock().unwrap().clone();
        assert_eq!(
            seen[0].form["client_secret"],
            oidc_support::CLIENT_SECRET,
            "{auth_method}"
        );
        assert!(
            !seen[0].headers.contains_key("authorization"),
            "never a Basic header ({auth_method})"
        );
    }
}

// 5 -------------------------------------------------------------------------

#[tokio::test]
async fn empty_inputs_refused_locally() {
    let server = MockServer::start().await;
    mount_token(
        &server,
        ResponseTemplate::new(200).set_body_json(token_response(json!({}))),
    )
    .await;
    let client = build_client(&server.uri(), false);
    let base = server.uri();
    let cases: Vec<(&str, Result<_, AxiamError>)> = vec![
        ("provider", login(&client, "", &base).await),
        (
            "id_token",
            client
                .login_with_provider_id_token("p", s(""), s(RAW_NONCE), options(&base))
                .await,
        ),
        (
            "nonce",
            client
                .login_with_provider_id_token("p", s(PROVIDER_TOKEN), s(""), options(&base))
                .await,
        ),
    ];
    for (field, result) in cases {
        let err = result.expect_err("refused");
        let v = err.validation().expect("a local ValidationError");
        assert_eq!(v.fields[0].field, field);
    }
    // A slug-only client has no tenant UUID: a taxonomy error, no request.
    let slug_only = AxiamClient::builder()
        .base_url(server.uri())
        .unwrap()
        .tenant_slug("acme")
        .org_slug("acme")
        .oidc_client_id(oidc_support::CLIENT_ID)
        .build()
        .unwrap();
    let err = slug_only
        .login_with_provider_id_token("p", s(PROVIDER_TOKEN), s(RAW_NONCE), Default::default())
        .await
        .expect_err("slug-only");
    assert!(matches!(err, AxiamError::Auth { .. }), "{err:?}");
    assert_eq!(total(&server).await, 0, "zero requests for every refusal");
}

// 6 -------------------------------------------------------------------------

#[tokio::test]
async fn generic_invalid_grant_mapped() {
    let server = MockServer::start().await;
    let rec = mount_token(
        &server,
        ResponseTemplate::new(400).set_body_json(
            json!({"error":"invalid_grant","error_description":GENERIC_DESCRIPTION}),
        ),
    )
    .await;
    let client = build_client(&server.uri(), false);
    let err = login(&client, "p", &server.uri())
        .await
        .expect_err("refused");
    let oauth = err.as_oauth_protocol_error().expect("OAuthProtocolError");
    assert_eq!(oauth.error, "invalid_grant");
    assert_eq!(oauth.error_description, GENERIC_DESCRIPTION);
    assert!(
        matches!(&err, AxiamError::Auth { message, .. } if message == &format!("invalid_grant: {GENERIC_DESCRIPTION}"))
    );
    assert_eq!(rec.lock().unwrap().len(), 1, "no retry");
    assert_eq!(
        total(&server).await,
        1,
        "no regenerated nonce, no discovery, no refresh"
    );
}

// 7 -------------------------------------------------------------------------

#[tokio::test]
async fn consent_required_mapped() {
    let server = MockServer::start().await;
    let rec = mount_token(&server, error_body(400, "consent_required")).await;
    let client = build_client(&server.uri(), false);
    let err = login(&client, "p", &server.uri())
        .await
        .expect_err("refused");
    assert_eq!(err.oauth_error_code(), Some("consent_required"));
    assert_eq!(rec.lock().unwrap().len(), 1);
    assert_eq!(total(&server).await, 1, "no fallback to another grant");
}

// 8 -------------------------------------------------------------------------

#[tokio::test]
async fn client_and_scope_refusals_surfaced() {
    let cases = [
        (400u16, "unauthorized_client"),
        (401, "invalid_client"),
        (400, "invalid_scope"),
        (400, "invalid_target"),
    ];
    for (status, code) in cases {
        let server = MockServer::start().await;
        let mut t = error_body(status, code);
        if status == 401 {
            t = t.insert_header("WWW-Authenticate", "Basic realm=\"axiam\"");
        }
        let rec = mount_token(&server, t).await;
        let client = build_client(&server.uri(), false);
        let err = client
            .login_with_provider_id_token(
                "p",
                s(PROVIDER_TOKEN),
                s(RAW_NONCE),
                ProviderIdTokenOptions {
                    scopes: Some(vec!["openid".into(), "address".into()]),
                    configuration: Some(configuration(&server.uri())),
                    ..Default::default()
                },
            )
            .await
            .expect_err("refused");
        assert_eq!(err.oauth_error_code(), Some(code));
        assert_eq!(
            rec.lock().unwrap().len(),
            1,
            "{code}: one request, never narrowed"
        );
        assert_eq!(
            total(&server).await,
            1,
            "{code}: the 401 never enters the refresh guard"
        );
        if code == "invalid_scope" {
            assert_eq!(rec.lock().unwrap()[0].form["scope"], "openid address");
        }
    }
}

// 9 -------------------------------------------------------------------------

#[tokio::test]
async fn rate_limit_with_retry_after_mapped() {
    let server = MockServer::start().await;
    let rec = mount_token(
        &server,
        error_body(429, "rate_limit_exceeded").insert_header("Retry-After", "7"),
    )
    .await;
    let client = build_client(&server.uri(), false);
    let err = login(&client, "p", &server.uri())
        .await
        .expect_err("limited");
    // This SDK does not expose Retry-After on its errors; the assertion is the
    // error code and a single request.
    assert_eq!(err.oauth_error_code(), Some("rate_limit_exceeded"));
    assert_eq!(rec.lock().unwrap().len(), 1);
}

// 10 ------------------------------------------------------------------------

#[tokio::test]
async fn server_error_not_retried() {
    // 500 with a well-formed body: an OAuthProtocolError, one request.
    let server = MockServer::start().await;
    let rec = mount_token(&server, error_body(500, "server_error")).await;
    let client = build_client(&server.uri(), false);
    let err = login(&client, "p", &server.uri()).await.expect_err("500");
    assert_eq!(err.oauth_error_code(), Some("server_error"));
    assert_eq!(rec.lock().unwrap().len(), 1);

    // 500 with no body: NetworkError, one request.
    let server = MockServer::start().await;
    let rec = mount_token(&server, ResponseTemplate::new(500)).await;
    let client = build_client(&server.uri(), false);
    let err = login(&client, "p", &server.uri()).await.expect_err("500");
    assert!(matches!(err, AxiamError::Network { .. }), "{err:?}");
    assert_eq!(rec.lock().unwrap().len(), 1);

    // A transport failure after the request is sent: NetworkError, one request.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let accepted = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&accepted);
    let handle = std::thread::spawn(move || {
        use std::io::Read;
        while let Ok((mut stream, _)) = listener.accept() {
            counter.fetch_add(1, Ordering::SeqCst);
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf);
            drop(stream); // close without answering
            if counter.load(Ordering::SeqCst) >= 1 {
                std::thread::sleep(Duration::from_millis(300));
                break;
            }
        }
    });
    let base = format!("http://{addr}");
    let client = build_client(&base, false);
    let err = login(&client, "p", &base).await.expect_err("dropped");
    assert!(matches!(err, AxiamError::Network { .. }), "{err:?}");
    handle.join().unwrap();
    assert_eq!(accepted.load(Ordering::SeqCst), 1, "never retried");
}

// 11 ------------------------------------------------------------------------

#[tokio::test]
async fn result_is_the_ordinary_token_set() {
    let server = MockServer::start().await;
    let key = oidc_support::generate_signing_key("native-result");
    let jwks = oidc_support::jwks_body(&[&key]);
    Mock::given(method("GET"))
        .and(path("/oauth2/jwks"))
        .respond_with(ResponseTemplate::new(200).set_body_json(jwks))
        .mount(&server)
        .await;
    let good = oidc_support::sign_id_token(
        &key,
        IdTokenOptions {
            nonce: Some(Some(RAW_NONCE)),
            ..Default::default()
        },
    );
    let client = build_client(&server.uri(), false);

    // Full response; the raw nonce is the expected nonce.
    let rec = mount_token(
        &server,
        ResponseTemplate::new(200).set_body_json(token_response(json!({
            "refresh_token": "r-1", "id_token": good, "token_type": "DPoP", "scope": "openid profile"
        }))),
    )
    .await;
    let tokens = client
        .login_with_provider_id_token(
            "p",
            s(PROVIDER_TOKEN),
            s(RAW_NONCE),
            ProviderIdTokenOptions {
                scopes: Some(vec!["openid".into()]),
                configuration: Some(configuration(&server.uri())),
                ..Default::default()
            },
        )
        .await
        .expect("ok");
    assert_eq!(tokens.token_type, "DPoP", "read, not assumed");
    assert_eq!(tokens.scope.as_deref(), Some("openid profile"));
    assert!(tokens.refresh_token.is_some() && tokens.id_token.is_some());
    assert!(tokens.id_claims.is_some());
    assert_eq!(rec.lock().unwrap().len(), 1);
    // The SDK's posture (as `login_client_credentials` and `device_login`):
    // the tokens are returned and not adopted. A second sign-in therefore
    // carries no credential from the first, and the client's tenant is still
    // the one it was built with.
    client
        .login_with_provider_id_token("p", s(PROVIDER_TOKEN), s(RAW_NONCE), options(&server.uri()))
        .await
        .expect("second");
    let seen = rec.lock().unwrap().clone();
    assert!(!seen[1].headers.contains_key("authorization"));
    assert!(!seen[1].headers.contains_key("cookie"));
    assert_eq!(
        client.resolved_tenant_id().await,
        Some(oidc_support::tenant_id())
    );

    // A mismatching nonce claim is the nonce_mismatch AuthError.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/oauth2/jwks"))
        .respond_with(ResponseTemplate::new(200).set_body_json(oidc_support::jwks_body(&[&key])))
        .mount(&server)
        .await;
    let wrong = oidc_support::sign_id_token(
        &key,
        IdTokenOptions {
            nonce: Some(Some("someone-else")),
            ..Default::default()
        },
    );
    mount_token(
        &server,
        ResponseTemplate::new(200).set_body_json(token_response(json!({"id_token": wrong}))),
    )
    .await;
    let client = build_client(&server.uri(), false);
    let err = login(&client, "p", &server.uri()).await.expect_err("nonce");
    assert_eq!(
        err.id_token_failure_reason(),
        Some(IdTokenFailureReason::NonceMismatch)
    );

    // A 200 without refresh_token and id_token decodes with both absent.
    let server = MockServer::start().await;
    mount_token(
        &server,
        ResponseTemplate::new(200).set_body_json(token_response(json!({}))),
    )
    .await;
    let client = build_client(&server.uri(), false);
    let tokens = login(&client, "p", &server.uri()).await.expect("ok");
    assert!(
        tokens.refresh_token.is_none() && tokens.id_token.is_none() && tokens.id_claims.is_none()
    );
    assert_eq!(tokens.token_type, "Bearer");
}

// 12 ------------------------------------------------------------------------

#[derive(Clone, Default)]
struct Collector(Arc<Mutex<Vec<String>>>);

impl TelemetrySink for Collector {
    fn emit(&self, event: &TelemetryEvent) {
        self.0.lock().unwrap().push(format!("{event:?}"));
    }
}

#[cfg(any(feature = "amqp", feature = "observability"))]
mod capture {
    //! A global `tracing` subscriber recording every event at every level.
    use std::sync::{Mutex, Once};
    pub static LOG: Mutex<Vec<String>> = Mutex::new(Vec::new());
    struct V(String);
    impl tracing::field::Visit for V {
        fn record_debug(&mut self, f: &tracing::field::Field, v: &dyn std::fmt::Debug) {
            self.0.push_str(&format!("{}={:?} ", f.name(), v));
        }
    }
    struct Rec;
    impl tracing::Subscriber for Rec {
        fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
            true
        }
        fn new_span(&self, a: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            let mut v = V(String::new());
            a.record(&mut v);
            LOG.lock().unwrap().push(v.0);
            tracing::span::Id::from_u64(1)
        }
        fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
        fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
        fn event(&self, e: &tracing::Event<'_>) {
            let mut v = V(String::new());
            e.record(&mut v);
            LOG.lock().unwrap().push(v.0);
        }
        fn enter(&self, _: &tracing::span::Id) {}
        fn exit(&self, _: &tracing::span::Id) {}
    }
    static INIT: Once = Once::new();
    pub fn init() {
        INIT.call_once(|| {
            let _ = tracing::subscriber::set_global_default(Rec);
        });
    }
}

#[tokio::test]
async fn no_secret_in_logs_or_errors() {
    #[cfg(any(feature = "amqp", feature = "observability"))]
    capture::init();

    let secret_token = "SECRET-PROVIDER-TOKEN-7d41e0";
    let secret_nonce = "SECRET-RAW-NONCE-b8c25a";
    let scenarios: Vec<(u16, serde_json::Value)> = vec![
        (
            400,
            json!({"error":"invalid_grant","error_description":GENERIC_DESCRIPTION}),
        ),
        (
            400,
            json!({"error":"consent_required","error_description":"consent"}),
        ),
        (
            400,
            json!({"error":"unauthorized_client","error_description":"x"}),
        ),
        (
            401,
            json!({"error":"invalid_client","error_description":"x"}),
        ),
        (
            400,
            json!({"error":"invalid_scope","error_description":"x"}),
        ),
        (
            400,
            json!({"error":"invalid_target","error_description":"x"}),
        ),
        (
            429,
            json!({"error":"rate_limit_exceeded","error_description":"x"}),
        ),
        (500, json!({"error":"server_error","error_description":"x"})),
        (500, json!(null)),
    ];
    let collector = Collector::default();
    let mut rendered: Vec<String> = Vec::new();
    for (status, body) in scenarios {
        let server = MockServer::start().await;
        let template = if body.is_null() {
            ResponseTemplate::new(status)
        } else {
            ResponseTemplate::new(status).set_body_json(body)
        };
        mount_token(&server, template).await;
        let client = AxiamClient::builder()
            .base_url(server.uri())
            .unwrap()
            .tenant_id(oidc_support::tenant_id())
            .org_id(oidc_support::org_id())
            .oidc_client_id(oidc_support::CLIENT_ID)
            .telemetry_hook(collector.clone())
            .build()
            .unwrap();
        let err = client
            .login_with_provider_id_token(
                "p",
                s(secret_token),
                s(secret_nonce),
                options(&server.uri()),
            )
            .await
            .expect_err("failure");
        rendered.push(format!(
            "{err} | {err:?} | {:#?}",
            err.as_oauth_protocol_error()
        ));
    }
    // The local refusals (test 5) and a successful sign-in with a mismatching
    // nonce (test 11) as well.
    let server = MockServer::start().await;
    let client = build_client(&server.uri(), false);
    let err = client
        .login_with_provider_id_token("", s(secret_token), s(secret_nonce), options(&server.uri()))
        .await
        .expect_err("empty");
    rendered.push(format!("{err} | {err:?}"));
    let err = client
        .login_with_provider_id_token("p", s(""), s(secret_nonce), options(&server.uri()))
        .await
        .expect_err("empty");
    rendered.push(format!("{err} | {err:?}"));
    let server = MockServer::start().await;
    mount_token(
        &server,
        ResponseTemplate::new(200).set_body_json(token_response(json!({}))),
    )
    .await;
    let ok = build_client(&server.uri(), false)
        .login_with_provider_id_token(
            "p",
            s(secret_token),
            s(secret_nonce),
            options(&server.uri()),
        )
        .await
        .expect("success");
    rendered.push(format!("{ok:?}"));
    let pair = native_nonce().unwrap();
    rendered.push(format!("{pair:?}"));
    // The raw nonce of the pair must not render; its hash may.
    assert!(!rendered.last().unwrap().contains(pair.raw.expose()));

    let mut haystack = rendered.join("\n");
    haystack.push_str(&collector.0.lock().unwrap().join("\n"));
    #[cfg(any(feature = "amqp", feature = "observability"))]
    haystack.push_str(&capture::LOG.lock().unwrap().join("\n"));
    for secret in [secret_token, secret_nonce] {
        assert!(!haystack.contains(secret), "{secret} leaked");
    }
}

// 13 ------------------------------------------------------------------------

#[test]
fn native_nonce_pair() {
    let a = native_nonce().expect("nonce");
    let b = native_nonce().expect("nonce");
    let raw = a.raw.expose();
    assert!(!raw.contains('='), "no padding");
    assert!(
        raw.bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
    );
    assert!(URL_SAFE_NO_PAD.decode(raw).expect("base64url").len() >= 32);
    assert_eq!(a.hashed.len(), 64);
    assert!(
        a.hashed
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    );
    use sha2::{Digest, Sha256};
    let expect: String = Sha256::digest(raw.as_bytes())
        .iter()
        .map(|x| format!("{x:02x}"))
        .collect();
    assert_eq!(a.hashed, expect);
    assert_ne!(a.raw.expose(), b.raw.expose());
    assert_ne!(a.hashed, b.hashed);
    assert_eq!(
        format!("{:?}", a.raw),
        "Sensitive(<redacted>)",
        "raw is wrapped"
    );
    // The fixed vector, for the hashing step.
    let vector: String = Sha256::digest(RAW_NONCE.as_bytes())
        .iter()
        .map(|x| format!("{x:02x}"))
        .collect();
    assert_eq!(vector, RAW_NONCE_SHA256);
}

// idp_hint ------------------------------------------------------------------

fn begin(
    client: &AxiamClient,
    base: &str,
    params: OidcBeginParams,
) -> Result<axiam_sdk::oidc::AuthorizationRequest, AxiamError> {
    client.oidc_begin(&configuration(base), params)
}

fn query_pairs(url: &str) -> Vec<(String, String)> {
    url::Url::parse(url)
        .unwrap()
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect()
}

fn count(pairs: &[(String, String)], key: &str) -> usize {
    pairs.iter().filter(|(k, _)| k == key).count()
}

const EIGHT: [&str; 8] = [
    "response_type",
    "client_id",
    "redirect_uri",
    "scope",
    "state",
    "nonce",
    "code_challenge",
    "code_challenge_method",
];

#[test]
fn idp_hint_emitted_once() {
    let client = build_client("https://iam.example.com", false);
    let uuid = "0b9e6c74-1a2b-4c3d-8e4f-5a6b7c8d9e0f";
    for hint in ["corp-okta", uuid, "Google", "a b&c=d/é+%"] {
        let req = begin(
            &client,
            "https://iam.example.com",
            OidcBeginParams::new("https://app/cb").with_idp_hint(hint),
        )
        .unwrap();
        let pairs = query_pairs(&req.url);
        assert_eq!(count(&pairs, "axiam_idp_hint"), 1);
        assert_eq!(
            pairs.iter().find(|(k, _)| k == "axiam_idp_hint").unwrap().1,
            hint
        );
        for k in EIGHT {
            assert_eq!(count(&pairs, k), 1, "{k}");
        }
        assert_eq!(pairs.len(), 9);
    }
}

#[test]
fn idp_hint_omitted_when_unset() {
    let client = build_client("https://iam.example.com", false);
    let req = begin(
        &client,
        "https://iam.example.com",
        OidcBeginParams::new("https://app/cb"),
    )
    .unwrap();
    let pairs = query_pairs(&req.url);
    assert_eq!(count(&pairs, "axiam_idp_hint"), 0);
    assert_eq!(count(&pairs, "kc_idp_hint"), 0);
    let keys: BTreeSet<&str> = pairs.iter().map(|(k, _)| k.as_str()).collect();
    assert_eq!(keys, EIGHT.iter().copied().collect::<BTreeSet<_>>());
}

#[test]
fn idp_hint_not_duplicated() {
    let client = build_client("https://iam.example.com", false);
    let set = begin(
        &client,
        "https://iam.example.com",
        OidcBeginParams::new("https://app/cb")
            .with_extra_param("axiam_idp_hint", "other")
            .with_idp_hint("mine"),
    )
    .unwrap();
    let pairs = query_pairs(&set.url);
    assert_eq!(count(&pairs, "axiam_idp_hint"), 1);
    assert_eq!(
        pairs.iter().find(|(k, _)| k == "axiam_idp_hint").unwrap().1,
        "mine"
    );
    // Unset: the caller's extra passes through, still once.
    let unset = begin(
        &client,
        "https://iam.example.com",
        OidcBeginParams::new("https://app/cb").with_extra_param("axiam_idp_hint", "other"),
    )
    .unwrap();
    let pairs = query_pairs(&unset.url);
    assert_eq!(count(&pairs, "axiam_idp_hint"), 1);
    assert_eq!(
        pairs.iter().find(|(k, _)| k == "axiam_idp_hint").unwrap().1,
        "other"
    );
}

#[test]
fn idp_hint_bounds() {
    let client = build_client("https://iam.example.com", false);
    for bad in [String::new(), "x".repeat(257), "é".repeat(129)] {
        let err = begin(
            &client,
            "https://iam.example.com",
            OidcBeginParams::new("https://app/cb").with_idp_hint(bad),
        )
        .expect_err("refused, no URL built");
        assert!(err.validation().is_some(), "{err:?}");
    }
    let ok = "y".repeat(256);
    let req = begin(
        &client,
        "https://iam.example.com",
        OidcBeginParams::new("https://app/cb").with_idp_hint(ok.clone()),
    )
    .unwrap();
    let pairs = query_pairs(&req.url);
    assert_eq!(
        pairs.iter().find(|(k, _)| k == "axiam_idp_hint").unwrap().1,
        ok
    );
}

#[tokio::test]
async fn par_idp_hint_in_pushed_body() {
    for hint in [Some("corp-okta"), None] {
        let server = MockServer::start().await;
        let rec: Recorder = Arc::default();
        let r = Arc::clone(&rec);
        Mock::given(method("POST"))
            .and(path("/oauth2/par"))
            .respond_with(move |req: &Request| {
                record(req, &r);
                ResponseTemplate::new(201).set_body_json(
                    json!({"request_uri":"urn:ietf:params:oauth:request_uri:abc","expires_in":90}),
                )
            })
            .mount(&server)
            .await;
        let client = build_client(&server.uri(), true);
        let cfg = configuration(&server.uri());
        let mut p = OidcBeginParams::new("https://app/cb");
        if let Some(h) = hint {
            p = p.with_idp_hint(h);
        }
        let request = client.oidc_begin(&cfg, p).unwrap();
        let pushed = client
            .oidc_par(OidcParParams {
                request,
                redirect_uri: "https://app/cb".into(),
                scope: None,
                tenant_id: None,
                configuration: Some(cfg),
                dpop_jkt: None,
            })
            .await
            .unwrap();
        let seen = rec.lock().unwrap().clone();
        match hint {
            Some(h) => {
                assert_eq!(seen[0].form["axiam_idp_hint"], h);
                assert_eq!(seen[0].body.matches("axiam_idp_hint=").count(), 1);
            }
            None => assert!(!seen[0].form.contains_key("axiam_idp_hint")),
        }
        // The redirect carries the same parameter set with or without a hint.
        let keys: BTreeSet<String> = query_pairs(&pushed.url)
            .into_iter()
            .map(|(k, _)| k)
            .collect();
        let expected: BTreeSet<String> = ["tenant_id", "client_id", "request_uri"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(keys, expected);
    }
}

// §9 confirmation -----------------------------------------------------------

#[tokio::test]
async fn oidc_refresh_invalid_grant_burst_is_one_call_and_one_shared_error() {
    const N: usize = 8;
    let server = MockServer::start().await;
    let rec: Recorder = Arc::default();
    let r = Arc::clone(&rec);
    Mock::given(method("POST"))
        .and(path("/oauth2/token"))
        .respond_with(move |req: &Request| {
            record(req, &r);
            ResponseTemplate::new(400)
                .set_body_json(
                    json!({"error":"invalid_grant","error_description":"refresh token reused"}),
                )
                .set_delay(Duration::from_millis(200))
        })
        .mount(&server)
        .await;
    let client = build_client(&server.uri(), true);
    let cfg = configuration(&server.uri());
    let mut handles = Vec::new();
    for _ in 0..N {
        let client = client.clone();
        let cfg = cfg.clone();
        handles.push(tokio::spawn(async move {
            client
                .oidc_refresh(OidcRefreshParams {
                    refresh_token: Sensitive::new("spent-refresh-token".into()),
                    scope: None,
                    tenant_id: None,
                    configuration: Some(cfg),
                })
                .await
        }));
    }
    for h in handles {
        let err = h
            .await
            .unwrap()
            .expect_err("every waiter gets the one error");
        let oauth = err.as_oauth_protocol_error().expect("OAuthProtocolError");
        assert_eq!(oauth.error, "invalid_grant");
    }
    // Nothing follows: the SDK holds no refresh token, so nothing later can
    // present the spent one again unless the caller passes it.
    tokio::time::sleep(Duration::from_millis(400)).await;
    let seen = rec.lock().unwrap().clone();
    assert_eq!(seen.len(), 1, "exactly one wire call for the whole burst");
    assert_eq!(seen[0].form["refresh_token"], "spent-refresh-token");
}
