//! CONTRACT.md §14.6 and §12.1 rule 3 (contract 1.62) — a session or adopted
//! bearer credential never reaches an `/oauth2/*` request.
//!
//! The device operations (`device_authorize`, `device_poll`) go to
//! `/oauth2/device_authorization` and `/oauth2/token` through the SDK's raw
//! transport, which has no session-credential step. This pins that: with a
//! credential adopted by `authenticate_device` (a body-delivered bearer, the
//! case the other SDKs got wrong, review C162-05), and with a cookie session
//! from `login`, neither request carries an `Authorization` header — the
//! client's own authentication is the `client_secret` form member. In the
//! adopted-bearer case the access token's text is also absent from every part
//! of both requests.

#![cfg(feature = "rest")]

mod management_support;

use std::sync::{Arc, Mutex};

use axiam_sdk::Sensitive;
use axiam_sdk::client::AxiamClient;
use axiam_sdk::oidc::{DeviceAuthorizeParams, DevicePollParams};
use serde_json::json;
use uuid::Uuid;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

use management_support::{ORG_ID, TENANT_ID, mount_jwks, sign_claims};

const CLIENT_ID: &str = "device-client";
const CLIENT_SECRET: &str = "device-client-secret-value";
const DEVICE_CODE: &str = "device-code-value";

/// One request, as the server saw it.
#[derive(Debug, Clone)]
struct Seen {
    route: String,
    authorization: Option<String>,
    /// Every header value and the body, rendered, to search for a token's text.
    everything: String,
}

type Log = Arc<Mutex<Vec<Seen>>>;

/// Record every request that reaches `/oauth2/*` on this server.
async fn mount_oauth2(server: &MockServer) -> Log {
    let log: Log = Arc::default();

    let document = json!({
        "issuer": "https://iam.example.test",
        "authorization_endpoint": format!("{}/oauth2/authorize", server.uri()),
        "token_endpoint": format!("{}/oauth2/token", server.uri()),
        "userinfo_endpoint": format!("{}/oauth2/userinfo", server.uri()),
        "revocation_endpoint": format!("{}/oauth2/revoke", server.uri()),
        "introspection_endpoint": format!("{}/oauth2/introspect", server.uri()),
        "jwks_uri": format!("{}/oauth2/jwks", server.uri()),
        "device_authorization_endpoint":
            format!("{}/oauth2/device_authorization", server.uri()),
        "response_types_supported": ["code"],
        "scopes_supported": ["openid"],
        "claims_supported": ["sub"],
        "grant_types_supported": ["urn:ietf:params:oauth:grant-type:device_code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["EdDSA"],
        "token_endpoint_auth_methods_supported": ["client_secret_post"],
    });
    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(200).set_body_json(document))
        .mount(server)
        .await;

    for (route, answer) in [
        (
            "/oauth2/device_authorization",
            ResponseTemplate::new(200).set_body_json(json!({
                "device_code": DEVICE_CODE, "user_code": "WDJB-MJHT",
                "verification_uri": "https://iam.example.com/device",
                "expires_in": 30, "interval": 1,
            })),
        ),
        (
            "/oauth2/token",
            ResponseTemplate::new(200).set_body_json(json!({
                "access_token": "polled-access-token", "token_type": "Bearer",
                "expires_in": 900,
            })),
        ),
    ] {
        let sink = Arc::clone(&log);
        Mock::given(method("POST"))
            .and(path(route))
            .respond_with(move |req: &Request| {
                let mut everything = String::from_utf8_lossy(&req.body).into_owned();
                for (name, value) in req.headers.iter() {
                    everything.push_str(&format!(
                        "\n{}: {}",
                        name.as_str(),
                        value.to_str().unwrap_or_default()
                    ));
                }
                sink.lock().unwrap().push(Seen {
                    route: req.url.path().to_string(),
                    authorization: req
                        .headers
                        .get("authorization")
                        .map(|v| v.to_str().unwrap().to_string()),
                    everything,
                });
                answer.clone()
            })
            .mount(server)
            .await;
    }
    log
}

fn builder(base_url: &str) -> axiam_sdk::client::AxiamClientBuilder {
    AxiamClient::builder()
        .base_url(base_url)
        .unwrap()
        .tenant_id(Uuid::parse_str(TENANT_ID).unwrap())
        .org_id(Uuid::parse_str(ORG_ID).unwrap())
        .retry_enabled(false)
        .oidc_client_id(CLIENT_ID)
        .oidc_client_secret(CLIENT_SECRET)
}

/// Run both device operations and return what the two `/oauth2/*` routes saw.
async fn run_device_operations(client: &AxiamClient, log: &Log) -> Vec<Seen> {
    client
        .device_authorize(DeviceAuthorizeParams::default())
        .await
        .expect("device_authorize");
    client
        .device_poll(DevicePollParams {
            device_code: Sensitive::new(DEVICE_CODE.to_string()),
            tenant_id: None,
            configuration: None,
        })
        .await
        .expect("device_poll");
    let seen = log.lock().unwrap().clone();
    let routes: Vec<&str> = seen.iter().map(|s| s.route.as_str()).collect();
    assert_eq!(
        routes,
        ["/oauth2/device_authorization", "/oauth2/token"],
        "one request to each device endpoint"
    );
    seen
}

/// A body-delivered bearer adopted by `authenticate_device` (§6.1 rule 6) is
/// the identity of every `/api/v1/*` call and of none at `/oauth2/*`.
#[tokio::test]
async fn an_adopted_device_bearer_reaches_neither_device_endpoint() {
    let server = MockServer::start().await;
    mount_jwks(&server).await;
    let log = mount_oauth2(&server).await;

    let token = sign_claims(&json!({
        "sub": Uuid::new_v4().to_string(),
        "sub_kind": "service_account",
        "aud": "axiam:m2m",
        "tenant_id": TENANT_ID,
        "org_id": ORG_ID,
        "iss": "axiam-test",
        "iat": 0,
        "exp": 9_999_999_999i64,
        "jti": Uuid::new_v4().to_string(),
        "cnf": { "x5t#S256": "dGhpcy1pcy1hLXRlc3QtdGh1bWJwcmludC1ub3QtcmVhbA" },
    }));
    Mock::given(method("POST"))
        .and(path("/api/v1/auth/device"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": token, "token_type": "Bearer", "expires_in": 900,
        })))
        .mount(&server)
        .await;

    let cert = rcgen::generate_simple_self_signed(vec!["device-001".to_string()])
        .expect("rcgen certificate");
    let client = builder(&server.uri())
        .with_client_cert(
            cert.cert.pem().as_bytes(),
            cert.signing_key.serialize_pem().as_bytes(),
        )
        .unwrap()
        .build()
        .unwrap();
    client.authenticate_device().await.expect("device login");

    for seen in run_device_operations(&client, &log).await {
        assert_eq!(
            seen.authorization, None,
            "{}: no Authorization header (§14.6)",
            seen.route
        );
        assert!(
            !seen.everything.contains(&token),
            "{}: the adopted access token appears nowhere in the request",
            seen.route
        );
        assert!(
            seen.everything.contains(CLIENT_SECRET),
            "{}: the client authenticates with its own client_secret (§14.1 rule 2)",
            seen.route
        );
    }
}

/// A cookie session from `login` is not turned into a bearer either.
#[tokio::test]
async fn a_cookie_session_sends_no_authorization_header_to_the_device_endpoints() {
    let server = MockServer::start().await;
    mount_jwks(&server).await;
    let log = mount_oauth2(&server).await;

    let access = sign_claims(&json!({
        "sub": Uuid::new_v4().to_string(),
        "tenant_id": TENANT_ID,
        "org_id": ORG_ID,
        "iss": "axiam-test",
        "iat": 0,
        "exp": 9_999_999_999i64,
        "jti": Uuid::new_v4().to_string(),
    }));
    let mut login = ResponseTemplate::new(200).set_body_json(json!({
        "user": { "id": Uuid::new_v4(), "username": "admin", "email": "admin@example.com" },
        "session_id": Uuid::new_v4(),
        "expires_in": 900,
    }));
    for cookie in [
        format!("axiam_access={access}; Path=/; HttpOnly"),
        "axiam_refresh=test-refresh-token; Path=/; HttpOnly".to_string(),
        "axiam_csrf=test-csrf-token; Path=/".to_string(),
    ] {
        login = login.append_header("Set-Cookie", cookie.as_str());
    }
    Mock::given(method("POST"))
        .and(path("/api/v1/auth/login"))
        .respond_with(login)
        .mount(&server)
        .await;

    let client = builder(&server.uri()).build().unwrap();
    client
        .login("admin@example.com", "correct horse battery staple")
        .await
        .expect("login");

    for seen in run_device_operations(&client, &log).await {
        assert_eq!(
            seen.authorization, None,
            "{}: no Authorization header (§14.6)",
            seen.route
        );
    }
}
