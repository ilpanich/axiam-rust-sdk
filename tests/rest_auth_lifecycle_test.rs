//! `refresh()`/`logout()`/`verify_mfa()` (`src/rest/auth.rs`, CONTRACT.md
//! §1/§9) — `tests/login_mfa_flow_test.rs` covers `login()`'s success/MFA/
//! error paths in depth but never exercises `refresh`, `logout`, or
//! `verify_mfa`'s own error branches (calling it with no prior `login()`,
//! a non-2xx response, etc.). This file closes that gap end to end against
//! `wiremock`, mirroring the same fixed-Ed25519-keypair JWT pattern.

#![cfg(feature = "rest")]

use axiam_sdk::AxiamError;
use axiam_sdk::client::AxiamClient;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde::Serialize;
use serde_json::json;
use uuid::Uuid;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const TEST_ED25519_SEED: [u8; 32] = [
    0x74, 0x8c, 0x0b, 0xd3, 0xad, 0xc0, 0x28, 0x0a, 0xfd, 0xd7, 0xc0, 0x7c, 0x35, 0x07, 0x03, 0x64,
    0x6d, 0x14, 0x2d, 0x1d, 0xbd, 0x73, 0x4c, 0xd4, 0xf8, 0x17, 0x17, 0x0b, 0x91, 0x7b, 0x49, 0xfc,
];
const ED25519_PKCS8_DER_PREFIX: [u8; 16] = [
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];
const TEST_ED25519_PUBLIC_X: &str = "_r-I_0nRSSV8kvwA93gwhX-hFRiWkaNk5HEud-DjnMk";
const TEST_KID: &str = "test-kid-1";

#[derive(Debug, Serialize)]
struct TestClaims {
    sub: String,
    tenant_id: String,
    org_id: String,
    iss: String,
    iat: i64,
    exp: i64,
    jti: String,
}

fn issue_test_access_token(tenant_id: Uuid, org_id: Uuid, user_id: Uuid, jti: Uuid) -> String {
    let mut header = Header::new(Algorithm::EdDSA);
    header.kid = Some(TEST_KID.to_string());
    let claims = TestClaims {
        sub: user_id.to_string(),
        tenant_id: tenant_id.to_string(),
        org_id: org_id.to_string(),
        iss: "axiam-test".to_string(),
        iat: 0,
        exp: 9_999_999_999,
        jti: jti.to_string(),
    };
    let mut der = ED25519_PKCS8_DER_PREFIX.to_vec();
    der.extend_from_slice(&TEST_ED25519_SEED);
    let key = EncodingKey::from_ed_der(&der);
    jsonwebtoken::encode(&header, &claims, &key).expect("encode test access token")
}

fn jwks_body() -> serde_json::Value {
    json!({
        "keys": [
            {
                "kty": "OKP",
                "crv": "Ed25519",
                "kid": TEST_KID,
                "alg": "EdDSA",
                "x": TEST_ED25519_PUBLIC_X,
            }
        ]
    })
}

async fn mount_jwks(mock_server: &MockServer) {
    Mock::given(method("GET"))
        .and(path("/oauth2/jwks"))
        .respond_with(ResponseTemplate::new(200).set_body_json(jwks_body()))
        .mount(mock_server)
        .await;
}

fn session_cookies_header(access_token: &str, refresh_token: &str, csrf: &str) -> Vec<String> {
    vec![
        format!("axiam_access={access_token}; Path=/; HttpOnly"),
        format!("axiam_refresh={refresh_token}; Path=/; HttpOnly"),
        format!("axiam_csrf={csrf}; Path=/"),
    ]
}

fn build_client(base_url: &str) -> AxiamClient {
    AxiamClient::builder()
        .base_url(base_url)
        .expect("valid base_url")
        .tenant_slug("acme")
        .build()
        .expect("client with tenant_slug builds successfully")
}

/// Log a fresh client in against `mock_server` (which must already have the
/// JWKS + login mocks mounted) so `refresh`/`logout` tests start from a
/// state with resolved tenant_id/org_id/session — exactly what those two
/// methods require before they can do anything.
async fn logged_in_client(mock_server: &MockServer) -> (AxiamClient, Uuid, Uuid) {
    mount_jwks(mock_server).await;

    let tenant_id = Uuid::new_v4();
    let org_id = Uuid::new_v4();
    let user_id = Uuid::new_v4();
    let session_id = Uuid::new_v4();
    let access_token = issue_test_access_token(tenant_id, org_id, user_id, session_id);

    let mut response = ResponseTemplate::new(200).set_body_json(json!({
        "user": { "id": user_id, "username": "alice", "email": "alice@example.com" },
        "session_id": session_id,
        "expires_in": 900,
    }));
    for cookie in session_cookies_header(&access_token, "initial-refresh-token", "initial-csrf") {
        response = response.append_header("Set-Cookie", cookie.as_str());
    }
    Mock::given(method("POST"))
        .and(path("/api/v1/auth/login"))
        .respond_with(response)
        .mount(mock_server)
        .await;

    let client = build_client(&mock_server.uri());
    client
        .login("alice@example.com", "correct horse battery staple")
        .await
        .expect("seed login must succeed");
    (client, tenant_id, org_id)
}

// ---------------------------------------------------------------------------
// refresh()
// ---------------------------------------------------------------------------

#[tokio::test]
async fn refresh_before_login_fails_with_no_access_token() {
    let mock_server = MockServer::start().await;
    let client = build_client(&mock_server.uri());

    let err = client
        .refresh()
        .await
        .expect_err("refresh() before any login() must fail");
    assert!(matches!(err, AxiamError::Auth { .. }));
}

#[tokio::test]
async fn refresh_success_rotates_tokens_and_updates_state() {
    let mock_server = MockServer::start().await;
    let (client, tenant_id, _org_id) = logged_in_client(&mock_server).await;

    let new_session_id = Uuid::new_v4();
    let new_access =
        issue_test_access_token(tenant_id, Uuid::new_v4(), Uuid::new_v4(), new_session_id);
    let mut refresh_response = ResponseTemplate::new(200).set_body_json(json!({
        "expires_in": 900,
    }));
    for cookie in session_cookies_header(&new_access, "rotated-refresh-token", "rotated-csrf") {
        refresh_response = refresh_response.append_header("Set-Cookie", cookie.as_str());
    }
    Mock::given(method("POST"))
        .and(path("/api/v1/auth/refresh"))
        .respond_with(refresh_response)
        .mount(&mock_server)
        .await;

    client
        .refresh()
        .await
        .expect("refresh() should succeed against the mock");

    assert_eq!(client.resolved_tenant_id().await, Some(tenant_id));
}

#[tokio::test]
async fn refresh_401_maps_to_auth_error_with_no_retry() {
    let mock_server = MockServer::start().await;
    let (client, _tenant_id, _org_id) = logged_in_client(&mock_server).await;

    Mock::given(method("POST"))
        .and(path("/api/v1/auth/refresh"))
        .respond_with(ResponseTemplate::new(401).set_body_string("refresh token expired"))
        .mount(&mock_server)
        .await;

    let err = client
        .refresh()
        .await
        .expect_err("a 401 on the refresh call itself must surface as AuthError");
    assert!(matches!(err, AxiamError::Auth { .. }));
}

// ---------------------------------------------------------------------------
// logout()
// ---------------------------------------------------------------------------

#[tokio::test]
async fn logout_before_login_fails_with_no_active_session() {
    let mock_server = MockServer::start().await;
    let client = build_client(&mock_server.uri());

    let err = client
        .logout()
        .await
        .expect_err("logout() with no prior login() must fail");
    assert!(matches!(err, AxiamError::Auth { .. }));
}

#[tokio::test]
async fn logout_success_clears_token_state() {
    let mock_server = MockServer::start().await;
    let (client, tenant_id, _org_id) = logged_in_client(&mock_server).await;
    assert_eq!(client.resolved_tenant_id().await, Some(tenant_id));

    Mock::given(method("POST"))
        .and(path("/api/v1/auth/logout"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&mock_server)
        .await;

    client.logout().await.expect("logout() should succeed");

    // After logout, refresh() must fail again with "no access token" since
    // the token state was cleared.
    let err = client
        .refresh()
        .await
        .expect_err("token state must be cleared after logout");
    assert!(matches!(err, AxiamError::Auth { .. }));
}

#[tokio::test]
async fn logout_non_success_status_is_mapped_to_error() {
    let mock_server = MockServer::start().await;
    let (client, _tenant_id, _org_id) = logged_in_client(&mock_server).await;

    Mock::given(method("POST"))
        .and(path("/api/v1/auth/logout"))
        .respond_with(ResponseTemplate::new(500).set_body_string("internal error"))
        .mount(&mock_server)
        .await;

    let err = client
        .logout()
        .await
        .expect_err("a non-success logout response must surface as an error");
    assert!(matches!(err, AxiamError::Network { .. }));
}

// ---------------------------------------------------------------------------
// verify_mfa()
// ---------------------------------------------------------------------------

#[tokio::test]
async fn verify_mfa_with_no_pending_challenge_fails() {
    let mock_server = MockServer::start().await;
    let client = build_client(&mock_server.uri());

    let err = client
        .verify_mfa("123456")
        .await
        .expect_err("verify_mfa() with no prior mfa_required login() must fail");
    assert!(matches!(err, AxiamError::Auth { .. }));
}

#[tokio::test]
async fn verify_mfa_error_status_is_mapped() {
    let mock_server = MockServer::start().await;
    mount_jwks(&mock_server).await;

    Mock::given(method("POST"))
        .and(path("/api/v1/auth/login"))
        .respond_with(ResponseTemplate::new(202).set_body_json(json!({
            "mfa_required": true,
            "challenge_token": "test-challenge-token",
            "available_methods": ["totp"],
        })))
        .mount(&mock_server)
        .await;

    let client = build_client(&mock_server.uri());
    client
        .login("alice@example.com", "correct horse battery staple")
        .await
        .expect("login should report mfa_required");

    Mock::given(method("POST"))
        .and(path("/api/v1/auth/mfa/verify"))
        .respond_with(ResponseTemplate::new(401).set_body_string("invalid TOTP code"))
        .mount(&mock_server)
        .await;

    let err = client
        .verify_mfa("000000")
        .await
        .expect_err("a wrong TOTP code must surface as an error");
    assert!(matches!(err, AxiamError::Auth { .. }));
}

// ---------------------------------------------------------------------------
// login() transport failure
// ---------------------------------------------------------------------------

#[tokio::test]
async fn login_against_an_unreachable_server_maps_to_network_error() {
    // Bind an ephemeral loopback port, then immediately drop the listener so
    // nothing is bound to it any more — the OS refuses the next connection
    // attempt deterministically, without the shutdown race a live
    // `wiremock::MockServer` drop would introduce. Exercises `login()`'s
    // `reqwest` transport-error branch (connection refused), not a non-2xx
    // status response.
    let listener =
        std::net::TcpListener::bind("127.0.0.1:0").expect("bind an ephemeral loopback port");
    let addr = listener.local_addr().expect("resolve bound local_addr");
    drop(listener);

    let client = build_client(&format!("http://{addr}"));

    let err = client
        .login("alice@example.com", "correct horse battery staple")
        .await
        .expect_err("a request against a closed loopback port must fail");
    assert!(matches!(err, AxiamError::Network { .. }));
}
