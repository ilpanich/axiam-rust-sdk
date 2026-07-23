//! Additional `src/rest/auth.rs` coverage: the `verify_mfa` success path
//! (the lifecycle suite only exercises its error path), `build_login_body`'s
//! `tenant_id`/`org_id`/`org_slug` branches (the lifecycle suite always
//! builds with `tenant_slug` and no org), the `X-Tenant-ID` UUID header form,
//! and `absorb_session_cookies`' missing-cookie failure.

#![cfg(feature = "rest")]

use axiam_sdk::AxiamError;
use axiam_sdk::client::AxiamClient;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde::Serialize;
use serde_json::json;
use uuid::Uuid;
use wiremock::matchers::{body_string_contains, method, path};
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

fn issue_test_access_token(tenant_id: Uuid, org_id: Uuid) -> String {
    let mut header = Header::new(Algorithm::EdDSA);
    header.kid = Some(TEST_KID.to_string());
    let claims = TestClaims {
        sub: Uuid::new_v4().to_string(),
        tenant_id: tenant_id.to_string(),
        org_id: org_id.to_string(),
        iss: "axiam-test".to_string(),
        iat: 0,
        exp: 9_999_999_999,
        jti: Uuid::new_v4().to_string(),
    };
    let mut der = ED25519_PKCS8_DER_PREFIX.to_vec();
    der.extend_from_slice(&TEST_ED25519_SEED);
    let key = EncodingKey::from_ed_der(&der);
    jsonwebtoken::encode(&header, &claims, &key).expect("encode token")
}

fn jwks_body() -> serde_json::Value {
    json!({
        "keys": [{
            "kty": "OKP",
            "crv": "Ed25519",
            "kid": TEST_KID,
            "alg": "EdDSA",
            "x": TEST_ED25519_PUBLIC_X,
        }]
    })
}

async fn mount_jwks(mock_server: &MockServer) {
    Mock::given(method("GET"))
        .and(path("/oauth2/jwks"))
        .respond_with(ResponseTemplate::new(200).set_body_json(jwks_body()))
        .mount(mock_server)
        .await;
}

fn session_cookies(access: &str, refresh: &str, csrf: &str) -> Vec<String> {
    vec![
        format!("axiam_access={access}; Path=/; HttpOnly"),
        format!("axiam_refresh={refresh}; Path=/; HttpOnly"),
        format!("axiam_csrf={csrf}; Path=/"),
    ]
}

fn login_ok_response(access: &str) -> ResponseTemplate {
    let mut response = ResponseTemplate::new(200).set_body_json(json!({
        "user": { "id": Uuid::new_v4(), "username": "alice", "email": "alice@example.com" },
        "session_id": Uuid::new_v4(),
        "expires_in": 900,
    }));
    for cookie in session_cookies(access, "refresh-token", "csrf-token") {
        response = response.append_header("Set-Cookie", cookie.as_str());
    }
    response
}

#[tokio::test]
async fn login_with_tenant_id_and_org_id_sends_uuid_identifiers_and_then_logs_out() {
    let mock_server = MockServer::start().await;
    mount_jwks(&mock_server).await;

    let tenant_id = Uuid::new_v4();
    let org_id = Uuid::new_v4();
    let access = issue_test_access_token(tenant_id, org_id);

    // The login body must carry the UUID tenant_id/org_id (not slugs) — this
    // exercises `build_login_body`'s `TenantIdentifier::Id`/`OrgIdentifier::Id`
    // arms.
    Mock::given(method("POST"))
        .and(path("/api/v1/auth/login"))
        .and(body_string_contains(tenant_id.to_string()))
        .and(body_string_contains(org_id.to_string()))
        .respond_with(login_ok_response(&access))
        .mount(&mock_server)
        .await;

    let client = AxiamClient::builder()
        .base_url(mock_server.uri())
        .expect("valid base_url")
        .tenant_id(tenant_id)
        .org_id(org_id)
        .build()
        .expect("client builds");

    client
        .login("alice@example.com", "correct horse battery staple")
        .await
        .expect("login with UUID identifiers must succeed");
    assert_eq!(client.resolved_tenant_id().await, Some(tenant_id));

    // logout sends `X-Tenant-ID` via the UUID header form (tenant_header_value
    // on the `Id` variant).
    Mock::given(method("POST"))
        .and(path("/api/v1/auth/logout"))
        .and(wiremock::matchers::header(
            "X-Tenant-ID",
            tenant_id.to_string().as_str(),
        ))
        .respond_with(ResponseTemplate::new(204))
        .mount(&mock_server)
        .await;

    client
        .logout()
        .await
        .expect("logout must send the UUID X-Tenant-ID header and succeed");
}

#[tokio::test]
async fn login_with_org_slug_sends_the_slug_in_the_body() {
    let mock_server = MockServer::start().await;
    mount_jwks(&mock_server).await;

    let tenant_id = Uuid::new_v4();
    let org_id = Uuid::new_v4();
    let access = issue_test_access_token(tenant_id, org_id);

    Mock::given(method("POST"))
        .and(path("/api/v1/auth/login"))
        .and(body_string_contains("globex-inc"))
        .respond_with(login_ok_response(&access))
        .mount(&mock_server)
        .await;

    let client = AxiamClient::builder()
        .base_url(mock_server.uri())
        .expect("valid base_url")
        .tenant_slug("acme")
        .org_slug("globex-inc")
        .build()
        .expect("client builds");

    client
        .login("alice@example.com", "correct horse battery staple")
        .await
        .expect("login with an org_slug must succeed");
}

#[tokio::test]
async fn verify_mfa_success_absorbs_the_rotated_session() {
    let mock_server = MockServer::start().await;
    mount_jwks(&mock_server).await;

    let tenant_id = Uuid::new_v4();
    let org_id = Uuid::new_v4();

    // Phase 1: login returns 202 mfa_required, seeding the pending challenge.
    Mock::given(method("POST"))
        .and(path("/api/v1/auth/login"))
        .respond_with(ResponseTemplate::new(202).set_body_json(json!({
            "mfa_required": true,
            "challenge_token": "challenge-abc",
            "available_methods": ["totp"],
        })))
        .mount(&mock_server)
        .await;

    let client = AxiamClient::builder()
        .base_url(mock_server.uri())
        .expect("valid base_url")
        .tenant_slug("acme")
        .build()
        .expect("client builds");

    let login = client
        .login("alice@example.com", "correct horse battery staple")
        .await
        .expect("login should report mfa_required");
    assert!(login.mfa_required);

    // Phase 2: verify_mfa returns 200 with a full rotated session.
    let access = issue_test_access_token(tenant_id, org_id);
    Mock::given(method("POST"))
        .and(path("/api/v1/auth/mfa/verify"))
        .respond_with(login_ok_response(&access))
        .mount(&mock_server)
        .await;

    let result = client
        .verify_mfa("123456")
        .await
        .expect("a correct TOTP code must complete the flow");
    assert!(!result.mfa_required);
    assert_eq!(client.resolved_tenant_id().await, Some(tenant_id));
}

// ---------------------------------------------------------------------------
// Malformed success bodies -> `deser_err` (`src/rest/auth.rs::deser_err`)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn login_200_with_malformed_body_is_a_network_error() {
    let mock_server = MockServer::start().await;
    mount_jwks(&mock_server).await;

    // A 200 status but a body that is not valid JSON at all: `deser_err`
    // must map the `response.json()` failure to a Network error rather than
    // panic.
    Mock::given(method("POST"))
        .and(path("/api/v1/auth/login"))
        .respond_with(ResponseTemplate::new(200).set_body_string("not json at all {{{"))
        .mount(&mock_server)
        .await;

    let client = AxiamClient::builder()
        .base_url(mock_server.uri())
        .expect("valid base_url")
        .tenant_slug("acme")
        .build()
        .expect("client builds");

    let err = client
        .login("alice@example.com", "correct horse battery staple")
        .await
        .expect_err("a malformed 200 login body must surface as an error, not panic");
    assert!(matches!(err, AxiamError::Network { .. }));
}

#[tokio::test]
async fn login_202_with_malformed_body_is_a_network_error() {
    let mock_server = MockServer::start().await;
    mount_jwks(&mock_server).await;

    // A 202 status (MFA-required shape expected) but a malformed body.
    Mock::given(method("POST"))
        .and(path("/api/v1/auth/login"))
        .respond_with(ResponseTemplate::new(202).set_body_string("not json at all {{{"))
        .mount(&mock_server)
        .await;

    let client = AxiamClient::builder()
        .base_url(mock_server.uri())
        .expect("valid base_url")
        .tenant_slug("acme")
        .build()
        .expect("client builds");

    let err = client
        .login("alice@example.com", "correct horse battery staple")
        .await
        .expect_err("a malformed 202 login body must surface as an error, not panic");
    assert!(matches!(err, AxiamError::Network { .. }));
}

#[tokio::test]
async fn verify_mfa_200_with_malformed_body_is_a_network_error() {
    let mock_server = MockServer::start().await;
    mount_jwks(&mock_server).await;

    Mock::given(method("POST"))
        .and(path("/api/v1/auth/login"))
        .respond_with(ResponseTemplate::new(202).set_body_json(json!({
            "mfa_required": true,
            "challenge_token": "challenge-abc",
            "available_methods": ["totp"],
        })))
        .mount(&mock_server)
        .await;

    let client = AxiamClient::builder()
        .base_url(mock_server.uri())
        .expect("valid base_url")
        .tenant_slug("acme")
        .build()
        .expect("client builds");

    client
        .login("alice@example.com", "correct horse battery staple")
        .await
        .expect("login should report mfa_required");

    Mock::given(method("POST"))
        .and(path("/api/v1/auth/mfa/verify"))
        .respond_with(ResponseTemplate::new(200).set_body_string("not json at all {{{"))
        .mount(&mock_server)
        .await;

    let err = client
        .verify_mfa("123456")
        .await
        .expect_err("a malformed 200 verify_mfa body must surface as an error, not panic");
    assert!(matches!(err, AxiamError::Network { .. }));
}

#[tokio::test]
async fn refresh_200_with_malformed_body_is_a_network_error() {
    let mock_server = MockServer::start().await;
    mount_jwks(&mock_server).await;

    let tenant_id = Uuid::new_v4();
    let org_id = Uuid::new_v4();
    let access = issue_test_access_token(tenant_id, org_id);

    Mock::given(method("POST"))
        .and(path("/api/v1/auth/login"))
        .respond_with(login_ok_response(&access))
        .mount(&mock_server)
        .await;

    let client = AxiamClient::builder()
        .base_url(mock_server.uri())
        .expect("valid base_url")
        .tenant_slug("acme")
        .build()
        .expect("client builds");
    client
        .login("alice@example.com", "correct horse battery staple")
        .await
        .expect("seed login must succeed");

    Mock::given(method("POST"))
        .and(path("/api/v1/auth/refresh"))
        .respond_with(ResponseTemplate::new(200).set_body_string("not json at all {{{"))
        .mount(&mock_server)
        .await;

    let err = client
        .refresh()
        .await
        .expect_err("a malformed 200 refresh body must surface as an error, not panic");
    assert!(matches!(err, AxiamError::Network { .. }));
}

// ---------------------------------------------------------------------------
// `refresh()`'s tenant_id/org_id-unresolved guards
// ---------------------------------------------------------------------------

/// A claims shape with fully caller-controlled `tenant_id`/`org_id`/`jti`
/// fields (unlike `issue_test_access_token`, which always emits well-formed
/// UUIDs for all three) — lets these tests craft the exact malformed/missing
/// claim shapes `refresh()`/`logout()` must guard against.
#[derive(Debug, Serialize)]
struct CustomClaims {
    sub: String,
    tenant_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    org_id: Option<String>,
    iss: String,
    iat: i64,
    exp: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    jti: Option<String>,
}

fn issue_custom_token(tenant_id: &str, org_id: Option<&str>, jti: Option<&str>) -> String {
    let mut header = Header::new(Algorithm::EdDSA);
    header.kid = Some(TEST_KID.to_string());
    let claims = CustomClaims {
        sub: Uuid::new_v4().to_string(),
        tenant_id: tenant_id.to_string(),
        org_id: org_id.map(str::to_string),
        iss: "axiam-test".to_string(),
        iat: 0,
        exp: 9_999_999_999,
        jti: jti.map(str::to_string),
    };
    let mut der = ED25519_PKCS8_DER_PREFIX.to_vec();
    der.extend_from_slice(&TEST_ED25519_SEED);
    let key = EncodingKey::from_ed_der(&der);
    jsonwebtoken::encode(&header, &claims, &key).expect("encode custom-claims token")
}

#[tokio::test]
async fn refresh_fails_when_tenant_id_claim_is_not_a_uuid() {
    let mock_server = MockServer::start().await;
    mount_jwks(&mock_server).await;

    // `tenant_id` is not a valid UUID: `absorb_session_cookies` leaves
    // `TokenManager`'s `tenant_id` at `None` (login itself still succeeds —
    // `Claims::tenant_id` is a plain `String`), and since the client was
    // built with a *slug* (never resolvable on its own), `resolved_tenant_id()`
    // has no fallback either, so `refresh()` must fail with "tenant_id could
    // not be resolved" rather than panic on a bad claim.
    let access = issue_custom_token("not-a-uuid", Some(&Uuid::new_v4().to_string()), None);

    Mock::given(method("POST"))
        .and(path("/api/v1/auth/login"))
        .respond_with(login_ok_response(&access))
        .mount(&mock_server)
        .await;

    let client = AxiamClient::builder()
        .base_url(mock_server.uri())
        .expect("valid base_url")
        .tenant_slug("acme")
        .build()
        .expect("client builds");
    client
        .login("alice@example.com", "correct horse battery staple")
        .await
        .expect("login succeeds even with a non-UUID tenant_id claim");
    assert_eq!(client.resolved_tenant_id().await, None);

    let err = client
        .refresh()
        .await
        .expect_err("refresh() must fail when tenant_id cannot be resolved");
    match err {
        AxiamError::Auth { message } => assert!(message.contains("tenant_id"), "{message}"),
        other => panic!("expected Auth error, got {other:?}"),
    }
}

#[tokio::test]
async fn refresh_fails_when_org_id_claim_is_absent() {
    let mock_server = MockServer::start().await;
    mount_jwks(&mock_server).await;

    let tenant_id = Uuid::new_v4();
    // No `org_id` claim at all: `resolved_org_id()` stays `None` even though
    // `tenant_id` resolves fine.
    let access = issue_custom_token(&tenant_id.to_string(), None, None);

    Mock::given(method("POST"))
        .and(path("/api/v1/auth/login"))
        .respond_with(login_ok_response(&access))
        .mount(&mock_server)
        .await;

    let client = AxiamClient::builder()
        .base_url(mock_server.uri())
        .expect("valid base_url")
        .tenant_slug("acme")
        .build()
        .expect("client builds");
    client
        .login("alice@example.com", "correct horse battery staple")
        .await
        .expect("login succeeds with no org_id claim");
    assert_eq!(client.resolved_tenant_id().await, Some(tenant_id));

    let err = client
        .refresh()
        .await
        .expect_err("refresh() must fail when org_id cannot be resolved");
    match err {
        AxiamError::Auth { message } => assert!(message.contains("org_id"), "{message}"),
        other => panic!("expected Auth error, got {other:?}"),
    }
}

#[tokio::test]
async fn refresh_success_response_without_axiam_access_cookie_is_an_auth_error() {
    let mock_server = MockServer::start().await;
    mount_jwks(&mock_server).await;

    let tenant_id = Uuid::new_v4();
    let org_id = Uuid::new_v4();
    let access = issue_test_access_token(tenant_id, org_id);

    Mock::given(method("POST"))
        .and(path("/api/v1/auth/login"))
        .respond_with(login_ok_response(&access))
        .mount(&mock_server)
        .await;

    let client = AxiamClient::builder()
        .base_url(mock_server.uri())
        .expect("valid base_url")
        .tenant_slug("acme")
        .build()
        .expect("client builds");
    client
        .login("alice@example.com", "correct horse battery staple")
        .await
        .expect("seed login must succeed");

    // A 200 refresh response that actively EXPIRES the `axiam_access` cookie
    // (`Max-Age=0`) rather than rotating it — the jar removes it entirely, so
    // `refresh()`'s post-success cookie read must reject this rather than
    // silently keep going with no access token. (A response that simply
    // omits `Set-Cookie` would leave the jar's *existing* cookie from login
    // untouched, which is not the branch this test targets.)
    Mock::given(method("POST"))
        .and(path("/api/v1/auth/refresh"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({ "expires_in": 900 }))
                .append_header("Set-Cookie", "axiam_access=; Path=/; Max-Age=0"),
        )
        .mount(&mock_server)
        .await;

    let err = client
        .refresh()
        .await
        .expect_err("a refresh 200 with no rotated axiam_access cookie must fail");
    match err {
        AxiamError::Auth { message } => assert!(message.contains("axiam_access"), "{message}"),
        other => panic!("expected Auth error, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// `logout()`'s missing-`jti` guard
// ---------------------------------------------------------------------------

#[tokio::test]
async fn logout_fails_when_access_token_has_no_jti() {
    let mock_server = MockServer::start().await;
    mount_jwks(&mock_server).await;

    // No `jti` claim at all: the server keys logout off the session id
    // embedded in the caller's own JWT, so `logout()` must refuse to proceed
    // rather than send a nonsensical request.
    let access = issue_custom_token(&Uuid::new_v4().to_string(), Some(&Uuid::new_v4().to_string()), None);

    Mock::given(method("POST"))
        .and(path("/api/v1/auth/login"))
        .respond_with(login_ok_response(&access))
        .mount(&mock_server)
        .await;

    let client = AxiamClient::builder()
        .base_url(mock_server.uri())
        .expect("valid base_url")
        .tenant_slug("acme")
        .build()
        .expect("client builds");
    client
        .login("alice@example.com", "correct horse battery staple")
        .await
        .expect("login succeeds with no jti claim");

    let err = client
        .logout()
        .await
        .expect_err("logout() must fail when the access token carries no jti");
    match err {
        AxiamError::Auth { message } => assert!(message.contains("jti"), "{message}"),
        other => panic!("expected Auth error, got {other:?}"),
    }
}

#[tokio::test]
async fn login_200_without_session_cookies_is_an_auth_error() {
    let mock_server = MockServer::start().await;
    mount_jwks(&mock_server).await;

    // A 200 login body but NO Set-Cookie headers — `absorb_session_cookies`
    // must reject it rather than silently proceed without a token.
    Mock::given(method("POST"))
        .and(path("/api/v1/auth/login"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "user": { "id": Uuid::new_v4(), "username": "alice", "email": "a@example.com" },
            "session_id": Uuid::new_v4(),
            "expires_in": 900,
        })))
        .mount(&mock_server)
        .await;

    let client = AxiamClient::builder()
        .base_url(mock_server.uri())
        .expect("valid base_url")
        .tenant_slug("acme")
        .build()
        .expect("client builds");

    let err = client
        .login("alice@example.com", "correct horse battery staple")
        .await
        .expect_err("a 200 login with no session cookie must fail");
    assert!(matches!(err, AxiamError::Auth { .. }));
}
