//! CONTRACT.md §10 oracle: the Actix `FromRequest` extractor `AxiamUser`
//! reads the session from the `axiam_access` cookie OR the `Authorization:
//! Bearer` header, verifies it locally against the cached JWKS (no
//! AXIAM-server round-trip for the token itself — only the initial JWKS
//! fetch touches the network), injects `{ user_id, tenant_id, roles }`, and
//! maps verification failure to HTTP 401/403 with a standardized JSON
//! error body.

#![cfg(feature = "actix")]

use actix_web::{FromRequest, test::TestRequest, web};
use axiam_sdk::AxiamError;
use axiam_sdk::middleware::AxiamUser;
use axiam_sdk::middleware::actix::AxiamExtractorError;
use axiam_sdk::token::JwksVerifier;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde::Serialize;
use serde_json::json;
use uuid::Uuid;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// A fixed test Ed25519 private seed (test-only, deterministic), reused
/// verbatim from `tests/login_mfa_flow_test.rs` so both suites share one
/// known-good keypair. Stored as a raw 32-byte seed — NOT a PEM/DER key
/// block — so no private-key literal lives in source; the PKCS8 v1 DER is
/// rebuilt at runtime and fed to `EncodingKey::from_ed_der`.
const TEST_ED25519_SEED: [u8; 32] = [
    0x74, 0x8c, 0x0b, 0xd3, 0xad, 0xc0, 0x28, 0x0a, 0xfd, 0xd7, 0xc0, 0x7c, 0x35, 0x07, 0x03, 0x64,
    0x6d, 0x14, 0x2d, 0x1d, 0xbd, 0x73, 0x4c, 0xd4, 0xf8, 0x17, 0x17, 0x0b, 0x91, 0x7b, 0x49, 0xfc,
];
/// Standard PKCS8 v1 DER prefix for an Ed25519 private key (alg id + seed OCTET STRING header).
const ED25519_PKCS8_DER_PREFIX: [u8; 16] = [
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];
/// The raw public key `x` coordinate (base64url, no padding) matching the seed above.
const TEST_ED25519_PUBLIC_X: &str = "_r-I_0nRSSV8kvwA93gwhX-hFRiWkaNk5HEud-DjnMk";
const TEST_KID: &str = "test-kid-1";
/// CONTRACT.md §10.1 rule 4: `JwksVerifier::verify` asserts `tenant_id`
/// against the verifier's configured tenant, so every fixture token in this
/// file is minted for one fixed tenant and `build_verifier` expects it.
const TEST_TENANT: &str = "3f6b1c8e-0000-4000-8000-0000000000d4";

fn test_tenant() -> Uuid {
    TEST_TENANT.parse().expect("TEST_TENANT is a UUID")
}

#[derive(Debug, Serialize)]
struct TestClaims {
    sub: String,
    tenant_id: String,
    org_id: String,
    iss: String,
    iat: i64,
    exp: i64,
    jti: String,
    scope: Option<String>,
}

fn issue_test_access_token(
    tenant_id: Uuid,
    org_id: Uuid,
    user_id: Uuid,
    jti: Uuid,
    exp: i64,
    scope: Option<&str>,
) -> String {
    let mut header = Header::new(Algorithm::EdDSA);
    header.kid = Some(TEST_KID.to_string());
    let claims = TestClaims {
        sub: user_id.to_string(),
        tenant_id: tenant_id.to_string(),
        org_id: org_id.to_string(),
        iss: "axiam-test".to_string(),
        iat: 0,
        exp,
        jti: jti.to_string(),
        scope: scope.map(str::to_owned),
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

/// Starts a mock server serving only `GET /oauth2/jwks`. No other route is
/// registered, so any test that reaches a *different* path would fail loud
/// — this doubles as the "no outbound AXIAM-server request for the token
/// itself" proof: the extractor only ever calls this one JWKS endpoint,
/// never a token-introspection/verification endpoint.
async fn mount_jwks_server() -> MockServer {
    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/oauth2/jwks"))
        .respond_with(ResponseTemplate::new(200).set_body_json(jwks_body()))
        .mount(&mock_server)
        .await;
    mock_server
}

fn build_verifier(base_url: &str) -> JwksVerifier {
    let http_client = reqwest::Client::new();
    let url = url::Url::parse(base_url).expect("valid base url");
    JwksVerifier::new(http_client, &url)
        .expect("verifier constructs")
        .expect_tenant_id(test_tenant())
}

#[tokio::test]
async fn cookie_path_extracts_axiam_user() {
    let mock_server = mount_jwks_server().await;
    let verifier = build_verifier(&mock_server.uri());

    let tenant_id = test_tenant();
    let org_id = Uuid::new_v4();
    let user_id = Uuid::new_v4();
    let jti = Uuid::new_v4();
    let token = issue_test_access_token(
        tenant_id,
        org_id,
        user_id,
        jti,
        9_999_999_999,
        Some("users:read users:write"),
    );

    let req = TestRequest::default()
        .app_data(web::Data::new(verifier))
        .cookie(actix_web::cookie::Cookie::new("axiam_access", token))
        .to_http_request();

    let mut payload = actix_web::dev::Payload::None;
    let user = AxiamUser::from_request(&req, &mut payload)
        .await
        .expect("cookie-path extraction should succeed");

    assert_eq!(user.user_id, user_id);
    assert_eq!(user.tenant_id, tenant_id);
    assert_eq!(
        user.roles,
        vec!["users:read".to_string(), "users:write".to_string()]
    );
}

#[tokio::test]
async fn bearer_header_path_extracts_axiam_user_when_no_cookie() {
    let mock_server = mount_jwks_server().await;
    let verifier = build_verifier(&mock_server.uri());

    let tenant_id = test_tenant();
    let org_id = Uuid::new_v4();
    let user_id = Uuid::new_v4();
    let jti = Uuid::new_v4();
    let token = issue_test_access_token(tenant_id, org_id, user_id, jti, 9_999_999_999, None);

    let req = TestRequest::default()
        .app_data(web::Data::new(verifier))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_http_request();

    let mut payload = actix_web::dev::Payload::None;
    let user = AxiamUser::from_request(&req, &mut payload)
        .await
        .expect("bearer-header-path extraction should succeed");

    assert_eq!(user.user_id, user_id);
    assert_eq!(user.tenant_id, tenant_id);
    assert!(
        user.roles.is_empty(),
        "no scope claim must yield an empty roles vec"
    );
}

#[tokio::test]
async fn missing_credentials_yields_401() {
    let mock_server = mount_jwks_server().await;
    let verifier = build_verifier(&mock_server.uri());

    let req = TestRequest::default()
        .app_data(web::Data::new(verifier))
        .to_http_request();

    let mut payload = actix_web::dev::Payload::None;
    let err = AxiamUser::from_request(&req, &mut payload)
        .await
        .expect_err("missing credentials must fail");

    use actix_web::ResponseError;
    assert_eq!(err.status_code(), actix_web::http::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn invalid_signature_token_yields_401_with_json_body_not_panic() {
    let mock_server = mount_jwks_server().await;
    let verifier = build_verifier(&mock_server.uri());

    // Signed with a *different* Ed25519 key than the one served by the JWKS
    // mock, so signature verification must fail (not panic).
    let mut header = Header::new(Algorithm::EdDSA);
    header.kid = Some(TEST_KID.to_string());
    let claims = TestClaims {
        sub: Uuid::new_v4().to_string(),
        tenant_id: Uuid::new_v4().to_string(),
        org_id: Uuid::new_v4().to_string(),
        iss: "axiam-test".to_string(),
        iat: 0,
        exp: 9_999_999_999,
        jti: Uuid::new_v4().to_string(),
        scope: None,
    };
    let mut wrong_seed = TEST_ED25519_SEED;
    wrong_seed[0] ^= 0xFF; // flip bits to get a different (but still valid-length) key
    let mut der = ED25519_PKCS8_DER_PREFIX.to_vec();
    der.extend_from_slice(&wrong_seed);
    let wrong_key = EncodingKey::from_ed_der(&der);
    let bad_token = jsonwebtoken::encode(&header, &claims, &wrong_key)
        .expect("encode token with mismatched key");

    let req = TestRequest::default()
        .app_data(web::Data::new(verifier))
        .insert_header(("Authorization", format!("Bearer {bad_token}")))
        .to_http_request();

    let mut payload = actix_web::dev::Payload::None;
    let err = AxiamUser::from_request(&req, &mut payload)
        .await
        .expect_err("signature-invalid token must fail, not panic");

    use actix_web::ResponseError;
    assert_eq!(err.status_code(), actix_web::http::StatusCode::UNAUTHORIZED);

    // The standardized JSON error body must be well-formed and must never
    // contain the raw token value (§7/§10 — no token echoed in error body).
    let resp = err.error_response();
    let body_bytes = actix_web::body::to_bytes(resp.into_body())
        .await
        .expect("error body should be readable");
    let body: serde_json::Value =
        serde_json::from_slice(&body_bytes).expect("error body must be valid JSON, not a panic");
    assert!(body.get("error").is_some());
    assert!(body.get("message").is_some());
    let body_str = body.to_string();
    assert!(
        !body_str.contains(&bad_token),
        "error body must never echo the raw token"
    );
}

#[tokio::test]
async fn expired_token_yields_401() {
    let mock_server = mount_jwks_server().await;
    let verifier = build_verifier(&mock_server.uri());

    let token = issue_test_access_token(
        test_tenant(),
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
        1, // expired long ago
        None,
    );

    let req = TestRequest::default()
        .app_data(web::Data::new(verifier))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_http_request();

    let mut payload = actix_web::dev::Payload::None;
    let err = AxiamUser::from_request(&req, &mut payload)
        .await
        .expect_err("expired token must fail");

    use actix_web::ResponseError;
    assert_eq!(err.status_code(), actix_web::http::StatusCode::UNAUTHORIZED);
}

/// §3 CSRF double-submit: a cookie-sourced credential on a state-changing
/// request (POST) with no `X-CSRF-Token` header must be rejected with 403
/// before any token verification is attempted.
#[tokio::test]
async fn cookie_auth_state_changing_without_csrf_header_yields_403() {
    let mock_server = mount_jwks_server().await;
    let verifier = build_verifier(&mock_server.uri());

    let token = issue_test_access_token(
        test_tenant(),
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
        9_999_999_999,
        None,
    );

    let req = TestRequest::post()
        .app_data(web::Data::new(verifier))
        .cookie(actix_web::cookie::Cookie::new("axiam_access", token))
        .cookie(actix_web::cookie::Cookie::new(
            "axiam_csrf",
            "matching-csrf-token",
        ))
        // Deliberately no X-CSRF-Token header.
        .to_http_request();

    let mut payload = actix_web::dev::Payload::None;
    let err = AxiamUser::from_request(&req, &mut payload)
        .await
        .expect_err("cookie-sourced POST without X-CSRF-Token must fail");

    use actix_web::ResponseError;
    assert_eq!(err.status_code(), actix_web::http::StatusCode::FORBIDDEN);

    let resp = err.error_response();
    let body_bytes = actix_web::body::to_bytes(resp.into_body())
        .await
        .expect("error body should be readable");
    let body: serde_json::Value =
        serde_json::from_slice(&body_bytes).expect("error body must be valid JSON");
    assert_eq!(
        body.get("error").and_then(|v| v.as_str()),
        Some("authorization_denied")
    );
}

/// §3 CSRF double-submit: a cookie-sourced credential on a state-changing
/// request WITH a matching `X-CSRF-Token` header/`axiam_csrf` cookie pair
/// must pass the CSRF gate and proceed to (successful) verification.
#[tokio::test]
async fn cookie_auth_state_changing_with_matching_csrf_token_succeeds() {
    let mock_server = mount_jwks_server().await;
    let verifier = build_verifier(&mock_server.uri());

    let tenant_id = test_tenant();
    let user_id = Uuid::new_v4();
    let token = issue_test_access_token(
        tenant_id,
        Uuid::new_v4(),
        user_id,
        Uuid::new_v4(),
        9_999_999_999,
        None,
    );

    let req = TestRequest::post()
        .app_data(web::Data::new(verifier))
        .cookie(actix_web::cookie::Cookie::new("axiam_access", token))
        .cookie(actix_web::cookie::Cookie::new(
            "axiam_csrf",
            "matching-csrf-token",
        ))
        .insert_header(("X-CSRF-Token", "matching-csrf-token"))
        .to_http_request();

    let mut payload = actix_web::dev::Payload::None;
    let user = AxiamUser::from_request(&req, &mut payload)
        .await
        .expect("cookie-sourced POST with matching CSRF token must succeed");

    assert_eq!(user.user_id, user_id);
    assert_eq!(user.tenant_id, tenant_id);
}

/// A Bearer-header-sourced request needs no CSRF token at all, even for a
/// state-changing method — a cross-site attacker cannot set custom headers,
/// so the header path is CSRF-immune by construction.
#[tokio::test]
async fn bearer_auth_state_changing_without_csrf_succeeds() {
    let mock_server = mount_jwks_server().await;
    let verifier = build_verifier(&mock_server.uri());

    let tenant_id = test_tenant();
    let user_id = Uuid::new_v4();
    let token = issue_test_access_token(
        tenant_id,
        Uuid::new_v4(),
        user_id,
        Uuid::new_v4(),
        9_999_999_999,
        None,
    );

    let req = TestRequest::post()
        .app_data(web::Data::new(verifier))
        .insert_header(("Authorization", format!("Bearer {token}")))
        // No CSRF cookie/header at all.
        .to_http_request();

    let mut payload = actix_web::dev::Payload::None;
    let user = AxiamUser::from_request(&req, &mut payload)
        .await
        .expect("Bearer-header POST needs no CSRF token");

    assert_eq!(user.user_id, user_id);
    assert_eq!(user.tenant_id, tenant_id);
}

/// A cookie-sourced credential on a safe method (GET) must NOT be subject
/// to the CSRF gate — safe methods must not have side effects, so the §3
/// double-submit check only applies to state-changing methods.
#[tokio::test]
async fn cookie_auth_safe_method_without_csrf_succeeds() {
    let mock_server = mount_jwks_server().await;
    let verifier = build_verifier(&mock_server.uri());

    let tenant_id = test_tenant();
    let user_id = Uuid::new_v4();
    let token = issue_test_access_token(
        tenant_id,
        Uuid::new_v4(),
        user_id,
        Uuid::new_v4(),
        9_999_999_999,
        None,
    );

    let req = TestRequest::get()
        .app_data(web::Data::new(verifier))
        .cookie(actix_web::cookie::Cookie::new("axiam_access", token))
        // No X-CSRF-Token header, no axiam_csrf cookie.
        .to_http_request();

    let mut payload = actix_web::dev::Payload::None;
    let user = AxiamUser::from_request(&req, &mut payload)
        .await
        .expect("cookie-sourced GET needs no CSRF token");

    assert_eq!(user.user_id, user_id);
    assert_eq!(user.tenant_id, tenant_id);
}

#[tokio::test]
async fn local_verification_makes_no_outbound_axiam_server_request() {
    // Only the JWKS endpoint is mounted (no /api/v1/auth/* or /oauth2/introspect
    // route exists on this mock server). A successful extraction therefore
    // proves the extractor performed no server round-trip beyond the one-time
    // JWKS fetch — local verification only (§10.2).
    let mock_server = mount_jwks_server().await;
    let verifier = build_verifier(&mock_server.uri());

    let tenant_id = test_tenant();
    let user_id = Uuid::new_v4();
    let token = issue_test_access_token(
        tenant_id,
        Uuid::new_v4(),
        user_id,
        Uuid::new_v4(),
        9_999_999_999,
        None,
    );

    let req = TestRequest::default()
        .app_data(web::Data::new(verifier))
        .cookie(actix_web::cookie::Cookie::new("axiam_access", token))
        .to_http_request();

    let mut payload = actix_web::dev::Payload::None;
    let user = AxiamUser::from_request(&req, &mut payload)
        .await
        .expect("local-only verification should succeed with no auth-check route mounted");

    assert_eq!(user.user_id, user_id);
    assert_eq!(user.tenant_id, tenant_id);
}

/// Missing `app_data::<web::Data<JwksVerifier>>()` — the extractor is
/// misconfigured (the caller forgot to register the verifier), not the
/// caller's request that's malformed. Must fail closed with 401, never
/// panic on the `.ok_or_else(...)?`.
#[tokio::test]
async fn missing_jwks_verifier_app_data_yields_401() {
    let tenant_id = test_tenant();
    let token = issue_test_access_token(
        tenant_id,
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
        9_999_999_999,
        None,
    );

    // No `.app_data(web::Data::new(verifier))` at all.
    let req = TestRequest::default()
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_http_request();

    let mut payload = actix_web::dev::Payload::None;
    let err = AxiamUser::from_request(&req, &mut payload)
        .await
        .expect_err("a misconfigured extractor (no JwksVerifier registered) must fail");

    use actix_web::ResponseError;
    assert_eq!(err.status_code(), actix_web::http::StatusCode::UNAUTHORIZED);
}

/// An `Authorization` header present but using a scheme other than
/// `Bearer` must be rejected distinctly from "missing credentials".
#[tokio::test]
async fn non_bearer_authorization_scheme_yields_401() {
    let mock_server = mount_jwks_server().await;
    let verifier = build_verifier(&mock_server.uri());

    let req = TestRequest::default()
        .app_data(web::Data::new(verifier))
        .insert_header(("Authorization", "Basic dXNlcjpwYXNz"))
        .to_http_request();

    let mut payload = actix_web::dev::Payload::None;
    let err = AxiamUser::from_request(&req, &mut payload)
        .await
        .expect_err("a non-Bearer Authorization scheme must be rejected");

    use actix_web::ResponseError;
    assert_eq!(err.status_code(), actix_web::http::StatusCode::UNAUTHORIZED);
}

/// `Authorization: Bearer` with no credentials after the scheme is the same
/// invalid-scheme rejection as a wrong scheme entirely.
#[tokio::test]
async fn bearer_scheme_with_empty_credentials_yields_401() {
    let mock_server = mount_jwks_server().await;
    let verifier = build_verifier(&mock_server.uri());

    let req = TestRequest::default()
        .app_data(web::Data::new(verifier))
        .insert_header(("Authorization", "Bearer "))
        .to_http_request();

    let mut payload = actix_web::dev::Payload::None;
    let err = AxiamUser::from_request(&req, &mut payload)
        .await
        .expect_err("Bearer with no credentials must be rejected");

    use actix_web::ResponseError;
    assert_eq!(err.status_code(), actix_web::http::StatusCode::UNAUTHORIZED);
}

/// A verified token whose `sub` claim is not a valid UUID must be rejected
/// via `invalid_claim`, not panic on `Uuid::parse_str(...).unwrap()`.
#[tokio::test]
async fn non_uuid_sub_claim_yields_401() {
    let mock_server = mount_jwks_server().await;
    let verifier = build_verifier(&mock_server.uri());

    let mut header = Header::new(Algorithm::EdDSA);
    header.kid = Some(TEST_KID.to_string());
    #[derive(Debug, Serialize)]
    struct BadSubClaims {
        sub: String,
        tenant_id: String,
        org_id: String,
        iss: String,
        iat: i64,
        exp: i64,
        jti: String,
        scope: Option<String>,
    }
    let claims = BadSubClaims {
        sub: "not-a-uuid".to_string(),
        tenant_id: Uuid::new_v4().to_string(),
        org_id: Uuid::new_v4().to_string(),
        iss: "axiam-test".to_string(),
        iat: 0,
        exp: 9_999_999_999,
        jti: Uuid::new_v4().to_string(),
        scope: None,
    };
    let mut der = ED25519_PKCS8_DER_PREFIX.to_vec();
    der.extend_from_slice(&TEST_ED25519_SEED);
    let key = EncodingKey::from_ed_der(&der);
    let token = jsonwebtoken::encode(&header, &claims, &key).expect("encode token");

    let req = TestRequest::default()
        .app_data(web::Data::new(verifier))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_http_request();

    let mut payload = actix_web::dev::Payload::None;
    let err = AxiamUser::from_request(&req, &mut payload)
        .await
        .expect_err("a non-UUID sub claim must be rejected, not panic");

    use actix_web::ResponseError;
    assert_eq!(err.status_code(), actix_web::http::StatusCode::UNAUTHORIZED);
}

/// §3 CSRF double-submit: a cookie-sourced credential on a state-changing
/// request with an `X-CSRF-Token` header present but NO `axiam_csrf` cookie
/// at all must be rejected with 403 — exercises `csrf_valid`'s
/// cookie-missing fallback (distinct from the header-missing fallback the
/// other §3 tests here reach).
#[tokio::test]
async fn cookie_auth_state_changing_with_csrf_header_but_no_csrf_cookie_yields_403() {
    let mock_server = mount_jwks_server().await;
    let verifier = build_verifier(&mock_server.uri());

    let token = issue_test_access_token(
        test_tenant(),
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
        9_999_999_999,
        None,
    );

    let req = TestRequest::post()
        .app_data(web::Data::new(verifier))
        .cookie(actix_web::cookie::Cookie::new("axiam_access", token))
        .insert_header(("X-CSRF-Token", "some-token"))
        // Deliberately no `axiam_csrf` cookie at all.
        .to_http_request();

    let mut payload = actix_web::dev::Payload::None;
    let err = AxiamUser::from_request(&req, &mut payload)
        .await
        .expect_err("a X-CSRF-Token header with no axiam_csrf cookie must be rejected");

    use actix_web::ResponseError;
    assert_eq!(err.status_code(), actix_web::http::StatusCode::FORBIDDEN);
}

/// `AxiamExtractorError`'s `Display` impl delegates to the wrapped
/// `AxiamError`'s own redacting `Display` — never independently exercised by
/// any of the request-driven tests above (they only ever inspect the
/// `ResponseError` JSON body, never `format!("{}", ...)` the error itself).
#[test]
fn axiam_extractor_error_display_delegates_to_inner_error() {
    let err = AxiamExtractorError(AxiamError::auth("custom auth failure"));
    assert!(format!("{err}").contains("custom auth failure"));
}

/// `AxiamExtractorError::status_code`/`error_response` map every
/// `AxiamError` variant, including `Network` — never produced by the
/// extractor itself (its own error paths only ever build `Auth`/`Authz`), so
/// this constructs one directly via the `pub` field to exercise that arm.
#[tokio::test]
async fn axiam_extractor_error_network_variant_maps_to_401() {
    use actix_web::ResponseError;

    let err = AxiamExtractorError(AxiamError::network("transport failed"));
    assert_eq!(err.status_code(), actix_web::http::StatusCode::UNAUTHORIZED);

    let resp = err.error_response();
    let body_bytes = actix_web::body::to_bytes(resp.into_body())
        .await
        .expect("error body should be readable");
    let body: serde_json::Value =
        serde_json::from_slice(&body_bytes).expect("error body must be valid JSON");
    assert_eq!(body["error"], "authentication_failed");
}

/// §3 CSRF double-submit: a cookie-sourced credential on a state-changing
/// request with a `X-CSRF-Token` header present but NOT equal to the
/// `axiam_csrf` cookie must be rejected with 403.
#[tokio::test]
async fn cookie_auth_state_changing_with_mismatched_csrf_token_yields_403() {
    let mock_server = mount_jwks_server().await;
    let verifier = build_verifier(&mock_server.uri());

    let token = issue_test_access_token(
        test_tenant(),
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
        9_999_999_999,
        None,
    );

    let req = TestRequest::post()
        .app_data(web::Data::new(verifier))
        .cookie(actix_web::cookie::Cookie::new("axiam_access", token))
        .cookie(actix_web::cookie::Cookie::new(
            "axiam_csrf",
            "the-real-csrf-token",
        ))
        .insert_header(("X-CSRF-Token", "a-different-csrf-token"))
        .to_http_request();

    let mut payload = actix_web::dev::Payload::None;
    let err = AxiamUser::from_request(&req, &mut payload)
        .await
        .expect_err("a mismatched X-CSRF-Token header must be rejected");

    use actix_web::ResponseError;
    assert_eq!(err.status_code(), actix_web::http::StatusCode::FORBIDDEN);
}

// ---------------------------------------------------------------------------
// CONTRACT.md §10.1 rule 8 — "subject of the decision" (SEC-085, §15.3.1).
//
// Rules 1-7 ask whether the token is good. Rule 8 asks whether it is the token
// the decision is even ABOUT. SEC-085 satisfied all seven and was still an
// authentication bypass: the PHP guard routed a failed verification into a
// second, successful one against the *application's own* session, so the caller
// was admitted as the app's service account — in an IAM integration usually far
// more privileged than the user whose request it replaced.
//
// This extractor is structurally safe from that shape: it resolves exactly one
// thing from `app_data` — a `JwksVerifier` — and decides on the token it pulled
// off the request. There is no session in scope to substitute.
//
// The Actix-specific risk these tests pin is real, though: `app_data` is a
// type-keyed bag, and a production app will very plausibly register its
// `AxiamClient` there too, for its own outbound calls. That places a second
// credential *within reach* of the extractor even though it is structurally
// safe today. These tests assert the extractor ignores anything but the
// verifier, so the property cannot be quietly undone later.
// ---------------------------------------------------------------------------

/// A stand-in for the application's own authenticated client, registered in
/// `app_data` exactly as a real service would. Its token is deliberately one
/// the verifier WOULD accept: if the extractor ever reached for it, the request
/// would succeed and the assertions below would catch it.
struct AppOwnSession {
    #[allow(dead_code)]
    access_token: String,
    #[allow(dead_code)]
    principal: Uuid,
}

#[tokio::test]
async fn rule8_rejects_a_failed_caller_token_with_an_app_session_in_app_data() {
    let mock_server = mount_jwks_server().await;
    let verifier = build_verifier(&mock_server.uri());

    let tenant_id = test_tenant();
    let app_principal = Uuid::new_v4();

    // The application's own credential — genuinely valid, so a substitution
    // would actually succeed rather than failing for an incidental reason.
    let app_token = issue_test_access_token(
        tenant_id,
        Uuid::new_v4(),
        app_principal,
        Uuid::new_v4(),
        9_999_999_999,
        Some("admin:all"),
    );

    // The caller's credential: correctly signed, for the right tenant, and
    // expired. It fails rule 2 and nothing else, so the only way to admit it
    // is to decide on some other credential.
    let expired = issue_test_access_token(
        tenant_id,
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
        1, // 1970 — far outside any leeway
        Some("documents:read"),
    );

    let req = TestRequest::default()
        .app_data(web::Data::new(verifier))
        // The second credential, in reach but not the caller's.
        .app_data(web::Data::new(AppOwnSession {
            access_token: app_token.clone(),
            principal: app_principal,
        }))
        .insert_header(("Authorization", format!("Bearer {expired}")))
        .to_http_request();

    let mut payload = actix_web::dev::Payload::None;
    let result = AxiamUser::from_request(&req, &mut payload).await;

    match result {
        Ok(user) => panic!(
            "SECURITY: a caller whose token failed verification was admitted as {} \
             — rule 8 violated",
            user.user_id
        ),
        Err(err) => {
            // Must be an authentication failure, and must NOT be the app's identity.
            let rendered = format!("{err}");
            assert!(
                !rendered.contains(&app_principal.to_string()),
                "the rejection must not surface the application's own principal"
            );
        }
    }
}

#[tokio::test]
async fn rule8_the_extractor_consults_only_the_credential_on_the_request() {
    // The positive half: with a valid caller token AND an app session present,
    // the identity injected is the CALLER's, never the app's. A guard that
    // preferred the ambient credential would pass the negative test above while
    // still being wrong.
    let mock_server = mount_jwks_server().await;
    let verifier = build_verifier(&mock_server.uri());

    let tenant_id = test_tenant();
    let caller_id = Uuid::new_v4();
    let app_principal = Uuid::new_v4();

    let caller_token = issue_test_access_token(
        tenant_id,
        Uuid::new_v4(),
        caller_id,
        Uuid::new_v4(),
        9_999_999_999,
        Some("documents:read"),
    );
    let app_token = issue_test_access_token(
        tenant_id,
        Uuid::new_v4(),
        app_principal,
        Uuid::new_v4(),
        9_999_999_999,
        Some("admin:all"),
    );

    let req = TestRequest::default()
        .app_data(web::Data::new(verifier))
        .app_data(web::Data::new(AppOwnSession {
            access_token: app_token,
            principal: app_principal,
        }))
        .insert_header(("Authorization", format!("Bearer {caller_token}")))
        .to_http_request();

    let mut payload = actix_web::dev::Payload::None;
    let user = AxiamUser::from_request(&req, &mut payload)
        .await
        .expect("a valid caller token must be admitted");

    assert_eq!(
        user.user_id, caller_id,
        "the injected identity must be the caller's"
    );
    assert_ne!(
        user.user_id, app_principal,
        "SECURITY: the extractor injected the application's own principal"
    );
    assert_eq!(user.roles, vec!["documents:read".to_string()]);
}

#[tokio::test]
async fn rule8_a_missing_verifier_fails_closed_rather_than_falling_back() {
    // If the one dependency the extractor is allowed to resolve is absent, it
    // must fail — not look around `app_data` for something else that could
    // authenticate the request.
    let mock_server = mount_jwks_server().await;
    let tenant_id = test_tenant();
    let app_principal = Uuid::new_v4();
    let app_token = issue_test_access_token(
        tenant_id,
        Uuid::new_v4(),
        app_principal,
        Uuid::new_v4(),
        9_999_999_999,
        Some("admin:all"),
    );
    // Keep the server alive so a fallback could genuinely have verified.
    let _keepalive = &mock_server;

    let req = TestRequest::default()
        // No JwksVerifier registered — only the app's own session.
        .app_data(web::Data::new(AppOwnSession {
            access_token: app_token.clone(),
            principal: app_principal,
        }))
        .insert_header(("Authorization", format!("Bearer {app_token}")))
        .to_http_request();

    let mut payload = actix_web::dev::Payload::None;
    let result = AxiamUser::from_request(&req, &mut payload).await;
    assert!(
        result.is_err(),
        "SECURITY: the extractor authenticated a request with no verifier configured"
    );
}
