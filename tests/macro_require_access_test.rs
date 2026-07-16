//! CONTRACT.md §11 oracle for the Rust SDK: the `#[require_access]` /
//! `#[require_auth]` / `#[require_role]` Actix-Web attribute macros.
//!
//! Drives real Actix handlers annotated with the macros through a full test
//! app whose `AxiamClient` and `JwksVerifier` point at a wiremock server, and
//! asserts the complete §11 matrix: allow, deny→403, unauthenticated→401,
//! unresolvable resource→400, transport failure→503 (fail closed), plus that
//! `subject_id` and `scope` are sent on the wire and no token is echoed.

#![cfg(feature = "macros")]

use actix_web::{test, web, App, HttpResponse};
use axiam_sdk::client::AxiamClient;
use axiam_sdk::token::JwksVerifier;
use axiam_sdk::{require_access, require_auth, require_role};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde::Serialize;
use serde_json::json;
use uuid::Uuid;
use wiremock::matchers::{body_partial_json, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

// ---- Test JWT plumbing (shared shape with tests/actix_extractor_test.rs) ----

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
    scope: Option<String>,
}

fn issue_token(user_id: Uuid, scope: Option<&str>) -> String {
    let mut header = Header::new(Algorithm::EdDSA);
    header.kid = Some(TEST_KID.to_string());
    let claims = TestClaims {
        sub: user_id.to_string(),
        tenant_id: Uuid::new_v4().to_string(),
        org_id: Uuid::new_v4().to_string(),
        iss: "axiam-test".to_string(),
        iat: 0,
        exp: 9_999_999_999,
        jti: Uuid::new_v4().to_string(),
        scope: scope.map(str::to_owned),
    };
    let mut der = ED25519_PKCS8_DER_PREFIX.to_vec();
    der.extend_from_slice(&TEST_ED25519_SEED);
    let key = EncodingKey::from_ed_der(&der);
    jsonwebtoken::encode(&header, &claims, &key).expect("encode test access token")
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

async fn mount_jwks(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path("/oauth2/jwks"))
        .respond_with(ResponseTemplate::new(200).set_body_json(jwks_body()))
        .mount(server)
        .await;
}

fn verifier_for(server: &MockServer) -> JwksVerifier {
    let url = url::Url::parse(&server.uri()).expect("valid base url");
    JwksVerifier::new(reqwest::Client::new(), &url).expect("verifier constructs")
}

fn client_for(server: &MockServer) -> AxiamClient {
    AxiamClient::builder()
        .base_url(server.uri())
        .expect("loopback base_url accepted")
        .tenant_slug("acme")
        .build()
        .expect("client builds")
}

// ---- Handlers under test ----

#[require_access(action = "read", resource_param = "id")]
async fn read_doc() -> HttpResponse {
    HttpResponse::Ok().body("read ok")
}

#[require_access(action = "read", resource_param = "id", scope = "confidential")]
async fn read_doc_scoped() -> HttpResponse {
    HttpResponse::Ok().body("read scoped ok")
}

#[require_auth]
async fn auth_only() -> HttpResponse {
    HttpResponse::Ok().body("auth ok")
}

#[require_role("admin")]
async fn admin_only() -> HttpResponse {
    HttpResponse::Ok().body("admin ok")
}

// ---- Tests: the §11 matrix ----

/// Allow path — and proof that `subject_id`, `action` and `resource_id` are
/// sent on the wire: the authz mock only matches (returns `allowed: true`)
/// when the request body carries exactly those values, so a 200 implies they
/// were present.
#[tokio::test]
async fn allow_sends_subject_id_and_returns_200() {
    let server = MockServer::start().await;
    mount_jwks(&server).await;

    let user_id = Uuid::new_v4();
    let resource_id = Uuid::new_v4();

    Mock::given(method("POST"))
        .and(path("/api/v1/authz/check"))
        .and(body_partial_json(json!({
            "subject_id": user_id,
            "action": "read",
            "resource_id": resource_id,
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "allowed": true })))
        .expect(1)
        .mount(&server)
        .await;

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(verifier_for(&server)))
            .app_data(web::Data::new(client_for(&server)))
            .route("/documents/{id}", web::get().to(read_doc)),
    )
    .await;

    let req = test::TestRequest::get()
        .uri(&format!("/documents/{resource_id}"))
        .insert_header((
            "Authorization",
            format!("Bearer {}", issue_token(user_id, None)),
        ))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);
}

/// Scope passthrough: the `scope = "confidential"` argument must reach the
/// authz endpoint verbatim.
#[tokio::test]
async fn scope_is_passed_through_on_the_wire() {
    let server = MockServer::start().await;
    mount_jwks(&server).await;

    let user_id = Uuid::new_v4();
    let resource_id = Uuid::new_v4();

    Mock::given(method("POST"))
        .and(path("/api/v1/authz/check"))
        .and(body_partial_json(json!({
            "subject_id": user_id,
            "action": "read",
            "resource_id": resource_id,
            "scope": "confidential",
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "allowed": true })))
        .expect(1)
        .mount(&server)
        .await;

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(verifier_for(&server)))
            .app_data(web::Data::new(client_for(&server)))
            .route("/documents/{id}", web::get().to(read_doc_scoped)),
    )
    .await;

    let req = test::TestRequest::get()
        .uri(&format!("/documents/{resource_id}"))
        .insert_header((
            "Authorization",
            format!("Bearer {}", issue_token(user_id, None)),
        ))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);
}

/// Deny path: `allowed: false` → 403 `authorization_denied`.
#[tokio::test]
async fn deny_returns_403() {
    let server = MockServer::start().await;
    mount_jwks(&server).await;

    Mock::given(method("POST"))
        .and(path("/api/v1/authz/check"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "allowed": false })))
        .mount(&server)
        .await;

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(verifier_for(&server)))
            .app_data(web::Data::new(client_for(&server)))
            .route("/documents/{id}", web::get().to(read_doc)),
    )
    .await;

    let token = issue_token(Uuid::new_v4(), None);
    let req = test::TestRequest::get()
        .uri(&format!("/documents/{}", Uuid::new_v4()))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 403);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["error"], "authorization_denied");
    // No token material ever echoed in the error body (§11.8).
    assert!(!body.to_string().contains(&token));
}

/// Unauthenticated: no credential at all → the injected §10 extractor rejects
/// with 401 `authentication_failed` before the guard runs. The authz endpoint
/// is deliberately not mounted, proving no check was attempted.
#[tokio::test]
async fn unauthenticated_returns_401() {
    let server = MockServer::start().await;
    mount_jwks(&server).await;

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(verifier_for(&server)))
            .app_data(web::Data::new(client_for(&server)))
            .route("/documents/{id}", web::get().to(read_doc)),
    )
    .await;

    let req = test::TestRequest::get()
        .uri(&format!("/documents/{}", Uuid::new_v4()))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 401);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["error"], "authentication_failed");
}

/// Unresolvable resource: a non-UUID path segment → 400 `invalid_request`,
/// never a silent allow and never a nil-UUID fallback (§11.3).
#[tokio::test]
async fn bad_uuid_returns_400() {
    let server = MockServer::start().await;
    mount_jwks(&server).await;

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(verifier_for(&server)))
            .app_data(web::Data::new(client_for(&server)))
            .route("/documents/{id}", web::get().to(read_doc)),
    )
    .await;

    let req = test::TestRequest::get()
        .uri("/documents/not-a-uuid")
        .insert_header((
            "Authorization",
            format!("Bearer {}", issue_token(Uuid::new_v4(), None)),
        ))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 400);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["error"], "invalid_request");
}

/// Transport failure reaching the authz endpoint → fail closed with 503
/// `authz_unavailable` (deny; never allow on transport failure).
#[tokio::test]
async fn transport_failure_returns_503_fail_closed() {
    let server = MockServer::start().await;
    mount_jwks(&server).await;

    // A 5xx from the authz endpoint maps to the SDK's `NetworkError` taxonomy
    // (CONTRACT.md §2), which the §11 guard must fail closed on.
    Mock::given(method("POST"))
        .and(path("/api/v1/authz/check"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(verifier_for(&server)))
            .app_data(web::Data::new(client_for(&server)))
            .route("/documents/{id}", web::get().to(read_doc)),
    )
    .await;

    let req = test::TestRequest::get()
        .uri(&format!("/documents/{}", Uuid::new_v4()))
        .insert_header((
            "Authorization",
            format!("Bearer {}", issue_token(Uuid::new_v4(), None)),
        ))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 503);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["error"], "authz_unavailable");
}

/// `#[require_auth]`: a valid session passes straight through to the body.
#[tokio::test]
async fn require_auth_allows_authenticated() {
    let server = MockServer::start().await;
    mount_jwks(&server).await;

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(verifier_for(&server)))
            .route("/whoami", web::get().to(auth_only)),
    )
    .await;

    let req = test::TestRequest::get()
        .uri("/whoami")
        .insert_header((
            "Authorization",
            format!("Bearer {}", issue_token(Uuid::new_v4(), None)),
        ))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);
}

/// `#[require_auth]`: no credential → 401.
#[tokio::test]
async fn require_auth_rejects_anonymous() {
    let server = MockServer::start().await;
    mount_jwks(&server).await;

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(verifier_for(&server)))
            .route("/whoami", web::get().to(auth_only)),
    )
    .await;

    let req = test::TestRequest::get().uri("/whoami").to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 401);
}

/// `#[require_role]`: the verified token's `scope` claim surfaces as `roles`;
/// a token carrying `admin` passes the local check (no server round-trip — the
/// authz endpoint is not mounted).
#[tokio::test]
async fn require_role_allows_when_role_present() {
    let server = MockServer::start().await;
    mount_jwks(&server).await;

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(verifier_for(&server)))
            .route("/admin", web::get().to(admin_only)),
    )
    .await;

    let req = test::TestRequest::get()
        .uri("/admin")
        .insert_header((
            "Authorization",
            format!(
                "Bearer {}",
                issue_token(Uuid::new_v4(), Some("admin editor"))
            ),
        ))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);
}

/// `#[require_role]`: a token without the required role → 403.
#[tokio::test]
async fn require_role_denies_when_role_absent() {
    let server = MockServer::start().await;
    mount_jwks(&server).await;

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(verifier_for(&server)))
            .route("/admin", web::get().to(admin_only)),
    )
    .await;

    let req = test::TestRequest::get()
        .uri("/admin")
        .insert_header((
            "Authorization",
            format!("Bearer {}", issue_token(Uuid::new_v4(), Some("viewer"))),
        ))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 403);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["error"], "authorization_denied");
}

/// Misconfiguration: `#[require_access]` on an app with no `AxiamClient`
/// registered fails with a 5xx (the `web::Data<AxiamClient>` extractor
/// rejects), never a silent allow.
#[tokio::test]
async fn missing_client_data_returns_server_error() {
    let server = MockServer::start().await;
    mount_jwks(&server).await;

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(verifier_for(&server)))
            // No AxiamClient app data registered.
            .route("/documents/{id}", web::get().to(read_doc)),
    )
    .await;

    let req = test::TestRequest::get()
        .uri(&format!("/documents/{}", Uuid::new_v4()))
        .insert_header((
            "Authorization",
            format!("Bearer {}", issue_token(Uuid::new_v4(), None)),
        ))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_server_error());
}
