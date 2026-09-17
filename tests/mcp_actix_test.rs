//! CONTRACT.md §28.9 required tests 3, 4 and 5 on the Actix-Web surface,
//! plus the regression §28.9 calls "more than all five": with
//! `resource_metadata_url` unset, nothing changes.
//!
//! Ported from the TypeScript reference implementation's
//! `test/middleware/mcp.express.test.ts` (T21.9b). Tests 3 and 5 drive
//! [`AxiamUser::from_request`] directly against a real [`HttpRequest`],
//! exactly as `tests/actix_extractor_test.rs` already does for the plain §10
//! guard — no `App`/socket needed, since the extractor takes no dependency
//! on Actix's router. Test 4 drives [`RequireAccess::check`] directly for
//! the same reason `tests/uma_challenge_middleware_test.rs` does: it is a
//! plain async method, not a route. The one sub-assertion that needs a real
//! registered route — the metadata document itself — goes through
//! `actix_web::test::call_service` against a service built from
//! [`serve_protected_resource_metadata`].
//!
//! The fixture is §28.9's, restated here (integration test binaries are
//! separate crates in this project and do not share modules across files
//! except via `#[path]`, which none of the sibling middleware test files
//! use either).

#![cfg(feature = "actix")]

use actix_web::dev::Payload;
use actix_web::{App, FromRequest, HttpRequest, ResponseError, test, web};
use axiam_sdk::client::AxiamClient;
use axiam_sdk::middleware::{
    AxiamUser, RequireAccess, protected_resource_metadata, serve_protected_resource_metadata,
};
use axiam_sdk::rest::authz::reason_code;
use axiam_sdk::token::JwksVerifier;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde::Serialize;
use serde_json::json;
use uuid::Uuid;
use wiremock::matchers::{method, path};
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
const TEST_TENANT: &str = "3f6b1c8e-0000-4000-8000-0000000000e5";

const RESOURCE: &str = "https://mcp.example.com/mcp";
const METADATA_PATH: &str = "/.well-known/oauth-protected-resource/mcp";
const METADATA_URL: &str = "https://mcp.example.com/.well-known/oauth-protected-resource/mcp";
const EXPECTED_AUDIENCE: &str = "https://mcp.example.com/mcp";

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
    #[serde(skip_serializing_if = "Option::is_none")]
    aud: Option<String>,
}

/// A signed AXIAM access token. `aud` and `expired` are what the §28 tests
/// vary — mirrors the reference port's own `token({ aud, expired })` helper.
fn issue_token(aud: Option<&str>, expired: bool) -> String {
    let mut header = Header::new(Algorithm::EdDSA);
    header.kid = Some(TEST_KID.to_string());
    let claims = TestClaims {
        sub: Uuid::new_v4().to_string(),
        tenant_id: test_tenant().to_string(),
        org_id: Uuid::new_v4().to_string(),
        iss: "axiam-test".to_string(),
        iat: 0,
        // Well past CLOCK_SKEW_LEEWAY_SEC, so an expired token is expired
        // rather than merely skewed.
        exp: if expired { 1 } else { 9_999_999_999 },
        jti: Uuid::new_v4().to_string(),
        scope: Some("mcp:read".to_string()),
        aud: aud.map(str::to_string),
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

/// The §28-configured verifier: `resource_metadata_url` set, and
/// `expected_audience` set to the document's `resource` — §28.5 rule 2 makes
/// the second mandatory once the first is present.
fn mcp_verifier(server: &MockServer) -> JwksVerifier {
    let url = url::Url::parse(&server.uri()).expect("valid base url");
    JwksVerifier::new(reqwest::Client::new(), &url)
        .expect("verifier constructs")
        .expect_tenant_id(test_tenant())
        .expect_audience(EXPECTED_AUDIENCE)
        .with_resource_metadata_url(METADATA_URL)
        .expect("valid §28 configuration")
}

/// The same verifier with §28 off — the regression's baseline.
fn plain_verifier(server: &MockServer) -> JwksVerifier {
    let url = url::Url::parse(&server.uri()).expect("valid base url");
    JwksVerifier::new(reqwest::Client::new(), &url)
        .expect("verifier constructs")
        .expect_tenant_id(test_tenant())
        .expect_audience(EXPECTED_AUDIENCE)
}

fn www_authenticate(err: &impl ResponseError) -> Option<String> {
    err.error_response()
        .headers()
        .get(actix_web::http::header::WWW_AUTHENTICATE)
        .map(|v| v.to_str().expect("ASCII header").to_string())
}

fn no_credential_vector() -> String {
    format!("Bearer resource_metadata=\"{METADATA_URL}\"")
}
fn invalid_token_vector() -> String {
    format!("Bearer error=\"invalid_token\", resource_metadata=\"{METADATA_URL}\"")
}
fn insufficient_scope_vector(scope: &str) -> String {
    format!(
        "Bearer error=\"insufficient_scope\", scope=\"{scope}\", resource_metadata=\"{METADATA_URL}\""
    )
}

async fn extract(
    req: &HttpRequest,
) -> Result<AxiamUser, axiam_sdk::middleware::actix::AxiamExtractorError> {
    let mut payload = Payload::None;
    AxiamUser::from_request(req, &mut payload).await
}

// ---------------------------------------------------------------------------
// §28.9 test 3 — 401 with the challenge
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_request_with_no_authorization_header_answers_vector_1_body_unchanged() {
    let server = MockServer::start().await;
    mount_jwks(&server).await;
    let verifier = mcp_verifier(&server);

    let req = test::TestRequest::default()
        .app_data(web::Data::new(verifier))
        .to_http_request();
    let err = extract(&req).await.expect_err("no credential");

    assert_eq!(err.error_response().status(), 401);
    let challenge = www_authenticate(&err).expect("challenge present");
    assert_eq!(challenge, no_credential_vector());
    // No `error` parameter: RFC 6750 §3 says a resource server SHOULD NOT
    // name an error code when the request carried no authentication
    // information at all. No credential is not a bad credential.
    assert!(!challenge.contains("error="));

    let body_bytes = actix_web::body::to_bytes(err.error_response().into_body())
        .await
        .expect("readable body");
    let body: serde_json::Value = serde_json::from_slice(&body_bytes).expect("valid JSON");
    // §28 adds a header. It does not touch the status or the body.
    assert_eq!(body["error"], "authentication_failed");
    assert_eq!(body["message"], "missing authentication credentials");
}

#[tokio::test]
async fn a_request_with_an_expired_token_answers_vector_2_and_says_nothing_else_about_why() {
    let server = MockServer::start().await;
    mount_jwks(&server).await;
    let verifier = mcp_verifier(&server);

    let token = issue_token(Some(EXPECTED_AUDIENCE), true);
    let req = test::TestRequest::default()
        .app_data(web::Data::new(verifier))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_http_request();
    let err = extract(&req).await.expect_err("expired token");

    assert_eq!(err.error_response().status(), 401);
    let challenge = www_authenticate(&err).expect("challenge present");
    assert_eq!(challenge, invalid_token_vector());
    // §28.4 and §28.8: no `error_description`, and nothing derived from the
    // token — every distinction a 401 draws for an unauthenticated stranger
    // is an oracle.
    assert!(!challenge.contains("error_description"));
    assert!(!challenge.to_lowercase().contains("expired"));
}

#[tokio::test]
async fn serves_the_document_with_no_credential_and_identically_to_an_authenticated_caller() {
    let server = MockServer::start().await;
    mount_jwks(&server).await;
    let verifier = mcp_verifier(&server);

    let metadata = protected_resource_metadata(
        axiam_sdk::middleware::ProtectedResourceMetadataOptions::new(
            RESOURCE,
            vec!["https://axiam.example.com".to_string()],
        )
        .scopes_supported(vec!["mcp:read".to_string(), "mcp:tools".to_string()])
        .resource_documentation("https://mcp.example.com/docs"),
    )
    .expect("valid fixture");
    assert_eq!(metadata.metadata_path, METADATA_PATH);

    let app = test::init_service(App::new().service(
        serve_protected_resource_metadata(&metadata, Some(&verifier)).expect("cross-check passes"),
    ))
    .await;

    let anonymous = test::TestRequest::get().uri(METADATA_PATH).to_request();
    let anonymous_resp = test::call_service(&app, anonymous).await;
    assert_eq!(anonymous_resp.status().as_u16(), 200);
    assert!(
        anonymous_resp
            .headers()
            .get(actix_web::http::header::WWW_AUTHENTICATE)
            .is_none()
    );
    assert_eq!(
        anonymous_resp
            .headers()
            .get(actix_web::http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("application/json")
    );
    assert_eq!(
        anonymous_resp
            .headers()
            .get("cache-control")
            .and_then(|v| v.to_str().ok()),
        Some("public, max-age=3600")
    );
    assert_eq!(
        anonymous_resp
            .headers()
            .get("access-control-allow-origin")
            .and_then(|v| v.to_str().ok()),
        Some("*")
    );
    assert!(
        anonymous_resp
            .headers()
            .get("access-control-allow-credentials")
            .is_none()
    );
    assert!(
        anonymous_resp
            .headers()
            .get(actix_web::http::header::SET_COOKIE)
            .is_none()
    );
    let anonymous_body = test::read_body(anonymous_resp).await;
    let anonymous_json: serde_json::Value = serde_json::from_slice(&anonymous_body).unwrap();
    assert_eq!(
        anonymous_json,
        json!({
            "resource": RESOURCE,
            "authorization_servers": ["https://axiam.example.com"],
            "scopes_supported": ["mcp:read", "mcp:tools"],
            "bearer_methods_supported": ["header"],
            "resource_documentation": "https://mcp.example.com/docs",
        })
    );

    // §28.3 rule 4: the response MUST NOT vary on the request.
    let token = issue_token(Some(EXPECTED_AUDIENCE), false);
    let authenticated = test::TestRequest::get()
        .uri(METADATA_PATH)
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();
    let authenticated_resp = test::call_service(&app, authenticated).await;
    let authenticated_body = test::read_body(authenticated_resp).await;
    assert_eq!(anonymous_body, authenticated_body);
}

// ---------------------------------------------------------------------------
// §28.9 test 4 — 403 insufficient_scope
// ---------------------------------------------------------------------------

fn checker_client(server: &MockServer) -> AxiamClient {
    AxiamClient::builder()
        .base_url(server.uri())
        .expect("loopback base_url accepted")
        .tenant_slug("acme")
        .build()
        .expect("client builds")
}

/// A verifier configured for §28, but pointed at a base URL nothing ever
/// resolves — `RequireAccess::check` never calls `verifier.verify(...)`, so
/// this exists only to carry the precomputed §28.4 challenge values.
fn mcp_only_verifier() -> JwksVerifier {
    let url = url::Url::parse("https://unused.example.invalid").unwrap();
    JwksVerifier::new(reqwest::Client::new(), &url)
        .expect("verifier constructs")
        .expect_audience(EXPECTED_AUDIENCE)
        .with_resource_metadata_url(METADATA_URL)
        .expect("valid §28 configuration")
}

async fn mount_check(server: &MockServer, decision: serde_json::Value) {
    Mock::given(method("POST"))
        .and(path("/api/v1/authz/check"))
        .respond_with(ResponseTemplate::new(200).set_body_json(decision))
        .mount(server)
        .await;
}

#[tokio::test]
async fn a_no_grant_denial_on_a_scoped_route_answers_vector_3_body_unchanged() {
    let server = MockServer::start().await;
    mount_check(
        &server,
        json!({ "allowed": false, "reason": "no matching grant", "reason_code": reason_code::NO_GRANT }),
    )
    .await;
    let client = checker_client(&server);
    let verifier = mcp_only_verifier();
    let user = AxiamUser {
        user_id: Uuid::new_v4(),
        tenant_id: Uuid::new_v4(),
        roles: vec![],
    };

    let err = RequireAccess::new("mcp:invoke")
        .scope("mcp:tools")
        .with_resource_metadata_url(&verifier)
        .check(&client, &user, Uuid::new_v4())
        .await
        .expect_err("denied");

    let resp = err.error_response();
    assert_eq!(resp.status(), 403);
    let challenge = www_authenticate(&err).expect("challenge present");
    assert_eq!(challenge, insufficient_scope_vector("mcp:tools"));

    // Read this twice: the JSON body does not change. `insufficient_scope`
    // appears ONLY as the `error` parameter inside the header.
    let body_bytes = actix_web::body::to_bytes(resp.into_body()).await.unwrap();
    let body: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(body["error"], "authorization_denied");
    assert!(
        !serde_json::to_string(&body)
            .unwrap()
            .contains("insufficient_scope")
    );
}

#[tokio::test]
async fn names_the_scope_the_route_asked_for_verbatim() {
    let server = MockServer::start().await;
    mount_check(
        &server,
        json!({ "allowed": false, "reason": "no matching grant", "reason_code": reason_code::NO_GRANT }),
    )
    .await;
    let client = checker_client(&server);
    let verifier = mcp_only_verifier();
    let user = AxiamUser {
        user_id: Uuid::new_v4(),
        tenant_id: Uuid::new_v4(),
        roles: vec![],
    };

    // §28.5 rule 6: never synthesised, never derived from `action`/`resource`.
    let err = RequireAccess::new("mcp:invoke")
        .scope("urn:example:tools.invoke")
        .with_resource_metadata_url(&verifier)
        .check(&client, &user, Uuid::new_v4())
        .await
        .expect_err("denied");

    assert_eq!(
        www_authenticate(&err).unwrap(),
        insufficient_scope_vector("urn:example:tools.invoke")
    );
}

#[tokio::test]
async fn carries_no_challenge_on_denied_by_rule_an_absent_reason_code_or_no_scope_argument() {
    let user = AxiamUser {
        user_id: Uuid::new_v4(),
        tenant_id: Uuid::new_v4(),
        roles: vec![],
    };
    let verifier = mcp_only_verifier();

    async fn denial(
        client: &AxiamClient,
        verifier: &JwksVerifier,
        user: &AxiamUser,
        scope: Option<&str>,
    ) -> axiam_sdk::middleware::AuthzGuardError {
        let mut guard = RequireAccess::new("mcp:invoke").with_resource_metadata_url(verifier);
        if let Some(scope) = scope {
            guard = guard.scope(scope);
        }
        guard
            .check(client, user, Uuid::new_v4())
            .await
            .expect_err("denied")
    }

    // `no_grant` means *ask for more*; `denied_by_rule` means *an admin has
    // already decided* — challenging on it sends an MCP client around the
    // authorization loop to arrive at the identical 403.
    let server = MockServer::start().await;
    mount_check(
        &server,
        json!({ "allowed": false, "reason": "denied", "reason_code": reason_code::DENIED_BY_RULE }),
    )
    .await;
    let client = checker_client(&server);
    let by_rule = denial(&client, &verifier, &user, Some("mcp:tools")).await;
    assert!(www_authenticate(&by_rule).is_none());

    // An older server, or a code this SDK predates.
    let server = MockServer::start().await;
    mount_check(&server, json!({ "allowed": false, "reason": "denied" })).await;
    let client = checker_client(&server);
    let no_code = denial(&client, &verifier, &user, Some("mcp:tools")).await;
    assert!(www_authenticate(&no_code).is_none());

    let server = MockServer::start().await;
    mount_check(
        &server,
        json!({ "allowed": false, "reason": "denied", "reason_code": "quota_exhausted" }),
    )
    .await;
    let client = checker_client(&server);
    let unknown_code = denial(&client, &verifier, &user, Some("mcp:tools")).await;
    assert!(www_authenticate(&unknown_code).is_none());

    // No scope argument: there is nothing to name, and §28 forbids guessing.
    let server = MockServer::start().await;
    mount_check(
        &server,
        json!({ "allowed": false, "reason": "denied", "reason_code": reason_code::NO_GRANT }),
    )
    .await;
    let client = checker_client(&server);
    let no_scope = denial(&client, &verifier, &user, None).await;
    assert!(www_authenticate(&no_scope).is_none());
}

#[tokio::test]
async fn touches_no_other_response_an_allow_gains_nothing() {
    let server = MockServer::start().await;
    mount_check(
        &server,
        json!({ "allowed": true, "reason_code": reason_code::ALLOWED }),
    )
    .await;
    let client = checker_client(&server);
    let verifier = mcp_only_verifier();
    let user = AxiamUser {
        user_id: Uuid::new_v4(),
        tenant_id: Uuid::new_v4(),
        roles: vec![],
    };

    // A challenge on a success is a client asking the authorization server
    // what went right.
    RequireAccess::new("mcp:invoke")
        .scope("mcp:tools")
        .with_resource_metadata_url(&verifier)
        .check(&client, &user, Uuid::new_v4())
        .await
        .expect("allowed");
}

// ---------------------------------------------------------------------------
// §28.9 test 5 — a token whose `aud` is not the resource is refused
// ---------------------------------------------------------------------------

#[tokio::test]
async fn refuses_a_token_minted_for_another_resource_server() {
    let server = MockServer::start().await;
    mount_jwks(&server).await;
    let verifier = mcp_verifier(&server);

    let token = issue_token(Some("https://other.example.com/mcp"), false);
    let req = test::TestRequest::default()
        .app_data(web::Data::new(verifier))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_http_request();
    let err = extract(&req).await.expect_err("wrong audience");

    assert_eq!(err.error_response().status(), 401);
    assert_eq!(www_authenticate(&err).unwrap(), invalid_token_vector());
}

#[tokio::test]
async fn refuses_a_general_purpose_axiam_user_token_identically() {
    let server = MockServer::start().await;
    mount_jwks(&server).await;
    let verifier = mcp_verifier(&server);

    // A perfectly valid AXIAM token that simply was not minted for this
    // resource. The two refusals are indistinguishable from outside, which
    // is the point.
    let token = issue_token(Some("axiam:user"), false);
    let req = test::TestRequest::default()
        .app_data(web::Data::new(verifier))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_http_request();
    let err = extract(&req).await.expect_err("wrong audience");

    assert_eq!(err.error_response().status(), 401);
    assert_eq!(www_authenticate(&err).unwrap(), invalid_token_vector());
}

#[tokio::test]
async fn admits_a_token_whose_aud_is_this_resource() {
    let server = MockServer::start().await;
    mount_jwks(&server).await;
    let verifier = mcp_verifier(&server);

    let token = issue_token(Some(EXPECTED_AUDIENCE), false);
    let req = test::TestRequest::default()
        .app_data(web::Data::new(verifier))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_http_request();
    extract(&req).await.expect("matching audience admitted");
}

// `#[tokio::test]` rather than the plain `#[test]`: `use actix_web::test`
// above brings `actix_web`'s async-test attribute macro into scope under the
// same name as the builtin, shadowing it for this file.
#[tokio::test]
async fn refuses_at_construction_when_resource_metadata_url_is_set_with_no_expected_audience() {
    let url = url::Url::parse("https://axiam.example.invalid").unwrap();
    // `JwksVerifier` is not `Debug` (§7: it may carry a credential-bearing
    // configuration downstream), so this matches rather than `.expect_err`s.
    let result = JwksVerifier::new(reqwest::Client::new(), &url)
        .expect("verifier constructs")
        // Deliberately no `.expect_audience(...)` first.
        .with_resource_metadata_url(METADATA_URL);
    let Err(err) = result else {
        panic!("must refuse — announcing yourself obliges you to check");
    };

    let rendered = err.to_string();
    assert!(rendered.contains("resource_metadata_url"), "{rendered}");
    assert!(rendered.contains("expect_audience"), "{rendered}");
}

// ---------------------------------------------------------------------------
// The regression that matters more than all five
// ---------------------------------------------------------------------------

#[tokio::test]
async fn emits_no_www_authenticate_on_any_response_when_resource_metadata_url_is_unset() {
    let server = MockServer::start().await;
    mount_jwks(&server).await;
    // Wrapped once and the `web::Data` handle cloned (a cheap `Arc` clone)
    // rather than the `JwksVerifier` itself, which is not `Clone` — the same
    // single instance backs both requests below.
    let verifier = web::Data::new(plain_verifier(&server));

    let unauthenticated_req = test::TestRequest::default()
        .app_data(verifier.clone())
        .to_http_request();
    let unauthenticated = extract(&unauthenticated_req)
        .await
        .expect_err("no credential");
    // Assert the header's ABSENCE explicitly rather than the status: a 401
    // that grew a header is still a 401, and an implementation that emitted
    // a bare `Bearer` challenge unconditionally would pass every other test
    // in this file.
    assert_eq!(unauthenticated.error_response().status(), 401);
    assert!(www_authenticate(&unauthenticated).is_none());
    let body_bytes = actix_web::body::to_bytes(unauthenticated.error_response().into_body())
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(body["error"], "authentication_failed");

    let token = issue_token(Some(EXPECTED_AUDIENCE), false);
    let authenticated_req = test::TestRequest::default()
        .app_data(verifier.clone())
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_http_request();
    extract(&authenticated_req)
        .await
        .expect("valid token admitted");

    // The one class of 403 §28 would otherwise touch, still bare.
    let authz_server = MockServer::start().await;
    mount_check(
        &authz_server,
        json!({ "allowed": false, "reason": "no matching grant", "reason_code": reason_code::NO_GRANT }),
    )
    .await;
    let client = checker_client(&authz_server);
    let user = AxiamUser {
        user_id: Uuid::new_v4(),
        tenant_id: Uuid::new_v4(),
        roles: vec![],
    };
    // No `.with_resource_metadata_url(...)` call at all: §28 stays off.
    let denied = RequireAccess::new("mcp:invoke")
        .scope("mcp:tools")
        .check(&client, &user, Uuid::new_v4())
        .await
        .expect_err("denied");
    assert!(www_authenticate(&denied).is_none());
    let resp = denied.error_response();
    let body_bytes = actix_web::body::to_bytes(resp.into_body()).await.unwrap();
    let body: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(body["error"], "authorization_denied");
}
