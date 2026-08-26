//! Shared harness for the CONTRACT §27 management tests.
//!
//! Every management operation requires an authenticated session (§27.4 rule 1
//! refuses to make a wire call without one), so each test needs a client that
//! has actually logged in against its mock server. That setup is identical for
//! all of them and lives here.

#![cfg(feature = "rest")]
#![allow(dead_code)]

use axiam_sdk::client::AxiamClient;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde::Serialize;
use serde_json::json;
use uuid::Uuid;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// A fixed test Ed25519 private seed (test-only, deterministic), stored as raw
/// bytes rather than a PEM/DER block so no private-key literal lives in source.
const TEST_ED25519_SEED: [u8; 32] = [
    0x74, 0x8c, 0x0b, 0xd3, 0xad, 0xc0, 0x28, 0x0a, 0xfd, 0xd7, 0xc0, 0x7c, 0x35, 0x07, 0x03, 0x64,
    0x6d, 0x14, 0x2d, 0x1d, 0xbd, 0x73, 0x4c, 0xd4, 0xf8, 0x17, 0x17, 0x0b, 0x91, 0x7b, 0x49, 0xfc,
];
const ED25519_PKCS8_DER_PREFIX: [u8; 16] = [
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];
const TEST_ED25519_PUBLIC_X: &str = "_r-I_0nRSSV8kvwA93gwhX-hFRiWkaNk5HEud-DjnMk";
const TEST_KID: &str = "test-kid-1";

/// The tenant every harness client is built with, as a UUID.
///
/// A UUID rather than a slug on purpose: §27.4 rule 3 makes a slug-only client
/// fail locally on any route carrying `{tenant_id}`, and that refusal has its
/// own test rather than being the default everywhere.
pub const TENANT_ID: &str = "22222222-2222-4222-8222-222222222222";
/// The organization every harness client is built with.
pub const ORG_ID: &str = "33333333-3333-4333-8333-333333333333";
/// The id the generated surface test substitutes into every path parameter.
pub const EXAMPLE_ID: &str = "11111111-1111-4111-8111-111111111111";

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

fn issue_test_access_token() -> String {
    let mut header = Header::new(Algorithm::EdDSA);
    header.kid = Some(TEST_KID.to_string());
    let claims = TestClaims {
        sub: Uuid::new_v4().to_string(),
        tenant_id: TENANT_ID.to_string(),
        org_id: ORG_ID.to_string(),
        iss: "axiam-test".to_string(),
        iat: 0,
        exp: 9_999_999_999,
        jti: Uuid::new_v4().to_string(),
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

/// Mount JWKS + login, and return a client that has completed a login.
///
/// The login mock is mounted at lowest specificity, so a test may mount its
/// own management routes before or after without ordering trouble.
pub async fn logged_in_client(server: &MockServer) -> AxiamClient {
    Mock::given(method("GET"))
        .and(path("/oauth2/jwks"))
        .respond_with(ResponseTemplate::new(200).set_body_json(jwks_body()))
        .mount(server)
        .await;

    let access_token = issue_test_access_token();
    let mut response = ResponseTemplate::new(200).set_body_json(json!({
        "user": { "id": Uuid::new_v4(), "username": "admin", "email": "admin@example.com" },
        "session_id": Uuid::new_v4(),
        "expires_in": 900,
    }));
    for cookie in [
        format!("axiam_access={access_token}; Path=/; HttpOnly"),
        "axiam_refresh=test-refresh-token; Path=/; HttpOnly".to_string(),
        "axiam_csrf=test-csrf-token; Path=/".to_string(),
    ] {
        response = response.append_header("Set-Cookie", cookie.as_str());
    }
    Mock::given(method("POST"))
        .and(path("/api/v1/auth/login"))
        .respond_with(response)
        .mount(server)
        .await;

    let client = anonymous_client(&server.uri());
    client
        .login("admin@example.com", "correct horse battery staple")
        .await
        .expect("harness login");
    client
}

/// A client with tenant and organization UUIDs, but no session.
pub fn anonymous_client(base_url: &str) -> AxiamClient {
    AxiamClient::builder()
        .base_url(base_url)
        .expect("valid base_url")
        .tenant_id(Uuid::parse_str(TENANT_ID).unwrap())
        .org_id(Uuid::parse_str(ORG_ID).unwrap())
        // §16 is exercised by its own tests; leaving it on here would make a
        // deliberate 5xx fixture take three round-trips and seconds of backoff.
        .retry_enabled(false)
        .build()
        .expect("client builds")
}

/// Mount one canned response for `verb` at `route`.
pub async fn mount(server: &MockServer, verb: &str, route: &str, status: u16, body: &str) {
    let template = if body.is_empty() {
        ResponseTemplate::new(status)
    } else {
        ResponseTemplate::new(status).set_body_raw(body.as_bytes().to_vec(), "application/json")
    };
    Mock::given(method(verb))
        .and(path(route))
        .respond_with(template)
        .mount(server)
        .await;
}

/// The operations `management-registry.json` names, `namespace.operation`.
///
/// Parsed from the vendored registry at test time rather than restated, so
/// this cannot drift from the file the generator reads.
pub fn expected_surface() -> Vec<String> {
    let registry: serde_json::Value =
        serde_json::from_str(include_str!("../management-registry.json"))
            .expect("management-registry.json parses");
    let mut out = Vec::new();
    for (namespace, def) in registry["namespaces"].as_object().expect("namespaces") {
        for operation in def["operations"].as_object().expect("operations").keys() {
            out.push(format!("{namespace}.{operation}"));
        }
    }
    out.sort();
    out
}
