//! `JwksVerifier::verify` (`src/token/jwks.rs`) rejection branches not
//! covered by the fetch/refetch/single-flight suites: a non-EdDSA `alg`
//! header, a structurally invalid token header, an expired-but-otherwise
//! valid EdDSA token, and a JWKS whose matching `kid` entry is not a
//! usable decoding key.

#![cfg(feature = "rest")]

use axiam_sdk::token::JwksVerifier;
use axiam_sdk::AxiamError;
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

fn ed25519_key() -> EncodingKey {
    let mut der = ED25519_PKCS8_DER_PREFIX.to_vec();
    der.extend_from_slice(&TEST_ED25519_SEED);
    EncodingKey::from_ed_der(&der)
}

/// Mint an EdDSA token with a caller-chosen `exp` so the expiry branch can be
/// exercised deterministically.
fn issue_ed25519_token(exp: i64) -> String {
    let mut header = Header::new(Algorithm::EdDSA);
    header.kid = Some(TEST_KID.to_string());
    let claims = TestClaims {
        sub: Uuid::new_v4().to_string(),
        tenant_id: Uuid::new_v4().to_string(),
        org_id: Uuid::new_v4().to_string(),
        iss: "axiam-test".to_string(),
        iat: 0,
        exp,
        jti: Uuid::new_v4().to_string(),
    };
    jsonwebtoken::encode(&header, &claims, &ed25519_key()).expect("encode token")
}

fn build_verifier(base_url: &str) -> JwksVerifier {
    let http_client = reqwest::Client::new();
    let url = url::Url::parse(base_url).expect("valid base url");
    JwksVerifier::new(http_client, &url).expect("verifier constructs")
}

#[tokio::test]
async fn verify_rejects_a_non_eddsa_alg_before_any_fetch() {
    // An HS256 token — the alg gate rejects it before the JWKS is ever
    // fetched, so no mock server is needed.
    let mut header = Header::new(Algorithm::HS256);
    header.kid = Some(TEST_KID.to_string());
    let claims = TestClaims {
        sub: Uuid::new_v4().to_string(),
        tenant_id: Uuid::new_v4().to_string(),
        org_id: Uuid::new_v4().to_string(),
        iss: "axiam-test".to_string(),
        iat: 0,
        exp: 9_999_999_999,
        jti: Uuid::new_v4().to_string(),
    };
    let token = jsonwebtoken::encode(&header, &claims, &EncodingKey::from_secret(b"secret"))
        .expect("encode HS256 token");

    let verifier = build_verifier("https://iam.example.com");
    let err = verifier
        .verify(&token)
        .await
        .expect_err("a non-EdDSA alg must be rejected");
    match err {
        AxiamError::Auth { message } => assert!(message.contains("EdDSA"), "message: {message}"),
        other => panic!("expected Auth error, got {other:?}"),
    }
}

#[tokio::test]
async fn verify_rejects_a_structurally_invalid_token_header() {
    let verifier = build_verifier("https://iam.example.com");
    let err = verifier
        .verify("this-is-not-a-jwt")
        .await
        .expect_err("a malformed token header must be rejected");
    assert!(matches!(err, AxiamError::Auth { .. }));
}

#[tokio::test]
async fn verify_maps_an_expired_token_to_an_auth_error() {
    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/oauth2/jwks"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "keys": [{
                "kty": "OKP",
                "crv": "Ed25519",
                "kid": TEST_KID,
                "alg": "EdDSA",
                "x": TEST_ED25519_PUBLIC_X,
            }]
        })))
        .mount(&mock_server)
        .await;

    let verifier = build_verifier(&mock_server.uri());
    // exp in the distant past: signature verifies but the token is expired.
    let token = issue_ed25519_token(1);

    let err = verifier
        .verify(&token)
        .await
        .expect_err("an expired token must be rejected");
    match err {
        AxiamError::Auth { message } => assert!(message.contains("expired"), "message: {message}"),
        other => panic!("expected Auth error, got {other:?}"),
    }
}

#[tokio::test]
async fn verify_maps_an_unusable_matching_jwk_to_an_auth_error() {
    let mock_server = MockServer::start().await;
    // A JWK carrying the requested `kid` but whose `x` is not valid
    // base64url material — `DecodingKey::from_jwk` cannot build a key from it.
    Mock::given(method("GET"))
        .and(path("/oauth2/jwks"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "keys": [{
                "kty": "OKP",
                "crv": "Ed25519",
                "kid": TEST_KID,
                "alg": "EdDSA",
                "x": "!!!not-valid-base64url!!!",
            }]
        })))
        .mount(&mock_server)
        .await;

    let verifier = build_verifier(&mock_server.uri());
    let token = issue_ed25519_token(9_999_999_999);

    let err = verifier
        .verify(&token)
        .await
        .expect_err("an unusable matching JWK must surface as an error");
    assert!(matches!(err, AxiamError::Auth { .. }));
}
