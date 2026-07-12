//! `JwksVerifier` (`src/token/jwks.rs`, D-03/D-11) fetch-failure and
//! forced-refetch branches. `tests/jwks_single_flight_test.rs` covers the
//! concurrent-fetch-collapses-to-one oracle; this file covers the paths it
//! doesn't: a non-success/malformed JWKS response, and the unknown-`kid`
//! forced-refetch path (D-11 key rotation).

#![cfg(feature = "rest")]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

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
const ROTATED_KID: &str = "test-kid-2";

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

fn issue_test_access_token(kid: &str) -> String {
    let mut header = Header::new(Algorithm::EdDSA);
    header.kid = Some(kid.to_string());
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
    let mut der = ED25519_PKCS8_DER_PREFIX.to_vec();
    der.extend_from_slice(&TEST_ED25519_SEED);
    let key = EncodingKey::from_ed_der(&der);
    jsonwebtoken::encode(&header, &claims, &key).expect("encode test access token")
}

fn jwks_body_with_kid(kid: &str) -> serde_json::Value {
    json!({
        "keys": [
            {
                "kty": "OKP",
                "crv": "Ed25519",
                "kid": kid,
                "alg": "EdDSA",
                "x": TEST_ED25519_PUBLIC_X,
            }
        ]
    })
}

fn build_verifier(base_url: &str) -> JwksVerifier {
    let http_client = reqwest::Client::new();
    let url = url::Url::parse(base_url).expect("valid base url");
    JwksVerifier::new(http_client, &url).expect("verifier constructs")
}

#[tokio::test]
async fn verify_maps_a_non_success_jwks_response_to_an_error() {
    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/oauth2/jwks"))
        .respond_with(ResponseTemplate::new(503).set_body_string("jwks endpoint down"))
        .mount(&mock_server)
        .await;

    let verifier = build_verifier(&mock_server.uri());
    let token = issue_test_access_token(TEST_KID);

    let err = verifier
        .verify(&token)
        .await
        .expect_err("a non-success JWKS response must surface as an error");
    assert!(matches!(err, AxiamError::Network { .. }));
}

#[tokio::test]
async fn verify_maps_a_malformed_jwks_body_to_a_network_error() {
    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/oauth2/jwks"))
        .respond_with(ResponseTemplate::new(200).set_body_string("not valid json {{{"))
        .mount(&mock_server)
        .await;

    let verifier = build_verifier(&mock_server.uri());
    let token = issue_test_access_token(TEST_KID);

    let err = verifier
        .verify(&token)
        .await
        .expect_err("a malformed JWKS body must surface as an error, not panic");
    assert!(matches!(err, AxiamError::Network { .. }));
}

#[tokio::test]
async fn verify_with_unknown_kid_triggers_exactly_one_forced_refetch_then_succeeds() {
    // First fetch serves the OLD kid only; the token is signed with a
    // ROTATED kid the cache doesn't know about yet. `verify()` must miss on
    // the cached JWKS, force exactly one refetch (D-11), pick up the new
    // key, and succeed — proving the forced-refetch path, not just the
    // cold-cache path already covered by `jwks_single_flight_test.rs`.
    let mock_server = MockServer::start().await;
    let call_count = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&call_count);

    Mock::given(method("GET"))
        .and(path("/oauth2/jwks"))
        .respond_with(move |_req: &wiremock::Request| {
            let n = counter.fetch_add(1, Ordering::SeqCst);
            if n == 0 {
                ResponseTemplate::new(200).set_body_json(jwks_body_with_kid(TEST_KID))
            } else {
                ResponseTemplate::new(200).set_body_json(jwks_body_with_kid(ROTATED_KID))
            }
        })
        .mount(&mock_server)
        .await;

    let verifier = build_verifier(&mock_server.uri());

    // Prime the cache with the OLD kid.
    let old_token = issue_test_access_token(TEST_KID);
    verifier
        .verify(&old_token)
        .await
        .expect("priming verify with the known kid must succeed");
    assert_eq!(call_count.load(Ordering::SeqCst), 1);

    // Now verify a token signed with the ROTATED kid — a cache miss that
    // must trigger exactly one forced refetch.
    let rotated_token = issue_test_access_token(ROTATED_KID);
    let claims = verifier
        .verify(&rotated_token)
        .await
        .expect("an unknown kid must trigger a forced refetch and then succeed");
    assert_eq!(claims.iss, "axiam-test");
    assert_eq!(
        call_count.load(Ordering::SeqCst),
        2,
        "exactly one forced refetch must occur for the unknown-kid miss"
    );
}

#[tokio::test]
async fn verify_with_permanently_unknown_kid_fails_after_forced_refetch() {
    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/oauth2/jwks"))
        .respond_with(ResponseTemplate::new(200).set_body_json(jwks_body_with_kid(TEST_KID)))
        .mount(&mock_server)
        .await;

    let verifier = build_verifier(&mock_server.uri());
    // Signed with a kid the JWKS endpoint never serves, even after refetch.
    let token = issue_test_access_token("never-seen-kid");

    let err = verifier
        .verify(&token)
        .await
        .expect_err("a kid absent even after a forced refetch must fail, not loop forever");
    assert!(matches!(err, AxiamError::Auth { .. }));
}
