//! CONTRACT.md §10.4 — the optional session-revocation feed (contract 1.44,
//! AXIAM threats T-39 and T-143).
//!
//! Two properties, and the second is the one that makes the feature safe to
//! ship. A revoked `sid` is rejected **after one poll and not before**, which
//! pins that the guard reads a cached set rather than fetching per request.
//! And a guard with the feature **off**, or with it on and the feed
//! unreachable, behaves byte-for-byte as it does today — asserted by counting
//! requests on the wire, so "does not fetch" is proven rather than claimed.
//!
//! The harness mirrors `tests/local_verification_set_test.rs`: one Ed25519 key,
//! a JWKS mock, and a guard-shaped verifier with an expected tenant.

#![cfg(feature = "rest")]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use axiam_sdk::AxiamError;
use axiam_sdk::token::JwksVerifier;
use axiam_sdk::token::revocation::RevocationFeed;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde_json::{Value, json};
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
const TEST_KID: &str = "sec-101-kid";
const TENANT: &str = "3f6b1c8e-0000-4000-8000-0000000000a1";
const ISSUER: &str = "https://iam.example.com";

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock is after the epoch")
        .as_secs() as i64
}

fn ed25519_key() -> EncodingKey {
    let mut der = ED25519_PKCS8_DER_PREFIX.to_vec();
    der.extend_from_slice(&TEST_ED25519_SEED);
    EncodingKey::from_ed_der(&der)
}

fn sign(claims: &Value) -> String {
    let mut header = Header::new(Algorithm::EdDSA);
    header.kid = Some(TEST_KID.to_string());
    jsonwebtoken::encode(&header, claims, &ed25519_key()).expect("encode EdDSA token")
}

/// A token that satisfies every §10.1 rule, naming `sid`.
fn token_for_session(sid: &str) -> String {
    sign(&json!({
        "sub": Uuid::new_v4().to_string(),
        "tenant_id": TENANT,
        "iss": ISSUER,
        "aud": "axiam:user",
        "iat": now() - 60,
        "exp": now() + 3600,
        "jti": Uuid::new_v4().to_string(),
        "sid": sid,
        "scope": "read",
    }))
}

/// A token with no session behind it — a client-credentials token, an RPT, a
/// token exchange. §10.4 rule 6: never matched against the feed.
fn token_with_no_session() -> String {
    sign(&json!({
        "sub": Uuid::new_v4().to_string(),
        "tenant_id": TENANT,
        "iss": ISSUER,
        "aud": "axiam:m2m",
        "iat": now() - 60,
        "exp": now() + 3600,
        "jti": Uuid::new_v4().to_string(),
        "scope": "read",
    }))
}

async fn mount_jwks(server: &MockServer) {
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
        .mount(server)
        .await;
}

/// Mount the feed, counting every fetch. The counter is what proves the guard
/// is not polling per request.
async fn mount_feed(server: &MockServer, body: Value) -> Arc<AtomicUsize> {
    let fetches = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&fetches);
    Mock::given(method("GET"))
        .and(path("/oauth2/revocations"))
        .respond_with(move |_req: &wiremock::Request| {
            counter.fetch_add(1, Ordering::SeqCst);
            ResponseTemplate::new(200).set_body_json(body.clone())
        })
        .mount(server)
        .await;
    fetches
}

fn feed_document(revoked_sids: &[&str]) -> Value {
    json!({
        "alg": "SHA-256",
        "issued_at": now(),
        "ttl": 900,
        "revoked": revoked_sids
            .iter()
            .map(|s| RevocationFeed::entry_for(s))
            .collect::<Vec<_>>(),
    })
}

fn verifier(base_url: &str) -> JwksVerifier {
    let url = url::Url::parse(base_url).expect("valid base url");
    JwksVerifier::new(reqwest::Client::new(), &url)
        .expect("verifier constructs")
        .expect_tenant_id(TENANT.parse().expect("tenant const is a UUID"))
}

fn with_feed(base_url: &str) -> JwksVerifier {
    let url = url::Url::parse(base_url).expect("valid base url");
    verifier(base_url).with_revocation_feed(
        RevocationFeed::new(reqwest::Client::new(), &url).expect("feed constructs"),
    )
}

// ── The feature, on ────────────────────────────────────────────────────────

#[tokio::test]
async fn a_revoked_session_is_rejected() {
    let server = MockServer::start().await;
    mount_jwks(&server).await;
    let revoked = Uuid::new_v4().to_string();
    mount_feed(&server, feed_document(&[&revoked])).await;

    let err = with_feed(&server.uri())
        .verify(&token_for_session(&revoked))
        .await
        .expect_err("a listed session must be rejected");
    match err {
        AxiamError::Auth { message, .. } => assert!(message.contains("revoked"), "{message}"),
        other => panic!("expected AxiamError::Auth, got {other:?}"),
    }
}

#[tokio::test]
async fn a_session_the_feed_does_not_list_still_verifies() {
    let server = MockServer::start().await;
    mount_jwks(&server).await;
    mount_feed(&server, feed_document(&[&Uuid::new_v4().to_string()])).await;

    with_feed(&server.uri())
        .verify(&token_for_session(&Uuid::new_v4().to_string()))
        .await
        .expect("a session nobody revoked is unaffected");
}

/// §10.4 rule 2, and the property the whole design rests on: the guard reads a
/// cached set. Ten verifies produce **one** fetch, because the poll interval
/// has not elapsed — a guard fetching per request would show ten here and
/// nowhere else.
#[tokio::test]
async fn the_guard_polls_on_an_interval_and_never_per_request() {
    let server = MockServer::start().await;
    mount_jwks(&server).await;
    let fetches = mount_feed(&server, feed_document(&[])).await;
    let verifier = with_feed(&server.uri());

    for _ in 0..10 {
        verifier
            .verify(&token_for_session(&Uuid::new_v4().to_string()))
            .await
            .expect("verification succeeds");
    }

    assert_eq!(
        fetches.load(Ordering::SeqCst),
        1,
        "one poll for ten verifies — the set is cached, and the request path \
         never waits on the network"
    );
}

/// §10.4 rule 6. A token with no `sid` names no session, so it is not matched
/// against the feed at all — and specifically not by hashing its `jti`, which
/// would match nothing while looking like it worked.
#[tokio::test]
async fn a_token_with_no_session_is_never_matched() {
    let server = MockServer::start().await;
    mount_jwks(&server).await;
    // The feed lists the token's OWN `jti`, so an implementation that fell
    // back to it would reject here.
    let token = token_with_no_session();
    let jti = {
        let payload = token.split('.').nth(1).expect("three segments");
        let bytes =
            base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, payload)
                .expect("payload is base64url");
        let claims: Value = serde_json::from_slice(&bytes).expect("payload is JSON");
        claims["jti"].as_str().expect("jti").to_owned()
    };
    mount_feed(&server, feed_document(&[&jti])).await;

    with_feed(&server.uri())
        .verify(&token)
        .await
        .expect("a token with no sid is never matched against the feed");
}

// ── The feature, off — and the failure modes ───────────────────────────────

/// **I4 twin.** With no feed attached, the guard behaves exactly as it did
/// before contract 1.44: the revoked token verifies, and the feed endpoint is
/// **never called**. Asserted on the wire, because "does not fetch" is the
/// claim and a counter is the only thing that proves it.
#[tokio::test]
async fn with_the_feature_off_nothing_is_fetched_and_nothing_is_rejected() {
    let server = MockServer::start().await;
    mount_jwks(&server).await;
    let revoked = Uuid::new_v4().to_string();
    let fetches = mount_feed(&server, feed_document(&[&revoked])).await;

    verifier(&server.uri())
        .verify(&token_for_session(&revoked))
        .await
        .expect("the default guard is unchanged by contract 1.44");

    assert_eq!(
        fetches.load(Ordering::SeqCst),
        0,
        "a guard with no feed attached must not touch the endpoint"
    );
}

/// §10.4 rule 3, the load-bearing one. An unreachable feed behaves exactly as
/// the feature being off — **not** as an empty list, which would assert that
/// nothing has been revoked and is a guard silently honouring none.
#[tokio::test]
async fn an_unreachable_feed_behaves_as_no_feed_at_all() {
    let server = MockServer::start().await;
    mount_jwks(&server).await;
    Mock::given(method("GET"))
        .and(path("/oauth2/revocations"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&server)
        .await;

    with_feed(&server.uri())
        .verify(&token_for_session(&Uuid::new_v4().to_string()))
        .await
        .expect("an unreachable feed never denies a request");
}

/// The same, for a document this build cannot interpret. A server that starts
/// publishing a different digest must not silently produce a guard that
/// matches nothing.
#[tokio::test]
async fn an_unknown_alg_behaves_as_no_feed_at_all() {
    let server = MockServer::start().await;
    mount_jwks(&server).await;
    let revoked = Uuid::new_v4().to_string();
    mount_feed(
        &server,
        json!({
            "alg": "BLAKE3",
            "issued_at": now(),
            "ttl": 900,
            "revoked": [RevocationFeed::entry_for(&revoked)],
        }),
    )
    .await;

    with_feed(&server.uri())
        .verify(&token_for_session(&revoked))
        .await
        .expect("a document this build cannot interpret denies nothing");
}

/// And for a body that is not the document at all — a proxy's error page, a
/// deployment that does not publish the feed and answers 404 with HTML.
#[tokio::test]
async fn an_unparseable_document_behaves_as_no_feed_at_all() {
    let server = MockServer::start().await;
    mount_jwks(&server).await;
    Mock::given(method("GET"))
        .and(path("/oauth2/revocations"))
        .respond_with(ResponseTemplate::new(200).set_body_string("<html>not found</html>"))
        .mount(&server)
        .await;

    with_feed(&server.uri())
        .verify(&token_for_session(&Uuid::new_v4().to_string()))
        .await
        .expect("a body that is not the document denies nothing");
}
