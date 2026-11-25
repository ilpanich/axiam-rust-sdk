//! CONTRACT.md §10.1 rules 10-12 (contract 1.68, security audit N14): the
//! access-token path refuses purpose tokens, wrong-`typ` tokens and kid-less
//! tokens, with a verifier configured with ONLY an expected tenant (no
//! audience, no issuer) -- the default a route guard gets.

#![cfg(feature = "rest")]

use axiam_sdk::token::JwksVerifier;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde_json::{Value, json};
use uuid::Uuid;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const SEED: [u8; 32] = [
    0x74, 0x8c, 0x0b, 0xd3, 0xad, 0xc0, 0x28, 0x0a, 0xfd, 0xd7, 0xc0, 0x7c, 0x35, 0x07, 0x03, 0x64,
    0x6d, 0x14, 0x2d, 0x1d, 0xbd, 0x73, 0x4c, 0xd4, 0xf8, 0x17, 0x17, 0x0b, 0x91, 0x7b, 0x49, 0xfc,
];
const PKCS8_PREFIX: [u8; 16] = [
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];
const PUBLIC_X: &str = "_r-I_0nRSSV8kvwA93gwhX-hFRiWkaNk5HEud-DjnMk";
const KID: &str = "n14-kid";
const TENANT: &str = "3f6b1c8e-0000-4000-8000-0000000000a1";

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn key() -> EncodingKey {
    let mut der = PKCS8_PREFIX.to_vec();
    der.extend_from_slice(&SEED);
    EncodingKey::from_ed_der(&der)
}

/// Claims of a server-minted purpose token: no `aud`, no `sid`.
fn claims(sub: &str, purpose: Option<&str>) -> Value {
    let mut c = json!({
        "sub": sub,
        "tenant_id": TENANT,
        "org_id": Uuid::new_v4().to_string(),
        "iss": "https://iam.example.com",
        "iat": now(),
        "exp": now() + 300,
    });
    if let Some(p) = purpose {
        c["purpose"] = json!(p);
    }
    c
}

fn sign(claims: &Value, kid: Option<&str>, typ: Option<&str>) -> String {
    let mut h = Header::new(Algorithm::EdDSA);
    h.kid = kid.map(str::to_owned);
    h.typ = typ.map(str::to_owned);
    jsonwebtoken::encode(&h, claims, &key()).unwrap()
}

async fn verifier() -> (MockServer, JwksVerifier) {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/oauth2/jwks"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "keys": [{"kty":"OKP","crv":"Ed25519","kid":KID,"alg":"EdDSA","x":PUBLIC_X}]
        })))
        .mount(&server)
        .await;
    let url = url::Url::parse(&server.uri()).unwrap();
    let v = JwksVerifier::new(reqwest::Client::new(), &url)
        .unwrap()
        .expect_tenant_id(TENANT.parse().unwrap());
    (server, v)
}

#[tokio::test]
async fn kidless_mfa_challenge_token_is_refused() {
    let (_s, v) = verifier().await;
    let t = sign(
        &claims(&Uuid::new_v4().to_string(), Some("mfa_challenge")),
        None,
        None,
    );
    assert!(
        v.verify(&t).await.is_err(),
        "kid-less MFA challenge accepted"
    );
}

#[tokio::test]
async fn kidless_webauthn_discoverable_state_token_is_refused() {
    let (_s, v) = verifier().await;
    let t = sign(
        &claims(
            &Uuid::nil().to_string(),
            Some("webauthn_authenticate_discoverable"),
        ),
        None,
        None,
    );
    assert!(v.verify(&t).await.is_err(), "nil-UUID state token accepted");
}

#[tokio::test]
async fn kidless_token_is_refused_even_without_purpose() {
    let (_s, v) = verifier().await;
    let t = sign(
        &claims(&Uuid::new_v4().to_string(), None),
        None,
        Some("at+jwt"),
    );
    assert!(v.verify(&t).await.is_err(), "kid-less token accepted");
}

#[tokio::test]
async fn purpose_claim_is_refused_with_valid_kid_and_at_jwt_typ() {
    let (_s, v) = verifier().await;
    let t = sign(
        &claims(&Uuid::new_v4().to_string(), Some("mfa_challenge")),
        Some(KID),
        Some("at+jwt"),
    );
    assert!(v.verify(&t).await.is_err(), "purpose token accepted");
}

#[tokio::test]
async fn null_purpose_member_is_refused() {
    let (_s, v) = verifier().await;
    let mut c = claims(&Uuid::new_v4().to_string(), None);
    c["purpose"] = Value::Null;
    let t = sign(&c, Some(KID), Some("at+jwt"));
    assert!(v.verify(&t).await.is_err(), "purpose:null token accepted");
}

#[tokio::test]
async fn wrong_typ_values_are_refused() {
    let (_s, v) = verifier().await;
    for typ in [
        "JWT",
        "axiam-mfa-challenge+jwt",
        "axiam-webauthn-state+jwt",
        "logout+jwt",
        "secevent+jwt",
    ] {
        let t = sign(
            &claims(&Uuid::new_v4().to_string(), None),
            Some(KID),
            Some(typ),
        );
        assert!(v.verify(&t).await.is_err(), "typ {typ:?} accepted");
    }
}

#[tokio::test]
async fn at_jwt_typ_in_any_accepted_spelling_and_absent_typ_pass() {
    let (_s, v) = verifier().await;
    for typ in [
        Some("at+jwt"),
        Some("AT+JWT"),
        Some("application/at+jwt"),
        None,
    ] {
        let t = sign(&claims(&Uuid::new_v4().to_string(), None), Some(KID), typ);
        v.verify(&t)
            .await
            .unwrap_or_else(|e| panic!("typ {typ:?} refused: {e:?}"));
    }
}
