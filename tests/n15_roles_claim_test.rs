//! N15 (contract 1.68, CONTRACT.md §11.2 rule 11): `AxiamUser::roles` is read
//! ONLY from the token's `roles` claim and is empty (so `require_role` fails
//! closed) when the claim is absent. It is never derived from `scope`.

#![cfg(feature = "actix")]

use actix_web::FromRequest;
use actix_web::test::TestRequest;
use actix_web::web;
use axiam_sdk::middleware::AxiamUser;
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
const KID: &str = "n15-kid";
const TENANT: &str = "3f6b1c8e-0000-4000-8000-0000000000a1";

fn token(scope: &str, roles: Option<Value>) -> String {
    let mut c = json!({
        "sub": Uuid::new_v4().to_string(),
        "tenant_id": TENANT,
        "org_id": Uuid::new_v4().to_string(),
        "iss": "https://iam.example.com",
        "iat": 0,
        "exp": 9_999_999_999i64,
        "scope": scope,
    });
    if let Some(r) = roles {
        c["roles"] = r;
    }
    let mut h = Header::new(Algorithm::EdDSA);
    // Access tokens carry `typ: at+jwt` (CONTRACT.md §10.1 rule 10).
    h.typ = Some("at+jwt".to_string());
    h.kid = Some(KID.into());
    let mut der = PKCS8_PREFIX.to_vec();
    der.extend_from_slice(&SEED);
    jsonwebtoken::encode(&h, &c, &EncodingKey::from_ed_der(&der)).unwrap()
}

async fn extract(token: String) -> AxiamUser {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/oauth2/jwks"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "keys": [{"kty":"OKP","crv":"Ed25519","kid":KID,"alg":"EdDSA","x":PUBLIC_X}]
        })))
        .mount(&server)
        .await;
    let verifier = JwksVerifier::new(
        reqwest::Client::new(),
        &url::Url::parse(&server.uri()).unwrap(),
    )
    .unwrap()
    .expect_tenant_id(TENANT.parse().unwrap());
    let req = TestRequest::default()
        .app_data(web::Data::new(verifier))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_http_request();
    let mut payload = actix_web::dev::Payload::None;
    AxiamUser::from_request(&req, &mut payload)
        .await
        .expect("token verifies")
}

#[tokio::test]
async fn scope_is_never_a_source_of_roles() {
    let user = extract(token("openid admin", None)).await;
    assert!(
        user.roles.is_empty(),
        "scope `admin` surfaced as the role: {:?}",
        user.roles
    );
}

#[tokio::test]
async fn roles_come_from_the_roles_claim() {
    let user = extract(token("openid", Some(json!(["admin"])))).await;
    assert_eq!(user.roles, vec!["admin".to_string()]);
}
