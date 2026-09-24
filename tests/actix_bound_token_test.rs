//! CONTRACT.md §10.1 rule 9 at the `AxiamUser` guard (contract 1.51).
//!
//! The §6.1 device login mints a token bound to the device's certificate. A
//! resource server guarding a route with `AxiamUser` must refuse that token
//! from anyone who cannot present the certificate — and, until contract 1.51,
//! did not: the guard's verifier ignored `cnf`, so a bound token lifted off a
//! device was a bearer token here.
//!
//! The negative half runs through `TestRequest`. The positive half needs a
//! certificate on the *connection*, which `TestRequest` cannot carry, so it
//! runs a real `HttpServer` whose `on_connect` records a [`PeerCertificate`]
//! — in production from the TLS stack's verified peer certificate, here from a
//! fixed DER value, since what is under test is the extractor's use of it.

#![cfg(feature = "actix")]

mod management_support;

use actix_web::{App, FromRequest, HttpResponse, HttpServer, test::TestRequest, web};
use axiam_sdk::middleware::{AxiamUser, PeerCertificate};
use axiam_sdk::token::{JwksVerifier, certificate_thumbprint_s256};
use serde_json::json;
use uuid::Uuid;
use wiremock::MockServer;

use management_support::{TENANT_ID, mount_jwks, sign_claims};

/// The DER bytes the "TLS layer" of the test server reports for every
/// connection. Not a real certificate — the extractor only ever thumbprints it.
const PEER_DER: &[u8] = b"a device certificate, as DER";

fn token(cnf: Option<serde_json::Value>) -> String {
    let mut claims = json!({
        "sub": Uuid::new_v4().to_string(),
        "tenant_id": TENANT_ID,
        "org_id": management_support::ORG_ID,
        "iss": "axiam-test",
        "iat": 0,
        "exp": 9_999_999_999i64,
        "jti": Uuid::new_v4().to_string(),
    });
    if let Some(cnf) = cnf {
        claims["cnf"] = cnf;
    }
    sign_claims(&claims)
}

async fn verifier(jwks: &MockServer) -> JwksVerifier {
    mount_jwks(jwks).await;
    let base = url::Url::parse(&jwks.uri()).unwrap();
    JwksVerifier::new(reqwest::Client::new(), &base)
        .unwrap()
        .expect_tenant_id(Uuid::parse_str(TENANT_ID).unwrap())
}

async fn extract(verifier: &web::Data<JwksVerifier>, bearer: &str) -> bool {
    let req = TestRequest::default()
        .insert_header(("Authorization", format!("Bearer {bearer}")))
        .app_data(verifier.clone())
        .to_http_request();
    AxiamUser::extract(&req).await.is_ok()
}

/// No certificate on the connection: a bound token is refused, and the I4
/// twin — an unbound token — is accepted exactly as before.
#[actix_web::test]
async fn without_connection_evidence_a_bound_token_is_refused() {
    let jwks = MockServer::start().await;
    let v = web::Data::new(verifier(&jwks).await);
    let thumbprint = certificate_thumbprint_s256(PEER_DER);

    assert!(
        !extract(&v, &token(Some(json!({ "x5t#S256": thumbprint })))).await,
        "a device token without its certificate is not a bearer token"
    );
    assert!(
        extract(&v, &token(None)).await,
        "an unbound token is unaffected"
    );
}

async fn whoami(user: AxiamUser) -> HttpResponse {
    HttpResponse::Ok().body(user.user_id.to_string())
}

/// A certificate recorded for the connection is the evidence: the token bound
/// to it is accepted, a token bound to another certificate is refused, and an
/// unbound token is accepted with a certificate present.
#[actix_web::test]
async fn a_recorded_peer_certificate_is_the_evidence() {
    let jwks = MockServer::start().await;
    let v = web::Data::new(verifier(&jwks).await);

    let server = HttpServer::new(move || {
        App::new()
            .app_data(v.clone())
            .route("/whoami", web::get().to(whoami))
    })
    .workers(1)
    .on_connect(|_conn, ext| {
        ext.insert(PeerCertificate::from_der(PEER_DER));
    })
    .bind(("127.0.0.1", 0))
    .unwrap();
    let addr = server.addrs()[0];
    let running = server.run();
    let handle = running.handle();
    actix_web::rt::spawn(running);

    let http = reqwest::Client::new();
    let status = |bearer: String| {
        let http = http.clone();
        async move {
            http.get(format!("http://{addr}/whoami"))
                .bearer_auth(bearer)
                .send()
                .await
                .unwrap()
                .status()
                .as_u16()
        }
    };

    let own = certificate_thumbprint_s256(PEER_DER);
    let other = certificate_thumbprint_s256(b"another device's certificate");
    assert_eq!(status(token(Some(json!({ "x5t#S256": own })))).await, 200);
    assert_eq!(status(token(Some(json!({ "x5t#S256": other })))).await, 401);
    assert_eq!(status(token(None)).await, 200);
    // No DPoP proof is ever verified by this extractor, so a `jkt` binding is
    // refused rather than read as a bearer token.
    assert_eq!(
        status(token(Some(
            json!({ "jkt": "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I" })
        )))
        .await,
        401
    );

    handle.stop(false).await;
}
