//! Contract 1.61 — the rows §34.5 assigns every SDK that ships `certificates`:
//!
//! * §27.11 rule 5 — `Certificate.user_id`, and the optional request member on
//!   `certificates.generate` and `certificates.sign_csr` (the one required test).
//!
//! (`SsfStreamInput.expected_updated_at` and the three meanings of
//! `events_requested` are §32.8 test 1's and live in `ssf_management_test.rs`;
//! `CibaPendingList` is a console surface no operation returns — §33.3 rule 16 —
//! and this SDK models neither it nor `CibaApprovalPage`.)

#![cfg(feature = "rest")]

mod management_support;

use axiam_sdk::management::models;
use serde_json::{Value, json};
use uuid::Uuid;
use wiremock::MockServer;

use management_support::{EXAMPLE_ID, TENANT_ID, logged_in_client, mount};

fn example_id() -> Uuid {
    Uuid::parse_str(EXAMPLE_ID).expect("fixture id")
}

/// A `Certificate` body; `user_id` is `Some(json)` to carry the member (a UUID
/// string or `null`) and `None` to leave it out altogether.
fn certificate_body(user_id: Option<Value>) -> Value {
    let mut body = json!({
        "cert_type": "User", "created_at": "2026-10-13T00:00:00Z",
        "fingerprint": "ab:cd", "id": Uuid::new_v4(), "issuer_ca_id": EXAMPLE_ID,
        "key_algorithm": "Ed25519", "metadata": {},
        "not_after": "2027-10-13T00:00:00Z", "not_before": "2026-10-13T00:00:00Z",
        "public_cert_pem": "pem", "status": "Active", "subject": "ada",
        "tenant_id": TENANT_ID,
    });
    if let Some(v) = user_id {
        body["user_id"] = v;
    }
    body
}

/// A `GeneratedCertificate` body: the certificate plus its one-time key.
fn generated_body(user_id: Option<Value>) -> String {
    let mut body = certificate_body(user_id);
    body["private_key_pem"] = json!("k");
    body.to_string()
}

async fn last_body(server: &MockServer, route: &str) -> Value {
    let requests = server.received_requests().await.unwrap_or_default();
    let request = requests
        .iter()
        .rev()
        .find(|r| r.url.path() == route)
        .unwrap_or_else(|| panic!("no request reached {route}"));
    serde_json::from_slice(&request.body).expect("a JSON body")
}

fn generate(user_id: Option<&str>) -> models::CreateCertificateRequest {
    models::CreateCertificateRequest {
        cert_type: models::CertificateType::User,
        issuer_ca_id: example_id(),
        key_algorithm: models::KeyAlgorithm::Ed25519,
        metadata: None,
        subject: "ada".into(),
        subject_alt_names: None,
        user_id: user_id.map(str::to_string),
        validity_days: 90,
    }
}

fn sign(user_id: Option<&str>) -> models::SignCertificateCsrRequest {
    models::SignCertificateCsrRequest {
        cert_type: models::CertificateType::User,
        csr_pem: "csr".into(),
        issuer_ca_id: example_id(),
        metadata: None,
        subject_alt_names: None,
        user_id: user_id.map(str::to_string),
        validity_days: 90,
    }
}

/// Required test, first half: both requests send the `user_id` the caller set
/// exactly as given, and no `user_id` key — not `null` — when none was set.
#[tokio::test]
async fn generate_and_sign_csr_send_user_id_as_given_and_omit_the_key_when_unset() {
    let server = MockServer::start().await;
    let client = logged_in_client(&server).await;
    mount(
        &server,
        "POST",
        "/api/v1/certificates",
        201,
        &generated_body(None),
    )
    .await;
    mount(
        &server,
        "POST",
        "/api/v1/certificates/sign-csr",
        201,
        &certificate_body(None).to_string(),
    )
    .await;

    let account = Uuid::new_v4().to_string();
    let account = account.as_str();

    client
        .certificates()
        .generate(&generate(Some(account)))
        .await
        .expect("generate");
    let sent = last_body(&server, "/api/v1/certificates").await;
    assert_eq!(sent["user_id"], json!(account));

    client
        .certificates()
        .generate(&generate(None))
        .await
        .expect("generate");
    let sent = last_body(&server, "/api/v1/certificates").await;
    assert!(
        sent.get("user_id").is_none(),
        "unset is absent, never null: {sent}"
    );

    client
        .certificates()
        .sign_csr(&sign(Some(account)))
        .await
        .expect("sign_csr");
    let sent = last_body(&server, "/api/v1/certificates/sign-csr").await;
    assert_eq!(sent["user_id"], json!(account));

    client
        .certificates()
        .sign_csr(&sign(None))
        .await
        .expect("sign_csr");
    let sent = last_body(&server, "/api/v1/certificates/sign-csr").await;
    assert!(
        sent.get("user_id").is_none(),
        "unset is absent, never null: {sent}"
    );
}

/// Required test, second half: a body carrying a UUID, one carrying `null` and
/// one lacking the member each decode, and the last two give "no account named".
#[test]
fn a_certificate_decodes_a_uuid_a_null_and_an_absent_user_id() {
    let account = Uuid::new_v4();

    let named: models::Certificate =
        serde_json::from_value(certificate_body(Some(json!(account)))).unwrap();
    assert_eq!(named.user_id, Some(account));

    let null: models::Certificate =
        serde_json::from_value(certificate_body(Some(Value::Null))).unwrap();
    assert_eq!(null.user_id, None);

    let absent: models::Certificate = serde_json::from_value(certificate_body(None)).unwrap();
    assert_eq!(absent.user_id, None);

    // Never synthesised: a `metadata.user_id` is free-form metadata and does not
    // become the field.
    let mut body = certificate_body(None);
    body["metadata"] = json!({ "user_id": account });
    let metadata_only: models::Certificate = serde_json::from_value(body).unwrap();
    assert_eq!(metadata_only.user_id, None);
}

/// `certificates.generate` answers a `GeneratedCertificate` (through its wire
/// twin) and `get` a `Certificate`; the member reaches both, in the three
/// shapes, with no second request.
#[tokio::test]
async fn user_id_reaches_a_generated_certificate_and_a_get() {
    let server = MockServer::start().await;
    let client = logged_in_client(&server).await;
    let account = Uuid::new_v4();
    mount(
        &server,
        "POST",
        "/api/v1/certificates",
        201,
        &generated_body(Some(json!(account))),
    )
    .await;
    let id = Uuid::new_v4();
    mount(
        &server,
        "GET",
        &format!("/api/v1/certificates/{id}"),
        200,
        &certificate_body(Some(json!(account))).to_string(),
    )
    .await;

    let generated = client
        .certificates()
        .generate(&generate(Some(&account.to_string())))
        .await
        .unwrap();
    assert_eq!(generated.user_id, Some(account));

    let got = client.certificates().get(id).await.unwrap();
    assert_eq!(got.user_id, Some(account));
    let requests = server.received_requests().await.unwrap();
    assert_eq!(
        requests
            .iter()
            .filter(|r| r.url.path().contains(&id.to_string()))
            .count(),
        1,
        "a get costs one request"
    );
}

/// Contract 1.62, §27.11 rule 5 (item (i)): the request `user_id` is an untyped
/// string. A value that is not a UUID is representable, reaches the server
/// byte for byte, and the server's `400` is what the caller sees; the SDK
/// judges nothing. (The *response* member stays `Option<Uuid>`, above.)
#[tokio::test]
async fn a_malformed_request_user_id_reaches_the_server_and_its_400_is_surfaced() {
    let server = MockServer::start().await;
    let client = logged_in_client(&server).await;
    let refusal = json!({
        "error": "validation_error",
        "message": "user_id: not a UUID",
    })
    .to_string();
    mount(&server, "POST", "/api/v1/certificates", 400, &refusal).await;
    mount(
        &server,
        "POST",
        "/api/v1/certificates/sign-csr",
        400,
        &refusal,
    )
    .await;

    let malformed = "not-a-uuid ";

    let err = client
        .certificates()
        .generate(&generate(Some(malformed)))
        .await
        .expect_err("the server refuses it");
    let validation = err
        .validation()
        .expect("a ValidationError, not a local one");
    assert_eq!(validation.status, 400);
    assert!(validation.message.contains("not a UUID"), "{validation:?}");
    assert_eq!(
        last_body(&server, "/api/v1/certificates").await["user_id"],
        json!(malformed),
        "sent exactly as given — untrimmed, unparsed"
    );

    let err = client
        .certificates()
        .sign_csr(&sign(Some(malformed)))
        .await
        .expect_err("the server refuses it");
    assert_eq!(err.validation().expect("a ValidationError").status, 400);
    assert_eq!(
        last_body(&server, "/api/v1/certificates/sign-csr").await["user_id"],
        json!(malformed)
    );
}
