//! CONTRACT.md §27.13 (contract 1.51) — the model changes of the dogfooding
//! remediation, as a decoder and an encoder see them.
//!
//! The regenerated types pick up every new field for free. What they do not
//! pick up by themselves is the behaviour §27.13 asks for at the edges: a
//! `cert_type` this SDK does not know must not fail `certificates.list`, a
//! `subject_alt_names` entry must reach the wire in the shape the server
//! parses, and an `inherit` a server does not send must read as `true`.

#![cfg(feature = "rest")]

mod management_support;

use axiam_sdk::management::PageRequest;
use axiam_sdk::management::models;
use serde_json::{Value, json};
use uuid::Uuid;

use management_support::{EXAMPLE_ID, TENANT_ID, logged_in_client, mount};

fn example_id() -> Uuid {
    Uuid::parse_str(EXAMPLE_ID).expect("fixture id")
}

fn certificate(cert_type: &str) -> String {
    format!(
        r#"{{"cert_type": "{cert_type}", "created_at": "2026-09-24T00:00:00Z",
             "fingerprint": "ab", "id": "{}", "issuer_ca_id": "{EXAMPLE_ID}",
             "key_algorithm": "Ed25519", "metadata": {{}},
             "not_after": "2027-09-24T00:00:00Z", "not_before": "2026-09-24T00:00:00Z",
             "public_cert_pem": "pem", "status": "Active", "subject": "device-001",
             "tenant_id": "{TENANT_ID}"}}"#,
        Uuid::new_v4()
    )
}

// ---------------------------------------------------------------------------
// S-7 rule 2 — `CertificateType` decodes openly
// ---------------------------------------------------------------------------

/// One certificate of a type this SDK has never heard of must not take the
/// page down with it.
///
/// §27.13 S-7 rule 2 names the failure: a closed enum fails the **whole**
/// `certificates.list` on one server certificate. Re-vendoring taught the enum
/// `Server`; this is the rule for the value after that.
#[tokio::test]
async fn certificates_list_survives_a_type_this_sdk_does_not_know() {
    let server = wiremock::MockServer::start().await;
    let client = logged_in_client(&server).await;

    mount(
        &server,
        "GET",
        "/api/v1/certificates",
        200,
        &format!(
            r#"{{"items": [{}, {}, {}], "total": 3, "offset": 0, "limit": 50}}"#,
            certificate("Device"),
            certificate("Server"),
            certificate("Gateway")
        ),
    )
    .await;

    let page = client
        .certificates()
        .list(PageRequest::first(50))
        .await
        .expect("an unknown cert_type must not fail certificates.list");

    let types: Vec<_> = page.items.iter().map(|c| c.cert_type.clone()).collect();
    assert_eq!(
        types,
        vec![
            models::CertificateType::Device,
            models::CertificateType::Server,
            models::CertificateType::Unknown("Gateway".into()),
        ],
        "the unknown value is kept verbatim, not collapsed into a known one"
    );
}

/// The raw string survives a read-modify-write: decoding and re-encoding a
/// record must not rewrite a field this SDK did not understand.
#[test]
fn an_unknown_certificate_type_round_trips_verbatim() {
    let decoded: models::CertificateType =
        serde_json::from_value(json!("Gateway")).expect("open enum decodes");
    assert_eq!(serde_json::to_value(&decoded).unwrap(), json!("Gateway"));

    // The I4 twin: the known values are the ones the server spells.
    for (value, known) in [
        ("User", models::CertificateType::User),
        ("Service", models::CertificateType::Service),
        ("Device", models::CertificateType::Device),
        ("Server", models::CertificateType::Server),
    ] {
        assert_eq!(
            serde_json::from_value::<models::CertificateType>(json!(value)).unwrap(),
            known
        );
        assert_eq!(serde_json::to_value(&known).unwrap(), json!(value));
    }
}

// ---------------------------------------------------------------------------
// S-7 rule 1 — `subject_alt_names`
// ---------------------------------------------------------------------------

/// `SubjectAltName` is externally tagged: `{"dns": …}` or `{"ip": …}`.
///
/// The generator used to emit this `oneOf` as a struct with no fields, which
/// compiles, serializes as `{}` and is refused by the server. This pins the
/// shape on the wire — through a real `generate` call, not only through
/// `serde_json::to_value`, so the request path cannot re-shape it either.
#[tokio::test]
async fn a_server_certificate_sends_its_names_externally_tagged() {
    let server = wiremock::MockServer::start().await;
    let client = logged_in_client(&server).await;
    mount(
        &server,
        "POST",
        "/api/v1/certificates",
        201,
        &certificate("Server").replacen('{', r#"{"private_key_pem": "k", "#, 1),
    )
    .await;

    client
        .certificates()
        .generate(&models::CreateCertificateRequest {
            cert_type: models::CertificateType::Server,
            issuer_ca_id: example_id(),
            key_algorithm: models::KeyAlgorithm::Ed25519,
            metadata: None,
            subject: "api.lakeside.internal".into(),
            subject_alt_names: Some(vec![
                models::SubjectAltName::Dns("api.lakeside.internal".into()),
                models::SubjectAltName::Ip("10.0.0.5".into()),
            ]),
            validity_days: 90,
        })
        .await
        .expect("certificates.generate");

    let body = last_body(&server, "/api/v1/certificates").await;
    assert_eq!(
        body["subject_alt_names"],
        json!([{ "dns": "api.lakeside.internal" }, { "ip": "10.0.0.5" }])
    );
}

/// The I4 twin: a request with no names sends **no** `subject_alt_names` key —
/// not `null`, not `[]` (§27.13 S-7 rule 1: "SHOULD omit the key") — on both
/// leaf paths, so a pre-1.51 body is byte-for-byte what it was.
#[test]
fn a_leaf_request_without_names_omits_the_key() {
    let generate = serde_json::to_value(models::CreateCertificateRequest {
        cert_type: models::CertificateType::Device,
        issuer_ca_id: example_id(),
        key_algorithm: models::KeyAlgorithm::Ed25519,
        metadata: None,
        subject: "device-001".into(),
        subject_alt_names: None,
        validity_days: 90,
    })
    .unwrap();
    let sign = serde_json::to_value(models::SignCertificateCsrRequest {
        cert_type: models::CertificateType::Device,
        csr_pem: "csr".into(),
        issuer_ca_id: example_id(),
        metadata: None,
        subject_alt_names: None,
        validity_days: 90,
    })
    .unwrap();
    for (label, body) in [("generate", generate), ("sign_csr", sign)] {
        assert!(body.get("subject_alt_names").is_none(), "{label}: {body}");
    }
}

/// And a name decodes back from the shape the server documents.
#[test]
fn a_subject_alt_name_decodes_from_the_documented_shape() {
    let names: Vec<models::SubjectAltName> =
        serde_json::from_value(json!([{ "dns": "a.example" }, { "ip": "fd00::1" }])).unwrap();
    assert_eq!(
        names,
        vec![
            models::SubjectAltName::Dns("a.example".into()),
            models::SubjectAltName::Ip("fd00::1".into()),
        ]
    );
}

// ---------------------------------------------------------------------------
// S-10 — `inherit`
// ---------------------------------------------------------------------------

/// Rule 1: the key is sent only when it is `false`. `None` — the default — and
/// an inheritable assignment's body stay a pre-1.51 body.
#[test]
fn an_assign_request_carries_inherit_only_when_stated() {
    let base = models::AssignRoleToUserRequest {
        user_id: example_id(),
        inherit: None,
        resource_id: Some(example_id()),
        tenant_scope: None,
    };
    let omitted = serde_json::to_value(&base).unwrap();
    assert_eq!(
        key_set(&omitted),
        vec!["resource_id", "user_id"],
        "no inherit key when it is not stated"
    );

    let stopped = serde_json::to_value(models::AssignRoleToUserRequest {
        inherit: Some(false),
        ..base
    })
    .unwrap();
    assert_eq!(stopped["inherit"], json!(false));
}

/// Rule 3, role side. The field is required there, but a server older than
/// contract 1.51 does not send it — and failing the listing over it would take
/// the manifest's planning read down with it. Absent reads as `true`; a stated
/// `false` is kept.
#[tokio::test]
async fn a_role_side_listing_reads_an_absent_inherit_as_true() {
    let server = wiremock::MockServer::start().await;
    let client = logged_in_client(&server).await;
    let user = |extra: &str| {
        format!(
            r#"{{{extra}"user": {{"created_at": "2026-09-24T00:00:00Z", "email": "a@example.com",
                "email_verified": true, "failed_login_attempts": 0, "id": "{}",
                "is_locked": false, "metadata": {{}}, "mfa_enabled": false, "status": "Active",
                "tenant_id": "{TENANT_ID}", "updated_at": "2026-09-24T00:00:00Z",
                "username": "a"}}}}"#,
            Uuid::new_v4()
        )
    };
    mount(
        &server,
        "GET",
        &format!("/api/v1/roles/{EXAMPLE_ID}/users"),
        200,
        &format!("[{}, {}]", user(""), user(r#""inherit": false, "#)),
    )
    .await;

    let rows = client
        .roles()
        .list_users(example_id())
        .await
        .expect("a listing without inherit decodes");
    assert!(rows[0].inherit, "absent must read as true, never false");
    assert!(!rows[1].inherit, "a stated false is kept");
}

/// Rule 3, subject side: `RoleAssignment.inherit` is optional, and
/// [`inherits`](models::RoleAssignment::inherits) is the one place the default
/// is decided.
#[tokio::test]
async fn a_subject_side_assignment_reads_absent_as_inheriting() {
    let server = wiremock::MockServer::start().await;
    let client = logged_in_client(&server).await;
    let role = |extra: &str| {
        format!(
            r#"{{{extra}"role": {{"created_at": "2026-09-24T00:00:00Z", "description": "d",
                "id": "{}", "is_global": false, "name": "r", "tenant_id": "{TENANT_ID}",
                "updated_at": "2026-09-24T00:00:00Z"}}}}"#,
            Uuid::new_v4()
        )
    };
    mount(
        &server,
        "GET",
        &format!("/api/v1/users/{EXAMPLE_ID}/roles"),
        200,
        &format!(
            "[{}, {}, {}]",
            role(""),
            role(r#""inherit": true, "#),
            role(r#""inherit": false, "#)
        ),
    )
    .await;

    let rows = client
        .users()
        .list_roles(example_id())
        .await
        .expect("users.list_roles");
    assert_eq!(rows[0].inherit, None, "the wire value is not invented");
    let read: Vec<bool> = rows.iter().map(models::RoleAssignment::inherits).collect();
    assert_eq!(read, vec![true, true, false]);
}

// ---------------------------------------------------------------------------

fn key_set(value: &Value) -> Vec<&str> {
    let mut keys: Vec<&str> = value
        .as_object()
        .expect("an object")
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    keys
}

async fn last_body(server: &wiremock::MockServer, route: &str) -> Value {
    let requests = server.received_requests().await.unwrap_or_default();
    let request = requests
        .iter()
        .rev()
        .find(|r| r.url.path() == route)
        .unwrap_or_else(|| panic!("no request reached {route}"));
    serde_json::from_slice(&request.body).expect("a JSON body")
}
