//! The `saml` management namespace — CONTRACT.md §29.8's eight required tests.

#![cfg(feature = "rest")]

mod management_support;

use std::sync::{Arc, Mutex};

use axiam_sdk::AxiamError;
use axiam_sdk::management::{PageRequest, models};
use serde_json::{Value, json};
use uuid::Uuid;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

use management_support::{TENANT_ID, logged_in_client, logged_in_client_with_retry, mount};

const SAML: &str = "/api/v1/tenants/22222222-2222-4222-8222-222222222222/saml";

fn sp_body(extra: Value) -> Value {
    let mut body = json!({
        "id": Uuid::new_v4(), "tenant_id": TENANT_ID, "enabled": true,
        "display_name": "Payroll", "entity_id": "https://payroll.example/sp",
        "acs_urls": [{"url": "https://payroll.example/acs", "binding": "http_post",
                      "index": 0, "is_default": true}],
        "slo_url": null, "slo_binding": null, "name_id_format": "persistent",
        "sign_responses": true, "encrypt_assertions": false,
        "sp_signing_cert_pem": null, "sp_encryption_cert_pem": null,
        "want_authn_requests_signed": false, "allow_idp_initiated": false,
        "attribute_mappings": [], "allowed_groups": [],
        "created_at": "2026-10-04T00:00:00Z", "updated_at": "2026-10-04T00:00:00Z",
    });
    for (k, v) in extra.as_object().unwrap() {
        body[k] = v.clone();
    }
    body
}

fn credential_body(status: &str, extra: Value) -> Value {
    let mut body = json!({
        "id": Uuid::new_v4(), "tenant_id": TENANT_ID, "issuer_ca_id": Uuid::new_v4(),
        "certificate_pem": "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
        "serial": "0a1b", "fingerprint": "ab".repeat(32),
        "not_before": "2026-10-04T00:00:00Z", "not_after": "2027-10-04T00:00:00Z",
        "status": status, "created_at": "2026-10-04T00:00:00Z", "retired_at": null,
    });
    for (k, v) in extra.as_object().unwrap() {
        body[k] = v.clone();
    }
    body
}

fn input() -> models::SamlServiceProviderInput {
    models::SamlServiceProviderInput {
        acs_urls: vec![models::AcsEndpoint {
            binding: models::SamlBinding::HttpPost,
            index: 0,
            is_default: Some(true),
            url: "https://payroll.example/acs".into(),
        }],
        allow_idp_initiated: None,
        allowed_groups: None,
        attribute_mappings: None,
        display_name: "Payroll".into(),
        enabled: None,
        encrypt_assertions: None,
        entity_id: "https://payroll.example/sp".into(),
        name_id_format: None,
        sign_responses: None,
        slo_binding: None,
        slo_url: None,
        sp_encryption_cert_pem: None,
        sp_signing_cert_pem: None,
        want_authn_requests_signed: None,
    }
}

async fn capture(
    server: &MockServer,
    verb: &str,
    route: String,
    template: ResponseTemplate,
) -> Arc<Mutex<Vec<(String, Value)>>> {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&seen);
    Mock::given(method(verb))
        .and(path(route))
        .respond_with(move |req: &Request| {
            sink.lock().unwrap().push((
                req.url.query().unwrap_or("").to_string(),
                serde_json::from_slice(&req.body).unwrap_or(Value::Null),
            ));
            template.clone()
        })
        .mount(server)
        .await;
    seen
}

// ── 1. Replacement ──────────────────────────────────────────────────────────

#[tokio::test]
async fn update_service_provider_puts_the_whole_registration() {
    let server = MockServer::start().await;
    let client = logged_in_client(&server).await;
    let id = Uuid::new_v4();
    let seen = capture(
        &server,
        "PUT",
        format!("{SAML}/service-providers/{id}"),
        ResponseTemplate::new(200).set_body_json(sp_body(json!({}))),
    )
    .await;

    // The read-modify-write form: every member of a read carried over.
    let current: models::SamlServiceProvider = serde_json::from_value(sp_body(json!({}))).unwrap();
    let mut body = models::SamlServiceProviderInput::from(&current);
    body.display_name = "Payroll (EU)".into();
    let sp = client
        .saml()
        .update_service_provider(id, &body)
        .await
        .expect("200 decodes to SamlServiceProvider");
    assert_eq!(sp.entity_id, "https://payroll.example/sp");

    let sent = &seen.lock().unwrap()[0].1;
    for member in [
        "acs_urls",
        "allow_idp_initiated",
        "allowed_groups",
        "attribute_mappings",
        "display_name",
        "enabled",
        "encrypt_assertions",
        "entity_id",
        "name_id_format",
        "sign_responses",
        "want_authn_requests_signed",
    ] {
        assert!(sent.get(member).is_some(), "{member} not sent");
    }
    assert_eq!(sent["display_name"], "Payroll (EU)");
    // `display_name`, `entity_id` and `acs_urls` are non-`Option` fields with no
    // `Default`: an input without them does not compile.
}

// ── 2. No signing switch, open decoding ─────────────────────────────────────

#[tokio::test]
async fn sign_assertions_does_not_exist_and_unknown_values_decode() {
    let server = MockServer::start().await;
    let client = logged_in_client(&server).await;
    let id = Uuid::new_v4();
    let mut body = sp_body(json!({"sign_assertions": false, "some_future_member": 1}));
    body["acs_urls"][0]["binding"] = json!("http_artifact");
    mount(
        &server,
        "GET",
        &format!("{SAML}/service-providers/{id}"),
        200,
        &body.to_string(),
    )
    .await;
    let seen = capture(
        &server,
        "PUT",
        format!("{SAML}/service-providers/{id}"),
        ResponseTemplate::new(200).set_body_json(sp_body(json!({}))),
    )
    .await;

    let sp = client
        .saml()
        .get_service_provider(id)
        .await
        .expect("decodes");
    assert_eq!(
        sp.acs_urls[0].binding,
        models::SamlBinding::Unknown("http_artifact".into())
    );
    // An unknown enum value is decoded, but MUST NOT be sent: drop the ACS
    // that carries it before writing back.
    let mut input = models::SamlServiceProviderInput::from(&sp);
    input.acs_urls[0].binding = models::SamlBinding::HttpPost;
    client
        .saml()
        .update_service_provider(id, &input)
        .await
        .expect("update");
    let sent = &seen.lock().unwrap()[0].1;
    assert!(sent.get("sign_assertions").is_none());
    assert!(sent.get("some_future_member").is_none());
}

// ── 3. Draft round trip ─────────────────────────────────────────────────────

#[tokio::test]
async fn parse_sp_metadata_sends_exactly_one_member_and_the_draft_creates() {
    let server = MockServer::start().await;
    let client = logged_in_client(&server).await;
    let draft = json!({
        "service_provider": {
            "display_name": "Imported", "entity_id": "https://imported.example/sp",
            "acs_urls": [{"url": "https://imported.example/acs", "binding": "http_post",
                          "index": 1, "is_default": false}],
            "want_authn_requests_signed": true,
            "sp_signing_cert_pem": "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
        },
        "signing_certificate_fingerprint": "cd".repeat(32),
        "encryption_certificate_fingerprint": null,
        "warnings": ["the metadata's signature was not evaluated"],
    });
    let parsed = capture(
        &server,
        "POST",
        format!("{SAML}/parse-sp-metadata"),
        ResponseTemplate::new(200).set_body_json(draft.clone()),
    )
    .await;
    let created = capture(
        &server,
        "POST",
        format!("{SAML}/service-providers"),
        ResponseTemplate::new(201).set_body_json(sp_body(json!({}))),
    )
    .await;

    let from_url = client
        .saml()
        .parse_sp_metadata(&models::ParseSamlSpMetadata::from_url(
            "https://imported.example/metadata",
        ))
        .await
        .expect("url");
    client
        .saml()
        .parse_sp_metadata(&models::ParseSamlSpMetadata::from_xml(
            "<EntityDescriptor/>",
        ))
        .await
        .expect("xml");

    for both_or_neither in [
        models::ParseSamlSpMetadata {
            metadata_url: Some("https://a".into()),
            metadata_xml: Some("<x/>".into()),
        },
        models::ParseSamlSpMetadata::default(),
    ] {
        let e = client
            .saml()
            .parse_sp_metadata(&both_or_neither)
            .await
            .unwrap_err();
        assert!(e.validation().is_some(), "local ValidationError: {e}");
    }
    {
        let sent = parsed.lock().unwrap();
        assert_eq!(sent.len(), 2, "the refused calls sent nothing");
        assert_eq!(
            sent[0].1,
            json!({"metadata_url": "https://imported.example/metadata"})
        );
        assert_eq!(sent[1].1, json!({"metadata_xml": "<EntityDescriptor/>"}));
    }

    client
        .saml()
        .create_service_provider(&from_url.service_provider)
        .await
        .expect("the draft is accepted unchanged");
    assert_eq!(created.lock().unwrap()[0].1, draft["service_provider"]);
}

// ── 4. Credentials carry no key ─────────────────────────────────────────────

#[tokio::test]
async fn a_credential_has_no_key_member_and_promotion_may_retire_nothing() {
    let server = MockServer::start().await;
    let client = logged_in_client(&server).await;
    let leaked = format!("-----BEGIN PRIVATE KEY-----{}", Uuid::new_v4().simple());
    let id = Uuid::new_v4();
    mount(
        &server,
        "POST",
        &format!("{SAML}/idp-credentials/{id}/retire"),
        200,
        &credential_body("retired", json!({"private_key_pem": leaked})).to_string(),
    )
    .await;
    mount(
        &server,
        "POST",
        &format!("{SAML}/idp-credentials/{id}/promote"),
        200,
        &json!({"active": credential_body("active", json!({})), "retired": null}).to_string(),
    )
    .await;

    let credential = client
        .saml()
        .retire_idp_credential(id)
        .await
        .expect("decodes");
    for rendering in [
        format!("{credential:?}"),
        format!("{credential:#?}"),
        serde_json::to_string(&credential).unwrap(),
    ] {
        assert!(!rendering.contains(&leaked), "{rendering}");
        assert!(!rendering.contains("private_key_pem"));
    }
    let promotion = client
        .saml()
        .promote_idp_credential(id)
        .await
        .expect("decodes");
    assert!(promotion.retired.is_none());
    assert_eq!(
        promotion.active.status,
        models::SamlIdpCredentialStatus::Active
    );
}

// ── 5. Pagination ───────────────────────────────────────────────────────────

#[tokio::test]
async fn service_providers_page_with_search_and_credentials_are_a_plain_list() {
    let server = MockServer::start().await;
    let client = logged_in_client(&server).await;
    let seen = Arc::new(Mutex::new(Vec::<String>::new()));
    let sink = Arc::clone(&seen);
    Mock::given(method("GET"))
        .and(path(format!("{SAML}/service-providers")))
        .respond_with(move |req: &Request| {
            let offset: u64 = req
                .url
                .query_pairs()
                .find(|(k, _)| k == "offset")
                .map(|(_, v)| v.parse().unwrap())
                .unwrap_or(0);
            sink.lock()
                .unwrap()
                .push(req.url.query().unwrap_or("").to_string());
            let items = if offset < 2 {
                vec![sp_body(json!({}))]
            } else {
                vec![]
            };
            ResponseTemplate::new(200).set_body_json(json!({
                "items": items, "total": 2, "offset": offset, "limit": 1,
            }))
        })
        .mount(&server)
        .await;
    mount(
        &server,
        "GET",
        &format!("{SAML}/idp-credentials"),
        200,
        &json!([
            credential_body("next", json!({})),
            credential_body("active", json!({}))
        ])
        .to_string(),
    )
    .await;

    let page = client
        .saml()
        .list_service_providers(PageRequest::first(1).search("payroll"))
        .await
        .expect("page");
    assert_eq!(page.total, 2);
    let all = client
        .saml()
        .list_service_providers_all(PageRequest::first(1).search("payroll"))
        .await
        .expect("walk");
    assert_eq!(all.len(), 2);
    for query in seen.lock().unwrap().iter() {
        assert!(query.contains("search=payroll"), "{query}");
    }
    let credentials: Vec<models::SamlIdpCredential> =
        client.saml().list_idp_credentials().await.expect("list");
    assert_eq!(credentials.len(), 2);
}

// ── 6. No retry ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn none_of_the_seven_writes_is_retried_on_503() {
    let server = MockServer::start().await;
    let client = logged_in_client_with_retry(&server).await;
    let id = Uuid::new_v4();
    let routes = [
        ("POST", format!("{SAML}/service-providers")),
        ("PUT", format!("{SAML}/service-providers/{id}")),
        ("DELETE", format!("{SAML}/service-providers/{id}")),
        ("POST", format!("{SAML}/parse-sp-metadata")),
        ("POST", format!("{SAML}/idp-credentials")),
        ("POST", format!("{SAML}/idp-credentials/{id}/promote")),
        ("POST", format!("{SAML}/idp-credentials/{id}/retire")),
    ];
    let mut hits = Vec::new();
    for (verb, route) in &routes {
        hits.push(capture(&server, verb, route.clone(), ResponseTemplate::new(503)).await);
    }
    let s = client.saml();
    let errors = vec![
        s.create_service_provider(&input()).await.unwrap_err(),
        s.update_service_provider(id, &input()).await.unwrap_err(),
        s.delete_service_provider(id).await.unwrap_err(),
        s.parse_sp_metadata(&models::ParseSamlSpMetadata::from_url("https://m"))
            .await
            .unwrap_err(),
        s.issue_idp_credential(&models::IssueSamlIdpCredential {
            issuer_ca_id: Uuid::new_v4(),
            slot: models::SamlIdpSlot::Next,
            validity_days: None,
        })
        .await
        .unwrap_err(),
        s.promote_idp_credential(id).await.unwrap_err(),
        s.retire_idp_credential(id).await.unwrap_err(),
    ];
    for e in &errors {
        assert!(matches!(e, AxiamError::Network { .. }), "{e}");
    }
    for (h, (verb, route)) in hits.iter().zip(&routes) {
        assert_eq!(h.lock().unwrap().len(), 1, "{verb} {route}");
    }
}

// ── 7. Errors ───────────────────────────────────────────────────────────────

#[tokio::test]
async fn statuses_map_per_section_2() {
    let server = MockServer::start().await;
    let client = logged_in_client(&server).await;
    let id = Uuid::new_v4();
    mount(
        &server,
        "POST",
        &format!("{SAML}/service-providers"),
        409,
        r#"{"error":"conflict","message":"entity_id"}"#,
    )
    .await;
    mount(&server, "PUT", &format!("{SAML}/service-providers/{id}"), 400,
          r#"{"error":"validation_error","message":"entity_id is immutable: register a new service provider"}"#).await;
    mount(
        &server,
        "GET",
        &format!("{SAML}/service-providers/{id}"),
        404,
        r#"{"error":"not_found","message":"no"}"#,
    )
    .await;
    mount(
        &server,
        "POST",
        &format!("{SAML}/idp-credentials/{id}/promote"),
        409,
        r#"{"error":"conflict","message":"not next"}"#,
    )
    .await;
    mount(
        &server,
        "POST",
        &format!("{SAML}/parse-sp-metadata"),
        503,
        r#"{"error":"service_unavailable","message":"saml"}"#,
    )
    .await;

    let s = client.saml();
    assert!(
        s.create_service_provider(&input())
            .await
            .unwrap_err()
            .is_conflict()
    );
    let e = s.update_service_provider(id, &input()).await.unwrap_err();
    assert!(e.validation().unwrap().message.contains("immutable"));
    assert!(s.get_service_provider(id).await.unwrap_err().is_not_found());
    assert!(
        s.promote_idp_credential(id)
            .await
            .unwrap_err()
            .is_conflict()
    );
    let e = s
        .parse_sp_metadata(&models::ParseSamlSpMetadata::from_url("https://m"))
        .await
        .unwrap_err();
    assert!(matches!(e, AxiamError::Network { .. }) && e.validation().is_none());
}

// ── 8. Readiness is read, not cached ────────────────────────────────────────

#[tokio::test]
async fn get_idp_is_never_cached_and_keeps_null_apart_from_absent() {
    let server = MockServer::start().await;
    let client = logged_in_client(&server).await;
    let active = Uuid::new_v4();
    let hits = Arc::new(Mutex::new(0usize));
    let sink = Arc::clone(&hits);
    let body = json!({
        "tenant_id": TENANT_ID, "saml_available": true, "saml_idp_enabled": false,
        "metadata_served": true, "entity_id": "https://iam.example/saml/v2/t",
        "metadata_url": "https://iam.example/saml/v2/t/metadata",
        "sso_url": "https://iam.example/saml/v2/t/sso", "slo_url": "https://iam.example/saml/v2/t/slo",
        "active_credential_id": active, "next_credential_id": null,
    });
    // The configured tenant, in the path: `get_idp` takes no tenant argument.
    Mock::given(method("GET"))
        .and(path(format!("{SAML}/idp")))
        .respond_with(move |_: &Request| {
            *sink.lock().unwrap() += 1;
            ResponseTemplate::new(200).set_body_json(body.clone())
        })
        .mount(&server)
        .await;

    let info = client.saml().get_idp().await.expect("decodes");
    client.saml().get_idp().await.expect("again");
    assert_eq!(*hits.lock().unwrap(), 2, "two calls, two requests");
    assert_eq!(info.active_credential_id, Some(Some(active)));
    assert_eq!(info.next_credential_id, Some(None), "null, not absent");
    assert!(info.saml_available && info.metadata_served && !info.saml_idp_enabled);

    let without: models::SamlIdpInfo = serde_json::from_value(json!({
        "tenant_id": TENANT_ID, "saml_available": true, "saml_idp_enabled": false,
        "metadata_served": false, "entity_id": "e", "metadata_url": "m",
        "sso_url": "s", "slo_url": "l",
    }))
    .unwrap();
    assert_eq!(without.next_credential_id, None, "absent stays absent");
}
