//! The `directory` management namespace — CONTRACT.md §30.8's six required
//! tests. The bind secret is generated at run time: a literal would be a
//! credential in the repository and would let a redaction test pass by
//! coincidence.

#![cfg(feature = "rest")]

mod management_support;

use std::sync::{Arc, Mutex};

use axiam_sdk::management::models;
use axiam_sdk::{AxiamError, Sensitive};
use serde_json::{Value, json};
use uuid::Uuid;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

use management_support::{TENANT_ID, logged_in_client, logged_in_client_with_retry, mount};

const DIRECTORY: &str = "/api/v1/tenants/22222222-2222-4222-8222-222222222222/directory";

fn secret() -> String {
    format!("bind-{}", Uuid::new_v4().simple())
}

fn assert_no_fragment(haystack: &str, secret: &str) {
    // The failure message names neither the fragment nor the haystack: a
    // failing redaction test must not itself print the secret it caught.
    for i in 0..=secret.len().saturating_sub(8) {
        assert!(
            !haystack.contains(&secret[i..i + 8]),
            "an 8-character fragment of the secret (offset {i}) appears in a rendering"
        );
    }
}

fn config_body() -> Value {
    json!({
        "id": Uuid::new_v4(), "tenant_id": TENANT_ID, "enabled": true, "kind": "active_directory",
        "url": "ldaps://dc.corp.example", "start_tls": false, "bind_dn": "cn=svc,dc=corp",
        "base_dn": "dc=corp", "user_filter": "(sAMAccountName={username})",
        "user_attribute_map": {"username": "sAMAccountName", "email": "mail",
                               "display_name": "displayName", "external_id": "objectGUID"},
        "group_base_dn": null, "group_filter": null, "group_member_attribute": "member",
        "group_nesting_depth": 5, "group_mappings": [], "sync_interval_secs": 3600,
        "jit_provisioning": false, "trust_anchors_pem": [],
        "created_at": "2026-10-04T00:00:00Z", "updated_at": "2026-10-04T00:00:00Z",
    })
}

fn set_body(bind_secret: Option<String>) -> models::SetDirectoryConfig {
    models::SetDirectoryConfig {
        base_dn: "dc=corp".into(),
        bind_dn: "cn=svc,dc=corp".into(),
        bind_secret: bind_secret.map(Sensitive::new),
        enabled: true,
        group_base_dn: None,
        group_filter: None,
        group_mappings: None,
        group_member_attribute: None,
        group_nesting_depth: None,
        jit_provisioning: None,
        kind: models::DirectoryKind::ActiveDirectory,
        start_tls: false,
        sync_interval_secs: None,
        trust_anchors_pem: None,
        url: "ldaps://dc.corp.example".into(),
        user_attribute_map: None,
        user_filter: "(sAMAccountName={username})".into(),
    }
}

/// Record the bodies sent to `verb DIRECTORY{suffix}` and answer `template`.
async fn capture(
    server: &MockServer,
    verb: &str,
    suffix: &str,
    template: ResponseTemplate,
) -> Arc<Mutex<Vec<Value>>> {
    let bodies = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&bodies);
    Mock::given(method(verb))
        .and(path(format!("{DIRECTORY}{suffix}")))
        .respond_with(move |req: &Request| {
            sink.lock()
                .unwrap()
                .push(serde_json::from_slice(&req.body).unwrap_or(Value::Null));
            template.clone()
        })
        .mount(server)
        .await;
    bodies
}

// ── 1. Redaction ────────────────────────────────────────────────────────────

#[tokio::test]
async fn the_bind_secret_reaches_the_wire_and_no_rendering() {
    let server = MockServer::start().await;
    let client = logged_in_client(&server).await;
    let s = secret();

    let set = set_body(Some(s.clone()));
    let update = models::UpdateDirectoryConfig {
        bind_secret: Some(Sensitive::new(s.clone())),
        ..Default::default()
    };
    for rendering in [
        format!("{set:?}"),
        format!("{set:#?}"),
        format!("{update:?}"),
        format!("{update:#?}"),
    ] {
        assert_no_fragment(&rendering, &s);
    }

    let bodies = capture(
        &server,
        "PUT",
        "",
        ResponseTemplate::new(400).set_body_json(json!({
            "error": "validation_error", "message": "url: plaintext LDAP is refused"
        })),
    )
    .await;
    let err = client.directory().set(&set).await.unwrap_err();
    assert_no_fragment(&format!("{err} {err:?}"), &s);
    assert_eq!(
        bodies.lock().unwrap()[0]["bind_secret"],
        s,
        "but it is on the wire"
    );
}

// ── 2. No secret on the response ────────────────────────────────────────────

#[tokio::test]
async fn a_bind_secret_in_a_response_is_dropped() {
    let server = MockServer::start().await;
    let client = logged_in_client(&server).await;
    let leaked = secret();
    let mut body = config_body();
    body["bind_secret"] = json!(leaked);
    mount(&server, "GET", DIRECTORY, 200, &body.to_string()).await;

    let config = client.directory().get().await.expect("decodes");
    assert_no_fragment(&format!("{config:?} {config:#?}"), &leaked);
    assert_no_fragment(&serde_json::to_string(&config).unwrap(), &leaked);
    // ... and there is no accessor: `DirectoryConfig` declares no such field,
    // which this test would fail to compile against if it did.
    let models::DirectoryConfig { url, .. } = config;
    assert_eq!(url, "ldaps://dc.corp.example");
}

// ── 3. Sparse update ────────────────────────────────────────────────────────

fn keys(v: &Value) -> Vec<String> {
    let mut k: Vec<String> = v.as_object().unwrap().keys().cloned().collect();
    k.sort();
    k
}

#[tokio::test]
async fn update_sends_exactly_the_members_it_was_given() {
    let server = MockServer::start().await;
    let client = logged_in_client(&server).await;
    let bodies = capture(
        &server,
        "PATCH",
        "",
        ResponseTemplate::new(200).set_body_json(config_body()),
    )
    .await;
    let s = secret();

    client
        .directory()
        .update(&models::UpdateDirectoryConfig {
            enabled: Some(false),
            ..Default::default()
        })
        .await
        .expect("disable");
    client
        .directory()
        .update(&models::UpdateDirectoryConfig {
            url: Some("ldaps://dc2.corp.example".into()),
            bind_secret: Some(Sensitive::new(s.clone())),
            ..Default::default()
        })
        .await
        .expect("move with the secret");
    client
        .directory()
        .update(&models::UpdateDirectoryConfig {
            group_filter: Some(None),
            ..Default::default()
        })
        .await
        .expect("clear the filter");

    let sent = bodies.lock().unwrap();
    assert_eq!(sent[0], json!({"enabled": false}));
    assert_eq!(keys(&sent[1]), ["bind_secret", "url"]);
    assert_eq!(sent[1]["bind_secret"], s);
    assert_eq!(sent[2], json!({"group_filter": null}));
}

// ── 4. Replacement ──────────────────────────────────────────────────────────

#[tokio::test]
async fn set_sends_every_required_member_and_decodes_201_and_200() {
    let server = MockServer::start().await;
    let client = logged_in_client(&server).await;
    // `SetDirectoryConfig` cannot be built without its seven required members:
    // they are non-`Option` fields with no `Default`, so the compiler refuses a
    // literal that omits one. What is left to check is the wire.
    for status in [201u16, 200] {
        let bodies = capture(
            &server,
            "PUT",
            "",
            ResponseTemplate::new(status).set_body_json(config_body()),
        )
        .await;
        let config = client.directory().set(&set_body(None)).await.expect("set");
        assert!(config.enabled);
        let sent = bodies.lock().unwrap().pop().unwrap();
        for required in [
            "enabled",
            "kind",
            "url",
            "start_tls",
            "bind_dn",
            "base_dn",
            "user_filter",
        ] {
            assert!(sent.get(required).is_some(), "{required} missing");
        }
        assert!(
            sent.get("bind_secret").is_none(),
            "absent keeps the stored secret"
        );
        server.reset().await;
        management_support::mount_jwks(&server).await;
    }
}

// ── 5. No retry ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn no_write_is_retried_on_503() {
    let server = MockServer::start().await;
    let client = logged_in_client_with_retry(&server).await;
    let put = capture(&server, "PUT", "", ResponseTemplate::new(503)).await;
    let patch = capture(&server, "PATCH", "", ResponseTemplate::new(503)).await;
    let delete = capture(&server, "DELETE", "", ResponseTemplate::new(503)).await;
    let link = capture(&server, "POST", "/links", ResponseTemplate::new(503)).await;

    let d = client.directory();
    let errors = [
        d.set(&set_body(Some(secret()))).await.unwrap_err(),
        d.update(&models::UpdateDirectoryConfig::default())
            .await
            .unwrap_err(),
        d.delete().await.unwrap_err(),
        d.link_account(&models::LinkDirectoryAccount {
            user_id: Uuid::new_v4(),
        })
        .await
        .unwrap_err(),
    ];
    for e in &errors {
        assert!(matches!(e, AxiamError::Network { .. }), "{e}");
    }
    for (name, hits) in [
        ("set", put),
        ("update", patch),
        ("delete", delete),
        ("link", link),
    ] {
        assert_eq!(hits.lock().unwrap().len(), 1, "{name}: exactly one request");
    }
}

// ── 6. Errors and link_account ──────────────────────────────────────────────

#[tokio::test]
async fn errors_map_per_section_2_and_link_account_sends_only_the_user_id() {
    let server = MockServer::start().await;
    let client = logged_in_client(&server).await;
    mount(
        &server,
        "PUT",
        DIRECTORY,
        400,
        r#"{"error":"validation_error","message":"url: changing the connection requires entering the bind secret again"}"#,
    )
    .await;
    mount(
        &server,
        "PATCH",
        DIRECTORY,
        409,
        r#"{"error":"conflict","message":"opaque_mode"}"#,
    )
    .await;
    mount(
        &server,
        "GET",
        DIRECTORY,
        404,
        r#"{"error":"not_found","message":"none"}"#,
    )
    .await;

    let e = client.directory().set(&set_body(None)).await.unwrap_err();
    let v = e.validation().expect("ValidationError");
    assert!(v.message.contains("bind secret again"));
    let e = client
        .directory()
        .update(&models::UpdateDirectoryConfig {
            enabled: Some(true),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert!(e.is_conflict(), "{e}");
    let e = client.directory().get().await.unwrap_err();
    assert!(e.is_not_found(), "{e}");

    let user = Uuid::new_v4();
    let bodies = capture(
        &server,
        "POST",
        "/links",
        ResponseTemplate::new(200).set_body_json(json!({
            "user_id": user, "directory_external_id": "3f2a-objectguid",
            "webauthn_credentials_deleted": 2, "certificates_revoked": 1,
            "was_already_linked": false,
        })),
    )
    .await;
    let result = client
        .directory()
        .link_account(&models::LinkDirectoryAccount { user_id: user })
        .await
        .expect("link");
    assert_eq!(bodies.lock().unwrap()[0], json!({"user_id": user}));
    assert_eq!(result.user_id, user);
    assert_eq!(result.directory_external_id, "3f2a-objectguid");
    assert_eq!(result.webauthn_credentials_deleted, 2);
    assert_eq!(result.certificates_revoked, 1);
    assert!(!result.was_already_linked);
}

#[tokio::test]
async fn sync_status_decodes_an_unknown_result_and_the_first_run_nulls() {
    let server = MockServer::start().await;
    let client = logged_in_client(&server).await;
    mount(
        &server,
        "GET",
        &format!("{DIRECTORY}/sync-status"),
        200,
        r#"{"last_result":"something_new","last_attempt_at":null,"last_full_run_at":null,
            "full_required":true,"has_watermark":false}"#,
    )
    .await;
    let status = client.directory().get_sync_status().await.expect("decodes");
    assert_eq!(status.last_result.as_deref(), Some("something_new"));
    assert!(status.full_required && !status.has_watermark);
}

#[test]
fn a_read_converts_into_the_replacement_body_without_a_secret() {
    let config: models::DirectoryConfig = serde_json::from_value(config_body()).unwrap();
    let body = models::SetDirectoryConfig::from(&config);
    assert!(body.bind_secret.is_none(), "absent keeps the stored secret");
    assert_eq!(body.url, config.url);
    assert_eq!(body.group_nesting_depth, Some(5));
    assert_eq!(body.sync_interval_secs, Some(3600));
}
