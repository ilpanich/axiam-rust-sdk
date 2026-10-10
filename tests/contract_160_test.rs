//! Contract 1.60 — the rows §34.4 assigns every SDK that are not the SSF
//! receiver's (those live in `ssf_receiver_test.rs`) or §31's (in
//! `scim_targets_test.rs`):
//!
//! * §27.15 note 1 — `notification_rules`' `window_minutes`, passed through and
//!   never clamped (the one required test);
//! * §27.15 notes 6 – 8 — the `federation` configuration's
//!   `allow_sha1_signatures` and `idp_metadata_signing_cert_pem`, and the
//!   `update_config` null rule with §27.4 rule 5's exact key-set test;
//! * §12.1 — the `scope` of an `oidc_refresh` response is the token's;
//! * §21.5 — the four revocation and introspection discovery members decode
//!   as optional.
//!
//! Every secret is generated at run time.

#![cfg(feature = "rest")]

mod management_support;

#[path = "oidc_support/mod.rs"]
mod oidc_support;

use std::sync::{Arc, Mutex};

use axiam_sdk::Sensitive;
use axiam_sdk::management::models;
use axiam_sdk::oidc::{OidcConfiguration, OidcRefreshParams};
use serde_json::{Value, json};
use uuid::Uuid;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

use management_support::{TENANT_ID, logged_in_client};

/// Mount `verb route` answering `template`, and collect every request body.
async fn capture(
    server: &MockServer,
    verb: &str,
    route: String,
    template: ResponseTemplate,
) -> Arc<Mutex<Vec<Value>>> {
    let bodies = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&bodies);
    Mock::given(method(verb))
        .and(path(route))
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

fn keys(v: &Value) -> Vec<String> {
    let mut k: Vec<String> = v.as_object().unwrap().keys().cloned().collect();
    k.sort();
    k
}

// ── §27.15 note 1: `window_minutes` ─────────────────────────────────────────

fn rule_body(window_minutes: i64) -> Value {
    json!({
        "id": Uuid::new_v4(), "tenant_id": TENANT_ID, "name": "Lockouts",
        "description": "", "enabled": true, "events": ["account_locked"],
        "recipient_emails": ["secops@example.test"],
        "created_at": "2026-10-10T00:00:00Z", "updated_at": "2026-10-10T00:00:00Z",
        "window_minutes": window_minutes,
    })
}

fn rule(window_minutes: Option<i32>) -> models::CreateNotificationRuleRequest {
    models::CreateNotificationRuleRequest {
        description: String::new(),
        events: vec![models::NotificationEventType::AccountLocked],
        name: "Lockouts".into(),
        recipient_emails: vec!["secops@example.test".into()],
        window_minutes,
    }
}

#[tokio::test]
async fn window_minutes_is_sent_as_given_omitted_when_unset_and_decoded() {
    let server = MockServer::start().await;
    let client = logged_in_client(&server).await;
    let sent = capture(
        &server,
        "POST",
        "/api/v1/notification-rules".into(),
        ResponseTemplate::new(201).set_body_json(rule_body(45)),
    )
    .await;

    let created = client
        .notification_rules()
        .create(&rule(Some(45)))
        .await
        .expect("create");
    assert_eq!(created.window_minutes, 45, "the response's value decodes");
    // Outside 1 … 1440 the server answers 400; the SDK does not clamp first.
    for out_of_range in [0, 1441] {
        client
            .notification_rules()
            .create(&rule(Some(out_of_range)))
            .await
            .expect("the mock accepts it");
    }
    client
        .notification_rules()
        .create(&rule(None))
        .await
        .expect("create without");

    let sent = sent.lock().unwrap();
    assert_eq!(sent[0]["window_minutes"], 45);
    assert_eq!(sent[1]["window_minutes"], 0, "never clamped up");
    assert_eq!(sent[2]["window_minutes"], 1441, "never clamped down");
    assert!(
        sent[3].get("window_minutes").is_none(),
        "an unset window is not sent: {}",
        sent[3]
    );
}

#[tokio::test]
async fn a_sparse_rule_update_carries_window_minutes_only_when_set() {
    let server = MockServer::start().await;
    let client = logged_in_client(&server).await;
    let id = Uuid::new_v4();
    let sent = capture(
        &server,
        "PUT",
        format!("/api/v1/notification-rules/{id}"),
        ResponseTemplate::new(200).set_body_json(rule_body(15)),
    )
    .await;
    let rules = client.notification_rules();
    rules
        .update(
            id,
            &models::UpdateNotificationRuleRequest {
                window_minutes: Some(1440),
                ..Default::default()
            },
        )
        .await
        .expect("update");
    rules
        .update(
            id,
            &models::UpdateNotificationRuleRequest {
                enabled: Some(false),
                ..Default::default()
            },
        )
        .await
        .expect("update");
    let sent = sent.lock().unwrap();
    assert_eq!(sent[0], json!({"window_minutes": 1440}));
    assert_eq!(sent[1], json!({"enabled": false}));
}

// ── §27.15 notes 6 – 8: the federation configuration ────────────────────────

fn federation_body(extra: Value) -> Value {
    let mut body = json!({
        "id": Uuid::new_v4(), "tenant_id": TENANT_ID, "provider": "Corporate IdP",
        "protocol": "Saml", "client_id": "axiam-sp", "attribute_map": {},
        "enabled": true, "provider_kind": "generic_saml",
        "allow_tenant_inheritance": false, "scopes": [], "effective_scopes": [],
        "allowed_issuer_tenants": [], "allowed_algorithms": ["RS256"],
        "mints_client_secret": false, "pkce_required": false, "has_bundled_mark": false,
        "token_exchange": {"enabled": false, "accepted_audiences": [],
                           "max_token_age_secs": 300, "scope_map": {},
                           "subject_mapping": "by_email"},
        "created_at": "2026-10-10T00:00:00Z", "updated_at": "2026-10-10T00:00:00Z",
    });
    for (k, v) in extra.as_object().unwrap() {
        body[k] = v.clone();
    }
    body
}

/// A PEM-shaped placeholder, made at run time (no certificate literal).
fn pem() -> String {
    format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
        Uuid::new_v4().simple()
    )
}

fn saml_config() -> models::CreateFederationConfigRequest {
    models::CreateFederationConfigRequest {
        allow_sha1_signatures: None,
        allow_tenant_inheritance: None,
        allowed_algorithms: None,
        allowed_issuer_tenants: None,
        apple_key_id: None,
        apple_team_id: None,
        attribute_map: None,
        authorization_endpoint: None,
        button_icon: None,
        client_id: "axiam-sp".into(),
        client_secret: Sensitive::new(format!("fed-{}", Uuid::new_v4().simple())),
        idp_metadata_signing_cert_pem: None,
        idp_signing_cert_pem: None,
        metadata_url: Some("https://idp.example.test/metadata".into()),
        protocol: "Saml".into(),
        provider: "Corporate IdP".into(),
        provider_kind: None,
        provider_slug: None,
        require_pkce: None,
        scopes: None,
        token_endpoint: None,
        token_exchange: None,
        userinfo_endpoint: None,
    }
}

#[tokio::test]
async fn the_two_new_federation_members_are_sent_only_when_set() {
    let server = MockServer::start().await;
    let client = logged_in_client(&server).await;
    let sent = capture(
        &server,
        "POST",
        "/api/v1/federation-configs".into(),
        ResponseTemplate::new(201).set_body_json(federation_body(json!({}))),
    )
    .await;
    let cert = pem();
    client
        .federation()
        .create_config(&saml_config())
        .await
        .expect("create");
    client
        .federation()
        .create_config(&models::CreateFederationConfigRequest {
            allow_sha1_signatures: Some(true),
            idp_metadata_signing_cert_pem: Some(cert.clone()),
            ..saml_config()
        })
        .await
        .expect("create with both");
    let sent = sent.lock().unwrap();
    for member in ["allow_sha1_signatures", "idp_metadata_signing_cert_pem"] {
        assert!(sent[0].get(member).is_none(), "{member} unset is not sent");
    }
    assert_eq!(sent[1]["allow_sha1_signatures"], true);
    assert_eq!(sent[1]["idp_metadata_signing_cert_pem"], cert);
}

#[test]
fn a_response_without_allow_sha1_signatures_reads_false() {
    // A server before 1.0.0 sends neither member.
    let old: models::FederationConfigResponse =
        serde_json::from_value(federation_body(json!({}))).expect("decodes");
    assert!(!old.allow_sha1_signatures);
    assert_eq!(old.idp_metadata_signing_cert_pem, None);

    let cert = pem();
    let new: models::FederationConfigResponse = serde_json::from_value(federation_body(json!({
        "allow_sha1_signatures": true, "idp_metadata_signing_cert_pem": cert,
    })))
    .expect("decodes");
    assert!(new.allow_sha1_signatures);
    assert_eq!(
        new.idp_metadata_signing_cert_pem.as_deref(),
        Some(cert.as_str())
    );

    let unset: models::FederationConfigResponse = serde_json::from_value(federation_body(
        json!({"allow_sha1_signatures": false, "idp_metadata_signing_cert_pem": null}),
    ))
    .expect("decodes");
    assert_eq!(unset.idp_metadata_signing_cert_pem, None, "null when unset");
}

/// The ten members of `UpdateFederationConfigRequest` an explicit `null`
/// clears (§27.15 note 8), each set to `Some(None)` on an otherwise empty body.
fn cleared(member: &str) -> models::UpdateFederationConfigRequest {
    let mut body = models::UpdateFederationConfigRequest::default();
    let slot = match member {
        "metadata_url" => &mut body.metadata_url,
        "idp_signing_cert_pem" => &mut body.idp_signing_cert_pem,
        "idp_metadata_signing_cert_pem" => &mut body.idp_metadata_signing_cert_pem,
        "provider_slug" => &mut body.provider_slug,
        "authorization_endpoint" => &mut body.authorization_endpoint,
        "token_endpoint" => &mut body.token_endpoint,
        "userinfo_endpoint" => &mut body.userinfo_endpoint,
        "apple_team_id" => &mut body.apple_team_id,
        "apple_key_id" => &mut body.apple_key_id,
        "button_icon" => &mut body.button_icon,
        other => panic!("{other} is not one of the ten"),
    };
    *slot = Some(None);
    body
}

const CLEARABLE: [&str; 10] = [
    "metadata_url",
    "idp_signing_cert_pem",
    "idp_metadata_signing_cert_pem",
    "provider_slug",
    "authorization_endpoint",
    "token_endpoint",
    "userinfo_endpoint",
    "apple_team_id",
    "apple_key_id",
    "button_icon",
];

#[tokio::test]
async fn update_config_sends_null_only_to_clear_and_omits_what_is_unset() {
    let server = MockServer::start().await;
    let client = logged_in_client(&server).await;
    let id = Uuid::new_v4();
    let sent = capture(
        &server,
        "PUT",
        format!("/api/v1/federation-configs/{id}"),
        ResponseTemplate::new(200).set_body_json(federation_body(json!({}))),
    )
    .await;
    let federation = client.federation();

    // §27.4 rule 5's exact key-set test: one cleared member is the whole body.
    federation
        .update_config(id, &cleared("idp_metadata_signing_cert_pem"))
        .await
        .expect("clear");
    // Unset is not `null`: an empty body leaves every member as stored.
    federation
        .update_config(id, &models::UpdateFederationConfigRequest::default())
        .await
        .expect("nothing");
    // Set is the value, and the other nine stay off the wire.
    let cert = pem();
    federation
        .update_config(
            id,
            &models::UpdateFederationConfigRequest {
                idp_metadata_signing_cert_pem: Some(Some(cert.clone())),
                allow_sha1_signatures: Some(false),
                ..Default::default()
            },
        )
        .await
        .expect("replace");
    for member in CLEARABLE {
        federation
            .update_config(id, &cleared(member))
            .await
            .expect("clear each");
    }

    let sent = sent.lock().unwrap();
    assert_eq!(sent[0], json!({"idp_metadata_signing_cert_pem": null}));
    assert_eq!(keys(&sent[0]), ["idp_metadata_signing_cert_pem"]);
    assert_eq!(sent[1], json!({}));
    assert_eq!(
        sent[2],
        json!({"idp_metadata_signing_cert_pem": cert, "allow_sha1_signatures": false})
    );
    for (i, member) in CLEARABLE.iter().enumerate() {
        let mut expected = serde_json::Map::new();
        expected.insert((*member).to_string(), Value::Null);
        assert_eq!(
            sent[3 + i],
            Value::Object(expected),
            "{member}: null clears"
        );
    }
}

#[test]
fn the_clearable_members_are_double_options_and_the_others_are_not() {
    // `client_id` cannot be cleared (the server reads its `null` as absent):
    // a single `Option`, so `Some(None)` does not type-check for it.
    let body = models::UpdateFederationConfigRequest {
        client_id: Some("axiam-sp".into()),
        provider_slug: Some(Some("corp".into())),
        ..Default::default()
    };
    assert_eq!(body.provider_slug, Some(Some("corp".to_string())));
    let rendered = format!("{body:?}");
    assert!(rendered.contains("corp"), "{rendered}");
}

// ── §12.1: a refresh may narrow `scope` ─────────────────────────────────────

#[tokio::test]
async fn the_scope_of_a_refresh_response_is_the_tokens_scope() {
    let server = MockServer::start().await;
    let answers = Arc::new(Mutex::new(vec![
        oidc_support::token_response(json!({"scope": "profile"})),
        oidc_support::token_response(json!({})),
    ]));
    Mock::given(method("POST"))
        .and(path("/oauth2/token"))
        .respond_with(move |_: &Request| {
            ResponseTemplate::new(200).set_body_json(answers.lock().unwrap().remove(0))
        })
        .mount(&server)
        .await;
    let client = oidc_support::build_client(&server.uri(), true);
    let configuration: OidcConfiguration =
        serde_json::from_value(oidc_support::discovery_document(&server.uri())).unwrap();
    let refresh = |scope: Option<&str>| OidcRefreshParams {
        refresh_token: Sensitive::new(format!("rt-{}", Uuid::new_v4().simple())),
        scope: scope.map(str::to_owned),
        tenant_id: None,
        configuration: Some(configuration.clone()),
    };

    // The registration was narrowed since the grant: asked for three, the
    // server grants one, and the token set says one.
    let narrowed = client
        .oidc_refresh(refresh(Some("openid profile email")))
        .await
        .expect("refresh");
    assert_eq!(narrowed.scope.as_deref(), Some("profile"));
    assert!(
        narrowed.id_token.is_none(),
        "no ID token once openid is gone"
    );

    // A response that states no scope is not filled in from the request.
    let unstated = client
        .oidc_refresh(refresh(Some("openid profile email")))
        .await
        .expect("refresh");
    assert_eq!(unstated.scope, None);
}

// ── §21.5: the four contract 1.60 discovery members ─────────────────────────

#[test]
fn the_four_revocation_and_introspection_members_decode_as_optional() {
    let base = "https://iam.example.com";
    let absent: OidcConfiguration =
        serde_json::from_value(oidc_support::discovery_document(base)).expect("decodes");
    assert_eq!(absent.revocation_endpoint_auth_methods_supported, None);
    assert_eq!(absent.introspection_endpoint_auth_methods_supported, None);
    assert_eq!(
        absent.revocation_endpoint_auth_signing_alg_values_supported,
        None
    );
    assert_eq!(
        absent.introspection_endpoint_auth_signing_alg_values_supported,
        None
    );

    let mut doc = oidc_support::discovery_document(base);
    let algs = json!(["PS256", "ES256", "EdDSA"]);
    let map = doc.as_object_mut().unwrap();
    map.insert(
        "revocation_endpoint_auth_methods_supported".into(),
        json!(["client_secret_post", "private_key_jwt", "none"]),
    );
    map.insert(
        "introspection_endpoint_auth_methods_supported".into(),
        json!(["client_secret_post", "private_key_jwt"]),
    );
    map.insert(
        "revocation_endpoint_auth_signing_alg_values_supported".into(),
        algs.clone(),
    );
    map.insert(
        "introspection_endpoint_auth_signing_alg_values_supported".into(),
        algs,
    );
    let present: OidcConfiguration = serde_json::from_value(doc).expect("decodes");
    let strings = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    assert_eq!(
        present.revocation_endpoint_auth_methods_supported,
        Some(strings(&["client_secret_post", "private_key_jwt", "none"]))
    );
    assert_eq!(
        present.introspection_endpoint_auth_methods_supported,
        Some(strings(&["client_secret_post", "private_key_jwt"]))
    );
    assert_eq!(
        present.introspection_endpoint_auth_signing_alg_values_supported,
        Some(strings(&["PS256", "ES256", "EdDSA"]))
    );
    // They describe the deployment; nothing a client authenticates with moves.
    assert_eq!(present.token_endpoint, absent.token_endpoint);
}
