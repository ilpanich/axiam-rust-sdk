//! The `scim_targets` management namespace — CONTRACT.md §31.8's six
//! required tests. The credential is generated at run time.

#![cfg(feature = "rest")]

mod management_support;

use std::sync::{Arc, Mutex};

use axiam_sdk::management::{PageRequest, models};
use axiam_sdk::{AxiamError, Sensitive};
use serde_json::{Value, json};
use uuid::Uuid;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

use management_support::{TENANT_ID, logged_in_client, logged_in_client_with_retry, mount};

const TARGETS: &str = "/api/v1/scim-targets";

fn credential() -> String {
    format!("scim-{}", Uuid::new_v4().simple())
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

fn target_body(extra: Value) -> Value {
    let mut body = json!({
        "id": Uuid::new_v4(), "tenant_id": TENANT_ID, "name": "Downstream",
        "base_url": "https://idp.example/scim/v2", "enabled": true,
        "auth": {"type": "bearer"}, "scope": {"type": "all_users"},
        "push_groups": false, "user_name_from": "username", "deprovision": "deactivate",
        "created_at": "2026-10-05T00:00:00Z", "updated_at": "2026-10-05T00:00:00Z",
        "state": {"last_success_at": null, "last_failure_at": null,
                  "last_failure_reason": null, "consecutive_failures": 0,
                  "dead_lettered_total": 0, "last_reconciled_at": null},
    });
    for (k, v) in extra.as_object().unwrap() {
        body[k] = v.clone();
    }
    body
}

fn input(credential: Option<String>) -> models::ScimTargetInput {
    models::ScimTargetInput {
        auth: models::ScimTargetAuth::Bearer {},
        base_url: "https://idp.example/scim/v2".into(),
        credential: credential.map(Sensitive::new),
        deprovision: None,
        enabled: None,
        expected_updated_at: None,
        name: "Downstream".into(),
        push_groups: None,
        scope: models::ScimTargetScope::AllUsers {},
        user_name_from: None,
    }
}

async fn capture(
    server: &MockServer,
    verb: &str,
    route: String,
    template: ResponseTemplate,
) -> Arc<Mutex<Vec<(String, Vec<u8>)>>> {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&seen);
    Mock::given(method(verb))
        .and(path(route))
        .respond_with(move |req: &Request| {
            sink.lock()
                .unwrap()
                .push((req.url.query().unwrap_or("").to_string(), req.body.clone()));
            template.clone()
        })
        .mount(server)
        .await;
    seen
}

fn json_of(raw: &[u8]) -> Value {
    serde_json::from_slice(raw).unwrap()
}

// ── 1. Redaction ────────────────────────────────────────────────────────────

#[tokio::test]
async fn the_credential_is_on_the_wire_and_in_no_rendering() {
    let server = MockServer::start().await;
    let client = logged_in_client(&server).await;
    let c = credential();
    let body = input(Some(c.clone()));
    assert_no_fragment(&format!("{body:?} {body:#?}"), &c);

    let seen = capture(
        &server,
        "POST",
        TARGETS.into(),
        ResponseTemplate::new(400)
            .set_body_json(json!({"error": "validation_error", "message": "base_url: refused"})),
    )
    .await;
    let e = client.scim_targets().create(&body).await.unwrap_err();
    assert_no_fragment(&format!("{e} {e:?}"), &c);
    assert_eq!(json_of(&seen.lock().unwrap()[0].1)["credential"], c);
}

// ── 2. No credential on the response ────────────────────────────────────────

#[tokio::test]
async fn a_credential_in_a_response_is_dropped() {
    let server = MockServer::start().await;
    let client = logged_in_client(&server).await;
    let leaked = credential();
    let id = Uuid::new_v4();
    mount(
        &server,
        "GET",
        &format!("{TARGETS}/{id}"),
        200,
        &target_body(json!({"credential": leaked, "credential_set": true})).to_string(),
    )
    .await;
    let t = client.scim_targets().get(id).await.expect("decodes");
    assert_no_fragment(
        &format!("{t:?} {t:#?} {}", serde_json::to_string(&t).unwrap()),
        &leaked,
    );
    // `ScimTargetResponse` declares no credential field: naming one here would
    // not compile.
    let models::ScimTargetResponse { name, .. } = t;
    assert_eq!(name, "Downstream");
}

// ── 3. Replacement and the omitted credential ───────────────────────────────

#[tokio::test]
async fn update_without_a_credential_sends_no_key_and_the_variants_keep_their_shape() {
    let server = MockServer::start().await;
    let client = logged_in_client(&server).await;
    let id = Uuid::new_v4();
    let seen = capture(
        &server,
        "PUT",
        format!("{TARGETS}/{id}"),
        ResponseTemplate::new(200).set_body_json(target_body(json!({}))),
    )
    .await;
    let c = credential();
    client
        .scim_targets()
        .update(id, &input(None))
        .await
        .expect("keep");
    client
        .scim_targets()
        .update(id, &input(Some(c.clone())))
        .await
        .expect("replace");
    // Contract 1.60: `expected_updated_at` is absent when unset, and sent as
    // the very string given -- fractional seconds and offset included, never
    // re-formatted -- when set.
    let read_at = "2026-10-05T00:00:00.123456789+02:00";
    client
        .scim_targets()
        .update(
            id,
            &models::ScimTargetInput {
                expected_updated_at: Some(read_at.into()),
                ..input(None)
            },
        )
        .await
        .expect("conditional");
    let sent = seen.lock().unwrap();
    assert!(
        json_of(&sent[0].1).get("credential").is_none(),
        "no credential key"
    );
    assert_eq!(json_of(&sent[1].1)["credential"], c);
    assert!(
        json_of(&sent[0].1).get("expected_updated_at").is_none(),
        "unset is not sent"
    );
    assert_eq!(json_of(&sent[2].1)["expected_updated_at"], read_at);
    // `name`, `base_url`, `auth` and `scope` are non-`Option` fields with no
    // `Default`: an input without them does not compile.

    let shapes = [
        (
            serde_json::to_value(models::ScimTargetAuth::Bearer {}).unwrap(),
            json!({"type": "bearer"}),
        ),
        (
            serde_json::to_value(models::ScimTargetAuth::Oauth2ClientCredentials {
                client_id: "axiam".into(),
                scope: Some("scim".into()),
                token_url: "https://idp.example/token".into(),
            })
            .unwrap(),
            json!({"type": "oauth2_client_credentials", "client_id": "axiam",
                   "scope": "scim", "token_url": "https://idp.example/token"}),
        ),
        (
            serde_json::to_value(models::ScimTargetScope::AllUsers {}).unwrap(),
            json!({"type": "all_users"}),
        ),
        (
            serde_json::to_value(models::ScimTargetScope::Groups {
                group_ids: vec![Uuid::nil()],
            })
            .unwrap(),
            json!({"type": "groups", "group_ids": [Uuid::nil()]}),
        ),
    ];
    for (got, want) in shapes {
        assert_eq!(got, want);
    }
}

#[tokio::test]
async fn an_overtaken_conditional_update_surfaces_409_and_is_sent_once() {
    // §31.3 rule 4: the target changed since `expected_updated_at`; the SDK
    // surfaces the conflict and does not retry it (§31.7).
    let server = MockServer::start().await;
    let client = logged_in_client_with_retry(&server).await;
    let id = Uuid::new_v4();
    let seen = capture(
        &server,
        "PUT",
        format!("{TARGETS}/{id}"),
        ResponseTemplate::new(409).set_body_json(
            json!({"error": "conflict", "message": "the SCIM target changed since it was read"}),
        ),
    )
    .await;
    let read: models::ScimTargetResponse = serde_json::from_value(target_body(json!({}))).unwrap();
    let body = models::ScimTargetInput::from(&read);
    let e = client.scim_targets().update(id, &body).await.unwrap_err();
    assert!(e.is_conflict(), "{e}");
    let sent = seen.lock().unwrap();
    assert_eq!(sent.len(), 1, "a 409 is never retried");
    assert_eq!(
        json_of(&sent[0].1)["expected_updated_at"],
        "2026-10-05T00:00:00Z"
    );
}

// ── 4. Open decoding and pagination ─────────────────────────────────────────

#[tokio::test]
async fn unknown_values_decode_and_the_pager_carries_search() {
    let server = MockServer::start().await;
    let client = logged_in_client(&server).await;
    let odd = target_body(json!({
        "auth": {"type": "mtls", "certificate_id": Uuid::new_v4()},
        "deprovision": "archive", "user_name_from": "employee_number", "state": null,
    }));
    let failing = target_body(json!({"state": {
        "last_success_at": null, "last_failure_at": "2026-10-05T01:00:00Z",
        "last_failure_reason": "a reason this SDK has never seen",
        "consecutive_failures": 3, "dead_lettered_total": 1, "last_reconciled_at": null}}));
    let seen = Arc::new(Mutex::new(Vec::<String>::new()));
    let sink = Arc::clone(&seen);
    Mock::given(method("GET"))
        .and(path(TARGETS))
        .respond_with(move |req: &Request| {
            let offset: u64 = req
                .url
                .query_pairs()
                .find(|(k, _)| k == "offset")
                .map(|(_, v)| v.parse().unwrap())
                .unwrap_or(0);
            sink.lock()
                .unwrap()
                .push(req.url.query().unwrap_or("").into());
            let items = match offset {
                0 => vec![odd.clone()],
                1 => vec![failing.clone()],
                _ => vec![],
            };
            ResponseTemplate::new(200)
                .set_body_json(json!({"items": items, "total": 2, "offset": offset, "limit": 1}))
        })
        .mount(&server)
        .await;

    let page = client
        .scim_targets()
        .list(PageRequest::first(1).search("downstream"))
        .await
        .expect("page");
    assert_eq!(page.total, 2);
    assert_eq!(page.items[0].auth, models::ScimTargetAuth::Unknown);
    assert_eq!(
        page.items[0].deprovision,
        models::DeprovisionPolicy::Unknown("archive".into())
    );
    assert!(page.items[0].state.is_none());
    let all = client
        .scim_targets()
        .list_all(PageRequest::first(1).search("downstream"))
        .await
        .expect("walk");
    assert_eq!(
        all[1]
            .state
            .as_ref()
            .unwrap()
            .last_failure_reason
            .as_deref(),
        Some("a reason this SDK has never seen")
    );
    for q in seen.lock().unwrap().iter() {
        assert!(q.contains("search=downstream"), "{q}");
    }
    // An unknown variant decodes but is never sent.
    assert!(serde_json::to_value(models::ScimTargetAuth::Unknown).is_err());
}

// ── 5. No retry ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn no_write_is_retried_on_503() {
    let server = MockServer::start().await;
    let client = logged_in_client_with_retry(&server).await;
    let id = Uuid::new_v4();
    let create = capture(&server, "POST", TARGETS.into(), ResponseTemplate::new(503)).await;
    let update = capture(
        &server,
        "PUT",
        format!("{TARGETS}/{id}"),
        ResponseTemplate::new(503),
    )
    .await;
    let delete = capture(
        &server,
        "DELETE",
        format!("{TARGETS}/{id}"),
        ResponseTemplate::new(503),
    )
    .await;
    let reconcile = capture(
        &server,
        "POST",
        format!("{TARGETS}/{id}/reconcile"),
        ResponseTemplate::new(503),
    )
    .await;
    let t = client.scim_targets();
    let errors = [
        t.create(&input(Some(credential()))).await.unwrap_err(),
        t.update(id, &input(None)).await.unwrap_err(),
        t.delete(id).await.unwrap_err(),
        t.reconcile(id).await.unwrap_err(),
    ];
    for e in &errors {
        assert!(matches!(e, AxiamError::Network { .. }), "{e}");
    }
    for h in [create, update, delete, reconcile] {
        assert_eq!(h.lock().unwrap().len(), 1);
    }
}

// ── 6. Errors and reconcile ─────────────────────────────────────────────────

#[tokio::test]
async fn statuses_map_and_reconcile_is_a_bodyless_202() {
    let server = MockServer::start().await;
    let client = logged_in_client(&server).await;
    let id = Uuid::new_v4();
    let other = Uuid::new_v4();
    mount(
        &server,
        "POST",
        TARGETS,
        400,
        r#"{"error":"validation_error","message":"credential: required on create"}"#,
    )
    .await;
    mount(
        &server,
        "PUT",
        &format!("{TARGETS}/{id}"),
        409,
        r#"{"error":"conflict","message":"the SCIM target changed since it was read"}"#,
    )
    .await;
    mount(
        &server,
        "POST",
        &format!("{TARGETS}/{other}/reconcile"),
        409,
        r#"{"error":"conflict","message":"a run holds the claim"}"#,
    )
    .await;
    mount(
        &server,
        "GET",
        &format!("{TARGETS}/{id}"),
        404,
        r#"{"error":"not_found","message":"no"}"#,
    )
    .await;
    mount(
        &server,
        "DELETE",
        &format!("{TARGETS}/{id}"),
        401,
        r#"{"error":"unauthorized","message":"human only"}"#,
    )
    .await;
    mount(
        &server,
        "POST",
        "/api/v1/auth/refresh",
        401,
        r#"{"error":"unauthorized"}"#,
    )
    .await;
    let reconcile = capture(
        &server,
        "POST",
        format!("{TARGETS}/{id}/reconcile"),
        ResponseTemplate::new(202).set_body_json(json!({"target_id": id, "status": "started"})),
    )
    .await;

    let t = client.scim_targets();
    let e = t.create(&input(None)).await.unwrap_err();
    assert!(e.validation().unwrap().message.contains("credential"));
    assert!(t.update(id, &input(None)).await.unwrap_err().is_conflict());
    assert!(t.reconcile(other).await.unwrap_err().is_conflict());
    assert!(t.get(id).await.unwrap_err().is_not_found());
    assert!(matches!(
        t.delete(id).await.unwrap_err(),
        AxiamError::Auth { .. }
    ));

    let accepted = t.reconcile(id).await.expect("202 is success");
    assert_eq!(accepted.target_id, id);
    assert_eq!(accepted.status, "started");
    assert!(
        reconcile.lock().unwrap()[0].1.is_empty(),
        "reconcile sends no body"
    );
}

#[test]
fn a_read_converts_into_the_replacement_body_without_a_credential() {
    let t: models::ScimTargetResponse = serde_json::from_value(target_body(json!({}))).unwrap();
    let body = models::ScimTargetInput::from(&t);
    assert!(
        body.credential.is_none(),
        "absent keeps the stored credential"
    );
    assert_eq!(body.base_url, t.base_url);
    assert_eq!(body.enabled, Some(true));
    assert_eq!(
        body.expected_updated_at.as_deref(),
        Some(t.updated_at.as_str()),
        "the read-modify-write form sends the version it read (§31.3 rule 4)"
    );
}
