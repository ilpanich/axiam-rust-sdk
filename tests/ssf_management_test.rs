//! The `ssf` management namespace — CONTRACT.md §32.8's six management tests.
//! (The receiver helper's eight are in `ssf_receiver_test.rs`.)

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

const STREAMS: &str = "/api/v1/tenants/22222222-2222-4222-8222-222222222222/ssf/streams";
const REVOKED: &str = "https://schemas.openid.net/secevent/caep/event-type/session-revoked";

fn header_value() -> String {
    format!("Bearer {}", Uuid::new_v4().simple())
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

fn stream_body(extra: Value) -> Value {
    let mut body = json!({
        "id": Uuid::new_v4(), "tenant_id": TENANT_ID, "receiver_client_id": "rp-1",
        "audience": "https://rp.example", "description": null, "delivery_method": "push",
        "endpoint_url": "https://rp.example/ssf", "authorization_header_set": true,
        "events_allowed": [REVOKED], "events_requested": [REVOKED], "events_delivered": [REVOKED],
        "subject_format": "iss_sub", "status": "enabled", "status_reason": null,
        "status_actor": "admin", "last_verification_at": null,
        "created_at": "2026-10-04T00:00:00Z", "updated_at": "2026-10-04T00:00:00Z",
        "transmitter_active": true,
    });
    for (k, v) in extra.as_object().unwrap() {
        body[k] = v.clone();
    }
    body
}

fn input(header: Option<String>) -> models::SsfStreamInput {
    models::SsfStreamInput {
        audience: "https://rp.example".into(),
        authorization_header: header.map(Sensitive::new),
        clear_authorization_header: None,
        delivery_method: models::SsfDeliveryMethod::Push,
        description: Some("the RP".into()),
        endpoint_url: Some("https://rp.example/ssf".into()),
        events_allowed: vec![models::SsfEventType::SessionRevoked],
        events_requested: None,
        receiver_client_id: "rp-1".into(),
        status: None,
        status_reason: None,
        subject_format: None,
    }
}

async fn capture(
    server: &MockServer,
    verb: &str,
    route: String,
    template: ResponseTemplate,
) -> Arc<Mutex<Vec<Value>>> {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&seen);
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
    seen
}

// ── 1. Replacement ──────────────────────────────────────────────────────────

#[tokio::test]
async fn update_stream_puts_every_member_it_models() {
    let server = MockServer::start().await;
    let client = logged_in_client(&server).await;
    let id = Uuid::new_v4();
    let seen = capture(
        &server,
        "PUT",
        format!("{STREAMS}/{id}"),
        ResponseTemplate::new(200).set_body_json(stream_body(json!({}))),
    )
    .await;
    let mut body = input(None);
    body.events_requested = Some(vec![models::SsfEventType::SessionRevoked]);
    body.subject_format = Some(models::SsfSubjectFormat::IssSub);
    body.status = Some(models::SsfStreamStatus::Enabled);
    body.status_reason = Some("ok".into());
    body.clear_authorization_header = Some(false);
    let stream = client.ssf().update_stream(id, &body).await.expect("200");
    assert!(stream.transmitter_active);
    let sent = &seen.lock().unwrap()[0];
    for member in [
        "receiver_client_id",
        "audience",
        "delivery_method",
        "events_allowed",
        "description",
        "endpoint_url",
        "events_requested",
        "subject_format",
        "status",
        "status_reason",
        "clear_authorization_header",
    ] {
        assert!(sent.get(member).is_some(), "{member}");
    }
    assert_eq!(sent["events_allowed"], json!([REVOKED]));
    assert!(
        sent.get("authorization_header").is_none(),
        "absent keeps the stored header"
    );
    // The four required members are non-`Option` fields with no `Default`.
}

// ── 2. The header is Sensitive ──────────────────────────────────────────────

#[tokio::test]
async fn the_push_header_is_sent_and_never_rendered_or_decoded() {
    let server = MockServer::start().await;
    let client = logged_in_client(&server).await;
    let h = header_value();
    let body = input(Some(h.clone()));
    assert_no_fragment(&format!("{body:?} {body:#?}"), &h);
    let seen = capture(
        &server,
        "POST",
        STREAMS.into(),
        ResponseTemplate::new(201).set_body_json(stream_body(json!({"authorization_header": h}))),
    )
    .await;
    let created = client.ssf().create_stream(&body).await.expect("201");
    assert_eq!(seen.lock().unwrap()[0]["authorization_header"], h);
    assert_no_fragment(
        &format!("{created:?} {}", serde_json::to_string(&created).unwrap()),
        &h,
    );
    let models::SsfStream {
        authorization_header_set,
        ..
    } = created;
    assert!(authorization_header_set);
}

// ── 3. Open decoding ────────────────────────────────────────────────────────

#[tokio::test]
async fn unknown_values_and_both_transmitter_states_decode() {
    let odd: models::SsfStream = serde_json::from_value(stream_body(json!({
        "status": "quarantined", "delivery_method": "websocket", "subject_format": "opaque",
        "status_actor": "policy",
        "events_allowed": ["https://example.test/event-type/new"],
    })))
    .expect("decodes");
    assert_eq!(
        odd.status,
        models::SsfStreamStatus::Unknown("quarantined".into())
    );
    assert_eq!(
        odd.delivery_method,
        models::SsfDeliveryMethod::Unknown("websocket".into())
    );
    assert_eq!(
        odd.subject_format,
        models::SsfSubjectFormat::Unknown("opaque".into())
    );
    assert_eq!(
        odd.status_actor,
        models::SsfStatusActor::Unknown("policy".into())
    );
    assert_eq!(
        odd.events_allowed[0],
        models::SsfEventType::Unknown("https://example.test/event-type/new".into())
    );

    let inactive: models::SsfStream = serde_json::from_value(stream_body(json!({
        "transmitter_active": false,
        "transmitter_inactive_reason": "per-tenant issuers are off in a multi-tenant deployment",
    })))
    .unwrap();
    assert!(!inactive.transmitter_active);
    assert!(inactive.transmitter_inactive_reason.is_some());
    let active: models::SsfStream = serde_json::from_value(stream_body(json!({}))).unwrap();
    assert!(active.transmitter_inactive_reason.is_none());
}

// ── 4. Pagination ───────────────────────────────────────────────────────────

#[tokio::test]
async fn list_streams_pages_and_the_walk_carries_search() {
    let server = MockServer::start().await;
    let client = logged_in_client(&server).await;
    let seen = Arc::new(Mutex::new(Vec::<String>::new()));
    let sink = Arc::clone(&seen);
    Mock::given(method("GET"))
        .and(path(STREAMS))
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
            let items = if offset < 2 {
                vec![stream_body(json!({}))]
            } else {
                vec![]
            };
            ResponseTemplate::new(200)
                .set_body_json(json!({"items": items, "total": 2, "offset": offset, "limit": 1}))
        })
        .mount(&server)
        .await;
    let page = client
        .ssf()
        .list_streams(PageRequest::first(1).search("rp.example"))
        .await
        .unwrap();
    assert_eq!(page.total, 2);
    let all = client
        .ssf()
        .list_streams_all(PageRequest::first(1).search("rp.example"))
        .await
        .unwrap();
    assert_eq!(all.len(), 2);
    for q in seen.lock().unwrap().iter() {
        assert!(q.contains("search=rp.example"), "{q}");
    }
}

// ── 5. No retry ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn none_of_the_three_writes_is_retried_on_503() {
    let server = MockServer::start().await;
    let client = logged_in_client_with_retry(&server).await;
    let id = Uuid::new_v4();
    let create = capture(&server, "POST", STREAMS.into(), ResponseTemplate::new(503)).await;
    let update = capture(
        &server,
        "PUT",
        format!("{STREAMS}/{id}"),
        ResponseTemplate::new(503),
    )
    .await;
    let delete = capture(
        &server,
        "DELETE",
        format!("{STREAMS}/{id}"),
        ResponseTemplate::new(503),
    )
    .await;
    let s = client.ssf();
    let errors = [
        s.create_stream(&input(Some(header_value())))
            .await
            .unwrap_err(),
        s.update_stream(id, &input(None)).await.unwrap_err(),
        s.delete_stream(id).await.unwrap_err(),
    ];
    for e in &errors {
        assert!(matches!(e, AxiamError::Network { .. }), "{e}");
    }
    for h in [create, update, delete] {
        assert_eq!(h.lock().unwrap().len(), 1);
    }
}

// ── 6. Errors ───────────────────────────────────────────────────────────────

#[tokio::test]
async fn statuses_map_per_section_2() {
    let server = MockServer::start().await;
    let client = logged_in_client(&server).await;
    let id = Uuid::new_v4();
    mount(
        &server,
        "PUT",
        &format!("{STREAMS}/{id}"),
        400,
        r#"{"error":"validation_error","message":"endpoint_url: must be https"}"#,
    )
    .await;
    mount(
        &server,
        "POST",
        STREAMS,
        409,
        r#"{"error":"conflict","message":"audience"}"#,
    )
    .await;
    mount(
        &server,
        "GET",
        &format!("{STREAMS}/{id}"),
        404,
        r#"{"error":"not_found","message":"no"}"#,
    )
    .await;
    mount(
        &server,
        "DELETE",
        &format!("{STREAMS}/{id}"),
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
    let s = client.ssf();
    let e = s.update_stream(id, &input(None)).await.unwrap_err();
    assert!(e.validation().unwrap().message.contains("https"));
    assert!(
        s.create_stream(&input(None))
            .await
            .unwrap_err()
            .is_conflict()
    );
    assert!(s.get_stream(id).await.unwrap_err().is_not_found());
    assert!(matches!(
        s.delete_stream(id).await.unwrap_err(),
        AxiamError::Auth { .. }
    ));
}

#[test]
fn a_read_converts_into_the_replacement_body_without_the_header() {
    let s: models::SsfStream = serde_json::from_value(stream_body(json!({}))).unwrap();
    let body = models::SsfStreamInput::from(&s);
    assert!(body.authorization_header.is_none() && body.clear_authorization_header.is_none());
    assert_eq!(
        body.events_requested.as_deref(),
        Some(s.events_requested.as_slice())
    );
}
