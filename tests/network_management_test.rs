//! The `network` management namespace — CONTRACT.md §36.8's five tests
//! (contract 1.62), against a mocked HTTP server.
//!
//! The manifest side of the namespace is in `network_manifest_test.rs`; the
//! per-operation wire assertions generated from the registry are in
//! `management_surface_generated.rs`.

#![cfg(feature = "rest")]

mod management_support;

use std::sync::{Arc, Mutex};

use axiam_sdk::management::{PageRequest, models};
use axiam_sdk::{AuthzKind, AxiamError};
use serde_json::{Value, json};
use uuid::Uuid;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

use management_support::{
    TENANT_ID, expected_surface, logged_in_client, logged_in_client_with_retry, mount,
};

const SEGMENTS: &str = "/api/v1/network/segments";
const PROFILES: &str = "/api/v1/network/profiles";
const POLICY: &str = "/api/v1/network/policy";

fn segment_body(extra: Value) -> Value {
    let mut body = json!({
        "id": Uuid::new_v4(), "tenant_id": TENANT_ID,
        "path": "/network/zones/default/lab", "name": "lab", "site_key": "default",
        "kind": "access", "vlan_id": 20, "filter_ids": ["lab-in"], "rank": 1,
        "enabled": true, "version": 3,
        "created_by": Uuid::new_v4(), "updated_by": Uuid::new_v4(),
        "created_at": "2026-10-16T00:00:00Z", "updated_at": "2026-10-16T00:00:00Z",
    });
    for (k, v) in extra.as_object().unwrap() {
        body[k] = v.clone();
    }
    body
}

fn profile_body(segment_id: Uuid, extra: Value) -> Value {
    let mut body = json!({
        "segment_id": segment_id, "tenant_id": TENANT_ID,
        "dictionary": "axiam-radius-reply/1", "session_timeout_secs": 3600,
        "session_timeout_clamped": false, "termination_action": "radius_request",
        "idle_timeout_secs": 600, "filter_id": "lab-in", "service_type": "framed_user",
        "version": 2,
        "created_by": Uuid::new_v4(), "updated_by": Uuid::new_v4(),
        "created_at": "2026-10-16T00:00:00Z", "updated_at": "2026-10-16T00:00:00Z",
    });
    for (k, v) in extra.as_object().unwrap() {
        body[k] = v.clone();
    }
    body
}

fn policy_body(max: i64, version: i64) -> Value {
    json!({ "tenant_id": TENANT_ID, "session_timeout_max_secs": max, "version": version })
}

fn page(items: Vec<Value>, total: u64, offset: u64) -> Value {
    json!({ "items": items, "total": total, "offset": offset, "limit": 1 })
}

/// One request as the mock saw it: verb, path, query, JSON body.
#[derive(Debug, Clone)]
struct Seen {
    verb: String,
    path: String,
    query: String,
    body: Value,
}

type Log = Arc<Mutex<Vec<Seen>>>;

async fn capture(server: &MockServer, verb: &str, route: &str, template: ResponseTemplate) -> Log {
    let log: Log = Arc::default();
    let sink = Arc::clone(&log);
    Mock::given(method(verb))
        .and(path(route))
        .respond_with(move |req: &Request| {
            sink.lock().unwrap().push(Seen {
                verb: req.method.to_string(),
                path: req.url.path().to_string(),
                query: req.url.query().unwrap_or("").to_string(),
                body: serde_json::from_slice(&req.body).unwrap_or(Value::Null),
            });
            template.clone()
        })
        .mount(server)
        .await;
    log
}

fn only(log: &Log) -> Seen {
    let seen = log.lock().unwrap();
    assert_eq!(seen.len(), 1, "exactly one request: {seen:?}");
    seen[0].clone()
}

fn keys(value: &Value) -> Vec<String> {
    let mut keys: Vec<String> = value
        .as_object()
        .expect("an object")
        .keys()
        .cloned()
        .collect();
    keys.sort();
    keys
}

fn profile_input() -> models::NetworkReplyProfileInput {
    models::NetworkReplyProfileInput {
        dictionary: None,
        filter_id: None,
        idle_timeout_secs: None,
        service_type: None,
        session_timeout_secs: 1800,
        termination_action: None,
    }
}

fn create_segment_request() -> models::CreateNetworkSegmentRequest {
    models::CreateNetworkSegmentRequest {
        enabled: None,
        filter_ids: None,
        kind: models::NetworkSegmentKind::Quarantine,
        name: "jail".into(),
        rank: None,
        site_key: "default".into(),
        vlan_id: 999,
    }
}

fn replace_segment_request(version: i64) -> models::ReplaceNetworkSegmentRequest {
    models::ReplaceNetworkSegmentRequest {
        enabled: true,
        filter_ids: vec![],
        rank: None,
        version,
        vlan_id: 30,
    }
}

// ── 1. The surface ──────────────────────────────────────────────────────────

/// The twelve operations exist on the `network` handle with the paths and
/// methods of §36.1 — and no method reaches `POST /api/v1/network/decide`.
#[tokio::test]
async fn the_twelve_operations_exist_and_the_decision_route_does_not() {
    let server = MockServer::start().await;
    let client = logged_in_client(&server).await;
    let id = Uuid::new_v4();
    let segment = segment_body(json!({ "id": id }));
    let profile = profile_body(id, json!({}));

    let logs = [
        (
            "GET",
            SEGMENTS.to_string(),
            capture(
                &server,
                "GET",
                SEGMENTS,
                ResponseTemplate::new(200).set_body_json(page(vec![segment.clone()], 1, 0)),
            )
            .await,
        ),
        (
            "POST",
            SEGMENTS.to_string(),
            capture(
                &server,
                "POST",
                SEGMENTS,
                ResponseTemplate::new(201).set_body_json(segment.clone()),
            )
            .await,
        ),
        (
            "GET",
            format!("{SEGMENTS}/{id}"),
            capture(
                &server,
                "GET",
                &format!("{SEGMENTS}/{id}"),
                ResponseTemplate::new(200).set_body_json(segment.clone()),
            )
            .await,
        ),
        (
            "PUT",
            format!("{SEGMENTS}/{id}"),
            capture(
                &server,
                "PUT",
                &format!("{SEGMENTS}/{id}"),
                ResponseTemplate::new(200).set_body_json(segment.clone()),
            )
            .await,
        ),
        (
            "DELETE",
            format!("{SEGMENTS}/{id}"),
            capture(
                &server,
                "DELETE",
                &format!("{SEGMENTS}/{id}"),
                ResponseTemplate::new(204),
            )
            .await,
        ),
        (
            "GET",
            PROFILES.to_string(),
            capture(
                &server,
                "GET",
                PROFILES,
                ResponseTemplate::new(200).set_body_json(page(vec![profile.clone()], 1, 0)),
            )
            .await,
        ),
        (
            "POST",
            PROFILES.to_string(),
            capture(
                &server,
                "POST",
                PROFILES,
                ResponseTemplate::new(201).set_body_json(profile.clone()),
            )
            .await,
        ),
        (
            "GET",
            format!("{PROFILES}/{id}"),
            capture(
                &server,
                "GET",
                &format!("{PROFILES}/{id}"),
                ResponseTemplate::new(200).set_body_json(profile.clone()),
            )
            .await,
        ),
        (
            "PUT",
            format!("{PROFILES}/{id}"),
            capture(
                &server,
                "PUT",
                &format!("{PROFILES}/{id}"),
                ResponseTemplate::new(200).set_body_json(profile.clone()),
            )
            .await,
        ),
        (
            "DELETE",
            format!("{PROFILES}/{id}"),
            capture(
                &server,
                "DELETE",
                &format!("{PROFILES}/{id}"),
                ResponseTemplate::new(204),
            )
            .await,
        ),
        (
            "GET",
            POLICY.to_string(),
            capture(
                &server,
                "GET",
                POLICY,
                ResponseTemplate::new(200).set_body_json(policy_body(3600, 0)),
            )
            .await,
        ),
        (
            "PUT",
            POLICY.to_string(),
            capture(
                &server,
                "PUT",
                POLICY,
                ResponseTemplate::new(200).set_body_json(policy_body(7200, 1)),
            )
            .await,
        ),
    ];

    let n = client.network();
    n.list_segments(None, PageRequest::first(10)).await.unwrap();
    n.create_segment(&create_segment_request()).await.unwrap();
    n.get_segment(id).await.unwrap();
    n.replace_segment(id, &replace_segment_request(3))
        .await
        .unwrap();
    n.delete_segment(id, 3).await.unwrap();
    n.list_profiles(PageRequest::first(10)).await.unwrap();
    n.create_profile(&models::CreateNetworkReplyProfileRequest {
        profile: profile_input(),
        segment_id: id,
        segment_version: 3,
    })
    .await
    .unwrap();
    n.get_profile(id).await.unwrap();
    n.replace_profile(
        id,
        &models::ReplaceNetworkReplyProfileRequest {
            profile: profile_input(),
            segment_version: 3,
            version: 2,
        },
    )
    .await
    .unwrap();
    n.delete_profile(id, 2).await.unwrap();
    n.get_policy().await.unwrap();
    n.replace_policy(&models::ReplaceNetworkPolicyRequest {
        session_timeout_max_secs: 7200,
        version: 0,
    })
    .await
    .unwrap();

    for (verb, route, log) in &logs {
        let seen = only(log);
        assert_eq!(&seen.verb, verb, "{route}");
        assert_eq!(&seen.path, route);
    }

    // The registry names exactly these twelve, and excludes the decision route.
    let surface = expected_surface();
    let network: Vec<&String> = surface
        .iter()
        .filter(|op| op.starts_with("network."))
        .collect();
    assert_eq!(
        network,
        [
            "network.create_profile",
            "network.create_segment",
            "network.delete_profile",
            "network.delete_segment",
            "network.get_policy",
            "network.get_profile",
            "network.get_segment",
            "network.list_profiles",
            "network.list_segments",
            "network.replace_policy",
            "network.replace_profile",
            "network.replace_segment",
        ]
    );
    let registry: Value =
        serde_json::from_str(include_str!("../management-registry.json")).unwrap();
    assert!(
        registry["excluded_operations"]
            .to_string()
            .contains("/api/v1/network/decide"),
        "the decision route is excluded by name (§27.0)"
    );
    // ... and nothing generated reaches it: the §27.8 regeneration check is
    // what keeps it out, and this is what it would catch.
    assert!(!include_str!("../src/management/ops/network.rs").contains("decide"));
    assert!(
        server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .all(|r| !r.url.path().ends_with("/decide")),
        "no call reached the decision route"
    );
}

// ── 2. Versions ─────────────────────────────────────────────────────────────

/// Every write names the version it read, exactly: in the body for the three
/// replaces and `segment_version` of a profile write, in `?version=` for the
/// two deletes.
#[tokio::test]
async fn versions_are_sent_exactly_as_given() {
    let server = MockServer::start().await;
    let client = logged_in_client(&server).await;
    let id = Uuid::new_v4();
    let replace_segment = capture(
        &server,
        "PUT",
        &format!("{SEGMENTS}/{id}"),
        ResponseTemplate::new(200).set_body_json(segment_body(json!({}))),
    )
    .await;
    let delete_segment = capture(
        &server,
        "DELETE",
        &format!("{SEGMENTS}/{id}"),
        ResponseTemplate::new(204),
    )
    .await;
    let create_profile = capture(
        &server,
        "POST",
        PROFILES,
        ResponseTemplate::new(201).set_body_json(profile_body(id, json!({}))),
    )
    .await;
    let replace_profile = capture(
        &server,
        "PUT",
        &format!("{PROFILES}/{id}"),
        ResponseTemplate::new(200).set_body_json(profile_body(id, json!({}))),
    )
    .await;
    let delete_profile = capture(
        &server,
        "DELETE",
        &format!("{PROFILES}/{id}"),
        ResponseTemplate::new(204),
    )
    .await;
    let replace_policy = capture(
        &server,
        "PUT",
        POLICY,
        ResponseTemplate::new(200).set_body_json(policy_body(900, 8)),
    )
    .await;

    let n = client.network();
    n.replace_segment(id, &replace_segment_request(41))
        .await
        .unwrap();
    n.delete_segment(id, 42).await.unwrap();
    n.create_profile(&models::CreateNetworkReplyProfileRequest {
        profile: profile_input(),
        segment_id: id,
        segment_version: 43,
    })
    .await
    .unwrap();
    n.replace_profile(
        id,
        &models::ReplaceNetworkReplyProfileRequest {
            profile: profile_input(),
            segment_version: 44,
            version: 45,
        },
    )
    .await
    .unwrap();
    n.delete_profile(id, 46).await.unwrap();
    n.replace_policy(&models::ReplaceNetworkPolicyRequest {
        session_timeout_max_secs: 900,
        version: 0,
    })
    .await
    .unwrap();

    assert_eq!(only(&replace_segment).body["version"], json!(41));
    assert_eq!(only(&delete_segment).query, "version=42");
    assert_eq!(only(&create_profile).body["segment_version"], json!(43));
    let sent = only(&replace_profile).body;
    assert_eq!(sent["version"], json!(45));
    assert_eq!(sent["segment_version"], json!(44));
    assert_eq!(only(&delete_profile).query, "version=46");
    // `0` is a version (the tenant's first write), sent as `0` and not omitted.
    assert_eq!(only(&replace_policy).body["version"], json!(0));
    // (`delete_segment(id)` without a version does not compile: the argument is
    // not optional, so "cannot be called without one" is the type's.)
}

/// A `409` to each write is a conflict after exactly one request, exposing the
/// body's `reason_code` — and `already_exists` is a conflict too.
#[tokio::test]
async fn a_409_to_each_write_is_one_request_and_exposes_its_reason_code() {
    let server = MockServer::start().await;
    // Retry on: a write that were retried would show as a second request.
    let client = logged_in_client_with_retry(&server).await;
    let id = Uuid::new_v4();
    let stale = ResponseTemplate::new(409).set_body_json(json!({
        "error": "conflict", "message": "changed since read", "reason_code": "stale_version",
    }));
    let duplicate = ResponseTemplate::new(409).set_body_json(json!({
        "error": "already_exists", "message": "vlan taken", "reason_code": "duplicate_vlan",
    }));
    let logs = [
        capture(&server, "POST", SEGMENTS, duplicate.clone()).await,
        capture(&server, "PUT", &format!("{SEGMENTS}/{id}"), stale.clone()).await,
        capture(
            &server,
            "DELETE",
            &format!("{SEGMENTS}/{id}"),
            stale.clone(),
        )
        .await,
        capture(&server, "POST", PROFILES, stale.clone()).await,
        capture(&server, "PUT", &format!("{PROFILES}/{id}"), stale.clone()).await,
        capture(
            &server,
            "DELETE",
            &format!("{PROFILES}/{id}"),
            stale.clone(),
        )
        .await,
        capture(&server, "PUT", POLICY, stale.clone()).await,
    ];

    let n = client.network();
    let errors = [
        n.create_segment(&create_segment_request())
            .await
            .unwrap_err(),
        n.replace_segment(id, &replace_segment_request(1))
            .await
            .unwrap_err(),
        n.delete_segment(id, 1).await.unwrap_err(),
        n.create_profile(&models::CreateNetworkReplyProfileRequest {
            profile: profile_input(),
            segment_id: id,
            segment_version: 1,
        })
        .await
        .unwrap_err(),
        n.replace_profile(
            id,
            &models::ReplaceNetworkReplyProfileRequest {
                profile: profile_input(),
                segment_version: 1,
                version: 1,
            },
        )
        .await
        .unwrap_err(),
        n.delete_profile(id, 1).await.unwrap_err(),
        n.replace_policy(&models::ReplaceNetworkPolicyRequest {
            session_timeout_max_secs: 900,
            version: 1,
        })
        .await
        .unwrap_err(),
    ];

    let expected = [
        "duplicate_vlan",
        "stale_version",
        "stale_version",
        "stale_version",
        "stale_version",
        "stale_version",
        "stale_version",
    ];
    for (error, code) in errors.iter().zip(expected) {
        assert!(error.is_conflict(), "{error:?}");
        assert!(matches!(
            error,
            AxiamError::Authz {
                kind: AuthzKind::Conflict,
                ..
            }
        ));
        assert_eq!(error.reason_code(), Some(code), "{error:?}");
    }
    for log in &logs {
        only(log);
    }
}

/// The vocabulary is open: a `reason_code` this SDK has never seen is surfaced
/// verbatim, a server that predates the member gives `None`, and a refusal that
/// is not a `409` has none.
#[tokio::test]
async fn an_unknown_reason_code_is_surfaced_verbatim_and_an_absent_one_is_none() {
    let server = MockServer::start().await;
    let client = logged_in_client(&server).await;
    let id = Uuid::new_v4();
    mount(
        &server,
        "PUT",
        &format!("{SEGMENTS}/{id}"),
        409,
        r#"{"error":"conflict","message":"m","reason_code":"brand_new"}"#,
    )
    .await;
    mount(
        &server,
        "DELETE",
        &format!("{SEGMENTS}/{id}"),
        409,
        r#"{"error":"conflict","message":"m"}"#,
    )
    .await;
    mount(
        &server,
        "PUT",
        POLICY,
        403,
        r#"{"error":"authorization_denied","message":"m","reason_code":"stale_version"}"#,
    )
    .await;

    let n = client.network();
    let unknown = n
        .replace_segment(id, &replace_segment_request(1))
        .await
        .unwrap_err();
    assert_eq!(unknown.reason_code(), Some("brand_new"));
    assert!(unknown.is_conflict());
    let old_server = n.delete_segment(id, 1).await.unwrap_err();
    assert!(old_server.is_conflict());
    assert_eq!(old_server.reason_code(), None);
    let denied = n
        .replace_policy(&models::ReplaceNetworkPolicyRequest {
            session_timeout_max_secs: 900,
            version: 1,
        })
        .await
        .unwrap_err();
    assert_eq!(
        denied.reason_code(),
        None,
        "only a 409 carries the sub-code"
    );
}

// ── 3. Closed bodies ────────────────────────────────────────────────────────

#[test]
fn request_bodies_carry_exactly_the_keys_of_the_members_set() {
    // Nothing optional set: the optionals are absent, never `null`.
    let create_segment = serde_json::to_value(create_segment_request()).unwrap();
    assert_eq!(
        keys(&create_segment),
        ["kind", "name", "site_key", "vlan_id"]
    );
    assert_eq!(create_segment["kind"], json!("quarantine"));

    let replace_segment = serde_json::to_value(replace_segment_request(5)).unwrap();
    assert_eq!(
        keys(&replace_segment),
        ["enabled", "filter_ids", "version", "vlan_id"]
    );
    assert!(
        replace_segment.get("rank").is_none(),
        "an unset rank is absent"
    );

    let create_profile = serde_json::to_value(models::CreateNetworkReplyProfileRequest {
        profile: profile_input(),
        segment_id: Uuid::new_v4(),
        segment_version: 1,
    })
    .unwrap();
    assert_eq!(
        keys(&create_profile),
        ["profile", "segment_id", "segment_version"]
    );
    assert_eq!(keys(&create_profile["profile"]), ["session_timeout_secs"]);

    let replace_policy = serde_json::to_value(models::ReplaceNetworkPolicyRequest {
        session_timeout_max_secs: 300,
        version: 0,
    })
    .unwrap();
    assert_eq!(
        keys(&replace_policy),
        ["session_timeout_max_secs", "version"]
    );

    // Everything set: still no member §36.2 does not name — and a profile has
    // no VLAN member, because the VLAN is the segment's.
    let full = serde_json::to_value(models::NetworkReplyProfileInput {
        dictionary: Some("axiam-radius-reply/1".into()),
        filter_id: Some("lab-in".into()),
        idle_timeout_secs: Some(60),
        service_type: Some(models::RadiusServiceType::FramedUser),
        session_timeout_secs: 300,
        termination_action: Some(models::RadiusTerminationAction::Default),
    })
    .unwrap();
    assert_eq!(
        keys(&full),
        [
            "dictionary",
            "filter_id",
            "idle_timeout_secs",
            "service_type",
            "session_timeout_secs",
            "termination_action",
        ]
    );
    assert!(full.get("vlan_id").is_none());
}

/// The replace types cannot be built without their required members: a Rust
/// struct literal that omits one does not compile, and a document that omits
/// one does not decode.
#[test]
fn the_replace_types_require_their_members() {
    assert!(
        serde_json::from_value::<models::ReplaceNetworkSegmentRequest>(json!({ "vlan_id": 1 }))
            .is_err()
    );
    assert!(
        serde_json::from_value::<models::ReplaceNetworkPolicyRequest>(json!({ "version": 1 }))
            .is_err()
    );
    assert!(
        serde_json::from_value::<models::ReplaceNetworkReplyProfileRequest>(json!({
            "version": 1, "profile": { "session_timeout_secs": 300 }
        }))
        .is_err(),
        "segment_version is required"
    );
}

// ── 4. Open decoding and pagination ─────────────────────────────────────────

#[test]
fn unknown_enum_values_decode_and_round_trip() {
    let segment: models::NetworkSegmentResponse =
        serde_json::from_value(segment_body(json!({ "kind": "dmz" }))).unwrap();
    assert_eq!(
        segment.kind,
        models::NetworkSegmentKind::Unknown("dmz".into())
    );
    assert_eq!(serde_json::to_value(&segment.kind).unwrap(), json!("dmz"));

    let profile: models::NetworkReplyProfile = serde_json::from_value(profile_body(
        Uuid::new_v4(),
        json!({ "termination_action": "reauthenticate", "service_type": "login_user" }),
    ))
    .unwrap();
    assert_eq!(
        profile.termination_action,
        models::RadiusTerminationAction::Unknown("reauthenticate".into())
    );
    assert_eq!(
        profile.service_type,
        Some(models::RadiusServiceType::Unknown("login_user".into()))
    );

    // A clamped profile decodes with both members.
    let clamped: models::NetworkReplyProfile = serde_json::from_value(profile_body(
        Uuid::new_v4(),
        json!({ "session_timeout_secs": 900, "session_timeout_clamped": true }),
    ))
    .unwrap();
    assert!(clamped.session_timeout_clamped);
    assert_eq!(clamped.session_timeout_secs, 900);
}

#[tokio::test]
async fn both_lists_return_pages_and_the_auto_pager_carries_search_and_site() {
    let server = MockServer::start().await;
    let client = logged_in_client(&server).await;
    let queries: Arc<Mutex<Vec<(String, String)>>> = Arc::default();
    for (route, make) in [
        (SEGMENTS, (|| segment_body(json!({}))) as fn() -> Value),
        (
            PROFILES,
            (|| profile_body(Uuid::new_v4(), json!({}))) as fn() -> Value,
        ),
    ] {
        let sink = Arc::clone(&queries);
        Mock::given(method("GET"))
            .and(path(route))
            .respond_with(move |req: &Request| {
                let query = req.url.query().unwrap_or("").to_string();
                sink.lock()
                    .unwrap()
                    .push((req.url.path().to_string(), query.clone()));
                let offset: u64 = query
                    .split('&')
                    .find_map(|kv| kv.strip_prefix("offset="))
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(0);
                let items = if offset < 2 { vec![make()] } else { vec![] };
                ResponseTemplate::new(200).set_body_json(page(items, 2, offset))
            })
            .mount(&server)
            .await;
    }

    let n = client.network();
    let first = n
        .list_segments(Some("hq"), PageRequest::first(1).search("lab"))
        .await
        .unwrap();
    assert_eq!(first.total, 2);
    assert_eq!(first.items.len(), 1);
    let all = n
        .list_segments_all(Some("hq"), PageRequest::first(1).search("lab"))
        .await
        .unwrap();
    assert_eq!(all.len(), 2);
    let profiles = n
        .list_profiles(PageRequest::first(1).search("lab-in"))
        .await
        .unwrap();
    assert_eq!(profiles.total, 2);
    let all_profiles = n
        .list_profiles_all(PageRequest::first(1).search("lab-in"))
        .await
        .unwrap();
    assert_eq!(all_profiles.len(), 2);

    for (route, query) in queries.lock().unwrap().iter() {
        assert!(query.contains("search=lab"), "{route}: {query}");
        if route == SEGMENTS {
            assert!(query.contains("site=hq"), "{route}: {query}");
        }
    }
}

// ── 5. Errors ───────────────────────────────────────────────────────────────

#[tokio::test]
async fn statuses_map_per_section_2() {
    let server = MockServer::start().await;
    let client = logged_in_client(&server).await;
    let id = Uuid::new_v4();
    let node = Uuid::new_v4();
    mount(
        &server,
        "PUT",
        &format!("{PROFILES}/{id}"),
        403,
        &json!({
            "error": "authorization_denied", "message": "network:grant is missing",
            "action": "network:grant", "resource_id": node,
        })
        .to_string(),
    )
    .await;
    mount(
        &server,
        "POST",
        SEGMENTS,
        400,
        r#"{"error":"validation_error","message":"vlan_id: out of range"}"#,
    )
    .await;
    mount(
        &server,
        "GET",
        &format!("{PROFILES}/{id}"),
        404,
        r#"{"error":"not_found","message":"no"}"#,
    )
    .await;
    mount(
        &server,
        "GET",
        POLICY,
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

    let n = client.network();
    let denied = n
        .replace_profile(
            id,
            &models::ReplaceNetworkReplyProfileRequest {
                profile: profile_input(),
                segment_version: 1,
                version: 1,
            },
        )
        .await
        .unwrap_err();
    match &denied {
        AxiamError::Authz {
            kind: AuthzKind::Denied,
            action,
            resource_id,
            ..
        } => {
            assert_eq!(action.as_deref(), Some("network:grant"));
            assert_eq!(resource_id.as_deref(), Some(node.to_string().as_str()));
        }
        other => panic!("expected AuthzError, got {other:?}"),
    }
    let invalid = n
        .create_segment(&create_segment_request())
        .await
        .unwrap_err();
    assert!(
        invalid
            .validation()
            .unwrap()
            .message
            .contains("out of range")
    );
    assert!(n.get_profile(id).await.unwrap_err().is_not_found());
    assert!(matches!(
        n.get_policy().await.unwrap_err(),
        AxiamError::Auth { .. }
    ));
}

/// `429` and `503` on each of the seven writes are a network error after
/// exactly one request, with the §16 retry policy on.
#[tokio::test]
async fn none_of_the_seven_writes_is_retried_on_429_or_503() {
    for status in [429u16, 503] {
        let server = MockServer::start().await;
        let client = logged_in_client_with_retry(&server).await;
        let id = Uuid::new_v4();
        let refuse = || ResponseTemplate::new(status);
        let logs = [
            capture(&server, "POST", SEGMENTS, refuse()).await,
            capture(&server, "PUT", &format!("{SEGMENTS}/{id}"), refuse()).await,
            capture(&server, "DELETE", &format!("{SEGMENTS}/{id}"), refuse()).await,
            capture(&server, "POST", PROFILES, refuse()).await,
            capture(&server, "PUT", &format!("{PROFILES}/{id}"), refuse()).await,
            capture(&server, "DELETE", &format!("{PROFILES}/{id}"), refuse()).await,
            capture(&server, "PUT", POLICY, refuse()).await,
        ];

        let n = client.network();
        let errors = [
            n.create_segment(&create_segment_request())
                .await
                .unwrap_err(),
            n.replace_segment(id, &replace_segment_request(1))
                .await
                .unwrap_err(),
            n.delete_segment(id, 1).await.unwrap_err(),
            n.create_profile(&models::CreateNetworkReplyProfileRequest {
                profile: profile_input(),
                segment_id: id,
                segment_version: 1,
            })
            .await
            .unwrap_err(),
            n.replace_profile(
                id,
                &models::ReplaceNetworkReplyProfileRequest {
                    profile: profile_input(),
                    segment_version: 1,
                    version: 1,
                },
            )
            .await
            .unwrap_err(),
            n.delete_profile(id, 1).await.unwrap_err(),
            n.replace_policy(&models::ReplaceNetworkPolicyRequest {
                session_timeout_max_secs: 900,
                version: 1,
            })
            .await
            .unwrap_err(),
        ];
        for error in &errors {
            assert!(
                matches!(error, AxiamError::Network { .. }),
                "{status}: {error:?}"
            );
        }
        for log in &logs {
            only(log);
        }
    }
}
