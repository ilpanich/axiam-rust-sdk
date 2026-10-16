//! CONTRACT §27.6.2 / §27.9 — the `network` namespace in a manifest
//! (contract 1.62), against a small stateful fake of the six routes it reads
//! and writes.
//!
//! The fake enforces what the server enforces that matters here: a write is
//! conditional on the `version` it names (and a profile write on the
//! `segment_version`), and each write bumps the version. That is what makes
//! "the profile's `segment_version` is the segment write's response, not the
//! one `plan` read" and "`apply` then `plan` is all `NoChange`" assertions
//! about the SDK rather than about the mock.

#![cfg(feature = "rest")]

mod management_support;

use std::sync::{Arc, Mutex};

use axiam_sdk::AxiamError;
use axiam_sdk::client::AxiamClient;
use axiam_sdk::management::manifest::{
    Change, ManagementManifest, NetworkPolicySpec, NetworkProfileSpec, NetworkSegmentSpec, Outcome,
    Target,
};
use axiam_sdk::management::models::{RadiusServiceType, RadiusTerminationAction};
use serde_json::{Value, json};
use uuid::Uuid;
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

use management_support::{TENANT_ID, logged_in_client_with_retry};

const NOW: &str = "2026-10-16T00:00:00Z";
/// What the fake gives a segment it creates: distinctive, so a `segment_version`
/// that was hard-coded or taken from the wrong place cannot pass.
const CREATED_VERSION: i64 = 7;

#[derive(Debug, Clone)]
struct Seen {
    verb: String,
    path: String,
    body: Value,
}

#[derive(Default)]
struct State {
    policy_max: i64,
    policy_version: i64,
    segments: Vec<Value>,
    profiles: Vec<Value>,
    /// `(verb, route suffix, status, body)`: answer the first matching write
    /// with this instead of applying it.
    refuse: Vec<(String, String, u16, Value)>,
    log: Vec<Seen>,
}

/// A fake `/api/v1/network/*`, plus empty answers for the five reads every
/// `plan` makes whatever the manifest holds.
struct Fake {
    server: MockServer,
    state: Arc<Mutex<State>>,
    client: AxiamClient,
    /// Requests made before the test began (the login).
    baseline: usize,
}

fn page(items: &[Value], req: &Request) -> Value {
    let query = req.url.query().unwrap_or("");
    let get = |name: &str| {
        query
            .split('&')
            .find_map(|kv| kv.strip_prefix(&format!("{name}=")))
            .and_then(|v| v.parse::<usize>().ok())
    };
    let offset = get("offset").unwrap_or(0);
    let limit = get("limit").unwrap_or(items.len().max(1));
    let slice: Vec<Value> = items.iter().skip(offset).take(limit).cloned().collect();
    json!({ "items": slice, "total": items.len(), "offset": offset, "limit": limit })
}

fn conflict(code: &str, error: &str) -> ResponseTemplate {
    ResponseTemplate::new(409).set_body_json(json!({
        "error": error, "message": "refused by the fake", "reason_code": code,
    }))
}

fn respond(state: &Mutex<State>, req: &Request) -> ResponseTemplate {
    let mut s = state.lock().unwrap();
    let verb = req.method.to_string();
    let route = req.url.path().to_string();
    let body: Value = serde_json::from_slice(&req.body).unwrap_or(Value::Null);
    s.log.push(Seen {
        verb: verb.clone(),
        path: route.clone(),
        body: body.clone(),
    });

    if verb != "GET"
        && let Some(at) = s
            .refuse
            .iter()
            .position(|(v, suffix, ..)| *v == verb && route.ends_with(suffix.as_str()))
    {
        let (_, _, status, refusal) = s.refuse.remove(at);
        return ResponseTemplate::new(status).set_body_json(refusal);
    }

    let tail = route.trim_start_matches("/api/v1/network/");
    let (collection, id) = match tail.split_once('/') {
        Some((c, id)) => (c, Some(id.to_string())),
        None => (tail, None),
    };
    match (verb.as_str(), collection, id) {
        ("GET", "policy", _) => ResponseTemplate::new(200).set_body_json(json!({
            "tenant_id": TENANT_ID, "session_timeout_max_secs": s.policy_max,
            "version": s.policy_version,
        })),
        ("PUT", "policy", _) => {
            if body["version"] != json!(s.policy_version) {
                return conflict("stale_version", "conflict");
            }
            s.policy_max = body["session_timeout_max_secs"].as_i64().unwrap();
            s.policy_version += 1;
            ResponseTemplate::new(200).set_body_json(json!({
                "tenant_id": TENANT_ID, "session_timeout_max_secs": s.policy_max,
                "version": s.policy_version,
            }))
        }
        ("GET", "segments", None) => {
            ResponseTemplate::new(200).set_body_json(page(&s.segments, req))
        }
        ("GET", "profiles", None) => {
            ResponseTemplate::new(200).set_body_json(page(&s.profiles, req))
        }
        ("POST", "segments", None) => {
            let id = Uuid::new_v4();
            let kind = body["kind"].as_str().unwrap().to_string();
            let zone = if kind == "access" {
                "zones"
            } else {
                "quarantine"
            };
            let segment = json!({
                "id": id, "tenant_id": TENANT_ID,
                "path": format!("/network/{zone}/{}/{}", body["site_key"].as_str().unwrap(), body["name"].as_str().unwrap()),
                "name": body["name"], "site_key": body["site_key"], "kind": kind,
                "vlan_id": body["vlan_id"],
                "filter_ids": body.get("filter_ids").cloned().unwrap_or(json!([])),
                "rank": body.get("rank").cloned().unwrap_or(Value::Null),
                "enabled": body.get("enabled").cloned().unwrap_or(json!(true)),
                "version": CREATED_VERSION,
                "created_by": Uuid::nil(), "updated_by": Uuid::nil(),
                "created_at": NOW, "updated_at": NOW,
            });
            s.segments.push(segment.clone());
            ResponseTemplate::new(201).set_body_json(segment)
        }
        ("PUT", "segments", Some(id)) => {
            let Some(segment) = s.segments.iter_mut().find(|x| x["id"] == json!(id)) else {
                return ResponseTemplate::new(404)
                    .set_body_json(json!({"error":"not_found","message":"no"}));
            };
            if body["version"] != segment["version"] {
                return conflict("stale_version", "conflict");
            }
            segment["vlan_id"] = body["vlan_id"].clone();
            segment["filter_ids"] = body["filter_ids"].clone();
            segment["enabled"] = body["enabled"].clone();
            segment["rank"] = body.get("rank").cloned().unwrap_or(Value::Null);
            segment["version"] = json!(segment["version"].as_i64().unwrap() + 1);
            ResponseTemplate::new(200).set_body_json(segment.clone())
        }
        ("POST", "profiles", None) => {
            let sid = body["segment_id"].clone();
            let Some(segment) = s.segments.iter().find(|x| x["id"] == sid).cloned() else {
                return ResponseTemplate::new(404)
                    .set_body_json(json!({"error":"not_found","message":"no"}));
            };
            if body["segment_version"] != segment["version"] {
                return conflict("stale_version", "conflict");
            }
            if s.profiles.iter().any(|p| p["segment_id"] == sid) {
                return conflict("profile_exists", "already_exists");
            }
            let profile = effective_profile(&sid, &body["profile"], 1, s.policy_max);
            s.profiles.push(profile.clone());
            ResponseTemplate::new(201).set_body_json(profile)
        }
        ("PUT", "profiles", Some(id)) => {
            let sid = json!(id);
            let Some(segment) = s.segments.iter().find(|x| x["id"] == sid).cloned() else {
                return ResponseTemplate::new(404)
                    .set_body_json(json!({"error":"not_found","message":"no"}));
            };
            if body["segment_version"] != segment["version"] {
                return conflict("stale_version", "conflict");
            }
            let max = s.policy_max;
            let Some(at) = s.profiles.iter().position(|p| p["segment_id"] == sid) else {
                return ResponseTemplate::new(404)
                    .set_body_json(json!({"error":"not_found","message":"no"}));
            };
            if body["version"] != s.profiles[at]["version"] {
                return conflict("stale_version", "conflict");
            }
            let next = s.profiles[at]["version"].as_i64().unwrap() + 1;
            s.profiles[at] = effective_profile(&sid, &body["profile"], next, max);
            ResponseTemplate::new(200).set_body_json(s.profiles[at].clone())
        }
        other => panic!("the fake has no route for {other:?}"),
    }
}

/// A profile as the server reads it back: the *effective* one, the stored
/// timeout lowered to the cap.
fn effective_profile(segment_id: &Value, input: &Value, version: i64, cap: i64) -> Value {
    let stored = input["session_timeout_secs"].as_i64().unwrap();
    json!({
        "segment_id": segment_id, "tenant_id": TENANT_ID,
        "dictionary": input.get("dictionary").cloned().unwrap_or(json!("axiam-radius-reply/1")),
        "session_timeout_secs": stored.min(cap), "session_timeout_clamped": stored > cap,
        "termination_action": input.get("termination_action").cloned().unwrap_or(json!("radius_request")),
        "idle_timeout_secs": input.get("idle_timeout_secs").cloned().unwrap_or(Value::Null),
        "filter_id": input.get("filter_id").cloned().unwrap_or(Value::Null),
        "service_type": input.get("service_type").cloned().unwrap_or(Value::Null),
        "version": version,
        "created_by": Uuid::nil(), "updated_by": Uuid::nil(),
        "created_at": NOW, "updated_at": NOW,
    })
}

impl Fake {
    async fn start() -> Self {
        let server = MockServer::start().await;
        // Retry on: a network write that were retried would show in the log.
        let client = logged_in_client_with_retry(&server).await;
        let state = Arc::new(Mutex::new(State {
            policy_max: 3600,
            ..State::default()
        }));
        let sink = Arc::clone(&state);
        Mock::given(path_regex("^/api/v1/network/"))
            .respond_with(move |req: &Request| respond(&sink, req))
            .mount(&server)
            .await;
        for route in [
            "/api/v1/resources",
            "/api/v1/permissions",
            "/api/v1/roles",
            "/api/v1/groups",
            "/api/v1/users",
        ] {
            Mock::given(method("GET"))
                .and(path(route))
                .respond_with(
                    ResponseTemplate::new(200).set_body_json(
                        json!({ "items": [], "total": 0, "offset": 0, "limit": 200 }),
                    ),
                )
                .mount(&server)
                .await;
        }
        let baseline = server.received_requests().await.unwrap().len();
        Self {
            server,
            state,
            client,
            baseline,
        }
    }

    /// Everything the test itself provoked, in order.
    async fn requests(&self) -> Vec<(String, String)> {
        self.server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .skip(self.baseline)
            .map(|r| (r.method.to_string(), r.url.path().to_string()))
            .collect()
    }

    /// The network writes the fake saw, oldest first.
    fn writes(&self) -> Vec<Seen> {
        self.state
            .lock()
            .unwrap()
            .log
            .iter()
            .filter(|s| s.verb != "GET")
            .cloned()
            .collect()
    }

    fn seed_segment(
        &self,
        kind: &str,
        name: &str,
        vlan: i64,
        rank: Option<i64>,
        filter_ids: &[&str],
        version: i64,
    ) -> Uuid {
        let id = Uuid::new_v4();
        self.state.lock().unwrap().segments.push(json!({
            "id": id, "tenant_id": TENANT_ID,
            "path": format!("/network/zones/default/{name}"), "name": name, "site_key": "default",
            "kind": kind, "vlan_id": vlan, "filter_ids": filter_ids, "rank": rank,
            "enabled": true, "version": version,
            "created_by": Uuid::nil(), "updated_by": Uuid::nil(),
            "created_at": NOW, "updated_at": NOW,
        }));
        id
    }

    fn seed_profile(&self, segment: Uuid, stored: i64, version: i64) {
        let mut s = self.state.lock().unwrap();
        let cap = s.policy_max;
        s.profiles.push(effective_profile(
            &json!(segment),
            &json!({
                "session_timeout_secs": stored, "idle_timeout_secs": 600,
                "filter_id": "lab-in", "service_type": "framed_user",
            }),
            version,
            cap,
        ));
    }

    fn refuse_next(&self, verb: &str, suffix: &str, status: u16, body: Value) {
        self.state
            .lock()
            .unwrap()
            .refuse
            .push((verb.into(), suffix.into(), status, body));
    }
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

fn lab() -> NetworkSegmentSpec {
    NetworkSegmentSpec::access("lab", "default", "lab", 20, 1)
}

// ── plan writes nothing ─────────────────────────────────────────────────────

/// `plan` of a manifest with a policy, a segment and a profile issues `GET`s
/// only — `get_policy`, `list_segments`, `list_profiles` — and no other method.
#[tokio::test]
async fn plan_issues_gets_only() {
    let fake = Fake::start().await;
    let manifest = ManagementManifest::new()
        .with_network_policy(NetworkPolicySpec::new(7200))
        .with_network_segment(lab())
        .with_network_profile(NetworkProfileSpec::new("lab", 1800));

    let plan = fake.client.manifest().plan(&manifest).await.unwrap();

    let network: Vec<_> = fake
        .requests()
        .await
        .into_iter()
        .filter(|(_, p)| p.starts_with("/api/v1/network/"))
        .collect();
    assert_eq!(
        network,
        [
            ("GET".to_string(), "/api/v1/network/policy".to_string()),
            ("GET".to_string(), "/api/v1/network/segments".to_string()),
            ("GET".to_string(), "/api/v1/network/profiles".to_string()),
        ]
    );
    assert!(
        fake.requests().await.iter().all(|(verb, _)| verb == "GET"),
        "plan wrote nothing"
    );
    // Policy, segments, profiles — the order §27.6.2 item 2 fixes.
    let targets: Vec<_> = plan.actions.iter().map(|a| (a.target, a.change)).collect();
    assert_eq!(
        targets,
        [
            (Target::NetworkPolicy, Change::Update),
            (Target::NetworkSegment, Change::Create),
            (Target::NetworkProfile, Change::Create),
        ]
    );
}

/// A manifest without a `network` section plans exactly as before 1.62: not one
/// request to the network routes.
#[tokio::test]
async fn a_manifest_without_a_network_section_reads_nothing_of_it() {
    let fake = Fake::start().await;
    fake.client
        .manifest()
        .plan(&ManagementManifest::new())
        .await
        .unwrap();
    assert!(
        fake.requests()
            .await
            .iter()
            .all(|(_, p)| !p.starts_with("/api/v1/network/")),
        "a plan sends no request to the network surface"
    );
}

// ── apply on an empty tenant ────────────────────────────────────────────────

/// On an empty tenant, `apply` writes the policy, creates the segment and then
/// the profile, in that order; the profile request carries the **new segment's
/// id and the `version` of the create response** as `segment_version`; and
/// `plan` afterwards is all `NoChange` (rule 6).
#[tokio::test]
async fn apply_creates_segment_then_profile_and_converges() {
    let fake = Fake::start().await;
    let manifest = ManagementManifest::new()
        .with_network_policy(NetworkPolicySpec::new(7200))
        .with_network_segment(lab().with_filter_ids(["lab-in", "lab-out"]))
        .with_network_profile(
            NetworkProfileSpec::new("lab", 1800)
                .with_filter_id("lab-in")
                .with_service_type(RadiusServiceType::FramedUser),
        );

    let report = fake.client.manifest().apply(&manifest).await.unwrap();
    assert!(report.is_complete(), "the apply has a failing step");
    assert_eq!(report.changed(), 3);

    let writes = fake.writes();
    let order: Vec<_> = writes
        .iter()
        .map(|w| (w.verb.as_str(), w.path.as_str()))
        .collect();
    let segment_id = fake.state.lock().unwrap().segments[0]["id"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(
        order,
        [
            ("PUT", "/api/v1/network/policy"),
            ("POST", "/api/v1/network/segments"),
            ("POST", "/api/v1/network/profiles"),
        ]
    );
    assert_eq!(
        writes[0].body,
        json!({ "session_timeout_max_secs": 7200, "version": 0 })
    );
    assert_eq!(
        writes[1].body["kind"],
        json!("access"),
        "the wire spelling, asserted as a string"
    );
    let profile = &writes[2].body;
    assert_eq!(profile["segment_id"], json!(segment_id));
    assert_eq!(
        profile["segment_version"],
        json!(CREATED_VERSION),
        "the create response's version"
    );

    let again = fake.client.manifest().plan(&manifest).await.unwrap();
    assert!(again.is_converged(), "a second plan still has changes");
    assert!(again.actions.iter().all(|a| a.change == Change::NoChange));
}

// ── Update bodies ───────────────────────────────────────────────────────────

/// A segment `Update` sends the **full** replacement body: `version` as read,
/// the stated members, and every unstated one carried from the read — and no
/// `kind`, `site_key` or `name`. A stated `null` on an optional profile member
/// leaves the key out.
#[tokio::test]
async fn an_update_sends_the_full_body_from_the_read() {
    let fake = Fake::start().await;
    let id = fake.seed_segment("access", "lab", 10, Some(3), &["a", "b"], 4);
    fake.seed_profile(id, 1800, 2);
    let manifest = ManagementManifest::new()
        .with_network_segment(NetworkSegmentSpec::new(
            "lab",
            "default",
            axiam_sdk::management::models::NetworkSegmentKind::Access,
            "lab",
            20,
        ))
        .with_network_profile(
            NetworkProfileSpec::new("lab", 1800)
                .with_no_idle_timeout()
                .with_termination_action(RadiusTerminationAction::Default),
        );

    let report = fake.client.manifest().apply(&manifest).await.unwrap();
    assert!(report.is_complete(), "the apply has a failing step");

    let writes = fake.writes();
    let segment = &writes[0];
    assert_eq!(
        (segment.verb.as_str(), segment.path.as_str()),
        ("PUT", format!("/api/v1/network/segments/{id}").as_str())
    );
    assert_eq!(
        keys(&segment.body),
        ["enabled", "filter_ids", "rank", "version", "vlan_id"]
    );
    assert_eq!(segment.body["version"], json!(4));
    assert_eq!(segment.body["vlan_id"], json!(20), "stated");
    assert_eq!(segment.body["rank"], json!(3), "carried from the read");
    assert_eq!(
        segment.body["filter_ids"],
        json!(["a", "b"]),
        "carried from the read"
    );
    assert_eq!(
        segment.body["enabled"],
        json!(true),
        "carried from the read"
    );

    let profile = &writes[1];
    assert_eq!(profile.path, format!("/api/v1/network/profiles/{id}"));
    assert_eq!(profile.body["version"], json!(2));
    let input = &profile.body["profile"];
    assert!(
        input.get("idle_timeout_secs").is_none(),
        "a stated none is left out of the profile body"
    );
    assert_eq!(input["termination_action"], json!("default"));
    assert_eq!(input["filter_id"], json!("lab-in"), "carried from the read");
    assert_eq!(
        input["dictionary"],
        json!("axiam-radius-reply/1"),
        "carried from the read"
    );
    assert!(input.get("vlan_id").is_none());
}

/// A manifest that changes a segment and its profile in one `apply` sends
/// `replace_segment` and then `replace_profile`, and the profile's
/// `segment_version` is the `replace_segment` response's `version`, not the one
/// `plan` read.
#[tokio::test]
async fn the_profile_follows_the_segment_write_version() {
    let fake = Fake::start().await;
    let id = fake.seed_segment("access", "lab", 10, Some(1), &["lab-in"], 4);
    fake.seed_profile(id, 1800, 2);
    let manifest = ManagementManifest::new()
        .with_network_segment(NetworkSegmentSpec::access("lab", "default", "lab", 20, 1))
        .with_network_profile(NetworkProfileSpec::new("lab", 900));

    let report = fake.client.manifest().apply(&manifest).await.unwrap();
    assert!(report.is_complete(), "the apply has a failing step");

    let writes = fake.writes();
    assert_eq!(writes.len(), 2);
    assert!(writes[0].path.contains("/segments/"));
    assert!(writes[1].path.contains("/profiles/"));
    assert_eq!(writes[0].body["version"], json!(4), "as plan read it");
    assert_eq!(
        writes[1].body["segment_version"],
        json!(5),
        "the replace_segment response's version, not the 4 plan read"
    );
}

// ── a 409 is that action's failure ──────────────────────────────────────────

/// A `409` with `stale_version` on a network write makes exactly one request,
/// stops the `apply` (later actions are not attempted), and the outcome exposes
/// `reason_code`; a `409` with `already_exists` and `duplicate_vlan` does the
/// same.
#[tokio::test]
async fn a_409_stops_the_apply_and_the_outcome_exposes_the_reason_code() {
    for (error, code, replace) in [
        ("conflict", "stale_version", true),
        ("already_exists", "duplicate_vlan", false),
    ] {
        let fake = Fake::start().await;
        let id = fake.seed_segment("access", "lab", 10, Some(1), &["lab-in"], 4);
        fake.seed_profile(id, 1800, 2);
        let (manifest, verb, suffix) = if replace {
            // An Update of the existing segment, then of its profile.
            (
                ManagementManifest::new()
                    .with_network_segment(NetworkSegmentSpec::access(
                        "lab", "default", "lab", 20, 1,
                    ))
                    .with_network_profile(NetworkProfileSpec::new("lab", 900)),
                "PUT",
                id.to_string(),
            )
        } else {
            // A Create of a new segment, then of its profile.
            (
                ManagementManifest::new()
                    .with_network_segment(NetworkSegmentSpec::access(
                        "new", "default", "new", 20, 2,
                    ))
                    .with_network_profile(NetworkProfileSpec::new("new", 900)),
                "POST",
                "/segments".to_string(),
            )
        };
        fake.refuse_next(
            verb,
            &suffix,
            409,
            json!({ "error": error, "message": "refused", "reason_code": code }),
        );

        let report = fake.client.manifest().apply(&manifest).await.unwrap();

        assert!(!report.is_complete());
        assert_eq!(report.reason_code(), Some(code));
        let (failed, _) = report.failure().unwrap();
        assert_eq!(failed.target, Target::NetworkSegment);
        let outcomes: Vec<&Outcome> = report.steps.iter().map(|(_, o)| o).collect();
        assert!(
            matches!(outcomes[0], Outcome::Conflict { reason_code: Some(c), .. } if c == code),
            "the first step is not a conflict carrying the expected reason code"
        );
        assert_eq!(outcomes[0].reason_code(), Some(code));
        assert!(
            matches!(outcomes[1], Outcome::NotAttempted),
            "later actions are not attempted"
        );
        // Retry is ON for this client, and the write still went out once.
        let writes = fake.writes();
        assert_eq!(writes.len(), 1, "exactly one write, never retried");
    }
}

// ── pruning ─────────────────────────────────────────────────────────────────

/// Nothing is deleted. This SDK offers no pruning for any namespace (§27.6
/// rule 4), so a segment and a profile the manifest does not state are left
/// alone, `plan` emits no `Delete`, and the policy is never deleted.
#[tokio::test]
async fn nothing_is_pruned() {
    let fake = Fake::start().await;
    let id = fake.seed_segment("access", "orphan", 10, Some(1), &[], 1);
    fake.seed_profile(id, 600, 1);
    let manifest = ManagementManifest::new().with_network_segment(lab());

    let report = fake.client.manifest().apply(&manifest).await.unwrap();

    assert!(report.is_complete());
    assert!(fake.writes().iter().all(|w| w.verb != "DELETE"));
    assert_eq!(
        fake.state.lock().unwrap().segments.len(),
        2,
        "the unstated segment is still there"
    );
    assert_eq!(
        fake.state.lock().unwrap().profiles.len(),
        1,
        "and its profile"
    );
    let plan = fake.client.manifest().plan(&manifest).await.unwrap();
    assert!(plan.is_converged());
}

// ── refused before any request ──────────────────────────────────────────────

/// Two segments with one site, kind and name; a profile whose `segment` names no
/// segment spec; two profiles for one segment; a segment listing one Filter-Id
/// twice — each refused, at `plan` and at `apply`, with zero wire calls.
#[tokio::test]
async fn unreconcilable_manifests_are_refused_with_zero_wire_calls() {
    let cases: Vec<(&str, ManagementManifest)> = vec![
        (
            "one natural key twice",
            ManagementManifest::new()
                .with_network_segment(NetworkSegmentSpec::access("a", "default", "lab", 20, 1))
                .with_network_segment(NetworkSegmentSpec::access("b", "default", "lab", 30, 2)),
        ),
        (
            "a profile naming no segment",
            ManagementManifest::new().with_network_profile(NetworkProfileSpec::new("nowhere", 900)),
        ),
        (
            "two profiles for one segment",
            ManagementManifest::new()
                .with_network_segment(lab())
                .with_network_profile(NetworkProfileSpec::new("lab", 900))
                .with_network_profile(NetworkProfileSpec::new("lab", 1800)),
        ),
        (
            "a Filter-Id twice",
            ManagementManifest::new()
                .with_network_segment(lab().with_filter_ids(["lab-in", "lab-out", "lab-in"])),
        ),
        (
            "one segment key twice",
            ManagementManifest::new()
                .with_network_segment(NetworkSegmentSpec::access("a", "default", "one", 20, 1))
                .with_network_segment(NetworkSegmentSpec::access("a", "default", "two", 30, 2)),
        ),
    ];
    for (name, manifest) in cases {
        let fake = Fake::start().await;
        let planned = fake.client.manifest().plan(&manifest).await;
        let applied = fake.client.manifest().apply(&manifest).await;
        for result in [planned.map(|_| ()), applied.map(|_| ())] {
            let error = result.expect_err(name);
            assert!(
                matches!(error, AxiamError::Network { .. }),
                "{name}: expected a Network error"
            );
        }
        assert!(
            fake.requests().await.is_empty(),
            "{name}: a rejected manifest sends no request"
        );
    }
}

// ── kind and filter_ids ─────────────────────────────────────────────────────

/// A segment whose `kind` is stated as `access` is `NoChange` against a read
/// that says `"access"` and its `create_segment` body carries `"kind":
/// "access"`; a quarantine segment says `"quarantine"`. The SDK has no `zones`
/// value anywhere.
#[tokio::test]
async fn kind_is_the_wire_spelling() {
    let fake = Fake::start().await;
    fake.seed_segment("access", "lab", 20, Some(1), &[], 1);
    let manifest = ManagementManifest::new()
        .with_network_segment(NetworkSegmentSpec::access("lab", "default", "lab", 20, 1))
        .with_network_segment(NetworkSegmentSpec::quarantine(
            "jail", "default", "jail", 999,
        ));

    let plan = fake.client.manifest().plan(&manifest).await.unwrap();
    assert_eq!(plan.actions[0].change, Change::NoChange);
    assert_eq!(plan.actions[1].change, Change::Create);

    fake.client.manifest().apply(&manifest).await.unwrap();
    let writes = fake.writes();
    assert_eq!(writes.len(), 1);
    assert_eq!(writes[0].body["kind"], json!("quarantine"));
    assert!(!writes[0].body.to_string().contains("zones"));
}

/// A segment whose stated `filter_ids` are the read's names in another order is
/// `NoChange` and `apply` makes no write for it; a segment `Update` caused by
/// another member sends `filter_ids` in the **order the manifest states**; a
/// `Create` does the same.
#[tokio::test]
async fn filter_ids_compare_as_a_set_and_are_sent_in_the_stated_order() {
    let fake = Fake::start().await;
    fake.seed_segment("access", "lab", 20, Some(1), &["a", "b", "c"], 1);
    let reordered =
        ManagementManifest::new().with_network_segment(lab().with_filter_ids(["c", "a", "b"]));
    let report = fake.client.manifest().apply(&reordered).await.unwrap();
    assert!(report.is_complete());
    assert!(
        fake.writes().is_empty(),
        "a reorder alone is never an Update"
    );

    // Another member changes (the VLAN): the names go out as the manifest states them.
    let changed = ManagementManifest::new()
        .with_network_segment(
            NetworkSegmentSpec::access("lab", "default", "lab", 21, 1)
                .with_filter_ids(["c", "a", "b"]),
        )
        .with_network_segment(
            NetworkSegmentSpec::access("fresh", "default", "fresh", 40, 2)
                .with_filter_ids(["z", "y"]),
        );
    fake.client.manifest().apply(&changed).await.unwrap();
    let writes = fake.writes();
    assert_eq!(writes[0].body["filter_ids"], json!(["c", "a", "b"]));
    assert_eq!(writes[1].body["filter_ids"], json!(["z", "y"]));
}

// ── a clamped profile ───────────────────────────────────────────────────────

/// A profile read with `session_timeout_clamped: true` and a timeout equal to
/// the cap: a manifest stating that value is `NoChange`; a manifest stating a
/// value above the cap is an `Update` in `plan`, and `apply` of it sends exactly
/// one `replace_profile`, receives `403 authorization_denied`, stops without a
/// retry, does not attempt later actions, and the outcome carries the server's
/// message.
#[tokio::test]
async fn a_clamped_profile_is_judged_on_the_read() {
    let fake = Fake::start().await;
    {
        let mut s = fake.state.lock().unwrap();
        s.policy_max = 900; // lowered after the profile below was stored at 3600
    }
    let one = fake.seed_segment("access", "lab", 20, Some(1), &["lab-in"], 1);
    let two = fake.seed_segment("access", "lab2", 21, Some(2), &["lab-in"], 1);
    // Stored at 3600, read back clamped to the cap.
    {
        let mut s = fake.state.lock().unwrap();
        for id in [one, two] {
            let profile = effective_profile(
                &json!(id),
                &json!({ "session_timeout_secs": 3600, "idle_timeout_secs": 600, "filter_id": "lab-in", "service_type": "framed_user" }),
                1,
                900,
            );
            assert_eq!(profile["session_timeout_clamped"], json!(true));
            s.profiles.push(profile);
        }
    }

    // Stating the cap is NoChange: the stored value is neither restored nor rewritten.
    let at_cap = ManagementManifest::new()
        .with_network_segment(lab())
        .with_network_profile(NetworkProfileSpec::new("lab", 900));
    let plan = fake.client.manifest().plan(&at_cap).await.unwrap();
    assert!(plan.is_converged(), "a profile at the cap is not a change");
    fake.client.manifest().apply(&at_cap).await.unwrap();
    assert!(fake.writes().is_empty());

    // Stating a value above the cap differs from the read.
    let above = ManagementManifest::new()
        .with_network_segment(lab())
        .with_network_segment(NetworkSegmentSpec::access("lab2", "default", "lab2", 21, 2))
        .with_network_profile(NetworkProfileSpec::new("lab", 1800))
        .with_network_profile(NetworkProfileSpec::new("lab2", 1800));
    let plan = fake.client.manifest().plan(&above).await.unwrap();
    assert_eq!(
        plan.change_count(),
        2,
        "both profiles above the cap differ from the read"
    );

    fake.refuse_next(
        "PUT",
        &format!("/profiles/{one}"),
        403,
        json!({
            "error": "authorization_denied",
            "message": "session_timeout_secs is above the tenant's cap of 900",
        }),
    );
    let report = fake.client.manifest().apply(&above).await.unwrap();

    assert!(!report.is_complete());
    let (failed, message) = report.failure().unwrap();
    assert_eq!(failed.target, Target::NetworkProfile);
    assert!(
        message.contains("above the tenant's cap of 900"),
        "the failure message does not name the tenant cap"
    );
    assert!(
        matches!(
            report
                .steps
                .iter()
                .find(|(a, _)| a.key == "lab" && a.target == Target::NetworkProfile)
                .unwrap()
                .1,
            Outcome::Failed(_)
        ),
        "a 403 is a plain failure, reported as given"
    );
    let later = report
        .steps
        .iter()
        .find(|(a, _)| a.key == "lab2" && a.target == Target::NetworkProfile)
        .unwrap();
    assert!(
        matches!(later.1, Outcome::NotAttempted),
        "the later profile action is not attempted"
    );
    let writes = fake.writes();
    assert_eq!(writes.len(), 1, "exactly one replace_profile, no retry");
    assert_eq!(
        writes[0].body["profile"]["session_timeout_secs"],
        json!(1800),
        "nothing lowered to the cap by the SDK"
    );
}

/// An `Update` that does not state the timeout carries the read's — the clamped
/// — value (§36.3 rule 6), and an unstated timeout is no difference.
#[tokio::test]
async fn an_update_of_a_clamped_profile_carries_the_clamped_timeout() {
    let fake = Fake::start().await;
    fake.state.lock().unwrap().policy_max = 900;
    let id = fake.seed_segment("access", "lab", 20, Some(1), &["lab-in", "lab-out"], 1);
    {
        let mut s = fake.state.lock().unwrap();
        s.profiles.push(effective_profile(
            &json!(id),
            &json!({ "session_timeout_secs": 3600, "filter_id": "lab-in" }),
            1,
            900,
        ));
    }
    let manifest = ManagementManifest::new()
        .with_network_segment(lab())
        .with_network_profile(NetworkProfileSpec::new("lab", 900).with_filter_id("lab-out"));

    let report = fake.client.manifest().apply(&manifest).await.unwrap();
    assert!(report.is_complete(), "the apply has a failing step");
    let writes = fake.writes();
    assert_eq!(writes.len(), 1);
    assert_eq!(
        writes[0].body["profile"]["session_timeout_secs"],
        json!(900)
    );
    assert_eq!(writes[0].body["profile"]["filter_id"], json!("lab-out"));
}
