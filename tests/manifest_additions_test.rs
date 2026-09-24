//! CONTRACT.md §27.9 "Manifest additions" (contract 1.51, §27.6.1).
//!
//! These run against a small **stateful** fake of the tenant rather than
//! canned responses, because the property that matters — `apply(m)` then
//! `plan(m)` is all `NoChange` (§27.6 rule 6) — only means something when the
//! second read sees what the first write did. The fake keeps the server's
//! rules that the manifest depends on: one assignment per (subject, role), a
//! resource's metadata replaced whole, `{}` for a resource created without
//! any, and a `client_secret` returned by `create` and never again.

#![cfg(feature = "rest")]

mod management_support;

use std::sync::{Arc, Mutex};

use axiam_sdk::management::manifest::{
    Change, GroupSpec, ManagementManifest, Outcome, ResourceSpec, RoleBinding, RoleSpec,
    ServiceAccountSpec, Target, UserSpec,
};
use serde_json::{Value, json};
use uuid::Uuid;
use wiremock::matchers::any;
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

use management_support::{TENANT_ID, logged_in_client};

const NOW: &str = "2026-09-24T00:00:00Z";

// ---------------------------------------------------------------------------
// The fake tenant
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct Assignment {
    kind: &'static str, // "users" | "groups" | "service-accounts"
    role: Uuid,
    subject: Uuid,
    resource_id: Option<Uuid>,
    inherit: bool,
    tenant_scope: Option<Vec<Uuid>>,
}

#[derive(Default)]
struct State {
    resources: Vec<Value>,
    roles: Vec<Value>,
    groups: Vec<Value>,
    users: Vec<Value>,
    service_accounts: Vec<Value>,
    assignments: Vec<Assignment>,
    /// Refuse an assign that names this resource, with a 400 — the fault the
    /// binding-update restore is tested against.
    refuse_assign_at: Option<Uuid>,
}

#[derive(Clone, Default)]
struct Tenant(Arc<Mutex<State>>);

fn page(items: &[Value]) -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_json(json!({
        "items": items, "total": items.len(), "offset": 0, "limit": 200,
    }))
}

fn user_json(id: Uuid, username: &str) -> Value {
    json!({
        "id": id, "tenant_id": TENANT_ID, "username": username,
        "email": format!("{username}@example.com"), "status": "Active", "mfa_enabled": false,
        "email_verified": true, "metadata": {}, "created_at": NOW, "updated_at": NOW,
        "failed_login_attempts": 0, "is_locked": false,
    })
}

fn sa_json(id: Uuid, name: &str, description: Option<&str>) -> Value {
    json!({
        "id": id, "tenant_id": TENANT_ID, "name": name, "description": description,
        "client_id": format!("client-{id}"), "status": "Active",
        "created_at": NOW, "updated_at": NOW,
    })
}

fn id_of(v: &Value) -> Uuid {
    Uuid::parse_str(v["id"].as_str().unwrap()).unwrap()
}

impl Tenant {
    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.0.lock().unwrap()
    }

    fn seed_resource(&self, name: &str, metadata: Value) -> Uuid {
        let id = Uuid::new_v4();
        self.state().resources.push(json!({
            "id": id, "tenant_id": TENANT_ID, "name": name, "resource_type": "site",
            "parent_id": null, "metadata": metadata, "created_at": NOW, "updated_at": NOW,
        }));
        id
    }

    fn seed_role(&self, name: &str, is_global: bool) -> Uuid {
        let id = Uuid::new_v4();
        self.state().roles.push(json!({
            "id": id, "tenant_id": TENANT_ID, "name": name, "description": name,
            "is_global": is_global, "created_at": NOW, "updated_at": NOW,
        }));
        id
    }

    fn seed_user(&self, username: &str) -> Uuid {
        let id = Uuid::new_v4();
        self.state().users.push(user_json(id, username));
        id
    }

    fn seed_service_account(&self, name: &str) -> Uuid {
        let id = Uuid::new_v4();
        self.state().service_accounts.push(sa_json(id, name, None));
        id
    }

    fn seed_assignment(&self, a: Assignment) {
        self.state().assignments.push(a);
    }

    fn assignment_json(&self, s: &State, a: &Assignment) -> Value {
        let (field, subject) = match a.kind {
            "users" => (
                "user",
                s.users.iter().find(|u| id_of(u) == a.subject).cloned(),
            ),
            "groups" => (
                "group",
                s.groups.iter().find(|g| id_of(g) == a.subject).cloned(),
            ),
            _ => (
                "service_account",
                s.service_accounts
                    .iter()
                    .find(|x| id_of(x) == a.subject)
                    .cloned(),
            ),
        };
        let mut v = json!({
            field: subject.unwrap(), "resource_id": a.resource_id, "inherit": a.inherit,
        });
        if let Some(scope) = &a.tenant_scope {
            v["tenant_scope"] = json!(scope);
        }
        v
    }
}

impl Respond for Tenant {
    fn respond(&self, req: &Request) -> ResponseTemplate {
        let segments: Vec<&str> = req
            .url
            .path()
            .trim_start_matches("/api/v1/")
            .split('/')
            .collect();
        let body: Value = serde_json::from_slice(&req.body).unwrap_or(Value::Null);
        let method = req.method.as_str();
        let mut s = self.state();
        match (method, segments.as_slice()) {
            ("GET", ["resources"]) => page(&s.resources),
            ("GET", ["resources", _, "scopes"]) => {
                ResponseTemplate::new(200).set_body_json(json!([]))
            }
            ("POST", ["resources"]) => {
                let id = Uuid::new_v4();
                let v = json!({
                    "id": id, "tenant_id": TENANT_ID, "name": body["name"],
                    "resource_type": body["resource_type"], "parent_id": body["parent_id"],
                    // The server stores `{}` for a resource created without any.
                    "metadata": if body["metadata"].is_null() { json!({}) } else { body["metadata"].clone() },
                    "created_at": NOW, "updated_at": NOW,
                });
                s.resources.push(v.clone());
                ResponseTemplate::new(201).set_body_json(v)
            }
            ("PUT", ["resources", id]) => {
                let id = Uuid::parse_str(id).unwrap();
                let r = s.resources.iter_mut().find(|r| id_of(r) == id).unwrap();
                // An update carrying metadata replaces the whole object.
                for field in ["metadata", "resource_type"] {
                    if !body[field].is_null() {
                        r[field] = body[field].clone();
                    }
                }
                ResponseTemplate::new(200).set_body_json(r.clone())
            }
            ("GET", ["permissions"]) => page(&[]),
            ("GET", ["roles"]) => page(&s.roles),
            ("POST", ["roles"]) => {
                let id = Uuid::new_v4();
                let v = json!({
                    "id": id, "tenant_id": TENANT_ID, "name": body["name"],
                    "description": body["description"], "is_global": body["is_global"],
                    "created_at": NOW, "updated_at": NOW,
                });
                s.roles.push(v.clone());
                ResponseTemplate::new(201).set_body_json(v)
            }
            ("GET", ["roles", _, "permissions"]) => {
                ResponseTemplate::new(200).set_body_json(json!([]))
            }
            ("GET", ["roles", role, kind]) => {
                let role = Uuid::parse_str(role).unwrap();
                let rows: Vec<Value> = s
                    .assignments
                    .iter()
                    .filter(|a| a.role == role && a.kind == *kind)
                    .map(|a| self.assignment_json(&s, a))
                    .collect();
                ResponseTemplate::new(200).set_body_json(rows)
            }
            ("POST", ["roles", role, kind]) => {
                let role = Uuid::parse_str(role).unwrap();
                let subject_field = match *kind {
                    "users" => "user_id",
                    "groups" => "group_id",
                    _ => "service_account_id",
                };
                let subject = Uuid::parse_str(body[subject_field].as_str().unwrap()).unwrap();
                let resource_id = body["resource_id"]
                    .as_str()
                    .map(|r| Uuid::parse_str(r).unwrap());
                if resource_id.is_some() && resource_id == s.refuse_assign_at {
                    return ResponseTemplate::new(400)
                        .set_body_string("resource refuses this assignment");
                }
                // has_role is UNIQUE(in, out): one assignment per subject and role.
                if s.assignments
                    .iter()
                    .any(|a| a.role == role && a.subject == subject)
                {
                    return ResponseTemplate::new(409).set_body_string("already assigned");
                }
                let kind = match *kind {
                    "users" => "users",
                    "groups" => "groups",
                    _ => "service-accounts",
                };
                s.assignments.push(Assignment {
                    kind,
                    role,
                    subject,
                    resource_id,
                    inherit: body["inherit"].as_bool().unwrap_or(true),
                    tenant_scope: body["tenant_scope"].as_array().map(|a| {
                        a.iter()
                            .map(|t| Uuid::parse_str(t.as_str().unwrap()).unwrap())
                            .collect()
                    }),
                });
                ResponseTemplate::new(204)
            }
            ("DELETE", ["roles", role, _kind, subject]) => {
                let role = Uuid::parse_str(role).unwrap();
                let subject = Uuid::parse_str(subject).unwrap();
                let resource = req
                    .url
                    .query_pairs()
                    .find(|(k, _)| k == "resource_id")
                    .map(|(_, v)| Uuid::parse_str(&v).unwrap());
                let before = s.assignments.len();
                s.assignments.retain(|a| {
                    !(a.role == role && a.subject == subject && a.resource_id == resource)
                });
                if s.assignments.len() == before {
                    ResponseTemplate::new(404)
                } else {
                    ResponseTemplate::new(204)
                }
            }
            ("GET", ["groups"]) => page(&s.groups),
            ("GET", ["groups", _, "members"]) => page(&[]),
            ("POST", ["groups"]) => {
                let id = Uuid::new_v4();
                let v = json!({
                    "id": id, "tenant_id": TENANT_ID, "name": body["name"],
                    "description": body["description"], "metadata": {},
                    "created_at": NOW, "updated_at": NOW,
                });
                s.groups.push(v.clone());
                ResponseTemplate::new(201).set_body_json(v)
            }
            ("GET", ["users"]) => page(&s.users),
            ("POST", ["users"]) => {
                let v = user_json(Uuid::new_v4(), body["username"].as_str().unwrap());
                s.users.push(v.clone());
                ResponseTemplate::new(201).set_body_json(v)
            }
            ("GET", ["service-accounts"]) => page(&s.service_accounts),
            ("POST", ["service-accounts"]) => {
                let id = Uuid::new_v4();
                let v = sa_json(
                    id,
                    body["name"].as_str().unwrap(),
                    body["description"].as_str(),
                );
                s.service_accounts.push(v.clone());
                let mut created = v;
                // Returned here, and by nothing else.
                created["client_secret"] = json!(format!("secret-of-{id}"));
                ResponseTemplate::new(201).set_body_json(created)
            }
            ("PUT", ["service-accounts", id]) => {
                let id = Uuid::parse_str(id).unwrap();
                let a = s
                    .service_accounts
                    .iter_mut()
                    .find(|a| id_of(a) == id)
                    .unwrap();
                if !body["description"].is_null() {
                    a["description"] = body["description"].clone();
                }
                ResponseTemplate::new(200).set_body_json(a.clone())
            }
            _ => ResponseTemplate::new(599)
                .set_body_string(format!("fake: unhandled {method} {}", req.url.path())),
        }
    }
}

async fn tenant_server() -> (MockServer, Tenant, axiam_sdk::client::AxiamClient) {
    let server = MockServer::start().await;
    let client = logged_in_client(&server).await;
    let tenant = Tenant::default();
    Mock::given(any())
        .respond_with(tenant.clone())
        .with_priority(u8::MAX)
        .mount(&server)
        .await;
    (server, tenant, client)
}

/// Manifest-issued requests, in order, excluding the harness login and JWKS.
async fn writes(server: &MockServer) -> Vec<Request> {
    server
        .received_requests()
        .await
        .unwrap_or_default()
        .into_iter()
        .filter(|r| r.method.as_str() != "GET")
        .filter(|r| !r.url.path().starts_with("/api/v1/auth/"))
        .collect()
}

async fn requests_since(server: &MockServer, mark: usize) -> Vec<Request> {
    server
        .received_requests()
        .await
        .unwrap_or_default()
        .into_iter()
        .skip(mark)
        .collect()
}

async fn mark(server: &MockServer) -> usize {
    server.received_requests().await.unwrap_or_default().len()
}

fn body(r: &Request) -> Value {
    serde_json::from_slice(&r.body).unwrap()
}

fn keys(v: &Value) -> Vec<String> {
    let mut k: Vec<String> = v.as_object().unwrap().keys().cloned().collect();
    k.sort();
    k
}

// ---------------------------------------------------------------------------
// §27.6.1 item 1 — metadata
// ---------------------------------------------------------------------------

/// `metadata` round-trips: apply, then plan, is all `NoChange`; changing one
/// key is an `Update` whose body carries the **whole** object.
#[tokio::test]
async fn metadata_round_trips_and_an_update_sends_the_whole_object() {
    let (server, _tenant, client) = tenant_server().await;
    let first = json!({ "region": "eu", "floor": 3 });
    let manifest = ManagementManifest::new()
        .with_resource(ResourceSpec::new("site", "site-1", "site").with_metadata(first.clone()));

    let report = client.manifest().apply(&manifest).await.unwrap();
    assert!(report.is_complete(), "{:?}", report.failure());
    let created = writes(&server).await;
    assert_eq!(body(&created[0])["metadata"], first, "sent on Create");
    assert!(
        client
            .manifest()
            .plan(&manifest)
            .await
            .unwrap()
            .is_converged(),
        "§27.6 rule 6"
    );

    let second = json!({ "region": "eu", "floor": 4 });
    let changed = ManagementManifest::new()
        .with_resource(ResourceSpec::new("site", "site-1", "site").with_metadata(second.clone()));
    let plan = client.manifest().plan(&changed).await.unwrap();
    assert_eq!(plan.actions[0].change, Change::Update);

    let at = mark(&server).await;
    client.manifest().apply(&changed).await.unwrap();
    let update = requests_since(&server, at)
        .await
        .into_iter()
        .find(|r| r.method.as_str() == "PUT")
        .expect("an update");
    let sent = body(&update);
    assert_eq!(
        keys(&sent),
        vec!["metadata"],
        "sparse: only the drifted field"
    );
    assert_eq!(sent["metadata"], second, "the whole object, never a merge");
    assert!(
        client
            .manifest()
            .plan(&changed)
            .await
            .unwrap()
            .is_converged()
    );
}

/// A stated `{}` equals what the server stores for none; an unstated metadata
/// is silent whatever the server holds (§27.6 rule 3).
#[tokio::test]
async fn an_empty_or_unstated_metadata_is_not_drift() {
    let (_server, tenant, client) = tenant_server().await;
    tenant.seed_resource("bare", json!({}));
    tenant.seed_resource("rich", json!({ "hand": "made" }));

    let plan = client
        .manifest()
        .plan(
            &ManagementManifest::new()
                .with_resource(ResourceSpec::new("a", "bare", "site").with_metadata(json!({})))
                .with_resource(ResourceSpec::new("b", "rich", "site")),
        )
        .await
        .unwrap();
    assert!(plan.is_converged(), "{:?}", plan.actions);
}

// ---------------------------------------------------------------------------
// §27.6.1 item 2 — two-shape bindings
// ---------------------------------------------------------------------------

/// A resource-scoped binding with `inherit: false` sends `resource_id` and
/// `inherit: false`; the same binding inheriting sends **no** `inherit` key.
#[tokio::test]
async fn a_scoped_binding_sends_inherit_only_when_false() {
    let (server, _tenant, client) = tenant_server().await;
    let manifest = ManagementManifest::new()
        .with_resource(ResourceSpec::new("site", "site-1", "site"))
        .with_role(RoleSpec::new("resident", "Resident", "Lives here"))
        .with_role(RoleSpec::new("guest", "Guest", "Visits"))
        .with_group(
            GroupSpec::new("g", "Residents", "All residents").with_roles([
                RoleBinding::at_only("resident", "site"),
                RoleBinding::at("guest", "site"),
            ]),
        );

    let report = client.manifest().apply(&manifest).await.unwrap();
    assert!(report.is_complete(), "{:?}", report.failure());

    let assigns: Vec<Value> = writes(&server)
        .await
        .iter()
        .filter(|r| r.url.path().ends_with("/groups") && r.url.path().starts_with("/api/v1/roles/"))
        .map(body)
        .collect();
    assert_eq!(assigns.len(), 2);
    assert_eq!(assigns[0]["inherit"], json!(false));
    assert!(assigns[0]["resource_id"].is_string());
    assert_eq!(
        keys(&assigns[1]),
        vec!["group_id", "resource_id"],
        "an inheriting binding carries no inherit key"
    );
    assert!(
        client
            .manifest()
            .plan(&manifest)
            .await
            .unwrap()
            .is_converged()
    );
}

/// Changing a binding's resource is unassign then assign, in that order, and
/// the server binding's `tenant_scope` survives the change.
#[tokio::test]
async fn a_changed_binding_is_unassign_then_assign_and_keeps_tenant_scope() {
    let (server, tenant, client) = tenant_server().await;
    let old_site = tenant.seed_resource("site-1", json!({}));
    tenant.seed_resource("site-2", json!({}));
    let role = tenant.seed_role("Concierge", false);
    let user = tenant.seed_user("ann");
    let scope = Uuid::new_v4();
    tenant.seed_assignment(Assignment {
        kind: "users",
        role,
        subject: user,
        resource_id: Some(old_site),
        inherit: true,
        tenant_scope: Some(vec![scope]),
    });
    let manifest = ManagementManifest::new()
        .with_resource(ResourceSpec::new("s1", "site-1", "site"))
        .with_resource(ResourceSpec::new("s2", "site-2", "site"))
        .with_role(RoleSpec::new("concierge", "Concierge", "Concierge"))
        .with_user(
            UserSpec::new("ann", "ann", "ann@example.com")
                .with_roles([RoleBinding::at("concierge", "s2")]),
        );

    let plan = client.manifest().plan(&manifest).await.unwrap();
    let binding = plan
        .actions
        .iter()
        .find(|a| a.target == Target::UserRole)
        .unwrap();
    assert_eq!(binding.change, Change::Update);

    let at = mark(&server).await;
    let report = client.manifest().apply(&manifest).await.unwrap();
    assert!(report.is_complete(), "{:?}", report.failure());
    let sent: Vec<Request> = requests_since(&server, at)
        .await
        .into_iter()
        .filter(|r| r.method.as_str() != "GET")
        .collect();
    assert_eq!(sent.len(), 2, "one unassign, one assign");
    assert_eq!(sent[0].method.as_str(), "DELETE", "unassign first");
    assert!(
        sent[0]
            .url
            .query()
            .unwrap_or("")
            .contains(&old_site.to_string())
    );
    assert_eq!(sent[1].method.as_str(), "POST", "then assign");
    assert_eq!(
        body(&sent[1])["tenant_scope"],
        json!([scope]),
        "§27.6.1: tenant_scope is carried across, not dropped"
    );
    assert!(
        client
            .manifest()
            .plan(&manifest)
            .await
            .unwrap()
            .is_converged()
    );
}

/// When the re-assignment fails, the previous binding is assigned again and
/// both results are reported.
#[tokio::test]
async fn a_failed_reassignment_restores_the_previous_binding() {
    let (_server, tenant, client) = tenant_server().await;
    let old_site = tenant.seed_resource("site-1", json!({}));
    let new_site = tenant.seed_resource("site-2", json!({}));
    let role = tenant.seed_role("Concierge", false);
    let user = tenant.seed_user("ann");
    let scope = Uuid::new_v4();
    tenant.seed_assignment(Assignment {
        kind: "users",
        role,
        subject: user,
        resource_id: Some(old_site),
        inherit: false,
        tenant_scope: Some(vec![scope]),
    });
    tenant.state().refuse_assign_at = Some(new_site);
    let manifest = ManagementManifest::new()
        .with_resource(ResourceSpec::new("s1", "site-1", "site"))
        .with_resource(ResourceSpec::new("s2", "site-2", "site"))
        .with_role(RoleSpec::new("concierge", "Concierge", "Concierge"))
        .with_user(
            UserSpec::new("ann", "ann", "ann@example.com")
                .with_roles([RoleBinding::at("concierge", "s2")]),
        );

    let report = client.manifest().apply(&manifest).await.unwrap();

    let (_, outcome) = report
        .steps
        .iter()
        .find(|(a, _)| a.target == Target::UserRole)
        .unwrap();
    match outcome {
        Outcome::BindingUpdateFailed { error, restore } => {
            assert!(error.contains("refuses"), "{error}");
            assert_eq!(restore, &Ok(()), "the previous binding is back");
        }
        other => panic!("expected BindingUpdateFailed, got {other:?}"),
    }
    assert!(!report.is_complete());
    let state = tenant.state();
    let held = state
        .assignments
        .iter()
        .find(|a| a.subject == user)
        .unwrap();
    assert_eq!(held.resource_id, Some(old_site));
    assert!(!held.inherit, "same inherit");
    assert_eq!(held.tenant_scope, Some(vec![scope]), "same tenant_scope");
}

/// One role bound twice to one subject is a state the server cannot hold —
/// rejected with zero wire calls, naming the subject and the role.
#[tokio::test]
async fn one_role_bound_twice_to_one_subject_is_refused_with_no_wire_call() {
    let (server, _tenant, client) = tenant_server().await;
    let before = mark(&server).await;
    let manifest = ManagementManifest::new()
        .with_resource(ResourceSpec::new("s1", "site-1", "site"))
        .with_resource(ResourceSpec::new("s2", "site-2", "site"))
        .with_role(RoleSpec::new("resident", "Resident", "Lives here"))
        .with_user(UserSpec::new("ann", "ann", "ann@example.com").with_roles([
            RoleBinding::at("resident", "s1"),
            RoleBinding::at("resident", "s2"),
        ]));

    let err = client.manifest().plan(&manifest).await.unwrap_err();
    let text = err.to_string();
    assert!(
        text.contains("\"ann\"") && text.contains("\"resident\""),
        "{text}"
    );
    assert_eq!(mark(&server).await, before, "zero wire calls");

    // Plain and scoped at once is the same impossibility.
    let mixed = ManagementManifest::new()
        .with_resource(ResourceSpec::new("s1", "site-1", "site"))
        .with_role(RoleSpec::new("resident", "Resident", "Lives here"))
        .with_group(GroupSpec::new("g", "G", "G").with_roles([
            RoleBinding::from("resident"),
            RoleBinding::at("resident", "s1"),
        ]));
    assert!(client.manifest().plan(&mixed).await.is_err());
    assert_eq!(mark(&server).await, before);
}

/// A global role bound with `inherit: false` is refused by the server; the
/// manifest says so first when the role is in it.
#[tokio::test]
async fn a_global_role_bound_here_only_is_refused_client_side() {
    let (server, _tenant, client) = tenant_server().await;
    let before = mark(&server).await;
    let manifest = ManagementManifest::new()
        .with_resource(ResourceSpec::new("s1", "site-1", "site"))
        .with_role(RoleSpec::new("admin", "Admin", "Everything").global())
        .with_group(
            GroupSpec::new("g", "G", "G").with_roles([RoleBinding::at_only("admin", "s1")]),
        );
    assert!(client.manifest().plan(&manifest).await.is_err());
    assert_eq!(mark(&server).await, before);
}

/// A plain binding whose server assignment is scoped is an `Update`: the
/// string shape means "no resource" (§27.6.1 item 2).
#[tokio::test]
async fn a_plain_binding_over_a_scoped_assignment_is_an_update() {
    let (_server, tenant, client) = tenant_server().await;
    let site = tenant.seed_resource("site-1", json!({}));
    let role = tenant.seed_role("Resident", false);
    let user = tenant.seed_user("ann");
    tenant.seed_assignment(Assignment {
        kind: "users",
        role,
        subject: user,
        resource_id: Some(site),
        inherit: true,
        tenant_scope: None,
    });
    let plan = client
        .manifest()
        .plan(
            &ManagementManifest::new()
                .with_role(RoleSpec::new("resident", "Resident", "Resident"))
                .with_user(UserSpec::new("ann", "ann", "ann@example.com").with_roles(["resident"])),
        )
        .await
        .unwrap();
    let binding = plan
        .actions
        .iter()
        .find(|a| a.target == Target::UserRole)
        .unwrap();
    assert_eq!(binding.change, Change::Update);
}

// ---------------------------------------------------------------------------
// §27.6.1 item 3 and §27.5 rule 5 — service accounts
// ---------------------------------------------------------------------------

/// A service-account `Create` outcome carries `client_secret` as
/// `Sensitive<T>` — and still does when a later action of the same `apply`
/// fails. A second `apply` is `NoChange` and never rotates the secret.
#[tokio::test]
async fn a_created_service_accounts_secret_survives_a_later_failure_and_is_never_rotated() {
    let (server, tenant, client) = tenant_server().await;
    let site = tenant.seed_resource("site-1", json!({}));
    tenant.state().refuse_assign_at = Some(site);
    let manifest = ManagementManifest::new()
        .with_resource(ResourceSpec::new("s1", "site-1", "site"))
        .with_role(RoleSpec::new("gate", "Gate", "Opens the gate"))
        .with_service_account(
            ServiceAccountSpec::new("ctl", "gate-controller")
                .with_description("Opens the gate")
                .with_roles([RoleBinding::at("gate", "s1")]),
        );

    let report = client.manifest().apply(&manifest).await.unwrap();

    assert!(
        !report.is_complete(),
        "the binding after the account failed"
    );
    let (action, created) = report
        .created_service_accounts()
        .next()
        .expect("the secret is on the report despite the later failure");
    assert_eq!(action.target, Target::ServiceAccount);
    assert!(created.client_secret.expose().starts_with("secret-of-"));
    let rendered = format!("{report:?}");
    assert!(
        !rendered.contains("secret-of-"),
        "§7: the secret never reaches Debug: {rendered}"
    );
    // Ordering (§27.6 rule 5): the account before its binding.
    let account_at = report
        .steps
        .iter()
        .position(|(a, _)| a.target == Target::ServiceAccount);
    let binding_at = report
        .steps
        .iter()
        .position(|(a, _)| a.target == Target::ServiceAccountRole);
    assert!(account_at < binding_at);

    // Fix the cause and re-apply: the account is NoChange, and nothing rotates.
    tenant.state().refuse_assign_at = None;
    let report = client.manifest().apply(&manifest).await.unwrap();
    assert!(report.is_complete(), "{:?}", report.failure());
    let account = report
        .steps
        .iter()
        .find(|(a, _)| a.target == Target::ServiceAccount)
        .unwrap();
    assert_eq!(account.0.change, Change::NoChange);
    assert!(report.created_service_accounts().next().is_none());
    assert!(
        server
            .received_requests()
            .await
            .unwrap_or_default()
            .iter()
            .all(|r| !r.url.path().ends_with("/rotate-secret")),
        "apply never rotates a secret"
    );
    assert!(
        client
            .manifest()
            .plan(&manifest)
            .await
            .unwrap()
            .is_converged()
    );
}

/// The name is the natural key and the server does not enforce it: two
/// existing accounts with the stated name make `plan` fail before any write.
#[tokio::test]
async fn an_ambiguous_service_account_name_fails_plan_before_any_write() {
    let (server, tenant, client) = tenant_server().await;
    tenant.seed_service_account("gate-controller");
    tenant.seed_service_account("gate-controller");
    let manifest = ManagementManifest::new()
        .with_service_account(ServiceAccountSpec::new("ctl", "gate-controller"));

    let err = client.manifest().apply(&manifest).await.unwrap_err();
    assert!(err.to_string().contains("ambiguous"), "{err}");
    assert!(writes(&server).await.is_empty(), "nothing written");
}

/// A stated description that drifts is a sparse `Update` of that field alone;
/// an unstated one is silent.
#[tokio::test]
async fn only_a_stated_description_is_reconciled() {
    let (server, tenant, client) = tenant_server().await;
    tenant.seed_service_account("gate-controller");

    let silent = ManagementManifest::new()
        .with_service_account(ServiceAccountSpec::new("ctl", "gate-controller"));
    assert!(
        client
            .manifest()
            .plan(&silent)
            .await
            .unwrap()
            .is_converged()
    );

    let stated = ManagementManifest::new().with_service_account(
        ServiceAccountSpec::new("ctl", "gate-controller").with_description("Opens the gate"),
    );
    client.manifest().apply(&stated).await.unwrap();
    let update = writes(&server)
        .await
        .into_iter()
        .find(|r| r.method.as_str() == "PUT")
        .unwrap();
    assert_eq!(keys(&body(&update)), vec!["description"]);
    assert!(
        client
            .manifest()
            .plan(&stated)
            .await
            .unwrap()
            .is_converged()
    );
}

/// §27.6 rule 6 over all three additions at once — the test worth more than
/// any other in the section.
#[tokio::test]
async fn apply_then_plan_converges_with_every_addition() {
    let (_server, _tenant, client) = tenant_server().await;
    let manifest = ManagementManifest::new()
        .with_resource(ResourceSpec::new("site", "site-1", "site").with_metadata(json!({ "k": 1 })))
        .with_resource(ResourceSpec::new("flat", "flat-7", "apartment").under("site"))
        .with_role(RoleSpec::new("resident", "Resident", "Lives here"))
        .with_role(RoleSpec::new("concierge", "Concierge", "Runs the site"))
        .with_group(GroupSpec::new("staff", "Staff", "Staff").with_roles(["concierge"]))
        .with_user(
            UserSpec::new("ann", "ann", "ann@example.com")
                .with_initial_password(axiam_sdk::Sensitive::new("pw".into()))
                .with_roles([RoleBinding::at_only("resident", "flat")]),
        )
        .with_service_account(
            ServiceAccountSpec::new("ctl", "gate-controller")
                .with_roles([RoleBinding::at_only("concierge", "site")]),
        );

    let report = client.manifest().apply(&manifest).await.unwrap();
    assert!(report.is_complete(), "{:?}", report.failure());
    let plan = client.manifest().plan(&manifest).await.unwrap();
    assert!(
        plan.is_converged(),
        "{:?}",
        plan.changes().collect::<Vec<_>>()
    );
}

// A tiny guard that the fake itself refuses a second assignment — the
// property the "bound twice" rule is about — so the tests above are not
// passing against a fake more permissive than the server.
#[tokio::test]
async fn the_fake_enforces_one_assignment_per_subject_and_role() {
    let (server, tenant, _client) = tenant_server().await;
    let role = tenant.seed_role("R", false);
    let user = tenant.seed_user("u");
    let http = reqwest::Client::new();
    let url = format!("{}/api/v1/roles/{role}/users", server.uri());
    let statuses: Vec<u16> = {
        let mut out = Vec::new();
        for _ in 0..2 {
            out.push(
                http.post(&url)
                    .json(&json!({ "user_id": user }))
                    .send()
                    .await
                    .unwrap()
                    .status()
                    .as_u16(),
            );
        }
        out
    };
    assert_eq!(statuses, vec![204, 409]);
}
