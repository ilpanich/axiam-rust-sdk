//! CONTRACT §27.6 / §27.9 — the declarative manifest.
//!
//! The assertions here are the ones that decide whether the layer is safe to
//! point at a real tenant: that `plan` writes nothing, that `apply` converges,
//! that a broken manifest is refused before anything has been changed, and
//! that a failure halfway through is reported rather than papered over.

#![cfg(feature = "rest")]

mod management_support;

use axiam_sdk::Sensitive;
use axiam_sdk::client::AxiamClient;
use axiam_sdk::management::manifest::{
    Change, GrantSpec, GroupSpec, ManagementManifest, PermissionSpec, ResourceSpec, RoleSpec,
    ScopeSpec, Target, UserSpec,
};
use serde_json::json;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use management_support::{EXAMPLE_ID, TENANT_ID, logged_in_client};

const NOW: &str = "2026-08-26T00:00:00Z";

fn empty_page() -> String {
    r#"{"items": [], "total": 0, "offset": 0, "limit": 200}"#.to_string()
}

fn resource_json(id: &str, name: &str, parent: Option<&str>) -> serde_json::Value {
    json!({
        "id": id, "tenant_id": TENANT_ID, "name": name, "resource_type": "collection",
        "parent_id": parent, "metadata": {}, "created_at": NOW, "updated_at": NOW,
    })
}

fn role_json(id: &str, name: &str, description: &str) -> serde_json::Value {
    json!({
        "id": id, "tenant_id": TENANT_ID, "name": name, "description": description,
        "is_global": false, "created_at": NOW, "updated_at": NOW,
    })
}

/// A manifest exercising every stage: nested resources, a scope, a permission,
/// a role that grants it, a group holding the role, and a user in the group.
fn full_manifest() -> ManagementManifest {
    ManagementManifest::new()
        .with_resource(ResourceSpec::new("root", "workspace", "collection"))
        .with_resource(
            ResourceSpec::new("docs", "documents", "collection")
                .under("root")
                .with_scope(ScopeSpec::new("draft", "draft", "Unpublished")),
        )
        .with_permission(PermissionSpec::new(
            "read",
            "document:read",
            "Read a document",
        ))
        .with_role(
            RoleSpec::new("editor", "Editor", "Edits documents")
                .granting(GrantSpec::allow("read").scoped_to(["draft"])),
        )
        .with_group(GroupSpec::new("staff", "Staff", "All staff").with_roles(["editor"]))
        .with_user(
            UserSpec::new("alice", "alice", "alice@example.com")
                .with_initial_password(Sensitive::new("correct horse battery staple".into()))
                .in_groups(["staff"]),
        )
}

/// Mount every read a plan performs, all answering "nothing exists yet".
async fn mount_empty_reads(server: &MockServer) {
    for route in [
        "/api/v1/resources",
        "/api/v1/permissions",
        "/api/v1/roles",
        "/api/v1/groups",
        "/api/v1/users",
    ] {
        Mock::given(method("GET"))
            .and(path(route))
            .respond_with(ResponseTemplate::new(200).set_body_raw(empty_page(), "application/json"))
            .mount(server)
            .await;
    }
}

// ---------------------------------------------------------------------------
// §27.6 rule 1 — plan writes nothing
// ---------------------------------------------------------------------------

/// `plan` must issue `GET`s and nothing else.
///
/// This is what makes the layer safe to point at production, so it is asserted
/// on the transport rather than trusted from the code.
#[tokio::test]
async fn plan_issues_no_write() {
    let server = MockServer::start().await;
    let client = logged_in_client(&server).await;
    mount_empty_reads(&server).await;

    let plan = client
        .manifest()
        .plan(&full_manifest())
        .await
        .expect("plan against an empty tenant");

    assert!(plan.change_count() > 0, "an empty tenant needs changes");

    let writes: Vec<String> = server
        .received_requests()
        .await
        .unwrap_or_default()
        .iter()
        .filter(|r| r.method.as_str() != "GET")
        // The harness logs in, which is a POST and not the manifest's doing.
        .filter(|r| !r.url.path().starts_with("/api/v1/auth/"))
        .map(|r| format!("{} {}", r.method, r.url.path()))
        .collect();
    assert!(writes.is_empty(), "§27.6 rule 1: plan wrote: {writes:?}");
}

/// Two plans over unchanged state are equal, in the same order.
///
/// §27.6 rule 8: a plan that reorders between runs cannot be diffed, and
/// diffing it is most of the reason it exists.
#[tokio::test]
async fn plan_is_stable_across_runs() {
    let server = MockServer::start().await;
    let client = logged_in_client(&server).await;
    mount_empty_reads(&server).await;
    let manifest = full_manifest();

    let first = client.manifest().plan(&manifest).await.expect("plan 1");
    let second = client.manifest().plan(&manifest).await.expect("plan 2");
    assert_eq!(first, second);
}

// ---------------------------------------------------------------------------
// §27.6 rule 5 — derived ordering
// ---------------------------------------------------------------------------

/// A parent resource is planned before its child, and a role before its bindings.
#[tokio::test]
async fn a_plan_orders_producers_before_consumers() {
    let server = MockServer::start().await;
    let client = logged_in_client(&server).await;
    mount_empty_reads(&server).await;

    let plan = client
        .manifest()
        .plan(&full_manifest())
        .await
        .expect("plan");
    let index = |target: Target, key: &str| {
        plan.actions
            .iter()
            .position(|a| a.target == target && a.key == key)
            .unwrap_or_else(|| panic!("no {target:?} action for {key:?}"))
    };

    assert!(index(Target::Resource, "root") < index(Target::Resource, "docs"));
    assert!(index(Target::Resource, "docs") < index(Target::Scope, "draft"));
    assert!(index(Target::Permission, "read") < index(Target::Role, "editor"));
    assert!(index(Target::Role, "editor") < index(Target::RoleGrant, "editor"));
    assert!(index(Target::Group, "staff") < index(Target::GroupRole, "staff"));
    assert!(index(Target::User, "alice") < index(Target::GroupMember, "alice"));
}

// ---------------------------------------------------------------------------
// §27.6 rule 2 — validation happens before any request
// ---------------------------------------------------------------------------

/// A dangling cross-reference is refused with **zero** requests made.
#[tokio::test]
async fn a_dangling_reference_is_refused_before_any_request() {
    let server = MockServer::start().await;
    let client = logged_in_client(&server).await;
    let before = server.received_requests().await.unwrap_or_default().len();

    let manifest = ManagementManifest::new().with_role(
        RoleSpec::new("editor", "Editor", "Edits").granting(GrantSpec::allow("nonexistent")),
    );
    let err = client
        .manifest()
        .plan(&manifest)
        .await
        .expect_err("a grant naming no permission is not reconcilable");
    assert!(err.to_string().contains("nonexistent"), "{err}");

    let after = server.received_requests().await.unwrap_or_default().len();
    assert_eq!(before, after, "validation must precede the first read");
}

/// A cycle in the resource parent graph is refused, not looped on.
#[tokio::test]
async fn a_resource_cycle_is_refused_client_side() {
    let server = MockServer::start().await;
    let client = logged_in_client(&server).await;

    let manifest = ManagementManifest::new()
        .with_resource(ResourceSpec::new("a", "a", "collection").under("b"))
        .with_resource(ResourceSpec::new("b", "b", "collection").under("a"));

    let err = client
        .manifest()
        .plan(&manifest)
        .await
        .expect_err("a cycle has no creation order");
    assert!(err.to_string().contains("cycle"), "{err}");
}

/// A user that would have to be created with no password fails during `plan`.
///
/// §27.6 rule 1 in its most useful form: this is exactly the failure you do
/// not want to meet halfway through an apply.
#[tokio::test]
async fn a_user_needing_creation_without_a_password_fails_in_plan() {
    let server = MockServer::start().await;
    let client = logged_in_client(&server).await;
    mount_empty_reads(&server).await;

    let manifest =
        ManagementManifest::new().with_user(UserSpec::new("bob", "bob", "bob@example.com"));

    let err = client
        .manifest()
        .plan(&manifest)
        .await
        .expect_err("no password, no creation");
    assert!(err.to_string().contains("initial_password"), "{err}");
}

// ---------------------------------------------------------------------------
// §27.6 rules 3 and 4 — drift and pruning
// ---------------------------------------------------------------------------

/// A tenant already matching the manifest yields an all-`NoChange` plan.
///
/// This is the §27.6 rule 6 acceptance test, expressed against a tenant that
/// is already converged.
#[tokio::test]
async fn a_converged_tenant_plans_no_changes() {
    let server = MockServer::start().await;
    let client = logged_in_client(&server).await;

    Mock::given(method("GET"))
        .and(path("/api/v1/roles"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "items": [role_json(EXAMPLE_ID, "Editor", "Edits documents")],
            "total": 1, "offset": 0, "limit": 200,
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/api/v1/roles/{EXAMPLE_ID}/permissions")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/api/v1/roles/{EXAMPLE_ID}/users")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/api/v1/roles/{EXAMPLE_ID}/groups")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .mount(&server)
        .await;
    for route in [
        "/api/v1/resources",
        "/api/v1/permissions",
        "/api/v1/groups",
        "/api/v1/users",
    ] {
        Mock::given(method("GET"))
            .and(path(route))
            .respond_with(ResponseTemplate::new(200).set_body_raw(empty_page(), "application/json"))
            .mount(&server)
            .await;
    }

    let manifest =
        ManagementManifest::new().with_role(RoleSpec::new("editor", "Editor", "Edits documents"));
    let plan = client.manifest().plan(&manifest).await.expect("plan");

    assert!(
        plan.is_converged(),
        "unexpected changes: {:?}",
        plan.changes().collect::<Vec<_>>()
    );
}

/// A manifest omitting an existing role plans no deletion.
///
/// §27.6 rule 4: a manifest is usually a *subset* of a tenant's truth, and
/// pruning by default turns "make sure this role exists" into "delete the
/// other forty".
#[tokio::test]
async fn an_omitted_role_is_never_deleted() {
    let server = MockServer::start().await;
    let client = logged_in_client(&server).await;

    Mock::given(method("GET"))
        .and(path("/api/v1/roles"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "items": [role_json(EXAMPLE_ID, "SomeoneElsesRole", "Not in the manifest")],
            "total": 1, "offset": 0, "limit": 200,
        })))
        .mount(&server)
        .await;
    for route in [
        "/api/v1/resources",
        "/api/v1/permissions",
        "/api/v1/groups",
        "/api/v1/users",
    ] {
        Mock::given(method("GET"))
            .and(path(route))
            .respond_with(ResponseTemplate::new(200).set_body_raw(empty_page(), "application/json"))
            .mount(&server)
            .await;
    }

    let plan = client
        .manifest()
        .plan(&ManagementManifest::new())
        .await
        .expect("an empty manifest is valid");
    assert!(plan.actions.is_empty(), "{:?}", plan.actions);
}

/// A resource whose type drifted is an `Update`, not a `Create`.
#[tokio::test]
async fn a_drifted_field_the_manifest_states_is_an_update() {
    let server = MockServer::start().await;
    let client = logged_in_client(&server).await;

    Mock::given(method("GET"))
        .and(path("/api/v1/resources"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "items": [{
                "id": EXAMPLE_ID, "tenant_id": TENANT_ID, "name": "documents",
                "resource_type": "folder", "parent_id": null, "metadata": {},
                "created_at": NOW, "updated_at": NOW,
            }],
            "total": 1, "offset": 0, "limit": 200,
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/api/v1/resources/{EXAMPLE_ID}/scopes")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .mount(&server)
        .await;
    for route in [
        "/api/v1/permissions",
        "/api/v1/roles",
        "/api/v1/groups",
        "/api/v1/users",
    ] {
        Mock::given(method("GET"))
            .and(path(route))
            .respond_with(ResponseTemplate::new(200).set_body_raw(empty_page(), "application/json"))
            .mount(&server)
            .await;
    }

    let manifest = ManagementManifest::new().with_resource(ResourceSpec::new(
        "docs",
        "documents",
        "collection",
    ));
    let plan = client.manifest().plan(&manifest).await.expect("plan");

    let resource = plan
        .actions
        .iter()
        .find(|a| a.target == Target::Resource)
        .expect("a resource action");
    assert_eq!(resource.change, Change::Update);
}

// ---------------------------------------------------------------------------
// §27.6 rules 6 and 7 — apply
// ---------------------------------------------------------------------------

/// A successful apply reports an outcome for every step, and converges.
#[tokio::test]
async fn apply_creates_everything_and_then_converges() {
    let server = MockServer::start().await;
    let client = logged_in_client(&server).await;
    mount_empty_reads(&server).await;

    Mock::given(method("POST"))
        .and(path("/api/v1/resources"))
        .respond_with(ResponseTemplate::new(201).set_body_json(resource_json(
            EXAMPLE_ID,
            "workspace",
            None,
        )))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(format!("/api/v1/resources/{EXAMPLE_ID}/scopes")))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "id": EXAMPLE_ID, "tenant_id": TENANT_ID, "resource_id": EXAMPLE_ID,
            "name": "draft", "description": "Unpublished",
            "created_at": NOW, "updated_at": NOW,
        })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/v1/permissions"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "id": EXAMPLE_ID, "tenant_id": TENANT_ID, "action": "document:read",
            "description": "Read a document", "created_at": NOW, "updated_at": NOW,
        })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/v1/roles"))
        .respond_with(ResponseTemplate::new(201).set_body_json(role_json(
            EXAMPLE_ID,
            "Editor",
            "Edits documents",
        )))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(format!("/api/v1/roles/{EXAMPLE_ID}/permissions")))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/v1/groups"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "id": EXAMPLE_ID, "tenant_id": TENANT_ID, "name": "Staff",
            "description": "All staff", "metadata": {}, "created_at": NOW, "updated_at": NOW,
        })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(format!("/api/v1/roles/{EXAMPLE_ID}/groups")))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/v1/users"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "id": EXAMPLE_ID, "tenant_id": TENANT_ID, "username": "alice",
            "email": "alice@example.com", "status": "Active", "mfa_enabled": false,
            "email_verified": false, "metadata": {}, "created_at": NOW, "updated_at": NOW,
            "failed_login_attempts": 0, "is_locked": false,
        })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(format!("/api/v1/groups/{EXAMPLE_ID}/members")))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;

    let report = client
        .manifest()
        .apply(&full_manifest())
        .await
        .expect("apply");

    assert!(report.is_complete(), "{:?}", report.failure());
    assert_eq!(report.changed(), report.steps.len());
}

/// A failure stops the apply and reports every step honestly.
///
/// §27.6 rule 7: there is no transaction across these endpoints, so the report
/// has to say what already happened and what was never tried.
#[tokio::test]
async fn a_failure_stops_the_apply_and_is_reported() {
    let server = MockServer::start().await;
    let client = logged_in_client(&server).await;
    mount_empty_reads(&server).await;

    // Resources succeed; the permission that follows them does not.
    Mock::given(method("POST"))
        .and(path("/api/v1/resources"))
        .respond_with(ResponseTemplate::new(201).set_body_json(resource_json(
            EXAMPLE_ID,
            "workspace",
            None,
        )))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(format!("/api/v1/resources/{EXAMPLE_ID}/scopes")))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "id": EXAMPLE_ID, "tenant_id": TENANT_ID, "resource_id": EXAMPLE_ID,
            "name": "draft", "description": "Unpublished",
            "created_at": NOW, "updated_at": NOW,
        })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/v1/permissions"))
        .respond_with(
            ResponseTemplate::new(409)
                .set_body_raw(r#"{"error":"action already declared"}"#, "application/json"),
        )
        .mount(&server)
        .await;

    let report = client
        .manifest()
        .apply(&full_manifest())
        .await
        .expect("apply returns a report even when a step fails");

    assert!(!report.is_complete());
    let (failed, message) = report.failure().expect("a failure is recorded");
    assert_eq!(failed.target, Target::Permission);
    assert!(
        message.contains("409") || message.contains("already"),
        "{message}"
    );

    // Everything before the failure ran; everything after was not attempted.
    let outcomes: Vec<&axiam_sdk::management::manifest::Outcome> =
        report.steps.iter().map(|(_, o)| o).collect();
    let failed_at = outcomes
        .iter()
        .position(|o| matches!(o, axiam_sdk::management::manifest::Outcome::Failed(_)))
        .expect("a failed step");
    assert!(
        outcomes[..failed_at]
            .iter()
            .all(|o| !matches!(o, axiam_sdk::management::manifest::Outcome::NotAttempted)),
        "steps before the failure must have been attempted"
    );
    assert!(
        outcomes[failed_at + 1..]
            .iter()
            .all(|o| matches!(o, axiam_sdk::management::manifest::Outcome::NotAttempted)),
        "§27.6 rule 7: nothing after a failure is attempted"
    );
}

/// An empty manifest is valid and does nothing.
#[tokio::test]
async fn an_empty_manifest_applies_cleanly() {
    let server = MockServer::start().await;
    let client: AxiamClient = logged_in_client(&server).await;
    mount_empty_reads(&server).await;

    let report = client
        .manifest()
        .apply(&ManagementManifest::new())
        .await
        .expect("apply");
    assert!(report.is_complete());
    assert_eq!(report.changed(), 0);
}

/// Every `Update` path runs: resource, permission, role, group and user.
///
/// The create paths are covered above; these are the other half of the
/// reconciler, and the half where getting the request body wrong quietly
/// overwrites a field nobody meant to touch.
#[tokio::test]
async fn apply_updates_every_drifted_kind() {
    let server = MockServer::start().await;
    let client = logged_in_client(&server).await;

    // Everything exists, and every field the manifest states has drifted.
    Mock::given(method("GET"))
        .and(path("/api/v1/resources"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "items": [{
                "id": EXAMPLE_ID, "tenant_id": TENANT_ID, "name": "documents",
                "resource_type": "folder", "parent_id": null, "metadata": {},
                "created_at": NOW, "updated_at": NOW,
            }],
            "total": 1, "offset": 0, "limit": 200,
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/api/v1/resources/{EXAMPLE_ID}/scopes")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v1/permissions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "items": [{
                "id": EXAMPLE_ID, "tenant_id": TENANT_ID, "action": "document:read",
                "description": "stale", "created_at": NOW, "updated_at": NOW,
            }],
            "total": 1, "offset": 0, "limit": 200,
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v1/roles"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "items": [role_json(EXAMPLE_ID, "Editor", "stale")],
            "total": 1, "offset": 0, "limit": 200,
        })))
        .mount(&server)
        .await;
    for suffix in ["permissions", "users", "groups"] {
        Mock::given(method("GET"))
            .and(path(format!("/api/v1/roles/{EXAMPLE_ID}/{suffix}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
            .mount(&server)
            .await;
    }
    Mock::given(method("GET"))
        .and(path("/api/v1/groups"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "items": [{
                "id": EXAMPLE_ID, "tenant_id": TENANT_ID, "name": "Staff",
                "description": "stale", "metadata": {}, "created_at": NOW, "updated_at": NOW,
            }],
            "total": 1, "offset": 0, "limit": 200,
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/api/v1/groups/{EXAMPLE_ID}/members")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "items": [], "total": 0, "offset": 0, "limit": 200,
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v1/users"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "items": [{
                "id": EXAMPLE_ID, "tenant_id": TENANT_ID, "username": "alice",
                "email": "stale@example.com", "status": "Active", "mfa_enabled": false,
                "email_verified": true, "metadata": {}, "created_at": NOW, "updated_at": NOW,
                "failed_login_attempts": 0, "is_locked": false,
            }],
            "total": 1, "offset": 0, "limit": 200,
        })))
        .mount(&server)
        .await;

    // Every write the reconciler will make. Each answers with the shape its
    // route really returns — a `{}` here would fail deserialization, which is
    // the generated surface test's job to catch, not this one's.
    for (route, body) in [
        (
            format!("/api/v1/resources/{EXAMPLE_ID}"),
            resource_json(EXAMPLE_ID, "documents", None),
        ),
        (
            format!("/api/v1/permissions/{EXAMPLE_ID}"),
            json!({
                "id": EXAMPLE_ID, "tenant_id": TENANT_ID, "action": "document:read",
                "description": "Read a document", "created_at": NOW, "updated_at": NOW,
            }),
        ),
        (
            format!("/api/v1/roles/{EXAMPLE_ID}"),
            role_json(EXAMPLE_ID, "Editor", "Edits documents"),
        ),
        (
            format!("/api/v1/groups/{EXAMPLE_ID}"),
            json!({
                "id": EXAMPLE_ID, "tenant_id": TENANT_ID, "name": "Staff",
                "description": "All staff", "metadata": {}, "created_at": NOW, "updated_at": NOW,
            }),
        ),
        (
            format!("/api/v1/users/{EXAMPLE_ID}"),
            json!({
                "id": EXAMPLE_ID, "tenant_id": TENANT_ID, "username": "alice",
                "email": "alice@example.com", "status": "Active", "mfa_enabled": false,
                "email_verified": true, "metadata": {}, "created_at": NOW, "updated_at": NOW,
                "failed_login_attempts": 0, "is_locked": false,
            }),
        ),
    ] {
        Mock::given(method("PUT"))
            .and(path(route))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .mount(&server)
            .await;
    }
    Mock::given(method("POST"))
        .and(path(format!("/api/v1/resources/{EXAMPLE_ID}/scopes")))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "id": EXAMPLE_ID, "tenant_id": TENANT_ID, "resource_id": EXAMPLE_ID,
            "name": "draft", "description": "Unpublished",
            "created_at": NOW, "updated_at": NOW,
        })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(format!("/api/v1/roles/{EXAMPLE_ID}/permissions")))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(format!("/api/v1/roles/{EXAMPLE_ID}/groups")))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(format!("/api/v1/groups/{EXAMPLE_ID}/members")))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(format!("/api/v1/roles/{EXAMPLE_ID}/users")))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;

    let manifest = ManagementManifest::new()
        .with_resource(
            ResourceSpec::new("docs", "documents", "collection").with_scope(ScopeSpec::new(
                "draft",
                "draft",
                "Unpublished",
            )),
        )
        .with_permission(PermissionSpec::new(
            "read",
            "document:read",
            "Read a document",
        ))
        .with_role(
            RoleSpec::new("editor", "Editor", "Edits documents")
                .granting(GrantSpec::allow("read").scoped_to(["draft"])),
        )
        .with_group(GroupSpec::new("staff", "Staff", "All staff").with_roles(["editor"]))
        .with_user(
            UserSpec::new("alice", "alice", "alice@example.com")
                .with_roles(["editor"])
                .in_groups(["staff"]),
        );

    let plan = client.manifest().plan(&manifest).await.expect("plan");
    let updates = plan
        .actions
        .iter()
        .filter(|a| a.change == Change::Update)
        .count();
    assert_eq!(
        updates, 5,
        "resource, permission, role, group and user all drifted"
    );

    let report = client.manifest().apply(&manifest).await.expect("apply");
    assert!(report.is_complete(), "{:?}", report.failure());
}

/// A user that already exists is never given the manifest's `initial_password`.
///
/// A manifest is a description of shape. Silently resetting a live account's
/// password because a config file mentions one is not a shape change, and is
/// the kind of thing nobody notices until someone cannot log in.
#[tokio::test]
async fn an_existing_user_is_not_given_the_initial_password() {
    let server = MockServer::start().await;
    let client = logged_in_client(&server).await;

    Mock::given(method("GET"))
        .and(path("/api/v1/users"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "items": [{
                "id": EXAMPLE_ID, "tenant_id": TENANT_ID, "username": "alice",
                "email": "alice@example.com", "status": "Active", "mfa_enabled": false,
                "email_verified": true, "metadata": {}, "created_at": NOW, "updated_at": NOW,
                "failed_login_attempts": 0, "is_locked": false,
            }],
            "total": 1, "offset": 0, "limit": 200,
        })))
        .mount(&server)
        .await;
    for route in [
        "/api/v1/resources",
        "/api/v1/permissions",
        "/api/v1/roles",
        "/api/v1/groups",
    ] {
        Mock::given(method("GET"))
            .and(path(route))
            .respond_with(ResponseTemplate::new(200).set_body_raw(empty_page(), "application/json"))
            .mount(&server)
            .await;
    }

    let manifest = ManagementManifest::new().with_user(
        UserSpec::new("alice", "alice", "alice@example.com")
            .with_initial_password(Sensitive::new("never-sent".into())),
    );
    let report = client.manifest().apply(&manifest).await.expect("apply");

    assert_eq!(report.changed(), 0, "an unchanged user needs no write");
    let writes = server
        .received_requests()
        .await
        .unwrap_or_default()
        .iter()
        .filter(|r| r.method.as_str() != "GET" && !r.url.path().starts_with("/api/v1/auth/"))
        .count();
    assert_eq!(writes, 0);
}
