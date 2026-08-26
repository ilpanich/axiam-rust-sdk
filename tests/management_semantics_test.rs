//! CONTRACT §27.9 — the semantics that are not per-operation.
//!
//! Each assertion here exists because the thing it checks is easy to get wrong
//! and silent when wrong. The per-operation coverage lives in the generated
//! `management_surface_generated.rs`; this file is the part a generator cannot
//! write.

#![cfg(feature = "rest")]

mod management_support;

use axiam_sdk::management::models;
use axiam_sdk::management::{PageRequest, ValidationError};
use axiam_sdk::{AuthzKind, AxiamError, Sensitive};
use serde_json::json;
use uuid::Uuid;
use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

use management_support::{
    EXAMPLE_ID, ORG_ID, TENANT_ID, anonymous_client, logged_in_client, mount,
};

fn example_id() -> Uuid {
    Uuid::parse_str(EXAMPLE_ID).expect("fixture id")
}

fn user_body(email: &str) -> serde_json::Value {
    json!({
        "id": EXAMPLE_ID, "tenant_id": TENANT_ID, "username": "alice", "email": email,
        "status": "Active", "mfa_enabled": false, "email_verified": true, "metadata": {},
        "created_at": "2026-08-26T00:00:00Z", "updated_at": "2026-08-26T00:00:00Z",
        "failed_login_attempts": 0, "is_locked": false,
    })
}

// ---------------------------------------------------------------------------
// §27.4 rule 1 — the authentication precondition
// ---------------------------------------------------------------------------

/// Calling an authenticated operation with no session must fail **locally**.
///
/// The assertion that matters is the request count. Letting the request go out
/// trades a clear local error for a 401 that then enters the §9 refresh guard
/// and fails there, two indirections from the actual mistake.
#[tokio::test]
async fn an_operation_without_a_session_makes_no_wire_call() {
    let server = MockServer::start().await;
    let client = anonymous_client(&server.uri());

    let err = client
        .users()
        .get(example_id())
        .await
        .expect_err("no session, so this cannot succeed");

    assert!(matches!(err, AxiamError::Auth { .. }), "{err:?}");
    assert!(
        server
            .received_requests()
            .await
            .unwrap_or_default()
            .is_empty(),
        "§27.4 rule 1: the SDK must refuse before reaching the network"
    );
}

// ---------------------------------------------------------------------------
// §27.4 rule 3 — implicit path context
// ---------------------------------------------------------------------------

/// `{org_id}` and `{tenant_id}` come from the client, and land in the *path*.
#[tokio::test]
async fn implicit_scope_is_taken_from_the_client() {
    let server = MockServer::start().await;
    let client = logged_in_client(&server).await;

    mount(
        &server,
        "GET",
        &format!("/api/v1/organizations/{ORG_ID}/tenants"),
        200,
        r#"{"items": [], "total": 0, "offset": 0, "limit": 50}"#,
    )
    .await;
    client
        .tenants()
        .list(PageRequest::first(50))
        .await
        .expect("tenants.list under the client's org");

    mount(
        &server,
        "GET",
        &format!("/api/v1/tenants/{TENANT_ID}/webauthn/attestation-policy"),
        200,
        r#"{"mode": "none", "require_fido_certified": false, "block_revoked_status": false, "effective_unknown_aaguid": "allow"}"#,
    )
    .await;
    client
        .webauthn_policy()
        .get()
        .await
        .expect("policy under the client's tenant");
}

/// An explicit override wins, and it is the *path* that proves it.
#[tokio::test]
async fn an_explicit_scope_override_changes_the_path() {
    let server = MockServer::start().await;
    let client = logged_in_client(&server).await;
    let other_org = Uuid::new_v4();

    mount(
        &server,
        "GET",
        &format!("/api/v1/organizations/{other_org}/tenants"),
        200,
        r#"{"items": [], "total": 0, "offset": 0, "limit": 50}"#,
    )
    .await;

    client
        .tenants()
        .in_org(other_org)
        .list(PageRequest::first(50))
        .await
        .expect("an overridden org is addressable");
}

/// A slug-only client fails locally on a route that needs the UUID.
///
/// §27.4 rule 3 forbids resolving the slug behind the caller's back, so the
/// request count is again the real assertion.
#[tokio::test]
async fn a_slug_only_client_refuses_a_uuid_route_without_calling() {
    let server = MockServer::start().await;
    let client = axiam_sdk::client::AxiamClient::builder()
        .base_url(server.uri())
        .expect("valid base url")
        .tenant_slug("acme")
        .org_slug("acme")
        .build()
        .expect("client builds");

    // The precondition of rule 1 would also refuse this, so give it a session
    // first: the point is that scope resolution fails, not authentication.
    Mock::given(method("GET"))
        .and(path("/oauth2/jwks"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"keys": []})))
        .mount(&server)
        .await;

    let err = client
        .tenants()
        .list(PageRequest::first(50))
        .await
        .expect_err("a slug-only client cannot address an org route");
    let rendered = err.to_string();
    assert!(rendered.contains("org"), "{rendered}");
    assert!(
        server
            .received_requests()
            .await
            .unwrap_or_default()
            .is_empty(),
        "no lookup round-trip may be made on the caller's behalf"
    );
}

// ---------------------------------------------------------------------------
// §27.4 rule 4 — pagination
// ---------------------------------------------------------------------------

/// `total` is the size of the *set*, not of the page.
///
/// Asserted against a fixture where the two differ: a `Page` that reports
/// `total == items.len()` passes every test written against a single page.
#[tokio::test]
async fn a_page_reports_the_whole_set_not_the_page() {
    let server = MockServer::start().await;
    let client = logged_in_client(&server).await;

    mount(
        &server,
        "GET",
        "/api/v1/users",
        200,
        &format!(
            r#"{{"items": [{}], "total": 97, "offset": 0, "limit": 1}}"#,
            user_body("a@b.c")
        ),
    )
    .await;

    let page = client
        .users()
        .list(PageRequest::first(1))
        .await
        .expect("users.list");
    assert_eq!(page.items.len(), 1);
    assert_eq!(page.total, 97);
    assert!(page.has_more());
}

/// The auto-paging form walks to exhaustion, with the expected offsets.
#[tokio::test]
async fn list_all_walks_every_page() {
    let server = MockServer::start().await;
    let client = logged_in_client(&server).await;

    for (offset, email) in [(0u64, "a@b.c"), (1, "d@e.f"), (2, "g@h.i")] {
        Mock::given(method("GET"))
            .and(path("/api/v1/users"))
            .and(query_param("offset", offset.to_string()))
            .respond_with(ResponseTemplate::new(200).set_body_raw(
                format!(
                    r#"{{"items": [{}], "total": 3, "offset": {offset}, "limit": 1}}"#,
                    user_body(email)
                ),
                "application/json",
            ))
            .expect(1)
            .mount(&server)
            .await;
    }

    let all = client
        .users()
        .list_all(PageRequest::first(1))
        .await
        .expect("users.list_all");
    assert_eq!(all.len(), 3);
    assert_eq!(all[2].email, "g@h.i");
}

/// An empty page ends the walk even when `total` insists there is more.
///
/// A server that keeps answering with no items would otherwise loop forever;
/// one wasted request is the right price.
#[tokio::test]
async fn list_all_stops_on_an_empty_page_despite_a_lying_total() {
    let server = MockServer::start().await;
    let client = logged_in_client(&server).await;

    Mock::given(method("GET"))
        .and(path("/api/v1/users"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(
            r#"{"items": [], "total": 900, "offset": 0, "limit": 50}"#,
            "application/json",
        ))
        .expect(1)
        .mount(&server)
        .await;

    let all = client
        .users()
        .list_all(PageRequest::first(50))
        .await
        .expect("users.list_all");
    assert!(all.is_empty());
}

// ---------------------------------------------------------------------------
// §27.4 rule 5 — sparse updates
// ---------------------------------------------------------------------------

/// A sparse update carrying one field serializes a body with **exactly** that key.
///
/// The assertion is on the full key set. Asserting the field is present passes
/// even when every other field went along as `null` — which is the bug, since
/// the server reads an explicit null as "set this to null".
#[tokio::test]
async fn a_sparse_update_sends_only_the_fields_that_were_set() {
    let server = MockServer::start().await;
    let client = logged_in_client(&server).await;

    Mock::given(method("PUT"))
        .and(path(format!("/api/v1/users/{EXAMPLE_ID}")))
        .respond_with(move |request: &Request| {
            let body: serde_json::Value =
                serde_json::from_slice(&request.body).expect("body is JSON");
            let keys: Vec<&String> = body.as_object().expect("object").keys().collect();
            assert_eq!(
                keys,
                vec!["email"],
                "§27.4 rule 5: an unset field must be absent, not null"
            );
            ResponseTemplate::new(200).set_body_json(user_body("new@example.com"))
        })
        .mount(&server)
        .await;

    client
        .users()
        .update(
            example_id(),
            &models::UpdateUserRequest {
                email: Some("new@example.com".into()),
                ..Default::default()
            },
        )
        .await
        .expect("users.update");
}

// ---------------------------------------------------------------------------
// §27.4 rule 7 — error mapping
// ---------------------------------------------------------------------------

/// 404 is `AuthzKind::NotFound`, and is still catchable as `AuthzError`.
#[tokio::test]
async fn a_404_is_not_found_and_still_an_authz_error() {
    let server = MockServer::start().await;
    let client = logged_in_client(&server).await;
    mount(
        &server,
        "GET",
        &format!("/api/v1/users/{EXAMPLE_ID}"),
        404,
        "",
    )
    .await;

    let err = client.users().get(example_id()).await.expect_err("404");
    assert!(err.is_not_found(), "{err:?}");
    assert!(
        matches!(
            err,
            AxiamError::Authz {
                kind: AuthzKind::NotFound,
                ..
            }
        ),
        "{err:?}"
    );
}

/// 409 is `AuthzKind::Conflict`, and is **not** retried.
#[tokio::test]
async fn a_409_is_a_conflict_and_is_issued_once() {
    let server = MockServer::start().await;
    let client = logged_in_client(&server).await;
    Mock::given(method("POST"))
        .and(path("/api/v1/roles"))
        .respond_with(
            ResponseTemplate::new(409)
                .set_body_raw(r#"{"error":"role name already taken"}"#, "application/json"),
        )
        .expect(1)
        .mount(&server)
        .await;

    let err = client
        .roles()
        .create(&models::CreateRoleRequest {
            name: "Editor".into(),
            description: "Edits".into(),
            is_global: false,
        })
        .await
        .expect_err("409");
    assert!(err.is_conflict(), "{err:?}");
}

/// 400 carries typed validation detail, and is still a `NetworkError`.
#[tokio::test]
async fn a_400_carries_field_level_validation_detail() {
    let server = MockServer::start().await;
    let client = logged_in_client(&server).await;
    mount(
        &server,
        "POST",
        "/api/v1/users",
        400,
        r#"{"errors":[{"field":"email","message":"is not a valid address"}]}"#,
    )
    .await;

    let err = client
        .users()
        .create(&models::CreateUserRequest {
            username: "alice".into(),
            email: "not-an-email".into(),
            password: Sensitive::new("hunter2hunter2".into()),
            metadata: None,
            opaque: None,
        })
        .await
        .expect_err("400");

    assert!(matches!(err, AxiamError::Network { .. }), "{err:?}");
    let detail: &ValidationError = err.validation().expect("typed validation detail");
    assert_eq!(detail.status, 400);
    assert_eq!(detail.operation, "users.create");
    assert_eq!(detail.fields.len(), 1);
    assert_eq!(detail.fields[0].field, "email");
}

/// An ordinary 403 is still a plain `AuthzError`, not one of the new kinds.
#[tokio::test]
async fn a_403_stays_a_plain_denial() {
    let server = MockServer::start().await;
    let client = logged_in_client(&server).await;
    mount(
        &server,
        "GET",
        &format!("/api/v1/users/{EXAMPLE_ID}"),
        403,
        "",
    )
    .await;

    let err = client.users().get(example_id()).await.expect_err("403");
    assert!(
        matches!(
            err,
            AxiamError::Authz {
                kind: AuthzKind::Denied,
                ..
            }
        ),
        "{err:?}"
    );
    assert!(!err.is_not_found());
    assert!(!err.is_conflict());
}

/// A second delete surfaces `NotFound` rather than being swallowed as success.
///
/// §27.4 rule 6: a caller retrying a failed delete needs to know whether it is
/// finishing its own job or looking at someone else's.
#[tokio::test]
async fn a_repeated_delete_is_not_silently_successful() {
    let server = MockServer::start().await;
    let client = logged_in_client(&server).await;
    mount(
        &server,
        "DELETE",
        &format!("/api/v1/users/{EXAMPLE_ID}"),
        404,
        "",
    )
    .await;

    let err = client
        .users()
        .delete(example_id())
        .await
        .expect_err("second delete");
    assert!(err.is_not_found(), "{err:?}");
}

// ---------------------------------------------------------------------------
// §27.4 rule 8 — retry
// ---------------------------------------------------------------------------

/// A write is issued exactly once on a 5xx, even though it looks idempotent.
#[tokio::test]
async fn a_write_is_never_retried() {
    let server = MockServer::start().await;
    let client = logged_in_client(&server).await;

    Mock::given(method("POST"))
        .and(path(format!(
            "/api/v1/service-accounts/{EXAMPLE_ID}/rotate-secret"
        )))
        .respond_with(ResponseTemplate::new(503))
        .expect(1)
        .mount(&server)
        .await;

    let err = client
        .service_accounts()
        .rotate_secret(example_id())
        .await
        .expect_err("503");
    assert!(matches!(err, AxiamError::Network { .. }), "{err:?}");
    // `expect(1)` is verified when the server drops; state it here too so the
    // reason the assertion exists is readable at the assertion.
    let calls = server.received_requests().await.unwrap_or_default();
    let rotations = calls
        .iter()
        .filter(|r| r.url.path().ends_with("/rotate-secret"))
        .count();
    assert_eq!(rotations, 1, "§27.4 rule 8: writes are issued exactly once");
}

// ---------------------------------------------------------------------------
// §27.5 — secrets
// ---------------------------------------------------------------------------

/// A one-time secret is `Sensitive`, and its value is absent from every render.
///
/// Scans the debug output for the fixture value rather than asserting on the
/// type: the type can be right while a field renders through some other sink.
#[tokio::test]
async fn a_returned_secret_is_redacted_in_debug_output() {
    let server = MockServer::start().await;
    let client = logged_in_client(&server).await;
    let secret = "sk_live_do_not_log_me_0123456789";

    mount(
        &server,
        "POST",
        "/api/v1/scim-tokens",
        201,
        &json!({
            "id": EXAMPLE_ID, "tenant_id": TENANT_ID, "user_id": EXAMPLE_ID,
            "created_by": EXAMPLE_ID, "name": "provisioning", "status": "active",
            "created_at": "2026-08-26T00:00:00Z", "expires_at": "2027-08-26T00:00:00Z",
            "provisioning_token": secret,
        })
        .to_string(),
    )
    .await;

    let token = client
        .scim_tokens()
        .create(&models::CreateScimTokenRequest {
            name: "provisioning".into(),
            user_id: example_id(),
            expires_in_days: None,
        })
        .await
        .expect("scim_tokens.create");

    assert_eq!(token.provisioning_token.expose(), secret);
    let rendered = format!("{token:?}");
    assert!(
        !rendered.contains(secret),
        "§7: the secret leaked into Debug output: {rendered}"
    );
}

/// The request-side secret is redacted too.
///
/// A create body reaches a debug log exactly as easily as a response does, and
/// `users().create(spec)` with a plaintext password in it is the most-logged
/// object on this surface.
#[test]
fn a_supplied_password_is_redacted_in_debug_output() {
    let password = "correct horse battery staple";
    let body = models::CreateUserRequest {
        username: "alice".into(),
        email: "alice@example.com".into(),
        password: Sensitive::new(password.into()),
        metadata: None,
        opaque: None,
    };
    let rendered = format!("{body:?}");
    assert!(!rendered.contains(password), "{rendered}");
}

// ---------------------------------------------------------------------------
// §27.2 — handle rules
// ---------------------------------------------------------------------------

/// Acquiring a namespace handle performs no I/O.
#[tokio::test]
async fn acquiring_a_handle_makes_no_request() {
    let server = MockServer::start().await;
    let client = logged_in_client(&server).await;
    let before = server.received_requests().await.unwrap_or_default().len();

    let _ = client.users();
    let _ = client.roles();
    let _ = client.ca_certificates().in_org(Uuid::new_v4());
    let _ = client.settings().for_tenant(Uuid::new_v4());

    let after = server.received_requests().await.unwrap_or_default().len();
    assert_eq!(before, after, "§27.2 rule 1: handles are free");
}
