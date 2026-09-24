//! CONTRACT.md §5.2 rule 1 (contract 1.51) — the acting-tenant helper.
//!
//! An organization-level principal acts on another tenant of its organization
//! by sending `X-Axiam-Tenant`. The assertions here are about the wire, not
//! the arguments: the header is sent when set, **absent when not** (the I4
//! twin — a client that never asked for one must send what it sent before
//! 1.51), never coupled to `X-Tenant-ID` or a `{tenant_id}` path, and refused
//! client-side when a held login result says the server would refuse it.

#![cfg(feature = "rest")]

mod management_support;

use std::time::Duration;

use axiam_sdk::client::{ACTING_TENANT_HEADER, AxiamClient};
use axiam_sdk::{AuthzKind, AxiamError};
use serde_json::json;
use uuid::Uuid;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

use management_support::{
    EXAMPLE_ID, TENANT_ID, anonymous_client, logged_in_client, logged_in_client_as, mount,
};

const OTHER_TENANT: &str = "44444444-4444-4444-8444-444444444444";
const THIRD_TENANT: &str = "55555555-5555-4555-8555-555555555555";

fn other() -> Uuid {
    Uuid::parse_str(OTHER_TENANT).unwrap()
}

fn org_admin() -> serde_json::Value {
    json!({
        "id": Uuid::new_v4(), "username": "root", "email": "root@example.com",
        "organization_level": true,
    })
}

async fn mount_groups_list(server: &MockServer) {
    mount(
        server,
        "GET",
        "/api/v1/groups",
        200,
        r#"{"items": [], "total": 0, "offset": 0, "limit": 50}"#,
    )
    .await;
}

async fn requests_to(server: &MockServer, route: &str) -> Vec<Request> {
    server
        .received_requests()
        .await
        .unwrap_or_default()
        .into_iter()
        .filter(|r| r.url.path() == route)
        .collect()
}

fn acting_header(request: &Request) -> Option<String> {
    request
        .headers
        .get(ACTING_TENANT_HEADER)
        .map(|v| v.to_str().unwrap().to_string())
}

fn tenant_id_header(request: &Request) -> Option<String> {
    request
        .headers
        .get("X-Tenant-ID")
        .map(|v| v.to_str().unwrap().to_string())
}

// ---------------------------------------------------------------------------
// Sent when set, absent when not
// ---------------------------------------------------------------------------

/// The builder form puts `X-Axiam-Tenant` on a management request and leaves
/// `X-Tenant-ID` naming the constructor tenant — the two headers are read by
/// different mechanisms and the SDK does not couple them (§5, §5.2 rule 1).
#[tokio::test]
async fn the_builder_form_sends_the_header_beside_an_unchanged_x_tenant_id() {
    let server = MockServer::start().await;
    let logged_in = logged_in_client_as(&server, org_admin()).await;
    // The builder form on a fresh client that shares nothing; log it in too.
    let client = AxiamClient::builder()
        .base_url(server.uri())
        .unwrap()
        .tenant_id(Uuid::parse_str(TENANT_ID).unwrap())
        .org_id(Uuid::parse_str(management_support::ORG_ID).unwrap())
        .retry_enabled(false)
        .with_acting_tenant(other())
        .build()
        .unwrap();
    drop(logged_in);
    client.login("root@example.com", "pw").await.expect("login");
    assert_eq!(client.acting_tenant_id(), Some(other()));
    mount_groups_list(&server).await;

    client
        .groups()
        .list(axiam_sdk::management::PageRequest::first(50))
        .await
        .expect("groups.list");

    let sent = requests_to(&server, "/api/v1/groups").await;
    assert_eq!(sent.len(), 1);
    assert_eq!(acting_header(&sent[0]).as_deref(), Some(OTHER_TENANT));
    assert_eq!(tenant_id_header(&sent[0]).as_deref(), Some(TENANT_ID));
}

/// The I4 twin, and the assertion that matters most: a client that never set
/// an acting tenant sends **no** `X-Axiam-Tenant` — on management, on
/// `check_access`, on a self-service call, on `refresh` and on `logout`.
#[tokio::test]
async fn a_client_without_an_acting_tenant_sends_no_header_anywhere() {
    let server = MockServer::start().await;
    let client = logged_in_client(&server).await;
    assert_eq!(client.acting_tenant_id(), None);
    mount_groups_list(&server).await;
    mount(
        &server,
        "POST",
        "/api/v1/authz/check",
        200,
        r#"{"allowed": true}"#,
    )
    .await;
    mount(
        &server,
        "POST",
        "/api/v1/auth/mfa/enroll",
        200,
        r#"{"secret_base32": "JBSWY3DPEHPK3PXP", "totp_uri": "otpauth://totp/x"}"#,
    )
    .await;
    management_support::mount_refresh(&server).await;
    mount(&server, "POST", "/api/v1/auth/logout", 204, "").await;

    client
        .groups()
        .list(axiam_sdk::management::PageRequest::first(50))
        .await
        .unwrap();
    client
        .check_access("read", Uuid::new_v4(), None)
        .await
        .unwrap();
    client.mfa_enroll().await.unwrap();
    client.refresh().await.unwrap();
    client.logout().await.unwrap();

    let requests = server.received_requests().await.unwrap_or_default();
    assert!(requests.len() >= 6, "every call reached the mock");
    for request in &requests {
        assert!(
            request.headers.get(ACTING_TENANT_HEADER).is_none(),
            "{} {} carried X-Axiam-Tenant without being asked to",
            request.method,
            request.url.path()
        );
    }
}

/// The on-client form returns a **new handle**; the original keeps acting on
/// its own tenant, and `clear_acting_tenant` sends no header — byte for byte
/// the original's request.
#[tokio::test]
async fn acting_tenant_rebinds_a_handle_and_clearing_removes_the_header() {
    let server = MockServer::start().await;
    let client = logged_in_client_as(&server, org_admin()).await;
    mount_groups_list(&server).await;

    let acting = client
        .acting_tenant(other())
        .expect("an org-level principal");
    let cleared = acting.clear_acting_tenant();
    assert_eq!(acting.acting_tenant_id(), Some(other()));
    assert_eq!(client.acting_tenant_id(), None, "the original is unchanged");
    assert_eq!(cleared.acting_tenant_id(), None);

    let page = axiam_sdk::management::PageRequest::first(50);
    acting.groups().list(page.clone()).await.unwrap();
    client.groups().list(page.clone()).await.unwrap();
    cleared.groups().list(page).await.unwrap();

    let sent = requests_to(&server, "/api/v1/groups").await;
    let headers: Vec<Option<String>> = sent.iter().map(acting_header).collect();
    assert_eq!(headers, vec![Some(OTHER_TENANT.to_string()), None, None]);
}

/// `{tenant_id}` in a path still defaults from the constructor tenant
/// (§27.4 rule 3). The header and the path are different mechanisms.
#[tokio::test]
async fn the_acting_tenant_does_not_rewrite_a_tenant_id_path_segment() {
    let server = MockServer::start().await;
    let client = logged_in_client_as(&server, org_admin())
        .await
        .acting_tenant(other())
        .unwrap();
    let route = format!("/api/v1/tenants/{TENANT_ID}/settings");
    Mock::given(method("GET"))
        .and(path(route.clone()))
        .and(header(ACTING_TENANT_HEADER, OTHER_TENANT))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;

    let _ = client.settings().get_tenant_override().await;
    assert_eq!(
        requests_to(&server, &route).await.len(),
        1,
        "the path names the constructor tenant, with the header beside it"
    );
}

// ---------------------------------------------------------------------------
// Gating on a held login result
// ---------------------------------------------------------------------------

/// A login that reported `organization_level: false` — or omitted it, which a
/// server older than contract 1.31 does and which reads as `false` — makes
/// the helper refuse client-side, with no wire call.
#[tokio::test]
async fn a_tenant_principal_is_refused_client_side() {
    let server = MockServer::start().await;
    // The harness login omits `organization_level` entirely.
    let client = logged_in_client(&server).await;
    let before = server.received_requests().await.unwrap_or_default().len();

    let Err(err) = client.acting_tenant(other()) else {
        panic!("not organization-level, so the helper must refuse");
    };

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
    assert_eq!(
        server.received_requests().await.unwrap_or_default().len(),
        before,
        "refused before any wire call"
    );
}

/// §5.2.3 rule 4: `reachable_tenant_ids` bounds the choice when present.
#[tokio::test]
async fn reachable_tenant_ids_bound_the_acting_tenant() {
    let server = MockServer::start().await;
    let client = logged_in_client_as(
        &server,
        json!({
            "id": Uuid::new_v4(), "username": "narrow", "email": "n@example.com",
            "organization_level": true, "reachable_tenant_ids": [OTHER_TENANT],
        }),
    )
    .await;

    assert!(client.acting_tenant(other()).is_ok(), "inside the reach");
    let Err(err) = client.acting_tenant(Uuid::parse_str(THIRD_TENANT).unwrap()) else {
        panic!("outside the reach, so the helper must refuse");
    };
    assert!(matches!(err, AxiamError::Authz { .. }), "{err:?}");
}

/// A client holding **no** login result — a service account, an injected
/// token, or nothing yet — has nothing to gate on. The handle is returned, the
/// header is sent, and the server's `403` is the answer.
#[tokio::test]
async fn without_a_login_result_the_server_decides() {
    let server = MockServer::start().await;
    let client = anonymous_client(&server.uri());
    let acting = client
        .acting_tenant(other())
        .expect("no login result, nothing to gate on");

    Mock::given(method("POST"))
        .and(path("/api/v1/authz/check"))
        .and(header(ACTING_TENANT_HEADER, OTHER_TENANT))
        .respond_with(ResponseTemplate::new(403).set_body_string("tenant not reachable"))
        .mount(&server)
        .await;

    let err = acting
        .check_access("read", Uuid::new_v4(), None)
        .await
        .expect_err("the server refuses");
    assert!(matches!(err, AxiamError::Authz { .. }), "{err:?}");
}

/// Logging out forgets the previous principal's reach: the next principal is
/// not refused on the strength of someone else's login.
#[tokio::test]
async fn logout_forgets_the_gate() {
    let server = MockServer::start().await;
    let client = logged_in_client(&server).await;
    mount(&server, "POST", "/api/v1/auth/logout", 204, "").await;
    assert!(client.acting_tenant(other()).is_err());

    client.logout().await.unwrap();
    assert!(client.acting_tenant(other()).is_ok());
}

// ---------------------------------------------------------------------------
// The decision memo is keyed on it
// ---------------------------------------------------------------------------

/// Two handles over one session share one §17 memo. A decision taken while
/// acting on one tenant must not answer the same check on another — the
/// server can, and does, answer them differently.
#[tokio::test]
async fn the_decision_memo_does_not_answer_across_acting_tenants() {
    let server = MockServer::start().await;
    let base = AxiamClient::builder()
        .base_url(server.uri())
        .unwrap()
        .tenant_id(Uuid::parse_str(TENANT_ID).unwrap())
        .org_id(Uuid::parse_str(management_support::ORG_ID).unwrap())
        .retry_enabled(false)
        .decision_memo_ttl(Duration::from_secs(5))
        .build()
        .unwrap();
    // Reuse the harness login against the same server for this client.
    let _ = logged_in_client_as(&server, org_admin()).await;
    base.login("root@example.com", "pw").await.unwrap();

    Mock::given(method("POST"))
        .and(path("/api/v1/authz/check"))
        .and(header(ACTING_TENANT_HEADER, OTHER_TENANT))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "allowed": false })))
        .mount(&server)
        .await;
    mount(
        &server,
        "POST",
        "/api/v1/authz/check",
        200,
        r#"{"allowed": true}"#,
    )
    .await;

    let resource = Uuid::parse_str(EXAMPLE_ID).unwrap();
    assert!(base.can("read", resource, None).await.unwrap());
    let acting = base.acting_tenant(other()).unwrap();
    assert!(
        !acting.can("read", resource, None).await.unwrap(),
        "the other tenant's answer, not the memo's"
    );
    // And the memo still serves the handle it belongs to.
    assert!(base.can("read", resource, None).await.unwrap());
    assert_eq!(requests_to(&server, "/api/v1/authz/check").await.len(), 2);
}
