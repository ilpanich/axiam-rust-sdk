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
// §27.4 rule 4 — `search`
// ---------------------------------------------------------------------------

/// A term on the page request reaches the **query string**.
///
/// Asserted on the request URI rather than on the arguments: a term the SDK
/// accepts, stores and never sends is the failure this test exists for, and it
/// is invisible from the call site.
#[tokio::test]
async fn a_search_term_reaches_the_query_string() {
    let server = MockServer::start().await;
    let client = logged_in_client(&server).await;

    Mock::given(method("GET"))
        .and(path("/api/v1/users"))
        .and(query_param("search", "ada"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(
            format!(
                r#"{{"items": [{}], "total": 1, "offset": 0, "limit": 50}}"#,
                user_body("ada@b.c")
            ),
            "application/json",
        ))
        .expect(1)
        .mount(&server)
        .await;

    let page = client
        .users()
        .list(PageRequest::first(50).search("ada"))
        .await
        .expect("users.list");
    assert_eq!(page.total, 1);
}

/// No term sends **no** `search` key, and a blank one is the same request.
///
/// Asserted on the exact query key set. A UI that fires on every keystroke
/// sends `?search=` the moment the box is cleared, and "rows whose name
/// contains the empty string" is a different question from "all rows" —
/// different enough that the server normalizes it away too.
#[tokio::test]
async fn an_absent_or_blank_term_sends_no_search_key() {
    for term in [None, Some(""), Some("   ")] {
        let server = MockServer::start().await;
        let client = logged_in_client(&server).await;

        Mock::given(method("GET"))
            .and(path("/api/v1/users"))
            .respond_with(move |req: &Request| {
                let keys: Vec<String> =
                    req.url.query_pairs().map(|(k, _)| k.into_owned()).collect();
                assert!(
                    !keys.iter().any(|k| k == "search"),
                    "sent a search key for {term:?}: {keys:?}"
                );
                ResponseTemplate::new(200).set_body_raw(
                    r#"{"items": [], "total": 0, "offset": 0, "limit": 50}"#,
                    "application/json",
                )
            })
            .expect(1)
            .mount(&server)
            .await;

        let mut request = PageRequest::first(50);
        if let Some(term) = term {
            request = request.search(term);
        }
        client.users().list(request).await.expect("users.list");
    }
}

/// The walk carries the term on **every** request, not only the first.
///
/// A `list_all` that filtered page one and not page two would concatenate the
/// matches with the unfiltered remainder — which reads as a server bug from the
/// caller's side, and which a test counting requests rather than inspecting
/// them would pass.
#[tokio::test]
async fn list_all_carries_the_search_term_across_the_whole_walk() {
    let server = MockServer::start().await;
    let client = logged_in_client(&server).await;

    for (offset, email) in [(0u64, "ada@b.c"), (1, "adam@e.f")] {
        Mock::given(method("GET"))
            .and(path("/api/v1/users"))
            .and(query_param("offset", offset.to_string()))
            // Every page of the walk must carry it, so this matcher is on each
            // mock rather than on the first.
            .and(query_param("search", "ad"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(
                format!(
                    r#"{{"items": [{}], "total": 2, "offset": {offset}, "limit": 1}}"#,
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
        .list_all(PageRequest::first(1).search("ad"))
        .await
        .expect("users.list_all");
    assert_eq!(all.len(), 2);
    assert_eq!(all[1].email, "adam@e.f");
}

/// `search` is trimmed, and the trimmed term is what goes on the wire.
#[tokio::test]
async fn a_padded_term_is_trimmed_before_it_is_sent() {
    let server = MockServer::start().await;
    let client = logged_in_client(&server).await;

    Mock::given(method("GET"))
        .and(path("/api/v1/users"))
        .and(query_param("search", "ada"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(
            r#"{"items": [], "total": 0, "offset": 0, "limit": 50}"#,
            "application/json",
        ))
        .expect(1)
        .mount(&server)
        .await;

    client
        .users()
        .list(PageRequest::first(50).search("  ada  "))
        .await
        .expect("users.list");
}

/// The server's length cap is the **server's**, and this SDK does not copy it.
///
/// A client-side truncation the server would not have made is a silently
/// different query — the caller asked one question and the wire carried
/// another, with nothing to indicate it. §27.4 rule 4.
#[tokio::test]
async fn a_long_term_is_sent_whole_rather_than_truncated_locally() {
    let server = MockServer::start().await;
    let client = logged_in_client(&server).await;
    let long = "x".repeat(400);
    let expected = long.clone();

    Mock::given(method("GET"))
        .and(path("/api/v1/users"))
        .respond_with(move |req: &Request| {
            let sent = req
                .url
                .query_pairs()
                .find(|(k, _)| k == "search")
                .map(|(_, v)| v.into_owned())
                .expect("a search key");
            assert_eq!(sent.len(), expected.len(), "term was truncated client-side");
            ResponseTemplate::new(200).set_body_raw(
                r#"{"items": [], "total": 0, "offset": 0, "limit": 50}"#,
                "application/json",
            )
        })
        .expect(1)
        .mount(&server)
        .await;

    client
        .users()
        .list(PageRequest::first(50).search(long))
        .await
        .expect("users.list");
}

// ---------------------------------------------------------------------------
// §27.11 — model additions
// ---------------------------------------------------------------------------

/// An unrecognised enum value decodes rather than failing the whole page.
///
/// §27.11 rule 1. A closed enum turns the next `kind` the server adds into a
/// parse error on `tenants.list`, taking down every tenant on the page over one
/// field of one of them — including the ones the caller was actually after.
#[tokio::test]
async fn an_unknown_tenant_kind_decodes_instead_of_failing_the_page() {
    let server = MockServer::start().await;
    let client = logged_in_client(&server).await;
    let org = management_support::ORG_ID;

    let tenant = |slug: &str, kind: &str| {
        format!(
            r#"{{"id": "{}", "organization_id": "{org}", "name": "{slug}", "slug": "{slug}",
                 "kind": "{kind}", "status": "active", "metadata": {{}},
                 "created_at": "2026-08-27T00:00:00Z", "updated_at": "2026-08-27T00:00:00Z"}}"#,
            Uuid::new_v4()
        )
    };

    mount(
        &server,
        "GET",
        &format!("/api/v1/organizations/{org}/tenants"),
        200,
        &format!(
            r#"{{"items": [{}, {}], "total": 2, "offset": 0, "limit": 50}}"#,
            tenant("prod", "standard"),
            tenant("future", "some-kind-from-a-newer-server")
        ),
    )
    .await;

    let page = client
        .tenants()
        .list(PageRequest::first(50))
        .await
        .expect("tenants.list decodes an unknown kind");

    assert_eq!(page.items.len(), 2);
    assert_eq!(page.items[0].kind, Some(models::TenantKind::Standard));
    assert_eq!(
        page.items[1].kind,
        Some(models::TenantKind::Unknown(
            "some-kind-from-a-newer-server".into()
        )),
        "the unknown value must be kept verbatim, not collapsed into a default"
    );
}

/// A tenant row written before organization scope existed has no `kind`.
#[tokio::test]
async fn a_tenant_without_a_kind_decodes_as_absent() {
    let server = MockServer::start().await;
    let client = logged_in_client(&server).await;
    let org = management_support::ORG_ID;
    let id = Uuid::new_v4();

    mount(
        &server,
        "GET",
        &format!("/api/v1/organizations/{org}/tenants/{id}"),
        200,
        &format!(
            r#"{{"id": "{id}", "organization_id": "{org}", "name": "prod", "slug": "prod",
                 "status": "active", "metadata": {{}},
                 "created_at": "2026-08-27T00:00:00Z", "updated_at": "2026-08-27T00:00:00Z"}}"#
        ),
    )
    .await;

    let tenant = client.tenants().get(id).await.expect("tenants.get");
    assert_eq!(tenant.kind, None);
}

/// `trusted_anchors` is nullable, and `null` is not `0`.
///
/// §27.11 rule 3: "the listener trusts no CAs" and "there was no listener to
/// ask" are different operational states, and only one of them is a problem.
#[tokio::test]
async fn a_trust_anchor_response_without_a_reload_carries_no_count() {
    let server = MockServer::start().await;
    let client = logged_in_client(&server).await;
    let org = management_support::ORG_ID;
    let ca = Uuid::new_v4();

    mount(
        &server,
        "PUT",
        &format!("/api/v1/organizations/{org}/ca-certificates/{ca}/mtls-trust-anchor"),
        200,
        &format!(
            r#"{{"ca_certificate_id": "{ca}", "mtls_trust_anchor": true,
                 "restart_required": true, "message": "stored; applies at next start"}}"#
        ),
    )
    .await;

    let out = client
        .ca_certificates()
        .set_mtls_trust_anchor(ca, &models::SetMtlsTrustAnchor { enabled: true })
        .await
        .expect("set_mtls_trust_anchor");
    assert!(out.restart_required);
    assert_eq!(out.trusted_anchors, None);
}

/// `bound_service_account_id` is populated by the list and absent from the get.
///
/// §27.11 rule 4. The `get` assertion is the load-bearing one: an SDK that
/// filled it in there would be issuing a second request nobody asked for.
#[tokio::test]
async fn a_bound_certificate_carries_its_service_account_on_the_list_only() {
    let server = MockServer::start().await;
    let client = logged_in_client(&server).await;
    let cert = Uuid::new_v4();
    let sa = Uuid::new_v4();
    let body = |extra: &str| {
        format!(
            r#"{{"id": "{cert}", "tenant_id": "{}", "issuer_ca_id": "{}",
                 "subject": "CN=device-1", "public_cert_pem": "-----BEGIN CERTIFICATE-----",
                 "fingerprint": "ab:cd", "cert_type": "device", "key_algorithm": "ed25519",
                 "not_before": "2026-08-27T00:00:00Z", "not_after": "2027-08-27T00:00:00Z",
                 "status": "active", "metadata": {{}},
                 "created_at": "2026-08-27T00:00:00Z"{extra}}}"#,
            Uuid::new_v4(),
            Uuid::new_v4()
        )
    };

    mount(
        &server,
        "GET",
        "/api/v1/certificates",
        200,
        &format!(
            r#"{{"items": [{}], "total": 1, "offset": 0, "limit": 50}}"#,
            body(&format!(r#", "bound_service_account_id": "{sa}""#))
        ),
    )
    .await;
    mount(
        &server,
        "GET",
        &format!("/api/v1/certificates/{cert}"),
        200,
        &body(""),
    )
    .await;

    let page = client
        .certificates()
        .list(PageRequest::first(50))
        .await
        .expect("certificates.list");
    assert_eq!(page.items[0].bound_service_account_id, Some(sa));

    let one = client
        .certificates()
        .get(cert)
        .await
        .expect("certificates.get");
    assert_eq!(
        one.bound_service_account_id, None,
        "the get must not synthesize the projection with a second request"
    );
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

// ---------------------------------------------------------------------------
// §9 / §27.4 rule 1 — the one refresh, and the one retry
// ---------------------------------------------------------------------------

/// A 401 on a management call refreshes once and retries once.
///
/// §9 rule 1 makes this a MUST for every SDK that manages token state, and a
/// management surface is where it matters most: an admin script running for an
/// hour crosses a 15-minute access-token lifetime four times.
#[tokio::test]
async fn a_401_refreshes_once_and_retries_the_call() {
    let server = MockServer::start().await;
    let client = logged_in_client(&server).await;
    management_support::mount_refresh(&server).await;

    // The first attempt 401s; the retry after the refresh succeeds.
    Mock::given(method("GET"))
        .and(path(format!("/api/v1/users/{EXAMPLE_ID}")))
        .respond_with(ResponseTemplate::new(401))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/api/v1/users/{EXAMPLE_ID}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(user_body("alice@example.com")))
        .mount(&server)
        .await;

    let user = client
        .users()
        .get(example_id())
        .await
        .expect("the retry after a successful refresh must succeed");
    assert_eq!(user.email, "alice@example.com");

    let refreshes = server
        .received_requests()
        .await
        .unwrap_or_default()
        .iter()
        .filter(|r| r.url.path() == "/api/v1/auth/refresh")
        .count();
    assert_eq!(refreshes, 1, "§9 rule 2: exactly one refresh wire call");
}

/// When the refresh itself fails, the original call fails with that error.
///
/// §9 rule 3: a 401 on the refresh means re-authenticate. There is no second
/// refresh and no third attempt at the management call.
#[tokio::test]
async fn a_failed_refresh_surfaces_and_does_not_loop() {
    let server = MockServer::start().await;
    let client = logged_in_client(&server).await;

    Mock::given(method("POST"))
        .and(path("/api/v1/auth/refresh"))
        .respond_with(ResponseTemplate::new(401).set_body_string("refresh token expired"))
        .expect(1)
        .mount(&server)
        .await;
    mount(
        &server,
        "GET",
        &format!("/api/v1/users/{EXAMPLE_ID}"),
        401,
        "",
    )
    .await;

    let err = client.users().get(example_id()).await.expect_err("401");
    assert!(matches!(err, AxiamError::Auth { .. }), "{err:?}");
}

// ---------------------------------------------------------------------------
// §27.4 rule 3 — the other scope-resolution failures
// ---------------------------------------------------------------------------

/// A client with no organization at all fails locally on an org route.
#[tokio::test]
async fn a_client_with_no_org_refuses_an_org_route() {
    let server = MockServer::start().await;
    let client = management_support::client_without_org(&server.uri());

    Mock::given(method("GET"))
        .and(path("/oauth2/jwks"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"keys": []})))
        .mount(&server)
        .await;

    let err = client
        .tenants()
        .list(PageRequest::first(50))
        .await
        .expect_err("no organization configured");
    assert!(err.to_string().contains("organization"), "{err}");
    assert!(
        server
            .received_requests()
            .await
            .unwrap_or_default()
            .is_empty()
    );
}

/// `for_tenant` overrides the client's tenant on a tenant-scoped route.
#[tokio::test]
async fn for_tenant_overrides_the_clients_tenant() {
    let server = MockServer::start().await;
    let client = logged_in_client(&server).await;
    let other = Uuid::new_v4();

    mount(
        &server,
        "DELETE",
        &format!("/api/v1/tenants/{other}/email-config"),
        204,
        "",
    )
    .await;

    client
        .email_config()
        .for_tenant(other)
        .delete_tenant()
        .await
        .expect("an overridden tenant is addressable");
}

// ---------------------------------------------------------------------------
// Filter structs — the operations with more than two optional query parameters
// ---------------------------------------------------------------------------

/// `audit.list`'s filter reaches the query string, and unset fields do not.
#[tokio::test]
async fn an_audit_filter_sends_only_the_fields_that_were_set() {
    let server = MockServer::start().await;
    let client = logged_in_client(&server).await;

    Mock::given(method("GET"))
        .and(path("/api/v1/audit-logs"))
        .respond_with(move |request: &Request| {
            let query: Vec<(String, String)> = request
                .url
                .query_pairs()
                .map(|(k, v)| (k.into_owned(), v.into_owned()))
                .collect();
            let keys: Vec<&str> = query.iter().map(|(k, _)| k.as_str()).collect();
            assert!(keys.contains(&"action"), "{keys:?}");
            assert!(
                !keys.contains(&"actor_id"),
                "an unset filter must not be sent: {keys:?}"
            );
            ResponseTemplate::new(200).set_body_raw(
                r#"{"items": [], "total": 0, "offset": 0, "limit": 50}"#,
                "application/json",
            )
        })
        .mount(&server)
        .await;

    client
        .audit()
        .list(
            &axiam_sdk::management::ops::audit::AuditListFilter {
                action: Some("user.created".into()),
                ..Default::default()
            },
            PageRequest::first(50),
        )
        .await
        .expect("audit.list");
}
