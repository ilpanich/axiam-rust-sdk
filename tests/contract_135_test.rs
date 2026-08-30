//! Contract 1.34 §5.2.2 and contract 1.35 §5.2.3 — the acting tenant vs the
//! principal tenant, and tenant-scoped role assignments.
//!
//! Two of these rules are the kind an SDK breaks silently rather than loudly,
//! which is why they are pinned here rather than left to the generated surface
//! test:
//!
//! * **§5.2.2 rule 2.** A registration record for the caller's *own* password
//!   is sealed against the tenant the account lives in, not the one the client
//!   is pointed at. Get it wrong and the server answers "the OPAQUE session
//!   was issued for a different tenant" — but only for an organization-level
//!   principal that has switched tenant, so it passes every test written
//!   against an ordinary account.
//! * **§5.2.3 rule 1.** `tenant_scope: []` is refused with `400`. `Option`
//!   alone does not prevent it: the natural way to build the field is to
//!   collect into a `Vec` and wrap it, which yields `Some([])` for "no tenants
//!   named" and puts the refused shape on the wire.

#![cfg(feature = "rest")]

use axiam_sdk::client::AxiamClient;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde::Serialize;
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};
use uuid::Uuid;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

// Same fixed Ed25519 keypair the other REST tests use, so a login's access
// token verifies against a JWKS this file serves.
const TEST_ED25519_SEED: [u8; 32] = [
    0x74, 0x8c, 0x0b, 0xd3, 0xad, 0xc0, 0x28, 0x0a, 0xfd, 0xd7, 0xc0, 0x7c, 0x35, 0x07, 0x03, 0x64,
    0x6d, 0x14, 0x2d, 0x1d, 0xbd, 0x73, 0x4c, 0xd4, 0xf8, 0x17, 0x17, 0x0b, 0x91, 0x7b, 0x49, 0xfc,
];
const ED25519_PKCS8_DER_PREFIX: [u8; 16] = [
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];
const TEST_ED25519_PUBLIC_X: &str = "_r-I_0nRSSV8kvwA93gwhX-hFRiWkaNk5HEud-DjnMk";
const TEST_KID: &str = "test-kid-1";

#[derive(Debug, Serialize)]
struct TestClaims {
    sub: String,
    tenant_id: String,
    org_id: String,
    iss: String,
    iat: i64,
    exp: i64,
    jti: String,
}

fn issue_test_access_token(tenant_id: Uuid, org_id: Uuid, user_id: Uuid, jti: Uuid) -> String {
    let mut der = ED25519_PKCS8_DER_PREFIX.to_vec();
    der.extend_from_slice(&TEST_ED25519_SEED);
    let key = EncodingKey::from_ed_der(&der);
    let mut header = Header::new(Algorithm::EdDSA);
    header.kid = Some(TEST_KID.to_string());
    let now = chrono_now();
    let claims = TestClaims {
        sub: user_id.to_string(),
        tenant_id: tenant_id.to_string(),
        org_id: org_id.to_string(),
        iss: "https://axiam.test".to_string(),
        iat: now,
        exp: now + 900,
        jti: jti.to_string(),
    };
    jsonwebtoken::encode(&header, &claims, &key).expect("token encodes")
}

fn chrono_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock is after the epoch")
        .as_secs() as i64
}

async fn mount_jwks(mock_server: &MockServer) {
    Mock::given(method("GET"))
        .and(path("/oauth2/jwks"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "keys": [{
                "kty": "OKP", "crv": "Ed25519", "alg": "EdDSA",
                "use": "sig", "kid": TEST_KID, "x": TEST_ED25519_PUBLIC_X,
            }]
        })))
        .mount(mock_server)
        .await;
}

fn session_cookies_header(access_token: &str) -> Vec<String> {
    vec![
        format!("axiam_access={access_token}; Path=/; HttpOnly"),
        "axiam_refresh=refresh-token; Path=/; HttpOnly".to_string(),
        "axiam_csrf=csrf-token; Path=/".to_string(),
    ]
}

/// A throwaway credential built at run time.
///
/// Deliberately not a literal. A password spelled out in source is a finding
/// for CodeQL and for secret scanners alike, and it stays one wherever the
/// file gets copied. Nothing in these tests depends on the value: the login
/// mock answers `200` regardless, and `register/start` is captured and
/// refused, so what is under test is which tenant the body names, never
/// whether a credential matched.
fn fixture_password() -> String {
    format!("Fixture-{}-aA1!", Uuid::new_v4())
}

fn build_client(base_url: &str) -> AxiamClient {
    AxiamClient::builder()
        .base_url(base_url)
        .expect("valid base_url")
        .tenant_slug("acme")
        .org_slug("acme")
        .build()
        .expect("client builds")
}

/// Mount `POST /auth/login` returning `user` verbatim, so each test can decide
/// which of the §5.2.2 fields the "server" reports.
async fn mount_login(mock_server: &MockServer, user_extra: Value, tenant_id: Uuid, org_id: Uuid) {
    let user_id = Uuid::new_v4();
    let session_id = Uuid::new_v4();
    let access_token = issue_test_access_token(tenant_id, org_id, user_id, session_id);

    let mut user = json!({
        "id": user_id,
        "username": "alice",
        "email": "alice@example.com",
    });
    let (Value::Object(base), Value::Object(extra)) = (&mut user, user_extra) else {
        panic!("user objects are maps");
    };
    base.extend(extra);

    let mut response = ResponseTemplate::new(200).set_body_json(json!({
        "user": user,
        "session_id": session_id,
        "expires_in": 900,
    }));
    for cookie in session_cookies_header(&access_token) {
        response = response.append_header("Set-Cookie", cookie.as_str());
    }
    Mock::given(method("POST"))
        .and(path("/api/v1/auth/login"))
        .respond_with(response)
        .mount(mock_server)
        .await;
}

// ---------------------------------------------------------------------------
// §5.2.2 — acting tenant vs principal tenant
// ---------------------------------------------------------------------------

/// Rule 1: a server older than contract 1.34 omits `principal_tenant_id`, and
/// absent means *equal* rather than unknown — such a server cannot switch the
/// acting tenant either, so `tenant_id` is not a guess but the only value the
/// field could have had.
#[tokio::test]
async fn absent_principal_tenant_reads_as_the_acting_tenant() {
    let mock_server = MockServer::start().await;
    mount_jwks(&mock_server).await;
    let tenant_id = Uuid::new_v4();
    mount_login(
        &mock_server,
        json!({ "tenant_id": tenant_id }),
        tenant_id,
        Uuid::new_v4(),
    )
    .await;

    let result = build_client(&mock_server.uri())
        .login("alice@example.com", &fixture_password())
        .await
        .expect("login succeeds");

    assert_eq!(result.tenant_id, Some(tenant_id));
    assert_eq!(
        result.principal_tenant_id,
        Some(tenant_id),
        "absent principal_tenant_id must default to the acting tenant"
    );
}

/// The whole point of the field: for an organization-level principal that has
/// selected another tenant, the two differ and the SDK must not collapse them.
#[tokio::test]
async fn a_divergent_principal_tenant_is_reported_separately() {
    let mock_server = MockServer::start().await;
    mount_jwks(&mock_server).await;
    let acting = Uuid::new_v4();
    let principal = Uuid::new_v4();
    let org_id = Uuid::new_v4();
    mount_login(
        &mock_server,
        json!({
            "tenant_id": acting,
            "principal_tenant_id": principal,
            "principal_tenant_slug": "organization",
            "org_id": org_id,
            "organization_level": true,
        }),
        acting,
        org_id,
    )
    .await;

    let result = build_client(&mock_server.uri())
        .login("alice@example.com", &fixture_password())
        .await
        .expect("login succeeds");

    assert_eq!(result.tenant_id, Some(acting));
    assert_eq!(result.principal_tenant_id, Some(principal));
    assert_eq!(
        result.principal_tenant_slug.as_deref(),
        Some("organization")
    );
    // Rule 3: read the organization from the session rather than resolving a
    // slug through the `super-admin`-only `GET /api/v1/organizations`.
    assert_eq!(result.org_id, Some(org_id));
    assert!(result.organization_level);
}

/// §5.2.3: absent `reachable_tenant_ids` means unrestricted, and a present one
/// travels with `organization_level: true` rather than instead of it — which
/// is exactly why gating on that flag alone offers tenants the server refuses.
#[tokio::test]
async fn reachable_tenant_ids_narrows_an_organization_level_principal() {
    let mock_server = MockServer::start().await;
    mount_jwks(&mock_server).await;
    let tenant_id = Uuid::new_v4();
    let reachable = Uuid::new_v4();
    mount_login(
        &mock_server,
        json!({
            "tenant_id": tenant_id,
            "organization_level": true,
            "reachable_tenant_ids": [reachable],
        }),
        tenant_id,
        Uuid::new_v4(),
    )
    .await;

    let result = build_client(&mock_server.uri())
        .login("alice@example.com", &fixture_password())
        .await
        .expect("login succeeds");

    assert!(result.organization_level);
    assert_eq!(
        result.reachable_tenant_ids.as_deref(),
        Some([reachable].as_slice()),
        "a narrowed principal still reports organization_level: true, so the \
         list is what bounds a tenant switch"
    );
}

// ---------------------------------------------------------------------------
// §5.2.2 rule 2 — which tenant a registration record is sealed against
// ---------------------------------------------------------------------------

/// Captures the `register/start` body, then refuses, because the tenant the
/// body names is the whole assertion — the OPAQUE exchange beyond it is
/// covered by `opaque_login_test.rs`.
struct CaptureRegisterStart {
    seen: Arc<Mutex<Option<Value>>>,
}

impl Respond for CaptureRegisterStart {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let body: Value = serde_json::from_slice(&request.body).expect("json body");
        *self.seen.lock().expect("lock") = Some(body);
        // 404 is "this tenant does not offer OPAQUE" — a clean, terminal exit
        // that leaves the captured body untouched.
        ResponseTemplate::new(404)
    }
}

async fn capture_enrollment_body(
    for_self: bool,
    user_extra: Value,
) -> (Value, MockServer, AxiamClient) {
    let mock_server = MockServer::start().await;
    mount_jwks(&mock_server).await;
    let tenant_id = Uuid::new_v4();
    mount_login(&mock_server, user_extra, tenant_id, Uuid::new_v4()).await;

    let seen = Arc::new(Mutex::new(None));
    Mock::given(method("POST"))
        .and(path("/api/v1/auth/opaque/register/start"))
        .respond_with(CaptureRegisterStart {
            seen: Arc::clone(&seen),
        })
        .mount(&mock_server)
        .await;

    let client = build_client(&mock_server.uri());
    client
        .login("alice@example.com", &fixture_password())
        .await
        .expect("login succeeds");

    let _ = if for_self {
        client.opaque_enrollment_for_self(&fixture_password()).await
    } else {
        client.opaque_enrollment(&fixture_password()).await
    };

    let body = seen.lock().expect("lock").clone().expect("body captured");
    (body, mock_server, client)
}

/// Creating **another** account seals against the tenant being acted on — the
/// tenant that account is created in.
#[tokio::test]
async fn opaque_enrollment_seals_against_the_acting_tenant() {
    let (body, _server, _client) = capture_enrollment_body(
        false,
        json!({ "tenant_id": Uuid::new_v4(), "principal_tenant_id": Uuid::new_v4() }),
    )
    .await;

    assert_eq!(
        body.get("tenant_slug").and_then(Value::as_str),
        Some("acme"),
        "the acting tenant is the one this client was pointed at"
    );
    assert!(
        body.get("tenant_id").is_none(),
        "nothing should override the acting tenant here"
    );
}

/// The caller's **own** password change seals against the tenant the account
/// lives in. A record sealed against the acting tenant is refused with "the
/// OPAQUE session was issued for a different tenant".
#[tokio::test]
async fn opaque_enrollment_for_self_seals_against_the_principal_tenant() {
    let principal = Uuid::new_v4();
    let (body, _server, _client) = capture_enrollment_body(
        true,
        json!({
            "tenant_id": Uuid::new_v4(),
            "principal_tenant_id": principal,
            "organization_level": true,
        }),
    )
    .await;

    assert_eq!(
        body.get("tenant_id").and_then(Value::as_str),
        Some(principal.to_string().as_str()),
        "the caller's own credentials live in the principal tenant"
    );
    assert!(
        body.get("tenant_slug").is_none(),
        "the acting tenant's slug must not travel alongside the principal \
         tenant's id, or it out-votes it server-side"
    );
}

/// Before a login there is no principal tenant to seal against, and guessing
/// the acting one is exactly the bug this method exists to prevent — so it
/// refuses rather than falling back.
#[tokio::test]
async fn opaque_enrollment_for_self_refuses_before_a_login() {
    let mock_server = MockServer::start().await;
    let client = build_client(&mock_server.uri());

    let err = client
        .opaque_enrollment_for_self(&fixture_password())
        .await
        .expect_err("no principal tenant is known yet");
    assert!(
        err.to_string().contains("principal tenant"),
        "error should name what is missing, got: {err}"
    );
}

// ---------------------------------------------------------------------------
// §5.2.3 rules 1 and 2 — tenant_scope on an assignment
// ---------------------------------------------------------------------------

/// Rule 1. `[]` is refused with `400`, and `Some(vec![])` is what a builder
/// that collects into a `Vec` produces for "no tenants named", so both
/// spellings of absent must serialize the same way: by not appearing.
#[test]
fn an_empty_tenant_scope_is_dropped_from_the_body() {
    use axiam_sdk::management::models::AssignRoleToUserRequest;

    let omitted = AssignRoleToUserRequest {
        user_id: Uuid::new_v4(),
        resource_id: None,
        tenant_scope: None,
    };
    let empty = AssignRoleToUserRequest {
        user_id: Uuid::new_v4(),
        resource_id: None,
        tenant_scope: Some(Vec::new()),
    };

    for (label, body) in [("None", &omitted), ("Some([])", &empty)] {
        let json = serde_json::to_value(body).expect("serializes");
        assert!(
            json.get("tenant_scope").is_none(),
            "{label} must not put `tenant_scope` on the wire; the server \
             refuses an empty one with 400"
        );
    }
}

/// Rule 2. The other half: a scope the caller *did* name must actually be
/// sent. Dropping it would turn a refusal the caller needs to see into a
/// success that silently applied no restriction.
#[test]
fn a_named_tenant_scope_is_sent() {
    use axiam_sdk::management::models::{
        AssignRoleToGroupRequest, AssignRoleToServiceAccountRequest, AssignRoleToUserRequest,
    };

    let scoped = Uuid::new_v4();
    let expect_present = |json: Value, which: &str| {
        let scope = json
            .get("tenant_scope")
            .unwrap_or_else(|| panic!("{which} must carry the named scope"));
        assert_eq!(scope, &json!([scoped.to_string()]), "{which}");
    };

    expect_present(
        serde_json::to_value(AssignRoleToUserRequest {
            user_id: Uuid::new_v4(),
            resource_id: None,
            tenant_scope: Some(vec![scoped]),
        })
        .expect("serializes"),
        "users",
    );
    expect_present(
        serde_json::to_value(AssignRoleToGroupRequest {
            group_id: Uuid::new_v4(),
            resource_id: None,
            tenant_scope: Some(vec![scoped]),
        })
        .expect("serializes"),
        "groups",
    );
    expect_present(
        serde_json::to_value(AssignRoleToServiceAccountRequest {
            service_account_id: Uuid::new_v4(),
            resource_id: None,
            tenant_scope: Some(vec![scoped]),
        })
        .expect("serializes"),
        "service accounts",
    );
}

/// The eight §27 operations contract 1.34 added for service accounts as RBAC
/// principals. The generated surface test proves each one's wire shape; this
/// pins the one argument that is easy to drop, because dropping it silently
/// revokes the wrong grant: omitting `resource_id` removes the *global*
/// assignment specifically, not every assignment of that role.
#[test]
fn unassign_from_service_account_keeps_its_resource_id() {
    let src = include_str!("../src/management/ops/roles.rs");
    let start = src
        .find("pub async fn unassign_from_service_account")
        .expect("the operation exists");
    let window = &src[start..start + 400];
    assert!(
        window.contains("resource_id: Option<"),
        "resource_id must stay an optional argument"
    );
    assert!(
        window.contains(r#"query.push(("resource_id""#),
        "resource_id must be forwarded as a query parameter when supplied"
    );
}
