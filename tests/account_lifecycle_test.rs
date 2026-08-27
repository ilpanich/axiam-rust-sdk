//! §25 account lifecycle and MFA enrolment — the CONTRACT.md §25.6 test set.
//!
//! The assertion worth reading is `mfa_secret_never_renders`: it scans for the
//! secret **value**, not the field name, which is what catches `totp_uri` — the
//! field that actually reaches a log, because it is the one a caller passes to
//! a QR renderer, and the one that silently contains the secret it sits beside.

#![cfg(feature = "rest")]

use std::sync::Arc;
use std::sync::Mutex;

use axiam_sdk::client::AxiamClient;
use axiam_sdk::rest::{PasswordResetConfirmation, PasswordResetRequest};
use axiam_sdk::{AxiamError, Sensitive};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde::Serialize;
use serde_json::{Value, json};
use uuid::Uuid;
use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

const SECRET: &str = "JBSWY3DPEHPK3PXPSECRETVALUE";
const SETUP_TOKEN: &str = "setup-token-value-do-not-log";
const RESET_TOKEN: &str = "reset-token-value-do-not-log";

const TEST_ED25519_SEED: [u8; 32] = [
    0x74, 0x8c, 0x0b, 0xd3, 0xad, 0xc0, 0x28, 0x0a, 0xfd, 0xd7, 0xc0, 0x7c, 0x35, 0x07, 0x03, 0x64,
    0x6d, 0x14, 0x2d, 0x1d, 0xbd, 0x73, 0x4c, 0xd4, 0xf8, 0x17, 0x17, 0x0b, 0x91, 0x7b, 0x49, 0xfc,
];
const ED25519_PKCS8_DER_PREFIX: [u8; 16] = [
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];
const TEST_ED25519_PUBLIC_X: &str = "_r-I_0nRSSV8kvwA93gwhX-hFRiWkaNk5HEud-DjnMk";
const TEST_KID: &str = "test-kid-1";

fn totp_uri() -> String {
    format!("otpauth://totp/AXIAM:alice@example.com?secret={SECRET}&issuer=AXIAM")
}

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

fn access_token(tenant_id: Uuid, org_id: Uuid) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs() as i64;
    let claims = TestClaims {
        sub: Uuid::new_v4().to_string(),
        tenant_id: tenant_id.to_string(),
        org_id: org_id.to_string(),
        iss: "axiam".into(),
        iat: now,
        exp: now + 900,
        jti: Uuid::new_v4().to_string(),
    };
    let mut der = ED25519_PKCS8_DER_PREFIX.to_vec();
    der.extend_from_slice(&TEST_ED25519_SEED);
    let mut header = Header::new(Algorithm::EdDSA);
    header.kid = Some(TEST_KID.into());
    jsonwebtoken::encode(&header, &claims, &EncodingKey::from_ed_der(&der)).expect("encode")
}

async fn mount_jwks(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path("/oauth2/jwks"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "keys": [{
                "kty": "OKP", "crv": "Ed25519", "kid": TEST_KID,
                "alg": "EdDSA", "x": TEST_ED25519_PUBLIC_X,
            }]
        })))
        .mount(server)
        .await;
}

fn build_client(base_url: &str) -> AxiamClient {
    AxiamClient::builder()
        .base_url(base_url)
        .expect("valid base_url")
        .tenant_slug("acme")
        .org_slug("globex")
        .build()
        .expect("client builds")
}

fn enroll_body() -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_json(json!({
        "secret_base32": SECRET,
        "totp_uri": totp_uri(),
    }))
}

async fn mount_capturing(
    server: &MockServer,
    endpoint: &str,
    template: ResponseTemplate,
) -> Arc<Mutex<Vec<Value>>> {
    let bodies = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&bodies);
    Mock::given(method("POST"))
        .and(path(endpoint))
        .respond_with(move |req: &Request| {
            if let Ok(value) = serde_json::from_slice::<Value>(&req.body) {
                sink.lock().expect("lock").push(value);
            }
            template.clone()
        })
        .mount(server)
        .await;
    bodies
}

// ---------------------------------------------------------------------------
// §25.2 rule 1 — login's third outcome
// ---------------------------------------------------------------------------

#[tokio::test]
async fn login_surfaces_the_setup_branch_as_an_outcome() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/auth/login"))
        .respond_with(ResponseTemplate::new(403).set_body_json(json!({
            "mfa_setup_required": true,
            "setup_token": SETUP_TOKEN,
        })))
        .mount(&server)
        .await;

    let result = build_client(&server.uri())
        .login("alice@example.com", "pw")
        .await
        .expect("the setup branch is an outcome, not an error");

    assert!(result.mfa_setup_required);
    assert!(!result.mfa_required);
    assert_eq!(
        result.setup_token.as_ref().expect("token").expose(),
        SETUP_TOKEN
    );
}

#[tokio::test]
async fn a_genuine_403_still_raises() {
    // Matched on the body's discriminant, not on the status: a real
    // authorization failure is also a 403 and must not be read as a setup
    // branch just because it shares a status code.
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/auth/login"))
        .respond_with(
            ResponseTemplate::new(403).set_body_json(json!({"message": "tenant suspended"})),
        )
        .mount(&server)
        .await;

    let err = build_client(&server.uri())
        .login("alice@example.com", "pw")
        .await
        .expect_err("a genuine refusal");
    assert!(matches!(err, AxiamError::Authz { .. }));
}

#[tokio::test]
async fn the_setup_token_never_renders() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/auth/login"))
        .respond_with(ResponseTemplate::new(403).set_body_json(json!({
            "mfa_setup_required": true,
            "setup_token": SETUP_TOKEN,
        })))
        .mount(&server)
        .await;

    let result = build_client(&server.uri())
        .login("alice@example.com", "pw")
        .await
        .expect("setup branch");
    let rendered = format!("{result:?}{result:#?}");
    assert!(!rendered.contains(SETUP_TOKEN));
}

// ---------------------------------------------------------------------------
// MFA enrolment
// ---------------------------------------------------------------------------

#[tokio::test]
async fn mfa_enroll_returns_the_secret_and_uri() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/auth/mfa/enroll"))
        .respond_with(enroll_body())
        .mount(&server)
        .await;

    let enrolment = build_client(&server.uri())
        .mfa_enroll()
        .await
        .expect("enroll");
    assert_eq!(enrolment.secret_base32.expose(), SECRET);
    assert!(enrolment.totp_uri.expose().contains(SECRET));
}

#[tokio::test]
async fn mfa_secret_never_renders() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/auth/mfa/enroll"))
        .respond_with(enroll_body())
        .mount(&server)
        .await;

    let enrolment = build_client(&server.uri())
        .mfa_enroll()
        .await
        .expect("enroll");
    let rendered = format!(
        "{enrolment:?}{enrolment:#?}{:?}{:?}",
        enrolment.secret_base32, enrolment.totp_uri
    );
    // Scanning for the VALUE, not the field name. `totp_uri` contains the
    // secret, so an SDK that wrapped only `secret_base32` fails right here.
    assert!(
        !rendered.contains(SECRET),
        "the TOTP secret leaked into a Debug rendering"
    );
}

#[tokio::test]
async fn mfa_confirm_activates_the_factor() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/auth/mfa/confirm"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"mfa_enabled": true})))
        .mount(&server)
        .await;

    assert!(
        build_client(&server.uri())
            .mfa_confirm("123456")
            .await
            .expect("confirm")
    );
}

#[tokio::test]
async fn mfa_confirm_raises_on_a_wrong_code() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/auth/mfa/confirm"))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({"message": "invalid"})))
        .mount(&server)
        .await;

    let err = build_client(&server.uri())
        .mfa_confirm("000000")
        .await
        .expect_err("wrong code");
    assert!(matches!(err, AxiamError::Auth { .. }));
}

#[tokio::test]
async fn the_forced_path_runs_end_to_end() {
    let server = MockServer::start().await;
    mount_jwks(&server).await;
    let tenant_id = Uuid::new_v4();
    let org_id = Uuid::new_v4();

    Mock::given(method("POST"))
        .and(path("/api/v1/auth/login"))
        .respond_with(ResponseTemplate::new(403).set_body_json(json!({
            "mfa_setup_required": true,
            "setup_token": SETUP_TOKEN,
        })))
        .mount(&server)
        .await;
    let enroll_bodies =
        mount_capturing(&server, "/api/v1/auth/mfa/setup/enroll", enroll_body()).await;

    let access = access_token(tenant_id, org_id);
    Mock::given(method("POST"))
        .and(path("/api/v1/auth/mfa/setup/confirm"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"session_id": Uuid::new_v4(), "expires_in": 900}))
                .append_header(
                    "Set-Cookie",
                    format!("axiam_access={access}; Path=/; HttpOnly").as_str(),
                )
                .append_header(
                    "Set-Cookie",
                    "axiam_refresh=refresh-cookie; Path=/; HttpOnly",
                )
                .append_header("Set-Cookie", "axiam_csrf=csrf-tok; Path=/"),
        )
        .mount(&server)
        .await;

    let client = build_client(&server.uri());
    let login = client
        .login("alice@example.com", "pw")
        .await
        .expect("login");
    let setup_token = login.setup_token.as_ref().expect("setup token");

    let enrolment = client
        .mfa_setup_enroll(setup_token)
        .await
        .expect("setup enroll");
    assert_eq!(enrolment.secret_base32.expose(), SECRET);
    assert_eq!(
        enroll_bodies.lock().expect("lock")[0]["setup_token"],
        SETUP_TOKEN
    );

    let done = client
        .mfa_setup_confirm(setup_token, "123456")
        .await
        .expect("setup confirm");
    assert!(!done.mfa_required && !done.mfa_setup_required);
    // It IS the completion of a login, so it adopts credentials (§25.2 rule 2).
    assert_eq!(client.resolved_tenant_id().await, Some(tenant_id));
}

// ---------------------------------------------------------------------------
// Email verification
// ---------------------------------------------------------------------------

#[tokio::test]
async fn verify_email_sends_the_token_in_the_body() {
    let server = MockServer::start().await;
    let bodies = mount_capturing(
        &server,
        "/api/v1/auth/verify-email",
        ResponseTemplate::new(200),
    )
    .await;
    let tenant_id = Uuid::new_v4();

    build_client(&server.uri())
        .verify_email(&Sensitive::new("verify-tok".into()), tenant_id)
        .await
        .expect("verify");

    let sent = &bodies.lock().expect("lock")[0];
    assert_eq!(sent["token"], "verify-tok");
    assert_eq!(sent["tenant_id"], tenant_id.to_string());
}

#[tokio::test]
async fn resend_verification() {
    let server = MockServer::start().await;
    let bodies = mount_capturing(
        &server,
        "/api/v1/auth/resend-verification",
        ResponseTemplate::new(200),
    )
    .await;
    let tenant_id = Uuid::new_v4();

    build_client(&server.uri())
        .resend_verification("alice@example.com", tenant_id)
        .await
        .expect("resend");

    assert_eq!(
        bodies.lock().expect("lock")[0]["email"],
        "alice@example.com"
    );
}

// ---------------------------------------------------------------------------
// §25.7 — the two resends are two operations
// ---------------------------------------------------------------------------

/// The authenticated resend carries **no address**, and hits its own path.
///
/// The body assertion is the one that matters: a signature with no address
/// parameter proves nothing about what the SDK serializes, and an address on
/// this endpoint would let an authenticated session mail an arbitrary one.
#[tokio::test]
async fn resend_own_verification_sends_no_address() {
    let server = MockServer::start().await;
    let bodies = mount_capturing(
        &server,
        "/api/v1/users/me/resend-verification",
        ResponseTemplate::new(200).set_body_json(json!({ "sent": true })),
    )
    .await;

    build_client(&server.uri())
        .resend_own_verification()
        .await
        .expect("resend own");

    let sent = &bodies.lock().expect("lock")[0];
    let keys: Vec<&String> = sent.as_object().expect("an object").keys().collect();
    assert!(keys.is_empty(), "caller-supplied data went out: {keys:?}");
}

/// The two resends are distinct operations against distinct paths.
///
/// An SDK that aliased one to the other would reintroduce the exact defect
/// §25.7 exists to describe, and every other test here would still pass — so
/// this asserts on the path each one actually reached.
#[tokio::test]
async fn the_two_resends_reach_different_endpoints() {
    let server = MockServer::start().await;
    mount_capturing(
        &server,
        "/api/v1/auth/resend-verification",
        ResponseTemplate::new(200),
    )
    .await;
    mount_capturing(
        &server,
        "/api/v1/users/me/resend-verification",
        ResponseTemplate::new(200).set_body_json(json!({ "sent": true })),
    )
    .await;

    let client = build_client(&server.uri());
    client
        .resend_verification("alice@example.com", Uuid::new_v4())
        .await
        .expect("public resend");
    client
        .resend_own_verification()
        .await
        .expect("authenticated resend");

    let paths: Vec<String> = server
        .received_requests()
        .await
        .expect("requests")
        .iter()
        .map(|r| r.url.path().to_string())
        .filter(|p| p.contains("resend"))
        .collect();
    assert_eq!(
        paths,
        vec![
            "/api/v1/auth/resend-verification".to_string(),
            "/api/v1/users/me/resend-verification".to_string(),
        ]
    );
}

/// `409` raises, and is **not** retried through the public endpoint.
///
/// The bug this operation exists to fix was a success return on a request that
/// achieved nothing, so "does not resolve" is the assertion, and "issued
/// exactly one request" is what rules out the §25.7 rule 2 fallback.
#[tokio::test]
async fn resend_own_verification_surfaces_a_409_rather_than_falling_back() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/users/me/resend-verification"))
        .respond_with(ResponseTemplate::new(409))
        .expect(1)
        .mount(&server)
        .await;
    // Mounted and expected zero times: if the SDK "helpfully" retried through
    // the enumeration-safe endpoint, both failures would turn back into a
    // green result and only this expectation would notice.
    Mock::given(method("POST"))
        .and(path("/api/v1/auth/resend-verification"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&server)
        .await;

    let err = build_client(&server.uri())
        .resend_own_verification()
        .await
        .expect_err("409 must not resolve");
    assert!(matches!(err, AxiamError::Authz { .. }), "{err:?}");
}

/// `429` raises too, as the §2 mapping of a rate limit.
#[tokio::test]
async fn resend_own_verification_surfaces_the_daily_limit() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/users/me/resend-verification"))
        .respond_with(ResponseTemplate::new(429))
        .expect(1)
        .mount(&server)
        .await;

    let err = build_client(&server.uri())
        .resend_own_verification()
        .await
        .expect_err("429 must not resolve");
    assert!(matches!(err, AxiamError::Network { .. }), "{err:?}");
}

// ---------------------------------------------------------------------------
// §25.4 — password reset
// ---------------------------------------------------------------------------

#[tokio::test]
async fn request_reset_resolves_for_an_unknown_address() {
    // The uniform response is the whole mechanism; an SDK that surfaced a
    // "no such user" signal would rebuild the enumeration oracle it prevents.
    let server = MockServer::start().await;
    let bodies = mount_capturing(&server, "/api/v1/auth/reset", ResponseTemplate::new(200)).await;

    build_client(&server.uri())
        .request_password_reset(&PasswordResetRequest {
            email: "nobody@example.com".into(),
            ..Default::default()
        })
        .await
        .expect("an unknown address must not raise");

    let sent = &bodies.lock().expect("lock")[0];
    assert_eq!(sent["org_slug"], "globex");
    assert_eq!(sent["tenant_slug"], "acme");
}

/// Contract 1.26 removed the username from this response. The type has exactly
/// one field, so reintroducing an identity would not compile — asserted here as
/// an exhaustive destructure rather than by inspecting a serialization.
#[test]
fn the_reset_context_carries_only_the_opaque_policy() {
    let axiam_sdk::rest::PasswordResetContext { opaque } =
        axiam_sdk::rest::PasswordResetContext::default();
    assert!(opaque.is_none());
}

#[tokio::test]
async fn reset_context_returns_the_policy_and_no_identity() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/auth/reset/context"))
        .and(query_param("token", RESET_TOKEN))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"opaque": {"mode": "required", "ksf": "argon2id"}})),
        )
        .mount(&server)
        .await;

    let context = build_client(&server.uri())
        .password_reset_context(&Sensitive::new(RESET_TOKEN.into()))
        .await
        .expect("context");

    assert_eq!(context.opaque.expect("policy")["mode"], "required");
}

#[tokio::test]
async fn reset_context_404_is_one_indistinguishable_failure() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/auth/reset/context"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;

    build_client(&server.uri())
        .password_reset_context(&Sensitive::new("some-other-token".into()))
        .await
        .expect_err("unknown, expired or consumed");
}

#[tokio::test]
async fn confirm_reset_sends_the_opaque_record_when_there_is_one() {
    let server = MockServer::start().await;
    let bodies = mount_capturing(
        &server,
        "/api/v1/auth/reset/confirm",
        ResponseTemplate::new(200),
    )
    .await;
    let tenant_id = Uuid::new_v4();

    build_client(&server.uri())
        .confirm_password_reset(&PasswordResetConfirmation {
            token: Sensitive::new(RESET_TOKEN.into()),
            new_password: Sensitive::new("new-password".into()),
            tenant_id,
            opaque: Some(json!({"registration_record": "abc"})),
        })
        .await
        .expect("confirm");

    assert_eq!(
        bodies.lock().expect("lock")[0]["opaque"]["registration_record"],
        "abc"
    );
}

#[tokio::test]
async fn confirm_reset_omits_opaque_entirely_when_there_is_none() {
    let server = MockServer::start().await;
    let bodies = mount_capturing(
        &server,
        "/api/v1/auth/reset/confirm",
        ResponseTemplate::new(200),
    )
    .await;

    build_client(&server.uri())
        .confirm_password_reset(&PasswordResetConfirmation {
            token: Sensitive::new(RESET_TOKEN.into()),
            new_password: Sensitive::new("new-password".into()),
            tenant_id: Uuid::new_v4(),
            opaque: None,
        })
        .await
        .expect("confirm");

    assert!(
        bodies.lock().expect("lock")[0].get("opaque").is_none(),
        "an absent OPAQUE record must be omitted, not sent as null"
    );
}

#[tokio::test]
async fn reset_confirmation_never_renders_its_secrets() {
    let confirmation = PasswordResetConfirmation {
        token: Sensitive::new(RESET_TOKEN.into()),
        new_password: Sensitive::new("new-password".into()),
        tenant_id: Uuid::new_v4(),
        opaque: None,
    };
    let rendered = format!("{confirmation:?}{confirmation:#?}");
    assert!(!rendered.contains(RESET_TOKEN));
    assert!(!rendered.contains("new-password"));
}
