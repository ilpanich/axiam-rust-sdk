//! `login_opaque` end to end against a mock server that really speaks OPAQUE
//! (`src/rest/opaque.rs`, CONTRACT.md §23).
//!
//! The mock is not a canned response: it holds a real `ServerSetup` and a real
//! registration record, and computes `KE2` from whatever `KE1` the client
//! sends. A client that mishandled the hex, the KSF parameters or the session
//! token fails against it, which a fixture-replaying mock could never detect.
//!
//! What this file deliberately does **not** test is the protocol arithmetic.
//! Its SRP predecessor had to — that arithmetic lived in this crate — but
//! CONTRACT §23.1 forbids an SDK from implementing OPAQUE, so it is proven in
//! `axiam-opaque` and against a live server in the AXIAM repository. What is
//! left here is the two HTTP calls and the policy around them.

#![cfg(feature = "opaque")]

use axiam_opaque::testing;
use axiam_sdk::AxiamError;
use axiam_sdk::client::AxiamClient;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};
use uuid::Uuid;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

const PASSWORD: &str = "correct horse battery staple";

/// Cheap but real Argon2id costs, so the tests exercise the actual stretching
/// without paying the production parameters on every run.
const KSF: (u32, u32, u32) = (8192, 1, 1);

fn ksf_fields() -> Value {
    json!({
        "ksf": "argon2id",
        "memory_kib": KSF.0,
        "iterations": KSF.1,
        "parallelism": KSF.2,
    })
}

/// A server that performs the real server half of a registration.
struct RegisterStart {
    /// Captured so a subsequent login can be served against the same setup.
    setup: Arc<Mutex<Option<String>>>,
}

impl Respond for RegisterStart {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let body: Value = serde_json::from_slice(&request.body).unwrap();
        let req_hex = body["registration_request"].as_str().unwrap();
        let (setup, response) = testing::server_registration_start(req_hex);
        *self.setup.lock().unwrap() = Some(setup);

        let mut payload = json!({
            "opaque_session": "sealed-registration-session",
            "registration_response": response,
            "suite": "ristretto255_sha512",
        });
        payload
            .as_object_mut()
            .unwrap()
            .extend(ksf_fields().as_object().unwrap().clone());
        ResponseTemplate::new(200).set_body_json(payload)
    }
}

/// A server that performs the real server half of a login against a stored
/// record.
struct LoginStart {
    setup: String,
    record: String,
    /// The tenant's `opaque_mode`, as §23.5 has `login/start` report it.
    /// `None` models a server older than the field — §23.4 rule 7 requires
    /// that to behave exactly like `"required"`.
    mode: Option<&'static str>,
}

impl LoginStart {
    fn new(setup: String, record: String, mode: Option<&'static str>) -> Self {
        Self {
            setup,
            record,
            mode,
        }
    }
}

impl Respond for LoginStart {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let body: Value = serde_json::from_slice(&request.body).unwrap();
        let ke1 = body["ke1"].as_str().unwrap();
        let ke2 = testing::server_login_start(&self.setup, &self.record, ke1);

        let mut payload = json!({
            "opaque_session": "sealed-login-session",
            "ke2": ke2,
            "suite": "ristretto255_sha512",
        });
        let object = payload.as_object_mut().unwrap();
        object.extend(ksf_fields().as_object().unwrap().clone());
        if let Some(mode) = self.mode {
            object.insert("mode".to_string(), json!(mode));
        }
        ResponseTemplate::new(200).set_body_json(payload)
    }
}

fn client(server: &MockServer) -> AxiamClient {
    AxiamClient::builder()
        .base_url(server.uri())
        .expect("valid base url")
        .org_slug("acme")
        .tenant_slug("default")
        .build()
        .expect("client builds")
}

/// Stand up a mock that has an enrolled account, returning `(server, setup,
/// record)`.
async fn enrolled() -> (MockServer, String, String) {
    let server = MockServer::start().await;
    let setup_slot = Arc::new(Mutex::new(None));

    Mock::given(method("POST"))
        .and(path("/api/v1/auth/opaque/register/start"))
        .respond_with(RegisterStart {
            setup: setup_slot.clone(),
        })
        .mount(&server)
        .await;

    let enrollment = client(&server).opaque_enrollment(PASSWORD).await.unwrap();
    let setup = setup_slot.lock().unwrap().clone().unwrap();
    (server, setup, enrollment.registration_record)
}

// ---------------------------------------------------------------------------

#[tokio::test]
async fn an_enrolment_round_trips_and_produces_a_usable_record() {
    let (_server, _setup, record) = enrolled().await;
    assert_eq!(
        record.len(),
        384,
        "192 bytes of RegistrationRecord, hex-encoded"
    );
    assert!(hex::decode(&record).is_ok());
}

#[tokio::test]
async fn an_enrolment_carries_the_sealed_session_verbatim() {
    // The server chose the credential identifier, the suite and the costs and
    // sealed them into this token. A client that rewrote it could not enrol at
    // all; a client that could *choose* them could enrol against someone
    // else's account.
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/auth/opaque/register/start"))
        .respond_with(RegisterStart {
            setup: Arc::new(Mutex::new(None)),
        })
        .mount(&server)
        .await;

    let enrollment = client(&server).opaque_enrollment(PASSWORD).await.unwrap();
    assert_eq!(enrollment.opaque_session, "sealed-registration-session");
}

#[tokio::test]
async fn the_password_never_appears_in_any_request_body() {
    // The property the whole protocol exists for. Asserted over the bodies the
    // mock actually received rather than by reading the code.
    let (server, setup, record) = enrolled().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/auth/opaque/login/start"))
        .respond_with(LoginStart::new(setup, record, None))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/v1/auth/opaque/login/finish"))
        .respond_with(ResponseTemplate::new(401))
        .mount(&server)
        .await;

    let _ = client(&server).login_opaque("alice", PASSWORD).await;

    for received in server.received_requests().await.unwrap() {
        let body = String::from_utf8_lossy(&received.body);
        assert!(
            !body.contains(PASSWORD),
            "{} carried the plaintext password",
            received.url
        );
    }
}

#[tokio::test]
async fn a_wrong_password_never_reaches_login_finish() {
    // §23.4 rule 7. The envelope does not open, and the client must stop —
    // sending a KE3 it could not derive would be sending junk, and the
    // information it would leak is that this client got that far.
    let (server, setup, record) = enrolled().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/auth/opaque/login/start"))
        .respond_with(LoginStart::new(setup, record, None))
        .mount(&server)
        .await;

    let err = client(&server)
        .login_opaque("alice", "not the password")
        .await
        .unwrap_err();
    assert!(
        matches!(err, AxiamError::Auth { .. }),
        "a wrong password is an AuthError, got {err:?}"
    );

    let finish_calls = server
        .received_requests()
        .await
        .unwrap()
        .into_iter()
        .filter(|r| r.url.path().ends_with("/login/finish"))
        .count();
    assert_eq!(
        finish_calls, 0,
        "nothing may be sent after the envelope fails"
    );
}

#[tokio::test]
async fn a_tenant_with_opaque_disabled_is_a_network_error_not_an_auth_error() {
    // Reporting this as a credential failure would send a user off to reset a
    // password that works, and would stop a caller falling back to `login()`.
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/auth/opaque/login/start"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;

    let err = client(&server)
        .login_opaque("alice", PASSWORD)
        .await
        .unwrap_err();
    assert!(
        matches!(err, AxiamError::Network { .. }),
        "expected a NetworkError, got {err:?}"
    );
}

#[tokio::test]
async fn an_unknown_ksf_is_refused_rather_than_substituted() {
    // §23.4 rule 3. Substituting produces a well-formed randomized password
    // that no AXIAM server agrees with, reported to the user as a wrong
    // password.
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/auth/opaque/login/start"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "opaque_session": "s",
            "ke2": "00".repeat(320),
            "suite": "ristretto255_sha512",
            "ksf": "pbkdf2_sha256",
            "iterations": 600000,
        })))
        .mount(&server)
        .await;

    let err = client(&server)
        .login_opaque("alice", PASSWORD)
        .await
        .unwrap_err();
    match err {
        AxiamError::Network { ref message, .. } => {
            assert!(
                message.contains("pbkdf2_sha256"),
                "the refusal must name the KSF: {message}"
            );
        }
        other => panic!("expected a NetworkError naming the KSF, got {other:?}"),
    }
}

#[tokio::test]
async fn a_ksf_missing_its_cost_parameters_is_refused() {
    // Absent is not zero. Reading a missing `memory_kib` as 0 would stretch
    // with the wrong cost and fail against a record that is perfectly good.
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/auth/opaque/login/start"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "opaque_session": "s",
            "ke2": "00".repeat(320),
            "suite": "ristretto255_sha512",
            "ksf": "argon2id",
        })))
        .mount(&server)
        .await;

    let err = client(&server)
        .login_opaque("alice", PASSWORD)
        .await
        .unwrap_err();
    assert!(matches!(err, AxiamError::Network { .. }), "{err:?}");
}

#[tokio::test]
async fn out_of_range_ksf_costs_are_refused_rather_than_clamped() {
    // A server is trusted to name its own policy, not to name a cost that
    // would wedge every device an account owns.
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/auth/opaque/login/start"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "opaque_session": "s",
            "ke2": "00".repeat(320),
            "suite": "ristretto255_sha512",
            "ksf": "argon2id",
            "memory_kib": 4_194_304,
            "iterations": 1,
            "parallelism": 1,
        })))
        .mount(&server)
        .await;

    let err = client(&server)
        .login_opaque("alice", PASSWORD)
        .await
        .unwrap_err();
    assert!(matches!(err, AxiamError::Network { .. }), "{err:?}");
}

#[tokio::test]
async fn opaque_available_is_true_for_this_build() {
    let server = MockServer::start().await;
    assert!(client(&server).opaque_available());
}

// ---------------------------------------------------------------------------
// §23.4 rule 7 — what happens after `KE2` fails to open, which depends on
// `mode` from `login/start` and on nothing else.
//
// Under `optional` a failed exchange is the ordinary case rather than an
// error: every account has no OPAQUE record the moment an operator enables the
// feature and acquires one only when its password is next set, so an SDK that
// treated the failure as final would lock out every user of a tenant
// mid-migration. Under `required` — and against a server too old to report a
// mode at all — the failure is final and no plaintext password may go on the
// wire.
// ---------------------------------------------------------------------------

/// A fixed test Ed25519 private seed (test-only, deterministic), stored as raw
/// bytes so no private-key block lives in source. The PKCS8 v1 DER is rebuilt
/// at runtime from the standard 16-byte prefix plus this 32-byte seed. Same
/// keypair as `tests/login_mfa_flow_test.rs`, so `PUBLIC_X` matches.
const TEST_ED25519_SEED: [u8; 32] = [
    0x74, 0x8c, 0x0b, 0xd3, 0xad, 0xc0, 0x28, 0x0a, 0xfd, 0xd7, 0xc0, 0x7c, 0x35, 0x07, 0x03, 0x64,
    0x6d, 0x14, 0x2d, 0x1d, 0xbd, 0x73, 0x4c, 0xd4, 0xf8, 0x17, 0x17, 0x0b, 0x91, 0x7b, 0x49, 0xfc,
];
const ED25519_PKCS8_DER_PREFIX: [u8; 16] = [
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];
const TEST_ED25519_PUBLIC_X: &str = "_r-I_0nRSSV8kvwA93gwhX-hFRiWkaNk5HEud-DjnMk";
const TEST_KID: &str = "test-kid-1";

fn issue_test_access_token(tenant_id: Uuid, org_id: Uuid, user_id: Uuid, jti: Uuid) -> String {
    let mut header = Header::new(Algorithm::EdDSA);
    header.kid = Some(TEST_KID.to_string());
    let claims = json!({
        "sub": user_id.to_string(),
        "tenant_id": tenant_id.to_string(),
        "org_id": org_id.to_string(),
        "iss": "axiam-test",
        "iat": 0,
        "exp": 9_999_999_999i64,
        "jti": jti.to_string(),
    });
    let mut der = ED25519_PKCS8_DER_PREFIX.to_vec();
    der.extend_from_slice(&TEST_ED25519_SEED);
    let key = EncodingKey::from_ed_der(&der);
    jsonwebtoken::encode(&header, &claims, &key).expect("encode test access token")
}

/// Mount the JWKS a successful `/auth/login` needs, so the access token it
/// hands back through `Set-Cookie` verifies.
async fn mount_jwks(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path("/oauth2/jwks"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "keys": [{
                "kty": "OKP",
                "crv": "Ed25519",
                "kid": TEST_KID,
                "alg": "EdDSA",
                "x": TEST_ED25519_PUBLIC_X,
            }]
        })))
        .mount(server)
        .await;
}

/// Mount a `POST /api/v1/auth/login` that succeeds exactly as the real handler
/// does — a §3 success body plus the session cookies. Returns the `session_id`
/// it will report.
async fn mount_successful_plaintext_login(server: &MockServer) -> Uuid {
    mount_jwks(server).await;
    let (tenant_id, org_id, user_id, session_id) = (
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
    );
    let access_token = issue_test_access_token(tenant_id, org_id, user_id, session_id);

    let mut response = ResponseTemplate::new(200).set_body_json(json!({
        "user": { "id": user_id, "username": "alice", "email": "alice@example.com" },
        "session_id": session_id,
        "expires_in": 900,
    }));
    for cookie in [
        format!("axiam_access={access_token}; Path=/; HttpOnly"),
        "axiam_refresh=test-refresh-token; Path=/; HttpOnly".to_string(),
        "axiam_csrf=test-csrf-token; Path=/".to_string(),
    ] {
        response = response.append_header("Set-Cookie", cookie.as_str());
    }

    Mock::given(method("POST"))
        .and(path("/api/v1/auth/login"))
        .respond_with(response)
        .mount(server)
        .await;
    session_id
}

/// How many requests the mock saw for a given path suffix.
async fn calls_to(server: &MockServer, suffix: &str) -> usize {
    server
        .received_requests()
        .await
        .unwrap()
        .into_iter()
        .filter(|r| r.url.path().ends_with(suffix))
        .count()
}

#[tokio::test]
async fn under_optional_a_failed_exchange_retries_over_plaintext_login_and_succeeds() {
    // The migration case rule 7 exists for: the account has no record yet, so
    // the exchange cannot succeed and the SDK must complete the login the
    // other way rather than reporting a password the user typed correctly as
    // wrong.
    let (server, setup, record) = enrolled().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/auth/opaque/login/start"))
        .respond_with(LoginStart::new(setup, record, Some("optional")))
        .mount(&server)
        .await;
    let session_id = mount_successful_plaintext_login(&server).await;

    let result = client(&server)
        .login_opaque("alice", "not the password")
        .await
        .expect("the plaintext retry succeeded, so login_opaque must succeed");

    assert!(!result.mfa_required);
    assert_eq!(result.session_id, Some(session_id));
    assert_eq!(
        calls_to(&server, "/auth/login").await,
        1,
        "exactly one retry over the plaintext path"
    );
    assert_eq!(
        calls_to(&server, "/login/finish").await,
        0,
        "no KE3 may be sent once the envelope fails"
    );
}

#[tokio::test]
async fn under_optional_a_failed_exchange_and_a_failed_retry_reports_the_retrys_error() {
    // The fallback is not a way to hide a genuine bad password: what the
    // caller sees is whatever `/auth/login` said.
    let (server, setup, record) = enrolled().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/auth/opaque/login/start"))
        .respond_with(LoginStart::new(setup, record, Some("optional")))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/v1/auth/login"))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({
            "error": "invalid_credentials",
            "message": "invalid username or password",
        })))
        .mount(&server)
        .await;

    let err = client(&server)
        .login_opaque("alice", "not the password")
        .await
        .unwrap_err();
    assert!(
        matches!(err, AxiamError::Auth { .. }),
        "a failed retry surfaces as an AuthError, got {err:?}"
    );
    assert_eq!(calls_to(&server, "/auth/login").await, 1);
    assert_eq!(
        calls_to(&server, "/login/finish").await,
        0,
        "no KE3 may be sent once the envelope fails"
    );
}

#[tokio::test]
async fn under_required_a_failed_exchange_is_final_and_never_touches_plaintext_login() {
    // `required` answers `403 opaque_required` for every principal, so a retry
    // would put a plaintext password on the wire for nothing.
    let (server, setup, record) = enrolled().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/auth/opaque/login/start"))
        .respond_with(LoginStart::new(setup, record, Some("required")))
        .mount(&server)
        .await;
    mount_successful_plaintext_login(&server).await;

    let err = client(&server)
        .login_opaque("alice", "not the password")
        .await
        .unwrap_err();
    assert!(
        matches!(err, AxiamError::Auth { .. }),
        "expected an AuthError, got {err:?}"
    );
    assert_eq!(
        calls_to(&server, "/auth/login").await,
        0,
        "under `required` the plaintext path must never be tried"
    );
    assert_eq!(calls_to(&server, "/login/finish").await, 0);
}

#[tokio::test]
async fn a_response_with_no_mode_field_behaves_exactly_like_required() {
    // A server older than the field. Failing closed is the only safe reading:
    // the alternative sends a plaintext password to a server whose policy the
    // SDK does not know.
    let (server, setup, record) = enrolled().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/auth/opaque/login/start"))
        .respond_with(LoginStart::new(setup, record, None))
        .mount(&server)
        .await;
    mount_successful_plaintext_login(&server).await;

    let err = client(&server)
        .login_opaque("alice", "not the password")
        .await
        .unwrap_err();
    assert!(
        matches!(err, AxiamError::Auth { .. }),
        "expected an AuthError, got {err:?}"
    );
    assert_eq!(
        calls_to(&server, "/auth/login").await,
        0,
        "an absent mode must not be read as `optional`"
    );
    assert_eq!(calls_to(&server, "/login/finish").await, 0);
}

#[tokio::test]
async fn an_unrecognised_mode_fails_closed_like_required() {
    // A mode this SDK has never heard of is not a licence to send the
    // plaintext.
    let (server, setup, record) = enrolled().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/auth/opaque/login/start"))
        .respond_with(LoginStart::new(setup, record, Some("enforced-someday")))
        .mount(&server)
        .await;
    mount_successful_plaintext_login(&server).await;

    let err = client(&server)
        .login_opaque("alice", "not the password")
        .await
        .unwrap_err();
    assert!(matches!(err, AxiamError::Auth { .. }), "{err:?}");
    assert_eq!(calls_to(&server, "/auth/login").await, 0);
    assert_eq!(calls_to(&server, "/login/finish").await, 0);
}

#[tokio::test]
async fn the_optional_retry_still_never_puts_the_password_on_the_opaque_wire() {
    // The retry is a plaintext login and carries the password by definition —
    // but the OPAQUE endpoints must remain clean.
    let (server, setup, record) = enrolled().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/auth/opaque/login/start"))
        .respond_with(LoginStart::new(setup, record, Some("optional")))
        .mount(&server)
        .await;
    mount_successful_plaintext_login(&server).await;

    let _ = client(&server).login_opaque("alice", PASSWORD).await;

    for received in server.received_requests().await.unwrap() {
        if received.url.path().contains("/auth/opaque/") {
            let body = String::from_utf8_lossy(&received.body);
            assert!(
                !body.contains(PASSWORD),
                "{} carried the plaintext password",
                received.url
            );
        }
    }
}
