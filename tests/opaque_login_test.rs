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
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};
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
        payload
            .as_object_mut()
            .unwrap()
            .extend(ksf_fields().as_object().unwrap().clone());
        ResponseTemplate::new(200).set_body_json(payload)
    }
}

fn client(server: &MockServer) -> AxiamClient {
    AxiamClient::builder()
        .base_url(&server.uri())
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
        .respond_with(LoginStart { setup, record })
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
        .respond_with(LoginStart { setup, record })
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
