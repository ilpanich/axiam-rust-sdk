//! §24 WebAuthn relying-party layer — the CONTRACT.md §24.8 test set.
//!
//! Every assertion maps to a named requirement in §24.8. Two are worth reading
//! twice:
//!
//! * `register_start_does_not_retry_503` asserts on the **request count**, not
//!   the error variant, because §24.4 rule 2 regresses the moment someone tidies
//!   a retry predicate — and a variant assertion would still pass.
//!
//! * `state_token_is_never_parsed` hands the SDK a state token that is not a
//!   JWT at all. If anything decoded one, this is where it would fail.

#![cfg(feature = "rest")]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use axiam_sdk::client::AxiamClient;
use axiam_sdk::rest::{WebauthnFailure, WebauthnWorkspace, webauthn_response_from_json};
use axiam_sdk::{AxiamError, Sensitive};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde::Serialize;
use serde_json::{Value, json};
use uuid::Uuid;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

const STATE_TOKEN: &str = "state-token-fixture-value-do-not-log";
const CHALLENGE_TOKEN: &str = "challenge-token-fixture-do-not-log";
const ACCESS_TOKEN_FIXTURE: &str = "access-token-fixture-do-not-log";
const REFRESH_TOKEN_FIXTURE: &str = "refresh-token-fixture-do-not-log";

const REGISTER_START: &str = "/api/v1/auth/webauthn/register/start";
const REGISTER_FINISH: &str = "/api/v1/auth/webauthn/register/finish";
const AUTH_START: &str = "/api/v1/auth/webauthn/authenticate/start";
const AUTH_FINISH: &str = "/api/v1/auth/webauthn/authenticate/finish";
const DISCOVERABLE_START: &str = "/api/v1/auth/webauthn/authenticate/discoverable/start";
const DISCOVERABLE_FINISH: &str = "/api/v1/auth/webauthn/authenticate/discoverable/finish";

const TEST_ED25519_SEED: [u8; 32] = [
    0x74, 0x8c, 0x0b, 0xd3, 0xad, 0xc0, 0x28, 0x0a, 0xfd, 0xd7, 0xc0, 0x7c, 0x35, 0x07, 0x03, 0x64,
    0x6d, 0x14, 0x2d, 0x1d, 0xbd, 0x73, 0x4c, 0xd4, 0xf8, 0x17, 0x17, 0x0b, 0x91, 0x7b, 0x49, 0xfc,
];
const ED25519_PKCS8_DER_PREFIX: [u8; 16] = [
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];
const TEST_ED25519_PUBLIC_X: &str = "_r-I_0nRSSV8kvwA93gwhX-hFRiWkaNk5HEud-DjnMk";
const TEST_KID: &str = "test-kid-1";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// Deliberately "unusual but valid": every optional field populated, so the
/// pass-through assertion has something to catch an over-eager implementation
/// dropping. A minimal fixture would prove nothing.
fn creation_challenge() -> Value {
    json!({
        "publicKey": {
            "challenge": "Y2hhbGxlbmdlLWJ5dGVz",
            "rp": { "id": "axiam.test", "name": "AXIAM Test" },
            "user": { "id": "dXNlci1oYW5kbGU", "name": "alice", "displayName": "Alice" },
            "pubKeyCredParams": [
                { "type": "public-key", "alg": -7 },
                { "type": "public-key", "alg": -8 },
                { "type": "public-key", "alg": -257 }
            ],
            "timeout": 60000,
            "excludeCredentials": [
                { "id": "ZXhpc3Rpbmc", "type": "public-key", "transports": ["usb", "nfc"] }
            ],
            "authenticatorSelection": {
                "residentKey": "required",
                "requireResidentKey": true,
                "userVerification": "required"
            },
            "attestation": "direct",
            "extensions": { "credProps": true }
        }
    })
}

fn minimal_creation_challenge() -> Value {
    json!({
        "publicKey": {
            "challenge": "bWluaW1hbA",
            "rp": { "name": "AXIAM Test" },
            "user": { "id": "dQ", "name": "bob", "displayName": "Bob" },
            "pubKeyCredParams": [{ "type": "public-key", "alg": -7 }]
        }
    })
}

fn discoverable_challenge() -> Value {
    json!({
        "publicKey": {
            "challenge": "ZGlzY292ZXJhYmxl",
            "rpId": "axiam.test",
            "allowCredentials": [],
            "userVerification": "required"
        }
    })
}

/// Carries an unknown key the SDK must forward rather than strip — the shape a
/// platform actually produces, not a curated subset.
fn registration_response() -> Value {
    json!({
        "id": "bmV3LWNyZWQ",
        "rawId": "bmV3LWNyZWQ",
        "response": {
            "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0",
            "attestationObject": "o2NmbXRkbm9uZQ",
            "transports": ["internal"],
            "vendorSpecific": "must-survive"
        },
        "type": "public-key",
        "clientExtensionResults": { "credProps": { "rk": true } }
    })
}

fn authentication_response() -> Value {
    json!({
        "id": "bmV3LWNyZWQ",
        "rawId": "bmV3LWNyZWQ",
        "response": {
            "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0In0",
            "authenticatorData": "YXV0aC1kYXRh",
            "signature": "c2ln",
            "userHandle": "dXNlci1oYW5kbGU"
        },
        "type": "public-key",
        "clientExtensionResults": {}
    })
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
    let now = chrono_now();
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
    let key = EncodingKey::from_ed_der(&der);
    let mut header = Header::new(Algorithm::EdDSA);
    header.kid = Some(TEST_KID.into());
    jsonwebtoken::encode(&header, &claims, &key).expect("encode test access token")
}

fn chrono_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs() as i64
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

/// A `200` carrying the cookie triple a completed passkey sign-in sets.
///
/// The server started setting these with contract 1.28 — before that, a passkey
/// sign-in returned tokens in the body and left the caller with no session at
/// all.
fn login_response(tenant_id: Uuid, org_id: Uuid) -> ResponseTemplate {
    let access = access_token(tenant_id, org_id);
    ResponseTemplate::new(200)
        .set_body_json(json!({
            "access_token": ACCESS_TOKEN_FIXTURE,
            "refresh_token": REFRESH_TOKEN_FIXTURE,
            "session_id": Uuid::new_v4(),
            "expires_in": 900,
        }))
        .append_header(
            "Set-Cookie",
            format!("axiam_access={access}; Path=/; HttpOnly").as_str(),
        )
        .append_header(
            "Set-Cookie",
            "axiam_refresh=refresh-cookie; Path=/; HttpOnly",
        )
        .append_header("Set-Cookie", "axiam_csrf=csrf-tok; Path=/")
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

/// Sign a client in, so `register/*`'s §24.1 precondition is satisfied.
async fn signed_in_client(server: &MockServer) -> AxiamClient {
    mount_jwks(server).await;
    let tenant_id = Uuid::new_v4();
    let org_id = Uuid::new_v4();

    // The password path answers LoginSuccessResponse, not the webauthn body —
    // this only exists to put the cookie triple in the jar so register/*'s
    // §24.1 precondition is satisfied.
    let access = access_token(tenant_id, org_id);
    Mock::given(method("POST"))
        .and(path("/api/v1/auth/login"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({
                    "user": { "id": Uuid::new_v4(), "username": "alice", "email": "a@example.com" },
                    "session_id": Uuid::new_v4(),
                    "expires_in": 900,
                }))
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
        .mount(server)
        .await;

    let client = build_client(&server.uri());
    client
        .login("alice@example.com", "pw")
        .await
        .expect("login");
    client
}

/// Mount a handler that records how many times it was hit.
async fn mount_counted(
    server: &MockServer,
    endpoint: &str,
    template: ResponseTemplate,
) -> Arc<AtomicUsize> {
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&hits);
    Mock::given(method("POST"))
        .and(path(endpoint))
        .respond_with(move |_: &Request| {
            counter.fetch_add(1, Ordering::SeqCst);
            template.clone()
        })
        .mount(server)
        .await;
    hits
}

/// Mount a handler that records the request body it received.
async fn mount_capturing(
    server: &MockServer,
    endpoint: &str,
    template: ResponseTemplate,
) -> Arc<std::sync::Mutex<Vec<Value>>> {
    let bodies = Arc::new(std::sync::Mutex::new(Vec::new()));
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

fn challenge_body(challenge: Value) -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_json(json!({
        "challenge": challenge,
        "state_token": STATE_TOKEN,
    }))
}

fn credential_body() -> ResponseTemplate {
    ResponseTemplate::new(201).set_body_json(json!({
        "id": Uuid::new_v4(),
        "credential_id": "bmV3LWNyZWQ",
        "name": "Alice's laptop",
        "credential_type": "passkey",
        "created_at": "2026-08-22T10:00:00Z",
    }))
}

// ---------------------------------------------------------------------------
// §24.0 — options and responses pass through untouched
// ---------------------------------------------------------------------------

#[tokio::test]
async fn options_pass_through_structurally_unchanged() {
    let server = MockServer::start().await;
    let client = signed_in_client(&server).await;
    Mock::given(method("POST"))
        .and(path(REGISTER_START))
        .respond_with(challenge_body(creation_challenge()))
        .mount(&server)
        .await;

    let challenge = client.webauthn_register_start().await.expect("start");
    // Structural equality, not a spot-check of three fields: the failure mode
    // this guards is an SDK that quietly drops the one option it did not
    // recognize.
    assert_eq!(challenge.challenge, creation_challenge());
}

#[tokio::test]
async fn synthesizes_no_field_the_server_omitted() {
    let server = MockServer::start().await;
    let client = signed_in_client(&server).await;
    Mock::given(method("POST"))
        .and(path(REGISTER_START))
        .respond_with(challenge_body(minimal_creation_challenge()))
        .mount(&server)
        .await;

    let challenge = client.webauthn_register_start().await.expect("start");
    let options = &challenge.challenge["publicKey"];
    for key in [
        "authenticatorSelection",
        "timeout",
        "excludeCredentials",
        "attestation",
    ] {
        assert!(options.get(key).is_none(), "SDK synthesized {key}");
    }
    assert_eq!(challenge.challenge, minimal_creation_challenge());
}

#[tokio::test]
async fn authenticator_response_is_sent_back_verbatim() {
    let server = MockServer::start().await;
    let client = signed_in_client(&server).await;
    let bodies = mount_capturing(&server, REGISTER_FINISH, credential_body()).await;

    client
        .webauthn_register_finish(
            &Sensitive::new(STATE_TOKEN.into()),
            "laptop",
            registration_response(),
        )
        .await
        .expect("finish");

    let sent = &bodies.lock().expect("lock")[0];
    assert_eq!(sent["response"], registration_response());
}

// ---------------------------------------------------------------------------
// §24.1 — preconditions and workspace resolution
// ---------------------------------------------------------------------------

#[tokio::test]
async fn register_without_a_session_makes_no_wire_call() {
    let server = MockServer::start().await;
    let hits = mount_counted(
        &server,
        REGISTER_START,
        challenge_body(creation_challenge()),
    )
    .await;
    let client = build_client(&server.uri());

    let err = client
        .webauthn_register_start()
        .await
        .expect_err("no session");
    assert!(matches!(err, AxiamError::Auth { .. }));
    // Asserted on the transport, not on the error variant alone.
    assert_eq!(hits.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn discoverable_workspace_comes_from_the_client_in_slug_form() {
    let server = MockServer::start().await;
    let bodies = mount_capturing(
        &server,
        DISCOVERABLE_START,
        challenge_body(discoverable_challenge()),
    )
    .await;
    let client = build_client(&server.uri());

    client
        .webauthn_discoverable_start(None)
        .await
        .expect("start");

    let sent = &bodies.lock().expect("lock")[0];
    assert_eq!(sent["org_slug"], "globex");
    assert_eq!(sent["tenant_slug"], "acme");
    // §24.2: a discoverable ceremony has no prior step to have minted one.
    assert!(sent.get("challenge_token").is_none());
}

#[tokio::test]
async fn discoverable_workspace_can_be_overridden() {
    let server = MockServer::start().await;
    let bodies = mount_capturing(
        &server,
        DISCOVERABLE_START,
        challenge_body(discoverable_challenge()),
    )
    .await;
    let client = build_client(&server.uri());
    let org_id = Uuid::new_v4();

    client
        .webauthn_discoverable_start(Some(&WebauthnWorkspace {
            org_id: Some(org_id),
            tenant_slug: Some("other".into()),
            ..Default::default()
        }))
        .await
        .expect("start");

    let sent = &bodies.lock().expect("lock")[0];
    assert_eq!(sent["org_id"], org_id.to_string());
    assert_eq!(sent["tenant_slug"], "other");
}

// ---------------------------------------------------------------------------
// §24.2 — two distinct flows
// ---------------------------------------------------------------------------

#[tokio::test]
async fn second_factor_start_sends_only_the_challenge_token() {
    let server = MockServer::start().await;
    let bodies = mount_capturing(
        &server,
        AUTH_START,
        challenge_body(discoverable_challenge()),
    )
    .await;
    let client = build_client(&server.uri());

    client
        .webauthn_authenticate_start(&Sensitive::new(CHALLENGE_TOKEN.into()))
        .await
        .expect("start");

    let sent = &bodies.lock().expect("lock")[0];
    assert_eq!(sent["challenge_token"], CHALLENGE_TOKEN);
    assert_eq!(sent.as_object().expect("object").len(), 1);
}

#[tokio::test]
async fn discoverable_finish_reaches_its_own_endpoint() {
    let server = MockServer::start().await;
    mount_jwks(&server).await;
    let tenant_id = Uuid::new_v4();
    let org_id = Uuid::new_v4();

    let discoverable = mount_counted(
        &server,
        DISCOVERABLE_FINISH,
        login_response(tenant_id, org_id),
    )
    .await;
    let username_bound =
        mount_counted(&server, AUTH_FINISH, login_response(tenant_id, org_id)).await;

    let client = build_client(&server.uri());
    client
        .webauthn_discoverable_finish(
            &Sensitive::new(STATE_TOKEN.into()),
            authentication_response(),
        )
        .await
        .expect("finish");

    assert_eq!(discoverable.load(Ordering::SeqCst), 1);
    assert_eq!(username_bound.load(Ordering::SeqCst), 0);
}

// ---------------------------------------------------------------------------
// §24.3 — credential adoption
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_completed_sign_in_adopts_the_session() {
    let server = MockServer::start().await;
    mount_jwks(&server).await;
    let tenant_id = Uuid::new_v4();
    let org_id = Uuid::new_v4();

    Mock::given(method("POST"))
        .and(path(AUTH_FINISH))
        .respond_with(login_response(tenant_id, org_id))
        .mount(&server)
        .await;

    let client = build_client(&server.uri());
    let result = client
        .webauthn_authenticate_finish(
            &Sensitive::new(STATE_TOKEN.into()),
            authentication_response(),
        )
        .await
        .expect("finish");

    // The client's own state — not merely that a token came back. §24.3 rule 1
    // exists because returning a token set without adopting it would make this
    // the one way to log in that does not log you in. `resolved_tenant_id` is
    // populated by `absorb_session_cookies` from the access token's claims, so
    // it is `Some` exactly when the session was adopted.
    assert_eq!(client.resolved_tenant_id().await, Some(tenant_id));
    let _ = org_id;
    assert_eq!(result.access_token.expose(), ACCESS_TOKEN_FIXTURE);
    assert_eq!(result.refresh_token.expose(), REFRESH_TOKEN_FIXTURE);
    assert_eq!(result.expires_in, 900);
}

#[tokio::test]
async fn register_finish_returns_the_credential() {
    let server = MockServer::start().await;
    let client = signed_in_client(&server).await;
    Mock::given(method("POST"))
        .and(path(REGISTER_FINISH))
        .respond_with(credential_body())
        .mount(&server)
        .await;

    let credential = client
        .webauthn_register_finish(
            &Sensitive::new(STATE_TOKEN.into()),
            "Alice's laptop",
            registration_response(),
        )
        .await
        .expect("finish");

    assert_eq!(credential.credential_id, "bmV3LWNyZWQ");
    assert_eq!(credential.credential_type, "passkey");
    assert!(credential.last_used_at.is_none());
}

// ---------------------------------------------------------------------------
// §24.4 — error taxonomy
// ---------------------------------------------------------------------------

#[tokio::test]
async fn register_start_does_not_retry_503() {
    let server = MockServer::start().await;
    let client = signed_in_client(&server).await;
    let hits = mount_counted(
        &server,
        REGISTER_START,
        ResponseTemplate::new(503).set_body_json(json!({"message": "FIDO metadata unavailable"})),
    )
    .await;

    client.webauthn_register_start().await.expect_err("503");
    // §24.4 rule 2. Asserted on the request count: a 503 here is a server
    // CONFIGURATION state, retrying changes nothing, and this regresses
    // silently the moment the retry predicate is tidied.
    assert_eq!(hits.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn a_403_is_an_authorization_error_carrying_the_policy_message() {
    let server = MockServer::start().await;
    let client = signed_in_client(&server).await;
    Mock::given(method("POST"))
        .and(path(REGISTER_FINISH))
        .respond_with(
            ResponseTemplate::new(403)
                .set_body_json(json!({"message": "this security key is not FIDO certified"})),
        )
        .mount(&server)
        .await;

    let err = client
        .webauthn_register_finish(
            &Sensitive::new(STATE_TOKEN.into()),
            "key",
            registration_response(),
        )
        .await
        .expect_err("403");

    match err {
        AxiamError::Authz { ref message, .. } => {
            // §24.4 rule 1: the policy message is the only way the person
            // holding the key learns a different one would work.
            assert!(
                message.contains("FIDO certified"),
                "the attestation policy message was lost: {message}"
            );
        }
        other => panic!("expected Authz, got {other:?}"),
    }
}

#[tokio::test]
async fn a_failed_assertion_is_an_auth_error() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(AUTH_FINISH))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({"message": "nope"})))
        .mount(&server)
        .await;

    let client = build_client(&server.uri());
    let err = client
        .webauthn_authenticate_finish(
            &Sensitive::new(STATE_TOKEN.into()),
            authentication_response(),
        )
        .await
        .expect_err("401");
    assert!(matches!(err, AxiamError::Auth { .. }));
}

// ---------------------------------------------------------------------------
// §24.5 — the state token is opaque, and Sensitive
// ---------------------------------------------------------------------------

#[tokio::test]
async fn state_token_is_never_parsed() {
    let server = MockServer::start().await;
    mount_jwks(&server).await;
    let bodies = mount_capturing(
        &server,
        AUTH_FINISH,
        login_response(Uuid::new_v4(), Uuid::new_v4()),
    )
    .await;

    // Not a JWT, not three dot-separated segments, not base64 anything. If the
    // SDK decoded state tokens at all, this would fail — which is exactly the
    // assertion §24.8 asks for.
    let not_a_jwt = "this-is-not-a-jwt-and-never-will-be";
    let client = build_client(&server.uri());
    client
        .webauthn_authenticate_finish(&Sensitive::new(not_a_jwt.into()), authentication_response())
        .await
        .expect("finish");

    assert_eq!(bodies.lock().expect("lock")[0]["state_token"], not_a_jwt);
}

#[tokio::test]
async fn secrets_never_render() {
    let server = MockServer::start().await;
    let client = signed_in_client(&server).await;
    Mock::given(method("POST"))
        .and(path(REGISTER_START))
        .respond_with(challenge_body(creation_challenge()))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(AUTH_FINISH))
        .respond_with(login_response(Uuid::new_v4(), Uuid::new_v4()))
        .mount(&server)
        .await;

    let challenge = client.webauthn_register_start().await.expect("start");
    let login = client
        .webauthn_authenticate_finish(
            &Sensitive::new(STATE_TOKEN.into()),
            authentication_response(),
        )
        .await
        .expect("finish");

    let rendered = format!("{challenge:?}{challenge:#?}{login:?}{login:#?}");
    for secret in [STATE_TOKEN, ACCESS_TOKEN_FIXTURE, REFRESH_TOKEN_FIXTURE] {
        assert!(
            !rendered.contains(secret),
            "{secret} leaked into a Debug rendering"
        );
    }
}

// ---------------------------------------------------------------------------
// §24.6a — the JSON bridge
// ---------------------------------------------------------------------------

#[tokio::test]
async fn request_json_round_trips_and_drops_the_wrapper() {
    let server = MockServer::start().await;
    let client = signed_in_client(&server).await;
    Mock::given(method("POST"))
        .and(path(REGISTER_START))
        .respond_with(challenge_body(creation_challenge()))
        .mount(&server)
        .await;

    let challenge = client.webauthn_register_start().await.expect("start");
    let parsed: Value = serde_json::from_str(&challenge.request_json()).expect("valid JSON");

    // The string an Android app hands to CreatePublicKeyCredentialRequest, and
    // a browser to PublicKeyCredential.parseCreationOptionsFromJSON.
    assert!(parsed.get("publicKey").is_none());
    assert_eq!(parsed, creation_challenge()["publicKey"]);
}

#[tokio::test]
async fn finish_accepts_a_platform_response_string() {
    let server = MockServer::start().await;
    mount_jwks(&server).await;
    let bodies = mount_capturing(
        &server,
        AUTH_FINISH,
        login_response(Uuid::new_v4(), Uuid::new_v4()),
    )
    .await;

    // A plain string, exactly as Android's authenticationResponseJson or a
    // browser's credential.toJSON() arrives.
    let platform_string = authentication_response().to_string();
    let response = webauthn_response_from_json(&platform_string).expect("valid JSON");

    let client = build_client(&server.uri());
    client
        .webauthn_authenticate_finish(&Sensitive::new(STATE_TOKEN.into()), response)
        .await
        .expect("finish");

    assert_eq!(
        bodies.lock().expect("lock")[0]["response"],
        authentication_response()
    );
}

#[test]
fn a_malformed_response_string_is_refused() {
    let err = webauthn_response_from_json("{not json").expect_err("malformed");
    assert!(matches!(err, AxiamError::Auth { .. }));
    // A JSON scalar is valid JSON but not an authenticator response.
    assert!(webauthn_response_from_json("\"a string\"").is_err());
}

// ---------------------------------------------------------------------------
// §24.6b rule 5 — the classification, with no authenticator in sight
// ---------------------------------------------------------------------------

#[test]
fn classification_maps_the_five_outcomes() {
    for (name, expected) in [
        ("NotAllowedError", WebauthnFailure::Cancelled),
        ("InvalidStateError", WebauthnFailure::AlreadyRegistered),
        ("AbortError", WebauthnFailure::Timeout),
        ("NotSupportedError", WebauthnFailure::Unsupported),
        ("SecurityError", WebauthnFailure::Unsupported),
        ("SomethingElseError", WebauthnFailure::Unknown),
        // An Android CreateCredentialException or an ASAuthorizationError code
        // relayed to a Rust service as a bare name (§24.6b rule 5's last line).
        ("canceled", WebauthnFailure::Cancelled),
        ("", WebauthnFailure::Unknown),
    ] {
        assert_eq!(
            WebauthnFailure::classify(name),
            expected,
            "classify({name})"
        );
    }
}

#[test]
fn already_registered_is_distinguishable_from_cancelled() {
    assert_ne!(
        WebauthnFailure::classify("InvalidStateError"),
        WebauthnFailure::classify("NotAllowedError")
    );
    // The only classification whose remedy is a different device.
    assert!(
        WebauthnFailure::AlreadyRegistered
            .message()
            .contains("different device")
    );
    // The same name covers a silent timeout, and the spec will not say which,
    // so the copy must not accuse the user.
    assert!(
        WebauthnFailure::Cancelled
            .message()
            .contains("cancelled or timed out")
    );
}
