//! WebAuthn / passkeys from Rust — CONTRACT.md §24.
//!
//! The native Rust build has no authenticator, so this SDK ships the
//! **relying-party** half of a passkey ceremony: the four JSON round trips with
//! AXIAM. That is not a consolation prize. A Rust service completing a ceremony
//! that ran on an Android or iOS handset is the relying party exactly as a
//! browser is, and this is the shape that service takes:
//!
//! 1. Ask AXIAM for a challenge.
//! 2. Hand the client the challenge in its platform JSON form (§24.6a) — the
//!    exact string Android's `CreatePublicKeyCredentialRequest` and a browser's
//!    `parseCreationOptionsFromJSON()` both take.
//! 3. Take the client's response JSON back, unaltered, and post it to AXIAM.
//!
//! Nothing here emulates an authenticator. §24.6b rule 2 forbids it: a
//! "credential" held in process memory is not a second factor.
//!
//! `axiam-sdk-wasm` is the one build of this SDK that *does* reach an
//! authenticator, through `web-sys`.
//!
//! Run: `AXIAM_BASE_URL=… cargo run --example webauthn_relying_party --features rest`

use axiam_sdk::client::AxiamClient;
use axiam_sdk::rest::{WebauthnFailure, webauthn_response_from_json};
use axiam_sdk::{AxiamError, Sensitive};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = AxiamClient::builder()
        .base_url(env_or("AXIAM_BASE_URL", "https://iam.example.com"))?
        .tenant_slug(env_or("AXIAM_TENANT_SLUG", "acme"))
        .org_slug(env_or("AXIAM_ORG_SLUG", "globex"))
        .build()?;

    if let Err(err) = sign_in_with_a_passkey(&client).await {
        eprintln!("sign-in: {err}");
    }
    Ok(())
}

/// Usernameless sign-in, driven from a service.
///
/// The workspace still has to be named — a discoverable credential is resolved
/// inside one tenant — but it comes from the client's own configuration, and
/// this endpoint accepts slugs.
async fn sign_in_with_a_passkey(client: &AxiamClient) -> Result<(), Box<dyn std::error::Error>> {
    let challenge = client.webauthn_discoverable_start(None).await?;

    // This string goes to the device untouched — every WebAuthn option is a
    // security parameter the server chose, and a client that "helpfully"
    // adjusts one has weakened a ceremony the server believes it configured
    // (§24.0).
    let response_json = send_to_device_and_await_reply(&challenge.request_json())?;

    let session = client
        .webauthn_discoverable_finish(
            &challenge.state_token,
            webauthn_response_from_json(&response_json)?,
        )
        .await?;

    // The client is authenticated now — §24.3 rule 1 is not "MAY adopt".
    println!(
        "signed in, session {}, expires in {}s",
        session.session_id, session.expires_in
    );
    Ok(())
}

/// Enrol a credential for the signed-in user.
#[allow(dead_code)]
async fn enrol_a_passkey(
    client: &AxiamClient,
    name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let challenge = client.webauthn_register_start().await?;
    let response_json = send_to_device_and_await_reply(&challenge.request_json())?;

    // The response goes back byte-for-byte: it is the input to a signature
    // check over bytes this process did not produce.
    match client
        .webauthn_register_finish(
            &challenge.state_token,
            name,
            webauthn_response_from_json(&response_json)?,
        )
        .await
    {
        Ok(credential) => {
            println!(
                "enrolled {} {:?}",
                credential.credential_type, credential.name
            );
            Ok(())
        }
        // §24.4 rule 1: the tenant's attestation policy refusing THIS
        // authenticator, and its message is the only way the person holding the
        // key learns a different one would work.
        Err(AxiamError::Authz { message, .. }) => {
            Err(format!("attestation policy refused this device: {message}").into())
        }
        Err(other) => Err(other.into()),
    }
}

/// Passkey as a second factor, continuing a password login.
#[allow(dead_code)]
async fn sign_in_with_password_then_passkey(
    client: &AxiamClient,
    email: &str,
    password: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let result = client.login(email, password).await?;

    if result.mfa_setup_required {
        // §25.2 rule 1 — see examples/account_lifecycle.rs.
        println!("this tenant requires MFA and this account has none");
        return Ok(());
    }
    let Some(challenge_token) = result.challenge_token.as_ref() else {
        println!("signed in with the password alone");
        return Ok(());
    };

    let challenge = client.webauthn_authenticate_start(challenge_token).await?;
    let response_json = send_to_device_and_await_reply(&challenge.request_json())?;
    client
        .webauthn_authenticate_finish(
            &challenge.state_token,
            webauthn_response_from_json(&response_json)?,
        )
        .await?;

    println!("signed in with a passkey as the second factor");
    Ok(())
}

/// Translate a failure the device reported into one vocabulary.
///
/// Every platform reports a ceremony failure as one opaque type whose only
/// machine-readable part is a name, so a device can relay just that. The five
/// outcomes are the same everywhere, and `AlreadyRegistered` is the one worth
/// separating: the authenticator already holds a credential for this account
/// and refused to mint a second, so the remedy is a different device rather
/// than another attempt.
#[allow(dead_code)]
fn report_a_device_failure(error_name_from_device: &str) {
    let failure = WebauthnFailure::classify(error_name_from_device);
    if failure == WebauthnFailure::AlreadyRegistered {
        println!("this device is already enrolled — try another");
    }
    println!("{}", failure.message());
}

/// Stand-in for your own channel to the device.
///
/// In a real deployment this is a websocket to a mobile app, a push
/// notification, a QR-code handshake — whatever carries the string there and
/// the answer back. Both directions are opaque to this process, which is the
/// point.
fn send_to_device_and_await_reply(
    request_json: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let _ = request_json;
    Err(
        "wire this to your own device channel; it must return the platform's \
         registrationResponseJson / authenticationResponseJson verbatim"
            .into(),
    )
}

fn env_or(key: &str, fallback: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| fallback.to_string())
}

/// Keeps the `Sensitive` import honest for readers scanning the example: every
/// token this file touches is one.
#[allow(dead_code)]
fn secrets_are_wrapped(token: &Sensitive<String>) -> bool {
    !token.expose().is_empty()
}
