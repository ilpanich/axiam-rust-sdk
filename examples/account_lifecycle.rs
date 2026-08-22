//! Account lifecycle and MFA enrolment — CONTRACT.md §25.
//!
//! The operations that get an account into the state §1's `login`/`verify_mfa`/
//! `refresh`/`logout` already assume: email verification, both MFA enrolment
//! paths, and password reset.
//!
//! Run: `AXIAM_BASE_URL=… cargo run --example account_lifecycle --features rest`

use axiam_sdk::Sensitive;
use axiam_sdk::client::AxiamClient;
use axiam_sdk::rest::{PasswordResetConfirmation, PasswordResetRequest};
use uuid::Uuid;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = AxiamClient::builder()
        .base_url(env_or("AXIAM_BASE_URL", "https://iam.example.com"))?
        .tenant_slug(env_or("AXIAM_TENANT_SLUG", "acme"))
        .org_slug(env_or("AXIAM_ORG_SLUG", "globex"))
        .build()?;

    start_a_password_reset(&client, "alice@example.com").await?;
    Ok(())
}

/// Voluntary enrolment, by a signed-in user.
///
/// Two calls, and deliberately no one-call helper: the human step in the middle
/// — scanning the URI, reading a code off a phone — is not something a composed
/// helper can wait for, and one that returned after `mfa_enroll` would report
/// MFA as enabled when it is not (§25.2 rule 4).
#[allow(dead_code)]
async fn enrol_totp(
    client: &AxiamClient,
    code_from_user: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let enrolment = client.mfa_enroll().await?;

    // `totp_uri` CONTAINS the secret: it is `otpauth://…?secret=…`. Both are
    // Sensitive for that reason, and the URI is the one that actually reaches
    // a log, because it is the one you hand to a QR renderer (§25.3).
    render_qr(enrolment.totp_uri.expose());

    if client.mfa_confirm(code_from_user).await? {
        println!("TOTP is now active");
    }
    Ok(())
}

/// Sign in, handling the enrolment a tenant may demand.
///
/// Before contract 1.28 the `403 mfa_setup_required` answer reached callers as
/// an `AxiamError::Authz` — telling them they lacked permission to log in, when
/// what the server said was recoverable and came with the means to recover. It
/// is an outcome now (§25.2 rule 1), which is the whole reason this function
/// can be written at all.
#[allow(dead_code)]
async fn sign_in(
    client: &AxiamClient,
    email: &str,
    password: &str,
    code_from_user: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let result = client.login(email, password).await?;

    if result.mfa_setup_required {
        let setup_token = result
            .setup_token
            .as_ref()
            .expect("§25.2 rule 1 populates this");
        let enrolment = client.mfa_setup_enroll(setup_token).await?;
        render_qr(enrolment.totp_uri.expose());
        // This completes the login that was interrupted, and adopts
        // credentials exactly as `login()` would have (§25.2 rule 2).
        client
            .mfa_setup_confirm(setup_token, code_from_user)
            .await?;
        println!("enrolled and signed in");
    } else if result.mfa_required {
        client.verify_mfa(code_from_user).await?;
        println!("signed in with the second factor");
    } else {
        println!("signed in");
    }
    Ok(())
}

/// Ask for a reset mail.
///
/// Returns `Ok(())` **whether or not the address exists**, and this SDK exposes
/// no way to tell the difference. That is not an omission to improve on: any
/// signal distinguishing them — including one inferred from timing — turns the
/// endpoint into the account enumeration oracle its uniform response exists to
/// prevent (§25.4).
async fn start_a_password_reset(
    client: &AxiamClient,
    email: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    client
        .request_password_reset(&PasswordResetRequest {
            email: email.to_string(),
            ..Default::default()
        })
        .await?;
    println!("if that address has an account, a reset mail is on its way");
    Ok(())
}

/// Set the new password.
///
/// The context call is not optional on a tenant that might have OPAQUE enabled
/// (§23): the client has to build a registration record, and building one needs
/// parameters it cannot know before it has a token to ask with. Sending a
/// plaintext password to a tenant in `opaque_mode: required` is refused, and
/// refused late.
#[allow(dead_code)]
async fn finish_a_password_reset(
    client: &AxiamClient,
    token_from_link: &str,
    new_password: &str,
    tenant_id: Uuid,
) -> Result<(), Box<dyn std::error::Error>> {
    let token = Sensitive::new(token_from_link.to_string());
    let context = client.password_reset_context(&token).await?;

    client
        .confirm_password_reset(&PasswordResetConfirmation {
            token,
            new_password: Sensitive::new(new_password.to_string()),
            tenant_id,
            // Build the §23 record here when `context.opaque` is `Some`; the
            // OPAQUE helpers live behind the `opaque` feature.
            opaque: context.opaque.as_ref().map(|_| {
                unimplemented!(
                    "build the §23 registration record with the `opaque` feature enabled"
                )
            }),
        })
        .await?;
    println!("password changed");
    Ok(())
}

/// Stand-in for showing the enrolment URI to a human.
fn render_qr(totp_uri: &str) {
    println!("scan this: {}…", &totp_uri[..totp_uri.len().min(32)]);
}

fn env_or(key: &str, fallback: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| fallback.to_string())
}
