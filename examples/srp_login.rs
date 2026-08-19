//! CONTRACT.md §23 — SRP-6a login, with the password-login fallback.
//!
//! Run against a live AXIAM whose tenant has `srp_mode` set to `optional` or
//! `required`:
//!
//! ```bash
//! AXIAM_URL=https://axiam.example \
//! AXIAM_ORG=acme AXIAM_TENANT=default \
//! AXIAM_USER=alice AXIAM_PASSWORD='…' \
//!   cargo run --example srp_login --features srp
//! ```
//!
//! What is worth reading here is the *ordering* and the *error handling*, not
//! the happy path: SRP is attempted first so a tenant on `srp_mode: optional`
//! actually gets SRP logins, and the two failure modes that are not "wrong
//! password" are handled distinctly.

use axiam_sdk::AxiamError;
use axiam_sdk::client::AxiamClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let base_url = std::env::var("AXIAM_URL")?;
    let org = std::env::var("AXIAM_ORG")?;
    let tenant = std::env::var("AXIAM_TENANT")?;
    let user = std::env::var("AXIAM_USER")?;
    let password = std::env::var("AXIAM_PASSWORD")?;

    let client = AxiamClient::builder()
        .base_url(&base_url)?
        .org_slug(&org)
        .tenant_slug(&tenant)
        .build()?;

    // SRP first, password second. The reverse order — password login, SRP only
    // when refused — would mean a tenant running `srp_mode: optional` never
    // sees a single SRP login, which is the mode operators run for the whole
    // of a migration.
    println!("attempting SRP (the pause is the KDF, and it is the point)…");
    let result = match client.login_srp(&user, &password).await {
        Ok(result) => {
            println!("signed in over SRP — the password never left this process");
            result
        }

        // The tenant does not offer SRP. A property of the tenant, not of the
        // credentials, and reported as `NetworkError` rather than `AuthError`
        // precisely so it cannot be mistaken for a bad password.
        Err(e) if is_srp_unavailable(&e) => {
            println!("tenant has SRP disabled — falling back to password login");
            client.login(&user, &password).await?
        }

        // The endpoint that answered could not prove it holds this account's
        // verifier, so it is not the server it claims to be. Do NOT retry over
        // the password path: that hands the same endpoint the plaintext it just
        // failed to prove it deserves.
        Err(e) if e.to_string().contains("failed to prove") => {
            eprintln!("ABORTED: {e}");
            eprintln!("Not retrying with a password — this endpoint does not hold the verifier.");
            std::process::exit(1);
        }

        Err(e) => return Err(e.into()),
    };

    if result.mfa_required {
        println!(
            "MFA required ({}). Enter the code:",
            result.available_methods.join(", ")
        );
        let mut code = String::new();
        std::io::stdin().read_line(&mut code)?;
        client.verify_mfa(code.trim()).await?;
        println!("MFA accepted");
    }

    println!(
        "session established (expires in {}s)",
        result.expires_in.unwrap_or(0)
    );

    client.logout().await?;
    client.close().await;
    Ok(())
}

/// Whether this error means "the tenant does not do SRP" rather than "your
/// password is wrong".
///
/// Matched on the message because §2 gives SDKs exactly three error types and
/// this is a `NetworkError` among many — an application that needs to branch on
/// it more robustly should probe the tenant's policy from `/auth/me` instead of
/// inferring it from a failure.
fn is_srp_unavailable(err: &AxiamError) -> bool {
    err.to_string()
        .contains("does not offer Secure Remote Password")
}
