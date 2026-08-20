//! OPAQUE (RFC 9807) login and enrolment — CONTRACT.md §23.
//!
//! ```bash
//! AXIAM_URL=https://axiam.example \
//! AXIAM_ORG=acme AXIAM_TENANT=default \
//! AXIAM_USER=alice AXIAM_PASSWORD='correct horse battery staple' \
//!   cargo run --example opaque_login --features opaque
//! ```
//!
//! Requires the target tenant to have `opaque_mode` set to `optional` or
//! `required`.

use axiam_sdk::AxiamError;
use axiam_sdk::client::AxiamClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let base_url = std::env::var("AXIAM_URL")?;
    let org = std::env::var("AXIAM_ORG")?;
    let tenant = std::env::var("AXIAM_TENANT")?;
    let username = std::env::var("AXIAM_USER")?;
    let password = std::env::var("AXIAM_PASSWORD")?;

    let client = AxiamClient::builder()
        .base_url(&base_url)?
        .org_slug(&org)
        .tenant_slug(&tenant)
        .build()?;

    // ------------------------------------------------------------------
    // Sign in.
    // ------------------------------------------------------------------
    //
    // Two round trips, and the password does not appear in either. What
    // crosses the wire is a blinded group element and a MAC, useless without
    // the account's record *and* the tenant's OPRF seed.
    //
    // Note what this example does not do, where its SRP predecessor had to:
    // check a server proof afterwards. RFC 9807's AKE authenticates the server
    // during the handshake, so by the time this returns `Ok` the server has
    // already proved it holds the record.
    let result = match client.login_opaque(&username, &password).await {
        Ok(result) => result,
        // A `NetworkError` means the tenant has OPAQUE disabled, or this build
        // cannot perform the KSF the server named — either way a configuration
        // fault rather than a wrong password, and the one case where falling
        // back to `login()` is correct.
        Err(AxiamError::Network { message, .. }) => {
            eprintln!("OPAQUE unavailable ({message}); falling back to password login");
            client.login(&username, &password).await?
        }
        // An `AuthError` is a failed exchange: wrong password, no such
        // account, or a server that does not hold the record, indistinguishable
        // by design. Retrying it over `login()` would hand the plaintext to a
        // server that just failed to prove itself, so this returns.
        Err(e) => return Err(e.into()),
    };

    if result.mfa_required {
        println!("signed in over OPAQUE; MFA challenge issued");
    } else {
        println!("signed in over OPAQUE; session {:?}", result.session_id);
    }

    // ------------------------------------------------------------------
    // Enrol a record for a new password.
    // ------------------------------------------------------------------
    //
    // Attach this to any request that sets a password. It performs a
    // `register/start` round trip, which the SRP verifier did not need: the
    // envelope is sealed under the server's oblivious PRF, so there is no
    // offline computation that produces a valid record.
    //
    // There is no identity argument. SRP required the account's canonical
    // username, and passing an email produced a verifier no login could ever
    // satisfy; a record binds to a credential identifier the server chooses,
    // so a later rename cannot invalidate it either.
    if let Ok(new_password) = std::env::var("AXIAM_NEW_PASSWORD") {
        let enrollment = client.opaque_enrollment(&new_password).await?;
        println!(
            "built an enrolment ({} bytes of record) — attach it as the \
             request body's `opaque` field",
            enrollment.registration_record.len() / 2
        );
    }

    Ok(())
}
