//! Device Authorization Grant (CONTRACT.md §14) — signing in a device that
//! cannot show a browser.
//!
//! The shape this example is really demonstrating: the SDK hands you the
//! user code and verification URI *before* it starts polling, and what you do
//! with them is yours. Here that is `println!`; on a real device it is a
//! screen, a QR code, or an e-ink panel. The SDK deliberately never prints
//! them for you (§14.3 rule 2).
//!
//! Run: `cargo run --example device_login --features rest`

use axiam_sdk::client::AxiamClient;
use axiam_sdk::oidc::DeviceLoginParams;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let base_url =
        std::env::var("AXIAM_BASE_URL").unwrap_or_else(|_| "https://localhost:8443".to_string());
    let tenant_id = std::env::var("AXIAM_TENANT_ID")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(uuid::Uuid::new_v4);
    let client_id =
        std::env::var("AXIAM_OIDC_CLIENT_ID").unwrap_or_else(|_| "my-device".to_string());

    // No client secret: a device that cannot show a browser cannot keep one
    // either, and §14.1 makes `device_authorize` unauthenticated for exactly
    // that reason.
    let client = AxiamClient::builder()
        .base_url(&base_url)?
        .tenant_id(tenant_id)
        .oidc_client_id(&client_id)
        .build()?;

    println!("Starting device authorization…");

    let tokens = client
        .device_login(
            DeviceLoginParams {
                scope: Some("openid profile".to_string()),
                ..Default::default()
            },
            |authorization| {
                // Called BEFORE the first poll. Display, then the SDK waits.
                println!();
                println!("  To sign in, visit: {}", authorization.verification_uri);
                println!("  and enter code:    {}", authorization.user_code);
                if let Some(complete) = &authorization.verification_uri_complete {
                    // Prefer this when the device can render a QR code — the
                    // user then types nothing at all. Never build it
                    // yourself when it is absent: the format is the
                    // server's to choose (§14.3).
                    println!("  or go straight to: {complete}");
                }
                println!();
                println!("Waiting for approval…");
            },
        )
        .await?;

    // §14.3 rule 4 (contract 1.7): the Rust SDK returns the tokens rather
    // than adopting them, matching its `login_client_credentials` posture.
    // Storing them is the application's decision.
    println!("Signed in. Access token expires in {}s.", tokens.expires_in);
    if let Some(claims) = &tokens.id_claims {
        println!("Subject: {}", claims.sub);
    }

    // The two failure modes worth telling apart in real code — a human said
    // no, versus nobody answered:
    //
    //   Err(e) if e.oauth_error_code() == Some("access_denied")  => refused
    //   Err(e) if e.oauth_error_code() == Some("expired_token")  => timed out
    //
    // Collapsing them loses the only information the device can act on
    // (§14.2 rule 3): whether re-prompting could possibly help.

    Ok(())
}
