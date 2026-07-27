//! "Login with AXIAM" via the CONTRACT.md §12 OIDC/SSO relying-party helpers.
//!
//! Demonstrates the full authorization-code + PKCE round trip using all of:
//! `oidc_discover`, `oidc_begin`, `oidc_exchange`, plus a
//! [`axiam_sdk::oidc::MemoryOidcStateStore`] to bridge the "redirect the
//! browser" step and the "handle the callback" step — two separate HTTP
//! requests in a real web app, simulated here in one process for a
//! self-contained, illustrative example.
//!
//! This example is illustrative/compilable — it reads connection details
//! from environment variables and does not itself perform a browser
//! redirect. Running the full flow end-to-end against a live AXIAM server
//! additionally requires a real browser round trip to the
//! `authorize_url` and a callback with the resulting `code`.
//!
//! Run: `cargo run --example oidc_login --features rest`

use axiam_sdk::client::AxiamClient;
use axiam_sdk::oidc::{
    MemoryOidcStateStore, OidcBeginParams, OidcExchangeParams, OidcStateEntry, OidcStateStore,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let base_url =
        std::env::var("AXIAM_BASE_URL").unwrap_or_else(|_| "https://localhost:8443".to_string());
    let tenant_id = std::env::var("AXIAM_TENANT_ID")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(uuid::Uuid::new_v4);
    let client_id = std::env::var("AXIAM_OIDC_CLIENT_ID").unwrap_or_else(|_| "my-app".to_string());
    let client_secret = std::env::var("AXIAM_OIDC_CLIENT_SECRET").ok();
    let redirect_uri = std::env::var("AXIAM_OIDC_REDIRECT_URI")
        .unwrap_or_else(|_| "https://app.example.com/auth/callback".to_string());

    let mut builder = AxiamClient::builder()
        .base_url(&base_url)?
        .tenant_id(tenant_id)
        .oidc_client_id(client_id);
    if let Some(secret) = client_secret {
        builder = builder.oidc_client_secret(secret);
    }
    let client = builder.build()?;

    // A store bridging the two HTTP requests of a real redirect flow —
    // strictly optional (CONTRACT.md §12.3 rule 1); the SDK itself stores
    // nothing.
    let store = MemoryOidcStateStore::new();

    // --- Step 1: build the authorization request (login route) ---------
    let configuration = client.oidc_discover().await?;
    let request = client.oidc_begin(
        &configuration,
        OidcBeginParams::new(redirect_uri.clone()).with_scope("openid profile email"),
    )?;

    println!("Redirect the user agent to: {}", request.url);

    store
        .save(OidcStateEntry {
            state: request.state.clone(),
            nonce: request.nonce.clone(),
            code_verifier: request.code_verifier,
            redirect_uri: redirect_uri.clone(),
            return_to: Some("/dashboard".to_string()),
        })
        .await;

    // --- Step 2: the callback route (normally a separate HTTP request) -
    // In a real application, `callback_state`/`callback_code` come from the
    // IdP's redirect query parameters. This example has no live IdP to
    // redirect through, so it stops here rather than fabricating a code.
    let callback_state = request.state;
    let entry = store
        .consume(&callback_state)
        .await
        .expect("state was just saved above (single-use consume)");

    println!(
        "Would now exchange code from the callback using nonce {} and the stored code_verifier for redirect_uri {}",
        entry.nonce, entry.redirect_uri
    );
    println!(
        "(Skipping the actual exchange: this example has no live IdP to redirect through and back.) \
         In a real handler: client.oidc_exchange({{ code: <from callback>, code_verifier: entry.code_verifier, \
         nonce: entry.nonce, redirect_uri: entry.redirect_uri, .. }}).await?"
    );

    // What that call would look like, for reference (not executed — `code`
    // would come from the real IdP callback):
    let _unused = OidcExchangeParams {
        code: "authorization-code-from-callback".to_string(),
        code_verifier: entry.code_verifier,
        redirect_uri: entry.redirect_uri,
        nonce: entry.nonce,
        tenant_id: None,
        configuration: Some(configuration),
    };

    Ok(())
}
