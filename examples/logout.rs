//! RP-initiated and back-channel logout (CONTRACT.md §12.7).
//!
//! Two halves that close each other's hole. Without the first, a user who
//! logs out of your app stays logged in at AXIAM and is silently signed back
//! in on the next "Login with AXIAM". Without the second, a user who logs out
//! *of AXIAM* stays logged in at your app indefinitely, because nothing tells
//! you — which is what leaves live sessions behind when an admin revokes a
//! compromised account.
//!
//! Run: `cargo run --example logout --features rest`

use axiam_sdk::Sensitive;
use axiam_sdk::client::AxiamClient;
use axiam_sdk::oidc::LogoutUrlParams;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let base_url =
        std::env::var("AXIAM_BASE_URL").unwrap_or_else(|_| "https://localhost:8443".to_string());
    let tenant_id = std::env::var("AXIAM_TENANT_ID")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(uuid::Uuid::new_v4);
    let client_id = std::env::var("AXIAM_OIDC_CLIENT_ID").unwrap_or_else(|_| "my-app".to_string());

    let client = AxiamClient::builder()
        .base_url(&base_url)?
        .tenant_id(tenant_id)
        .oidc_client_id(&client_id)
        .build()?;

    let configuration = client.oidc_discover().await?;

    // ---------------------------------------------------------------
    // Half 1: the user clicked "log out" in YOUR app.
    // ---------------------------------------------------------------

    // The ID token you stored at login. It is what identifies *which*
    // session to end — a signed statement rather than a parameter anyone
    // could send. AXIAM does not check its expiry (a logging-out user's ID
    // token has usually expired already), but it does check the signature.
    let stored_id_token =
        std::env::var("AXIAM_ID_TOKEN").unwrap_or_else(|_| "the-id-token-from-login".to_string());

    // `state` is yours to generate and yours to check when it comes back.
    // The SDK passes it through and never invents one, because the value
    // only means something to the app that will receive it.
    let state = "csrf-value-you-stored-in-the-session";

    let url = client.logout_url(
        &configuration,
        LogoutUrlParams {
            id_token: Sensitive::new(stored_id_token),
            post_logout_redirect_uri: Some("https://app.example.com/goodbye".to_string()),
            state: Some(state.to_string()),
        },
    )?;

    // Redirect the browser here. Note what the SDK did NOT do: it did not
    // clear this client's own session. Whether your local session ends is
    // your decision — a backend holding a service-account session must not
    // lose it because a *user* logged out.
    println!("Redirect the user agent to:\n  {url}");

    // The redirect URI is honoured only if it exactly matches your client's
    // registered `post_logout_redirect_uris` — a separate list from
    // `redirect_uris`. The SDK does not pre-check it against a local copy
    // (§12.7.2 rule 3): that copy would drift and would reject a URI an
    // operator had just registered. If it does not match, AXIAM still logs
    // the user out and renders its own page.

    // ---------------------------------------------------------------
    // Half 2: AXIAM tells YOU a session ended.
    // ---------------------------------------------------------------
    //
    // Mount this at the `backchannel_logout_uri` you registered. AXIAM POSTs
    // `logout_token=<jwt>`, form-encoded.

    let inbound_logout_token = std::env::var("AXIAM_LOGOUT_TOKEN").ok();
    if let Some(token) = inbound_logout_token {
        match client.verify_logout_token(&token, &configuration).await {
            Ok(verified) => {
                // Dedup on `jti` in YOUR store. Delivery is at-least-once, so
                // a valid token legitimately arrives twice — that is a retry,
                // not an attack. The SDK deliberately does not dedup: it has
                // no durable store, and an in-memory guard would silently
                // drop a real second logout after a restart.
                println!("logout token {} verified", verified.jti);

                match verified.sid.as_deref() {
                    // End THAT session only. Falling back to "every session
                    // for this user" is over-reach AXIAM itself refuses to
                    // make — the user's other devices are still signed in on
                    // purpose.
                    Some(sid) => println!("end session {sid} only"),
                    None => println!(
                        "no sid: this token names only sub {:?}",
                        verified.sub.as_deref()
                    ),
                }
            }
            Err(e) => {
                // Answer 400 and log. Do not end anything: an unverifiable
                // token is not a logout instruction, and treating it as one
                // would make your endpoint a denial-of-service primitive for
                // anyone who can reach it.
                eprintln!("rejected logout token: {e}");
            }
        }
    }

    Ok(())
}
