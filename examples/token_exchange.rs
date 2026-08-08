//! Token Exchange (CONTRACT.md §15) — narrowing a user's token before
//! calling the next service.
//!
//! The situation: an API gateway holds a user's access token and needs to
//! call an orders service. Forwarding the user's token verbatim
//! over-privileges that call and leaves the second hop unable to tell the
//! caller from the user; using the gateway's own service credentials has the
//! right privileges but loses the user entirely. The exchange gives you both:
//! a token that acts for the user, scoped to what this one call needs.
//!
//! Run: `cargo run --example token_exchange --features rest`

use axiam_sdk::Sensitive;
use axiam_sdk::client::AxiamClient;
use axiam_sdk::oidc::TokenExchangeParams;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let base_url =
        std::env::var("AXIAM_BASE_URL").unwrap_or_else(|_| "https://localhost:8443".to_string());
    let tenant_id = std::env::var("AXIAM_TENANT_ID")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(uuid::Uuid::new_v4);
    let client_id =
        std::env::var("AXIAM_OIDC_CLIENT_ID").unwrap_or_else(|_| "api-gateway".to_string());
    let client_secret =
        std::env::var("AXIAM_OIDC_CLIENT_SECRET").unwrap_or_else(|_| "gateway-secret".to_string());

    // The user's token, as it would arrive on an inbound request.
    let user_token = std::env::var("AXIAM_SUBJECT_TOKEN")
        .unwrap_or_else(|_| "the-users-access-token".to_string());

    // Unlike §14's device, an exchanging client is a confidential service
    // and authenticates.
    let client = AxiamClient::builder()
        .base_url(&base_url)?
        .tenant_id(tenant_id)
        .oidc_client_id(&client_id)
        .oidc_client_secret(&client_secret)
        .build()?;

    // Delegation: "the gateway, acting on behalf of the user". Supplying an
    // `actor_token` is what makes it delegation; omitting it asks for
    // impersonation instead — a different operation with different risk,
    // which the server refuses unless this client holds that grant. The SDK
    // will not pick for you (§15.2 rule 1).
    let exchanged = client
        .token_exchange(TokenExchangeParams {
            scopes: Some(vec!["orders:read".to_string()]),
            audience: Some("orders-service".to_string()),
            ..TokenExchangeParams::new(Sensitive::new(user_token))
        })
        .await?;

    // Read what you actually got. On success the granted scope may still be
    // narrower than requested (§15.2 rule 7) — the client's registration
    // bounds it, and assuming the request was honoured verbatim is how a
    // caller ends up surprised at the *next* service.
    println!(
        "exchanged for {}s, granted scope: {}",
        exchanged.expires_in,
        exchanged.scope.as_deref().unwrap_or("(server default)")
    );

    // Hand it onward in ONE outbound call. It is not this client's session:
    // adopting it would silently re-privilege every later call the gateway
    // makes, and the narrowed token would make most of them fail far from
    // here (§15.2 rule 5). There is also no refresh token, ever — re-run the
    // exchange when you need a fresh one (rule 4).
    let _authorization_header = format!("Bearer {}", exchanged.access_token.expose());

    // Worth handling explicitly, because each names something an operator
    // must fix rather than something to retry:
    //
    //   unauthorized_client -> this client may not exchange, or may not
    //                          impersonate. A registration fact.
    //   invalid_scope       -> you asked for something the user does not
    //                          have. Do NOT re-send with fewer scopes; the
    //                          server refused rather than silently narrowing
    //                          precisely so you would find out here.
    //   invalid_grant       -> subject token bad, expired, or from another
    //                          tenant. The server collapses those on
    //                          purpose; do not try to tell them apart.

    Ok(())
}
