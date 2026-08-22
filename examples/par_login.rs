//! Pushed Authorization Requests — CONTRACT.md §26 (RFC 9126).
//!
//! PAR moves the authorization request off the browser. Instead of putting
//! `scope`, `redirect_uri`, `state` and the PKCE challenge into a URL the user
//! agent carries, the client POSTs them straight to AXIAM over an authenticated
//! back channel and puts an opaque `request_uri` in the redirect. What travels
//! through the browser is then a random string that cannot be edited into
//! meaning something else.
//!
//! Required for a FAPI 2.0 client: `profile: "fapi2"` refuses a registration
//! that does not set `require_par`, so such a client cannot authorize any other
//! way.
//!
//! Run: `AXIAM_CLIENT_ID=… cargo run --example par_login --features rest`

use axiam_sdk::client::AxiamClient;
use axiam_sdk::oidc::{
    OidcBeginParams, OidcExchangeParams, OidcParParams, PushedAuthorizationRequest,
};

const REDIRECT_URI: &str = "https://app.example.com/auth/callback";
const SCOPE: &str = "openid profile email";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut builder = AxiamClient::builder()
        .base_url(env_or("AXIAM_BASE_URL", "https://iam.example.com"))?
        .tenant_slug(env_or("AXIAM_TENANT_SLUG", "acme"))
        .org_slug(env_or("AXIAM_ORG_SLUG", "globex"))
        .oidc_client_id(env_or("AXIAM_CLIENT_ID", "axiam-rp"));
    if let Ok(secret) = std::env::var("AXIAM_CLIENT_SECRET") {
        builder = builder.oidc_client_secret(secret);
    }
    let client = builder.build()?;

    if let Err(err) = begin(&client).await {
        eprintln!("push: {err}");
    }
    Ok(())
}

/// Start a login by pushing the request.
///
/// `oidc_begin` still does the computing — §26.2 rule 1 forbids a second
/// generator for `state`, `nonce` and PKCE, so `oidc_par` pushes what it
/// produced rather than producing its own.
async fn begin(
    client: &AxiamClient,
) -> Result<PushedAuthorizationRequest, Box<dyn std::error::Error>> {
    let configuration = client.oidc_discover().await?;
    let request = client.oidc_begin(
        &configuration,
        OidcBeginParams {
            redirect_uri: REDIRECT_URI.into(),
            scope: Some(SCOPE.into()),
            ..Default::default()
        },
    )?;

    let pushed = client
        .oidc_par(OidcParParams {
            request,
            redirect_uri: REDIRECT_URI.into(),
            scope: Some(SCOPE.into()),
            tenant_id: None,
            configuration: Some(configuration),
        })
        .await?;

    // Exactly two query parameters: `client_id` and `request_uri`. Not
    // `response_type`, not `scope`, not `state` — the server REFUSES a request
    // carrying both a `request_uri` and any inline authorization parameter
    // rather than merging them, because merging is where parameter confusion
    // lives (§26.2 rule 2). Do not "helpfully" re-add them.
    println!("redirect the browser to {}", pushed.url);

    // Store `state`, `nonce` and `code_verifier` against the browser session,
    // as you would without PAR. `request_uri` is single-use and short-lived;
    // there is nothing to retry with it if the redirect fails (§26.2 rule 3).
    Ok(pushed)
}

/// Finish the login. Unchanged by PAR — same grant, same verifier.
#[allow(dead_code)]
async fn complete(
    client: &AxiamClient,
    pushed: PushedAuthorizationRequest,
    code: &str,
    returned_state: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    if returned_state != pushed.state {
        return Err("state mismatch — abandon this login".into());
    }

    let tokens = client
        .oidc_exchange(OidcExchangeParams {
            code: code.to_string(),
            redirect_uri: REDIRECT_URI.into(),
            nonce: pushed.nonce,
            // The verifier `oidc_begin` produced, carried through the push. One
            // value, so there is no second place for the two to disagree
            // (§26.2 rule 6).
            code_verifier: pushed.code_verifier,
            tenant_id: None,
            configuration: None,
        })
        .await?;

    println!("token set acquired, expires in {}s", tokens.expires_in);
    Ok(())
}

fn env_or(key: &str, fallback: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| fallback.to_string())
}
