//! UMA 2.0 (CONTRACT.md §20) — the **client** half of the pair.
//!
//! Run `examples/uma_resource_server.rs` first; this program talks to it.
//!
//! The flow, which is the whole reason UMA exists:
//!
//! 1. Ask for the invoice with the user's ordinary token. The resource server
//!    refuses — but its `401`/`403` carries `WWW-Authenticate: UMA` naming a
//!    ticket and an authorization server.
//! 2. **Parse** the challenge. Note what happens next, and what does not:
//!    parsing performs no exchange (§20.3). The `as_uri` in that header is a
//!    host the *server we just failed against* chose; auto-redeeming would send
//!    the user's token wherever a 403 pointed.
//! 3. Decide to trust it, then **exchange** the ticket for an RPT.
//! 4. Retry with the RPT.
//!
//! Step 3 is a decision, not a formality — this example makes it explicitly, by
//! comparing the nominated `as_uri` against the issuer this client already
//! trusts, and refusing when they differ.
//!
//! Run: `cargo run --example uma_client --features rest`

use axiam_sdk::Sensitive;
use axiam_sdk::client::AxiamClient;
use axiam_sdk::uma::uma_parse_challenge;
use uuid::Uuid;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let base_url =
        std::env::var("AXIAM_BASE_URL").unwrap_or_else(|_| "https://localhost:8443".to_string());
    let tenant_id: Uuid = std::env::var("AXIAM_TENANT_ID")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(Uuid::new_v4);
    let client_id =
        std::env::var("AXIAM_OIDC_CLIENT_ID").unwrap_or_else(|_| "invoices-client".to_string());
    let client_secret =
        std::env::var("AXIAM_OIDC_CLIENT_SECRET").unwrap_or_else(|_| "client-secret".to_string());

    // The resource server printed this id when it registered.
    let invoice_id = std::env::var("AXIAM_INVOICE_ID")
        .unwrap_or_else(|_| "00000000-0000-0000-0000-000000000000".to_string());
    let resource_server = std::env::var("AXIAM_RESOURCE_SERVER")
        .unwrap_or_else(|_| "http://127.0.0.1:8081".to_string());

    // The requesting party's own token — what this program would normally send
    // and, in step 3, the `claim_token` that names *who* is asking.
    let user_token = std::env::var("AXIAM_USER_TOKEN")
        .unwrap_or_else(|_| "the-requesting-partys-access-token".to_string());

    // The exchange is a token-endpoint grant, so this client is confidential.
    let client = AxiamClient::builder()
        .base_url(&base_url)?
        .tenant_id(tenant_id)
        .oidc_client_id(&client_id)
        .oidc_client_secret(&client_secret)
        .build()?;

    let http = reqwest::Client::new();
    let url = format!("{resource_server}/invoices/{invoice_id}");

    // ---- 1. The refusal ----
    let refused = http.get(&url).bearer_auth(&user_token).send().await?;
    println!("first attempt: {}", refused.status());

    let Some(header) = refused
        .headers()
        .get(reqwest::header::WWW_AUTHENTICATE)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
    else {
        // A resource server that refuses without a challenge is telling you it
        // has nothing to offer — there is no ticket to redeem, and retrying the
        // same request would be pointless.
        println!("no WWW-Authenticate header: this refusal is not actionable.");
        return Ok(());
    };

    // ---- 2. Parse, and only parse ----
    let Some(challenge) = uma_parse_challenge(&header) else {
        println!("the challenge is not a UMA one; nothing to redeem.");
        return Ok(());
    };

    // Nothing from the challenge is echoed, and there are two separate reasons.
    //
    // The ticket, because §20.6 says so: its 60-second life does not make it
    // harmless — for those 60 seconds it IS the credential that converts into an
    // RPT, so a header in a log line is a live credential in a log line.
    //
    // The realm and as_uri, because they are strings a *remote* server chose.
    // They are not secrets, but echoing attacker-controlled text into a terminal
    // or a log file is its own small hazard (escape sequences, log forging), and
    // an example is the last place to teach the habit. What matters here is the
    // shape of the challenge, not its contents.
    println!(
        "challenge parsed: as_uri present={}, ticket present={}",
        challenge.as_uri.is_some(),
        challenge.ticket.is_some()
    );

    let Some(ticket) = challenge.ticket else {
        println!("the challenge names no ticket; nothing to redeem.");
        return Ok(());
    };

    // ---- 3. The trust decision ----
    //
    // This is the step §20.3 exists to keep in the caller's hands. The SDK
    // parsed the header and stopped; deciding whether to send the user's token
    // to the host it names is this program's call, and it is a real one — a
    // compromised or merely misconfigured resource server could nominate
    // anything here.
    let trusted_issuer = client
        .oidc_discover()
        .await
        .map(|configuration| configuration.issuer)
        .unwrap_or_else(|_| base_url.clone());

    match challenge.as_uri.as_deref() {
        Some(as_uri) if as_uri.trim_end_matches('/') == trusted_issuer.trim_end_matches('/') => {
            println!("as_uri matches the issuer we already trust; redeeming.");
        }
        Some(_) => {
            // The nominated value is deliberately not echoed — see above. Our own
            // issuer is ours to print, and it is the half a reader needs to debug
            // the mismatch.
            println!(
                "refusing to redeem: the challenge nominates a server that is not {trusted_issuer}."
            );
            println!("this is the auto-exchange §20.3 forbids, and why it forbids it.");
            return Ok(());
        }
        None => {
            println!("the challenge names no as_uri; redeeming against our own issuer.");
        }
    }

    // ---- 4. Exchange, then retry ----
    //
    // One request. A ticket is spent whether or not this succeeds (§20.2
    // rule 6), so on failure the next step is a *new* ticket — which means
    // going back to step 1, not resending this one.
    let rpt = match client
        .uma_exchange_ticket(&ticket, &Sensitive::new(user_token))
        .await
    {
        Ok(rpt) => rpt,
        Err(error) => {
            println!("exchange failed: {error}");
            println!("the ticket is spent either way — request a new one by retrying the call.");
            return Ok(());
        }
    };
    println!("got an RPT, valid for {}s", rpt.expires_in);

    let allowed = http
        .get(&url)
        .bearer_auth(rpt.access_token.expose())
        .send()
        .await?;
    println!("second attempt: {}", allowed.status());
    if allowed.status().is_success() {
        println!("body: {}", allowed.text().await?);
    }

    Ok(())
}
