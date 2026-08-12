//! UMA 2.0 (CONTRACT.md §20) — the **resource-server** half of the pair.
//!
//! The situation: this service holds invoices that belong to *users*, not to
//! itself. When someone asks for one, the useful answer is not just "no" — it
//! is "not with what you're carrying, and here is where to go and get better".
//! That actionable refusal is what UMA adds over plain RBAC.
//!
//! What this shows, in order:
//!
//! 1. Mint a **PAT** — a client-credentials token carrying `uma_protection`.
//!    §20.2 rule 1 requires a *client* token: a minted ticket is bound to the
//!    `client_id` that minted it, so a user token cannot stand in.
//! 2. **Register** the resource this service guards. The returned id *is* the
//!    AXIAM resource id — there is no parallel resource store to keep in sync.
//! 3. Guard a route with `RequireAccess::with_uma_challenge`, so a denial
//!    carries `WWW-Authenticate: UMA` with a fresh ticket.
//!
//! Its counterpart is `examples/uma_client.rs`, which consumes that header.
//!
//! Run: `cargo run --example uma_resource_server --features rest,actix`
//!
//! Serves on `127.0.0.1:8081`; `GET /invoices/{id}` is the guarded route.

use actix_web::{App, HttpResponse, HttpServer, Responder, web};
use axiam_sdk::client::AxiamClient;
use axiam_sdk::middleware::{AuthzGuardError, AxiamUser, RequireAccess, UmaChallenger};
use axiam_sdk::oidc::LoginClientCredentialsParams;
use axiam_sdk::uma::{ResourceSet, UMA_PROTECTION_SCOPE};
use uuid::Uuid;

/// What the guard needs on every request: the client to check with, and the
/// challenger that turns a denial into a ticket.
struct Guarded {
    client: AxiamClient,
    challenger: UmaChallenger,
}

/// `GET /invoices/{id}`, guarded by the `invoices:read` action.
///
/// The load-bearing line is `.with_uma_challenge(...)`. Without it this is an
/// ordinary §11 check and a denial is a bare 403. With it, the denial carries a
/// ticket and the caller can act on it.
async fn read_invoice(
    guarded: web::Data<Guarded>,
    user: AxiamUser,
    path: web::Path<Uuid>,
) -> Result<impl Responder, AuthzGuardError> {
    let invoice_id = path.into_inner();

    RequireAccess::new("invoices:read")
        .with_uma_challenge(guarded.challenger.clone())
        .check(&guarded.client, &user, invoice_id)
        .await?;

    // Reached only when the engine allowed it — including honouring any deny
    // rule, which UMA does not bypass: the ticket asks for the same action this
    // check just evaluated, so the same grants and the same denies apply.
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "id": invoice_id,
        "total": "42.00",
        "currency": "EUR",
    })))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let base_url =
        std::env::var("AXIAM_BASE_URL").unwrap_or_else(|_| "https://localhost:8443".to_string());
    let tenant_id: Uuid = std::env::var("AXIAM_TENANT_ID")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(Uuid::new_v4);
    let client_id = std::env::var("AXIAM_OIDC_CLIENT_ID")
        .unwrap_or_else(|_| "invoices-resource-server".to_string());
    let client_secret = std::env::var("AXIAM_OIDC_CLIENT_SECRET")
        .unwrap_or_else(|_| "resource-server-secret".to_string());

    // A resource server is a confidential client: it authenticates at the token
    // endpoint with a secret, and it is the subject its tickets are bound to.
    let client = AxiamClient::builder()
        .base_url(&base_url)
        .expect("valid base url")
        .tenant_id(tenant_id)
        .oidc_client_id(&client_id)
        .oidc_client_secret(&client_secret)
        .build()
        .expect("client builds");

    // ---- 1. The PAT ----
    //
    // §20.2 rule 1: a client-credentials token carrying `uma_protection`. Not a
    // user token, and not this client's ambient session — the SDK will not
    // substitute either, and the Protection API would refuse them anyway.
    let pat = match client
        .login_client_credentials(LoginClientCredentialsParams {
            scope: Some(UMA_PROTECTION_SCOPE.to_string()),
            tenant_id: Some(tenant_id),
            configuration: None,
        })
        .await
    {
        Ok(session) => session.access_token,
        Err(error) => {
            // Nothing below works without it, and starting anyway would produce
            // a service that fails on its first denial instead of saying why.
            eprintln!("could not mint a PAT: {error}");
            eprintln!("this client needs the `{UMA_PROTECTION_SCOPE}` scope granted to it.");
            return Ok(());
        }
    };

    // ---- 2. Registration ----
    //
    // Registering the same name twice creates two resources, so a real service
    // registers once at provisioning time and stores the id, or reconciles by
    // listing. Kept inline here because it is the step that shows the id is the
    // AXIAM resource id.
    let invoice_id = match client
        .uma_register_resource(
            &pat,
            &ResourceSet::new("invoice-7")
                .with_type("invoice")
                // The declared scopes are the allow-list the permission endpoint
                // validates a ticket request against. A resource registered with
                // none can never appear in a ticket.
                .with_scopes(["invoices:read", "invoices:approve"]),
        )
        .await
    {
        Ok(resource) => resource
            .id
            .expect("the server assigns an id on registration"),
        Err(error) => {
            eprintln!("could not register the resource: {error}");
            return Ok(());
        }
    };
    println!("registered invoice-7 as {invoice_id}");
    println!("try:  curl -i http://127.0.0.1:8081/invoices/{invoice_id}");

    // ---- 3. The guard ----
    //
    // `as_uri` names where the caller should redeem the ticket. Read it from the
    // discovery document rather than assembling it by hand — a deployment is
    // free to move its endpoints, which is why §12.3 rule 6 forbids hardcoding
    // them and why this SDK's ticket grant reads the token endpoint from the
    // same document.
    let as_uri = match client.oidc_discover().await {
        Ok(configuration) => configuration.issuer,
        Err(_) => std::env::var("AXIAM_ISSUER").unwrap_or_else(|_| base_url.clone()),
    };
    let challenger = UmaChallenger::new("invoices", as_uri, pat);

    let guarded = web::Data::new(Guarded { client, challenger });

    println!("resource server listening on http://127.0.0.1:8081");
    HttpServer::new(move || {
        App::new()
            .app_data(guarded.clone())
            // The §10 `AxiamUser` extractor runs first and injects the verified
            // identity; the §11 guard consumes it and never re-extracts the
            // token (§11.2.1).
            .route("/invoices/{id}", web::get().to(read_invoice))
    })
    .bind(("127.0.0.1", 8081))?
    .run()
    .await
}
