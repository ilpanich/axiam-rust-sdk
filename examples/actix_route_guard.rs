//! Actix-Web route guards: the `AxiamUser` `FromRequest` extractor (§10) plus
//! the declarative authorization attribute macros (§11).
//!
//! Demonstrates, in one app:
//!
//! - registering a shared [`axiam_sdk::token::JwksVerifier`] and an
//!   [`axiam_sdk::client::AxiamClient`] as `app_data`;
//! - [`axiam_sdk::middleware::AxiamUser`] as a plain handler parameter (§10):
//!   the extractor reads the session from the `axiam_access` cookie (falling
//!   back to `Authorization: Bearer`), verifies it locally against the cached
//!   JWKS (no AXIAM-server round-trip), and injects
//!   `{ user_id, tenant_id, roles }` — 401/403 automatically on failure;
//! - `#[require_auth]` (§11): require an authenticated identity;
//! - `#[require_access(action = "read", resource_param = "id")]` (§11):
//!   additionally require the authenticated caller to pass an AXIAM
//!   authorization check for `read` on the `{id}` path resource — the check is
//!   issued with `subject_id = <the request user's id>`, and maps deny → 403,
//!   bad/absent UUID → 400, authz transport failure → 503 (fail closed);
//! - `#[require_role("admin")]` (§11): a local, no-round-trip role check.
//!
//! This example is illustrative/compilable — it starts a real Actix-Web server
//! bound to `AXIAM_LISTEN_ADDR` (default `127.0.0.1:8080`) and does not require
//! a live AXIAM server to `cargo build --example actix_route_guard --features
//! actix,macros`. Serving real traffic requires a reachable `AXIAM_BASE_URL`
//! (for the extractor's JWKS fetch and the `require_access` check).
//!
//! Run: `cargo run --example actix_route_guard --features actix,macros`

use actix_web::{App, HttpServer, web};
use axiam_sdk::client::AxiamClient;
use axiam_sdk::middleware::AxiamUser;
use axiam_sdk::token::JwksVerifier;
use axiam_sdk::{require_access, require_auth, require_role};

/// §10: a route guarded only by the `AxiamUser` extractor — Actix rejects the
/// request with 401/403 automatically if extraction fails.
async fn protected_resource(user: AxiamUser) -> String {
    format!(
        "Hello, user {} (tenant {}) — roles: {:?}",
        user.user_id, user.tenant_id, user.roles
    )
}

/// §11 `require_auth`: identical guarantee to `protected_resource`, expressed
/// declaratively. The handler needs no `AxiamUser` parameter of its own.
#[require_auth]
async fn whoami() -> &'static str {
    "you are authenticated"
}

/// §11 `require_access`: requires the authenticated caller to pass a `read`
/// check on the resource named by the `{id}` path parameter. The handler may
/// still declare its own `AxiamUser` to use the identity in its body — the
/// macro injects an independent extractor for the guard.
#[require_access(action = "read", resource_param = "id")]
async fn get_document(user: AxiamUser) -> String {
    format!("user {} is authorized to read this document", user.user_id)
}

/// §11 `require_role`: a local check against the verified token's roles claim
/// (no server round-trip). Not a substitute for a resource-level
/// `require_access` check.
#[require_role("admin")]
async fn admin_panel() -> &'static str {
    "welcome to the admin panel"
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let base_url =
        std::env::var("AXIAM_BASE_URL").unwrap_or_else(|_| "https://localhost:8443".to_string());
    let listen_addr =
        std::env::var("AXIAM_LISTEN_ADDR").unwrap_or_else(|_| "127.0.0.1:8080".to_string());

    let base_url_parsed = url::Url::parse(&base_url).expect("AXIAM_BASE_URL must be a valid URL");
    let http = reqwest::Client::new();
    let jwks_verifier =
        JwksVerifier::new(http, &base_url_parsed).expect("failed to construct JwksVerifier");

    // The `AxiamClient` the `#[require_access]` guard uses to issue checks. In
    // production this typically holds a service-account session; the guard
    // sends the request user's id as `subject_id` so the check is made for the
    // end user, not the service account (§11.2).
    let client = AxiamClient::builder()
        .base_url(&base_url)
        .expect("valid base_url")
        .tenant_slug("acme")
        .build()
        .expect("failed to build AxiamClient");

    // `web::Data<T>` is `Arc`-backed: build each once here, then `.clone()` the
    // cheap handles into every worker's factory closure below.
    let jwks_data = web::Data::new(jwks_verifier);
    let client_data = web::Data::new(client);

    println!("Listening on http://{listen_addr}");
    println!("  GET /protected          requires an AXIAM session (§10 extractor)");
    println!("  GET /whoami             requires an AXIAM session (#[require_auth])");
    println!("  GET /documents/{{id}}     requires `read` on {{id}} (#[require_access])");
    println!("  GET /admin              requires the `admin` role (#[require_role])");

    HttpServer::new(move || {
        App::new()
            .app_data(jwks_data.clone())
            .app_data(client_data.clone())
            .route("/protected", web::get().to(protected_resource))
            .route("/whoami", web::get().to(whoami))
            .route("/documents/{id}", web::get().to(get_document))
            .route("/admin", web::get().to(admin_panel))
    })
    .bind(&listen_addr)?
    .run()
    .await
}
