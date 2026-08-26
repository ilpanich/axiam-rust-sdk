//! The §27 management surface, imperatively — CONTRACT.md §27.
//!
//! Builds a small tenant by hand: a resource with a scope, a permission, a
//! role that grants it, a group holding the role, and a user in the group.
//! The declarative equivalent is `management_manifest.rs`, and is what you
//! probably want for anything this shaped — this example exists to show the
//! calls the declarative form makes on your behalf, and the four rules that
//! bite when you make them yourself.
//!
//! ```text
//! cargo run --example management_basics --features rest
//! ```
//!
//! No network I/O: the calls are printed, not made.

use axiam_sdk::client::AxiamClient;
use axiam_sdk::management::models;
use axiam_sdk::management::{Page, PageRequest};
use axiam_sdk::{AuthzKind, AxiamError};
use uuid::Uuid;

#[tokio::main]
async fn main() -> Result<(), AxiamError> {
    let client = AxiamClient::builder()
        .base_url("https://iam.example.com")?
        .tenant_id(Uuid::nil())
        .org_id(Uuid::nil())
        .build()?;
    // A real run logs in here. §27.4 rule 1 makes every management call fail
    // locally, with no request, until it does.
    let _ = &client;

    section("Namespaces, not 146 methods on the client");
    println!("  client.users().list(..)          client.roles().assign_to_user(..)");
    println!("  client.tenants().create(..)      client.certificates().generate(..)");
    println!();
    println!("  Twenty namespaces have a `list` and fourteen a `get`. Flattened, every");
    println!("  one would need a prefix invented per operation. Acquiring a handle costs");
    println!("  nothing and makes no request.");

    section("Pagination: `total` is the set, not the page");
    let page: Page<models::UserResponse> = Page {
        items: Vec::new(),
        total: 4_312,
        offset: 0,
        limit: 50,
    };
    println!("  let page = client.users().list(PageRequest::first(50)).await?;");
    println!(
        "  page.items.len() = {}, page.total = {}, page.has_more() = {}",
        page.items.len(),
        page.total,
        page.has_more()
    );
    println!();
    println!("  For the whole set, `list_all` walks to exhaustion:");
    println!("      client.users().list_all(PageRequest::first(200)).await?");
    println!("  The SDK never truncates silently — if it returns one page, `total` says so.");
    let _ = PageRequest::new(200, 200);

    section("Sparse update: what you leave None is left alone");
    let patch = models::UpdateUserRequest {
        email: Some("new@example.com".into()),
        ..Default::default()
    };
    println!("  client.users().update(id, &UpdateUserRequest {{");
    println!("      email: Some(\"new@example.com\".into()),");
    println!("      ..Default::default()");
    println!("  }}).await?");
    println!();
    println!("  Wire body: {}", serde_json::to_string(&patch).unwrap());
    println!("  One key. Not `username: null` — absent means unchanged, and this SDK");
    println!("  cannot express \"set it to null\", which is the safe direction.");

    section("...but four PUTs are replacements, not patches");
    println!("  settings().set_org, email_config().set_org, webauthn_policy().set and");
    println!("  ca_certificates().set_mtls_trust_anchor REPLACE. Their request types have");
    println!("  required fields, so a half-filled one does not compile — which is the");
    println!("  point: sending a subset of SetOrgSettings resets the other eighteen.");
    println!();
    println!("  Read, change, send the whole thing back:");
    println!("      let current = client.settings().get_org().await?;");
    println!("      let mut next = SetOrgSettings::from(current);   // carry everything over");
    println!("      next.max_failed_login_attempts = 10;");
    println!("      client.settings().set_org(&next).await?;");

    section("404 means \"absent, or not yours\"");
    println!("  match client.users().get(id).await {{");
    println!("      Err(e) if e.is_not_found() => /* both cases, deliberately */,");
    println!("      Err(e) if e.is_conflict()  => /* 409: something already exists */,");
    println!("      Err(e) => if let Some(v) = e.validation() {{ /* 400, per field */ }},");
    println!("      Ok(user) => {{ /* .. */ }}");
    println!("  }}");
    println!();
    println!("  The server answers 404 for another tenant's resource on purpose: a");
    println!("  distinguishable \"exists but not yours\" is an enumeration oracle. Both");
    println!(
        "  arrive as AxiamError::Authz {{ kind: {:?}, .. }}.",
        AuthzKind::NotFound
    );

    section("Writes are never retried");
    println!("  Reads retry under §16. Writes do not — not even the idempotent-looking");
    println!("  ones. certificates().generate() twice mints two certificates, and");
    println!("  service_accounts().rotate_secret() twice invalidates the secret the");
    println!("  first call returned and you already stored.");

    section("Seven calls return a secret exactly once");
    println!("  service_accounts().create / rotate_secret, oauth2_clients().create,");
    println!("  scim_tokens().create, certificates().generate, ca_certificates()");
    println!("  .generate / .generate_signing_ca, pgp_keys().generate.");
    println!();
    println!("  Each returns Sensitive<String>: redacted in Debug, readable with");
    println!("  .expose(). No later `get` returns it again, and the `get` projection has");
    println!("  no field where it was — nothing tells you it is missing.");

    Ok(())
}

fn section(title: &str) {
    println!("\n=== {title} ===");
}
