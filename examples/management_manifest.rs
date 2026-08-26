//! Declarative management — CONTRACT.md §27.6 and §27.7.
//!
//! The same tenant `management_basics.rs` builds call by call, declared
//! instead. This is what most applications actually want at start-up, in a
//! migration, or in a test fixture: assert a shape and let the SDK work out
//! which of the 146 operations that takes.
//!
//! ```text
//! cargo run --example management_manifest --features rest
//! ```
//!
//! Prints the manifest and the plan it implies; makes no network calls.

use axiam_sdk::client::AxiamClient;
use axiam_sdk::{AxiamError, Sensitive, manifest};
use uuid::Uuid;

#[tokio::main]
async fn main() -> Result<(), AxiamError> {
    // Statements, in any order, each ending in `;`. The identifiers before `=`
    // are manifest-local keys — they exist so other statements can point at
    // this one, and never reach the server.
    let desired = manifest! {
        resource workspace = "workspace", "collection";
        resource documents = "documents", "collection", under workspace;
        scope    drafts    = "draft", "Unpublished documents", in documents;
        scope    published = "published", "Published documents", in documents;

        permission read  = "document:read",  "Read a document";
        permission write = "document:write", "Write a document";

        role editor = "Editor", "Edits drafts, reads everything";
        grant editor, allow read;
        grant editor, allow write, in [drafts];

        // A deny grant overrides EVERY allow, at any depth of the hierarchy
        // and at equal specificity. AXIAM's engine is deny-override, not
        // most-specific-wins — so this is absolute, not a tie-break.
        role contractor = "Contractor", "Reads drafts only";
        grant contractor, allow read, in [drafts];
        grant contractor, deny write;

        group staff = "Staff", "Everyone on the team";
        assign role editor, to group staff;

        user alice = "alice", "alice@example.com",
             password Sensitive::new("correct horse battery staple".into());
        member alice, in staff;
    };

    println!(
        "declared: {} resources, {} permissions, {} roles, {} groups, {} users",
        desired.resources.len(),
        desired.permissions.len(),
        desired.roles.len(),
        desired.groups.len(),
        desired.users.len(),
    );

    let client = AxiamClient::builder()
        .base_url("https://iam.example.com")?
        .tenant_id(Uuid::nil())
        .org_id(Uuid::nil())
        .build()?;
    let _ = &client;

    println!("\nAgainst a live, logged-in client:");
    println!();
    println!("    let plan = client.manifest().plan(&desired).await?;");
    println!("    for action in plan.changes() {{");
    println!("        println!(\"{{:?}} {{}}\", action.change, action.summary);");
    println!("    }}");
    println!();
    println!("`plan` issues GETs and nothing else, so it is safe to point at production.");
    println!("It reads the tenant, matches each spec by its natural key — a user's");
    println!("username, a role's name, a scope's name within its resource — and returns");
    println!("the ordered actions that would reconcile it.");
    println!();
    println!("    let report = client.manifest().apply(&desired).await?;");
    println!("    assert!(report.is_complete());");
    println!();
    println!("Four things worth knowing before you point this at a real tenant:");
    println!();
    println!(" 1. Nothing is ever deleted. A manifest is usually a SUBSET of a tenant's");
    println!("    truth; pruning would turn \"make sure these roles exist\" into \"delete");
    println!("    the other forty\". There is no prune option, on purpose.");
    println!();
    println!(" 2. A field the manifest does not state is never a difference, so this is");
    println!("    safe against a tenant that also holds hand-made state.");
    println!();
    println!(" 3. Applying twice converges: the second plan is all NoChange. That is the");
    println!("    property that makes re-running after a failure safe.");
    println!();
    println!(" 4. There is no transaction across 146 independent HTTP endpoints, and");
    println!("    ApplyReport does not pretend there is. If step 12 of 30 fails, steps");
    println!("    1-11 have happened; the report says which, execution stops rather than");
    println!("    continuing blindly, and there is no rollback — because the SDK could");
    println!("    not honour one. Fix the cause and re-apply; (3) makes that safe.");
    println!();
    println!("Broken manifests are refused before the first request: dangling keys,");
    println!("duplicate keys, a cycle in the resource parents, and a user that would have");
    println!("to be created with no initial_password all fail while nothing has changed.");

    Ok(())
}
