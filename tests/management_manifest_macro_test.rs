//! CONTRACT §27.7 — the `manifest!` declarative form.
//!
//! The macro is sugar over `ManifestBuilder`, so what needs testing is that
//! the sugar lowers to the same value the fluent constructors produce, and
//! that a statement naming an undeclared key says so rather than quietly
//! dropping itself.

#![cfg(feature = "rest")]

use axiam_sdk::management::manifest::{
    GrantSpec, ManagementManifest, ManifestBuilder, PermissionSpec, ResourceSpec, RoleSpec,
    ScopeSpec,
};
use axiam_sdk::management::models::PermissionEffect;
use axiam_sdk::{Sensitive, manifest};

/// The macro produces exactly what the fluent constructors do.
///
/// Asserted field by field rather than with `PartialEq` on the whole manifest,
/// because `UserSpec` deliberately has no equality — it holds a `Sensitive`.
#[test]
fn the_macro_and_the_fluent_form_agree() {
    let declared = manifest! {
        resource root  = "workspace", "collection";
        resource docs  = "documents", "collection", under root;
        scope    draft = "draft", "Unpublished", in docs;
        permission read = "document:read", "Read a document";
        role editor    = "Editor", "Edits documents";
        grant editor, allow read, in [draft];
    };

    let built = ManagementManifest::new()
        .with_resource(ResourceSpec::new("root", "workspace", "collection"))
        .with_resource(
            ResourceSpec::new("docs", "documents", "collection")
                .under("root")
                .with_scope(ScopeSpec::new("draft", "draft", "Unpublished")),
        )
        .with_permission(PermissionSpec::new(
            "read",
            "document:read",
            "Read a document",
        ))
        .with_role(
            RoleSpec::new("editor", "Editor", "Edits documents")
                .granting(GrantSpec::allow("read").scoped_to(["draft"])),
        );

    assert_eq!(declared.resources, built.resources);
    assert_eq!(declared.permissions, built.permissions);
    assert_eq!(declared.roles, built.roles);
}

/// `global` on a role, and `deny` on a grant, both survive the lowering.
#[test]
fn the_macro_carries_global_roles_and_deny_grants() {
    let m = manifest! {
        permission write = "document:write", "Write";
        role auditor = "Auditor", "Reads everything", global;
        grant auditor, deny write;
    };

    assert!(m.roles[0].is_global);
    assert_eq!(m.roles[0].grants[0].effect, Some(PermissionEffect::Deny));
    assert!(m.roles[0].grants[0].scopes.is_empty());
}

/// Statements may appear in any order; attachment is by key, not by position.
#[test]
fn statement_order_does_not_matter() {
    let forwards = manifest! {
        resource docs = "documents", "collection";
        scope draft = "draft", "Unpublished", in docs;
    };
    let backwards = manifest! {
        scope draft = "draft", "Unpublished", in docs;
        resource docs = "documents", "collection";
    };
    assert_eq!(forwards.resources, backwards.resources);
    assert_eq!(backwards.resources[0].scopes.len(), 1);
}

/// A user's password reaches the spec, and is `Sensitive` on arrival.
#[test]
fn the_macro_accepts_an_initial_password() {
    let secret = "correct horse battery staple";
    let m = manifest! {
        group staff = "Staff", "All staff";
        user alice = "alice", "alice@example.com", password Sensitive::new(secret.into());
        member alice, in staff;
        role editor = "Editor", "Edits";
        assign role editor, to user alice;
        assign role editor, to group staff;
    };

    assert_eq!(
        m.users[0].initial_password.as_ref().unwrap().expose(),
        secret
    );
    assert_eq!(m.users[0].groups, vec!["staff"]);
    assert_eq!(m.users[0].roles, vec!["editor"]);
    assert_eq!(m.groups[0].roles, vec!["editor"]);
    // §7: the password must not render, even nested two structs deep.
    let rendered = format!("{:?}", m.users[0]);
    assert!(!rendered.contains(secret), "{rendered}");
}

/// A scope attached to a resource nobody declared names the key it could not find.
#[test]
fn an_unresolvable_attachment_is_reported_by_key() {
    let mut builder = ManifestBuilder::new();
    builder.scope("ghost", "draft", "draft", "Unpublished");
    let err = builder.try_build().expect_err("no such resource");
    assert!(err.contains("ghost"), "{err}");
    assert!(err.contains("draft"), "{err}");
}

/// The same, through the macro, which panics rather than returning a `Result`.
#[test]
#[should_panic(expected = "ghost")]
fn the_macro_panics_on_an_unresolvable_attachment() {
    let _ = manifest! {
        scope draft = "draft", "Unpublished", in ghost;
    };
}

/// An empty declaration is legal and yields an empty manifest.
#[test]
fn an_empty_declaration_is_legal() {
    let m = manifest! {};
    assert!(m.resources.is_empty());
    assert!(m.roles.is_empty());
}
