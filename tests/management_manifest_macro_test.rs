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

// ---------------------------------------------------------------------------
// Contract 1.51 (§27.6.1): metadata, scoped bindings, service accounts
// ---------------------------------------------------------------------------

/// Every 1.51 statement lowers to what the fluent constructors build.
#[test]
fn the_1_51_statements_agree_with_the_fluent_form() {
    use axiam_sdk::management::manifest::{GroupSpec, RoleBinding, ServiceAccountSpec, UserSpec};
    let meta = serde_json::json!({ "region": "eu" });

    let declared = manifest! {
        resource site  = "site-1", "site", metadata meta.clone();
        resource flat  = "flat-7", "apartment", under site, metadata serde_json::json!({});
        role resident  = "Resident", "Lives here";
        role guest     = "Guest", "Visits";
        role concierge = "Concierge", "Runs the site";
        group staff    = "Staff", "Staff";
        assign role concierge, to group staff, at site;
        assign role guest, to group staff, at flat, here only;
        user ann       = "ann", "ann@example.com";
        assign role resident, to user ann, at flat, here only;
        assign role guest, to user ann, at site;
        service_account gate  = "gate-controller", "Opens the gate";
        service_account meter = "meter";
        assign role concierge, to service_account gate, at site, here only;
        assign role guest, to service_account gate;
        assign role resident, to service_account meter, at flat;
    };

    assert_eq!(declared.resources[0].metadata, Some(meta));
    assert_eq!(declared.resources[1].parent.as_deref(), Some("site"));
    assert_eq!(declared.resources[1].metadata, Some(serde_json::json!({})));
    let group = GroupSpec::new("staff", "Staff", "Staff").with_roles([
        RoleBinding::at("concierge", "site"),
        RoleBinding::at_only("guest", "flat"),
    ]);
    assert_eq!(declared.groups[0], group);
    let user = UserSpec::new("ann", "ann", "ann@example.com").with_roles([
        RoleBinding::at_only("resident", "flat"),
        RoleBinding::at("guest", "site"),
    ]);
    assert_eq!(declared.users[0].roles, user.roles);
    assert_eq!(
        declared.service_accounts,
        vec![
            ServiceAccountSpec::new("gate", "gate-controller")
                .with_description("Opens the gate")
                .with_roles([
                    RoleBinding::at_only("concierge", "site"),
                    RoleBinding::from("guest"),
                ]),
            ServiceAccountSpec::new("meter", "meter")
                .with_roles([RoleBinding::at("resident", "flat")]),
        ]
    );
    // The accessors say what the shape says.
    let b = &declared.service_accounts[0].roles[0];
    assert_eq!(
        (b.role(), b.resource(), b.inherit()),
        ("concierge", Some("site"), false)
    );
    let plain = &declared.service_accounts[0].roles[1];
    assert_eq!(
        (plain.role(), plain.resource(), plain.inherit()),
        ("guest", None, true)
    );
    assert_eq!(*plain, "guest");
    assert_ne!(*b, "concierge", "a scoped binding is not its bare key");
}

/// A 1.51 statement attaching to an undeclared key is reported by key, like
/// every other attachment.
#[test]
fn an_unresolvable_1_51_attachment_is_reported_by_key() {
    let mut builder = ManifestBuilder::new();
    builder.resource_metadata("nowhere", serde_json::json!({}));
    let err = builder.try_build().expect_err("no such resource");
    assert!(err.contains("nowhere"), "{err}");

    let mut builder = ManifestBuilder::new();
    builder.service_account_role("ghost", "role");
    let err = builder.try_build().expect_err("no such service account");
    assert!(err.contains("ghost"), "{err}");

    let mut builder = ManifestBuilder::new();
    builder.group_role("nobody", "role");
    let err = builder.try_build().expect_err("no such group");
    assert!(err.contains("nobody"), "{err}");

    let mut builder = ManifestBuilder::new();
    builder.user_role("nobody", "role");
    let err = builder.try_build().expect_err("no such user");
    assert!(err.contains("nobody"), "{err}");

    let mut builder = ManifestBuilder::new();
    builder.member("nobody", "group");
    let err = builder.try_build().expect_err("no such user");
    assert!(err.contains("nobody"), "{err}");

    let mut builder = ManifestBuilder::new();
    builder.grant("nobody", "perm", PermissionEffect::Allow, &[]);
    assert!(builder.try_build().is_err());
}
