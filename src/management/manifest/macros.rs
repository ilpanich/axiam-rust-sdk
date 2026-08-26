//! The `manifest!` declarative form — CONTRACT §27.7.

/// Declare a [`ManagementManifest`] as a flat list of statements.
///
/// [`ManagementManifest`]: crate::management::manifest::ManagementManifest
///
/// The fluent constructors nest — a scope is built inside its resource, a
/// grant inside its role — which reads well as Rust and badly as a
/// *declaration*, where the natural form is statements in whatever order you
/// think of them. This macro is that form. It lowers to
/// [`ManifestBuilder`](crate::management::manifest::ManifestBuilder) and
/// produces exactly the value the fluent constructors would.
///
/// Every statement ends in `;`. Identifiers before `=` are manifest-local
/// keys, not names: they exist so the other statements can refer to this one,
/// and they never reach the server.
///
/// ```
/// use axiam_sdk::manifest;
///
/// let m = manifest! {
///     resource root    = "workspace", "collection";
///     resource docs    = "documents", "collection", under root;
///     scope    draft   = "draft", "Unpublished documents", in docs;
///
///     permission read  = "document:read", "Read a document";
///     permission write = "document:write", "Write a document";
///
///     role editor      = "Editor", "Edits documents";
///     grant editor, allow read;
///     grant editor, allow write, in [draft];
///
///     role auditor     = "Auditor", "Reads everything", global;
///     grant auditor, allow read;
///     grant auditor, deny write;
///
///     group staff      = "Staff", "All staff";
///     assign role editor, to group staff;
///
///     user alice       = "alice", "alice@example.com";
///     member alice, in staff;
///     assign role auditor, to user alice;
/// };
///
/// assert_eq!(m.resources.len(), 2);
/// assert_eq!(m.resources[1].scopes.len(), 1);
/// assert_eq!(m.roles[0].grants.len(), 2);
/// assert_eq!(m.users[0].groups, vec!["staff"]);
/// ```
///
/// A `user` that may have to be *created* needs a password; add it with
/// `password <expr>`, where the expression is a
/// [`Sensitive<String>`](crate::Sensitive):
///
/// ```
/// # use axiam_sdk::{manifest, Sensitive};
/// let m = manifest! {
///     user bob = "bob", "bob@example.com", password Sensitive::new("s3cret".into());
/// };
/// assert!(m.users[0].initial_password.is_some());
/// ```
///
/// # Panics
///
/// If a statement attaches to a key no statement declares — `in docs` with no
/// `docs` resource, a `grant` on an undeclared role. In a literal declaration
/// that is a typo the author meets on the first run, so it panics naming the
/// key rather than making every call site unwrap a `Result`. Build from
/// configuration with
/// [`ManifestBuilder::try_build`](crate::management::manifest::ManifestBuilder::try_build)
/// instead.
///
/// Cross-references that merely have to *exist* — a grant naming a
/// permission, a group naming a role — are not resolved here. They are checked
/// by `plan`, together with cycles and duplicates, so every semantic complaint
/// about a manifest arrives in one message.
#[macro_export]
macro_rules! manifest {
    ($($statements:tt)*) => {{
        #[allow(unused_mut)]
        let mut builder = $crate::management::manifest::ManifestBuilder::new();
        $crate::__axiam_manifest_stmt!(builder; $($statements)*);
        builder.build()
    }};
}

/// The statement muncher behind [`manifest!`]. Not part of the public API.
#[doc(hidden)]
#[macro_export]
macro_rules! __axiam_manifest_stmt {
    ($b:ident;) => {};

    // resource <key> = <name>, <type>[, under <parent>];
    ($b:ident; resource $key:ident = $name:expr, $ty:expr, under $parent:ident; $($rest:tt)*) => {
        $b.resource(stringify!($key), $name, $ty, Some(stringify!($parent)));
        $crate::__axiam_manifest_stmt!($b; $($rest)*);
    };
    ($b:ident; resource $key:ident = $name:expr, $ty:expr; $($rest:tt)*) => {
        $b.resource(stringify!($key), $name, $ty, None);
        $crate::__axiam_manifest_stmt!($b; $($rest)*);
    };

    // scope <key> = <name>, <description>, in <resource>;
    ($b:ident; scope $key:ident = $name:expr, $desc:expr, in $resource:ident; $($rest:tt)*) => {
        $b.scope(stringify!($resource), stringify!($key), $name, $desc);
        $crate::__axiam_manifest_stmt!($b; $($rest)*);
    };

    // permission <key> = <action>, <description>;
    ($b:ident; permission $key:ident = $action:expr, $desc:expr; $($rest:tt)*) => {
        $b.permission(stringify!($key), $action, $desc);
        $crate::__axiam_manifest_stmt!($b; $($rest)*);
    };

    // role <key> = <name>, <description>[, global];
    ($b:ident; role $key:ident = $name:expr, $desc:expr, global; $($rest:tt)*) => {
        $b.role(stringify!($key), $name, $desc, true);
        $crate::__axiam_manifest_stmt!($b; $($rest)*);
    };
    ($b:ident; role $key:ident = $name:expr, $desc:expr; $($rest:tt)*) => {
        $b.role(stringify!($key), $name, $desc, false);
        $crate::__axiam_manifest_stmt!($b; $($rest)*);
    };

    // grant <role>, allow|deny <permission>[, in [<scope>, ...]];
    ($b:ident; grant $role:ident, allow $perm:ident, in [$($scope:ident),* $(,)?]; $($rest:tt)*) => {
        $b.grant(
            stringify!($role),
            stringify!($perm),
            $crate::management::models::PermissionEffect::Allow,
            &[$(stringify!($scope)),*],
        );
        $crate::__axiam_manifest_stmt!($b; $($rest)*);
    };
    ($b:ident; grant $role:ident, deny $perm:ident, in [$($scope:ident),* $(,)?]; $($rest:tt)*) => {
        $b.grant(
            stringify!($role),
            stringify!($perm),
            $crate::management::models::PermissionEffect::Deny,
            &[$(stringify!($scope)),*],
        );
        $crate::__axiam_manifest_stmt!($b; $($rest)*);
    };
    ($b:ident; grant $role:ident, allow $perm:ident; $($rest:tt)*) => {
        $b.grant(
            stringify!($role),
            stringify!($perm),
            $crate::management::models::PermissionEffect::Allow,
            &[],
        );
        $crate::__axiam_manifest_stmt!($b; $($rest)*);
    };
    ($b:ident; grant $role:ident, deny $perm:ident; $($rest:tt)*) => {
        $b.grant(
            stringify!($role),
            stringify!($perm),
            $crate::management::models::PermissionEffect::Deny,
            &[],
        );
        $crate::__axiam_manifest_stmt!($b; $($rest)*);
    };

    // group <key> = <name>, <description>;
    ($b:ident; group $key:ident = $name:expr, $desc:expr; $($rest:tt)*) => {
        $b.group(stringify!($key), $name, $desc);
        $crate::__axiam_manifest_stmt!($b; $($rest)*);
    };

    // assign role <role>, to group|user <key>;
    ($b:ident; assign role $role:ident, to group $group:ident; $($rest:tt)*) => {
        $b.group_role(stringify!($group), stringify!($role));
        $crate::__axiam_manifest_stmt!($b; $($rest)*);
    };
    ($b:ident; assign role $role:ident, to user $user:ident; $($rest:tt)*) => {
        $b.user_role(stringify!($user), stringify!($role));
        $crate::__axiam_manifest_stmt!($b; $($rest)*);
    };

    // user <key> = <username>, <email>[, password <expr>];
    ($b:ident; user $key:ident = $name:expr, $email:expr, password $pw:expr; $($rest:tt)*) => {
        $b.user(stringify!($key), $name, $email, Some($pw));
        $crate::__axiam_manifest_stmt!($b; $($rest)*);
    };
    ($b:ident; user $key:ident = $name:expr, $email:expr; $($rest:tt)*) => {
        $b.user(stringify!($key), $name, $email, None);
        $crate::__axiam_manifest_stmt!($b; $($rest)*);
    };

    // member <user>, in <group>;
    ($b:ident; member $user:ident, in $group:ident; $($rest:tt)*) => {
        $b.member(stringify!($user), stringify!($group));
        $crate::__axiam_manifest_stmt!($b; $($rest)*);
    };
}
