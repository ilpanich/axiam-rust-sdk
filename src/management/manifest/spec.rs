//! The desired shape of a tenant — CONTRACT.md §27.6.
//!
//! A manifest is a **value**. It is built before the things in it exist, so it
//! cannot name them by UUID; every spec carries a manifest-local `key` that
//! other specs refer to, and `plan` resolves those keys to ids against the
//! tenant's current state.
//!
//! Nothing here touches the network, and nothing here needs a client — which
//! is what makes a manifest something you can deserialize from configuration,
//! commit to a repository, and diff.

use crate::Sensitive;
use crate::management::models::PermissionEffect;

/// The shape a tenant should have.
///
/// Deliberately covers only the namespaces that describe a tenant's *shape*.
/// Certificates, CA certificates, PGP keys and SCIM tokens are absent on
/// purpose (§27.6): they mint one-time secrets, and a declarative layer that
/// "ensures a certificate exists" either re-mints one on every run or silently
/// accepts drift. Both are worse than an imperative call made once, on
/// purpose, whose result the caller stores.
#[derive(Debug, Clone, Default)]
pub struct ManagementManifest {
    /// Resources, in any order — `plan` sorts them so a parent precedes its
    /// children.
    pub resources: Vec<ResourceSpec>,
    /// Permissions. On this server a permission is an action plus a
    /// description, tenant-wide; what binds it to a resource is the scope list
    /// on a role's grant.
    pub permissions: Vec<PermissionSpec>,
    /// Roles and the permissions granted to them.
    pub roles: Vec<RoleSpec>,
    /// Groups and the roles their members inherit.
    pub groups: Vec<GroupSpec>,
    /// Users, their role assignments and their group memberships.
    pub users: Vec<UserSpec>,
    /// Service accounts and their role assignments (contract 1.51, §27.6.1).
    ///
    /// **The one section that returns a secret.** A service account that
    /// `apply` has to create comes back with its `client_secret` on that
    /// action's outcome — [`Outcome::CreatedServiceAccount`] — **once**: the
    /// server keeps only a hash, and no later read returns it (§27.5 rules 3
    /// and 5). Store it from the report, or lose it. `apply` never rotates a
    /// secret to reconcile anything, so a re-run after a lost report is
    /// `NoChange`, and the only way back is an explicit
    /// `service_accounts().rotate_secret(id)`.
    ///
    /// [`Outcome::CreatedServiceAccount`]: super::Outcome::CreatedServiceAccount
    pub service_accounts: Vec<ServiceAccountSpec>,
}

impl ManagementManifest {
    /// An empty manifest. Applying it is a no-op, which is a useful base case.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a resource.
    #[must_use]
    pub fn with_resource(mut self, resource: ResourceSpec) -> Self {
        self.resources.push(resource);
        self
    }

    /// Add a permission.
    #[must_use]
    pub fn with_permission(mut self, permission: PermissionSpec) -> Self {
        self.permissions.push(permission);
        self
    }

    /// Add a role.
    #[must_use]
    pub fn with_role(mut self, role: RoleSpec) -> Self {
        self.roles.push(role);
        self
    }

    /// Add a group.
    #[must_use]
    pub fn with_group(mut self, group: GroupSpec) -> Self {
        self.groups.push(group);
        self
    }

    /// Add a user.
    #[must_use]
    pub fn with_user(mut self, user: UserSpec) -> Self {
        self.users.push(user);
        self
    }

    /// Add a service account. See [`Self::service_accounts`] for the one-time
    /// secret a `Create` returns.
    #[must_use]
    pub fn with_service_account(mut self, account: ServiceAccountSpec) -> Self {
        self.service_accounts.push(account);
        self
    }
}

/// A resource in the hierarchy, and the scopes beneath it.
#[derive(Debug, Clone, PartialEq)]
pub struct ResourceSpec {
    /// Manifest-local identifier, referred to by `parent` and by grants.
    pub key: String,
    /// The resource's name — its natural key within the tenant.
    pub name: String,
    /// The server's `resource_type` discriminator.
    pub resource_type: String,
    /// The `key` of this resource's parent, if it has one.
    pub parent: Option<String>,
    /// Scopes declared under this resource.
    pub scopes: Vec<ScopeSpec>,
    /// The resource's metadata, when the manifest states it (contract 1.51,
    /// §27.6.1 item 1).
    ///
    /// `None` is silent: the server's metadata is left alone, whatever it is.
    /// `Some(object)` is sent on `Create` and, when it differs, on `Update` —
    /// and "differs" is JSON value equality of the **whole** object, never a
    /// key-by-key merge. A merge could not remove a key, and then `apply`
    /// could never converge on a manifest that dropped one. The server returns
    /// `{}` for a resource created without metadata, so a stated `{}` matches
    /// it.
    pub metadata: Option<serde_json::Value>,
}

impl ResourceSpec {
    /// A root resource named `name`, keyed by its own name.
    pub fn new(
        key: impl Into<String>,
        name: impl Into<String>,
        resource_type: impl Into<String>,
    ) -> Self {
        Self {
            key: key.into(),
            name: name.into(),
            resource_type: resource_type.into(),
            parent: None,
            scopes: Vec::new(),
            metadata: None,
        }
    }

    /// State this resource's metadata — the whole object (see
    /// [`Self::metadata`]).
    #[must_use]
    pub fn with_metadata(mut self, metadata: serde_json::Value) -> Self {
        self.metadata = Some(metadata);
        self
    }

    /// Nest this resource under `parent` (another spec's `key`).
    #[must_use]
    pub fn under(mut self, parent: impl Into<String>) -> Self {
        self.parent = Some(parent.into());
        self
    }

    /// Declare a scope beneath this resource.
    #[must_use]
    pub fn with_scope(mut self, scope: ScopeSpec) -> Self {
        self.scopes.push(scope);
        self
    }
}

/// A scope, always beneath the resource that declares it.
#[derive(Debug, Clone, PartialEq)]
pub struct ScopeSpec {
    /// Manifest-local identifier, referred to by a role's grants.
    pub key: String,
    /// The scope's name — its natural key within its resource.
    pub name: String,
    /// Human-readable description. The server requires one.
    pub description: String,
}

impl ScopeSpec {
    /// A scope named `name`.
    pub fn new(
        key: impl Into<String>,
        name: impl Into<String>,
        description: impl Into<String>,
    ) -> Self {
        Self {
            key: key.into(),
            name: name.into(),
            description: description.into(),
        }
    }
}

/// A permission — an action, tenant-wide.
#[derive(Debug, Clone, PartialEq)]
pub struct PermissionSpec {
    /// Manifest-local identifier, referred to by a role's grants.
    pub key: String,
    /// The action — the permission's natural key within the tenant.
    pub action: String,
    /// Human-readable description. The server requires one.
    pub description: String,
}

impl PermissionSpec {
    /// A permission for `action`.
    pub fn new(
        key: impl Into<String>,
        action: impl Into<String>,
        description: impl Into<String>,
    ) -> Self {
        Self {
            key: key.into(),
            action: action.into(),
            description: description.into(),
        }
    }
}

/// A role and the permissions granted to it.
#[derive(Debug, Clone, PartialEq)]
pub struct RoleSpec {
    /// Manifest-local identifier, referred to by users and groups.
    pub key: String,
    /// The role's name — its natural key within the tenant.
    pub name: String,
    /// Human-readable description. The server requires one.
    pub description: String,
    /// Whether the role applies tenant-wide rather than to a resource subtree.
    pub is_global: bool,
    /// Permissions this role grants.
    pub grants: Vec<GrantSpec>,
}

impl RoleSpec {
    /// A role named `name`.
    pub fn new(
        key: impl Into<String>,
        name: impl Into<String>,
        description: impl Into<String>,
    ) -> Self {
        Self {
            key: key.into(),
            name: name.into(),
            description: description.into(),
            is_global: false,
            grants: Vec::new(),
        }
    }

    /// Make the role tenant-wide.
    #[must_use]
    pub fn global(mut self) -> Self {
        self.is_global = true;
        self
    }

    /// Grant a permission to this role.
    #[must_use]
    pub fn granting(mut self, grant: GrantSpec) -> Self {
        self.grants.push(grant);
        self
    }
}

/// One permission granted to a role, optionally narrowed to scopes.
#[derive(Debug, Clone, PartialEq)]
pub struct GrantSpec {
    /// The `key` of the [`PermissionSpec`] being granted.
    pub permission: String,
    /// Allow or deny. `None` lets the server default, which is allow.
    ///
    /// A [`Deny`](PermissionEffect::Deny) grant overrides **every** allow, at
    /// any depth of the resource hierarchy and at equal specificity — AXIAM's
    /// RBAC engine is deny-override, not most-specific-wins.
    pub effect: Option<PermissionEffect>,
    /// The `key`s of the [`ScopeSpec`]s this grant is narrowed to. Empty means
    /// the whole resource.
    pub scopes: Vec<String>,
}

impl GrantSpec {
    /// Grant `permission`, unscoped.
    pub fn allow(permission: impl Into<String>) -> Self {
        Self {
            permission: permission.into(),
            effect: Some(PermissionEffect::Allow),
            scopes: Vec::new(),
        }
    }

    /// Deny `permission`. Overrides every allow, at any depth.
    pub fn deny(permission: impl Into<String>) -> Self {
        Self {
            permission: permission.into(),
            effect: Some(PermissionEffect::Deny),
            scopes: Vec::new(),
        }
    }

    /// Narrow this grant to the given scope `key`s.
    #[must_use]
    pub fn scoped_to(mut self, scopes: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.scopes = scopes.into_iter().map(Into::into).collect();
        self
    }
}

/// One role bound to a subject — a group, a user or a service account —
/// in one of the two shapes §27.6.1 item 2 allows (contract 1.51).
///
/// A plain role key converts into [`RoleBinding::Role`], so
/// `with_roles(["editor"])` reads as it always did.
///
/// # A subject holds a role at most once
///
/// The server keys an assignment on `(subject, role)` with no resource
/// component, and a second assignment of the same role to the same subject is
/// a `409` — whatever the resource and whatever the flag. So a subject's
/// bindings name each role **once**: two scoped bindings of one role, or a
/// plain one and a scoped one, describe a state the server cannot hold, and
/// `plan` refuses the manifest before any request, naming the subject and the
/// role.
///
/// # Changing a binding
///
/// The binding's natural key is `(subject, role)`; its resource and `inherit`
/// are fields. When either differs from the server, the action is an
/// `Update`, performed as **unassign, then assign** — there is no update
/// endpoint — so between the two calls the subject does not hold the role. If
/// the assign fails, `apply` assigns the previous binding again and reports
/// both results. The server binding's `tenant_scope` (§5.2.3), which a
/// manifest does not state, is carried across unchanged.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RoleBinding {
    /// The role, with no resource — tenant-wide, and so with no inheritance
    /// question. The binding every manifest had before contract 1.51.
    Role(String),
    /// The role at a resource: a role key and a resource key, both
    /// manifest-local.
    Scoped {
        /// The `key` of the [`RoleSpec`] bound.
        role: String,
        /// The `key` of the [`ResourceSpec`] it is bound at.
        resource: String,
        /// Whether the assignment reaches the resource's descendants — `true`,
        /// the default, or stops at the resource itself (`false`, server
        /// T22.11). Sent to the server only when `false`, so an inheritable
        /// binding's request body is byte-for-byte a pre-1.51 body.
        inherit: bool,
    },
}

impl RoleBinding {
    /// `role` at `resource`, reaching its descendants.
    pub fn at(role: impl Into<String>, resource: impl Into<String>) -> Self {
        RoleBinding::Scoped {
            role: role.into(),
            resource: resource.into(),
            inherit: true,
        }
    }

    /// `role` at `resource` **only** — "here and no further". Refused by the
    /// server (`400`) for a role with `is_global: true`; `plan` refuses it
    /// first when that role is in the manifest.
    pub fn at_only(role: impl Into<String>, resource: impl Into<String>) -> Self {
        RoleBinding::Scoped {
            role: role.into(),
            resource: resource.into(),
            inherit: false,
        }
    }

    /// The `key` of the bound role.
    #[must_use]
    pub fn role(&self) -> &str {
        match self {
            RoleBinding::Role(role) | RoleBinding::Scoped { role, .. } => role,
        }
    }

    /// The `key` of the resource it is bound at, if any.
    #[must_use]
    pub fn resource(&self) -> Option<&str> {
        match self {
            RoleBinding::Role(_) => None,
            RoleBinding::Scoped { resource, .. } => Some(resource),
        }
    }

    /// Whether the binding reaches the resource's descendants. `true` for a
    /// plain role, which has none to stop at.
    #[must_use]
    pub fn inherit(&self) -> bool {
        match self {
            RoleBinding::Role(_) => true,
            RoleBinding::Scoped { inherit, .. } => *inherit,
        }
    }
}

/// A plain binding is its role key: `RoleBinding::Role("editor") == "editor"`.
/// A scoped binding equals no bare key — it says more than one.
impl PartialEq<str> for RoleBinding {
    fn eq(&self, other: &str) -> bool {
        matches!(self, RoleBinding::Role(role) if role == other)
    }
}

impl PartialEq<&str> for RoleBinding {
    fn eq(&self, other: &&str) -> bool {
        self == *other
    }
}

impl From<&str> for RoleBinding {
    fn from(role: &str) -> Self {
        RoleBinding::Role(role.to_string())
    }
}

impl From<String> for RoleBinding {
    fn from(role: String) -> Self {
        RoleBinding::Role(role)
    }
}

impl From<&String> for RoleBinding {
    fn from(role: &String) -> Self {
        RoleBinding::Role(role.clone())
    }
}

/// A group and the roles its members inherit.
#[derive(Debug, Clone, PartialEq)]
pub struct GroupSpec {
    /// Manifest-local identifier, referred to by users.
    pub key: String,
    /// The group's name — its natural key within the tenant.
    pub name: String,
    /// Human-readable description. The server requires one.
    pub description: String,
    /// The roles assigned to this group — role keys, or resource-scoped
    /// [`RoleBinding`]s.
    pub roles: Vec<RoleBinding>,
}

impl GroupSpec {
    /// A group named `name`.
    pub fn new(
        key: impl Into<String>,
        name: impl Into<String>,
        description: impl Into<String>,
    ) -> Self {
        Self {
            key: key.into(),
            name: name.into(),
            description: description.into(),
            roles: Vec::new(),
        }
    }

    /// Assign roles to this group — role keys, or [`RoleBinding`]s.
    #[must_use]
    pub fn with_roles(mut self, roles: impl IntoIterator<Item = impl Into<RoleBinding>>) -> Self {
        self.roles = roles.into_iter().map(Into::into).collect();
        self
    }
}

/// A user, their roles and their group memberships.
///
/// Deliberately not `PartialEq`: it holds a [`Sensitive`], which has no
/// equality by design — comparing secrets in constant time is a different
/// operation from comparing structs, and deriving one here would invite the
/// wrong one.
#[derive(Debug, Clone)]
pub struct UserSpec {
    /// Manifest-local identifier.
    pub key: String,
    /// The username — the user's natural key within the tenant.
    pub username: String,
    /// The user's email address.
    pub email: String,
    /// The password to set **if this user has to be created**.
    ///
    /// Never used for a user that already exists: a manifest is a description
    /// of shape, and silently resetting a live account's password because a
    /// config file mentions one is not a shape change. `plan` fails before any
    /// request when a user must be created and this is `None`, rather than
    /// discovering it halfway through an apply (§27.6 rule 1).
    pub initial_password: Option<Sensitive<String>>,
    /// The roles assigned directly to this user — role keys, or
    /// resource-scoped [`RoleBinding`]s.
    pub roles: Vec<RoleBinding>,
    /// The `key`s of groups this user belongs to.
    pub groups: Vec<String>,
}

impl UserSpec {
    /// A user with the given username and email.
    pub fn new(
        key: impl Into<String>,
        username: impl Into<String>,
        email: impl Into<String>,
    ) -> Self {
        Self {
            key: key.into(),
            username: username.into(),
            email: email.into(),
            initial_password: None,
            roles: Vec::new(),
            groups: Vec::new(),
        }
    }

    /// The password to use if this user has to be created.
    #[must_use]
    pub fn with_initial_password(mut self, password: Sensitive<String>) -> Self {
        self.initial_password = Some(password);
        self
    }

    /// Assign roles directly to this user — role keys, or [`RoleBinding`]s.
    #[must_use]
    pub fn with_roles(mut self, roles: impl IntoIterator<Item = impl Into<RoleBinding>>) -> Self {
        self.roles = roles.into_iter().map(Into::into).collect();
        self
    }

    /// Put this user in the given groups, by `key`.
    #[must_use]
    pub fn in_groups(mut self, groups: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.groups = groups.into_iter().map(Into::into).collect();
        self
    }
}

/// A service account and the roles it holds (contract 1.51, §27.6.1 item 3).
///
/// # Its secret is returned once
///
/// When `apply` creates the account, the action's outcome carries the
/// `client_secret` the server minted — [`Outcome::CreatedServiceAccount`] —
/// **even when a later action of the same `apply` fails**. It is returned by
/// that call and by no other: the server keeps a hash, and `get`/`list` have no
/// secret field at all. Store it from the report. `apply` never calls
/// `rotate_secret`, so re-running after losing it reports `NoChange`.
///
/// # The name is the natural key, and the server does not enforce it
///
/// A service account's only unique index is its `client_id`, so a tenant can
/// hold two accounts with one name. When more than one existing account
/// matches `name`, `plan` fails before `apply` writes anything, rather than
/// reconciling an arbitrary one of them.
///
/// Group membership and `status` are not manifest fields in contract 1.51.
///
/// [`Outcome::CreatedServiceAccount`]: super::Outcome::CreatedServiceAccount
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceAccountSpec {
    /// Manifest-local identifier.
    pub key: String,
    /// The account's name — its natural key within the tenant.
    pub name: String,
    /// Description. The only field an `Update` reconciles; `None` is silent.
    pub description: Option<String>,
    /// The roles this account holds — role keys, or resource-scoped
    /// [`RoleBinding`]s.
    pub roles: Vec<RoleBinding>,
}

impl ServiceAccountSpec {
    /// A service account named `name`.
    pub fn new(key: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            name: name.into(),
            description: None,
            roles: Vec::new(),
        }
    }

    /// State the description.
    #[must_use]
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    /// Assign roles to this account — role keys, or [`RoleBinding`]s.
    #[must_use]
    pub fn with_roles(mut self, roles: impl IntoIterator<Item = impl Into<RoleBinding>>) -> Self {
        self.roles = roles.into_iter().map(Into::into).collect();
        self
    }
}
