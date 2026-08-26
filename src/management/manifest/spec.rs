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
        }
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

/// A group and the roles its members inherit.
#[derive(Debug, Clone, PartialEq)]
pub struct GroupSpec {
    /// Manifest-local identifier, referred to by users.
    pub key: String,
    /// The group's name — its natural key within the tenant.
    pub name: String,
    /// Human-readable description. The server requires one.
    pub description: String,
    /// The `key`s of roles assigned to this group.
    pub roles: Vec<String>,
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

    /// Assign roles to this group, by `key`.
    #[must_use]
    pub fn with_roles(mut self, roles: impl IntoIterator<Item = impl Into<String>>) -> Self {
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
    /// The `key`s of roles assigned directly to this user.
    pub roles: Vec<String>,
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

    /// Assign roles directly to this user, by `key`.
    #[must_use]
    pub fn with_roles(mut self, roles: impl IntoIterator<Item = impl Into<String>>) -> Self {
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
