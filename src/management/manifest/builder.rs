//! The flat builder the [`manifest!`](crate::manifest) macro lowers to.
//!
//! [`ManagementManifest`]'s own fluent constructors nest — a scope is built
//! *inside* the resource that owns it, a grant inside its role. That reads
//! well in Rust and badly in a declaration, where the natural form is a flat
//! list of statements in any order. This builder takes the flat form and does
//! the assembling.
//!
//! It is public because the macro is sugar over it, not a replacement for it:
//! anything the macro can declare, this can build at runtime from a config
//! file, and the two produce the same value.

use std::collections::HashMap;

use super::spec::{
    GrantSpec, GroupSpec, ManagementManifest, PermissionSpec, ResourceSpec, RoleBinding, RoleSpec,
    ScopeSpec, ServiceAccountSpec, UserSpec,
};
use crate::Sensitive;
use crate::management::models::PermissionEffect;

/// Assembles a [`ManagementManifest`] from flat, order-independent statements.
#[derive(Debug, Default)]
pub struct ManifestBuilder {
    resources: Vec<ResourceSpec>,
    scopes: Vec<(String, ScopeSpec)>,
    permissions: Vec<PermissionSpec>,
    roles: Vec<RoleSpec>,
    grants: Vec<(String, GrantSpec)>,
    groups: Vec<GroupSpec>,
    group_roles: Vec<(String, RoleBinding)>,
    users: Vec<UserSpec>,
    user_roles: Vec<(String, RoleBinding)>,
    memberships: Vec<(String, String)>,
    service_accounts: Vec<ServiceAccountSpec>,
    service_account_roles: Vec<(String, RoleBinding)>,
    metadata: Vec<(String, serde_json::Value)>,
}

impl ManifestBuilder {
    /// A builder with nothing declared.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Declare a resource, optionally under another resource's key.
    pub fn resource(
        &mut self,
        key: &str,
        name: &str,
        resource_type: &str,
        parent: Option<&str>,
    ) -> &mut Self {
        let mut spec = ResourceSpec::new(key, name, resource_type);
        spec.parent = parent.map(ToString::to_string);
        self.resources.push(spec);
        self
    }

    /// State the metadata of the resource with key `resource` — the whole
    /// object (contract 1.51, §27.6.1 item 1).
    pub fn resource_metadata(&mut self, resource: &str, metadata: serde_json::Value) -> &mut Self {
        self.metadata.push((resource.to_string(), metadata));
        self
    }

    /// Declare a scope beneath the resource with key `resource`.
    pub fn scope(&mut self, resource: &str, key: &str, name: &str, description: &str) -> &mut Self {
        self.scopes
            .push((resource.to_string(), ScopeSpec::new(key, name, description)));
        self
    }

    /// Declare a permission.
    pub fn permission(&mut self, key: &str, action: &str, description: &str) -> &mut Self {
        self.permissions
            .push(PermissionSpec::new(key, action, description));
        self
    }

    /// Declare a role.
    pub fn role(&mut self, key: &str, name: &str, description: &str, is_global: bool) -> &mut Self {
        let mut spec = RoleSpec::new(key, name, description);
        spec.is_global = is_global;
        self.roles.push(spec);
        self
    }

    /// Grant a permission to a role, optionally narrowed to scope keys.
    pub fn grant(
        &mut self,
        role: &str,
        permission: &str,
        effect: PermissionEffect,
        scopes: &[&str],
    ) -> &mut Self {
        self.grants.push((
            role.to_string(),
            GrantSpec {
                permission: permission.to_string(),
                effect: Some(effect),
                scopes: scopes.iter().map(ToString::to_string).collect(),
            },
        ));
        self
    }

    /// Declare a group.
    pub fn group(&mut self, key: &str, name: &str, description: &str) -> &mut Self {
        self.groups.push(GroupSpec::new(key, name, description));
        self
    }

    /// Assign a role to a group.
    pub fn group_role(&mut self, group: &str, role: impl Into<RoleBinding>) -> &mut Self {
        self.group_roles.push((group.to_string(), role.into()));
        self
    }

    /// Declare a user. `password` is used only if the user has to be created.
    pub fn user(
        &mut self,
        key: &str,
        username: &str,
        email: &str,
        password: Option<Sensitive<String>>,
    ) -> &mut Self {
        let mut spec = UserSpec::new(key, username, email);
        spec.initial_password = password;
        self.users.push(spec);
        self
    }

    /// Assign a role directly to a user.
    pub fn user_role(&mut self, user: &str, role: impl Into<RoleBinding>) -> &mut Self {
        self.user_roles.push((user.to_string(), role.into()));
        self
    }

    /// Declare a service account (contract 1.51, §27.6.1 item 3). If `apply`
    /// creates it, the one-time `client_secret` is on that action's outcome.
    pub fn service_account(
        &mut self,
        key: &str,
        name: &str,
        description: Option<&str>,
    ) -> &mut Self {
        let mut spec = ServiceAccountSpec::new(key, name);
        spec.description = description.map(ToString::to_string);
        self.service_accounts.push(spec);
        self
    }

    /// Assign a role to the service account with key `account` — a role key,
    /// or a resource-scoped [`RoleBinding`].
    pub fn service_account_role(
        &mut self,
        account: &str,
        role: impl Into<RoleBinding>,
    ) -> &mut Self {
        self.service_account_roles
            .push((account.to_string(), role.into()));
        self
    }

    /// Put a user in a group.
    pub fn member(&mut self, user: &str, group: &str) -> &mut Self {
        self.memberships.push((user.to_string(), group.to_string()));
        self
    }

    /// Assemble the manifest, or say which statement names something undeclared.
    ///
    /// Only *structural* references are resolved here — the ones that decide
    /// where a statement attaches. Cross-references that merely need to exist
    /// (a grant naming a permission, a group naming a role) are left as keys
    /// and checked by `plan`, alongside cycles and duplicates, so that all the
    /// semantic complaints arrive together rather than one per build.
    pub fn try_build(self) -> Result<ManagementManifest, String> {
        let mut resources = self.resources;
        let mut index: HashMap<String, usize> = HashMap::new();
        for (i, r) in resources.iter().enumerate() {
            index.insert(r.key.clone(), i);
        }
        for (resource_key, metadata) in self.metadata {
            let at = *index.get(&resource_key).ok_or_else(|| {
                format!(
                    "metadata is stated for resource {resource_key:?}, which no statement declares"
                )
            })?;
            resources[at].metadata = Some(metadata);
        }
        for (resource_key, scope) in self.scopes {
            let at = *index.get(&resource_key).ok_or_else(|| {
                format!(
                    "scope {:?} is declared in resource {resource_key:?}, which no statement \
                     declares",
                    scope.key
                )
            })?;
            resources[at].scopes.push(scope);
        }

        let mut roles = self.roles;
        let role_index: HashMap<String, usize> = roles
            .iter()
            .enumerate()
            .map(|(i, r)| (r.key.clone(), i))
            .collect();
        for (role_key, grant) in self.grants {
            let at = *role_index.get(&role_key).ok_or_else(|| {
                format!(
                    "a grant of {:?} is declared on role {role_key:?}, which no statement declares",
                    grant.permission
                )
            })?;
            roles[at].grants.push(grant);
        }

        let mut groups = self.groups;
        let group_index: HashMap<String, usize> = groups
            .iter()
            .enumerate()
            .map(|(i, g)| (g.key.clone(), i))
            .collect();
        for (group_key, binding) in self.group_roles {
            let at = *group_index.get(&group_key).ok_or_else(|| {
                format!(
                    "role {:?} is assigned to group {group_key:?}, which no statement declares",
                    binding.role()
                )
            })?;
            groups[at].roles.push(binding);
        }

        let mut users = self.users;
        let user_index: HashMap<String, usize> = users
            .iter()
            .enumerate()
            .map(|(i, u)| (u.key.clone(), i))
            .collect();
        for (user_key, binding) in self.user_roles {
            let at = *user_index.get(&user_key).ok_or_else(|| {
                format!(
                    "role {:?} is assigned to user {user_key:?}, which no statement declares",
                    binding.role()
                )
            })?;
            users[at].roles.push(binding);
        }
        for (user_key, group_key) in self.memberships {
            let at = *user_index.get(&user_key).ok_or_else(|| {
                format!(
                    "user {user_key:?} is put in group {group_key:?}, but no statement declares \
                     that user"
                )
            })?;
            users[at].groups.push(group_key);
        }

        let mut service_accounts = self.service_accounts;
        let account_index: HashMap<String, usize> = service_accounts
            .iter()
            .enumerate()
            .map(|(i, a)| (a.key.clone(), i))
            .collect();
        for (account_key, binding) in self.service_account_roles {
            let at = *account_index.get(&account_key).ok_or_else(|| {
                format!(
                    "role {:?} is assigned to service account {account_key:?}, which no statement \
                     declares",
                    binding.role()
                )
            })?;
            service_accounts[at].roles.push(binding);
        }

        Ok(ManagementManifest {
            resources,
            permissions: self.permissions,
            roles,
            groups,
            users,
            service_accounts,
        })
    }

    /// [`Self::try_build`], panicking on an unresolvable structural reference.
    ///
    /// This is what the [`manifest!`](crate::manifest) macro calls. In a
    /// literal declaration an unknown key is a typo the author meets the first
    /// time the code runs, in the same way an out-of-range index in an array
    /// literal is — so it panics with the key named rather than returning a
    /// `Result` the macro would have to make every caller unwrap.
    ///
    /// Build from configuration with [`Self::try_build`] instead.
    #[must_use]
    pub fn build(self) -> ManagementManifest {
        match self.try_build() {
            Ok(manifest) => manifest,
            Err(problem) => panic!("manifest! declaration is malformed: {problem}"),
        }
    }
}
