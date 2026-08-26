//! Declarative management — CONTRACT.md §27.6.
//!
//! The 146 operations of §27 are the floor, not the ceiling. What an
//! application actually does at start-up, in a migration, or in a test fixture
//! is **assert a shape**: this tenant has these resources, with these scopes,
//! these permissions, these roles, and these bindings. Written imperatively
//! that is forty calls wrapped in exists-checks, and it is wrong the second
//! time it runs.
//!
//! ```no_run
//! # use axiam_sdk::client::AxiamClient;
//! use axiam_sdk::management::manifest::{
//!     GrantSpec, ManagementManifest, PermissionSpec, ResourceSpec, RoleSpec, ScopeSpec,
//! };
//!
//! # async fn demo(client: &AxiamClient) -> Result<(), axiam_sdk::AxiamError> {
//! let manifest = ManagementManifest::new()
//!     .with_resource(
//!         ResourceSpec::new("docs", "documents", "collection")
//!             .with_scope(ScopeSpec::new("docs.draft", "draft", "Unpublished documents")),
//!     )
//!     .with_permission(PermissionSpec::new("read", "document:read", "Read a document"))
//!     .with_role(
//!         RoleSpec::new("editor", "Editor", "Edits documents")
//!             .granting(GrantSpec::allow("read").scoped_to(["docs.draft"])),
//!     );
//!
//! // Read-only: shows what would change, touches nothing.
//! let plan = client.manifest().plan(&manifest).await?;
//! println!("{} change(s)", plan.change_count());
//!
//! let report = client.manifest().apply(&manifest).await?;
//! assert!(report.is_complete());
//! # Ok(())
//! # }
//! ```
//!
//! # The rules that matter
//!
//! **[`plan`](Manifest::plan) writes nothing.** Not "nothing important" —
//! nothing. It issues `GET`s only, which is what makes it safe to point at
//! production, and which has its own test asserting the mock transport saw no
//! other verb.
//!
//! **Reconciliation is by natural key.** A manifest is written before the
//! things in it exist, so it cannot name them by id. Each spec carries the key
//! its namespace is unique on — a user's `username`, a role's `name`, a
//! scope's `name` within its resource — and cross-references use a
//! manifest-local `key` resolved during planning.
//!
//! **A field the manifest does not state is never a difference.** That is what
//! makes [`apply`](Manifest::apply) safe against a tenant that also holds
//! hand-made state.
//!
//! **Nothing is ever deleted.** §27.6 rule 4 forbids deleting without an
//! explicit per-namespace opt-in; this SDK offers no such opt-in at all, so a
//! manifest that omits an existing role leaves it alone. A manifest is usually
//! a *subset* of a tenant's truth, and a prune would turn "make sure these
//! three roles exist" into "delete the other forty".
//!
//! **There is no transaction.** See [`ApplyReport`].

mod builder;
#[macro_use]
mod macros;
mod plan;
mod spec;

pub use builder::ManifestBuilder;
pub use plan::{ApplyReport, Change, ManagementPlan, Outcome, PlannedAction, Target};
pub use spec::{
    GrantSpec, GroupSpec, ManagementManifest, PermissionSpec, ResourceSpec, RoleSpec, ScopeSpec,
    UserSpec,
};

use std::collections::HashMap;

use uuid::Uuid;

use crate::AxiamError;
use crate::client::AxiamClient;
use crate::management::models;
use crate::management::page::PageRequest;
use plan::{Resolved, topological_order, validate};

/// How many items a planning read asks for per page.
///
/// Planning walks each collection to exhaustion; this is only the page size.
const PLAN_PAGE: u64 = 200;

/// The declarative-management handle, reached from [`AxiamClient::manifest`].
#[derive(Clone, Copy)]
pub struct Manifest<'c> {
    client: &'c AxiamClient,
}

impl std::fmt::Debug for Manifest<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Manifest")
    }
}

impl AxiamClient {
    /// Declarative management (CONTRACT.md §27.6) — [`plan`](Manifest::plan)
    /// and [`apply`](Manifest::apply) a [`ManagementManifest`].
    #[must_use]
    pub fn manifest(&self) -> Manifest<'_> {
        Manifest { client: self }
    }
}

/// The current state a plan is computed against.
struct Snapshot {
    resources: Vec<models::Resource>,
    scopes: HashMap<Uuid, Vec<models::Scope>>,
    permissions: Vec<models::Permission>,
    roles: Vec<models::Role>,
    groups: Vec<models::Group>,
    users: Vec<models::UserResponse>,
    role_grants: HashMap<Uuid, Vec<Uuid>>,
    role_users: HashMap<Uuid, Vec<Uuid>>,
    role_groups: HashMap<Uuid, Vec<Uuid>>,
    group_members: HashMap<Uuid, Vec<Uuid>>,
}

impl<'c> Manifest<'c> {
    /// What reconciling `manifest` would do. **Issues no writes.**
    pub async fn plan(&self, manifest: &ManagementManifest) -> Result<ManagementPlan, AxiamError> {
        validate(manifest)?;
        let snapshot = self.read(manifest).await?;
        let (plan, _, _) = self.compute(manifest, &snapshot)?;
        Ok(plan)
    }

    /// Reconcile `manifest`, stopping at the first failure.
    ///
    /// Re-running after fixing the cause is the recovery path, and is safe:
    /// applying twice converges (§27.6 rule 6).
    pub async fn apply(&self, manifest: &ManagementManifest) -> Result<ApplyReport, AxiamError> {
        validate(manifest)?;
        let snapshot = self.read(manifest).await?;
        let (plan, mut resolved, steps) = self.compute(manifest, &snapshot)?;
        self.execute(plan, steps, &mut resolved).await
    }

    // -----------------------------------------------------------------
    // Read
    // -----------------------------------------------------------------

    async fn read(&self, manifest: &ManagementManifest) -> Result<Snapshot, AxiamError> {
        let c = self.client;
        let start = PageRequest::first(PLAN_PAGE);
        let resources = c.resources().list_all(start).await?;
        let permissions = c.permissions().list_all(start).await?;
        let roles = c.roles().list_all(start).await?;
        let groups = c.groups().list_all(start).await?;
        let users = c.users().list_all(start).await?;

        let mut scopes = HashMap::new();
        // Only resources the manifest could match: a tenant with a thousand
        // resources should not cost a thousand scope reads to plan five.
        let wanted: Vec<&models::Resource> = resources
            .iter()
            .filter(|r| manifest.resources.iter().any(|s| s.name == r.name))
            .collect();
        for resource in wanted {
            scopes.insert(resource.id, c.scopes().list(resource.id).await?);
        }

        let mut role_grants = HashMap::new();
        let mut role_users = HashMap::new();
        let mut role_groups = HashMap::new();
        for role in roles
            .iter()
            .filter(|r| manifest.roles.iter().any(|s| s.name == r.name))
        {
            role_grants.insert(
                role.id,
                c.roles()
                    .list_permissions(role.id)
                    .await?
                    .into_iter()
                    .map(|g| g.permission.id)
                    .collect::<Vec<_>>(),
            );
            role_users.insert(
                role.id,
                c.roles()
                    .list_users(role.id)
                    .await?
                    .into_iter()
                    .map(|a| a.user.id)
                    .collect::<Vec<_>>(),
            );
            role_groups.insert(
                role.id,
                c.roles()
                    .list_groups(role.id)
                    .await?
                    .into_iter()
                    .map(|a| a.group.id)
                    .collect::<Vec<_>>(),
            );
        }

        let mut group_members = HashMap::new();
        for group in groups
            .iter()
            .filter(|g| manifest.groups.iter().any(|s| s.name == g.name))
        {
            group_members.insert(
                group.id,
                c.groups()
                    .list_members_all(group.id, start)
                    .await?
                    .into_iter()
                    .map(|u| u.id)
                    .collect::<Vec<_>>(),
            );
        }

        Ok(Snapshot {
            resources,
            scopes,
            permissions,
            roles,
            groups,
            users,
            role_grants,
            role_users,
            role_groups,
            group_members,
        })
    }
}

/// One executable step, carrying manifest keys rather than ids.
///
/// Keys, not ids, because a child resource's parent may not exist until the
/// step before it runs — the plan is computed once, up front, and resolution
/// has to happen as execution goes.
#[derive(Debug, Clone)]
enum Step {
    Noop,
    CreateResource {
        key: String,
        name: String,
        resource_type: String,
        parent: Option<String>,
    },
    UpdateResource {
        key: String,
        resource_type: String,
    },
    CreateScope {
        resource: String,
        key: String,
        name: String,
        description: String,
    },
    CreatePermission {
        key: String,
        action: String,
        description: String,
    },
    UpdatePermission {
        key: String,
        description: String,
    },
    CreateRole {
        key: String,
        name: String,
        description: String,
        is_global: bool,
    },
    UpdateRole {
        key: String,
        description: String,
        is_global: bool,
    },
    GrantPermission {
        role: String,
        permission: String,
        effect: Option<crate::management::models::PermissionEffect>,
        scopes: Vec<String>,
    },
    CreateGroup {
        key: String,
        name: String,
        description: String,
    },
    UpdateGroup {
        key: String,
        description: String,
    },
    AssignRoleToGroup {
        role: String,
        group: String,
    },
    CreateUser {
        key: String,
        username: String,
        email: String,
        password: crate::Sensitive<String>,
    },
    UpdateUser {
        key: String,
        email: String,
    },
    AssignRoleToUser {
        role: String,
        user: String,
    },
    AddGroupMember {
        group: String,
        user: String,
    },
}

impl<'c> Manifest<'c> {
    // -----------------------------------------------------------------
    // Plan
    // -----------------------------------------------------------------

    #[allow(clippy::too_many_lines)]
    fn compute(
        &self,
        manifest: &ManagementManifest,
        snapshot: &Snapshot,
    ) -> Result<(ManagementPlan, Resolved, Vec<Step>), AxiamError> {
        let mut resolved = Resolved::default();
        let mut steps: Vec<(PlannedAction, Step)> = Vec::new();

        let specs: HashMap<&str, &ResourceSpec> = manifest
            .resources
            .iter()
            .map(|r| (r.key.as_str(), r))
            .collect();

        // Resources, parents first — `topological_order` already rejected a
        // cycle during validation, so this cannot loop.
        let order = topological_order(manifest).map_err(AxiamError::network)?;
        for key in &order {
            let spec = specs[key.as_str()];
            let parent_id = spec
                .parent
                .as_ref()
                .map(|p| resolved.resources.get(p).copied());
            // A child whose parent is itself pending cannot already exist, so
            // matching it against a root of the same name would be wrong.
            let parent_pending = matches!(parent_id, Some(None));
            let parent_id = parent_id.flatten();
            let existing = if parent_pending {
                None
            } else {
                snapshot
                    .resources
                    .iter()
                    .find(|r| r.name == spec.name && r.parent_id == parent_id)
            };
            match existing {
                Some(found) => {
                    resolved.resources.insert(spec.key.clone(), found.id);
                    let drifted = found.resource_type != spec.resource_type;
                    steps.push((
                        action(
                            if drifted {
                                Change::Update
                            } else {
                                Change::NoChange
                            },
                            Target::Resource,
                            &spec.key,
                            format!("resource {:?} ({})", spec.name, spec.resource_type),
                        ),
                        if drifted {
                            Step::UpdateResource {
                                key: spec.key.clone(),
                                resource_type: spec.resource_type.clone(),
                            }
                        } else {
                            Step::Noop
                        },
                    ));
                }
                None => steps.push((
                    action(
                        Change::Create,
                        Target::Resource,
                        &spec.key,
                        format!("resource {:?} ({})", spec.name, spec.resource_type),
                    ),
                    Step::CreateResource {
                        key: spec.key.clone(),
                        name: spec.name.clone(),
                        resource_type: spec.resource_type.clone(),
                        parent: spec.parent.clone(),
                    },
                )),
            }
        }

        // Scopes, under whichever resource declares them.
        for key in &order {
            let spec = specs[key.as_str()];
            let resource_id = resolved.resources.get(&spec.key).copied();
            let empty = Vec::new();
            let existing_scopes = resource_id
                .and_then(|id| snapshot.scopes.get(&id))
                .unwrap_or(&empty);
            for scope in &spec.scopes {
                match existing_scopes.iter().find(|s| s.name == scope.name) {
                    Some(found) => {
                        resolved.scopes.insert(scope.key.clone(), found.id);
                        steps.push((
                            action(
                                Change::NoChange,
                                Target::Scope,
                                &scope.key,
                                format!("scope {:?} on {:?}", scope.name, spec.name),
                            ),
                            Step::Noop,
                        ));
                    }
                    None => steps.push((
                        action(
                            Change::Create,
                            Target::Scope,
                            &scope.key,
                            format!("scope {:?} on {:?}", scope.name, spec.name),
                        ),
                        Step::CreateScope {
                            resource: spec.key.clone(),
                            key: scope.key.clone(),
                            name: scope.name.clone(),
                            description: scope.description.clone(),
                        },
                    )),
                }
            }
        }

        for spec in &manifest.permissions {
            match snapshot
                .permissions
                .iter()
                .find(|p| p.action == spec.action)
            {
                Some(found) => {
                    resolved.permissions.insert(spec.key.clone(), found.id);
                    let drifted = found.description != spec.description;
                    steps.push((
                        action(
                            if drifted {
                                Change::Update
                            } else {
                                Change::NoChange
                            },
                            Target::Permission,
                            &spec.key,
                            format!("permission {:?}", spec.action),
                        ),
                        if drifted {
                            Step::UpdatePermission {
                                key: spec.key.clone(),
                                description: spec.description.clone(),
                            }
                        } else {
                            Step::Noop
                        },
                    ));
                }
                None => steps.push((
                    action(
                        Change::Create,
                        Target::Permission,
                        &spec.key,
                        format!("permission {:?}", spec.action),
                    ),
                    Step::CreatePermission {
                        key: spec.key.clone(),
                        action: spec.action.clone(),
                        description: spec.description.clone(),
                    },
                )),
            }
        }

        for spec in &manifest.roles {
            match snapshot.roles.iter().find(|r| r.name == spec.name) {
                Some(found) => {
                    resolved.roles.insert(spec.key.clone(), found.id);
                    let drifted =
                        found.description != spec.description || found.is_global != spec.is_global;
                    steps.push((
                        action(
                            if drifted {
                                Change::Update
                            } else {
                                Change::NoChange
                            },
                            Target::Role,
                            &spec.key,
                            format!("role {:?}", spec.name),
                        ),
                        if drifted {
                            Step::UpdateRole {
                                key: spec.key.clone(),
                                description: spec.description.clone(),
                                is_global: spec.is_global,
                            }
                        } else {
                            Step::Noop
                        },
                    ));
                }
                None => steps.push((
                    action(
                        Change::Create,
                        Target::Role,
                        &spec.key,
                        format!("role {:?}", spec.name),
                    ),
                    Step::CreateRole {
                        key: spec.key.clone(),
                        name: spec.name.clone(),
                        description: spec.description.clone(),
                        is_global: spec.is_global,
                    },
                )),
            }
        }

        // Role grants. Present-or-absent only: a grant this manifest does not
        // mention is left alone (§27.6 rule 3), which is also why there is no
        // "revoke" step.
        for spec in &manifest.roles {
            let held = resolved
                .roles
                .get(&spec.key)
                .and_then(|id| snapshot.role_grants.get(id));
            for grant in &spec.grants {
                let permission_id = resolved.permissions.get(&grant.permission).copied();
                let present =
                    matches!((held, permission_id), (Some(list), Some(pid)) if list.contains(&pid));
                steps.push((
                    action(
                        if present {
                            Change::NoChange
                        } else {
                            Change::Create
                        },
                        Target::RoleGrant,
                        &spec.key,
                        format!("role {:?} grants {:?}", spec.name, grant.permission),
                    ),
                    if present {
                        Step::Noop
                    } else {
                        Step::GrantPermission {
                            role: spec.key.clone(),
                            permission: grant.permission.clone(),
                            effect: grant.effect,
                            scopes: grant.scopes.clone(),
                        }
                    },
                ));
            }
        }

        for spec in &manifest.groups {
            match snapshot.groups.iter().find(|g| g.name == spec.name) {
                Some(found) => {
                    resolved.groups.insert(spec.key.clone(), found.id);
                    let drifted = found.description != spec.description;
                    steps.push((
                        action(
                            if drifted {
                                Change::Update
                            } else {
                                Change::NoChange
                            },
                            Target::Group,
                            &spec.key,
                            format!("group {:?}", spec.name),
                        ),
                        if drifted {
                            Step::UpdateGroup {
                                key: spec.key.clone(),
                                description: spec.description.clone(),
                            }
                        } else {
                            Step::Noop
                        },
                    ));
                }
                None => steps.push((
                    action(
                        Change::Create,
                        Target::Group,
                        &spec.key,
                        format!("group {:?}", spec.name),
                    ),
                    Step::CreateGroup {
                        key: spec.key.clone(),
                        name: spec.name.clone(),
                        description: spec.description.clone(),
                    },
                )),
            }
        }

        for spec in &manifest.groups {
            let group_id = resolved.groups.get(&spec.key).copied();
            for role_key in &spec.roles {
                let role_id = resolved.roles.get(role_key).copied();
                let present = matches!(
                    (role_id, group_id),
                    (Some(rid), Some(gid))
                        if snapshot.role_groups.get(&rid).is_some_and(|l| l.contains(&gid))
                );
                steps.push((
                    action(
                        if present {
                            Change::NoChange
                        } else {
                            Change::Create
                        },
                        Target::GroupRole,
                        &spec.key,
                        format!("group {:?} holds role {role_key:?}", spec.name),
                    ),
                    if present {
                        Step::Noop
                    } else {
                        Step::AssignRoleToGroup {
                            role: role_key.clone(),
                            group: spec.key.clone(),
                        }
                    },
                ));
            }
        }

        for spec in &manifest.users {
            match snapshot.users.iter().find(|u| u.username == spec.username) {
                Some(found) => {
                    resolved.users.insert(spec.key.clone(), found.id);
                    let drifted = found.email != spec.email;
                    steps.push((
                        action(
                            if drifted {
                                Change::Update
                            } else {
                                Change::NoChange
                            },
                            Target::User,
                            &spec.key,
                            format!("user {:?}", spec.username),
                        ),
                        if drifted {
                            Step::UpdateUser {
                                key: spec.key.clone(),
                                email: spec.email.clone(),
                            }
                        } else {
                            Step::Noop
                        },
                    ));
                }
                None => {
                    // §27.6 rule 1: catch this here, before anything has been
                    // written, rather than halfway through an apply.
                    let password = spec.initial_password.clone().ok_or_else(|| {
                        AxiamError::network(format!(
                            "user {:?} does not exist and would be created, but the spec carries \
                             no initial_password",
                            spec.username
                        ))
                    })?;
                    steps.push((
                        action(
                            Change::Create,
                            Target::User,
                            &spec.key,
                            format!("user {:?}", spec.username),
                        ),
                        Step::CreateUser {
                            key: spec.key.clone(),
                            username: spec.username.clone(),
                            email: spec.email.clone(),
                            password,
                        },
                    ));
                }
            }
        }

        for spec in &manifest.users {
            let user_id = resolved.users.get(&spec.key).copied();
            for role_key in &spec.roles {
                let role_id = resolved.roles.get(role_key).copied();
                let present = matches!(
                    (role_id, user_id),
                    (Some(rid), Some(uid))
                        if snapshot.role_users.get(&rid).is_some_and(|l| l.contains(&uid))
                );
                steps.push((
                    action(
                        if present {
                            Change::NoChange
                        } else {
                            Change::Create
                        },
                        Target::UserRole,
                        &spec.key,
                        format!("user {:?} holds role {role_key:?}", spec.username),
                    ),
                    if present {
                        Step::Noop
                    } else {
                        Step::AssignRoleToUser {
                            role: role_key.clone(),
                            user: spec.key.clone(),
                        }
                    },
                ));
            }
            for group_key in &spec.groups {
                let group_id = resolved.groups.get(group_key).copied();
                let present = matches!(
                    (group_id, user_id),
                    (Some(gid), Some(uid))
                        if snapshot.group_members.get(&gid).is_some_and(|l| l.contains(&uid))
                );
                steps.push((
                    action(
                        if present {
                            Change::NoChange
                        } else {
                            Change::Create
                        },
                        Target::GroupMember,
                        &spec.key,
                        format!("user {:?} is in group {group_key:?}", spec.username),
                    ),
                    if present {
                        Step::Noop
                    } else {
                        Step::AddGroupMember {
                            group: group_key.clone(),
                            user: spec.key.clone(),
                        }
                    },
                ));
            }
        }

        let (actions, pending): (Vec<_>, Vec<_>) = steps.into_iter().unzip();
        Ok((ManagementPlan { actions }, resolved, pending))
    }
}

fn action(change: Change, target: Target, key: &str, summary: String) -> PlannedAction {
    PlannedAction {
        change,
        target,
        key: key.to_string(),
        summary,
    }
}

impl<'c> Manifest<'c> {
    // -----------------------------------------------------------------
    // Apply
    // -----------------------------------------------------------------

    /// Run the plan, stopping at the first failure.
    ///
    /// §27.6 rule 7: there is no transaction across 146 independent HTTP
    /// endpoints, so this reports what each step did, stops rather than
    /// continuing blindly past a failure, and offers no rollback.
    async fn execute(
        &self,
        plan: ManagementPlan,
        steps: Vec<Step>,
        resolved: &mut Resolved,
    ) -> Result<ApplyReport, AxiamError> {
        let mut out: Vec<(PlannedAction, Outcome)> = Vec::with_capacity(plan.actions.len());
        let mut stopped = false;
        for (action, step) in plan.actions.into_iter().zip(steps) {
            if stopped {
                out.push((action, Outcome::NotAttempted));
                continue;
            }
            if matches!(step, Step::Noop) {
                out.push((action, Outcome::Unchanged));
                continue;
            }
            let created = matches!(action.change, Change::Create);
            match self.run(step, resolved).await {
                Ok(()) => out.push((
                    action,
                    if created {
                        Outcome::Created
                    } else {
                        Outcome::Updated
                    },
                )),
                Err(e) => {
                    stopped = true;
                    out.push((action, Outcome::Failed(e.to_string())));
                }
            }
        }
        Ok(ApplyReport { steps: out })
    }

    #[allow(clippy::too_many_lines)]
    async fn run(&self, step: Step, resolved: &mut Resolved) -> Result<(), AxiamError> {
        let c = self.client;
        match step {
            Step::Noop => {}
            Step::CreateResource {
                key,
                name,
                resource_type,
                parent,
            } => {
                let parent_id = match parent {
                    Some(p) => Some(lookup(&resolved.resources, &p, "resource")?),
                    None => None,
                };
                let created = c
                    .resources()
                    .create(&models::CreateResourceRequest {
                        name,
                        resource_type,
                        parent_id,
                        metadata: None,
                    })
                    .await?;
                resolved.resources.insert(key, created.id);
            }
            Step::UpdateResource { key, resource_type } => {
                let id = lookup(&resolved.resources, &key, "resource")?;
                c.resources()
                    .update(
                        id,
                        &models::UpdateResourceRequest {
                            resource_type: Some(resource_type),
                            ..Default::default()
                        },
                    )
                    .await?;
            }
            Step::CreateScope {
                resource,
                key,
                name,
                description,
            } => {
                let resource_id = lookup(&resolved.resources, &resource, "resource")?;
                let created = c
                    .scopes()
                    .create(
                        resource_id,
                        &models::CreateScopeRequest { name, description },
                    )
                    .await?;
                resolved.scopes.insert(key, created.id);
            }
            Step::CreatePermission {
                key,
                action,
                description,
            } => {
                let created = c
                    .permissions()
                    .create(&models::CreatePermissionRequest {
                        action,
                        description,
                    })
                    .await?;
                resolved.permissions.insert(key, created.id);
            }
            Step::UpdatePermission { key, description } => {
                let id = lookup(&resolved.permissions, &key, "permission")?;
                c.permissions()
                    .update(
                        id,
                        &models::UpdatePermissionRequest {
                            description: Some(description),
                            ..Default::default()
                        },
                    )
                    .await?;
            }
            Step::CreateRole {
                key,
                name,
                description,
                is_global,
            } => {
                let created = c
                    .roles()
                    .create(&models::CreateRoleRequest {
                        name,
                        description,
                        is_global,
                    })
                    .await?;
                resolved.roles.insert(key, created.id);
            }
            Step::UpdateRole {
                key,
                description,
                is_global,
            } => {
                let id = lookup(&resolved.roles, &key, "role")?;
                c.roles()
                    .update(
                        id,
                        &models::UpdateRole {
                            description: Some(description),
                            is_global: Some(is_global),
                            ..Default::default()
                        },
                    )
                    .await?;
            }
            Step::GrantPermission {
                role,
                permission,
                effect,
                scopes,
            } => {
                let role_id = lookup(&resolved.roles, &role, "role")?;
                let permission_id = lookup(&resolved.permissions, &permission, "permission")?;
                let scope_ids = scopes
                    .iter()
                    .map(|s| lookup(&resolved.scopes, s, "scope"))
                    .collect::<Result<Vec<_>, _>>()?;
                c.roles()
                    .grant_permission(
                        role_id,
                        &models::GrantPermissionRequest {
                            permission_id,
                            effect,
                            scope_ids: if scope_ids.is_empty() {
                                None
                            } else {
                                Some(scope_ids)
                            },
                        },
                    )
                    .await?;
            }
            Step::CreateGroup {
                key,
                name,
                description,
            } => {
                let created = c
                    .groups()
                    .create(&models::CreateGroupRequest {
                        name,
                        description,
                        metadata: None,
                    })
                    .await?;
                resolved.groups.insert(key, created.id);
            }
            Step::UpdateGroup { key, description } => {
                let id = lookup(&resolved.groups, &key, "group")?;
                c.groups()
                    .update(
                        id,
                        &models::UpdateGroup {
                            description: Some(description),
                            ..Default::default()
                        },
                    )
                    .await?;
            }
            Step::AssignRoleToGroup { role, group } => {
                let role_id = lookup(&resolved.roles, &role, "role")?;
                let group_id = lookup(&resolved.groups, &group, "group")?;
                c.roles()
                    .assign_to_group(
                        role_id,
                        &models::AssignRoleToGroupRequest {
                            group_id,
                            resource_id: None,
                        },
                    )
                    .await?;
            }
            Step::CreateUser {
                key,
                username,
                email,
                password,
            } => {
                let created = c
                    .users()
                    .create(&models::CreateUserRequest {
                        username,
                        email,
                        password,
                        metadata: None,
                        opaque: None,
                    })
                    .await?;
                resolved.users.insert(key, created.id);
            }
            Step::UpdateUser { key, email } => {
                let id = lookup(&resolved.users, &key, "user")?;
                c.users()
                    .update(
                        id,
                        &models::UpdateUserRequest {
                            email: Some(email),
                            ..Default::default()
                        },
                    )
                    .await?;
            }
            Step::AssignRoleToUser { role, user } => {
                let role_id = lookup(&resolved.roles, &role, "role")?;
                let user_id = lookup(&resolved.users, &user, "user")?;
                c.roles()
                    .assign_to_user(
                        role_id,
                        &models::AssignRoleToUserRequest {
                            user_id,
                            resource_id: None,
                        },
                    )
                    .await?;
            }
            Step::AddGroupMember { group, user } => {
                let group_id = lookup(&resolved.groups, &group, "group")?;
                let user_id = lookup(&resolved.users, &user, "user")?;
                c.groups()
                    .add_member(group_id, &models::AddMemberRequest { user_id })
                    .await?;
            }
        }
        Ok(())
    }
}

/// Resolve a manifest key to the id an earlier step recorded.
///
/// A miss here is an SDK bug, not a user error — validation already rejected
/// dangling references, and the plan orders producers before consumers — so it
/// says so rather than blaming the manifest.
fn lookup(map: &HashMap<String, Uuid>, key: &str, kind: &str) -> Result<Uuid, AxiamError> {
    map.get(key).copied().ok_or_else(|| {
        AxiamError::network(format!(
            "internal: {kind} key {key:?} was consumed before the step that creates it ran"
        ))
    })
}
