//! The plan a manifest reconciles to — CONTRACT.md §27.6.

use std::collections::{HashMap, HashSet};

use uuid::Uuid;

use super::spec::{ManagementManifest, RoleBinding};
use crate::AxiamError;

/// What reconciling one spec would do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Change {
    /// The thing does not exist and would be created.
    Create,
    /// It exists, and a field the manifest *states* differs.
    Update,
    /// It exists and matches. §27.6 rule 3: a field the manifest does not
    /// mention is never a difference, which is what makes `apply` safe against
    /// a tenant that also holds hand-made state.
    NoChange,
}

/// Which part of the manifest an action came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Target {
    /// A resource in the hierarchy.
    Resource,
    /// A scope beneath a resource.
    Scope,
    /// A permission.
    Permission,
    /// A role.
    Role,
    /// A permission granted to a role.
    RoleGrant,
    /// A group.
    Group,
    /// A role assigned to a group.
    GroupRole,
    /// A user.
    User,
    /// A role assigned directly to a user.
    UserRole,
    /// A user's membership of a group.
    GroupMember,
    /// A service account (contract 1.51).
    ServiceAccount,
    /// A role assigned to a service account (contract 1.51).
    ServiceAccountRole,
}

/// One step of a plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedAction {
    /// Whether this step creates, updates, or does nothing.
    pub change: Change,
    /// What kind of thing it acts on.
    pub target: Target,
    /// The manifest key it came from, for a human reading the plan.
    pub key: String,
    /// A one-line description, stable across runs so plans can be diffed.
    pub summary: String,
}

/// The ordered set of actions that would reconcile a manifest.
///
/// Ordering is derived, not incidental (§27.6 rule 5): resources (parents
/// before children), then scopes, permissions, roles, role grants, groups,
/// group bindings, users and their bindings, and finally service accounts and
/// theirs.
/// Two plans over unchanged state are equal, in the same order (§27.6 rule 8)
/// — a plan that reorders between runs cannot be diffed, and diffing it is
/// most of the reason it exists.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ManagementPlan {
    /// Every step, including the no-ops.
    pub actions: Vec<PlannedAction>,
}

impl ManagementPlan {
    /// The steps that would actually change something.
    pub fn changes(&self) -> impl Iterator<Item = &PlannedAction> {
        self.actions.iter().filter(|a| a.change != Change::NoChange)
    }

    /// Whether applying this plan would change nothing.
    ///
    /// This is the §27.6 rule 6 acceptance test: `apply` then `plan` must land
    /// here, or the SDK has a drift-detection bug.
    pub fn is_converged(&self) -> bool {
        self.changes().next().is_none()
    }

    /// How many steps would change something.
    pub fn change_count(&self) -> usize {
        self.changes().count()
    }
}

/// What actually happened to one planned step.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Outcome {
    /// The step ran and the thing now exists.
    Created,
    /// A service account was created, and this is what the server returned —
    /// **including its `client_secret`, which no later read returns** (§27.5
    /// rules 3 and 5). Kept on the report even when a later step fails.
    CreatedServiceAccount(CreatedServiceAccount),
    /// The step ran and the thing was updated.
    Updated,
    /// A no-op step; nothing was sent.
    Unchanged,
    /// The step failed. Everything before it has already happened.
    Failed(String),
    /// A role binding's `Update` failed at its re-assignment (§27.6.1 item 2).
    ///
    /// The previous assignment had already been removed, so `apply` tried to
    /// assign it again. `restore` says how that went: `Ok` means the subject
    /// holds the role exactly as before; `Err` means it holds **no** such role
    /// now, and says why.
    BindingUpdateFailed {
        /// Why the new assignment was refused.
        error: String,
        /// Whether the previous assignment was restored.
        restore: Result<(), String>,
    },
    /// The step was never attempted, because an earlier one failed.
    NotAttempted,
}

/// The server's answer to a service-account `Create`, carried on
/// [`Outcome::CreatedServiceAccount`].
///
/// Equality compares the account's identity — `id` and `client_id` — and
/// **never** the secret: comparing secrets is a constant-time operation with a
/// different purpose, and `Sensitive` deliberately has no `PartialEq`.
#[derive(Debug, Clone)]
pub struct CreatedServiceAccount(pub Box<crate::management::models::ServiceAccountCreatedResponse>);

impl CreatedServiceAccount {
    /// The created account, `client_secret` included (a
    /// [`Sensitive`](crate::Sensitive), redacted in every rendering).
    #[must_use]
    pub fn account(&self) -> &crate::management::models::ServiceAccountCreatedResponse {
        &self.0
    }
}

impl PartialEq for CreatedServiceAccount {
    fn eq(&self, other: &Self) -> bool {
        self.0.id == other.0.id && self.0.client_id == other.0.client_id
    }
}

impl Eq for CreatedServiceAccount {}

/// The result of applying a manifest.
///
/// **There is no transaction here and this type does not pretend there is**
/// (§27.6 rule 7). These are independent HTTP endpoints; nothing spans them.
/// If step 12 of 30 fails, steps 1–11 have happened and will not be undone —
/// so every step's outcome is reported, execution stops at the first failure
/// rather than continuing blindly, and there is no `rollback` method because
/// this SDK could not honour one. Fix the cause and re-apply: rule 6's
/// idempotence is what makes that safe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplyReport {
    /// Each planned step paired with what became of it, in plan order.
    pub steps: Vec<(PlannedAction, Outcome)>,
}

impl ApplyReport {
    /// The failing step, if the apply stopped early.
    pub fn failure(&self) -> Option<(&PlannedAction, &str)> {
        self.steps
            .iter()
            .find_map(|(action, outcome)| match outcome {
                Outcome::Failed(message) => Some((action, message.as_str())),
                Outcome::BindingUpdateFailed { error, .. } => Some((action, error.as_str())),
                _ => None,
            })
    }

    /// Every service account this apply created, with the one-time secret the
    /// server returned for it — including those created before a later step
    /// failed (§27.5 rule 5).
    pub fn created_service_accounts(
        &self,
    ) -> impl Iterator<
        Item = (
            &PlannedAction,
            &crate::management::models::ServiceAccountCreatedResponse,
        ),
    > {
        self.steps
            .iter()
            .filter_map(|(action, outcome)| match outcome {
                Outcome::CreatedServiceAccount(created) => Some((action, created.account())),
                _ => None,
            })
    }

    /// Whether every step that was meant to run did.
    pub fn is_complete(&self) -> bool {
        self.failure().is_none()
    }

    /// How many steps actually changed something.
    pub fn changed(&self) -> usize {
        self.steps
            .iter()
            .filter(|(_, o)| {
                matches!(
                    o,
                    Outcome::Created | Outcome::CreatedServiceAccount(_) | Outcome::Updated
                )
            })
            .count()
    }
}

/// Manifest keys resolved to server ids, built during planning.
#[derive(Debug, Clone, Default)]
pub(crate) struct Resolved {
    pub resources: HashMap<String, Uuid>,
    pub scopes: HashMap<String, Uuid>,
    pub permissions: HashMap<String, Uuid>,
    pub roles: HashMap<String, Uuid>,
    pub groups: HashMap<String, Uuid>,
    pub users: HashMap<String, Uuid>,
    pub service_accounts: HashMap<String, Uuid>,
}

/// Reject a manifest that cannot be reconciled, before any request is made.
///
/// §27.6 rule 2 and rule 5 both land here. Every failure this catches would
/// otherwise surface halfway through an apply, with some of the tenant already
/// changed — which is the expensive moment to learn that a role refers to a
/// permission nobody declared.
pub(crate) fn validate(manifest: &ManagementManifest) -> Result<(), AxiamError> {
    let mut problems: Vec<String> = Vec::new();

    let resource_keys: HashSet<&str> = manifest.resources.iter().map(|r| r.key.as_str()).collect();
    let scope_keys: HashSet<&str> = manifest
        .resources
        .iter()
        .flat_map(|r| r.scopes.iter().map(|s| s.key.as_str()))
        .collect();
    let permission_keys: HashSet<&str> = manifest
        .permissions
        .iter()
        .map(|p| p.key.as_str())
        .collect();
    let role_keys: HashSet<&str> = manifest.roles.iter().map(|r| r.key.as_str()).collect();
    let group_keys: HashSet<&str> = manifest.groups.iter().map(|g| g.key.as_str()).collect();

    duplicates(
        "resource",
        manifest.resources.iter().map(|r| &r.key),
        &mut problems,
    );
    duplicates(
        "scope",
        manifest
            .resources
            .iter()
            .flat_map(|r| r.scopes.iter().map(|s| &s.key)),
        &mut problems,
    );
    duplicates(
        "permission",
        manifest.permissions.iter().map(|p| &p.key),
        &mut problems,
    );
    duplicates("role", manifest.roles.iter().map(|r| &r.key), &mut problems);
    duplicates(
        "group",
        manifest.groups.iter().map(|g| &g.key),
        &mut problems,
    );
    duplicates("user", manifest.users.iter().map(|u| &u.key), &mut problems);

    for resource in &manifest.resources {
        if let Some(parent) = &resource.parent
            && !resource_keys.contains(parent.as_str())
        {
            problems.push(format!(
                "resource {:?} names parent {parent:?}, which no resource declares",
                resource.key
            ));
        }
    }
    for role in &manifest.roles {
        for grant in &role.grants {
            if !permission_keys.contains(grant.permission.as_str()) {
                problems.push(format!(
                    "role {:?} grants permission {:?}, which no permission declares",
                    role.key, grant.permission
                ));
            }
            for scope in &grant.scopes {
                if !scope_keys.contains(scope.as_str()) {
                    problems.push(format!(
                        "role {:?} scopes a grant to {scope:?}, which no scope declares",
                        role.key
                    ));
                }
            }
        }
    }
    duplicates(
        "service account",
        manifest.service_accounts.iter().map(|a| &a.key),
        &mut problems,
    );
    // A service account's name is its natural key, and the server does not
    // enforce it: two specs with one name would create two accounts, and the
    // next plan could no longer tell them apart.
    duplicates(
        "service account name",
        manifest.service_accounts.iter().map(|a| &a.name),
        &mut problems,
    );

    let global_roles: HashSet<&str> = manifest
        .roles
        .iter()
        .filter(|r| r.is_global)
        .map(|r| r.key.as_str())
        .collect();
    let subjects = manifest
        .groups
        .iter()
        .map(|g| ("group", &g.key, &g.roles))
        .chain(manifest.users.iter().map(|u| ("user", &u.key, &u.roles)))
        .chain(
            manifest
                .service_accounts
                .iter()
                .map(|a| ("service account", &a.key, &a.roles)),
        );
    for (kind, subject, bindings) in subjects {
        check_bindings(
            kind,
            subject,
            bindings,
            &role_keys,
            &resource_keys,
            &global_roles,
            &mut problems,
        );
    }
    for user in &manifest.users {
        for group in &user.groups {
            if !group_keys.contains(group.as_str()) {
                problems.push(format!(
                    "user {:?} is in group {group:?}, which no group declares",
                    user.key
                ));
            }
        }
    }

    if let Err(cycle) = topological_order(manifest) {
        problems.push(cycle);
    }

    if problems.is_empty() {
        Ok(())
    } else {
        Err(AxiamError::network(format!(
            "manifest is not reconcilable ({} problem(s)): {}",
            problems.len(),
            problems.join("; ")
        )))
    }
}

/// The §27.6.1 item 2 rules for one subject's role bindings.
fn check_bindings(
    kind: &str,
    subject: &str,
    bindings: &[RoleBinding],
    role_keys: &HashSet<&str>,
    resource_keys: &HashSet<&str>,
    global_roles: &HashSet<&str>,
    problems: &mut Vec<String>,
) {
    let mut seen: HashSet<&str> = HashSet::new();
    for binding in bindings {
        let role = binding.role();
        if !role_keys.contains(role) {
            problems.push(format!(
                "{kind} {subject:?} is assigned role {role:?}, which no role declares"
            ));
        }
        if let Some(resource) = binding.resource()
            && !resource_keys.contains(resource)
        {
            problems.push(format!(
                "{kind} {subject:?} is assigned role {role:?} at resource {resource:?}, which no \
                 resource declares"
            ));
        }
        // The server keys an assignment on (subject, role) — `has_role` is
        // UNIQUE(in, out), a repeat is a 409 — so one role bound twice to one
        // subject is a state it cannot hold, at two resources or once plain and
        // once scoped alike.
        if !seen.insert(role) {
            problems.push(format!(
                "{kind} {subject:?} binds role {role:?} more than once; a subject holds a role at \
                 most once, whatever the resource (the server keys assignments on subject and \
                 role, and answers 409 to a second)"
            ));
        }
        // The server refuses this with 400; §27.6.1 lets an SDK say so first
        // when the role is in the manifest.
        if !binding.inherit() && global_roles.contains(role) {
            problems.push(format!(
                "{kind} {subject:?} binds global role {role:?} with inherit: false; a global role \
                 applies everywhere and ignores the resource, so the server refuses the flag"
            ));
        }
    }
}

fn duplicates<'a>(kind: &str, keys: impl Iterator<Item = &'a String>, problems: &mut Vec<String>) {
    let mut seen: HashSet<&str> = HashSet::new();
    for key in keys {
        if !seen.insert(key.as_str()) {
            problems.push(format!("{kind} key {key:?} is declared more than once"));
        }
    }
}

/// Resource keys ordered so a parent always precedes its children.
///
/// Returns the cycle as an error rather than looping: a resource graph with a
/// cycle has no valid creation order, and discovering that by hanging is worse
/// than discovering it by message.
pub(crate) fn topological_order(manifest: &ManagementManifest) -> Result<Vec<String>, String> {
    let mut parents: HashMap<&str, Option<&str>> = HashMap::new();
    for resource in &manifest.resources {
        parents.insert(resource.key.as_str(), resource.parent.as_deref());
    }

    let mut order: Vec<String> = Vec::new();
    let mut placed: HashSet<&str> = HashSet::new();
    // Iterate the manifest's own order so the result is stable run to run
    // (§27.6 rule 8), rather than a hash-map traversal order that is not.
    for resource in &manifest.resources {
        let mut chain: Vec<&str> = Vec::new();
        let mut cursor = Some(resource.key.as_str());
        let mut guard: HashSet<&str> = HashSet::new();
        while let Some(key) = cursor {
            if placed.contains(key) {
                break;
            }
            if !guard.insert(key) {
                return Err(format!(
                    "resource parent graph has a cycle through {key:?}; there is no order in \
                     which these can be created"
                ));
            }
            chain.push(key);
            cursor = parents.get(key).copied().flatten();
        }
        for key in chain.into_iter().rev() {
            if placed.insert(key) {
                order.push(key.to_string());
            }
        }
    }
    Ok(order)
}
