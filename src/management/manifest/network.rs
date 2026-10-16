//! The `network` namespace in a manifest — CONTRACT.md §27.6.2 (contract 1.62).
//!
//! A tenant's network segments, the reply profile each owns and the tenant's
//! `Session-Timeout` cap (CONTRACT.md §36) are *shape*, and so a manifest
//! namespace. Three specs, three natural keys:
//!
//! | Spec | Natural key |
//! |---|---|
//! | [`NetworkSegmentSpec`] | **site + kind + name**, where `kind` is the wire spelling `access` or `quarantine` |
//! | [`NetworkProfileSpec`] | **its segment**: a profile has no name or id of its own |
//! | [`NetworkPolicySpec`]  | **a singleton**: the tenant has exactly one |
//!
//! # Order
//!
//! After everything else a manifest plans: the policy, then the segments, then
//! the profiles, and within the profiles the segments' order. The policy is
//! first because a profile's timeout is checked against the cap at the write.
//!
//! # Judged on the read
//!
//! Every stated member is compared with the value as the read returns it — for
//! a profile, the **effective** one. Two consequences worth knowing:
//!
//! * **A clamped profile.** A profile whose stored timeout is above a lowered
//!   cap reads as the cap, with `session_timeout_clamped: true`. A manifest
//!   that states the cap is `NoChange` (the stored value is neither restored
//!   nor rewritten). A manifest that states a value **above** the cap differs
//!   from the read, so [`plan`](super::Manifest::plan) shows an `Update`, and
//!   [`apply`](super::Manifest::apply) sends the `replace_profile` — which the
//!   server refuses with `403 authorization_denied`, its message naming the
//!   cap. That is the action's failure: reported as given, `apply` stops, and
//!   nothing is retried, adjusted or lowered to the cap by this SDK. Lower the
//!   stated value, or state a higher [`NetworkPolicySpec`] in the same manifest
//!   (the policy is written first).
//!
//!   A read-modify-write of a clamped profile **cannot restore the stored
//!   value**: it can send at most the cap, and what it sends is what is stored
//!   from then on (§36.3 rule 6). An `Update` that does not state the timeout
//!   carries the *read's* — the clamped — value. Raise the cap first, with the
//!   profile left alone, to get the stored value back at read.
//! * **`filter_ids` is a set.** The same names in another order are `NoChange`.
//!   When this SDK does write a segment it sends the names in the order the
//!   manifest states. A list that repeats a name is refused at `plan`, with no
//!   request made.
//!
//! # What this SDK does not do
//!
//! * It never retries a write, and never re-reads and tries again on a `409`:
//!   another administrator wrote, and the administrator decides (§36.9). The
//!   action fails with [`Outcome::Conflict`](super::Outcome::Conflict), which
//!   exposes the server's `reason_code`; run `apply` again, which re-reads.
//! * It does not **prune**. §27.6 rule 4 makes deletion opt-in, per namespace,
//!   and this SDK offers no such opt-in for any namespace, so `plan` never
//!   emits a `Delete` — for a segment, a profile or anything else. Use
//!   `network().delete_segment` / `delete_profile` (each takes the `version`).
//! * The `manifest!` macro and [`ManifestBuilder`](super::ManifestBuilder) do
//!   not declare `network` statements; build it with the constructors below.
//!
//! The namespace is **human-only** (§36.1): an `apply` whose manifest has a
//! `network` section needs a human caller, and a service-account token meets
//! `401` at the first network action.

use std::collections::{BTreeSet, HashSet};

use uuid::Uuid;

use super::plan::{Change, PlannedAction, Resolved, Target};
use super::{Done, Manifest, Step, StepError, action, lookup};
use crate::AxiamError;
use crate::management::models::{
    CreateNetworkReplyProfileRequest, CreateNetworkSegmentRequest, NetworkPolicyResponse,
    NetworkReplyProfile, NetworkReplyProfileInput, NetworkSegmentKind, NetworkSegmentResponse,
    RadiusServiceType, RadiusTerminationAction, ReplaceNetworkPolicyRequest,
    ReplaceNetworkReplyProfileRequest, ReplaceNetworkSegmentRequest,
};

// ---------------------------------------------------------------------------
// Specs
// ---------------------------------------------------------------------------

/// The `network` section of a [`ManagementManifest`](super::ManagementManifest).
///
/// Empty by default, and an empty section costs no request: a manifest without
/// one plans exactly as it did before contract 1.62.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct NetworkSpec {
    /// The tenant's `Session-Timeout` cap, when the manifest states it. At most
    /// one — the type cannot hold two, which is §27.6.2's "a manifest carries at
    /// most one". Never `Create` (the tenant's policy always exists, at
    /// version 0 until first written) and never pruned.
    pub policy: Option<NetworkPolicySpec>,
    /// Segments, in the order they are planned and written.
    pub segments: Vec<NetworkSegmentSpec>,
    /// Reply profiles, one per segment at most.
    pub profiles: Vec<NetworkProfileSpec>,
}

impl NetworkSpec {
    /// Whether the manifest states nothing about the network.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.policy.is_none() && self.segments.is_empty() && self.profiles.is_empty()
    }
}

/// The tenant's cap on a reply profile's `Session-Timeout` — a singleton.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkPolicySpec {
    /// `session_timeout_max_secs`, 300 to 86 400. This SDK does not check the
    /// range: the server's `400` is the answer (§36.3 rule 5).
    pub session_timeout_max_secs: i32,
}

impl NetworkPolicySpec {
    /// A cap of `session_timeout_max_secs` seconds.
    #[must_use]
    pub fn new(session_timeout_max_secs: i32) -> Self {
        Self {
            session_timeout_max_secs,
        }
    }
}

/// A network segment — natural key **site + kind + name**.
///
/// `site`, `kind` and `name` are the key and are never drift: a segment's kind
/// and place in the tree do not change (§36.3 rule 4). Every other member is a
/// field. An unset optional member is silent (§27.6 rule 3), and is carried
/// from the read when a segment is replaced; `Some(None)` on `rank` is a stated
/// "none", which leaves the key out of the body.
#[derive(Debug, Clone, PartialEq)]
pub struct NetworkSegmentSpec {
    /// Manifest-local identifier, referred to by a [`NetworkProfileSpec`].
    pub key: String,
    /// The site key (`site_key` on the wire). A single-site tenant uses `default`.
    pub site: String,
    /// `access` or `quarantine`, **the wire spelling** — the value the API reads
    /// and writes. There is no `zones` spelling here.
    pub kind: NetworkSegmentKind,
    /// The segment's name, unique within its site.
    pub name: String,
    /// The VLAN, 1 to 4094, unique within the site.
    pub vlan_id: i32,
    /// The placement rank of an `access` segment. `None` is silent;
    /// `Some(None)` states "none".
    pub rank: Option<Option<i32>>,
    /// The segment's `Filter-Id` envelope. Compared as a **set**; sent in the
    /// order stated. `None` is silent.
    pub filter_ids: Option<Vec<String>>,
    /// Whether the segment is a placement candidate. `None` is silent.
    pub enabled: Option<bool>,
}

impl NetworkSegmentSpec {
    /// A segment of any `kind`; the optional members are silent.
    pub fn new(
        key: impl Into<String>,
        site: impl Into<String>,
        kind: NetworkSegmentKind,
        name: impl Into<String>,
        vlan_id: i32,
    ) -> Self {
        Self {
            key: key.into(),
            site: site.into(),
            kind,
            name: name.into(),
            vlan_id,
            rank: None,
            filter_ids: None,
            enabled: None,
        }
    }

    /// An `access` segment, which needs a `rank`.
    pub fn access(
        key: impl Into<String>,
        site: impl Into<String>,
        name: impl Into<String>,
        vlan_id: i32,
        rank: i32,
    ) -> Self {
        Self::new(key, site, NetworkSegmentKind::Access, name, vlan_id).with_rank(rank)
    }

    /// A `quarantine` segment, which has no rank.
    pub fn quarantine(
        key: impl Into<String>,
        site: impl Into<String>,
        name: impl Into<String>,
        vlan_id: i32,
    ) -> Self {
        Self::new(key, site, NetworkSegmentKind::Quarantine, name, vlan_id)
    }

    /// State the placement rank.
    #[must_use]
    pub fn with_rank(mut self, rank: i32) -> Self {
        self.rank = Some(Some(rank));
        self
    }

    /// State that the segment has **no** rank (the key is left out of the body).
    #[must_use]
    pub fn with_no_rank(mut self) -> Self {
        self.rank = Some(None);
        self
    }

    /// State the `Filter-Id` envelope.
    #[must_use]
    pub fn with_filter_ids(
        mut self,
        filter_ids: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        self.filter_ids = Some(filter_ids.into_iter().map(Into::into).collect());
        self
    }

    /// State whether the segment is a placement candidate.
    #[must_use]
    pub fn with_enabled(mut self, enabled: bool) -> Self {
        self.enabled = Some(enabled);
        self
    }
}

/// A segment's reply profile — natural key **its segment**.
///
/// Compared with the *effective* profile the read returns (see the module
/// docs). An unset optional member is silent and carried from the read on an
/// `Update`; `Some(None)` states "none" and leaves the key out of the body.
#[derive(Debug, Clone, PartialEq)]
pub struct NetworkProfileSpec {
    /// The `key` of the [`NetworkSegmentSpec`] this profile belongs to. A key no
    /// segment spec of the manifest declares is refused before any request.
    pub segment: String,
    /// `Session-Timeout`, seconds. A value above the tenant's cap differs from
    /// the read and is refused by the server on `apply` (module docs).
    pub session_timeout_secs: i32,
    /// `Termination-Action`. `None` is silent.
    pub termination_action: Option<RadiusTerminationAction>,
    /// `Idle-Timeout`, seconds. `None` is silent; `Some(None)` states "none".
    pub idle_timeout_secs: Option<Option<i32>>,
    /// `Filter-Id`, one of the segment's `filter_ids`. `None` is silent;
    /// `Some(None)` states "none".
    pub filter_id: Option<Option<String>>,
    /// `Service-Type`. `None` is silent; `Some(None)` states "none".
    pub service_type: Option<Option<RadiusServiceType>>,
}

impl NetworkProfileSpec {
    /// A profile for the segment with key `segment`.
    pub fn new(segment: impl Into<String>, session_timeout_secs: i32) -> Self {
        Self {
            segment: segment.into(),
            session_timeout_secs,
            termination_action: None,
            idle_timeout_secs: None,
            filter_id: None,
            service_type: None,
        }
    }

    /// State `Termination-Action`.
    #[must_use]
    pub fn with_termination_action(mut self, action: RadiusTerminationAction) -> Self {
        self.termination_action = Some(action);
        self
    }

    /// State `Idle-Timeout`.
    #[must_use]
    pub fn with_idle_timeout_secs(mut self, secs: i32) -> Self {
        self.idle_timeout_secs = Some(Some(secs));
        self
    }

    /// State that the profile has **no** `Idle-Timeout`.
    #[must_use]
    pub fn with_no_idle_timeout(mut self) -> Self {
        self.idle_timeout_secs = Some(None);
        self
    }

    /// State `Filter-Id`.
    #[must_use]
    pub fn with_filter_id(mut self, filter_id: impl Into<String>) -> Self {
        self.filter_id = Some(Some(filter_id.into()));
        self
    }

    /// State that the profile has **no** `Filter-Id`.
    #[must_use]
    pub fn with_no_filter_id(mut self) -> Self {
        self.filter_id = Some(None);
        self
    }

    /// State `Service-Type`.
    #[must_use]
    pub fn with_service_type(mut self, service_type: RadiusServiceType) -> Self {
        self.service_type = Some(Some(service_type));
        self
    }

    /// State that the profile has **no** `Service-Type`.
    #[must_use]
    pub fn with_no_service_type(mut self) -> Self {
        self.service_type = Some(None);
        self
    }
}

// ---------------------------------------------------------------------------
// Validation (before any request)
// ---------------------------------------------------------------------------

/// The wire spelling of a kind, for natural-key comparison and summaries.
fn kind_wire(kind: &NetworkSegmentKind) -> &str {
    match kind {
        NetworkSegmentKind::Access => "access",
        NetworkSegmentKind::Quarantine => "quarantine",
        NetworkSegmentKind::Unknown(other) => other,
    }
}

/// §27.6.2 item 1: the refusals that need no request.
///
/// A natural key named twice, a profile for a segment the manifest does not
/// declare, two profiles for one segment, a segment that lists one Filter-Id
/// twice, a segment key declared twice. Each would otherwise surface halfway
/// through an `apply`, or never — the server cannot see a manifest.
pub(crate) fn validate(spec: &NetworkSpec, problems: &mut Vec<String>) {
    let mut keys: HashSet<&str> = HashSet::new();
    let mut natural: HashSet<(&str, &str, &str)> = HashSet::new();
    for segment in &spec.segments {
        if !keys.insert(segment.key.as_str()) {
            problems.push(format!(
                "network segment key {:?} is declared more than once",
                segment.key
            ));
        }
        if !natural.insert((
            segment.site.as_str(),
            kind_wire(&segment.kind),
            segment.name.as_str(),
        )) {
            problems.push(format!(
                "network segment {:?} (site {:?}, kind {:?}) is declared more than once; one \
                 natural key is one server row",
                segment.name,
                segment.site,
                kind_wire(&segment.kind)
            ));
        }
        if let Some(filter_ids) = &segment.filter_ids {
            let mut seen: HashSet<&str> = HashSet::new();
            for name in filter_ids {
                if !seen.insert(name.as_str()) {
                    problems.push(format!(
                        "network segment {:?} lists Filter-Id {name:?} more than once; \
                         filter_ids is a set",
                        segment.key
                    ));
                }
            }
        }
    }

    let mut profiled: HashSet<&str> = HashSet::new();
    for profile in &spec.profiles {
        if !keys.contains(profile.segment.as_str()) {
            problems.push(format!(
                "a network profile names segment {:?}, which no segment of the manifest declares",
                profile.segment
            ));
        }
        if !profiled.insert(profile.segment.as_str()) {
            problems.push(format!(
                "network segment {:?} has more than one profile; a segment has at most one",
                profile.segment
            ));
        }
    }
}

// ---------------------------------------------------------------------------
// What `plan` reads
// ---------------------------------------------------------------------------

/// The network state a plan is computed against.
#[derive(Debug, Default)]
pub(crate) struct NetworkSnapshot {
    pub(crate) policy: Option<NetworkPolicyResponse>,
    pub(crate) segments: Vec<NetworkSegmentResponse>,
    pub(crate) profiles: Vec<NetworkReplyProfile>,
}

impl<'c> Manifest<'c> {
    /// `get_policy`, `list_segments` and `list_profiles`, each only when the
    /// manifest has something to compare against it, each walked to exhaustion.
    pub(super) async fn read_network(
        &self,
        spec: &NetworkSpec,
    ) -> Result<NetworkSnapshot, AxiamError> {
        let network = self.client.network();
        let start = || crate::management::page::PageRequest::first(super::PLAN_PAGE);
        let policy = if spec.policy.is_some() {
            Some(network.get_policy().await?)
        } else {
            None
        };
        // A profile is matched to its segment, so profiles need the segments
        // too; segments alone need no profile read.
        let segments = if spec.segments.is_empty() && spec.profiles.is_empty() {
            Vec::new()
        } else {
            network.list_segments_all(None, start()).await?
        };
        let profiles = if spec.profiles.is_empty() {
            Vec::new()
        } else {
            network.list_profiles_all(start()).await?
        };
        Ok(NetworkSnapshot {
            policy,
            segments,
            profiles,
        })
    }
}

// ---------------------------------------------------------------------------
// Plan
// ---------------------------------------------------------------------------

/// One executable network step.
#[derive(Debug, Clone)]
pub(super) enum NetStep {
    /// `replace_policy`, carrying the policy's `version` as read.
    ReplacePolicy { body: ReplaceNetworkPolicyRequest },
    /// `create_segment`.
    CreateSegment {
        key: String,
        body: CreateNetworkSegmentRequest,
    },
    /// `replace_segment`: the full body, `version` as read.
    ReplaceSegment {
        key: String,
        id: Uuid,
        body: ReplaceNetworkSegmentRequest,
    },
    /// `create_profile`: the segment's id and version are taken at execution,
    /// from the read or from the segment write that preceded it.
    CreateProfile {
        segment: String,
        profile: NetworkReplyProfileInput,
    },
    /// `replace_profile`: `version` as read; the `segment_version` is taken at
    /// execution.
    ReplaceProfile {
        segment: String,
        version: i64,
        profile: NetworkReplyProfileInput,
    },
}

fn as_set(names: &[String]) -> BTreeSet<&str> {
    names.iter().map(String::as_str).collect()
}

fn change(drifted: bool) -> Change {
    if drifted {
        Change::Update
    } else {
        Change::NoChange
    }
}

/// Plan the `network` namespace and append its actions: the policy, then the
/// segments, then the profiles (§27.6.2 item 2).
pub(super) fn plan(
    spec: &NetworkSpec,
    snapshot: &NetworkSnapshot,
    resolved: &mut Resolved,
    steps: &mut Vec<(PlannedAction, Step)>,
) -> Result<(), AxiamError> {
    // The policy always exists, so it is `NoChange` or `Update`, never `Create`.
    if let Some(stated) = &spec.policy {
        let read = snapshot.policy.as_ref().ok_or_else(|| {
            AxiamError::network("internal: the network policy was not read although it is stated")
        })?;
        let drifted = read.session_timeout_max_secs != stated.session_timeout_max_secs;
        steps.push((
            action(
                change(drifted),
                Target::NetworkPolicy,
                "policy",
                format!(
                    "network policy: session_timeout_max_secs {}",
                    stated.session_timeout_max_secs
                ),
            ),
            if drifted {
                Step::Network(NetStep::ReplacePolicy {
                    body: ReplaceNetworkPolicyRequest {
                        session_timeout_max_secs: stated.session_timeout_max_secs,
                        version: read.version,
                    },
                })
            } else {
                Step::Noop
            },
        ));
    }

    for segment in &spec.segments {
        let summary = format!(
            "network segment {:?} ({} on site {:?})",
            segment.name,
            kind_wire(&segment.kind),
            segment.site
        );
        let found = snapshot.segments.iter().find(|r| {
            r.site_key == segment.site && r.kind == segment.kind && r.name == segment.name
        });
        match found {
            Some(read) => {
                resolved
                    .network_segments
                    .insert(segment.key.clone(), read.id);
                resolved
                    .network_segment_versions
                    .insert(segment.key.clone(), read.version);
                // Judged on the read: vlan, then each stated optional member.
                let drifted = read.vlan_id != segment.vlan_id
                    || segment
                        .rank
                        .as_ref()
                        .is_some_and(|stated| *stated != read.rank)
                    || segment
                        .filter_ids
                        .as_ref()
                        .is_some_and(|stated| as_set(stated) != as_set(&read.filter_ids))
                    || segment.enabled.is_some_and(|stated| stated != read.enabled);
                steps.push((
                    action(
                        change(drifted),
                        Target::NetworkSegment,
                        &segment.key,
                        summary,
                    ),
                    if drifted {
                        Step::Network(NetStep::ReplaceSegment {
                            key: segment.key.clone(),
                            id: read.id,
                            // Every member the manifest states replaces the
                            // read's; every one it does not is carried from
                            // it; a stated "none" is left out. `kind`,
                            // `site_key` and `name` are not in the body.
                            body: ReplaceNetworkSegmentRequest {
                                version: read.version,
                                vlan_id: segment.vlan_id,
                                filter_ids: segment
                                    .filter_ids
                                    .clone()
                                    .unwrap_or_else(|| read.filter_ids.clone()),
                                enabled: segment.enabled.unwrap_or(read.enabled),
                                rank: match segment.rank {
                                    Some(stated) => stated,
                                    None => read.rank,
                                },
                            },
                        })
                    } else {
                        Step::Noop
                    },
                ));
            }
            None => steps.push((
                action(
                    Change::Create,
                    Target::NetworkSegment,
                    &segment.key,
                    summary,
                ),
                Step::Network(NetStep::CreateSegment {
                    key: segment.key.clone(),
                    body: CreateNetworkSegmentRequest {
                        kind: segment.kind.clone(),
                        site_key: segment.site.clone(),
                        name: segment.name.clone(),
                        vlan_id: segment.vlan_id,
                        // Sent in the order the manifest states.
                        filter_ids: segment.filter_ids.clone(),
                        rank: segment.rank.flatten(),
                        enabled: segment.enabled,
                    },
                }),
            )),
        }
    }

    // Profiles follow their segments, in the segments' order, so `plan` is stable.
    for segment in &spec.segments {
        let Some(stated) = spec.profiles.iter().find(|p| p.segment == segment.key) else {
            continue;
        };
        let summary = format!(
            "network profile of segment {:?} (session_timeout_secs {})",
            segment.name, stated.session_timeout_secs
        );
        let read = resolved
            .network_segments
            .get(&segment.key)
            .and_then(|id| snapshot.profiles.iter().find(|p| p.segment_id == *id));
        match read {
            Some(read) => {
                let drifted = read.session_timeout_secs != stated.session_timeout_secs
                    || stated
                        .termination_action
                        .as_ref()
                        .is_some_and(|s| *s != read.termination_action)
                    || stated
                        .idle_timeout_secs
                        .is_some_and(|s| s != read.idle_timeout_secs)
                    || stated
                        .filter_id
                        .as_ref()
                        .is_some_and(|s| *s != read.filter_id)
                    || stated
                        .service_type
                        .as_ref()
                        .is_some_and(|s| *s != read.service_type);
                steps.push((
                    action(
                        change(drifted),
                        Target::NetworkProfile,
                        &segment.key,
                        summary,
                    ),
                    if drifted {
                        Step::Network(NetStep::ReplaceProfile {
                            segment: segment.key.clone(),
                            version: read.version,
                            profile: NetworkReplyProfileInput {
                                // Carried from the read: the dictionary the
                                // profile was validated against.
                                dictionary: Some(read.dictionary.clone()),
                                session_timeout_secs: stated.session_timeout_secs,
                                termination_action: Some(
                                    stated
                                        .termination_action
                                        .clone()
                                        .unwrap_or_else(|| read.termination_action.clone()),
                                ),
                                idle_timeout_secs: stated
                                    .idle_timeout_secs
                                    .unwrap_or(read.idle_timeout_secs),
                                filter_id: stated
                                    .filter_id
                                    .clone()
                                    .unwrap_or_else(|| read.filter_id.clone()),
                                service_type: stated
                                    .service_type
                                    .clone()
                                    .unwrap_or_else(|| read.service_type.clone()),
                            },
                        })
                    } else {
                        Step::Noop
                    },
                ));
            }
            None => steps.push((
                action(
                    Change::Create,
                    Target::NetworkProfile,
                    &segment.key,
                    summary,
                ),
                Step::Network(NetStep::CreateProfile {
                    segment: segment.key.clone(),
                    profile: NetworkReplyProfileInput {
                        dictionary: None,
                        session_timeout_secs: stated.session_timeout_secs,
                        termination_action: stated.termination_action.clone(),
                        idle_timeout_secs: stated.idle_timeout_secs.flatten(),
                        filter_id: stated.filter_id.clone().flatten(),
                        service_type: stated.service_type.clone().flatten(),
                    },
                }),
            )),
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Apply
// ---------------------------------------------------------------------------

impl<'c> Manifest<'c> {
    /// Run one network step. Every write is issued **once** and never retried;
    /// a refusal — `409` and its `reason_code`, or the write gate's `403` — is
    /// this action's failure, and the caller stops (§27.6 rule 7).
    pub(super) async fn run_network(
        &self,
        step: NetStep,
        resolved: &mut Resolved,
    ) -> Result<Done, StepError> {
        let network = self.client.network();
        match step {
            NetStep::ReplacePolicy { body } => {
                network.replace_policy(&body).await?;
            }
            NetStep::CreateSegment { key, body } => {
                let created = network.create_segment(&body).await?;
                resolved.network_segments.insert(key.clone(), created.id);
                // The version of **this write's response**: a profile that
                // follows is checked against it (§27.6.2 item 4).
                resolved
                    .network_segment_versions
                    .insert(key, created.version);
            }
            NetStep::ReplaceSegment { key, id, body } => {
                let replaced = network.replace_segment(id, &body).await?;
                resolved
                    .network_segment_versions
                    .insert(key, replaced.version);
            }
            NetStep::CreateProfile { segment, profile } => {
                let segment_id = lookup(&resolved.network_segments, &segment, "network segment")?;
                let segment_version = segment_version(resolved, &segment)?;
                network
                    .create_profile(&CreateNetworkReplyProfileRequest {
                        segment_id,
                        segment_version,
                        profile,
                    })
                    .await?;
            }
            NetStep::ReplaceProfile {
                segment,
                version,
                profile,
            } => {
                let segment_id = lookup(&resolved.network_segments, &segment, "network segment")?;
                let segment_version = segment_version(resolved, &segment)?;
                network
                    .replace_profile(
                        segment_id,
                        &ReplaceNetworkReplyProfileRequest {
                            profile,
                            segment_version,
                            version,
                        },
                    )
                    .await?;
            }
        }
        Ok(Done::Plain)
    }
}

/// The segment's `version` as last known: the read's, or the response of the
/// write this `apply` made to it.
fn segment_version(resolved: &Resolved, key: &str) -> Result<i64, AxiamError> {
    resolved
        .network_segment_versions
        .get(key)
        .copied()
        .ok_or_else(|| {
            AxiamError::network(format!(
                "internal: network segment key {key:?} has no version: it was consumed before \
                 the step that creates it ran"
            ))
        })
}
