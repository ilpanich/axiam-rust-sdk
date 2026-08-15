//! The reactor event registry and its mutable-field allow-lists
//! (CONTRACT.md §22.5, §22.7, §22.8).
//!
//! **Mirror, never import.** This is the same data as the server's
//! `EVENT_REGISTRY` in `crates/axiam-core/src/models/reactor.rs`, restated
//! here so a reactor author can name an event, ask what it may mutate, and
//! compute a registration's default failure policy without a network call.
//! The live copy is served at `GET /api/v1/reactors/events` and is the one an
//! admin UI SHOULD read; this table is the offline equivalent.
//!
//! # What is deliberately absent (§22.7 — normative MUST NOT)
//!
//! `authz.check`, `authz.check_batch` and `token.introspect` are **not
//! hookable** and this SDK does not present them as such — they appear in no
//! constant, no slice and no example here. A reactor round-trip is
//! milliseconds; the check path's budget is microseconds. An application that
//! needs external input on an authorization decision writes a **deny grant**,
//! which the engine evaluates in the hot path at hot-path cost.

/// What the server does when an interceptor produces no usable reply
/// (CONTRACT.md §22.8).
///
/// "No usable reply" is one closed set and every member takes the same path:
/// timeout, transport failure, a budget exhausted before this reactor was
/// reached, the in-flight cap, and every §22.4 rejection — including a valid
/// signature carrying a forbidden patch field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FailurePolicy {
    /// Deny the underlying operation, with an audited reason naming the
    /// failure. The safe default for veto-capable security hooks: a fraud
    /// check that cannot be reached has not passed.
    FailClosed,
    /// Proceed as if the reactor had replied `allow`. Appropriate only where
    /// the reactor *adds* something optional.
    FailOpen,
}

impl FailurePolicy {
    /// The wire string (`"fail_closed"` / `"fail_open"`).
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FailClosed => "fail_closed",
            Self::FailOpen => "fail_open",
        }
    }

    /// Parse a wire string, case- and whitespace-insensitively. `None` for
    /// anything else — an unknown policy is never silently read as the
    /// permissive one.
    pub fn from_wire(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "fail_closed" => Some(Self::FailClosed),
            "fail_open" => Some(Self::FailOpen),
            _ => None,
        }
    }
}

impl std::fmt::Display for FailurePolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// How a reactor participates in an event (CONTRACT.md §22.5, §22.9).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ReactorMode {
    /// Synchronous request/response: the server waits, and the reply can veto
    /// or mutate the operation within the event's allow-list.
    Intercept,
    /// Fire-and-forget observation. The server never waits and never reads a
    /// reply, so a listener cannot affect any outcome — and
    /// [`reactor_serve`](crate::amqp::reactor::reactor_serve) publishes
    /// nothing at all in this mode.
    Listen,
}

impl ReactorMode {
    /// The wire string (`"intercept"` / `"listen"`).
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Intercept => "intercept",
            Self::Listen => "listen",
        }
    }

    /// Parse a wire string, case- and whitespace-insensitively.
    pub fn from_wire(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "intercept" => Some(Self::Intercept),
            "listen" => Some(Self::Listen),
            _ => None,
        }
    }
}

impl std::fmt::Display for ReactorMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One hookable event: its name, what a reply may change, and what happens
/// when the reactor does not answer (CONTRACT.md §22.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReactorEventSpec {
    /// Wire name, and the second half of the routing key
    /// (`<tenant_id>.<event>`).
    pub name: &'static str,
    /// Whether an interceptor may register for this event at all. `false`
    /// means listen-only.
    pub interceptable: bool,
    /// Whether an interceptor's reply may carry a `patch`.
    pub mutable: bool,
    /// The **complete** allow-list. An entry ending in `.` is a namespace
    /// prefix — see [`ReactorEventSpec::patch_field_allowed`].
    pub mutable_fields: &'static [&'static str],
    /// The `failure_policy` a registration gets when it names none.
    pub default_failure_policy: FailurePolicy,
    /// One line, as the admin surface shows it.
    pub description: &'static str,
}

impl ReactorEventSpec {
    /// Whether `field` may appear in a `patch` for this event (§22.5).
    ///
    /// An allow-list entry ending in `.` is a **namespace prefix**, and it
    /// matches a field that starts with the entry and has **at least one
    /// character after the dot**. So `ext.` admits `ext.department` and
    /// `ext.a.b.c`, and refuses `ext.` itself (it names the namespace, not a
    /// claim), `ext` (not in the namespace), `extra` / `external_id` (a prefix
    /// match on the *string* is not a match on the namespace) and
    /// `evil.ext.department` (not a suffix match either).
    ///
    /// # This is a lookup, not a filter
    ///
    /// It exists so a handler can check its own patch before returning it.
    /// [`reactor_serve`](crate::amqp::reactor::reactor_serve) does **not**
    /// call it to prune a patch: §22.4 rule 1 and §22.10 rule 3 forbid
    /// filtering a handler's patch down to the allowed subset, because one
    /// forbidden key rejects the *whole* patch server-side and dropping it
    /// silently would leave the author believing a field was set when it was
    /// not.
    pub fn patch_field_allowed(&self, field: &str) -> bool {
        if !self.mutable {
            return false;
        }
        self.mutable_fields.iter().any(|allowed| {
            if allowed.ends_with('.') {
                field.len() > allowed.len() && field.starts_with(allowed)
            } else {
                field == *allowed
            }
        })
    }
}

/// Every hookable event in v1 — five of them (CONTRACT.md §22.5).
///
/// The order matches the server's `EVENT_REGISTRY`. Nothing on the
/// authorization hot path appears here, and nothing may be added to it
/// locally: an event outside the registry dispatches to nothing and resolves
/// to `allow`, which is what makes §22.7's exclusion structural rather than
/// advisory.
pub const EVENT_REGISTRY: &[ReactorEventSpec] = &[
    ReactorEventSpec {
        name: events::TOKEN_PRE_ISSUE,
        interceptable: true,
        mutable: true,
        // Custom claims only. `iss`, `sub`, `aud`, `exp`, `iat`, `nbf`, `jti`,
        // `scope`, `scp`, `azp`, `act` and `client_id` are all unreachable
        // because none of them begins with `ext.` — a hook that can rewrite
        // `sub` is a hook that can mint a token for anyone.
        mutable_fields: &["ext."],
        default_failure_policy: FailurePolicy::FailOpen,
        description: "Enrich or veto token issuance. May add claims under `ext.` only.",
    },
    ReactorEventSpec {
        name: events::LOGIN_POST_AUTH,
        interceptable: true,
        mutable: false,
        mutable_fields: &[],
        default_failure_policy: FailurePolicy::FailClosed,
        description: "After credentials verify, before session issuance: veto or require step-up MFA.",
    },
    ReactorEventSpec {
        name: events::USER_PRE_CREATE,
        interceptable: true,
        mutable: true,
        mutable_fields: &["username", "email", "metadata."],
        default_failure_policy: FailurePolicy::FailClosed,
        description: "Validate or normalize a new user's profile fields.",
    },
    ReactorEventSpec {
        name: events::USER_PRE_UPDATE,
        interceptable: true,
        mutable: true,
        mutable_fields: &["username", "email", "metadata."],
        default_failure_policy: FailurePolicy::FailClosed,
        description: "Validate or normalize a profile update.",
    },
    ReactorEventSpec {
        name: events::GRANT_PRE_ASSIGN,
        interceptable: true,
        mutable: false,
        mutable_fields: &[],
        default_failure_policy: FailurePolicy::FailClosed,
        description: "Veto a role or permission assignment (four-eyes workflows). Veto-only.",
    },
];

/// The five v1 event names as `&'static str` constants.
///
/// Handlers match on these rather than string literals so a typo is a compile
/// error rather than an event that silently never fires.
pub mod events {
    /// Before an access token is minted. Mutable: the `ext.` claim namespace.
    pub const TOKEN_PRE_ISSUE: &str = "token.pre_issue";
    /// After credentials verify, before a session is issued. Veto or step-up.
    ///
    /// Fires on password authentication, on SAML ACS and on the OIDC callback
    /// (§22.5, SEC-095). MFA completion and the WebAuthn
    /// `authenticate/finish` ceremony are **not** separate firings — both
    /// continue a login that was already gated at its first step.
    ///
    /// The federated paths have no step-up branch, so a `require_mfa` answer
    /// on those is **refused** (the sign-in fails) rather than silently
    /// dropped: a reactor that needs step-up there answers `deny` and drives
    /// enrolment out of band.
    pub const LOGIN_POST_AUTH: &str = "login.post_auth";
    /// Before a user row is written. Mutable: `username`, `email`,
    /// `metadata.`.
    pub const USER_PRE_CREATE: &str = "user.pre_create";
    /// Before a user row is updated. Mutable: `username`, `email`,
    /// `metadata.`.
    pub const USER_PRE_UPDATE: &str = "user.pre_update";
    /// Before a role or permission is assigned. Veto only.
    pub const GRANT_PRE_ASSIGN: &str = "grant.pre_assign";
}

/// Look an event up by wire name. `None` for anything outside the registry —
/// including the three hot-path operations §22.7 excludes.
pub fn event_spec(name: &str) -> Option<&'static ReactorEventSpec> {
    EVENT_REGISTRY.iter().find(|spec| spec.name == name)
}

/// The `failure_policy` a registration gets when it names none: **the
/// strictest default among its events** (CONTRACT.md §22.8).
///
/// A reactor registered for both `token.pre_issue` (open) and
/// `login.post_auth` (closed) can veto a login, so it inherits `fail_closed`
/// — **in either array order**. Reimplementing this as "take the first
/// event's default" would let the order of a JSON array decide whether an
/// unreachable fraud check passes.
///
/// An unknown event name contributes [`FailurePolicy::FailClosed`]: it will be
/// refused at registration anyway, and guessing `fail_open` for a name this
/// SDK does not recognise is the one guess that could weaken a decision. An
/// empty list is likewise `fail_closed` — a registration with no events is
/// invalid, not permissive.
pub fn default_failure_policy_for<I, S>(event_names: I) -> FailurePolicy
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut any = false;
    for name in event_names {
        any = true;
        match event_spec(name.as_ref()) {
            Some(spec) if spec.default_failure_policy == FailurePolicy::FailOpen => {}
            _ => return FailurePolicy::FailClosed,
        }
    }
    if any {
        FailurePolicy::FailOpen
    } else {
        FailurePolicy::FailClosed
    }
}

/// Default `timeout_ms` when a registration does not name one (§22.8).
pub const DEFAULT_TIMEOUT_MS: u32 = 500;

/// Lowest accepted `timeout_ms` at registration (§22.8). `0` is refused.
pub const MIN_TIMEOUT_MS: u32 = 1;

/// Hard ceiling on a registration's `timeout_ms`, and on the whole chain's
/// wall clock (§22.8). A reactor that needs longer than five seconds to answer
/// is not an interceptor, it is an outage.
pub const MAX_TIMEOUT_MS: u32 = 5_000;

/// Per-tenant in-flight interception cap, enforced server-side with a
/// non-blocking acquire (§22.8). Stated here so a reactor author sizing a
/// worker pool knows the ceiling they are working under.
pub const DEFAULT_MAX_IN_FLIGHT: u32 = 64;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_registry_holds_exactly_the_five_v1_events() {
        let names: Vec<&str> = EVENT_REGISTRY.iter().map(|spec| spec.name).collect();
        assert_eq!(
            names,
            vec![
                "token.pre_issue",
                "login.post_auth",
                "user.pre_create",
                "user.pre_update",
                "grant.pre_assign",
            ]
        );
    }

    /// §22.7 asserted on the data, not on a comment: the three hot-path
    /// operations are absent from every constant this SDK exposes.
    #[test]
    fn the_hot_path_operations_are_absent_from_the_registry() {
        for excluded in ["authz.check", "authz.check_batch", "token.introspect"] {
            assert!(
                event_spec(excluded).is_none(),
                "{excluded} must not be hookable (§22.7)"
            );
            assert!(EVENT_REGISTRY.iter().all(|spec| spec.name != excluded));
        }
    }

    #[test]
    fn token_pre_issue_admits_the_ext_namespace_and_nothing_else() {
        let spec = event_spec("token.pre_issue").unwrap();
        for allowed in ["ext.department", "ext.a.b.c", "ext.x"] {
            assert!(
                spec.patch_field_allowed(allowed),
                "{allowed} must be allowed"
            );
        }
        for refused in [
            "ext.",
            "ext",
            "extra",
            "external_id",
            "evil.ext.department",
            "iss",
            "sub",
            "aud",
            "exp",
            "iat",
            "nbf",
            "jti",
            "scope",
            "scp",
            "azp",
            "act",
            "client_id",
        ] {
            assert!(
                !spec.patch_field_allowed(refused),
                "{refused} must be refused"
            );
        }
    }

    #[test]
    fn the_user_events_admit_profile_fields_and_refuse_credentials() {
        for event in ["user.pre_create", "user.pre_update"] {
            let spec = event_spec(event).unwrap();
            for allowed in ["username", "email", "metadata.source", "metadata.a.b"] {
                assert!(spec.patch_field_allowed(allowed), "{event}: {allowed}");
            }
            for refused in [
                "password",
                "password_hash",
                "tenant_id",
                "id",
                "roles",
                "is_admin",
                "metadata",
                "metadata.",
            ] {
                assert!(!spec.patch_field_allowed(refused), "{event}: {refused}");
            }
        }
    }

    #[test]
    fn the_veto_only_events_accept_no_patch_field_at_all() {
        for event in ["login.post_auth", "grant.pre_assign"] {
            let spec = event_spec(event).unwrap();
            assert!(!spec.mutable);
            assert!(spec.mutable_fields.is_empty());
            for field in ["anything", "username", "ext.department", "require_mfa"] {
                assert!(!spec.patch_field_allowed(field), "{event}: {field}");
            }
        }
    }

    /// §22.8: the strictest default wins, **in either array order**.
    #[test]
    fn the_strictest_default_failure_policy_wins_regardless_of_order() {
        assert_eq!(
            default_failure_policy_for(["token.pre_issue"]),
            FailurePolicy::FailOpen
        );
        assert_eq!(
            default_failure_policy_for(["token.pre_issue", "login.post_auth"]),
            FailurePolicy::FailClosed
        );
        assert_eq!(
            default_failure_policy_for(["login.post_auth", "token.pre_issue"]),
            FailurePolicy::FailClosed
        );
        // An unknown name, and the empty list, are both fail_closed — never
        // the permissive guess.
        assert_eq!(
            default_failure_policy_for(["token.pre_issue", "authz.check"]),
            FailurePolicy::FailClosed
        );
        assert_eq!(
            default_failure_policy_for(Vec::<&str>::new()),
            FailurePolicy::FailClosed
        );
    }

    #[test]
    fn wire_strings_round_trip() {
        for policy in [FailurePolicy::FailOpen, FailurePolicy::FailClosed] {
            assert_eq!(FailurePolicy::from_wire(policy.as_str()), Some(policy));
        }
        assert_eq!(
            FailurePolicy::from_wire("  FAIL_OPEN "),
            Some(FailurePolicy::FailOpen)
        );
        assert_eq!(FailurePolicy::from_wire("open"), None);

        for mode in [ReactorMode::Intercept, ReactorMode::Listen] {
            assert_eq!(ReactorMode::from_wire(mode.as_str()), Some(mode));
        }
        assert_eq!(ReactorMode::from_wire("observe"), None);
    }

    #[test]
    fn the_timeout_bounds_match_the_contract() {
        assert_eq!(DEFAULT_TIMEOUT_MS, 500);
        assert_eq!(MIN_TIMEOUT_MS, 1);
        assert_eq!(MAX_TIMEOUT_MS, 5_000);
        assert_eq!(DEFAULT_MAX_IN_FLIGHT, 64);
    }
}
