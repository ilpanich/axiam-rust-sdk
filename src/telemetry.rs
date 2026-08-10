//! Telemetry hooks — CONTRACT.md §19.
//!
//! An optional callback surface so callers can wire OpenTelemetry, Prometheus,
//! or a log line **without this crate depending on any of them**. No hook
//! installed costs one `Option` check per request; the OTel adapter lives in
//! `examples/`, where it costs nothing to anyone who does not want it.
//!
//! # What a hook may not do
//!
//! Two rules from §19.2 are load-bearing and are enforced here rather than
//! left to documentation:
//!
//! * **A hook cannot break the SDK.** [`TelemetrySink::emit`] is invoked
//!   through [`std::panic::catch_unwind`], so a panicking hook cannot fail an
//!   authorization check. Telemetry is not permitted that power.
//! * **No secrets, ever.** [`TelemetryEvent`] carries a closed set of fields
//!   and there is no escape hatch for arbitrary data. This surface exists to be
//!   shipped to a metrics backend, which is the last place a bearer token
//!   should land — so the type system, not a review comment, is what keeps
//!   tokens out of it.

use std::time::Duration;

/// Why a request finished.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// A 2xx response.
    Success,
    /// Any error — transport, or a status the SDK maps to an error.
    Failure,
}

/// Whether this caller performed a §9 refresh or waited on another's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefreshRole {
    /// This caller won the single-flight race and performed the refresh.
    Leader,
    /// This caller waited on an in-flight refresh started by someone else.
    Follower,
}

/// A telemetry event (§19.1).
///
/// The variants carry a **fixed** field list. Notably absent, and deliberately
/// so: tokens, request bodies, response bodies, headers, and anything wrapped
/// in [`crate::Sensitive`].
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum TelemetryEvent {
    /// Emitted before an outbound call leaves the SDK.
    RequestStart {
        /// Canonical operation name, e.g. `check_access`.
        operation: &'static str,
        /// HTTP method.
        method: &'static str,
        /// Path **template** — `/api/v1/authz/check`, never a URL with ids
        /// substituted in. A metric label carrying a UUID is a cardinality
        /// bomb, so the template is what the SDK reports.
        path_template: &'static str,
        /// 1 for the first attempt, incrementing per §16 retry.
        attempt: u32,
    },
    /// Emitted after a call completes, success or failure.
    RequestEnd {
        /// Canonical operation name.
        operation: &'static str,
        /// HTTP method.
        method: &'static str,
        /// Path template — see [`TelemetryEvent::RequestStart`].
        path_template: &'static str,
        /// Attempt this event closes.
        attempt: u32,
        /// HTTP status, or `None` when the call never got a response.
        status: Option<u16>,
        /// Wall-clock duration of this attempt.
        duration: Duration,
        /// Success or failure.
        outcome: Outcome,
    },
    /// Emitted before each §16 retry wait.
    ///
    /// §16.5 requires this: a retried-then-succeeded operation is otherwise
    /// invisible — the caller sees a slow success and no signal that the server
    /// is failing. That silence is the standing objection to automatic retry,
    /// and this event is what answers it.
    Retry {
        /// Canonical operation name.
        operation: &'static str,
        /// The attempt that just failed.
        attempt: u32,
        /// The delay about to be taken, after jitter and any `Retry-After`.
        delay: Duration,
        /// A short, redacted description of the failure that triggered the
        /// retry. Never carries a token — see [`crate::AxiamError`], whose
        /// `Display` is already redacted per §2.
        reason: String,
    },
    /// Emitted around a §9 single-flight refresh.
    Refresh {
        /// Whether this caller performed the refresh or waited on another's.
        role: RefreshRole,
        /// How long the refresh (or the wait for one) took.
        duration: Duration,
    },
    /// Emitted at construction, once per caller-supplied setting the SDK
    /// clamped (§19.1, §19.2 rule 6).
    ///
    /// Two places in the contract require clamping rather than rejecting:
    /// §16.1's attempt cap, base delay and delay cap, and §17.1 rule 2's memo
    /// TTL. Both clamps are right — rejecting would break a caller whose
    /// configuration was merely optimistic, and honoring would let one client
    /// become the herd §16 exists to prevent. Doing it *silently* is the part
    /// that is wrong.
    ///
    /// An operator who set a 60-second memo TTL believes they have one. They
    /// have five seconds, and their staleness reasoning is off by a factor of
    /// twelve with nothing anywhere to say so.
    ///
    /// Not emitted for a value already within its limit: an event that fires
    /// when nothing happened trains its reader to ignore it.
    ConfigClamped {
        /// The setting's name, e.g. `decision_memo_ttl`.
        setting: &'static str,
        /// The value the caller asked for, rendered.
        requested: String,
        /// The value actually in force, rendered.
        effective: String,
        /// The §-reference for the limit, e.g. `§17.1 rule 2`.
        contract_reference: &'static str,
    },
}

/// A caller-supplied telemetry sink (§19).
///
/// Implementations must be cheap and non-blocking: hooks are invoked on the
/// calling path, and §19.2 rule 4 makes buffering the caller's job so they can
/// pick the policy. A hook that blocks slows down every request that fires it.
pub trait TelemetrySink: Send + Sync + 'static {
    /// Receive one event. Must not block; must not panic (a panic is caught,
    /// but relying on that is not a design).
    fn emit(&self, event: &TelemetryEvent);
}

impl<F> TelemetrySink for F
where
    F: Fn(&TelemetryEvent) + Send + Sync + 'static,
{
    fn emit(&self, event: &TelemetryEvent) {
        self(event)
    }
}

/// Internal dispatcher. `None` is the overwhelmingly common case and costs one
/// branch.
#[derive(Clone, Default)]
pub(crate) struct Telemetry {
    sink: Option<std::sync::Arc<dyn TelemetrySink>>,
}

impl std::fmt::Debug for Telemetry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Telemetry")
            .field("installed", &self.sink.is_some())
            .finish()
    }
}

impl Telemetry {
    pub(crate) fn new(sink: Option<std::sync::Arc<dyn TelemetrySink>>) -> Self {
        Self { sink }
    }

    /// Emit an event, swallowing any panic the caller's hook raises.
    ///
    /// §19.2 rule 2: telemetry is not permitted to fail an authorization check.
    /// The panic is caught and dropped; the operation continues as though no
    /// hook were installed.
    pub(crate) fn emit(&self, event: TelemetryEvent) {
        let Some(sink) = self.sink.as_ref() else {
            return;
        };
        // `AssertUnwindSafe` is correct here: we own nothing across the call
        // that a panic could leave inconsistent — the event is borrowed and
        // dropped either way, and the sink is behind a shared reference whose
        // own invariants are its implementor's problem.
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| sink.emit(&event)));
    }
}
