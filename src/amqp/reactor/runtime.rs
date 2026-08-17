//! `reactor_serve` — the SDK reactor runtime (CONTRACT.md §22.10).
//!
//! One helper. It connects (TLS per §8b and §6.1), consumes the
//! **server-declared** queue, and for each delivery: verifies §8 v2
//! (`key_version`, MAC, freshness, nonce), decodes the event, dispatches to a
//! user-supplied handler, then signs and publishes the reply. It maintains
//! reconnect, and it drains the in-flight event on shutdown per §18.
//!
//! # The four rules on the helper itself (§22.10)
//!
//! 1. **It declares no topology.** There is no `queue_declare`,
//!    `exchange_declare` or `queue_bind` anywhere in this module, and the
//!    transport seam it is written against exposes no such operation, so the
//!    rule is structural rather than remembered. A reactor that can bind is a
//!    reactor that can bind itself to `*.token.pre_issue`.
//! 2. **It fails closed on its own errors.** A handler that panics, a payload
//!    that will not decode, a window that has already closed — every one of
//!    them produces **no reply**, letting the server's `failure_policy`
//!    decide. Answering `allow` on behalf of a handler that crashed would
//!    override the operator's `fail_closed` setting from inside the library.
//! 3. **It does not filter a patch.** A handler's patch is published exactly
//!    as returned, forbidden keys and all (§22.4 rule 1).
//! 4. **It honours `timeout_ms`.** The handler runs under the event's own
//!    window, and a reply whose window has closed is abandoned rather than
//!    published late.

use std::collections::BTreeMap;
use std::future::Future;
use std::panic::AssertUnwindSafe;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use chrono::Utc;
use futures_util::{FutureExt, StreamExt};
use lapin::BasicProperties;
use lapin::options::{BasicAckOptions, BasicConsumeOptions, BasicNackOptions, BasicPublishOptions};
use lapin::types::FieldTable;
use uuid::Uuid;

use crate::amqp::consumer::ReplayGuard;
use crate::amqp::reactor::protocol::{
    DEFAULT_FRESHNESS_SKEW_SECS, EventRejection, ReactorEvent, ReactorReply, ReplyDecision,
    queue_name, verify_event,
};
use crate::amqp::reactor::registry::{ReactorMode, event_spec, events};
use crate::error::AxiamError;
use crate::sensitive::Sensitive;
use crate::telemetry::{Outcome, Telemetry, TelemetryEvent, TelemetrySink};

/// Telemetry operation name for one reactor dispatch (§19.1).
const TELEMETRY_OPERATION: &str = "reactor_dispatch";

/// Longest wait between reconnect attempts. Deliberately the same 5 s as
/// §16.1's delay cap: a reactor that has been unreachable for five seconds has
/// already had every in-flight interception resolved by its `failure_policy`,
/// so waiting longer buys nothing.
const RECONNECT_DELAY_CAP: Duration = Duration::from_secs(5);

/// First reconnect wait, doubled per consecutive failure up to the cap.
const RECONNECT_BASE_DELAY: Duration = Duration::from_millis(200);

// ---------------------------------------------------------------------------
// The handler's answer
// ---------------------------------------------------------------------------

/// What a handler decided about one event (CONTRACT.md §22.10).
///
/// Three answers plus one absence. `Allow`, `Deny` and `Mutate` are the three
/// the wire carries; [`ReactorDecision::Abstain`] is the *absence* of a reply,
/// which the server resolves through the registration's `failure_policy`
/// (§22.8) exactly as it resolves a timeout.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReactorDecision {
    /// Proceed unchanged.
    Allow {
        /// Proceed **only after step-up authentication**. `login.post_auth`
        /// only — it is not a separate decision value, and sending it on any
        /// other event is refused (§22.4 rule 3).
        require_mfa: bool,
    },
    /// Refuse. A deny with no reason still denies; the reason is for the audit
    /// trail, and the server substitutes `"denied by reactor"` when absent.
    Deny {
        /// Audited reason.
        reason: Option<String>,
    },
    /// Proceed, applying `patch` — a flat `string → string` map.
    ///
    /// The patch is published **unfiltered**: one forbidden key rejects the
    /// whole patch server-side, and pruning it here would leave you believing
    /// a field was set when it was dropped (§22.4 rule 1). Check it yourself
    /// with
    /// [`ReactorEventSpec::patch_field_allowed`](super::registry::ReactorEventSpec::patch_field_allowed)
    /// if you want to know before you send.
    Mutate {
        /// The fields to set.
        patch: BTreeMap<String, String>,
    },
    /// Publish nothing at all.
    ///
    /// The right answer when the window has already closed (§22.3: shed load
    /// rather than answer into a closed window) or when the handler cannot
    /// decide. It is **not** a quiet `allow`: the server applies the
    /// registration's `failure_policy`, which for every event except
    /// `token.pre_issue` defaults to `fail_closed`.
    Abstain,
}

impl ReactorDecision {
    /// Proceed unchanged.
    pub fn allow() -> Self {
        Self::Allow { require_mfa: false }
    }

    /// Proceed, but demand step-up authentication first. `login.post_auth`
    /// only.
    pub fn require_step_up() -> Self {
        Self::Allow { require_mfa: true }
    }

    /// Refuse, with a reason for the audit trail.
    pub fn deny(reason: impl Into<String>) -> Self {
        Self::Deny {
            reason: Some(reason.into()),
        }
    }

    /// Refuse without a reason. Still denies; the audit record reads
    /// `"denied by reactor"`.
    pub fn deny_unexplained() -> Self {
        Self::Deny { reason: None }
    }

    /// Proceed, applying a patch.
    pub fn mutate<K, V, I>(patch: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
    {
        Self::Mutate {
            patch: patch
                .into_iter()
                .map(|(k, v)| (k.into(), v.into()))
                .collect(),
        }
    }

    /// Publish nothing; let the registration's `failure_policy` decide.
    pub fn abstain() -> Self {
        Self::Abstain
    }
}

// ---------------------------------------------------------------------------
// Shutdown (§18)
// ---------------------------------------------------------------------------

/// A deterministic stop signal for [`reactor_serve`] (CONTRACT.md §18).
///
/// Triggering it stops the runtime from taking **new** deliveries. The
/// delivery already in flight runs to completion — handler, signature, publish
/// — before the loop returns, so shutdown drains rather than truncates. It is
/// idempotent: triggering an already-triggered signal is a no-op, and a
/// runtime that has already returned stays returned.
#[derive(Clone, Debug)]
pub struct ReactorShutdown {
    tx: Arc<tokio::sync::watch::Sender<bool>>,
}

impl ReactorShutdown {
    /// A fresh, untriggered signal.
    pub fn new() -> Self {
        let (tx, _rx) = tokio::sync::watch::channel(false);
        Self { tx: Arc::new(tx) }
    }

    /// Ask the runtime to stop after the current delivery. Idempotent.
    ///
    /// `send_replace` rather than `send`: the latter is a no-op when no
    /// receiver is listening, which would make a signal raised *before*
    /// [`reactor_serve`] subscribes silently vanish — the one ordering a
    /// caller cannot control.
    pub fn trigger(&self) {
        self.tx.send_replace(true);
    }

    /// Whether [`ReactorShutdown::trigger`] has been called.
    pub fn is_triggered(&self) -> bool {
        *self.tx.borrow()
    }

    fn subscribe(&self) -> tokio::sync::watch::Receiver<bool> {
        self.tx.subscribe()
    }
}

impl Default for ReactorShutdown {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// How to reach the broker and which reactor this process is
/// (CONTRACT.md §22.1, §22.9).
///
/// Build one with [`ReactorConfig::builder`].
pub struct ReactorConfig {
    amqp_url: String,
    tls: crate::amqp::transport::AmqpTlsConfig,
    tenant_id: Uuid,
    reactor_id: Uuid,
    signing_key: Sensitive<Vec<u8>>,
    mode: ReactorMode,
    freshness_skew: chrono::Duration,
    telemetry: Telemetry,
    shutdown: Option<ReactorShutdown>,
    reconnect: bool,
}

impl std::fmt::Debug for ReactorConfig {
    /// §22.12: the tenant AMQP signing key is a credential and MUST NOT appear
    /// in a diagnostic, so it is named but never rendered.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReactorConfig")
            .field("amqp_url", &self.amqp_url)
            .field("tenant_id", &self.tenant_id)
            .field("reactor_id", &self.reactor_id)
            .field("signing_key", &self.signing_key)
            .field("mode", &self.mode)
            .field("freshness_skew_secs", &self.freshness_skew.num_seconds())
            .field("reconnect", &self.reconnect)
            .finish()
    }
}

impl ReactorConfig {
    /// Start building a configuration.
    pub fn builder() -> ReactorConfigBuilder {
        ReactorConfigBuilder::default()
    }

    /// The queue this reactor consumes — `axiam.reactor.q.<tenant>.<reactor>`,
    /// **declared by the server** (§22.1).
    pub fn queue(&self) -> String {
        queue_name(self.tenant_id, self.reactor_id)
    }
}

/// Builder for [`ReactorConfig`].
#[derive(Default)]
pub struct ReactorConfigBuilder {
    amqp_url: Option<String>,
    tls: crate::amqp::transport::AmqpTlsConfig,
    tenant_id: Option<Uuid>,
    reactor_id: Option<Uuid>,
    signing_key: Option<Sensitive<Vec<u8>>>,
    mode: Option<ReactorMode>,
    freshness_skew: Option<Duration>,
    telemetry: Option<Arc<dyn TelemetrySink>>,
    shutdown: Option<ReactorShutdown>,
    reconnect: Option<bool>,
}

impl std::fmt::Debug for ReactorConfigBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReactorConfigBuilder")
            .field("amqp_url", &self.amqp_url)
            .field("tenant_id", &self.tenant_id)
            .field("reactor_id", &self.reactor_id)
            .field("signing_key_set", &self.signing_key.is_some())
            .field("mode", &self.mode)
            .finish_non_exhaustive()
    }
}

impl ReactorConfigBuilder {
    /// Broker URL. Must be `amqps://` (§8b rules 1 and 5) — there is no
    /// verification-skip switch, no plaintext fallback, and no loopback
    /// exception.
    pub fn amqp_url(mut self, url: impl Into<String>) -> Self {
        self.amqp_url = Some(url.into());
        self
    }

    /// TLS material for the broker connection (§8b rules 2 and 3).
    ///
    /// Optional, and omitting it weakens nothing: the URL must be `amqps://`
    /// either way, and with no material supplied the broker is verified against
    /// the platform root store. Set
    /// [`ca_cert_pem`](crate::amqp::AmqpTlsConfig::ca_cert_pem) when the broker
    /// certificate is issued by a private CA — the common case for an
    /// in-cluster broker, and the reason rule 2 is a MUST.
    ///
    /// ```no_run
    /// use axiam_sdk::amqp::AmqpTlsConfig;
    ///
    /// let tls = AmqpTlsConfig {
    ///     ca_cert_pem: Some(std::fs::read_to_string("/etc/axiam/broker-ca.pem")?),
    ///     ..Default::default()
    /// };
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn tls(mut self, tls: crate::amqp::transport::AmqpTlsConfig) -> Self {
        self.tls = tls;
        self
    }

    /// The tenant this reactor is registered in. Both halves of the queue name
    /// and the reply's `tenant_id` come from it.
    pub fn tenant_id(mut self, tenant_id: Uuid) -> Self {
        self.tenant_id = Some(tenant_id);
        self
    }

    /// This reactor's registration id, from `POST /api/v1/reactors` (§22.9).
    ///
    /// It names the **one** queue this process may consume. Passing another
    /// reactor's id is not a supported way to share a runtime: §22.1 forbids
    /// deriving a queue name for a reactor other than the one you are.
    pub fn reactor_id(mut self, reactor_id: Uuid) -> Self {
        self.reactor_id = Some(reactor_id);
        self
    }

    /// The tenant's HKDF-derived AMQP subkey (§8 v2, §22.2) — **not** the
    /// master key. Obtain it from the AXIAM management API for this tenant;
    /// hard-coding one is prohibited.
    ///
    /// It is wrapped in [`Sensitive`] (§22.12) so it cannot be logged, printed
    /// or serialized by accident.
    pub fn signing_key(mut self, key: Sensitive<Vec<u8>>) -> Self {
        self.signing_key = Some(key);
        self
    }

    /// `intercept` (default) or `listen`.
    ///
    /// In [`ReactorMode::Listen`] the runtime publishes **nothing**: a
    /// listener cannot affect any outcome, and §22.5 requires the handler be
    /// written idempotently because a redelivery after a broker hiccup is
    /// normal.
    pub fn mode(mut self, mode: ReactorMode) -> Self {
        self.mode = Some(mode);
        self
    }

    /// Override the ±300 s `issued_at` acceptance window. The same window,
    /// doubled, bounds how long a `nonce` is remembered for replay detection.
    pub fn freshness_skew(mut self, skew: Duration) -> Self {
        self.freshness_skew = Some(skew);
        self
    }

    /// Install a §19 telemetry sink. One `RequestStart`/`RequestEnd` pair is
    /// emitted per dispatch, with the registry event name as the path
    /// template — a bounded label set, never a correlation id.
    pub fn telemetry_hook<S: TelemetrySink>(mut self, sink: S) -> Self {
        self.telemetry = Some(Arc::new(sink));
        self
    }

    /// Install a §18 shutdown signal. Without one, [`reactor_serve`] runs
    /// until the broker connection ends and reconnect is exhausted or off.
    pub fn shutdown(mut self, shutdown: ReactorShutdown) -> Self {
        self.shutdown = Some(shutdown);
        self
    }

    /// Reconnect after a dropped broker connection (default `true`).
    ///
    /// Turn it off to make [`reactor_serve`] return the first time the
    /// connection ends — useful when a supervisor already owns restarts.
    pub fn reconnect(mut self, reconnect: bool) -> Self {
        self.reconnect = Some(reconnect);
        self
    }

    /// Finish. Fails with [`AxiamError::Network`] when a required field is
    /// missing or the broker URL is not TLS-protected.
    pub fn build(self) -> Result<ReactorConfig, AxiamError> {
        let amqp_url = self
            .amqp_url
            .ok_or_else(|| AxiamError::network("reactor config requires an amqp_url"))?;
        // §8b rules 1 and 5: reactors connect across a trust boundary, and a
        // reactor's reply is an instruction to allow, deny or rewrite a token.
        // HMAC does not substitute for TLS and TLS does not substitute for
        // HMAC.
        //
        // This used to be wrapped in `if let Ok(parsed) = url::Url::parse(..)`,
        // which meant a URL that failed to parse skipped the check entirely.
        // `ensure_amqps` has no such hole: an input nobody can parse is the one
        // to refuse, not the one to wave through.
        crate::amqp::transport::ensure_amqps(&amqp_url)?;
        self.tls.validate()?;
        let freshness_skew = self
            .freshness_skew
            .and_then(|d| chrono::Duration::from_std(d).ok())
            .unwrap_or_else(|| chrono::Duration::seconds(DEFAULT_FRESHNESS_SKEW_SECS));

        Ok(ReactorConfig {
            amqp_url,
            tls: self.tls,
            tenant_id: self
                .tenant_id
                .ok_or_else(|| AxiamError::network("reactor config requires a tenant_id"))?,
            reactor_id: self
                .reactor_id
                .ok_or_else(|| AxiamError::network("reactor config requires a reactor_id"))?,
            signing_key: self
                .signing_key
                .ok_or_else(|| AxiamError::network("reactor config requires a signing_key"))?,
            mode: self.mode.unwrap_or(ReactorMode::Intercept),
            freshness_skew,
            telemetry: Telemetry::new(self.telemetry),
            shutdown: self.shutdown,
            reconnect: self.reconnect.unwrap_or(true),
        })
    }
}

// ---------------------------------------------------------------------------
// The transport seam
// ---------------------------------------------------------------------------

/// The operations one delivery needs — **and no others**.
///
/// There is deliberately no `declare_queue`, `declare_exchange` or `bind` on
/// this trait: §22.1's "actors consume; they never declare topology" is
/// enforced by the seam's shape, so it cannot be violated by a later edit that
/// forgets the rule. `lapin::message::Delivery` (plus the channel it arrived
/// on) implements it for real; tests provide a recording fake that never
/// touches a broker.
pub(crate) trait ReactorDelivery {
    /// Raw message bytes.
    fn data(&self) -> &[u8];
    /// The AMQP `reply_to` basic property — the reply queue to publish to.
    fn reply_to(&self) -> Option<&str>;
    /// The AMQP `correlation_id` basic property, echoed on the reply. What the
    /// server authenticates is the `correlation_id` *inside the signed body*;
    /// this is the RPC convention that gets the message back to the right
    /// consumer.
    fn property_correlation_id(&self) -> Option<&str>;
    /// Acknowledge.
    fn ack(&self) -> impl Future<Output = ()> + Send;
    /// Negatively acknowledge. `requeue` is `false` on every failure path in
    /// this module, so an unverifiable delivery cannot loop the queue.
    fn nack(&self, requeue: bool) -> impl Future<Output = ()> + Send;
    /// Publish a signed reply to `reply_to`, echoing `correlation_id`.
    fn publish_reply(
        &self,
        reply_to: &str,
        correlation_id: &str,
        body: Vec<u8>,
    ) -> impl Future<Output = Result<(), String>> + Send;
}

/// A live delivery: the lapin message plus the channel it arrived on, which is
/// what the reply is published through.
struct LapinDelivery {
    delivery: lapin::message::Delivery,
    channel: lapin::Channel,
    reply_to: Option<String>,
    correlation_id: Option<String>,
}

impl ReactorDelivery for LapinDelivery {
    fn data(&self) -> &[u8] {
        &self.delivery.data
    }

    fn reply_to(&self) -> Option<&str> {
        self.reply_to.as_deref()
    }

    fn property_correlation_id(&self) -> Option<&str> {
        self.correlation_id.as_deref()
    }

    async fn ack(&self) {
        let _ = self.delivery.acker.ack(BasicAckOptions::default()).await;
    }

    async fn nack(&self, requeue: bool) {
        let _ = self
            .delivery
            .acker
            .nack(BasicNackOptions {
                requeue,
                ..Default::default()
            })
            .await;
    }

    async fn publish_reply(
        &self,
        reply_to: &str,
        correlation_id: &str,
        body: Vec<u8>,
    ) -> Result<(), String> {
        // The default exchange, routed by queue name — standard AMQP RPC. The
        // reactor publishes to a queue the *server* owns; it declares nothing.
        self.channel
            .basic_publish(
                "".into(),
                reply_to.into(),
                BasicPublishOptions::default(),
                &body,
                BasicProperties::default()
                    .with_correlation_id(correlation_id.into())
                    .with_content_type("application/json".into()),
            )
            .await
            .map_err(|e| format!("failed to publish reactor reply: {e}"))?
            .await
            .map_err(|e| format!("reactor reply was not confirmed: {e}"))?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Per-delivery dispatch
// ---------------------------------------------------------------------------

/// Everything one dispatch needs that does not come from the delivery.
pub(crate) struct DispatchContext {
    pub(crate) signing_key: Sensitive<Vec<u8>>,
    pub(crate) tenant_id: Uuid,
    pub(crate) mode: ReactorMode,
    pub(crate) freshness_skew: chrono::Duration,
    pub(crate) replay: ReplayGuard,
    pub(crate) telemetry: Telemetry,
}

/// Verify one delivery, dispatch it to `handler`, and publish the answer.
///
/// Every path that cannot produce a **usable** reply publishes nothing at all,
/// which is what hands the decision to the registration's `failure_policy`
/// (§22.8) rather than to this library.
pub(crate) async fn dispatch_delivery<D, F, Fut>(delivery: &D, ctx: &DispatchContext, handler: &F)
where
    D: ReactorDelivery,
    F: Fn(ReactorEvent) -> Fut + Send + Sync,
    Fut: Future<Output = ReactorDecision> + Send,
{
    let Some(body) = parse_body(delivery.data()) else {
        tracing::warn!(
            target: "axiam_sdk::security",
            "reactor delivery body failed JSON parse; nacking without requeue"
        );
        delivery.nack(false).await;
        return;
    };

    // §22.3, in order: key_version, MAC, freshness. Only then is anything in
    // the payload looked at.
    let event = match verify_event(
        &body,
        ctx.signing_key.expose(),
        Utc::now(),
        ctx.freshness_skew,
    ) {
        Ok(event) => event,
        Err(rejection) => {
            reject(delivery, &rejection.to_string()).await;
            return;
        }
    };

    // The fourth §22.3 check: the nonce seen-set.
    if !ctx.replay.check_and_record_nonce(&event.nonce.to_string()) {
        reject(delivery, &EventRejection::ReplayedNonce.to_string()).await;
        return;
    }

    // A queue is per-tenant and the subkey is per-tenant, so this can only
    // fire on a misconfiguration — but a reactor answering for a tenant it was
    // not configured as is exactly the confusion §22.1 refuses to allow.
    if event.tenant_id != ctx.tenant_id {
        reject(
            delivery,
            "event names a different tenant than this reactor is configured for",
        )
        .await;
        return;
    }

    let started = Instant::now();
    let deadline = started + event.timeout();
    let event_label = static_event_label(&event.event);
    ctx.telemetry.emit(TelemetryEvent::RequestStart {
        operation: TELEMETRY_OPERATION,
        method: "AMQP",
        path_template: event_label,
        attempt: 1,
    });

    // §22.10 rules 2 and 4 together: the handler runs inside the window the
    // server declared, and a panic is caught rather than propagated — both
    // resolve to *no reply*, never to a synthesized `allow`.
    let outcome = tokio::time::timeout(
        event.timeout(),
        AssertUnwindSafe(handler(event.clone())).catch_unwind(),
    )
    .await;

    let decision = match outcome {
        Ok(Ok(decision)) => Some(decision),
        Ok(Err(_panic)) => {
            tracing::error!(
                target: "axiam_sdk::security",
                event = %event.event,
                correlation_id = %event.correlation_id,
                "reactor handler panicked; publishing no reply so the registration's failure_policy decides"
            );
            None
        }
        Err(_elapsed) => {
            tracing::warn!(
                target: "axiam_sdk::security",
                event = %event.event,
                correlation_id = %event.correlation_id,
                timeout_ms = event.timeout_ms,
                "reactor handler exceeded the event's timeout_ms; publishing no reply"
            );
            None
        }
    };

    ctx.telemetry.emit(TelemetryEvent::RequestEnd {
        operation: TELEMETRY_OPERATION,
        method: "AMQP",
        path_template: event_label,
        attempt: 1,
        status: None,
        duration: started.elapsed(),
        outcome: if decision.is_some() {
            Outcome::Success
        } else {
            Outcome::Failure
        },
    });

    // A listener never publishes: the server does not wait for it and does not
    // read a reply, so anything it sent would be noise on a queue nobody is
    // draining (§22.5).
    if ctx.mode == ReactorMode::Listen {
        delivery.ack().await;
        return;
    }

    if let Some(decision) = decision {
        publish_answer(delivery, ctx, &event, decision, deadline).await;
    }

    // The event verified and was consumed. Acking is what keeps
    // `last_seen_at` moving — a heartbeat derived from real work (§22.9) —
    // and requeueing an event whose correlation is already spent would only
    // re-run a handler against a window that has closed.
    delivery.ack().await;
}

/// Build, sign and publish the reply for `decision`, or publish nothing and
/// say why.
async fn publish_answer<D: ReactorDelivery>(
    delivery: &D,
    ctx: &DispatchContext,
    event: &ReactorEvent,
    decision: ReactorDecision,
    deadline: Instant,
) {
    let (wire_decision, reason, patch, require_mfa) = match decision {
        ReactorDecision::Abstain => {
            tracing::debug!(
                target: "axiam_sdk::reactor",
                event = %event.event,
                correlation_id = %event.correlation_id,
                "handler abstained; the registration's failure_policy decides"
            );
            return;
        }
        ReactorDecision::Allow { require_mfa } => (ReplyDecision::Allow, None, None, require_mfa),
        ReactorDecision::Deny { reason } => (ReplyDecision::Deny, reason, None, false),
        ReactorDecision::Mutate { patch } => {
            if patch.is_empty() {
                // `mutate` with an empty patch is `malformed_mutation`
                // server-side (§22.4 row 10). Refusing it here is not
                // filtering — no field is being dropped, the reply has no
                // content to carry.
                tracing::error!(
                    target: "axiam_sdk::reactor",
                    event = %event.event,
                    correlation_id = %event.correlation_id,
                    "handler returned a mutation with an empty patch (malformed_mutation); publishing no reply"
                );
                return;
            }
            // Published UNFILTERED (§22.4 rule 1 / §22.10 rule 3). One
            // forbidden key rejects the whole patch server-side, and pruning
            // it here would leave the author believing a field was set.
            (ReplyDecision::Mutate, None, Some(patch), false)
        }
    };

    // §22.4 row 7 / rule 3: `require_mfa` rides on `allow`, on
    // `login.post_auth`, and nowhere else. §22.13 allows an SDK to refuse this
    // client-side; doing so puts the mistake in the reactor author's log
    // instead of only in the server's audit trail.
    if require_mfa && event.event != events::LOGIN_POST_AUTH {
        tracing::error!(
            target: "axiam_sdk::reactor",
            event = %event.event,
            correlation_id = %event.correlation_id,
            "require_mfa is only valid on login.post_auth (require_mfa_not_supported); publishing no reply"
        );
        return;
    }

    let mut reply = ReactorReply::answering(event, wire_decision, Utc::now());
    reply.reason = reason;
    reply.patch = patch;
    reply.require_mfa = require_mfa;

    if reply.sign(ctx.signing_key.expose()).is_err() {
        tracing::error!(
            target: "axiam_sdk::reactor",
            correlation_id = %event.correlation_id,
            "reactor reply could not be serialized for signing; publishing no reply"
        );
        return;
    }
    let Ok(body) = serde_json::to_vec(&reply) else {
        tracing::error!(
            target: "axiam_sdk::reactor",
            correlation_id = %event.correlation_id,
            "reactor reply could not be serialized; publishing no reply"
        );
        return;
    };

    // §22.3 / §22.10 rule 4: a late reply is discarded, and the CPU spent
    // producing it was spent for nothing. Do not spend the network on it too.
    if Instant::now() >= deadline {
        tracing::warn!(
            target: "axiam_sdk::reactor",
            event = %event.event,
            correlation_id = %event.correlation_id,
            timeout_ms = event.timeout_ms,
            "the event's window closed before the reply was ready; not publishing"
        );
        return;
    }

    let Some(reply_to) = delivery.reply_to() else {
        tracing::warn!(
            target: "axiam_sdk::reactor",
            correlation_id = %event.correlation_id,
            "delivery carried no reply_to property; nowhere to publish the reply"
        );
        return;
    };
    // The AMQP property is the RPC convention; what the server authenticates
    // is the correlation_id inside the signed body, which
    // `ReactorReply::answering` copied from the event.
    let property_correlation = delivery
        .property_correlation_id()
        .map(str::to_owned)
        .unwrap_or_else(|| event.correlation_id.to_string());

    if let Err(message) = delivery
        .publish_reply(reply_to, &property_correlation, body)
        .await
    {
        tracing::warn!(
            target: "axiam_sdk::reactor",
            correlation_id = %event.correlation_id,
            error = %message,
            "reactor reply could not be published"
        );
    }
}

fn parse_body(data: &[u8]) -> Option<serde_json::Value> {
    serde_json::from_slice(data).ok()
}

/// Nack without requeue and log the reason. The reason never carries the
/// signing key, and never the received or expected MAC.
async fn reject<D: ReactorDelivery>(delivery: &D, reason: &str) {
    tracing::warn!(
        target: "axiam_sdk::security",
        reason,
        "reactor event rejected; nacking without requeue"
    );
    delivery.nack(false).await;
}

/// Map a wire event name onto the registry's `&'static str`, so a telemetry
/// label can never be an attacker-chosen string or a cardinality bomb.
fn static_event_label(name: &str) -> &'static str {
    event_spec(name).map_or("unknown_event", |spec| spec.name)
}

// ---------------------------------------------------------------------------
// reactor_serve
// ---------------------------------------------------------------------------

/// Run a reactor: consume the server-declared queue, answer every event
/// (CONTRACT.md §22.10).
///
/// `handler` is called **only** with an event whose `key_version`, MAC,
/// freshness and nonce have all passed. It returns one of
/// [`ReactorDecision`]'s three answers, or [`ReactorDecision::Abstain`] to
/// publish nothing.
///
/// Returns when the [`ReactorShutdown`] signal fires (draining the delivery in
/// flight), or when the broker connection ends and `reconnect(false)` was set.
///
/// # Example
///
/// ```no_run
/// use axiam_sdk::Sensitive;
/// use axiam_sdk::amqp::reactor::{
///     ReactorConfig, ReactorDecision, events, reactor_serve,
/// };
///
/// # async fn run(subkey: Sensitive<Vec<u8>>) -> Result<(), axiam_sdk::AxiamError> {
/// let config = ReactorConfig::builder()
///     .amqp_url("amqps://reactor:secret@broker.example.com:5671")
///     .tenant_id("11111111-1111-1111-1111-111111111111".parse().unwrap())
///     .reactor_id("99999999-9999-9999-9999-999999999999".parse().unwrap())
///     .signing_key(subkey)
///     .build()?;
///
/// reactor_serve(config, |event| async move {
///     match event.event.as_str() {
///         events::TOKEN_PRE_ISSUE => {
///             ReactorDecision::mutate([("ext.cost_center", "42")])
///         }
///         events::LOGIN_POST_AUTH => ReactorDecision::allow(),
///         _ => ReactorDecision::allow(),
///     }
/// })
/// .await
/// # }
/// ```
///
/// # Security
///
/// The `payload`, `patch`, `reason` and `decision` are tenant business data:
/// readable by design (a handler that cannot inspect the event cannot decide
/// anything) but **not** logged at info level by this runtime, and they should
/// not be logged at info level by yours either (§22.12). The signing key is
/// [`Sensitive`] and never appears in a log line, a reconnect diagnostic, or
/// an error payload.
pub async fn reactor_serve<F, Fut>(config: ReactorConfig, handler: F) -> Result<(), AxiamError>
where
    F: Fn(ReactorEvent) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = ReactorDecision> + Send,
{
    let queue = config.queue();
    let ctx = DispatchContext {
        signing_key: config.signing_key,
        tenant_id: config.tenant_id,
        mode: config.mode,
        freshness_skew: config.freshness_skew,
        replay: ReplayGuard::new(config.freshness_skew),
        telemetry: config.telemetry,
    };
    let mut shutdown_rx = config.shutdown.as_ref().map(ReactorShutdown::subscribe);
    let mut consecutive_failures: u32 = 0;

    loop {
        if shutdown_triggered(shutdown_rx.as_ref()) {
            return Ok(());
        }

        match serve_once(
            &config.amqp_url,
            &config.tls,
            &queue,
            &ctx,
            &handler,
            shutdown_rx.as_mut(),
        )
        .await
        {
            Ok(ServeExit::ShutdownRequested) => return Ok(()),
            Ok(ServeExit::StreamEnded) | Err(_) if !config.reconnect => {
                // A caller who owns restarts asked for exactly one attempt.
                return Ok(());
            }
            Ok(ServeExit::StreamEnded) => {
                consecutive_failures = consecutive_failures.saturating_add(1);
            }
            Err(error) => {
                // The URL, the queue and the failure — never the key (§22.12).
                tracing::warn!(
                    target: "axiam_sdk::reactor",
                    queue = %queue,
                    error = %error,
                    "reactor broker connection failed; will reconnect"
                );
                consecutive_failures = consecutive_failures.saturating_add(1);
            }
        }

        let delay = reconnect_delay(consecutive_failures);
        if let Some(rx) = shutdown_rx.as_mut() {
            tokio::select! {
                _ = tokio::time::sleep(delay) => {}
                _ = rx.changed() => return Ok(()),
            }
        } else {
            tokio::time::sleep(delay).await;
        }
    }
}

/// Why one connection's consume loop ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ServeExit {
    /// The §18 signal fired; the in-flight delivery was drained first.
    ShutdownRequested,
    /// The broker closed the consumer.
    StreamEnded,
}

/// The consume loop, over any stream of deliveries.
///
/// Generic over the stream so the §18 drain guarantee is testable without a
/// broker: the shutdown branch is only ever polled **between** deliveries, so
/// a signal arriving while [`dispatch_delivery`] is awaiting finishes that
/// delivery — handler, signature and publish — before the loop returns.
pub(crate) async fn consume_loop<D, S, E, F, Fut>(
    stream: &mut S,
    ctx: &DispatchContext,
    handler: &F,
    mut shutdown_rx: Option<&mut tokio::sync::watch::Receiver<bool>>,
) -> ServeExit
where
    D: ReactorDelivery,
    E: std::fmt::Display,
    S: futures_util::Stream<Item = Result<D, E>> + Unpin,
    F: Fn(ReactorEvent) -> Fut + Send + Sync,
    Fut: Future<Output = ReactorDecision> + Send,
{
    loop {
        // A signal raised before this loop was reached (or between two
        // deliveries) is honoured here rather than waited for: `changed()`
        // reports a *transition*, and a receiver that has already observed
        // the transition would otherwise wait forever.
        if shutdown_rx.as_ref().is_some_and(|rx| *rx.borrow()) {
            return ServeExit::ShutdownRequested;
        }

        let next = match shutdown_rx.as_mut() {
            Some(rx) => {
                tokio::select! {
                    biased;
                    _ = rx.changed() => return ServeExit::ShutdownRequested,
                    next = stream.next() => next,
                }
            }
            None => stream.next().await,
        };

        let Some(item) = next else {
            return ServeExit::StreamEnded;
        };

        match item {
            // Awaited to completion: a shutdown that arrives now drains this
            // delivery rather than truncating it (§18).
            Ok(delivery) => dispatch_delivery(&delivery, ctx, handler).await,
            Err(e) => {
                tracing::warn!(target: "axiam_sdk::reactor", error = %e, "reactor consumer stream error");
                return ServeExit::StreamEnded;
            }
        }
    }
}

async fn serve_once<F, Fut>(
    amqp_url: &str,
    tls: &crate::amqp::transport::AmqpTlsConfig,
    queue: &str,
    ctx: &DispatchContext,
    handler: &F,
    shutdown_rx: Option<&mut tokio::sync::watch::Receiver<bool>>,
) -> Result<ServeExit, AxiamError>
where
    F: Fn(ReactorEvent) -> Fut + Send + Sync,
    Fut: Future<Output = ReactorDecision> + Send,
{
    // §8b: the scheme and the TLS material are both re-checked here, not only
    // in the builder. `serve_once` is the reconnect loop's body, so this is the
    // call that actually opens every socket a reactor ever opens.
    let connection = crate::amqp::transport::connect_amqps(amqp_url, tls).await?;
    let channel = connection
        .create_channel()
        .await
        .map_err(|e| AxiamError::network(format!("failed to create AMQP channel: {e}")))?;

    // NOTE: there is no queue_declare / exchange_declare / queue_bind here,
    // and there must never be one. §22.1: the server declares the exchange,
    // the queue and the bindings; actors consume.
    let consumer = channel
        .basic_consume(
            queue.into(),
            "axiam-sdk-reactor".into(),
            BasicConsumeOptions::default(),
            FieldTable::default(),
        )
        .await
        .map_err(|e| AxiamError::network(format!("failed to start reactor consumer: {e}")))?;

    let reply_channel = channel.clone();
    let mut stream = consumer.map(move |result| {
        result.map(|delivery| {
            let reply_to = delivery
                .properties
                .reply_to()
                .as_ref()
                .map(|s| s.to_string());
            let correlation_id = delivery
                .properties
                .correlation_id()
                .as_ref()
                .map(|s| s.to_string());
            LapinDelivery {
                delivery,
                channel: reply_channel.clone(),
                reply_to,
                correlation_id,
            }
        })
    });

    Ok(consume_loop(&mut stream, ctx, handler, shutdown_rx).await)
}

fn shutdown_triggered(rx: Option<&tokio::sync::watch::Receiver<bool>>) -> bool {
    rx.is_some_and(|rx| *rx.borrow())
}

/// Exponential backoff with full jitter, capped at [`RECONNECT_DELAY_CAP`].
///
/// The jitter source is the wall clock's sub-second component rather than a
/// CSPRNG: this decides how long to wait before redialling a broker, which is
/// a thundering-herd concern and not a security one, and reaching for
/// `getrandom` here would add a dependency to the `amqp` feature for a
/// non-security purpose.
fn reconnect_delay(consecutive_failures: u32) -> Duration {
    let exponent = consecutive_failures.saturating_sub(1).min(16);
    let backoff = RECONNECT_BASE_DELAY
        .saturating_mul(1u32 << exponent)
        .min(RECONNECT_DELAY_CAP);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::from(d.subsec_nanos()));
    let millis = backoff.as_millis().max(1) as u64;
    Duration::from_millis(nanos % millis)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use crate::amqp::reactor::protocol::ReactorEvent;
    use crate::amqp::test_log::{captured_log, init_recording_subscriber};

    // -----------------------------------------------------------------
    // Fixtures and fakes
    // -----------------------------------------------------------------

    /// The §22.13 vectors — same file, same master key, tenant and derived
    /// subkey as the §8 fixture.
    fn fixture() -> serde_json::Value {
        serde_json::from_str(include_str!(
            "../../../testdata/reactor_v2_reference_vectors.json"
        ))
        .expect("reactor reference vectors parse")
    }

    fn subkey() -> Vec<u8> {
        let hex = fixture()["hkdf"]["derived_subkey_hex"]
            .as_str()
            .expect("derived_subkey_hex")
            .to_owned();
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }

    fn fixture_tenant() -> Uuid {
        fixture()["tenant_id"].as_str().unwrap().parse().unwrap()
    }

    /// Build and sign an event exactly as the server would.
    fn signed_event_bytes(
        key: &[u8],
        tenant_id: Uuid,
        event: &str,
        timeout_ms: u32,
        issued_at: chrono::DateTime<Utc>,
        key_version: u8,
    ) -> Vec<u8> {
        let mut message = ReactorEvent {
            tenant_id,
            event: event.to_owned(),
            correlation_id: Uuid::new_v4(),
            payload: serde_json::json!({"sub": "alice"}),
            timeout_ms,
            key_version,
            nonce: Uuid::new_v4(),
            issued_at,
            hmac_signature: None,
        };
        let canonical = serde_json::to_vec(&message).unwrap();
        message.hmac_signature = Some(crate::amqp::hmac::sign_payload(key, &canonical));
        serde_json::to_vec(&message).unwrap()
    }

    fn fresh_event_bytes(key: &[u8], event: &str, timeout_ms: u32) -> Vec<u8> {
        signed_event_bytes(key, fixture_tenant(), event, timeout_ms, Utc::now(), 2)
    }

    /// A recording delivery. It offers exactly the operations §22.1 permits —
    /// there is nothing here that could declare a queue, an exchange or a
    /// binding, because the trait it implements offers no such thing.
    /// `(reply_to, correlation_id property, body)` for one published reply.
    type PublishedReply = (String, String, Vec<u8>);

    #[derive(Clone)]
    struct FakeDelivery {
        data: Vec<u8>,
        reply_to: Option<String>,
        correlation_id: Option<String>,
        published: Arc<Mutex<Vec<PublishedReply>>>,
        acked: Arc<AtomicUsize>,
        nacked_no_requeue: Arc<AtomicUsize>,
        nacked_requeue: Arc<AtomicUsize>,
    }

    impl FakeDelivery {
        fn new(data: Vec<u8>) -> Self {
            Self {
                data,
                reply_to: Some("amq.rabbitmq.reply-to.abc".to_owned()),
                correlation_id: Some("property-correlation".to_owned()),
                published: Arc::new(Mutex::new(Vec::new())),
                acked: Arc::new(AtomicUsize::new(0)),
                nacked_no_requeue: Arc::new(AtomicUsize::new(0)),
                nacked_requeue: Arc::new(AtomicUsize::new(0)),
            }
        }

        fn without_reply_to(mut self) -> Self {
            self.reply_to = None;
            self
        }

        fn published(&self) -> Vec<PublishedReply> {
            self.published.lock().unwrap().clone()
        }

        fn published_reply(&self) -> ReactorReply {
            let all = self.published();
            assert_eq!(all.len(), 1, "expected exactly one published reply");
            serde_json::from_slice(&all[0].2).expect("the reply is JSON")
        }
    }

    impl ReactorDelivery for FakeDelivery {
        fn data(&self) -> &[u8] {
            &self.data
        }

        fn reply_to(&self) -> Option<&str> {
            self.reply_to.as_deref()
        }

        fn property_correlation_id(&self) -> Option<&str> {
            self.correlation_id.as_deref()
        }

        async fn ack(&self) {
            self.acked.fetch_add(1, Ordering::SeqCst);
        }

        async fn nack(&self, requeue: bool) {
            if requeue {
                self.nacked_requeue.fetch_add(1, Ordering::SeqCst);
            } else {
                self.nacked_no_requeue.fetch_add(1, Ordering::SeqCst);
            }
        }

        async fn publish_reply(
            &self,
            reply_to: &str,
            correlation_id: &str,
            body: Vec<u8>,
        ) -> Result<(), String> {
            self.published.lock().unwrap().push((
                reply_to.to_owned(),
                correlation_id.to_owned(),
                body,
            ));
            Ok(())
        }
    }

    fn context(key: Vec<u8>, mode: ReactorMode) -> DispatchContext {
        let skew = chrono::Duration::seconds(DEFAULT_FRESHNESS_SKEW_SECS);
        DispatchContext {
            signing_key: Sensitive::new(key),
            tenant_id: fixture_tenant(),
            mode,
            freshness_skew: skew,
            replay: ReplayGuard::new(skew),
            telemetry: Telemetry::default(),
        }
    }

    fn intercept_context() -> DispatchContext {
        context(subkey(), ReactorMode::Intercept)
    }

    /// A handler that records how many times it ran and answers `decision`.
    fn counting_handler(
        calls: Arc<AtomicUsize>,
        decision: ReactorDecision,
    ) -> impl Fn(ReactorEvent) -> std::pin::Pin<Box<dyn Future<Output = ReactorDecision> + Send>>
    + Send
    + Sync {
        move |_event| {
            let calls = Arc::clone(&calls);
            let decision = decision.clone();
            Box::pin(async move {
                calls.fetch_add(1, Ordering::SeqCst);
                decision
            })
        }
    }

    // -----------------------------------------------------------------
    // The happy path
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn a_verified_event_reaches_the_handler_and_its_reply_is_signed() {
        let key = subkey();
        let delivery = FakeDelivery::new(fresh_event_bytes(&key, events::LOGIN_POST_AUTH, 5_000));
        let calls = Arc::new(AtomicUsize::new(0));

        dispatch_delivery(
            &delivery,
            &intercept_context(),
            &counting_handler(Arc::clone(&calls), ReactorDecision::allow()),
        )
        .await;

        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(delivery.acked.load(Ordering::SeqCst), 1);
        assert_eq!(delivery.nacked_no_requeue.load(Ordering::SeqCst), 0);

        let reply = delivery.published_reply();
        assert_eq!(reply.decision, ReplyDecision::Allow);
        assert!(reply.signature_valid(&key), "the reply must be signed");
        assert_eq!(reply.key_version, 2);
        assert!(!reply.require_mfa);

        // The correlation_id inside the SIGNED BODY is what the server
        // authenticates; the AMQP property is only the RPC convention.
        let event: ReactorEvent = serde_json::from_slice(&delivery.data).unwrap();
        assert_eq!(reply.correlation_id, event.correlation_id);
        assert_eq!(reply.tenant_id, event.tenant_id);
        assert_eq!(reply.event, event.event);
        assert_eq!(delivery.published()[0].0, "amq.rabbitmq.reply-to.abc");
        assert_eq!(delivery.published()[0].1, "property-correlation");
    }

    // -----------------------------------------------------------------
    // §22.10 rule 2 — fail closed on our own errors
    // -----------------------------------------------------------------

    /// §22.13: a handler that throws produces **no reply** — assert zero
    /// published messages, not an `allow`.
    #[tokio::test]
    async fn a_handler_that_panics_publishes_nothing_rather_than_an_allow() {
        let key = subkey();
        let delivery = FakeDelivery::new(fresh_event_bytes(&key, events::LOGIN_POST_AUTH, 5_000));

        dispatch_delivery(&delivery, &intercept_context(), &|_event| async {
            panic!("handler blew up");
        })
        .await;

        assert!(
            delivery.published().is_empty(),
            "a crashed handler must not have an `allow` synthesized on its behalf"
        );
        assert_eq!(delivery.acked.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn a_handler_that_outruns_timeout_ms_publishes_nothing() {
        let key = subkey();
        // The server declared a 1 ms window; the handler takes far longer.
        let delivery = FakeDelivery::new(fresh_event_bytes(&key, events::LOGIN_POST_AUTH, 1));

        dispatch_delivery(&delivery, &intercept_context(), &|_event| async {
            tokio::time::sleep(Duration::from_millis(80)).await;
            ReactorDecision::allow()
        })
        .await;

        assert!(
            delivery.published().is_empty(),
            "a late reply is discarded anyway; publishing it spends the network for nothing"
        );
    }

    #[tokio::test]
    async fn an_abstaining_handler_publishes_nothing() {
        let key = subkey();
        let delivery = FakeDelivery::new(fresh_event_bytes(&key, events::GRANT_PRE_ASSIGN, 5_000));

        dispatch_delivery(&delivery, &intercept_context(), &|_event| async {
            ReactorDecision::abstain()
        })
        .await;

        assert!(delivery.published().is_empty());
        assert_eq!(delivery.acked.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn an_empty_mutation_publishes_nothing() {
        let key = subkey();
        let delivery = FakeDelivery::new(fresh_event_bytes(&key, events::TOKEN_PRE_ISSUE, 5_000));

        dispatch_delivery(&delivery, &intercept_context(), &|_event| async {
            ReactorDecision::Mutate {
                patch: BTreeMap::new(),
            }
        })
        .await;

        assert!(delivery.published().is_empty(), "malformed_mutation");
    }

    // -----------------------------------------------------------------
    // §22.10 rule 3 — no filtering
    // -----------------------------------------------------------------

    /// §22.13: a mutation containing a forbidden key is sent **unfiltered**.
    /// Assert the SDK did not silently drop `sub` from a `token.pre_issue`
    /// patch.
    #[tokio::test]
    async fn a_forbidden_patch_key_is_published_unfiltered() {
        let key = subkey();
        let delivery = FakeDelivery::new(fresh_event_bytes(&key, events::TOKEN_PRE_ISSUE, 5_000));

        dispatch_delivery(&delivery, &intercept_context(), &|_event| async {
            ReactorDecision::mutate([("ext.department", "eng"), ("sub", "root")])
        })
        .await;

        let reply = delivery.published_reply();
        assert_eq!(reply.decision, ReplyDecision::Mutate);
        assert!(reply.signature_valid(&key));
        let patch = reply.patch.expect("a patch");
        assert_eq!(patch.get("sub").map(String::as_str), Some("root"));
        assert_eq!(patch.get("ext.department").map(String::as_str), Some("eng"));
    }

    // -----------------------------------------------------------------
    // §22.4 rule 3 — require_mfa
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn require_mfa_rides_on_allow_for_login_post_auth() {
        let key = subkey();
        let delivery = FakeDelivery::new(fresh_event_bytes(&key, events::LOGIN_POST_AUTH, 5_000));

        dispatch_delivery(&delivery, &intercept_context(), &|_event| async {
            ReactorDecision::require_step_up()
        })
        .await;

        let reply = delivery.published_reply();
        assert_eq!(reply.decision, ReplyDecision::Allow);
        assert!(reply.require_mfa);
        assert!(reply.signature_valid(&key));
    }

    /// §22.13 permits an SDK to refuse this client-side. This one does, which
    /// puts the mistake in the reactor author's log rather than only in the
    /// server's audit trail.
    #[tokio::test]
    async fn require_mfa_on_any_other_event_is_refused_client_side() {
        let key = subkey();
        for event in [
            events::TOKEN_PRE_ISSUE,
            events::USER_PRE_CREATE,
            events::GRANT_PRE_ASSIGN,
        ] {
            let delivery = FakeDelivery::new(fresh_event_bytes(&key, event, 5_000));
            dispatch_delivery(&delivery, &intercept_context(), &|_event| async {
                ReactorDecision::require_step_up()
            })
            .await;
            assert!(
                delivery.published().is_empty(),
                "{event}: require_mfa_not_supported"
            );
        }
    }

    // -----------------------------------------------------------------
    // §22.5 — listeners
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn a_listener_never_publishes_a_reply() {
        let key = subkey();
        let delivery = FakeDelivery::new(fresh_event_bytes(&key, events::LOGIN_POST_AUTH, 5_000));
        let calls = Arc::new(AtomicUsize::new(0));

        dispatch_delivery(
            &delivery,
            &context(key, ReactorMode::Listen),
            // Even a handler that answers `deny` cannot affect the outcome.
            &counting_handler(Arc::clone(&calls), ReactorDecision::deny("nope")),
        )
        .await;

        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "the handler still observes"
        );
        assert!(delivery.published().is_empty());
        assert_eq!(delivery.acked.load(Ordering::SeqCst), 1);
    }

    // -----------------------------------------------------------------
    // §22.3 — verification before the handler ever runs
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn a_bad_signature_never_reaches_the_handler() {
        let key = subkey();
        let mut body: serde_json::Value =
            serde_json::from_slice(&fresh_event_bytes(&key, events::LOGIN_POST_AUTH, 5_000))
                .unwrap();
        body["hmac_signature"] = serde_json::Value::String("00".repeat(32));
        let delivery = FakeDelivery::new(serde_json::to_vec(&body).unwrap());
        let calls = Arc::new(AtomicUsize::new(0));

        dispatch_delivery(
            &delivery,
            &intercept_context(),
            &counting_handler(Arc::clone(&calls), ReactorDecision::allow()),
        )
        .await;

        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert!(delivery.published().is_empty());
        assert_eq!(delivery.nacked_no_requeue.load(Ordering::SeqCst), 1);
        assert_eq!(delivery.nacked_requeue.load(Ordering::SeqCst), 0);
        assert_eq!(delivery.acked.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn a_v1_event_is_refused_and_a_stale_one_too() {
        let key = subkey();
        let calls = Arc::new(AtomicUsize::new(0));

        let v1 = FakeDelivery::new(signed_event_bytes(
            &key,
            fixture_tenant(),
            events::LOGIN_POST_AUTH,
            5_000,
            Utc::now(),
            1,
        ));
        dispatch_delivery(
            &v1,
            &intercept_context(),
            &counting_handler(Arc::clone(&calls), ReactorDecision::allow()),
        )
        .await;
        assert_eq!(v1.nacked_no_requeue.load(Ordering::SeqCst), 1);

        for offset in [
            chrono::Duration::seconds(DEFAULT_FRESHNESS_SKEW_SECS + 5),
            -chrono::Duration::seconds(DEFAULT_FRESHNESS_SKEW_SECS + 5),
        ] {
            let stale = FakeDelivery::new(signed_event_bytes(
                &key,
                fixture_tenant(),
                events::LOGIN_POST_AUTH,
                5_000,
                Utc::now() - offset,
                2,
            ));
            dispatch_delivery(
                &stale,
                &intercept_context(),
                &counting_handler(Arc::clone(&calls), ReactorDecision::allow()),
            )
            .await;
            assert_eq!(stale.nacked_no_requeue.load(Ordering::SeqCst), 1);
        }

        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "no unverified event may reach user code"
        );
    }

    #[tokio::test]
    async fn a_replayed_nonce_is_refused_the_second_time() {
        let key = subkey();
        let bytes = fresh_event_bytes(&key, events::LOGIN_POST_AUTH, 5_000);
        let ctx = intercept_context();
        let calls = Arc::new(AtomicUsize::new(0));
        let handler = counting_handler(Arc::clone(&calls), ReactorDecision::allow());

        let first = FakeDelivery::new(bytes.clone());
        dispatch_delivery(&first, &ctx, &handler).await;
        let second = FakeDelivery::new(bytes);
        dispatch_delivery(&second, &ctx, &handler).await;

        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(second.nacked_no_requeue.load(Ordering::SeqCst), 1);
        assert!(second.published().is_empty());
    }

    #[tokio::test]
    async fn an_event_naming_another_tenant_is_refused() {
        let key = subkey();
        // Signed correctly *for that other tenant's* body, but this reactor
        // is not configured for it.
        let delivery = FakeDelivery::new(signed_event_bytes(
            &key,
            Uuid::new_v4(),
            events::LOGIN_POST_AUTH,
            5_000,
            Utc::now(),
            2,
        ));
        let calls = Arc::new(AtomicUsize::new(0));

        dispatch_delivery(
            &delivery,
            &intercept_context(),
            &counting_handler(Arc::clone(&calls), ReactorDecision::allow()),
        )
        .await;

        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert!(delivery.published().is_empty());
        assert_eq!(delivery.nacked_no_requeue.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn a_delivery_with_no_reply_to_publishes_nothing() {
        let key = subkey();
        let delivery = FakeDelivery::new(fresh_event_bytes(&key, events::LOGIN_POST_AUTH, 5_000))
            .without_reply_to();

        dispatch_delivery(&delivery, &intercept_context(), &|_event| async {
            ReactorDecision::allow()
        })
        .await;

        assert!(delivery.published().is_empty());
    }

    #[tokio::test]
    async fn an_unparseable_body_is_nacked_without_requeue() {
        let delivery = FakeDelivery::new(b"{not json".to_vec());
        dispatch_delivery(&delivery, &intercept_context(), &|_event| async {
            ReactorDecision::allow()
        })
        .await;
        assert_eq!(delivery.nacked_no_requeue.load(Ordering::SeqCst), 1);
        assert!(delivery.published().is_empty());
    }

    // -----------------------------------------------------------------
    // §22.1 — the runtime declares no topology
    // -----------------------------------------------------------------

    /// Asserted against the source rather than against a comment: no reactor
    /// module may call a declare or bind operation, and the transport seam
    /// offers none to call.
    #[test]
    fn the_reactor_runtime_declares_no_exchange_queue_or_binding() {
        // Built at runtime so this test's own source cannot match itself.
        let forbidden: Vec<String> = [
            "queue_declare",
            "exchange_declare",
            "queue_bind",
            "exchange_bind",
        ]
        .iter()
        .map(|op| format!(".{op}("))
        .collect();
        for (name, source) in [
            ("runtime.rs", include_str!("runtime.rs")),
            ("protocol.rs", include_str!("protocol.rs")),
            ("registry.rs", include_str!("registry.rs")),
            ("mod.rs", include_str!("mod.rs")),
        ] {
            for call in &forbidden {
                assert!(
                    !source.contains(call.as_str()),
                    "{name} must not call {call} — §22.1: actors consume, they never declare topology"
                );
            }
        }
    }

    // -----------------------------------------------------------------
    // §18 — shutdown drains
    // -----------------------------------------------------------------

    /// The shutdown branch is only ever polled **between** deliveries, so a
    /// signal raised while an event is in flight finishes that event —
    /// handler, signature and publish — and only then stops.
    #[tokio::test]
    async fn shutdown_drains_the_in_flight_event_and_stops_before_the_next() {
        let key = subkey();
        let first = FakeDelivery::new(fresh_event_bytes(&key, events::LOGIN_POST_AUTH, 5_000));
        let second = FakeDelivery::new(fresh_event_bytes(&key, events::LOGIN_POST_AUTH, 5_000));

        let shutdown = ReactorShutdown::new();
        let mut rx = shutdown.subscribe();
        let signal = shutdown.clone();

        let mut stream = futures_util::stream::iter(vec![
            Ok::<_, String>(first.clone()),
            Ok::<_, String>(second.clone()),
        ]);

        let exit = consume_loop(
            &mut stream,
            &intercept_context(),
            &move |_event: ReactorEvent| {
                let signal = signal.clone();
                async move {
                    // Shutdown arrives while this event is still in flight.
                    signal.trigger();
                    ReactorDecision::allow()
                }
            },
            Some(&mut rx),
        )
        .await;

        assert_eq!(exit, ServeExit::ShutdownRequested);
        assert_eq!(
            first.published().len(),
            1,
            "the in-flight event must be drained, not truncated"
        );
        assert_eq!(first.acked.load(Ordering::SeqCst), 1);
        assert!(
            second.published().is_empty(),
            "no NEW delivery may be taken after the signal"
        );
        assert_eq!(second.acked.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn the_loop_reports_a_stream_that_ends_on_its_own() {
        let mut stream = futures_util::stream::iter(Vec::<Result<FakeDelivery, String>>::new());
        let exit = consume_loop(
            &mut stream,
            &intercept_context(),
            &|_event: ReactorEvent| async { ReactorDecision::allow() },
            None,
        )
        .await;
        assert_eq!(exit, ServeExit::StreamEnded);
    }

    // -----------------------------------------------------------------
    // §22.12 — the signing key is never logged
    // -----------------------------------------------------------------

    /// Scan the serialized log output for the fixture's own key value, as
    /// §22.13 (and §12/§14/§15/§20 before it) require.
    #[tokio::test]
    async fn the_signing_key_never_appears_in_a_log_line() {
        init_recording_subscriber();

        let key = subkey();
        let key_hex: String = key.iter().map(|b| format!("{b:02x}")).collect();
        let key_debug = format!("{key:?}");

        // Drive every logging path the runtime has: a bad signature, a
        // replayed nonce, a panicking handler, a forbidden require_mfa, and an
        // unaddressable reply.
        let mut tampered: serde_json::Value =
            serde_json::from_slice(&fresh_event_bytes(&key, events::LOGIN_POST_AUTH, 5_000))
                .unwrap();
        tampered["hmac_signature"] = serde_json::Value::String("11".repeat(32));
        let ctx = intercept_context();
        dispatch_delivery(
            &FakeDelivery::new(serde_json::to_vec(&tampered).unwrap()),
            &ctx,
            &|_event| async { ReactorDecision::allow() },
        )
        .await;

        let replayed = fresh_event_bytes(&key, events::LOGIN_POST_AUTH, 5_000);
        dispatch_delivery(
            &FakeDelivery::new(replayed.clone()),
            &ctx,
            &|_event| async { ReactorDecision::allow() },
        )
        .await;
        dispatch_delivery(&FakeDelivery::new(replayed), &ctx, &|_event| async {
            ReactorDecision::allow()
        })
        .await;

        dispatch_delivery(
            &FakeDelivery::new(fresh_event_bytes(&key, events::LOGIN_POST_AUTH, 5_000)),
            &ctx,
            &|_event| async { panic!("boom") },
        )
        .await;

        dispatch_delivery(
            &FakeDelivery::new(fresh_event_bytes(&key, events::TOKEN_PRE_ISSUE, 5_000)),
            &ctx,
            &|_event| async { ReactorDecision::require_step_up() },
        )
        .await;

        dispatch_delivery(
            &FakeDelivery::new(fresh_event_bytes(&key, events::LOGIN_POST_AUTH, 5_000))
                .without_reply_to(),
            &ctx,
            &|_event| async { ReactorDecision::allow() },
        )
        .await;

        let log = captured_log();
        assert!(!log.is_empty(), "these paths must log something");
        assert!(
            !log.contains(&key_hex),
            "the tenant signing key must never be logged (§22.12): {log}"
        );
        assert!(
            !log.contains(&key_debug),
            "the tenant signing key must never be logged (§22.12): {log}"
        );
        // Nor may the raw key bytes reach the log through any other rendering.
        assert!(!log.contains("super-secret"));
    }

    #[test]
    fn the_reconnect_delay_never_exceeds_the_cap() {
        for failures in 0..40 {
            assert!(reconnect_delay(failures) <= RECONNECT_DELAY_CAP);
        }
    }

    #[test]
    fn a_shutdown_signal_is_idempotent() {
        let shutdown = ReactorShutdown::new();
        assert!(!shutdown.is_triggered());
        shutdown.trigger();
        shutdown.trigger();
        assert!(shutdown.is_triggered());
    }

    /// §22.12: the signing key is a credential and must not appear in a
    /// diagnostic — including the config's own `Debug`.
    #[test]
    fn the_config_debug_output_never_renders_the_signing_key() {
        let config = ReactorConfig::builder()
            .amqp_url("amqps://broker.example.com:5671")
            .tenant_id(Uuid::nil())
            .reactor_id(Uuid::nil())
            .signing_key(Sensitive::new(b"super-secret-subkey".to_vec()))
            .build()
            .expect("valid config");
        let rendered = format!("{config:?}");
        assert!(!rendered.contains("super-secret-subkey"));
        assert!(!rendered.contains("115, 117, 112")); // byte-rendered form
    }

    #[test]
    fn a_plaintext_broker_url_is_refused() {
        let error = ReactorConfig::builder()
            .amqp_url("amqp://broker.example.com:5672")
            .tenant_id(Uuid::nil())
            .reactor_id(Uuid::nil())
            .signing_key(Sensitive::new(vec![1, 2, 3]))
            .build()
            .expect_err("plaintext must be refused");
        assert!(matches!(error, AxiamError::Network { .. }));
    }

    #[test]
    fn the_queue_name_is_derived_for_this_reactor_only() {
        let tenant: Uuid = "11111111-1111-1111-1111-111111111111".parse().unwrap();
        let reactor: Uuid = "99999999-9999-9999-9999-999999999999".parse().unwrap();
        let config = ReactorConfig::builder()
            .amqp_url("amqps://broker.example.com:5671")
            .tenant_id(tenant)
            .reactor_id(reactor)
            .signing_key(Sensitive::new(vec![0u8; 32]))
            .build()
            .unwrap();
        assert_eq!(
            config.queue(),
            "axiam.reactor.q.11111111-1111-1111-1111-111111111111.99999999-9999-9999-9999-999999999999"
        );
    }

    #[test]
    fn a_missing_required_field_is_a_build_error() {
        assert!(ReactorConfig::builder().build().is_err());
        assert!(
            ReactorConfig::builder()
                .amqp_url("amqps://b.example.com")
                .build()
                .is_err()
        );
    }

    #[test]
    fn telemetry_labels_come_from_the_registry_not_the_wire() {
        assert_eq!(static_event_label("token.pre_issue"), "token.pre_issue");
        assert_eq!(static_event_label("../../etc/passwd"), "unknown_event");
        // §22.7: even if a server somehow named one, it is not a registry
        // event and cannot become a label.
        assert_eq!(static_event_label("authz.check"), "unknown_event");
    }

    #[test]
    fn decision_constructors_produce_the_documented_shapes() {
        assert_eq!(
            ReactorDecision::allow(),
            ReactorDecision::Allow { require_mfa: false }
        );
        assert_eq!(
            ReactorDecision::require_step_up(),
            ReactorDecision::Allow { require_mfa: true }
        );
        assert_eq!(
            ReactorDecision::deny("nope"),
            ReactorDecision::Deny {
                reason: Some("nope".into())
            }
        );
        assert_eq!(
            ReactorDecision::deny_unexplained(),
            ReactorDecision::Deny { reason: None }
        );
        assert_eq!(
            ReactorDecision::mutate([("ext.a", "b")]),
            ReactorDecision::Mutate {
                patch: BTreeMap::from([("ext.a".to_string(), "b".to_string())])
            }
        );
        assert_eq!(ReactorDecision::abstain(), ReactorDecision::Abstain);
    }
}
