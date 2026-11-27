//! Closure-handler AMQP consumer (D-07): `consume(queue, handler)`.
//!
//! The SDK owns the full ack/nack loop. Every delivery is HMAC-verified
//! (CONTRACT.md §8) BEFORE the user-supplied handler closure is ever
//! invoked. On any verification failure (signature mismatch, missing
//! signature, a body that is not exactly a signed event, or a body that fails
//! to parse as JSON) the delivery is nacked WITHOUT requeue and a security event is
//! emitted — the event never contains the received or expected HMAC value.
//! Only a verified delivery reaches the handler, and only then is it acked.
//!
//! This design (D-07) is chosen over exposing a raw `Stream` that would push
//! ack/nack correctness onto the caller: the nack-without-requeue contract
//! on verification failure is security-sensitive, so the API makes it
//! impossible to misuse by never handing the caller an unverified message.
//!
//! ## NEW-4: v2 replay protection (CONTRACT.md §8 "v2 — Replay Protection")
//!
//! As of `key_version = 2` the signed body also carries `nonce` and
//! `issued_at`, covered by the HMAC. Verification never re-serializes the
//! delivery (CONTRACT.md §8 step 2): it cuts the trailing
//! `,"hmac_signature":"<64 hex>"` member from the received bytes, checks that
//! the members left are those of a signed event type in declaration order, and
//! verifies the HMAC over exactly those bytes. Once a signature verifies,
//! `verify_and_dispatch` applies three additional
//! gates — the SAME nack-without-requeue path as an invalid signature —
//! before the handler is ever invoked:
//!   - `key_version` must be `>= 2` (the hard cutover; a v1 message is
//!     rejected outright, there is no grace path).
//!   - `issued_at` must lie within `±skew` of the consumer's clock (default
//!     5 minutes, see `DEFAULT_FRESHNESS_SKEW_SECS`).
//!   - `nonce` must not have already been seen within the freshness window
//!     (an in-memory, TTL-bounded dedup set — see `ReplayGuard`).

use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::{Duration as StdDuration, Instant};

use chrono::{DateTime, SecondsFormat, Utc};
use futures_util::StreamExt;
use lapin::Channel;
use lapin::options::{BasicAckOptions, BasicConsumeOptions, BasicNackOptions, QueueDeclareOptions};
use lapin::types::FieldTable;

use crate::amqp::authz_requester::{cut_trailing_signature, parse_strict_object};
use crate::amqp::hmac::verify_payload;
use crate::amqp::messages::{AuditEventMessage, AuthzRequest};
use crate::amqp::transport::{AmqpTlsConfig, connect_amqps};
use crate::error::AxiamError;
use crate::sensitive::Sensitive;

/// Minimum accepted envelope `key_version` (NEW-4 hard cutover,
/// CONTRACT.md §8 "v2 — Replay Protection"). A message signed under an
/// older key version predates the mandatory `nonce`/`issued_at`
/// replay-protection fields and is rejected outright — there is no v1
/// grace path (mirrors the server's `MIN_ACCEPTED_KEY_VERSION`,
/// `crates/axiam-amqp/src/messages.rs:52`).
pub(crate) const MIN_ACCEPTED_KEY_VERSION: u8 = 2;

/// Default freshness skew for the `issued_at` acceptance window (NEW-4,
/// CONTRACT.md §8): a message is accepted only when its `issued_at` lies
/// within ±5 minutes of the consumer's current clock (mirrors the server's
/// `DEFAULT_FRESHNESS_SKEW_SECS`, `crates/axiam-amqp/src/messages.rs:58`).
/// [`consume`] lets a caller override this via its `freshness_skew`
/// parameter.
pub(crate) const DEFAULT_FRESHNESS_SKEW_SECS: i64 = 300;

/// The one signed event type a consumer is configured for (CONTRACT.md §8
/// protocol step 2c, contract 1.69, D-9).
///
/// The two types are signed with one scheme under one tenant subkey, so a
/// genuine signed audit event replayed onto a queue of authorization requests
/// passes the signature check; only its layout tells it apart. A consumer is
/// therefore given the type it consumes and refuses every other layout —
/// before the HMAC, before decoding — as `malformed`. An application that
/// consumes both types runs two consumers, each typed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventType {
    /// [`AuthzRequest`], from `axiam.authz.request`.
    AuthzRequest,
    /// [`AuditEventMessage`], from `axiam.audit.events`.
    AuditEvent,
}

impl EventType {
    /// The members this type declares, in order, and whether each is required
    /// (CONTRACT.md §8 "Exact signed field order").
    fn layout(self) -> &'static [(&'static str, bool)] {
        match self {
            Self::AuthzRequest => &AUTHZ_REQUEST_LAYOUT,
            Self::AuditEvent => &AUDIT_EVENT_LAYOUT,
        }
    }

    /// Decode the verified canonical bytes into this type and return the v2
    /// replay-protection fields (step 2f). A member of the wrong JSON type, an
    /// `issued_at` that is not an RFC 3339 timestamp or a `nonce` that is not
    /// a UUID fails here.
    fn decode(self, canonical: &[u8]) -> Option<ReplayFields> {
        match self {
            Self::AuthzRequest => {
                let m: AuthzRequest = serde_json::from_slice(canonical).ok()?;
                Some(ReplayFields {
                    key_version: m.key_version,
                    nonce: m.nonce.to_string(),
                    issued_at: m.issued_at,
                })
            }
            Self::AuditEvent => {
                let m: AuditEventMessage = serde_json::from_slice(canonical).ok()?;
                Some(ReplayFields {
                    key_version: m.key_version,
                    nonce: m.nonce.to_string(),
                    issued_at: m.issued_at,
                })
            }
        }
    }
}

/// What a consumer is configured with besides its signing key: the tenant whose
/// subkey it verifies with (named in every discard event, never read from a
/// body) and the one type it consumes.
#[derive(Debug, Clone, Copy)]
pub struct ConsumerTarget<'a> {
    /// The consumer's own tenant, whose subkey `signing_key` is.
    pub tenant_id: &'a str,
    /// The one signed type this consumer consumes.
    pub event_type: EventType,
}

/// Why a delivery was discarded: the closed vocabulary of CONTRACT.md §8
/// protocol rule 4 for an event consumer. Nothing read from the body is ever
/// attached to it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DiscardReason {
    Malformed,
    Unsigned,
    Signature,
    KeyVersion,
    Stale,
    Replay,
}

impl DiscardReason {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Malformed => "malformed",
            Self::Unsigned => "unsigned",
            Self::Signature => "signature",
            Self::KeyVersion => "key_version",
            Self::Stale => "stale",
            Self::Replay => "replay",
        }
    }
}

/// The v2 replay-protection fields of a body whose HMAC has verified and that
/// decoded into the configured type.
struct ReplayFields {
    key_version: u8,
    nonce: String,
    issued_at: DateTime<Utc>,
}

/// In-memory nonce-replay guard + `issued_at` freshness gate (NEW-4).
///
/// One `ReplayGuard` is shared (via `Arc`) across every delivery processed
/// by [`consume`], so a nonce observed on one message is remembered for
/// every subsequent one on the same consumer. It never touches durable
/// storage — CONTRACT.md §8 permits "reject within the freshness window" as
/// the minimum bar for SDKs that do not persist nonces, which this
/// satisfies: a nonce is retained for `2 × skew` (the full width of the
/// freshness window on either side of `now`), which is always at least as
/// long as a replayed message could still pass the freshness gate on its
/// own — so a replay can never sneak through after its entry has been
/// pruned. Pruning is opportunistic (done inline on every check, see
/// [`check_and_record_nonce`](Self::check_and_record_nonce)) rather than via
/// a background sweep task, which is what keeps the map naturally bounded.
pub(crate) struct ReplayGuard {
    skew: chrono::Duration,
    seen: Mutex<HashMap<String, Instant>>,
}

impl ReplayGuard {
    /// Build a guard with an explicit freshness skew.
    pub(crate) fn new(skew: chrono::Duration) -> Self {
        Self {
            skew,
            seen: Mutex::new(HashMap::new()),
        }
    }

    /// Build a guard using `DEFAULT_FRESHNESS_SKEW_SECS` (5 minutes) — what
    /// [`consume`] uses when no override is supplied.
    pub(crate) fn with_default_skew() -> Self {
        Self::new(chrono::Duration::seconds(DEFAULT_FRESHNESS_SKEW_SECS))
    }

    /// Nonce dedup TTL: `2 × skew`, i.e. the full width of the freshness
    /// acceptance window. Falls back to `2 × DEFAULT_FRESHNESS_SKEW_SECS` in
    /// the (practically unreachable, since skew is always a small duration)
    /// case where the doubled skew overflows `std::time::Duration`.
    fn ttl(&self) -> StdDuration {
        (self.skew * 2)
            .to_std()
            .unwrap_or_else(|_| StdDuration::from_secs(DEFAULT_FRESHNESS_SKEW_SECS as u64 * 2))
    }

    /// `true` when `issued_at` lies within ±skew of `now` — mirrors the
    /// server's `is_fresh` (`crates/axiam-amqp/src/messages.rs:86-88`).
    pub(crate) fn is_fresh(&self, issued_at: DateTime<Utc>, now: DateTime<Utc>) -> bool {
        now.signed_duration_since(issued_at).abs() <= self.skew
    }

    /// Returns `true` the first time `nonce` is observed (accept); `false`
    /// if it was already recorded and hasn't expired yet (a replay).
    /// Expired entries are pruned on every call.
    pub(crate) fn check_and_record_nonce(&self, nonce: &str) -> bool {
        let ttl = self.ttl();
        let now = Instant::now();
        let mut seen = match self.seen.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        seen.retain(|_, expiry| *expiry > now);
        if seen.contains_key(nonce) {
            return false;
        }
        seen.insert(nonce.to_owned(), now + ttl);
        true
    }
}

impl Default for ReplayGuard {
    fn default() -> Self {
        Self::with_default_skew()
    }
}

/// Apply the NEW-4 gates, in the contract's order (6) `key_version`, (7)
/// freshness, (8) nonce. The nonce is recorded only when every other gate has
/// passed, so a message refused at (1)–(7) leaves no nonce behind.
fn validate_v2_replay_protection(
    fields: &ReplayFields,
    replay: &ReplayGuard,
) -> Result<(), DiscardReason> {
    if fields.key_version < MIN_ACCEPTED_KEY_VERSION {
        return Err(DiscardReason::KeyVersion);
    }
    if !replay.is_fresh(fields.issued_at, Utc::now()) {
        return Err(DiscardReason::Stale);
    }
    if !replay.check_and_record_nonce(&fields.nonce) {
        return Err(DiscardReason::Replay);
    }
    Ok(())
}

/// A minimal seam over the AMQP acknowledgement primitives this module
/// needs. `lapin::message::Delivery` implements this directly (via its
/// `Deref<Target = Acker>`); tests provide a recording fake that never
/// touches a live broker, so the security-sensitive nack-without-requeue
/// behavior of [`verify_and_dispatch`] can be asserted without a running
/// RabbitMQ instance.
pub(crate) trait AckableDelivery {
    /// The raw message payload bytes.
    fn data(&self) -> &[u8];
    /// The exchange the broker delivered this message from (`""` for the
    /// default exchange).
    fn exchange(&self) -> &str;
    /// The routing key the broker reported for this delivery.
    fn routing_key(&self) -> &str;
    /// Acknowledge the delivery (message processed successfully).
    fn ack(&self) -> impl Future<Output = ()> + Send;
    /// Negatively acknowledge the delivery. `requeue` MUST be `false` on
    /// every failure path in this module (verification failure, parse
    /// failure) so poison/unverifiable messages do not loop the queue.
    fn nack(&self, requeue: bool) -> impl Future<Output = ()> + Send;
}

impl AckableDelivery for lapin::message::Delivery {
    fn data(&self) -> &[u8] {
        &self.data
    }

    fn exchange(&self) -> &str {
        self.exchange.as_str()
    }

    fn routing_key(&self) -> &str {
        self.routing_key.as_str()
    }

    async fn ack(&self) {
        let _ = self.acker.ack(BasicAckOptions::default()).await;
    }

    async fn nack(&self, requeue: bool) {
        let _ = self
            .acker
            .nack(BasicNackOptions {
                requeue,
                ..Default::default()
            })
            .await;
    }
}

/// The members each signed event type declares, in order, with whether the
/// member is required (CONTRACT.md §8 "Exact signed field order"). `hmac_signature`
/// is not among them: it is cut off before the layout is read.
const AUTHZ_REQUEST_LAYOUT: [(&str, bool); 9] = [
    ("correlation_id", true),
    ("tenant_id", true),
    ("subject_id", true),
    ("action", true),
    ("resource_id", true),
    ("scope", false),
    ("key_version", true),
    ("nonce", true),
    ("issued_at", true),
];
const AUDIT_EVENT_LAYOUT: [(&str, bool); 11] = [
    ("tenant_id", true),
    ("actor_id", true),
    ("actor_type", true),
    ("action", true),
    ("resource_id", false),
    ("outcome", true),
    ("ip_address", false),
    ("metadata", false),
    ("key_version", true),
    ("nonce", true),
    ("issued_at", true),
];

/// Whether `names` are exactly the members of `layout`, in declaration order,
/// optional members possibly absent and nothing else (step 2c).
fn matches_layout<'a>(mut names: impl Iterator<Item = &'a str>, layout: &[(&str, bool)]) -> bool {
    let mut next = names.next();
    for (name, required) in layout {
        if next == Some(name) {
            next = names.next();
        } else if *required {
            return false;
        }
    }
    next.is_none()
}

/// §8 protocol step 2: turn a delivered body into the verified message, or say
/// why it is refused, with the first reason that applies in rule 4's order:
/// (1) not one JSON object → `malformed`; (2) no `hmac_signature` member →
/// `unsigned`; (3) steps 2a–2c, the typed layout check included → `malformed`;
/// (4) the HMAC → `signature`; (5) the verified bytes do not decode into the
/// configured type → `malformed`; (6) `key_version`; (7) freshness; (8) replay.
/// The signature is cut from the received bytes (nothing is re-serialized),
/// the layout of what is left is checked against the configured type only,
/// the HMAC is verified over exactly those bytes, and the returned value is
/// decoded from them.
fn verified_body(
    data: &[u8],
    signing_key: &[u8],
    event_type: EventType,
    replay: &ReplayGuard,
) -> Result<serde_json::Value, DiscardReason> {
    use DiscardReason::{Malformed, Signature, Unsigned};
    // (1) 2a: the first byte is `{` (a byte-order mark, whitespace or any other
    // prefix is refused, never skipped) and the body parses as JSON, trailing
    // content included. A plain parse: duplicates are position (3).
    if data.first() != Some(&b'{') {
        return Err(Malformed);
    }
    let Ok(serde_json::Value::Object(plain)) = serde_json::from_slice(data) else {
        return Err(Malformed);
    };
    // (2) no signature member at all, whatever else the body lacks.
    if !plain.contains_key("hmac_signature") {
        return Err(Unsigned);
    }
    // (3) 2a: unambiguous names; 2b: the body ends in the signature member,
    // refused, never repaired.
    parse_strict_object(data).map_err(|_| Malformed)?;
    let (canonical, signature) = cut_trailing_signature(data).ok_or(Malformed)?;
    // 2c: the canonical bytes are exactly the configured type, member for
    // member — before the HMAC, before decoding.
    let members = parse_strict_object(&canonical).map_err(|_| Malformed)?;
    if !matches_layout(members.keys().map(String::as_str), event_type.layout()) {
        return Err(Malformed);
    }
    // (4) 2d-2e: constant-time HMAC over the canonical bytes.
    if !verify_payload(signing_key, &canonical, signature) {
        return Err(Signature);
    }
    // (5) 2f: decode from the verified bytes, then (6)-(8) the v2 gates.
    let fields = event_type.decode(&canonical).ok_or(Malformed)?;
    validate_v2_replay_protection(&fields, replay)?;
    Ok(serde_json::Value::Object(members))
}

/// Verify a single delivery's HMAC signature (CONTRACT.md §8 step 2a–2g),
/// then apply the NEW-4 v2 replay-protection gates (`key_version`,
/// freshness, nonce dedup via `replay`) and, only if everything passes,
/// invoke `handler` with the parsed body before acking. On any failure the
/// delivery is nacked without requeue and one security event is emitted: the
/// delivery's exchange and routing key, the consumer's own tenant and a
/// closed reason (never the HMAC value, a nonce or anything from the body).
///
/// This is the load-bearing, separately-testable unit backing
/// [`consume`]'s per-message loop — kept generic over [`AckableDelivery`]
/// so it can be exercised against a recording fake in unit tests without a
/// live broker.
pub(crate) async fn verify_and_dispatch<D, F, Fut>(
    delivery: &D,
    signing_key: &[u8],
    target: &ConsumerTarget<'_>,
    handler: &F,
    replay: &ReplayGuard,
) where
    D: AckableDelivery,
    F: Fn(serde_json::Value) -> Fut + Send + Sync,
    Fut: Future<Output = ()> + Send,
{
    // §8 step 2: verify over the bytes that arrived, never over a re-serialization.
    let body = match verified_body(delivery.data(), signing_key, target.event_type, replay) {
        Ok(body) => body,
        Err(reason) => {
            tracing::warn!(
                target: "axiam_sdk::security",
                timestamp = %Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
                exchange = %delivery.exchange(),
                routing_key = %delivery.routing_key(),
                tenant_id = %target.tenant_id,
                reason = reason.as_str(),
                "AMQP message discarded; nacking without requeue"
            );
            delivery.nack(false).await;
            return;
        }
    };

    handler(body).await;
    delivery.ack().await;
}

/// Connect to the AMQP broker at `amqp_url`, declare `queue` as durable if
/// it does not already exist, and consume from it — verifying each
/// delivery's HMAC-SHA256 signature (CONTRACT.md §8) BEFORE invoking
/// `handler`. The handler never sees an unverified message; verification
/// failures are nacked without requeue and logged as a security event.
///
/// `signing_key` MUST be obtained from the AXIAM management API for the
/// tenant whose queue is being consumed (CONTRACT.md §8.1) — hardcoding a
/// signing key is prohibited. It is wrapped in [`Sensitive<Vec<u8>>`] so it
/// can never be logged accidentally.
///
/// `target.tenant_id` is the tenant whose subkey `signing_key` is: the consumer's
/// **own** tenant, named in every discard event and never read from a body.
/// `target.event_type` is the **one** type this consumer consumes
/// ([`EventType::AuthzRequest`] or [`EventType::AuditEvent`]); a body with the
/// other type's layout is refused as `malformed` before the HMAC is computed.
/// An application that consumes both queues runs two consumers.
///
/// Every discard — whatever the reason — is nacked without requeue and logged
/// as exactly one `warn` event on target `axiam_sdk::security` with the fields
/// `timestamp`, `exchange`, `routing_key`, `tenant_id` and `reason`
/// (`malformed`, `unsigned`, `signature`, `key_version`, `stale` or `replay`;
/// CONTRACT.md §8 protocol rule 4), and never a signature, a nonce, a key or
/// the body.
///
/// `freshness_skew` overrides the NEW-4 `issued_at` acceptance window
/// (default `±5 minutes`, i.e. `DEFAULT_FRESHNESS_SKEW_SECS`) — pass
/// `None` to use the default. The same window (doubled) bounds how long a
/// `nonce` is remembered for replay detection; see `ReplayGuard`.
///
/// This function owns the full ack/nack loop; the closure `handler` is
/// invoked only after successful verification (HMAC signature AND the
/// NEW-4 replay-protection gates) and MUST NOT itself call ack/nack (there
/// is no delivery handle exposed to it).
///
/// `amqp_url` MUST be `amqps://` (CONTRACT.md §8b), checked before any socket
/// is opened. Use [`consume_with_tls`] to supply a CA bundle for a
/// privately-issued broker certificate, or a client identity for mutual TLS;
/// this function verifies the broker against the platform root store, which is
/// correct only for a publicly-issued certificate.
pub async fn consume<F, Fut>(
    amqp_url: &str,
    queue: &str,
    signing_key: Sensitive<Vec<u8>>,
    target: ConsumerTarget<'_>,
    freshness_skew: Option<StdDuration>,
    handler: F,
) -> Result<(), AxiamError>
where
    F: Fn(serde_json::Value) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = ()> + Send,
{
    consume_with_tls(
        amqp_url,
        queue,
        signing_key,
        target,
        freshness_skew,
        &AmqpTlsConfig::default(),
        handler,
    )
    .await
}

/// [`consume`], with explicit TLS material for the broker connection
/// (CONTRACT.md §8b rules 2 and 3).
///
/// Supply `tls.ca_cert_pem` when the broker certificate is issued by a private
/// CA — the common case for an in-cluster broker, and the reason rule 2 is a
/// MUST — and the `client_cert_pem`/`client_key_pem` pair for mutual TLS.
///
/// There is deliberately no verification-skip option, here or anywhere else in
/// this SDK (rule 4); see [`AmqpTlsConfig`].
pub async fn consume_with_tls<F, Fut>(
    amqp_url: &str,
    queue: &str,
    signing_key: Sensitive<Vec<u8>>,
    target: ConsumerTarget<'_>,
    freshness_skew: Option<StdDuration>,
    tls: &AmqpTlsConfig,
    handler: F,
) -> Result<(), AxiamError>
where
    F: Fn(serde_json::Value) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = ()> + Send,
{
    // §8b rules 1 and 5: refuse anything but `amqps://`, before a socket is
    // opened and with no fallback path to take. Signed message bodies and the
    // per-tenant context would otherwise cross an unencrypted link — HMAC
    // proves who wrote them, it does not keep them off the wire.
    let connection = connect_amqps(amqp_url, tls).await?;

    let channel: Channel = connection
        .create_channel()
        .await
        .map_err(|e| AxiamError::Network {
            message: format!("failed to create AMQP channel: {e}"),
            source: None,
        })?;

    channel
        .queue_declare(
            queue.into(),
            QueueDeclareOptions {
                durable: true,
                ..Default::default()
            },
            FieldTable::default(),
        )
        .await
        .map_err(|e| AxiamError::Network {
            message: format!("failed to declare AMQP queue: {e}"),
            source: None,
        })?;

    let mut consumer = channel
        .basic_consume(
            queue.into(),
            "axiam-sdk-consumer".into(),
            BasicConsumeOptions::default(),
            FieldTable::default(),
        )
        .await
        .map_err(|e| AxiamError::Network {
            message: format!("failed to start AMQP consumer: {e}"),
            source: None,
        })?;

    let key = Arc::new(signing_key);
    let tenant_id: Arc<str> = Arc::from(target.tenant_id);
    let event_type = target.event_type;
    let handler = Arc::new(handler);
    // One ReplayGuard shared across every delivery on this consumer, so a
    // nonce observed on one message is remembered for the lifetime of the
    // loop (NEW-4).
    let replay = Arc::new(
        freshness_skew
            .and_then(|skew| chrono::Duration::from_std(skew).ok())
            .map(ReplayGuard::new)
            .unwrap_or_default(),
    );

    while let Some(delivery_result) = consumer.next().await {
        match delivery_result {
            Ok(delivery) => {
                let target = ConsumerTarget {
                    tenant_id: &tenant_id,
                    event_type,
                };
                verify_and_dispatch(
                    &delivery,
                    key.expose(),
                    &target,
                    handler.as_ref(),
                    replay.as_ref(),
                )
                .await;
            }
            Err(e) => {
                tracing::warn!(target: "axiam_sdk::security", error = %e, "AMQP consumer stream error");
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use crate::amqp::hmac::sign_payload;

    const CONSUMER_TENANT: &str = "99999999-9999-9999-9999-999999999999";
    const AUTHZ_TARGET: ConsumerTarget<'static> = ConsumerTarget {
        tenant_id: CONSUMER_TENANT,
        event_type: EventType::AuthzRequest,
    };
    const AUDIT_TARGET: ConsumerTarget<'static> = ConsumerTarget {
        tenant_id: CONSUMER_TENANT,
        event_type: EventType::AuditEvent,
    };

    /// A recording fake delivery: never touches a live broker. Records
    /// whether `ack` or `nack` (and with which `requeue` value) was called,
    /// so the security-sensitive nack-without-requeue contract can be
    /// asserted directly.
    #[derive(Clone)]
    struct RecordingDelivery {
        data: Vec<u8>,
        acked: Arc<AtomicUsize>,
        nacked_requeue_true: Arc<AtomicUsize>,
        nacked_requeue_false: Arc<AtomicUsize>,
    }

    impl RecordingDelivery {
        fn new(data: Vec<u8>) -> Self {
            Self {
                data,
                acked: Arc::new(AtomicUsize::new(0)),
                nacked_requeue_true: Arc::new(AtomicUsize::new(0)),
                nacked_requeue_false: Arc::new(AtomicUsize::new(0)),
            }
        }
    }

    impl AckableDelivery for RecordingDelivery {
        fn data(&self) -> &[u8] {
            &self.data
        }

        fn exchange(&self) -> &str {
            "axiam.test.exchange"
        }

        fn routing_key(&self) -> &str {
            "axiam.test.routing"
        }

        async fn ack(&self) {
            self.acked.fetch_add(1, Ordering::SeqCst);
        }

        async fn nack(&self, requeue: bool) {
            if requeue {
                self.nacked_requeue_true.fetch_add(1, Ordering::SeqCst);
            } else {
                self.nacked_requeue_false.fetch_add(1, Ordering::SeqCst);
            }
        }
    }

    // The recording `tracing::Subscriber` these assertions read lives in
    // `crate::amqp::test_log`, shared with the §22 reactor-runtime tests: a
    // test binary may install exactly one global subscriber, and both suites
    // need to assert on what would have been logged.
    use crate::amqp::test_log::{THREAD_EVENTS, init_recording_subscriber};

    /// Build a v2 message body (NEW-4: always carries `key_version`,
    /// `nonce`, `issued_at`) with a fresh, unique `nonce` and `issued_at`
    /// set to `Utc::now()` unless overridden. Used by tests that only care
    /// about the HMAC verification step (not the replay-protection gates),
    /// so a sensible, always-fresh default keeps them independent of wall-
    /// clock timing.
    fn v2_body(key_version: u8, nonce: &str, issued_at: DateTime<Utc>) -> serde_json::Value {
        serde_json::from_str(&authz_canonical(key_version, nonce, issued_at)).unwrap()
    }

    fn make_signed_body_with(
        key_version: u8,
        nonce: &str,
        issued_at: DateTime<Utc>,
    ) -> (serde_json::Value, Vec<u8>) {
        let key = b"consumer-test-signing-key";
        let canonical = authz_canonical(key_version, nonce, issued_at);
        let sig = sign_payload(key, canonical.as_bytes());
        let data = wire_bytes_with_signature(&canonical, &sig);
        (serde_json::from_slice(&data).unwrap(), data)
    }

    fn make_signed_body() -> (serde_json::Value, Vec<u8>) {
        make_signed_body_with(2, &uuid::Uuid::new_v4().to_string(), Utc::now())
    }

    #[tokio::test]
    async fn valid_signature_invokes_handler_once_then_acks() {
        let key = b"consumer-test-signing-key";
        let (_body, data) = make_signed_body();
        let delivery = RecordingDelivery::new(data);
        let replay = ReplayGuard::with_default_skew();
        let handler_calls = Arc::new(AtomicUsize::new(0));
        let handler_calls_clone = Arc::clone(&handler_calls);
        let handler = move |_value: serde_json::Value| {
            let calls = Arc::clone(&handler_calls_clone);
            async move {
                calls.fetch_add(1, Ordering::SeqCst);
            }
        };

        verify_and_dispatch(&delivery, key, &AUTHZ_TARGET, &handler, &replay).await;

        assert_eq!(handler_calls.load(Ordering::SeqCst), 1);
        assert_eq!(delivery.acked.load(Ordering::SeqCst), 1);
        assert_eq!(delivery.nacked_requeue_false.load(Ordering::SeqCst), 0);
        assert_eq!(delivery.nacked_requeue_true.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn mismatched_signature_never_invokes_handler_and_nacks_without_requeue() {
        let key = b"consumer-test-signing-key";
        let (mut body, _data) = make_signed_body();
        // Corrupt the signature so it no longer matches the canonical body.
        body.as_object_mut().unwrap().insert(
            "hmac_signature".into(),
            serde_json::Value::String(
                "0000000000000000000000000000000000000000000000000000000000000000".into(),
            ),
        );
        let data = serde_json::to_vec(&body).unwrap();
        let delivery = RecordingDelivery::new(data);
        let replay = ReplayGuard::with_default_skew();
        let handler_calls = Arc::new(AtomicUsize::new(0));
        let handler_calls_clone = Arc::clone(&handler_calls);
        let handler = move |_value: serde_json::Value| {
            let calls = Arc::clone(&handler_calls_clone);
            async move {
                calls.fetch_add(1, Ordering::SeqCst);
            }
        };

        verify_and_dispatch(&delivery, key, &AUTHZ_TARGET, &handler, &replay).await;

        assert_eq!(
            handler_calls.load(Ordering::SeqCst),
            0,
            "handler must never be invoked on a tampered/mismatched signature"
        );
        assert_eq!(delivery.nacked_requeue_false.load(Ordering::SeqCst), 1);
        assert_eq!(delivery.nacked_requeue_true.load(Ordering::SeqCst), 0);
        assert_eq!(delivery.acked.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn missing_signature_strict_mode_default_never_invokes_handler_and_nacks_without_requeue()
    {
        let key = b"consumer-test-signing-key";
        let body = v2_body(2, &uuid::Uuid::new_v4().to_string(), Utc::now());
        let data = serde_json::to_vec(&body).unwrap();
        let delivery = RecordingDelivery::new(data);
        let replay = ReplayGuard::with_default_skew();
        let handler_calls = Arc::new(AtomicUsize::new(0));
        let handler_calls_clone = Arc::clone(&handler_calls);
        let handler = move |_value: serde_json::Value| {
            let calls = Arc::clone(&handler_calls_clone);
            async move {
                calls.fetch_add(1, Ordering::SeqCst);
            }
        };

        verify_and_dispatch(&delivery, key, &AUTHZ_TARGET, &handler, &replay).await;

        assert_eq!(
            handler_calls.load(Ordering::SeqCst),
            0,
            "a delivery with no hmac_signature must be rejected in strict mode (the default)"
        );
        assert_eq!(delivery.nacked_requeue_false.load(Ordering::SeqCst), 1);
        assert_eq!(delivery.nacked_requeue_true.load(Ordering::SeqCst), 0);
        assert_eq!(delivery.acked.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn invalid_json_body_never_invokes_handler_and_nacks_without_requeue() {
        let key = b"consumer-test-signing-key";
        let delivery = RecordingDelivery::new(b"not valid json {{{".to_vec());
        let replay = ReplayGuard::with_default_skew();
        let handler_calls = Arc::new(AtomicUsize::new(0));
        let handler_calls_clone = Arc::clone(&handler_calls);
        let handler = move |_value: serde_json::Value| {
            let calls = Arc::clone(&handler_calls_clone);
            async move {
                calls.fetch_add(1, Ordering::SeqCst);
            }
        };

        verify_and_dispatch(&delivery, key, &AUTHZ_TARGET, &handler, &replay).await;

        assert_eq!(handler_calls.load(Ordering::SeqCst), 0);
        assert_eq!(delivery.nacked_requeue_false.load(Ordering::SeqCst), 1);
        assert_eq!(delivery.nacked_requeue_true.load(Ordering::SeqCst), 0);
        assert_eq!(delivery.acked.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn security_event_log_omits_hmac_value() {
        init_recording_subscriber();

        let key = b"consumer-test-signing-key";
        let (mut body, _data) = make_signed_body();
        let leaked_signature_would_be = body
            .get("hmac_signature")
            .and_then(|v| v.as_str())
            .unwrap()
            .to_owned();
        // Corrupt the signature so verification fails and the security
        // event path fires.
        let wrong_sig = "1".repeat(leaked_signature_would_be.len());
        body.as_object_mut().unwrap().insert(
            "hmac_signature".into(),
            serde_json::Value::String(wrong_sig.clone()),
        );
        let data = serde_json::to_vec(&body).unwrap();
        let delivery = RecordingDelivery::new(data);
        let replay = ReplayGuard::with_default_skew();
        let handler = |_value: serde_json::Value| async {};

        verify_and_dispatch(&delivery, key, &AUTHZ_TARGET, &handler, &replay).await;

        let captured = THREAD_EVENTS.with(|events| events.borrow().clone());
        assert!(
            !captured.is_empty(),
            "a security event must be emitted on verification failure"
        );
        for event in captured.iter() {
            assert!(
                !event.contains(&wrong_sig) && !event.contains(&leaked_signature_would_be),
                "security event log line must never contain the received or expected HMAC \
                 value (CONTRACT.md §8.4): {event}"
            );
        }
        assert_eq!(delivery.nacked_requeue_false.load(Ordering::SeqCst), 1);
    }

    // SDK-Q01 regression: the server signs the HMAC over the concrete struct
    // serialized in FIELD-DECLARATION order (correlation_id, tenant_id,
    // subject_id, action, resource_id, scope, key_version, nonce, issued_at)
    // — which is NOT alphabetical. This fixture builds the canonical signed
    // bytes by HAND in that declaration order (never by round-tripping
    // through the verifier's own `Value` path), then feeds the SDK a
    // delivery whose body is exactly what the server put on the wire.
    // Before the fix (no `preserve_order`), the verifier re-serialized the
    // parsed `Value` alphabetically and HMACed over the wrong bytes,
    // rejecting this genuine message.
    //
    // NEW-4: bumped to `key_version = 2` with `nonce`/`issued_at` appended
    // in declaration order (immediately before `hmac_signature`).
    // `issued_at` is computed at call time (not baked into a `const`) so
    // these tests stay fresh regardless of when they actually run.
    fn authz_canonical(key_version: u8, nonce: &str, issued_at: DateTime<Utc>) -> String {
        format!(
            concat!(
                "{{",
                "\"correlation_id\":\"11111111-1111-1111-1111-111111111111\",",
                "\"tenant_id\":\"22222222-2222-2222-2222-222222222222\",",
                "\"subject_id\":\"33333333-3333-3333-3333-333333333333\",",
                "\"action\":\"read\",",
                "\"resource_id\":\"44444444-4444-4444-4444-444444444444\",",
                "\"scope\":\"sub\",",
                "\"key_version\":{},",
                "\"nonce\":\"{}\",",
                "\"issued_at\":\"{}\"",
                "}}"
            ),
            key_version,
            nonce,
            issued_at.to_rfc3339(),
        )
    }

    /// Build the on-the-wire delivery bytes: the canonical payload with
    /// `hmac_signature` appended as the final key (exactly how the server
    /// emits it after signing).
    fn wire_bytes_with_signature(canonical: &str, sig: &str) -> Vec<u8> {
        // Splice the signature in just before the closing brace, keeping the
        // canonical field order intact and adding `hmac_signature` last.
        let without_close = &canonical[..canonical.len() - 1];
        format!("{without_close},\"hmac_signature\":\"{sig}\"}}").into_bytes()
    }

    #[tokio::test]
    async fn server_declaration_order_message_is_accepted() {
        let key = b"declaration-order-signing-key";
        let canonical = authz_canonical(2, "77777777-7777-7777-7777-777777777777", Utc::now());
        // Sign the hand-built declaration-order canonical bytes — NOT bytes
        // produced by re-serializing a `Value` the same way the verifier does.
        let sig = sign_payload(key, canonical.as_bytes());
        let data = wire_bytes_with_signature(&canonical, &sig);
        let delivery = RecordingDelivery::new(data);
        let replay = ReplayGuard::with_default_skew();

        let handler_calls = Arc::new(AtomicUsize::new(0));
        let handler_calls_clone = Arc::clone(&handler_calls);
        let handler = move |_value: serde_json::Value| {
            let calls = Arc::clone(&handler_calls_clone);
            async move {
                calls.fetch_add(1, Ordering::SeqCst);
            }
        };

        verify_and_dispatch(&delivery, key, &AUTHZ_TARGET, &handler, &replay).await;

        assert_eq!(
            handler_calls.load(Ordering::SeqCst),
            1,
            "a genuine server message signed in declaration order must verify \
             and reach the handler (SDK-Q01)"
        );
        assert_eq!(delivery.acked.load(Ordering::SeqCst), 1);
        assert_eq!(delivery.nacked_requeue_false.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn server_declaration_order_message_tampered_is_rejected() {
        let key = b"declaration-order-signing-key";
        let canonical = authz_canonical(2, "88888888-8888-8888-8888-888888888888", Utc::now());
        // Signature is over the pristine canonical bytes...
        let sig = sign_payload(key, canonical.as_bytes());
        // ...but the delivered body flips `action` from read -> write, so the
        // recomputed HMAC must not match.
        let tampered_canonical = canonical.replace("\"read\"", "\"write\"");
        let data = wire_bytes_with_signature(&tampered_canonical, &sig);
        let delivery = RecordingDelivery::new(data);
        let replay = ReplayGuard::with_default_skew();

        let handler_calls = Arc::new(AtomicUsize::new(0));
        let handler_calls_clone = Arc::clone(&handler_calls);
        let handler = move |_value: serde_json::Value| {
            let calls = Arc::clone(&handler_calls_clone);
            async move {
                calls.fetch_add(1, Ordering::SeqCst);
            }
        };

        verify_and_dispatch(&delivery, key, &AUTHZ_TARGET, &handler, &replay).await;

        assert_eq!(
            handler_calls.load(Ordering::SeqCst),
            0,
            "a tampered body must never reach the handler"
        );
        assert_eq!(delivery.nacked_requeue_false.load(Ordering::SeqCst), 1);
        assert_eq!(delivery.acked.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn hmac_signature_not_last_member_is_refused() {
        // §8 step 2b: a signature that is not the last member is refused, never
        // repaired by moving it, even though the HMAC over the rest is valid.
        let key = b"declaration-order-signing-key";
        let canonical = authz_canonical(2, "99999999-9999-9999-9999-999999999999", Utc::now());
        let sig = sign_payload(key, canonical.as_bytes());
        let data = format!("{{\"hmac_signature\":\"{sig}\",{}", &canonical[1..]).into_bytes();
        let (calls, delivery) = dispatch(key, data).await;
        assert!(calls.is_empty(), "the handler must not run");
        assert_eq!(delivery.nacked_requeue_false.load(Ordering::SeqCst), 1);
        assert_eq!(delivery.acked.load(Ordering::SeqCst), 0);
    }

    // --- #882 pins: verify over what arrived, dispatch what was verified -----

    /// Run `data` through the consumer; return the handler's calls and the
    /// delivery.
    async fn dispatch(key: &[u8], data: Vec<u8>) -> (Vec<serde_json::Value>, RecordingDelivery) {
        dispatch_as(key, data, &AUTHZ_TARGET).await
    }

    async fn dispatch_as(
        key: &[u8],
        data: Vec<u8>,
        target: &ConsumerTarget<'_>,
    ) -> (Vec<serde_json::Value>, RecordingDelivery) {
        let delivery = RecordingDelivery::new(data);
        let replay = ReplayGuard::with_default_skew();
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink = Arc::clone(&seen);
        let handler = move |value: serde_json::Value| {
            let sink = Arc::clone(&sink);
            async move { sink.lock().unwrap().push(value) }
        };
        verify_and_dispatch(&delivery, key, target, &handler, &replay).await;
        let calls = seen.lock().unwrap().clone();
        (calls, delivery)
    }

    #[tokio::test]
    async fn genuine_message_with_characters_encoders_disagree_on_verifies() {
        // `<`, `>`, `&`, a non-ASCII character raw (as serde_json writes them)
        // and a control character as its `\u` escape, which serde_json also
        // writes: a verifier that re-encoded differently would reject this.
        let key = b"declaration-order-signing-key";
        let canonical = authz_canonical(2, "12121212-1212-1212-1212-121212121212", Utc::now())
            .replace("\"read\"", "\"a&b</c>/\u{e9}\u{20ac}\\u0001\"");
        assert!(canonical.contains("a&b</c>/\u{e9}\u{20ac}\\u0001"));
        let sig = sign_payload(key, canonical.as_bytes());
        let (calls, delivery) = dispatch(key, wire_bytes_with_signature(&canonical, &sig)).await;
        assert_eq!(calls.len(), 1, "a genuine message must verify");
        assert_eq!(calls[0]["action"], "a&b</c>/\u{e9}\u{20ac}\u{1}");
        assert_eq!(delivery.acked.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn genuine_audit_event_with_escaped_and_non_ascii_text_verifies() {
        // `action` and a `metadata` value hold `&`, `<`, `>`, a `\u0041` escape of
        // a printable character and a non-ASCII one; both reach the handler as
        // exactly `a&b<c>Aé`.
        let key = b"declaration-order-signing-key";
        let canonical = format!(
            concat!(
                "{{\"tenant_id\":\"22222222-2222-2222-2222-222222222222\",",
                "\"actor_id\":\"33333333-3333-3333-3333-333333333333\",",
                "\"actor_type\":\"User\",\"action\":\"a&b<c>\\u0041\u{e9}\",",
                "\"outcome\":\"Success\",\"metadata\":{{\"note\":\"a&b<c>\\u0041\u{e9}\"}},",
                "\"key_version\":2,\"nonce\":\"18181818-1818-1818-1818-181818181818\",",
                "\"issued_at\":\"{}\"}}"
            ),
            Utc::now().to_rfc3339()
        );
        let sig = sign_payload(key, canonical.as_bytes());
        let (calls, delivery) = dispatch_as(
            key,
            wire_bytes_with_signature(&canonical, &sig),
            &AUDIT_TARGET,
        )
        .await;
        assert_eq!(calls.len(), 1, "a genuine message must verify");
        assert_eq!(calls[0]["action"], "a&b<c>A\u{e9}");
        assert_eq!(calls[0]["metadata"]["note"], "a&b<c>A\u{e9}");
        assert_eq!(delivery.acked.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn genuine_message_with_floats_big_integers_and_integer_like_keys_verifies() {
        // An audit event whose `metadata` holds a float `1.0`, an integer above
        // 2^53 and keys that sort differently as numbers and as strings: a
        // verifier that re-encoded numbers or re-ordered keys would reject it.
        let key = b"declaration-order-signing-key";
        let canonical = format!(
            concat!(
                "{{\"tenant_id\":\"22222222-2222-2222-2222-222222222222\",",
                "\"actor_id\":\"33333333-3333-3333-3333-333333333333\",",
                "\"actor_type\":\"User\",\"action\":\"user.login\",\"outcome\":\"Success\",",
                "\"metadata\":{{\"10\":1,\"9\":2,\"ratio\":1.0,\"big\":9007199254740993}},",
                "\"key_version\":2,\"nonce\":\"14141414-1414-1414-1414-141414141414\",",
                "\"issued_at\":\"{}\"}}"
            ),
            Utc::now().to_rfc3339()
        );
        let sig = sign_payload(key, canonical.as_bytes());
        let (calls, delivery) = dispatch_as(
            key,
            wire_bytes_with_signature(&canonical, &sig),
            &AUDIT_TARGET,
        )
        .await;
        assert_eq!(calls.len(), 1, "a genuine message must verify");
        assert_eq!(
            calls[0]["metadata"]["big"].as_u64(),
            Some(9_007_199_254_740_993)
        );
        assert_eq!(delivery.acked.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn duplicate_key_or_trailing_content_is_nacked_and_the_handler_never_runs() {
        let key = b"declaration-order-signing-key";
        let canonical = authz_canonical(2, "13131313-1313-1313-1313-131313131313", Utc::now());
        let sig = sign_payload(key, canonical.as_bytes());
        let genuine = wire_bytes_with_signature(&canonical, &sig);

        // A duplicate key, signed over what a re-serializing verifier would
        // have produced (the last value, in the first one's position).
        let dup_canonical = canonical.replace("\"read\"", "\"write\"");
        let dup_sig = sign_payload(key, dup_canonical.as_bytes());
        let dup = wire_bytes_with_signature(
            &dup_canonical.replace(
                "\"action\":\"write\"",
                "\"action\":\"read\",\"action\":\"write\"",
            ),
            &dup_sig,
        );
        // The same duplicate, signed over the received bytes.
        let dup_received = wire_bytes_with_signature(
            &canonical.replace(
                "\"action\":\"read\"",
                "\"action\":\"read\",\"action\":\"write\"",
            ),
            &sign_payload(
                key,
                canonical
                    .replace(
                        "\"action\":\"read\"",
                        "\"action\":\"read\",\"action\":\"write\"",
                    )
                    .as_bytes(),
            ),
        );
        let mut trailing_garbage = genuine.clone();
        trailing_garbage.extend_from_slice(b"x");
        let mut trailing_object = genuine.clone();
        trailing_object.extend_from_slice(b"{}");

        for (name, data) in [
            ("duplicate key, signed over the deduplicated form", dup),
            (
                "duplicate key, signed over the received bytes",
                dup_received,
            ),
            ("trailing garbage", trailing_garbage),
            ("trailing object", trailing_object),
        ] {
            let (calls, delivery) = dispatch(key, data).await;
            assert!(calls.is_empty(), "{name}: the handler must not run");
            assert_eq!(
                delivery.nacked_requeue_false.load(Ordering::SeqCst),
                1,
                "{name}: nacked without requeue"
            );
            assert_eq!(delivery.acked.load(Ordering::SeqCst), 0, "{name}");
        }
        // The undamaged message still verifies.
        let (calls, _) = dispatch(key, genuine).await;
        assert_eq!(calls.len(), 1);
    }

    // --- contract 1.69 §8 steps 2a-2g: received-bytes verification ----------

    /// The server-produced vectors: the subkey and the parsed fixture.
    fn vectors() -> (Vec<u8>, serde_json::Value) {
        let fixture: serde_json::Value = serde_json::from_str(REFERENCE_VECTORS_JSON).unwrap();
        let subkey = hex::decode(fixture["hkdf"]["derived_subkey_hex"].as_str().unwrap()).unwrap();
        (subkey, fixture)
    }

    /// The consumer configured for a fixture vector's own type.
    fn fixture_target(message_type: &str) -> &'static ConsumerTarget<'static> {
        if message_type == "authz_request" {
            &AUTHZ_TARGET
        } else {
            &AUDIT_TARGET
        }
    }

    /// `dispatch` with a skew wide enough for the fixture's fixed `issued_at`.
    async fn dispatch_fixture(
        key: &[u8],
        data: Vec<u8>,
        target: &ConsumerTarget<'_>,
    ) -> (Vec<serde_json::Value>, RecordingDelivery) {
        let delivery = RecordingDelivery::new(data);
        let replay = ReplayGuard::new(chrono::Duration::days(3650));
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink = Arc::clone(&seen);
        let handler = move |value: serde_json::Value| {
            let sink = Arc::clone(&sink);
            async move { sink.lock().unwrap().push(value) }
        };
        verify_and_dispatch(&delivery, key, target, &handler, &replay).await;
        let calls = seen.lock().unwrap().clone();
        (calls, delivery)
    }

    #[tokio::test]
    async fn fixture_wire_json_is_cut_verified_laid_out_and_dispatched() {
        let (subkey, fixture) = vectors();
        for message_type in ["authz_request", "audit_event"] {
            let vector = &fixture[message_type];
            let wire = vector["wire_json"].as_str().unwrap();
            let canonical = vector["canonical_signed_json"].as_str().unwrap();
            let sig = vector["hmac_signature_hex"].as_str().unwrap();
            let (cut, cut_sig) =
                crate::amqp::authz_requester::cut_trailing_signature(wire.as_bytes())
                    .unwrap_or_else(|| panic!("{message_type}: wire_json must cut"));
            assert_eq!(cut, canonical.as_bytes(), "{message_type}");
            assert_eq!(cut_sig, sig, "{message_type}");

            let target = fixture_target(message_type);
            let (calls, delivery) =
                dispatch_fixture(&subkey, wire.as_bytes().to_vec(), target).await;
            assert_eq!(calls.len(), 1, "{message_type}: dispatched");
            // The handler gets the value decoded from the verified canonical bytes.
            assert_eq!(
                calls[0],
                serde_json::from_str::<serde_json::Value>(canonical).unwrap(),
                "{message_type}"
            );
            assert_eq!(delivery.acked.load(Ordering::SeqCst), 1, "{message_type}");
        }
    }

    #[tokio::test]
    async fn the_fixtures_sorted_message_member_is_not_wire_bytes_and_is_refused() {
        let (subkey, fixture) = vectors();
        for message_type in ["authz_request", "audit_event"] {
            let data = serde_json::to_vec(&fixture[message_type]["message"]).unwrap();
            let target = fixture_target(message_type);
            let (calls, delivery) = dispatch_fixture(&subkey, data, target).await;
            assert!(calls.is_empty(), "{message_type}");
            assert_eq!(delivery.nacked_requeue_false.load(Ordering::SeqCst), 1);
        }
    }

    /// Every body below is refused: nacked without requeue, handler never runs.
    async fn assert_all_refused(key: &[u8], cases: Vec<(&str, Vec<u8>)>) {
        for (name, data) in cases {
            let (calls, delivery) = dispatch(key, data).await;
            assert!(calls.is_empty(), "{name}: the handler must not run");
            assert_eq!(
                delivery.nacked_requeue_false.load(Ordering::SeqCst),
                1,
                "{name}: nacked without requeue"
            );
            assert_eq!(
                delivery.nacked_requeue_true.load(Ordering::SeqCst),
                0,
                "{name}"
            );
            assert_eq!(delivery.acked.load(Ordering::SeqCst), 0, "{name}");
        }
    }

    #[tokio::test]
    async fn ambiguous_or_malformed_envelopes_are_refused() {
        let key = b"declaration-order-signing-key";
        let canonical = authz_canonical(2, "15151515-1515-1515-1515-151515151515", Utc::now());
        let sig = sign_payload(key, canonical.as_bytes());
        let genuine = wire_bytes_with_signature(&canonical, &sig);
        let signed = |c: &str| wire_bytes_with_signature(c, &sign_payload(key, c.as_bytes()));

        let mut trailing_ws = genuine.clone();
        trailing_ws.push(b'\n');
        let null_sig = format!(
            "{{{},\"hmac_signature\":null}}",
            &canonical[1..canonical.len() - 1]
        );
        let nested_dup = canonical.replacen(
            "\"action\":\"read\"",
            "\"action\":\"read\",\"x\":{\"y\":1,\"y\":2}",
            1,
        );
        // Two top-level names that fold together.
        let folded = canonical.replacen("\"action\"", "\"ACTION\":\"w\",\"action\"", 1);

        assert_all_refused(
            key,
            vec![
                ("trailing whitespace", trailing_ws),
                ("hmac_signature null", null_sig.into_bytes()),
                ("nested duplicate member", signed(&nested_dup)),
                ("names that fold together", signed(&folded)),
                ("a bare, unsigned body", canonical.clone().into_bytes()),
            ],
        )
        .await;
        assert_eq!(dispatch(key, genuine).await.0.len(), 1);
    }

    #[tokio::test]
    async fn layout_violations_are_refused_even_when_validly_signed() {
        let key = b"declaration-order-signing-key";
        let now = Utc::now();
        let canonical = authz_canonical(2, "16161616-1616-1616-1616-161616161616", now);
        let signed = |c: &str| wire_bytes_with_signature(c, &sign_payload(key, c.as_bytes()));

        // Declared members, wrong order.
        let reordered = canonical.replacen(
            "\"correlation_id\":\"11111111-1111-1111-1111-111111111111\",\"tenant_id\":\"22222222-2222-2222-2222-222222222222\"",
            "\"tenant_id\":\"22222222-2222-2222-2222-222222222222\",\"correlation_id\":\"11111111-1111-1111-1111-111111111111\"",
            1,
        );
        assert_ne!(reordered, canonical);
        // A member the type does not declare.
        let extra = canonical.replacen("\"action\"", "\"extra\":1,\"action\"", 1);
        // A required member missing.
        let missing = canonical.replacen(
            "\"subject_id\":\"33333333-3333-3333-3333-333333333333\",",
            "",
            1,
        );
        // Another signed message type: an AuthzResponse, and a cache-invalidation shape
        // that does carry valid v2 replay fields.
        let response = r#"{"correlation_id":"22222222-2222-2222-2222-222222222222","allowed":true,"reason_code":"allowed","tenant_id":"11111111-1111-1111-1111-111111111111","nonce":"55555555-5555-5555-5555-555555555555"}"#;
        let invalidation = format!(
            "{{\"event\":\"cache.invalidate\",\"tenant_id\":\"11111111-1111-1111-1111-111111111111\",\"key_version\":2,\"nonce\":\"17171717-1717-1717-1717-171717171717\",\"issued_at\":\"{}\"}}",
            now.to_rfc3339()
        );

        assert_all_refused(
            key,
            vec![
                ("reordered members", signed(&reordered)),
                ("undeclared member", signed(&extra)),
                ("required member missing", signed(&missing)),
                ("signed AuthzResponse", signed(response)),
                ("cache-invalidation shape", signed(&invalidation)),
            ],
        )
        .await;
    }

    // --- NEW-4: v2 replay-protection gate tests -----------------------------

    #[tokio::test]
    async fn key_version_below_minimum_is_rejected_even_with_valid_signature() {
        let key = b"declaration-order-signing-key";
        // key_version = 1 predates NEW-4; the HMAC over this body is
        // perfectly valid, but the hard-cutover gate must still reject it.
        let canonical = authz_canonical(1, "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", Utc::now());
        let sig = sign_payload(key, canonical.as_bytes());
        let data = wire_bytes_with_signature(&canonical, &sig);
        let delivery = RecordingDelivery::new(data);
        let replay = ReplayGuard::with_default_skew();

        let handler_calls = Arc::new(AtomicUsize::new(0));
        let handler_calls_clone = Arc::clone(&handler_calls);
        let handler = move |_value: serde_json::Value| {
            let calls = Arc::clone(&handler_calls_clone);
            async move {
                calls.fetch_add(1, Ordering::SeqCst);
            }
        };

        verify_and_dispatch(&delivery, key, &AUTHZ_TARGET, &handler, &replay).await;

        assert_eq!(
            handler_calls.load(Ordering::SeqCst),
            0,
            "key_version < 2 must be rejected even when the signature verifies (NEW-4 hard cutover)"
        );
        assert_eq!(delivery.nacked_requeue_false.load(Ordering::SeqCst), 1);
        assert_eq!(delivery.nacked_requeue_true.load(Ordering::SeqCst), 0);
        assert_eq!(delivery.acked.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn stale_issued_at_is_rejected_even_with_valid_signature() {
        let key = b"declaration-order-signing-key";
        // 10 minutes in the past — outside the default ±5 minute skew.
        let stale = Utc::now() - chrono::Duration::minutes(10);
        let canonical = authz_canonical(2, "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", stale);
        let sig = sign_payload(key, canonical.as_bytes());
        let data = wire_bytes_with_signature(&canonical, &sig);
        let delivery = RecordingDelivery::new(data);
        let replay = ReplayGuard::with_default_skew();

        let handler_calls = Arc::new(AtomicUsize::new(0));
        let handler_calls_clone = Arc::clone(&handler_calls);
        let handler = move |_value: serde_json::Value| {
            let calls = Arc::clone(&handler_calls_clone);
            async move {
                calls.fetch_add(1, Ordering::SeqCst);
            }
        };

        verify_and_dispatch(&delivery, key, &AUTHZ_TARGET, &handler, &replay).await;

        assert_eq!(
            handler_calls.load(Ordering::SeqCst),
            0,
            "a stale issued_at (outside the freshness skew) must be rejected"
        );
        assert_eq!(delivery.nacked_requeue_false.load(Ordering::SeqCst), 1);
        assert_eq!(delivery.acked.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn replayed_nonce_is_rejected_on_second_delivery() {
        let key = b"declaration-order-signing-key";
        let nonce = "cccccccc-cccc-cccc-cccc-cccccccccccc";
        let canonical = authz_canonical(2, nonce, Utc::now());
        let sig = sign_payload(key, canonical.as_bytes());
        // Same ReplayGuard for both deliveries — the nonce dedup only works
        // if state is retained across messages on the same consumer.
        let replay = ReplayGuard::with_default_skew();

        let handler_calls = Arc::new(AtomicUsize::new(0));
        let handler_calls_clone = Arc::clone(&handler_calls);
        let handler = move |_value: serde_json::Value| {
            let calls = Arc::clone(&handler_calls_clone);
            async move {
                calls.fetch_add(1, Ordering::SeqCst);
            }
        };

        let first_delivery = RecordingDelivery::new(wire_bytes_with_signature(&canonical, &sig));
        verify_and_dispatch(&first_delivery, key, &AUTHZ_TARGET, &handler, &replay).await;
        assert_eq!(
            handler_calls.load(Ordering::SeqCst),
            1,
            "the first delivery of a fresh nonce must be accepted"
        );
        assert_eq!(first_delivery.acked.load(Ordering::SeqCst), 1);

        // Replay: identical body + signature, same nonce, delivered again.
        let second_delivery = RecordingDelivery::new(wire_bytes_with_signature(&canonical, &sig));
        verify_and_dispatch(&second_delivery, key, &AUTHZ_TARGET, &handler, &replay).await;

        assert_eq!(
            handler_calls.load(Ordering::SeqCst),
            1,
            "a replayed nonce must not reach the handler a second time"
        );
        assert_eq!(
            second_delivery.nacked_requeue_false.load(Ordering::SeqCst),
            1
        );
        assert_eq!(second_delivery.acked.load(Ordering::SeqCst), 0);
    }

    // --- NEW-4: byte-for-byte parity against the server reference vectors --
    //
    // `testdata/v2_reference_vectors.json` is GENERATED by the AXIAM server
    // sign path (`axiam-amqp::messages`) and vendored into this repo verbatim.
    // It is the ground truth every SDK's HMAC implementation must reproduce
    // exactly (CONTRACT.md §8 "Canonical reference vectors"). It carries, per
    // message type, the exact canonical signed JSON bytes, the resulting hex
    // HMAC, and the HKDF-derived per-tenant subkey used to compute it.
    // Re-vendor it from the server repo whenever §8 changes.
    const REFERENCE_VECTORS_JSON: &str = include_str!("../../testdata/v2_reference_vectors.json");

    fn hex_decode(s: &str) -> Vec<u8> {
        hex::decode(s).expect("fixture hex field must decode")
    }

    #[test]
    fn fixture_v2_reference_vectors_hmac_byte_parity() {
        let fixture: serde_json::Value =
            serde_json::from_str(REFERENCE_VECTORS_JSON).expect("fixture must parse as JSON");
        let subkey = hex_decode(
            fixture["hkdf"]["derived_subkey_hex"]
                .as_str()
                .expect("hkdf.derived_subkey_hex present"),
        );

        for message_type in ["authz_request", "audit_event"] {
            let vector = &fixture[message_type];
            let canonical = vector["canonical_signed_json"]
                .as_str()
                .unwrap_or_else(|| panic!("{message_type}.canonical_signed_json present"));
            let expected_hmac = vector["hmac_signature_hex"]
                .as_str()
                .unwrap_or_else(|| panic!("{message_type}.hmac_signature_hex present"));

            let sig = sign_payload(&subkey, canonical.as_bytes());
            assert_eq!(
                sig, expected_hmac,
                "{message_type}: SDK sign_payload output must be byte-for-byte identical to \
                 the server-generated reference vector"
            );
            assert!(
                verify_payload(&subkey, canonical.as_bytes(), expected_hmac),
                "{message_type}: the server-generated signature must verify against the same \
                 derived subkey + canonical bytes"
            );
        }
    }

    #[tokio::test]
    async fn fixture_v2_reference_vector_authz_request_accepted_by_consumer() {
        let fixture: serde_json::Value =
            serde_json::from_str(REFERENCE_VECTORS_JSON).expect("fixture must parse as JSON");
        let vector = &fixture["authz_request"];
        let canonical = vector["canonical_signed_json"]
            .as_str()
            .expect("authz_request.canonical_signed_json present");
        let expected_hmac = vector["hmac_signature_hex"]
            .as_str()
            .expect("authz_request.hmac_signature_hex present");
        let subkey = hex_decode(
            fixture["hkdf"]["derived_subkey_hex"]
                .as_str()
                .expect("hkdf.derived_subkey_hex present"),
        );

        let data = wire_bytes_with_signature(canonical, expected_hmac);
        let delivery = RecordingDelivery::new(data);
        // The fixture's `issued_at` (2026-07-10T12:00:00Z) is a fixed
        // historical timestamp baked into the reference vectors. This test
        // exercises HMAC/structure acceptance through the full dispatch
        // pipeline, NOT the freshness gate (covered independently by
        // `stale_issued_at_is_rejected_even_with_valid_signature`), so use a
        // generous skew that tolerates the gap between the fixture's
        // timestamp and whenever this test actually runs.
        let replay = ReplayGuard::new(chrono::Duration::days(3650));

        let handler_calls = Arc::new(AtomicUsize::new(0));
        let handler_calls_clone = Arc::clone(&handler_calls);
        let handler = move |_value: serde_json::Value| {
            let calls = Arc::clone(&handler_calls_clone);
            async move {
                calls.fetch_add(1, Ordering::SeqCst);
            }
        };

        verify_and_dispatch(&delivery, &subkey, &AUTHZ_TARGET, &handler, &replay).await;

        assert_eq!(
            handler_calls.load(Ordering::SeqCst),
            1,
            "a genuine server-signed v2 reference vector must be accepted end-to-end"
        );
        assert_eq!(delivery.acked.load(Ordering::SeqCst), 1);
        assert_eq!(delivery.nacked_requeue_false.load(Ordering::SeqCst), 0);
    }

    // --- `consume()` pre-connect validation (X-2) --------------------------
    //
    // `consume()` runs the X-2 plaintext-scheme guard BEFORE attempting the
    // AMQP broker connection, so its rejection path is reachable without a
    // live RabbitMQ instance — unlike the rest of `consume()` (the actual
    // `Connection::connect`/consume loop), which needs one and is therefore
    // exercised by CI's integration environment, not this unit test binary.

    #[tokio::test]
    async fn consume_rejects_plaintext_amqp_url_against_a_routable_host() {
        let err = consume(
            "amqp://rabbitmq.example.com:5672",
            "test-queue",
            Sensitive::new(b"irrelevant-signing-key".to_vec()),
            ConsumerTarget {
                tenant_id: CONSUMER_TENANT,
                event_type: EventType::AuthzRequest,
            },
            None,
            |_value: serde_json::Value| async {},
        )
        .await
        .expect_err(
            "plaintext amqp:// against a routable host must be rejected before connecting (X-2)",
        );

        match err {
            AxiamError::Network { message, .. } => {
                assert!(message.contains("amqps"), "message: {message}");
            }
            other => panic!("expected Network error, got {other:?}"),
        }
    }

    /// §8b has no loopback carve-out, unlike §6's rule for REST and gRPC.
    ///
    /// This test previously asserted the opposite: it bound an ephemeral
    /// loopback port, dropped it, and checked that `consume()` got as far as a
    /// connection failure — "proving the X-2 guard's loopback exception let
    /// control through". That exception is gone for AMQP. §8b rules 1 and 5 are
    /// unconditional, the five other SDKs that ship AMQP dialers enforce them
    /// with no host exception, and since the server became TLS-only there is no
    /// plaintext loopback broker left to reach.
    ///
    /// The assertion is now that no socket is attempted at all — the URL is
    /// refused on its scheme, and the port never enters into it.
    #[tokio::test]
    async fn consume_rejects_plaintext_amqp_url_on_loopback_too() {
        for url in [
            "amqp://localhost:5672",
            "amqp://127.0.0.1:5672",
            "amqp://[::1]:5672",
        ] {
            let err = consume(
                url,
                "test-queue",
                Sensitive::new(b"irrelevant-signing-key".to_vec()),
                ConsumerTarget {
                    tenant_id: CONSUMER_TENANT,
                    event_type: EventType::AuthzRequest,
                },
                None,
                |_value: serde_json::Value| async {},
            )
            .await
            .expect_err("plaintext is refused on loopback too (§8b rules 1 and 5)");

            match err {
                AxiamError::Network { message, .. } => assert!(
                    message.contains("amqps://"),
                    "the error must name the scheme to use, got: {message}"
                ),
                other => panic!("expected Network error, got {other:?}"),
            }
        }
    }

    /// Regression: the guard used to be `if let Ok(parsed) = Url::parse(..)`,
    /// so a URL that failed to parse skipped it entirely and went straight to
    /// lapin. A security check must fail closed on an input it cannot read.
    #[tokio::test]
    async fn consume_rejects_an_unparseable_url_rather_than_dialling_it() {
        for url in ["", "not a url at all", "://broker"] {
            let err = consume(
                url,
                "test-queue",
                Sensitive::new(b"irrelevant-signing-key".to_vec()),
                ConsumerTarget {
                    tenant_id: CONSUMER_TENANT,
                    event_type: EventType::AuthzRequest,
                },
                None,
                |_value: serde_json::Value| async {},
            )
            .await
            .expect_err("an unparseable url must fail closed");
            assert!(
                matches!(err, AxiamError::Network { .. }),
                "got {err:?} for {url:?}"
            );
        }
    }

    // --- v2 replay-protection field extraction/validation ------------------

    #[test]
    fn decode_refuses_a_missing_or_ill_typed_v2_member() {
        let ok = |nonce: &str, issued_at: &str, key_version: &str| {
            format!(
                concat!(
                    "{{\"correlation_id\":\"22222222-2222-2222-2222-222222222222\",",
                    "\"tenant_id\":\"11111111-1111-1111-1111-111111111111\",",
                    "\"subject_id\":\"33333333-3333-3333-3333-333333333333\",\"action\":\"read\",",
                    "\"resource_id\":\"44444444-4444-4444-4444-444444444444\",",
                    "\"key_version\":{},\"nonce\":\"{}\",\"issued_at\":\"{}\"}}"
                ),
                key_version, nonce, issued_at
            )
        };
        let good_nonce = "55555555-5555-5555-5555-555555555555";
        let good_at = "2026-07-10T12:00:00Z";
        assert!(
            EventType::AuthzRequest
                .decode(ok(good_nonce, good_at, "2").as_bytes())
                .is_some()
        );
        for (what, body) in [
            ("nonce not a UUID", ok("some-nonce", good_at, "2")),
            (
                "issued_at not RFC 3339",
                ok(good_nonce, "not-a-timestamp", "2"),
            ),
            (
                "key_version wrong JSON type",
                ok(good_nonce, good_at, "\"2\""),
            ),
        ] {
            assert!(
                EventType::AuthzRequest.decode(body.as_bytes()).is_none(),
                "{what}"
            );
        }
    }

    #[test]
    fn gates_apply_in_order_and_record_the_nonce_last() {
        let replay = ReplayGuard::with_default_skew();
        let fields = |key_version, age_secs: i64| ReplayFields {
            key_version,
            nonce: "n-1".into(),
            issued_at: Utc::now() - chrono::Duration::seconds(age_secs),
        };
        // (6) before (7): a v1 message that is also stale is `key_version`.
        assert_eq!(
            validate_v2_replay_protection(&fields(1, 100_000), &replay),
            Err(DiscardReason::KeyVersion)
        );
        // (7) before (8), and a stale message leaves no nonce behind.
        assert_eq!(
            validate_v2_replay_protection(&fields(2, 100_000), &replay),
            Err(DiscardReason::Stale)
        );
        assert_eq!(
            validate_v2_replay_protection(&fields(2, 0), &replay),
            Ok(())
        );
        assert_eq!(
            validate_v2_replay_protection(&fields(2, 0), &replay),
            Err(DiscardReason::Replay)
        );
    }

    #[test]
    fn replay_guard_ttl_does_not_panic_on_an_extreme_skew() {
        // `chrono::Duration::MAX * 2` overflows `std::time::Duration`; the
        // fallback branch in `ReplayGuard::ttl()` must be taken instead of
        // panicking.
        let guard = ReplayGuard::new(chrono::Duration::MAX);
        let ttl = guard.ttl();
        assert!(ttl.as_secs() > 0);
    }

    // --- contract 1.69 (D-8, D-9, D-10): typed consume, discard event, BOM ---

    /// The `reason`, exchange, routing key and tenant of the single event this
    /// thread logged, and the whole captured text for exclusion checks.
    fn one_discard_event() -> (String, String) {
        let events = THREAD_EVENTS.with(|e| e.borrow().clone());
        assert_eq!(events.len(), 1, "exactly one event per discard: {events:?}");
        let text = events[0].clone();
        (text.clone(), text)
    }

    fn event_field<'a>(event: &'a str, name: &str) -> &'a str {
        let marker = format!("{name}=");
        let start = event
            .find(&marker)
            .unwrap_or_else(|| panic!("event has no {name}: {event}"))
            + marker.len();
        let rest = &event[start..];
        rest[..rest.find(' ').unwrap_or(rest.len())].trim_matches('"')
    }

    /// Flip the last hex digit of the trailing signature.
    fn with_signature_digit_changed(wire: &str) -> Vec<u8> {
        let mut bytes = wire.as_bytes().to_vec();
        let at = bytes.len() - 3; // `...<hex>"}`: the last hex digit
        bytes[at] = if bytes[at] == b'0' { b'1' } else { b'0' };
        bytes
    }

    #[tokio::test]
    async fn each_vectors_wire_json_is_malformed_for_the_other_types_consumer() {
        let (subkey, fixture) = vectors();
        for (message_type, other) in [
            ("audit_event", &AUTHZ_TARGET),
            ("authz_request", &AUDIT_TARGET),
        ] {
            let wire = fixture[message_type]["wire_json"].as_str().unwrap();
            for (what, data) in [
                ("genuine", wire.as_bytes().to_vec()),
                // The typed check precedes the HMAC: still `malformed`, not `signature`.
                (
                    "signature digit changed",
                    with_signature_digit_changed(wire),
                ),
            ] {
                init_recording_subscriber();
                let (calls, delivery) = dispatch_fixture(&subkey, data, other).await;
                assert!(calls.is_empty(), "{message_type} {what}: never handed on");
                assert_eq!(delivery.nacked_requeue_false.load(Ordering::SeqCst), 1);
                assert_eq!(delivery.acked.load(Ordering::SeqCst), 0);
                let (event, _) = one_discard_event();
                assert_eq!(
                    event_field(&event, "reason"),
                    "malformed",
                    "{message_type} {what}"
                );
            }
        }
    }

    #[tokio::test]
    async fn the_discard_event_carries_exchange_routing_key_and_the_configured_tenant_only() {
        let (subkey, fixture) = vectors();
        let wire = fixture["audit_event"]["wire_json"].as_str().unwrap();
        let sig = fixture["audit_event"]["hmac_signature_hex"]
            .as_str()
            .unwrap();
        let nonce = fixture["audit_event"]["message"]["nonce"].as_str().unwrap();
        let body_tenant = fixture["audit_event"]["message"]["tenant_id"]
            .as_str()
            .unwrap();
        assert_ne!(
            body_tenant, CONSUMER_TENANT,
            "the body's tenant is a different one"
        );

        let unsigned = wire.replace(&format!(",\"hmac_signature\":\"{sig}\""), "");
        let wrong_sig = with_signature_digit_changed(wire);
        for (reason, data, target) in [
            ("malformed", wire.as_bytes().to_vec(), &AUTHZ_TARGET), // typed
            ("unsigned", unsigned.into_bytes(), &AUDIT_TARGET),
            ("signature", wrong_sig, &AUDIT_TARGET),
        ] {
            init_recording_subscriber();
            let (calls, _) = dispatch_fixture(&subkey, data, target).await;
            assert!(calls.is_empty(), "{reason}");
            let (event, _) = one_discard_event();
            assert_eq!(event_field(&event, "reason"), reason);
            assert_eq!(event_field(&event, "exchange"), "axiam.test.exchange");
            assert_eq!(event_field(&event, "routing_key"), "axiam.test.routing");
            assert_eq!(event_field(&event, "tenant_id"), CONSUMER_TENANT);
            assert!(event.contains("timestamp="), "{event}");
            for secret in [sig, nonce, body_tenant] {
                assert!(
                    !event.contains(secret),
                    "{reason}: the event leaks {secret}"
                );
            }
        }
    }

    #[tokio::test]
    async fn a_byte_order_mark_or_any_prefix_is_malformed_and_the_next_delivery_is_processed() {
        let (subkey, fixture) = vectors();
        let key = &subkey[..];
        for message_type in ["authz_request", "audit_event"] {
            let wire = fixture[message_type]["wire_json"].as_str().unwrap();
            let target = fixture_target(message_type);
            for (what, prefix) in [
                ("byte-order mark", &b"\xEF\xBB\xBF"[..]),
                ("space", b" "),
                ("newline", b"\n"),
                ("NUL", b"\0"),
            ] {
                init_recording_subscriber();
                let mut data = prefix.to_vec();
                data.extend_from_slice(wire.as_bytes());
                let (calls, delivery) = dispatch_fixture(key, data, target).await;
                assert!(calls.is_empty(), "{message_type} {what}");
                assert_eq!(delivery.nacked_requeue_false.load(Ordering::SeqCst), 1);
                let (event, _) = one_discard_event();
                assert_eq!(event_field(&event, "reason"), "malformed", "{what}");
            }
            // The very next delivery is processed.
            let (calls, delivery) = dispatch_fixture(key, wire.as_bytes().to_vec(), target).await;
            assert_eq!(calls.len(), 1, "{message_type}: next delivery processed");
            assert_eq!(delivery.acked.load(Ordering::SeqCst), 1);
        }
    }

    #[tokio::test]
    async fn arbitrary_bodies_never_panic_and_are_each_one_malformed_or_unsigned_event() {
        let key = b"consumer-test-signing-key";
        let deep = format!("{{\"a\":{}1{}}}", "[".repeat(100_000), "]".repeat(100_000));
        let cases: Vec<(&str, Vec<u8>, &str)> = vec![
            ("empty", vec![], "malformed"),
            ("not UTF-8", vec![b'{', 0xFF, 0xFE, b'}'], "malformed"),
            ("lone brace", b"{".to_vec(), "malformed"),
            ("array", b"[1]".to_vec(), "malformed"),
            ("deep nesting", deep.into_bytes(), "malformed"),
            (
                "object without signature",
                br#"{"a":1}"#.to_vec(),
                "unsigned",
            ),
            // `unsigned` is position (2): it wins over a missing layout.
            ("empty object", b"{}".to_vec(), "unsigned"),
            (
                "null signature",
                br#"{"hmac_signature":null}"#.to_vec(),
                "malformed",
            ),
        ];
        for (what, data, reason) in cases {
            init_recording_subscriber();
            let (calls, delivery) = dispatch(key, data).await;
            assert!(calls.is_empty(), "{what}");
            assert_eq!(
                delivery.nacked_requeue_false.load(Ordering::SeqCst),
                1,
                "{what}"
            );
            let (event, _) = one_discard_event();
            assert_eq!(event_field(&event, "reason"), reason, "{what}");
        }
    }

    #[tokio::test]
    async fn the_event_reasons_follow_the_normative_order() {
        let key = b"consumer-test-signing-key";
        let fresh = Utc::now();
        let stale = fresh - chrono::Duration::hours(2);
        let nonce = "66666666-6666-6666-6666-666666666666";
        let sign = |canonical: String| {
            let sig = sign_payload(key, canonical.as_bytes());
            wire_bytes_with_signature(&canonical, &sig)
        };
        // (5) decode failure after a good HMAC: the nonce is not a UUID.
        let undecodable = sign(authz_canonical(2, "not-a-uuid", fresh));
        // (6) wins over (7): v1 and stale.
        let v1_and_stale = sign(authz_canonical(1, nonce, stale));
        // (7)
        let stale_only = sign(authz_canonical(2, nonce, stale));
        // (8): same body twice on one guard.
        let replayed = sign(authz_canonical(2, nonce, fresh));
        let replay = ReplayGuard::with_default_skew();
        let handler = |_v: serde_json::Value| async {};
        for (reason, data) in [
            ("malformed", undecodable),
            ("key_version", v1_and_stale),
            ("stale", stale_only.clone()),
            ("stale", stale_only), // a stale message left no nonce behind
            ("replay", replayed.clone()),
        ] {
            if reason == "replay" {
                let accepted = RecordingDelivery::new(data.clone());
                verify_and_dispatch(&accepted, key, &AUTHZ_TARGET, &handler, &replay).await;
                assert_eq!(accepted.acked.load(Ordering::SeqCst), 1);
            }
            init_recording_subscriber();
            let delivery = RecordingDelivery::new(data);
            verify_and_dispatch(&delivery, key, &AUTHZ_TARGET, &handler, &replay).await;
            assert_eq!(
                delivery.nacked_requeue_false.load(Ordering::SeqCst),
                1,
                "{reason}"
            );
            let (event, _) = one_discard_event();
            assert_eq!(event_field(&event, "reason"), reason);
        }
    }
}
