//! The AMQP authorization requester (CONTRACT.md §8, "Signed authorization
//! responses", contract 1.68; N2, D-9).
//!
//! [`AuthzRequester`] publishes an `AuthzRequest` on `axiam.authz.request`
//! with a private, exclusive, broker-named `reply_to` queue, and accepts an
//! answer only when it verifies as the server's signed response to **that**
//! request.
//!
//! The rule that decides the design: **verify the received bytes and deliver
//! the same bytes** (the C2 lesson). The signature is checked over the
//! delivery body with its trailing `hmac_signature` member cut out, never
//! over a re-serialization, and the decision handed to the caller is decoded
//! from those same canonical bytes.
//!
//! # What a caller gets
//!
//! - `reply_to` is a queue declared `exclusive` and `auto-delete` with a
//!   broker-chosen name (`amq.gen-…`); only this requester consumes it. A
//!   configured name that is empty or starts with `axiam.` is refused, since
//!   the server does not honour it (§8 consumer rule 5).
//! - `correlation_id` and `nonce` are fresh random UUIDs per request
//!   (independent of each other).
//! - A response that fails the strict parse, the signature or the binding is
//!   nacked without requeue, logged as a security event (never with a
//!   signature value), is **never** an allow, and does **not** complete the
//!   request: [`AuthzRequester::check`] keeps waiting for the genuine answer.
//! - Responses that carry no signature are refused unless
//!   [`AuthzRequesterOptions::allow_unsigned_responses`] is set; that opt-out
//!   never admits a response that carries a signature member and fails.

use std::collections::HashMap;
use std::fmt;
use std::future::{Future, ready};
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use chrono::{SubsecRound, Utc};
use futures_util::{Stream, StreamExt};
use lapin::options::{BasicConsumeOptions, BasicPublishOptions, QueueDeclareOptions};
use lapin::types::FieldTable;
use lapin::{BasicProperties, Channel, Connection};
use serde::Deserialize;
use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Value};
use tokio::sync::{oneshot, watch};
use uuid::Uuid;

use crate::amqp::consumer::AckableDelivery;
use crate::amqp::hmac::{sign_payload, verify_payload};
use crate::amqp::messages::AuthzRequest;
use crate::amqp::transport::{AmqpTlsConfig, connect_amqps};
use crate::error::AxiamError;
use crate::sensitive::Sensitive;

/// The queue the server consumes `AuthzRequest` from.
pub const AUTHZ_REQUEST_QUEUE: &str = "axiam.authz.request";

/// The signing-key version this requester sends. The response carries no
/// `key_version`; the requester verifies with the one it sent (§8).
const AUTHZ_KEY_VERSION: u8 = 2;

/// Bound on one [`AuthzRequester::check`] when the caller sets none.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

/// Prefix of the server's own queues; a `reply_to` naming one is not honoured.
const SERVER_QUEUE_PREFIX: &str = "axiam.";

/// `,"hmac_signature":"` — the member that ends every signed response.
const SIG_MEMBER: &[u8] = b",\"hmac_signature\":\"";
const SIG_HEX_LEN: usize = 64;

/// A verified answer to one `AuthzRequest`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthzDecision {
    /// The decision. `true` only for a response that verified under the
    /// tenant subkey (or, with the unsigned opt-out, one that carried no
    /// signature at all; see [`Self::unsigned`]).
    pub allowed: bool,
    /// The server's human-readable reason, when present.
    pub reason: Option<String>,
    /// The machine-readable code (`allowed`, `no_grant`, `denied_by_rule`,
    /// `tenant_suspended`, ...), when present. A code this SDK does not know
    /// is surfaced verbatim.
    pub reason_code: Option<String>,
    /// `true` when the response carried no `hmac_signature` and was accepted
    /// only because the unsigned opt-out is set.
    pub unsigned: bool,
}

/// Options for an [`AuthzRequester`].
#[derive(Debug, Clone, Default)]
pub struct AuthzRequesterOptions {
    allow_unsigned: bool,
    timeout: Option<Duration>,
}

impl AuthzRequesterOptions {
    /// The explicit, integrator-set opt-out for ONE rolling upgrade against a
    /// server older than contract 1.68, whose responses are unsigned. Off by
    /// default. With it set, a response that carries **no** `hmac_signature`
    /// member at all is accepted on its `correlation_id` alone (and logged as
    /// a security warning). A response that carries a signature is verified in
    /// full whatever this says, and the opt-out never admits one that fails.
    /// Remove it once the server is upgraded.
    #[must_use]
    pub fn allow_unsigned_responses(mut self) -> Self {
        self.allow_unsigned = true;
        self
    }

    /// Bound each [`AuthzRequester::check`] (default 10 s). A zero duration
    /// is ignored.
    #[must_use]
    pub fn timeout(mut self, timeout: Duration) -> Self {
        if !timeout.is_zero() {
            self.timeout = Some(timeout);
        }
        self
    }
}

type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// The publishing half of the broker seam; tests supply a fake.
pub(crate) trait ReplyPublisher: Send + Sync {
    /// Publish `body` on the default exchange with routing key `queue`,
    /// AMQP `reply_to = reply_to` and `correlation_id = correlation_id`.
    fn publish<'a>(
        &'a self,
        queue: &'a str,
        reply_to: &'a str,
        correlation_id: &'a str,
        body: Vec<u8>,
    ) -> BoxFuture<'a, Result<(), AxiamError>>;
}

struct LapinPublisher {
    channel: Channel,
}

impl ReplyPublisher for LapinPublisher {
    fn publish<'a>(
        &'a self,
        queue: &'a str,
        reply_to: &'a str,
        correlation_id: &'a str,
        body: Vec<u8>,
    ) -> BoxFuture<'a, Result<(), AxiamError>> {
        Box::pin(async move {
            self.channel
                .basic_publish(
                    "".into(),
                    queue.into(),
                    BasicPublishOptions::default(),
                    &body,
                    BasicProperties::default()
                        .with_content_type("application/json".into())
                        .with_correlation_id(correlation_id.into())
                        .with_reply_to(reply_to.into()),
                )
                .await
                .map_err(|e| AxiamError::network(format!("failed to publish authz request: {e}")))?
                .await
                .map_err(|e| {
                    AxiamError::network(format!("authz request was not confirmed: {e}"))
                })?;
            Ok(())
        })
    }
}

/// The reply queue's declaration: exclusive (only this connection consumes
/// it), auto-delete (it goes with its consumer), not durable. The name is left
/// empty so the broker picks an `amq.gen-…` one.
pub(crate) fn reply_queue_declare_options() -> QueueDeclareOptions {
    QueueDeclareOptions {
        durable: false,
        exclusive: true,
        auto_delete: true,
        ..Default::default()
    }
}

/// The reply queue's consumption: exclusive, manual acknowledgement.
pub(crate) fn reply_queue_consume_options() -> BasicConsumeOptions {
    BasicConsumeOptions {
        no_ack: false,
        exclusive: true,
        ..Default::default()
    }
}

/// Refuse a reply queue that is empty or names one of the server's own.
fn validate_reply_queue(name: &str) -> Result<(), AxiamError> {
    if name.is_empty() || name.starts_with(SERVER_QUEUE_PREFIX) {
        // The server answers such a reply_to on the shared axiam.authz.response
        // instead (§8 rule 5), which would put this requester back on the
        // shared queue the contract forbids.
        return Err(AxiamError::network(format!(
            "authz reply queue {name:?} is not a private queue"
        )));
    }
    Ok(())
}

struct Pending {
    nonce: String,
    tx: oneshot::Sender<AuthzDecision>,
}

struct Inner {
    tenant_id: Uuid,
    tenant: String,
    key: Sensitive<Vec<u8>>,
    allow_unsigned: bool,
    timeout: Duration,
    reply_to: String,
    publisher: Box<dyn ReplyPublisher>,
    pending: Mutex<HashMap<String, Pending>>,
    closed: watch::Sender<bool>,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

fn security_warn(msg: &str) {
    tracing::warn!(target: "axiam_sdk::security", "{msg}");
}

/// Publishes `AuthzRequest` messages and verifies their answers. Cheap to
/// share behind an `Arc`; many [`check`](Self::check) calls may be outstanding
/// at once.
pub struct AuthzRequester {
    inner: Arc<Inner>,
    /// Keeps the connection open when this requester dialled it itself.
    _connection: Option<Connection>,
}

impl fmt::Debug for AuthzRequester {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthzRequester")
            .field("tenant_id", &self.inner.tenant_id)
            .field("reply_to", &self.inner.reply_to)
            .finish_non_exhaustive()
    }
}

impl AuthzRequester {
    /// Open a private reply queue on `channel` and return a requester for
    /// `tenant_id`.
    ///
    /// `signing_key` is the tenant's AMQP subkey for key version 2 (§8.1);
    /// `tenant_id` is the requester's OWN tenant and the only tenant a
    /// response is accepted for. The channel should be on an `amqps://`
    /// connection (§8b); see [`AuthzRequester::connect`].
    pub async fn new(
        channel: &Channel,
        tenant_id: Uuid,
        signing_key: Sensitive<Vec<u8>>,
        options: AuthzRequesterOptions,
    ) -> Result<Self, AxiamError> {
        let queue = channel
            .queue_declare(
                "".into(),
                reply_queue_declare_options(),
                FieldTable::default(),
            )
            .await
            .map_err(|e| {
                AxiamError::network(format!("failed to declare the authz reply queue: {e}"))
            })?;
        let name = queue.name().as_str().to_string();
        validate_reply_queue(&name)?;
        let consumer = channel
            .basic_consume(
                name.clone().into(),
                "".into(),
                reply_queue_consume_options(),
                FieldTable::default(),
            )
            .await
            .map_err(|e| {
                AxiamError::network(format!("failed to consume the authz reply queue: {e}"))
            })?;
        // A consumer error ends the stream, which closes the requester.
        let deliveries = consumer
            .take_while(|d| ready(d.is_ok()))
            .filter_map(|d| ready(d.ok()));
        Self::start(
            LapinPublisher {
                channel: channel.clone(),
            },
            name,
            deliveries,
            tenant_id,
            signing_key,
            options,
            None,
        )
    }

    /// Dial `amqp_url` (which MUST be `amqps://`, §8b, checked before a socket
    /// opens) and return a requester that owns the connection.
    pub async fn connect(
        amqp_url: &str,
        tls: &AmqpTlsConfig,
        tenant_id: Uuid,
        signing_key: Sensitive<Vec<u8>>,
        options: AuthzRequesterOptions,
    ) -> Result<Self, AxiamError> {
        let connection = connect_amqps(amqp_url, tls).await?;
        let channel = connection
            .create_channel()
            .await
            .map_err(|e| AxiamError::network(format!("failed to create AMQP channel: {e}")))?;
        let mut requester = Self::new(&channel, tenant_id, signing_key, options).await?;
        requester._connection = Some(connection);
        Ok(requester)
    }

    /// Wire a requester to a publisher and a stream of deliveries from its
    /// private reply queue. The single constructor everything funnels through,
    /// so tests exercise the same code as production.
    pub(crate) fn start<P, S, D>(
        publisher: P,
        reply_queue: String,
        deliveries: S,
        tenant_id: Uuid,
        signing_key: Sensitive<Vec<u8>>,
        options: AuthzRequesterOptions,
        connection: Option<Connection>,
    ) -> Result<Self, AxiamError>
    where
        P: ReplyPublisher + 'static,
        S: Stream<Item = D> + Send + 'static,
        D: AckableDelivery + Send + Sync + 'static,
    {
        if signing_key.expose().is_empty() {
            return Err(AxiamError::network(
                "the authz requester needs the tenant signing key",
            ));
        }
        validate_reply_queue(&reply_queue)?;
        let (closed, _) = watch::channel(false);
        let inner = Arc::new(Inner {
            tenant_id,
            tenant: tenant_id.hyphenated().to_string(),
            key: signing_key,
            allow_unsigned: options.allow_unsigned,
            timeout: options.timeout.unwrap_or(DEFAULT_TIMEOUT),
            reply_to: reply_queue,
            publisher: Box::new(publisher),
            pending: Mutex::new(HashMap::new()),
            closed,
        });
        tokio::spawn(consume_loop(Arc::clone(&inner), deliveries));
        Ok(Self {
            inner,
            _connection: connection,
        })
    }

    /// The private reply queue requests name in their `reply_to`.
    pub fn reply_to(&self) -> &str {
        &self.inner.reply_to
    }

    /// Stop accepting answers. Outstanding and later [`check`](Self::check)
    /// calls fail. The reply queue is exclusive and auto-delete, so the broker
    /// removes it with the consumer.
    pub fn close(&self) {
        self.inner.closed.send_replace(true);
    }

    /// Ask the server whether `subject_id` may perform `action` on
    /// `resource_id` (optionally narrowed by one `scope`) and wait for the
    /// verified answer.
    ///
    /// A response that fails verification or binding is discarded and this
    /// keeps waiting for the genuine one until the timeout ends: a failed
    /// verification is never an allow and never completes the request.
    /// Dropping the returned future abandons the request.
    pub async fn check(
        &self,
        subject_id: Uuid,
        action: &str,
        resource_id: Uuid,
        scope: Option<&str>,
    ) -> Result<AuthzDecision, AxiamError> {
        let inner = &self.inner;
        let mut closed = inner.closed.subscribe();
        if *closed.borrow() {
            return Err(closed_error());
        }

        // Fresh, independent, unpredictable ids (v4 = OS CSPRNG).
        let correlation_id = Uuid::new_v4();
        let nonce = Uuid::new_v4();
        let body = build_authz_request(
            inner.key.expose(),
            correlation_id,
            inner.tenant_id,
            subject_id,
            action,
            resource_id,
            scope,
            nonce,
        )?;

        let key = correlation_id.hyphenated().to_string();
        let (tx, rx) = oneshot::channel();
        lock(&inner.pending).insert(
            key.clone(),
            Pending {
                nonce: nonce.hyphenated().to_string(),
                tx,
            },
        );
        // Retire the entry however this future ends (answer, timeout, drop).
        let _retire = Retire {
            inner: Arc::clone(inner),
            key: key.clone(),
        };

        let wait = async {
            inner
                .publisher
                .publish(AUTHZ_REQUEST_QUEUE, &inner.reply_to, &key, body)
                .await?;
            tokio::select! {
                answer = rx => answer.map_err(|_| closed_error()),
                _ = wait_closed(&mut closed) => Err(closed_error()),
            }
        };
        match tokio::time::timeout(inner.timeout, wait).await {
            Ok(result) => result,
            Err(_) => Err(AxiamError::network(
                "timed out waiting for a verified authz response",
            )),
        }
    }
}

impl Drop for AuthzRequester {
    fn drop(&mut self) {
        self.close();
    }
}

/// Resolve once the requester is closed. The watch guard `wait_for` returns
/// is dropped here, so it is never held across an await by a caller.
async fn wait_closed(closed: &mut watch::Receiver<bool>) {
    let _ = closed.wait_for(|c| *c).await;
}

fn closed_error() -> AxiamError {
    AxiamError::network("the authz requester is closed")
}

struct Retire {
    inner: Arc<Inner>,
    key: String,
}

impl Drop for Retire {
    fn drop(&mut self) {
        lock(&self.inner.pending).remove(&self.key);
    }
}

/// Read the private reply queue until it ends or the requester closes.
async fn consume_loop<S, D>(inner: Arc<Inner>, deliveries: S)
where
    S: Stream<Item = D> + Send + 'static,
    D: AckableDelivery + Send + Sync + 'static,
{
    let mut deliveries = Box::pin(deliveries);
    let mut closed = inner.closed.subscribe();
    loop {
        tokio::select! {
            _ = wait_closed(&mut closed) => return,
            next = deliveries.next() => match next {
                Some(delivery) => inner.handle(&delivery).await,
                None => {
                    // The queue or connection went away.
                    inner.closed.send_replace(true);
                    return;
                }
            },
        }
    }
}

/// What a response that passed rules 1 and 2 binds to.
struct Verified {
    decision: AuthzDecision,
    correlation_id: String,
    /// `None` only for an unsigned response admitted by the opt-out.
    nonce: Option<String>,
}

impl Inner {
    /// Verify one delivery and complete the matching request, or discard it
    /// (nack without requeue plus a security event).
    async fn handle<D: AckableDelivery>(&self, delivery: &D) {
        let verified = match self.verify_response(delivery.data()) {
            Ok(v) => v,
            Err(why) => {
                // The fact of failure only, never a signature value (§8
                // protocol rule 4).
                security_warn(&format!("AMQP authz response discarded: {why}"));
                delivery.nack(false).await;
                return;
            }
        };

        // Rule 3 (binding) and retirement under one lock, so two deliveries
        // cannot both complete the same request.
        let tx = {
            let mut pending = lock(&self.pending);
            match pending.get(&verified.correlation_id) {
                Some(p) if verified.nonce.as_deref().is_none_or(|n| n == p.nonce) => {
                    pending.remove(&verified.correlation_id).map(|p| p.tx)
                }
                _ => None,
            }
        };
        match tx {
            Some(tx) => {
                if verified.decision.unsigned {
                    security_warn(
                        "AMQP authz response accepted UNSIGNED because \
                         allow_unsigned_responses is set",
                    );
                }
                let _ = tx.send(verified.decision);
                delivery.ack().await;
            }
            None => {
                security_warn(
                    "AMQP authz response discarded: correlation_id and nonce \
                     match no outstanding request",
                );
                delivery.nack(false).await;
            }
        }
    }

    /// Apply §8 consumer obligations 1 and 2, plus the tenant half of 3, to
    /// `body`. It never re-serializes: the signature is checked over `body`
    /// minus its trailing signature member, and the decision is decoded from
    /// those same canonical bytes.
    fn verify_response(&self, body: &[u8]) -> Result<Verified, &'static str> {
        let members = parse_strict_object(body)?;
        // Any spelling of the signature member counts as a signature member:
        // the opt-out must never admit a response that carries one.
        let has_sig = members
            .keys()
            .any(|k| k.eq_ignore_ascii_case("hmac_signature"));

        // Rule 1 for the member every response carries.
        if !matches!(members.get("allowed"), Some(Value::Bool(_))) {
            return Err("allowed is missing or not a boolean");
        }

        if !has_sig {
            return self.accept_unsigned(&members);
        }

        // The canonical bytes: body with the final
        // `,"hmac_signature":"<64 hex>"` taken out of the closing brace. A
        // body that does not end in that member is discarded, never repaired
        // by re-serializing.
        let (canonical, sig_hex) =
            cut_trailing_signature(body).ok_or("body does not end in the hmac_signature member")?;
        if members.get("hmac_signature") != Some(&Value::String(sig_hex.to_string())) {
            return Err("hmac_signature is not the trailing member");
        }

        // Rule 2: HMAC-SHA256 under the requester's own tenant subkey,
        // constant-time, before anything else is read from the body.
        if !verify_payload(self.key.expose(), &canonical, sig_hex) {
            return Err("signature does not verify");
        }

        // Everything below reads the verified canonical bytes, not `body` (C2).
        let verified =
            parse_strict_object(&canonical).map_err(|_| "verified bytes do not decode")?;
        if verified
            .keys()
            .any(|k| k.eq_ignore_ascii_case("hmac_signature"))
        {
            return Err("canonical bytes still carry a signature member");
        }
        let Some(Value::Bool(allowed)) = verified.get("allowed") else {
            return Err("allowed is missing or not a boolean");
        };
        let text = |name: &str| match verified.get(name) {
            Some(Value::String(s)) if !s.is_empty() => Some(s.clone()),
            _ => None,
        };
        let (Some(tenant_id), Some(nonce), Some(correlation_id)) =
            (text("tenant_id"), text("nonce"), text("correlation_id"))
        else {
            return Err("tenant_id, nonce or correlation_id is missing");
        };

        // Rule 3, tenant half: the requester's own tenant only.
        if tenant_id != self.tenant {
            return Err("tenant_id is not the requester's");
        }
        Ok(Verified {
            decision: decision_from(&verified, *allowed, false),
            correlation_id,
            nonce: Some(nonce),
        })
    }

    /// A response with no signature member: refused unless the opt-out is set,
    /// in which case it is accepted on its `correlation_id` alone (a pre-1.68
    /// server answers with no `tenant_id` or `nonce`).
    fn accept_unsigned(&self, members: &Map<String, Value>) -> Result<Verified, &'static str> {
        if !self.allow_unsigned {
            return Err("response is unsigned");
        }
        let Some(Value::Bool(allowed)) = members.get("allowed") else {
            return Err("allowed is missing or not a boolean");
        };
        let correlation_id = match members.get("correlation_id") {
            Some(Value::String(s)) if !s.is_empty() => s.clone(),
            _ => return Err("unsigned response has no correlation_id"),
        };
        Ok(Verified {
            decision: decision_from(members, *allowed, true),
            correlation_id,
            nonce: None,
        })
    }
}

fn decision_from(members: &Map<String, Value>, allowed: bool, unsigned: bool) -> AuthzDecision {
    let string = |name: &str| match members.get(name) {
        Some(Value::String(s)) => Some(s.clone()),
        _ => None,
    };
    AuthzDecision {
        allowed,
        reason: string("reason"),
        reason_code: string("reason_code"),
        unsigned,
    }
}

/// Remove the final `,"hmac_signature":"<64 hex>"` member from `body`,
/// returning the canonical bytes (everything before it, closed with `}`) and
/// the signature hex. `None` when `body` does not end in exactly that member.
fn cut_trailing_signature(body: &[u8]) -> Option<(Vec<u8>, &str)> {
    const TAIL: &[u8] = b"\"}";
    let suffix_len = SIG_MEMBER.len() + SIG_HEX_LEN + TAIL.len();
    if body.len() <= suffix_len || !body.ends_with(TAIL) {
        return None;
    }
    let start = body.len() - suffix_len;
    if &body[start..start + SIG_MEMBER.len()] != SIG_MEMBER {
        return None;
    }
    let sig = &body[start + SIG_MEMBER.len()..body.len() - TAIL.len()];
    if !sig.iter().all(u8::is_ascii_hexdigit) {
        return None;
    }
    let sig = std::str::from_utf8(sig).ok()?;
    let mut canonical = Vec::with_capacity(start + 1);
    canonical.extend_from_slice(&body[..start]);
    canonical.push(b'}');
    Some((canonical, sig))
}

/// Parse `body` as one JSON object with unambiguous keys: no key twice at any
/// depth, and no two top-level keys that differ only by case (a decoder that
/// matches fields case-insensitively would read two keys as one). Anything
/// else, including trailing garbage, is refused.
fn parse_strict_object(body: &[u8]) -> Result<Map<String, Value>, &'static str> {
    let StrictValue(value) = serde_json::from_slice(body)
        .map_err(|_| "body is not a JSON object with unambiguous keys")?;
    let Value::Object(members) = value else {
        return Err("body is not a JSON object");
    };
    let mut folded = std::collections::HashSet::new();
    for key in members.keys() {
        if !folded.insert(key.to_lowercase()) {
            return Err("body has two keys that differ only by case");
        }
    }
    Ok(members)
}

/// A `serde_json::Value` that refuses a duplicate object key at any depth
/// instead of keeping the last one.
struct StrictValue(Value);

impl<'de> Deserialize<'de> for StrictValue {
    fn deserialize<D: de::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_any(StrictVisitor)
    }
}

struct StrictVisitor;

impl<'de> Visitor<'de> for StrictVisitor {
    type Value = StrictValue;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a JSON value without duplicate object keys")
    }

    fn visit_bool<E>(self, v: bool) -> Result<StrictValue, E> {
        Ok(StrictValue(Value::Bool(v)))
    }

    fn visit_i64<E>(self, v: i64) -> Result<StrictValue, E> {
        Ok(StrictValue(Value::from(v)))
    }

    fn visit_u64<E>(self, v: u64) -> Result<StrictValue, E> {
        Ok(StrictValue(Value::from(v)))
    }

    fn visit_f64<E: de::Error>(self, v: f64) -> Result<StrictValue, E> {
        serde_json::Number::from_f64(v)
            .map(|n| StrictValue(Value::Number(n)))
            .ok_or_else(|| E::custom("non-finite number"))
    }

    fn visit_str<E>(self, v: &str) -> Result<StrictValue, E> {
        Ok(StrictValue(Value::String(v.to_string())))
    }

    fn visit_string<E>(self, v: String) -> Result<StrictValue, E> {
        Ok(StrictValue(Value::String(v)))
    }

    fn visit_unit<E>(self) -> Result<StrictValue, E> {
        Ok(StrictValue(Value::Null))
    }

    fn visit_none<E>(self) -> Result<StrictValue, E> {
        Ok(StrictValue(Value::Null))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<StrictValue, A::Error> {
        let mut out = Vec::new();
        while let Some(StrictValue(v)) = seq.next_element()? {
            out.push(v);
        }
        Ok(StrictValue(Value::Array(out)))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<StrictValue, A::Error> {
        let mut out = Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if out.contains_key(&key) {
                return Err(de::Error::custom("duplicate object key"));
            }
            let StrictValue(v) = map.next_value()?;
            out.insert(key, v);
        }
        Ok(StrictValue(Value::Object(out)))
    }
}

/// Serialize and sign an `AuthzRequest` in the server's field order, compact,
/// with the signature appended as the trailing member.
///
/// `serde_json` writes `<`, `>`, `&`, U+2028 and U+2029 raw, exactly as the
/// server does, so the signed bytes are the bytes the server would produce.
#[allow(clippy::too_many_arguments)]
pub(crate) fn build_authz_request(
    key: &[u8],
    correlation_id: Uuid,
    tenant_id: Uuid,
    subject_id: Uuid,
    action: &str,
    resource_id: Uuid,
    scope: Option<&str>,
    nonce: Uuid,
) -> Result<Vec<u8>, AxiamError> {
    let request = AuthzRequest {
        correlation_id,
        tenant_id,
        subject_id,
        action: action.to_string(),
        resource_id,
        scope: scope.map(str::to_string),
        key_version: AUTHZ_KEY_VERSION,
        nonce,
        issued_at: Utc::now().trunc_subsecs(0),
        hmac_signature: None,
    };
    let mut canonical = serde_json::to_vec(&request)
        .map_err(|e| AxiamError::network(format!("failed to encode the authz request: {e}")))?;
    let signature = sign_payload(key, &canonical);
    // The canonical form ends in `}`; the signature member goes before it.
    canonical.pop();
    canonical.extend_from_slice(SIG_MEMBER);
    canonical.extend_from_slice(signature.as_bytes());
    canonical.extend_from_slice(b"\"}");
    Ok(canonical)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::amqp::test_log::{captured_log, init_recording_subscriber};
    use hmac::{Hmac, KeyInit, Mac};
    use sha2::Sha256;
    use std::sync::atomic::{AtomicUsize, Ordering};

    // Contract 1.68 §8 test vectors ("Signed authorization responses").
    const VEC_MASTER_KEY_HEX: &str =
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    const VEC_SUBKEY_HEX: &str = "919e125ec83799c1e113a27707cac5008a2608d0557e00dfe1b3a316abed4b89";
    const VEC_TENANT: &str = "11111111-1111-1111-1111-111111111111";
    const VEC_OTHER_TENANT: &str = "99999999-9999-9999-9999-999999999999";
    const VEC_CORRELATION: &str = "22222222-2222-2222-2222-222222222222";
    const VEC_NONCE: &str = "55555555-5555-5555-5555-555555555555";

    struct Vector {
        name: &'static str,
        canonical: &'static str,
        sig: &'static str,
        allowed: bool,
        reason: Option<&'static str>,
        code: &'static str,
    }

    const VECTORS: [Vector; 4] = [
        Vector {
            name: "1 allow",
            canonical: r#"{"correlation_id":"22222222-2222-2222-2222-222222222222","allowed":true,"reason_code":"allowed","tenant_id":"11111111-1111-1111-1111-111111111111","nonce":"55555555-5555-5555-5555-555555555555"}"#,
            sig: "8d81f0437df6c6fffafd13f4265bd41d3cfd6fcbf7c251b3bb79e0846578574a",
            allowed: true,
            reason: None,
            code: "allowed",
        },
        Vector {
            name: "2 deny no_grant",
            canonical: r#"{"correlation_id":"22222222-2222-2222-2222-222222222222","allowed":false,"reason":"no permission grants action 'documents:read'","reason_code":"no_grant","tenant_id":"11111111-1111-1111-1111-111111111111","nonce":"55555555-5555-5555-5555-555555555555"}"#,
            sig: "f3105ee678acd79da6ffd28c02b86311e16bb8d8dfd3fd0addbacdf73bd5a400",
            allowed: false,
            reason: Some("no permission grants action 'documents:read'"),
            code: "no_grant",
        },
        Vector {
            name: "3 deny denied_by_rule",
            canonical: r#"{"correlation_id":"22222222-2222-2222-2222-222222222222","allowed":false,"reason":"an explicit deny rule refuses action 'documents:read'","reason_code":"denied_by_rule","tenant_id":"11111111-1111-1111-1111-111111111111","nonce":"55555555-5555-5555-5555-555555555555"}"#,
            sig: "4bfc2ce9a035bd4a028ee2a5cb75a08832915c60cd2b176c8d4bf28910a61adc",
            allowed: false,
            reason: Some("an explicit deny rule refuses action 'documents:read'"),
            code: "denied_by_rule",
        },
        Vector {
            name: "4 escapes encoders disagree on",
            canonical: r#"{"correlation_id":"22222222-2222-2222-2222-222222222222","allowed":false,"reason":"no permission grants action 'docs:a&b</\"c\">/é€'","reason_code":"no_grant","tenant_id":"11111111-1111-1111-1111-111111111111","nonce":"55555555-5555-5555-5555-555555555555"}"#,
            sig: "5194142df4bf66b07e9e8d516caf6be099af025219ab12deb26fea39e93490ff",
            allowed: false,
            reason: Some(r#"no permission grants action 'docs:a&b</"c">/é€'"#),
            code: "no_grant",
        },
    ];

    impl Vector {
        fn wire(&self) -> Vec<u8> {
            wire_with(self.canonical, self.sig)
        }
    }

    fn wire_with(canonical: &str, sig: &str) -> Vec<u8> {
        let mut s = canonical.strip_suffix('}').expect("object").to_string();
        s.push_str(&format!(",\"hmac_signature\":\"{sig}\"}}"));
        s.into_bytes()
    }

    fn sign_with(key: &[u8], canonical: &str) -> Vec<u8> {
        wire_with(canonical, &sign_payload(key, canonical.as_bytes()))
    }

    type HmacSha256 = Hmac<Sha256>;

    fn hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
        let mut mac = <HmacSha256 as KeyInit>::new_from_slice(key).unwrap();
        mac.update(data);
        mac.finalize().into_bytes().to_vec()
    }

    /// The contract's derivation: HKDF-SHA256(salt, ikm = master, info =
    /// "axiam-amqp-v1" || key_version || tenant_id raw 16 bytes, L = 32).
    ///
    /// The salt and domain tag come from the vendored contract fixture, as
    /// consumer.rs's parity test reads them, rather than as byte literals: a
    /// literal passed as an HMAC key reads as a hard-coded key to CodeQL, and
    /// the fixture is the source of truth for both values anyway.
    fn subkey_for(tenant: &str, key_version: u8) -> Vec<u8> {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../../testdata/v2_reference_vectors.json"))
                .expect("fixture must parse as JSON");
        let field = |name: &str| {
            fixture["hkdf"][name]
                .as_str()
                .unwrap_or_else(|| panic!("hkdf.{name} present"))
                .as_bytes()
                .to_vec()
        };
        let master = hex::decode(VEC_MASTER_KEY_HEX).unwrap();
        let prk = hmac(&field("app_salt_utf8"), &master);
        let mut info = field("domain_tag_utf8");
        info.push(key_version);
        info.extend_from_slice(Uuid::parse_str(tenant).unwrap().as_bytes());
        info.push(1);
        hmac(&prk, &info) // L = 32 is one HKDF block
    }

    fn vec_key() -> Vec<u8> {
        hex::decode(VEC_SUBKEY_HEX).unwrap()
    }

    #[derive(Clone)]
    struct Published {
        queue: String,
        reply_to: String,
        correlation_id: String,
        body: Vec<u8>,
    }

    #[derive(Clone, Default)]
    struct FakePublisher {
        published: Arc<Mutex<Vec<Published>>>,
    }

    impl ReplyPublisher for FakePublisher {
        fn publish<'a>(
            &'a self,
            queue: &'a str,
            reply_to: &'a str,
            correlation_id: &'a str,
            body: Vec<u8>,
        ) -> BoxFuture<'a, Result<(), AxiamError>> {
            Box::pin(async move {
                self.published.lock().unwrap().push(Published {
                    queue: queue.into(),
                    reply_to: reply_to.into(),
                    correlation_id: correlation_id.into(),
                    body,
                });
                Ok(())
            })
        }
    }

    #[derive(Clone)]
    struct Recording {
        data: Vec<u8>,
        acked: Arc<AtomicUsize>,
        nack_requeue: Arc<AtomicUsize>,
        nack_no_requeue: Arc<AtomicUsize>,
    }

    impl Recording {
        fn new(data: Vec<u8>) -> Self {
            Self {
                data,
                acked: Arc::default(),
                nack_requeue: Arc::default(),
                nack_no_requeue: Arc::default(),
            }
        }
        fn counts(&self) -> (usize, usize, usize) {
            (
                self.acked.load(Ordering::SeqCst),
                self.nack_requeue.load(Ordering::SeqCst),
                self.nack_no_requeue.load(Ordering::SeqCst),
            )
        }
    }

    impl AckableDelivery for Recording {
        fn data(&self) -> &[u8] {
            &self.data
        }
        async fn ack(&self) {
            self.acked.fetch_add(1, Ordering::SeqCst);
        }
        async fn nack(&self, requeue: bool) {
            let c = if requeue {
                &self.nack_requeue
            } else {
                &self.nack_no_requeue
            };
            c.fetch_add(1, Ordering::SeqCst);
        }
    }

    type Feed = tokio::sync::mpsc::UnboundedSender<Recording>;

    fn feed_stream() -> (Feed, impl Stream<Item = Recording> + Send + 'static) {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let stream =
            futures_util::stream::unfold(
                rx,
                |mut rx| async move { rx.recv().await.map(|d| (d, rx)) },
            );
        (tx, stream)
    }

    fn requester(options: AuthzRequesterOptions) -> (AuthzRequester, FakePublisher, Feed) {
        let publisher = FakePublisher::default();
        let (feed, stream) = feed_stream();
        let r = AuthzRequester::start(
            publisher.clone(),
            "amq.gen-Xk3p".into(),
            stream,
            Uuid::parse_str(VEC_TENANT).unwrap(),
            Sensitive::new(vec_key()),
            options,
            None,
        )
        .expect("requester");
        (r, publisher, feed)
    }

    /// A requester with one outstanding request: the vectors' correlation_id
    /// and nonce.
    fn vector_requester(
        options: AuthzRequesterOptions,
    ) -> (AuthzRequester, oneshot::Receiver<AuthzDecision>) {
        let (r, _p, _feed) = requester(options);
        let (tx, rx) = oneshot::channel();
        lock(&r.inner.pending).insert(
            VEC_CORRELATION.into(),
            Pending {
                nonce: VEC_NONCE.into(),
                tx,
            },
        );
        (r, rx)
    }

    /// Feed `body` to the requester; report whether it completed the request.
    async fn offer(
        r: &AuthzRequester,
        rx: &mut oneshot::Receiver<AuthzDecision>,
        body: Vec<u8>,
    ) -> (Option<AuthzDecision>, Recording) {
        let d = Recording::new(body);
        r.inner.handle(&d).await;
        (rx.try_recv().ok(), d)
    }

    #[test]
    fn test_hkdf_matches_the_contract_subkey() {
        assert_eq!(hex::encode(subkey_for(VEC_TENANT, 2)), VEC_SUBKEY_HEX);
    }

    #[tokio::test]
    async fn all_four_contract_vectors_verify() {
        for v in &VECTORS {
            let (r, mut rx) = vector_requester(AuthzRequesterOptions::default());
            let (decision, d) = offer(&r, &mut rx, v.wire()).await;
            let decision = decision.unwrap_or_else(|| panic!("vector {} must verify", v.name));
            assert_eq!(decision.allowed, v.allowed, "{}", v.name);
            assert_eq!(decision.reason.as_deref(), v.reason, "{}", v.name);
            assert_eq!(decision.reason_code.as_deref(), Some(v.code), "{}", v.name);
            assert!(!decision.unsigned);
            assert_eq!(d.counts(), (1, 0, 0), "accepted must be acked");

            // Retired on acceptance: the same response again is dropped.
            let (again, d2) = offer(&r, &mut rx, v.wire()).await;
            assert!(
                again.is_none(),
                "{}: second response must be dropped",
                v.name
            );
            assert_eq!(d2.counts(), (0, 0, 1), "duplicate nacked without requeue");
        }
    }

    #[tokio::test]
    async fn vector_signature_is_over_the_received_bytes_not_a_reserialization() {
        // Vector 4 carries `<`, `>`, `&` and non-ASCII raw. A decoder that
        // re-serialized the parsed members could not reproduce these bytes.
        let v = &VECTORS[3];
        let wire = v.wire();
        let (canonical, sig) = cut_trailing_signature(&wire).unwrap();
        assert_eq!(canonical, v.canonical.as_bytes());
        assert_eq!(sig, v.sig);
        assert!(verify_payload(&vec_key(), &canonical, sig));
    }

    #[tokio::test]
    async fn discarded_responses_never_allow_and_leave_the_request_waiting() {
        let v1 = &VECTORS[0];
        let v2 = &VECTORS[1];
        let good = vec_key();
        let flip = |v: &Vector, from: &str, to: &str| {
            String::from_utf8(v.wire())
                .unwrap()
                .replacen(from, to, 1)
                .into_bytes()
        };
        let resign = |key: &[u8], canonical: &str| sign_with(key, canonical);

        let mut with_trailing_ws = v1.wire();
        with_trailing_ws.push(b'\n');

        let cases: Vec<(&str, Vec<u8>)> = vec![
            (
                "vector 1 under another tenant's subkey",
                resign(&subkey_for(VEC_OTHER_TENANT, 2), v1.canonical),
            ),
            (
                "vector 1 under key_version 3",
                resign(&subkey_for(VEC_TENANT, 3), v1.canonical),
            ),
            (
                "tampered decision: allowed flipped to false, signature kept",
                flip(v1, r#""allowed":true"#, r#""allowed":false"#),
            ),
            (
                "tampered decision: vector 2 flipped to true, signature kept",
                flip(v2, r#""allowed":false"#, r#""allowed":true"#),
            ),
            ("tampered reason_code", flip(v2, "no_grant", "allowed")),
            (
                "response for another nonce",
                resign(
                    &good,
                    &v1.canonical
                        .replacen(VEC_NONCE, "66666666-6666-6666-6666-666666666666", 1),
                ),
            ),
            (
                "response for another correlation_id",
                resign(
                    &good,
                    &v1.canonical.replacen(
                        VEC_CORRELATION,
                        "77777777-7777-7777-7777-777777777777",
                        1,
                    ),
                ),
            ),
            (
                "response for another tenant (validly signed with our key)",
                resign(
                    &good,
                    &v1.canonical.replacen(VEC_TENANT, VEC_OTHER_TENANT, 1),
                ),
            ),
            (
                "no allowed: a signed AuthzRequest on the response queue",
                resign(
                    &good,
                    &format!(
                        r#"{{"correlation_id":"{VEC_CORRELATION}","tenant_id":"{VEC_TENANT}","subject_id":"33333333-3333-3333-3333-333333333333","action":"documents:read","resource_id":"44444444-4444-4444-4444-444444444444","key_version":2,"nonce":"{VEC_NONCE}","issued_at":"2026-07-10T12:00:00Z"}}"#
                    ),
                ),
            ),
            (
                "allowed not a boolean",
                resign(
                    &good,
                    &v1.canonical
                        .replacen(r#""allowed":true"#, r#""allowed":"true""#, 1),
                ),
            ),
            (
                "no tenant_id",
                resign(
                    &good,
                    &v1.canonical
                        .replacen(&format!(r#""tenant_id":"{VEC_TENANT}","#), "", 1),
                ),
            ),
            (
                "no nonce",
                resign(
                    &good,
                    &v1.canonical
                        .replacen(&format!(r#","nonce":"{VEC_NONCE}""#), "", 1),
                ),
            ),
            (
                "signature not the trailing member",
                flip(v1, r#""allowed":true"#, r#""allowed":true,"x":1"#),
            ),
            (
                "duplicate allowed keys, validly signed",
                resign(
                    &good,
                    &v1.canonical.replacen(
                        r#""allowed":true"#,
                        r#""allowed":false,"allowed":true"#,
                        1,
                    ),
                ),
            ),
            (
                "case-variant allowed key, validly signed",
                resign(
                    &good,
                    &v1.canonical.replacen(
                        r#""reason_code""#,
                        r#""ALLOWED":false,"reason_code""#,
                        1,
                    ),
                ),
            ),
            (
                "trailing whitespace after the closing brace",
                with_trailing_ws,
            ),
            ("non-hex signature", flip(v1, v1.sig, &"z".repeat(64))),
            ("short signature", flip(v1, v1.sig, &v1.sig[..62])),
            ("not JSON", b"not json".to_vec()),
            ("empty body", Vec::new()),
        ];

        for (name, body) in cases {
            let (r, mut rx) = vector_requester(AuthzRequesterOptions::default());
            let (decision, d) = offer(&r, &mut rx, body).await;
            assert!(
                decision.is_none(),
                "{name}: must never complete the request"
            );
            assert_eq!(
                d.counts(),
                (0, 0, 1),
                "{name}: nacked without requeue, never acked"
            );
            // Still outstanding: the genuine answer completes it.
            let (genuine, _) = offer(&r, &mut rx, v1.wire()).await;
            assert!(
                genuine.is_some_and(|g| g.allowed),
                "{name}: a discarded response must leave the request waiting"
            );
        }
    }

    #[tokio::test]
    async fn discarding_is_logged_without_the_signature_value() {
        init_recording_subscriber();
        let (r, mut rx) = vector_requester(AuthzRequesterOptions::default());
        let tampered = String::from_utf8(VECTORS[1].wire())
            .unwrap()
            .replacen(r#""allowed":false"#, r#""allowed":true"#, 1)
            .into_bytes();
        let _ = offer(&r, &mut rx, tampered).await;
        let log = captured_log();
        assert!(
            log.contains("discarded"),
            "a security event must be logged: {log}"
        );
        assert!(
            !log.contains(VECTORS[1].sig),
            "never the signature value: {log}"
        );
    }

    #[tokio::test]
    async fn unsigned_responses() {
        let unsigned = format!(
            r#"{{"correlation_id":"{VEC_CORRELATION}","allowed":true,"reason_code":"allowed"}}"#
        )
        .into_bytes();

        // Refused by default.
        let (r, mut rx) = vector_requester(AuthzRequesterOptions::default());
        let (decision, d) = offer(&r, &mut rx, unsigned.clone()).await;
        assert!(decision.is_none(), "unsigned must be refused by default");
        assert_eq!(d.counts(), (0, 0, 1));

        // Accepted with the opt-out, flagged and logged.
        init_recording_subscriber();
        let (r, mut rx) =
            vector_requester(AuthzRequesterOptions::default().allow_unsigned_responses());
        let (decision, _) = offer(&r, &mut rx, unsigned.clone()).await;
        let decision = decision.expect("opt-out admits an unsigned response");
        assert!(decision.allowed && decision.unsigned);
        assert_eq!(decision.reason_code.as_deref(), Some("allowed"));
        assert!(
            captured_log().contains("UNSIGNED"),
            "must be logged as a warning"
        );

        // The opt-out needs an outstanding correlation_id and a boolean allowed.
        let (r, mut rx) =
            vector_requester(AuthzRequesterOptions::default().allow_unsigned_responses());
        for body in [
            r#"{"correlation_id":"77777777-7777-7777-7777-777777777777","allowed":true}"#
                .to_string(),
            format!(r#"{{"correlation_id":"{VEC_CORRELATION}"}}"#),
            format!(r#"{{"correlation_id":"{VEC_CORRELATION}","allowed":"yes"}}"#),
        ] {
            let (decision, _) = offer(&r, &mut rx, body.clone().into_bytes()).await;
            assert!(decision.is_none(), "must be refused: {body}");
        }

        // The opt-out never admits a response that carries a signature member
        // and fails.
        let tampered = String::from_utf8(VECTORS[1].wire())
            .unwrap()
            .replacen(r#""allowed":false"#, r#""allowed":true"#, 1)
            .into_bytes();
        let (decision, _) = offer(&r, &mut rx, tampered).await;
        assert!(decision.is_none(), "tampered signed response, opt-out on");
        for sig_member in [
            format!(
                r#"{{"correlation_id":"{VEC_CORRELATION}","allowed":true,"hmac_signature":null}}"#
            ),
            format!(
                r#"{{"correlation_id":"{VEC_CORRELATION}","allowed":true,"HMAC_SIGNATURE":"{}"}}"#,
                "0".repeat(64)
            ),
            format!(
                r#"{{"correlation_id":"{VEC_CORRELATION}","allowed":true,"hmac_signature":"{}"}}"#,
                "0".repeat(64)
            ),
        ] {
            let (decision, _) = offer(&r, &mut rx, sig_member.clone().into_bytes()).await;
            assert!(
                decision.is_none(),
                "a signature member of any spelling is verified, not treated as absent: {sig_member}"
            );
        }
    }

    #[test]
    fn reply_queue_is_declared_exclusive_and_auto_delete() {
        let declare = reply_queue_declare_options();
        assert!(declare.exclusive, "only this requester may consume it");
        assert!(declare.auto_delete, "it must go with its consumer");
        assert!(!declare.durable);
        let consume = reply_queue_consume_options();
        assert!(consume.exclusive);
        assert!(
            !consume.no_ack,
            "manual acknowledgement: nack must be possible"
        );
    }

    #[tokio::test]
    async fn a_reply_queue_naming_a_server_queue_or_nothing_is_refused() {
        for name in ["", "axiam.authz.response", "axiam.mail", "axiam."] {
            let (_feed, stream) = feed_stream();
            let err = AuthzRequester::start(
                FakePublisher::default(),
                name.into(),
                stream,
                Uuid::parse_str(VEC_TENANT).unwrap(),
                Sensitive::new(vec_key()),
                AuthzRequesterOptions::default(),
                None,
            )
            .expect_err("must refuse a non-private reply queue");
            assert!(format!("{err}").contains("not a private queue"), "{name}");
        }
        let (_feed, stream) = feed_stream();
        assert!(
            AuthzRequester::start(
                FakePublisher::default(),
                "amq.gen-Xk3p".into(),
                stream,
                Uuid::parse_str(VEC_TENANT).unwrap(),
                Sensitive::new(Vec::new()),
                AuthzRequesterOptions::default(),
                None,
            )
            .is_err(),
            "an empty signing key is refused"
        );
    }

    async fn wait_published(p: &FakePublisher, n: usize) -> Published {
        for _ in 0..2000 {
            {
                let g = p.published.lock().unwrap();
                if g.len() >= n {
                    return g[n - 1].clone();
                }
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        panic!("no request was published");
    }

    fn subject() -> Uuid {
        Uuid::parse_str("33333333-3333-3333-3333-333333333333").unwrap()
    }
    fn resource() -> Uuid {
        Uuid::parse_str("44444444-4444-4444-4444-444444444444").unwrap()
    }

    #[tokio::test]
    async fn check_end_to_end() {
        let (r, publisher, feed) =
            requester(AuthzRequesterOptions::default().timeout(Duration::from_secs(5)));
        let r = Arc::new(r);
        assert_eq!(r.reply_to(), "amq.gen-Xk3p");

        let r1 = Arc::clone(&r);
        let h1 = tokio::spawn(async move {
            r1.check(
                subject(),
                "docs:a&b</\"c\">",
                resource(),
                Some("confidential"),
            )
            .await
        });
        let p1 = wait_published(&publisher, 1).await;

        // Default-exchange routing key, private reply_to, correlation_id
        // property equal to the body's.
        assert_eq!(p1.queue, AUTHZ_REQUEST_QUEUE);
        assert_eq!(p1.reply_to, "amq.gen-Xk3p");
        let body: Value = serde_json::from_slice(&p1.body).unwrap();
        assert_eq!(body["correlation_id"], p1.correlation_id);
        assert_eq!(body["tenant_id"], VEC_TENANT);
        assert_eq!(body["key_version"], 2);
        assert_eq!(body["scope"], "confidential");

        // Characters the encoders disagree on are written raw, as the server's
        // serde_json writes them, and the signature verifies over those bytes.
        let text = String::from_utf8(p1.body.clone()).unwrap();
        assert!(text.contains(r#""action":"docs:a&b</\"c\">""#), "{text}");
        let (canonical, sig) = cut_trailing_signature(&p1.body).expect("trailing signature");
        assert!(verify_payload(&vec_key(), &canonical, sig));
        // The server's DTO reads it back, signature member included.
        let parsed: AuthzRequest = serde_json::from_slice(&p1.body).unwrap();
        assert_eq!(parsed.hmac_signature.as_deref(), Some(sig));

        // A forgery with the right ids and the wrong key is discarded; the
        // genuine answer then completes the check.
        let nonce = body["nonce"].as_str().unwrap();
        let canonical = format!(
            r#"{{"correlation_id":"{}","allowed":true,"reason_code":"allowed","tenant_id":"{VEC_TENANT}","nonce":"{nonce}"}}"#,
            p1.correlation_id
        );
        let forged = Recording::new(sign_with(&subkey_for(VEC_OTHER_TENANT, 2), &canonical));
        feed.send(forged.clone()).unwrap();
        for _ in 0..200 {
            if forged.counts().2 == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        assert_eq!(forged.counts(), (0, 0, 1));
        assert!(
            !h1.is_finished(),
            "a forged response must not complete the check"
        );

        let genuine = Recording::new(sign_with(&vec_key(), &canonical));
        feed.send(genuine.clone()).unwrap();
        let decision = h1
            .await
            .unwrap()
            .expect("genuine answer completes the check");
        assert!(decision.allowed);
        assert_eq!(decision.reason_code.as_deref(), Some("allowed"));
        assert_eq!(genuine.counts(), (1, 0, 0));

        // Fresh, distinct, unpredictable ids per request.
        let r2 = Arc::clone(&r);
        let h2 = tokio::spawn(async move {
            r2.check(subject(), "documents:read", resource(), None)
                .await
        });
        let p2 = wait_published(&publisher, 2).await;
        assert_ne!(p2.correlation_id, p1.correlation_id);
        let body2: Value = serde_json::from_slice(&p2.body).unwrap();
        assert_ne!(body2["nonce"], body["nonce"]);
        assert_ne!(body2["nonce"], p2.correlation_id.as_str());
        assert!(body2.get("scope").is_none(), "no scope member when absent");

        r.close();
        assert!(
            h2.await.unwrap().is_err(),
            "close fails the outstanding check"
        );
        assert!(
            r.check(subject(), "x", resource(), None).await.is_err(),
            "a closed requester refuses new checks"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn check_times_out_and_retires_the_request() {
        let (r, _publisher, _feed) =
            requester(AuthzRequesterOptions::default().timeout(Duration::from_millis(50)));
        let err = r
            .check(subject(), "documents:read", resource(), None)
            .await
            .expect_err("no answer: timeout");
        assert!(format!("{err}").contains("timed out"));
        assert!(lock(&r.inner.pending).is_empty(), "the request is retired");
    }

    #[tokio::test]
    async fn the_response_stream_ending_closes_the_requester() {
        let (r, _publisher, feed) = requester(AuthzRequesterOptions::default());
        drop(feed); // the queue or connection went away
        for _ in 0..200 {
            if *r.inner.closed.borrow() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        assert!(r.check(subject(), "x", resource(), None).await.is_err());
    }

    #[test]
    fn strict_parse_rejects_ambiguity_and_accepts_plain_objects() {
        assert!(parse_strict_object(br#"{"a":1,"b":{"c":2}}"#).is_ok());
        assert!(parse_strict_object(br#"{"a":1,"a":2}"#).is_err());
        assert!(parse_strict_object(br#"{"a":{"b":1,"b":2}}"#).is_err());
        assert!(parse_strict_object(br#"{"a":[{"b":1,"b":2}]}"#).is_err());
        assert!(parse_strict_object(br#"{"allowed":true,"ALLOWED":false}"#).is_err());
        assert!(parse_strict_object(b"[1]").is_err());
        assert!(parse_strict_object(br#"{"a":1} x"#).is_err());
        assert!(parse_strict_object(b"\xff").is_err());
    }
}
