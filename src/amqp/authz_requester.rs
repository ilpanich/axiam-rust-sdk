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
//!   nacked without requeue, logged as one security event (§8 consumer
//!   obligation 4: timestamp, exchange, routing key, the requester's own
//!   tenant and a reason code; never a signature, a nonce or anything read
//!   from the body), is **never** an allow, and does **not** complete the
//!   request: [`AuthzRequester::check`] keeps waiting for the genuine answer.
//!
//! # Server version
//!
//! The AMQP authorization requester requires an AXIAM server of 1.68 or later
//! (contract 1.68). Such a server signs every authorization response with the
//! tenant's AMQP subkey and answers on the requester's private `reply_to`
//! queue. A server older than 1.68 ignores `reply_to` and answers, unsigned,
//! only on the shared `axiam.authz.response` queue, which this requester never
//! reads: against it every check times out. There is no option to accept
//! unsigned responses (CONTRACT 1.69 §8): no AXIAM server sends one to a reply
//! queue, so an unsigned response can only have been published by someone
//! else, and it is discarded and logged. During a rolling upgrade from a
//! pre-1.68 server, use REST or gRPC authorization until every replica runs
//! 1.68 or later.

use std::collections::HashMap;
use std::fmt;
use std::future::{Future, ready};
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use chrono::{SecondsFormat, SubsecRound, Utc};
use futures_util::{Stream, StreamExt};
use lapin::options::{
    BasicConsumeOptions, BasicPublishOptions, ConfirmSelectOptions, QueueDeclareOptions,
};
use lapin::types::FieldTable;
use lapin::{BasicProperties, Channel, Confirmation, Connection};
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
    /// tenant subkey.
    pub allowed: bool,
    /// The server's human-readable reason, when present.
    pub reason: Option<String>,
    /// The machine-readable code (`allowed`, `no_grant`, `denied_by_rule`,
    /// `tenant_suspended`, ...), when present. A code this SDK does not know
    /// is surfaced verbatim.
    pub reason_code: Option<String>,
}

/// Options for an [`AuthzRequester`].
///
/// There is deliberately no option to accept unsigned responses; see the
/// [module documentation](self#server-version).
#[derive(Debug, Clone, Default)]
pub struct AuthzRequesterOptions {
    timeout: Option<Duration>,
}

impl AuthzRequesterOptions {
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
                .map_err(|e| AxiamError::network(format!("authz request was not confirmed: {e}")))
                .and_then(check_confirmation)
        })
    }
}

/// A broker `Nack` means the request was not accepted: fail the check at once
/// rather than let it wait out the timeout for an answer that cannot come.
/// The publish is not `mandatory`, so a request nothing can route to (no
/// `axiam.authz.request` queue) is acked and still times out.
fn check_confirmation(confirmation: Confirmation) -> Result<(), AxiamError> {
    match confirmation {
        Confirmation::Nack(_) => Err(AxiamError::network(
            "the broker refused (nacked) the authz request",
        )),
        _ => Ok(()),
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
    timeout: Duration,
    reply_to: String,
    publisher: Box<dyn ReplyPublisher>,
    pending: Mutex<HashMap<String, Pending>>,
    closed: watch::Sender<bool>,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// Why a response was discarded: the §8 consumer-obligation-4 `reason` codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Discard {
    /// Not a well-formed signed response (rule 1, apart from `Unsigned`).
    Malformed,
    /// No `hmac_signature` member at all (rule 1; there is no opt-out).
    Unsigned,
    /// The HMAC does not verify under this tenant's subkey (rule 2).
    Signature,
    /// `tenant_id` is not the requester's (rule 3).
    Tenant,
    /// No outstanding request has this `correlation_id` and `nonce` (rule 3).
    UnknownRequest,
}

impl Discard {
    fn as_str(self) -> &'static str {
        match self {
            Self::Malformed => "malformed",
            Self::Unsigned => "unsigned",
            Self::Signature => "signature",
            Self::Tenant => "tenant",
            Self::UnknownRequest => "unknown_request",
        }
    }
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
    ///
    /// A broker nack of a request fails [`check`](Self::check) at once only on
    /// a channel with publisher confirms enabled (`confirm_select`), which
    /// [`connect`](Self::connect) does; on any other channel a nacked request
    /// simply times out. The publish is not `mandatory`, so a request nothing
    /// can route to (no `axiam.authz.request` queue) is acked and still times
    /// out.
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
        // Publisher confirms, so a broker nack of a request fails `check`.
        channel
            .confirm_select(ConfirmSelectOptions::default())
            .await
            .map_err(|e| {
                AxiamError::network(format!("failed to enable publisher confirms: {e}"))
            })?;
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
            // Closed wins over a ready delivery.
            biased;
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
    nonce: String,
}

impl Inner {
    /// Verify one delivery and complete the matching request, or discard it
    /// (nack without requeue plus one security event).
    async fn handle<D: AckableDelivery>(&self, delivery: &D) {
        // After close nothing is verified or reported (A.2 "After Close").
        if *self.closed.borrow() {
            delivery.nack(false).await;
            return;
        }
        let discard = match self.verify_response(delivery.data()) {
            Ok(verified) => match self.take_pending(&verified) {
                Some(tx) => {
                    let _ = tx.send(verified.decision);
                    delivery.ack().await;
                    return;
                }
                None => Discard::UnknownRequest,
            },
            Err(discard) => discard,
        };
        self.log_discard(discard);
        delivery.nack(false).await;
    }

    /// Rule 3 (binding) and retirement under one lock, so two deliveries
    /// cannot both complete the same request.
    fn take_pending(&self, verified: &Verified) -> Option<oneshot::Sender<AuthzDecision>> {
        let mut pending = lock(&self.pending);
        match pending.get(&verified.correlation_id) {
            Some(p) if p.nonce == verified.nonce => {
                pending.remove(&verified.correlation_id).map(|p| p.tx)
            }
            _ => None,
        }
    }

    /// The §8 consumer-obligation-4 event. The routing key and tenant are the
    /// requester's own (this reply queue and configured tenant), which are the
    /// same for every delivery it can receive; the default exchange is `""`.
    /// Nothing read from the unauthenticated body goes in: no signature, no
    /// `nonce`, no `correlation_id`, no claimed `tenant_id`.
    fn log_discard(&self, reason: Discard) {
        tracing::warn!(
            target: "axiam_sdk::security",
            timestamp = %Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
            exchange = "",
            routing_key = %self.reply_to,
            tenant_id = %self.tenant,
            reason = reason.as_str(),
            "AMQP authz response discarded"
        );
    }

    /// Apply §8 consumer obligations 1 and 2, plus the tenant half of 3, to
    /// `body`. It never re-serializes: the signature is checked over `body`
    /// minus its trailing signature member, and the decision is decoded from
    /// those same canonical bytes.
    fn verify_response(&self, body: &[u8]) -> Result<Verified, Discard> {
        let malformed = |_| Discard::Malformed;
        let members = parse_strict_object(body).map_err(malformed)?;
        // Any spelling of the signature member counts as a signature member.
        if !members
            .keys()
            .any(|k| k.eq_ignore_ascii_case("hmac_signature"))
        {
            return Err(Discard::Unsigned);
        }

        // Rule 3 of the discard order: the members every response carries are
        // present and well typed, whatever the signature says.
        response_fields(&members).ok_or(Discard::Malformed)?;

        // The canonical bytes: body with the final
        // `,"hmac_signature":"<64 hex>"` taken out of the closing brace. A
        // body that does not end in that member is discarded, never repaired
        // by re-serializing.
        let (canonical, sig_hex) = cut_trailing_signature(body).ok_or(Discard::Malformed)?;
        if members.get("hmac_signature") != Some(&Value::String(sig_hex.to_string())) {
            return Err(Discard::Malformed);
        }

        // Rule 2: HMAC-SHA256 under the requester's own tenant subkey,
        // constant-time, before anything else is read from the body.
        if !verify_payload(self.key.expose(), &canonical, sig_hex) {
            return Err(Discard::Signature);
        }

        // Everything below reads the verified canonical bytes, not `body` (C2).
        let verified = parse_strict_object(&canonical).map_err(malformed)?;
        if verified
            .keys()
            .any(|k| k.eq_ignore_ascii_case("hmac_signature"))
        {
            return Err(Discard::Malformed);
        }
        let (allowed, tenant_id, nonce, correlation_id) =
            response_fields(&verified).ok_or(Discard::Malformed)?;

        // Rule 3, tenant half: the requester's own tenant only.
        if tenant_id != self.tenant {
            return Err(Discard::Tenant);
        }
        Ok(Verified {
            decision: decision_from(&verified, allowed),
            correlation_id,
            nonce,
        })
    }
}

/// `allowed` and the non-empty `tenant_id`, `nonce` and `correlation_id` of a
/// response, or `None` when one is missing or not of its type.
fn response_fields(members: &Map<String, Value>) -> Option<(bool, String, String, String)> {
    let text = |name: &str| match members.get(name) {
        Some(Value::String(s)) if !s.is_empty() => Some(s.clone()),
        _ => None,
    };
    let Some(Value::Bool(allowed)) = members.get("allowed") else {
        return None;
    };
    Some((
        *allowed,
        text("tenant_id")?,
        text("nonce")?,
        text("correlation_id")?,
    ))
}

fn decision_from(members: &Map<String, Value>, allowed: bool) -> AuthzDecision {
    let string = |name: &str| match members.get(name) {
        Some(Value::String(s)) => Some(s.clone()),
        _ => None,
    };
    AuthzDecision {
        allowed,
        reason: string("reason"),
        reason_code: string("reason_code"),
    }
}

/// Remove the final `,"hmac_signature":"<64 hex>"` member from `body`,
/// returning the canonical bytes (everything before it, closed with `}`) and
/// the signature hex. `None` when `body` does not end in exactly that member.
pub(crate) fn cut_trailing_signature(body: &[u8]) -> Option<(Vec<u8>, &str)> {
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
pub(crate) fn parse_strict_object(body: &[u8]) -> Result<Map<String, Value>, &'static str> {
    // The first byte is `{`: a byte-order mark, whitespace or any other prefix
    // is refused, never skipped (§8 step 2a, contract 1.69).
    if body.first() != Some(&b'{') {
        return Err("body does not begin with `{`");
    }
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
        fn exchange(&self) -> &str {
            ""
        }
        fn routing_key(&self) -> &str {
            ""
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
    fn vector_requester() -> (AuthzRequester, oneshot::Receiver<AuthzDecision>) {
        let (r, _p, _feed) = requester(AuthzRequesterOptions::default());
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
            let (r, mut rx) = vector_requester();
            let (decision, d) = offer(&r, &mut rx, v.wire()).await;
            let decision = decision.unwrap_or_else(|| panic!("vector {} must verify", v.name));
            assert_eq!(decision.allowed, v.allowed, "{}", v.name);
            assert_eq!(decision.reason.as_deref(), v.reason, "{}", v.name);
            assert_eq!(decision.reason_code.as_deref(), Some(v.code), "{}", v.name);
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
            let (r, mut rx) = vector_requester();
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

    /// Offer `body`, then assert the one discard event (CONTRACT §8 consumer
    /// obligation 4): the requester's own queue and tenant, the reason code,
    /// and nothing read from the body.
    async fn assert_discard_event(name: &str, body: Vec<u8>, reason: &str, secrets: &[&str]) {
        init_recording_subscriber();
        let (r, mut rx) = vector_requester();
        let (decision, d) = offer(&r, &mut rx, body).await;
        assert!(decision.is_none(), "{name}: must not complete the request");
        assert_eq!(d.counts(), (0, 0, 1), "{name}: nacked without requeue");
        let log = captured_log();
        assert_eq!(
            log.lines().count(),
            1,
            "{name}: exactly one event per discard: {log}"
        );
        for expected in [
            "AMQP authz response discarded".to_string(),
            "timestamp=".to_string(),
            "exchange=\"\"".to_string(),
            "routing_key=amq.gen-Xk3p".to_string(),
            format!("tenant_id={VEC_TENANT}"),
            format!("reason=\"{reason}\""),
        ] {
            assert!(log.contains(&expected), "{name}: missing {expected}: {log}");
        }
        for secret in secrets {
            assert!(!log.contains(secret), "{name}: leaked {secret}: {log}");
        }
    }

    #[tokio::test]
    async fn every_discard_path_logs_the_a2_event_without_secrets() {
        let v1 = &VECTORS[0];
        let good = vec_key();
        let tampered = String::from_utf8(VECTORS[1].wire())
            .unwrap()
            .replacen(r#""allowed":false"#, r#""allowed":true"#, 1)
            .into_bytes();
        let other_tenant = v1.canonical.replacen(VEC_TENANT, VEC_OTHER_TENANT, 1);
        let other_corr =
            v1.canonical
                .replacen(VEC_CORRELATION, "77777777-7777-7777-7777-777777777777", 1);
        let unsigned = format!(
            r#"{{"correlation_id":"{VEC_CORRELATION}","allowed":true,"reason_code":"allowed"}}"#
        );

        assert_discard_event(
            "signature",
            tampered,
            "signature",
            &[VECTORS[1].sig, VEC_NONCE, VEC_CORRELATION],
        )
        .await;
        assert_discard_event(
            "tenant",
            sign_with(&good, &other_tenant),
            "tenant",
            &[v1.sig, VEC_NONCE, VEC_OTHER_TENANT, VEC_CORRELATION],
        )
        .await;
        assert_discard_event(
            "unknown_request",
            sign_with(&good, &other_corr),
            "unknown_request",
            &[
                v1.sig,
                VEC_NONCE,
                "77777777-7777-7777-7777-777777777777",
                &sign_payload(&good, other_corr.as_bytes()),
            ],
        )
        .await;
        assert_discard_event(
            "unsigned",
            unsigned.into_bytes(),
            "unsigned",
            &[VEC_NONCE, VEC_CORRELATION],
        )
        .await;
        assert_discard_event("malformed", b"not json".to_vec(), "malformed", &[]).await;
        assert_discard_event(
            "malformed: signature member not 64 hex",
            flip_sig(v1, &"z".repeat(64)),
            "malformed",
            &[VEC_NONCE],
        )
        .await;
    }

    #[tokio::test]
    async fn a_byte_order_mark_or_other_prefix_is_malformed_and_the_next_response_completes() {
        // Contract 1.69 (D-10): the first byte must be `{`; a prefix is refused,
        // never stripped, and the requester goes on with the next delivery.
        let v = &VECTORS[0];
        for (what, prefix) in [
            ("byte-order mark", &b"\xEF\xBB\xBF"[..]),
            ("space", b" "),
            ("newline", b"\n"),
        ] {
            let mut body = prefix.to_vec();
            body.extend_from_slice(&v.wire());
            assert_discard_event(what, body, "malformed", &[v.sig, VEC_NONCE]).await;
        }
        let (r, mut rx) = vector_requester();
        let mut bom = b"\xEF\xBB\xBF".to_vec();
        bom.extend_from_slice(&v.wire());
        let (decision, d) = offer(&r, &mut rx, bom).await;
        assert!(decision.is_none());
        assert_eq!(d.counts(), (0, 0, 1));
        // The same request is still waiting and the genuine response completes it.
        let (decision, d) = offer(&r, &mut rx, v.wire()).await;
        assert!(decision.is_some(), "the next delivery is processed");
        assert_eq!(d.counts(), (1, 0, 0));
    }

    #[tokio::test]
    async fn ill_typed_or_missing_members_are_malformed_before_the_hmac_is_tried() {
        // Reason order (§8 consumer obligation 4): rule 3, members, comes
        // before rule 4, the signature. A body with both faults is `malformed`.
        let v1 = &VECTORS[0];
        let wrong_sig = "0".repeat(64);
        let signed_wrongly = |canonical: String| {
            format!(
                "{},\"hmac_signature\":\"{wrong_sig}\"}}",
                &canonical[..canonical.len() - 1]
            )
            .into_bytes()
        };
        let no_nonce = v1
            .canonical
            .replacen(&format!(r#","nonce":"{VEC_NONCE}""#), "", 1);
        let allowed_text = v1
            .canonical
            .replacen(r#""allowed":true"#, r#""allowed":"true""#, 1);
        assert_discard_event(
            "nonce missing, signature wrong",
            signed_wrongly(no_nonce),
            "malformed",
            &[VEC_CORRELATION],
        )
        .await;
        assert_discard_event(
            "allowed ill-typed, signature wrong",
            signed_wrongly(allowed_text),
            "malformed",
            &[VEC_CORRELATION],
        )
        .await;
    }

    fn flip_sig(v: &Vector, to: &str) -> Vec<u8> {
        String::from_utf8(v.wire())
            .unwrap()
            .replacen(v.sig, to, 1)
            .into_bytes()
    }

    #[tokio::test]
    async fn an_unsigned_response_is_discarded_and_the_check_keeps_waiting() {
        // CONTRACT 1.69 §8: there is no opt-out; a well-formed unsigned
        // response for an outstanding correlation_id never completes it.
        let (r, mut rx) = vector_requester();
        let unsigned = format!(
            r#"{{"correlation_id":"{VEC_CORRELATION}","allowed":true,"reason_code":"allowed"}}"#
        );
        for body in [
            unsigned,
            format!(
                r#"{{"correlation_id":"{VEC_CORRELATION}","allowed":true,"hmac_signature":null}}"#
            ),
            format!(
                r#"{{"correlation_id":"{VEC_CORRELATION}","allowed":true,"HMAC_SIGNATURE":"{}"}}"#,
                "0".repeat(64)
            ),
        ] {
            let (decision, d) = offer(&r, &mut rx, body.clone().into_bytes()).await;
            assert!(decision.is_none(), "must be refused: {body}");
            assert_eq!(d.counts(), (0, 0, 1));
        }
        let (genuine, _) = offer(&r, &mut rx, VECTORS[0].wire()).await;
        assert!(genuine.is_some_and(|g| g.allowed), "still waiting");
    }

    #[tokio::test]
    async fn a_closed_requester_nacks_without_requeue_and_logs_nothing() {
        // A.2 "After Close": nothing is verified or reported once closed.
        init_recording_subscriber();
        let (r, mut rx) = vector_requester();
        r.close();
        for body in [VECTORS[0].wire(), b"not json".to_vec()] {
            let (decision, d) = offer(&r, &mut rx, body).await;
            assert!(decision.is_none());
            assert_eq!(d.counts(), (0, 0, 1), "nacked without requeue");
        }
        assert_eq!(captured_log(), "", "no discard event after close");
    }

    #[test]
    fn a_broker_nack_fails_the_publish_at_once() {
        assert!(check_confirmation(Confirmation::Nack(None)).is_err());
        assert!(check_confirmation(Confirmation::Ack(None)).is_ok());
        assert!(check_confirmation(Confirmation::NotRequested).is_ok());
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
