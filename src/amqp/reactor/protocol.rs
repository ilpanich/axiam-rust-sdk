//! The reactor wire protocol — the signed event and the signed reply
//! (CONTRACT.md §22.1–§22.4).
//!
//! **Mirror, never import.** These types reproduce the field order and serde
//! shape of the server's `ReactorEventMessage` / `ReactorReply`
//! (`crates/axiam-amqp/src/reactor/protocol.rs`) byte-for-byte, using only
//! external crates. `testdata/reactor_v2_reference_vectors.json` — generated
//! by the server's own sign path — is what pins them.
//!
//! # The one canonicalization difference that will cost you a day
//!
//! §8's own two message types (`AuthzRequest`, `AuditEventMessage`) sign a
//! body with `hmac_signature` **omitted**. A reactor event and a reactor reply
//! sign it **serialized as `null`**:
//!
//! ```text
//! {"correlation_id":"…","tenant_id":"…", … ,"hmac_signature":null}
//!                                                             ^^^^ present
//! ```
//!
//! Everything else about §8 v2 is unchanged: the HKDF-derived per-tenant
//! subkey, HMAC-SHA256 hex-encoded and compared in constant time,
//! `key_version = 2` as a hard floor, a ±300 s freshness window checked in
//! **both** directions, and a fresh UUIDv4 `nonce` inside the signed bytes.
//!
//! # Signing is symmetric in direction
//!
//! The server signs the event; the reactor signs the reply, with the **same**
//! tenant subkey. There is no second key and no asymmetric variant in v1. A
//! reply that is unsigned or stale is not a weak reply — the server discards
//! it and applies the registration's `failure_policy`, exactly as if the
//! reactor had never answered.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::amqp::hmac::{sign_payload, verify_payload};

/// Topic exchange every reactor event is published to (§22.1).
pub const REACTOR_EXCHANGE: &str = "axiam.reactor.events";

/// Envelope key version this SDK emits, and the floor it accepts (§22.2).
/// A body carrying less than this is refused before anything else about it is
/// considered.
pub const REACTOR_KEY_VERSION: u8 = 2;

/// Freshness window for `issued_at`, in seconds, in **both** directions
/// (§22.2). A future timestamp is not "extra fresh" — it is the shape of a
/// captured message held for later.
pub const DEFAULT_FRESHNESS_SKEW_SECS: i64 = 300;

/// The routing key an event is published with: `<tenant_id>.<event>` (§22.1).
///
/// Stated so an SDK can assert against it; a reactor runtime never *binds*
/// with it. See [`queue_name`].
pub fn routing_key(tenant_id: Uuid, event: &str) -> String {
    format!("{tenant_id}.{event}")
}

/// The durable per-reactor queue name: `axiam.reactor.q.<tenant_id>.<reactor_id>`
/// (§22.1).
///
/// **The server declares this queue; a reactor only consumes from it.** This
/// SDK derives the name for the reactor it is configured as and for no other:
/// a reactor that can declare and bind is a reactor that can bind itself to
/// `*.token.pre_issue` and read another tenant's issuance events, and refusing
/// to hold that capability at all is cheaper than proving each actor does not
/// misuse it.
pub fn queue_name(tenant_id: Uuid, reactor_id: Uuid) -> String {
    format!("axiam.reactor.q.{tenant_id}.{reactor_id}")
}

/// `true` when `issued_at` lies within `±skew` of `now` — the freshness gate,
/// applied in both directions (§22.2).
pub fn is_fresh(issued_at: DateTime<Utc>, now: DateTime<Utc>, skew: chrono::Duration) -> bool {
    now.signed_duration_since(issued_at).abs() <= skew
}

// ---------------------------------------------------------------------------
// Event (server → reactor)
// ---------------------------------------------------------------------------

/// One hook firing, delivered to a reactor (CONTRACT.md §22.3).
///
/// Field order is load-bearing: it is the order the server serializes, and
/// therefore the order the canonical signed bytes carry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReactorEvent {
    /// The tenant this firing belongs to. The signing subkey is derived from
    /// it, so an event cannot be replayed into another tenant.
    pub tenant_id: Uuid,
    /// A registry name (§22.5) — also the second half of the routing key.
    pub event: String,
    /// The single-use handle for this dispatch. **Echo it in the reply body**;
    /// copying it only into the AMQP property produces a reply the server
    /// discards.
    pub correlation_id: Uuid,
    /// Event-specific body. Never carries a credential, a token, or a signing
    /// key — a reactor is told *what is being decided*, not handed the means
    /// to act on it elsewhere.
    ///
    /// On a chained event this object also carries `_reactor_patch`, the patch
    /// an earlier reactor in the chain already returned (§22.3). Treat it as
    /// **read-only context**: echoing it back inside your own `patch` is not
    /// how a field is preserved — the server merges (§22.6).
    pub payload: serde_json::Value,
    /// How long the server will actually wait for *this* dispatch. Inside the
    /// signed body, so it cannot be widened in transit.
    pub timeout_ms: u32,
    /// §8 v2 envelope key version. Always `2` or higher.
    pub key_version: u8,
    /// Fresh UUIDv4 per message, inside the signed bytes.
    pub nonce: Uuid,
    /// Producer-side send time, for the freshness gate.
    pub issued_at: DateTime<Utc>,
    /// HMAC-SHA256 over this body with the field serialized as `null`.
    pub hmac_signature: Option<String>,
}

impl ReactorEvent {
    /// The accumulated patch an earlier reactor in the chain returned, if this
    /// is a chained dispatch (§22.3's `_reactor_patch`).
    ///
    /// Read-only context: it tells you what the state will be if the chain
    /// commits, so you can decide against that rather than against the
    /// original. It is **not** something to copy into your own patch.
    pub fn chained_patch(&self) -> Option<&serde_json::Value> {
        self.payload.get("_reactor_patch")
    }

    /// The registry spec for this event's name, if the SDK knows it.
    pub fn spec(&self) -> Option<&'static super::registry::ReactorEventSpec> {
        super::registry::event_spec(&self.event)
    }

    /// The wall-clock window this dispatch has, from `timeout_ms`.
    ///
    /// §22.3 sends it so an actor can **shed load rather than answer into a
    /// closed window**: a late reply is discarded, and the CPU spent producing
    /// it was spent for nothing.
    pub fn timeout(&self) -> std::time::Duration {
        std::time::Duration::from_millis(u64::from(self.timeout_ms))
    }
}

/// Why a delivered event was not usable, in the order §22.3 requires the
/// checks to run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EventRejection {
    /// The body is not a JSON object, or is missing a mandatory field.
    Malformed(&'static str),
    /// `key_version` below the §8 v2 floor — refused **before** the signature
    /// is even computed.
    KeyVersionTooOld(u8),
    /// Missing or wrong MAC.
    BadSignature,
    /// `issued_at` outside ±`skew`, in either direction.
    Stale,
    /// This `nonce` was already seen inside the freshness window.
    ReplayedNonce,
}

impl std::fmt::Display for EventRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed(what) => write!(f, "malformed reactor event: {what}"),
            Self::KeyVersionTooOld(v) => {
                write!(f, "event key_version {v} is below the accepted floor")
            }
            Self::BadSignature => write!(f, "event signature is missing or invalid"),
            Self::Stale => write!(f, "event issued_at is outside the freshness window"),
            Self::ReplayedNonce => write!(f, "event nonce was already seen (replay)"),
        }
    }
}

impl std::error::Error for EventRejection {}

/// The canonical bytes of a delivered event: the body exactly as it arrived,
/// with `hmac_signature` **set to `null` in place** (§22.2).
///
/// Setting the value rather than removing the key is the whole difference from
/// §8's own two message types, and re-serializing the parsed `Value` (rather
/// than a struct) is what makes the payload's own key order and nesting
/// reproduce byte-for-byte — this crate enables `serde_json`'s `preserve_order`
/// precisely so a parsed object keeps the order it arrived in.
pub fn canonical_event_bytes(body: &serde_json::Value) -> Result<Vec<u8>, EventRejection> {
    let mut canonical = body.clone();
    let obj = canonical
        .as_object_mut()
        .ok_or(EventRejection::Malformed("body is not a JSON object"))?;
    if !obj.contains_key("hmac_signature") {
        // An unsigned event is not a weak event; it is not an event. Refusing
        // here (rather than inserting the key) also keeps the field's position
        // in the canonical bytes honest.
        return Err(EventRejection::Malformed("hmac_signature is absent"));
    }
    obj.insert("hmac_signature".into(), serde_json::Value::Null);
    serde_json::to_vec(&canonical)
        .map_err(|_| EventRejection::Malformed("body could not be re-serialized"))
}

/// Verify a delivered event and decode it, in the order §22.3 fixes:
/// **`key_version`, then the MAC, then freshness** — the fourth check, the
/// nonce seen-set, is the runtime's rather than this function's, because it is
/// state rather than a property of the message.
///
/// A runtime that hands an unverified payload to user code has already lost:
/// the handler will act on it, and "we checked afterwards" is not a check.
pub fn verify_event(
    body: &serde_json::Value,
    signing_key: &[u8],
    now: DateTime<Utc>,
    skew: chrono::Duration,
) -> Result<ReactorEvent, EventRejection> {
    // 1. key_version, before anything else about the body is considered.
    let key_version = body
        .get("key_version")
        .and_then(serde_json::Value::as_u64)
        .and_then(|v| u8::try_from(v).ok())
        .ok_or(EventRejection::Malformed(
            "key_version is absent or invalid",
        ))?;
    if key_version < REACTOR_KEY_VERSION {
        return Err(EventRejection::KeyVersionTooOld(key_version));
    }

    // 2. the MAC, over the body with hmac_signature serialized as null.
    let signature = body
        .get("hmac_signature")
        .and_then(serde_json::Value::as_str)
        .ok_or(EventRejection::BadSignature)?
        .to_owned();
    let canonical = canonical_event_bytes(body)?;
    if !verify_payload(signing_key, &canonical, &signature) {
        return Err(EventRejection::BadSignature);
    }

    // 3. freshness, in both directions.
    let event: ReactorEvent = serde_json::from_value(body.clone())
        .map_err(|_| EventRejection::Malformed("body does not decode as a reactor event"))?;
    if !is_fresh(event.issued_at, now, skew) {
        return Err(EventRejection::Stale);
    }

    Ok(event)
}

// ---------------------------------------------------------------------------
// Reply (reactor → server)
// ---------------------------------------------------------------------------

/// The closed set of decision values (§22.4). Lowercase on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ReplyDecision {
    /// Proceed unchanged. Carries `require_mfa` on `login.post_auth`.
    Allow,
    /// Refuse. The `reason` is for the audit trail, not for the decision — a
    /// deny with no reason still denies, and the server substitutes
    /// `"denied by reactor"`.
    Deny,
    /// Proceed, applying `patch`. Mutable events only.
    Mutate,
}

impl ReplyDecision {
    /// The wire string.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
            Self::Mutate => "mutate",
        }
    }
}

impl std::fmt::Display for ReplyDecision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A reactor's answer to one event (CONTRACT.md §22.4).
///
/// The three conditionally-omitted fields are load-bearing. A reply that
/// serializes `"require_mfa": false` rather than omitting it produces
/// different canonical bytes and therefore a different MAC — the omission
/// rule, not just the values, is part of the wire format.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReactorReply {
    /// Copied from the event body. The single-use handle binding one reply to
    /// one event; a reply carrying any other value is refused as
    /// `wrong_correlation` even when its signature is perfectly valid.
    pub correlation_id: Uuid,
    /// Copied from the event body.
    pub tenant_id: Uuid,
    /// Copied from the event body.
    pub event: String,
    /// `allow`, `deny` or `mutate`.
    pub decision: ReplyDecision,
    /// Audited on a `deny`. **Omitted when absent.**
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// A flat `string → string` map — there is no nested or typed patch in v1.
    /// **Omitted when absent.** `mutate` only, and only on a mutable event.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub patch: Option<BTreeMap<String, String>>,
    /// `login.post_auth` only. **Omitted when `false`.**
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub require_mfa: bool,
    /// §8 v2 envelope key version — always [`REACTOR_KEY_VERSION`].
    pub key_version: u8,
    /// A **fresh** UUIDv4 per reply. It is inside the signed bytes, so a
    /// unique one is what keeps two replies from being byte-identical — which
    /// is what makes a captured reply distinguishable from a fresh one.
    /// Emitting a constant nonce removes the only uniqueness a reply body
    /// carries beyond its timestamp.
    pub nonce: Uuid,
    /// Reactor-side send time. The server rejects a reply outside ±300 s of
    /// its own clock, in either direction.
    pub issued_at: DateTime<Utc>,
    /// HMAC-SHA256 over this body with the field serialized as `null`.
    pub hmac_signature: Option<String>,
}

impl ReactorReply {
    /// Build an unsigned reply answering `event`, with `correlation_id`,
    /// `tenant_id` and `event` copied from the event body (§22.1, §22.4).
    ///
    /// The nonce is fresh per call and `issued_at` is `now` — both inside the
    /// signed bytes. Call [`ReactorReply::sign`] before publishing.
    pub fn answering(event: &ReactorEvent, decision: ReplyDecision, now: DateTime<Utc>) -> Self {
        Self {
            correlation_id: event.correlation_id,
            tenant_id: event.tenant_id,
            event: event.event.clone(),
            decision,
            reason: None,
            patch: None,
            require_mfa: false,
            key_version: REACTOR_KEY_VERSION,
            nonce: Uuid::new_v4(),
            issued_at: now,
            hmac_signature: None,
        }
    }

    /// The exact bytes this reply is signed over: itself, serialized in
    /// declaration order, with `hmac_signature` set to `null`.
    ///
    /// Clearing the field here rather than asking the caller to remember is
    /// what makes it impossible to sign over a body that already contains a
    /// signature.
    pub fn canonical_signed_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        let mut unsigned = self.clone();
        unsigned.hmac_signature = None;
        serde_json::to_vec(&unsigned)
    }

    /// Sign this reply in place with the tenant's derived AMQP subkey.
    ///
    /// Also forces `key_version` to [`REACTOR_KEY_VERSION`]: signing under a
    /// version the server would refuse is never what a caller meant.
    pub fn sign(&mut self, signing_key: &[u8]) -> Result<(), serde_json::Error> {
        self.hmac_signature = None;
        self.key_version = REACTOR_KEY_VERSION;
        let bytes = self.canonical_signed_bytes()?;
        self.hmac_signature = Some(sign_payload(signing_key, &bytes));
        Ok(())
    }

    /// Verify this reply's own signature — the check the server performs, made
    /// available so an SDK test (or a proxy) can run it locally.
    pub fn signature_valid(&self, signing_key: &[u8]) -> bool {
        let Some(signature) = self.hmac_signature.as_deref() else {
            return false;
        };
        let Ok(bytes) = self.canonical_signed_bytes() else {
            return false;
        };
        verify_payload(signing_key, &bytes, signature)
    }
}

/// Why the server would not use a reply (CONTRACT.md §22.4).
///
/// Every variant resolves to the registration's `failure_policy` and every
/// variant is audited: a rejected reply is **not** a softer failure than no
/// reply at all. This SDK exposes the taxonomy so a reactor author can assert
/// against it in tests and read it in a log line, and rejects the two members
/// it can detect locally without guessing (see
/// [`reactor_serve`](super::reactor_serve)).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplyRejection {
    /// `correlation_id` is not the one dispatched.
    WrongCorrelation,
    /// The reply names another tenant.
    TenantMismatch,
    /// The reply names another event.
    EventMismatch,
    /// `key_version < 2`.
    KeyVersionTooOld(u8),
    /// `issued_at` outside ±300 s, in either direction.
    Stale,
    /// Missing or wrong MAC.
    BadSignature,
    /// `require_mfa` on any event other than `login.post_auth` — checked
    /// before the decision, so it refuses a `deny` carrying it too.
    RequireMfaNotSupported,
    /// `mutate` on a veto-only event.
    NotMutable,
    /// A patch key outside the event's allow-list. Carries the offending key,
    /// which the audit record names.
    ForbiddenPatchField(String),
    /// `mutate` with no patch, `mutate` with an empty patch, or `allow`
    /// carrying a patch.
    MalformedMutation,
}

impl std::fmt::Display for ReplyRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WrongCorrelation => write!(f, "reply correlation_id does not match the event"),
            Self::TenantMismatch => write!(f, "reply is for a different tenant"),
            Self::EventMismatch => write!(f, "reply is for a different event"),
            Self::KeyVersionTooOld(v) => {
                write!(f, "reply key_version {v} is below the accepted floor")
            }
            Self::Stale => write!(f, "reply issued_at is outside the freshness window"),
            Self::BadSignature => write!(f, "reply signature is missing or invalid"),
            Self::RequireMfaNotSupported => {
                write!(f, "require_mfa is not supported for this event")
            }
            Self::NotMutable => write!(f, "event is veto-only; a mutate reply is not accepted"),
            Self::ForbiddenPatchField(key) => {
                write!(f, "patch field '{key}' is outside the event's allow-list")
            }
            Self::MalformedMutation => write!(f, "mutate without a patch, or patch without mutate"),
        }
    }
}

impl std::error::Error for ReplyRejection {}
