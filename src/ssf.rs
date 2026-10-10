//! The SSF receiver helper — CONTRACT.md §32.7 (contract 1.56).
//!
//! AXIAM is a Shared Signals Framework transmitter: it sends CAEP and RISC
//! security events as Security Event Tokens (RFC 8417) to the relying parties
//! a tenant administrator registered (the §27 `ssf` namespace,
//! [`crate::management::ops::ssf`]). This module is for the **relying party**
//! that receives them, and is a different audience from that namespace:
//!
//! * [`SsfReceiver::verify_set`] verifies one compact SET — pushed to your
//!   endpoint (RFC 8935) or returned by a poll — in the contract's fixed order
//!   and refuses at the first failure with an [`AxiamError::Auth`] whose
//!   [`AxiamError::set_failure_reason`] names the step.
//! * [`SsfReceiver::poll`] calls the stream's poll endpoint (RFC 8936), verifies
//!   every returned SET and hands back the verified and the refused apart.
//!
//! Neither transmits, signs or registers anything, and neither trusts a key it
//! did not fetch from the configured JWKS: no `jwk` or `x5c` header member is
//! honoured (§32.9).

use crate::time::Duration;
use std::collections::{BTreeMap, HashMap};
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
use serde::Serialize;
use serde_json::{Map, Value};

use crate::client::AxiamClient;
use crate::error::{AxiamError, SetFailureReason};
use crate::sensitive::Sensitive;
use crate::token::jwks::JwksVerifier;

/// The replay window's floor and default: seven days, the transmitter's buffer
/// retention (§32.6). A window shorter than that would forget a `jti` the
/// transmitter can still re-send.
pub const MIN_REPLAY_WINDOW: Duration = Duration::from_secs(7 * 24 * 60 * 60);

/// The six event types AXIAM transmits, plus the two SSF stream events
/// (§32.6). Event types are open: a SET whose type is not among these still
/// verifies, and [`SecurityEvent::event_type`] carries it verbatim.
pub mod event_types {
    /// CAEP session revoked.
    pub const SESSION_REVOKED: &str =
        "https://schemas.openid.net/secevent/caep/event-type/session-revoked";
    /// CAEP credential change.
    pub const CREDENTIAL_CHANGE: &str =
        "https://schemas.openid.net/secevent/caep/event-type/credential-change";
    /// CAEP assurance level change.
    pub const ASSURANCE_LEVEL_CHANGE: &str =
        "https://schemas.openid.net/secevent/caep/event-type/assurance-level-change";
    /// RISC account disabled.
    pub const ACCOUNT_DISABLED: &str =
        "https://schemas.openid.net/secevent/risc/event-type/account-disabled";
    /// RISC account enabled.
    pub const ACCOUNT_ENABLED: &str =
        "https://schemas.openid.net/secevent/risc/event-type/account-enabled";
    /// RISC account purged.
    pub const ACCOUNT_PURGED: &str =
        "https://schemas.openid.net/secevent/risc/event-type/account-purged";
    /// SSF verification.
    pub const VERIFICATION: &str =
        "https://schemas.openid.net/secevent/ssf/event-type/verification";
    /// SSF stream updated.
    pub const STREAM_UPDATED: &str =
        "https://schemas.openid.net/secevent/ssf/event-type/stream-updated";
}

/// Where the transmitter's signing keys come from.
#[derive(Debug, Clone)]
pub enum SsfKeySource {
    /// The JWKS URL itself (AXIAM: `{issuer}/oauth2/jwks`).
    JwksUri(String),
    /// The transmitter's SSF configuration document
    /// (`/.well-known/ssf-configuration…`); its `jwks_uri` is used, and its
    /// `issuer` must equal the configured issuer.
    DiscoveryUrl(String),
}

/// A future yielding the bearer [`SsfReceiver::poll`] presents: a
/// client-credentials access token carrying `ssf.manage` (for example from
/// [`AxiamClient::login_client_credentials`]).
pub type AccessTokenFuture =
    Pin<Box<dyn Future<Output = Result<Sensitive<String>, AxiamError>> + Send>>;

/// Supplies [`AccessTokenFuture`]s, called once per poll.
pub type AccessTokenProvider = Arc<dyn Fn() -> AccessTokenFuture + Send + Sync>;

/// Why a [`ReplayStore`] could not answer: its backend was unreachable, a
/// timeout, an error of any kind. Boxed, so a store reports whatever error its
/// backend raised.
pub type ReplayStoreError = Box<dyn std::error::Error + Send + Sync>;

/// Remembers the `jti`s already accepted, for step 9.
///
/// Pluggable so a receiver running several instances can share one store
/// (§32.7). [`MemoryReplayStore`] is the default.
///
/// A store has three answers — seen, not seen, **cannot answer** — and
/// [`Self::check_and_record`] can give all three (§32.7 step 9, contract 1.60
/// P4). A store that cannot answer returns `Err`: that is **no verdict**. The
/// SET is neither refused nor accepted and stays *unjudged* —
/// [`SsfReceiver::verify_set`] raises an [`AxiamError::Network`] chaining your
/// error, and [`SsfReceiver::poll`] records nothing for it, returns it in
/// neither `events` nor `refused` (its `jti` is in
/// [`SsfPollResult::unjudged`]) and expects you not to acknowledge it, so the
/// transmitter offers it again. Never answer `Ok(false)` ("already seen") for a
/// `jti` you could not check: that turns an outage into a `replayed` refusal,
/// which a caller acknowledges, and an event that was never processed is lost.
/// Make the outage visible from inside the store as well (a log line, a
/// metric).
pub trait ReplayStore: Send + Sync {
    /// Record `jti` for `window` and return `Ok(true)`, or return `Ok(false)`
    /// without recording when it is already held, or `Err` when the store
    /// cannot answer (nothing is recorded then). Must be atomic: two
    /// concurrent calls with one `jti` must not both see `Ok(true)`.
    ///
    /// # Errors
    /// [`ReplayStoreError`] when the store cannot answer — no verdict on the
    /// SET.
    fn check_and_record(&self, jti: &str, window: Duration) -> Result<bool, ReplayStoreError>;
}

/// The in-memory [`ReplayStore`]: one process, lost on restart.
///
/// Bounded in time, **unbounded in count**: every accepted `jti` is kept for
/// the replay window (seven days by default) and dropped once it expires, with
/// no cap on how many are held meanwhile (§34.2 P4 permits this). A receiver
/// that expects a high event rate, or runs several instances, supplies its own
/// store.
#[derive(Debug, Default)]
pub struct MemoryReplayStore {
    seen: Mutex<HashMap<String, crate::time::Instant>>,
}

impl ReplayStore for MemoryReplayStore {
    fn check_and_record(&self, jti: &str, window: Duration) -> Result<bool, ReplayStoreError> {
        let now = crate::time::Instant::now();
        let mut seen = self.seen.lock().unwrap_or_else(|p| p.into_inner());
        seen.retain(|_, expires| *expires > now);
        if seen.contains_key(jti) {
            return Ok(false);
        }
        seen.insert(jti.to_string(), now + window);
        Ok(true)
    }
}

/// Configuration for an [`SsfReceiver`] (§32.7: `{ issuer, audience,
/// jwks_uri | discovery_url, access_token_provider }`).
#[derive(Clone)]
pub struct SsfReceiverConfig {
    /// The transmitter's issuer — compared to `iss` exactly.
    pub issuer: String,
    /// This receiver's audience — the stream's `audience`.
    pub audience: String,
    /// Where the signing keys come from.
    pub keys: SsfKeySource,
    /// The bearer for [`SsfReceiver::poll`]; `None` for a push-only receiver.
    pub access_token_provider: Option<AccessTokenProvider>,
    /// How long a `jti` is remembered. At least [`MIN_REPLAY_WINDOW`].
    pub replay_window: Duration,
    /// Where accepted `jti`s are kept; `None` uses a [`MemoryReplayStore`].
    pub replay_store: Option<Arc<dyn ReplayStore>>,
}

impl std::fmt::Debug for SsfReceiverConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SsfReceiverConfig")
            .field("issuer", &self.issuer)
            .field("audience", &self.audience)
            .field("keys", &self.keys)
            .field(
                "access_token_provider",
                &self.access_token_provider.as_ref().map(|_| "<provider>"),
            )
            .field("replay_window", &self.replay_window)
            .finish_non_exhaustive()
    }
}

impl SsfReceiverConfig {
    /// A configuration with the default replay window and store and no poll
    /// credential.
    pub fn new(issuer: impl Into<String>, audience: impl Into<String>, keys: SsfKeySource) -> Self {
        Self {
            issuer: issuer.into(),
            audience: audience.into(),
            keys,
            access_token_provider: None,
            replay_window: MIN_REPLAY_WINDOW,
            replay_store: None,
        }
    }
}

/// A verified Security Event Token (§32.7's result).
#[derive(Debug, Clone, PartialEq)]
pub struct SecurityEvent {
    /// The SET's unique id.
    pub jti: String,
    /// When it was issued, seconds since the epoch.
    pub iat: i64,
    /// The issuer, equal to the configured one.
    pub iss: String,
    /// The audience as sent: one string, or an array containing yours.
    pub aud: Value,
    /// The transaction id shared by every SET one operation produced.
    pub txn: Option<String>,
    /// The single `events` key — an event-type URI, see [`event_types`].
    pub event_type: String,
    /// That event's object, opaque to the helper.
    pub event: Value,
    /// The RFC 9493 subject identifier, opaque to the helper.
    pub sub_id: Value,
}

/// One SET a poll returned and the helper refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefusedSet {
    /// The key the transmitter returned the SET under.
    pub jti: String,
    /// Why it was refused. Pass [`SetErr::from_reason`] of it in the next
    /// poll's `set_errs` — unless it is [`SetFailureReason::Replayed`]: this
    /// receiver accepted that SET earlier, so acknowledge it in `ack`
    /// (§32.7, contract 1.59 P2).
    pub reason: SetFailureReason,
}

/// An RFC 8936 `setErrs` entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SetErr {
    /// The RFC 8935 §2.4 code.
    pub err: String,
    /// Optional text. AXIAM never stores it (§32.6).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

impl SetErr {
    /// The entry for a refusal: its [`SetFailureReason::push_error_code`].
    pub fn from_reason(reason: SetFailureReason) -> Self {
        Self {
            err: reason.push_error_code().to_string(),
            description: None,
        }
    }
}

/// Arguments to [`SsfReceiver::poll`]. Every member is passed through as given;
/// an unset one is not sent.
#[derive(Debug, Clone, Default)]
pub struct SsfPollOptions {
    /// `maxEvents` — the server clamps it to 100; `0` acknowledges and returns
    /// nothing.
    pub max_events: Option<u32>,
    /// `returnImmediately` — without it the server long-polls up to 30 s.
    pub return_immediately: Option<bool>,
    /// `ack` — the `jti`s you **processed** since the last poll.
    pub ack: Option<Vec<String>>,
    /// `setErrs` — the `jti`s you refuse, each with its code.
    pub set_errs: Option<BTreeMap<String, SetErr>>,
}

#[derive(Serialize)]
struct PollBody<'a> {
    #[serde(rename = "maxEvents", skip_serializing_if = "Option::is_none")]
    max_events: Option<u32>,
    #[serde(rename = "returnImmediately", skip_serializing_if = "Option::is_none")]
    return_immediately: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ack: Option<&'a Vec<String>>,
    #[serde(rename = "setErrs", skip_serializing_if = "Option::is_none")]
    set_errs: Option<&'a BTreeMap<String, SetErr>>,
}

/// What [`SsfReceiver::poll`] returns.
#[derive(Debug, Clone)]
pub struct SsfPollResult {
    /// The SETs that verified, in the order the transmitter's map listed them.
    pub events: Vec<SecurityEvent>,
    /// Whether the transmitter holds more.
    pub more_available: bool,
    /// The SETs that did not verify.
    pub refused: Vec<RefusedSet>,
    /// The `jti`s of SETs that verified but that the [`ReplayStore`] could not
    /// answer for, and those after them in the batch (contract 1.60 P1, P4):
    /// neither accepted nor refused, recorded nowhere. Acknowledge none of
    /// them and refuse none of them; the transmitter offers them again.
    pub unjudged: Vec<String>,
}

/// The receiver helper (§32.7). Build with [`SsfReceiver::new`].
pub struct SsfReceiver {
    client: AxiamClient,
    issuer: String,
    audience: String,
    keys: SsfKeySource,
    verifier: tokio::sync::OnceCell<JwksVerifier>,
    token_provider: Option<AccessTokenProvider>,
    replay_window: Duration,
    replay_store: Arc<dyn ReplayStore>,
}

impl std::fmt::Debug for SsfReceiver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SsfReceiver")
            .field("issuer", &self.issuer)
            .field("audience", &self.audience)
            .field("keys", &self.keys)
            .field("replay_window", &self.replay_window)
            .finish_non_exhaustive()
    }
}

fn refuse(reason: SetFailureReason, detail: &str) -> AxiamError {
    AxiamError::set_refused(reason, detail)
}

fn b64_json(part: &str) -> Option<Map<String, Value>> {
    let bytes = URL_SAFE_NO_PAD.decode(part).ok()?;
    match serde_json::from_slice(&bytes).ok()? {
        Value::Object(map) => Some(map),
        _ => None,
    }
}

impl SsfReceiver {
    /// Build a receiver over `client`'s transport (its §6 TLS policy fetches
    /// the JWKS; its base URL is the transmitter root `poll` calls).
    ///
    /// # Errors
    /// A local `ValidationError` when `replay_window` is below
    /// [`MIN_REPLAY_WINDOW`], or `issuer` / `audience` is empty.
    pub fn new(client: &AxiamClient, config: SsfReceiverConfig) -> Result<Self, AxiamError> {
        use crate::management::error::local_refusal;
        if config.replay_window < MIN_REPLAY_WINDOW {
            return Err(local_refusal(
                "ssf.receiver",
                "replay_window",
                "must be at least seven days, the transmitter's buffer retention (CONTRACT.md §32.7)",
            ));
        }
        if config.issuer.is_empty() || config.audience.is_empty() {
            return Err(local_refusal(
                "ssf.receiver",
                "issuer",
                "issuer and audience are required (CONTRACT.md §32.7)",
            ));
        }
        Ok(Self {
            client: client.clone(),
            issuer: config.issuer,
            audience: config.audience,
            keys: config.keys,
            verifier: tokio::sync::OnceCell::new(),
            token_provider: config.access_token_provider,
            replay_window: config.replay_window,
            replay_store: config
                .replay_store
                .unwrap_or_else(|| Arc::new(MemoryReplayStore::default())),
        })
    }

    async fn verifier(&self) -> Result<&JwksVerifier, AxiamError> {
        self.verifier
            .get_or_try_init(|| async {
                let jwks_uri = match &self.keys {
                    SsfKeySource::JwksUri(u) => u.clone(),
                    SsfKeySource::DiscoveryUrl(d) => self.discover_jwks_uri(d).await?,
                };
                let url = parse_secure("jwks_uri", &jwks_uri)?;
                Ok::<_, AxiamError>(JwksVerifier::for_jwks_url(self.client.http().clone(), url))
            })
            .await
    }

    async fn discover_jwks_uri(&self, discovery_url: &str) -> Result<String, AxiamError> {
        let url = parse_secure("discovery_url", discovery_url)?;
        let response = self
            .client
            .http()
            .get(url)
            .send()
            .await
            .map_err(|e| AxiamError::network(format!("SSF configuration fetch failed: {e}")))?;
        if !response.status().is_success() {
            return Err(AxiamError::from_http_status(
                response.status().as_u16(),
                "SSF configuration endpoint returned a non-success status",
            ));
        }
        let doc: Value = response
            .json()
            .await
            .map_err(|e| AxiamError::network(format!("SSF configuration parse failed: {e}")))?;
        if doc.get("issuer").and_then(Value::as_str) != Some(self.issuer.as_str()) {
            return Err(AxiamError::network(
                "the SSF configuration's issuer is not the configured issuer",
            ));
        }
        doc.get("jwks_uri")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| AxiamError::network("the SSF configuration carries no jwks_uri"))
    }

    /// Verify one compact SET (§32.7), in this order, refusing at the first
    /// failure with the [`SetFailureReason`] in brackets:
    ///
    /// 1. three base64url parts, a JSON header and payload \[`malformed`\];
    /// 2. `typ` `secevent+jwt` or `application/secevent+jwt`, any case
    ///    \[`invalid_type`\];
    /// 3. `alg` exactly `EdDSA` \[`invalid_key`\];
    /// 4. the `kid` in the configured JWKS — on a miss, one refetch, at most
    ///    once a minute \[`invalid_key`\];
    /// 5. the signature \[`invalid_key`\];
    /// 6. `iss` equal to the configured issuer \[`invalid_issuer`\];
    /// 7. `aud` equal to, or an array containing, the audience
    ///    \[`invalid_audience`\];
    /// 8. no `exp`, no `sub`; `jti`, `iat`, `sub_id` present; exactly one
    ///    `events` member \[`invalid_request`\];
    /// 9. a `jti` not seen within the replay window \[`replayed`\] — recorded
    ///    only once steps 1–8 passed.
    ///
    /// A SET that verifies has been **recorded**: verifying it again is
    /// `replayed`. Acknowledge a polled SET once you have processed it.
    ///
    /// # Errors
    /// [`AxiamError::Auth`] with [`AxiamError::set_failure_reason`] set, or
    /// [`AxiamError::Network`] when the JWKS could not be fetched or the
    /// [`ReplayStore`] could not answer — neither is a verdict on the SET
    /// (§34.2 P3, P4), and the error carries no reason code. A SET whose store
    /// failed was not recorded: verify it again once the store is back.
    pub async fn verify_set(&self, set: &str) -> Result<SecurityEvent, AxiamError> {
        let event = self.judge(set, None).await?;
        self.record(event)
    }

    /// Step 9: record the `jti` of a SET that passed steps 1–8.
    fn record(&self, event: SecurityEvent) -> Result<SecurityEvent, AxiamError> {
        // A store that cannot answer gives no verdict (§34.2 P4): the SET is
        // neither refused nor accepted, and the error is no `replayed`.
        match self
            .replay_store
            .check_and_record(&event.jti, self.replay_window)
        {
            Ok(true) => Ok(event),
            Ok(false) => Err(refuse(SetFailureReason::Replayed, "jti already seen")),
            Err(cause) => Err(AxiamError::network_with_source(
                "the replay store could not answer: the SET is unjudged and was not recorded",
                cause,
            )),
        }
    }

    /// Steps 1–8, recording nothing.
    async fn judge(
        &self,
        set: &str,
        expected_jti: Option<&str>,
    ) -> Result<SecurityEvent, AxiamError> {
        use SetFailureReason::*;
        // 1.
        let parts: Vec<&str> = set.split('.').collect();
        if parts.len() != 3 || URL_SAFE_NO_PAD.decode(parts[2]).is_err() {
            return Err(refuse(Malformed, "not three base64url parts"));
        }
        let (Some(header), Some(claims)) = (b64_json(parts[0]), b64_json(parts[1])) else {
            return Err(refuse(Malformed, "header or payload is not a JSON object"));
        };
        // 2.
        let typ = header.get("typ").and_then(Value::as_str).unwrap_or("");
        if !typ.eq_ignore_ascii_case("secevent+jwt")
            && !typ.eq_ignore_ascii_case("application/secevent+jwt")
        {
            return Err(refuse(InvalidType, "typ is not secevent+jwt"));
        }
        // 3.
        if header.get("alg").and_then(Value::as_str) != Some("EdDSA") {
            return Err(refuse(InvalidKey, "alg is not EdDSA"));
        }
        // 4.
        let Some(kid) = header.get("kid").and_then(Value::as_str) else {
            return Err(refuse(InvalidKey, "no kid"));
        };
        let verifier = self.verifier().await?;
        let Some(jwk) = verifier.key_for_kid(kid).await? else {
            return Err(refuse(InvalidKey, "no key for kid in the JWKS"));
        };
        // 5.
        let key = DecodingKey::from_jwk(&jwk)
            .map_err(|_| refuse(InvalidKey, "the JWKS key is not usable"))?;
        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.required_spec_claims.clear();
        validation.validate_exp = false;
        validation.validate_nbf = false;
        validation.validate_aud = false;
        validation.leeway = 0;
        decode::<Value>(set, &key, &validation)
            .map_err(|_| refuse(InvalidKey, "signature does not verify"))?;
        // 6.
        let iss = claims.get("iss").and_then(Value::as_str).unwrap_or("");
        if iss != self.issuer {
            return Err(refuse(InvalidIssuer, "iss is not the configured issuer"));
        }
        // 7.
        let aud = claims.get("aud").cloned().unwrap_or(Value::Null);
        let aud_ok = match &aud {
            Value::String(a) => *a == self.audience,
            Value::Array(items) => items.iter().any(|a| a.as_str() == Some(&self.audience)),
            _ => false,
        };
        if !aud_ok {
            return Err(refuse(InvalidAudience, "aud does not name this receiver"));
        }
        // 8.
        if claims.contains_key("exp") || claims.contains_key("sub") {
            return Err(refuse(InvalidRequest, "a SET carries no exp and no sub"));
        }
        let jti = claims
            .get("jti")
            .and_then(Value::as_str)
            .filter(|j| !j.is_empty())
            .ok_or_else(|| refuse(InvalidRequest, "no jti"))?;
        let iat = claims
            .get("iat")
            .and_then(Value::as_i64)
            .ok_or_else(|| refuse(InvalidRequest, "no numeric iat"))?;
        let sub_id = claims
            .get("sub_id")
            .filter(|v| v.is_object())
            .cloned()
            .ok_or_else(|| refuse(InvalidRequest, "no sub_id"))?;
        let events = claims
            .get("events")
            .and_then(Value::as_object)
            .filter(|e| e.len() == 1)
            .ok_or_else(|| refuse(InvalidRequest, "events must have exactly one member"))?;
        if expected_jti.is_some_and(|k| k != jti) {
            return Err(refuse(InvalidRequest, "the poll key is not the SET's jti"));
        }
        let (event_type, event) = events.iter().next().expect("one member");
        // 9 is the caller's: `verify_set` and `poll` record through `record`.
        Ok(SecurityEvent {
            jti: jti.to_string(),
            iat,
            iss: iss.to_string(),
            aud,
            txn: claims.get("txn").and_then(Value::as_str).map(str::to_owned),
            event_type: event_type.clone(),
            event: event.clone(),
            sub_id,
        })
    }

    /// Poll the stream's RFC 8936 endpoint, `{root}/ssf/v1/poll/{stream_id}`,
    /// with a bearer from the configured `access_token_provider`.
    ///
    /// `ack` and `set_errs` are sent exactly as given. **Nothing is
    /// acknowledged on your behalf**: acknowledge, on the next call, the
    /// `jti`s you processed, and pass each refused one in `set_errs`
    /// ([`SetErr::from_reason`]) — except a `replayed` one, which this
    /// receiver accepted on an earlier poll: acknowledge that one in `ack`
    /// (§32.7, contract 1.59 P2). A SET you neither acknowledge nor refuse is
    /// re-offered, and — having been recorded when it verified — then reads as
    /// `replayed`.
    ///
    /// **All or nothing** (§32.7, contract 1.59 P1): steps 1–8 run over the
    /// whole batch before any `jti` is recorded. A failure that is no verdict
    /// on a SET — the JWKS or discovery fetch failing — aborts the poll with
    /// that error having recorded nothing, so every SET of the batch is offered
    /// again and none is lost as a false `replayed`.
    ///
    /// **A store that cannot answer is no verdict either** (contract 1.60 P4):
    /// the store's one atomic check-and-record cannot undo a `jti` recorded
    /// earlier in the batch, so the poll returns what it judged — the SETs
    /// recorded before the failure — and leaves the SET the store failed on
    /// and every one after it *unjudged*: in neither `events` nor `refused`,
    /// recorded nowhere, their `jti`s in [`SsfPollResult::unjudged`]. Do not
    /// acknowledge them; the transmitter offers them again.
    ///
    /// Retried per §16 on a transport failure, a `5xx`, a `408` or a `429`;
    /// never on another `4xx`.
    pub async fn poll(
        &self,
        stream_id: &str,
        options: SsfPollOptions,
    ) -> Result<SsfPollResult, AxiamError> {
        use crate::retry::{
            Attempt, RetryRunner, ThreadRngJitter, TokioSleeper, parse_retry_after,
        };
        self.client.ensure_open()?;
        let provider = self.token_provider.as_ref().ok_or_else(|| {
            AxiamError::auth(
                "ssf.poll needs an access_token_provider (a client-credentials token with ssf.manage)",
            )
        })?;
        let mut url = self.client.base_url().clone();
        url.path_segments_mut()
            .map_err(|_| AxiamError::network("the base URL cannot carry a path"))?
            .pop_if_empty()
            .extend(["ssf", "v1", "poll", stream_id]);
        let body = PollBody {
            max_events: options.max_events,
            return_immediately: options.return_immediately,
            ack: options.ack.as_ref(),
            set_errs: options.set_errs.as_ref(),
        };
        let token = provider().await?;
        let runner = RetryRunner {
            enabled: self.client.retry_enabled(),
            operation: "ssf.poll",
            telemetry: self.client.telemetry(),
            jitter: &ThreadRngJitter,
            sleeper: &TokioSleeper,
        };
        let (url, body, token) = (&url, &body, &token);
        let reply: Value = runner
            .run(|_| async move {
                let response = self
                    .client
                    .http_bare()
                    .post(url.clone())
                    .bearer_auth(token.expose())
                    .json(body)
                    .send()
                    .await
                    .map_err(|e| {
                        Attempt::bare(AxiamError::network(format!("ssf.poll request failed: {e}")))
                    })?;
                let status = response.status();
                if !status.is_success() {
                    let retry_after = response
                        .headers()
                        .get(reqwest::header::RETRY_AFTER)
                        .and_then(|v| v.to_str().ok())
                        .and_then(parse_retry_after);
                    let text = response.text().await.unwrap_or_default();
                    let err = crate::management::error::from_management_status(
                        "ssf.poll",
                        status.as_u16(),
                        text,
                    );
                    // §32.7: never retried on a 4xx.
                    if !crate::retry::status_is_retryable(status.as_u16()) {
                        return Ok(Err(err));
                    }
                    return Err(Attempt { err, retry_after });
                }
                Ok(response.json::<Value>().await.map_err(|e| {
                    AxiamError::network(format!("ssf.poll: failed to parse the response: {e}"))
                }))
            })
            .await??;

        let more_available = reply
            .get("moreAvailable")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        // Steps 1–8 over the whole batch first: a non-verdict failure on any
        // SET returns here, before a single `jti` is recorded (P1).
        let mut judged = Vec::new();
        if let Some(sets) = reply.get("sets").and_then(Value::as_object) {
            for (jti, set) in sets {
                let verdict = match set.as_str() {
                    Some(set) => self.judge(set, Some(jti)).await,
                    None => Err(refuse(SetFailureReason::Malformed, "not a string")),
                };
                if let Err(e) = &verdict
                    && e.set_failure_reason().is_none()
                {
                    return Err(verdict.unwrap_err());
                }
                judged.push((jti, verdict));
            }
        }
        // Step 9, in the transmitter's order.
        let mut events = Vec::new();
        let mut refused = Vec::new();
        let mut unjudged = Vec::new();
        for (jti, verdict) in judged {
            // The store already failed: it is not asked again for the rest of
            // the batch, whose SETs stay unjudged and unrecorded (P1, P4).
            if !unjudged.is_empty() && verdict.is_ok() {
                unjudged.push(jti.clone());
                continue;
            }
            match verdict.and_then(|event| self.record(event)) {
                Ok(event) => events.push(event),
                Err(e) => match e.set_failure_reason() {
                    Some(reason) => refused.push(RefusedSet {
                        jti: jti.clone(),
                        reason,
                    }),
                    // No reason code: the store could not answer.
                    None => unjudged.push(jti.clone()),
                },
            }
        }
        Ok(SsfPollResult {
            events,
            more_available,
            refused,
            unjudged,
        })
    }
}

fn parse_secure(label: &str, raw: &str) -> Result<url::Url, AxiamError> {
    let url = url::Url::parse(raw)
        .map_err(|e| AxiamError::network(format!("{label} is not an absolute URL: {e}")))?;
    crate::url_guard::ensure_secure_scheme(label, url.scheme(), url.host_str(), "https")
        .map_err(AxiamError::network)?;
    Ok(url)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_memory_store_refuses_a_second_sighting_and_forgets_after_the_window() {
        let store = MemoryReplayStore::default();
        assert!(
            store
                .check_and_record("a", Duration::from_secs(60))
                .unwrap()
        );
        assert!(
            !store
                .check_and_record("a", Duration::from_secs(60))
                .unwrap()
        );
        assert!(store.check_and_record("b", Duration::ZERO).unwrap());
        assert!(
            store.check_and_record("b", Duration::ZERO).unwrap(),
            "expired, so new again"
        );
    }

    #[test]
    fn push_codes_are_rfc_8935_codes() {
        for (reason, code) in [
            (SetFailureReason::Malformed, "invalid_request"),
            (SetFailureReason::InvalidType, "invalid_request"),
            (SetFailureReason::Replayed, "invalid_request"),
            (SetFailureReason::InvalidKey, "invalid_key"),
            (SetFailureReason::InvalidIssuer, "invalid_issuer"),
            (SetFailureReason::InvalidAudience, "invalid_audience"),
            (SetFailureReason::InvalidRequest, "invalid_request"),
        ] {
            assert_eq!(reason.push_error_code(), code);
            assert_eq!(SetErr::from_reason(reason).err, code);
        }
        assert_eq!(SetFailureReason::Replayed.to_string(), "replayed");
    }
}
