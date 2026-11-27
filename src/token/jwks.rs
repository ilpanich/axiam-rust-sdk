//! Local JWKS fetch/cache/verification (D-03/D-11).
//!
//! Mirrors `crates/axiam-federation/src/oidc.rs:370-429,600-657` — the
//! server's own proven EdDSA/JWKS verification pattern — applied here by
//! the SDK to AXIAM's own tokens. This module does **not** import any
//! `axiam-*` server crate; every type below is the SDK's own plain
//! equivalent (CONTEXT.md domain boundary, 16-PATTERNS.md).
//!
//! Endpoint: `GET {base_url}/oauth2/jwks` — a single, organization-wide
//! endpoint. This is NOT the common OIDC discovery-style JWKS path some
//! other IdPs serve, and it is NOT tenant-scoped.

#[cfg(any(feature = "rest", feature = "actix"))]
use crate::time::{Duration, Instant};
#[cfg(any(feature = "rest", feature = "actix"))]
use std::sync::{Arc, RwLock};

#[cfg(any(feature = "rest", feature = "actix"))]
use jsonwebtoken::jwk::JwkSet;
#[cfg(any(feature = "rest", feature = "actix"))]
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use serde::{Deserialize, Serialize};

// Unconditional: `Claims::verify_certificate_binding` (CONTRACT.md §10.1
// rule 9) returns this and is deliberately available with no features, so a
// `--no-default-features` consumer can apply the rule to a token it obtained
// through its own transport.
use crate::AxiamError;
#[cfg(any(feature = "rest", feature = "actix"))]
use crate::client::OmitBrowserCredentials;

/// The AXIAM JWKS endpoint path — organization-wide, not tenant-scoped
/// (RESEARCH.md D-11). This is the only correct path; do not substitute a
/// generic OIDC discovery-style JWKS path here.
pub const JWKS_PATH: &str = "/oauth2/jwks";

/// How long a fetched `JwkSet` is cached before a normal (non-forced)
/// refetch is attempted, when the response advertises no `Cache-Control:
/// max-age`; and the **upper bound** of every TTL: a larger advertised value is
/// clamped down to it, a smaller one is honoured (CONTRACT.md §12.4 rule 2,
/// contract 1.69). Five minutes, inside the ten §34.2 P6 allows the SSF key
/// cache (contract 1.60).
#[cfg(any(feature = "rest", feature = "actix"))]
const JWKS_CACHE_TTL: Duration = Duration::from_secs(300);

/// How long past its TTL a held key set keeps verifying while no refresh has
/// succeeded (stale-if-error, CONTRACT.md §12.4 rule 2, contract 1.69, D-10).
/// Exactly 300 s beyond the TTL, measured from the last successful fetch:
/// held keys are never used past `TTL + JWKS_MAX_STALE`, however many
/// attempts failed, so a key removed upstream cannot be kept alive by whoever
/// can block the fetch.
#[cfg(any(feature = "rest", feature = "actix"))]
const JWKS_MAX_STALE: Duration = Duration::from_secs(300);

/// After a failed fetch, how long NO verifier makes another (§34.2 P6 and
/// contract 1.69: a failed fill, a failed refresh of an expired cache and a
/// failed unknown-`kid` refetch each count toward the once-a-minute limit, so a
/// JWKS outage is not one fetch per verification). It is also the floor
/// between two TTL-driven refreshes of a held set, so an advertised
/// `max-age=0` never means one fetch per verification.
#[cfg(any(feature = "rest", feature = "actix"))]
pub(crate) const FAILED_FETCH_MIN_INTERVAL: Duration = Duration::from_secs(60);

/// The SDK's own bound on one JWKS fetch (request and body), applied inside the
/// fetch task whatever `reqwest::Client` the caller supplied: a client built
/// with `Client::new()` has no timeout of its own.
#[cfg(any(feature = "rest", feature = "actix"))]
const JWKS_FETCH_TIMEOUT: Duration = Duration::from_secs(10);

/// The shared outcome of one single-flight fetch: the key set, or the failure
/// message (an [`AxiamError`] is not `Clone`).
#[cfg(any(feature = "rest", feature = "actix"))]
type FetchOutcome = Result<JwkSet, String>;

/// Minimum interval between forced refetches triggered by an unknown `kid`,
/// to avoid a hostile/rotating token stream hammering the JWKS endpoint.
#[cfg(any(feature = "rest", feature = "actix"))]
const FORCED_REFETCH_MIN_INTERVAL: Duration = Duration::from_secs(60);

/// Clock-skew leeway applied to the `exp` and `nbf` checks (CONTRACT.md
/// §10.1 rule 7).
///
/// A **named, bounded, non-configurable** constant, deliberately fixed at the
/// contract's RECOMMENDED 60 seconds: rule 7 forbids both an inline literal
/// and an operator-settable value that could be widened to something
/// unbounded. There is no setter for it anywhere in this SDK — widening the
/// window is a source change, reviewable as such.
#[cfg(any(feature = "rest", feature = "actix"))]
pub const CLOCK_SKEW_LEEWAY_SECS: u64 = 60;

/// The SDK's own plain claims struct, matching the field names AXIAM issues
/// in its access tokens (`crates/axiam-auth/src/token.rs::AccessTokenClaims`)
/// — mirrored, not imported.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    /// Subject — user ID (UUID string).
    pub sub: String,
    /// Tenant ID (UUID string).
    pub tenant_id: String,
    /// Organization ID (UUID string).
    #[serde(default)]
    pub org_id: Option<String>,
    /// Issuer.
    pub iss: String,
    /// Issued-at (Unix timestamp).
    #[serde(default)]
    pub iat: Option<i64>,
    /// Expiration (Unix timestamp).
    pub exp: i64,
    /// Unique token ID / session id.
    #[serde(default)]
    pub jti: Option<String>,
    /// The AXIAM session this token descends from (AXIAM T-249).
    ///
    /// Present on tokens minted by the authorization-code and refresh grants;
    /// absent on a client-credentials token, an RPT or a token exchange, which
    /// have no session behind them.
    ///
    /// Read **only** by the §10.4 revocation feed, and deliberately with no
    /// fallback to [`Self::jti`]: a token with no `sid` names no session, and
    /// hashing its `jti` instead would match nothing while looking like it
    /// worked.
    #[serde(default)]
    pub sid: Option<String>,
    /// Token audience — `"axiam:user"` or `"axiam:m2m"`.
    #[serde(default)]
    pub aud: Option<String>,
    /// OAuth2 scopes (space-separated string), if any. `None` also when the
    /// claim is present but is not a string: that must not invalidate the
    /// token, it only makes every `require_scope` fail (§11.2 rule 11d).
    #[serde(default, deserialize_with = "lenient_scope")]
    pub scope: Option<String>,
    /// The subject's global role names in the tenant (CONTRACT.md §11.2
    /// rule 11, contract 1.68). Present only when the client requested the
    /// `roles` scope; absent otherwise.
    ///
    /// `None` also when the claim is present but is not a JSON array of
    /// strings (rule 11b): that must not invalidate the token, it only makes
    /// every role check fail.
    #[serde(
        default,
        deserialize_with = "lenient_roles",
        skip_serializing_if = "Option::is_none"
    )]
    pub roles: Option<Vec<String>>,
    /// RFC 7800 / RFC 8705 §3.1 confirmation claim — present **only** on a
    /// sender-constrained token (CONTRACT.md §10.1 rule 9, contract 1.15).
    ///
    /// Its presence changes what the token *is*. A token without `cnf` is a
    /// bearer credential: whoever holds it may use it. A token with `cnf`
    /// names a key, and accepting it without proving the caller holds that key
    /// converts it back into a bearer token — discarding the whole protection
    /// the operator turned on.
    ///
    /// [`JwksVerifier::verify`] does **not** check it, because it cannot: the
    /// check needs the client certificate for *this connection*, which a
    /// claims-only API has no access to. Use
    /// [`JwksVerifier::verify_sender_constrained`], or call
    /// [`Claims::verify_certificate_binding`] yourself with the thumbprint your
    /// transport gives you.
    #[serde(default)]
    pub cnf: Option<CnfClaim>,
}

/// Read the `roles` claim without letting a malformed one fail the token:
/// anything that is not an array of strings reads as no roles.
fn lenient_roles<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<Vec<String>>, D::Error> {
    let value = serde_json::Value::deserialize(d)?;
    Ok(serde_json::from_value(value).ok())
}

/// Read the `scope` claim without letting a non-string one fail the token.
fn lenient_scope<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<String>, D::Error> {
    Ok(match serde_json::Value::deserialize(d)? {
        serde_json::Value::String(s) => Some(s),
        _ => None,
    })
}

/// RFC 7800 confirmation claim.
///
/// Deliberately a struct with one optional field rather than an enum: RFC 7800
/// permits confirmation methods this SDK does not implement, and such a token
/// must still *decode* — what it must not do is validate. See
/// [`Self::certificate_thumbprint`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CnfClaim {
    /// RFC 8705 §3.1 `x5t#S256` — base64url (unpadded) SHA-256 of the DER
    /// client certificate the token was issued to.
    #[serde(rename = "x5t#S256", default, skip_serializing_if = "Option::is_none")]
    pub x5t_s256: Option<String>,
    /// RFC 9449 §6.1 `jkt` — base64url (unpadded) RFC 7638 thumbprint of the
    /// DPoP public key the token was issued to (contract 1.16).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jkt: Option<String>,
}

impl CnfClaim {
    /// The certificate thumbprint this token is bound to, or `None` when the
    /// confirmation names some other method.
    ///
    /// A caller that gets `None` from a claim that *exists* is looking at a
    /// constraint it cannot check and MUST reject the token. It must never
    /// read that as "unconstrained".
    pub fn certificate_thumbprint(&self) -> Option<&str> {
        self.x5t_s256.as_deref()
    }

    /// The DPoP key thumbprint this token is bound to, or `None` when the
    /// confirmation does not name one (contract 1.16).
    pub fn dpop_thumbprint(&self) -> Option<&str> {
        self.jkt.as_deref()
    }

    /// Whether this confirmation names **no** method this SDK understands.
    ///
    /// A `cnf` that exists but names nothing checkable is the case rule 9 is
    /// most often got wrong: it is an *unverifiable constraint*, never *no
    /// constraint*, and it must be refused. Over gRPC it is also the shape an
    /// empty `CnfClaim` message arrives in, because proto3 cannot distinguish
    /// an absent string from an empty one (§10.3 rule 3).
    pub fn names_nothing_checkable(&self) -> bool {
        self.certificate_thumbprint().is_none() && self.dpop_thumbprint().is_none()
    }
}

/// The proofs a caller can present for a sender-constrained token
/// (contract 1.16, CONTRACT.md §10.1 rule 9).
///
/// Both fields are `Option` because a caller may hold one, both, or neither —
/// and "neither" is a legitimate thing to pass for an ordinary bearer token,
/// which is why [`Claims::verify_token_binding`] accepts it and returns `Ok`
/// when the token names no confirmation.
///
/// # Every thumbprint must come from the transport
///
/// Take the certificate thumbprint from the TLS peer certificate (or from a
/// trusted terminating proxy over a channel your application controls), and
/// the DPoP thumbprint from a proof **you have already verified** against this
/// request's method and URI. Never from a request header the caller can set:
/// a forgeable input makes the whole mechanism decorative.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PresentedProofs<'a> {
    /// RFC 8705 §3.1 `x5t#S256` of the peer certificate on this connection.
    pub certificate_thumbprint: Option<&'a str>,
    /// RFC 9449 §6.1 `jkt` of the key that signed a DPoP proof **this SDK has
    /// already verified** for this request's `htm`/`htu`.
    ///
    /// Passing a thumbprint here asserts the proof checked out. Passing the
    /// `jkt` off an unverified proof would let any captured proof authorize
    /// any request.
    pub dpop_thumbprint: Option<&'a str>,
}

impl Claims {
    /// CONTRACT.md §10.1 rule 9 — enforce this token's sender constraint
    /// against the certificate the caller presented on **this** connection.
    ///
    /// `presented_thumbprint` is the RFC 8705 §3.1 `x5t#S256` of the peer
    /// certificate: base64url, **unpadded**, SHA-256 over the **DER** encoding.
    /// [`certificate_thumbprint_s256`] computes it from DER bytes.
    ///
    /// This is the **narrow** entry point, kept for callers whose transport can
    /// only ever produce a certificate thumbprint. It refuses a DPoP-bound
    /// token outright rather than ignoring the `jkt` it cannot check — see
    /// [`Claims::verify_token_binding`] for the full rule.
    ///
    /// # The five cases
    ///
    /// | this token's `cnf` | `presented_thumbprint` | result |
    /// |---|---|---|
    /// | absent | anything | `Ok` — an ordinary bearer token |
    /// | `x5t#S256` | equal | `Ok` |
    /// | `x5t#S256` | different, or `None` | `Err` |
    /// | names `jkt` (contract 1.16) | anything | `Err` — **this** function cannot check a DPoP proof |
    /// | present, names neither | anything | `Err` |
    ///
    /// The first row is why a guard that adopts this rule does not break
    /// existing deployments: an unbound token is still accepted whether or not
    /// a certificate is present. The last two are the ones that are easy to get
    /// wrong — a `cnf` naming a method this SDK cannot check *here* is an
    /// *unverifiable constraint*, never *no constraint*.
    ///
    /// # The thumbprint must come from the transport
    ///
    /// Take it from the TLS peer certificate, or from a value a **trusted**
    /// terminating proxy forwarded over a channel your application controls.
    /// Never from a request header the caller can set: a forgeable input makes
    /// the whole mechanism decorative.
    ///
    /// # Errors
    ///
    /// [`AxiamError::Auth`] on any of the three rejecting rows.
    pub fn verify_certificate_binding(
        &self,
        presented_thumbprint: Option<&str>,
    ) -> Result<(), AxiamError> {
        let Some(cnf) = self.cnf.as_ref() else {
            return Ok(());
        };

        let auth = |message: &str| AxiamError::Auth {
            message: message.to_owned(),
            oauth: None,
            reason: None,
            set_reason: None,
            retry_after: None,
        };

        let Some(expected) = cnf.certificate_thumbprint() else {
            // Includes the DPoP case: this function has no proof to check, so
            // a `jkt`-bound token is refused rather than silently downgraded.
            return Err(auth(
                "token carries a cnf confirmation naming a method this entry point cannot verify \
                 (CONTRACT.md §10.1 rule 9 — an unverifiable constraint is not an absent one; \
                 use verify_token_binding for DPoP)",
            ));
        };

        // A token naming BOTH methods is a conjunction (contract 1.16): this
        // function can only establish one half, so it must not answer for the
        // whole. Refusing here is what stops "check whichever we can".
        if cnf.dpop_thumbprint().is_some() {
            return Err(auth(
                "token names both a certificate and a DPoP key; both must hold \
                 (CONTRACT.md §10.1 rule 9) — use verify_token_binding",
            ));
        }

        let Some(presented) = presented_thumbprint else {
            return Err(auth(
                "token is certificate-bound but no client certificate was presented",
            ));
        };

        if constant_time_eq(expected.as_bytes(), presented.as_bytes()) {
            Ok(())
        } else {
            Err(auth(
                "token is bound to a different client certificate than the one presented",
            ))
        }
    }

    /// CONTRACT.md §10.1 rule 9 — enforce this token's sender constraint
    /// against **every** proof the caller presented (contract 1.16).
    ///
    /// This is the full rule, and the one to use unless your transport
    /// genuinely cannot produce a DPoP thumbprint.
    ///
    /// # The ten cases
    ///
    /// | this token's `cnf` | certificate | DPoP | result |
    /// |---|---|---|---|
    /// | absent | anything | anything | `Ok` — an ordinary bearer token |
    /// | `x5t#S256` | equal | ignored | `Ok` |
    /// | `x5t#S256` | different | ignored | `Err` |
    /// | `x5t#S256` | `None` | ignored | `Err` |
    /// | `jkt` | ignored | equal | `Ok` |
    /// | `jkt` | ignored | different | `Err` |
    /// | `jkt` | ignored | `None` | `Err` |
    /// | both | equal | equal | `Ok` — **conjunction** |
    /// | both | either wrong or missing | — | `Err` |
    /// | present, names neither | anything | anything | `Err` |
    ///
    /// Two rows carry the weight. **Both present is a conjunction**: an
    /// operator who turned on two constraints asked for two, and satisfying
    /// the more convenient one is not compliance. **Names neither is a
    /// refusal**: a confirmation this SDK cannot interpret is an unverifiable
    /// constraint, and reading it as "unconstrained" is the exact downgrade
    /// rule 9 exists to prevent.
    ///
    /// # The DPoP thumbprint must come from a *verified* proof
    ///
    /// This function compares thumbprints; it does not verify proofs. Supply
    /// `dpop_thumbprint` only after checking the proof's signature, `htm`,
    /// `htu`, `iat` and `jti` for **this** request. A thumbprint lifted from an
    /// unverified proof would let a proof captured from any other endpoint
    /// authorize this one.
    ///
    /// # Errors
    ///
    /// [`AxiamError::Auth`] on any rejecting row.
    pub fn verify_token_binding(&self, proofs: PresentedProofs<'_>) -> Result<(), AxiamError> {
        // The fast path, and the common one. Note it comes first: an unbound
        // token is accepted with no proofs at all, which is the property that
        // keeps existing deployments working.
        match self.cnf.as_ref() {
            None => Ok(()),
            Some(cnf) => cnf.verify(proofs),
        }
    }
}

impl CnfClaim {
    /// CONTRACT.md §10.1 rule 9 for a confirmation that is **present** — the
    /// table [`Claims::verify_token_binding`] documents, minus its first row.
    ///
    /// The one implementation of the rule. [`Claims::verify_token_binding`]
    /// applies it to a locally verified token, and the `grpc` feature's
    /// `TokenValidation::verify_possession` to the `cnf` the gRPC
    /// `TokenService` returned (§10.3 rule 1), so a local-verification caller
    /// and a gRPC-introspecting one cannot disagree about whether a token is a
    /// bearer token (§10.1 rule 9 detail 4).
    ///
    /// A confirmation naming neither member is refused — over gRPC that is an
    /// empty `CnfClaim` message, which §10.3 rule 3 says to refuse rather than
    /// read as unbound.
    ///
    /// # Errors
    ///
    /// [`AxiamError::Auth`] on any rejecting row.
    pub fn verify(&self, proofs: PresentedProofs<'_>) -> Result<(), AxiamError> {
        let cnf = self;
        let auth = |message: &str| AxiamError::Auth {
            message: message.to_owned(),
            oauth: None,
            reason: None,
            set_reason: None,
            retry_after: None,
        };

        if cnf.names_nothing_checkable() {
            return Err(auth(
                "token carries a cnf confirmation naming no method this SDK can verify \
                 (CONTRACT.md §10.1 rule 9 — an unverifiable constraint is not an absent one)",
            ));
        }

        // Each arm that applies must pass. Written as two independent checks
        // rather than a match on the pair precisely so that "both named" needs
        // no separate branch — it is simply the case where both run.
        if let Some(expected) = cnf.certificate_thumbprint() {
            let Some(presented) = proofs.certificate_thumbprint else {
                return Err(auth(
                    "token is certificate-bound but no client certificate was presented",
                ));
            };
            if !constant_time_eq(expected.as_bytes(), presented.as_bytes()) {
                return Err(auth(
                    "token is bound to a different client certificate than the one presented",
                ));
            }
        }

        if let Some(expected) = cnf.dpop_thumbprint() {
            let Some(presented) = proofs.dpop_thumbprint else {
                return Err(auth(
                    "token is DPoP-bound but no verified DPoP proof was presented",
                ));
            };
            if !constant_time_eq(expected.as_bytes(), presented.as_bytes()) {
                return Err(auth(
                    "token is bound to a different DPoP key than the one presented",
                ));
            }
        }

        Ok(())
    }
}

/// Constant-time byte comparison, hand-rolled so that
/// [`Claims::verify_certificate_binding`] stays available with **no features
/// enabled**.
///
/// `subtle` would be the natural choice, but it is an optional dependency of
/// this crate gated behind `rest`/`amqp`/`actix`, and rule 9 is pure claim
/// logic that a `--no-default-features` consumer must be able to apply to a
/// token it obtained some other way. Fifteen lines here beats making a
/// normative rule conditional on a feature flag.
///
/// The thumbprint is usually public — it derives from a certificate sent in
/// the clear during the handshake — so this is defence in depth. It matters
/// most for a self-signed client, where the registered thumbprint is the whole
/// credential.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    // Length inequality short-circuits, leaking only the length. Both operands
    // are fixed-length base64url SHA-256 digests whenever either is well-formed.
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Compute the RFC 8705 §3.1 `x5t#S256` thumbprint of a DER client
/// certificate: base64url-encoded SHA-256, **without** padding.
///
/// Unpadded is not a style choice — RFC 7515 §2 defines base64url in JOSE as
/// omitting `=`, and a padded value will not compare equal to what AXIAM put
/// in the token.
///
/// Feature-gated because it needs `sha2` and `base64`, which are optional here.
/// [`Claims::verify_certificate_binding`] deliberately is **not** gated: a
/// consumer that already has the thumbprint from its TLS stack (most do —
/// rustls, OpenSSL and Go's `crypto/tls` all expose the peer certificate) can
/// apply the rule without pulling either crate in.
#[cfg(any(feature = "rest", feature = "actix"))]
pub fn certificate_thumbprint_s256(der: &[u8]) -> String {
    use base64::Engine as _;
    use sha2::{Digest, Sha256};
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(der))
}

#[cfg(any(feature = "rest", feature = "actix"))]
struct CachedJwks {
    jwks: JwkSet,
    /// The anchor: when the last **successful** fetch (a `200` with at least
    /// one key, or a `304` to a conditional request) was made. A failed
    /// refresh never moves it.
    fetched_at: Instant,
    /// The lifetime of this set: the response's `Cache-Control: max-age`
    /// clamped to at most [`JWKS_CACHE_TTL`], or that default.
    ttl: Duration,
    /// The response's `ETag`, sent as `If-None-Match` on the next refresh.
    etag: Option<String>,
    last_forced_refetch: Option<Instant>,
}

/// The TTL a response gives the set it carries: its `Cache-Control: max-age`,
/// clamped to at most [`JWKS_CACHE_TTL`] (never honoured above it, silently),
/// else the default.
#[cfg(any(feature = "rest", feature = "actix"))]
fn advertised_ttl(headers: &reqwest::header::HeaderMap) -> Duration {
    headers
        .get_all(reqwest::header::CACHE_CONTROL)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .filter_map(|directive| {
            let (name, value) = directive.trim().split_once('=')?;
            name.trim()
                .eq_ignore_ascii_case("max-age")
                .then(|| value.trim().trim_matches('"').parse::<u64>().ok())
                .flatten()
        })
        .next()
        .map_or(JWKS_CACHE_TTL, |secs| {
            Duration::from_secs(secs).min(JWKS_CACHE_TTL)
        })
}

/// Fetches, caches, and verifies AXIAM access tokens locally against the
/// organization-wide EdDSA JWKS.
///
/// **Feature gating note:** this type owns a `reqwest::Client` to perform
/// the JWKS fetch, so it is gated behind `any(feature = "rest", feature =
/// "actix")` to preserve 16-01's `cargo build --no-default-features`
/// invariant while also being available to 16-05's Actix `FromRequest`
/// extractor (which declares `actix = ["dep:actix-web", "rest"]`, so `rest`
/// is always active whenever `actix` is — this `any(...)` gate is kept for
/// clarity/documentation of the two call sites rather than strict
/// necessity).
///
/// ## CONTRACT.md §10.1 — minimum local-verification set
///
/// [`Self::verify`] is the SDK's **documented guard entry point** and applies
/// every rule of §10.1: EdDSA `alg` pinned before key lookup, a REQUIRED
/// numeric `exp`, `nbf` honoured when present, `tenant_id` asserted against
/// the tenant configured with [`Self::expect_tenant_id`] (failing closed when
/// either is absent), and `iss`/`aud` checked when — and only when —
/// [`Self::expect_issuer`]/[`Self::expect_audience`] were configured. A
/// verifier used as a §10 route guard **must** be given an expected tenant;
/// without one, `verify` rejects every token rather than accepting a token
/// minted for a sibling tenant under the same organization-wide JWKS.
///
/// [`Self::verify_signature_only_unchecked`] is the §10.1 "raw signature-only
/// primitive" escape hatch. It is deliberately *not* the guard entry point.
#[cfg(any(feature = "rest", feature = "actix"))]
pub struct JwksVerifier {
    http_client: reqwest::Client,
    jwks_url: url::Url,
    cache: Arc<RwLock<Option<CachedJwks>>>,
    /// The single-flight slot: the receiver of the fetch task in flight, if
    /// any. The fetch runs as a detached task owned by the SDK, never inside a
    /// caller's future, so a caller that is cancelled (client disconnect) can
    /// neither abort it nor leave a half-recorded outcome behind. Only this
    /// slot's std mutex is taken, never across an `.await`.
    inflight: std::sync::Mutex<Option<tokio::sync::watch::Receiver<Option<FetchOutcome>>>>,
    /// The SDK's own bound on one fetch (see [`JWKS_FETCH_TIMEOUT`]).
    fetch_timeout: Duration,
    /// When the last fetch failed (`None` after a success).
    last_failed_fetch: Arc<std::sync::Mutex<Option<Instant>>>,
    /// §10.1 rule 4: the tenant every verified token MUST be scoped to.
    /// `None` means "not configured", which makes [`Self::verify`] fail
    /// closed — never "no tenant constraint".
    expected_tenant_id: Option<uuid::Uuid>,
    /// §10.1 rule 5: expected `iss`. `None` means the check is not performed
    /// (the rule is explicitly conditional on configuration).
    expected_issuer: Option<String>,
    /// §10.1 rule 6: expected `aud`. `None` means the check is not performed.
    expected_audience: Option<String>,
    /// §10.4 (contract 1.44): the optional revocation feed.
    ///
    /// `None` — the default — means the guard behaves exactly as it did before
    /// contract 1.44: a revoked session's access token verifies locally until
    /// it expires, which is the §10.2 posture this narrows rather than
    /// replaces.
    revocation_feed: Option<crate::token::revocation::RevocationFeed>,
    /// §28.5: the MCP resource-server metadata URL, when configured via
    /// [`Self::with_resource_metadata_url`]. `None` — the default — means
    /// §28 is off: [`crate::middleware::AxiamUser`] behaves byte-for-byte as
    /// it did before §28 existed (§28.5 rule 1).
    #[cfg(feature = "actix")]
    resource_metadata_url: Option<String>,
    /// The §28.4 challenge values precomputed by
    /// [`Self::with_resource_metadata_url`] — built once, at construction,
    /// so an invalid configuration is a startup failure rather than a
    /// surprise on the 401 path.
    #[cfg(feature = "actix")]
    mcp_challenges: Option<crate::middleware::mcp::McpChallenges>,
}

#[cfg(any(feature = "rest", feature = "actix"))]
impl JwksVerifier {
    /// Construct a verifier that will fetch `{base_url}/oauth2/jwks` lazily
    /// on first use.
    pub fn new(http_client: reqwest::Client, base_url: &url::Url) -> Result<Self, AxiamError> {
        let jwks_url = base_url.join(JWKS_PATH).map_err(|e| AxiamError::Network {
            message: format!("invalid JWKS URL: {e}"),
            source: None,
        })?;
        Ok(Self {
            http_client,
            jwks_url,
            cache: Arc::new(RwLock::new(None)),
            inflight: std::sync::Mutex::new(None),
            fetch_timeout: JWKS_FETCH_TIMEOUT,
            last_failed_fetch: Arc::new(std::sync::Mutex::new(None)),
            expected_tenant_id: None,
            expected_issuer: None,
            expected_audience: None,
            revocation_feed: None,
            #[cfg(feature = "actix")]
            resource_metadata_url: None,
            #[cfg(feature = "actix")]
            mcp_challenges: None,
        })
    }

    /// Configure the tenant every token accepted by [`Self::verify`] must be
    /// scoped to (CONTRACT.md §10.1 rule 4) — **required** for any verifier
    /// used as a §10 route guard.
    ///
    /// The `/oauth2/jwks` trust anchor is organization-wide, so a valid
    /// signature says only "some tenant in this organization", never "this
    /// tenant". Without this call [`Self::verify`] fails closed on every
    /// token.
    ///
    /// ```no_run
    /// # use axiam_sdk::token::JwksVerifier;
    /// # fn demo(http: reqwest::Client, base: url::Url, tenant: uuid::Uuid)
    /// #     -> Result<(), axiam_sdk::AxiamError> {
    /// let verifier = JwksVerifier::new(http, &base)?.expect_tenant_id(tenant);
    /// # let _ = verifier;
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn expect_tenant_id(mut self, tenant_id: uuid::Uuid) -> Self {
        self.expected_tenant_id = Some(tenant_id);
        self
    }

    /// Configure the expected `iss` claim (CONTRACT.md §10.1 rule 5).
    ///
    /// Optional and unset by default — the rule is conditional, and this SDK
    /// never hardcodes an issuer. When set, a token whose `iss` differs is
    /// rejected by [`Self::verify`].
    #[must_use]
    pub fn expect_issuer(mut self, issuer: impl Into<String>) -> Self {
        self.expected_issuer = Some(issuer.into());
        self
    }

    /// Configure the expected `aud` claim (CONTRACT.md §10.1 rule 6).
    ///
    /// Optional and unset by default. A resource server guarding user-facing
    /// routes SHOULD set `"axiam:user"`; a machine-to-machine one
    /// `"axiam:m2m"`. When set, a token whose `aud` does not match is
    /// rejected by [`Self::verify`].
    #[must_use]
    pub fn expect_audience(mut self, audience: impl Into<String>) -> Self {
        self.expected_audience = Some(audience.into());
        self
    }

    /// The expected `aud` claim configured via [`Self::expect_audience`], if
    /// any.
    pub fn expected_audience(&self) -> Option<&str> {
        self.expected_audience.as_deref()
    }

    /// Turn on the CONTRACT.md §28 MCP resource-server challenge: every
    /// `WWW-Authenticate`-bearing 401 [`crate::middleware::AxiamUser`] emits
    /// (and, via
    /// [`crate::middleware::RequireAccess::with_resource_metadata_url`], the
    /// one class of 403 §28.5 rule 5 names) carries the RFC 6750 challenge
    /// pointing at `url`. Off by default; with this unset, every guard built
    /// from this verifier behaves byte-for-byte as it did before §28
    /// existed (§28.5 rule 1) — no `WWW-Authenticate` header on any
    /// response, no status changed, no body changed.
    ///
    /// **Call [`Self::expect_audience`] first.** §28.5 rule 2: a resource
    /// server that publishes "tokens for me carry this `aud`" and then does
    /// not check `aud` has published a claim it does not honour, and a
    /// token minted for a *different* resource server opens it — so this
    /// call refuses rather than merely warns when no expected audience is
    /// already configured. §28.5 rule 6: this is the *only* audience option
    /// §28 reads; there is no second one to set.
    ///
    /// `url` is ordinarily
    /// [`ProtectedResourceMetadata::metadata_url`](crate::middleware::ProtectedResourceMetadata::metadata_url),
    /// fed from the same
    /// [`protected_resource_metadata`](crate::middleware::protected_resource_metadata)
    /// call that builds the document this verifier's audience must match —
    /// [`crate::middleware::serve_protected_resource_metadata`] cross-checks
    /// the two when given this verifier.
    ///
    /// # Errors
    ///
    /// [`AxiamError::Network`] (carrying a
    /// [`ValidationError`](crate::management::ValidationError) source,
    /// CONTRACT.md §2 — §28 adds no new error type) naming both
    /// `resource_metadata_url` and `expect_audience` when no expected
    /// audience is configured yet, or when `url` is not a syntactically
    /// valid `WWW-Authenticate` `resource_metadata` value (CONTRACT.md
    /// §28.2 rules 1–2, §28.4).
    #[cfg(feature = "actix")]
    pub fn with_resource_metadata_url(
        mut self,
        url: impl Into<String>,
    ) -> Result<Self, AxiamError> {
        let url = url.into();
        if self.expected_audience.is_none() {
            return Err(crate::middleware::mcp::refuse(
                "with_resource_metadata_url",
                "resource_metadata_url",
                "requires expect_audience(...) to be called first (CONTRACT.md §28.5 rule 2) — announcing a resource identifier obliges this server to check that an inbound token's `aud` is that identifier, and a resource server that announces itself without checking is opened by a token minted for somebody else",
            ));
        }
        let challenges = crate::middleware::mcp::McpChallenges::build(&url)?;
        self.resource_metadata_url = Some(url);
        self.mcp_challenges = Some(challenges);
        Ok(self)
    }

    /// The URL configured via [`Self::with_resource_metadata_url`], if any.
    #[cfg(feature = "actix")]
    pub fn resource_metadata_url(&self) -> Option<&str> {
        self.resource_metadata_url.as_deref()
    }

    /// The precomputed §28.4 challenge values, when §28 is configured.
    #[cfg(feature = "actix")]
    pub(crate) fn mcp_challenges(&self) -> Option<&crate::middleware::mcp::McpChallenges> {
        self.mcp_challenges.as_ref()
    }

    /// Construct a verifier against an **already-absolute** JWKS URL
    /// (CONTRACT.md §12.3 rule 6: "SDKs MUST read `jwks_uri` from the
    /// document rather than hardcoding `/oauth2/jwks`"). Used by
    /// `crate::oidc` to verify ID tokens against the `jwks_uri` the OIDC
    /// discovery document advertises, which is not necessarily
    /// `{base_url}/oauth2/jwks` (e.g. behind a proxy).
    ///
    /// The caller owns the X-2 scheme check. `jwks_url` here is remote input,
    /// unlike [`Self::new`]'s `base_url`, which
    /// `AxiamClientBuilder::base_url` already validated. The sole caller,
    /// `AxiamClient::oidc_verifier_for`, runs
    /// [`crate::url_guard::ensure_secure_scheme`] before constructing — keep
    /// it that way if a second caller ever appears, or the SDK will fetch its
    /// signing keys over cleartext.
    pub(crate) fn for_jwks_url(http_client: reqwest::Client, jwks_url: url::Url) -> Self {
        Self {
            http_client,
            jwks_url,
            cache: Arc::new(RwLock::new(None)),
            inflight: std::sync::Mutex::new(None),
            fetch_timeout: JWKS_FETCH_TIMEOUT,
            last_failed_fetch: Arc::new(std::sync::Mutex::new(None)),
            expected_tenant_id: None,
            expected_issuer: None,
            expected_audience: None,
            revocation_feed: None,
            #[cfg(feature = "actix")]
            resource_metadata_url: None,
            #[cfg(feature = "actix")]
            mcp_challenges: None,
        }
    }

    /// The refusal a lookup gets inside the minute after a failed fetch.
    fn failed_fetch_cooldown(&self) -> Result<(), AxiamError> {
        self.failed_fetch_cooldown_for(FAILED_FETCH_MIN_INTERVAL)
    }

    fn failed_fetch_cooldown_for(&self, window: Duration) -> Result<(), AxiamError> {
        let last = *self
            .last_failed_fetch
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        match last {
            Some(at) if at.elapsed() < window => Err(AxiamError::network(
                "the previous JWKS fetch failed moments ago; no fetch was made",
            )),
            _ => Ok(()),
        }
    }

    /// Verify an arbitrary JWT's EdDSA signature against the cached JWKS,
    /// returning the decoded claims — CONTRACT.md §12.4 rules 1–2 (`alg`
    /// allowlist, `kid` lookup with a single forced re-fetch on miss,
    /// Ed25519 signature verification).
    ///
    /// Reuses the SAME fetch/cache/single-flight/forced-refetch machinery as
    /// [`Self::verify`] (`get_or_fetch`/`force_refetch_if_allowed`) — §12
    /// forbids forking the JWKS verifier — but performs NO issuer/audience/
    /// time/nonce checks (rules 3–6) and tags every failure with the
    /// CONTRACT.md §12.3 rule 3 reason code, via
    /// [`AxiamError::id_token_invalid`], rather than [`Self::verify`]'s plain
    /// message.
    ///
    /// **Divergence from the lenient session path, required by §12.4 rule 2:**
    /// a missing `kid` is rejected outright, with no single-key fallback —
    /// "a token with no `kid` … MUST be rejected". [`Self::verify`] has no
    /// fallback either since contract 1.68 (§10.1 rule 12); [`find_jwk`]'s
    /// survives only on the lenient session / signature-only paths.
    ///
    /// Serves the ID token (§12.4) and the back-channel logout token
    /// (§12.7.3, contract 1.69: its `kid` is required). §10.1 rules 10 (`typ`)
    /// and 11 (`purpose`) are applied by [`Self::verify`] only and never run
    /// here.
    pub(crate) async fn verify_id_token_signature<T>(&self, token: &str) -> Result<T, AxiamError>
    where
        T: serde::de::DeserializeOwned,
    {
        use crate::error::IdTokenFailureReason;

        let header = decode_header(token).map_err(|e| {
            AxiamError::id_token_invalid(
                IdTokenFailureReason::InvalidAlg,
                format!("malformed token: {e}"),
            )
        })?;

        if header.alg != Algorithm::EdDSA {
            return Err(AxiamError::id_token_invalid(
                IdTokenFailureReason::InvalidAlg,
                format!(
                    "expected alg \"{}\", got {:?}",
                    crate::oidc::id_token::ID_TOKEN_ALG,
                    header.alg
                ),
            ));
        }

        let kid = header.kid.as_deref().ok_or_else(|| {
            AxiamError::id_token_invalid(
                IdTokenFailureReason::UnknownKid,
                "token has no kid header",
            )
        })?;

        let jwks = self.get_or_fetch().await?;
        let jwk = match find_jwk_by_kid(&jwks, kid) {
            Some(jwk) => jwk,
            None => {
                let refreshed = self.force_refetch_if_allowed().await?;
                find_jwk_by_kid(&refreshed, kid).ok_or_else(|| {
                    AxiamError::id_token_invalid(
                        IdTokenFailureReason::UnknownKid,
                        "unknown kid after JWKS refetch",
                    )
                })?
            }
        };

        let decoding_key = DecodingKey::from_jwk(&jwk).map_err(|_| {
            AxiamError::id_token_invalid(
                IdTokenFailureReason::InvalidSignature,
                "unable to build decoding key from JWK",
            )
        })?;

        let mut validation = Validation::new(Algorithm::EdDSA);
        // Rules 3-6 (issuer/audience/time/nonce) are applied by the caller
        // (`crate::oidc::id_token`) over the returned claims, with its own
        // configurable clock skew — disable jsonwebtoken's own exp/nbf/aud
        // checks and required-claims gate so they cannot fight the SDK's own
        // checklist or double-report a single failure under two different
        // reason codes.
        validation.required_spec_claims.clear();
        validation.validate_exp = false;
        validation.validate_nbf = false;
        validation.validate_aud = false;
        validation.leeway = 0;

        let data = decode::<T>(token, &decoding_key, &validation).map_err(|e| {
            use jsonwebtoken::errors::ErrorKind;
            match e.kind() {
                ErrorKind::InvalidSignature => AxiamError::id_token_invalid(
                    IdTokenFailureReason::InvalidSignature,
                    "signature invalid",
                ),
                _ => AxiamError::id_token_invalid(
                    IdTokenFailureReason::InvalidSignature,
                    format!("claim decode failed: {e}"),
                ),
            }
        })?;

        Ok(data.claims)
    }

    /// The key `kid` names, fetching the JWKS if needed and, on a miss, forcing
    /// **one** refetch — rate-limited to once per minute
    /// (`FORCED_REFETCH_MIN_INTERVAL`) — before giving up with `Ok(None)`.
    ///
    /// The shared machinery behind the §32.7 SET verifier, which maps its
    /// own reason codes and so needs the lookup without
    /// [`Self::verify_id_token_signature`]'s §12.3 ones.
    pub(crate) async fn key_for_kid(
        &self,
        kid: &str,
    ) -> Result<Option<jsonwebtoken::jwk::Jwk>, AxiamError> {
        let jwks = self.get_or_fetch().await?;
        if let Some(jwk) = find_jwk_by_kid(&jwks, kid) {
            return Ok(Some(jwk));
        }
        let refreshed = self.force_refetch_if_allowed().await?;
        Ok(find_jwk_by_kid(&refreshed, kid))
    }

    /// Verify an inbound AXIAM access token against the **complete**
    /// CONTRACT.md §10.1 minimum local-verification set. This is the SDK's
    /// documented guard entry point — the §10 [`AxiamUser`] extractor and the
    /// §11 `require_*` macros (which inject that extractor) both land here.
    ///
    /// | § | rule | how it is enforced |
    /// |---|---|---|
    /// | 1 | signature | `alg` read from the header and pinned to `EdDSA` **before** the JWKS is consulted, so `alg: none` and an HS-signed token bearing an EdDSA `kid` are rejected without a key lookup; the Ed25519 signature is then checked against the org JWKS. |
    /// | 2 | `exp` | REQUIRED: `exp` is in `required_spec_claims` *and* a non-`Option` field of [`Claims`], so an absent or non-numeric `exp` is rejected. |
    /// | 3 | `nbf` | `validate_nbf` enabled — a future `nbf` is rejected, an absent one is fine. |
    /// | 4 | `tenant_id` | asserted against [`Self::expect_tenant_id`]; **fails closed** when the claim is absent/not a UUID, and when no expected tenant was configured at all. |
    /// | 5 | `iss` | checked only when [`Self::expect_issuer`] was called. |
    /// | 6 | `aud` | checked only when [`Self::expect_audience`] was called. |
    /// | 7 | clock skew | [`CLOCK_SKEW_LEEWAY_SECS`] — a named, bounded, non-configurable 60 s. |
    /// | 9 | `cnf` | this entry point has **no** transport evidence, so a token carrying `cnf` is **refused**, whatever it names; an unbound token is unaffected. |
    /// | 10 | `typ` | a present `typ` must be `at+jwt` (case and an `application/` prefix ignored); absent is fine. Checked before any key lookup. |
    /// | 11 | `purpose` | any `purpose` claim, whatever its value, refuses the token (MFA challenge, WebAuthn state). |
    /// | 12 | `kid` | REQUIRED; the key is selected by `kid` only, with no single-key fallback, before and after the forced refetch. |
    ///
    /// # Rule 9, and which entry point to call
    ///
    /// A token with `cnf` is not a bearer token (§10.1 rule 9): it may be used
    /// only by a presenter that proves possession of the key it names. This
    /// method is handed a token and nothing else, so it cannot see that proof,
    /// and it fails closed — the "a different certificate, or none" row of the
    /// rule's table. Until contract 1.51 it accepted such a token as a bearer
    /// token, which is exactly the downgrade rule 9 exists to forbid, and the
    /// §6.1 device login now mints bound tokens by default.
    ///
    /// To **accept** bound tokens, give the verifier the evidence your
    /// transport holds: [`Self::verify_sender_constrained`] for a TLS client
    /// certificate, [`Self::verify_with_proofs`] when a verified DPoP proof may
    /// be present too. The [`AxiamUser`] extractor does this itself when the
    /// server records the peer certificate (see
    /// [`PeerCertificate`](crate::middleware::PeerCertificate)).
    ///
    /// # Errors
    ///
    /// [`AxiamError::Auth`] on any failed rule (the SDK never distinguishes
    /// "no `tenant_id` to check" from "wrong `tenant_id`" — both reject), or
    /// [`AxiamError::Network`] if the JWKS itself is unreachable.
    ///
    /// [`AxiamUser`]: crate::middleware::AxiamUser
    pub async fn verify(&self, token: &str) -> Result<Claims, AxiamError> {
        self.verify_with_proofs(token, PresentedProofs::default())
            .await
    }

    /// The complete §10.1 set — rules 1–8, then rule 9 against `proofs` — for
    /// a resource server that may receive **certificate-bound or DPoP-bound**
    /// tokens.
    ///
    /// `proofs` must come from the transport: the thumbprint of the peer
    /// certificate the TLS layer verified for this connection, and the `jkt`
    /// returned by [`crate::token::verify_dpop_proof`] for a proof checked
    /// against this request — never a value a caller supplied in a header.
    /// [`PresentedProofs::default()`] (no evidence) is exactly [`Self::verify`].
    /// An unbound token is accepted with or without proofs.
    ///
    /// # Errors
    ///
    /// Everything [`Self::verify`] returns; rule 9 refusals are listed on
    /// [`Claims::verify_token_binding`].
    pub async fn verify_with_proofs(
        &self,
        token: &str,
        proofs: PresentedProofs<'_>,
    ) -> Result<Claims, AxiamError> {
        let claims = self.verify_rules_one_to_eight(token).await?;
        claims.verify_token_binding(proofs)?;
        Ok(claims)
    }

    /// Rules 1–8 and the §10.4 feed — everything but the sender constraint,
    /// which every public entry point then applies with the evidence it has.
    /// Private on purpose: no caller may stop here.
    async fn verify_rules_one_to_eight(&self, token: &str) -> Result<Claims, AxiamError> {
        let claims = self.verify_claims(token, AccessTokenRules::Strict).await?;
        self.assert_tenant(&claims)?;
        self.assert_not_revoked(&claims).await?;
        Ok(claims)
    }

    /// Attach a §10.4 revocation feed (contract 1.44).
    ///
    /// Off by default and opt-in per caller. With one attached, a token whose
    /// `sid` the feed lists is rejected within one poll interval instead of
    /// within one access-token lifetime.
    ///
    /// It never makes this verifier stricter in any other way. Every §10.1
    /// rule runs first and still decides; the feed can only turn an accept
    /// into a reject, and a feed that cannot be read turns nothing at all —
    /// see [`crate::token::revocation`] for why that is a rule and not a
    /// convenience.
    #[must_use]
    pub fn with_revocation_feed(mut self, feed: crate::token::revocation::RevocationFeed) -> Self {
        self.revocation_feed = Some(feed);
        self
    }

    /// §10.4 rules 4 and 6.
    ///
    /// A token with no `sid` is never matched against the feed: there is no
    /// session behind it. Everything else is a lookup in a cached set — no
    /// network work on this path, ever.
    async fn assert_not_revoked(&self, claims: &Claims) -> Result<(), AxiamError> {
        let Some(feed) = &self.revocation_feed else {
            return Ok(());
        };
        let Some(sid) = claims.sid.as_deref() else {
            return Ok(());
        };
        if feed.is_revoked(sid).await {
            return Err(AxiamError::Auth {
                message: "the session behind this access token has been revoked \
                          (CONTRACT.md §10.4)"
                    .into(),
                oauth: None,
                reason: None,
                set_reason: None,
                retry_after: None,
            });
        }
        Ok(())
    }

    /// [`Self::verify`] plus CONTRACT.md §10.1 **rule 9** — the sender
    /// constraint (RFC 8705 §3, contract 1.15).
    ///
    /// This is the guard entry point for a resource server that accepts
    /// **certificate-bound** access tokens. Pass the `x5t#S256` thumbprint of
    /// the client certificate on the current connection, or `None` if there is
    /// none; [`certificate_thumbprint_s256`] computes it from DER bytes.
    ///
    /// It is a separate method rather than a parameter on [`Self::verify`]
    /// because the two have different *inputs*: `verify` needs only a token,
    /// and a great many integrations have no transport-level certificate to
    /// offer. Folding the thumbprint into `verify` would have forced every
    /// caller to thread an `Option<&str>` they do not have, and the usual
    /// result of that is `None` everywhere — which reads as "no certificate"
    /// and rejects every bound token.
    ///
    /// **An unbound token is still accepted** here, with or without a
    /// certificate. Rule 9 constrains tokens that claim a constraint; it does
    /// not make certificates mandatory.
    ///
    /// # Errors
    ///
    /// Everything [`Self::verify`] returns, plus [`AxiamError::Auth`] when the
    /// token's `cnf` does not match what was presented — see
    /// [`Claims::verify_certificate_binding`] for the exact table.
    pub async fn verify_sender_constrained(
        &self,
        token: &str,
        presented_thumbprint: Option<&str>,
    ) -> Result<Claims, AxiamError> {
        let claims = self.verify_rules_one_to_eight(token).await?;
        claims.verify_certificate_binding(presented_thumbprint)?;
        Ok(claims)
    }

    /// Verify **only** the EdDSA signature of `token` against the org JWKS —
    /// CONTRACT.md §10.1's "raw signature-only primitive".
    ///
    /// # This is not a guard
    ///
    /// It performs **no** `exp`, `nbf`, `tenant_id`, `iss` or `aud` check
    /// whatsoever. An expired token, a not-yet-valid token, and a token
    /// minted for a *different tenant* in the same organization all pass. It
    /// exists purely for integrators deliberately implementing their own
    /// policy on top of the signature; the `_unchecked` suffix is there to
    /// make that omission obvious at the call site. Anything guarding a route
    /// MUST call [`Self::verify`] instead.
    ///
    /// (`exp` must still be *present and numeric* simply because [`Claims`]
    /// declares it as a non-`Option` `i64`; nothing checks whether it has
    /// passed.)
    ///
    /// # Errors
    ///
    /// [`AxiamError::Auth`] if the `alg` is not EdDSA, the `kid` is unknown,
    /// the signature does not verify, or the payload is not shaped like
    /// [`Claims`]; [`AxiamError::Network`] if the JWKS is unreachable.
    pub async fn verify_signature_only_unchecked(&self, token: &str) -> Result<Claims, AxiamError> {
        let decoding_key = self
            .decoding_key_for(token, AccessTokenRules::Lenient)
            .await?;

        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.required_spec_claims.clear();
        validation.validate_exp = false;
        validation.validate_nbf = false;
        validation.validate_aud = false;
        validation.leeway = 0;

        decode_claims(token, &decoding_key, &validation, false)
    }

    /// The client's own freshly-issued session token, decoded to learn the
    /// identity the server just handed us (`login`/`verify_mfa`/`refresh`/
    /// `logout`).
    ///
    /// **Not a §10 guard, and deliberately not `verify`.** §10.1 governs
    /// relying-party verification of a token that arrived from an untrusted
    /// caller; this path decodes a token this very client just received in
    /// the TLS response of its own authenticated request to the configured
    /// `base_url`. Rule 4 cannot apply here in either direction: the
    /// `tenant_id` claim is what the client is *learning* (a client built
    /// with a `tenant_slug` has no tenant UUID to compare against yet), so
    /// asserting it would be circular. Every other rule — alg pinning,
    /// required numeric `exp`, `nbf`, the configured-only `iss`/`aud`, and
    /// the shared [`CLOCK_SKEW_LEEWAY_SECS`] — is applied exactly as in
    /// [`Self::verify`].
    pub(crate) async fn verify_session_token(&self, token: &str) -> Result<Claims, AxiamError> {
        self.verify_claims(token, AccessTokenRules::Lenient).await
    }

    /// Everything in §10.1 except rule 4 (the tenant assertion), shared by
    /// [`Self::verify`] and [`Self::verify_session_token`].
    async fn verify_claims(
        &self,
        token: &str,
        rules: AccessTokenRules,
    ) -> Result<Claims, AxiamError> {
        let decoding_key = self.decoding_key_for(token, rules).await?;

        let mut validation = Validation::new(Algorithm::EdDSA);
        // Rule 7: one named, bounded, non-operator-settable leeway for both
        // the `exp` and the `nbf` comparison.
        validation.leeway = CLOCK_SKEW_LEEWAY_SECS;
        // Rule 2: `exp` is REQUIRED, not "checked if present". Two
        // independent gates enforce it, and either is sufficient:
        // `Claims::exp` is a non-`Option` `i64`, so serde rejects an absent
        // or non-numeric `exp` while deserializing (jsonwebtoken decodes `T`
        // before it validates, so in practice this is the one that trips);
        // and `required_spec_claims` covers the same ground at the
        // validation layer. jsonwebtoken already defaults the latter to
        // `{"exp"}` — setting it explicitly keeps the guarantee from
        // silently changing under a dependency bump.
        validation.set_required_spec_claims(&["exp"]);
        validation.validate_exp = true;
        // Rule 3: honour `nbf` when present (jsonwebtoken defaults this to
        // `false`, i.e. a future-dated token would otherwise be accepted).
        // An absent `nbf` stays valid — it is not in `required_spec_claims`.
        validation.validate_nbf = true;

        // Rules 5 and 6 are CONDITIONAL: only checked when this verifier was
        // configured with an expected value. Note that leaving
        // `validate_aud` at jsonwebtoken's `true` default while
        // `validation.aud` is `None` rejects every token that merely *has* an
        // `aud` — i.e. every real AXIAM access token — so it is switched off
        // unless an expectation was actually configured.
        //
        // Configuring an expectation also makes the corresponding claim
        // REQUIRED: jsonwebtoken only compares a claim it can see, so an
        // absent `aud` against a configured expectation would otherwise slip
        // through ("the claim was missing so there was nothing to check" —
        // the SEC-080 shape). A token whose `aud` does not contain the
        // expected value is rejected, and an absent `aud` does not contain
        // it.
        match self.expected_issuer.as_deref() {
            Some(iss) => {
                validation.set_issuer(&[iss]);
                validation.required_spec_claims.insert("iss".to_string());
            }
            None => validation.iss = None,
        }
        match self.expected_audience.as_deref() {
            Some(aud) => {
                validation.validate_aud = true;
                validation.set_audience(&[aud]);
                validation.required_spec_claims.insert("aud".to_string());
            }
            None => {
                validation.validate_aud = false;
                validation.aud = None;
            }
        }

        decode_claims(
            token,
            &decoding_key,
            &validation,
            rules == AccessTokenRules::Strict,
        )
    }

    /// §10.1 rule 1's first half: pin `alg` to EdDSA from the header
    /// **before** any JWKS lookup, then resolve the `kid` to a decoding key.
    async fn decoding_key_for(
        &self,
        token: &str,
        rules: AccessTokenRules,
    ) -> Result<DecodingKey, AxiamError> {
        let header = decode_header(token).map_err(|e| AxiamError::Auth {
            message: format!("invalid token header: {e}"),
            oauth: None,
            reason: None,
            set_reason: None,
            retry_after: None,
        })?;

        // Rule 1: rejected WITHOUT consulting a key — `alg: none` and every
        // HS-family confusion attempt dies here, before `get_or_fetch`.
        if header.alg != Algorithm::EdDSA {
            return Err(AxiamError::Auth {
                message: "unexpected alg: only EdDSA is accepted".into(),
                oauth: None,
                reason: None,
                set_reason: None,
                retry_after: None,
            });
        }

        let strict = rules == AccessTokenRules::Strict;
        if strict {
            // Rule 10 (contract 1.68): a header that names a `typ` must name
            // `at+jwt`. Checked before any key lookup, like `alg`.
            if let Some(typ) = header.typ.as_deref()
                && !is_access_token_typ(typ)
            {
                return Err(auth_err(
                    "token typ is not at+jwt; refusing a non-access token (CONTRACT.md §10.1 rule 10)",
                ));
            }
            // Rule 12: `kid` is REQUIRED on the access-token path. No
            // single-key fallback, no trying every key.
            if header.kid.is_none() {
                return Err(auth_err(
                    "token header has no kid; refusing (CONTRACT.md §10.1 rule 12)",
                ));
            }
        }
        let select = |set: &JwkSet| {
            if strict {
                header.kid.as_deref().and_then(|k| find_jwk_by_kid(set, k))
            } else {
                find_jwk(set, header.kid.as_deref())
            }
        };

        let jwks = self.get_or_fetch().await?;
        let jwk = select(&jwks);

        let jwk = match jwk {
            Some(j) => j,
            None => {
                // Unknown kid → forced refetch (rate-limited), matching the
                // server's own kid-rotation handling (D-11).
                let refreshed = self.force_refetch_if_allowed().await?;
                select(&refreshed).ok_or_else(|| AxiamError::Auth {
                    message: "unknown kid after JWKS refetch".into(),
                    oauth: None,
                    reason: None,
                    set_reason: None,
                    retry_after: None,
                })?
            }
        };

        DecodingKey::from_jwk(&jwk).map_err(|_| AxiamError::Auth {
            message: "unable to build decoding key from JWK".into(),
            oauth: None,
            reason: None,
            set_reason: None,
            retry_after: None,
        })
    }

    /// §10.1 rule 4 — the `tenant_id` claim MUST equal the configured tenant.
    ///
    /// Fails closed on all three ways this can go wrong: no configured
    /// tenant, an unparseable/absent claim, and a mismatch. "There was no
    /// tenant to compare against, so there was nothing to check" is the
    /// `SEC-080` defect, not a pass.
    fn assert_tenant(&self, claims: &Claims) -> Result<(), AxiamError> {
        let expected = self.expected_tenant_id.ok_or_else(|| AxiamError::Auth {
            message: "JWKS verifier has no expected tenant configured; refusing to accept a \
                      token (CONTRACT.md §10.1 rule 4 — call \
                      JwksVerifier::expect_tenant_id before using it as a route guard)"
                .into(),
            oauth: None,
            reason: None,
            set_reason: None,
            retry_after: None,
        })?;

        let actual =
            uuid::Uuid::parse_str(claims.tenant_id.trim()).map_err(|_| AxiamError::Auth {
                message: "token tenant_id claim is absent or not a UUID".into(),
                oauth: None,
                reason: None,
                set_reason: None,
                retry_after: None,
            })?;

        if actual != expected {
            return Err(AxiamError::Auth {
                message: "token tenant_id does not match the configured tenant".into(),
                oauth: None,
                reason: None,
                set_reason: None,
                retry_after: None,
            });
        }

        Ok(())
    }

    async fn get_or_fetch(&self) -> Result<JwkSet, AxiamError> {
        if let Some(jwks) = self.cached_if_fresh() {
            return Ok(jwks);
        }
        // Stale-if-error (§12.4 rule 2, contract 1.69): past its TTL the held
        // set keeps verifying until exactly TTL + 300 s after the last
        // successful fetch. A TTL-driven refresh, successful or not, respects
        // the 60 s window (an advertised `max-age=0` never means one fetch per
        // verification).
        let held = self.held_within_stale_bound();
        let age = self
            .cache
            .read()
            .ok()
            .and_then(|c| c.as_ref().map(|e| e.fetched_at.elapsed()));
        let cooldown = self.failed_fetch_cooldown();
        if let Some(held) = held {
            if age.is_some_and(|a| a >= FAILED_FETCH_MIN_INTERVAL) && cooldown.is_ok() {
                // A usable held set is returned at once; the refresh runs as
                // the detached single-flight task and nobody waits for it.
                let _ = self.start_fetch(false);
            }
            return Ok(held);
        }
        cooldown?;
        // Nothing usable is held: wait for the shared fetch. Only this wait
        // is cancellable; the fetch itself is not.
        await_outcome(self.start_fetch(false)).await
    }

    fn cached_if_fresh(&self) -> Option<JwkSet> {
        let cache = self.cache.read().ok()?;
        let entry = cache.as_ref()?;
        if entry.fetched_at.elapsed() < entry.ttl {
            Some(entry.jwks.clone())
        } else {
            None
        }
    }

    /// The held key set while it is no older than `TTL + 300 s`, measured from
    /// the last successful fetch; `None` past that, or with nothing held.
    fn held_within_stale_bound(&self) -> Option<JwkSet> {
        let cache = self.cache.read().ok()?;
        let entry = cache.as_ref()?;
        let bound = entry.ttl.saturating_add(JWKS_MAX_STALE);
        (entry.fetched_at.elapsed() < bound).then(|| entry.jwks.clone())
    }

    /// Force a refetch, but rate-limited to at most once per
    /// `FORCED_REFETCH_MIN_INTERVAL` to avoid a rotating/hostile `kid`
    /// stream hammering the JWKS endpoint.
    async fn force_refetch_if_allowed(&self) -> Result<JwkSet, AxiamError> {
        self.failed_fetch_cooldown()?;

        // Check and open the window in one synchronous critical section: the
        // window opens when the fetch STARTS, so a caller cancelled mid-fetch
        // cannot bypass it, and a burst collapses to one fetch.
        let allowed = match self.cache.write() {
            Ok(mut cache) => match cache.as_mut() {
                Some(entry) => {
                    let due = entry
                        .last_forced_refetch
                        .is_none_or(|last| last.elapsed() >= FORCED_REFETCH_MIN_INTERVAL);
                    if due {
                        entry.last_forced_refetch = Some(Instant::now());
                    }
                    due
                }
                None => true,
            },
            Err(_) => true,
        };

        if allowed {
            await_outcome(self.start_fetch(true)).await
        } else if let Some(jwks) = self.held_within_stale_bound() {
            Ok(jwks)
        } else {
            await_outcome(self.start_fetch(true)).await
        }
    }

    /// Join the fetch in flight, or start one as a detached task: single-flight
    /// per verifier, bounded by `fetch_timeout`, its REAL outcome recorded by
    /// the task itself (failure anchor, forced window), never by a caller.
    fn start_fetch(&self, is_forced: bool) -> tokio::sync::watch::Receiver<Option<FetchOutcome>> {
        let mut slot = self.inflight.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(rx) = slot.as_ref()
            && rx.borrow().is_none()
            && rx.has_changed().is_ok()
        {
            return rx.clone();
        }
        let (tx, rx) = tokio::sync::watch::channel(None);
        let client = self.http_client.clone();
        let url = self.jwks_url.clone();
        let cache = Arc::clone(&self.cache);
        let failed = Arc::clone(&self.last_failed_fetch);
        let timeout = self.fetch_timeout;
        tokio::spawn(async move {
            let outcome =
                match tokio::time::timeout(timeout, fetch_once(&client, &url, &cache, is_forced))
                    .await
                {
                    Ok(outcome) => outcome,
                    Err(_) => Err(AxiamError::network("JWKS fetch timed out")),
                };
            *failed.lock().unwrap_or_else(|p| p.into_inner()) = outcome.is_err().then(Instant::now);
            if outcome.is_err()
                && is_forced
                && let Ok(mut cache) = cache.write()
                && let Some(entry) = cache.as_mut()
            {
                entry.last_forced_refetch = Some(Instant::now());
            }
            let _ = tx.send(Some(outcome.map_err(|e| e.to_string())));
        });
        *slot = Some(rx.clone());
        rx
    }
}

/// Wait for the shared fetch result. Dropping this future (the caller went
/// away) abandons only the wait.
#[cfg(any(feature = "rest", feature = "actix"))]
async fn await_outcome(
    mut rx: tokio::sync::watch::Receiver<Option<FetchOutcome>>,
) -> Result<JwkSet, AxiamError> {
    loop {
        if let Some(outcome) = rx.borrow().clone() {
            return outcome.map_err(AxiamError::network);
        }
        if rx.changed().await.is_err() {
            return Err(AxiamError::network("JWKS fetch task ended unexpectedly"));
        }
    }
}

/// One JWKS fetch: conditional when a set and its ETag are held; a `200` with
/// at least one key, or a `304` to a conditional request, is a success.
#[cfg(any(feature = "rest", feature = "actix"))]
async fn fetch_once(
    http_client: &reqwest::Client,
    jwks_url: &url::Url,
    cache: &RwLock<Option<CachedJwks>>,
    is_forced: bool,
) -> Result<JwkSet, AxiamError> {
    // A conditional request when a set (and its ETag) is held: a `304`
    // re-confirms it (§12.4 rule 2, "What counts as a successful fetch").
    let held_etag = cache
        .read()
        .ok()
        .and_then(|c| c.as_ref().and_then(|e| e.etag.clone()));
    let mut request = http_client.get(jwks_url.clone());
    if let Some(etag) = &held_etag {
        request = request.header(reqwest::header::IF_NONE_MATCH, etag);
    }
    let response = request
        .omit_browser_credentials()
        .send()
        .await
        .map_err(|e| AxiamError::Network {
            message: format!("JWKS fetch failed: {e}"),
            source: Some(Box::new(e)),
        })?;

    let status = response.status();
    let now = Instant::now();
    if status == reqwest::StatusCode::NOT_MODIFIED && held_etag.is_some() {
        let ttl = advertised_ttl(response.headers());
        if let Ok(mut cache) = cache.write()
            && let Some(entry) = cache.as_mut()
        {
            entry.fetched_at = now;
            entry.ttl = ttl;
            if is_forced {
                entry.last_forced_refetch = Some(now);
            }
            return Ok(entry.jwks.clone());
        }
        return Err(AxiamError::network(
            "JWKS cache unavailable after a 304 response",
        ));
    }
    if status != reqwest::StatusCode::OK {
        return Err(AxiamError::from_http_status(
            status.as_u16(),
            "JWKS endpoint returned a non-success status".to_string(),
        ));
    }

    let ttl = advertised_ttl(response.headers());
    let etag = response
        .headers()
        .get(reqwest::header::ETAG)
        .and_then(|v| v.to_str().ok())
        // Never stored or echoed: over 256 bytes or with a control character.
        .filter(|v| v.len() <= 256 && !v.bytes().any(|b| b.is_ascii_control()))
        .map(str::to_owned);
    let document: serde_json::Value = response.json().await.map_err(|e| AxiamError::Network {
        message: format!("JWKS response parse failed: {e}"),
        source: Some(Box::new(e)),
    })?;
    // A JWKS document holds at least one JWK object with a string `kty`;
    // `{"keys":[]}`, `{"keys":[{}]}`, `[0]` and `[null]` are not one.
    let has_jwk = document
        .get("keys")
        .and_then(|k| k.as_array())
        .is_some_and(|keys| {
            keys.iter()
                .any(|k| k.get("kty").is_some_and(serde_json::Value::is_string))
        });
    if !has_jwk {
        return Err(AxiamError::network(
            "JWKS document holds no keys; the held set is kept",
        ));
    }
    // Entries are parsed one by one: a well-formed JWK this SDK cannot use
    // (e.g. RSA without `alg`) still counts as a key held by the document
    // and is skipped, instead of refusing the whole set.
    let jwks = JwkSet {
        keys: document["keys"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|k| serde_json::from_value(k.clone()).ok())
            .collect(),
    };
    if let Ok(mut cache) = cache.write() {
        *cache = Some(CachedJwks {
            jwks: jwks.clone(),
            fetched_at: now,
            ttl,
            etag,
            last_forced_refetch: if is_forced { Some(now) } else { None },
        });
    }

    Ok(jwks)
}

/// Decode `token` into [`Claims`] under `validation`, translating
/// `jsonwebtoken`'s error kinds into the SDK's [`AxiamError::Auth`] messages.
///
/// Every failure mode — bad signature, expired, not-yet-valid, missing or
/// mistyped `exp`, wrong issuer/audience, a payload that is not shaped like
/// [`Claims`] — funnels through here and is a rejection. There is no branch
/// that turns a claim it could not evaluate into success.
#[cfg(any(feature = "rest", feature = "actix"))]
fn decode_claims(
    token: &str,
    decoding_key: &DecodingKey,
    validation: &Validation,
    reject_purpose: bool,
) -> Result<Claims, AxiamError> {
    let data = decode::<Claims>(token, decoding_key, validation).map_err(|e| {
        use jsonwebtoken::errors::ErrorKind;
        let message = match e.kind() {
            ErrorKind::InvalidSignature => "token signature invalid".to_string(),
            ErrorKind::ExpiredSignature => "token expired".to_string(),
            ErrorKind::ImmatureSignature => "token is not valid yet (nbf is in the future)".into(),
            ErrorKind::MissingRequiredClaim(claim) => {
                format!("token is missing the required {claim} claim")
            }
            ErrorKind::InvalidClaimFormat(claim) => {
                format!("token {claim} claim is not a number")
            }
            ErrorKind::InvalidIssuer => "token issuer does not match the expected issuer".into(),
            ErrorKind::InvalidAudience => {
                "token audience does not match the expected audience".into()
            }
            _ => format!("token claim validation failed: {e}"),
        };
        AxiamError::Auth {
            message,
            oauth: None,
            reason: None,
            set_reason: None,
            retry_after: None,
        }
    })?;

    if reject_purpose {
        // Rule 11 (contract 1.68): a `purpose` member refuses the token
        // whatever its value, `null` included. Read from the verified payload
        // itself (same token, same key, same validation), not from `Claims`,
        // which ignores unknown members.
        let raw = decode::<serde_json::Value>(token, decoding_key, validation)
            .map_err(|_| auth_err("token payload could not be re-read"))?;
        if raw
            .claims
            .as_object()
            .is_some_and(|o| o.contains_key("purpose"))
        {
            return Err(auth_err(
                "token carries a purpose claim; refusing a non-access token (CONTRACT.md §10.1 rule 11)",
            ));
        }
    }

    Ok(data.claims)
}

/// Which §10.1 rule set a token is verified under.
///
/// `Strict` is the access-token path: rules 10-12 (`typ`, `purpose`, `kid`).
/// `Lenient` is for the client's own freshly-issued session token and the
/// diagnostic `verify_signature_only_unchecked`, neither of which is a guard.
#[cfg(any(feature = "rest", feature = "actix"))]
#[derive(Clone, Copy, PartialEq, Eq)]
enum AccessTokenRules {
    Strict,
    Lenient,
}

/// §10.1 rule 10: `at+jwt`, ASCII case-insensitive, with or without the
/// `application/` prefix (RFC 7515 §4.1.9).
#[cfg(any(feature = "rest", feature = "actix"))]
fn is_access_token_typ(typ: &str) -> bool {
    let t = typ;
    let t = match t.get(..12) {
        Some(prefix) if prefix.eq_ignore_ascii_case("application/") => &t[12..],
        _ => t,
    };
    t.eq_ignore_ascii_case("at+jwt")
}

#[cfg(any(feature = "rest", feature = "actix"))]
fn auth_err(message: &str) -> AxiamError {
    AxiamError::Auth {
        message: message.into(),
        oauth: None,
        reason: None,
        set_reason: None,
        retry_after: None,
    }
}

/// Find a JWK by `kid` in a JWK set. If `kid` is `None` and the set has
/// exactly one key, returns that key as a best-effort match — AXIAM's
/// `/oauth2/jwks` serves exactly one org-wide Ed25519 key (D-11).
///
/// **Lenient path only** (the client's own server-issued session token and
/// `verify_signature_only_unchecked`). The guard path, the ID-token path and
/// the logout-token path select by `kid` alone ([`find_jwk_by_kid`]).
///
/// Mirrors `crates/axiam-federation/src/oidc.rs::find_jwk` exactly.
#[cfg(any(feature = "rest", feature = "actix"))]
fn find_jwk(jwks: &JwkSet, kid: Option<&str>) -> Option<jsonwebtoken::jwk::Jwk> {
    match kid {
        Some(k) => jwks
            .keys
            .iter()
            .find(|j| j.common.key_id.as_deref() == Some(k))
            .cloned(),
        None if jwks.keys.len() == 1 => jwks.keys.first().cloned(),
        None => None,
    }
}

/// Find a JWK by an EXPLICIT `kid` only — no single-key fallback. Used by the
/// access-token guard (§10.1 rule 12) and by
/// [`JwksVerifier::verify_id_token_signature`] (§12.4 rule 2), both of which
/// require a `kid` header; a token with none never reaches this function.
#[cfg(any(feature = "rest", feature = "actix"))]
fn find_jwk_by_kid(jwks: &JwkSet, kid: &str) -> Option<jsonwebtoken::jwk::Jwk> {
    jwks.keys
        .iter()
        .find(|j| j.common.key_id.as_deref() == Some(kid))
        .cloned()
}

#[cfg(all(test, any(feature = "rest", feature = "actix")))]
mod tests {
    use super::*;
    use jsonwebtoken::{EncodingKey, Header, jwk::*};

    /// A fixed, valid Ed25519 public key `x` coordinate (base64url, no
    /// padding) used only to exercise `find_jwk`'s selection logic in these
    /// tests. `find_jwk` never verifies a signature itself, so an arbitrary
    /// (but well-formed) OKP key is sufficient here — no signing key or
    /// extra crypto dependency needed.
    const TEST_PUBLIC_X: &str = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo";

    fn ed25519_test_jwk(kid: Option<&str>) -> Jwk {
        Jwk {
            common: CommonParameters {
                key_algorithm: Some(jsonwebtoken::jwk::KeyAlgorithm::EdDSA),
                key_id: kid.map(str::to_string),
                ..Default::default()
            },
            algorithm: AlgorithmParameters::OctetKeyPair(OctetKeyPairParameters {
                key_type: OctetKeyPairType::OctetKeyPair,
                curve: EllipticCurve::Ed25519,
                x: TEST_PUBLIC_X.to_string(),
            }),
        }
    }

    #[test]
    fn rejects_non_eddsa_alg_header() {
        // A well-formed HS256 token header must be rejected before any
        // signature/JWK lookup happens.
        let claims = Claims {
            sub: "u".into(),
            tenant_id: "t".into(),
            org_id: None,
            iss: "axiam".into(),
            iat: None,
            exp: 9_999_999_999,
            jti: None,
            sid: None,
            aud: None,
            scope: None,
            roles: None,
            cnf: None,
        };
        let token = jsonwebtoken::encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(b"irrelevant").expect("non-empty HMAC secret"),
        )
        .expect("encode HS256 test token");

        let header = decode_header(&token).expect("decode header");
        assert_ne!(header.alg, Algorithm::EdDSA);
    }

    #[test]
    fn find_jwk_single_key_fallback_when_kid_absent() {
        let jwk = ed25519_test_jwk(Some("test-kid"));
        let jwks = JwkSet { keys: vec![jwk] };
        let found = find_jwk(&jwks, None);
        assert!(
            found.is_some(),
            "single-key fallback must match on kid=None"
        );
    }

    #[test]
    fn find_jwk_no_fallback_with_multiple_keys() {
        let jwk1 = ed25519_test_jwk(Some("kid-1"));
        let jwk2 = ed25519_test_jwk(Some("kid-2"));
        let jwks = JwkSet {
            keys: vec![jwk1, jwk2],
        };
        let found = find_jwk(&jwks, None);
        assert!(
            found.is_none(),
            "must not fall back to a key when multiple keys exist and kid is absent"
        );
    }

    #[test]
    fn find_jwk_matches_by_kid() {
        let jwk1 = ed25519_test_jwk(Some("kid-1"));
        let jwk2 = ed25519_test_jwk(Some("kid-2"));
        let jwks = JwkSet {
            keys: vec![jwk1, jwk2],
        };
        let found = find_jwk(&jwks, Some("kid-2"));
        assert_eq!(found.unwrap().common.key_id.as_deref(), Some("kid-2"));
    }

    // ── §34.2 P6 (contract 1.60): the key cache expires, and a failed fetch
    //    counts toward the once-a-minute limit ──

    /// A JWKS endpoint answering `statuses` in turn (the last one repeats),
    /// and the number of fetches it saw.
    async fn jwks_endpoint(
        statuses: Vec<u16>,
    ) -> (
        wiremock::MockServer,
        std::sync::Arc<std::sync::atomic::AtomicUsize>,
    ) {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let server = wiremock::MockServer::start().await;
        let hits = std::sync::Arc::new(AtomicUsize::new(0));
        let seen = std::sync::Arc::clone(&hits);
        let body = serde_json::json!({ "keys": [ed25519_test_jwk(Some("kid-1"))] });
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .respond_with(move |_: &wiremock::Request| {
                let n = seen.fetch_add(1, Ordering::SeqCst);
                let status = statuses[n.min(statuses.len() - 1)];
                wiremock::ResponseTemplate::new(status).set_body_json(body.clone())
            })
            .mount(&server)
            .await;
        (server, hits)
    }

    fn ssf_verifier(server: &wiremock::MockServer) -> JwksVerifier {
        let url = url::Url::parse(&format!("{}/oauth2/jwks", server.uri())).unwrap();
        JwksVerifier::for_jwks_url(reqwest::Client::new(), url)
    }

    fn backdate(verifier: &JwksVerifier, field: &str, by: Duration) {
        let past = Instant::now()
            .checked_sub(by)
            .expect("a monotonic clock that far back");
        match field {
            "fetched_at" => verifier.cache.write().unwrap().as_mut().unwrap().fetched_at = past,
            _ => *verifier.last_failed_fetch.lock().unwrap() = Some(past),
        }
    }

    #[test]
    fn the_key_cache_lifetime_is_within_ten_minutes() {
        assert!(JWKS_CACHE_TTL <= Duration::from_secs(600));
    }

    #[tokio::test]
    async fn the_key_cache_expires_and_the_next_lookup_fetches_again() {
        use std::sync::atomic::Ordering;
        let (server, hits) = jwks_endpoint(vec![200]).await;
        let verifier = ssf_verifier(&server);
        assert!(verifier.key_for_kid("kid-1").await.unwrap().is_some());
        assert!(verifier.key_for_kid("kid-1").await.unwrap().is_some());
        assert_eq!(hits.load(Ordering::SeqCst), 1, "served from the cache");

        backdate(&verifier, "fetched_at", JWKS_CACHE_TTL);
        // The held set answers at once; the refresh runs detached.
        assert!(verifier.key_for_kid("kid-1").await.unwrap().is_some());
        settle(&verifier).await;
        assert_eq!(
            hits.load(Ordering::SeqCst),
            2,
            "an expired cache fetches again"
        );
        // A successful refresh is not counted: the unknown-kid refetch runs.
        assert!(verifier.key_for_kid("kid-9").await.unwrap().is_none());
        assert_eq!(hits.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn a_failed_fill_counts_and_the_next_lookup_inside_the_minute_makes_no_fetch() {
        use std::sync::atomic::Ordering;
        let (server, hits) = jwks_endpoint(vec![503, 200]).await;
        let verifier = ssf_verifier(&server);
        let e = verifier.key_for_kid("kid-1").await.unwrap_err();
        assert!(matches!(e, AxiamError::Network { .. }), "{e}");
        let e = verifier.key_for_kid("kid-1").await.unwrap_err();
        assert!(matches!(e, AxiamError::Network { .. }), "no verdict: {e}");
        assert_eq!(hits.load(Ordering::SeqCst), 1, "no fetch inside the minute");

        backdate(&verifier, "last_failed_fetch", FAILED_FETCH_MIN_INTERVAL);
        assert!(verifier.key_for_kid("kid-1").await.unwrap().is_some());
        assert_eq!(hits.load(Ordering::SeqCst), 2, "the minute is over");
    }

    #[tokio::test]
    async fn a_failed_expiry_refresh_and_a_failed_refetch_each_count() {
        use std::sync::atomic::Ordering;
        let (server, hits) = jwks_endpoint(vec![200, 503]).await;
        let verifier = ssf_verifier(&server);
        assert!(verifier.key_for_kid("kid-1").await.unwrap().is_some());

        // An unknown kid's refetch fails: a second unknown kid inside the
        // minute makes no fetch and is no verdict, while a known one still
        // verifies from the cache.
        assert!(verifier.key_for_kid("kid-9").await.is_err());
        assert_eq!(hits.load(Ordering::SeqCst), 2);
        let e = verifier.key_for_kid("kid-8").await.unwrap_err();
        assert!(matches!(e, AxiamError::Network { .. }), "{e}");
        assert!(verifier.key_for_kid("kid-1").await.unwrap().is_some());
        assert_eq!(hits.load(Ordering::SeqCst), 2);

        // The cache expires and its refresh fails: counted the same way. The
        // held key keeps verifying (stale-if-error, §12.4 rule 2, contract 1.69)
        // instead of the lookup failing as it did before.
        backdate(&verifier, "last_failed_fetch", FAILED_FETCH_MIN_INTERVAL);
        backdate(&verifier, "fetched_at", JWKS_CACHE_TTL);
        assert!(verifier.key_for_kid("kid-1").await.unwrap().is_some());
        settle(&verifier).await;
        assert_eq!(hits.load(Ordering::SeqCst), 3);
        assert!(verifier.key_for_kid("kid-1").await.unwrap().is_some());
        assert_eq!(hits.load(Ordering::SeqCst), 3, "no fetch inside the minute");
    }

    #[tokio::test]
    async fn a_failing_endpoint_is_fetched_once_per_60s_window() {
        use std::sync::atomic::Ordering;
        let (server, hits) = jwks_endpoint(vec![503, 200]).await;
        let url = url::Url::parse(&format!("{}/oauth2/jwks", server.uri())).unwrap();
        let verifier = JwksVerifier::for_jwks_url(reqwest::Client::new(), url);
        for _ in 0..50 {
            let e = verifier.key_for_kid("kid-1").await.unwrap_err();
            assert!(matches!(e, AxiamError::Network { .. }), "{e}");
        }
        assert_eq!(
            hits.load(Ordering::SeqCst),
            1,
            "a cold cache and a failing endpoint: one fetch per window"
        );

        // 11 s on: still inside the 60 s window, no fetch is made.
        backdate(&verifier, "last_failed_fetch", Duration::from_secs(11));
        assert!(verifier.key_for_kid("kid-1").await.is_err());
        assert_eq!(hits.load(Ordering::SeqCst), 1, "no fetch at 11 s");

        // 61 s on: a healthy endpoint is fetched and succeeds.
        backdate(&verifier, "last_failed_fetch", Duration::from_secs(61));
        assert!(verifier.key_for_kid("kid-1").await.unwrap().is_some());
        assert_eq!(hits.load(Ordering::SeqCst), 2);
    }

    // --- contract 1.69 (D-10) §12.4 rule 2: bounded stale-if-error ----------
    //
    // The clock is injected by moving every instant the cache holds back by the
    // time that "passes": the verifier only ever compares `elapsed()` against
    // them, so this is the same as advancing a fake clock, and nothing sleeps.

    use std::sync::Arc;
    use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering as AtomicOrdering};

    const OK: u8 = 0;
    const FAIL: u8 = 1;
    const EMPTY: u8 = 2;
    const NOT_JWKS: u8 = 3;
    const ETAGGED: u8 = 4;
    const EMPTY_OBJECT_KEY: u8 = 5;

    struct Jwks {
        server: wiremock::MockServer,
        mode: Arc<AtomicU8>,
        hits: Arc<AtomicUsize>,
        max_age: Arc<std::sync::Mutex<Option<String>>>,
        delay_ms: Arc<AtomicUsize>,
    }

    impl Jwks {
        async fn start() -> Self {
            let server = wiremock::MockServer::start().await;
            let mode = Arc::new(AtomicU8::new(OK));
            let hits = Arc::new(AtomicUsize::new(0));
            let max_age = Arc::new(std::sync::Mutex::new(None::<String>));
            let delay_ms = Arc::new(AtomicUsize::new(0));
            let (m, h, ma, dl) = (
                Arc::clone(&mode),
                Arc::clone(&hits),
                Arc::clone(&max_age),
                Arc::clone(&delay_ms),
            );
            let keys = serde_json::json!({ "keys": [ed25519_test_jwk(Some("kid-1"))] });
            wiremock::Mock::given(wiremock::matchers::method("GET"))
                .respond_with(move |req: &wiremock::Request| {
                    h.fetch_add(1, AtomicOrdering::SeqCst);
                    let mut r = match m.load(AtomicOrdering::SeqCst) {
                        FAIL => return wiremock::ResponseTemplate::new(503),
                        EMPTY => wiremock::ResponseTemplate::new(200)
                            .set_body_json(serde_json::json!({ "keys": [] })),
                        EMPTY_OBJECT_KEY => wiremock::ResponseTemplate::new(200)
                            .set_body_json(serde_json::json!({ "keys": [{}] })),
                        NOT_JWKS => wiremock::ResponseTemplate::new(200).set_body_string("<html>"),
                        ETAGGED => {
                            if req.headers.get("if-none-match").is_some() {
                                return wiremock::ResponseTemplate::new(304);
                            }
                            wiremock::ResponseTemplate::new(200)
                                .insert_header("etag", "\"v1\"")
                                .set_body_json(keys.clone())
                        }
                        _ => wiremock::ResponseTemplate::new(200).set_body_json(keys.clone()),
                    };
                    if let Some(v) = ma.lock().unwrap().as_ref() {
                        r = r.insert_header("cache-control", v.as_str());
                    }
                    let d = dl.load(AtomicOrdering::SeqCst) as u64;
                    r.set_delay(std::time::Duration::from_millis(d))
                })
                .mount(&server)
                .await;
            Self {
                server,
                mode,
                hits,
                max_age,
                delay_ms,
            }
        }

        fn verifier(&self) -> JwksVerifier {
            let url = url::Url::parse(&format!("{}/oauth2/jwks", self.server.uri())).unwrap();
            JwksVerifier::for_jwks_url(reqwest::Client::new(), url)
        }

        fn set(&self, mode: u8) {
            self.mode.store(mode, AtomicOrdering::SeqCst);
        }

        fn fetches(&self) -> usize {
            self.hits.load(AtomicOrdering::SeqCst)
        }
    }

    /// Let `by` pass: every instant the verifier holds moves back by it.
    fn advance(verifier: &JwksVerifier, by: Duration) {
        let back = |t: Instant| t.checked_sub(by).expect("a monotonic clock that far back");
        if let Some(entry) = verifier.cache.write().unwrap().as_mut() {
            entry.fetched_at = back(entry.fetched_at);
            entry.last_forced_refetch = entry.last_forced_refetch.map(back);
        }
        let mut failed = verifier.last_failed_fetch.lock().unwrap();
        *failed = failed.map(back);
    }

    /// Whether the verifier records a failed refresh or an opened forced window.
    fn cooldown_state(v: &JwksVerifier) -> (bool, bool) {
        let failed = v.last_failed_fetch.lock().unwrap().is_some();
        let forced = v
            .cache
            .read()
            .unwrap()
            .as_ref()
            .is_some_and(|e| e.last_forced_refetch.is_some());
        (failed, forced)
    }

    #[tokio::test]
    async fn max_age_zero_never_means_one_fetch_per_verification() {
        let jwks = Jwks::start().await;
        *jwks.max_age.lock().unwrap() = Some("max-age=0".into());
        let v = jwks.verifier();
        for _ in 0..10 {
            assert!(accepted(&v, "kid-1").await);
        }
        assert_eq!(jwks.fetches(), 1);
        advance(&v, FAILED_FETCH_MIN_INTERVAL);
        assert!(accepted(&v, "kid-1").await);
        assert_eq!(jwks.fetches(), 2, "refreshed once the 60 s window passed");
        // A failing refresh respects the same window.
        jwks.set(FAIL);
        advance(&v, FAILED_FETCH_MIN_INTERVAL);
        for _ in 0..10 {
            assert!(accepted(&v, "kid-1").await, "the held set keeps serving");
        }
        assert_eq!(jwks.fetches(), 3, "one failed attempt, then the window");
    }

    #[tokio::test]
    async fn callers_cancelled_mid_fetch_never_cause_more_than_one_fetch_per_window() {
        let jwks = Jwks::start().await;
        let v = Arc::new(jwks.verifier());
        assert!(accepted(&v, "kid-1").await);
        assert_eq!(jwks.fetches(), 1);
        jwks.delay_ms.store(300, AtomicOrdering::SeqCst);
        // 20 unknown-kid callers, each cancelled after 60 ms, mid-fetch.
        for i in 0..20 {
            // The first is cancelled mid-fetch; the rest meet the open window.
            let _ = tokio::time::timeout(
                std::time::Duration::from_millis(60),
                v.key_for_kid(&format!("kid-x{i}")),
            )
            .await;
        }
        settle(&v).await;
        assert_eq!(jwks.fetches(), 2, "one forced fetch, however many callers");
        // The fetch ran to completion on its own and recorded its REAL outcome:
        // a success, so no failure is on record; the forced window is open.
        assert_eq!(cooldown_state(&v), (false, true));
    }

    #[tokio::test]
    async fn a_cancelled_cold_caller_leaves_the_fetch_running_and_its_result_cached() {
        let jwks = Jwks::start().await;
        jwks.delay_ms.store(300, AtomicOrdering::SeqCst);
        let v = jwks.verifier();
        let dropped =
            tokio::time::timeout(std::time::Duration::from_millis(60), v.key_for_kid("kid-1"))
                .await;
        assert!(dropped.is_err());
        settle(&v).await;
        assert_eq!(cooldown_state(&v), (false, false));
        assert_eq!(jwks.fetches(), 1);
        assert!(v.cache.read().unwrap().is_some(), "the task filled it");
    }

    #[tokio::test]
    async fn a_failing_forced_fetch_opens_the_window_and_records_the_failure_once() {
        let jwks = Jwks::start().await;
        let v = jwks.verifier();
        assert!(accepted(&v, "kid-1").await);
        jwks.set(FAIL);
        jwks.delay_ms.store(200, AtomicOrdering::SeqCst);
        let _ = tokio::time::timeout(std::time::Duration::from_millis(50), v.key_for_kid("kid-9"))
            .await;
        settle(&v).await;
        assert_eq!(cooldown_state(&v), (true, true));
        assert_eq!(jwks.fetches(), 2);
    }

    #[tokio::test]
    async fn a_fetch_that_never_answers_is_bounded_by_the_sdk_own_timeout() {
        // A socket that accepts and never replies; the client has no timeout.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((sock, _)) = listener.accept().await {
                held.push(sock);
            }
        });
        let url = url::Url::parse(&format!("http://127.0.0.1:{port}/oauth2/jwks")).unwrap();
        let mut v =
            JwksVerifier::for_jwks_url(reqwest::Client::builder().no_proxy().build().unwrap(), url);
        v.fetch_timeout = std::time::Duration::from_millis(200);
        let started = std::time::Instant::now();
        let e = v.key_for_kid("kid-1").await.unwrap_err();
        assert!(matches!(e, AxiamError::Network { .. }), "{e}");
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
        settle(&v).await;
        assert_eq!(cooldown_state(&v), (true, false), "a timeout is a failure");
    }

    #[tokio::test]
    async fn a_usable_held_set_returns_promptly_while_a_slow_fetch_is_in_flight() {
        let jwks = Jwks::start().await;
        let v = jwks.verifier();
        assert!(accepted(&v, "kid-1").await);
        advance(&v, TTL + Duration::from_secs(1)); // stale, inside the bound
        jwks.delay_ms.store(3000, AtomicOrdering::SeqCst);
        // The caller that STARTS the refresh is served at once, not after it.
        let started = std::time::Instant::now();
        assert!(matches!(v.key_for_kid("kid-1").await, Ok(Some(_))));
        assert!(started.elapsed() < std::time::Duration::from_millis(500));
        // A second one, with the refresh in flight, is too, and joins it.
        let started = std::time::Instant::now();
        assert!(matches!(v.key_for_kid("kid-1").await, Ok(Some(_))));
        assert!(started.elapsed() < std::time::Duration::from_millis(500));
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert_eq!(jwks.fetches(), 2, "single-flight: one refresh");
    }

    #[tokio::test]
    async fn a_keys_member_that_is_an_object_is_a_failed_refresh() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({ "keys": { "kty": "OKP" } })),
            )
            .mount(&server)
            .await;
        let url = url::Url::parse(&format!("{}/oauth2/jwks", server.uri())).unwrap();
        let v = JwksVerifier::for_jwks_url(reqwest::Client::new(), url);
        assert!(v.key_for_kid("kid-1").await.is_err());
        assert!(v.cache.read().unwrap().is_none());
    }

    /// A token with `kid` would be accepted: its key is found.
    async fn accepted(verifier: &JwksVerifier, kid: &str) -> bool {
        let found = matches!(verifier.key_for_kid(kid).await, Ok(Some(_)));
        settle(verifier).await;
        found
    }

    /// Wait for the detached refresh a stale-but-usable lookup started, so the
    /// fetch count and the cache can be asserted on.
    async fn settle(verifier: &JwksVerifier) {
        for _ in 0..500 {
            let busy = verifier
                .inflight
                .lock()
                .unwrap()
                .as_ref()
                .is_some_and(|rx| rx.borrow().is_none() && rx.has_changed().is_ok());
            if !busy {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        panic!("the JWKS fetch never finished");
    }

    const TTL: Duration = JWKS_CACHE_TTL;

    #[tokio::test]
    async fn a_failed_refresh_keeps_the_held_keys_until_exactly_ttl_plus_300s() {
        for failure in [FAIL, EMPTY, EMPTY_OBJECT_KEY, NOT_JWKS] {
            let jwks = Jwks::start().await;
            let v = jwks.verifier();
            // t0: the cache is filled.
            assert!(accepted(&v, "kid-1").await);
            assert_eq!(jwks.fetches(), 1);
            jwks.set(failure);

            // t0 + TTL + 1: one failed refresh is attempted; the held kid is accepted.
            advance(&v, TTL + Duration::from_secs(1));
            assert!(
                accepted(&v, "kid-1").await,
                "mode {failure}: held kid at TTL+1"
            );
            assert_eq!(jwks.fetches(), 2, "mode {failure}: one refresh attempted");

            // t0 + TTL + 250: an unknown kid is refused, the held kid still accepted.
            advance(&v, Duration::from_secs(249));
            assert!(
                !accepted(&v, "kid-9").await,
                "mode {failure}: unknown kid at TTL+250"
            );
            assert!(
                accepted(&v, "kid-1").await,
                "mode {failure}: held kid at TTL+250"
            );

            // t0 + TTL + 301: the held kid is refused too: the anchor never moved.
            advance(&v, Duration::from_secs(51));
            assert!(
                !accepted(&v, "kid-1").await,
                "mode {failure}: held kid at TTL+301"
            );

            // The endpoint recovers; past the window, one fetch accepts it again.
            jwks.set(OK);
            advance(&v, Duration::from_secs(61));
            let before = jwks.fetches();
            assert!(
                accepted(&v, "kid-1").await,
                "mode {failure}: after a successful fetch"
            );
            assert_eq!(
                jwks.fetches(),
                before + 1,
                "mode {failure}: after one fetch"
            );
        }
    }

    #[tokio::test]
    async fn an_empty_key_set_never_replaces_the_held_one() {
        let jwks = Jwks::start().await;
        let v = jwks.verifier();
        assert!(accepted(&v, "kid-1").await);
        jwks.set(EMPTY);
        advance(&v, TTL + Duration::from_secs(1));
        assert!(
            accepted(&v, "kid-1").await,
            "the held kid is still accepted"
        );
        assert_eq!(v.cache.read().unwrap().as_ref().unwrap().jwks.keys.len(), 1);
    }

    #[tokio::test]
    async fn an_unknown_kid_refresh_that_fails_never_opens_or_extends_the_stale_window() {
        let jwks = Jwks::start().await;
        let v = jwks.verifier();
        assert!(accepted(&v, "kid-1").await);
        jwks.set(FAIL);
        // Within the TTL an unknown kid triggers its one refetch; it fails.
        advance(&v, Duration::from_secs(100));
        assert!(!accepted(&v, "kid-9").await);
        assert_eq!(jwks.fetches(), 2);
        // The failed attempt counts toward the cooldown: no second fetch.
        assert!(!accepted(&v, "kid-8").await);
        assert_eq!(jwks.fetches(), 2);
        assert!(accepted(&v, "kid-1").await, "the held set stays in place");
        // The bound still runs from t0, not from the failed attempt.
        advance(&v, TTL + Duration::from_secs(201));
        assert!(!accepted(&v, "kid-1").await, "t0 + TTL + 301: refused");
    }

    #[tokio::test]
    async fn a_304_to_a_conditional_request_is_a_success_and_moves_the_anchor() {
        let jwks = Jwks::start().await;
        jwks.set(ETAGGED);
        let v = jwks.verifier();
        assert!(accepted(&v, "kid-1").await);
        advance(&v, TTL + Duration::from_secs(1));
        assert!(accepted(&v, "kid-1").await);
        assert_eq!(
            jwks.fetches(),
            2,
            "the refresh was conditional and got a 304"
        );
        // The anchor moved to the 304: fresh again, no fetch...
        advance(&v, Duration::from_secs(290));
        assert!(accepted(&v, "kid-1").await);
        assert_eq!(jwks.fetches(), 2);
        // ...and 611 s after t0 the keys still verify (the refresh fails), because
        // the anchor moved to the 304: they are 310 s old, not 611 s.
        jwks.set(FAIL);
        advance(&v, Duration::from_secs(20));
        assert!(accepted(&v, "kid-1").await);
    }

    #[test]
    fn the_advertised_max_age_is_honoured_below_300s_and_clamped_above() {
        let ttl = |value: Option<&str>| {
            let mut h = reqwest::header::HeaderMap::new();
            if let Some(v) = value {
                h.insert(reqwest::header::CACHE_CONTROL, v.parse().unwrap());
            }
            advertised_ttl(&h)
        };
        assert_eq!(ttl(None), TTL);
        assert_eq!(ttl(Some("public, max-age=300")), TTL);
        assert_eq!(ttl(Some("public, max-age=60")), Duration::from_secs(60));
        assert_eq!(
            ttl(Some("max-age=3600")),
            TTL,
            "clamped down, never honoured"
        );
        assert_eq!(ttl(Some("MAX-AGE=0")), Duration::ZERO);
        assert_eq!(ttl(Some("max-age=nonsense")), TTL);
        assert_eq!(ttl(Some("no-store")), TTL);
    }

    #[tokio::test]
    async fn an_advertised_one_hour_max_age_does_not_stretch_the_ttl() {
        let jwks = Jwks::start().await;
        *jwks.max_age.lock().unwrap() = Some("public, max-age=3600".into());
        let v = jwks.verifier();
        assert!(accepted(&v, "kid-1").await);
        advance(&v, TTL);
        assert!(accepted(&v, "kid-1").await);
        assert_eq!(jwks.fetches(), 2, "refetched at 300 s, not at 3600 s");
    }

    #[tokio::test]
    async fn a_failing_first_fetch_costs_one_fetch_per_window_not_one_per_token() {
        let jwks = Jwks::start().await;
        jwks.set(FAIL);
        let v = jwks.verifier();
        for _ in 0..20 {
            assert!(!accepted(&v, "kid-1").await);
        }
        assert_eq!(jwks.fetches(), 1);
    }

    #[tokio::test]
    async fn only_a_200_is_a_success_and_a_hostile_etag_is_not_stored() {
        let jwks = Jwks::start().await;
        let v = jwks.verifier();
        assert!(accepted(&v, "kid-1").await);
        assert!(v.cache.read().unwrap().as_ref().unwrap().etag.is_none());
        jwks.set(ETAGGED);
        advance(&v, TTL);
        assert!(accepted(&v, "kid-1").await);
        assert_eq!(
            v.cache.read().unwrap().as_ref().unwrap().etag.as_deref(),
            Some("\"v1\"")
        );
    }
}
