//! DPoP proof verification — CONTRACT.md §21.7.2 (RFC 9449), contract 1.16.
//!
//! The resource-server half of DPoP: given the `DPoP` header a caller
//! presented, decide whether it proves possession for *this* request and
//! *this* access token, and return the key thumbprint that
//! [`Claims::verify_token_binding`](super::jwks::Claims::verify_token_binding)
//! then matches against the token's `cnf.jkt`.
//!
//! # Why this lives in the SDK
//!
//! §21.7.2 is a ten-check list, and the contract is blunt about partial
//! implementations: *"Partial verification is worse than none, because it
//! produces a guard that reports success."* Nine of the ten look optional
//! until someone builds an attack out of the one that was skipped, so they
//! belong in one audited place rather than in every application guarding an
//! endpoint.
//!
//! The two most often missing, and what they cost:
//!
//! - **`typ`** — without pinning it to `dpop+jwt`, any *other* JWT signed by
//!   the same key (an access token, an ID token) is replayable as a proof.
//! - **`ath`** — without it, a proof captured on one request can be re-aimed
//!   at a different token held by the same key. `ath` binds the proof to the
//!   token rather than merely to the key.
//!
//! # The algorithm comes from the key, never from the header
//!
//! `alg: none` and RSA-public-key-as-HMAC-secret are the same bug wearing
//! different clothes: *the token told the verifier how to check the token*.
//! This module derives the expected algorithm from the embedded key's
//! `kty`/`crv` and passes that one algorithm to the decoder, so the header
//! never *selects* anything.
//!
//! One divergence from the Python and TypeScript SDKs, recorded here because
//! it is visible to callers: `jsonwebtoken` additionally refuses a token whose
//! header `alg` disagrees with the allowlist it was handed. Those SDKs ignore
//! a lying `alg` header and verify anyway; this one rejects the proof. Both
//! satisfy §21.7.2 check 2 — neither lets the header choose the algorithm —
//! and this is the stricter of the two.
//!
//! # Feature gating
//!
//! Gated on `rest`/`actix` because the checks need `sha2`, `base64` and
//! `subtle`, which those features bring in. A `--no-default-features`
//! consumer keeps `Claims::verify_token_binding` (pure claim comparison) and
//! simply has no proof verifier — which, per §10.1 rule 9, means it must
//! refuse `jkt`-bound tokens rather than accept them as bearer tokens.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jsonwebtoken::jwk::Jwk;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::AxiamError;

/// §21.7.2 check 7 — the `iat` acceptance window, applied in **both**
/// directions. RFC 9449 recommends a small window without fixing a number; 60
/// seconds is the contract's RECOMMENDED value. A named constant, because a
/// bare `60` three call frames deep is a number nobody ever revisits.
pub const DPOP_IAT_LEEWAY_SECS: u64 = 60;

/// RFC 9449 §4.3 — private key material that must never appear in a proof's
/// embedded public `jwk`. `k` is the symmetric-key member: its presence means
/// the "public key" is a shared secret.
const PRIVATE_JWK_MEMBERS: &[&str] = &["d", "p", "q", "dp", "dq", "qi", "oth", "k"];

fn auth(message: impl Into<String>) -> AxiamError {
    AxiamError::Auth {
        message: message.into(),
        oauth: None,
        reason: None,
    }
}

/// §21.7.2 check 8 — single-use `jti` tracking.
///
/// One method, and its contract is the point: [`claim`](JtiStore::claim) must
/// be atomic. A `contains?`-then-`insert` pair read as two calls is a race
/// that two concurrent replays of the same proof can both win.
pub trait JtiStore: Send + Sync {
    /// Record `jti` as used until `expires_at_unix`.
    ///
    /// Returns `true` if this is the first sighting, `false` if it is a replay.
    fn claim(&self, jti: &str, expires_at_unix: u64) -> bool;
}

/// A [`JtiStore`] for a single process.
///
/// **Per-process, therefore per-worker.** Four processes behind a load
/// balancer give an attacker four chances to replay a proof inside its
/// freshness window, and a restart clears the window entirely. Any deployment
/// running more than one process needs a shared store (Redis, a database
/// table).
#[derive(Debug, Default)]
pub struct InMemoryJtiStore {
    seen: Mutex<HashMap<String, u64>>,
}

impl InMemoryJtiStore {
    /// Creates an empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl JtiStore for InMemoryJtiStore {
    fn claim(&self, jti: &str, expires_at_unix: u64) -> bool {
        let now = now_unix();
        // A poisoned lock means another thread panicked mid-claim. Recovering
        // the guard is right here: the map is a plain replay ledger with no
        // cross-entry invariant a panic could have torn.
        let mut seen = self.seen.lock().unwrap_or_else(|e| e.into_inner());
        // Prune under the same lock as the insert. Entries only ever live for
        // the freshness window, so this stays small with no background task.
        if seen.len() > 128 {
            seen.retain(|_, expiry| *expiry > now);
        }
        if seen.get(jti).is_some_and(|expiry| *expiry > now) {
            return false;
        }
        seen.insert(jti.to_owned(), expires_at_unix);
        true
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// RFC 7638 SHA-256 thumbprint of a JWK — the `jkt`.
///
/// Only the members RFC 7638 names for the key type take part, serialised as
/// compact JSON with lexicographically ordered keys. Members outside that set
/// (`kid`, `use`, `alg`, `x5c`) are excluded by the spec, which is what makes
/// the thumbprint stable across two encodings of the same key.
///
/// # Errors
///
/// [`AxiamError::Auth`] if the key type is unsupported or a required member is
/// missing.
pub fn jwk_thumbprint_s256(jwk: &serde_json::Value) -> Result<String, AxiamError> {
    let get = |member: &str| -> Result<String, AxiamError> {
        jwk.get(member)
            .and_then(serde_json::Value::as_str)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .ok_or_else(|| {
                auth(format!(
                    "DPoP proof jwk is missing the required member '{member}'"
                ))
            })
    };

    // Built by hand rather than through a map, so the member set and their
    // order are visible at the point they are required rather than depending
    // on a serialiser's ordering behaviour.
    let canonical = match jwk.get("kty").and_then(serde_json::Value::as_str) {
        Some("RSA") => {
            format!(r#"{{"e":"{}","kty":"RSA","n":"{}"}}"#, get("e")?, get("n")?)
        }
        Some("EC") => format!(
            r#"{{"crv":"{}","kty":"EC","x":"{}","y":"{}"}}"#,
            get("crv")?,
            get("x")?,
            get("y")?
        ),
        Some("OKP") => {
            format!(
                r#"{{"crv":"{}","kty":"OKP","x":"{}"}}"#,
                get("crv")?,
                get("x")?
            )
        }
        other => {
            return Err(auth(format!(
                "DPoP proof jwk has an unsupported kty: {}",
                other.unwrap_or("<missing>")
            )));
        }
    };

    Ok(URL_SAFE_NO_PAD.encode(Sha256::digest(canonical.as_bytes())))
}

/// The `ath` claim value for `access_token` — RFC 9449 §4.2.
///
/// base64url-unpadded SHA-256 over the token's bytes exactly as they travelled
/// in the `Authorization` header, not over anything decoded out of them.
#[must_use]
pub fn access_token_hash(access_token: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(access_token.as_bytes()))
}

/// The `htu` comparison form — §21.7.2 check 6.
///
/// Query and fragment removed, and **nothing else**. No case folding, no
/// default-port elision, no percent-decoding, no trailing-slash fixing: a
/// normalising comparison is precisely where two unequal URIs become equal,
/// and an attacker who finds such a pair can aim a proof at an endpoint it was
/// never minted for.
#[must_use]
pub fn canonical_htu(uri: &str) -> &str {
    let without_fragment = uri.split('#').next().unwrap_or(uri);
    without_fragment
        .split('?')
        .next()
        .unwrap_or(without_fragment)
}

/// §21.7.2 check 2 — derive the algorithm from the key itself.
///
/// This function is why the proof header's `alg` is never read: the key's own
/// type determines how a signature over it can be checked, and that is not a
/// matter the presenter gets an opinion on.
fn expected_alg(jwk: &serde_json::Value) -> Result<Algorithm, AxiamError> {
    let kty = jwk.get("kty").and_then(serde_json::Value::as_str);
    let crv = jwk.get("crv").and_then(serde_json::Value::as_str);
    match (kty, crv) {
        (Some("RSA"), _) => Ok(Algorithm::PS256),
        (Some("EC"), Some("P-256")) => Ok(Algorithm::ES256),
        (Some("OKP"), Some("Ed25519")) => Ok(Algorithm::EdDSA),
        _ => Err(auth(format!(
            "DPoP proof key type is not permitted by CONTRACT.md §21.7.2 \
             (kty={}, crv={}; permitted: ES256, EdDSA, PS256)",
            kty.unwrap_or("<missing>"),
            crv.unwrap_or("<missing>")
        ))),
    }
}

/// The claims §21.7.2 reads out of a proof.
#[derive(Debug, Deserialize)]
struct DpopClaims {
    htm: Option<String>,
    htu: Option<String>,
    iat: Option<i64>,
    jti: Option<String>,
    ath: Option<String>,
}

/// Everything [`verify_dpop_proof`] needs. Each field feeds a check that
/// cannot be made without it — there is no "just check the signature" mode,
/// because that is exactly the partial verification the contract calls worse
/// than none.
pub struct DpopRequest<'a> {
    /// The request method, e.g. `"POST"`.
    pub http_method: &'a str,
    /// The full request URI. Query and fragment are stripped here, so passing
    /// it with a query string is fine and expected.
    pub http_uri: &'a str,
    /// The access token from the `Authorization` header, exactly as it
    /// arrived — this is hashed for the `ath` check.
    pub access_token: &'a str,
    /// The token's `cnf.jkt`, when the caller has it. Supplying it performs
    /// check 10 here; omitting it means the caller must do that comparison
    /// itself, which `Claims::verify_token_binding` does.
    pub expected_jkt: Option<&'a str>,
    /// The `iat` window, both directions.
    pub leeway_secs: u64,
    /// Override for the current UNIX time, for tests.
    pub now_unix: Option<u64>,
}

impl<'a> DpopRequest<'a> {
    /// A request with the contract's default leeway and the real clock.
    #[must_use]
    pub fn new(http_method: &'a str, http_uri: &'a str, access_token: &'a str) -> Self {
        Self {
            http_method,
            http_uri,
            access_token,
            expected_jkt: None,
            leeway_secs: DPOP_IAT_LEEWAY_SECS,
            now_unix: None,
        }
    }

    /// Sets the token's `cnf.jkt`, enabling check 10 inside this call.
    #[must_use]
    pub fn with_expected_jkt(mut self, jkt: &'a str) -> Self {
        self.expected_jkt = Some(jkt);
        self
    }
}

/// Verify a DPoP proof against this request — all ten §21.7.2 checks.
///
/// Returns the proof key's RFC 7638 thumbprint (`jkt`) on success. Feed it to
/// [`Claims::verify_token_binding`](super::jwks::Claims::verify_token_binding)
/// as `dpop_thumbprint`; returning it rather than a bare `()` is deliberate,
/// so the value a guard passes onward could only have come from a proof that
/// actually verified.
///
/// # Errors
///
/// [`AxiamError::Auth`] on any failing check.
pub fn verify_dpop_proof(
    proof: &str,
    request: &DpopRequest<'_>,
    jti_store: &dyn JtiStore,
) -> Result<String, AxiamError> {
    if proof.is_empty() {
        return Err(auth("DPoP proof is missing or empty"));
    }
    // RFC 9449 §4.2 makes exactly one proof the rule. Rejecting beats picking
    // the first, which is how a verifier and a downstream parser end up
    // reading different proofs.
    if proof.contains(',') || proof.trim().contains(char::is_whitespace) {
        return Err(auth("DPoP header must carry exactly one proof"));
    }

    // The header as RAW JSON. §21.7.2 check 4 insists the private-material
    // check run against this rather than a parsed key type, because many JWK
    // libraries quietly drop `d`/`p`/`q` when parsing into a public key — the
    // check would then pass by virtue of the library having hidden the
    // evidence.
    let segments: Vec<&str> = proof.split('.').collect();
    if segments.len() != 3 {
        return Err(auth("DPoP proof is not a compact JWS with three segments"));
    }
    let header_bytes = URL_SAFE_NO_PAD
        .decode(segments[0])
        .map_err(|_| auth("DPoP proof header is not valid base64url"))?;
    let header: serde_json::Value = serde_json::from_slice(&header_bytes)
        .map_err(|_| auth("DPoP proof header is not valid JSON"))?;

    // Check 1 — typ. First, because it is what stops any other JWT signed by
    // the same key from standing in as a proof.
    let typ = header
        .get("typ")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    if !typ.eq_ignore_ascii_case("dpop+jwt") {
        return Err(auth(format!(
            "DPoP proof typ header must be 'dpop+jwt', got '{typ}'"
        )));
    }

    // Check 3 (first half) — the header carries a public jwk.
    let jwk_value = header
        .get("jwk")
        .filter(|v| v.is_object())
        .ok_or_else(|| auth("DPoP proof header must carry a public 'jwk'"))?;

    // Check 4 — no private material, tested against the raw header JSON.
    let leaked: Vec<&str> = PRIVATE_JWK_MEMBERS
        .iter()
        .copied()
        .filter(|m| jwk_value.get(*m).is_some())
        .collect();
    if !leaked.is_empty() {
        return Err(auth(format!(
            "DPoP proof jwk carries private key material ({}) — RFC 9449 §4.3",
            leaked.join(", ")
        )));
    }

    // Check 2 — algorithm from the key, never from the header.
    let alg = expected_alg(jwk_value)?;

    // Check 3 (second half) — the signature verifies under that key.
    let jwk: Jwk = serde_json::from_value(jwk_value.clone())
        .map_err(|e| auth(format!("DPoP proof jwk is not a usable public key: {e}")))?;
    let key = DecodingKey::from_jwk(&jwk)
        .map_err(|e| auth(format!("DPoP proof jwk is not a usable public key: {e}")))?;

    let mut validation = Validation::new(alg);
    // A DPoP proof carries no `exp` and no `aud`; `iat` freshness is check 7
    // below, which is this module's sole authority on the matter. Clearing the
    // defaults here keeps two windows from disagreeing about one claim.
    validation.required_spec_claims.clear();
    validation.validate_exp = false;
    validation.validate_aud = false;
    let claims = decode::<DpopClaims>(proof, &key, &validation)
        .map_err(|e| auth(format!("DPoP proof signature or claims are invalid: {e}")))?
        .claims;

    // Check 5 — htm.
    let htm = claims.htm.as_deref().unwrap_or_default();
    if htm != request.http_method {
        return Err(auth(format!(
            "DPoP proof htm '{htm}' does not match request method '{}'",
            request.http_method
        )));
    }

    // Check 6 — htu, with query and fragment stripped from BOTH sides and
    // nothing else touched.
    let htu = claims.htu.as_deref().unwrap_or_default();
    let expected_htu = canonical_htu(request.http_uri);
    if canonical_htu(htu) != expected_htu {
        return Err(auth(format!(
            "DPoP proof htu '{htu}' does not match request URI '{expected_htu}'"
        )));
    }

    // Check 7 — iat freshness, in both directions. A proof from the future is
    // as suspect as a stale one: it is how a one-sided skew allowance becomes
    // a long-lived proof.
    let iat = claims
        .iat
        .ok_or_else(|| auth("DPoP proof iat must be a number"))?;
    let now = i64::try_from(request.now_unix.unwrap_or_else(now_unix)).unwrap_or(i64::MAX);
    let leeway = i64::try_from(request.leeway_secs).unwrap_or(i64::MAX);
    if (now - iat).abs() > leeway {
        return Err(auth(format!(
            "DPoP proof iat is outside the {}s freshness window",
            request.leeway_secs
        )));
    }

    // Check 9 — ath ties the proof to this specific access token.
    let ath = claims.ath.as_deref().unwrap_or_default();
    if ath.is_empty() {
        return Err(auth("DPoP proof is missing the ath claim"));
    }
    let expected_ath = access_token_hash(request.access_token);
    if ath.as_bytes().ct_eq(expected_ath.as_bytes()).unwrap_u8() != 1 {
        return Err(auth(
            "DPoP proof ath does not match the presented access token",
        ));
    }

    // Check 10 — the thumbprint that ties the proof to the token's cnf.
    let jkt = jwk_thumbprint_s256(jwk_value)?;
    if let Some(expected) = request.expected_jkt
        && jkt.as_bytes().ct_eq(expected.as_bytes()).unwrap_u8() != 1
    {
        return Err(auth("DPoP proof key does not match the token's cnf.jkt"));
    }

    // Check 8 — jti single-use. LAST on purpose: claiming a jti is a mutation,
    // and doing it before the cheap checks would let an attacker burn
    // arbitrary jti values out of the store with proofs that were never going
    // to verify.
    let jti = claims.jti.as_deref().unwrap_or_default();
    if jti.is_empty() {
        return Err(auth("DPoP proof is missing a non-empty jti"));
    }
    let expires_at = u64::try_from(iat)
        .unwrap_or(0)
        .saturating_add(request.leeway_secs);
    if !jti_store.claim(jti, expires_at) {
        return Err(auth("DPoP proof jti has already been used (replay)"));
    }

    Ok(jkt)
}
