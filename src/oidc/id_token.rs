//! ID-token claim validation — CONTRACT.md §12.4, OIDC Core §3.1.3.7.
//!
//! PURE logic only: no network I/O. The signature half of §12.4 (rules 1–2:
//! `alg` allowlist, `kid` lookup, Ed25519 verification, single JWKS
//! re-fetch) lives in [`crate::token::jwks`], on the SAME [`crate::token::JwksVerifier`]
//! the §10 middleware already uses — §12 forbids forking it. This module
//! holds rules 3–6 (issuer, audience, time, nonce) over an
//! already-signature-verified claim set, so both halves are unit-testable
//! independently.
//!
//! Every failure raises [`AxiamError::id_token_invalid`] carrying one of the
//! seven stable reason codes from §12.3 rule 3
//! ([`crate::error::IdTokenFailureReason`]). Rule 7 (all-or-nothing discard)
//! is enforced by the caller (`crate::oidc::exchange`) — a token set whose ID
//! token fails here is never returned to the caller.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::AxiamError;
use crate::error::IdTokenFailureReason;

/// Maximum (and default) permitted clock skew, in seconds, for ID-token time
/// claims. CONTRACT.md §12.4 rule 5 caps this at 60s and forbids any
/// configuration above the bound.
pub const MAX_CLOCK_SKEW_SEC: u64 = 60;

/// The JOSE `alg` this SDK accepts for an ID token (CONTRACT.md §12.4
/// rule 1). Every other value — including `none` and every algorithm the
/// discovery document might additionally advertise — is rejected.
///
/// The rejection itself happens in
/// `crate::token::jwks::JwksVerifier::verify_id_token_signature`, which
/// compares the decoded header against `jsonwebtoken`'s typed
/// `Algorithm::EdDSA` and names this constant in the resulting
/// `invalid_alg` error, so the wire spelling has exactly one definition.
pub const ID_TOKEN_ALG: &str = "EdDSA";

/// Either a single audience string or a list of them — the `aud` claim may
/// be either shape per RFC 7519 §4.1.3.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Audience {
    /// A single audience value.
    One(String),
    /// Multiple audience values.
    Many(Vec<String>),
}

impl Audience {
    /// View the audience value(s) as a slice, regardless of the wire shape.
    pub fn as_slice(&self) -> Vec<&str> {
        match self {
            Audience::One(s) => vec![s.as_str()],
            Audience::Many(items) => items.iter().map(String::as_str).collect(),
        }
    }
}

/// The decoded, **already-validated** ID-token claim set carried by
/// `OidcTokenSet::id_claims` (CONTRACT.md §12.1).
///
/// Claim names are kept verbatim in their JWT/OIDC spelling (`iss`, `sub`,
/// `aud`, …) rather than converted to another naming convention: they are
/// protocol identifiers a caller cross-references against OIDC Core. Unknown
/// claims are preserved in `extra` rather than rejected — the ID token's full
/// claim set is not enumerated by `openapi.json` (CONTRACT.md §12.1).
#[derive(Debug, Clone, Deserialize)]
pub struct IdTokenClaims {
    /// Issuer — matched for exact string equality against the discovery
    /// document's `issuer` (§12.4 rule 3).
    pub iss: String,
    /// Subject — the authenticated end user's stable identifier at AXIAM.
    pub sub: String,
    /// Audience — contains the relying party's `client_id` (§12.4 rule 4).
    pub aud: Audience,
    /// Expiry time (epoch seconds).
    #[serde(default)]
    pub exp: Option<i64>,
    /// Issued-at time (epoch seconds).
    #[serde(default)]
    pub iat: Option<i64>,
    /// Not-before time (epoch seconds), when the server sends one.
    #[serde(default)]
    pub nbf: Option<i64>,
    /// The `nonce` echoed back from the authorization request (§12.4 rule 6).
    #[serde(default)]
    pub nonce: Option<String>,
    /// Authorized party — required to equal `client_id` when `aud` holds
    /// multiple audiences (§12.4 rule 4).
    #[serde(default)]
    pub azp: Option<String>,
    /// Any further claim the server sends (e.g. `email`,
    /// `preferred_username`) — preserved, never rejected (CONTRACT.md
    /// §12.1).
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}

/// What an ID token is checked against by [`check_id_token_claims`]
/// (CONTRACT.md §12.4 rules 3–6).
#[derive(Debug, Clone)]
pub struct IdTokenExpectations<'a> {
    /// The authoritative issuer — always the `issuer` value of the discovery
    /// document the token endpoint was read from, never the client base URL
    /// (§12.3 rule 6: behind a proxy the two legitimately differ).
    pub issuer: &'a str,
    /// The relying party's own `client_id`, matched against `aud`/`azp`
    /// (rule 4).
    pub client_id: &'a str,
    /// The `nonce` returned by `oidc_begin` and passed back into
    /// `oidc_exchange`. Mandatory for `oidc_exchange`. `None` for
    /// `oidc_refresh`/`login_client_credentials`, which skip rule 6 entirely
    /// (OIDC Core §12.2 does not require a `nonce` in a refresh-issued ID
    /// token).
    pub nonce: Option<&'a str>,
    /// Permitted clock skew in seconds for `exp`/`iat`/`nbf` (rule 5).
    /// Clamped to [`MAX_CLOCK_SKEW_SEC`] — the contract forbids configuring
    /// it higher.
    pub clock_skew_sec: u64,
}

/// Resolve the effective clock skew: the caller's value clamped to
/// `[0, MAX_CLOCK_SKEW_SEC]`.
pub fn resolve_clock_skew_sec(clock_skew_sec: u64) -> u64 {
    clock_skew_sec.min(MAX_CLOCK_SKEW_SEC)
}

/// Constant-time string equality, used for the `nonce` comparison §12.4
/// rule 6 requires.
pub fn constant_time_equals(a: &str, b: &str) -> bool {
    let a = a.as_bytes();
    let b = b.as_bytes();
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// §12.4 rules 3–6 — issuer, audience, time and nonce checks over an
/// already-signature-verified claim set. Returns the claims unchanged on
/// success; returns the matching [`AxiamError::id_token_invalid`] on the
/// first failure.
///
/// `now_sec` is injectable so tests can pin the clock.
pub fn check_id_token_claims(
    claims: IdTokenClaims,
    expectations: &IdTokenExpectations<'_>,
    now_sec: i64,
) -> Result<IdTokenClaims, AxiamError> {
    let skew = resolve_clock_skew_sec(expectations.clock_skew_sec) as i64;

    // Rule 3 — exact string comparison. No normalization, no trailing-slash
    // tolerance, no prefix matching.
    if claims.iss != expectations.issuer {
        return Err(AxiamError::id_token_invalid(
            IdTokenFailureReason::InvalidIssuer,
            "iss does not equal the discovery document issuer",
        ));
    }

    // Rule 4 — aud must contain our client_id; with multiple audiences an
    // azp claim must be present and equal to it.
    let audiences = claims.aud.as_slice();
    if !audiences.contains(&expectations.client_id) {
        return Err(AxiamError::id_token_invalid(
            IdTokenFailureReason::InvalidAudience,
            "aud does not contain this client_id",
        ));
    }
    if audiences.len() > 1 && claims.azp.as_deref() != Some(expectations.client_id) {
        return Err(AxiamError::id_token_invalid(
            IdTokenFailureReason::InvalidAudience,
            "aud holds multiple audiences and azp is absent or does not equal this client_id",
        ));
    }

    // Rule 5 — exp must be in the future, iat must not be in the future, nbf
    // is honored when present; all within `skew` seconds. `exp` is REQUIRED:
    // a missing exp could never satisfy "exp must be in the future", so its
    // absence is an expiry failure rather than a free pass.
    let exp = claims.exp.ok_or_else(|| {
        AxiamError::id_token_invalid(IdTokenFailureReason::TokenExpired, "exp claim is missing")
    })?;
    if exp + skew <= now_sec {
        return Err(AxiamError::id_token_invalid(
            IdTokenFailureReason::TokenExpired,
            "exp is in the past",
        ));
    }
    let iat = claims.iat.ok_or_else(|| {
        AxiamError::id_token_invalid(IdTokenFailureReason::TokenExpired, "iat claim is missing")
    })?;
    if iat - skew > now_sec {
        return Err(AxiamError::id_token_invalid(
            IdTokenFailureReason::TokenExpired,
            "iat is in the future",
        ));
    }
    if let Some(nbf) = claims.nbf
        && nbf - skew > now_sec
    {
        return Err(AxiamError::id_token_invalid(
            IdTokenFailureReason::TokenExpired,
            "nbf is in the future",
        ));
    }

    // Rule 6 — mandatory for oidc_exchange, skipped when the caller expects
    // no nonce (oidc_refresh / login_client_credentials).
    if let Some(expected_nonce) = expectations.nonce {
        match claims.nonce.as_deref() {
            Some(actual) if constant_time_equals(actual, expected_nonce) => {}
            _ => {
                return Err(AxiamError::id_token_invalid(
                    IdTokenFailureReason::NonceMismatch,
                    "nonce claim is absent or does not match the request nonce",
                ));
            }
        }
    }

    Ok(claims)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claims() -> IdTokenClaims {
        IdTokenClaims {
            iss: "https://iam.example.com".into(),
            sub: "user-1".into(),
            aud: Audience::One("axiam-rp".into()),
            exp: Some(1_800_003_600),
            iat: Some(1_800_000_000),
            nbf: None,
            nonce: Some("nonce-value".into()),
            azp: None,
            extra: BTreeMap::new(),
        }
    }

    fn expectations() -> IdTokenExpectations<'static> {
        IdTokenExpectations {
            issuer: "https://iam.example.com",
            client_id: "axiam-rp",
            nonce: Some("nonce-value"),
            clock_skew_sec: 60,
        }
    }

    const NOW: i64 = 1_800_000_000;

    #[test]
    fn accepts_a_fully_valid_claim_set() {
        assert!(check_id_token_claims(claims(), &expectations(), NOW).is_ok());
    }

    #[test]
    fn rule3_rejects_issuer_mismatch_including_trailing_slash() {
        let mut c = claims();
        c.iss = "https://iam.example.com/".into();
        let err = check_id_token_claims(c, &expectations(), NOW).unwrap_err();
        assert_eq!(
            err.id_token_failure_reason(),
            Some(IdTokenFailureReason::InvalidIssuer)
        );
    }

    #[test]
    fn rule4_accepts_array_audience_containing_client_id() {
        let mut c = claims();
        c.aud = Audience::Many(vec!["axiam-rp".into()]);
        assert!(check_id_token_claims(c, &expectations(), NOW).is_ok());
    }

    #[test]
    fn rule4_rejects_wrong_audience() {
        let mut c = claims();
        c.aud = Audience::One("other".into());
        let err = check_id_token_claims(c, &expectations(), NOW).unwrap_err();
        assert_eq!(
            err.id_token_failure_reason(),
            Some(IdTokenFailureReason::InvalidAudience)
        );
    }

    #[test]
    fn rule4_multiple_audiences_require_matching_azp() {
        let mut c = claims();
        c.aud = Audience::Many(vec!["axiam-rp".into(), "other-rp".into()]);
        let err = check_id_token_claims(c.clone(), &expectations(), NOW).unwrap_err();
        assert_eq!(
            err.id_token_failure_reason(),
            Some(IdTokenFailureReason::InvalidAudience)
        );

        c.azp = Some("axiam-rp".into());
        assert!(check_id_token_claims(c, &expectations(), NOW).is_ok());
    }

    #[test]
    fn rule5_missing_exp_or_iat_is_token_expired() {
        let mut c = claims();
        c.exp = None;
        let err = check_id_token_claims(c, &expectations(), NOW).unwrap_err();
        assert_eq!(
            err.id_token_failure_reason(),
            Some(IdTokenFailureReason::TokenExpired)
        );

        let mut c = claims();
        c.iat = None;
        let err = check_id_token_claims(c, &expectations(), NOW).unwrap_err();
        assert_eq!(
            err.id_token_failure_reason(),
            Some(IdTokenFailureReason::TokenExpired)
        );
    }

    #[test]
    fn rule5_allows_up_to_60s_skew_on_exp_but_no_more() {
        let mut c = claims();
        c.exp = Some(NOW - 30);
        assert!(check_id_token_claims(c, &expectations(), NOW).is_ok());

        let mut c = claims();
        c.exp = Some(NOW - 61);
        let err = check_id_token_claims(c, &expectations(), NOW).unwrap_err();
        assert_eq!(
            err.id_token_failure_reason(),
            Some(IdTokenFailureReason::TokenExpired)
        );
    }

    #[test]
    fn rule5_honours_nbf_when_present() {
        let mut c = claims();
        c.nbf = Some(NOW + 30);
        assert!(check_id_token_claims(c, &expectations(), NOW).is_ok());

        let mut c = claims();
        c.nbf = Some(NOW + 600);
        let err = check_id_token_claims(c, &expectations(), NOW).unwrap_err();
        assert_eq!(
            err.id_token_failure_reason(),
            Some(IdTokenFailureReason::TokenExpired)
        );
    }

    #[test]
    fn rule5_a_narrowed_skew_is_respected() {
        let mut c = claims();
        c.exp = Some(NOW - 30);
        let mut exp = expectations();
        exp.clock_skew_sec = 5;
        let err = check_id_token_claims(c, &exp, NOW).unwrap_err();
        assert_eq!(
            err.id_token_failure_reason(),
            Some(IdTokenFailureReason::TokenExpired)
        );
    }

    #[test]
    fn resolve_clock_skew_clamps_above_the_maximum() {
        assert_eq!(resolve_clock_skew_sec(3600), MAX_CLOCK_SKEW_SEC);
        assert_eq!(resolve_clock_skew_sec(5), 5);
    }

    #[test]
    fn rule6_rejects_mismatched_or_missing_nonce() {
        let mut c = claims();
        c.nonce = Some("other".into());
        let err = check_id_token_claims(c, &expectations(), NOW).unwrap_err();
        assert_eq!(
            err.id_token_failure_reason(),
            Some(IdTokenFailureReason::NonceMismatch)
        );

        let mut c = claims();
        c.nonce = None;
        let err = check_id_token_claims(c, &expectations(), NOW).unwrap_err();
        assert_eq!(
            err.id_token_failure_reason(),
            Some(IdTokenFailureReason::NonceMismatch)
        );
    }

    #[test]
    fn rule6_is_skipped_when_no_nonce_is_expected() {
        let mut exp = expectations();
        exp.nonce = None;
        let mut c = claims();
        c.nonce = None;
        assert!(check_id_token_claims(c.clone(), &exp, NOW).is_ok());
        c.nonce = Some("anything".into());
        assert!(check_id_token_claims(c, &exp, NOW).is_ok());
    }

    #[test]
    fn never_embeds_the_expected_or_actual_nonce_in_the_error_message() {
        let mut c = claims();
        c.nonce = Some("wrong-value".into());
        let err = check_id_token_claims(c, &expectations(), NOW).unwrap_err();
        let message = err.to_string();
        assert!(!message.contains("nonce-value"));
        assert!(!message.contains("wrong-value"));
    }

    #[test]
    fn preserves_unknown_claims_in_extra() {
        let json = serde_json::json!({
            "iss": "https://iam.example.com",
            "sub": "user-1",
            "aud": "axiam-rp",
            "exp": 1_800_003_600i64,
            "iat": 1_800_000_000i64,
            "nonce": "n",
            "email": "user@example.com",
            "custom_org_tier": "gold",
        });
        let claims: IdTokenClaims = serde_json::from_value(json).expect("deserialize");
        assert_eq!(
            claims.extra.get("email").and_then(|v| v.as_str()),
            Some("user@example.com")
        );
        assert_eq!(
            claims.extra.get("custom_org_tier").and_then(|v| v.as_str()),
            Some("gold")
        );
    }
}
