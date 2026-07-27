//! PKCE + CSPRNG primitives and `oidc_begin` (CONTRACT.md §12.1
//! "`oidc_begin` inputs and construction", RFC 7636).
//!
//! This module is deliberately tiny, pure and synchronous: `oidc_begin`
//! performs **no network I/O** — every value here is derived locally from a
//! CSPRNG. **S256 only.** `plain` is not implemented, not reachable, and not
//! configurable: there is no code path in this SDK that can emit
//! `code_challenge_method=plain`.
//!
//! No new runtime dependency: `getrandom` and `base64` are already
//! unconditional transitive dependencies of this crate whenever `rest` is
//! enabled (see the `Cargo.toml` `rest` feature comment); `sha2` was already
//! an optional direct dependency, now also wired to `rest`.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

use crate::AxiamError;
use crate::Sensitive;
use crate::client::AxiamClient;

use super::discovery::OidcConfiguration;

/// The only PKCE code-challenge method this SDK emits (RFC 7636 §4.2,
/// CONTRACT.md §12.1 rule 3). `plain` is intentionally absent.
pub const CODE_CHALLENGE_METHOD_S256: &str = "S256";

/// Entropy, in bytes, of a generated `state`/`nonce`/`code_verifier`.
///
/// §12.1 rule 1 requires at least 16 bytes (128 bits) and RECOMMENDS 32;
/// rule 2 RECOMMENDS 32 bytes for the verifier, which base64url-encodes to
/// exactly 43 characters — the minimum RFC 7636 §4.1 length, drawn only from
/// the unreserved set `[A-Za-z0-9-._~]`.
pub const CSPRNG_BYTES: usize = 32;

/// The `openid` scope every authorization request must carry (§12.1 rule 4).
const OPENID_SCOPE: &str = "openid";

/// The eight query parameters `oidc_begin` owns (§12.1 rule 5). Caller-
/// supplied `extra_params` may add to the authorization request but never
/// override these.
const RESERVED_AUTHORIZE_PARAMS: &[&str] = &[
    "response_type",
    "client_id",
    "redirect_uri",
    "scope",
    "state",
    "nonce",
    "code_challenge",
    "code_challenge_method",
];

/// Generate a URL-safe random token: `bytes` CSPRNG bytes, base64url-encoded
/// **without** padding (RFC 4648 §5).
///
/// Used for both `state` and `nonce`, which CONTRACT.md §12.3 rule 2 classes
/// as **non-secret**: they are returned as plain strings, are echoed through
/// the browser's address bar by construction, and are safe to log.
pub fn random_url_safe_token(bytes: usize) -> Result<String, AxiamError> {
    let mut buf = vec![0u8; bytes];
    getrandom::fill(&mut buf).map_err(|e| AxiamError::Network {
        message: format!("failed to generate CSPRNG bytes: {e}"),
        source: None,
    })?;
    Ok(URL_SAFE_NO_PAD.encode(buf))
}

/// Generate a fresh PKCE `code_verifier` (RFC 7636 §4.1): 32 CSPRNG bytes
/// base64url-encoded without padding, i.e. 43 characters from the unreserved
/// set `[A-Za-z0-9-._~]`.
///
/// Returned already wrapped in [`Sensitive`] — §12.5 makes the verifier
/// secret **for its whole lifetime**, including while it sits in the
/// [`AuthorizationRequest`] handed back to the caller and in any
/// `OidcStateStore` entry.
pub fn generate_code_verifier() -> Result<Sensitive<String>, AxiamError> {
    Ok(Sensitive::new(random_url_safe_token(CSPRNG_BYTES)?))
}

/// Derive the PKCE `code_challenge` from a verifier:
/// `BASE64URL-ENCODE(SHA256(ASCII(code_verifier)))`, unpadded (RFC 7636
/// §4.2, CONTRACT.md §12.1 rule 3).
///
/// The verifier is hashed as ASCII exactly as the RFC specifies. Verified
/// against the RFC 7636 Appendix B test vector in `tests/oidc_pkce_test.rs`.
/// The challenge is a one-way digest and is **not** secret — it travels in
/// the authorization URL — so it is returned as a plain string.
pub fn compute_code_challenge(code_verifier: &str) -> String {
    let digest = Sha256::digest(code_verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(digest)
}

/// The result of `oidc_begin` — everything the caller needs to start an
/// authorization-code + PKCE login (CONTRACT.md §12.1).
///
/// **The caller owns this state** (§12.3 rule 1). The SDK stores nothing: it
/// keeps no copy of `state`, `nonce` or `code_verifier` in process-global
/// state or any implicit cache. Persist all three in your own session (or in
/// an [`crate::oidc::state::OidcStateStore`]), redirect to [`Self::url`], and
/// pass `nonce` + `code_verifier` back into `oidc_exchange` when the code
/// arrives.
#[derive(Debug)]
pub struct AuthorizationRequest {
    /// The fully-built authorization URL to redirect the user agent to.
    pub url: String,
    /// CSPRNG CSRF value (≥128 bits, base64url unpadded) to compare against
    /// the `state` the IdP returns. Not a secret (§12.3 rule 2).
    pub state: String,
    /// CSPRNG replay-protection value (≥128 bits) that must equal the ID
    /// token's `nonce` claim. Not a secret (§12.3 rule 2).
    pub nonce: String,
    /// The PKCE verifier, secret for its whole lifetime (§12.5). Pass it
    /// back into `oidc_exchange`.
    pub code_verifier: Sensitive<String>,
}

/// Arguments to `oidc_begin` (pure local computation — no network I/O).
#[derive(Debug, Clone, Default)]
pub struct OidcBeginParams {
    /// The relying party's redirect URI, echoed back into `oidc_exchange`
    /// unchanged.
    pub redirect_uri: String,
    /// Requested scope, space-separated. `openid` is added automatically
    /// when absent (§12.1 rule 4). Defaults to `openid`.
    pub scope: Option<String>,
    /// Extra authorization-request parameters (e.g. `prompt`, `login_hint`,
    /// `ui_locales`). §12.1 rule 5 allows caller-supplied additions but
    /// forbids the SDK from adding any of its own beyond the mandated eight,
    /// so attempting to override one of those eight is a client-side error.
    pub extra_params: Vec<(String, String)>,
}

impl OidcBeginParams {
    /// Build params with just a redirect URI and the default `openid` scope.
    pub fn new(redirect_uri: impl Into<String>) -> Self {
        Self {
            redirect_uri: redirect_uri.into(),
            scope: None,
            extra_params: Vec::new(),
        }
    }

    /// Set the requested scope (space-separated). `openid` is added
    /// automatically if missing.
    pub fn with_scope(mut self, scope: impl Into<String>) -> Self {
        self.scope = Some(scope.into());
        self
    }

    /// Add an extra authorization-request query parameter. Overriding one of
    /// the eight SDK-owned parameters is rejected by `oidc_begin`.
    pub fn with_extra_param(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.extra_params.push((key.into(), value.into()));
        self
    }
}

/// Normalize the requested scope to a space-separated string that always
/// contains `openid` (§12.1 rule 4). Duplicate entries are collapsed.
fn normalize_scope(scope: Option<&str>) -> String {
    let mut seen = BTreeSet::new();
    let mut ordered = Vec::new();
    ordered.push(OPENID_SCOPE.to_string());
    seen.insert(OPENID_SCOPE.to_string());
    for token in scope.unwrap_or_default().split_whitespace() {
        if seen.insert(token.to_string()) {
            ordered.push(token.to_string());
        }
    }
    ordered.join(" ")
}

impl AxiamClient {
    /// `oidc_begin` (CONTRACT.md §12.1) — build an authorization request.
    /// **Pure local computation, no network I/O.**
    ///
    /// Generates a 32-byte CSPRNG `state` and `nonce` (base64url, unpadded)
    /// and a fresh PKCE verifier/challenge pair using **S256 only**. The URL
    /// is built from `configuration.authorization_endpoint` with exactly the
    /// eight parameters §12.1 rule 5 mandates, plus any `extra_params` the
    /// caller adds.
    ///
    /// Nothing is stored: persist the returned `state`, `nonce` and
    /// `code_verifier` yourself (§12.3 rule 1).
    ///
    /// # Errors
    /// Returns `AxiamError::Network` (a client-side, no-wire-call
    /// programming error) when `extra_params` tries to override one of the
    /// eight SDK-owned parameters, or when the discovery document's
    /// `authorization_endpoint` does not parse as a URL.
    pub fn oidc_begin(
        &self,
        configuration: &OidcConfiguration,
        params: OidcBeginParams,
    ) -> Result<AuthorizationRequest, AxiamError> {
        for (key, _) in &params.extra_params {
            if RESERVED_AUTHORIZE_PARAMS.contains(&key.as_str()) {
                return Err(AxiamError::Network {
                    message: format!(
                        "oidc_begin: extra_params may not override the SDK-owned authorization parameter \"{key}\" (CONTRACT.md §12.1 rule 5)"
                    ),
                    source: None,
                });
            }
        }

        let state = random_url_safe_token(CSPRNG_BYTES)?;
        let nonce = random_url_safe_token(CSPRNG_BYTES)?;
        let code_verifier = generate_code_verifier()?;
        let code_challenge = compute_code_challenge(code_verifier.expose());
        let scope = normalize_scope(params.scope.as_deref());

        let mut url = url::Url::parse(&configuration.authorization_endpoint).map_err(|e| {
            AxiamError::Network {
                message: format!("invalid authorization_endpoint in discovery document: {e}"),
                source: None,
            }
        })?;

        {
            let mut query = url.query_pairs_mut();
            for (key, value) in &params.extra_params {
                query.append_pair(key, value);
            }
            query.append_pair("response_type", "code");
            query.append_pair("client_id", self.oidc_client_id_or_err()?);
            query.append_pair("redirect_uri", &params.redirect_uri);
            query.append_pair("scope", &scope);
            query.append_pair("state", &state);
            query.append_pair("nonce", &nonce);
            query.append_pair("code_challenge", &code_challenge);
            query.append_pair("code_challenge_method", CODE_CHALLENGE_METHOD_S256);
        }

        Ok(AuthorizationRequest {
            url: url.to_string(),
            state,
            nonce,
            code_verifier,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc7636_appendix_b_test_vector() {
        // RFC 7636 Appendix B.
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let expected_challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        assert_eq!(compute_code_challenge(verifier), expected_challenge);
    }

    #[test]
    fn random_tokens_are_at_least_128_bits_and_unique() {
        let a = random_url_safe_token(CSPRNG_BYTES).expect("csprng token");
        let b = random_url_safe_token(CSPRNG_BYTES).expect("csprng token");
        assert_ne!(a, b, "two draws must not collide");
        // base64url-no-pad of 32 bytes is 43 chars; no '=' padding chars.
        assert_eq!(a.len(), 43);
        assert!(!a.contains('='));
    }

    #[test]
    fn code_verifier_is_43_chars_from_the_unreserved_set() {
        let verifier = generate_code_verifier().expect("verifier");
        let raw = verifier.expose();
        assert_eq!(raw.len(), 43);
        assert!(
            raw.chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_' | '~'))
        );
    }

    #[test]
    fn normalize_scope_adds_openid_and_dedupes() {
        assert_eq!(normalize_scope(None), "openid");
        assert_eq!(normalize_scope(Some("profile")), "openid profile");
        assert_eq!(
            normalize_scope(Some("openid openid profile")),
            "openid profile"
        );
    }
}
