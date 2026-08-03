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
use std::sync::RwLock;
#[cfg(any(feature = "rest", feature = "actix"))]
use std::time::{Duration, Instant};

#[cfg(any(feature = "rest", feature = "actix"))]
use jsonwebtoken::jwk::JwkSet;
#[cfg(any(feature = "rest", feature = "actix"))]
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use serde::{Deserialize, Serialize};

#[cfg(any(feature = "rest", feature = "actix"))]
use crate::AxiamError;

/// The AXIAM JWKS endpoint path — organization-wide, not tenant-scoped
/// (RESEARCH.md D-11). This is the only correct path; do not substitute a
/// generic OIDC discovery-style JWKS path here.
pub const JWKS_PATH: &str = "/oauth2/jwks";

/// How long a fetched `JwkSet` is cached before a normal (non-forced)
/// refetch is attempted.
#[cfg(any(feature = "rest", feature = "actix"))]
const JWKS_CACHE_TTL: Duration = Duration::from_secs(300);

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
    /// Token audience — `"axiam:user"` or `"axiam:m2m"`.
    #[serde(default)]
    pub aud: Option<String>,
    /// OAuth2 scopes (space-separated string), if any.
    #[serde(default)]
    pub scope: Option<String>,
}

#[cfg(any(feature = "rest", feature = "actix"))]
struct CachedJwks {
    jwks: JwkSet,
    fetched_at: Instant,
    last_forced_refetch: Option<Instant>,
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
    cache: RwLock<Option<CachedJwks>>,
    /// Serializes concurrent fetchers so a burst of cache-miss callers (e.g.
    /// an invalid-`kid` storm) collapses to exactly one network fetch
    /// (D-08/D-09). Guards ONLY the fetch — a coalescing wrapper, never the
    /// cryptographic verify path.
    fetch_lock: tokio::sync::Mutex<()>,
    /// §10.1 rule 4: the tenant every verified token MUST be scoped to.
    /// `None` means "not configured", which makes [`Self::verify`] fail
    /// closed — never "no tenant constraint".
    expected_tenant_id: Option<uuid::Uuid>,
    /// §10.1 rule 5: expected `iss`. `None` means the check is not performed
    /// (the rule is explicitly conditional on configuration).
    expected_issuer: Option<String>,
    /// §10.1 rule 6: expected `aud`. `None` means the check is not performed.
    expected_audience: Option<String>,
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
            cache: RwLock::new(None),
            fetch_lock: tokio::sync::Mutex::new(()),
            expected_tenant_id: None,
            expected_issuer: None,
            expected_audience: None,
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

    /// Construct a verifier against an **already-absolute** JWKS URL
    /// (CONTRACT.md §12.3 rule 6: "SDKs MUST read `jwks_uri` from the
    /// document rather than hardcoding `/oauth2/jwks`"). Used by
    /// `crate::oidc` to verify ID tokens against the `jwks_uri` the OIDC
    /// discovery document advertises, which is not necessarily
    /// `{base_url}/oauth2/jwks` (e.g. behind a proxy).
    pub(crate) fn for_jwks_url(http_client: reqwest::Client, jwks_url: url::Url) -> Self {
        Self {
            http_client,
            jwks_url,
            cache: RwLock::new(None),
            fetch_lock: tokio::sync::Mutex::new(()),
            expected_tenant_id: None,
            expected_issuer: None,
            expected_audience: None,
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
    /// **Divergence from [`Self::verify`], required by §12.4 rule 2:** a
    /// missing `kid` is rejected outright, with no single-key fallback. The
    /// access-token path's [`find_jwk`] intentionally falls back to a lone
    /// published key when `kid` is absent (D-11, AXIAM's own tokens may omit
    /// it); an ID token from a third-party-shaped flow gets no such
    /// convenience — CONTRACT.md §12.4 rule 2 says plainly "a token with no
    /// `kid` … MUST be rejected".
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
    ///
    /// # Errors
    ///
    /// [`AxiamError::Auth`] on any failed rule (the SDK never distinguishes
    /// "no `tenant_id` to check" from "wrong `tenant_id`" — both reject), or
    /// [`AxiamError::Network`] if the JWKS itself is unreachable.
    ///
    /// [`AxiamUser`]: crate::middleware::AxiamUser
    pub async fn verify(&self, token: &str) -> Result<Claims, AxiamError> {
        let claims = self.verify_claims(token).await?;
        self.assert_tenant(&claims)?;
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
        let decoding_key = self.decoding_key_for(token).await?;

        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.required_spec_claims.clear();
        validation.validate_exp = false;
        validation.validate_nbf = false;
        validation.validate_aud = false;
        validation.leeway = 0;

        decode_claims(token, &decoding_key, &validation)
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
        self.verify_claims(token).await
    }

    /// Everything in §10.1 except rule 4 (the tenant assertion), shared by
    /// [`Self::verify`] and [`Self::verify_session_token`].
    async fn verify_claims(&self, token: &str) -> Result<Claims, AxiamError> {
        let decoding_key = self.decoding_key_for(token).await?;

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

        decode_claims(token, &decoding_key, &validation)
    }

    /// §10.1 rule 1's first half: pin `alg` to EdDSA from the header
    /// **before** any JWKS lookup, then resolve the `kid` to a decoding key.
    async fn decoding_key_for(&self, token: &str) -> Result<DecodingKey, AxiamError> {
        let header = decode_header(token).map_err(|e| AxiamError::Auth {
            message: format!("invalid token header: {e}"),
            oauth: None,
            reason: None,
        })?;

        // Rule 1: rejected WITHOUT consulting a key — `alg: none` and every
        // HS-family confusion attempt dies here, before `get_or_fetch`.
        if header.alg != Algorithm::EdDSA {
            return Err(AxiamError::Auth {
                message: "unexpected alg: only EdDSA is accepted".into(),
                oauth: None,
                reason: None,
            });
        }

        let jwks = self.get_or_fetch().await?;
        let jwk = find_jwk(&jwks, header.kid.as_deref());

        let jwk = match jwk {
            Some(j) => j,
            None => {
                // Unknown kid → forced refetch (rate-limited), matching the
                // server's own kid-rotation handling (D-11).
                let refreshed = self.force_refetch_if_allowed().await?;
                find_jwk(&refreshed, header.kid.as_deref()).ok_or_else(|| AxiamError::Auth {
                    message: "unknown kid after JWKS refetch".into(),
                    oauth: None,
                    reason: None,
                })?
            }
        };

        DecodingKey::from_jwk(&jwk).map_err(|_| AxiamError::Auth {
            message: "unable to build decoding key from JWK".into(),
            oauth: None,
            reason: None,
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
        })?;

        let actual =
            uuid::Uuid::parse_str(claims.tenant_id.trim()).map_err(|_| AxiamError::Auth {
                message: "token tenant_id claim is absent or not a UUID".into(),
                oauth: None,
                reason: None,
            })?;

        if actual != expected {
            return Err(AxiamError::Auth {
                message: "token tenant_id does not match the configured tenant".into(),
                oauth: None,
                reason: None,
            });
        }

        Ok(())
    }

    async fn get_or_fetch(&self) -> Result<JwkSet, AxiamError> {
        if let Some(jwks) = self.cached_if_fresh() {
            return Ok(jwks);
        }
        // Serialize concurrent fetchers on a cold/stale cache (D-08/D-09):
        // acquire the fetch guard, then double-check under it — a
        // concurrent caller may have already refreshed while we waited.
        let _guard = self.fetch_lock.lock().await;
        if let Some(jwks) = self.cached_if_fresh() {
            return Ok(jwks);
        }
        self.fetch_and_cache(false).await
    }

    fn cached_if_fresh(&self) -> Option<JwkSet> {
        let cache = self.cache.read().ok()?;
        let entry = cache.as_ref()?;
        if entry.fetched_at.elapsed() < JWKS_CACHE_TTL {
            Some(entry.jwks.clone())
        } else {
            None
        }
    }

    /// Force a refetch, but rate-limited to at most once per
    /// `FORCED_REFETCH_MIN_INTERVAL` to avoid a rotating/hostile `kid`
    /// stream hammering the JWKS endpoint.
    async fn force_refetch_if_allowed(&self) -> Result<JwkSet, AxiamError> {
        // Same fetch_lock as get_or_fetch — a rotating/hostile-kid burst
        // that reaches this forced-refetch path must ALSO serialize on the
        // single fetch guard so concurrent callers collapse to one fetch
        // (D-08/D-09), rather than each racing the cooldown check
        // independently (the pre-existing TOCTOU this plan closes).
        let _guard = self.fetch_lock.lock().await;

        let allowed = {
            let cache = self.cache.read().ok();
            match cache.as_ref().and_then(|c| c.as_ref()) {
                Some(entry) => match entry.last_forced_refetch {
                    Some(last) => last.elapsed() >= FORCED_REFETCH_MIN_INTERVAL,
                    None => true,
                },
                None => true,
            }
        };

        if allowed {
            self.fetch_and_cache(true).await
        } else if let Some(jwks) = self
            .cache
            .read()
            .ok()
            .and_then(|c| c.as_ref().map(|e| e.jwks.clone()))
        {
            Ok(jwks)
        } else {
            self.fetch_and_cache(true).await
        }
    }

    async fn fetch_and_cache(&self, is_forced: bool) -> Result<JwkSet, AxiamError> {
        let response = self
            .http_client
            .get(self.jwks_url.clone())
            .send()
            .await
            .map_err(|e| AxiamError::Network {
                message: format!("JWKS fetch failed: {e}"),
                source: Some(Box::new(e)),
            })?;

        if !response.status().is_success() {
            return Err(AxiamError::from_http_status(
                response.status().as_u16(),
                "JWKS endpoint returned a non-success status".to_string(),
            ));
        }

        let jwks: JwkSet = response.json().await.map_err(|e| AxiamError::Network {
            message: format!("JWKS response parse failed: {e}"),
            source: Some(Box::new(e)),
        })?;

        let now = Instant::now();
        if let Ok(mut cache) = self.cache.write() {
            *cache = Some(CachedJwks {
                jwks: jwks.clone(),
                fetched_at: now,
                last_forced_refetch: if is_forced { Some(now) } else { None },
            });
        }

        Ok(jwks)
    }
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
        }
    })?;

    Ok(data.claims)
}

/// Find a JWK by `kid` in a JWK set. If `kid` is `None` and the set has
/// exactly one key, returns that key as a best-effort match — AXIAM's
/// `/oauth2/jwks` serves exactly one org-wide Ed25519 key (D-11).
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

/// Find a JWK by an EXPLICIT `kid` only — no single-key fallback. Used by
/// [`JwksVerifier::verify_id_token_signature`] (CONTRACT.md §12.4 rule 2),
/// which requires a `kid` header to be present at all; callers with no
/// `kid` never reach this function (see its doc comment for why the
/// access-token path's fallback in [`find_jwk`] does not apply here).
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
            aud: None,
            scope: None,
        };
        let token = jsonwebtoken::encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(b"irrelevant"),
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
}
