//! Actix-Web `FromRequest` extractor `AxiamUser` (CONTRACT.md §10).
//!
//! Mirrors the server's JWT auth extractor (`extractors/auth.rs` under the
//! REST API crate) — **mirror only, do not import** (that file depends on
//! server-only auth/core/db crates that this SDK may not depend on; see
//! 16-PATTERNS.md for the full domain-boundary rule).
//!
//! ## §10 contract steps implemented here
//! 1. Extract the session from the `axiam_access` cookie, falling back to
//!    `Authorization: Bearer <token>` (§10.1, cookie-then-header).
//! 2. Verify the token locally against the cached JWKS from 16-02's
//!    [`crate::token::JwksVerifier`] via `app_data` — no AXIAM-server
//!    round-trip (§10.2).
//!
//!    This is the **complete §10.1 minimum local-verification set**, applied
//!    by [`crate::token::JwksVerifier::verify`]: EdDSA `alg` pinned before
//!    key lookup, a required numeric `exp`, `nbf` honoured when present,
//!    `tenant_id` asserted against the verifier's configured tenant, and
//!    `iss`/`aud` checked when configured. The registered verifier therefore
//!    **must** be built with
//!    [`expect_tenant_id`](crate::token::JwksVerifier::expect_tenant_id):
//!    the `/oauth2/jwks` trust anchor is organization-wide, so without it
//!    every token — including one minted for a sibling tenant — is rejected
//!    (fail closed, §10.1 rule 4). The §11 `require_auth`/`require_access`/
//!    `require_role` macros inject this same extractor, so they inherit the
//!    identical set with no separate verification path of their own.
//! 3. Build and inject `AxiamUser { user_id, tenant_id, roles }` from the
//!    verified claims (§10.3).
//! 4. Map `AuthError` -> HTTP 401 and `AuthzError` -> HTTP 403 with a
//!    standardized JSON error body (§10 closing requirement), via
//!    [`AxiamExtractorError`]'s `actix_web::ResponseError` impl.
//!
//! The verified result is never cached beyond the token's own `exp` — the
//! [`crate::token::JwksVerifier`] re-checks `exp` on every call, so no
//! additional TTL bookkeeping is needed here (§10 "MUST NOT cache session
//! verification results longer than the token's remaining TTL").
//!
//! ## CSRF (cookie double-submit, CONTRACT.md §3)
//!
//! `Authorization: Bearer` requests are CSRF-immune by construction — a
//! cross-site attacker cannot set arbitrary request headers. The
//! `axiam_access` cookie is not: in a same-site deployment the browser
//! attaches it automatically to a cross-site form POST, so trusting a
//! cookie-sourced credential for a state-changing request without further
//! checks is a classic CSRF hole.
//!
//! When the credential in `extract_token` was sourced from the
//! `axiam_access` COOKIE (not the `Authorization` header) and the request
//! method is state-changing (anything other than GET/HEAD/OPTIONS), this
//! extractor additionally requires the `X-CSRF-Token` request header to be
//! present and equal, in constant time, to the `axiam_csrf` cookie value
//! (see `csrf_valid`), rejecting with 403 on mismatch/absence — token
//! verification is never attempted in that case. In any same-site
//! deployment where `axiam_access` reaches this app, the non-`HttpOnly`
//! `axiam_csrf` cookie does too, so this mirrors, locally, the same
//! double-submit check the AXIAM server performs on its own endpoints (§3;
//! see also `CONTRACT.md` §3 and the equivalent check in
//! `AxiamAuthenticationFilter` on the Java SDK).

use std::future::Future;
use std::pin::Pin;

use actix_web::http::Method;
use actix_web::{HttpRequest, HttpResponse, dev::Payload, web};
use serde::Serialize;
use subtle::ConstantTimeEq;
use uuid::Uuid;

use crate::AxiamError;
use crate::token::JwksVerifier;

/// Name of the (non-`HttpOnly`) CSRF cookie set by AXIAM alongside
/// `axiam_access` (CONTRACT.md §3) — reuses the same public constant the
/// outbound client side uses ([`crate::token::manager::COOKIE_CSRF`]) so
/// the cookie name lives in exactly one place.
const CSRF_COOKIE_NAME: &str = crate::token::manager::COOKIE_CSRF;
/// Name of the request header carrying the double-submit CSRF token.
const CSRF_HEADER_NAME: &str = "X-CSRF-Token";

/// Authenticated identity injected by the [`AxiamUser`] extractor.
///
/// At minimum carries `user_id`, `tenant_id`, and `roles` per CONTRACT.md
/// §10's closing "Interface contract" clause.
#[derive(Debug, Clone)]
pub struct AxiamUser {
    /// Subject (`sub` claim) of the verified access token.
    pub user_id: Uuid,
    /// Tenant the access token is scoped to.
    pub tenant_id: Uuid,
    /// Derived from the verified access token's `scope` claim (space-separated
    /// OAuth2 scopes) — AXIAM's `AccessTokenClaims` has no dedicated `roles`
    /// claim (confirmed against `crates/axiam-auth/src/token.rs`), so `scope`
    /// is the closest available authorization-relevant claim to surface here.
    /// Empty when the token carries no `scope` claim.
    pub roles: Vec<String>,
}

/// The SDK's extractor-local error type, mapping to the standardized JSON
/// error body + HTTP status per CONTRACT.md §10's closing requirement
/// (`AuthError` -> 401, `AuthzError` -> 403).
///
/// Also carries the CONTRACT.md §28.4 `WWW-Authenticate` challenge value to
/// attach to this failure's response, precomputed by
/// [`crate::token::JwksVerifier::with_resource_metadata_url`] and threaded
/// through at construction — `error_response`'s `&self` has no access to the
/// original request, so the value must travel with the error rather than be
/// computed while rendering it. `None` whenever §28 is off, or (§28.5 rule
/// 5) this particular failure is one no challenge is ever attached to (the
/// §3 CSRF refusal).
#[derive(Debug)]
pub struct AxiamExtractorError {
    error: AxiamError,
    challenge: Option<String>,
}

impl From<AxiamError> for AxiamExtractorError {
    fn from(err: AxiamError) -> Self {
        Self {
            error: err,
            challenge: None,
        }
    }
}

impl std::fmt::Display for AxiamExtractorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Delegate to the inner AxiamError's redacting Display — never emits
        // a raw token value (§7, §10 "standardized JSON error body").
        write!(f, "{}", self.error)
    }
}

#[derive(Serialize)]
struct ErrorBody {
    error: String,
    message: String,
}

impl actix_web::ResponseError for AxiamExtractorError {
    fn status_code(&self) -> actix_web::http::StatusCode {
        match &self.error {
            AxiamError::Auth { .. } => actix_web::http::StatusCode::UNAUTHORIZED,
            AxiamError::Authz { .. } => actix_web::http::StatusCode::FORBIDDEN,
            AxiamError::Network { .. } => actix_web::http::StatusCode::UNAUTHORIZED,
        }
    }

    fn error_response(&self) -> HttpResponse {
        let (error, message) = match &self.error {
            AxiamError::Auth { message, .. } => ("authentication_failed", message.clone()),
            AxiamError::Authz { message, .. } => ("authorization_denied", message.clone()),
            AxiamError::Network { message, .. } => ("authentication_failed", message.clone()),
        };
        let mut builder = HttpResponse::build(self.status_code());
        if let Some(challenge) = &self.challenge {
            // §28.4/§28.5 rule 4: tell the caller where to discover the
            // authorization server. Additive — the JSON body below is the
            // unchanged §10 shape, so a client that does not speak §28 sees
            // exactly the 401 it saw before.
            builder.insert_header((
                actix_web::http::header::WWW_AUTHENTICATE,
                challenge.as_str(),
            ));
        }
        builder.json(ErrorBody {
            error: error.into(),
            message,
        })
    }
}

impl AxiamExtractorError {
    /// The wrapped [`AxiamError`] this failure carries.
    pub fn error(&self) -> &AxiamError {
        &self.error
    }

    fn auth(message: impl Into<String>, challenge: Option<String>) -> Self {
        Self {
            error: AxiamError::Auth {
                message: message.into(),
                oauth: None,
                reason: None,
            },
            challenge,
        }
    }

    fn missing_credentials(challenge: Option<String>) -> Self {
        Self::auth("missing authentication credentials", challenge)
    }

    fn invalid_scheme(challenge: Option<String>) -> Self {
        Self::auth("invalid Authorization scheme, expected Bearer", challenge)
    }

    fn misconfigured(challenge: Option<String>) -> Self {
        Self::auth(
            "missing JwksVerifier app_data — extractor misconfigured",
            challenge,
        )
    }

    fn invalid_claim(name: &str, challenge: Option<String>) -> Self {
        Self::auth(format!("invalid {name} claim"), challenge)
    }

    /// CSRF double-submit check failed (§3): a cookie-sourced credential on
    /// a state-changing request with a missing or mismatched
    /// `X-CSRF-Token` header. Mapped to `AxiamError::Authz` so it surfaces
    /// as HTTP 403 with the same `"authorization_denied"` standardized
    /// error body shape used elsewhere in this extractor — token
    /// verification is never reached in this case.
    ///
    /// Carries no §28 challenge: CONTRACT.md §28.5 rule 5 lists a CSRF
    /// refusal among the 403s that gain no `WWW-Authenticate` header.
    fn csrf_validation_failed() -> Self {
        Self {
            error: AxiamError::Authz {
                kind: crate::error::AuthzKind::Denied,
                message: "CSRF validation failed: missing or mismatched X-CSRF-Token header".into(),
                action: None,
                resource_id: None,
            },
            challenge: None,
        }
    }
}

/// True for any HTTP method that mutates state on the resource server —
/// i.e. everything except the safe methods GET, HEAD, and OPTIONS. Only
/// state-changing requests are subject to the CSRF double-submit check
/// (§3): a cross-site GET can be triggered by an `<img>`/`<a>` tag too, but
/// it must not itself cause a side effect, so CSRF protection targets the
/// methods that can.
fn is_state_changing(method: &Method) -> bool {
    !matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS)
}

/// CSRF double-submit check (§3): the `X-CSRF-Token` request header must be
/// present and equal, in constant time, to the `axiam_csrf` cookie value.
///
/// Uses `subtle::ConstantTimeEq` rather than `==` so the comparison time
/// does not leak how many leading bytes of a guessed token matched — the
/// same rationale as the AMQP HMAC verification in
/// `src/amqp/hmac.rs::verify_payload` (which gets constant-time comparison
/// for free from `hmac::Mac::verify_slice`). This is a plain string
/// compare, not a keyed MAC, so there is no `Mac` type to lean on here.
/// `[u8]::ct_eq` itself short-circuits on a length mismatch without
/// comparing content — safe because the token's length is not secret (an
/// attacker can already observe the cookie's length off the wire).
fn csrf_valid(req: &HttpRequest) -> bool {
    let header_value = match req
        .headers()
        .get(CSRF_HEADER_NAME)
        .and_then(|v| v.to_str().ok())
    {
        Some(v) if !v.is_empty() => v,
        _ => return false,
    };

    let cookie_value = match req.cookie(CSRF_COOKIE_NAME) {
        Some(c) if !c.value().is_empty() => c,
        _ => return false,
    };

    bool::from(
        header_value
            .as_bytes()
            .ct_eq(cookie_value.value().as_bytes()),
    )
}

/// Where the credential returned by [`extract_token`] came from. Drives the
/// §3 CSRF gate below: only a cookie-sourced credential on a
/// state-changing request needs the double-submit check — a Bearer header
/// cannot be set by a cross-site attacker in the first place.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CredentialSource {
    Cookie,
    AuthorizationHeader,
}

/// §10.1: extract the bearer token from the `axiam_access` cookie, falling
/// back to the `Authorization: Bearer` header (cookie-then-header, matching
/// the server-side extractor's parse logic — see the module doc comment for
/// the analog file reference). Also reports which source the credential
/// came from, so the caller can apply the §3 CSRF gate to cookie-sourced
/// requests only.
///
/// `no_credential_challenge` is CONTRACT.md §28.4 vector 1 — precomputed by
/// the caller from `app_data`, since building it needs the registered
/// `JwksVerifier` this free function does not have access to — attached to
/// either failure below: a request carrying no `Authorization` header at
/// all, and one carrying a non-Bearer scheme, are both "no authentication
/// information" under RFC 6750 §3 (mirrors the TypeScript reference port's
/// `extractCredential`, which returns nothing for either case alike).
fn extract_token(
    req: &HttpRequest,
    no_credential_challenge: Option<String>,
) -> Result<(String, CredentialSource), AxiamExtractorError> {
    if let Some(cookie) = req.cookie("axiam_access") {
        return Ok((cookie.value().to_owned(), CredentialSource::Cookie));
    }

    let header = req
        .headers()
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| AxiamExtractorError::missing_credentials(no_credential_challenge.clone()))?;

    let header = header.trim();
    let mut parts = header.splitn(2, char::is_whitespace);
    let scheme = parts.next().unwrap_or("");
    let credentials = parts.next().unwrap_or("").trim();

    if !scheme.eq_ignore_ascii_case("bearer") || credentials.is_empty() {
        return Err(AxiamExtractorError::invalid_scheme(no_credential_challenge));
    }

    Ok((
        credentials.to_owned(),
        CredentialSource::AuthorizationHeader,
    ))
}

impl actix_web::FromRequest for AxiamUser {
    type Error = AxiamExtractorError;
    type Future = Pin<Box<dyn Future<Output = Result<Self, Self::Error>>>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        let verifier = req.app_data::<web::Data<JwksVerifier>>().cloned();
        // §28.5: `None` whenever `resource_metadata_url` is unset on the
        // registered verifier — which is what keeps a guard without §28
        // byte-for-byte identical to one from before §28 existed. Cloned
        // (cheap: a handful of `String`s) up front so both challenge values
        // are available inside the `async move` block below without
        // borrowing `verifier` after it is moved into it.
        let mcp = verifier.as_ref().and_then(|v| v.mcp_challenges().cloned());
        let no_credential_challenge = mcp.as_ref().map(|c| c.no_credential().to_string());
        let invalid_token_challenge = mcp.as_ref().map(|c| c.invalid_token().to_string());

        // Clone/compute what we need synchronously so the returned future
        // is `'static` and does not borrow `req` (matches the server-side
        // extractor's FromRequest shape — see the module doc comment).
        let token_result = extract_token(req, no_credential_challenge);
        // §3 CSRF gate inputs: only relevant for a cookie-sourced
        // credential on a state-changing request, but cheap enough to
        // compute unconditionally here (both are constant-time reads off
        // `req`, no I/O).
        let method_is_state_changing = is_state_changing(req.method());
        let csrf_ok = csrf_valid(req);

        Box::pin(async move {
            let (token, source) = token_result?;

            // §3: a cookie-sourced credential is not CSRF-immune the way a
            // Bearer header is — reject before any verification work if
            // the double-submit check fails. Bearer-header requests always
            // skip this branch. No §28 challenge: §28.5 rule 5 lists a CSRF
            // refusal among the 403s that carry none.
            if source == CredentialSource::Cookie && method_is_state_changing && !csrf_ok {
                return Err(AxiamExtractorError::csrf_validation_failed());
            }

            // §10.2: verify locally against the cached JWKS — no
            // AXIAM-server round-trip. A credential WAS presented by this
            // point (`token_result` above already succeeded), so every
            // failure from here carries §28.4 vector 2 (`invalid_token`)
            // rather than vector 1.
            let verifier = verifier.ok_or_else(|| {
                AxiamExtractorError::misconfigured(invalid_token_challenge.clone())
            })?;
            let claims = verifier
                .verify(&token)
                .await
                .map_err(|e| AxiamExtractorError {
                    error: e,
                    challenge: invalid_token_challenge.clone(),
                })?;

            // §10.3: build and inject the authenticated identity.
            let user_id = Uuid::parse_str(&claims.sub).map_err(|_| {
                AxiamExtractorError::invalid_claim("sub", invalid_token_challenge.clone())
            })?;
            let tenant_id = Uuid::parse_str(&claims.tenant_id).map_err(|_| {
                AxiamExtractorError::invalid_claim("tenant_id", invalid_token_challenge.clone())
            })?;
            let roles = claims
                .scope
                .as_deref()
                .map(|s| s.split_whitespace().map(str::to_owned).collect())
                .unwrap_or_default();

            Ok(AxiamUser {
                user_id,
                tenant_id,
                roles,
            })
        })
    }
}
