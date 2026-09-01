//! `oidc_exchange`, `oidc_refresh`, `login_client_credentials`,
//! `introspect`, `revoke`, `sso_start`, `sso_complete` (CONTRACT.md §12.1).
//!
//! The token endpoint is form-encoded (RFC 6749 §4.1.3, note 1); the
//! federation `sso_*` pair is JSON. `tenant_id` travels as a required
//! **query** parameter on `/oauth2/*` (note 2) — never in the form body —
//! alongside the unconditional §5 `X-Tenant-ID` header.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::AxiamError;
use crate::Sensitive;
use crate::client::{AxiamClient, OrgIdentifier, TenantIdentifier};
use crate::rest::auth::CsrfHeaderExt;

use super::discovery::OidcConfiguration;
use super::id_token::{IdTokenClaims, IdTokenExpectations, check_id_token_claims};

/// Path of the federation SSO step-1 endpoint.
pub const SSO_START_PATH: &str = "/api/v1/auth/federation/oidc/start";
/// Path of the federation SSO step-2 (callback) endpoint.
pub const SSO_CALLBACK_PATH: &str = "/api/v1/auth/federation/oidc/callback";

// ---------------------------------------------------------------------------
// Wire types (snake_case, mirror the server schemas verbatim)
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct TokenRequestForm<'a> {
    grant_type: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    code: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    code_verifier: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    redirect_uri: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    refresh_token: Option<&'a str>,
    client_id: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_secret: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    scope: Option<&'a str>,
}

#[derive(Serialize)]
struct IntrospectOrRevokeForm<'a> {
    token: &'a str,
    client_id: &'a str,
    client_secret: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    token_type_hint: Option<&'a str>,
}

/// 200 body of `POST /oauth2/token` (wire schema `TokenResponse`).
#[derive(Debug, Deserialize)]
pub(crate) struct TokenResponseWire {
    pub(crate) access_token: String,
    pub(crate) token_type: String,
    pub(crate) expires_in: u64,
    #[serde(default)]
    pub(crate) scope: Option<String>,
    #[serde(default)]
    pub(crate) refresh_token: Option<String>,
    #[serde(default)]
    pub(crate) id_token: Option<String>,
}

/// 200 body of `POST /oauth2/introspect` (wire schema
/// `IntrospectionResponse`).
#[derive(Debug, Deserialize)]
struct IntrospectionResponseWire {
    active: bool,
    #[serde(default)]
    sub: Option<String>,
    #[serde(default)]
    client_id: Option<String>,
    #[serde(default)]
    scope: Option<String>,
    #[serde(default)]
    token_type: Option<String>,
    #[serde(default)]
    exp: Option<i64>,
    #[serde(default)]
    iat: Option<i64>,
}

/// The RFC 6749 error body shape (`OAuth2ErrorResponse`) returned by
/// AXIAM's `/oauth2/*` endpoints. Both fields are required by the schema.
#[derive(Debug, Deserialize)]
struct OAuth2ErrorResponseWire {
    error: String,
    error_description: String,
}

#[derive(Serialize)]
struct OidcStartRequestWire {
    federation_config_id: String,
    redirect_uri: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    tenant_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tenant_slug: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    org_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    org_slug: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OidcStartResponseWire {
    authorize_url: String,
    state: String,
    expires_in_secs: u64,
}

#[derive(Serialize)]
struct OidcPublicCallbackRequestWire<'a> {
    state: &'a str,
    code: &'a str,
}

#[derive(Debug, Deserialize)]
struct SsoLoginSuccessResponseWire {
    user_id: Uuid,
    session_id: Uuid,
    expires_in: u64,
    redirect_uri: String,
}

// ---------------------------------------------------------------------------
// Public SDK types
// ---------------------------------------------------------------------------

/// A token set returned by the OAuth2 token endpoint (wire schema
/// `TokenResponse`), returned by `oidc_exchange`, `oidc_refresh` and
/// `login_client_credentials`.
///
/// `access_token`, `refresh_token` and `id_token` are [`Sensitive`] (§12.5).
/// `id_claims` is present exactly when `id_token` is, and holds the
/// **already-validated** claim set (§12.4) — validation happens before this
/// struct is ever constructed, so an `OidcTokenSet` in your hands is never
/// partially trusted (§12.4 rule 7).
///
/// `Clone` is implemented so the single in-flight `oidc_refresh` can hand the
/// *same* token set to every concurrent waiter (CONTRACT.md §9 rule 2). It
/// clones the [`Sensitive`] wrappers, never unwraps them: a clone redacts
/// exactly as the original does.
#[derive(Debug, Clone)]
pub struct OidcTokenSet {
    /// The OAuth2 access token (§12.5 secret).
    pub access_token: Sensitive<String>,
    /// The token type the server issued (`Bearer`).
    pub token_type: String,
    /// Access-token lifetime in seconds from the time of the response.
    pub expires_in: u64,
    /// Granted scope, when the server narrowed or echoed it.
    pub scope: Option<String>,
    /// The refresh token, when the grant issued one (§12.5 secret).
    pub refresh_token: Option<Sensitive<String>>,
    /// The raw ID token, when the grant issued one (§12.5 secret).
    pub id_token: Option<Sensitive<String>>,
    /// The validated ID-token claims — present exactly when [`Self::id_token`]
    /// is.
    pub id_claims: Option<IdTokenClaims>,
}

/// Arguments to `oidc_exchange` (`grant_type=authorization_code`).
pub struct OidcExchangeParams {
    /// The authorization code the IdP redirected back with.
    pub code: String,
    /// The verifier from the matching [`super::AuthorizationRequest`].
    pub code_verifier: Sensitive<String>,
    /// The same `redirect_uri` that was sent on the authorization request.
    pub redirect_uri: String,
    /// The `nonce` from the matching [`super::AuthorizationRequest`].
    /// MANDATORY — §12.4 rule 6 is not optional for this grant.
    pub nonce: String,
    /// Tenant UUID for the token endpoint's required `tenant_id` query
    /// parameter. Defaults to the client's configured tenant when it was
    /// built in UUID form (§12.3 rule 4).
    pub tenant_id: Option<Uuid>,
    /// A pre-fetched discovery document, to avoid re-reading the (cached)
    /// one. Fetched via `oidc_discover` when `None`.
    pub configuration: Option<OidcConfiguration>,
}

/// Arguments to `oidc_refresh` (`grant_type=refresh_token`).
pub struct OidcRefreshParams {
    /// The refresh token to redeem.
    pub refresh_token: Sensitive<String>,
    /// Optional narrowed scope to request. Omitted from the form body when
    /// absent.
    pub scope: Option<String>,
    /// Tenant UUID for the `tenant_id` query parameter (§12.3 rule 4).
    pub tenant_id: Option<Uuid>,
    /// A pre-fetched discovery document. Fetched via `oidc_discover` when
    /// `None`.
    pub configuration: Option<OidcConfiguration>,
}

/// Arguments to `login_client_credentials` (`grant_type=client_credentials`).
#[derive(Default)]
pub struct LoginClientCredentialsParams {
    /// Optional scope to request. This grant requests no `openid` scope and
    /// the response carries no `id_token` (§12.1).
    pub scope: Option<String>,
    /// Tenant UUID for the `tenant_id` query parameter (§12.3 rule 4).
    pub tenant_id: Option<Uuid>,
    /// A pre-fetched discovery document. Fetched via `oidc_discover` when
    /// `None`.
    pub configuration: Option<OidcConfiguration>,
}

/// Arguments to `introspect` (RFC 7662). Requires confidential-client
/// credentials (§12.1 note 4).
pub struct IntrospectParams {
    /// The token to introspect.
    pub token: Sensitive<String>,
    /// Optional RFC 7662 `token_type_hint` (`access_token`/`refresh_token`).
    pub token_type_hint: Option<String>,
    /// Tenant UUID for the `tenant_id` query parameter (§12.3 rule 4).
    pub tenant_id: Option<Uuid>,
    /// A pre-fetched discovery document. Fetched via `oidc_discover` when
    /// `None`.
    pub configuration: Option<OidcConfiguration>,
}

/// Arguments to `revoke` (RFC 7009). Requires confidential-client
/// credentials (§12.1 note 4).
pub struct RevokeParams {
    /// The token to revoke.
    pub token: Sensitive<String>,
    /// Optional RFC 7009 `token_type_hint`.
    pub token_type_hint: Option<String>,
    /// Tenant UUID for the `tenant_id` query parameter (§12.3 rule 4).
    pub tenant_id: Option<Uuid>,
    /// A pre-fetched discovery document. Fetched via `oidc_discover` when
    /// `None`.
    pub configuration: Option<OidcConfiguration>,
}

/// The RFC 7662 introspection result (wire schema
/// `IntrospectionResponse`). Only `active` is guaranteed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntrospectionResult {
    /// Whether the token is currently active.
    pub active: bool,
    /// Subject the token was issued to.
    pub sub: Option<String>,
    /// Client the token was issued to.
    pub client_id: Option<String>,
    /// Scope granted to the token.
    pub scope: Option<String>,
    /// Token type (`Bearer`).
    pub token_type: Option<String>,
    /// Expiry time, epoch seconds.
    pub exp: Option<i64>,
    /// Issued-at time, epoch seconds.
    pub iat: Option<i64>,
}

/// Arguments to `sso_start` (`POST /api/v1/auth/federation/oidc/start`).
#[derive(Default)]
pub struct SsoStartParams {
    /// UUID of the server-side federation configuration identifying the
    /// upstream IdP.
    pub federation_config_id: String,
    /// Post-login destination, stored server-side and echoed back by
    /// `sso_complete`.
    pub redirect_uri: String,
    /// Tenant UUID. One tenant form (`tenant_id` or `tenant_slug`) is
    /// required; defaults to the client's configuration (§5.1).
    pub tenant_id: Option<Uuid>,
    /// Tenant slug. Alternative to [`Self::tenant_id`].
    pub tenant_slug: Option<String>,
    /// Organization UUID. One org form (`org_id` or `org_slug`) is
    /// required; defaults to the client's configuration (§5.1).
    pub org_id: Option<Uuid>,
    /// Organization slug. Alternative to [`Self::org_id`].
    pub org_slug: Option<String>,
}

/// The result of `sso_start` (wire schema `OidcStartResponse`).
///
/// There is deliberately **no nonce**: on the federation path the nonce
/// never leaves the server (§12.1 note 7). Round-trip [`Self::state`] into
/// `sso_complete` unmodified.
#[derive(Debug, Clone)]
pub struct SsoStartResult {
    /// The upstream IdP authorization URL to redirect the user agent to.
    pub authorize_url: String,
    /// Single-use CSRF state to round-trip back into `sso_complete`
    /// unmodified.
    pub state: String,
    /// Remaining TTL of the server-side state row, in seconds (600 = 10
    /// min).
    pub expires_in_secs: u64,
}

/// Arguments to `sso_complete`
/// (`POST /api/v1/auth/federation/oidc/callback`).
pub struct SsoCompleteParams {
    /// The `state` value the IdP redirected back with — must be the one
    /// `sso_start` returned.
    pub state: String,
    /// The authorization code the IdP redirected back with.
    pub code: String,
}

/// The result of `sso_complete` (wire schema `SsoLoginSuccessResponse`).
///
/// Carries **no token material** — the session arrives as `Set-Cookie`
/// (§12.1 note 6), captured automatically by this client's existing §4
/// cookie jar (the same `reqwest::cookie::Jar` every other REST call uses).
#[derive(Debug, Clone)]
pub struct SsoCompleteResult {
    /// The provisioned/linked user's UUID.
    pub user_id: Uuid,
    /// The established session's UUID.
    pub session_id: Uuid,
    /// Session/access-token lifetime in seconds.
    pub expires_in: u64,
    /// The post-login destination that was stored during `sso_start`.
    pub redirect_uri: String,
}

// ---------------------------------------------------------------------------
// Internals shared across the nine operations
// ---------------------------------------------------------------------------

/// Map a non-2xx `/oauth2/*` response onto the §2 taxonomy: an
/// `OAuth2ErrorResponse`-shaped body becomes [`AxiamError::oauth_protocol_error`]
/// (CONTRACT.md §12.3 rule 3); anything else falls back to the generic
/// [`AxiamError::from_http_status`] mapping.
pub(crate) async fn oauth2_error_or_fallback(response: reqwest::Response) -> AxiamError {
    let status = response.status().as_u16();
    let text = response
        .text()
        .await
        .unwrap_or_else(|_| "no response body".to_string());
    if let Ok(body) = serde_json::from_str::<OAuth2ErrorResponseWire>(&text) {
        return AxiamError::oauth_protocol_error(body.error, body.error_description);
    }
    AxiamError::from_http_status(status, text)
}

pub(crate) fn network_err(context: &str, e: reqwest::Error) -> AxiamError {
    AxiamError::Network {
        message: format!("{context}: {e}"),
        source: Some(Box::new(e)),
    }
}

impl AxiamClient {
    /// The configured §12 `client_id`, or a client-side [`AxiamError::Auth`]
    /// (no wire call) when none was configured.
    pub(crate) fn oidc_client_id_or_err(&self) -> Result<&str, AxiamError> {
        self.oidc_client_id().ok_or_else(|| AxiamError::Auth {
            message:
                "this OIDC operation requires a client_id: build the client with .oidc_client_id(...) (CONTRACT.md §12.1)"
                    .into(),
            oauth: None,
            reason: None,
        })
    }

    /// The configured §12 `client_secret`, or a client-side
    /// [`AxiamError::Auth`] (no wire call) for an operation that cannot be
    /// performed by a public client (§12.1 note 4).
    pub(crate) fn oidc_client_secret_or_err(&self, operation: &str) -> Result<String, AxiamError> {
        self.oidc_client_secret()
            .map(|s| s.expose().clone())
            .ok_or_else(|| AxiamError::Auth {
                message: format!(
                    "{operation} requires confidential-client credentials: build the client with .oidc_client_secret(...) (CONTRACT.md §12.1 note 4)"
                ),
                oauth: None,
                reason: None,
            })
    }

    /// Resolve the tenant UUID for the `/oauth2/*` `tenant_id` query
    /// parameter (§12.3 rule 4): the explicit argument, else the client's
    /// resolved tenant, else a client-side [`AxiamError::Auth`] (no wire
    /// call) — a slug-only, not-yet-logged-in client cannot fill this.
    pub(crate) async fn resolve_oidc_tenant_id(
        &self,
        explicit: Option<Uuid>,
    ) -> Result<Uuid, AxiamError> {
        if let Some(id) = explicit {
            return Ok(id);
        }
        self.resolved_tenant_id().await.ok_or_else(|| AxiamError::Auth {
            message:
                "this operation requires a tenant_id UUID for the /oauth2 query parameter: pass tenant_id explicitly, or construct the client with the tenant_id (UUID) form (CONTRACT.md §12.3 rule 4)"
                    .into(),
            oauth: None,
            reason: None,
        })
    }

    /// Build the token/introspection/revocation endpoint URL with the
    /// mandatory `?tenant_id=<uuid>` query parameter (§12.1 note 2).
    pub(crate) fn oidc_endpoint_url(
        &self,
        endpoint: &str,
        tenant_id: Uuid,
    ) -> Result<url::Url, AxiamError> {
        let mut url = url::Url::parse(endpoint).map_err(|e| AxiamError::Network {
            message: format!("invalid endpoint URL in discovery document: {e}"),
            source: None,
        })?;
        url.query_pairs_mut()
            .append_pair("tenant_id", &tenant_id.to_string());
        Ok(url)
    }

    async fn post_token(
        &self,
        configuration: &OidcConfiguration,
        form: &TokenRequestForm<'_>,
        tenant_id: Uuid,
    ) -> Result<TokenResponseWire, AxiamError> {
        let url = self.oidc_endpoint_url(&configuration.token_endpoint, tenant_id)?;
        let response = self
            .http()
            .post(url)
            .header("X-Tenant-ID", self.tenant_header_value())
            .maybe_csrf_header(self)
            .form(form)
            .send()
            .await
            .map_err(|e| network_err("token request failed", e))?;

        if !response.status().is_success() {
            return Err(oauth2_error_or_fallback(response).await);
        }
        response
            .json::<TokenResponseWire>()
            .await
            .map_err(|e| network_err("failed to parse token response", e))
    }

    /// Convert a `TokenResponse` into an [`OidcTokenSet`], validating any
    /// `id_token` first (§12.4). Validation precedes construction, so a
    /// failure discards the whole set (§12.4 rule 7).
    pub(crate) async fn to_token_set(
        &self,
        wire: TokenResponseWire,
        configuration: &OidcConfiguration,
        nonce: Option<&str>,
    ) -> Result<OidcTokenSet, AxiamError> {
        let id_claims = match &wire.id_token {
            Some(id_token) => {
                let verifier = self.oidc_verifier_for(&configuration.jwks_uri)?;
                let claims: IdTokenClaims = verifier.verify_id_token_signature(id_token).await?;
                let expectations = IdTokenExpectations {
                    issuer: &configuration.issuer,
                    client_id: self.oidc_client_id_or_err()?,
                    nonce,
                    clock_skew_sec: self.oidc_clock_skew_sec(),
                };
                let now_sec = crate::time::SystemTime::now()
                    .duration_since(crate::time::UNIX_EPOCH)
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or(0);
                Some(check_id_token_claims(claims, &expectations, now_sec)?)
            }
            None => None,
        };

        Ok(OidcTokenSet {
            access_token: Sensitive::new(wire.access_token),
            token_type: wire.token_type,
            expires_in: wire.expires_in,
            scope: wire.scope,
            refresh_token: wire.refresh_token.map(Sensitive::new),
            id_token: wire.id_token.map(Sensitive::new),
            id_claims,
        })
    }
}

// ---------------------------------------------------------------------------
// The seven remaining canonical operations (`oidc_discover`/`oidc_begin`
// live in `discovery.rs`/`authorize.rs`)
// ---------------------------------------------------------------------------

impl AxiamClient {
    /// `POST /oauth2/token` with `grant_type=authorization_code`
    /// (CONTRACT.md §12.1) — exchange an authorization code for a token
    /// set, validating the returned ID token in full before returning.
    ///
    /// If **any** §12.4 rule fails, the whole token set is discarded and
    /// the matching `AxiamError` reason code is raised — the access and
    /// refresh tokens from the same response are never returned (rule 7).
    pub async fn oidc_exchange(
        &self,
        params: OidcExchangeParams,
    ) -> Result<OidcTokenSet, AxiamError> {
        let configuration = match params.configuration {
            Some(c) => c,
            None => self.oidc_discover().await?,
        };
        let tenant_id = self.resolve_oidc_tenant_id(params.tenant_id).await?;
        let client_id = self.oidc_client_id_or_err()?.to_string();
        let client_secret = self.oidc_client_secret().map(|s| s.expose().clone());

        let form = TokenRequestForm {
            grant_type: "authorization_code",
            code: Some(&params.code),
            code_verifier: Some(params.code_verifier.expose().as_str()),
            redirect_uri: Some(&params.redirect_uri),
            refresh_token: None,
            client_id: &client_id,
            client_secret: client_secret.as_deref(),
            scope: None,
        };

        let wire = self.post_token(&configuration, &form, tenant_id).await?;
        self.to_token_set(wire, &configuration, Some(&params.nonce))
            .await
    }

    /// `POST /oauth2/token` with `grant_type=refresh_token` (CONTRACT.md
    /// §12.1) — refresh an [`OidcTokenSet`], under the §9 single-flight
    /// refresh guard.
    ///
    /// A **distinct operation** from [`AxiamClient::refresh`], which drives
    /// the cookie/opaque-token session path at `POST /api/v1/auth/refresh`.
    /// The two are never merged or aliased.
    ///
    /// An `id_token` in the response is validated against rules 1–5 and 7;
    /// rule 6 (nonce) is skipped (OIDC Core §12.2 does not require a nonce
    /// in a refresh-issued ID token).
    ///
    /// # Concurrency (CONTRACT.md §9)
    ///
    /// A burst of N concurrent calls produces **exactly one**
    /// `POST /oauth2/token` and every one of the N callers receives that one
    /// call's outcome — the same [`OidcTokenSet`] on success, an equivalent
    /// error (same variant, same `oauth` payload, same `reason`) on failure.
    /// This is §9 rule 2's observable requirement, and it is not optional:
    /// AXIAM refresh tokens are single-use with rotation, so N independent
    /// wire calls would mean N−1 replays of a consumed token, each failing
    /// `invalid_grant`. The coalescer lives in `src/oidc/single_flight.rs` — a
    /// dedicated instance, as §9 rule 5 permits. There is no retry loop
    /// anywhere on this path (§9 rule 3).
    pub async fn oidc_refresh(
        &self,
        params: OidcRefreshParams,
    ) -> Result<OidcTokenSet, AxiamError> {
        use super::single_flight::{OidcRefreshCancelled, OidcRefreshElection};

        // §9 rules 1 + 2: elect one leader per burst; everyone else waits for
        // the leader's outcome and issues no wire call of its own.
        let leader = match self.oidc_refresh_election() {
            OidcRefreshElection::Waiter(waiter) => {
                return match waiter.wait().await {
                    Ok(Ok(tokens)) => Ok(tokens),
                    Ok(Err(shared)) => Err(shared.clone_for_waiter()),
                    // The leader's future was cancelled before it published
                    // (see `single_flight`'s Drop impl). §9 rule 3 forbids a
                    // retry loop, so this surfaces as an auth failure and the
                    // caller decides what to do next.
                    Err(OidcRefreshCancelled) => Err(AxiamError::auth(
                        "the in-flight oidc_refresh was cancelled before completing; retry or re-authenticate (CONTRACT.md §9)",
                    )),
                };
            }
            OidcRefreshElection::Leader(leader) => leader,
        };

        let result = self.oidc_refresh_wire_call(params).await;
        leader.publish(&result);
        result
    }

    /// The actual single `POST /oauth2/token?grant_type=refresh_token` wire
    /// call, performed by the elected leader only.
    async fn oidc_refresh_wire_call(
        &self,
        params: OidcRefreshParams,
    ) -> Result<OidcTokenSet, AxiamError> {
        let configuration = match params.configuration {
            Some(c) => c,
            None => self.oidc_discover().await?,
        };
        let tenant_id = self.resolve_oidc_tenant_id(params.tenant_id).await?;
        let client_id = self.oidc_client_id_or_err()?.to_string();
        let client_secret = self.oidc_client_secret().map(|s| s.expose().clone());

        let form = TokenRequestForm {
            grant_type: "refresh_token",
            code: None,
            code_verifier: None,
            redirect_uri: None,
            refresh_token: Some(params.refresh_token.expose().as_str()),
            client_id: &client_id,
            client_secret: client_secret.as_deref(),
            scope: params.scope.as_deref(),
        };

        let wire = self.post_token(&configuration, &form, tenant_id).await?;
        self.to_token_set(wire, &configuration, None).await
    }

    /// `POST /oauth2/token` with `grant_type=client_credentials`
    /// (CONTRACT.md §12.1) — service-account machine-to-machine login.
    ///
    /// Requests no `openid` scope, so the response carries no `id_token`.
    ///
    /// # Errors
    /// A client-side [`AxiamError::Auth`] when no `client_secret` is
    /// configured — this grant cannot be performed by a public client.
    pub async fn login_client_credentials(
        &self,
        params: LoginClientCredentialsParams,
    ) -> Result<OidcTokenSet, AxiamError> {
        let configuration = match params.configuration {
            Some(c) => c,
            None => self.oidc_discover().await?,
        };
        let tenant_id = self.resolve_oidc_tenant_id(params.tenant_id).await?;
        let client_id = self.oidc_client_id_or_err()?.to_string();
        let client_secret = self.oidc_client_secret_or_err("login_client_credentials")?;

        let form = TokenRequestForm {
            grant_type: "client_credentials",
            code: None,
            code_verifier: None,
            redirect_uri: None,
            refresh_token: None,
            client_id: &client_id,
            client_secret: Some(&client_secret),
            scope: params.scope.as_deref(),
        };

        let wire = self.post_token(&configuration, &form, tenant_id).await?;
        // No nonce: rule 6 does not apply to this grant.
        self.to_token_set(wire, &configuration, None).await
    }

    /// `POST /oauth2/introspect` (RFC 7662, CONTRACT.md §12.1) — ask the
    /// server whether a token is active and, if so, for its metadata.
    ///
    /// Requires confidential-client credentials (§12.1 note 4). A `401`
    /// here is a *client-credential* failure surfaced as
    /// [`AxiamError::oauth_protocol_error`]; it never enters the §9
    /// single-flight refresh guard (§12.3 rule 3) — this method does not
    /// touch that guard at all.
    pub async fn introspect(
        &self,
        params: IntrospectParams,
    ) -> Result<IntrospectionResult, AxiamError> {
        let configuration = match params.configuration {
            Some(c) => c,
            None => self.oidc_discover().await?,
        };
        let tenant_id = self.resolve_oidc_tenant_id(params.tenant_id).await?;
        let client_id = self.oidc_client_id_or_err()?.to_string();
        let client_secret = self.oidc_client_secret_or_err("introspect")?;

        let url = self.oidc_endpoint_url(&configuration.introspection_endpoint, tenant_id)?;
        let form = IntrospectOrRevokeForm {
            token: params.token.expose().as_str(),
            client_id: &client_id,
            client_secret: &client_secret,
            token_type_hint: params.token_type_hint.as_deref(),
        };

        let response = self
            .http()
            .post(url)
            .header("X-Tenant-ID", self.tenant_header_value())
            .maybe_csrf_header(self)
            .form(&form)
            .send()
            .await
            .map_err(|e| network_err("introspect request failed", e))?;

        if !response.status().is_success() {
            return Err(oauth2_error_or_fallback(response).await);
        }

        let wire: IntrospectionResponseWire = response
            .json()
            .await
            .map_err(|e| network_err("failed to parse introspect response", e))?;

        Ok(IntrospectionResult {
            active: wire.active,
            sub: wire.sub,
            client_id: wire.client_id,
            scope: wire.scope,
            token_type: wire.token_type,
            exp: wire.exp,
            iat: wire.iat,
        })
    }

    /// `POST /oauth2/revoke` (RFC 7009, CONTRACT.md §12.1) — revoke an
    /// access or refresh token.
    ///
    /// Per RFC 7009 the server answers `200` for unknown, expired and
    /// already-revoked tokens alike, so revocation is **idempotent**: any
    /// `200` is success. Only a `401` (client authentication failed) is an
    /// error, surfaced as [`AxiamError::oauth_protocol_error`].
    ///
    /// # Errors
    /// A client-side [`AxiamError::Auth`] when no `client_secret` is
    /// configured.
    pub async fn revoke(&self, params: RevokeParams) -> Result<(), AxiamError> {
        let configuration = match params.configuration {
            Some(c) => c,
            None => self.oidc_discover().await?,
        };
        let tenant_id = self.resolve_oidc_tenant_id(params.tenant_id).await?;
        let client_id = self.oidc_client_id_or_err()?.to_string();
        let client_secret = self.oidc_client_secret_or_err("revoke")?;

        let url = self.oidc_endpoint_url(&configuration.revocation_endpoint, tenant_id)?;
        let form = IntrospectOrRevokeForm {
            token: params.token.expose().as_str(),
            client_id: &client_id,
            client_secret: &client_secret,
            token_type_hint: params.token_type_hint.as_deref(),
        };

        let response = self
            .http()
            .post(url)
            .header("X-Tenant-ID", self.tenant_header_value())
            .maybe_csrf_header(self)
            .form(&form)
            .send()
            .await
            .map_err(|e| network_err("revoke request failed", e))?;

        if !response.status().is_success() {
            return Err(oauth2_error_or_fallback(response).await);
        }
        Ok(())
    }

    /// `POST /api/v1/auth/federation/oidc/start` (CONTRACT.md §12.1) — step
    /// 1 of first-time SSO against an **upstream** IdP. No JWT required.
    ///
    /// One tenant form (`tenant_id`/`tenant_slug`) and one org form
    /// (`org_id`/`org_slug`) must be resolvable, from the arguments or from
    /// the client's construction-time configuration (§5.1). Redirect to the
    /// returned `authorize_url` and round-trip `state` back into
    /// [`Self::sso_complete`] unmodified.
    ///
    /// # Errors
    /// A client-side [`AxiamError::Auth`] (no wire call) when tenant or org
    /// context cannot be resolved.
    pub async fn sso_start(&self, params: SsoStartParams) -> Result<SsoStartResult, AxiamError> {
        // Tenant context always resolves: `TenantIdentifier` is a two-variant
        // enum and §5 guarantees the builder set one of them, so unlike the
        // organization pair below there is no unresolvable case to guard
        // against here.
        let (tenant_id, tenant_slug) = match (params.tenant_id, params.tenant_slug) {
            (Some(id), _) => (Some(id), None),
            (None, Some(slug)) => (None, Some(slug)),
            (None, None) => match &self.inner.tenant {
                TenantIdentifier::Id(id) => (Some(*id), None),
                TenantIdentifier::Slug(slug) => (None, Some(slug.clone())),
            },
        };

        let (org_id, org_slug) = match (params.org_id, params.org_slug) {
            (Some(id), _) => (Some(id), None),
            (None, Some(slug)) => (None, Some(slug)),
            (None, None) => match self.org_identifier() {
                Some(OrgIdentifier::Id(id)) => (Some(*id), None),
                Some(OrgIdentifier::Slug(slug)) => (None, Some(slug.clone())),
                None => (self.resolved_org_id(), None),
            },
        };
        if org_id.is_none() && org_slug.is_none() {
            return Err(AxiamError::Auth {
                message:
                    "sso_start requires organization context: pass org_id or org_slug, or construct the client with one (CONTRACT.md §5.1)"
                        .into(),
                oauth: None,
                reason: None,
            });
        }

        let body = OidcStartRequestWire {
            federation_config_id: params.federation_config_id,
            redirect_uri: params.redirect_uri,
            tenant_id,
            tenant_slug,
            org_id,
            org_slug,
        };

        let url = self
            .base_url()
            .join(SSO_START_PATH)
            .expect("sso_start path is a well-formed relative URL literal");
        let response = self
            .http()
            .post(url)
            .header("X-Tenant-ID", self.tenant_header_value())
            .maybe_csrf_header(self)
            .json(&body)
            .send()
            .await
            .map_err(|e| network_err("sso_start request failed", e))?;

        if !response.status().is_success() {
            // Addendum item 12: the federation start endpoint documents no
            // response schema for its errors, so it is NOT parsed as an
            // OAuth2ErrorResponse — plain §2 status mapping only.
            let status = response.status().as_u16();
            let message = response
                .text()
                .await
                .unwrap_or_else(|_| "no response body".to_string());
            return Err(AxiamError::from_http_status(status, message));
        }

        let wire: OidcStartResponseWire = response
            .json()
            .await
            .map_err(|e| network_err("failed to parse sso_start response", e))?;

        Ok(SsoStartResult {
            authorize_url: wire.authorize_url,
            state: wire.state,
            expires_in_secs: wire.expires_in_secs,
        })
    }

    /// `POST /api/v1/auth/federation/oidc/callback` (CONTRACT.md §12.1) —
    /// step 2 of upstream SSO: consumes the single-use `state`, provisions
    /// or links the user, and establishes the session.
    ///
    /// The session arrives as **`Set-Cookie`** (§12.1 note 6), captured
    /// automatically by this client's own cookie jar (§4) — the same
    /// `reqwest::Client` every other REST call on this `AxiamClient` uses.
    /// §12.4 does not apply here: no ID token ever reaches the SDK on the
    /// federation path.
    ///
    /// On success this runs the **same post-login session sync** as
    /// [`AxiamClient::login`] / [`AxiamClient::verify_mfa`] (§4, §3): the
    /// `axiam_access`/`axiam_refresh` cookies are read out of the jar, the
    /// access token is verified through the JWKS verifier to resolve
    /// `tenant_id`/`org_id` and its expiry, the token manager is seeded, and
    /// the `axiam_csrf` value is cached for §3 forwarding. A `sso_complete`
    /// therefore leaves the client in exactly the state a `login()` would —
    /// [`AxiamClient::refresh`] and [`AxiamClient::logout`] work afterwards.
    ///
    /// # Errors
    /// Besides the §2 status mapping, an [`AxiamError::Auth`] when the
    /// response set no usable `axiam_access` cookie or that cookie does not
    /// verify — identical to `login()`'s behaviour, since a session that
    /// cannot be absorbed is not a successful login.
    pub async fn sso_complete(
        &self,
        params: SsoCompleteParams,
    ) -> Result<SsoCompleteResult, AxiamError> {
        let body = OidcPublicCallbackRequestWire {
            state: &params.state,
            code: &params.code,
        };

        let url = self
            .base_url()
            .join(SSO_CALLBACK_PATH)
            .expect("sso_complete path is a well-formed relative URL literal");
        let response = self
            .http()
            .post(url)
            .header("X-Tenant-ID", self.tenant_header_value())
            .maybe_csrf_header(self)
            .json(&body)
            .send()
            .await
            .map_err(|e| network_err("sso_complete request failed", e))?;

        if !response.status().is_success() {
            let status = response.status().as_u16();
            let message = response
                .text()
                .await
                .unwrap_or_else(|_| "no response body".to_string());
            return Err(AxiamError::from_http_status(status, message));
        }

        let wire: SsoLoginSuccessResponseWire = response
            .json()
            .await
            .map_err(|e| network_err("failed to parse sso_complete response", e))?;

        // Addendum judgment call 16 / §4 + §3: mark the session authenticated
        // by running the *same* post-login sync login()/verify_mfa() run —
        // seed the token manager from the jar, resolve tenant_id/org_id from
        // the verified access token, and cache the CSRF token. Without this a
        // caller holds a live server-side session the client knows nothing
        // about, and a subsequent refresh() fails with "no access token to
        // refresh".
        crate::rest::auth::absorb_session_cookies(self).await?;

        Ok(SsoCompleteResult {
            user_id: wire.user_id,
            session_id: wire.session_id,
            expires_in: wire.expires_in,
            redirect_uri: wire.redirect_uri,
        })
    }
}
