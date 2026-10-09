//! CIBA — client-initiated backchannel authentication, CONTRACT.md §33
//! (contract 1.58; CIBA Core 1.0, poll and ping modes).
//!
//! A client that already knows whom it wants to authenticate asks AXIAM to
//! authenticate that user **on another device**; AXIAM notifies the user, who
//! approves or refuses on the console. The client then collects the tokens at
//! the token endpoint — by polling, or once after AXIAM *pings* it.
//!
//! Four operations on [`AxiamClient`]:
//!
//! | Operation | What it does |
//! |---|---|
//! | [`AxiamClient::ciba_initiate`] | `POST /oauth2/bc-authorize`. **Never retried.** |
//! | [`AxiamClient::ciba_poll`] | one token request with `grant_type=urn:openid:params:grant-type:ciba` |
//! | [`AxiamClient::ciba_await`] | polls to a terminal outcome, honouring `interval` and `slow_down` |
//! | [`AxiamClient::ciba_handle_ping`] | verifies a ping's bearer and returns its `auth_req_id`; no I/O |
//!
//! Two things a caller must not read into a success:
//!
//! * **A successful `ciba_initiate` proves nothing about the user** (§33.3
//!   rule 4). AXIAM answers a hint that names nobody, a locked user and a real
//!   one identically, and the only signal that a user did not answer is
//!   `expired_token`. Nothing here reports that a user "exists" or "was
//!   notified".
//! * **A ping says the request was decided, never how** (§33.2). Call
//!   `ciba_poll` after answering the ping; the outcome — tokens,
//!   `access_denied` or `expired_token` — comes from the token endpoint.
//!
//! The client always authenticates, by the credential this SDK was built with
//! (`client_secret_post`, or the §6.1 client certificate for a
//! `tls_client_auth` client); a client built with neither is refused locally.
//! `auth_req_id`, `client_notification_token` and the signing key are
//! [`Sensitive`] (§33.5).

use crate::time::{Duration, Instant};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use uuid::Uuid;

use super::discovery::OidcConfiguration;
use super::exchange::{OidcTokenSet, TokenResponseWire, oauth2_error_or_fallback};
use crate::client::AxiamClient;
use crate::error::AxiamError;
use crate::management::error::local_refusal;
use crate::rest::auth::CsrfHeaderExt;
use crate::sensitive::Sensitive;

/// `grant_type` of the CIBA token request (CIBA Core §10.1).
pub const CIBA_GRANT_TYPE: &str = "urn:openid:params:grant-type:ciba";

/// The interval used when the initiate response carries none (§33.7 rule 2).
pub const DEFAULT_CIBA_INTERVAL_SECS: u64 = 5;

/// Seconds added to the interval per `slow_down`, permanently (§33.7 rule 3).
pub const CIBA_SLOW_DOWN_INCREMENT_SECS: u64 = 5;

/// The lifetime of a signed request this SDK mints: five minutes, inside the
/// server's sixty-minute bound on `exp - nbf` (§33.2).
pub const SIGNED_REQUEST_LIFETIME_SECS: i64 = 300;

// ---------------------------------------------------------------------------
// Request and response types
// ---------------------------------------------------------------------------

/// Whom to authenticate: **exactly one** hint (§33.2). A sum type, so sending
/// both, or neither, cannot be written. `login_hint_token` is not offered.
#[derive(Debug, Clone)]
pub enum CibaUserHint {
    /// A username, then an e-mail address, within the tenant.
    LoginHint(String),
    /// An ID token this deployment issued to this client.
    IdTokenHint(String),
}

/// How the client receives the outcome, as it registered.
#[derive(Debug, Clone)]
pub enum CibaDelivery {
    /// The client polls the token endpoint.
    Poll,
    /// AXIAM pings the client's registered notification endpoint, presenting
    /// this token as a bearer; the client then polls once.
    Ping {
        /// The bearer AXIAM presents at the ping; keep it to check the ping
        /// with [`AxiamClient::ciba_handle_ping`]. Never returned by AXIAM.
        client_notification_token: Sensitive<String>,
    },
}

/// The signature algorithms a signed request may use (§33.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CibaSigningAlg {
    /// RSASSA-PSS with SHA-256.
    Ps256,
    /// ECDSA on P-256 with SHA-256.
    Es256,
    /// Ed25519.
    EdDsa,
}

impl CibaSigningAlg {
    fn jose(self) -> Algorithm {
        match self {
            CibaSigningAlg::Ps256 => Algorithm::PS256,
            CibaSigningAlg::Es256 => Algorithm::ES256,
            CibaSigningAlg::EdDsa => Algorithm::EdDSA,
        }
    }
}

/// The key and algorithm for the signed request form (§33.2, CIBA Core
/// §7.1.1). Both are the caller's: there is no default for either, and the
/// SDK signs under exactly the algorithm given — the one the client
/// registered as `backchannel_authentication_request_signing_alg`.
///
/// The key is held only as a signing key; `Debug` shows the algorithm and
/// `kid`, never the key.
#[derive(Clone)]
pub struct CibaRequestSigner {
    alg: CibaSigningAlg,
    key: Sensitive<EncodingKey>,
    kid: Option<String>,
}

impl std::fmt::Debug for CibaRequestSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CibaRequestSigner")
            .field("alg", &self.alg)
            .field("kid", &self.kid)
            .field("key", &self.key)
            .finish()
    }
}

impl CibaRequestSigner {
    /// A signer from a PEM private key (PKCS#8 for EdDSA and ES256; PKCS#1 or
    /// PKCS#8 for PS256) and the algorithm it signs under.
    ///
    /// # Errors
    /// A local `ValidationError`, before any request, when the PEM is not a
    /// key, or not a key that signs under `alg`.
    pub fn from_pem(
        alg: CibaSigningAlg,
        pem: &Sensitive<Vec<u8>>,
        kid: Option<String>,
    ) -> Result<Self, AxiamError> {
        let refuse = || {
            local_refusal(
                "ciba_initiate",
                "signing_key",
                "the key is not a private key that signs under the given algorithm (CONTRACT.md §33.2)",
            )
        };
        let key = match alg {
            CibaSigningAlg::EdDsa => EncodingKey::from_ed_pem(pem.expose()),
            CibaSigningAlg::Es256 => EncodingKey::from_ec_pem(pem.expose()),
            CibaSigningAlg::Ps256 => EncodingKey::from_rsa_pem(pem.expose()),
        }
        .map_err(|_| refuse())?;
        // A key that parses is not yet a key for this algorithm: prove it signs.
        jsonwebtoken::crypto::sign(b"axiam-ciba-probe", &key, alg.jose()).map_err(|_| refuse())?;
        Ok(Self {
            alg,
            key: Sensitive::new(key),
            kid,
        })
    }

    /// The algorithm this signer uses.
    pub fn alg(&self) -> CibaSigningAlg {
        self.alg
    }
}

/// Arguments to [`AxiamClient::ciba_initiate`] (§33.2 `CibaInitiateRequest`).
///
/// `binding_message` and `login_hint` can be personal data: the SDK never logs
/// them. `user_code`, `login_hint_token` and `request_uri` are not members —
/// AXIAM refuses each (§33.3 rule 3).
#[derive(Debug, Clone)]
pub struct CibaInitiateParams {
    /// Space-separated; must include `openid`.
    pub scope: String,
    /// Whom to authenticate.
    pub hint: CibaUserHint,
    /// Shown to the user on the approval page — what lets them tell the
    /// request they started from one an attacker did. Required for a `fapi2`
    /// client.
    pub binding_message: Option<String>,
    /// The requested lifetime, 30–600 s (absent: 300).
    pub requested_expiry: Option<u32>,
    /// Space-separated authentication context classes.
    pub acr_values: Option<String>,
    /// RFC 8707 resource indicator.
    pub resource: Option<String>,
    /// Poll or ping, as registered.
    pub delivery: CibaDelivery,
    /// `Some` sends the request as one signed JWT (`request`) — required of a
    /// client that registered a signing algorithm, refused from one that did
    /// not.
    pub signer: Option<CibaRequestSigner>,
    /// Tenant UUID for the `tenant_id` query parameter (§12.1 note 2).
    pub tenant_id: Option<Uuid>,
    /// A pre-fetched discovery document.
    pub configuration: Option<OidcConfiguration>,
}

impl CibaInitiateParams {
    /// A poll-mode, unsigned request for `scope` and `hint`.
    pub fn new(scope: impl Into<String>, hint: CibaUserHint) -> Self {
        Self {
            scope: scope.into(),
            hint,
            binding_message: None,
            requested_expiry: None,
            acr_values: None,
            resource: None,
            delivery: CibaDelivery::Poll,
            signer: None,
            tenant_id: None,
            configuration: None,
        }
    }
}

/// `CibaInitiateResponse` (§33.2).
#[derive(Debug, Clone)]
pub struct CibaInitiateResponse {
    /// The request's id at the token endpoint — a bearer credential for the
    /// grant (§33.5). Never parse or length-check it.
    pub auth_req_id: Sensitive<String>,
    /// The request's lifetime, seconds — authoritative (§33.7 rule 4).
    pub expires_in: u64,
    /// The minimum seconds between token requests; the response's value, or
    /// [`DEFAULT_CIBA_INTERVAL_SECS`] when it was absent or zero.
    pub interval: u64,
    /// When the response was received; `ciba_await`'s deadline is this plus
    /// `expires_in`.
    pub received_at: Instant,
}

#[derive(Deserialize)]
struct CibaInitiateResponseWire {
    auth_req_id: String,
    expires_in: u64,
    #[serde(default)]
    interval: Option<u64>,
}

/// Arguments to [`AxiamClient::ciba_poll`].
#[derive(Debug, Clone)]
pub struct CibaPollParams {
    /// The `auth_req_id` from [`CibaInitiateResponse`] or a ping.
    pub auth_req_id: Sensitive<String>,
    /// Tenant UUID for the `tenant_id` query parameter.
    pub tenant_id: Option<Uuid>,
    /// A pre-fetched discovery document.
    pub configuration: Option<OidcConfiguration>,
}

/// The clock [`AxiamClient::ciba_await`] waits on — injectable so its
/// schedule is testable without sleeping (§33.8 tests 6 and 7).
pub trait CibaClock: Send + Sync {
    /// The current instant.
    fn now(&self) -> Instant;
    /// Wait `duration`.
    fn sleep(&self, duration: Duration) -> Pin<Box<dyn Future<Output = ()> + Send + '_>>;
}

/// The real clock: `Instant::now` and `tokio::time::sleep`.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemCibaClock;

impl CibaClock for SystemCibaClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
    fn sleep(&self, duration: Duration) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(tokio::time::sleep(duration))
    }
}

/// Arguments to [`AxiamClient::ciba_await`].
#[derive(Clone, Default)]
pub struct CibaAwaitParams {
    /// Tenant UUID for the `tenant_id` query parameter.
    pub tenant_id: Option<Uuid>,
    /// A pre-fetched discovery document.
    pub configuration: Option<OidcConfiguration>,
    /// The clock to wait on; `None` is [`SystemCibaClock`].
    pub clock: Option<Arc<dyn CibaClock>>,
}

impl std::fmt::Debug for CibaAwaitParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CibaAwaitParams")
            .field("tenant_id", &self.tenant_id)
            .field(
                "configuration",
                &self.configuration.as_ref().map(|c| &c.issuer),
            )
            .field("clock", &self.clock.as_ref().map(|_| "<clock>"))
            .finish()
    }
}

// ---------------------------------------------------------------------------
// The polling schedule (§33.7), as a value type
// ---------------------------------------------------------------------------

/// What one poll answer means for the loop (§33.3 rule 6, §33.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Step {
    /// `authorization_pending` — keep polling at the current interval.
    Pending,
    /// `slow_down` — add 5 s to the interval, for good.
    SlowDown,
    /// A transport failure, a `408`, a `429` or a `5xx` (whatever its body)
    /// that outlived §16's retries — not terminal; wait one interval (§33.7
    /// rule 5, contract 1.59 P8, P9).
    Transient,
    /// Anything else is the answer: `access_denied`, `expired_token`,
    /// `invalid_grant`, a `4xx` without an `error` member, the call refused
    /// locally — and **any failure after a `2xx`** (a body that does not
    /// decode, an ID token that does not validate or whose key cannot be
    /// fetched), because the redemption is spent (§33.7 rule 7, P9).
    Terminal,
}

/// A failed [`AxiamClient::ciba_poll`], with what it means for the loop.
struct PollFailure {
    err: AxiamError,
    step: Step,
}

impl PollFailure {
    fn terminal(err: AxiamError) -> Self {
        Self {
            err,
            step: Step::Terminal,
        }
    }
}

/// The step a decisive (not retried) non-`2xx` answer means.
fn decisive_step(err: &AxiamError, status: u16) -> Step {
    match err.oauth_error_code() {
        Some("authorization_pending") => Step::Pending,
        Some("slow_down") => Step::SlowDown,
        // §33.3 rule 13: a 429's body is `rate_limit_exceeded`, never terminal
        // for a poll; P9: a `408` and a `429` are transient, whatever they say.
        Some("rate_limit_exceeded") => Step::Transient,
        _ if status == 408 || status == 429 => Step::Transient,
        _ => Step::Terminal,
    }
}

// ---------------------------------------------------------------------------
// The four operations
// ---------------------------------------------------------------------------

/// The client's credential for these calls: client_secret_post, or the client
/// certificate the transport presents (`tls_client_auth`).
struct ClientAuth {
    client_id: String,
    client_secret: Option<String>,
}

impl AxiamClient {
    fn ciba_client_auth(&self, operation: &str) -> Result<ClientAuth, AxiamError> {
        let client_id = self.oidc_client_id_or_err()?.to_string();
        let client_secret = self.oidc_client_secret().map(|s| s.expose().clone());
        if client_secret.is_none() && !self.presents_client_certificate() {
            return Err(AxiamError::auth(format!(
                "{operation} requires client authentication: a CIBA client is never public — \
                 build the client with .oidc_client_secret(...) or a §6.1 client certificate \
                 (CONTRACT.md §33.1)"
            )));
        }
        Ok(ClientAuth {
            client_id,
            client_secret,
        })
    }

    /// `POST /oauth2/bc-authorize` (CIBA Core §7, CONTRACT.md §33.1) — ask AXIAM
    /// to authenticate a user on another device.
    ///
    /// **Never retried** — not on a transport error, a `5xx` or a `429`
    /// (§33.7 rule 1): every accepted call stores a request and may notify a
    /// person. On a lost answer, let it expire and ask again deliberately.
    ///
    /// A success proves nothing about the user (§33.3 rule 4); see the module
    /// documentation.
    ///
    /// # Errors
    /// * a local [`AxiamError::Auth`] when the client has no credential;
    /// * a local `ValidationError` for a ping-mode request without a
    ///   `client_notification_token`;
    /// * the server's refusals as [`crate::OAuthProtocolError`]s — for
    ///   example `invalid_binding_message`, whose `error_description` is the
    ///   server's.
    pub async fn ciba_initiate(
        &self,
        params: CibaInitiateParams,
    ) -> Result<CibaInitiateResponse, AxiamError> {
        self.ensure_open()?;
        let auth = self.ciba_client_auth("ciba_initiate")?;
        if let CibaDelivery::Ping {
            client_notification_token,
        } = &params.delivery
            && client_notification_token.expose().is_empty()
        {
            return Err(local_refusal(
                "ciba_initiate",
                "client_notification_token",
                "a ping-mode request needs a client_notification_token: without one AXIAM has nothing to ping with (CONTRACT.md §33.8)",
            ));
        }
        let configuration = match params.configuration.clone() {
            Some(c) => c,
            None => self.oidc_discover().await?,
        };
        let tenant_id = self.resolve_oidc_tenant_id(params.tenant_id).await?;
        let endpoint = self
            .mtls_preferred_opt(
                &configuration,
                |a| a.backchannel_authentication_endpoint.as_deref(),
                configuration.backchannel_authentication_endpoint.as_deref(),
            )?
            .ok_or_else(|| {
                AxiamError::auth(
                    "the authorization server's discovery document advertises no \
                     backchannel_authentication_endpoint: this server does not support CIBA \
                     (CONTRACT.md §33.1)",
                )
            })?;
        let url = self.oidc_endpoint_url(endpoint, tenant_id)?;

        let mut form: Vec<(&'static str, Sensitive<String>)> =
            vec![("client_id", Sensitive::new(auth.client_id.clone()))];
        if let Some(secret) = &auth.client_secret {
            form.push(("client_secret", Sensitive::new(secret.clone())));
        }
        match &params.signer {
            Some(signer) => {
                let request =
                    signed_request(&params, signer, &auth.client_id, &configuration.issuer)?;
                form.push(("request", request));
            }
            None => form.extend(plain_members(&params)),
        }
        let body: Vec<(&str, &str)> = form
            .iter()
            .map(|(k, v)| (*k, v.expose().as_str()))
            .collect();

        let response = self
            .http()
            .post(url)
            .header("X-Tenant-ID", self.tenant_header_value())
            .maybe_csrf_header(self)
            .form(&body)
            .send()
            .await
            .map_err(|e| AxiamError::network(format!("ciba_initiate request failed: {e}")))?;
        if !response.status().is_success() {
            return Err(oauth2_error_or_fallback(response).await);
        }
        let wire: CibaInitiateResponseWire = response.json().await.map_err(|e| {
            AxiamError::network(format!("failed to parse the ciba_initiate response: {e}"))
        })?;
        Ok(CibaInitiateResponse {
            auth_req_id: Sensitive::new(wire.auth_req_id),
            expires_in: wire.expires_in,
            interval: wire
                .interval
                .filter(|i| *i > 0)
                .unwrap_or(DEFAULT_CIBA_INTERVAL_SECS),
            received_at: Instant::now(),
        })
    }

    /// `POST /oauth2/token` with `grant_type=urn:openid:params:grant-type:ciba`
    /// (CIBA Core §10.1, CONTRACT.md §33.1) — **one** token request.
    ///
    /// The answers of §33.3 rule 6 surface as [`AxiamError::Auth`] carrying a
    /// [`crate::OAuthProtocolError`]: `authorization_pending` and `slow_down`
    /// (non-terminal), `access_denied` and `expired_token` (terminal and
    /// distinct — [`AxiamError::is_access_denied`],
    /// [`AxiamError::is_expired_token`]), `invalid_grant`.
    ///
    /// Retried per §16 on a transport failure, a bodiless `408` or `429`, and
    /// a `5xx` **whatever its body** — AXIAM answers an internal failure
    /// `500 {"error":"server_error"}` — which then surfaces as a
    /// `NetworkError`, never as that `OAuthProtocolError` (§33.7 rule 5,
    /// contract 1.59 P8). **Store the returned tokens before anything else**:
    /// a request is redeemed once, and a second `ciba_poll` for it is
    /// `invalid_grant` (§33.7 rule 7).
    pub async fn ciba_poll(&self, params: CibaPollParams) -> Result<OidcTokenSet, AxiamError> {
        self.ciba_poll_step(params).await.map_err(|f| f.err)
    }

    /// [`Self::ciba_poll`], keeping what a failure means for
    /// [`Self::ciba_await`]'s loop.
    async fn ciba_poll_step(&self, params: CibaPollParams) -> Result<OidcTokenSet, PollFailure> {
        use crate::retry::{
            Attempt, RetryRunner, ThreadRngJitter, TokioSleeper, parse_retry_after,
        };
        self.ensure_open().map_err(PollFailure::terminal)?;
        let auth = self
            .ciba_client_auth("ciba_poll")
            .map_err(PollFailure::terminal)?;
        let configuration = match params.configuration {
            Some(c) => c,
            None => self
                .oidc_discover()
                .await
                .map_err(PollFailure::terminal)?,
        };
        let tenant_id = self
            .resolve_oidc_tenant_id(params.tenant_id)
            .await
            .map_err(PollFailure::terminal)?;
        let endpoint = self
            .mtls_preferred(
                &configuration,
                |a| a.token_endpoint.as_deref(),
                &configuration.token_endpoint,
            )
            .map_err(PollFailure::terminal)?;
        let url = self
            .oidc_endpoint_url(endpoint, tenant_id)
            .map_err(PollFailure::terminal)?;
        let mut form: Vec<(&str, &str)> = vec![
            ("grant_type", CIBA_GRANT_TYPE),
            ("auth_req_id", params.auth_req_id.expose().as_str()),
            ("client_id", auth.client_id.as_str()),
        ];
        if let Some(secret) = &auth.client_secret {
            form.push(("client_secret", secret.as_str()));
        }
        let runner = RetryRunner {
            enabled: self.retry_enabled(),
            operation: "ciba_poll",
            telemetry: self.telemetry(),
            jitter: &ThreadRngJitter,
            sleeper: &TokioSleeper,
        };
        let (url, form) = (&url, &form);
        let wire: TokenResponseWire = runner
            .run(|_| async move {
                let response = self
                    .http()
                    .post(url.clone())
                    .header("X-Tenant-ID", self.tenant_header_value())
                    .maybe_csrf_header(self)
                    .form(form)
                    .send()
                    .await
                    .map_err(|e| {
                        Attempt::bare(AxiamError::network(format!(
                            "ciba_poll request failed: {e}"
                        )))
                    })?;
                if !response.status().is_success() {
                    let retry_after = response
                        .headers()
                        .get(reqwest::header::RETRY_AFTER)
                        .and_then(|v| v.to_str().ok())
                        .and_then(parse_retry_after);
                    let status = response.status().as_u16();
                    // P8: on this operation a 5xx is transient whatever its
                    // body, so it maps by status (§2) rather than by `error`.
                    if status >= 500 {
                        let text = response.text().await.unwrap_or_default();
                        let err = AxiamError::from_http_status(status, text);
                        return Err(Attempt { err, retry_after });
                    }
                    let err = oauth2_error_or_fallback(response).await;
                    // The protocol answers (`authorization_pending`, …) are
                    // decisive, and so is any other 4xx but a bodiless 408 /
                    // 429.
                    if err.oauth_error_code().is_some()
                        || !crate::retry::status_is_retryable(status)
                    {
                        let step = decisive_step(&err, status);
                        return Ok(Err(PollFailure { err, step }));
                    }
                    return Err(Attempt { err, retry_after });
                }
                // §33.7 rule 7: consume the 200 before anything else — and a
                // body that does not parse is not retried, since the server
                // may already have redeemed the request: it is terminal.
                Ok(response.json::<TokenResponseWire>().await.map_err(|e| {
                    PollFailure::terminal(AxiamError::network(format!(
                        "failed to parse the ciba_poll response: {e}"
                    )))
                }))
            })
            .await
            // What outlived §16's retries is a transport failure, a 5xx or a
            // bodiless 408 / 429: transient for the loop.
            .map_err(|err| PollFailure {
                err,
                step: Step::Transient,
            })??;
        // After the 2xx: a failure here — the ID token, or the key fetch its
        // validation needs — is terminal; the redemption is spent (P9).
        self.to_token_set(wire, &configuration, None)
            .await
            .map_err(PollFailure::terminal)
    }

    /// Poll for `initiated`'s outcome until it is decided or expires (§33.1,
    /// §33.7). Surfaces nothing to the user — AXIAM notified them.
    ///
    /// * The first poll waits one `interval`; polling earlier only earns
    ///   `slow_down` and a longer wait.
    /// * `slow_down` adds [`CIBA_SLOW_DOWN_INCREMENT_SECS`] to the interval,
    ///   cumulatively and permanently; `authorization_pending` never lowers it.
    /// * A transport failure, a `408`, a `429` or a `5xx` (whatever its body)
    ///   is not terminal: the loop waits the interval and polls again.
    /// * Anything else ends the loop: a `4xx` without an `error` member, and
    ///   any failure **after** a `200` — a body that does not decode, an ID
    ///   token that does not validate or whose key cannot be fetched. The
    ///   redemption is spent, so polling again could only answer
    ///   `invalid_grant` (§33.7 rule 7, contract 1.59 P9); such tokens are
    ///   not returned (§12.4), and the application starts a new request.
    /// * Polling stops at `received_at + expires_in`, even if the server has
    ///   not said `expired_token`; the same `expired_token` is then raised
    ///   locally.
    ///
    /// Returns the token set without adopting it as this client's credential
    /// — the posture of `device_login` and `login_client_credentials`. In
    /// **ping** mode, do not call this: call [`Self::ciba_poll`] once from
    /// the ping handler, and fall back to this loop only once half of
    /// `expires_in` has passed without a ping (§33.7 rule 6).
    pub async fn ciba_await(
        &self,
        initiated: &CibaInitiateResponse,
        params: CibaAwaitParams,
    ) -> Result<OidcTokenSet, AxiamError> {
        let clock: Arc<dyn CibaClock> = params
            .clock
            .clone()
            .unwrap_or_else(|| Arc::new(SystemCibaClock));
        let configuration = match params.configuration {
            Some(c) => c,
            None => self.oidc_discover().await?,
        };
        let deadline = initiated.received_at + Duration::from_secs(initiated.expires_in);
        let mut interval = if initiated.interval == 0 {
            DEFAULT_CIBA_INTERVAL_SECS
        } else {
            initiated.interval
        };
        loop {
            let wait = Duration::from_secs(interval);
            if clock.now() + wait >= deadline {
                return Err(AxiamError::oauth_protocol_error(
                    "expired_token",
                    "the CIBA request expired before it was decided (client-side deadline from \
                     expires_in; CONTRACT.md §33.7 rule 4)",
                ));
            }
            clock.sleep(wait).await;
            match self
                .ciba_poll_step(CibaPollParams {
                    auth_req_id: initiated.auth_req_id.clone(),
                    tenant_id: params.tenant_id,
                    configuration: Some(configuration.clone()),
                })
                .await
            {
                Ok(tokens) => return Ok(tokens),
                Err(PollFailure { err, step }) => match step {
                    Step::Pending | Step::Transient => continue,
                    Step::SlowDown => interval += CIBA_SLOW_DOWN_INCREMENT_SECS,
                    Step::Terminal => return Err(err),
                },
            }
        }
    }

    /// Check a ping AXIAM delivered to your notification endpoint and return
    /// the `auth_req_id` it names (CIBA Core §10.2, CONTRACT.md §33.1). **No
    /// I/O.**
    ///
    /// `headers` are the request's headers as `(name, value)` pairs, in any
    /// framework's shape; `body` its raw body; `expected_token` the
    /// `client_notification_token` you sent with the request.
    ///
    /// 1. Exactly one `Authorization` header, `Bearer` (any case), one space,
    ///    and the token — compared in constant time. Otherwise
    ///    [`AxiamError::Auth`], whose message names no value.
    /// 2. A JSON object with a non-empty string `auth_req_id`; any other
    ///    member is ignored. Otherwise a local `ValidationError`.
    ///
    /// It neither answers the HTTP request nor calls the token endpoint:
    /// answer `204` as soon as this returns, **then** [`Self::ciba_poll`] —
    /// AXIAM retries a ping that is not answered quickly. Nor does it check
    /// that the `auth_req_id` is one you issued: the token endpoint answers
    /// `invalid_grant` for any other.
    pub fn ciba_handle_ping<'a>(
        &self,
        headers: impl IntoIterator<Item = (&'a str, &'a [u8])>,
        body: &[u8],
        expected_token: &Sensitive<String>,
    ) -> Result<Sensitive<String>, AxiamError> {
        use subtle::ConstantTimeEq;
        let refused = || {
            AxiamError::auth(
                "ciba ping refused: the Authorization header is not the expected bearer \
                 (CONTRACT.md §33.1)",
            )
        };
        let mut authorization = headers
            .into_iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case("authorization"))
            .map(|(_, value)| value);
        let (Some(value), None) = (authorization.next(), authorization.next()) else {
            return Err(refused());
        };
        let Some(space) = value.iter().position(|b| *b == b' ') else {
            return Err(refused());
        };
        let (scheme, token) = (&value[..space], &value[space + 1..]);
        if !scheme.eq_ignore_ascii_case(b"bearer") || token.is_empty() {
            return Err(refused());
        }
        let expected = expected_token.expose().as_bytes();
        if expected.is_empty() || !bool::from(token.ct_eq(expected)) {
            return Err(refused());
        }
        let parsed: Value = serde_json::from_slice(body)
            .map_err(|_| local_refusal("ciba_handle_ping", "body", "the ping body is not JSON"))?;
        match parsed.get("auth_req_id") {
            Some(Value::String(id)) if !id.is_empty() && parsed.is_object() => {
                Ok(Sensitive::new(id.clone()))
            }
            _ => Err(local_refusal(
                "ciba_handle_ping",
                "auth_req_id",
                "the ping body carries no non-empty auth_req_id string",
            )),
        }
    }
}

impl AxiamError {
    /// Whether this is the `access_denied` answer — at a CIBA or device poll,
    /// the user refused (§33.4).
    pub fn is_access_denied(&self) -> bool {
        self.oauth_error_code() == Some("access_denied")
    }

    /// Whether this is the `expired_token` answer — at a CIBA or device poll,
    /// nobody decided in time; raised locally too when `ciba_await` reaches
    /// its deadline (§33.4, §33.7 rule 4).
    pub fn is_expired_token(&self) -> bool {
        self.oauth_error_code() == Some("expired_token")
    }
}

/// The plain form's authentication-request members, exactly those set.
fn plain_members(params: &CibaInitiateParams) -> Vec<(&'static str, Sensitive<String>)> {
    let mut out = vec![("scope", Sensitive::new(params.scope.clone()))];
    match &params.hint {
        CibaUserHint::LoginHint(h) => out.push(("login_hint", Sensitive::new(h.clone()))),
        CibaUserHint::IdTokenHint(h) => out.push(("id_token_hint", Sensitive::new(h.clone()))),
    }
    if let Some(m) = &params.binding_message {
        out.push(("binding_message", Sensitive::new(m.clone())));
    }
    if let Some(e) = params.requested_expiry {
        out.push(("requested_expiry", Sensitive::new(e.to_string())));
    }
    if let Some(a) = &params.acr_values {
        out.push(("acr_values", Sensitive::new(a.clone())));
    }
    if let Some(r) = &params.resource {
        out.push(("resource", Sensitive::new(r.clone())));
    }
    if let CibaDelivery::Ping {
        client_notification_token,
    } = &params.delivery
    {
        out.push((
            "client_notification_token",
            client_notification_token.clone(),
        ));
    }
    out
}

#[derive(Serialize)]
struct SignedClaims<'a> {
    iss: &'a str,
    aud: &'a str,
    iat: i64,
    nbf: i64,
    exp: i64,
    jti: String,
    #[serde(flatten)]
    members: serde_json::Map<String, Value>,
}

/// The CIBA Core §7.1.1 signed request: every member inside the JWT, plus
/// `iss`, `aud`, `iat`, `nbf`, `exp` and a fresh `jti`.
fn signed_request(
    params: &CibaInitiateParams,
    signer: &CibaRequestSigner,
    client_id: &str,
    issuer: &str,
) -> Result<Sensitive<String>, AxiamError> {
    let now = crate::time::SystemTime::now()
        .duration_since(crate::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let mut members = serde_json::Map::new();
    for (k, v) in plain_members(params) {
        let value = if k == "requested_expiry" {
            // A number inside the JWT (CIBA Core §7.1), a string on the form.
            json!(params.requested_expiry)
        } else {
            Value::String(v.expose().clone())
        };
        members.insert(k.to_string(), value);
    }
    let claims = SignedClaims {
        iss: client_id,
        aud: issuer,
        iat: now,
        nbf: now,
        exp: now + SIGNED_REQUEST_LIFETIME_SECS,
        jti: Uuid::new_v4().simple().to_string(),
        members,
    };
    let mut header = Header::new(signer.alg.jose());
    header.kid = signer.kid.clone();
    jsonwebtoken::encode(&header, &claims, signer.key.expose())
        .map(Sensitive::new)
        .map_err(|_| {
            local_refusal(
                "ciba_initiate",
                "signing_key",
                "the signed request could not be signed with the given key",
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_classification_follows_section_33_3_rule_6() {
        let cases = [
            ("authorization_pending", Step::Pending),
            ("slow_down", Step::SlowDown),
            ("rate_limit_exceeded", Step::Transient),
            ("access_denied", Step::Terminal),
            ("expired_token", Step::Terminal),
            ("invalid_grant", Step::Terminal),
            ("something_new", Step::Terminal),
        ];
        for (code, step) in cases {
            assert_eq!(
                decisive_step(&AxiamError::oauth_protocol_error(code, "d"), 400),
                step,
                "{code}"
            );
        }
        // P9: a 408 and a 429 are transient whatever they carry; a 4xx
        // without an `error` member is decisive.
        let unknown = AxiamError::oauth_protocol_error("something_new", "d");
        assert_eq!(decisive_step(&unknown, 429), Step::Transient);
        assert_eq!(decisive_step(&unknown, 408), Step::Transient);
        assert_eq!(
            decisive_step(&AxiamError::from_http_status(400, "x"), 400),
            Step::Terminal
        );
        assert_eq!(
            decisive_step(&AxiamError::from_http_status(404, "x"), 404),
            Step::Terminal
        );
    }

    #[test]
    fn the_two_terminal_outcomes_are_told_apart() {
        let denied = AxiamError::oauth_protocol_error("access_denied", "no");
        let expired = AxiamError::oauth_protocol_error("expired_token", "late");
        assert!(denied.is_access_denied() && !denied.is_expired_token());
        assert!(expired.is_expired_token() && !expired.is_access_denied());
    }
}
