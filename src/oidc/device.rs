//! Device Authorization Grant (RFC 8628) — CONTRACT.md §14 (contract 1.7).
//!
//! The *client* half of the grant: the device that cannot show a browser.
//! The verification page (`GET /api/v1/device/verify`, `POST
//! /api/v1/device/decide`) is an authenticated first-party surface and is
//! explicitly out of scope for every SDK (§14 preamble) — it is the AXIAM
//! console's job.
//!
//! Three operations under the §14.4 Rust names:
//! [`AxiamClient::device_authorize`], [`AxiamClient::device_poll`] and the
//! composed [`AxiamClient::device_login`].
//!
//! Everything is reuse, not reimplementation: the transport, §2 error
//! mapping, §5 tenant header and §12.3 rule 3 `OAuth2ErrorResponse` handling
//! all come from the same `post_token`/`oauth2_error_or_fallback` internals
//! the nine §12 operations use.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::discovery::OidcConfiguration;
use super::exchange::{OidcTokenSet, oauth2_error_or_fallback};
use crate::client::AxiamClient;
use crate::error::AxiamError;
use crate::sensitive::Sensitive;

/// `grant_type` of the device access-token request (RFC 8628 §3.4).
pub const DEVICE_CODE_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:device_code";

/// Polling interval used when the authorization response omits `interval`
/// (RFC 8628 §3.2, §14.2 rule 2). An SDK MUST NOT hard-code a faster floor.
pub const DEFAULT_POLL_INTERVAL_SECS: u64 = 5;

/// Seconds added to the polling interval on each `slow_down` (RFC 8628 §3.5,
/// §14.2 rule 1). The increase is permanent and cumulative — it is added to
/// the *current* interval and never reset.
pub const SLOW_DOWN_INCREMENT_SECS: u64 = 5;

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------

/// The form of `device_authorize`. The client's secret rides **in the body**
/// when — and only when — the client was configured with one (§14.1 rule 2,
/// contract 1.62): never as `Authorization: Basic`, whatever the client is
/// registered for (§12.1 rule 3 stands for these two routes).
#[derive(Serialize)]
struct DeviceAuthorizationForm<'a> {
    client_id: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_secret: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    scope: Option<&'a str>,
}

/// The form of every `device_poll`: it names its client (`client_id`, §14.1
/// rule 3) and carries the same credential as `device_authorize`.
#[derive(Serialize)]
struct DeviceTokenForm<'a> {
    grant_type: &'a str,
    device_code: &'a str,
    client_id: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_secret: Option<&'a str>,
}

/// Not `Debug`: it holds the `device_code` until it is wrapped (§7 rule 1).
#[derive(Deserialize)]
struct DeviceAuthorizationResponseWire {
    device_code: String,
    user_code: String,
    verification_uri: String,
    #[serde(default)]
    verification_uri_complete: Option<String>,
    expires_in: u64,
    #[serde(default)]
    interval: Option<u64>,
}

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// The `DeviceAuthorizationResponse` — what the device shows its user, plus
/// the `device_code` it polls with.
///
/// `device_code` is [`Sensitive`] (§14.5): it is a bearer credential for the
/// lifetime of the grant. `user_code` deliberately is **not** — it exists to
/// be read aloud and typed by a human, and wrapping it would defeat the one
/// thing it is for. Neither may be logged; displaying `user_code` is the
/// caller's job.
#[derive(Debug, Clone)]
pub struct DeviceAuthorization {
    /// The device's polling credential (§14.5 secret).
    pub device_code: Sensitive<String>,
    /// The short code the human types into the verification page.
    pub user_code: String,
    /// Where the human goes to enter [`Self::user_code`].
    pub verification_uri: String,
    /// The verification URI with the user code already embedded, when the
    /// server chose to send one — a device that can render a QR code should
    /// prefer it so the user types nothing.
    ///
    /// Never synthesised by concatenation when absent (§14.3): its format is
    /// the server's to choose.
    pub verification_uri_complete: Option<String>,
    /// Seconds until the grant expires. Polling stops here (§14.2 rule 4).
    pub expires_in: u64,
    /// Seconds between polls, from the response, defaulted to
    /// [`DEFAULT_POLL_INTERVAL_SECS`] when the server omitted it.
    pub interval: u64,
}

/// Arguments to [`AxiamClient::device_authorize`].
#[derive(Debug, Default, Clone)]
pub struct DeviceAuthorizeParams {
    /// Space-delimited scopes to request.
    pub scope: Option<String>,
    /// Tenant UUID for the mandatory `tenant_id` query parameter (§12.1
    /// note 2), when the client was not built in UUID form.
    pub tenant_id: Option<Uuid>,
    /// A pre-fetched discovery document; fetched via `oidc_discover` when
    /// `None`.
    pub configuration: Option<OidcConfiguration>,
}

/// Arguments to [`AxiamClient::device_poll`].
#[derive(Debug, Clone)]
pub struct DevicePollParams {
    /// The `device_code` from [`DeviceAuthorization`].
    pub device_code: Sensitive<String>,
    /// Tenant UUID for the `tenant_id` query parameter (§12.1 note 2).
    pub tenant_id: Option<Uuid>,
    /// A pre-fetched discovery document.
    pub configuration: Option<OidcConfiguration>,
}

/// Arguments to [`AxiamClient::device_login`].
#[derive(Debug, Default, Clone)]
pub struct DeviceLoginParams {
    /// Space-delimited scopes to request.
    pub scope: Option<String>,
    /// Tenant UUID for the `tenant_id` query parameter (§12.1 note 2).
    pub tenant_id: Option<Uuid>,
    /// A pre-fetched discovery document.
    pub configuration: Option<OidcConfiguration>,
}

/// The five RFC 8628 §3.5 polling answers, classified per §14.2.
///
/// All five arrive as `400` with an `OAuth2ErrorResponse` body, which the §2
/// taxonomy would otherwise map to a validation error — §14.2 rule 5
/// overrides that for this grant, so the poll loop dispatches on the `error`
/// field *first* and falls back to the §2 mapping only for a `400` whose
/// `error` is none of the five.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PollOutcome {
    /// `authorization_pending` — the user has not decided yet.
    Pending,
    /// `slow_down` — back off permanently by [`SLOW_DOWN_INCREMENT_SECS`].
    SlowDown,
    /// `429 rate_limit_exceeded` — not terminal (§14.2 rule 9, contract 1.64):
    /// wait `Retry-After` as a minimum, without raising the interval.
    RateLimited,
    /// A `5xx` whatever its body (§14.2 rule 6, contract 1.64 amended): a
    /// transport failure, not terminal.
    Transient,
    /// `expired_token`, `access_denied`, `invalid_grant`, or anything else.
    Terminal,
}

/// The §14.2 polling schedule: the interval, and a budget of waited seconds.
///
/// [`AxiamClient::device_login`] takes its **deadline from the clock**
/// (`expires_in` from the moment the grant was issued, §14.2 rule 4), so that
/// the time requests take counts against it, and uses this type for the
/// interval arithmetic only (rules 1 and 2). [`Self::tick`] and
/// [`Self::tick_for`] count waits alone, which suits a loop that also checks
/// its own clock.
///
/// Extracted as a plain value type with no I/O so the arithmetic §14.2
/// rules 1, 2 and 4 describe can be tested exhaustively and instantly.
/// Driving that arithmetic through a mock HTTP server would test `reqwest`
/// and a sleeping runtime rather than the rule, and would take a real
/// half-minute to assert one `slow_down`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PollSchedule {
    interval_secs: u64,
    remaining_secs: u64,
}

impl PollSchedule {
    /// Build from a [`DeviceAuthorization`]'s `interval`/`expires_in`.
    pub fn new(interval_secs: u64, expires_in_secs: u64) -> Self {
        Self {
            interval_secs: if interval_secs == 0 {
                DEFAULT_POLL_INTERVAL_SECS
            } else {
                interval_secs
            },
            remaining_secs: expires_in_secs,
        }
    }

    /// The current inter-poll delay, in seconds.
    pub fn interval_secs(&self) -> u64 {
        self.interval_secs
    }

    /// Apply one `slow_down` (§14.2 rule 1): **cumulative, never reset.**
    pub fn slow_down(&mut self) {
        self.interval_secs += SLOW_DOWN_INCREMENT_SECS;
    }

    /// Consume one interval's worth of the budget of waited seconds.
    ///
    /// Returns `false` when the deadline has been reached, at which point the
    /// caller MUST stop (§14.2 rule 4) — the deadline is authoritative even
    /// if the server is still answering `authorization_pending`.
    pub fn tick(&mut self) -> bool {
        self.tick_for(self.interval_secs)
    }

    /// [`Self::tick`] for a wait of `wait_secs` rather than one interval: a
    /// wait such as a `429`'s `Retry-After` (a minimum, §14.2 rule 9, contract
    /// 1.64) counts as one interval and leaves the interval itself untouched.
    /// A wait that reaches the end of the budget is `false`, as for an interval.
    pub fn tick_for(&mut self, wait_secs: u64) -> bool {
        if wait_secs >= self.remaining_secs {
            self.remaining_secs = 0;
            return false;
        }
        self.remaining_secs -= wait_secs;
        true
    }
}

/// Whether a transport failure is a failure to connect. A browser's `fetch`
/// does not say, so on wasm32 it is never reported.
fn is_connect_error(e: &reqwest::Error) -> bool {
    #[cfg(not(target_arch = "wasm32"))]
    {
        e.is_connect()
    }
    #[cfg(target_arch = "wasm32")]
    {
        let _ = e;
        false
    }
}

/// The typed `expired_token` outcome of §14.2 rule 4, raised locally.
fn device_expired() -> AxiamError {
    AxiamError::oauth_protocol_error(
        "expired_token",
        "the device authorization expired before the user completed it \
         (client-side deadline from expires_in; CONTRACT.md §14.2 rule 4)",
    )
}

/// A failed poll and the `Retry-After` it carried, if any.
struct PollFailure {
    err: AxiamError,
    retry_after: Option<std::time::Duration>,
    /// The HTTP status of the answer; `None` for a failure with no answer
    /// (transport, discovery, local).
    status: Option<u16>,
}

impl From<AxiamError> for PollFailure {
    fn from(err: AxiamError) -> Self {
        Self {
            err,
            retry_after: None,
            status: None,
        }
    }
}

fn classify(err: &AxiamError) -> PollOutcome {
    match err.oauth_error_code() {
        Some("authorization_pending") => PollOutcome::Pending,
        Some("slow_down") => PollOutcome::SlowDown,
        Some("rate_limit_exceeded") => PollOutcome::RateLimited,
        _ => PollOutcome::Terminal,
    }
}

/// [`classify`], with the status read **before** the body (§14.2 rules 6 and
/// 9, contract 1.64 amended): a `5xx` is a transport failure whatever it says
/// (AXIAM answers an internal fault `500 {"error":"server_error"}`), any `429`
/// is the rate-limit wait whatever its body names (a `429 slow_down` from an
/// older server or an intermediary included), and `slow_down` raises the
/// interval only as the `400` of the answer table.
fn classify_failure(failure: &PollFailure) -> PollOutcome {
    match failure.status {
        Some(s) if s >= 500 => PollOutcome::Transient,
        Some(429) => PollOutcome::RateLimited,
        Some(400) | None => classify(&failure.err),
        // An answer at any other status is not one of the table's rows;
        // `authorization_pending` and `slow_down` mean nothing there.
        Some(_) => PollOutcome::Terminal,
    }
}

impl AxiamClient {
    /// `POST /oauth2/device_authorization` (CONTRACT.md §14.1) — start the
    /// grant and obtain the code pair.
    ///
    /// **The client authenticates as it does at every other token request**
    /// (§14.1 rule 2, contract 1.62; this replaces 1.60's "never sends
    /// `client_secret`"):
    ///
    /// * A client built **with** `.oidc_client_secret(..)` sends it as
    ///   `client_secret` in the form body — also when it is registered
    ///   `client_secret_basic`, and never as `Authorization: Basic` (§12.1
    ///   rule 3). The same secret goes with every [`Self::device_poll`].
    /// * A client built **with** `.with_client_cert(..)` presents its
    ///   certificate on the connection, and goes to the `mtls_endpoint_aliases`
    ///   entry for this endpoint when the discovery document publishes one.
    /// * A **public** client — the usual device, which cannot hold a secret —
    ///   sends `client_id` and no credential, and is never refused client-side.
    ///   The server refuses a public client that sends one.
    ///
    /// The SDK sends a credential only if its caller configured one: it never
    /// borrows a secret from elsewhere and never invents one. `private_key_jwt`
    /// assertions are not produced by this SDK.
    ///
    /// A failed client authentication is `401 invalid_client`, surfaced as an
    /// [`AxiamError::Auth`] carrying an [`crate::OAuthProtocolError`] — one
    /// request, no retry, and it never enters the §9 refresh guard.
    pub async fn device_authorize(
        &self,
        params: DeviceAuthorizeParams,
    ) -> Result<DeviceAuthorization, AxiamError> {
        let configuration = match params.configuration {
            Some(c) => c,
            None => self.oidc_discover().await?,
        };
        let tenant_id = self.resolve_oidc_tenant_id(params.tenant_id).await?;
        let client_id = self.oidc_client_id_or_err()?.to_string();

        let endpoint = self
            .mtls_preferred_opt(
                &configuration,
                |a| a.device_authorization_endpoint.as_deref(),
                configuration.device_authorization_endpoint.as_deref(),
            )?
            .ok_or_else(|| {
            AxiamError::Auth {
                message:
                    "the authorization server's discovery document advertises no device_authorization_endpoint: this server does not support the device grant (CONTRACT.md §14.1)"
                        .into(),
                oauth: None,
                reason: None,
                set_reason: None,
            }
        })?;
        let url = self.oidc_endpoint_url(endpoint, tenant_id)?;

        // §14.1 rule 2: the credential this client was configured with, and
        // none when it was configured with none.
        let client_secret = self.oidc_client_secret().map(|s| s.expose().clone());
        let form = DeviceAuthorizationForm {
            client_id: &client_id,
            client_secret: client_secret.as_deref(),
            scope: params.scope.as_deref(),
        };

        let response = self
            .oauth2_post(url)
            .form(&form)
            .send()
            .await
            .map_err(|e| AxiamError::Network {
                message: format!("device authorization request failed: {e}"),
                source: Some(Box::new(e)),
            })?;

        if !response.status().is_success() {
            return Err(oauth2_error_or_fallback(response).await);
        }

        let wire: DeviceAuthorizationResponseWire =
            response.json().await.map_err(|e| AxiamError::Network {
                message: format!("failed to parse device authorization response: {e}"),
                source: Some(Box::new(e)),
            })?;

        Ok(DeviceAuthorization {
            device_code: Sensitive::new(wire.device_code),
            user_code: wire.user_code,
            verification_uri: wire.verification_uri,
            verification_uri_complete: wire.verification_uri_complete,
            expires_in: wire.expires_in,
            // §14.2 rule 2: the interval comes from the response; only its
            // absence falls back to the RFC default. A server-sent 0 is
            // treated as absent — polling with no delay is never what the
            // server meant, and RFC 8628 §3.2 makes 5 s the floor.
            interval: wire
                .interval
                .filter(|i| *i > 0)
                .unwrap_or(DEFAULT_POLL_INTERVAL_SECS),
        })
    }

    /// `POST /oauth2/token` with `grant_type=urn:ietf:params:oauth:grant-type:device_code`
    /// (CONTRACT.md §14.1) — **one** poll attempt.
    ///
    /// This is the raw single call, so an application driving its own loop
    /// (a UI that wants to render a countdown, say) can. The five RFC 8628
    /// §3.5 answers surface as [`AxiamError::Auth`] carrying an
    /// [`crate::OAuthProtocolError`] whose `error` field the caller
    /// dispatches on — `authorization_pending` and `slow_down` included, so
    /// a hand-rolled loop sees the same answers [`Self::device_login`] does
    /// (a `429`'s `Retry-After` apart, below).
    ///
    /// **The poll names its client and authenticates it** (§14.1 rules 2 and
    /// 3, contract 1.62): every poll sends `client_id`, and the credential the
    /// client was configured with — a `client_secret` in the form body (never
    /// `Authorization: Basic`), or the client certificate on the connection —
    /// exactly as [`Self::device_authorize`] does. A public client sends none.
    /// The sixth answer, `401 invalid_client` (a failed or missing credential, a
    /// public client that sent one, a deleted client, a client that no longer
    /// holds the grant, a sender-constrained client's missing proof), is
    /// terminal: an [`crate::OAuthProtocolError`] with `error == "invalid_client"`,
    /// one request, never retried, never refreshed (§14.2 rule 5).
    ///
    /// **DPoP (§14.2 rule 8).** This SDK verifies DPoP proofs but does not
    /// generate them (§21.7.3), so it cannot drive a client registered for
    /// DPoP-bound tokens: the server's `401 invalid_client` for the missing
    /// proof is surfaced as above. A response whose `token_type` is `DPoP` is
    /// returned as the server said it, in [`OidcTokenSet::token_type`](super::OidcTokenSet) —
    /// never assumed to be `Bearer`.
    ///
    /// **A `429` is not terminal (§14.2 rule 9, contract 1.64).** It surfaces
    /// here as an [`crate::OAuthProtocolError`] with
    /// `error == "rate_limit_exceeded"`: wait at least the server's
    /// `Retry-After` (or one interval) without raising the interval, and poll
    /// again. This call does not expose the `Retry-After`, so a hand-rolled
    /// loop waits the interval; [`Self::device_login`] reads it and does the
    /// rest for you.
    ///
    /// **A `5xx` is the §2 `NetworkError` whatever its body** (rule 6): AXIAM
    /// answers an internal fault `500 {"error":"server_error"}`, and this call
    /// returns it as [`AxiamError::Network`] (`oauth_error_code()` is `None`),
    /// not as an authentication error. It is retried inside this call under the
    /// bounded read-only policy of §16 (at most three attempts; off with
    /// `.retry_enabled(false)`); a `429` and every other `4xx` are returned at
    /// once, never retried.
    ///
    /// Most callers want [`Self::device_login`] instead.
    pub async fn device_poll(&self, params: DevicePollParams) -> Result<OidcTokenSet, AxiamError> {
        self.device_poll_step(params, None).await.map_err(|f| f.err)
    }

    /// [`Self::device_poll`], keeping the `Retry-After` of a failed poll for
    /// [`Self::device_login`]'s loop. `bound`, when set, is the loop's deadline
    /// and clock: a §16 retry here never waits past it, and no request follows
    /// it (`expired_token` is then the outcome).
    async fn device_poll_step(
        &self,
        params: DevicePollParams,
        bound: Option<&crate::retry::RetryBound<'_>>,
    ) -> Result<OidcTokenSet, PollFailure> {
        use crate::retry::{
            Attempt, RetryRunner, ThreadRngJitter, TokioSleeper, parse_retry_after,
        };
        let configuration = match params.configuration {
            Some(c) => c,
            None => self.oidc_discover().await.map_err(PollFailure::from)?,
        };
        let tenant_id = self
            .resolve_oidc_tenant_id(params.tenant_id)
            .await
            .map_err(PollFailure::from)?;
        let client_id = self
            .oidc_client_id_or_err()
            .map_err(PollFailure::from)?
            .to_string();
        let endpoint = self
            .mtls_preferred(
                &configuration,
                |a| a.token_endpoint.as_deref(),
                &configuration.token_endpoint,
            )
            .map_err(PollFailure::from)?;
        let url = self
            .oidc_endpoint_url(endpoint, tenant_id)
            .map_err(PollFailure::from)?;

        // §14.1 rules 2 and 3: the poll names its client on every request and
        // carries the credential `device_authorize` carried.
        let client_secret = self.oidc_client_secret().map(|s| s.expose().clone());
        let form = DeviceTokenForm {
            grant_type: DEVICE_CODE_GRANT_TYPE,
            device_code: params.device_code.expose().as_str(),
            client_id: &client_id,
            client_secret: client_secret.as_deref(),
        };

        // §14.2 rule 6, §16.2: a `5xx` or a transport failure is retried under
        // the bounded read-only policy, inside this one poll attempt (the
        // budget is per poll, separate from the grant's own loop). Every
        // `4xx` — the `400` answers and the `429` wait among them — is
        // decisive here and is returned to the loop, never retried.
        let runner = RetryRunner {
            enabled: self.retry_enabled(),
            operation: "device_poll",
            telemetry: self.telemetry(),
            jitter: &ThreadRngJitter,
            sleeper: &TokioSleeper,
        };
        let (url, form) = (&url, &form);
        let wire = runner
            .run_until(bound, |_| async move {
                let response = self
                    .oauth2_post(url.clone())
                    .form(form)
                    .send()
                    .await
                    .map_err(|e| {
                        // The text names the kind of failure, not the
                        // transport error's own message: the §16 runner hands
                        // this error's text to the §19 telemetry sink, and the
                        // original stays reachable as the error's `source`.
                        let kind = if e.is_timeout() {
                            "timed out"
                        } else if is_connect_error(&e) {
                            "could not connect"
                        } else {
                            "transport error"
                        };
                        Attempt::bare(AxiamError::Network {
                            message: format!("device token request failed: {kind}"),
                            source: Some(Box::new(e)),
                        })
                    })?;

                if !response.status().is_success() {
                    let retry_after = response
                        .headers()
                        .get(reqwest::header::RETRY_AFTER)
                        .and_then(|v| v.to_str().ok())
                        .and_then(parse_retry_after);
                    let status = response.status().as_u16();
                    // The status is read before the body: a `5xx` is the §2
                    // `NetworkError` whatever it says (AXIAM answers a fault
                    // `500 {"error":"server_error"}`), as `ciba_poll` does.
                    //
                    // The message is the status alone, never the server's body:
                    // the §16 runner hands this error's text to the §19
                    // telemetry sink, and the status is all a retry decision or a
                    // caller needs.
                    if status >= 500 {
                        return Err(Attempt {
                            err: AxiamError::from_http_status(
                                status,
                                format!("device token request failed: HTTP {status}"),
                            ),
                            retry_after,
                        });
                    }
                    return Ok(Err(PollFailure {
                        err: oauth2_error_or_fallback(response).await,
                        retry_after,
                        status: Some(status),
                    }));
                }

                // The 200 is consumed outside the retry: the grant may already
                // be redeemed, so a body that does not parse is not re-sent.
                Ok(response
                    .json::<super::exchange::TokenResponseWire>()
                    .await
                    .map_err(|e| {
                        PollFailure::from(AxiamError::Network {
                            message: format!("failed to parse device token response: {e}"),
                            source: Some(Box::new(e)),
                        })
                    }))
            })
            .await
            .map_err(|ended| {
                if ended.at_deadline {
                    // The retry's wait ended at the deadline: no request
                    // follows it (§14.2 rule 4).
                    return PollFailure::from(device_expired());
                }
                // What outlived §16's retries is a transport failure or a
                // `5xx`: the loop's next interval, not a verdict.
                PollFailure::from(ended.err)
            })??;

        // No nonce: the device grant has no authorization request to carry
        // one, and §12.4 rule 6 applies to the authorization-code flow.
        self.to_token_set(wire, &configuration, None)
            .await
            .map_err(PollFailure::from)
    }

    /// The composed §14.3 helper: start the grant, hand the caller the user
    /// code, poll to completion.
    ///
    /// `on_user_code` is invoked with the [`DeviceAuthorization`] **before
    /// the first poll** — §14.3 rule 2 requires the caller to have had the
    /// chance to display the code before polling begins. The SDK never
    /// prints it: what the device does with it (screen, QR code, e-ink
    /// panel) is the application's decision.
    ///
    /// # Returns
    ///
    /// The [`OidcTokenSet`]. Per §14.3 rule 4 (contract 1.7 errata) this SDK
    /// **does not adopt** it as the client's own credential: adoption is the
    /// same MAY as `login_client_credentials`, where the Rust SDK's settled
    /// posture is to leave the tokens with the caller. Returning them and
    /// letting the application decide is the same thing `oidc_exchange`
    /// does, and §12.3 rule 1's stateless-by-default rule is why.
    ///
    /// # Polling
    ///
    /// Per §14.2: the interval comes from the response; `slow_down` adds
    /// [`SLOW_DOWN_INCREMENT_SECS`] **permanently**; `authorization_pending`
    /// loops; `access_denied` and `expired_token` raise distinct errors;
    /// polling stops at `expires_in` even if the server has not yet said
    /// `expired_token`.
    ///
    /// A `5xx` or transport failure mid-poll is **not** terminal (§14.2
    /// rule 6) — the loop absorbs it and tries again on the next tick,
    /// bounded by the same deadline. A server restart must not lose a grant
    /// the user has already approved.
    ///
    /// A `429 rate_limit_exceeded` is not terminal either (§14.2 rule 9,
    /// contract 1.64): the loop waits the `Retry-After` as a minimum (never
    /// less than one interval, and capped at the `expires_in` deadline),
    /// counts the wait as one interval, does **not** raise the interval for
    /// it, and polls again. Only the `400 slow_down` raises the interval.
    pub async fn device_login<F>(
        &self,
        params: DeviceLoginParams,
        on_user_code: F,
    ) -> Result<OidcTokenSet, AxiamError>
    where
        F: FnOnce(&DeviceAuthorization),
    {
        self.device_login_with(
            params,
            on_user_code,
            &crate::retry::TokioSleeper,
            &crate::time::Instant::now,
        )
        .await
    }

    /// [`Self::device_login`] on an injected clock, so the §14.6 tests record
    /// the waits instead of sleeping them.
    pub(crate) async fn device_login_with<F>(
        &self,
        params: DeviceLoginParams,
        on_user_code: F,
        sleeper: &dyn crate::retry::Sleeper,
        now: &(dyn Fn() -> crate::time::Instant + Send + Sync),
    ) -> Result<OidcTokenSet, AxiamError>
    where
        F: FnOnce(&DeviceAuthorization),
    {
        let configuration = match params.configuration {
            Some(c) => c,
            None => self.oidc_discover().await?,
        };

        let authorization = self
            .device_authorize(DeviceAuthorizeParams {
                scope: params.scope,
                tenant_id: params.tenant_id,
                configuration: Some(configuration.clone()),
            })
            .await?;

        // §14.3 rule 2 — before any polling.
        on_user_code(&authorization);

        // The deadline is a point on the clock, anchored when the grant was
        // issued: request round trips, the callback above and slow answers
        // count against it, not only the waits (§14.2 rule 4, C164-05).
        let deadline = now() + std::time::Duration::from_secs(authorization.expires_in);
        let mut schedule = PollSchedule::new(authorization.interval, authorization.expires_in);
        // A §16 retry inside a poll is served on this loop's clock and never
        // waits past the deadline (the P10 pattern `ciba_await` follows).
        let retry_bound = crate::retry::RetryBound {
            deadline,
            now,
            sleeper,
        };
        // The `Retry-After` of a `429` poll, which stands in for the next
        // interval when it is longer (§14.2 rule 9).
        let mut retry_after_secs = 0;

        loop {
            // §14.2 rule 4: the deadline is authoritative. Checking *before*
            // sleeping keeps the SDK from issuing a request that can only be
            // refused, and reports the outcome under the same `expired_token`
            // code the server would have used — so a caller's match arm does
            // not care which side noticed first.
            let wait_secs = schedule.interval_secs().max(retry_after_secs);
            retry_after_secs = 0;
            let wait = std::time::Duration::from_secs(wait_secs);
            if now() + wait >= deadline {
                return Err(device_expired());
            }

            sleeper.sleep(wait).await;
            if now() >= deadline {
                return Err(device_expired());
            }

            match self
                .device_poll_step(
                    DevicePollParams {
                        device_code: authorization.device_code.clone(),
                        tenant_id: params.tenant_id,
                        configuration: Some(configuration.clone()),
                    },
                    Some(&retry_bound),
                )
                .await
            {
                Ok(tokens) => return Ok(tokens),
                Err(failure) => match classify_failure(&failure) {
                    PollOutcome::Pending | PollOutcome::Transient => continue,
                    PollOutcome::SlowDown => {
                        // §14.2 rule 1: cumulative, and never reset.
                        schedule.slow_down();
                        continue;
                    }
                    PollOutcome::RateLimited => {
                        retry_after_secs = failure.retry_after.map_or(0, |d| d.as_secs());
                        continue;
                    }
                    PollOutcome::Terminal => {
                        let e = failure.err;
                        // §14.2 rule 6: a transport/5xx failure is not one of
                        // the five protocol answers and is not terminal.
                        // `oauth_error_code()` is `None` for those, which is
                        // exactly what distinguishes them here.
                        if e.oauth_error_code().is_none() && e.is_retryable_transport() {
                            continue;
                        }
                        return Err(e);
                    }
                },
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // §14.2 rule 2 — the interval comes from the response.
    #[test]
    fn zero_or_absent_interval_falls_back_to_the_rfc_default() {
        assert_eq!(
            PollSchedule::new(0, 600).interval_secs(),
            DEFAULT_POLL_INTERVAL_SECS
        );
        assert_eq!(PollSchedule::new(7, 600).interval_secs(), 7);
    }

    // §14.2 rule 1 — the increase is permanent and cumulative. This is the
    // rule implementations get wrong: backing off for one round and then
    // returning to the original interval earns another `slow_down`, forever.
    #[test]
    fn slow_down_is_cumulative_and_never_resets() {
        let mut s = PollSchedule::new(5, 1800);
        s.slow_down();
        assert_eq!(s.interval_secs(), 10);
        s.slow_down();
        assert_eq!(s.interval_secs(), 15);

        // Ticking (i.e. polling on) must not undo the raise.
        s.tick();
        s.tick();
        assert_eq!(
            s.interval_secs(),
            15,
            "the raised interval persists across polls"
        );
    }

    // §14.2 rule 4 — polling stops at expires_in.
    #[test]
    fn tick_reports_the_deadline_and_stops() {
        let mut s = PollSchedule::new(5, 12);
        assert!(s.tick(), "t=5");
        assert!(s.tick(), "t=10");
        assert!(!s.tick(), "t=15 is past the 12 s deadline");
    }

    #[test]
    fn a_slowed_interval_can_exhaust_the_grant_early() {
        // A grant with 20 s left and a 5 s interval has room for three more
        // polls; two `slow_down`s make the next one 15 s and the one after
        // that impossible. The deadline still wins.
        let mut s = PollSchedule::new(5, 20);
        assert!(s.tick());
        s.slow_down();
        s.slow_down();
        assert_eq!(s.interval_secs(), 15);
        assert!(!s.tick(), "15 s does not fit in the 15 s remaining");
    }

    #[test]
    fn an_interval_equal_to_the_whole_grant_never_polls() {
        let mut s = PollSchedule::new(30, 30);
        assert!(
            !s.tick(),
            "the first poll would land exactly on the deadline"
        );
    }

    // §14.2 rule 5 — dispatch on the `error` field, not the status code.
    #[test]
    fn classification_covers_the_five_rfc_8628_answers() {
        let cases = [
            ("authorization_pending", PollOutcome::Pending),
            ("slow_down", PollOutcome::SlowDown),
            ("expired_token", PollOutcome::Terminal),
            ("access_denied", PollOutcome::Terminal),
            ("invalid_grant", PollOutcome::Terminal),
        ];
        for (code, want) in cases {
            let err = AxiamError::oauth_protocol_error(code, "d");
            assert_eq!(classify(&err), want, "{code}");
        }
    }

    #[test]
    fn a_transport_failure_is_neither_pending_nor_a_protocol_answer() {
        let err = AxiamError::network("connection reset");
        assert_eq!(err.oauth_error_code(), None);
        assert!(err.is_retryable_transport());
        // Classified Terminal, but the loop consults `is_retryable_transport`
        // for exactly this case (§14.2 rule 6) and keeps polling.
        assert_eq!(classify(&err), PollOutcome::Terminal);
    }

    // --- §14.6 (contract 1.64): a `429` on a poll is waited out -----------

    use crate::client::AxiamClient;
    use crate::oidc::DeviceLoginParams;
    use crate::retry::Sleeper;
    use serde_json::json;
    use std::sync::Mutex;
    use std::time::Duration;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// Records the waits instead of sleeping them (no wall clock).
    #[derive(Default)]
    struct Recorded(Mutex<Vec<Duration>>);

    impl Sleeper for Recorded {
        fn sleep(&self, d: Duration) -> std::pin::Pin<Box<dyn Future<Output = ()> + Send + '_>> {
            self.0.lock().unwrap().push(d);
            Box::pin(std::future::ready(()))
        }
    }

    /// A mock authorization server whose `/oauth2/token` answers from `script`
    /// in order (the last answer repeats), and a client for it. `expires_in` is
    /// the grant's lifetime; the interval is 5 s.
    async fn device_fixture(
        script: Vec<ResponseTemplate>,
        expires_in: u64,
    ) -> (
        MockServer,
        AxiamClient,
        std::sync::Arc<std::sync::atomic::AtomicUsize>,
    ) {
        device_fixture_with(script, expires_in, std::sync::Arc::new(|| {}), true).await
    }

    /// [`device_fixture`], running `on_poll` as each poll arrives (a fake
    /// clock advances by the request's duration there).
    async fn device_fixture_with(
        script: Vec<ResponseTemplate>,
        expires_in: u64,
        on_poll: std::sync::Arc<dyn Fn() + Send + Sync>,
        retry: bool,
    ) -> (
        MockServer,
        AxiamClient,
        std::sync::Arc<std::sync::atomic::AtomicUsize>,
    ) {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let server = MockServer::start().await;
        let base = server.uri();
        Mock::given(method("GET"))
            .and(path("/.well-known/openid-configuration"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "issuer": "https://iam.example.com",
                "authorization_endpoint": format!("{base}/oauth2/authorize"),
                "token_endpoint": format!("{base}/oauth2/token"),
                "userinfo_endpoint": format!("{base}/oauth2/userinfo"),
                "jwks_uri": format!("{base}/oauth2/jwks"),
                "revocation_endpoint": format!("{base}/oauth2/revoke"),
                "introspection_endpoint": format!("{base}/oauth2/introspect"),
                "scopes_supported": ["openid"],
                "token_endpoint_auth_methods_supported": ["client_secret_post"],
                "claims_supported": ["sub"],
                "grant_types_supported": ["urn:ietf:params:oauth:grant-type:device_code"],
                "device_authorization_endpoint": format!("{base}/oauth2/device_authorization"),
                "response_types_supported": ["code"],
                "subject_types_supported": ["public"],
                "id_token_signing_alg_values_supported": ["EdDSA"],
            })))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/oauth2/device_authorization"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "device_code": "dc",
                "user_code": "WDJB-MJHT",
                "verification_uri": "https://iam.example.com/device",
                "expires_in": expires_in,
                "interval": 5,
            })))
            .mount(&server)
            .await;
        let polls = std::sync::Arc::new(AtomicUsize::new(0));
        let seen = std::sync::Arc::clone(&polls);
        let script = Mutex::new(script);
        let on_poll = std::sync::Arc::clone(&on_poll);
        Mock::given(method("POST"))
            .and(path("/oauth2/token"))
            .respond_with(move |_: &wiremock::Request| {
                on_poll();
                let i = seen.fetch_add(1, Ordering::SeqCst);
                let script = script.lock().unwrap();
                script
                    .get(i)
                    .or(script.last())
                    .cloned()
                    .expect("non-empty script")
            })
            .mount(&server)
            .await;
        let client = AxiamClient::builder()
            .base_url(&base)
            .expect("valid base url")
            .tenant_id(uuid::Uuid::nil())
            .org_id(uuid::Uuid::nil())
            .oidc_client_id("axiam-rp")
            .retry_enabled(retry)
            .build()
            .expect("client builds");
        (server, client, polls)
    }

    fn rate_limited(retry_after: &str) -> ResponseTemplate {
        ResponseTemplate::new(429)
            .insert_header("Retry-After", retry_after)
            .set_body_json(json!({"error": "rate_limit_exceeded"}))
    }

    fn pending() -> ResponseTemplate {
        ResponseTemplate::new(400).set_body_json(json!({"error": "authorization_pending"}))
    }

    fn tokens() -> ResponseTemplate {
        ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "device-access-token",
            "token_type": "Bearer",
            "expires_in": 900,
        }))
    }

    // §14.6: one poll answered `429` + `Retry-After`; the loop waits at least
    // that long, polls again, completes, and the interval is unchanged.
    #[tokio::test]
    async fn a_429_on_a_poll_is_waited_out_and_the_interval_is_unchanged() {
        let (_server, client, polls) =
            device_fixture(vec![rate_limited("12"), pending(), tokens()], 600).await;
        let sleeps = Recorded::default();
        let set = client
            .device_login_with(
                DeviceLoginParams::default(),
                |_| {},
                &sleeps,
                &crate::time::Instant::now,
            )
            .await
            .expect("the loop completes after the 429");
        assert_eq!(set.access_token.expose(), "device-access-token");
        assert_eq!(polls.load(std::sync::atomic::Ordering::SeqCst), 3);
        let secs: Vec<u64> = sleeps
            .0
            .lock()
            .unwrap()
            .iter()
            .map(|d| d.as_secs())
            .collect();
        // interval, then the Retry-After (a minimum, above the interval), then
        // the interval again: not 10 s, as a `slow_down` would have made it.
        assert_eq!(secs, [5, 12, 5]);
    }

    // A `Retry-After` shorter than the interval does not shorten the wait.
    #[tokio::test]
    async fn a_short_retry_after_never_goes_below_the_interval() {
        let (_server, client, _) = device_fixture(vec![rate_limited("1"), tokens()], 600).await;
        let sleeps = Recorded::default();
        client
            .device_login_with(
                DeviceLoginParams::default(),
                |_| {},
                &sleeps,
                &crate::time::Instant::now,
            )
            .await
            .expect("completes");
        let secs: Vec<u64> = sleeps
            .0
            .lock()
            .unwrap()
            .iter()
            .map(|d| d.as_secs())
            .collect();
        assert_eq!(secs, [5, 5]);
    }

    // A `Retry-After` past the `expires_in` deadline is capped at it: the
    // typed `expired_token` outcome, and nothing is sent after the deadline.
    #[tokio::test]
    async fn a_retry_after_past_the_deadline_ends_in_expired_token() {
        let (_server, client, polls) =
            device_fixture(vec![rate_limited("3600"), tokens()], 60).await;
        let sleeps = Recorded::default();
        let err = client
            .device_login_with(
                DeviceLoginParams::default(),
                |_| {},
                &sleeps,
                &crate::time::Instant::now,
            )
            .await
            .expect_err("the deadline wins");
        assert_eq!(err.oauth_error_code(), Some("expired_token"));
        assert_eq!(polls.load(std::sync::atomic::Ordering::SeqCst), 1);
        let secs: Vec<u64> = sleeps
            .0
            .lock()
            .unwrap()
            .iter()
            .map(|d| d.as_secs())
            .collect();
        assert_eq!(secs, [5], "no wait is served past the deadline");
    }

    #[test]
    fn a_retry_after_wait_counts_as_one_interval_and_keeps_the_interval() {
        let mut s = PollSchedule::new(5, 100);
        assert!(s.tick_for(30));
        assert_eq!(s.interval_secs(), 5);
        assert!(!s.tick_for(70), "the wait that reaches the deadline stops");
    }

    fn server_error() -> ResponseTemplate {
        ResponseTemplate::new(500)
            .set_body_json(json!({"error": "server_error", "error_description": "db"}))
    }

    // §14.2 rule 6 (contract 1.64 amended; C164-03): a `5xx` is a transport
    // failure whatever its body. AXIAM's own datastore fault is
    // `500 {"error":"server_error"}`; it does not end the flow.
    #[tokio::test]
    async fn a_500_with_an_error_body_mid_poll_is_not_terminal() {
        let (_server, client, polls) =
            device_fixture(vec![server_error(), pending(), tokens()], 600).await;
        let sleeps = Recorded::default();
        client
            .device_login_with(
                DeviceLoginParams::default(),
                |_| {},
                &sleeps,
                &crate::time::Instant::now,
            )
            .await
            .expect("a 500 mid-poll does not lose the grant");
        assert_eq!(polls.load(std::sync::atomic::Ordering::SeqCst), 3);
        // The interval, the §16 backoff inside the poll that met the 500, and
        // the interval again: not a raised interval.
        let waits = sleeps.0.lock().unwrap().clone();
        assert_eq!(waits.len(), 3);
        assert_eq!(waits[0], Duration::from_secs(5));
        assert!(
            waits[1] <= Duration::from_millis(200),
            "unexpected retry waits"
        );
        assert_eq!(waits[2], Duration::from_secs(5));
    }

    // §14.2 rule 9 (amended; C164-04): the status decides. A `429` whose body
    // says `slow_down` is the wait, and does not raise the interval.
    #[tokio::test]
    async fn a_429_slow_down_waits_and_does_not_raise_the_interval() {
        let slow = ResponseTemplate::new(429)
            .insert_header("Retry-After", "1")
            .set_body_json(json!({"error": "slow_down"}));
        let (_server, client, _) = device_fixture(vec![slow, pending(), tokens()], 600).await;
        let sleeps = Recorded::default();
        client
            .device_login_with(
                DeviceLoginParams::default(),
                |_| {},
                &sleeps,
                &crate::time::Instant::now,
            )
            .await
            .expect("completes");
        let secs: Vec<u64> = sleeps
            .0
            .lock()
            .unwrap()
            .iter()
            .map(|d| d.as_secs())
            .collect();
        assert_eq!(secs, [5, 5, 5]);
    }

    // The `400 slow_down` is the one that raises it (rule 1), unchanged.
    #[tokio::test]
    async fn a_400_slow_down_still_raises_the_interval() {
        let slow = ResponseTemplate::new(400).set_body_json(json!({"error": "slow_down"}));
        let (_server, client, _) = device_fixture(vec![slow, tokens()], 600).await;
        let sleeps = Recorded::default();
        client
            .device_login_with(
                DeviceLoginParams::default(),
                |_| {},
                &sleeps,
                &crate::time::Instant::now,
            )
            .await
            .expect("completes");
        let secs: Vec<u64> = sleeps
            .0
            .lock()
            .unwrap()
            .iter()
            .map(|d| d.as_secs())
            .collect();
        assert_eq!(secs, [5, 10]);
    }

    // A bodiless `429` honours `Retry-After` as a floor (rule 9).
    #[tokio::test]
    async fn a_bodiless_429_honours_retry_after() {
        let bare = ResponseTemplate::new(429).insert_header("Retry-After", "12");
        let (_server, client, _) = device_fixture(vec![bare, tokens()], 600).await;
        let sleeps = Recorded::default();
        client
            .device_login_with(
                DeviceLoginParams::default(),
                |_| {},
                &sleeps,
                &crate::time::Instant::now,
            )
            .await
            .expect("completes");
        let secs: Vec<u64> = sleeps
            .0
            .lock()
            .unwrap()
            .iter()
            .map(|d| d.as_secs())
            .collect();
        assert_eq!(secs, [5, 12]);
    }

    /// A clock the test moves: the sleeper advances it by the wait, and the
    /// mock advances it by the time a poll took.
    struct FakeClock {
        base: crate::time::Instant,
        offset_secs: std::sync::atomic::AtomicU64,
        waits: Mutex<Vec<Duration>>,
    }

    impl FakeClock {
        fn now(&self) -> crate::time::Instant {
            self.base
                + Duration::from_secs(self.offset_secs.load(std::sync::atomic::Ordering::SeqCst))
        }
    }

    impl Sleeper for FakeClock {
        fn sleep(&self, d: Duration) -> std::pin::Pin<Box<dyn Future<Output = ()> + Send + '_>> {
            self.waits.lock().unwrap().push(d);
            self.offset_secs
                .fetch_add(d.as_secs(), std::sync::atomic::Ordering::SeqCst);
            Box::pin(std::future::ready(()))
        }
    }

    // §14.2 rule 4 (C164-05): the deadline is `authorization time +
    // expires_in` on the clock, so the time a poll takes counts against it.
    // `expires_in` 60, interval 5, each poll takes 30 s: a poll at t=5 ends at
    // 35, the next waits to 40 and ends at 70, and nothing follows.
    #[tokio::test]
    async fn the_time_a_poll_takes_counts_against_the_deadline() {
        let clock = std::sync::Arc::new(FakeClock {
            base: crate::time::Instant::now(),
            offset_secs: std::sync::atomic::AtomicU64::new(0),
            waits: Mutex::new(Vec::new()),
        });
        let tick = std::sync::Arc::clone(&clock);
        let (_server, client, polls) = device_fixture_with(
            vec![pending()],
            60,
            std::sync::Arc::new(move || {
                tick.offset_secs
                    .fetch_add(30, std::sync::atomic::Ordering::SeqCst);
            }),
            true,
        )
        .await;
        let reader = std::sync::Arc::clone(&clock);
        let err = client
            .device_login_with(DeviceLoginParams::default(), |_| {}, &*clock, &move || {
                reader.now()
            })
            .await
            .expect_err("the deadline wins");
        assert_eq!(err.oauth_error_code(), Some("expired_token"));
        assert_eq!(polls.load(std::sync::atomic::Ordering::SeqCst), 2);
        let secs: Vec<u64> = clock
            .waits
            .lock()
            .unwrap()
            .iter()
            .map(|d| d.as_secs())
            .collect();
        assert_eq!(secs, [5, 5]);
    }

    fn run_params() -> DeviceLoginParams {
        DeviceLoginParams::default()
    }

    async fn login_recording(
        client: &AxiamClient,
        sleeps: &Recorded,
    ) -> Result<crate::oidc::OidcTokenSet, AxiamError> {
        client
            .device_login_with(run_params(), |_| {}, sleeps, &crate::time::Instant::now)
            .await
    }

    fn waits_of(sleeps: &Recorded) -> Vec<Duration> {
        sleeps.0.lock().unwrap().clone()
    }

    // §14.2 rule 6, §16.2 (C164-25): with retry on, the poll that meets a 5xx
    // retries inside the attempt (at most three), so the loop completes in one
    // interval; with retry off there is one request per poll.
    #[tokio::test]
    async fn a_5xx_is_retried_inside_the_poll() {
        let (_server, client, polls) =
            device_fixture(vec![server_error(), server_error(), tokens()], 600).await;
        let sleeps = Recorded::default();
        login_recording(&client, &sleeps).await.expect("completes");
        assert_eq!(polls.load(std::sync::atomic::Ordering::SeqCst), 3);
        let waits = waits_of(&sleeps);
        assert_eq!(waits.len(), 3, "unexpected retry waits");
        assert_eq!(waits[0], Duration::from_secs(5), "the one interval");
        assert!(
            waits[1] <= Duration::from_millis(200),
            "unexpected retry waits"
        );
        assert!(
            waits[2] <= Duration::from_millis(400),
            "unexpected retry waits"
        );
    }

    #[tokio::test]
    async fn with_retry_off_a_5xx_costs_an_interval() {
        let (_server, client, polls) = device_fixture_with(
            vec![server_error(), server_error(), tokens()],
            600,
            std::sync::Arc::new(|| {}),
            false,
        )
        .await;
        let sleeps = Recorded::default();
        login_recording(&client, &sleeps).await.expect("completes");
        assert_eq!(polls.load(std::sync::atomic::Ordering::SeqCst), 3);
        assert_eq!(waits_of(&sleeps), [Duration::from_secs(5); 3]);
    }

    // A 5xx's Retry-After is the retry's floor (§16.1).
    #[tokio::test]
    async fn a_5xx_retry_after_is_a_floor_inside_the_poll() {
        let busy = ResponseTemplate::new(503)
            .insert_header("Retry-After", "9")
            .set_body_json(json!({"error": "temporarily_unavailable"}));
        let (_server, client, _) = device_fixture(vec![busy, tokens()], 600).await;
        let sleeps = Recorded::default();
        login_recording(&client, &sleeps).await.expect("completes");
        assert_eq!(
            waits_of(&sleeps),
            [Duration::from_secs(5), Duration::from_secs(9)]
        );
    }

    // The retry never waits past the deadline: the typed `expired_token`.
    #[tokio::test]
    async fn a_retry_wait_is_capped_at_the_deadline_and_ends_in_expired_token() {
        let busy = ResponseTemplate::new(503).insert_header("Retry-After", "3600");
        let (_server, client, polls) = device_fixture(vec![busy, tokens()], 60).await;
        let sleeps = Recorded::default();
        let err = login_recording(&client, &sleeps)
            .await
            .expect_err("the deadline wins");
        assert_eq!(err.oauth_error_code(), Some("expired_token"));
        assert_eq!(polls.load(std::sync::atomic::Ordering::SeqCst), 1);
        // The interval, then the retry's wait capped at the time left (§33.7
        // rule 5 allows serving it); nothing is sent after the deadline.
        let waits = waits_of(&sleeps);
        assert_eq!(waits.len(), 2, "unexpected retry waits");
        assert_eq!(waits[0], Duration::from_secs(5));
        assert!(waits[1] < Duration::from_secs(60), "unexpected retry waits");
        assert!(waits[1] > Duration::from_secs(50), "unexpected retry waits");
    }

    fn poll_params() -> DevicePollParams {
        DevicePollParams {
            device_code: crate::Sensitive::new("dc".to_string()),
            tenant_id: None,
            configuration: None,
        }
    }

    // §14.2 rule 6 (C164-27): the single `device_poll` types a 5xx as the §2
    // `NetworkError` whatever its body, so a hand-rolled loop does not end on
    // it. Retry off: one request.
    #[tokio::test]
    async fn a_single_device_poll_types_a_5xx_as_a_network_error() {
        for answer in [
            server_error(),
            ResponseTemplate::new(503).set_body_json(json!({"error": "temporarily_unavailable"})),
        ] {
            let (_server, client, polls) =
                device_fixture_with(vec![answer], 600, std::sync::Arc::new(|| {}), false).await;
            let err = client
                .device_poll(poll_params())
                .await
                .expect_err("a 5xx is an error");
            assert!(
                matches!(err, AxiamError::Network { .. }),
                "expected a network error"
            );
            assert_eq!(err.oauth_error_code(), None);
            assert!(err.is_retryable_transport());
            assert_eq!(polls.load(std::sync::atomic::Ordering::SeqCst), 1);
        }
    }

    // With retry on, the single poll also retries inside the attempt, and a
    // 429 is returned at once (the wait is the caller's).
    #[tokio::test]
    async fn a_single_device_poll_retries_a_5xx_but_not_a_429() {
        let (_server, client, polls) =
            device_fixture(vec![server_error(), server_error(), tokens()], 600).await;
        let set = client.device_poll(poll_params()).await.expect("recovers");
        assert_eq!(set.access_token.expose(), "device-access-token");
        assert_eq!(polls.load(std::sync::atomic::Ordering::SeqCst), 3);

        let (_server, client, polls) = device_fixture(vec![rate_limited("1"), tokens()], 600).await;
        let err = client.device_poll(poll_params()).await.expect_err("429");
        assert_eq!(err.oauth_error_code(), Some("rate_limit_exceeded"));
        assert_eq!(polls.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    // §14.6 (contract 1.64 amended): a third 5xx in a row exhausts the cap of
    // three attempts; the poll surfaces the failure, and the loop takes its
    // next interval.
    #[tokio::test]
    async fn three_5xx_exhaust_the_attempt_cap() {
        let (_server, client, polls) = device_fixture(
            vec![server_error(), server_error(), server_error(), tokens()],
            600,
        )
        .await;
        let err = client
            .device_poll(poll_params())
            .await
            .expect_err("three attempts, all 5xx");
        assert!(
            matches!(err, AxiamError::Network { .. }),
            "expected a network error"
        );
        assert_eq!(polls.load(std::sync::atomic::Ordering::SeqCst), 3);

        let sleeps = Recorded::default();
        login_recording(&client, &sleeps).await.expect("completes");
        // The 4th request (the tokens) is the first of the loop's poll.
        assert_eq!(polls.load(std::sync::atomic::Ordering::SeqCst), 4);
        assert_eq!(waits_of(&sleeps), [Duration::from_secs(5)]);
    }
}

/// CONTRACT.md §7 rule 1: these wire structs hold the plaintext of a value
/// the public type wraps in `Sensitive`, so none of them may be `Debug`.
#[cfg(test)]
mod wire_redaction_tests {
    #[test]
    fn no_wire_struct_holding_a_secret_is_debug() {
        assert!(
            !crate::sensitive::implements_debug!(super::DeviceAuthorizationResponseWire),
            "DeviceAuthorizationResponseWire is Debug"
        );
    }
}
