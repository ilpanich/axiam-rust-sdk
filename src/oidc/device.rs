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
use crate::rest::auth::CsrfHeaderExt;
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

#[derive(Serialize)]
struct DeviceAuthorizationForm<'a> {
    client_id: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    scope: Option<&'a str>,
}

#[derive(Serialize)]
struct DeviceTokenForm<'a> {
    grant_type: &'a str,
    device_code: &'a str,
    client_id: &'a str,
}

#[derive(Debug, Deserialize)]
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
    /// `expired_token`, `access_denied`, `invalid_grant`, or anything else.
    Terminal,
}

/// The §14.2 polling schedule: the interval, and the deadline it stops at.
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

    /// Consume one interval's worth of the grant's remaining life.
    ///
    /// Returns `false` when the deadline has been reached, at which point the
    /// caller MUST stop (§14.2 rule 4) — the deadline is authoritative even
    /// if the server is still answering `authorization_pending`.
    pub fn tick(&mut self) -> bool {
        if self.interval_secs >= self.remaining_secs {
            self.remaining_secs = 0;
            return false;
        }
        self.remaining_secs -= self.interval_secs;
        true
    }
}

fn classify(err: &AxiamError) -> PollOutcome {
    match err.oauth_error_code() {
        Some("authorization_pending") => PollOutcome::Pending,
        Some("slow_down") => PollOutcome::SlowDown,
        _ => PollOutcome::Terminal,
    }
}

impl AxiamClient {
    /// `POST /oauth2/device_authorization` (CONTRACT.md §14.1) — start the
    /// grant and obtain the code pair.
    ///
    /// **Unauthenticated by design.** A device that cannot show a browser
    /// also cannot hold a client secret, so this operation never sends
    /// `client_secret` and never refuses a client built without one (§14.1).
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

        let endpoint = configuration.device_authorization_endpoint.as_deref().ok_or_else(|| {
            AxiamError::Auth {
                message:
                    "the authorization server's discovery document advertises no device_authorization_endpoint: this server does not support the device grant (CONTRACT.md §14.1)"
                        .into(),
                oauth: None,
                reason: None,
            }
        })?;
        let url = self.oidc_endpoint_url(endpoint, tenant_id)?;

        let form = DeviceAuthorizationForm {
            client_id: &client_id,
            scope: params.scope.as_deref(),
        };

        let response = self
            .http()
            .post(url)
            .header("X-Tenant-ID", self.tenant_header_value())
            .maybe_csrf_header(self)
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
    /// a hand-rolled loop sees exactly what [`Self::device_login`] sees.
    ///
    /// Most callers want [`Self::device_login`] instead.
    pub async fn device_poll(&self, params: DevicePollParams) -> Result<OidcTokenSet, AxiamError> {
        let configuration = match params.configuration {
            Some(c) => c,
            None => self.oidc_discover().await?,
        };
        let tenant_id = self.resolve_oidc_tenant_id(params.tenant_id).await?;
        let client_id = self.oidc_client_id_or_err()?.to_string();
        let url = self.oidc_endpoint_url(&configuration.token_endpoint, tenant_id)?;

        let form = DeviceTokenForm {
            grant_type: DEVICE_CODE_GRANT_TYPE,
            device_code: params.device_code.expose().as_str(),
            client_id: &client_id,
        };

        let response = self
            .http()
            .post(url)
            .header("X-Tenant-ID", self.tenant_header_value())
            .maybe_csrf_header(self)
            .form(&form)
            .send()
            .await
            .map_err(|e| AxiamError::Network {
                message: format!("device token request failed: {e}"),
                source: Some(Box::new(e)),
            })?;

        if !response.status().is_success() {
            return Err(oauth2_error_or_fallback(response).await);
        }

        let wire = response
            .json::<super::exchange::TokenResponseWire>()
            .await
            .map_err(|e| AxiamError::Network {
                message: format!("failed to parse device token response: {e}"),
                source: Some(Box::new(e)),
            })?;

        // No nonce: the device grant has no authorization request to carry
        // one, and §12.4 rule 6 applies to the authorization-code flow.
        self.to_token_set(wire, &configuration, None).await
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
    pub async fn device_login<F>(
        &self,
        params: DeviceLoginParams,
        on_user_code: F,
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

        let mut schedule = PollSchedule::new(authorization.interval, authorization.expires_in);

        loop {
            // §14.2 rule 4: the deadline is authoritative. Checking *before*
            // sleeping keeps the SDK from issuing a request that can only be
            // refused, and reports the outcome under the same `expired_token`
            // code the server would have used — so a caller's match arm does
            // not care which side noticed first.
            if !schedule.tick() {
                return Err(AxiamError::oauth_protocol_error(
                    "expired_token",
                    "the device authorization expired before the user completed it \
                     (client-side deadline from expires_in; CONTRACT.md §14.2 rule 4)",
                ));
            }

            tokio::time::sleep(std::time::Duration::from_secs(schedule.interval_secs())).await;

            match self
                .device_poll(DevicePollParams {
                    device_code: authorization.device_code.clone(),
                    tenant_id: params.tenant_id,
                    configuration: Some(configuration.clone()),
                })
                .await
            {
                Ok(tokens) => return Ok(tokens),
                Err(e) => match classify(&e) {
                    PollOutcome::Pending => continue,
                    PollOutcome::SlowDown => {
                        // §14.2 rule 1: cumulative, and never reset.
                        schedule.slow_down();
                        continue;
                    }
                    PollOutcome::Terminal => {
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
}
