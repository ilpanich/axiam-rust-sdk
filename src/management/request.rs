//! The one request path every §27 management operation goes through.
//!
//! §27.8 is explicit that the generated layer MUST sit on the SDK's existing
//! request path and MUST NOT build its own. That is what this module is: 147
//! generated operations all funnel into [`AxiamClient::management_send`], so
//! they inherit §3 (CSRF), §4 (the cookie jar), §5 (`X-Tenant-ID`), §6 (TLS),
//! §9 (single-flight refresh), §16 (retry) and §19 (telemetry) by
//! construction rather than by 147 opportunities to forget one.

use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::AxiamError;
use crate::client::AxiamClient;
use crate::rest::auth::CsrfHeaderExt;
use crate::retry::{Attempt, RetryRunner, ThreadRngJitter, TokioSleeper, parse_retry_after};
use crate::telemetry::{Outcome, TelemetryEvent};

/// The HTTP verbs this surface uses.
///
/// A closed set rather than `reqwest::Method`, because [`Self::is_read_only`]
/// is what decides §16 retry eligibility and that decision must not be
/// reachable with a verb nobody considered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Verb {
    /// `GET` — the only retry-eligible verb on this surface.
    Get,
    /// `POST`.
    Post,
    /// `PUT`.
    Put,
    /// `DELETE`.
    Delete,
}

impl Verb {
    fn as_str(self) -> &'static str {
        match self {
            Verb::Get => "GET",
            Verb::Post => "POST",
            Verb::Put => "PUT",
            Verb::Delete => "DELETE",
        }
    }

    /// Whether §16.2 makes this verb retry-eligible.
    ///
    /// **Only `GET`.** §27.4 rule 8 forbids treating any write here as
    /// retriable even when it looks idempotent: `certificates.generate` twice
    /// mints two certificates, and `service_accounts.rotate_secret` twice
    /// invalidates the secret the first call returned and the caller has
    /// already stored.
    fn is_read_only(self) -> bool {
        matches!(self, Verb::Get)
    }

    fn apply(self, client: &AxiamClient, url: url::Url) -> reqwest::RequestBuilder {
        let http = client.http();
        match self {
            Verb::Get => http.get(url),
            Verb::Post => http.post(url),
            Verb::Put => http.put(url),
            Verb::Delete => http.delete(url),
        }
    }
}

/// One management call, fully resolved.
///
/// `path` is interpolated; `path_template` is not, and is what reaches
/// telemetry — §19.1 wants a bounded-cardinality label, and a template with
/// the UUIDs substituted in is a new label per call.
pub(crate) struct Call<'a> {
    /// `"users.create"` — the registry's namespace-qualified operation name.
    pub operation: &'static str,
    pub verb: Verb,
    /// `"/api/v1/users/{user_id}"`, ids **not** substituted.
    pub path_template: &'static str,
    /// The same path with ids substituted, ready to send.
    pub path: String,
    pub query: &'a [(&'static str, String)],
}

impl AxiamClient {
    /// Send a management request and deserialize its body.
    pub(crate) async fn management_send<B, R>(
        &self,
        call: Call<'_>,
        body: Option<&B>,
    ) -> Result<R, AxiamError>
    where
        B: Serialize + ?Sized,
        R: DeserializeOwned,
    {
        let raw = self.management_raw(call, body).await?;
        // An empty body where one was expected is a server contract violation,
        // not a `None` — surfacing it as a parse failure names the actual
        // problem instead of handing back a defaulted struct.
        serde_json::from_slice(&raw).map_err(|e| AxiamError::Network {
            message: format!("failed to parse management response body: {e}"),
            source: Some(Box::new(e)),
        })
    }

    /// Send a management request that answers `204 No Content`.
    ///
    /// Separate from [`Self::management_send`] because `()` does not
    /// deserialize from an empty body, and a `R = ()` overload that silently
    /// accepted any body would hide a server change.
    pub(crate) async fn management_send_no_content<B>(
        &self,
        call: Call<'_>,
        body: Option<&B>,
    ) -> Result<(), AxiamError>
    where
        B: Serialize + ?Sized,
    {
        self.management_raw(call, body).await.map(|_| ())
    }

    /// The shared body: precondition, retry envelope, and the one 401 refresh.
    async fn management_raw<B>(
        &self,
        call: Call<'_>,
        body: Option<&B>,
    ) -> Result<Vec<u8>, AxiamError>
    where
        B: Serialize + ?Sized,
    {
        // §18.1 rule 4: use-after-close is an error, never a silent reconnect.
        self.ensure_open()?;

        // §27.4 rule 1: no session, no wire call. Letting the request go out
        // trades a clear local error for a 401 that then enters the §9 guard
        // and fails there, two indirections from the actual mistake.
        if self.token_manager().cached_access_token().is_none() {
            return Err(AxiamError::auth(format!(
                "{}: no active session — call login() before using the management API",
                call.operation
            )));
        }

        let url = self.management_url(&call.path, call.query)?;
        // Borrowed once, here: the retry runner's closure is `FnMut`, so it may
        // capture references but can never move the call or the URL into itself.
        let call = &call;
        let url = &url;

        // §16.2: only reads are retried, and only through the shared runner so
        // the backoff, jitter and `Retry-After` floor are the contract's rather
        // than this module's.
        let first = if call.verb.is_read_only() {
            let runner = RetryRunner {
                enabled: self.retry_enabled(),
                operation: call.operation,
                telemetry: self.telemetry(),
                jitter: &ThreadRngJitter,
                sleeper: &TokioSleeper,
            };
            runner
                .run(|attempt| async move { self.management_attempt(call, url, body, attempt).await })
                .await
        } else {
            self.management_attempt(call, url, body, 0)
                .await
                .map_err(|a| a.err)
        };

        match first {
            Ok(bytes) => Ok(bytes),
            // §9 rule 1: a 401 with a refresh token available means refresh
            // once and retry once. `refresh()` is itself single-flight, so a
            // burst of concurrent management calls produces one refresh wire
            // call and shares its outcome (§9 rule 2).
            Err(AxiamError::Auth { .. }) => {
                self.refresh().await?;
                self.management_attempt(call, url, body, 1)
                    .await
                    .map_err(|a| a.err)
            }
            Err(other) => Err(other),
        }
    }

    /// Exactly one wire attempt, with its §19 event pair.
    ///
    /// The pair is emitted **per attempt**, not per logical call: §19.2 rule 5
    /// requires a caller to be able to count real wire calls from the events.
    async fn management_attempt<B>(
        &self,
        call: &Call<'_>,
        url: &url::Url,
        body: Option<&B>,
        attempt: u32,
    ) -> Result<Vec<u8>, Attempt>
    where
        B: Serialize + ?Sized,
    {
        let telemetry = self.telemetry();
        let method = call.verb.as_str();
        telemetry.emit(TelemetryEvent::RequestStart {
            operation: call.operation,
            method,
            path_template: call.path_template,
            attempt,
        });
        let started = crate::time::Instant::now();
        let finish = |status: Option<u16>, outcome: Outcome| {
            telemetry.emit(TelemetryEvent::RequestEnd {
                operation: call.operation,
                method,
                path_template: call.path_template,
                attempt,
                status,
                duration: started.elapsed(),
                outcome,
            });
        };

        let mut request = call
            .verb
            .apply(self, url.clone())
            // §5 rule 2: on every outgoing request, without exception.
            .header("X-Tenant-ID", self.tenant_header_value())
            // §3: the double-submit header rides every state-changing verb.
            .maybe_csrf_header(self);
        if let Some(b) = body {
            request = request.json(b);
        }

        let response = match request.send().await {
            Ok(r) => r,
            Err(e) => {
                finish(None, Outcome::Failure);
                return Err(Attempt::bare(AxiamError::Network {
                    message: format!("{} request failed: {e}", call.operation),
                    source: Some(Box::new(e)),
                }));
            }
        };

        let status = response.status().as_u16();
        if !response.status().is_success() {
            // Read the hint before consuming the body — §16.1 makes it a floor
            // on the next wait.
            let retry_after = response
                .headers()
                .get(reqwest::header::RETRY_AFTER)
                .and_then(|v| v.to_str().ok())
                .and_then(parse_retry_after);
            let message = response
                .text()
                .await
                .unwrap_or_else(|_| "no response body".to_string());
            finish(Some(status), Outcome::Failure);
            return Err(Attempt {
                err: super::error::from_management_status(call.operation, status, message),
                retry_after,
            });
        }

        match response.bytes().await {
            Ok(bytes) => {
                finish(Some(status), Outcome::Success);
                Ok(bytes.to_vec())
            }
            Err(e) => {
                finish(Some(status), Outcome::Failure);
                Err(Attempt::bare(AxiamError::Network {
                    message: format!("failed to read management response body: {e}"),
                    source: Some(Box::new(e)),
                }))
            }
        }
    }

    fn management_url(
        &self,
        path: &str,
        query: &[(&'static str, String)],
    ) -> Result<url::Url, AxiamError> {
        let mut url = self.base_url().join(path).map_err(|e| {
            AxiamError::network(format!("management path {path} is not a valid URL: {e}"))
        })?;
        if !query.is_empty() {
            let mut pairs = url.query_pairs_mut();
            for (k, v) in query {
                pairs.append_pair(k, v);
            }
        }
        Ok(url)
    }
}
