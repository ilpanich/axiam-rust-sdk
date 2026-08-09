//! REST authz methods: `check_access`/`can`/`batch_check` (CONTRACT.md §1).
//!
//! Mirrors `crates/axiam-api-rest/src/handlers/authz_check.rs` request/
//! response shapes exactly (mirror only, no server crate dependency).
//! `tenant_id` is never sent in the body — the server derives it from the
//! JWT (§5); the SDK only sends `X-Tenant-ID` as the CONTRACT.md §5 header.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::AxiamError;
use crate::client::AxiamClient;
use crate::rest::auth::CsrfHeaderExt;
use crate::retry::{Attempt, RetryRunner, ThreadRngJitter, TokioSleeper, parse_retry_after};
use crate::telemetry::{Outcome, TelemetryEvent};

const CHECK_PATH: &str = "/api/v1/authz/check";
const BATCH_CHECK_PATH: &str = "/api/v1/authz/check/batch";

/// A single access check request (CONTRACT.md §1).
#[derive(Debug, Clone, Serialize)]
pub struct AccessCheckRequest {
    /// Permission action to check (CONTRACT.md §1 method vocabulary, e.g.
    /// `"read"`, `"write"`).
    pub action: String,
    /// Resource the action is checked against.
    pub resource_id: Uuid,
    /// Optional sub-resource scope narrowing the check. `None` means the
    /// check applies to the whole resource.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// Subject to check access for. `None` defers to the server, which uses
    /// the authenticated caller from the JWT (§5).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject_id: Option<Uuid>,
}

impl AccessCheckRequest {
    /// Builds a request for `action` on `resource_id` with no scope and no
    /// explicit subject (the server resolves the subject from the caller's
    /// JWT).
    pub fn new(action: impl Into<String>, resource_id: Uuid) -> Self {
        Self {
            action: action.into(),
            resource_id,
            scope: None,
            subject_id: None,
        }
    }

    /// Narrows the check to the given sub-resource `scope`.
    pub fn with_scope(mut self, scope: impl Into<String>) -> Self {
        self.scope = Some(scope.into());
        self
    }

    /// Checks access on behalf of `subject_id` instead of the authenticated
    /// caller.
    pub fn with_subject(mut self, subject_id: Uuid) -> Self {
        self.subject_id = Some(subject_id);
        self
    }
}

/// The result of a single access check (mirrors `CheckAccessResponse`).
#[derive(Debug, Clone, Deserialize)]
pub struct AccessDecision {
    /// Whether the checked action is permitted.
    ///
    /// **This field alone carries the outcome.** [`Self::reason_code`]
    /// explains it and never contradicts it.
    pub allowed: bool,
    /// Optional human-readable explanation for the decision (e.g. which
    /// role/permission granted or denied it). Not guaranteed to be present.
    #[serde(default)]
    pub reason: Option<String>,
    /// Machine-readable decision reason (CONTRACT.md §11 rule 9, B1
    /// deny-override): `"allowed"`, `"no_grant"`, or `"denied_by_rule"`.
    ///
    /// **The two refusals mean opposite things to the person on the other
    /// end.** `no_grant` says *ask an admin for access*; `denied_by_rule`
    /// says *an admin has already decided*. An application that cannot tell
    /// them apart sends users to raise tickets that will be refused — which
    /// is why the contract forbids collapsing them into a bare `false`.
    ///
    /// `None` when the server does not send the field: a newer SDK against an
    /// older server treats it as absent, never as an error. An unrecognised
    /// value is surfaced verbatim and never changes [`Self::allowed`].
    #[serde(default)]
    pub reason_code: Option<String>,
}

/// The three `reason_code` values CONTRACT.md §11 rule 9 defines.
///
/// Deliberately **not** an enum on [`AccessDecision`]: the contract requires
/// an unrecognised code to be surfaced verbatim, and a closed enum would have
/// to either drop it or invent an `Unknown(String)` arm that callers would
/// then match on as though it meant something. The field stays a `String`;
/// these constants exist so callers compare against a name rather than a
/// literal.
pub mod reason_code {
    /// An allow grant matched and no deny did.
    pub const ALLOWED: &str = "allowed";
    /// Nothing matched — default deny. *Ask an admin for access.*
    pub const NO_GRANT: &str = "no_grant";
    /// An explicit deny rule matched and overrode any allow. *An admin has
    /// already decided.*
    pub const DENIED_BY_RULE: &str = "denied_by_rule";
}

#[derive(Debug, Serialize)]
struct BatchCheckRequestBody {
    checks: Vec<AccessCheckRequest>,
}

#[derive(Debug, Deserialize)]
struct BatchCheckResponseWire {
    results: Vec<AccessDecision>,
}

impl AxiamClient {
    /// `POST /api/v1/authz/check` — evaluate a single authorization check
    /// for the given `action`/`resource_id`/`scope` (CONTRACT.md §1).
    ///
    /// This is a read-only, idempotent operation: transient
    /// network/429-with-Retry-After failures are retried a bounded number
    /// of times (D-12); `login`/`verify_mfa`/`refresh`/`logout` are
    /// state-changing and deliberately do NOT get this treatment.
    pub async fn check_access(
        &self,
        action: &str,
        resource_id: Uuid,
        scope: Option<&str>,
    ) -> Result<AccessDecision, AxiamError> {
        let request = AccessCheckRequest {
            action: action.to_string(),
            resource_id,
            scope: scope.map(str::to_string),
            subject_id: None,
        };
        self.check_access_request(&request).await
    }

    /// `POST /api/v1/authz/check` — evaluate a single authorization check on
    /// behalf of an explicit `subject_id` rather than the authenticated
    /// caller (CONTRACT.md §11.2.2).
    ///
    /// This is the subject-aware form used by the §11 declarative
    /// authorization helpers ([`crate::middleware::RequireAccess`]): the
    /// application's `AxiamClient` typically holds a service-account session,
    /// so the request's end-user id must be sent explicitly as `subject_id`,
    /// otherwise the service account's permissions would be checked instead.
    /// Same bounded read-only retry policy as [`Self::check_access`].
    pub async fn check_access_as(
        &self,
        subject_id: Uuid,
        action: &str,
        resource_id: Uuid,
        scope: Option<&str>,
    ) -> Result<AccessDecision, AxiamError> {
        let request = AccessCheckRequest {
            action: action.to_string(),
            resource_id,
            scope: scope.map(str::to_string),
            subject_id: Some(subject_id),
        };
        self.check_access_request(&request).await
    }

    /// `can` — alias for [`Self::check_access`] targeting browser/UI
    /// scenarios (CONTRACT.md §1 note).
    pub async fn can(
        &self,
        action: &str,
        resource_id: Uuid,
        scope: Option<&str>,
    ) -> Result<bool, AxiamError> {
        self.check_access(action, resource_id, scope)
            .await
            .map(|decision| decision.allowed)
    }

    /// `POST /api/v1/authz/check/batch` — evaluate an ordered list of
    /// checks; results are returned in the same order as `requests`
    /// (CONTRACT.md §1).
    pub async fn batch_check(
        &self,
        requests: Vec<AccessCheckRequest>,
    ) -> Result<Vec<AccessDecision>, AxiamError> {
        self.ensure_open()?;
        let body = BatchCheckRequestBody { checks: requests };
        let client = self.clone();

        let wire: BatchCheckResponseWire = self
            .runner("batch_check")
            .run(|attempt| {
                let client = client.clone();
                let body_ref = &body;
                async move {
                    client
                        .send_authz_post("batch_check", BATCH_CHECK_PATH, body_ref, attempt)
                        .await
                }
            })
            .await?;

        Ok(wire.results)
    }

    async fn check_access_request(
        &self,
        request: &AccessCheckRequest,
    ) -> Result<AccessDecision, AxiamError> {
        self.ensure_open()?;
        let client = self.clone();
        self.runner("check_access")
            .run(|attempt| {
                let client = client.clone();
                async move {
                    client
                        .send_authz_post("check_access", CHECK_PATH, request, attempt)
                        .await
                }
            })
            .await
    }

    /// A §16 runner bound to this client's telemetry sink and retry switch.
    fn runner(&self, operation: &'static str) -> RetryRunner<'_> {
        RetryRunner {
            enabled: self.retry_enabled(),
            operation,
            telemetry: self.telemetry(),
            jitter: &ThreadRngJitter,
            sleeper: &TokioSleeper,
        }
    }

    /// One attempt at an authz POST.
    ///
    /// Emits the §19 `RequestStart`/`RequestEnd` pair **per attempt**, not per
    /// logical call: §19.2 rule 5 requires a caller to be able to count real
    /// wire calls from the events, which one pair per operation would hide.
    /// `path` doubles as the §19.1 path template — these are literal constants
    /// with no ids substituted in, so there is no cardinality risk.
    async fn send_authz_post<B, R>(
        &self,
        operation: &'static str,
        path: &'static str,
        body: &B,
        attempt: u32,
    ) -> Result<R, Attempt>
    where
        B: Serialize + ?Sized,
        R: for<'de> Deserialize<'de>,
    {
        let telemetry = self.telemetry();
        telemetry.emit(TelemetryEvent::RequestStart {
            operation,
            method: "POST",
            path_template: path,
            attempt,
        });
        let started = std::time::Instant::now();

        // Closes the §19 pair exactly once, on every exit path.
        let finish = |status: Option<u16>, outcome: Outcome| {
            telemetry.emit(TelemetryEvent::RequestEnd {
                operation,
                method: "POST",
                path_template: path,
                attempt,
                status,
                duration: started.elapsed(),
                outcome,
            });
        };

        let response = match self
            .http()
            .post(self.authz_url(path))
            .header("X-Tenant-ID", self.tenant_header_value())
            // SDK-Q04: forward the captured `X-CSRF-Token` on this POST, the
            // same way `refresh`/`logout` do (§3) — the server's CSRF
            // protection covers state-changing verbs including authz POSTs.
            .maybe_csrf_header(self)
            .json(body)
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => {
                finish(None, Outcome::Failure);
                return Err(Attempt::bare(AxiamError::Network {
                    message: format!("authz request failed: {e}"),
                    source: Some(Box::new(e)),
                }));
            }
        };

        if !response.status().is_success() {
            let status = response.status().as_u16();
            // Read the hint before consuming the body — §16.1 makes it a floor
            // on the next wait, and it typically rides a 429 or 503.
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
                err: AxiamError::from_http_status(status, message),
                retry_after,
            });
        }

        let status = response.status().as_u16();
        match response.json().await {
            Ok(v) => {
                finish(Some(status), Outcome::Success);
                Ok(v)
            }
            Err(e) => {
                finish(Some(status), Outcome::Failure);
                Err(Attempt::bare(AxiamError::Network {
                    message: format!("failed to parse authz response body: {e}"),
                    source: Some(Box::new(e)),
                }))
            }
        }
    }

    fn authz_url(&self, path: &str) -> url::Url {
        self.base_url()
            .join(path)
            .expect("authz path is a well-formed relative URL literal")
    }
}

// The retry policy that used to live here — `backon`'s ExponentialBuilder
// defaults with `with_max_times(2)` — has moved to `crate::retry`, which
// implements CONTRACT.md §16's normative table: full jitter over [0, backoff]
// rather than backon's narrower `[0, min_delay)` addition, and `Retry-After`
// honored as a floor, neither of which the old policy did.
