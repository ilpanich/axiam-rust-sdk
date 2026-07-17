//! Declarative authorization helpers (CONTRACT.md §11) for Actix-Web.
//!
//! This module is the **runtime** half of the §11 helpers: the
//! `#[require_access]` / `#[require_auth]` / `#[require_role]` attribute
//! macros (feature `macros`) expand to thin wrappers that call the plain
//! functions and the [`RequireAccess`] builder defined here, so the
//! enforcement logic is ordinary, unit-testable library code rather than
//! macro output.
//!
//! The helpers run strictly *after* the §10 [`AxiamUser`] extractor and
//! consume the identity it injected — they never duplicate token extraction
//! or verification (§11.2.1). The authorization check is always issued for
//! the **request's** authenticated user: [`RequireAccess::check`] sends the
//! caller's `user_id` as `subject_id`, so the app's own (often
//! service-account) `AxiamClient` session is never mistaken for the end user
//! (§11.2.2).
//!
//! ## Error mapping (§11.5)
//!
//! All failures surface as [`AuthzGuardError`], whose
//! [`actix_web::ResponseError`] impl produces the standardized §10 JSON body
//! `{ "error", "message" }`:
//!
//! | Condition | Status | `error` code |
//! |-----------|--------|--------------|
//! | no verified identity | 401 | `authentication_failed` |
//! | `allowed = false` / server 403 | 403 | `authorization_denied` |
//! | resource id missing or not a UUID | 400 | `invalid_request` |
//! | transport failure reaching authz (fail closed) | 503 | `authz_unavailable` |
//! | `AxiamClient` app data not registered | 500 | `internal_error` |
//!
//! Deny and error paths never log or echo the token (§11.8): the token never
//! enters this module — only the already-verified [`AxiamUser`] does.

use actix_web::http::StatusCode;
use actix_web::{HttpRequest, HttpResponse};
use serde::Serialize;
use uuid::Uuid;

use crate::AxiamError;
use crate::client::AxiamClient;
use crate::middleware::AxiamUser;

/// The error type for the CONTRACT.md §11 declarative authorization helpers.
///
/// Each variant maps to a specific HTTP status and standardized JSON error
/// body via the [`actix_web::ResponseError`] impl (see the [module
/// docs](self) for the full table). Construct values through the associated
/// functions rather than the variants directly.
#[derive(Debug)]
pub enum AuthzGuardError {
    /// No verified identity was present — 401 `authentication_failed`.
    Unauthenticated(String),
    /// The authorization check denied the request — 403 `authorization_denied`.
    Denied(String),
    /// The resource id could not be resolved to a UUID — 400 `invalid_request`.
    InvalidResource(String),
    /// The authorization service could not be reached (fail closed) — 503
    /// `authz_unavailable`.
    Unavailable(String),
    /// The handler is misconfigured (e.g. no `AxiamClient` app data) — 500
    /// `internal_error`.
    Misconfigured(String),
}

impl AuthzGuardError {
    /// Build a 401 `authentication_failed` error with `message`.
    pub fn unauthenticated(message: impl Into<String>) -> Self {
        Self::Unauthenticated(message.into())
    }

    /// Build a 403 `authorization_denied` error with `message`.
    pub fn denied(message: impl Into<String>) -> Self {
        Self::Denied(message.into())
    }

    /// Build a 400 `invalid_request` error with `message`, for a resource id
    /// that is missing or not a valid UUID (§11.3).
    pub fn invalid_resource(message: impl Into<String>) -> Self {
        Self::InvalidResource(message.into())
    }

    /// Build a 503 `authz_unavailable` error with `message`, used on the
    /// fail-closed transport-failure path (§11.5).
    pub fn unavailable(message: impl Into<String>) -> Self {
        Self::Unavailable(message.into())
    }

    /// Build a 500 `internal_error` error with `message`, for handler
    /// misconfiguration.
    pub fn misconfigured(message: impl Into<String>) -> Self {
        Self::Misconfigured(message.into())
    }

    /// The `error` code string for the standardized JSON body.
    fn code(&self) -> &'static str {
        match self {
            Self::Unauthenticated(_) => "authentication_failed",
            Self::Denied(_) => "authorization_denied",
            Self::InvalidResource(_) => "invalid_request",
            Self::Unavailable(_) => "authz_unavailable",
            Self::Misconfigured(_) => "internal_error",
        }
    }

    /// The human-readable message for the standardized JSON body.
    fn message(&self) -> &str {
        match self {
            Self::Unauthenticated(m)
            | Self::Denied(m)
            | Self::InvalidResource(m)
            | Self::Unavailable(m)
            | Self::Misconfigured(m) => m,
        }
    }
}

impl std::fmt::Display for AuthzGuardError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code(), self.message())
    }
}

impl std::error::Error for AuthzGuardError {}

#[derive(Serialize)]
struct ErrorBody<'a> {
    error: &'a str,
    message: &'a str,
}

impl actix_web::ResponseError for AuthzGuardError {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::Unauthenticated(_) => StatusCode::UNAUTHORIZED,
            Self::Denied(_) => StatusCode::FORBIDDEN,
            Self::InvalidResource(_) => StatusCode::BAD_REQUEST,
            Self::Unavailable(_) => StatusCode::SERVICE_UNAVAILABLE,
            Self::Misconfigured(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn error_response(&self) -> HttpResponse {
        HttpResponse::build(self.status_code()).json(ErrorBody {
            error: self.code(),
            message: self.message(),
        })
    }
}

/// Resolve a resource [`Uuid`] from a named path/route parameter (§11.3b).
///
/// Returns [`AuthzGuardError::InvalidResource`] (400 `invalid_request`) if the
/// parameter is absent or does not parse as a UUID — never a silent allow and
/// never a nil-UUID fallback.
///
/// ```no_run
/// # use actix_web::HttpRequest;
/// # fn demo(req: &HttpRequest) -> Result<(), axiam_sdk::middleware::AuthzGuardError> {
/// let resource_id = axiam_sdk::middleware::resource_from_path(req, "id")?;
/// # let _ = resource_id;
/// # Ok(())
/// # }
/// ```
pub fn resource_from_path(req: &HttpRequest, param: &str) -> Result<Uuid, AuthzGuardError> {
    match req.match_info().get(param) {
        Some(raw) => Uuid::parse_str(raw).map_err(|_| {
            AuthzGuardError::invalid_resource(format!(
                "path parameter '{param}' is not a valid resource UUID"
            ))
        }),
        None => Err(AuthzGuardError::invalid_resource(format!(
            "missing path parameter '{param}'"
        ))),
    }
}

/// Resolve a resource [`Uuid`] from a static UUID string literal (§11.3a),
/// for singleton resources.
///
/// Returns [`AuthzGuardError::InvalidResource`] (400 `invalid_request`) if the
/// literal does not parse as a UUID.
pub fn resource_from_static(literal: &str) -> Result<Uuid, AuthzGuardError> {
    Uuid::parse_str(literal).map_err(|_| {
        AuthzGuardError::invalid_resource(format!(
            "static resource_id '{literal}' is not a valid UUID"
        ))
    })
}

/// Local role check (§11 `require_role`): succeeds if `user` holds at least
/// one of `required` roles, otherwise returns
/// [`AuthzGuardError::Denied`] (403 `authorization_denied`).
///
/// This is a purely local check against the verified token's claims; it never
/// contacts the server. Role names are tenant-defined and this is **not** a
/// substitute for the resource-level [`RequireAccess`] check.
///
/// ```
/// # use axiam_sdk::middleware::require_role_check;
/// # fn demo(user: &axiam_sdk::middleware::AxiamUser) {
/// let ok = require_role_check(user, &["admin", "superadmin"]).is_ok();
/// # let _ = ok;
/// # }
/// ```
pub fn require_role_check(user: &AxiamUser, required: &[&str]) -> Result<(), AuthzGuardError> {
    let granted = user
        .roles
        .iter()
        .any(|held| required.iter().any(|want| held == want));
    if granted {
        Ok(())
    } else {
        Err(AuthzGuardError::denied(
            "caller does not hold any of the required roles".to_string(),
        ))
    }
}

/// Programmatic, framework-agnostic form of the §11 `require_access` check.
///
/// This is the builder the `#[require_access]` attribute macro expands to; it
/// is also usable directly inside a handler when the macro is not a good fit
/// (e.g. a resource resolved from the request body). Build it with an
/// `action`, optionally attach a `scope`, then call [`check`](Self::check)
/// with the app's [`AxiamClient`], the request's [`AxiamUser`], and the
/// resolved resource id.
///
/// ```no_run
/// use axiam_sdk::client::AxiamClient;
/// use axiam_sdk::middleware::{AxiamUser, RequireAccess};
/// use uuid::Uuid;
///
/// # async fn handler(client: &AxiamClient, user: &AxiamUser, id: Uuid)
/// #     -> Result<(), axiam_sdk::middleware::AuthzGuardError> {
/// RequireAccess::new("read")
///     .scope("confidential")
///     .check(client, user, id)
///     .await?;
/// // ... resource access authorized ...
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct RequireAccess {
    action: String,
    scope: Option<String>,
}

impl RequireAccess {
    /// Start a check for `action` (e.g. `"read"`), with no scope.
    pub fn new(action: impl Into<String>) -> Self {
        Self {
            action: action.into(),
            scope: None,
        }
    }

    /// Narrow the check to `scope`, passed through to `check_access` verbatim
    /// (§11.4).
    pub fn scope(mut self, scope: impl Into<String>) -> Self {
        self.scope = Some(scope.into());
        self
    }

    /// Issue the authorization check for `user` on `resource_id`.
    ///
    /// Sends `subject_id = user.user_id` so the decision is made for the
    /// request's authenticated caller, not the app's client session (§11.2.2).
    /// No decision is cached (§11.6). Maps the outcome to [`AuthzGuardError`]:
    /// `allowed = false` or a server 403 → [`AuthzGuardError::Denied`]; a
    /// transport failure → [`AuthzGuardError::Unavailable`] (fail closed,
    /// §11.5); a server 401 → [`AuthzGuardError::Unauthenticated`].
    pub async fn check(
        &self,
        client: &AxiamClient,
        user: &AxiamUser,
        resource_id: Uuid,
    ) -> Result<(), AuthzGuardError> {
        let outcome = client
            .check_access_as(
                user.user_id,
                &self.action,
                resource_id,
                self.scope.as_deref(),
            )
            .await;
        match outcome {
            Ok(decision) if decision.allowed => Ok(()),
            Ok(_) => Err(AuthzGuardError::denied(format!(
                "access denied for action '{}'",
                self.action
            ))),
            Err(AxiamError::Authz { .. }) => Err(AuthzGuardError::denied(format!(
                "access denied for action '{}'",
                self.action
            ))),
            Err(AxiamError::Auth { .. }) => Err(AuthzGuardError::unauthenticated(
                "authentication rejected by the authorization service".to_string(),
            )),
            Err(AxiamError::Network { .. }) => Err(AuthzGuardError::unavailable(
                "authorization service unavailable".to_string(),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::ResponseError;
    use actix_web::body::to_bytes;

    fn user_with_roles(roles: &[&str]) -> AxiamUser {
        AxiamUser {
            user_id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            roles: roles.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn error_status_and_code_mapping_covers_every_variant() {
        let cases = [
            (
                AuthzGuardError::unauthenticated("x"),
                StatusCode::UNAUTHORIZED,
                "authentication_failed",
            ),
            (
                AuthzGuardError::denied("x"),
                StatusCode::FORBIDDEN,
                "authorization_denied",
            ),
            (
                AuthzGuardError::invalid_resource("x"),
                StatusCode::BAD_REQUEST,
                "invalid_request",
            ),
            (
                AuthzGuardError::unavailable("x"),
                StatusCode::SERVICE_UNAVAILABLE,
                "authz_unavailable",
            ),
            (
                AuthzGuardError::misconfigured("x"),
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
            ),
        ];
        for (err, status, code) in cases {
            assert_eq!(err.status_code(), status);
            assert_eq!(err.code(), code);
            assert_eq!(err.message(), "x");
            // Display renders "<code>: <message>".
            assert_eq!(err.to_string(), format!("{code}: x"));
        }
    }

    #[tokio::test]
    async fn error_response_emits_standardized_json_body() {
        let err = AuthzGuardError::denied("nope");
        let resp = err.error_response();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let bytes = to_bytes(resp.into_body()).await.expect("readable body");
        let body: serde_json::Value = serde_json::from_slice(&bytes).expect("valid JSON");
        assert_eq!(body["error"], "authorization_denied");
        assert_eq!(body["message"], "nope");
    }

    #[test]
    fn resource_from_static_parses_and_rejects() {
        let id = Uuid::new_v4();
        assert_eq!(resource_from_static(&id.to_string()).unwrap(), id);

        let err = resource_from_static("not-a-uuid").expect_err("must reject non-UUID");
        assert_eq!(err.status_code(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn require_role_check_allows_when_one_role_matches() {
        let user = user_with_roles(&["editor", "admin"]);
        assert!(require_role_check(&user, &["admin", "superadmin"]).is_ok());
    }

    #[test]
    fn require_role_check_denies_when_no_role_matches() {
        let user = user_with_roles(&["viewer"]);
        let err = require_role_check(&user, &["admin"]).expect_err("must deny");
        assert_eq!(err.status_code(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn require_access_builder_records_action_and_scope() {
        let guard = RequireAccess::new("read").scope("confidential");
        assert_eq!(guard.action, "read");
        assert_eq!(guard.scope.as_deref(), Some("confidential"));
    }
}
