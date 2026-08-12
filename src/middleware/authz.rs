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
    /// Denied, and a `WWW-Authenticate: UMA` challenge was minted for the
    /// caller — 403 `authorization_denied` with the §20.3 header attached.
    ///
    /// Carries `(message, header_value)`. The header is built during the async
    /// [`RequireAccess::check`], because minting a ticket is a wire call and
    /// [`actix_web::ResponseError::error_response`] is synchronous; by the time
    /// this variant exists the ticket is already in hand.
    DeniedWithChallenge(String, String),
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

    /// Build a 403 `authorization_denied` error that also carries a
    /// `WWW-Authenticate: UMA` challenge (§20.3).
    ///
    /// `header_value` is the complete header value, already formatted by
    /// [`crate::uma::uma_challenge_header`] — the ticket inside it is a live
    /// credential for its 60-second life, so it is built once, here, and never
    /// re-derived on a later render of the response.
    pub fn denied_with_challenge(
        message: impl Into<String>,
        header_value: impl Into<String>,
    ) -> Self {
        Self::DeniedWithChallenge(message.into(), header_value.into())
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
            Self::Denied(_) | Self::DeniedWithChallenge(..) => "authorization_denied",
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
            | Self::DeniedWithChallenge(m, _)
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
            Self::Denied(_) | Self::DeniedWithChallenge(..) => StatusCode::FORBIDDEN,
            Self::InvalidResource(_) => StatusCode::BAD_REQUEST,
            Self::Unavailable(_) => StatusCode::SERVICE_UNAVAILABLE,
            Self::Misconfigured(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn error_response(&self) -> HttpResponse {
        let mut builder = HttpResponse::build(self.status_code());
        if let Self::DeniedWithChallenge(_, header) = self {
            // §20.3: tell the caller where to redeem authority. The body is the
            // unchanged §11.5 shape — the challenge is additive, so a client
            // that does not speak UMA sees exactly the 403 it saw before.
            builder.insert_header((actix_web::http::header::WWW_AUTHENTICATE, header.as_str()));
        }
        builder.json(ErrorBody {
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

/// A configured `WWW-Authenticate: UMA` challenge emitter (§20.3, emit half).
///
/// Attach one to a [`RequireAccess`] with
/// [`RequireAccess::with_uma_challenge`] and a denial stops being a bare 403:
/// the guard mints a fresh permission ticket for the pairs the caller lacked
/// and returns it in the header, so a UMA-aware client knows where to go for
/// authority instead of only being told "no".
///
/// **Opt-in, and deliberately so.** Emitting a challenge means minting a
/// credential — a wire call to the Protection API, and a live ticket, produced
/// on a path the caller did not explicitly request. A guard that did that on
/// every denial by default would turn each unauthorized request into a
/// Protection API call, which is a denial-of-service amplifier pointed at your
/// own authorization server. So it happens only where an application has said
/// it wants UMA semantics on this route.
///
/// # Failure is not escalation
///
/// If minting fails — the PAT expired, the Protection API is down, the
/// resource declares none of the requested scopes — the denial still surfaces
/// as an ordinary 403 without a challenge. A caller who was going to be refused
/// is refused either way; letting a Protection API outage turn a deny into a
/// 500 would hand the outage a second consequence, and letting it turn into an
/// allow would be a security bug.
#[derive(Clone)]
pub struct UmaChallenger {
    realm: String,
    as_uri: String,
    pat: crate::sensitive::Sensitive<String>,
}

impl UmaChallenger {
    /// Build a challenger.
    ///
    /// `realm` is the protection realm to name, `as_uri` the authorization
    /// server to send the caller to — normally this deployment's issuer, read
    /// from `/.well-known/uma2-configuration` rather than concatenated by hand.
    /// `pat` is a Protection API Token: a *client-credentials* token carrying
    /// the `uma_protection` scope (§20.2 rule 1).
    pub fn new(
        realm: impl Into<String>,
        as_uri: impl Into<String>,
        pat: crate::sensitive::Sensitive<String>,
    ) -> Self {
        Self {
            realm: realm.into(),
            as_uri: as_uri.into(),
            pat,
        }
    }
}

impl std::fmt::Debug for UmaChallenger {
    /// Renders without the PAT (§7): a challenger is configuration a caller may
    /// reasonably log, and the credential inside it is not.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UmaChallenger")
            .field("realm", &self.realm)
            .field("as_uri", &self.as_uri)
            .field("pat", &self.pat)
            .finish()
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
    challenger: Option<UmaChallenger>,
}

impl RequireAccess {
    /// Start a check for `action` (e.g. `"read"`), with no scope.
    pub fn new(action: impl Into<String>) -> Self {
        Self {
            action: action.into(),
            scope: None,
            challenger: None,
        }
    }

    /// On denial, mint a permission ticket and emit the `WWW-Authenticate: UMA`
    /// challenge (§20.3) alongside the 403.
    ///
    /// The UMA scope requested is this check's **action** — the same mapping
    /// the server uses, so a deny rule vetoes an RPT exactly as it vetoes this
    /// check. See [`UmaChallenger`] for why this is opt-in and what happens
    /// when minting fails.
    pub fn with_uma_challenge(mut self, challenger: UmaChallenger) -> Self {
        self.challenger = Some(challenger);
        self
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
            Ok(_) => Err(self.deny(client, resource_id).await),
            Err(AxiamError::Authz { .. }) => Err(self.deny(client, resource_id).await),
            Err(AxiamError::Auth { .. }) => Err(AuthzGuardError::unauthenticated(
                "authentication rejected by the authorization service".to_string(),
            )),
            Err(AxiamError::Network { .. }) => Err(AuthzGuardError::unavailable(
                "authorization service unavailable".to_string(),
            )),
        }
    }

    /// Build the denial, minting a §20.3 challenge when one was configured.
    ///
    /// Only ever called on a path that has already decided to refuse, so the
    /// mint cannot change the outcome — at worst it fails and the caller gets
    /// the plain 403 they would have got anyway.
    async fn deny(&self, client: &AxiamClient, resource_id: Uuid) -> AuthzGuardError {
        let message = format!("access denied for action '{}'", self.action);
        let Some(challenger) = self.challenger.as_ref() else {
            return AuthzGuardError::denied(message);
        };

        // §20.2: the UMA scope is the AXIAM *action*, which is what makes the
        // ticket ask for exactly the authority this check just refused.
        let permission = crate::uma::RequestedPermission {
            resource_id,
            resource_scopes: vec![self.action.clone()],
        };
        match client
            .uma_request_ticket(&challenger.pat, std::slice::from_ref(&permission))
            .await
        {
            Ok(ticket) => AuthzGuardError::denied_with_challenge(
                message,
                crate::uma::uma_challenge_header(&challenger.realm, &challenger.as_uri, &ticket),
            ),
            // Deliberately swallowed: see UmaChallenger's "failure is not
            // escalation" note. The reason is not logged here either, because
            // this module never writes the token or the ticket anywhere (§11.8).
            Err(_) => AuthzGuardError::denied(message),
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
    fn resource_from_path_rejects_a_missing_path_parameter() {
        // No route registered at all, so `match_info().get("id")` is `None` —
        // exercises the "missing path parameter" arm, distinct from
        // `resource_from_path`'s "present but not a UUID" arm covered
        // end-to-end by `tests/macro_require_access_test.rs::bad_uuid_returns_400`.
        let req = actix_web::test::TestRequest::default().to_http_request();
        let err = resource_from_path(&req, "id").expect_err("missing path parameter must fail");
        assert_eq!(err.status_code(), StatusCode::BAD_REQUEST);
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
