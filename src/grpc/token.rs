//! gRPC `validate_token` / `introspect_token` (CONTRACT.md §1.1.1, contract
//! 1.51) — the wrappers over `axiam.v1.TokenService` that §10.3 needed and no
//! SDK had.
//!
//! Until 1.51 §10.3 obliged an SDK validating over gRPC to read the response's
//! `cnf`, while §1's closed vocabulary permitted no method that could return
//! it: the stubs were generated here and wrapped by nothing. This module is
//! the wrapper, and its whole reason to exist is the confirmation.
//!
//! # Two tokens, kept apart
//!
//! Every call carries **two** credentials, and confusing them is the mistake
//! this API is shaped against (§1.1.1 rule 1):
//!
//! * the **caller's** own access token, which the [`AuthInterceptor`] puts in
//!   `authorization` exactly as for every other RPC, and which the server
//!   enforces like any other — including its own `cnf`;
//! * the **inspected** token, the one being asked about, which travels in the
//!   request message. It is a [`Sensitive`] argument with no default: nothing
//!   here falls back to the caller's token when it is omitted, because it
//!   cannot be omitted.
//!
//! # `valid` is not "usable as presented"
//!
//! `valid` / `active` mean the signature, expiry and tenant check out. When the
//! token carries `cnf`, whoever presented it to *you* must also prove
//! possession of the named key, against *your* connection — the AXIAM server
//! cannot, because the proof is not on the connection carrying this RPC
//! (§10.3 rule 2). So each result offers [`TokenValidation::status`], which
//! says which of the three cases this is without letting a caller treat a bound
//! token as a bearer one by reading one boolean, and
//! [`TokenValidation::verify_possession`], which applies §10.1 rule 9 with the
//! proofs you hold.
//!
//! Boundness is decided from `cnf` alone, never from `token_type`: the server
//! reports `"Bearer"` for a certificate-bound token, and only a `jkt`-bound one
//! is `"DPoP"` (§1.1.1 rule 5).

use std::future::Future;
use std::sync::Arc;

use tonic::Code;
use tonic::service::interceptor::InterceptedService;
use tonic::transport::Channel;
use uuid::Uuid;

use crate::grpc::client::{RefreshFn, status_to_axiam_error};
use crate::grpc::r#gen::token_service_client::TokenServiceClient;
use crate::grpc::r#gen::{
    CnfClaim as WireCnfClaim, IntrospectTokenRequest,
    IntrospectTokenResponse as WireIntrospectTokenResponse, RptPermission as WireRptPermission,
    ValidateTokenRequest, ValidateTokenResponse as WireValidateTokenResponse,
};
use crate::grpc::interceptor::AuthInterceptor;
use crate::token::{CnfClaim, PresentedProofs, TokenManager};
use crate::{AxiamError, Sensitive};

/// What a validation or introspection result means for the presenter — the
/// three cases §10.1 rule 9 and §10.3 distinguish.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TokenStatus {
    /// `valid` / `active` is `false`: expired, badly signed, revoked, or a
    /// token of **another tenant** — which the server reports as inactive, not
    /// as an error (§1.1.1 rule 6).
    Inactive,
    /// Valid, and carries no `cnf`: an ordinary bearer token. Whoever holds it
    /// may use it.
    Bearer,
    /// Valid, **and sender-constrained**: it carries a `cnf` naming at least
    /// one method this SDK can check. Usable only by a presenter that proves
    /// possession — call `verify_possession` with the proofs from your own
    /// connection.
    SenderConstrained,
    /// Valid, but its `cnf` names **no** method this SDK can check — an empty
    /// `CnfClaim` message, which proto3 is the only way to spell. Refused, not
    /// read as unbound (§10.3 rule 3): `verify_possession` never accepts it.
    Unverifiable,
}

fn status_of(valid: bool, cnf: Option<&CnfClaim>) -> TokenStatus {
    match (valid, cnf) {
        (false, _) => TokenStatus::Inactive,
        (true, None) => TokenStatus::Bearer,
        (true, Some(c)) if c.names_nothing_checkable() => TokenStatus::Unverifiable,
        (true, Some(_)) => TokenStatus::SenderConstrained,
    }
}

fn verify_possession_of(
    valid: bool,
    cnf: Option<&CnfClaim>,
    proofs: PresentedProofs<'_>,
) -> Result<(), AxiamError> {
    if !valid {
        return Err(AxiamError::auth(
            "the token is not valid (expired, revoked, badly signed, or of another tenant)",
        ));
    }
    match cnf {
        None => Ok(()),
        Some(cnf) => cnf.verify(proofs),
    }
}

/// `proto3` cannot tell an absent string from an empty one, so an empty member
/// is an absent member. The message itself being absent is the distinction
/// that survives the wire, and is kept: `None` is unbound, `Some` with both
/// members `None` is the §10.3 rule 3 case.
fn cnf_from_wire(wire: Option<WireCnfClaim>) -> Option<CnfClaim> {
    wire.map(|c| CnfClaim {
        x5t_s256: non_empty(c.x5t_s256),
        jkt: non_empty(c.jkt),
    })
}

fn non_empty(value: String) -> Option<String> {
    if value.is_empty() { None } else { Some(value) }
}

/// The result of [`TokenGrpcClient::validate_token`] — every field of
/// `ValidateTokenResponse` (§1.1.1 rule 3).
///
/// **`valid` is not permission to proceed.** Read [`Self::status`], or call
/// [`Self::verify_possession`]; see the module documentation.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct TokenValidation {
    /// The server's verdict on signature, expiry and tenant — and nothing
    /// more. `false` for a token of another tenant, with every other field
    /// empty (§1.1.1 rule 6).
    pub valid: bool,
    /// Subject UUID; empty when not valid.
    pub subject_id: String,
    /// Tenant UUID; empty when not valid.
    pub tenant_id: String,
    /// Organization UUID; empty when not valid.
    pub org_id: String,
    /// Expiry, seconds since the epoch; `0` when not valid.
    pub exp: i64,
    /// The RFC 7800 confirmation. `None` means **unbound**; `Some` with both
    /// members `None` is an empty confirmation, which is refused, never read
    /// as unbound (§10.3 rule 3). Always carried, whether or not the caller
    /// looks at it — the field is the reason this method exists.
    pub cnf: Option<CnfClaim>,
    /// `"Bearer"` or `"DPoP"`. **Does not say whether the token is bound**: a
    /// certificate-bound token is `"Bearer"` (§1.1.1 rule 5). Use
    /// [`Self::status`].
    pub token_type: String,
}

impl TokenValidation {
    /// Which of the §10.1 rule 9 cases this is, decided from `valid` and `cnf`
    /// — never from `token_type`.
    #[must_use]
    pub fn status(&self) -> TokenStatus {
        status_of(self.valid, self.cnf.as_ref())
    }

    /// Whether the **presenter** may use this token: `valid`, and every sender
    /// constraint its `cnf` names satisfied by `proofs` (§10.1 rule 9, §10.3
    /// rule 2).
    ///
    /// `proofs` are what *your* connection established — the peer
    /// certificate's thumbprint, a DPoP proof you verified — never values taken
    /// from a request header the caller controls. An unbound valid token is
    /// accepted with or without proofs.
    ///
    /// # Errors
    ///
    /// [`AxiamError::Auth`] when the token is not valid, or when its `cnf` is
    /// not satisfied — including an empty `cnf`, which nothing satisfies.
    pub fn verify_possession(&self, proofs: PresentedProofs<'_>) -> Result<(), AxiamError> {
        verify_possession_of(self.valid, self.cnf.as_ref(), proofs)
    }
}

impl From<WireValidateTokenResponse> for TokenValidation {
    fn from(wire: WireValidateTokenResponse) -> Self {
        Self {
            valid: wire.valid,
            subject_id: wire.subject_id,
            tenant_id: wire.tenant_id,
            org_id: wire.org_id,
            exp: wire.exp,
            cnf: cnf_from_wire(wire.cnf),
            token_type: wire.token_type,
        }
    }
}

/// A UMA 2.0 permission carried by an RPT (CONTRACT.md §20) — one entry of
/// [`TokenIntrospection::permissions`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct RptPermission {
    /// Resource UUID.
    pub resource_id: String,
    /// Scopes granted on that resource.
    pub resource_scopes: Vec<String>,
    /// Expiry of this permission, seconds since the epoch.
    pub exp: i64,
}

impl From<WireRptPermission> for RptPermission {
    fn from(wire: WireRptPermission) -> Self {
        Self {
            resource_id: wire.resource_id,
            resource_scopes: wire.resource_scopes,
            exp: wire.exp,
        }
    }
}

/// The result of [`TokenGrpcClient::introspect_token`] — every field of
/// `IntrospectTokenResponse`, the RFC 7662 set (§1.1.1 rule 3).
///
/// **`active` is not permission to proceed.** Read [`Self::status`], or call
/// [`Self::verify_possession`]; see the module documentation.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct TokenIntrospection {
    /// Signature, expiry and tenant check out — and nothing more. `false` for a
    /// token of another tenant (§1.1.1 rule 6).
    pub active: bool,
    /// Subject UUID.
    pub sub: String,
    /// Tenant UUID.
    pub tenant_id: String,
    /// Organization UUID.
    pub org_id: String,
    /// Issuer.
    pub iss: String,
    /// Issued-at, seconds since the epoch.
    pub iat: i64,
    /// Expiry, seconds since the epoch.
    pub exp: i64,
    /// Token id.
    pub jti: String,
    /// Space-separated granted scopes; `None` when the token carries none.
    pub scope: Option<String>,
    /// The client the token was issued to, when it was issued to one.
    pub client_id: Option<String>,
    /// `"Bearer"` or `"DPoP"`. **Does not say whether the token is bound** —
    /// see [`TokenValidation::token_type`].
    pub token_type: String,
    /// The RFC 7800 confirmation; `None` is unbound, and an empty one is
    /// refused (§10.3 rule 3). See [`TokenValidation::cnf`].
    pub cnf: Option<CnfClaim>,
    /// UMA 2.0 RPT permissions (§20); empty for any other token.
    pub permissions: Vec<RptPermission>,
    /// The foreign issuer whose subject token bought this one (token exchange,
    /// §15.7), when there was one.
    pub ext_exchange_iss: Option<String>,
}

impl TokenIntrospection {
    /// As [`TokenValidation::status`].
    #[must_use]
    pub fn status(&self) -> TokenStatus {
        status_of(self.active, self.cnf.as_ref())
    }

    /// As [`TokenValidation::verify_possession`].
    ///
    /// # Errors
    ///
    /// [`AxiamError::Auth`] when the token is not active, or its `cnf` is not
    /// satisfied by `proofs`.
    pub fn verify_possession(&self, proofs: PresentedProofs<'_>) -> Result<(), AxiamError> {
        verify_possession_of(self.active, self.cnf.as_ref(), proofs)
    }
}

impl From<WireIntrospectTokenResponse> for TokenIntrospection {
    fn from(wire: WireIntrospectTokenResponse) -> Self {
        Self {
            active: wire.active,
            sub: wire.sub,
            tenant_id: wire.tenant_id,
            org_id: wire.org_id,
            iss: wire.iss,
            iat: wire.iat,
            exp: wire.exp,
            jti: wire.jti,
            scope: non_empty(wire.scope),
            client_id: non_empty(wire.client_id),
            token_type: wire.token_type,
            cnf: cnf_from_wire(wire.cnf),
            permissions: wire.permissions.into_iter().map(Into::into).collect(),
            ext_exchange_iss: non_empty(wire.ext_exchange_iss),
        }
    }
}

type InnerClient = TokenServiceClient<InterceptedService<Channel, AuthInterceptor>>;

/// gRPC transport client for `TokenService` — `validate_token` and
/// `introspect_token` (CONTRACT.md §1.1.1).
///
/// Built like [`crate::grpc::UserInfoGrpcClient`]: on the shared
/// lazily-connected [`Channel`], with the same [`AuthInterceptor`] putting the
/// caller's token and `x-tenant-id` on every RPC, and the same
/// `UNAUTHENTICATED` → single-flight refresh → retry-once (§9), which applies
/// to the **caller's** token only.
#[derive(Clone)]
pub struct TokenGrpcClient {
    inner: InnerClient,
    token_manager: Arc<TokenManager>,
    tenant_id: Uuid,
    refresh_fn: RefreshFn,
}

impl std::fmt::Debug for TokenGrpcClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenGrpcClient")
            .field("tenant_id", &self.tenant_id)
            .finish_non_exhaustive()
    }
}

impl TokenGrpcClient {
    /// Wrap a shared [`Channel`] with the auth/tenant interceptor. Share the
    /// same `TokenManager` as the rest of the client so the caller's token is
    /// the one a `login()` produced; `refresh_fn` follows
    /// [`crate::grpc::AuthzGrpcClient::new`].
    pub fn new(
        channel: Channel,
        token_manager: Arc<TokenManager>,
        tenant_id: Uuid,
        refresh_fn: RefreshFn,
    ) -> Self {
        let interceptor = AuthInterceptor::new(Arc::clone(&token_manager), tenant_id);
        Self {
            inner: TokenServiceClient::with_interceptor(channel, interceptor),
            token_manager,
            tenant_id,
            refresh_fn,
        }
    }

    /// The tenant UUID this client was constructed with.
    pub fn tenant_id(&self) -> Uuid {
        self.tenant_id
    }

    /// `TokenService/ValidateToken` — validate `token` (signature, expiry,
    /// tenant) and return every field the server sends, `cnf` included.
    ///
    /// `token` is the token being **asked about**, not the caller's own; the
    /// caller's token authenticates the call and comes from the shared
    /// `TokenManager`.
    ///
    /// # Errors
    ///
    /// * [`AxiamError::Auth`], **with no wire call**, when this client holds no
    ///   caller token (§1.1.1 rule 2) — log in first.
    /// * The §2 mapping of any other gRPC status. A token of another tenant is
    ///   **not** an error: it comes back with `valid: false` (rule 6).
    pub async fn validate_token(
        &self,
        token: &Sensitive<String>,
    ) -> Result<TokenValidation, AxiamError> {
        self.require_caller_token("validate_token")?;
        let request = || ValidateTokenRequest {
            access_token: token.expose().clone(),
        };
        self.call(|| {
            let mut client = self.inner.clone();
            let request = request();
            async move { client.validate_token(request).await }
        })
        .await
        .map(Into::into)
    }

    /// `TokenService/IntrospectToken` — the RFC 7662 view of `token`, every
    /// field included, `cnf` among them.
    ///
    /// Same two-token rule and the same errors as [`Self::validate_token`].
    ///
    /// # Errors
    ///
    /// As [`Self::validate_token`].
    pub async fn introspect_token(
        &self,
        token: &Sensitive<String>,
    ) -> Result<TokenIntrospection, AxiamError> {
        self.require_caller_token("introspect_token")?;
        let request = || IntrospectTokenRequest {
            access_token: token.expose().clone(),
        };
        self.call(|| {
            let mut client = self.inner.clone();
            let request = request();
            async move { client.introspect_token(request).await }
        })
        .await
        .map(Into::into)
    }

    /// §1.1 rule 3 via §1.1.1 rule 2: no caller token, no wire call.
    ///
    /// The interceptor would also refuse, with `UNAUTHENTICATED` — but that
    /// status is what sends a call to the §9 guard, and a guard handed no token
    /// has nothing to refresh. Refusing here names the mistake instead.
    fn require_caller_token(&self, operation: &str) -> Result<(), AxiamError> {
        if self.token_manager.cached_access_token().is_none() {
            return Err(AxiamError::auth(format!(
                "{operation}: no caller token — call login() first (the token being inspected is \
                 a separate argument and never authenticates the call)"
            )));
        }
        Ok(())
    }

    /// One attempt, and on `UNAUTHENTICATED` one single-flight refresh of the
    /// **caller's** token and one retry (§9).
    async fn call<T, F, Fut>(&self, attempt: F) -> Result<T, AxiamError>
    where
        F: Fn() -> Fut,
        Fut: Future<Output = Result<tonic::Response<T>, tonic::Status>>,
    {
        match attempt().await {
            Ok(response) => Ok(response.into_inner()),
            Err(status) if status.code() == Code::Unauthenticated => {
                let observed = self
                    .token_manager
                    .cached_access_token()
                    .map(|t| t.expose().clone())
                    .unwrap_or_default();
                let refresh_fn = Arc::clone(&self.refresh_fn);
                self.token_manager
                    .refresh_if_needed(&observed, move |refresh_token| refresh_fn(refresh_token))
                    .await?;
                attempt()
                    .await
                    .map(tonic::Response::into_inner)
                    .map_err(status_to_axiam_error)
            }
            Err(status) => Err(status_to_axiam_error(status)),
        }
    }
}
