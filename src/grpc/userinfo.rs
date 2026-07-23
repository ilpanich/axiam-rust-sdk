//! gRPC `get_user_info` client (CONTRACT.md §1.1) — the OIDC-style identity
//! read served only over gRPC (`axiam.v1.UserInfoService/GetUserInfo`).
//!
//! Structurally parallel to [`crate::grpc::client::AuthzGrpcClient`]: it reuses
//! the same shared lazily-connected [`Channel`], the same [`AuthInterceptor`]
//! (auth + `x-tenant-id` metadata, CONTRACT.md §5), and the same
//! `UNAUTHENTICATED` → single-flight-refresh → retry-once behavior (§9). The
//! request message is empty; identity is derived entirely server-side from the
//! bearer token, and the response's `email`/`preferred_username` are populated
//! only when the token carries the `email`/`profile` scopes.

use std::future::Future;
use std::sync::Arc;

use tonic::Code;
use tonic::service::interceptor::InterceptedService;
use tonic::transport::Channel;
use uuid::Uuid;

use crate::AxiamError;
use crate::grpc::client::{RefreshFn, status_to_axiam_error};
use crate::grpc::r#gen::user_info_service_client::UserInfoServiceClient;
use crate::grpc::r#gen::{GetUserInfoRequest, GetUserInfoResponse as WireGetUserInfoResponse};
use crate::grpc::interceptor::AuthInterceptor;
use crate::token::TokenManager;

/// The authenticated caller's identity claims (CONTRACT.md §1.1). Mirrors the
/// `GetUserInfoResponse` proto message and the server's REST `/oauth2/userinfo`
/// claim set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserInfo {
    /// Subject (user) UUID — always present.
    pub sub: String,
    /// Tenant UUID — always present.
    pub tenant_id: String,
    /// Organization UUID — always present.
    pub org_id: String,
    /// User email. `Some` only when the access token carried the `email` scope.
    pub email: Option<String>,
    /// Preferred username. `Some` only when the token carried the `profile` scope.
    pub preferred_username: Option<String>,
}

impl From<WireGetUserInfoResponse> for UserInfo {
    fn from(wire: WireGetUserInfoResponse) -> Self {
        UserInfo {
            sub: wire.sub,
            tenant_id: wire.tenant_id,
            org_id: wire.org_id,
            email: wire.email,
            preferred_username: wire.preferred_username,
        }
    }
}

type InnerClient = UserInfoServiceClient<InterceptedService<Channel, AuthInterceptor>>;

/// gRPC transport client for `UserInfoService` (`GetUserInfo`), reusing the
/// single shared lazily-connected [`Channel`] and injecting auth + tenant
/// metadata via [`AuthInterceptor`] on every RPC.
#[derive(Clone)]
pub struct UserInfoGrpcClient {
    inner: InnerClient,
    token_manager: Arc<TokenManager>,
    tenant_id: Uuid,
    refresh_fn: RefreshFn,
}

impl UserInfoGrpcClient {
    /// Wrap an already-constructed shared [`Channel`] (see
    /// [`crate::grpc::channel::build_channel`]) with the auth/tenant
    /// interceptor. `token_manager` and `refresh_fn` follow the same contract
    /// as [`crate::grpc::client::AuthzGrpcClient::new`] — share the same
    /// `TokenManager` instance across transports so a `login()` token is
    /// visible here.
    pub fn new(
        channel: Channel,
        token_manager: Arc<TokenManager>,
        tenant_id: Uuid,
        refresh_fn: RefreshFn,
    ) -> Self {
        let interceptor = AuthInterceptor::new(Arc::clone(&token_manager), tenant_id);
        let inner = UserInfoServiceClient::with_interceptor(channel, interceptor);
        Self {
            inner,
            token_manager,
            tenant_id,
            refresh_fn,
        }
    }

    /// The tenant UUID this client was constructed with (never the slug form).
    pub fn tenant_id(&self) -> Uuid {
        self.tenant_id
    }

    /// `get_user_info` — fetch the authenticated caller's identity (CONTRACT.md
    /// §1.1). Requires a prior `login()` (the interceptor injects the cached
    /// access token; with no token the interceptor fails `UNAUTHENTICATED`
    /// before any wire call). On `UNAUTHENTICATED`, drives the shared
    /// single-flight refresh (§9) and retries exactly once.
    pub async fn get_user_info(&self) -> Result<UserInfo, AxiamError> {
        match self.try_get_user_info().await {
            Ok(resp) => Ok(resp.into()),
            Err(status) if status.code() == Code::Unauthenticated => self
                .refresh_and_retry(|| self.try_get_user_info())
                .await
                .map(Into::into),
            Err(status) => Err(status_to_axiam_error(status)),
        }
    }

    async fn try_get_user_info(&self) -> Result<WireGetUserInfoResponse, tonic::Status> {
        let mut client = self.inner.clone();
        client
            .get_user_info(GetUserInfoRequest {})
            .await
            .map(|resp| resp.into_inner())
    }

    /// Drive the shared single-flight refresh (§9) then retry `attempt` exactly
    /// once. Mirrors `AuthzGrpcClient::refresh_and_retry` — the interceptor is
    /// synchronous and must never touch the async refresh mutex (Pitfall 3).
    async fn refresh_and_retry<T, F, Fut>(&self, attempt: F) -> Result<T, AxiamError>
    where
        F: Fn() -> Fut,
        Fut: Future<Output = Result<T, tonic::Status>>,
    {
        let observed = self
            .token_manager
            .cached_access_token()
            .map(|t| t.expose().clone())
            .unwrap_or_default();

        let refresh_fn = Arc::clone(&self.refresh_fn);
        self.token_manager
            .refresh_if_needed(&observed, move |refresh_token| refresh_fn(refresh_token))
            .await?;

        attempt().await.map_err(status_to_axiam_error)
    }
}
