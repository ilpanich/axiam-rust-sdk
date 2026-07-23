//! In-process tonic test server proving `get_user_info` round-trips through the
//! generated `UserInfoService` stubs (CONTRACT.md §1.1): claim mapping, optional
//! scope-gated fields, `UNAUTHENTICATED` → single-flight-refresh → retry-once.

#![cfg(feature = "grpc")]

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use axiam_sdk::grpc::r#gen::user_info_service_server::{UserInfoService, UserInfoServiceServer};
use axiam_sdk::grpc::r#gen::{GetUserInfoRequest, GetUserInfoResponse as WireGetUserInfoResponse};
use axiam_sdk::grpc::{GrpcChannelConfig, UserInfo, UserInfoGrpcClient, build_channel};
use axiam_sdk::token::TokenManager;
use axiam_sdk::token::refresh_guard::RefreshedTokens;
use axiam_sdk::{AxiamError, Sensitive};
use tonic::transport::Server;
use tonic::transport::server::TcpIncoming;
use tonic::{Request, Response, Status};
use uuid::Uuid;

/// Stub `UserInfoService`. Returns a canned identity; when
/// `unauthenticated_once` is set, fails `UNAUTHENTICATED` on the first call and
/// succeeds afterward (proves the §9 refresh-then-retry path). `always_status`
/// forces every call to fail with the given status code (proves error mapping
/// and the retry-still-fails path).
struct StubUserInfoService {
    sub: String,
    tenant_id: String,
    org_id: String,
    email: Option<String>,
    preferred_username: Option<String>,
    unauthenticated_once: bool,
    /// When `Some`, every call fails with this code (never succeeds).
    always_status: Option<tonic::Code>,
    already_fired: Arc<AtomicBool>,
    call_count: Arc<AtomicUsize>,
}

#[tonic::async_trait]
impl UserInfoService for StubUserInfoService {
    async fn get_user_info(
        &self,
        _request: Request<GetUserInfoRequest>,
    ) -> Result<Response<WireGetUserInfoResponse>, Status> {
        self.call_count.fetch_add(1, Ordering::SeqCst);
        if let Some(code) = self.always_status {
            return Err(Status::new(code, "forced test failure"));
        }
        if self.unauthenticated_once && !self.already_fired.swap(true, Ordering::SeqCst) {
            return Err(Status::unauthenticated("token expired"));
        }
        Ok(Response::new(WireGetUserInfoResponse {
            sub: self.sub.clone(),
            tenant_id: self.tenant_id.clone(),
            org_id: self.org_id.clone(),
            email: self.email.clone(),
            preferred_username: self.preferred_username.clone(),
        }))
    }
}

async fn start_test_server(service: StubUserInfoService) -> SocketAddr {
    let incoming =
        TcpIncoming::bind("127.0.0.1:0".parse().unwrap()).expect("bind ephemeral loopback port");
    let addr = incoming.local_addr().expect("resolve bound local_addr");
    tokio::spawn(async move {
        Server::builder()
            .add_service(UserInfoServiceServer::new(service))
            .serve_with_incoming(incoming)
            .await
            .expect("in-process tonic test server");
    });
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    addr
}

fn counting_refresh_fn(counter: Arc<AtomicUsize>) -> axiam_sdk::grpc::RefreshFn {
    Arc::new(move |_refresh_token: String| {
        let counter = Arc::clone(&counter);
        let fut: Pin<Box<dyn Future<Output = Result<RefreshedTokens, AxiamError>> + Send>> =
            Box::pin(async move {
                counter.fetch_add(1, Ordering::SeqCst);
                Ok(RefreshedTokens {
                    access: Sensitive::new("new-access-token".to_string()),
                    refresh: Some(Sensitive::new("new-refresh-token".to_string())),
                    exp: Some(9_999_999_999),
                    tenant_id: None,
                })
            });
        fut
    })
}

async fn build_test_client(
    addr: SocketAddr,
    tenant_id: Uuid,
    refresh_call_count: Arc<AtomicUsize>,
) -> UserInfoGrpcClient {
    let token_manager = Arc::new(TokenManager::new());
    token_manager
        .set_tokens(
            Sensitive::new("initial-access-token".to_string()),
            Some(Sensitive::new("initial-refresh-token".to_string())),
            Some(9_999_999_999),
            Some(tenant_id),
        )
        .await;
    let channel = build_channel(&format!("http://{addr}"), &GrpcChannelConfig::default())
        .expect("build shared lazy channel");
    UserInfoGrpcClient::new(
        channel,
        token_manager,
        tenant_id,
        counting_refresh_fn(refresh_call_count),
    )
}

fn stub(
    email: Option<&str>,
    preferred_username: Option<&str>,
    unauthenticated_once: bool,
    call_count: Arc<AtomicUsize>,
) -> StubUserInfoService {
    StubUserInfoService {
        sub: "11111111-1111-1111-1111-111111111111".to_string(),
        tenant_id: "22222222-2222-2222-2222-222222222222".to_string(),
        org_id: "33333333-3333-3333-3333-333333333333".to_string(),
        email: email.map(String::from),
        preferred_username: preferred_username.map(String::from),
        unauthenticated_once,
        always_status: None,
        already_fired: Arc::new(AtomicBool::new(false)),
        call_count,
    }
}

/// A stub that fails every call with the given status code.
fn failing_stub(code: tonic::Code) -> StubUserInfoService {
    StubUserInfoService {
        sub: "11111111-1111-1111-1111-111111111111".to_string(),
        tenant_id: "22222222-2222-2222-2222-222222222222".to_string(),
        org_id: "33333333-3333-3333-3333-333333333333".to_string(),
        email: None,
        preferred_username: None,
        unauthenticated_once: false,
        always_status: Some(code),
        already_fired: Arc::new(AtomicBool::new(false)),
        call_count: Arc::new(AtomicUsize::new(0)),
    }
}

#[tokio::test]
async fn grpc_get_user_info_maps_all_claims() {
    let addr = start_test_server(stub(
        Some("alice@example.com"),
        Some("alice"),
        false,
        Arc::new(AtomicUsize::new(0)),
    ))
    .await;
    let tenant_id = Uuid::new_v4();
    let client = build_test_client(addr, tenant_id, Arc::new(AtomicUsize::new(0))).await;

    let info = client
        .get_user_info()
        .await
        .expect("get_user_info succeeds");
    assert_eq!(
        info,
        UserInfo {
            sub: "11111111-1111-1111-1111-111111111111".to_string(),
            tenant_id: "22222222-2222-2222-2222-222222222222".to_string(),
            org_id: "33333333-3333-3333-3333-333333333333".to_string(),
            email: Some("alice@example.com".to_string()),
            preferred_username: Some("alice".to_string()),
        }
    );
}

#[tokio::test]
async fn grpc_get_user_info_omits_absent_scoped_claims() {
    let addr = start_test_server(stub(None, None, false, Arc::new(AtomicUsize::new(0)))).await;
    let tenant_id = Uuid::new_v4();
    let client = build_test_client(addr, tenant_id, Arc::new(AtomicUsize::new(0))).await;

    let info = client
        .get_user_info()
        .await
        .expect("get_user_info succeeds");
    assert!(info.email.is_none());
    assert!(info.preferred_username.is_none());
    assert_eq!(info.sub, "11111111-1111-1111-1111-111111111111");
}

#[tokio::test]
async fn grpc_get_user_info_unauthenticated_drives_exactly_one_refresh() {
    let addr = start_test_server(stub(
        Some("alice@example.com"),
        None,
        true,
        Arc::new(AtomicUsize::new(0)),
    ))
    .await;
    let tenant_id = Uuid::new_v4();
    let refresh_count = Arc::new(AtomicUsize::new(0));
    let client = build_test_client(addr, tenant_id, Arc::clone(&refresh_count)).await;

    let info = client
        .get_user_info()
        .await
        .expect("UNAUTHENTICATED-then-success should ultimately succeed");
    assert_eq!(info.email.as_deref(), Some("alice@example.com"));
    assert_eq!(
        refresh_count.load(Ordering::SeqCst),
        1,
        "exactly one single-flight refresh must occur (§9.3)"
    );
}

#[tokio::test]
async fn grpc_get_user_info_permission_denied_maps_to_authz_error() {
    // A non-UNAUTHENTICATED terminal status is mapped through the §2 taxonomy
    // and returned directly (no refresh). PERMISSION_DENIED -> AxiamError::Authz.
    let addr = start_test_server(failing_stub(tonic::Code::PermissionDenied)).await;
    let tenant_id = Uuid::new_v4();
    let client = build_test_client(addr, tenant_id, Arc::new(AtomicUsize::new(0))).await;

    let err = client.get_user_info().await.unwrap_err();
    assert!(
        matches!(err, AxiamError::Authz { .. }),
        "PERMISSION_DENIED must map to AxiamError::Authz per CONTRACT §2, got: {err:?}"
    );
}

#[tokio::test]
async fn grpc_get_user_info_unauthenticated_retry_still_fails_returns_error() {
    // Server always returns UNAUTHENTICATED: the single-flight refresh runs
    // once, the retry also fails, and the terminal error is surfaced.
    let addr = start_test_server(failing_stub(tonic::Code::Unauthenticated)).await;
    let tenant_id = Uuid::new_v4();
    let refresh_count = Arc::new(AtomicUsize::new(0));
    let client = build_test_client(addr, tenant_id, Arc::clone(&refresh_count)).await;

    let err = client.get_user_info().await.unwrap_err();
    assert!(
        matches!(err, AxiamError::Auth { .. }),
        "a persistent UNAUTHENTICATED must surface AxiamError::Auth after the single retry, got: {err:?}"
    );
    assert_eq!(
        refresh_count.load(Ordering::SeqCst),
        1,
        "exactly one single-flight refresh, even when the retry also fails (§9.3)"
    );
}

#[tokio::test]
async fn grpc_user_info_client_exposes_tenant_id() {
    let addr = start_test_server(stub(None, None, false, Arc::new(AtomicUsize::new(0)))).await;
    let tenant_id = Uuid::new_v4();
    let client = build_test_client(addr, tenant_id, Arc::new(AtomicUsize::new(0))).await;
    assert_eq!(client.tenant_id(), tenant_id);
}

#[tokio::test]
async fn grpc_get_user_info_unavailable_maps_to_network_error() {
    // A transport-level UNAVAILABLE (no refresh) maps to AxiamError::Network (§2),
    // exercising the generated client's error path for this RPC.
    let addr = start_test_server(failing_stub(tonic::Code::Unavailable)).await;
    let tenant_id = Uuid::new_v4();
    let client = build_test_client(addr, tenant_id, Arc::new(AtomicUsize::new(0))).await;

    let err = client.get_user_info().await.unwrap_err();
    assert!(
        matches!(err, AxiamError::Network { .. }),
        "UNAVAILABLE must map to AxiamError::Network per CONTRACT §2, got: {err:?}"
    );
}

/// Exercise the generated `GetUserInfoRequest` / `GetUserInfoResponse` message
/// derive impls (Clone / PartialEq / Debug / Default) and the SDK's `UserInfo`
/// conversion — round-trip tests alone don't touch these code paths.
#[test]
fn generated_userinfo_message_and_model_derives() {
    let resp = WireGetUserInfoResponse {
        sub: "s".to_string(),
        tenant_id: "t".to_string(),
        org_id: "o".to_string(),
        email: Some("e@example.com".to_string()),
        preferred_username: None,
    };
    let cloned = resp.clone();
    assert_eq!(resp, cloned);
    assert!(!format!("{resp:?}").is_empty());
    assert_ne!(resp, WireGetUserInfoResponse::default());

    let req = GetUserInfoRequest {};
    assert_eq!(req, GetUserInfoRequest::default());
    assert!(format!("{req:?}").contains("GetUserInfoRequest"));

    // SDK model conversion + its own derives.
    let info: UserInfo = cloned.into();
    assert_eq!(info.email.as_deref(), Some("e@example.com"));
    assert!(info.preferred_username.is_none());
    assert_eq!(info, info.clone());
    assert!(format!("{info:?}").contains("UserInfo"));
}
