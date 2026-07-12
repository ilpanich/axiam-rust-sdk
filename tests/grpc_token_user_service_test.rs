//! In-process tonic 0.14 test servers proving the `TokenService`/`UserService`
//! generated stubs (`src/gen/axiam.v1.rs`) round-trip correctly end to end.
//!
//! Unlike `AuthorizationService` (see `tests/grpc_check_access_test.rs`),
//! neither `TokenService` nor `UserService` has an ergonomic wrapper in
//! `src/grpc/client.rs` — the SDK only builds `AuthzGrpcClient` on top of
//! `AuthorizationServiceClient`. The two generated client/server pairs
//! exercised here are still `pub mod gen` and therefore part of the crate's
//! public API surface (reachable as
//! `axiam_sdk::grpc::gen::token_service_client::TokenServiceClient` /
//! `axiam_sdk::grpc::gen::user_service_client::UserServiceClient`), so a
//! consumer that needs raw JWT introspection or a server-side credential
//! check can already use them directly. These tests exercise that surface
//! the same way `grpc_check_access_test.rs` exercises `AuthorizationService`:
//! a stub server implementing the generated `*Service` trait, and the
//! generated `*Client` making real (in-process, loopback) unary RPCs against
//! it — proving both the client's request encoding and the server's
//! dispatch/response encoding, not just the message structs' `Message` impl
//! in isolation.

#![cfg(feature = "grpc")]

use std::net::SocketAddr;

use axiam_sdk::grpc::gen::token_service_client::TokenServiceClient;
use axiam_sdk::grpc::gen::token_service_server::{TokenService, TokenServiceServer};
use axiam_sdk::grpc::gen::user_service_client::UserServiceClient;
use axiam_sdk::grpc::gen::user_service_server::{UserService, UserServiceServer};
use axiam_sdk::grpc::gen::{
    GetUserRequest, IntrospectTokenRequest, IntrospectTokenResponse, UserResponse,
    ValidateCredentialsRequest, ValidateCredentialsResponse, ValidateTokenRequest,
    ValidateTokenResponse,
};
use tonic::transport::server::TcpIncoming;
use tonic::transport::{Channel, Server};
use tonic::{Request, Response, Status};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// TokenService stub
// ---------------------------------------------------------------------------

struct StubTokenService;

#[tonic::async_trait]
impl TokenService for StubTokenService {
    async fn validate_token(
        &self,
        request: Request<ValidateTokenRequest>,
    ) -> Result<Response<ValidateTokenResponse>, Status> {
        let req = request.into_inner();
        if req.access_token == "valid-token" {
            Ok(Response::new(ValidateTokenResponse {
                valid: true,
                subject_id: "11111111-1111-1111-1111-111111111111".into(),
                tenant_id: "22222222-2222-2222-2222-222222222222".into(),
                org_id: "33333333-3333-3333-3333-333333333333".into(),
                exp: 9_999_999_999,
            }))
        } else if req.access_token == "invalid-token" {
            Ok(Response::new(ValidateTokenResponse {
                valid: false,
                subject_id: String::new(),
                tenant_id: String::new(),
                org_id: String::new(),
                exp: 0,
            }))
        } else {
            Err(Status::invalid_argument("unknown test token"))
        }
    }

    async fn introspect_token(
        &self,
        request: Request<IntrospectTokenRequest>,
    ) -> Result<Response<IntrospectTokenResponse>, Status> {
        let req = request.into_inner();
        if req.access_token == "expired-token" {
            return Err(Status::unauthenticated("token expired"));
        }
        Ok(Response::new(IntrospectTokenResponse {
            active: true,
            sub: "11111111-1111-1111-1111-111111111111".into(),
            tenant_id: "22222222-2222-2222-2222-222222222222".into(),
            org_id: "33333333-3333-3333-3333-333333333333".into(),
            iss: "axiam-test".into(),
            iat: 1_000,
            exp: 9_999_999_999,
            jti: Uuid::new_v4().to_string(),
        }))
    }
}

async fn start_token_service_server() -> SocketAddr {
    let incoming =
        TcpIncoming::bind("127.0.0.1:0".parse().unwrap()).expect("bind ephemeral loopback port");
    let addr = incoming.local_addr().expect("resolve bound local_addr");

    tokio::spawn(async move {
        Server::builder()
            .add_service(TokenServiceServer::new(StubTokenService))
            .serve_with_incoming(incoming)
            .await
            .expect("in-process TokenService test server");
    });
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    addr
}

async fn connect_token_client(addr: SocketAddr) -> TokenServiceClient<Channel> {
    let channel = Channel::from_shared(format!("http://{addr}"))
        .expect("valid endpoint")
        .connect()
        .await
        .expect("connect to in-process TokenService server");
    TokenServiceClient::new(channel)
}

#[tokio::test]
async fn validate_token_reports_valid_for_a_good_token() {
    let addr = start_token_service_server().await;
    let mut client = connect_token_client(addr).await;

    let resp = client
        .validate_token(ValidateTokenRequest {
            access_token: "valid-token".into(),
        })
        .await
        .expect("validate_token RPC should succeed")
        .into_inner();

    assert!(resp.valid);
    assert_eq!(resp.subject_id, "11111111-1111-1111-1111-111111111111");
    assert_eq!(resp.exp, 9_999_999_999);
}

#[tokio::test]
async fn validate_token_reports_invalid_with_empty_fields() {
    let addr = start_token_service_server().await;
    let mut client = connect_token_client(addr).await;

    let resp = client
        .validate_token(ValidateTokenRequest {
            access_token: "invalid-token".into(),
        })
        .await
        .expect("validate_token RPC should succeed even for an invalid token")
        .into_inner();

    assert!(!resp.valid);
    assert!(resp.subject_id.is_empty());
    assert_eq!(resp.exp, 0);
}

#[tokio::test]
async fn validate_token_propagates_server_error_status() {
    let addr = start_token_service_server().await;
    let mut client = connect_token_client(addr).await;

    let err = client
        .validate_token(ValidateTokenRequest {
            access_token: "unrecognized".into(),
        })
        .await
        .expect_err("unknown token must surface as a gRPC error");

    assert_eq!(err.code(), tonic::Code::InvalidArgument);
}

#[tokio::test]
async fn introspect_token_returns_full_claims_for_an_active_token() {
    let addr = start_token_service_server().await;
    let mut client = connect_token_client(addr).await;

    let resp = client
        .introspect_token(IntrospectTokenRequest {
            access_token: "active-token".into(),
        })
        .await
        .expect("introspect_token RPC should succeed")
        .into_inner();

    assert!(resp.active);
    assert_eq!(resp.iss, "axiam-test");
    assert_eq!(resp.iat, 1_000);
}

#[tokio::test]
async fn introspect_token_maps_expired_token_to_unauthenticated() {
    let addr = start_token_service_server().await;
    let mut client = connect_token_client(addr).await;

    let err = client
        .introspect_token(IntrospectTokenRequest {
            access_token: "expired-token".into(),
        })
        .await
        .expect_err("expired token must surface as a gRPC error");

    assert_eq!(err.code(), tonic::Code::Unauthenticated);
}

// ---------------------------------------------------------------------------
// UserService stub
// ---------------------------------------------------------------------------

struct StubUserService;

#[tonic::async_trait]
impl UserService for StubUserService {
    async fn get_user(
        &self,
        request: Request<GetUserRequest>,
    ) -> Result<Response<UserResponse>, Status> {
        let req = request.into_inner();
        if req.user_id == "not-found" {
            return Err(Status::not_found("user not found"));
        }
        Ok(Response::new(UserResponse {
            id: req.user_id,
            tenant_id: req.tenant_id,
            username: "alice".into(),
            email: "alice@example.com".into(),
            status: "active".into(),
            created_at: "2026-01-01T00:00:00Z".into(),
            updated_at: "2026-01-01T00:00:00Z".into(),
        }))
    }

    async fn validate_credentials(
        &self,
        request: Request<ValidateCredentialsRequest>,
    ) -> Result<Response<ValidateCredentialsResponse>, Status> {
        let req = request.into_inner();
        if req.password == "correct horse battery staple" {
            Ok(Response::new(ValidateCredentialsResponse {
                valid: true,
                user_id: "44444444-4444-4444-4444-444444444444".into(),
            }))
        } else {
            Ok(Response::new(ValidateCredentialsResponse {
                valid: false,
                user_id: String::new(),
            }))
        }
    }
}

async fn start_user_service_server() -> SocketAddr {
    let incoming =
        TcpIncoming::bind("127.0.0.1:0".parse().unwrap()).expect("bind ephemeral loopback port");
    let addr = incoming.local_addr().expect("resolve bound local_addr");

    tokio::spawn(async move {
        Server::builder()
            .add_service(UserServiceServer::new(StubUserService))
            .serve_with_incoming(incoming)
            .await
            .expect("in-process UserService test server");
    });
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    addr
}

async fn connect_user_client(addr: SocketAddr) -> UserServiceClient<Channel> {
    let channel = Channel::from_shared(format!("http://{addr}"))
        .expect("valid endpoint")
        .connect()
        .await
        .expect("connect to in-process UserService server");
    UserServiceClient::new(channel)
}

#[tokio::test]
async fn get_user_returns_the_requested_user() {
    let addr = start_user_service_server().await;
    let mut client = connect_user_client(addr).await;
    let tenant_id = Uuid::new_v4().to_string();
    let user_id = Uuid::new_v4().to_string();

    let resp = client
        .get_user(GetUserRequest {
            tenant_id: tenant_id.clone(),
            user_id: user_id.clone(),
        })
        .await
        .expect("get_user RPC should succeed")
        .into_inner();

    assert_eq!(resp.id, user_id);
    assert_eq!(resp.tenant_id, tenant_id);
    assert_eq!(resp.status, "active");
}

#[tokio::test]
async fn get_user_maps_missing_user_to_not_found() {
    let addr = start_user_service_server().await;
    let mut client = connect_user_client(addr).await;

    let err = client
        .get_user(GetUserRequest {
            tenant_id: Uuid::new_v4().to_string(),
            user_id: "not-found".into(),
        })
        .await
        .expect_err("missing user must surface as a gRPC error");

    assert_eq!(err.code(), tonic::Code::NotFound);
}

#[tokio::test]
async fn validate_credentials_accepts_the_correct_password() {
    let addr = start_user_service_server().await;
    let mut client = connect_user_client(addr).await;

    let resp = client
        .validate_credentials(ValidateCredentialsRequest {
            tenant_id: Uuid::new_v4().to_string(),
            username_or_email: "alice@example.com".into(),
            password: "correct horse battery staple".into(),
        })
        .await
        .expect("validate_credentials RPC should succeed")
        .into_inner();

    assert!(resp.valid);
    assert_eq!(resp.user_id, "44444444-4444-4444-4444-444444444444");
}

#[tokio::test]
async fn validate_credentials_rejects_the_wrong_password() {
    let addr = start_user_service_server().await;
    let mut client = connect_user_client(addr).await;

    let resp = client
        .validate_credentials(ValidateCredentialsRequest {
            tenant_id: Uuid::new_v4().to_string(),
            username_or_email: "alice@example.com".into(),
            password: "wrong-password".into(),
        })
        .await
        .expect("validate_credentials RPC itself should succeed even on a wrong password")
        .into_inner();

    assert!(!resp.valid);
    assert!(resp.user_id.is_empty());
}
