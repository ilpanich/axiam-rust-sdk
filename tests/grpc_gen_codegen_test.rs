//! Coverage for the generated tonic stubs (`src/gen/axiam.v1.rs`) surface
//! that the higher-level round-trip tests
//! (`grpc_check_access_test.rs`/`grpc_token_user_service_test.rs`) do not
//! exercise: the generated *client* configuration builders
//! (`send_compressed`/`accept_compressed`/`max_*_message_size`/
//! `with_origin`/`with_interceptor`), the generated associated `connect`
//! constructor, and the generated *server* configuration builders +
//! `Clone`/`NamedService`/unknown-path dispatch fallback.
//!
//! These are all part of the crate's public API surface (`pub mod gen`) — a
//! consumer building a raw client or hosting a raw server reaches them
//! directly. None require a real `AuthorizationEngine`; the stubs return
//! canned responses, and several checks (the config builders, the
//! unknown-path fallback) need no server round-trip at all.

#![cfg(feature = "grpc")]

use std::net::SocketAddr;

use axiam_sdk::grpc::r#gen::authorization_service_client::AuthorizationServiceClient;
use axiam_sdk::grpc::r#gen::authorization_service_server::{
    AuthorizationService, AuthorizationServiceServer, SERVICE_NAME as AUTHZ_SERVICE_NAME,
};
use axiam_sdk::grpc::r#gen::token_service_client::TokenServiceClient;
use axiam_sdk::grpc::r#gen::token_service_server::{
    TokenService, TokenServiceServer, SERVICE_NAME as TOKEN_SERVICE_NAME,
};
use axiam_sdk::grpc::r#gen::user_service_client::UserServiceClient;
use axiam_sdk::grpc::r#gen::user_service_server::{
    UserService, UserServiceServer, SERVICE_NAME as USER_SERVICE_NAME,
};
use axiam_sdk::grpc::r#gen::{
    BatchCheckAccessRequest, BatchCheckAccessResponse, CheckAccessRequest, CheckAccessResponse,
    GetUserRequest, IntrospectTokenRequest, IntrospectTokenResponse, UserResponse,
    ValidateCredentialsRequest, ValidateCredentialsResponse, ValidateTokenRequest,
    ValidateTokenResponse,
};
use tonic::codegen::http;
use tonic::codegen::CompressionEncoding;
use tonic::codegen::Service;
use tonic::server::NamedService;
use tonic::transport::server::TcpIncoming;
use tonic::transport::{Channel, Server};
use tonic::{Request, Response, Status};

// ---------------------------------------------------------------------------
// Minimal stub service implementations (canned OK responses).
// ---------------------------------------------------------------------------

struct StubAuthz;

#[tonic::async_trait]
impl AuthorizationService for StubAuthz {
    async fn check_access(
        &self,
        _request: Request<CheckAccessRequest>,
    ) -> Result<Response<CheckAccessResponse>, Status> {
        Ok(Response::new(CheckAccessResponse {
            allowed: true,
            deny_reason: String::new(),
        }))
    }

    async fn batch_check_access(
        &self,
        _request: Request<BatchCheckAccessRequest>,
    ) -> Result<Response<BatchCheckAccessResponse>, Status> {
        Ok(Response::new(BatchCheckAccessResponse { results: vec![] }))
    }
}

struct StubToken;

#[tonic::async_trait]
impl TokenService for StubToken {
    async fn validate_token(
        &self,
        _request: Request<ValidateTokenRequest>,
    ) -> Result<Response<ValidateTokenResponse>, Status> {
        Ok(Response::new(ValidateTokenResponse {
            valid: true,
            subject_id: String::new(),
            tenant_id: String::new(),
            org_id: String::new(),
            exp: 0,
        }))
    }

    async fn introspect_token(
        &self,
        _request: Request<IntrospectTokenRequest>,
    ) -> Result<Response<IntrospectTokenResponse>, Status> {
        Ok(Response::new(IntrospectTokenResponse::default()))
    }
}

struct StubUser;

#[tonic::async_trait]
impl UserService for StubUser {
    async fn get_user(
        &self,
        _request: Request<GetUserRequest>,
    ) -> Result<Response<UserResponse>, Status> {
        Ok(Response::new(UserResponse::default()))
    }

    async fn validate_credentials(
        &self,
        _request: Request<ValidateCredentialsRequest>,
    ) -> Result<Response<ValidateCredentialsResponse>, Status> {
        Ok(Response::new(ValidateCredentialsResponse {
            valid: true,
            user_id: String::new(),
        }))
    }
}

/// Start an `AuthorizationService` server whose generated server type has the
/// full set of configuration builders applied (compression + message-size
/// caps), proving those generated builder methods compile and are wired into
/// a working server. Returns the bound loopback address.
async fn start_configured_authz_server() -> SocketAddr {
    let incoming = TcpIncoming::bind("127.0.0.1:0".parse().unwrap()).expect("bind loopback");
    let addr = incoming.local_addr().expect("resolve local_addr");

    let service = AuthorizationServiceServer::from_arc(std::sync::Arc::new(StubAuthz))
        .accept_compressed(CompressionEncoding::Gzip)
        .send_compressed(CompressionEncoding::Gzip)
        .max_decoding_message_size(8 * 1024 * 1024)
        .max_encoding_message_size(8 * 1024 * 1024);

    tokio::spawn(async move {
        Server::builder()
            .add_service(service)
            .serve_with_incoming(incoming)
            .await
            .expect("in-process authz server");
    });

    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    addr
}

#[tokio::test]
async fn generated_authz_client_connect_and_config_builders_round_trip() {
    let addr = start_configured_authz_server().await;

    // The generated associated `connect` constructor (distinct from building
    // a `Channel` by hand) — establishes a real connection to the server.
    let client = AuthorizationServiceClient::connect(format!("http://{addr}"))
        .await
        .expect("generated connect() must reach the in-process server");

    // Exercise every generated client-side configuration builder.
    let mut client = client
        .send_compressed(CompressionEncoding::Gzip)
        .accept_compressed(CompressionEncoding::Gzip)
        .max_decoding_message_size(4 * 1024 * 1024)
        .max_encoding_message_size(4 * 1024 * 1024);

    let resp = client
        .check_access(CheckAccessRequest {
            tenant_id: "t".into(),
            subject_id: "s".into(),
            action: "read".into(),
            resource_id: "r".into(),
            scope: Some("sub".into()),
        })
        .await
        .expect("configured client round-trips against the configured server");
    assert!(resp.into_inner().allowed);
}

#[tokio::test]
async fn generated_token_client_connect_and_config_builders_round_trip() {
    let incoming = TcpIncoming::bind("127.0.0.1:0".parse().unwrap()).expect("bind loopback");
    let addr = incoming.local_addr().expect("local_addr");
    let service = TokenServiceServer::from_arc(std::sync::Arc::new(StubToken))
        .accept_compressed(CompressionEncoding::Gzip)
        .send_compressed(CompressionEncoding::Gzip)
        .max_decoding_message_size(1024 * 1024)
        .max_encoding_message_size(1024 * 1024);
    tokio::spawn(async move {
        Server::builder()
            .add_service(service)
            .serve_with_incoming(incoming)
            .await
            .expect("token server");
    });
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;

    let mut client = TokenServiceClient::connect(format!("http://{addr}"))
        .await
        .expect("generated TokenServiceClient::connect")
        .send_compressed(CompressionEncoding::Gzip)
        .accept_compressed(CompressionEncoding::Gzip)
        .max_decoding_message_size(1024 * 1024)
        .max_encoding_message_size(1024 * 1024);

    let resp = client
        .validate_token(ValidateTokenRequest {
            access_token: "x".into(),
        })
        .await
        .expect("token round-trip");
    assert!(resp.into_inner().valid);
}

#[tokio::test]
async fn generated_user_client_connect_and_config_builders_round_trip() {
    let incoming = TcpIncoming::bind("127.0.0.1:0".parse().unwrap()).expect("bind loopback");
    let addr = incoming.local_addr().expect("local_addr");
    let service = UserServiceServer::from_arc(std::sync::Arc::new(StubUser))
        .accept_compressed(CompressionEncoding::Gzip)
        .send_compressed(CompressionEncoding::Gzip)
        .max_decoding_message_size(1024 * 1024)
        .max_encoding_message_size(1024 * 1024);
    tokio::spawn(async move {
        Server::builder()
            .add_service(service)
            .serve_with_incoming(incoming)
            .await
            .expect("user server");
    });
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;

    let mut client = UserServiceClient::connect(format!("http://{addr}"))
        .await
        .expect("generated UserServiceClient::connect")
        .send_compressed(CompressionEncoding::Gzip)
        .accept_compressed(CompressionEncoding::Gzip)
        .max_decoding_message_size(1024 * 1024)
        .max_encoding_message_size(1024 * 1024);

    let resp = client
        .validate_credentials(ValidateCredentialsRequest {
            tenant_id: "t".into(),
            username_or_email: "u".into(),
            password: "p".into(),
        })
        .await
        .expect("credentials round-trip");
    assert!(resp.into_inner().valid);
}

// ---------------------------------------------------------------------------
// `with_origin` / `with_interceptor` constructors — build over a lazy channel
// (no I/O needed to construct them).
// ---------------------------------------------------------------------------

fn lazy_channel() -> Channel {
    Channel::from_static("http://127.0.0.1:50051").connect_lazy()
}

#[tokio::test]
async fn generated_clients_with_origin_and_with_interceptor_construct() {
    let origin: http::Uri = "http://example.test/".parse().unwrap();

    // `with_origin` on every generated client type.
    let _ = AuthorizationServiceClient::with_origin(lazy_channel(), origin.clone());
    let _ = TokenServiceClient::with_origin(lazy_channel(), origin.clone());
    let _ = UserServiceClient::with_origin(lazy_channel(), origin);

    // `with_interceptor` on every generated client type — a no-op interceptor
    // that passes the request through unchanged.
    let noop = |req: Request<()>| Ok(req);
    let _ = AuthorizationServiceClient::with_interceptor(lazy_channel(), noop);
    let _ = TokenServiceClient::with_interceptor(lazy_channel(), noop);
    let _ = UserServiceClient::with_interceptor(lazy_channel(), noop);
}

#[test]
fn generated_servers_with_interceptor_and_clone_construct() {
    let noop = |req: Request<()>| Ok(req);

    // `with_interceptor` on every generated server type.
    let _ = AuthorizationServiceServer::with_interceptor(StubAuthz, noop);
    let _ = TokenServiceServer::with_interceptor(StubToken, noop);
    let _ = UserServiceServer::with_interceptor(StubUser, noop);

    // `Clone` (the generated hand-rolled impl that copies the config fields).
    let authz = AuthorizationServiceServer::new(StubAuthz)
        .max_decoding_message_size(1)
        .max_encoding_message_size(1);
    let _ = authz.clone();
    let token = TokenServiceServer::new(StubToken);
    let _ = token.clone();
    let user = UserServiceServer::new(StubUser);
    let _ = user.clone();
}

#[test]
fn generated_named_service_constants_match_proto_package() {
    assert_eq!(AUTHZ_SERVICE_NAME, "axiam.v1.AuthorizationService");
    assert_eq!(TOKEN_SERVICE_NAME, "axiam.v1.TokenService");
    assert_eq!(USER_SERVICE_NAME, "axiam.v1.UserService");

    // The `NamedService::NAME` associated const mirrors `SERVICE_NAME`.
    assert_eq!(
        <AuthorizationServiceServer<StubAuthz> as NamedService>::NAME,
        AUTHZ_SERVICE_NAME
    );
    assert_eq!(
        <TokenServiceServer<StubToken> as NamedService>::NAME,
        TOKEN_SERVICE_NAME
    );
    assert_eq!(
        <UserServiceServer<StubUser> as NamedService>::NAME,
        USER_SERVICE_NAME
    );
}

// ---------------------------------------------------------------------------
// Unknown-path dispatch fallback: every generated server's `Service::call`
// answers an unrecognized method path with a gRPC `Unimplemented` response
// rather than panicking or 404-ing.
// ---------------------------------------------------------------------------

async fn assert_unimplemented_on_unknown_path<S>(mut server: S, path: &str)
where
    S: Service<
        http::Request<tonic::body::Body>,
        Response = http::Response<tonic::body::Body>,
        Error = std::convert::Infallible,
    >,
{
    let req = http::Request::builder()
        .method("POST")
        .uri(path)
        .body(tonic::body::Body::default())
        .expect("build request");
    let resp = server.call(req).await.expect("dispatch is infallible");
    let grpc_status = resp
        .headers()
        .get("grpc-status")
        .expect("unknown path must set a grpc-status header");
    // `tonic::Code::Unimplemented as i32` == 12.
    assert_eq!(grpc_status, "12");
}

#[tokio::test]
async fn generated_authz_server_unknown_path_maps_to_unimplemented() {
    assert_unimplemented_on_unknown_path(
        AuthorizationServiceServer::new(StubAuthz),
        "/axiam.v1.AuthorizationService/NoSuchMethod",
    )
    .await;
}

#[tokio::test]
async fn generated_token_server_unknown_path_maps_to_unimplemented() {
    assert_unimplemented_on_unknown_path(
        TokenServiceServer::new(StubToken),
        "/axiam.v1.TokenService/NoSuchMethod",
    )
    .await;
}

#[tokio::test]
async fn generated_user_server_unknown_path_maps_to_unimplemented() {
    assert_unimplemented_on_unknown_path(
        UserServiceServer::new(StubUser),
        "/axiam.v1.UserService/NoSuchMethod",
    )
    .await;
}

// ---------------------------------------------------------------------------
// Message-type `prost::Message` round-trips + `Debug`: covers encode/decode
// of the optional-field (`scope`) and repeated-field (`requests`/`results`)
// branches, and the derived `Debug` formatting.
// ---------------------------------------------------------------------------

#[test]
fn message_types_encode_decode_round_trip() {
    use prost::Message as _;

    // Optional field present.
    let with_scope = CheckAccessRequest {
        tenant_id: "t".into(),
        subject_id: "s".into(),
        action: "read".into(),
        resource_id: "r".into(),
        scope: Some("child".into()),
    };
    let mut buf = Vec::new();
    with_scope.encode(&mut buf).unwrap();
    assert_eq!(CheckAccessRequest::decode(&buf[..]).unwrap(), with_scope);

    // Optional field absent (exercises the other merge/encode branch).
    let no_scope = CheckAccessRequest {
        scope: None,
        ..with_scope.clone()
    };
    let mut buf2 = Vec::new();
    no_scope.encode(&mut buf2).unwrap();
    assert_eq!(CheckAccessRequest::decode(&buf2[..]).unwrap(), no_scope);

    // Repeated message field round-trip.
    let batch = BatchCheckAccessRequest {
        requests: vec![with_scope.clone(), no_scope.clone()],
    };
    let mut buf3 = Vec::new();
    batch.encode(&mut buf3).unwrap();
    assert_eq!(BatchCheckAccessRequest::decode(&buf3[..]).unwrap(), batch);

    let batch_resp = BatchCheckAccessResponse {
        results: vec![CheckAccessResponse {
            allowed: false,
            deny_reason: "nope".into(),
        }],
    };
    let mut buf4 = Vec::new();
    batch_resp.encode(&mut buf4).unwrap();
    assert_eq!(
        BatchCheckAccessResponse::decode(&buf4[..]).unwrap(),
        batch_resp
    );

    // `Debug` on a representative set of the generated types.
    assert!(format!("{with_scope:?}").contains("CheckAccessRequest"));
    assert!(format!("{batch_resp:?}").contains("BatchCheckAccessResponse"));
    assert!(format!("{:?}", IntrospectTokenResponse::default()).contains("IntrospectTokenResponse"));
    assert!(format!("{:?}", UserResponse::default()).contains("UserResponse"));
}

#[test]
fn access_decision_from_wire_response_maps_deny_reason() {
    use axiam_sdk::grpc::AccessDecision;

    // An allow decision carries no reason.
    let allow = AccessDecision::from(CheckAccessResponse {
        allowed: true,
        deny_reason: String::new(),
    });
    assert!(allow.allowed);
    assert!(allow.reason.is_none());

    // A deny decision surfaces the non-empty `deny_reason` as `Some(_)`.
    let deny = AccessDecision::from(CheckAccessResponse {
        allowed: false,
        deny_reason: "caller lacks permission".into(),
    });
    assert!(!deny.allowed);
    assert_eq!(deny.reason.as_deref(), Some("caller lacks permission"));
}
