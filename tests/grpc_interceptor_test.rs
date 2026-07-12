//! `AuthInterceptor` (`src/grpc/interceptor.rs`) branch coverage: the
//! "no cached access token" rejection and a successful metadata-injection
//! call. The happy path is already exercised indirectly through
//! `tests/grpc_check_access_test.rs` (via `AuthzGrpcClient`), but this file
//! drives `Interceptor::call` directly so both branches are independently
//! verifiable without a running gRPC server.

#![cfg(feature = "grpc")]

use std::sync::Arc;

use axiam_sdk::grpc::AuthInterceptor;
use axiam_sdk::token::TokenManager;
use axiam_sdk::Sensitive;
use tonic::service::Interceptor;
use tonic::Request;
use uuid::Uuid;

#[test]
fn call_rejects_when_no_access_token_is_cached() {
    let token_manager = Arc::new(TokenManager::new());
    let tenant_id = Uuid::new_v4();
    let mut interceptor = AuthInterceptor::new(token_manager, tenant_id);

    let err = interceptor
        .call(Request::new(()))
        .expect_err("an interceptor with no cached token must reject the call synchronously");

    assert_eq!(err.code(), tonic::Code::Unauthenticated);
}

#[tokio::test]
async fn call_injects_authorization_and_tenant_metadata_when_token_is_cached() {
    let token_manager = Arc::new(TokenManager::new());
    token_manager
        .set_tokens(
            Sensitive::new("cached-access-token".to_string()),
            None,
            None,
            None,
        )
        .await;
    let tenant_id = Uuid::new_v4();
    let mut interceptor = AuthInterceptor::new(Arc::clone(&token_manager), tenant_id);

    let req = interceptor
        .call(Request::new(()))
        .expect("a cached token must let the call through");

    let auth = req
        .metadata()
        .get("authorization")
        .expect("authorization metadata must be set")
        .to_str()
        .expect("authorization metadata must be valid ASCII");
    assert_eq!(auth, "Bearer cached-access-token");

    let tenant = req
        .metadata()
        .get("x-tenant-id")
        .expect("x-tenant-id metadata must be set")
        .to_str()
        .expect("x-tenant-id metadata must be valid ASCII");
    assert_eq!(tenant, tenant_id.to_string());
}

#[tokio::test]
async fn call_rejects_when_cached_token_contains_an_invalid_header_byte() {
    // `tonic::metadata::MetadataValue<Ascii>` wraps `http::HeaderValue`,
    // which actually permits non-ASCII UTF-8 bytes as opaque `obs-text`
    // (RFC 7230) — only true control characters (e.g. `\n`, `\r`, and other
    // bytes < 0x20 or 0x7F) are rejected. So a merely-accented character is
    // NOT enough to hit this branch (confirmed empirically: the interceptor
    // accepts it). A raw newline embedded in the cached token, however, IS
    // rejected, letting this test reach the "failed to construct
    // authorization metadata" -> `Status::internal` branch without
    // panicking on the `.parse().unwrap()`-equivalent `?`.
    let token_manager = Arc::new(TokenManager::new());
    token_manager
        .set_tokens(
            Sensitive::new("bad-token-with-a\nnewline".to_string()),
            None,
            None,
            None,
        )
        .await;
    let tenant_id = Uuid::new_v4();
    let mut interceptor = AuthInterceptor::new(token_manager, tenant_id);

    let err = interceptor
        .call(Request::new(()))
        .expect_err("a cached token containing a control byte must be rejected, not panic");

    assert_eq!(err.code(), tonic::Code::Internal);
}
