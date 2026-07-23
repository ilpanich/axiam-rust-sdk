//! `TokenManager::refresh_if_needed` (`src/token/refresh_guard.rs`, §9)
//! branches the single-flight oracle does not reach directly: the
//! double-check short-circuit (a newer token already exists, so no refresh
//! call is made) and the missing-refresh-token error (§9 — re-authentication
//! required).

#![cfg(any(feature = "rest", feature = "grpc"))]

use axiam_sdk::token::TokenManager;
use axiam_sdk::{AxiamError, Sensitive};
use uuid::Uuid;

#[tokio::test]
async fn refresh_short_circuits_when_a_newer_token_already_exists() {
    let tm = TokenManager::new();
    tm.set_tokens(
        Sensitive::new("current-access-token".to_string()),
        Some(Sensitive::new("refresh-token".to_string())),
        Some(9_999_999_999),
        Some(Uuid::new_v4()),
    )
    .await;

    // The caller observed a DIFFERENT (older) access token failing, so a
    // concurrent refresher must already have rotated it — `refresh_if_needed`
    // returns the current token without ever invoking the refresh closure.
    tm.refresh_if_needed("some-older-observed-token", |_refresh| async {
        panic!("do_refresh must NOT be called when a newer token already exists");
    })
    .await
    .expect("double-check must return the already-rotated token without refreshing");
}

#[test]
fn token_manager_default_is_equivalent_to_new() {
    // `#[derive(Default)]`-style parity check for the hand-written `Default`
    // impl (`TokenManager::default()` just delegates to `::new()`) — every
    // other test in this suite constructs via `::new()` directly, so
    // `default()` itself is otherwise never called.
    let tm = TokenManager::default();
    assert!(tm.cached_access_token().is_none());
}

#[tokio::test]
async fn refresh_without_a_refresh_token_is_an_auth_error() {
    let tm = TokenManager::new();
    // Tokens set with NO refresh token available.
    tm.set_tokens(
        Sensitive::new("access-token".to_string()),
        None,
        Some(9_999_999_999),
        Some(Uuid::new_v4()),
    )
    .await;

    let err = tm
        .refresh_if_needed("access-token", |_refresh| async {
            unreachable!("no refresh token means the closure is never reached");
        })
        .await
        .expect_err("refresh with no refresh token must be an auth error");
    assert!(matches!(err, AxiamError::Auth { .. }));
}
