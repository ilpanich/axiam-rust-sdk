//! `check_access`/`batch_check` retry policy (`src/rest/authz.rs`, D-12):
//! transient `NetworkError` is retried up to the bounded max, decisive
//! `Auth`/`Authz` failures are never retried. `tests/login_mfa_flow_test.rs`
//! only exercises the happy path; this file covers the retry branches.

#![cfg(feature = "rest")]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use axiam_sdk::AxiamError;
use axiam_sdk::client::AxiamClient;
use axiam_sdk::rest::authz::AccessCheckRequest;
use serde_json::json;
use uuid::Uuid;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn build_client(base_url: &str) -> AxiamClient {
    AxiamClient::builder()
        .base_url(base_url)
        .expect("valid base_url")
        .tenant_slug("acme")
        .build()
        .expect("client builds")
}

#[tokio::test]
async fn check_access_retries_a_transient_network_failure_then_succeeds() {
    let mock_server = MockServer::start().await;
    let call_count = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&call_count);

    Mock::given(method("POST"))
        .and(path("/api/v1/authz/check"))
        .respond_with(move |_req: &wiremock::Request| {
            let n = counter.fetch_add(1, Ordering::SeqCst);
            if n == 0 {
                ResponseTemplate::new(503).set_body_string("temporarily unavailable")
            } else {
                ResponseTemplate::new(200).set_body_json(json!({ "allowed": true }))
            }
        })
        .mount(&mock_server)
        .await;

    let client = build_client(&mock_server.uri());
    let decision = client
        .check_access("users:get", Uuid::new_v4(), None)
        .await
        .expect("a transient 503 followed by a 200 must ultimately succeed via retry");

    assert!(decision.allowed);
    assert_eq!(
        call_count.load(Ordering::SeqCst),
        2,
        "exactly one retry must have occurred after the first transient failure"
    );
}

#[tokio::test]
async fn check_access_exhausts_retries_on_persistent_network_failure() {
    let mock_server = MockServer::start().await;
    let call_count = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&call_count);

    Mock::given(method("POST"))
        .and(path("/api/v1/authz/check"))
        .respond_with(move |_req: &wiremock::Request| {
            counter.fetch_add(1, Ordering::SeqCst);
            ResponseTemplate::new(503).set_body_string("still unavailable")
        })
        .mount(&mock_server)
        .await;

    let client = build_client(&mock_server.uri());
    let err = client
        .check_access("users:get", Uuid::new_v4(), None)
        .await
        .expect_err("a persistently failing endpoint must exhaust retries and return an error");

    assert!(matches!(err, AxiamError::Network { .. }));
    assert_eq!(
        call_count.load(Ordering::SeqCst),
        3,
        "D-12 bounds retries to 1 initial attempt + 2 retries = 3 total"
    );
}

#[tokio::test]
async fn check_access_does_not_retry_a_decisive_auth_failure() {
    let mock_server = MockServer::start().await;
    let call_count = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&call_count);

    Mock::given(method("POST"))
        .and(path("/api/v1/authz/check"))
        .respond_with(move |_req: &wiremock::Request| {
            counter.fetch_add(1, Ordering::SeqCst);
            ResponseTemplate::new(401).set_body_string("unauthenticated")
        })
        .mount(&mock_server)
        .await;

    let client = build_client(&mock_server.uri());
    let err = client
        .check_access("users:get", Uuid::new_v4(), None)
        .await
        .expect_err("a 401 must surface as an error");

    assert!(matches!(err, AxiamError::Auth { .. }));
    assert_eq!(
        call_count.load(Ordering::SeqCst),
        1,
        "an Auth failure is decisive, not transient — it must never be retried (D-12)"
    );
}

#[tokio::test]
async fn batch_check_retries_a_transient_network_failure_then_succeeds() {
    let mock_server = MockServer::start().await;
    let call_count = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&call_count);

    Mock::given(method("POST"))
        .and(path("/api/v1/authz/check/batch"))
        .respond_with(move |_req: &wiremock::Request| {
            let n = counter.fetch_add(1, Ordering::SeqCst);
            if n == 0 {
                ResponseTemplate::new(500).set_body_string("internal error")
            } else {
                ResponseTemplate::new(200).set_body_json(json!({
                    "results": [{ "allowed": true }]
                }))
            }
        })
        .mount(&mock_server)
        .await;

    let client = build_client(&mock_server.uri());
    let results = client
        .batch_check(vec![AccessCheckRequest::new("users:get", Uuid::new_v4())])
        .await
        .expect("a transient 500 followed by a 200 must ultimately succeed via retry");

    assert_eq!(results.len(), 1);
    assert!(results[0].allowed);
    assert_eq!(call_count.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn can_returns_the_allowed_bool_directly() {
    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/authz/check"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "allowed": false,
            "reason": "no permission",
        })))
        .mount(&mock_server)
        .await;

    let client = build_client(&mock_server.uri());
    let allowed = client
        .can("users:delete", Uuid::new_v4(), Some("sub-resource"))
        .await
        .expect("can() should succeed");
    assert!(!allowed);
}

// ── T-262 / CONTRACT §16.3 — a contended write answers 503 + Retry-After ────
//
// The server changed on 2026-09-12: a write that loses an optimistic-
// concurrency race in the datastore, and stays lost after every retry the
// server spends on it, now answers `503 write_contention` with
// `Retry-After: 1` instead of `500 internal_error`.
//
// No SDK behaviour changes. §16.3 already retries `5xx` on an eligible
// operation and §16.1 already honours `Retry-After` as a floor. These two
// tests exist because a policy nobody asserts through the public surface is
// exactly the failure §16.7 was written about — two SDKs had a tested retry
// helper that no production path called, and both suites were green.

/// The eligible half. `check_access` is side-effect-free, so the new answer is
/// retried and the caller sees a success rather than an error.
#[tokio::test]
async fn check_access_retries_a_503_carrying_retry_after() {
    let mock_server = MockServer::start().await;
    let call_count = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&call_count);

    Mock::given(method("POST"))
        .and(path("/api/v1/authz/check"))
        .respond_with(move |_req: &wiremock::Request| {
            if counter.fetch_add(1, Ordering::SeqCst) == 0 {
                // Byte-for-byte what the server now sends for a contended
                // write: the status, the slug and the header.
                ResponseTemplate::new(503)
                    .insert_header("Retry-After", "1")
                    .set_body_json(json!({
                        "error": "write_contention",
                        "message": "the datastore is busy; retry this request",
                    }))
            } else {
                ResponseTemplate::new(200).set_body_json(json!({
                    "allowed": true,
                    "reason": "granted",
                }))
            }
        })
        .mount(&mock_server)
        .await;

    let decision = build_client(&mock_server.uri())
        .check_access("users:get", Uuid::new_v4(), None)
        .await
        .expect("a 503 with Retry-After is transient and is retried");

    assert!(decision.allowed);
    assert_eq!(
        call_count.load(Ordering::SeqCst),
        2,
        "one failure, one retry — asserted on the wire, not against the helper"
    );
}

/// The non-idempotent half, and the one that catches a retry wired at the
/// transport layer instead of the operation layer (§16.7). `login` changes
/// state and consumes a credential, so the same `503` must produce **exactly
/// one** request — a silent retry would replay a spent credential and turn a
/// recoverable blip into a hard failure the caller cannot interpret.
#[tokio::test]
async fn login_makes_exactly_one_attempt_against_the_same_503() {
    let mock_server = MockServer::start().await;
    let call_count = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&call_count);

    Mock::given(method("POST"))
        .and(path("/api/v1/auth/login"))
        .respond_with(move |_req: &wiremock::Request| {
            counter.fetch_add(1, Ordering::SeqCst);
            ResponseTemplate::new(503)
                .insert_header("Retry-After", "1")
                .set_body_json(json!({
                    "error": "write_contention",
                    "message": "the datastore is busy; retry this request",
                }))
        })
        .mount(&mock_server)
        .await;

    let _ = build_client(&mock_server.uri())
        .login("someone@example.test", "password")
        .await
        .expect_err("a mutation is never retried, so the 503 reaches the caller");

    assert_eq!(
        call_count.load(Ordering::SeqCst),
        1,
        "counted on the wire: a retry wired at the transport layer would show up \
         here as 3 and nowhere else"
    );
}
