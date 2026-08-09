//! Deterministic shutdown — CONTRACT.md §18.
//!
//! The §18.3 required tests. The load-bearing one is
//! `close_issues_no_network_request`: it asserts against the *wire*, not the
//! return value, because the failure it guards against — a `logout` quietly
//! wired into `close()` — succeeds silently and would end every user's session
//! on each deploy.

use axiam_sdk::client::AxiamClient;
use wiremock::matchers::any;
use wiremock::{Mock, MockServer, ResponseTemplate};

async fn client_for(server: &MockServer) -> AxiamClient {
    AxiamClient::builder()
        .base_url(server.uri())
        .expect("loopback base url")
        .tenant_slug("acme")
        .org_slug("acme")
        .build()
        .expect("builder")
}

#[tokio::test]
async fn close_is_idempotent() {
    // Cleanup runs from error paths, and an error path that itself fails hides
    // the original failure. Closing twice must be a no-op, not a panic.
    let server = MockServer::start().await;
    let client = client_for(&server).await;

    client.close().await;
    client.close().await;
    client.close().await;
}

#[tokio::test]
async fn close_issues_no_network_request() {
    // §18.1 rule 5. The mock has NO handler mounted, so any outbound request
    // fails the assertion below rather than being quietly absorbed.
    let server = MockServer::start().await;
    let client = client_for(&server).await;

    client.close().await;

    assert!(
        server.received_requests().await.unwrap().is_empty(),
        "close() must not reach the network — the session outlives the client \
         object, which is what lets a process restart and resume"
    );
}

#[tokio::test]
async fn a_call_after_close_errors_rather_than_reconnecting() {
    // §18.1 rule 4. A caller holding a handle past shutdown has a bug; silently
    // reopening the transport would hide it.
    let server = MockServer::start().await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "allowed": true
        })))
        .mount(&server)
        .await;
    let client = client_for(&server).await;

    // Sanity: the call works before close, so the assertion after it is about
    // the close and not about a broken fixture.
    let before = client.can("read", uuid::Uuid::nil(), None).await;
    assert!(before.is_ok(), "pre-close call should succeed: {before:?}");
    let calls_before = server.received_requests().await.unwrap().len();

    client.close().await;

    let after = client.can("read", uuid::Uuid::nil(), None).await;
    let err = after.expect_err("a call after close must fail");
    assert!(
        err.to_string().contains("closed"),
        "the error must name the cause, got: {err}"
    );

    // And it must fail *without* touching the wire.
    assert_eq!(
        server.received_requests().await.unwrap().len(),
        calls_before,
        "a post-close call must not reach the network"
    );
}

#[tokio::test]
async fn every_entry_point_refuses_after_close() {
    let server = MockServer::start().await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
        .mount(&server)
        .await;
    let client = client_for(&server).await;
    client.close().await;

    // One assertion per public operation: a guard added to `check_access` but
    // forgotten on `login` would otherwise pass a narrower test.
    assert!(client.login("u@example.com", "pw").await.is_err());
    assert!(client.verify_mfa("123456").await.is_err());
    assert!(client.refresh().await.is_err());
    assert!(client.logout().await.is_err());
    assert!(client.can("read", uuid::Uuid::nil(), None).await.is_err());
    assert!(client.batch_check(vec![]).await.is_err());

    assert!(
        server.received_requests().await.unwrap().is_empty(),
        "no operation may reach the wire after close"
    );
}
