//! Additional `src/rest/authz.rs` coverage the retry suite leaves open: the
//! `AccessCheckRequest` builder (`with_scope`/`with_subject`), a malformed
//! 200 authz body (the response-parse error branch), and a hard transport
//! failure (the request-send error branch).

#![cfg(feature = "rest")]

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
async fn batch_check_forwards_scope_and_subject_from_the_request_builder() {
    let mock_server = MockServer::start().await;
    // Assert the server actually receives the scope/subject the builder set.
    let subject = Uuid::new_v4();
    Mock::given(method("POST"))
        .and(path("/api/v1/authz/check/batch"))
        .and(wiremock::matchers::body_string_contains("child-scope"))
        .and(wiremock::matchers::body_string_contains(
            subject.to_string(),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "results": [{ "allowed": true, "reason": null }]
        })))
        .mount(&mock_server)
        .await;

    let client = build_client(&mock_server.uri());
    let request = AccessCheckRequest::new("users:get", Uuid::new_v4())
        .with_scope("child-scope")
        .with_subject(subject);

    let results = client
        .batch_check(vec![request])
        .await
        .expect("batch_check with a builder-configured request must succeed");
    assert_eq!(results.len(), 1);
    assert!(results[0].allowed);
}

#[tokio::test]
async fn check_access_maps_a_malformed_success_body_to_a_network_error() {
    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/authz/check"))
        .respond_with(ResponseTemplate::new(200).set_body_string("not json at all {{{"))
        .mount(&mock_server)
        .await;

    let client = build_client(&mock_server.uri());
    let err = client
        .check_access("users:get", Uuid::new_v4(), None)
        .await
        .expect_err("a malformed 200 authz body must surface as an error");
    assert!(matches!(err, AxiamError::Network { .. }));
}

#[tokio::test]
async fn check_access_maps_a_transport_failure_to_a_network_error() {
    // Bind then drop an ephemeral loopback port so the connection is refused
    // deterministically — exercises the request-send error branch (not a
    // non-2xx HTTP status).
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let addr = listener.local_addr().expect("resolve local_addr");
    drop(listener);

    let client = build_client(&format!("http://{addr}"));
    let err = client
        .check_access("users:get", Uuid::new_v4(), None)
        .await
        .expect_err("a refused connection must surface as a network error");
    assert!(matches!(err, AxiamError::Network { .. }));
}
