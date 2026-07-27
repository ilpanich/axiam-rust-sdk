//! `oidc_discover` (CONTRACT.md §12.1, §12.3 rule 6): fetch, per-origin
//! cache key, and single-flight de-duplication of concurrent calls.
//! Mirrors the counting-mock harness `tests/jwks_single_flight_test.rs`
//! already uses for the analogous JWKS single-flight guarantee.

#![cfg(feature = "rest")]

#[path = "oidc_support/mod.rs"]
mod oidc_support;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use axiam_sdk::client::AxiamClient;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

async fn mount_counting_discovery(mock_server: &MockServer) -> Arc<AtomicUsize> {
    let call_count = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&call_count);
    let base_url = mock_server.uri();
    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(move |_req: &wiremock::Request| {
            counter.fetch_add(1, Ordering::SeqCst);
            ResponseTemplate::new(200).set_body_json(oidc_support::discovery_document(&base_url))
        })
        .mount(mock_server)
        .await;
    call_count
}

#[tokio::test]
async fn fetches_and_returns_the_discovery_document() {
    let mock_server = MockServer::start().await;
    mount_counting_discovery(&mock_server).await;
    let client = oidc_support::build_client(&mock_server.uri(), true);

    let configuration = client.oidc_discover().await.expect("discovery succeeds");

    assert_eq!(configuration.issuer, oidc_support::ISSUER);
    assert_eq!(
        configuration.jwks_uri,
        format!("{}/oauth2/jwks", mock_server.uri())
    );
    assert_eq!(
        configuration.token_endpoint_auth_methods_supported,
        vec!["client_secret_post".to_string()]
    );
}

#[tokio::test]
async fn concurrent_cold_cache_calls_collapse_to_one_fetch() {
    let mock_server = MockServer::start().await;
    let call_count = mount_counting_discovery(&mock_server).await;
    let client = Arc::new(oidc_support::build_client(&mock_server.uri(), true));

    let mut handles = Vec::new();
    for _ in 0..8 {
        let client = Arc::clone(&client);
        handles.push(tokio::spawn(async move { client.oidc_discover().await }));
    }
    for handle in handles {
        handle
            .await
            .expect("task should not panic")
            .expect("discovery should succeed for every concurrent caller");
    }

    assert_eq!(
        call_count.load(Ordering::SeqCst),
        1,
        "exactly one discovery fetch must occur across 8 concurrent cold-cache callers (§12.3 rule 6)"
    );
}

#[tokio::test]
async fn a_warm_cache_serves_a_second_call_with_no_additional_fetch() {
    let mock_server = MockServer::start().await;
    let call_count = mount_counting_discovery(&mock_server).await;
    let client = oidc_support::build_client(&mock_server.uri(), true);

    client.oidc_discover().await.expect("first discover");
    assert_eq!(call_count.load(Ordering::SeqCst), 1);

    client
        .oidc_discover()
        .await
        .expect("second discover, served from cache");
    assert_eq!(
        call_count.load(Ordering::SeqCst),
        1,
        "a fresh cache entry must not trigger a second fetch (TTL floor is 5 minutes, §12.3 rule 6)"
    );
}

#[tokio::test]
async fn cache_is_per_client_instance_not_process_global() {
    // Two independently-constructed clients against the SAME origin must
    // not share a cache — each does its own fetch (§12.3 rule 6: "MUST NOT
    // be process-global unless the key includes the origin").
    let mock_server = MockServer::start().await;
    let call_count = mount_counting_discovery(&mock_server).await;

    let client_a = oidc_support::build_client(&mock_server.uri(), true);
    let client_b = oidc_support::build_client(&mock_server.uri(), true);

    client_a.oidc_discover().await.expect("client A discover");
    client_b.oidc_discover().await.expect("client B discover");

    assert_eq!(
        call_count.load(Ordering::SeqCst),
        2,
        "two independent client instances must not share one discovery cache"
    );
}

#[tokio::test]
async fn a_short_configured_ttl_is_floored_to_five_minutes() {
    // §12.3 rule 6: TTL MUST be at least 5 minutes even if a smaller value
    // is configured. Request an absurdly short TTL, then verify a second
    // call shortly afterward still hits the (still-fresh) cache.
    let mock_server = MockServer::start().await;
    let call_count = mount_counting_discovery(&mock_server).await;
    let client = AxiamClient::builder()
        .base_url(mock_server.uri())
        .expect("valid base url")
        .tenant_id(oidc_support::tenant_id())
        .oidc_client_id(oidc_support::CLIENT_ID)
        .oidc_discovery_ttl(std::time::Duration::from_millis(1))
        .build()
        .expect("client builds");

    client.oidc_discover().await.expect("first discover");
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    client.oidc_discover().await.expect("second discover");

    assert_eq!(
        call_count.load(Ordering::SeqCst),
        1,
        "a 1ms configured TTL must be floored to the 5-minute minimum, not honored literally"
    );
}
