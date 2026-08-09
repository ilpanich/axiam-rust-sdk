//! Client-side decision memo — CONTRACT.md §17.3 required tests.
//!
//! These assert against the **wire-call count**, not just the returned value.
//! A memo that returned the right answer while still making the request would
//! pass a value-only test and deliver none of the point; and off-by-default —
//! the single most important property here — is only observable as "every
//! repeat check still reaches the server".

use std::time::Duration;

use axiam_sdk::client::AxiamClient;
use uuid::Uuid;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const RESOURCE: Uuid = Uuid::from_u128(0x4444_4444_4444_4444_4444_4444_4444_4444);

async fn mount_decision(server: &MockServer, allowed: bool, reason_code: &str) {
    Mock::given(method("POST"))
        .and(path("/api/v1/authz/check"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "allowed": allowed,
            "reason_code": reason_code,
        })))
        .mount(server)
        .await;
}

fn client(server: &MockServer, ttl: Option<Duration>) -> AxiamClient {
    let mut b = AxiamClient::builder()
        .base_url(server.uri())
        .expect("loopback base url")
        .tenant_slug("acme")
        .org_slug("acme");
    if let Some(ttl) = ttl {
        b = b.decision_memo_ttl(ttl);
    }
    b.build().expect("builder")
}

async fn wire_calls(server: &MockServer) -> usize {
    server.received_requests().await.unwrap().len()
}

#[tokio::test]
async fn off_by_default_every_repeat_check_reaches_the_wire() {
    // The most important assertion in this file. §11.2 rule 6's ban on decision
    // caching is still the default; §17 is an opt-in exception, and a build
    // that quietly enabled it would change authorization staleness for every
    // existing caller without them asking.
    let server = MockServer::start().await;
    mount_decision(&server, true, "allowed").await;
    let c = client(&server, None);

    for _ in 0..3 {
        assert!(c.can("read", RESOURCE, None).await.unwrap());
    }

    assert_eq!(wire_calls(&server).await, 3, "default must not memoize");
}

#[tokio::test]
async fn a_repeat_inside_the_ttl_makes_no_second_call() {
    let server = MockServer::start().await;
    mount_decision(&server, true, "allowed").await;
    let c = client(&server, Some(Duration::from_secs(5)));

    let first = c.check_access("read", RESOURCE, None).await.unwrap();
    let second = c.check_access("read", RESOURCE, None).await.unwrap();

    assert_eq!(wire_calls(&server).await, 1);
    assert_eq!(first.allowed, second.allowed);
    // §17.1 rule 5: the reason code survives the round trip through the memo.
    // A memo returning `allowed` but dropping the code would make the field
    // intermittently absent, which is worse than never having had it.
    assert_eq!(second.reason_code.as_deref(), Some("allowed"));
}

#[tokio::test]
async fn a_deny_is_memoized_exactly_as_an_allow_is() {
    // §17.1 rule 4. Asymmetric caching would make the two outcomes take
    // measurably different times, leaking which one occurred to anyone who can
    // observe latency — so this asserts the call *count*, not the outcome.
    let server = MockServer::start().await;
    mount_decision(&server, false, "denied_by_rule").await;
    let c = client(&server, Some(Duration::from_secs(5)));

    let first = c.check_access("read", RESOURCE, None).await.unwrap();
    let second = c.check_access("read", RESOURCE, None).await.unwrap();

    assert_eq!(wire_calls(&server).await, 1, "denies must memoize too");
    assert!(!first.allowed);
    assert!(!second.allowed);
    assert_eq!(second.reason_code.as_deref(), Some("denied_by_rule"));
}

#[tokio::test]
async fn a_ttl_above_the_ceiling_is_clamped_rather_than_rejected() {
    // §17.1 rule 2 — construction succeeds, and the memo works, at the clamped
    // value. The clamp itself is unit-tested; this proves the builder accepts
    // an over-large TTL instead of failing.
    let server = MockServer::start().await;
    mount_decision(&server, true, "allowed").await;
    let c = client(&server, Some(Duration::from_secs(3600)));

    c.check_access("read", RESOURCE, None).await.unwrap();
    c.check_access("read", RESOURCE, None).await.unwrap();

    assert_eq!(wire_calls(&server).await, 1);
}

#[tokio::test]
async fn each_key_component_misses_rather_than_colliding() {
    // §17.1 rule 3. A memo that ignored any component would answer a different
    // question than the one asked — the `scope` case is the dangerous one: a
    // broader answer to a narrower question.
    let server = MockServer::start().await;
    mount_decision(&server, true, "allowed").await;
    let c = client(&server, Some(Duration::from_secs(5)));

    c.check_access("read", RESOURCE, None).await.unwrap();
    c.check_access("write", RESOURCE, None).await.unwrap(); // action differs
    c.check_access("read", RESOURCE, Some("col-a"))
        .await
        .unwrap(); // scope present
    c.check_access("read", Uuid::from_u128(9), None)
        .await
        .unwrap(); // resource differs
    c.check_access_as(Uuid::from_u128(7), "read", RESOURCE, None)
        .await
        .unwrap(); // subject differs

    assert_eq!(
        wire_calls(&server).await,
        5,
        "each differing component must miss"
    );

    // …and each of those is now independently memoized.
    c.check_access("read", RESOURCE, Some("col-a"))
        .await
        .unwrap();
    assert_eq!(wire_calls(&server).await, 5);
}

#[tokio::test]
async fn a_failure_is_never_memoized() {
    // §17.1 rule 7. Memoizing a transport failure as a deny would turn a blip
    // into a TTL-long outage; as an allow it is unthinkable. Either way the
    // next call must reach the wire.
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/authz/check"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&server)
        .await;
    // Retry off, so the call count is exactly one per check and this test is
    // about memoization rather than about §16.
    let c = AxiamClient::builder()
        .base_url(server.uri())
        .unwrap()
        .tenant_slug("acme")
        .org_slug("acme")
        .decision_memo_ttl(Duration::from_secs(5))
        .retry_enabled(false)
        .build()
        .unwrap();

    assert!(c.check_access("read", RESOURCE, None).await.is_err());
    assert!(c.check_access("read", RESOURCE, None).await.is_err());

    assert_eq!(
        wire_calls(&server).await,
        2,
        "a failure must not be memoized"
    );
}

#[tokio::test]
async fn logout_clears_the_memo() {
    // §17.1 rule 9. Entries are keyed by subject, not by session, so a
    // re-authentication as a different principal would otherwise inherit the
    // previous principal's decisions.
    let server = MockServer::start().await;
    mount_decision(&server, true, "allowed").await;
    Mock::given(method("POST"))
        .and(path("/api/v1/auth/logout"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
        .mount(&server)
        .await;
    let c = client(&server, Some(Duration::from_secs(5)));

    c.check_access("read", RESOURCE, None).await.unwrap();
    c.check_access("read", RESOURCE, None).await.unwrap();
    assert_eq!(wire_calls(&server).await, 1);

    let _ = c.logout().await;
    // This client never logged in, so `logout` short-circuits without touching
    // the wire — the count below is 1 check + 0 logout + 1 fresh check. What
    // matters is that the third check reaches the server at all: with the memo
    // still populated it would have been served from cache and the count would
    // have stayed at 1.
    let after_logout = wire_calls(&server).await;

    c.check_access("read", RESOURCE, None).await.unwrap();
    assert_eq!(
        wire_calls(&server).await,
        after_logout + 1,
        "logout must drop memoized decisions"
    );
}
