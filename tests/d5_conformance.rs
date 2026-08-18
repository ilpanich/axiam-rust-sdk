//! D5 conformance — CONTRACT.md §16, §17, §18, §19.
//!
//! # Why this file exists
//!
//! Ten of the eleven AXIAM SDKs ship a single named D5 suite —
//! `D5ConformanceTest.java/.kt/.php`, `D5ConformanceTests.cs/.swift`,
//! `test_d5_conformance.c/.cpp/.py`, `d5_conformance_test.go`,
//! `d5Conformance.test.ts`. This SDK had only `d5_config_clamped.rs`, with the
//! rest of §16–§18 spread across files named after their mechanism rather than
//! after the contract section they satisfy. Nothing was missing from §16–§18 —
//! but nobody could tell that without reading eleven test files, and **§19 was
//! genuinely uncovered**: `src/telemetry.rs` had no test at all.
//!
//! So this file does two things. It carries the §19 assertions, and it names
//! where the rest of D5 already lives:
//!
//! | Section | Covered by |
//! |---|---|
//! | §16 retry / backoff / jitter | `tests/rest_authz_retry_test.rs`, `src/retry.rs` unit tests |
//! | §17 decision memo | `tests/decision_memo_test.rs`, `src/memo.rs` unit tests |
//! | §17.1 rule 2 clamping | `tests/d5_config_clamped.rs` |
//! | §18 deterministic shutdown | `tests/close_lifecycle_test.rs` |
//! | §19 telemetry | **this file** |
//!
//! # Why §19 being untested mattered
//!
//! `src/telemetry.rs` implements both of §19.2's load-bearing rules correctly:
//! `Telemetry::emit` wraps the sink in `std::panic::catch_unwind`, and
//! `TelemetryEvent` is a closed enum with no arbitrary-data escape hatch.
//! Neither was asserted anywhere.
//!
//! The Go suite's own header explains why that gap is not academic:
//!
//! > the TypeScript SDK shipped a retry helper that was exported, unit-tested
//! > and green while no production path called it, so that SDK performed no
//! > read-only retries at all and every test passed.
//!
//! Correct code that nothing exercises is one refactor away from being
//! incorrect code that nothing exercises. "No telemetry event carries a token"
//! is a security invariant, and an unasserted invariant is a comment.
//!
//! Every assertion below goes through the **public** client surface and counts
//! what reaches the wire or the sink, never a helper in isolation — the same
//! rule the Go suite states, and for the same reason.

#![cfg(feature = "rest")]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axiam_sdk::client::AxiamClient;
use axiam_sdk::telemetry::{Outcome, TelemetryEvent, TelemetrySink};
use serde_json::json;
use uuid::Uuid;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const RESOURCE: Uuid = Uuid::from_u128(0xD5D5_D5D5_D5D5_D5D5_D5D5_D5D5_D5D5_D5D5);

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

/// Records every event a client emits, in order.
#[derive(Clone, Default)]
struct Collector(Arc<Mutex<Vec<TelemetryEvent>>>);

impl TelemetrySink for Collector {
    fn emit(&self, event: &TelemetryEvent) {
        self.0
            .lock()
            .expect("collector poisoned")
            .push(event.clone());
    }
}

impl Collector {
    fn events(&self) -> Vec<TelemetryEvent> {
        self.0.lock().expect("collector poisoned").clone()
    }

    /// Every event rendered with `Debug`, which is the widest view of what a
    /// sink can observe: a caller that logs `{:?}` sees exactly this.
    fn rendered(&self) -> String {
        self.events()
            .iter()
            .map(|e| format!("{e:?}"))
            .collect::<Vec<_>>()
            .join("\n")
    }
}

/// A sink that panics on the first event it sees.
struct PanickingSink;

impl TelemetrySink for PanickingSink {
    fn emit(&self, _event: &TelemetryEvent) {
        panic!("a telemetry hook is allowed to be this badly behaved");
    }
}

fn client_with_sink(server: &MockServer, sink: impl TelemetrySink) -> AxiamClient {
    AxiamClient::builder()
        .base_url(server.uri())
        .expect("loopback base url")
        .tenant_slug("acme")
        .org_slug("acme")
        .telemetry_hook(sink)
        .build()
        .expect("client builds")
}

/// `POST /api/v1/authz/check` answering 200 with the given decision.
async fn mount_allow(server: &MockServer) {
    Mock::given(method("POST"))
        .and(path("/api/v1/authz/check"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "allowed": true,
            "reason_code": "allowed",
        })))
        .mount(server)
        .await;
}

/// `POST /api/v1/authz/check` answering 503 `n` times, then 200.
async fn mount_transient_then_allow(server: &MockServer, failures: usize) -> Arc<AtomicUsize> {
    let calls = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&calls);
    Mock::given(method("POST"))
        .and(path("/api/v1/authz/check"))
        .respond_with(move |_req: &wiremock::Request| {
            let n = counter.fetch_add(1, Ordering::SeqCst);
            if n < failures {
                ResponseTemplate::new(503).set_body_string("temporarily unavailable")
            } else {
                ResponseTemplate::new(200)
                    .set_body_json(json!({ "allowed": true, "reason_code": "allowed" }))
            }
        })
        .mount(server)
        .await;
    calls
}

// ---------------------------------------------------------------------------
// §19.1 — the request pair, once per attempt
// ---------------------------------------------------------------------------

#[tokio::test]
async fn telemetry_emits_a_request_pair_per_attempt_with_a_retry_between() {
    // §16.5's whole argument for the Retry event is that a retried-then-
    // succeeded operation is otherwise invisible: the caller sees a slow
    // success and no signal that the server is failing. Asserting the *shape*
    // of the sequence is what makes that claim true rather than intended.
    let server = MockServer::start().await;
    let calls = mount_transient_then_allow(&server, 1).await;
    let collector = Collector::default();
    let client = client_with_sink(&server, collector.clone());

    let decision = client
        .check_access("users:get", RESOURCE, None)
        .await
        .expect("a transient 503 followed by a 200 must succeed via retry");
    assert!(decision.allowed);
    assert_eq!(calls.load(Ordering::SeqCst), 2, "one retry expected");

    let events = collector.events();
    let starts: Vec<u32> = events
        .iter()
        .filter_map(|e| match e {
            TelemetryEvent::RequestStart { attempt, .. } => Some(*attempt),
            _ => None,
        })
        .collect();
    let ends: Vec<(u32, Option<u16>, Outcome)> = events
        .iter()
        .filter_map(|e| match e {
            TelemetryEvent::RequestEnd {
                attempt,
                status,
                outcome,
                ..
            } => Some((*attempt, *status, *outcome)),
            _ => None,
        })
        .collect();
    let retries = events
        .iter()
        .filter(|e| matches!(e, TelemetryEvent::Retry { .. }))
        .count();

    assert_eq!(
        starts,
        vec![1, 2],
        "one RequestStart per attempt, numbered from 1"
    );
    assert_eq!(
        ends.len(),
        2,
        "every RequestStart must be closed by a RequestEnd"
    );
    assert_eq!(
        ends[0].1,
        Some(503),
        "the first attempt closes with the 503 it got"
    );
    assert_eq!(ends[0].2, Outcome::Failure);
    assert_eq!(
        ends[1].1,
        Some(200),
        "the second attempt closes with the 200"
    );
    assert_eq!(ends[1].2, Outcome::Success);
    assert_eq!(
        retries, 1,
        "exactly one Retry event, between the two attempts"
    );

    // Ordering, not just counts: start(1), end(1), retry, start(2), end(2).
    let kinds: Vec<&str> = events
        .iter()
        .map(|e| match e {
            TelemetryEvent::RequestStart { .. } => "start",
            TelemetryEvent::RequestEnd { .. } => "end",
            TelemetryEvent::Retry { .. } => "retry",
            TelemetryEvent::Refresh { .. } => "refresh",
            TelemetryEvent::ConfigClamped { .. } => "clamped",
            _ => "unknown",
        })
        .collect();
    assert_eq!(kinds, vec!["start", "end", "retry", "start", "end"]);
}

#[tokio::test]
async fn a_single_successful_call_emits_exactly_one_pair() {
    let server = MockServer::start().await;
    mount_allow(&server).await;
    let collector = Collector::default();
    let client = client_with_sink(&server, collector.clone());

    client
        .check_access("users:get", RESOURCE, None)
        .await
        .expect("the mock allows");

    let events = collector.events();
    assert_eq!(
        events.len(),
        2,
        "one start, one end, nothing else: {events:?}"
    );
    assert!(matches!(
        events[0],
        TelemetryEvent::RequestStart { attempt: 1, .. }
    ));
    assert!(matches!(
        events[1],
        TelemetryEvent::RequestEnd {
            attempt: 1,
            status: Some(200),
            outcome: Outcome::Success,
            ..
        }
    ));
}

// ---------------------------------------------------------------------------
// §19.2 rule 2 — a hook may not fail the operation
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_panicking_telemetry_hook_cannot_fail_the_operation() {
    // The rule that makes telemetry safe to enable in production. A caller
    // wires up a metrics backend, the backend's client panics on a full
    // buffer, and authorization must not go down with it.
    let server = MockServer::start().await;
    mount_allow(&server).await;
    let client = client_with_sink(&server, PanickingSink);

    let decision = client
        .check_access("users:get", RESOURCE, None)
        .await
        .expect("a panicking hook must not fail the check");

    assert!(decision.allowed);
}

#[tokio::test]
async fn a_panicking_hook_does_not_poison_later_calls() {
    // catch_unwind swallows the first panic; the interesting question is
    // whether the client is still usable afterwards. A sink held behind a
    // poisoned lock would fail here and not above.
    let server = MockServer::start().await;
    mount_allow(&server).await;
    let client = client_with_sink(&server, PanickingSink);

    for i in 0..3 {
        let decision = client
            .check_access("users:get", RESOURCE, None)
            .await
            .unwrap_or_else(|e| panic!("call {i} failed after an earlier hook panic: {e}"));
        assert!(decision.allowed);
    }
}

// ---------------------------------------------------------------------------
// §19.2 rule 3 — no event carries a secret
// ---------------------------------------------------------------------------

#[tokio::test]
async fn no_telemetry_event_carries_a_token_or_a_password() {
    // The security invariant. `TelemetryEvent` is a closed enum with no
    // arbitrary-data variant, which is what *makes* this true — this test is
    // what keeps it true when somebody adds a variant.
    //
    // The events are inspected through `Debug`, because that is the widest
    // view a sink has: a caller who logs `{:?}` sees exactly this string.
    const PASSWORD: &str = "correct-horse-battery-staple-9f3a";
    const BEARER: &str = "eyJhbGciOiJFZERTQSIsImtpZCI6InQifQ.e30.c2lnbmF0dXJlLXBsYWNlaG9sZGVy";

    let server = MockServer::start().await;

    // The login response hands the client a session; the authz call then
    // carries it. Both legs are observed by the sink.
    Mock::given(method("POST"))
        .and(path("/api/v1/auth/login"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({
                    "user": { "id": Uuid::new_v4(), "username": "alice", "email": "a@example.com" },
                    "session_id": Uuid::new_v4(),
                    "expires_in": 900,
                }))
                .append_header(
                    "Set-Cookie",
                    format!("axiam_access={BEARER}; Path=/; HttpOnly").as_str(),
                )
                .append_header("Set-Cookie", "axiam_csrf=test-csrf-token; Path=/"),
        )
        .mount(&server)
        .await;
    mount_transient_then_allow(&server, 1).await;

    let collector = Collector::default();
    let client = client_with_sink(&server, collector.clone());

    let _ = client.login("alice@example.com", PASSWORD).await;
    let _ = client.check_access("users:get", RESOURCE, None).await;

    let rendered = collector.rendered();
    assert!(
        !rendered.is_empty(),
        "the test proves nothing if no events were emitted"
    );
    for secret in [PASSWORD, BEARER, "test-csrf-token"] {
        assert!(
            !rendered.contains(secret),
            "a telemetry event carried a secret.\nsecret: {secret}\nevents:\n{rendered}"
        );
    }

    // A path template, never a URL with ids substituted in: a metric label
    // carrying a UUID is a cardinality bomb, and it is also how a resource id
    // leaks into a metrics backend.
    assert!(
        !rendered.contains(&RESOURCE.to_string()),
        "a telemetry event carried a resource id:\n{rendered}"
    );
}

#[tokio::test]
async fn the_retry_reason_is_redacted_prose_not_a_response_body() {
    // `Retry.reason` is the one free-text field in the event set, which makes
    // it the one place a secret could reach a sink. It is documented as
    // carrying `AxiamError`'s already-redacted `Display`; this asserts that the
    // server's raw body is not what lands there.
    const BODY_SECRET: &str = "internal-detail-Bearer-abcdefghij0123456789";

    let server = MockServer::start().await;
    let calls = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&calls);
    Mock::given(method("POST"))
        .and(path("/api/v1/authz/check"))
        .respond_with(move |_req: &wiremock::Request| {
            let n = counter.fetch_add(1, Ordering::SeqCst);
            if n == 0 {
                ResponseTemplate::new(503).set_body_string(BODY_SECRET)
            } else {
                ResponseTemplate::new(200)
                    .set_body_json(json!({ "allowed": true, "reason_code": "allowed" }))
            }
        })
        .mount(&server)
        .await;

    let collector = Collector::default();
    let client = client_with_sink(&server, collector.clone());
    let _ = client.check_access("users:get", RESOURCE, None).await;

    let reasons: Vec<String> = collector
        .events()
        .iter()
        .filter_map(|e| match e {
            TelemetryEvent::Retry { reason, .. } => Some(reason.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(reasons.len(), 1, "one retry, one reason: {reasons:?}");
    assert!(
        !reasons[0].contains("Bearer abcdefghij0123456789"),
        "the retry reason echoed an unredacted bearer token: {}",
        reasons[0]
    );
}

// ---------------------------------------------------------------------------
// §19.1 — the event set is closed
// ---------------------------------------------------------------------------

#[tokio::test]
async fn telemetry_events_are_a_closed_set() {
    // §19.1's fixed field list is what keeps secrets out by construction, so
    // "which variants can actually reach a sink" is worth pinning. A new
    // variant appearing on the ordinary request path is a contract change and
    // should fail here rather than surprise a metrics pipeline.
    let server = MockServer::start().await;
    let _ = mount_transient_then_allow(&server, 1).await;
    let collector = Collector::default();
    let client = client_with_sink(&server, collector.clone());

    let _ = client.check_access("users:get", RESOURCE, None).await;

    for event in collector.events() {
        match event {
            TelemetryEvent::RequestStart { .. }
            | TelemetryEvent::RequestEnd { .. }
            | TelemetryEvent::Retry { .. } => {}
            other => panic!(
                "an unexpected event variant reached the sink on the ordinary \
                 check_access path: {other:?}"
            ),
        }
    }
}

#[tokio::test]
async fn request_events_report_a_path_template_and_a_stable_operation_name() {
    let server = MockServer::start().await;
    mount_allow(&server).await;
    let collector = Collector::default();
    let client = client_with_sink(&server, collector.clone());

    let _ = client.check_access("users:get", RESOURCE, None).await;

    let mut seen = 0;
    for event in collector.events() {
        let (operation, method_name, template) = match event {
            TelemetryEvent::RequestStart {
                operation,
                method,
                path_template,
                ..
            }
            | TelemetryEvent::RequestEnd {
                operation,
                method,
                path_template,
                ..
            } => (operation, method, path_template),
            _ => continue,
        };
        seen += 1;
        assert_eq!(operation, "check_access");
        assert_eq!(method_name, "POST");
        assert_eq!(template, "/api/v1/authz/check");
    }
    assert_eq!(seen, 2, "a start and an end were expected");
}

// ---------------------------------------------------------------------------
// §19.2 rule 1 — no hook costs nothing
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_client_with_no_hook_installed_still_works() {
    // The default path. `Telemetry::emit` returns on `None` before touching
    // `catch_unwind`, so this is the branch almost every caller takes; it is
    // also the branch a change to the emit path is most likely to break
    // without any hook-carrying test noticing.
    let server = MockServer::start().await;
    mount_allow(&server).await;
    let client = AxiamClient::builder()
        .base_url(server.uri())
        .expect("loopback base url")
        .tenant_slug("acme")
        .org_slug("acme")
        .build()
        .expect("client builds");

    let decision = client
        .check_access("users:get", RESOURCE, None)
        .await
        .expect("no hook installed must not change the outcome");
    assert!(decision.allowed);
}

// ---------------------------------------------------------------------------
// §16 — the retry budget, asserted through the public surface
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_persistent_failure_stops_at_the_attempt_cap() {
    // Counted on the wire rather than against the helper in `src/retry.rs`,
    // which is the distinction the Go suite calls normative: an exported,
    // unit-tested retry helper that no production path calls passes every test
    // and retries nothing.
    let server = MockServer::start().await;
    let calls = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&calls);
    Mock::given(method("POST"))
        .and(path("/api/v1/authz/check"))
        .respond_with(move |_req: &wiremock::Request| {
            counter.fetch_add(1, Ordering::SeqCst);
            ResponseTemplate::new(503).set_body_string("still unavailable")
        })
        .mount(&server)
        .await;

    let collector = Collector::default();
    let client = client_with_sink(&server, collector.clone());
    let result = client.check_access("users:get", RESOURCE, None).await;
    assert!(result.is_err(), "a persistent 503 must ultimately fail");

    let attempts = calls.load(Ordering::SeqCst);
    assert!(
        (2..=4).contains(&attempts),
        "a bounded number of attempts was expected, got {attempts}"
    );
    let retries = collector
        .events()
        .iter()
        .filter(|e| matches!(e, TelemetryEvent::Retry { .. }))
        .count();
    assert_eq!(
        retries,
        attempts - 1,
        "every attempt after the first must be announced by a Retry event"
    );
}

#[tokio::test]
async fn retry_disabled_makes_exactly_one_attempt_and_emits_no_retry() {
    let server = MockServer::start().await;
    let calls = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&calls);
    Mock::given(method("POST"))
        .and(path("/api/v1/authz/check"))
        .respond_with(move |_req: &wiremock::Request| {
            counter.fetch_add(1, Ordering::SeqCst);
            ResponseTemplate::new(503).set_body_string("unavailable")
        })
        .mount(&server)
        .await;

    let collector = Collector::default();
    let client = AxiamClient::builder()
        .base_url(server.uri())
        .expect("loopback base url")
        .tenant_slug("acme")
        .org_slug("acme")
        .retry_enabled(false)
        .telemetry_hook(collector.clone())
        .build()
        .expect("client builds");

    let _ = client.check_access("users:get", RESOURCE, None).await;

    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "retry disabled means one attempt"
    );
    assert!(
        !collector
            .events()
            .iter()
            .any(|e| matches!(e, TelemetryEvent::Retry { .. })),
        "no Retry event may be emitted when retry is disabled"
    );
}

#[tokio::test]
async fn a_decisive_refusal_is_not_retried() {
    // §16.2: retry is for "the server could not answer", never for "the server
    // answered no". Retrying a 403 turns one refusal into a burst of them and
    // tells the caller nothing new.
    let server = MockServer::start().await;
    let calls = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&calls);
    Mock::given(method("POST"))
        .and(path("/api/v1/authz/check"))
        .respond_with(move |_req: &wiremock::Request| {
            counter.fetch_add(1, Ordering::SeqCst);
            ResponseTemplate::new(403).set_body_json(json!({
                "error": "authorization_denied",
                "message": "Authorization denied: no grant",
            }))
        })
        .mount(&server)
        .await;

    let collector = Collector::default();
    let client = client_with_sink(&server, collector.clone());
    let _ = client.check_access("users:get", RESOURCE, None).await;

    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "a decisive 403 must reach the wire exactly once"
    );
    assert!(
        !collector
            .events()
            .iter()
            .any(|e| matches!(e, TelemetryEvent::Retry { .. })),
        "a decisive refusal must not emit a Retry event"
    );
}

// ---------------------------------------------------------------------------
// §17 / §18 — the two properties worth restating at the D5 entry point
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_decision_memo_is_off_by_default() {
    // Restated here, not merely in `tests/decision_memo_test.rs`, because it is
    // the one §17 property whose regression changes authorization staleness for
    // every existing caller without them asking. §11.2 rule 6's ban on decision
    // caching remains the default; §17 is an opt-in exception.
    let server = MockServer::start().await;
    mount_allow(&server).await;
    let client = client_with_sink(&server, Collector::default());

    for _ in 0..3 {
        let _ = client.check_access("users:get", RESOURCE, None).await;
    }

    assert_eq!(
        server.received_requests().await.unwrap().len(),
        3,
        "every repeat check must reach the wire when no memo TTL was requested"
    );
}

#[tokio::test]
async fn a_memo_hit_emits_no_request_events() {
    // The memo's observable contract from a telemetry point of view: a served
    // repeat is not a request, so it must not look like one in a metrics
    // backend. A memo that emitted a RequestStart/End pair would report a
    // request rate that never happened.
    let server = MockServer::start().await;
    mount_allow(&server).await;
    let collector = Collector::default();
    let client = AxiamClient::builder()
        .base_url(server.uri())
        .expect("loopback base url")
        .tenant_slug("acme")
        .org_slug("acme")
        .decision_memo_ttl(Duration::from_secs(5))
        .telemetry_hook(collector.clone())
        .build()
        .expect("client builds");

    let _ = client.check_access("users:get", RESOURCE, None).await;
    let after_first = collector.events().len();
    let _ = client.check_access("users:get", RESOURCE, None).await;

    assert_eq!(
        server.received_requests().await.unwrap().len(),
        1,
        "the second check must be served from the memo"
    );
    assert_eq!(
        collector.events().len(),
        after_first,
        "a memo hit must emit no request events: {:?}",
        collector.events()
    );
}

#[tokio::test]
async fn close_is_idempotent_and_silent() {
    // §18.1 rule 5, restated at the D5 entry point because its failure mode is
    // invisible: a `logout` quietly wired into `close()` succeeds silently and
    // would end every user's session on each deploy.
    let server = MockServer::start().await;
    let client = client_with_sink(&server, Collector::default());

    client.close().await;
    client.close().await;

    assert!(
        server.received_requests().await.unwrap().is_empty(),
        "close() must not reach the network"
    );
}
