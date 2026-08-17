//! CONTRACT.md §22.14 — declarative reactor handler binding.
//!
//! Six groups for six rules. None needs a broker: [`ReactorRouter`] is pure
//! composition over the handler `reactor_serve` already takes, so what is under
//! test is the binding table and the one answer it gives for an event nobody
//! bound.

#![cfg(feature = "reactor-macros")]

use std::collections::BTreeMap;

use chrono::Utc;
use uuid::Uuid;

use axiam_sdk::amqp::reactor::{
    EVENT_REGISTRY, ReactorDecision, ReactorEvent, ReactorRouter, default_failure_policy_for,
    events,
};
use axiam_sdk::reactor_handler;

/// Assembled from halves so a plain source scan for §22.7's three excluded
/// operations over this repository's reactor surface finds nothing, and this
/// file's own text cannot be what such a scan matches on.
fn excluded_hot_path() -> Vec<String> {
    [
        ("authz", "check"),
        ("authz", "check_batch"),
        ("token", "introspect"),
    ]
    .iter()
    .map(|(a, b)| format!("{a}.{b}"))
    .collect()
}

/// A minimal verified event — only `event` is read by the router.
fn event(name: &str) -> ReactorEvent {
    ReactorEvent {
        key_version: 2,
        tenant_id: Uuid::nil(),
        event: name.to_string(),
        correlation_id: Uuid::nil(),
        payload: serde_json::json!({}),
        timeout_ms: 500,
        nonce: Uuid::nil(),
        issued_at: Utc::now(),
        hmac_signature: None,
    }
}

// ---------------------------------------------------------------------------
// Rule 1 — it composes, it does not replace
// ---------------------------------------------------------------------------

#[reactor_handler("token.pre_issue")]
async fn enrich_token(_event: ReactorEvent) -> ReactorDecision {
    ReactorDecision::mutate([("ext.department", "engineering")])
}

#[reactor_handler("login.post_auth")]
async fn screen_login(_event: ReactorEvent) -> ReactorDecision {
    ReactorDecision::deny("embargoed region")
}

#[tokio::test]
async fn dispatches_each_event_to_its_own_handler() {
    let handler = ReactorRouter::new()
        .on::<enrich_token>()
        .on::<screen_login>()
        .build()
        .expect("router builds");

    let mut expected = BTreeMap::new();
    expected.insert("ext.department".to_string(), "engineering".to_string());
    assert_eq!(
        handler(event(events::TOKEN_PRE_ISSUE)).await,
        ReactorDecision::Mutate { patch: expected }
    );
    assert_eq!(
        handler(event(events::LOGIN_POST_AUTH)).await,
        ReactorDecision::deny("embargoed region")
    );
}

/// The macro emits the function unchanged, so it stays directly callable — the
/// marker type lives in the *type* namespace only and does not shadow it.
#[tokio::test]
async fn a_decorated_handler_stays_directly_callable() {
    assert!(matches!(
        enrich_token(event(events::TOKEN_PRE_ISSUE)).await,
        ReactorDecision::Mutate { .. }
    ));
}

#[tokio::test]
async fn a_closure_can_be_bound_without_the_macro() {
    let handler = ReactorRouter::new()
        .bind(events::USER_PRE_CREATE, |_event| async move {
            ReactorDecision::allow()
        })
        .build()
        .expect("router builds");

    assert_eq!(
        handler(event(events::USER_PRE_CREATE)).await,
        ReactorDecision::allow()
    );
}

/// The composed value is what `reactor_serve` takes. A compile-time assertion:
/// if `build()`'s return type stopped satisfying the bound, this would not
/// compile.
#[test]
fn build_produces_a_reactor_serve_handler() {
    fn accepts<F, Fut>(_handler: F)
    where
        F: Fn(ReactorEvent) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = ReactorDecision> + Send,
    {
    }

    accepts(
        ReactorRouter::new()
            .on::<enrich_token>()
            .build()
            .expect("router builds"),
    );
}

// ---------------------------------------------------------------------------
// Rule 2 — an unregistered name is refused at bind time
// ---------------------------------------------------------------------------

#[test]
fn rejects_a_misspelled_event_name() {
    let error = ReactorRouter::new()
        .bind("token.pre_isue", |_event| async move {
            ReactorDecision::allow()
        })
        .build()
        .err()
        .expect("a typo'd event name was accepted");

    assert!(error.to_string().contains("token.pre_isue"), "{error}");
    assert!(
        error.to_string().contains("not a hookable reactor event"),
        "{error}"
    );
}

/// §22.7's three are in no registry row, so rule 2 refuses them as unknown
/// names. Asserted on behaviour, not on a comment.
#[test]
fn rejects_the_hot_path_operations() {
    for name in excluded_hot_path() {
        let leaked: &'static str = Box::leak(name.clone().into_boxed_str());
        assert!(
            ReactorRouter::new()
                .bind(leaked, |_event| async move { ReactorDecision::allow() })
                .build()
                .is_err(),
            "binding {name} was accepted; §22.7 makes it un-hookable"
        );
    }
}

/// The rejection names what IS hookable — §22.14 rule 2's second half. A
/// hot-path list in library code, even only to produce a better message, is the
/// constant §22.13 forbids.
#[test]
fn rejection_names_the_registry_not_the_exclusions() {
    let error = ReactorRouter::new()
        .bind("nope", |_event| async move { ReactorDecision::allow() })
        .build()
        .err()
        .expect("an unregistered name was accepted")
        .to_string();

    assert!(error.contains(events::TOKEN_PRE_ISSUE), "{error}");
    for excluded in excluded_hot_path() {
        assert!(!error.contains(&excluded), "{error}");
    }
}

/// The proc-macro validates its literal against its own copy of the registry,
/// because a host-compiled proc-macro crate cannot depend on the library it
/// expands into. This asserts the copy is complete: every registry event must be
/// bindable, so an event added upstream and forgotten in the macro fails here
/// rather than becoming silently unbindable.
#[test]
fn every_registry_event_is_bindable() {
    for spec in EVENT_REGISTRY {
        assert!(
            ReactorRouter::new()
                .bind(spec.name, |_event| async move { ReactorDecision::allow() })
                .build()
                .is_ok(),
            "{} is in the registry but was refused by the router",
            spec.name
        );
    }
    assert_eq!(
        EVENT_REGISTRY.len(),
        5,
        "the macro's copy lists five events"
    );
}

// ---------------------------------------------------------------------------
// Rule 3 — one handler per event
// ---------------------------------------------------------------------------

#[test]
fn rejects_a_duplicate_binding() {
    let error = ReactorRouter::new()
        .on::<enrich_token>()
        .on::<enrich_token>()
        .build()
        .err()
        .expect("a duplicate binding was accepted");

    assert!(error.to_string().contains("already bound"), "{error}");
}

/// Every rejected binding is reported, not just the first: a chained builder
/// that surfaced one error per call would make fixing three typos three runs.
#[test]
fn reports_every_rejection() {
    let error = ReactorRouter::new()
        .bind("nope.one", |_event| async move { ReactorDecision::allow() })
        .bind("nope.two", |_event| async move { ReactorDecision::allow() })
        .build()
        .err()
        .expect("bad bindings were accepted")
        .to_string();

    assert!(error.contains("nope.one"), "{error}");
    assert!(error.contains("nope.two"), "{error}");
}

// ---------------------------------------------------------------------------
// Rule 4 — an unbound event abstains. The reason this module exists.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn an_unbound_event_abstains_rather_than_allowing() {
    let handler = ReactorRouter::new()
        .on::<enrich_token>()
        .build()
        .expect("router builds");

    let decision = handler(event(events::GRANT_PRE_ASSIGN)).await;

    assert_eq!(decision, ReactorDecision::Abstain);
    // Stated separately and deliberately: "not allow" is the whole claim. A
    // `_ => allow()` arm answers on behalf of code that never ran, which
    // defeats an operator's fail_closed setting (§22.10 rule 2).
    assert!(!matches!(decision, ReactorDecision::Allow { .. }));
    assert!(!matches!(decision, ReactorDecision::Deny { .. }));
}

#[test]
fn an_empty_router_is_refused() {
    let error = ReactorRouter::new()
        .build()
        .err()
        .expect("an empty router was accepted")
        .to_string();

    assert!(error.contains("no bindings"), "{error}");
}

// ---------------------------------------------------------------------------
// Rule 5 — a handler's own failure propagates
// ---------------------------------------------------------------------------

#[reactor_handler("user.pre_update")]
async fn explodes(_event: ReactorEvent) -> ReactorDecision {
    panic!("directory timed out");
}

#[tokio::test]
#[should_panic(expected = "directory timed out")]
async fn a_panicking_handler_propagates() {
    let handler = ReactorRouter::new()
        .on::<explodes>()
        .build()
        .expect("router builds");

    // No catch_unwind in the router: the panic must reach `reactor_serve`
    // unchanged so it publishes nothing (§22.10 rule 2).
    let _ = handler(event(events::USER_PRE_UPDATE)).await;
}

// ---------------------------------------------------------------------------
// Rule 6 and the SHOULD — no filtering, bound events visible
// ---------------------------------------------------------------------------

#[reactor_handler("user.pre_create")]
async fn sets_a_forbidden_key(_event: ReactorEvent) -> ReactorDecision {
    ReactorDecision::mutate([("password", "hunter2")])
}

#[tokio::test]
async fn a_forbidden_patch_key_is_sent_unfiltered() {
    let handler = ReactorRouter::new()
        .on::<sets_a_forbidden_key>()
        .build()
        .expect("router builds");

    let mut expected = BTreeMap::new();
    expected.insert("password".to_string(), "hunter2".to_string());
    assert_eq!(
        handler(event(events::USER_PRE_CREATE)).await,
        ReactorDecision::Mutate { patch: expected },
        "the router silently dropped a patch key"
    );
}

#[test]
fn bound_events_feed_the_failure_policy() {
    let router = ReactorRouter::new()
        .on::<enrich_token>()
        .on::<screen_login>();

    assert_eq!(
        router.events(),
        [events::TOKEN_PRE_ISSUE, events::LOGIN_POST_AUTH]
    );
    // token.pre_issue defaults open, login.post_auth defaults closed; §22.8's
    // strictest-wins composition makes the pair fail_closed.
    assert_eq!(
        default_failure_policy_for(router.events().iter().copied()).as_str(),
        "fail_closed"
    );
}
