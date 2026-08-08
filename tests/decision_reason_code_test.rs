//! Decision reason codes — CONTRACT.md §11 rule 9 (B1 deny-override).
//!
//! The §11 rule 9 required tests: an allow, a `no_grant` deny and a
//! `denied_by_rule` deny each surface their own code; an unknown code does not
//! alter the outcome; and an older server that omits the field is treated as
//! absent rather than as an error.
//!
//! The rule exists because the two refusals mean **opposite things to the
//! person on the other end**: `no_grant` says *ask an admin for access*,
//! `denied_by_rule` says *an admin has already decided*. An application that
//! cannot tell them apart sends users to raise tickets that will be refused.

#![cfg(feature = "rest")]

use axiam_sdk::client::AxiamClient;
use axiam_sdk::rest::authz::reason_code;
use serde_json::json;
use uuid::Uuid;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn build_client(base_url: &str) -> AxiamClient {
    AxiamClient::builder()
        .base_url(base_url)
        .expect("valid base url")
        .tenant_slug("acme")
        .org_slug("acme")
        .build()
        .expect("client builds")
}

async fn decision_for(body: serde_json::Value) -> axiam_sdk::rest::authz::AccessDecision {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/authz/check"))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .mount(&server)
        .await;

    build_client(&server.uri())
        .check_access("read", Uuid::new_v4(), None)
        .await
        .expect("check_access succeeds")
}

#[tokio::test]
async fn an_allow_surfaces_the_allowed_reason_code() {
    let decision = decision_for(json!({ "allowed": true, "reason_code": "allowed" })).await;
    assert!(decision.allowed);
    assert_eq!(decision.reason_code.as_deref(), Some(reason_code::ALLOWED));
}

#[tokio::test]
async fn no_grant_and_denied_by_rule_are_not_collapsed() {
    let no_grant = decision_for(json!({ "allowed": false, "reason_code": "no_grant" })).await;
    let by_rule = decision_for(json!({ "allowed": false, "reason_code": "denied_by_rule" })).await;

    // Both are refusals…
    assert!(!no_grant.allowed);
    assert!(!by_rule.allowed);

    // …and the SDK must not reduce them to that shared `false`.
    assert_eq!(no_grant.reason_code.as_deref(), Some(reason_code::NO_GRANT));
    assert_eq!(
        by_rule.reason_code.as_deref(),
        Some(reason_code::DENIED_BY_RULE)
    );
    assert_ne!(no_grant.reason_code, by_rule.reason_code);
}

#[tokio::test]
async fn an_unknown_reason_code_is_surfaced_verbatim_and_changes_nothing() {
    // §11 rule 9: an SDK that does not recognise a code MUST surface it
    // unchanged and MUST NOT let it affect the outcome, which `allowed`
    // carries alone. This is what lets the server add a fourth code without
    // breaking every deployed SDK.
    let decision =
        decision_for(json!({ "allowed": false, "reason_code": "denied_by_some_future_thing" }))
            .await;

    assert!(!decision.allowed);
    assert_eq!(
        decision.reason_code.as_deref(),
        Some("denied_by_some_future_thing")
    );
}

#[tokio::test]
async fn an_unknown_reason_code_does_not_flip_an_allow() {
    let decision =
        decision_for(json!({ "allowed": true, "reason_code": "something-unrecognised" })).await;
    assert!(
        decision.allowed,
        "the outcome is carried by `allowed` alone"
    );
}

#[tokio::test]
async fn an_older_server_omitting_the_field_is_not_an_error() {
    // A newer SDK against an older server: the field is simply absent, and
    // that MUST degrade to today's behaviour rather than failing to parse.
    let decision = decision_for(json!({ "allowed": false })).await;
    assert!(!decision.allowed);
    assert_eq!(decision.reason_code, None);

    let allowed = decision_for(json!({ "allowed": true, "reason": "role grants it" })).await;
    assert!(allowed.allowed);
    assert_eq!(allowed.reason_code, None);
    assert_eq!(allowed.reason.as_deref(), Some("role grants it"));
}

#[tokio::test]
async fn can_still_returns_a_bare_bool_for_both_refusals() {
    // §11 rule 9 is about *reporting*, not enforcement: `can` is the
    // "just tell me yes or no" helper and both refusals answer `false`
    // identically. An SDK must not start varying enforcement on the code.
    for code in [reason_code::NO_GRANT, reason_code::DENIED_BY_RULE] {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/authz/check"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({ "allowed": false, "reason_code": code })),
            )
            .mount(&server)
            .await;

        let allowed = build_client(&server.uri())
            .can("read", Uuid::new_v4(), None)
            .await
            .expect("can succeeds");
        assert!(!allowed, "{code} is still a refusal");
    }
}

#[tokio::test]
async fn batch_check_surfaces_a_reason_code_per_decision() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/authz/check/batch"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "results": [
                { "allowed": true,  "reason_code": "allowed" },
                { "allowed": false, "reason_code": "no_grant" },
                { "allowed": false, "reason_code": "denied_by_rule" },
            ]
        })))
        .mount(&server)
        .await;

    let checks = vec![
        axiam_sdk::rest::authz::AccessCheckRequest::new("read", Uuid::new_v4()),
        axiam_sdk::rest::authz::AccessCheckRequest::new("write", Uuid::new_v4()),
        axiam_sdk::rest::authz::AccessCheckRequest::new("delete", Uuid::new_v4()),
    ];
    let decisions = build_client(&server.uri())
        .batch_check(checks)
        .await
        .expect("batch_check succeeds");

    assert_eq!(decisions.len(), 3);
    assert_eq!(
        decisions[0].reason_code.as_deref(),
        Some(reason_code::ALLOWED)
    );
    assert_eq!(
        decisions[1].reason_code.as_deref(),
        Some(reason_code::NO_GRANT)
    );
    assert_eq!(
        decisions[2].reason_code.as_deref(),
        Some(reason_code::DENIED_BY_RULE)
    );
}
