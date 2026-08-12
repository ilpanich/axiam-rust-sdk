//! The §20.3 emit half, wired into the §11 route guard.
//!
//! `RequireAccess::with_uma_challenge` turns a denial from a bare 403 into a
//! 403 that tells the caller where to obtain authority. Three properties are
//! worth a socket rather than a unit test, and all three are about what happens
//! on the *deny* path — the only path that mints anything:
//!
//! 1. A denial with a challenger attached mints exactly one ticket and emits it.
//! 2. An **allow** mints nothing. A guard that minted on the happy path would
//!    put a Protection API call in front of every authorized request.
//! 3. A minting failure still denies, without a challenge. A Protection API
//!    outage must not turn a deny into a 500, and must never turn it into an
//!    allow.

#![cfg(all(feature = "rest", feature = "actix"))]

#[path = "oidc_support/mod.rs"]
mod oidc_support;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use actix_web::ResponseError;
use actix_web::http::header::WWW_AUTHENTICATE;
use axiam_sdk::Sensitive;
use axiam_sdk::middleware::{AuthzGuardError, AxiamUser, RequireAccess, UmaChallenger};
use axiam_sdk::uma::uma_parse_challenge;
use serde_json::json;
use uuid::Uuid;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

use oidc_support::build_client;

const PAT: &str = "pat-token-value";
const TICKET: &str = "ticket-value";

fn user() -> AxiamUser {
    AxiamUser {
        user_id: Uuid::new_v4(),
        tenant_id: Uuid::new_v4(),
        roles: vec![],
    }
}

fn challenger() -> UmaChallenger {
    UmaChallenger::new(
        "invoices",
        "https://id.example",
        Sensitive::new(PAT.to_string()),
    )
}

/// Mount the authz check answering `allowed`, and `/uma2/perm` answering
/// `perm_template`. Both counters are returned, because the assertions are
/// about how many times each was called.
async fn mount(
    server: &MockServer,
    allowed: bool,
    perm_template: ResponseTemplate,
) -> (Arc<AtomicUsize>, Arc<AtomicUsize>) {
    let authz_calls = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&authz_calls);
    Mock::given(method("POST"))
        .and(path("/api/v1/authz/check"))
        .respond_with(move |_: &Request| {
            counter.fetch_add(1, Ordering::SeqCst);
            ResponseTemplate::new(200).set_body_json(json!({
                "allowed": allowed,
                "reason_code": if allowed { "allowed" } else { "no_matching_grant" },
            }))
        })
        .mount(server)
        .await;

    let perm_calls = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&perm_calls);
    Mock::given(method("POST"))
        .and(path("/uma2/perm"))
        .respond_with(move |_: &Request| {
            counter.fetch_add(1, Ordering::SeqCst);
            perm_template.clone()
        })
        .mount(server)
        .await;

    (authz_calls, perm_calls)
}

#[tokio::test]
async fn a_denial_mints_one_ticket_and_emits_the_challenge() {
    let server = MockServer::start().await;
    let (_, perm_calls) = mount(
        &server,
        false,
        ResponseTemplate::new(201).set_body_json(json!({ "ticket": TICKET })),
    )
    .await;

    let client = build_client(&server.uri(), true);
    let error = RequireAccess::new("read")
        .with_uma_challenge(challenger())
        .check(&client, &user(), Uuid::new_v4())
        .await
        .expect_err("the check denies");

    assert!(matches!(error, AuthzGuardError::DeniedWithChallenge(..)));
    assert_eq!(perm_calls.load(Ordering::SeqCst), 1, "one ticket, not two");

    let response = error.error_response();
    assert_eq!(
        response.status(),
        403,
        "the challenge is additive, not a redirect"
    );

    let header = response
        .headers()
        .get(WWW_AUTHENTICATE)
        .expect("the challenge is emitted")
        .to_str()
        .expect("ASCII header");

    // The emitted header is the one the consuming half parses — the round trip
    // is the point of shipping both halves.
    let parsed = uma_parse_challenge(header).expect("a UMA challenge");
    assert_eq!(parsed.realm.as_deref(), Some("invoices"));
    assert_eq!(parsed.as_uri.as_deref(), Some("https://id.example"));
    assert_eq!(parsed.ticket.expect("a ticket").expose(), TICKET);
}

#[tokio::test]
async fn the_minted_ticket_asks_for_the_action_that_was_refused() {
    let server = MockValidator::start().await;
    let client = build_client(&server.server.uri(), true);

    RequireAccess::new("invoices:approve")
        .with_uma_challenge(challenger())
        .check(&client, &user(), server.resource_id)
        .await
        .expect_err("the check denies");

    let body = server.captured_permission_body();
    // §20.2: the UMA scope is the AXIAM *action*. Asking for anything else would
    // mint a ticket for authority other than the one this check just refused —
    // and would break the deny-override property the server relies on.
    assert_eq!(body[0]["resource_scopes"][0], "invoices:approve");
    assert_eq!(body[0]["resource_id"], server.resource_id.to_string());
}

#[tokio::test]
async fn an_allow_mints_nothing() {
    let server = MockServer::start().await;
    let (authz_calls, perm_calls) = mount(
        &server,
        true,
        ResponseTemplate::new(201).set_body_json(json!({ "ticket": TICKET })),
    )
    .await;

    let client = build_client(&server.uri(), true);
    RequireAccess::new("read")
        .with_uma_challenge(challenger())
        .check(&client, &user(), Uuid::new_v4())
        .await
        .expect("the check allows");

    assert_eq!(authz_calls.load(Ordering::SeqCst), 1);
    // A guard that minted on the happy path would put a Protection API call —
    // and a live credential — in front of every authorized request.
    assert_eq!(perm_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_minting_failure_still_denies_without_a_challenge() {
    let server = MockServer::start().await;
    let (_, perm_calls) = mount(&server, false, ResponseTemplate::new(500)).await;

    let client = build_client(&server.uri(), true);
    let error = RequireAccess::new("read")
        .with_uma_challenge(challenger())
        .check(&client, &user(), Uuid::new_v4())
        .await
        .expect_err("the check denies");

    // Failure is not escalation: the caller was going to be refused, and a
    // Protection API outage must not turn that into a 500 — nor, obviously,
    // into an allow.
    assert!(matches!(error, AuthzGuardError::Denied(_)));
    let response = error.error_response();
    assert_eq!(response.status(), 403);
    assert!(response.headers().get(WWW_AUTHENTICATE).is_none());
    assert_eq!(
        perm_calls.load(Ordering::SeqCst),
        1,
        "one attempt, not a retry loop"
    );
}

#[tokio::test]
async fn without_a_challenger_a_denial_is_the_plain_403_it_always_was() {
    let server = MockServer::start().await;
    let (_, perm_calls) = mount(
        &server,
        false,
        ResponseTemplate::new(201).set_body_json(json!({ "ticket": TICKET })),
    )
    .await;

    let client = build_client(&server.uri(), true);
    let error = RequireAccess::new("read")
        .check(&client, &user(), Uuid::new_v4())
        .await
        .expect_err("the check denies");

    // Opt-in means opt-in: an application that never asked for UMA semantics
    // gets no Protection API traffic from its guards.
    assert!(matches!(error, AuthzGuardError::Denied(_)));
    assert!(
        error
            .error_response()
            .headers()
            .get(WWW_AUTHENTICATE)
            .is_none()
    );
    assert_eq!(perm_calls.load(Ordering::SeqCst), 0);
}

#[test]
fn a_challenger_never_renders_its_pat() {
    // §7: a challenger is configuration an application may reasonably log, and
    // the PAT inside it is not.
    let rendered = format!("{:?}", challenger());
    assert!(!rendered.contains(PAT), "PAT leaked: {rendered}");
    assert!(rendered.contains("invoices"));
}

/// A server that captures the `/uma2/perm` body, so a test can assert what the
/// guard actually asked for rather than only that it asked.
struct MockValidator {
    server: MockServer,
    resource_id: Uuid,
    captured: Arc<std::sync::Mutex<Option<serde_json::Value>>>,
}

impl MockValidator {
    async fn start() -> Self {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/authz/check"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "allowed": false,
                "reason_code": "no_matching_grant",
            })))
            .mount(&server)
            .await;

        let captured: Arc<std::sync::Mutex<Option<serde_json::Value>>> =
            Arc::new(std::sync::Mutex::new(None));
        let sink = Arc::clone(&captured);
        Mock::given(method("POST"))
            .and(path("/uma2/perm"))
            .respond_with(move |req: &Request| {
                *sink.lock().expect("lock") = Some(req.body_json().expect("json body"));
                ResponseTemplate::new(201).set_body_json(json!({ "ticket": TICKET }))
            })
            .mount(&server)
            .await;

        Self {
            server,
            resource_id: Uuid::new_v4(),
            captured,
        }
    }

    fn captured_permission_body(&self) -> serde_json::Value {
        self.captured
            .lock()
            .expect("lock")
            .clone()
            .expect("the guard posted a permission request")
    }
}
