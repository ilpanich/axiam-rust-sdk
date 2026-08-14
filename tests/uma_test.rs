//! UMA 2.0 — CONTRACT.md §20.7 required assertions, at the wire.
//!
//! The parsing and payload-shape rules are unit-tested in `src/uma.rs`. What
//! only exists once a socket is involved lives here, and the centrepiece is
//! **§20.2 rule 6**: a permission ticket must never be retried.
//!
//! That rule is the one §16 exception in the contract, and the only way to
//! assert it is to count requests. A ticket is consumed *before* the request is
//! evaluated, so a failed exchange has already spent it — and under concurrency
//! a retry is precisely the concurrent redemption a server whose storage engine
//! this SDK cannot attest may admit twice (ilpanich/axiam#302). "Exactly one
//! request" is therefore a security assertion, not a performance one.
//!
//! Every test is named after the thing it stops.

#![cfg(feature = "rest")]

#[path = "oidc_support/mod.rs"]
mod oidc_support;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use axiam_sdk::Sensitive;
use axiam_sdk::client::AxiamClient;
use axiam_sdk::uma::{RequestedPermission, ResourceSet, uma_parse_challenge};
use serde_json::json;
use uuid::Uuid;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

use oidc_support::{build_client, discovery_document};

const PAT: &str = "pat-token-value";
const TICKET: &str = "ticket-value";
const CLAIM_TOKEN: &str = "claim-token-value";

async fn mount_discovery(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(200).set_body_json(discovery_document(&server.uri())))
        .mount(server)
        .await;
}

/// Mount `/oauth2/token` answering `template`, counting how many requests
/// arrive. The count is the assertion.
async fn mount_token_counting(server: &MockServer, template: ResponseTemplate) -> Arc<AtomicUsize> {
    let calls = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&calls);
    Mock::given(method("POST"))
        .and(path("/oauth2/token"))
        .respond_with(move |_: &Request| {
            counter.fetch_add(1, Ordering::SeqCst);
            template.clone()
        })
        .mount(server)
        .await;
    calls
}

// ---------------------------------------------------------------------------
// §20.2 rule 6 — the ticket grant is never retried
// ---------------------------------------------------------------------------

/// A `500` must not be retried. This is the §16 exception: the ticket is spent
/// whether or not the exchange succeeded, so a retry cannot succeed — and it is
/// the concurrent redemption #302 measures.
#[tokio::test]
async fn a_5xx_on_the_ticket_grant_is_not_retried() {
    let server = MockServer::start().await;
    mount_discovery(&server).await;
    let calls = mount_token_counting(&server, ResponseTemplate::new(500)).await;

    let client = build_client(&server.uri(), true);
    let result = client
        .uma_exchange_ticket(
            &Sensitive::new(TICKET.to_string()),
            &Sensitive::new(CLAIM_TOKEN.to_string()),
        )
        .await;

    assert!(result.is_err(), "a 500 must surface as an error");
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "the ticket grant must issue exactly one request — retrying a spent \
         ticket is the concurrent redemption ilpanich/axiam#302 describes"
    );
}

/// A **timeout** must not be retried either. §20.7 names it alongside `5xx`
/// and `invalid_grant`, and it is the case most tempting to treat as "the
/// request never happened" — a §16 retry runner will normally re-send a
/// request that produced no response at all.
///
/// It is the wrong instinct here. A timeout says nothing about whether the
/// server saw the exchange; it may well have arrived and spent the ticket, and
/// silence is not evidence that it did not. Re-sending is then the second
/// redemption.
///
/// The server answers far later than the client is willing to wait, so the
/// timeout is deterministic rather than a race against a sleeping test.
#[tokio::test]
async fn a_timeout_on_the_ticket_grant_is_not_retried() {
    let server = MockServer::start().await;
    mount_discovery(&server).await;
    let calls = mount_token_counting(
        &server,
        ResponseTemplate::new(200).set_delay(Duration::from_secs(30)),
    )
    .await;

    let client = AxiamClient::builder()
        .base_url(&server.uri())
        .expect("valid base url")
        .tenant_id(oidc_support::tenant_id())
        .org_id(oidc_support::org_id())
        .oidc_client_id(oidc_support::CLIENT_ID)
        .oidc_client_secret(oidc_support::CLIENT_SECRET)
        .request_timeout(Duration::from_millis(250))
        .build()
        .expect("client builds");

    let result = client
        .uma_exchange_ticket(
            &Sensitive::new(TICKET.to_string()),
            &Sensitive::new(CLAIM_TOKEN.to_string()),
        )
        .await;

    assert!(result.is_err(), "a timeout must surface as an error");
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "the ticket grant must issue exactly one request even when it times \
         out — a timed-out exchange may already have spent the ticket, so a \
         retry is the concurrent redemption a server whose storage engine \
         this SDK cannot attest may admit twice"
    );
}

/// `invalid_grant` — the answer a replayed ticket gets — must not be retried
/// either. The retry could not succeed, and attempting it is the bug.
#[tokio::test]
async fn an_invalid_grant_on_the_ticket_grant_is_not_retried() {
    let server = MockServer::start().await;
    mount_discovery(&server).await;
    let calls = mount_token_counting(
        &server,
        ResponseTemplate::new(400).set_body_json(json!({
            "error": "invalid_grant",
            "error_description": "permission ticket is invalid, expired, or already used"
        })),
    )
    .await;

    let client = build_client(&server.uri(), true);
    let err = client
        .uma_exchange_ticket(
            &Sensitive::new(TICKET.to_string()),
            &Sensitive::new(CLAIM_TOKEN.to_string()),
        )
        .await
        .expect_err("invalid_grant must surface");

    assert_eq!(err.oauth_error_code(), Some("invalid_grant"));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

/// `access_denied` arrives as **403** on this grant (UMA 2.0 §3.3.6), unlike
/// RFC 8628's, which is a 400. The SDK dispatches on the `error` field, so the
/// code reaches the caller either way — and is not auto-narrowed into a smaller
/// ticket request (§20.2 rule 3).
#[tokio::test]
async fn access_denied_surfaces_as_itself_and_is_not_auto_narrowed() {
    let server = MockServer::start().await;
    mount_discovery(&server).await;
    let calls = mount_token_counting(
        &server,
        ResponseTemplate::new(403).set_body_json(json!({
            "error": "access_denied",
            "error_description": "the requesting party is not authorized for every requested permission"
        })),
    )
    .await;

    let client = build_client(&server.uri(), true);
    let err = client
        .uma_exchange_ticket(
            &Sensitive::new(TICKET.to_string()),
            &Sensitive::new(CLAIM_TOKEN.to_string()),
        )
        .await
        .expect_err("access_denied must surface");

    assert_eq!(
        err.oauth_error_code(),
        Some("access_denied"),
        "the 403 must not be flattened into a generic authorization error"
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "a refused ticket must not be re-requested with fewer scopes"
    );
}

// ---------------------------------------------------------------------------
// The happy path, and what it must not do
// ---------------------------------------------------------------------------

/// An RPT comes back with no refresh token, and the client's own session is
/// untouched — the RPT is the requesting party's, not this client's
/// (§20.2 rules 4 and 5).
#[tokio::test]
async fn an_rpt_is_not_adopted_as_the_clients_own_credentials() {
    let server = MockServer::start().await;
    mount_discovery(&server).await;
    Mock::given(method("POST"))
        .and(path("/oauth2/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "rpt-value",
            "token_type": "Bearer",
            "expires_in": 300
        })))
        .mount(&server)
        .await;

    // Capture the Authorization header of any later call on the same client.
    let seen = Arc::new(std::sync::Mutex::new(None::<Option<String>>));
    let sink = Arc::clone(&seen);
    Mock::given(method("POST"))
        .and(path("/api/v1/authz/check"))
        .respond_with(move |req: &Request| {
            *sink.lock().unwrap() = Some(
                req.headers
                    .get("authorization")
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_string),
            );
            ResponseTemplate::new(200).set_body_json(json!({ "allowed": false }))
        })
        .mount(&server)
        .await;

    let client = build_client(&server.uri(), true);
    let rpt = client
        .uma_exchange_ticket(
            &Sensitive::new(TICKET.to_string()),
            &Sensitive::new(CLAIM_TOKEN.to_string()),
        )
        .await
        .expect("exchange succeeds");

    assert_eq!(rpt.access_token.expose(), "rpt-value");
    assert_eq!(rpt.expires_in, 300);

    // A subsequent call must not carry the RPT. Rule 4 is a MUST NOT because
    // adopting it would re-privilege every later call this resource server
    // makes *as the requesting party* — a privilege change far from here.
    let _ = client.can("read", Uuid::new_v4(), None).await;
    let sent = seen.lock().unwrap().clone().flatten();
    assert!(
        !sent.is_some_and(|h| h.contains("rpt-value")),
        "§20.2 rule 4: uma_exchange_ticket MUST NOT adopt the RPT"
    );
}

// ---------------------------------------------------------------------------
// Protection API
// ---------------------------------------------------------------------------

/// Registration round-trips, and the `_id` it returns is directly usable as the
/// `resource_id` of a ticket request — there is no parallel identifier to
/// translate through.
#[tokio::test]
async fn a_registered_id_is_usable_as_a_ticket_resource_id() {
    let server = MockServer::start().await;
    let resource_id = Uuid::new_v4();

    Mock::given(method("POST"))
        .and(path("/uma2/rreg/resource_set"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "_id": resource_id,
            "name": "invoice-7",
            "type": "document",
            "resource_scopes": ["view"]
        })))
        .mount(&server)
        .await;

    let captured = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&captured);
    Mock::given(method("POST"))
        .and(path("/uma2/perm"))
        .respond_with(move |_: &Request| {
            counter.fetch_add(1, Ordering::SeqCst);
            ResponseTemplate::new(201).set_body_json(json!({ "ticket": TICKET }))
        })
        .mount(&server)
        .await;

    let client = build_client(&server.uri(), true);
    let pat = Sensitive::new(PAT.to_string());

    let registered = client
        .uma_register_resource(
            &pat,
            &ResourceSet::new("invoice-7")
                .with_type("document")
                .with_scopes(["view"]),
        )
        .await
        .expect("registration succeeds");

    assert_eq!(registered.id, Some(resource_id));

    let ticket = client
        .uma_request_ticket(
            &pat,
            &[RequestedPermission::new(
                registered.id.expect("registered id"),
                ["view"],
            )],
        )
        .await
        .expect("ticket mints");

    assert_eq!(ticket.expose(), TICKET);
    assert_eq!(captured.load(Ordering::SeqCst), 1);
}

/// An update sends exactly the scopes it was given. If the SDK ever read the
/// current set and merged, removing a scope would become impossible through it
/// (§20.2 rule 8).
#[tokio::test]
async fn an_update_sends_only_the_scopes_given_and_does_not_read_first() {
    let server = MockServer::start().await;
    let resource_id = Uuid::new_v4();

    let sent = Arc::new(std::sync::Mutex::new(None::<serde_json::Value>));
    let sink = Arc::clone(&sent);
    Mock::given(method("PUT"))
        .and(path(format!("/uma2/rreg/resource_set/{resource_id}")))
        .respond_with(move |req: &Request| {
            *sink.lock().unwrap() = Some(serde_json::from_slice(&req.body).unwrap());
            ResponseTemplate::new(200).set_body_json(json!({
                "_id": resource_id, "name": "invoice-7", "type": "document",
                "resource_scopes": ["view"]
            }))
        })
        .mount(&server)
        .await;

    // Deliberately NOT mounting GET: if the SDK read-modify-wrote, the missing
    // mock would make this test fail rather than pass quietly.
    let client = build_client(&server.uri(), true);
    client
        .uma_update_resource(
            &Sensitive::new(PAT.to_string()),
            resource_id,
            &ResourceSet::new("invoice-7")
                .with_type("document")
                .with_scopes(["view"]),
        )
        .await
        .expect("update succeeds");

    let body = sent.lock().unwrap().clone().expect("a body was sent");
    assert_eq!(body["resource_scopes"], json!(["view"]));
}

/// A `403` from the Protection API — the answer to a token that is not a PAT —
/// reaches the caller rather than being retried or reshaped.
#[tokio::test]
async fn a_non_pat_is_refused_and_the_refusal_reaches_the_caller() {
    let server = MockServer::start().await;
    let calls = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&calls);
    Mock::given(method("POST"))
        .and(path("/uma2/perm"))
        .respond_with(move |_: &Request| {
            counter.fetch_add(1, Ordering::SeqCst);
            ResponseTemplate::new(403).set_body_json(json!({
                "error": "authorization_denied",
                "message": "the protection API requires the 'uma_protection' scope"
            }))
        })
        .mount(&server)
        .await;

    let client = build_client(&server.uri(), true);
    let result = client
        .uma_request_ticket(
            &Sensitive::new("not-a-pat".to_string()),
            &[RequestedPermission::new(Uuid::new_v4(), ["view"])],
        )
        .await;

    assert!(result.is_err());
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

// ---------------------------------------------------------------------------
// §20.3 — the challenge helper does not act
// ---------------------------------------------------------------------------

/// Parsing a challenge must perform **no** outbound request. The `as_uri` names
/// an authorization server the client has not chosen to trust; auto-exchanging
/// would send the requesting party's `claim_token` to whatever host answered
/// the 403.
#[tokio::test]
async fn parsing_a_challenge_performs_no_exchange() {
    let server = MockServer::start().await;
    // Any request at all fails the test: nothing is mounted, so wiremock
    // answers 404 and records it.
    let challenge = uma_parse_challenge(&format!(
        r#"UMA realm="example", as_uri="{}", ticket="{TICKET}""#,
        server.uri()
    ))
    .expect("parses");

    assert_eq!(challenge.as_uri.as_deref(), Some(server.uri().as_str()));
    assert_eq!(
        server.received_requests().await.expect("recording").len(),
        0,
        "uma_parse_challenge must not exchange the ticket it parsed"
    );
}
