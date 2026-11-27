//! CONTRACT.md §9 / §12.1 — the `oidc_refresh` single-flight is keyed per
//! refresh token (and resolved tenant), never shared across different grants
//! (#161).
//!
//! The mock token endpoint answers each request with an access token derived
//! from the refresh token it was sent, so a caller handed another grant's
//! token set is visible as a wrong `access_token`.

#![cfg(feature = "rest")]

#[path = "oidc_support/mod.rs"]
mod oidc_support;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axiam_sdk::client::AxiamClient;
use axiam_sdk::oidc::{OidcConfiguration, OidcRefreshParams, OidcTokenSet};
use axiam_sdk::{AxiamError, Sensitive};
use oidc_support::{build_client, discovery_document, token_response};
use serde_json::json;
use uuid::Uuid;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

#[derive(Clone, Debug)]
struct Call {
    refresh_token: String,
    tenant_id: String,
}

type Calls = Arc<Mutex<Vec<Call>>>;

/// Mount `/oauth2/token`: replies `access-for-<refresh_token>`, delayed by
/// `delay`, and records the refresh token and `tenant_id` query of each call.
async fn mount(server: &MockServer, delay: Duration) -> Calls {
    let calls: Calls = Arc::default();
    let c = Arc::clone(&calls);
    Mock::given(method("POST"))
        .and(path("/oauth2/token"))
        .respond_with(move |req: &Request| {
            let form: HashMap<String, String> = url::form_urlencoded::parse(&req.body)
                .map(|(k, v)| (k.into_owned(), v.into_owned()))
                .collect();
            let token = form.get("refresh_token").cloned().unwrap_or_default();
            let tenant_id = req
                .url
                .query_pairs()
                .find(|(k, _)| k == "tenant_id")
                .map(|(_, v)| v.into_owned())
                .unwrap_or_default();
            c.lock().unwrap().push(Call {
                refresh_token: token.clone(),
                tenant_id,
            });
            ResponseTemplate::new(200)
                .set_body_json(token_response(json!({
                    "access_token": format!("access-for-{token}"),
                })))
                .set_delay(delay)
        })
        .mount(server)
        .await;
    calls
}

fn cfg(base: &str) -> OidcConfiguration {
    serde_json::from_value(discovery_document(base)).expect("discovery parses")
}

async fn refresh(
    client: &AxiamClient,
    cfg: &OidcConfiguration,
    token: &str,
    tenant: Option<Uuid>,
    scope: Option<&str>,
) -> Result<OidcTokenSet, AxiamError> {
    client
        .oidc_refresh(OidcRefreshParams {
            refresh_token: Sensitive::new(token.to_string()),
            scope: scope.map(str::to_string),
            tenant_id: tenant,
            configuration: Some(cfg.clone()),
        })
        .await
}

fn access(r: &Result<OidcTokenSet, AxiamError>) -> String {
    r.as_ref()
        .expect("refresh succeeds")
        .access_token
        .expose()
        .clone()
}

/// A tenant UUID containing hex letters, so upper- and lower-case differ.
const HEX_TENANT: &str = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";

fn client_with_tenant(base: &str, tenant: Uuid) -> AxiamClient {
    AxiamClient::builder()
        .base_url(base)
        .expect("valid base url")
        .tenant_id(tenant)
        .oidc_client_id("axiam-test-client")
        .build()
        .expect("client builds")
}

#[tokio::test]
async fn a_different_token_during_a_live_flight_gets_its_own_wire_call_and_token_set() {
    let server = MockServer::start().await;
    let calls = mount(&server, Duration::from_millis(400)).await;
    let client = build_client(&server.uri(), false);
    let cfg = cfg(&server.uri());

    let (a1, a2, b) = tokio::join!(
        refresh(&client, &cfg, "token-a", None, None),
        async {
            tokio::time::sleep(Duration::from_millis(50)).await;
            refresh(&client, &cfg, "token-a", None, None).await
        },
        async {
            tokio::time::sleep(Duration::from_millis(100)).await;
            refresh(&client, &cfg, "token-b", None, None).await
        },
    );
    assert_eq!(access(&a1), "access-for-token-a");
    assert_eq!(
        access(&a2),
        "access-for-token-a",
        "a second A caller shares A's one call"
    );
    assert_eq!(
        access(&b),
        "access-for-token-b",
        "B must get its own grant's tokens"
    );
    let seen = calls.lock().unwrap().clone();
    assert_eq!(seen.len(), 2, "one wire call per distinct token");
    let mut sent: Vec<_> = seen.iter().map(|c| c.refresh_token.as_str()).collect();
    sent.sort_unstable();
    assert_eq!(
        sent,
        ["token-a", "token-b"],
        "each token is sent exactly once"
    );
}

#[tokio::test]
async fn twenty_distinct_tokens_run_concurrently_and_all_complete() {
    let server = MockServer::start().await;
    let calls = mount(&server, Duration::from_millis(300)).await;
    let client = build_client(&server.uri(), false);
    let cfg = cfg(&server.uri());

    let started = std::time::Instant::now();
    let all = tokio::time::timeout(Duration::from_secs(5), async {
        let mut set = tokio::task::JoinSet::new();
        for i in 0..20 {
            let client = client.clone();
            let cfg = cfg.clone();
            set.spawn(async move {
                let t = format!("token-{i}");
                (t.clone(), refresh(&client, &cfg, &t, None, None).await)
            });
        }
        let mut out = Vec::new();
        while let Some(r) = set.join_next().await {
            out.push(r.expect("task"));
        }
        out
    })
    .await
    .expect("20 distinct-token refreshes complete under the timeout");
    for (t, r) in &all {
        assert_eq!(access(r), format!("access-for-{t}"));
    }
    assert_eq!(calls.lock().unwrap().len(), 20);
    assert!(
        started.elapsed() < Duration::from_millis(3000),
        "different keys' wire calls must overlap, not queue behind one another"
    );
}

#[tokio::test]
async fn a_different_keys_wire_call_starts_while_another_is_held_on_the_transport() {
    let server = MockServer::start().await;
    // Token A's response is held for 1.5 s; B's request must still ARRIVE at
    // the transport long before that.
    let calls = mount(&server, Duration::from_millis(1500)).await;
    let client = build_client(&server.uri(), false);
    let cfg = cfg(&server.uri());

    let a = tokio::spawn({
        let (client, cfg) = (client.clone(), cfg.clone());
        async move { refresh(&client, &cfg, "token-a", None, None).await }
    });
    tokio::time::sleep(Duration::from_millis(200)).await;
    let b = tokio::spawn({
        let (client, cfg) = (client.clone(), cfg.clone());
        async move { refresh(&client, &cfg, "token-b", None, None).await }
    });
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        calls.lock().unwrap().len(),
        2,
        "B's request reached the wire while A's was still held"
    );
    assert!(!a.is_finished());
    assert_eq!(access(&a.await.unwrap()), "access-for-token-a");
    assert_eq!(access(&b.await.unwrap()), "access-for-token-b");
}

#[tokio::test]
async fn same_token_different_scope_joins_the_one_flight() {
    let server = MockServer::start().await;
    let calls = mount(&server, Duration::from_millis(300)).await;
    let client = build_client(&server.uri(), false);
    let cfg = cfg(&server.uri());
    let (x, y) = tokio::join!(
        refresh(&client, &cfg, "token-a", None, Some("openid")),
        async {
            tokio::time::sleep(Duration::from_millis(60)).await;
            refresh(&client, &cfg, "token-a", None, Some("openid profile")).await
        },
    );
    assert_eq!(access(&x), "access-for-token-a");
    assert_eq!(access(&y), "access-for-token-a");
    assert_eq!(calls.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn same_token_different_tenant_are_separate_flights() {
    let server = MockServer::start().await;
    let calls = mount(&server, Duration::from_millis(300)).await;
    let client = build_client(&server.uri(), false);
    let cfg = cfg(&server.uri());
    let t1 = Uuid::parse_str(HEX_TENANT).unwrap();
    let t2 = Uuid::parse_str("11111111-2222-4333-8444-555555555555").unwrap();
    let (x, y) = tokio::join!(refresh(&client, &cfg, "token-a", Some(t1), None), async {
        tokio::time::sleep(Duration::from_millis(60)).await;
        refresh(&client, &cfg, "token-a", Some(t2), None).await
    },);
    assert!(x.is_ok() && y.is_ok());
    let seen = calls.lock().unwrap().clone();
    assert_eq!(seen.len(), 2);
    let tenants: Vec<_> = seen.iter().map(|c| c.tenant_id.clone()).collect();
    assert!(tenants.contains(&t1.hyphenated().to_string()));
    assert!(tenants.contains(&t2.hyphenated().to_string()));
}

#[tokio::test]
async fn same_token_explicit_default_tenant_upper_case_or_omitted_is_one_flight() {
    let server = MockServer::start().await;
    let calls = mount(&server, Duration::from_millis(400)).await;
    let tenant = Uuid::parse_str(HEX_TENANT).unwrap();
    let client = client_with_tenant(&server.uri(), tenant);
    let cfg = cfg(&server.uri());
    // The upper-case spelling parses to the very same Uuid.
    let upper = Uuid::parse_str(&HEX_TENANT.to_uppercase()).unwrap();
    let (x, y, z) = tokio::join!(
        refresh(&client, &cfg, "token-a", None, None),
        async {
            tokio::time::sleep(Duration::from_millis(60)).await;
            refresh(&client, &cfg, "token-a", Some(tenant), None).await
        },
        async {
            tokio::time::sleep(Duration::from_millis(120)).await;
            refresh(&client, &cfg, "token-a", Some(upper), None).await
        },
    );
    assert_eq!(access(&x), "access-for-token-a");
    assert_eq!(access(&y), "access-for-token-a");
    assert_eq!(access(&z), "access-for-token-a");
    let seen = calls.lock().unwrap().clone();
    assert_eq!(
        seen.len(),
        1,
        "omitted, explicit and upper-case tenant share one flight"
    );
    assert_eq!(
        seen[0].tenant_id, HEX_TENANT,
        "the wire carries the canonical lower-case tenant"
    );
}

#[tokio::test]
async fn an_unresolvable_tenant_fails_before_any_slot_or_wire_call() {
    let server = MockServer::start().await;
    let calls = mount(&server, Duration::ZERO).await;
    // Slug-only client with no login: no tenant UUID can be resolved.
    let client = AxiamClient::builder()
        .base_url(server.uri())
        .expect("valid base url")
        .tenant_slug("acme")
        .oidc_client_id("axiam-test-client")
        .build()
        .expect("client builds");
    let cfg = cfg(&server.uri());
    let err = refresh(&client, &cfg, "token-a", None, None)
        .await
        .expect_err("no tenant");
    assert!(matches!(err, AxiamError::Auth { .. }));
    assert!(calls.lock().unwrap().is_empty());
}
