//! `oidc_refresh`, `login_client_credentials`, `introspect`, `revoke`
//! (CONTRACT.md §12.1, §12.3 rules 3–4, §9).

#![cfg(feature = "rest")]

#[path = "oidc_support/mod.rs"]
mod oidc_support;

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use axiam_sdk::AxiamError;
use axiam_sdk::Sensitive;
use axiam_sdk::oidc::{
    IntrospectParams, LoginClientCredentialsParams, OidcConfiguration, OidcRefreshParams,
    RevokeParams,
};
use serde_json::json;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

fn parse_form(body: &[u8]) -> HashMap<String, String> {
    url::form_urlencoded::parse(body)
        .into_owned()
        .collect::<HashMap<_, _>>()
}

async fn mount_discovery(mock_server: &MockServer) {
    let base = mock_server.uri();
    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(move |_req: &Request| {
            ResponseTemplate::new(200).set_body_json(oidc_support::discovery_document(&base))
        })
        .mount(mock_server)
        .await;
}

// ---------------------------------------------------------------------------
// oidc_refresh
// ---------------------------------------------------------------------------

#[tokio::test]
async fn oidc_refresh_posts_the_documented_field_set() {
    let mock_server = MockServer::start().await;
    mount_discovery(&mock_server).await;
    let captured: Arc<std::sync::Mutex<Vec<HashMap<String, String>>>> =
        Arc::new(std::sync::Mutex::new(Vec::new()));
    let captured_for = Arc::clone(&captured);
    Mock::given(method("POST"))
        .and(path("/oauth2/token"))
        .respond_with(move |req: &Request| {
            captured_for.lock().unwrap().push(parse_form(&req.body));
            ResponseTemplate::new(200).set_body_json(oidc_support::token_response(
                json!({ "refresh_token": "rotated-refresh" }),
            ))
        })
        .mount(&mock_server)
        .await;

    let client = oidc_support::build_client(&mock_server.uri(), true);
    let tokens = client
        .oidc_refresh(OidcRefreshParams {
            refresh_token: Sensitive::new("old-refresh".into()),
            scope: Some("openid".into()),
            tenant_id: None,
            configuration: None,
        })
        .await
        .expect("refresh succeeds");

    let form = captured.lock().unwrap().remove(0);
    assert_eq!(form.get("grant_type").unwrap(), "refresh_token");
    assert_eq!(form.get("refresh_token").unwrap(), "old-refresh");
    assert_eq!(form.get("client_id").unwrap(), oidc_support::CLIENT_ID);
    assert_eq!(
        form.get("client_secret").unwrap(),
        oidc_support::CLIENT_SECRET
    );
    assert_eq!(form.get("scope").unwrap(), "openid");
    let mut keys: Vec<&str> = form.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        vec![
            "client_id",
            "client_secret",
            "grant_type",
            "refresh_token",
            "scope"
        ]
    );
    assert_eq!(tokens.refresh_token.unwrap().expose(), "rotated-refresh");
}

#[tokio::test]
async fn oidc_refresh_omits_scope_when_not_narrowed() {
    let mock_server = MockServer::start().await;
    mount_discovery(&mock_server).await;
    let captured: Arc<std::sync::Mutex<Vec<HashMap<String, String>>>> =
        Arc::new(std::sync::Mutex::new(Vec::new()));
    let captured_for = Arc::clone(&captured);
    Mock::given(method("POST"))
        .and(path("/oauth2/token"))
        .respond_with(move |req: &Request| {
            captured_for.lock().unwrap().push(parse_form(&req.body));
            ResponseTemplate::new(200).set_body_json(oidc_support::token_response(json!({})))
        })
        .mount(&mock_server)
        .await;

    let client = oidc_support::build_client(&mock_server.uri(), true);
    client
        .oidc_refresh(OidcRefreshParams {
            refresh_token: Sensitive::new("r".into()),
            scope: None,
            tenant_id: None,
            configuration: None,
        })
        .await
        .expect("refresh succeeds");

    assert!(!captured.lock().unwrap()[0].contains_key("scope"));
}

#[tokio::test]
async fn oidc_refresh_maps_400_invalid_grant_without_a_retry_loop() {
    let mock_server = MockServer::start().await;
    mount_discovery(&mock_server).await;
    let call_count = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&call_count);
    Mock::given(method("POST"))
        .and(path("/oauth2/token"))
        .respond_with(move |_req: &Request| {
            counter.fetch_add(1, Ordering::SeqCst);
            ResponseTemplate::new(400).set_body_json(
                json!({ "error": "invalid_grant", "error_description": "refresh token revoked" }),
            )
        })
        .mount(&mock_server)
        .await;

    let client = oidc_support::build_client(&mock_server.uri(), true);
    let err = client
        .oidc_refresh(OidcRefreshParams {
            refresh_token: Sensitive::new("r".into()),
            scope: None,
            tenant_id: None,
            configuration: None,
        })
        .await
        .expect_err("must fail");

    let oauth = err.as_oauth_protocol_error().expect("OAuthProtocolError");
    assert_eq!(oauth.error, "invalid_grant");
    assert_eq!(call_count.load(Ordering::SeqCst), 1, "no silent retry");
}

// ---------------------------------------------------------------------------
// oidc_refresh — CONTRACT.md §9 single-flight (rules 1, 2, 4; §9's test
// requirement, which contract 1.5 clarifies applies *per refresh operation*,
// so `oidc_refresh` needs its own burst test alongside the §1 `refresh` one
// in `tests/single_flight_refresh_test.rs`)
// ---------------------------------------------------------------------------

/// Number of concurrent callers in the §9 burst tests. §9's test requirement
/// is N ≥ 5.
const BURST: usize = 5;

fn configuration_for(base_url: &str) -> OidcConfiguration {
    serde_json::from_value(oidc_support::discovery_document(base_url))
        .expect("valid discovery document")
}

/// §9 rules 1 + 2: a burst of five concurrent `oidc_refresh` callers must
/// produce **exactly one** `POST /oauth2/token`, and all five must receive
/// that one call's token set.
///
/// This is the rule's whole point: AXIAM refresh tokens are single-use with
/// rotation, so five independent wire calls would mean four replays of an
/// already-consumed token, each failing `invalid_grant`. The mock therefore
/// also asserts the negative directly — it answers `invalid_grant` to every
/// request after the first, so a non-coalescing implementation cannot pass by
/// accident.
#[tokio::test]
async fn oidc_refresh_burst_of_five_makes_exactly_one_wire_call_and_shares_the_token_set() {
    let mock_server = MockServer::start().await;
    let call_count = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&call_count);
    Mock::given(method("POST"))
        .and(path("/oauth2/token"))
        .respond_with(move |_req: &Request| {
            let nth = counter.fetch_add(1, Ordering::SeqCst);
            if nth == 0 {
                ResponseTemplate::new(200)
                    .set_body_json(oidc_support::token_response(json!({
                        "access_token": "leader-access-token",
                        "refresh_token": "leader-rotated-refresh",
                    })))
                    // Hold the leader in flight long enough for the other
                    // four callers to reach the guard and become waiters.
                    .set_delay(Duration::from_millis(150))
            } else {
                // The single-use token was already consumed by call #1.
                ResponseTemplate::new(400).set_body_json(json!({
                    "error": "invalid_grant",
                    "error_description": "refresh token already used",
                }))
            }
        })
        .mount(&mock_server)
        .await;

    let client = oidc_support::build_client(&mock_server.uri(), true);
    let configuration = configuration_for(&mock_server.uri());

    let mut handles = Vec::with_capacity(BURST);
    for _ in 0..BURST {
        let client = client.clone();
        let configuration = configuration.clone();
        handles.push(tokio::spawn(async move {
            client
                .oidc_refresh(OidcRefreshParams {
                    refresh_token: Sensitive::new("single-use-refresh".into()),
                    scope: None,
                    tenant_id: None,
                    configuration: Some(configuration),
                })
                .await
        }));
    }

    let mut outcomes = Vec::with_capacity(BURST);
    for handle in handles {
        outcomes.push(handle.await.expect("task must not panic"));
    }

    assert_eq!(
        call_count.load(Ordering::SeqCst),
        1,
        "CONTRACT.md §9 rules 1+2: a burst of {BURST} concurrent oidc_refresh callers must produce EXACTLY ONE POST /oauth2/token"
    );

    assert_eq!(outcomes.len(), BURST);
    for outcome in &outcomes {
        let tokens = outcome
            .as_ref()
            .expect("every caller in the burst receives the leader's success (§9 rule 2)");
        assert_eq!(
            tokens.access_token.expose(),
            "leader-access-token",
            "every caller must receive THAT ONE call's outcome (§9 rule 2)"
        );
        assert_eq!(
            tokens
                .refresh_token
                .as_ref()
                .map(|r| r.expose().as_str())
                .expect("rotated refresh token"),
            "leader-rotated-refresh"
        );
        // §7: shared or not, the token set still redacts.
        assert!(!format!("{tokens:?}").contains("leader-access-token"));
    }
}

/// §9 rule 2, failure half: when the single in-flight refresh fails, **all**
/// waiters observe a failure carrying the same taxonomy variant and the same
/// RFC 6749 `error` code — and still only one wire call is made (rule 3: no
/// retry loop, not even a per-waiter one).
#[tokio::test]
async fn oidc_refresh_burst_shares_the_leaders_failure_with_every_waiter() {
    let mock_server = MockServer::start().await;
    let call_count = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&call_count);
    Mock::given(method("POST"))
        .and(path("/oauth2/token"))
        .respond_with(move |_req: &Request| {
            counter.fetch_add(1, Ordering::SeqCst);
            ResponseTemplate::new(400)
                .set_body_json(json!({
                    "error": "invalid_grant",
                    "error_description": "refresh token revoked",
                }))
                .set_delay(Duration::from_millis(150))
        })
        .mount(&mock_server)
        .await;

    let client = oidc_support::build_client(&mock_server.uri(), true);
    let configuration = configuration_for(&mock_server.uri());

    let mut handles = Vec::with_capacity(BURST);
    for _ in 0..BURST {
        let client = client.clone();
        let configuration = configuration.clone();
        handles.push(tokio::spawn(async move {
            client
                .oidc_refresh(OidcRefreshParams {
                    refresh_token: Sensitive::new("revoked-refresh".into()),
                    scope: None,
                    tenant_id: None,
                    configuration: Some(configuration),
                })
                .await
        }));
    }

    let mut errors = Vec::with_capacity(BURST);
    for handle in handles {
        errors.push(
            handle
                .await
                .expect("task must not panic")
                .expect_err("the leader failed, so every caller must fail"),
        );
    }

    assert_eq!(
        call_count.load(Ordering::SeqCst),
        1,
        "a failing leader must still mean exactly one wire call for the whole burst (§9 rules 1-3)"
    );
    assert_eq!(errors.len(), BURST);
    for err in &errors {
        assert!(
            matches!(err, AxiamError::Auth { .. }),
            "waiters keep the leader's taxonomy variant: {err:?}"
        );
        let oauth = err
            .as_oauth_protocol_error()
            .expect("waiters keep the leader's OAuthProtocolError payload");
        assert_eq!(oauth.error, "invalid_grant");
        assert_eq!(oauth.error_description, "refresh token revoked");
        assert_eq!(
            err.to_string(),
            "authentication failed: invalid_grant: refresh token revoked"
        );
    }
}

/// Coalescing is per *burst*, not for the client's lifetime: once the
/// in-flight refresh resolves, the slot is retired and the next caller
/// performs a genuine new wire call.
#[tokio::test]
async fn oidc_refresh_coalesces_per_burst_and_not_across_sequential_calls() {
    let mock_server = MockServer::start().await;
    let call_count = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&call_count);
    Mock::given(method("POST"))
        .and(path("/oauth2/token"))
        .respond_with(move |_req: &Request| {
            let nth = counter.fetch_add(1, Ordering::SeqCst);
            ResponseTemplate::new(200).set_body_json(oidc_support::token_response(json!({
                "access_token": format!("access-{nth}"),
            })))
        })
        .mount(&mock_server)
        .await;

    let client = oidc_support::build_client(&mock_server.uri(), true);
    let configuration = configuration_for(&mock_server.uri());

    for expected in 0..3 {
        let tokens = client
            .oidc_refresh(OidcRefreshParams {
                refresh_token: Sensitive::new("r".into()),
                scope: None,
                tenant_id: None,
                configuration: Some(configuration.clone()),
            })
            .await
            .expect("sequential refresh succeeds");
        assert_eq!(tokens.access_token.expose(), &format!("access-{expected}"));
    }
    assert_eq!(call_count.load(Ordering::SeqCst), 3);
}

/// Cancel safety: if the elected leader's future is dropped before it can
/// publish (a `tokio::time::timeout`, a cancelled `select!` branch), the guard
/// must not wedge. Waiters are woken with an error rather than hanging
/// forever, and — critically — the slot is released so the *next* caller
/// performs a real refresh instead of subscribing to a dead channel.
#[tokio::test]
async fn a_cancelled_leader_does_not_wedge_the_guard_for_later_callers() {
    let mock_server = MockServer::start().await;
    let call_count = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&call_count);
    Mock::given(method("POST"))
        .and(path("/oauth2/token"))
        .respond_with(move |_req: &Request| {
            let nth = counter.fetch_add(1, Ordering::SeqCst);
            ResponseTemplate::new(200)
                .set_body_json(oidc_support::token_response(json!({
                    "access_token": format!("access-{nth}"),
                })))
                // Long enough that the leader below is always cancelled first.
                .set_delay(Duration::from_secs(30))
        })
        .mount(&mock_server)
        .await;

    let client = oidc_support::build_client(&mock_server.uri(), true);
    let configuration = configuration_for(&mock_server.uri());

    let leader_client = client.clone();
    let leader_configuration = configuration.clone();
    let leader = tokio::spawn(async move {
        tokio::time::timeout(
            Duration::from_millis(150),
            leader_client.oidc_refresh(OidcRefreshParams {
                refresh_token: Sensitive::new("r".into()),
                scope: None,
                tenant_id: None,
                configuration: Some(leader_configuration),
            }),
        )
        .await
    });

    // Join the leader's burst as a waiter while it is still in flight.
    tokio::time::sleep(Duration::from_millis(40)).await;
    let waiter_client = client.clone();
    let waiter_configuration = configuration.clone();
    let waiter = tokio::spawn(async move {
        waiter_client
            .oidc_refresh(OidcRefreshParams {
                refresh_token: Sensitive::new("r".into()),
                scope: None,
                tenant_id: None,
                configuration: Some(waiter_configuration),
            })
            .await
    });

    assert!(
        leader.await.expect("no panic").is_err(),
        "the leader must have been cancelled by the timeout"
    );
    let waiter_result = waiter.await.expect("no panic");
    let err = waiter_result.expect_err("a waiter whose leader vanished cannot succeed");
    assert!(matches!(err, AxiamError::Auth { .. }), "{err:?}");
    assert!(
        err.to_string().contains("cancelled before completing"),
        "the waiter must be told why, not hang: {err}"
    );

    // The slot is free again: this third caller becomes a leader and issues a
    // genuinely new wire call (which we cancel too, to keep the test quick).
    let third = tokio::time::timeout(
        Duration::from_millis(150),
        client.oidc_refresh(OidcRefreshParams {
            refresh_token: Sensitive::new("r".into()),
            scope: None,
            tenant_id: None,
            configuration: Some(configuration),
        }),
    )
    .await;
    assert!(third.is_err(), "third call timed out on its own wire call");
    assert_eq!(
        call_count.load(Ordering::SeqCst),
        2,
        "the cancelled leader made call 1; the third caller made call 2; the waiter made none"
    );
}

// ---------------------------------------------------------------------------
// login_client_credentials
// ---------------------------------------------------------------------------

#[tokio::test]
async fn login_client_credentials_posts_only_the_documented_fields() {
    let mock_server = MockServer::start().await;
    mount_discovery(&mock_server).await;
    let captured: Arc<std::sync::Mutex<Vec<HashMap<String, String>>>> =
        Arc::new(std::sync::Mutex::new(Vec::new()));
    let captured_for = Arc::clone(&captured);
    Mock::given(method("POST"))
        .and(path("/oauth2/token"))
        .respond_with(move |req: &Request| {
            captured_for.lock().unwrap().push(parse_form(&req.body));
            ResponseTemplate::new(200).set_body_json(oidc_support::token_response(
                json!({ "scope": "authz:check" }),
            ))
        })
        .mount(&mock_server)
        .await;

    let client = oidc_support::build_client(&mock_server.uri(), true);
    let tokens = client
        .login_client_credentials(LoginClientCredentialsParams {
            scope: Some("authz:check".into()),
            tenant_id: None,
            configuration: None,
        })
        .await
        .expect("login_client_credentials succeeds");

    let form = captured.lock().unwrap().remove(0);
    assert_eq!(form.get("grant_type").unwrap(), "client_credentials");
    let mut keys: Vec<&str> = form.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        vec!["client_id", "client_secret", "grant_type", "scope"]
    );
    assert_eq!(tokens.access_token.expose(), "access-token-value");
    assert!(tokens.id_token.is_none());
    assert!(tokens.id_claims.is_none());
}

#[tokio::test]
async fn login_client_credentials_requires_a_client_secret() {
    let mock_server = MockServer::start().await;
    mount_discovery(&mock_server).await;
    let client = oidc_support::build_client(&mock_server.uri(), false);

    let err = client
        .login_client_credentials(LoginClientCredentialsParams::default())
        .await
        .expect_err("public client cannot use client_credentials");
    assert!(matches!(err, AxiamError::Auth { .. }));
    assert!(err.to_string().contains("confidential-client credentials"));
}

// ---------------------------------------------------------------------------
// introspect
// ---------------------------------------------------------------------------

#[tokio::test]
async fn introspect_posts_a_form_body_and_maps_the_response() {
    let mock_server = MockServer::start().await;
    mount_discovery(&mock_server).await;
    Mock::given(method("POST"))
        .and(path("/oauth2/introspect"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "active": true,
            "sub": "user-9",
            "client_id": oidc_support::CLIENT_ID,
            "scope": "openid profile",
            "token_type": "Bearer",
            "exp": 1_800_000_900i64,
            "iat": 1_800_000_000i64,
        })))
        .mount(&mock_server)
        .await;

    let client = oidc_support::build_client(&mock_server.uri(), true);
    let result = client
        .introspect(IntrospectParams {
            token: Sensitive::new("token-to-check".into()),
            token_type_hint: Some("access_token".into()),
            tenant_id: None,
            configuration: None,
        })
        .await
        .expect("introspect succeeds");

    assert!(result.active);
    assert_eq!(result.sub.as_deref(), Some("user-9"));
    assert_eq!(result.scope.as_deref(), Some("openid profile"));
}

#[tokio::test]
async fn introspect_401_becomes_oauth_protocol_error_and_does_not_trigger_the_refresh_guard() {
    let mock_server = MockServer::start().await;
    mount_discovery(&mock_server).await;
    let refresh_calls = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&refresh_calls);
    Mock::given(method("POST"))
        .and(path("/api/v1/auth/refresh"))
        .respond_with(move |_req: &Request| {
            counter.fetch_add(1, Ordering::SeqCst);
            ResponseTemplate::new(200).set_body_json(json!({ "expires_in": 900 }))
        })
        .mount(&mock_server)
        .await;
    Mock::given(method("POST"))
        .and(path("/oauth2/introspect"))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({
            "error": "invalid_client",
            "error_description": "client authentication failed",
        })))
        .mount(&mock_server)
        .await;

    let client = oidc_support::build_client(&mock_server.uri(), true);
    let err = client
        .introspect(IntrospectParams {
            token: Sensitive::new("t".into()),
            token_type_hint: None,
            tenant_id: None,
            configuration: None,
        })
        .await
        .expect_err("401 must fail");

    let oauth = err.as_oauth_protocol_error().expect("OAuthProtocolError");
    assert_eq!(oauth.error, "invalid_client");
    // §12.3 rule 3: a client-credential failure is not a session expiry —
    // this method never even calls into the §9 guard machinery.
    assert_eq!(refresh_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn introspect_requires_a_client_secret() {
    let mock_server = MockServer::start().await;
    mount_discovery(&mock_server).await;
    let client = oidc_support::build_client(&mock_server.uri(), false);
    let err = client
        .introspect(IntrospectParams {
            token: Sensitive::new("t".into()),
            token_type_hint: None,
            tenant_id: None,
            configuration: None,
        })
        .await
        .expect_err("public client cannot introspect");
    assert!(err.to_string().contains("confidential-client credentials"));
}

// ---------------------------------------------------------------------------
// revoke
// ---------------------------------------------------------------------------

#[tokio::test]
async fn revoke_is_idempotent_for_an_unknown_token() {
    let mock_server = MockServer::start().await;
    mount_discovery(&mock_server).await;
    // RFC 7009: the server answers 200 for tokens it has never seen.
    Mock::given(method("POST"))
        .and(path("/oauth2/revoke"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&mock_server)
        .await;

    let client = oidc_support::build_client(&mock_server.uri(), true);
    for _ in 0..3 {
        client
            .revoke(RevokeParams {
                token: Sensitive::new("never-existed".into()),
                token_type_hint: None,
                tenant_id: None,
                configuration: None,
            })
            .await
            .expect("revoke of an unknown token is success (idempotent)");
    }
}

#[tokio::test]
async fn revoke_surfaces_a_401_as_oauth_protocol_error() {
    let mock_server = MockServer::start().await;
    mount_discovery(&mock_server).await;
    Mock::given(method("POST"))
        .and(path("/oauth2/revoke"))
        .respond_with(
            ResponseTemplate::new(401).set_body_json(
                json!({ "error": "invalid_client", "error_description": "bad secret" }),
            ),
        )
        .mount(&mock_server)
        .await;

    let client = oidc_support::build_client(&mock_server.uri(), true);
    let err = client
        .revoke(RevokeParams {
            token: Sensitive::new("t".into()),
            token_type_hint: None,
            tenant_id: None,
            configuration: None,
        })
        .await
        .expect_err("must fail");
    assert!(err.as_oauth_protocol_error().is_some());
}

#[tokio::test]
async fn revoke_surfaces_a_transport_failure_as_network_error() {
    let mock_server = MockServer::start().await;
    mount_discovery(&mock_server).await;
    Mock::given(method("POST"))
        .and(path("/oauth2/revoke"))
        .respond_with(ResponseTemplate::new(500).set_body_json(json!({ "oops": true })))
        .mount(&mock_server)
        .await;

    let client = oidc_support::build_client(&mock_server.uri(), true);
    let err = client
        .revoke(RevokeParams {
            token: Sensitive::new("t".into()),
            token_type_hint: None,
            tenant_id: None,
            configuration: None,
        })
        .await
        .expect_err("must fail");
    assert!(matches!(err, AxiamError::Network { .. }));
}

#[tokio::test]
async fn revoke_requires_a_client_secret() {
    let mock_server = MockServer::start().await;
    mount_discovery(&mock_server).await;
    let client = oidc_support::build_client(&mock_server.uri(), false);
    let err = client
        .revoke(RevokeParams {
            token: Sensitive::new("t".into()),
            token_type_hint: None,
            tenant_id: None,
            configuration: None,
        })
        .await
        .expect_err("public client cannot revoke");
    assert!(err.to_string().contains("confidential-client credentials"));
}
