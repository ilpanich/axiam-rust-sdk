//! `oidc_refresh`, `login_client_credentials`, `introspect`, `revoke`
//! (CONTRACT.md §12.1, §12.3 rules 3–4, §9).

#![cfg(feature = "rest")]

#[path = "oidc_support/mod.rs"]
mod oidc_support;

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use axiam_sdk::AxiamError;
use axiam_sdk::Sensitive;
use axiam_sdk::oidc::{
    IntrospectParams, LoginClientCredentialsParams, OidcRefreshParams, RevokeParams,
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
