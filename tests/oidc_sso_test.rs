//! `sso_start` / `sso_complete` (CONTRACT.md §12.1) — the federation SSO
//! pair against an upstream IdP.

#![cfg(feature = "rest")]

#[path = "oidc_support/mod.rs"]
mod oidc_support;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use axiam_sdk::AxiamError;
use axiam_sdk::client::AxiamClient;
use axiam_sdk::oidc::{SsoCompleteParams, SsoStartParams};
use serde_json::json;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

/// Mount `/oauth2/jwks` publishing the key that signs this file's session
/// access tokens — `sso_complete`'s post-login sync verifies the
/// `axiam_access` cookie through the same JWKS verifier `login()` uses.
async fn mount_session_jwks(mock_server: &MockServer) -> oidc_support::SigningKeyFixture {
    let key = oidc_support::generate_signing_key("sso-session-key");
    Mock::given(method("GET"))
        .and(path("/oauth2/jwks"))
        .respond_with(ResponseTemplate::new(200).set_body_json(oidc_support::jwks_body(&[&key])))
        .mount(mock_server)
        .await;
    key
}

/// A `200` from the federation callback, delivering the session as
/// `Set-Cookie` exactly as `POST /api/v1/auth/login` does (§12.1 note 6, §4).
fn callback_response(
    user_id: uuid::Uuid,
    session_id: uuid::Uuid,
    access_token: &str,
) -> ResponseTemplate {
    let mut response = ResponseTemplate::new(200).set_body_json(json!({
        "user_id": user_id,
        "session_id": session_id,
        "expires_in": 900,
        "redirect_uri": "https://app.example.com/post-login",
    }));
    for cookie in
        oidc_support::session_cookie_headers(access_token, "sso-refresh-token", "sso-csrf-value")
    {
        response = response.append_header("Set-Cookie", cookie.as_str());
    }
    response
}

#[tokio::test]
async fn sso_start_posts_json_with_tenant_and_org_context() {
    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/auth/federation/oidc/start"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "authorize_url": "https://upstream-idp.example.com/authorize?...",
            "state": "federation-state-value",
            "expires_in_secs": 600,
        })))
        .mount(&mock_server)
        .await;

    let client = oidc_support::build_client(&mock_server.uri(), true);
    let result = client
        .sso_start(SsoStartParams {
            federation_config_id: "11111111-1111-1111-1111-111111111111".to_string(),
            redirect_uri: "https://app.example.com/post-login".to_string(),
            ..Default::default()
        })
        .await
        .expect("sso_start succeeds using the client's own tenant/org context");

    assert_eq!(result.state, "federation-state-value");
    assert_eq!(result.expires_in_secs, 600);
    assert!(
        result
            .authorize_url
            .starts_with("https://upstream-idp.example.com")
    );
}

#[tokio::test]
async fn sso_start_requires_organization_context_client_side() {
    let mock_server = MockServer::start().await;
    // No mock mounted for /start: a wire call here would fail the test.
    let client = AxiamClient::builder()
        .base_url(mock_server.uri())
        .expect("valid base url")
        .tenant_slug("acme")
        .oidc_client_id(oidc_support::CLIENT_ID)
        .build()
        .expect("client builds without org context");

    let err = client
        .sso_start(SsoStartParams {
            federation_config_id: "cfg".to_string(),
            redirect_uri: "https://app.example.com/cb".to_string(),
            ..Default::default()
        })
        .await
        .expect_err("sso_start must fail client-side with no org context");
    assert!(matches!(err, AxiamError::Auth { .. }));
    assert!(err.to_string().contains("organization context"));
}

#[tokio::test]
async fn sso_complete_returns_the_success_body_with_no_token_material() {
    let mock_server = MockServer::start().await;
    let key = mount_session_jwks(&mock_server).await;
    let user_id = uuid::Uuid::new_v4();
    let session_id = uuid::Uuid::new_v4();
    let access_token = oidc_support::sign_session_access_token(
        &key,
        oidc_support::tenant_id(),
        oidc_support::org_id(),
        session_id,
    );
    Mock::given(method("POST"))
        .and(path("/api/v1/auth/federation/oidc/callback"))
        .respond_with(callback_response(user_id, session_id, &access_token))
        .mount(&mock_server)
        .await;

    let client = oidc_support::build_client(&mock_server.uri(), true);
    let result = client
        .sso_complete(SsoCompleteParams {
            state: "federation-state-value".to_string(),
            code: "upstream-authorization-code".to_string(),
        })
        .await
        .expect("sso_complete succeeds");

    assert_eq!(result.user_id, user_id);
    assert_eq!(result.session_id, session_id);
    assert_eq!(result.expires_in, 900);
    assert_eq!(result.redirect_uri, "https://app.example.com/post-login");
    // §12.1 note 6: SsoLoginSuccessResponse carries no token material — the
    // session is in the cookie jar, never in this struct.
    assert!(!format!("{result:?}").contains(&access_token));
}

/// F-05 / addendum judgment call 16: `sso_complete` must leave the client in
/// the **same authenticated state** `login()` does — token manager seeded from
/// the jar, `tenant_id`/`org_id` resolved from the verified access token, CSRF
/// cached for §3 forwarding.
///
/// Asserted through observable behaviour, since the resolved ids are
/// crate-internal: `refresh()` refuses to run without *both* a cached access
/// token and a resolved `org_id` (`src/rest/auth.rs`), and the refresh request
/// it sends carries the resolved `tenant_id`/`org_id` in its body and the
/// captured CSRF token in its header. A `sso_complete` that skipped the sync
/// fails this test with "no access token to refresh".
#[tokio::test]
async fn sso_complete_leaves_the_client_authenticated_exactly_as_login_does() {
    let mock_server = MockServer::start().await;
    let key = mount_session_jwks(&mock_server).await;
    let session_id = uuid::Uuid::new_v4();
    let access_token = oidc_support::sign_session_access_token(
        &key,
        oidc_support::tenant_id(),
        oidc_support::org_id(),
        session_id,
    );
    Mock::given(method("POST"))
        .and(path("/api/v1/auth/federation/oidc/callback"))
        .respond_with(callback_response(
            uuid::Uuid::new_v4(),
            session_id,
            &access_token,
        ))
        .mount(&mock_server)
        .await;

    // The follow-on §1 refresh: capture what the client sends, and rotate the
    // session cookies the way the server does.
    let rotated = oidc_support::sign_session_access_token(
        &key,
        oidc_support::tenant_id(),
        oidc_support::org_id(),
        session_id,
    );
    let refresh_bodies: Arc<std::sync::Mutex<Vec<serde_json::Value>>> =
        Arc::new(std::sync::Mutex::new(Vec::new()));
    let refresh_csrf: Arc<std::sync::Mutex<Vec<String>>> =
        Arc::new(std::sync::Mutex::new(Vec::new()));
    let bodies_for = Arc::clone(&refresh_bodies);
    let csrf_for = Arc::clone(&refresh_csrf);
    Mock::given(method("POST"))
        .and(path("/api/v1/auth/refresh"))
        .respond_with(move |req: &Request| {
            bodies_for
                .lock()
                .unwrap()
                .push(serde_json::from_slice(&req.body).unwrap_or(json!(null)));
            if let Some(value) = req.headers.get("X-CSRF-Token") {
                csrf_for
                    .lock()
                    .unwrap()
                    .push(value.to_str().unwrap_or_default().to_string());
            }
            let mut response =
                ResponseTemplate::new(200).set_body_json(json!({ "expires_in": 900 }));
            for cookie in oidc_support::session_cookie_headers(
                &rotated,
                "rotated-refresh-token",
                "rotated-csrf",
            ) {
                response = response.append_header("Set-Cookie", cookie.as_str());
            }
            response
        })
        .mount(&mock_server)
        .await;

    let client = oidc_support::build_client(&mock_server.uri(), true);
    client
        .sso_complete(SsoCompleteParams {
            state: "federation-state-value".to_string(),
            code: "upstream-authorization-code".to_string(),
        })
        .await
        .expect("sso_complete succeeds");

    // The whole point: this works only because sso_complete ran the sync.
    client
        .refresh()
        .await
        .expect("refresh() must work after sso_complete, exactly as after login()");

    let bodies = refresh_bodies.lock().unwrap().clone();
    let csrf_headers = refresh_csrf.lock().unwrap().clone();
    assert_eq!(bodies.len(), 1, "one refresh call");
    assert_eq!(
        bodies[0]["tenant_id"].as_str(),
        Some(oidc_support::tenant_id().to_string().as_str()),
        "tenant_id must have been resolved from the verified access token"
    );
    assert_eq!(
        bodies[0]["org_id"].as_str(),
        Some(oidc_support::org_id().to_string().as_str()),
        "org_id must have been resolved from the verified access token"
    );
    assert_eq!(
        csrf_headers.as_slice(),
        ["sso-csrf-value"],
        "the axiam_csrf cookie set by sso_complete must be forwarded per §3"
    );

    // And the session is fully live: logout keys off the same absorbed token.
    Mock::given(method("POST"))
        .and(path("/api/v1/auth/logout"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&mock_server)
        .await;
    client
        .logout()
        .await
        .expect("logout() must work after sso_complete too");
}

/// The sync is not best-effort: a callback that sets no usable `axiam_access`
/// cookie is not a successful login, and `sso_complete` says so rather than
/// silently returning a result the client cannot act on. Same behaviour as
/// `login()`, and the same as the Go/Python/TypeScript siblings.
#[tokio::test]
async fn sso_complete_fails_when_the_response_sets_no_usable_session_cookie() {
    let mock_server = MockServer::start().await;
    mount_session_jwks(&mock_server).await;
    let calls = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&calls);
    Mock::given(method("POST"))
        .and(path("/api/v1/auth/federation/oidc/callback"))
        .respond_with(move |_req: &Request| {
            counter.fetch_add(1, Ordering::SeqCst);
            // 200 body, but no Set-Cookie at all.
            ResponseTemplate::new(200).set_body_json(json!({
                "user_id": uuid::Uuid::new_v4(),
                "session_id": uuid::Uuid::new_v4(),
                "expires_in": 900,
                "redirect_uri": "https://app.example.com/post-login",
            }))
        })
        .mount(&mock_server)
        .await;

    let client = oidc_support::build_client(&mock_server.uri(), true);
    let err = client
        .sso_complete(SsoCompleteParams {
            state: "s".to_string(),
            code: "c".to_string(),
        })
        .await
        .expect_err("no session cookie means no session");
    assert!(matches!(err, AxiamError::Auth { .. }));
    assert!(err.to_string().contains("axiam_access"));
    assert_eq!(calls.load(Ordering::SeqCst), 1, "no retry");
}

#[tokio::test]
async fn sso_complete_surfaces_a_401_using_the_generic_status_mapping() {
    // Addendum item 12: the federation endpoints document no response
    // schema for their errors, so no OAuth2ErrorResponse parsing is
    // attempted here — plain §2 status mapping only.
    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/auth/federation/oidc/callback"))
        .respond_with(ResponseTemplate::new(401).set_body_string("unauthorized"))
        .mount(&mock_server)
        .await;

    let client = oidc_support::build_client(&mock_server.uri(), true);
    let err = client
        .sso_complete(SsoCompleteParams {
            state: "s".to_string(),
            code: "c".to_string(),
        })
        .await
        .expect_err("must fail");
    assert!(matches!(err, AxiamError::Auth { .. }));
    assert!(err.as_oauth_protocol_error().is_none());
}
