//! `sso_start` / `sso_complete` (CONTRACT.md §12.1) — the federation SSO
//! pair against an upstream IdP.

#![cfg(feature = "rest")]

#[path = "oidc_support/mod.rs"]
mod oidc_support;

use axiam_sdk::AxiamError;
use axiam_sdk::client::AxiamClient;
use axiam_sdk::oidc::{SsoCompleteParams, SsoStartParams};
use serde_json::json;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

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
    let user_id = uuid::Uuid::new_v4();
    let session_id = uuid::Uuid::new_v4();
    Mock::given(method("POST"))
        .and(path("/api/v1/auth/federation/oidc/callback"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({
                    "user_id": user_id,
                    "session_id": session_id,
                    "expires_in": 900,
                    "redirect_uri": "https://app.example.com/post-login",
                }))
                .append_header(
                    "Set-Cookie",
                    "axiam_access=opaque-session-cookie; Path=/; HttpOnly",
                )
                .append_header("Set-Cookie", "axiam_csrf=csrf-value; Path=/"),
        )
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
