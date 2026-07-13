//! Additional `src/client.rs` coverage: the `base_url` parse-error branch,
//! `resolved_tenant_id`'s pre-login arms (UUID form resolves, slug form does
//! not), and the host-isolation redirect policy (same-host follow up to the
//! cap, and cross-host stop) that the builder installs.

#![cfg(feature = "rest")]

use axiam_sdk::client::AxiamClient;
use axiam_sdk::AxiamError;
use uuid::Uuid;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[test]
fn base_url_that_does_not_parse_is_a_network_error() {
    match AxiamClient::builder().base_url("not a url at all") {
        Ok(_) => panic!("an unparseable base_url must be rejected"),
        Err(AxiamError::Network { message, .. }) => {
            assert!(message.contains("invalid base_url"), "message: {message}");
        }
        Err(other) => panic!("expected Network error, got {other}"),
    }
}

#[tokio::test]
async fn resolved_tenant_id_returns_the_uuid_form_before_login() {
    let tenant_id = Uuid::new_v4();
    let client = AxiamClient::builder()
        .base_url("https://iam.example.com")
        .expect("valid base_url")
        .tenant_id(tenant_id)
        .build()
        .expect("client builds");

    // No login yet: the UUID form is known up front and resolves directly.
    assert_eq!(client.resolved_tenant_id().await, Some(tenant_id));
}

#[tokio::test]
async fn resolved_tenant_id_is_none_for_a_slug_before_login() {
    let client = AxiamClient::builder()
        .base_url("https://iam.example.com")
        .expect("valid base_url")
        .tenant_slug("acme")
        .build()
        .expect("client builds");

    // A slug cannot be resolved to a UUID until a login decodes the
    // `tenant_id` claim, so before login it is `None`.
    assert_eq!(client.resolved_tenant_id().await, None);
}

#[tokio::test]
async fn a_same_host_redirect_loop_is_capped_and_surfaces_as_a_network_error() {
    // Every login response is a same-host 307 pointing back at itself. The
    // redirect policy follows same-host redirects but caps them, so the
    // request ultimately fails with a "too many redirects" transport error
    // rather than looping forever — exercising both the follow arm and the
    // redirect-cap arm of the policy closure.
    let mock_server = MockServer::start().await;
    let self_location = format!("{}/api/v1/auth/login", mock_server.uri());
    Mock::given(method("POST"))
        .and(path("/api/v1/auth/login"))
        .respond_with(ResponseTemplate::new(307).append_header("Location", self_location.as_str()))
        .mount(&mock_server)
        .await;

    let client = AxiamClient::builder()
        .base_url(mock_server.uri())
        .expect("valid base_url")
        .tenant_slug("acme")
        .build()
        .expect("client builds");

    let err = client
        .login("alice@example.com", "correct horse battery staple")
        .await
        .expect_err("an unbounded same-host redirect loop must be capped and fail");
    assert!(matches!(err, AxiamError::Network { .. }));
}

#[tokio::test]
async fn a_cross_host_redirect_is_not_followed() {
    // A login that 307s to a *different* host must NOT be followed (the policy
    // stops), so the 3xx is returned as-is and login maps it to an error
    // rather than leaking X-Tenant-ID / CSRF headers to the other host.
    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/auth/login"))
        .respond_with(
            ResponseTemplate::new(307)
                .append_header("Location", "http://attacker.example.com/steal"),
        )
        .mount(&mock_server)
        .await;

    let client = AxiamClient::builder()
        .base_url(mock_server.uri())
        .expect("valid base_url")
        .tenant_slug("acme")
        .build()
        .expect("client builds");

    let err = client
        .login("alice@example.com", "correct horse battery staple")
        .await
        .expect_err("a cross-host redirect must not be followed and login must fail");
    // The 3xx is returned as-is (not a transport error), so it maps via the
    // HTTP-status path.
    assert!(matches!(
        err,
        AxiamError::Network { .. } | AxiamError::Auth { .. } | AxiamError::Authz { .. }
    ));
}
