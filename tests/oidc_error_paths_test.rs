//! Error and edge arms of the CONTRACT.md §12 operations that the
//! happy-path suites in `tests/oidc_*_test.rs` never reach: malformed
//! response bodies on all four parse sites, transport failures, an
//! unparseable endpoint URL from the discovery document, the missing-
//! `client_id` fail-fast, the pre-fetched-`configuration` arm of each
//! operation, and `sso_start`'s tenant/org resolution matrix.
//!
//! These are the "~15 untested error arms" the cross-SDK conformance review
//! called out in `src/oidc/exchange.rs` (F-10).

#![cfg(feature = "rest")]

#[path = "oidc_support/mod.rs"]
mod oidc_support;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use axiam_sdk::AxiamError;
use axiam_sdk::Sensitive;
use axiam_sdk::client::AxiamClient;
use axiam_sdk::oidc::{
    IntrospectParams, LoginClientCredentialsParams, OidcConfiguration, OidcExchangeParams,
    OidcRefreshParams, RevokeParams, SsoStartParams,
};
use serde_json::json;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

/// A port nothing listens on — connecting to it produces a genuine
/// `reqwest::Error`, which is the only way to reach the `network_err` /
/// `AxiamError::Network { source: Some(..) }` arms.
const DEAD_ENDPOINT_HOST: &str = "http://127.0.0.1:1";

fn configuration_for(base_url: &str) -> OidcConfiguration {
    serde_json::from_value(oidc_support::discovery_document(base_url))
        .expect("valid discovery document")
}

/// A discovery document whose four `/oauth2/*` endpoints are replaced by
/// `replacement`, so a single fixture can drive "unparseable URL" and
/// "unreachable host" for every operation.
fn configuration_with_endpoints(base_url: &str, replacement: &str) -> OidcConfiguration {
    let mut doc = oidc_support::discovery_document(base_url);
    let map = doc.as_object_mut().expect("object");
    map.insert("token_endpoint".into(), json!(replacement));
    map.insert("introspection_endpoint".into(), json!(replacement));
    map.insert("revocation_endpoint".into(), json!(replacement));
    serde_json::from_value(doc).expect("valid discovery document")
}

fn exchange_params(configuration: OidcConfiguration) -> OidcExchangeParams {
    OidcExchangeParams {
        code: "the-code".into(),
        code_verifier: Sensitive::new("verifier".into()),
        redirect_uri: oidc_support::REDIRECT_URI.into(),
        nonce: "test-nonce".into(),
        tenant_id: None,
        configuration: Some(configuration),
    }
}

// ---------------------------------------------------------------------------
// Malformed 200 bodies — the four `failed to parse …` arms
// ---------------------------------------------------------------------------

/// `POST /oauth2/token` answers 200 with something that is not a
/// `TokenResponse`. §2: a deserialization failure is transport-level, so a
/// `NetworkError` — never a silent partial token set.
#[tokio::test]
async fn a_malformed_token_response_body_is_a_network_error() {
    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/oauth2/token"))
        .respond_with(ResponseTemplate::new(200).set_body_string("<html>not json</html>"))
        .mount(&mock_server)
        .await;
    let client = oidc_support::build_client(&mock_server.uri(), true);
    let configuration = configuration_for(&mock_server.uri());

    // All three grants share `post_token`, so all three surface it.
    let err = client
        .oidc_exchange(exchange_params(configuration.clone()))
        .await
        .expect_err("a malformed token response cannot succeed");
    assert!(matches!(err, AxiamError::Network { .. }), "{err:?}");
    assert!(err.to_string().contains("failed to parse token response"));

    let err = client
        .oidc_refresh(OidcRefreshParams {
            refresh_token: Sensitive::new("r".into()),
            scope: None,
            tenant_id: None,
            configuration: Some(configuration.clone()),
        })
        .await
        .expect_err("must fail");
    assert!(err.to_string().contains("failed to parse token response"));

    let err = client
        .login_client_credentials(LoginClientCredentialsParams {
            scope: None,
            tenant_id: None,
            configuration: Some(configuration),
        })
        .await
        .expect_err("must fail");
    assert!(err.to_string().contains("failed to parse token response"));
}

#[tokio::test]
async fn a_malformed_introspect_response_body_is_a_network_error() {
    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/oauth2/introspect"))
        .respond_with(ResponseTemplate::new(200).set_body_string("not json"))
        .mount(&mock_server)
        .await;
    let client = oidc_support::build_client(&mock_server.uri(), true);

    let err = client
        .introspect(IntrospectParams {
            token: Sensitive::new("t".into()),
            token_type_hint: None,
            tenant_id: None,
            configuration: Some(configuration_for(&mock_server.uri())),
        })
        .await
        .expect_err("must fail");
    assert!(matches!(err, AxiamError::Network { .. }), "{err:?}");
    assert!(
        err.to_string()
            .contains("failed to parse introspect response")
    );
}

#[tokio::test]
async fn a_malformed_sso_start_response_body_is_a_network_error() {
    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/auth/federation/oidc/start"))
        .respond_with(ResponseTemplate::new(200).set_body_string("not json"))
        .mount(&mock_server)
        .await;
    let client = oidc_support::build_client(&mock_server.uri(), true);

    let err = client
        .sso_start(SsoStartParams {
            federation_config_id: "cfg".into(),
            redirect_uri: "https://app.example.com/cb".into(),
            ..Default::default()
        })
        .await
        .expect_err("must fail");
    assert!(matches!(err, AxiamError::Network { .. }), "{err:?}");
    assert!(
        err.to_string()
            .contains("failed to parse sso_start response")
    );
}

#[tokio::test]
async fn a_malformed_sso_complete_response_body_is_a_network_error() {
    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/auth/federation/oidc/callback"))
        .respond_with(ResponseTemplate::new(200).set_body_string("not json"))
        .mount(&mock_server)
        .await;
    let client = oidc_support::build_client(&mock_server.uri(), true);

    let err = client
        .sso_complete(axiam_sdk::oidc::SsoCompleteParams {
            state: "s".into(),
            code: "c".into(),
        })
        .await
        .expect_err("must fail");
    assert!(matches!(err, AxiamError::Network { .. }), "{err:?}");
    assert!(
        err.to_string()
            .contains("failed to parse sso_complete response")
    );
}

// ---------------------------------------------------------------------------
// Transport failures — CONTRACT.md §2 requires the underlying error to be
// chained as the `cause`
// ---------------------------------------------------------------------------

/// A connection failure on each `/oauth2/*` call is a `NetworkError` that
/// **chains** the transport error as its `source` (§2 construction rules), and
/// leaks no token material into the message.
#[tokio::test]
async fn a_connection_failure_is_a_network_error_that_chains_its_cause() {
    let mock_server = MockServer::start().await;
    let client = oidc_support::build_client(&mock_server.uri(), true);
    let configuration = configuration_with_endpoints(
        &mock_server.uri(),
        &format!("{DEAD_ENDPOINT_HOST}/oauth2/token"),
    );

    for (label, err) in [
        (
            "token request failed",
            client
                .oidc_refresh(OidcRefreshParams {
                    refresh_token: Sensitive::new("super-secret-refresh".into()),
                    scope: None,
                    tenant_id: None,
                    configuration: Some(configuration.clone()),
                })
                .await
                .expect_err("unreachable host must fail"),
        ),
        (
            "introspect request failed",
            client
                .introspect(IntrospectParams {
                    token: Sensitive::new("super-secret-token".into()),
                    token_type_hint: None,
                    tenant_id: None,
                    configuration: Some(configuration.clone()),
                })
                .await
                .expect_err("unreachable host must fail"),
        ),
        (
            "revoke request failed",
            client
                .revoke(RevokeParams {
                    token: Sensitive::new("super-secret-token".into()),
                    token_type_hint: None,
                    tenant_id: None,
                    configuration: Some(configuration.clone()),
                })
                .await
                .expect_err("unreachable host must fail"),
        ),
    ] {
        assert!(
            matches!(err, AxiamError::Network { .. }),
            "{label}: {err:?}"
        );
        assert!(err.to_string().contains(label), "{err}");
        assert!(
            std::error::Error::source(&err).is_some(),
            "{label}: §2 requires the transport error to be chained"
        );
        assert!(!err.to_string().contains("super-secret"), "{err}");
    }
}

/// The federation pair uses the client's own base URL, so its transport arms
/// are reached with a client pointed at a dead port instead.
#[tokio::test]
async fn a_connection_failure_on_the_federation_pair_is_a_network_error() {
    let client = AxiamClient::builder()
        .base_url(DEAD_ENDPOINT_HOST)
        .expect("loopback base url")
        .tenant_id(oidc_support::tenant_id())
        .org_id(oidc_support::org_id())
        .oidc_client_id(oidc_support::CLIENT_ID)
        .build()
        .expect("client builds");

    let err = client
        .sso_start(SsoStartParams {
            federation_config_id: "cfg".into(),
            redirect_uri: "https://app.example.com/cb".into(),
            ..Default::default()
        })
        .await
        .expect_err("unreachable host must fail");
    assert!(
        err.to_string().contains("sso_start request failed"),
        "{err}"
    );

    let err = client
        .sso_complete(axiam_sdk::oidc::SsoCompleteParams {
            state: "s".into(),
            code: "c".into(),
        })
        .await
        .expect_err("unreachable host must fail");
    assert!(
        err.to_string().contains("sso_complete request failed"),
        "{err}"
    );
}

// ---------------------------------------------------------------------------
// Client-side fail-fast arms — no wire call at all
// ---------------------------------------------------------------------------

/// §12.1: with no configured `client_id` every token-endpoint operation fails
/// fast, client-side, with **no** wire call.
#[tokio::test]
async fn a_missing_client_id_fails_fast_with_no_wire_call() {
    let mock_server = MockServer::start().await;
    let calls = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&calls);
    Mock::given(method("POST"))
        .and(path("/oauth2/token"))
        .respond_with(move |_req: &Request| {
            counter.fetch_add(1, Ordering::SeqCst);
            ResponseTemplate::new(200).set_body_json(oidc_support::token_response(json!({})))
        })
        .mount(&mock_server)
        .await;

    let client = AxiamClient::builder()
        .base_url(mock_server.uri())
        .expect("valid base url")
        .tenant_id(oidc_support::tenant_id())
        .build()
        .expect("a client with no oidc_client_id still builds");
    let configuration = configuration_for(&mock_server.uri());

    let err = client
        .oidc_refresh(OidcRefreshParams {
            refresh_token: Sensitive::new("r".into()),
            scope: None,
            tenant_id: None,
            configuration: Some(configuration.clone()),
        })
        .await
        .expect_err("no client_id configured");
    assert!(matches!(err, AxiamError::Auth { .. }), "{err:?}");
    assert!(err.to_string().contains("requires a client_id"), "{err}");

    let err = client
        .oidc_exchange(exchange_params(configuration))
        .await
        .expect_err("no client_id configured");
    assert!(err.to_string().contains("requires a client_id"), "{err}");

    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "a missing client_id must be caught before any request is sent"
    );
}

/// §12.3 rule 4: a slug-only client with no resolved UUID cannot fill
/// `?tenant_id=`, and must say so client-side rather than send a slug.
#[tokio::test]
async fn a_slug_only_client_cannot_call_the_token_endpoint() {
    let mock_server = MockServer::start().await;
    let calls = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&calls);
    Mock::given(method("POST"))
        .and(path("/oauth2/token"))
        .respond_with(move |_req: &Request| {
            counter.fetch_add(1, Ordering::SeqCst);
            ResponseTemplate::new(200).set_body_json(oidc_support::token_response(json!({})))
        })
        .mount(&mock_server)
        .await;

    let client = AxiamClient::builder()
        .base_url(mock_server.uri())
        .expect("valid base url")
        .tenant_slug("acme")
        .oidc_client_id(oidc_support::CLIENT_ID)
        .build()
        .expect("client builds");

    let err = client
        .oidc_refresh(OidcRefreshParams {
            refresh_token: Sensitive::new("r".into()),
            scope: None,
            tenant_id: None,
            configuration: Some(configuration_for(&mock_server.uri())),
        })
        .await
        .expect_err("a slug cannot fill the tenant_id query parameter");
    assert!(matches!(err, AxiamError::Auth { .. }), "{err:?}");
    assert!(err.to_string().contains("tenant_id UUID"), "{err}");
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

/// An `authorization_endpoint`/`token_endpoint` the discovery document
/// advertises but that does not parse as a URL is a `NetworkError`, raised
/// before any request is attempted.
#[tokio::test]
async fn an_unparseable_endpoint_url_from_the_discovery_document_is_rejected() {
    let mock_server = MockServer::start().await;
    let client = oidc_support::build_client(&mock_server.uri(), true);
    let configuration = configuration_with_endpoints(&mock_server.uri(), "not a url at all");

    let err = client
        .oidc_refresh(OidcRefreshParams {
            refresh_token: Sensitive::new("r".into()),
            scope: None,
            tenant_id: None,
            configuration: Some(configuration.clone()),
        })
        .await
        .expect_err("must fail");
    assert!(matches!(err, AxiamError::Network { .. }), "{err:?}");
    assert!(
        err.to_string()
            .contains("invalid endpoint URL in discovery document"),
        "{err}"
    );

    let err = client
        .revoke(RevokeParams {
            token: Sensitive::new("t".into()),
            token_type_hint: None,
            tenant_id: None,
            configuration: Some(configuration),
        })
        .await
        .expect_err("must fail");
    assert!(
        err.to_string()
            .contains("invalid endpoint URL in discovery document"),
        "{err}"
    );

    // …and the same for `oidc_begin`'s authorization_endpoint.
    let mut doc = oidc_support::discovery_document(&mock_server.uri());
    doc.as_object_mut()
        .unwrap()
        .insert("authorization_endpoint".into(), json!("not a url"));
    let broken: OidcConfiguration = serde_json::from_value(doc).expect("deserializes");
    let err = client
        .oidc_begin(
            &broken,
            axiam_sdk::oidc::OidcBeginParams::new(oidc_support::REDIRECT_URI),
        )
        .expect_err("must fail");
    assert!(
        err.to_string()
            .contains("invalid authorization_endpoint in discovery document"),
        "{err}"
    );
}

// ---------------------------------------------------------------------------
// The pre-fetched-`configuration` arm of every operation (§12.1: `oidc_begin`
// and the token ops take an already-fetched document to avoid re-reading the
// cache)
// ---------------------------------------------------------------------------

/// Passing `configuration: Some(..)` must skip discovery entirely — asserted
/// by mounting **no** `/.well-known/openid-configuration` mock and counting
/// zero calls to it.
#[tokio::test]
async fn a_pre_fetched_configuration_skips_discovery_for_every_operation() {
    let mock_server = MockServer::start().await;
    let discovery_calls = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&discovery_calls);
    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(move |_req: &Request| {
            counter.fetch_add(1, Ordering::SeqCst);
            ResponseTemplate::new(500)
        })
        .mount(&mock_server)
        .await;
    let key = oidc_support::generate_signing_key("prefetched-key");
    Mock::given(method("GET"))
        .and(path("/oauth2/jwks"))
        .respond_with(ResponseTemplate::new(200).set_body_json(oidc_support::jwks_body(&[&key])))
        .mount(&mock_server)
        .await;
    Mock::given(method("POST"))
        .and(path("/oauth2/token"))
        .respond_with(move |_req: &Request| {
            ResponseTemplate::new(200).set_body_json(oidc_support::token_response(json!({})))
        })
        .mount(&mock_server)
        .await;
    Mock::given(method("POST"))
        .and(path("/oauth2/introspect"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "active": false })))
        .mount(&mock_server)
        .await;
    Mock::given(method("POST"))
        .and(path("/oauth2/revoke"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&mock_server)
        .await;

    let client = oidc_support::build_client(&mock_server.uri(), true);
    let configuration = configuration_for(&mock_server.uri());

    client
        .oidc_exchange(OidcExchangeParams {
            configuration: Some(configuration.clone()),
            ..exchange_params(configuration.clone())
        })
        .await
        .expect("oidc_exchange with a pre-fetched document");
    client
        .oidc_refresh(OidcRefreshParams {
            refresh_token: Sensitive::new("r".into()),
            scope: None,
            tenant_id: None,
            configuration: Some(configuration.clone()),
        })
        .await
        .expect("oidc_refresh with a pre-fetched document");
    client
        .login_client_credentials(LoginClientCredentialsParams {
            scope: None,
            tenant_id: None,
            configuration: Some(configuration.clone()),
        })
        .await
        .expect("login_client_credentials with a pre-fetched document");
    client
        .introspect(IntrospectParams {
            token: Sensitive::new("t".into()),
            token_type_hint: None,
            tenant_id: None,
            configuration: Some(configuration.clone()),
        })
        .await
        .expect("introspect with a pre-fetched document");
    client
        .revoke(RevokeParams {
            token: Sensitive::new("t".into()),
            token_type_hint: None,
            tenant_id: None,
            configuration: Some(configuration),
        })
        .await
        .expect("revoke with a pre-fetched document");

    assert_eq!(
        discovery_calls.load(Ordering::SeqCst),
        0,
        "a pre-fetched configuration must not trigger discovery (which here would 500)"
    );
}

// ---------------------------------------------------------------------------
// `oidc_discover` failure arms
// ---------------------------------------------------------------------------

#[tokio::test]
async fn discovery_maps_a_non_success_status_and_a_malformed_body() {
    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(503).set_body_string("upstream down"))
        .mount(&mock_server)
        .await;
    let client = oidc_support::build_client(&mock_server.uri(), true);
    let err = client
        .oidc_discover()
        .await
        .expect_err("a 503 discovery must fail");
    assert!(matches!(err, AxiamError::Network { .. }), "{err:?}");
    assert!(err.to_string().contains("upstream down"), "{err}");

    // A fresh client, so the (per-instance) cache does not serve the first
    // failure's origin key.
    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(200).set_body_string("{\"not\":\"a document\"}"))
        .mount(&mock_server)
        .await;
    let client = oidc_support::build_client(&mock_server.uri(), true);
    let err = client
        .oidc_discover()
        .await
        .expect_err("a body missing required fields must fail");
    assert!(matches!(err, AxiamError::Network { .. }), "{err:?}");
    assert!(
        err.to_string()
            .contains("failed to parse discovery document"),
        "{err}"
    );
}

#[tokio::test]
async fn discovery_maps_a_transport_failure_and_chains_its_cause() {
    let client = AxiamClient::builder()
        .base_url(DEAD_ENDPOINT_HOST)
        .expect("loopback base url")
        .tenant_id(oidc_support::tenant_id())
        .oidc_client_id(oidc_support::CLIENT_ID)
        .build()
        .expect("client builds");
    let err = client
        .oidc_discover()
        .await
        .expect_err("unreachable host must fail");
    assert!(matches!(err, AxiamError::Network { .. }), "{err:?}");
    assert!(
        err.to_string().contains("oidc discovery request failed"),
        "{err}"
    );
    assert!(std::error::Error::source(&err).is_some());
}

// ---------------------------------------------------------------------------
// `sso_start` tenant/org resolution matrix (§5.1) and its error status arm
// ---------------------------------------------------------------------------

async fn mount_capturing_sso_start(
    mock_server: &MockServer,
) -> Arc<std::sync::Mutex<Vec<serde_json::Value>>> {
    let captured: Arc<std::sync::Mutex<Vec<serde_json::Value>>> =
        Arc::new(std::sync::Mutex::new(Vec::new()));
    let captured_for = Arc::clone(&captured);
    Mock::given(method("POST"))
        .and(path("/api/v1/auth/federation/oidc/start"))
        .respond_with(move |req: &Request| {
            captured_for
                .lock()
                .unwrap()
                .push(serde_json::from_slice(&req.body).unwrap_or(json!(null)));
            ResponseTemplate::new(200).set_body_json(json!({
                "authorize_url": "https://upstream-idp.example.com/authorize",
                "state": "s",
                "expires_in_secs": 600,
            }))
        })
        .mount(mock_server)
        .await;
    captured
}

/// §5.1: explicit per-call `tenant_id`/`org_id` win over the client's
/// construction-time configuration, and only the UUID form is sent.
#[tokio::test]
async fn sso_start_prefers_explicit_uuid_arguments() {
    let mock_server = MockServer::start().await;
    let captured = mount_capturing_sso_start(&mock_server).await;
    let client = oidc_support::build_client(&mock_server.uri(), true);

    let explicit_tenant = uuid::Uuid::new_v4();
    let explicit_org = uuid::Uuid::new_v4();
    client
        .sso_start(SsoStartParams {
            federation_config_id: "cfg".into(),
            redirect_uri: "https://app.example.com/cb".into(),
            tenant_id: Some(explicit_tenant),
            // Deliberately supplied alongside the UUID: the UUID wins and the
            // slug is dropped rather than both being sent.
            tenant_slug: Some("ignored-slug".into()),
            org_id: Some(explicit_org),
            org_slug: Some("ignored-org-slug".into()),
        })
        .await
        .expect("sso_start succeeds");

    let body = &captured.lock().unwrap()[0];
    assert_eq!(
        body["tenant_id"].as_str(),
        Some(explicit_tenant.to_string()).as_deref()
    );
    assert_eq!(
        body["org_id"].as_str(),
        Some(explicit_org.to_string()).as_deref()
    );
    assert!(body.get("tenant_slug").is_none(), "{body}");
    assert!(body.get("org_slug").is_none(), "{body}");
}

/// §5.1: the slug forms are accepted too — both when passed per call and when
/// they come from the client's construction-time configuration.
#[tokio::test]
async fn sso_start_accepts_slug_forms_from_arguments_and_from_client_configuration() {
    let mock_server = MockServer::start().await;
    let captured = mount_capturing_sso_start(&mock_server).await;
    let client = oidc_support::build_client(&mock_server.uri(), true);

    client
        .sso_start(SsoStartParams {
            federation_config_id: "cfg".into(),
            redirect_uri: "https://app.example.com/cb".into(),
            tenant_id: None,
            tenant_slug: Some("acme-tenant".into()),
            org_id: None,
            org_slug: Some("acme-org".into()),
        })
        .await
        .expect("sso_start succeeds with slugs");

    // Now the same, resolved from the *client's* slug configuration.
    let slug_client = AxiamClient::builder()
        .base_url(mock_server.uri())
        .expect("valid base url")
        .tenant_slug("configured-tenant")
        .org_slug("configured-org")
        .oidc_client_id(oidc_support::CLIENT_ID)
        .build()
        .expect("client builds");
    slug_client
        .sso_start(SsoStartParams {
            federation_config_id: "cfg".into(),
            redirect_uri: "https://app.example.com/cb".into(),
            ..Default::default()
        })
        .await
        .expect("sso_start succeeds from client slug configuration");

    let bodies = captured.lock().unwrap();
    assert_eq!(bodies[0]["tenant_slug"].as_str(), Some("acme-tenant"));
    assert_eq!(bodies[0]["org_slug"].as_str(), Some("acme-org"));
    assert!(bodies[0].get("tenant_id").is_none());
    assert!(bodies[0].get("org_id").is_none());
    assert_eq!(bodies[1]["tenant_slug"].as_str(), Some("configured-tenant"));
    assert_eq!(bodies[1]["org_slug"].as_str(), Some("configured-org"));
}

/// Addendum item 12: the federation endpoints document no error schema, so a
/// non-2xx there is mapped by plain §2 status mapping — never parsed as an
/// `OAuth2ErrorResponse`, even when the body happens to look like one.
#[tokio::test]
async fn sso_start_maps_a_non_success_status_without_oauth_parsing() {
    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/auth/federation/oidc/start"))
        .respond_with(ResponseTemplate::new(403).set_body_json(json!({
            "error": "invalid_request",
            "error_description": "would be an OAuth2ErrorResponse on /oauth2/*",
            "action": "federation:start",
        })))
        .mount(&mock_server)
        .await;
    let client = oidc_support::build_client(&mock_server.uri(), true);

    let err = client
        .sso_start(SsoStartParams {
            federation_config_id: "cfg".into(),
            redirect_uri: "https://app.example.com/cb".into(),
            ..Default::default()
        })
        .await
        .expect_err("a 403 must fail");
    // §2: 403 → Authz, and NOT an OAuthProtocolError despite the body shape.
    assert!(matches!(err, AxiamError::Authz { .. }), "{err:?}");
    assert!(err.as_oauth_protocol_error().is_none());
}
