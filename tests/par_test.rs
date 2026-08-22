//! Pushed Authorization Requests — CONTRACT.md §26 (RFC 9126).
//!
//! The first test is the one this section exists for: the endpoint answers
//! **201**, and a success predicate written `== 200` treats every successful
//! push as a failure while passing every other assertion here.

#![cfg(feature = "rest")]

#[path = "oidc_support/mod.rs"]
mod oidc_support;

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use axiam_sdk::AxiamError;
use axiam_sdk::oidc::{OidcBeginParams, OidcConfiguration, OidcParParams};
use serde_json::json;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

use oidc_support::{
    CLIENT_ID, CLIENT_SECRET, REDIRECT_URI, build_client, discovery_document,
    discovery_document_without_optional_endpoints,
};

const REQUEST_URI: &str = "urn:ietf:params:oauth:request_uri:6esc_11ACC5bwc014ltc14eY22c";
const PAR_PATH: &str = "/oauth2/par";

fn configuration(base_url: &str) -> OidcConfiguration {
    serde_json::from_value(discovery_document(base_url)).expect("discovery parses")
}

/// RFC 9126 §2.2 — Created, not OK.
fn created() -> ResponseTemplate {
    ResponseTemplate::new(201).set_body_json(json!({
        "request_uri": REQUEST_URI,
        "expires_in": 90,
    }))
}

/// Captured pushes: the form fields, the query, and the content type.
#[derive(Default)]
struct Capture {
    forms: Vec<HashMap<String, String>>,
    tenant_ids: Vec<Option<String>>,
    content_types: Vec<Option<String>>,
}

async fn mount_par(
    server: &MockServer,
    template: ResponseTemplate,
) -> (Arc<std::sync::Mutex<Capture>>, Arc<AtomicUsize>) {
    let capture = Arc::new(std::sync::Mutex::new(Capture::default()));
    let hits = Arc::new(AtomicUsize::new(0));
    let sink = Arc::clone(&capture);
    let counter = Arc::clone(&hits);

    Mock::given(method("POST"))
        .and(path(PAR_PATH))
        .respond_with(move |req: &Request| {
            counter.fetch_add(1, Ordering::SeqCst);
            let body = String::from_utf8_lossy(&req.body).into_owned();
            let form: HashMap<String, String> = url::form_urlencoded::parse(body.as_bytes())
                .map(|(k, v)| (k.into_owned(), v.into_owned()))
                .collect();
            let tenant_id = req
                .url
                .query_pairs()
                .find(|(k, _)| k == "tenant_id")
                .map(|(_, v)| v.into_owned());
            let content_type = req
                .headers
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned);

            let mut guard = sink.lock().expect("lock");
            guard.forms.push(form);
            guard.tenant_ids.push(tenant_id);
            guard.content_types.push(content_type);
            template.clone()
        })
        .mount(server)
        .await;

    (capture, hits)
}

// ---------------------------------------------------------------------------
// §26.1 — the 201 and the wire shape
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_201_is_treated_as_success() {
    let server = MockServer::start().await;
    mount_par(&server, created()).await;

    let client = build_client(&server.uri(), true);
    let configuration = configuration(&server.uri());
    let request = client
        .oidc_begin(
            &configuration,
            OidcBeginParams {
                redirect_uri: REDIRECT_URI.into(),
                scope: Some("openid profile".into()),
                ..Default::default()
            },
        )
        .expect("begin");

    let pushed = client
        .oidc_par(OidcParParams {
            request,
            redirect_uri: REDIRECT_URI.into(),
            scope: Some("openid profile".into()),
            tenant_id: None,
            configuration: Some(configuration),
        })
        .await
        .expect("a 201 is the RFC 9126 success status");

    assert_eq!(pushed.request_uri.expose(), REQUEST_URI);
    assert_eq!(pushed.expires_in, 90);
}

#[tokio::test]
async fn the_push_carries_exactly_the_rule_1_parameters() {
    let server = MockServer::start().await;
    let (capture, _) = mount_par(&server, created()).await;

    let client = build_client(&server.uri(), true);
    let configuration = configuration(&server.uri());
    let request = client
        .oidc_begin(
            &configuration,
            OidcBeginParams {
                redirect_uri: REDIRECT_URI.into(),
                scope: Some("openid profile".into()),
                ..Default::default()
            },
        )
        .expect("begin");
    let (state, nonce) = (request.state.clone(), request.nonce.clone());
    let expected_challenge =
        axiam_sdk::oidc::authorize::compute_code_challenge(request.code_verifier.expose());

    client
        .oidc_par(OidcParParams {
            request,
            redirect_uri: REDIRECT_URI.into(),
            scope: Some("openid profile".into()),
            tenant_id: None,
            configuration: Some(configuration),
        })
        .await
        .expect("push");

    let guard = capture.lock().expect("lock");
    let form = &guard.forms[0];
    assert_eq!(form["client_id"], CLIENT_ID);
    assert_eq!(form["response_type"], "code");
    assert_eq!(form["redirect_uri"], REDIRECT_URI);
    assert_eq!(form["scope"], "openid profile");
    assert_eq!(form["state"], state);
    assert_eq!(form["nonce"], nonce);
    assert_eq!(form["code_challenge_method"], "S256");
    // §26.2 rule 1: derived from oidc_begin's verifier, not a fresh one.
    assert_eq!(form["code_challenge"], expected_challenge);
    assert_eq!(form["client_secret"], CLIENT_SECRET);

    // Form-encoded, with tenant_id in the QUERY and never in the body.
    assert!(
        guard.content_types[0]
            .as_deref()
            .expect("content type")
            .contains("application/x-www-form-urlencoded")
    );
    assert!(guard.tenant_ids[0].is_some());
    assert!(!form.contains_key("tenant_id"));
}

#[tokio::test]
async fn a_public_client_omits_client_secret() {
    let server = MockServer::start().await;
    let (capture, _) = mount_par(&server, created()).await;

    let client = build_client(&server.uri(), false);
    let configuration = configuration(&server.uri());
    let request = client
        .oidc_begin(
            &configuration,
            OidcBeginParams {
                redirect_uri: REDIRECT_URI.into(),
                ..Default::default()
            },
        )
        .expect("begin");
    client
        .oidc_par(OidcParParams {
            request,
            redirect_uri: REDIRECT_URI.into(),
            scope: None,
            tenant_id: None,
            configuration: Some(configuration),
        })
        .await
        .expect("push");

    // §12.1 forbids sending an empty value for an absent optional field.
    assert!(!capture.lock().expect("lock").forms[0].contains_key("client_secret"));
}

#[tokio::test]
async fn openid_is_added_when_the_caller_omits_it() {
    let server = MockServer::start().await;
    let (capture, _) = mount_par(&server, created()).await;

    let client = build_client(&server.uri(), true);
    let configuration = configuration(&server.uri());
    let request = client
        .oidc_begin(
            &configuration,
            OidcBeginParams {
                redirect_uri: REDIRECT_URI.into(),
                ..Default::default()
            },
        )
        .expect("begin");
    client
        .oidc_par(OidcParParams {
            request,
            redirect_uri: REDIRECT_URI.into(),
            scope: Some("profile".into()),
            tenant_id: None,
            configuration: Some(configuration),
        })
        .await
        .expect("push");

    assert_eq!(
        capture.lock().expect("lock").forms[0]["scope"],
        "openid profile"
    );
}

#[tokio::test]
async fn an_op_without_a_par_endpoint_errors_rather_than_concatenating() {
    let server = MockServer::start().await;
    let (_, hits) = mount_par(&server, created()).await;

    let client = build_client(&server.uri(), true);
    let configuration: OidcConfiguration =
        serde_json::from_value(discovery_document_without_optional_endpoints(&server.uri()))
            .expect("discovery parses");
    let request = client
        .oidc_begin(
            &configuration,
            OidcBeginParams {
                redirect_uri: REDIRECT_URI.into(),
                ..Default::default()
            },
        )
        .expect("begin");

    let err = client
        .oidc_par(OidcParParams {
            request,
            redirect_uri: REDIRECT_URI.into(),
            scope: None,
            tenant_id: None,
            configuration: Some(configuration),
        })
        .await
        .expect_err("no PAR endpoint");
    assert!(matches!(err, AxiamError::Auth { .. }));
    assert_eq!(hits.load(Ordering::SeqCst), 0);
}

// ---------------------------------------------------------------------------
// §26.2 rule 2 — the redirect URL carries exactly two parameters
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_authorization_url_carries_exactly_two_parameters() {
    let server = MockServer::start().await;
    mount_par(&server, created()).await;

    let client = build_client(&server.uri(), true);
    let configuration = configuration(&server.uri());
    let request = client
        .oidc_begin(
            &configuration,
            OidcBeginParams {
                redirect_uri: REDIRECT_URI.into(),
                ..Default::default()
            },
        )
        .expect("begin");
    let pushed = client
        .oidc_par(OidcParParams {
            request,
            redirect_uri: REDIRECT_URI.into(),
            scope: None,
            tenant_id: None,
            configuration: Some(configuration),
        })
        .await
        .expect("push");

    let parsed = url::Url::parse(&pushed.url).expect("valid URL");
    let params: HashMap<String, String> = parsed
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();

    // Asserted on the FULL parameter set, not on the presence of the two: the
    // server refuses a request mixing a request_uri with inline authorization
    // parameters rather than merging them, and re-adding them "for
    // compatibility" restores the parameter-confusion attack that prevents.
    assert_eq!(params.len(), 2, "unexpected parameters: {params:?}");
    assert_eq!(params["client_id"], CLIENT_ID);
    assert_eq!(params["request_uri"], REQUEST_URI);
    assert!(
        pushed
            .url
            .starts_with(&format!("{}/oauth2/authorize", server.uri()))
    );
}

// ---------------------------------------------------------------------------
// §26.2 rules 1 and 6, and §26.5
// ---------------------------------------------------------------------------

#[tokio::test]
async fn state_nonce_and_verifier_come_from_oidc_begin_and_stay_secret() {
    let server = MockServer::start().await;
    mount_par(&server, created()).await;

    let client = build_client(&server.uri(), true);
    let configuration = configuration(&server.uri());
    let request = client
        .oidc_begin(
            &configuration,
            OidcBeginParams {
                redirect_uri: REDIRECT_URI.into(),
                ..Default::default()
            },
        )
        .expect("begin");
    let (state, nonce, verifier) = (
        request.state.clone(),
        request.nonce.clone(),
        request.code_verifier.expose().clone(),
    );

    let pushed = client
        .oidc_par(OidcParParams {
            request,
            redirect_uri: REDIRECT_URI.into(),
            scope: None,
            tenant_id: None,
            configuration: Some(configuration),
        })
        .await
        .expect("push");

    assert_eq!(pushed.state, state);
    assert_eq!(pushed.nonce, nonce);
    // The same verifier, so there is exactly one value to keep and no second
    // place for the two to disagree (§26.2 rule 6).
    assert_eq!(pushed.code_verifier.expose(), &verifier);

    // §26.5: request_uri and the verifier are secret, but the handle must still
    // reach the redirect URL — which is the point of it.
    let rendered = format!("{pushed:?}{pushed:#?}");
    assert!(!rendered.contains(REQUEST_URI));
    assert!(!rendered.contains(&verifier));
    assert!(pushed.url.contains("request_uri="));
    // state, nonce and expires_in are not secrets and stay readable.
    assert!(!pushed.state.is_empty() && !pushed.nonce.is_empty());
    assert_eq!(pushed.expires_in, 90);
}

// ---------------------------------------------------------------------------
// §26.2 rule 4 / §26.3 — retries and errors
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_5xx_is_not_retried() {
    let server = MockServer::start().await;
    let (_, hits) = mount_par(&server, ResponseTemplate::new(503)).await;

    let client = build_client(&server.uri(), true);
    let configuration = configuration(&server.uri());
    let request = client
        .oidc_begin(
            &configuration,
            OidcBeginParams {
                redirect_uri: REDIRECT_URI.into(),
                ..Default::default()
            },
        )
        .expect("begin");

    client
        .oidc_par(OidcParParams {
            request,
            redirect_uri: REDIRECT_URI.into(),
            scope: None,
            tenant_id: None,
            configuration: Some(configuration),
        })
        .await
        .expect_err("503");

    // It is a POST that creates server state, so it falls outside §16.2's
    // read-only eligibility exactly as oidc_exchange does.
    assert_eq!(hits.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn oauth2_errors_map_through_the_shared_mapper() {
    for (status, code) in [(401u16, "invalid_client"), (400, "invalid_request")] {
        let server = MockServer::start().await;
        mount_par(
            &server,
            ResponseTemplate::new(status)
                .set_body_json(json!({"error": code, "error_description": "nope"})),
        )
        .await;

        let client = build_client(&server.uri(), true);
        let configuration = configuration(&server.uri());
        let request = client
            .oidc_begin(
                &configuration,
                OidcBeginParams {
                    redirect_uri: REDIRECT_URI.into(),
                    ..Default::default()
                },
            )
            .expect("begin");

        let err = client
            .oidc_par(OidcParParams {
                request,
                redirect_uri: REDIRECT_URI.into(),
                scope: None,
                tenant_id: None,
                configuration: Some(configuration),
            })
            .await
            .expect_err("oauth2 error");

        assert_eq!(err.oauth_error_code(), Some(code), "status {status}");
    }
}
