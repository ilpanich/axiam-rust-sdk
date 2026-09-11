//! Contract 1.42 — the first OIDF conformance run's consequences for this SDK.
//!
//! Three things arrived together and only two of them are additive:
//!
//!   * §21.5 gains `code_challenge_methods_supported` and
//!     `token_endpoint_auth_signing_alg_values_supported` (RFC 8414 §2), which
//!     this SDK now reads and which a document may still omit;
//!   * RFC 9449 §10 `dpop_jkt` becomes pushable at PAR;
//!   * **the discovery document now publishes the tenant inside the endpoint
//!     URLs it advertises**, which is the one that breaks working code. A
//!     client that appends its own `?tenant_id=` to such a URL sends two, and
//!     the `oidc_par` redirect target — which used to clear the query
//!     outright — sent none.
//!
//! The tenant tests are the load-bearing ones here. They use
//! [`oidc_support::tenant_scoped_discovery_document`], whose `token_endpoint`
//! deliberately also carries an unrelated `deployment=eu-west`: RFC 6749 §3.2
//! requires a client adding parameters of its own to retain the endpoint's
//! existing query component, not merely the part of it the client recognises.

#![cfg(feature = "rest")]

#[path = "oidc_support/mod.rs"]
mod oidc_support;

use std::sync::Arc;
use std::sync::Mutex;

use axiam_sdk::oidc::{
    LoginClientCredentialsParams, OidcBeginParams, OidcConfiguration, OidcParParams,
};
use serde_json::json;
use url::Url;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

use oidc_support::{
    CLIENT_ID, REDIRECT_URI, build_client, discovery_document, tenant_id,
    tenant_scoped_discovery_document, token_response,
};

const REQUEST_URI: &str = "urn:ietf:params:oauth:request_uri:6esc_11ACC5bwc014ltc14eY22c";

fn configuration(value: serde_json::Value) -> OidcConfiguration {
    serde_json::from_value(value).expect("discovery document parses")
}

/// Every `tenant_id` query value on `url`, in order. A `Vec` rather than an
/// `Option` on purpose: the bug this file exists for is *two* of them, and an
/// accessor that returns the first would report success.
fn tenant_ids(url: &Url) -> Vec<String> {
    url.query_pairs()
        .filter(|(k, _)| k == "tenant_id")
        .map(|(_, v)| v.into_owned())
        .collect()
}

// ---------------------------------------------------------------------------
// §21.5 — the two new discovery members
// ---------------------------------------------------------------------------

/// Read when present. AXIAM publishes `S256` and only `S256`; the
/// authorization endpoint refuses `plain`.
#[test]
fn discovery_reads_the_two_members_contract_1_42_added() {
    let mut doc = discovery_document("https://iam.example.com");
    let map = doc.as_object_mut().unwrap();
    map.insert("code_challenge_methods_supported".into(), json!(["S256"]));
    map.insert(
        "token_endpoint_auth_signing_alg_values_supported".into(),
        json!(["PS256", "ES256", "EdDSA"]),
    );

    let config = configuration(doc);
    assert_eq!(
        config.code_challenge_methods_supported.as_deref(),
        Some(["S256".to_owned()].as_slice()),
    );
    assert_eq!(
        config
            .token_endpoint_auth_signing_alg_values_supported
            .as_deref(),
        Some(["PS256".to_owned(), "ES256".to_owned(), "EdDSA".to_owned()].as_slice()),
    );
}

/// Absent is a value, not a parse failure — and it is NOT the same answer as
/// `["S256"]`.
///
/// §21.5 is explicit that RFC 8414 defines no default for
/// `code_challenge_methods_supported`, so silence means "this client cannot
/// establish that PKCE is available", not "S256". Modelling either member as
/// required would refuse every pre-1.42 AXIAM document and most third-party
/// OPs — which is why they are `Option` here despite `openapi.json` listing
/// them in `required`.
#[test]
fn discovery_without_the_two_members_still_parses_and_reports_absence() {
    let config = configuration(discovery_document("https://iam.example.com"));
    assert!(
        config.code_challenge_methods_supported.is_none(),
        "absence must not be normalised into a default the RFC does not define",
    );
    assert!(
        config
            .token_endpoint_auth_signing_alg_values_supported
            .is_none(),
    );
}

// ---------------------------------------------------------------------------
// The tenant is already in the advertised URL (the regression)
// ---------------------------------------------------------------------------

/// `POST /oauth2/token` against a tenant-scoped document sends exactly ONE
/// `tenant_id`, and keeps the endpoint's unrelated query parameter.
#[tokio::test]
async fn token_endpoint_does_not_double_a_tenant_the_document_already_carries() {
    let server = MockServer::start().await;
    let seen: Arc<Mutex<Option<Url>>> = Arc::new(Mutex::new(None));
    let sink = Arc::clone(&seen);

    Mock::given(method("POST"))
        .and(path("/oauth2/token"))
        .respond_with(move |req: &Request| {
            *sink.lock().unwrap() = Some(req.url.clone());
            ResponseTemplate::new(200).set_body_json(token_response(json!({})))
        })
        .mount(&server)
        .await;

    let client = build_client(&server.uri(), true);
    client
        .login_client_credentials(LoginClientCredentialsParams {
            scope: None,
            tenant_id: None,
            configuration: Some(configuration(tenant_scoped_discovery_document(
                &server.uri(),
                tenant_id(),
            ))),
        })
        .await
        .expect("the grant succeeds");

    let url = seen
        .lock()
        .unwrap()
        .clone()
        .expect("the token call was made");
    assert_eq!(
        tenant_ids(&url),
        vec![tenant_id().to_string()],
        "exactly one tenant_id: appending to an already-scoped endpoint sends two, \
         and the server cannot deserialise two into one Uuid",
    );
    assert_eq!(
        url.query_pairs()
            .find(|(k, _)| k == "deployment")
            .map(|(_, v)| v.into_owned()),
        Some("eu-west".to_owned()),
        "RFC 6749 §3.2: the endpoint's own query component is retained, not just \
         the part this SDK recognises",
    );
}

/// A bare (non-tenant-scoped) document is the pre-1.42 case and still gets the
/// SDK's own `tenant_id` appended. The fix must not turn "add it" into
/// "only ever replace it".
#[tokio::test]
async fn token_endpoint_still_adds_the_tenant_when_the_document_omits_it() {
    let server = MockServer::start().await;
    let seen: Arc<Mutex<Option<Url>>> = Arc::new(Mutex::new(None));
    let sink = Arc::clone(&seen);

    Mock::given(method("POST"))
        .and(path("/oauth2/token"))
        .respond_with(move |req: &Request| {
            *sink.lock().unwrap() = Some(req.url.clone());
            ResponseTemplate::new(200).set_body_json(token_response(json!({})))
        })
        .mount(&server)
        .await;

    let client = build_client(&server.uri(), true);
    client
        .login_client_credentials(LoginClientCredentialsParams {
            scope: None,
            tenant_id: None,
            configuration: Some(configuration(discovery_document(&server.uri()))),
        })
        .await
        .expect("the grant succeeds");

    let url = seen
        .lock()
        .unwrap()
        .clone()
        .expect("the token call was made");
    assert_eq!(tenant_ids(&url), vec![tenant_id().to_string()]);
}

/// The PAR redirect target keeps the tenant the document put on
/// `authorization_endpoint`, and still carries nothing else beyond
/// `client_id` and `request_uri`.
///
/// §26.2 rule 2 caps what may accompany a `request_uri`, and this is the one
/// carry-over: `tenant_id` is AXIAM's tenant routing parameter rather than an
/// OAuth2 authorization request parameter, it is never part of the pushed
/// body, and `/oauth2/authorize` reads it to route a browser that has no
/// session yet — which is every browser arriving on a PAR redirect. Clearing
/// the query, as this code did before contract 1.42, produced a URL the
/// server answers `401` to.
#[tokio::test]
async fn par_redirect_keeps_the_advertised_tenant_and_adds_nothing_else() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/oauth2/par"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "request_uri": REQUEST_URI,
            "expires_in": 90,
        })))
        .mount(&server)
        .await;

    let client = build_client(&server.uri(), true);
    let config = configuration(tenant_scoped_discovery_document(&server.uri(), tenant_id()));
    let request = client
        .oidc_begin(
            &config,
            OidcBeginParams {
                redirect_uri: REDIRECT_URI.into(),
                ..Default::default()
            },
        )
        .expect("oidc_begin");

    let pushed = client
        .oidc_par(OidcParParams {
            request,
            redirect_uri: REDIRECT_URI.into(),
            scope: Some("openid profile".into()),
            tenant_id: None,
            configuration: Some(config),
            dpop_jkt: None,
        })
        .await
        .expect("the push succeeds");

    let url = Url::parse(&pushed.url).expect("the redirect target is a URL");
    assert_eq!(
        tenant_ids(&url),
        vec![tenant_id().to_string()],
        "the tenant the server advertised must survive into the redirect",
    );

    let mut names: Vec<String> = url.query_pairs().map(|(k, _)| k.into_owned()).collect();
    names.sort();
    assert_eq!(
        names,
        vec![
            "client_id".to_owned(),
            "request_uri".to_owned(),
            "tenant_id".to_owned()
        ],
        "§26.2 rule 2: no inline authorization parameter rides along",
    );
}

/// A bare `authorization_endpoint` still yields the two-parameter redirect
/// §26.2 rule 2 describes — no empty `tenant_id=` invented for symmetry.
#[tokio::test]
async fn par_redirect_from_a_bare_endpoint_carries_exactly_two_parameters() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/oauth2/par"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "request_uri": REQUEST_URI,
            "expires_in": 90,
        })))
        .mount(&server)
        .await;

    let client = build_client(&server.uri(), true);
    let config = configuration(discovery_document(&server.uri()));
    let request = client
        .oidc_begin(
            &config,
            OidcBeginParams {
                redirect_uri: REDIRECT_URI.into(),
                ..Default::default()
            },
        )
        .expect("oidc_begin");

    let pushed = client
        .oidc_par(OidcParParams {
            request,
            redirect_uri: REDIRECT_URI.into(),
            scope: None,
            tenant_id: None,
            configuration: Some(config),
            dpop_jkt: None,
        })
        .await
        .expect("the push succeeds");

    let url = Url::parse(&pushed.url).expect("the redirect target is a URL");
    let mut names: Vec<String> = url.query_pairs().map(|(k, _)| k.into_owned()).collect();
    names.sort();
    assert_eq!(
        names,
        vec!["client_id".to_owned(), "request_uri".to_owned()]
    );
}

// ---------------------------------------------------------------------------
// RFC 9449 §10 — dpop_jkt
// ---------------------------------------------------------------------------

/// Pushed when the caller supplies it, and **omitted entirely** — not sent
/// empty — when they do not. §12.1 forbids an empty value for an absent
/// optional field, and an empty `dpop_jkt` would pin the code to a key
/// nobody holds.
#[tokio::test]
async fn dpop_jkt_is_pushed_when_set_and_absent_when_not() {
    async fn push(dpop_jkt: Option<String>) -> String {
        let server = MockServer::start().await;
        let seen: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
        let sink = Arc::clone(&seen);
        Mock::given(method("POST"))
            .and(path("/oauth2/par"))
            .respond_with(move |req: &Request| {
                *sink.lock().unwrap() = Some(String::from_utf8_lossy(&req.body).into_owned());
                ResponseTemplate::new(201).set_body_json(json!({
                    "request_uri": REQUEST_URI,
                    "expires_in": 90,
                }))
            })
            .mount(&server)
            .await;

        let client = build_client(&server.uri(), true);
        let config = configuration(discovery_document(&server.uri()));
        let request = client
            .oidc_begin(
                &config,
                OidcBeginParams {
                    redirect_uri: REDIRECT_URI.into(),
                    ..Default::default()
                },
            )
            .expect("oidc_begin");

        client
            .oidc_par(OidcParParams {
                request,
                redirect_uri: REDIRECT_URI.into(),
                scope: None,
                tenant_id: None,
                configuration: Some(config),
                dpop_jkt,
            })
            .await
            .expect("the push succeeds");

        seen.lock().unwrap().clone().expect("the push was made")
    }

    const JKT: &str = "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I";
    let with = push(Some(JKT.to_owned())).await;
    assert!(
        with.contains(&format!("dpop_jkt={JKT}")),
        "RFC 9449 §10: the thumbprint is pushed with the request; body was {with}",
    );

    let without = push(None).await;
    assert!(
        !without.contains("dpop_jkt"),
        "an unset dpop_jkt is omitted, never sent empty (§12.1); body was {without}",
    );
    assert!(
        without.contains(&format!("client_id={CLIENT_ID}")),
        "sanity: the rest of the push is unchanged",
    );
}

// ---------------------------------------------------------------------------
// OIDC Core §5.4 — the ID token stopped carrying tenant_id/org_id/email
// ---------------------------------------------------------------------------

/// This SDK never typed those three as ID-token claims, and this test is what
/// keeps it that way.
///
/// [`axiam_sdk::oidc::IdTokenClaims`] models only the protocol claims §12.4
/// validates (`iss`, `sub`, `aud`, `exp`, `iat`, `nbf`, `nonce`, `azp`) and
/// keeps everything else in `extra` — so an AXIAM that stopped sending
/// `tenant_id`, `org_id` and `email` (OIDC Core §5.4, contract 1.42) changes
/// nothing here. A future field promoted out of `extra` would break this
/// assertion, which is the point: the tenant is resolved from the
/// access-token claims returned by login, never from the ID token.
#[test]
fn id_token_claims_type_names_no_tenant_org_or_email() {
    let claims: axiam_sdk::oidc::IdTokenClaims = serde_json::from_value(json!({
        "iss": "https://iam.example.com",
        "sub": "user-1",
        "aud": CLIENT_ID,
        "exp": 9_999_999_999i64,
        "iat": 1_700_000_000i64,
        "nonce": "n",
    }))
    .expect("an ID token carrying none of the three still deserialises");

    assert_eq!(claims.sub, "user-1");
    for absent in ["tenant_id", "org_id", "email"] {
        assert!(
            !claims.extra.contains_key(absent),
            "{absent} is not synthesised when the OP does not send it",
        );
    }
}

/// An OP that *does* still send them is not rejected — they land in `extra`,
/// which is what §12.1 requires of a claim set `openapi.json` does not
/// enumerate. AXIAM is not the only OP an SDK meets.
#[test]
fn unrecognised_claims_are_preserved_rather_than_rejected() {
    let claims: axiam_sdk::oidc::IdTokenClaims = serde_json::from_value(json!({
        "iss": "https://other-op.example",
        "sub": "user-1",
        "aud": CLIENT_ID,
        "exp": 9_999_999_999i64,
        "iat": 1_700_000_000i64,
        "tenant_id": "11111111-2222-3333-4444-555555555555",
        "email": "user@example.test",
    }))
    .expect("deserialises");

    assert_eq!(
        claims.extra.get("email").and_then(|v| v.as_str()),
        Some("user@example.test"),
    );
    assert!(claims.extra.contains_key("tenant_id"));
}
