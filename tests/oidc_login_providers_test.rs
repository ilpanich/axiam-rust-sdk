//! The four public "Sign in with X" operations added by contract 1.38 —
//! `sso_providers`, `sso_start_oauth2`, `sso_complete_oauth2`,
//! `sso_complete_handoff` (CONTRACT.md §12.1).
//!
//! Two kinds of assertion live here, and both are needed.
//!
//! The **wire-shape** tests read the vendored `openapi.json` and assert the
//! method, path, content type and — for `sso_providers` — the *parameter
//! location* the server declares, then assert that what this SDK actually
//! puts on the wire matches. Asserting only against the mock would pin the
//! SDK to the test's own idea of the endpoint; asserting only against the
//! spec would not notice an SDK that agrees with the spec and calls
//! something else.
//!
//! The **rule** tests cover the four §12.1 notes that are easiest to get
//! quietly wrong: note 9 (an empty provider list is a success, not a
//! not-found), note 10 (`protocol` selects the start operation), note 12 (a
//! handoff `401` is terminal and is never retried) and rule 12a (a `400`
//! from a start call is a configuration refusal, not something to retry).

#![cfg(feature = "rest")]

#[path = "oidc_support/mod.rs"]
mod oidc_support;

use axiam_sdk::AxiamError;
use axiam_sdk::oidc::{
    HANDOFF_CODE_TTL_SECS, HANDOFF_QUERY_PARAM, PROTOCOL_OAUTH2, PROTOCOL_OIDC_CONNECT,
    PROTOCOL_SAML, SSO_HANDOFF_PATH, SSO_OAUTH2_CALLBACK_PATH, SSO_OAUTH2_START_PATH,
    SSO_PROVIDERS_PATH, SsoCompleteHandoffParams, SsoCompleteOauth2Params, SsoProvidersParams,
    SsoStartOauth2Params, SsoStartParams,
};
use serde_json::{Value, json};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn openapi() -> Value {
    serde_json::from_str(include_str!("../openapi.json")).expect("openapi.json parses")
}

/// Mount `/oauth2/jwks` publishing the key that signs this file's session
/// access tokens — the two session-establishing operations run the same
/// post-login cookie sync `login()` does, which verifies `axiam_access`.
async fn mount_session_jwks(mock_server: &MockServer) -> oidc_support::SigningKeyFixture {
    let key = oidc_support::generate_signing_key("login-providers-session-key");
    Mock::given(method("GET"))
        .and(path("/oauth2/jwks"))
        .respond_with(ResponseTemplate::new(200).set_body_json(oidc_support::jwks_body(&[&key])))
        .mount(mock_server)
        .await;
    key
}

/// A `200` from a session-establishing federation endpoint, delivering the
/// session as `Set-Cookie` exactly as `POST /api/v1/auth/login` does
/// (§12.1 note 6, §4).
fn session_response(
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
        oidc_support::session_cookie_headers(access_token, "handoff-refresh", "handoff-csrf")
    {
        response = response.append_header("Set-Cookie", cookie.as_str());
    }
    response
}

fn provider(id: &str, kind: &str, protocol: &str) -> Value {
    json!({
        "id": id,
        "provider_kind": kind,
        "display_name": kind,
        "protocol": protocol,
        "has_bundled_mark": true,
        "inherited": false,
    })
}

// ---------------------------------------------------------------------------
// Wire shape, against openapi.json
// ---------------------------------------------------------------------------

/// The four operations exist in the spec at exactly the method and path the
/// SDK's exported constants name, with the request media type §12.1 gives
/// them. A change to any of those four columns upstream fails here rather
/// than at runtime against a real server.
#[test]
fn openapi_declares_the_four_operations_where_the_sdk_calls_them() {
    let spec = openapi();
    let paths = &spec["paths"];

    // `sso_providers` — GET, no request body at all.
    let providers = &paths[SSO_PROVIDERS_PATH]["get"];
    assert!(
        providers.is_object(),
        "openapi.json must declare GET {SSO_PROVIDERS_PATH}"
    );
    assert!(
        providers.get("requestBody").is_none(),
        "sso_providers is a GET and must have no request body (§12.1)"
    );

    for (endpoint, schema) in [
        (SSO_OAUTH2_START_PATH, "OAuth2StartRequest"),
        (SSO_OAUTH2_CALLBACK_PATH, "OAuth2CallbackRequest"),
        (SSO_HANDOFF_PATH, "SsoHandoffRequest"),
    ] {
        let op = &paths[endpoint]["post"];
        assert!(op.is_object(), "openapi.json must declare POST {endpoint}");
        let body = &op["requestBody"]["content"]["application/json"];
        assert!(
            body.is_object(),
            "{endpoint} must accept application/json (§12.1)"
        );
        assert_eq!(
            body["schema"]["$ref"].as_str(),
            Some(format!("#/components/schemas/{schema}").as_str()),
            "{endpoint} must carry the {schema} body §12.1 names"
        );
    }
}

/// The success responses §12.1 names: `PublicFederationProvidersResponse`
/// for the listing, `SsoLoginSuccessResponse` for both completions.
#[test]
fn openapi_declares_the_success_schemas_section_12_1_names() {
    let spec = openapi();
    let paths = &spec["paths"];

    let body_ref = |op: &Value| -> String {
        op["responses"]["200"]["content"]["application/json"]["schema"]["$ref"]
            .as_str()
            .unwrap_or_default()
            .to_string()
    };

    assert_eq!(
        body_ref(&paths[SSO_PROVIDERS_PATH]["get"]),
        "#/components/schemas/PublicFederationProvidersResponse"
    );
    assert_eq!(
        body_ref(&paths[SSO_OAUTH2_START_PATH]["post"]),
        "#/components/schemas/OAuth2StartResponse"
    );
    for endpoint in [SSO_OAUTH2_CALLBACK_PATH, SSO_HANDOFF_PATH] {
        assert_eq!(
            body_ref(&paths[endpoint]["post"]),
            "#/components/schemas/SsoLoginSuccessResponse",
            "{endpoint} answers SsoLoginSuccessResponse"
        );
    }
}

/// §12.1: `sso_providers` takes `org_slug`/`org_id` and the optional tenant
/// pair as **query** parameters. The spec says so, and this asserts it,
/// because the neighbouring start operations take the same four identifiers
/// in a JSON *body* and the two are one copy-paste apart.
#[test]
fn openapi_puts_the_provider_identifiers_in_the_query_string() {
    let spec = openapi();
    let params = spec["paths"][SSO_PROVIDERS_PATH]["get"]["parameters"]
        .as_array()
        .expect("sso_providers declares parameters");

    let mut seen: Vec<&str> = Vec::new();
    for p in params {
        let name = p["name"].as_str().expect("parameter has a name");
        assert_eq!(
            p["in"].as_str(),
            Some("query"),
            "{name} must be a query parameter, not a body field (§12.1)"
        );
        seen.push(name);
    }
    seen.sort_unstable();
    assert_eq!(seen, ["org_id", "org_slug", "tenant_id", "tenant_slug"]);
}

/// `PublicFederationProvider` is modelled faithfully: the six required
/// fields plus the nullable `button_icon`, and nothing that would imply the
/// unauthenticated response carries configuration.
#[test]
fn openapi_public_provider_shape_matches_the_sdk_type() {
    let spec = openapi();
    let schema = &spec["components"]["schemas"]["PublicFederationProvider"];

    let mut required: Vec<&str> = schema["required"]
        .as_array()
        .expect("required list")
        .iter()
        .map(|v| v.as_str().expect("string"))
        .collect();
    required.sort_unstable();
    assert_eq!(
        required,
        [
            "display_name",
            "has_bundled_mark",
            "id",
            "inherited",
            "protocol",
            "provider_kind"
        ]
    );

    let props = schema["properties"].as_object().expect("properties");
    assert!(
        props.contains_key("button_icon"),
        "button_icon is part of the shape even though it is nullable"
    );
    assert!(
        props["button_icon"]["type"]
            .as_array()
            .expect("button_icon is a nullable string")
            .iter()
            .any(|t| t == "null"),
        "button_icon is nullable — absent for most providers"
    );
    for absent in [
        "client_id",
        "client_secret",
        "metadata_url",
        "token_endpoint",
    ] {
        assert!(
            !props.contains_key(absent),
            "the unauthenticated provider response must not carry {absent} (§12.1 note 9)"
        );
    }
}

/// §12.1 note 11: the OAuth2 start response carries no PKCE material,
/// because the verifier is generated and held server-side. An SDK that
/// grew a `code_verifier` field here would be modelling something the
/// server deliberately never sends.
#[test]
fn openapi_oauth2_start_carries_no_pkce_material() {
    let spec = openapi();
    for schema in ["OAuth2StartRequest", "OAuth2StartResponse"] {
        let props = spec["components"]["schemas"][schema]["properties"]
            .as_object()
            .expect("properties");
        for pkce in ["code_verifier", "code_challenge", "code_challenge_method"] {
            assert!(
                !props.contains_key(pkce),
                "{schema} must not carry {pkce}: PKCE is server-side on this path (§12.1 note 11)"
            );
        }
    }
}

/// §12.1 note 12: the handoff request carries the code and nothing else.
#[test]
fn openapi_handoff_request_is_just_the_code() {
    let spec = openapi();
    let schema = &spec["components"]["schemas"]["SsoHandoffRequest"];
    let props = schema["properties"].as_object().expect("properties");
    assert_eq!(props.len(), 1);
    assert!(props.contains_key("code"));
    assert_eq!(
        schema["required"].as_array().expect("required"),
        &vec![Value::from("code")]
    );
}

// ---------------------------------------------------------------------------
// Wire shape, against what the SDK actually sends
// ---------------------------------------------------------------------------

/// The identifiers reach the server in the **query string**, and the `GET`
/// carries no body — the SDK half of the assertion above.
#[tokio::test]
async fn sso_providers_sends_the_identifiers_as_query_parameters_and_no_body() {
    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(SSO_PROVIDERS_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "providers": [] })))
        .mount(&mock_server)
        .await;

    let client = oidc_support::build_client(&mock_server.uri(), true);
    client
        .sso_providers(SsoProvidersParams {
            org_slug: Some("acme".into()),
            tenant_slug: Some("engineering".into()),
            ..Default::default()
        })
        .await
        .expect("sso_providers succeeds");

    let requests = mock_server
        .received_requests()
        .await
        .expect("recording enabled");
    let request = requests.last().expect("one request");
    assert_eq!(request.method, wiremock::http::Method::GET);
    assert_eq!(request.url.path(), SSO_PROVIDERS_PATH);

    let query: Vec<(String, String)> = request
        .url
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    assert!(query.contains(&("org_slug".to_string(), "acme".to_string())));
    assert!(query.contains(&("tenant_slug".to_string(), "engineering".to_string())));
    assert!(
        request.body.is_empty(),
        "sso_providers is a GET with no body (§12.1)"
    );
}

/// The three POSTs go to the paths §12.1 names, as `application/json`, with
/// the body fields the schemas declare — and, on the start call, with no
/// PKCE material invented client-side.
#[tokio::test]
async fn the_three_posts_send_json_bodies_to_the_contract_paths() {
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
        .and(path(SSO_OAUTH2_START_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "authorize_url": "https://github.com/login/oauth/authorize?...",
            "state": "oauth2-state",
            "expires_in_secs": 600,
        })))
        .mount(&mock_server)
        .await;
    for endpoint in [SSO_OAUTH2_CALLBACK_PATH, SSO_HANDOFF_PATH] {
        Mock::given(method("POST"))
            .and(path(endpoint))
            .respond_with(session_response(
                uuid::Uuid::new_v4(),
                session_id,
                &access_token,
            ))
            .mount(&mock_server)
            .await;
    }

    let client = oidc_support::build_client(&mock_server.uri(), true);

    client
        .sso_start_oauth2(SsoStartOauth2Params {
            federation_config_id: "22222222-2222-2222-2222-222222222222".into(),
            redirect_uri: "https://app.example.com/cb".into(),
            ..Default::default()
        })
        .await
        .expect("sso_start_oauth2 succeeds");
    client
        .sso_complete_oauth2(SsoCompleteOauth2Params {
            state: "oauth2-state".into(),
            code: "provider-code".into(),
        })
        .await
        .expect("sso_complete_oauth2 succeeds");
    client
        .sso_complete_handoff(SsoCompleteHandoffParams {
            code: "handoff-code".into(),
        })
        .await
        .expect("sso_complete_handoff succeeds");

    let requests = mock_server
        .received_requests()
        .await
        .expect("recording enabled");
    let posts: Vec<_> = requests
        .iter()
        .filter(|r| r.method == wiremock::http::Method::POST)
        .collect();
    assert_eq!(posts.len(), 3, "one wire call per operation");

    for request in &posts {
        assert_eq!(
            request
                .headers
                .get("content-type")
                .and_then(|v| v.to_str().ok()),
            Some("application/json"),
            "{} must be sent as application/json (§12.1)",
            request.url.path()
        );
    }

    let start: Value = serde_json::from_slice(&posts[0].body).expect("start body is JSON");
    assert_eq!(posts[0].url.path(), SSO_OAUTH2_START_PATH);
    assert_eq!(
        start["federation_config_id"],
        "22222222-2222-2222-2222-222222222222"
    );
    assert_eq!(start["redirect_uri"], "https://app.example.com/cb");
    for pkce in ["code_verifier", "code_challenge", "code_challenge_method"] {
        assert!(
            start.get(pkce).is_none(),
            "the SDK must not send {pkce}: PKCE is server-side here (§12.1 note 11)"
        );
    }

    let callback: Value = serde_json::from_slice(&posts[1].body).expect("callback body is JSON");
    assert_eq!(posts[1].url.path(), SSO_OAUTH2_CALLBACK_PATH);
    assert_eq!(
        callback,
        json!({"state": "oauth2-state", "code": "provider-code"})
    );

    let handoff: Value = serde_json::from_slice(&posts[2].body).expect("handoff body is JSON");
    assert_eq!(posts[2].url.path(), SSO_HANDOFF_PATH);
    assert_eq!(handoff, json!({"code": "handoff-code"}));
}

// ---------------------------------------------------------------------------
// §12.1 note 9 — an empty list is a success
// ---------------------------------------------------------------------------

/// The three cases note 9 makes indistinguishable — unknown organization,
/// known organization with nothing configured, and no workspace named at
/// all — are all `Ok` with an empty list. An SDK that mapped any of them to
/// an error would restore the two-valued answer the empty list removes, and
/// with it the organization-slug oracle.
#[tokio::test]
async fn an_empty_provider_list_is_a_success_not_an_error() {
    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(SSO_PROVIDERS_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "providers": [] })))
        .mount(&mock_server)
        .await;

    let client = oidc_support::build_client(&mock_server.uri(), true);

    for params in [
        // an organization that does not exist
        SsoProvidersParams {
            org_slug: Some("no-such-organization".into()),
            ..Default::default()
        },
        // a real one with nothing configured
        SsoProvidersParams {
            org_id: Some(oidc_support::org_id()),
            tenant_id: Some(oidc_support::tenant_id()),
            ..Default::default()
        },
        // and one naming no workspace beyond the client's own context
        SsoProvidersParams::default(),
    ] {
        let list = client
            .sso_providers(params)
            .await
            .expect("an empty provider list is a normal success (§12.1 note 9)");
        assert!(list.providers.is_empty());
    }
}

/// The nullable `button_icon` and the two booleans are surfaced faithfully:
/// absent for a branded provider, present as a `data:` URL for a generic
/// one whose operator uploaded a mark.
#[tokio::test]
async fn provider_fields_including_the_nullable_button_icon_round_trip() {
    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(SSO_PROVIDERS_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "providers": [
                {
                    "id": "33333333-3333-3333-3333-333333333333",
                    "provider_kind": "google",
                    "display_name": "Google",
                    "protocol": PROTOCOL_OIDC_CONNECT,
                    "has_bundled_mark": true,
                    "inherited": true,
                    "button_icon": null,
                },
                {
                    "id": "44444444-4444-4444-4444-444444444444",
                    "provider_kind": "generic_oauth2",
                    "display_name": "Acme SSO",
                    "protocol": PROTOCOL_OAUTH2,
                    "has_bundled_mark": false,
                    "inherited": false,
                    "button_icon": "data:image/png;base64,iVBORw0KGgo=",
                },
            ]
        })))
        .mount(&mock_server)
        .await;

    let client = oidc_support::build_client(&mock_server.uri(), true);
    let list = client
        .sso_providers(SsoProvidersParams::default())
        .await
        .expect("sso_providers succeeds");

    assert_eq!(list.providers.len(), 2);

    let google = &list.providers[0];
    assert_eq!(google.provider_kind, "google");
    assert_eq!(google.protocol, PROTOCOL_OIDC_CONNECT);
    assert!(google.has_bundled_mark);
    assert!(google.inherited, "inherited is reported, not computed");
    assert!(
        google.button_icon.is_none(),
        "button_icon is absent for most providers"
    );

    let acme = &list.providers[1];
    assert_eq!(acme.protocol, PROTOCOL_OAUTH2);
    assert!(!acme.has_bundled_mark);
    assert_eq!(
        acme.button_icon.as_deref(),
        Some("data:image/png;base64,iVBORw0KGgo=")
    );
}

// ---------------------------------------------------------------------------
// §12.1 note 10 — `protocol` selects the start operation
// ---------------------------------------------------------------------------

/// All three branches. The dispatch is written the way an application must
/// write it — on `protocol`, never on `provider_kind` — and the assertion
/// is on which endpoint the resulting call reached.
///
/// `provider_kind` is deliberately misleading in this fixture: the `Saml`
/// row is `google`, a kind whose OIDC connector is the one everybody
/// assumes. A dispatch that read the kind would send it to the OIDC start
/// endpoint and this test would catch it.
#[tokio::test]
async fn protocol_selects_the_start_operation_for_all_three_branches() {
    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(SSO_PROVIDERS_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "providers": [
                provider("55555555-5555-5555-5555-555555555555", "microsoft", PROTOCOL_OIDC_CONNECT),
                provider("66666666-6666-6666-6666-666666666666", "github", PROTOCOL_OAUTH2),
                provider("77777777-7777-7777-7777-777777777777", "google", PROTOCOL_SAML),
            ]
        })))
        .mount(&mock_server)
        .await;
    for endpoint in ["/api/v1/auth/federation/oidc/start", SSO_OAUTH2_START_PATH] {
        Mock::given(method("POST"))
            .and(path(endpoint))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "authorize_url": "https://upstream.example.com/authorize",
                "state": "dispatch-state",
                "expires_in_secs": 600,
            })))
            .mount(&mock_server)
            .await;
    }

    let client = oidc_support::build_client(&mock_server.uri(), true);
    let list = client
        .sso_providers(SsoProvidersParams::default())
        .await
        .expect("sso_providers succeeds");
    assert_eq!(list.providers.len(), 3);

    let mut saml_seen = false;
    for p in &list.providers {
        match p.protocol.as_str() {
            PROTOCOL_OIDC_CONNECT => {
                client
                    .sso_start(SsoStartParams {
                        federation_config_id: p.id.to_string(),
                        redirect_uri: "https://app.example.com/cb".into(),
                        ..Default::default()
                    })
                    .await
                    .expect("OidcConnect dispatches to sso_start");
            }
            PROTOCOL_OAUTH2 => {
                client
                    .sso_start_oauth2(SsoStartOauth2Params {
                        federation_config_id: p.id.to_string(),
                        redirect_uri: "https://app.example.com/cb".into(),
                        ..Default::default()
                    })
                    .await
                    .expect("OAuth2 dispatches to sso_start_oauth2");
            }
            PROTOCOL_SAML => {
                // Saml goes to the SAML login endpoint, which §12.1 note 10
                // says is *not* a §12 vocabulary operation. The assertion is
                // that this SDK offers no §12 start method for it — the
                // branch exists so that a Saml provider is never quietly
                // handed to one of the other two.
                saml_seen = true;
            }
            other => panic!("unknown protocol {other}"),
        }
    }
    assert!(saml_seen, "the Saml branch must be reachable");

    let requests = mock_server
        .received_requests()
        .await
        .expect("recording enabled");
    let started: Vec<&str> = requests
        .iter()
        .filter(|r| r.method == wiremock::http::Method::POST)
        .map(|r| r.url.path())
        .collect();
    assert_eq!(
        started,
        vec!["/api/v1/auth/federation/oidc/start", SSO_OAUTH2_START_PATH],
        "OidcConnect must reach the OIDC start endpoint and OAuth2 the OAuth2 one — \
         and the Saml provider must reach neither"
    );
}

// ---------------------------------------------------------------------------
// §12.1 note 12 — a handoff 401 is terminal
// ---------------------------------------------------------------------------

/// Unknown, expired and already-redeemed all answer the same `401`, on
/// purpose. The code is spent either way, so a retry cannot succeed and
/// would only widen the window in which the code sits in a log. Exactly one
/// wire call must leave the SDK.
#[tokio::test]
async fn a_handoff_401_is_terminal_and_is_not_retried() {
    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(SSO_HANDOFF_PATH))
        .respond_with(ResponseTemplate::new(401).set_body_string("unauthorized"))
        .mount(&mock_server)
        .await;

    let client = oidc_support::build_client(&mock_server.uri(), true);
    let err = client
        .sso_complete_handoff(SsoCompleteHandoffParams {
            code: "spent-or-expired-or-never-existed".into(),
        })
        .await
        .expect_err("a 401 from the handoff endpoint is an error");
    assert!(matches!(err, AxiamError::Auth { .. }), "got {err:?}");

    let requests = mock_server
        .received_requests()
        .await
        .expect("recording enabled");
    assert_eq!(
        requests.len(),
        1,
        "the handoff redemption must not be retried (§12.1 note 12): the code is \
         gone whether or not the call succeeded"
    );
}

/// The TTL and the query parameter name are part of the contract a caller
/// codes against: it reads the code out of `?axiam_handoff=` and has 60
/// seconds to spend it.
#[test]
fn the_handoff_parameter_and_ttl_are_what_the_contract_says() {
    assert_eq!(HANDOFF_QUERY_PARAM, "axiam_handoff");
    assert_eq!(HANDOFF_CODE_TTL_SECS, 60);
}

// ---------------------------------------------------------------------------
// §12.1 rule 12a — a 400 from a start call is a configuration refusal
// ---------------------------------------------------------------------------

/// On the SAML and Apple flows the identity provider never validates the
/// SPA `redirect_uri`, so the server confines it to its own issuer origin
/// plus `AXIAM__AUTH__SSO_SPA_ORIGINS` and answers `400` otherwise.
///
/// That `400` is a **configuration** refusal — §2's `400` row, whose
/// taxonomy member in this SDK is [`AxiamError::Network`] ("malformed
/// request / SDK programming error"), as distinct from the `401`
/// [`AxiamError::Auth`] an unknown workspace gets. It must not be retried:
/// the deployment will refuse the same origin every time. Asserted on both
/// start operations, because Apple arrives over the OIDC one and SAML over
/// neither — a caller can reach the refusal from either entry point.
#[tokio::test]
async fn a_400_from_a_start_call_is_a_configuration_error_and_is_not_retried() {
    for (endpoint, is_oauth2) in [
        ("/api/v1/auth/federation/oidc/start", false),
        (SSO_OAUTH2_START_PATH, true),
    ] {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(endpoint))
            .respond_with(
                ResponseTemplate::new(400)
                    .set_body_string("redirect_uri origin is not permitted for this deployment"),
            )
            .mount(&mock_server)
            .await;

        let client = oidc_support::build_client(&mock_server.uri(), true);
        let err = if is_oauth2 {
            client
                .sso_start_oauth2(SsoStartOauth2Params {
                    federation_config_id: "88888888-8888-8888-8888-888888888888".into(),
                    redirect_uri: "https://attacker.example/".into(),
                    ..Default::default()
                })
                .await
                .expect_err("a refused redirect_uri origin is an error")
        } else {
            client
                .sso_start(SsoStartParams {
                    federation_config_id: "88888888-8888-8888-8888-888888888888".into(),
                    redirect_uri: "https://attacker.example/".into(),
                    ..Default::default()
                })
                .await
                .expect_err("a refused redirect_uri origin is an error")
        };

        assert!(
            matches!(err, AxiamError::Network { .. }),
            "rule 12a: a 400 from {endpoint} is a configuration refusal, not an \
             authentication outcome — got {err:?}"
        );

        let requests = mock_server
            .received_requests()
            .await
            .expect("recording enabled");
        assert_eq!(
            requests.len(),
            1,
            "rule 12a: the refusal must not be retried — the origin will be refused again"
        );
    }
}

/// A `401` from a start call is the uniform "unknown workspace or provider"
/// answer, and is a *different* taxonomy member from the rule-12a `400`.
/// Asserted so the two cannot quietly collapse into one.
#[tokio::test]
async fn a_401_from_a_start_call_stays_an_auth_error() {
    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(SSO_OAUTH2_START_PATH))
        .respond_with(ResponseTemplate::new(401).set_body_string("unauthorized"))
        .mount(&mock_server)
        .await;

    let client = oidc_support::build_client(&mock_server.uri(), true);
    let err = client
        .sso_start_oauth2(SsoStartOauth2Params {
            federation_config_id: "99999999-9999-9999-9999-999999999999".into(),
            redirect_uri: "https://app.example.com/cb".into(),
            ..Default::default()
        })
        .await
        .expect_err("an unknown workspace is a 401");
    assert!(matches!(err, AxiamError::Auth { .. }), "got {err:?}");
}

// ---------------------------------------------------------------------------
// §12.3 cross-cutting
// ---------------------------------------------------------------------------

/// §5 rule 2 admits no exceptions: `X-Tenant-ID` is emitted on all four of
/// the new operations, exactly as on the nine that came before.
#[tokio::test]
async fn all_four_operations_emit_the_tenant_header() {
    let mock_server = MockServer::start().await;
    let key = mount_session_jwks(&mock_server).await;
    let session_id = uuid::Uuid::new_v4();
    let access_token = oidc_support::sign_session_access_token(
        &key,
        oidc_support::tenant_id(),
        oidc_support::org_id(),
        session_id,
    );

    Mock::given(method("GET"))
        .and(path(SSO_PROVIDERS_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "providers": [] })))
        .mount(&mock_server)
        .await;
    Mock::given(method("POST"))
        .and(path(SSO_OAUTH2_START_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "authorize_url": "https://upstream.example.com/authorize",
            "state": "s",
            "expires_in_secs": 600,
        })))
        .mount(&mock_server)
        .await;
    for endpoint in [SSO_OAUTH2_CALLBACK_PATH, SSO_HANDOFF_PATH] {
        Mock::given(method("POST"))
            .and(path(endpoint))
            .respond_with(session_response(
                uuid::Uuid::new_v4(),
                session_id,
                &access_token,
            ))
            .mount(&mock_server)
            .await;
    }

    let client = oidc_support::build_client(&mock_server.uri(), true);
    client
        .sso_providers(SsoProvidersParams::default())
        .await
        .expect("providers");
    client
        .sso_start_oauth2(SsoStartOauth2Params {
            federation_config_id: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa".into(),
            redirect_uri: "https://app.example.com/cb".into(),
            ..Default::default()
        })
        .await
        .expect("start");
    client
        .sso_complete_oauth2(SsoCompleteOauth2Params {
            state: "s".into(),
            code: "c".into(),
        })
        .await
        .expect("callback");
    client
        .sso_complete_handoff(SsoCompleteHandoffParams { code: "h".into() })
        .await
        .expect("handoff");

    let requests = mock_server
        .received_requests()
        .await
        .expect("recording enabled");
    let federation: Vec<_> = requests
        .iter()
        .filter(|r| r.url.path().starts_with("/api/v1/auth/federation/"))
        .collect();
    assert_eq!(federation.len(), 4, "one call per operation");
    for request in federation {
        assert!(
            request.headers.contains_key("x-tenant-id"),
            "{} must carry X-Tenant-ID (§5 rule 2)",
            request.url.path()
        );
    }
}

/// The two session-establishing operations absorb the `Set-Cookie` session
/// exactly as `sso_complete` does, so `refresh()` works afterwards — the
/// §4 cookie-jar requirement applies verbatim (§12.1 note 6).
#[tokio::test]
async fn the_completions_absorb_the_session_cookies() {
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
        .and(path(SSO_HANDOFF_PATH))
        .respond_with(session_response(user_id, session_id, &access_token))
        .mount(&mock_server)
        .await;
    // The follow-on §1 refresh, which works only if the sync ran: it needs a
    // cached access token AND an org_id resolved from it.
    let rotated = oidc_support::sign_session_access_token(
        &key,
        oidc_support::tenant_id(),
        oidc_support::org_id(),
        session_id,
    );
    Mock::given(method("POST"))
        .and(path("/api/v1/auth/refresh"))
        .respond_with({
            let mut response =
                ResponseTemplate::new(200).set_body_json(json!({ "expires_in": 900 }));
            for cookie in
                oidc_support::session_cookie_headers(&rotated, "rotated-refresh", "rotated-csrf")
            {
                response = response.append_header("Set-Cookie", cookie.as_str());
            }
            response
        })
        .mount(&mock_server)
        .await;

    let client = oidc_support::build_client(&mock_server.uri(), true);
    let result = client
        .sso_complete_handoff(SsoCompleteHandoffParams {
            code: "good-code".into(),
        })
        .await
        .expect("handoff redemption succeeds");

    assert_eq!(result.user_id, user_id);
    assert_eq!(result.session_id, session_id);
    assert_eq!(result.expires_in, 900);
    assert_eq!(result.redirect_uri, "https://app.example.com/post-login");
    // §12.1 note 6: the success body carries no token material.
    assert!(!format!("{result:?}").contains(&access_token));
    // And the session really was absorbed — this is the observable proof.
    client
        .refresh()
        .await
        .expect("refresh() must work after sso_complete_handoff, exactly as after login()");
}
