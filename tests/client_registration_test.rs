//! RFC 7592 client configuration — CONTRACT.md §28.12.6's five required tests.
//!
//! Every token here is generated at run time: a literal would be a credential
//! in the repository, and the redaction test needs a value no fixture shares.

#![cfg(feature = "rest")]

#[path = "oidc_support/mod.rs"]
mod oidc_support;

use std::sync::{Arc, Mutex};

use axiam_sdk::client::AxiamClient;
use axiam_sdk::oidc::{ClientRegistration, SsoCompleteParams};
use axiam_sdk::{AxiamError, Sensitive};
use serde_json::{Value, json};
use uuid::Uuid;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

const CLIENT: &str = "dcr-client-1";

fn fresh_token() -> String {
    // 43 base64url-ish characters, like the server's, but random per run.
    format!(
        "{}{}",
        Uuid::new_v4().simple(),
        &Uuid::new_v4().simple().to_string()[..11]
    )
}

fn registration_uri(server: &MockServer) -> String {
    format!(
        "{}/oauth2/register/{CLIENT}?tenant_id={}",
        server.uri(),
        oidc_support::tenant_id()
    )
}

fn registration_body(server: &MockServer, extra: Value) -> Value {
    let mut body = json!({
        "client_id": CLIENT,
        "client_id_issued_at": 1_700_000_000,
        "client_name": "Agent",
        "redirect_uris": ["https://agent.example.test/cb"],
        "grant_types": ["authorization_code"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "private_key_jwt",
        "scope": "openid",
        "registration_client_uri": registration_uri(server),
        "jwks_uri": "https://agent.example.test/jwks",
    });
    for (k, v) in extra.as_object().unwrap() {
        body[k] = v.clone();
    }
    body
}

#[derive(Default, Clone)]
struct Seen {
    method: String,
    authorization: Option<String>,
    cookie: Option<String>,
    query: Option<String>,
    body: Vec<u8>,
}

async fn record(
    server: &MockServer,
    verb: &str,
    template: ResponseTemplate,
) -> Arc<Mutex<Vec<Seen>>> {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&seen);
    Mock::given(method(verb))
        .and(path(format!("/oauth2/register/{CLIENT}")))
        .respond_with(move |req: &Request| {
            sink.lock().unwrap().push(Seen {
                method: req.method.to_string(),
                authorization: req
                    .headers
                    .get("authorization")
                    .map(|v| v.to_str().unwrap().to_owned()),
                cookie: req
                    .headers
                    .get("cookie")
                    .map(|v| v.to_str().unwrap().to_owned()),
                query: req.url.query().map(str::to_owned),
                body: req.body.clone(),
            });
            template.clone()
        })
        .mount(server)
        .await;
    seen
}

/// Count every `/api/v1/auth/refresh` — §28.12.2 rule 3 says a `401` from
/// these operations never reaches the §9 guard.
async fn count_refreshes(server: &MockServer) -> Arc<Mutex<usize>> {
    let hits = Arc::new(Mutex::new(0usize));
    let sink = Arc::clone(&hits);
    Mock::given(method("POST"))
        .and(path("/api/v1/auth/refresh"))
        .respond_with(move |_: &Request| {
            *sink.lock().unwrap() += 1;
            ResponseTemplate::new(500)
        })
        .mount(server)
        .await;
    hits
}

/// A client holding a real SDK session (cookies + access token), so "the
/// session is not attached" is a claim about something that exists.
async fn client_with_session(server: &MockServer) -> (AxiamClient, String) {
    let key = oidc_support::generate_signing_key("dcr-session-key");
    Mock::given(method("GET"))
        .and(path("/oauth2/jwks"))
        .respond_with(ResponseTemplate::new(200).set_body_json(oidc_support::jwks_body(&[&key])))
        .mount(server)
        .await;
    let session_id = Uuid::new_v4();
    let access = oidc_support::sign_session_access_token(
        &key,
        oidc_support::tenant_id(),
        oidc_support::org_id(),
        session_id,
    );
    let mut ok = ResponseTemplate::new(200).set_body_json(json!({
        "user_id": Uuid::new_v4(),
        "session_id": session_id,
        "expires_in": 900,
        "redirect_uri": "https://app.example.test/",
    }));
    for c in oidc_support::session_cookie_headers(&access, &fresh_token(), "csrf-v") {
        ok = ok.append_header("Set-Cookie", c.as_str());
    }
    Mock::given(method("POST"))
        .and(path("/api/v1/auth/federation/oidc/callback"))
        .respond_with(ok)
        .mount(server)
        .await;
    let client = oidc_support::build_client(&server.uri(), false);
    client
        .sso_complete(SsoCompleteParams {
            state: "s".into(),
            code: "c".into(),
        })
        .await
        .expect("session established");
    (client, access)
}

// ── 1. Origin refusal ───────────────────────────────────────────────────────

#[tokio::test]
async fn a_uri_at_another_origin_is_refused_locally_and_nothing_is_sent() {
    let server = MockServer::start().await;
    let reads = record(&server, "GET", ResponseTemplate::new(200)).await;
    let deletes = record(&server, "DELETE", ResponseTemplate::new(204)).await;
    let puts = record(&server, "PUT", ResponseTemplate::new(200)).await;
    let client = oidc_support::build_client(&server.uri(), false);
    let token = Sensitive::new(fresh_token());

    let port = url::Url::parse(&server.uri()).unwrap().port().unwrap();
    let other_host = format!("http://localhost:{port}/oauth2/register/{CLIENT}");
    let other_port = format!("http://127.0.0.1:{}/oauth2/register/{CLIENT}", port + 1);
    for uri in [other_host.as_str(), other_port.as_str()] {
        let e = client
            .read_client_registration(uri, &token)
            .await
            .unwrap_err();
        assert!(e.validation().is_some(), "{uri}: {e}");
        let e = client
            .delete_client_registration(uri, &token)
            .await
            .unwrap_err();
        assert!(e.validation().is_some(), "{uri}: {e}");
        let e = client
            .update_client_registration(uri, &token, &ClientRegistration::default())
            .await
            .unwrap_err();
        assert!(e.validation().is_some(), "{uri}: {e}");
    }

    // `http` against an `https` base URL: the base is https here, the URI is not.
    let https_client = AxiamClient::builder()
        .base_url("https://iam.example.test")
        .unwrap()
        .tenant_id(oidc_support::tenant_id())
        .build()
        .unwrap();
    let e = https_client
        .read_client_registration("http://iam.example.test/oauth2/register/x", &token)
        .await
        .unwrap_err();
    assert!(e.validation().is_some());

    assert!(reads.lock().unwrap().is_empty());
    assert!(deletes.lock().unwrap().is_empty());
    assert!(puts.lock().unwrap().is_empty());
}

// ── 2. Header only ──────────────────────────────────────────────────────────

#[tokio::test]
async fn read_and_delete_send_the_bearer_only_and_keep_the_query_verbatim() {
    let server = MockServer::start().await;
    let (client, session_access) = client_with_session(&server).await;
    let reads = record(
        &server,
        "GET",
        ResponseTemplate::new(200).set_body_json(registration_body(&server, json!({}))),
    )
    .await;
    let deletes = record(&server, "DELETE", ResponseTemplate::new(204)).await;
    let token = fresh_token();
    let secret = Sensitive::new(token.clone());

    let read = client
        .read_client_registration(&registration_uri(&server), &secret)
        .await
        .expect("read");
    assert_eq!(read.client_id, CLIENT);
    assert!(read.registration_access_token.is_none());
    client
        .delete_client_registration(&registration_uri(&server), &secret)
        .await
        .expect("a 204 on delete returns normally");

    for seen in reads
        .lock()
        .unwrap()
        .iter()
        .chain(deletes.lock().unwrap().iter())
    {
        assert_eq!(
            seen.authorization.as_deref(),
            Some(format!("Bearer {token}").as_str())
        );
        assert!(seen.cookie.is_none(), "{}: no session cookie", seen.method);
        assert!(
            !seen
                .authorization
                .as_deref()
                .unwrap()
                .contains(&session_access),
            "never the SDK's access token"
        );
        assert!(seen.body.is_empty(), "{}: no body", seen.method);
        assert_eq!(
            seen.query.as_deref(),
            Some(format!("tenant_id={}", oidc_support::tenant_id()).as_str()),
            "the URI's own query, verbatim, and the token never in it"
        );
    }
}

// ── 3. Update body ──────────────────────────────────────────────────────────

#[tokio::test]
async fn update_drops_the_five_server_stated_members_and_returns_the_rotated_token() {
    let server = MockServer::start().await;
    let rotated = fresh_token();
    let puts = record(
        &server,
        "PUT",
        ResponseTemplate::new(200).set_body_json(registration_body(
            &server,
            json!({ "registration_access_token": rotated }),
        )),
    )
    .await;
    let client = oidc_support::build_client(&server.uri(), false);

    let mut metadata = ClientRegistration::from_json(registration_body(
        &server,
        json!({
            "registration_access_token": fresh_token(),
            "client_secret": fresh_token(),
            "client_secret_expires_at": 0,
            "backchannel_token_delivery_mode": "poll",
        }),
    ))
    .unwrap();
    metadata.client_name = Some("Agent v2".into());

    let updated = client
        .update_client_registration(
            &registration_uri(&server),
            &Sensitive::new(fresh_token()),
            &metadata,
        )
        .await
        .expect("update");
    assert_eq!(
        updated
            .registration_access_token
            .as_ref()
            .map(|t| t.expose().as_str()),
        Some(rotated.as_str())
    );

    let seen = puts.lock().unwrap();
    assert_eq!(seen.len(), 1);
    let body: Value = serde_json::from_slice(&seen[0].body).unwrap();
    for gone in [
        "registration_access_token",
        "registration_client_uri",
        "client_secret_expires_at",
        "client_id_issued_at",
        "client_secret",
    ] {
        assert!(body.get(gone).is_none(), "{gone} must not be sent");
    }
    assert_eq!(body["client_id"], CLIENT);
    assert_eq!(body["client_name"], "Agent v2");
    assert_eq!(body["jwks_uri"], "https://agent.example.test/jwks");
    assert_eq!(
        body["backchannel_token_delivery_mode"], "poll",
        "unknown members round-trip"
    );
}

/// §28.12.2 rule 4 as contract 1.59 reads it (§34.2 P12.4): the replacement
/// is built from what the read carried. A list the read lacked is not sent —
/// never as `[]` — and a member of an unexpected shape is sent back as read.
#[tokio::test]
async fn update_sends_no_list_the_read_lacked_and_keeps_an_unexpected_shape() {
    let server = MockServer::start().await;
    let puts = record(
        &server,
        "PUT",
        ResponseTemplate::new(200).set_body_json(registration_body(
            &server,
            json!({ "registration_access_token": fresh_token() }),
        )),
    )
    .await;
    let client = oidc_support::build_client(&server.uri(), false);

    let mut read = registration_body(
        &server,
        json!({
            // An item of an unexpected type, and a string where a list belongs.
            "redirect_uris": ["https://agent.example.test/cb", 42],
            "response_types": "code",
        }),
    );
    read.as_object_mut().unwrap().remove("grant_types");
    let metadata = ClientRegistration::from_json(read).unwrap();
    client
        .update_client_registration(
            &registration_uri(&server),
            &Sensitive::new(fresh_token()),
            &metadata,
        )
        .await
        .expect("update");

    // An explicitly empty list is carried, and so is sent back.
    let mut read = registration_body(&server, json!({ "grant_types": [] }));
    read.as_object_mut().unwrap().remove("response_types");
    let metadata = ClientRegistration::from_json(read).unwrap();
    client
        .update_client_registration(
            &registration_uri(&server),
            &Sensitive::new(fresh_token()),
            &metadata,
        )
        .await
        .expect("update");

    let seen = puts.lock().unwrap();
    assert_eq!(seen.len(), 2);
    let first: Value = serde_json::from_slice(&seen[0].body).unwrap();
    assert!(
        first.get("grant_types").is_none(),
        "a list the read lacked is not sent: {}",
        first.get("grant_types").unwrap_or(&Value::Null)
    );
    assert_eq!(
        first["redirect_uris"],
        json!(["https://agent.example.test/cb", 42]),
        "a list with an item of an unexpected type is kept as read"
    );
    assert_eq!(
        first["response_types"],
        json!("code"),
        "a member of an unexpected shape is kept as read"
    );
    let second: Value = serde_json::from_slice(&seen[1].body).unwrap();
    assert_eq!(second["grant_types"], json!([]));
    assert!(second.get("response_types").is_none());
    assert_eq!(
        second["redirect_uris"],
        json!(["https://agent.example.test/cb"])
    );
}

#[tokio::test]
async fn an_update_answered_503_is_not_retried() {
    let server = MockServer::start().await;
    let puts = record(&server, "PUT", ResponseTemplate::new(503)).await;
    let client = oidc_support::build_client(&server.uri(), false);
    let metadata = ClientRegistration::from_json(registration_body(&server, json!({}))).unwrap();
    let e = client
        .update_client_registration(
            &registration_uri(&server),
            &Sensitive::new(fresh_token()),
            &metadata,
        )
        .await
        .unwrap_err();
    assert!(matches!(e, AxiamError::Network { .. }));
    assert_eq!(puts.lock().unwrap().len(), 1, "exactly one request");
}

#[tokio::test]
async fn a_delete_answered_503_is_not_retried_and_a_read_is() {
    let server = MockServer::start().await;
    let deletes = record(&server, "DELETE", ResponseTemplate::new(503)).await;
    let reads = record(&server, "GET", ResponseTemplate::new(503)).await;
    let client = oidc_support::build_client(&server.uri(), false);
    let token = Sensitive::new(fresh_token());
    client
        .delete_client_registration(&registration_uri(&server), &token)
        .await
        .unwrap_err();
    assert_eq!(deletes.lock().unwrap().len(), 1);
    client
        .read_client_registration(&registration_uri(&server), &token)
        .await
        .unwrap_err();
    assert!(
        reads.lock().unwrap().len() > 1,
        "the read MAY be retried per §16"
    );
}

// ── 4. Errors ───────────────────────────────────────────────────────────────

#[tokio::test]
async fn a_401_invalid_token_is_an_oauth_protocol_error_and_refreshes_nothing() {
    let server = MockServer::start().await;
    let (client, _) = client_with_session(&server).await;
    let refreshes = count_refreshes(&server).await;
    record(
        &server,
        "GET",
        ResponseTemplate::new(401)
            .append_header("WWW-Authenticate", "Bearer error=\"invalid_token\"")
            .set_body_json(json!({"error": "invalid_token", "error_description": "no"})),
    )
    .await;
    let e = client
        .read_client_registration(&registration_uri(&server), &Sensitive::new(fresh_token()))
        .await
        .unwrap_err();
    assert_eq!(e.oauth_error_code(), Some("invalid_token"));
    assert!(matches!(e, AxiamError::Auth { .. }));
    assert_eq!(*refreshes.lock().unwrap(), 0, "§9 is not entered");
}

#[tokio::test]
async fn a_400_invalid_client_metadata_is_an_oauth_protocol_error() {
    let server = MockServer::start().await;
    record(
        &server,
        "PUT",
        ResponseTemplate::new(400).set_body_json(
            json!({"error": "invalid_client_metadata", "error_description": "scope"}),
        ),
    )
    .await;
    let client = oidc_support::build_client(&server.uri(), false);
    let metadata = ClientRegistration::from_json(registration_body(&server, json!({}))).unwrap();
    let e = client
        .update_client_registration(
            &registration_uri(&server),
            &Sensitive::new(fresh_token()),
            &metadata,
        )
        .await
        .unwrap_err();
    assert_eq!(e.oauth_error_code(), Some("invalid_client_metadata"));
}

// ── 5. Redaction ────────────────────────────────────────────────────────────

fn assert_no_fragment(haystack: &str, secret: &str) {
    // The failure message names neither the fragment nor the haystack: a
    // failing redaction test must not itself print the secret it caught.
    for i in 0..=secret.len().saturating_sub(8) {
        assert!(
            !haystack.contains(&secret[i..i + 8]),
            "an 8-character fragment of the secret (offset {i}) appears in a rendering"
        );
    }
}

#[tokio::test]
async fn neither_the_token_nor_the_secret_reaches_any_rendering() {
    let server = MockServer::start().await;
    let token = fresh_token();
    let secret = fresh_token();
    let registration = ClientRegistration::from_json(registration_body(
        &server,
        json!({"registration_access_token": token, "client_secret": secret}),
    ))
    .unwrap();
    let debug = format!("{registration:?}");
    let pretty = format!("{registration:#?}");
    for rendering in [&debug, &pretty] {
        assert_no_fragment(rendering, &token);
        assert_no_fragment(rendering, &secret);
    }

    // An error raised by an operation given the token.
    record(
        &server,
        "GET",
        ResponseTemplate::new(401).set_body_json(json!({"error": "invalid_token"})),
    )
    .await;
    let client = oidc_support::build_client(&server.uri(), false);
    let e = client
        .read_client_registration(&registration_uri(&server), &Sensitive::new(token.clone()))
        .await
        .unwrap_err();
    assert_no_fragment(&format!("{e} {e:?}"), &token);
    let refused = client
        .read_client_registration(
            "https://elsewhere.example.test/r",
            &Sensitive::new(token.clone()),
        )
        .await
        .unwrap_err();
    assert_no_fragment(&format!("{refused} {refused:?}"), &token);
}
