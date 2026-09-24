//! CONTRACT.md §6.1 rules 6–10 (contract 1.51) — `authenticate_device()`.
//!
//! The mTLS device login: no body, the certificate is the credential, three
//! fields back, no refresh token. The mock here is plain HTTP on loopback, so
//! the certificate is configured but never presented; what these tests pin is
//! the SDK's side — the gate before the wire, the request shape, the adoption,
//! and the refusal to send a `401` into the §9 refresh guard.

#![cfg(feature = "rest")]

mod management_support;

use axiam_sdk::AxiamError;
use axiam_sdk::Sensitive;
use axiam_sdk::client::AxiamClient;
use axiam_sdk::management::PageRequest;
use serde_json::json;
use uuid::Uuid;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

use management_support::{
    ORG_ID, TENANT_ID, anonymous_client, logged_in_client_as, mount, mount_jwks, sign_claims,
};

const DEVICE_PATH: &str = "/api/v1/auth/device";

fn identity() -> (String, String) {
    let cert = rcgen::generate_simple_self_signed(vec!["device-001".to_string()])
        .expect("rcgen certificate");
    (cert.cert.pem(), cert.signing_key.serialize_pem())
}

fn device_client(base_url: &str) -> AxiamClient {
    let (cert, key) = identity();
    AxiamClient::builder()
        .base_url(base_url)
        .unwrap()
        .tenant_id(Uuid::parse_str(TENANT_ID).unwrap())
        .org_id(Uuid::parse_str(ORG_ID).unwrap())
        .retry_enabled(false)
        .with_client_cert(cert.as_bytes(), key.as_bytes())
        .unwrap()
        .build()
        .unwrap()
}

/// The token a server mints for a device: a service-account token bound to
/// the presenting certificate (§6.1 rules 9–10).
fn device_token() -> String {
    sign_claims(&json!({
        "sub": Uuid::new_v4().to_string(),
        "sub_kind": "service_account",
        "aud": "axiam:m2m",
        "tenant_id": TENANT_ID,
        "org_id": ORG_ID,
        "iss": "axiam-test",
        "iat": 0,
        "exp": 9_999_999_999i64,
        "jti": Uuid::new_v4().to_string(),
        "cnf": { "x5t#S256": "dGhpcy1pcy1hLXRlc3QtdGh1bWJwcmludC1ub3QtcmVhbA" },
    }))
}

async fn mount_device_login(server: &MockServer, token: &str) {
    Mock::given(method("POST"))
        .and(path(DEVICE_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": token, "token_type": "Bearer", "expires_in": 900,
        })))
        .mount(server)
        .await;
}

async fn requests_to(server: &MockServer, route: &str) -> Vec<Request> {
    server
        .received_requests()
        .await
        .unwrap_or_default()
        .into_iter()
        .filter(|r| r.url.path() == route)
        .collect()
}

fn header<'a>(request: &'a Request, name: &str) -> Option<&'a str> {
    request.headers.get(name).map(|v| v.to_str().unwrap())
}

// ---------------------------------------------------------------------------
// Rule 7 — unreachable without a certificate
// ---------------------------------------------------------------------------

/// Without a certificate the server can only answer `401`, so the SDK answers
/// first: `AuthError`, zero wire calls.
#[tokio::test]
async fn without_a_certificate_it_fails_with_no_wire_call() {
    let server = MockServer::start().await;
    let client = anonymous_client(&server.uri());

    let err = client
        .authenticate_device()
        .await
        .expect_err("no certificate configured");

    assert!(matches!(err, AxiamError::Auth { .. }), "{err:?}");
    assert!(err.to_string().contains("with_client_cert"), "{err}");
    assert!(
        server
            .received_requests()
            .await
            .unwrap_or_default()
            .is_empty(),
        "§6.1 rule 7: refused before the network"
    );
}

// ---------------------------------------------------------------------------
// Rule 6 — one call, no body, three fields back, adopted
// ---------------------------------------------------------------------------

#[tokio::test]
async fn it_posts_no_body_and_returns_the_three_fields() {
    let server = MockServer::start().await;
    mount_jwks(&server).await;
    let token = device_token();
    mount_device_login(&server, &token).await;
    let client = device_client(&server.uri());

    let result = client.authenticate_device().await.expect("device login");

    assert_eq!(result.access_token.expose(), &token);
    assert_eq!(result.token_type, "Bearer");
    assert_eq!(result.expires_in, 900);
    let rendered = format!("{result:?}");
    assert!(
        !rendered.contains(&token),
        "§7: the token must not appear in Debug: {rendered}"
    );

    let sent = requests_to(&server, DEVICE_PATH).await;
    assert_eq!(sent.len(), 1, "exactly one attempt");
    assert!(sent[0].body.is_empty(), "the certificate is the credential");
    assert_eq!(header(&sent[0], "X-Tenant-ID"), Some(TENANT_ID));
    assert!(header(&sent[0], "authorization").is_none());
}

/// The token is adopted: what follows sends it as a bearer — on the §27
/// surface and on `check_access` alike — which a cookie session never does.
#[tokio::test]
async fn the_token_is_adopted_as_the_clients_bearer_credential() {
    let server = MockServer::start().await;
    mount_jwks(&server).await;
    let token = device_token();
    mount_device_login(&server, &token).await;
    mount(
        &server,
        "GET",
        "/api/v1/groups",
        200,
        r#"{"items": [], "total": 0, "offset": 0, "limit": 50}"#,
    )
    .await;
    mount(
        &server,
        "POST",
        "/api/v1/authz/check",
        200,
        r#"{"allowed": true}"#,
    )
    .await;
    let client = device_client(&server.uri());
    client.authenticate_device().await.unwrap();

    client.groups().list(PageRequest::first(50)).await.unwrap();
    assert!(client.can("read", Uuid::new_v4(), None).await.unwrap());

    let expected = format!("Bearer {token}");
    for route in ["/api/v1/groups", "/api/v1/authz/check"] {
        let sent = requests_to(&server, route).await;
        assert_eq!(
            header(&sent[0], "authorization"),
            Some(expected.as_str()),
            "{route}"
        );
    }
}

/// A client that held a cookie session and then logs in as a device must
/// not send the old session's cookie beside the device token: the server
/// reads the cookie **first**, so it would silently win and the request would
/// run as the previous principal.
#[tokio::test]
async fn a_device_login_withholds_a_previous_cookie_session() {
    let server = MockServer::start().await;
    // Mounts JWKS and a cookie-setting login.
    let _ = logged_in_client_as(
        &server,
        json!({ "id": Uuid::new_v4(), "username": "u", "email": "u@example.com" }),
    )
    .await;
    let token = device_token();
    mount_device_login(&server, &token).await;
    mount(
        &server,
        "GET",
        "/api/v1/groups",
        200,
        r#"{"items": [], "total": 0, "offset": 0, "limit": 50}"#,
    )
    .await;

    let client = device_client(&server.uri());
    client
        .login("u@example.com", &Uuid::new_v4().to_string())
        .await
        .expect("cookie session");
    client.authenticate_device().await.expect("device login");
    client.groups().list(PageRequest::first(50)).await.unwrap();

    let device_call = &requests_to(&server, DEVICE_PATH).await[0];
    let cookies = header(device_call, "cookie").unwrap_or("");
    assert!(
        !cookies.contains("axiam_access"),
        "the device login presents the certificate, not the session: {cookies:?}"
    );

    let sent = &requests_to(&server, "/api/v1/groups").await[0];
    let cookies = header(sent, "cookie").unwrap_or("");
    assert!(
        !cookies.contains("axiam_access"),
        "the old session's cookie must be withheld: {cookies:?}"
    );
    assert_eq!(
        header(sent, "authorization"),
        Some(format!("Bearer {token}").as_str())
    );
}

/// The I4 twin: a cookie session sends no `Authorization` header — the device
/// path must not have changed how every other session travels.
#[tokio::test]
async fn a_cookie_session_still_sends_no_authorization_header() {
    let server = MockServer::start().await;
    let client = logged_in_client_as(
        &server,
        json!({ "id": Uuid::new_v4(), "username": "u", "email": "u@example.com" }),
    )
    .await;
    mount(
        &server,
        "GET",
        "/api/v1/groups",
        200,
        r#"{"items": [], "total": 0, "offset": 0, "limit": 50}"#,
    )
    .await;

    client.groups().list(PageRequest::first(50)).await.unwrap();

    let sent = &requests_to(&server, "/api/v1/groups").await[0];
    assert!(header(sent, "authorization").is_none());
    assert!(
        header(sent, "cookie")
            .unwrap_or("")
            .contains("axiam_access")
    );
}

// ---------------------------------------------------------------------------
// Rules 6 and 8 — refusals, and never the refresh guard
// ---------------------------------------------------------------------------

/// A refused certificate is `401` (server T22.4), surfaced as `AuthError` with
/// the server's message verbatim, and never sent to the §9 guard — this *is*
/// the login.
#[tokio::test]
async fn a_refused_certificate_is_an_auth_error_and_never_refreshes() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(DEVICE_PATH))
        .respond_with(
            ResponseTemplate::new(401)
                .set_body_string("certificate is not bound to a service account"),
        )
        .mount(&server)
        .await;
    management_support::mount_refresh(&server).await;
    let client = device_client(&server.uri());

    let err = client
        .authenticate_device()
        .await
        .expect_err("the server refuses");

    assert!(matches!(err, AxiamError::Auth { .. }), "{err:?}");
    assert!(
        err.to_string()
            .contains("certificate is not bound to a service account"),
        "verbatim: {err}"
    );
    assert_eq!(requests_to(&server, DEVICE_PATH).await.len(), 1);
    assert!(
        requests_to(&server, "/api/v1/auth/refresh")
            .await
            .is_empty()
    );
}

/// The route is rate-limited per IP. A `429` is not an authentication
/// failure, and a login is attempted exactly once (§16).
#[tokio::test]
async fn a_rate_limited_login_is_not_an_auth_error_and_is_not_retried() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(DEVICE_PATH))
        .respond_with(ResponseTemplate::new(429).insert_header("Retry-After", "1"))
        .mount(&server)
        .await;
    let (cert, key) = identity();
    // Retry left ON: the device login must still make one attempt.
    let client = AxiamClient::builder()
        .base_url(server.uri())
        .unwrap()
        .tenant_id(Uuid::parse_str(TENANT_ID).unwrap())
        .with_client_cert(cert.as_bytes(), key.as_bytes())
        .unwrap()
        .build()
        .unwrap();

    let err = client.authenticate_device().await.expect_err("429");

    assert!(!matches!(err, AxiamError::Auth { .. }), "{err:?}");
    assert_eq!(requests_to(&server, DEVICE_PATH).await.len(), 1);
}

/// A later `401` on the device token — expired, or presented without its
/// certificate — is surfaced as `AuthError` without a refresh attempt: there
/// is no refresh token to spend (§6.1 rule 6).
#[tokio::test]
async fn a_later_401_on_the_device_token_does_not_refresh() {
    let server = MockServer::start().await;
    mount_jwks(&server).await;
    mount_device_login(&server, &device_token()).await;
    management_support::mount_refresh(&server).await;
    mount(&server, "GET", "/api/v1/groups", 401, "token expired").await;
    let client = device_client(&server.uri());
    client.authenticate_device().await.unwrap();

    let err = client
        .groups()
        .list(PageRequest::first(50))
        .await
        .expect_err("401");

    assert!(matches!(err, AxiamError::Auth { .. }), "{err:?}");
    // The server's own answer, not the guard's "no refresh token available":
    // with no refresh token the guard would also fail before the wire, so the
    // request count alone cannot tell "surfaced" from "sent to the guard".
    assert!(
        err.to_string().contains("token expired"),
        "the 401 is surfaced verbatim rather than entering the §9 guard: {err}"
    );
    assert!(
        requests_to(&server, "/api/v1/auth/refresh")
            .await
            .is_empty(),
        "§6.1 rule 6: nothing for the guard to spend"
    );
    assert_eq!(requests_to(&server, "/api/v1/groups").await.len(), 1);
}

// ---------------------------------------------------------------------------
// C-12 N4.3 — the self-service builders (`account_post`, `webauthn_post`,
// `logout`) must present the device credential and withhold a stale cookie,
// exactly as management/authz already do (`client.rs::session_credential`).
// ---------------------------------------------------------------------------

/// `mfa_setup_enroll` goes through `account_post` (`src/rest/account.rs`),
/// one of the self-service builders that predates the §6.1 device credential.
#[tokio::test]
async fn account_post_presents_the_device_credential_and_withholds_the_cookie() {
    let server = MockServer::start().await;
    let _ = logged_in_client_as(
        &server,
        json!({ "id": Uuid::new_v4(), "username": "u", "email": "u@example.com" }),
    )
    .await;
    let token = device_token();
    mount_device_login(&server, &token).await;
    mount(
        &server,
        "POST",
        "/api/v1/auth/mfa/setup/enroll",
        200,
        r#"{"secret_base32": "JBSWY3DP", "totp_uri": "otpauth://totp/x"}"#,
    )
    .await;

    let client = device_client(&server.uri());
    client
        .login("u@example.com", &Uuid::new_v4().to_string())
        .await
        .expect("cookie session");
    client.authenticate_device().await.expect("device login");
    client
        .mfa_setup_enroll(&Sensitive::new("setup-token".to_string()))
        .await
        .expect("enroll");

    let sent = &requests_to(&server, "/api/v1/auth/mfa/setup/enroll").await[0];
    let cookies = header(sent, "cookie").unwrap_or("");
    assert!(
        !cookies.contains("axiam_access"),
        "the previous session's cookie must be withheld: {cookies:?}"
    );
    assert_eq!(
        header(sent, "authorization"),
        Some(format!("Bearer {token}").as_str())
    );
}

/// The webauthn ceremony starts (`webauthn_post`, `src/rest/webauthn.rs`)
/// have the same gap.
#[tokio::test]
async fn webauthn_post_presents_the_device_credential_and_withholds_the_cookie() {
    let server = MockServer::start().await;
    let _ = logged_in_client_as(
        &server,
        json!({ "id": Uuid::new_v4(), "username": "u", "email": "u@example.com" }),
    )
    .await;
    let token = device_token();
    mount_device_login(&server, &token).await;
    mount(
        &server,
        "POST",
        "/api/v1/auth/webauthn/authenticate/start",
        200,
        r#"{"challenge": {}, "state_token": "state-1"}"#,
    )
    .await;

    let client = device_client(&server.uri());
    client
        .login("u@example.com", &Uuid::new_v4().to_string())
        .await
        .expect("cookie session");
    client.authenticate_device().await.expect("device login");
    client
        .webauthn_authenticate_start(&Sensitive::new("challenge-token".to_string()))
        .await
        .expect("start");

    let sent = &requests_to(&server, "/api/v1/auth/webauthn/authenticate/start").await[0];
    let cookies = header(sent, "cookie").unwrap_or("");
    assert!(
        !cookies.contains("axiam_access"),
        "the previous session's cookie must be withheld: {cookies:?}"
    );
    assert_eq!(
        header(sent, "authorization"),
        Some(format!("Bearer {token}").as_str())
    );
}

/// `logout()` itself must not leak the prior session's cookie once a device
/// credential has been adopted.
#[tokio::test]
async fn logout_presents_the_device_credential_and_withholds_the_cookie() {
    let server = MockServer::start().await;
    let _ = logged_in_client_as(
        &server,
        json!({ "id": Uuid::new_v4(), "username": "u", "email": "u@example.com" }),
    )
    .await;
    let token = device_token();
    mount_device_login(&server, &token).await;
    mount(&server, "POST", "/api/v1/auth/logout", 204, "").await;

    let client = device_client(&server.uri());
    client
        .login("u@example.com", &Uuid::new_v4().to_string())
        .await
        .expect("cookie session");
    client.authenticate_device().await.expect("device login");
    client.logout().await.expect("logout");

    let sent = &requests_to(&server, "/api/v1/auth/logout").await[0];
    let cookies = header(sent, "cookie").unwrap_or("");
    assert!(
        !cookies.contains("axiam_access"),
        "the previous session's cookie must be withheld: {cookies:?}"
    );
    assert_eq!(
        header(sent, "authorization"),
        Some(format!("Bearer {token}").as_str())
    );
}

// ---------------------------------------------------------------------------
// C-12 N4.4 — lifecycle: a later `login()` replaces the device credential,
// and `logout()` releases it. Regression coverage: code reading shows both
// directions already correct (`absorb_session_cookies` clears the bearer
// flag; `logout` calls `token_manager().clear()`), so this pins the already-
// right behaviour rather than proving a defect.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn login_after_a_device_login_replaces_the_device_credential() {
    let server = MockServer::start().await;
    mount_jwks(&server).await;
    mount_device_login(&server, &device_token()).await;
    let access_token = sign_claims(&json!({
        "sub": Uuid::new_v4().to_string(),
        "tenant_id": TENANT_ID,
        "org_id": ORG_ID,
        "iss": "axiam-test",
        "iat": 0,
        "exp": 9_999_999_999i64,
        "jti": Uuid::new_v4().to_string(),
    }));
    let mut response = ResponseTemplate::new(200).set_body_json(json!({
        "user": { "id": Uuid::new_v4(), "username": "u", "email": "u@example.com" },
        "session_id": Uuid::new_v4(),
        "expires_in": 900,
    }));
    for cookie in [
        format!("axiam_access={access_token}; Path=/; HttpOnly"),
        "axiam_refresh=test-refresh-token; Path=/; HttpOnly".to_string(),
        "axiam_csrf=test-csrf-token; Path=/".to_string(),
    ] {
        response = response.append_header("Set-Cookie", cookie.as_str());
    }
    Mock::given(method("POST"))
        .and(path("/api/v1/auth/login"))
        .respond_with(response)
        .mount(&server)
        .await;
    mount(
        &server,
        "GET",
        "/api/v1/groups",
        200,
        r#"{"items": [], "total": 0, "offset": 0, "limit": 50}"#,
    )
    .await;

    let client = device_client(&server.uri());
    client.authenticate_device().await.expect("device login");
    client
        .login("u@example.com", "correct horse")
        .await
        .expect("login");
    client.groups().list(PageRequest::first(50)).await.unwrap();

    let sent = &requests_to(&server, "/api/v1/groups").await[0];
    assert!(
        header(sent, "authorization").is_none(),
        "a later login must replace the device credential"
    );
    assert!(
        header(sent, "cookie")
            .unwrap_or("")
            .contains("axiam_access"),
        "the new cookie session must be used"
    );
}

#[tokio::test]
async fn logout_after_a_device_login_releases_the_device_credential() {
    let server = MockServer::start().await;
    mount_jwks(&server).await;
    mount_device_login(&server, &device_token()).await;
    mount(&server, "POST", "/api/v1/auth/logout", 204, "").await;
    mount(
        &server,
        "GET",
        "/api/v1/groups",
        200,
        r#"{"items": [], "total": 0, "offset": 0, "limit": 50}"#,
    )
    .await;

    let client = device_client(&server.uri());
    client.authenticate_device().await.expect("device login");
    client.logout().await.expect("logout");

    // No credential of any kind survives `logout()`: neither the device
    // bearer nor a cookie session, so the management gate refuses
    // client-side rather than letting the call ride anonymously — the
    // clearest proof the device credential was actually released.
    let err = client
        .groups()
        .list(PageRequest::first(50))
        .await
        .expect_err("no session remains after logout");
    assert!(matches!(err, AxiamError::Auth { .. }), "{err:?}");
    assert!(
        requests_to(&server, "/api/v1/groups").await.is_empty(),
        "the refusal must be client-side, with no wire call"
    );
}
