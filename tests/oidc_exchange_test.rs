//! `oidc_exchange`: authorization-code grant + the full §12.4 ID-token
//! validation checklist (CONTRACT.md §12.1, §12.4), plus the wire-shape
//! assertions from §12.1 notes 1–3 (form encoding, `tenant_id` as a query
//! parameter, `client_secret_post`).
//!
//! One failing test per §12.4 rule, as the contract requires:
//!   rule 1 alg      -> "alg: none" + "non-EdDSA alg"
//!   rule 2 kid      -> "unknown kid (forced re-fetch then fail)" + "no kid"
//!                      + "signature mismatch under a published kid"
//!   rule 3 iss      -> "issuer mismatch (trailing slash, no normalization)"
//!   rule 4 aud      -> "audience mismatch" + "multiple aud without azp"
//!   rule 5 time     -> "expired" + "iat in the future"
//!   rule 6 nonce    -> "nonce mismatch" + "nonce absent"
//!   rule 7 discard  -> no token material reaches the caller on failure

#![cfg(feature = "rest")]

#[path = "oidc_support/mod.rs"]
mod oidc_support;

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use axiam_sdk::AxiamError;
use axiam_sdk::Sensitive;
use axiam_sdk::oidc::OidcExchangeParams;
use oidc_support::IdTokenOptions;
use serde_json::json;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

const CODE: &str = "authorization-code-value";
const NONCE: &str = "the-request-nonce";

fn parse_form(body: &[u8]) -> HashMap<String, String> {
    url::form_urlencoded::parse(body)
        .into_owned()
        .collect::<HashMap<_, _>>()
}

struct Captured {
    tenant_id_query: Option<String>,
    content_type: Option<String>,
    form: HashMap<String, String>,
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

async fn mount_jwks(
    mock_server: &MockServer,
    keys: Vec<&oidc_support::SigningKeyFixture>,
) -> Arc<AtomicUsize> {
    let call_count = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&call_count);
    let body = oidc_support::jwks_body(&keys);
    Mock::given(method("GET"))
        .and(path("/oauth2/jwks"))
        .respond_with(move |_req: &Request| {
            counter.fetch_add(1, Ordering::SeqCst);
            ResponseTemplate::new(200).set_body_json(body.clone())
        })
        .mount(mock_server)
        .await;
    call_count
}

/// Mount `/oauth2/token` replying with a fixed `token_response` body
/// (optionally carrying `id_token`), capturing every request it sees.
async fn mount_token(
    mock_server: &MockServer,
    response_body: serde_json::Value,
) -> Arc<Mutex<Vec<Captured>>> {
    let captured: Arc<Mutex<Vec<Captured>>> = Arc::new(Mutex::new(Vec::new()));
    let captured_for_responder = Arc::clone(&captured);
    Mock::given(method("POST"))
        .and(path("/oauth2/token"))
        .respond_with(move |req: &Request| {
            let tenant_id_query = req
                .url
                .query_pairs()
                .find(|(k, _)| k == "tenant_id")
                .map(|(_, v)| v.into_owned());
            let content_type = req
                .headers
                .get("content-type")
                .map(|v| v.to_str().unwrap_or_default().to_string());
            let form = parse_form(&req.body);
            captured_for_responder.lock().unwrap().push(Captured {
                tenant_id_query,
                content_type,
                form,
            });
            ResponseTemplate::new(200).set_body_json(response_body.clone())
        })
        .mount(mock_server)
        .await;
    captured
}

async fn mount_token_error(
    mock_server: &MockServer,
    status: u16,
    error: &str,
    error_description: &str,
) {
    let body = json!({ "error": error, "error_description": error_description });
    Mock::given(method("POST"))
        .and(path("/oauth2/token"))
        .respond_with(ResponseTemplate::new(status).set_body_json(body))
        .mount(mock_server)
        .await;
}

// ---------------------------------------------------------------------------
// Happy path + wire shape (§12.1 notes 1-3)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn happy_path_posts_form_encoded_body_with_tenant_id_as_a_query_parameter() {
    let mock_server = MockServer::start().await;
    let key = oidc_support::generate_signing_key("rp-kid-happy");
    let id_token = oidc_support::sign_id_token(
        &key,
        IdTokenOptions {
            nonce: Some(Some(NONCE)),
            ..Default::default()
        },
    );

    mount_discovery(&mock_server).await;
    mount_jwks(&mock_server, vec![&key]).await;
    let captured = mount_token(
        &mock_server,
        oidc_support::token_response(json!({
            "refresh_token": "refresh-token-value",
            "scope": "openid profile",
            "id_token": id_token,
        })),
    )
    .await;

    let client = oidc_support::build_client(&mock_server.uri(), true);
    let tokens = client
        .oidc_exchange(OidcExchangeParams {
            code: CODE.into(),
            code_verifier: Sensitive::new("verifier-value".into()),
            redirect_uri: oidc_support::REDIRECT_URI.into(),
            nonce: NONCE.into(),
            tenant_id: None,
            configuration: None,
        })
        .await
        .expect("oidc_exchange succeeds");

    let requests = captured.lock().unwrap();
    assert_eq!(requests.len(), 1);
    let req = &requests[0];
    assert_eq!(
        req.tenant_id_query.as_deref(),
        Some(oidc_support::tenant_id().to_string().as_str())
    );
    assert!(
        req.content_type
            .as_deref()
            .unwrap()
            .contains("application/x-www-form-urlencoded")
    );
    assert_eq!(req.form.get("grant_type").unwrap(), "authorization_code");
    assert_eq!(req.form.get("code").unwrap(), CODE);
    assert_eq!(req.form.get("code_verifier").unwrap(), "verifier-value");
    assert_eq!(
        req.form.get("redirect_uri").unwrap(),
        oidc_support::REDIRECT_URI
    );
    assert_eq!(req.form.get("client_id").unwrap(), oidc_support::CLIENT_ID);
    assert_eq!(
        req.form.get("client_secret").unwrap(),
        oidc_support::CLIENT_SECRET
    );
    // No field outside the grant's documented set (§12.1).
    let mut keys: Vec<&str> = req.form.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        vec![
            "client_id",
            "client_secret",
            "code",
            "code_verifier",
            "grant_type",
            "redirect_uri"
        ]
    );

    assert_eq!(tokens.access_token.expose(), "access-token-value");
    assert_eq!(
        tokens.refresh_token.unwrap().expose(),
        "refresh-token-value"
    );
    assert_eq!(tokens.token_type, "Bearer");
    assert_eq!(tokens.expires_in, 900);
    assert_eq!(tokens.scope.as_deref(), Some("openid profile"));
    let claims = tokens.id_claims.expect("id_claims present");
    assert_eq!(claims.sub, "user-1");
    assert_eq!(claims.iss, oidc_support::ISSUER);
    assert_eq!(claims.nonce.as_deref(), Some(NONCE));
}

#[tokio::test]
async fn omits_client_secret_entirely_for_a_public_client() {
    let mock_server = MockServer::start().await;
    let key = oidc_support::generate_signing_key("rp-kid-public");
    let id_token = oidc_support::sign_id_token(
        &key,
        IdTokenOptions {
            nonce: Some(Some(NONCE)),
            ..Default::default()
        },
    );
    mount_discovery(&mock_server).await;
    mount_jwks(&mock_server, vec![&key]).await;
    let captured = mount_token(
        &mock_server,
        oidc_support::token_response(json!({ "id_token": id_token })),
    )
    .await;

    let client = oidc_support::build_client(&mock_server.uri(), false);
    client
        .oidc_exchange(OidcExchangeParams {
            code: CODE.into(),
            code_verifier: Sensitive::new("v".into()),
            redirect_uri: oidc_support::REDIRECT_URI.into(),
            nonce: NONCE.into(),
            tenant_id: None,
            configuration: None,
        })
        .await
        .expect("public client exchange succeeds");

    assert!(
        !captured.lock().unwrap()[0]
            .form
            .contains_key("client_secret")
    );
}

#[tokio::test]
async fn preserves_unknown_id_token_claims() {
    let mock_server = MockServer::start().await;
    let key = oidc_support::generate_signing_key("rp-kid-extra");
    let id_token = oidc_support::sign_id_token(
        &key,
        IdTokenOptions {
            nonce: Some(Some(NONCE)),
            extra_claims: vec![
                ("email".to_string(), json!("user@example.com")),
                ("custom_org_tier".to_string(), json!("gold")),
            ],
            ..Default::default()
        },
    );
    mount_discovery(&mock_server).await;
    mount_jwks(&mock_server, vec![&key]).await;
    mount_token(
        &mock_server,
        oidc_support::token_response(json!({ "id_token": id_token })),
    )
    .await;

    let client = oidc_support::build_client(&mock_server.uri(), true);
    let tokens = client
        .oidc_exchange(OidcExchangeParams {
            code: CODE.into(),
            code_verifier: Sensitive::new("v".into()),
            redirect_uri: oidc_support::REDIRECT_URI.into(),
            nonce: NONCE.into(),
            tenant_id: None,
            configuration: None,
        })
        .await
        .expect("exchange succeeds");

    let claims = tokens.id_claims.unwrap();
    assert_eq!(claims.extra.get("email").unwrap(), "user@example.com");
    assert_eq!(claims.extra.get("custom_org_tier").unwrap(), "gold");
}

// ---------------------------------------------------------------------------
// §12.4 ID-token validation failures
// ---------------------------------------------------------------------------

async fn expect_failure(
    id_token: String,
    keys: Vec<&oidc_support::SigningKeyFixture>,
    nonce: &str,
) -> AxiamError {
    let mock_server = MockServer::start().await;
    mount_discovery(&mock_server).await;
    mount_jwks(&mock_server, keys).await;
    mount_token(
        &mock_server,
        oidc_support::token_response(json!({ "id_token": id_token })),
    )
    .await;

    let client = oidc_support::build_client(&mock_server.uri(), true);
    client
        .oidc_exchange(OidcExchangeParams {
            code: CODE.into(),
            code_verifier: Sensitive::new("v".into()),
            redirect_uri: oidc_support::REDIRECT_URI.into(),
            nonce: nonce.into(),
            tenant_id: None,
            configuration: None,
        })
        .await
        .expect_err("exchange must fail")
}

#[tokio::test]
async fn rule1_rejects_alg_none_outright() {
    let token = oidc_support::unsigned_id_token(json!({
        "iss": oidc_support::ISSUER,
        "sub": "user-1",
        "aud": oidc_support::CLIENT_ID,
        "exp": 9_999_999_999i64,
        "iat": 0,
        "nonce": NONCE,
    }));
    let err = expect_failure(token, vec![], NONCE).await;
    assert_eq!(
        err.id_token_failure_reason(),
        Some(axiam_sdk::IdTokenFailureReason::InvalidAlg)
    );
}

#[tokio::test]
async fn rule1_rejects_a_non_eddsa_algorithm() {
    let claims = json!({ "iss": oidc_support::ISSUER, "sub": "user-1", "aud": oidc_support::CLIENT_ID, "exp": 9_999_999_999i64, "iat": 0, "nonce": NONCE });
    let hs_token = jsonwebtoken::encode(
        &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256),
        &claims,
        &jsonwebtoken::EncodingKey::from_secret(b"a-32-byte-symmetric-secret-value"),
    )
    .expect("encode HS256 token");
    let err = expect_failure(hs_token, vec![], NONCE).await;
    assert_eq!(
        err.id_token_failure_reason(),
        Some(axiam_sdk::IdTokenFailureReason::InvalidAlg)
    );
}

#[tokio::test]
async fn rule2_unknown_kid_triggers_a_forced_refetch_then_fails() {
    let published = oidc_support::generate_signing_key("published-kid");
    let rogue = oidc_support::generate_signing_key("rogue-kid");
    let id_token = oidc_support::sign_id_token(
        &rogue,
        IdTokenOptions {
            nonce: Some(Some(NONCE)),
            ..Default::default()
        },
    );

    let mock_server = MockServer::start().await;
    mount_discovery(&mock_server).await;
    let jwks_calls = mount_jwks(&mock_server, vec![&published]).await;
    mount_token(
        &mock_server,
        oidc_support::token_response(json!({ "id_token": id_token })),
    )
    .await;

    let client = oidc_support::build_client(&mock_server.uri(), true);
    let err = client
        .oidc_exchange(OidcExchangeParams {
            code: CODE.into(),
            code_verifier: Sensitive::new("v".into()),
            redirect_uri: oidc_support::REDIRECT_URI.into(),
            nonce: NONCE.into(),
            tenant_id: None,
            configuration: None,
        })
        .await
        .expect_err("unknown kid must fail");

    assert_eq!(
        err.id_token_failure_reason(),
        Some(axiam_sdk::IdTokenFailureReason::UnknownKid)
    );
    // Cold cache: 1 initial fetch + 1 forced refetch on the kid miss —
    // mirrors the existing access-token behavior in
    // `tests/jwks_fetch_and_refetch_test.rs` (addendum item 9).
    assert_eq!(jwks_calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn rule2_rejects_a_token_with_no_kid_header() {
    let key = oidc_support::generate_signing_key("rp-kid-1");
    let no_kid = oidc_support::sign_id_token(
        &key,
        IdTokenOptions {
            nonce: Some(Some(NONCE)),
            omit_kid: true,
            ..Default::default()
        },
    );
    // Absence of `kid` must fail before any JWKS lookup succeeds, regardless
    // of what the JWKS publishes.
    let err = expect_failure(no_kid, vec![&key], NONCE).await;
    assert_eq!(
        err.id_token_failure_reason(),
        Some(axiam_sdk::IdTokenFailureReason::UnknownKid)
    );
}

#[tokio::test]
async fn rule2_rejects_a_token_signed_by_another_key_under_a_published_kid() {
    let published = oidc_support::generate_signing_key("shared-kid");
    let impostor = oidc_support::generate_signing_key("impostor-actual-key");
    let id_token = oidc_support::sign_id_token(
        &impostor,
        IdTokenOptions {
            nonce: Some(Some(NONCE)),
            kid_override: Some("shared-kid"),
            ..Default::default()
        },
    );
    let err = expect_failure(id_token, vec![&published], NONCE).await;
    assert_eq!(
        err.id_token_failure_reason(),
        Some(axiam_sdk::IdTokenFailureReason::InvalidSignature)
    );
}

#[tokio::test]
async fn rule3_rejects_issuer_mismatch_with_no_normalization() {
    let key = oidc_support::generate_signing_key("rp-kid-1");
    let id_token = oidc_support::sign_id_token(
        &key,
        IdTokenOptions {
            nonce: Some(Some(NONCE)),
            issuer: Some(&format!("{}/", oidc_support::ISSUER)),
            ..Default::default()
        },
    );
    let err = expect_failure(id_token, vec![&key], NONCE).await;
    assert_eq!(
        err.id_token_failure_reason(),
        Some(axiam_sdk::IdTokenFailureReason::InvalidIssuer)
    );
}

#[tokio::test]
async fn rule4_rejects_wrong_audience() {
    let key = oidc_support::generate_signing_key("rp-kid-1");
    let id_token = oidc_support::sign_id_token(
        &key,
        IdTokenOptions {
            nonce: Some(Some(NONCE)),
            audience: Some(json!("some-other-client")),
            ..Default::default()
        },
    );
    let err = expect_failure(id_token, vec![&key], NONCE).await;
    assert_eq!(
        err.id_token_failure_reason(),
        Some(axiam_sdk::IdTokenFailureReason::InvalidAudience)
    );
}

#[tokio::test]
async fn rule4_rejects_multiple_audiences_without_matching_azp() {
    let key = oidc_support::generate_signing_key("rp-kid-1");
    let id_token = oidc_support::sign_id_token(
        &key,
        IdTokenOptions {
            nonce: Some(Some(NONCE)),
            audience: Some(json!([oidc_support::CLIENT_ID, "another-client"])),
            ..Default::default()
        },
    );
    let err = expect_failure(id_token, vec![&key], NONCE).await;
    assert_eq!(
        err.id_token_failure_reason(),
        Some(axiam_sdk::IdTokenFailureReason::InvalidAudience)
    );
}

#[tokio::test]
async fn rule5_rejects_an_expired_token() {
    let key = oidc_support::generate_signing_key("rp-kid-1");
    let id_token = oidc_support::sign_id_token(
        &key,
        IdTokenOptions {
            nonce: Some(Some(NONCE)),
            expires_in_sec: Some(-600),
            ..Default::default()
        },
    );
    let err = expect_failure(id_token, vec![&key], NONCE).await;
    assert_eq!(
        err.id_token_failure_reason(),
        Some(axiam_sdk::IdTokenFailureReason::TokenExpired)
    );
}

#[tokio::test]
async fn rule5_rejects_an_iat_in_the_future_beyond_skew() {
    let key = oidc_support::generate_signing_key("rp-kid-1");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let id_token = oidc_support::sign_id_token(
        &key,
        IdTokenOptions {
            nonce: Some(Some(NONCE)),
            issued_at_sec: Some(now + 600),
            ..Default::default()
        },
    );
    let err = expect_failure(id_token, vec![&key], NONCE).await;
    assert_eq!(
        err.id_token_failure_reason(),
        Some(axiam_sdk::IdTokenFailureReason::TokenExpired)
    );
}

#[tokio::test]
async fn rule6_rejects_a_mismatched_nonce() {
    let key = oidc_support::generate_signing_key("rp-kid-1");
    let id_token = oidc_support::sign_id_token(
        &key,
        IdTokenOptions {
            nonce: Some(Some("a-different-nonce")),
            ..Default::default()
        },
    );
    let err = expect_failure(id_token, vec![&key], NONCE).await;
    assert_eq!(
        err.id_token_failure_reason(),
        Some(axiam_sdk::IdTokenFailureReason::NonceMismatch)
    );
}

#[tokio::test]
async fn rule6_rejects_a_missing_nonce_claim() {
    let key = oidc_support::generate_signing_key("rp-kid-1");
    let id_token = oidc_support::sign_id_token(
        &key,
        IdTokenOptions {
            nonce: Some(None),
            ..Default::default()
        },
    );
    let err = expect_failure(id_token, vec![&key], NONCE).await;
    assert_eq!(
        err.id_token_failure_reason(),
        Some(axiam_sdk::IdTokenFailureReason::NonceMismatch)
    );
}

#[tokio::test]
async fn rule7_discards_the_whole_token_set_on_failure() {
    let key = oidc_support::generate_signing_key("rp-kid-1");
    let id_token = oidc_support::sign_id_token(
        &key,
        IdTokenOptions {
            nonce: Some(Some("wrong")),
            ..Default::default()
        },
    );
    let err = expect_failure(id_token.clone(), vec![&key], NONCE).await;

    let serialized = format!("{err}");
    assert!(!serialized.contains("access-token-value"));
    assert!(!serialized.contains(&id_token));
    assert!(!serialized.contains(oidc_support::CLIENT_SECRET));
    assert_eq!(
        err.id_token_failure_reason(),
        Some(axiam_sdk::IdTokenFailureReason::NonceMismatch)
    );
}

// ---------------------------------------------------------------------------
// OAuth2ErrorResponse -> OAuthProtocolError (§12.3 rule 3)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn maps_a_400_invalid_grant_body_to_oauth_protocol_error() {
    let mock_server = MockServer::start().await;
    mount_discovery(&mock_server).await;
    mount_token_error(
        &mock_server,
        400,
        "invalid_grant",
        "authorization code expired",
    )
    .await;

    let client = oidc_support::build_client(&mock_server.uri(), true);
    let err = client
        .oidc_exchange(OidcExchangeParams {
            code: CODE.into(),
            code_verifier: Sensitive::new("v".into()),
            redirect_uri: oidc_support::REDIRECT_URI.into(),
            nonce: NONCE.into(),
            tenant_id: None,
            configuration: None,
        })
        .await
        .expect_err("must fail");

    // Still an AuthError-family failure (matches AxiamError::Auth) — contract
    // 1.4 additive: existing "this is an auth failure" handling still works.
    assert!(matches!(err, AxiamError::Auth { .. }));
    let oauth = err
        .as_oauth_protocol_error()
        .expect("carries OAuthProtocolError");
    assert_eq!(oauth.error, "invalid_grant");
    assert_eq!(oauth.error_description, "authorization code expired");
    assert_eq!(
        err.to_string(),
        "authentication failed: invalid_grant: authorization code expired"
    );
}

#[tokio::test]
async fn raises_auth_error_client_side_with_no_wire_call_when_tenant_is_a_slug() {
    let mock_server = MockServer::start().await;
    mount_discovery(&mock_server).await;
    // Deliberately mount NO /oauth2/token handler: any request there fails
    // the test via wiremock's unmatched-request panic, proving no wire call
    // was attempted.

    let client = axiam_sdk::client::AxiamClient::builder()
        .base_url(mock_server.uri())
        .expect("valid base url")
        .tenant_slug("acme")
        .org_slug("acme")
        .oidc_client_id(oidc_support::CLIENT_ID)
        .oidc_client_secret(oidc_support::CLIENT_SECRET)
        .build()
        .expect("client builds");

    let err = client
        .oidc_exchange(OidcExchangeParams {
            code: CODE.into(),
            code_verifier: Sensitive::new("v".into()),
            redirect_uri: oidc_support::REDIRECT_URI.into(),
            nonce: NONCE.into(),
            tenant_id: None,
            configuration: None,
        })
        .await
        .expect_err("must fail client-side");
    assert!(matches!(err, AxiamError::Auth { .. }));
    assert!(err.to_string().contains("tenant_id UUID"));
}

#[tokio::test]
async fn an_explicit_tenant_id_overrides_the_clients_configured_one() {
    let mock_server = MockServer::start().await;
    let key = oidc_support::generate_signing_key("rp-kid-explicit-tenant");
    let id_token = oidc_support::sign_id_token(
        &key,
        IdTokenOptions {
            nonce: Some(Some(NONCE)),
            ..Default::default()
        },
    );
    mount_discovery(&mock_server).await;
    mount_jwks(&mock_server, vec![&key]).await;
    let captured = mount_token(
        &mock_server,
        oidc_support::token_response(json!({ "id_token": id_token })),
    )
    .await;

    let client = oidc_support::build_client(&mock_server.uri(), true);
    let explicit_tenant = uuid::Uuid::new_v4();
    client
        .oidc_exchange(OidcExchangeParams {
            code: CODE.into(),
            code_verifier: Sensitive::new("v".into()),
            redirect_uri: oidc_support::REDIRECT_URI.into(),
            nonce: NONCE.into(),
            tenant_id: Some(explicit_tenant),
            configuration: None,
        })
        .await
        .expect("exchange succeeds");

    assert_eq!(
        captured.lock().unwrap()[0].tenant_id_query.as_deref(),
        Some(explicit_tenant.to_string().as_str())
    );
}
