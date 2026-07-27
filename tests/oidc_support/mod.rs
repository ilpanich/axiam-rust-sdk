//! Shared fixtures for the CONTRACT.md §12 OIDC/SSO integration tests
//! (`tests/oidc_*_test.rs`). Included via `#[path] mod oidc_support;` from
//! each test file — not a `tests/*.rs` file itself, so cargo does not treat
//! it as its own test binary.
//!
//! Mirrors the fixed-Ed25519-keypair JWT pattern already used by
//! `tests/jwks_fetch_and_refetch_test.rs` / `tests/rest_auth_lifecycle_test.rs`,
//! extended to mint several *distinct* deterministic test keys (needed for
//! "published"/"rogue"/"impostor" kid scenarios) via `ed25519-dalek`
//! (already a transitive dependency, promoted to a named `[dev-dependencies]`
//! entry — see `Cargo.toml`).

#![allow(dead_code)]

use axiam_sdk::client::AxiamClient;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::SigningKey;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// PKCS#8 DER prefix for a raw 32-byte Ed25519 seed (matches the existing
/// `ED25519_PKCS8_DER_PREFIX` pattern in the pre-existing JWKS tests).
const ED25519_PKCS8_DER_PREFIX: [u8; 16] = [
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];

pub const ISSUER: &str = "https://iam.example.com";
pub const CLIENT_ID: &str = "axiam-rp";
pub const CLIENT_SECRET: &str = "rp-secret-value";
pub const REDIRECT_URI: &str = "https://app.example.com/auth/callback";

pub fn tenant_id() -> Uuid {
    Uuid::parse_str("11111111-2222-3333-4444-555555555555").unwrap()
}

pub fn org_id() -> Uuid {
    Uuid::parse_str("66666666-7777-8888-9999-aaaaaaaaaaaa").unwrap()
}

/// A deterministic (test-only — never used for anything security-sensitive)
/// Ed25519 signing key plus the JWK it publishes.
pub struct SigningKeyFixture {
    pub kid: String,
    seed: [u8; 32],
    pub x_b64: String,
}

/// Derive a distinct, deterministic Ed25519 key for `kid` (SHA-256 of the
/// name as the seed — reproducible across test runs, not a real secret).
pub fn generate_signing_key(kid: &str) -> SigningKeyFixture {
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&Sha256::digest(kid.as_bytes()));
    let signing_key = SigningKey::from_bytes(&seed);
    let x_b64 = URL_SAFE_NO_PAD.encode(signing_key.verifying_key().to_bytes());
    SigningKeyFixture {
        kid: kid.to_string(),
        seed,
        x_b64,
    }
}

fn encoding_key(fixture: &SigningKeyFixture) -> EncodingKey {
    let mut der = ED25519_PKCS8_DER_PREFIX.to_vec();
    der.extend_from_slice(&fixture.seed);
    EncodingKey::from_ed_der(&der)
}

/// Build a `JwksDocument` body publishing the given keys.
pub fn jwks_body(keys: &[&SigningKeyFixture]) -> Value {
    json!({
        "keys": keys
            .iter()
            .map(|k| json!({
                "kty": "OKP",
                "crv": "Ed25519",
                "kid": k.kid,
                "alg": "EdDSA",
                "x": k.x_b64,
            }))
            .collect::<Vec<_>>()
    })
}

/// Claim/header knobs for [`sign_id_token`] — each maps to one §12.4 rule.
#[derive(Default)]
pub struct IdTokenOptions<'a> {
    pub issuer: Option<&'a str>,
    /// A string or array JSON value for `aud`. Defaults to [`CLIENT_ID`].
    pub audience: Option<Value>,
    pub azp: Option<&'a str>,
    /// `Some(Some(n))` sets `nonce: n`; `Some(None)` omits the claim
    /// entirely; `None` (the default) uses `"test-nonce"`.
    pub nonce: Option<Option<&'a str>>,
    pub subject: Option<&'a str>,
    pub expires_in_sec: Option<i64>,
    pub issued_at_sec: Option<i64>,
    pub not_before_sec: Option<i64>,
    /// `kid` written into the header — defaults to the signing key's own.
    pub kid_override: Option<&'a str>,
    /// When `true`, the header carries NO `kid` at all (§12.4 rule 2 "a
    /// token with no kid ... MUST be rejected"). Overrides `kid_override`.
    pub omit_kid: bool,
    pub extra_claims: Vec<(String, Value)>,
}

fn now_sec() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before epoch")
        .as_secs() as i64
}

/// Sign an ID token with the given (possibly deliberately wrong) claims.
pub fn sign_id_token(key: &SigningKeyFixture, opts: IdTokenOptions<'_>) -> String {
    let now = now_sec();
    let mut header = Header::new(Algorithm::EdDSA);
    header.kid = if opts.omit_kid {
        None
    } else {
        Some(opts.kid_override.unwrap_or(&key.kid).to_string())
    };

    let mut claims = serde_json::Map::new();
    claims.insert("iss".into(), json!(opts.issuer.unwrap_or(ISSUER)));
    claims.insert("sub".into(), json!(opts.subject.unwrap_or("user-1")));
    claims.insert(
        "aud".into(),
        opts.audience.unwrap_or_else(|| json!(CLIENT_ID)),
    );
    claims.insert(
        "exp".into(),
        json!(now + opts.expires_in_sec.unwrap_or(3600)),
    );
    claims.insert("iat".into(), json!(opts.issued_at_sec.unwrap_or(now)));
    if let Some(nbf) = opts.not_before_sec {
        claims.insert("nbf".into(), json!(nbf));
    }
    match opts.nonce {
        Some(Some(n)) => {
            claims.insert("nonce".into(), json!(n));
        }
        Some(None) => {}
        None => {
            claims.insert("nonce".into(), json!("test-nonce"));
        }
    }
    if let Some(azp) = opts.azp {
        claims.insert("azp".into(), json!(azp));
    }
    for (k, v) in opts.extra_claims {
        claims.insert(k, v);
    }

    jsonwebtoken::encode(&header, &Value::Object(claims), &encoding_key(key))
        .expect("sign id token")
}

/// Build an unsigned `alg: none` JWT — the §12.4 rule 1 "must be rejected
/// outright" case.
pub fn unsigned_id_token(claims: Value) -> String {
    fn b64(v: &Value) -> String {
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(v).expect("serialize"))
    }
    format!(
        "{}.{}.",
        b64(&json!({"alg": "none", "kid": "any"})),
        b64(&claims)
    )
}

/// A discovery document pointing every endpoint at the mocked origin.
pub fn discovery_document(base_url: &str) -> Value {
    json!({
        "issuer": ISSUER,
        "authorization_endpoint": format!("{base_url}/oauth2/authorize"),
        "token_endpoint": format!("{base_url}/oauth2/token"),
        "userinfo_endpoint": format!("{base_url}/oauth2/userinfo"),
        "jwks_uri": format!("{base_url}/oauth2/jwks"),
        "revocation_endpoint": format!("{base_url}/oauth2/revoke"),
        "introspection_endpoint": format!("{base_url}/oauth2/introspect"),
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["EdDSA"],
        "scopes_supported": ["openid", "profile", "email"],
        "token_endpoint_auth_methods_supported": ["client_secret_post"],
        "claims_supported": ["sub", "iss", "aud", "exp", "iat", "nonce"],
        "grant_types_supported": ["authorization_code", "client_credentials", "refresh_token"],
    })
}

/// A `TokenResponse` wire body, with `overrides` merged in (shallow).
pub fn token_response(overrides: Value) -> Value {
    let mut base = json!({
        "access_token": "access-token-value",
        "token_type": "Bearer",
        "expires_in": 900,
    });
    if let (Some(b), Some(o)) = (base.as_object_mut(), overrides.as_object()) {
        for (k, v) in o {
            b.insert(k.clone(), v.clone());
        }
    }
    base
}

/// Build an `AxiamClient` against the mocked origin, with the standard test
/// tenant and (optionally) a confidential-client secret.
pub fn build_client(base_url: &str, with_client_secret: bool) -> AxiamClient {
    let mut builder = AxiamClient::builder()
        .base_url(base_url)
        .expect("valid base url")
        .tenant_id(tenant_id())
        .org_id(org_id())
        .oidc_client_id(CLIENT_ID);
    if with_client_secret {
        builder = builder.oidc_client_secret(CLIENT_SECRET);
    }
    builder.build().expect("client builds")
}
