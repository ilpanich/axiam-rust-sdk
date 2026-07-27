//! `Sensitive<T>` redaction of the CONTRACT.md §12.5 secret fields
//! (`access_token`, `refresh_token`, `id_token`, `client_secret`,
//! `code_verifier`) across every §12 public type whose `Debug` output could
//! otherwise leak them.

#![cfg(feature = "rest")]

use axiam_sdk::Sensitive;
use axiam_sdk::oidc::{AuthorizationRequest, OidcStateEntry, OidcTokenSet};

const SECRET_ACCESS: &str = "super-secret-access-token-value";
const SECRET_REFRESH: &str = "super-secret-refresh-token-value";
const SECRET_ID: &str = "super-secret-id-token-value";
const SECRET_VERIFIER: &str = "super-secret-code-verifier-value";

#[test]
fn oidc_token_set_debug_redacts_every_secret_field() {
    let tokens = OidcTokenSet {
        access_token: Sensitive::new(SECRET_ACCESS.to_string()),
        token_type: "Bearer".to_string(),
        expires_in: 900,
        scope: Some("openid".to_string()),
        refresh_token: Some(Sensitive::new(SECRET_REFRESH.to_string())),
        id_token: Some(Sensitive::new(SECRET_ID.to_string())),
        id_claims: None,
    };

    let rendered = format!("{tokens:?}");
    assert!(
        !rendered.contains(SECRET_ACCESS),
        "access_token leaked: {rendered}"
    );
    assert!(
        !rendered.contains(SECRET_REFRESH),
        "refresh_token leaked: {rendered}"
    );
    assert!(!rendered.contains(SECRET_ID), "id_token leaked: {rendered}");
    assert!(rendered.contains("Sensitive(<redacted>)"));
}

#[test]
fn authorization_request_debug_redacts_the_code_verifier() {
    let request = AuthorizationRequest {
        url: "https://iam.example.com/oauth2/authorize?...".to_string(),
        state: "plain-state-value".to_string(),
        nonce: "plain-nonce-value".to_string(),
        code_verifier: Sensitive::new(SECRET_VERIFIER.to_string()),
    };

    let rendered = format!("{request:?}");
    assert!(
        !rendered.contains(SECRET_VERIFIER),
        "code_verifier leaked: {rendered}"
    );
    // state/nonce are NOT secrets (§12.3 rule 2) — they legitimately appear.
    assert!(rendered.contains("plain-state-value"));
    assert!(rendered.contains("plain-nonce-value"));
}

#[test]
fn oidc_state_entry_debug_redacts_the_code_verifier() {
    let entry = OidcStateEntry {
        state: "s".to_string(),
        nonce: "n".to_string(),
        code_verifier: Sensitive::new(SECRET_VERIFIER.to_string()),
        redirect_uri: "https://app.example.com/cb".to_string(),
        return_to: None,
    };
    let rendered = format!("{entry:?}");
    assert!(
        !rendered.contains(SECRET_VERIFIER),
        "code_verifier leaked: {rendered}"
    );
}

/// §9 rule 2 requires the single in-flight `oidc_refresh` to hand the *same*
/// token set to every waiter, so `OidcTokenSet` is `Clone`. Cloning must not
/// open a leak path: the clone's `Debug` has to redact every §12.5 secret
/// field exactly as the original's does.
#[test]
fn cloning_an_oidc_token_set_keeps_every_secret_field_redacted() {
    let tokens = OidcTokenSet {
        access_token: Sensitive::new(SECRET_ACCESS.to_string()),
        token_type: "Bearer".to_string(),
        expires_in: 900,
        scope: Some("openid".to_string()),
        refresh_token: Some(Sensitive::new(SECRET_REFRESH.to_string())),
        id_token: Some(Sensitive::new(SECRET_ID.to_string())),
        id_claims: None,
    };

    let cloned = tokens.clone();
    let rendered = format!("{cloned:?}");
    assert!(!rendered.contains(SECRET_ACCESS), "leaked: {rendered}");
    assert!(!rendered.contains(SECRET_REFRESH), "leaked: {rendered}");
    assert!(!rendered.contains(SECRET_ID), "leaked: {rendered}");
    assert!(rendered.contains("Sensitive(<redacted>)"));
    // Same values, still only reachable via `expose()`.
    assert_eq!(cloned.access_token.expose(), SECRET_ACCESS);
    assert_eq!(
        cloned.refresh_token.as_ref().map(|t| t.expose().as_str()),
        Some(SECRET_REFRESH)
    );
    assert_eq!(
        cloned.id_token.as_ref().map(|t| t.expose().as_str()),
        Some(SECRET_ID)
    );
    // The original is untouched by the clone.
    assert_eq!(tokens.access_token.expose(), SECRET_ACCESS);
}

#[test]
fn sensitive_display_and_debug_never_emit_the_wrapped_value() {
    let secret = Sensitive::new(SECRET_ACCESS.to_string());
    assert_eq!(format!("{secret}"), "[SENSITIVE]");
    assert_eq!(format!("{secret:?}"), "Sensitive(<redacted>)");
    // The only way to reach the raw value is the documented `expose()` call.
    assert_eq!(secret.expose(), SECRET_ACCESS);
}
