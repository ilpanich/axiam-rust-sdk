//! Native sign-in with a provider ID token — CONTRACT.md §37 (contract 1.65).
//!
//! A mobile or desktop app that used Google, Apple or Facebook's *native* SDK
//! holds an ID token the provider signed for that app. It presents the token
//! to AXIAM's token endpoint with
//! `grant_type=urn:axiam:params:oauth:grant-type:provider-id-token`, and gets
//! the client's ordinary token set back.
//!
//! This is **not** token exchange (§15): [`AxiamClient::token_exchange`]
//! refuses ID tokens, and neither helper stands in for the other.
//!
//! # What this module never does (§37.2 rules 10 and 12, §37.8)
//!
//! * It never retries. The provider's token is single-use across the whole
//!   deployment, so a repeated presentation is refused, and a transport
//!   failure after the request left is indeterminate. The recovery for every
//!   failure is a **fresh** provider token with a **fresh** nonce.
//! * It never logs, stores or caches the provider ID token or the raw nonce.
//!   Hold the raw nonce only for the length of the attempt.
//! * It never verifies the provider's token, resolves a provider, reads the
//!   token's claims, or falls back to another grant.
//! * It never adds `openid` to the scopes: an omitted `scopes` means no scope
//!   and so no ID token in the response.
//!
//! The returned tokens are **not** adopted as the client's own credential,
//! the same posture as `login_client_credentials` and `device_login`.

use serde::Serialize;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::AxiamError;
use crate::Sensitive;
use crate::client::AxiamClient;
use crate::management::error::local_refusal;

use super::authorize::{CSPRNG_BYTES, random_url_safe_token};
use super::discovery::OidcConfiguration;
use super::exchange::OidcTokenSet;

/// The grant type of native sign-in (CONTRACT.md §37.1).
pub const PROVIDER_ID_TOKEN_GRANT_TYPE: &str =
    "urn:axiam:params:oauth:grant-type:provider-id-token";

const OPERATION: &str = "login_with_provider_id_token";

/// The pair a native sign-in needs (CONTRACT.md §37.4).
///
/// Give the provider's SDK [`Self::hashed`] as *its* nonce, and pass
/// [`Self::raw`] to [`AxiamClient::login_with_provider_id_token`]. Hold the
/// raw value only for the length of the attempt.
#[derive(Debug, Clone)]
pub struct ProviderNonce {
    /// The raw nonce: at least 32 CSPRNG bytes, base64url without padding.
    /// A credential (§37.6), so [`Sensitive`]; this is what AXIAM is sent.
    pub raw: Sensitive<String>,
    /// `SHA-256` of the bytes of [`Self::raw`] as lower-case hexadecimal (64
    /// characters). Not a secret: it travels to the provider and into the
    /// provider's token.
    pub hashed: String,
}

impl ProviderNonce {
    /// A fresh pair. Equivalent to [`native_nonce`].
    pub fn generate() -> Result<Self, AxiamError> {
        let raw = random_url_safe_token(CSPRNG_BYTES)?;
        let hashed = hash_nonce(&raw);
        Ok(Self {
            raw: Sensitive::new(raw),
            hashed,
        })
    }
}

/// `SHA-256(raw)` as lower-case hexadecimal (CONTRACT.md §37.4 rule 2).
fn hash_nonce(raw: &str) -> String {
    hex::encode(Sha256::digest(raw.as_bytes()))
}

/// `native_nonce` (CONTRACT.md §37.4) — a fresh [`ProviderNonce`].
///
/// **Pure local computation, no network I/O**; nothing is stored. Each call
/// returns a different pair.
///
/// # Errors
/// [`AxiamError::Network`] if the operating system's CSPRNG fails.
pub fn native_nonce() -> Result<ProviderNonce, AxiamError> {
    ProviderNonce::generate()
}

/// The optional inputs of [`AxiamClient::login_with_provider_id_token`].
///
/// `Default` is "no scopes, no resource, the client's own tenant, discovery
/// fetched on demand".
#[derive(Debug, Default, Clone)]
pub struct ProviderIdTokenOptions {
    /// Scopes to request, space-joined on the wire. **Sent only when set; the
    /// SDK adds none** (§37.2 rule 7). Pass `openid` yourself to receive an
    /// ID token. A scope outside the client's registration is `invalid_scope`,
    /// not narrowed and re-sent.
    pub scopes: Option<Vec<String>>,
    /// RFC 8707 `resource`, sent only when set.
    pub resource: Option<String>,
    /// Tenant UUID for the `tenant_id` query parameter (§12.3 rule 4).
    pub tenant_id: Option<Uuid>,
    /// A pre-fetched discovery document; fetched via `oidc_discover` when
    /// `None`.
    pub configuration: Option<OidcConfiguration>,
}

/// The form body: exactly the field set of CONTRACT.md §37.1. Deliberately not
/// `Debug`: it holds the provider token and the raw nonce.
#[derive(Serialize)]
struct ProviderIdTokenForm<'a> {
    grant_type: &'a str,
    client_id: &'a str,
    provider: &'a str,
    id_token: &'a str,
    nonce: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    scope: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    resource: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_secret: Option<&'a str>,
}

impl AxiamClient {
    /// `login_with_provider_id_token` (CONTRACT.md §37) — sign a user in with
    /// the ID token a provider's native SDK produced.
    ///
    /// One `POST /oauth2/token?tenant_id=<uuid>`, form-encoded, with
    /// `grant_type=urn:axiam:params:oauth:grant-type:provider-id-token`.
    ///
    /// * `provider` is the provider's **UUID or `provider_slug`** and nothing
    ///   else; a kind name such as `google` is not accepted unless the
    ///   operator also chose it as the slug. It is sent as given: not
    ///   trimmed, case-folded or looked up.
    /// * `id_token` is the provider's ID token.
    /// * `nonce` is the **raw** nonce whose `SHA-256` hex the provider's SDK
    ///   was given (see [`native_nonce`]). It is sent byte for byte; the SDK
    ///   neither hashes it nor reads the token's own claim.
    ///
    /// A **public** client (`client_id` only) is the normal caller and is
    /// never refused for holding no secret; a client built with a secret sends
    /// it as `client_secret` in the body, never as `Authorization: Basic`.
    ///
    /// The result is the ordinary [`OidcTokenSet`]: a `refresh_token` only if
    /// the client holds that grant, an `id_token` (validated under §12.4 with
    /// the raw nonce as the expected nonce) only if `openid` was granted.
    /// `token_type` is read from the response. The tokens are **not**
    /// adopted as the client's credential.
    ///
    /// # Errors
    /// * a local [`ValidationError`](crate::management::ValidationError)
    ///   (`err.validation()`), with **no request sent**, for an empty
    ///   `provider`, `id_token` or `nonce`;
    /// * a local [`AxiamError::Auth`], no request sent, when the client has no
    ///   `client_id` or no tenant UUID (§12.3 rule 4);
    /// * the server's refusals as [`crate::OAuthProtocolError`]. In
    ///   particular `invalid_grant` is the server's one generic answer to
    ///   every refusal of the provider token and is never refined;
    ///   `consent_required` means the token is spent; `rate_limit_exceeded`
    ///   spent nothing;
    /// * [`AxiamError::Network`] for a transport failure or a body-less `5xx`.
    ///
    /// **Never retried**, by this method or by the client's §16 policy. After
    /// any failure obtain a fresh provider token with a fresh nonce.
    pub async fn login_with_provider_id_token(
        &self,
        provider: &str,
        id_token: Sensitive<String>,
        nonce: Sensitive<String>,
        options: ProviderIdTokenOptions,
    ) -> Result<OidcTokenSet, AxiamError> {
        self.ensure_open()?;
        // §37.2 rule 4: empty inputs are refused before anything else.
        for (field, empty) in [
            ("provider", provider.is_empty()),
            ("id_token", id_token.expose().is_empty()),
            ("nonce", nonce.expose().is_empty()),
        ] {
            if empty {
                return Err(local_refusal(
                    OPERATION,
                    field,
                    format!("{field} must not be empty (CONTRACT.md §37.2 rule 4)"),
                ));
            }
        }
        // Local checks come before discovery, so a refusal costs no request.
        let client_id = self.oidc_client_id_or_err()?.to_string();
        let tenant_id = self.resolve_oidc_tenant_id(options.tenant_id).await?;
        let configuration = match options.configuration {
            Some(c) => c,
            None => self.oidc_discover().await?,
        };
        let client_secret = self.oidc_client_secret().map(|s| s.expose().clone());
        let scope = options.scopes.as_ref().map(|s| s.join(" "));

        let form = ProviderIdTokenForm {
            grant_type: PROVIDER_ID_TOKEN_GRANT_TYPE,
            client_id: &client_id,
            provider,
            id_token: id_token.expose().as_str(),
            nonce: nonce.expose().as_str(),
            scope: scope.as_deref(),
            resource: options.resource.as_deref(),
            client_secret: client_secret.as_deref(),
        };

        // One request, no retry (§37.2 rule 10), outside the §9 guard.
        let wire = self.post_token(&configuration, &form, tenant_id).await?;
        // §37.2 rule 8: the AXIAM ID token carries the raw nonce as sent.
        self.to_token_set(wire, &configuration, Some(nonce.expose().as_str()))
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashing_matches_the_contract_vector() {
        assert_eq!(
            hash_nonce("n-0S6_WzA2Mj"),
            "0823a09b54cb9381561068b00aaf4e539b3f54604631d3e6a820879b6b04cc19"
        );
    }

    #[test]
    fn the_form_never_debug_prints_and_the_pair_redacts_raw() {
        let pair = native_nonce().expect("nonce");
        let rendered = format!("{pair:?}");
        assert!(!rendered.contains(pair.raw.expose()), "{rendered}");
        assert!(rendered.contains(&pair.hashed));
    }
}
