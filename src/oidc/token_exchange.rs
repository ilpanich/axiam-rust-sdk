//! Token Exchange (RFC 8693) — CONTRACT.md §15 (contract 1.7).
//!
//! A backend holding a user's access token exchanges it for a **narrower**
//! one before calling the next service.
//!
//! The rule this module exists to not paper over: **an exchange only ever
//! narrows.** The server enforces it; the SDK's job is to surface the
//! refusals unchanged, because every one of them is the server telling the
//! caller their assumption about their own privileges was wrong (§15).

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::discovery::OidcConfiguration;
use super::exchange::oauth2_error_or_fallback;
use crate::client::AxiamClient;
use crate::error::AxiamError;
use crate::rest::auth::CsrfHeaderExt;
use crate::sensitive::Sensitive;

/// `grant_type` of an RFC 8693 exchange.
pub const TOKEN_EXCHANGE_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";

/// The `actor_token_type` this SDK sends, and the `subject_token_type` it
/// sends when the caller names none — an AXIAM-issued access token (§15.1).
pub const ACCESS_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:access_token";

/// A JWT from a trusted external issuer — the cross-domain exchange of §15.7.
///
/// Pass it as [`TokenExchangeParams::subject_token_type`] to exchange a partner
/// IdP's token. AXIAM also accepts [`ACCESS_TOKEN_TYPE`] for an external
/// issuer, and refuses refresh and ID token types **by name**.
pub const JWT_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:jwt";

#[derive(Serialize)]
struct TokenExchangeForm<'a> {
    grant_type: &'a str,
    subject_token: &'a str,
    subject_token_type: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    actor_token: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    actor_token_type: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    scope: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    audience: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    resource: Option<&'a str>,
    client_id: &'a str,
    client_secret: &'a str,
}

#[derive(Debug, Deserialize)]
struct TokenExchangeResponseWire {
    access_token: String,
    issued_token_type: String,
    token_type: String,
    expires_in: u64,
    #[serde(default)]
    scope: Option<String>,
}

/// Arguments to [`AxiamClient::token_exchange`].
///
/// `subject_token` is the only required field. The rest are optional and
/// **named**, per §15.1 — four optional strings in positional order is a bug
/// waiting to be written, so this is a struct rather than a long signature.
pub struct TokenExchangeParams {
    /// The token being exchanged (§15.5 secret).
    pub subject_token: Sensitive<String>,
    /// What kind of token [`Self::subject_token`] is.
    ///
    /// `None` sends [`ACCESS_TOKEN_TYPE`], the same-domain exchange of §15.1.
    /// To exchange a token from a **trusted external issuer** (§15.7), set
    /// this explicitly — normally to [`JWT_TOKEN_TYPE`].
    ///
    /// The SDK never reads [`Self::subject_token`] to decide this value
    /// (§15.7). Which kind of token you hold is something only you know;
    /// AXIAM refuses refresh and ID token types by name, and the SDK will not
    /// retry a refusal as a different type.
    pub subject_token_type: Option<String>,
    /// The acting party, when this is a **delegation** (§15.2 rule 1).
    ///
    /// Its absence selects **impersonation**, which is a different operation
    /// with different risk. The SDK never fills this in for you — see
    /// [`AxiamClient::token_exchange`].
    pub actor_token: Option<Sensitive<String>>,
    /// Scopes to request. Omitted from the body when `None`, which asks the
    /// server for the widest set the subject and the client's registration
    /// both allow.
    pub scopes: Option<Vec<String>>,
    /// The service the issued token is for.
    pub audience: Option<String>,
    /// RFC 8707 synonym of [`Self::audience`]; the server refuses the pair
    /// when they disagree.
    pub resource: Option<String>,
    /// Tenant UUID for the mandatory `tenant_id` query parameter (§12.1
    /// note 2).
    pub tenant_id: Option<Uuid>,
    /// A pre-fetched discovery document.
    pub configuration: Option<OidcConfiguration>,
}

impl TokenExchangeParams {
    /// A minimal exchange: just the subject token, everything else defaulted.
    pub fn new(subject_token: Sensitive<String>) -> Self {
        Self {
            subject_token,
            subject_token_type: None,
            actor_token: None,
            scopes: None,
            audience: None,
            resource: None,
            tenant_id: None,
            configuration: None,
        }
    }
}

/// The result of an exchange (wire schema `TokenExchangeResponse`).
///
/// **There is no `refresh_token` field, and that is deliberate** (§15.2
/// rule 4). RFC 8693 issues none, so the type cannot represent one: an
/// application that wants a fresh exchanged token re-runs the exchange. This
/// result also never enters the §9 single-flight refresh guard — there is
/// nothing for it to refresh.
#[derive(Debug, Clone)]
pub struct ExchangedToken {
    /// The issued token (§15.5 secret).
    pub access_token: Sensitive<String>,
    /// What the server actually issued. Mandatory in RFC 8693 §2.2.1 and
    /// surfaced rather than dropped (§15.2 rule 6) so a client that asked
    /// for one type and got another can tell.
    pub issued_token_type: String,
    /// The token type (`Bearer`).
    pub token_type: String,
    /// Lifetime in seconds. Never longer than the subject token's remaining
    /// life — the server caps it so an exchange cannot launder lifetime.
    pub expires_in: u64,
    /// **The granted scope, which may be narrower than requested** even on
    /// success (§15.2 rule 7) — read it rather than assuming the request was
    /// honoured verbatim.
    pub scope: Option<String>,
}

impl AxiamClient {
    /// `POST /oauth2/token` with
    /// `grant_type=urn:ietf:params:oauth:grant-type:token-exchange`
    /// (CONTRACT.md §15.1) — exchange a token for a narrower one.
    ///
    /// The exchanging client **authenticates** (`client_secret_post`): unlike
    /// §14's device, this is a confidential service, so a client built
    /// without a secret fails client-side with no wire call.
    ///
    /// # What this method deliberately does not do
    ///
    /// * **No default `actor_token`** (§15.2 rule 1). Passing none asks for
    ///   *impersonation*; the SDK will not quietly reuse the client's own
    ///   session token as the actor and turn that into a delegation. They
    ///   are different operations with different risk.
    /// * **No retry or downgrade on `unauthorized_client`** (rule 2). It
    ///   means either "this client may not exchange" or "may not
    ///   impersonate" — both registration facts an operator must fix, not
    ///   conditions a client library can work around.
    /// * **No auto-narrowing on `invalid_scope`** (rule 3). The server
    ///   refuses instead of silently narrowing precisely so the caller finds
    ///   out here; re-sending with fewer scopes would hide that.
    /// * **No adoption** (rule 5). The returned token is handed onward in
    ///   one outbound call; adopting it as the client's own credential would
    ///   silently re-privilege every subsequent call this client makes. This
    ///   is a MUST NOT, not the MAY that governs `login_client_credentials`.
    ///
    /// A cross-tenant subject token answers `invalid_grant`, identically to
    /// an expired or malformed one. The SDK does not try to tell them apart
    /// (§15.3): the server collapses them because distinguishing them is a
    /// tenant-enumeration signal, and re-deriving the distinction
    /// client-side would hand back exactly what the server withheld.
    pub async fn token_exchange(
        &self,
        params: TokenExchangeParams,
    ) -> Result<ExchangedToken, AxiamError> {
        let configuration = match params.configuration {
            Some(c) => c,
            None => self.oidc_discover().await?,
        };
        let tenant_id = self.resolve_oidc_tenant_id(params.tenant_id).await?;
        let client_id = self.oidc_client_id_or_err()?.to_string();
        let client_secret = self.oidc_client_secret_or_err("token_exchange")?;
        let url = self.oidc_endpoint_url(&configuration.token_endpoint, tenant_id)?;

        let scope = params.scopes.as_ref().map(|s| s.join(" "));
        let actor = params.actor_token.as_ref().map(|t| t.expose().as_str());

        let form = TokenExchangeForm {
            grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
            subject_token: params.subject_token.expose().as_str(),
            // Whatever the caller named, verbatim. The subject token is
            // NEVER decoded to pick this (§15.7): which kind of token the
            // caller holds is the caller's to know, and a guess here is the
            // difference between a request that is refused and one that is
            // silently reinterpreted.
            subject_token_type: params
                .subject_token_type
                .as_deref()
                .unwrap_or(ACCESS_TOKEN_TYPE),
            actor_token: actor,
            // Sent exactly when `actor_token` is: RFC 8693 §2.1 requires the
            // pair, and sending the type alone would be a malformed request
            // the server answers `invalid_request`.
            actor_token_type: actor.map(|_| ACCESS_TOKEN_TYPE),
            scope: scope.as_deref(),
            audience: params.audience.as_deref(),
            resource: params.resource.as_deref(),
            client_id: &client_id,
            client_secret: &client_secret,
        };

        let response = self
            .http()
            .post(url)
            .header("X-Tenant-ID", self.tenant_header_value())
            .maybe_csrf_header(self)
            .form(&form)
            .send()
            .await
            .map_err(|e| AxiamError::Network {
                message: format!("token exchange request failed: {e}"),
                source: Some(Box::new(e)),
            })?;

        if !response.status().is_success() {
            // §15.3: dispatch on the `error` field before the status code.
            // `oauth2_error_or_fallback` already does exactly that, so the
            // six §15.3 codes reach the caller verbatim in
            // `OAuthProtocolError.error`.
            return Err(oauth2_error_or_fallback(response).await);
        }

        let wire: TokenExchangeResponseWire =
            response.json().await.map_err(|e| AxiamError::Network {
                message: format!("failed to parse token exchange response: {e}"),
                source: Some(Box::new(e)),
            })?;

        Ok(ExchangedToken {
            access_token: Sensitive::new(wire.access_token),
            issued_token_type: wire.issued_token_type,
            token_type: wire.token_type,
            expires_in: wire.expires_in,
            scope: wire.scope,
        })
    }
}
