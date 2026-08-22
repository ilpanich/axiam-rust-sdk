//! Pushed Authorization Requests — CONTRACT.md §26 (RFC 9126).
//!
//! PAR moves the authorization request off the browser. Instead of putting
//! `scope`, `redirect_uri`, `state` and the PKCE challenge into a URL the user
//! agent carries, the client POSTs them straight to AXIAM over an authenticated
//! back channel and puts an opaque `request_uri` in the redirect. What travels
//! through the browser is then a random string that cannot be edited into
//! meaning something else.
//!
//! A §12 extension, not a replacement: `oidc_exchange` afterwards is unchanged.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::AxiamError;
use crate::Sensitive;
use crate::client::AxiamClient;
use crate::oidc::authorize::{
    AuthorizationRequest, CODE_CHALLENGE_METHOD_S256, compute_code_challenge, normalize_scope,
};
use crate::oidc::discovery::OidcConfiguration;
use crate::oidc::exchange::oauth2_error_or_fallback;
use crate::rest::auth::CsrfHeaderExt;

/// The result of [`AxiamClient::oidc_par`] (CONTRACT.md §26.1).
///
/// The server answered **201** — RFC 9126 §2.2 specifies Created, and a success
/// predicate written `== 200` would treat every successful push as a failure.
///
/// `state`, `nonce` and `code_verifier` are carried straight through from the
/// [`AuthorizationRequest`] that was pushed: §26.2 rule 1 forbids a second
/// generator, and rule 6 wants exactly one `code_verifier` so there is no
/// second place for the two to disagree.
#[derive(Debug, Clone)]
pub struct PushedAuthorizationRequest {
    /// Where to redirect the user agent.
    ///
    /// Carries **exactly** `client_id` and `request_uri`. Not `response_type`,
    /// not `redirect_uri`, not `scope`, not `state` — the server refuses a
    /// request that mixes a `request_uri` with inline authorization parameters
    /// rather than merging them, because merging is where parameter confusion
    /// lives (§26.2 rule 2).
    pub url: String,
    /// The opaque, single-use handle.
    ///
    /// [`Sensitive`] per §26.5: short-lived and single-use are both reasons it
    /// gets treated as harmless, but between the push and the redirect it is a
    /// bearer handle to a fully-formed authorization request, and a log line is
    /// the wrong place for it to sit for the length of that window.
    pub request_uri: Sensitive<String>,
    /// The handle's lifetime in seconds. Not advisory (§26.2 rule 3).
    pub expires_in: i64,
    /// The value to compare against the `state` the IdP returns.
    pub state: String,
    /// The value that must equal the ID token's `nonce` claim.
    pub nonce: String,
    /// The PKCE verifier to pass into `oidc_exchange` — the same one
    /// `oidc_begin` produced.
    pub code_verifier: Sensitive<String>,
}

/// Arguments to [`AxiamClient::oidc_par`].
///
/// Not `Clone`: it owns the [`AuthorizationRequest`], which is not `Clone`
/// either because it carries the PKCE verifier — one verifier, one login, and
/// a type that cannot be duplicated is one fewer way to get that wrong.
#[derive(Debug)]
pub struct OidcParParams {
    /// What `oidc_begin` returned. Its `url` is replaced by
    /// [`PushedAuthorizationRequest::url`].
    pub request: AuthorizationRequest,
    /// The relying party's redirect URI — the same value that will be sent at
    /// `oidc_exchange` (§26.2 rule 6).
    pub redirect_uri: String,
    /// Requested scope. `openid` is added when absent, exactly as `oidc_begin`
    /// does.
    pub scope: Option<String>,
    /// Tenant UUID override for the mandatory `?tenant_id=` query parameter
    /// (§12.1 note 2).
    pub tenant_id: Option<Uuid>,
    /// The discovery document; fetched via `oidc_discover` when `None`.
    pub configuration: Option<OidcConfiguration>,
}

#[derive(Serialize)]
struct ParForm<'a> {
    client_id: &'a str,
    response_type: &'a str,
    redirect_uri: &'a str,
    scope: &'a str,
    state: &'a str,
    nonce: &'a str,
    code_challenge: &'a str,
    code_challenge_method: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_secret: Option<&'a str>,
}

impl std::fmt::Debug for ParForm<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ParForm")
            .field("client_id", &self.client_id)
            .field("response_type", &self.response_type)
            .field("redirect_uri", &self.redirect_uri)
            .field("scope", &self.scope)
            .field("state", &self.state)
            .field("nonce", &self.nonce)
            .field("code_challenge", &self.code_challenge)
            .field("code_challenge_method", &self.code_challenge_method)
            .field(
                "client_secret",
                &self.client_secret.map(|_| "[REDACTED]").unwrap_or("None"),
            )
            .finish()
    }
}

#[derive(Deserialize)]
struct PushedAuthorizationWire {
    request_uri: String,
    expires_in: i64,
}

impl AxiamClient {
    /// `POST /oauth2/par` (CONTRACT.md §26.1) — push the authorization request
    /// over the back channel and get an opaque handle to redirect with.
    ///
    /// **Required for a FAPI 2.0 client**: `profile: "fapi2"` refuses a
    /// registration that does not set `require_par`, so such a client cannot
    /// authorize any other way (§21.1).
    ///
    /// Not retried on a `5xx` or a transport failure — it is a POST that
    /// creates server state, so it falls outside §16.2's read-only eligibility
    /// exactly as `oidc_exchange` does. The safe recovery is a fresh push,
    /// which costs one round trip and cannot double-consume anything (§26.2
    /// rule 4).
    pub async fn oidc_par(
        &self,
        params: OidcParParams,
    ) -> Result<PushedAuthorizationRequest, AxiamError> {
        self.ensure_open()?;

        let configuration = match params.configuration {
            Some(c) => c,
            None => self.oidc_discover().await?,
        };
        let tenant_id = self.resolve_oidc_tenant_id(params.tenant_id).await?;
        let client_id = self.oidc_client_id_or_err()?.to_string();

        let endpoint = configuration
            .pushed_authorization_request_endpoint
            .as_deref()
            .ok_or_else(|| {
                AxiamError::auth(
                    "the authorization server's discovery document advertises no \
                     pushed_authorization_request_endpoint: this server does not support \
                     RFC 9126 (CONTRACT.md §26.1)",
                )
            })?;
        let url = self.oidc_endpoint_url(endpoint, tenant_id)?;

        // §26.2 rule 1: everything below was computed by `oidc_begin`. There is
        // no second generator here, and there must not be — two sources for
        // `state` or the PKCE pair are two things that can disagree.
        let scope = normalize_scope(params.scope.as_deref());
        let code_challenge = compute_code_challenge(params.request.code_verifier.expose());
        let client_secret = self.oidc_client_secret().map(|s| s.expose().clone());

        let form = ParForm {
            client_id: &client_id,
            response_type: "code",
            redirect_uri: &params.redirect_uri,
            scope: &scope,
            state: &params.request.state,
            nonce: &params.request.nonce,
            code_challenge: &code_challenge,
            code_challenge_method: CODE_CHALLENGE_METHOD_S256,
            client_secret: client_secret.as_deref(),
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
                message: format!("pushed authorization request failed: {e}"),
                source: Some(Box::new(e)),
            })?;

        // 201, not 200. RFC 9126 §2.2 specifies Created, and this is the one
        // thing an implementation of this section gets wrong: a success
        // predicate written `== 200` treats every successful push as a failure
        // while passing every other assertion.
        if !response.status().is_success() {
            return Err(oauth2_error_or_fallback(response).await);
        }

        let wire: PushedAuthorizationWire =
            response.json().await.map_err(|e| AxiamError::Network {
                message: format!("failed to parse pushed authorization response: {e}"),
                source: Some(Box::new(e)),
            })?;

        // §26.2 rule 2: exactly two query parameters. The server REFUSES a
        // request carrying both a `request_uri` and any inline authorization
        // parameter rather than merging them: an attacker supplies the inline
        // value they want and lets the pushed copy satisfy whichever check
        // reads the other one. Re-adding them "for compatibility" restores the
        // attack.
        let mut target = url::Url::parse(&configuration.authorization_endpoint).map_err(|e| {
            AxiamError::Network {
                message: format!("invalid authorization_endpoint in discovery document: {e}"),
                source: None,
            }
        })?;
        target.set_query(None);
        target
            .query_pairs_mut()
            .append_pair("client_id", &client_id)
            .append_pair("request_uri", &wire.request_uri);

        Ok(PushedAuthorizationRequest {
            url: target.to_string(),
            request_uri: Sensitive::new(wire.request_uri),
            expires_in: wire.expires_in,
            state: params.request.state,
            nonce: params.request.nonce,
            code_verifier: params.request.code_verifier,
        })
    }
}
