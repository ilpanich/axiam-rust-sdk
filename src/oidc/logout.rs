//! RP-initiated and back-channel logout — CONTRACT.md §12.7 (contract 1.7).
//!
//! Two operations on opposite sides of the flow:
//!
//! * [`AxiamClient::logout_url`] builds the URL to redirect the user agent
//!   to. Pure local computation — no network I/O of its own.
//! * [`AxiamClient::verify_logout_token`] validates a logout token the OP
//!   **pushed** to this application's own back-channel endpoint.
//!
//! The second is where the security weight sits: its input arrives
//! unsolicited, from the network, and instructs the RP to terminate a
//! session.

use serde::Deserialize;
use serde_json::{Map, Value};

use super::discovery::OidcConfiguration;
use crate::client::AxiamClient;
use crate::error::{AxiamError, IdTokenFailureReason};
use crate::sensitive::Sensitive;

/// The `events` member that distinguishes a logout token from an ID token
/// (OIDC Back-Channel Logout 1.0 §2.4).
pub const BACKCHANNEL_LOGOUT_EVENT: &str = "http://schemas.openid.net/event/backchannel-logout";

/// Maximum age accepted for a logout token's `iat`, in seconds.
///
/// AXIAM issues them with a 120 s lifetime; this bound is the same order and
/// exists so a token captured from a mis-configured RP cannot be replayed
/// days later against a correctly configured one.
pub const MAX_LOGOUT_TOKEN_AGE_SECS: i64 = 300;

#[derive(Debug, Deserialize)]
struct LogoutTokenClaims {
    iss: String,
    aud: String,
    iat: i64,
    exp: i64,
    jti: String,
    #[serde(default)]
    sid: Option<String>,
    #[serde(default)]
    sub: Option<String>,
    #[serde(default)]
    events: Option<Map<String, Value>>,
    /// Never legitimately present. See [`AxiamClient::verify_logout_token`].
    #[serde(default)]
    nonce: Option<String>,
}

/// Arguments to [`AxiamClient::logout_url`].
pub struct LogoutUrlParams {
    /// A previously-issued ID token, placed in `id_token_hint`. The only
    /// *authenticated* statement of which session is being ended.
    pub id_token: Sensitive<String>,
    /// Where the OP should send the browser afterwards. Honoured only if it
    /// exactly matches the client's registered allow-list — a server-side
    /// check the SDK deliberately does not duplicate.
    pub post_logout_redirect_uri: Option<String>,
    /// An opaque value echoed back on the redirect. Generated and checked by
    /// the caller (§12.7.2 rule 2), never by the SDK.
    pub state: Option<String>,
}

impl LogoutUrlParams {
    /// The minimal form: just the ID token hint.
    pub fn new(id_token: Sensitive<String>) -> Self {
        Self {
            id_token,
            post_logout_redirect_uri: None,
            state: None,
        }
    }
}

/// What a verified logout token names (§12.7.3).
///
/// Deliberately **not** a bare `bool`: the RP has to know *which* session to
/// end, and a verifier that only says "valid" would force the caller to
/// re-parse the token themselves, with none of the checks this type is proof
/// of.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedLogoutToken {
    /// The session that ended. **When present, end only this session.**
    /// Falling back to "every session for `sub`" is over-reach the AXIAM
    /// server itself refuses to make.
    pub sid: Option<String>,
    /// The subject whose session ended.
    pub sub: Option<String>,
    /// Replay identifier.
    ///
    /// **The RP dedups on this, not the SDK.** Back-channel delivery is
    /// at-least-once with retry, so a valid token legitimately arrives
    /// twice; the SDK has no durable store and an in-memory guard would
    /// silently drop a real second logout after a restart. Surfaced, never
    /// consumed.
    pub jti: String,
}

impl AxiamClient {
    /// Build the RP-initiated logout URL to redirect the user agent to
    /// (CONTRACT.md §12.7.2).
    ///
    /// Performs **no network I/O** beyond the discovery fetch the SDK would
    /// cache anyway, and does **not** clear this client's own session:
    /// whether the local session ends is the application's decision — a
    /// backend holding a service-account session must not lose it because a
    /// *user* logged out.
    ///
    /// `end_session_endpoint` is read from discovery and never synthesised
    /// from the issuer (§12.7.2 rule 1). Code that concatenates
    /// `{issuer}/oauth2/end_session` works against AXIAM and breaks against
    /// every other OP the same application is pointed at — which is the
    /// entire reason discovery exists.
    ///
    /// `post_logout_redirect_uri` is passed through **unvalidated against
    /// any local list** (rule 3): the allow-list lives in the client's
    /// server-side registration, and a client-side copy would drift and
    /// reject a URI an operator had just registered.
    pub fn logout_url(
        &self,
        configuration: &OidcConfiguration,
        params: LogoutUrlParams,
    ) -> Result<String, AxiamError> {
        let endpoint = configuration.end_session_endpoint.as_deref().ok_or_else(|| {
            AxiamError::Auth {
                message:
                    "the authorization server's discovery document advertises no end_session_endpoint: this server does not support RP-initiated logout (CONTRACT.md §12.7.2 rule 1)"
                        .into(),
                oauth: None,
                reason: None,
            }
        })?;

        let mut url = url::Url::parse(endpoint).map_err(|e| AxiamError::Network {
            message: format!("invalid end_session_endpoint in discovery document: {e}"),
            source: None,
        })?;

        {
            let mut q = url.query_pairs_mut();
            q.append_pair("id_token_hint", params.id_token.expose().as_str());
            if let Some(uri) = params.post_logout_redirect_uri.as_deref() {
                q.append_pair("post_logout_redirect_uri", uri);
            }
            if let Some(state) = params.state.as_deref() {
                q.append_pair("state", state);
            }
        }

        Ok(url.to_string())
    }

    /// Verify a back-channel logout token the OP POSTed to this
    /// application's `backchannel_logout_uri` (CONTRACT.md §12.7.3).
    ///
    /// Every check below is required, and each exists because skipping it
    /// has a name:
    ///
    /// 1. **Signature**, through the same §12.4 JWKS verifier the ID-token
    ///    path uses — no second key-fetching path.
    /// 2. **`iss`** matches the configured issuer, **`aud`** matches this
    ///    client's `client_id`: a token minted for another RP is not
    ///    accepted here.
    /// 3. **`events` contains [`BACKCHANNEL_LOGOUT_EVENT`]**. This is what
    ///    distinguishes a logout token from an ID token; skipping it means
    ///    accepting a replayed ID token as a logout instruction.
    /// 4. **`nonce` is absent.** Back-Channel Logout 1.0 §2.4 forbids it,
    ///    and its presence is the documented signature of an ID token being
    ///    replayed. Rejected, not ignored.
    /// 5. **At least one of `sid`/`sub`.** A token naming neither identifies
    ///    nothing.
    /// 6. **`exp` in the future, `iat` recent.**
    ///
    /// Failure is an [`AxiamError::Auth`] carrying a §12.3 reason code and
    /// **never** echoes the token.
    pub async fn verify_logout_token(
        &self,
        token: &str,
        configuration: &OidcConfiguration,
    ) -> Result<VerifiedLogoutToken, AxiamError> {
        // 1. Signature (and alg/kid discipline) — reused, not reimplemented.
        let verifier = self.oidc_verifier_for(&configuration.jwks_uri)?;
        let claims: LogoutTokenClaims = verifier.verify_id_token_signature(token).await?;

        // 2. Issuer / audience.
        if claims.iss != configuration.issuer {
            return Err(AxiamError::id_token_invalid(
                IdTokenFailureReason::InvalidIssuer,
                "logout token issuer does not match the discovery document",
            ));
        }
        let client_id = self.oidc_client_id_or_err()?;
        if claims.aud != client_id {
            return Err(AxiamError::id_token_invalid(
                IdTokenFailureReason::InvalidAudience,
                "logout token audience does not match this client_id",
            ));
        }

        // 3. The events member. Without this check the whole function is an
        // elaborate way to accept an ID token.
        let has_event = claims.events.as_ref().is_some_and(|e| {
            e.get(BACKCHANNEL_LOGOUT_EVENT)
                .is_some_and(Value::is_object)
        });
        if !has_event {
            return Err(AxiamError::id_token_invalid(
                IdTokenFailureReason::InvalidSignature,
                "not a logout token: the events claim does not carry \
                 http://schemas.openid.net/event/backchannel-logout",
            ));
        }

        // 4. nonce MUST be absent.
        if claims.nonce.is_some() {
            return Err(AxiamError::id_token_invalid(
                IdTokenFailureReason::NonceMismatch,
                "logout token carries a nonce, which Back-Channel Logout 1.0 §2.4 forbids: \
                 this is an ID token being replayed as a logout token",
            ));
        }

        // 5. Something must be named.
        if claims.sid.is_none() && claims.sub.is_none() {
            return Err(AxiamError::id_token_invalid(
                IdTokenFailureReason::InvalidSignature,
                "logout token names neither sid nor sub, so it identifies no session",
            ));
        }

        // 6. Freshness. The same clock-skew allowance the §12.4 checklist
        // uses, so the two paths cannot disagree about what "now" means.
        let now = crate::time::SystemTime::now()
            .duration_since(crate::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let skew = self.oidc_clock_skew_sec() as i64;
        if claims.exp + skew < now {
            return Err(AxiamError::id_token_invalid(
                IdTokenFailureReason::TokenExpired,
                "logout token has expired",
            ));
        }
        if claims.iat - skew > now {
            return Err(AxiamError::id_token_invalid(
                IdTokenFailureReason::TokenExpired,
                "logout token was issued in the future",
            ));
        }
        if now - claims.iat > MAX_LOGOUT_TOKEN_AGE_SECS + skew {
            return Err(AxiamError::id_token_invalid(
                IdTokenFailureReason::TokenExpired,
                "logout token is too old to be a live delivery",
            ));
        }

        Ok(VerifiedLogoutToken {
            sid: claims.sid,
            sub: claims.sub,
            jti: claims.jti,
        })
    }
}
