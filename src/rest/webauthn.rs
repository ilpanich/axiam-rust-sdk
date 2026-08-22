//! WebAuthn and passkeys — CONTRACT.md §24.
//!
//! A passkey ceremony is **two exchanges stacked**: one with an
//! *authenticator*, which needs a platform API, and one with *AXIAM*, which is
//! four ordinary JSON round trips. The native Rust build has no authenticator,
//! so this module is the second half.
//!
//! That is not a consolation prize. A Rust service completing a ceremony that
//! ran on an Android or iOS handset is the relying party exactly as a browser
//! is, and §24.6b rule 2 forbids the alternative outright: an SDK MUST NOT
//! emulate an authenticator in software, because a "credential" held in process
//! memory is not a second factor.
//!
//! `axiam-sdk-wasm` is the one build of this SDK that *does* reach an
//! authenticator, through `web-sys`; it drives these same six operations.
//!
//! The rule everything below obeys is §24.0: the server chooses every option
//! and verifies every response, so this carries both through untouched. It does
//! not default a field, normalize one, or re-encode a buffer — the challenge is
//! held as [`serde_json::Value`] precisely so there is nothing to normalize
//! through.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use crate::AxiamError;
use crate::Sensitive;
use crate::client::{AxiamClient, OrgIdentifier, TenantIdentifier};
use crate::rest::auth::{CsrfHeaderExt, absorb_session_cookies, deser_err, map_error_response};

const REGISTER_START_PATH: &str = "/api/v1/auth/webauthn/register/start";
const REGISTER_FINISH_PATH: &str = "/api/v1/auth/webauthn/register/finish";
const AUTH_START_PATH: &str = "/api/v1/auth/webauthn/authenticate/start";
const AUTH_FINISH_PATH: &str = "/api/v1/auth/webauthn/authenticate/finish";
const DISCOVERABLE_START_PATH: &str = "/api/v1/auth/webauthn/authenticate/discoverable/start";
const DISCOVERABLE_FINISH_PATH: &str = "/api/v1/auth/webauthn/authenticate/discoverable/finish";

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// A started ceremony: the server's options plus the token binding a response
/// to them.
#[derive(Debug, Clone)]
pub struct WebauthnChallenge {
    /// The server's options, exactly as they arrived.
    ///
    /// A `{"publicKey": {…}}` object carrying base64url buffers. Hand it to the
    /// authenticator **unchanged** (§24.0), or call
    /// [`Self::request_json`] for the string a platform API takes.
    pub challenge: Value,
    /// Binds the authenticator's answer to this challenge.
    ///
    /// A bearer credential for the length of the ceremony — one that leaks
    /// inside that window is a ceremony an attacker can try to complete — so it
    /// is [`Sensitive`] (§24.5). It is **opaque**: this SDK never decodes it,
    /// and neither should a caller.
    pub state_token: Sensitive<String>,
}

impl WebauthnChallenge {
    /// The challenge in the JSON form every platform authenticator API takes
    /// (§24.6a rule 1).
    ///
    /// This is the string an Android app passes to
    /// `CreatePublicKeyCredentialRequest` or `GetPublicKeyCredentialOption`,
    /// and the value a browser passes to
    /// `PublicKeyCredential.parseCreationOptionsFromJSON()`. It is the inner
    /// options object: the `publicKey` wrapper belongs to the DOM's
    /// `CredentialCreationOptions`, and the platform JSON APIs do not want it.
    ///
    /// Pure local computation, no I/O. Nothing is defaulted, dropped or
    /// reordered on the way through (§24.0).
    pub fn request_json(&self) -> String {
        let options = self.challenge.get("publicKey").unwrap_or(&self.challenge);
        options.to_string()
    }
}

/// A credential the user just enrolled — the `201` body of `register/finish`.
#[derive(Debug, Clone, Deserialize)]
pub struct WebauthnCredential {
    /// The AXIAM record id.
    pub id: Uuid,
    /// base64url credential id, as the authenticator reported it.
    pub credential_id: String,
    /// The caller-supplied label.
    pub name: String,
    /// `"passkey"` or `"security_key"`, as the server classified it.
    pub credential_type: String,
    /// RFC 3339 timestamp of enrolment.
    pub created_at: String,
    /// RFC 3339 timestamp of the last successful assertion, if there has been
    /// one.
    #[serde(default)]
    pub last_used_at: Option<String>,
}

/// The outcome of a completed passkey sign-in.
///
/// The client is **already authenticated** when this is returned (§24.3
/// rule 1) — the tokens come back as well because a caller may want to hand
/// them onward, not because adoption was optional.
#[derive(Debug, Clone)]
pub struct WebauthnLoginResult {
    /// The new access token.
    pub access_token: Sensitive<String>,
    /// A **session** refresh token, refreshed through
    /// [`AxiamClient::refresh`] and not `oidc_refresh` (§24.3 rule 5).
    pub refresh_token: Sensitive<String>,
    /// Identifies the session just created.
    pub session_id: Uuid,
    /// Access-token lifetime in seconds.
    pub expires_in: u64,
}

/// The workspace a usernameless ceremony runs inside.
///
/// Unlike the five tenant-scoped `/oauth2/*` operations of §12.1 rule 2, this
/// endpoint **accepts slugs**, so a slug-only client can run a discoverable
/// sign-in. The SDK fills these from its own configured identity when the
/// caller passes `None`.
#[derive(Debug, Clone, Default)]
pub struct WebauthnWorkspace {
    /// Organization UUID.
    pub org_id: Option<Uuid>,
    /// Organization slug — accepted here, unlike on the `/oauth2/*` operations.
    pub org_slug: Option<String>,
    /// Tenant UUID.
    pub tenant_id: Option<Uuid>,
    /// Tenant slug.
    pub tenant_slug: Option<String>,
}

// ---------------------------------------------------------------------------
// Wire shapes
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct ChallengeWire {
    challenge: Value,
    state_token: String,
}

#[derive(Deserialize)]
struct LoginWire {
    access_token: String,
    refresh_token: String,
    session_id: Uuid,
    expires_in: u64,
}

#[derive(Serialize)]
struct RegisterFinishBody {
    state_token: String,
    credential_name: String,
    response: Value,
}

impl std::fmt::Debug for RegisterFinishBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegisterFinishBody")
            .field("state_token", &"[REDACTED]")
            .field("credential_name", &self.credential_name)
            .field("response", &self.response)
            .finish()
    }
}

#[derive(Serialize)]
struct FinishBody {
    state_token: String,
    response: Value,
}

impl std::fmt::Debug for FinishBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FinishBody")
            .field("state_token", &"[REDACTED]")
            .field("response", &self.response)
            .finish()
    }
}

#[derive(Debug, Serialize)]
struct AuthStartBody {
    challenge_token: String,
}

#[derive(Debug, Default, Serialize)]
struct DiscoverableStartBody {
    #[serde(skip_serializing_if = "Option::is_none")]
    org_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    org_slug: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tenant_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tenant_slug: Option<String>,
}

// ---------------------------------------------------------------------------
// The six operations
// ---------------------------------------------------------------------------

impl AxiamClient {
    /// `POST /api/v1/auth/webauthn/register/start` (CONTRACT.md §24.1).
    ///
    /// Enrolling a passkey is something a signed-in user does to their own
    /// account, so this requires a session and fails **client-side with no wire
    /// call** when there is none.
    ///
    /// A `503` means the tenant's attestation policy requires attestation and
    /// the FIDO metadata service has no usable snapshot. That is a server
    /// configuration state, not a transient failure, so §24.4 rule 2
    /// deliberately does not retry it.
    pub async fn webauthn_register_start(&self) -> Result<WebauthnChallenge, AxiamError> {
        self.ensure_open()?;
        self.require_webauthn_session("webauthn_register_start")?;
        self.webauthn_start(REGISTER_START_PATH, &serde_json::json!({}))
            .await
    }

    /// `POST /api/v1/auth/webauthn/register/finish` (CONTRACT.md §24.1).
    ///
    /// `response` is the authenticator's answer, as
    /// [`serde_json::Value`] — build it from a platform's own JSON string with
    /// [`webauthn_response_from_json`] (§24.6a rule 2). It reaches the server
    /// unchanged: it is the input to a signature check over bytes this SDK did
    /// not produce.
    ///
    /// A `403` is the tenant's attestation policy refusing **this
    /// authenticator** — an AAGUID that is not allow-listed, a missing FIDO
    /// certification, a revoked status — not a permission problem with the
    /// user. The server's message is surfaced verbatim (§24.4 rule 1), because
    /// it is the only way the person holding the key learns a different one
    /// would work.
    pub async fn webauthn_register_finish(
        &self,
        state_token: &Sensitive<String>,
        credential_name: &str,
        response: Value,
    ) -> Result<WebauthnCredential, AxiamError> {
        self.ensure_open()?;
        self.require_webauthn_session("webauthn_register_finish")?;

        let body = RegisterFinishBody {
            state_token: state_token.expose().clone(),
            credential_name: credential_name.to_string(),
            response,
        };
        let http_response = self.webauthn_post(REGISTER_FINISH_PATH, &body).await?;

        match http_response.status().as_u16() {
            200 | 201 => http_response
                .json::<WebauthnCredential>()
                .await
                .map_err(deser_err),
            status => Err(map_error_response(status, http_response).await),
        }
    }

    /// `POST /api/v1/auth/webauthn/authenticate/start` (CONTRACT.md §24.1).
    ///
    /// The **second-factor** ceremony: it continues a
    /// [`login`](AxiamClient::login) that answered `mfa_required` with
    /// `"webauthn"` among its methods, and `challenge_token` is that result's
    /// token.
    ///
    /// A different flow from [`Self::webauthn_discoverable_start`], not the
    /// same one with an optional argument — see §24.2 for why they cannot be
    /// merged.
    pub async fn webauthn_authenticate_start(
        &self,
        challenge_token: &Sensitive<String>,
    ) -> Result<WebauthnChallenge, AxiamError> {
        self.ensure_open()?;
        let body = AuthStartBody {
            challenge_token: challenge_token.expose().clone(),
        };
        self.webauthn_start(AUTH_START_PATH, &body).await
    }

    /// `POST /api/v1/auth/webauthn/authenticate/finish` (CONTRACT.md §24.1).
    ///
    /// Leaves this client authenticated (§24.3 rule 1). That is not §14.3's
    /// "MAY adopt" posture: `device_login` mints tokens a caller may want to
    /// route elsewhere, and this is the SDK's own primary authentication —
    /// returning a token set without adopting it would make a passkey sign-in
    /// the one way to log in that does not log you in.
    pub async fn webauthn_authenticate_finish(
        &self,
        state_token: &Sensitive<String>,
        response: Value,
    ) -> Result<WebauthnLoginResult, AxiamError> {
        self.webauthn_finish(AUTH_FINISH_PATH, state_token, response)
            .await
    }

    /// `POST /api/v1/auth/webauthn/authenticate/discoverable/start`
    /// (CONTRACT.md §24.1).
    ///
    /// The **primary-factor** ceremony: nothing precedes it, the server sends
    /// an empty `allowCredentials`, and the assertion itself identifies the
    /// user.
    ///
    /// The workspace still has to be named — a discoverable credential is
    /// resolved inside one tenant's isolation boundary — but it comes from this
    /// client's own configuration unless overridden, and slugs are accepted.
    pub async fn webauthn_discoverable_start(
        &self,
        workspace: Option<&WebauthnWorkspace>,
    ) -> Result<WebauthnChallenge, AxiamError> {
        self.ensure_open()?;
        let body = self.webauthn_workspace_body(workspace)?;
        self.webauthn_start(DISCOVERABLE_START_PATH, &body).await
    }

    /// `POST /api/v1/auth/webauthn/authenticate/discoverable/finish`
    /// (CONTRACT.md §24.1).
    ///
    /// Leaves this client authenticated (§24.3). Unlike its username-bound
    /// twin, this fires the server's `login.post_auth` reactor hook (§22.5):
    /// there was no password step for the event to have been fired at.
    pub async fn webauthn_discoverable_finish(
        &self,
        state_token: &Sensitive<String>,
        response: Value,
    ) -> Result<WebauthnLoginResult, AxiamError> {
        self.webauthn_finish(DISCOVERABLE_FINISH_PATH, state_token, response)
            .await
    }

    // -----------------------------------------------------------------------
    // Internals
    // -----------------------------------------------------------------------

    /// Run either `*_start` call and return the options untouched.
    async fn webauthn_start<B: Serialize>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<WebauthnChallenge, AxiamError> {
        let response = self.webauthn_post(path, body).await?;
        match response.status().as_u16() {
            200 => {
                let wire: ChallengeWire = response.json().await.map_err(deser_err)?;
                Ok(WebauthnChallenge {
                    challenge: wire.challenge,
                    state_token: Sensitive::new(wire.state_token),
                })
            }
            status => Err(map_error_response(status, response).await),
        }
    }

    /// The shared tail of both authentication ceremonies.
    async fn webauthn_finish(
        &self,
        path: &str,
        state_token: &Sensitive<String>,
        response: Value,
    ) -> Result<WebauthnLoginResult, AxiamError> {
        self.ensure_open()?;
        // §17.1 rule 9 / §24.3 rule 4: memo entries are keyed by subject, and
        // this call changes the subject.
        self.decision_memo().clear();

        let body = FinishBody {
            state_token: state_token.expose().clone(),
            response,
        };
        let http_response = self.webauthn_post(path, &body).await?;

        match http_response.status().as_u16() {
            200 => {
                let wire: LoginWire = http_response.json().await.map_err(deser_err)?;
                // The server sets the same axiam_access/axiam_refresh/axiam_csrf
                // triple here as it does on a password login, so adoption is
                // the same call.
                absorb_session_cookies(self).await?;
                Ok(WebauthnLoginResult {
                    access_token: Sensitive::new(wire.access_token),
                    refresh_token: Sensitive::new(wire.refresh_token),
                    session_id: wire.session_id,
                    expires_in: wire.expires_in,
                })
            }
            status => Err(map_error_response(status, http_response).await),
        }
    }

    /// POST a JSON body.
    ///
    /// Deliberately not routed through §16's retry helper, and that is true for
    /// the whole section: five of the six operations are ceremony steps that
    /// consume server-side state, and the sixth (`register/start`) carries the
    /// `503` §24.4 rule 2 forbids retrying. There is nothing here a bounded
    /// retry could help.
    async fn webauthn_post<B: Serialize>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<reqwest::Response, AxiamError> {
        self.http()
            .post(self.url(path))
            .maybe_csrf_header(self)
            .json(body)
            .send()
            .await
            .map_err(|e| AxiamError::Network {
                message: format!("webauthn request failed: {e}"),
                source: Some(Box::new(e)),
            })
    }

    /// §24.1: `register/*` needs a session, and the refusal is raised
    /// client-side with **no wire call** — the shape §1.1 rule 3 requires of
    /// `get_user_info`.
    ///
    /// The signal is the access cookie rather than a separate flag: this SDK
    /// has never kept one, and a second source of truth for "am I signed in" is
    /// a second thing to get out of step with the jar.
    fn require_webauthn_session(&self, operation: &str) -> Result<(), AxiamError> {
        if self.inner.jar.access_token(&self.inner.base_url).is_none() {
            return Err(AxiamError::Auth {
                message: format!(
                    "{operation} requires an authenticated session: enrol a passkey while \
                     signed in (CONTRACT.md §24.1)"
                ),
                oauth: None,
                reason: None,
            });
        }
        Ok(())
    }

    /// Fill the discoverable ceremony's workspace from this client's own
    /// configuration when the caller passed none.
    ///
    /// Only fields that actually have a value are emitted: the server takes
    /// either form at either level, and sending `null` for the ones it does not
    /// have is indistinguishable from asking it to resolve nothing.
    fn webauthn_workspace_body(
        &self,
        workspace: Option<&WebauthnWorkspace>,
    ) -> Result<DiscoverableStartBody, AxiamError> {
        let mut body = DiscoverableStartBody {
            org_id: workspace.and_then(|w| w.org_id),
            org_slug: workspace.and_then(|w| w.org_slug.clone()),
            tenant_id: workspace.and_then(|w| w.tenant_id),
            tenant_slug: workspace.and_then(|w| w.tenant_slug.clone()),
        };

        if body.org_id.is_none() && body.org_slug.is_none() {
            match self.org_identifier() {
                Some(OrgIdentifier::Id(id)) => body.org_id = Some(*id),
                Some(OrgIdentifier::Slug(slug)) => body.org_slug = Some(slug.clone()),
                None => {
                    // This SDK's §2 taxonomy has three variants and no
                    // Validation; a missing client configuration is a
                    // deployment mistake, which §12.1 already routes through
                    // `Auth` for the same reason.
                    return Err(AxiamError::auth(
                        "webauthn_discoverable_start needs an organization: construct the \
                         client with one, or pass it in the workspace argument \
                         (CONTRACT.md §24.1)",
                    ));
                }
            }
        }
        if body.tenant_id.is_none() && body.tenant_slug.is_none() {
            match &self.inner.tenant {
                TenantIdentifier::Id(id) => body.tenant_id = Some(*id),
                TenantIdentifier::Slug(slug) => body.tenant_slug = Some(slug.clone()),
            }
        }
        Ok(body)
    }
}

/// Parse a platform's authenticator response JSON into the value the
/// `*_finish` operations take (§24.6a rule 2).
///
/// Android's Credential Manager hands back `registrationResponseJson` /
/// `authenticationResponseJson`, and a browser hands back
/// `credential.toJSON()`. Making a caller model one of those as a Rust struct
/// this SDK immediately re-serializes is three chances to corrupt a signed
/// buffer in service of nothing — so the string is taken directly.
///
/// Parsing is value-preserving: every field in these messages is a string or a
/// plain object, so what reaches the server is what the authenticator produced.
pub fn webauthn_response_from_json(response: &str) -> Result<Value, AxiamError> {
    let value: Value = serde_json::from_str(response).map_err(|e| {
        AxiamError::auth(format!(
            "the authenticator response string is not valid JSON ({e}). Pass the platform's \
             response JSON verbatim (CONTRACT.md §24.6a)"
        ))
    })?;
    if !value.is_object() {
        return Err(AxiamError::auth(
            "the authenticator response must be a JSON object (CONTRACT.md §24.6a)",
        ));
    }
    Ok(value)
}

// ---------------------------------------------------------------------------
// §24.6b rule 5 — ceremony failure classification
// ---------------------------------------------------------------------------

/// A ceremony failure a caller can say something useful about (§24.6b rule 5).
///
/// Five outcomes, and the first two are the ones that matter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WebauthnFailure {
    /// Covers **both** an explicit refusal and a silent timeout.
    ///
    /// The WebAuthn spec deliberately refuses to distinguish them, because
    /// telling a website which one happened leaks whether an authenticator was
    /// present. It must not be recovered by timing the call.
    Cancelled,
    /// The authenticator already holds a credential for this account and
    /// refused to silently mint a second — the exclusion list working, not a
    /// failure. The only classification whose remedy is "use a different
    /// device".
    AlreadyRegistered,
    /// An explicitly aborted ceremony.
    Timeout,
    /// This device or browser cannot run the ceremony.
    Unsupported,
    /// Everything else.
    Unknown,
}

impl WebauthnFailure {
    /// Map a platform ceremony error name to its canonical classification.
    ///
    /// Every platform reports a ceremony failure as one opaque type whose only
    /// machine-readable part is a name, so a handset can relay just that name
    /// and a Rust service can turn it into the same five outcomes a browser
    /// would see. Anything unrecognized is [`Self::Unknown`] rather than an
    /// error — a classifier that can fail is one more thing for an error
    /// handler to handle.
    pub fn classify(name: &str) -> Self {
        match name.trim().to_ascii_lowercase().as_str() {
            "notallowederror" | "canceled" | "cancelled" => Self::Cancelled,
            "invalidstateerror" => Self::AlreadyRegistered,
            "aborterror" | "timeout" => Self::Timeout,
            "notsupportederror" | "securityerror" => Self::Unsupported,
            _ => Self::Unknown,
        }
    }

    /// Copy for this failure, safe to show a user.
    ///
    /// The [`Self::Cancelled`] string deliberately does not accuse anyone of
    /// cancelling: the same classification covers a silent timeout, and the
    /// spec will not say which happened.
    pub fn message(self) -> &'static str {
        match self {
            Self::Cancelled => "The request was cancelled or timed out. You can try again.",
            Self::AlreadyRegistered => {
                "This device is already registered on your account. Try a different device, \
                 or remove the existing one first."
            }
            Self::Timeout => "The request timed out before it completed. Please try again.",
            Self::Unsupported => {
                "This browser or device cannot be used for passkeys. Try a different browser, \
                 or use another sign-in method."
            }
            Self::Unknown => "Something went wrong. Please try again.",
        }
    }
}
