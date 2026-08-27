//! Account lifecycle and MFA enrolment — CONTRACT.md §25.
//!
//! §1 locked the *middle* of an account's life: `login`, `verify_mfa`,
//! `refresh` and `logout` all assume an account that already exists, is
//! verified, and already has its second factor. These nine operations are how
//! an account gets into that state. None of them is new server surface — all
//! nine have been live and unreachable-from-an-SDK since before §1 was written,
//! which meant every application hand-rolled a POST against a path this SDK
//! also knew.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use crate::AxiamError;
use crate::Sensitive;
use crate::client::{AxiamClient, OrgIdentifier, TenantIdentifier};
use crate::rest::LoginResult;
use crate::rest::auth::{CsrfHeaderExt, absorb_session_cookies, deser_err, map_error_response};

const MFA_ENROLL_PATH: &str = "/api/v1/auth/mfa/enroll";
const MFA_CONFIRM_PATH: &str = "/api/v1/auth/mfa/confirm";
const MFA_SETUP_ENROLL_PATH: &str = "/api/v1/auth/mfa/setup/enroll";
const MFA_SETUP_CONFIRM_PATH: &str = "/api/v1/auth/mfa/setup/confirm";
const VERIFY_EMAIL_PATH: &str = "/api/v1/auth/verify-email";
const RESEND_VERIFICATION_PATH: &str = "/api/v1/auth/resend-verification";
const RESEND_OWN_VERIFICATION_PATH: &str = "/api/v1/users/me/resend-verification";
const RESET_PATH: &str = "/api/v1/auth/reset";
const RESET_CONFIRM_PATH: &str = "/api/v1/auth/reset/confirm";
const RESET_CONTEXT_PATH: &str = "/api/v1/auth/reset/context";

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// A TOTP enrolment offer.
///
/// **The factor is not active yet.** It becomes active when
/// [`AxiamClient::mfa_confirm`] accepts a code derived from this secret — which
/// is why §25.2 rule 4 forbids a composed one-call helper here: the human step
/// in the middle, scanning the URI and reading a code, is not something a
/// helper can wait for, and one that returned after `mfa_enroll` would report
/// MFA as enabled when it is not.
#[derive(Debug, Clone)]
pub struct MfaEnrollment {
    /// The shared TOTP secret, base32. Anyone holding it can generate valid
    /// codes indefinitely.
    pub secret_base32: Sensitive<String>,
    /// `otpauth://totp/…?secret=<secret_base32>` — so it *contains* the secret
    /// beside it. Both are [`Sensitive`] for that reason, and this is the one
    /// that actually reaches a log, because it is the one a caller hands to a
    /// QR renderer (§25.3).
    pub totp_uri: Sensitive<String>,
}

/// The effective OPAQUE policy for the account a reset token belongs to.
///
/// Discloses no identity. Contract 1.26 removed the username from this response
/// when OPAQUE replaced SRP — OPAQUE has no identity in its key derivation, so
/// nothing needed it, and an unauthenticated endpoint that confirms which
/// account a token belongs to is an oracle worth not having (§25.4 rule 2).
#[derive(Debug, Clone, Default, Deserialize)]
pub struct PasswordResetContext {
    /// The tenant's OPAQUE parameters when it has OPAQUE enabled; `None` means
    /// plaintext is accepted.
    #[serde(default)]
    pub opaque: Option<Value>,
}

/// Names the account a reset mail should go to.
///
/// Slugs are accepted here, as on `login` — this is not an `/oauth2/*` endpoint
/// and §12.1 rule 2's UUID requirement does not reach it. `None` fields fall
/// back to the client's own configuration.
#[derive(Debug, Clone, Default)]
pub struct PasswordResetRequest {
    /// The address to send the reset mail to.
    pub email: String,
    /// Organization slug.
    pub org_slug: Option<String>,
    /// Tenant UUID.
    pub tenant_id: Option<Uuid>,
    /// Tenant slug.
    pub tenant_slug: Option<String>,
}

/// Everything [`AxiamClient::confirm_password_reset`] needs.
#[derive(Debug, Clone)]
pub struct PasswordResetConfirmation {
    /// The single-use token from the reset mail.
    pub token: Sensitive<String>,
    /// The replacement password.
    pub new_password: Sensitive<String>,
    /// The tenant the account belongs to. A **body** field — this is not an
    /// `/oauth2/*` endpoint.
    pub tenant_id: Uuid,
    /// The §23 registration record, for a tenant whose
    /// [`AxiamClient::password_reset_context`] says it requires one. Sending a
    /// plaintext `new_password` to a tenant in `opaque_mode: required` is
    /// refused, and refused late (§25.4 rule 1).
    pub opaque: Option<Value>,
}

// ---------------------------------------------------------------------------
// Wire shapes
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct MfaEnrollWire {
    secret_base32: String,
    totp_uri: String,
}

#[derive(Deserialize)]
struct MfaConfirmWire {
    mfa_enabled: bool,
}

#[derive(Deserialize)]
struct LoginSuccessWire {
    session_id: Uuid,
    expires_in: u64,
}

#[derive(Serialize)]
struct TotpCodeBody {
    totp_code: String,
}

impl std::fmt::Debug for TotpCodeBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TotpCodeBody")
            .field("totp_code", &"[REDACTED]")
            .finish()
    }
}

#[derive(Serialize)]
struct SetupTokenBody {
    setup_token: String,
}

impl std::fmt::Debug for SetupTokenBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SetupTokenBody")
            .field("setup_token", &"[REDACTED]")
            .finish()
    }
}

#[derive(Serialize)]
struct SetupConfirmBody {
    setup_token: String,
    totp_code: String,
}

impl std::fmt::Debug for SetupConfirmBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SetupConfirmBody")
            .field("setup_token", &"[REDACTED]")
            .field("totp_code", &"[REDACTED]")
            .finish()
    }
}

#[derive(Serialize)]
struct VerifyEmailBody {
    token: String,
    tenant_id: Uuid,
}

impl std::fmt::Debug for VerifyEmailBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerifyEmailBody")
            .field("token", &"[REDACTED]")
            .field("tenant_id", &self.tenant_id)
            .finish()
    }
}

#[derive(Debug, Serialize)]
struct ResendVerificationBody {
    email: String,
    tenant_id: Uuid,
}

#[derive(Debug, Default, Serialize)]
struct ResetBody {
    email: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    org_slug: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tenant_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tenant_slug: Option<String>,
}

#[derive(Serialize)]
struct ResetConfirmBody {
    token: String,
    new_password: String,
    tenant_id: Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    opaque: Option<Value>,
}

impl std::fmt::Debug for ResetConfirmBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResetConfirmBody")
            .field("token", &"[REDACTED]")
            .field("new_password", &"[REDACTED]")
            .field("tenant_id", &self.tenant_id)
            .field("opaque", &self.opaque)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// The ten operations
// ---------------------------------------------------------------------------

impl AxiamClient {
    /// `POST /api/v1/auth/mfa/enroll` (CONTRACT.md §25.1) — start voluntary
    /// TOTP enrolment for the signed-in user.
    ///
    /// Changes nothing about the current session. In particular it does **not**
    /// clear the §17 decision memo: the subject has not changed, and discarding
    /// a warm memo on an unrelated profile action costs a round trip on every
    /// check that follows (§25.2 rule 3).
    pub async fn mfa_enroll(&self) -> Result<MfaEnrollment, AxiamError> {
        self.ensure_open()?;
        let response = self
            .account_post(MFA_ENROLL_PATH, &serde_json::json!({}))
            .await?;
        Self::mfa_enrollment(response).await
    }

    /// `POST /api/v1/auth/mfa/confirm` (CONTRACT.md §25.1) — activate the
    /// factor [`Self::mfa_enroll`] offered.
    pub async fn mfa_confirm(&self, totp_code: &str) -> Result<bool, AxiamError> {
        self.ensure_open()?;
        let body = TotpCodeBody {
            totp_code: totp_code.to_string(),
        };
        let response = self.account_post(MFA_CONFIRM_PATH, &body).await?;
        match response.status().as_u16() {
            200 => Ok(response
                .json::<MfaConfirmWire>()
                .await
                .map_err(deser_err)?
                .mfa_enabled),
            status => Err(map_error_response(status, response).await),
        }
    }

    /// `POST /api/v1/auth/mfa/setup/enroll` (CONTRACT.md §25.1) — start the
    /// enrolment a `login()` demanded.
    ///
    /// Reached when `login()` returns `mfa_setup_required`: the tenant requires
    /// MFA and this account has none. There is no session yet — the setup token
    /// *is* the credential.
    pub async fn mfa_setup_enroll(
        &self,
        setup_token: &Sensitive<String>,
    ) -> Result<MfaEnrollment, AxiamError> {
        self.ensure_open()?;
        let body = SetupTokenBody {
            setup_token: setup_token.expose().clone(),
        };
        let response = self.account_post(MFA_SETUP_ENROLL_PATH, &body).await?;
        Self::mfa_enrollment(response).await
    }

    /// `POST /api/v1/auth/mfa/setup/confirm` (CONTRACT.md §25.1) — finish
    /// forced enrolment and, with it, the login that was interrupted.
    ///
    /// Adopts credentials exactly as `login()` does, because it *is* the
    /// completion of a login (§25.2 rule 2).
    pub async fn mfa_setup_confirm(
        &self,
        setup_token: &Sensitive<String>,
        totp_code: &str,
    ) -> Result<LoginResult, AxiamError> {
        self.ensure_open()?;
        self.decision_memo().clear();

        let body = SetupConfirmBody {
            setup_token: setup_token.expose().clone(),
            totp_code: totp_code.to_string(),
        };
        let response = self.account_post(MFA_SETUP_CONFIRM_PATH, &body).await?;
        match response.status().as_u16() {
            200 => {
                let wire: LoginSuccessWire = response.json().await.map_err(deser_err)?;
                absorb_session_cookies(self).await?;
                Ok(LoginResult::success(wire.session_id, wire.expires_in))
            }
            status => Err(map_error_response(status, response).await),
        }
    }

    /// `POST /api/v1/auth/verify-email` (CONTRACT.md §25.1).
    ///
    /// Unauthenticated: a user whose address is unverified may have no session
    /// at all. `tenant_id` is a **body** field here — this is not an
    /// `/oauth2/*` endpoint, so §12.1 rule 2's query-parameter convention does
    /// not reach it.
    pub async fn verify_email(
        &self,
        token: &Sensitive<String>,
        tenant_id: Uuid,
    ) -> Result<(), AxiamError> {
        self.ensure_open()?;
        let body = VerifyEmailBody {
            token: token.expose().clone(),
            tenant_id,
        };
        let response = self.account_post(VERIFY_EMAIL_PATH, &body).await?;
        Self::expect_success(response).await
    }

    /// `POST /api/v1/auth/resend-verification` (CONTRACT.md §25.1) — the
    /// **unauthenticated** resend, for a caller with no session.
    ///
    /// **Returns `Ok(())` whatever the outcome.** The address may not exist,
    /// may already be verified, or may be over the daily limit, and this
    /// operation answers identically in all four cases because it takes an
    /// address from an anonymous caller: anything else is an oracle for which
    /// addresses have accounts (§25.7).
    ///
    /// A caller that *is* signed in wants
    /// [`resend_own_verification`](Self::resend_own_verification), which says
    /// which of those happened. Do not reach for this one because it is the
    /// name you already knew.
    pub async fn resend_verification(
        &self,
        email: &str,
        tenant_id: Uuid,
    ) -> Result<(), AxiamError> {
        self.ensure_open()?;
        let body = ResendVerificationBody {
            email: email.to_string(),
            tenant_id,
        };
        let response = self.account_post(RESEND_VERIFICATION_PATH, &body).await?;
        Self::expect_success(response).await
    }

    /// `POST /api/v1/users/me/resend-verification` (CONTRACT.md §25.1, §25.7)
    /// — resend the **signed-in caller's own** verification mail, and say what
    /// happened.
    ///
    /// Takes no address. The server reads it off the caller's own record, and
    /// this signature deliberately offers no way to name a different one: a
    /// parameter here would let an authenticated session mail an arbitrary
    /// address.
    ///
    /// Unlike [`resend_verification`](Self::resend_verification) this reports
    /// the outcome, because the caller is signed in to the account it is asking
    /// about and none of the outcomes tells it anything it did not already
    /// know:
    ///
    /// * `Ok(())` — a token was minted and the mail **enqueued**. Delivery is
    ///   asynchronous and can still fail at the provider; a queue that accepts
    ///   everything in front of a provider that rejects it looks exactly like
    ///   this succeeding.
    /// * [`AxiamError::Authz`] (from `409`) — already verified, or the account
    ///   is in a state that must not be sent a live token.
    /// * [`AxiamError::Network`] (from `429`) — the daily resend limit.
    ///
    /// §25.7 rule 2 forbids falling back to the unauthenticated endpoint on
    /// either of those, and this SDK does not: that fallback would turn both
    /// failures back into a green `Ok(())` and restore the bug this operation
    /// exists to fix, with an extra round-trip.
    pub async fn resend_own_verification(&self) -> Result<(), AxiamError> {
        self.ensure_open()?;
        let response = self
            .account_post(RESEND_OWN_VERIFICATION_PATH, &serde_json::json!({}))
            .await?;
        Self::expect_success(response).await
    }

    /// `POST /api/v1/auth/reset` (CONTRACT.md §25.1) — ask for a reset mail.
    ///
    /// **Returns `Ok(())` whether or not the address exists**, and this SDK
    /// exposes no way to tell the two apart. That is not an omission to improve
    /// on: a client that surfaced a "no such user" state — even one inferred
    /// from timing — would turn the endpoint into the account enumeration
    /// oracle its uniform response exists to prevent (§25.4).
    pub async fn request_password_reset(
        &self,
        request: &PasswordResetRequest,
    ) -> Result<(), AxiamError> {
        self.ensure_open()?;

        let mut body = ResetBody {
            email: request.email.clone(),
            org_slug: request.org_slug.clone(),
            tenant_id: request.tenant_id,
            tenant_slug: request.tenant_slug.clone(),
        };
        if body.org_slug.is_none()
            && let Some(OrgIdentifier::Slug(slug)) = self.org_identifier()
        {
            body.org_slug = Some(slug.clone());
        }
        if body.tenant_id.is_none() && body.tenant_slug.is_none() {
            match &self.inner.tenant {
                TenantIdentifier::Id(id) => body.tenant_id = Some(*id),
                TenantIdentifier::Slug(slug) => body.tenant_slug = Some(slug.clone()),
            }
        }

        let response = self.account_post(RESET_PATH, &body).await?;
        Self::expect_success(response).await
    }

    /// `GET /api/v1/auth/reset/context` (CONTRACT.md §25.1) — the OPAQUE policy
    /// for the account a reset token belongs to.
    ///
    /// Call this before [`Self::confirm_password_reset`] on any tenant that
    /// might have §23 enabled: the client has to build a registration record,
    /// and building one needs parameters it cannot know before it has a token
    /// to ask with. Sending a plaintext password to a tenant in
    /// `opaque_mode: required` is refused, and refused late (§25.4 rule 1).
    ///
    /// A `404` means unknown, expired **or** already-consumed, deliberately
    /// without distinguishing them; this SDK does not distinguish them either
    /// (§25.4 rule 3).
    pub async fn password_reset_context(
        &self,
        token: &Sensitive<String>,
    ) -> Result<PasswordResetContext, AxiamError> {
        self.ensure_open()?;
        let mut url = self.url(RESET_CONTEXT_PATH);
        url.query_pairs_mut().append_pair("token", token.expose());

        let response = self
            .http()
            .get(url)
            .send()
            .await
            .map_err(|e| AxiamError::Network {
                message: format!("password_reset_context request failed: {e}"),
                source: Some(Box::new(e)),
            })?;

        match response.status().as_u16() {
            200 => response
                .json::<PasswordResetContext>()
                .await
                .map_err(deser_err),
            status => Err(map_error_response(status, response).await),
        }
    }

    /// `POST /api/v1/auth/reset/confirm` (CONTRACT.md §25.1) — set the new
    /// password.
    pub async fn confirm_password_reset(
        &self,
        confirmation: &PasswordResetConfirmation,
    ) -> Result<(), AxiamError> {
        self.ensure_open()?;
        let body = ResetConfirmBody {
            token: confirmation.token.expose().clone(),
            new_password: confirmation.new_password.expose().clone(),
            tenant_id: confirmation.tenant_id,
            opaque: confirmation.opaque.clone(),
        };
        let response = self.account_post(RESET_CONFIRM_PATH, &body).await?;
        Self::expect_success(response).await
    }

    // -----------------------------------------------------------------------
    // Internals
    // -----------------------------------------------------------------------

    async fn account_post<B: Serialize>(
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
                message: format!("request failed: {e}"),
                source: Some(Box::new(e)),
            })
    }

    async fn mfa_enrollment(response: reqwest::Response) -> Result<MfaEnrollment, AxiamError> {
        match response.status().as_u16() {
            200 => {
                let wire: MfaEnrollWire = response.json().await.map_err(deser_err)?;
                Ok(MfaEnrollment {
                    secret_base32: Sensitive::new(wire.secret_base32),
                    totp_uri: Sensitive::new(wire.totp_uri),
                })
            }
            status => Err(map_error_response(status, response).await),
        }
    }

    async fn expect_success(response: reqwest::Response) -> Result<(), AxiamError> {
        match response.status().as_u16() {
            200 | 202 | 204 => Ok(()),
            status => Err(map_error_response(status, response).await),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // §7 rule 3: a request body that carries a credential renders it as
    // `[REDACTED]`. These five types are `Serialize` but hand-write `Debug`
    // precisely so a `tracing` span or a `dbg!` left in a caller's code cannot
    // spill them — a guard nobody exercises is a guard that quietly rots.

    #[test]
    fn totp_code_body_debug_redacts_the_code() {
        let rendered = format!(
            "{:?}",
            TotpCodeBody {
                totp_code: "654321".into()
            }
        );
        assert!(!rendered.contains("654321"), "{rendered}");
        assert!(rendered.contains("[REDACTED]"), "{rendered}");
    }

    #[test]
    fn setup_token_body_debug_redacts_the_token() {
        let rendered = format!(
            "{:?}",
            SetupTokenBody {
                setup_token: "setup-token-abc".into()
            }
        );
        assert!(!rendered.contains("setup-token-abc"), "{rendered}");
        assert!(rendered.contains("[REDACTED]"), "{rendered}");
    }

    #[test]
    fn setup_confirm_body_debug_redacts_both_secrets() {
        let rendered = format!(
            "{:?}",
            SetupConfirmBody {
                setup_token: "setup-token-abc".into(),
                totp_code: "123456".into(),
            }
        );
        assert!(!rendered.contains("setup-token-abc"), "{rendered}");
        assert!(!rendered.contains("123456"), "{rendered}");
        assert!(rendered.contains("[REDACTED]"), "{rendered}");
    }

    #[test]
    fn verify_email_body_debug_redacts_the_token_but_keeps_the_tenant() {
        let tenant_id = Uuid::nil();
        let rendered = format!(
            "{:?}",
            VerifyEmailBody {
                token: "verify-token-xyz".into(),
                tenant_id
            }
        );
        assert!(!rendered.contains("verify-token-xyz"), "{rendered}");
        assert!(rendered.contains("[REDACTED]"), "{rendered}");
        // The tenant is not a secret, and a redaction that hides it makes the
        // diagnostic useless.
        assert!(rendered.contains(&tenant_id.to_string()), "{rendered}");
    }

    #[test]
    fn reset_confirm_body_debug_redacts_the_token_and_the_new_password() {
        let tenant_id = Uuid::nil();
        let rendered = format!(
            "{:?}",
            ResetConfirmBody {
                token: "reset-token-xyz".into(),
                new_password: "hunter2-super-secret".into(),
                tenant_id,
                opaque: None,
            }
        );
        assert!(!rendered.contains("reset-token-xyz"), "{rendered}");
        assert!(!rendered.contains("hunter2-super-secret"), "{rendered}");
        assert!(rendered.contains("[REDACTED]"), "{rendered}");
        assert!(rendered.contains(&tenant_id.to_string()), "{rendered}");
    }

    // §25.4: the OPAQUE envelope rides through untouched. It is an evaluated
    // element and a masked response, not a password — visible in a diagnostic
    // is exactly where it belongs, and hiding it would make the one field an
    // integrator has to debug the one field they cannot see.
    #[test]
    fn reset_confirm_body_debug_keeps_the_opaque_envelope_visible() {
        let rendered = format!(
            "{:?}",
            ResetConfirmBody {
                token: "reset-token-xyz".into(),
                new_password: String::new(),
                tenant_id: Uuid::nil(),
                opaque: Some(serde_json::json!({ "record": "opaque-record-b64" })),
            }
        );
        assert!(rendered.contains("opaque-record-b64"), "{rendered}");
    }
}
