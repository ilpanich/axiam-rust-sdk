//! `login_opaque` — the OPAQUE (RFC 9807) login path (CONTRACT.md §23).
//!
//! A sibling of [`AxiamClient::login`], not a replacement. It establishes the
//! same fact — this principal knows the password — by a route that never puts
//! the password on the wire, and returns the **same** [`LoginResult`], so an
//! application can switch a tenant to OPAQUE without touching its own code.
//!
//! # Where the protocol is
//!
//! Not here. CONTRACT §23.1 forbids an SDK from implementing OPAQUE, and this
//! SDK does not: [`axiam_opaque`] is the same crate the AXIAM server links, and
//! the same one the other ten SDKs bind through a C ABI or WebAssembly.
//!
//! That is a change from the SRP implementation this replaces, which carried
//! three modules and ~870 lines of modular arithmetic, group constants and KDF
//! plumbing — because SRP is arithmetic every language can express, so every
//! SDK wrote its own. OPAQUE needs an oblivious PRF, `hash_to_curve`,
//! `expand_message_xmd`, an envelope construction and a three-message AKE. This
//! module is the HTTP calls and the policy around them, and nothing else.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use axiam_opaque::{AxiamKsf, ClientLoginState, ClientRegistrationState};

use super::auth::{LoginResult, absorb_session_cookies};
use crate::client::{AxiamClient, OrgIdentifier, TenantIdentifier};
use crate::error::AxiamError;
use crate::sensitive::Sensitive;

const REGISTER_START_PATH: &str = "/api/v1/auth/opaque/register/start";
const LOGIN_START_PATH: &str = "/api/v1/auth/opaque/login/start";
const LOGIN_FINISH_PATH: &str = "/api/v1/auth/opaque/login/finish";

/// The key-stretching fields a `register/start` or `login/start` response
/// carries.
///
/// Flat and optional, matching the wire format: the fields that do not apply to
/// the named function are **absent, not zero**. Reading an absent field as `0`
/// would stretch with the wrong cost and fail against a record that is
/// perfectly good (§23.4 rule 5).
#[derive(Debug, Deserialize)]
struct KsfFields {
    ksf: String,
    #[serde(default)]
    memory_kib: Option<u32>,
    #[serde(default)]
    iterations: Option<u32>,
    #[serde(default)]
    parallelism: Option<u32>,
    #[serde(default)]
    log_n: Option<u8>,
    #[serde(default)]
    r: Option<u32>,
    #[serde(default)]
    p: Option<u32>,
}

impl KsfFields {
    /// Build the stretching function the server named.
    ///
    /// Never substituted and never defaulted: substituting produces a
    /// well-formed randomized password that no AXIAM server agrees with,
    /// reported to the user as a wrong password (§23.4 rule 3). A refusal is
    /// `NetworkError` — a client-side fault — rather than `AuthError`, which
    /// would send a user off to reset a password that works.
    fn build(&self) -> Result<AxiamKsf, AxiamError> {
        let missing = |what: &str| {
            AxiamError::network(format!(
                "OPAQUE: the server named ksf `{}` without `{what}`",
                self.ksf
            ))
        };
        let ksf = match self.ksf.as_str() {
            "argon2id" => AxiamKsf::argon2id(
                self.memory_kib.ok_or_else(|| missing("memory_kib"))?,
                self.iterations.ok_or_else(|| missing("iterations"))?,
                self.parallelism.ok_or_else(|| missing("parallelism"))?,
            ),
            "scrypt" => AxiamKsf::scrypt(
                self.log_n.ok_or_else(|| missing("log_n"))?,
                self.r.ok_or_else(|| missing("r"))?,
                self.p.ok_or_else(|| missing("p"))?,
            ),
            other => {
                return Err(AxiamError::network(format!(
                    "OPAQUE: this SDK cannot perform the key-stretching function \
                     the server named (`{other}`)"
                )));
            }
        };
        ksf.map_err(|e| AxiamError::network(format!("OPAQUE: {e}")))
    }
}

#[derive(Debug, Serialize)]
struct WorkspaceBody {
    #[serde(skip_serializing_if = "Option::is_none")]
    tenant_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    org_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tenant_slug: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    org_slug: Option<String>,
}

#[derive(Debug, Serialize)]
struct RegisterStartRequest {
    #[serde(flatten)]
    workspace: WorkspaceBody,
    registration_request: String,
}

#[derive(Debug, Deserialize)]
struct RegisterStartResponse {
    opaque_session: String,
    registration_response: String,
    #[serde(flatten)]
    ksf: KsfFields,
}

#[derive(Debug, Serialize)]
struct LoginStartRequest {
    #[serde(flatten)]
    workspace: WorkspaceBody,
    username_or_email: String,
    ke1: String,
}

#[derive(Debug, Deserialize)]
struct LoginStartResponse {
    opaque_session: String,
    ke2: String,
    #[serde(flatten)]
    ksf: KsfFields,
}

#[derive(Debug, Serialize)]
struct LoginFinishRequest {
    opaque_session: String,
    ke3: String,
}

#[derive(Debug, Deserialize)]
struct FinishSuccessResponse {
    session_id: Uuid,
    expires_in: u64,
}

#[derive(Debug, Deserialize)]
struct FinishMfaRequiredResponse {
    challenge_token: String,
    #[serde(default)]
    available_methods: Vec<String>,
}

/// A completed enrolment, to send with any request that sets a password.
///
/// Two fields, where the SRP equivalent had seven. The server chose the
/// credential identifier, the ciphersuite and the costs, and sealed them into
/// `opaque_session` — so a client cannot name any of them, which is also why it
/// cannot enrol a record against somebody else's account.
#[derive(Debug, Clone, Serialize)]
pub struct OpaqueEnrollment {
    /// The `opaque_session` from `register/start`, echoed verbatim.
    pub opaque_session: String,
    /// Lowercase-hex serialized RFC 9807 `RegistrationRecord`.
    pub registration_record: String,
}

impl AxiamClient {
    /// `POST /api/v1/auth/opaque/login/start` + `/finish` — OPAQUE login
    /// (CONTRACT.md §23).
    ///
    /// Returns the same [`LoginResult`] as [`AxiamClient::login`], including
    /// the MFA-challenge case, so a caller needs one result handler for both.
    ///
    /// # What this does that `login` does not
    ///
    /// The password never leaves this process. What crosses the wire is a
    /// blinded group element and a MAC, neither of which is useful without the
    /// account's record *and* the tenant's OPRF seed — so a TLS-terminating
    /// proxy, an accidentally verbose request log or a heap dump on the server
    /// cannot capture a plaintext password, because the server never has one.
    ///
    /// It also means a stolen record database is not offline-crackable on its
    /// own, which is the property SRP could not offer.
    ///
    /// It does **not** protect against a compromised AXIAM server.
    ///
    /// # What a caller no longer has to do
    ///
    /// Under SRP this method returned only after verifying the server's `M2`,
    /// and §23.3 rule 6 had to mandate that in capitals because skipping it
    /// kept only the half of the protocol that authenticates the client. RFC
    /// 9807's AKE authenticates the server during the handshake — opening
    /// `KE2` *is* the proof that the server holds the record — so there is no
    /// separate check, and no way for a caller to omit one.
    ///
    /// # Errors
    ///
    /// * `NetworkError` when the tenant has OPAQUE disabled (`404`), or when
    ///   this SDK cannot perform the KSF the server named (§23.4 rule 3).
    ///   These are client-side or configuration faults, deliberately **not**
    ///   `AuthError`: reporting them as a credential failure would send a user
    ///   off to reset a password that works.
    /// * `AuthError` for a wrong password, an account that does not exist, and
    ///   a server that does not hold the record — indistinguishable by design.
    ///   Nothing is sent to `login/finish` in that case (§23.4 rule 7).
    pub async fn login_opaque(
        &self,
        username_or_email: &str,
        password: &str,
    ) -> Result<LoginResult, AxiamError> {
        let (state, ke1) = ClientLoginState::start(password)
            .map_err(|e| AxiamError::network(format!("OPAQUE: {e}")))?;

        let response = self
            .http()
            .post(self.url(LOGIN_START_PATH))
            .json(&LoginStartRequest {
                workspace: self.workspace_body(),
                username_or_email: username_or_email.to_string(),
                ke1,
            })
            .send()
            .await
            .map_err(|e| AxiamError::Network {
                message: format!("OPAQUE login/start request failed: {e}"),
                source: Some(Box::new(e)),
            })?;

        let status = response.status().as_u16();
        if status == 404 {
            // A property of the tenant, not of the user. Reported as a
            // configuration fault rather than an auth failure so a caller can
            // fall back to `login()` without mistaking it for bad credentials.
            return Err(AxiamError::network(
                "this tenant does not offer OPAQUE (opaque_mode is disabled); \
                 use login() instead",
            ));
        }
        if status != 200 {
            return Err(super::auth::map_error_response(status, response).await);
        }
        let started: LoginStartResponse = response.json().await.map_err(super::auth::deser_err)?;
        let ksf = started.ksf.build()?;

        // The whole of the client's authentication check. A failure here covers
        // both halves of the mutual authentication, and nothing further may be
        // sent.
        let finished = state
            .finish(password, &started.ke2, &ksf)
            .map_err(|_| AxiamError::auth("invalid credentials"))?;

        let response = self
            .http()
            .post(self.url(LOGIN_FINISH_PATH))
            .json(&LoginFinishRequest {
                opaque_session: started.opaque_session,
                ke3: finished.ke3,
            })
            .send()
            .await
            .map_err(|e| AxiamError::Network {
                message: format!("OPAQUE login/finish request failed: {e}"),
                source: Some(Box::new(e)),
            })?;

        match response.status().as_u16() {
            200 => {
                let wire: FinishSuccessResponse =
                    response.json().await.map_err(super::auth::deser_err)?;
                absorb_session_cookies(self).await?;
                Ok(LoginResult::success(wire.session_id, wire.expires_in))
            }
            202 => {
                let wire: FinishMfaRequiredResponse =
                    response.json().await.map_err(super::auth::deser_err)?;
                self.set_pending_mfa_challenge(Sensitive::new(wire.challenge_token.clone()));
                Ok(LoginResult::mfa_required(
                    wire.challenge_token,
                    wire.available_methods,
                ))
            }
            status => Err(super::auth::map_error_response(status, response).await),
        }
    }

    /// Build a registration record for `password`, to send with any request
    /// that sets one (user creation, change-password, reset completion).
    ///
    /// This performs a `register/start` round trip, which the SRP equivalent
    /// did not need: OPAQUE's envelope is sealed under the server's oblivious
    /// PRF, so there is no offline computation that produces a valid record.
    ///
    /// Note the absence of an `identity` argument. The SRP version required
    /// one — the account's canonical username — and passing an email produced
    /// a verifier no login could ever satisfy. A record binds to a credential
    /// identifier the server chooses, so there is nothing here to get wrong,
    /// and a later rename cannot invalidate it.
    ///
    /// # Errors
    ///
    /// `NetworkError` when the tenant has OPAQUE disabled or the SDK cannot
    /// perform the KSF the server named.
    pub async fn opaque_enrollment(&self, password: &str) -> Result<OpaqueEnrollment, AxiamError> {
        let (state, request) = ClientRegistrationState::start(password)
            .map_err(|e| AxiamError::network(format!("OPAQUE: {e}")))?;

        let response = self
            .http()
            .post(self.url(REGISTER_START_PATH))
            .json(&RegisterStartRequest {
                workspace: self.workspace_body(),
                registration_request: request,
            })
            .send()
            .await
            .map_err(|e| AxiamError::Network {
                message: format!("OPAQUE register/start request failed: {e}"),
                source: Some(Box::new(e)),
            })?;

        let status = response.status().as_u16();
        if status == 404 {
            // A property of the tenant, not of the user. Reported as a
            // configuration fault rather than an auth failure so a caller can
            // fall back to `login()` without mistaking it for bad credentials.
            return Err(AxiamError::network(
                "this tenant does not offer OPAQUE (opaque_mode is disabled); \
                 use login() instead",
            ));
        }
        if status != 200 {
            return Err(super::auth::map_error_response(status, response).await);
        }
        let started: RegisterStartResponse =
            response.json().await.map_err(super::auth::deser_err)?;
        let ksf = started.ksf.build()?;

        let outcome = state
            .finish(password, &started.registration_response, &ksf)
            .map_err(|e| AxiamError::network(format!("OPAQUE: {e}")))?;

        Ok(OpaqueEnrollment {
            opaque_session: started.opaque_session,
            registration_record: outcome.record,
        })
    }

    /// Whether this SDK build can perform OPAQUE at all.
    ///
    /// Always `true` for the Rust SDK, which links the implementation directly.
    /// It exists because §23.2 puts it in the locked method vocabulary for
    /// every SDK, and in the SDKs that load a native library or a WebAssembly
    /// module it genuinely answers `false` when that artifact is absent.
    pub fn opaque_available(&self) -> bool {
        true
    }

    fn workspace_body(&self) -> WorkspaceBody {
        let (tenant_id, tenant_slug) = match &self.inner.tenant {
            TenantIdentifier::Id(id) => (Some(*id), None),
            TenantIdentifier::Slug(slug) => (None, Some(slug.clone())),
        };
        let (org_id, org_slug) = match self.org_identifier() {
            Some(OrgIdentifier::Id(id)) => (Some(*id), None),
            Some(OrgIdentifier::Slug(slug)) => (None, Some(slug.clone())),
            None => (None, None),
        };
        WorkspaceBody {
            tenant_id,
            org_id,
            tenant_slug,
            org_slug,
        }
    }
}
