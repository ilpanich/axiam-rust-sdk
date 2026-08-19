//! `login_srp` — the SRP-6a login path (CONTRACT.md §23).
//!
//! A sibling of [`AxiamClient::login`], not a replacement. It establishes the
//! same fact — this principal knows the password — by a route that never puts
//! the password on the wire, and returns the **same** [`LoginResult`], so an
//! application can switch a tenant to SRP without touching its own code.
//!
//! The protocol arithmetic lives in [`crate::srp`] and performs no I/O; this
//! module is the two HTTP calls and the policy around them.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::auth::{LoginResult, absorb_session_cookies};
use crate::client::{AxiamClient, OrgIdentifier, TenantIdentifier};
use crate::error::AxiamError;
use crate::sensitive::Sensitive;
use crate::srp::kdf::{SrpKdf, derive_x};
use crate::srp::{ClientSession, SrpGroup, compute_verifier, verify_server_proof};

const SRP_CHALLENGE_PATH: &str = "/api/v1/auth/srp/challenge";
const SRP_VERIFY_PATH: &str = "/api/v1/auth/srp/verify";

/// The group a client opens an exchange in before the server has named one.
///
/// The challenge response names the group, but `A` has to be computed *before*
/// that response exists — so the first attempt guesses, and the exchange
/// restarts if the server names another. The guess is AXIAM's default, so the
/// restart is the exceptional path, not the normal one.
const OPENING_GROUP: SrpGroup = SrpGroup::Rfc5054_4096;

#[derive(Debug, Serialize)]
struct ChallengeRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    tenant_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    org_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tenant_slug: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    org_slug: Option<String>,
    username_or_email: String,
    client_public: String,
}

#[derive(Debug, Deserialize)]
struct ChallengeResponse {
    srp_session: String,
    identity: String,
    salt: String,
    group: String,
    kdf: String,
    #[serde(default)]
    memory_kib: Option<u32>,
    iterations: u32,
    #[serde(default)]
    parallelism: Option<u32>,
    b_pub: String,
}

#[derive(Debug, Serialize)]
struct VerifyRequest {
    srp_session: String,
    client_proof: String,
}

#[derive(Debug, Deserialize)]
struct VerifySuccessResponse {
    session_id: Uuid,
    expires_in: u64,
    #[serde(default)]
    server_proof: Option<String>,
}

#[derive(Debug, Deserialize)]
struct VerifyMfaRequiredResponse {
    challenge_token: String,
    #[serde(default)]
    available_methods: Vec<String>,
    #[serde(default)]
    server_proof: Option<String>,
}

/// The verifier and its parameters, ready to be sent to any endpoint that sets
/// a password.
///
/// The server cannot compute this — it never sees the plaintext — so it has to
/// arrive with the request or not at all.
#[derive(Debug, Clone, Serialize)]
pub struct SrpEnrollment {
    /// RFC 5054 group name.
    pub group: String,
    /// KDF name.
    pub kdf: String,
    /// Argon2id memory cost in KiB; absent for PBKDF2.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_kib: Option<u32>,
    /// KDF iteration/time cost.
    pub iterations: u32,
    /// Argon2id parallelism; absent for PBKDF2.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parallelism: Option<u32>,
    /// Lowercase-hex 32-byte salt, freshly generated.
    pub salt: String,
    /// Lowercase-hex verifier `v = g^x mod N`.
    pub verifier: String,
}

impl AxiamClient {
    /// `POST /api/v1/auth/srp/challenge` + `/verify` — SRP-6a login
    /// (CONTRACT.md §23).
    ///
    /// Returns the same [`LoginResult`] as [`AxiamClient::login`], including
    /// the MFA-challenge case, so a caller needs one result handler for both.
    ///
    /// # What this does that `login` does not
    ///
    /// The password never leaves this process. What crosses the wire is `A`
    /// and a proof, neither of which is useful without the account's verifier
    /// — so a TLS-terminating proxy, an accidentally verbose request log or a
    /// heap dump on the server cannot capture a plaintext password, because
    /// the server never has one.
    ///
    /// It does **not** protect against a compromised AXIAM server.
    ///
    /// # Errors
    ///
    /// * `NetworkError` when the tenant has SRP disabled (`404`), or when this
    ///   SDK cannot perform the group or KDF the server named (§23.3 rule 4).
    ///   These are client-side/config faults, deliberately **not**
    ///   `AuthError`: reporting them as a credential failure would send a user
    ///   off to reset a password that works.
    /// * `AuthError` for a wrong password, and for a server whose `M2` does
    ///   not verify — in the latter case the session is discarded rather than
    ///   returned, because an endpoint that cannot prove it holds the verifier
    ///   is not the server it claims to be.
    ///
    /// # Cost
    ///
    /// This runs the tenant's KDF, which at AXIAM's default Argon2id
    /// parameters allocates 19 MiB and takes tens of milliseconds. On an async
    /// runtime, treat a call to this as blocking work.
    pub async fn login_srp(
        &self,
        username_or_email: &str,
        password: &str,
    ) -> Result<LoginResult, AxiamError> {
        // §18.1 rule 4: use-after-close is an error, not a reconnect.
        self.ensure_open()?;
        // §17.1 rule 9: entries are keyed by subject, so any credential change
        // must drop them, or a re-authentication as a different principal
        // inherits the previous one's decisions.
        self.decision_memo().clear();

        let (mut session, mut challenge) = self
            .request_challenge(username_or_email, OPENING_GROUP)
            .await?;

        // The server named a group other than the one `A` was computed in, so
        // the exchange has to restart. Rare — the opening guess is AXIAM's own
        // default — but a tenant on a narrower group must work rather than
        // fail.
        let group = SrpGroup::parse(&challenge.group)?;
        if group != OPENING_GROUP {
            let (fresh_session, fresh_challenge) =
                self.request_challenge(username_or_email, group).await?;
            session = fresh_session;
            challenge = fresh_challenge;
        }

        let kdf = SrpKdf::from_wire(
            &challenge.kdf,
            challenge.iterations,
            challenge.memory_kib,
            challenge.parallelism,
        )?;
        let salt = hex::decode(&challenge.salt)
            .map_err(|_| AxiamError::auth("SRP: server salt is not valid hex"))?;

        // `challenge.identity`, never `username_or_email` (§23.3 rule 2): a
        // user may sign in with either their username or their email, and only
        // one of the two is bound into `x`.
        let x = derive_x(&challenge.identity, password, &salt, &kdf)?;
        let proofs = session.finish(&challenge.identity, &challenge.salt, &challenge.b_pub, &x)?;

        let response = self
            .http()
            .post(self.url(SRP_VERIFY_PATH))
            .json(&VerifyRequest {
                srp_session: challenge.srp_session,
                client_proof: proofs.client_proof,
            })
            .send()
            .await
            .map_err(|e| AxiamError::Network {
                message: format!("SRP verify request failed: {e}"),
                source: Some(Box::new(e)),
            })?;

        match response.status().as_u16() {
            200 => {
                let wire: VerifySuccessResponse =
                    response.json().await.map_err(super::auth::deser_err)?;
                self.check_server_proof(
                    &proofs.expected_server_proof,
                    wire.server_proof.as_deref(),
                )?;
                absorb_session_cookies(self).await?;
                Ok(LoginResult::success(wire.session_id, wire.expires_in))
            }
            202 => {
                let wire: VerifyMfaRequiredResponse =
                    response.json().await.map_err(super::auth::deser_err)?;
                // Checked BEFORE the challenge token is stored: a rogue server
                // that cannot prove itself must not get the chance to collect
                // an MFA code either.
                self.check_server_proof(
                    &proofs.expected_server_proof,
                    wire.server_proof.as_deref(),
                )?;
                self.set_pending_mfa_challenge(Sensitive::new(wire.challenge_token.clone()));
                Ok(LoginResult::mfa_required(
                    wire.challenge_token,
                    wire.available_methods,
                ))
            }
            status => Err(super::auth::map_error_response(status, response).await),
        }
    }

    /// Compute a verifier for `password`, to send with any request that sets a
    /// password (user creation, change-password, reset completion, bootstrap).
    ///
    /// `identity` MUST be the account's **username** — the canonical identity
    /// the challenge endpoint will later hand back. Passing an email produces a
    /// verifier no login can ever satisfy.
    ///
    /// The salt is 32 fresh bytes from the platform CSPRNG (§23.3 rule 11).
    pub fn srp_enrollment(
        &self,
        identity: &str,
        password: &str,
        group: SrpGroup,
        kdf: &SrpKdf,
    ) -> Result<SrpEnrollment, AxiamError> {
        let mut salt = [0u8; 32];
        getrandom::fill(&mut salt).map_err(|e| {
            AxiamError::network(format!("SRP: no source of randomness available: {e}"))
        })?;

        let x = derive_x(identity, password, &salt, kdf)?;
        let verifier = compute_verifier(group, &x);

        let (memory_kib, iterations, parallelism) = match kdf {
            SrpKdf::Argon2id {
                memory_kib,
                iterations,
                parallelism,
            } => (Some(*memory_kib), *iterations, Some(*parallelism)),
            SrpKdf::Pbkdf2Sha256 { iterations } => (None, *iterations, None),
        };

        Ok(SrpEnrollment {
            group: group.as_str().to_string(),
            kdf: kdf.name().to_string(),
            memory_kib,
            iterations,
            parallelism,
            salt: hex::encode(salt),
            verifier,
        })
    }

    /// Whether this SDK build can perform SRP at all.
    ///
    /// Always `true` for the Rust SDK, which has both KDFs and all three
    /// groups compiled in. It exists because §23.1 puts it in the locked
    /// method vocabulary for every SDK, and in PHP — which needs `ext-gmp` or
    /// `ext-bcmath` for big-integer arithmetic and is guaranteed neither — it
    /// genuinely answers `false`.
    pub fn srp_available(&self) -> bool {
        true
    }

    async fn request_challenge(
        &self,
        username_or_email: &str,
        group: SrpGroup,
    ) -> Result<(ClientSession, ChallengeResponse), AxiamError> {
        let session = ClientSession::begin(group)?;

        let (tenant_id, tenant_slug) = match &self.inner.tenant {
            TenantIdentifier::Id(id) => (Some(*id), None),
            TenantIdentifier::Slug(slug) => (None, Some(slug.clone())),
        };
        let (org_id, org_slug) = match self.org_identifier() {
            Some(OrgIdentifier::Id(id)) => (Some(*id), None),
            Some(OrgIdentifier::Slug(slug)) => (None, Some(slug.clone())),
            None => (None, None),
        };

        let response = self
            .http()
            .post(self.url(SRP_CHALLENGE_PATH))
            .json(&ChallengeRequest {
                tenant_id,
                org_id,
                tenant_slug,
                org_slug,
                username_or_email: username_or_email.to_string(),
                client_public: session.client_public.clone(),
            })
            .send()
            .await
            .map_err(|e| AxiamError::Network {
                message: format!("SRP challenge request failed: {e}"),
                source: Some(Box::new(e)),
            })?;

        match response.status().as_u16() {
            200 => {
                let wire: ChallengeResponse =
                    response.json().await.map_err(super::auth::deser_err)?;
                Ok((session, wire))
            }
            // A property of the tenant, not of the user. Reported as a
            // configuration fault rather than an auth failure so a caller can
            // fall back to `login()` without mistaking it for bad credentials.
            404 => Err(AxiamError::network(
                "this tenant does not offer Secure Remote Password (srp_mode is disabled); \
                 use login() instead",
            )),
            status => Err(super::auth::map_error_response(status, response).await),
        }
    }

    /// Verify the server's `M2` (§23.3 rule 6).
    ///
    /// A mismatch means the endpoint that answered does not hold the account's
    /// verifier, so it is not the server it claims to be. This is a hard
    /// failure: without it the client has proved itself to the server but has
    /// not proved the server to itself, which is half the protocol.
    fn check_server_proof(&self, expected: &str, actual: Option<&str>) -> Result<(), AxiamError> {
        let Some(actual) = actual else {
            return Err(AxiamError::auth(
                "SRP: the server did not return a proof; it cannot be authenticated",
            ));
        };
        if !verify_server_proof(expected, actual) {
            return Err(AxiamError::auth(
                "SRP: the server failed to prove it holds this account's verifier",
            ));
        }
        Ok(())
    }
}
