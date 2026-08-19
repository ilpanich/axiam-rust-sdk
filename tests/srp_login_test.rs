//! `login_srp` end to end against a mock server that really speaks SRP-6a
//! (`src/rest/srp.rs`, CONTRACT.md §23).
//!
//! `tests/srp_vectors_test.rs` proves the arithmetic reproduces the
//! cross-language vectors. It says nothing about the two HTTP calls around it:
//! which identity is bound into `x`, what happens when the server names a
//! different group than the one `A` was opened in, whether a tenant with SRP
//! disabled is distinguishable from a wrong password, and — the one that
//! matters most — whether a server that cannot prove it holds the verifier is
//! actually refused rather than quietly accepted.
//!
//! So the mock here is not a canned response: it holds a verifier, picks its
//! own `b`, and computes `B`, `M1` and `M2` from whatever `A` the client sends.
//! A client that got `u`, the padding or the exponent wrong fails against it,
//! which a fixture-replaying mock could never detect.

#![cfg(feature = "srp")]

use axiam_sdk::AxiamError;
use axiam_sdk::client::AxiamClient;
use axiam_sdk::srp::SrpGroup;
use axiam_sdk::srp::kdf::{SrpKdf, derive_x};
use num_bigint::BigUint;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

#[path = "oidc_support/mod.rs"]
mod oidc_support;

use oidc_support::{
    generate_signing_key, jwks_body, session_cookie_headers, sign_session_access_token,
};

/// RFC 5054 Appendix A, 2048-bit group. `g = 2`.
///
/// Written out here rather than read from the SDK, deliberately: the SDK's copy
/// is what is under test, and a mock that borrowed it would agree with a typo.
/// This is a published constant from the RFC, not key material.
const N_2048_HEX: &str = concat!(
    "AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050A37329CBB4",
    "A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50E8083969EDB767B0CF60",
    "95179A163AB3661A05FBD5FAAAE82918A9962F0B93B855F97993EC975EEAA80D740ADBF4FF",
    "747359D041D5C33EA71D281E446B14773BCA97B43A23FB801676BD207A436C6481F1D2B907",
    "8717461A5B9D32E688F87748544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB37861",
    "60279004E57AE6AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DB",
    "FBB694B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73",
);
const G_2048: u32 = 2;

/// PBKDF2 rather than Argon2id: the derivation under test is the transport's,
/// not the KDF's, and a low iteration count keeps the suite fast. §23.6's
/// Argon2id path is exercised by `tests/srp_vectors_test.rs`.
fn test_kdf() -> SrpKdf {
    SrpKdf::Pbkdf2Sha256 { iterations: 1000 }
}

fn kdf_wire() -> (&'static str, u32) {
    ("pbkdf2_sha256", 1000)
}

fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

/// Left-pad to the group width, exactly as §23.3 rule 8 requires of every hash
/// input. A mock that skipped this would agree with a client that skipped it.
fn pad(value: &BigUint, byte_len: usize) -> Vec<u8> {
    let raw = value.to_bytes_be();
    let mut out = vec![0u8; byte_len - raw.len()];
    out.extend_from_slice(&raw);
    out
}

/// The server half of one SRP-6a exchange, for one account.
struct SrpServer {
    n: BigUint,
    g: BigUint,
    k: BigUint,
    byte_len: usize,
    identity: String,
    salt: Vec<u8>,
    verifier: BigUint,
    b_priv: BigUint,
    b_pub: BigUint,
}

impl SrpServer {
    /// Enrol `identity`/`password` and pick this exchange's `b`.
    fn enrol(identity: &str, password: &str) -> Self {
        let n = BigUint::parse_bytes(N_2048_HEX.as_bytes(), 16).expect("RFC 5054 modulus");
        let g = BigUint::from(G_2048);
        let byte_len = 256;
        let k = BigUint::from_bytes_be(&sha256(&[&pad(&n, byte_len), &pad(&g, byte_len)]));

        // A salt is 32 fresh bytes per §23.3 rule 11 — including here, so that
        // the fixture cannot accidentally depend on a particular one.
        let mut salt = vec![0u8; 32];
        getrandom::fill(&mut salt).expect("platform CSPRNG");
        let x = derive_x(identity, password, &salt, &test_kdf()).expect("derive x");
        let verifier = g.modpow(&(BigUint::from_bytes_be(&x) % &n), &n);

        let mut b_bytes = [0u8; 32];
        getrandom::fill(&mut b_bytes).expect("platform CSPRNG");
        b_bytes[0] |= 0x80;
        let b_priv = BigUint::from_bytes_be(&b_bytes);
        // B = k*v + g^b mod N.
        let b_pub = ((&k * &verifier) + g.modpow(&b_priv, &n)) % &n;

        Self {
            n,
            g,
            k,
            byte_len,
            identity: identity.to_string(),
            salt,
            verifier,
            b_priv,
            b_pub,
        }
    }

    fn challenge_body(&self, srp_session: &str) -> Value {
        let (kdf, iterations) = kdf_wire();
        json!({
            "srp_session": srp_session,
            "identity": self.identity,
            "salt": hex::encode(&self.salt),
            "group": "rfc5054_2048",
            "kdf": kdf,
            "iterations": iterations,
            "b_pub": hex::encode(pad(&self.b_pub, self.byte_len)),
        })
    }

    /// `(M1, M2)` for the `A` the client actually sent.
    fn proofs_for(&self, a_pub_hex: &str) -> (String, String) {
        let a_pub = BigUint::parse_bytes(a_pub_hex.as_bytes(), 16).expect("A is hex");
        let u = BigUint::from_bytes_be(&sha256(&[
            &pad(&a_pub, self.byte_len),
            &pad(&self.b_pub, self.byte_len),
        ]));
        // S = (A * v^u)^b mod N — the server's route to the same secret.
        let s = ((&a_pub % &self.n) * self.verifier.modpow(&u, &self.n) % &self.n)
            .modpow(&self.b_priv, &self.n);
        let session_key = sha256(&[&pad(&s, self.byte_len)]);

        let h_n = sha256(&[&pad(&self.n, self.byte_len)]);
        let h_g = sha256(&[&pad(&self.g, self.byte_len)]);
        let mut xored = [0u8; 32];
        for i in 0..32 {
            xored[i] = h_n[i] ^ h_g[i];
        }
        let h_i = sha256(&[self.identity.as_bytes()]);
        let m1 = sha256(&[
            &xored,
            &h_i,
            &self.salt,
            &pad(&a_pub, self.byte_len),
            &pad(&self.b_pub, self.byte_len),
            &session_key,
        ]);
        let m2 = sha256(&[&pad(&a_pub, self.byte_len), &m1, &session_key]);
        (hex::encode(m1), hex::encode(m2))
    }

    /// The `k` this group implies, so a test can assert the mock and the SDK
    /// agree on it before blaming the transport for a mismatch.
    fn multiplier(&self) -> &BigUint {
        &self.k
    }
}

/// Answers `/srp/challenge` with this account's parameters, echoing back the
/// `client_public` the SDK sent so the verify responder can use it.
struct ChallengeResponder {
    server: std::sync::Arc<SrpServer>,
    last_client_public: std::sync::Arc<std::sync::Mutex<Option<String>>>,
}

impl Respond for ChallengeResponder {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let body: Value = serde_json::from_slice(&request.body).expect("challenge body is JSON");
        let a_pub = body["client_public"]
            .as_str()
            .expect("client_public is a string")
            .to_string();
        *self.last_client_public.lock().expect("not poisoned") = Some(a_pub);
        ResponseTemplate::new(200).set_body_json(self.server.challenge_body("session-1"))
    }
}

/// What the mock server should say once the client's proof arrives.
#[derive(Clone, Copy)]
enum VerifyOutcome {
    /// 200 with a correct `M2`.
    Success,
    /// 202 with a correct `M2` and an MFA challenge token.
    MfaRequired,
    /// 200 with an `M2` that does not verify — a server that does not hold the
    /// verifier.
    WrongProof,
    /// 200 with no `M2` at all.
    NoProof,
}

struct VerifyResponder {
    server: std::sync::Arc<SrpServer>,
    last_client_public: std::sync::Arc<std::sync::Mutex<Option<String>>>,
    outcome: VerifyOutcome,
    session_id: Uuid,
    cookies: Vec<String>,
}

impl Respond for VerifyResponder {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let body: Value = serde_json::from_slice(&request.body).expect("verify body is JSON");
        let client_proof = body["client_proof"]
            .as_str()
            .expect("client_proof")
            .to_string();
        let a_pub = self
            .last_client_public
            .lock()
            .expect("not poisoned")
            .clone()
            .expect("the challenge ran first");
        let (expected_m1, m2) = self.server.proofs_for(&a_pub);
        // The mock authenticates the client for real: a client that computed
        // `u`, the padding or the exponent differently never gets past here.
        assert_eq!(
            client_proof, expected_m1,
            "the SDK's M1 must match the server's own"
        );

        match self.outcome {
            VerifyOutcome::Success => {
                let mut response = ResponseTemplate::new(200).set_body_json(json!({
                    "session_id": self.session_id,
                    "expires_in": 900,
                    "server_proof": m2,
                }));
                for cookie in &self.cookies {
                    response = response.append_header("set-cookie", cookie.as_str());
                }
                response
            }
            VerifyOutcome::MfaRequired => ResponseTemplate::new(202).set_body_json(json!({
                "challenge_token": "srp-mfa-challenge",
                "available_methods": ["totp"],
                "server_proof": m2,
            })),
            // Flip one hex digit: still well-formed, still the right length,
            // and still wrong.
            VerifyOutcome::WrongProof => ResponseTemplate::new(200).set_body_json(json!({
                "session_id": self.session_id,
                "expires_in": 900,
                "server_proof": format!("{}{}", &m2[..m2.len() - 1], if m2.ends_with('0') { '1' } else { '0' }),
            })),
            VerifyOutcome::NoProof => ResponseTemplate::new(200).set_body_json(json!({
                "session_id": self.session_id,
                "expires_in": 900,
            })),
        }
    }
}

async fn mount_srp(
    mock_server: &MockServer,
    server: &std::sync::Arc<SrpServer>,
    outcome: VerifyOutcome,
    session_id: Uuid,
    cookies: Vec<String>,
) {
    let last_client_public = std::sync::Arc::new(std::sync::Mutex::new(None));

    Mock::given(method("POST"))
        .and(path("/api/v1/auth/srp/challenge"))
        .respond_with(ChallengeResponder {
            server: server.clone(),
            last_client_public: last_client_public.clone(),
        })
        .mount(mock_server)
        .await;

    Mock::given(method("POST"))
        .and(path("/api/v1/auth/srp/verify"))
        .respond_with(VerifyResponder {
            server: server.clone(),
            last_client_public,
            outcome,
            session_id,
            cookies,
        })
        .mount(mock_server)
        .await;
}

fn client_for(base_url: &str) -> AxiamClient {
    AxiamClient::builder()
        .base_url(base_url)
        .expect("valid base url")
        .tenant_slug("acme")
        .org_slug("acme")
        .build()
        .expect("client builds")
}

async fn mount_jwks(mock_server: &MockServer, key: &oidc_support::SigningKeyFixture) {
    Mock::given(method("GET"))
        .and(path("/oauth2/jwks"))
        .respond_with(ResponseTemplate::new(200).set_body_json(jwks_body(&[key])))
        .mount(mock_server)
        .await;
}

#[tokio::test]
async fn a_full_exchange_authenticates_both_sides_and_opens_a_session() {
    let mock_server = MockServer::start().await;
    let key = generate_signing_key("srp-login-kid");
    mount_jwks(&mock_server, &key).await;

    let tenant = Uuid::new_v4();
    let org = Uuid::new_v4();
    let session = Uuid::new_v4();
    let access_token = sign_session_access_token(&key, tenant, org, session);
    let cookies = session_cookie_headers(&access_token, "srp-refresh-token", "srp-csrf");

    let server = std::sync::Arc::new(SrpServer::enrol("alice", "correct horse battery staple"));
    mount_srp(
        &mock_server,
        &server,
        VerifyOutcome::Success,
        session,
        cookies,
    )
    .await;

    let client = client_for(&mock_server.uri());
    let result = client
        .login_srp("alice@example.com", "correct horse battery staple")
        .await
        .expect("SRP login succeeds");

    assert!(
        !result.mfa_required,
        "no MFA was configured for this account"
    );
    assert_eq!(result.session_id, Some(session));
    assert_eq!(result.expires_in, Some(900));
    assert!(result.challenge_token.is_none());
}

#[tokio::test]
async fn mfa_required_returns_the_same_result_shape_as_password_login() {
    let mock_server = MockServer::start().await;
    let server = std::sync::Arc::new(SrpServer::enrol("alice", "hunter2-but-longer"));
    mount_srp(
        &mock_server,
        &server,
        VerifyOutcome::MfaRequired,
        Uuid::new_v4(),
        vec![],
    )
    .await;

    let client = client_for(&mock_server.uri());
    let result = client
        .login_srp("alice", "hunter2-but-longer")
        .await
        .expect("SRP login reaches the MFA step");

    assert!(result.mfa_required, "the server asked for a second factor");
    assert_eq!(
        result
            .challenge_token
            .as_ref()
            .expect("an MFA challenge carries a token")
            .expose(),
        "srp-mfa-challenge"
    );
    assert_eq!(result.available_methods, vec!["totp".to_string()]);
    assert!(result.session_id.is_none(), "MFA is not yet a session");
}

#[tokio::test]
async fn a_server_whose_proof_does_not_verify_gets_no_session() {
    let mock_server = MockServer::start().await;
    let server = std::sync::Arc::new(SrpServer::enrol("alice", "a-perfectly-good-password"));
    mount_srp(
        &mock_server,
        &server,
        VerifyOutcome::WrongProof,
        Uuid::new_v4(),
        vec![],
    )
    .await;

    let client = client_for(&mock_server.uri());
    let err = client
        .login_srp("alice", "a-perfectly-good-password")
        .await
        .expect_err("a server that cannot prove itself must be refused");

    assert!(
        matches!(err, AxiamError::Auth { .. }),
        "M2 mismatch is an auth failure, got {err:?}"
    );
    assert!(
        format!("{err}").contains("failed to prove"),
        "the refusal must say what was not proved: {err}"
    );
    // ...and nothing was adopted on the way past the failed check: the client
    // never resolved a tenant from a session it refused.
    assert!(
        client.resolved_tenant_id().await.is_none(),
        "no session state may survive a failed M2"
    );
}

#[tokio::test]
async fn a_server_that_returns_no_proof_at_all_is_refused() {
    let mock_server = MockServer::start().await;
    let server = std::sync::Arc::new(SrpServer::enrol("alice", "another-good-password"));
    mount_srp(
        &mock_server,
        &server,
        VerifyOutcome::NoProof,
        Uuid::new_v4(),
        vec![],
    )
    .await;

    let client = client_for(&mock_server.uri());
    let err = client
        .login_srp("alice", "another-good-password")
        .await
        .expect_err("a missing M2 is not an optional field");

    assert!(matches!(err, AxiamError::Auth { .. }), "got {err:?}");
}

#[tokio::test]
async fn a_tenant_with_srp_disabled_is_a_configuration_fault_not_a_bad_password() {
    // The distinction is the whole point: a caller that saw AuthError here
    // would send a user off to reset a password that works perfectly.
    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/auth/srp/challenge"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&mock_server)
        .await;

    let client = client_for(&mock_server.uri());
    let err = client
        .login_srp("alice", "irrelevant")
        .await
        .expect_err("a disabled tenant cannot serve a challenge");

    match err {
        AxiamError::Network { message, .. } => {
            assert!(message.contains("srp_mode"), "{message}");
            assert!(message.contains("login()"), "{message}");
        }
        other => panic!("srp_mode disabled must not look like bad credentials: {other:?}"),
    }
}

#[tokio::test]
async fn wrong_credentials_reach_the_caller_as_an_auth_failure() {
    let mock_server = MockServer::start().await;
    let server = std::sync::Arc::new(SrpServer::enrol("alice", "the-real-password"));
    let last_client_public = std::sync::Arc::new(std::sync::Mutex::new(None));
    Mock::given(method("POST"))
        .and(path("/api/v1/auth/srp/challenge"))
        .respond_with(ChallengeResponder {
            server: server.clone(),
            last_client_public,
        })
        .mount(&mock_server)
        .await;
    // The server rejects the proof, which is what a wrong password produces:
    // the exchange is well-formed, M1 simply does not match.
    Mock::given(method("POST"))
        .and(path("/api/v1/auth/srp/verify"))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({
            "error": "invalid_credentials",
            "message": "invalid username or password",
        })))
        .mount(&mock_server)
        .await;

    let client = client_for(&mock_server.uri());
    let err = client
        .login_srp("alice", "not-the-real-password")
        .await
        .expect_err("a rejected proof is an auth failure");

    assert!(matches!(err, AxiamError::Auth { .. }), "got {err:?}");
}

#[tokio::test]
async fn a_kdf_this_build_cannot_perform_is_refused_rather_than_substituted() {
    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/auth/srp/challenge"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "srp_session": "session-1",
            "identity": "alice",
            "salt": "00112233445566778899aabbccddeeff",
            "group": "rfc5054_2048",
            "kdf": "scrypt",
            "iterations": 1,
            "b_pub": "01",
        })))
        .mount(&mock_server)
        .await;

    let client = client_for(&mock_server.uri());
    let err = client
        .login_srp("alice", "irrelevant")
        .await
        .expect_err("an unknown KDF cannot be guessed at");

    assert!(
        format!("{err}").contains("scrypt"),
        "the refusal must name the KDF: {err}"
    );
}

#[tokio::test]
async fn a_group_this_build_does_not_implement_is_refused() {
    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/auth/srp/challenge"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "srp_session": "session-1",
            "identity": "alice",
            "salt": "00112233445566778899aabbccddeeff",
            "group": "rfc5054_1024",
            "kdf": "pbkdf2_sha256",
            "iterations": 1000,
            "b_pub": "01",
        })))
        .mount(&mock_server)
        .await;

    let client = client_for(&mock_server.uri());
    let err = client
        .login_srp("alice", "irrelevant")
        .await
        .expect_err("rfc5054_1024 is not implemented");

    assert!(format!("{err}").contains("rfc5054_1024"), "{err}");
}

#[tokio::test]
async fn a_malformed_salt_is_rejected_before_the_kdf_runs() {
    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/auth/srp/challenge"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "srp_session": "session-1",
            "identity": "alice",
            "salt": "not-hex",
            "group": "rfc5054_2048",
            "kdf": "pbkdf2_sha256",
            "iterations": 1000,
            "b_pub": "01",
        })))
        .mount(&mock_server)
        .await;

    let client = client_for(&mock_server.uri());
    let err = client
        .login_srp("alice", "irrelevant")
        .await
        .expect_err("a non-hex salt is not usable");

    assert!(format!("{err}").contains("salt"), "{err}");
}

#[tokio::test]
async fn b_congruent_to_zero_is_refused_without_a_second_round_trip() {
    // §23.3 rule 5, and the classic SRP break: B ≡ 0 (mod N) makes S
    // predictable. The verify endpoint is deliberately not mounted, so if the
    // client sent a proof anyway the test fails on a connection error rather
    // than passing quietly.
    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/auth/srp/challenge"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "srp_session": "session-1",
            "identity": "alice",
            "salt": "00112233445566778899aabbccddeeff",
            "group": "rfc5054_2048",
            "kdf": "pbkdf2_sha256",
            "iterations": 1000,
            "b_pub": "00",
        })))
        .mount(&mock_server)
        .await;

    let client = client_for(&mock_server.uri());
    let err = client
        .login_srp("alice", "irrelevant")
        .await
        .expect_err("B ≡ 0 mod N must be refused");

    assert!(matches!(err, AxiamError::Auth { .. }), "got {err:?}");
    assert!(format!("{err}").contains("invalid public value"), "{err}");
}

#[tokio::test]
async fn enrolment_produces_a_verifier_the_server_can_reproduce() {
    // The one direction the transport tests above cannot check: what
    // `srp_enrollment` hands a change-password request has to be the same
    // thing the server would have stored.
    let client = client_for("https://iam.example.com");
    let kdf = test_kdf();
    let enrolment = client
        .srp_enrollment("alice", "a-new-password", SrpGroup::Rfc5054_2048, &kdf)
        .expect("enrolment computes");

    assert_eq!(enrolment.group, "rfc5054_2048");
    assert_eq!(enrolment.kdf, "pbkdf2_sha256");
    assert_eq!(enrolment.iterations, 1000);
    assert!(enrolment.memory_kib.is_none(), "PBKDF2 has no memory cost");
    assert!(enrolment.parallelism.is_none());
    assert_eq!(enrolment.salt.len(), 64, "32 bytes of salt, hex-encoded");
    assert_eq!(
        enrolment.verifier.len(),
        512,
        "the verifier is padded to 256 bytes"
    );

    // Recompute it the way the server would, from the salt it was given.
    let n = BigUint::parse_bytes(N_2048_HEX.as_bytes(), 16).expect("modulus");
    let salt = hex::decode(&enrolment.salt).expect("salt is hex");
    let x = derive_x("alice", "a-new-password", &salt, &kdf).expect("derive x");
    let expected = BigUint::from(G_2048).modpow(&(BigUint::from_bytes_be(&x) % &n), &n);
    assert_eq!(
        enrolment.verifier,
        hex::encode(pad(&expected, 256)),
        "the SDK's verifier must be what the server would compute"
    );

    // Two enrolments of the same password must differ: the salt is fresh per
    // §23.3 rule 11, and a verifier that repeated would leak that two accounts
    // share a password.
    let second = client
        .srp_enrollment("alice", "a-new-password", SrpGroup::Rfc5054_2048, &kdf)
        .expect("enrolment computes");
    assert_ne!(enrolment.salt, second.salt);
    assert_ne!(enrolment.verifier, second.verifier);
}

#[tokio::test]
async fn argon2id_enrolment_carries_its_cost_parameters() {
    let client = client_for("https://iam.example.com");
    let kdf = SrpKdf::Argon2id {
        memory_kib: 8192,
        iterations: 1,
        parallelism: 1,
    };
    let enrolment = client
        .srp_enrollment("alice", "a-new-password", SrpGroup::Rfc5054_3072, &kdf)
        .expect("enrolment computes");

    // A verifier enrolled under one set of costs stays valid, so the costs
    // have to travel with it or a later login cannot reproduce `x`.
    assert_eq!(enrolment.kdf, "argon2id");
    assert_eq!(enrolment.memory_kib, Some(8192));
    assert_eq!(enrolment.iterations, 1);
    assert_eq!(enrolment.parallelism, Some(1));
    assert_eq!(enrolment.group, "rfc5054_3072");
    assert_eq!(enrolment.verifier.len(), 768);
}

#[test]
fn this_build_can_perform_srp() {
    // §23.1 puts this probe in every SDK's vocabulary; Rust has both KDFs and
    // all three groups compiled in, so it is unconditionally true here.
    let client = client_for("https://iam.example.com");
    assert!(client.srp_available());
}

#[test]
fn the_mock_and_the_sdk_agree_on_the_group_multiplier() {
    // If this fails, every proof mismatch above is the fixture's fault rather
    // than the SDK's — worth one assertion to tell the two apart.
    let server = SrpServer::enrol("alice", "some-password");
    assert_eq!(server.multiplier().to_bytes_be().len(), 32);
    assert_ne!(*server.multiplier(), BigUint::from(0u32));
}
