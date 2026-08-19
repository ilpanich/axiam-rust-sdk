//! Deriving the SRP private key `x` from a password.
//!
//! `x = OS2IP(KDF(identity ":" password, salt)) mod N` (CONTRACT.md §23.3
//! rule 3).
//!
//! # Why a KDF rather than RFC 5054's bare hash
//!
//! RFC 5054 §2.6 defines `x = SHA1(s | SHA1(I ":" p))`. With a bare hash, a
//! leaked verifier database is *cheaper* to attack offline than the Argon2id
//! password hashes AXIAM already stores — so adopting SRP as specified would
//! have been a net security regression at rest, not an improvement. The
//! identity stays inside the KDF input exactly as the RFC intends, so a
//! verifier remains bound to one account.
//!
//! # Why two KDFs
//!
//! Argon2id is preferred and is what a new verifier gets. PBKDF2-HMAC-SHA256
//! exists because three of AXIAM's eleven SDK languages have no vetted Argon2
//! binding in their standard distribution, and shipping a protocol only half
//! the SDKs could speak would have been worse than shipping a
//! weaker-but-universal fallback.
//!
//! The server dictates which one per exchange, along with its cost parameters,
//! and those MUST be honoured as given: a verifier enrolled under different
//! costs is still valid and must keep working, so caching parameters across
//! logins would break exactly the users who enrolled earliest.

use crate::error::AxiamError;

/// Which KDF a challenge asked for, with its cost parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SrpKdf {
    /// Argon2id — memory-hard, and what AXIAM prefers.
    Argon2id {
        /// Memory cost in KiB.
        memory_kib: u32,
        /// Time cost (number of passes).
        iterations: u32,
        /// Degree of parallelism.
        parallelism: u32,
    },
    /// PBKDF2-HMAC-SHA256. Not memory-hard; present for portability.
    Pbkdf2Sha256 {
        /// Iteration count.
        iterations: u32,
    },
}

impl SrpKdf {
    /// Build from a challenge response's `kdf` name and parameters.
    ///
    /// An unknown KDF is refused rather than substituted (§23.3 rule 4).
    /// Substituting the other one derives a different `x` and surfaces as
    /// "invalid password" — the single most misleading failure this code could
    /// produce, sending a user off to reset a password that works.
    pub fn from_wire(
        kdf: &str,
        iterations: u32,
        memory_kib: Option<u32>,
        parallelism: Option<u32>,
    ) -> Result<Self, AxiamError> {
        match kdf {
            "argon2id" => Ok(Self::Argon2id {
                memory_kib: memory_kib.ok_or_else(|| {
                    AxiamError::network("SRP challenge named argon2id but carried no memory cost")
                })?,
                iterations,
                parallelism: parallelism.ok_or_else(|| {
                    AxiamError::network("SRP challenge named argon2id but carried no parallelism")
                })?,
            }),
            "pbkdf2_sha256" => Ok(Self::Pbkdf2Sha256 { iterations }),
            other => Err(AxiamError::network(format!(
                "this SDK cannot perform the key-derivation function this tenant requires ({other})"
            ))),
        }
    }

    /// The wire name.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Argon2id { .. } => "argon2id",
            Self::Pbkdf2Sha256 { .. } => "pbkdf2_sha256",
        }
    }
}

/// Derive `x` — 32 bytes — from the password.
///
/// `identity` MUST be the value from the challenge response, never what the
/// user typed (§23.3 rule 2).
///
/// This is deliberately slow. Argon2id at AXIAM's default parameters allocates
/// 19 MiB and takes tens of milliseconds; that cost is the point, and a caller
/// on an async runtime should treat it as blocking work.
pub fn derive_x(
    identity: &str,
    password: &str,
    salt: &[u8],
    kdf: &SrpKdf,
) -> Result<Vec<u8>, AxiamError> {
    let secret = format!("{identity}:{password}");

    match kdf {
        SrpKdf::Argon2id {
            memory_kib,
            iterations,
            parallelism,
        } => {
            use argon2::{Algorithm, Argon2, Params, Version};

            let params =
                Params::new(*memory_kib, *iterations, *parallelism, Some(32)).map_err(|e| {
                    AxiamError::network(format!("SRP argon2id parameters rejected: {e}"))
                })?;
            let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
            let mut out = vec![0u8; 32];
            argon2
                .hash_password_into(secret.as_bytes(), salt, &mut out)
                .map_err(|e| AxiamError::network(format!("SRP argon2id derivation failed: {e}")))?;
            Ok(out)
        }
        SrpKdf::Pbkdf2Sha256 { iterations } => {
            Ok(pbkdf2_hmac_sha256(secret.as_bytes(), salt, *iterations))
        }
    }
}

/// PBKDF2-HMAC-SHA256 producing exactly 32 bytes (RFC 8018 §5.2).
///
/// Hand-rolled rather than pulled from the `pbkdf2` crate for a boring reason:
/// that crate's current release is built against `hmac` 0.12 and this crate is
/// on 0.13, so taking it would mean carrying two incompatible copies of the
/// RustCrypto stack. The algorithm is twenty lines and one output block wide —
/// `dkLen == hLen`, so there is no block loop and no `INT(i)` beyond the
/// constant `1` — which makes the hand-rolled version smaller than the
/// dependency it replaces and easier to check against the RFC.
///
/// It is checked against the vendored cross-language vectors like everything
/// else here, so a mistake in it fails loudly rather than silently deriving a
/// wrong `x`.
fn pbkdf2_hmac_sha256(password: &[u8], salt: &[u8], iterations: u32) -> Vec<u8> {
    use hmac::{Hmac, KeyInit, Mac};
    use sha2::Sha256;

    type HmacSha256 = Hmac<Sha256>;

    // U_1 = PRF(P, S || INT(1))
    let mut mac = <HmacSha256 as KeyInit>::new_from_slice(password)
        .expect("HMAC accepts a key of any length");
    mac.update(salt);
    mac.update(&1u32.to_be_bytes());
    let mut u: [u8; 32] = mac.finalize().into_bytes().into();
    let mut out = u;

    // U_c = PRF(P, U_{c-1}); T_1 = U_1 XOR U_2 XOR ... XOR U_c
    for _ in 1..iterations.max(1) {
        let mut mac = <HmacSha256 as KeyInit>::new_from_slice(password)
            .expect("HMAC accepts a key of any length");
        mac.update(&u);
        u = mac.finalize().into_bytes().into();
        for i in 0..32 {
            out[i] ^= u[i];
        }
    }
    out.to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test credentials, generated per run rather than written as literals.
    ///
    /// CodeQL's `rust/hard-coded-cryptographic-value` flags a literal that
    /// reaches a KDF as a password or a salt, and in shipping code that rule is
    /// exactly right. Suppressing it for the tests would blunt it everywhere
    /// else in this crate, so the fixtures are generated instead — which is
    /// also the better test: a derivation that only holds for the literal
    /// `"salt"` is not one anybody should trust.
    ///
    /// Determinism is not needed here. Every assertion below compares one
    /// `derive_x` output against another from the same run; none compares
    /// against a fixed expected value. The published §23.6 vectors are replayed
    /// in `tests/srp_vectors_test.rs`, which is where fixed inputs belong.
    fn random_word(len: usize) -> String {
        let mut raw = vec![0u8; len];
        getrandom::fill(&mut raw).expect("the platform CSPRNG is available");
        raw.iter().map(|b| char::from(b'a' + (b % 26))).collect()
    }

    /// Salt material of `len` bytes from the platform CSPRNG. See
    /// [`random_word`] for why these are not literals.
    fn random_salt(len: usize) -> Vec<u8> {
        let mut raw = vec![0u8; len];
        getrandom::fill(&mut raw).expect("the platform CSPRNG is available");
        raw
    }

    #[test]
    fn an_unknown_kdf_is_refused_rather_than_substituted() {
        // Substituting would derive a different x and report "invalid
        // password" for a password that is entirely correct.
        let err = SrpKdf::from_wire("scrypt", 1, None, None).unwrap_err();
        assert!(format!("{err}").contains("scrypt"), "{err}");
    }

    #[test]
    fn argon2id_requires_its_own_parameters() {
        assert!(SrpKdf::from_wire("argon2id", 2, None, Some(1)).is_err());
        assert!(SrpKdf::from_wire("argon2id", 2, Some(19456), None).is_err());
        assert!(SrpKdf::from_wire("argon2id", 2, Some(19456), Some(1)).is_ok());
    }

    #[test]
    fn pbkdf2_needs_no_argon2_parameters() {
        assert_eq!(
            SrpKdf::from_wire("pbkdf2_sha256", 600_000, None, None).unwrap(),
            SrpKdf::Pbkdf2Sha256 {
                iterations: 600_000
            }
        );
    }

    #[test]
    fn x_is_deterministic_and_binds_identity_salt_and_password() {
        // Every one of these four inputs must change the output, or a verifier
        // would be replayable against a different account or a different salt.
        let kdf = SrpKdf::Pbkdf2Sha256 { iterations: 1000 };
        let (identity, password, salt) = (random_word(5), random_word(12), random_salt(32));
        let (other_identity, other_password, other_salt) =
            (random_word(5), random_word(12), random_salt(32));

        let base = derive_x(&identity, &password, &salt, &kdf).unwrap();
        assert_eq!(base.len(), 32);
        assert_eq!(derive_x(&identity, &password, &salt, &kdf).unwrap(), base);
        assert_ne!(
            derive_x(&other_identity, &password, &salt, &kdf).unwrap(),
            base
        );
        assert_ne!(
            derive_x(&identity, &other_password, &salt, &kdf).unwrap(),
            base
        );
        assert_ne!(
            derive_x(&identity, &password, &other_salt, &kdf).unwrap(),
            base
        );
    }

    #[test]
    fn the_identity_separator_collides_but_the_salt_makes_it_harmless() {
        // `identity ":" password` is ambiguous, and this is the demonstration:
        // ("alice", "bob:pw") and ("alice:bob", "pw") both concatenate to
        // "alice:bob:pw" and derive the identical x. RFC 5054 §2.6 has the same
        // property and AXIAM keeps the format, so the collision is real.
        //
        // It is not exploitable, and the reason is the salt rather than the
        // separator. Every credential gets 32 fresh random bytes, so two
        // accounts never share one; deriving the same x from the same salt
        // requires already knowing the other account's password AND its salt,
        // at which point the verifier is not what is protecting anything.
        //
        // Asserted rather than left implicit so that anyone who later changes
        // the salt to something derived — from the username, say, or a
        // per-tenant constant — finds out here that they have just made this
        // collision reachable.
        let kdf = SrpKdf::Pbkdf2Sha256 { iterations: 1000 };
        // `left`, `right` and `password` stand in for the three fragments that
        // straddle the separator: ("left", "right:password") and
        // ("left:right", "password") concatenate identically.
        let (left, right, password) = (random_word(5), random_word(3), random_word(12));
        let shared_salt = random_salt(32);
        assert_eq!(
            derive_x(&left, &format!("{right}:{password}"), &shared_salt, &kdf).unwrap(),
            derive_x(&format!("{left}:{right}"), &password, &shared_salt, &kdf).unwrap(),
            "the concatenation is ambiguous by construction"
        );
        // ...and with the per-credential salts that actually ship, it is not.
        assert_ne!(
            derive_x(
                &left,
                &format!("{right}:{password}"),
                &random_salt(32),
                &kdf
            )
            .unwrap(),
            derive_x(
                &format!("{left}:{right}"),
                &password,
                &random_salt(32),
                &kdf
            )
            .unwrap()
        );
    }

    #[test]
    fn argon2id_derives_a_32_byte_key_at_realistic_parameters() {
        // Low memory so the test stays fast; the code path is identical.
        let kdf = SrpKdf::Argon2id {
            memory_kib: 8192,
            iterations: 1,
            parallelism: 1,
        };
        assert_eq!(
            derive_x(&random_word(5), &random_word(12), &random_salt(16), &kdf)
                .unwrap()
                .len(),
            32
        );
    }
}
