//! Secure Remote Password (SRP-6a) — CONTRACT.md §23.
//!
//! SRP is an *augmented PAKE*: the password never leaves this process. What
//! goes on the wire is `A` and a proof `M1`, neither of which is useful to
//! anyone who does not already hold the account's verifier.
//!
//! # What this buys, and what it does not
//!
//! TLS already protects the password against a network attacker. SRP closes a
//! different set of holes: a TLS-terminating proxy, ingress controller or CDN
//! no longer sees a plaintext password, an accidentally verbose request log
//! cannot capture one, and neither can a heap dump — because the server never
//! has one.
//!
//! It does **not** protect against a compromised AXIAM server. Nothing in this
//! module's documentation, or in any SDK's, may claim otherwise.
//!
//! # Layout
//!
//! * `group` (private) — the RFC 5054 moduli, embedded as constants, reached
//!   through [`SrpGroup`](crate::srp::SrpGroup).
//! * [`kdf`](crate::srp::kdf) — Argon2id and PBKDF2-HMAC-SHA256, the two ways
//!   `x` is derived.
//! * [`ClientSession`](crate::srp::ClientSession) — one exchange: pick `a`,
//!   compute `A`, then finish.
//!
//! Nothing here performs I/O. The transport lives in
//! [`crate::rest::srp`], which is what `login_srp` drives. That split is
//! deliberate: this half has to agree byte-for-byte with ten other languages,
//! and keeping it free of HTTP is what lets it be tested directly against the
//! vendored `srp-test-vectors.json`.

mod group;
pub mod kdf;

use num_bigint::BigUint;
use sha2::{Digest, Sha256};

use group::GroupParams;
pub use group::SrpGroup;

use crate::error::AxiamError;

/// `PAD(x)`: big-endian bytes, left-padded with zeros to the group width.
///
/// Every hash input in SRP-6a is padded to the modulus width. Skipping it is
/// *the* SRP interop bug: two implementations agree until a value happens to
/// have a leading zero byte, and then roughly one login in 256 fails in a way
/// that reads as a flaky network rather than as a defect. The vendored vectors
/// are built with a leading-zero salt and `x` specifically to catch it.
pub(crate) fn pad(value: &BigUint, byte_len: usize) -> Vec<u8> {
    let raw = value.to_bytes_be();
    if raw.len() >= byte_len {
        return raw;
    }
    let mut out = vec![0u8; byte_len - raw.len()];
    out.extend_from_slice(&raw);
    out
}

pub(crate) fn hash(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

fn hash_to_int(parts: &[&[u8]]) -> BigUint {
    BigUint::from_bytes_be(&hash(parts))
}

/// `u = H(PAD(A) | PAD(B))`.
fn compute_u(a_pub: &BigUint, b_pub: &BigUint, byte_len: usize) -> BigUint {
    hash_to_int(&[&pad(a_pub, byte_len), &pad(b_pub, byte_len)])
}

/// Compute the verifier `v = g^x mod N` for enrolment.
///
/// `x` is the KDF output — see [`kdf::derive_x`]. This is the only value the
/// server ever receives that is derived from the password, and it is
/// computationally infeasible to invert.
pub fn compute_verifier(group: SrpGroup, x: &[u8]) -> String {
    let params = GroupParams::for_group(group);
    let x = BigUint::from_bytes_be(x) % &params.n;
    hex::encode(pad(&params.g.modpow(&x, &params.n), params.byte_len))
}

/// An SRP exchange in progress.
///
/// Created by [`ClientSession::begin`], consumed by
/// [`ClientSession::finish`]. Holds the client's private ephemeral `a`, which
/// is generated fresh per exchange (§23.3 rule 7) and never leaves this type.
pub struct ClientSession {
    /// Client public value `A = g^a mod N`, lowercase hex. Send this with the
    /// challenge request.
    pub client_public: String,
    a_priv: BigUint,
    group: SrpGroup,
}

/// The two proofs a finished exchange produces.
///
/// `Debug` renders both values, which is safe: `M1` and `M2` are proofs *about*
/// the password, not the password, and neither is reusable outside the exchange
/// that produced it. The password, `x`, `S` and `K` never reach this type.
#[derive(Debug, Clone)]
pub struct ClientProofs {
    /// `M1`, lowercase hex — send this to `/auth/srp/verify`.
    pub client_proof: String,
    /// The `M2` the server must return.
    ///
    /// A caller MUST compare the server's `server_proof` against this and
    /// discard the session on mismatch (§23.3 rule 6). Skipping it keeps the
    /// half of SRP that authenticates the client to the server and throws away
    /// the half that authenticates the server to the client — leaving an
    /// endpoint that never knew the verifier indistinguishable from the real
    /// one. [`crate::rest::srp`] does this for you; it is exposed here for
    /// implementations that drive the protocol themselves.
    pub expected_server_proof: String,
}

impl ClientSession {
    /// Start an exchange: pick a fresh `a` and compute `A = g^a mod N`.
    ///
    /// `a` is 256 bits from the platform CSPRNG. Reusing it across exchanges
    /// would leak the relationship between two session secrets, which is why
    /// there is no way to supply one.
    pub fn begin(group: SrpGroup) -> Result<Self, AxiamError> {
        let params = GroupParams::for_group(group);
        let mut bytes = [0u8; 32];
        getrandom::fill(&mut bytes).map_err(|e| {
            AxiamError::network(format!("SRP: no source of randomness available: {e}"))
        })?;
        // Force the top bit so `a` is always full width. Not a security
        // property at 256 bits — just makes the value uniform in length.
        bytes[0] |= 0x80;
        let a_priv = BigUint::from_bytes_be(&bytes);
        let a_pub = params.g.modpow(&a_priv, &params.n);

        Ok(Self {
            client_public: hex::encode(pad(&a_pub, params.byte_len)),
            a_priv,
            group,
        })
    }

    /// Rebuild a session from a **fixed** private ephemeral `a`.
    ///
    /// # This is for conformance vectors, and nothing else
    ///
    /// CONTRACT.md §23.7 requires every SDK to reproduce the shared
    /// `srp-test-vectors.json` exactly, and a vector pins `a` so the whole
    /// exchange is deterministic. Without this constructor a conformance test
    /// would have to reimplement `finish` — testing a copy of the code rather
    /// than the code.
    ///
    /// **Never call this in production.** Reusing `a` across exchanges leaks
    /// the relationship between two session secrets, which is precisely why
    /// [`Self::begin`] offers no way to supply one. It is `#[doc(hidden)]`
    /// rather than `#[cfg(test)]` only because the conformance test lives in
    /// `tests/`, outside the crate.
    #[doc(hidden)]
    pub fn from_private_ephemeral(group: SrpGroup, a_priv_hex: &str) -> Result<Self, AxiamError> {
        let params = GroupParams::for_group(group);
        let a_priv = BigUint::parse_bytes(a_priv_hex.as_bytes(), 16)
            .ok_or_else(|| AxiamError::network("SRP: private ephemeral is not valid hex"))?;
        let a_pub = params.g.modpow(&a_priv, &params.n);
        Ok(Self {
            client_public: hex::encode(pad(&a_pub, params.byte_len)),
            a_priv,
            group,
        })
    }

    /// Finish the exchange from the server's challenge.
    ///
    /// `identity` MUST be the `identity` field of the challenge response, not
    /// what the user typed (§23.3 rule 2): AXIAM lets a user sign in with a
    /// username *or* an email while only one of the two is bound into `x`.
    ///
    /// `x` is the KDF output — see [`kdf::derive_x`].
    pub fn finish(
        &self,
        identity: &str,
        salt_hex: &str,
        server_public_hex: &str,
        x: &[u8],
    ) -> Result<ClientProofs, AxiamError> {
        let params = GroupParams::for_group(self.group);
        let n = &params.n;

        let b_pub = BigUint::parse_bytes(server_public_hex.as_bytes(), 16)
            .ok_or_else(|| AxiamError::auth("SRP: server public value is not valid hex"))?;
        // B ≡ 0 (mod N) means a broken or hostile server, not a wrong password
        // (§23.3 rule 5). Refuse before doing any work with it.
        if (&b_pub % n).is_zero_ref() {
            return Err(AxiamError::auth(
                "SRP: the server returned an invalid public value (B ≡ 0 mod N)",
            ));
        }

        let salt = hex::decode(salt_hex)
            .map_err(|_| AxiamError::auth("SRP: server salt is not valid hex"))?;
        let x = BigUint::from_bytes_be(x) % n;
        let a_pub = BigUint::parse_bytes(self.client_public.as_bytes(), 16)
            .expect("client_public was produced by hex::encode");

        let u = compute_u(&a_pub, &b_pub, params.byte_len);
        if u.is_zero_ref() {
            return Err(AxiamError::auth(
                "SRP: the server returned an invalid scrambling parameter (u = 0)",
            ));
        }

        // S = (B - k*g^x)^(a + u*x) mod N. `+ n` before the subtraction:
        // `k*g^x` can exceed `B`, and `BigUint` has no negative values.
        let kgx = (&params.k * params.g.modpow(&x, n)) % n;
        let base = ((&b_pub % n) + n - kgx) % n;
        let s = base.modpow(&(&self.a_priv + &u * &x), n);
        let session_key = hash(&[&pad(&s, params.byte_len)]);

        let h_n = hash(&[&pad(n, params.byte_len)]);
        let h_g = hash(&[&pad(&params.g, params.byte_len)]);
        let mut xored = [0u8; 32];
        for i in 0..32 {
            xored[i] = h_n[i] ^ h_g[i];
        }
        let h_i = hash(&[identity.as_bytes()]);

        let m1 = hash(&[
            &xored,
            &h_i,
            &salt,
            &pad(&a_pub, params.byte_len),
            &pad(&b_pub, params.byte_len),
            &session_key,
        ]);
        let m2 = hash(&[&pad(&a_pub, params.byte_len), &m1, &session_key]);

        Ok(ClientProofs {
            client_proof: hex::encode(m1),
            expected_server_proof: hex::encode(m2),
        })
    }
}

/// Constant-time comparison of the server's proof against the expected one.
///
/// `M2` is not a secret the client guards, so constant-time here is
/// belt-and-braces — but it costs nothing and keeps the habit intact where it
/// does matter.
pub fn verify_server_proof(expected: &str, actual: &str) -> bool {
    use subtle::ConstantTimeEq;

    let (Ok(expected), Ok(actual)) = (hex::decode(expected), hex::decode(actual)) else {
        return false;
    };
    if expected.len() != actual.len() {
        return false;
    }
    bool::from(expected.ct_eq(&actual))
}

/// `BigUint` has no `is_zero` without `num-traits`; this keeps the dependency
/// list one crate shorter for a two-line predicate.
trait IsZeroRef {
    fn is_zero_ref(&self) -> bool;
}

impl IsZeroRef for BigUint {
    fn is_zero_ref(&self) -> bool {
        self.to_bytes_be() == [0]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pad_left_pads_to_the_group_width() {
        assert_eq!(pad(&BigUint::from(1u32), 4), vec![0, 0, 0, 1]);
        // Already wide enough: unchanged.
        assert_eq!(pad(&BigUint::from(0x0102u32), 2), vec![1, 2]);
    }

    #[test]
    fn a_fresh_ephemeral_is_used_for_every_exchange() {
        let first = ClientSession::begin(SrpGroup::Rfc5054_2048).unwrap();
        let second = ClientSession::begin(SrpGroup::Rfc5054_2048).unwrap();
        assert_ne!(first.client_public, second.client_public);
    }

    #[test]
    fn a_server_public_value_congruent_to_zero_is_refused() {
        // The classic SRP break: a client that accepts B ≡ 0 derives a
        // predictable S and would authenticate against a server that never
        // knew the verifier.
        let session = ClientSession::begin(SrpGroup::Rfc5054_2048).unwrap();
        for b in ["00", &"0".repeat(512)] {
            let err = session
                .finish("alice", &"ab".repeat(32), b, &[1u8; 32])
                .unwrap_err();
            assert!(format!("{err}").contains("invalid public value"), "{err}");
        }
    }

    #[test]
    fn malformed_server_input_is_an_error_rather_than_a_panic() {
        let session = ClientSession::begin(SrpGroup::Rfc5054_2048).unwrap();
        assert!(session.finish("a", "ab", "zzzz", &[1u8; 32]).is_err());
        assert!(session.finish("a", "not-hex", "ab", &[1u8; 32]).is_err());
    }

    #[test]
    fn verify_server_proof_accepts_a_match_and_nothing_else() {
        assert!(verify_server_proof("abcd", "abcd"));
        assert!(!verify_server_proof("abcd", "abce"));
        assert!(!verify_server_proof("abcd", "ab"));
        assert!(!verify_server_proof("abcd", ""));
        assert!(!verify_server_proof("abcd", "not-hex"));
    }
}
