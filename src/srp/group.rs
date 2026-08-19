//! The RFC 5054 Appendix A groups, embedded as constants.
//!
//! # Why the modulus is never taken from the server
//!
//! A server-supplied `N` is a server-supplied trapdoor: a hostile server could
//! hand over a group whose discrete logarithm it knows and recover `x` — and
//! therefore the password — from the exchange. §23.4 makes embedding these
//! mandatory, and this SDK has no code path that accepts one over the wire.
//!
//! A transcription slip in any of these constants is a silent, total break: the
//! client and server would still agree with each other while the hardness
//! assumption the whole protocol rests on quietly vanished, and a round-trip
//! test could not catch it because both sides share the same wrong value. The
//! tests below therefore assert each modulus is the advertised width, is prime,
//! is a *safe* prime, and that `g` generates the large subgroup.

use std::sync::OnceLock;

use num_bigint::BigUint;

use super::hash;
use crate::error::AxiamError;

/// An RFC 5054 Appendix A safe-prime group.
///
/// A verifier is only meaningful under the group it was created with, so the
/// server names the group in every challenge rather than assuming one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SrpGroup {
    /// RFC 5054 Appendix A, 2048-bit group (g = 2).
    Rfc5054_2048,
    /// RFC 5054 Appendix A, 3072-bit group (g = 5).
    Rfc5054_3072,
    /// RFC 5054 Appendix A, 4096-bit group (g = 5). The AXIAM default.
    #[default]
    Rfc5054_4096,
}

impl SrpGroup {
    /// Width of the modulus in bytes — what every `PAD()` pads to.
    pub fn byte_len(self) -> usize {
        match self {
            Self::Rfc5054_2048 => 256,
            Self::Rfc5054_3072 => 384,
            Self::Rfc5054_4096 => 512,
        }
    }

    /// The wire name, as it appears in a challenge response.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Rfc5054_2048 => "rfc5054_2048",
            Self::Rfc5054_3072 => "rfc5054_3072",
            Self::Rfc5054_4096 => "rfc5054_4096",
        }
    }

    /// Parse a group name from a challenge response.
    ///
    /// An unrecognised name is refused rather than guessed at (§23.4): the
    /// alternative is computing in a group the SDK does not know is safe.
    pub fn parse(name: &str) -> Result<Self, AxiamError> {
        match name {
            "rfc5054_2048" => Ok(Self::Rfc5054_2048),
            "rfc5054_3072" => Ok(Self::Rfc5054_3072),
            "rfc5054_4096" => Ok(Self::Rfc5054_4096),
            other => Err(AxiamError::network(format!(
                "this SDK does not implement the SRP group this tenant requires ({other})"
            ))),
        }
    }
}

impl std::fmt::Display for SrpGroup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

const N_2048_HEX: &str = concat!(
    "AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050",
    "A37329CBB4A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50",
    "E8083969EDB767B0CF6095179A163AB3661A05FBD5FAAAE82918A9962F0B93B8",
    "55F97993EC975EEAA80D740ADBF4FF747359D041D5C33EA71D281E446B14773B",
    "CA97B43A23FB801676BD207A436C6481F1D2B9078717461A5B9D32E688F87748",
    "544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6",
    "AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB6",
    "94B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73",
);

const N_3072_HEX: &str = concat!(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74",
    "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437",
    "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED",
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05",
    "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB",
    "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B",
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718",
    "3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33",
    "A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7",
    "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864",
    "D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E2",
    "08E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF",
);

const N_4096_HEX: &str = concat!(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74",
    "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437",
    "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED",
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05",
    "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB",
    "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B",
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718",
    "3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33",
    "A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7",
    "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864",
    "D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E2",
    "08E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D7",
    "88719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8",
    "DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2",
    "233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA9",
    "93B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199FFFFFFFFFFFFFFFF",
);

/// Parsed group parameters, computed once per group and cached.
pub(crate) struct GroupParams {
    pub(crate) n: BigUint,
    pub(crate) g: BigUint,
    /// `k = H(N | PAD(g))` — the SRP-6a multiplier. Depends only on the group.
    pub(crate) k: BigUint,
    pub(crate) byte_len: usize,
}

impl GroupParams {
    pub(crate) fn for_group(group: SrpGroup) -> &'static GroupParams {
        static G2048: OnceLock<GroupParams> = OnceLock::new();
        static G3072: OnceLock<GroupParams> = OnceLock::new();
        static G4096: OnceLock<GroupParams> = OnceLock::new();

        fn build(n_hex: &str, g: u32, byte_len: usize) -> GroupParams {
            let n = BigUint::parse_bytes(n_hex.as_bytes(), 16)
                .expect("compile-time SRP modulus is valid hex");
            let g = BigUint::from(g);
            let k = BigUint::from_bytes_be(&hash(&[
                &super::pad(&n, byte_len),
                &super::pad(&g, byte_len),
            ]));
            GroupParams { n, g, k, byte_len }
        }

        match group {
            SrpGroup::Rfc5054_2048 => G2048.get_or_init(|| build(N_2048_HEX, 2, 256)),
            SrpGroup::Rfc5054_3072 => G3072.get_or_init(|| build(N_3072_HEX, 5, 384)),
            SrpGroup::Rfc5054_4096 => G4096.get_or_init(|| build(N_4096_HEX, 5, 512)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Miller-Rabin with fixed bases — deterministic, and strong at these
    /// sizes.
    fn is_probable_prime(n: &BigUint) -> bool {
        let one = BigUint::from(1u32);
        let two = BigUint::from(2u32);
        if *n < two {
            return false;
        }
        let n_minus_1 = n - &one;
        let mut d = n_minus_1.clone();
        let mut r = 0u32;
        while (&d % &two) == BigUint::from(0u32) {
            d /= &two;
            r += 1;
        }
        for base in [2u32, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37] {
            let mut x = BigUint::from(base).modpow(&d, n);
            if x == one || x == n_minus_1 {
                continue;
            }
            let mut passed = false;
            for _ in 0..r - 1 {
                x = x.modpow(&two, n);
                if x == n_minus_1 {
                    passed = true;
                    break;
                }
            }
            if !passed {
                return false;
            }
        }
        true
    }

    #[test]
    fn every_modulus_is_a_safe_prime_of_the_advertised_width() {
        for group in [
            SrpGroup::Rfc5054_2048,
            SrpGroup::Rfc5054_3072,
            SrpGroup::Rfc5054_4096,
        ] {
            let params = GroupParams::for_group(group);
            assert_eq!(
                params.n.bits() as usize,
                group.byte_len() * 8,
                "{group} modulus is the wrong width"
            );
            assert!(is_probable_prime(&params.n), "{group} modulus is not prime");
            let q = (&params.n - BigUint::from(1u32)) / BigUint::from(2u32);
            assert!(is_probable_prime(&q), "{group} modulus is not a safe prime");
            assert_eq!(
                params.g.modpow(&q, &params.n),
                &params.n - BigUint::from(1u32),
                "{group} generator does not generate the large subgroup"
            );
        }
    }

    #[test]
    fn group_names_round_trip_and_unknown_names_are_refused() {
        for group in [
            SrpGroup::Rfc5054_2048,
            SrpGroup::Rfc5054_3072,
            SrpGroup::Rfc5054_4096,
        ] {
            assert_eq!(SrpGroup::parse(group.as_str()).unwrap(), group);
        }
        // Guessing at an unknown group would mean computing in one whose
        // safety this SDK has not verified.
        assert!(SrpGroup::parse("rfc5054_1024").is_err());
        assert!(SrpGroup::parse("").is_err());
    }
}
