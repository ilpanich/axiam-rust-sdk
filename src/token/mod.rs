//! Token management (owned by 16-02): `TokenManager`, single-flight refresh
//! guard, and local JWKS verification.

pub mod jwks;
pub mod manager;
pub mod refresh_guard;

pub use jwks::Claims;
// §10.1 rule 9 (contract 1.15). Ungated alongside `Claims`, because
// `Claims::verify_certificate_binding` is pure claim logic a
// `--no-default-features` consumer must be able to apply.
pub use jwks::CnfClaim;
// §10.1 rule 9 extended for DPoP (contract 1.16). Ungated for the same reason
// as `CnfClaim`: `Claims::verify_token_binding` is pure claim comparison, and
// a `--no-default-features` consumer must be able to apply the full rule and
// not just its certificate half.
pub use jwks::PresentedProofs;
#[cfg(any(feature = "rest", feature = "actix", feature = "amqp"))]
pub use jwks::certificate_thumbprint_s256;
#[cfg(any(feature = "rest", feature = "actix"))]
pub use jwks::{CLOCK_SKEW_LEEWAY_SECS, JwksVerifier};
pub use manager::TokenManager;
