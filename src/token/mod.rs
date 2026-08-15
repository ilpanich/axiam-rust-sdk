//! Token management (owned by 16-02): `TokenManager`, single-flight refresh
//! guard, and local JWKS verification.

// §21.7.2 DPoP proof verification (contract 1.16). Gated on `rest`/`actix`:
// the ten checks need `sha2`, `base64` and `subtle`, which those features
// bring in. A `--no-default-features` consumer keeps `verify_token_binding`
// (pure claim comparison) and has no proof verifier — which per §10.1 rule 9
// means it must refuse `jkt`-bound tokens, not accept them as bearer tokens.
#[cfg(any(feature = "rest", feature = "actix"))]
pub mod dpop;
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

// §21.7.2 (contract 1.16). `verify_dpop_proof` returns the proof key's
// thumbprint, which is exactly what `Claims::verify_token_binding` expects as
// `dpop_thumbprint` — the two are meant to be used together, and the
// thumbprint can only ever originate from a proof that verified.
#[cfg(any(feature = "rest", feature = "actix"))]
pub use dpop::{
    DPOP_IAT_LEEWAY_SECS, DpopRequest, InMemoryJtiStore, JtiStore, access_token_hash,
    canonical_htu, jwk_thumbprint_s256, verify_dpop_proof,
};
