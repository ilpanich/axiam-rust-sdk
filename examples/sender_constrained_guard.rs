//! Enforcing CONTRACT.md §10.1 rule 9 in a resource server — the full rule,
//! covering both certificate-bound (RFC 8705) and DPoP-bound (RFC 9449)
//! access tokens.
//!
//! Run with:
//!
//! ```bash
//! cargo run --example sender_constrained_guard --features rest
//! ```
//!
//! # What rule 9 actually says
//!
//! A token carrying `cnf` is **not** a bearer token. Accepting one without
//! proving the caller holds the confirmed key converts it back into a bearer
//! token and discards the whole protection the operator turned on.
//!
//! Three cases are worth internalising, because they are the ones that get
//! implemented wrongly:
//!
//! 1. **An unbound token is still accepted** — with no certificate and no
//!    proof. Rule 9 is not "require evidence from everybody".
//! 2. **`cnf` naming both methods is a conjunction.** Two constraints means
//!    two; satisfying the more convenient one is not compliance.
//! 3. **A `cnf` this SDK cannot interpret is refused**, never read as
//!    unconstrained — including an *empty* one.

use axiam_sdk::token::{JwksVerifier, PresentedProofs, certificate_thumbprint_s256};

/// Whatever your transport gives you for this request.
///
/// The one rule: every value here must come from the connection, never from a
/// header the caller can set. A forgeable input makes the mechanism
/// decorative.
struct Transport {
    /// The DER-encoded TLS peer certificate, when the peer presented one.
    peer_certificate_der: Option<Vec<u8>>,
    /// The `jkt` of a DPoP proof **you have already verified** against this
    /// request's method, URI, `iat` and `jti`.
    ///
    /// Supplying a thumbprint here asserts the proof checked out. Lifting it
    /// off an unverified proof would let a proof captured from any other
    /// endpoint authorize this one.
    verified_dpop_thumbprint: Option<String>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let base_url =
        std::env::var("AXIAM_BASE_URL").unwrap_or_else(|_| "https://axiam.example.com".to_owned());
    let base_url_parsed = url::Url::parse(&base_url)?;

    // §10.1 rule 4: `/oauth2/jwks` is organization-wide, so a valid signature
    // proves only "some tenant in this org" — a guard must name the tenant it
    // is guarding or it fails closed on every request.
    let tenant_id: uuid::Uuid = std::env::var("AXIAM_TENANT_ID")
        .expect("AXIAM_TENANT_ID is required: the §10 guard asserts it on every token")
        .parse()?;

    let verifier = JwksVerifier::new(reqwest::Client::new(), &base_url_parsed)?
        .expect_tenant_id(tenant_id)
        .expect_audience("axiam:user");

    let token = "…the access token from the Authorization header…";
    let transport = Transport {
        peer_certificate_der: None,
        verified_dpop_thumbprint: None,
    };

    // Rules 1-8: signature, expiry, issuer, audience. NOT rule 9 — `verify`
    // has no transport to ask, which is exactly why the binding check is a
    // separate call rather than something you can forget to opt into.
    let claims = verifier.verify(token).await?;

    let certificate_thumbprint = transport
        .peer_certificate_der
        .as_deref()
        .map(certificate_thumbprint_s256);

    // Rule 9. Returns `Ok` immediately for an unbound token, so adopting this
    // does not break existing deployments.
    claims.verify_token_binding(PresentedProofs {
        certificate_thumbprint: certificate_thumbprint.as_deref(),
        dpop_thumbprint: transport.verified_dpop_thumbprint.as_deref(),
    })?;

    println!("subject {} authorized", claims.sub);
    Ok(())
}
