//! CONTRACT.md §10.1 "Minimum local-verification set" — the complete required
//! negative-test set, asserted against the SDK's local-verification entry
//! points: [`JwksVerifier::verify`] (the documented guard) and, through it,
//! the §10 Actix `AxiamUser` extractor that the §11 `require_*` macros inject.
//!
//! §10.1 exists because `SEC-071` and `SEC-080` were the same defect found
//! twice: each SDK verified a *different subset* of the token, and each subset
//! looked complete in isolation. This file is the stated complete set, so a
//! future change that quietly drops one rule fails here instead of in
//! production.

#![cfg(feature = "rest")]

use axiam_sdk::AxiamError;
use axiam_sdk::token::PresentedProofs;
use axiam_sdk::token::{CLOCK_SKEW_LEEWAY_SECS, JwksVerifier};
use base64::Engine as _;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde_json::{Value, json};
use uuid::Uuid;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const TEST_ED25519_SEED: [u8; 32] = [
    0x74, 0x8c, 0x0b, 0xd3, 0xad, 0xc0, 0x28, 0x0a, 0xfd, 0xd7, 0xc0, 0x7c, 0x35, 0x07, 0x03, 0x64,
    0x6d, 0x14, 0x2d, 0x1d, 0xbd, 0x73, 0x4c, 0xd4, 0xf8, 0x17, 0x17, 0x0b, 0x91, 0x7b, 0x49, 0xfc,
];
const ED25519_PKCS8_DER_PREFIX: [u8; 16] = [
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];
const TEST_ED25519_PUBLIC_X: &str = "_r-I_0nRSSV8kvwA93gwhX-hFRiWkaNk5HEud-DjnMk";
const TEST_KID: &str = "sec-101-kid";
const TENANT: &str = "3f6b1c8e-0000-4000-8000-0000000000a1";
const OTHER_TENANT: &str = "3f6b1c8e-0000-4000-8000-0000000000b2";
const ISSUER: &str = "https://iam.example.com";

fn tenant_uuid() -> Uuid {
    TENANT.parse().expect("tenant const is a UUID")
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock is after the epoch")
        .as_secs() as i64
}

fn ed25519_key() -> EncodingKey {
    let mut der = ED25519_PKCS8_DER_PREFIX.to_vec();
    der.extend_from_slice(&TEST_ED25519_SEED);
    EncodingKey::from_ed_der(&der)
}

/// A claims object satisfying every §10.1 rule, before a test breaks one.
fn good_claims() -> Value {
    json!({
        "sub": Uuid::new_v4().to_string(),
        "tenant_id": TENANT,
        "org_id": Uuid::new_v4().to_string(),
        "iss": ISSUER,
        "aud": "axiam:user",
        "iat": now() - 60,
        "exp": now() + 3600,
        "jti": Uuid::new_v4().to_string(),
        "scope": "read write",
    })
}

fn sign_eddsa(claims: &Value) -> String {
    let mut header = Header::new(Algorithm::EdDSA);
    header.kid = Some(TEST_KID.to_string());
    jsonwebtoken::encode(&header, claims, &ed25519_key()).expect("encode EdDSA token")
}

/// Serve the org-wide JWKS with the one Ed25519 key the tests sign against.
async fn jwks_server() -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/oauth2/jwks"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "keys": [{
                "kty": "OKP",
                "crv": "Ed25519",
                "kid": TEST_KID,
                "alg": "EdDSA",
                "x": TEST_ED25519_PUBLIC_X,
            }]
        })))
        .mount(&server)
        .await;
    server
}

/// A guard-shaped verifier: an expected tenant is configured, as §10.1 rule 4
/// requires of anything used as a route guard.
fn guard_verifier(base_url: &str) -> JwksVerifier {
    let url = url::Url::parse(base_url).expect("valid base url");
    JwksVerifier::new(reqwest::Client::new(), &url)
        .expect("verifier constructs")
        .expect_tenant_id(tenant_uuid())
}

fn assert_auth_error_containing(err: AxiamError, needle: &str) {
    match err {
        AxiamError::Auth { message, .. } => assert!(
            message.contains(needle),
            "expected message containing {needle:?}, got {message:?}"
        ),
        other => panic!("expected AxiamError::Auth, got {other:?}"),
    }
}

// ---------------------------------------------------------------- control --

#[tokio::test]
async fn accepts_a_token_that_satisfies_every_rule() {
    let server = jwks_server().await;
    let verifier = guard_verifier(&server.uri())
        .expect_issuer(ISSUER)
        .expect_audience("axiam:user");
    let token = sign_eddsa(&good_claims());

    let claims = verifier
        .verify(&token)
        .await
        .expect("control token verifies");
    assert_eq!(claims.tenant_id, TENANT);
}

// ------------------------------------------------- rule 1: signature / alg --

#[tokio::test]
async fn rule1_rejects_alg_none_without_consulting_a_key() {
    // No JWKS mock is mounted at all: if the implementation reached a key
    // lookup, the request would fail as a *network* error rather than an
    // auth error, which is exactly what this assertion distinguishes.
    let url = url::Url::parse("https://iam.invalid").expect("url");
    let verifier = JwksVerifier::new(reqwest::Client::new(), &url)
        .expect("verifier constructs")
        .expect_tenant_id(tenant_uuid());

    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    // The `kid` names a real published key — only the `alg` header may sink it.
    let header = b64.encode(json!({"alg": "none", "kid": TEST_KID}).to_string());
    let payload = b64.encode(good_claims().to_string());
    let token = format!("{header}.{payload}.");

    let err = verifier
        .verify(&token)
        .await
        .expect_err("alg: none must be rejected");
    assert_auth_error_containing(err, "EdDSA");
}

#[tokio::test]
async fn rule1_rejects_an_hs_signed_token_bearing_the_eddsa_kid() {
    // Same reasoning: no JWKS mock, so reaching a key lookup would surface as
    // a network error instead of the alg rejection asserted below.
    let url = url::Url::parse("https://iam.invalid").expect("url");
    let verifier = JwksVerifier::new(reqwest::Client::new(), &url)
        .expect("verifier constructs")
        .expect_tenant_id(tenant_uuid());

    let mut header = Header::new(Algorithm::HS256);
    header.kid = Some(TEST_KID.to_string());
    let token = jsonwebtoken::encode(
        &header,
        &good_claims(),
        &EncodingKey::from_secret(b"irrelevant-shared-secret"),
    )
    .expect("encode HS256 token");

    let err = verifier
        .verify(&token)
        .await
        .expect_err("HS-family confusion must be rejected");
    assert_auth_error_containing(err, "EdDSA");
}

#[tokio::test]
async fn rule1_rejects_a_token_signed_by_a_foreign_key() {
    let server = jwks_server().await;
    let verifier = guard_verifier(&server.uri());

    let mut wrong_seed = TEST_ED25519_SEED;
    wrong_seed[0] ^= 0xFF;
    let mut wrong_der = ED25519_PKCS8_DER_PREFIX.to_vec();
    wrong_der.extend_from_slice(&wrong_seed);
    let mut header = Header::new(Algorithm::EdDSA);
    header.kid = Some(TEST_KID.to_string());
    let token = jsonwebtoken::encode(
        &header,
        &good_claims(),
        &EncodingKey::from_ed_der(&wrong_der),
    )
    .expect("encode token signed with the wrong key");

    let err = verifier
        .verify(&token)
        .await
        .expect_err("a foreign signature must be rejected");
    assert_auth_error_containing(err, "signature");
}

// -------------------------------------------------------------- rule 2: exp --

#[tokio::test]
async fn rule2_rejects_an_expired_token() {
    let server = jwks_server().await;
    let verifier = guard_verifier(&server.uri());
    let mut claims = good_claims();
    claims["exp"] = json!(now() - 3600);

    let err = verifier
        .verify(&sign_eddsa(&claims))
        .await
        .expect_err("an expired token must be rejected");
    assert_auth_error_containing(err, "expired");
}

#[tokio::test]
async fn rule2_rejects_a_token_with_no_exp_claim() {
    let server = jwks_server().await;
    let verifier = guard_verifier(&server.uri());
    let mut claims = good_claims();
    claims.as_object_mut().expect("object").remove("exp");

    // An absent `exp` is a PERMANENT credential — never "no expiry constraint".
    let err = verifier
        .verify(&sign_eddsa(&claims))
        .await
        .expect_err("a token with no exp must be rejected");
    assert_auth_error_containing(err, "exp");
}

#[tokio::test]
async fn rule2_rejects_a_token_with_a_non_numeric_exp() {
    let server = jwks_server().await;
    let verifier = guard_verifier(&server.uri());
    let mut claims = good_claims();
    claims["exp"] = json!("tomorrow");

    let err = verifier
        .verify(&sign_eddsa(&claims))
        .await
        .expect_err("a non-numeric exp must be rejected");
    assert_auth_error_containing(err, "exp");
}

// -------------------------------------------------------------- rule 3: nbf --

#[tokio::test]
async fn rule3_rejects_a_token_whose_nbf_is_in_the_future() {
    let server = jwks_server().await;
    let verifier = guard_verifier(&server.uri());
    let mut claims = good_claims();
    claims["nbf"] = json!(now() + 3600);

    let err = verifier
        .verify(&sign_eddsa(&claims))
        .await
        .expect_err("a future nbf must be rejected");
    assert_auth_error_containing(err, "not valid yet");
}

#[tokio::test]
async fn rule3_accepts_a_token_with_no_nbf() {
    let server = jwks_server().await;
    let verifier = guard_verifier(&server.uri());

    verifier
        .verify(&sign_eddsa(&good_claims()))
        .await
        .expect("an absent nbf is valid");
}

// -------------------------------------------------------- rule 4: tenant_id --

#[tokio::test]
async fn rule4_rejects_a_token_minted_for_a_different_tenant() {
    let server = jwks_server().await;
    let verifier = guard_verifier(&server.uri());
    let mut claims = good_claims();
    claims["tenant_id"] = json!(OTHER_TENANT);

    // The JWKS trust anchor is organization-wide, so this token's signature is
    // perfectly valid — only the tenant assertion stops it.
    let err = verifier
        .verify(&sign_eddsa(&claims))
        .await
        .expect_err("a sibling tenant's token must be rejected");
    assert_auth_error_containing(err, "does not match the configured tenant");
}

#[tokio::test]
async fn rule4_rejects_a_token_with_no_tenant_id_claim() {
    let server = jwks_server().await;
    let verifier = guard_verifier(&server.uri());
    let mut claims = good_claims();
    claims.as_object_mut().expect("object").remove("tenant_id");

    let err = verifier
        .verify(&sign_eddsa(&claims))
        .await
        .expect_err("a token with no tenant_id must be rejected");
    assert_auth_error_containing(err, "tenant_id");
}

#[tokio::test]
async fn rule4_fails_closed_when_no_expected_tenant_is_configured() {
    let server = jwks_server().await;
    let url = url::Url::parse(&server.uri()).expect("valid base url");
    // Deliberately NOT calling `expect_tenant_id`.
    let verifier = JwksVerifier::new(reqwest::Client::new(), &url).expect("verifier constructs");

    // "There was nothing to compare against, so there was nothing to check"
    // is the SEC-080 defect — it must reject, not pass.
    let err = verifier
        .verify(&sign_eddsa(&good_claims()))
        .await
        .expect_err("an unconfigured verifier must fail closed");
    assert_auth_error_containing(err, "no expected tenant configured");
}

// -------------------------------------------------------------- rule 5: iss --

#[tokio::test]
async fn rule5_rejects_an_issuer_mismatch_when_configured() {
    let server = jwks_server().await;
    let verifier = guard_verifier(&server.uri()).expect_issuer(ISSUER);
    let mut claims = good_claims();
    claims["iss"] = json!("https://evil.example.com");

    let err = verifier
        .verify(&sign_eddsa(&claims))
        .await
        .expect_err("an issuer mismatch must be rejected");
    assert_auth_error_containing(err, "issuer");
}

#[tokio::test]
async fn rule5_does_not_check_iss_when_not_configured() {
    let server = jwks_server().await;
    let verifier = guard_verifier(&server.uri());
    let mut claims = good_claims();
    claims["iss"] = json!("https://anything.example.com");

    verifier
        .verify(&sign_eddsa(&claims))
        .await
        .expect("iss is not checked without an expectation");
}

// -------------------------------------------------------------- rule 6: aud --

#[tokio::test]
async fn rule6_rejects_an_audience_mismatch_when_configured() {
    let server = jwks_server().await;
    let verifier = guard_verifier(&server.uri()).expect_audience("axiam:user");
    let mut claims = good_claims();
    claims["aud"] = json!("axiam:m2m");

    let err = verifier
        .verify(&sign_eddsa(&claims))
        .await
        .expect_err("an audience mismatch must be rejected");
    assert_auth_error_containing(err, "audience");
}

#[tokio::test]
async fn rule6_rejects_a_missing_aud_when_configured() {
    let server = jwks_server().await;
    let verifier = guard_verifier(&server.uri()).expect_audience("axiam:user");
    let mut claims = good_claims();
    claims.as_object_mut().expect("object").remove("aud");

    let err = verifier
        .verify(&sign_eddsa(&claims))
        .await
        .expect_err("an absent aud must be rejected once an expectation is configured");
    assert_auth_error_containing(err, "aud");
}

#[tokio::test]
async fn rule6_does_not_check_aud_when_not_configured() {
    let server = jwks_server().await;
    let verifier = guard_verifier(&server.uri());
    let mut claims = good_claims();
    claims["aud"] = json!("axiam:m2m");

    verifier
        .verify(&sign_eddsa(&claims))
        .await
        .expect("aud is not checked without an expectation");
}

// ------------------------------------------------------- rule 7: clock skew --

#[tokio::test]
async fn rule7_exposes_a_named_bounded_sixty_second_skew() {
    assert_eq!(CLOCK_SKEW_LEEWAY_SECS, 60);
}

#[tokio::test]
async fn rule7_tolerates_an_exp_that_just_passed() {
    let server = jwks_server().await;
    let verifier = guard_verifier(&server.uri());
    let mut claims = good_claims();
    claims["exp"] = json!(now() - 5);

    verifier
        .verify(&sign_eddsa(&claims))
        .await
        .expect("a 5s-stale exp is inside the named 60s leeway");
}

// -------------------------------------------- the §10.1 raw escape hatch ---

#[tokio::test]
async fn signature_only_unchecked_skips_every_claim_rule_but_the_guard_does_not() {
    let server = jwks_server().await;
    let verifier = guard_verifier(&server.uri());

    let mut claims = good_claims();
    claims["tenant_id"] = json!(OTHER_TENANT);
    claims["exp"] = json!(now() - 3600);
    claims["nbf"] = json!(now() + 3600);
    let token = sign_eddsa(&claims);

    // The raw primitive is documented to check the signature and nothing else
    // — which is precisely why its name says `_unchecked`.
    let raw = verifier
        .verify_signature_only_unchecked(&token)
        .await
        .expect("signature-only verification succeeds");
    assert_eq!(raw.tenant_id, OTHER_TENANT);

    // ...and the same token is rejected by the documented guard entry point.
    verifier
        .verify(&token)
        .await
        .expect_err("the guard must reject what the raw primitive waves through");
}

#[tokio::test]
async fn signature_only_unchecked_still_rejects_a_bad_signature() {
    let server = jwks_server().await;
    let verifier = guard_verifier(&server.uri());

    let mut wrong_seed = TEST_ED25519_SEED;
    wrong_seed[0] ^= 0xFF;
    let mut wrong_der = ED25519_PKCS8_DER_PREFIX.to_vec();
    wrong_der.extend_from_slice(&wrong_seed);
    let mut header = Header::new(Algorithm::EdDSA);
    header.kid = Some(TEST_KID.to_string());
    let token = jsonwebtoken::encode(
        &header,
        &good_claims(),
        &EncodingKey::from_ed_der(&wrong_der),
    )
    .expect("encode token signed with the wrong key");

    verifier
        .verify_signature_only_unchecked(&token)
        .await
        .expect_err("a bad signature is rejected even by the raw primitive");
}

// ------------------------------------- rule 9: sender-constrained tokens --
//
// CONTRACT.md §10.1 rule 9 (contract 1.15, RFC 8705 §3). A token carrying
// `cnf` is not a bearer token and must not be accepted as one.
//
// The required set is three negatives and one positive, and the POSITIVE is
// the one that matters most: rule 9 must not turn into "every caller must
// present a certificate", which would break every deployment that does not
// use mTLS at all.

/// A real 43-character base64url `x5t#S256`, and a different one.
const THUMBPRINT: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
const OTHER_THUMBPRINT: &str = "bWluZS1ub3QteW91cnMtdGhpcy1pcy00My1jaGFyc18";

fn bound_claims(thumbprint: &str) -> Value {
    let mut claims = good_claims();
    claims["cnf"] = json!({ "x5t#S256": thumbprint });
    claims
}

/// The regression test that keeps rule 9 from becoming a certificate mandate.
#[tokio::test]
async fn an_unbound_token_is_accepted_with_or_without_a_certificate() {
    let server = jwks_server().await;
    let verifier = guard_verifier(&server.uri());
    let token = sign_eddsa(&good_claims());

    verifier
        .verify_sender_constrained(&token, None)
        .await
        .expect("an unbound token must still be accepted when no cert is presented");
    verifier
        .verify_sender_constrained(&token, Some(THUMBPRINT))
        .await
        .expect("an unbound token must still be accepted when a cert IS presented");
}

#[tokio::test]
async fn a_bound_token_is_accepted_with_its_own_certificate() {
    let server = jwks_server().await;
    let verifier = guard_verifier(&server.uri());
    let token = sign_eddsa(&bound_claims(THUMBPRINT));

    let claims = verifier
        .verify_sender_constrained(&token, Some(THUMBPRINT))
        .await
        .expect("the bound token's own certificate must be accepted");
    assert_eq!(
        claims.cnf.and_then(|c| c.x5t_s256),
        Some(THUMBPRINT.to_string()),
        "the cnf claim must survive decoding"
    );
}

#[tokio::test]
async fn a_bound_token_is_rejected_with_no_certificate() {
    let server = jwks_server().await;
    let verifier = guard_verifier(&server.uri());
    let token = sign_eddsa(&bound_claims(THUMBPRINT));

    let err = verifier
        .verify_sender_constrained(&token, None)
        .await
        .expect_err("a certificate-bound token with no certificate must be rejected");
    assert_auth_error_containing(err, "no client certificate was presented");
}

#[tokio::test]
async fn a_bound_token_is_rejected_with_a_different_certificate() {
    let server = jwks_server().await;
    let verifier = guard_verifier(&server.uri());
    let token = sign_eddsa(&bound_claims(THUMBPRINT));

    let err = verifier
        .verify_sender_constrained(&token, Some(OTHER_THUMBPRINT))
        .await
        .expect_err("a certificate-bound token used with another certificate must be rejected");
    assert_auth_error_containing(err, "bound to a different client certificate");
}

/// The subtle one. A `cnf` naming a confirmation method this SDK cannot check
/// — a DPoP `jkt`, say — is an *unverifiable constraint*, never *no
/// constraint*. Reading it the other way silently downgrades a
/// sender-constrained token to a bearer token the day a newer AXIAM issues a
/// confirmation this SDK predates.
#[tokio::test]
async fn a_cnf_naming_an_unimplemented_method_is_rejected_not_ignored() {
    let server = jwks_server().await;
    let verifier = guard_verifier(&server.uri());
    let mut claims = good_claims();
    claims["cnf"] = json!({ "jkt": "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I" });
    let token = sign_eddsa(&claims);

    for presented in [None, Some(THUMBPRINT)] {
        let err = verifier
            .verify_sender_constrained(&token, presented)
            .await
            .expect_err("an unverifiable confirmation must fail closed");
        assert_auth_error_containing(err, "cannot verify");
    }
}

/// `verify` is deliberately NOT a sender-constraining guard — it has no
/// transport to ask. Documented, and asserted here so the split cannot be
/// removed by accident: a resource server accepting bound tokens must call
/// `verify_sender_constrained`.
#[tokio::test]
async fn plain_verify_does_not_enforce_the_binding_and_says_so() {
    let server = jwks_server().await;
    let verifier = guard_verifier(&server.uri());
    let token = sign_eddsa(&bound_claims(THUMBPRINT));

    let claims = verifier
        .verify(&token)
        .await
        .expect("verify() checks rules 1-8, not rule 9");
    // ...but the claim is right there for a caller that wants to apply rule 9
    // itself, which is exactly what the standalone method is for.
    claims
        .verify_certificate_binding(Some(THUMBPRINT))
        .expect("the standalone rule-9 check accepts the right certificate");
    claims
        .verify_certificate_binding(None)
        .expect_err("...and rejects an absent one");
}

// ---------------------------------------------------------------------------
// §10.1 rule 9 extended for DPoP (contract 1.16)
// ---------------------------------------------------------------------------

const JKT: &str = "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I";
const OTHER_JKT: &str = "sBjflhaR2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

/// Claims carrying whatever `cnf` the caller wants.
fn claims_with_cnf(cnf: serde_json::Value) -> serde_json::Value {
    let mut claims = good_claims();
    claims["cnf"] = cnf;
    claims
}

/// **The positive regression test**, and the one this whole change is most
/// likely to break: an unbound token must still verify with **no certificate
/// and no proof**. The likeliest wrong implementation of rule 9 is one that
/// starts demanding evidence from every caller.
#[tokio::test]
async fn an_unbound_token_is_accepted_with_no_proofs_at_all() {
    let server = jwks_server().await;
    let verifier = guard_verifier(&server.uri());
    let token = sign_eddsa(&good_claims());

    let claims = verifier.verify(&token).await.unwrap();
    claims
        .verify_token_binding(PresentedProofs::default())
        .expect("an unbound token needs no proofs");
    claims
        .verify_token_binding(PresentedProofs {
            certificate_thumbprint: Some(THUMBPRINT),
            dpop_thumbprint: Some(JKT),
        })
        .expect("...and is not made invalid by proofs it never asked for");
}

#[tokio::test]
async fn a_dpop_bound_token_accepts_the_matching_key() {
    let server = jwks_server().await;
    let verifier = guard_verifier(&server.uri());
    let token = sign_eddsa(&claims_with_cnf(json!({ "jkt": JKT })));

    let claims = verifier.verify(&token).await.unwrap();
    claims
        .verify_token_binding(PresentedProofs {
            certificate_thumbprint: None,
            dpop_thumbprint: Some(JKT),
        })
        .expect("the proof names the confirmed key");
}

#[tokio::test]
async fn a_dpop_bound_token_is_rejected_without_a_proof_or_with_the_wrong_key() {
    let server = jwks_server().await;
    let verifier = guard_verifier(&server.uri());
    let token = sign_eddsa(&claims_with_cnf(json!({ "jkt": JKT })));
    let claims = verifier.verify(&token).await.unwrap();

    let err = claims
        .verify_token_binding(PresentedProofs::default())
        .expect_err("no proof means no possession");
    assert_auth_error_containing(err, "no verified DPoP proof");

    let err = claims
        .verify_token_binding(PresentedProofs {
            certificate_thumbprint: None,
            dpop_thumbprint: Some(OTHER_JKT),
        })
        .expect_err("another key's proof is not this token's");
    assert_auth_error_containing(err, "different DPoP key");
}

/// **A `cnf` naming both methods is a conjunction.** An operator who turned on
/// two constraints asked for two; satisfying the more convenient one is not
/// compliance. This is the rule most likely to be implemented as "check
/// whichever we can", which is why each half is asserted to fail alone.
#[tokio::test]
async fn a_cnf_naming_both_methods_requires_both() {
    let server = jwks_server().await;
    let verifier = guard_verifier(&server.uri());
    let token = sign_eddsa(&claims_with_cnf(
        json!({ "x5t#S256": THUMBPRINT, "jkt": JKT }),
    ));
    let claims = verifier.verify(&token).await.unwrap();

    claims
        .verify_token_binding(PresentedProofs {
            certificate_thumbprint: Some(THUMBPRINT),
            dpop_thumbprint: Some(JKT),
        })
        .expect("both proofs present and correct");

    claims
        .verify_token_binding(PresentedProofs {
            certificate_thumbprint: Some(THUMBPRINT),
            dpop_thumbprint: None,
        })
        .expect_err("the certificate alone is not enough");

    claims
        .verify_token_binding(PresentedProofs {
            certificate_thumbprint: None,
            dpop_thumbprint: Some(JKT),
        })
        .expect_err("the proof alone is not enough");
}

/// An **empty** `cnf` names nothing checkable and must be refused, not read as
/// unbound. Over gRPC this is also how proto3 delivers an empty `CnfClaim`
/// message, which is why §10.3 rule 3 spells it out separately.
#[tokio::test]
async fn an_empty_cnf_is_refused_rather_than_read_as_unbound() {
    let server = jwks_server().await;
    let verifier = guard_verifier(&server.uri());
    let token = sign_eddsa(&claims_with_cnf(json!({})));
    let claims = verifier.verify(&token).await.unwrap();

    let err = claims
        .verify_token_binding(PresentedProofs::default())
        .expect_err("an empty confirmation is unverifiable, not absent");
    assert_auth_error_containing(err, "no method this SDK can verify");
}

/// The narrow entry point keeps working for certificates, and **refuses** a
/// DPoP-bound token rather than ignoring the `jkt` it cannot check. That
/// refusal is the whole reason it can stay in the API without becoming a
/// downgrade path.
#[tokio::test]
async fn the_certificate_only_entry_point_refuses_a_dpop_bound_token() {
    let server = jwks_server().await;
    let verifier = guard_verifier(&server.uri());
    let token = sign_eddsa(&claims_with_cnf(json!({ "jkt": JKT })));
    let claims = verifier.verify(&token).await.unwrap();

    for presented in [None, Some(THUMBPRINT)] {
        claims
            .verify_certificate_binding(presented)
            .expect_err("a certificate-only check must not answer for a DPoP binding");
    }
}

/// ...and it refuses a both-bound token too, for the same reason: it can
/// establish one half and must not answer for the whole.
#[tokio::test]
async fn the_certificate_only_entry_point_refuses_a_both_bound_token() {
    let server = jwks_server().await;
    let verifier = guard_verifier(&server.uri());
    let token = sign_eddsa(&claims_with_cnf(
        json!({ "x5t#S256": THUMBPRINT, "jkt": JKT }),
    ));
    let claims = verifier.verify(&token).await.unwrap();

    let err = claims
        .verify_certificate_binding(Some(THUMBPRINT))
        .expect_err("the certificate half alone does not satisfy a conjunction");
    assert_auth_error_containing(err, "both must hold");
}

/// The thumbprint helper must produce RFC 7515 §2 base64url: unpadded, and
/// using `-`/`_` rather than `+`/`/`. A padded or standard-base64 value will
/// not compare equal to what AXIAM put in the token.
#[test]
fn thumbprint_helper_produces_unpadded_base64url() {
    let der = vec![0x42u8; 512];
    let tp = axiam_sdk::token::certificate_thumbprint_s256(&der);
    assert_eq!(tp.len(), 43, "SHA-256 in unpadded base64url is 43 chars");
    assert!(!tp.contains('='), "must not be padded");
    assert!(!tp.contains('+') && !tp.contains('/'), "must be base64URL");
    assert_eq!(tp, axiam_sdk::token::certificate_thumbprint_s256(&der));
}
