//! CONTRACT.md §21.7.2 — DPoP proof verification, all ten checks.
//!
//! Each check gets a negative test, because §21.7.2's whole premise is that a
//! verifier missing one of them still reports success. A suite that only
//! proved a good proof passes would not distinguish this module from
//! `Ok(thumbprint)`.

#![cfg(any(feature = "rest", feature = "actix"))]

use axiam_sdk::token::{
    DPOP_IAT_LEEWAY_SECS, DpopRequest, InMemoryJtiStore, JtiStore, access_token_hash,
    canonical_htu, jwk_thumbprint_s256, verify_dpop_proof,
};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::json;
use std::time::{SystemTime, UNIX_EPOCH};

const METHOD: &str = "POST";
const URI: &str = "https://rs.example.com/v1/things";
const TOKEN: &str = "eyJhbGciOiJFZERTQSJ9.e30.sig";

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

struct Key {
    signing: SigningKey,
    jwk: serde_json::Value,
}

fn ed25519_key(seed: u8) -> Key {
    let signing = SigningKey::from_bytes(&[seed; 32]);
    let jwk = json!({
        "kty": "OKP",
        "crv": "Ed25519",
        "x": URL_SAFE_NO_PAD.encode(signing.verifying_key().to_bytes()),
    });
    Key { signing, jwk }
}

/// Builds a proof by hand rather than through a JWT library, so a test can put
/// anything at all in the header — including the private material and bogus
/// `alg` values a cooperative library would refuse to emit.
fn sign_proof(key: &SigningKey, header: &serde_json::Value, claims: &serde_json::Value) -> String {
    let h = URL_SAFE_NO_PAD.encode(serde_json::to_vec(header).unwrap());
    let c = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).unwrap());
    let signing_input = format!("{h}.{c}");
    let sig = key.sign(signing_input.as_bytes());
    format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(sig.to_bytes()))
}

fn claims_with(overrides: serde_json::Value) -> serde_json::Value {
    let mut base = json!({
        "htm": METHOD,
        "htu": URI,
        "iat": now(),
        "jti": format!("jti-{}", uuid_like()),
        "ath": access_token_hash(TOKEN),
    });
    let map = base.as_object_mut().unwrap();
    for (k, v) in overrides.as_object().unwrap() {
        if v.is_null() {
            map.remove(k);
        } else {
            map.insert(k.clone(), v.clone());
        }
    }
    base
}

/// A unique-enough jti without pulling `uuid` into dev-dependencies.
fn uuid_like() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    format!("{}-{}", now(), N.fetch_add(1, Ordering::Relaxed))
}

fn good_proof(key: &Key) -> String {
    sign_proof(
        &key.signing,
        &json!({"typ": "dpop+jwt", "alg": "EdDSA", "jwk": key.jwk}),
        &claims_with(json!({})),
    )
}

fn request<'a>() -> DpopRequest<'a> {
    DpopRequest::new(METHOD, URI, TOKEN)
}

// ---------------------------------------------------------------------------
// The happy path
// ---------------------------------------------------------------------------

#[test]
fn a_well_formed_proof_verifies_and_returns_its_thumbprint() {
    let key = ed25519_key(1);
    let store = InMemoryJtiStore::new();
    let jkt = verify_dpop_proof(&good_proof(&key), &request(), &store).expect("should verify");
    // Returning the thumbprint rather than () is what lets a guard pass a
    // value onward that could only have come from a verified proof.
    assert_eq!(jkt, jwk_thumbprint_s256(&key.jwk).unwrap());
    assert_eq!(jkt.len(), 43);
}

#[test]
fn query_and_fragment_are_stripped_from_both_sides_of_htu() {
    let key = ed25519_key(2);
    let store = InMemoryJtiStore::new();
    let uri = format!("{URI}?page=2#frag");
    let mut req = request();
    req.http_uri = &uri;
    verify_dpop_proof(&good_proof(&key), &req, &store).expect("query string must not matter");
}

// ---------------------------------------------------------------------------
// One negative test per check
// ---------------------------------------------------------------------------

/// Without pinning `typ`, any other JWT signed by the same key — an access
/// token, an ID token — is replayable as a proof.
#[test]
fn check1_a_proof_without_the_dpop_typ_is_refused() {
    let key = ed25519_key(3);
    let store = InMemoryJtiStore::new();
    let proof = sign_proof(
        &key.signing,
        &json!({"typ": "JWT", "alg": "EdDSA", "jwk": key.jwk}),
        &claims_with(json!({})),
    );
    let err = verify_dpop_proof(&proof, &request(), &store).unwrap_err();
    assert!(err.to_string().contains("typ"), "got: {err}");
}

#[test]
fn check1_the_typ_comparison_is_case_insensitive() {
    let key = ed25519_key(4);
    let store = InMemoryJtiStore::new();
    let proof = sign_proof(
        &key.signing,
        &json!({"typ": "DPoP+JWT", "alg": "EdDSA", "jwk": key.jwk}),
        &claims_with(json!({})),
    );
    verify_dpop_proof(&proof, &request(), &store).expect("typ is case-insensitive");
}

/// **The attack check 2 exists for**, run for real.
///
/// The attacker holds no private key. They take the *public* key out of a
/// proof they observed, use its raw bytes as an HMAC secret, sign a proof of
/// their own with `HS256`, and embed the same public `jwk`. A verifier that
/// reads `alg` from the header computes HMAC with that public key, gets a
/// match, and reports success — the signature is valid, just not proof of
/// anything.
///
/// Here the verification algorithm is derived from `kty: OKP` before the
/// decoder is ever called, so HMAC is never a candidate.
#[test]
fn check2_the_public_key_as_hmac_secret_forgery_is_refused() {
    use hmac::{Hmac, KeyInit, Mac};
    use sha2::Sha256;

    let key = ed25519_key(5);
    let store = InMemoryJtiStore::new();

    let public_bytes = key.signing.verifying_key().to_bytes();
    let header = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&json!({"typ": "dpop+jwt", "alg": "HS256", "jwk": key.jwk})).unwrap(),
    );
    let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims_with(json!({}))).unwrap());
    let signing_input = format!("{header}.{payload}");

    let mut mac = Hmac::<Sha256>::new_from_slice(&public_bytes).unwrap();
    mac.update(signing_input.as_bytes());
    let forged = format!(
        "{signing_input}.{}",
        URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    );

    let err = verify_dpop_proof(&forged, &request(), &store).unwrap_err();
    assert!(
        err.to_string().contains("signature or claims")
            || err.to_string().contains("not permitted"),
        "the HMAC forgery was not refused: {err}"
    );
}

/// A cross-SDK divergence worth recording rather than papering over.
///
/// The contract requires the algorithm be *taken from the embedded `jwk`, not
/// believed from the header*. This SDK satisfies that — the algorithm is
/// derived from `kty`/`crv` before decoding — but `jsonwebtoken` additionally
/// refuses a header whose `alg` disagrees with the allowlist it was given. So
/// where the Python and TypeScript SDKs ignore a lying `alg` header outright
/// and verify anyway, this one rejects the proof.
///
/// Both satisfy check 2: neither ever lets the header choose the algorithm.
/// This is strictly the stricter of the two, and the test exists so the
/// difference is a recorded decision rather than a surprise to the next reader
/// comparing the SDKs.
#[test]
fn check2_a_disagreeing_alg_header_is_refused_by_this_sdk() {
    let key = ed25519_key(21);
    let store = InMemoryJtiStore::new();
    let proof = sign_proof(
        &key.signing,
        &json!({"typ": "dpop+jwt", "alg": "ES256", "jwk": key.jwk}),
        &claims_with(json!({})),
    );
    let err = verify_dpop_proof(&proof, &request(), &store).unwrap_err();
    assert!(
        err.to_string().contains("signature or claims"),
        "got: {err}"
    );
}

#[test]
fn check2_an_unpermitted_key_type_is_refused() {
    let key = ed25519_key(6);
    let store = InMemoryJtiStore::new();
    let proof = sign_proof(
        &key.signing,
        &json!({"typ": "dpop+jwt", "jwk": {"kty": "EC", "crv": "P-521", "x": "AA", "y": "AA"}}),
        &claims_with(json!({})),
    );
    let err = verify_dpop_proof(&proof, &request(), &store).unwrap_err();
    assert!(err.to_string().contains("not permitted"), "got: {err}");
}

#[test]
fn check3_a_proof_with_no_jwk_or_a_foreign_signature_is_refused() {
    let key = ed25519_key(7);
    let store = InMemoryJtiStore::new();

    let no_jwk = sign_proof(
        &key.signing,
        &json!({"typ": "dpop+jwt", "alg": "EdDSA"}),
        &claims_with(json!({})),
    );
    let err = verify_dpop_proof(&no_jwk, &request(), &store).unwrap_err();
    assert!(err.to_string().contains("public 'jwk'"), "got: {err}");

    // Signed by a DIFFERENT key than the one it embeds.
    let other = ed25519_key(8);
    let forged = sign_proof(
        &other.signing,
        &json!({"typ": "dpop+jwt", "alg": "EdDSA", "jwk": key.jwk}),
        &claims_with(json!({})),
    );
    let err = verify_dpop_proof(&forged, &request(), &store).unwrap_err();
    assert!(
        err.to_string().contains("signature or claims"),
        "got: {err}"
    );
}

/// RFC 9449 §4.3. Checked against the RAW header JSON, because many JWK
/// libraries silently drop these members when parsing into a public-key type
/// — the check would then pass because the library hid the evidence.
#[test]
fn check4_private_key_material_in_the_jwk_is_refused() {
    let key = ed25519_key(9);
    let store = InMemoryJtiStore::new();
    for member in ["d", "p", "q", "dp", "dq", "qi", "oth", "k"] {
        let mut leaky = key.jwk.clone();
        leaky[member] = json!("c2VjcmV0");
        let proof = sign_proof(
            &key.signing,
            &json!({"typ": "dpop+jwt", "alg": "EdDSA", "jwk": leaky}),
            &claims_with(json!({})),
        );
        let err = verify_dpop_proof(&proof, &request(), &store).unwrap_err();
        assert!(
            err.to_string().contains("private key material"),
            "member {member} was not caught: {err}"
        );
    }
}

#[test]
fn check5_a_proof_minted_for_another_method_is_refused() {
    let key = ed25519_key(10);
    let store = InMemoryJtiStore::new();
    let proof = sign_proof(
        &key.signing,
        &json!({"typ": "dpop+jwt", "alg": "EdDSA", "jwk": key.jwk}),
        &claims_with(json!({"htm": "GET"})),
    );
    let err = verify_dpop_proof(&proof, &request(), &store).unwrap_err();
    assert!(err.to_string().contains("htm"), "got: {err}");
}

#[test]
fn check6_a_proof_minted_for_another_uri_is_refused() {
    let key = ed25519_key(11);
    let store = InMemoryJtiStore::new();
    let proof = sign_proof(
        &key.signing,
        &json!({"typ": "dpop+jwt", "alg": "EdDSA", "jwk": key.jwk}),
        &claims_with(json!({"htu": "https://rs.example.com/v1/other"})),
    );
    let err = verify_dpop_proof(&proof, &request(), &store).unwrap_err();
    assert!(err.to_string().contains("htu"), "got: {err}");
}

/// A normalising comparison is where two unequal URIs become equal. Only query
/// and fragment come off; case, default ports and trailing slashes are left
/// exactly as they are.
#[test]
fn check6_htu_is_compared_without_normalisation() {
    assert_eq!(
        canonical_htu("https://a.example/p?q=1#f"),
        "https://a.example/p"
    );
    assert_ne!(
        canonical_htu("https://A.example/P"),
        canonical_htu("https://a.example/p")
    );
    assert_ne!(
        canonical_htu("https://a.example:443/p"),
        canonical_htu("https://a.example/p")
    );
    assert_ne!(
        canonical_htu("https://a.example/p/"),
        canonical_htu("https://a.example/p")
    );
}

/// Both directions. A proof from the future is as suspect as a stale one: it
/// is how a one-sided skew allowance becomes a long-lived proof.
#[test]
fn check7_a_stale_or_future_proof_is_refused() {
    let key = ed25519_key(12);
    let store = InMemoryJtiStore::new();
    let base = now();

    for iat in [
        base - DPOP_IAT_LEEWAY_SECS - 5,
        base + DPOP_IAT_LEEWAY_SECS + 5,
    ] {
        let proof = sign_proof(
            &key.signing,
            &json!({"typ": "dpop+jwt", "alg": "EdDSA", "jwk": key.jwk}),
            &claims_with(json!({"iat": iat})),
        );
        let mut req = request();
        req.now_unix = Some(base);
        let err = verify_dpop_proof(&proof, &req, &store).unwrap_err();
        assert!(
            err.to_string().contains("freshness window"),
            "iat {iat} accepted: {err}"
        );
    }
}

/// Freshness bounds the window; the `jti` guard is what makes the window
/// unusable. Without this the same proof works repeatedly for a full minute.
#[test]
fn check8_a_replayed_proof_is_refused() {
    let key = ed25519_key(13);
    let store = InMemoryJtiStore::new();
    let proof = good_proof(&key);
    verify_dpop_proof(&proof, &request(), &store).expect("first use");
    let err = verify_dpop_proof(&proof, &request(), &store).unwrap_err();
    assert!(err.to_string().contains("replay"), "got: {err}");
}

/// The `jti` claim is a mutation, so it runs last. Claiming it earlier would
/// let an attacker burn arbitrary `jti` values out of the store using proofs
/// that were never going to verify — turning the replay guard into a
/// denial-of-service surface against legitimate proofs.
#[test]
fn check8_the_jti_is_only_claimed_after_the_other_checks_pass() {
    let key = ed25519_key(14);
    let store = InMemoryJtiStore::new();
    let proof = sign_proof(
        &key.signing,
        &json!({"typ": "dpop+jwt", "alg": "EdDSA", "jwk": key.jwk}),
        &claims_with(json!({"htm": "GET", "jti": "precious"})),
    );
    let err = verify_dpop_proof(&proof, &request(), &store).unwrap_err();
    assert!(err.to_string().contains("htm"), "got: {err}");

    // That jti is still unused, so a genuine proof carrying it still works.
    assert!(
        store.claim("precious", now() + 60),
        "a failed proof must not burn its jti"
    );
}

/// Without `ath`, a proof captured on one request can be re-aimed at a
/// different token held by the same key.
#[test]
fn check9_a_proof_aimed_at_another_token_is_refused() {
    let key = ed25519_key(15);
    let store = InMemoryJtiStore::new();
    let proof = sign_proof(
        &key.signing,
        &json!({"typ": "dpop+jwt", "alg": "EdDSA", "jwk": key.jwk}),
        &claims_with(json!({"ath": access_token_hash("some.other.token")})),
    );
    let err = verify_dpop_proof(&proof, &request(), &store).unwrap_err();
    assert!(err.to_string().contains("ath"), "got: {err}");
}

#[test]
fn check9_a_proof_with_no_ath_at_all_is_refused() {
    let key = ed25519_key(16);
    let store = InMemoryJtiStore::new();
    let proof = sign_proof(
        &key.signing,
        &json!({"typ": "dpop+jwt", "alg": "EdDSA", "jwk": key.jwk}),
        &claims_with(json!({"ath": null})),
    );
    let err = verify_dpop_proof(&proof, &request(), &store).unwrap_err();
    assert!(err.to_string().contains("ath"), "got: {err}");
}

/// This is the step that ties the proof to the token; the other nine are what
/// make the proof mean anything.
#[test]
fn check10_a_proof_by_the_wrong_key_is_refused() {
    let key = ed25519_key(17);
    let other = ed25519_key(18);
    let store = InMemoryJtiStore::new();
    let expected = jwk_thumbprint_s256(&other.jwk).unwrap();
    let req = request().with_expected_jkt(&expected);
    let err = verify_dpop_proof(&good_proof(&key), &req, &store).unwrap_err();
    assert!(err.to_string().contains("cnf.jkt"), "got: {err}");
}

// ---------------------------------------------------------------------------
// Thumbprint and framing
// ---------------------------------------------------------------------------

/// The RFC's own worked example. A thumbprint implementation that is
/// self-consistent but wrong agrees with itself on every round trip, so the
/// only useful test is against a published vector.
#[test]
fn the_thumbprint_matches_rfc7638_appendix_a() {
    let rfc_key = json!({
        "kty": "RSA",
        "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAt\
              VT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn6\
              4tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FD\
              W2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n9\
              1CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINH\
              aQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
        "e": "AQAB",
    });
    assert_eq!(
        jwk_thumbprint_s256(&rfc_key).unwrap(),
        "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
    );
}

/// `kid`/`use`/`alg`/`x5c` are excluded by the spec — which is exactly what
/// makes the thumbprint stable across two different encodings of the same key.
#[test]
fn the_thumbprint_ignores_members_outside_the_rfc7638_set() {
    let key = ed25519_key(19);
    let mut decorated = key.jwk.clone();
    decorated["kid"] = json!("abc");
    decorated["use"] = json!("sig");
    decorated["alg"] = json!("EdDSA");
    decorated["x5c"] = json!(["zz"]);
    assert_eq!(
        jwk_thumbprint_s256(&decorated).unwrap(),
        jwk_thumbprint_s256(&key.jwk).unwrap()
    );
}

/// RFC 9449 §4.2 makes exactly one the rule. Rejecting beats picking the
/// first, which is how a verifier and a downstream parser end up reading
/// different proofs.
#[test]
fn a_header_carrying_two_proofs_is_refused() {
    let key = ed25519_key(20);
    let store = InMemoryJtiStore::new();
    let proof = good_proof(&key);
    let doubled = format!("{proof},{proof}");
    let err = verify_dpop_proof(&doubled, &request(), &store).unwrap_err();
    assert!(err.to_string().contains("exactly one proof"), "got: {err}");
}

#[test]
fn a_malformed_proof_is_refused_rather_than_panicking() {
    let store = InMemoryJtiStore::new();
    for junk in ["", "not-a-jwt", "a.b", "a.b.c.d", "!!!.###.$$$"] {
        assert!(
            verify_dpop_proof(junk, &request(), &store).is_err(),
            "accepted {junk:?}"
        );
    }
}
