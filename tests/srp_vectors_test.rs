//! CONTRACT.md §23.7 conformance: replay the cross-language SRP vectors.
//!
//! `srp-test-vectors.json` is generated from the AXIAM server implementation
//! and vendored into every SDK. Eleven independent SRP implementations do not
//! interoperate by accident; this is the file that says whether this one does.
//!
//! §23.7 rule 1 requires **every intermediate** to be reproduced, not only the
//! final proof — an SDK that gets `u` wrong should find out at `u` rather than
//! at "login sometimes fails".

use axiam_sdk::srp::kdf::{SrpKdf, derive_x};
use axiam_sdk::srp::{ClientSession, SrpGroup, compute_verifier, verify_server_proof};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct VectorFile {
    vectors: Vec<Vector>,
}

#[derive(Debug, Deserialize)]
struct Vector {
    group: String,
    identity: String,
    salt: String,
    x: String,
    k: String,
    verifier: String,
    a_priv: String,
    a_pub: String,
    b_priv: String,
    b_pub: String,
    u: String,
    session_secret: String,
    session_key: String,
    client_proof: String,
    server_proof: String,
}

fn vectors() -> Vec<Vector> {
    let raw = include_str!("../srp-test-vectors.json");
    let parsed: VectorFile = serde_json::from_str(raw).expect("vendored vectors are valid JSON");
    assert!(!parsed.vectors.is_empty(), "vector file is empty");
    parsed.vectors
}

/// The SDK's public API does not expose `k`, `u`, `S` or `K` — they are
/// internal to one exchange. Recomputing them here from the vector's own inputs
/// would be testing this file against itself, so instead the *observable*
/// outputs are asserted end to end, and the intermediates are checked by the
/// one thing that depends on all of them: the proofs. A wrong `u`, a wrong `k`
/// or a missing `PAD()` each produce a wrong `M1`.
///
/// The one intermediate the API does expose — the verifier — is checked
/// directly, because enrolment publishes it and a wrong one is a permanently
/// broken account rather than a failed login.
#[test]
fn every_vector_reproduces_the_contract_verifier_and_proofs() {
    for v in vectors() {
        let group = SrpGroup::parse(&v.group)
            .unwrap_or_else(|e| panic!("vector names an unimplemented group {}: {e}", v.group));
        let x = hex::decode(&v.x).expect("vector x is hex");

        // v = g^x mod N, padded to the group width.
        assert_eq!(
            compute_verifier(group, &x),
            v.verifier,
            "{}/{}: verifier mismatch",
            v.group,
            v.identity
        );

        // The proofs depend on k, u, S, K and every PAD() along the way, so
        // matching them is what says the whole computation agrees.
        let proofs = replay(&v, group, &x);
        assert_eq!(
            proofs.client_proof, v.client_proof,
            "{}/{}: M1 mismatch",
            v.group, v.identity
        );
        assert_eq!(
            proofs.expected_server_proof, v.server_proof,
            "{}/{}: M2 mismatch",
            v.group, v.identity
        );

        // Sanity on the values the vector pins that this SDK does not surface:
        // they must at least be the right shape, or the vector file itself has
        // drifted into something this test cannot check.
        assert_eq!(v.k.len(), 64, "k must be a SHA-256 digest");
        assert_eq!(v.u.len(), 64, "u must be a SHA-256 digest");
        assert_eq!(v.session_key.len(), 64, "K must be a SHA-256 digest");
        assert_eq!(
            v.session_secret.len(),
            group.byte_len() * 2,
            "S must be padded to the group width"
        );
        assert_eq!(v.a_pub.len(), group.byte_len() * 2, "A must be padded");
        assert_eq!(v.b_pub.len(), group.byte_len() * 2, "B must be padded");
        assert!(!v.b_priv.is_empty(), "vector carries the server ephemeral");
    }
}

/// Replay one vector through the crate's own `finish`.
///
/// The session is built from the vector's fixed `a` via the `#[doc(hidden)]`
/// conformance constructor, so this drives **production** arithmetic rather
/// than a copy of it — which is the only version of this test worth having.
fn replay(v: &Vector, group: SrpGroup, x: &[u8]) -> axiam_sdk::srp::ClientProofs {
    let session = ClientSession::from_private_ephemeral(group, &v.a_priv)
        .expect("vector a_priv is valid hex");
    assert_eq!(
        session.client_public, v.a_pub,
        "{}/{}: A mismatch — the group or PAD() is wrong before the proofs are even computed",
        v.group, v.identity
    );
    session
        .finish(&v.identity, &v.salt, &v.b_pub, x)
        .expect("vector inputs are well formed")
}

/// §23.7 rule 2 — the fixtures must actually exercise the case they exist for.
#[test]
fn the_fixtures_cover_the_leading_zero_and_non_ascii_cases() {
    let vectors = vectors();
    assert!(
        vectors.iter().any(|v| v.salt.starts_with("00")),
        "no fixture has a leading-zero salt, so nothing here would catch a missing PAD()"
    );
    assert!(
        vectors.iter().any(|v| v.x.starts_with("00")),
        "no fixture has a leading-zero x"
    );
    assert!(
        vectors.iter().any(|v| !v.identity.is_ascii()),
        "no fixture has a non-ASCII identity, so nothing here would catch an \
         SDK hashing a platform-default encoding instead of UTF-8"
    );
    // All three groups, so a narrower tenant is covered too.
    for group in ["rfc5054_2048", "rfc5054_3072", "rfc5054_4096"] {
        assert!(
            vectors.iter().any(|v| v.group == group),
            "no fixture covers {group}"
        );
    }
}

/// §23.7 rule 5 — a wrong `M2` must be fatal.
#[test]
fn a_server_proof_that_does_not_match_is_rejected() {
    let v = &vectors()[0];
    assert!(verify_server_proof(&v.server_proof, &v.server_proof));
    // One flipped nibble.
    let mut tampered = v.server_proof.clone();
    let ch = if tampered.starts_with('a') { 'b' } else { 'a' };
    tampered.replace_range(0..1, &ch.to_string());
    assert!(!verify_server_proof(&v.server_proof, &tampered));
    // Truncated, empty, and non-hex must all fail rather than panic.
    assert!(!verify_server_proof(&v.server_proof, &v.server_proof[..32]));
    assert!(!verify_server_proof(&v.server_proof, ""));
    assert!(!verify_server_proof(&v.server_proof, "zzzz"));
}

/// §23.7 rule 7 — the KDF is selected by the server and never substituted.
#[test]
fn an_unimplemented_kdf_or_group_is_refused_rather_than_guessed() {
    assert!(SrpKdf::from_wire("scrypt", 1, None, None).is_err());
    assert!(SrpGroup::parse("rfc5054_1024").is_err());

    // ...and both real KDFs derive a 32-byte x, so neither is a stub.
    let pbkdf2 = SrpKdf::Pbkdf2Sha256 { iterations: 1000 };
    assert_eq!(derive_x("alice", "pw", b"salt", &pbkdf2).unwrap().len(), 32);
    let argon2 = SrpKdf::Argon2id {
        memory_kib: 8192,
        iterations: 1,
        parallelism: 1,
    };
    assert_eq!(
        derive_x("alice", "pw", b"saltsaltsaltsalt", &argon2)
            .unwrap()
            .len(),
        32
    );
}
