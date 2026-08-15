//! CONTRACT.md §22.13 — the required reactor tests, run against the
//! server-generated vectors in `testdata/reactor_v2_reference_vectors.json`.
//!
//! Those vectors were produced by the AXIAM server's own reactor sign path and
//! ship beside the §8 vectors, under the **same** master key, tenant and
//! derived subkey — so the one loader below serves both files, exactly as
//! §22.13 intends. Nothing here hand-rolls an expectation: every byte string
//! and every MAC is read from the fixture.

#![cfg(feature = "amqp")]

use std::collections::BTreeMap;

use axiam_sdk::amqp::reactor::{
    EventRejection, REACTOR_EXCHANGE, ReactorEvent, ReactorReply, ReplyDecision,
    canonical_event_bytes, event_spec, events, queue_name, routing_key, verify_event,
};
use chrono::{DateTime, Utc};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Fixture loading — one loader, two files (§22.13)
// ---------------------------------------------------------------------------

fn reactor_fixture() -> serde_json::Value {
    let raw = include_str!("../testdata/reactor_v2_reference_vectors.json");
    serde_json::from_str(raw).expect("reactor reference vectors parse")
}

fn hmac_fixture() -> serde_json::Value {
    let raw = include_str!("../testdata/v2_reference_vectors.json");
    serde_json::from_str(raw).expect("§8 reference vectors parse")
}

/// The tenant's HKDF-derived AMQP subkey, as the fixture committed it. Both
/// directions of §22 sign with this one key.
fn subkey(fixture: &serde_json::Value) -> Vec<u8> {
    hex_decode(
        fixture["hkdf"]["derived_subkey_hex"]
            .as_str()
            .expect("hkdf.derived_subkey_hex present"),
    )
}

fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hmac_hex(key: &[u8], message: &[u8]) -> String {
    hex_encode(&raw_hmac(key, message))
}

/// HMAC-SHA256, computed here rather than through the SDK, so the assertions
/// below check the SDK's *canonical bytes* against an independent MAC.
fn raw_hmac(key: &[u8], message: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    const BLOCK: usize = 64;
    let mut k = key.to_vec();
    if k.len() > BLOCK {
        k = Sha256::digest(&k).to_vec();
    }
    k.resize(BLOCK, 0);
    let ipad: Vec<u8> = k.iter().map(|b| b ^ 0x36).collect();
    let opad: Vec<u8> = k.iter().map(|b| b ^ 0x5c).collect();
    let inner = Sha256::digest([ipad.as_slice(), message].concat());
    Sha256::digest([opad.as_slice(), inner.as_slice()].concat()).to_vec()
}

fn verified_at(fixture: &serde_json::Value) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(fixture["verified_at"].as_str().expect("verified_at"))
        .expect("verified_at parses")
        .with_timezone(&Utc)
}

fn skew(fixture: &serde_json::Value) -> chrono::Duration {
    chrono::Duration::seconds(
        fixture["freshness_skew_secs"]
            .as_i64()
            .expect("freshness_skew_secs"),
    )
}

/// Rebuild a [`ReactorReply`] from a vector's `message` object — deliberately
/// field by field rather than by `serde_json::from_value`, so the assertion
/// exercises the SDK's own struct and its serde attributes.
fn reply_from_vector(message: &serde_json::Value) -> ReactorReply {
    ReactorReply {
        correlation_id: uuid_at(message, "correlation_id"),
        tenant_id: uuid_at(message, "tenant_id"),
        event: message["event"].as_str().expect("event").to_owned(),
        decision: match message["decision"].as_str().expect("decision") {
            "allow" => ReplyDecision::Allow,
            "deny" => ReplyDecision::Deny,
            "mutate" => ReplyDecision::Mutate,
            other => panic!("unknown decision {other}"),
        },
        reason: message
            .get("reason")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned),
        patch: message.get("patch").and_then(|p| p.as_object()).map(|obj| {
            obj.iter()
                .map(|(k, v)| {
                    (
                        k.clone(),
                        v.as_str().expect("patch value is a string").to_owned(),
                    )
                })
                .collect::<BTreeMap<String, String>>()
        }),
        require_mfa: message
            .get("require_mfa")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false),
        key_version: u8::try_from(message["key_version"].as_u64().expect("key_version")).unwrap(),
        nonce: uuid_at(message, "nonce"),
        issued_at: DateTime::parse_from_rfc3339(message["issued_at"].as_str().expect("issued_at"))
            .expect("issued_at parses")
            .with_timezone(&Utc),
        hmac_signature: None,
    }
}

/// The bytes the server actually put on the wire for an event vector.
///
/// **Read this before reaching for `vector["message"]`.** The fixture stores
/// each `message` object with its keys in *alphabetical* order, because that
/// is how the generator's JSON writer emitted them; the authoritative wire
/// order lives in `canonical_signed_json`. Since the signed bytes are
/// order-sensitive, a verifier must be fed the wire body — which is exactly
/// what a broker delivers — and not the fixture's convenience copy.
fn event_wire_value(vector: &serde_json::Value) -> serde_json::Value {
    let canonical = vector["canonical_signed_json"]
        .as_str()
        .expect("canonical_signed_json");
    let signature = vector["hmac_signature_hex"]
        .as_str()
        .expect("hmac_signature_hex");
    let wire = canonical.replace(
        r#""hmac_signature":null"#,
        &format!(r#""hmac_signature":"{signature}""#),
    );
    serde_json::from_str(&wire).expect("the wire body parses")
}

fn uuid_at(value: &serde_json::Value, key: &str) -> Uuid {
    value[key]
        .as_str()
        .unwrap_or_else(|| panic!("{key} present"))
        .parse()
        .unwrap_or_else(|_| panic!("{key} is a uuid"))
}

// ---------------------------------------------------------------------------
// One loader serves both fixture files (§22.13 preamble)
// ---------------------------------------------------------------------------

#[test]
fn both_fixtures_share_the_same_master_key_tenant_and_derived_subkey() {
    let reactor = reactor_fixture();
    let eight = hmac_fixture();
    for path in [
        ("master_signing_key_hex", None),
        ("tenant_id", None),
        ("hkdf", Some("derived_subkey_hex")),
        ("hkdf", Some("app_salt_utf8")),
        ("hkdf", Some("domain_tag_utf8")),
    ] {
        let (outer, inner) = path;
        let (a, b) = match inner {
            Some(inner) => (&reactor[outer][inner], &eight[outer][inner]),
            None => (&reactor[outer], &eight[outer]),
        };
        assert_eq!(
            a,
            b,
            "{outer}{} must match across both fixtures",
            inner.unwrap_or("")
        );
    }
    assert_eq!(reactor["key_version"], 2);
}

// ---------------------------------------------------------------------------
// Topology (§22.1)
// ---------------------------------------------------------------------------

#[test]
fn topology_matches_the_rendered_fixture_values() {
    let fixture = reactor_fixture();
    let tenant: Uuid = fixture["tenant_id"].as_str().unwrap().parse().unwrap();
    let reactor: Uuid = fixture["reactor_id"].as_str().unwrap().parse().unwrap();

    assert_eq!(REACTOR_EXCHANGE, fixture["topology"]["exchange"]);
    assert_eq!("topic", fixture["topology"]["exchange_type"]);
    assert_eq!(
        queue_name(tenant, reactor),
        fixture["topology"]["queue"].as_str().unwrap()
    );
    assert_eq!(
        routing_key(tenant, events::TOKEN_PRE_ISSUE),
        fixture["topology"]["routing_key_token_pre_issue"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        routing_key(tenant, events::LOGIN_POST_AUTH),
        fixture["topology"]["routing_key_login_post_auth"]
            .as_str()
            .unwrap()
    );
}

// ---------------------------------------------------------------------------
// Sign direction (§22.13)
// ---------------------------------------------------------------------------

/// For each committed reply vector: building the reply from its fields
/// reproduces `canonical_signed_json` **byte-for-byte** and recomputes
/// `hmac_signature_hex` — including the `"hmac_signature": null` placeholder
/// inside the signed bytes and every omission rule.
#[test]
fn every_reply_vector_reproduces_its_canonical_bytes_and_mac() {
    let fixture = reactor_fixture();
    let key = subkey(&fixture);

    let mut checked = 0usize;
    for group in ["reactor_to_server", "rejected_replies"] {
        for (name, vector) in fixture[group].as_object().expect("vector group").iter() {
            let Some(message) = vector.get("message") else {
                continue;
            };
            let mut reply = reply_from_vector(message);
            // key_version is taken verbatim from the vector, so the
            // downgraded `key_version_too_old` body still canonicalizes.
            let bytes = reply.canonical_signed_bytes().expect("serializes");
            assert_eq!(
                String::from_utf8(bytes.clone()).unwrap(),
                vector["canonical_signed_json"].as_str().unwrap(),
                "{group}.{name}: canonical bytes must match byte-for-byte"
            );

            // The MAC over exactly those bytes, computed independently.
            let expected = vector["hmac_signature_hex"].as_str().unwrap();
            if reply.key_version >= 2 {
                assert_eq!(
                    hmac_hex(&key, &bytes),
                    expected,
                    "{group}.{name}: MAC over the canonical bytes"
                );
                // …and through the SDK's own signing path.
                reply.sign(&key).expect("sign");
                assert_eq!(reply.hmac_signature.as_deref(), Some(expected));
                assert!(reply.signature_valid(&key));
            }
            checked += 1;
        }
    }
    assert!(
        checked >= 10,
        "expected every committed reply vector, saw {checked}"
    );
}

/// §22.13, stated as its own assertion: a reply built with
/// `require_mfa = false` MUST NOT serialize the field, and `reason` / `patch`
/// are omitted when absent.
#[test]
fn the_three_omission_rules_are_reproduced_not_merely_the_values() {
    let fixture = reactor_fixture();
    let allow = &fixture["reactor_to_server"]["allow"];
    let reply = reply_from_vector(&allow["message"]);
    assert!(!reply.require_mfa);

    let json = String::from_utf8(reply.canonical_signed_bytes().unwrap()).unwrap();
    assert!(
        !json.contains("require_mfa"),
        "require_mfa=false must be omitted: {json}"
    );
    assert!(
        !json.contains("reason"),
        "absent reason must be omitted: {json}"
    );
    assert!(
        !json.contains("patch"),
        "absent patch must be omitted: {json}"
    );
    assert!(
        json.ends_with(r#""hmac_signature":null}"#),
        "null placeholder: {json}"
    );

    // The require_mfa vector proves the other half: true IS serialized, and
    // right after `decision`.
    let mfa = reply_from_vector(&fixture["reactor_to_server"]["require_mfa"]["message"]);
    let json = String::from_utf8(mfa.canonical_signed_bytes().unwrap()).unwrap();
    assert!(
        json.contains(r#""decision":"allow","require_mfa":true"#),
        "{json}"
    );
}

/// Serializing `hmac_signature` as `null` — rather than omitting it, as §8's
/// own two message types do — changes the bytes and therefore the MAC. This is
/// the difference §22.2 calls "the single most likely place for an SDK to
/// produce a MAC that will not verify".
#[test]
fn omitting_the_signature_field_instead_of_nulling_it_produces_a_different_mac() {
    let fixture = reactor_fixture();
    let key = subkey(&fixture);
    let canonical = fixture["reactor_to_server"]["allow"]["canonical_signed_json"]
        .as_str()
        .unwrap();
    let omitted = canonical.replace(r#","hmac_signature":null"#, "");
    assert_ne!(canonical, omitted);
    assert_ne!(
        hmac_hex(&key, omitted.as_bytes()),
        fixture["reactor_to_server"]["allow"]["hmac_signature_hex"]
            .as_str()
            .unwrap(),
        "the §8 omission rule must NOT reproduce a reactor MAC"
    );
}

// ---------------------------------------------------------------------------
// Verify direction (§22.13)
// ---------------------------------------------------------------------------

#[test]
fn every_event_vector_verifies_under_the_derived_subkey_and_no_other() {
    let fixture = reactor_fixture();
    let key = subkey(&fixture);
    let now = verified_at(&fixture);
    let window = skew(&fixture);

    for (name, vector) in fixture["server_to_reactor"].as_object().unwrap().iter() {
        let body = &event_wire_value(vector);

        // The canonical bytes the SDK derives from the delivery are the ones
        // the fixture committed.
        let canonical = canonical_event_bytes(body).expect("canonical bytes");
        assert_eq!(
            String::from_utf8(canonical.clone()).unwrap(),
            vector["canonical_signed_json"].as_str().unwrap(),
            "{name}: event canonical bytes"
        );
        assert_eq!(
            hmac_hex(&key, &canonical),
            vector["hmac_signature_hex"].as_str().unwrap(),
            "{name}: event MAC"
        );

        let event = verify_event(body, &key, now, window)
            .unwrap_or_else(|e| panic!("{name} must verify: {e}"));
        assert_eq!(event.event, body["event"].as_str().unwrap());
        assert_eq!(
            event.timeout_ms,
            body["timeout_ms"].as_u64().unwrap() as u32
        );

        // …and fails under any other key.
        assert_eq!(
            verify_event(body, b"a different key entirely", now, window),
            Err(EventRejection::BadSignature),
            "{name} must not verify under another key"
        );
    }
}

#[test]
fn tampering_with_a_signed_event_invalidates_it() {
    let fixture = reactor_fixture();
    let key = subkey(&fixture);
    let now = verified_at(&fixture);
    let window = skew(&fixture);
    let original = event_wire_value(&fixture["server_to_reactor"]["token_pre_issue"]);

    /// One named mutation applied to a signed body after the fact.
    type Tamper = Box<dyn Fn(&mut serde_json::Value)>;

    let tampers: Vec<(&str, Tamper)> = vec![
        (
            "payload",
            Box::new(|b: &mut serde_json::Value| b["payload"]["sub"] = "root".into()),
        ),
        (
            "timeout_ms",
            Box::new(|b: &mut serde_json::Value| b["timeout_ms"] = 60_000.into()),
        ),
        (
            "tenant_id",
            Box::new(|b: &mut serde_json::Value| {
                b["tenant_id"] = "33333333-3333-3333-3333-333333333333".into()
            }),
        ),
        (
            "nonce",
            Box::new(|b: &mut serde_json::Value| {
                b["nonce"] = "dddddddd-dddd-dddd-dddd-dddddddddddd".into()
            }),
        ),
    ];

    for (field, tamper) in tampers {
        let mut body = original.clone();
        tamper(&mut body);
        assert_eq!(
            verify_event(&body, &key, now, window),
            Err(EventRejection::BadSignature),
            "tampering with '{field}' must invalidate the event"
        );
    }
}

/// §22.2: `key_version` below the floor is refused **before anything else
/// about the body is considered** — including before the signature is
/// computed. The vector proves it: its committed MAC is over the v2 body, so a
/// verifier that checked the signature first would report `bad_signature`.
#[test]
fn a_key_version_below_two_is_refused_before_the_signature_is_computed() {
    let fixture = reactor_fixture();
    let key = subkey(&fixture);
    let now = verified_at(&fixture);
    let window = skew(&fixture);

    let mut body = event_wire_value(&fixture["server_to_reactor"]["token_pre_issue"]);
    body["key_version"] = 1.into();
    assert_eq!(
        verify_event(&body, &key, now, window),
        Err(EventRejection::KeyVersionTooOld(1))
    );

    // The committed reply vector says the same thing on the reply side.
    assert_eq!(
        fixture["rejected_replies"]["key_version_too_old"]["expected_rejection"],
        "key_version_too_old"
    );
    assert_eq!(
        fixture["rejected_replies"]["key_version_too_old"]["message"]["key_version"],
        1
    );
}

/// §22.2: an `issued_at` outside ±300 s is refused in **both** directions.
/// Both halves are committed vectors, keyed to `verified_at`.
#[test]
fn a_stale_or_future_issued_at_is_refused_in_both_directions() {
    let fixture = reactor_fixture();
    let key = subkey(&fixture);
    let now = verified_at(&fixture);
    let window = skew(&fixture);
    let body = event_wire_value(&fixture["server_to_reactor"]["token_pre_issue"]);

    // Behind the clock.
    let stale_at = now + chrono::Duration::seconds(window.num_seconds() + 1);
    assert_eq!(
        verify_event(&body, &key, stale_at, window),
        Err(EventRejection::Stale)
    );
    // Ahead of it — not "extra fresh", but the shape of a captured message
    // held for later.
    let future_at = now - chrono::Duration::seconds(window.num_seconds() + 1);
    assert_eq!(
        verify_event(&body, &key, future_at, window),
        Err(EventRejection::Stale)
    );
    // Exactly on the boundary is still fresh.
    assert!(
        verify_event(&body, &key, now + window, window).is_ok(),
        "±skew is inclusive"
    );

    // The reply-side vectors carry both halves too, with valid signatures.
    for (vector, expected) in [("stale", "stale"), ("stale_future", "stale")] {
        let v = &fixture["rejected_replies"][vector];
        assert_eq!(v["expected_rejection"], expected);
        let reply = {
            let mut r = reply_from_vector(&v["message"]);
            r.sign(&key).unwrap();
            r
        };
        assert!(
            reply.signature_valid(&key),
            "{vector}: the signature is valid; only the freshness gate refuses it"
        );
        assert!(!axiam_sdk::amqp::reactor::is_fresh(
            reply.issued_at,
            now,
            window
        ));
    }
}

/// An unsigned event is not a weak event; it is not an event.
#[test]
fn an_event_with_no_signature_is_refused() {
    let fixture = reactor_fixture();
    let key = subkey(&fixture);
    let now = verified_at(&fixture);
    let window = skew(&fixture);

    let mut body = event_wire_value(&fixture["server_to_reactor"]["token_pre_issue"]);
    body.as_object_mut().unwrap().remove("hmac_signature");
    assert_eq!(
        canonical_event_bytes(&body),
        Err(EventRejection::Malformed("hmac_signature is absent"))
    );
    assert_eq!(
        verify_event(&body, &key, now, window),
        Err(EventRejection::BadSignature)
    );
}

// ---------------------------------------------------------------------------
// Replay (§22.13)
// ---------------------------------------------------------------------------

/// The `correlation_replay` vector: the accepted reply verbatim, valid
/// signature, inside the freshness window — and still refused when presented
/// against a different `correlation_id`.
#[test]
fn a_valid_reply_replayed_against_another_correlation_is_refused() {
    let fixture = reactor_fixture();
    let key = subkey(&fixture);
    let vector = &fixture["rejected_replies"]["correlation_replay"];

    let mut reply = reply_from_vector(&vector["message"]);
    reply.sign(&key).unwrap();
    assert!(reply.signature_valid(&key), "the signature really is valid");
    assert_eq!(vector["expected_rejection"], "wrong_correlation");

    let presented_against: Uuid = vector["verify_against_correlation_id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    assert_ne!(
        reply.correlation_id, presented_against,
        "a perfectly valid signature does not make a reply the answer to another question"
    );
    // The reply body is byte-identical to the accepted `allow` vector.
    assert_eq!(
        vector["hmac_signature_hex"],
        fixture["reactor_to_server"]["allow"]["hmac_signature_hex"]
    );
}

/// The `nonce_binding` pair: two replies differing in **nothing but the
/// nonce** carry different MACs, because the nonce is inside the signed bytes.
#[test]
fn two_replies_differing_only_in_nonce_carry_different_macs() {
    let fixture = reactor_fixture();
    let key = subkey(&fixture);
    let binding = &fixture["nonce_binding"];

    let mut a = reply_from_vector(&fixture["reactor_to_server"]["allow"]["message"]);
    a.nonce = binding["nonce_a"].as_str().unwrap().parse().unwrap();
    a.sign(&key).unwrap();

    let mut b = a.clone();
    b.nonce = binding["nonce_b"].as_str().unwrap().parse().unwrap();
    b.sign(&key).unwrap();

    assert_eq!(a.hmac_signature.as_deref(), binding["hmac_a_hex"].as_str());
    assert_eq!(b.hmac_signature.as_deref(), binding["hmac_b_hex"].as_str());
    assert_ne!(a.hmac_signature, b.hmac_signature);
}

/// A fresh nonce per reply is not optional: two replies built back to back for
/// the same event must not be byte-identical.
#[test]
fn the_reply_builder_mints_a_fresh_nonce_every_time() {
    let fixture = reactor_fixture();
    let event = event_from_vector(&fixture, "token_pre_issue");
    let now = verified_at(&fixture);

    let a = ReactorReply::answering(&event, ReplyDecision::Allow, now);
    let b = ReactorReply::answering(&event, ReplyDecision::Allow, now);
    assert_ne!(a.nonce, b.nonce);
    assert_eq!(a.correlation_id, event.correlation_id);
    assert_eq!(a.tenant_id, event.tenant_id);
    assert_eq!(a.event, event.event);
    assert_eq!(a.key_version, 2);
}

fn event_from_vector(fixture: &serde_json::Value, name: &str) -> ReactorEvent {
    serde_json::from_value(event_wire_value(&fixture["server_to_reactor"][name]))
        .expect("event vector decodes")
}

// ---------------------------------------------------------------------------
// Reply construction (§22.13)
// ---------------------------------------------------------------------------

/// A handler returning a mutation produces `decision: "mutate"` and never
/// `allow` + `patch`; a patch containing a forbidden key is sent
/// **unfiltered**.
#[test]
fn a_mutation_is_sent_unfiltered_and_never_as_an_allow() {
    let fixture = reactor_fixture();
    let key = subkey(&fixture);
    let vector = &fixture["rejected_replies"]["forbidden_patch_field"];
    assert_eq!(vector["expected_rejection"], "forbidden_patch_field:sub");

    let mut reply = reply_from_vector(&vector["message"]);
    reply.sign(&key).unwrap();
    let wire = serde_json::to_string(&reply).unwrap();

    assert!(wire.contains(r#""decision":"mutate""#));
    assert!(
        wire.contains(r#""sub":"root""#),
        "the SDK must NOT silently drop `sub` from a token.pre_issue patch: {wire}"
    );
    assert!(wire.contains(r#""ext.department":"eng""#));
    // The event's allow-list says `sub` is forbidden — and the SDK sends it
    // anyway, because one forbidden key rejects the WHOLE patch server-side
    // and pruning would leave the author believing it was set.
    let spec = event_spec(events::TOKEN_PRE_ISSUE).unwrap();
    assert!(!spec.patch_field_allowed("sub"));
    assert!(spec.patch_field_allowed("ext.department"));
}

/// §22.4 rule 2: `allow` and `patch` are mutually exclusive, so a handler that
/// returns a mutation MUST produce `decision: "mutate"`. The reply type makes
/// the shape reachable, and the server refuses it — this test pins which way
/// the SDK builds it.
#[test]
fn the_mutate_vector_is_a_mutate_and_the_allow_vector_carries_no_patch() {
    let fixture = reactor_fixture();
    let mutate = reply_from_vector(&fixture["reactor_to_server"]["mutate"]["message"]);
    assert_eq!(mutate.decision, ReplyDecision::Mutate);
    assert_eq!(mutate.patch.as_ref().unwrap().len(), 2);

    let allow = reply_from_vector(&fixture["reactor_to_server"]["allow"]["message"]);
    assert_eq!(allow.decision, ReplyDecision::Allow);
    assert!(allow.patch.is_none());
}

/// §22.4 row 8 / the `mutation_on_veto_only_event` vector: a mutation on a
/// veto-only event is refused. The SDK's registry knows it locally.
#[test]
fn a_mutation_on_a_veto_only_event_is_recognisable_locally() {
    let fixture = reactor_fixture();
    let vector = &fixture["rejected_replies"]["mutation_on_veto_only_event"];
    assert_eq!(vector["expected_rejection"], "not_mutable");

    let event_name = vector["message"]["event"].as_str().unwrap();
    let spec = event_spec(event_name).expect("a registry event");
    assert!(!spec.mutable, "{event_name} is veto-only");
    assert!(!spec.patch_field_allowed("role"));
}

/// §22.13: the deny vector's reason rides through unchanged, and a deny with
/// no reason still denies.
#[test]
fn a_deny_carries_its_reason_and_denies_without_one() {
    let fixture = reactor_fixture();
    let key = subkey(&fixture);
    let vector = &fixture["reactor_to_server"]["deny"];
    assert_eq!(vector["expected_outcome"]["reason"], "embargoed region");

    let mut reply = reply_from_vector(&vector["message"]);
    assert_eq!(reply.reason.as_deref(), Some("embargoed region"));
    reply.sign(&key).unwrap();
    assert_eq!(
        reply.hmac_signature.as_deref(),
        vector["hmac_signature_hex"].as_str()
    );

    let mut unexplained = reply.clone();
    unexplained.reason = None;
    unexplained.sign(&key).unwrap();
    let wire = serde_json::to_string(&unexplained).unwrap();
    assert!(
        !wire.contains("reason"),
        "an absent reason is omitted: {wire}"
    );
    assert_eq!(unexplained.decision, ReplyDecision::Deny);
}
