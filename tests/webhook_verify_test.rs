//! CONTRACT.md §13 / T-145 — `axiam_sdk::webhook::verify_webhook` exercised
//! through the **public** crate surface.
//!
//! The exhaustive branch coverage lives in `src/webhook.rs`'s own unit tests;
//! this file's job is different: prove that the helper, its options builder,
//! its error type and the `Sensitive<T>` secret wrapper are all reachable from
//! outside the crate under the documented path, and that the §13.4 required
//! cases hold across that boundary.

#![cfg(any(feature = "rest", feature = "amqp"))]

use std::time::Duration;

use axiam_sdk::Sensitive;
use axiam_sdk::webhook::{
    DEFAULT_TOLERANCE, WebhookVerifyError, WebhookVerifyOptions, verify_webhook,
};
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

/// The CONTRACT.md §13.4 cross-SDK shared vector.
const SECRET: &str = "whsec_test_0123456789abcdef";
const TIMESTAMP: i64 = 1_785_700_000;
const BODY: &[u8] = br#"{"event":"user.created","id":"01JQ0000000000000000000000"}"#;

/// The server's algorithm (`compute_signature_v2`), reimplemented here from the
/// §13.1 spec rather than copying a hex constant from a document — that is what
/// makes this the cross-SDK pin: all 11 SDKs derive the same bytes from the
/// same three inputs.
fn server_v1(secret: &str, timestamp: i64, body: &[u8]) -> String {
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(secret.as_bytes())
        .expect("HMAC accepts any key length");
    mac.update(timestamp.to_string().as_bytes());
    mac.update(b".");
    mac.update(body);
    hex::encode(mac.finalize().into_bytes())
}

fn signature_header(secret: &str, timestamp: i64, body: &[u8]) -> String {
    format!("t={timestamp},v1={}", server_v1(secret, timestamp, body))
}

fn secret() -> Sensitive<String> {
    Sensitive::new(SECRET.to_string())
}

/// Required test 1 + 7: the shared vector verifies when fresh.
#[test]
fn shared_vector_verifies_and_exposes_the_delivery_id() {
    let header = signature_header(SECRET, TIMESTAMP, BODY);
    let opts = WebhookVerifyOptions::new()
        .now(TIMESTAMP + 12)
        .event_type("user.created")
        .delivery_id("018f4c1a-0000-7000-8000-0000000000ab")
        .timestamp_header("1785700000");

    let event = verify_webhook(&secret(), &header, BODY, &opts)
        .expect("the §13.4 shared vector must verify");

    assert_eq!(event.timestamp, TIMESTAMP);
    assert_eq!(event.body, BODY);
    assert_eq!(event.event_type, Some("user.created"));
    assert_eq!(
        event.delivery_id,
        Some("018f4c1a-0000-7000-8000-0000000000ab"),
        "the at-least-once dedup key must be reachable from the result"
    );
}

/// Required test 2: one flipped body byte invalidates the MAC.
#[test]
fn tampered_body_is_rejected() {
    let header = signature_header(SECRET, TIMESTAMP, BODY);
    let opts = WebhookVerifyOptions::new().now(TIMESTAMP);
    let mut tampered = BODY.to_vec();
    tampered[7] ^= 0x01;

    assert_eq!(
        verify_webhook(&secret(), &header, &tampered, &opts),
        Err(WebhookVerifyError::SignatureMismatch)
    );
}

/// Required test 3.
#[test]
fn wrong_secret_is_rejected() {
    let header = signature_header("whsec_not_the_real_secret", TIMESTAMP, BODY);
    let opts = WebhookVerifyOptions::new().now(TIMESTAMP);

    assert_eq!(
        verify_webhook(&secret(), &header, BODY, &opts),
        Err(WebhookVerifyError::SignatureMismatch)
    );
}

/// Required tests 4 and 5: the freshness window is two-sided, and defaults to
/// 300 seconds.
#[test]
fn freshness_window_is_two_sided_and_defaults_to_300s() {
    assert_eq!(DEFAULT_TOLERANCE, Duration::from_secs(300));

    let header = signature_header(SECRET, TIMESTAMP, BODY);
    let stale = WebhookVerifyOptions::new().now(TIMESTAMP + 301);
    let future = WebhookVerifyOptions::new().now(TIMESTAMP - 301);

    assert!(matches!(
        verify_webhook(&secret(), &header, BODY, &stale),
        Err(WebhookVerifyError::Stale { .. })
    ));
    assert!(
        matches!(
            verify_webhook(&secret(), &header, BODY, &future),
            Err(WebhookVerifyError::Stale { .. })
        ),
        "a future-dated timestamp beyond tolerance must be rejected too"
    );

    // Both edges of the default window are still accepted.
    for now in [TIMESTAMP - 300, TIMESTAMP + 300] {
        let opts = WebhookVerifyOptions::new().now(now);
        assert!(verify_webhook(&secret(), &header, BODY, &opts).is_ok());
    }
}

/// Required test 6: malformed headers — missing `v1`, non-numeric `t`, empty.
#[test]
fn malformed_headers_are_rejected() {
    let opts = WebhookVerifyOptions::new().now(TIMESTAMP);
    let v1 = server_v1(SECRET, TIMESTAMP, BODY);

    assert_eq!(
        verify_webhook(&secret(), &format!("t={TIMESTAMP}"), BODY, &opts),
        Err(WebhookVerifyError::MissingSignature),
        "a header with no v1 must never be treated as success"
    );
    assert_eq!(
        verify_webhook(&secret(), &format!("t=abc,v1={v1}"), BODY, &opts),
        Err(WebhookVerifyError::InvalidTimestamp)
    );
    assert_eq!(
        verify_webhook(&secret(), "", BODY, &opts),
        Err(WebhookVerifyError::InvalidTimestamp)
    );
}

/// §13.3 rule 2: the redundant `X-Axiam-Timestamp` header is not trusted, but
/// when supplied it must agree with the MAC-covered `t=`.
#[test]
fn timestamp_header_must_agree_with_the_signed_t() {
    let header = signature_header(SECRET, TIMESTAMP, BODY);
    let opts = WebhookVerifyOptions::new()
        .now(TIMESTAMP)
        .timestamp_header("1785700001");

    assert_eq!(
        verify_webhook(&secret(), &header, BODY, &opts),
        Err(WebhookVerifyError::TimestampMismatch)
    );
}

/// §13.3 rule 6: no rendering of any rejection may carry the expected MAC or
/// the secret.
#[test]
fn rejections_never_leak_the_expected_mac_or_the_secret() {
    let expected = server_v1(SECRET, TIMESTAMP, BODY);
    let opts = WebhookVerifyOptions::new().now(TIMESTAMP);
    let bogus = format!("t={TIMESTAMP},v1={}", "f".repeat(64));

    let err = verify_webhook(&secret(), &bogus, BODY, &opts).expect_err("must reject");
    let rendered = format!("{err} | {err:?}");

    assert!(!rendered.contains(&expected), "leaked expected MAC");
    assert!(!rendered.contains(SECRET), "leaked the secret");
}

/// §13.3 rule 4: an undecodable or wrong-length `v1` fails closed rather than
/// short-circuiting to success.
#[test]
fn undecodable_v1_fails_closed() {
    let opts = WebhookVerifyOptions::new().now(TIMESTAMP);
    for bad in ["nothex", "", "abcd"] {
        assert_eq!(
            verify_webhook(&secret(), &format!("t={TIMESTAMP},v1={bad}"), BODY, &opts),
            Err(WebhookVerifyError::SignatureMismatch),
            "v1={bad:?} must fail closed"
        );
    }
}

/// §13.3 rule 3: unknown keys and future schemes are ignored for forward
/// compatibility — but only alongside a real `v1`.
#[test]
fn unknown_keys_are_ignored_but_do_not_substitute_for_v1() {
    let v1 = server_v1(SECRET, TIMESTAMP, BODY);
    let opts = WebhookVerifyOptions::new().now(TIMESTAMP);

    assert!(
        verify_webhook(
            &secret(),
            &format!("t={TIMESTAMP},v0=legacy,v1={v1},alg=hs256"),
            BODY,
            &opts
        )
        .is_ok(),
        "unknown keys must not break a valid v1"
    );
    assert_eq!(
        verify_webhook(&secret(), &format!("t={TIMESTAMP},v2={v1}"), BODY, &opts),
        Err(WebhookVerifyError::MissingSignature)
    );
}
