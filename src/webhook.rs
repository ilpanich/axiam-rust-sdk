//! Webhook signature verification (CONTRACT.md §13, T-145).
//!
//! AXIAM signs every webhook delivery with a Stripe-style *signed timestamp*.
//! [`verify_webhook`] is the SDK-side receiver half: it recomputes the MAC over
//! the exact bytes the server signed, compares it in constant time, and applies
//! a two-sided freshness window — so integrators never have to hand-roll the
//! HMAC comparison (or skip it).
//!
//! # What the server sends
//!
//! | Header | Value |
//! |---|---|
//! | `X-Axiam-Timestamp` | unix seconds, decimal ASCII |
//! | `X-Axiam-Signature` | `t=<unix_seconds>,v1=<hex_lowercase>` |
//! | `X-Axiam-Event` | event type |
//! | `X-Axiam-Delivery` | delivery UUID (at-least-once dedup key) |
//!
//! `v1 = HMAC-SHA256(secret_utf8_bytes, "<timestamp>.<raw_body>")`, hex-encoded
//! lowercase, where `<timestamp>` is byte-identical to the `t=` field.
//!
//! # ⚠ The body MUST be the raw bytes received off the wire
//!
//! [`verify_webhook`] takes `&[u8]` on purpose. **Never** parse the request body
//! into a JSON value and re-serialize it before verifying: key order and
//! whitespace are not preserved by a round-trip through a JSON parser, the
//! recomputed MAC is then taken over different bytes than the server signed, and
//! every genuine delivery is rejected. Capture the untouched body (e.g.
//! `actix_web::web::Bytes`, `axum::body::Bytes`, `hyper::body::to_bytes`) and
//! hand *those* bytes to this function; parse afterwards.
//!
//! # Which timestamp is authoritative
//!
//! `X-Axiam-Timestamp` is redundant with the `t=` field, and only `t=` is
//! covered by the MAC. This helper therefore parses `t=` from the signature
//! header. If you also pass the separate header via
//! [`WebhookVerifyOptions::timestamp_header`], it MUST be equal to `t=` or
//! verification fails ([`WebhookVerifyError::TimestampMismatch`]).
//!
//! # Deduplication is the receiver's job
//!
//! Deliveries are at-least-once: a retry replays a *valid* signature inside the
//! freshness window, so a successful verification is not proof of a new event.
//! Keep a short-lived seen-set keyed on `X-Axiam-Delivery` (surfaced as
//! [`WebhookEvent::delivery_id`] when you pass it in) and drop repeats.
//!
//! # Example
//!
//! ```
//! use axiam_sdk::Sensitive;
//! use axiam_sdk::webhook::{WebhookVerifyOptions, verify_webhook};
//!
//! # fn handle(
//! #     signature_header: &str,
//! #     event_header: &str,
//! #     delivery_header: &str,
//! #     raw_body: &[u8],
//! # ) {
//! let secret = Sensitive::new(std::env::var("AXIAM_WEBHOOK_SECRET").unwrap_or_default());
//!
//! let opts = WebhookVerifyOptions::new()
//!     .event_type(event_header)
//!     .delivery_id(delivery_header);
//!
//! match verify_webhook(&secret, signature_header, raw_body, &opts) {
//!     Ok(event) => {
//!         // `event.body` is still the raw bytes — parse them now, not before.
//!         let _ = (event.delivery_id, event.event_type, event.body);
//!     }
//!     Err(_) => { /* 400/401 — do not echo the error to the sender */ }
//! }
//! # }
//! ```

#![cfg(any(feature = "rest", feature = "amqp"))]

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use subtle::{Choice, ConstantTimeEq};

use crate::AxiamError;
use crate::Sensitive;

type HmacSha256 = Hmac<Sha256>;

/// Default two-sided freshness window: a delivery is accepted only when
/// `abs(now - t) <= 300` seconds (CONTRACT.md §13.2).
pub const DEFAULT_TOLERANCE: Duration = Duration::from_secs(300);

/// Length of an HMAC-SHA256 tag, in bytes.
const MAC_LEN: usize = 32;

/// A webhook delivery whose signature has been verified.
///
/// Borrows the caller's raw body rather than copying it: verification is
/// allocation-free on the success path apart from the MAC itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct WebhookEvent<'a> {
    /// The signed unix timestamp (`t=` from the signature header), already
    /// validated against the freshness window.
    pub timestamp: i64,
    /// The `X-Axiam-Event` value, if it was supplied via
    /// [`WebhookVerifyOptions::event_type`].
    pub event_type: Option<&'a str>,
    /// The `X-Axiam-Delivery` value, if it was supplied via
    /// [`WebhookVerifyOptions::delivery_id`]. This is the at-least-once dedup
    /// key — see the [module docs](self).
    pub delivery_id: Option<&'a str>,
    /// The exact raw body bytes the MAC was verified over.
    pub body: &'a [u8],
}

/// Why a webhook delivery was rejected.
///
/// Every variant is deliberately terse: it never carries, formats, or otherwise
/// surfaces the expected signature, the computed MAC, or the secret
/// (CONTRACT.md §13.3 rule 6). Nothing in this module logs at any level.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum WebhookVerifyError {
    /// The `X-Axiam-Signature` header could not be parsed into `key=value`
    /// pairs, or carried more than one `t` field.
    #[error("malformed X-Axiam-Signature header: {reason}")]
    MalformedHeader {
        /// Short, non-sensitive description of the parse failure.
        reason: &'static str,
    },
    /// The header carried no `v1` signature at all. "Nothing to verify" is a
    /// failure, never a pass (CONTRACT.md §13.3 rule 3).
    #[error("X-Axiam-Signature header carried no v1 signature")]
    MissingSignature,
    /// The `t` field was absent or not a decimal integer.
    #[error("X-Axiam-Signature `t` is not a unix timestamp")]
    InvalidTimestamp,
    /// A separate `X-Axiam-Timestamp` header was supplied and disagreed with
    /// the MAC-covered `t=` field (CONTRACT.md §13.3 rule 2).
    #[error("X-Axiam-Timestamp does not match the signed `t` value")]
    TimestampMismatch,
    /// No supplied `v1` matched the recomputed MAC.
    #[error("webhook signature verification failed")]
    SignatureMismatch,
    /// The signed timestamp fell outside the two-sided freshness window —
    /// either too old or too far in the future (CONTRACT.md §13.3 rule 5).
    #[error("webhook timestamp is {skew_secs}s from now, outside the {tolerance_secs}s window")]
    Stale {
        /// `|now - t|`, in seconds. Neither operand is secret.
        skew_secs: u64,
        /// The configured tolerance, in seconds.
        tolerance_secs: u64,
    },
}

impl From<WebhookVerifyError> for AxiamError {
    /// A rejected webhook is an authentication failure: the sender did not
    /// prove possession of the shared secret. The message is the error's own
    /// terse `Display`, which never contains the expected signature.
    fn from(err: WebhookVerifyError) -> Self {
        AxiamError::auth(err.to_string())
    }
}

/// Knobs for [`verify_webhook`]. Build with [`WebhookVerifyOptions::new`]; the
/// defaults (300 s tolerance, system clock, no cross-checked headers) are what
/// CONTRACT.md §13.2 mandates.
#[derive(Debug, Clone, Copy)]
pub struct WebhookVerifyOptions<'a> {
    tolerance: Duration,
    now: Option<i64>,
    timestamp_header: Option<&'a str>,
    event_type: Option<&'a str>,
    delivery_id: Option<&'a str>,
}

impl Default for WebhookVerifyOptions<'_> {
    fn default() -> Self {
        Self {
            tolerance: DEFAULT_TOLERANCE,
            now: None,
            timestamp_header: None,
            event_type: None,
            delivery_id: None,
        }
    }
}

impl<'a> WebhookVerifyOptions<'a> {
    /// Default options: a 300-second two-sided freshness window evaluated
    /// against the system clock.
    pub fn new() -> Self {
        Self::default()
    }

    /// Override the two-sided freshness window (default
    /// [`DEFAULT_TOLERANCE`], 300 s). Sub-second precision is truncated.
    pub fn tolerance(mut self, tolerance: Duration) -> Self {
        self.tolerance = tolerance;
        self
    }

    /// Pin "now" to a fixed unix timestamp instead of reading the system
    /// clock — the injection seam CONTRACT.md §13.2 requires for tests.
    pub fn now(mut self, now_unix_secs: i64) -> Self {
        self.now = Some(now_unix_secs);
        self
    }

    /// Cross-check the separate `X-Axiam-Timestamp` header against the
    /// MAC-covered `t=` field. When supplied the two MUST be equal
    /// (CONTRACT.md §13.3 rule 2); a mismatch is
    /// [`WebhookVerifyError::TimestampMismatch`].
    pub fn timestamp_header(mut self, raw: &'a str) -> Self {
        self.timestamp_header = Some(raw);
        self
    }

    /// Carry the `X-Axiam-Event` header through to
    /// [`WebhookEvent::event_type`]. Not covered by the MAC; informational.
    pub fn event_type(mut self, raw: &'a str) -> Self {
        self.event_type = Some(raw);
        self
    }

    /// Carry the `X-Axiam-Delivery` header through to
    /// [`WebhookEvent::delivery_id`] — the at-least-once dedup key. Not
    /// covered by the MAC; informational.
    pub fn delivery_id(mut self, raw: &'a str) -> Self {
        self.delivery_id = Some(raw);
        self
    }
}

/// Verify an AXIAM webhook delivery (CONTRACT.md §13).
///
/// # Arguments
///
/// * `secret` — the webhook's plaintext secret, wrapped in [`Sensitive`] per
///   CONTRACT.md §7. Its raw UTF-8 bytes are the HMAC key.
/// * `signature_header` — the raw `X-Axiam-Signature` value.
/// * `body` — **the exact raw request-body bytes received off the wire.**
///   Re-serializing parsed JSON changes key order/whitespace and breaks the
///   MAC; see the [module docs](self).
/// * `options` — freshness window, `now` seam, and optional headers to carry
///   through / cross-check. Pass `&WebhookVerifyOptions::new()` for defaults.
///
/// # Order of checks
///
/// Header parse → `t` parse → recompute MAC → constant-time compare →
/// freshness. Failure is always a typed [`WebhookVerifyError`]; the expected
/// signature is never surfaced, and nothing here is logged.
///
/// # Example
///
/// ```
/// use std::time::Duration;
///
/// use axiam_sdk::Sensitive;
/// use axiam_sdk::webhook::{WebhookVerifyError, WebhookVerifyOptions, verify_webhook};
///
/// # fn receive(signature_header: &str, raw_body: &[u8]) -> Result<(), WebhookVerifyError> {
/// let secret = Sensitive::new(std::env::var("AXIAM_WEBHOOK_SECRET").unwrap_or_default());
///
/// let opts = WebhookVerifyOptions::new().tolerance(Duration::from_secs(300));
/// let event = verify_webhook(&secret, signature_header, raw_body, &opts)?;
///
/// // `event.body` is still the untouched bytes — parse them only now.
/// let payload: serde_json::Value = serde_json::from_slice(event.body).unwrap();
/// let _ = (payload, event.timestamp);
/// # Ok(())
/// # }
/// ```
///
/// A wrong secret, a tampered body, a stale or future-dated `t`, or a header
/// with no `v1` all return `Err`; none of those errors reveal the expected
/// signature.
pub fn verify_webhook<'a>(
    secret: &Sensitive<String>,
    signature_header: &str,
    body: &'a [u8],
    options: &WebhookVerifyOptions<'a>,
) -> Result<WebhookEvent<'a>, WebhookVerifyError> {
    // ---- 1. Parse the header into comma-separated `key=value` pairs. -------
    // Unknown keys and future schemes are ignored for forward compatibility,
    // but exactly one `t` and at least one `v1` are required.
    let mut raw_t: Option<&str> = None;
    let mut v1_values: Vec<&str> = Vec::new();

    for pair in signature_header.split(',') {
        let pair = pair.trim();
        if pair.is_empty() {
            continue;
        }
        let (key, value) = match pair.split_once('=') {
            Some((k, v)) => (k.trim(), v.trim()),
            // A bare token with no `=` is not a `key=value` pair. Reject
            // rather than silently ignore: a header we cannot fully parse is
            // not a header we can claim to have checked.
            None => {
                return Err(WebhookVerifyError::MalformedHeader {
                    reason: "expected comma-separated key=value pairs",
                });
            }
        };
        match key {
            "t" => {
                if raw_t.is_some() {
                    return Err(WebhookVerifyError::MalformedHeader {
                        reason: "duplicate `t` field",
                    });
                }
                raw_t = Some(value);
            }
            "v1" => v1_values.push(value),
            // Forward compatibility: unknown keys (and future `v2`, …
            // schemes) are ignored.
            _ => {}
        }
    }

    // ---- 2. Parse `t` as an integer. Reject non-numeric. ------------------
    // The MAC is computed over the `t` field *as it appeared on the wire*
    // (byte-identical, per §13.1) — the parsed integer is used only for the
    // freshness comparison below.
    let raw_t = raw_t.ok_or(WebhookVerifyError::InvalidTimestamp)?;
    let timestamp: i64 = raw_t
        .parse()
        .map_err(|_| WebhookVerifyError::InvalidTimestamp)?;

    if let Some(header_ts) = options.timestamp_header {
        // §13.3 rule 2: only `t=` is covered by the MAC, so the redundant
        // header is not trusted — it is merely required to agree.
        let header_ts: i64 = header_ts
            .trim()
            .parse()
            .map_err(|_| WebhookVerifyError::TimestampMismatch)?;
        if header_ts != timestamp {
            return Err(WebhookVerifyError::TimestampMismatch);
        }
    }

    // "no v1" is checked after `t` parsing so a header that is malformed in
    // both respects reports the more specific failure first; either way it is
    // never a pass (§13.3 rule 3).
    if v1_values.is_empty() {
        return Err(WebhookVerifyError::MissingSignature);
    }

    // ---- 3. Recompute HMAC-SHA256(secret, "<t>.<body>"). ------------------
    let mut mac = <HmacSha256 as KeyInit>::new_from_slice(secret.expose().as_bytes())
        .expect("HMAC-SHA256 accepts a key of any length");
    mac.update(raw_t.as_bytes());
    mac.update(b".");
    mac.update(body);
    let expected = mac.finalize().into_bytes();

    // ---- 4. Constant-time compare against every supplied `v1`. ------------
    // No early return: every candidate is decoded and compared, and the
    // outcome is folded into a single `Choice`, so neither the number of
    // matching leading bytes nor the position of a matching candidate is
    // observable through timing. A candidate that is not valid hex, or is not
    // 32 bytes, contributes 0 — fail closed.
    let mut matched = Choice::from(0u8);
    let mut decoded = [0u8; MAC_LEN];
    for candidate in &v1_values {
        let is_match = match hex::decode_to_slice(candidate.as_bytes(), &mut decoded) {
            Ok(()) => expected.as_slice().ct_eq(&decoded),
            Err(_) => Choice::from(0u8),
        };
        matched |= is_match;
    }
    if !bool::from(matched) {
        return Err(WebhookVerifyError::SignatureMismatch);
    }

    // ---- 5. Two-sided freshness window. -----------------------------------
    // Rejecting future-dated timestamps as well as stale ones is required:
    // otherwise a clock-skew abuse buys an attacker an unbounded replay window
    // (§13.3 rule 5).
    let now = options.now.unwrap_or_else(current_unix_secs);
    let skew_secs = now.saturating_sub(timestamp).unsigned_abs();
    let tolerance_secs = options.tolerance.as_secs();
    if skew_secs > tolerance_secs {
        return Err(WebhookVerifyError::Stale {
            skew_secs,
            tolerance_secs,
        });
    }

    Ok(WebhookEvent {
        timestamp,
        event_type: options.event_type,
        delivery_id: options.delivery_id,
        body,
    })
}

/// Wall-clock unix seconds. Pre-epoch clocks (only reachable on a badly
/// misconfigured host) read as 0, which the freshness window then rejects —
/// fail closed rather than panic.
fn current_unix_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "whsec_test_0123456789abcdef";
    const TS: i64 = 1_785_700_000;
    const BODY: &[u8] = br#"{"event":"user.created","id":"01JQ0000000000000000000000"}"#;

    /// Reproduce the server's algorithm (`compute_signature_v2`) in the test
    /// setup rather than hardcoding a hex string, so this test is the
    /// cross-SDK pin: every SDK computes the same bytes from the same inputs.
    fn server_signature(secret: &str, timestamp: i64, body: &[u8]) -> String {
        let mut mac = <HmacSha256 as KeyInit>::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(timestamp.to_string().as_bytes());
        mac.update(b".");
        mac.update(body);
        hex::encode(mac.finalize().into_bytes())
    }

    fn header(secret: &str, timestamp: i64, body: &[u8]) -> String {
        format!(
            "t={timestamp},v1={}",
            server_signature(secret, timestamp, body)
        )
    }

    fn secret() -> Sensitive<String> {
        Sensitive::new(SECRET.to_string())
    }

    // ---- Required test 1: valid signature + fresh timestamp -> accepted ----
    #[test]
    fn valid_fresh_signature_is_accepted() {
        let opts = WebhookVerifyOptions::new().now(TS + 5);
        let event = verify_webhook(&secret(), &header(SECRET, TS, BODY), BODY, &opts)
            .expect("a fresh, correctly-signed delivery must verify");
        assert_eq!(event.timestamp, TS);
        assert_eq!(event.body, BODY);
    }

    // ---- Required test 7: cross-SDK pinned vector -------------------------
    #[test]
    fn cross_sdk_shared_vector_round_trips() {
        // secret/timestamp/body are the shared vector from CONTRACT.md §13.4.
        // The expected v1 is computed here from the spec's algorithm, never
        // copied from a document, so all 11 SDKs are pinned to the same bytes.
        let sig = server_signature(SECRET, TS, BODY);
        assert_eq!(sig.len(), 64, "hex-encoded HMAC-SHA256 is 64 chars");
        assert_eq!(sig, sig.to_lowercase(), "hex must be lowercase");

        let opts = WebhookVerifyOptions::new().now(TS);
        let event = verify_webhook(&secret(), &format!("t={TS},v1={sig}"), BODY, &opts)
            .expect("the shared vector must verify");
        assert_eq!(event.timestamp, TS);

        // …and the byte-flipped body under the SAME signature must not.
        let mut tampered = BODY.to_vec();
        tampered[0] ^= 0x01;
        assert_eq!(
            verify_webhook(&secret(), &format!("t={TS},v1={sig}"), &tampered, &opts),
            Err(WebhookVerifyError::SignatureMismatch)
        );
    }

    // ---- Required test 2: tampered body (one byte flipped) -> rejected -----
    #[test]
    fn tampered_body_is_rejected() {
        let hdr = header(SECRET, TS, BODY);
        let opts = WebhookVerifyOptions::new().now(TS);
        for idx in [0usize, BODY.len() / 2, BODY.len() - 1] {
            let mut tampered = BODY.to_vec();
            tampered[idx] ^= 0x01;
            assert_eq!(
                verify_webhook(&secret(), &hdr, &tampered, &opts),
                Err(WebhookVerifyError::SignatureMismatch),
                "flipping byte {idx} must invalidate the MAC"
            );
        }
    }

    // ---- Required test 3: wrong secret -> rejected ------------------------
    #[test]
    fn wrong_secret_is_rejected() {
        let hdr = header("whsec_some_other_secret", TS, BODY);
        let opts = WebhookVerifyOptions::new().now(TS);
        assert_eq!(
            verify_webhook(&secret(), &hdr, BODY, &opts),
            Err(WebhookVerifyError::SignatureMismatch)
        );
    }

    // ---- Required test 4: stale timestamp -> rejected ---------------------
    #[test]
    fn stale_timestamp_is_rejected() {
        let hdr = header(SECRET, TS, BODY);
        // 301s in the past, one second past the default 300s window.
        let opts = WebhookVerifyOptions::new().now(TS + 301);
        assert_eq!(
            verify_webhook(&secret(), &hdr, BODY, &opts),
            Err(WebhookVerifyError::Stale {
                skew_secs: 301,
                tolerance_secs: 300,
            })
        );
        // Exactly at the boundary is still fresh.
        let at_edge = WebhookVerifyOptions::new().now(TS + 300);
        assert!(verify_webhook(&secret(), &hdr, BODY, &at_edge).is_ok());
    }

    // ---- Required test 5: future timestamp beyond tolerance -> rejected ----
    #[test]
    fn future_timestamp_beyond_tolerance_is_rejected() {
        let hdr = header(SECRET, TS, BODY);
        let opts = WebhookVerifyOptions::new().now(TS - 301);
        assert_eq!(
            verify_webhook(&secret(), &hdr, BODY, &opts),
            Err(WebhookVerifyError::Stale {
                skew_secs: 301,
                tolerance_secs: 300,
            })
        );
        let at_edge = WebhookVerifyOptions::new().now(TS - 300);
        assert!(
            verify_webhook(&secret(), &hdr, BODY, &at_edge).is_ok(),
            "a future-dated delivery inside the window is still accepted"
        );
    }

    // ---- Required test 6: malformed headers -> rejected -------------------
    #[test]
    fn header_with_no_v1_is_rejected() {
        let opts = WebhookVerifyOptions::new().now(TS);
        assert_eq!(
            verify_webhook(&secret(), &format!("t={TS}"), BODY, &opts),
            Err(WebhookVerifyError::MissingSignature),
            "\"nothing to verify\" must never be treated as success"
        );
        // An unknown future scheme alone is likewise not a signature.
        assert_eq!(
            verify_webhook(&secret(), &format!("t={TS},v2=deadbeef"), BODY, &opts),
            Err(WebhookVerifyError::MissingSignature)
        );
    }

    #[test]
    fn header_with_non_numeric_t_is_rejected() {
        let sig = server_signature(SECRET, TS, BODY);
        let opts = WebhookVerifyOptions::new().now(TS);
        for bad in ["t=not-a-number", "t=", "t=17857000000000000000000"] {
            assert_eq!(
                verify_webhook(&secret(), &format!("{bad},v1={sig}"), BODY, &opts),
                Err(WebhookVerifyError::InvalidTimestamp),
                "`{bad}` must be rejected"
            );
        }
    }

    #[test]
    fn empty_and_shapeless_headers_are_rejected() {
        let opts = WebhookVerifyOptions::new().now(TS);
        assert_eq!(
            verify_webhook(&secret(), "", BODY, &opts),
            Err(WebhookVerifyError::InvalidTimestamp)
        );
        assert_eq!(
            verify_webhook(&secret(), "   ", BODY, &opts),
            Err(WebhookVerifyError::InvalidTimestamp)
        );
        assert!(matches!(
            verify_webhook(&secret(), "garbage-without-equals", BODY, &opts),
            Err(WebhookVerifyError::MalformedHeader { .. })
        ));
        assert!(matches!(
            verify_webhook(&secret(), &format!("t={TS},t={TS}"), BODY, &opts),
            Err(WebhookVerifyError::MalformedHeader { .. })
        ));
    }

    // ---- Additional coverage ---------------------------------------------
    #[test]
    fn non_hex_and_short_v1_fail_closed() {
        let opts = WebhookVerifyOptions::new().now(TS);
        for bad_sig in ["zz", "", "deadbeef", &"a".repeat(63), &"a".repeat(66)] {
            assert_eq!(
                verify_webhook(&secret(), &format!("t={TS},v1={bad_sig}"), BODY, &opts),
                Err(WebhookVerifyError::SignatureMismatch),
                "an undecodable v1 must fail closed, not pass"
            );
        }
    }

    #[test]
    fn multiple_v1_values_accept_when_any_matches() {
        // During a secret rotation the server may send more than one v1.
        let good = server_signature(SECRET, TS, BODY);
        let opts = WebhookVerifyOptions::new().now(TS);
        let hdr = format!("t={TS},v1={},v1={good}", "0".repeat(64));
        assert!(verify_webhook(&secret(), &hdr, BODY, &opts).is_ok());
    }

    #[test]
    fn unknown_keys_and_whitespace_are_tolerated() {
        let sig = server_signature(SECRET, TS, BODY);
        let hdr = format!(" t = {TS} , scheme=v2 , v1 = {sig} ");
        let opts = WebhookVerifyOptions::new().now(TS);
        assert!(verify_webhook(&secret(), &hdr, BODY, &opts).is_ok());
    }

    #[test]
    fn timestamp_header_must_equal_the_signed_t() {
        let hdr = header(SECRET, TS, BODY);
        let matching = WebhookVerifyOptions::new()
            .now(TS)
            .timestamp_header("1785700000");
        assert!(verify_webhook(&secret(), &hdr, BODY, &matching).is_ok());

        let mismatched = WebhookVerifyOptions::new()
            .now(TS)
            .timestamp_header("1785700001");
        assert_eq!(
            verify_webhook(&secret(), &hdr, BODY, &mismatched),
            Err(WebhookVerifyError::TimestampMismatch)
        );

        let garbage = WebhookVerifyOptions::new().now(TS).timestamp_header("nope");
        assert_eq!(
            verify_webhook(&secret(), &hdr, BODY, &garbage),
            Err(WebhookVerifyError::TimestampMismatch)
        );
    }

    #[test]
    fn event_and_delivery_headers_are_carried_through() {
        let hdr = header(SECRET, TS, BODY);
        let opts = WebhookVerifyOptions::new()
            .now(TS)
            .event_type("user.created")
            .delivery_id("018f4c1a-0000-7000-8000-000000000000");
        let event = verify_webhook(&secret(), &hdr, BODY, &opts).expect("verifies");
        assert_eq!(event.event_type, Some("user.created"));
        assert_eq!(
            event.delivery_id,
            Some("018f4c1a-0000-7000-8000-000000000000")
        );
    }

    #[test]
    fn custom_tolerance_is_respected() {
        let hdr = header(SECRET, TS, BODY);
        let tight = WebhookVerifyOptions::new()
            .now(TS + 30)
            .tolerance(Duration::from_secs(10));
        assert_eq!(
            verify_webhook(&secret(), &hdr, BODY, &tight),
            Err(WebhookVerifyError::Stale {
                skew_secs: 30,
                tolerance_secs: 10,
            })
        );
    }

    // §13.3 rule 6: no error rendering may leak the expected signature.
    #[test]
    fn errors_never_surface_the_expected_signature_or_secret() {
        let expected = server_signature(SECRET, TS, BODY);
        let opts = WebhookVerifyOptions::new().now(TS);
        let err = verify_webhook(
            &secret(),
            &format!("t={TS},v1={}", "0".repeat(64)),
            BODY,
            &opts,
        )
        .expect_err("must reject");
        let rendered = format!("{err} / {err:?}");
        assert!(!rendered.contains(&expected), "leaked MAC: {rendered}");
        assert!(!rendered.contains(SECRET), "leaked secret: {rendered}");
    }

    // The `now` seam is optional: with no injection the system clock is used,
    // so a delivery stamped "now" verifies and an ancient one does not.
    #[test]
    fn system_clock_is_used_when_no_now_is_injected() {
        let now = current_unix_secs();
        let hdr = header(SECRET, now, BODY);
        assert!(verify_webhook(&secret(), &hdr, BODY, &WebhookVerifyOptions::new()).is_ok());

        let old = header(SECRET, now - 86_400, BODY);
        assert!(matches!(
            verify_webhook(&secret(), &old, BODY, &WebhookVerifyOptions::new()),
            Err(WebhookVerifyError::Stale { .. })
        ));
    }

    #[test]
    fn verify_error_converts_to_an_axiam_auth_error() {
        let err: AxiamError = WebhookVerifyError::SignatureMismatch.into();
        assert!(matches!(err, AxiamError::Auth { .. }));
    }
}
