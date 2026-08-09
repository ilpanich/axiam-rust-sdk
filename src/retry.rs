//! Bounded read-only retry policy — CONTRACT.md §16.
//!
//! Until contract 1.8 this policy did not exist. §11.2 rule 5 and §14.2 rule 6
//! had both been *requiring* retries "under the SDK's existing bounded
//! read-only retry policy" while no such policy was written down anywhere, so
//! each SDK invented one — this crate's was `backon`'s defaults with
//! `with_max_times(2)`, which has no jitter and ignores `Retry-After`. §16 is
//! the table those clauses had been pointing at all along; this module is that
//! table.
//!
//! # Why this is hand-rolled rather than `backon`
//!
//! §16 requires **full jitter**: the wait is uniform over `[0, backoff]`.
//! `backon`'s `with_jitter()` adds a random value in `[0, min_delay)` on top of
//! the computed backoff, which is a different (and much narrower) distribution.
//! The distinction is the whole point of the clause — partial jitter keeps
//! every client's retries clustered around the same instant, which causes the
//! thundering herd retries are supposed to avoid. `backon` also has no seam for
//! honoring `Retry-After`, which §16.1 makes a floor on the wait.
//!
//! # Testability
//!
//! §16.7 forbids proving this with real sleeps ("a test that really waits
//! 200 ms is a test nobody runs"), so both non-deterministic inputs are
//! injected: [`Jitter`] supplies the random fraction and [`Sleeper`] supplies
//! the wait. Production uses [`ThreadRngJitter`] and [`TokioSleeper`]; tests
//! pin the fraction to 0.0 and 1.0 to assert the range really is `[0, backoff]`
//! and record delays instead of taking them.

use std::future::Future;
use std::time::Duration;

use crate::error::AxiamError;
use crate::telemetry::{Telemetry, TelemetryEvent};

/// Attempt cap: 1 initial + 2 retries (§16.1).
pub const MAX_ATTEMPTS: u32 = 3;
/// First backoff step (§16.1).
pub const BASE_DELAY: Duration = Duration::from_millis(200);
/// Ceiling on any single wait (§16.1).
pub const MAX_DELAY: Duration = Duration::from_secs(5);

/// Source of the jitter fraction, in `[0.0, 1.0]`.
///
/// §16.1 notes this need not be cryptographic: the jitter is a load-spreading
/// device, not a secret.
pub(crate) trait Jitter: Send + Sync {
    /// Returns a value in `[0.0, 1.0]`.
    fn fraction(&self) -> f64;
}

/// Production jitter source.
pub(crate) struct ThreadRngJitter;

impl Jitter for ThreadRngJitter {
    fn fraction(&self) -> f64 {
        // Uniform in [0, 1) from 8 bytes of OS randomness. `getrandom` is
        // already an unconditional transitive dependency of the `rest` feature
        // (see Cargo.toml), so this adds nothing to the dependency tree.
        let mut buf = [0u8; 8];
        if getrandom::fill(&mut buf).is_err() {
            // A randomness failure must not fail an authorization check. Fall
            // back to the full backoff — correct, merely unjittered.
            return 1.0;
        }
        // 53-bit mantissa: the standard way to get a uniform f64 in [0, 1).
        (u64::from_le_bytes(buf) >> 11) as f64 / (1u64 << 53) as f64
    }
}

/// Waits. Injected so tests record instead of sleeping.
pub(crate) trait Sleeper: Send + Sync {
    fn sleep(&self, d: Duration) -> std::pin::Pin<Box<dyn Future<Output = ()> + Send + '_>>;
}

/// Production sleeper.
pub(crate) struct TokioSleeper;

impl Sleeper for TokioSleeper {
    fn sleep(&self, d: Duration) -> std::pin::Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(tokio::time::sleep(d))
    }
}

/// The un-jittered backoff for `attempt` (1-based): `min(cap, base * 2^(n-1))`.
///
/// attempt 1 → 200 ms, attempt 2 → 400 ms — both under the 5 s cap, which only
/// binds if the attempt cap is ever raised.
pub(crate) fn backoff_for(attempt: u32) -> Duration {
    let shift = attempt.saturating_sub(1).min(32);
    BASE_DELAY
        .saturating_mul(1u32.checked_shl(shift).unwrap_or(u32::MAX))
        .min(MAX_DELAY)
}

/// The actual wait: full jitter over `[0, backoff]`, then raised to any
/// server-supplied `Retry-After` (§16.1).
///
/// `Retry-After` is a **floor, never a ceiling**: the server is telling you
/// when it will be ready, so retrying sooner is not permitted — and a
/// `Retry-After: 0` cannot shorten the backoff below what jitter chose.
pub(crate) fn delay_for(
    attempt: u32,
    retry_after: Option<Duration>,
    jitter: &dyn Jitter,
) -> Duration {
    let backoff = backoff_for(attempt);
    let fraction = jitter.fraction().clamp(0.0, 1.0);
    let jittered = backoff.mul_f64(fraction);
    match retry_after {
        Some(hint) => jittered.max(hint),
        None => jittered,
    }
}

/// Is this failure worth another attempt? (§16.3)
///
/// The §2 taxonomy folds 408/429/5xx/transport all into `Network`, so "retry
/// `Network` only" implements the whole table: `Auth`, `Authz`, validation and
/// `OAuthProtocolError` are decisive answers, not transport failures, and
/// retrying an unacceptable request reproduces the identical rejection.
pub(crate) fn is_retryable(err: &AxiamError) -> bool {
    matches!(err, AxiamError::Network { .. })
}

/// One failed attempt: the error the caller will eventually see, plus the
/// server's `Retry-After` hint if the response carried one.
///
/// The hint rides here rather than on [`AxiamError`] deliberately. §16 requires
/// the policy to *honor* `Retry-After`; it does not require callers to be able
/// to read it, and adding a field to the public `Network` variant would churn
/// every construction site in the crate for something no caller asked for. The
/// hint is consumed entirely inside this module and then dropped.
pub(crate) struct Attempt {
    pub(crate) err: AxiamError,
    pub(crate) retry_after: Option<Duration>,
}

impl Attempt {
    /// A failure with no server hint.
    pub(crate) fn bare(err: AxiamError) -> Self {
        Self {
            err,
            retry_after: None,
        }
    }
}

/// Parse an HTTP `Retry-After` header value.
///
/// RFC 9110 permits either delta-seconds or an HTTP-date. Only delta-seconds is
/// honored: the date form requires trusting the client's clock to be in sync
/// with the server's, and a skewed clock would turn the hint into either a
/// no-op or a multi-hour stall. An unparseable value is simply absent, which
/// falls back to the jittered backoff — always a safe answer.
///
/// The value is **not** clamped to [`MAX_DELAY`]. That cap governs the computed
/// backoff; §16.1 makes `Retry-After` a floor with no ceiling, and clamping it
/// would mean retrying *sooner* than the server said it would be ready — the
/// one thing the clause forbids. Total exposure stays bounded by the attempt
/// cap, and a server that wants to stall a client can simply not answer, so a
/// ceiling here would buy nothing.
pub(crate) fn parse_retry_after(value: &str) -> Option<Duration> {
    let secs: u64 = value.trim().parse().ok()?;
    Some(Duration::from_secs(secs))
}

/// Runs `op` under the §16 policy.
///
/// `op` MUST be side-effect-free: §16.2 restricts eligibility to operations
/// that change no server state, and this helper — like every retry helper —
/// cannot tell the difference. Routing a mutation through it would silently
/// duplicate a side effect, or replay a single-use credential into a hard
/// `invalid_grant`.
pub(crate) struct RetryRunner<'a> {
    pub(crate) enabled: bool,
    pub(crate) operation: &'static str,
    pub(crate) telemetry: &'a Telemetry,
    pub(crate) jitter: &'a dyn Jitter,
    pub(crate) sleeper: &'a dyn Sleeper,
}

impl RetryRunner<'_> {
    pub(crate) async fn run<T, F, Fut>(&self, mut op: F) -> Result<T, AxiamError>
    where
        F: FnMut(u32) -> Fut,
        Fut: Future<Output = Result<T, Attempt>>,
    {
        // §16.1: the disable switch yields exactly one attempt. Some callers
        // own their own retry layer and want the SDK out of the way.
        let cap = if self.enabled { MAX_ATTEMPTS } else { 1 };

        let mut attempt = 1;
        loop {
            match op(attempt).await {
                Ok(v) => return Ok(v),
                Err(Attempt { err, retry_after }) => {
                    let last = attempt >= cap;
                    if last || !is_retryable(&err) {
                        return Err(err);
                    }
                    let delay = delay_for(attempt, retry_after, self.jitter);
                    self.telemetry.emit(TelemetryEvent::Retry {
                        operation: self.operation,
                        attempt,
                        delay,
                        // `AxiamError`'s Display is already redacted per §2 —
                        // it never carries a token.
                        reason: err.to_string(),
                    });
                    self.sleeper.sleep(delay).await;
                    attempt += 1;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Pinned(f64);
    impl Jitter for Pinned {
        fn fraction(&self) -> f64 {
            self.0
        }
    }

    #[test]
    fn backoff_doubles_from_the_base_and_stops_at_the_cap() {
        assert_eq!(backoff_for(1), Duration::from_millis(200));
        assert_eq!(backoff_for(2), Duration::from_millis(400));
        // The cap only binds well past the 3-attempt cap, but it must bind.
        assert_eq!(backoff_for(20), MAX_DELAY);
        // And must not overflow at absurd attempt numbers.
        assert_eq!(backoff_for(u32::MAX), MAX_DELAY);
    }

    #[test]
    fn full_jitter_spans_zero_to_the_whole_backoff() {
        // This is the assertion that distinguishes full jitter from
        // `backoff ± something`: pinned to 0 the wait is 0, pinned to 1 it is
        // the entire backoff. Anything narrower is a different distribution.
        assert_eq!(delay_for(1, None, &Pinned(0.0)), Duration::ZERO);
        assert_eq!(delay_for(1, None, &Pinned(1.0)), Duration::from_millis(200));
        assert_eq!(delay_for(2, None, &Pinned(1.0)), Duration::from_millis(400));
        assert_eq!(delay_for(2, None, &Pinned(0.5)), Duration::from_millis(200));
    }

    #[test]
    fn retry_after_raises_the_wait_but_never_lowers_it() {
        // Longer than the backoff: the server wins.
        assert_eq!(
            delay_for(1, Some(Duration::from_secs(2)), &Pinned(1.0)),
            Duration::from_secs(2)
        );
        // Shorter than the backoff: the backoff stands. A `Retry-After: 0`
        // must not be able to defeat the policy.
        assert_eq!(
            delay_for(1, Some(Duration::ZERO), &Pinned(1.0)),
            Duration::from_millis(200)
        );
        // Even against a zero-jitter wait, the hint is still a floor.
        assert_eq!(
            delay_for(1, Some(Duration::from_millis(50)), &Pinned(0.0)),
            Duration::from_millis(50)
        );
    }

    #[test]
    fn a_jitter_fraction_outside_the_range_is_clamped() {
        assert_eq!(delay_for(1, None, &Pinned(9.0)), Duration::from_millis(200));
        assert_eq!(delay_for(1, None, &Pinned(-1.0)), Duration::ZERO);
    }

    #[test]
    fn only_network_failures_are_retryable() {
        // The §2 taxonomy folds 408/429/5xx/transport into `Network`, so this
        // one predicate implements the whole §16.3 table.
        assert!(is_retryable(&AxiamError::network("boom")));
        assert!(!is_retryable(&AxiamError::auth("nope")));
        assert!(!is_retryable(&AxiamError::authz("denied", None, None)));
    }

    #[test]
    fn retry_after_parses_delta_seconds_and_ignores_the_date_form() {
        assert_eq!(parse_retry_after("3"), Some(Duration::from_secs(3)));
        assert_eq!(parse_retry_after("  7 "), Some(Duration::from_secs(7)));
        assert_eq!(parse_retry_after("0"), Some(Duration::ZERO));
        // The HTTP-date form is deliberately not honored: it would require
        // trusting the client clock to agree with the server's, and a skewed
        // clock turns the hint into a no-op or a multi-hour stall.
        assert_eq!(parse_retry_after("Wed, 21 Oct 2026 07:28:00 GMT"), None);
        assert_eq!(parse_retry_after("garbage"), None);
        assert_eq!(parse_retry_after("-5"), None);
        // Not clamped to MAX_DELAY: that cap governs the computed backoff,
        // while §16.1 makes the hint a floor with no ceiling. Clamping would
        // retry sooner than the server said it would be ready.
        assert_eq!(
            parse_retry_after("86400"),
            Some(Duration::from_secs(86_400))
        );
    }

    /// Records delays instead of taking them, so the attempt-cap and
    /// delay-sequence tests run instantly (§16.7).
    #[derive(Default)]
    struct RecordingSleeper {
        delays: std::sync::Mutex<Vec<Duration>>,
    }
    impl Sleeper for RecordingSleeper {
        fn sleep(&self, d: Duration) -> std::pin::Pin<Box<dyn Future<Output = ()> + Send + '_>> {
            self.delays.lock().unwrap().push(d);
            Box::pin(std::future::ready(()))
        }
    }

    fn runner<'a>(
        enabled: bool,
        telemetry: &'a Telemetry,
        jitter: &'a dyn Jitter,
        sleeper: &'a dyn Sleeper,
    ) -> RetryRunner<'a> {
        RetryRunner {
            enabled,
            operation: "check_access",
            telemetry,
            jitter,
            sleeper,
        }
    }

    #[tokio::test]
    async fn a_permanently_failing_operation_makes_exactly_three_attempts() {
        let tel = Telemetry::default();
        let sleeper = RecordingSleeper::default();
        let calls = std::sync::atomic::AtomicU32::new(0);

        let out: Result<(), _> = runner(true, &tel, &Pinned(1.0), &sleeper)
            .run(|_| {
                calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                async { Err(Attempt::bare(AxiamError::network("down"))) }
            })
            .await;

        assert!(out.is_err());
        // Exactly 3 — not 2, not 4. The cap is the whole point of "bounded".
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 3);
        // …and the delay sequence with jitter pinned to its maximum.
        assert_eq!(
            *sleeper.delays.lock().unwrap(),
            vec![Duration::from_millis(200), Duration::from_millis(400)]
        );
    }

    #[tokio::test]
    async fn a_decisive_failure_makes_exactly_one_attempt() {
        // A 401 and a 403 are answers, not transport failures. Retrying either
        // reproduces the identical rejection and wastes the caller's latency.
        for decisive in ["auth", "authz"] {
            let tel = Telemetry::default();
            let sleeper = RecordingSleeper::default();
            let calls = std::sync::atomic::AtomicU32::new(0);

            let out: Result<(), _> = runner(true, &tel, &Pinned(1.0), &sleeper)
                .run(|_| {
                    calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    async move {
                        Err(Attempt::bare(if decisive == "auth" {
                            AxiamError::auth("401")
                        } else {
                            AxiamError::authz("403", None, None)
                        }))
                    }
                })
                .await;

            assert!(out.is_err(), "{decisive} must surface");
            assert_eq!(
                calls.load(std::sync::atomic::Ordering::SeqCst),
                1,
                "{decisive} must not be retried"
            );
            assert!(sleeper.delays.lock().unwrap().is_empty());
        }
    }

    #[tokio::test]
    async fn the_disable_switch_yields_exactly_one_attempt_even_on_a_503() {
        // The switch exists for callers who own their own retry layer. With it
        // off, a retryable failure must still be surfaced after one attempt.
        let tel = Telemetry::default();
        let sleeper = RecordingSleeper::default();
        let calls = std::sync::atomic::AtomicU32::new(0);

        let out: Result<(), _> = runner(false, &tel, &Pinned(1.0), &sleeper)
            .run(|_| {
                calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                async { Err(Attempt::bare(AxiamError::network("503"))) }
            })
            .await;

        assert!(out.is_err());
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert!(sleeper.delays.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_retry_that_then_succeeds_returns_the_value_and_emits_the_event() {
        // §16.5: a retried-then-succeeded call is otherwise invisible to the
        // caller — a slow success with no signal the server is failing.
        let events = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let sink_events = events.clone();
        let tel = Telemetry::new(Some(std::sync::Arc::new(
            move |e: &TelemetryEvent| match e {
                TelemetryEvent::Retry { attempt, delay, .. } => sink_events
                    .lock()
                    .unwrap()
                    .push(format!("retry {attempt} {delay:?}")),
                _ => {}
            },
        )));
        let sleeper = RecordingSleeper::default();
        let calls = std::sync::atomic::AtomicU32::new(0);

        let out = runner(true, &tel, &Pinned(1.0), &sleeper)
            .run(|_| {
                let n = calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                async move {
                    if n == 0 {
                        Err(Attempt::bare(AxiamError::network("transient")))
                    } else {
                        Ok(42u32)
                    }
                }
            })
            .await;

        assert_eq!(out.unwrap(), 42);
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 2);
        assert_eq!(events.lock().unwrap().len(), 1);
        assert!(events.lock().unwrap()[0].starts_with("retry 1 "));
    }

    #[tokio::test]
    async fn a_panicking_hook_does_not_fail_the_operation() {
        // §19.2 rule 2 — telemetry may not fail an authorization check.
        let tel = Telemetry::new(Some(std::sync::Arc::new(|_: &TelemetryEvent| {
            panic!("hook exploded");
        })));
        let sleeper = RecordingSleeper::default();
        let calls = std::sync::atomic::AtomicU32::new(0);

        let out = runner(true, &tel, &Pinned(0.0), &sleeper)
            .run(|_| {
                let n = calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                async move {
                    if n == 0 {
                        Err(Attempt::bare(AxiamError::network("transient")))
                    } else {
                        Ok(7u32)
                    }
                }
            })
            .await;

        assert_eq!(out.unwrap(), 7);
    }

    #[tokio::test]
    async fn a_server_hint_lengthens_the_recorded_wait() {
        let tel = Telemetry::default();
        let sleeper = RecordingSleeper::default();

        let out: Result<(), _> = runner(true, &tel, &Pinned(1.0), &sleeper)
            .run(|_| async {
                Err(Attempt {
                    err: AxiamError::network("429"),
                    retry_after: Some(Duration::from_secs(2)),
                })
            })
            .await;

        assert!(out.is_err());
        assert_eq!(
            *sleeper.delays.lock().unwrap(),
            vec![Duration::from_secs(2), Duration::from_secs(2)]
        );
    }

    #[test]
    fn the_production_jitter_source_stays_in_range() {
        let j = ThreadRngJitter;
        for _ in 0..1_000 {
            let f = j.fraction();
            assert!((0.0..=1.0).contains(&f), "fraction out of range: {f}");
        }
    }
}
