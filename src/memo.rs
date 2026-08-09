//! Client-side decision memo — CONTRACT.md §17.
//!
//! **Disabled by default.** §11.2 rule 6's ban on caching allow/deny decisions
//! is still the default behaviour; this module is the single opt-in exception
//! that section carves out, and a caller has to switch it on having read what
//! it costs them.
//!
//! # What it costs
//!
//! The staleness bound is the TTL, **in both directions**. A grant revoked on
//! the server can still read as `allowed` for up to the TTL, and a grant just
//! added can still read as denied for up to the TTL. That second direction is
//! the one that surprises people: **reads-your-own-writes is not guaranteed.**
//! An admin UI that grants a role and immediately re-checks is the case that
//! breaks, and it breaks silently.
//!
//! This mirrors the server's own bound rather than inventing a second staleness
//! story — `AXIAM__AUTHZ__DECISION_CACHE_TTL_SECS` (default 5 s) and
//! `AXIAM__AUTH__SESSION_VALIDATION_CACHE_TTL_SECS` (default 0, off) make the
//! same trade server-side. One deliberate difference: the server's setting is
//! an unclamped `u64`, so an operator can configure a multi-hour staleness
//! window. [`MAX_TTL`] clamps this one at 5 s, because the client has no reason
//! to repeat that.
//!
//! # Why allows and denies are cached identically
//!
//! §17.1 rule 4. Caching only one of them would make the two outcomes take
//! measurably different times, leaking which one occurred to anyone who can
//! observe latency — and it would surprise every reader who assumed a cache is
//! a cache. Uniform is both safer to reason about and simpler to implement.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use uuid::Uuid;

use crate::rest::authz::AccessDecision;

/// The §17.1 rule 2 ceiling. A configured TTL above this is clamped, not
/// rejected: a caller who asked for 60 s wants caching, and silently giving
/// them the maximum safe value beats failing construction.
pub const MAX_TTL: Duration = Duration::from_secs(5);

/// Entry cap before FIFO eviction (§17.1 rule 8). The memo is a latency
/// optimisation, so dropping an entry is always correct and eviction needs no
/// coordination.
const MAX_ENTRIES: usize = 1024;

/// The §17.1 rule 3 key: all four components, with absent distinguished from
/// present. A memo that ignored `scope` would answer a narrower question with a
/// broader answer.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct MemoKey {
    subject_id: Option<Uuid>,
    resource_id: Uuid,
    action: String,
    scope: Option<String>,
}

impl MemoKey {
    pub(crate) fn new(
        subject_id: Option<Uuid>,
        resource_id: Uuid,
        action: &str,
        scope: Option<&str>,
    ) -> Self {
        Self {
            subject_id,
            resource_id,
            action: action.to_string(),
            scope: scope.map(str::to_string),
        }
    }
}

struct Entry {
    decision: AccessDecision,
    stored_at: Instant,
}

/// A bounded, TTL-clamped decision memo.
///
/// `ttl == Duration::ZERO` means **disabled** — not "cache for zero seconds".
/// That is the default, and [`Self::get`]/[`Self::put`] both become no-ops.
pub(crate) struct DecisionMemo {
    ttl: Duration,
    entries: Mutex<HashMap<MemoKey, Entry>>,
    /// Insertion order, for FIFO eviction at the cap.
    order: Mutex<std::collections::VecDeque<MemoKey>>,
}

impl DecisionMemo {
    /// Build a memo with `ttl`, clamped to [`MAX_TTL`] (§17.1 rule 2).
    pub(crate) fn new(ttl: Duration) -> Self {
        Self {
            ttl: ttl.min(MAX_TTL),
            entries: Mutex::new(HashMap::new()),
            order: Mutex::new(std::collections::VecDeque::new()),
        }
    }

    /// Whether this memo does anything. `false` for the default configuration.
    pub(crate) fn is_enabled(&self) -> bool {
        !self.ttl.is_zero()
    }

    /// The effective TTL after clamping.
    #[cfg(test)]
    pub(crate) fn ttl(&self) -> Duration {
        self.ttl
    }

    /// A live decision for `key`, if one is memoized and unexpired.
    ///
    /// `now` is injected so the TTL can be tested without sleeping.
    pub(crate) fn get_at(&self, key: &MemoKey, now: Instant) -> Option<AccessDecision> {
        if !self.is_enabled() {
            return None;
        }
        let entries = self.entries.lock().ok()?;
        let entry = entries.get(key)?;
        if now.duration_since(entry.stored_at) >= self.ttl {
            return None;
        }
        // Cloned whole, including `reason_code`: §17.1 rule 5 forbids returning
        // `allowed` while dropping the code, which would make the field
        // intermittently absent — worse than never having had it.
        Some(entry.decision.clone())
    }

    /// Memoize a decision the server actually returned.
    ///
    /// Only successful decisions reach here. §17.1 rule 7 forbids negative-
    /// caching a failure: memoizing a `NetworkError` as a deny would turn a
    /// blip into a TTL-long outage, and memoizing it as an allow is
    /// unthinkable. That rule is enforced at the call site by only invoking
    /// this on the `Ok` path.
    pub(crate) fn put_at(&self, key: MemoKey, decision: &AccessDecision, now: Instant) {
        if !self.is_enabled() {
            return;
        }
        let (Ok(mut entries), Ok(mut order)) = (self.entries.lock(), self.order.lock()) else {
            // A poisoned lock means another thread panicked mid-update. The
            // memo is an optimisation; losing it is always safe.
            return;
        };
        if entries
            .insert(
                key.clone(),
                Entry {
                    decision: decision.clone(),
                    stored_at: now,
                },
            )
            .is_none()
        {
            order.push_back(key);
        }
        while order.len() > MAX_ENTRIES {
            if let Some(oldest) = order.pop_front() {
                entries.remove(&oldest);
            }
        }
    }

    /// Drop every entry (§17.1 rule 9).
    ///
    /// Called on `login`, `logout` and `refresh`. Entries are keyed by subject,
    /// not by session, so a re-authentication as a *different* principal would
    /// otherwise read the previous principal's decisions.
    pub(crate) fn clear(&self) {
        if let Ok(mut entries) = self.entries.lock() {
            entries.clear();
        }
        if let Ok(mut order) = self.order.lock() {
            order.clear();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decision(allowed: bool, code: &str) -> AccessDecision {
        AccessDecision {
            allowed,
            reason: None,
            reason_code: Some(code.to_string()),
        }
    }

    fn key(action: &str, scope: Option<&str>) -> MemoKey {
        MemoKey::new(None, Uuid::nil(), action, scope)
    }

    #[test]
    fn the_default_is_disabled_and_never_answers() {
        let memo = DecisionMemo::new(Duration::ZERO);
        assert!(!memo.is_enabled());

        let now = Instant::now();
        memo.put_at(key("read", None), &decision(true, "allowed"), now);
        assert!(memo.get_at(&key("read", None), now).is_none());
    }

    #[test]
    fn a_ttl_above_the_ceiling_is_clamped_not_rejected() {
        // §17.1 rule 2. The server's equivalent setting is unclamped; the
        // client has no reason to repeat that.
        assert_eq!(DecisionMemo::new(Duration::from_secs(60)).ttl(), MAX_TTL);
        assert_eq!(DecisionMemo::new(Duration::from_secs(5)).ttl(), MAX_TTL);
        assert_eq!(
            DecisionMemo::new(Duration::from_secs(2)).ttl(),
            Duration::from_secs(2)
        );
    }

    #[test]
    fn a_hit_inside_the_ttl_returns_the_whole_decision() {
        let memo = DecisionMemo::new(Duration::from_secs(5));
        let now = Instant::now();
        memo.put_at(key("read", None), &decision(false, "denied_by_rule"), now);

        let hit = memo
            .get_at(&key("read", None), now + Duration::from_secs(4))
            .expect("still live");
        assert!(!hit.allowed);
        // §17.1 rule 5: the code rides along, never dropped.
        assert_eq!(hit.reason_code.as_deref(), Some("denied_by_rule"));
    }

    #[test]
    fn an_entry_expires_exactly_at_the_ttl() {
        let memo = DecisionMemo::new(Duration::from_secs(5));
        let now = Instant::now();
        memo.put_at(key("read", None), &decision(true, "allowed"), now);

        assert!(
            memo.get_at(&key("read", None), now + Duration::from_millis(4_999))
                .is_some()
        );
        // At exactly the TTL the entry is gone: the bound is what the caller
        // was promised, so it must not be exceeded by even a millisecond.
        assert!(
            memo.get_at(&key("read", None), now + Duration::from_secs(5))
                .is_none()
        );
    }

    #[test]
    fn allows_and_denies_are_memoized_identically() {
        // §17.1 rule 4. Caching only one would make the two outcomes take
        // measurably different times and leak which occurred.
        let memo = DecisionMemo::new(Duration::from_secs(5));
        let now = Instant::now();

        memo.put_at(key("allow-me", None), &decision(true, "allowed"), now);
        memo.put_at(key("deny-me", None), &decision(false, "no_grant"), now);

        assert!(memo.get_at(&key("allow-me", None), now).unwrap().allowed);
        assert!(!memo.get_at(&key("deny-me", None), now).unwrap().allowed);
    }

    #[test]
    fn every_key_component_is_load_bearing() {
        // §17.1 rule 3 — a memo that ignored any of the four would answer a
        // different question than the one asked.
        let memo = DecisionMemo::new(Duration::from_secs(5));
        let now = Instant::now();
        let base = MemoKey::new(None, Uuid::nil(), "read", None);
        memo.put_at(base.clone(), &decision(true, "allowed"), now);

        assert!(memo.get_at(&base, now).is_some());
        // Different action.
        assert!(memo.get_at(&key("write", None), now).is_none());
        // Different scope — and crucially, a *present* scope must not hit an
        // absent-scope entry.
        assert!(memo.get_at(&key("read", Some("col-a")), now).is_none());
        // Different resource.
        assert!(
            memo.get_at(&MemoKey::new(None, Uuid::from_u128(7), "read", None), now)
                .is_none()
        );
        // Different subject.
        assert!(
            memo.get_at(
                &MemoKey::new(Some(Uuid::from_u128(9)), Uuid::nil(), "read", None),
                now
            )
            .is_none()
        );
    }

    #[test]
    fn an_absent_scope_and_a_present_scope_are_distinct_keys() {
        let memo = DecisionMemo::new(Duration::from_secs(5));
        let now = Instant::now();
        memo.put_at(key("read", None), &decision(true, "allowed"), now);
        memo.put_at(
            key("read", Some("col-a")),
            &decision(false, "no_grant"),
            now,
        );

        assert!(memo.get_at(&key("read", None), now).unwrap().allowed);
        assert!(
            !memo
                .get_at(&key("read", Some("col-a")), now)
                .unwrap()
                .allowed
        );
    }

    #[test]
    fn clear_drops_everything() {
        // §17.1 rule 9 — entries are keyed by subject, not session, so a
        // re-authentication as a different principal must not inherit them.
        let memo = DecisionMemo::new(Duration::from_secs(5));
        let now = Instant::now();
        memo.put_at(key("read", None), &decision(true, "allowed"), now);
        assert!(memo.get_at(&key("read", None), now).is_some());

        memo.clear();
        assert!(memo.get_at(&key("read", None), now).is_none());
    }

    #[test]
    fn the_entry_cap_evicts_rather_than_growing() {
        let memo = DecisionMemo::new(Duration::from_secs(5));
        let now = Instant::now();
        for i in 0..(MAX_ENTRIES + 50) {
            memo.put_at(
                MemoKey::new(None, Uuid::from_u128(i as u128), "read", None),
                &decision(true, "allowed"),
                now,
            );
        }
        assert!(memo.entries.lock().unwrap().len() <= MAX_ENTRIES);
        // FIFO: the oldest are the ones gone.
        assert!(
            memo.get_at(&MemoKey::new(None, Uuid::from_u128(0), "read", None), now)
                .is_none()
        );
        assert!(
            memo.get_at(
                &MemoKey::new(
                    None,
                    Uuid::from_u128((MAX_ENTRIES + 49) as u128),
                    "read",
                    None
                ),
                now
            )
            .is_some()
        );
    }
}
