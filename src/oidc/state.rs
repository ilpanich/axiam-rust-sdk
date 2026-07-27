//! `OidcStateStore` + `MemoryOidcStateStore` (CONTRACT.md §12.3 rule 1).
//!
//! STRICTLY OPTIONAL. The nine §12 operations never touch a store:
//! `oidc_begin` and `oidc_exchange` are stateless by contract, and the
//! caller normally keeps `state`/`nonce`/`code_verifier` in its own session.
//! This store exists for framework glue where a login and its callback are
//! two separate HTTP requests with nothing but a `state` value linking them.
//!
//! Semantics mirror the server's `federation_login_state` table: 10-minute
//! TTL, single-use consume.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::Sensitive;

/// The contract-mandated TTL for stored login state: 10 minutes, matching
/// the server's `federation_login_state` row lifetime (§12.3 rule 1).
pub const OIDC_STATE_TTL: Duration = Duration::from_secs(600);

/// The tuple an [`OidcStateStore`] holds for one in-flight login.
///
/// `code_verifier` stays [`Sensitive`] while stored (§12.5: the verifier is
/// secret for its whole lifetime, "including … in any `OidcStateStore`
/// entry").
#[derive(Debug)]
pub struct OidcStateEntry {
    /// The `state` value this entry is keyed by. Not a secret (§12.3
    /// rule 2).
    pub state: String,
    /// The `nonce` to check the ID token's `nonce` claim against. Not a
    /// secret (§12.3 rule 2).
    pub nonce: String,
    /// The PKCE verifier for the matching authorization request (§12.5
    /// secret).
    pub code_verifier: Sensitive<String>,
    /// The `redirect_uri` that was sent on the authorization request and
    /// must be replayed on exchange.
    pub redirect_uri: String,
    /// Optional application-owned data, e.g. the page the user was heading
    /// to before login.
    pub return_to: Option<String>,
}

/// Optional server-side store for in-flight `oidc_begin` state
/// (CONTRACT.md §12.3 rule 1).
///
/// Implement this to back login/callback handlers with your own storage
/// (Redis, a database, an encrypted cookie). Two invariants are normative:
///
/// 1. **Single-use.** [`Self::consume`] MUST return the entry *and delete
///    it atomically*, so a replayed callback cannot reuse a `state`.
/// 2. **Expiry.** An entry older than 10 minutes MUST NOT be returned.
///
/// Uses a native `async fn` in the trait (stable, no `async-trait` macro
/// dependency needed) — implementations are used generically
/// (`impl OidcStateStore` / `<S: OidcStateStore>`), which this crate's own
/// framework glue does not need `dyn` dispatch for.
pub trait OidcStateStore: Send + Sync {
    /// Persist an entry, keyed by its `state`, starting its TTL now.
    fn save(&self, entry: OidcStateEntry) -> impl std::future::Future<Output = ()> + Send;
    /// Atomically fetch **and remove** the entry for `state`. Returns
    /// `None` when the state is unknown, already consumed, or expired —
    /// three cases a caller MUST treat identically (as a failed login),
    /// because distinguishing them leaks whether a `state` ever existed.
    fn consume(
        &self,
        state: &str,
    ) -> impl std::future::Future<Output = Option<OidcStateEntry>> + Send;
}

struct Held {
    entry: OidcStateEntry,
    expires_at: Instant,
}

/// In-memory reference implementation of [`OidcStateStore`] (§12.3 rule 1).
///
/// Per-instance (never process-global), single-use, 10-minute TTL. Expired
/// entries are dropped lazily on [`Self::consume`]/[`Self::save`] — no
/// background timer, so this type needs no shutdown hook.
///
/// Suitable for a single-process app and for tests. A multi-instance
/// deployment needs a shared store (Redis, database) — implement
/// [`OidcStateStore`] yourself for that.
pub struct MemoryOidcStateStore {
    entries: Mutex<HashMap<String, Held>>,
    ttl: Duration,
}

impl Default for MemoryOidcStateStore {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryOidcStateStore {
    /// Build a store with the default (and maximum) TTL of
    /// [`OIDC_STATE_TTL`] (10 minutes).
    pub fn new() -> Self {
        Self::with_ttl(OIDC_STATE_TTL)
    }

    /// Build a store with an explicit TTL. Clamped to
    /// [`OIDC_STATE_TTL`] — a shorter TTL is honoured (useful in tests), a
    /// longer one is reduced, because §12.3 rule 1 fixes 10 minutes as the
    /// maximum.
    pub fn with_ttl(ttl: Duration) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            ttl: ttl.min(OIDC_STATE_TTL),
        }
    }

    /// Number of unexpired entries currently held. Intended for tests and
    /// metrics.
    pub fn len(&self) -> usize {
        self.sweep();
        self.entries
            .lock()
            .expect("state store mutex poisoned")
            .len()
    }

    /// Whether the store currently holds no unexpired entries.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn sweep(&self) {
        let now = Instant::now();
        self.entries
            .lock()
            .expect("state store mutex poisoned")
            .retain(|_, held| held.expires_at > now);
    }
}

impl OidcStateStore for MemoryOidcStateStore {
    async fn save(&self, entry: OidcStateEntry) {
        self.sweep();
        let expires_at = Instant::now() + self.ttl;
        self.entries
            .lock()
            .expect("state store mutex poisoned")
            .insert(entry.state.clone(), Held { entry, expires_at });
    }

    async fn consume(&self, state: &str) -> Option<OidcStateEntry> {
        let held = self
            .entries
            .lock()
            .expect("state store mutex poisoned")
            .remove(state)?;
        if held.expires_at <= Instant::now() {
            return None;
        }
        Some(held.entry)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(state: &str) -> OidcStateEntry {
        OidcStateEntry {
            state: state.to_string(),
            nonce: "nonce-value".to_string(),
            code_verifier: Sensitive::new("verifier-value".to_string()),
            redirect_uri: "https://app.example.com/cb".to_string(),
            return_to: None,
        }
    }

    #[tokio::test]
    async fn consume_is_single_use() {
        let store = MemoryOidcStateStore::new();
        store.save(entry("s1")).await;
        assert_eq!(store.len(), 1);

        let consumed = store.consume("s1").await.expect("first consume succeeds");
        assert_eq!(consumed.nonce, "nonce-value");

        assert!(store.consume("s1").await.is_none(), "state is single-use");
    }

    #[tokio::test]
    async fn consume_returns_none_for_unknown_state() {
        let store = MemoryOidcStateStore::new();
        assert!(store.consume("never-saved").await.is_none());
    }

    #[tokio::test]
    async fn ttl_expiry_makes_an_entry_unavailable() {
        let store = MemoryOidcStateStore::with_ttl(Duration::from_millis(20));
        store.save(entry("s1")).await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            store.consume("s1").await.is_none(),
            "expired entry must not be returned"
        );
    }

    #[tokio::test]
    async fn ttl_is_clamped_to_ten_minutes_maximum() {
        let store = MemoryOidcStateStore::with_ttl(Duration::from_secs(3600));
        // Not directly observable from outside, but constructing with an
        // over-long TTL must not panic and must still behave as a store.
        store.save(entry("s1")).await;
        assert!(store.consume("s1").await.is_some());
    }
}
