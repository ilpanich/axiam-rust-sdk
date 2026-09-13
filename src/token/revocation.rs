//! The optional session-revocation feed poller (CONTRACT.md §10.4, contract
//! 1.44 — AXIAM threats T-39 and T-143).
//!
//! # What this narrows, and what it is not
//!
//! An AXIAM access token is self-contained and valid for up to fifteen
//! minutes, and [`JwksVerifier`](super::jwks::JwksVerifier) verifies it
//! locally. A logout, a role removal or an account disable therefore does not
//! reach a token already in a caller's hands until it expires — §10.2 records
//! that, and the documented answer has been "route the decision through gRPC
//! introspection instead", which is correct and costs a round trip **per
//! request**.
//!
//! A deployment may publish `GET /oauth2/revocations`: the base64url-unpadded
//! SHA-256 of every session id revoked within the last access-token lifetime.
//! A guard that polls it rejects a revoked session within **one poll interval**
//! instead of one token lifetime, for one cacheable fetch per interval.
//!
//! It is **not a control**, and every rule below follows from that:
//!
//! * **Default off.** Nothing polls unless a caller attaches one.
//! * **Never on the request path.** [`RevocationFeed::is_revoked`] answers from
//!   the cached set and, at most, starts a refresh whose result the *next*
//!   caller sees. A verify never waits on a network fetch.
//! * **Never fail closed.** An unreachable feed, a non-`200`, a body that does
//!   not parse, an `alg` this build does not know — every one of them behaves
//!   exactly as no feed at all. Not as an empty list: an empty list asserts
//!   that nothing has been revoked, which is a guard that silently honours no
//!   revocations while appearing to honour them.
//! * **It only ever rejects.** Every §10.1 rule runs first and still decides.
//!   The feed can turn an accept into a reject and never the reverse.
//! * **A token with no `sid` is never matched.** There is no session behind a
//!   client-credentials token, an RPT or a token exchange, and hashing `jti`
//!   instead would match nothing while looking like it worked.

use std::collections::HashSet;
use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};
use tokio::sync::RwLock;

use crate::error::AxiamError;
use crate::time::{Duration, Instant};

/// The only digest the feed publishes, and the only one this poller accepts.
///
/// A document naming anything else is treated as unusable — exactly as an
/// unreachable feed is — rather than as a list of entries that happen not to
/// match. Silently matching nothing is how a guard ends up reporting that it
/// honours revocations while honouring none.
const SUPPORTED_ALG: &str = "SHA-256";

/// The shortest interval a caller may configure (§10.4 rule 2).
///
/// Bounded because the feed is one deployment-wide document and a fleet of
/// guards polling it at a hundred milliseconds is a load source rather than a
/// security improvement. The floor is applied by clamping, not by refusing: a
/// caller who asked for something faster gets the fastest thing on offer.
pub const MIN_POLL_INTERVAL: Duration = Duration::from_secs(15);

/// The default interval, and the one §10.4 recommends.
pub const DEFAULT_POLL_INTERVAL: Duration = Duration::from_secs(30);

/// The largest number of entries kept in the cache (§10.4 rule 2).
///
/// The server bounds the document by its own revocation rate over one token
/// lifetime, so this is defence against a server that stops doing so — a cache
/// with no ceiling is an allocation an unauthenticated endpoint controls.
/// Overflow drops the **whole** set rather than truncating it: a truncated set
/// is a guard that admits some revoked sessions and reports none, which is
/// worse than a guard that admits all of them and says the feed is unusable.
pub const MAX_ENTRIES: usize = 100_000;

/// The feed document, as published.
#[derive(Debug, serde::Deserialize)]
struct FeedDocument {
    alg: String,
    #[serde(default)]
    revoked: Vec<String>,
}

/// What the poller currently believes, and when it last learned it.
#[derive(Debug, Default)]
struct FeedState {
    /// `None` means "never successfully fetched" — which is not the same as
    /// an empty set, and is why this is an `Option` rather than a bare
    /// `HashSet`.
    entries: Option<HashSet<String>>,
    last_success: Option<Instant>,
    last_attempt: Option<Instant>,
}

/// A poller for one deployment's revocation feed.
///
/// Cheap to clone: the state is shared, so several guards built from one feed
/// poll once between them rather than once each.
#[derive(Clone)]
pub struct RevocationFeed {
    inner: Arc<FeedInner>,
}

struct FeedInner {
    http_client: reqwest::Client,
    feed_url: url::Url,
    poll_interval: Duration,
    state: RwLock<FeedState>,
    /// Serializes refreshers, so a burst of guards that all notice the cache
    /// is stale produces one fetch rather than one each — the same shape as
    /// `JwksVerifier`'s fetch lock, and for the same reason.
    fetch_lock: tokio::sync::Mutex<()>,
}

impl std::fmt::Debug for RevocationFeed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RevocationFeed")
            .field("feed_url", &self.inner.feed_url.as_str())
            .field("poll_interval", &self.inner.poll_interval)
            .finish_non_exhaustive()
    }
}

impl RevocationFeed {
    /// Poll `{base_url}/oauth2/revocations` on the default interval.
    ///
    /// # Errors
    ///
    /// Only if `base_url` cannot be joined with the feed path. A deployment
    /// that does not publish the feed is not an error here — it is discovered
    /// on the first poll, and behaves as no feed at all from then on.
    pub fn new(http_client: reqwest::Client, base_url: &url::Url) -> Result<Self, AxiamError> {
        let feed_url = base_url
            .join("/oauth2/revocations")
            .map_err(|e| AxiamError::Network {
                message: format!("invalid revocation feed URL: {e}"),
                source: None,
            })?;
        Ok(Self {
            inner: Arc::new(FeedInner {
                http_client,
                feed_url,
                poll_interval: DEFAULT_POLL_INTERVAL,
                state: RwLock::new(FeedState::default()),
                fetch_lock: tokio::sync::Mutex::new(()),
            }),
        })
    }

    /// Override the poll interval, clamped to [`MIN_POLL_INTERVAL`].
    #[must_use]
    pub fn with_poll_interval(mut self, interval: Duration) -> Self {
        let clamped = interval.max(MIN_POLL_INTERVAL);
        // The `Arc` is not yet shared at build time in any supported usage, so
        // rebuilding is cheap and keeps `FeedInner`'s fields immutable —
        // which is what lets `is_revoked` read them without a lock.
        let inner = Arc::get_mut(&mut self.inner);
        match inner {
            Some(inner) => inner.poll_interval = clamped,
            None => {
                let old = &self.inner;
                self.inner = Arc::new(FeedInner {
                    http_client: old.http_client.clone(),
                    feed_url: old.feed_url.clone(),
                    poll_interval: clamped,
                    state: RwLock::new(FeedState::default()),
                    fetch_lock: tokio::sync::Mutex::new(()),
                });
            }
        }
        self
    }

    /// The feed entry for a `sid`, as the server computes it.
    ///
    /// Base64url without padding over the claim's **exact string** — never a
    /// parsed-and-re-rendered UUID, or the answer depends on this crate's UUID
    /// parser rather than on the feed.
    #[must_use]
    pub fn entry_for(sid: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(sid.as_bytes());
        URL_SAFE_NO_PAD.encode(hasher.finalize())
    }

    /// Has this session been revoked, as far as this poller knows?
    ///
    /// `false` whenever the answer is not a confident yes — a feed never
    /// fetched, unreachable, malformed, or simply not listing this session.
    /// The caller admits the request in all of those cases, which is §10.4
    /// rule 3 and is the whole reason the feature is safe to turn on.
    ///
    /// Never blocks on the network. If the cache is older than the poll
    /// interval this starts a refresh and answers from what it currently has;
    /// the refreshed set is what the next caller sees.
    pub async fn is_revoked(&self, sid: &str) -> bool {
        self.refresh_if_stale().await;
        let state = self.inner.state.read().await;
        state
            .entries
            .as_ref()
            .is_some_and(|set| set.contains(&Self::entry_for(sid)))
    }

    /// Fetch now, whatever the interval says. For tests and for a caller that
    /// wants the first poll to have happened before it starts serving.
    pub async fn refresh(&self) {
        let _guard = self.inner.fetch_lock.lock().await;
        let fetched = self.fetch().await;
        let mut state = self.inner.state.write().await;
        state.last_attempt = Some(Instant::now());
        if let Some(entries) = fetched {
            state.entries = Some(entries);
            state.last_success = Some(Instant::now());
        }
        // On failure the previous set is deliberately left in place. It ages
        // out with `last_success` rather than being dropped on the first
        // hiccup, so a blip does not un-revoke a session the guard already
        // knows about.
    }

    async fn refresh_if_stale(&self) {
        let due = {
            let state = self.inner.state.read().await;
            match state.last_attempt {
                None => true,
                Some(at) => at.elapsed() >= self.inner.poll_interval,
            }
        };
        if due {
            self.refresh().await;
        }
    }

    /// One fetch. `None` for every kind of failure, which the caller treats
    /// identically — see the module docs on why "unusable" must not collapse
    /// into "empty".
    async fn fetch(&self) -> Option<HashSet<String>> {
        let response = self
            .inner
            .http_client
            .get(self.inner.feed_url.clone())
            .send()
            .await
            .ok()?;
        if !response.status().is_success() {
            return None;
        }
        let document: FeedDocument = response.json().await.ok()?;
        if document.alg != SUPPORTED_ALG {
            return None;
        }
        if document.revoked.len() > MAX_ENTRIES {
            return None;
        }
        Some(document.revoked.into_iter().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The wire format, pinned against the server's own vector. Eleven SDKs
    /// compute this independently; a change here is a change every one of them
    /// silently stops matching, which presents as "revocation stopped working"
    /// with nothing failing.
    #[test]
    fn the_entry_is_base64url_unpadded_sha256_of_the_claim_string() {
        let entry = RevocationFeed::entry_for("6f3e0a5c-1b2d-4e8f-9a7b-0c1d2e3f4a5b");
        assert_eq!(entry, "i9N2lYMTV4FhA0husWjGYCqJXXTb7_fMBuomhWjSsgQ");
        assert_eq!(entry.len(), 43);
        assert!(!entry.contains('+') && !entry.contains('/') && !entry.contains('='));
    }

    /// The claim is hashed as read. Parsing it to a UUID first and rendering
    /// it back would make the answer depend on this crate's parser rather than
    /// on the feed — and would quietly stop matching for any rendering the
    /// server does not use.
    #[test]
    fn the_entry_never_normalises_the_claim() {
        assert_ne!(
            RevocationFeed::entry_for("6F3E0A5C-1B2D-4E8F-9A7B-0C1D2E3F4A5B"),
            RevocationFeed::entry_for("6f3e0a5c-1b2d-4e8f-9a7b-0c1d2e3f4a5b"),
        );
    }

    #[test]
    fn the_poll_interval_is_clamped_rather_than_refused() {
        let client = reqwest::Client::new();
        let base = url::Url::parse("https://iam.example.test").unwrap();
        let feed = RevocationFeed::new(client, &base)
            .unwrap()
            .with_poll_interval(Duration::from_millis(1));
        assert_eq!(feed.inner.poll_interval, MIN_POLL_INTERVAL);
    }

    /// The `Debug` carries the URL and the interval and nothing that could be
    /// a session identifier — the cached set is the one thing in here that is
    /// derived from user data.
    #[test]
    fn the_debug_never_renders_the_cached_set() {
        let client = reqwest::Client::new();
        let base = url::Url::parse("https://iam.example.test").unwrap();
        let feed = RevocationFeed::new(client, &base).unwrap();
        let rendered = format!("{feed:?}");
        assert!(rendered.contains("oauth2/revocations"));
        assert!(!rendered.contains("entries"));
    }
}
