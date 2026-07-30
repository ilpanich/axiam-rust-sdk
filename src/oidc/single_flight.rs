//! `oidc_refresh`'s single-flight coalescer — CONTRACT.md §9 rules 1, 2, 4
//! and 5, applied to the CONTRACT.md §12.1 `oidc_refresh` operation.
//!
//! # Why this exists
//!
//! §9 rule 1 ("exactly one in-flight refresh") and §9 rule 2 ("result
//! sharing") are two halves of **one** requirement, and rule 2 spells out the
//! observable form: a burst of N concurrent callers MUST produce exactly one
//! refresh wire call, and all N MUST receive *that one call's* outcome. A bare
//! mutex satisfies only the first half — it serializes N callers, each of
//! which then issues its **own** `POST /oauth2/token`. AXIAM refresh tokens
//! are opaque, server-stored and **single-use with rotation**, so callers
//! 2..N would replay an already-consumed token and every one of them would
//! fail `invalid_grant`. Sharing the leader's result is what makes the rule
//! useful, not an optimization on top of it.
//!
//! # The invariant
//!
//! **The in-flight slot is a result-sharing channel, not a busy flag.**
//! Publication must therefore happen *before* the slot is vacated, so that a
//! caller reaching the slot at any instant either
//!
//! * finds it **occupied** and joins that burst's shared outcome, or
//! * finds it **empty**, in which case the previous refresh has already
//!   settled *and been published*, and this caller correctly starts a fresh
//!   one —
//!
//! and never the third thing: *empty with nothing published*, which is what
//! makes a second, doomed wire call happen.
//!
//! # The mechanism
//!
//! A leader/waiter election over a slot holding one shared publication — a
//! [`tokio::sync::watch`] channel whose value is this burst's
//! [`OidcRefreshState`]:
//!
//! * the first caller to find the slot empty installs a fresh publication in
//!   the `Running` state and becomes the **leader** — it alone performs the
//!   wire call;
//! * every caller that finds the slot holding a *joinable* publication
//!   subscribes to it and becomes a **waiter**, awaiting that publication's
//!   terminal state and making **no** wire call of its own;
//! * the leader **publishes first and retires second**: `send_replace`s the
//!   terminal state (`Settled`, or `Cancelled` from `Drop`) into the
//!   publication, then clears the slot;
//! * once the slot is empty, the burst is over: the next caller is a new
//!   leader running a genuinely fresh refresh.
//!
//! §9 rule 5 (contract 1.5) explicitly permits this **dedicated** guard
//! instance rather than reusing the §1 cookie-session guard
//! ([`crate::token::refresh_guard`]): that guard's API compares an observed
//! `axiam_access` cookie value against its own cache, a comparison with no
//! meaning for an OAuth2 `refresh_token` grant over a different token
//! namespace. The mechanism is free; the observable behaviour is not. A
//! "channel publishing a shared result" is one of the mechanisms rule 5 lists
//! by name.
//!
//! No new dependency: `tokio`'s `sync` feature is already enabled, and the
//! slot's lock is [`std::sync::Mutex`].
//!
//! # Why a value-retaining channel, and not `broadcast`
//!
//! This guard originally held a [`tokio::sync::broadcast::Sender`] and did the
//! opposite of the invariant above — it **retired the slot before sending**,
//! precisely *because* `broadcast` is not value-retaining: a receiver never
//! observes sends that predate its `subscribe()`, so a caller that subscribed
//! after the leader's single send would have hung until the sender dropped.
//! Retiring first avoided that lost wakeup, but opened a correctness window:
//! between the retire and the send the slot was **empty while the refresh had
//! already settled**, so a concurrent caller became a *second* leader and
//! issued a *second* `refresh_token` grant — replaying the token the leader
//! had just consumed, and failing `invalid_grant`. There is no `.await`
//! between those two statements, but on a multi-threaded runtime another
//! worker thread can land there, which makes this a real bug rather than a
//! theoretical one.
//!
//! [`tokio::sync::watch`] closes that window because it **retains its
//! value**: a receiver created *after* `send_replace` still observes the value
//! that is in the channel (that is exactly what
//! [`watch::Receiver::wait_for`] does — it evaluates its predicate against the
//! current value before it ever awaits a change). So the leader can publish
//! first and retire second, and a caller that arrives in between subscribes to
//! an already-`Settled` publication and gets the outcome immediately instead
//! of hanging or starting a doomed second grant. Two further properties fit:
//! `send_replace` cannot fail when there are no receivers (the old code had to
//! ignore a `send` error for the common single-caller case), and there is no
//! ring buffer, so no waiter can ever lag out of one.
//!
//! The alternative — an `Arc<OnceCell<..>>` or a shared boxed future in the
//! slot — is equally value-retaining, but it makes cancellation harder, not
//! easier: a `OnceCell` that is never initialized (the cancelled-leader case)
//! carries no way to *tell* the waiters so, and a shared future must be
//! `Clone` + poll-safe from many tasks. `watch` models exactly the three
//! states this protocol has, and its wake-up is edge-triggered on any of them.
//!
//! # Live, settled, and empty — why occupancy alone is not "join this"
//!
//! Publishing before retiring means the slot can legitimately hold a
//! *settled* publication for an instant. Occupancy therefore no longer
//! implies "a refresh is still running", and the three states are treated
//! distinctly by [`OidcRefreshInflight::elect`]:
//!
//! | slot state              | election                                     |
//! |-------------------------|----------------------------------------------|
//! | empty                   | **Leader** — fresh wire call                 |
//! | `Running`               | **Waiter** — awaits the leader's outcome     |
//! | `Settled(..)`           | **Waiter** — gets that outcome immediately   |
//! | `Cancelled`             | **Leader** — nothing will ever be published  |
//!
//! Joining a `Settled` publication cannot hand back a **stale** token set,
//! and the reason is structural rather than a timing argument: the slot is
//! the mutual exclusion. While a publication occupies it, no other refresh
//! can have been elected — so *no later rotation can exist anywhere in this
//! process*, and the settled outcome is by construction the newest one there
//! is. Contrast the failure mode this is deliberately not: a slot that
//! *keeps* a settled publication (a one-entry cache) would serve a caller
//! arriving minutes later a token from a refresh that completed before that
//! caller even started — the bug of the same family as the one fixed here,
//! and the reason the leader retires unconditionally, with no `.await`
//! between publishing and retiring, before it returns to its own caller.
//!
//! A caller that arrives once the slot is **empty** is thus the only kind
//! that could ever be served a superseded token, and it never is: it becomes
//! a leader and runs a fresh refresh (this is what
//! `a_caller_arriving_after_the_burst_settled_starts_a_fresh_refresh` pins
//! down).
//!
//! # Why a `std::sync::Mutex` and not a `tokio::sync::Mutex`
//!
//! Both critical sections here are tiny and fully synchronous — elect
//! (check/install) and retire (compare/clear) — so nothing is ever held
//! across an `.await`, which is the only reason to reach for the async mutex.
//! Using the std lock buys **cancel safety**: [`OidcRefreshLeader`] can settle
//! the publication and clear the slot from `Drop`, which cannot `.await`. That
//! matters, because a leader future dropped mid-flight (a
//! `tokio::time::timeout`, a cancelled `select!` branch, an aborted task)
//! would otherwise leave a publication stranded in the slot forever — every
//! later `oidc_refresh` would elect itself a waiter on a burst that will never
//! finish and hang permanently. With the drop guard, a cancelled leader
//! publishes the typed [`OidcRefreshState::Cancelled`] state — which wakes
//! every waiter with [`OidcRefreshCancelled`] rather than leaving them to
//! infer it from a closed channel — and then frees the slot, so the next
//! caller runs a normal refresh.
//!
//! [`watch::Receiver::wait_for`]: tokio::sync::watch::Receiver::wait_for

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use tokio::sync::watch;

use crate::AxiamError;

use super::exchange::OidcTokenSet;

/// The outcome the single in-flight `oidc_refresh` publishes to its waiters.
///
/// The error side is an [`Arc`] because [`AxiamError`] is not `Clone` (its
/// `Network` variant chains a `Box<dyn Error>`), while a shared publication's
/// value must be; waiters turn it back into an owned `AxiamError` via
/// [`AxiamError::clone_for_waiter`].
pub(crate) type OidcRefreshOutcome = Result<OidcTokenSet, Arc<AxiamError>>;

/// The three states of one burst's shared publication.
///
/// `Running` is the initial value; exactly one terminal value replaces it —
/// `Settled` from [`OidcRefreshLeader::publish`], or `Cancelled` from the
/// leader's `Drop`.
enum OidcRefreshState {
    /// The leader is performing its one wire call; no outcome yet.
    Running,
    /// The leader's wire call finished and this is its outcome. Retained by
    /// the channel, so a waiter that subscribes after this was published
    /// still observes it (see the module docs).
    ///
    /// Boxed so the two unit-like states do not each carry an
    /// [`OidcTokenSet`]-sized payload: `watch` stores its value inline, and
    /// this enum lives for the whole burst (`clippy::large_enum_variant`).
    Settled(Box<OidcRefreshOutcome>),
    /// The leader's future was dropped before it published (cancellation).
    /// Nothing will ever be published here: waiters must fail with
    /// [`OidcRefreshCancelled`] and the slot must not be joined again.
    Cancelled,
}

/// One burst's shared publication: the channel the leader publishes its
/// outcome on and every waiter of that burst reads.
///
/// Identified by [`Arc`] pointer identity, which is what lets
/// [`OidcRefreshInflight::retire`] clear *only its own* entry — a leader whose
/// publication has already been replaced (the cancelled-leader case) must
/// never clear a later leader's slot.
struct OidcRefreshPublication {
    tx: watch::Sender<OidcRefreshState>,
}

impl OidcRefreshPublication {
    fn running() -> Self {
        Self {
            tx: watch::channel(OidcRefreshState::Running).0,
        }
    }

    /// Subscribe unless this publication is already `Cancelled` (nothing will
    /// ever be published on it — see the live/settled/empty table in the
    /// module docs).
    fn subscribe_if_joinable(&self) -> Option<watch::Receiver<OidcRefreshState>> {
        let cancelled = matches!(*self.tx.borrow(), OidcRefreshState::Cancelled);
        if cancelled {
            None
        } else {
            Some(self.tx.subscribe())
        }
    }

    /// Publish a terminal state. Cannot fail: `send_replace` stores the value
    /// whether or not anyone is subscribed, and every later subscriber still
    /// observes it while this publication remains reachable.
    fn publish(&self, state: OidcRefreshState) {
        let _previous = self.tx.send_replace(state);
    }
}

type OidcRefreshSlot = Mutex<Option<Arc<OidcRefreshPublication>>>;

/// A test-only seam invoked *inside* the publish→retire window — see
/// [`OidcRefreshInflight::set_after_publish_hook`].
#[cfg(test)]
type AfterPublishHook = Arc<dyn Fn(&OidcRefreshInflight) + Send + Sync>;

/// The `oidc_refresh` in-flight slot held by
/// `AxiamClientInner::oidc_refresh_inflight`. Empty means "no refresh in
/// flight, and the previous one (if any) has already published its outcome";
/// occupied means "this is the current burst's shared publication".
pub(crate) struct OidcRefreshInflight {
    slot: OidcRefreshSlot,
    /// Test-only, and **never set in production**: no production code path
    /// calls [`Self::set_after_publish_hook`], and the field does not even
    /// exist outside `cfg(test)` builds. It exists so the publish→retire
    /// window — a window with no `.await` in it, which a test could otherwise
    /// only race for — can be pinned open deterministically.
    #[cfg(test)]
    after_publish: Mutex<Option<AfterPublishHook>>,
}

/// The outcome of one leader/waiter election — see
/// [`OidcRefreshInflight::elect`].
pub(crate) enum OidcRefreshElection<'a> {
    /// This caller won the election: it must perform exactly one wire call
    /// and then hand the outcome to [`OidcRefreshLeader::publish`].
    Leader(OidcRefreshLeader<'a>),
    /// A refresh was already in flight (or had just settled): await this
    /// waiter for that burst's outcome and make **no** wire call.
    Waiter(OidcRefreshWaiter),
}

/// A waiter's join handle on the current burst's shared publication.
pub(crate) struct OidcRefreshWaiter {
    rx: watch::Receiver<OidcRefreshState>,
}

/// The leader's future was dropped before it published an outcome — its wire
/// call was cancelled (a `timeout`, a cancelled `select!` branch, an aborted
/// task), so there is no outcome to share.
///
/// A distinct, clearly-typed signal rather than a channel-closed error:
/// §9 rule 3 forbids an automatic re-attempt, so this must surface to the
/// caller as an auth failure it can act on.
#[derive(Debug)]
pub(crate) struct OidcRefreshCancelled;

impl OidcRefreshWaiter {
    /// Await this burst's outcome (§9 rule 2), making no wire call.
    ///
    /// Returns immediately if the publication is already `Settled` — the
    /// value-retaining property the whole design rests on:
    /// [`watch::Receiver::wait_for`] evaluates its predicate against the
    /// channel's current value before awaiting a change, so an outcome
    /// published before this waiter subscribed is still delivered.
    ///
    /// [`watch::Receiver::wait_for`]: tokio::sync::watch::Receiver::wait_for
    pub(crate) async fn wait(mut self) -> Result<OidcRefreshOutcome, OidcRefreshCancelled> {
        match self
            .rx
            .wait_for(|state| !matches!(state, OidcRefreshState::Running))
            .await
        {
            // Cloned out of the borrow: every waiter of the burst gets its own
            // owned copy of the one wire call's outcome (§9 rule 2).
            Ok(state) => match &*state {
                OidcRefreshState::Settled(outcome) => Ok((**outcome).clone()),
                // `Running` is excluded by the predicate above; treating it
                // like cancellation keeps the match total without a panic
                // path.
                OidcRefreshState::Cancelled | OidcRefreshState::Running => {
                    Err(OidcRefreshCancelled)
                }
            },
            // Every sender dropped without publishing a terminal state. The
            // `Drop` guard makes this unreachable in practice (it publishes
            // `Cancelled` first), but a dropped publication means exactly the
            // same thing: no outcome is coming.
            Err(_) => Err(OidcRefreshCancelled),
        }
    }
}

impl OidcRefreshInflight {
    /// A slot with no refresh in flight.
    pub(crate) fn new() -> Self {
        Self {
            slot: Mutex::new(None),
            #[cfg(test)]
            after_publish: Mutex::new(None),
        }
    }

    /// Lock the slot, recovering from poisoning rather than panicking.
    ///
    /// The guarded value is a plain `Option<Arc<_>>` that cannot be left
    /// logically inconsistent by a panic mid-critical-section (both sections
    /// are a single assignment), so `into_inner` is the correct recovery: a
    /// panicking unrelated caller must not permanently disable refreshing.
    fn lock(&self) -> MutexGuard<'_, Option<Arc<OidcRefreshPublication>>> {
        self.slot.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Elect this caller as either the single leader or one of the waiters
    /// (§9 rules 1 and 2).
    ///
    /// Occupancy alone does not mean "join this burst" — see the
    /// live/settled/empty table in the module docs. A `Cancelled` publication
    /// is *replaced*, not joined; the cancelled leader's own retire is
    /// identity-checked, so it cannot clear the replacement.
    pub(crate) fn elect(&self) -> OidcRefreshElection<'_> {
        let mut slot = self.lock();
        if let Some(current) = slot.as_ref()
            && let Some(rx) = current.subscribe_if_joinable()
        {
            return OidcRefreshElection::Waiter(OidcRefreshWaiter { rx });
        }
        let publication = Arc::new(OidcRefreshPublication::running());
        *slot = Some(Arc::clone(&publication));
        OidcRefreshElection::Leader(OidcRefreshLeader {
            inflight: self,
            publication: Some(publication),
        })
    }

    /// Vacate the slot, but only if it still holds `mine`, so the next caller
    /// starts a fresh election.
    ///
    /// The identity check is what makes publish-then-retire safe: a leader
    /// whose publication was already replaced in the slot (a cancelled leader
    /// overtaken by the next one) must never clear the current burst's entry.
    fn retire(&self, mine: &Arc<OidcRefreshPublication>) {
        let mut slot = self.lock();
        if slot
            .as_ref()
            .is_some_and(|current| Arc::ptr_eq(current, mine))
        {
            *slot = None;
        }
    }

    /// Install the test-only publish→retire-window hook, which fires once at
    /// the next publication. Never called by production code — see the
    /// [`Self::after_publish`] field docs.
    #[cfg(test)]
    fn set_after_publish_hook(&self, hook: AfterPublishHook) {
        *self
            .after_publish
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(hook);
    }

    /// Run the test-only hook, if any, holding no lock while it runs (it
    /// calls back into [`Self::elect`]).
    ///
    /// **One-shot**: the hook is taken out before it runs, so a hook that
    /// itself drives another election — and therefore possibly another
    /// publication, via that election's `Drop` — cannot re-enter itself.
    #[cfg(test)]
    fn run_after_publish_hook(&self) {
        let hook = self
            .after_publish
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        if let Some(hook) = hook {
            hook(self);
        }
    }
}

/// The single elected performer of one `oidc_refresh` burst.
///
/// Holding one of these is the *permission* to make the wire call; every
/// other concurrent caller is an [`OidcRefreshElection::Waiter`]. Publishes
/// the outcome and then retires the slot on [`Self::publish`], or publishes
/// [`OidcRefreshState::Cancelled`] and retires on `Drop` if the leader's
/// future was cancelled before it got that far.
pub(crate) struct OidcRefreshLeader<'a> {
    inflight: &'a OidcRefreshInflight,
    /// `None` once a terminal state has been published, so a terminal state
    /// is published exactly once and `Drop` never contradicts `publish`.
    publication: Option<Arc<OidcRefreshPublication>>,
}

impl OidcRefreshLeader<'_> {
    /// Publish `result` to every waiter of this burst, then retire the slot
    /// (§9 rule 2).
    ///
    /// **Publication precedes retirement**, and that order is the whole point
    /// of this module: a caller reaching the slot in between joins the
    /// just-settled publication and receives this outcome, instead of finding
    /// an empty slot and issuing a second `refresh_token` grant that would
    /// replay the token this call just consumed. See the module docs for why
    /// the reverse order (which this guard used to do, out of a `broadcast`
    /// lost-wakeup constraint that `watch` does not have) was a bug, and for
    /// why the momentarily-settled slot cannot serve a stale token.
    ///
    /// Retiring is unconditional and immediate — no `.await` sits between the
    /// two steps — so the settled publication cannot survive into a later
    /// burst.
    pub(crate) fn publish(mut self, result: &Result<OidcTokenSet, AxiamError>) {
        let Some(publication) = self.publication.take() else {
            return;
        };
        let shared: OidcRefreshOutcome = match result {
            Ok(tokens) => Ok(tokens.clone()),
            Err(e) => Err(Arc::new(e.clone_for_waiter())),
        };
        publication.publish(OidcRefreshState::Settled(Box::new(shared)));
        #[cfg(test)]
        self.inflight.run_after_publish_hook();
        self.inflight.retire(&publication);
    }
}

impl Drop for OidcRefreshLeader<'_> {
    fn drop(&mut self) {
        // Only reached when the leader's future was dropped before
        // `publish` — i.e. cancellation. Publish the typed `Cancelled` state
        // first (so every waiter is woken with `OidcRefreshCancelled` instead
        // of hanging or having to interpret a closed channel), then free the
        // slot so `oidc_refresh` is not wedged permanently.
        if let Some(publication) = self.publication.take() {
            publication.publish(OidcRefreshState::Cancelled);
            #[cfg(test)]
            self.inflight.run_after_publish_hook();
            self.inflight.retire(&publication);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    fn token_set(access: &str) -> OidcTokenSet {
        OidcTokenSet {
            access_token: crate::Sensitive::new(access.to_string()),
            token_type: "Bearer".into(),
            expires_in: 900,
            scope: None,
            refresh_token: None,
            id_token: None,
            id_claims: None,
        }
    }

    /// A faithful stand-in for `AxiamClient::oidc_refresh`: the same
    /// elect → (wire call | wait) → publish protocol, with the wire call
    /// replaced by a counter so a test can assert how many grants a burst
    /// would have issued. `access` is the access token the *leader* would
    /// receive from the server, so a waiter handed the wrong burst's outcome
    /// is visible.
    async fn coalesced_refresh(
        inflight: &OidcRefreshInflight,
        wire_calls: &AtomicUsize,
        access: &str,
    ) -> Result<OidcTokenSet, AxiamError> {
        match inflight.elect() {
            OidcRefreshElection::Waiter(waiter) => match waiter.wait().await {
                Ok(Ok(tokens)) => Ok(tokens),
                Ok(Err(shared)) => Err(shared.clone_for_waiter()),
                Err(OidcRefreshCancelled) => Err(AxiamError::auth("the leader was cancelled")),
            },
            OidcRefreshElection::Leader(leader) => {
                wire_calls.fetch_add(1, Ordering::SeqCst);
                let result = Ok(token_set(access));
                leader.publish(&result);
                result
            }
        }
    }

    #[test]
    fn the_first_caller_leads_and_the_next_ones_wait() {
        let inflight = OidcRefreshInflight::new();
        let leader = match inflight.elect() {
            OidcRefreshElection::Leader(l) => l,
            OidcRefreshElection::Waiter(_) => panic!("first caller must lead"),
        };
        for _ in 0..4 {
            assert!(matches!(inflight.elect(), OidcRefreshElection::Waiter(_)));
        }
        leader.publish(&Ok(token_set("a")));
        // Slot retired: the next caller leads a fresh burst.
        assert!(matches!(inflight.elect(), OidcRefreshElection::Leader(_)));
    }

    #[tokio::test]
    async fn waiters_receive_the_leaders_success() {
        let inflight = OidcRefreshInflight::new();
        let leader = match inflight.elect() {
            OidcRefreshElection::Leader(l) => l,
            OidcRefreshElection::Waiter(_) => unreachable!(),
        };
        let mut waiters = Vec::new();
        for _ in 0..5 {
            match inflight.elect() {
                OidcRefreshElection::Waiter(w) => waiters.push(w),
                OidcRefreshElection::Leader(_) => panic!("only one leader per burst"),
            }
        }
        leader.publish(&Ok(token_set("shared-access")));
        for waiter in waiters {
            let outcome = waiter.wait().await.expect("leader published");
            assert_eq!(
                outcome.expect("success").access_token.expose(),
                "shared-access"
            );
        }
    }

    #[tokio::test]
    async fn waiters_receive_the_leaders_failure_with_the_oauth_payload_intact() {
        let inflight = OidcRefreshInflight::new();
        let leader = match inflight.elect() {
            OidcRefreshElection::Leader(l) => l,
            OidcRefreshElection::Waiter(_) => unreachable!(),
        };
        let waiter = match inflight.elect() {
            OidcRefreshElection::Waiter(w) => w,
            OidcRefreshElection::Leader(_) => unreachable!(),
        };
        leader.publish(&Err(AxiamError::oauth_protocol_error(
            "invalid_grant",
            "refresh token already used",
        )));
        let err = waiter.wait().await.expect("leader published").unwrap_err();
        assert_eq!(
            err.as_oauth_protocol_error().map(|o| o.error.as_str()),
            Some("invalid_grant")
        );
    }

    /// A leader future dropped without publishing (cancellation) must not
    /// wedge the slot, and its waiters must be woken with the typed
    /// cancellation signal rather than hanging — see the module doc comment.
    #[tokio::test]
    async fn a_cancelled_leader_frees_the_slot_and_wakes_waiters() {
        let inflight = OidcRefreshInflight::new();
        let leader = match inflight.elect() {
            OidcRefreshElection::Leader(l) => l,
            OidcRefreshElection::Waiter(_) => unreachable!(),
        };
        let waiter = match inflight.elect() {
            OidcRefreshElection::Waiter(w) => w,
            OidcRefreshElection::Leader(_) => unreachable!(),
        };
        drop(leader);
        assert!(
            matches!(waiter.wait().await, Err(OidcRefreshCancelled)),
            "a waiter must not hang when its leader is cancelled"
        );
        assert!(
            matches!(inflight.elect(), OidcRefreshElection::Leader(_)),
            "the slot must be free again after a cancelled leader"
        );
    }

    /// The regression this module was rewritten for. A caller reaching the
    /// slot **inside the publish→retire window** must join the just-settled
    /// outcome and make no wire call of its own; under the old
    /// retire-before-send ordering it found an empty slot, became a second
    /// leader, and replayed a consumed single-use refresh token.
    ///
    /// The window contains no `.await`, so it is pinned open deterministically
    /// with the test-only after-publish hook instead of being raced for.
    #[tokio::test]
    async fn a_caller_inside_the_publish_retire_window_joins_instead_of_calling_the_wire() {
        let inflight = OidcRefreshInflight::new();
        let wire_calls = Arc::new(AtomicUsize::new(0));
        let window_waiter: Arc<Mutex<Option<OidcRefreshWaiter>>> = Arc::new(Mutex::new(None));
        let elected_a_second_leader = Arc::new(AtomicUsize::new(0));

        let stash = Arc::clone(&window_waiter);
        let second_leaders = Arc::clone(&elected_a_second_leader);
        inflight.set_after_publish_hook(Arc::new(move |inflight: &OidcRefreshInflight| {
            match inflight.elect() {
                OidcRefreshElection::Waiter(w) => {
                    *stash.lock().unwrap() = Some(w);
                }
                OidcRefreshElection::Leader(_) => {
                    // The pre-fix behaviour: the slot was already empty, so
                    // this caller would issue a second `refresh_token` grant.
                    second_leaders.fetch_add(1, Ordering::SeqCst);
                }
            }
        }));

        let leader_tokens = coalesced_refresh(&inflight, &wire_calls, "leader-access")
            .await
            .expect("the leader's refresh succeeds");
        assert_eq!(leader_tokens.access_token.expose(), "leader-access");

        assert_eq!(
            elected_a_second_leader.load(Ordering::SeqCst),
            0,
            "a caller inside the publish->retire window must join the burst, not lead a new one"
        );
        let waiter = window_waiter
            .lock()
            .unwrap()
            .take()
            .expect("the window caller became a waiter");
        let outcome = waiter
            .wait()
            .await
            .expect("the settled publication is value-retaining")
            .expect("and carries the leader's success");
        assert_eq!(
            outcome.access_token.expose(),
            "leader-access",
            "the window caller must receive THAT ONE call's outcome (§9 rule 2)"
        );
        assert_eq!(
            wire_calls.load(Ordering::SeqCst),
            1,
            "exactly one wire call for the whole burst, window caller included (§9 rules 1+2)"
        );
    }

    /// The other half of the semantics: once a burst has fully settled (slot
    /// vacated), a later caller MUST run a genuinely fresh refresh. It must
    /// never be handed the previous burst's token set — that would be a
    /// caller silently receiving a token from a refresh that completed before
    /// it started.
    #[tokio::test]
    async fn a_caller_arriving_after_the_burst_settled_starts_a_fresh_refresh() {
        let inflight = OidcRefreshInflight::new();
        let wire_calls = AtomicUsize::new(0);

        let first = coalesced_refresh(&inflight, &wire_calls, "first-burst-access")
            .await
            .expect("first refresh succeeds");
        assert_eq!(first.access_token.expose(), "first-burst-access");
        assert_eq!(wire_calls.load(Ordering::SeqCst), 1);

        // Nothing is in flight any more: the slot must be empty, not holding
        // a settled publication for later callers to join (that would be a
        // one-entry token cache, which this guard is not).
        assert!(
            inflight.lock().is_none(),
            "the leader must vacate the slot before returning"
        );

        let second = coalesced_refresh(&inflight, &wire_calls, "second-burst-access")
            .await
            .expect("second refresh succeeds");
        assert_eq!(
            second.access_token.expose(),
            "second-burst-access",
            "a caller arriving after the burst settled must get its OWN refresh's tokens"
        );
        assert_eq!(
            wire_calls.load(Ordering::SeqCst),
            2,
            "a caller arriving after the burst settled must make a fresh wire call"
        );
    }

    /// The cancellation counterpart of the publish→retire window: a caller
    /// reaching the slot while it still holds a `Cancelled` publication must
    /// become a fresh leader, not a waiter on a burst that will never
    /// publish an outcome (which would hang). The cancelled leader's own
    /// retire must then not clear the replacement — that is the `Arc`
    /// identity check.
    #[tokio::test]
    async fn a_caller_inside_the_cancel_retire_window_leads_a_fresh_burst() {
        let inflight = OidcRefreshInflight::new();
        let window_election: Arc<Mutex<Option<&'static str>>> = Arc::new(Mutex::new(None));
        let seen = Arc::clone(&window_election);
        inflight.set_after_publish_hook(Arc::new(move |inflight: &OidcRefreshInflight| {
            let kind = match inflight.elect() {
                OidcRefreshElection::Leader(leader) => {
                    // Keep this replacement in the slot: forget the guard's
                    // publication so `Drop` does not immediately retire it,
                    // letting the assertion below observe the identity check.
                    std::mem::forget(leader);
                    "leader"
                }
                OidcRefreshElection::Waiter(_) => "waiter",
            };
            *seen.lock().unwrap() = Some(kind);
        }));

        let leader = match inflight.elect() {
            OidcRefreshElection::Leader(l) => l,
            OidcRefreshElection::Waiter(_) => unreachable!(),
        };
        drop(leader);

        assert_eq!(
            window_election.lock().unwrap().take(),
            Some("leader"),
            "a cancelled publication must never be joined"
        );
        assert!(
            inflight.lock().is_some(),
            "the cancelled leader's retire must not clear the replacement publication"
        );
    }

    /// §9 rule 4 + the §9 test requirement, at the primitive's own level: N
    /// concurrent callers on a multi-threaded runtime produce exactly one
    /// wire call and all N receive that one outcome.
    ///
    /// Deterministic rather than timing-based: the leader does not publish
    /// until all N callers have been elected, so the burst provably overlaps
    /// (a sleep would only make it *probably* overlap).
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn a_multi_thread_burst_of_thirty_two_makes_exactly_one_wire_call() {
        const BURST: usize = 32;

        let inflight = Arc::new(OidcRefreshInflight::new());
        let wire_calls = Arc::new(AtomicUsize::new(0));
        let elected = Arc::new(AtomicUsize::new(0));

        let mut handles = Vec::with_capacity(BURST);
        for _ in 0..BURST {
            let inflight = Arc::clone(&inflight);
            let wire_calls = Arc::clone(&wire_calls);
            let elected = Arc::clone(&elected);
            handles.push(tokio::spawn(async move {
                let election = inflight.elect();
                elected.fetch_add(1, Ordering::SeqCst);
                match election {
                    OidcRefreshElection::Waiter(waiter) => waiter
                        .wait()
                        .await
                        .expect("no leader is cancelled here")
                        .expect("the leader succeeds"),
                    OidcRefreshElection::Leader(leader) => {
                        wire_calls.fetch_add(1, Ordering::SeqCst);
                        // Stay "in flight" until every caller has been
                        // elected, so the whole burst overlaps this one call.
                        while elected.load(Ordering::SeqCst) < BURST {
                            tokio::task::yield_now().await;
                        }
                        let tokens = token_set("one-and-only-access");
                        leader.publish(&Ok(tokens.clone()));
                        tokens
                    }
                }
            }));
        }

        for handle in handles {
            let tokens = handle.await.expect("task must not panic");
            assert_eq!(
                tokens.access_token.expose(),
                "one-and-only-access",
                "every caller in the burst gets that one call's outcome (§9 rule 2)"
            );
        }
        assert_eq!(
            wire_calls.load(Ordering::SeqCst),
            1,
            "a burst of {BURST} concurrent callers must make exactly one wire call (§9 rules 1+2)"
        );
        assert!(
            inflight.lock().is_none(),
            "the slot must be empty once the burst is over"
        );
    }
}
