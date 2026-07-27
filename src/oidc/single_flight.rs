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
//! # The mechanism
//!
//! A leader/waiter election over a slot holding a
//! [`tokio::sync::broadcast::Sender`]:
//!
//! * the first caller to find the slot empty publishes a fresh channel into
//!   it and becomes the **leader** — it alone performs the wire call;
//! * every caller that finds the slot occupied
//!   [`subscribe`](tokio::sync::broadcast::Sender::subscribe)s and becomes a
//!   **waiter**, awaiting the leader's single broadcast;
//! * the leader retires the slot **before** broadcasting, so a caller
//!   arriving after the burst starts a fresh election (and a fresh wire call)
//!   rather than subscribing to a channel that has already fired — there is
//!   no lost-wakeup window, because retiring and electing both happen under
//!   the same lock.
//!
//! §9 rule 5 (contract 1.5) explicitly permits this **dedicated** guard
//! instance rather than reusing the §1 cookie-session guard
//! ([`crate::token::refresh_guard`]): that guard's API compares an observed
//! `axiam_access` cookie value against its own cache, a comparison with no
//! meaning for an OAuth2 `refresh_token` grant over a different token
//! namespace. The mechanism is free; the observable behaviour is not.
//!
//! No new dependency: `tokio`'s `sync` feature is already enabled, and the
//! slot's lock is [`std::sync::Mutex`].
//!
//! # Why a `std::sync::Mutex` and not a `tokio::sync::Mutex`
//!
//! Both critical sections here are tiny and fully synchronous — elect
//! (check/insert) and retire (take) — so nothing is ever held across an
//! `.await`, which is the only reason to reach for the async mutex. Using the
//! std lock buys **cancel safety**: [`OidcRefreshLeader`] can clear the slot
//! from `Drop`, which cannot `.await`. That matters, because a leader future
//! dropped mid-flight (a `tokio::time::timeout`, a cancelled `select!` branch,
//! an aborted task) would otherwise leave a `Sender` stranded in the slot
//! forever — every later `oidc_refresh` would elect itself a waiter on a dead
//! channel and fail permanently. With the drop guard, a cancelled leader
//! simply frees the slot and the next caller runs a normal refresh.

use std::sync::{Mutex, MutexGuard, PoisonError};

use tokio::sync::broadcast;

use crate::AxiamError;

use super::exchange::OidcTokenSet;

/// The outcome the single in-flight `oidc_refresh` broadcasts to its waiters.
///
/// The error side is an [`std::sync::Arc`] because [`AxiamError`] is not
/// `Clone` (its `Network` variant chains a `Box<dyn Error>`), while a
/// broadcast payload must be; waiters turn it back into an owned `AxiamError`
/// via [`AxiamError::clone_for_waiter`].
pub(crate) type OidcRefreshOutcome = Result<OidcTokenSet, std::sync::Arc<AxiamError>>;

type OidcRefreshSlot = Mutex<Option<broadcast::Sender<OidcRefreshOutcome>>>;

/// The `oidc_refresh` in-flight slot held by
/// `AxiamClientInner::oidc_refresh_inflight`. Empty means "no refresh in
/// flight"; occupied means "a leader is running and this is the channel it
/// will broadcast its outcome on".
pub(crate) struct OidcRefreshInflight {
    slot: OidcRefreshSlot,
}

/// The outcome of one leader/waiter election — see
/// [`OidcRefreshInflight::elect`].
pub(crate) enum OidcRefreshElection<'a> {
    /// This caller won the election: it must perform exactly one wire call
    /// and then hand the outcome to [`OidcRefreshLeader::publish`].
    Leader(OidcRefreshLeader<'a>),
    /// A refresh was already in flight: await this receiver for the leader's
    /// outcome and make **no** wire call.
    Waiter(broadcast::Receiver<OidcRefreshOutcome>),
}

impl OidcRefreshInflight {
    /// A slot with no refresh in flight.
    pub(crate) fn new() -> Self {
        Self {
            slot: Mutex::new(None),
        }
    }

    /// Lock the slot, recovering from poisoning rather than panicking.
    ///
    /// The guarded value is a plain `Option<Sender>` that cannot be left
    /// logically inconsistent by a panic mid-critical-section (both sections
    /// are a single assignment), so `into_inner` is the correct recovery: a
    /// panicking unrelated caller must not permanently disable refreshing.
    fn lock(&self) -> MutexGuard<'_, Option<broadcast::Sender<OidcRefreshOutcome>>> {
        self.slot.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Elect this caller as either the single leader or one of the waiters
    /// (§9 rules 1 and 2).
    pub(crate) fn elect(&self) -> OidcRefreshElection<'_> {
        let mut slot = self.lock();
        if let Some(tx) = slot.as_ref() {
            return OidcRefreshElection::Waiter(tx.subscribe());
        }
        // Capacity 1: the leader sends exactly one message, and every
        // receiver subscribed before that send reads it, so the ring never
        // needs more than one slot and no waiter can lag.
        let (tx, _rx) = broadcast::channel(1);
        *slot = Some(tx.clone());
        OidcRefreshElection::Leader(OidcRefreshLeader {
            inflight: self,
            tx: Some(tx),
        })
    }

    /// Retire the in-flight channel, so the next caller starts a fresh
    /// election.
    fn retire(&self) {
        *self.lock() = None;
    }
}

/// The single elected performer of one `oidc_refresh` burst.
///
/// Holding one of these is the *permission* to make the wire call; every
/// other concurrent caller is a [`OidcRefreshElection::Waiter`]. Retires the
/// slot on [`Self::publish`], or on `Drop` if the leader's future was
/// cancelled before it got that far.
pub(crate) struct OidcRefreshLeader<'a> {
    inflight: &'a OidcRefreshInflight,
    /// `None` once the outcome has been published (or the slot released), so
    /// `Drop` never retires a *later* leader's channel.
    tx: Option<broadcast::Sender<OidcRefreshOutcome>>,
}

impl OidcRefreshLeader<'_> {
    /// Retire the slot and broadcast `result` to every waiter (§9 rule 2).
    ///
    /// Retiring first is deliberate: a caller arriving between the retire and
    /// the send finds an empty slot and becomes a new leader, rather than
    /// subscribing to a channel whose only message has already gone out (a
    /// `tokio::sync::broadcast` receiver never sees sends that predate its
    /// `subscribe`, so such a caller would hang until the sender dropped).
    ///
    /// A `send` error means simply that no waiter joined this burst — the
    /// common single-caller case — and is ignored.
    pub(crate) fn publish(mut self, result: &Result<OidcTokenSet, AxiamError>) {
        let Some(tx) = self.tx.take() else {
            return;
        };
        self.inflight.retire();
        let shared: OidcRefreshOutcome = match result {
            Ok(tokens) => Ok(tokens.clone()),
            Err(e) => Err(std::sync::Arc::new(e.clone_for_waiter())),
        };
        let _ = tx.send(shared);
    }
}

impl Drop for OidcRefreshLeader<'_> {
    fn drop(&mut self) {
        // Only reached when the leader's future was dropped before
        // `publish` — i.e. cancellation. Free the slot so `oidc_refresh` does
        // not deadlock permanently; the stranded `Sender` is dropped with
        // `self`, which wakes any waiter with `RecvError::Closed`.
        if self.tx.take().is_some() {
            self.inflight.retire();
        }
    }
}

#[cfg(test)]
mod tests {
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
                OidcRefreshElection::Waiter(rx) => waiters.push(rx),
                OidcRefreshElection::Leader(_) => panic!("only one leader per burst"),
            }
        }
        leader.publish(&Ok(token_set("shared-access")));
        for mut rx in waiters {
            let outcome = rx.recv().await.expect("leader published");
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
        let mut rx = match inflight.elect() {
            OidcRefreshElection::Waiter(rx) => rx,
            OidcRefreshElection::Leader(_) => unreachable!(),
        };
        leader.publish(&Err(AxiamError::oauth_protocol_error(
            "invalid_grant",
            "refresh token already used",
        )));
        let err = rx.recv().await.expect("leader published").unwrap_err();
        assert_eq!(
            err.as_oauth_protocol_error().map(|o| o.error.as_str()),
            Some("invalid_grant")
        );
    }

    /// A leader future dropped without publishing (cancellation) must not
    /// wedge the slot — see the module doc comment.
    #[tokio::test]
    async fn a_cancelled_leader_frees_the_slot_and_wakes_waiters() {
        let inflight = OidcRefreshInflight::new();
        let leader = match inflight.elect() {
            OidcRefreshElection::Leader(l) => l,
            OidcRefreshElection::Waiter(_) => unreachable!(),
        };
        let mut rx = match inflight.elect() {
            OidcRefreshElection::Waiter(rx) => rx,
            OidcRefreshElection::Leader(_) => unreachable!(),
        };
        drop(leader);
        assert!(
            rx.recv().await.is_err(),
            "a waiter must not hang when its leader is cancelled"
        );
        assert!(
            matches!(inflight.elect(), OidcRefreshElection::Leader(_)),
            "the slot must be free again after a cancelled leader"
        );
    }
}
