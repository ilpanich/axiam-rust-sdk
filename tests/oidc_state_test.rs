//! `MemoryOidcStateStore` (CONTRACT.md §12.3 rule 1) through the public
//! `axiam_sdk::oidc` surface: single-use consume + TTL expiry.

#![cfg(feature = "rest")]

use axiam_sdk::Sensitive;
use axiam_sdk::oidc::{MemoryOidcStateStore, OidcStateEntry, OidcStateStore};
use std::time::Duration;

fn entry(state: &str) -> OidcStateEntry {
    OidcStateEntry {
        state: state.to_string(),
        nonce: "nonce-value".to_string(),
        code_verifier: Sensitive::new("verifier-value".to_string()),
        redirect_uri: "https://app.example.com/cb".to_string(),
        return_to: Some("/dashboard".to_string()),
    }
}

#[tokio::test]
async fn save_then_consume_returns_the_entry_exactly_once() {
    let store = MemoryOidcStateStore::new();
    store.save(entry("state-1")).await;
    assert_eq!(store.len(), 1);

    let consumed = store
        .consume("state-1")
        .await
        .expect("first consume must succeed");
    assert_eq!(consumed.nonce, "nonce-value");
    assert_eq!(consumed.redirect_uri, "https://app.example.com/cb");
    assert_eq!(consumed.return_to.as_deref(), Some("/dashboard"));
    assert_eq!(consumed.code_verifier.expose(), "verifier-value");

    assert!(
        store.consume("state-1").await.is_none(),
        "a state row must be single-use (§12.3 rule 1)"
    );
    assert!(store.is_empty());
}

#[tokio::test]
async fn consume_of_an_unknown_or_expired_state_is_indistinguishable_from_replay() {
    let store = MemoryOidcStateStore::with_ttl(Duration::from_millis(15));
    assert!(store.consume("never-saved").await.is_none());

    store.save(entry("state-2")).await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(
        store.consume("state-2").await.is_none(),
        "an expired entry must not be returned"
    );
}

#[tokio::test]
async fn multiple_in_flight_logins_are_tracked_independently() {
    let store = MemoryOidcStateStore::new();
    store.save(entry("a")).await;
    store.save(entry("b")).await;
    assert_eq!(store.len(), 2);

    assert!(store.consume("a").await.is_some());
    assert_eq!(store.len(), 1);
    assert!(store.consume("b").await.is_some());
    assert_eq!(store.len(), 0);
}
