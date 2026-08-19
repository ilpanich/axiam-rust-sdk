//! Clock types that work on every target the SDK builds for.
//!
//! # Why this module exists
//!
//! `std::time::Instant::now()` and `std::time::SystemTime::now()` **panic** on
//! `wasm32-unknown-unknown`: the target has no clock, and `std` chose to abort
//! rather than return a wrong answer. Every cache TTL, every DPoP `iat`, and
//! every `exp` check in this crate calls one of them, so a browser build would
//! compile cleanly and then panic on the first authorization decision.
//!
//! [`web_time`] is the drop-in fix — `Instant` backed by
//! `performance.now()` and `SystemTime` backed by `Date.now()`. On every other
//! target it is a re-export of `std::time`, so this indirection costs nothing
//! natively and the dependency is not even pulled in.
//!
//! # Use these, not `std::time`
//!
//! Anywhere in this crate that needs a clock imports from here. `Duration` is
//! re-exported alongside them only so a call site needs one `use` rather than
//! two from two different modules — it is `std::time::Duration` on every
//! target and has never been the problem.
//!
//! [`web_time`]: https://docs.rs/web-time

#[cfg(not(target_arch = "wasm32"))]
pub use std::time::{Instant, SystemTime, UNIX_EPOCH};

#[cfg(target_arch = "wasm32")]
pub use web_time::{Instant, SystemTime, UNIX_EPOCH};

pub use std::time::Duration;
