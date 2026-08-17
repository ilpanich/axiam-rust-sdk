//! AMQP transport (owned by 16-04): HMAC sign/verify, closure-handler
//! consumer, `AuthzRequest`/`AuditEventMessage` DTOs.
//!
//! This module is a **mirror, never an import**, of the server's
//! `crates/axiam-amqp/src/messages.rs` wire format: the HMAC-SHA256
//! sign/verify functions and the `AuthzRequest`/`AuditEventMessage` structs
//! reproduce the server's algorithm and serde shape byte-for-byte using only
//! external crates (`hmac`, `sha2`, `hex`, `serde`, `uuid`, `serde_json`,
//! `lapin`) — this crate never depends on any `axiam-*` workspace crate.
//!
//! See `CONTRACT.md` §8 for the full HMAC verification protocol this
//! module implements.
//!
//! The [`reactor`] submodule adds CONTRACT.md §22 — the reactor wire protocol
//! and the [`reactor_serve`] runtime. It reuses the same §8 v2 primitives in
//! **both** directions (the server signs the event, the reactor signs the
//! reply) with one canonicalization difference that is easy to miss and
//! impossible to work around: a reactor body signs `hmac_signature` as
//! **`null`**, where §8's own two message types omit it entirely.

pub mod consumer;
pub mod hmac;
pub mod messages;
pub mod reactor;
#[cfg(test)]
pub(crate) mod test_log;
pub mod transport;

pub use consumer::{consume, consume_with_tls};
pub use hmac::{sign_payload, verify_payload};
pub use messages::{AuditEventMessage, AuthzRequest};
pub use reactor::{ReactorConfig, ReactorDecision, ReactorEvent, ReactorShutdown, reactor_serve};
pub use transport::{AmqpTlsConfig, ensure_amqps};
