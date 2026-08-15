//! Reactors — AMQP extension actors (CONTRACT.md §22).
//!
//! A **Reactor** is an external process that subscribes to named hook events
//! on the AMQP bus and answers back — allow, deny, or a field-allow-listed
//! mutation — inside a timeout the server declared. It is AXIAM's answer to
//! Zitadel Actions and Keycloak SPIs, and the difference is the whole design:
//! those load third-party code *into* the authorization server, and this keeps
//! it outside, reachable only through a signed reply schema the server
//! validates before it believes a word of it.
//!
//! ```no_run
//! use axiam_sdk::Sensitive;
//! use axiam_sdk::amqp::reactor::{ReactorConfig, ReactorDecision, events, reactor_serve};
//!
//! # async fn run(subkey: Sensitive<Vec<u8>>) -> Result<(), axiam_sdk::AxiamError> {
//! let config = ReactorConfig::builder()
//!     .amqp_url("amqps://reactor:secret@broker.example.com:5671")
//!     .tenant_id("11111111-1111-1111-1111-111111111111".parse().unwrap())
//!     .reactor_id("99999999-9999-9999-9999-999999999999".parse().unwrap())
//!     .signing_key(subkey)
//!     .build()?;
//!
//! reactor_serve(config, |event| async move {
//!     if event.event == events::LOGIN_POST_AUTH {
//!         let from_embargoed_country = false; // your check here
//!         if from_embargoed_country {
//!             return ReactorDecision::deny("embargoed region");
//!         }
//!     }
//!     ReactorDecision::allow()
//! })
//! .await
//! # }
//! ```
//!
//! # The rule this module does not paper over
//!
//! A reply is an instruction to change a token or refuse a login, so an
//! unsigned reply is not a weak reply — **it is not a reply at all**. Both
//! directions are signed, with the same §8 v2 primitives and the same tenant
//! subkey. This runtime verifies every event before user code sees it, and
//! signs every reply before it leaves.
//!
//! # Hot-path exclusion (§22.7 — normative MUST NOT)
//!
//! `authz.check`, `authz.check_batch` and `token.introspect` are **not
//! hookable**, and nothing in this module presents them as such: they appear
//! in no constant, no registry row and no example. A reactor round-trip is
//! milliseconds; the check path's budget is microseconds. An application that
//! needs external input on an authorization decision writes a **deny grant**,
//! which the engine evaluates in the hot path at hot-path cost. There is
//! deliberately no client-side interceptor, middleware hook or callback in
//! this SDK offering itself as the reactor equivalent for those operations.
//!
//! # Layout
//!
//! * [`registry`] — the five hookable events, their mutable-field allow-lists,
//!   and the failure-policy composition rule (§22.5, §22.7, §22.8).
//! * [`protocol`] — the signed event and the signed reply, including the
//!   `"hmac_signature": null` canonicalization that differs from §8's own two
//!   message types (§22.1–§22.4).
//! * [`runtime`] — [`reactor_serve`] itself (§22.10).

pub mod protocol;
pub mod registry;
pub mod runtime;

pub use protocol::{
    DEFAULT_FRESHNESS_SKEW_SECS, EventRejection, REACTOR_EXCHANGE, REACTOR_KEY_VERSION,
    ReactorEvent, ReactorReply, ReplyDecision, ReplyRejection, canonical_event_bytes, is_fresh,
    queue_name, routing_key, verify_event,
};
pub use registry::{
    DEFAULT_MAX_IN_FLIGHT, DEFAULT_TIMEOUT_MS, EVENT_REGISTRY, FailurePolicy, MAX_TIMEOUT_MS,
    MIN_TIMEOUT_MS, ReactorEventSpec, ReactorMode, default_failure_policy_for, event_spec, events,
};
pub use runtime::{
    ReactorConfig, ReactorConfigBuilder, ReactorDecision, ReactorShutdown, reactor_serve,
};
