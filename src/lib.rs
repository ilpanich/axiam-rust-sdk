//! AXIAM SDK for Rust
//!
//! This crate provides the official Rust client SDK for AXIAM
//! (Access eXtended Identity and Authorization Management), a multi-tenant
//! IAM solution. It conforms to the cross-language SDK behavioral contract
//! in `../CONTRACT.md` §1–§11, and offers three interchangeable transports
//! behind Cargo features:
//!
//! - `rest` — [`client::AxiamClient`], built on `reqwest`; cookie-based
//!   sessions with CSRF double-submit protection (§3/§4).
//! - `grpc` — [`grpc::AuthzGrpcClient`], for low-latency authorization
//!   checks from a service mesh.
//! - `amqp` — [`amqp`], a closure-handler consumer for HMAC-signed,
//!   replay-protected authorization/audit messages (§8).
//!
//! An additional `actix` feature provides [`middleware::AxiamUser`], an
//! Actix-Web extractor that verifies sessions locally against a cached JWKS
//! (§10). The `macros` feature adds the §11 *declarative authorization
//! helpers* — the [`macro@require_access`], [`macro@require_auth`] and
//! [`macro@require_role`] attribute macros — layered on top of that extractor.
//! All access/refresh tokens are wrapped in [`Sensitive`] so they are never
//! accidentally logged or displayed.
//!
//! # Example: login then check access (REST transport)
//!
//! ```no_run
//! use axiam_sdk::client::AxiamClient;
//!
//! # async fn run() -> Result<(), axiam_sdk::AxiamError> {
//! let client = AxiamClient::builder()
//!     .base_url("https://axiam.example.com")?
//!     .tenant_slug("acme")
//!     .org_slug("acme")
//!     .build()?;
//!
//! client.login("user@example.com", "hunter2").await?;
//!
//! let allowed = client
//!     .can("read", "resource-uuid".parse().unwrap(), None)
//!     .await?;
//! # Ok(())
//! # }
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod error;
mod sensitive;
// X-2: shared TLS-scheme guard for transport URLs (REST/gRPC/AMQP). Always
// compiled (transport modules below are feature-gated but all reuse this).
mod url_guard;

// CONTRACT.md §19 telemetry hooks. Deliberately ungated: the event types are
// pure data with no transport dependency, so a caller can name them (and write
// a sink) under any feature set.
pub mod telemetry;

// CONTRACT.md §16 bounded read-only retry policy. Internal — the policy is
// machinery, and §16.6 makes only the disable switch public surface. Gated on
// `rest` because it waits on the tokio timer.
#[cfg(feature = "rest")]
mod retry;

pub use error::{AxiamError, IdTokenFailureReason, OAuthProtocolError};
pub use sensitive::Sensitive;

// Single owner of all Phase 16 module declarations (this file is final
// after plan 16-01; downstream plans 16-02..16-05 only fill in module
// bodies, never edit this file, to avoid parallel-execution merge
// conflicts).
pub mod client;
pub mod token;

#[cfg(feature = "rest")]
pub mod rest;

// CONTRACT.md §12 OIDC / SSO relying-party helpers — REST-only (built on the
// same `reqwest`-based transport as `rest`/`client`).
#[cfg(feature = "rest")]
pub mod oidc;

#[cfg(feature = "grpc")]
pub mod grpc;

#[cfg(feature = "amqp")]
pub mod amqp;

#[cfg(feature = "actix")]
pub mod middleware;

// CONTRACT.md §13 webhook signature verification (T-145). Pure computation
// over caller-supplied bytes — no transport of its own — so it is gated on
// `any(rest, amqp)` rather than on a transport: those are exactly the two
// feature sets that already vendor its inputs (`hmac`, `sha2`, `hex`,
// `subtle`), which is why it adds no dependency to either. `rest` is the
// natural home (webhooks arrive over HTTP and `rest` is on by default, so
// `verify_webhook` is available out of the box); `amqp` is included because an
// AMQP-only consumer already has the identical crypto stack and gating a pure
// HMAC helper away from it would be arbitrary.
#[cfg(any(feature = "rest", feature = "amqp"))]
pub mod webhook;

// §11 declarative authorization helpers: re-export the proc-macro attributes
// from the companion `axiam-sdk-macros` crate so consumers write
// `use axiam_sdk::require_access;` and never name the macro crate directly.
// The macros expand to the runtime helpers in [`middleware::authz`].
#[cfg(feature = "macros")]
pub use axiam_sdk_macros::{require_access, require_auth, require_role};
