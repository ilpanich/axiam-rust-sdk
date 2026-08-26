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
//!   replay-protected authorization/audit messages (§8), plus
//!   [`amqp::reactor`] — the §22 reactor runtime, where the same HMAC runs in
//!   **both** directions: the server signs the hook event, and the reactor
//!   signs the allow/deny/mutate reply.
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

// CONTRACT.md §17 client-side decision memo. Internal — §17.2 makes only the
// TTL public surface. Off by default; see the module docs for the staleness
// bound a caller accepts by enabling it.
/// The per-client cookie store, and the one place a browser build differs.
#[cfg(feature = "rest")]
pub mod cookies;
#[cfg(feature = "rest")]
mod memo;
/// CONTRACT.md §23 Secure Remote Password — the protocol half, with no I/O.
/// Clock types that work on wasm32 as well as native — see the module docs for
/// why `std::time` cannot be used directly.
pub mod time;

pub use error::{AuthzKind, AxiamError, IdTokenFailureReason, OAuthProtocolError};
pub use sensitive::Sensitive;

// Single owner of all Phase 16 module declarations (this file is final
// after plan 16-01; downstream plans 16-02..16-05 only fill in module
// bodies, never edit this file, to avoid parallel-execution merge
// conflicts).
pub mod client;
pub mod token;

#[cfg(feature = "rest")]
pub mod rest;

// CONTRACT.md §27 — the management API. Documented by `src/management/mod.rs`'s
// own `//!` block; a `///` here would be merged with it by rustdoc and resolved
// in *this* scope, which breaks every intra-doc link the module makes to its own
// children (and reports the failure with no file or line to point at).
pub mod management;

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
pub mod uma;
pub mod webhook;

// §11 declarative authorization helpers: re-export the proc-macro attributes
// from the companion `axiam-sdk-macros` crate so consumers write
// `use axiam_sdk::require_access;` and never name the macro crate directly.
// The macros expand to the runtime helpers in [`middleware::authz`].
#[cfg(feature = "macros")]
pub use axiam_sdk_macros::{require_access, require_auth, require_role};

// §22.14 declarative reactor handler binding: `#[reactor_handler("...")]`, from
// the same companion crate. Gated on its own feature rather than on `macros`
// because `macros` implies `actix` — a reactor is an AMQP daemon with no HTTP
// surface at all, and making one pull actix-web in to get an attribute macro
// would be a dependency for nothing.
#[cfg(feature = "reactor-macros")]
pub use axiam_sdk_macros::reactor_handler;

/// The range of Rust toolchains this SDK is built and tested against.
///
/// The floor enforces itself, and does so well: `rust-version` in `Cargo.toml` is a
/// hard constraint Cargo checks during resolution, so a consumer on an older
/// toolchain gets a message naming the crate and the version it needs rather than a
/// compile error deep in someone else's source.
///
/// Nothing enforces the upper end, and nothing can — there is no "maximum Rust" to
/// declare. Code that compiles on the MSRV keeps compiling on newer toolchains
/// almost always, but "almost" is where new `deny`-by-default lints, tightened
/// inference, and edition-adjacent behaviour changes live. Only a build on a current
/// toolchain settles it.
///
/// This SDK has gated on both ends since it was written (D-10), which is why it was
/// the model the other ten AXIAM SDKs were brought in line with. These constants make
/// the range readable from code, matching the equivalent surface those SDKs now
/// expose.
///
/// `tests/version_policy.rs` asserts both against `Cargo.toml` and the CI matrix, so
/// neither can go stale.
pub mod supported_versions {
    /// The minimum supported Rust version, mirroring `rust-version` in `Cargo.toml`.
    ///
    /// Cargo refuses to build the crate on anything older.
    pub const MIN_RUST_VERSION: &str = "1.88";

    /// The Rust edition the crate is compiled under.
    ///
    /// The edition is a per-crate choice and does not constrain consumers — a 2024
    /// edition crate is usable from a 2015 edition one — but it does set the MSRV
    /// floor, since edition 2024 requires Rust 1.85 or newer.
    pub const EDITION: &str = "2024";

    /// The newest toolchain the CI matrix builds.
    ///
    /// `"stable"` rather than a pinned number, deliberately: pinning would freeze
    /// the upper end at whatever was current the day it was written and quietly stop
    /// testing anything new. Tracking `stable` means the newest leg keeps moving on
    /// its own, and a regression introduced by a Rust release surfaces here rather
    /// than in a consumer's build.
    pub const NEWEST_TESTED: &str = "stable";
}
