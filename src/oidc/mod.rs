//! OIDC / SSO relying-party helpers — CONTRACT.md §12 (contract 1.4).
//!
//! The nine canonical §12 operations, under the exact §12.2 Rust names, as
//! methods on the existing [`crate::client::AxiamClient`] (this SDK has no
//! browser-bundle constraint, so — per the plan — the operations live
//! directly on the client rather than a separate type):
//!
//! `oidc_discover`, `oidc_begin`, `oidc_exchange`, `oidc_refresh`,
//! `login_client_credentials`, `introspect`, `revoke`, `sso_start`,
//! `sso_complete`.
//!
//! Everything is reuse, not reimplementation (§12 forbids forking):
//!   * transport + §2 error mapping + §5 tenant header + §6 TLS →
//!     [`crate::client::AxiamClient`]'s own `reqwest::Client`;
//!   * §3 CSRF forwarding → the crate's existing `CsrfHeaderExt` extension
//!     trait (`src/rest/auth.rs`), reused as-is;
//!   * §9 single-flight refresh → a dedicated coalescer
//!     (`src/oidc/single_flight.rs`) built from the same primitives as the
//!     existing guard in [`crate::token::refresh_guard`], permitted explicitly
//!     by §9 rule 5; see that module and the crate-internal
//!     `AxiamClientInner::oidc_refresh_inflight` field doc comment for why it
//!     is a separate instance, and for how §9 rule 2's result sharing works;
//!   * §12.4 signature verification → [`crate::token::jwks::JwksVerifier`],
//!     extended (never forked) with its crate-internal
//!     `verify_id_token_signature` method;
//!   * §7/§12.5 redaction → [`crate::Sensitive`].
//!
//! # Example
//!
//! ```no_run
//! use axiam_sdk::client::AxiamClient;
//! use axiam_sdk::oidc::{OidcBeginParams, OidcExchangeParams};
//!
//! # async fn run() -> Result<(), axiam_sdk::AxiamError> {
//! let client = AxiamClient::builder()
//!     .base_url("https://iam.example.com")?
//!     .tenant_id("11111111-2222-3333-4444-555555555555".parse().unwrap())
//!     .oidc_client_id("my-app")
//!     .oidc_client_secret("my-app-secret")
//!     .build()?;
//!
//! // 1. redirect the user agent
//! let configuration = client.oidc_discover().await?;
//! let request = client.oidc_begin(&configuration, OidcBeginParams::new("https://app.example.com/cb"))?;
//! // …store request.state / request.nonce / request.code_verifier in your own session…
//!
//! // 2. on the callback, having checked the returned `state` matches
//! let tokens = client
//!     .oidc_exchange(OidcExchangeParams {
//!         code: "the-code-from-the-callback".into(),
//!         code_verifier: request.code_verifier,
//!         redirect_uri: "https://app.example.com/cb".into(),
//!         nonce: request.nonce,
//!         tenant_id: None,
//!         configuration: Some(configuration),
//!     })
//!     .await?;
//! println!("{:?}", tokens.id_claims.map(|c| c.sub));
//! # Ok(())
//! # }
//! ```

pub mod authorize;
pub mod device;
pub mod discovery;
pub mod exchange;
pub mod id_token;
pub mod logout;
pub(crate) mod single_flight;
pub mod state;
pub mod token_exchange;

pub use authorize::{AuthorizationRequest, CODE_CHALLENGE_METHOD_S256, OidcBeginParams};
pub use device::{
    DEFAULT_POLL_INTERVAL_SECS, DEVICE_CODE_GRANT_TYPE, DeviceAuthorization, DeviceAuthorizeParams,
    DeviceLoginParams, DevicePollParams, SLOW_DOWN_INCREMENT_SECS,
};
pub use discovery::{DISCOVERY_PATH, MIN_DISCOVERY_TTL, OidcConfiguration};
pub use exchange::{
    IntrospectParams, IntrospectionResult, LoginClientCredentialsParams, OidcExchangeParams,
    OidcRefreshParams, OidcTokenSet, RevokeParams, SsoCompleteParams, SsoCompleteResult,
    SsoStartParams, SsoStartResult,
};
pub use id_token::{IdTokenClaims, MAX_CLOCK_SKEW_SEC};
pub use logout::{
    BACKCHANNEL_LOGOUT_EVENT, LogoutUrlParams, MAX_LOGOUT_TOKEN_AGE_SECS, VerifiedLogoutToken,
};
pub use state::{MemoryOidcStateStore, OIDC_STATE_TTL, OidcStateEntry, OidcStateStore};
pub use token_exchange::{
    ACCESS_TOKEN_TYPE, ExchangedToken, TOKEN_EXCHANGE_GRANT_TYPE, TokenExchangeParams,
};
