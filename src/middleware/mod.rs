//! Actix-Web middleware (owned by 16-05): `FromRequest` extractor
//! `AxiamUser`.
//!
//! Satisfies CONTRACT.md §10's per-framework middleware/route-guard
//! requirement for Actix-Web: extract the session (cookie or Bearer),
//! verify it locally against the cached JWKS (no AXIAM-server round-trip),
//! inject the authenticated identity, and map `AuthError`/`AuthzError` to
//! HTTP 401/403 with a standardized JSON error body.
//!
//! Also carries the [`mcp`] module: the MCP resource-server helpers
//! (CONTRACT.md §28) — publishing the RFC 9728 protected-resource metadata
//! document and emitting the RFC 6750 `WWW-Authenticate` challenge on this
//! guard's own 401/403 responses, opt-in via
//! [`crate::token::JwksVerifier::with_resource_metadata_url`].
//!
//! Feature-gated behind `actix` so the core SDK does not pull `actix-web`
//! unconditionally (D-02 modularity).

pub mod actix;
pub mod authz;
pub mod mcp;

pub use actix::{AxiamUser, PeerCertificate};
pub use authz::{
    AuthzGuardError, RequireAccess, UmaChallenger, require_role_check, resource_from_path,
    resource_from_static,
};
pub use mcp::{
    BearerChallengeError, BearerChallengeOptions, PROTECTED_RESOURCE_METADATA_PREFIX,
    ProtectedResourceMetadata, ProtectedResourceMetadataDocument, ProtectedResourceMetadataOptions,
    bearer_challenge, protected_resource_metadata, serve_protected_resource_metadata,
};
