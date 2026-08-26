//! The AXIAM management API — CONTRACT.md §27.
//!
//! Every other part of this SDK assumes a populated tenant. [`login`] signs a
//! user in; [`check_access`] asks about a resource; [`webhook`] verifies a
//! delivery signature. None of them can create the user, declare the resource
//! or register the webhook. This module is the part that can: **146 operations
//! across 24 namespaces**, which is the whole server API minus what other
//! contract sections already own and minus organization creation and deletion,
//! which §27.0 keeps deliberately out of reach of a client library.
//!
//! [`login`]: crate::client::AxiamClient::login
//! [`check_access`]: crate::client::AxiamClient::check_access
//! [`webhook`]: crate::webhook
//!
//! # Shape
//!
//! Operations hang off **namespace handles**, not off the client:
//!
//! ```no_run
//! # use axiam_sdk::client::AxiamClient;
//! # use axiam_sdk::management::PageRequest;
//! # async fn demo(client: &AxiamClient) -> Result<(), axiam_sdk::AxiamError> {
//! let users = client.users().list(PageRequest::first(50)).await?;
//! let role = client.roles().get(some_uuid()).await?;
//! # fn some_uuid() -> uuid::Uuid { uuid::Uuid::nil() }
//! # let _ = (users, role);
//! # Ok(())
//! # }
//! ```
//!
//! §27.2 makes that normative rather than stylistic: twenty namespaces have a
//! `list` and fourteen a `get`, so a flat surface would need a disambiguating
//! prefix invented once per operation — and 146 more methods on `AxiamClient`
//! would bury the eight most callers actually want.
//!
//! Acquiring a handle performs no I/O. It borrows the client, so it cannot
//! outlive it, and it cannot be constructed without one — a handle with its
//! own transport would be a second client with none of §3–§9 attached.
//!
//! # What you get for free
//!
//! Every operation here goes through the same request path as [`§1`]'s, so it
//! inherits the CSRF forwarding of §3, the cookie jar of §4, the `X-Tenant-ID`
//! header of §5, the TLS policy of §6, the single-flight refresh of §9, the
//! retry policy of §16 and the telemetry of §19. None of it is reimplemented
//! here, and none of it can be forgotten per-operation.
//!
//! [`§1`]: crate::rest
//!
//! # Four things worth knowing before you call anything
//!
//! **Reads retry; writes do not.** §27.4 rule 8. `certificates().generate()`
//! twice mints two certificates and `service_accounts().rotate_secret()` twice
//! invalidates the secret the first call returned — so no write on this
//! surface is retried, including the ones that look idempotent.
//!
//! **Some `PUT`s replace rather than patch.** Seventeen update bodies are
//! sparse: set the field you mean, leave the rest `None`, and nothing else
//! changes. Four are replacements — [`settings().set_org()`], the
//! organization-level email config, the WebAuthn attestation policy, and the
//! mTLS trust anchor — where the fields you omit are not preserved. The
//! generated types make the difference visible: a replacement body has
//! required fields and will not compile half-filled.
//!
//! [`settings().set_org()`]: ops::settings::Settings::set_org
//!
//! **Seven operations return a secret exactly once.** Creating a service
//! account or an OAuth2 client, generating a certificate, a CA, a signing CA
//! or a PGP key, minting a SCIM token. No later `get` returns that material
//! again — and the `get` projection has no field where it used to be, so
//! nothing tells you it is missing. Store it, or lose it.
//!
//! **404 means "absent, or not yours".** The server answers 404 for a resource
//! in another tenant on purpose: a distinguishable "exists but not yours" lets
//! a caller enumerate another tenant's ids. Both arrive as
//! [`AxiamError::Authz`] with [`AuthzKind::NotFound`], which is what
//! [`AxiamError::is_not_found`] tests.
//!
//! [`AxiamError::Authz`]: crate::AxiamError::Authz
//! [`AuthzKind::NotFound`]: crate::AuthzKind::NotFound
//!
//! # How this module is built
//!
//! `models.rs` and `ops/` are **generated** by `tools/gen_management.py` from
//! the vendored `management-registry.json` — §27.8 requires that, because a
//! hand-maintained table of 146 names is wrong by the next release. Everything
//! else here is written by hand. CI regenerates and diffs.

pub mod error;
pub mod manifest;
pub mod models;
pub mod ops;
pub mod page;
pub(crate) mod request;
pub(crate) mod scope;

pub use error::{FieldError, ValidationError};
pub use page::{Page, PageRequest};
