//! Where `{org_id}` and `{tenant_id}` come from (CONTRACT.md §27.4 rule 3).
//!
//! Thirty-one of the 147 routes carry one or both, and in almost every call they
//! are the client's own. Making the caller restate them on every call is the
//! kind of ceremony that gets wrapped in a helper anyway; making them
//! impossible to override is worse, because a platform-admin token
//! legitimately administers a tenant other than the one its client was built
//! with. So they default from the client and every namespace handle that needs
//! one exposes an override.

use uuid::Uuid;

use crate::AxiamError;
use crate::client::{AxiamClient, OrgIdentifier, TenantIdentifier};

/// Per-handle overrides for the two implicit path parameters.
///
/// `None` means "use the client's". Copied by value into each handle, so an
/// override is scoped to the handle it was set on and never leaks back into
/// the client.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Scope {
    pub org_id: Option<Uuid>,
    pub tenant_id: Option<Uuid>,
}

impl Scope {
    /// Resolve `{org_id}`: the handle's override, else the client's.
    ///
    /// A client built with `org_slug` and no `org_id` fails **here**, with no
    /// wire call. §27.4 rule 3 forbids resolving the slug behind the caller's
    /// back: a silent extra round-trip on an admin path is exactly what
    /// §12.1 rule 2 refuses for `/oauth2/*`, and for the same reason — the
    /// caller cannot see it, cannot cache it, and pays for it on every call.
    pub(crate) fn org(&self, client: &AxiamClient, operation: &str) -> Result<Uuid, AxiamError> {
        if let Some(id) = self.org_id {
            return Ok(id);
        }
        match &client.inner.org {
            Some(OrgIdentifier::Id(id)) => Ok(*id),
            Some(OrgIdentifier::Slug(slug)) => Err(AxiamError::network(format!(
                "{operation}: this route needs an organization UUID, but the client was built \
                 with org_slug {slug:?}. Rebuild it with .org_id(..), or name one on the handle \
                 with .in_org(..)."
            ))),
            None => Err(AxiamError::network(format!(
                "{operation}: this route needs an organization UUID and the client has none. \
                 Build the client with .org_id(..), or name one on the handle with .in_org(..)."
            ))),
        }
    }

    /// Resolve `{tenant_id}` where it names the *context*, not the object.
    ///
    /// Namespaces where `{tenant_id}` names the thing being acted on --
    /// `tenants`, and the signing CAs under `ca_certificates` -- take it as an
    /// ordinary argument instead and never reach this.
    pub(crate) fn tenant(&self, client: &AxiamClient, operation: &str) -> Result<Uuid, AxiamError> {
        if let Some(id) = self.tenant_id {
            return Ok(id);
        }
        match &client.inner.tenant {
            TenantIdentifier::Id(id) => Ok(*id),
            TenantIdentifier::Slug(slug) => Err(AxiamError::network(format!(
                "{operation}: this route needs a tenant UUID, but the client was built with \
                 tenant_slug {slug:?}. Rebuild it with .tenant_id(..), or name one on the \
                 handle with .for_tenant(..)."
            ))),
        }
    }
}
