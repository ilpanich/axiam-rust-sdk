//! Local checks the generated §27 surface runs before any I/O, and the
//! hand-written conveniences around the generated models.
//!
//! The generator (`tools/gen_management.py`, `PRECHECKS`) emits a call to a
//! function here at the top of an operation; nothing here performs I/O.

use crate::AxiamError;
use crate::management::error::local_refusal;
use crate::management::models;

/// §29.2: `ParseSamlSpMetadata` is **exactly one** of `metadata_xml` and
/// `metadata_url`. Both or neither is a local `ValidationError`, raised before
/// any request — never a request the server refuses.
pub(crate) fn parse_sp_metadata_exactly_one(
    body: &models::ParseSamlSpMetadata,
) -> Result<(), AxiamError> {
    match (&body.metadata_xml, &body.metadata_url) {
        (Some(_), None) | (None, Some(_)) => Ok(()),
        (Some(_), Some(_)) => Err(local_refusal(
            "saml.parse_sp_metadata",
            "metadata_xml",
            "set exactly one of metadata_xml and metadata_url, not both (CONTRACT.md §29.2)",
        )),
        (None, None) => Err(local_refusal(
            "saml.parse_sp_metadata",
            "metadata_url",
            "set exactly one of metadata_xml and metadata_url (CONTRACT.md §29.2)",
        )),
    }
}

impl models::ParseSamlSpMetadata {
    /// A request for the server to fetch the SP's metadata from `url`
    /// (`https` only, through its SSRF guard).
    pub fn from_url(url: impl Into<String>) -> Self {
        Self {
            metadata_url: Some(url.into()),
            metadata_xml: None,
        }
    }

    /// A request carrying the SP's metadata document itself (at most 512 KiB).
    pub fn from_xml(xml: impl Into<String>) -> Self {
        Self {
            metadata_url: None,
            metadata_xml: Some(xml.into()),
        }
    }
}

/// The read-modify-write form §27.4 rule 5 recommends for `replace` updates:
/// a read result turned back into the replacement body, every member carried
/// over, so changing one field and sending it back preserves the rest.
impl From<&models::SamlServiceProvider> for models::SamlServiceProviderInput {
    fn from(sp: &models::SamlServiceProvider) -> Self {
        Self {
            acs_urls: sp.acs_urls.clone(),
            allow_idp_initiated: Some(sp.allow_idp_initiated),
            allowed_groups: Some(sp.allowed_groups.clone()),
            attribute_mappings: Some(sp.attribute_mappings.clone()),
            display_name: sp.display_name.clone(),
            enabled: Some(sp.enabled),
            encrypt_assertions: Some(sp.encrypt_assertions),
            entity_id: sp.entity_id.clone(),
            name_id_format: Some(sp.name_id_format.clone()),
            sign_responses: Some(sp.sign_responses),
            slo_binding: sp.slo_binding.clone(),
            slo_url: sp.slo_url.clone(),
            sp_encryption_cert_pem: sp.sp_encryption_cert_pem.clone(),
            sp_signing_cert_pem: sp.sp_signing_cert_pem.clone(),
            want_authn_requests_signed: Some(sp.want_authn_requests_signed),
        }
    }
}

/// Deserialize a member where an explicit `null` and an absent member differ:
/// with `#[serde(default)]`, absent stays `None` and `null` becomes
/// `Some(None)` (generator `EXPLICIT_NULL_FIELDS`).
pub(crate) fn explicit_null<'de, D, T>(deserializer: D) -> Result<Option<Option<T>>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::Deserialize<'de>,
{
    serde::Deserialize::deserialize(deserializer).map(Some)
}

/// Read-modify-write for `ssf.update_stream`. `authorization_header` is left
/// `None` — absent keeps the stored header (§32.2) — and so is
/// `clear_authorization_header`.
impl From<&models::SsfStream> for models::SsfStreamInput {
    fn from(s: &models::SsfStream) -> Self {
        Self {
            audience: s.audience.clone(),
            authorization_header: None,
            clear_authorization_header: None,
            delivery_method: s.delivery_method.clone(),
            description: s.description.clone(),
            endpoint_url: s.endpoint_url.clone(),
            events_allowed: s.events_allowed.clone(),
            events_requested: Some(s.events_requested.clone()),
            receiver_client_id: s.receiver_client_id.clone(),
            status: Some(s.status.clone()),
            status_reason: s.status_reason.clone(),
            subject_format: Some(s.subject_format.clone()),
        }
    }
}

/// Read-modify-write for `scim_targets.update`. `credential` is left `None` —
/// absent keeps the stored one, unless the write moves its URL (§31.3 rule 2).
impl From<&models::ScimTargetResponse> for models::ScimTargetInput {
    fn from(t: &models::ScimTargetResponse) -> Self {
        Self {
            auth: t.auth.clone(),
            base_url: t.base_url.clone(),
            credential: None,
            deprovision: Some(t.deprovision.clone()),
            enabled: Some(t.enabled),
            expected_updated_at: None,
            name: t.name.clone(),
            push_groups: Some(t.push_groups),
            scope: t.scope.clone(),
            user_name_from: Some(t.user_name_from.clone()),
        }
    }
}

/// Read-modify-write for `directory.set`. `bind_secret` is left `None` —
/// absent keeps the stored secret, unless the write moves the connection
/// (§30.3 rule 2).
impl From<&models::DirectoryConfig> for models::SetDirectoryConfig {
    fn from(c: &models::DirectoryConfig) -> Self {
        Self {
            base_dn: c.base_dn.clone(),
            bind_dn: c.bind_dn.clone(),
            bind_secret: None,
            enabled: c.enabled,
            group_base_dn: c.group_base_dn.clone(),
            group_filter: c.group_filter.clone(),
            group_mappings: Some(c.group_mappings.clone()),
            group_member_attribute: Some(c.group_member_attribute.clone()),
            group_nesting_depth: Some(c.group_nesting_depth),
            jit_provisioning: Some(c.jit_provisioning),
            kind: c.kind.clone(),
            start_tls: c.start_tls,
            sync_interval_secs: Some(c.sync_interval_secs),
            trust_anchors_pem: Some(c.trust_anchors_pem.clone()),
            url: c.url.clone(),
            user_attribute_map: Some(c.user_attribute_map.clone()),
            user_filter: c.user_filter.clone(),
        }
    }
}
