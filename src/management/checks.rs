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

/// Read-modify-write for `ssf.update_stream`, **the plain converter**.
/// `authorization_header` is left `None` — absent keeps the stored header
/// (§32.2) — and so is `clear_authorization_header`. `events_requested` is always
/// sent, as read (`[]` stays `[]`; omitting it would reset a receiver's narrowing
/// to every allowed event), and `expected_updated_at` carries the `updated_at`
/// string that was read — the server's own, byte for byte — so the replacement is
/// refused `409` if the stream was written in between (§32.2, contract 1.61); set
/// it to `None` for the old last-writer-wins behaviour.
///
/// # The caller's duty
///
/// **This converter cannot know that you are about to lower `events_allowed`, so
/// it does not cut `events_requested` to the new ceiling — that is yours.** If
/// you shrink `events_allowed`, remove from `events_requested` every event the
/// new ceiling no longer holds, or the server refuses the update `400` (a list
/// outside `events_allowed`). Never clear it to `None` to get out of the
/// problem: an absent `events_requested` *resets* the stream to every event of
/// `events_allowed`, widening a narrowing the receiver made, and AXIAM then
/// sends the receiver more events about the tenant's users than it asked for.
/// `Some(vec![])` is the receiver's "none" and stays that. A `409` means the
/// stream was written since you read it (the receiver's own pause or narrowing
/// included): read it again. The three meanings of `events_requested` are stated
/// at [`Ssf::update_stream`](crate::management::ops::ssf::Ssf::update_stream).
///
/// Prefer [`models::SsfStreamInput::from_stream_with`], which takes the changes
/// and does the cut for you.
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
            expected_updated_at: Some(s.updated_at.clone()),
            receiver_client_id: s.receiver_client_id.clone(),
            status: Some(s.status.clone()),
            status_reason: s.status_reason.clone(),
            subject_format: Some(s.subject_format.clone()),
        }
    }
}

/// What to change in a stream that was read — the second argument of
/// [`models::SsfStreamInput::from_stream_with`] (CONTRACT.md §32.2, contract
/// 1.62).
///
/// Every member is optional and `None` means *leave as read*. The members that
/// can be "none" on the wire are `Option<Option<_>>`: `Some(Some(v))` sets `v`,
/// and `Some(None)` is a stated "none" — the key is **left out** of the body and
/// `null` is never sent (§27.11 rule 5).
///
/// ```
/// # use axiam_sdk::management::{SsfStreamChanges, models};
/// # fn demo(stream: &models::SsfStream, one: models::SsfEventType) {
/// let body = models::SsfStreamInput::from_stream_with(
///     stream,
///     SsfStreamChanges {
///         events_allowed: Some(vec![one]),
///         ..Default::default()
///     },
/// );
/// # let _ = body;
/// # }
/// ```
#[derive(Debug, Clone, Default)]
pub struct SsfStreamChanges {
    /// A new `audience` (1–512 bytes, unique across the deployment).
    pub audience: Option<String>,
    /// Send this `Authorization` header value to the push endpoint. Write-only;
    /// absent (the default) keeps the stored one, unless the update moves the
    /// endpoint to another origin (§32.3 rule 5).
    pub authorization_header: Option<crate::Sensitive<String>>,
    /// Remove the stored header. Refused with `authorization_header`.
    pub clear_authorization_header: Option<bool>,
    /// A new delivery method.
    pub delivery_method: Option<models::SsfDeliveryMethod>,
    /// A new `description`; `Some(None)` clears it (the key is left out).
    pub description: Option<Option<String>>,
    /// A new `endpoint_url`; `Some(None)` leaves the key out.
    pub endpoint_url: Option<Option<String>>,
    /// A new ceiling. When this is set and [`Self::events_requested`] is not,
    /// the `events_requested` that was read is **cut** to it: the entries that
    /// are in the new ceiling, in their order.
    pub events_allowed: Option<Vec<models::SsfEventType>>,
    /// Name the `events_requested` to send, and it is sent **as given** — the
    /// server judges it (`400` outside `events_allowed`). `Some(None)` leaves
    /// the key out, which *resets* the stream to every event of
    /// `events_allowed`: say so on purpose, never by accident (§32.2).
    pub events_requested: Option<Option<Vec<models::SsfEventType>>>,
    /// Name the `expected_updated_at` to send instead of the read's.
    /// `Some(None)` is "none": the key is left out, `null` is never sent, and
    /// the replacement is conditional only on what the server reads during the
    /// request (last-writer-wins on the fields a receiver may have changed).
    pub expected_updated_at: Option<Option<String>>,
    /// A new `receiver_client_id`.
    pub receiver_client_id: Option<String>,
    /// A new `status`.
    pub status: Option<models::SsfStreamStatus>,
    /// A new `status_reason`; `Some(None)` leaves the key out.
    pub status_reason: Option<Option<String>>,
    /// A new `subject_format`.
    pub subject_format: Option<models::SsfSubjectFormat>,
}

impl models::SsfStreamInput {
    /// The **change-taking** read-modify-write form for `ssf.update_stream`:
    /// `(stream, changes) → body` (CONTRACT.md §32.2, contract 1.62; PHP's
    /// `ReadModifyWrite::ssfStream` is the model).
    ///
    /// Applies `changes` over what was read and:
    ///
    /// * sends the `events_requested` **as read** — `[]` stays `[]`, never
    ///   omitted, because an absent one *resets* the stream to every event of
    ///   `events_allowed` and widens what the receiver narrowed;
    /// * sends the `expected_updated_at` **as read**: the response's own string,
    ///   byte for byte, so a write made since (the receiver's included) answers
    ///   `409` instead of being overwritten;
    /// * **cuts** `events_requested` to the new `events_allowed` when the
    ///   changes lower the ceiling and name no `events_requested` themselves —
    ///   the entries of the read list that are in the new ceiling, in their
    ///   order. An `events_requested` named in the changes is sent as given;
    /// * leaves `authorization_header` and `clear_authorization_header` alone
    ///   unless the changes set them: absent keeps the stored header.
    ///
    /// A `Some(None)` on `expected_updated_at` or any nullable member is "none":
    /// the key is omitted and `null` is never sent (§27.11 rule 5).
    #[must_use]
    pub fn from_stream_with(stream: &models::SsfStream, changes: SsfStreamChanges) -> Self {
        let mut body = Self::from(stream);
        let SsfStreamChanges {
            audience,
            authorization_header,
            clear_authorization_header,
            delivery_method,
            description,
            endpoint_url,
            events_allowed,
            events_requested,
            expected_updated_at,
            receiver_client_id,
            status,
            status_reason,
            subject_format,
        } = changes;

        if let Some(v) = audience {
            body.audience = v;
        }
        if let Some(v) = authorization_header {
            body.authorization_header = Some(v);
        }
        if let Some(v) = clear_authorization_header {
            body.clear_authorization_header = Some(v);
        }
        if let Some(v) = delivery_method {
            body.delivery_method = v;
        }
        if let Some(v) = description {
            body.description = v;
        }
        if let Some(v) = endpoint_url {
            body.endpoint_url = v;
        }
        if let Some(ceiling) = events_allowed {
            // The cut: only when the caller did not name `events_requested`.
            if events_requested.is_none() {
                body.events_requested = body.events_requested.take().map(|read| {
                    read.into_iter()
                        .filter(|event| ceiling.contains(event))
                        .collect()
                });
            }
            body.events_allowed = ceiling;
        }
        if let Some(v) = events_requested {
            body.events_requested = v;
        }
        if let Some(v) = expected_updated_at {
            body.expected_updated_at = v;
        }
        if let Some(v) = receiver_client_id {
            body.receiver_client_id = v;
        }
        if let Some(v) = status {
            body.status = Some(v);
        }
        if let Some(v) = status_reason {
            body.status_reason = v;
        }
        if let Some(v) = subject_format {
            body.subject_format = Some(v);
        }
        body
    }
}

/// Read-modify-write for `scim_targets.update`. `credential` is left `None` —
/// absent keeps the stored one, unless the write moves its URL (§31.3 rule 2).
/// `expected_updated_at` carries the `updated_at` that was read, so the
/// replacement is refused `409` if another administrator wrote the target in
/// between (§31.3 rule 4, contract 1.60); set it to `None` for the old
/// last-writer-wins behaviour.
impl From<&models::ScimTargetResponse> for models::ScimTargetInput {
    fn from(t: &models::ScimTargetResponse) -> Self {
        Self {
            auth: t.auth.clone(),
            base_url: t.base_url.clone(),
            credential: None,
            deprovision: Some(t.deprovision.clone()),
            enabled: Some(t.enabled),
            expected_updated_at: Some(t.updated_at.clone()),
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
