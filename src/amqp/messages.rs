//! AMQP message DTOs mirroring the server's wire format (CONTRACT.md §8).
//!
//! **Mirror, never import.** These structs reproduce field declaration
//! order and `#[serde(...)]` attributes byte-for-byte from
//! `crates/axiam-amqp/src/messages.rs:166-245` so that
//! `serde_json::to_vec`/`to_string` produces canonical JSON byte-identical
//! to what the server signs/verifies against. This crate does NOT depend on
//! the `axiam-amqp` or `axiam-core` crates — these are standalone plain
//! structs built only on `serde`, `uuid`, `chrono`, and `serde_json`.
//!
//! Before computing or verifying the HMAC over either struct, the caller
//! MUST set `hmac_signature` to `None` (or remove the key entirely from the
//! serialized JSON object) — otherwise the signature would be computed over
//! a payload that includes a placeholder signature value, making
//! verification impossible. This matches the server's `sign_payload` doc
//! comment (`crates/axiam-amqp/src/messages.rs:31-34`).
//!
//! NEW-4 (v2, `key_version = 2`, BREAKING/hard cutover): the signed body now
//! carries two additional mandatory fields, `nonce` and `issued_at`, used for
//! replay protection (CONTRACT.md §8 "v2 — Replay Protection"). Both fields
//! are ALWAYS emitted (no `skip_serializing_if`) so they sit inside the HMAC
//! coverage. See `testdata/v2_reference_vectors.json`
//! for server-generated canonical bytes + expected HMAC this SDK must
//! reproduce byte-for-byte.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::AxiamError;

/// The action namespaces the audit ingestion keeps for the server's own
/// control records (CONTRACT.md §8, "Actions the audit ingestion refuses").
const RESERVED_AUDIT_PREFIXES: [&str; 2] = ["tenants.", "gdpr."];

/// Whether `action` begins with a reserved namespace, ASCII case ignored.
fn is_reserved_audit_action(action: &str) -> bool {
    RESERVED_AUDIT_PREFIXES.iter().any(|prefix| {
        action
            .as_bytes()
            .get(..prefix.len())
            .is_some_and(|head| head.eq_ignore_ascii_case(prefix.as_bytes()))
    })
}

/// Authorization check request received from `axiam.authz.request`.
///
/// Field declaration order matches the server's `AuthzRequest`
/// (`crates/axiam-amqp/src/messages.rs:166-197`) exactly: `correlation_id`,
/// `tenant_id`, `subject_id`, `action`, `resource_id`, `scope`,
/// `key_version`, `nonce`, `issued_at`, `hmac_signature`.
#[derive(Debug, Deserialize, Serialize)]
pub struct AuthzRequest {
    /// Caller-provided ID to correlate request with response.
    pub correlation_id: Uuid,
    /// Tenant the authorization check is scoped to.
    pub tenant_id: Uuid,
    /// Subject (user or service account) requesting access.
    pub subject_id: Uuid,
    /// Permission action being checked (e.g. `"read"`, `"write"`).
    pub action: String,
    /// Resource the action is being checked against.
    pub resource_id: Uuid,
    /// Optional sub-resource scope narrowing the check (CONTRACT.md §1).
    /// `None` means the check applies to the whole resource.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// HKDF master-key rotation version (NEW-4). The consumer rejects any
    /// message with `key_version < 2` — v1 (pre-replay-protection) messages
    /// are not accepted (hard cutover, no grace path).
    pub key_version: u8,
    /// Per-message unique value for replay protection (NEW-4). ALWAYS
    /// emitted (no `skip_serializing_if`) so it sits inside the signed HMAC
    /// body. The consumer rejects a `nonce` it has already seen within the
    /// freshness window as a replay.
    pub nonce: Uuid,
    /// Producer-side send time for the freshness gate (NEW-4). ALWAYS
    /// emitted (no `skip_serializing_if`) so it sits inside the signed HMAC
    /// body. The consumer rejects the message when this lies outside ±skew
    /// of its own clock.
    pub issued_at: DateTime<Utc>,
    /// HMAC-SHA256 of the JSON-serialized message body (this field set to
    /// `None`/omitted before signing). Computed with the per-tenant AMQP
    /// signing key (CONTRACT.md §8). The consumer MUST verify this before
    /// processing; a missing signature is rejected in strict mode (the
    /// default).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hmac_signature: Option<String>,
}

/// Audit event received from external services via `axiam.audit.events`.
///
/// Field declaration order matches the server's `AuditEventMessage`
/// (`crates/axiam-amqp/src/messages.rs:211-245`) exactly: `tenant_id`,
/// `actor_id`, `actor_type`, `action`, `resource_id`, `outcome`,
/// `ip_address`, `metadata`, `key_version`, `nonce`, `issued_at`,
/// `hmac_signature`.
#[derive(Debug, Deserialize, Serialize)]
pub struct AuditEventMessage {
    /// Tenant the audited event occurred in.
    pub tenant_id: Uuid,
    /// User or service account that performed the action.
    pub actor_id: Uuid,
    /// Kind of actor that performed the action (e.g. `"user"`, `"service_account"`).
    pub actor_type: String,
    /// Action that was performed (e.g. `"login"`, `"role.assign"`).
    pub action: String,
    /// Resource the action was performed on, if applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_id: Option<Uuid>,
    /// Result of the action (e.g. `"success"`, `"denied"`, `"error"`).
    pub outcome: String,
    /// Source IP address of the actor, if known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip_address: Option<String>,
    /// Arbitrary structured context attached to the event (e.g. changed
    /// fields, request parameters).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
    /// HKDF master-key rotation version (NEW-4). The consumer rejects any
    /// message with `key_version < 2` — v1 (pre-replay-protection) messages
    /// are not accepted (hard cutover, no grace path).
    pub key_version: u8,
    /// Per-message unique value for replay protection (NEW-4). ALWAYS
    /// emitted (no `skip_serializing_if`) so it sits inside the signed HMAC
    /// body. The consumer rejects a `nonce` it has already seen within the
    /// freshness window as a replay.
    pub nonce: Uuid,
    /// Producer-side send time for the freshness gate (NEW-4). ALWAYS
    /// emitted (no `skip_serializing_if`) so it sits inside the signed HMAC
    /// body. The consumer rejects the message when this lies outside ±skew
    /// of its own clock.
    pub issued_at: DateTime<Utc>,
    /// HMAC-SHA256 of the JSON-serialized message body (CONTRACT.md §8).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hmac_signature: Option<String>,
}

impl AuditEventMessage {
    /// Refuse a reserved `action` before anything is published (CONTRACT.md §8,
    /// contract 1.63): an action that begins with `tenants.` or `gdpr.`, ASCII
    /// case ignored, is dead-lettered by the ingestion with no error from the
    /// acknowledging broker, so the producer says no first. The message names
    /// the namespace, never the payload.
    ///
    /// # Errors
    ///
    /// A local `ValidationError` (status 400, carried as the `source` of an
    /// [`AxiamError::Network`], like every other local refusal of this SDK).
    pub fn check_action(&self) -> Result<(), AxiamError> {
        if !is_reserved_audit_action(&self.action) {
            return Ok(());
        }
        let message = "action: the `tenants.` and `gdpr.` namespaces are reserved for the \
                       server's own audit records and are refused by the audit ingestion \
                       (CONTRACT.md §8)"
            .to_owned();
        #[cfg(feature = "rest")]
        {
            use crate::management::{FieldError, ValidationError};
            Err(AxiamError::network_with_source(
                message.clone(),
                Box::new(ValidationError {
                    status: 400,
                    operation: "audit.publish",
                    message: message.clone(),
                    fields: vec![FieldError {
                        field: "action".to_owned(),
                        message,
                    }],
                }),
            ))
        }
        #[cfg(not(feature = "rest"))]
        Err(AxiamError::network(message))
    }

    /// Sign this message in place with the tenant's derived AMQP subkey,
    /// after [`Self::check_action`]: a message the ingestion would refuse is
    /// never signed, so it cannot be published.
    ///
    /// # Errors
    ///
    /// The [`Self::check_action`] refusal, or a serialization failure.
    pub fn sign(&mut self, signing_key: &[u8]) -> Result<(), AxiamError> {
        self.check_action()?;
        self.hmac_signature = None;
        let bytes = serde_json::to_vec(&*self)
            .map_err(|e| AxiamError::network(format!("audit event serialization failed: {e}")))?;
        self.hmac_signature = Some(crate::amqp::hmac::sign_payload(signing_key, &bytes));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message(action: &str) -> AuditEventMessage {
        AuditEventMessage {
            tenant_id: Uuid::nil(),
            actor_id: Uuid::nil(),
            actor_type: "user".into(),
            action: action.into(),
            resource_id: None,
            outcome: "success".into(),
            ip_address: None,
            metadata: None,
            key_version: 2,
            nonce: Uuid::nil(),
            issued_at: Utc::now(),
            hmac_signature: None,
        }
    }

    #[test]
    fn reserved_actions_are_refused_ascii_case_insensitively() {
        for action in [
            "tenants.delete",
            "Tenants.audit_exported",
            "GDPR.erase",
            "gdpr.x",
        ] {
            let mut m = message(action);
            assert!(m.check_action().is_err(), "{action}");
            assert!(m.sign(b"key").is_err(), "{action} must not be signed");
            assert!(m.hmac_signature.is_none(), "{action}: nothing signed");
        }
    }

    #[test]
    fn refusal_names_the_namespace_and_not_the_action() {
        let e = message("tenants.secret_action").check_action().unwrap_err();
        let text = e.to_string();
        assert!(text.contains("tenants."), "{text}");
        assert!(!text.contains("secret_action"), "{text}");
    }

    #[test]
    fn other_actions_pass_and_sign() {
        for action in [
            "login",
            "role.assign",
            "tenant.x",
            "gdprx",
            "tenants",
            "éenants.x",
        ] {
            let mut m = message(action);
            m.sign(b"key").unwrap_or_else(|e| panic!("{action}: {e}"));
            assert!(m.hmac_signature.is_some());
        }
    }
}
