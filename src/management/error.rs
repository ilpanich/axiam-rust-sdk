//! Status → error mapping for the §27 management surface.
//!
//! §2 fixes the taxonomy at three error types and §27.4 rule 7 does not widen
//! it. What it adds is a *classification* inside two of them, because a
//! management surface produces refusals §2 never had to describe: §2 has no
//! 404 row at all, since nothing before §27 could return one.
//!
//! In a language with exceptions those classifications are subclasses. Rust
//! has no subtyping, so they are realized the two ways Rust actually offers:
//! a discriminant on the variant ([`crate::AuthzKind`]) for 404/409, and a
//! typed [`std::error::Error`] source for 400/422. Both leave
//! `matches!(e, AxiamError::Authz { .. })` and
//! `matches!(e, AxiamError::Network { .. })` compiling and true, which is what
//! "additive" has to mean.

use serde::Deserialize;

use crate::error::AuthzKind;
use crate::{AxiamError, Sensitive};

/// A rejected management request, carried as the `source` of an
/// [`AxiamError::Network`] (CONTRACT.md §27.4 rule 7).
///
/// §2 maps 400 to `NetworkError`, described as an "SDK programming error".
/// That description was written when nothing but the SDK itself could produce
/// a 400. On the management surface a 400 is usually a *user's* invalid input
/// — an email that is not an email, a slug that is taken — and an application
/// needs to tell that from a broken socket without matching on message text.
///
/// The parent type is inherited from §2 rather than chosen here. Retrieve one
/// with [`AxiamError::validation`].
#[derive(Debug, Clone, thiserror::Error)]
#[error("{message}")]
pub struct ValidationError {
    /// The HTTP status the server answered with — 400 or 422.
    pub status: u16,
    /// The registry operation that was rejected, e.g. `"users.create"`.
    pub operation: &'static str,
    /// The server's message.
    pub message: String,
    /// Per-field detail, where the server sent any. Empty is normal.
    pub fields: Vec<FieldError>,
}

/// One field-level complaint inside a [`ValidationError`].
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct FieldError {
    /// The offending field's name, as the server names it.
    pub field: String,
    /// What is wrong with it.
    pub message: String,
}

/// The two body shapes the server uses for field-level validation detail.
///
/// Parsed leniently and on a best-effort basis: a body that carries no field
/// detail, or carries it in a shape neither arm matches, yields an empty
/// `fields` rather than an error. Failing to parse an error body would replace
/// a useful message with a useless one.
#[derive(Deserialize)]
#[serde(untagged)]
enum FieldErrorBody {
    Keyed {
        errors: Vec<FieldError>,
    },
    /// `{"errors": {"email": "is not valid", ...}}`
    Map {
        errors: std::collections::BTreeMap<String, String>,
    },
}

impl AxiamError {
    /// The §27.4 rule 7 validation detail, when this error carries any.
    ///
    /// `None` for every error that is not a management 400/422 — including
    /// every transport failure, which is the distinction this exists to make.
    pub fn validation(&self) -> Option<&ValidationError> {
        match self {
            AxiamError::Network {
                source: Some(source),
                ..
            } => source.downcast_ref::<ValidationError>(),
            _ => None,
        }
    }

    /// Whether this is a management 404 — absent, or another tenant's.
    pub fn is_not_found(&self) -> bool {
        matches!(
            self,
            AxiamError::Authz {
                kind: AuthzKind::NotFound,
                ..
            }
        )
    }

    /// Whether this is a management 409 — a uniqueness or state conflict.
    pub fn is_conflict(&self) -> bool {
        matches!(
            self,
            AxiamError::Authz {
                kind: AuthzKind::Conflict,
                ..
            }
        )
    }
}

/// Map a failed management response onto the §2 taxonomy.
///
/// Delegates to [`AxiamError::from_http_status`] for everything §27 does not
/// classify, so the two mappers cannot drift: this function's whole job is the
/// three statuses §27.4 rule 7 names, and 404 is the one §2 genuinely lacks.
pub(crate) fn from_management_status(
    operation: &'static str,
    status: u16,
    body: String,
) -> AxiamError {
    match status {
        // §2 has no 404 row. In a multi-tenant IAM the server answers 404 for
        // a resource in another tenant *on purpose* — a distinguishable
        // "exists but not yours" is an enumeration oracle — so "absent" and
        // "not yours" are one outcome, and `AuthzError` is where it belongs.
        404 => AxiamError::authz_kind(
            AuthzKind::NotFound,
            format!("{operation}: not found (or not visible to this tenant): {body}"),
            None,
            None,
        ),
        400 | 422 => {
            let fields = parse_field_errors(&body);
            AxiamError::network_with_source(
                format!("{operation}: request rejected: {body}"),
                Box::new(ValidationError {
                    status,
                    operation,
                    message: body,
                    fields,
                }),
            )
        }
        // 401/403/409/5xx and everything else keep §2's mapping exactly;
        // `from_http_status` already splits 409 into `AuthzKind::Conflict`.
        other => AxiamError::from_http_status(other, body),
    }
}

fn parse_field_errors(body: &str) -> Vec<FieldError> {
    match serde_json::from_str::<FieldErrorBody>(body) {
        Ok(FieldErrorBody::Keyed { errors }) => errors,
        Ok(FieldErrorBody::Map { errors }) => errors
            .into_iter()
            .map(|(field, message)| FieldError { field, message })
            .collect(),
        Err(_) => Vec::new(),
    }
}

/// Redaction guard for generated request models that carry a secret.
///
/// The generated wire structs hold plain `String`s so `serde` can write them;
/// the public models hold [`Sensitive`]. This is the one place the two meet,
/// so that "unwrap a secret to put it on the wire" is a single greppable call
/// rather than fourteen (§7 rule 4).
pub(crate) fn expose_for_wire(value: &Sensitive<String>) -> String {
    value.expose().clone()
}

/// The inverse: wrap a secret the server returned exactly once.
pub(crate) fn wrap_from_wire(value: String) -> Sensitive<String> {
    Sensitive::new(value)
}
