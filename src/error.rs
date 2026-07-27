//! `AxiamError` — the single, `?`-friendly error type for this SDK
//! (CONTRACT.md §2, D-06).
//!
//! Three top-level *kinds* exist: `Auth`, `Authz`, `Network`, matching the
//! CONTRACT.md §2 error taxonomy exactly. §2 additionally permits
//! language-idiomatic **sub-types** of those three (they never replace them):
//! [`OAuthProtocolError`] is one such sub-type, carried by the `Auth` variant
//! itself via its `oauth` field (CONTRACT.md §12.3 rule 3, addendum item 17)
//! — `AxiamError::Auth { .. }` still matches an OAuth2-protocol failure, so
//! existing `match`/`?` handling that only cares about the outer variant
//! keeps compiling and behaving correctly; code that wants the structured
//! `error`/`error_description` pair reads the `oauth` field or calls
//! [`AxiamError::oauth_protocol_error`]. Mapping helpers translate HTTP
//! status codes and gRPC status codes into the correct variant per the
//! CONTRACT.md §2 tables.
//!
//! **Security note:** none of these variants may ever carry a raw token
//! value. The mapping helpers below accept a caller-controlled `message`;
//! callers MUST NOT pass token values into it.

use std::error::Error as StdError;
use std::fmt;

/// The unified error type returned by all fallible operations in this SDK.
///
/// # Stability of the variant *fields*
///
/// All three variants are `#[non_exhaustive]`. The enum itself is not: §2
/// fixes the taxonomy at exactly three error types, so no fourth variant can
/// ever be added and `match`ing all three exhaustively stays sound. What §2
/// does *not* freeze is each variant's field set — contract 1.4 added
/// `oauth`/`reason` to [`AxiamError::Auth`], and a future contract revision
/// may add more.
///
/// `#[non_exhaustive]` on the variants makes such an addition additive
/// instead of source-breaking:
///
/// * **Matching** — always use `..`: `AxiamError::Auth { message, .. }`,
///   `matches!(e, AxiamError::Network { .. })`. This already compiles today
///   and keeps compiling when fields are added.
/// * **Constructing** — outside this crate, use the constructors
///   ([`AxiamError::auth`], [`AxiamError::authz`], [`AxiamError::network`],
///   [`AxiamError::network_with_source`], [`AxiamError::oauth_protocol_error`],
///   [`AxiamError::id_token_invalid`], [`AxiamError::from_http_status`],
///   [`AxiamError::from_grpc_code`]) rather than struct-variant literals.
#[derive(thiserror::Error, Debug)]
pub enum AxiamError {
    /// Authentication failure: wrong credentials, expired session, MFA
    /// failure, a 401 on refresh, an RFC 6749 OAuth2 protocol error
    /// (CONTRACT.md §12.3 rule 3), or a §12.4 ID-token validation failure
    /// (CONTRACT.md §2).
    ///
    /// Construct with [`AxiamError::auth`] (or one of the more specific
    /// builders); destructure with a trailing `..`.
    #[error("authentication failed: {message}")]
    #[non_exhaustive]
    Auth {
        /// Human-readable description of the failure. MUST NOT contain a
        /// raw token value.
        message: String,
        /// Populated when this failure is specifically an RFC 6749
        /// `OAuth2ErrorResponse` from an `/oauth2/*` endpoint
        /// (CONTRACT.md §12.3 rule 3) — `None` for every other `Auth`
        /// failure. See [`OAuthProtocolError`].
        oauth: Option<OAuthProtocolError>,
        /// A stable, machine-readable reason code, populated by the
        /// CONTRACT.md §12.4 ID-token validation checklist with one of the
        /// seven codes [`IdTokenFailureReason`] enumerates; `None` for every
        /// other `Auth` failure. A *code*, never free text, so callers can
        /// branch on it without parsing `message`.
        reason: Option<IdTokenFailureReason>,
    },

    /// Authorization failure: the caller is authenticated but lacks
    /// permission for the requested operation (CONTRACT.md §2).
    ///
    /// Construct with [`AxiamError::authz`]; destructure with a trailing `..`.
    #[error("authorization denied: {message}")]
    #[non_exhaustive]
    Authz {
        /// Human-readable description of the failure. MUST NOT contain a
        /// raw token value.
        message: String,
        /// The denied action, if known from the response body.
        action: Option<String>,
        /// The resource the action was denied against, if known.
        resource_id: Option<String>,
    },

    /// Transport-level failure: connection refused, timeout, TLS error, DNS
    /// failure, or a server-side 5xx (CONTRACT.md §2).
    ///
    /// Construct with [`AxiamError::network`] /
    /// [`AxiamError::network_with_source`]; destructure with a trailing `..`.
    #[error("network error: {message}")]
    #[non_exhaustive]
    Network {
        /// Human-readable description of the failure. MUST NOT contain a
        /// raw token value.
        message: String,
        /// The underlying transport error, if any. Boxed as a trait object
        /// so this variant compiles without any transport feature enabled;
        /// later plans may wrap concrete `reqwest`/`tonic`/`lapin` errors
        /// here via `From` impls.
        #[source]
        source: Option<Box<dyn StdError + Send + Sync>>,
    },
}

impl AxiamError {
    /// Build an [`AxiamError::Auth`] carrying just a message — the public
    /// constructor to use instead of a struct-variant literal, so that adding
    /// a field to the variant stays additive (see the type-level docs).
    ///
    /// `message` MUST NOT contain a raw token value.
    pub fn auth(message: impl Into<String>) -> AxiamError {
        AxiamError::Auth {
            message: message.into(),
            oauth: None,
            reason: None,
        }
    }

    /// Build an [`AxiamError::Authz`], optionally with the denied `action`
    /// and `resource_id` CONTRACT.md §2 says to carry when the response body
    /// provides them.
    pub fn authz(
        message: impl Into<String>,
        action: Option<String>,
        resource_id: Option<String>,
    ) -> AxiamError {
        AxiamError::Authz {
            message: message.into(),
            action,
            resource_id,
        }
    }

    /// Build an [`AxiamError::Network`] with no chained transport cause.
    pub fn network(message: impl Into<String>) -> AxiamError {
        AxiamError::Network {
            message: message.into(),
            source: None,
        }
    }

    /// Build an [`AxiamError::Network`] chaining the underlying transport
    /// error as its [`std::error::Error::source`], as CONTRACT.md §2's
    /// construction rules require.
    pub fn network_with_source(
        message: impl Into<String>,
        source: Box<dyn StdError + Send + Sync>,
    ) -> AxiamError {
        AxiamError::Network {
            message: message.into(),
            source: Some(source),
        }
    }

    /// Map an HTTP status code to an [`AxiamError`] variant per CONTRACT.md
    /// §2's HTTP status table.
    ///
    /// | Status       | Variant  |
    /// |--------------|----------|
    /// | 400          | Network  |
    /// | 401          | Auth     |
    /// | 403          | Authz    |
    /// | 408, 429     | Network  |
    /// | 409          | Authz    |
    /// | 5xx          | Network  |
    /// | other        | Network  |
    ///
    /// `message` is caller-controlled and MUST NOT contain a raw token
    /// value.
    ///
    /// For 403/409 (mapped to `Authz`), `message` is also speculatively
    /// parsed as the server's structured error body
    /// (`{"error":"authorization_denied","message":"...","action":"...",
    /// "resource_id":"..."}`) to populate `action`/`resource_id` when the
    /// server included them. `message` itself is left exactly as passed in
    /// (raw body text) — only `action`/`resource_id` are pulled out of the
    /// same body.
    pub fn from_http_status(status: u16, message: impl Into<String>) -> AxiamError {
        let message = message.into();
        match status {
            401 => AxiamError::Auth {
                message,
                oauth: None,
                reason: None,
            },
            403 | 409 => {
                let (action, resource_id) = parse_authz_body_fields(&message);
                AxiamError::Authz {
                    message,
                    action,
                    resource_id,
                }
            }
            _ => AxiamError::Network {
                message,
                source: None,
            },
        }
    }

    /// Map a gRPC status code (as its numeric `tonic::Code` value) to an
    /// [`AxiamError`] variant per CONTRACT.md §2's gRPC status table.
    ///
    /// | Code                      | Variant  |
    /// |---------------------------|----------|
    /// | 16 UNAUTHENTICATED        | Auth     |
    /// | 7 PERMISSION_DENIED       | Authz    |
    /// | 14 UNAVAILABLE            | Network  |
    /// | 4 DEADLINE_EXCEEDED       | Network  |
    /// | 13 INTERNAL               | Network  |
    /// | 8 RESOURCE_EXHAUSTED      | Network  |
    /// | other                     | Network  |
    ///
    /// `message` is caller-controlled and MUST NOT contain a raw token
    /// value.
    pub fn from_grpc_code(code: i32, message: impl Into<String>) -> AxiamError {
        let message = message.into();
        match code {
            16 => AxiamError::Auth {
                message,
                oauth: None,
                reason: None,
            },
            // gRPC `PERMISSION_DENIED` carries no structured error body (no
            // JSON payload analogous to the REST 403's
            // `{"action":...,"resource_id":...}`) — `action`/`resource_id`
            // stay `None` here.
            7 => AxiamError::Authz {
                message,
                action: None,
                resource_id: None,
            },
            _ => AxiamError::Network {
                message,
                source: None,
            },
        }
    }
}

impl AxiamError {
    /// Build the `Auth` sub-type for an RFC 6749 `OAuth2ErrorResponse` body
    /// returned by an `/oauth2/*` endpoint (CONTRACT.md §12.3 rule 3,
    /// addendum item 17): a `400` from `POST /oauth2/token` or a `401` from
    /// `POST /oauth2/introspect` / `POST /oauth2/revoke`.
    ///
    /// The result is still `AxiamError::Auth { .. }` — `matches!(err,
    /// AxiamError::Auth { .. })` is `true` for it, so it participates in
    /// every existing "this is an authentication failure" code path — but
    /// its `oauth` field is populated so callers can branch on the RFC 6749
    /// `error` code without parsing `message`. `message` is always exactly
    /// `"<error>: <error_description>"` (CONTRACT.md §2 construction rules).
    pub fn oauth_protocol_error(
        error: impl Into<String>,
        error_description: impl Into<String>,
    ) -> AxiamError {
        let error = error.into();
        let error_description = error_description.into();
        let message = format!("{error}: {error_description}");
        AxiamError::Auth {
            message,
            oauth: Some(OAuthProtocolError {
                error,
                error_description,
            }),
            reason: None,
        }
    }

    /// Build the `Auth` sub-type for a CONTRACT.md §12.4 ID-token validation
    /// failure, carrying the matching stable `reason` code. `detail` is a
    /// short, human-readable explanation; per §2's construction rules it
    /// MUST NOT embed a token, client secret, code verifier, or expected
    /// nonce value.
    pub fn id_token_invalid(reason: IdTokenFailureReason, detail: impl fmt::Display) -> AxiamError {
        AxiamError::Auth {
            message: format!("id_token validation failed ({reason}): {detail}"),
            oauth: None,
            reason: Some(reason),
        }
    }

    /// The structured RFC 6749 `error`/`error_description` pair, when this
    /// is an OAuth2-protocol `Auth` failure (CONTRACT.md §12.3 rule 3).
    /// `None` for every other error, including every other `Auth` failure.
    pub fn as_oauth_protocol_error(&self) -> Option<&OAuthProtocolError> {
        match self {
            AxiamError::Auth {
                oauth: Some(oauth), ..
            } => Some(oauth),
            _ => None,
        }
    }

    /// The stable CONTRACT.md §12.4 ID-token validation reason code, when
    /// this `Auth` failure came from the ID-token validation checklist.
    /// `None` for every other error.
    pub fn id_token_failure_reason(&self) -> Option<IdTokenFailureReason> {
        match self {
            AxiamError::Auth { reason, .. } => *reason,
            _ => None,
        }
    }

    /// Reconstruct this error for a CONTRACT.md §9 rule 2 *waiter*.
    ///
    /// `AxiamError` is not `Clone`, and cannot cheaply become so: the
    /// `Network` variant chains a `Box<dyn std::error::Error + Send + Sync>`
    /// that has no `Clone` bound. §9 rule 2 nonetheless requires the single
    /// in-flight refresh to hand *its* failure to every concurrent waiter, and
    /// a waiter needs **an** error, not a byte-identical one. This therefore
    /// preserves everything a caller can branch on —
    ///
    /// * the taxonomy variant (`Auth` stays `Auth`, never widens to `Network`),
    /// * the `oauth` [`OAuthProtocolError`] payload (`error` +
    ///   `error_description`, so `invalid_grant` is still `invalid_grant`),
    /// * the `reason` [`IdTokenFailureReason`] code,
    /// * the `message` string, and for `Authz` the `action`/`resource_id`
    ///
    /// — and drops only the un-clonable `Network::source` chain, which is a
    /// diagnostic detail rather than something a caller matches on. `Display`
    /// output is byte-identical in every case, because every variant's
    /// `#[error(...)]` format string reads only `message`.
    pub(crate) fn clone_for_waiter(&self) -> AxiamError {
        match self {
            AxiamError::Auth {
                message,
                oauth,
                reason,
            } => AxiamError::Auth {
                message: message.clone(),
                oauth: oauth.clone(),
                reason: *reason,
            },
            AxiamError::Authz {
                message,
                action,
                resource_id,
            } => AxiamError::Authz {
                message: message.clone(),
                action: action.clone(),
                resource_id: resource_id.clone(),
            },
            AxiamError::Network { message, .. } => AxiamError::Network {
                message: message.clone(),
                source: None,
            },
        }
    }
}

/// An RFC 6749 protocol error returned by an `/oauth2/*` endpoint as an
/// `OAuth2ErrorResponse` body (CONTRACT.md §2 sub-type table, §12.3 rule 3).
///
/// A **sub-type of [`AxiamError::Auth`]**, not a replacement for it: it is
/// always carried *inside* an `Auth` value (see
/// [`AxiamError::oauth_protocol_error`]), never a separate top-level
/// variant, so existing `match err { AxiamError::Auth { .. } => .. }` code
/// keeps matching it — that backward compatibility is what makes contract
/// 1.4 additive rather than breaking.
///
/// `error`/`error_description` are the two `OAuth2ErrorResponse` wire
/// fields, exposed individually; [`AxiamError::Auth`]'s `message` field is
/// always exactly `"<error>: <error_description>"`, built from them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OAuthProtocolError {
    /// The RFC 6749 `error` code (e.g. `"invalid_grant"`, `"invalid_client"`,
    /// `"unsupported_grant_type"`).
    pub error: String,
    /// The server's human-readable `error_description`. Never contains
    /// token material.
    pub error_description: String,
}

impl fmt::Display for OAuthProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.error, self.error_description)
    }
}

impl StdError for OAuthProtocolError {}

/// The seven stable reason codes CONTRACT.md §12.3 rule 3 defines for
/// ID-token validation failures ([§12.4](crate) checklist), one per rule.
/// Surfaced via [`AxiamError::id_token_failure_reason`]. `Display` renders
/// the exact wire spelling the contract fixes (e.g. `invalid_alg`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IdTokenFailureReason {
    /// The JOSE header `alg` was not exactly `EdDSA` (§12.4 rule 1).
    InvalidAlg,
    /// The `kid` was absent, or still unknown after one JWKS re-fetch
    /// (§12.4 rule 2).
    UnknownKid,
    /// The Ed25519 signature did not verify against the resolved key
    /// (§12.4 rule 2).
    InvalidSignature,
    /// The `iss` claim did not exactly equal the discovery document's
    /// `issuer` (§12.4 rule 3).
    InvalidIssuer,
    /// The `aud` claim did not contain this client's `client_id`, or
    /// multiple audiences were present with no matching `azp` (§12.4
    /// rule 4).
    InvalidAudience,
    /// `exp`, `iat`, or `nbf` failed the §12.4 rule 5 time checks (beyond
    /// the permitted clock skew, or missing/non-numeric).
    TokenExpired,
    /// The `nonce` claim was absent, non-string, or did not match the
    /// request nonce (§12.4 rule 6).
    NonceMismatch,
}

impl IdTokenFailureReason {
    /// The exact machine-readable wire spelling CONTRACT.md §12.3 rule 3
    /// fixes for this reason code (e.g. `"invalid_alg"`).
    pub fn as_str(self) -> &'static str {
        match self {
            IdTokenFailureReason::InvalidAlg => "invalid_alg",
            IdTokenFailureReason::UnknownKid => "unknown_kid",
            IdTokenFailureReason::InvalidSignature => "invalid_signature",
            IdTokenFailureReason::InvalidIssuer => "invalid_issuer",
            IdTokenFailureReason::InvalidAudience => "invalid_audience",
            IdTokenFailureReason::TokenExpired => "token_expired",
            IdTokenFailureReason::NonceMismatch => "nonce_mismatch",
        }
    }
}

impl fmt::Display for IdTokenFailureReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Best-effort extraction of `action`/`resource_id` out of a REST error
/// body for the `Authz` variant (CONTRACT.md §2: "SHOULD carry the denied
/// `action` and `resource_id` if available from the response body"). The
/// server's structured 403 body looks like:
/// `{"error":"authorization_denied","message":"...","action":"users:get","resource_id":"<uuid>"}`
/// — `action` is present when known, `resource_id` only for a
/// resource-scoped denial. Any parse failure (non-JSON body, missing keys,
/// or a 409 body with a different shape) silently yields `(None, None)`
/// rather than surfacing a secondary error — `action`/`resource_id` are
/// best-effort extras, never load-bearing for the `Authz` variant itself.
fn parse_authz_body_fields(body: &str) -> (Option<String>, Option<String>) {
    #[derive(serde::Deserialize)]
    struct AuthzErrorBody {
        #[serde(default)]
        action: Option<String>,
        #[serde(default)]
        resource_id: Option<String>,
    }

    match serde_json::from_str::<AuthzErrorBody>(body) {
        Ok(parsed) => (parsed.action, parsed.resource_id),
        Err(_) => (None, None),
    }
}

// Manual Display impls are provided by `#[error(...)]` above via thiserror;
// this explicit re-statement documents the redaction invariant for readers
// browsing the source without expanding the derive macro.
#[allow(dead_code)]
fn _assert_no_token_in_display<T: fmt::Display>(_: &T) {}

#[cfg(test)]
mod tests {
    use super::*;

    // Exercises the otherwise-uncalled `_assert_no_token_in_display` helper
    // itself (it exists purely to document the redaction invariant at the
    // type level — no other code path ever calls it).
    #[test]
    fn assert_no_token_in_display_accepts_any_display_error_variant() {
        let auth = AxiamError::auth("msg");
        _assert_no_token_in_display(&auth);
    }

    #[test]
    fn public_constructors_build_the_documented_variants() {
        assert!(matches!(AxiamError::auth("a"), AxiamError::Auth { .. }));
        assert!(matches!(
            AxiamError::authz("b", Some("users:get".into()), None),
            AxiamError::Authz {
                action: Some(_),
                resource_id: None,
                ..
            }
        ));
        assert!(matches!(
            AxiamError::network("c"),
            AxiamError::Network { source: None, .. }
        ));
        let chained = AxiamError::network_with_source("d", Box::new(std::fmt::Error));
        assert!(StdError::source(&chained).is_some());
    }

    /// CONTRACT.md §9 rule 2: waiters receive the leader's outcome. The
    /// taxonomy variant, the `oauth` payload, the `reason` code and the
    /// rendered `Display` must all survive the trip.
    #[test]
    fn clone_for_waiter_preserves_variant_oauth_payload_and_reason() {
        let oauth = AxiamError::oauth_protocol_error("invalid_grant", "refresh token revoked");
        let cloned = oauth.clone_for_waiter();
        assert!(matches!(cloned, AxiamError::Auth { .. }));
        assert_eq!(
            cloned.as_oauth_protocol_error().map(|o| o.error.as_str()),
            Some("invalid_grant")
        );
        assert_eq!(
            cloned
                .as_oauth_protocol_error()
                .map(|o| o.error_description.as_str()),
            Some("refresh token revoked")
        );
        assert_eq!(cloned.to_string(), oauth.to_string());

        let id_token = AxiamError::id_token_invalid(IdTokenFailureReason::NonceMismatch, "nope");
        let cloned = id_token.clone_for_waiter();
        assert_eq!(
            cloned.id_token_failure_reason(),
            Some(IdTokenFailureReason::NonceMismatch)
        );
        assert_eq!(cloned.to_string(), id_token.to_string());
    }

    #[test]
    fn clone_for_waiter_keeps_authz_fields_and_drops_only_the_network_source() {
        let authz = AxiamError::from_http_status(
            403,
            r#"{"action":"users:get","resource_id":"r-1"}"#.to_string(),
        );
        let cloned = authz.clone_for_waiter();
        match cloned {
            AxiamError::Authz {
                ref action,
                ref resource_id,
                ..
            } => {
                assert_eq!(action.as_deref(), Some("users:get"));
                assert_eq!(resource_id.as_deref(), Some("r-1"));
            }
            other => panic!("expected Authz, got {other:?}"),
        }

        let network = AxiamError::network_with_source("boom", Box::new(std::fmt::Error));
        let cloned = network.clone_for_waiter();
        assert!(matches!(cloned, AxiamError::Network { source: None, .. }));
        // Display is unchanged: the format string reads only `message`.
        assert_eq!(cloned.to_string(), network.to_string());
    }
}
