//! MCP resource-server helpers (CONTRACT.md §28, RFC 9728 + RFC 6750).
//!
//! §28.0: this SDK implements the **resource server**'s half of the Model
//! Context Protocol authorization handshake and nothing else. AXIAM is the
//! authorization server and implements none of §28; the MCP client's half
//! (parsing a challenge, fetching a document, deciding whether to trust the
//! authorization server it names) is deliberately not in this contract
//! version, for the same reason §20.3 stops at parsing.
//!
//! **No operation here performs network I/O**, so §16 (retry) and §9
//! (single-flight refresh) do not apply, and nothing in this module touches
//! the SDK client's own session. All three canonical operations —
//! [`protected_resource_metadata`], [`serve_protected_resource_metadata`],
//! [`bearer_challenge`] — are pure local computation, like `oidc_begin`
//! (§12.1) and `uma_parse_challenge` (§20.5).
//!
//! **Nothing here is a source of truth about a token.** The document is a
//! claim a resource server publishes about itself; the challenge is a hint
//! it gives a caller that already failed. Whether a request is authorized
//! stays [`crate::token::JwksVerifier::verify`]'s and
//! [`crate::middleware::RequireAccess`]'s decision, unchanged and
//! unreachable from here.
//!
//! ## The fourth piece: `resource_metadata_url`
//!
//! §28.1 names one more thing that is a middleware *option*, not an
//! operation: `resource_metadata_url`. In this SDK it lives on
//! [`crate::token::JwksVerifier`] (via
//! [`crate::token::JwksVerifier::with_resource_metadata_url`]) — the same
//! object [`crate::middleware::AxiamUser`] already reads for §10
//! verification — so a §28 challenge is built from the SAME
//! `expected_audience` the guard already checks (§28.5 rule 6: "an SDK MUST
//! NOT add a second audience option for §28"), never a second one.
//! [`crate::middleware::RequireAccess::with_resource_metadata_url`] reads the
//! same configuration for the one class of 403 that gains a challenge
//! (§28.5 rule 5).
//!
//! ## Actix's route-scoped extractor model and §28.3 rule 2
//!
//! §28.3 rule 2 requires an SDK to exempt the metadata document's path
//! explicitly wherever the §10 guard is applied **globally** — the Express
//! and Fastify reference ports need this because their guard is a middleware
//! that runs in front of every route, including the document's own.
//! Actix-Web has no such thing: [`crate::middleware::AxiamUser`] is a
//! `FromRequest` **extractor** a handler opts into by declaring it as a
//! parameter (directly, or via the `#[require_auth]`/`#[require_access]`
//! macros), never a blanket `App::wrap`. [`serve_protected_resource_metadata`]
//! registers a plain `web::resource` whose handler takes no such extractor,
//! so the document is unauthenticated by construction — there is no global
//! guard for it to be exempted *from*. This module therefore ships no
//! `isMetadataDocumentRequest`-equivalent function; see the crate's `CHANGELOG.md`
//! for this noted as a deliberate, structural divergence from the TypeScript
//! reference port rather than a gap.

use std::collections::HashSet;

use actix_web::{HttpResponse, web};
use serde::Serialize;

use crate::AxiamError;
use crate::management::{FieldError, ValidationError};

/// RFC 9728 §3.1's well-known prefix — the segment inserted between a
/// resource's authority and its path to reach the document that describes
/// it.
pub const PROTECTED_RESOURCE_METADATA_PREFIX: &str = "/.well-known/oauth-protected-resource";

/// The three hosts §28.2 rule 2 lets an `http` URL use, and the only ones.
///
/// AXIAM's RFC 8252 §7.3 loopback hosts, reused verbatim. There is
/// deliberately no flag, environment variable or debug build that widens
/// this: a resource server reachable over plaintext on a routable host
/// publishes an identifier an attacker can impersonate.
const LOOPBACK_HOSTS: [&str; 3] = ["127.0.0.1", "[::1]", "localhost"];

// ---------------------------------------------------------------------------
// Refusals (§28.2, §28.4, §28.5) — always `ValidationError`, never a new type
// ---------------------------------------------------------------------------

/// Raise §28's refusal.
///
/// §28.6 pins the error taxonomy: "§28's refusals are `ValidationError`; no
/// new type". This crate's [`ValidationError`] is carried as the `source` of
/// an [`AxiamError::Network`] (CONTRACT.md §27.4 rule 7), so `status` names
/// the HTTP code an AXIAM server would answer with for the same rejected
/// field — **400** — even though no server was asked and no request was
/// made. `operation` names the §28 operation that refused, the way a
/// management refusal names `"users.create"`.
pub(crate) fn refuse(
    operation: &'static str,
    field: &str,
    detail: impl std::fmt::Display,
) -> AxiamError {
    let detail = detail.to_string();
    let message = format!("{field}: {detail} (CONTRACT.md §28)");
    AxiamError::network_with_source(
        message.clone(),
        Box::new(ValidationError {
            status: 400,
            operation,
            message,
            fields: vec![FieldError {
                field: field.to_string(),
                message: detail,
            }],
        }),
    )
}

// ---------------------------------------------------------------------------
// Character classes (RFC 6749 Appendix A) — §28.2 rule 5, §28.4
// ---------------------------------------------------------------------------

/// `NQCHAR`: `%x21` / `%x23`-`%x5B` / `%x5D`-`%x7E`. No space, no `"`, no
/// `\`, no control character, no non-ASCII.
fn is_nqchar(c: char) -> bool {
    let code = c as u32;
    code == 0x21 || (0x23..=0x5b).contains(&code) || (0x5d..=0x7e).contains(&code)
}

/// `NQSCHAR`: `NQCHAR` plus the space (`%x20`).
fn is_nqschar(c: char) -> bool {
    c == ' ' || is_nqchar(c)
}

fn is_all(value: &str, predicate: impl Fn(char) -> bool) -> bool {
    value.chars().all(predicate)
}

// ---------------------------------------------------------------------------
// Absolute-URI parsing (§28.2 rules 1, 2, 3, 7)
// ---------------------------------------------------------------------------

/// The pieces of an absolute URI, sliced out of the caller's string without
/// normalisation.
struct ParsedUri<'a> {
    /// The scheme, verbatim (compared case-insensitively, stored as written).
    scheme: &'a str,
    /// The authority, verbatim — `userinfo@host:port` included.
    authority: &'a str,
    /// The path component: empty, or starting with `/`. A trailing slash is
    /// preserved.
    path: &'a str,
    /// True when the string carried a `?`, even an empty one.
    has_query: bool,
    /// True when the string carried a `#`, even an empty one.
    has_fragment: bool,
}

/// `scheme://authority[path][?query][#fragment]`, matched against the
/// caller's string exactly as given.
///
/// Deliberately not [`url::Url::parse`]: that parser *normalises* — it
/// lowercases the host, resolves `..` segments, appends a path to an
/// authority-only URL, and re-encodes. §28.2 forbids adjusting a value to
/// make it pass, and §28.3 derives the document's own path from this string,
/// so what is validated must be what was written.
fn parse_absolute_uri(raw: &str) -> Option<ParsedUri<'_>> {
    let scheme_end = raw.find("://")?;
    let scheme = &raw[..scheme_end];
    let mut chars = scheme.chars();
    let first = chars.next()?;
    if !first.is_ascii_alphabetic() {
        return None;
    }
    if !chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '.' | '-')) {
        return None;
    }

    let rest = &raw[scheme_end + 3..];
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    if authority.is_empty() {
        return None;
    }

    let after_authority = &rest[authority_end..];
    let path_end = after_authority
        .find(['?', '#'])
        .unwrap_or(after_authority.len());
    let path = &after_authority[..path_end];

    let after_path = &after_authority[path_end..];
    let (has_query, after_query) = match after_path.strip_prefix('?') {
        Some(stripped) => {
            let query_end = stripped.find('#').unwrap_or(stripped.len());
            (true, &stripped[query_end..])
        }
        None => (false, after_path),
    };
    let has_fragment = after_query.starts_with('#');

    Some(ParsedUri {
        scheme,
        authority,
        path,
        has_query,
        has_fragment,
    })
}

/// The host inside an authority: `userinfo@` stripped, port stripped, an
/// IPv6 literal's brackets kept (so `[::1]` compares as §28.2 rule 2 spells
/// it).
///
/// Stripping `userinfo` is what makes `http://localhost@evil.example.com/` a
/// refusal rather than a loopback pass — the host there is
/// `evil.example.com`.
fn host_of(authority: &str) -> &str {
    let hostport = match authority.rfind('@') {
        Some(at) => &authority[at + 1..],
        None => authority,
    };
    if let Some(rest) = hostport.strip_prefix('[') {
        match rest.find(']') {
            Some(close) => &hostport[..close + 2],
            None => hostport,
        }
    } else {
        match hostport.find(':') {
            Some(colon) => &hostport[..colon],
            None => hostport,
        }
    }
}

/// How much of §28.2 rule 1 a particular member is held to — rule 7 and
/// §28.4's `resource_metadata` relax two parts of it.
#[derive(Clone, Copy)]
struct UriPolicy {
    /// `true` for `resource_documentation` (§28.2 rule 7) and
    /// `resource_metadata` (§28.4): a page for a human may be parameterised.
    allow_query: bool,
    /// `true` for the same two members, for the same reason.
    allow_fragment: bool,
}

const IDENTIFIER: UriPolicy = UriPolicy {
    allow_query: false,
    allow_fragment: false,
};
const LOCATOR: UriPolicy = UriPolicy {
    allow_query: true,
    allow_fragment: true,
};

/// §28.2 rules 1 and 2, applied to one member. Returns the parse so a caller
/// that needs the path (§28.3) does not parse twice.
fn require_absolute_uri<'a>(
    operation: &'static str,
    field: &str,
    raw: &'a str,
    policy: UriPolicy,
) -> Result<ParsedUri<'a>, AxiamError> {
    if raw.is_empty() {
        return Err(refuse(operation, field, "must be a non-empty absolute URI"));
    }
    let Some(parsed) = parse_absolute_uri(raw) else {
        return Err(refuse(
            operation,
            field,
            format!("must be an absolute URI with a scheme and an authority, not {raw:?}"),
        ));
    };
    if parsed.has_query && !policy.allow_query {
        return Err(refuse(
            operation,
            field,
            "must carry no query — §28.3 derives the metadata path from it",
        ));
    }
    if parsed.has_fragment && !policy.allow_fragment {
        return Err(refuse(operation, field, "must carry no fragment"));
    }
    let scheme_lower = parsed.scheme.to_ascii_lowercase();
    if scheme_lower == "https" {
        return Ok(parsed);
    }
    if scheme_lower == "http" {
        let host_lower = host_of(parsed.authority).to_ascii_lowercase();
        if LOOPBACK_HOSTS.contains(&host_lower.as_str()) {
            return Ok(parsed);
        }
    }
    Err(refuse(
        operation,
        field,
        format!(
            "must use https — http is accepted only on 127.0.0.1, [::1] or localhost, and {raw:?} is neither"
        ),
    ))
}

// ---------------------------------------------------------------------------
// §28.1 / §28.2 — `protected_resource_metadata`
// ---------------------------------------------------------------------------

/// The RFC 9728 §2 document, carrying **at most** the five members §28.2
/// permits, in that order, and no others.
///
/// Member names are the wire names, because this struct serializes to the
/// document byte for byte. RFC 9728 defines further members; §28.2 forbids
/// emitting them in this contract version — a member one SDK emits and ten
/// do not is a divergence the cross-SDK review would then have to
/// reconcile.
///
/// Two members are **omitted rather than emitted empty or `null`**:
/// `scopes_supported` when the caller passed no scopes, and
/// `resource_documentation` when the caller passed none.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProtectedResourceMetadataDocument {
    /// The resource identifier this server publishes for itself — the
    /// string an RFC 8707 `resource` parameter carries and the `aud` the
    /// guard checks.
    pub resource: String,
    /// The issuer identifiers of the authorization servers that guard this
    /// resource. At least one, each verbatim.
    pub authorization_servers: Vec<String>,
    /// The scope tokens this resource server understands, in the caller's
    /// order. Omitted when the caller passed none.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub scopes_supported: Vec<String>,
    /// Always `["header"]` in this contract version — §10's guard reads a
    /// bearer credential from the `Authorization` header alone.
    pub bearer_methods_supported: Vec<String>,
    /// A human-readable documentation page. Omitted when the caller passed
    /// none; never `null`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_documentation: Option<String>,
}

/// The arguments of §28.1's `protected_resource_metadata`.
///
/// Build with [`Self::new`], then the optional builder methods — the same
/// idiom [`crate::middleware::RequireAccess`] and [`crate::oidc`]'s login
/// options already use. All fields are `pub` so a test fixture can be
/// spread with struct-update syntax (`ProtectedResourceMetadataOptions {
/// resource: "...".into(), ..fixture() }`), mirroring the reference port's
/// per-field negative-test fixtures.
#[derive(Debug, Clone)]
pub struct ProtectedResourceMetadataOptions {
    /// The resource identifier. Absolute, `https` (or `http` on a loopback
    /// host), with no query and no fragment. A trailing slash is
    /// significant.
    pub resource: String,
    /// The issuer identifiers of the authorization servers guarding it — at
    /// least one, no duplicates, no query, no fragment.
    pub authorization_servers: Vec<String>,
    /// The scope tokens this resource server understands. Order is
    /// preserved, duplicates are refused, and an empty list omits the
    /// member.
    pub scopes_supported: Vec<String>,
    /// Defaults to `["header"]`, and `["header"]` is the only accepted
    /// value in this contract version.
    pub bearer_methods_supported: Vec<String>,
    /// Optional documentation page for a human. May carry a query and a
    /// fragment; omitted from the document when absent.
    pub resource_documentation: Option<String>,
}

impl ProtectedResourceMetadataOptions {
    /// Start building options for `resource`, guarded by `authorization_servers`.
    pub fn new(resource: impl Into<String>, authorization_servers: Vec<String>) -> Self {
        Self {
            resource: resource.into(),
            authorization_servers,
            scopes_supported: Vec::new(),
            bearer_methods_supported: vec!["header".to_string()],
            resource_documentation: None,
        }
    }

    /// Set the scope tokens this resource server understands.
    #[must_use]
    pub fn scopes_supported(mut self, scopes_supported: Vec<String>) -> Self {
        self.scopes_supported = scopes_supported;
        self
    }

    /// Override `bearer_methods_supported` — `["header"]` is the only value
    /// that will pass validation in this contract version, so there is
    /// ordinarily no reason to call this.
    #[must_use]
    pub fn bearer_methods_supported(mut self, bearer_methods_supported: Vec<String>) -> Self {
        self.bearer_methods_supported = bearer_methods_supported;
        self
    }

    /// Set a human-readable documentation page.
    #[must_use]
    pub fn resource_documentation(mut self, resource_documentation: impl Into<String>) -> Self {
        self.resource_documentation = Some(resource_documentation.into());
        self
    }
}

/// What [`protected_resource_metadata`] returns: the document, the path it
/// is served at, and the URL that path resolves to.
///
/// [`Self::metadata_url`] exists so that
/// [`crate::token::JwksVerifier::with_resource_metadata_url`] can be fed
/// from the helper that derived it rather than by retyping the string.
/// [`serve_protected_resource_metadata`] cross-checks against the same
/// value for the same reason: retyping is how the two come to disagree, and
/// a challenge pointing at a document that is not this resource server's is
/// worse than no challenge at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtectedResourceMetadata {
    /// The RFC 9728 §2 document, ready to serialize.
    pub document: ProtectedResourceMetadataDocument,
    /// The absolute path the document is served at, derived from the
    /// resource per §28.3 — never chosen.
    pub metadata_path: String,
    /// [`Self::metadata_path`] resolved against the resource's scheme and
    /// authority. Feed this to
    /// [`crate::token::JwksVerifier::with_resource_metadata_url`].
    pub metadata_url: String,
}

/// `protected_resource_metadata(options)` (CONTRACT.md §28.1) — build and
/// validate the RFC 9728 protected-resource metadata document this server
/// publishes about itself, and derive the path and URL it is served at.
///
/// **Validation happens here and it refuses; it never repairs.** Every
/// §28.2 rule is checked before any route exists and before any request is
/// served, and a violation returns [`AxiamError::Network`] carrying a
/// [`ValidationError`] source. Nothing is normalised, trimmed, lowercased or
/// re-encoded to make it pass: a value that needs adjusting is a
/// configuration mistake an operator can fix in one line, and a helper that
/// quietly fixed it would publish a document describing a resource server
/// that does not exist.
///
/// **Nothing in the document may come from a request** (§28.2 rule 8).
/// `resource` and `authorization_servers` are configuration; this SDK
/// offers no option to build either from the `Host` header, the
/// `Forwarded`/`X-Forwarded-*` family or the request URL, because a
/// document assembled from the request is a document an attacker can point
/// at an authorization server of their choosing — the whole handshake
/// redirected with one header.
///
/// ```
/// use axiam_sdk::middleware::{ProtectedResourceMetadataOptions, protected_resource_metadata};
///
/// let metadata = protected_resource_metadata(ProtectedResourceMetadataOptions::new(
///     "https://mcp.example.com/mcp",
///     vec!["https://axiam.example.com".to_string()],
/// ).scopes_supported(vec!["mcp:read".to_string(), "mcp:tools".to_string()]))
/// .expect("valid configuration");
/// assert_eq!(metadata.metadata_path, "/.well-known/oauth-protected-resource/mcp");
/// assert_eq!(
///     metadata.metadata_url,
///     "https://mcp.example.com/.well-known/oauth-protected-resource/mcp"
/// );
/// ```
///
/// # Errors
///
/// [`AxiamError::Network`] (carrying a [`ValidationError`] source) when any
/// §28.2 rule is violated.
pub fn protected_resource_metadata(
    options: ProtectedResourceMetadataOptions,
) -> Result<ProtectedResourceMetadata, AxiamError> {
    let op = "protected_resource_metadata";

    // Rule 1 + rule 2.
    let parsed = require_absolute_uri(op, "resource", &options.resource, IDENTIFIER)?;
    let scheme = parsed.scheme.to_string();
    let authority = parsed.authority.to_string();
    let path = parsed.path.to_string();

    // Rule 3 + rule 4: at least one entry, each an issuer verbatim, no
    // duplicates.
    if options.authorization_servers.is_empty() {
        return Err(refuse(
            op,
            "authorization_servers",
            "must name at least one authorization server — a document that names none answers none of the question the client asked",
        ));
    }
    let mut seen_servers: HashSet<&str> = HashSet::new();
    for entry in &options.authorization_servers {
        require_absolute_uri(op, "authorization_servers", entry, IDENTIFIER)?;
        if !seen_servers.insert(entry.as_str()) {
            return Err(refuse(
                op,
                "authorization_servers",
                format!("duplicate entry {entry:?}"),
            ));
        }
    }

    // Rule 5: NQCHAR tokens, order preserved, duplicates refused, empty
    // omits.
    let mut seen_scopes: HashSet<&str> = HashSet::new();
    for scope in &options.scopes_supported {
        if scope.is_empty() || !is_all(scope, is_nqchar) {
            return Err(refuse(
                op,
                "scopes_supported",
                format!(
                    "{scope:?} is not a scope token — one or more NQCHAR (no space, no '\"', no '\\', no control character, no non-ASCII)"
                ),
            ));
        }
        if !seen_scopes.insert(scope.as_str()) {
            return Err(refuse(
                op,
                "scopes_supported",
                format!("duplicate scope {scope:?}"),
            ));
        }
    }

    // Rule 6: exactly ["header"].
    if options.bearer_methods_supported.len() != 1
        || options.bearer_methods_supported[0] != "header"
    {
        return Err(refuse(
            op,
            "bearer_methods_supported",
            format!(
                "must be exactly [\"header\"] in this contract version — §10's guard reads a bearer credential from the Authorization header alone, so {:?} would describe behaviour this SDK does not have",
                options.bearer_methods_supported
            ),
        ));
    }

    // Rule 7: absolute URL, query and fragment permitted, omitted when
    // absent.
    if let Some(documentation) = &options.resource_documentation {
        require_absolute_uri(op, "resource_documentation", documentation, LOCATOR)?;
    }

    // §28.2 fixes the member order; `Serialize`'s field-declaration order
    // matches it, and the conditional `skip_serializing_if`s sit where the
    // omitted members belong.
    let document = ProtectedResourceMetadataDocument {
        resource: options.resource.clone(),
        authorization_servers: options.authorization_servers,
        scopes_supported: options.scopes_supported,
        bearer_methods_supported: vec!["header".to_string()],
        resource_documentation: options.resource_documentation,
    };

    let metadata_path = derive_metadata_path(&path);
    let metadata_url = format!("{scheme}://{authority}{metadata_path}");

    Ok(ProtectedResourceMetadata {
        document,
        metadata_path,
        metadata_url,
    })
}

/// §28.3's derivation: RFC 9728 §3.1 inserts the well-known segment between
/// the authority and the path. An empty path and a bare `/` both reach the
/// root form; anything else is appended, **trailing slash included** — it
/// is part of the identifier a client compares, and two resources that
/// differ only by it are two resources.
fn derive_metadata_path(resource_path: &str) -> String {
    if resource_path.is_empty() || resource_path == "/" {
        PROTECTED_RESOURCE_METADATA_PREFIX.to_string()
    } else {
        format!("{PROTECTED_RESOURCE_METADATA_PREFIX}{resource_path}")
    }
}

// ---------------------------------------------------------------------------
// §28.4 — `bearer_challenge`
// ---------------------------------------------------------------------------

/// RFC 6750 §3.1's three error codes — the complete vocabulary a challenge
/// may name (§28.4).
///
/// A closed enum, not a validated string: unlike
/// [`crate::rest::authz::reason_code`] (whose set an older/newer server may
/// extend and which this SDK must therefore surface verbatim), §28.4 fixes
/// this vocabulary at exactly three values with no escape hatch — "nothing
/// else, not even a well-formed-looking OAuth error code". A caller
/// therefore cannot construct a fourth value at all, which is a stricter
/// (and, for a closed contract vocabulary, more faithful) guarantee than the
/// reference port's runtime refusal of e.g. `invalid_grant`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BearerChallengeError {
    /// `invalid_request` — available to a caller building a challenge by
    /// hand for its own `400`; the SDK's own guards never emit it.
    InvalidRequest,
    /// `invalid_token` — a credential was presented and rejected.
    InvalidToken,
    /// `insufficient_scope` — a `no_grant` denial on a route that named a
    /// scope (§28.5 rule 5).
    InsufficientScope,
}

impl BearerChallengeError {
    /// The exact RFC 6750 §3.1 wire spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::InvalidToken => "invalid_token",
            Self::InsufficientScope => "insufficient_scope",
        }
    }
}

impl std::fmt::Display for BearerChallengeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The arguments of §28.1's `bearer_challenge`, in canonical order.
#[derive(Debug, Clone)]
pub struct BearerChallengeOptions {
    /// The document's URL — the one parameter that is always present. May
    /// carry a query and a fragment.
    pub resource_metadata_url: String,
    /// One of RFC 6750 §3.1's three codes, or absent when the request
    /// carried no authentication information at all.
    pub error: Option<BearerChallengeError>,
    /// A human-readable description, for an application building **its
    /// own** challenge for its own 400.
    ///
    /// This SDK's own guards never set it: expired, not yet valid, wrong
    /// tenant, wrong audience, bad signature, an unsatisfiable `cnf`, a
    /// revoked `sid` — §28.4 makes all of them `invalid_token`,
    /// indistinguishably. Every distinction a 401 draws for an
    /// unauthenticated stranger is an oracle.
    pub error_description: Option<String>,
    /// The scope the route asked for, verbatim — one or more tokens joined
    /// by a single space.
    pub scope: Option<String>,
}

impl BearerChallengeOptions {
    /// Start building challenge options carrying only the mandatory
    /// `resource_metadata_url`.
    pub fn new(resource_metadata_url: impl Into<String>) -> Self {
        Self {
            resource_metadata_url: resource_metadata_url.into(),
            error: None,
            error_description: None,
            scope: None,
        }
    }

    /// Name the RFC 6750 error code.
    #[must_use]
    pub fn error(mut self, error: BearerChallengeError) -> Self {
        self.error = Some(error);
        self
    }

    /// Attach a human-readable description (never used by this SDK's own
    /// guards — see [`Self::error_description`]'s field docs).
    #[must_use]
    pub fn error_description(mut self, error_description: impl Into<String>) -> Self {
        self.error_description = Some(error_description.into());
        self
    }

    /// Name the requested scope, verbatim.
    #[must_use]
    pub fn scope(mut self, scope: impl Into<String>) -> Self {
        self.scope = Some(scope.into());
        self
    }
}

/// `bearer_challenge(options)` (CONTRACT.md §28.4) — build the **value** of
/// a `WWW-Authenticate` header, never the whole header line and never a
/// map. The caller sets the header.
///
/// Parameters appear in a fixed order — `error`, `error_description`,
/// `scope`, `resource_metadata` — separated by exactly `, `.
/// `resource_metadata` is always present; the other three are omitted when
/// not given.
///
/// **Every value is quoted and no value is ever escaped.** RFC 6750 §3
/// restricts each parameter to a character set that cannot contain `"` or
/// `\`, so a value needing an escape is a value that does not belong in a
/// challenge: this function refuses it rather than escaping, truncating or
/// stripping it. A challenge is built from the code's own constants and a
/// route's own configuration, so an invalid one is a programming error, not
/// a runtime condition to degrade around.
///
/// ```
/// use axiam_sdk::middleware::{BearerChallengeError, BearerChallengeOptions, bearer_challenge};
///
/// let url = "https://mcp.example.com/.well-known/oauth-protected-resource/mcp";
/// assert_eq!(
///     bearer_challenge(BearerChallengeOptions::new(url)).unwrap(),
///     format!("Bearer resource_metadata=\"{url}\""),
/// );
/// assert_eq!(
///     bearer_challenge(
///         BearerChallengeOptions::new(url)
///             .error(BearerChallengeError::InsufficientScope)
///             .scope("mcp:tools")
///     )
///     .unwrap(),
///     format!("Bearer error=\"insufficient_scope\", scope=\"mcp:tools\", resource_metadata=\"{url}\""),
/// );
/// ```
///
/// # Errors
///
/// [`AxiamError::Network`] (carrying a [`ValidationError`] source) when any
/// parameter is outside RFC 6750's syntax.
pub fn bearer_challenge(options: BearerChallengeOptions) -> Result<String, AxiamError> {
    let op = "bearer_challenge";
    let mut params: Vec<String> = Vec::new();

    if let Some(error) = options.error {
        params.push(format!("error=\"{}\"", error.as_str()));
    }

    if let Some(description) = &options.error_description {
        if description.is_empty() || !is_all(description, is_nqschar) {
            return Err(refuse(
                op,
                "error_description",
                "must be one or more NQSCHAR (no '\"', no '\\', no control character, no non-ASCII) — a value needing an escape does not belong in a challenge",
            ));
        }
        params.push(format!("error_description=\"{description}\""));
    }

    if let Some(scope) = &options.scope {
        if scope.is_empty() {
            return Err(refuse(
                op,
                "scope",
                "must be one or more scope tokens joined by a single space",
            ));
        }
        for token in scope.split(' ') {
            if token.is_empty() || !is_all(token, is_nqchar) {
                return Err(refuse(
                    op,
                    "scope",
                    format!(
                        "{scope:?} is not a space-joined list of scope tokens — no leading, trailing or doubled space, and no empty token"
                    ),
                ));
            }
        }
        params.push(format!("scope=\"{scope}\""));
    }

    let url = &options.resource_metadata_url;
    require_absolute_uri(op, "resource_metadata", url, LOCATOR)?;
    if !is_all(url, is_nqchar) {
        return Err(refuse(
            op,
            "resource_metadata",
            "must carry no '\"', no '\\', no space and no control character — a correctly encoded URL cannot, so one that does has not been encoded",
        ));
    }
    params.push(format!("resource_metadata=\"{url}\""));

    Ok(format!("Bearer {}", params.join(", ")))
}

// ---------------------------------------------------------------------------
// §28.5 — the `resource_metadata_url` guard option
// ---------------------------------------------------------------------------

/// The §28 challenge values a guard emits, precomputed once — by
/// [`crate::token::JwksVerifier::with_resource_metadata_url`] — so that an
/// invalid configuration is a startup failure rather than a surprise on the
/// 401 path.
///
/// Not constructible or nameable outside this crate: an integrator turns
/// §28 on through
/// [`crate::token::JwksVerifier::with_resource_metadata_url`] and
/// [`crate::middleware::RequireAccess::with_resource_metadata_url`], never
/// by building one of these directly (§28.1: "the fourth piece of the set
/// is a middleware option, not an operation").
#[derive(Debug, Clone)]
pub(crate) struct McpChallenges {
    resource_metadata_url: String,
    /// §28.4 vector 1 — the request carried **no** authentication
    /// information, so RFC 6750 §3 says not to name an error.
    no_credential: String,
    /// §28.4 vector 2 — a credential was presented and rejected. The only
    /// thing a 401 ever says about why.
    invalid_token: String,
}

impl McpChallenges {
    /// Validate `resource_metadata_url` and precompute the two challenge
    /// values that do not depend on a route's own scope.
    pub(crate) fn build(resource_metadata_url: &str) -> Result<Self, AxiamError> {
        let no_credential = bearer_challenge(BearerChallengeOptions::new(resource_metadata_url))?;
        let invalid_token = bearer_challenge(
            BearerChallengeOptions::new(resource_metadata_url)
                .error(BearerChallengeError::InvalidToken),
        )?;
        Ok(Self {
            resource_metadata_url: resource_metadata_url.to_string(),
            no_credential,
            invalid_token,
        })
    }

    pub(crate) fn no_credential(&self) -> &str {
        &self.no_credential
    }

    pub(crate) fn invalid_token(&self) -> &str {
        &self.invalid_token
    }

    /// §28.4 vector 3, built on demand for the route's own scope. Never
    /// precomputed: the scope is per-route and (§28.5 rule 6) is never
    /// synthesised, derived, or substituted — only the exact string the
    /// route named.
    pub(crate) fn insufficient_scope_challenge(&self, scope: &str) -> Result<String, AxiamError> {
        bearer_challenge(
            BearerChallengeOptions::new(self.resource_metadata_url.clone())
                .error(BearerChallengeError::InsufficientScope)
                .scope(scope),
        )
    }
}

// ---------------------------------------------------------------------------
// §28.3 — `serve_protected_resource_metadata`
// ---------------------------------------------------------------------------

/// `serve_protected_resource_metadata(metadata, verifier)` (CONTRACT.md
/// §28.3) — an Actix-Web `web::resource` serving the document at its
/// derived path, ready for `App::service(...)`.
///
/// **The path is derived, not chosen**, and **exactly one route is
/// registered.** The root form is not also registered for a resource that
/// has a path: a deployment fronting two resources would then have two
/// helpers competing for the same root path, and registration order would
/// decide the loser. A deployment fronting several resources calls this
/// once per resource, and the derived paths cannot collide because each is
/// derived from its own resource.
///
/// The response is `200` with `Content-Type: application/json`, the
/// document as its body, `Cache-Control: public, max-age=3600` and
/// `Access-Control-Allow-Origin: *` — the last because an MCP client
/// running in a browser cannot read the document without it, and it is
/// safe precisely because the response is identical for every caller. It
/// carries no `Access-Control-Allow-Credentials`, which would be asking a
/// browser to attach the user's cookies to a request that has no use for
/// them. Nothing is read from the request, so there is no `Set-Cookie` and
/// no per-caller content, and §3a does not apply: it is a `GET`, and §3a is
/// scoped to state-changing methods and cookie-sourced credentials.
///
/// **Needs no route ordering, and no exemption to implement.** The returned
/// resource composes no [`crate::middleware::AxiamUser`] extractor, so it
/// is unauthenticated by construction — see the [module docs](self) for why
/// that makes Actix's route-scoped extractor model structurally exempt from
/// §28.3 rule 2's global-guard carve-out rather than merely handling it.
///
/// `verifier` is optional: pass the same [`crate::token::JwksVerifier`] the
/// §10 guard was built from to let this function apply §28.5 rule 3's
/// cross-check, or `None` where the guard is configured in a different
/// process — nothing can be checked there, and the operator configures both
/// from one constant, which is what [`ProtectedResourceMetadata::metadata_url`]
/// is for.
///
/// # Errors
///
/// [`AxiamError::Network`] (carrying a [`ValidationError`] source) when
/// `verifier` is given and its `resource_metadata_url` is not exactly
/// `metadata.metadata_url`, or its expected audience is not exactly
/// `metadata.document.resource`.
///
/// Both comparisons are simple string equality (RFC 3986 §6.2.1): no
/// normalisation, no case folding of the host, no trailing-slash tolerance.
/// Note that the two strings compared are *different* strings — the
/// resource is `https://mcp.example.com/mcp` and the metadata URL is
/// `https://mcp.example.com/.well-known/oauth-protected-resource/mcp` — so
/// each is compared against its own counterpart.
pub fn serve_protected_resource_metadata(
    metadata: &ProtectedResourceMetadata,
    verifier: Option<&crate::token::JwksVerifier>,
) -> Result<impl actix_web::dev::HttpServiceFactory + use<>, AxiamError> {
    let op = "serve_protected_resource_metadata";

    if let Some(verifier) = verifier {
        let configured_url = verifier.resource_metadata_url();
        if configured_url != Some(metadata.metadata_url.as_str()) {
            return Err(refuse(
                op,
                "resource_metadata_url",
                format!(
                    "is {configured_url:?} but this document is published at {:?} — the challenge would point at a document that is not this resource server's",
                    metadata.metadata_url
                ),
            ));
        }
        let configured_audience = verifier.expected_audience();
        if configured_audience != Some(metadata.document.resource.as_str()) {
            return Err(refuse(
                op,
                "expected_audience",
                format!(
                    "is {configured_audience:?} but this document announces {:?} — the document would announce one identifier while the guard checked `aud` against another, so every token the flow produced would be refused",
                    metadata.document.resource
                ),
            ));
        }
    }

    // Serialized once: the response is identical for every caller (§28.3
    // rule 4), so there is nothing per-request to build.
    let body = serde_json::to_string(&metadata.document)
        .map_err(|e| AxiamError::network(format!("{op}: failed to serialize the document: {e}")))?;

    Ok(
        web::resource(metadata.metadata_path.clone()).route(web::get().to(move || {
            let body = body.clone();
            async move {
                HttpResponse::Ok()
                    .content_type("application/json")
                    .insert_header(("Cache-Control", "public, max-age=3600"))
                    .insert_header(("Access-Control-Allow-Origin", "*"))
                    .body(body)
            }
        })),
    )
}
