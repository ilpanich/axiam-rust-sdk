//! UMA 2.0 — Protection API and ticket grant. CONTRACT.md §20 (contract 1.10).
//!
//! The **resource-server** side of User-Managed Access: register the resources
//! you guard, ask AXIAM what a caller would need, and exchange the resulting
//! permission ticket for a Requesting Party Token.
//!
//! # The rule this module exists to not paper over
//!
//! **A permission ticket is single-use and is not retryable** (§20.2 rule 6).
//! Every other refusal in this SDK can be re-sent once the caller fixes
//! something; this one cannot. The ticket is consumed *before* the request is
//! evaluated, so a failed exchange has already spent it.
//!
//! That alone would make retrying useless. What makes it unsafe is that
//! single-use rests on a mechanism with a **measured residual** of roughly 1 in
//! 640 under concurrency (ilpanich/axiam#302) — so a client that retries is
//! deliberately generating the concurrent redemption that residual describes.
//! [`AxiamClient::uma_exchange_ticket`] therefore issues **exactly one** request
//! and is excluded from the §16 retry runner, on every failure class including
//! timeout and `5xx`.
//!
//! # What a PAT is
//!
//! A Protection API Token is an ordinary client-credentials access token that
//! carries the `uma_protection` scope. It is passed **explicitly** to every
//! Protection API method rather than taken from the client's own session: the
//! client's session is frequently a *user* session, and §20.2 rule 1 forbids
//! silently offering one as a PAT — a ticket is bound to the `client_id` that
//! minted it, and a user token names no client to bind to.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::client::AxiamClient;
use crate::error::AxiamError;
use crate::oidc::discovery::OidcConfiguration;
use crate::oidc::exchange::oauth2_error_or_fallback;
use crate::rest::auth::CsrfHeaderExt;
use crate::sensitive::Sensitive;

/// `grant_type` of the UMA ticket grant (UMA 2.0 §3.3.1).
pub const UMA_TICKET_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:uma-ticket";

/// The scope that makes an access token a Protection API Token.
pub const UMA_PROTECTION_SCOPE: &str = "uma_protection";

/// The only `claim_token_format` AXIAM v1 accepts.
pub const UMA_CLAIM_TOKEN_FORMAT: &str = "urn:ietf:params:oauth:token-type:access_token";

// ---------------------------------------------------------------------------
// Resource registration (FedAuthz §2.2)
// ---------------------------------------------------------------------------

/// A UMA resource set — an AXIAM resource seen through the Protection API.
///
/// `id` is **the AXIAM resource id**, not a parallel identifier: the same UUID
/// works as the `resource_id` of a later [`RequestedPermission`], and as the
/// resource id anywhere else in this SDK.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceSet {
    /// Assigned by the server on registration; absent on the way out.
    #[serde(rename = "_id", default, skip_serializing_if = "Option::is_none")]
    pub id: Option<Uuid>,
    /// Human-readable name, shown in the admin UI.
    pub name: String,
    /// Free-form resource type. Defaults server-side to `uma_resource` when
    /// empty, so a resource server that omits it does not produce a row that
    /// sorts oddly next to hand-made ones.
    #[serde(rename = "type", default, skip_serializing_if = "String::is_empty")]
    pub resource_type: String,
    /// The scope names a resource server may ask for on this resource.
    ///
    /// **Replaced wholesale by an update, never merged** (§20.2 rule 8). This
    /// SDK does not read the current scopes and fold them into an update
    /// payload as a convenience, because that would make removing a scope
    /// impossible through the SDK.
    #[serde(default)]
    pub resource_scopes: Vec<String>,
}

impl ResourceSet {
    /// A registration payload. `type` and scopes default to empty.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            id: None,
            name: name.into(),
            resource_type: String::new(),
            resource_scopes: Vec::new(),
        }
    }

    /// Set the resource type.
    pub fn with_type(mut self, resource_type: impl Into<String>) -> Self {
        self.resource_type = resource_type.into();
        self
    }

    /// Set the complete declared scope set. On an update this **replaces**
    /// whatever the server holds (§20.2 rule 8).
    pub fn with_scopes<I, S>(mut self, scopes: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.resource_scopes = scopes.into_iter().map(Into::into).collect();
        self
    }
}

// ---------------------------------------------------------------------------
// Permission tickets
// ---------------------------------------------------------------------------

/// One `(resource, scopes)` pair a resource server requires.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestedPermission {
    /// The AXIAM resource id — the same UUID the Protection API returned as
    /// `_id`.
    pub resource_id: Uuid,
    /// Scope names, each of which the resource must already declare. Matched
    /// exactly: no prefix or wildcard semantics in either direction.
    pub resource_scopes: Vec<String>,
}

impl RequestedPermission {
    /// One pair: a resource and the scopes required on it.
    pub fn new<I, S>(resource_id: Uuid, scopes: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            resource_id,
            resource_scopes: scopes.into_iter().map(Into::into).collect(),
        }
    }
}

#[derive(Debug, Deserialize)]
struct TicketResponseWire {
    ticket: String,
}

/// One entry of an RPT's `permissions` claim.
///
/// **A record of a decision already made, not a live authorization answer**
/// (§20.2 rule 7). These are the pairs the engine allowed when the RPT was
/// minted; a grant revoked afterwards does not empty a live RPT. Do not cache
/// them beyond the token's own expiry — which is why that expiry is short.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RptPermission {
    /// The resource the engine allowed.
    pub resource_id: Uuid,
    /// The scopes it allowed on that resource.
    pub resource_scopes: Vec<String>,
    /// Absolute expiry, seconds since the epoch.
    pub exp: i64,
}

#[derive(Debug, Deserialize)]
struct RptResponseWire {
    access_token: String,
    token_type: String,
    expires_in: u64,
}

/// A Requesting Party Token.
///
/// **There is no `refresh_token` field, and that is deliberate** (§20.2
/// rule 5). The grant issues none, so an RPT cannot outlive the ticket that
/// authorised it; an application that wants a fresh one re-runs the grant. This
/// result never enters the §9 single-flight refresh guard — there is nothing
/// for it to refresh.
#[derive(Debug, Clone)]
pub struct RequestingPartyToken {
    /// The RPT itself (§20.6 secret).
    pub access_token: Sensitive<String>,
    /// Always `Bearer`.
    pub token_type: String,
    /// `min(claim_token remaining, server ceiling, 300 s)`.
    pub expires_in: u64,
}

// ---------------------------------------------------------------------------
// The WWW-Authenticate: UMA challenge (§20.3)
// ---------------------------------------------------------------------------

/// A parsed `WWW-Authenticate: UMA` challenge (UMA 2.0 §3.2).
///
/// Deliberately not `PartialEq`: the ticket is a `Sensitive<String>`, and
/// comparing two challenges would mean comparing two live credentials — a
/// timing-unsafe operation this type has no reason to offer.
#[derive(Debug, Clone)]
pub struct UmaChallenge {
    /// The protection realm the resource server named.
    pub realm: Option<String>,
    /// The authorization server the resource server nominates.
    ///
    /// **Not automatically trusted.** See [`uma_parse_challenge`].
    pub as_uri: Option<String>,
    /// The ticket to exchange — a bearer credential for its 60-second life.
    pub ticket: Option<Sensitive<String>>,
}

/// Parse a `WWW-Authenticate: UMA …` header value (§20.3).
///
/// # This deliberately does not exchange the ticket
///
/// Parsing a challenge and acting on it are separate decisions. The `as_uri`
/// names an authorization server this client has not necessarily chosen to
/// trust, and auto-exchanging would send the requesting party's `claim_token`
/// to whatever host answered the 403. The caller decides.
///
/// Returns `None` when the header is not a UMA challenge.
pub fn uma_parse_challenge(header: &str) -> Option<UmaChallenge> {
    let rest = header.trim().strip_prefix("UMA")?;
    // "UMA" alone is a valid, if useless, challenge; anything else must be
    // separated by whitespace so `UMAX realm="…"` is not read as UMA.
    if !rest.is_empty() && !rest.starts_with(char::is_whitespace) {
        return None;
    }

    let mut challenge = UmaChallenge {
        realm: None,
        as_uri: None,
        ticket: None,
    };

    for part in rest.split(',') {
        let Some((key, value)) = part.split_once('=') else {
            continue;
        };
        let value = value.trim().trim_matches('"').to_string();
        match key.trim() {
            "realm" => challenge.realm = Some(value),
            "as_uri" => challenge.as_uri = Some(value),
            "ticket" => challenge.ticket = Some(Sensitive::new(value)),
            _ => {}
        }
    }

    Some(challenge)
}

/// Format a `WWW-Authenticate: UMA` header value (§20.3, emit half).
///
/// The resource-server side: having obtained a ticket from
/// [`AxiamClient::uma_request_ticket`], tell the caller where to redeem it.
pub fn uma_challenge_header(realm: &str, as_uri: &str, ticket: &Sensitive<String>) -> String {
    format!(
        "UMA realm=\"{realm}\", as_uri=\"{as_uri}\", ticket=\"{}\"",
        ticket.expose()
    )
}

// ---------------------------------------------------------------------------
// Client methods
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct UmaTicketForm<'a> {
    grant_type: &'a str,
    ticket: &'a str,
    claim_token: &'a str,
    claim_token_format: &'a str,
    client_id: &'a str,
    client_secret: &'a str,
}

impl AxiamClient {
    /// `POST /uma2/rreg/resource_set` — register a resource set (§20.1).
    ///
    /// Returns the set with its server-assigned `_id`, which **is** the AXIAM
    /// resource id.
    pub async fn uma_register_resource(
        &self,
        pat: &Sensitive<String>,
        resource: &ResourceSet,
    ) -> Result<ResourceSet, AxiamError> {
        self.uma_protection_json("POST", "/uma2/rreg/resource_set", pat, Some(resource))
            .await
    }

    /// `GET /uma2/rreg/resource_set/{id}` — read a resource set (§20.1).
    pub async fn uma_read_resource(
        &self,
        pat: &Sensitive<String>,
        id: Uuid,
    ) -> Result<ResourceSet, AxiamError> {
        let path = format!("/uma2/rreg/resource_set/{id}");
        self.uma_protection_json::<ResourceSet, ResourceSet>("GET", &path, pat, None)
            .await
    }

    /// `PUT /uma2/rreg/resource_set/{id}` — replace a resource set (§20.1).
    ///
    /// **The scope list is replaced, not merged** (§20.2 rule 8). Whatever
    /// `resource.resource_scopes` contains becomes the resource's complete
    /// declared set; omitting a scope removes it, which is how a resource
    /// server drops an authority.
    pub async fn uma_update_resource(
        &self,
        pat: &Sensitive<String>,
        id: Uuid,
        resource: &ResourceSet,
    ) -> Result<ResourceSet, AxiamError> {
        let path = format!("/uma2/rreg/resource_set/{id}");
        self.uma_protection_json("PUT", &path, pat, Some(resource))
            .await
    }

    /// `DELETE /uma2/rreg/resource_set/{id}` — deregister (§20.1).
    pub async fn uma_delete_resource(
        &self,
        pat: &Sensitive<String>,
        id: Uuid,
    ) -> Result<(), AxiamError> {
        let path = format!("/uma2/rreg/resource_set/{id}");
        let response = self
            .uma_protection_request("DELETE", &path, pat, None::<&()>)
            .await?;
        if !response.status().is_success() {
            return Err(oauth2_error_or_fallback(response).await);
        }
        Ok(())
    }

    /// `GET /uma2/rreg/resource_set` — list the ids **this client** registered
    /// (§20.1).
    ///
    /// Not the tenant's whole resource tree: a protection scope does not
    /// entitle a caller to enumerate it.
    pub async fn uma_list_resources(
        &self,
        pat: &Sensitive<String>,
    ) -> Result<Vec<Uuid>, AxiamError> {
        self.uma_protection_json::<Vec<Uuid>, ()>("GET", "/uma2/rreg/resource_set", pat, None)
            .await
    }

    /// `POST /uma2/perm` — mint a permission ticket (§20.1).
    ///
    /// Scope names are validated **here**, against each resource's declared
    /// set. Asking for an undeclared scope is a `400`, not a denial — the two
    /// are different failures and this SDK surfaces the distinction the server
    /// draws rather than flattening it.
    pub async fn uma_request_ticket(
        &self,
        pat: &Sensitive<String>,
        permissions: &[RequestedPermission],
    ) -> Result<Sensitive<String>, AxiamError> {
        let wire: TicketResponseWire = self
            .uma_protection_json("POST", "/uma2/perm", pat, Some(permissions))
            .await?;
        Ok(Sensitive::new(wire.ticket))
    }

    /// `POST /oauth2/token` with
    /// `grant_type=urn:ietf:params:oauth:grant-type:uma-ticket` (§20.1) —
    /// exchange a ticket for an RPT.
    ///
    /// # This method never retries, by design
    ///
    /// It issues **exactly one** request and does not go through the §16 retry
    /// runner — not on `5xx`, not on timeout, not on any transport failure
    /// (§20.2 rule 6). The ticket is consumed before the request is evaluated,
    /// so a failed exchange has already spent it: a retry cannot succeed, and
    /// under concurrency it is precisely the second redemption that
    /// ilpanich/axiam#302's measured residual describes. On failure, request a
    /// **new** ticket.
    ///
    /// # What this method deliberately does not do
    ///
    /// * **No default `claim_token`** (§20.2 rule 2). It is a required
    ///   parameter. Defaulting it to the resource server's own PAT would mint
    ///   an RPT for the resource server instead of for the user.
    /// * **No auto-narrowing on `access_denied`** (rule 3). A partial grant is
    ///   refused whole; whether two-of-three permissions is useful is the
    ///   application's judgement, not this SDK's.
    /// * **No adoption** (rule 4). The RPT is the *requesting party's* token,
    ///   returned for the caller to hand onward or inspect. Adopting it as this
    ///   client's credentials would re-privilege every later call as that user.
    ///
    /// The four ticket refusals — unknown, expired, already used, wrong client
    /// — all answer `invalid_grant` with one message. This SDK does not try to
    /// tell them apart (§20.4): the server collapses them so a caller cannot
    /// probe for live ticket handles, and re-deriving the distinction
    /// client-side would hand back exactly what the server withheld.
    pub async fn uma_exchange_ticket(
        &self,
        ticket: &Sensitive<String>,
        claim_token: &Sensitive<String>,
    ) -> Result<RequestingPartyToken, AxiamError> {
        self.uma_exchange_ticket_with(ticket, claim_token, None, None)
            .await
    }

    /// [`Self::uma_exchange_ticket`] with an explicit tenant and/or a
    /// pre-fetched discovery document.
    pub async fn uma_exchange_ticket_with(
        &self,
        ticket: &Sensitive<String>,
        claim_token: &Sensitive<String>,
        tenant_id: Option<Uuid>,
        configuration: Option<OidcConfiguration>,
    ) -> Result<RequestingPartyToken, AxiamError> {
        let configuration = match configuration {
            Some(c) => c,
            None => self.oidc_discover().await?,
        };
        let tenant_id = self.resolve_oidc_tenant_id(tenant_id).await?;
        let client_id = self.oidc_client_id_or_err()?.to_string();
        let client_secret = self.oidc_client_secret_or_err("uma_exchange_ticket")?;
        let url = self.oidc_endpoint_url(&configuration.token_endpoint, tenant_id)?;

        let form = UmaTicketForm {
            grant_type: UMA_TICKET_GRANT_TYPE,
            ticket: ticket.expose().as_str(),
            claim_token: claim_token.expose().as_str(),
            claim_token_format: UMA_CLAIM_TOKEN_FORMAT,
            client_id: &client_id,
            client_secret: &client_secret,
        };

        // One `send()`, no retry wrapper. See the rule-6 note above — this is
        // the §16 exception, and it is load-bearing rather than stylistic.
        let response = self
            .http()
            .post(url)
            .header("X-Tenant-ID", self.tenant_header_value())
            .maybe_csrf_header(self)
            .form(&form)
            .send()
            .await
            .map_err(|e| AxiamError::Network {
                message: format!("uma ticket exchange request failed: {e}"),
                source: Some(Box::new(e)),
            })?;

        if !response.status().is_success() {
            // §20.4: dispatch on the `error` field before the status code, so
            // `access_denied` reads as itself whether it arrives as 403 (as the
            // ticket grant sends it) or as anything else.
            return Err(oauth2_error_or_fallback(response).await);
        }

        let wire: RptResponseWire = response.json().await.map_err(|e| AxiamError::Network {
            message: format!("failed to parse RPT response: {e}"),
            source: Some(Box::new(e)),
        })?;

        Ok(RequestingPartyToken {
            access_token: Sensitive::new(wire.access_token),
            token_type: wire.token_type,
            expires_in: wire.expires_in,
        })
    }

    /// Shared PAT-authenticated Protection API request.
    async fn uma_protection_request<B: Serialize + ?Sized>(
        &self,
        method: &str,
        path: &str,
        pat: &Sensitive<String>,
        body: Option<&B>,
    ) -> Result<reqwest::Response, AxiamError> {
        let url = self
            .base_url()
            .join(path)
            .map_err(|e| AxiamError::Network {
                message: format!("invalid UMA path {path}: {e}"),
                source: None,
            })?;

        let mut request = match method {
            "POST" => self.http().post(url),
            "PUT" => self.http().put(url),
            "DELETE" => self.http().delete(url),
            _ => self.http().get(url),
        }
        .header("X-Tenant-ID", self.tenant_header_value())
        .bearer_auth(pat.expose())
        .maybe_csrf_header(self);

        if let Some(body) = body {
            request = request.json(body);
        }

        request.send().await.map_err(|e| AxiamError::Network {
            message: format!("UMA protection API request failed: {e}"),
            source: Some(Box::new(e)),
        })
    }

    async fn uma_protection_json<R, B>(
        &self,
        method: &str,
        path: &str,
        pat: &Sensitive<String>,
        body: Option<&B>,
    ) -> Result<R, AxiamError>
    where
        R: for<'de> Deserialize<'de>,
        B: Serialize + ?Sized,
    {
        let response = self.uma_protection_request(method, path, pat, body).await?;
        if !response.status().is_success() {
            return Err(oauth2_error_or_fallback(response).await);
        }
        response.json().await.map_err(|e| AxiamError::Network {
            message: format!("failed to parse UMA response: {e}"),
            source: Some(Box::new(e)),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_well_formed_challenge() {
        let c = uma_parse_challenge(
            r#"UMA realm="example", as_uri="https://id.example", ticket="abc123""#,
        )
        .expect("should parse");
        assert_eq!(c.realm.as_deref(), Some("example"));
        assert_eq!(c.as_uri.as_deref(), Some("https://id.example"));
        assert_eq!(c.ticket.map(|t| t.expose().clone()), Some("abc123".into()));
    }

    #[test]
    fn rejects_a_non_uma_scheme() {
        assert!(uma_parse_challenge(r#"Bearer realm="example""#).is_none());
        // A scheme that merely starts with UMA is not UMA.
        assert!(uma_parse_challenge(r#"UMAX realm="example""#).is_none());
    }

    #[test]
    fn a_ticket_is_not_printed_by_debug() {
        // §20.6: the ticket is a bearer credential for its 60-second life, and
        // its short lifetime is exactly what invites logging it.
        let c = uma_parse_challenge(r#"UMA ticket="super-secret-ticket""#).unwrap();
        let rendered = format!("{c:?}");
        assert!(
            !rendered.contains("super-secret-ticket"),
            "the ticket must be redacted in Debug output, got: {rendered}"
        );
    }

    #[test]
    fn challenge_header_round_trips() {
        let header = uma_challenge_header(
            "example",
            "https://id.example",
            &Sensitive::new("tkt".to_string()),
        );
        let parsed = uma_parse_challenge(&header).expect("round trip");
        assert_eq!(parsed.as_uri.as_deref(), Some("https://id.example"));
        assert_eq!(
            parsed.ticket.map(|t| t.expose().clone()),
            Some("tkt".into())
        );
    }

    #[test]
    fn an_update_payload_carries_exactly_the_scopes_given() {
        // §20.2 rule 8: no read-modify-write. Serializing a set with one scope
        // must send one scope, never the union with whatever the server holds.
        let set = ResourceSet::new("invoice").with_scopes(["view"]);
        let json = serde_json::to_value(&set).unwrap();
        assert_eq!(json["resource_scopes"], serde_json::json!(["view"]));
    }
}
