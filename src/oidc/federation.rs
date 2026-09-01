//! The four public "Sign in with X" operations — CONTRACT.md §12.1 as of
//! contract 1.38: `sso_providers`, `sso_start_oauth2`, `sso_complete_oauth2`
//! and `sso_complete_handoff`.
//!
//! They sit on [`crate::client::AxiamClient`] beside the nine that came
//! before, because §12.2's "which object hosts the methods" rule is
//! unchanged by their arrival and this SDK has no packaging constraint that
//! would justify a second host.
//!
//! # What is new here, and what is deliberately absent
//!
//! `sso_start`/`sso_complete` (`src/oidc/exchange.rs`) drive an **OIDC**
//! upstream. These four add the rest of the public login surface:
//!
//! * [`AxiamClient::sso_providers`] — which buttons to render. It answers
//!   `200` with an **empty list** for an unknown organization, for a known
//!   one with nothing configured, and for a request naming no workspace at
//!   all (§12.1 note 9). All three are ordinary successes here; mapping any
//!   of them to an error would rebuild the organization-slug oracle the
//!   endpoint is shaped to deny.
//! * [`AxiamClient::sso_start_oauth2`] / [`AxiamClient::sso_complete_oauth2`]
//!   — the plain-OAuth2 upstream (GitHub, Facebook, `generic_oauth2`). There
//!   is no ID token on this path, so §12.4 does not apply; PKCE **is**
//!   mandatory and is generated and held server-side (§12.1 note 11), so
//!   this module computes no verifier and sends no `code_challenge`. Look
//!   for one and you will not find it: its absence is the contract.
//! * [`AxiamClient::sso_complete_handoff`] — redeems the single-use
//!   [`HANDOFF_QUERY_PARAM`] code the SAML and Apple flows deliver on the
//!   SPA's callback URL (§12.1 note 12).
//!
//! # Which start operation to call
//!
//! [`FederationProvider::protocol`] selects it, and nothing else does
//! (§12.1 note 10) — in particular not `provider_kind`, which is branding:
//!
//! | `protocol` | operation |
//! |---|---|
//! | `OidcConnect` | [`AxiamClient::sso_start`](crate::client::AxiamClient::sso_start) |
//! | `OAuth2` | [`AxiamClient::sso_start_oauth2`] |
//! | `Saml` | the SAML login endpoint — not a §12 vocabulary operation |
//!
//! The server refuses a mismatch with `400` rather than accepting it
//! silently, so a client that assumes OIDC fails on every GitHub button.
//!
//! # Inheritance is not computed here
//!
//! A federation config may be inherited from the organization (§12.1 note
//! 13). Resolution happens server-side: pass the workspace and the
//! [`FederationProvider::id`] that [`AxiamClient::sso_providers`] handed
//! you. [`FederationProvider::inherited`] is reported so an admin surface
//! can show that a provider is not the tenant's to edit — it is not an
//! input to anything.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::AxiamError;
use crate::client::{AxiamClient, OrgIdentifier, TenantIdentifier};
use crate::rest::auth::CsrfHeaderExt;

use super::exchange::{SsoCompleteResult, SsoStartResult, network_err};

/// Path of the public provider-listing endpoint.
pub const SSO_PROVIDERS_PATH: &str = "/api/v1/auth/federation/providers";
/// Path of the plain-OAuth2 federation step-1 endpoint.
pub const SSO_OAUTH2_START_PATH: &str = "/api/v1/auth/federation/oauth2/start";
/// Path of the plain-OAuth2 federation step-2 (callback) endpoint.
pub const SSO_OAUTH2_CALLBACK_PATH: &str = "/api/v1/auth/federation/oauth2/callback";
/// Path of the handoff-code redemption endpoint.
pub const SSO_HANDOFF_PATH: &str = "/api/v1/auth/federation/handoff";

/// The query parameter the server delivers a handoff code in, on the SPA's
/// own callback URL (CONTRACT.md §12.1 note 12).
pub const HANDOFF_QUERY_PARAM: &str = "axiam_handoff";

/// How long a handoff code is valid, in seconds (CONTRACT.md §12.1 note 12).
///
/// It exists to survive one redirect. Redeem it immediately.
pub const HANDOFF_CODE_TTL_SECS: u64 = 60;

/// `protocol` value selecting [`AxiamClient::sso_start`](crate::client::AxiamClient::sso_start).
pub const PROTOCOL_OIDC_CONNECT: &str = "OidcConnect";
/// `protocol` value selecting [`AxiamClient::sso_start_oauth2`].
pub const PROTOCOL_OAUTH2: &str = "OAuth2";
/// `protocol` value selecting the SAML login endpoint, which is **not** a
/// §12 vocabulary operation.
pub const PROTOCOL_SAML: &str = "Saml";

// ---------------------------------------------------------------------------
// Wire types (mirror the server schemas verbatim)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct PublicFederationProviderWire {
    id: Uuid,
    provider_kind: String,
    display_name: String,
    protocol: String,
    has_bundled_mark: bool,
    inherited: bool,
    #[serde(default)]
    button_icon: Option<String>,
}

#[derive(Debug, Deserialize)]
struct PublicFederationProvidersResponseWire {
    providers: Vec<PublicFederationProviderWire>,
}

#[derive(Serialize)]
struct OAuth2StartRequestWire {
    federation_config_id: String,
    redirect_uri: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    tenant_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tenant_slug: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    org_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    org_slug: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OAuth2StartResponseWire {
    authorize_url: String,
    state: String,
    expires_in_secs: u64,
}

#[derive(Serialize)]
struct OAuth2CallbackRequestWire<'a> {
    state: &'a str,
    code: &'a str,
}

#[derive(Serialize)]
struct SsoHandoffRequestWire<'a> {
    code: &'a str,
}

#[derive(Debug, Deserialize)]
struct SsoLoginSuccessResponseWire {
    user_id: Uuid,
    session_id: Uuid,
    expires_in: u64,
    redirect_uri: String,
}

// ---------------------------------------------------------------------------
// Public SDK types
// ---------------------------------------------------------------------------

/// One sign-in button (wire schema `PublicFederationProvider`).
///
/// This is an **unauthenticated** response and carries only what a button
/// needs. There is no `client_id`, no `metadata_url`, no endpoint URL and no
/// secret — not filtered out, absent by construction — and §12.1 note 9
/// forbids an SDK from expecting one.
#[derive(Debug, Clone)]
pub struct FederationProvider {
    /// Config id, to be echoed back to the matching start operation.
    ///
    /// Pass it through unmodified: inheritance is resolved server-side
    /// (§12.1 note 13) and this id is how the server is told which config
    /// resolution produced.
    pub id: Uuid,
    /// Which provider this is, for the button's branding — `google`,
    /// `github`, `generic_oidc`, … **Not** what selects the start
    /// operation; see [`Self::protocol`].
    pub provider_kind: String,
    /// The operator's display name for the provider.
    pub display_name: String,
    /// `OidcConnect`, `Saml` or `OAuth2` — the value that selects which
    /// start operation to call (§12.1 note 10). Compare against
    /// [`PROTOCOL_OIDC_CONNECT`], [`PROTOCOL_OAUTH2`] and [`PROTOCOL_SAML`].
    ///
    /// Kept as the wire string rather than narrowed to an enum: the server
    /// owns this vocabulary, and an SDK enum would turn a value added
    /// server-side into a deserialization failure for the whole list.
    ///
    /// An `OAuth2` provider issues **no ID token** — the server
    /// authenticates by calling a configured userinfo endpoint, so there is
    /// no signature, no `nonce` and no `aud` (§12.1 note 11). A surface
    /// that renders these buttons SHOULD make that distinction visible
    /// rather than presenting the two as equivalent.
    pub protocol: String,
    /// Whether AXIAM ships this provider's own sign-in mark, which its
    /// button must then use. `false` for the generic kinds, whose buttons
    /// read "Sign in with `display_name`" and use [`Self::button_icon`]
    /// where the operator uploaded one.
    pub has_bundled_mark: bool,
    /// `true` when the provider is inherited from the organization rather
    /// than configured on this tenant (§12.1 note 13). Informational — it
    /// is not needed to sign in.
    pub inherited: bool,
    /// The operator's uploaded button icon as a bounded raster `data:` URL.
    ///
    /// `None` for most providers: it is present only for generic ones whose
    /// operator uploaded one.
    pub button_icon: Option<String>,
}

/// The result of `sso_providers` (wire schema
/// `PublicFederationProvidersResponse`).
///
/// An **empty** [`Self::providers`] is a normal success, never an error
/// (§12.1 note 9).
#[derive(Debug, Clone)]
pub struct FederationProviderList {
    /// The providers to offer, in a stable server-defined order.
    pub providers: Vec<FederationProvider>,
}

/// Arguments to `sso_providers` (`GET /api/v1/auth/federation/providers`).
///
/// Every field is optional and all four travel as **query** parameters —
/// this is a `GET` with no body (§12.1). Unset tenant and organization
/// forms fall back to the client's own configuration (§5.1); when neither
/// the arguments nor the client supply a workspace the request is still
/// sent, and still answers `200` with an empty list.
#[derive(Debug, Clone, Default)]
pub struct SsoProvidersParams {
    /// Organization UUID. Alternative to [`Self::org_slug`].
    pub org_id: Option<Uuid>,
    /// Organization slug, as typed on a login page.
    pub org_slug: Option<String>,
    /// Tenant UUID. Alternative to [`Self::tenant_slug`].
    pub tenant_id: Option<Uuid>,
    /// Tenant slug. Omitted or blank means the organization's own scope.
    pub tenant_slug: Option<String>,
}

/// Arguments to `sso_start_oauth2`
/// (`POST /api/v1/auth/federation/oauth2/start`).
///
/// Deliberately identical in shape to
/// [`SsoStartParams`](crate::oidc::SsoStartParams), because the wire
/// schemas are: `OAuth2StartRequest` and `OidcStartRequest` differ in name
/// only. There is **no** PKCE field, and there must not be — the verifier
/// is generated and held server-side (§12.1 note 11).
#[derive(Debug, Clone, Default)]
pub struct SsoStartOauth2Params {
    /// UUID of the federation configuration, from
    /// [`FederationProvider::id`].
    pub federation_config_id: String,
    /// The SPA callback route. Sent to the provider verbatim, so it must
    /// match what is registered there byte for byte.
    pub redirect_uri: String,
    /// Tenant UUID; defaults to the client's configuration (§5.1).
    pub tenant_id: Option<Uuid>,
    /// Tenant slug. Alternative to [`Self::tenant_id`].
    pub tenant_slug: Option<String>,
    /// Organization UUID; defaults to the client's configuration (§5.1).
    pub org_id: Option<Uuid>,
    /// Organization slug. Alternative to [`Self::org_id`].
    pub org_slug: Option<String>,
}

/// Arguments to `sso_complete_oauth2`
/// (`POST /api/v1/auth/federation/oauth2/callback`).
#[derive(Debug, Clone, Default)]
pub struct SsoCompleteOauth2Params {
    /// The `state` the provider redirected back with — the one
    /// `sso_start_oauth2` returned, unmodified.
    pub state: String,
    /// The authorization code the provider redirected back with.
    pub code: String,
}

/// Arguments to `sso_complete_handoff`
/// (`POST /api/v1/auth/federation/handoff`).
#[derive(Debug, Clone, Default)]
pub struct SsoCompleteHandoffParams {
    /// The single-use code read from the [`HANDOFF_QUERY_PARAM`] query
    /// parameter on the SPA's callback URL.
    ///
    /// Valid for [`HANDOFF_CODE_TTL_SECS`] seconds and redeemable **once**.
    pub code: String,
}

// ---------------------------------------------------------------------------
// Operations
// ---------------------------------------------------------------------------

impl AxiamClient {
    /// Resolve the tenant pair for a federation call, falling back to the
    /// client's own §5 identifier when the caller named neither form.
    fn federation_tenant_pair(
        &self,
        tenant_id: Option<Uuid>,
        tenant_slug: Option<String>,
    ) -> (Option<Uuid>, Option<String>) {
        match (tenant_id, tenant_slug) {
            (Some(id), _) => (Some(id), None),
            (None, Some(slug)) => (None, Some(slug)),
            (None, None) => match &self.inner.tenant {
                TenantIdentifier::Id(id) => (Some(*id), None),
                TenantIdentifier::Slug(slug) => (None, Some(slug.clone())),
            },
        }
    }

    /// Resolve the organization pair for a federation call, falling back to
    /// the client's own configuration. Unlike the tenant pair this can come
    /// back `(None, None)`: the client is not required to carry an
    /// organization, and what each operation does about that differs
    /// (`sso_providers` sends the request anyway, the start operations
    /// refuse client-side).
    fn federation_org_pair(
        &self,
        org_id: Option<Uuid>,
        org_slug: Option<String>,
    ) -> (Option<Uuid>, Option<String>) {
        match (org_id, org_slug) {
            (Some(id), _) => (Some(id), None),
            (None, Some(slug)) => (None, Some(slug)),
            (None, None) => match self.org_identifier() {
                Some(OrgIdentifier::Id(id)) => (Some(*id), None),
                Some(OrgIdentifier::Slug(slug)) => (None, Some(slug.clone())),
                None => (self.resolved_org_id(), None),
            },
        }
    }

    /// `GET /api/v1/auth/federation/providers` (CONTRACT.md §12.1) — which
    /// "Sign in with X" buttons to render for a workspace.
    ///
    /// The identifiers travel as **query** parameters; this is a `GET` and
    /// sends no body.
    ///
    /// # An empty list is a success
    ///
    /// An unknown organization, a known one with nothing configured, and a
    /// request naming no workspace at all all answer `200` with an empty
    /// [`FederationProviderList::providers`] (§12.1 note 9). This method
    /// therefore returns `Ok` with an empty list in every one of those
    /// cases and never synthesises a not-found: the endpoint is shaped so
    /// that it cannot be used to enumerate organization or tenant slugs,
    /// and an SDK that reintroduced the distinction would reintroduce the
    /// oracle. A caller learns it named the workspace wrongly at the start
    /// operations, where every failure is a uniform `401`.
    ///
    /// # Errors
    /// The §2 status mapping, for the transport and server failures that
    /// can still happen. Not for an empty list.
    pub async fn sso_providers(
        &self,
        params: SsoProvidersParams,
    ) -> Result<FederationProviderList, AxiamError> {
        let (tenant_id, tenant_slug) =
            self.federation_tenant_pair(params.tenant_id, params.tenant_slug);
        let (org_id, org_slug) = self.federation_org_pair(params.org_id, params.org_slug);

        let mut url = self
            .base_url()
            .join(SSO_PROVIDERS_PATH)
            .expect("sso_providers path is a well-formed relative URL literal");
        {
            let mut query = url.query_pairs_mut();
            if let Some(id) = org_id {
                query.append_pair("org_id", &id.to_string());
            }
            if let Some(slug) = org_slug.as_deref() {
                query.append_pair("org_slug", slug);
            }
            if let Some(id) = tenant_id {
                query.append_pair("tenant_id", &id.to_string());
            }
            if let Some(slug) = tenant_slug.as_deref() {
                query.append_pair("tenant_slug", slug);
            }
        }

        let response = self
            .http()
            .get(url)
            .header("X-Tenant-ID", self.tenant_header_value())
            .send()
            .await
            .map_err(|e| network_err("sso_providers request failed", e))?;

        if !response.status().is_success() {
            let status = response.status().as_u16();
            let message = response
                .text()
                .await
                .unwrap_or_else(|_| "no response body".to_string());
            return Err(AxiamError::from_http_status(status, message));
        }

        let wire: PublicFederationProvidersResponseWire = response
            .json()
            .await
            .map_err(|e| network_err("failed to parse sso_providers response", e))?;

        Ok(FederationProviderList {
            providers: wire
                .providers
                .into_iter()
                .map(|p| FederationProvider {
                    id: p.id,
                    provider_kind: p.provider_kind,
                    display_name: p.display_name,
                    protocol: p.protocol,
                    has_bundled_mark: p.has_bundled_mark,
                    inherited: p.inherited,
                    button_icon: p.button_icon,
                })
                .collect(),
        })
    }

    /// `POST /api/v1/auth/federation/oauth2/start` (CONTRACT.md §12.1) —
    /// step 1 of a login through a **plain-OAuth2** upstream (GitHub,
    /// Facebook, `generic_oauth2`).
    ///
    /// Call this, rather than
    /// [`sso_start`](crate::client::AxiamClient::sso_start), exactly when
    /// [`FederationProvider::protocol`] is [`PROTOCOL_OAUTH2`] (§12.1 note
    /// 10). The server refuses a mismatch with `400`.
    ///
    /// PKCE is mandatory on this path and is generated and stored
    /// server-side; nothing about it appears in the request or the response
    /// (§12.1 note 11).
    ///
    /// # Errors
    /// A client-side [`AxiamError::Auth`] (no wire call) when organization
    /// context cannot be resolved. On the wire, the §2 status mapping — of
    /// which one case is worth naming: a **`400`** can mean the
    /// `redirect_uri` is not on an origin the deployment accepts (§12.1
    /// rule 12a) and surfaces as [`AxiamError::Network`], §2's
    /// configuration-error member for a request the deployment refuses to
    /// act on. Fix the configuration; it is not retried, and retrying it
    /// cannot help.
    pub async fn sso_start_oauth2(
        &self,
        params: SsoStartOauth2Params,
    ) -> Result<SsoStartResult, AxiamError> {
        let (tenant_id, tenant_slug) =
            self.federation_tenant_pair(params.tenant_id, params.tenant_slug);
        let (org_id, org_slug) = self.federation_org_pair(params.org_id, params.org_slug);
        if org_id.is_none() && org_slug.is_none() {
            return Err(AxiamError::auth(
                "sso_start_oauth2 requires organization context: pass org_id or org_slug, or \
                 construct the client with one (CONTRACT.md §5.1)",
            ));
        }

        let body = OAuth2StartRequestWire {
            federation_config_id: params.federation_config_id,
            redirect_uri: params.redirect_uri,
            tenant_id,
            tenant_slug,
            org_id,
            org_slug,
        };

        let url = self
            .base_url()
            .join(SSO_OAUTH2_START_PATH)
            .expect("sso_start_oauth2 path is a well-formed relative URL literal");
        let response = self
            .http()
            .post(url)
            .header("X-Tenant-ID", self.tenant_header_value())
            .maybe_csrf_header(self)
            .json(&body)
            .send()
            .await
            .map_err(|e| network_err("sso_start_oauth2 request failed", e))?;

        if !response.status().is_success() {
            // The federation endpoints document no error schema, so this is
            // the plain §2 status mapping — never an `OAuth2ErrorResponse`
            // parse, which §12.3 rule 3 scopes to `/oauth2/*`.
            let status = response.status().as_u16();
            let message = response
                .text()
                .await
                .unwrap_or_else(|_| "no response body".to_string());
            return Err(AxiamError::from_http_status(status, message));
        }

        let wire: OAuth2StartResponseWire = response
            .json()
            .await
            .map_err(|e| network_err("failed to parse sso_start_oauth2 response", e))?;

        Ok(SsoStartResult {
            authorize_url: wire.authorize_url,
            state: wire.state,
            expires_in_secs: wire.expires_in_secs,
        })
    }

    /// `POST /api/v1/auth/federation/oauth2/callback` (CONTRACT.md §12.1) —
    /// step 2 of a plain-OAuth2 login.
    ///
    /// The session arrives as `Set-Cookie` (§12.1 note 6) and is absorbed
    /// into this client exactly as
    /// [`sso_complete`](crate::client::AxiamClient::sso_complete) absorbs
    /// it, so `refresh()` and `logout()` work afterwards.
    ///
    /// §12.4 does not apply: an `OAuth2` provider issues no ID token, so
    /// there is nothing to validate. The server authenticated the user by
    /// calling a configured userinfo endpoint with the access token it just
    /// received — configuration and transport trust rather than
    /// cryptographic trust (§12.1 note 11).
    ///
    /// # Errors
    /// The §2 status mapping — a `401` means the `state` was unknown or
    /// expired, or the provider returned no verified email. Also an
    /// [`AxiamError::Auth`] when the response set no usable `axiam_access`
    /// cookie, since a session that cannot be absorbed is not a successful
    /// login.
    pub async fn sso_complete_oauth2(
        &self,
        params: SsoCompleteOauth2Params,
    ) -> Result<SsoCompleteResult, AxiamError> {
        let body = OAuth2CallbackRequestWire {
            state: &params.state,
            code: &params.code,
        };
        let url = self
            .base_url()
            .join(SSO_OAUTH2_CALLBACK_PATH)
            .expect("sso_complete_oauth2 path is a well-formed relative URL literal");

        self.post_federation_session(url, &body, "sso_complete_oauth2")
            .await
    }

    /// `POST /api/v1/auth/federation/handoff` (CONTRACT.md §12.1) — redeem
    /// the single-use code the SAML and Apple flows deliver.
    ///
    /// Those two protocols return **cross-site**, so the server cannot set
    /// `SameSite=Strict` session cookies on that response. It instead
    /// redirects the browser to the SPA's callback URL with an
    /// [`HANDOFF_QUERY_PARAM`] query parameter; this call posts that code
    /// back same-origin, and *this* response is the one that carries the
    /// cookies (§12.1 note 12).
    ///
    /// # The code is gone either way
    ///
    /// It is valid for [`HANDOFF_CODE_TTL_SECS`] seconds and redeemable
    /// **once**. Redeem it from the same origin, immediately, and **never
    /// retry a failed redemption** — a `401` is terminal, and this method
    /// makes exactly one wire call so that it cannot become a retry by
    /// accident. Unknown, expired and already-redeemed all answer the same
    /// `401`, deliberately: telling them apart is not something a caller
    /// gets to do.
    ///
    /// # Errors
    /// [`AxiamError::Auth`] on the `401`, per the §2 status mapping. Also
    /// an [`AxiamError::Auth`] when the response set no usable
    /// `axiam_access` cookie.
    pub async fn sso_complete_handoff(
        &self,
        params: SsoCompleteHandoffParams,
    ) -> Result<SsoCompleteResult, AxiamError> {
        let body = SsoHandoffRequestWire { code: &params.code };
        let url = self
            .base_url()
            .join(SSO_HANDOFF_PATH)
            .expect("sso_complete_handoff path is a well-formed relative URL literal");

        self.post_federation_session(url, &body, "sso_complete_handoff")
            .await
    }

    /// The shared body of the two session-establishing federation POSTs:
    /// one wire call, §2 status mapping on anything but success, and the
    /// same post-login cookie sync `login()` and `sso_complete()` run (§4,
    /// §3).
    async fn post_federation_session<B: Serialize + ?Sized>(
        &self,
        url: url::Url,
        body: &B,
        operation: &str,
    ) -> Result<SsoCompleteResult, AxiamError> {
        let response = self
            .http()
            .post(url)
            .header("X-Tenant-ID", self.tenant_header_value())
            .maybe_csrf_header(self)
            .json(body)
            .send()
            .await
            .map_err(|e| network_err(&format!("{operation} request failed"), e))?;

        if !response.status().is_success() {
            let status = response.status().as_u16();
            let message = response
                .text()
                .await
                .unwrap_or_else(|_| "no response body".to_string());
            return Err(AxiamError::from_http_status(status, message));
        }

        let wire: SsoLoginSuccessResponseWire = response
            .json()
            .await
            .map_err(|e| network_err(&format!("failed to parse {operation} response"), e))?;

        crate::rest::auth::absorb_session_cookies(self).await?;

        Ok(SsoCompleteResult {
            user_id: wire.user_id,
            session_id: wire.session_id,
            expires_in: wire.expires_in,
            redirect_uri: wire.redirect_uri,
        })
    }
}
