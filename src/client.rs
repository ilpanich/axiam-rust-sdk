//! `AxiamClient` + builder (owned by 16-02): tenant-scoped client
//! construction, base URL, timeouts, custom CA.
//!
//! CONTRACT.md §5: `tenant_slug` or `tenant_id` is a **non-optional**
//! constructor parameter — there is no default tenant. This builder
//! enforces that at `build()` time with a dedicated construction error
//! (never a silent default).
//!
//! CONTRACT.md §4: the client owns a per-instance
//! [`reqwest::cookie::Jar`] (not a process-global store) so multiple
//! clients can hold independent sessions.
//!
//! CONTRACT.md §6: TLS verification is always strict; the only escape
//! hatch is [`AxiamClientBuilder::with_custom_ca`]. There is no method on
//! this type that weakens or bypasses certificate verification.
//!
//! **Feature gating note:** `AxiamClient` is a REST-transport client (its
//! fields are all `reqwest`-based), so this entire module body is gated
//! behind `feature = "rest"` to preserve 16-01's `cargo build
//! --no-default-features` invariant (`client.rs`/`token` are declared
//! unconditionally in `lib.rs`, unlike `rest`/`grpc`/`amqp`).

#![cfg(feature = "rest")]

use std::sync::Arc;
use std::time::Duration;

use uuid::Uuid;

use crate::AxiamError;
use crate::token::TokenManager;
use crate::token::jwks::JwksVerifier;

// `fetch` has no configurable deadline, so these govern the native transport
// only. Kept out of the browser build rather than defined-and-ignored.
#[cfg(not(target_arch = "wasm32"))]
const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
#[cfg(not(target_arch = "wasm32"))]
const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// The tenant identifier a client was built with — either form is accepted
/// per CONTRACT.md §5; the SDK resolves `Slug` to a UUID after the first
/// successful login by decoding the `tenant_id` claim from the verified
/// access token (RESEARCH.md Open Question #1).
#[derive(Debug, Clone)]
pub(crate) enum TenantIdentifier {
    Slug(String),
    Id(Uuid),
}

impl TenantIdentifier {
    /// The value to send in the `X-Tenant-ID` header before resolution.
    pub(crate) fn header_value(&self) -> String {
        match self {
            TenantIdentifier::Slug(s) => s.clone(),
            TenantIdentifier::Id(id) => id.to_string(),
        }
    }
}

/// The organization identifier a client was built with (see
/// [`AxiamClientBuilder::org_slug`]/[`AxiamClientBuilder::org_id`]).
///
/// **Deviation from CONTRACT.md §5 (Rule 2 — missing critical
/// functionality):** the contract specifies only `tenant_slug`/`tenant_id`
/// as constructor parameters. AXIAM's actual `POST /api/v1/auth/login` and
/// `POST /api/v1/auth/refresh` endpoints additionally require an
/// organization identifier (`org_id`/`org_slug` on login; `org_id: Uuid`,
/// non-optional, on refresh) — organizations are the top-level multi-tenant
/// entity above tenants (CLAUDE.md domain model). Without this, `login()`
/// cannot succeed against the real server at all, so an optional
/// `org_slug`/`org_id` builder parameter is added: if supplied it is
/// forwarded on login; either way, the resolved organization UUID is
/// decoded from the verified access token's `org_id` claim after the first
/// successful login and cached for `refresh()` to reuse, so the caller only
/// ever needs to supply it once (at construction, if known) or not at all
/// (if it can be inferred from the JWT after login).
#[derive(Debug, Clone)]
pub(crate) enum OrgIdentifier {
    Slug(String),
    Id(Uuid),
}

/// Builder for [`AxiamClient`]. Construct via [`AxiamClient::builder`].
///
/// `base_url` and one of `tenant_slug`/`tenant_id` are required; omitting
/// the tenant identifier is a `build()`-time [`AxiamError`], never a silent
/// default (§5). `org_slug`/`org_id` are optional (see `OrgIdentifier`
/// doc comment for why they exist beyond the CONTRACT.md §5 baseline).
#[derive(Default)]
pub struct AxiamClientBuilder {
    base_url: Option<url::Url>,
    tenant: Option<TenantIdentifier>,
    org: Option<OrgIdentifier>,
    connect_timeout: Option<Duration>,
    request_timeout: Option<Duration>,
    custom_ca_pem: Option<Vec<u8>>,
    client_cert_pem: Option<Vec<u8>>,
    client_key: Option<crate::Sensitive<Vec<u8>>>,
    oidc_client_id: Option<String>,
    oidc_client_secret: Option<crate::Sensitive<String>>,
    oidc_discovery_ttl: Option<Duration>,
    oidc_clock_skew: Option<Duration>,
    /// §16.1 disable switch. `None` means the default, which is **on**.
    retry_enabled: Option<bool>,
    /// §19 telemetry sink. `None` means no hook installed, which costs one
    /// branch per request.
    telemetry: Option<std::sync::Arc<dyn crate::telemetry::TelemetrySink>>,
    /// §17 decision-memo TTL. `None` (and `Some(ZERO)`) mean disabled, which
    /// is the default.
    decision_memo_ttl: Option<Duration>,
}

impl AxiamClientBuilder {
    /// The AXIAM server's base URL (required, no default per §14).
    ///
    /// The URL MUST use `https://` (X-2): a plaintext `http://` base URL is
    /// rejected here because every request forwards tenant identifiers, CSRF
    /// tokens, and session cookies that must never traverse cleartext. The
    /// sole exception is a loopback host (localhost/127.0.0.1/::1) for local
    /// development.
    pub fn base_url(mut self, url: impl AsRef<str>) -> Result<Self, AxiamError> {
        let parsed = url::Url::parse(url.as_ref()).map_err(|e| AxiamError::Network {
            message: format!("invalid base_url: {e}"),
            source: None,
        })?;
        crate::url_guard::ensure_secure_scheme(
            "base_url",
            parsed.scheme(),
            parsed.host_str(),
            "https",
        )
        .map_err(|message| AxiamError::Network {
            message,
            source: None,
        })?;
        self.base_url = Some(parsed);
        Ok(self)
    }

    /// Human-readable tenant slug form (§5). Mutually exclusive with
    /// [`Self::tenant_id`] — the last one called wins.
    ///
    /// A blank slug is refused by [`Self::build`], not here: `""` is exactly as
    /// much of a tenant as none at all (§5.2.1 rule 2). To sign in an
    /// organization-level principal, name the organization's reserved tenant,
    /// whose slug is `"organization"` in every deployment (§5.2.1).
    pub fn tenant_slug(mut self, slug: impl Into<String>) -> Self {
        self.tenant = Some(TenantIdentifier::Slug(slug.into()));
        self
    }

    /// UUID tenant identifier form (§5). Mutually exclusive with
    /// [`Self::tenant_slug`] — the last one called wins.
    pub fn tenant_id(mut self, id: Uuid) -> Self {
        self.tenant = Some(TenantIdentifier::Id(id));
        self
    }

    /// Organization slug — optional; see `OrgIdentifier` doc comment.
    /// Mutually exclusive with [`Self::org_id`] — the last one called wins.
    ///
    /// As with [`Self::tenant_slug`], a blank slug is refused by
    /// [`Self::build`] rather than sent as `""`.
    pub fn org_slug(mut self, slug: impl Into<String>) -> Self {
        self.org = Some(OrgIdentifier::Slug(slug.into()));
        self
    }

    /// Organization UUID — optional; see `OrgIdentifier` doc comment.
    /// Mutually exclusive with [`Self::org_slug`] — the last one called wins.
    pub fn org_id(mut self, id: Uuid) -> Self {
        self.org = Some(OrgIdentifier::Id(id));
        self
    }

    /// Override the TCP connect timeout (default 10s, D-14).
    pub fn connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = Some(timeout);
        self
    }

    /// Override the overall request timeout (default 30s, D-14).
    pub fn request_timeout(mut self, timeout: Duration) -> Self {
        self.request_timeout = Some(timeout);
        self
    }

    /// Add a custom CA certificate (PEM-encoded bytes) to the TLS
    /// verification chain, for development environments using self-signed
    /// certificates (§6). This is the **only** TLS-related escape hatch;
    /// there is deliberately no way to disable or weaken verification.
    ///
    /// Returns a construction-time error if `pem` is not valid PEM.
    // `mut self` is used only on the native path; the browser path returns
    // before touching it.
    #[cfg_attr(target_arch = "wasm32", allow(unused_mut))]
    pub fn with_custom_ca(mut self, pem: &[u8]) -> Result<Self, AxiamError> {
        // A browser will not let page script choose trust roots. Refusing here
        // is the only honest answer: accepting the call and ignoring it would
        // leave a caller believing they had pinned a CA when every request was
        // still validated against the browser's own store.
        #[cfg(target_arch = "wasm32")]
        {
            let _ = pem;
            return Err(AxiamError::network(
                "with_custom_ca is not available in a browser: TLS trust roots \
                 belong to the browser and cannot be set from page script",
            ));
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            // Validate eagerly so a malformed CA is caught here rather than at
            // first request time.
            reqwest::Certificate::from_pem(pem).map_err(|e| AxiamError::Network {
                message: format!("invalid custom CA PEM: {e}"),
                source: None,
            })?;
            self.custom_ca_pem = Some(pem.to_vec());
            Ok(self)
        }
    }

    /// Configure a **client certificate** for mutual TLS (mTLS), per
    /// CONTRACT.md §6.1. AXIAM authenticates IoT devices and service accounts
    /// by mTLS: the client presents an X.509 identity certificate (signed by
    /// the tenant's organization CA) that the server binds to a service
    /// account. The configured identity is applied to **both** the REST
    /// transport (this client's `reqwest::Client`) and to any gRPC channel
    /// built from this client via [`AxiamClient::grpc_channel_config`].
    ///
    /// # Arguments
    /// * `cert_pem` — the PEM-encoded client certificate **chain**.
    /// * `key_pem` — the PEM-encoded private key (PKCS#8 or PKCS#1). It is
    ///   retained behind [`crate::Sensitive`] and is never exposed via any
    ///   public getter, `Debug`, or log output (§6.1 rule 3, §7).
    ///
    /// mTLS is opt-in; omitting this leaves the default bearer/cookie
    /// behavior unchanged (§6.1 rule 5). Presenting a client certificate
    /// **never** relaxes server verification (§6.1 rule 2) — strict TLS stays
    /// on and this is a separate code path from [`Self::with_custom_ca`].
    ///
    /// Returns a construction-time [`AxiamError`] if `cert_pem`/`key_pem` do
    /// not parse as a valid PEM certificate + private key (§6.1 rule 1).
    ///
    /// # Example
    /// ```no_run
    /// # use axiam_sdk::client::AxiamClient;
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let cert_pem = std::fs::read("device-cert.pem")?;
    /// let key_pem = std::fs::read("device-key.pem")?;
    /// let client = AxiamClient::builder()
    ///     .base_url("https://iam.example.com")?
    ///     .tenant_slug("acme")
    ///     .with_client_cert(&cert_pem, &key_pem)?
    ///     .build()?;
    /// # let _ = client;
    /// # Ok(())
    /// # }
    /// ```
    #[cfg_attr(target_arch = "wasm32", allow(unused_mut))]
    pub fn with_client_cert(mut self, cert_pem: &[u8], key_pem: &[u8]) -> Result<Self, AxiamError> {
        // Validate eagerly so a malformed cert/key is caught here rather than
        // at first-request time. `reqwest::Identity::from_pem` (rustls backend)
        // takes a single buffer holding the cert chain followed by the PKCS#8
        // private key — build it once to surface parse errors now, then store
        // the two PEMs separately (the key behind `Sensitive`, §7).
        // Same reasoning as `with_custom_ca`: a browser selects the client
        // certificate itself, from the user's own store, in response to the
        // server's CertificateRequest. Page script cannot supply one, and
        // silently dropping it would let an mTLS-configured client believe it
        // was presenting an identity it never sent.
        #[cfg(target_arch = "wasm32")]
        {
            let _ = (cert_pem, key_pem);
            return Err(AxiamError::network(
                "with_client_cert is not available in a browser: the client \
                 certificate is chosen by the browser, not by page script",
            ));
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            let combined = concat_cert_and_key(cert_pem, key_pem);
            reqwest::Identity::from_pem(&combined).map_err(|e| AxiamError::Network {
                message: format!("invalid client certificate / key PEM: {e}"),
                source: None,
            })?;
            self.client_cert_pem = Some(cert_pem.to_vec());
            self.client_key = Some(crate::Sensitive::new(key_pem.to_vec()));
            Ok(self)
        }
    }

    /// The relying-party OAuth2 `client_id` used by the CONTRACT.md §12
    /// OIDC/SSO helpers (`oidc_begin`, `oidc_exchange`, `oidc_refresh`,
    /// `login_client_credentials`, `introspect`, `revoke`). Optional: a
    /// client built without it can still use every §1–§11 operation; calling
    /// one of the nine §12 operations without it is a client-side
    /// [`AxiamError::Auth`], with no wire call.
    pub fn oidc_client_id(mut self, client_id: impl Into<String>) -> Self {
        self.oidc_client_id = Some(client_id.into());
        self
    }

    /// The confidential-client `client_secret` for the §12 OIDC/SSO
    /// helpers. Required by `introspect`/`revoke` (§12.1 note 4); optional
    /// for `oidc_exchange`/`oidc_refresh` (a public client omits it) and
    /// mandatory for `login_client_credentials`. Held behind
    /// [`crate::Sensitive`] (§12.5).
    pub fn oidc_client_secret(mut self, client_secret: impl Into<String>) -> Self {
        self.oidc_client_secret = Some(crate::Sensitive::new(client_secret.into()));
        self
    }

    /// Override the §12 OIDC discovery-document cache TTL. Clamped up to
    /// [`crate::oidc::MIN_DISCOVERY_TTL`] (5 minutes) — CONTRACT.md §12.3
    /// rule 6 forbids a smaller value. Defaults to that floor.
    pub fn oidc_discovery_ttl(mut self, ttl: Duration) -> Self {
        self.oidc_discovery_ttl = Some(ttl);
        self
    }

    /// Override the permitted ID-token clock skew for the §12.4 rule 5 time
    /// checks. Clamped down to 60 seconds — the contract forbids configuring
    /// it higher. Defaults to that maximum.
    pub fn oidc_clock_skew(mut self, skew: Duration) -> Self {
        self.oidc_clock_skew = Some(skew);
        self
    }

    /// Enable or disable the CONTRACT.md §16 bounded read-only retry policy.
    /// **Default: enabled.**
    ///
    /// Disabling it yields exactly one attempt per operation. That is the right
    /// choice for a caller who owns their own retry layer — they know their
    /// deadline and this SDK does not — but it is not a way to make failures
    /// quieter: a transient `NetworkError` will simply surface immediately.
    ///
    /// §16.1 permits this switch but forbids raising the attempt cap, base
    /// delay or delay cap above the contract's values, so there is no knob for
    /// those: eleven SDKs agreeing on one table is the point.
    pub fn retry_enabled(mut self, enabled: bool) -> Self {
        self.retry_enabled = Some(enabled);
        self
    }

    /// Install a CONTRACT.md §19 telemetry sink.
    ///
    /// The sink receives [`crate::telemetry::TelemetryEvent`]s for request
    /// start/end, §16 retries, and §9 refreshes, so metrics can be wired
    /// without this crate depending on any metrics library. See
    /// `examples/telemetry_otel.rs` for an OpenTelemetry adapter.
    ///
    /// Two guarantees worth knowing: a sink that panics cannot fail the
    /// operation that fired it (§19.2 rule 2), and no event payload can carry a
    /// token — the event type has a closed field set with no escape hatch
    /// (§19.2 rule 3). The sink is invoked on the calling path, so it must not
    /// block; buffer on your side if you need async delivery.
    pub fn telemetry_hook(mut self, sink: impl crate::telemetry::TelemetrySink) -> Self {
        self.telemetry = Some(std::sync::Arc::new(sink));
        self
    }

    /// Enable the CONTRACT.md §17 client-side decision memo with `ttl`.
    /// **Default: disabled** (`Duration::ZERO`, which means off — not "cache
    /// for zero seconds").
    ///
    /// # What you are accepting
    ///
    /// The staleness bound is `ttl`, **in both directions**. A grant revoked on
    /// the server can still read as `allowed` for up to `ttl`, and a grant just
    /// added can still read as denied for up to `ttl`.
    ///
    /// **Reads-your-own-writes is not guaranteed.** An admin UI that grants a
    /// role and immediately re-checks is the case that breaks, and it breaks
    /// silently. If that is your workload, leave this off.
    ///
    /// `ttl` is clamped to **5 seconds** rather than rejected, so asking for
    /// 60 s gets you 5 s. Allows and denies are memoized
    /// identically (§17.1 rule 4 — asymmetric caching leaks the outcome through
    /// latency), failures are never memoized, and the memo is cleared on
    /// `login`/`logout`/`refresh`. The §11 route guard's fail-closed path never
    /// consults it, so an outage cannot be papered over with a stale allow.
    pub fn decision_memo_ttl(mut self, ttl: Duration) -> Self {
        self.decision_memo_ttl = Some(ttl);
        self
    }

    /// Finalize the client. Fails if `base_url` or a tenant identifier is
    /// missing (§5 — never a silent default).
    pub fn build(self) -> Result<AxiamClient, AxiamError> {
        let base_url = self.base_url.ok_or_else(|| AxiamError::Network {
            message: "base_url is required to build an AxiamClient".into(),
            source: None,
        })?;
        let tenant = self.tenant.ok_or_else(|| AxiamError::Auth {
            message:
                "a tenant identifier (tenant_slug or tenant_id) is required to build an AxiamClient \
                 — AXIAM is multi-tenant and there is no default tenant (CONTRACT.md §5)"
                    .into(),
                oauth: None,
reason: None,
})?;

        // A blank slug is not an identifier, and §5.2.1 rule 2 makes refusing
        // it here a MUST rather than a nicety. Nothing can carry an empty slug,
        // so `tenant_slug: ""` on the wire resolves nothing — and on
        // `/auth/opaque/login/start` it fails on the workspace *before* the
        // tenant's OPAQUE mode is read, so the `404` that means "OPAQUE is not
        // offered here" never arrives and the caller has no fallback to take.
        // Sign-in then fails even against a tenant with OPAQUE disabled, and
        // the server's answer says "invalid credentials", which sends the user
        // off to reset a password that works.
        //
        // Checked at build rather than in `tenant_slug()`, which returns `Self`
        // and has nowhere to put an error. `""` is exactly as much of a tenant
        // as no tenant at all, so it earns the same refusal.
        if let TenantIdentifier::Slug(slug) = &tenant
            && slug.trim().is_empty()
        {
            return Err(AxiamError::Auth {
                message: "tenant_slug must not be blank — AXIAM is multi-tenant and there is no \
                          default tenant; to sign in an organization-level principal, name the \
                          organization's reserved tenant, whose slug is \"organization\" \
                          (CONTRACT.md §5, §5.2.1)"
                    .into(),
                oauth: None,
                reason: None,
            });
        }
        if let Some(OrgIdentifier::Slug(slug)) = &self.org
            && slug.trim().is_empty()
        {
            return Err(AxiamError::Auth {
                message: "org_slug must not be blank — omit it entirely, or name the organization \
                          (CONTRACT.md §5.1, §5.2.1)"
                    .into(),
                oauth: None,
                reason: None,
            });
        }

        let jar = crate::cookies::CookieJar::new();

        // Everything reqwest lets us configure here — redirect policy, cookie
        // provider, timeouts, custom CA, client identity — exists only on a
        // native transport. `fetch` exposes none of it: the browser owns
        // redirects, cookies, TLS and the request deadline. So the whole block
        // is native-only, and the two capabilities a caller could have *asked*
        // for and silently not received (custom CA, client certificate) are
        // refused at the builder methods above rather than dropped here.
        #[cfg(not(target_arch = "wasm32"))]
        let client_builder = {
            // Host-isolation (3A, defense in depth): never follow a redirect that
            // leaves our own origin. reqwest strips Authorization/Cookie on a
            // cross-host redirect but forwards custom headers (X-Tenant-ID /
            // X-CSRF-Token) — so a redirect to a third-party host would leak the
            // tenant identifier and CSRF token. Same-host redirects are followed
            // (capped at 10, matching reqwest's default); cross-host redirects are
            // not followed (the 3xx is returned as-is).
            //
            // Scheme-downgrade isolation (SDK-04): comparing host alone would let a
            // same-host `https://…` -> `http://…` redirect be followed, re-sending
            // X-Tenant-ID / X-CSRF-Token over cleartext. So a redirect that drops
            // from the original secure scheme to a less-secure one (https -> http)
            // is also refused, even on the same host.
            let redirect_base_host = base_url.host_str().map(str::to_owned);
            let redirect_base_scheme = base_url.scheme().to_owned();
            let redirect_policy = reqwest::redirect::Policy::custom(move |attempt| {
                if attempt.previous().len() >= 10 {
                    return attempt.error("too many redirects");
                }
                // Refuse a downgrade from the original secure scheme (https) to a
                // non-https scheme, regardless of host.
                if redirect_base_scheme.eq_ignore_ascii_case("https")
                    && !attempt.url().scheme().eq_ignore_ascii_case("https")
                {
                    return attempt.stop();
                }
                match (attempt.url().host_str(), redirect_base_host.as_deref()) {
                    (Some(next), Some(base)) if !next.eq_ignore_ascii_case(base) => attempt.stop(),
                    _ => attempt.follow(),
                }
            });

            let mut client_builder = reqwest::Client::builder()
                .cookie_provider(jar.provider())
                .redirect(redirect_policy)
                .connect_timeout(self.connect_timeout.unwrap_or(DEFAULT_CONNECT_TIMEOUT))
                .timeout(self.request_timeout.unwrap_or(DEFAULT_REQUEST_TIMEOUT));

            if let Some(pem) = &self.custom_ca_pem {
                let cert =
                    reqwest::Certificate::from_pem(pem).map_err(|e| AxiamError::Network {
                        message: format!("invalid custom CA PEM: {e}"),
                        source: None,
                    })?;
                client_builder = client_builder.add_root_certificate(cert);
            }

            // §6.1: apply the client-certificate identity (mTLS) to the REST
            // transport. `reqwest::Identity::from_pem` takes ONE buffer with
            // the cert chain followed by the private key. This never weakens
            // server verification — it only adds the client identity we
            // present.
            if let (Some(cert), Some(key)) = (&self.client_cert_pem, &self.client_key) {
                let combined = concat_cert_and_key(cert, key.expose());
                let identity =
                    reqwest::Identity::from_pem(&combined).map_err(|e| AxiamError::Network {
                        message: format!("invalid client certificate / key PEM: {e}"),
                        source: None,
                    })?;
                client_builder = client_builder.identity(identity);
            }
            client_builder
        };

        // The browser build takes reqwest's defaults, which are the browser's
        // defaults: same-origin credentials, browser redirect handling, no
        // configurable deadline.
        #[cfg(target_arch = "wasm32")]
        let client_builder = reqwest::Client::builder();

        let http = client_builder.build().map_err(|e| AxiamError::Network {
            message: format!("failed to construct HTTP client: {e}"),
            source: Some(Box::new(e)),
        })?;

        // CONTRACT.md §10.1 rule 4: when the client was built with a tenant
        // UUID, the verifier it owns is pre-configured with it, so
        // `JwksVerifier::verify` on this instance is a ready-to-use §10 guard.
        // A `tenant_slug`-built client has no UUID to compare against, so its
        // verifier stays unconfigured and `verify` fails closed — the SDK's
        // own session-absorption path uses `verify_session_token`, which is
        // explicitly not a guard, and does not depend on this.
        let jwks_verifier = match &tenant {
            TenantIdentifier::Id(id) => {
                JwksVerifier::new(http.clone(), &base_url)?.expect_tenant_id(*id)
            }
            TenantIdentifier::Slug(_) => JwksVerifier::new(http.clone(), &base_url)?,
        };

        // CONTRACT.md §12.3 rule 6: discovery-cache TTL floored at 5 minutes,
        // never process-global (owned by this client instance).
        let oidc_discovery_cache = crate::oidc::discovery::DiscoveryCache::new(
            self.oidc_discovery_ttl
                .unwrap_or(crate::oidc::MIN_DISCOVERY_TTL),
        );
        // CONTRACT.md §12.4 rule 5: clock skew capped at 60s, never
        // configurable above that bound.
        let oidc_clock_skew_sec = self
            .oidc_clock_skew
            .map(|d| d.as_secs())
            .unwrap_or(crate::oidc::id_token::MAX_CLOCK_SKEW_SEC)
            .min(crate::oidc::id_token::MAX_CLOCK_SKEW_SEC);

        Ok(AxiamClient {
            inner: Arc::new(AxiamClientInner {
                http,
                jar,
                base_url,
                tenant,
                org: self.org,
                token_manager: TokenManager::new(),
                jwks_verifier,
                csrf_token: std::sync::RwLock::new(None),
                resolved_org_id: std::sync::RwLock::new(None),
                resolved_principal_tenant_id: std::sync::RwLock::new(None),
                pending_mfa_challenge: std::sync::RwLock::new(None),
                custom_ca_pem: self.custom_ca_pem,
                client_cert_pem: self.client_cert_pem,
                client_key: self.client_key,
                oidc_client_id: self.oidc_client_id,
                oidc_client_secret: self.oidc_client_secret,
                oidc_discovery_cache,
                oidc_clock_skew_sec,
                oidc_verifiers: std::sync::RwLock::new(std::collections::HashMap::new()),
                oidc_refresh_inflight: crate::oidc::single_flight::OidcRefreshInflight::new(),
                // §16.1: the policy is on unless the caller turns it off.
                retry_enabled: self.retry_enabled.unwrap_or(true),
                telemetry: {
                    let telemetry = crate::telemetry::Telemetry::new(self.telemetry);
                    // §19.2 rule 6: a clamped setting is reported, not swallowed.
                    // Emitted here because construction is the only moment an
                    // operator can act on it.
                    let requested = self.decision_memo_ttl.unwrap_or(Duration::ZERO);
                    crate::memo::DecisionMemo::report_clamp(
                        requested,
                        requested.min(crate::memo::MAX_TTL),
                        &telemetry,
                    );
                    telemetry
                },
                // §17.1 rule 1: off unless the caller asked for it.
                decision_memo: crate::memo::DecisionMemo::new(
                    self.decision_memo_ttl.unwrap_or(Duration::ZERO),
                ),
                closed: std::sync::atomic::AtomicBool::new(false),
            }),
        })
    }
}

/// Concatenate a PEM cert chain and a PEM private key into the single buffer
/// `reqwest::Identity::from_pem` expects (cert(s) first, then key), ensuring a
/// newline separates the two so an already-trailing-newline-less cert does not
/// run into the key's `-----BEGIN` armor.
// mTLS is native-only: a browser chooses the client certificate itself.
#[cfg(not(target_arch = "wasm32"))]
fn concat_cert_and_key(cert_pem: &[u8], key_pem: &[u8]) -> Vec<u8> {
    let mut combined = Vec::with_capacity(cert_pem.len() + key_pem.len() + 1);
    combined.extend_from_slice(cert_pem);
    if !cert_pem.ends_with(b"\n") {
        combined.push(b'\n');
    }
    combined.extend_from_slice(key_pem);
    combined
}

pub(crate) struct AxiamClientInner {
    /// The one `reqwest::Client` every REST and §12 OIDC call shares.
    ///
    /// # Invariant: this transport has **no** 401→refresh interceptor
    ///
    /// CONTRACT.md §12 requires that a 401 from an `/oauth2/*` endpoint never
    /// enters the CONTRACT.md §9 single-flight refresh guard: such a
    /// 401 means the *client credentials* are bad (`invalid_client`), not that
    /// the user's session expired, so refreshing is both meaningless and
    /// harmful — it would burn a single-use rotating refresh token in response
    /// to someone else's failure.
    ///
    /// Three sibling SDKs (TypeScript, Java, C#) satisfy that rule with an
    /// explicit `/oauth2/*` skip list because their transports *do* carry a
    /// reactive 401 interceptor. This SDK satisfies it **structurally**: no
    /// interceptor is installed on this client at all. Refresh is only ever
    /// driven explicitly, by [`crate::token::refresh_guard`] on the §1 cookie
    /// session and by `oidc_refresh`'s dedicated coalescer
    /// ([`crate::oidc::single_flight`]) on the §12 token namespace — never
    /// automatically, from here.
    ///
    /// **Therefore: do not add a reactive 401→refresh interceptor (or any
    /// other blanket retry-on-401 middleware) to this `reqwest::Client`.** Doing
    /// so would silently route `/oauth2/*` 401s into the §9 guard and break the
    /// rule with no compile error and no obvious symptom. If one is ever needed
    /// for the REST surface, it MUST carry an explicit `/oauth2/*` skip list, as
    /// the three list-based SDKs do — and the skip list must cover every §12
    /// endpoint, including those reached at a *foreign host* via the discovery
    /// document, not merely paths under `base_url`.
    ///
    /// Pinned by the regression test
    /// `introspect_401_becomes_oauth_protocol_error_and_does_not_trigger_the_refresh_guard`
    /// (`tests/oidc_token_ops_test.rs`), which asserts a 401 from
    /// `/oauth2/introspect` produces zero `/api/v1/auth/refresh` calls.
    /// Cross-SDK conformance review follow-up F-14.
    pub(crate) http: reqwest::Client,
    pub(crate) jar: crate::cookies::CookieJar,
    pub(crate) base_url: url::Url,
    pub(crate) tenant: TenantIdentifier,
    pub(crate) org: Option<OrgIdentifier>,
    pub(crate) token_manager: TokenManager,
    pub(crate) jwks_verifier: JwksVerifier,
    /// Latest captured `X-CSRF-Token` value, forwarded on state-changing
    /// verbs (§3). `None` until the first response carrying the cookie.
    pub(crate) csrf_token: std::sync::RwLock<Option<String>>,
    /// CONTRACT.md §16.1 retry switch. Defaults to `true`.
    pub(crate) retry_enabled: bool,
    /// CONTRACT.md §19 telemetry dispatcher. Empty unless a sink was installed.
    pub(crate) telemetry: crate::telemetry::Telemetry,
    /// CONTRACT.md §17 decision memo. Disabled unless a TTL was configured.
    pub(crate) decision_memo: crate::memo::DecisionMemo,
    /// CONTRACT.md §18 shutdown flag. Set once by `close()`; read on every
    /// operation so use-after-close is an error rather than a reconnect.
    pub(crate) closed: std::sync::atomic::AtomicBool,
    /// Organization UUID resolved from the `org_id` claim of the verified
    /// access token after the first successful login/verify_mfa. See
    /// `OrgIdentifier` doc comment.
    pub(crate) resolved_org_id: std::sync::RwLock<Option<Uuid>>,
    /// CONTRACT.md §5.2.2 — the tenant the signed-in principal's record
    /// *lives* in, reported by the login response and cached here because the
    /// acting tenant (`self.tenant`) is a different thing and the two diverge
    /// for an organization-level principal.
    ///
    /// Read by [`AxiamClient::opaque_enrollment_for_self`], which must seal a
    /// §23 record against the account's own tenant rather than whichever one
    /// the client is currently pointed at. `None` until a login completes.
    pub(crate) resolved_principal_tenant_id: std::sync::RwLock<Option<Uuid>>,
    /// The challenge token from the most recent `login()` call that
    /// returned `mfa_required: true`, so `verify_mfa(code)` can complete
    /// the two-phase flow with only a `code` argument, matching
    /// CONTRACT.md §1's exact `verify_mfa(code)` signature.
    pub(crate) pending_mfa_challenge: std::sync::RwLock<Option<crate::Sensitive<String>>>,
    /// Custom CA PEM this client was built with, if any — retained so a gRPC
    /// channel built from the same client can share the identical trust chain
    /// (see [`AxiamClient::grpc_channel_config`]).
    ///
    /// Read only by the gRPC transport, so a REST-only build (including every
    /// browser build, which has no gRPC) never touches it. Retained rather
    /// than `cfg`-ed away so the struct's shape does not change with a
    /// feature — the field is inert, not absent.
    #[cfg_attr(not(feature = "grpc"), allow(dead_code))]
    pub(crate) custom_ca_pem: Option<Vec<u8>>,
    /// §6.1 client-certificate chain (PEM), if mTLS was configured — retained
    /// so the same identity applies to the gRPC transport (§6.1 rule 4).
    #[cfg_attr(not(feature = "grpc"), allow(dead_code))]
    pub(crate) client_cert_pem: Option<Vec<u8>>,
    /// §6.1 client private key (PEM), held behind [`crate::Sensitive`] so it
    /// never leaks via `Debug`/log/getter (§6.1 rule 3, §7).
    #[cfg_attr(not(feature = "grpc"), allow(dead_code))]
    pub(crate) client_key: Option<crate::Sensitive<Vec<u8>>>,
    /// The CONTRACT.md §12 relying-party `client_id`, if configured.
    pub(crate) oidc_client_id: Option<String>,
    /// The CONTRACT.md §12 confidential-client `client_secret`, if
    /// configured (§12.5).
    pub(crate) oidc_client_secret: Option<crate::Sensitive<String>>,
    /// Per-instance, origin-keyed, single-flight OIDC discovery cache
    /// (§12.3 rule 6).
    pub(crate) oidc_discovery_cache: crate::oidc::discovery::DiscoveryCache,
    /// Permitted ID-token clock skew in seconds, already clamped to
    /// [`crate::oidc::id_token::MAX_CLOCK_SKEW_SEC`] (§12.4 rule 5).
    pub(crate) oidc_clock_skew_sec: u64,
    /// One [`JwksVerifier`] per `jwks_uri` seen so far (§12.3 rule 6) — the
    /// discovery document's `jwks_uri` is not necessarily this client's own
    /// `/oauth2/jwks`, so it cannot reuse `jwks_verifier` above.
    pub(crate) oidc_verifiers:
        std::sync::RwLock<std::collections::HashMap<String, Arc<JwksVerifier>>>,
    /// Single-flight coalescer for `oidc_refresh` (CONTRACT.md §9 rules 1, 2,
    /// 4 and 5) — a **dedicated** instance, distinct from the §1
    /// cookie-session refresh guard owned by `token_manager`: the two protect
    /// unrelated token spaces (an OAuth2 `TokenResponse` the caller owns vs.
    /// the session's own cookie-derived access/refresh tokens) and must never
    /// be merged (CONTRACT.md §12.1 "`oidc_refresh` vs `refresh`"; §9 rule 5
    /// permits exactly this).
    ///
    /// It holds the in-flight **result channel**, not just a lock, because §9
    /// rule 2 requires the one wire call's outcome to be shared with every
    /// concurrent caller — serializing callers so each replays a single-use
    /// refresh token is explicitly non-conformant. See
    /// [`crate::oidc::single_flight`].
    pub(crate) oidc_refresh_inflight: crate::oidc::single_flight::OidcRefreshInflight,
}

/// The AXIAM SDK's REST/gRPC/AMQP client entry point.
///
/// Cheaply cloneable (`Arc`-backed); every clone shares the same cookie
/// jar, token state, and JWKS cache.
#[derive(Clone)]
pub struct AxiamClient {
    pub(crate) inner: Arc<AxiamClientInner>,
}

impl AxiamClient {
    /// Start building a client. See [`AxiamClientBuilder`].
    pub fn builder() -> AxiamClientBuilder {
        AxiamClientBuilder::default()
    }

    /// The base URL this client was constructed with.
    pub fn base_url(&self) -> &url::Url {
        &self.inner.base_url
    }

    /// The `X-Tenant-ID` header value to send on every request — the raw
    /// slug/UUID string the client was built with (CONTRACT.md §5).
    pub(crate) fn tenant_header_value(&self) -> String {
        self.inner.tenant.header_value()
    }

    /// The resolved tenant UUID, if a login/verify_mfa has already
    /// decoded it from the access token's `tenant_id` claim; otherwise the
    /// UUID form the client was constructed with, if any.
    pub async fn resolved_tenant_id(&self) -> Option<Uuid> {
        if let Some(id) = self.inner.token_manager.tenant_id().await {
            return Some(id);
        }
        match &self.inner.tenant {
            TenantIdentifier::Id(id) => Some(*id),
            TenantIdentifier::Slug(_) => None,
        }
    }

    /// Access the underlying `reqwest::Client` (crate-internal use by the
    /// `rest`/`token`/`oidc` modules).
    ///
    /// This is the transport seam the §12 OIDC helpers share with the §1 REST
    /// surface. It deliberately carries **no** reactive 401→refresh
    /// interceptor — see the `AxiamClientInner::http` field docs for the
    /// invariant that keeps a 401 from `/oauth2/*` out of the §9 guard, and why
    /// adding such an interceptor here would break CONTRACT.md §12 silently.
    pub(crate) fn http(&self) -> &reqwest::Client {
        &self.inner.http
    }

    /// Access the token manager (crate-internal use by `rest`/`grpc`).
    pub(crate) fn token_manager(&self) -> &TokenManager {
        &self.inner.token_manager
    }

    /// Whether the §16 retry policy is enabled on this client.
    pub(crate) fn retry_enabled(&self) -> bool {
        self.inner.retry_enabled
    }

    /// This client's §19 telemetry dispatcher.
    pub(crate) fn telemetry(&self) -> &crate::telemetry::Telemetry {
        &self.inner.telemetry
    }

    /// This client's §17 decision memo (disabled by default).
    pub(crate) fn decision_memo(&self) -> &crate::memo::DecisionMemo {
        &self.inner.decision_memo
    }

    /// Release this client's transport resources (CONTRACT.md §18).
    ///
    /// Idempotent — calling it twice is not an error. Cleanup runs from error
    /// paths, and an error path that itself fails hides the original failure.
    ///
    /// **This does not log out.** §18.1 rule 5: shutting down a client releases
    /// *local* resources only and never reaches the network. The server-side
    /// session deliberately outlives the client object, which is what lets a
    /// process restart and resume; a `close()` that logged out would silently
    /// end every user's session on each deploy. Call [`Self::logout`] first if
    /// ending the session is what you actually want.
    ///
    /// After this returns, any operation on the client fails with
    /// [`AxiamError::Network`] rather than silently reconnecting.
    pub async fn close(&self) {
        // `Release` pairs with the `Acquire` in `ensure_open`, so a thread that
        // observes `closed` also observes everything that happened before it.
        self.inner
            .closed
            .store(true, std::sync::atomic::Ordering::Release);
        // Drop the cookie jar's contents: §18.1 rule 3 requires the jar cleared,
        // and it is the one piece of session state this type owns outright.
        // `reqwest`'s pool is released when the last `Arc` clone drops — there
        // is no eager shutdown hook — so the observable guarantee this method
        // makes is "no further requests", enforced by `ensure_open`.
        self.inner.token_manager.clear().await;
    }

    /// Returns an error if [`Self::close`] has been called (§18.1 rule 4).
    ///
    /// Use-after-close is an error, never undefined and never a silent
    /// reconnect: a caller who kept a handle past shutdown has a bug, and
    /// quietly reopening the transport would hide it.
    pub(crate) fn ensure_open(&self) -> Result<(), AxiamError> {
        if self.inner.closed.load(std::sync::atomic::Ordering::Acquire) {
            return Err(AxiamError::network(
                "client is closed: this AxiamClient was shut down with close()",
            ));
        }
        Ok(())
    }

    /// Access the JWKS verifier (crate-internal use by `rest`/`middleware`).
    pub(crate) fn jwks_verifier(&self) -> &JwksVerifier {
        &self.inner.jwks_verifier
    }

    /// The configured CONTRACT.md §12 OIDC `client_id`, if any
    /// (crate-internal; `crate::oidc` turns its absence into a client-side
    /// `AxiamError`).
    pub(crate) fn oidc_client_id(&self) -> Option<&str> {
        self.inner.oidc_client_id.as_deref()
    }

    /// The configured CONTRACT.md §12 OIDC `client_secret`, if any (§12.5).
    pub(crate) fn oidc_client_secret(&self) -> Option<&crate::Sensitive<String>> {
        self.inner.oidc_client_secret.as_ref()
    }

    /// The per-instance, origin-keyed OIDC discovery cache (§12.3 rule 6).
    pub(crate) fn oidc_discovery_cache(&self) -> &crate::oidc::discovery::DiscoveryCache {
        &self.inner.oidc_discovery_cache
    }

    /// The permitted ID-token clock skew in seconds (§12.4 rule 5, already
    /// clamped to the 60s maximum).
    pub(crate) fn oidc_clock_skew_sec(&self) -> u64 {
        self.inner.oidc_clock_skew_sec
    }

    /// Lazily build (and cache) the JWKS verifier for `jwks_uri` (CONTRACT.md
    /// §12.3 rule 6 — one verifier per `jwks_uri`, which is read from the
    /// discovery document rather than hardcoded, and is never shared across
    /// tenants).
    pub(crate) fn oidc_verifier_for(
        &self,
        jwks_uri: &str,
    ) -> Result<Arc<JwksVerifier>, AxiamError> {
        if let Some(existing) = self
            .inner
            .oidc_verifiers
            .read()
            .ok()
            .and_then(|m| m.get(jwks_uri).cloned())
        {
            return Ok(existing);
        }
        let url = url::Url::parse(jwks_uri).map_err(|e| AxiamError::Network {
            message: format!("invalid jwks_uri in discovery document: {e}"),
            source: None,
        })?;
        let verifier = Arc::new(JwksVerifier::for_jwks_url(self.inner.http.clone(), url));
        if let Ok(mut map) = self.inner.oidc_verifiers.write() {
            map.entry(jwks_uri.to_string())
                .or_insert_with(|| Arc::clone(&verifier));
            return Ok(Arc::clone(map.get(jwks_uri).expect("just inserted")));
        }
        Ok(verifier)
    }

    /// Run the CONTRACT.md §9 leader/waiter election for `oidc_refresh`.
    ///
    /// The winner performs the single wire call and publishes its outcome;
    /// everyone else awaits that outcome and makes no call of its own (§9
    /// rules 1 and 2). See the field doc on
    /// `AxiamClientInner::oidc_refresh_inflight` for why this is a dedicated
    /// instance rather than the §1 cookie-session refresh guard.
    pub(crate) fn oidc_refresh_election(
        &self,
    ) -> crate::oidc::single_flight::OidcRefreshElection<'_> {
        self.inner.oidc_refresh_inflight.elect()
    }

    /// Read the latest captured CSRF token, if any (§3).
    pub(crate) fn csrf_token(&self) -> Option<String> {
        self.inner.csrf_token.read().ok().and_then(|g| g.clone())
    }

    /// Store a freshly-observed CSRF token (§3).
    pub(crate) fn set_csrf_token(&self, token: String) {
        if let Ok(mut guard) = self.inner.csrf_token.write() {
            *guard = Some(token);
        }
    }

    /// Read the `axiam_csrf` cookie directly out of the jar and cache it
    /// (used right after login/verify_mfa/refresh, mirroring how the
    /// `axiam_access` cookie is read — RESEARCH.md Pattern 1).
    pub(crate) fn capture_csrf_from_jar(&self) {
        if let Some(csrf) = self.inner.jar.csrf_token(&self.inner.base_url) {
            self.set_csrf_token(csrf);
        }
    }

    /// The `org_slug`/`org_id` the client was constructed with, if any
    /// (see `OrgIdentifier` doc comment for why this exists).
    pub(crate) fn org_identifier(&self) -> Option<&OrgIdentifier> {
        self.inner.org.as_ref()
    }

    /// The organization UUID resolved from the access token's `org_id`
    /// claim after the first successful login/verify_mfa, if any yet.
    pub(crate) fn resolved_org_id(&self) -> Option<Uuid> {
        self.inner.resolved_org_id.read().ok().and_then(|g| *g)
    }

    /// Cache the resolved organization UUID (called after decoding the
    /// access token post-login/verify_mfa/refresh).
    pub(crate) fn set_resolved_org_id(&self, org_id: Uuid) {
        if let Ok(mut guard) = self.inner.resolved_org_id.write() {
            *guard = Some(org_id);
        }
    }

    /// The tenant the signed-in principal's record lives in — CONTRACT.md
    /// §5.2.2. `None` until a login has reported one.
    pub(crate) fn resolved_principal_tenant_id(&self) -> Option<Uuid> {
        self.inner
            .resolved_principal_tenant_id
            .read()
            .ok()
            .and_then(|g| *g)
    }

    /// Cache the principal tenant reported by a completed login.
    pub(crate) fn set_resolved_principal_tenant_id(&self, tenant_id: Uuid) {
        if let Ok(mut guard) = self.inner.resolved_principal_tenant_id.write() {
            *guard = Some(tenant_id);
        }
    }

    /// Build a [`GrpcChannelConfig`](crate::grpc::GrpcChannelConfig) that
    /// mirrors this client's TLS configuration — the custom CA (§6) **and**
    /// the client-certificate identity (§6.1), if either was configured on the
    /// builder. This is how the mTLS identity configured via
    /// [`AxiamClientBuilder::with_client_cert`] is applied to the gRPC
    /// transport of the *same* client (§6.1 rule 4: both transports).
    ///
    /// Combine with [`crate::grpc::build_channel`]:
    /// ```no_run
    /// # #[cfg(all(feature = "rest", feature = "grpc"))]
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # use axiam_sdk::client::AxiamClient;
    /// # use axiam_sdk::grpc::build_channel;
    /// # let client = AxiamClient::builder()
    /// #     .base_url("https://iam.example.com")?
    /// #     .tenant_slug("acme")
    /// #     .build()?;
    /// let channel = build_channel("https://iam.example.com:9443", &client.grpc_channel_config())?;
    /// # let _ = channel;
    /// # Ok(())
    /// # }
    /// # #[cfg(not(all(feature = "rest", feature = "grpc")))]
    /// # fn main() {}
    /// ```
    #[cfg(feature = "grpc")]
    pub fn grpc_channel_config(&self) -> crate::grpc::GrpcChannelConfig {
        crate::grpc::GrpcChannelConfig {
            custom_ca_pem: self.inner.custom_ca_pem.clone(),
            client_cert_pem: self.inner.client_cert_pem.clone(),
            client_key: self.inner.client_key.as_ref().map(|k| k.clone_inner()),
            ..Default::default()
        }
    }

    /// Store the challenge token from a `login()` call that returned
    /// `mfa_required: true`, so a subsequent `verify_mfa(code)` can
    /// complete the flow without the caller re-supplying it.
    pub(crate) fn set_pending_mfa_challenge(&self, challenge: crate::Sensitive<String>) {
        if let Ok(mut guard) = self.inner.pending_mfa_challenge.write() {
            *guard = Some(challenge);
        }
    }

    /// Take (consume) the pending MFA challenge token, if any.
    pub(crate) fn take_pending_mfa_challenge(&self) -> Option<crate::Sensitive<String>> {
        self.inner
            .pending_mfa_challenge
            .write()
            .ok()
            .and_then(|mut guard| guard.take())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // `AxiamClientBuilder` intentionally has no `Debug` impl, so match on the
    // result rather than using `Result::expect_err`/`unwrap` (which require it).
    fn base_url_is_ok(url: &str) -> bool {
        AxiamClient::builder().base_url(url).is_ok()
    }

    // X-2: a plaintext http:// base URL against a routable host is rejected.
    #[test]
    fn plaintext_http_base_url_is_rejected() {
        match AxiamClient::builder().base_url("http://iam.example.com") {
            Ok(_) => panic!("plaintext http base_url must be rejected"),
            Err(AxiamError::Network { message, .. }) => {
                assert!(message.contains("https"), "message: {message}");
            }
            Err(other) => panic!("expected Network error, got {other}"),
        }
    }

    #[test]
    fn https_base_url_is_accepted() {
        assert!(base_url_is_ok("https://iam.example.com"));
    }

    // X-2: loopback dev exception — plaintext is tolerated only on localhost.
    #[test]
    fn plaintext_loopback_base_url_is_allowed() {
        for url in [
            "http://localhost:8080",
            "http://127.0.0.1:8080",
            "http://[::1]:8080",
        ] {
            assert!(
                base_url_is_ok(url),
                "loopback dev URL must be allowed: {url}"
            );
        }
    }

    // §5: `build()` never silently defaults a missing tenant identifier.
    #[test]
    fn build_without_base_url_fails() {
        match AxiamClient::builder().tenant_slug("acme").build() {
            Ok(_) => panic!("build() without a base_url must fail"),
            Err(AxiamError::Network { message, .. }) => {
                assert!(message.contains("base_url"), "message: {message}");
            }
            Err(other) => panic!("expected Network error, got {other}"),
        }
    }

    #[test]
    fn build_without_tenant_fails() {
        match AxiamClient::builder()
            .base_url("https://iam.example.com")
            .expect("valid base_url")
            .build()
        {
            Ok(_) => panic!("build() without a tenant identifier must fail (§5)"),
            Err(AxiamError::Auth { message, .. }) => {
                assert!(message.contains("tenant"), "message: {message}");
            }
            Err(other) => panic!("expected Auth error, got {other}"),
        }
    }

    // §5.2.1 rule 2: an SDK MUST NOT send an empty-string slug. The builder is
    // the only place this crate can enforce it — `tenant_slug()` returns `Self`
    // and has nowhere to put an error — and enforcing it there is what makes
    // the rule structural rather than a convention every call site has to
    // remember.
    //
    // The rule is not cosmetic. `tenant_slug: ""` matches no row, so the server
    // resolves nothing; on `/auth/opaque/login/start` it fails on the workspace
    // before the tenant's OPAQUE mode is read, so the `404` of §23.4 rule 10
    // never arrives, this crate has no fallback to take, and sign-in fails even
    // against a tenant with OPAQUE disabled — reported as "invalid
    // credentials", which sends a user off to reset a password that works.
    #[test]
    fn build_with_a_blank_tenant_slug_fails() {
        for blank in ["", "   "] {
            match AxiamClient::builder()
                .base_url("https://iam.example.com")
                .expect("valid base_url")
                .tenant_slug(blank)
                .org_slug("globex")
                .build()
            {
                Ok(_) => panic!("a blank tenant_slug must be refused (§5, §5.2.1)"),
                Err(AxiamError::Auth { message, .. }) => {
                    assert!(message.contains("tenant_slug"), "message: {message}");
                    assert!(
                        message.contains("organization"),
                        "the refusal must point at the reserved tenant, which is what an \
                         organization-level principal names instead: {message}"
                    );
                }
                Err(other) => panic!("expected Auth error, got {other}"),
            }
        }
    }

    #[test]
    fn build_with_a_blank_org_slug_fails() {
        match AxiamClient::builder()
            .base_url("https://iam.example.com")
            .expect("valid base_url")
            .tenant_slug("acme")
            .org_slug("")
            .build()
        {
            Ok(_) => panic!("a blank org_slug must be refused (§5.1, §5.2.1)"),
            Err(AxiamError::Auth { message, .. }) => {
                assert!(message.contains("org_slug"), "message: {message}");
            }
            Err(other) => panic!("expected Auth error, got {other}"),
        }
    }

    /// §5.2.1: an organization-level principal signs in by naming the
    /// organization's reserved tenant, whose slug is fixed in every deployment.
    /// No new surface — the ordinary builder reaches it.
    #[test]
    fn build_with_the_reserved_organization_tenant_succeeds() {
        let client = AxiamClient::builder()
            .base_url("https://iam.example.com")
            .expect("valid base_url")
            .tenant_slug("organization")
            .org_slug("globex")
            .build()
            .expect("the reserved tenant is named like any other");
        assert_eq!(client.base_url().as_str(), "https://iam.example.com/");
    }

    #[test]
    fn build_with_tenant_id_succeeds() {
        let client = AxiamClient::builder()
            .base_url("https://iam.example.com")
            .expect("valid base_url")
            .tenant_id(Uuid::new_v4())
            .org_slug("acme-corp")
            .connect_timeout(Duration::from_secs(3))
            .request_timeout(Duration::from_secs(9))
            .build()
            .expect("a base_url + tenant_id is sufficient to build");
        assert_eq!(client.base_url().as_str(), "https://iam.example.com/");
    }

    // §6: the only TLS escape hatch is a custom CA PEM. The doc comment on
    // `with_custom_ca` claims eager construction-time validation, but under
    // this crate's `rustls-tls` build (no `default-tls`/native-tls),
    // `reqwest::Certificate::from_pem` never actually parses/validates the
    // bytes — it just stores them (`Cert::Pem(buf)`), deferring real PEM
    // parsing to `ClientBuilder::build()` (confirmed against
    // `reqwest-0.12.28/src/tls.rs::{from_pem, add_to_rustls}`). So a byte
    // string with no `-----BEGIN CERTIFICATE-----` armor at all is NOT
    // rejected by `with_custom_ca()` — it is silently treated as "zero
    // certificates" and only a PEM block that IS armored but has corrupt
    // content inside fails, and only once `.build()` actually runs.
    #[test]
    fn with_custom_ca_accepts_pem_shaped_bytes_regardless_of_content() {
        let result = AxiamClient::builder().with_custom_ca(b"not a valid PEM at all");
        assert!(
            result.is_ok(),
            "with_custom_ca() does not itself validate PEM content under rustls-tls"
        );
    }

    #[test]
    fn build_fails_when_custom_ca_has_pem_armor_but_corrupt_content() {
        let armored_but_corrupt =
            b"-----BEGIN CERTIFICATE-----\nnot-valid-base64-!!!\n-----END CERTIFICATE-----\n";
        let result = AxiamClient::builder()
            .base_url("https://iam.example.com")
            .expect("valid base_url")
            .tenant_slug("acme")
            .with_custom_ca(armored_but_corrupt)
            .expect("with_custom_ca itself does not validate")
            .build();
        assert!(
            result.is_err(),
            "a PEM-armored but corrupt custom CA must fail at build() time"
        );
    }

    #[test]
    fn with_custom_ca_accepts_a_well_formed_pem_and_build_succeeds() {
        // A real self-signed Ed25519 certificate (generated once via
        // `openssl req -x509 -newkey ed25519 ... -days 36500`, test-only, no
        // corresponding private key is shipped anywhere in this repo). Its
        // cryptographic validity beyond "a well-formed X.509 DER
        // certificate" is irrelevant here — this test exercises the `Ok` arm
        // of `reqwest::Certificate::from_pem` and `build()`'s
        // `add_root_certificate` branch, distinct from the malformed-PEM
        // `Err` arm covered by `with_custom_ca_rejects_malformed_pem` above.
        let pem = b"-----BEGIN CERTIFICATE-----\n\
MIIBTzCCAQGgAwIBAgIUDR1ws2GiNbcb4OA2Lwi1txF7ej4wBQYDK2VwMBwxGjAY\n\
BgNVBAMMEWF4aWFtLXNkay10ZXN0LWNhMCAXDTI2MDcxMjE5MDkzNVoYDzIxMjYw\n\
NjE4MTkwOTM1WjAcMRowGAYDVQQDDBFheGlhbS1zZGstdGVzdC1jYTAqMAUGAytl\n\
cAMhALONss49Zo5XLA7afp7IqEjAZOuwOOeJFguUGAgFKiqOo1MwUTAdBgNVHQ4E\n\
FgQUIP+1NWh0QysH58QJrLhf3tQB5vYwHwYDVR0jBBgwFoAUIP+1NWh0QysH58QJ\n\
rLhf3tQB5vYwDwYDVR0TAQH/BAUwAwEB/zAFBgMrZXADQQDdqXRycg8FEUCfoSPD\n\
Vvc+22jEDDqLIztrKVMpUZZshflOEFzxYPMjEreJE7nnndY6+Of+l1I6+/xsR9qs\n\
W10C\n\
-----END CERTIFICATE-----\n";
        let client = AxiamClient::builder()
            .base_url("https://iam.example.com")
            .expect("valid base_url")
            .tenant_slug("acme")
            .with_custom_ca(pem)
            .expect("well-formed CA PEM must be accepted")
            .build()
            .expect("build() must succeed with a valid custom CA configured");
        assert_eq!(client.base_url().as_str(), "https://iam.example.com/");
    }
}
