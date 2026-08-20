//! `axiam-sdk-wasm` — the AXIAM Rust SDK, in a browser.
//!
//! # What this is
//!
//! A `wasm-bindgen` façade over [`axiam_sdk`]. It holds no protocol logic: every
//! method here parses its arguments, calls the same crate a native Rust
//! consumer calls, and converts the result to a JavaScript value. A second
//! implementation of login, authorization or OPAQUE would be a second thing to get
//! wrong, and the npm package would drift from the crate the first time either
//! changed.
//!
//! # What is not here, and why
//!
//! * **gRPC.** A browser has no sockets. `axiam-sdk`'s gRPC transport is
//!   compiled out.
//! * **AMQP and the reactor runtime.** Same reason.
//! * **The Actix middleware and route guards.** They guard a server; there is
//!   no server here.
//! * **mTLS and custom CA roots.** The browser chooses the client certificate
//!   and owns the trust store. `axiam-sdk` returns a typed error for both
//!   rather than accepting the call and ignoring it.
//! * **Request timeouts and redirect policy.** `fetch` exposes neither.
//!
//! Everything else — login (password and OPAQUE), MFA, refresh, logout,
//! `check_access`/`can`/`batch_check`, the decision memo, local JWKS
//! verification, and the §12 OIDC relying-party helpers — is the same code
//! path as the native SDK.
//!
//! # Cookies and sessions
//!
//! Tokens arrive as `HttpOnly` cookies and the browser stores them. That is
//! *stronger* than the native SDK's in-process jar, which `HttpOnly` cannot
//! protect: page script, including this module, genuinely cannot read them.
//! Requests must therefore be same-origin with the AXIAM API, or the API must
//! send CORS headers permitting credentials — a cross-origin `fetch` without
//! `credentials` will not carry the session and every call will 401.
//!
//! # OPAQUE in a browser: the honest limit
//!
//! [`AxiamWasmClient::loginOpaque`] keeps the password inside the wasm module, so
//! a TLS-terminating proxy, an accidentally verbose access log or a server-side
//! heap dump never sees it. It does **not** protect against a compromised AXIAM
//! server: that server also serves the page that loads this module, and could
//! serve one that posts the password instead. Do not describe browser OPAQUE as
//! protection against AXIAM itself.

use axiam_sdk::client::AxiamClient;
use axiam_sdk::rest::authz::AccessCheckRequest;
use serde::Serialize;
use wasm_bindgen::prelude::*;

/// Install the panic hook exactly once, so a Rust panic reaches the console
/// with a location instead of "unreachable executed".
fn install_panic_hook() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(console_error_panic_hook::set_once);
}

/// Map an SDK error to a JS `Error`.
///
/// The message is preserved verbatim: `axiam-sdk` already guarantees no error
/// message contains a raw token (§2, §7), so there is nothing to redact here,
/// and stripping detail would only make failures harder to diagnose.
fn to_js(err: axiam_sdk::AxiamError) -> JsValue {
    js_sys::Error::new(&err.to_string()).into()
}

fn to_js_value<T: Serialize>(value: &T) -> Result<JsValue, JsValue> {
    serde_wasm_bindgen::to_value(value)
        .map_err(|e| js_sys::Error::new(&format!("failed to encode result: {e}")).into())
}

/// The result of a login, in the shape JavaScript expects.
///
/// Mirrors `axiam_sdk::rest::auth::LoginResult` with two differences that are
/// deliberate rather than incidental: the challenge token is a plain string
/// (JavaScript has no `Sensitive<T>`, and pretending otherwise would be
/// theatre), and field names are camelCase to match every other AXIAM
/// JavaScript surface.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct JsLoginResult {
    mfa_required: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    challenge_token: Option<String>,
    available_methods: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    session_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    expires_in: Option<u64>,
}

impl From<axiam_sdk::rest::auth::LoginResult> for JsLoginResult {
    fn from(result: axiam_sdk::rest::auth::LoginResult) -> Self {
        Self {
            mfa_required: result.mfa_required,
            challenge_token: result.challenge_token.map(|t| t.expose().clone()),
            available_methods: result.available_methods,
            session_id: result.session_id.map(|id| id.to_string()),
            expires_in: result.expires_in,
        }
    }
}

/// An authorization decision, in the shape JavaScript expects.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct JsDecision {
    allowed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
}

/// A registration record ready to send with any request that sets a password.
///
/// Two fields where the SRP equivalent had seven: the server chose the
/// credential identifier, the suite and the costs and sealed them into
/// `opaqueSession`.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct JsOpaqueEnrollment {
    opaque_session: String,
    registration_record: String,
}

/// An AXIAM client, for the browser.
///
/// Build one with [`AxiamWasmClient::new`], then call the same operations the
/// native SDK exposes.
///
/// ```js
/// import init, { AxiamWasmClient } from "axiam-sdk-wasm";
///
/// await init();
/// const client = new AxiamWasmClient("https://axiam.example", "acme", "default");
/// await client.loginOpaque("alice", "correct horse battery staple");
/// const decision = await client.can("documents:read", "doc-42");
/// ```
#[wasm_bindgen]
pub struct AxiamWasmClient {
    inner: AxiamClient,
}

#[wasm_bindgen]
impl AxiamWasmClient {
    /// Build a client against `base_url`, scoped to one organization and
    /// tenant by slug.
    ///
    /// Slugs rather than UUIDs because a browser application generally knows
    /// the workspace it is serving by name. A client built this way has no
    /// tenant UUID to compare against, so `axiam-sdk`'s JWKS verifier stays
    /// unconfigured and its §10 route-guard path fails closed — which is
    /// correct, and irrelevant in a browser, where there is no route to guard.
    #[wasm_bindgen(constructor)]
    pub fn new(base_url: &str, org_slug: &str, tenant_slug: &str) -> Result<AxiamWasmClient, JsValue> {
        install_panic_hook();
        let inner = AxiamClient::builder()
            .base_url(base_url)
            .map_err(to_js)?
            .org_slug(org_slug)
            .tenant_slug(tenant_slug)
            .build()
            .map_err(to_js)?;
        Ok(Self { inner })
    }

    /// `POST /api/v1/auth/login` — password login.
    ///
    /// Prefer [`Self::loginOpaque`] where the tenant offers it: this method puts
    /// the password in the request body, where every TLS-terminating hop
    /// between the browser and AXIAM can read it.
    #[wasm_bindgen(js_name = login)]
    pub async fn login(&self, username_or_email: String, password: String) -> Result<JsValue, JsValue> {
        let result = self
            .inner
            .login(&username_or_email, &password)
            .await
            .map_err(to_js)?;
        to_js_value(&JsLoginResult::from(result))
    }

    /// OPAQUE login (CONTRACT.md §23) — the password never leaves this module.
    ///
    /// Returns the same shape as [`Self::login`], including the MFA-challenge
    /// case, so one result handler serves both.
    ///
    /// Rejects with a message naming OPAQUE when the tenant has it disabled,
    /// so a caller can fall back to [`Self::login`] rather than mistaking it
    /// for a bad password.
    ///
    /// **This blocks the thread it runs on** for the duration of the
    /// key-stretching function — tens to hundreds of milliseconds at
    /// Argon2id's default parameters, which is the cost that makes a stolen
    /// record expensive to attack. In a page that must stay responsive, run
    /// this module in a Web Worker.
    #[wasm_bindgen(js_name = loginOpaque)]
    pub async fn login_opaque(
        &self,
        username_or_email: String,
        password: String,
    ) -> Result<JsValue, JsValue> {
        let result = self
            .inner
            .login_opaque(&username_or_email, &password)
            .await
            .map_err(to_js)?;
        to_js_value(&JsLoginResult::from(result))
    }

    /// `POST /api/v1/auth/mfa/verify` — complete a login that returned
    /// `mfaRequired`.
    #[wasm_bindgen(js_name = verifyMfa)]
    pub async fn verify_mfa(&self, code: String) -> Result<JsValue, JsValue> {
        let result = self.inner.verify_mfa(&code).await.map_err(to_js)?;
        to_js_value(&JsLoginResult::from(result))
    }

    /// `POST /api/v1/auth/refresh` — rotate the session.
    ///
    /// Single-flight: concurrent callers coalesce onto one request, exactly as
    /// in the native SDK (§9 rule 6).
    #[wasm_bindgen(js_name = refresh)]
    pub async fn refresh(&self) -> Result<(), JsValue> {
        self.inner.refresh().await.map_err(to_js)
    }

    /// `POST /api/v1/auth/logout`.
    #[wasm_bindgen(js_name = logout)]
    pub async fn logout(&self) -> Result<(), JsValue> {
        self.inner.logout().await.map_err(to_js)
    }

    /// `POST /api/v1/authz/check` — one authorization decision.
    ///
    /// `resource` is a resource UUID. Parsed here rather than accepted as an
    /// opaque string so a typo fails with "not a UUID" at the call site
    /// instead of as a `no_grant` decision that looks like a permissions
    /// problem.
    #[wasm_bindgen(js_name = checkAccess)]
    pub async fn check_access(
        &self,
        action: String,
        resource: String,
        scope: Option<String>,
    ) -> Result<JsValue, JsValue> {
        let resource_id = parse_resource(&resource)?;
        let decision = self
            .inner
            .check_access(&action, resource_id, scope.as_deref())
            .await
            .map_err(to_js)?;
        to_js_value(&JsDecision {
            allowed: decision.allowed,
            reason_code: decision.reason_code,
            reason: decision.reason,
        })
    }

    /// `can` — the browser-facing alias of [`Self::checkAccess`], returning a
    /// plain boolean for the common "should I render this button" case.
    #[wasm_bindgen(js_name = can)]
    pub async fn can(
        &self,
        action: String,
        resource: String,
        scope: Option<String>,
    ) -> Result<bool, JsValue> {
        let resource_id = parse_resource(&resource)?;
        self.inner
            .can(&action, resource_id, scope.as_deref())
            .await
            .map_err(to_js)
    }

    /// `POST /api/v1/authz/check/batch` — many decisions in one round trip.
    ///
    /// `checks` is an array of `[action, resource]` or
    /// `[action, resource, scope]` tuples. Results come back in the same order,
    /// which is what makes a page-level permission sweep one request instead of
    /// N.
    #[wasm_bindgen(js_name = batchCheck)]
    pub async fn batch_check(&self, checks: JsValue) -> Result<JsValue, JsValue> {
        let parsed: Vec<Vec<String>> = serde_wasm_bindgen::from_value(checks)
            .map_err(|e| js_sys::Error::new(&format!("batchCheck expects an array of [action, resource, scope?] tuples: {e}")))?;

        let mut requests = Vec::with_capacity(parsed.len());
        for (index, tuple) in parsed.iter().enumerate() {
            let (Some(action), Some(resource)) = (tuple.first(), tuple.get(1)) else {
                return Err(js_sys::Error::new(&format!(
                    "batchCheck entry {index} needs at least [action, resource]"
                ))
                .into());
            };
            let mut request = AccessCheckRequest::new(action.clone(), parse_resource(resource)?);
            request.scope = tuple.get(2).cloned();
            requests.push(request);
        }

        let decisions = self.inner.batch_check(requests).await.map_err(to_js)?;

        let mapped: Vec<JsDecision> = decisions
            .into_iter()
            .map(|d| JsDecision {
                allowed: d.allowed,
                reason_code: d.reason_code,
                reason: d.reason,
            })
            .collect();
        to_js_value(&mapped)
    }

    /// Build an OPAQUE registration record for a password, to send with any
    /// request that sets one (user creation, change-password, reset
    /// completion).
    ///
    /// Performs a `register/start` round trip, which the SRP verifier this
    /// replaces did not need: the envelope is sealed under the server's
    /// oblivious PRF, so there is no offline computation that produces a valid
    /// record.
    ///
    /// Note the absence of the four arguments the SRP version required. There
    /// is no `identity` — a record binds to a credential identifier the server
    /// chooses, so passing an email can no longer produce something no login
    /// can satisfy — and no `group`/`kdf`/cost parameters, because the server
    /// names them in its response and this method honours what it names.
    #[wasm_bindgen(js_name = opaqueEnrollment)]
    pub async fn opaque_enrollment(&self, password: String) -> Result<JsValue, JsValue> {
        let enrollment = self
            .inner
            .opaque_enrollment(&password)
            .await
            .map_err(to_js)?;
        to_js_value(&JsOpaqueEnrollment {
            opaque_session: enrollment.opaque_session,
            registration_record: enrollment.registration_record,
        })
    }

    /// Whether this build can perform OPAQUE. Always `true` here — the
    /// implementation is compiled into the module.
    #[wasm_bindgen(js_name = opaqueAvailable)]
    pub fn opaque_available(&self) -> bool {
        self.inner.opaque_available()
    }

    /// Shut the client down (§18.1). Further calls fail rather than silently
    /// reconnecting.
    #[wasm_bindgen(js_name = close)]
    pub async fn close(&self) {
        self.inner.close().await;
    }
}

/// The version of `axiam-sdk` this package wraps.
///
/// Exported so a page can report which SDK it is running without a build-time
/// constant that could drift from the artifact actually loaded.
#[wasm_bindgen(js_name = sdkVersion)]
pub fn sdk_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

/// Parse a resource UUID, with a message that names the offending value.
///
/// A bad resource id is a caller mistake, and saying so is much more useful
/// than letting it reach the server and come back as `no_grant` — which reads
/// as "you lack permission" and sends the reader looking at roles instead of at
/// their own string.
fn parse_resource(resource: &str) -> Result<uuid::Uuid, JsValue> {
    resource.parse().map_err(|_| {
        js_sys::Error::new(&format!(
            "resource must be a UUID, got {resource:?}"
        ))
        .into()
    })
}

/// Run a complete OPAQUE registration and login inside this module, for
/// conformance testing.
///
/// # This is for the smoke test, and nothing else
///
/// Its SRP predecessor computed a verifier from a fixed `x` so that
/// `scripts/wasm-smoke.mjs` could reproduce the shared vectors exactly. OPAQUE
/// has no fixed-`x` equivalent — the blind is generated inside the protocol and
/// is not injectable — so the check takes the other available shape: perform
/// both halves of a real exchange and assert they agree.
///
/// That distinction is not academic. An old `binaryen` silently miscompiles
/// this module (see `Cargo.toml`), and "it built" is not evidence that the
/// elliptic-curve arithmetic inside survived. A round trip that completes is:
/// a miscompiled scalar multiplication produces an envelope that will not open.
///
/// Returns `true` on success and throws on failure, so a smoke test can assert
/// on either.
///
/// **Never call this in application code.** It talks to no server and
/// authenticates nobody.
#[doc(hidden)]
#[wasm_bindgen(js_name = __conformanceRoundTrip)]
pub fn conformance_round_trip() -> Result<bool, JsValue> {
    use axiam_opaque::{AxiamKsf, ClientLoginState, ClientRegistrationState, testing};

    const PASSWORD: &str = "wasm-smoke-test";
    let ksf = AxiamKsf::argon2id(8192, 1, 1).map_err(|e| js_sys::Error::new(&e.to_string()))?;

    let (state, request) =
        ClientRegistrationState::start(PASSWORD).map_err(|e| js_sys::Error::new(&e.to_string()))?;
    let (setup, response) = testing::server_registration_start(&request);
    let registered = state
        .finish(PASSWORD, &response, &ksf)
        .map_err(|e| js_sys::Error::new(&e.to_string()))?;

    let (state, ke1) =
        ClientLoginState::start(PASSWORD).map_err(|e| js_sys::Error::new(&e.to_string()))?;
    let ke2 = testing::server_login_start(&setup, &registered.record, &ke1);
    let logged_in = state
        .finish(PASSWORD, &ke2, &ksf)
        .map_err(|e| js_sys::Error::new(&e.to_string()))?;

    // The export key is derived from the password on both sides independently.
    // Agreement is the strongest single assertion available here.
    if logged_in.export_key != registered.export_key {
        return Err(js_sys::Error::new(
            "OPAQUE round trip produced disagreeing export keys — this artifact is miscompiled",
        )
        .into());
    }
    Ok(true)
}

