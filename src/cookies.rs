//! The cookie store, and the one place the browser's differs from everyone
//! else's.
//!
//! # Why an abstraction rather than `reqwest::cookie::Jar` directly
//!
//! On every native target this SDK keeps a per-client
//! [`reqwest::cookie::Jar`] — deliberately per-client rather than
//! process-global, so two `AxiamClient`s cannot leak sessions into each other
//! — and reads `axiam_access`, `axiam_refresh` and `axiam_csrf` straight out of
//! it after a login (§3, §4).
//!
//! In a browser none of that is possible or wanted:
//!
//! * reqwest's `cookies` feature does not exist on `wasm32`. It drives an
//!   in-process jar, and a `fetch` call would ignore it.
//! * The browser attaches the cookies itself, from its own store, once the
//!   request is made with `credentials: include`.
//! * `axiam_access` and `axiam_refresh` are `HttpOnly`. Page script — including
//!   wasm — cannot read them, by design. That is a *stronger* guarantee than
//!   the native jar offers, not a gap: the native jar's docs already note that
//!   `HttpOnly` means nothing to an in-process store.
//!
//! So the browser build stores nothing and reads nothing. The one value the
//! SDK genuinely needs back — the CSRF token, which is not secret and is
//! deliberately readable (§3) — arrives on the `X-CSRF-Token` response header,
//! which the server sends on every login and refresh for exactly this reason.
//! `AxiamClient::capture_csrf` reads that header on **all** targets and falls
//! back to the jar only where there is one.
//!
//! The result is that no call site needs a `cfg`: they hold a [`CookieJar`](crate::cookies::CookieJar) and
//! ask it for what they need, and it answers `None` on a target where the
//! answer cannot be known.

#[cfg(not(target_arch = "wasm32"))]
use std::sync::Arc;

use crate::sensitive::Sensitive;

// The cookie names live in `token::manager` alongside the rest of the §3/§4
// wire vocabulary; re-declaring them here would be a second place for them to
// drift.
#[cfg(not(target_arch = "wasm32"))]
use crate::token::manager::{COOKIE_ACCESS, COOKIE_CSRF, COOKIE_REFRESH};

// ---------------------------------------------------------------------------
// Native
// ---------------------------------------------------------------------------

/// A per-client cookie store.
///
/// Cheap to clone — it is an `Arc` internally on native and a unit on wasm.
#[cfg(not(target_arch = "wasm32"))]
#[derive(Clone, Default)]
pub struct CookieJar {
    inner: Arc<reqwest::cookie::Jar>,
}

#[cfg(not(target_arch = "wasm32"))]
impl CookieJar {
    /// A fresh, empty jar.
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// The jar as a `reqwest` cookie provider, for `ClientBuilder`.
    pub(crate) fn provider(&self) -> Arc<reqwest::cookie::Jar> {
        Arc::clone(&self.inner)
    }

    /// The `axiam_access` cookie, wrapped in [`Sensitive`] the moment it is
    /// read.
    pub(crate) fn access_token(&self, base_url: &url::Url) -> Option<Sensitive<String>> {
        self.cookie(base_url, COOKIE_ACCESS).map(Sensitive::new)
    }

    /// The `axiam_refresh` cookie. Note the caller must pass the **refresh
    /// endpoint's** URL, not the base: that cookie is `Path`-scoped to
    /// `/api/v1/auth/refresh`, and a jar read scoped to any other path returns
    /// nothing (RFC 6265 path matching).
    pub(crate) fn refresh_token(&self, refresh_url: &url::Url) -> Option<Sensitive<String>> {
        self.cookie(refresh_url, COOKIE_REFRESH).map(Sensitive::new)
    }

    /// The `axiam_csrf` cookie. Not wrapped in [`Sensitive`] — it is
    /// deliberately readable (§3) and is not a secret.
    pub(crate) fn csrf_token(&self, base_url: &url::Url) -> Option<String> {
        self.cookie(base_url, COOKIE_CSRF)
    }

    fn cookie(&self, url: &url::Url, name: &str) -> Option<String> {
        use reqwest::cookie::CookieStore;

        let header = self.inner.cookies(url)?;
        let raw = header.to_str().ok()?;
        let prefix = format!("{name}=");
        raw.split(';')
            .map(str::trim)
            .find_map(|kv| kv.strip_prefix(&prefix))
            .map(str::to_string)
    }
}

// ---------------------------------------------------------------------------
// Browser
// ---------------------------------------------------------------------------

/// A per-client cookie store.
///
/// On `wasm32` this holds nothing: the browser owns the cookie store, attaches
/// cookies to outgoing requests itself, and refuses page script access to the
/// `HttpOnly` ones. Every accessor therefore answers `None`, which callers
/// already handle — a `None` access token means "not captured from a cookie",
/// and the browser will still send it.
#[cfg(target_arch = "wasm32")]
#[derive(Clone, Default)]
pub struct CookieJar;

#[cfg(target_arch = "wasm32")]
impl CookieJar {
    pub(crate) fn new() -> Self {
        Self
    }

    /// Always `None`: `axiam_access` is `HttpOnly` and unreadable from page
    /// script. The browser still attaches it to every same-origin request.
    pub(crate) fn access_token(&self, _base_url: &url::Url) -> Option<Sensitive<String>> {
        None
    }

    /// Always `None`, for the same reason as [`Self::access_token`].
    pub(crate) fn refresh_token(&self, _refresh_url: &url::Url) -> Option<Sensitive<String>> {
        None
    }

    /// Always `None`. The CSRF token is recovered from the `X-CSRF-Token`
    /// response header instead — see the module docs.
    pub(crate) fn csrf_token(&self, _base_url: &url::Url) -> Option<String> {
        None
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;

    fn url(s: &str) -> url::Url {
        url::Url::parse(s).unwrap()
    }

    fn jar_with(cookies: &[&str], at: &str) -> CookieJar {
        use reqwest::cookie::CookieStore;
        let jar = CookieJar::new();
        let target = url(at);
        for c in cookies {
            jar.inner
                .set_cookies(&mut [c.parse().unwrap()].iter(), &target);
        }
        jar
    }

    #[test]
    fn reads_each_cookie_by_name() {
        let jar = jar_with(
            &["axiam_access=at-1; Path=/", "axiam_csrf=csrf-1; Path=/"],
            "https://axiam.example/",
        );
        let base = url("https://axiam.example/");
        assert_eq!(
            jar.access_token(&base).map(|s| s.expose().to_string()),
            Some("at-1".into())
        );
        assert_eq!(jar.csrf_token(&base), Some("csrf-1".into()));
    }

    #[test]
    fn a_missing_cookie_is_none_rather_than_an_error() {
        let jar = CookieJar::new();
        assert!(jar.access_token(&url("https://axiam.example/")).is_none());
        assert!(jar.csrf_token(&url("https://axiam.example/")).is_none());
    }

    #[test]
    fn the_refresh_cookie_is_only_visible_at_its_own_path() {
        // `axiam_refresh` is Path-scoped to /api/v1/auth/refresh. Reading the
        // jar against the base URL returns nothing (RFC 6265 path matching) —
        // the bug that once made every refresh fall back to a re-login.
        let jar = jar_with(
            &["axiam_refresh=rt-1; Path=/api/v1/auth/refresh"],
            "https://axiam.example/api/v1/auth/refresh",
        );
        assert!(jar.refresh_token(&url("https://axiam.example/")).is_none());
        assert_eq!(
            jar.refresh_token(&url("https://axiam.example/api/v1/auth/refresh"))
                .map(|s| s.expose().to_string()),
            Some("rt-1".into())
        );
    }
}
