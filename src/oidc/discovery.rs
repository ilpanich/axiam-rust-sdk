//! `oidc_discover` (CONTRACT.md §12.1) — fetch, cache and single-flight the
//! OIDC discovery document.
//!
//! The cache is origin-keyed (normalized scheme+host+port, §12.3 rule 6), so
//! a document fetched from one origin can never be served for another. TTL
//! is at least [`MIN_DISCOVERY_TTL`] (5 minutes); concurrent callers for the
//! same (possibly cold) origin collapse into a single HTTP fetch via
//! [`tokio::sync::OnceCell::get_or_try_init`] — the same single-flight
//! primitive family CONTRACT.md §9 already prescribes for this language.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tokio::sync::{OnceCell, RwLock};

use crate::AxiamError;
use crate::client::AxiamClient;

/// Path of the OIDC discovery document, relative to the client base URL.
pub const DISCOVERY_PATH: &str = "/.well-known/openid-configuration";

/// Minimum — and default — discovery-cache TTL. CONTRACT.md §12.3 rule 6
/// sets a floor of 5 minutes; a smaller configured value is raised to it.
pub const MIN_DISCOVERY_TTL: Duration = Duration::from_secs(300);

/// The OIDC Discovery 1.0 metadata document served by
/// `GET /.well-known/openid-configuration` (wire schema
/// `OidcDiscoveryDocument`). Every field is required by the server's schema.
///
/// `issuer` is the **authoritative** issuer for ID-token validation
/// (CONTRACT.md §12.4 rule 3). It may legitimately differ from the client's
/// base URL when AXIAM runs behind a proxy, so this SDK never rejects a
/// document on an issuer/base-URL mismatch (§12.3 rule 6). Likewise
/// `jwks_uri` is read from here rather than hardcoded.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcConfiguration {
    /// The authorization server's issuer identifier — the value an ID
    /// token's `iss` claim must equal exactly.
    pub issuer: String,
    /// The authorization endpoint `oidc_begin` builds its redirect URL from.
    pub authorization_endpoint: String,
    /// The token endpoint used by `oidc_exchange`, `oidc_refresh` and
    /// `login_client_credentials`.
    pub token_endpoint: String,
    /// The userinfo endpoint. Advertised by the server but deliberately NOT
    /// called by any SDK (§12.3 rule 5).
    pub userinfo_endpoint: String,
    /// URI of the JWKS document whose keys verify ID-token signatures
    /// (§12.4 rule 2).
    pub jwks_uri: String,
    /// The RFC 7009 revocation endpoint used by `revoke`.
    pub revocation_endpoint: String,
    /// The RFC 7662 introspection endpoint used by `introspect`.
    pub introspection_endpoint: String,
    /// OAuth2 `response_type` values the server supports.
    pub response_types_supported: Vec<String>,
    /// Subject identifier types the server supports.
    pub subject_types_supported: Vec<String>,
    /// ID-token signing algorithms the server advertises. Informational
    /// only: §12.4 rule 1 pins verification to `EdDSA` regardless of what
    /// appears here.
    pub id_token_signing_alg_values_supported: Vec<String>,
    /// Scopes the server supports.
    pub scopes_supported: Vec<String>,
    /// Client-authentication methods the token endpoint supports
    /// (`client_secret_post`, §12.1 note 3).
    pub token_endpoint_auth_methods_supported: Vec<String>,
    /// Claims the server may include in an ID token.
    pub claims_supported: Vec<String>,
    /// Grant types the token endpoint supports.
    pub grant_types_supported: Vec<String>,
}

/// Normalize a base URL to its cache key: lowercased scheme and host with
/// the port always explicit (§12.3 rule 6). `https://IAM.example.com/` and
/// `https://iam.example.com:443/x` therefore share one key, while
/// `http://iam.example.com` gets its own.
pub(crate) fn normalize_origin(url: &url::Url) -> String {
    let scheme = url.scheme().to_ascii_lowercase();
    let host = url.host_str().unwrap_or_default().to_ascii_lowercase();
    let default_port = match scheme.as_str() {
        "https" => 443,
        "http" => 80,
        _ => 0,
    };
    let port = url.port().unwrap_or(default_port);
    format!("{scheme}://{host}:{port}")
}

struct CacheEntry {
    cell: OnceCell<OidcConfiguration>,
    created_at: Instant,
}

/// Origin-keyed discovery cache with single-flight fetching (CONTRACT.md
/// §12.3 rule 6). Not process-global: owned per [`AxiamClient`] instance, so
/// it is never shared across tenants or clients.
pub(crate) struct DiscoveryCache {
    entries: RwLock<HashMap<String, Arc<CacheEntry>>>,
    ttl: Duration,
}

impl DiscoveryCache {
    /// `ttl` is clamped up to [`MIN_DISCOVERY_TTL`] — §12.3 rule 6 forbids a
    /// smaller value.
    pub(crate) fn new(ttl: Duration) -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
            ttl: ttl.max(MIN_DISCOVERY_TTL),
        }
    }

    /// Fetch (or reuse a cached/in-flight) document for `origin_key`.
    /// Concurrent callers for the same cold origin share one `fetcher` call.
    pub(crate) async fn get<F, Fut>(
        &self,
        origin_key: &str,
        fetcher: F,
    ) -> Result<OidcConfiguration, AxiamError>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<OidcConfiguration, AxiamError>>,
    {
        // Fast path: an existing, still-fresh entry (initialized or another
        // caller's in-flight fetch) — no write lock needed.
        {
            let entries = self.entries.read().await;
            if let Some(entry) = entries.get(origin_key)
                && entry.created_at.elapsed() < self.ttl
            {
                let entry = Arc::clone(entry);
                drop(entries);
                let doc = entry.cell.get_or_try_init(fetcher).await?;
                return Ok(doc.clone());
            }
        }

        // Slow path: no fresh entry yet. Acquire the write lock and either
        // reuse an entry a racing writer already inserted, or create a new
        // one — this keeps a burst of cold-start callers to exactly one
        // fresh `CacheEntry`, and therefore (via `get_or_try_init` below)
        // exactly one HTTP fetch.
        let entry = {
            let mut entries = self.entries.write().await;
            let fresh = entries
                .get(origin_key)
                .is_some_and(|e| e.created_at.elapsed() < self.ttl);
            if !fresh {
                entries.insert(
                    origin_key.to_string(),
                    Arc::new(CacheEntry {
                        cell: OnceCell::new(),
                        created_at: Instant::now(),
                    }),
                );
            }
            Arc::clone(
                entries
                    .get(origin_key)
                    .expect("just inserted or already fresh"),
            )
        };

        let doc = entry.cell.get_or_try_init(fetcher).await?;
        Ok(doc.clone())
    }
}

impl AxiamClient {
    /// `GET /.well-known/openid-configuration` (CONTRACT.md §12.1) — fetch
    /// the OIDC discovery document, cached per origin with a ≥5-minute TTL
    /// and single-flight de-duplication of concurrent calls (§12.3 rule 6).
    ///
    /// The document's own `issuer` is authoritative for ID-token validation
    /// and may legitimately differ from the client's base URL behind a
    /// proxy, so a mismatch is never treated as an error.
    pub async fn oidc_discover(&self) -> Result<OidcConfiguration, AxiamError> {
        let origin_key = normalize_origin(self.base_url());
        let url = self
            .base_url()
            .join(DISCOVERY_PATH)
            .map_err(|e| AxiamError::Network {
                message: format!("invalid discovery URL: {e}"),
                source: None,
            })?;
        let http = self.http().clone();

        self.oidc_discovery_cache()
            .get(&origin_key, move || async move {
                let response = http
                    .get(url)
                    .send()
                    .await
                    .map_err(|e| AxiamError::Network {
                        message: format!("oidc discovery request failed: {e}"),
                        source: Some(Box::new(e)),
                    })?;
                if !response.status().is_success() {
                    let status = response.status().as_u16();
                    let message = response
                        .text()
                        .await
                        .unwrap_or_else(|_| "no response body".to_string());
                    return Err(AxiamError::from_http_status(status, message));
                }
                response
                    .json::<OidcConfiguration>()
                    .await
                    .map_err(|e| AxiamError::Network {
                        message: format!("failed to parse discovery document: {e}"),
                        source: Some(Box::new(e)),
                    })
            })
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_origin_lowercases_and_fills_default_port() {
        let a = url::Url::parse("https://IAM.example.com/").unwrap();
        let b = url::Url::parse("https://iam.example.com:443/x").unwrap();
        assert_eq!(normalize_origin(&a), normalize_origin(&b));

        let c = url::Url::parse("http://iam.example.com").unwrap();
        assert_ne!(normalize_origin(&a), normalize_origin(&c));
    }

    /// A scheme with no IANA default port (the `_ => 0` arm) still yields a
    /// stable, distinct origin key rather than colliding with `https`.
    #[test]
    fn normalize_origin_handles_a_scheme_with_no_default_port() {
        let explicit = url::Url::parse("ftp://iam.example.com:2121/").unwrap();
        assert_eq!(normalize_origin(&explicit), "ftp://iam.example.com:2121");

        let implicit = url::Url::parse("ftp://iam.example.com/").unwrap();
        assert_eq!(normalize_origin(&implicit), "ftp://iam.example.com:0");
        assert_ne!(
            normalize_origin(&implicit),
            normalize_origin(&url::Url::parse("https://iam.example.com/").unwrap())
        );
    }
}
