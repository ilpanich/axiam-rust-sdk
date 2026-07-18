//! Shared lazily-connected `tonic::Channel` (D-04, RESEARCH.md Pitfall 5).
//!
//! Built once via `Endpoint::from_shared(base_url)?.connect_lazy()` — no
//! network I/O (no TCP/TLS handshake) happens until the first RPC call.
//! The resulting `Channel` is `Clone + Send + Sync` and is reused across
//! every RPC made through the client (never reconstructed per-call).
//!
//! CONTRACT.md §6: TLS verification is always strict by default. The only
//! escape hatch is a custom CA certificate (PEM) added to the verification
//! chain — there is deliberately no API surface here that disables or skips
//! certificate verification.

use std::time::Duration;

use tonic::transport::{Channel, ClientTlsConfig, Endpoint};

use crate::AxiamError;

/// Default gRPC connect timeout (D-14), mirroring the REST transport's
/// default in `src/client.rs`.
const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Default gRPC per-request timeout (D-14).
const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Options for constructing the shared gRPC channel. Mirrors the subset of
/// `AxiamClientBuilder` (`src/client.rs`) settings relevant to gRPC: base
/// URL, timeouts, and an optional custom CA PEM (§6's one and only TLS
/// escape hatch — never an insecure/skip-verification surface).
#[derive(Debug, Default)]
pub struct GrpcChannelConfig {
    /// Timeout for establishing the TCP+TLS connection. Defaults to 10
    /// seconds when `None`.
    pub connect_timeout: Option<Duration>,
    /// Timeout applied to each individual RPC. Defaults to 30 seconds when
    /// `None`.
    pub request_timeout: Option<Duration>,
    /// PEM-encoded custom CA certificate bytes (§6). `None` means: verify
    /// strictly against the platform's native trust store only.
    pub custom_ca_pem: Option<Vec<u8>>,
    /// §6.1 client-certificate **chain** (PEM), for mutual TLS. `None` leaves
    /// the default (no client certificate presented) behavior unchanged.
    /// Populate this together with [`Self::client_key`]; the easiest way is
    /// [`crate::client::AxiamClient::grpc_channel_config`], which copies the identity
    /// configured via `AxiamClientBuilder::with_client_cert`.
    pub client_cert_pem: Option<Vec<u8>>,
    /// §6.1 client private key (PEM, PKCS#8 or PKCS#1), held behind
    /// [`crate::Sensitive`] so it never leaks via `Debug`/log output (§7).
    /// Only used when [`Self::client_cert_pem`] is also set.
    pub client_key: Option<crate::Sensitive<Vec<u8>>>,
}

// `Sensitive<T>` deliberately does not derive a public `Clone` (see
// `src/sensitive.rs`), so `GrpcChannelConfig` cannot `#[derive(Clone)]`.
// This manual impl clones the key via the crate-internal, still
// redaction-safe `clone_inner`, preserving the no-public-leak invariant.
impl Clone for GrpcChannelConfig {
    fn clone(&self) -> Self {
        Self {
            connect_timeout: self.connect_timeout,
            request_timeout: self.request_timeout,
            custom_ca_pem: self.custom_ca_pem.clone(),
            client_cert_pem: self.client_cert_pem.clone(),
            client_key: self.client_key.as_ref().map(|k| k.clone_inner()),
        }
    }
}

/// Build the single, lazily-connected `tonic::Channel` for `base_url`.
///
/// No network I/O occurs here — the first actual RPC call triggers the
/// TCP+TLS handshake (Pitfall 5). Store the returned `Channel` once and
/// clone it for every RPC; never call this function per-call.
pub fn build_channel(base_url: &str, config: &GrpcChannelConfig) -> Result<Channel, AxiamError> {
    // X-2: refuse a plaintext `http://` gRPC endpoint (loopback excepted). The
    // interceptor attaches the bearer/tenant metadata to every RPC, so the
    // channel must be TLS-protected. Parsing via `url::Url` lets us inspect the
    // scheme/host before handing the string to tonic.
    if let Ok(parsed) = url::Url::parse(base_url) {
        crate::url_guard::ensure_secure_scheme(
            "gRPC base_url",
            parsed.scheme(),
            parsed.host_str(),
            "https",
        )
        .map_err(|message| AxiamError::Network {
            message,
            source: None,
        })?;
    }

    let mut endpoint =
        Endpoint::from_shared(base_url.to_string()).map_err(|e| AxiamError::Network {
            message: format!("invalid gRPC base_url: {e}"),
            source: Some(Box::new(e)),
        })?;

    endpoint = endpoint
        .connect_timeout(config.connect_timeout.unwrap_or(DEFAULT_CONNECT_TIMEOUT))
        .timeout(config.request_timeout.unwrap_or(DEFAULT_REQUEST_TIMEOUT));

    // §6: strict TLS verification is always on for `https` endpoints. Unlike
    // `Endpoint::new`, `Endpoint::from_shared` does NOT auto-detect the
    // scheme and enable TLS — it must be configured explicitly here.
    // `with_enabled_roots()` activates the `tls-native-roots` feature's
    // platform trust store (the system trust store per §6). The custom CA
    // path (`with_custom_ca`, if configured) ADDS to that chain — it never
    // replaces or bypasses it.
    if base_url.starts_with("https://") {
        let mut tls = ClientTlsConfig::new().with_enabled_roots();
        if let Some(pem) = &config.custom_ca_pem {
            let cert = tonic::transport::Certificate::from_pem(pem);
            tls = tls.ca_certificate(cert);
        }
        // §6.1: present a client certificate identity for mutual TLS. tonic's
        // `Identity::from_pem(cert, key)` takes the two PEMs separately. This
        // only ADDS the client identity we present — server verification stays
        // strict (the `with_enabled_roots` + optional CA chain above).
        if let (Some(cert), Some(key)) = (&config.client_cert_pem, &config.client_key) {
            let identity = tonic::transport::Identity::from_pem(cert, key.expose());
            tls = tls.identity(identity);
        }
        endpoint = endpoint.tls_config(tls).map_err(|e| AxiamError::Network {
            message: format!("failed to configure gRPC TLS: {e}"),
            source: Some(Box::new(e)),
        })?;
    }

    // `connect_lazy` performs NO network I/O — the returned `Channel` is
    // `Clone + Send + Sync` and is safe to store and reuse across every RPC
    // (Pitfall 5, D-04). The actual TCP+TLS handshake happens transparently
    // on the first RPC call.
    Ok(endpoint.connect_lazy())
}
