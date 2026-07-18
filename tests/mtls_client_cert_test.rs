//! §6.1 client-certificate / mutual-TLS (mTLS) coverage for
//! [`AxiamClientBuilder::with_client_cert`] (`src/client.rs`) and the
//! [`GrpcChannelConfig`] client-identity branch (`src/grpc/channel.rs`).
//!
//! All test PKI (a self-signed cert + its PKCS#8 private key) is generated at
//! **runtime** with `rcgen` — no private key is ever committed to the repo
//! (§6.1 rule 3 / repo secret-scanning policy). `connect_lazy()` performs no
//! network I/O, so the gRPC assertions exercise the identity-config control
//! flow, not a live handshake.

#![cfg(feature = "rest")]

use axiam_sdk::AxiamError;
use axiam_sdk::client::AxiamClient;

/// Generate a throwaway self-signed certificate + PKCS#8 private key PEM pair
/// for use as a §6.1 client identity. Minted fresh in-process every call.
fn generate_client_identity() -> (String, String) {
    let cert = rcgen::generate_simple_self_signed(vec!["axiam-sdk-test-client".to_string()])
        .expect("rcgen must generate a self-signed cert");
    let cert_pem = cert.cert.pem();
    let key_pem = cert.key_pair.serialize_pem();
    (cert_pem, key_pem)
}

#[test]
fn with_client_cert_accepts_valid_pem_and_build_succeeds() {
    let (cert_pem, key_pem) = generate_client_identity();
    let client = AxiamClient::builder()
        .base_url("https://iam.example.com")
        .expect("valid base_url")
        .tenant_slug("acme")
        .with_client_cert(cert_pem.as_bytes(), key_pem.as_bytes())
        .expect("a valid rcgen cert + key must be accepted by with_client_cert")
        .build()
        .expect("build() must succeed with a client certificate configured");
    assert_eq!(client.base_url().as_str(), "https://iam.example.com/");
}

#[test]
fn with_client_cert_rejects_malformed_pem_at_construction_time() {
    // Neither buffer is valid PEM — the eager `Identity::from_pem` validation
    // in `with_client_cert` must surface this as an AxiamError right here,
    // not defer it to first-request time (§6.1 rule 1).
    let result = AxiamClient::builder().with_client_cert(b"not a certificate", b"not a key");
    match result {
        Ok(_) => panic!("a malformed client cert/key PEM must be rejected at construction time"),
        Err(AxiamError::Network { message, .. }) => {
            assert!(message.contains("client certificate"), "message: {message}");
        }
        Err(other) => panic!("expected Network error, got {other}"),
    }
}

#[test]
fn with_client_cert_rejects_valid_cert_but_missing_key() {
    // A well-formed cert paired with bytes that contain no parseable private
    // key must still fail — the combined buffer has a cert block but no key.
    let (cert_pem, _key_pem) = generate_client_identity();
    let result =
        AxiamClient::builder().with_client_cert(cert_pem.as_bytes(), b"no key material here");
    assert!(
        result.is_err(),
        "a valid cert with no parseable private key must be rejected"
    );
}

// The gRPC identity plumbing: a client built WITH a §6.1 client cert must
// surface it through `grpc_channel_config()` so the same identity reaches the
// gRPC transport (§6.1 rule 4 — both transports), and `build_channel` must
// accept that config (exercising the `tls.identity(...)` branch).
#[cfg(feature = "grpc")]
#[tokio::test]
async fn grpc_channel_config_carries_client_identity_and_builds() {
    use axiam_sdk::grpc::build_channel;

    let (cert_pem, key_pem) = generate_client_identity();
    let client = AxiamClient::builder()
        .base_url("https://iam.example.com")
        .expect("valid base_url")
        .tenant_slug("acme")
        .with_client_cert(cert_pem.as_bytes(), key_pem.as_bytes())
        .expect("valid client identity")
        .build()
        .expect("build with client cert");

    let config = client.grpc_channel_config();
    assert!(
        config.client_cert_pem.is_some(),
        "grpc_channel_config must carry the client certificate chain"
    );
    assert!(
        config.client_key.is_some(),
        "grpc_channel_config must carry the (Sensitive) client private key"
    );

    // The `Sensitive` key must not leak through Debug output (§7).
    let dbg = format!("{:?}", config.client_key);
    assert!(
        dbg.contains("redacted") && !dbg.contains("PRIVATE KEY"),
        "the private key must be redacted in Debug output: {dbg}"
    );

    build_channel("https://iam.example.com:9443", &config)
        .expect("https:// with a client identity configured must build a lazy channel");
}

// A client built WITHOUT a client cert produces a config with no identity —
// the default bearer/cookie behavior is unchanged (§6.1 rule 5).
#[cfg(feature = "grpc")]
#[test]
fn grpc_channel_config_without_client_cert_has_no_identity() {
    let client = AxiamClient::builder()
        .base_url("https://iam.example.com")
        .expect("valid base_url")
        .tenant_slug("acme")
        .build()
        .expect("build without client cert");
    let config = client.grpc_channel_config();
    assert!(config.client_cert_pem.is_none());
    assert!(config.client_key.is_none());
}

// The gRPC `GrpcChannelConfig` client-identity branch, driven directly (no
// AxiamClient) — mirrors how a `grpc`-only consumer would configure mTLS.
#[cfg(feature = "grpc")]
#[tokio::test]
async fn grpc_build_channel_applies_directly_configured_client_identity() {
    use axiam_sdk::Sensitive;
    use axiam_sdk::grpc::{GrpcChannelConfig, build_channel};

    let (cert_pem, key_pem) = generate_client_identity();
    let config = GrpcChannelConfig {
        client_cert_pem: Some(cert_pem.into_bytes()),
        client_key: Some(Sensitive::new(key_pem.into_bytes())),
        ..Default::default()
    };
    // Clone exercises the manual `impl Clone` that preserves key redaction.
    let cloned = config.clone();
    assert!(cloned.client_key.is_some());

    build_channel("https://grpc.example.com:9090", &config)
        .expect("a directly-configured client identity must build a lazy channel");
}
