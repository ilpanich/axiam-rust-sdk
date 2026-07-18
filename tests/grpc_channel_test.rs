//! `build_channel` (`src/grpc/channel.rs`) branch coverage: the X-2
//! plaintext-scheme guard (with its loopback exception), the `https://`
//! TLS-config branch (with and without a custom CA), and the
//! `Endpoint::from_shared` error path for a malformed `base_url`.
//!
//! `connect_lazy()` means none of these tests perform network I/O — they
//! only exercise `build_channel`'s own validation/construction logic
//! (CONTRACT.md §6, X-2).

#![cfg(feature = "grpc")]

use axiam_sdk::AxiamError;
use axiam_sdk::grpc::{GrpcChannelConfig, build_channel};

#[test]
fn plaintext_non_loopback_base_url_is_rejected() {
    let err = build_channel(
        "http://grpc.example.com:9090",
        &GrpcChannelConfig::default(),
    )
    .expect_err("plaintext http:// against a routable host must be rejected (X-2)");
    match err {
        AxiamError::Network { message, .. } => {
            assert!(message.contains("https"), "message: {message}");
        }
        other => panic!("expected Network error, got {other:?}"),
    }
}

// `connect_lazy()` needs an active Tokio runtime to construct the channel
// (it does not perform network I/O, but it does register with the runtime's
// reactor) — plain `#[test]` panics with "there is no reactor running".
#[tokio::test]
async fn plaintext_loopback_base_url_is_allowed() {
    for base_url in [
        "http://localhost:9090",
        "http://127.0.0.1:9090",
        "http://[::1]:9090",
    ] {
        build_channel(base_url, &GrpcChannelConfig::default())
            .unwrap_or_else(|e| panic!("loopback gRPC url must be allowed: {base_url}: {e:?}"));
    }
}

#[tokio::test]
async fn https_base_url_without_custom_ca_builds_successfully() {
    build_channel(
        "https://grpc.example.com:9090",
        &GrpcChannelConfig::default(),
    )
    .expect("https:// with the platform trust store only must build a lazy channel");
}

#[tokio::test]
async fn https_base_url_with_custom_ca_builds_successfully() {
    // A syntactically well-formed (self-signed, test-only) PEM block. Its
    // cryptographic validity is irrelevant here: `connect_lazy()` performs no
    // handshake, so this only exercises the `custom_ca_pem` branch's control
    // flow (config.custom_ca_pem.is_some() -> ca_certificate() -> tls_config()),
    // not certificate parsing correctness (already covered indirectly by
    // `AxiamClientBuilder::with_custom_ca`'s eager `reqwest::Certificate`
    // validation on the REST side, `src/client.rs`).
    let pem = b"-----BEGIN CERTIFICATE-----\n\
                MIIBhTCCASugAwIBAgIUANQoDwuCiEyzAyxjE0uMlQeqmXAwCgYIKoZIzj0EAwIw\n\
                -----END CERTIFICATE-----\n";
    let config = GrpcChannelConfig {
        custom_ca_pem: Some(pem.to_vec()),
        ..Default::default()
    };
    build_channel("https://grpc.example.com:9090", &config)
        .expect("https:// with a custom CA PEM configured must build a lazy channel");
}

#[test]
fn malformed_base_url_that_is_not_a_valid_uri_is_rejected() {
    // Not parseable as a `url::Url` at all (embedded whitespace), so the X-2
    // scheme guard is silently skipped (its `if let Ok(parsed) = ...` never
    // matches) and control falls through to `Endpoint::from_shared`, which
    // rejects it as an invalid URI — the error path this test targets.
    let err = build_channel("not a valid url", &GrpcChannelConfig::default())
        .expect_err("a string that is not a valid URI must be rejected by Endpoint::from_shared");
    match err {
        AxiamError::Network { message, .. } => {
            assert!(
                message.contains("invalid gRPC base_url"),
                "message: {message}"
            );
        }
        other => panic!("expected Network error, got {other:?}"),
    }
}

#[tokio::test]
async fn custom_connect_and_request_timeouts_are_accepted() {
    let config = GrpcChannelConfig {
        connect_timeout: Some(std::time::Duration::from_secs(5)),
        request_timeout: Some(std::time::Duration::from_secs(15)),
        custom_ca_pem: None,
        ..Default::default()
    };
    build_channel("https://grpc.example.com:9090", &config)
        .expect("custom timeouts must not affect lazy channel construction");
}
