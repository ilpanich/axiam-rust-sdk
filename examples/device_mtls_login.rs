//! mTLS device login: `authenticate_device()` (CONTRACT.md §6.1 rules 6–10).
//!
//! **Not to be confused with `examples/device_login.rs`**, which is the RFC
//! 8628 Device Authorization Grant — a device with no keyboard showing a user
//! a code to type in on a phone. This one is a device that *holds its own
//! credential*: an X.509 certificate issued under its tenant's signing CA and
//! bound to a service account (see `examples/device_mtls_provisioning.rs` for
//! how it got one). No user, no code, no password.
//!
//! The flow is one call. The certificate is presented during the TLS
//! handshake, the request has no body, and the token that comes back is:
//!
//! * a **service-account** token (`aud` = `axiam:m2m`), usable for
//!   `check_access` and for the §27 operations the account's roles allow;
//! * **bound to the certificate** (`cnf.x5t#S256`) whenever AXIAM itself
//!   terminated TLS — so it works only over connections that present the same
//!   certificate, which this client does on REST and gRPC alike;
//! * **not refreshable**: call `authenticate_device()` again before
//!   `expires_in` runs out. It costs one handshake.
//!
//! This example is illustrative/compilable — it reads connection details and
//! the certificate paths from environment variables and does not require a
//! live AXIAM server to `cargo build --example device_mtls_login --features rest`.
//!
//! Run:
//!
//! ```text
//! AXIAM_BASE_URL=https://iam.example.com \
//! AXIAM_TENANT_ID=<tenant uuid> \
//! AXIAM_DEVICE_CERT=device.pem AXIAM_DEVICE_KEY=device.key \
//! cargo run --example device_mtls_login --features rest
//! ```

use axiam_sdk::client::AxiamClient;
use uuid::Uuid;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let base_url =
        std::env::var("AXIAM_BASE_URL").unwrap_or_else(|_| "https://localhost:8443".to_string());
    let tenant_id = std::env::var("AXIAM_TENANT_ID")
        .ok()
        .and_then(|s| Uuid::parse_str(&s).ok())
        .unwrap_or_else(Uuid::nil);
    let (Ok(cert_path), Ok(key_path)) = (
        std::env::var("AXIAM_DEVICE_CERT"),
        std::env::var("AXIAM_DEVICE_KEY"),
    ) else {
        eprintln!("set AXIAM_DEVICE_CERT and AXIAM_DEVICE_KEY to the device's PEM files");
        return Ok(());
    };
    let cert_pem = std::fs::read(cert_path)?;
    // Read once, handed to the builder, and dropped: the SDK keeps its own
    // copy behind `Sensitive` (§6.1 rule 3) and never exposes it again.
    let key_pem = std::fs::read(key_path)?;

    // The certificate is what makes `authenticate_device` reachable at all.
    // On a client built without one, it fails with `AxiamError::Auth` before
    // any request is made (§6.1 rule 7).
    let device = AxiamClient::builder()
        .base_url(&base_url)?
        .tenant_id(tenant_id)
        .with_client_cert(&cert_pem, &key_pem)?
        .build()?;

    // POST /api/v1/auth/device — no body; a refused certificate (unknown,
    // untrusted, expired, revoked, unbound, or a `Server` certificate) is a
    // 401 surfaced as `AxiamError::Auth` with the server's message.
    let token = device.authenticate_device().await?;
    // `token.access_token` is `Sensitive`: this prints `[SENSITIVE]`.
    println!(
        "authenticated: {} token, valid {} s ({})",
        token.token_type, token.expires_in, token.access_token
    );

    // The token is now this client's credential. Use the same client — the
    // one presenting the certificate — for everything that follows; a second
    // client without the certificate would have its requests refused.
    let resource_id = std::env::var("AXIAM_RESOURCE_ID")
        .ok()
        .and_then(|s| Uuid::parse_str(&s).ok())
        .unwrap_or_else(Uuid::new_v4);
    let allowed = device.can("telemetry:publish", resource_id, None).await?;
    println!("telemetry:publish on {resource_id}: {allowed}");

    // When `expires_in` is close, log in again. There is no refresh: a later
    // 401 is returned as-is rather than retried through a refresh token that
    // does not exist.
    Ok(())
}
