//! Provision an IoT device and authenticate it with mTLS — CONTRACT §27 + §6.1.
//!
//! This is the flow that motivated the §27 management surface. Before it, an
//! SDK could *authenticate* a device with a client certificate but could not
//! **issue** one: minting the certificate, binding it to a service account,
//! and anchoring the CA for mTLS all had to happen out of band, by hand,
//! before any SDK client could be built.
//!
//! Five steps, and every one of them a §27 call:
//!
//! 1. Anchor the organization CA as an mTLS trust anchor, so the server will
//!    accept certificates it signed at the TLS layer.
//! 2. Create a service account — the device's identity.
//! 3. Generate a device certificate. **This is the only moment the private key
//!    exists outside the device**; it is returned once and never again.
//! 4. Bind the certificate to the service account, so presenting it
//!    authenticates as that identity rather than as an anonymous holder.
//! 5. Build a second client that presents the certificate, and use it.
//!
//! Run with:
//!
//! ```text
//! cargo run --example device_mtls_provisioning --features rest
//! ```
//!
//! It performs no network I/O: every call is printed rather than made, so the
//! example is readable and runnable without a server. The lines marked
//! `// →` are the requests a real run would issue.

use axiam_sdk::client::AxiamClient;
use axiam_sdk::management::models;
use axiam_sdk::{AxiamError, Sensitive};
use uuid::Uuid;

#[tokio::main]
async fn main() -> Result<(), AxiamError> {
    let _admin = AxiamClient::builder()
        .base_url("https://iam.example.com")?
        .tenant_id(Uuid::nil())
        .org_id(Uuid::nil())
        .build()?;

    // A real run authenticates first: §27.4 rule 1 refuses to make a wire call
    // without a session, so this would be `admin.login(..).await?`.
    println!("1. anchor the organization CA for mTLS");
    print_call(
        "PUT /api/v1/organizations/{org}/ca-certificates/{ca}/mtls-trust-anchor",
        "ca_certificates().set_mtls_trust_anchor(ca_id, &SetMtlsTrustAnchor { enabled: true })",
    );
    // Note the shape: `SetMtlsTrustAnchor` has a *required* field, because this
    // route is a replacement rather than a patch (§27.4 rule 5). The compiler
    // will not let you send a half-filled one.
    let _anchor = models::SetMtlsTrustAnchor { enabled: true };

    println!("\n2. create the device's service account");
    print_call(
        "POST /api/v1/service-accounts",
        "service_accounts().create(&CreateServiceAccountRequest { .. })",
    );
    // The response carries `client_secret`, returned **once** (§27.5). A device
    // authenticating by certificate does not need it — but if you discard it
    // and later decide you do, the only way back is `rotate_secret`.

    println!("\n3. generate the device certificate");
    print_call(
        "POST /api/v1/certificates",
        "certificates().generate(&GenerateCertificateRequest { cert_type: Device, .. })",
    );
    // `GeneratedCertificate::private_key_pem` is `Sensitive<String>` and is
    // returned by this call and by no other. `certificates().get(id)` afterwards
    // returns the *projection* — same certificate, no key field at all, and
    // nothing in the response to suggest something is missing. Write it to the
    // device now or mint a new certificate later; there is no third option.
    let device_key: Sensitive<String> = Sensitive::new("-----BEGIN PRIVATE KEY-----…".into());
    println!("   private key: {device_key}  <- redacted by §7, even here");

    println!("\n4. bind the certificate to the service account");
    print_call(
        "POST /api/v1/service-accounts/{sa}/bind-certificate",
        "service_accounts().bind_certificate(sa_id, &BindCertificateRequest { certificate_id })",
    );
    // Without this, the certificate is valid TLS material that authenticates as
    // nobody: the handshake succeeds and the authorization check finds no
    // subject to check.

    println!("\n5. the device builds its own client and authenticates");
    // On the device itself, with the key from step 3 and the cert alongside it:
    //
    //     let device = AxiamClient::builder()
    //         .base_url("https://iam.example.com")?
    //         .tenant_id(tenant_id)
    //         .with_client_cert(cert_pem.as_bytes(), key_pem.as_bytes())?
    //         .build()?;
    //     let decision = device.check_access("telemetry:publish", resource_id, None).await?;
    //
    // §6.1: the certificate is presented at the TLS layer on every request,
    // including the gRPC channel, and the server maps it to the service account
    // bound in step 4.
    print_call(
        "(TLS handshake)",
        "AxiamClient::builder().with_client_cert(cert_pem, key_pem)",
    );

    println!("\nRotation, when the certificate nears expiry:");
    println!("   - generate a new one (step 3) and bind it (step 4) BEFORE revoking the old");
    println!("   - then certificates().revoke(old_id) — a device that revokes first is a");
    println!("     device that has locked itself out and cannot call the API to fix it");

    Ok(())
}

fn print_call(route: &str, call: &str) {
    println!("   → {route}");
    println!("     {call}");
}
