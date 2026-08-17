//! AMQP transport security (CONTRACT.md §8b).
//!
//! HMAC signing (§8) gives authenticity and replay protection. It does not give
//! confidentiality: a signed `AuthzRequest` still names a subject, a resource
//! and an action in cleartext on the wire, and a signed reactor reply is still
//! an instruction to change a token. TLS gives confidentiality; HMAC gives
//! end-to-end authenticity *across broker hops*, which TLS cannot, because TLS
//! terminates at the broker and the broker then re-sends. Both are required and
//! neither substitutes for the other.
//!
//! This module is the single place where a broker URL plus optional PEM
//! material becomes a lapin connection. Both AMQP entry points — [`consume`]
//! (§8) and `reactor_serve` (§22) — dial through it.
//!
//! [`consume`]: crate::amqp::consume
//!
//! # Two things this fixes
//!
//! **A CA bundle was not expressible.** Both entry points dialled with
//! `Connection::connect`, which takes no TLS material at all, so an `amqps://`
//! broker could only ever be verified against the platform root store. §8b
//! rule 2 makes a custom CA bundle a **MUST** precisely because the common
//! deployment — an in-cluster broker whose certificate is issued by a private
//! CA or by AXIAM's own `axiam-pki` organization CA — cannot be verified by the
//! platform store. The rule was therefore not merely unimplemented here; it was
//! unimplementable.
//!
//! **The scheme guard failed open.** The check was written as
//! `if let Ok(parsed) = url::Url::parse(amqp_url) { … }`, so a URL that failed
//! to parse skipped the guard entirely and went straight to lapin. That is
//! backwards for a security check: an input nobody can parse is the one to
//! refuse, not the one to wave through. It is now an error.

use lapin::tcp::{OwnedIdentity, OwnedTLSConfig};
use lapin::{Connection, ConnectionProperties};

use crate::error::AxiamError;

/// TLS material for an `amqps://` broker connection (§8b).
///
/// Every field is optional: with none set, an `amqps://` URL still connects and
/// still verifies, against the platform root store. The fields exist for the
/// two cases that store cannot serve — a privately-issued broker certificate
/// (rule 2), and mutual TLS toward the broker (rule 3).
///
/// Fields hold PEM **content**, not paths. lapin wants the bytes either way, so
/// taking content keeps this SDK out of the business of reading the caller's
/// filesystem — and lets a caller source the material from a secret manager,
/// an env var, or a mounted file as they prefer.
///
/// # There is deliberately no `verify_peer: false`
///
/// Not as an oversight, and not as something to add later behind a scary name.
/// §8b rule 4 forbids surfacing a verification-skip option under any name,
/// because such a switch is the most reliably misused option in TLS: it appears
/// in a dev compose file, it works, and it travels unchanged into production,
/// where it turns TLS into an expensive no-op against exactly the attacker TLS
/// exists to stop. [`Self::ca_cert_pem`] covers the legitimate reason people
/// reach for it without covering the rest.
#[derive(Debug, Clone, Default)]
pub struct AmqpTlsConfig {
    /// PEM bundle of the CA(s) that issued the broker's certificate (rule 2).
    ///
    /// Unset = verify against the platform root store, which is correct for a
    /// publicly-issued broker certificate and is why this is optional.
    ///
    /// # This ADDS a root; it does not replace the platform store
    ///
    /// Setting this does **not** narrow the trust set to your CA. lapin hands
    /// the bundle to `tcp-stream`, whose rustls backend calls
    /// `add_parsable_certificates` on top of the platform verifier's existing
    /// roots — so afterwards, a certificate for the broker's hostname issued by
    /// *any* publicly trusted CA is still accepted. The trust set got wider,
    /// not narrower, which is the opposite of what "pin my private broker CA"
    /// usually means.
    ///
    /// There is no configuration here that changes that: `OwnedTLSConfig`
    /// carries only an identity and a certificate chain, with no hook for a
    /// rustls `ClientConfig`. To genuinely restrict trust, restrict it at the
    /// platform trust store, or authenticate the broker with mutual TLS via
    /// [`Self::client_cert_pem`] — a stronger statement than root pinning
    /// anyway. This matches the server's own `AmqpTlsConfig`, which documents
    /// the identical caveat for the identical reason.
    pub ca_cert_pem: Option<String>,
    /// PEM client certificate chain, for mutual TLS toward the broker (rule 3).
    ///
    /// Must be set together with [`Self::client_key_pem`]; one without the
    /// other is a misconfiguration that fails closed rather than silently
    /// connecting without the mutual half of mutual TLS.
    pub client_cert_pem: Option<Vec<u8>>,
    /// PEM private key matching [`Self::client_cert_pem`]. Secret material.
    pub client_key_pem: Option<Vec<u8>>,
}

impl AmqpTlsConfig {
    /// Validate the combination without touching the network.
    ///
    /// The one rule: a client certificate and its key travel together.
    pub fn validate(&self) -> Result<(), AxiamError> {
        match (&self.client_cert_pem, &self.client_key_pem) {
            (Some(_), None) => Err(AxiamError::network(
                "AMQP TLS: a client certificate was supplied without its key — half a \
                 client identity cannot authenticate, and connecting anyway would \
                 silently drop the mutual half of mutual TLS (CONTRACT.md §8b rule 3). \
                 Set both or neither.",
            )),
            (None, Some(_)) => Err(AxiamError::network(
                "AMQP TLS: a client key was supplied without its certificate; set both \
                 or neither (CONTRACT.md §8b rule 3).",
            )),
            _ => Ok(()),
        }
    }

    /// Whether any TLS material is configured at all.
    pub fn is_empty(&self) -> bool {
        self.ca_cert_pem.is_none()
            && self.client_cert_pem.is_none()
            && self.client_key_pem.is_none()
    }

    fn to_owned_tls_config(&self) -> OwnedTLSConfig {
        let identity = match (&self.client_cert_pem, &self.client_key_pem) {
            (Some(cert), Some(key)) => Some(OwnedIdentity::PKCS8 {
                pem: cert.clone(),
                key: key.clone(),
            }),
            // The mismatched cases are rejected by `validate`, which
            // `connect_amqps` runs before reaching here.
            _ => None,
        };
        OwnedTLSConfig {
            identity,
            cert_chain: self.ca_cert_pem.clone(),
        }
    }
}

/// Reject any broker URL that is not `amqps://` (§8b rules 1 and 5).
///
/// # Why there is no loopback exception here
///
/// [`crate::url_guard`] permits plaintext against a loopback host, and that
/// exception is right for §6's REST and gRPC rules — a dev server on
/// `http://localhost` is a normal thing to talk to. §8b is a different rule and
/// does not carry that carve-out: rules 1 and 5 are unconditional, the five
/// other SDKs that ship AMQP dialers (Go, Python, PHP, Kotlin, and the server's
/// own client) enforce them with no host exception, and since the server became
/// TLS-only there is no loopback broker to reach over plaintext anyway. An
/// exception that reaches nothing is only a way for this SDK to disagree with
/// every other one.
///
/// The `://` separator is load-bearing: matching on `amqps` alone would accept
/// a hypothetical `amqpsomething://`.
pub fn ensure_amqps(amqp_url: &str) -> Result<(), AxiamError> {
    if amqp_url.trim().to_ascii_lowercase().starts_with("amqps://") {
        return Ok(());
    }
    Err(AxiamError::network(format!(
        "AMQP url must use the encrypted `amqps://` scheme (got {amqp_url:?}). Broker \
         traffic carries authorization requests, audit events and reactor replies across \
         a trust boundary, and HMAC signing gives them authenticity and replay protection \
         but NOT confidentiality. There is no plaintext fallback and no verification-skip \
         switch (CONTRACT.md §8b rules 1, 4 and 5); supply a private broker CA via \
         `AmqpTlsConfig::ca_cert_pem` if the broker certificate is not publicly issued."
    )))
}

/// Validate the URL and TLS material, then open one `amqps://` connection.
///
/// Both checks run **before** a socket is opened. A configuration fault
/// discovered at connect time arrives as a network error that says nothing
/// about what to fix.
pub async fn connect_amqps(amqp_url: &str, tls: &AmqpTlsConfig) -> Result<Connection, AxiamError> {
    ensure_amqps(amqp_url)?;
    tls.validate()?;

    // `connect_with_config` is lapin's only TLS-carrying entry point, and it
    // also requires an explicit runtime — so resolve the same default runtime
    // `Connection::connect` would have picked rather than introducing a second
    // runtime story for the TLS path.
    let runtime = lapin::runtime::default_runtime()
        .map_err(|e| AxiamError::network(format!("failed to resolve the AMQP runtime: {e}")))?;

    Connection::connect_with_config(
        amqp_url,
        ConnectionProperties::default(),
        tls.to_owned_tls_config(),
        runtime,
    )
    .await
    .map_err(|e| AxiamError::network(format!("failed to connect to AMQP broker: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn amqps_is_accepted_case_insensitively() {
        ensure_amqps("amqps://broker.example.com:5671").expect("amqps is the required scheme");
        // An operator who wrote AMQPS:// meant TLS.
        ensure_amqps("AMQPS://broker.example.com:5671").expect("scheme match is case-insensitive");
    }

    #[test]
    fn plaintext_is_refused_including_on_loopback() {
        for url in [
            "amqp://broker.example.com:5672",
            // The loopback carve-out §6 grants REST and gRPC does NOT apply
            // here — §8b rules 1 and 5 are unconditional, and every other SDK
            // that ships an AMQP dialer enforces them without a host exception.
            "amqp://localhost:5672",
            "amqp://127.0.0.1:5672",
        ] {
            let err = ensure_amqps(url).expect_err("plaintext must be refused");
            assert!(
                format!("{err}").contains("amqps://"),
                "the error must name the scheme to use, got: {err}"
            );
        }
    }

    /// The bug this module was written to close: the old guard was
    /// `if let Ok(parsed) = url::Url::parse(..)`, so anything unparseable
    /// skipped the check entirely. An input nobody can parse is the one to
    /// refuse, not the one to wave through.
    #[test]
    fn an_unparseable_url_is_refused_rather_than_waved_through() {
        for url in ["", "   ", "not a url at all", "://broker", "amqps:/broker"] {
            assert!(
                ensure_amqps(url).is_err(),
                "an unparseable url ({url:?}) must fail closed"
            );
        }
    }

    #[test]
    fn an_amqps_prefixed_impostor_is_not_amqps() {
        assert!(ensure_amqps("amqpsomething://broker:5671").is_err());
    }

    #[test]
    fn tls_material_is_optional_but_must_be_internally_consistent() {
        assert!(AmqpTlsConfig::default().validate().is_ok());
        assert!(AmqpTlsConfig::default().is_empty());

        let ca_only = AmqpTlsConfig {
            ca_cert_pem: Some("-----BEGIN CERTIFICATE-----".into()),
            ..Default::default()
        };
        ca_only
            .validate()
            .expect("a CA bundle alone is the common private-CA case (rule 2)");
        assert!(!ca_only.is_empty());

        let cert_only = AmqpTlsConfig {
            client_cert_pem: Some(b"cert".to_vec()),
            ..Default::default()
        };
        let err = cert_only
            .validate()
            .expect_err("half a client identity must fail closed");
        assert!(format!("{err}").contains("key"), "got: {err}");

        let key_only = AmqpTlsConfig {
            client_key_pem: Some(b"key".to_vec()),
            ..Default::default()
        };
        assert!(key_only.validate().is_err(), "…and so must the mirror case");
    }

    /// A tripwire on the config surface itself: adding a verification-skip
    /// field would make this fail, which is the point (rule 4).
    #[test]
    fn there_is_no_verification_skip_option() {
        let rendered = format!("{:?}", AmqpTlsConfig::default()).to_ascii_lowercase();
        for forbidden in ["verify", "insecure", "skip", "danger", "plaintext"] {
            assert!(
                !rendered.contains(forbidden),
                "AmqpTlsConfig must not grow a {forbidden:?}-shaped field: a \
                 verification-skip switch travels from a dev compose file into \
                 production and turns TLS into an expensive no-op"
            );
        }
    }

    /// The CA bundle must actually reach lapin's TLS config — the gap that made
    /// rule 2 unimplementable was precisely that nothing carried it there.
    #[test]
    fn tls_material_reaches_lapins_owned_config() {
        let cfg = AmqpTlsConfig {
            ca_cert_pem: Some("ca-pem".into()),
            client_cert_pem: Some(b"cert-pem".to_vec()),
            client_key_pem: Some(b"key-pem".to_vec()),
        };
        let owned = cfg.to_owned_tls_config();
        assert_eq!(owned.cert_chain.as_deref(), Some("ca-pem"));
        match owned.identity {
            Some(OwnedIdentity::PKCS8 { pem, key }) => {
                assert_eq!(pem, b"cert-pem".to_vec());
                assert_eq!(key, b"key-pem".to_vec());
            }
            other => panic!("expected a PKCS8 client identity, got {other:?}"),
        }
    }
}
