//! Transport-URL security guard (X-2): reject plaintext (non-TLS) endpoint
//! URLs at construction time.
//!
//! The HTTP transports (REST over HTTPS, gRPC over HTTPS) must run over TLS —
//! CONTRACT.md §6 mandates TLS 1.3 for all external communication and the SDK
//! forwards tenant identifiers / CSRF tokens / bearer cookies that must never
//! traverse a cleartext link. A plaintext `http://` base URL is therefore
//! refused up front rather than silently accepted.
//!
//! The single, deliberate exception is a loopback host (`localhost`,
//! `127.0.0.1`, `::1`) so local development / integration tests against a
//! non-TLS dev server still work. This is the only escape hatch; there is no
//! flag to disable the check for a routable host.
//!
//! # AMQP does not come through here
//!
//! It used to. [`crate::amqp::transport::ensure_amqps`] now owns the broker
//! URL, and it is **stricter**: §8b rules 1 and 5 carry no loopback carve-out,
//! the five other SDKs that ship AMQP dialers enforce them with no host
//! exception, and the server itself became TLS-only with no plaintext listener
//! for a loopback exception to reach. The generic helper below also failed open
//! on a URL that would not parse, which is the wrong direction for a security
//! check; `ensure_amqps` fails closed instead.

/// Returns `true` if `host` is a loopback / localhost literal — the sole
/// allowed exception to the plaintext-transport ban.
pub(crate) fn is_loopback_host(host: &str) -> bool {
    // `url` reports an IPv6 host without the surrounding brackets, but accept
    // the bracketed form too in case a raw authority string is passed in.
    host.eq_ignore_ascii_case("localhost")
        || host == "127.0.0.1"
        || host == "::1"
        || host == "[::1]"
}

/// Validate that `scheme` is the required TLS scheme (`secure_scheme`), unless
/// `host` is a loopback address. On rejection returns a human-readable reason
/// (never containing any secret) suitable for wrapping in an [`crate::AxiamError`].
///
/// `label` names the transport for the error message (e.g. `"base_url"`,
/// `"gRPC base_url"`, `"AMQP url"`).
pub(crate) fn ensure_secure_scheme(
    label: &str,
    scheme: &str,
    host: Option<&str>,
    secure_scheme: &str,
) -> Result<(), String> {
    if scheme.eq_ignore_ascii_case(secure_scheme) {
        return Ok(());
    }
    if host.is_some_and(is_loopback_host) {
        // Loopback dev exception: a non-TLS scheme is tolerated only because
        // the traffic never leaves the local host.
        return Ok(());
    }
    Err(format!(
        "{label} must use the encrypted `{secure_scheme}://` scheme (got \
         `{scheme}://`); plaintext transport is refused because it would expose \
         tenant identifiers, CSRF tokens, and session cookies — the only \
         exception is a loopback host (localhost/127.0.0.1/::1) for local \
         development (X-2, CONTRACT.md §6)"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn https_is_accepted() {
        assert!(ensure_secure_scheme("base_url", "https", Some("example.com"), "https").is_ok());
    }

    #[test]
    fn plaintext_routable_host_is_rejected() {
        let err = ensure_secure_scheme("base_url", "http", Some("example.com"), "https")
            .expect_err("plaintext http against a routable host must be rejected");
        assert!(err.contains("https"));
        // The reason must not leak anything odd; it should name the schemes.
        assert!(err.contains("http"));
    }

    #[test]
    fn plaintext_loopback_is_allowed() {
        for host in ["localhost", "127.0.0.1", "::1", "[::1]", "LOCALHOST"] {
            assert!(
                ensure_secure_scheme("base_url", "http", Some(host), "https").is_ok(),
                "loopback host {host} must be allowed over plaintext for dev"
            );
        }
    }

    #[test]
    /// The helper is generic over the required scheme, and this pins that
    /// genericity. It is **not** the AMQP guard: broker URLs go through
    /// `amqp::transport::ensure_amqps`, which grants no loopback exception —
    /// see this module's docs.
    fn the_required_scheme_is_a_parameter_not_a_constant() {
        assert!(ensure_secure_scheme("some url", "amqps", Some("broker"), "amqps").is_ok());
        assert!(ensure_secure_scheme("some url", "amqp", Some("broker"), "amqps").is_err());
        assert!(ensure_secure_scheme("some url", "amqp", Some("localhost"), "amqps").is_ok());
    }

    #[test]
    fn scheme_comparison_is_case_insensitive() {
        assert!(ensure_secure_scheme("base_url", "HTTPS", Some("example.com"), "https").is_ok());
    }
}
