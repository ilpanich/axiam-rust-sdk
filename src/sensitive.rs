//! `Sensitive<T>` — a token-redaction newtype (CONTRACT.md §7).
//!
//! Wraps any token-carrying value so that it can never accidentally leak via
//! `Debug`, `Display`, `tracing`, or any other diagnostic sink. The inner
//! value is genuinely private (no `pub` field, no `Deref` impl); the only
//! path to the raw value is [`Sensitive::expose`] — see its doc comment for
//! why it is `pub` (needed by CONTRACT.md §12's `OidcTokenSet`) rather than
//! `pub(crate)`.

use std::fmt;

/// Wraps a sensitive value (e.g. an access or refresh token) so it can never
/// be printed, logged, or serialized in its raw form.
///
/// See CONTRACT.md §7: "The raw token string MUST NOT be exposed via any
/// public getter API." and "Debug/logging representations ... MUST emit a
/// redacted placeholder."
pub struct Sensitive<T>(T);

impl<T> Sensitive<T> {
    /// Wrap `value` so it is protected from Debug/Display leakage.
    pub fn new(value: T) -> Self {
        Self(value)
    }

    /// The only path to the raw wrapped value.
    ///
    /// For the §1–§11 surface (cookie/opaque-token sessions), this crate
    /// never needs to hand a raw token back to a caller — every internal use
    /// of `expose()` stays within this crate. §12's `OidcTokenSet`
    /// (`access_token`/`refresh_token`/`id_token`) is different: those
    /// tokens are delivered directly in the `/oauth2/token` JSON response
    /// body, not via `Set-Cookie`, so a relying-party application MUST be
    /// able to read them back out in order to use them (attach as an
    /// `Authorization` header on its own downstream calls, store them,
    /// revoke them later). This method is therefore `pub`, not
    /// `pub(crate)` — mirroring the TypeScript reference SDK's `Sensitive`,
    /// whose `expose()` is likewise a real, callable public method (marked
    /// `@internal` in its doc comment as a *convention*, not a compiler
    /// restriction). Call it only at the point of actually using the value;
    /// MUST NOT pass the returned value to any `Debug`/`Display`/logging/
    /// tracing sink.
    pub fn expose(&self) -> &T {
        &self.0
    }

    /// Crate-internal clone of the wrapped value, still redaction-safe.
    ///
    /// `Sensitive<T>` deliberately does not derive `Clone` publicly (a public
    /// derive would let a redacted value be cloned and then exposed through
    /// unrelated code paths). This manual, crate-private clone exists for the
    /// few internal call sites (e.g. `TokenManager`) that need to duplicate a
    /// token into a fresh `Sensitive<T>` without ever surfacing the raw value.
    #[allow(dead_code)]
    pub(crate) fn clone_inner(&self) -> Sensitive<T>
    where
        T: Clone,
    {
        Sensitive(self.0.clone())
    }
}

impl<T> fmt::Debug for Sensitive<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Sensitive(<redacted>)")
    }
}

impl<T> fmt::Display for Sensitive<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[SENSITIVE]")
    }
}

// Deliberately NOT derived: Serialize, Deserialize, Clone (public).
// A public derive of any of these would create a leak path around the
// redacting Debug/Display impls above (RESEARCH.md Pitfall 4).
