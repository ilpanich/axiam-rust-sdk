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
/// This satisfies all four CONTRACT.md §7 rules (as restructured in contract
/// 1.5):
///
/// 1. **Redaction (MUST)** — `Debug` renders `Sensitive(<redacted>)` and
///    `Display` renders `[SENSITIVE]`; `Serialize` is deliberately not
///    implemented, so no serializer can reach the value either.
/// 2. **No implicit reachability (MUST)** — the field is private, and there is
///    no `Deref`, `AsRef`, `From`, or value-comparing `PartialEq`.
/// 3. **One explicit accessor (MAY, RECOMMENDED where §12 ships)** —
///    [`Sensitive::expose`], `pub` because §12's `OidcTokenSet` hands tokens to
///    the calling application, which must be able to read them.
/// 4. **Point-of-use discipline (MUST)** — call `expose()` where the value is
///    actually used, and never pass its result to a log/trace/serialize sink.
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

    /// Crate-internal alias for [`Clone::clone`], kept for the internal call
    /// sites that predate the `Clone` impl below and read more clearly as
    /// "duplicate the wrapper, not the secret".
    pub(crate) fn clone_inner(&self) -> Sensitive<T>
    where
        T: Clone,
    {
        Sensitive(self.0.clone())
    }
}

/// Duplicating the wrapper duplicates the *protection*, not the exposure.
///
/// Written by hand rather than `#[derive(Clone)]` on purpose, so this doc
/// comment sits next to the impl: cloning a `Sensitive<T>` yields another
/// `Sensitive<T>`, whose `Debug`/`Display` still redact (see the impls below
/// and `tests/sensitive_redaction_test.rs`). There is still exactly **one**
/// path to the raw value — [`Sensitive::expose`] — so `Clone` adds no leak
/// path: a caller who can clone could already have called `expose()` on the
/// original. What it *does* enable is CONTRACT.md §9 rule 2 result sharing:
/// the single in-flight `oidc_refresh` has to hand the same `OidcTokenSet`
/// (which is built out of `Sensitive` fields) to every concurrent waiter,
/// and it cannot do that without duplicating the wrapper.
///
/// `Serialize`/`Deserialize` remain deliberately **un**implemented — those
/// *would* be leak paths around the redacting `Debug`/`Display`
/// (RESEARCH.md Pitfall 4).
impl<T: Clone> Clone for Sensitive<T> {
    fn clone(&self) -> Self {
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

// Deliberately NOT derived: Serialize, Deserialize.
// A derive of either would create a leak path around the redacting
// Debug/Display impls above (RESEARCH.md Pitfall 4). `Clone` is implemented
// (by hand, above) because duplicating a redacting wrapper cannot leak
// anything — only `expose()` can — and CONTRACT.md §9 rule 2 needs it.
