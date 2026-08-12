# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **§20 UMA 2.0 — Protection API and ticket grant (contract 1.10).** New `uma` module:
  `uma_register_resource` / `uma_read_resource` / `uma_update_resource` /
  `uma_delete_resource` / `uma_list_resources`, `uma_request_ticket`,
  `uma_exchange_ticket`, and the `WWW-Authenticate: UMA` challenge helpers
  (`uma_parse_challenge`, `uma_challenge_header`).

  Two behaviours are load-bearing rather than incidental, and both are asserted at
  the wire. **`uma_exchange_ticket` never retries** — it is the one documented
  exception to the §16 retry policy, because a ticket is consumed before the
  request is evaluated, so a retry cannot succeed and under concurrency is exactly
  the second redemption that ilpanich/axiam#302's measured residual describes.
  And **`uma_parse_challenge` does not exchange the ticket it parsed**: the
  `as_uri` names an authorization server the client has not chosen to trust.

  The PAT is an explicit parameter on every Protection API call rather than being
  taken from the client's session, because that session is usually a *user*
  session and a ticket binds to a `client_id`.

- **§19 `TelemetryEvent::ConfigClamped` (contract 1.9).** The SDK now reports a clamped
  setting at construction rather than applying it silently — currently the §17.1 rule 2 memo
  TTL. Clamping is right; clamping *silently* is not: an operator who set a 60-second TTL
  believes their staleness bound is 60 seconds, and it is five. Nothing is emitted for a value
  already within its limit, or for the disabled default — an event that fires when nothing
  happened trains its reader to ignore it.

### Changed

- Re-vendored `CONTRACT.md` at **1.10** and `openapi.json` with the UMA paths.

## [Unreleased]

### Added

- **§16 bounded read-only retry policy.** §11.2 rule 5 and §14.2 rule 6 had both been
  *requiring* retries "under the SDK's existing bounded read-only retry policy" while no
  such policy existed in the contract; this crate's improvisation was `backon`'s defaults
  with `with_max_times(2)`. Contract 1.8 wrote the table down and `src/retry.rs`
  implements it: 3 attempts, 200 ms base, 5 s cap, **full jitter** over `[0, backoff]`,
  and `Retry-After` honored as a floor. Hand-rolled rather than reconfigured because
  `backon`'s `with_jitter()` adds a value in `[0, min_delay)` — a much narrower
  distribution, and partial jitter is what *causes* the thundering herd retries are meant
  to prevent — and because it has no seam for `Retry-After`. Both non-deterministic inputs
  are injected, so the tests pin the jitter fraction to 0.0 and 1.0 to prove the range and
  record delays instead of sleeping.
- **§18 deterministic shutdown.** `AxiamClient::close()`, idempotent, with use-after-close
  raising rather than silently reconnecting. It does **not** log out and never reaches the
  network: the server-side session outlives the client object, and a `close()` that logged
  out would end every user's session on each deploy.
- **§19 telemetry hooks.** `AxiamClientBuilder::telemetry_hook` and the `telemetry` module,
  so callers can wire OpenTelemetry or Prometheus without this crate depending on either.
  A panicking hook cannot fail the operation that fired it, and `TelemetryEvent` has a
  closed field set so no payload can carry a token. One request pair per *attempt*, not per
  logical call, so callers can count real wire calls.
- **§17 client-side decision memo — opt-in, off by default.**
  `AxiamClientBuilder::decision_memo_ttl`, TTL clamped to 5 s. Allows and denies are
  memoized identically (asymmetric caching leaks the outcome through latency), failures
  are never memoized, and the memo is cleared on any credential change. **Reads-your-own-
  writes is not guaranteed** — an admin UI that grants a role and immediately re-checks is
  the case that breaks, and it breaks silently.
- `AxiamClientBuilder::retry_enabled` (§16.6), default on. There is deliberately no knob
  for the attempt cap, base or delay cap: §16.1 forbids raising them.
- `examples/telemetry_hook.rs` — a runnable §19 sink aggregating request counts, latency
  and retries, with the exact OpenTelemetry mapping alongside it. Running it against an
  unreachable host prints `count=3` and `retries=2`, which is the §16 attempt cap made
  observable: without the hook a retried call is indistinguishable from a slow one.

### Removed

- The direct `backon` dependency. Nothing referenced it after §16 landed; it remains in
  the lockfile only as a transitive dependency of `lapin` under the `amqp` feature.

### Changed

- Re-vendored `CONTRACT.md` at **1.8**. `openapi.json` is unchanged — 1.8 is docs-only.
- `check_access`/`can`/`batch_check` now run under the §16 runner rather than `backon`, so
  they gain full jitter and `Retry-After` handling. The retry-eligible set is unchanged and
  remains authz reads only; no mutation became retryable.

### Notes

- `Retry-After` is **not** clamped to the 5 s delay cap. That cap governs the computed
  backoff, while §16.1 makes the hint a floor with no ceiling — clamping it would retry
  sooner than the server said it would be ready. Exposure stays bounded by the attempt cap.
- The hint rides on an internal type rather than on `AxiamError`. §16 requires the policy
  to *honor* `Retry-After`, not callers to read it, so the public error type is unchanged.
- `backon` remains a dependency; removing it is a separate cleanup once the other call
  sites migrate.

## [1.0.0-alpha24] - 2026-08-04

### Added

- Enforce the full CONTRACT §10.1 local-verification set
- Add CONTRACT §13 verify_webhook; trim build-time dependency surface

### Changed

- Add the §10.1 rule-8 guardrail regression tests (#43)
- Device (mTLS) tokens now carry aud=axiam:m2m (#42)
- Service accounts can use login_client_credentials (#41)
- Bump github/codeql-action from 4 to 4.37.4
- Bump taiki-e/install-action from 2.85.2 to 2.85.5
- Sync CONTRACT.md §10.1 rule 8 — subject of the decision (#38)

## [Unreleased]

### Security — BREAKING

- **`JwksVerifier::verify` now applies the complete CONTRACT §10.1 "minimum
  local-verification set".** §10.1 is a new normative section written because
  `SEC-071` and `SEC-080` were the same defect found independently in two
  SDKs: each verified a *different subset* of the token, and each subset
  looked complete in isolation. This SDK was audited against the stated
  complete set for the first time; three rules were missing and are now
  enforced. Every §10 / §11 entry point routes through the same call — the
  Actix `AxiamUser` extractor, and the `require_auth` / `require_access` /
  `require_role` macros, which inject that extractor rather than verifying
  anything themselves.

  This **tightens acceptance** and is therefore breaking, as §10.1 requires it
  to be called out. A token minted by the AXIAM server is unaffected — it
  always carries `exp` and never a future `nbf` — but a guard fed tokens from
  another signer sharing the organization JWKS may start rejecting what it
  used to accept. That is the intent.

  - **`nbf` is now honoured (rule 3).** `jsonwebtoken` defaults `validate_nbf`
    to `false`, so a token dated into the future previously verified.
    `validate_nbf` is now enabled; an absent `nbf` remains valid.
  - **`tenant_id` is now asserted (rule 4).** The `/oauth2/jwks` trust anchor
    is *organization-wide*, so a valid signature only ever proved "some tenant
    in this organization". `verify` now requires an expected tenant, set with
    the new `JwksVerifier::expect_tenant_id(Uuid)`, and rejects a token whose
    `tenant_id` is absent, unparseable, or different. **A verifier with no
    expected tenant configured now rejects every token (fail closed).** Any
    application registering a `JwksVerifier` as Actix `app_data` for the §10
    extractor must add `.expect_tenant_id(...)`; an `AxiamClient` built with
    `tenant_id(uuid)` pre-configures the verifier it owns.
  - **Clock skew is now a named, bounded constant (rule 7).** The previous
    inline `validation.leeway = 0` becomes the exported
    `axiam_sdk::token::CLOCK_SKEW_LEEWAY_SECS` at the contract's RECOMMENDED
    60 seconds, applied to both `exp` and `nbf`. It is deliberately not
    operator-configurable, so it can never be widened to an unbounded value.
    Note this makes the `exp` check 60 s *more* tolerant than before.
  - `exp` (rule 2) and the `alg`-pinned signature check (rule 1) were already
    correct and are unchanged: `Claims::exp` is a non-`Option` `i64` and
    `required_spec_claims` contains `"exp"`, so an absent or non-numeric `exp`
    was — and is — rejected; `alg` is read from the header and compared to
    `EdDSA` *before* the JWKS is consulted, so `alg: none` and an HS-signed
    token bearing an EdDSA `kid` are both rejected without a key lookup.

- The client's own session-absorption path (`login`/`verify_mfa`/`refresh`/
  `logout`) now calls a new crate-internal `verify_session_token` instead of
  `verify`. It applies every §10.1 rule except the tenant assertion, which
  cannot apply there: that path decodes a token the client just received over
  TLS from its own authenticated request, and the `tenant_id` claim is what it
  is *learning* (a `tenant_slug`-built client has no tenant UUID to compare
  against yet). No public API changes; no relaxation of any check that
  previously ran on that path.

### Added

- **Conditional issuer/audience expectations (CONTRACT §10.1 rules 5 and 6).**
  New `JwksVerifier::expect_issuer(impl Into<String>)` and
  `JwksVerifier::expect_audience(impl Into<String>)`, both optional and unset
  by default — the rules are explicitly conditional on configuration, and the
  SDK never hardcodes an expected issuer. When configured, a mismatched value
  is rejected, and the corresponding claim additionally becomes required (an
  absent `aud` does not "contain" the expected audience).
- **`JwksVerifier::verify_signature_only_unchecked`** — the §10.1 raw
  signature-only primitive, for integrators deliberately implementing their
  own policy. It verifies the EdDSA signature and *nothing else*: no `exp`,
  `nbf`, `tenant_id`, `iss` or `aud` check. The `_unchecked` suffix is the
  contract's reference spelling, chosen so the omission is obvious at the call
  site. It is not, and must not become, the documented guard entry point.
- `tests/local_verification_set_test.rs` — the complete §10.1 required
  negative-test set: expired; no `exp`; non-numeric `exp`; future `nbf`;
  different tenant; no `tenant_id`; no configured tenant; `alg: none`;
  HS-signed token bearing the EdDSA `kid`; foreign signature; plus
  issuer-mismatch and audience-mismatch cases for the newly-configurable
  expectations, and proof that the raw primitive waves through exactly what
  the guard rejects.
- CONTRACT.md in this repository is re-synced with the upstream
  `ilpanich/axiam` copy: §10.1 is vendored verbatim.

### Added

- **Webhook signature verification (CONTRACT §13, T-145).** New
  `axiam_sdk::webhook::verify_webhook`: HMAC-SHA256 over `<t>.<raw_body>`,
  `t=`/`v1=` header parsing with forward-compatible unknown-key tolerance,
  constant-time comparison over the *decoded* MAC bytes via `subtle`, and a
  two-sided freshness window defaulting to 300 s (a future-dated timestamp is
  rejected as well as a stale one). The secret is taken as `Sensitive<String>`
  (§7) and the typed `WebhookVerifyError` never surfaces the expected
  signature. Compiled whenever `rest` **or** `amqp` is enabled — both already
  vendor `hmac`/`sha2`/`hex`/`subtle`, so no new dependency is added.
- `benches/jwks_verify.rs` — a dependency-free (`harness = false`) micro-benchmark
  for the SDK's hottest CPU path, per-request access-token verification behind
  the §10/§11 route guard, including a "floor" row that measures
  `jsonwebtoken::decode` directly so SDK-side overhead can be read off
  independently of the Ed25519 cost.

### Changed

- **`actix-web` is now depended on with `default-features = false`**
  (`features = ["cookies", "macros"]`). The SDK only uses `HttpRequest`,
  `web::Data`, `HttpResponse`, `Responder` and `ResponseError`; actix-web's
  default set additionally forced its response-compression stack
  (brotli/zstd/flate2), `h2` 0.3 — a second `h2` major alongside the 0.4 that
  tonic and reqwest already use — `encoding_rs`, `language-tags`, WebSockets
  and the `regex`-based router onto every build. A cold
  `cargo build --all-features` graph drops from 295 to 276 crates, removing
  roughly 60 s of measured compile work (zstd-sys 15.9 s, h2 0.3 15.7 s,
  brotli 8.1 s, regex-automata 7.6 s, encoding_rs 7.1 s, language-tags 5.1 s,
  regex-syntax 3.9 s). This takes nothing away from applications: an app using
  the `actix`/`macros` features has its own `actix-web` dependency, and Cargo
  unifies features across the graph.
- Documented the scope of `[profile.release]` in `Cargo.toml` and README:
  Cargo honours only the **top-level workspace's** profile tables, so the
  release-build settings in this repository govern its own examples/benches and
  are *not* inherited by consumers. README gains a "Release-profile tuning (for
  consumers)" section with the block to copy into their own manifest, and a
  "Build-time notes" section identifying `aws-lc-sys` (pulled in by `rustls`'s
  default crypto provider via both `reqwest` and `lapin`) as the dominant
  remaining cold-build cost.

### Removed

- The `[profile.release]` table in `axiam-sdk-macros/Cargo.toml`. Cargo ignores
  profile tables in non-root workspace members and printed
  "profiles for the non root package will be ignored" on **every** cargo
  invocation in this repository; the table had no effect other than that
  warning. The workspace-root profile already covers both members.

## [1.0.0-alpha23] - 2026-08-02

### Changed

- Maintenance release — no notable changes since v1.0.0-alpha21.

## [1.0.0-alpha21] - 2026-07-30

### Added

- Add OIDC/SSO relying-party helpers (CONTRACT §12)

### Changed

- Re-sync vendored CONTRACT.md to contract 1.6
- Update base64 requirement from 0.22 to 0.23
- Update ed25519-dalek requirement from 2 to 3
- Update jsonwebtoken requirement from 10 to 11
- Bump coverallsapp/github-action from 2.3.7 to 2.3.8
- Bump taiki-e/install-action from 2.84.0 to 2.85.2
- Re-sync vendored CONTRACT.md to contract 1.5

### Fixed

- Publish the single-flight refresh outcome before vacating the slot
- Read axiam_refresh from its REFRESH_PATH-scoped URL, not base_url (H8 SDK bench)
- Disable aud validation in JwksVerifier::verify (H8 SDK bench)
- Share the single-flight oidc_refresh result (CONTRACT §9 rule 2)

## [Unreleased]

### ⚠ Breaking

This release is **source-breaking for downstream code that constructs
`AxiamError` variants with struct-expression syntax.** The earlier draft of
these notes described the §12 work as "additive, not breaking"; that was
wrong, and this section replaces it.

- **`AxiamError::Auth` gained two fields** (`oauth: Option<OAuthProtocolError>`
  and `reason: Option<IdTokenFailureReason>`) for CONTRACT.md §12.3 rule 3 and
  §12.4. Because the variant was not `#[non_exhaustive]`, that addition alone
  already broke downstream code: every `AxiamError::Auth { message: … }`
  construction became `E0063` (missing fields) and every exhaustive
  destructure `AxiamError::Auth { message }` became `E0027`. 33 constructions
  and 9 patterns inside this repository — including one in a shipped
  `examples/` file — had to be rewritten. Nothing prevented the same break
  recurring on the next field addition.
- **All three variants are now `#[non_exhaustive]`** (`Auth`, `Authz`,
  `Network`) so that no future field addition can break a consumer again. The
  cost is a one-time break, taken deliberately at `1.0.0-alpha18`:
  - **Constructing** a variant from outside this crate with struct-expression
    syntax is no longer possible (`E0639`). Use the constructors instead — the
    new `AxiamError::auth`, `AxiamError::authz`, `AxiamError::network`,
    `AxiamError::network_with_source`, alongside the existing
    `AxiamError::oauth_protocol_error`, `AxiamError::id_token_invalid`,
    `AxiamError::from_http_status` and `AxiamError::from_grpc_code`. They cover
    every shape the SDK itself builds.
  - **Destructuring** now requires a trailing `..`
    (`AxiamError::Auth { message, .. }`, `E0638` without it). Patterns that
    already ended in `..` — including every `matches!(e, AxiamError::Auth { .. })`
    — are unaffected.
  - The **enum itself is deliberately *not* `#[non_exhaustive]`**: CONTRACT.md
    §2 fixes the taxonomy at exactly three error types, so no fourth variant
    can ever be added and `match`ing all three exhaustively stays valid.
- **`AxiamClient::oidc_begin` now panics** instead of returning
  `Err(AxiamError::Network { .. })` when caller-supplied `extra_params` try to
  override one of the eight SDK-owned authorization query parameters. Per
  CONTRACT.md §12.1 rule 5 that is a programming error, not a §2 taxonomy
  outcome; every sibling SDK raises its language's unchecked
  programming-error type there, and a panic is Rust's equivalent. Correct code
  cannot trigger it — the condition depends only on parameter names the
  calling code chooses. Tenant/organization resolution failures remain
  `AxiamError::Auth` (§12.3 rule 4).
- **`AxiamClient::sso_complete` now fails** (with `AxiamError::Auth`) when the
  callback response sets no usable `axiam_access` cookie, where it previously
  returned `Ok`. This is the same behaviour `login()` has always had, and is
  required by the post-login session sync described under *Fixed* below.

### Added

- CONTRACT.md §12 OIDC/SSO relying-party helpers (contract 1.4): nine new
  methods directly on `AxiamClient` — `oidc_discover`, `oidc_begin`,
  `oidc_exchange`, `oidc_refresh`, `login_client_credentials`, `introspect`,
  `revoke`, `sso_start`, `sso_complete` — covering "Login with AXIAM"
  (authorization-code + PKCE, S256-only), service-account
  `client_credentials` login, RFC 7662 introspection, RFC 7009 revocation,
  and the upstream-IdP federation SSO pair. New module `src/oidc/`
  (`discovery`, `authorize`, `exchange`, `state`, `id_token`).
- Full CONTRACT.md §12.4 ID-token validation checklist (`EdDSA`-only,
  single-JWKS-refetch-on-unknown-`kid`, issuer/audience/time/nonce checks,
  all-or-nothing discard), extending the existing `JwksVerifier` rather than
  forking it.
- `OidcStateStore` trait + `MemoryOidcStateStore` reference implementation
  (10-minute TTL, single-use `consume`) for framework glue bridging the
  login-redirect and callback requests — strictly optional; the core
  operations remain stateless (§12.3 rule 1).
- `AxiamClientBuilder::oidc_client_id`/`oidc_client_secret`/
  `oidc_discovery_ttl`/`oidc_clock_skew` builder methods.
- `OAuthProtocolError`, a language-idiomatic sub-type of the existing
  `AxiamError::Auth` (carried via its new `oauth` field, not a new top-level
  error variant), for RFC 6749 `OAuth2ErrorResponse` bodies from
  `/oauth2/*`. `AxiamError::Auth` also gained a `reason: Option<IdTokenFailureReason>`
  field carrying the stable §12.4 reason code for ID-token validation
  failures. Existing `AxiamError::Auth { message, .. }` **matches** keep
  compiling and keep catching these as authentication failures; **constructions
  and exhaustive destructures do not** — see the ⚠ Breaking section above.
- Public `AxiamError` constructors — `auth`, `authz`, `network`,
  `network_with_source` — so downstream code can build the taxonomy variants
  without struct-expression syntax now that they are `#[non_exhaustive]`.
- `Clone` for `Sensitive<T>` (hand-written, not derived) and for
  `OidcTokenSet`. Required by CONTRACT.md §9 rule 2: the single in-flight
  `oidc_refresh` must hand the *same* token set to every concurrent waiter.
  Cloning duplicates the redacting wrapper, never the exposure — `Debug` and
  `Display` still redact on a clone, and `expose()` remains the one and only
  accessor. `Serialize`/`Deserialize` remain deliberately unimplemented.
- New example `examples/oidc_login.rs`.

### Fixed

- **`oidc_refresh` now satisfies CONTRACT.md §9 rule 2 (result sharing).** It
  previously took a bare `tokio::sync::Mutex<()>` with no result slot, so a
  burst of N concurrent callers produced **N serialized wire calls**; because
  AXIAM refresh tokens are single-use with rotation, callers 2..N replayed an
  already-consumed token and each failed `invalid_grant`. The mutex is
  replaced by a leader/waiter election over a shared publication — a
  `watch::Sender` carrying `Running | Settled(Result<OidcTokenSet,
  Arc<AxiamError>>) | Cancelled` (`src/oidc/single_flight.rs`): exactly one
  caller per burst performs the wire call and publishes its outcome, and every
  other caller receives *that* outcome — the same token set on success, an
  equivalent error (same taxonomy variant, same `oauth` payload, same `reason`)
  on failure. A cancelled leader publishes a typed `Cancelled` state and
  releases the slot rather than wedging the guard. No new dependency: `tokio`'s
  `sync` feature was already enabled. Covered by ≥5-caller burst tests for both
  the success and failure paths, each asserting exactly one request reaches the
  server.
- **`oidc_refresh`'s single-flight guard no longer has a publish/retire race
  that could issue a second, doomed `refresh_token` grant.** The guard's first
  implementation held a `tokio::sync::broadcast::Sender` and had to retire the
  in-flight slot *before* sending (a `broadcast` receiver never observes sends
  that predate its `subscribe`, so a caller subscribing after the send would
  have hung). That left the slot **empty while the refresh had already
  settled**: a concurrent caller landing there — no `.await` separates the two
  statements, but another runtime worker thread can — became a second leader
  and replayed the single-use refresh token the first leader had just consumed,
  failing `invalid_grant`. The slot now holds a *value-retaining*
  `tokio::sync::watch` publication, so **publication precedes vacating the
  slot**: a caller at any instant either joins the shared outcome or finds the
  slot empty with the refresh already settled and published, never "empty and
  nothing published". Occupancy alone no longer means "join this": a `Settled`
  publication is joinable (and cannot be stale — while it occupies the slot no
  later refresh can have been elected), a `Cancelled` one never is, and a
  caller arriving once the slot is empty still starts a genuinely fresh
  refresh rather than being handed the previous burst's tokens. Observable §9
  behaviour is unchanged: one wire call per burst, that outcome shared, no
  retry loop, and a cancelled leader still frees the slot and wakes its
  waiters (now with a typed cancellation signal instead of a channel-closed
  error).
- **`oidc_begin` now percent-encodes spaces as `%20`, not `+`.**
  `url::Url::query_pairs_mut` is an `application/x-www-form-urlencoded`
  serializer, so a multi-valued `scope` was emitted as
  `openid+profile+email`; CONTRACT.md §12.1 rule 5 requires literal RFC 3986
  encoding, which is what every other AXIAM SDK emits. The query component is
  now re-encoded before the URL is returned.
- **`sso_complete` now performs the post-login session sync.** It captured
  cookies and the CSRF token but never ran `absorb_session_cookies`, so it did
  not seed the token manager or resolve `tenant_id`/`org_id` — a subsequent
  `refresh()` failed with "no access token to refresh". It now runs the exact
  same sync `login()`/`verify_mfa()` do (CONTRACT.md §4/§3), leaving the client
  in an identical authenticated state.
- Removed an unreachable tenant-context guard in `sso_start`
  (`TenantIdentifier` is a two-variant enum and §5 guarantees one is set), and
  corrected the `compute_code_challenge` doc link, which pointed at
  `tests/oidc_pkce_test.rs` for the RFC 7636 Appendix B vector that actually
  lives in this module's own unit tests. `oidc::id_token::ID_TOKEN_ALG` is no
  longer a dead constant — it is the single definition of the wire spelling
  reported in the `invalid_alg` error.

### Changed

- `Sensitive::expose()` is now `pub` (previously `pub(crate)`): §12's
  `OidcTokenSet` hands `access_token`/`refresh_token`/`id_token` directly to
  the caller (unlike the §1 cookie-only session), so a relying party needs a
  way to read them back out to use them. Still the only path to the wrapped
  value; still never touched by `Debug`/`Display`.
- Conformance statement updated to "CONTRACT.md §1–§12 (including §6.1
  mTLS)".

## [1.0.0-alpha18] - 2026-07-24

### Changed

- Update syn requirement from 2 to 3 (#24)
- Bump dtolnay/rust-toolchain (#20)
- Bump taiki-e/install-action from 2.83.2 to 2.84.0 (#21)
- Bump actions/checkout from 7.0.0 to 7.0.1 (#22)
- Update rcgen requirement from 0.13 to 0.14 (#23)
- Rust SDK 89.3% → ≥92% + ratchet gate 89→90 (Phase C) (#26)

### Fixed

- Use CertifiedKey.signing_key for rcgen 0.14 API rename (#27)

## [1.0.0-alpha17] - 2026-07-22

### Changed

- Updated dependencies

## [1.0.0-alpha16] - 2026-07-22

### Added

- Add get_user_info (UserInfoGrpcClient)

### Changed

- Exclude generated gRPC stubs from the line-coverage gate
- Expand userinfo coverage above the 89% gate
- Vendor userinfo.proto + CONTRACT 1.3

## [Unreleased]

### Added

- gRPC `get_user_info` (`UserInfoGrpcClient`) — OIDC-style identity read over
  `axiam.v1.UserInfoService/GetUserInfo` (CONTRACT §1.1). Returns a `UserInfo`
  with `sub`/`tenant_id`/`org_id` and scope-gated `email`/`preferred_username`,
  reusing the shared `tonic::Channel`, auth/tenant interceptor, and
  single-flight refresh guard. Adopts CONTRACT.md 1.3.

## [1.0.0-alpha15] - 2026-07-21

### Changed

- Maintenance release — no notable changes since v1.0.0-alpha12.

## [1.0.0-alpha12] - 2026-07-19

### Fixed

- Supply organization context for login/refresh (CONTRACT §5.1) (#19)

## [1.0.0-alpha11] - 2026-07-18

### Changed

- Maintenance release — no notable changes since v1.0.0-alpha10.

## [1.0.0-alpha10] - 2026-07-18

### Changed

- Maintenance release — no notable changes since v1.0.0-alpha9.

## [Unreleased]

### Added

- **Client-certificate / mutual-TLS (mTLS) support (CONTRACT.md §6.1).** New
  builder method `AxiamClient::builder().with_client_cert(cert_pem, key_pem)`
  configures a PEM client-certificate chain + private key, applied to **both**
  transports: the REST client (`reqwest::Identity`) and any gRPC channel built
  from the same client via the new `AxiamClient::grpc_channel_config()` helper
  (`ClientTlsConfig::identity`). `GrpcChannelConfig` gains `client_cert_pem`
  and `client_key` fields for direct `grpc`-only configuration. The private key
  is retained behind `Sensitive<T>` and never exposed via any getter, `Debug`,
  or log output. Presenting a client certificate never relaxes server
  verification — strict TLS stays on (kept as a separate code path from
  `with_custom_ca`). Malformed cert/key PEM is rejected at construction time.
  The crate now states conformance to "§1–§10 (including §6.1 mTLS)".

## [1.0.0-alpha7] - 2026-07-17

### Fixed

- Build failure under Rust edition 2024 that broke the crates.io publish job:
  the generated gRPC stub module was declared `pub mod gen`, but `gen` is a
  reserved keyword in edition 2024, so the crate (and every `grpc`-feature
  consumer) failed to compile with "expected identifier, found reserved
  keyword `gen`". The module is now declared and referenced as the raw
  identifier `r#gen` (`axiam_sdk::grpc::r#gen`); the on-disk `src/gen/`
  generated-code path is unchanged.
- Clippy `collapsible_if` failure (denied by the CI clippy gate) surfaced by
  edition 2024 stabilising `let_chains`: the refresh-guard double-check now
  uses a single `if let … && …` let-chain. No behavioural change.

### Changed

- Reformatted the workspace with edition-2024 `rustfmt` style (import ordering)
  so `cargo fmt --check` passes under the crate's declared edition. Formatting
  only — no code or API changes.

## [1.0.0-alpha2] - 2026-07-16

### Added

- Declarative authorization helpers (CONTRACT.md §11), behind the new `macros`
  feature: the `#[require_access]`, `#[require_auth]` and `#[require_role]`
  Actix-Web attribute macros (from the new companion `axiam-sdk-macros` crate,
  re-exported as `axiam_sdk::…`), plus the programmatic `middleware::RequireAccess`
  guard and the `middleware::AuthzGuardError` / `resource_from_path` /
  `resource_from_static` / `require_role_check` building blocks. Checks are
  issued for the request's authenticated user (`subject_id`), fail closed on
  transport error (503), and cache no decisions.
- `AxiamClient::check_access_as(subject_id, action, resource_id, scope)` — the
  subject-aware access-check form used by the §11 helpers.
- Contract conformance statement raised to CONTRACT.md §1–§11.

## [1.0.0-alpha] - 2026-07-15

First alpha release of the official Rust client SDK for AXIAM. This is an
early, pre-production preview published to crates.io for evaluation and
feedback — the public API may still change before the beta and stable releases.

### Added

- REST client covering the AXIAM API surface (authentication, authorization
  checks, tenant/user/role/resource management).
- gRPC client for low-latency authorization checks (stubs generated at build
  time; no `protoc`/`proto/` needed by consumers).
- AMQP consumer support for async/deferred authorization decisions.
- Actix-Web route-guard integration.
- Strict TLS by default, with `with_custom_ca()` as the only opt-in escape
  hatch; no certificate-verification bypass surface.
- `Sensitive<T>` wrapper that keeps token/secret values out of debug output.
- Runnable examples: login + MFA, REST and gRPC access checks, AMQP consumer,
  and Actix route guard.

[1.0.0-alpha]: https://github.com/ilpanich/axiam-rust-sdk/releases/tag/v1.0.0-alpha
