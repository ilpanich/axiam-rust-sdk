# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
