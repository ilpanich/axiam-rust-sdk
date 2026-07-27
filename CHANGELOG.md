# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
  failures. Existing `AxiamError::Auth { message, .. }` matches keep
  compiling and keep catching these as authentication failures — additive,
  not breaking.
- New example `examples/oidc_login.rs`.

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
