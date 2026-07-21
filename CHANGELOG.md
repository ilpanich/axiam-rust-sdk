# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
