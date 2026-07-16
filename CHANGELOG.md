# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
