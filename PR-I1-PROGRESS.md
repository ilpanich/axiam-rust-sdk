# PR I₁ — C-1, Rust SDK reference implementation of contract 1.51

Ledger for a session that may be interrupted by the usage limit. One line per
step; ticked and pushed the moment a step is done. Deleted in the final commit.

- Branch: `feat/contract-1.51`, cut from `main` @ `7d27160`.
- Vendored artefacts: axiam `56fbe44` (merge of #497, contract 1.51).
  Verified 2026-09-24: `origin/main` of axiam **is** `56fbe44`; CONTRACT.md
  sha256 `0ac7fd75f83c…`, footer "Contract version: 1.51".
- Resume check-ins (send_later): `trig_01JZEaKpiwyyNDQrrJ5g8U63` (11:17Z),
  `trig_01RexJZvWHMvyJqwewL1Gn33` (15:17Z), armed 2026-09-24 05:16Z.

## Steps

- [x] 1. SAGE boot — **not connected** in this session (no `sage_*` tools exist); continued without it
- [x] 2. Read CLAUDE.md, README conformance, CHANGELOG, every CI workflow; record CI commands below
- [x] 3. Re-vendor from `56fbe44` + regenerate §27; CertificateType decodes openly (+ test) — CONTRACT/openapi/registry byte-match `56fbe44`, proto already identical; generator taught externally-tagged `oneOf` (SubjectAltName was an empty struct) and `inherit` absent→true; `tests/contract_151_models_test.rs` (8); full suite 938/0
- [x] 4. Acting tenant (§5.2 rule 1) — handle-scoped `with_acting_tenant` / `acting_tenant` / `clear_acting_tenant`; gated on a held login result; memo keyed on it; `tests/acting_tenant_test.rs` (9); suite 947/0
- [x] 5. `authenticate_device()` (§6.1 rules 6–10) + `examples/device_mtls_login.rs` — runtime gate (AuthError, zero wire) rather than a typestate, reason in the commit; token adopted as a bearer with the jar withheld; 401 never refreshes; `tests/device_auth_test.rs` (8); suite 956/0
- [x] 6. gRPC `validate_token` / `introspect_token` (§1.1.1, §10.3) — `grpc::TokenGrpcClient`; rule-9 table moved onto `CnfClaim::verify` (one implementation for local and gRPC); `tests/grpc_token_test.rs` (8); suite 964/0
- [x] 7. JwksVerifier and `cnf` (§10.1 rule 9) — **bug fixed**: `verify()` (the `AxiamUser` guard) accepted bound tokens as bearer; now refuses them without evidence; `verify_with_proofs`; `middleware::PeerCertificate` via `on_connect`; the test that pinned the defect is inverted, not relaxed; `tests/actix_bound_token_test.rs` (2) + 3 new in `local_verification_set_test`; suite 968/0
- [x] 8. Manifest (§27.6.1, §27.5 rule 5, §27.9 tests) — `ResourceSpec.metadata`, `RoleBinding` (two shapes), `ServiceAccountSpec`, `Outcome::{CreatedServiceAccount, BindingUpdateFailed}`, `manifest!` statements; `tests/manifest_additions_test.rs` (13, stateful fake tenant); six mutations caught; suite 982/0
- [x] 9. README conformance, CHANGELOG, full CI suite locally — every `sdk-ci-rust.yml` job run here:
  fmt ✓, clippy -D warnings ✓, build/test all-features stable 985/0 ✓ and MSRV 1.88 982/0 ✓
  (before the last 3 tests), doc -D warnings ✓, examples (stable + 1.88) ✓, leak gate ✓,
  TLS-lint ✓, `--features grpc` ✓, macros publish dry-run ✓, §27.8 drift ✓, wasm32 check ✓,
  wasm-pack web/bundler/nodejs + `wasm-smoke.mjs` ✓ (wasm-pack 0.15.0 via npm), buf 1.50.0
  lint/format/breaking ✓ (via npm), `cargo audit` ✓ (0 findings; yank check could not reach
  the index: 503), coverage 92.08 % lines ≥ 90 ✓ (`manifest/builder.rs` raised to 100 %)
- [ ] 10. PR opened, subscribed, green
- [ ] 11. Fan-out row, ambiguities for C-12, prompt for C-2 … C-11

## CI commands (step 2)

The repository has **no CLAUDE.md**. CI is `.github/workflows/sdk-ci-rust.yml`
(PR jobs), plus `rust-clippy.yml` (SARIF, `continue-on-error`) and
`coverage.yml` (floor 90 % lines).

| Job | Command (as CI runs it) |
|---|---|
| scaffold | `test -f LICENSE` |
| proto-lint | `buf lint`; `buf format --diff --exit-code`; `buf breaking --against '.git#branch=origin/main'` |
| wasm | `RUSTFLAGS='--cfg getrandom_backend="wasm_js"' cargo check --lib --target wasm32-unknown-unknown --no-default-features --features rest,opaque`; `wasm-pack build` ×3 in `axiam-sdk-wasm`; `node scripts/wasm-smoke.mjs pkg-node` |
| test (1.88 + stable) | `cargo fmt --all --check` (stable); `cargo clippy --all-targets --all-features -- -D warnings` (stable); `cargo build --all-features`; `cargo test --all-features`; `RUSTDOCFLAGS=-D warnings cargo doc --all-features --no-deps`; `cargo audit --ignore RUSTSEC-2023-0071` (stable); `cargo build --examples --all-features`; leak gate `grep -r 'eyJ' target/debug/`; TLS-lint grep over `src/`; `cargo build --features grpc`; `cd axiam-sdk-macros && cargo publish --dry-run --all-features --allow-dirty` |
| §27.8 drift | `python3 tools/gen_management.py --check` |
| coverage | `cargo llvm-cov --all-features --ignore-filename-regex 'gen/axiam\.v1\.rs'` then `--fail-under-lines 90` |

Conformance: the README's "Contract conformance" section (currently "contract 1.50").
Local toolchain: cargo/rustc 1.94.1 present; `protoc`, `buf`, `wasm-pack`, `cargo-audit` absent at first look (to be searched for twice before any claim).

## Half-done state / notes

- Found, not fixed (pre-existing on `main`, out of scope):
  `cargo build --no-default-features --features grpc` fails, because
  `pub mod management` is ungated in `lib.rs` while `client` needs `rest`.
  CI never builds `grpc` without `rest`.
- Found, not built (pre-existing): §27.7 lists `#[derive(AxiamSpec)]` for
  Rust; this SDK has never shipped it (only `manifest!`). Not in C-1's scope.
