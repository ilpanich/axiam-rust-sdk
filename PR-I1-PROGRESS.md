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
- [ ] 3. Re-vendor from `56fbe44` + regenerate §27; CertificateType decodes openly (+ test)
- [ ] 4. Acting tenant (§5.2 rule 1)
- [ ] 5. `authenticate_device()` (§6.1 rules 6–10) + `examples/device_mtls_login.rs`
- [ ] 6. gRPC `validate_token` / `introspect_token` (§1.1.1, §10.3)
- [ ] 7. JwksVerifier and `cnf` (§10.1 rule 9)
- [ ] 8. Manifest (§27.6.1, §27.5 rule 5, §27.9 tests)
- [ ] 9. README conformance, CHANGELOG, full CI suite locally
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

_none_
