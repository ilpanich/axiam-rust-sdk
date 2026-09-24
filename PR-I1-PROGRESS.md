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

- [ ] 1. SAGE boot
- [ ] 2. Read CLAUDE.md, README conformance, CHANGELOG, every CI workflow; record CI commands below
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

_to be filled_

## Half-done state / notes

_none_
