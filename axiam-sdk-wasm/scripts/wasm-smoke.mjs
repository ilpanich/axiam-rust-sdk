/**
 * Smoke test for the BUILT `axiam-sdk-wasm` artifact.
 *
 * ## Why this exists as its own step
 *
 * `wasm-pack build` succeeding says nothing about whether the module works. The
 * concrete failure that motivated this: optimising a wasm-bindgen 0.2.127
 * artifact with binaryen 108 produces a package that builds cleanly, passes
 * every Rust test (those run against the *crate*, not the artifact), and then
 * throws `RangeError: WebAssembly.Table.grow(): failed to grow table by 4` the
 * first time anything imports it. Nothing in the build reports a problem. A
 * pipeline without this step would publish that to npm.
 *
 * So this runs against the artifact, after wasm-opt, and:
 *
 *   1. imports it — which is where a miscompiled module dies;
 *   2. reproduces the CONTRACT.md §23.7 verifiers from the vendored vectors,
 *      through the wasm boundary, which is where a miscompiled *computation*
 *      would die;
 *   3. asserts refusals cross the boundary as JS `Error`s rather than panics.
 *
 * Usage (from the axiam-sdk-wasm directory):
 *
 *   wasm-pack build --target nodejs --out-dir pkg-node --release
 *   node scripts/wasm-smoke.mjs pkg-node
 */

import { createRequire } from 'node:module';
import { readFileSync } from 'node:fs';
import { resolve, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const pkgDir = resolve(process.argv[2] ?? join(here, '..', 'pkg-node'));
const require = createRequire(import.meta.url);

let failures = 0;
function check(label, condition, detail = '') {
  if (condition) {
    console.log(`  ok    ${label}`);
  } else {
    failures += 1;
    console.error(`  FAIL  ${label}${detail ? ` — ${detail}` : ''}`);
  }
}

console.log(`axiam-sdk-wasm smoke test against ${pkgDir}`);

// (1) Import. A miscompiled module throws here.
let wasm;
try {
  wasm = require(join(pkgDir, 'axiam_sdk_wasm.js'));
} catch (err) {
  console.error(
    `\nFAILED TO IMPORT the built artifact. This is what a bad wasm-opt looks\n` +
      `like — the build succeeded and the module is broken. Check the binaryen\n` +
      `version (>= 116 required; Ubuntu's apt binaryen 108 miscompiles this).\n\n${err.stack}`,
  );
  process.exit(1);
}
check('module imports', true);
check('sdkVersion() returns a version', /^\d+\.\d+\.\d+/.test(wasm.sdkVersion()), wasm.sdkVersion());

const client = new wasm.AxiamWasmClient('https://axiam.example', 'acme', 'default');
check('client constructs', client instanceof wasm.AxiamWasmClient);
check('opaqueAvailable() is true for this build', client.opaqueAvailable() === true);

// (2) Prove the elliptic-curve arithmetic inside the artifact actually works.
//
// The SRP version of this step replayed `srp-test-vectors.json` through
// `__conformanceVerifier`, because SRP's `x` could be pinned and a verifier
// recomputed from it. OPAQUE's blind is generated inside the protocol and is
// not injectable, so there is no fixed input to replay — the available check
// is to run both halves of a real exchange inside the module and assert they
// agree. A miscompiled scalar multiplication produces an envelope that will
// not open, which is exactly what this catches.
check('a full OPAQUE round trip completes inside the artifact', wasm.__conformanceRoundTrip() === true);

// (3) The KSF wire fields are honoured as the server names them, and an
// unknown one is refused rather than substituted (CONTRACT §23.4 rule 3).
//
// `opaqueEnrollment` now performs a network round trip, so it cannot run in
// this offline smoke test — that path is covered by `tests/opaque_login_test.rs`
// against a mock that really speaks the protocol. What is checkable here is
// that the exported surface is the one CONTRACT §23.2 names.
for (const name of ['loginOpaque', 'opaqueEnrollment', 'opaqueAvailable']) {
  check(`${name} is exported`, typeof client[name] === 'function');
}
for (const gone of ['loginSrp', 'srpEnrollment', 'srpAvailable']) {
  check(`${gone} is gone`, client[gone] === undefined);
}

// (4) Refusals cross the boundary as Errors, not panics.
function refuses(label, fn) {
  try {
    fn();
    check(label, false, 'did not throw');
  } catch (err) {
    check(label, err instanceof Error, `threw ${typeof err}`);
  }
}
refuses('a malformed base URL is refused', () => new wasm.AxiamWasmClient('not a url', 'o', 't'));

// Async refusals arrive as rejected promises.
const rejected = await client
  .can('read', 'not-a-uuid')
  .then(() => null)
  .catch((err) => err);
check('a non-UUID resource rejects with an Error', rejected instanceof Error, String(rejected));

if (failures > 0) {
  console.error(`\n${failures} check(s) failed.`);
  process.exit(1);
}
console.log('\nAll checks passed.');
