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
check('srpAvailable() is true for this build', client.srpAvailable() === true);

// (2) Reproduce the contract vectors through the wasm boundary.
const vectorsPath = join(here, '..', '..', 'srp-test-vectors.json');
const vectors = JSON.parse(readFileSync(vectorsPath, 'utf8')).vectors;
check('vector file is non-empty', vectors.length > 0);

let verifierMismatches = 0;
for (const v of vectors) {
  const got = wasm.__conformanceVerifier(v.group, v.x);
  if (got !== v.verifier) {
    verifierMismatches += 1;
    console.error(`        ${v.group}/${v.identity}: expected ${v.verifier.slice(0, 24)}… got ${got.slice(0, 24)}…`);
  }
}
check(
  `all ${vectors.length} contract verifiers reproduce through wasm`,
  verifierMismatches === 0,
  verifierMismatches ? `${verifierMismatches} mismatch(es)` : '',
);

// (3) Enrolment produces well-formed, freshly-salted output.
const groups = { rfc5054_2048: 512, rfc5054_3072: 768, rfc5054_4096: 1024 };
for (const [group, verifierHexLen] of Object.entries(groups)) {
  const e = client.srpEnrollment('alice', 'hunter2', group, 'pbkdf2_sha256', 1000, null, null);
  check(`${group}: salt is 32 bytes`, e.salt.length === 64, `${e.salt.length} hex chars`);
  check(
    `${group}: verifier is padded to the group width`,
    e.verifier.length === verifierHexLen,
    `${e.verifier.length} hex chars`,
  );
  check(`${group}: kdf and group echo back`, e.group === group && e.kdf === 'pbkdf2_sha256');
}

const first = client.srpEnrollment('alice', 'hunter2', 'rfc5054_2048', 'pbkdf2_sha256', 1000, null, null);
const second = client.srpEnrollment('alice', 'hunter2', 'rfc5054_2048', 'pbkdf2_sha256', 1000, null, null);
check('each enrolment gets a fresh salt', first.salt !== second.salt);
check('a fresh salt yields a different verifier', first.verifier !== second.verifier);

// Argon2id runs too — the memory-hard path is the default, and a build where it
// silently failed would fall back to nothing.
const argon = client.srpEnrollment('alice', 'hunter2', 'rfc5054_2048', 'argon2id', 1, 8192, 1);
check('argon2id enrolment produces a verifier', argon.verifier.length === 512);
check('argon2id echoes its parameters', argon.memoryKib === 8192 && argon.parallelism === 1);

// (4) Refusals cross the boundary as Errors, not panics.
function refuses(label, fn) {
  try {
    fn();
    check(label, false, 'did not throw');
  } catch (err) {
    check(label, err instanceof Error, `threw ${typeof err}`);
  }
}
refuses('an unknown group is refused', () =>
  client.srpEnrollment('a', 'b', 'rfc5054_1024', 'pbkdf2_sha256', 1000, null, null),
);
refuses('an unknown KDF is refused', () =>
  client.srpEnrollment('a', 'b', 'rfc5054_2048', 'scrypt', 1000, null, null),
);
refuses('argon2id without its parameters is refused', () =>
  client.srpEnrollment('a', 'b', 'rfc5054_2048', 'argon2id', 1, null, null),
);
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
