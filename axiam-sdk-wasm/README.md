# axiam-sdk-wasm

The AXIAM Rust SDK, compiled to WebAssembly and published to npm.

```bash
npm install axiam-sdk-wasm
```

```js
import init, { AxiamWasmClient } from "axiam-sdk-wasm";

await init();                                   // loads the .wasm module

const client = new AxiamWasmClient(
  "https://axiam.example",                      // base URL
  "acme",                                       // organization slug
  "default",                                    // tenant slug
);

// OPAQUE login — the password never leaves the browser.
await client.loginOpaque("alice", "correct horse battery staple");

if (await client.can("documents:read", "3f8a…-uuid")) {
  renderDocument();
}
```

## Which package do I want?

This is **not** a replacement for [`axiam-sdk`](https://www.npmjs.com/package/axiam-sdk),
the TypeScript SDK. They are different trade-offs:

| | `axiam-sdk` (TypeScript) | `axiam-sdk-wasm` (this) |
|---|---|---|
| Payload | ~40 KB gzipped | ~540 KB gzipped |
| Transports | REST, gRPC-web, AMQP | REST only |
| Types | native `.d.ts` | generated `.d.ts` |
| Tree-shakes | yes | no — wasm is one blob |
| Shares code with | itself | the Rust server and SDK |

Reach for this one when you want the *same* implementation the Rust SDK and
the AXIAM server run — the OPAQUE implementation, the JWKS verifier, the decision memo
are literally the same compiled code, not a second implementation that has to be
kept in agreement. Reach for the TypeScript SDK when payload size matters, which
for most web applications it does.

## What is in it

Everything the Rust SDK's REST surface offers:

- `login`, `loginOpaque`, `verifyMfa`, `refresh`, `logout`
- `checkAccess`, `can`, `batchCheck` (with the client-side decision memo)
- `opaqueEnrollment`, `opaqueAvailable`
- local JWKS verification and the §12 OIDC relying-party helpers

## What is not, and why

| Missing | Reason |
|---|---|
| gRPC | A browser has no sockets |
| AMQP, the reactor runtime | Same |
| Actix middleware / route guards | They guard a server; there is no server here |
| mTLS (`with_client_cert`) | The browser picks the client certificate, not page script |
| Custom CA roots (`with_custom_ca`) | The browser owns the trust store |
| Request timeouts, redirect policy | `fetch` exposes neither |

The two capabilities a caller could plausibly *ask* for and silently not get —
mTLS and custom CA — return a typed error rather than being ignored, so a
misconfiguration is visible rather than a security assumption that quietly does
not hold.

## Cookies, CORS, and sessions

Tokens arrive as `HttpOnly` cookies and the browser stores them. That is
**stronger** than the native SDK's in-process jar, where `HttpOnly` means
nothing: page script, including this module, genuinely cannot read them.

The consequence is a CORS requirement. Either serve your application
same-origin with the AXIAM API, or configure the API to send
`Access-Control-Allow-Credentials` for your origin. A cross-origin request
without credentials carries no session and every call 401s — which looks like a
broken login and is actually a CORS configuration.

## OPAQUE in a browser: the honest limit

`loginOpaque` keeps the password inside the wasm module. A TLS-terminating proxy,
an accidentally verbose access log, or a server-side heap dump never sees it,
because the server never has it.

It does **not** protect you against a compromised AXIAM server. That server also
serves the page that loads this module, and could serve one that posts the
password instead. Browser OPAQUE defends against the infrastructure between you and
AXIAM, not against AXIAM. Do not tell your users otherwise.

### It blocks

`loginOpaque` runs the tenant's KDF — Argon2id at 19 MiB by default. That is tens
to hundreds of milliseconds of synchronous work, and the cost is the point: it
is what makes a stolen verifier expensive to attack offline. In a page that must
stay responsive, run this module in a Web Worker.

## Building from source

```bash
cd axiam-sdk-wasm
wasm-pack build --target web    --out-dir pkg-web    --release
wasm-pack build --target bundler --out-dir pkg-bundler --release
wasm-pack build --target nodejs --out-dir pkg-node   --release

# Always run this against what you built:
node scripts/wasm-smoke.mjs pkg-node
```

The smoke test is not optional ceremony. It imports the built artifact and
runs a complete OPAQUE exchange *through* it, because "wasm-pack
succeeded" is not evidence that the module works — see the `wasm-opt` note in
`Cargo.toml` for the concrete case where it built cleanly and was broken.

`getrandom` needs a build flag for the browser CSPRNG:

```bash
RUSTFLAGS='--cfg getrandom_backend="wasm_js"' wasm-pack build …
```

## Versioning

This package's version tracks `axiam-sdk` exactly. `sdkVersion()` reports the
version of the crate actually compiled into the artifact you loaded, rather than
a build-time constant that could drift from it.

## Conformance

This SDK conforms to CONTRACT.md §1–§10 and §23, minus the sections that require
a transport a browser does not have (§8b AMQP, §10.2/§10.3 gRPC, §22 reactors).
