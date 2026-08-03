# axiam-sdk (Rust)

[![SDK CI — Rust](https://github.com/ilpanich/axiam-rust-sdk/actions/workflows/sdk-ci-rust.yml/badge.svg)](https://github.com/ilpanich/axiam-rust-sdk/actions/workflows/sdk-ci-rust.yml)
[![Coverage Status](https://coveralls.io/repos/github/ilpanich/axiam-rust-sdk/badge.svg?branch=main)](https://coveralls.io/github/ilpanich/axiam-rust-sdk?branch=main)
[![crates.io](https://img.shields.io/crates/v/axiam-sdk.svg)](https://crates.io/crates/axiam-sdk)
[![docs.rs](https://docs.rs/axiam-sdk/badge.svg)](https://docs.rs/axiam-sdk)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

Official Rust client SDK for [AXIAM](https://github.com/ilpanich/axiam) — Access eXtended Identity and Authorization Management.

## Package identity

- **Crate:** `axiam-sdk`
- **Repository:** [github.com/ilpanich/axiam-rust-sdk](https://github.com/ilpanich/axiam-rust-sdk)
- **Registry:** [crates.io/crates/axiam-sdk](https://crates.io/crates/axiam-sdk) _(reserved, not yet published)_
- **API docs:** [docs.rs/axiam-sdk](https://docs.rs/axiam-sdk) — built automatically by docs.rs on each release
- **License:** Apache-2.0
- **MSRV:** Rust 1.88 (`rust-version = "1.88"` in `Cargo.toml`, enforced in CI)

## Contract conformance

This SDK conforms to CONTRACT.md §1–§13 (including §6.1 mTLS and §13 webhook signature
verification).

See [`CONTRACT.md`](CONTRACT.md) for the full cross-language behavioral contract. It is shared
verbatim across all seven AXIAM SDKs; the copy in this repository is the authority for this
crate's behaviour.

## Features

`axiam-sdk`'s functionality is split into Cargo features so a consumer only pulls in the
dependencies for the transports/integrations it actually uses:

| Feature | Default | Enables |
|---------|---------|---------|
| `rest` | on | `AxiamClient` REST transport: `login`/`verify_mfa`/`refresh`/`logout`, `check_access`/`can`/`batch_check`, cookie-jar session management, local JWKS/EdDSA verification, and the CONTRACT.md §12 OIDC/SSO relying-party helpers (`oidc_discover`, `oidc_begin`, `oidc_exchange`, `oidc_refresh`, `login_client_credentials`, `introspect`, `revoke`, `sso_start`, `sso_complete`) |
| `grpc` | on | `AuthzGrpcClient` gRPC transport: `check_access`/`batch_check`; `UserInfoGrpcClient` gRPC `get_user_info` (OIDC identity read, CONTRACT §1.1) — both over a shared lazily-connected `tonic::Channel`, with the shared single-flight refresh guard driven on `UNAUTHENTICATED` |
| `amqp` | on | `consume(amqp_url, queue, signing_key, handler)` closure-handler AMQP consumer with mandatory pre-handler HMAC-SHA256 verification (CONTRACT.md §8) |
| `observability` | off | Enables `tracing` instrumentation crate-wide beyond the mandatory AMQP security-event logging (which is always emitted regardless of this flag) |
| — | — | `webhook::verify_webhook` (CONTRACT.md §13) has no feature of its own: it is compiled whenever `rest` **or** `amqp` is on, since both already vendor its `hmac`/`sha2`/`hex`/`subtle` inputs. With the default feature set it is always available |
| `actix` | off | The `AxiamUser` Actix-Web `FromRequest` extractor (CONTRACT.md §10 route guard). Implies `rest` (shares the same `JwksVerifier`) |
| `macros` | off | The `#[require_access]` / `#[require_auth]` / `#[require_role]` declarative authorization attribute macros (CONTRACT.md §11), plus the programmatic `middleware::RequireAccess` guard. Implies `actix` |

To build a REST-only client (no gRPC, no AMQP), disable the default feature set and opt back
into just `rest`:

```toml
[dependencies]
axiam-sdk = { version = "0.1", default-features = false, features = ["rest"] }
```

## Usage

```toml
[dependencies]
axiam-sdk = "0.1"
```

Each capability below has a complete, runnable example under [`examples/`](examples/) — they
are illustrative/compilable (reading connection details from environment variables) and do not
require a live AXIAM server to `cargo build --examples --all-features`.

### Login + MFA (`rest`)

Construct a client with a non-optional tenant identifier (CONTRACT.md §5 — there is no default
tenant) plus the organization identifier login/refresh require (CONTRACT.md §5.1 — a tenant slug
is only unique within an organization), then complete the two-phase login/MFA flow:

```rust,no_run
use axiam_sdk::client::AxiamClient;

# async fn run() -> Result<(), Box<dyn std::error::Error>> {
let client = AxiamClient::builder()
    .base_url("https://axiam.example.com")?
    .tenant_slug("acme")
    .org_slug("acme")
    .build()?;

let login_result = client.login("user@example.com", "password").await?;
if login_result.mfa_required {
    client.verify_mfa("123456").await?;
}
# Ok(())
# }
```

See [`examples/login_mfa.rs`](examples/login_mfa.rs).

### REST authorization checks (`rest`)

```rust,no_run
# use axiam_sdk::client::AxiamClient;
# async fn run(client: &AxiamClient, resource_id: uuid::Uuid) -> Result<(), Box<dyn std::error::Error>> {
let decision = client.check_access("resource:read", resource_id, None).await?;
let allowed = client.can("resource:write", resource_id, None).await?;
# Ok(())
# }
```

See [`examples/rest_check_access.rs`](examples/rest_check_access.rs).

### gRPC authorization checks (`grpc`)

```rust,no_run
use axiam_sdk::grpc::{build_channel, GrpcChannelConfig};

# fn run() -> Result<(), Box<dyn std::error::Error>> {
let channel = build_channel("https://axiam.example.com:9443", &GrpcChannelConfig::default())?;
# Ok(())
# }
```

See [`examples/grpc_check_access.rs`](examples/grpc_check_access.rs) for the full
`AuthzGrpcClient` wiring, including the single-flight refresh guard (§9).

### OIDC / SSO relying-party helpers (`rest`)

CONTRACT.md §12 adds nine operations for "Login with AXIAM" (authorization-code + PKCE against
AXIAM's own OIDC provider), service-account `client_credentials` login, token
introspection/revocation, and the upstream-IdP federation pair — all as methods directly on
[`AxiamClient`], configured with an OIDC `client_id`/`client_secret` on the same builder used for
everything else:

```rust,no_run
use axiam_sdk::client::AxiamClient;
use axiam_sdk::oidc::OidcBeginParams;

# async fn run() -> Result<(), Box<dyn std::error::Error>> {
let client = AxiamClient::builder()
    .base_url("https://axiam.example.com")?
    .tenant_id("11111111-2222-3333-4444-555555555555".parse().unwrap())
    .oidc_client_id("my-app")
    .oidc_client_secret("my-app-secret") // omit for a public client
    .build()?;

// 1. redirect the user agent
let configuration = client.oidc_discover().await?;
let request = client.oidc_begin(&configuration, OidcBeginParams::new("https://app.example.com/cb"))?;
// …persist request.state / request.nonce / request.code_verifier in YOUR OWN session…

// 2. on the callback, having checked the returned `state` matches
// let tokens = client.oidc_exchange(OidcExchangeParams { code, code_verifier: request.code_verifier, nonce: request.nonce, redirect_uri: "https://app.example.com/cb".into(), tenant_id: None, configuration: Some(configuration) }).await?;
# Ok(())
# }
```

**The nine operations** (CONTRACT.md §12.2 Rust naming):

| Operation | What it does |
|-----------|--------------|
| `oidc_discover` | `GET /.well-known/openid-configuration`, cached per origin (≥5 min TTL) with single-flight de-duplication |
| `oidc_begin` | Pure, local PKCE (S256-only) + `state`/`nonce` generation and authorization-URL construction — **no network I/O** |
| `oidc_exchange` | `grant_type=authorization_code` — exchanges a code for an [`oidc::OidcTokenSet`], validating any `id_token` against the full §12.4 checklist before returning it |
| `oidc_refresh` | `grant_type=refresh_token`, under a §9-conformant single-flight guard dedicated to the OAuth2 token namespace (§9 rule 5): a burst of N concurrent callers makes **exactly one** wire call and every caller receives *that* call's outcome (§9 rule 2). Distinct from and never merged with the §1 `refresh()` cookie-session path |
| `login_client_credentials` | `grant_type=client_credentials` — service-account machine-to-machine login |
| `introspect` | `POST /oauth2/introspect` (RFC 7662) — requires a confidential client |
| `revoke` | `POST /oauth2/revoke` (RFC 7009) — idempotent; requires a confidential client |
| `sso_start` | `POST /api/v1/auth/federation/oidc/start` — step 1 of upstream-IdP SSO |
| `sso_complete` | `POST /api/v1/auth/federation/oidc/callback` — step 2; the session arrives via `Set-Cookie` through the same §4 cookie jar every other REST call uses, and the same post-login sync `login()` runs seeds the token manager and resolves `tenant_id`/`org_id`, so `refresh()`/`logout()` work straight afterwards |

**The caller owns the login state (§12.3 rule 1).** `oidc_begin` returns `state`, `nonce` and
`code_verifier`; this SDK stores none of them. Persist all three yourself (your own HTTP session,
a database row, …) between the login redirect and the callback, or use
[`axiam_sdk::oidc::MemoryOidcStateStore`] — a ready single-process, single-use, 10-minute-TTL
reference implementation of [`axiam_sdk::oidc::OidcStateStore`] — and pass `nonce` +
`code_verifier` back into `oidc_exchange` when the code arrives. See
[`examples/oidc_login.rs`](examples/oidc_login.rs) for the full two-step flow.

The five §12.5 secret fields — `access_token`, `refresh_token`, `id_token`, `client_secret`,
`code_verifier` — are all [`Sensitive<String>`](#security-notes); `state` and `nonce` are **not**
secrets and are plain `String`s. ID-token validation is `EdDSA`-only (rejecting `alg: none` and
every other algorithm outright) and all-or-nothing: on any failure the whole token set —
including the access and refresh tokens from the same response — is discarded and an `AuthError`
carrying one of `invalid_alg`/`unknown_kid`/`invalid_signature`/`invalid_issuer`/
`invalid_audience`/`token_expired`/`nonce_mismatch` is raised.

### AMQP consumer (`amqp`)

```rust,no_run
use axiam_sdk::amqp::consume;
use axiam_sdk::Sensitive;

# async fn run(signing_key: Sensitive<Vec<u8>>) -> Result<(), Box<dyn std::error::Error>> {
consume("amqp://guest:guest@localhost:5672", "axiam.authz.request", signing_key, |event| async move {
    println!("verified event: {event}");
})
.await?;
# Ok(())
# }
```

See [`examples/amqp_consumer.rs`](examples/amqp_consumer.rs). Every delivery's HMAC-SHA256
signature (CONTRACT.md §8) is verified before the handler runs; failures are nacked without
requeue.

### Actix-Web route guard (`actix`)

```rust,no_run
use axiam_sdk::middleware::AxiamUser;

async fn protected(user: AxiamUser) -> String {
    format!("hello {}", user.user_id)
}
```

See [`examples/actix_route_guard.rs`](examples/actix_route_guard.rs).

### Declarative authorization helpers (`macros`)

The `macros` feature adds the CONTRACT.md §11 *declarative authorization
helpers* — attribute macros that place a per-endpoint AXIAM permission check
directly on an Actix-Web handler, layered on top of the §10 `AxiamUser`
extractor. They run strictly **after** authentication and issue the check for
the **request's** authenticated user (`subject_id = user.user_id`), so the
app's own (usually service-account) `AxiamClient` session is never mistaken for
the end user.

Register a `web::Data<AxiamClient>` (used to issue the check) and a
`web::Data<JwksVerifier>` (used by the extractor) as app data, then annotate
handlers:

```rust,ignore
use axiam_sdk::{require_access, require_auth, require_role};
use axiam_sdk::middleware::AxiamUser;

// Require a `read` check on the `{id}` path resource. The handler may still
// take its own `AxiamUser` to use the identity in the body.
#[require_access(action = "read", resource_param = "id")]
async fn get_document(user: AxiamUser) -> String {
    format!("user {} may read this document", user.user_id)
}

// Require an authenticated identity (no resource check).
#[require_auth]
async fn whoami() -> &'static str {
    "authenticated"
}

// Local, no-round-trip role check (not a substitute for require_access).
#[require_role("admin")]
async fn admin_panel() -> &'static str {
    "welcome, admin"
}
```

`#[require_access]` also accepts `resource_id = "<uuid>"` (a static singleton
resource), `resolver = path::to::fn` (a
`fn(&HttpRequest) -> Result<Uuid, AuthzGuardError>` for body/header/composite
lookups), and an optional `scope = "…"` passed through verbatim. Errors map to
the standardized `{ "error", "message" }` JSON body: 401 `authentication_failed`
(unauthenticated), 403 `authorization_denied` (denied), 400 `invalid_request`
(unresolvable resource id), and 503 `authz_unavailable` (transport failure —
**fail closed**, never allow on error). No decision is cached.

For handlers that don't fit the attribute shape, the same logic is available
programmatically via `middleware::RequireAccess`:

```rust,ignore
use axiam_sdk::middleware::RequireAccess;

RequireAccess::new("read")
    .scope("confidential")
    .check(&client, &user, resource_id)
    .await?;
```

See [`examples/actix_route_guard.rs`](examples/actix_route_guard.rs).

### Webhook signature verification (`rest` or `amqp`)

AXIAM signs every webhook delivery with a Stripe-style signed timestamp:
`X-Axiam-Signature: t=<unix_seconds>,v1=<hex>`, where
`v1 = HMAC-SHA256(secret, "<t>.<raw_body>")`. `verify_webhook` recomputes the
MAC, compares it in constant time, and applies a two-sided 300-second freshness
window (CONTRACT.md §13).

```rust,ignore
use actix_web::{HttpRequest, HttpResponse, web};
use axiam_sdk::Sensitive;
use axiam_sdk::webhook::{WebhookVerifyOptions, verify_webhook};

async fn receive(req: HttpRequest, body: web::Bytes) -> HttpResponse {
    let secret = Sensitive::new(std::env::var("AXIAM_WEBHOOK_SECRET").unwrap());
    let header = |n: &str| req.headers().get(n).and_then(|v| v.to_str().ok()).unwrap_or("");

    let opts = WebhookVerifyOptions::new()
        .event_type(header("X-Axiam-Event"))
        .delivery_id(header("X-Axiam-Delivery"))
        .timestamp_header(header("X-Axiam-Timestamp"));

    // `body` is the UNPARSED request body — see the warning below.
    match verify_webhook(&secret, header("X-Axiam-Signature"), &body, &opts) {
        Ok(event) => {
            if already_seen(event.delivery_id) {
                return HttpResponse::Ok().finish(); // at-least-once retry
            }
            let payload: serde_json::Value = serde_json::from_slice(event.body).unwrap();
            let _ = payload;
            HttpResponse::Ok().finish()
        }
        // Never echo the error back to the sender.
        Err(_) => HttpResponse::Unauthorized().finish(),
    }
}
```

> **⚠ Pass the raw body bytes.** `verify_webhook` takes `&[u8]` deliberately.
> Parsing the body into JSON and re-serializing it changes key order and
> whitespace, so the recomputed MAC covers different bytes than the server
> signed and **every genuine delivery is rejected**. Capture the untouched body
> (`web::Bytes`, `axum::body::Bytes`, `hyper::body::to_bytes`, …), verify, then
> parse.

> **Deliveries are at-least-once.** A retry replays a *valid* signature inside
> the freshness window, so a successful verification does not mean a new event.
> `X-Axiam-Delivery` is the dedup key — keep a short-lived seen-set.

The `tolerance` (default 300 s) and a `now` injection seam for tests are both on
`WebhookVerifyOptions`.

## Security notes

- **`Sensitive<T>`** (§7): all token-carrying values redact their raw contents from `Debug`
  and `Display`. The raw value is reachable only via the documented `expose()` accessor, which
  exists because CONTRACT.md §12's `OidcTokenSet` (unlike the §1 cookie-only session) hands
  tokens directly to the caller in the OAuth2 response body — a relying party must be able to
  read them back out to use them (e.g. as a downstream `Authorization` header). Never pass its
  return value to a log/`Debug`/serialization sink.
- **TLS** (§6): strict TLS verification against the system trust store is always on. The only
  escape hatch is `with_custom_ca(pem)` for development environments with self-signed
  certificates — there is no API surface that disables or skips certificate verification.

### mTLS / client certificates (§6.1)

AXIAM can authenticate IoT devices and service accounts by **mutual TLS**: the client presents
an X.509 identity certificate (signed by the tenant's organization CA) that the server binds to
a service account. Configure it with `with_client_cert(cert_pem, key_pem)` — a PEM certificate
**chain** plus a PEM private key (PKCS#8 or PKCS#1). The identity is applied to **both** the REST
transport and any gRPC channel built from the same client. Presenting a client certificate never
relaxes server verification — strict TLS stays on. The private key is retained behind
`Sensitive<T>` and is never exposed via any getter, `Debug`, or log output.

```rust,no_run
use axiam_sdk::client::AxiamClient;
use axiam_sdk::grpc::build_channel;

# fn run() -> Result<(), Box<dyn std::error::Error>> {
let cert_pem = std::fs::read("device-cert.pem")?;
let key_pem = std::fs::read("device-key.pem")?;

let client = AxiamClient::builder()
    .base_url("https://axiam.example.com")?
    .tenant_slug("acme")
    .org_slug("acme") // §5.1: org context for any login/refresh this client drives
    .with_client_cert(&cert_pem, &key_pem)? // §6.1: applies to REST + gRPC
    .build()?;

// The same identity flows to the gRPC transport of the same client:
let channel = build_channel("https://axiam.example.com:9443", &client.grpc_channel_config())?;
# let _ = channel;
# Ok(())
# }
```

## Release-profile tuning (for consumers)

Cargo applies **only the top-level workspace's** `[profile.*]` tables. The
`[profile.release]` block in this repository's `Cargo.toml` therefore governs
this repository's own `cargo build --release` / `cargo bench` — it is *not*
inherited by anything that depends on `axiam-sdk`, and a `[profile.*]` table in
any dependency is silently ignored.

If you want whole-program optimization across the SDK, put it in **your own**
top-level manifest:

```toml
# your-app/Cargo.toml
[profile.release]
opt-level = 3
lto = "fat"          # cross-crate inlining into axiam-sdk and its deps
codegen-units = 1    # slower to build, best generated code
panic = "abort"      # optional; only if your app has no unwinding requirement
```

Two caveats worth knowing before reaching for these:

- `lto = "fat"` + `codegen-units = 1` mainly buy **link-time** optimization.
  The SDK's own per-call cost is dominated by network round-trips and by
  Ed25519/HMAC primitives inside `jsonwebtoken`/`ring` that are already
  compiled with full optimization, so the runtime gain on SDK code paths is
  small while the build gets substantially slower.
- Measure before adopting. `cargo bench --bench jwks_verify --features rest` in
  this repository measures the SDK's hottest CPU path (per-request access-token
  verification behind the §10/§11 route guard) against a local mock JWKS
  endpoint, alongside a "floor" row (`jsonwebtoken::decode` with a pre-built
  key) that shows how much of the cost the SDK can influence at all.

## Build-time notes

A cold `cargo build --all-features` compiles ~276 crates. The great majority of
that time is **not** SDK code:

- `aws-lc-sys` — a C build pulled in by `rustls`'s default `aws-lc-rs` crypto
  provider, via both `reqwest` (`rustls` feature) and `lapin` (default
  features). On a cold build its build script alone was measured between 65 s
  and 119 s depending on machine load — comfortably the single largest item.
  Note that `tonic` is configured for the `ring` provider, so a full-feature
  build currently compiles **two** rustls crypto backends.
- The SDK depends on `actix-web` with `default-features = false` precisely to
  keep the next tier off the graph (brotli/zstd/flate2 compression, `h2` 0.3,
  the `regex`-based router). Your application's own `actix-web` dependency
  decides which of those it wants; Cargo unifies features across the graph.

Enabling only the transports you use (`default-features = false, features =
["rest"]`) is the most effective single lever a consumer has.

## Development

```bash
cargo fmt --all --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
cargo bench --bench jwks_verify --features rest   # hot-path micro-benchmark
```

Building with the `grpc` feature requires **protoc** on `PATH` (`apt install protobuf-compiler`,
`brew install protobuf`): `build.rs` compiles [`proto/`](proto/) into the gitignored `src/gen/`
via `tonic-prost-build`. [`buf.gen.yaml`](buf.gen.yaml) drives the equivalent `buf generate`
pipeline into the same output directory; either path yields the same `axiam.v1` module, so buf
is optional for local work. Consumers installing from crates.io need neither — the stubs are
pre-generated into the published tarball.

`testdata/v2_reference_vectors.json` is generated by the AXIAM server's AMQP sign path and
vendored here verbatim. It pins this SDK's HMAC implementation byte-for-byte to the server's
(CONTRACT.md §8); re-vendor it from the server repository whenever §8 changes.
