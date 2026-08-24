# axiam-sdk (Rust)

[![SDK CI — Rust](https://github.com/ilpanich/axiam-rust-sdk/actions/workflows/sdk-ci-rust.yml/badge.svg)](https://github.com/ilpanich/axiam-rust-sdk/actions/workflows/sdk-ci-rust.yml)
[![Coverage Status](https://coveralls.io/repos/github/ilpanich/axiam-rust-sdk/badge.svg?branch=main)](https://coveralls.io/github/ilpanich/axiam-rust-sdk?branch=main)
[![crates.io](https://img.shields.io/crates/v/axiam-sdk.svg)](https://crates.io/crates/axiam-sdk)
[![docs.rs](https://docs.rs/axiam-sdk/badge.svg)](https://docs.rs/axiam-sdk)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

Official Rust client SDK for [AXIAM](https://github.com/ilpanich/axiam) — Access eXtended Identity and Authorization Management.

**Platform documentation:** <https://ilpanich.github.io/axiam/> — getting started, the authorization model, the OAuth2/OIDC surface, and the operations guides. This README covers the SDK; the site covers the server it talks to.

## Package identity

- **Crate:** `axiam-sdk`
- **Repository:** [github.com/ilpanich/axiam-rust-sdk](https://github.com/ilpanich/axiam-rust-sdk)
- **Registry:** [crates.io/crates/axiam-sdk](https://crates.io/crates/axiam-sdk) _(reserved, not yet published)_
- **API docs:** [docs.rs/axiam-sdk](https://docs.rs/axiam-sdk) — built automatically by docs.rs on each release
- **License:** Apache-2.0
- **MSRV:** Rust 1.88 (`rust-version = "1.88"` in `Cargo.toml`, enforced in CI) — see [Supported Rust versions](#supported-rust-versions)

## Supported Rust versions

| | Toolchain | Why this one |
|---|---|---|
| **Floor** | 1.88 | `rust-version` in `Cargo.toml`. Exposed as `supported_versions::MIN_RUST_VERSION`. Edition 2024 sets the hard lower bound at 1.85. |
| **Newest** | `stable` | Tracked, not pinned. Exposed as `supported_versions::NEWEST_TESTED`. |

**The crate is built against the floor, and against current stable.** The gating
matrix in `sdk-ci-rust.yml` runs the full suite on **both** (D-10). Style gates —
`cargo fmt`, `clippy -D warnings` — run on stable only, deliberately: clippy's lint
set grows with every release, so running it under the pinned MSRV compiler would turn
each new lint into a spurious MSRV-job failure. The MSRV job's job is to prove the
crate still *compiles* on 1.88.

Rust enforces the floor better than most ecosystems do, and there is genuinely
nothing to preflight there: `rust-version` is a hard constraint Cargo checks during
resolution, so a consumer on an older toolchain gets a message naming this crate and
the version it needs, rather than a compile error deep in someone else's source.

The upper end has no enforcement anywhere, because there is no "maximum Rust" to
declare. Code that compiles on the MSRV keeps compiling on newer toolchains almost
always — and "almost" is where new `deny`-by-default lints and tightened inference
live. Only a build on a current toolchain settles it, which is what the `stable` leg
is for.

The upper leg tracks `stable` rather than a pinned version on purpose. Pinning would
freeze the newest end at whatever was current the day it was written and quietly stop
testing anything after that, while still looking like a two-legged matrix.
`tests/version_policy.rs` asserts it stays `stable`, along with everything else here
— and additionally that the MSRV is high enough for the declared edition, since those
two are set independently in the same file and lowering one without the other
produces a manifest promising a toolchain the edition cannot compile on.

See [`examples/version_compatibility.rs`](./examples/version_compatibility.rs).

## Contract conformance

This SDK conforms to CONTRACT.md §1–§13 and §12.7, §14, §15, §17, §19, §20, §21, §22, §23,
§24, §25, §26 (including §6.1 mTLS, the §10.1 minimum local-verification set — **including
rule 9, sender-constrained tokens** — and §13 webhook signature verification).
The MUST-level §16 (retry policy) and §18 (deterministic shutdown) are implemented and so
are not named — a MUST is not something an SDK opts into.

§12.7, §14, §15, §17, §19, §20, §22, §24, §25 and §26 are named rather than folded into the
range because they landed after this SDK already claimed §1–§13: widening the range silently
would turn a statement that was true when written into a different claim without anyone
editing it.

### Retry policy (§16)

Read-only authorization checks — `check_access`, `check_access_as`, `can`, `batch_check`
— retry transient failures under the contract's normative table: **3 attempts** (1 initial
+ 2 retries), 200 ms base, 5 s cap, **full jitter** (uniform over `[0, backoff]`), and
`Retry-After` honored as a **floor**.

Only failures that could plausibly succeed on a second attempt are retried — transport
errors, `408`, `429`, `5xx`. A `401` or `403` is an answer, not a transport failure, and
is surfaced after exactly one attempt.

Nothing that changes server state is ever retried. `login`, `verify_mfa`, `refresh`,
`logout`, `oidc_exchange`, `device_authorize`, `device_login`, `token_exchange` and
`oidc_revoke` all make exactly one attempt, for two independent reasons: a transient
failure *after* the server committed is indistinguishable at the client from one before
it, and their credentials are single-use, so a retry replays a spent credential into a
hard `invalid_grant`.

```rust
// Turn it off if you own your own retry layer — you know your deadline, this SDK doesn't.
let client = AxiamClient::builder()
    .base_url("https://axiam.example.com")?
    .tenant_slug("acme")
    .retry_enabled(false)
    .build()?;
```

There is deliberately no knob for the attempt cap, base delay or delay cap: §16.1 forbids
raising them, and eleven SDKs agreeing on one table is the point of the section.

### Deterministic shutdown (§18)

`AxiamClient::close()` releases the client's local resources. It is idempotent, and any
call afterwards fails with an `AxiamError::Network` naming the cause rather than silently
reconnecting.

**`close()` does not log out.** It never reaches the network. The server-side session
deliberately outlives the client object — that is what lets a process restart and resume —
so a `close()` that logged out would silently end every user's session on each deploy.
Call `logout()` first if ending the session is what you want.

```rust
client.close().await;                  // local teardown only
assert!(client.can("read", id, None).await.is_err());
```

### Telemetry hooks (§19)

Wire metrics without this crate depending on any metrics library:

```rust
use axiam_sdk::telemetry::TelemetryEvent;

let client = AxiamClient::builder()
    .base_url("https://axiam.example.com")?
    .tenant_slug("acme")
    .telemetry_hook(|event: &TelemetryEvent| match event {
        TelemetryEvent::RequestEnd { operation, duration, outcome, .. } => {
            metrics::histogram!("axiam.request", duration, "op" => *operation, "outcome" => format!("{outcome:?}"));
        }
        TelemetryEvent::Retry { operation, attempt, .. } => {
            metrics::counter!("axiam.retry", 1, "op" => *operation, "attempt" => attempt.to_string());
        }
        _ => {}
    })
    .build()?;
```

Three properties worth knowing:

- **A hook that panics cannot fail the operation that fired it.** Telemetry is not
  permitted to fail an authorization check.
- **No event payload can carry a token.** `TelemetryEvent` has a closed field set with no
  escape hatch — this surface exists to be shipped to a metrics backend, which is the last
  place a bearer token should land.
- **Path templates, not URLs.** `/api/v1/authz/check`, never a path with ids substituted
  in, so a metric label cannot become a cardinality bomb.

One `RequestStart`/`RequestEnd` pair is emitted **per attempt**, not per logical call, so
you can count real wire calls. The `Retry` event exists because a retried-then-succeeded
operation is otherwise invisible — a slow success with no signal that the server is
failing.

### Decision memo (§17) — opt-in, off by default

An optional TTL-bounded cache for `check_access` results. **Disabled by default**, because
§11.2 rule 6's ban on caching authorization decisions is still the default behaviour.

```rust
let client = AxiamClient::builder()
    .base_url("https://axiam.example.com")?
    .tenant_slug("acme")
    .decision_memo_ttl(Duration::from_secs(5))   // 0 = off, which is the default
    .build()?;
```

**What you are accepting.** The staleness bound is the TTL, in *both* directions: a grant
revoked on the server can still read as allowed for up to the TTL, and a grant just added
can still read as denied for up to the TTL.

> **Reads-your-own-writes is not guaranteed.** An admin UI that grants a role and
> immediately re-checks is the case that breaks, and it breaks silently. If that is your
> workload, leave this off.

The TTL is clamped to 5 s rather than rejected, so asking for an hour gets you 5 s. Allows
and denies are memoized identically — asymmetric caching would leak which outcome occurred
through latency. Failures are never memoized: caching a transport error as a deny would
turn a blip into a TTL-long outage. The memo is cleared on `login`, `verify_mfa`,
`refresh` and `logout`, since entries are keyed by subject rather than by session. And the
§11 route guard's fail-closed path never consults it, so an outage cannot be papered over
with a stale allow.

### §10.1 minimum local-verification set

`JwksVerifier::verify` is the documented guard entry point and applies **every** §10.1
rule on every inbound token: EdDSA `alg` pinned before the JWKS is consulted, a REQUIRED
numeric `exp`, `nbf` honoured when present, `tenant_id` asserted against the configured
tenant, `iss`/`aud` checked when configured, all under a named 60-second
`CLOCK_SKEW_LEEWAY_SECS`. The §10 `AxiamUser` extractor and the §11 `require_auth` /
`require_access` / `require_role` macros (which inject that extractor) all route through
it — there is no second verification path.

Because the `/oauth2/jwks` trust anchor is **organization-wide**, a verifier used as a
route guard MUST be told which tenant it is guarding:

```rust,ignore
let verifier = JwksVerifier::new(http, &base_url)?
    .expect_tenant_id(tenant_uuid)      // §10.1 rule 4 — required, fails closed without it
    .expect_audience("axiam:user");     // §10.1 rule 6 — optional, recommended
```

`JwksVerifier::verify_signature_only_unchecked` is the §10.1 raw signature-only
primitive, for integrators implementing their own policy. It checks the signature and
nothing else — never use it to guard a route.

See [`CONTRACT.md`](CONTRACT.md) for the full cross-language behavioral contract. It is shared
verbatim across all seven AXIAM SDKs; the copy in this repository is the authority for this
crate's behaviour.

## Features

`axiam-sdk`'s functionality is split into Cargo features so a consumer only pulls in the
dependencies for the transports/integrations it actually uses:

| Feature | Default | Enables |
|---------|---------|---------|
| `rest` | on | `AxiamClient` REST transport: `login`/`verify_mfa`/`refresh`/`logout`, `check_access`/`can`/`batch_check`, cookie-jar session management, local JWKS/EdDSA verification, the CONTRACT.md §12 OIDC/SSO relying-party helpers (`oidc_discover`, `oidc_begin`, `oidc_exchange`, `oidc_refresh`, `login_client_credentials`, `introspect`, `revoke`, `sso_start`, `sso_complete`), the §12.7 logout helpers (`logout_url`, `verify_logout_token`), the §14 device grant (`device_authorize`, `device_poll`, `device_login`) and the §15 `token_exchange` |
| `grpc` | on | `AuthzGrpcClient` gRPC transport: `check_access`/`batch_check`; `UserInfoGrpcClient` gRPC `get_user_info` (OIDC identity read, CONTRACT §1.1) — both over a shared lazily-connected `tonic::Channel`, with the shared single-flight refresh guard driven on `UNAUTHENTICATED` |
| `amqp` | on | `consume(amqp_url, queue, signing_key, handler)` closure-handler AMQP consumer with mandatory pre-handler HMAC-SHA256 verification (CONTRACT.md §8), and `reactor_serve(config, handler)` — the CONTRACT.md §22 reactor runtime (hook events, signed in **both** directions) |
| `observability` | off | Enables `tracing` instrumentation crate-wide beyond the mandatory AMQP security-event logging (which is always emitted regardless of this flag) |
| — | — | `webhook::verify_webhook` (CONTRACT.md §13) has no feature of its own: it is compiled whenever `rest` **or** `amqp` is on, since both already vendor its `hmac`/`sha2`/`hex`/`subtle` inputs. With the default feature set it is always available |
| `actix` | off | The `AxiamUser` Actix-Web `FromRequest` extractor (CONTRACT.md §10 route guard). Implies `rest` (shares the same `JwksVerifier`) |
| `macros` | off | The `#[require_access]` / `#[require_auth]` / `#[require_role]` declarative authorization attribute macros (CONTRACT.md §11), plus the programmatic `middleware::RequireAccess` guard. Implies `actix` |
| `opaque` | on | CONTRACT.md §23 OPAQUE (RFC 9807): `login_opaque`, `opaque_enrollment`, `opaque_available`. Its own feature because it is the only thing in this crate that pulls an elliptic-curve stack and an Argon2/scrypt implementation — a build that will never call `login_opaque` should not carry them. Implies `rest`: OPAQUE is a login path, not a transport |
| `reactor-macros` | off | The `#[reactor_handler("...")]` attribute macro (CONTRACT.md §22.14), which binds an `async fn` to one hook event and validates the name against the §22.5 registry **at compile time**. Implies `amqp`, and deliberately not `macros`: a reactor is an AMQP daemon with no HTTP surface, so it should not pull `actix-web` in to get an attribute macro |

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
use axiam_sdk::amqp::{consume, consume_with_tls, AmqpTlsConfig};
use axiam_sdk::Sensitive;

# async fn run(signing_key: Sensitive<Vec<u8>>) -> Result<(), Box<dyn std::error::Error>> {
// §8b: amqps:// only, enforced before a socket opens.
consume("amqps://guest:guest@localhost:5671", "axiam.authz.request", signing_key, None, |event| async move {
    println!("verified event: {event}");
})
.await?;
# Ok(())
# }

# async fn run_private_ca(signing_key: Sensitive<Vec<u8>>) -> Result<(), Box<dyn std::error::Error>> {
// For a privately-issued broker certificate — the common in-cluster case:
let tls = AmqpTlsConfig {
    ca_cert_pem: Some(std::fs::read_to_string("/etc/axiam/broker-ca.pem")?),
    ..Default::default()
};
consume_with_tls("amqps://broker.internal:5671", "axiam.authz.request", signing_key, None, &tls, |event| async move {
    println!("verified event: {event}");
})
.await?;
# Ok(())
# }
```

See [`examples/amqp_consumer.rs`](examples/amqp_consumer.rs). Every delivery's HMAC-SHA256
signature (CONTRACT.md §8) is verified before the handler runs; failures are nacked without
requeue.

#### Transport security (§8b)

`consume`, `consume_with_tls` and `reactor_serve` all require `amqps://` and check it
before opening a socket. HMAC signing (§8) gives authenticity and replay protection
*across broker hops*; TLS gives confidentiality. Both are required and neither
substitutes for the other — a signed `AuthzRequest` still names its subject, resource
and action in cleartext on an unencrypted wire.

| `AmqpTlsConfig` field | Meaning |
|---|---|
| `ca_cert_pem` | PEM bundle for a privately issued broker certificate. Omit for a publicly issued one (platform roots verify it). |
| `client_cert_pem` + `client_key_pem` | Mutual TLS toward the broker. All-or-nothing: half an identity is refused before dialling. |

There is deliberately no verification-skip option, under any name (§8b rule 4).

**Note there is no loopback exception here.** The `http://localhost` carve-out that
§6 grants the REST and gRPC base URLs does *not* extend to the broker URL: §8b rules 1
and 5 are unconditional, and the AXIAM server itself is TLS-only with no plaintext
listener for such an exception to reach.

### Reactors — AMQP extension actors (`amqp`, CONTRACT.md §22)

A **reactor** is an external process that subscribes to named hook events on the AMQP bus
and answers back — allow, deny, or a field-allow-listed mutation — inside a timeout the
server declared. It is AXIAM's answer to Zitadel Actions and Keycloak SPIs, and the
difference is the whole design: those load third-party code *into* the authorization
server, and this keeps it outside, reachable only through a signed reply schema the server
validates before it believes a word of it.

```rust,no_run
use axiam_sdk::Sensitive;
use axiam_sdk::amqp::reactor::{ReactorConfig, ReactorDecision, events, reactor_serve};

# async fn run(subkey: Sensitive<Vec<u8>>) -> Result<(), axiam_sdk::AxiamError> {
let config = ReactorConfig::builder()
    .amqp_url("amqps://reactor:secret@broker.example.com:5671")
    .tenant_id("11111111-1111-1111-1111-111111111111".parse().unwrap())
    .reactor_id("99999999-9999-9999-9999-999999999999".parse().unwrap())
    .signing_key(subkey)   // the tenant's HKDF-derived AMQP subkey, never the master key
    .build()?;

reactor_serve(config, |event| async move {
    match event.event.as_str() {
        // token.pre_issue is mutable — the `ext.` namespace, and nothing else.
        events::TOKEN_PRE_ISSUE => ReactorDecision::mutate([("ext.cost_center", "42")]),
        // login.post_auth is veto-only, plus step-up.
        events::LOGIN_POST_AUTH => ReactorDecision::deny("embargoed region"),
        _ => ReactorDecision::allow(),
    }
})
.await
# }
```

#### Binding handlers per event (§22.14)

The `match` above is the shape every multi-event reactor grows, and its `_ =>` arm —
`ReactorDecision::allow()` — answers on behalf of code that never ran. That is the defect
§22.10 rule 2 forbids the *runtime* from committing, relocated into your file where the
rule does not reach it: an operator who set `fail_closed` on the registration has it
defeated there.

`ReactorRouter` is §22.14's declarative form, in the spirit of the §11 declarative
authorization helpers:

```rust,no_run
use axiam_sdk::amqp::reactor::{ReactorDecision, ReactorRouter, events, reactor_serve};
# use axiam_sdk::amqp::reactor::ReactorConfig;
# async fn run(config: ReactorConfig) -> Result<(), axiam_sdk::AxiamError> {
let handler = ReactorRouter::new()
    .bind(events::TOKEN_PRE_ISSUE, |event| async move {
        ReactorDecision::mutate([("ext.cost_center", "42")])
    })
    .bind(events::LOGIN_POST_AUTH, |event| async move {
        ReactorDecision::deny("embargoed region")
    })
    .build()?;   // every rejected binding at once, not one per run

reactor_serve(config, handler).await
# }
```

With the `reactor-macros` feature, `#[reactor_handler]` moves the event name next to the
function it belongs to — and checks it **at compile time**:

```rust,ignore
use axiam_sdk::reactor_handler;

#[reactor_handler("token.pre_issue")]
async fn enrich_token(event: ReactorEvent) -> ReactorDecision {
    ReactorDecision::mutate([("ext.cost_center", "42")])
}

let handler = ReactorRouter::new().on::<enrich_token>().build()?;
```

`#[reactor_handler("token.pre_isue")]` does not compile. The function itself is emitted
unchanged, so it stays directly callable and directly unit-testable; the macro adds only a
marker type in the *type* namespace carrying the validated event name.

- **A misspelled event is refused when you bind it** — the router accepts only §22.5
  registry names, which is also how it refuses the three hot-path operations §22.7
  excludes: they are in no registry row. The diagnostic names the registry, never the
  exclusions.
- **An unbound event abstains** — no reply, and the registration's `failure_policy` decides
  (§22.8), exactly as it decides a timeout. Never a synthesized `allow`.
- A duplicate binding is an error rather than a silent overwrite, and `router.events()`
  feeds `default_failure_policy_for` so you can see what an unreachable reactor costs
  before you go live.

It is pure sugar: `build()` produces exactly the handler `reactor_serve` already takes. It
opens nothing, verifies nothing, signs nothing, does not filter a patch, and a handler's
own panic reaches the runtime unchanged so nothing is published.

See [`examples/reactor/`](examples/reactor/) for a complete three-hook reactor with
graceful shutdown and a telemetry hook.

#### The five hookable events, and their allow-lists

| Event | Mutable | Complete allow-list | Default failure policy |
|---|---|---|---|
| `token.pre_issue` | yes | the **`ext.`** namespace only | `fail_open` |
| `login.post_auth` | no | — (veto, or `require_mfa`) | `fail_closed` |
| `user.pre_create` | yes | `username`, `email`, `metadata.` | `fail_closed` |
| `user.pre_update` | yes | `username`, `email`, `metadata.` | `fail_closed` |
| `grant.pre_assign` | no | — (veto only) | `fail_closed` |

An entry ending in `.` is a **namespace prefix** and needs at least one character after the
dot: `ext.` admits `ext.department` and `ext.a.b.c`, and refuses `ext.` itself, `ext`,
`extra`, `external_id` and `evil.ext.department`. So a reactor can never reach `sub`,
`aud`, `exp`, `scope` or any other standard claim — a **correctly signed** reply setting
`sub` is refused exactly as a forged one is.

Registrations that name no `failure_policy` get **the strictest default among their
events**, in either array order — `default_failure_policy_for([...])` computes it, and
"take the first event's default" is specifically what §22.8 forbids, because it lets the
order of a JSON array decide whether an unreachable fraud check passes.

#### `authz.check` is not hookable, and this SDK does not pretend otherwise

`authz.check`, `authz.check_batch` and `token.introspect` are absent from `EVENT_REGISTRY`,
from the `events` constants and from every example here (§22.7, a normative MUST NOT). A
reactor round-trip is milliseconds; the check path's budget is microseconds. An application
that needs external input on an authorization decision writes a **deny grant**, which the
engine evaluates in the hot path at hot-path cost — and there is deliberately no
client-side interceptor in this SDK offering itself as the reactor equivalent.

#### What the runtime guarantees

- **Both directions are signed.** The server signs the event with the tenant's HKDF-derived
  AMQP subkey; the reactor signs its reply with the same key. An unsigned or stale reply is
  not a weak reply — the server discards it as though the reactor had never answered. Every
  event is verified (`key_version ≥ 2`, MAC, ±300 s freshness, nonce seen-set) *before* your
  handler is called.
- **One canonicalization quirk, and it is the whole difference.** A reactor body signs
  `hmac_signature` as **`null`**, where §8's own two message types omit it. Getting this
  wrong produces a MAC that never verifies and no other symptom. It is pinned by
  server-generated vectors rather than by memory — see
  [`testdata/reactor_v2_reference_vectors.json`](testdata/reactor_v2_reference_vectors.json)
  and [`tests/reactor_vectors_test.rs`](tests/reactor_vectors_test.rs).
- **It declares no topology.** No `queue_declare`, no `exchange_declare`, no `queue_bind` —
  the server owns all three, and the transport seam this runtime is written against does
  not even offer them. A reactor that can bind is a reactor that can bind itself to
  `*.token.pre_issue` and read another tenant's issuance events.
- **It fails closed on its own errors.** A handler that panics, a body that will not decode,
  a window that has already closed: each publishes **nothing**, so the registration's
  `failure_policy` decides. Synthesizing an `allow` would override the operator's
  `fail_closed` setting from inside the library. `ReactorDecision::abstain()` is the
  explicit form of the same thing.
- **It does not filter your patch.** One forbidden key rejects the whole patch server-side;
  pruning it here would leave you believing a field was set when it was dropped. Check
  yourself with `ReactorEventSpec::patch_field_allowed` if you want to know before you send.
- **It honours `timeout_ms`.** The handler runs inside the window the server declared, and a
  reply whose window has closed is abandoned rather than published late.
- **Shutdown drains (§18).** `ReactorShutdown::trigger()` stops the runtime taking *new*
  deliveries; the event in flight finishes — handler, signature, publish — first.

#### Registering a reactor (§22.9)

Registration is a REST admin call, not part of this runtime:

```bash
curl -X POST https://axiam.example.com/api/v1/reactors \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d '{"name":"fraud-check","events":["login.post_auth"],"mode":"intercept","timeout_ms":500}'
```

The response's `id` is what `reactor_id(..)` takes, and the server declares the queue.
`timeout_ms` defaults to **500** and is refused outside `1…5000`; the chain's wall-clock
ceiling is **5000 ms** and the per-tenant in-flight cap is **64**. This SDK exposes those as
constants (`DEFAULT_TIMEOUT_MS`, `MAX_TIMEOUT_MS`, `DEFAULT_MAX_IN_FLIGHT`) but ships **no
typed client for the CRUD endpoints** — call them through `AxiamClient`'s HTTP surface, and
let the server validate; §22.9 explicitly warns against re-deriving `PUT` merge semantics or
the `failure_policy` re-derivation client-side.

#### Logging

The `payload`, `patch`, `reason` and `decision` are tenant business data — readable by
design, since a handler that cannot inspect the event cannot decide anything, but this
runtime never logs them at info level and yours should not either (§22.12). The signing key
is `Sensitive<Vec<u8>>`, is never logged at any level, and never appears in a reconnect
diagnostic. `nonce`, `correlation_id` and `hmac_signature` are not secrets and may be logged
for correlation.

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

### Device authorization grant (`rest`)

CONTRACT.md §14 (RFC 8628) — signing in a device that cannot show a browser: a TV, a
CLI, a headless commissioning tool.

```rust,ignore
let tokens = client
    .device_login(DeviceLoginParams::default(), |auth| {
        // Called BEFORE the first poll. Display it however the device can —
        // screen, QR code, e-ink panel. The SDK never prints it for you.
        println!("visit {} and enter {}", auth.verification_uri, auth.user_code);
    })
    .await?;
```

`device_authorize` and `device_poll` are also public, for an application that wants to
drive its own loop (to render a countdown, say). The polling rules are where
implementations go wrong, so they are worth stating:

- **`slow_down` raises the interval permanently.** An SDK that backs off for one round
  and returns to the original interval will be told to slow down again, forever.
- **`access_denied` and `expired_token` stay distinct.** A human said no, versus nobody
  answered — the only information the device can act on.
- **Polling stops at `expires_in`**, even if the server has not yet said `expired_token`.
- **A `5xx` mid-poll is not terminal.** A server restart must not lose a grant the user
  has already approved.

`device_code` is `Sensitive`; `user_code` deliberately is not — it exists to be read
aloud, and wrapping it would defeat the one thing it is for.

Per §14.3 rule 4, `device_login` **returns** the token set rather than adopting it, which
matches this SDK's `login_client_credentials` posture. See
[`examples/device_login.rs`](examples/device_login.rs).

### Token exchange (`rest`)

CONTRACT.md §15 (RFC 8693) — a service holding a user's token exchanging it for a
*narrower* one before calling the next service.

```rust,ignore
let exchanged = client
    .token_exchange(TokenExchangeParams {
        scopes: Some(vec!["orders:read".into()]),
        audience: Some("orders-service".into()),
        ..TokenExchangeParams::new(Sensitive::new(user_token))
    })
    .await?;
```

Most of what this method does is refuse to be helpful, and each refusal is deliberate:

- **No default `actor_token`.** Omitting it asks for *impersonation*; the SDK will not
  quietly substitute the client's own session token and turn that into a delegation.
- **No auto-narrowing after `invalid_scope`.** The server refuses rather than silently
  narrowing precisely so the caller finds out here.
- **No refresh token, ever** — `ExchangedToken` has no such field, so there is nothing to
  synthesise. Re-run the exchange.
- **No adoption.** The issued token is handed onward in one call; adopting it would
  silently re-privilege every later call this client makes. A MUST NOT, where
  `login_client_credentials` adoption is a MAY.

See [`examples/token_exchange.rs`](examples/token_exchange.rs).

#### External-IdP subject tokens (CONTRACT.md §15.7)

The same method exchanges a token minted by a **trusted external IdP** — a
partner's Entra, Okta or Keycloak — for an AXIAM token scoped to what the
resolved AXIAM user may actually do. There is no separate operation:

```rust,ignore
let exchanged = client
    .token_exchange(TokenExchangeParams {
        subject_token_type: JWT_TOKEN_TYPE.into(), // required; named, never guessed
        scopes: Some(vec!["read:orders".into()]),
        audience: Some("https://orders.internal".into()),
        ..TokenExchangeParams::new(Sensitive::new(partner_token))
    })
    .await?;
```

- **`subject_token_type` is yours to state, and is required** (§15.1). The SDK
  never decodes the subject token to pick it, and never overrides what you
  named. There is deliberately no `Option`: a field that can hold "no answer"
  forces the SDK to have one ready, and any answer it picks is the guess §15.7
  forbids. `TokenExchangeParams::new` takes it alongside the subject token.
- **No actor token.** Delegation across a trust boundary is unsupported in v1;
  sending one is `invalid_request`, which the SDK will not work around by
  dropping it and re-sending.
- **One refusal is distinguishable.** `invalid_grant` whose description is
  `the subject token's issuer is not configured for token exchange` means *fix
  the AXIAM trust configuration*. Every other `invalid_grant` means *fix your
  token*, and is deliberately generic.
- **Forward the result as-is.** It carries an `ext_exchange` claim naming the
  partner issuer; never strip it, and never read it as an authorization input.
  It also cannot be exchanged again — exchanges do not compose.

The operator guide is `docs/api/federated-token-exchange.md`.

### Logout — RP-initiated and back-channel (`rest`)

CONTRACT.md §12.7. `logout_url` builds the redirect (pure local computation);
`verify_logout_token` validates a token the OP **pushed** to your back-channel endpoint.

```rust,ignore
let url = client.logout_url(&configuration, LogoutUrlParams::new(id_token))?;

// …and at your registered backchannel_logout_uri:
let verified = client.verify_logout_token(&logout_token, &configuration).await?;
if let Some(sid) = verified.sid {
    end_session(&sid); // that session ONLY
}
```

The verifier is where the security weight sits — the input arrives unsolicited and
instructs you to terminate a session. It checks the signature, `iss`, `aud`, that
`events` carries the back-channel-logout key (**the only thing separating a logout token
from an ID token**), that `nonce` is *absent* (its presence is how an ID token gets
replayed as one), that something is named, and freshness.

It returns `sid`/`sub`/`jti` rather than a bare boolean: you have to know *which* session
to end. **Dedup on `jti` yourself** — delivery is at-least-once, so a valid token
legitimately arrives twice; the SDK has no durable store and an in-memory guard would
silently drop a real second logout after a restart.

See [`examples/logout.rs`](examples/logout.rs).

### UMA 2.0 — Protection API and ticket grant (`rest`, `actix`)

The resource-server side of User-Managed Access: register what you guard, ask the
authorization server what a caller would need, and redeem the resulting ticket.

The two runnable halves are [`examples/uma_resource_server.rs`](examples/uma_resource_server.rs)
and [`examples/uma_client.rs`](examples/uma_client.rs) — run the first, then the second
against it.

**Guarding a route so a denial is actionable** (needs `actix`):

```rust,no_run
# use axiam_sdk::client::AxiamClient;
# use axiam_sdk::middleware::{AuthzGuardError, AxiamUser, RequireAccess, UmaChallenger};
# use uuid::Uuid;
# async fn handler(client: &AxiamClient, user: &AxiamUser, id: Uuid, challenger: UmaChallenger)
#     -> Result<(), AuthzGuardError> {
RequireAccess::new("invoices:read")
    .with_uma_challenge(challenger)
    .check(client, user, id)
    .await?;
# Ok(())
# }
```

Without `with_uma_challenge` this is an ordinary §11 check and a denial is a bare 403. With
it, the guard mints a permission ticket for the action it just refused and returns
`WWW-Authenticate: UMA realm=…, as_uri=…, ticket=…` alongside the 403 — so a UMA-aware
client knows where to obtain authority instead of only being told no. The body is unchanged,
so a client that does not speak UMA sees exactly the 403 it saw before.

**It is opt-in, and that is a design decision rather than an oversight.** Emitting a
challenge means minting a credential: a wire call to the Protection API and a live ticket,
produced on a path the caller did not explicitly request. A guard that did that on every
denial by default would turn each unauthorized request into a Protection API call — a
denial-of-service amplifier pointed at your own authorization server.

**Failure is not escalation.** If minting fails — expired PAT, Protection API down, a scope
the resource never declared — the denial still surfaces as a plain 403 with no challenge. A
caller who was going to be refused is refused either way; letting an outage turn a deny into
a 500 would give it a second consequence, and letting it turn into an allow would be a
security bug.

**Consuming the challenge**, client side:

```rust,no_run
# use axiam_sdk::Sensitive;
# use axiam_sdk::client::AxiamClient;
use axiam_sdk::uma::uma_parse_challenge;

# async fn demo(client: &AxiamClient, header: &str, user_token: String)
#     -> Result<(), Box<dyn std::error::Error>> {
let challenge = uma_parse_challenge(header).ok_or("not a UMA challenge")?;
let ticket = challenge.ticket.ok_or("no ticket")?;
// Deciding whether to trust challenge.as_uri is YOUR call — parsing performed no
// exchange, deliberately (§20.3).
let rpt = client
    .uma_exchange_ticket(&ticket, &Sensitive::new(user_token))
    .await?;
# let _ = rpt;
# Ok(())
# }
```

The rest of the surface — `uma_register_resource`, the other four `rreg` operations,
`uma_request_ticket`, `uma_exchange_ticket` — plus the rules they enforce (a ticket is never
retried, the RPT is never adopted, an update replaces the scope list rather than merging it)
is documented on the [`uma`](https://docs.rs/axiam-sdk/latest/axiam_sdk/uma/) module.

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

## WebAuthn and passkeys (§24)

A passkey ceremony is **two exchanges stacked**: one with an *authenticator*,
which needs a platform API, and one with *AXIAM*, which is four ordinary JSON
round trips. The native build has no authenticator, so it ships the second half.

That is not a consolation prize. A Rust service completing a ceremony that ran on
an Android or iOS handset is the relying party exactly as a browser is — and
§24.6b rule 2 forbids the alternative outright: an SDK must not emulate an
authenticator in software, because a "credential" held in process memory is not a
second factor. `axiam-sdk-wasm` is the one build that *does* reach an
authenticator, through `web-sys`.

### The three-step shape

```rust
let challenge = client.webauthn_discoverable_start(None).await?;

// The JSON form every platform authenticator API takes (§24.6a) — the exact
// string Android's CreatePublicKeyCredentialRequest and a browser's
// parseCreationOptionsFromJSON() both want.
let response_json = your_device_channel(&challenge.request_json())?;

let session = client
    .webauthn_discoverable_finish(
        &challenge.state_token,
        webauthn_response_from_json(&response_json)?,
    )
    .await?;
```

The client is authenticated when that returns — §24.3 rule 1 is not a "MAY
adopt". `webauthn_register_start`/`_finish` and
`webauthn_authenticate_start`/`_finish` follow the same shape, for enrolling a
credential and for a passkey used as a second factor after `login()` set
`mfa_required`.

The challenge is a `serde_json::Value`, not a modelled struct — precisely so
there is nothing to normalize through. `webauthn_response_from_json` takes the
platform's own string; making a caller model one as a Rust struct this SDK
immediately re-serializes is three chances to corrupt a signed buffer in service
of nothing.

### What the SDK will not do

**It never adjusts an option.** The server generates the challenge and chooses
`residentKey`, `userVerification`, the attestation conveyance, the exclusion list
and the timeout; this SDK carries all of it through unchanged and posts the
answer back unchanged. Not because those fields are hard — because they are not,
and relaxing `userVerification` to `"preferred"` because a test authenticator
kept prompting weakens a ceremony the server believes it configured. The server
cannot catch it: an assertion produced under weaker options is a valid assertion.

**It never parses `state_token`.** It is opaque, it is `Sensitive`, and it goes
straight back to the matching `*_finish`.

### Classifying a device's failure

Every platform reports a ceremony failure as one opaque type whose only
machine-readable part is a name — so a handset can relay just that name, and a
Rust service can turn it into the same five outcomes a browser would see:

```rust
let failure = WebauthnFailure::classify(name_relayed_by_the_device);
if failure == WebauthnFailure::AlreadyRegistered {
    // the only outcome whose remedy is "use a different device"
}
show(failure.message());
```

`Cancelled` covers **both** an explicit refusal and a silent timeout. The
WebAuthn spec deliberately refuses to distinguish them, because telling a website
which one happened leaks whether an authenticator was present — so the copy does
not accuse anyone of cancelling, and the distinction must not be recovered by
timing the call.

### Two error rows that are not the generic mapping

- A **`403` on `webauthn_register_finish`** is the tenant's attestation policy
  refusing *this authenticator* — an AAGUID that is not allow-listed, a missing
  FIDO certification, a revoked status — not a permission problem with the user.
  The policy message survives into `AxiamError::Authz`, because it is the only
  way the person holding the key learns a different one would work.
- A **`503` on `webauthn_register_start`** means attestation is required and the
  FIDO metadata service has no usable snapshot. A server configuration state, not
  a transient failure, and deliberately **not** retried.

Worked example: [`examples/webauthn_relying_party.rs`](examples/webauthn_relying_party.rs).

## Account lifecycle and MFA enrolment (§25)

§1 locks the *middle* of an account's life — `login`, `verify_mfa`, `refresh`,
`logout` all assume an account that already exists, is verified, and already has
its second factor. These nine operations are how it gets there.

```rust
let enrolment = client.mfa_enroll().await?;
render_qr(enrolment.totp_uri.expose());
let enabled = client.mfa_confirm(code_typed_by_user).await?;
```

`secret_base32` and `totp_uri` are both `Sensitive`, and the URI is the one that
matters: it *is* `otpauth://…?secret=…`, so it contains the secret it sits beside.
Wrapping only the secret would have wrapped nothing — the URI is the field that
actually reaches a log, because it is the field you hand to a QR renderer.

### `login()` has a third outcome

`LoginResult` gains `mfa_setup_required` and `setup_token`. The server has always
been able to answer `403 mfa_setup_required` for an account in a tenant that
requires MFA; it used to reach you as `AxiamError::Authz`, saying you lacked
permission to log in when what the server said was recoverable.

```rust
let result = client.login(email, password).await?;
if result.mfa_setup_required {
    let setup_token = result.setup_token.as_ref().expect("populated by §25.2 rule 1");
    let enrolment = client.mfa_setup_enroll(setup_token).await?;
    render_qr(enrolment.totp_uri.expose());
    client.mfa_setup_confirm(setup_token, code).await?;   // completes the login
}
```

Additive here rather than a new type, because `LoginResult` has always been one
struct with flags rather than a discriminated enum — so nothing that reads
`mfa_required` today has to change. A genuine authorization refusal is still
`AxiamError::Authz`: the branch is matched on the body's discriminant, not the
`403` alone.

### Email verification and password reset

```rust
client.verify_email(&token, tenant_id).await?;
client.resend_verification(email, tenant_id).await?;
client.request_password_reset(&PasswordResetRequest { email, ..Default::default() }).await?;
```

`request_password_reset` returns `Ok(())` **whether or not the address exists**,
and this SDK exposes no way to tell them apart. Any signal distinguishing them —
including one inferred from timing — turns the endpoint into the account
enumeration oracle its uniform response exists to prevent.

Setting the new password takes one extra call on any tenant that might have
OPAQUE enabled, because the client has to build a registration record and cannot
know the parameters before it has a token to ask with:

```rust
let context = client.password_reset_context(&token).await?;
client.confirm_password_reset(&PasswordResetConfirmation {
    token, new_password, tenant_id,
    opaque: /* build a §23 record when context.opaque is Some */ None,
}).await?;
```

The context discloses no identity, and a `404` covers unknown, expired and
already-consumed without distinguishing them.

Worked example: [`examples/account_lifecycle.rs`](examples/account_lifecycle.rs).

## Pushed authorization requests (§26)

PAR (RFC 9126) moves the authorization request off the browser: the client POSTs
`scope`, `redirect_uri`, `state` and the PKCE challenge straight to AXIAM over an
authenticated back channel and puts an opaque `request_uri` in the redirect, so
what travels through the user agent is a random string that cannot be edited into
meaning something else.

Required for a FAPI 2.0 client — `profile: "fapi2"` refuses a registration that
does not set `require_par`.

```rust
let configuration = client.oidc_discover().await?;
let request = client.oidc_begin(&configuration, OidcBeginParams {
    redirect_uri: redirect_uri.clone(), scope: Some("openid profile".into()), ..Default::default()
})?;

let pushed = client.oidc_par(OidcParParams {
    request, redirect_uri: redirect_uri.clone(), scope: Some("openid profile".into()),
    tenant_id: None, configuration: Some(configuration),
}).await?;
redirect(&pushed.url);
```

`oidc_begin` still does the computing — there is no second generator for `state`,
`nonce` and PKCE — and `pushed.code_verifier` is the one it produced, so there is
exactly one value to keep.

Three things that are easy to get wrong:

1. **The endpoint answers `201`, not `200`.** RFC 9126 §2.2 specifies Created, and
   a success predicate written `== 200` treats every successful push as a failure.
2. **The authorization URL carries exactly `client_id` and `request_uri`.** The
   server *refuses* a request mixing a `request_uri` with inline authorization
   parameters rather than merging them, and re-adding them "for compatibility"
   restores the parameter-confusion attack the refusal prevents.
3. **`request_uri` is single-use and short-lived.** There is nothing to retry with
   it; the safe recovery is a fresh push. `oidc_par` is correspondingly never
   retried on a `5xx` or a transport failure — it is a POST that creates state.

Worked example: [`examples/par_login.rs`](examples/par_login.rs).

## OPAQUE (§23)

`login_opaque` proves the password without sending it. What crosses the wire is
a blinded group element and a MAC, neither of which is useful to anyone who
does not already hold the account's record *and* the tenant's OPRF seed.

```rust
use axiam_sdk::AxiamClient;

let client = AxiamClient::builder()
    .base_url("https://axiam.example")?
    .org_slug("acme")
    .tenant_slug("default")
    .build()?;

// Same LoginResult as login(), including the MFA-challenge case.
let result = client.login_opaque("alice", "correct horse battery staple").await?;
if result.mfa_required {
    client.verify_mfa("123456").await?;
}
```

Fall back to `login()` when the tenant does not offer OPAQUE — that case is a
`NetworkError` naming OPAQUE, deliberately **not** an `AuthError`, so it cannot
be mistaken for a bad password:

```rust
let result = match client.login_opaque(user, password).await {
    Ok(result) => result,
    Err(e) if e.to_string().contains("does not offer OPAQUE") => {
        client.login(user, password).await?
    }
    Err(e) => return Err(e),
};
```

Do **not** fall back on any other error — and you no longer need to for the
one case where a fallback is correct. `login/start` reports the tenant's
`opaque_mode`, and CONTRACT.md §23.4 rule 7 makes `login_opaque` act on it when
the exchange fails:

- `optional` — the mid-migration state. Every account has no OPAQUE record
  until its password is next set, so a failed exchange is the ordinary case
  rather than a wrong password. `login_opaque` retries over `login()` itself
  with the same credentials and returns that call's outcome, so most of a
  tenant can still sign in.
- `required`, an unrecognised mode, or a server too old to report one — the
  failure is final and comes back as an `AuthError`. No plaintext password goes
  on the wire; `required` answers `403 opaque_required` for every principal
  anyway.

In both cases no `KE3` is ever sent once the envelope fails. `mode` is **not**
downgrade protection — a hostile server that wanted the plaintext could just
answer `404` and take the fallback above. What closes that is `required`,
server-side.

### Enrolment

The server cannot build a record — it never sees the plaintext — so one has to
be sent with any request that sets a password:

```rust
let enrollment = client.opaque_enrollment("new password").await?;
// send `enrollment` as the request's `opaque` field
```

One argument, where the SRP verifier this replaces took four. There is no
`identity`, no group and no KDF: the server names the ciphersuite and the costs
in its `register/start` response, and the record binds to a credential
identifier the server chooses. It is `async` because that response has to be
fetched — OPAQUE's envelope is sealed under the server's oblivious PRF, so
there is no offline computation that produces a valid record.

### Three things worth knowing

**Nothing about the account's name matters.** The SRP version of this section
opened with a warning that the identity is always the username, because `x` was
derived over `username ":" password` and enrolling against an email produced a
verifier no login could satisfy. That whole class of mistake is gone, and so is
its consequence: a later rename no longer invalidates a credential.

**`login_opaque` blocks.** It runs the tenant's key-stretching function:
Argon2id at 19 MiB by default, tens to hundreds of milliseconds. That cost is
the point — it is what makes a stolen record expensive to attack even by
someone holding the OPRF seed — but on an async runtime, treat the call as
blocking work.

**What it does and does not protect.** A TLS-terminating proxy, an accidentally
verbose request log, or a heap dump on the server can no longer capture a
plaintext password, because the server never has one. A stolen record database
is additionally not offline-crackable without the tenant's OPRF seed, which is
the property SRP could not offer. It does **not** protect against a compromised
AXIAM server.

**This SDK does not implement OPAQUE.** CONTRACT.md §23.1 forbids it, and this
crate obeys: the protocol comes from `axiam-opaque`, the same implementation
the AXIAM server links and the other ten SDKs bind through a C ABI or
WebAssembly. That is why the `opaque` feature no longer pulls `num-bigint`, and
why the ~870 lines of group arithmetic the SRP implementation needed are gone.

## Browser builds (`axiam-sdk-wasm`)

This crate compiles to `wasm32-unknown-unknown` and is published to npm as
[`axiam-sdk-wasm`](axiam-sdk-wasm/README.md) — the same implementation, in a
browser, rather than a second one written in JavaScript.

The browser build is REST + OPAQUE only: gRPC and AMQP need sockets, and mTLS and
custom CA roots belong to the browser rather than to page script (both return a
typed error rather than being silently ignored). See that package's README for
the full list and for the CORS requirement that comes with `HttpOnly` cookies.

It is also the one build of this SDK that can run a **WebAuthn ceremony**
(§24.6b): `navigator.credentials` is reachable there through `web-sys`, where the
native build has no authenticator at all and ships the relying-party layer plus
the §24.6a JSON bridge instead.

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
