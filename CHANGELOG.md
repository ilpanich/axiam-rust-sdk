# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0-alpha29] - 2026-08-20

### Added

- SRP-6a login client + WASM port and the axiam-sdk-wasm npm package (#68)

## [1.0.0-alpha28] - 2026-08-19

### Changed

- Add the named D5 conformance suite covering §19 telemetry, and re-vendor openapi.json (#67)
- Bump taiki-e/install-action from 2.85.10 to 2.85.13
- Bump github/codeql-action from 4.37.6 to 4.37.7

## [1.0.0-alpha27] - 2026-08-17

### Added

- §22.14 declarative handler binding — ReactorRouter + #[reactor_handler]

### Changed

- Do not intra-doc-link a private module from public docs
- Re-vendor CONTRACT.md 1.23 (§8b rules 7 and 8)
- Re-vendor openapi.json for the SCIM provisioning-token endpoints
- Re-vendor CONTRACT.md 1.22 from the server repo

### Fixed

- Make §8b rule 2 implementable, and stop the guard failing open

## [Unreleased]

### Added

- **A named D5 conformance suite, and §19 telemetry is finally tested (F7).**
  `tests/d5_conformance.rs` carries the §19 assertions this SDK did not have —
  `src/telemetry.rs` had no test at all — and names where the rest of D5
  already lives, so the suite is locatable the way the other ten SDKs' is.

  New assertions: a request pair per attempt with a `Retry` between them and in
  that order; a panicking hook cannot fail an authorization check, and does not
  poison later calls; **no event carries a token, a password, a CSRF value or a
  resource id**; `Retry.reason` is redacted prose rather than the server's
  body; the emitted variant set is closed; a memo hit emits no request events;
  and retry-disabled makes exactly one attempt. All of it is asserted through
  the public client surface against a `wiremock` server, counting what reaches
  the wire and the sink rather than testing helpers in isolation.

- **A CA bundle and client identity for the broker connection (§8b rules 2 and
  3).** `AmqpTlsConfig` carries `ca_cert_pem` (for a privately-issued broker
  certificate) and a `client_cert_pem`/`client_key_pem` pair (for mutual TLS),
  reaching lapin through `Connection::connect_with_config`.

  Rule 2 is a **MUST**, and it was previously not merely unimplemented here but
  unimplementable: both AMQP entry points dialled with `Connection::connect`,
  which takes no TLS material at all, so an `amqps://` broker could only ever be
  verified against the platform root store. That excludes the common deployment
  — an in-cluster broker whose certificate is issued by a private CA, or by
  AXIAM's own `axiam-pki` organization CA.

- `consume_with_tls()` (the TLS-carrying sibling of `consume()`, which keeps its
  signature and delegates), `ReactorConfigBuilder::tls()`, and the exported
  `ensure_amqps()` for validating a broker URL at config-load time.

### Fixed

- **The §8b scheme guard failed open on an unparseable URL.** It was written as
  `if let Ok(parsed) = url::Url::parse(amqp_url) { … }`, so a URL that did not
  parse skipped the check entirely and went straight to lapin. That is backwards
  for a security check — an input nobody can parse is the one to refuse, not the
  one to wave through. It is now an error, in both `consume()` and the reactor
  builder.

### Changed

- Re-vendor `openapi.json` at 1.0.0-alpha27 — the copy was pinned at alpha26 and
  failing the cross-repo artifact-drift gate
- **BREAKING (AMQP only): plaintext `amqp://` is refused on loopback too.** The
  broker URL no longer goes through `url_guard`, whose `localhost` /
  `127.0.0.1` / `::1` exception is right for §6's REST and gRPC rules and wrong
  for §8b's: rules 1 and 5 carry no host carve-out, the five other SDKs that
  ship AMQP dialers enforce them without one, and the AXIAM server is now
  TLS-only with no plaintext listener for such an exception to reach.

  `http://localhost` for REST and gRPC is **unchanged** — this is an AMQP-only
  narrowing. If you develop against a local broker, give it a TLS listener;
  `scripts/gen-broker-tls.sh` in the server repo mints suitable material, and
  its certificate carries `localhost` in the SAN for exactly this case.

## [1.0.0-alpha25] - 2026-08-16

### Added

- Ship the CONTRACT.md §22 reactor runtime (R2.5)
- Implement §21.7.2 proof verification — all ten checks (#59)
- Subject_token_type is required (contract 1.13)
- §15.7 — external-IdP subject tokens at the exchange (X4)
- Wire §20.3 challenge emission into the §11 route guard, plus the example pair (#52)
- §20 — UMA 2.0 Protection API and ticket grant
- Report clamped settings via §19 ConfigClamped (contract 1.9)
- Contract 1.8 — §16 retry, §17 memo, §18 close(), §19 telemetry (D5) (#45)
- Device grant, token exchange, logout helpers; re-vendor (D6)

### Changed

- Re-vendor CONTRACT.md 1.19, openapi.json and proto/ from main (R5.8) (#61)
- Name the no-401-interceptor invariant at the transport seam (R5.7, F-14) (#60)
- Contract 1.15 — §10.1 rule 9, sender-constrained access tokens (#58)
- Drop a needless borrow in the timeout test
- Rustfmt import order
- Add the §20.7 required timeout assertion
- Retire the "measured residual" justification (contract 1.14)
- Re-sync to contract 1.14 (#302 closed)
- Bump github/codeql-action from 4.37.4 to 4.37.6
- Bump Swatinem/rust-cache from 2.9.1 to 2.9.2
- Bump dtolnay/rust-toolchain
- Bump taiki-e/install-action from 2.85.5 to 2.85.10

### Fixed

- Never print the raw UMA challenge header (#53)

## [Unreleased]

### Added

- **CONTRACT.md §22 — Reactors (AMQP extension actors).** New `amqp::reactor`
  module and the `reactor_serve(config, handler)` runtime: it consumes the
  server-declared per-reactor queue, verifies every event (§8 v2 — `key_version`,
  MAC, ±300 s freshness, nonce seen-set) *before* user code sees it, dispatches
  to a handler returning `Allow` / `Deny` / `Mutate`, then signs and publishes
  the reply. Also ships the event registry with its mutable-field allow-lists,
  the strictest-wins `failure_policy` composition (§22.8), `ReactorShutdown`
  for the §18 drain, and `examples/reactor/`.

  **§8's HMAC now runs in both directions**, with one canonicalization
  difference that produces a MAC that never verifies and no other symptom: a
  reactor body signs `hmac_signature` as **`null`**, where `AuthzRequest` and
  `AuditEventMessage` omit it. That is pinned by the server-generated vectors
  in `testdata/reactor_v2_reference_vectors.json` — same master key, tenant and
  derived subkey as the §8 fixture — rather than by a paragraph to remember.

  Three behaviours are structural rather than documented. The runtime **declares
  no topology**: the transport seam it is written against has no declare or bind
  operation at all, and a test asserts the source calls none (§22.1). It **fails
  closed on its own errors**: a panicking handler, an undecodable body or an
  expired window publishes *nothing*, so the operator's `failure_policy` decides
  rather than a synthesized `allow` from inside the library (§22.10 rule 2). And
  it **does not filter a patch** — one forbidden key rejects the whole patch
  server-side, and pruning it would leave the author believing a field was set
  (§22.4 rule 1).

  §22.7's hot-path exclusion is honoured by absence: `authz.check`,
  `authz.check_batch` and `token.introspect` appear in no constant, no registry
  row and no example, and a test asserts it against the data rather than a
  comment.

  Not shipped, deliberately: a typed client for the §22.9 admin CRUD endpoints.
  That subsection is informative, and §22.9 specifically warns against
  re-deriving `PUT` merge semantics or the `failure_policy` re-derivation
  client-side — so the right surface is the server's, called through
  `AxiamClient`'s HTTP layer.

- **CONTRACT.md §21.7.2 DPoP proof verification (RFC 9449).** New
  `token::dpop` implements all ten checks and returns the proof key's RFC 7638
  thumbprint, so a value passed on to `verify_token_binding` could only have
  come from a proof that verified. `InMemoryJtiStore` covers check 8 for a
  single process; the `JtiStore` trait is a required argument, not an optional
  one, because there is no safe default that skips replay tracking.

  Gated on `rest`/`actix` (the checks need `sha2`, `base64`, `subtle`). A
  `--no-default-features` consumer keeps `verify_token_binding` and has no proof
  verifier — which per §10.1 rule 9 means refusing `jkt`-bound tokens.

  **One recorded divergence from the Python and TypeScript SDKs:** `jsonwebtoken`
  refuses a token whose header `alg` disagrees with the allowlist it was handed,
  so this SDK *rejects* a lying `alg` header where those two ignore it and verify
  anyway. Both satisfy check 2 — neither lets the header choose the algorithm —
  and this is the stricter of the two. There is a test named for the divergence
  so it stays a decision rather than a surprise.

- **CONTRACT.md §10.1 rule 9 extended for DPoP (contract 1.16/1.17).**
  `CnfClaim` gains `jkt` (RFC 9449 §6.1), and a new
  `Claims::verify_token_binding(PresentedProofs)` applies the full ten-row
  rule: a certificate thumbprint, a verified DPoP key thumbprint, or **both**.
  A `cnf` naming both methods is a **conjunction** — satisfying only the more
  convenient one is not compliance — and a `cnf` naming nothing this SDK can
  check (including an *empty* one) is refused rather than read as unbound.
  `Claims::verify_certificate_binding` remains as the narrower entry point for
  transports that can only produce a certificate, and now **refuses** a
  DPoP-bound or both-bound token rather than ignoring the half it cannot
  check.
  New example: `examples/sender_constrained_guard.rs`.

  Not a breaking change: an unbound token is still accepted with no
  certificate and no proof, which is asserted directly by
  `an_unbound_token_is_accepted_with_no_proofs_at_all`.

  §10.3 (sender-constrained tokens over gRPC) needs no work in this SDK — its
  gRPC client calls `AuthorizationService` only and never introspects through
  `TokenService`, so there is no gRPC path here that could read a `cnf`. The
  vendored `proto/` is re-synced regardless, so the fields are present the day
  that changes.

### Changed

- **Re-sync vendored `CONTRACT.md`, `openapi.json` and `proto/` to contract 1.19**
  (upstream **R5.8**). The vendored copies had been pinned at the 1.15-era artifacts
  and drifted three contract revisions behind `ilpanich/axiam@main`. All five files are
  now byte-identical to upstream, and `proto/axiam/v1/reactor.proto` (contract 1.18
  §22, the AMQP reactor protocol) is vendored here for the first time.

- **CONTRACT.md §11.2 rule 9 — the gRPC decision reads `reason`, not `deny_reason`**
  (**SDK-Q10**, contract 1.19). `CheckAccessResponse` gains `reason` (field 4, explicit
  presence) carrying the same string the REST decision body has always called `reason`;
  `deny_reason` (field 2) is now `[deprecated = true]` and is removed at AXIAM 2.0.
  `AccessDecision::from` reads `reason` and falls back to `deny_reason` only when
  `reason` is **absent on a refusal** — which is exactly what a pre-SDK-Q10 server
  sends, and the reason field 4 has explicit presence rather than being a plain
  `string`. `AccessDecision` still exposes one reason accessor, so this is not a
  breaking change for callers and nothing changes on the wire today.

  **Known residual, deliberately not taken here:** contract 1.19 also relaxes gRPC
  `subject_id` to optional (an *empty* value meaning "the subject in the verified
  token"). `grpc::CheckAccessRequest::subject_id` stays a required `Uuid` — relaxing it
  to `Option<Uuid>` is a breaking signature move and belongs in its own change, not in
  an artifact re-sync. Passing the subject explicitly remains valid and is what a
  service-mesh caller does anyway; the type's doc comment now records the gap.

- **The "no reactive 401→refresh interceptor" invariant is now written down at the
  transport seam** (cross-SDK conformance review follow-up **F-14**; docs only, no
  behaviour change). CONTRACT.md §12 requires that a 401 from an `/oauth2/*` endpoint
  never enters the §9 single-flight refresh guard — that 401 means the *client
  credentials* are bad, not that the user's session expired, so refreshing would burn a
  single-use rotating refresh token for someone else's failure. Three sibling SDKs
  enforce this with an explicit `/oauth2/*` skip list; this SDK has always enforced it
  **structurally**, by installing no reactive 401 interceptor on its `reqwest::Client`
  at all. That made the SDK correct but the reason invisible: a future maintainer adding
  blanket retry-on-401 middleware would have broken a contract MUST with no compile error
  and no obvious symptom. The invariant, and what a future interceptor would have to do
  instead, are now stated on `AxiamClientInner::http` and on `AxiamClient::http()`. The
  regression test that pins it
  (`introspect_401_becomes_oauth_protocol_error_and_does_not_trigger_the_refresh_guard`)
  already existed and is named from the docs so the two stay connected.

- **Vendored `proto/axiam/v1/token.proto` re-synced** to pick up `cnf`,
  `token_type`, `scope`, `client_id`, `permissions` and `ext_exchange_iss` on
  the token responses.

  Additive proto fields are wire-compatible, but Rust struct literals are
  exhaustive — so **code that constructs `ValidateTokenResponse` or
  `IntrospectTokenResponse` literally will stop compiling** until it adds the
  new fields or `..Default::default()`. In practice that means mock servers,
  not production code, which reads the responses rather than building them.
  This crate's own test mocks now use `..Default::default()` so they do not
  need editing again the next time the schema grows.

- **CONTRACT.md §10.1 rule 9 — sender-constrained (certificate-bound) access tokens**
  (contract 1.15, RFC 8705 §3 / RFC 7800). AXIAM can now issue tokens carrying a
  `cnf.x5t#S256` confirmation naming the client certificate they were issued to. Such a
  token is **not** a bearer token, and a guard that accepts it without checking has
  silently converted it back into one.
  - `Claims::cnf` (`CnfClaim`) — the decoded confirmation claim.
  - `Claims::verify_certificate_binding(Option<&str>)` — the rule, standalone. Available
    with **no features enabled**: it is pure claim logic, and a `--no-default-features`
    consumer must be able to apply it to a token it obtained through its own transport.
  - `JwksVerifier::verify_sender_constrained(token, presented_thumbprint)` — the guard
    entry point for a resource server that accepts bound tokens.
  - `certificate_thumbprint_s256(der)` — RFC 8705 §3.1 `x5t#S256`: base64url, **unpadded**,
    SHA-256 over the DER certificate. Feature-gated (`rest`/`actix`/`amqp`) because it needs
    `sha2` and `base64`; most callers already have the thumbprint from their TLS stack.

  **This is not a breaking change and does not make certificates mandatory.** An *unbound*
  token is still accepted with or without a certificate present — asserted directly by
  `an_unbound_token_is_accepted_with_or_without_a_certificate`, because the likeliest wrong
  implementation of this rule is one that starts demanding certificates from every caller.

  Two design points worth knowing at the call site:

  - **`verify()` does not enforce rule 9**, deliberately: it has no transport to ask, and
    folding an `Option<&str>` into it would have every existing caller pass `None`, which
    reads as "no certificate" and rejects every bound token. Use
    `verify_sender_constrained` where bound tokens are in play.
  - **The thumbprint must come from the transport** — the TLS peer certificate, or a value
    a *trusted* terminating proxy forwarded over a channel you control. Never from a
    caller-settable request header; a forgeable input makes the mechanism decorative.

  A `cnf` naming a confirmation method this SDK cannot check (a DPoP `jkt`, say) is
  **rejected**, never read as "unconstrained" — otherwise a sender-constrained token
  silently degrades to a bearer token the day a newer AXIAM issues a constraint this SDK
  predates.

- **CONTRACT.md §21** — the FAPI 2.0 posture as an SDK sees it: client-registration fields
  (`profile`, `token_endpoint_auth_method`, the `tls_client_auth_*` parameters,
  certificate binding), RFC 9207 `iss` on authorization responses, and the discovery
  additions. Only rule 9 above is normative for this SDK; the rest is informative.

### Changed

- **Re-sync vendored `CONTRACT.md` / `openapi.json` to contract 1.15.** The spec gains the
  `ClientProfile`, `ClientAuthMethod` and `CnfClaim` schemas and seven client-registration
  fields.

- **Re-sync vendored `CONTRACT.md` to contract 1.14** — documentation only, no code change.
  §20.2 rule 6 (a permission ticket MUST NOT be retried) cited a "measured residual
  (ilpanich/axiam#302) … roughly 1 in 640" as its second reason. That residual is closed: the
  server now decides the ticket race with a transaction its storage engine arbitrates plus a
  redemption nonce read back after the commit. **The rule is unchanged, and this SDK's
  behaviour is unchanged** — `uma_exchange_ticket` stays excluded from every automatic retry
  path. What changed is the reasoning: the first reason (a spent ticket makes the retry
  useless) always stood alone, and the second now rests on what an SDK can actually know —
  it is talking to a server whose storage engine it cannot attest, and the guarantee is
  conditional on that engine being persistent.
- **BREAKING (contract 1.13): `TokenExchangeParams::subject_token_type` is now required**, and
  its type narrows from `Option<String>` to `String`. `TokenExchangeParams::new` takes it as a
  second argument.

  It shipped optional, defaulting to `ACCESS_TOKEN_TYPE` when `None` — which satisfied §15.7's
  "never inspect the subject token" while leaving the rule it serves unenforced: an optional
  field with a default *is* a default the SDK applies whenever the caller says nothing. §15.1
  now makes it required.

  **Dropping the `Option` is the point rather than a side effect.** A field that can hold "no
  answer" forces the SDK to have an answer ready for that case, and any answer it picks is the
  guess §15.7 forbids. A plain `String` cannot represent "the caller declined to say", so the
  type system carries the rule and omitting it does not compile — asserted by a `compile_fail`
  doc-test, which will fail the build if a default is ever reintroduced. (A `trybuild` UI case
  would have been the other option, but this repo's UI suite deliberately avoids depending on
  rustc's diagnostic formatting.)

  **Migration** — one argument, naming what you were previously getting by silence:

  ```rust
  let params = TokenExchangeParams::new(
      Sensitive::new(user_token),
      ACCESS_TOKEN_TYPE,          // <- add this
  );
  ```

  This closes a gap rather than opening one: `subject_token_type` has always been required *on
  the wire*, and the SDK was covering for that with a constant which stopped being the only
  legal value when X4 landed. For a caller who actually held a refresh token, the old default
  traded the `invalid_request` that names the type for a generic `invalid_grant`.

### Added

- **§15.7 external-IdP subject tokens (X4).** `token_exchange` can now exchange a token minted
  by a trusted external IdP — a partner's Entra, Okta or Keycloak — for an AXIAM token scoped
  to what the resolved AXIAM user may actually do. No new operation: the same method, plus
  `TokenExchangeParams::subject_token_type` and the new `JWT_TOKEN_TYPE` constant alongside the
  existing `ACCESS_TOKEN_TYPE`.

  **The type is the caller's to name, never the SDK's to guess.** §15.7 forbids inspecting the
  subject token to pick it, because which kind of token you hold is something only you know and
  a wrong guess is the difference between a request that is refused and one that is silently
  reinterpreted. A JWT-shaped subject token does **not** change what is sent, which is asserted
  by a test. (This shipped with an `…:access_token` default; contract 1.13 removed it — see
  *Changed* above.)

  Also asserted: an `actor_token` alongside an external subject token surfaces `invalid_request`
  with no retry and no request rewriting; a refused refresh or ID token type is never retried as
  a different type; the one normative description — `the subject token's issuer is not
  configured for token exchange`, meaning *fix the AXIAM trust config* rather than *fix your
  token* — reaches the caller intact; and nothing re-exchanges an exchanged token, which both
  server paths refuse because exchanges do not compose.

  `CONTRACT.md` and `openapi.json` re-synced from `ilpanich/axiam@main` (contract 1.10 → 1.12
  plus §15.7), which also brings contract 1.11's lifted §12.6 deferral, contract 1.12's
  `/oauth2/*` error rows dispatching on the `error` field at any status, and the
  `TokenExchangeTrust` schemas behind the X4 provider configuration.

- **§20.3 challenge emission wired into the §11 route guard.** `RequireAccess::with_uma_challenge`
  takes a new `middleware::UmaChallenger`; on denial the guard mints a permission ticket for
  the action it just refused and returns `WWW-Authenticate: UMA` alongside the 403. New
  `AuthzGuardError::DeniedWithChallenge` carries the formatted header, because minting is a
  wire call and `ResponseError::error_response` is synchronous — by the time the variant
  exists the ticket is already in hand.

  **Opt-in by construction.** Emitting a challenge means minting a credential, so a guard
  that did it by default would turn every unauthorized request into a Protection API call.
  And **failure is not escalation**: if minting fails the denial still surfaces as a plain
  403, because a caller who was going to be refused is refused either way and an outage must
  not turn a deny into a 500 — still less into an allow.

- **A runnable UMA example pair**: [`examples/uma_resource_server.rs`](examples/uma_resource_server.rs)
  mints a PAT, registers a resource and guards a route with the challenger;
  [`examples/uma_client.rs`](examples/uma_client.rs) catches the refusal, parses the
  challenge, **makes the trust decision about `as_uri` explicitly**, exchanges the ticket and
  retries with the RPT. The client half exists partly to show what §20.3 is protecting: the
  `as_uri` is chosen by the server you just failed against, and the example refuses to redeem
  against a host that is not the issuer it already trusts.

- **§20 UMA 2.0 — Protection API and ticket grant (contract 1.10).** New `uma` module:
  `uma_register_resource` / `uma_read_resource` / `uma_update_resource` /
  `uma_delete_resource` / `uma_list_resources`, `uma_request_ticket`,
  `uma_exchange_ticket`, and the `WWW-Authenticate: UMA` challenge helpers
  (`uma_parse_challenge`, `uma_challenge_header`).

  Two behaviours are load-bearing rather than incidental, and both are asserted at
  the wire. **`uma_exchange_ticket` never retries** — it is the one documented
  exception to the §16 retry policy, because a ticket is consumed before the
  request is evaluated, so a retry cannot succeed and under concurrency is exactly
  the second redemption that ilpanich/axiam#302's measured residual describes.
  And **`uma_parse_challenge` does not exchange the ticket it parsed**: the
  `as_uri` names an authorization server the client has not chosen to trust.

  The PAT is an explicit parameter on every Protection API call rather than being
  taken from the client's session, because that session is usually a *user*
  session and a ticket binds to a `client_id`.

- **§19 `TelemetryEvent::ConfigClamped` (contract 1.9).** The SDK now reports a clamped
  setting at construction rather than applying it silently — currently the §17.1 rule 2 memo
  TTL. Clamping is right; clamping *silently* is not: an operator who set a 60-second TTL
  believes their staleness bound is 60 seconds, and it is five. Nothing is emitted for a value
  already within its limit, or for the disabled default — an event that fires when nothing
  happened trains its reader to ignore it.

### Changed

- Re-vendored `CONTRACT.md` at **1.10** and `openapi.json` with the UMA paths.

## [Unreleased]

### Added

- **§16 bounded read-only retry policy.** §11.2 rule 5 and §14.2 rule 6 had both been
  *requiring* retries "under the SDK's existing bounded read-only retry policy" while no
  such policy existed in the contract; this crate's improvisation was `backon`'s defaults
  with `with_max_times(2)`. Contract 1.8 wrote the table down and `src/retry.rs`
  implements it: 3 attempts, 200 ms base, 5 s cap, **full jitter** over `[0, backoff]`,
  and `Retry-After` honored as a floor. Hand-rolled rather than reconfigured because
  `backon`'s `with_jitter()` adds a value in `[0, min_delay)` — a much narrower
  distribution, and partial jitter is what *causes* the thundering herd retries are meant
  to prevent — and because it has no seam for `Retry-After`. Both non-deterministic inputs
  are injected, so the tests pin the jitter fraction to 0.0 and 1.0 to prove the range and
  record delays instead of sleeping.
- **§18 deterministic shutdown.** `AxiamClient::close()`, idempotent, with use-after-close
  raising rather than silently reconnecting. It does **not** log out and never reaches the
  network: the server-side session outlives the client object, and a `close()` that logged
  out would end every user's session on each deploy.
- **§19 telemetry hooks.** `AxiamClientBuilder::telemetry_hook` and the `telemetry` module,
  so callers can wire OpenTelemetry or Prometheus without this crate depending on either.
  A panicking hook cannot fail the operation that fired it, and `TelemetryEvent` has a
  closed field set so no payload can carry a token. One request pair per *attempt*, not per
  logical call, so callers can count real wire calls.
- **§17 client-side decision memo — opt-in, off by default.**
  `AxiamClientBuilder::decision_memo_ttl`, TTL clamped to 5 s. Allows and denies are
  memoized identically (asymmetric caching leaks the outcome through latency), failures
  are never memoized, and the memo is cleared on any credential change. **Reads-your-own-
  writes is not guaranteed** — an admin UI that grants a role and immediately re-checks is
  the case that breaks, and it breaks silently.
- `AxiamClientBuilder::retry_enabled` (§16.6), default on. There is deliberately no knob
  for the attempt cap, base or delay cap: §16.1 forbids raising them.
- `examples/telemetry_hook.rs` — a runnable §19 sink aggregating request counts, latency
  and retries, with the exact OpenTelemetry mapping alongside it. Running it against an
  unreachable host prints `count=3` and `retries=2`, which is the §16 attempt cap made
  observable: without the hook a retried call is indistinguishable from a slow one.

### Removed

- The direct `backon` dependency. Nothing referenced it after §16 landed; it remains in
  the lockfile only as a transitive dependency of `lapin` under the `amqp` feature.

### Changed

- Re-vendored `CONTRACT.md` at **1.8**. `openapi.json` is unchanged — 1.8 is docs-only.
- `check_access`/`can`/`batch_check` now run under the §16 runner rather than `backon`, so
  they gain full jitter and `Retry-After` handling. The retry-eligible set is unchanged and
  remains authz reads only; no mutation became retryable.

### Notes

- `Retry-After` is **not** clamped to the 5 s delay cap. That cap governs the computed
  backoff, while §16.1 makes the hint a floor with no ceiling — clamping it would retry
  sooner than the server said it would be ready. Exposure stays bounded by the attempt cap.
- The hint rides on an internal type rather than on `AxiamError`. §16 requires the policy
  to *honor* `Retry-After`, not callers to read it, so the public error type is unchanged.
- `backon` remains a dependency; removing it is a separate cleanup once the other call
  sites migrate.

## [1.0.0-alpha24] - 2026-08-04

### Added

- Enforce the full CONTRACT §10.1 local-verification set
- Add CONTRACT §13 verify_webhook; trim build-time dependency surface

### Changed

- Add the §10.1 rule-8 guardrail regression tests (#43)
- Device (mTLS) tokens now carry aud=axiam:m2m (#42)
- Service accounts can use login_client_credentials (#41)
- Bump github/codeql-action from 4 to 4.37.4
- Bump taiki-e/install-action from 2.85.2 to 2.85.5
- Sync CONTRACT.md §10.1 rule 8 — subject of the decision (#38)

## [Unreleased]

### Security — BREAKING

- **`JwksVerifier::verify` now applies the complete CONTRACT §10.1 "minimum
  local-verification set".** §10.1 is a new normative section written because
  `SEC-071` and `SEC-080` were the same defect found independently in two
  SDKs: each verified a *different subset* of the token, and each subset
  looked complete in isolation. This SDK was audited against the stated
  complete set for the first time; three rules were missing and are now
  enforced. Every §10 / §11 entry point routes through the same call — the
  Actix `AxiamUser` extractor, and the `require_auth` / `require_access` /
  `require_role` macros, which inject that extractor rather than verifying
  anything themselves.

  This **tightens acceptance** and is therefore breaking, as §10.1 requires it
  to be called out. A token minted by the AXIAM server is unaffected — it
  always carries `exp` and never a future `nbf` — but a guard fed tokens from
  another signer sharing the organization JWKS may start rejecting what it
  used to accept. That is the intent.

  - **`nbf` is now honoured (rule 3).** `jsonwebtoken` defaults `validate_nbf`
    to `false`, so a token dated into the future previously verified.
    `validate_nbf` is now enabled; an absent `nbf` remains valid.
  - **`tenant_id` is now asserted (rule 4).** The `/oauth2/jwks` trust anchor
    is *organization-wide*, so a valid signature only ever proved "some tenant
    in this organization". `verify` now requires an expected tenant, set with
    the new `JwksVerifier::expect_tenant_id(Uuid)`, and rejects a token whose
    `tenant_id` is absent, unparseable, or different. **A verifier with no
    expected tenant configured now rejects every token (fail closed).** Any
    application registering a `JwksVerifier` as Actix `app_data` for the §10
    extractor must add `.expect_tenant_id(...)`; an `AxiamClient` built with
    `tenant_id(uuid)` pre-configures the verifier it owns.
  - **Clock skew is now a named, bounded constant (rule 7).** The previous
    inline `validation.leeway = 0` becomes the exported
    `axiam_sdk::token::CLOCK_SKEW_LEEWAY_SECS` at the contract's RECOMMENDED
    60 seconds, applied to both `exp` and `nbf`. It is deliberately not
    operator-configurable, so it can never be widened to an unbounded value.
    Note this makes the `exp` check 60 s *more* tolerant than before.
  - `exp` (rule 2) and the `alg`-pinned signature check (rule 1) were already
    correct and are unchanged: `Claims::exp` is a non-`Option` `i64` and
    `required_spec_claims` contains `"exp"`, so an absent or non-numeric `exp`
    was — and is — rejected; `alg` is read from the header and compared to
    `EdDSA` *before* the JWKS is consulted, so `alg: none` and an HS-signed
    token bearing an EdDSA `kid` are both rejected without a key lookup.

- The client's own session-absorption path (`login`/`verify_mfa`/`refresh`/
  `logout`) now calls a new crate-internal `verify_session_token` instead of
  `verify`. It applies every §10.1 rule except the tenant assertion, which
  cannot apply there: that path decodes a token the client just received over
  TLS from its own authenticated request, and the `tenant_id` claim is what it
  is *learning* (a `tenant_slug`-built client has no tenant UUID to compare
  against yet). No public API changes; no relaxation of any check that
  previously ran on that path.

### Added

- **Conditional issuer/audience expectations (CONTRACT §10.1 rules 5 and 6).**
  New `JwksVerifier::expect_issuer(impl Into<String>)` and
  `JwksVerifier::expect_audience(impl Into<String>)`, both optional and unset
  by default — the rules are explicitly conditional on configuration, and the
  SDK never hardcodes an expected issuer. When configured, a mismatched value
  is rejected, and the corresponding claim additionally becomes required (an
  absent `aud` does not "contain" the expected audience).
- **`JwksVerifier::verify_signature_only_unchecked`** — the §10.1 raw
  signature-only primitive, for integrators deliberately implementing their
  own policy. It verifies the EdDSA signature and *nothing else*: no `exp`,
  `nbf`, `tenant_id`, `iss` or `aud` check. The `_unchecked` suffix is the
  contract's reference spelling, chosen so the omission is obvious at the call
  site. It is not, and must not become, the documented guard entry point.
- `tests/local_verification_set_test.rs` — the complete §10.1 required
  negative-test set: expired; no `exp`; non-numeric `exp`; future `nbf`;
  different tenant; no `tenant_id`; no configured tenant; `alg: none`;
  HS-signed token bearing the EdDSA `kid`; foreign signature; plus
  issuer-mismatch and audience-mismatch cases for the newly-configurable
  expectations, and proof that the raw primitive waves through exactly what
  the guard rejects.
- CONTRACT.md in this repository is re-synced with the upstream
  `ilpanich/axiam` copy: §10.1 is vendored verbatim.

### Added

- **Webhook signature verification (CONTRACT §13, T-145).** New
  `axiam_sdk::webhook::verify_webhook`: HMAC-SHA256 over `<t>.<raw_body>`,
  `t=`/`v1=` header parsing with forward-compatible unknown-key tolerance,
  constant-time comparison over the *decoded* MAC bytes via `subtle`, and a
  two-sided freshness window defaulting to 300 s (a future-dated timestamp is
  rejected as well as a stale one). The secret is taken as `Sensitive<String>`
  (§7) and the typed `WebhookVerifyError` never surfaces the expected
  signature. Compiled whenever `rest` **or** `amqp` is enabled — both already
  vendor `hmac`/`sha2`/`hex`/`subtle`, so no new dependency is added.
- `benches/jwks_verify.rs` — a dependency-free (`harness = false`) micro-benchmark
  for the SDK's hottest CPU path, per-request access-token verification behind
  the §10/§11 route guard, including a "floor" row that measures
  `jsonwebtoken::decode` directly so SDK-side overhead can be read off
  independently of the Ed25519 cost.

### Changed

- **`actix-web` is now depended on with `default-features = false`**
  (`features = ["cookies", "macros"]`). The SDK only uses `HttpRequest`,
  `web::Data`, `HttpResponse`, `Responder` and `ResponseError`; actix-web's
  default set additionally forced its response-compression stack
  (brotli/zstd/flate2), `h2` 0.3 — a second `h2` major alongside the 0.4 that
  tonic and reqwest already use — `encoding_rs`, `language-tags`, WebSockets
  and the `regex`-based router onto every build. A cold
  `cargo build --all-features` graph drops from 295 to 276 crates, removing
  roughly 60 s of measured compile work (zstd-sys 15.9 s, h2 0.3 15.7 s,
  brotli 8.1 s, regex-automata 7.6 s, encoding_rs 7.1 s, language-tags 5.1 s,
  regex-syntax 3.9 s). This takes nothing away from applications: an app using
  the `actix`/`macros` features has its own `actix-web` dependency, and Cargo
  unifies features across the graph.
- Documented the scope of `[profile.release]` in `Cargo.toml` and README:
  Cargo honours only the **top-level workspace's** profile tables, so the
  release-build settings in this repository govern its own examples/benches and
  are *not* inherited by consumers. README gains a "Release-profile tuning (for
  consumers)" section with the block to copy into their own manifest, and a
  "Build-time notes" section identifying `aws-lc-sys` (pulled in by `rustls`'s
  default crypto provider via both `reqwest` and `lapin`) as the dominant
  remaining cold-build cost.

### Removed

- The `[profile.release]` table in `axiam-sdk-macros/Cargo.toml`. Cargo ignores
  profile tables in non-root workspace members and printed
  "profiles for the non root package will be ignored" on **every** cargo
  invocation in this repository; the table had no effect other than that
  warning. The workspace-root profile already covers both members.

## [1.0.0-alpha23] - 2026-08-02

### Changed

- Maintenance release — no notable changes since v1.0.0-alpha21.

## [1.0.0-alpha21] - 2026-07-30

### Added

- Add OIDC/SSO relying-party helpers (CONTRACT §12)

### Changed

- Re-sync vendored CONTRACT.md to contract 1.6
- Update base64 requirement from 0.22 to 0.23
- Update ed25519-dalek requirement from 2 to 3
- Update jsonwebtoken requirement from 10 to 11
- Bump coverallsapp/github-action from 2.3.7 to 2.3.8
- Bump taiki-e/install-action from 2.84.0 to 2.85.2
- Re-sync vendored CONTRACT.md to contract 1.5

### Fixed

- Publish the single-flight refresh outcome before vacating the slot
- Read axiam_refresh from its REFRESH_PATH-scoped URL, not base_url (H8 SDK bench)
- Disable aud validation in JwksVerifier::verify (H8 SDK bench)
- Share the single-flight oidc_refresh result (CONTRACT §9 rule 2)

## [Unreleased]

### ⚠ Breaking

This release is **source-breaking for downstream code that constructs
`AxiamError` variants with struct-expression syntax.** The earlier draft of
these notes described the §12 work as "additive, not breaking"; that was
wrong, and this section replaces it.

- **`AxiamError::Auth` gained two fields** (`oauth: Option<OAuthProtocolError>`
  and `reason: Option<IdTokenFailureReason>`) for CONTRACT.md §12.3 rule 3 and
  §12.4. Because the variant was not `#[non_exhaustive]`, that addition alone
  already broke downstream code: every `AxiamError::Auth { message: … }`
  construction became `E0063` (missing fields) and every exhaustive
  destructure `AxiamError::Auth { message }` became `E0027`. 33 constructions
  and 9 patterns inside this repository — including one in a shipped
  `examples/` file — had to be rewritten. Nothing prevented the same break
  recurring on the next field addition.
- **All three variants are now `#[non_exhaustive]`** (`Auth`, `Authz`,
  `Network`) so that no future field addition can break a consumer again. The
  cost is a one-time break, taken deliberately at `1.0.0-alpha18`:
  - **Constructing** a variant from outside this crate with struct-expression
    syntax is no longer possible (`E0639`). Use the constructors instead — the
    new `AxiamError::auth`, `AxiamError::authz`, `AxiamError::network`,
    `AxiamError::network_with_source`, alongside the existing
    `AxiamError::oauth_protocol_error`, `AxiamError::id_token_invalid`,
    `AxiamError::from_http_status` and `AxiamError::from_grpc_code`. They cover
    every shape the SDK itself builds.
  - **Destructuring** now requires a trailing `..`
    (`AxiamError::Auth { message, .. }`, `E0638` without it). Patterns that
    already ended in `..` — including every `matches!(e, AxiamError::Auth { .. })`
    — are unaffected.
  - The **enum itself is deliberately *not* `#[non_exhaustive]`**: CONTRACT.md
    §2 fixes the taxonomy at exactly three error types, so no fourth variant
    can ever be added and `match`ing all three exhaustively stays valid.
- **`AxiamClient::oidc_begin` now panics** instead of returning
  `Err(AxiamError::Network { .. })` when caller-supplied `extra_params` try to
  override one of the eight SDK-owned authorization query parameters. Per
  CONTRACT.md §12.1 rule 5 that is a programming error, not a §2 taxonomy
  outcome; every sibling SDK raises its language's unchecked
  programming-error type there, and a panic is Rust's equivalent. Correct code
  cannot trigger it — the condition depends only on parameter names the
  calling code chooses. Tenant/organization resolution failures remain
  `AxiamError::Auth` (§12.3 rule 4).
- **`AxiamClient::sso_complete` now fails** (with `AxiamError::Auth`) when the
  callback response sets no usable `axiam_access` cookie, where it previously
  returned `Ok`. This is the same behaviour `login()` has always had, and is
  required by the post-login session sync described under *Fixed* below.

### Added

- CONTRACT.md §12 OIDC/SSO relying-party helpers (contract 1.4): nine new
  methods directly on `AxiamClient` — `oidc_discover`, `oidc_begin`,
  `oidc_exchange`, `oidc_refresh`, `login_client_credentials`, `introspect`,
  `revoke`, `sso_start`, `sso_complete` — covering "Login with AXIAM"
  (authorization-code + PKCE, S256-only), service-account
  `client_credentials` login, RFC 7662 introspection, RFC 7009 revocation,
  and the upstream-IdP federation SSO pair. New module `src/oidc/`
  (`discovery`, `authorize`, `exchange`, `state`, `id_token`).
- Full CONTRACT.md §12.4 ID-token validation checklist (`EdDSA`-only,
  single-JWKS-refetch-on-unknown-`kid`, issuer/audience/time/nonce checks,
  all-or-nothing discard), extending the existing `JwksVerifier` rather than
  forking it.
- `OidcStateStore` trait + `MemoryOidcStateStore` reference implementation
  (10-minute TTL, single-use `consume`) for framework glue bridging the
  login-redirect and callback requests — strictly optional; the core
  operations remain stateless (§12.3 rule 1).
- `AxiamClientBuilder::oidc_client_id`/`oidc_client_secret`/
  `oidc_discovery_ttl`/`oidc_clock_skew` builder methods.
- `OAuthProtocolError`, a language-idiomatic sub-type of the existing
  `AxiamError::Auth` (carried via its new `oauth` field, not a new top-level
  error variant), for RFC 6749 `OAuth2ErrorResponse` bodies from
  `/oauth2/*`. `AxiamError::Auth` also gained a `reason: Option<IdTokenFailureReason>`
  field carrying the stable §12.4 reason code for ID-token validation
  failures. Existing `AxiamError::Auth { message, .. }` **matches** keep
  compiling and keep catching these as authentication failures; **constructions
  and exhaustive destructures do not** — see the ⚠ Breaking section above.
- Public `AxiamError` constructors — `auth`, `authz`, `network`,
  `network_with_source` — so downstream code can build the taxonomy variants
  without struct-expression syntax now that they are `#[non_exhaustive]`.
- `Clone` for `Sensitive<T>` (hand-written, not derived) and for
  `OidcTokenSet`. Required by CONTRACT.md §9 rule 2: the single in-flight
  `oidc_refresh` must hand the *same* token set to every concurrent waiter.
  Cloning duplicates the redacting wrapper, never the exposure — `Debug` and
  `Display` still redact on a clone, and `expose()` remains the one and only
  accessor. `Serialize`/`Deserialize` remain deliberately unimplemented.
- New example `examples/oidc_login.rs`.

### Fixed

- **`oidc_refresh` now satisfies CONTRACT.md §9 rule 2 (result sharing).** It
  previously took a bare `tokio::sync::Mutex<()>` with no result slot, so a
  burst of N concurrent callers produced **N serialized wire calls**; because
  AXIAM refresh tokens are single-use with rotation, callers 2..N replayed an
  already-consumed token and each failed `invalid_grant`. The mutex is
  replaced by a leader/waiter election over a shared publication — a
  `watch::Sender` carrying `Running | Settled(Result<OidcTokenSet,
  Arc<AxiamError>>) | Cancelled` (`src/oidc/single_flight.rs`): exactly one
  caller per burst performs the wire call and publishes its outcome, and every
  other caller receives *that* outcome — the same token set on success, an
  equivalent error (same taxonomy variant, same `oauth` payload, same `reason`)
  on failure. A cancelled leader publishes a typed `Cancelled` state and
  releases the slot rather than wedging the guard. No new dependency: `tokio`'s
  `sync` feature was already enabled. Covered by ≥5-caller burst tests for both
  the success and failure paths, each asserting exactly one request reaches the
  server.
- **`oidc_refresh`'s single-flight guard no longer has a publish/retire race
  that could issue a second, doomed `refresh_token` grant.** The guard's first
  implementation held a `tokio::sync::broadcast::Sender` and had to retire the
  in-flight slot *before* sending (a `broadcast` receiver never observes sends
  that predate its `subscribe`, so a caller subscribing after the send would
  have hung). That left the slot **empty while the refresh had already
  settled**: a concurrent caller landing there — no `.await` separates the two
  statements, but another runtime worker thread can — became a second leader
  and replayed the single-use refresh token the first leader had just consumed,
  failing `invalid_grant`. The slot now holds a *value-retaining*
  `tokio::sync::watch` publication, so **publication precedes vacating the
  slot**: a caller at any instant either joins the shared outcome or finds the
  slot empty with the refresh already settled and published, never "empty and
  nothing published". Occupancy alone no longer means "join this": a `Settled`
  publication is joinable (and cannot be stale — while it occupies the slot no
  later refresh can have been elected), a `Cancelled` one never is, and a
  caller arriving once the slot is empty still starts a genuinely fresh
  refresh rather than being handed the previous burst's tokens. Observable §9
  behaviour is unchanged: one wire call per burst, that outcome shared, no
  retry loop, and a cancelled leader still frees the slot and wakes its
  waiters (now with a typed cancellation signal instead of a channel-closed
  error).
- **`oidc_begin` now percent-encodes spaces as `%20`, not `+`.**
  `url::Url::query_pairs_mut` is an `application/x-www-form-urlencoded`
  serializer, so a multi-valued `scope` was emitted as
  `openid+profile+email`; CONTRACT.md §12.1 rule 5 requires literal RFC 3986
  encoding, which is what every other AXIAM SDK emits. The query component is
  now re-encoded before the URL is returned.
- **`sso_complete` now performs the post-login session sync.** It captured
  cookies and the CSRF token but never ran `absorb_session_cookies`, so it did
  not seed the token manager or resolve `tenant_id`/`org_id` — a subsequent
  `refresh()` failed with "no access token to refresh". It now runs the exact
  same sync `login()`/`verify_mfa()` do (CONTRACT.md §4/§3), leaving the client
  in an identical authenticated state.
- Removed an unreachable tenant-context guard in `sso_start`
  (`TenantIdentifier` is a two-variant enum and §5 guarantees one is set), and
  corrected the `compute_code_challenge` doc link, which pointed at
  `tests/oidc_pkce_test.rs` for the RFC 7636 Appendix B vector that actually
  lives in this module's own unit tests. `oidc::id_token::ID_TOKEN_ALG` is no
  longer a dead constant — it is the single definition of the wire spelling
  reported in the `invalid_alg` error.

### Changed

- `Sensitive::expose()` is now `pub` (previously `pub(crate)`): §12's
  `OidcTokenSet` hands `access_token`/`refresh_token`/`id_token` directly to
  the caller (unlike the §1 cookie-only session), so a relying party needs a
  way to read them back out to use them. Still the only path to the wrapped
  value; still never touched by `Debug`/`Display`.
- Conformance statement updated to "CONTRACT.md §1–§12 (including §6.1
  mTLS)".

## [1.0.0-alpha18] - 2026-07-24

### Changed

- Update syn requirement from 2 to 3 (#24)
- Bump dtolnay/rust-toolchain (#20)
- Bump taiki-e/install-action from 2.83.2 to 2.84.0 (#21)
- Bump actions/checkout from 7.0.0 to 7.0.1 (#22)
- Update rcgen requirement from 0.13 to 0.14 (#23)
- Rust SDK 89.3% → ≥92% + ratchet gate 89→90 (Phase C) (#26)

### Fixed

- Use CertifiedKey.signing_key for rcgen 0.14 API rename (#27)

## [1.0.0-alpha17] - 2026-07-22

### Changed

- Updated dependencies

## [1.0.0-alpha16] - 2026-07-22

### Added

- Add get_user_info (UserInfoGrpcClient)

### Changed

- Exclude generated gRPC stubs from the line-coverage gate
- Expand userinfo coverage above the 89% gate
- Vendor userinfo.proto + CONTRACT 1.3

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
