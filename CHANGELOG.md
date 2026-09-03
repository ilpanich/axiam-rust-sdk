# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0-beta10] - 2026-09-03

### Changed

- Maintenance release — no notable changes since v1.0.0-beta09.

## [1.0.0-beta09] - 2026-09-02

### Changed

- Maintenance release — no notable changes since v1.0.0-beta08.

## [1.0.0-beta08] - 2026-09-02

### Added

- The four public "Sign in with X" operations (CONTRACT §12.1, 1.38)

- **Contract 1.38: the four public "Sign in with X" operations.** `sso_providers`,
  `sso_start_oauth2`, `sso_complete_oauth2` and `sso_complete_handoff`, under the
  exact CONTRACT.md §12.2 Rust names, as methods on `AxiamClient` beside the nine
  §12 operations that came before — §12.2's host rule is unchanged by their
  arrival, and this SDK has no packaging constraint that would justify a second
  host. New module `src/oidc/federation.rs`; new public types
  `oidc::FederationProvider` and `oidc::FederationProviderList`, matching the
  §12.1 SDK-type table. Upstream: ilpanich/axiam#398.

  Four things worth naming, because each is a rule an implementation can satisfy
  by accident and break by accident:

  - **An empty provider list is a success** (§12.1 note 9). An unknown
    organization, a known one with nothing configured, and a request naming no
    workspace at all all answer `200 []`. `sso_providers` returns `Ok` with an
    empty list for every one of them and synthesises no not-found: the endpoint
    is shaped so it cannot enumerate organization or tenant slugs, and an SDK
    that told the three apart would rebuild that oracle in the client.
  - **`protocol` selects the start operation** (§12.1 note 10), never
    `provider_kind`: `OidcConnect` → `sso_start`, `OAuth2` → `sso_start_oauth2`,
    `Saml` → the SAML login endpoint, which is not a §12 vocabulary operation.
    `FederationProvider::protocol` is therefore surfaced as the wire string,
    alongside `PROTOCOL_OIDC_CONNECT` / `PROTOCOL_OAUTH2` / `PROTOCOL_SAML` to
    compare against; narrowing it to an SDK enum would turn a value added
    server-side into a deserialization failure for the whole list.
  - **PKCE on the OAuth2 variant is server-side** (§12.1 note 11). This SDK
    computes no verifier and sends no challenge on that path, and a test asserts
    the absence rather than leaving it to be noticed.
  - **A `400` from a start call is a configuration refusal** (§12.1 rule 12a,
    new at 1.38). On the SAML and Apple flows the identity provider never
    validates the SPA `redirect_uri`, so the server confines it to its own issuer
    origin plus `AXIAM__AUTH__SSO_SPA_ORIGINS`. It surfaces as
    `AxiamError::Network` — §2's `400` row, the taxonomy's
    configuration/programming-error member, distinct from the `AxiamError::Auth`
    a `401` gets — and is not retried, because the deployment will refuse the
    same origin every time.

  `oidc::HANDOFF_QUERY_PARAM` (`axiam_handoff`) and `oidc::HANDOFF_CODE_TTL_SECS`
  (60) are exported for callers driving the browser hop, in the same style as the
  module's existing protocol constants. A handoff `401` is terminal: the
  redemption makes exactly one wire call, so it cannot become a retry by
  accident.

- `tests/oidc_login_providers_test.rs` — 17 tests. The wire-shape half reads the
  vendored `openapi.json` and asserts method, path, media type, the success
  schema names, that the `sso_providers` identifiers are declared `in: query`,
  and that neither OAuth2 start schema carries PKCE material; the SDK half
  asserts that what actually reaches the wire matches. The rule half covers note
  9 (all three empty-list cases), note 10 (all three dispatch branches, with a
  `Saml` provider whose `provider_kind` is `google` so that a kind-based dispatch
  fails), note 12 (a handoff `401` is terminal and exactly one request is sent)
  and rule 12a (a `400` from either start operation is `Network`, not retried,
  and does not collapse into the `401` case).

### Changed

- Regenerate the §27 surface from the re-vendored artifacts

- State contract 1.38 conformance and document the thirteen §12 operations

- Wire shape and the four load-bearing rules for the 1.38 operations

- Re-vendor CONTRACT.md 1.38, openapi.json and management-registry.json

- Bump taiki-e/install-action from 2.86.5 to 2.87.0

- Bump github/codeql-action/upload-sarif

- Update argon2 requirement from 0.5 to 0.6

- Re-vendored `CONTRACT.md` (1.29 → 1.38), `openapi.json` and
  `management-registry.json` byte-for-byte from `ilpanich/axiam@1c457f6`.
  `proto/axiam/v1/`, `opaque-test-vectors.json` and `vendor/axiam-opaque/src`
  did not change upstream and were re-verified as already identical rather than
  re-copied. `management-registry.json` moves only its `spec_digest`:
  `operation_count` stays at 155, so the §27 surface is untouched.

- The README's contract-conformance statement now names **contract 1.38** and
  §12's thirteen operations; the §12 section documents the four new ones and the
  rules above.

## [1.0.0-beta07] - 2026-08-30

### Changed

- Re-vendor AXIAM contract 1.36

- **Documented contract 1.36, which this SDK already vendors.** `CONTRACT.md`,
  `openapi.json` and `management-registry.json` were re-vendored from the
  `sdks/` sources in [`ilpanich/axiam`](https://github.com/ilpanich/axiam)
  (ilpanich/axiam#396) as part of the 1.0.0-beta06 release, whose note recorded
  only "no notable changes". That understated it — the contract moved in that
  release — and v1.0.0-beta06 is tagged, so the correction is recorded here
  rather than by editing a released section. No SDK code changed with the
  artifacts; the three entries below are why not.

- **§5.2.2 rule 4 is new, and is an errata rather than a wire change.** The
  server now scopes every *self-service* endpoint to `principal_tenant_id`
  rather than to the acting tenant — `GET`/`PUT /users/{own id}`, that user's
  `mfa-methods`, `POST /users/{own id}/reset-mfa`, `POST /auth/mfa/enroll` and
  `/confirm`, `POST /auth/webauthn/register/start` and `/finish`, `POST
  /users/me/resend-verification`, the §25 account export and erasure for the
  caller's own id, and `GET /oauth2/userinfo`. Each of those answered `404` for
  an organization-level caller that had switched to another tenant and now
  succeeds. No request or response field is added, so nothing here is a wire
  change.

  The rule also forbids the obvious workaround: an SDK MUST NOT clear or rewrite
  the acting-tenant header for those calls, because that header is what makes
  the **administrative** form of the same endpoints reach the tenant the caller
  asked for — stripping it would break reading another tenant's user in order to
  fix reading your own. This SDK was audited for such a workaround and has none:
  the acting-tenant header is named in exactly one doc comment
  (`src/rest/auth.rs`) and is never emitted; every request sets `X-Tenant-ID`
  from `tenant_header_value()`, and nothing varies it per endpoint.

- **Issue #395 is settled: the acting-tenant header is `X-Axiam-Tenant`**, and
  §5.2, §5.2.2 and §5.2.3 now name it. The note under 1.0.0-beta05 below
  recorded the contract and the server disagreeing on it; they no longer do, and
  the name this SDK documents was already the server's. §5 rule 2's
  *unconditional* `X-Tenant-ID` is deliberately **not** renamed, and the
  contract now carries a note saying why it must not be: it names the client's
  *constructor* tenant, so folding it into `X-Axiam-Tenant` would override the
  acting tenant on every request an organization-level principal made after a
  switch. Every existing §5 rule 2 send is left exactly as it was.

- **`openapi.json` gained `/api/v1/auth/me`, `/api/v1/auth/password/change` and
  `/api/v1/admin/bootstrap`.** All three were always served and always normative
  in `CONTRACT.md`; they were missing from the generated document only because
  their handlers were never listed in its `paths(…)`. `management-registry.json`
  keeps `operation_count` at **155** — bootstrap is excluded on the §27.0
  boundary — so §27 code generation is unaffected and the generated surface is
  unchanged.

## [1.0.0-beta06] - 2026-08-30

### Changed

- Maintenance release — no notable changes since v1.0.0-beta05.

## [1.0.0-beta05] - 2026-08-30

### Added

- Contract 1.35, carrying 1.34 — service-account RBAC, principal tenant, tenant scope

- **Contract 1.35, which carries contract 1.34 with it.** Nothing had been
  fanned out since 1.33, so this re-vendors `CONTRACT.md`, `openapi.json` and
  `management-registry.json` across both revisions. The registry still holds
  155 operations across 24 namespaces — 1.35 changed only its `spec_digest` —
  so the eight §27 operations below arrived with 1.34 and are new here
  regardless.

- **§27: service accounts as RBAC principals** (contract 1.34) — eight
  generated operations: `roles.list_service_accounts`,
  `roles.assign_to_service_account`, `roles.unassign_from_service_account`,
  `groups.list_service_accounts`, `groups.add_service_account`,
  `groups.remove_service_account`, `service_accounts.list_roles` and
  `service_accounts.list_groups`. `unassign_from_service_account` takes the
  same optional `resource_id` query parameter as the user and group unassign
  calls: omitting it removes the *global* grant specifically, not every grant
  of that role.

- **§5.2.2: the acting tenant and the principal tenant are different things**
  (contract 1.34). `LoginResult` gains `tenant_id`, `principal_tenant_id`,
  `principal_tenant_slug` and `org_id`. Absent means equal — a server older
  than 1.34 omits them and cannot switch the acting tenant either, so
  `principal_tenant_id` falls back to `tenant_id` rather than to `None`. Read
  `org_id` from the session instead of resolving a slug through `GET
  /api/v1/organizations`, which is `super-admin`-only.

- **§5.2.3: tenant-scoped role assignments** (contract 1.35). `tenant_scope`
  appears on the three assignment request bodies and on the assignment objects
  the read paths return, and `LoginResult::reachable_tenant_ids` reports a
  narrowed principal's reach. Omitted means unrestricted, which is what every
  assignment written before the field existed already meant.

### Fixed

- Point the intra-doc link at where AxiamClient actually lives

- Format the new test file, and stop spelling credentials out in it

- Retain the packaged tarball so build-provenance has a subject (#90)

- **A registration record for your own password was sealed against the wrong
  tenant.** CONTRACT.md §5.2.2 rule 2: the caller's credentials live in the
  tenant the *account* lives in, not whichever tenant the client is currently
  pointed at, and a record sealed against the acting tenant is refused with
  "the OPAQUE session was issued for a different tenant".

  `opaque_enrollment` had one behaviour for a method documented for three
  callers — user creation, change-password and reset completion — and only the
  first of those wants the acting tenant. It keeps that behaviour, which is
  correct for creating *another* account; the new
  `opaque_enrollment_for_self` seals against `principal_tenant_id` and is what
  a self-service password change must call.

  The two collapse to the same request for every ordinary principal, so this
  only bit an organization-level account that had switched tenant — which is
  why it survived every test written against an ordinary one.

- **An empty `tenant_scope` is no longer put on the wire.** The server refuses
  `[]` with `400`: an assignment reaching no tenant is a grant that does not
  exist rather than a restriction. `Option::is_none` alone did not prevent it,
  because the natural way to build the field is to collect into a `Vec` and
  wrap it, which yields `Some([])` for "no tenants named". Both spellings of
  absent now serialize the same way — by not appearing.

### Note on `X-Tenant-ID` vs `X-Axiam-Tenant`

CONTRACT.md §5.2.2 and §5.2.3 name the acting-tenant header `X-Tenant-ID`, but
the AXIAM server reads **`X-Axiam-Tenant`** (`ACTIVE_TENANT_HEADER` in
`crates/axiam-api-rest/src/extractors/auth.rs`), as do its own tests, the admin
UI, and the `openapi.json` vendored alongside that contract. The server never
reads `X-Tenant-ID` at all.

Documentation added here for §5.2.3 rule 4 therefore names `X-Axiam-Tenant`,
because a tenant switch sent under the other name is not refused — it is
ignored, and the request quietly acts on the principal's own tenant instead.
The discrepancy has been reported upstream; this SDK's existing `X-Tenant-ID`
sends are left as they are, being out of scope for a contract re-vendor.

- **The release job no longer fails after publishing.** `cargo publish`
  assembles its tarball under `target/package/tmp-crate/` and deletes it once
  the upload returns, leaving only the unpacked verification directory behind.
  The `actions/attest-build-provenance` step therefore globbed
  `target/package/*.crate`, matched nothing, and failed the beta04 release with
  `Could not find subject at path target/package/*.crate` — *after* both crates
  were already live on crates.io and could never be republished.

  Both members are now packaged with `cargo package` (which runs the same
  verification build *and* retains the tarball) before being published with
  `--no-verify`, and a guard step asserts the attestation subject exists before
  anything is uploaded. The retained tarball is byte-identical to the one cargo
  uploads, so the attestation still covers exactly the bytes crates.io serves.

## [1.0.0-beta04] - 2026-08-28

### Changed

- Attest the published crates, pin actions by digest, re-vendor contract 1.33

- **CONTRACT 1.32 — signing in an organization-level principal (§5.2.1).**
  `CONTRACT.md`, `openapi.json` and `management-registry.json` re-vendored from
  the AXIAM server, where the same bug class had made an organization-level
  administrator unable to sign in at all (ilpanich/axiam#388).

  Naming no tenant now resolves the organization's own reserved scope on
  `/auth/login`, `/auth/opaque/login/start`, `/auth/opaque/register/start` and
  `/auth/webauthn/authenticate/discoverable/start`. That reserved tenant's slug
  is `organization`, so this crate reaches it through the ordinary builder and
  needs no new surface:

  ```rust
  AxiamClient::builder()
      .base_url("https://iam.example.com")?
      .tenant_slug("organization")
      .org_slug("globex")
      .build()?
  ```

  Prefer that over omitting the tenant: §5 rule 2 still requires one on the
  `X-Tenant-ID` header of every request after the login.

### Fixed

- Refuse a blank tenant_slug instead of sending it as ""

- **`build()` now refuses a blank `tenant_slug` or `org_slug`** (CONTRACT.md §5,
  §5.2.1 rule 2). `.tenant_slug("")` used to build a client that put
  `tenant_slug: ""` on the wire on every login. Nothing can carry an empty
  slug, so the server resolved nothing; on `/auth/opaque/login/start` it failed
  on the workspace *before* the tenant's OPAQUE mode was read, so the `404` of
  §23.4 rule 10 never arrived, this crate had no fallback to take, and sign-in
  failed even against a tenant with OPAQUE **disabled** — reported as `invalid
  credentials`, which sends a user off to reset a password that works.

  Checked at `build()` rather than in `tenant_slug()`, which returns `Self` and
  has nowhere to put an error. `""` is exactly as much of a tenant as none at
  all, so it earns §5's existing refusal.

## [1.0.0-beta02] - 2026-08-28

### Added

- Contract 1.31 — list search, the truthful resend, organization scope

- The manifest! declarative form, plus §27 examples

- Declarative manifests — plan and apply (§27.6)

- Generate the §27 surface — 146 operations, 24 namespaces

- **CONTRACT 1.31 — the AXIAM server PR #383 surface.** `CONTRACT.md`,
  `openapi.json` and `management-registry.json` re-vendored, and the six things
  they describe implemented.

  - **`search` on all twenty paginated management operations** (§27.4 rule 4).
    It is a third field on `PageRequest`, not a third argument on twenty
    generated `list` methods:

    ```rust
    client.users().list(PageRequest::first(50).search("ada")).await?;
    client.users().list_all(PageRequest::first(200).search("ada")).await?;
    ```

    Putting it on the page request is what makes `list_all` carry the term
    across the whole walk. A walk that filtered its first request and not the
    rest returns the matches followed by the unfiltered tail, which from the
    caller's side looks like a server bug.

    The server applies it **before** `offset`/`limit`, so `Page::total` counts
    matches rather than rows — which is what lets a pager built on it show a
    page count belonging to the result set it is paging. A blank or
    whitespace-only term sends no `search` key at all, so a search box that
    fires on every keystroke does not ask a different question once it is
    cleared. The server's length cap is deliberately **not** copied here: a
    client-side truncation the server would not have made is a silently
    different query.

  - **`resend_own_verification()`** (§25.1, §25.7) —
    `POST /api/v1/users/me/resend-verification`, for a caller that is signed in
    to the account it is asking about. It takes no address, and reports what
    happened: `Ok(())` for enqueued, a conflict for already-verified-or-
    ineligible, a network error for the daily limit.

    `resend_verification` still exists and still answers `Ok(())` whatever
    happens, because it takes an address from an anonymous caller and a truthful
    answer there is an enumeration oracle. Use the new one whenever there is a
    session — a profile page wired to the old one reports success while doing
    nothing, which is the defect the pair exists to separate. This SDK does not
    fall back from one to the other in either direction (§25.7 rule 2).

  - **`LoginResult::organization_level`** (§5.2) — whether the account that just
    signed in is an organization-level principal, whose global grants apply in
    every tenant of its organization. Check it before offering a tenant switch:
    an ordinary tenant principal changing `X-Tenant-ID` gets a `403`. `false`
    against a server older than contract 1.31, which is the safe reading of
    absent.

  - **`Tenant::kind` and `models::TenantKind`** (§27.11) — ordinary tenant or
    the organization's own scope. `None` on a row written before that scope
    existed. Read-only: it is not on `CreateTenantRequest` or
    `UpdateTenantRequest`, and a client that could set it could ask for a second
    organization scope and be refused at the database rather than at the type.

  - **`MtlsTrustAnchorResponse::trusted_anchors`** (§27.11) — how many CAs the
    live listener now trusts, when it was reloaded. `None` is **not** zero: it
    means there was no listener to ask (plaintext, or `client_auth` off), which
    is the case `restart_required: true` already reports.

  - **`Certificate::bound_service_account_id`** (§27.11) — the service account a
    certificate authenticates, resolved for a whole page in one query by
    `certificates().list()` and `None` on `certificates().get()`. The SDK does
    not spend a second request filling it in there.

### Changed

- Re-vendor openapi.json and management-registry.json from axiam main (#87)

- Re-vendor the contract artifacts: spec digest + §27.10 posture (#85)

- Gate the generated §27 surface against the registry

- Raise coverage on the paths the first pass missed

- Document the §27 management surface

- The §27.9 semantics a generator cannot write

- Generate a conformance test that reaches all 146 operations

- Re-vendor CONTRACT.md, openapi.json and the §27 registry

- **Generated management enums are now open.** A value this SDK's copy of the
  spec does not list decodes to `Unknown(String)` carrying it verbatim, instead
  of failing the response it arrived in (§27.11 rule 1). A closed enum turns the
  next `kind` or `status` the server adds into a parse error on the whole
  `list` — taking down every record on the page over one field of one of them,
  including the records the caller was after. Re-serializing round-trips the
  original string, so read-modify-write does not silently rewrite a field this
  SDK did not understand.

  Consequence: these enums are `Clone` and no longer `Copy`.

- **`PageRequest` is `Clone` and no longer `Copy`**, because it now holds an
  owned search term. Call sites that relied on the implicit copy — reusing one
  value across several `list` calls — need an explicit `.clone()`, or a fresh
  `PageRequest::first(n)` per call.

### Fixed

- Two rustdoc links in the contract 1.31 doc comments

- Resolve broken intra-doc links in the §27 management module

- **`tools/gen_management.py` no longer drops a projected list element.** The
  server answers `GET /api/v1/certificates` with `Certificate` plus one resolved
  graph edge, expressed as an `allOf` of the `$ref` and an anonymous object.
  Read as a whole, that composition has no name, so regenerating against the new
  registry crashed on `certificates.list` — a page with no element type. The
  generator now takes the base name through the `allOf` and folds the
  projection's added fields onto the base model as optional. (The registry-side
  half of this is AXIAM PR #386.)

## [1.0.0-alpha44] - 2026-08-25

### Changed

- Re-vendor openapi.json at alpha43 for tenant signing CAs (axiam#379)

- Bump taiki-e/install-action from 2.85.13 to 2.86.5

- Update scrypt requirement from 0.11 to 0.12

- Bump github/codeql-action from 4.37.7 to 4.37.8

- **Re-vendor `openapi.json` at 1.0.0-alpha43** for AXIAM server PR #379, which
  adds **tenant signing CAs**: an intermediate CA created beneath one of the
  organization's CAs and scoped to a single tenant, so a tenant's user, service
  and device certificates chain through a CA that can be revoked, rotated or
  handed to a different operator without redistributing the anchor the rest of
  the estate trusts. `CONTRACT.md` and `proto/` were untouched by that PR and are
  already current.

  This is a specification re-sync with **no SDK surface change**. CA-certificate
  administration is not part of the SDK contract — `CONTRACT.md` §1 maps no
  method onto any `/api/v1/organizations/{org_id}/...` CA route — and this SDK
  models none of the schemas below, so nothing here gains, loses, or changes a
  symbol. The spec is vendored so what this SDK is written against keeps
  describing the server it talks to.

  What moved in the spec:

  - **`POST /api/v1/organizations/{org_id}/tenants/{tenant_id}/signing-cas`**
    (`generate_intermediate`) — create a tenant signing CA under an organization
    CA, with AXIAM generating the key. Returns `GeneratedCaCertificate`; the
    private key comes back exactly once, and not at all under `vault_pki`, where
    it was born inside Vault and no API exports it.
  - **`GET .../signing-cas`** (`list_intermediates`) — a paginated list of one
    tenant's signing CAs.
  - **`POST .../signing-cas/sign-csr`** (`sign_intermediate_csr`) — the BYOK
    counterpart: sign a PKCS#10 CSR produced elsewhere, so the private key never
    reaches AXIAM at all. The response carries no `private_key_pem` because there
    is none to carry.
  - **`CaCertificate` gains two nullable fields** — `tenant_id`, the tenant a CA
    signs for, and `parent_ca_id`, the CA in the organization that signed it.
    Both are absent for an organization-level CA, which is the trust anchor and
    the only kind that existed before this change.
  - **Four new schemas**: `CreateIntermediateCa`, `CreateIntermediateCaRequest`,
    `SignIntermediateCsr` and `SignIntermediateCsrRequest`.

  The spec version moves from **1.0.0-alpha40** to **1.0.0-alpha43**; the
  intervening alpha41 and alpha42 releases changed nothing in it but that string.

### Fixed

- Drop the removed length argument from scrypt::Params::new

## [1.0.0-alpha43] - 2026-08-24

### Added

- Expose the supported-version range and pin the policy in a test (#79)

- **`axiam_sdk::supported_versions`** — `MIN_RUST_VERSION`, `EDITION` and
  `NEWEST_TESTED`, making the supported range readable from code. This crate already
  gated on both ends of that range (D-10, `toolchain: ["1.88", stable]`), which is why
  it was the model the other ten AXIAM SDKs were brought in line with; this adds the
  readable surface those SDKs now expose, so the family is consistent.

- **`tests/version_policy.rs`** — binds `rust-version`, `edition`, the CI matrix and
  the three constants together.

  Two of its assertions are worth more than the parity checks. It asserts the upper
  leg stays **`stable` rather than a pinned version**, because pinning would freeze
  the newest end at whatever was current the day someone wrote it and quietly stop
  testing anything after that — while still looking like a two-legged matrix. And it
  asserts the **MSRV is high enough for the declared edition** (2024 needs 1.85+),
  since those are set independently in the same file and lowering one without the
  other yields a manifest promising a toolchain the edition cannot compile on.

- **`examples/version_compatibility`** — reports the supported range and how to build
  against either end. Declared with no `required-features`, so it builds in the same
  minimal configuration a consumer might use.

- **A "Supported Rust versions" section in the README**, stating why the floor needs
  no preflight (Cargo enforces `rust-version` during resolution) and why the upper end
  cannot be enforced at all.

### Changed

- Nothing in the build or the CI matrix. `rust-version`, `edition` and
  `toolchain: ["1.88", stable]` are all unchanged — this crate was already correct,
  and the additions above only make that state legible and hard to drift out of.

## [1.0.0-alpha41] - 2026-08-24

### Added

- Act on `mode` when KE2 fails — CONTRACT.md §23.4 rule 7

### Changed

- Re-vendor openapi.json for the vault_pki CA custodian (axiam#368)

- Re-vendor CONTRACT.md 1.29 and openapi.json 1.0.0-alpha40

- **Re-vendor `openapi.json`** for AXIAM server PR #368, which adds a third CA
  key custodian, `vault_pki`, having HashiCorp Vault's PKI secrets engine
  generate the CA key inside Vault and sign on AXIAM's behalf. The spec version
  is unchanged at **1.0.0-alpha40**; `CONTRACT.md` and `proto/` are untouched by
  that PR and are already current.

  This is a specification re-sync with **no SDK surface change**. CA-certificate
  administration is not part of the SDK contract — `CONTRACT.md` §1 maps no
  method onto `/api/v1/organizations/{org_id}/ca-certificates`, and this SDK
  models none of the five schemas below — so nothing here gains, loses, or
  changes a symbol. It is vendored so the spec this SDK is written against keeps
  describing the server it talks to.

  What moved in the spec:

  - `CaCertificate` gains a nullable `chain_pem`: the issuers above
    `public_cert_pem`, concatenated PEM, nearest issuer first and the root last.
    Absent for a CA that is its own root, which is every CA AXIAM generated
    before this. Present for a `vault_pki` CA, where it is the only copy of the
    root certificate anything outside Vault will ever see.
  - `CaCertificate.public_cert_pem` is now documented as the certificate that
    *signs*, which under `vault_pki` custody is the intermediate rather than the
    root beneath which it was created. The field itself is unchanged.
  - `GeneratedCaCertificate.private_key_pem` is **no longer required**. Under
    `vault_pki` custody the key is born inside Vault and no API exports it, so
    there is nothing to return. The field is omitted rather than sent as `null`,
    which keeps a client that has always read it working unchanged against every
    custodian that does produce a key.
  - `GeneratedCertificate` gains a nullable `chain_pem`, present only when the
    signer returned one — the `vault_pki` case, where the root's certificate
    exists nowhere a client could fetch it from.
  - `CreateCaCertificate` and `CreateCaCertificateRequest` gain the optional
    `issue_from_root`, `intermediate_subject` and `intermediate_validity_days`.
    All three are `vault_pki`-only and ignored by every other custodian.
    `issue_from_root` defaults to off: a root that signs only one intermediate
    can have that intermediate revoked and replaced without redistributing the
    trust anchor, and a root that signs leaves directly cannot.

- **OPAQUE `login/start` now reports the tenant's mode, and §23.4 rule 7 acts
  on it.** The response gained an optional `mode` field carrying `opaque_mode`
  — `"optional"` or `"required"`, never `"disabled"` (that path still answers
  `404`). When `KE2` fails to open, `login_opaque` still sends no `KE3`, but
  what it does next now depends on that field and on nothing else: under
  `optional` it retries over `POST /api/v1/auth/login` with the same
  credentials and returns that call's outcome; under `required`, an
  unrecognised value, or no `mode` at all (a server older than the field) the
  failure stays an `AuthError` and the plaintext path is never tried. Without
  the `optional` clause, enabling `optional` locked out every user of a tenant
  mid-migration — every account has no OPAQUE record until its password is
  next set, so the exchange fails for all of them. `mode` is **not** downgrade
  protection and is not documented as such: a hostile server wanting the
  plaintext could simply answer `404`.

- Re-vendor `CONTRACT.md` at 1.29 and `openapi.json` at 1.0.0-alpha40.

## [1.0.0-alpha40] - 2026-08-23

### Changed

- Maintenance release — no notable changes since v1.0.0-alpha39.

## [1.0.0-alpha39] - 2026-08-23

### Changed

- Re-vendor CONTRACT.md for the §14.1 anchor repair
- Re-vendor openapi.json at 1.0.0-alpha38

## [1.0.0-alpha38] - 2026-08-22

### Added

- Add WebAuthn (§24), account lifecycle (§25) and PAR (§26)

- **WebAuthn and passkeys — CONTRACT.md §24.** Six relying-party operations on
  `AxiamClient`: `webauthn_register_start`/`_finish`,
  `webauthn_authenticate_start`/`_finish`,
  `webauthn_discoverable_start`/`_finish`. The native build has no
  authenticator, so §24.6b's linked-API helper is deliberately absent —
  §24.6b rule 2 forbids emulating one in software. `axiam-sdk-wasm` is the one
  build that reaches `navigator.credentials`.

- **The §24.6a JSON bridge.** `WebauthnChallenge::request_json()` produces the
  exact string a platform authenticator API takes, and
  `webauthn_response_from_json` accepts the platform's response JSON string —
  so a service driving an Android or iOS client passes both directions through
  untouched. Plus `WebauthnFailure::classify`/`message`, which give a
  server-side caller the same five outcomes a browser sees.

- **Account lifecycle and MFA enrolment — CONTRACT.md §25.** Nine operations:
  `mfa_enroll`/`mfa_confirm`, `mfa_setup_enroll`/`mfa_setup_confirm`,
  `verify_email`, `resend_verification`, `request_password_reset`,
  `confirm_password_reset`, `password_reset_context`.

- **Pushed authorization requests — CONTRACT.md §26 (RFC 9126).** `oidc_par`,
  plus `pushed_authorization_request_endpoint` on `OidcConfiguration`.

- Examples: `webauthn_relying_party`, `account_lifecycle`, `par_login`.

### Changed

- Test the redacting Debug impls on the new request bodies

- Re-vendor CONTRACT.md at 1.28

- Re-vendor `CONTRACT.md`. Repairs §14.1's link to the `device_login` heading,
  which dropped a hyphen the em dash leaves behind and so rendered as a link
  that went nowhere; the same heading's other two links were already correct.
  Link target only — no normative change and no contract-version bump.

- Re-vendor `openapi.json` at **1.0.0-alpha38**. The server registered the four
  GDPR data-subject endpoints (`POST /api/v1/account/export`,
  `GET /api/v1/account/export/{token}`, `POST /api/v1/account/delete`,
  `GET /api/v1/auth/account/delete/cancel`), taking the document to 181
  operations across 121 paths. Purely additive, and no SDK surface changes with
  it: nothing in this repo is generated from the spec, so the cross-repo
  artifact-drift gate was the only thing reporting `STALE`.

- Re-vendor `vendor/axiam-opaque/src/lib.rs`. Doc-comment only — the crate-level
  doctest stopped using a hardcoded password literal — but the drift gate compares
  blob hashes, so a doc change drifts exactly like a behavioural one.

- **`LoginResult` gains `mfa_setup_required` and `setup_token`** (§25.2 rule 1).
  A tenant that requires MFA answers `403 mfa_setup_required` with a setup token
  for an account that has none; that used to arrive as `AxiamError::Authz`,
  telling the caller they lacked permission to log in when what the server said
  was recoverable and came with the means to recover.

  **Additive, not breaking.** `LoginResult` has always been a struct with flags
  rather than a discriminated enum, so nothing that reads `mfa_required` has to
  change — unlike the SDKs whose login result is a union, where the same
  contract rule adds a variant. A genuine authorization refusal still returns
  `AxiamError::Authz`: the branch is matched on the body's discriminant, not the
  status.

## [1.0.0-alpha37] - 2026-08-21

### Added

- An `axiam-sdk-wasm` README section for readers arriving from 1.0.0-alpha31
  or earlier, mapping `loginSrp`/`srpEnrollment`/`srpAvailable` onto their
  OPAQUE replacements and saying plainly that a verifier does not migrate into
  a record.

### Changed

- Get the OPAQUE README onto the npm package page

### Fixed

- The `axiam-sdk-wasm` package page on npmjs.com documented SRP. The README in
  the repository has described OPAQUE since alpha34 and each tarball carried
  it, but npm renders the README of whatever version the `latest` dist-tag
  names, and `latest` had pointed at 1.0.0-alpha31 — the last SRP release —
  ever since the first publish. While no stable version exists, the npm
  release workflow now publishes each prerelease to `latest` rather than to a
  channel tag nobody reads; once 1.0.0 ships, prereleases go back to their own
  channel and never displace it.

- `axiam-sdk-wasm`'s quickstart called `init()`. The published package is
  wasm-pack's `bundler` target, which has no default export to call — that
  form belongs to the `web` target, and is now shown where the `web` target is
  built. Same fix in the crate doc comment, which becomes the shipped
  `.d.ts`.

- `axiam-sdk-wasm`'s README listed local JWKS verification and the §12 OIDC
  relying-party helpers among what the module offers. Neither crosses the wasm
  boundary; they are in the "what is not, and why" table now, with the reason
  (session tokens are `HttpOnly` cookies, so page script holds no token to
  verify).

## [1.0.0-alpha36] - 2026-08-21

### Fixed

- Issue with SDK release on crates.io

## [1.0.0-alpha35] - 2026-08-21

### Fixed

- Issues with the crates.io trusted publishing flow

## [1.0.0-alpha34] - 2026-08-21

### Added

- Replace SRP-6a with OPAQUE (RFC 9807) — CONTRACT 1.26

### Changed

- Link to the AXIAM platform documentation site
- Re-vendor openapi.json at alpha32 (#71)
- Publish to crates.io and npm by Trusted Publishing
- Added environment to NPM publish action

### Fixed

- Drop a needless borrow flagged by clippy under -D warnings
- Lower the vendored axiam-opaque MSRV to 1.88, which is its real floor
- Derive the conformance password instead of hard-coding it

## [1.0.0-alpha33] - 2026-08-21

### Added

- `vendor/axiam-opaque`, a vendored copy of the implementation, on the same
  terms as the existing `CONTRACT.md`/`openapi.json`/`proto/` copies: the
  source of truth is the server repository and a drift gate fails if it falls
  behind. It becomes an ordinary crates.io version requirement once the crate
  is published.

### Changed

- Added environment to NPM publish action
- **BREAKING: `login_srp` becomes `login_opaque`** — CONTRACT.md §23 is now
  OPAQUE (RFC 9807), and SRP-6a is removed from AXIAM entirely.
  - `login_srp` → `login_opaque`, `srp_enrollment` → `opaque_enrollment`,
    `srp_available` → `opaque_available`; the `srp` feature becomes `opaque`.
  - `opaque_enrollment` is now **async** and takes only a password. The SRP
    version took four arguments including the account's canonical username,
    and passing an email produced a verifier no login could satisfy. A record
    binds to a credential identifier the server chooses, so that mistake is
    not expressible — and a later rename no longer invalidates a credential.
  - `SrpEnrollment`'s seven fields become `OpaqueEnrollment`'s two. The server
    chose the identifier, the suite and the costs and sealed them into
    `opaque_session`.
- **This SDK no longer implements the protocol.** CONTRACT §23.1 forbids it:
  SRP was hand-written eleven times because it is modular arithmetic every
  language has, whereas OPAQUE needs an OPRF, `hash_to_curve`,
  `expand_message_xmd` and a three-message AKE. `src/srp/` — three modules,
  ~870 lines of group arithmetic, RFC 5054 constants and a hand-rolled PBKDF2 —
  is replaced by a dependency on `axiam-opaque`, the same crate the AXIAM
  server links.

- Release CI now authenticates by **Trusted Publishing (OIDC)** on both
  registries rather than long-lived tokens: `rust-lang/crates-io-auth-action`
  mints a short-lived crates.io token, and npm authenticates by workflow
  identity with no `NODE_AUTH_TOKEN`. Provenance is implied on both.
  - The npm job now **fails** if an `NPM_TOKEN` secret is still present. A
    token takes precedence over OIDC, so leaving one would mean Trusted
    Publishing is configured, believed to be in use, and silently bypassed.
  - Both publishers are bound to this repository, the workflow file path and
    the `production` environment. **Renaming or moving either workflow file
    breaks publishing** until the trusted publisher is updated on the registry.
  - The `CRATES_IO_TOKEN` and `NPM_TOKEN` repository secrets can be deleted.
- Re-vendor `openapi.json` at **1.0.0-alpha32**, matching the server. The
  content was already byte-identical in every path and schema; only
  `info.version` differed, which is what the cross-repo artifact-drift gate
  reports as `STALE`.

### Removed

- The server-proof check. RFC 9807's AKE authenticates the server during the
  handshake, so opening `KE2` *is* the proof it holds the record. §23.3 rule 6
  had to mandate an `M2` check in capitals because skipping it kept only half
  the protocol; there is now nothing to skip.
- `num-bigint` from the feature's dependency set.
- `srp-test-vectors.json`, replaced by the smaller `opaque-test-vectors.json`
  — see CONTRACT §23.7 for why the fixture shrank rather than being ported.
- `__conformanceVerifier` from the wasm build, replaced by
  `__conformanceRoundTrip`, which runs both halves of a real exchange inside
  the published artifact. Same purpose — catching a `wasm-opt` miscompilation —
  by the only means OPAQUE offers, since its blind is not injectable.

## [1.0.0-alpha31] - 2026-08-20

### Fixed

- Release: `npm publish` of the `axiam-sdk-wasm` package is called with an
  explicit `--tag`, derived from the version, so a prerelease publishes under
  `alpha` instead of being refused. npm >= 11 rejects publishing a prerelease
  with no dist-tag, and the publish job upgrades to npm@latest because Trusted
  Publishing needs >= 11.5.1 — so v1.0.0-alpha30 failed at the pre-publish dry
  run after the build, the wasm smoke test and all six contract verifiers had
  already passed. The fix landed on main after the alpha30 tag was cut, so this
  is the first release to carry it. The crates.io publishers were unaffected.

## [1.0.0-alpha30] - 2026-08-20

### Changed

- Maintenance release — no notable changes since v1.0.0-alpha29.

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

### Changed

- Do not intra-doc-link a private module from public docs
- Re-vendor CONTRACT.md 1.23 (§8b rules 7 and 8)
- Re-vendor openapi.json for the SCIM provisioning-token endpoints
- Re-vendor CONTRACT.md 1.22 from the server repo
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

### Fixed

- Make §8b rule 2 implementable, and stop the guard failing open
- **The §8b scheme guard failed open on an unparseable URL.** It was written as
  `if let Ok(parsed) = url::Url::parse(amqp_url) { … }`, so a URL that did not
  parse skipped the check entirely and went straight to lapin. That is backwards
  for a security check — an input nobody can parse is the one to refuse, not the
  one to wave through. It is now an error, in both `consume()` and the reactor
  builder.

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
- Re-vendored `CONTRACT.md` at **1.10** and `openapi.json` with the UMA paths.
- Re-vendored `CONTRACT.md` at **1.8**. `openapi.json` is unchanged — 1.8 is docs-only.
- `check_access`/`can`/`batch_check` now run under the §16 runner rather than `backon`, so
  they gain full jitter and `Retry-After` handling. The retry-eligible set is unchanged and
  remains authz reads only; no mutation became retryable.

### Removed

- The direct `backon` dependency. Nothing referenced it after §16 landed; it remains in
  the lockfile only as a transitive dependency of `lapin` under the `amqp` feature.

### Fixed

- Never print the raw UMA challenge header (#53)

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

- Add the §10.1 rule-8 guardrail regression tests (#43)
- Device (mTLS) tokens now carry aud=axiam:m2m (#42)
- Service accounts can use login_client_credentials (#41)
- Bump github/codeql-action from 4 to 4.37.4
- Bump taiki-e/install-action from 2.85.2 to 2.85.5
- Sync CONTRACT.md §10.1 rule 8 — subject of the decision (#38)
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

## [1.0.0-alpha23] - 2026-08-02

### Changed

- Maintenance release — no notable changes since v1.0.0-alpha21.

## [1.0.0-alpha21] - 2026-07-30

### Added

- Add OIDC/SSO relying-party helpers (CONTRACT §12)
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

### Changed

- Re-sync vendored CONTRACT.md to contract 1.6
- Update base64 requirement from 0.22 to 0.23
- Update ed25519-dalek requirement from 2 to 3
- Update jsonwebtoken requirement from 10 to 11
- Bump coverallsapp/github-action from 2.3.7 to 2.3.8
- Bump taiki-e/install-action from 2.84.0 to 2.85.2
- Re-sync vendored CONTRACT.md to contract 1.5
- `Sensitive::expose()` is now `pub` (previously `pub(crate)`): §12's
  `OidcTokenSet` hands `access_token`/`refresh_token`/`id_token` directly to
  the caller (unlike the §1 cookie-only session), so a relying party needs a
  way to read them back out to use them. Still the only path to the wrapped
  value; still never touched by `Debug`/`Display`.
- Conformance statement updated to "CONTRACT.md §1–§12 (including §6.1
  mTLS)".

### Fixed

- Publish the single-flight refresh outcome before vacating the slot
- Read axiam_refresh from its REFRESH_PATH-scoped URL, not base_url (H8 SDK bench)
- Disable aud validation in JwksVerifier::verify (H8 SDK bench)
- Share the single-flight oidc_refresh result (CONTRACT §9 rule 2)
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
- gRPC `get_user_info` (`UserInfoGrpcClient`) — OIDC-style identity read over
  `axiam.v1.UserInfoService/GetUserInfo` (CONTRACT §1.1). Returns a `UserInfo`
  with `sub`/`tenant_id`/`org_id` and scope-gated `email`/`preferred_username`,
  reusing the shared `tonic::Channel`, auth/tenant interceptor, and
  single-flight refresh guard. Adopts CONTRACT.md 1.3.

### Changed

- Exclude generated gRPC stubs from the line-coverage gate
- Expand userinfo coverage above the 89% gate
- Vendor userinfo.proto + CONTRACT 1.3

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

### Changed

- Maintenance release — no notable changes since v1.0.0-alpha9.

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
