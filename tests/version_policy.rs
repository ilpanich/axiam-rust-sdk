//! Language-version support policy — D-10.
//!
//! This SDK has gated on both ends of its supported range since it was written:
//! `toolchain: ["1.88", stable]`. That made it the model the other ten AXIAM SDKs
//! were brought in line with, and this test is what keeps it from quietly drifting
//! out of the shape everything else now copies.
//!
//! "Which Rust does this crate support?" is declared in three places, and nothing in
//! the toolchain compares them:
//!
//! 1. `rust-version` in `Cargo.toml` — a hard constraint Cargo checks during
//!    resolution, and the only one that can refuse a build;
//! 2. the `toolchain` matrix in `.github/workflows/sdk-ci-rust.yml` — the only one
//!    that is ever compiled;
//! 3. [`axiam_sdk::supported_versions`] — the only one readable from code.
//!
//! The floor half is genuinely well enforced here, better than in most ecosystems: a
//! consumer on an older toolchain gets a message naming this crate and the version it
//! needs, not a compile error deep in someone else's source. The upper half has no
//! enforcement anywhere, because there is no "maximum Rust" to declare. Code that
//! compiles on the MSRV keeps compiling on newer toolchains almost always — and
//! "almost" is where new `deny`-by-default lints and tightened inference live.

use std::fs;
use std::path::{Path, PathBuf};

use axiam_sdk::supported_versions;

/// The crate root, from `CARGO_MANIFEST_DIR` — set by cargo for every test binary,
/// so no walking or guessing is involved.
fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read(relative: &str) -> String {
    let path: PathBuf = repo_root().join(relative);
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("could not read {}: {e}", path.display()))
}

/// The `rust-version = "1.88"` value from Cargo.toml's `[package]` section.
fn declared_msrv() -> String {
    let manifest = read("Cargo.toml");
    manifest
        .lines()
        .find_map(|line| {
            let line = line.trim();
            let rest = line.strip_prefix("rust-version")?;
            let value = rest.trim_start().strip_prefix('=')?.trim();
            Some(value.trim_matches('"').to_owned())
        })
        .expect("Cargo.toml declares no rust-version")
}

/// The `edition = "2024"` value from Cargo.toml.
fn declared_edition() -> String {
    let manifest = read("Cargo.toml");
    manifest
        .lines()
        .find_map(|line| {
            let line = line.trim();
            let rest = line.strip_prefix("edition")?;
            let value = rest.trim_start().strip_prefix('=')?.trim();
            Some(value.trim_matches('"').to_owned())
        })
        .expect("Cargo.toml declares no edition")
}

/// The `toolchain: ["1.88", stable]` list from the CI test matrix.
fn ci_matrix() -> Vec<String> {
    let workflow = read(".github/workflows/sdk-ci-rust.yml");

    let matches: Vec<&str> = workflow
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            let rest = trimmed.strip_prefix("toolchain:")?;
            let rest = rest.trim();
            // Only the matrix list form, not the `toolchain: ${{ ... }}` reference
            // inside a step.
            rest.strip_prefix('[')?.strip_suffix(']')
        })
        .collect();

    assert_eq!(
        matches.len(),
        1,
        "expected exactly one `toolchain: [...]` matrix in sdk-ci-rust.yml, found {}; \
         a second would mean this test only checks one of them",
        matches.len()
    );

    matches[0]
        .split(',')
        .map(|entry| entry.trim().trim_matches('"').to_owned())
        .filter(|entry| !entry.is_empty())
        .collect()
}

/// The exported constant matches the constraint Cargo actually enforces.
///
/// It is the only part of the floor readable from code, so a stale value would
/// report a minimum that resolution does not enforce.
#[test]
fn min_rust_version_constant_matches_cargo_toml() {
    assert_eq!(
        declared_msrv(),
        supported_versions::MIN_RUST_VERSION,
        "supported_versions::MIN_RUST_VERSION has drifted from Cargo.toml's rust-version"
    );
}

/// The exported edition matches the one the crate is actually compiled under.
#[test]
fn edition_constant_matches_cargo_toml() {
    assert_eq!(
        declared_edition(),
        supported_versions::EDITION,
        "supported_versions::EDITION has drifted from Cargo.toml"
    );
}

/// CI compiles the declared MSRV, so `rust-version` is a promise something keeps.
///
/// Without this leg the MSRV is a number in a manifest: a 1.9x-only API compiles
/// clean on stable and the breakage lands on the first consumer who takes the crate
/// at its declared word.
#[test]
fn ci_builds_the_declared_msrv() {
    let matrix = ci_matrix();
    let msrv = declared_msrv();
    assert!(
        matrix.contains(&msrv),
        "Cargo.toml declares rust-version {msrv} but no CI leg builds it: {matrix:?}"
    );
}

/// CI also compiles a current toolchain, so the upper half of the claim is tested.
#[test]
fn ci_builds_the_newest_toolchain() {
    let matrix = ci_matrix();
    assert!(
        matrix
            .iter()
            .any(|t| t == supported_versions::NEWEST_TESTED),
        "no CI leg builds {:?}, so nothing proves the crate still compiles on a \
         current toolchain: {matrix:?}",
        supported_versions::NEWEST_TESTED
    );
}

/// The gating matrix is exactly the two ends — not a subset, not a list of pins.
///
/// Pinning the upper leg to a version number instead of `stable` is the specific
/// regression worth guarding against: it would freeze the newest end at whatever was
/// current the day someone wrote it and quietly stop testing anything after that,
/// while still looking like a two-legged matrix.
#[test]
fn ci_matrix_is_exactly_msrv_and_stable() {
    let matrix = ci_matrix();
    assert_eq!(
        matrix.len(),
        2,
        "expected exactly 2 CI legs (MSRV + stable), got {matrix:?}"
    );
    assert_eq!(
        matrix[0],
        declared_msrv(),
        "the first CI leg is not the MSRV"
    );
    assert_eq!(
        matrix[1],
        supported_versions::NEWEST_TESTED,
        "the second CI leg should track `stable` rather than a pinned version, or the \
         newest end stops moving"
    );
}

/// Edition 2024 requires Rust 1.85 or newer, so the MSRV cannot be below it.
///
/// These two are set independently in the same file and it is entirely possible to
/// lower one without the other; the result would be a manifest that promises a
/// toolchain the edition cannot compile on.
#[test]
fn msrv_is_high_enough_for_the_declared_edition() {
    let edition = declared_edition();
    let msrv = declared_msrv();

    let minimum_for_edition = match edition.as_str() {
        "2015" => (1, 0),
        "2018" => (1, 31),
        "2021" => (1, 56),
        "2024" => (1, 85),
        other => panic!("unknown edition {other:?} — add its minimum Rust version here"),
    };

    let mut parts = msrv.split('.');
    let major: u32 = parts
        .next()
        .unwrap()
        .parse()
        .expect("malformed rust-version");
    let minor: u32 = parts
        .next()
        .unwrap_or("0")
        .parse()
        .expect("malformed rust-version");

    assert!(
        (major, minor) >= minimum_for_edition,
        "rust-version {msrv} is below {}.{}, the minimum for edition {edition}",
        minimum_for_edition.0,
        minimum_for_edition.1
    );
}

/// The crate root really is where `CARGO_MANIFEST_DIR` says.
///
/// Cheap, and it turns a wrong-directory mistake into a clear failure rather than a
/// confusing one from every other test in this file.
#[test]
fn manifest_dir_locates_the_crate_root() {
    let root: &Path = &repo_root();
    assert!(
        root.join("Cargo.toml").is_file(),
        "CARGO_MANIFEST_DIR ({}) does not contain Cargo.toml",
        root.display()
    );
    assert!(
        root.join(".github/workflows/sdk-ci-rust.yml").is_file(),
        "CARGO_MANIFEST_DIR ({}) does not contain the CI workflow",
        root.display()
    );
}
