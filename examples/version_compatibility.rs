//! Reports the compiling toolchain against the range this SDK is built and tested
//! against.
//!
//! Rust enforces the floor better than most ecosystems do. `rust-version` in
//! `Cargo.toml` is a hard constraint checked during resolution, so a consumer on an
//! older toolchain gets a message naming this crate and the version it needs, rather
//! than a compile error deep in someone else's source. There is nothing to preflight
//! there — Cargo will not let you get it wrong.
//!
//! The upper end has no enforcement anywhere, because there is no "maximum Rust" to
//! declare. Code that compiles on the MSRV keeps compiling on newer toolchains almost
//! always, and "almost" is where new `deny`-by-default lints and tightened inference
//! live. That is why CI gates on `stable` as well as the MSRV, and why the useful
//! thing this example prints is which of the two ends you are on.
//!
//! This example is illustrative and self-contained — no server, no network, no
//! configuration.
//!
//! Run: `cargo run --example version_compatibility`

use axiam_sdk::supported_versions;

fn main() {
    println!("axiam-sdk version:   {}", env!("CARGO_PKG_VERSION"));
    println!(
        "SDK MSRV:            {}",
        supported_versions::MIN_RUST_VERSION
    );
    println!("SDK edition:         {}", supported_versions::EDITION);
    println!("newest tested:       {}", supported_versions::NEWEST_TESTED);

    // The compiling rustc is not available as a constant — `rustc_version` would be a
    // build dependency, and the crate deliberately does not take one for this. What
    // IS knowable without asking: the build got here at all, which means Cargo
    // accepted the rust-version constraint.
    println!();
    println!(
        "This binary compiled, so Cargo accepted the {} constraint — the floor is \
         satisfied by construction.",
        supported_versions::MIN_RUST_VERSION
    );
    println!(
        "Whether you are ON the floor or on something newer, CI covers both: the \
         gating matrix builds {} and {}.",
        supported_versions::MIN_RUST_VERSION,
        supported_versions::NEWEST_TESTED
    );
    println!();
    println!("To see the toolchain in use:  rustc --version");
    println!(
        "To build against the floor:   rustup toolchain install {0} && \
         cargo +{0} build",
        supported_versions::MIN_RUST_VERSION
    );
}
