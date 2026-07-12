//! Build-time gRPC codegen shim.
//!
//! When the `grpc` feature is enabled, compiles the AXIAM protobuf service
//! definitions in `proto/` into `src/gen/` via `tonic-prost-build`. This is
//! the local codegen fallback to this repository's `buf generate` pipeline
//! (D-09, `buf.gen.yaml` targets the same `src/gen` output directory); the
//! CI publish job pre-generates the stubs so the crates.io tarball is
//! self-contained.
//!
//! When the `grpc` feature is off, this build script is a no-op.

use std::path::Path;

fn main() {
    // Only run codegen when the `grpc` feature is requested. Cargo sets
    // `CARGO_FEATURE_<NAME>` env vars (uppercased, `-` -> `_`) for every
    // enabled feature of the crate being built.
    if std::env::var("CARGO_FEATURE_GRPC").is_err() {
        return;
    }

    let proto_dir = Path::new("proto/axiam/v1");
    let protos = [
        proto_dir.join("authorization.proto"),
        proto_dir.join("token.proto"),
        proto_dir.join("user.proto"),
    ];

    // Guard against missing proto inputs: warn (do not fail). `proto/` is
    // deliberately absent from the published crate's `include` list, so a
    // crates.io consumer building with the `grpc` feature has no protos and
    // no protoc — they compile against the stubs bundled into `src/gen/` at
    // publish time (D-09). Only a git checkout regenerates them here.
    let missing: Vec<&Path> = protos
        .iter()
        .map(|p| p.as_path())
        .filter(|p| !p.exists())
        .collect();
    if !missing.is_empty() {
        for p in &missing {
            println!(
                "cargo:warning=axiam-sdk build.rs: proto file not found, skipping gRPC codegen: {}",
                p.display()
            );
        }
        return;
    }

    let out_dir = Path::new("src/gen");
    if let Err(e) = std::fs::create_dir_all(out_dir) {
        println!(
            "cargo:warning=axiam-sdk build.rs: could not create {}: {e}",
            out_dir.display()
        );
        return;
    }

    let proto_paths: Vec<&Path> = protos.iter().map(|p| p.as_path()).collect();
    if let Err(e) = tonic_prost_build::configure()
        .out_dir(out_dir)
        .compile_protos(&proto_paths, &[proto_dir])
    {
        println!("cargo:warning=axiam-sdk build.rs: gRPC codegen failed: {e}");
    }

    for proto in &protos {
        println!("cargo:rerun-if-changed={}", proto.display());
    }
}
