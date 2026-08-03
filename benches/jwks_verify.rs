//! Micro-benchmark for the SDK's per-request hot path: local access-token
//! verification against the cached JWKS ([`axiam_sdk::token::JwksVerifier`]).
//!
//! This is the code the CONTRACT.md §10 route guard (`AxiamUser`) and the §11
//! `#[require_auth]` / `#[require_access]` / `#[require_role]` macros run on
//! **every inbound request**, so it is the one place in the SDK where client
//! CPU — rather than server latency — dominates. `check_access` by contrast is
//! a single HTTP round-trip whose cost is ~4 orders of magnitude larger than
//! the SDK-side serialization around it, which is why it is not benchmarked
//! here.
//!
//! Deliberately harness-free (`harness = false`) and dependency-free: no
//! criterion, no divan. Those pull a large dependency tree into
//! `cargo clippy --all-targets`/`cargo bench`, which would work against the
//! build-time goals this benchmark exists to measure. The loop below is a
//! plain wall-clock timing over a fixed iteration count with a warm-up pass,
//! reported as median/mean/p95 over repeated batches.
//!
//! Run with:
//!
//! ```text
//! cargo bench --bench jwks_verify --features rest
//! ```

use std::hint::black_box;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde_json::json;

/// PKCS#8 DER prefix for a raw 32-byte Ed25519 seed (same constant the JWKS
/// integration tests use).
const ED25519_PKCS8_DER_PREFIX: [u8; 16] = [
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];

const WARMUP: usize = 500;
const BATCH: usize = 500;
const BATCHES: usize = 25;

fn base64url(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

struct Key {
    kid: String,
    seed: [u8; 32],
    x: String,
}

fn key(kid: &str, seed_byte: u8) -> Key {
    let seed = [seed_byte; 32];
    let signing = SigningKey::from_bytes(&seed);
    Key {
        kid: kid.to_string(),
        seed,
        x: base64url(signing.verifying_key().as_bytes()),
    }
}

fn sign(k: &Key) -> String {
    let mut der = ED25519_PKCS8_DER_PREFIX.to_vec();
    der.extend_from_slice(&k.seed);
    let mut header = Header::new(Algorithm::EdDSA);
    header.kid = Some(k.kid.clone());
    let claims = json!({
        "sub": "3f6b1c8e-0000-4000-8000-000000000001",
        "tenant_id": "3f6b1c8e-0000-4000-8000-000000000002",
        "org_id": "3f6b1c8e-0000-4000-8000-000000000003",
        "iss": "https://iam.example.com",
        "iat": 1_700_000_000i64,
        "exp": 4_102_444_800i64, // 2100-01-01
        "jti": "3f6b1c8e-0000-4000-8000-000000000004",
        "aud": "axiam:user",
        "scope": "admin editor viewer",
    });
    jsonwebtoken::encode(&header, &claims, &EncodingKey::from_ed_der(&der))
        .expect("sign benchmark token")
}

/// Serve one fixed JWKS document over plain HTTP on loopback, forever.
fn spawn_jwks_server(body: String) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let addr = listener.local_addr().expect("local addr");
    std::thread::spawn(move || {
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf);
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.flush();
        }
    });
    format!("http://{addr}/")
}

fn percentile(sorted: &[f64], p: f64) -> f64 {
    let idx = ((sorted.len() as f64 - 1.0) * p).round() as usize;
    sorted[idx]
}

fn report(label: &str, mut per_op_ns: Vec<f64>) {
    per_op_ns.sort_by(|a, b| a.partial_cmp(b).unwrap());
    // `min` is the estimator to compare across runs: this is CPU-bound work on
    // a shared VM, so every source of noise (scheduling, neighbours, frequency
    // scaling) only ever adds time. The fastest batch is the closest thing to
    // an interference-free measurement; median/p95 are printed alongside to
    // show how much noise the box is contributing.
    let min = per_op_ns[0];
    println!(
        "{label:<32} min {:>8.0} ns/op  median {:>8.0}  p95 {:>8.0}   ~{:>7.0} ops/s (min)",
        min,
        percentile(&per_op_ns, 0.5),
        percentile(&per_op_ns, 0.95),
        1e9 / min
    );
}

/// The theoretical floor for `JwksVerifier::verify`: `jsonwebtoken::decode`
/// against an already-built `DecodingKey` and an already-built `Validation`,
/// with no cache lookup, no `decode_header`, and no async machinery at all.
///
/// Whatever this row costs, the SDK cannot go below it — it is Ed25519
/// verification plus base64/JSON decoding of the token. Subtracting it from the
/// `verify` rows gives the SDK's own per-request overhead.
fn measure_floor(keys: &[Key], token_kid: usize) {
    use jsonwebtoken::{DecodingKey, Validation, jwk::Jwk};

    let k = &keys[token_kid];
    let jwk: Jwk = serde_json::from_value(json!({
        "kty": "OKP", "crv": "Ed25519", "kid": k.kid, "alg": "EdDSA", "use": "sig", "x": k.x,
    }))
    .expect("jwk");
    let decoding_key = DecodingKey::from_jwk(&jwk).expect("decoding key");
    let mut validation = Validation::new(Algorithm::EdDSA);
    validation.leeway = 0;
    validation.validate_aud = false;
    let token = sign(k);

    for _ in 0..WARMUP {
        let _ = jsonwebtoken::decode::<serde_json::Value>(&token, &decoding_key, &validation);
    }

    let mut per_op_ns = Vec::with_capacity(BATCHES);
    for _ in 0..BATCHES {
        let start = Instant::now();
        for _ in 0..BATCH {
            let claims = jsonwebtoken::decode::<serde_json::Value>(
                black_box(&token),
                &decoding_key,
                &validation,
            )
            .expect("decodes");
            black_box(claims);
        }
        per_op_ns.push(start.elapsed().as_nanos() as f64 / BATCH as f64);
    }
    report("floor: jsonwebtoken::decode", per_op_ns);
}

async fn measure(label: &str, keys: &[Key], token_kid: usize) {
    let base = spawn_jwks_server(jwks_document(keys));
    let token = sign(&keys[token_kid]);

    let verifier = axiam_sdk::token::JwksVerifier::new(
        reqwest::Client::new(),
        &url::Url::parse(&base).expect("base url"),
    )
    .expect("verifier");

    // Warm the cache (and pay the one-off network fetch) before timing.
    for _ in 0..WARMUP {
        verifier.verify(&token).await.expect("token verifies");
    }

    let mut per_op_ns: Vec<f64> = Vec::with_capacity(BATCHES);
    for _ in 0..BATCHES {
        let start = Instant::now();
        for _ in 0..BATCH {
            let claims = verifier.verify(black_box(&token)).await.expect("verifies");
            black_box(claims);
        }
        let elapsed: Duration = start.elapsed();
        per_op_ns.push(elapsed.as_nanos() as f64 / BATCH as f64);
    }
    report(label, per_op_ns);
}

/// Concurrent verification across the whole runtime — the shape the §10 route
/// guard is actually used in. A per-request deep clone of the cached key
/// material shows up here (allocator contention) even when it hides inside the
/// crypto cost of the single-threaded rows above.
async fn measure_concurrent(label: &str, keys: &[Key], token_kid: usize, tasks: usize) {
    let jwks = jwks_document(keys);
    let base = spawn_jwks_server(jwks);
    let token = std::sync::Arc::new(sign(&keys[token_kid]));

    let verifier = std::sync::Arc::new(
        axiam_sdk::token::JwksVerifier::new(
            reqwest::Client::new(),
            &url::Url::parse(&base).expect("base url"),
        )
        .expect("verifier"),
    );
    for _ in 0..WARMUP {
        verifier.verify(&token).await.expect("token verifies");
    }

    let per_task = BATCH / tasks;
    let mut per_op_ns = Vec::with_capacity(BATCHES);
    for _ in 0..BATCHES {
        let start = Instant::now();
        let mut handles = Vec::with_capacity(tasks);
        for _ in 0..tasks {
            let verifier = std::sync::Arc::clone(&verifier);
            let token = std::sync::Arc::clone(&token);
            handles.push(tokio::spawn(async move {
                for _ in 0..per_task {
                    black_box(verifier.verify(black_box(&token)).await.expect("verifies"));
                }
            }));
        }
        for h in handles {
            h.await.expect("task");
        }
        per_op_ns.push(start.elapsed().as_nanos() as f64 / (per_task * tasks) as f64);
    }
    report(label, per_op_ns);
}

fn jwks_document(keys: &[Key]) -> String {
    json!({
        "keys": keys.iter().map(|k| json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "kid": k.kid,
            "alg": "EdDSA",
            "use": "sig",
            "x": k.x,
        })).collect::<Vec<_>>()
    })
    .to_string()
}

fn main() {
    let one = vec![key("bench-kid-1", 0x11)];
    let three = vec![
        key("bench-kid-1", 0x11),
        key("bench-kid-2", 0x22),
        key("bench-kid-3", 0x33),
    ];
    // A wide key set isolates the per-verify *bookkeeping* from the fixed cost
    // of the signature check: the amount of elliptic-curve work is identical to
    // the 1-key case, so any difference between the two rows is cache handling,
    // not crypto.
    let many: Vec<Key> = (0..16u8)
        .map(|i| key(&format!("bench-kid-{i}"), 0x10 + i))
        .collect();

    println!(
        "JwksVerifier::verify — warm cache, {BATCH} ops x {BATCHES} batches (after {WARMUP} warm-up)"
    );
    measure_floor(&one, 0);

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    rt.block_on(async {
        measure("1-key JWKS", &one, 0).await;
        measure("3-key JWKS (match on last)", &three, 2).await;
        measure("16-key JWKS (match on last)", &many, 15).await;
    });
    drop(rt);

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .expect("tokio runtime");
    rt.block_on(async {
        measure_concurrent("1-key JWKS, 8 tasks / 4 threads", &one, 0, 8).await;
        measure_concurrent("16-key JWKS, 8 tasks / 4 threads", &many, 15, 8).await;
    });
}
