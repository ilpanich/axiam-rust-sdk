//! Telemetry hooks — CONTRACT.md §19.
//!
//! Wiring metrics to an AXIAM client **without this crate depending on any
//! metrics library**. The sink below aggregates in-process so the example
//! builds with no extra dependencies; the block at the bottom shows the exact
//! mapping onto OpenTelemetry, which is a drop-in replacement for the body of
//! `emit`.
//!
//! Run: `cargo run --example telemetry_hook`

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::time::Duration;

use axiam_sdk::client::AxiamClient;
use axiam_sdk::telemetry::{Outcome, TelemetryEvent, TelemetrySink};

/// Metric key: the operation and its outcome label.
type RequestKey = (&'static str, &'static str);
/// Accumulated call count and total latency for one key.
type RequestStat = (u64, Duration);

/// A minimal metrics sink: request counts and total latency per
/// (operation, outcome), plus a retry counter.
#[derive(Default)]
struct Metrics {
    requests: Mutex<BTreeMap<RequestKey, RequestStat>>,
    retries: Mutex<BTreeMap<&'static str, u64>>,
}

impl TelemetrySink for Metrics {
    fn emit(&self, event: &TelemetryEvent) {
        match event {
            // One pair per ATTEMPT, not per logical call (§19.2 rule 5), so
            // counting these gives the real number of wire calls — including
            // the ones a retry made on your behalf.
            TelemetryEvent::RequestEnd {
                operation,
                duration,
                outcome,
                ..
            } => {
                let label = match outcome {
                    Outcome::Success => "success",
                    Outcome::Failure => "failure",
                };
                let mut m = self.requests.lock().unwrap();
                let entry = m.entry((operation, label)).or_insert((0, Duration::ZERO));
                entry.0 += 1;
                entry.1 += *duration;
            }

            // §16.5 — the reason this event exists. A retried-then-succeeded
            // operation is otherwise invisible: the caller sees a slow success
            // and no signal that the server is failing. Alert on this rate, not
            // on the error rate, or a degrading server looks healthy right up
            // until the retries stop being enough.
            TelemetryEvent::Retry { operation, .. } => {
                *self.retries.lock().unwrap().entry(operation).or_insert(0) += 1;
            }

            // `RequestStart` and `Refresh` are available too; a metrics sink
            // usually only needs the ends. Note the match is non-exhaustive by
            // design — `TelemetryEvent` is `#[non_exhaustive]`, so a future
            // event variant will not break this sink.
            _ => {}
        }
    }
}

impl Metrics {
    fn report(&self) {
        println!("--- requests (per attempt) ---");
        for ((op, outcome), (count, total)) in self.requests.lock().unwrap().iter() {
            let mean = total.checked_div(*count as u32).unwrap_or_default();
            println!("  {op:<16} {outcome:<8} count={count} mean={mean:?}");
        }
        println!("--- retries ---");
        let retries = self.retries.lock().unwrap();
        if retries.is_empty() {
            println!("  (none)");
        }
        for (op, count) in retries.iter() {
            println!("  {op:<16} {count}");
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let metrics = std::sync::Arc::new(Metrics::default());

    // The sink is `Arc`-shared so this example can print a report afterwards.
    // A real adapter usually writes straight to a global registry and keeps no
    // handle of its own.
    let sink = metrics.clone();
    let client = AxiamClient::builder()
        .base_url("https://axiam.example.com")?
        .tenant_slug("acme")
        .org_slug("acme")
        .telemetry_hook(move |event: &TelemetryEvent| sink.emit(event))
        .build()?;

    // This will fail — the host does not resolve — which is the point: a
    // failing call still emits a `RequestEnd` carrying the failure, and the
    // §16 retries are visible as `Retry` events. Against a real server the
    // same sink reports the success path.
    let resource = uuid::Uuid::nil();
    match client.check_access("read", resource, None).await {
        Ok(decision) => println!("allowed={}", decision.allowed),
        Err(e) => println!("check failed as expected in this example: {e}"),
    }

    metrics.report();

    // §18: release the client's local resources. Does not log out.
    client.close().await;
    Ok(())
}

// ---------------------------------------------------------------------------
// The same sink, against OpenTelemetry
// ---------------------------------------------------------------------------
//
// This crate deliberately ships no `opentelemetry` dependency — §19's whole
// point is that you choose your metrics stack. With `opentelemetry` and
// `opentelemetry_sdk` in YOUR Cargo.toml, the body of `emit` becomes:
//
// ```ignore
// use opentelemetry::{global, KeyValue};
//
// impl TelemetrySink for OtelSink {
//     fn emit(&self, event: &TelemetryEvent) {
//         let meter = global::meter("axiam-sdk");
//         match event {
//             TelemetryEvent::RequestEnd { operation, path_template, duration, status, outcome, .. } => {
//                 meter
//                     .f64_histogram("axiam.client.request.duration")
//                     .build()
//                     .record(duration.as_secs_f64(), &[
//                         KeyValue::new("axiam.operation", *operation),
//                         // The path TEMPLATE, never a substituted URL: a metric
//                         // label carrying a UUID is a cardinality bomb.
//                         KeyValue::new("http.route", *path_template),
//                         KeyValue::new("http.response.status_code", status.unwrap_or(0) as i64),
//                         KeyValue::new("axiam.outcome", format!("{outcome:?}")),
//                     ]);
//             }
//             TelemetryEvent::Retry { operation, attempt, .. } => {
//                 meter
//                     .u64_counter("axiam.client.retries")
//                     .build()
//                     .add(1, &[
//                         KeyValue::new("axiam.operation", *operation),
//                         KeyValue::new("axiam.attempt", *attempt as i64),
//                     ]);
//             }
//             _ => {}
//         }
//     }
// }
// ```
//
// Two rules to keep in mind when writing any adapter:
//
//   * **Do not block.** Hooks run on the calling path (§19.2 rule 4). Every
//     mature metrics library already buffers; if yours does not, buffer on
//     your side rather than doing I/O here.
//   * **Do not add your own fields from elsewhere.** `TelemetryEvent` carries a
//     closed set precisely so this surface cannot leak a token into a metrics
//     backend (§19.2 rule 3). Enriching an event with, say, the current
//     `Authorization` header would defeat that on your side of the boundary.
//
// A panicking hook is caught and swallowed by the SDK (§19.2 rule 2) — an
// authorization check is never failed by telemetry — but that is a backstop,
// not a licence to let a sink panic.
