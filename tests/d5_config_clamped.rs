//! §19.2 rule 6 — a clamped setting is reported, not swallowed (contract 1.9).
//!
//! Clamping is right: rejecting would break a caller whose configuration was
//! merely optimistic, and honoring would let one client become the herd §16
//! exists to prevent. Doing it *silently* is the part that is wrong — an
//! operator who set a 60-second memo TTL believes they have one, and their
//! staleness reasoning is off by a factor of twelve with nothing to say so.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use axiam_sdk::client::AxiamClient;
use axiam_sdk::telemetry::{TelemetryEvent, TelemetrySink};

/// Collects every event a client emits, so a test can assert on construction.
#[derive(Clone, Default)]
struct Collector(Arc<Mutex<Vec<TelemetryEvent>>>);

impl TelemetrySink for Collector {
    fn emit(&self, event: &TelemetryEvent) {
        self.0
            .lock()
            .expect("collector poisoned")
            .push(event.clone());
    }
}

impl Collector {
    fn clamps(&self) -> Vec<(String, String, String)> {
        self.0
            .lock()
            .expect("collector poisoned")
            .iter()
            .filter_map(|e| match e {
                TelemetryEvent::ConfigClamped {
                    setting,
                    requested,
                    effective,
                    ..
                } => Some(((*setting).to_string(), requested.clone(), effective.clone())),
                _ => None,
            })
            .collect()
    }
}

fn client_with(ttl: Duration, collector: Collector) -> AxiamClient {
    AxiamClient::builder()
        .base_url("https://axiam-d5.test")
        .expect("base url")
        .tenant_slug("acme")
        .org_slug("acme")
        .decision_memo_ttl(ttl)
        .telemetry_hook(collector)
        .build()
        .expect("client builds")
}

#[test]
fn clamping_the_memo_ttl_emits_config_clamped() {
    let collector = Collector::default();
    let _client = client_with(Duration::from_secs(60), collector.clone());

    let clamps = collector.clamps();
    assert_eq!(clamps.len(), 1, "expected exactly one clamp event");
    assert_eq!(clamps[0].0, "decision_memo_ttl");
    assert!(
        clamps[0].2.contains('5'),
        "effective value should render the 5s cap, got {}",
        clamps[0].2
    );
}

#[test]
fn a_value_already_within_its_limit_emits_nothing() {
    // §19.2 rule 6: an event that fires when nothing happened trains its reader
    // to ignore it.
    let collector = Collector::default();
    let _client = client_with(Duration::from_secs(2), collector.clone());

    assert!(
        collector.clamps().is_empty(),
        "a TTL inside the limit was not clamped, so nothing may be reported"
    );
}

#[test]
fn the_disabled_default_emits_nothing() {
    // The overwhelmingly common case: no memo configured at all. Reporting a
    // "clamp" of zero-to-zero would fire on every client ever built.
    let collector = Collector::default();
    let _client = AxiamClient::builder()
        .base_url("https://axiam-d5.test")
        .expect("base url")
        .tenant_slug("acme")
        .org_slug("acme")
        .telemetry_hook(collector.clone())
        .build()
        .expect("client builds");

    assert!(collector.clamps().is_empty());
}
