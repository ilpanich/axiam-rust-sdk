//! Test-only tracing capture, shared by the §8 consumer tests and the §22
//! reactor-runtime tests.
//!
//! It lives here rather than inside either test module because a test binary
//! may install exactly **one** global `tracing` subscriber, and both suites
//! need to assert on what would have been logged — the §8 rule that a security
//! event never carries the HMAC value, and the §22.12 rule that the tenant
//! signing key never appears in a log line.
//!
//! `tracing`'s per-callsite interest cache is process-global, so a
//! thread-local `set_default` guard installed per test can race any other
//! concurrently-running test that hits the same call site. This subscriber is
//! therefore installed exactly once, as the global default, and routes every
//! event into a **thread-local** buffer — so each test thread only ever sees
//! the events it caused itself.

thread_local! {
    pub(crate) static THREAD_EVENTS: std::cell::RefCell<Vec<String>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

struct MessageVisitor(String);

impl tracing::field::Visit for MessageVisitor {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        self.0.push_str(&format!("{}={:?} ", field.name(), value));
    }
}

struct ThreadLocalRecordingSubscriber;

impl tracing::Subscriber for ThreadLocalRecordingSubscriber {
    fn enabled(&self, _metadata: &tracing::Metadata<'_>) -> bool {
        true
    }

    fn new_span(&self, _span: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }

    fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}

    fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}

    fn event(&self, event: &tracing::Event<'_>) {
        let mut visitor = MessageVisitor(String::new());
        event.record(&mut visitor);
        THREAD_EVENTS.with(|events| events.borrow_mut().push(visitor.0));
    }

    fn enter(&self, _span: &tracing::span::Id) {}
    fn exit(&self, _span: &tracing::span::Id) {}
}

static INIT_GLOBAL_SUBSCRIBER: std::sync::Once = std::sync::Once::new();

/// Install the recording subscriber as the global default exactly once per
/// test binary run, then clear this thread's buffer so a prior test on the
/// same worker thread cannot leak events into the next one.
pub(crate) fn init_recording_subscriber() {
    INIT_GLOBAL_SUBSCRIBER.call_once(|| {
        tracing::subscriber::set_global_default(ThreadLocalRecordingSubscriber)
            .expect("no global subscriber set yet in this test binary");
    });
    THREAD_EVENTS.with(|events| events.borrow_mut().clear());
}

/// Everything this thread has logged since the last
/// [`init_recording_subscriber`], joined into one string for substring
/// assertions.
pub(crate) fn captured_log() -> String {
    THREAD_EVENTS.with(|events| events.borrow().join("\n"))
}
