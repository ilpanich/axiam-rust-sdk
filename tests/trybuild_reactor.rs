//! Compile-fail (`trybuild`) UI tests for the CONTRACT.md §22.14
//! `#[reactor_handler]` attribute macro.
//!
//! §22.14 rule 2 requires an unregistered event name to be refused when the
//! binding is *written*. In Rust that can be earlier than anywhere else — the
//! macro validates its literal against the §22.5 registry at compile time — and
//! these cases are what pins that behaviour, including the rule's second half:
//! the diagnostic names the registry, never the three hot-path operations
//! §22.7 excludes.

#![cfg(feature = "reactor-macros")]

#[test]
fn ui_reactor() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui_reactor/*.rs");
}
