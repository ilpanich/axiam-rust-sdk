//! Compile-fail (`trybuild`) UI tests for the CONTRACT.md §11 attribute
//! macros: each case exercises a misuse that must be rejected at compile time
//! with a clear, stable diagnostic (the macros emit their own
//! `compile_error!`s, so the expected `.stderr` output does not depend on
//! rustc's error formatting).

#![cfg(feature = "macros")]

#[test]
fn ui() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/*.rs");
}
