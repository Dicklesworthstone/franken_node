//! Bridge test for Frankensqlite Conformance Harness (bd-2pbfa)
//!
//! This file provides the cargo test entry point for the conformance harness.
//! The actual implementation is in tests/integration/frankensqlite_conformance_harness.rs

#[path = "../../../tests/integration/frankensqlite_conformance_harness.rs"]
mod frankensqlite_conformance_harness;

// Re-export the main conformance test
pub use frankensqlite_conformance_harness::*;
