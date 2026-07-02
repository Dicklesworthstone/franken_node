//! Comprehensive golden artifacts tests for supply_chain, registry, and claims
//!
//! This test suite covers the key outputs identified in the /testing-golden-artifacts
//! skill analysis:
//! - Trust-card exports and receipts (JSON and human-readable)
//! - Registry receipts and verification outputs
//! - Claim envelope structures and gate reports
//!
//! All outputs use scrubbing to handle dynamic values (timestamps, UUIDs, paths)
//! for deterministic comparison.

// Dependencies for claims testing
#[path = "adjacent_claim_language_gate.rs"]
mod adjacent_claim_language_gate;

// Golden test modules
#[path = "golden/mod.rs"]
mod golden;
#[path = "golden/trust_card_golden_tests.rs"]
mod trust_card_golden_tests;
#[path = "golden/registry_golden_tests.rs"]
mod registry_golden_tests;
#[path = "golden/claims_golden_tests.rs"]
mod claims_golden_tests;

use std::env;

#[test]
fn golden_tests_require_update_goldens_env_for_creation() {
    // This test documents how to create/update golden files
    println!("To create or update golden files, run:");
    println!("UPDATE_GOLDENS=1 cargo test golden_artifacts_comprehensive");
    println!();
    println!("Then review changes with:");
    println!("git diff tests/golden/");
    println!();
    println!("Golden files test these key outputs:");
    println!("- Trust card JSON exports and human tables");
    println!("- Registry receipts and verification reports");
    println!("- Claim envelope structures and gate results");
}

#[test]
fn golden_infrastructure_test() {
    // Test the golden test infrastructure itself
    let test_content = r#"{"test": "value", "timestamp": "2024-01-01T12:00:00Z", "uuid": "550e8400-e29b-41d4-a716-446655440000"}"#;
    let scrubbed = golden::scrub_dynamic_values(test_content);

    assert!(scrubbed.contains("[TIMESTAMP]"));
    assert!(scrubbed.contains("[UUID]"));
    assert!(scrubbed.contains(r#""test": "value""#));
}

// Re-export golden utilities for the test modules
pub use golden::*;

// Re-export the individual test modules so they run as part of this suite
pub use trust_card_golden_tests::*;
pub use registry_golden_tests::*;
pub use claims_golden_tests::*;