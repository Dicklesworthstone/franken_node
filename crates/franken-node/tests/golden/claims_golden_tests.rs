//! Golden artifact tests for claim envelope and conformance outputs
//!
//! Tests the deterministic outputs of claim operations including:
//! - Claim envelope JSON structures
//! - Claim gate reports and summaries
//! - Claim event streams
//! - Claim validation results

use serde_json::Value;

// Include the claims conformance module (surfaced via the adjacent_claim_language_gate shim)
use crate::adjacent_claim_language_gate::{Claim, ClaimCategory, ClaimLanguageGate, ClaimStatus};

// Golden utilities re-exported from parent module
use super::{assert_json_golden, assert_scrubbed_golden, assert_scrubbed_json_golden};

/// Create test claims for golden file testing
fn create_test_claims() -> Vec<Claim> {
    vec![
        Claim {
            file: "docs/api.md".to_string(),
            line: 42,
            claim_text: "The API supports batch operations for improved performance".to_string(),
            category: ClaimCategory::Api,
            linked_artifact: Some("artifacts/10.16/api_batch_conformance.json".to_string()),
            artifact_exists: true,
            status: ClaimStatus::Linked,
        },
        Claim {
            file: "docs/storage.md".to_string(),
            line: 128,
            claim_text: "Storage layer provides ACID guarantees for all transactions".to_string(),
            category: ClaimCategory::Storage,
            linked_artifact: Some("artifacts/10.16/storage_acid_test.json".to_string()),
            artifact_exists: true,
            status: ClaimStatus::Linked,
        },
        Claim {
            file: "docs/tui.md".to_string(),
            line: 67,
            claim_text: "TUI responds to resize events within 100ms".to_string(),
            category: ClaimCategory::Tui,
            linked_artifact: None,
            artifact_exists: false,
            status: ClaimStatus::Unlinked,
        },
        Claim {
            file: "docs/model.md".to_string(),
            line: 203,
            claim_text: "Model validation ensures data integrity constraints".to_string(),
            category: ClaimCategory::Model,
            linked_artifact: Some("artifacts/10.16/missing_file.json".to_string()),
            artifact_exists: false,
            status: ClaimStatus::BrokenLink,
        },
    ]
}

/// Create a claim envelope structure
fn create_test_claim_envelope() -> Value {
    serde_json::json!({
        "schema_version": "franken-node/claim-envelope/v1",
        "envelope_id": "claim-envelope-12345678",
        "created_at": "2024-01-01T00:00:00Z",
        "claims": create_test_claims(),
        "metadata": {
            "scan_root": "docs/",
            "scan_patterns": ["**/*.md"],
            "artifact_root": "artifacts/10.16/",
            "total_files_scanned": 12,
            "total_claims_found": 4
        },
        "signature": {
            "signer": "claim-validator-v1",
            "signature_b64": "dGVzdC1jbGFpbS1zaWduYXR1cmU=",
            "signed_at": "2024-01-01T00:00:00Z"
        }
    })
}

/// Create a claim gate validation result
fn create_test_gate_result() -> Value {
    let mut gate = ClaimLanguageGate::new();
    gate.scan_batch(create_test_claims());
    gate.to_report()
}

#[test]
fn test_claim_envelope_golden() {
    let envelope = create_test_claim_envelope();
    assert_scrubbed_json_golden("claim_envelope", &envelope);
}

#[test]
fn test_claim_gate_report_golden() {
    let report = create_test_gate_result();
    assert_scrubbed_json_golden("claim_gate_report", &report);
}

#[test]
fn test_claim_gate_summary_golden() {
    let mut gate = ClaimLanguageGate::new();
    gate.scan_batch(create_test_claims());
    let summary = gate.summary();

    let json = serde_json::to_value(&summary).unwrap();
    assert_json_golden("claim_gate_summary", &json);
}

#[test]
fn test_claim_gate_summary_display_golden() {
    let mut gate = ClaimLanguageGate::new();
    gate.scan_batch(create_test_claims());
    let summary = gate.summary();

    let display_output = format!("{}", summary);
    assert_scrubbed_golden("claim_gate_summary_display", &display_output);
}

#[test]
fn test_claim_gate_events_golden() {
    let mut gate = ClaimLanguageGate::new();
    gate.scan_batch(create_test_claims());
    let events = gate.events();

    let json = serde_json::to_value(events).unwrap();
    assert_scrubbed_json_golden("claim_gate_events", &json);
}

#[test]
fn test_claim_gate_pass_scenario_golden() {
    // Test scenario where all claims pass
    let passing_claims = vec![
        Claim {
            file: "docs/api.md".to_string(),
            line: 10,
            claim_text: "API endpoint responds in under 200ms".to_string(),
            category: ClaimCategory::Api,
            linked_artifact: Some("artifacts/10.16/api_performance_test.json".to_string()),
            artifact_exists: true,
            status: ClaimStatus::Linked,
        },
        Claim {
            file: "docs/storage.md".to_string(),
            line: 20,
            claim_text: "Storage encryption uses AES-256-GCM".to_string(),
            category: ClaimCategory::Storage,
            linked_artifact: Some("artifacts/10.16/storage_encryption_test.json".to_string()),
            artifact_exists: true,
            status: ClaimStatus::Linked,
        },
    ];

    let mut gate = ClaimLanguageGate::new();
    gate.scan_batch(passing_claims);
    let report = gate.to_report();

    assert_scrubbed_json_golden("claim_gate_pass_scenario", &report);
}

#[test]
fn test_claim_gate_fail_scenario_golden() {
    // Test scenario where claims fail
    let failing_claims = vec![
        Claim {
            file: "docs/tui.md".to_string(),
            line: 30,
            claim_text: "TUI supports keyboard navigation".to_string(),
            category: ClaimCategory::Tui,
            linked_artifact: None,
            artifact_exists: false,
            status: ClaimStatus::Unlinked,
        },
        Claim {
            file: "docs/model.md".to_string(),
            line: 40,
            claim_text: "Model supports concurrent access".to_string(),
            category: ClaimCategory::Model,
            linked_artifact: Some("artifacts/10.16/nonexistent.json".to_string()),
            artifact_exists: false,
            status: ClaimStatus::BrokenLink,
        },
    ];

    let mut gate = ClaimLanguageGate::new();
    gate.scan_batch(failing_claims);
    let report = gate.to_report();

    assert_scrubbed_json_golden("claim_gate_fail_scenario", &report);
}

#[test]
fn test_claim_categories_golden() {
    let categories_info = ClaimCategory::all()
        .iter()
        .map(|cat| {
            serde_json::json!({
                "category": cat,
                "label": cat.label(),
                "display": format!("{}", cat)
            })
        })
        .collect::<Vec<_>>();

    let json = serde_json::to_value(&categories_info).unwrap();
    assert_json_golden("claim_categories", &json);
}

#[test]
fn test_claim_status_variants_golden() {
    let status_variants = vec![
        serde_json::json!({
            "status": ClaimStatus::Linked,
            "display": format!("{}", ClaimStatus::Linked),
            "is_pass": ClaimStatus::Linked.is_pass()
        }),
        serde_json::json!({
            "status": ClaimStatus::Unlinked,
            "display": format!("{}", ClaimStatus::Unlinked),
            "is_pass": ClaimStatus::Unlinked.is_pass()
        }),
        serde_json::json!({
            "status": ClaimStatus::BrokenLink,
            "display": format!("{}", ClaimStatus::BrokenLink),
            "is_pass": ClaimStatus::BrokenLink.is_pass()
        }),
    ];

    let json = serde_json::to_value(&status_variants).unwrap();
    assert_json_golden("claim_status_variants", &json);
}

#[test]
fn test_claim_detailed_report_golden() {
    // Create a comprehensive claim report with all details
    let mut gate = ClaimLanguageGate::new();
    gate.scan_batch(create_test_claims());

    let detailed_report = serde_json::json!({
        "gate_report": gate.to_report(),
        "summary": gate.summary(),
        "events": gate.events(),
        "claims": gate.claims(),
        "gate_pass": gate.gate_pass(),
        "metadata": {
            "total_categories": ClaimCategory::all().len(),
            "scan_timestamp": "2024-01-01T00:00:00Z",
            "validator_version": "1.0.0"
        }
    });

    assert_scrubbed_json_golden("claim_detailed_report", &detailed_report);
}

#[test]
fn test_claim_envelope_with_validation_golden() {
    // Create a claim envelope that includes validation results
    let mut gate = ClaimLanguageGate::new();
    gate.scan_batch(create_test_claims());

    let envelope_with_validation = serde_json::json!({
        "envelope": create_test_claim_envelope(),
        "validation": {
            "gate_report": gate.to_report(),
            "gate_pass": gate.gate_pass(),
            "summary": gate.summary(),
            "validated_at": "2024-01-01T00:00:00Z",
            "validator": "franken-node-claim-gate-v1"
        }
    });

    assert_scrubbed_json_golden("claim_envelope_with_validation", &envelope_with_validation);
}
