//! Golden artifact test for decision receipt JSON export format
//!
//! Tests that decision receipt JSON serialization remains stable across versions.
//! Decision receipts are cryptographically signed audit records and any format
//! change would break signature validation and compliance tooling.

use std::{fs, path::Path};
use serde_json::{json, Value};
use frankenengine_node::security::decision_receipt::{Receipt, Decision};

/// Create a deterministic decision receipt for golden testing
fn create_deterministic_receipt() -> Receipt {
    // Use production constructor with deterministic inputs
    let input_data = json!({
        "extension_id": "npm:@malware/data-stealer",
        "action": "quarantine"
    });

    let output_data = json!({
        "status": "quarantined",
        "affected_nodes": 42
    });

    let mut receipt = Receipt::new(
        "quarantine_extension",
        "security-admin@franken-node.prod",
        &input_data,
        &output_data,
        Decision::Approved,
        "Extension exhibits suspicious network behavior patterns consistent with data exfiltration",
        vec![
            "evidence:network-anomaly-detector:2026-001".to_string(),
            "evidence:behavioral-analysis:ext-scan-001".to_string(),
            "evidence:reputation-feed:threat-intel-db".to_string()
        ],
        vec![
            "policy:network-egress-monitoring".to_string(),
            "policy:behavioral-reputation-gate".to_string(),
            "policy:quarantine-on-threat-match".to_string()
        ],
        0.85,
        "franken-node trust release --extension npm:@malware/data-stealer --audit-id AUD-2026-001",
    ).expect("Receipt creation should succeed");

    // Override non-deterministic fields for golden test stability
    receipt.receipt_id = "01234567-89ab-cdef-0123-456789abcdef".to_string();
    receipt.timestamp = "2026-01-01T00:00:00Z".to_string();
    receipt.previous_receipt_hash = Some("previous-receipt-hash-abc123def456".to_string());

    receipt
}

#[test]
fn decision_receipt_json_export_format_golden() {
    let receipt = create_deterministic_receipt();

    // Serialize to pretty-printed JSON (this is the format that would be exported)
    let json_output = serde_json::to_string_pretty(&receipt)
        .expect("Decision receipt should serialize to JSON");

    let golden_path = Path::new("artifacts/golden/decision_receipt.json");

    // Check if we're in update mode
    if std::env::var("UPDATE_GOLDENS").is_ok() {
        fs::create_dir_all(golden_path.parent().unwrap()).unwrap();
        fs::write(golden_path, &json_output).unwrap();
        eprintln!("[GOLDEN] Updated: {}", golden_path.display());
        return;
    }

    // Read expected golden output
    let expected_json = fs::read_to_string(golden_path).unwrap_or_else(|_| {
        panic!(
            "Golden file missing: {}\n\
             Run with UPDATE_GOLDENS=1 to create it\n\
             Then review and commit: git diff artifacts/golden/",
            golden_path.display()
        )
    });

    // Compare byte-for-byte
    if json_output != expected_json {
        let actual_path = Path::new("artifacts/golden/decision_receipt.actual.json");
        fs::write(actual_path, &json_output).unwrap();

        panic!(
            "GOLDEN MISMATCH: Decision receipt JSON format changed\n\n\
             This indicates a breaking change to decision receipt serialization\n\
             that could invalidate existing signatures and break audit compliance.\n\n\
             To update: UPDATE_GOLDENS=1 cargo test decision_receipt_json_export_format_golden\n\
             To review: diff {} {}",
            golden_path.display(),
            actual_path.display(),
        );
    }
}

#[test]
fn decision_receipt_json_schema_stability() {
    let receipt = create_deterministic_receipt();
    let json_value: Value = serde_json::to_value(&receipt)
        .expect("Receipt should convert to JSON value");

    // Verify critical schema elements are present and correctly typed
    assert!(json_value.get("receipt_id").unwrap().is_string());
    assert!(json_value.get("action_name").unwrap().is_string());
    assert!(json_value.get("actor_identity").unwrap().is_string());
    assert!(json_value.get("timestamp").unwrap().is_string());
    assert!(json_value.get("input_hash").unwrap().is_string());
    assert!(json_value.get("output_hash").unwrap().is_string());
    assert!(json_value.get("decision").unwrap().is_string());
    assert!(json_value.get("rationale").unwrap().is_string());
    assert!(json_value.get("evidence_refs").unwrap().is_array());
    assert!(json_value.get("policy_rule_chain").unwrap().is_array());
    assert!(json_value.get("confidence").unwrap().is_number());
    assert!(json_value.get("rollback_command").unwrap().is_string());
    assert!(json_value.get("previous_receipt_hash").unwrap().is_string());

    // Verify decision enum serializes correctly
    assert_eq!(json_value.get("decision").unwrap().as_str().unwrap(), "approved");

    // Verify confidence is serialized as integer (canonical_f64 serialization)
    assert!(json_value.get("confidence").unwrap().is_u64());
}