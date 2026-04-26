//! Regression tests for sync/fsync durability patterns.
//!
//! Ensures critical security modules properly sync writes to durable storage
//! and avoid excessive per-record sync operations that degrade performance.

use frankenengine_node::observability::evidence_ledger::{
    DecisionKind, EvidenceEntry, LabSpillMode, LedgerCapacity,
};
use std::io::Read;
use tempfile::NamedTempFile;

fn test_entry(name: &str, hash: &str, epoch_id: u64, chain_position: u64) -> EvidenceEntry {
    EvidenceEntry {
        schema_version: "sync-durability-regression-v1".to_string(),
        entry_id: Some(format!("EVD-{chain_position:03}")),
        decision_id: name.to_string(),
        decision_kind: DecisionKind::Admit,
        decision_time: "2026-04-26T00:00:00Z".to_string(),
        timestamp_ms: 1_700_000_000_000_u64.saturating_add(chain_position),
        trace_id: format!("trace-{name}"),
        epoch_id,
        payload: serde_json::json!({
            "evidence_hash": hash,
            "chain_position": chain_position,
            "derivation_source": "test",
        }),
        size_bytes: 0,
        signature: format!("sig-{chain_position}"),
        prev_entry_hash: if chain_position > 0 {
            format!("prev-hash-{}", chain_position - 1)
        } else {
            String::new()
        },
    }
}

#[test]
fn evidence_ledger_supports_batched_sync() {
    let temp_file = NamedTempFile::new().expect("create temp file");
    let temp_path = temp_file.path().to_path_buf();

    let capacity = LedgerCapacity {
        max_entries: 1000,
        max_bytes: 1024 * 1024,
    };

    let mut ledger = LabSpillMode::with_file(capacity, &temp_path).expect("create ledger");

    // Append multiple entries without individual syncs
    let entries = (0..5)
        .map(|i| test_entry(&format!("test-evidence-{i}"), &format!("hash-{i}"), 1000 + i as u64, i as u64))
        .collect::<Vec<_>>();

    let mut entry_ids = Vec::new();
    for entry in entries {
        let id = ledger.append(entry).expect("append entry");
        entry_ids.push(id);
    }

    // Batch sync all accumulated writes
    ledger.sync_evidence_durability().expect("sync durability");

    // Verify all entries were persisted
    assert_eq!(entry_ids.len(), 5);
    for id in &entry_ids {
        assert!(id.0 < 5); // All should be valid entry IDs
    }

    // Verify file contains expected content
    let mut file_content = String::new();
    let mut file = std::fs::File::open(&temp_path).expect("open temp file");
    file.read_to_string(&mut file_content).expect("read file");

    let lines: Vec<&str> = file_content.trim().split('\n').collect();
    assert_eq!(lines.len(), 5, "should have 5 JSON lines");

    for (i, line) in lines.iter().enumerate() {
        assert!(
            line.contains(&format!("test-evidence-{i}")),
            "line {i} should contain evidence ID"
        );
        assert!(
            line.contains(&format!("hash-{i}")),
            "line {i} should contain evidence hash"
        );
    }
}

#[test]
fn evidence_ledger_sync_handles_empty_batch() {
    let temp_file = NamedTempFile::new().expect("create temp file");
    let temp_path = temp_file.path().to_path_buf();

    let capacity = LedgerCapacity {
        max_entries: 1000,
        max_bytes: 1024 * 1024,
    };

    let mut ledger = LabSpillMode::with_file(capacity, &temp_path).expect("create ledger");

    // Sync with no entries should not fail
    ledger.sync_evidence_durability().expect("sync empty batch");

    // File should exist but be empty
    let metadata = std::fs::metadata(&temp_path).expect("get file metadata");
    assert_eq!(metadata.len(), 0, "empty ledger file should be 0 bytes");
}

#[test]
fn evidence_ledger_batch_and_sync_preserves_ordering() {
    let temp_file = NamedTempFile::new().expect("create temp file");
    let temp_path = temp_file.path().to_path_buf();

    let capacity = LedgerCapacity {
        max_entries: 1000,
        max_bytes: 1024 * 1024,
    };

    let mut ledger = LabSpillMode::with_file(capacity, &temp_path).expect("create ledger");

    // Append entries in specific order
    let ordered_evidence = ["alpha", "beta", "gamma", "delta"];
    for (i, name) in ordered_evidence.iter().enumerate() {
        let entry = test_entry(name, &format!("{name}-hash"), 2000 + i as u64, i as u64);
        ledger.append(entry).expect("append entry");
    }

    // Sync to ensure durability
    ledger.sync_evidence_durability().expect("sync durability");

    // Verify file preserves order
    let mut file_content = String::new();
    let mut file = std::fs::File::open(&temp_path).expect("open temp file");
    file.read_to_string(&mut file_content).expect("read file");

    let lines: Vec<&str> = file_content.trim().split('\n').collect();
    assert_eq!(lines.len(), 4, "should have 4 ordered entries");

    for (i, &expected_name) in ordered_evidence.iter().enumerate() {
        assert!(
            lines[i].contains(expected_name),
            "line {i} should contain {expected_name} in order"
        );
    }
}
