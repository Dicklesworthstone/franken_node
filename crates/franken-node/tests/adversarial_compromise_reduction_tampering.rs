use std::collections::HashMap;
use frankenengine_node::supply_chain::ecosystem_telemetry::CompromiseReductionReport;
use sha2::{Digest, Sha256};
use serde_json;

const CAMPAIGN_NAME: &str = "adversarial-tampering-test";
const CAMPAIGN_VERSION: &str = "2026.01.01";
const TRACE_ID_PREFIX: &str = "trace-tamper";

struct CompromiseReductionHarness {
    entries: Vec<CompromiseReductionReport>,
    integrity_hashes: Vec<String>,
}

impl CompromiseReductionHarness {
    fn new() -> Self {
        Self {
            entries: Vec::new(),
            integrity_hashes: Vec::new(),
        }
    }

    fn add_entry(&mut self, entry: CompromiseReductionReport) {
        // Compute integrity hash for the entry
        let hash = self.compute_entry_hash(&entry);
        self.integrity_hashes.push(hash);
        self.entries.push(entry);
    }

    fn compute_entry_hash(&self, entry: &CompromiseReductionReport) -> String {
        let mut hasher = Sha256::new();

        // Domain separator
        hasher.update(b"compromise_reduction_entry_v1:");

        // Hash all fields with length prefixes to prevent collision
        hasher.update((entry.bead_id.len() as u64).to_le_bytes());
        hasher.update(entry.bead_id.as_bytes());
        hasher.update((entry.generated_at_utc.len() as u64).to_le_bytes());
        hasher.update(entry.generated_at_utc.as_bytes());
        hasher.update((entry.trace_id.len() as u64).to_le_bytes());
        hasher.update(entry.trace_id.as_bytes());
        hasher.update((entry.campaign_name.len() as u64).to_le_bytes());
        hasher.update(entry.campaign_name.as_bytes());
        hasher.update((entry.campaign_version.len() as u64).to_le_bytes());
        hasher.update(entry.campaign_version.as_bytes());
        hasher.update((entry.reproducible_command.len() as u64).to_le_bytes());
        hasher.update(entry.reproducible_command.as_bytes());
        hasher.update(&entry.minimum_required_ratio.to_le_bytes());
        hasher.update(&entry.baseline_compromised.to_le_bytes());
        hasher.update(&entry.hardened_compromised.to_le_bytes());
        hasher.update(&entry.compromise_reduction_ratio.to_le_bytes());
        hasher.update(&entry.total_attack_vectors.to_le_bytes());
        hasher.update(&entry.containment_vectors.to_le_bytes());

        hex::encode(hasher.finalize())
    }

    fn verify_integrity(&self) -> Result<(), String> {
        if self.entries.len() != self.integrity_hashes.len() {
            return Err("Entry count mismatch with integrity hashes".to_string());
        }

        for (i, entry) in self.entries.iter().enumerate() {
            let computed_hash = self.compute_entry_hash(entry);
            let expected_hash = &self.integrity_hashes[i];

            if computed_hash != *expected_hash {
                return Err(format!(
                    "Integrity check failed for entry {}: expected hash {}, got {}",
                    i, expected_hash, computed_hash
                ));
            }
        }

        Ok(())
    }

    fn tamper_entry_post_hash(&mut self, index: usize) -> Result<(), String> {
        if index >= self.entries.len() {
            return Err("Entry index out of bounds".to_string());
        }

        // Tamper with the entry after its hash has been computed
        self.entries[index].baseline_compromised = self.entries[index].baseline_compromised.wrapping_add(1);
        Ok(())
    }

    fn reorder_entries(&mut self, from_index: usize, to_index: usize) -> Result<(), String> {
        if from_index >= self.entries.len() || to_index >= self.entries.len() {
            return Err("Index out of bounds for reordering".to_string());
        }

        let entry = self.entries.remove(from_index);
        let hash = self.integrity_hashes.remove(from_index);

        self.entries.insert(to_index, entry);
        self.integrity_hashes.insert(to_index, hash);
        Ok(())
    }

    fn drop_middle_entry(&mut self) -> Result<(), String> {
        if self.entries.len() < 3 {
            return Err("Need at least 3 entries to drop middle entry".to_string());
        }

        let middle_index = self.entries.len() / 2;
        self.entries.remove(middle_index);
        self.integrity_hashes.remove(middle_index);
        Ok(())
    }
}

fn create_sample_report(
    bead_id: &str,
    baseline_compromised: u64,
    hardened_compromised: u64,
) -> CompromiseReductionReport {
    let trace_id = format!("{}-{}", TRACE_ID_PREFIX, bead_id);
    CompromiseReductionReport {
        bead_id: bead_id.to_string(),
        generated_at_utc: "2026-04-26T16:30:00Z".to_string(),
        trace_id,
        campaign_name: CAMPAIGN_NAME.to_string(),
        campaign_version: CAMPAIGN_VERSION.to_string(),
        reproducible_command: "python3 scripts/check_compromise_reduction_gate.py --json".to_string(),
        minimum_required_ratio: 2.0,
        baseline_compromised,
        hardened_compromised,
        compromise_reduction_ratio: if hardened_compromised == 0 {
            f64::INFINITY
        } else {
            baseline_compromised as f64 / hardened_compromised as f64
        },
        total_attack_vectors: 50,
        containment_vectors: 10,
    }
}

#[test]
fn adversarial_compromise_reduction_tampering_modify_entry_post_hash() {
    let mut harness = CompromiseReductionHarness::new();

    // Generate valid entry sequence
    harness.add_entry(create_sample_report("bd-001", 100, 50));
    harness.add_entry(create_sample_report("bd-002", 80, 20));
    harness.add_entry(create_sample_report("bd-003", 60, 15));

    // Verify integrity before tampering
    assert!(
        harness.verify_integrity().is_ok(),
        "Integrity check should pass before tampering"
    );

    // Tamper with the middle entry post-hash-chain-init
    harness.tamper_entry_post_hash(1).expect("tampering should succeed");

    // Assert integrity check catches the tampering
    let integrity_result = harness.verify_integrity();
    assert!(
        integrity_result.is_err(),
        "Integrity check should detect post-hash tampering"
    );

    let error_msg = integrity_result.unwrap_err();
    assert!(
        error_msg.contains("Integrity check failed for entry 1"),
        "Error should identify the tampered entry: {}",
        error_msg
    );
}

#[test]
fn adversarial_compromise_reduction_tampering_reorder_entries() {
    let mut harness = CompromiseReductionHarness::new();

    // Generate valid entry sequence with different values
    harness.add_entry(create_sample_report("bd-alpha", 100, 50));
    harness.add_entry(create_sample_report("bd-beta", 80, 20));
    harness.add_entry(create_sample_report("bd-gamma", 60, 15));

    // Verify integrity before reordering
    assert!(
        harness.verify_integrity().is_ok(),
        "Integrity check should pass before reordering"
    );

    // Store original entry order for comparison
    let original_bead_ids: Vec<String> = harness.entries.iter()
        .map(|e| e.bead_id.clone())
        .collect();

    // Reorder entries (swap first and last)
    harness.reorder_entries(0, 2).expect("reordering should succeed");

    // Verify entries were actually reordered
    let reordered_bead_ids: Vec<String> = harness.entries.iter()
        .map(|e| e.bead_id.clone())
        .collect();
    assert_ne!(
        original_bead_ids, reordered_bead_ids,
        "Entries should be in different order after reordering"
    );

    // Assert integrity check catches the reordering
    let integrity_result = harness.verify_integrity();
    assert!(
        integrity_result.is_err(),
        "Integrity check should detect entry reordering"
    );

    let error_msg = integrity_result.unwrap_err();
    assert!(
        error_msg.contains("Integrity check failed"),
        "Error should indicate integrity failure: {}",
        error_msg
    );
}

#[test]
fn adversarial_compromise_reduction_tampering_drop_middle_entry() {
    let mut harness = CompromiseReductionHarness::new();

    // Generate valid entry sequence with at least 3 entries
    harness.add_entry(create_sample_report("bd-first", 100, 50));
    harness.add_entry(create_sample_report("bd-middle", 80, 20));
    harness.add_entry(create_sample_report("bd-last", 60, 15));
    harness.add_entry(create_sample_report("bd-extra", 40, 10));

    // Verify integrity before dropping
    assert!(
        harness.verify_integrity().is_ok(),
        "Integrity check should pass before dropping entry"
    );

    let original_count = harness.entries.len();

    // Drop middle entry
    harness.drop_middle_entry().expect("dropping entry should succeed");

    // Verify entry was actually dropped
    assert_eq!(
        harness.entries.len(),
        original_count - 1,
        "Entry count should decrease by 1 after dropping"
    );

    // Assert integrity check catches the missing entry
    let integrity_result = harness.verify_integrity();
    assert!(
        integrity_result.is_err(),
        "Integrity check should detect dropped entry"
    );

    let error_msg = integrity_result.unwrap_err();
    assert!(
        error_msg.contains("Entry count mismatch"),
        "Error should indicate count mismatch: {}",
        error_msg
    );
}

#[test]
fn adversarial_compromise_reduction_tampering_valid_sequence_passes() {
    let mut harness = CompromiseReductionHarness::new();

    // Generate valid entry sequence without tampering
    harness.add_entry(create_sample_report("bd-valid-1", 100, 50));
    harness.add_entry(create_sample_report("bd-valid-2", 80, 20));
    harness.add_entry(create_sample_report("bd-valid-3", 60, 15));

    // Assert integrity check passes for valid sequence
    let integrity_result = harness.verify_integrity();
    assert!(
        integrity_result.is_ok(),
        "Integrity check should pass for valid, untampered sequence: {:?}",
        integrity_result
    );
}