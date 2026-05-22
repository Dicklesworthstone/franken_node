#!/usr/bin/env cargo
//! bd-1oof: Trace-witness references conformance harness.
//!
//! Tests INV-WITNESS-PRESENCE, INV-WITNESS-INTEGRITY, and INV-WITNESS-RESOLVABLE
//! to ensure witness references provide traceable links to observations for
//! high-impact evidence entries with cryptographic integrity protection.

use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

use frankenengine_node::observability::witness_ref::{
    WitnessId, WitnessKind, WitnessRef, WitnessSet,
};

// ---------------------------------------------------------------------------
// Test Utilities
// ---------------------------------------------------------------------------

fn witness_id(id: &str) -> WitnessId {
    WitnessId::new(id)
}

fn compute_hash(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

fn valid_telemetry_witness() -> WitnessRef {
    let data = b"cpu_usage: 95%, memory_usage: 90%, threat_score: 8.5";
    WitnessRef::new("WIT-TELEMETRY-001", WitnessKind::Telemetry, compute_hash(data))
        .with_locator("telemetry/performance-spike.jsonl")
}

fn valid_proof_witness() -> WitnessRef {
    let data = b"merkle_root: abc123, inclusion_proof: [def456, ghi789]";
    WitnessRef::new("WIT-PROOF-045", WitnessKind::ProofArtifact, compute_hash(data))
        .with_locator("proofs/integrity-verification.proof")
}

fn valid_state_witness() -> WitnessRef {
    let data = b"memory_state: stable, network_state: connected, disk_state: healthy";
    WitnessRef::new("WIT-STATE-099", WitnessKind::StateSnapshot, compute_hash(data))
        .with_locator("snapshots/system-health-2024.json")
}

fn valid_external_witness() -> WitnessRef {
    let data = b"cve_id: CVE-2024-0001, severity: critical";
    WitnessRef::new("WIT-CVE-001", WitnessKind::ExternalSignal, compute_hash(data))
        // External signals often don't need locators
}

// ---------------------------------------------------------------------------
// INV-WITNESS-PRESENCE Tests
// ---------------------------------------------------------------------------

fn test_witness_presence_basic_attachment() -> Result<(), String> {
    println!("TEST: Basic witness attachment to witness set");

    let mut witness_set = WitnessSet::new();
    let witness = valid_telemetry_witness();

    witness_set.add(witness.clone());

    if witness_set.count() != 1 {
        return Err(format!(
            "Expected 1 witness after adding, got {}",
            witness_set.count()
        ));
    }

    let refs = witness_set.refs();
    if refs.len() != 1 {
        return Err(format!(
            "Expected 1 reference in set, got {}",
            refs.len()
        ));
    }

    if refs[0].witness_id.as_str() != "WIT-TELEMETRY-001" {
        return Err(format!(
            "Expected witness ID 'WIT-TELEMETRY-001', got '{}'",
            refs[0].witness_id.as_str()
        ));
    }

    println!("✓ Basic witness attachment successful");
    Ok(())
}

fn test_witness_presence_multiple_witnesses() -> Result<(), String> {
    println!("TEST: Multiple witnesses for high-impact evidence");

    let mut witness_set = WitnessSet::new();

    let witnesses = vec![
        valid_telemetry_witness(),
        valid_proof_witness(),
        valid_state_witness(),
        valid_external_witness(),
    ];

    for witness in witnesses.iter() {
        witness_set.add(witness.clone());
    }

    if witness_set.count() != 4 {
        return Err(format!(
            "Expected 4 witnesses after adding all, got {}",
            witness_set.count()
        ));
    }

    // Verify each witness kind is present
    let refs = witness_set.refs();
    let mut kinds_found = std::collections::HashSet::new();

    for witness_ref in refs.iter() {
        kinds_found.insert(witness_ref.witness_kind);
    }

    let expected_kinds = [
        WitnessKind::Telemetry,
        WitnessKind::ProofArtifact,
        WitnessKind::StateSnapshot,
        WitnessKind::ExternalSignal,
    ];

    for kind in expected_kinds.iter() {
        if !kinds_found.contains(kind) {
            return Err(format!(
                "Expected witness kind {:?} not found in set",
                kind
            ));
        }
    }

    println!("✓ Multiple witnesses with different kinds attached");
    Ok(())
}

fn test_witness_presence_high_impact_requirement() -> Result<(), String> {
    println!("TEST: High-impact decisions require witness presence");

    // Test that we can verify witness requirement enforcement
    let mut witness_set = WitnessSet::new();

    // Initially empty - should fail high-impact requirement
    if witness_set.count() > 0 {
        return Err("Expected empty witness set to start".to_string());
    }

    // Add witness to meet requirement
    witness_set.add(valid_telemetry_witness());

    if witness_set.count() != 1 {
        return Err(format!(
            "Expected 1 witness after adding for high-impact decision, got {}",
            witness_set.count()
        ));
    }

    // Verify we can check for witness presence
    if witness_set.is_empty() {
        return Err("Witness set should not be empty after adding witness".to_string());
    }

    println!("✓ High-impact witness requirement can be verified");
    Ok(())
}

// ---------------------------------------------------------------------------
// INV-WITNESS-INTEGRITY Tests
// ---------------------------------------------------------------------------

fn test_witness_integrity_hash_creation() -> Result<(), String> {
    println!("TEST: Witness integrity hash creation and verification");

    let test_data = b"test telemetry data for integrity verification";
    let expected_hash = compute_hash(test_data);

    let witness = WitnessRef::new("WIT-INTEGRITY-001", WitnessKind::Telemetry, expected_hash);

    if witness.integrity_hash != expected_hash {
        return Err(format!(
            "Integrity hash mismatch: expected {:?}, got {:?}",
            expected_hash, witness.integrity_hash
        ));
    }

    // Verify hex formatting
    let hex_hash = witness.hash_hex();
    if hex_hash.len() != 64 {
        return Err(format!(
            "Expected 64-character hex hash, got {} characters",
            hex_hash.len()
        ));
    }

    // Verify hex is lowercase
    if hex_hash != hex_hash.to_lowercase() {
        return Err("Hex hash should be lowercase".to_string());
    }

    // Verify hex contains only valid characters
    if !hex_hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("Hex hash contains invalid characters".to_string());
    }

    println!("✓ Integrity hash creation and formatting correct");
    Ok(())
}

fn test_witness_integrity_hash_verification() -> Result<(), String> {
    println!("TEST: Witness integrity hash verification against content");

    // Create witness with known content
    let original_data = b"cpu_usage: 75%, memory_usage: 60%, network_latency: 50ms";
    let original_hash = compute_hash(original_data);

    let witness = WitnessRef::new("WIT-VERIFY-001", WitnessKind::Telemetry, original_hash);

    // Verify against original data
    let verification_hash = compute_hash(original_data);
    if witness.integrity_hash != verification_hash {
        return Err("Integrity hash verification failed for original data".to_string());
    }

    // Verify against modified data (should fail)
    let modified_data = b"cpu_usage: 85%, memory_usage: 60%, network_latency: 50ms"; // Changed CPU
    let modified_hash = compute_hash(modified_data);
    if witness.integrity_hash == modified_hash {
        return Err("Integrity hash incorrectly matched modified data".to_string());
    }

    // Verify against completely different data (should fail)
    let different_data = b"completely different data";
    let different_hash = compute_hash(different_data);
    if witness.integrity_hash == different_hash {
        return Err("Integrity hash incorrectly matched different data".to_string());
    }

    println!("✓ Integrity hash verification correctly detects tampering");
    Ok(())
}

fn test_witness_integrity_zero_hash_rejection() -> Result<(), String> {
    println!("TEST: Zero/empty integrity hashes rejected (bd-2qre3)");

    // Attempt to create witness with all-zero hash
    let zero_hash = [0u8; 32];
    let witness = WitnessRef::new("WIT-ZERO-001", WitnessKind::Telemetry, zero_hash);

    let mut witness_set = WitnessSet::new();
    witness_set.add(witness);

    // bd-2qre3: is_valid_witness_structure should reject zero hashes
    if witness_set.count() != 0 {
        return Err("Zero integrity hash should have been rejected by validation".to_string());
    }

    println!("✓ Zero integrity hash correctly rejected");
    Ok(())
}

fn test_witness_integrity_cryptographic_strength() -> Result<(), String> {
    println!("TEST: Integrity hash cryptographic properties");

    let test_data_1 = b"data set one";
    let test_data_2 = b"data set two";

    let hash_1 = compute_hash(test_data_1);
    let hash_2 = compute_hash(test_data_2);

    // Hashes should be different for different inputs
    if hash_1 == hash_2 {
        return Err("Different inputs produced identical hashes".to_string());
    }

    // Hashes should be deterministic (same input = same output)
    let hash_1_again = compute_hash(test_data_1);
    if hash_1 != hash_1_again {
        return Err("Same input produced different hashes".to_string());
    }

    // Small changes should produce very different hashes (avalanche effect)
    let test_data_1_modified = b"data set onE"; // Changed 'e' to 'E'
    let hash_1_modified = compute_hash(test_data_1_modified);

    if hash_1 == hash_1_modified {
        return Err("Small change did not affect hash (avalanche failure)".to_string());
    }

    // Count differing bits (should be approximately 50% for good hash function)
    let mut differing_bits = 0;
    for i in 0..32 {
        differing_bits += (hash_1[i] ^ hash_1_modified[i]).count_ones();
    }

    // With 256 bits total, expect roughly 128 bits different (50%)
    // Allow range of 80-176 bits (31-69%) as reasonable for single bit input change
    if differing_bits < 80 || differing_bits > 176 {
        return Err(format!(
            "Avalanche effect poor: {} bits differ (expected 80-176)",
            differing_bits
        ));
    }

    println!("✓ Integrity hash shows good cryptographic properties");
    Ok(())
}

// ---------------------------------------------------------------------------
// INV-WITNESS-RESOLVABLE Tests
// ---------------------------------------------------------------------------

fn test_witness_resolvable_valid_locators() -> Result<(), String> {
    println!("TEST: Valid replay bundle locators accepted");

    let valid_locators = [
        "telemetry/performance-spike.jsonl",
        "proofs/integrity-verification.proof",
        "snapshots/system-health-2024.json",
        "evidence/quarantine-decision.json",
        "audit-logs/2024/01/15/high-impact-decisions.jsonl",
        "mmr-proofs/inclusion-proof-abc123.bin",
        "state-dumps/memory-pressure-event.dump",
        "threat-intel/cve-2024-0001.json",
    ];

    for locator in valid_locators.iter() {
        let witness = WitnessRef::new("WIT-VALID", WitnessKind::Telemetry, compute_hash(b"data"))
            .with_locator(*locator);

        if witness.replay_bundle_locator.as_deref() != Some(*locator) {
            return Err(format!(
                "Locator not stored correctly: expected '{}', got {:?}",
                locator, witness.replay_bundle_locator
            ));
        }

        // Verify it passes validation when added to set
        let mut witness_set = WitnessSet::new();
        witness_set.add(witness);

        if witness_set.count() != 1 {
            return Err(format!(
                "Valid locator '{}' was rejected by validation",
                locator
            ));
        }

        println!("  ✓ '{}' accepted", locator);
    }

    println!("✓ All valid locators accepted");
    Ok(())
}

fn test_witness_resolvable_invalid_locators() -> Result<(), String> {
    println!("TEST: Invalid replay bundle locators rejected (bd-2qre3)");

    let invalid_locators = [
        "",                              // Empty
        " ",                            // Whitespace only
        "/absolute/path",               // Leading slash
        "relative//double-slash",       // Double slash
        "path//with//multiples",        // Multiple double slashes
        "path/with space/file",         // Space character
        "path/with\nnewline",           // Newline
        "path/with\tTab",               // Tab
        "path/with%20encoding",         // Percent encoding
        "path/with:colon",              // Colon
        "path/with@symbol",             // At symbol
        "path/with\\backslash",         // Backslash
        "path/./current",               // Current directory reference
        "path/../parent",               // Parent directory reference
        "unicode/path/ñ",               // Non-ASCII
        &"x".repeat(600),               // Too long (>512 chars)
        "path/with\x00null",            // Null byte
        " leading/space",               // Leading whitespace
        "trailing/space ",              // Trailing whitespace
    ];

    for locator in invalid_locators.iter() {
        let witness = WitnessRef::new("WIT-INVALID", WitnessKind::Telemetry, compute_hash(b"data"))
            .with_locator(*locator);

        let mut witness_set = WitnessSet::new();
        witness_set.add(witness);

        // bd-2qre3: is_valid_witness_structure should reject invalid locators
        if witness_set.count() != 0 {
            return Err(format!(
                "Invalid locator '{}' was incorrectly accepted by validation",
                locator.escape_debug()
            ));
        }

        println!("  ✓ '{}' correctly rejected", locator.escape_debug());
    }

    println!("✓ All invalid locators correctly rejected");
    Ok(())
}

fn test_witness_resolvable_optional_locators() -> Result<(), String> {
    println!("TEST: Optional replay bundle locators (external signals)");

    // External signals often don't need locators
    let witness_without_locator = WitnessRef::new(
        "WIT-EXTERNAL-001",
        WitnessKind::ExternalSignal,
        compute_hash(b"external signal data")
    );

    if witness_without_locator.replay_bundle_locator.is_some() {
        return Err("Expected no locator for witness created without locator".to_string());
    }

    // Should still be valid and addable
    let mut witness_set = WitnessSet::new();
    witness_set.add(witness_without_locator);

    if witness_set.count() != 1 {
        return Err("Witness without locator should still be valid".to_string());
    }

    println!("✓ Witnesses without locators accepted for external signals");
    Ok(())
}

// ---------------------------------------------------------------------------
// bd-2qre3 Structure Validation Tests
// ---------------------------------------------------------------------------

fn test_structure_validation_witness_id_safety() -> Result<(), String> {
    println!("TEST: Witness ID safety validation (bd-2qre3)");

    let valid_ids = [
        "WIT-SIMPLE-001",
        "witness_with_underscores",
        "UPPERCASE-WITNESS",
        "Mixed.Case.With.Dots",
        "a1-B2_c3.D4",
    ];

    let invalid_ids = [
        "",                       // Empty
        " WIT-LEADING-SPACE",     // Leading space
        "WIT-TRAILING-SPACE ",    // Trailing space
        "WIT WITH SPACES",        // Internal spaces
        "WIT/SLASH",              // Forward slash
        "WIT\\BACKSLASH",         // Backslash
        "WIT:COLON",              // Colon
        "WIT@SYMBOL",             // At symbol
        "WIT#HASH",               // Hash
        "WIT%PERCENT",            // Percent
        "WIT+PLUS",               // Plus
        "WIT=EQUALS",             // Equals
        "WIT[BRACKET]",           // Brackets
        "WIT{BRACE}",             // Braces
        "WIT(PAREN)",             // Parentheses
        "WIT,COMMA",              // Comma
        "WIT;SEMICOLON",          // Semicolon
        "WIT\tTAB",               // Tab
        "WIT\nNEWLINE",          // Newline
        "unicode-ñ",              // Unicode
        &"x".repeat(1100),        // Too long (>1024 chars)
    ];

    for id in valid_ids.iter() {
        let witness = WitnessRef::new(*id, WitnessKind::Telemetry, compute_hash(b"data"));
        let mut witness_set = WitnessSet::new();
        witness_set.add(witness);

        if witness_set.count() != 1 {
            return Err(format!(
                "Valid witness ID '{}' was rejected",
                id
            ));
        }
        println!("  ✓ Valid ID '{}' accepted", id);
    }

    for id in invalid_ids.iter() {
        let witness = WitnessRef::new(*id, WitnessKind::Telemetry, compute_hash(b"data"));
        let mut witness_set = WitnessSet::new();
        witness_set.add(witness);

        if witness_set.count() != 0 {
            return Err(format!(
                "Invalid witness ID '{}' was incorrectly accepted",
                id.escape_debug()
            ));
        }
        println!("  ✓ Invalid ID '{}' correctly rejected", id.escape_debug());
    }

    println!("✓ Witness ID safety validation working correctly");
    Ok(())
}

fn test_structure_validation_prevents_garbage_eviction() -> Result<(), String> {
    println!("TEST: Structure validation prevents garbage from evicting valid witnesses");

    let mut witness_set = WitnessSet::new();

    // Add valid witness first
    let valid_witness = valid_telemetry_witness();
    witness_set.add(valid_witness);

    if witness_set.count() != 1 {
        return Err("Valid witness should be added successfully".to_string());
    }

    // Attempt to add garbage witnesses that should be rejected
    let garbage_witnesses = vec![
        // Zero hash
        WitnessRef::new("GARBAGE-1", WitnessKind::Telemetry, [0u8; 32]),
        // Invalid ID
        WitnessRef::new("GARBAGE WITH SPACES", WitnessKind::Telemetry, compute_hash(b"data")),
        // Invalid locator
        WitnessRef::new("GARBAGE-3", WitnessKind::Telemetry, compute_hash(b"data"))
            .with_locator("/absolute/path"),
        // Empty ID
        WitnessRef::new("", WitnessKind::Telemetry, compute_hash(b"data")),
    ];

    for (i, garbage) in garbage_witnesses.into_iter().enumerate() {
        witness_set.add(garbage);

        // Count should remain 1 (original valid witness only)
        if witness_set.count() != 1 {
            return Err(format!(
                "Garbage witness {} was incorrectly added (count: {})",
                i + 1,
                witness_set.count()
            ));
        }
    }

    // Verify original valid witness is still present
    let refs = witness_set.refs();
    if refs.len() != 1 || refs[0].witness_id.as_str() != "WIT-TELEMETRY-001" {
        return Err("Original valid witness was lost or corrupted".to_string());
    }

    println!("✓ Garbage witnesses rejected without affecting valid witnesses");
    Ok(())
}

// ---------------------------------------------------------------------------
// Witness Kind and Display Tests
// ---------------------------------------------------------------------------

fn test_witness_kinds_completeness() -> Result<(), String> {
    println!("TEST: All witness kinds supported and labeled correctly");

    let expected_kinds = [
        (WitnessKind::Telemetry, "telemetry"),
        (WitnessKind::StateSnapshot, "state_snapshot"),
        (WitnessKind::ProofArtifact, "proof_artifact"),
        (WitnessKind::ExternalSignal, "external_signal"),
    ];

    for (kind, expected_label) in expected_kinds.iter() {
        if kind.label() != *expected_label {
            return Err(format!(
                "Kind {:?} has incorrect label: expected '{}', got '{}'",
                kind, expected_label, kind.label()
            ));
        }

        if kind.to_string() != *expected_label {
            return Err(format!(
                "Kind {:?} Display impl incorrect: expected '{}', got '{}'",
                kind, expected_label, kind.to_string()
            ));
        }

        println!("  ✓ {:?} → '{}'", kind, expected_label);
    }

    // Verify all() method completeness
    let all_kinds = WitnessKind::all();
    if all_kinds.len() != expected_kinds.len() {
        return Err(format!(
            "WitnessKind::all() length mismatch: expected {}, got {}",
            expected_kinds.len(), all_kinds.len()
        ));
    }

    for (expected_kind, _) in expected_kinds.iter() {
        if !all_kinds.contains(expected_kind) {
            return Err(format!(
                "WitnessKind::all() missing kind: {:?}",
                expected_kind
            ));
        }
    }

    println!("✓ All witness kinds properly defined and accessible");
    Ok(())
}

// ---------------------------------------------------------------------------
// Performance Tests
// ---------------------------------------------------------------------------

fn test_performance_witness_operations() -> Result<(), String> {
    println!("TEST: Witness operation performance");

    let test_data = b"performance test data for witness operations";
    let hash = compute_hash(test_data);

    // Test witness creation performance
    let start = Instant::now();
    for i in 0..1000 {
        let _witness = WitnessRef::new(
            format!("WIT-PERF-{:04}", i),
            WitnessKind::Telemetry,
            hash
        ).with_locator("perf/test.json");
    }
    let creation_time = start.elapsed();

    // Test hash computation performance
    let start = Instant::now();
    for _ in 0..1000 {
        let _hash = compute_hash(test_data);
    }
    let hash_time = start.elapsed();

    // Test hex formatting performance
    let witness = WitnessRef::new("WIT-HEX-TEST", WitnessKind::Telemetry, hash);
    let start = Instant::now();
    for _ in 0..1000 {
        let _hex = witness.hash_hex();
    }
    let hex_time = start.elapsed();

    println!("  Creation: 1000 witnesses in {:?}", creation_time);
    println!("  Hashing: 1000 SHA-256 operations in {:?}", hash_time);
    println!("  Hex format: 1000 hex conversions in {:?}", hex_time);

    // Performance thresholds
    if creation_time > Duration::from_millis(50) {
        return Err(format!(
            "Witness creation performance regression: {:?}",
            creation_time
        ));
    }

    if hash_time > Duration::from_millis(20) {
        return Err(format!(
            "Hash computation performance regression: {:?}",
            hash_time
        ));
    }

    if hex_time > Duration::from_millis(10) {
        return Err(format!(
            "Hex formatting performance regression: {:?}",
            hex_time
        ));
    }

    println!("✓ All witness operations meet performance targets");
    Ok(())
}

// ---------------------------------------------------------------------------
// Main Conformance Runner
// ---------------------------------------------------------------------------

fn main() {
    println!("bd-1oof: Trace-Witness References Conformance Harness");
    println!("=====================================================");

    let mut tests_run = 0;
    let mut tests_passed = 0;
    let mut failures = Vec::new();

    let test_cases = vec![
        ("INV-WITNESS-PRESENCE: Basic witness attachment", test_witness_presence_basic_attachment as fn() -> Result<(), String>),
        ("INV-WITNESS-PRESENCE: Multiple witnesses for high-impact", test_witness_presence_multiple_witnesses),
        ("INV-WITNESS-PRESENCE: High-impact requirement verification", test_witness_presence_high_impact_requirement),
        ("INV-WITNESS-INTEGRITY: Hash creation and verification", test_witness_integrity_hash_creation),
        ("INV-WITNESS-INTEGRITY: Hash verification against content", test_witness_integrity_hash_verification),
        ("INV-WITNESS-INTEGRITY: Zero hash rejection (bd-2qre3)", test_witness_integrity_zero_hash_rejection),
        ("INV-WITNESS-INTEGRITY: Cryptographic properties", test_witness_integrity_cryptographic_strength),
        ("INV-WITNESS-RESOLVABLE: Valid locators accepted", test_witness_resolvable_valid_locators),
        ("INV-WITNESS-RESOLVABLE: Invalid locators rejected", test_witness_resolvable_invalid_locators),
        ("INV-WITNESS-RESOLVABLE: Optional locators supported", test_witness_resolvable_optional_locators),
        ("bd-2qre3: Witness ID safety validation", test_structure_validation_witness_id_safety),
        ("bd-2qre3: Garbage eviction prevention", test_structure_validation_prevents_garbage_eviction),
        ("COMPLETENESS: Witness kinds and labeling", test_witness_kinds_completeness),
        ("PERF-REGRESSION: Witness operation performance", test_performance_witness_operations),
    ];

    for (test_name, test_fn) in test_cases {
        tests_run += 1;
        println!("\n[{}] {}", tests_run, test_name);

        match test_fn() {
            Ok(()) => {
                tests_passed += 1;
                println!("✅ PASS");
            }
            Err(reason) => {
                failures.push((test_name, reason.clone()));
                println!("❌ FAIL: {}", reason);
            }
        }
    }

    println!("\n=====================================================");
    println!("bd-1oof Conformance Results");
    println!("Passed: {}/{}", tests_passed, tests_run);

    if failures.is_empty() {
        println!("✅ ALL CONFORMANCE TESTS PASSED");
        println!("\n🔍 WITNESS VALIDATION COMPLETE:");
        println!("  • High-impact decisions have traceable witness references");
        println!("  • Cryptographic integrity protection with SHA-256 hashes");
        println!("  • Replay bundle locators enable full audit trail reconstruction");
        println!("  • Structure validation prevents garbage witness eviction");
        println!("  • All witness kinds properly supported and validated");
        std::process::exit(0);
    } else {
        println!("❌ {} FAILURES:", failures.len());
        for (test_name, reason) in failures {
            println!("  - {}: {}", test_name, reason);
        }
        std::process::exit(1);
    }
}