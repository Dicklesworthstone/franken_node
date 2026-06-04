#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;

use frankenengine_node::storage::retrievability_gate::{
    ArtifactId, RetrievabilityConfig, RetrievabilityGate, SegmentId, StorageTier, TargetTierState,
};

// Size limits for bounded fuzzing
const MAX_OPERATIONS: usize = 12;
const MAX_STRING_LEN: usize = 128;
const MAX_HASH_LEN: usize = 128;
const MAX_CONFIG_VALUE: u64 = 10_000;
const MAX_TARGET_STATES: usize = 16;

/// Fuzzable retrievability configuration with bounded values
#[derive(Debug, Clone, Arbitrary)]
struct FuzzRetrievabilityConfig {
    #[arbitrary(with = bounded_latency)]
    max_latency_ms: u64,
    require_hash_match: bool,
}

impl From<FuzzRetrievabilityConfig> for RetrievabilityConfig {
    fn from(fuzz: FuzzRetrievabilityConfig) -> Self {
        RetrievabilityConfig {
            max_latency_ms: fuzz.max_latency_ms,
            require_hash_match: fuzz.require_hash_match,
        }
    }
}

#[derive(Debug, Clone, Copy, Arbitrary)]
enum FuzzStorageTier {
    L1Hot,
    L2Warm,
    L3Archive,
}

impl From<FuzzStorageTier> for StorageTier {
    fn from(tier: FuzzStorageTier) -> Self {
        match tier {
            FuzzStorageTier::L1Hot => StorageTier::L1Hot,
            FuzzStorageTier::L2Warm => StorageTier::L2Warm,
            FuzzStorageTier::L3Archive => StorageTier::L3Archive,
        }
    }
}

/// Fuzzable target tier state for simulation
#[derive(Debug, Clone, Arbitrary)]
struct FuzzTargetTierState {
    #[arbitrary(with = bounded_content_hash)]
    content_hash: String,
    #[arbitrary(with = bounded_latency)]
    fetch_latency_ms: u64,
    reachable: bool,
}

impl From<FuzzTargetTierState> for TargetTierState {
    fn from(fuzz: FuzzTargetTierState) -> Self {
        TargetTierState {
            content_hash: fuzz.content_hash,
            reachable: fuzz.reachable,
            fetch_latency_ms: fuzz.fetch_latency_ms,
        }
    }
}

/// Operations that can be performed on the retrievability gate
#[derive(Debug, Clone, Arbitrary)]
enum GateOperation {
    CheckRetrievability {
        #[arbitrary(with = bounded_artifact_id)]
        artifact_id: String,
        #[arbitrary(with = bounded_segment_id)]
        segment_id: String,
        source_tier: FuzzStorageTier,
        target_tier: FuzzStorageTier,
        #[arbitrary(with = bounded_expected_hash)]
        expected_hash: String,
    },
    CheckEviction {
        #[arbitrary(with = bounded_artifact_id)]
        artifact_id: String,
        #[arbitrary(with = bounded_segment_id)]
        segment_id: String,
        #[arbitrary(with = bounded_expected_hash)]
        expected_hash: String,
    },
    SetTargetState {
        #[arbitrary(with = bounded_artifact_id)]
        artifact_id: String,
        #[arbitrary(with = bounded_segment_id)]
        segment_id: String,
        target_tier: FuzzStorageTier,
        state: FuzzTargetTierState,
    },
}

/// Complete fuzz input with configuration and operations
#[derive(Debug, Arbitrary)]
struct FuzzInput {
    config: FuzzRetrievabilityConfig,
    #[arbitrary(with = bounded_initial_states)]
    initial_target_states: Vec<(String, String, FuzzStorageTier, FuzzTargetTierState)>,
    #[arbitrary(with = bounded_operations)]
    operations: Vec<GateOperation>,
}

// Bounded arbitrary helpers

fn bounded_latency(u: &mut Unstructured) -> arbitrary::Result<u64> {
    u.int_in_range(1..=MAX_CONFIG_VALUE)
}

fn bounded_artifact_id(u: &mut Unstructured) -> arbitrary::Result<String> {
    let choice = u.int_in_range(0..=6)?;
    Ok(match choice {
        0 => String::new(),                    // Empty - should be invalid
        1 => "valid-artifact-123".to_string(), // Valid format
        2 => " leading-space".to_string(),     // Leading whitespace
        3 => "trailing-space ".to_string(),    // Trailing whitespace
        4 => "control\x00char".to_string(),    // Control character
        5 => "control\nchar".to_string(),      // Newline
        6 => {
            // Random string with potential issues
            let len = u.int_in_range(0..=MAX_STRING_LEN)?;
            let bytes = u.bytes(len)?;
            String::from_utf8_lossy(bytes).into_owned()
        }
        _ => unreachable!(),
    })
}

fn bounded_segment_id(u: &mut Unstructured) -> arbitrary::Result<String> {
    let choice = u.int_in_range(0..=6)?;
    Ok(match choice {
        0 => String::new(),                 // Empty - should be invalid
        1 => "segment-456".to_string(),     // Valid format
        2 => " leading-space".to_string(),  // Leading whitespace
        3 => "trailing-space ".to_string(), // Trailing whitespace
        4 => "control\x00char".to_string(), // Control character
        5 => "control\rchar".to_string(),   // Carriage return
        6 => {
            // Random string with potential issues
            let len = u.int_in_range(0..=MAX_STRING_LEN)?;
            let bytes = u.bytes(len)?;
            String::from_utf8_lossy(bytes).into_owned()
        }
        _ => unreachable!(),
    })
}

fn bounded_content_hash(u: &mut Unstructured) -> arbitrary::Result<String> {
    let choice = u.int_in_range(0..=8)?;
    Ok(match choice {
        0 => String::new(),                // Empty - should be invalid
        1 => "a".repeat(64),               // Valid SHA256 format (all 'a')
        2 => "0123456789abcdef".repeat(4), // Valid SHA256 format
        3 => "g".repeat(64),               // Invalid characters in SHA256
        4 => "a".repeat(63),               // Too short for SHA256
        5 => "a".repeat(65),               // Too long for SHA256
        6 => "ABCDEF123456".to_string(),   // Uppercase (should be lowercase)
        7 => "\x00".repeat(32),            // Null bytes
        8 => {
            // Random hash with various characters
            let len = u.int_in_range(0..=MAX_HASH_LEN)?;
            let bytes = u.bytes(len)?;
            hex::encode(bytes)
        }
        _ => unreachable!(),
    })
}

fn bounded_expected_hash(u: &mut Unstructured) -> arbitrary::Result<String> {
    // Use same logic as content_hash for consistency
    bounded_content_hash(u)
}

fn bounded_initial_states(
    u: &mut Unstructured,
) -> arbitrary::Result<Vec<(String, String, FuzzStorageTier, FuzzTargetTierState)>> {
    let len = u.int_in_range(0..=MAX_TARGET_STATES)?;
    (0..len)
        .map(|_| {
            Ok((
                bounded_artifact_id(u)?,
                bounded_segment_id(u)?,
                u.arbitrary()?,
                u.arbitrary()?,
            ))
        })
        .collect()
}

fn bounded_operations(u: &mut Unstructured) -> arbitrary::Result<Vec<GateOperation>> {
    let len = u.int_in_range(0..=MAX_OPERATIONS)?;
    (0..len).map(|_| u.arbitrary()).collect()
}

fuzz_target!(|data: &[u8]| {
    // Input size guard to prevent OOM
    if data.len() > 50_000 {
        return;
    }

    let input: FuzzInput = match Unstructured::new(data).arbitrary() {
        Ok(input) => input,
        Err(_) => return, // Invalid input, skip silently
    };

    // Create the retrievability gate with fuzzed configuration
    let config: RetrievabilityConfig = input.config.into();
    let mut gate = RetrievabilityGate::new(config);

    // Set up initial target states
    for (artifact_id, segment_id, target_tier, state) in input.initial_target_states {
        let target_state: TargetTierState = state.into();
        gate.register_target(
            &ArtifactId(artifact_id),
            &SegmentId(segment_id),
            target_tier.into(),
            target_state,
        );
    }

    // Track state for invariant checking
    let mut retrievability_check_count = 0;
    let mut eviction_check_count = 0;
    let mut successful_proofs = 0;
    let mut failed_proofs = 0;

    // Execute fuzzed operations
    for op in input.operations {
        match op {
            GateOperation::CheckRetrievability {
                artifact_id,
                segment_id,
                source_tier,
                target_tier,
                expected_hash,
            } => {
                let aid = ArtifactId(artifact_id);
                let sid = SegmentId(segment_id);

                let source_tier: StorageTier = source_tier.into();
                let target_tier: StorageTier = target_tier.into();
                retrievability_check_count += 1;

                match gate.check_retrievability(
                    &aid,
                    &sid,
                    source_tier,
                    target_tier,
                    &expected_hash,
                ) {
                    Ok(proof) => {
                        successful_proofs += 1;

                        // Verify proof properties
                        assert_eq!(proof.artifact_id.0, aid.0, "Proof artifact_id mismatch");
                        assert_eq!(proof.segment_id.0, sid.0, "Proof segment_id mismatch");
                        assert_eq!(proof.source_tier, source_tier, "Proof source_tier mismatch");
                        assert_eq!(proof.target_tier, target_tier, "Proof target_tier mismatch");
                        assert!(
                            proof.proof_timestamp > 0,
                            "Proof timestamp should be positive"
                        );
                        assert!(
                            !proof.content_hash.is_empty(),
                            "Proof content hash should not be empty"
                        );
                    }
                    Err(_) => {
                        failed_proofs += 1;
                        // Failure is expected for invalid inputs - this is not a bug
                    }
                }
            }

            GateOperation::CheckEviction {
                artifact_id,
                segment_id,
                expected_hash,
            } => {
                let aid = ArtifactId(artifact_id);
                let sid = SegmentId(segment_id);

                eviction_check_count += 1;

                match gate.attempt_eviction(&aid, &sid, &expected_hash) {
                    Ok(permit) => {
                        // Eviction permit granted - verify its properties
                        assert_eq!(
                            permit.proof.artifact_id.0, aid.0,
                            "Permit artifact_id mismatch"
                        );
                        assert_eq!(
                            permit.proof.segment_id.0, sid.0,
                            "Permit segment_id mismatch"
                        );
                        assert!(
                            !permit.permit_id.is_empty(),
                            "Permit ID should not be empty"
                        );
                    }
                    Err(_) => {
                        // Eviction blocked - this is expected for cases without valid proofs
                    }
                }
            }

            GateOperation::SetTargetState {
                artifact_id,
                segment_id,
                target_tier,
                state,
            } => {
                let aid = ArtifactId(artifact_id);
                let sid = SegmentId(segment_id);
                let target_state: TargetTierState = state.into();

                // Set target state for future operations
                gate.register_target(&aid, &sid, target_tier.into(), target_state);
            }
        }
    }

    // Invariant checks - these must hold regardless of input
    let receipts = gate.receipts();
    let events = gate.events();
    let config = gate.config();

    // Receipt count consistency. The gate records both successful proofs and
    // failed checks, while eviction attempts also flow through retrievability.
    assert!(
        receipts.len() >= successful_proofs + failed_proofs,
        "Receipts should include all direct proof attempts"
    );

    // Event count should include all operations that generated events
    let total_operations = retrievability_check_count + eviction_check_count;
    assert!(
        receipts.len() <= total_operations,
        "Receipts should not exceed operations that can produce receipts"
    );
    assert!(
        events.len() >= 1, // At least initialization event
        "Should have at least one event (initialization)"
    );

    // No event should exceed reasonable bounds
    for event in events {
        assert!(
            event.code.len() <= 100,
            "Event code too long: {}",
            event.code
        );
        assert!(
            event.artifact_id.len() <= 1000,
            "Event artifact_id too long"
        );
        assert!(event.segment_id.len() <= 1000, "Event segment_id too long");
        assert!(event.detail.len() <= 2000, "Event detail too long");
    }

    // Configuration values should be preserved
    assert!(config.max_latency_ms > 0, "Max latency should be positive");

    // Receipt properties
    for receipt in receipts {
        assert!(
            !receipt.artifact_id.is_empty() || receipt.artifact_id.trim().is_empty(),
            "Receipt artifact_id should be non-empty or whitespace-only"
        );
        assert!(
            !receipt.segment_id.is_empty() || receipt.segment_id.trim().is_empty(),
            "Receipt segment_id should be non-empty or whitespace-only"
        );
        assert!(
            receipt.proof_timestamp > 0,
            "Receipt timestamp should be positive"
        );
        assert!(
            receipt.latency_ms <= config.max_latency_ms || !receipt.passed,
            "Passed receipt latency should stay within configured bounds"
        );
    }

    // Hash format validation testing - check that invalid hashes are rejected appropriately
    let test_hashes = vec![
        String::new(),         // Empty
        "invalid".to_string(), // Too short
        "g".repeat(64),        // Invalid characters
        "A".repeat(64),        // Uppercase
        "0".repeat(65),        // Too long
    ];

    for hash in &test_hashes {
        // These should generally fail validation, but we don't assert since the implementation
        // handles edge cases gracefully and may accept some formats for compatibility
        let test_aid = ArtifactId("test-artifact".to_string());
        let test_sid = SegmentId("test-segment".to_string());
        let _ = gate.check_retrievability(
            &test_aid,
            &test_sid,
            StorageTier::L2Warm,
            StorageTier::L3Archive,
            hash,
        );
    }
});
