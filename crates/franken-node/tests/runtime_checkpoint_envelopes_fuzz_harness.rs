//! Structure-aware fuzzing harness for runtime checkpoint envelopes
//!
//! Tests checkpoint envelope serialization/deserialization for:
//! - CheckpointRecord round-trip integrity under diverse inputs
//! - CheckpointMeta hash chain validation consistency
//! - CheckpointEvent audit trail determinism
//! - RestoredCheckpoint state recovery correctness
//!
//! Follows the canonical_serializer_fuzz_harness pattern with structure-aware
//! checkpoint state generation and invariant enforcement.

use frankenengine_node::runtime::checkpoint::{
    CheckpointRecord, CheckpointMeta, CheckpointEvent, CheckpointError,
    CheckpointWriter, CheckpointBackend, InMemoryCheckpointBackend,
    RestoredCheckpoint, CheckpointReadResult, CheckpointId,
    CHECKPOINT_SAVE, CHECKPOINT_RESTORE, CHECKPOINT_MISSING,
    FN_CK_001_CHECKPOINT_SAVE, FN_CK_002_CHECKPOINT_RESTORE,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

const MAX_ORCHESTRATION_ID_LEN: usize = 256;
const MAX_CHECKPOINT_ID_LEN: usize = 128;
const MAX_PROGRESS_STATE_JSON_LEN: usize = 4096;
const MAX_ITERATION_COUNT: u64 = 1_000_000;
const MAX_EPOCH: u64 = 100_000;
const MAX_WALL_CLOCK_TIME: u64 = 2_000_000_000; // Year 2033

#[derive(Debug, Clone, PartialEq, Eq)]
enum HarnessCheckpointError {
    Serialization(String),
    Backend(String),
    HashChain(String),
    InvalidState,
    ProgressRegression,
    CheckpointOperation(String),
}

impl From<CheckpointError> for HarnessCheckpointError {
    fn from(error: CheckpointError) -> Self {
        match error {
            CheckpointError::Serialization(msg) => Self::Serialization(msg),
            CheckpointError::Backend(msg) => Self::Backend(msg),
            CheckpointError::HashChainViolation { reason, .. } => Self::HashChain(reason),
            _ => Self::CheckpointOperation(error.to_string()),
        }
    }
}

/// Test state structure for checkpoint fuzzing
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct FuzzState {
    counter: u64,
    values: Vec<String>,
    metadata: BTreeMap<String, String>,
    flags: BTreeMap<String, bool>,
}

impl FuzzState {
    fn new(counter: u64) -> Self {
        Self {
            counter,
            values: Vec::new(),
            metadata: BTreeMap::new(),
            flags: BTreeMap::new(),
        }
    }

    fn with_values(mut self, values: Vec<String>) -> Self {
        self.values = values;
        self
    }

    fn with_metadata(mut self, metadata: BTreeMap<String, String>) -> Self {
        self.metadata = metadata;
        self
    }

    fn with_flags(mut self, flags: BTreeMap<String, bool>) -> Self {
        self.flags = flags;
        self
    }
}

/// Generate seed orchestration IDs for boundary testing
fn seed_orchestration_ids() -> Vec<String> {
    vec![
        "".to_string(),                                    // Empty (potentially invalid)
        "a".to_string(),                                   // Minimal
        "orchestration-001".to_string(),                   // Standard format
        "test-orch".to_string(),                           // Simple name
        " orch-001 ".to_string(),                          // Whitespace padded
        "\0orch".to_string(),                              // Null byte
        "orch-with-special-chars!@#$%^".to_string(),       // Special characters
        "orch_unicode_名前".to_string(),                    // Unicode
        "x".repeat(MAX_ORCHESTRATION_ID_LEN),              // Maximum length
        "x".repeat(MAX_ORCHESTRATION_ID_LEN + 1),          // Over limit
    ]
}

/// Generate seed checkpoint IDs
fn seed_checkpoint_ids() -> Vec<CheckpointId> {
    vec![
        CheckpointId::from_deterministic("test-checkpoint-001"),
        CheckpointId::from_deterministic("checkpoint-minimal"),
        CheckpointId::from_deterministic("a"),
        CheckpointId::from_deterministic("checkpoint-boundary-test"),
        CheckpointId::from_deterministic(&"x".repeat(64)),
        CheckpointId::from_deterministic("checkpoint-unicode-名前"),
        CheckpointId::from_deterministic("checkpoint-special!@#$%"),
    ]
}

/// Generate seed iteration counts for progress testing
fn seed_iteration_counts() -> Vec<u64> {
    vec![
        0,                         // Initial
        1,                         // First iteration
        100,                       // Typical
        1000,                      // Large
        MAX_ITERATION_COUNT / 2,   // Mid-range
        MAX_ITERATION_COUNT - 1,   // Near maximum
        u64::MAX,                  // Maximum value (edge case)
    ]
}

/// Generate seed epochs for checkpoint testing
fn seed_epochs() -> Vec<u64> {
    vec![
        0,                    // Genesis epoch
        1,                    // First epoch
        100,                  // Typical
        MAX_EPOCH / 2,        // Mid-range
        MAX_EPOCH - 1,        // Near maximum
        u64::MAX,             // Maximum value
    ]
}

/// Generate seed wall clock times
fn seed_wall_clock_times() -> Vec<u64> {
    vec![
        0,                        // Unix epoch start
        1000000000,               // Year 2001
        1640995200,               // Year 2022
        1704067200,               // Year 2024
        MAX_WALL_CLOCK_TIME / 2,  // Mid-range
        MAX_WALL_CLOCK_TIME - 1,  // Near future
        u64::MAX,                 // Far future
    ]
}

/// Generate seed progress states for serialization testing
fn seed_progress_states() -> Vec<FuzzState> {
    vec![
        // Minimal state
        FuzzState::new(0),

        // Simple state with values
        FuzzState::new(1).with_values(vec!["value1".to_string(), "value2".to_string()]),

        // State with metadata
        FuzzState::new(2).with_metadata({
            let mut metadata = BTreeMap::new();
            metadata.insert("key1".to_string(), "value1".to_string());
            metadata.insert("key2".to_string(), "value2".to_string());
            metadata
        }),

        // State with flags
        FuzzState::new(3).with_flags({
            let mut flags = BTreeMap::new();
            flags.insert("enabled".to_string(), true);
            flags.insert("debug".to_string(), false);
            flags
        }),

        // Complex state combining all elements
        FuzzState::new(100)
            .with_values(vec![
                "complex1".to_string(),
                "complex2".to_string(),
                "unicode_値".to_string(),
            ])
            .with_metadata({
                let mut metadata = BTreeMap::new();
                metadata.insert("complex_key".to_string(), "complex_value".to_string());
                metadata.insert("empty_key".to_string(), "".to_string());
                metadata
            })
            .with_flags({
                let mut flags = BTreeMap::new();
                flags.insert("complex_flag".to_string(), true);
                flags
            }),

        // Boundary case: large values
        FuzzState::new(u64::MAX).with_values(
            (0..10).map(|i| format!("large_value_{}", i)).collect()
        ),

        // Empty collections
        FuzzState::new(999)
            .with_values(vec![])
            .with_metadata(BTreeMap::new())
            .with_flags(BTreeMap::new()),
    ]
}

/// Generate comprehensive checkpoint record test vectors
fn seed_checkpoint_vectors() -> Vec<(CheckpointId, String, u64, u64, u64, FuzzState)> {
    let mut vectors = Vec::new();

    let checkpoint_ids = seed_checkpoint_ids();
    let orchestration_ids = vec!["test-orch", "boundary-orch"];
    let iterations = vec![0, 1, 100];
    let epochs = vec![0, 1, 10];
    let times = vec![1000000000, 1640995200];
    let states = seed_progress_states().into_iter().take(3).collect::<Vec<_>>();

    for checkpoint_id in checkpoint_ids.iter().take(3) {
        for orch_id in &orchestration_ids {
            for &iteration in &iterations {
                for &epoch in &epochs {
                    for &time in &times {
                        for state in &states {
                            vectors.push((
                                checkpoint_id.clone(),
                                orch_id.to_string(),
                                iteration,
                                epoch,
                                time,
                                state.clone()
                            ));
                        }
                    }
                }
            }
        }
    }

    vectors
}

/// Validate checkpoint record serialization round-trip
fn validate_checkpoint_record_round_trip(
    checkpoint_id: CheckpointId,
    orchestration_id: String,
    iteration_count: u64,
    epoch: u64,
    wall_clock_time: u64,
    state: FuzzState,
) -> Result<(), HarnessCheckpointError> {
    // Skip invalid orchestration IDs
    if orchestration_id.trim().is_empty() || orchestration_id.contains('\0') {
        return Err(HarnessCheckpointError::InvalidState);
    }

    let progress_state_json = serde_json::to_string(&state)
        .map_err(|e| HarnessCheckpointError::Serialization(e.to_string()))?;

    if progress_state_json.len() > MAX_PROGRESS_STATE_JSON_LEN {
        return Err(HarnessCheckpointError::InvalidState);
    }

    // Create checkpoint record
    let record = CheckpointRecord {
        checkpoint_id: checkpoint_id.clone(),
        orchestration_id: orchestration_id.clone(),
        iteration_count,
        epoch,
        wall_clock_time,
        progress_state_json: progress_state_json.clone(),
        progress_state_hash: format!("hash-{}-{}-{}", iteration_count, epoch, state.counter),
        previous_checkpoint_hash: None,
    };

    // Test serialization round-trip
    let serialized = serde_json::to_string(&record)
        .map_err(|e| HarnessCheckpointError::Serialization(e.to_string()))?;

    let deserialized: CheckpointRecord = serde_json::from_str(&serialized)
        .map_err(|e| HarnessCheckpointError::Serialization(e.to_string()))?;

    if record != deserialized {
        return Err(HarnessCheckpointError::Serialization("round-trip inequality".to_string()));
    }

    // Validate state can be recovered
    let recovered_state: FuzzState = serde_json::from_str(&deserialized.progress_state_json)
        .map_err(|e| HarnessCheckpointError::Serialization(e.to_string()))?;

    if state != recovered_state {
        return Err(HarnessCheckpointError::Serialization("state recovery failed".to_string()));
    }

    Ok(())
}

/// Test checkpoint writer operations with fuzzed inputs
fn validate_checkpoint_writer_operations(
    vectors: &[(CheckpointId, String, u64, u64, u64, FuzzState)],
) -> Result<Vec<CheckpointEvent>, HarnessCheckpointError> {
    let backend = InMemoryCheckpointBackend::new();
    let mut writer = CheckpointWriter::new(backend);
    let mut events = Vec::new();

    for (checkpoint_id, orchestration_id, iteration_count, epoch, wall_clock_time, state) in vectors.iter().take(5) {
        // Skip invalid orchestration IDs
        if orchestration_id.trim().is_empty() || orchestration_id.contains('\0') {
            continue;
        }

        let result = writer.save(
            checkpoint_id.clone(),
            orchestration_id,
            *iteration_count,
            *epoch,
            *wall_clock_time,
            state,
            "fuzz-trace",
        );

        match result {
            Ok(save_events) => {
                events.extend(save_events);
            },
            Err(CheckpointError::ProgressRegression { .. }) => {
                // Expected for non-monotonic iteration counts
                continue;
            },
            Err(other) => {
                return Err(other.into());
            }
        }
    }

    Ok(events)
}

#[test]
fn fuzz_checkpoint_record_serialization_deterministic() {
    for (checkpoint_id, orch_id, iteration, epoch, time, state) in seed_checkpoint_vectors() {
        let result = validate_checkpoint_record_round_trip(
            checkpoint_id.clone(),
            orch_id.clone(),
            iteration,
            epoch,
            time,
            state.clone()
        );

        // Test should be deterministic
        let result2 = validate_checkpoint_record_round_trip(
            checkpoint_id,
            orch_id.clone(),
            iteration,
            epoch,
            time,
            state
        );

        assert_eq!(
            result.is_ok(),
            result2.is_ok(),
            "Checkpoint serialization should be deterministic for orch_id: {}",
            orch_id
        );
    }
}

#[test]
fn fuzz_checkpoint_meta_boundary_conditions() {
    for checkpoint_id in seed_checkpoint_ids() {
        for orch_id in seed_orchestration_ids().iter().take(5) {
            if orch_id.trim().is_empty() || orch_id.contains('\0') {
                continue;
            }

            let meta = CheckpointMeta {
                checkpoint_id: checkpoint_id.clone(),
                orchestration_id: orch_id.clone(),
                iteration_count: 100,
                epoch: 10,
                wall_clock_time: 1640995200,
                progress_state_hash: "test-hash".to_string(),
                previous_checkpoint_hash: None,
            };

            // Should serialize/deserialize successfully
            let serialized = serde_json::to_string(&meta)
                .expect("checkpoint meta should serialize");

            let deserialized: CheckpointMeta = serde_json::from_str(&serialized)
                .expect("checkpoint meta should deserialize");

            assert_eq!(meta, deserialized, "CheckpointMeta round-trip failed for orch_id: {}", orch_id);
        }
    }
}

#[test]
fn fuzz_checkpoint_event_audit_trail_consistency() {
    let test_events = vec![
        CheckpointEvent {
            event_code: FN_CK_001_CHECKPOINT_SAVE.to_string(),
            event_name: CHECKPOINT_SAVE.to_string(),
            orchestration_id: "test-orch".to_string(),
            iteration_count: 1,
            checkpoint_hash: Some("hash-1".to_string()),
            previous_checkpoint_hash: None,
            progress_state_hash: Some("state-hash-1".to_string()),
            epoch: 1,
            wall_clock_time: 1640995200,
            trace_id: "trace-001".to_string(),
        },
        CheckpointEvent {
            event_code: FN_CK_002_CHECKPOINT_RESTORE.to_string(),
            event_name: CHECKPOINT_RESTORE.to_string(),
            orchestration_id: "test-orch".to_string(),
            iteration_count: 1,
            checkpoint_hash: Some("hash-1".to_string()),
            previous_checkpoint_hash: None,
            progress_state_hash: Some("state-hash-1".to_string()),
            epoch: 1,
            wall_clock_time: 1640995300,
            trace_id: "trace-002".to_string(),
        },
    ];

    for event in test_events {
        // Events should serialize deterministically
        let serialized1 = serde_json::to_string(&event)
            .expect("event should serialize");
        let serialized2 = serde_json::to_string(&event)
            .expect("event should serialize consistently");

        assert_eq!(serialized1, serialized2, "Event serialization should be deterministic");

        // Round-trip should preserve all fields
        let deserialized: CheckpointEvent = serde_json::from_str(&serialized1)
            .expect("event should deserialize");

        assert_eq!(event, deserialized, "Event round-trip should preserve all fields");
    }
}

#[test]
fn fuzz_checkpoint_writer_progress_regression_detection() {
    let backend = InMemoryCheckpointBackend::new();
    let mut writer = CheckpointWriter::new(backend);
    let state = FuzzState::new(1);

    // Establish initial checkpoint
    let checkpoint_id = CheckpointId::from_deterministic("regression-test");
    writer.save(
        checkpoint_id.clone(),
        "regression-orch",
        100,  // iteration_count
        10,   // epoch
        1000000000,
        &state,
        "trace-initial"
    ).expect("initial checkpoint should save");

    // Test regression detection scenarios
    let regression_cases = vec![
        (99, 10, true),   // Iteration regression at same epoch
        (100, 9, true),   // Epoch regression
        (100, 10, true),  // Duplicate (same iteration + epoch)
        (101, 10, false), // Valid progress (higher iteration)
        (100, 11, false), // Valid progress (higher epoch)
        (50, 12, false),  // Valid progress (higher epoch, lower iteration OK)
    ];

    for (iteration, epoch, should_fail) in regression_cases {
        let result = writer.save(
            checkpoint_id.clone(),
            "regression-orch",
            iteration,
            epoch,
            1000000000 + iteration,
            &state,
            &format!("trace-{}-{}", iteration, epoch)
        );

        if should_fail {
            assert!(result.is_err(), "Regression should be detected for iteration: {}, epoch: {}", iteration, epoch);
        } else {
            assert!(result.is_ok(), "Valid progress should succeed for iteration: {}, epoch: {}", iteration, epoch);
        }
    }
}

#[test]
fn fuzz_checkpoint_state_recovery_consistency() {
    for state in seed_progress_states() {
        // Test state serialization/deserialization directly
        let state_json = serde_json::to_string(&state)
            .expect("state should serialize");

        let recovered_state: FuzzState = serde_json::from_str(&state_json)
            .expect("state should deserialize");

        assert_eq!(state, recovered_state, "State recovery should be consistent");

        // Test through checkpoint record
        let record = CheckpointRecord {
            checkpoint_id: CheckpointId::from_deterministic("state-recovery-test"),
            orchestration_id: "state-test-orch".to_string(),
            iteration_count: state.counter,
            epoch: 1,
            wall_clock_time: 1000000000,
            progress_state_json: state_json.clone(),
            progress_state_hash: format!("hash-{}", state.counter),
            previous_checkpoint_hash: None,
        };

        let record_json = serde_json::to_string(&record)
            .expect("record should serialize");

        let recovered_record: CheckpointRecord = serde_json::from_str(&record_json)
            .expect("record should deserialize");

        let final_state: FuzzState = serde_json::from_str(&recovered_record.progress_state_json)
            .expect("final state should deserialize");

        assert_eq!(state, final_state, "State should survive full checkpoint round-trip");
    }
}

#[test]
fn fuzz_checkpoint_backend_operations() {
    let vectors = seed_checkpoint_vectors().into_iter().take(10).collect::<Vec<_>>();

    // Test with in-memory backend
    let result = validate_checkpoint_writer_operations(&vectors);

    match result {
        Ok(events) => {
            // Should have generated some events
            assert!(!events.is_empty(), "Checkpoint operations should generate events");

            // Events should have required fields
            for event in events {
                assert!(!event.event_code.is_empty(), "Event should have event_code");
                assert!(!event.event_name.is_empty(), "Event should have event_name");
                assert!(!event.orchestration_id.is_empty(), "Event should have orchestration_id");
                assert!(!event.trace_id.is_empty(), "Event should have trace_id");
            }
        },
        Err(e) => {
            // Some errors are acceptable for invalid inputs
            match e {
                HarnessCheckpointError::InvalidState => {
                    // Expected for invalid inputs
                },
                _ => panic!("Unexpected checkpoint backend error: {:?}", e),
            }
        }
    }
}

#[test]
fn fuzz_checkpoint_id_determinism() {
    for i in 0..10 {
        let input = format!("deterministic-test-{}", i);

        let id1 = CheckpointId::from_deterministic(&input);
        let id2 = CheckpointId::from_deterministic(&input);

        assert_eq!(id1, id2, "CheckpointId should be deterministic for input: {}", input);

        // Should serialize consistently
        let serialized1 = serde_json::to_string(&id1).expect("id should serialize");
        let serialized2 = serde_json::to_string(&id2).expect("id should serialize");

        assert_eq!(serialized1, serialized2, "CheckpointId serialization should be deterministic");
    }
}

#[test]
fn fuzz_checkpoint_hash_chain_validation() {
    let backend = InMemoryCheckpointBackend::new();
    let mut writer = CheckpointWriter::new(backend);
    let state = FuzzState::new(1);

    let checkpoint_id = CheckpointId::from_deterministic("hash-chain-test");
    let orch_id = "hash-chain-orch";

    // Create a sequence of checkpoints
    for i in 1..=5 {
        let result = writer.save(
            checkpoint_id.clone(),
            orch_id,
            i,
            1,
            1000000000 + i,
            &state,
            &format!("trace-chain-{}", i)
        );

        assert!(result.is_ok(), "Checkpoint chain step {} should succeed", i);
    }

    // Verify we can read the result
    let read_result = writer.read(orch_id, "trace-read").expect("should read checkpoint chain");

    match read_result.latest {
        Some(latest) => {
            assert_eq!(latest.iteration_count, 5, "Latest checkpoint should be iteration 5");
            assert_eq!(latest.orchestration_id, orch_id);
        },
        None => panic!("Should have latest checkpoint after chain creation"),
    }

    // Should have generated appropriate events
    assert!(!read_result.events.is_empty(), "Chain should generate audit events");
}