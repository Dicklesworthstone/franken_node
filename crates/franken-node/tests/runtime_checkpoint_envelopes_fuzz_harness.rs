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

use frankenengine_node::runtime::bounded_mask::{CancellationState, CapabilityContext};
use frankenengine_node::runtime::checkpoint::{
    CHECKPOINT_RESTORE, CHECKPOINT_SAVE, CheckpointBackend, CheckpointContract, CheckpointError,
    CheckpointEvent, CheckpointId, CheckpointMeta, CheckpointRecord, CheckpointWriter,
    FN_CK_001_CHECKPOINT_SAVE, FN_CK_002_CHECKPOINT_RESTORE,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use tempfile::TempDir;

const MAX_ORCHESTRATION_ID_LEN: usize = 256;
const MAX_PROGRESS_STATE_JSON_LEN: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq)]
enum HarnessCheckpointError {
    Serialization(String),
    Backend(String),
    HashChain(String),
    InvalidState,
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

/// Real file-based checkpoint backend for mock-free integration testing.
///
/// Uses temporary files with line-delimited JSON to persist checkpoint records.
/// Each orchestration_id gets its own file within a temporary directory.
///
/// This replaces InMemoryCheckpointBackend to test real file I/O paths,
/// serialization edge cases, and filesystem error handling.
#[derive(Debug)]
pub struct TempFileCheckpointBackend {
    _temp_dir: TempDir,
    base_path: PathBuf,
}

impl TempFileCheckpointBackend {
    /// Create a new temporary file-based checkpoint backend.
    ///
    /// Creates a temporary directory that will be automatically cleaned up
    /// when the backend is dropped.
    pub fn new() -> Result<Self, CheckpointError> {
        let temp_dir = TempDir::new()
            .map_err(|e| CheckpointError::Backend(format!("failed to create temp dir: {}", e)))?;

        let base_path = temp_dir.path().to_path_buf();

        eprintln!(
            "[TEMP_CHECKPOINT_BACKEND] Created at: {}",
            base_path.display()
        );

        Ok(Self {
            _temp_dir: temp_dir,
            base_path,
        })
    }

    /// Get the file path for a specific orchestration_id.
    ///
    /// Each orchestration gets its own file to avoid cross-contamination
    /// and enable parallel test execution.
    fn file_path_for_orchestration(&self, orchestration_id: &str) -> PathBuf {
        let hint = orchestration_id
            .chars()
            .take(32)
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                    c
                } else {
                    '_'
                }
            })
            .collect::<String>();
        let hint = if hint.is_empty() {
            "orchestration".to_string()
        } else {
            hint
        };
        let mut hasher = Sha256::new();
        hasher.update(orchestration_id.as_bytes());
        let digest = hex::encode(hasher.finalize());

        self.base_path.join(format!("{hint}-{digest}.jsonl"))
    }

    /// Log operation for debugging test failures.
    fn log_operation(&self, operation: &str, orchestration_id: &str, details: &str) {
        let file_path = self.file_path_for_orchestration(orchestration_id);
        eprintln!(
            "[TEMP_CHECKPOINT_BACKEND] {} orchestration='{}' file='{}' details='{}'",
            operation,
            orchestration_id,
            file_path.display(),
            details
        );
    }
}

impl CheckpointBackend for TempFileCheckpointBackend {
    fn save(&mut self, record: CheckpointRecord) -> Result<bool, CheckpointError> {
        let orchestration_id = &record.orchestration_id;
        let file_path = self.file_path_for_orchestration(orchestration_id);

        // Check if record already exists (idempotency)
        if file_path.exists() {
            let existing_records = self.load_all(orchestration_id)?;
            for existing in existing_records {
                if existing.checkpoint_id == record.checkpoint_id
                    && existing.iteration_count == record.iteration_count
                    && existing.epoch == record.epoch
                {
                    self.log_operation(
                        "SAVE_DUPLICATE",
                        orchestration_id,
                        &format!(
                            "checkpoint_id={:?} iteration={} epoch={}",
                            record.checkpoint_id, record.iteration_count, record.epoch
                        ),
                    );
                    return Ok(false); // Record already exists
                }
            }
        }

        // Serialize record as JSON line
        let json_line = serde_json::to_string(&record).map_err(|e| {
            CheckpointError::Serialization(format!("failed to serialize record: {}", e))
        })?;

        // Append to file (create if doesn't exist)
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&file_path)
            .map_err(|e| {
                CheckpointError::Backend(format!(
                    "failed to open checkpoint file '{}': {}",
                    file_path.display(),
                    e
                ))
            })?;

        writeln!(file, "{}", json_line).map_err(|e| {
            CheckpointError::Backend(format!(
                "failed to write to checkpoint file '{}': {}",
                file_path.display(),
                e
            ))
        })?;

        file.sync_all().map_err(|e| {
            CheckpointError::Backend(format!(
                "failed to sync checkpoint file '{}': {}",
                file_path.display(),
                e
            ))
        })?;

        self.log_operation(
            "SAVE_NEW",
            orchestration_id,
            &format!(
                "checkpoint_id={:?} iteration={} epoch={} file_size={}",
                record.checkpoint_id,
                record.iteration_count,
                record.epoch,
                file_path.metadata().map(|m| m.len()).unwrap_or(0)
            ),
        );

        Ok(true) // New record was inserted
    }

    fn load_all(&self, orchestration_id: &str) -> Result<Vec<CheckpointRecord>, CheckpointError> {
        let file_path = self.file_path_for_orchestration(orchestration_id);

        if !file_path.exists() {
            self.log_operation("LOAD_NO_FILE", orchestration_id, "file does not exist");
            return Ok(Vec::new()); // No records for this orchestration
        }

        let file = fs::File::open(&file_path).map_err(|e| {
            CheckpointError::Backend(format!(
                "failed to open checkpoint file '{}': {}",
                file_path.display(),
                e
            ))
        })?;

        let reader = BufReader::new(file);
        let mut records = Vec::new();

        for (line_num, line_result) in reader.lines().enumerate() {
            let line = line_result.map_err(|e| {
                CheckpointError::Backend(format!(
                    "failed to read line {} from '{}': {}",
                    line_num + 1,
                    file_path.display(),
                    e
                ))
            })?;

            if line.trim().is_empty() {
                continue; // Skip empty lines
            }

            let record: CheckpointRecord = serde_json::from_str(&line).map_err(|e| {
                CheckpointError::Serialization(format!(
                    "failed to deserialize record from line {} in '{}': {}",
                    line_num + 1,
                    file_path.display(),
                    e
                ))
            })?;

            if record.orchestration_id == orchestration_id {
                records.push(record);
            }
        }

        // Sort by iteration_count and epoch to ensure consistent ordering
        records.sort_by_key(|r| (r.iteration_count, r.epoch, r.wall_clock_time));

        self.log_operation(
            "LOAD_SUCCESS",
            orchestration_id,
            &format!("loaded {} records from file", records.len()),
        );

        Ok(records)
    }
}

fn checkpoint_id(seed: &str) -> CheckpointId {
    seed.to_string()
}

fn save_checkpoint_with_temp_backend(
    writer: &mut CheckpointWriter<TempFileCheckpointBackend>,
    orchestration_id: &str,
    iteration_count: u64,
    epoch: u64,
    state: &FuzzState,
    trace_id: &str,
) -> Result<CheckpointId, CheckpointError> {
    let cx = CapabilityContext::new(
        "cx-runtime-checkpoint-harness",
        "operator-checkpoint-harness",
    );
    let mut cancellation = CancellationState::new();
    writer.save_checkpoint(
        &cx,
        &mut cancellation,
        trace_id,
        orchestration_id,
        iteration_count,
        epoch,
        state,
    )
}

#[test]
fn tempfile_checkpoint_backend_isolates_path_colliding_orchestration_ids() {
    let mut backend =
        TempFileCheckpointBackend::new().expect("temp file backend should initialize");
    let left_orchestration_id = "orch.special";
    let right_orchestration_id = "orch/special";

    assert_ne!(
        backend.file_path_for_orchestration(left_orchestration_id),
        backend.file_path_for_orchestration(right_orchestration_id),
        "distinct orchestration IDs must not collapse onto one JSONL file"
    );

    let checkpoint_id = checkpoint_id("path-collision-checkpoint");
    backend
        .save(CheckpointRecord {
            checkpoint_id: checkpoint_id.clone(),
            orchestration_id: left_orchestration_id.to_string(),
            iteration_count: 1,
            epoch: 1,
            wall_clock_time: 1_640_995_200,
            progress_state_json: r#"{"counter":1}"#.to_string(),
            progress_state_hash: "left-state-hash".to_string(),
            previous_checkpoint_hash: None,
        })
        .expect("left checkpoint should save");
    backend
        .save(CheckpointRecord {
            checkpoint_id,
            orchestration_id: right_orchestration_id.to_string(),
            iteration_count: 1,
            epoch: 1,
            wall_clock_time: 1_640_995_201,
            progress_state_json: r#"{"counter":2}"#.to_string(),
            progress_state_hash: "right-state-hash".to_string(),
            previous_checkpoint_hash: None,
        })
        .expect("right checkpoint should save");

    let left_records = backend
        .load_all(left_orchestration_id)
        .expect("left records should load");
    let right_records = backend
        .load_all(right_orchestration_id)
        .expect("right records should load");

    assert_eq!(left_records.len(), 1);
    assert_eq!(right_records.len(), 1);
    assert_eq!(left_records[0].orchestration_id, left_orchestration_id);
    assert_eq!(right_records[0].orchestration_id, right_orchestration_id);
    assert_eq!(left_records[0].progress_state_hash, "left-state-hash");
    assert_eq!(right_records[0].progress_state_hash, "right-state-hash");
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
        "".to_string(),                              // Empty (potentially invalid)
        "a".to_string(),                             // Minimal
        "orchestration-001".to_string(),             // Standard format
        "test-orch".to_string(),                     // Simple name
        " orch-001 ".to_string(),                    // Whitespace padded
        "\0orch".to_string(),                        // Null byte
        "orch-with-special-chars!@#$%^".to_string(), // Special characters
        "orch_unicode_名前".to_string(),             // Unicode
        "x".repeat(MAX_ORCHESTRATION_ID_LEN),        // Maximum length
        "x".repeat(MAX_ORCHESTRATION_ID_LEN + 1),    // Over limit
    ]
}

/// Generate seed checkpoint IDs
fn seed_checkpoint_ids() -> Vec<CheckpointId> {
    vec![
        checkpoint_id("test-checkpoint-001"),
        checkpoint_id("checkpoint-minimal"),
        checkpoint_id("a"),
        checkpoint_id("checkpoint-boundary-test"),
        "x".repeat(64),
        checkpoint_id("checkpoint-unicode-名前"),
        checkpoint_id("checkpoint-special!@#$%"),
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
        FuzzState::new(u64::MAX)
            .with_values((0..10).map(|i| format!("large_value_{}", i)).collect()),
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
    let states = seed_progress_states()
        .into_iter()
        .take(3)
        .collect::<Vec<_>>();

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
                                state.clone(),
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
        return Err(HarnessCheckpointError::Serialization(
            "round-trip inequality".to_string(),
        ));
    }

    // Validate state can be recovered
    let recovered_state: FuzzState = serde_json::from_str(&deserialized.progress_state_json)
        .map_err(|e| HarnessCheckpointError::Serialization(e.to_string()))?;

    if state != recovered_state {
        return Err(HarnessCheckpointError::Serialization(
            "state recovery failed".to_string(),
        ));
    }

    Ok(())
}

/// Test checkpoint writer operations with fuzzed inputs
fn validate_checkpoint_writer_operations(
    vectors: &[(CheckpointId, String, u64, u64, u64, FuzzState)],
) -> Result<Vec<CheckpointEvent>, HarnessCheckpointError> {
    let backend = TempFileCheckpointBackend::new()
        .map_err(|e| HarnessCheckpointError::Backend(e.to_string()))?;
    let mut writer = CheckpointWriter::new(backend);
    let mut events = Vec::new();

    for (_checkpoint_id, orchestration_id, iteration_count, epoch, _wall_clock_time, state) in
        vectors.iter().take(5)
    {
        // Skip invalid orchestration IDs
        if orchestration_id.trim().is_empty() || orchestration_id.contains('\0') {
            continue;
        }

        let event_count_before_save = writer.decision_stream().len();
        let result = save_checkpoint_with_temp_backend(
            &mut writer,
            orchestration_id,
            *iteration_count,
            *epoch,
            state,
            "fuzz-trace",
        );

        match result {
            Ok(_) => {
                events.extend_from_slice(&writer.decision_stream()[event_count_before_save..]);
            }
            Err(CheckpointError::HashChainViolation { .. }) => {
                // Expected for non-monotonic iteration counts
                continue;
            }
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
            state.clone(),
        );

        // Test should be deterministic
        let result2 = validate_checkpoint_record_round_trip(
            checkpoint_id,
            orch_id.clone(),
            iteration,
            epoch,
            time,
            state,
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
            let serialized =
                serde_json::to_string(&meta).expect("checkpoint meta should serialize");

            let deserialized: CheckpointMeta =
                serde_json::from_str(&serialized).expect("checkpoint meta should deserialize");

            assert_eq!(
                meta, deserialized,
                "CheckpointMeta round-trip failed for orch_id: {}",
                orch_id
            );
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
            contract_status: "saved".to_string(),
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
            contract_status: "valid".to_string(),
        },
    ];

    for event in test_events {
        // Events should serialize deterministically
        let serialized1 = serde_json::to_string(&event).expect("event should serialize");
        let serialized2 =
            serde_json::to_string(&event).expect("event should serialize consistently");

        assert_eq!(
            serialized1, serialized2,
            "Event serialization should be deterministic"
        );

        // Round-trip should preserve all fields
        let deserialized: CheckpointEvent =
            serde_json::from_str(&serialized1).expect("event should deserialize");

        assert_eq!(
            event, deserialized,
            "Event round-trip should preserve all fields"
        );
    }
}

#[test]
fn fuzz_checkpoint_writer_progress_regression_detection() {
    let backend = TempFileCheckpointBackend::new().expect("temp file backend should initialize");
    let mut writer = CheckpointWriter::new(backend);
    let state = FuzzState::new(1);

    // Establish initial checkpoint
    save_checkpoint_with_temp_backend(
        &mut writer,
        "regression-orch",
        100, // iteration_count
        10,  // epoch
        &state,
        "trace-initial",
    )
    .expect("initial checkpoint should save");

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
        let result = save_checkpoint_with_temp_backend(
            &mut writer,
            "regression-orch",
            iteration,
            epoch,
            &state,
            &format!("trace-{}-{}", iteration, epoch),
        );

        if should_fail {
            assert!(
                result.is_err(),
                "Regression should be detected for iteration: {}, epoch: {}",
                iteration,
                epoch
            );
        } else {
            assert!(
                result.is_ok(),
                "Valid progress should succeed for iteration: {}, epoch: {}",
                iteration,
                epoch
            );
        }
    }
}

#[test]
fn fuzz_checkpoint_state_recovery_consistency() {
    for state in seed_progress_states() {
        // Test state serialization/deserialization directly
        let state_json = serde_json::to_string(&state).expect("state should serialize");

        let recovered_state: FuzzState =
            serde_json::from_str(&state_json).expect("state should deserialize");

        assert_eq!(
            state, recovered_state,
            "State recovery should be consistent"
        );

        // Test through checkpoint record
        let record = CheckpointRecord {
            checkpoint_id: checkpoint_id("state-recovery-test"),
            orchestration_id: "state-test-orch".to_string(),
            iteration_count: state.counter,
            epoch: 1,
            wall_clock_time: 1000000000,
            progress_state_json: state_json.clone(),
            progress_state_hash: format!("hash-{}", state.counter),
            previous_checkpoint_hash: None,
        };

        let record_json = serde_json::to_string(&record).expect("record should serialize");

        let recovered_record: CheckpointRecord =
            serde_json::from_str(&record_json).expect("record should deserialize");

        let final_state: FuzzState = serde_json::from_str(&recovered_record.progress_state_json)
            .expect("final state should deserialize");

        assert_eq!(
            state, final_state,
            "State should survive full checkpoint round-trip"
        );
    }
}

#[test]
fn fuzz_checkpoint_backend_operations() {
    let vectors = seed_checkpoint_vectors()
        .into_iter()
        .take(10)
        .collect::<Vec<_>>();

    // Test with in-memory backend
    let result = validate_checkpoint_writer_operations(&vectors);

    match result {
        Ok(events) => {
            // Should have generated some events
            assert!(
                !events.is_empty(),
                "Checkpoint operations should generate events"
            );

            // Events should have required fields
            for event in events {
                assert!(!event.event_code.is_empty(), "Event should have event_code");
                assert!(!event.event_name.is_empty(), "Event should have event_name");
                assert!(
                    !event.orchestration_id.is_empty(),
                    "Event should have orchestration_id"
                );
                assert!(!event.trace_id.is_empty(), "Event should have trace_id");
            }
        }
        Err(e) => {
            // Some errors are acceptable for invalid inputs
            assert!(
                matches!(e, HarnessCheckpointError::InvalidState),
                "Unexpected checkpoint backend error: {e:?}"
            );
        }
    }
}

#[test]
fn fuzz_checkpoint_id_determinism() {
    for i in 0..10 {
        let input = format!("deterministic-test-{}", i);

        let id1 = checkpoint_id(&input);
        let id2 = checkpoint_id(&input);

        assert_eq!(
            id1, id2,
            "CheckpointId should be deterministic for input: {}",
            input
        );

        // Should serialize consistently
        let serialized1 = serde_json::to_string(&id1).expect("id should serialize");
        let serialized2 = serde_json::to_string(&id2).expect("id should serialize");

        assert_eq!(
            serialized1, serialized2,
            "CheckpointId serialization should be deterministic"
        );
    }
}

#[test]
fn fuzz_checkpoint_hash_chain_validation() {
    let backend = TempFileCheckpointBackend::new().expect("temp file backend should initialize");
    let mut writer = CheckpointWriter::new(backend);
    let state = FuzzState::new(1);

    let orch_id = "hash-chain-orch";

    // Create a sequence of checkpoints
    for i in 1..=5 {
        let result = save_checkpoint_with_temp_backend(
            &mut writer,
            orch_id,
            i,
            1,
            &state,
            &format!("trace-chain-{}", i),
        );

        assert!(result.is_ok(), "Checkpoint chain step {} should succeed", i);
    }

    // Verify we can read the result
    let read_result = writer
        .read_latest_valid("trace-read", orch_id)
        .expect("should read checkpoint chain");

    let latest = read_result.latest.as_ref();
    assert_eq!(
        latest.map(|meta| meta.iteration_count),
        Some(5),
        "Latest checkpoint should be iteration 5"
    );
    assert_eq!(
        latest.map(|meta| meta.orchestration_id.as_str()),
        Some(orch_id)
    );

    // Should have generated appropriate events
    assert!(
        !read_result.events.is_empty(),
        "Chain should generate audit events"
    );
}
