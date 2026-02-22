//! bd-nbwo: Replay capsule format for deterministic re-execution (Section 10.17).
//!
//! A replay capsule is a self-contained, deterministic, format-versioned unit
//! that packages inputs, expected outputs, and the environment snapshot needed
//! for offline replay. Third-party verifiers can independently re-execute a
//! capsule and compare outputs without any external dependencies.
//!
//! # Format Versioning
//!
//! Every capsule carries a `format_version` field (u32). The current version is 1.
//! Future versions must maintain backwards-compatible deserialization for version 1
//! capsules.
//!
//! # Invariants
//!
//! - **INV-VSK-CAPSULE-SELF-CONTAINED**: A capsule carries ALL information needed
//!   for deterministic replay. No external lookups, no network, no ambient state.
//! - **INV-VSK-DETERMINISTIC-VERIFY**: Replaying the same capsule always produces
//!   the same output hash.
//! - **INV-VSK-STABLE-API**: The capsule schema is versioned for forward compatibility.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Current format version for replay capsules.
pub const CURRENT_FORMAT_VERSION: u32 = 1;

/// Minimum supported format version.
pub const MIN_FORMAT_VERSION: u32 = 1;

/// Schema identifier for the replay capsule format.
pub const CAPSULE_SCHEMA_ID: &str = "replay-capsule-v1";

// ---------------------------------------------------------------------------
// Core types
// ---------------------------------------------------------------------------

/// A single input event in a replay capsule.
///
/// INV-VSK-CAPSULE-SELF-CONTAINED: inputs carry all data inline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapsuleInput {
    /// Sequence number (monotonically increasing within a capsule).
    pub seq: u64,
    /// Raw input data bytes.
    pub data: Vec<u8>,
    /// Arbitrary key-value metadata for the input.
    pub metadata: BTreeMap<String, String>,
}

/// A single expected output in a replay capsule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapsuleOutput {
    /// Sequence number corresponding to the output.
    pub seq: u64,
    /// Raw expected output data bytes.
    pub data: Vec<u8>,
    /// Deterministic hash of the expected output.
    pub output_hash: String,
}

/// A snapshot of the environment at capsule creation time.
///
/// INV-VSK-CAPSULE-SELF-CONTAINED: the environment snapshot captures
/// everything needed to reproduce the execution context.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvironmentSnapshot {
    /// Runtime version string.
    pub runtime_version: String,
    /// Platform identifier (e.g. "linux-x86_64").
    pub platform: String,
    /// Hash of the configuration used during capsule creation.
    pub config_hash: String,
    /// Additional environment properties.
    pub properties: BTreeMap<String, String>,
}

/// A self-contained replay capsule for deterministic re-execution.
///
/// # INV-VSK-CAPSULE-SELF-CONTAINED
/// The capsule includes inputs, expected outputs, and the full environment
/// snapshot. No external lookups are needed for replay.
///
/// # INV-VSK-DETERMINISTIC-VERIFY
/// Replaying the capsule produces a deterministic hash that can be compared
/// against the `expected_outputs`.
///
/// # INV-VSK-STABLE-API
/// The `format_version` field enables forward-compatible evolution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayCapsule {
    /// Unique capsule identifier.
    pub capsule_id: String,
    /// Format version for compatibility checking.
    pub format_version: u32,
    /// Ordered input events.
    pub inputs: Vec<CapsuleInput>,
    /// Expected output events for verification.
    pub expected_outputs: Vec<CapsuleOutput>,
    /// Environment snapshot at capsule creation time.
    pub environment: EnvironmentSnapshot,
}

// ---------------------------------------------------------------------------
// Capsule errors
// ---------------------------------------------------------------------------

/// Errors that can occur during capsule operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapsuleError {
    /// The capsule ID is empty.
    EmptyId,
    /// The format version is unsupported.
    UnsupportedVersion(u32),
    /// The input sequence is not monotonically increasing.
    NonMonotonicInputSequence,
    /// The capsule has no inputs.
    NoInputs,
    /// The capsule has no expected outputs.
    NoOutputs,
    /// The environment snapshot is incomplete.
    IncompleteEnvironment(String),
    /// Replay produced a different hash than expected.
    ReplayMismatch { expected: String, actual: String },
}

impl std::fmt::Display for CapsuleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyId => write!(f, "capsule_id is empty"),
            Self::UnsupportedVersion(v) => {
                write!(
                    f,
                    "unsupported format_version={v} (min={MIN_FORMAT_VERSION})"
                )
            }
            Self::NonMonotonicInputSequence => {
                write!(f, "input sequence numbers are not strictly increasing")
            }
            Self::NoInputs => write!(f, "capsule has no inputs"),
            Self::NoOutputs => write!(f, "capsule has no expected outputs"),
            Self::IncompleteEnvironment(msg) => {
                write!(f, "incomplete environment snapshot: {msg}")
            }
            Self::ReplayMismatch { expected, actual } => {
                write!(f, "replay mismatch: expected={expected}, actual={actual}")
            }
        }
    }
}

impl std::error::Error for CapsuleError {}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Deterministic XOR-based hash (hex-encoded, 64 chars).
/// INV-VSK-DETERMINISTIC-VERIFY: same input always produces same output.
fn deterministic_hash(data: &str) -> String {
    let mut hash = [0u8; 32];
    for (i, b) in data.bytes().enumerate() {
        hash[i % 32] ^= b;
    }
    hex::encode(hash)
}

// ---------------------------------------------------------------------------
// Capsule operations
// ---------------------------------------------------------------------------

/// Validate a capsule for structural correctness.
///
/// Checks: non-empty ID, supported version, non-empty inputs/outputs,
/// monotonic sequence, and complete environment.
pub fn validate_capsule(capsule: &ReplayCapsule) -> Result<(), CapsuleError> {
    if capsule.capsule_id.is_empty() {
        return Err(CapsuleError::EmptyId);
    }
    if capsule.format_version < MIN_FORMAT_VERSION {
        return Err(CapsuleError::UnsupportedVersion(capsule.format_version));
    }
    if capsule.inputs.is_empty() {
        return Err(CapsuleError::NoInputs);
    }
    if capsule.expected_outputs.is_empty() {
        return Err(CapsuleError::NoOutputs);
    }
    // Check monotonic sequence
    for pair in capsule.inputs.windows(2) {
        if pair[0].seq >= pair[1].seq {
            return Err(CapsuleError::NonMonotonicInputSequence);
        }
    }
    // Check environment
    if capsule.environment.runtime_version.is_empty() {
        return Err(CapsuleError::IncompleteEnvironment(
            "runtime_version is empty".to_string(),
        ));
    }
    if capsule.environment.platform.is_empty() {
        return Err(CapsuleError::IncompleteEnvironment(
            "platform is empty".to_string(),
        ));
    }
    Ok(())
}

/// Replay a capsule and return the computed output hash.
///
/// INV-VSK-DETERMINISTIC-VERIFY: same capsule always produces same hash.
/// INV-VSK-CAPSULE-SELF-CONTAINED: uses only data from the capsule.
pub fn replay(capsule: &ReplayCapsule) -> Result<String, CapsuleError> {
    validate_capsule(capsule)?;

    let input_data: String = capsule
        .inputs
        .iter()
        .map(|inp| format!("{}:{}", inp.seq, hex::encode(&inp.data)))
        .collect::<Vec<_>>()
        .join("|");

    Ok(deterministic_hash(&input_data))
}

/// Replay a capsule and compare the result to the first expected output hash.
///
/// Returns `Ok(true)` if the replay hash matches, `Ok(false)` if it does not,
/// or `Err` if the capsule is structurally invalid.
pub fn replay_and_verify(capsule: &ReplayCapsule) -> Result<bool, CapsuleError> {
    let actual_hash = replay(capsule)?;

    if let Some(first_output) = capsule.expected_outputs.first() {
        Ok(first_output.output_hash == actual_hash)
    } else {
        Err(CapsuleError::NoOutputs)
    }
}

/// Create a new replay capsule from inputs and environment.
///
/// Computes expected output hashes deterministically.
pub fn create_capsule(
    capsule_id: &str,
    inputs: Vec<CapsuleInput>,
    environment: EnvironmentSnapshot,
) -> Result<ReplayCapsule, CapsuleError> {
    if capsule_id.is_empty() {
        return Err(CapsuleError::EmptyId);
    }
    if inputs.is_empty() {
        return Err(CapsuleError::NoInputs);
    }
    for pair in inputs.windows(2) {
        if pair[0].seq >= pair[1].seq {
            return Err(CapsuleError::NonMonotonicInputSequence);
        }
    }
    if environment.runtime_version.is_empty() {
        return Err(CapsuleError::IncompleteEnvironment(
            "runtime_version is empty".to_string(),
        ));
    }

    // Compute the expected output hash from inputs
    let input_data: String = inputs
        .iter()
        .map(|inp| format!("{}:{}", inp.seq, hex::encode(&inp.data)))
        .collect::<Vec<_>>()
        .join("|");
    let output_hash = deterministic_hash(&input_data);

    let expected_outputs = vec![CapsuleOutput {
        seq: 0,
        data: output_hash.as_bytes().to_vec(),
        output_hash,
    }];

    Ok(ReplayCapsule {
        capsule_id: capsule_id.to_string(),
        format_version: CURRENT_FORMAT_VERSION,
        inputs,
        expected_outputs,
        environment,
    })
}

/// Serialize a capsule to canonical JSON.
pub fn to_canonical_json(capsule: &ReplayCapsule) -> Result<String, serde_json::Error> {
    serde_json::to_string(capsule)
}

/// Deserialize a capsule from JSON.
pub fn from_json(json: &str) -> Result<ReplayCapsule, serde_json::Error> {
    serde_json::from_str(json)
}

/// Check whether a format version is supported.
pub fn is_version_supported(version: u32) -> bool {
    version >= MIN_FORMAT_VERSION && version <= CURRENT_FORMAT_VERSION
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_env() -> EnvironmentSnapshot {
        EnvironmentSnapshot {
            runtime_version: "1.0.0".to_string(),
            platform: "linux-x86_64".to_string(),
            config_hash: "aabb".repeat(8),
            properties: BTreeMap::new(),
        }
    }

    fn test_inputs() -> Vec<CapsuleInput> {
        vec![
            CapsuleInput {
                seq: 0,
                data: b"input-0".to_vec(),
                metadata: BTreeMap::new(),
            },
            CapsuleInput {
                seq: 1,
                data: b"input-1".to_vec(),
                metadata: BTreeMap::new(),
            },
            CapsuleInput {
                seq: 2,
                data: b"input-2".to_vec(),
                metadata: BTreeMap::new(),
            },
        ]
    }

    fn test_capsule() -> ReplayCapsule {
        create_capsule("capsule-test-001", test_inputs(), test_env()).unwrap()
    }

    // ── Constants ───────────────────────────────────────────────────

    #[test]
    fn test_current_format_version() {
        assert_eq!(CURRENT_FORMAT_VERSION, 1);
    }

    #[test]
    fn test_min_format_version() {
        assert_eq!(MIN_FORMAT_VERSION, 1);
    }

    #[test]
    fn test_capsule_schema_id() {
        assert_eq!(CAPSULE_SCHEMA_ID, "replay-capsule-v1");
    }

    // ── create_capsule ──────────────────────────────────────────────

    #[test]
    fn test_create_capsule_success() {
        let cap = test_capsule();
        assert_eq!(cap.capsule_id, "capsule-test-001");
        assert_eq!(cap.format_version, CURRENT_FORMAT_VERSION);
        assert_eq!(cap.inputs.len(), 3);
        assert_eq!(cap.expected_outputs.len(), 1);
    }

    #[test]
    fn test_create_capsule_empty_id() {
        let err = create_capsule("", test_inputs(), test_env()).unwrap_err();
        assert_eq!(err, CapsuleError::EmptyId);
    }

    #[test]
    fn test_create_capsule_no_inputs() {
        let err = create_capsule("cap", vec![], test_env()).unwrap_err();
        assert_eq!(err, CapsuleError::NoInputs);
    }

    #[test]
    fn test_create_capsule_non_monotonic() {
        let inputs = vec![
            CapsuleInput {
                seq: 5,
                data: b"a".to_vec(),
                metadata: BTreeMap::new(),
            },
            CapsuleInput {
                seq: 3,
                data: b"b".to_vec(),
                metadata: BTreeMap::new(),
            },
        ];
        let err = create_capsule("cap", inputs, test_env()).unwrap_err();
        assert_eq!(err, CapsuleError::NonMonotonicInputSequence);
    }

    #[test]
    fn test_create_capsule_empty_runtime_version() {
        let mut env = test_env();
        env.runtime_version = String::new();
        let err = create_capsule("cap", test_inputs(), env).unwrap_err();
        assert!(matches!(err, CapsuleError::IncompleteEnvironment(_)));
    }

    // ── validate_capsule ────────────────────────────────────────────

    #[test]
    fn test_validate_capsule_success() {
        let cap = test_capsule();
        assert!(validate_capsule(&cap).is_ok());
    }

    #[test]
    fn test_validate_capsule_empty_id() {
        let mut cap = test_capsule();
        cap.capsule_id = String::new();
        assert_eq!(validate_capsule(&cap).unwrap_err(), CapsuleError::EmptyId);
    }

    #[test]
    fn test_validate_capsule_bad_version() {
        let mut cap = test_capsule();
        cap.format_version = 0;
        assert!(matches!(
            validate_capsule(&cap).unwrap_err(),
            CapsuleError::UnsupportedVersion(0)
        ));
    }

    #[test]
    fn test_validate_capsule_no_inputs() {
        let mut cap = test_capsule();
        cap.inputs.clear();
        assert_eq!(validate_capsule(&cap).unwrap_err(), CapsuleError::NoInputs);
    }

    #[test]
    fn test_validate_capsule_no_outputs() {
        let mut cap = test_capsule();
        cap.expected_outputs.clear();
        assert_eq!(validate_capsule(&cap).unwrap_err(), CapsuleError::NoOutputs);
    }

    #[test]
    fn test_validate_capsule_non_monotonic() {
        let mut cap = test_capsule();
        cap.inputs[2].seq = 0;
        assert_eq!(
            validate_capsule(&cap).unwrap_err(),
            CapsuleError::NonMonotonicInputSequence
        );
    }

    #[test]
    fn test_validate_capsule_empty_runtime_version() {
        let mut cap = test_capsule();
        cap.environment.runtime_version = String::new();
        assert!(matches!(
            validate_capsule(&cap).unwrap_err(),
            CapsuleError::IncompleteEnvironment(_)
        ));
    }

    #[test]
    fn test_validate_capsule_empty_platform() {
        let mut cap = test_capsule();
        cap.environment.platform = String::new();
        assert!(matches!(
            validate_capsule(&cap).unwrap_err(),
            CapsuleError::IncompleteEnvironment(_)
        ));
    }

    // ── replay ──────────────────────────────────────────────────────

    #[test]
    fn test_replay_success() {
        let cap = test_capsule();
        let hash = replay(&cap).unwrap();
        assert_eq!(hash.len(), 64);
    }

    #[test]
    fn test_replay_deterministic() {
        // INV-VSK-DETERMINISTIC-VERIFY
        let cap = test_capsule();
        let h1 = replay(&cap).unwrap();
        let h2 = replay(&cap).unwrap();
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_replay_matches_expected() {
        let cap = test_capsule();
        let hash = replay(&cap).unwrap();
        assert_eq!(hash, cap.expected_outputs[0].output_hash);
    }

    #[test]
    fn test_replay_invalid_capsule() {
        let mut cap = test_capsule();
        cap.capsule_id = String::new();
        assert!(replay(&cap).is_err());
    }

    // ── replay_and_verify ───────────────────────────────────────────

    #[test]
    fn test_replay_and_verify_match() {
        let cap = test_capsule();
        assert!(replay_and_verify(&cap).unwrap());
    }

    #[test]
    fn test_replay_and_verify_mismatch() {
        let mut cap = test_capsule();
        cap.expected_outputs[0].output_hash = "wrong_hash".to_string();
        assert!(!replay_and_verify(&cap).unwrap());
    }

    #[test]
    fn test_replay_and_verify_no_outputs() {
        let mut cap = test_capsule();
        cap.expected_outputs.clear();
        assert!(replay_and_verify(&cap).is_err());
    }

    // ── Serde round-trips ───────────────────────────────────────────

    #[test]
    fn test_capsule_serde_roundtrip() {
        let cap = test_capsule();
        let json = serde_json::to_string(&cap).unwrap();
        let parsed: ReplayCapsule = serde_json::from_str(&json).unwrap();
        assert_eq!(cap, parsed);
    }

    #[test]
    fn test_capsule_input_serde_roundtrip() {
        let input = &test_inputs()[0];
        let json = serde_json::to_string(input).unwrap();
        let parsed: CapsuleInput = serde_json::from_str(&json).unwrap();
        assert_eq!(*input, parsed);
    }

    #[test]
    fn test_capsule_output_serde_roundtrip() {
        let cap = test_capsule();
        let output = &cap.expected_outputs[0];
        let json = serde_json::to_string(output).unwrap();
        let parsed: CapsuleOutput = serde_json::from_str(&json).unwrap();
        assert_eq!(*output, parsed);
    }

    #[test]
    fn test_environment_serde_roundtrip() {
        let env = test_env();
        let json = serde_json::to_string(&env).unwrap();
        let parsed: EnvironmentSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(env, parsed);
    }

    // ── to_canonical_json / from_json ───────────────────────────────

    #[test]
    fn test_canonical_json_roundtrip() {
        let cap = test_capsule();
        let json = to_canonical_json(&cap).unwrap();
        let parsed = from_json(&json).unwrap();
        assert_eq!(cap, parsed);
    }

    #[test]
    fn test_from_json_invalid() {
        assert!(from_json("not json").is_err());
    }

    // ── is_version_supported ────────────────────────────────────────

    #[test]
    fn test_version_supported() {
        assert!(is_version_supported(1));
    }

    #[test]
    fn test_version_unsupported_zero() {
        assert!(!is_version_supported(0));
    }

    #[test]
    fn test_version_unsupported_future() {
        assert!(!is_version_supported(999));
    }

    // ── CapsuleError display ────────────────────────────────────────

    #[test]
    fn test_error_display_empty_id() {
        assert!(format!("{}", CapsuleError::EmptyId).contains("empty"));
    }

    #[test]
    fn test_error_display_unsupported_version() {
        let err = CapsuleError::UnsupportedVersion(0);
        assert!(format!("{err}").contains("unsupported"));
    }

    #[test]
    fn test_error_display_non_monotonic() {
        assert!(format!("{}", CapsuleError::NonMonotonicInputSequence).contains("increasing"));
    }

    #[test]
    fn test_error_display_no_inputs() {
        assert!(format!("{}", CapsuleError::NoInputs).contains("no inputs"));
    }

    #[test]
    fn test_error_display_no_outputs() {
        assert!(format!("{}", CapsuleError::NoOutputs).contains("no expected outputs"));
    }

    #[test]
    fn test_error_display_incomplete_env() {
        let err = CapsuleError::IncompleteEnvironment("missing field".to_string());
        assert!(format!("{err}").contains("incomplete"));
    }

    #[test]
    fn test_error_display_replay_mismatch() {
        let err = CapsuleError::ReplayMismatch {
            expected: "a".to_string(),
            actual: "b".to_string(),
        };
        assert!(format!("{err}").contains("mismatch"));
    }

    // ── Send + Sync ─────────────────────────────────────────────────

    #[test]
    fn test_types_send_sync() {
        fn assert_send<T: Send>() {}
        fn assert_sync<T: Sync>() {}

        assert_send::<ReplayCapsule>();
        assert_sync::<ReplayCapsule>();
        assert_send::<CapsuleInput>();
        assert_sync::<CapsuleInput>();
        assert_send::<CapsuleOutput>();
        assert_sync::<CapsuleOutput>();
        assert_send::<EnvironmentSnapshot>();
        assert_sync::<EnvironmentSnapshot>();
        assert_send::<CapsuleError>();
        assert_sync::<CapsuleError>();
    }

    // ── deterministic_hash ──────────────────────────────────────────

    #[test]
    fn test_deterministic_hash_consistency() {
        let h1 = deterministic_hash("capsule_test");
        let h2 = deterministic_hash("capsule_test");
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64);
    }

    #[test]
    fn test_deterministic_hash_different_inputs() {
        let h1 = deterministic_hash("data_a");
        let h2 = deterministic_hash("data_b");
        assert_ne!(h1, h2);
    }

    // ── Metadata in inputs ──────────────────────────────────────────

    #[test]
    fn test_input_with_metadata() {
        let mut meta = BTreeMap::new();
        meta.insert("source".to_string(), "test".to_string());
        meta.insert("priority".to_string(), "high".to_string());

        let inputs = vec![CapsuleInput {
            seq: 0,
            data: b"data".to_vec(),
            metadata: meta.clone(),
        }];
        let cap = create_capsule("cap-meta", inputs, test_env()).unwrap();
        assert_eq!(cap.inputs[0].metadata.len(), 2);
        assert_eq!(cap.inputs[0].metadata.get("source").unwrap(), "test");
    }

    // ── Environment properties ──────────────────────────────────────

    #[test]
    fn test_environment_with_properties() {
        let mut env = test_env();
        env.properties
            .insert("feature_flag".to_string(), "enabled".to_string());
        let cap = create_capsule("cap-env", test_inputs(), env).unwrap();
        assert_eq!(
            cap.environment.properties.get("feature_flag").unwrap(),
            "enabled"
        );
    }

    // ── Single input capsule ────────────────────────────────────────

    #[test]
    fn test_single_input_capsule() {
        let inputs = vec![CapsuleInput {
            seq: 0,
            data: b"only".to_vec(),
            metadata: BTreeMap::new(),
        }];
        let cap = create_capsule("cap-single", inputs, test_env()).unwrap();
        assert!(validate_capsule(&cap).is_ok());
        assert!(replay_and_verify(&cap).unwrap());
    }
}
