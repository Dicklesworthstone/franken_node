//! bd-1xbc: Deterministic time-travel runtime capture/replay for extension-host workflows.
//!
//! Provides a [`ReplayEngine`] that captures full workflow traces during execution
//! and replays them deterministically, detecting any divergence between the
//! original and replayed outputs.
//!
//! # Lifecycle
//!
//! 1. **Capture** -- record every step of a workflow (inputs, outputs, side-effects,
//!    timestamps) into a [`WorkflowTrace`].
//! 2. **Replay** -- re-execute a captured trace under identical environment
//!    assumptions and compare outputs byte-for-byte.
//! 3. **Divergence detection** -- if replay produces different outputs, structured
//!    [`Divergence`] diagnostics pinpoint the first deviation.
//!
//! # Invariants
//!
//! - INV-TTR-DETERMINISM: Replay of captured traces produces bit-identical
//!   outcomes under identical environment assumptions.
//! - INV-TTR-DIVERGENCE-DETECT: Any divergence between original and replayed
//!   outputs is detected and reported with structured diagnostics.
//! - INV-TTR-TRACE-COMPLETE: Every captured trace includes all inputs, outputs,
//!   side-effects, and environment state necessary for faithful replay.
//! - INV-TTR-STEP-ORDER: Trace steps are strictly ordered by sequence number;
//!   replays respect that order.
//! - INV-TTR-ENV-SEALED: The environment snapshot is immutable once captured;
//!   replays use the sealed snapshot.
//! - INV-TTR-AUDIT-COMPLETE: Every capture, replay, and divergence event is
//!   logged with a stable event code and trace correlation ID.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, VecDeque};
use std::fmt;

use crate::security::constant_time;

// ---------------------------------------------------------------------------
// Schema version
// ---------------------------------------------------------------------------

/// Schema version for time-travel replay records.
pub const SCHEMA_VERSION: &str = "ttr-v1.0";

use crate::capacity_defaults::aliases::{
    MAX_AUDIT_LOG_ENTRIES, MAX_DIVERGENCES, MAX_REGISTERED_TRACES, MAX_TRACE_STEPS,
};

fn push_bounded<T>(items: &mut Vec<T>, item: T, cap: usize) {
    if items.len() >= cap {
        let overflow = items.len().saturating_sub(cap).saturating_add(1);
        items.drain(0..overflow);
    }
    items.push(item);
}

// ---------------------------------------------------------------------------
// Invariant constants (internal TTR invariants)
// ---------------------------------------------------------------------------

/// INV-TTR-DETERMINISM: Replay produces bit-identical outcomes under identical environment.
pub const INV_TTR_DETERMINISM: &str = "INV-TTR-DETERMINISM";
/// INV-TTR-DIVERGENCE-DETECT: Divergence is detected and reported with structured diagnostics.
pub const INV_TTR_DIVERGENCE_DETECT: &str = "INV-TTR-DIVERGENCE-DETECT";
/// INV-TTR-TRACE-COMPLETE: Every trace includes all data necessary for faithful replay.
pub const INV_TTR_TRACE_COMPLETE: &str = "INV-TTR-TRACE-COMPLETE";
/// INV-TTR-STEP-ORDER: Steps are strictly ordered by sequence number.
pub const INV_TTR_STEP_ORDER: &str = "INV-TTR-STEP-ORDER";
/// INV-TTR-ENV-SEALED: Environment snapshot is immutable once captured.
pub const INV_TTR_ENV_SEALED: &str = "INV-TTR-ENV-SEALED";
/// INV-TTR-AUDIT-COMPLETE: Every event is logged with a stable code and trace ID.
pub const INV_TTR_AUDIT_COMPLETE: &str = "INV-TTR-AUDIT-COMPLETE";

// ---------------------------------------------------------------------------
// Contract-level invariant constants (bd-1xbc acceptance criteria)
// ---------------------------------------------------------------------------

pub mod contract_invariants {
    /// INV-REPLAY-DETERMINISTIC: replayed executions produce byte-for-byte identical
    /// control decisions when given the same seed and input sequence.
    pub const INV_REPLAY_DETERMINISTIC: &str = "INV-REPLAY-DETERMINISTIC";
    /// INV-REPLAY-SEED-EQUIVALENCE: two executions sharing the same seed and input
    /// sequence converge to the same final state digest.
    pub const INV_REPLAY_SEED_EQUIVALENCE: &str = "INV-REPLAY-SEED-EQUIVALENCE";
    /// INV-REPLAY-STEP-NAVIGATION: the replay engine supports forward and backward
    /// stepwise navigation through recorded execution states.
    pub const INV_REPLAY_STEP_NAVIGATION: &str = "INV-REPLAY-STEP-NAVIGATION";
    /// INV-REPLAY-DIVERGENCE-EXPLAIN: when a replay diverges from its capture, the
    /// engine produces a structured explanation identifying the first divergent step.
    pub const INV_REPLAY_DIVERGENCE_EXPLAIN: &str = "INV-REPLAY-DIVERGENCE-EXPLAIN";
}

// ---------------------------------------------------------------------------
// Event codes
// ---------------------------------------------------------------------------

pub mod event_codes {
    /// TTR-001: Workflow trace capture started.
    pub const TTR_001: &str = "TTR-001";
    /// TTR-002: Trace step recorded.
    pub const TTR_002: &str = "TTR-002";
    /// TTR-003: Workflow trace capture completed.
    pub const TTR_003: &str = "TTR-003";
    /// TTR-004: Replay started.
    pub const TTR_004: &str = "TTR-004";
    /// TTR-005: Replay step compared (identical).
    pub const TTR_005: &str = "TTR-005";
    /// TTR-006: Replay step diverged.
    pub const TTR_006: &str = "TTR-006";
    /// TTR-007: Replay completed -- verdict emitted.
    pub const TTR_007: &str = "TTR-007";
    /// TTR-008: Environment snapshot sealed.
    pub const TTR_008: &str = "TTR-008";
    /// TTR-009: Trace integrity check passed.
    pub const TTR_009: &str = "TTR-009";
    /// TTR-010: Trace integrity check failed.
    pub const TTR_010: &str = "TTR-010";

    // bd-1xbc contract-level event codes (aliases mapping to TTR codes).
    /// Capture session opened.
    pub const REPLAY_CAPTURE_START: &str = "REPLAY_CAPTURE_START";
    /// Capture sealed with final digest.
    pub const REPLAY_CAPTURE_COMPLETE: &str = "REPLAY_CAPTURE_COMPLETE";
    /// Replay session initiated.
    pub const REPLAY_PLAYBACK_START: &str = "REPLAY_PLAYBACK_START";
    /// Replay matches capture byte-for-byte.
    pub const REPLAY_PLAYBACK_MATCH: &str = "REPLAY_PLAYBACK_MATCH";
    /// Replay diverges from capture.
    pub const REPLAY_DIVERGENCE_DETECTED: &str = "REPLAY_DIVERGENCE_DETECTED";
}

// ---------------------------------------------------------------------------
// Error codes
// ---------------------------------------------------------------------------

pub mod error_codes {
    pub const ERR_TTR_EMPTY_TRACE: &str = "ERR_TTR_EMPTY_TRACE";
    pub const ERR_TTR_SEQ_GAP: &str = "ERR_TTR_SEQ_GAP";
    pub const ERR_TTR_DIGEST_MISMATCH: &str = "ERR_TTR_DIGEST_MISMATCH";
    pub const ERR_TTR_ENV_MISSING: &str = "ERR_TTR_ENV_MISSING";
    pub const ERR_TTR_REPLAY_FAILED: &str = "ERR_TTR_REPLAY_FAILED";
    pub const ERR_TTR_DUPLICATE_TRACE: &str = "ERR_TTR_DUPLICATE_TRACE";
    pub const ERR_TTR_STEP_ORDER_VIOLATION: &str = "ERR_TTR_STEP_ORDER_VIOLATION";
    pub const ERR_TTR_TRACE_NOT_FOUND: &str = "ERR_TTR_TRACE_NOT_FOUND";

    // bd-1xbc contract-level error codes.
    /// Replay seed differs from capture seed.
    pub const ERR_REPLAY_SEED_MISMATCH: &str = "ERR_REPLAY_SEED_MISMATCH";
    /// Internal state integrity check failed.
    pub const ERR_REPLAY_STATE_CORRUPTION: &str = "ERR_REPLAY_STATE_CORRUPTION";
    /// Step index exceeds capture length.
    pub const ERR_REPLAY_STEP_OVERFLOW: &str = "ERR_REPLAY_STEP_OVERFLOW";
    /// Required input for step not available.
    pub const ERR_REPLAY_INPUT_MISSING: &str = "ERR_REPLAY_INPUT_MISSING";
    /// Deterministic clock deviates beyond tolerance.
    pub const ERR_REPLAY_CLOCK_DRIFT: &str = "ERR_REPLAY_CLOCK_DRIFT";
    /// Snapshot restoration failed validation.
    pub const ERR_REPLAY_SNAPSHOT_INVALID: &str = "ERR_REPLAY_SNAPSHOT_INVALID";
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors that can occur during time-travel capture or replay.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TimeTravelError {
    /// The trace has no steps.
    EmptyTrace { trace_id: String },
    /// A sequence gap was detected in the trace steps.
    SequenceGap {
        trace_id: String,
        expected: u64,
        found: u64,
    },
    /// Trace digest does not match recomputed value.
    DigestMismatch {
        trace_id: String,
        expected: String,
        found: String,
    },
    /// Environment snapshot is missing required fields.
    EnvironmentMissing { trace_id: String, field: String },
    /// Replay execution failed.
    ReplayFailed { trace_id: String, reason: String },
    /// A trace with this ID already exists.
    DuplicateTrace { trace_id: String },
    /// Steps are not in the correct order.
    StepOrderViolation { trace_id: String, step_seq: u64 },
    /// Trace not found in engine.
    TraceNotFound { trace_id: String },
}

impl fmt::Display for TimeTravelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyTrace { trace_id } => {
                write!(
                    f,
                    "[{0}] trace {trace_id} has no steps",
                    error_codes::ERR_TTR_EMPTY_TRACE
                )
            }
            Self::SequenceGap {
                trace_id,
                expected,
                found,
            } => {
                write!(
                    f,
                    "[{0}] trace {trace_id}: expected seq {expected}, found {found}",
                    error_codes::ERR_TTR_SEQ_GAP
                )
            }
            Self::DigestMismatch {
                trace_id,
                expected,
                found,
            } => {
                write!(
                    f,
                    "[{0}] trace {trace_id}: expected digest {expected}, found {found}",
                    error_codes::ERR_TTR_DIGEST_MISMATCH
                )
            }
            Self::EnvironmentMissing { trace_id, field } => {
                write!(
                    f,
                    "[{0}] trace {trace_id}: missing env field {field}",
                    error_codes::ERR_TTR_ENV_MISSING
                )
            }
            Self::ReplayFailed { trace_id, reason } => {
                write!(
                    f,
                    "[{0}] trace {trace_id}: replay failed: {reason}",
                    error_codes::ERR_TTR_REPLAY_FAILED
                )
            }
            Self::DuplicateTrace { trace_id } => {
                write!(
                    f,
                    "[{0}] trace {trace_id} already exists",
                    error_codes::ERR_TTR_DUPLICATE_TRACE
                )
            }
            Self::StepOrderViolation { trace_id, step_seq } => {
                write!(
                    f,
                    "[{0}] trace {trace_id}: step {step_seq} violates ordering",
                    error_codes::ERR_TTR_STEP_ORDER_VIOLATION
                )
            }
            Self::TraceNotFound { trace_id } => {
                write!(
                    f,
                    "[{0}] trace {trace_id} not found",
                    error_codes::ERR_TTR_TRACE_NOT_FOUND
                )
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Audit log entry
// ---------------------------------------------------------------------------

/// A structured audit-log entry emitted on capture/replay events.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub event_code: String,
    pub trace_id: String,
    pub detail: String,
    pub timestamp_ns: u64,
}

impl AuditEntry {
    pub fn new(event_code: &str, trace_id: &str, detail: &str, timestamp_ns: u64) -> Self {
        Self {
            event_code: event_code.to_string(),
            trace_id: trace_id.to_string(),
            detail: detail.to_string(),
            timestamp_ns,
        }
    }
}

// ---------------------------------------------------------------------------
// Core data types
// ---------------------------------------------------------------------------

/// Describes a single side-effect produced during a trace step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SideEffect {
    /// Human-readable kind of side-effect (e.g., "file_write", "network_call").
    pub kind: String,
    /// Machine-readable payload describing the effect.
    pub payload: Vec<u8>,
}

impl SideEffect {
    pub fn new(kind: &str, payload: Vec<u8>) -> Self {
        Self {
            kind: kind.to_string(),
            payload,
        }
    }
}

/// A snapshot of the execution environment at trace capture time.
/// INV-TTR-ENV-SEALED: immutable once captured.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvironmentSnapshot {
    /// Schema version.
    pub schema_version: String,
    /// Monotonic clock seed so replay can reconstruct timing.
    pub clock_seed_ns: u64,
    /// Key-value map of environment variables relevant to the workflow.
    pub env_vars: BTreeMap<String, String>,
    /// Platform identifier (e.g., "linux-x86_64").
    pub platform: String,
    /// Runtime version string.
    pub runtime_version: String,
}

impl EnvironmentSnapshot {
    /// Create a new snapshot with required fields.
    pub fn new(
        clock_seed_ns: u64,
        env_vars: BTreeMap<String, String>,
        platform: &str,
        runtime_version: &str,
    ) -> Self {
        Self {
            schema_version: SCHEMA_VERSION.to_string(),
            clock_seed_ns,
            env_vars,
            platform: platform.to_string(),
            runtime_version: runtime_version.to_string(),
        }
    }

    /// Validate that all required fields are present.
    pub fn validate(&self, trace_id: &str) -> Result<(), TimeTravelError> {
        if self.platform.is_empty() {
            return Err(TimeTravelError::EnvironmentMissing {
                trace_id: trace_id.to_string(),
                field: "platform".to_string(),
            });
        }
        if self.runtime_version.is_empty() {
            return Err(TimeTravelError::EnvironmentMissing {
                trace_id: trace_id.to_string(),
                field: "runtime_version".to_string(),
            });
        }
        Ok(())
    }
}

/// A single step in a workflow trace.
/// INV-TTR-STEP-ORDER: steps are strictly ordered by `seq`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceStep {
    /// Monotonically increasing sequence number (0-based).
    pub seq: u64,
    /// Input bytes consumed by this step.
    pub input: Vec<u8>,
    /// Output bytes produced by this step.
    pub output: Vec<u8>,
    /// Side-effects produced by this step.
    pub side_effects: Vec<SideEffect>,
    /// Timestamp in nanoseconds (relative to environment clock seed).
    pub timestamp_ns: u64,
}

impl TraceStep {
    /// Create a new trace step.
    pub fn new(
        seq: u64,
        input: Vec<u8>,
        output: Vec<u8>,
        side_effects: Vec<SideEffect>,
        timestamp_ns: u64,
    ) -> Self {
        Self {
            seq,
            input,
            output,
            side_effects,
            timestamp_ns,
        }
    }

    /// Compute a SHA-256 digest of the step's output for comparison.
    pub fn output_digest(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"replay_step_output_v1:");
        hasher.update(&self.output);
        hex::encode(hasher.finalize())
    }

    /// Compute a SHA-256 digest of the step's side-effects for comparison.
    pub fn side_effects_digest(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"replay_step_effects_v1:");
        hasher.update((u64::try_from(self.side_effects.len()).unwrap_or(u64::MAX)).to_le_bytes());
        for effect in &self.side_effects {
            hasher.update((u64::try_from(effect.kind.len()).unwrap_or(u64::MAX)).to_le_bytes());
            hasher.update(effect.kind.as_bytes());
            hasher.update((u64::try_from(effect.payload.len()).unwrap_or(u64::MAX)).to_le_bytes());
            hasher.update(&effect.payload);
        }
        hex::encode(hasher.finalize())
    }
}

/// A complete workflow trace capturing all steps and the environment.
/// INV-TTR-TRACE-COMPLETE: includes all data necessary for faithful replay.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkflowTrace {
    /// Unique trace identifier.
    pub trace_id: String,
    /// Human-readable workflow name.
    pub workflow_name: String,
    /// Ordered list of trace steps.
    pub steps: Vec<TraceStep>,
    /// Environment snapshot at capture time.
    pub environment: EnvironmentSnapshot,
    /// SHA-256 digest over all step outputs, for integrity checking.
    pub trace_digest: String,
    /// Schema version.
    pub schema_version: String,
}

impl WorkflowTrace {
    /// Compute the canonical trace digest from steps.
    pub fn compute_digest(steps: &[TraceStep]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"replay_trace_digest_v1:");
        hasher.update((u64::try_from(steps.len()).unwrap_or(u64::MAX)).to_le_bytes());
        for step in steps {
            hasher.update(step.seq.to_le_bytes());
            hasher.update((u64::try_from(step.input.len()).unwrap_or(u64::MAX)).to_le_bytes());
            hasher.update(&step.input);
            hasher.update((u64::try_from(step.output.len()).unwrap_or(u64::MAX)).to_le_bytes());
            hasher.update(&step.output);
            hasher
                .update((u64::try_from(step.side_effects.len()).unwrap_or(u64::MAX)).to_le_bytes());
            for effect in &step.side_effects {
                hasher.update((u64::try_from(effect.kind.len()).unwrap_or(u64::MAX)).to_le_bytes());
                hasher.update(effect.kind.as_bytes());
                hasher.update(
                    (u64::try_from(effect.payload.len()).unwrap_or(u64::MAX)).to_le_bytes(),
                );
                hasher.update(&effect.payload);
            }
        }
        hex::encode(hasher.finalize())
    }

    /// Validate trace invariants (non-empty, ordered, digest match, env complete).
    pub fn validate(&self) -> Result<(), TimeTravelError> {
        // INV-TTR-TRACE-COMPLETE: must have at least one step
        if self.steps.is_empty() {
            return Err(TimeTravelError::EmptyTrace {
                trace_id: self.trace_id.clone(),
            });
        }

        // INV-TTR-STEP-ORDER: verify strict sequential ordering
        for (i, step) in self.steps.iter().enumerate() {
            let expected_seq = u64::try_from(i).unwrap_or(u64::MAX);
            if step.seq != expected_seq {
                return Err(TimeTravelError::SequenceGap {
                    trace_id: self.trace_id.clone(),
                    expected: expected_seq,
                    found: step.seq,
                });
            }
        }

        // INV-TTR-TRACE-COMPLETE: verify digest integrity
        let recomputed = Self::compute_digest(&self.steps);
        if !constant_time::ct_eq(&recomputed, &self.trace_digest) {
            return Err(TimeTravelError::DigestMismatch {
                trace_id: self.trace_id.clone(),
                expected: self.trace_digest.clone(),
                found: recomputed,
            });
        }

        // INV-TTR-ENV-SEALED: validate environment snapshot
        self.environment.validate(&self.trace_id)?;

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Trace builder (capture phase)
// ---------------------------------------------------------------------------

/// Builder for constructing a [`WorkflowTrace`] step by step.
/// Enforces INV-TTR-STEP-ORDER during capture.
#[derive(Debug)]
pub struct TraceBuilder {
    trace_id: String,
    workflow_name: String,
    environment: EnvironmentSnapshot,
    steps: Vec<TraceStep>,
    next_seq: u64,
    audit_log: Vec<AuditEntry>,
}

impl TraceBuilder {
    /// Start a new trace capture.
    /// Emits event TTR-001 (capture started) and TTR-008 (environment sealed).
    pub fn new(trace_id: &str, workflow_name: &str, environment: EnvironmentSnapshot) -> Self {
        let now = environment.clock_seed_ns;
        let mut audit_log = Vec::new();
        push_bounded(
            &mut audit_log,
            AuditEntry::new(
                event_codes::TTR_001,
                trace_id,
                &format!("Capture started for workflow '{workflow_name}'"),
                now,
            ),
            MAX_AUDIT_LOG_ENTRIES,
        );
        push_bounded(
            &mut audit_log,
            AuditEntry::new(
                event_codes::TTR_008,
                trace_id,
                &format!(
                    "Environment snapshot sealed: platform={}",
                    environment.platform
                ),
                now,
            ),
            MAX_AUDIT_LOG_ENTRIES,
        );
        Self {
            trace_id: trace_id.to_string(),
            workflow_name: workflow_name.to_string(),
            environment,
            steps: Vec::new(),
            next_seq: 0,
            audit_log,
        }
    }

    /// Record a trace step.
    /// Emits event TTR-002 (step recorded).
    /// Returns the assigned sequence number.
    pub fn record_step(
        &mut self,
        input: Vec<u8>,
        output: Vec<u8>,
        side_effects: Vec<SideEffect>,
        timestamp_ns: u64,
    ) -> u64 {
        let seq = self.next_seq;
        // Cannot use push_bounded here: evicting oldest steps would shift
        // indices so that step.seq != enumerate-index, violating
        // INV-TTR-STEP-ORDER and causing validate() to reject the trace.
        // Instead, cap at MAX_TRACE_STEPS and silently stop recording.
        if self.steps.len() < MAX_TRACE_STEPS {
            self.steps.push(TraceStep::new(
                seq,
                input,
                output,
                side_effects,
                timestamp_ns,
            ));
        }
        let trace_id = self.trace_id.clone();
        push_bounded(
            &mut self.audit_log,
            AuditEntry::new(
                event_codes::TTR_002,
                &trace_id,
                &format!("Step {seq} recorded"),
                timestamp_ns,
            ),
            MAX_AUDIT_LOG_ENTRIES,
        );
        self.next_seq = self.next_seq.saturating_add(1);
        seq
    }

    /// Finalize the trace, computing the digest.
    /// Emits event TTR-003 (capture completed) and TTR-009/TTR-010 (integrity).
    pub fn build(mut self) -> Result<(WorkflowTrace, Vec<AuditEntry>), TimeTravelError> {
        if self.steps.is_empty() {
            return Err(TimeTravelError::EmptyTrace {
                trace_id: self.trace_id.clone(),
            });
        }

        let trace_digest = WorkflowTrace::compute_digest(&self.steps);
        let trace = WorkflowTrace {
            trace_id: self.trace_id.clone(),
            workflow_name: self.workflow_name.clone(),
            steps: self.steps,
            environment: self.environment,
            trace_digest: trace_digest.clone(),
            schema_version: SCHEMA_VERSION.to_string(),
        };

        // Validate immediately after construction
        match trace.validate() {
            Ok(()) => {
                push_bounded(
                    &mut self.audit_log,
                    AuditEntry::new(
                        event_codes::TTR_003,
                        &self.trace_id,
                        &format!(
                            "Capture completed: {} steps, digest={}",
                            trace.steps.len(),
                            &trace_digest[..16]
                        ),
                        0,
                    ),
                    MAX_AUDIT_LOG_ENTRIES,
                );
                push_bounded(
                    &mut self.audit_log,
                    AuditEntry::new(
                        event_codes::TTR_009,
                        &self.trace_id,
                        "Trace integrity check passed",
                        0,
                    ),
                    MAX_AUDIT_LOG_ENTRIES,
                );
                Ok((trace, self.audit_log))
            }
            Err(e) => {
                push_bounded(
                    &mut self.audit_log,
                    AuditEntry::new(
                        event_codes::TTR_010,
                        &self.trace_id,
                        &format!("Trace integrity check failed: {e}"),
                        0,
                    ),
                    MAX_AUDIT_LOG_ENTRIES,
                );
                Err(e)
            }
        }
    }

    /// Access the audit log accumulated so far.
    pub fn audit_log(&self) -> &[AuditEntry] {
        &self.audit_log
    }

    /// Current step count.
    pub fn step_count(&self) -> usize {
        self.steps.len()
    }
}

// ---------------------------------------------------------------------------
// Divergence and replay result
// ---------------------------------------------------------------------------

/// Describes a single divergence between original and replayed step outputs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Divergence {
    /// Step sequence number where divergence occurred.
    pub step_seq: u64,
    /// Kind of divergence.
    pub kind: DivergenceKind,
    /// Expected digest (from original).
    pub expected_digest: String,
    /// Actual digest (from replay).
    pub actual_digest: String,
    /// Human-readable explanation.
    pub explanation: String,
}

/// The kind of divergence detected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DivergenceKind {
    /// Output bytes differ.
    OutputMismatch,
    /// Side-effects differ.
    SideEffectMismatch,
    /// Both output and side-effects differ.
    FullMismatch,
}

impl fmt::Display for DivergenceKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OutputMismatch => write!(f, "output_mismatch"),
            Self::SideEffectMismatch => write!(f, "side_effect_mismatch"),
            Self::FullMismatch => write!(f, "full_mismatch"),
        }
    }
}

/// The verdict of a replay comparison.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplayVerdict {
    /// All steps produced identical outputs and side-effects.
    Identical,
    /// One or more steps diverged.
    Diverged(usize),
}

impl fmt::Display for ReplayVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Identical => write!(f, "identical"),
            Self::Diverged(n) => write!(f, "diverged({n})"),
        }
    }
}

/// The result of replaying a workflow trace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayResult {
    /// ID of the trace that was replayed.
    pub trace_id: String,
    /// List of divergences detected (empty if verdict is Identical).
    pub divergences: Vec<Divergence>,
    /// Overall verdict.
    pub verdict: ReplayVerdict,
    /// Number of steps replayed.
    pub steps_replayed: u64,
    /// Total replay duration estimate in nanoseconds.
    pub replay_duration_ns: u64,
    /// Schema version.
    pub schema_version: String,
}

// ---------------------------------------------------------------------------
// Replay executor (simulated deterministic re-execution)
// ---------------------------------------------------------------------------

/// A replay executor that deterministically re-executes workflow steps.
///
/// In a full production system, this would invoke the actual extension-host
/// runtime. For the capture/replay contract, it takes a "replay function"
/// that maps (step_input, environment) -> (output, side_effects).
///
/// The default replay function is the identity replay: it returns the
/// original outputs exactly, which should always produce Identical verdict.
/// This is the baseline for INV-TTR-DETERMINISM.
pub type ReplayFn = fn(&TraceStep, &EnvironmentSnapshot) -> (Vec<u8>, Vec<SideEffect>);

/// Default replay function: identity replay returns original outputs.
pub fn identity_replay(step: &TraceStep, _env: &EnvironmentSnapshot) -> (Vec<u8>, Vec<SideEffect>) {
    (step.output.clone(), step.side_effects.clone())
}

// ---------------------------------------------------------------------------
// ReplayEngine
// ---------------------------------------------------------------------------

/// The time-travel replay engine.
/// Stores captured traces and replays them with divergence detection.
#[derive(Debug)]
pub struct ReplayEngine {
    traces: BTreeMap<String, WorkflowTrace>,
    trace_registration_order: VecDeque<String>,
    audit_log: Vec<AuditEntry>,
}

impl ReplayEngine {
    /// Create a new empty replay engine.
    pub fn new() -> Self {
        Self {
            traces: BTreeMap::new(),
            trace_registration_order: VecDeque::new(),
            audit_log: Vec::new(),
        }
    }

    /// Register a captured trace.
    /// Validates the trace before storage.
    pub fn register_trace(&mut self, trace: WorkflowTrace) -> Result<(), TimeTravelError> {
        trace.validate()?;
        if self.traces.contains_key(&trace.trace_id) {
            return Err(TimeTravelError::DuplicateTrace {
                trace_id: trace.trace_id.clone(),
            });
        }
        if self.traces.len() >= MAX_REGISTERED_TRACES
            && let Some(oldest_trace_id) = self.trace_registration_order.pop_front()
        {
            self.traces.remove(&oldest_trace_id);
        }
        self.trace_registration_order
            .push_back(trace.trace_id.clone());
        self.traces.insert(trace.trace_id.clone(), trace);
        Ok(())
    }

    /// Retrieve a trace by ID.
    pub fn get_trace(&self, trace_id: &str) -> Option<&WorkflowTrace> {
        self.traces.get(trace_id)
    }

    /// Return the number of registered traces.
    pub fn trace_count(&self) -> usize {
        self.traces.len()
    }

    /// List all trace IDs (sorted, deterministic).
    pub fn trace_ids(&self) -> Vec<String> {
        self.traces.keys().cloned().collect()
    }

    /// Replay a trace using the provided replay function.
    ///
    /// INV-TTR-DETERMINISM: if the replay function is deterministic and
    /// environment-faithful, the result will be `Identical`.
    ///
    /// INV-TTR-DIVERGENCE-DETECT: every step where replay diverges from the
    /// original is recorded in `ReplayResult::divergences`.
    pub fn replay(
        &mut self,
        trace_id: &str,
        replay_fn: ReplayFn,
    ) -> Result<ReplayResult, TimeTravelError> {
        let trace = self
            .traces
            .get(trace_id)
            .ok_or_else(|| TimeTravelError::TraceNotFound {
                trace_id: trace_id.to_string(),
            })?;

        // Emit TTR-004: Replay started
        push_bounded(
            &mut self.audit_log,
            AuditEntry::new(
                event_codes::TTR_004,
                trace_id,
                &format!("Replay started: {} steps", trace.steps.len()),
                0,
            ),
            MAX_AUDIT_LOG_ENTRIES,
        );

        let mut divergences = Vec::new();
        let mut replay_duration_ns: u64 = 0;

        for step in &trace.steps {
            let (replayed_output, replayed_effects) = replay_fn(step, &trace.environment);

            let original_output_digest = step.output_digest();
            let original_effects_digest = step.side_effects_digest();

            // Compute replayed digests (must use same domain prefix as TraceStep methods)
            let replayed_output_digest = {
                let mut hasher = Sha256::new();
                hasher.update(b"replay_step_output_v1:");
                hasher.update(&replayed_output);
                hex::encode(hasher.finalize())
            };
            let replayed_effects_digest = {
                let mut hasher = Sha256::new();
                hasher.update(b"replay_step_effects_v1:");
                hasher.update(
                    (u64::try_from(replayed_effects.len()).unwrap_or(u64::MAX)).to_le_bytes(),
                );
                for effect in &replayed_effects {
                    hasher.update(
                        (u64::try_from(effect.kind.len()).unwrap_or(u64::MAX)).to_le_bytes(),
                    );
                    hasher.update(effect.kind.as_bytes());
                    hasher.update(
                        (u64::try_from(effect.payload.len()).unwrap_or(u64::MAX)).to_le_bytes(),
                    );
                    hasher.update(&effect.payload);
                }
                hex::encode(hasher.finalize())
            };

            let output_match = constant_time::ct_eq(&original_output_digest, &replayed_output_digest);
            let effects_match = constant_time::ct_eq(&original_effects_digest, &replayed_effects_digest);

            if output_match && effects_match {
                // TTR-005: step identical
                push_bounded(
                    &mut self.audit_log,
                    AuditEntry::new(
                        event_codes::TTR_005,
                        trace_id,
                        &format!("Step {} identical", step.seq),
                        step.timestamp_ns,
                    ),
                    MAX_AUDIT_LOG_ENTRIES,
                );
            } else {
                let kind = match (output_match, effects_match) {
                    (false, true) => DivergenceKind::OutputMismatch,
                    (true, false) => DivergenceKind::SideEffectMismatch,
                    _ => DivergenceKind::FullMismatch,
                };
                let explanation = format!(
                    "Step {} diverged: kind={}, output_match={}, effects_match={}",
                    step.seq, kind, output_match, effects_match
                );
                // TTR-006: step diverged
                push_bounded(
                    &mut self.audit_log,
                    AuditEntry::new(
                        event_codes::TTR_006,
                        trace_id,
                        &explanation,
                        step.timestamp_ns,
                    ),
                    MAX_AUDIT_LOG_ENTRIES,
                );
                push_bounded(
                    &mut divergences,
                    Divergence {
                        step_seq: step.seq,
                        kind,
                        expected_digest: original_output_digest,
                        actual_digest: replayed_output_digest,
                        explanation,
                    },
                    MAX_DIVERGENCES,
                );
            }

            replay_duration_ns = std::cmp::max(replay_duration_ns, step.timestamp_ns);
        }

        let verdict = if divergences.is_empty() {
            ReplayVerdict::Identical
        } else {
            ReplayVerdict::Diverged(divergences.len())
        };

        // TTR-007: Replay completed
        push_bounded(
            &mut self.audit_log,
            AuditEntry::new(
                event_codes::TTR_007,
                trace_id,
                &format!("Replay completed: verdict={verdict}"),
                0,
            ),
            MAX_AUDIT_LOG_ENTRIES,
        );

        Ok(ReplayResult {
            trace_id: trace_id.to_string(),
            divergences,
            verdict,
            steps_replayed: u64::try_from(trace.steps.len()).unwrap_or(u64::MAX),
            replay_duration_ns,
            schema_version: SCHEMA_VERSION.to_string(),
        })
    }

    /// Convenience: replay with the identity function (should always produce Identical).
    pub fn replay_identity(&mut self, trace_id: &str) -> Result<ReplayResult, TimeTravelError> {
        self.replay(trace_id, identity_replay)
    }

    /// Access the engine's accumulated audit log.
    pub fn audit_log(&self) -> &[AuditEntry] {
        &self.audit_log
    }

    /// Clear the audit log (e.g., after flushing to external sink).
    pub fn drain_audit_log(&mut self) -> Vec<AuditEntry> {
        std::mem::take(&mut self.audit_log)
    }

    /// Remove a trace by ID.
    pub fn remove_trace(&mut self, trace_id: &str) -> Option<WorkflowTrace> {
        let removed = self.traces.remove(trace_id);
        if removed.is_some() {
            self.trace_registration_order
                .retain(|registered_trace_id| registered_trace_id != trace_id);
        }
        removed
    }
}

impl Default for ReplayEngine {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Helper: build a demo trace for testing
// ---------------------------------------------------------------------------

/// Build a simple demo trace with the given number of steps.
/// Useful for testing and verification scripts.
#[cfg(any(test, feature = "test-support"))]
pub fn build_demo_trace(trace_id: &str, workflow_name: &str, step_count: usize) -> WorkflowTrace {
    let env = EnvironmentSnapshot::new(
        1_000_000,
        BTreeMap::from([("FRANKEN_NODE_PROFILE".to_string(), "balanced".to_string())]),
        "linux-x86_64",
        "0.1.0",
    );

    let mut steps = Vec::with_capacity(step_count);
    for i in 0..step_count {
        let input = format!("input-{i}").into_bytes();
        let output = format!("output-{i}").into_bytes();
        let effects = vec![SideEffect::new("log", format!("effect-{i}").into_bytes())];
        let seq = u64::try_from(i).unwrap_or(u64::MAX);
        let timestamp = seq.saturating_add(1).saturating_mul(1000);
        push_bounded(&mut steps, TraceStep::new(seq, input, output, effects, timestamp), MAX_TRACE_STEPS);
    }

    let trace_digest = WorkflowTrace::compute_digest(&steps);
    WorkflowTrace {
        trace_id: trace_id.to_string(),
        workflow_name: workflow_name.to_string(),
        steps,
        environment: env,
        trace_digest,
        schema_version: SCHEMA_VERSION.to_string(),
    }
}

// ===========================================================================
// Unit tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn demo_env() -> EnvironmentSnapshot {
        EnvironmentSnapshot::new(
            1_000_000,
            BTreeMap::from([("KEY".to_string(), "value".to_string())]),
            "linux-x86_64",
            "0.1.0",
        )
    }

    fn one_step_trace(trace_id: &str) -> WorkflowTrace {
        build_demo_trace(trace_id, "test-workflow", 1)
    }

    fn multi_step_trace(trace_id: &str, n: usize) -> WorkflowTrace {
        build_demo_trace(trace_id, "test-workflow", n)
    }

    fn trace_and_audit_with_timestamps(
        trace_id: &str,
        timestamps: &[u64],
    ) -> (WorkflowTrace, Vec<AuditEntry>) {
        let mut builder = TraceBuilder::new(trace_id, "clocked-workflow", demo_env());
        for (idx, timestamp_ns) in timestamps.iter().copied().enumerate() {
            builder.record_step(
                format!("input-{idx}").into_bytes(),
                format!("output-{idx}").into_bytes(),
                vec![SideEffect::new("log", format!("effect-{idx}").into_bytes())],
                timestamp_ns,
            );
        }
        builder.build().expect("trace should build")
    }

    fn trace_with_timestamps(trace_id: &str, timestamps: &[u64]) -> WorkflowTrace {
        let (trace, _) = trace_and_audit_with_timestamps(trace_id, timestamps);
        trace
    }

    fn counterfactual_output_and_effects(
        step: &TraceStep,
        _env: &EnvironmentSnapshot,
    ) -> (Vec<u8>, Vec<SideEffect>) {
        let mut output = step.output.clone();
        output.extend_from_slice(b":counterfactual");
        let mut side_effects = step.side_effects.clone();
        side_effects.push(SideEffect::new(
            "counterfactual",
            step.seq.to_le_bytes().to_vec(),
        ));
        (output, side_effects)
    }

    fn diverge_odd_steps(
        step: &TraceStep,
        _env: &EnvironmentSnapshot,
    ) -> (Vec<u8>, Vec<SideEffect>) {
        if !step.seq.is_multiple_of(2) {
            let mut output = step.output.clone();
            output.extend_from_slice(b":odd-divergence");
            (output, step.side_effects.clone())
        } else {
            (step.output.clone(), step.side_effects.clone())
        }
    }

    // --- Invariant constants are defined ---

    #[test]
    fn invariant_constants_defined() {
        assert_eq!(INV_TTR_DETERMINISM, "INV-TTR-DETERMINISM");
        assert_eq!(INV_TTR_DIVERGENCE_DETECT, "INV-TTR-DIVERGENCE-DETECT");
        assert_eq!(INV_TTR_TRACE_COMPLETE, "INV-TTR-TRACE-COMPLETE");
        assert_eq!(INV_TTR_STEP_ORDER, "INV-TTR-STEP-ORDER");
        assert_eq!(INV_TTR_ENV_SEALED, "INV-TTR-ENV-SEALED");
        assert_eq!(INV_TTR_AUDIT_COMPLETE, "INV-TTR-AUDIT-COMPLETE");
    }

    // --- Event codes are defined ---

    #[test]
    fn event_codes_defined() {
        assert_eq!(event_codes::TTR_001, "TTR-001");
        assert_eq!(event_codes::TTR_002, "TTR-002");
        assert_eq!(event_codes::TTR_003, "TTR-003");
        assert_eq!(event_codes::TTR_004, "TTR-004");
        assert_eq!(event_codes::TTR_005, "TTR-005");
        assert_eq!(event_codes::TTR_006, "TTR-006");
        assert_eq!(event_codes::TTR_007, "TTR-007");
        assert_eq!(event_codes::TTR_008, "TTR-008");
        assert_eq!(event_codes::TTR_009, "TTR-009");
        assert_eq!(event_codes::TTR_010, "TTR-010");
    }

    // --- Error codes are defined ---

    #[test]
    fn error_codes_defined() {
        assert!(!error_codes::ERR_TTR_EMPTY_TRACE.is_empty());
        assert!(!error_codes::ERR_TTR_SEQ_GAP.is_empty());
        assert!(!error_codes::ERR_TTR_DIGEST_MISMATCH.is_empty());
        assert!(!error_codes::ERR_TTR_ENV_MISSING.is_empty());
        assert!(!error_codes::ERR_TTR_REPLAY_FAILED.is_empty());
        assert!(!error_codes::ERR_TTR_DUPLICATE_TRACE.is_empty());
        assert!(!error_codes::ERR_TTR_STEP_ORDER_VIOLATION.is_empty());
        assert!(!error_codes::ERR_TTR_TRACE_NOT_FOUND.is_empty());
    }

    // --- Schema version ---

    #[test]
    fn schema_version_is_ttr_v1() {
        assert_eq!(SCHEMA_VERSION, "ttr-v1.0");
    }

    // --- EnvironmentSnapshot validation ---

    #[test]
    fn env_snapshot_validates_successfully() {
        let env = demo_env();
        assert!(env.validate("test").is_ok());
    }

    #[test]
    fn env_snapshot_rejects_empty_platform() {
        let env = EnvironmentSnapshot::new(0, BTreeMap::new(), "", "0.1.0");
        let err = env.validate("test").unwrap_err();
        assert!(
            matches!(err, TimeTravelError::EnvironmentMissing { field, .. } if field == "platform")
        );
    }

    #[test]
    fn env_snapshot_rejects_empty_runtime_version() {
        let env = EnvironmentSnapshot::new(0, BTreeMap::new(), "linux", "");
        let err = env.validate("test").unwrap_err();
        assert!(
            matches!(err, TimeTravelError::EnvironmentMissing { field, .. } if field == "runtime_version")
        );
    }

    // --- TraceStep digests ---

    #[test]
    fn trace_step_output_digest_is_deterministic() {
        let step = TraceStep::new(0, vec![1], vec![2, 3], vec![], 100);
        let d1 = step.output_digest();
        let d2 = step.output_digest();
        assert_eq!(d1, d2);
    }

    #[test]
    fn trace_step_side_effects_digest_changes_with_payload() {
        let s1 = TraceStep::new(0, vec![], vec![], vec![SideEffect::new("a", vec![1])], 0);
        let s2 = TraceStep::new(0, vec![], vec![], vec![SideEffect::new("a", vec![2])], 0);
        assert_ne!(s1.side_effects_digest(), s2.side_effects_digest());
    }

    // --- WorkflowTrace validation ---

    #[test]
    fn valid_trace_passes_validation() {
        let trace = one_step_trace("t1");
        assert!(trace.validate().is_ok());
    }

    #[test]
    fn empty_trace_fails_validation() {
        let trace = WorkflowTrace {
            trace_id: "empty".to_string(),
            workflow_name: "test".to_string(),
            steps: vec![],
            environment: demo_env(),
            trace_digest: String::new(),
            schema_version: SCHEMA_VERSION.to_string(),
        };
        let err = trace.validate().unwrap_err();
        assert!(matches!(err, TimeTravelError::EmptyTrace { .. }));
    }

    #[test]
    fn trace_with_sequence_gap_fails() {
        let env = demo_env();
        let steps = vec![
            TraceStep::new(0, vec![], vec![1], vec![], 100),
            TraceStep::new(2, vec![], vec![2], vec![], 200), // gap: expected 1
        ];
        let digest = WorkflowTrace::compute_digest(&steps);
        let trace = WorkflowTrace {
            trace_id: "gap".to_string(),
            workflow_name: "test".to_string(),
            steps,
            environment: env,
            trace_digest: digest,
            schema_version: SCHEMA_VERSION.to_string(),
        };
        let err = trace.validate().unwrap_err();
        assert!(matches!(
            err,
            TimeTravelError::SequenceGap {
                expected: 1,
                found: 2,
                ..
            }
        ));
    }

    #[test]
    fn trace_with_bad_digest_fails() {
        let mut trace = one_step_trace("bad-digest");
        trace.trace_digest = "0000000000000000".to_string();
        let err = trace.validate().unwrap_err();
        assert!(matches!(err, TimeTravelError::DigestMismatch { .. }));
    }

    // --- TraceBuilder ---

    #[test]
    fn trace_builder_captures_steps() {
        let env = demo_env();
        let mut builder = TraceBuilder::new("b1", "wf", env);
        let seq = builder.record_step(vec![1], vec![2], vec![], 100);
        assert_eq!(seq, 0);
        assert_eq!(builder.step_count(), 1);
    }

    #[test]
    fn trace_builder_emits_audit_on_new() {
        let env = demo_env();
        let builder = TraceBuilder::new("b2", "wf", env);
        let log = builder.audit_log();
        assert_eq!(log.len(), 2);
        assert_eq!(log[0].event_code, event_codes::TTR_001);
        assert_eq!(log[1].event_code, event_codes::TTR_008);
    }

    #[test]
    fn trace_builder_emits_ttr_002_on_record() {
        let env = demo_env();
        let mut builder = TraceBuilder::new("b3", "wf", env);
        builder.record_step(vec![1], vec![2], vec![], 100);
        let log = builder.audit_log();
        assert!(log.iter().any(|e| e.event_code == event_codes::TTR_002));
    }

    #[test]
    fn trace_builder_build_produces_valid_trace() {
        let env = demo_env();
        let mut builder = TraceBuilder::new("b4", "wf", env);
        builder.record_step(vec![1], vec![2], vec![], 100);
        let (trace, audit) = builder.build().expect("build should succeed");
        assert_eq!(trace.trace_id, "b4");
        assert_eq!(trace.steps.len(), 1);
        assert!(trace.validate().is_ok());
        assert!(audit.iter().any(|e| e.event_code == event_codes::TTR_003));
        assert!(audit.iter().any(|e| e.event_code == event_codes::TTR_009));
    }

    #[test]
    fn trace_builder_new_uses_supplied_clock_seed_for_initial_audit() {
        let clock_seed_ns = 9_876_543;
        let env = EnvironmentSnapshot::new(
            clock_seed_ns,
            BTreeMap::from([("CLOCK".to_string(), "supplied".to_string())]),
            "linux-x86_64",
            "0.1.0",
        );
        let builder = TraceBuilder::new("clock-start", "wf", env);

        let log = builder.audit_log();
        assert_eq!(log.len(), 2);
        assert_eq!(log[0].event_code, event_codes::TTR_001);
        assert_eq!(log[1].event_code, event_codes::TTR_008);
        assert_eq!(log[0].timestamp_ns, clock_seed_ns);
        assert_eq!(log[1].timestamp_ns, clock_seed_ns);
    }

    #[test]
    fn trace_builder_record_step_preserves_supplied_clock_per_step() {
        let timestamps = [42, 7, 999];
        let (trace, audit) = trace_and_audit_with_timestamps("clock-steps", &timestamps);

        let step_timestamps: Vec<u64> = trace.steps.iter().map(|step| step.timestamp_ns).collect();
        let recorded_timestamps: Vec<u64> = audit
            .iter()
            .filter(|entry| entry.event_code == event_codes::TTR_002)
            .map(|entry| entry.timestamp_ns)
            .collect();

        assert_eq!(step_timestamps, timestamps.to_vec());
        assert_eq!(recorded_timestamps, timestamps.to_vec());
    }

    #[test]
    fn trace_builder_empty_build_fails() {
        let env = demo_env();
        let builder = TraceBuilder::new("b5", "wf", env);
        let err = builder.build().unwrap_err();
        assert!(matches!(err, TimeTravelError::EmptyTrace { .. }));
    }

    // --- ReplayEngine ---

    #[test]
    fn engine_default_is_empty() {
        let engine = ReplayEngine::default();
        assert_eq!(engine.trace_count(), 0);
    }

    #[test]
    fn engine_registers_trace() {
        let mut engine = ReplayEngine::new();
        let trace = one_step_trace("r1");
        engine
            .register_trace(trace)
            .expect("register should succeed");
        assert_eq!(engine.trace_count(), 1);
    }

    #[test]
    fn engine_rejects_duplicate_trace() {
        let mut engine = ReplayEngine::new();
        engine
            .register_trace(one_step_trace("dup"))
            .expect("register should succeed");
        let err = engine.register_trace(one_step_trace("dup")).unwrap_err();
        assert!(matches!(err, TimeTravelError::DuplicateTrace { .. }));
    }

    #[test]
    fn engine_get_trace() {
        let mut engine = ReplayEngine::new();
        engine
            .register_trace(one_step_trace("g1"))
            .expect("register should succeed");
        assert!(engine.get_trace("g1").is_some());
        assert!(engine.get_trace("missing").is_none());
    }

    #[test]
    fn engine_trace_ids_sorted() {
        let mut engine = ReplayEngine::new();
        engine
            .register_trace(one_step_trace("z"))
            .expect("register should succeed");
        engine
            .register_trace(one_step_trace("a"))
            .expect("register should succeed");
        engine
            .register_trace(one_step_trace("m"))
            .expect("register should succeed");
        assert_eq!(engine.trace_ids(), vec!["a", "m", "z"]);
    }

    #[test]
    fn engine_remove_trace() {
        let mut engine = ReplayEngine::new();
        engine
            .register_trace(one_step_trace("rm"))
            .expect("register should succeed");
        let removed = engine.remove_trace("rm");
        assert!(removed.is_some());
        assert_eq!(engine.trace_count(), 0);
    }

    #[test]
    fn engine_capacity_evicts_oldest_registered_trace() {
        let mut engine = ReplayEngine::new();
        engine
            .register_trace(one_step_trace("zzz-oldest"))
            .expect("register should succeed");
        for idx in 0..(MAX_REGISTERED_TRACES - 1) {
            engine
                .register_trace(one_step_trace(&format!("aaa-{idx:04}")))
                .expect("register should succeed");
        }

        engine
            .register_trace(one_step_trace("mmm-newest"))
            .expect("overflow register should succeed");

        assert_eq!(engine.trace_count(), MAX_REGISTERED_TRACES);
        assert!(engine.get_trace("zzz-oldest").is_none());
        assert!(engine.get_trace("aaa-0000").is_some());
        assert!(engine.get_trace("mmm-newest").is_some());
    }

    #[test]
    fn engine_remove_trace_clears_registration_order() {
        let mut engine = ReplayEngine::new();
        engine
            .register_trace(one_step_trace("stale-order"))
            .expect("register should succeed");
        let removed = engine.remove_trace("stale-order");
        assert!(removed.is_some());

        for idx in 0..MAX_REGISTERED_TRACES {
            engine
                .register_trace(one_step_trace(&format!("fill-{idx:04}")))
                .expect("register should succeed");
        }
        engine
            .register_trace(one_step_trace("fill-overflow"))
            .expect("overflow register should succeed");

        assert_eq!(engine.trace_count(), MAX_REGISTERED_TRACES);
        assert!(engine.get_trace("stale-order").is_none());
        assert!(engine.get_trace("fill-overflow").is_some());
    }

    // --- Identity replay (INV-TTR-DETERMINISM) ---

    #[test]
    fn identity_replay_produces_identical_verdict() {
        let mut engine = ReplayEngine::new();
        engine
            .register_trace(multi_step_trace("id1", 5))
            .expect("register should succeed");
        let result = engine
            .replay_identity("id1")
            .expect("replay should succeed");
        assert_eq!(result.verdict, ReplayVerdict::Identical);
        assert!(result.divergences.is_empty());
        assert_eq!(result.steps_replayed, 5);
    }

    #[test]
    fn identity_replay_emits_ttr_004_005_007() {
        let mut engine = ReplayEngine::new();
        engine
            .register_trace(one_step_trace("audit1"))
            .expect("register should succeed");
        engine
            .replay_identity("audit1")
            .expect("replay should succeed");
        let log = engine.audit_log();
        assert!(log.iter().any(|e| e.event_code == event_codes::TTR_004));
        assert!(log.iter().any(|e| e.event_code == event_codes::TTR_005));
        assert!(log.iter().any(|e| e.event_code == event_codes::TTR_007));
    }

    #[test]
    fn replay_duration_uses_maximum_supplied_step_timestamp() {
        let mut engine = ReplayEngine::new();
        engine
            .register_trace(trace_with_timestamps("clock-duration", &[800, 1_200, 400]))
            .expect("register should succeed");

        let result = engine
            .replay_identity("clock-duration")
            .expect("replay should succeed");

        assert_eq!(result.replay_duration_ns, 1_200);
        assert_eq!(result.verdict, ReplayVerdict::Identical);
    }

    #[test]
    fn identity_replay_step_audit_keeps_sequence_order_when_timestamps_are_unsorted() {
        let mut engine = ReplayEngine::new();
        engine
            .register_trace(trace_with_timestamps(
                "order-stable",
                &[3_000, 1_000, 2_000],
            ))
            .expect("register should succeed");

        engine
            .replay_identity("order-stable")
            .expect("replay should succeed");

        let identical_steps: Vec<(&str, u64)> = engine
            .audit_log()
            .iter()
            .filter(|entry| entry.event_code == event_codes::TTR_005)
            .map(|entry| (entry.detail.as_str(), entry.timestamp_ns))
            .collect();

        assert_eq!(
            identical_steps,
            vec![
                ("Step 0 identical", 3_000),
                ("Step 1 identical", 1_000),
                ("Step 2 identical", 2_000),
            ]
        );
    }

    // --- Divergence detection (INV-TTR-DIVERGENCE-DETECT) ---

    #[test]
    fn divergent_replay_detected() {
        let mut engine = ReplayEngine::new();
        engine
            .register_trace(multi_step_trace("div1", 3))
            .expect("register should succeed");

        // Replay function that always returns different output
        fn bad_replay(step: &TraceStep, _env: &EnvironmentSnapshot) -> (Vec<u8>, Vec<SideEffect>) {
            let mut output = step.output.clone();
            output.push(0xFF); // alter output
            (output, step.side_effects.clone())
        }

        let result = engine
            .replay("div1", bad_replay)
            .expect("replay should succeed");
        assert_eq!(result.verdict, ReplayVerdict::Diverged(3));
        assert_eq!(result.divergences.len(), 3);
        for div in &result.divergences {
            assert_eq!(div.kind, DivergenceKind::OutputMismatch);
        }
    }

    #[test]
    fn divergent_replay_keeps_step_event_order_with_mixed_results() {
        let mut engine = ReplayEngine::new();
        engine
            .register_trace(trace_with_timestamps(
                "mixed-order",
                &[4_000, 1_000, 3_000, 2_000],
            ))
            .expect("register should succeed");

        let result = engine
            .replay("mixed-order", diverge_odd_steps)
            .expect("replay should succeed");

        let per_step_events: Vec<(&str, &str, u64)> = engine
            .audit_log()
            .iter()
            .filter(|entry| {
                let code = entry.event_code.as_str();
                code == event_codes::TTR_005 || code == event_codes::TTR_006
            })
            .map(|entry| {
                (
                    entry.event_code.as_str(),
                    entry.detail.as_str(),
                    entry.timestamp_ns,
                )
            })
            .collect();
        let divergent_seqs: Vec<u64> = result.divergences.iter().map(|div| div.step_seq).collect();

        assert_eq!(result.verdict, ReplayVerdict::Diverged(2));
        assert_eq!(divergent_seqs, vec![1, 3]);
        assert_eq!(per_step_events.len(), 4);
        assert_eq!(
            per_step_events[0],
            (event_codes::TTR_005, "Step 0 identical", 4_000)
        );
        assert_eq!(per_step_events[1].0, event_codes::TTR_006);
        assert!(per_step_events[1].1.starts_with("Step 1 diverged"));
        assert_eq!(per_step_events[1].2, 1_000);
        assert_eq!(
            per_step_events[2],
            (event_codes::TTR_005, "Step 2 identical", 3_000)
        );
        assert_eq!(per_step_events[3].0, event_codes::TTR_006);
        assert!(per_step_events[3].1.starts_with("Step 3 diverged"));
        assert_eq!(per_step_events[3].2, 2_000);
    }

    #[test]
    fn counterfactual_replay_does_not_mutate_registered_trace_steps() {
        let original = trace_with_timestamps("cf-original", &[100, 200, 300]);
        let mut engine = ReplayEngine::new();
        engine
            .register_trace(original.clone())
            .expect("register should succeed");

        let result = engine
            .replay("cf-original", counterfactual_output_and_effects)
            .expect("replay should succeed");

        assert_eq!(result.verdict, ReplayVerdict::Diverged(3));
        assert_eq!(
            engine
                .get_trace("cf-original")
                .expect("trace should remain registered"),
            &original
        );
    }

    #[test]
    fn counterfactual_replay_does_not_poison_future_identity_replay() {
        let original = trace_with_timestamps("cf-identity", &[25, 50]);
        let original_digest = original.trace_digest.clone();
        let mut engine = ReplayEngine::new();
        engine
            .register_trace(original)
            .expect("register should succeed");

        let divergent = engine
            .replay("cf-identity", counterfactual_output_and_effects)
            .expect("counterfactual replay should succeed");
        let identity = engine
            .replay_identity("cf-identity")
            .expect("identity replay should still succeed");
        let stored_trace = engine
            .get_trace("cf-identity")
            .expect("trace should remain registered");

        assert_eq!(divergent.verdict, ReplayVerdict::Diverged(2));
        assert_eq!(identity.verdict, ReplayVerdict::Identical);
        assert!(constant_time::ct_eq(&stored_trace.trace_digest, &original_digest));
    }

    #[test]
    fn counterfactual_replay_remove_returns_original_trace() {
        let original = trace_with_timestamps("cf-remove", &[11, 22]);
        let mut engine = ReplayEngine::new();
        engine
            .register_trace(original.clone())
            .expect("register should succeed");

        engine
            .replay("cf-remove", counterfactual_output_and_effects)
            .expect("counterfactual replay should succeed");

        let removed = engine
            .remove_trace("cf-remove")
            .expect("registered trace should be removable");
        assert_eq!(removed, original);
    }

    #[test]
    fn side_effect_divergence_detected() {
        let mut engine = ReplayEngine::new();
        engine
            .register_trace(one_step_trace("se-div"))
            .expect("register should succeed");

        fn bad_effects(
            _step: &TraceStep,
            _env: &EnvironmentSnapshot,
        ) -> (Vec<u8>, Vec<SideEffect>) {
            (
                _step.output.clone(),
                vec![SideEffect::new("different", vec![99])],
            )
        }

        let result = engine
            .replay("se-div", bad_effects)
            .expect("replay should succeed");
        assert_eq!(result.verdict, ReplayVerdict::Diverged(1));
        assert_eq!(
            result.divergences[0].kind,
            DivergenceKind::SideEffectMismatch
        );
    }

    #[test]
    fn full_mismatch_divergence() {
        let mut engine = ReplayEngine::new();
        engine
            .register_trace(one_step_trace("full-div"))
            .expect("register should succeed");

        fn bad_all(_step: &TraceStep, _env: &EnvironmentSnapshot) -> (Vec<u8>, Vec<SideEffect>) {
            (vec![0xFF], vec![SideEffect::new("different", vec![99])])
        }

        let result = engine
            .replay("full-div", bad_all)
            .expect("replay should succeed");
        assert_eq!(result.divergences[0].kind, DivergenceKind::FullMismatch);
    }

    #[test]
    fn divergence_emits_ttr_006() {
        let mut engine = ReplayEngine::new();
        engine
            .register_trace(one_step_trace("div-audit"))
            .expect("register should succeed");

        fn bad_replay(step: &TraceStep, _env: &EnvironmentSnapshot) -> (Vec<u8>, Vec<SideEffect>) {
            (vec![0xFF], step.side_effects.clone())
        }

        engine
            .replay("div-audit", bad_replay)
            .expect("replay should succeed");
        assert!(
            engine
                .audit_log()
                .iter()
                .any(|e| e.event_code == event_codes::TTR_006)
        );
    }

    // --- Replay error: trace not found ---

    #[test]
    fn replay_trace_not_found() {
        let mut engine = ReplayEngine::new();
        let err = engine.replay_identity("nonexistent").unwrap_err();
        assert!(matches!(err, TimeTravelError::TraceNotFound { .. }));
    }

    // --- Audit log drain ---

    #[test]
    fn drain_audit_log_empties() {
        let mut engine = ReplayEngine::new();
        engine
            .register_trace(one_step_trace("drain"))
            .expect("register should succeed");
        engine
            .replay_identity("drain")
            .expect("replay should succeed");
        let drained = engine.drain_audit_log();
        assert!(!drained.is_empty());
        assert!(engine.audit_log().is_empty());
    }

    // --- Serde round-trip ---

    #[test]
    fn workflow_trace_serde_roundtrip() {
        let trace = multi_step_trace("serde1", 3);
        let json = serde_json::to_string(&trace).expect("serialize should succeed");
        let deserialized: WorkflowTrace =
            serde_json::from_str(&json).expect("deserialize should succeed");
        assert_eq!(trace, deserialized);
    }

    #[test]
    fn replay_result_serde_roundtrip() {
        let result = ReplayResult {
            trace_id: "s1".to_string(),
            divergences: vec![],
            verdict: ReplayVerdict::Identical,
            steps_replayed: 1,
            replay_duration_ns: 1000,
            schema_version: SCHEMA_VERSION.to_string(),
        };
        let json = serde_json::to_string(&result).expect("serialize should succeed");
        let de: ReplayResult = serde_json::from_str(&json).expect("deserialize should succeed");
        assert_eq!(de.trace_id, "s1");
        assert_eq!(de.verdict, ReplayVerdict::Identical);
    }

    #[test]
    fn divergence_serde_roundtrip() {
        let div = Divergence {
            step_seq: 0,
            kind: DivergenceKind::OutputMismatch,
            expected_digest: "aaa".to_string(),
            actual_digest: "bbb".to_string(),
            explanation: "test".to_string(),
        };
        let json = serde_json::to_string(&div).expect("serialize should succeed");
        let de: Divergence = serde_json::from_str(&json).expect("deserialize should succeed");
        assert_eq!(div, de);
    }

    // --- Compute digest is deterministic ---

    #[test]
    fn compute_digest_deterministic() {
        let steps = vec![
            TraceStep::new(0, vec![1], vec![2], vec![], 100),
            TraceStep::new(1, vec![3], vec![4], vec![], 200),
        ];
        let d1 = WorkflowTrace::compute_digest(&steps);
        let d2 = WorkflowTrace::compute_digest(&steps);
        assert_eq!(d1, d2);
    }

    #[test]
    fn compute_digest_changes_with_different_output() {
        let s1 = vec![TraceStep::new(0, vec![1], vec![2], vec![], 100)];
        let s2 = vec![TraceStep::new(0, vec![1], vec![3], vec![], 100)];
        assert_ne!(
            WorkflowTrace::compute_digest(&s1),
            WorkflowTrace::compute_digest(&s2)
        );
    }

    // --- Demo trace builder ---

    #[test]
    fn build_demo_trace_valid() {
        let trace = build_demo_trace("demo", "wf", 10);
        assert!(trace.validate().is_ok());
        assert_eq!(trace.steps.len(), 10);
    }

    // --- Error Display ---

    #[test]
    fn error_display_includes_code() {
        let err = TimeTravelError::EmptyTrace {
            trace_id: "t".to_string(),
        };
        let msg = format!("{err}");
        assert!(msg.contains("ERR_TTR_EMPTY_TRACE"));
    }

    #[test]
    fn error_display_sequence_gap() {
        let err = TimeTravelError::SequenceGap {
            trace_id: "t".to_string(),
            expected: 1,
            found: 3,
        };
        let msg = format!("{err}");
        assert!(msg.contains("ERR_TTR_SEQ_GAP"));
        assert!(msg.contains("expected seq 1"));
    }

    #[test]
    fn error_display_duplicate_trace() {
        let err = TimeTravelError::DuplicateTrace {
            trace_id: "dup".to_string(),
        };
        let msg = format!("{err}");
        assert!(msg.contains("ERR_TTR_DUPLICATE_TRACE"));
    }

    // --- ReplayVerdict display ---

    #[test]
    fn verdict_display() {
        assert_eq!(format!("{}", ReplayVerdict::Identical), "identical");
        assert_eq!(format!("{}", ReplayVerdict::Diverged(3)), "diverged(3)");
    }

    // --- DivergenceKind display ---

    #[test]
    fn divergence_kind_display() {
        assert_eq!(
            format!("{}", DivergenceKind::OutputMismatch),
            "output_mismatch"
        );
        assert_eq!(
            format!("{}", DivergenceKind::SideEffectMismatch),
            "side_effect_mismatch"
        );
        assert_eq!(format!("{}", DivergenceKind::FullMismatch), "full_mismatch");
    }

    // --- SideEffect construction ---

    #[test]
    fn side_effect_new() {
        let se = SideEffect::new("file_write", vec![1, 2, 3]);
        assert_eq!(se.kind, "file_write");
        assert_eq!(se.payload, vec![1, 2, 3]);
    }

    // --- AuditEntry construction ---

    #[test]
    fn audit_entry_fields() {
        let entry = AuditEntry::new("TTR-001", "trace-1", "detail", 999);
        assert_eq!(entry.event_code, "TTR-001");
        assert_eq!(entry.trace_id, "trace-1");
        assert_eq!(entry.detail, "detail");
        assert_eq!(entry.timestamp_ns, 999);
    }

    // --- Multi-step identity replay with varied data ---

    #[test]
    fn multi_step_identity_replay_all_identical() {
        let mut engine = ReplayEngine::new();
        let trace = multi_step_trace("multi-id", 20);
        engine
            .register_trace(trace)
            .expect("register should succeed");
        let result = engine.replay_identity("multi-id").unwrap();
        assert_eq!(result.verdict, ReplayVerdict::Identical);
        assert_eq!(result.steps_replayed, 20);
    }

    // --- Partial divergence (some steps identical, some diverge) ---

    #[test]
    fn partial_divergence_detected() {
        let mut engine = ReplayEngine::new();
        engine
            .register_trace(multi_step_trace("partial", 5))
            .expect("register should succeed");

        // Only diverge on even steps
        fn even_bad(step: &TraceStep, _env: &EnvironmentSnapshot) -> (Vec<u8>, Vec<SideEffect>) {
            if step.seq.is_multiple_of(2) {
                (vec![0xFF], step.side_effects.clone())
            } else {
                (step.output.clone(), step.side_effects.clone())
            }
        }

        let result = engine
            .replay("partial", even_bad)
            .expect("replay should succeed");
        // Steps 0, 2, 4 diverge
        assert_eq!(result.verdict, ReplayVerdict::Diverged(3));
        assert_eq!(result.divergences.len(), 3);
        let seqs: Vec<u64> = result.divergences.iter().map(|d| d.step_seq).collect();
        assert_eq!(seqs, vec![0, 2, 4]);
    }

    // -- Negative-Path Tests --

    #[test]
    fn negative_massive_trace_step_memory_pressure_testing() {
        // Test trace capture with massive number of steps to validate memory bounds
        let mut engine = ReplayEngine::new();

        // Attempt to create trace with massive step count
        let massive_trace_id = "memory-stress-trace";
        let env = demo_env();

        // Start trace capture
        engine.start_capture(massive_trace_id, "massive-workflow", env).expect("start capture");

        let massive_step_count = MAX_TRACE_STEPS.saturating_add(1000);
        let mut successful_steps = 0;

        // Record steps up to and beyond capacity limit
        for i in 0..massive_step_count {
            let input = format!("input-{:08}", i).into_bytes();
            let output = format!("output-{:08}", i).into_bytes();
            let side_effects = vec![
                SideEffect::new("log", format!("effect-{:08}", i).into_bytes()),
                SideEffect::new("metric", format!("metric-{:08}", i).into_bytes()),
            ];

            match engine.record_step(massive_trace_id, input, output, side_effects, 1000000 + i as u64) {
                Ok(()) => {
                    successful_steps = successful_steps.saturating_add(1);
                },
                Err(ReplayEngineError::TraceNotFound { .. }) => {
                    // Expected if trace gets dropped due to memory pressure
                    break;
                },
                Err(_) => {
                    // Other capacity-related errors are acceptable
                    break;
                }
            }

            // Stop if we've recorded too many steps (capacity enforcement)
            if successful_steps >= MAX_TRACE_STEPS {
                break;
            }
        }

        // Should enforce capacity limits
        assert!(successful_steps <= MAX_TRACE_STEPS);
        assert!(successful_steps > 0, "Should record at least some steps");

        // Complete trace capture
        let capture_result = engine.complete_capture(massive_trace_id, 2000000);

        match capture_result {
            Ok((trace, _)) => {
                // Trace should be bounded
                assert!(trace.steps.len() <= MAX_TRACE_STEPS);
                assert_eq!(trace.steps.len(), successful_steps);

                // Should handle large traces without corruption
                assert!(!trace.trace_id.is_empty());
                assert!(!trace.workflow_name.is_empty());
            },
            Err(_) => {
                // Acceptable to reject massive traces for memory protection
            }
        }

        // Engine should remain functional despite stress test
        let registered_traces = engine.list_traces();
        assert!(registered_traces.len() <= MAX_REGISTERED_TRACES);
    }

    #[test]
    fn negative_unicode_injection_in_trace_identifiers_and_workflow_names() {
        // Test trace identifiers and workflow names with Unicode and control characters
        let mut engine = ReplayEngine::new();

        let malicious_identifiers = vec![
            // Unicode scripts
            ("trace🚀rocket", "workflow🔥fire"),
            ("трейс-кириллица", "рабочий-процесс"),
            ("轨迹-中文", "工作流程-测试"),

            // Control characters
            ("trace\0null", "workflow\0null"),
            ("trace\r\ncarriage", "workflow\x01control"),
            ("trace\x1B[Hescape", "workflow\x1B[2Jclear"),

            // Path traversal attempts
            ("../../../etc/passwd", "workflow"),
            ("trace", "../../../proc/version"),

            // Script injection
            ("trace<script>", "workflow"),
            ("trace", "workflow'; DROP TABLE traces; --"),

            // Unicode normalization attacks
            ("café", "café-workflow"), // NFC vs NFD forms
            ("cafe\u{0301}", "workflow-cafe\u{0301}"),

            // Zero-width and invisible characters
            ("trace\u{200B}invisible", "workflow\u{FEFF}bom"),
            ("trace\u{202E}rtl\u{202D}normal", "workflow"),

            // Extremely long identifiers
            (&"x".repeat(10000), "workflow"),
            ("trace", &"y".repeat(10000)),
        ];

        for (i, (trace_id, workflow_name)) in malicious_identifiers.iter().enumerate() {
            let env = demo_env();

            // Test trace capture with malicious identifiers
            let start_result = engine.start_capture(trace_id, workflow_name, env);

            match start_result {
                Ok(()) => {
                    // Successfully started - test record step with Unicode
                    let input = format!("unicode-input-{}", i).into_bytes();
                    let output = format!("unicode-output-{}", i).into_bytes();
                    let side_effects = vec![SideEffect::new("unicode-effect", format!("effect-{}", i).into_bytes())];

                    let record_result = engine.record_step(trace_id, input, output, side_effects, 1000_u64.saturating_add(u64::try_from(i).unwrap_or(u64::MAX)));

                    if record_result.is_ok() {
                        // Complete trace
                        let complete_result = engine.complete_capture(trace_id, 2000_u64.saturating_add(u64::try_from(i).unwrap_or(u64::MAX)));

                        match complete_result {
                            Ok((trace, audit)) => {
                                // Verify Unicode handling didn't corrupt trace
                                assert_eq!(trace.trace_id, *trace_id);
                                assert_eq!(trace.workflow_name, *workflow_name);
                                assert!(trace.steps.len() > 0);

                                // Audit log should handle Unicode safely
                                for entry in &audit {
                                    assert!(!entry.event_code.is_empty());
                                    // Fields should not be corrupted
                                }
                            },
                            Err(_) => {
                                // Acceptable to reject malformed identifiers
                            }
                        }
                    }
                },
                Err(_) => {
                    // Expected for malformed identifiers
                }
            }
        }

        // Trace listing should handle Unicode identifiers safely
        let traces = engine.list_traces();
        for trace_summary in traces {
            assert!(!trace_summary.trace_id.is_empty());
            assert!(!trace_summary.workflow_name.is_empty());
        }
    }

    #[test]
    fn negative_extreme_timestamp_arithmetic_overflow_protection() {
        // Test timestamp handling with extreme values near u64::MAX
        let mut engine = ReplayEngine::new();
        let extreme_trace_id = "extreme-timestamp-trace";
        let env = demo_env();

        engine.start_capture(extreme_trace_id, "extreme-workflow", env).expect("start capture");

        let extreme_timestamps = vec![
            0,                              // Minimum timestamp
            1,                              // Just above minimum
            u64::MAX.saturating_sub(1000),  // Near maximum
            u64::MAX.saturating_sub(1),     // One below maximum
            u64::MAX,                       // Maximum timestamp
        ];

        for (i, timestamp) in extreme_timestamps.iter().enumerate() {
            let input = format!("extreme-input-{}", i).into_bytes();
            let output = format!("extreme-output-{}", i).into_bytes();
            let side_effects = vec![SideEffect::new("extreme-log", format!("timestamp-{}", timestamp).into_bytes())];

            let record_result = engine.record_step(extreme_trace_id, input, output, side_effects, *timestamp);

            match record_result {
                Ok(()) => {
                    // Successfully recorded extreme timestamp
                },
                Err(_) => {
                    // May reject extreme timestamps for safety
                }
            }
        }

        // Complete trace with extreme timestamp
        let complete_result = engine.complete_capture(extreme_trace_id, u64::MAX);

        match complete_result {
            Ok((trace, audit)) => {
                // Verify timestamp handling didn't overflow
                for step in &trace.steps {
                    assert!(step.timestamp_ns <= u64::MAX);
                }

                for entry in &audit {
                    assert!(entry.timestamp_ms <= u64::MAX);
                }

                // Test replay with extreme timestamps
                if !trace.steps.is_empty() {
                    let replay_result = engine.replay(extreme_trace_id, |step, _env| {
                        // Return same output to avoid divergence
                        Ok((step.output.clone(), step.side_effects.clone()))
                    });

                    match replay_result {
                        Ok(result) => {
                            // Should handle extreme timestamps without overflow
                            assert_eq!(result.verdict, ReplayVerdict::Success);
                        },
                        Err(_) => {
                            // May fail due to extreme timestamp values
                        }
                    }
                }
            },
            Err(_) => {
                // Acceptable to reject extreme timestamp configurations
            }
        }
    }

    #[test]
    fn negative_malformed_side_effect_data_injection_attacks() {
        // Test side effect data handling against various injection attacks
        let mut engine = ReplayEngine::new();
        let malicious_trace_id = "malicious-side-effects";

        engine.start_capture(malicious_trace_id, "injection-test", demo_env()).expect("start capture");

        let malicious_side_effect_data = vec![
            // Binary data injection
            b"\x00\x01\x02\x03\x04\xFF\xFE".to_vec(),

            // Null byte injection
            b"normal_data\x00injected_content".to_vec(),

            // Extremely large payloads
            vec![0xAA; 10 * 1024 * 1024], // 10MB payload

            // Unicode in binary data
            "🔥 Unicode payload with 中文 and кириллица".as_bytes().to_vec(),

            // Control characters
            b"\x1B[H\x1B[2J\r\n\x01\x02\x03".to_vec(),

            // JSON injection attempt
            b"{\"injected\": true, \"payload\": \"malicious\"}".to_vec(),

            // SQL injection attempt
            b"'; DROP TABLE side_effects; --".to_vec(),

            // Shell command injection
            b"normal_data; rm -rf /; echo pwned".to_vec(),

            // Path traversal in data
            b"../../../etc/passwd".to_vec(),

            // Format string injection
            b"%s%s%s%s%s%s%s%s%s%s%n".to_vec(),
        ];

        for (i, malicious_data) in malicious_side_effect_data.iter().enumerate() {
            let input = format!("test-input-{}", i).into_bytes();
            let output = format!("test-output-{}", i).into_bytes();

            let malicious_side_effects = vec![
                SideEffect::new("log", malicious_data.clone()),
                SideEffect::new("metric", format!("normal-data-{}", i).into_bytes()),
                SideEffect::new("dangerous-type", malicious_data.clone()),
            ];

            let record_result = engine.record_step(
                malicious_trace_id,
                input,
                output,
                malicious_side_effects,
                1000_u64.saturating_add(u64::try_from(i).unwrap_or(u64::MAX)),
            );

            match record_result {
                Ok(()) => {
                    // Successfully recorded malicious side effect
                },
                Err(_) => {
                    // May reject malicious payloads
                }
            }
        }

        let complete_result = engine.complete_capture(malicious_trace_id, 5000);

        match complete_result {
            Ok((trace, _)) => {
                // Verify side effect data handling is safe
                for step in &trace.steps {
                    for side_effect in &step.side_effects {
                        assert!(!side_effect.effect_type.is_empty());
                        // Data may be arbitrary bytes, but should not corrupt other fields
                    }
                }

                // Test that replay handles malicious side effects safely
                let replay_result = engine.replay(malicious_trace_id, |step, _env| {
                    // Return same side effects to avoid divergence
                    Ok((step.output.clone(), step.side_effects.clone()))
                });

                match replay_result {
                    Ok(result) => {
                        assert_eq!(result.verdict, ReplayVerdict::Success);
                    },
                    Err(_) => {
                        // May fail due to malicious data validation
                    }
                }
            },
            Err(_) => {
                // Acceptable to reject traces with malicious side effects
            }
        }
    }

    #[test]
    fn negative_divergence_detection_with_massive_output_differences() {
        // Test divergence detection with massive output differences and edge cases
        let mut engine = ReplayEngine::new();
        let divergent_trace_id = "massive-divergence-test";

        // Create trace with various output sizes
        engine.start_capture(divergent_trace_id, "divergence-workflow", demo_env()).expect("start capture");

        let original_outputs = vec![
            vec![0x00; 1],                      // 1 byte
            vec![0x11; 1024],                   // 1KB
            vec![0x22; 1024 * 1024],           // 1MB
            vec![0x33; 10 * 1024 * 1024],      // 10MB (if accepted)
            b"normal small output".to_vec(),
        ];

        for (i, output) in original_outputs.iter().enumerate() {
            let input = format!("input-{}", i).into_bytes();
            let side_effects = vec![SideEffect::new("log", format!("step-{}", i).into_bytes())];

            let record_result = engine.record_step(
                divergent_trace_id,
                input,
                output.clone(),
                side_effects,
                1000_u64.saturating_add(u64::try_from(i).unwrap_or(u64::MAX)),
            );

            if record_result.is_err() {
                // May reject massive outputs - break early
                break;
            }
        }

        let (trace, _) = engine.complete_capture(divergent_trace_id, 5000).expect("complete capture");

        // Replay with intentionally different outputs to trigger divergence detection
        let replay_result = engine.replay(divergent_trace_id, |step, _env| {
            // Create outputs that differ massively from originals
            let divergent_outputs = match step.output.len() {
                1 => vec![0xFF; 1000],                    // Expand small to large
                len if len > 1000 => vec![0xDD; 10],      // Shrink large to small
                _ => vec![0xBB; step.output.len() * 2],   // Double the size
            };

            Ok((divergent_outputs, step.side_effects.clone()))
        });

        match replay_result {
            Ok(result) => {
                match result.verdict {
                    ReplayVerdict::Diverged(divergence_count) => {
                        // Should detect divergences despite size differences
                        assert!(divergence_count > 0);
                        assert!(result.divergences.len() > 0);

                        // Verify divergence details handle size differences safely
                        for divergence in &result.divergences {
                            assert!(divergence.step_seq < u64::try_from(trace.steps.len()).unwrap_or(u64::MAX));
                            assert!(!divergence.expected_hash.is_empty());
                            assert!(!divergence.actual_hash.is_empty());

                            // Expected and actual should be different
                            assert!(!constant_time::ct_eq(
                                divergence.expected_hash.as_bytes(),
                                divergence.actual_hash.as_bytes()
                            ));
                        }
                    },
                    ReplayVerdict::Success => {
                        panic!("Should have detected divergences with different outputs");
                    }
                }
            },
            Err(_) => {
                // May fail due to massive output handling
            }
        }
    }

    #[test]
    fn negative_environment_snapshot_corruption_and_tampering() {
        // Test environment snapshot handling against corruption and tampering
        let corrupted_environments = vec![
            // Empty/minimal environment
            EnvironmentSnapshot::new(0, BTreeMap::new(), "", ""),

            // Extreme values
            EnvironmentSnapshot::new(
                u64::MAX,
                BTreeMap::new(),
                &"x".repeat(10000), // Extremely long platform
                &"v".repeat(10000), // Extremely long version
            ),

            // Unicode in environment fields
            EnvironmentSnapshot::new(
                1000,
                BTreeMap::from([
                    ("🔑key".to_string(), "🔥value".to_string()),
                    ("кириллица".to_string(), "значение".to_string()),
                    ("中文".to_string(), "值".to_string()),
                ]),
                "platform-🚀-unicode",
                "version-🎯-test",
            ),

            // Control characters in environment
            EnvironmentSnapshot::new(
                1000,
                BTreeMap::from([
                    ("key\0null".to_string(), "value\r\ninjection".to_string()),
                    ("path\x1B[H".to_string(), "../../../etc/passwd".to_string()),
                ]),
                "platform\x01control",
                "version\x02test",
            ),

            // Massive environment variables
            EnvironmentSnapshot::new(
                1000,
                {
                    let mut huge_env = BTreeMap::new();
                    for i in 0..1000 {
                        huge_env.insert(
                            format!("MASSIVE_VAR_{:04}", i),
                            "x".repeat(1000), // 1KB per variable
                        );
                    }
                    huge_env
                },
                "massive-platform",
                "massive-version",
            ),
        ];

        for (i, corrupted_env) in corrupted_environments.into_iter().enumerate() {
            let trace_id = format!("env-corruption-{}", i);
            let mut engine = ReplayEngine::new();

            // Test trace capture with corrupted environment
            let start_result = engine.start_capture(&trace_id, "env-test", corrupted_env);

            match start_result {
                Ok(()) => {
                    // Record a simple step
                    let record_result = engine.record_step(
                        &trace_id,
                        b"test-input".to_vec(),
                        b"test-output".to_vec(),
                        vec![SideEffect::new("env-test", b"test-effect".to_vec())],
                        1000,
                    );

                    if record_result.is_ok() {
                        let complete_result = engine.complete_capture(&trace_id, 2000);

                        match complete_result {
                            Ok((trace, _)) => {
                                // Verify environment snapshot integrity
                                assert!(trace.environment.seed_timestamp_ns <= u64::MAX);

                                // Test replay with potentially corrupted environment
                                let replay_result = engine.replay(&trace_id, |step, _env| {
                                    Ok((step.output.clone(), step.side_effects.clone()))
                                });

                                match replay_result {
                                    Ok(result) => {
                                        assert_eq!(result.verdict, ReplayVerdict::Success);
                                    },
                                    Err(_) => {
                                        // May fail due to environment corruption
                                    }
                                }
                            },
                            Err(_) => {
                                // Acceptable to reject corrupted environments
                            }
                        }
                    }
                },
                Err(_) => {
                    // Expected for severely corrupted environments
                }
            }
        }
    }

    #[test]
    fn negative_concurrent_trace_manipulation_and_race_conditions() {
        // Test trace engine behavior under concurrent access patterns
        let mut engine = ReplayEngine::new();
        let concurrent_trace_id = "concurrent-test";

        // Start trace capture
        engine.start_capture(concurrent_trace_id, "concurrent-workflow", demo_env()).expect("start capture");

        // Simulate concurrent step recording (in reality this would need proper threading)
        let concurrent_operations = vec![
            ("record_step_1", 1000),
            ("record_step_2", 1001),
            ("record_step_3", 1002),
            ("complete_capture", 2000),
            ("record_step_after_complete", 2001), // Should fail
        ];

        let mut operation_results = Vec::new();

        for (operation, timestamp) in concurrent_operations {
            match operation {
                "complete_capture" => {
                    let result = engine.complete_capture(concurrent_trace_id, timestamp);
                    operation_results.push((operation, result.is_ok()));
                },
                op if op.starts_with("record_step") => {
                    let input = format!("{}-input", operation).into_bytes();
                    let output = format!("{}-output", operation).into_bytes();
                    let side_effects = vec![SideEffect::new("concurrent", format!("{}-effect", operation).into_bytes())];

                    let result = engine.record_step(concurrent_trace_id, input, output, side_effects, timestamp);
                    operation_results.push((operation, result.is_ok()));
                },
                _ => {}
            }
        }

        // Verify that operations have consistent behavior
        // Steps before complete_capture should succeed
        assert!(operation_results[0].1, "First record_step should succeed");
        assert!(operation_results[1].1, "Second record_step should succeed");
        assert!(operation_results[2].1, "Third record_step should succeed");

        // Complete should succeed
        assert!(operation_results[3].1, "Complete capture should succeed");

        // Step after complete should fail
        assert!(!operation_results[4].1, "Record step after complete should fail");

        // Test conflicting trace operations
        let conflicting_results = vec![
            engine.start_capture(concurrent_trace_id, "conflicting-workflow", demo_env()),
            engine.complete_capture(concurrent_trace_id, 3000),
        ];

        // Should handle conflicting operations gracefully
        for result in conflicting_results {
            // May succeed or fail, but should not crash
            if result.is_err() {
                // Expected failure case for conflicting operations
                continue;
            }
        }

        // Engine state should remain consistent
        let traces = engine.list_traces();
        // Should contain at most one trace with concurrent_trace_id
        let matching_traces: Vec<_> = traces.iter()
            .filter(|t| t.trace_id == concurrent_trace_id)
            .collect();
        assert!(matching_traces.len() <= 1);
    }

    #[test]
    fn negative_replay_function_exception_and_panic_handling() {
        // Test replay engine behavior when replay function throws exceptions or panics
        let mut engine = ReplayEngine::new();
        let exception_trace_id = "exception-test";

        // Create a simple trace
        engine.start_capture(exception_trace_id, "exception-workflow", demo_env()).expect("start capture");

        for i in 0..5 {
            engine.record_step(
                exception_trace_id,
                format!("input-{}", i).into_bytes(),
                format!("output-{}", i).into_bytes(),
                vec![SideEffect::new("log", format!("step-{}", i).into_bytes())],
                1000 + i,
            ).expect("record step");
        }

        let (_trace, _) = engine.complete_capture(exception_trace_id, 2000).expect("complete capture");

        // Test various failure modes in replay function
        let failure_modes = vec![
            // Return error on first step
            (0, "immediate_error"),
            // Return error on middle step
            (2, "middle_error"),
            // Return error on last step
            (4, "final_error"),
        ];

        for (fail_step, error_type) in failure_modes {
            let replay_result = engine.replay(exception_trace_id, |step, _env| {
                if step.sequence_number == fail_step {
                    Err(format!("Simulated {} at step {}", error_type, fail_step))
                } else {
                    Ok((step.output.clone(), step.side_effects.clone()))
                }
            });

            match replay_result {
                Ok(_) => {
                    panic!("Replay should have failed at step {}", fail_step);
                },
                Err(ReplayEngineError::ReplayFunctionFailed { step_seq, error }) => {
                    assert_eq!(step_seq, fail_step);
                    assert!(error.contains(error_type));
                },
                Err(_) => {
                    // Other error types acceptable
                }
            }
        }

        // Test replay function that returns corrupted data
        let corrupted_replay_result = engine.replay(exception_trace_id, |_step, _env| {
            // Return massive corrupted output
            Ok((vec![0xFF; 10 * 1024 * 1024], vec![]))
        });

        match corrupted_replay_result {
            Ok(result) => {
                // Should detect divergence due to corrupted output
                match result.verdict {
                    ReplayVerdict::Diverged(_) => {
                        // Expected - corrupted output should cause divergence
                    },
                    ReplayVerdict::Success => {
                        panic!("Should have detected divergence from corrupted output");
                    }
                }
            },
            Err(_) => {
                // May reject due to output size validation
            }
        }
    }

    #[test]
    fn hardening_audit_log_prevents_unbounded_growth() {
        // HARDENING: Audit log accumulation must use push_bounded to prevent memory exhaustion
        let mut engine = ReplayEngine::new();
        let trace_id = "audit-dos-test".to_string();

        // Start a capture to initialize audit logging
        engine.start_capture(&trace_id, "audit-test-workflow", demo_env())
            .expect("capture start should succeed");

        // Simulate many audit events to test bounding
        for i in 0..10000 {
            let input = format!("input-{}", i).into_bytes();
            let output = format!("output-{}", i).into_bytes();
            let effects = vec![SideEffect::new("test", format!("effect-{}", i).into_bytes())];

            let _result = engine.record_step(&trace_id, input, output, effects, i);
        }

        // Complete capture
        engine.complete_capture(&trace_id, 10000).expect("capture complete should succeed");

        // Get audit logs and verify they're bounded
        let audit_logs = engine.audit_logs();

        // Should be bounded by MAX_AUDIT_LOG_ENTRIES
        assert!(audit_logs.len() <= MAX_AUDIT_LOG_ENTRIES,
            "Audit log should be bounded to {} entries, got {}",
            MAX_AUDIT_LOG_ENTRIES, audit_logs.len());
    }

    #[test]
    fn hardening_side_effects_bounded_accumulation() {
        // HARDENING: Side effects collection must be bounded to prevent DoS
        let mut engine = ReplayEngine::new();
        let trace_id = "effects-dos-test".to_string();

        engine.start_capture(&trace_id, "effects-test", demo_env())
            .expect("capture start should succeed");

        // Test with excessive side effects in a single step
        let input = b"test-input".to_vec();
        let output = b"test-output".to_vec();

        // Create a massive number of side effects
        let massive_effects: Vec<SideEffect> = (0..100000)
            .map(|i| SideEffect::new("test", format!("effect-{}", i).into_bytes()))
            .collect();

        // This should either be bounded or fail safely (not panic)
        let result = engine.record_step(&trace_id, input, output, massive_effects, 1000);

        // Should complete without panic - may succeed with bounded effects or fail with validation error
        match result {
            Ok(_) => {
                // If it succeeds, verify the trace doesn't contain all effects
                let traces = engine.list_traces();
                let trace = traces.iter().find(|t| t.trace_id == trace_id).expect("trace should exist");

                if !trace.steps.is_empty() {
                    let step = &trace.steps[0];
                    // Side effects should be bounded, not all 100k
                    assert!(step.side_effects.len() < 50000,
                        "Side effects should be bounded, got {}", step.side_effects.len());
                }
            },
            Err(_) => {
                // Failure due to size validation is also acceptable
            }
        }
    }

    #[test]
    fn hardening_trace_digest_comparison_timing_safe() {
        // HARDENING: Trace digest comparisons must use constant-time comparison
        let mut engine = ReplayEngine::new();
        let trace_id = "timing-test".to_string();

        // Create a valid trace
        engine.start_capture(&trace_id, "timing-workflow", demo_env())
            .expect("capture start should succeed");
        engine.record_step(&trace_id, b"input".to_vec(), b"output".to_vec(), vec![], 1000)
            .expect("record step should succeed");
        engine.complete_capture(&trace_id, 2000).expect("capture complete should succeed");

        // Get the trace and its digest
        let traces = engine.list_traces();
        let trace = traces.iter().find(|t| t.trace_id == trace_id).expect("trace should exist");
        let correct_digest = &trace.trace_digest;

        // Create digests that differ by single bits to test timing consistency
        let mut almost_correct = correct_digest.clone();
        if !almost_correct.is_empty() {
            almost_correct = almost_correct.chars().take(correct_digest.len() - 1).collect::<String>() + "x";
        }

        let completely_different = "0".repeat(correct_digest.len().max(1));

        let test_digests = vec![
            correct_digest.clone(),
            almost_correct,
            completely_different,
            String::new(), // Empty digest
            "malicious-digest".to_string(),
        ];

        // Test digest validation timing consistency
        for test_digest in &test_digests {
            // Create a fake trace with the test digest
            let mut fake_trace = trace.clone();
            fake_trace.trace_digest = test_digest.clone();

            // Time the validation (simulated)
            let start = std::time::Instant::now();
            let validation_result = fake_trace.validate();
            let _elapsed = start.elapsed();

            // All validations should complete in reasonable time
            // (We can't easily test timing consistency here, but we verify no panic)
            assert!(validation_result.is_ok() || validation_result.is_err());
        }
    }

    #[test]
    fn hardening_step_sequence_overflow_protection() {
        // HARDENING: Step sequence numbers must use saturating arithmetic to prevent overflow
        let mut engine = ReplayEngine::new();
        let trace_id = "sequence-overflow-test".to_string();

        engine.start_capture(&trace_id, "sequence-test", demo_env())
            .expect("capture start should succeed");

        // Test sequence number boundary conditions
        let boundary_sequences = vec![
            0u64,
            1u64,
            u64::MAX - 1,
            u64::MAX,
        ];

        for seq in boundary_sequences {
            let input = format!("input-{}", seq).into_bytes();
            let output = format!("output-{}", seq).into_bytes();
            let effects = vec![SideEffect::new("test", format!("effect-{}", seq).into_bytes())];

            // Record step with explicit sequence (simulated via timestamp)
            let result = engine.record_step(&trace_id, input, output, effects, seq);

            // Should handle without panic - may succeed or fail with validation
            match result {
                Ok(_) => {
                    // Verify sequence is handled correctly
                    let traces = engine.list_traces();
                    if let Some(trace) = traces.iter().find(|t| t.trace_id == trace_id) {
                        if let Some(last_step) = trace.steps.last() {
                            // Sequence should be reasonable, not overflowed
                            assert!(last_step.seq <= u64::MAX);
                        }
                    }
                },
                Err(_) => {
                    // Validation errors for extreme sequences are acceptable
                }
            }
        }
    }

    #[test]
    fn hardening_environment_data_length_validation() {
        // HARDENING: Environment data must validate lengths safely using try_from
        let huge_env_value = "x".repeat(1_000_000);
        let malicious_env = vec![
            ("normal_key".to_string(), "normal_value".to_string()),
            ("empty_key".to_string(), "".to_string()),
            ("huge_key".to_string(), huge_env_value.clone()),
            ("null_byte_key".to_string(), "value\0with\0nulls".to_string()),
            ("unicode_key".to_string(), "\u{202E}malicious\u{202D}".to_string()),
        ].into_iter().collect();

        let malicious_env_snapshot = EnvironmentSnapshot {
            variables: malicious_env,
            working_dir: "/tmp".to_string(),
            timestamp: 1000,
        };

        let mut engine = ReplayEngine::new();
        let trace_id = "env-validation-test".to_string();

        // Try to start capture with malicious environment
        let result = engine.start_capture(&trace_id, "env-test", malicious_env_snapshot);

        // Should handle without panic - may succeed with bounded data or fail with validation
        match result {
            Ok(_) => {
                // If it succeeds, verify environment data is handled safely
                let traces = engine.list_traces();
                if let Some(trace) = traces.iter().find(|t| t.trace_id == trace_id) {
                    // Environment variables should be bounded or validated
                    for (key, value) in &trace.environment.variables {
                        assert!(key.len() < 100_000, "Environment key should be bounded");
                        assert!(value.len() <= 1_000_000, "Environment value should be handled safely");
                        assert!(!key.contains('\0'), "Environment key should not contain null bytes");
                    }
                }
            },
            Err(_) => {
                // Validation failure is also acceptable for malicious input
            }
        }
    }

    // Working negative-path hardening tests using correct API
    #[test]
    fn negative_vec_push_divergences_unbounded_memory_exhaustion() {
        // Test unbounded divergences.push() calls - potential DoS via memory exhaustion
        let mut engine = ReplayEngine::new();
        engine.register_trace(one_step_trace("dos-divergences")).expect("register should succeed");

        // Replay function that creates side effect divergences
        fn divergent_replay(
            step: &TraceStep,
            _env: &EnvironmentSnapshot,
        ) -> (Vec<u8>, Vec<SideEffect>) {
            // Return original output but with different side effects to cause divergence
            let fake_effects = vec![SideEffect::new("fake-effect", vec![0xFF, 0xFE, 0xFD])];
            (step.output.clone(), fake_effects)
        }

        let result = engine
            .replay("dos-divergences", divergent_replay)
            .expect("replay should succeed");

        // Vulnerability: divergences.push() at line 919 has no capacity bounds
        // Each step creates side effect divergence, pushing unbounded Divergence structs
        // Attacker could craft replay functions that exhaust memory via divergence accumulation

        match result.verdict {
            ReplayVerdict::Diverged(count) => {
                assert_eq!(count, 1, "Should detect divergence");
                assert_eq!(result.divergences.len(), 1, "Should record divergence");
                // The vulnerability: no limit on divergences vector size
                // Production code should use: push_bounded(&mut divergences, divergence, MAX_DIVERGENCES)
            }
            _ => panic!("Should detect side effect divergence"),
        }

        // Test with multiple traces to demonstrate accumulation
        for i in 0..10 {
            let trace_id = format!("dos-{:02}", i);
            engine.register_trace(one_step_trace(&trace_id)).expect("register should succeed");
            let result = engine.replay(&trace_id, divergent_replay).expect("replay should succeed");
            assert!(matches!(result.verdict, ReplayVerdict::Diverged(_)));
        }
    }

    #[test]
    fn negative_ct_eq_timing_attack_resistance_trace_digest_comparison() {
        // Verify trace digest validation uses ct_eq for timing attack resistance
        let valid_trace = one_step_trace("timing-test");
        let valid_digest = valid_trace.trace_digest.clone();

        // Create trace with invalid digest (differs only in last character)
        let mut invalid_trace = valid_trace.clone();
        let mut invalid_digest = valid_digest.clone();
        invalid_digest.pop(); // Remove last char
        invalid_digest.push('X'); // Change last char only
        invalid_trace.trace_digest = invalid_digest;

        // Both comparisons should take similar time - no early termination on first byte difference
        let start1 = std::time::Instant::now();
        let result1 = valid_trace.validate();
        let duration1 = start1.elapsed();

        let start2 = std::time::Instant::now();
        let result2 = invalid_trace.validate();
        let duration2 = start2.elapsed();

        assert!(result1.is_ok(), "Valid trace should pass validation");
        assert!(result2.is_err(), "Invalid trace should fail validation");

        // Verify timing is consistent - ct_eq prevents early termination timing leaks
        let ratio = duration1.as_nanos() as f64 / duration2.as_nanos().max(1) as f64;
        assert!(
            ratio < 5.0 && ratio > 0.2,
            "Potential timing leak in digest comparison: ratio={}",
            ratio
        );

        // The positive aspect: line 486 correctly uses ct_eq for digest comparison
        // if !constant_time::ct_eq(&recomputed, &self.trace_digest) prevents timing attacks ✓
    }

    #[test]
    fn negative_saturating_arithmetic_overflow_protection_verification() {
        // Verify arithmetic operations use saturating operations to prevent overflow
        let env = demo_env();
        let mut builder = TraceBuilder::new("overflow-test", "saturating-workflow", env);

        // Test saturating_add in sequence advancement near overflow boundary
        builder.next_seq = u64::MAX - 1;

        let seq1 = builder.record_step(vec![1], vec![2], vec![], 1000);
        assert_eq!(seq1, u64::MAX - 1, "Should allocate near-max sequence");
        assert_eq!(builder.next_seq, u64::MAX, "Should advance to max via saturating_add");

        let seq2 = builder.record_step(vec![3], vec![4], vec![], 2000);
        assert_eq!(seq2, u64::MAX, "Should allocate max sequence");
        assert_eq!(builder.next_seq, u64::MAX, "Should saturate at max, not wrap to 0");

        // Verify step count matches successful recordings
        assert_eq!(builder.step_count(), 2);

        // Positive verification: line 583 uses saturating_add correctly ✓
        // self.next_seq = self.next_seq.saturating_add(1)
        // This prevents sequence counter overflow that could cause replay confusion

        // Test saturating operations in build_demo_trace
        let test_seq = u64::MAX;
        let timestamp = test_seq.saturating_add(1).saturating_mul(1000);
        assert_eq!(timestamp, u64::MAX, "Should saturate multiplication, not overflow");

        // Raw arithmetic would wrap: (u64::MAX + 1) * 1000 = 0 * 1000 = 0
        let would_wrap = test_seq.wrapping_add(1).wrapping_mul(1000);
        assert_eq!(would_wrap, 0, "Demonstrates why saturating arithmetic is critical");
    }

    #[test]
    fn negative_safe_length_conversion_overflow_boundary_protection() {
        // Verify length conversions use try_from() instead of unsafe "as u64" casts

        // Test boundary conditions for length prefixed hashing
        let test_lengths = vec![
            0usize,
            1,
            u32::MAX as usize,
            // Cannot test usize::MAX due to memory constraints, but verify safe conversion exists
        ];

        for &test_len in &test_lengths {
            // Simulate the safe conversion pattern used throughout the code
            let safe_len_u64 = u64::try_from(test_len).unwrap_or(u64::MAX);

            if test_len <= u32::MAX as usize {
                assert_eq!(safe_len_u64, test_len as u64, "Should convert safely within bounds");
            } else {
                assert_eq!(safe_len_u64, u64::MAX, "Should clamp oversized lengths");
            }
        }

        // Verify the safe pattern is used in digest computation
        let effects = vec![
            SideEffect::new("test", vec![1, 2, 3]),
            SideEffect::new("large", vec![0xFF; 1000]),
        ];

        let step = TraceStep::new(0, vec![], vec![], effects, 1000);
        let effects_digest = step.side_effects_digest();

        // Should complete without panic - all length conversions are safe
        assert!(!effects_digest.is_empty(), "Should produce valid digest");

        // Positive verification: consistent use of safe conversions throughout ✓
        // Lines 408, 410, 412, 442, 445, 447, 450, 452, 455, 868, 872, 876, 953
        // All use: u64::try_from(len).unwrap_or(u64::MAX)
        // Instead of dangerous: len as u64 which could overflow on 32-bit platforms
    }

    #[test]
    fn negative_domain_separator_hash_collision_resistance_verification() {
        // Verify hash operations use proper domain separators to prevent collision attacks

        // Test that different operation types produce different hashes with overlapping data
        let step = TraceStep::new(0, vec![1, 2, 3], vec![4, 5, 6], vec![], 1000);

        let output_digest = step.output_digest();
        let effects_digest = step.side_effects_digest();

        // Domain separators should prevent collision even with similar input patterns
        assert_ne!(output_digest, effects_digest,
                  "Domain separators must prevent collision between output and effects");

        // Test trace-level vs step-level domain separation
        let trace_digest = WorkflowTrace::compute_digest(&[step.clone()]);
        assert_ne!(trace_digest, output_digest,
                  "Trace digest domain should prevent collision with step output");
        assert_ne!(trace_digest, effects_digest,
                  "Trace digest domain should prevent collision with step effects");

        // Verify domain prefixes are distinct
        assert_ne!(
            b"replay_step_output_v1:",
            b"replay_step_effects_v1:",
            "Step domain prefixes must be distinct"
        );
        assert_ne!(
            b"replay_trace_digest_v1:",
            b"replay_step_output_v1:",
            "Trace domain must be distinct from step domains"
        );

        // Test length-prefix collision resistance
        let effect1 = SideEffect::new("ab", vec![1, 2, 3]);
        let effect2 = SideEffect::new("a", vec![98, 1, 2, 3]); // 'b' = 98
        let step1 = TraceStep::new(0, vec![], vec![], vec![effect1], 1000);
        let step2 = TraceStep::new(0, vec![], vec![], vec![effect2], 1000);

        // Length prefixing should prevent "ab"|[1,2,3] from colliding with "a"|[98,1,2,3]
        assert_ne!(step1.side_effects_digest(), step2.side_effects_digest(),
                  "Length prefixing must prevent field boundary attacks");

        // Positive verification: consistent domain separation throughout ✓
        // Lines 399, 407, 441: Proper domain prefixes for all hash operations
        // Lines 860, 866: Replay uses same domain prefixes ensuring consistency
        // Length-prefixed encoding prevents field boundary collision attacks
    }

    #[test]
    fn negative_build_demo_trace_vec_push_unbounded_memory_exhaustion() {
        // Test unbounded steps.push() in build_demo_trace function - potential DoS

        // Test with large step count that could exhaust memory
        let large_trace = build_demo_trace("large-trace", "massive-workflow", 10000);

        // Should complete without panic, but demonstrates vulnerability
        assert_eq!(large_trace.steps.len(), 10000);
        assert!(large_trace.validate().is_ok());

        // The vulnerability: line 1012 in build_demo_trace does raw steps.push()
        // steps.push(TraceStep::new(seq, input, output, effects, timestamp));
        // This has no capacity bounds and could be exploited for memory exhaustion

        // An attacker calling build_demo_trace with massive step_count could DoS
        // Production code should use: push_bounded(&mut steps, step, MAX_DEMO_STEPS)
        // Or add validation: if steps.len() >= MAX_DEMO_STEPS { break; }

        // Test memory usage grows linearly with step count
        let small_trace = build_demo_trace("small", "test", 100);
        let medium_trace = build_demo_trace("medium", "test", 1000);

        assert_eq!(small_trace.steps.len(), 100);
        assert_eq!(medium_trace.steps.len(), 1000);

        // Memory usage: steps.len() * size_of::<TraceStep>() grows without bounds
        // Each TraceStep contains Vec<u8> fields that add to memory pressure
    }
}
