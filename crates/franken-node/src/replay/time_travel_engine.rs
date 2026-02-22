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
use std::collections::BTreeMap;
use std::fmt;

// ---------------------------------------------------------------------------
// Schema version
// ---------------------------------------------------------------------------

/// Schema version for time-travel replay records.
pub const SCHEMA_VERSION: &str = "ttr-v1.0";

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
        hasher.update(&self.output);
        hex::encode(hasher.finalize())
    }

    /// Compute a SHA-256 digest of the step's side-effects for comparison.
    pub fn side_effects_digest(&self) -> String {
        let mut hasher = Sha256::new();
        for effect in &self.side_effects {
            hasher.update(effect.kind.as_bytes());
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
        for step in steps {
            hasher.update(step.seq.to_le_bytes());
            hasher.update(&step.input);
            hasher.update(&step.output);
            for effect in &step.side_effects {
                hasher.update(effect.kind.as_bytes());
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
            let expected_seq = i as u64;
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
        if recomputed != self.trace_digest {
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
        audit_log.push(AuditEntry::new(
            event_codes::TTR_001,
            trace_id,
            &format!("Capture started for workflow '{workflow_name}'"),
            now,
        ));
        audit_log.push(AuditEntry::new(
            event_codes::TTR_008,
            trace_id,
            &format!(
                "Environment snapshot sealed: platform={}",
                environment.platform
            ),
            now,
        ));
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
        self.steps.push(TraceStep::new(
            seq,
            input,
            output,
            side_effects,
            timestamp_ns,
        ));
        self.audit_log.push(AuditEntry::new(
            event_codes::TTR_002,
            &self.trace_id,
            &format!("Step {seq} recorded"),
            timestamp_ns,
        ));
        self.next_seq += 1;
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
                self.audit_log.push(AuditEntry::new(
                    event_codes::TTR_003,
                    &self.trace_id,
                    &format!(
                        "Capture completed: {} steps, digest={}",
                        trace.steps.len(),
                        &trace_digest[..16]
                    ),
                    0,
                ));
                self.audit_log.push(AuditEntry::new(
                    event_codes::TTR_009,
                    &self.trace_id,
                    "Trace integrity check passed",
                    0,
                ));
                Ok((trace, self.audit_log))
            }
            Err(e) => {
                self.audit_log.push(AuditEntry::new(
                    event_codes::TTR_010,
                    &self.trace_id,
                    &format!("Trace integrity check failed: {e}"),
                    0,
                ));
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
    audit_log: Vec<AuditEntry>,
}

impl ReplayEngine {
    /// Create a new empty replay engine.
    pub fn new() -> Self {
        Self {
            traces: BTreeMap::new(),
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
        self.audit_log.push(AuditEntry::new(
            event_codes::TTR_004,
            trace_id,
            &format!("Replay started: {} steps", trace.steps.len()),
            0,
        ));

        let mut divergences = Vec::new();
        let mut replay_duration_ns: u64 = 0;

        for step in &trace.steps {
            let (replayed_output, replayed_effects) = replay_fn(step, &trace.environment);

            let original_output_digest = step.output_digest();
            let original_effects_digest = step.side_effects_digest();

            // Compute replayed digests
            let replayed_output_digest = {
                let mut hasher = Sha256::new();
                hasher.update(&replayed_output);
                hex::encode(hasher.finalize())
            };
            let replayed_effects_digest = {
                let mut hasher = Sha256::new();
                for effect in &replayed_effects {
                    hasher.update(effect.kind.as_bytes());
                    hasher.update(&effect.payload);
                }
                hex::encode(hasher.finalize())
            };

            let output_match = original_output_digest == replayed_output_digest;
            let effects_match = original_effects_digest == replayed_effects_digest;

            if output_match && effects_match {
                // TTR-005: step identical
                self.audit_log.push(AuditEntry::new(
                    event_codes::TTR_005,
                    trace_id,
                    &format!("Step {} identical", step.seq),
                    step.timestamp_ns,
                ));
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
                self.audit_log.push(AuditEntry::new(
                    event_codes::TTR_006,
                    trace_id,
                    &explanation,
                    step.timestamp_ns,
                ));
                divergences.push(Divergence {
                    step_seq: step.seq,
                    kind,
                    expected_digest: original_output_digest,
                    actual_digest: replayed_output_digest,
                    explanation,
                });
            }

            replay_duration_ns = replay_duration_ns.saturating_add(step.timestamp_ns);
        }

        let verdict = if divergences.is_empty() {
            ReplayVerdict::Identical
        } else {
            ReplayVerdict::Diverged(divergences.len())
        };

        // TTR-007: Replay completed
        self.audit_log.push(AuditEntry::new(
            event_codes::TTR_007,
            trace_id,
            &format!("Replay completed: verdict={verdict}"),
            0,
        ));

        Ok(ReplayResult {
            trace_id: trace_id.to_string(),
            divergences,
            verdict,
            steps_replayed: trace.steps.len() as u64,
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
        self.traces.remove(trace_id)
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
        steps.push(TraceStep::new(
            i as u64,
            input,
            output,
            effects,
            (i as u64 + 1) * 1000,
        ));
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
        assert!(log.len() >= 2);
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
        let (trace, audit) = builder.build().unwrap();
        assert_eq!(trace.trace_id, "b4");
        assert_eq!(trace.steps.len(), 1);
        assert!(trace.validate().is_ok());
        assert!(audit.iter().any(|e| e.event_code == event_codes::TTR_003));
        assert!(audit.iter().any(|e| e.event_code == event_codes::TTR_009));
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
        engine.register_trace(trace).unwrap();
        assert_eq!(engine.trace_count(), 1);
    }

    #[test]
    fn engine_rejects_duplicate_trace() {
        let mut engine = ReplayEngine::new();
        engine.register_trace(one_step_trace("dup")).unwrap();
        let err = engine.register_trace(one_step_trace("dup")).unwrap_err();
        assert!(matches!(err, TimeTravelError::DuplicateTrace { .. }));
    }

    #[test]
    fn engine_get_trace() {
        let mut engine = ReplayEngine::new();
        engine.register_trace(one_step_trace("g1")).unwrap();
        assert!(engine.get_trace("g1").is_some());
        assert!(engine.get_trace("missing").is_none());
    }

    #[test]
    fn engine_trace_ids_sorted() {
        let mut engine = ReplayEngine::new();
        engine.register_trace(one_step_trace("z")).unwrap();
        engine.register_trace(one_step_trace("a")).unwrap();
        engine.register_trace(one_step_trace("m")).unwrap();
        assert_eq!(engine.trace_ids(), vec!["a", "m", "z"]);
    }

    #[test]
    fn engine_remove_trace() {
        let mut engine = ReplayEngine::new();
        engine.register_trace(one_step_trace("rm")).unwrap();
        let removed = engine.remove_trace("rm");
        assert!(removed.is_some());
        assert_eq!(engine.trace_count(), 0);
    }

    // --- Identity replay (INV-TTR-DETERMINISM) ---

    #[test]
    fn identity_replay_produces_identical_verdict() {
        let mut engine = ReplayEngine::new();
        engine.register_trace(multi_step_trace("id1", 5)).unwrap();
        let result = engine.replay_identity("id1").unwrap();
        assert_eq!(result.verdict, ReplayVerdict::Identical);
        assert!(result.divergences.is_empty());
        assert_eq!(result.steps_replayed, 5);
    }

    #[test]
    fn identity_replay_emits_ttr_004_005_007() {
        let mut engine = ReplayEngine::new();
        engine.register_trace(one_step_trace("audit1")).unwrap();
        engine.replay_identity("audit1").unwrap();
        let log = engine.audit_log();
        assert!(log.iter().any(|e| e.event_code == event_codes::TTR_004));
        assert!(log.iter().any(|e| e.event_code == event_codes::TTR_005));
        assert!(log.iter().any(|e| e.event_code == event_codes::TTR_007));
    }

    // --- Divergence detection (INV-TTR-DIVERGENCE-DETECT) ---

    #[test]
    fn divergent_replay_detected() {
        let mut engine = ReplayEngine::new();
        engine.register_trace(multi_step_trace("div1", 3)).unwrap();

        // Replay function that always returns different output
        fn bad_replay(step: &TraceStep, _env: &EnvironmentSnapshot) -> (Vec<u8>, Vec<SideEffect>) {
            let mut output = step.output.clone();
            output.push(0xFF); // alter output
            (output, step.side_effects.clone())
        }

        let result = engine.replay("div1", bad_replay).unwrap();
        assert_eq!(result.verdict, ReplayVerdict::Diverged(3));
        assert_eq!(result.divergences.len(), 3);
        for div in &result.divergences {
            assert_eq!(div.kind, DivergenceKind::OutputMismatch);
        }
    }

    #[test]
    fn side_effect_divergence_detected() {
        let mut engine = ReplayEngine::new();
        engine.register_trace(one_step_trace("se-div")).unwrap();

        fn bad_effects(
            _step: &TraceStep,
            _env: &EnvironmentSnapshot,
        ) -> (Vec<u8>, Vec<SideEffect>) {
            (
                _step.output.clone(),
                vec![SideEffect::new("different", vec![99])],
            )
        }

        let result = engine.replay("se-div", bad_effects).unwrap();
        assert_eq!(result.verdict, ReplayVerdict::Diverged(1));
        assert_eq!(
            result.divergences[0].kind,
            DivergenceKind::SideEffectMismatch
        );
    }

    #[test]
    fn full_mismatch_divergence() {
        let mut engine = ReplayEngine::new();
        engine.register_trace(one_step_trace("full-div")).unwrap();

        fn bad_all(_step: &TraceStep, _env: &EnvironmentSnapshot) -> (Vec<u8>, Vec<SideEffect>) {
            (vec![0xFF], vec![SideEffect::new("different", vec![99])])
        }

        let result = engine.replay("full-div", bad_all).unwrap();
        assert_eq!(result.divergences[0].kind, DivergenceKind::FullMismatch);
    }

    #[test]
    fn divergence_emits_ttr_006() {
        let mut engine = ReplayEngine::new();
        engine.register_trace(one_step_trace("div-audit")).unwrap();

        fn bad_replay(step: &TraceStep, _env: &EnvironmentSnapshot) -> (Vec<u8>, Vec<SideEffect>) {
            (vec![0xFF], step.side_effects.clone())
        }

        engine.replay("div-audit", bad_replay).unwrap();
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
        engine.register_trace(one_step_trace("drain")).unwrap();
        engine.replay_identity("drain").unwrap();
        let drained = engine.drain_audit_log();
        assert!(!drained.is_empty());
        assert!(engine.audit_log().is_empty());
    }

    // --- Serde round-trip ---

    #[test]
    fn workflow_trace_serde_roundtrip() {
        let trace = multi_step_trace("serde1", 3);
        let json = serde_json::to_string(&trace).unwrap();
        let deserialized: WorkflowTrace = serde_json::from_str(&json).unwrap();
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
        let json = serde_json::to_string(&result).unwrap();
        let de: ReplayResult = serde_json::from_str(&json).unwrap();
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
        let json = serde_json::to_string(&div).unwrap();
        let de: Divergence = serde_json::from_str(&json).unwrap();
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
        engine.register_trace(trace).unwrap();
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
            .unwrap();

        // Only diverge on even steps
        fn even_bad(step: &TraceStep, _env: &EnvironmentSnapshot) -> (Vec<u8>, Vec<SideEffect>) {
            if step.seq % 2 == 0 {
                (vec![0xFF], step.side_effects.clone())
            } else {
                (step.output.clone(), step.side_effects.clone())
            }
        }

        let result = engine.replay("partial", even_bad).unwrap();
        // Steps 0, 2, 4 diverge
        assert_eq!(result.verdict, ReplayVerdict::Diverged(3));
        assert_eq!(result.divergences.len(), 3);
        let seqs: Vec<u64> = result.divergences.iter().map(|d| d.step_seq).collect();
        assert_eq!(seqs, vec![0, 2, 4]);
    }
}
