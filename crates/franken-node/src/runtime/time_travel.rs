//! bd-1xbc: Deterministic time-travel runtime capture/replay for extension-host workflows.
//!
//! Provides a [`TimeTravelRuntime`] that captures every control decision made during
//! an extension-host workflow execution and replays them byte-for-byte under the
//! same seed and input.
//!
//! # Lifecycle
//!
//! 1. **Capture** -- create a [`CaptureSession`], record [`CaptureFrame`]s as the
//!    workflow executes, then finalize into a [`WorkflowSnapshot`].
//! 2. **Replay** -- load a snapshot, create a [`ReplaySession`], step forward or
//!    backward through captured frames, and detect divergence.
//!
//! # Invariants
//!
//! - INV-TTR-DETERMINISTIC: identical seed + input => byte-for-byte equivalent decisions
//! - INV-TTR-FRAME-COMPLETE: every frame contains full state for decision reconstruction
//! - INV-TTR-CLOCK-MONOTONIC: deterministic clock advances monotonically
//! - INV-TTR-DIVERGENCE-DETECTED: divergence halts replay with structured explanation
//! - INV-TTR-SNAPSHOT-SCHEMA: snapshots carry a versioned schema tag
//! - INV-TTR-STEP-NAVIGATION: forward/backward stepping without state corruption

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt;

// ---------------------------------------------------------------------------
// Schema version
// ---------------------------------------------------------------------------

/// Schema version for time-travel runtime serialization.
pub const SCHEMA_VERSION: &str = "ttr-v1.0";

// ---------------------------------------------------------------------------
// Event codes
// ---------------------------------------------------------------------------

pub mod event_codes {
    /// TTR_001: Capture session started.
    pub const TTR_001: &str = "TTR_001";
    /// TTR_002: Frame captured.
    pub const TTR_002: &str = "TTR_002";
    /// TTR_003: Replay session started.
    pub const TTR_003: &str = "TTR_003";
    /// TTR_004: Replay step advanced (forward).
    pub const TTR_004: &str = "TTR_004";
    /// TTR_005: Replay step reversed (backward).
    pub const TTR_005: &str = "TTR_005";
    /// TTR_006: Divergence detected during replay.
    pub const TTR_006: &str = "TTR_006";
    /// TTR_007: Snapshot serialized to bytes.
    pub const TTR_007: &str = "TTR_007";
    /// TTR_008: Snapshot deserialized from bytes.
    pub const TTR_008: &str = "TTR_008";
    /// TTR_009: Capture session completed.
    pub const TTR_009: &str = "TTR_009";
    /// TTR_010: Replay session completed.
    pub const TTR_010: &str = "TTR_010";
}

// ---------------------------------------------------------------------------
// Error codes
// ---------------------------------------------------------------------------

pub mod error_codes {
    /// Replay attempted on a trace with zero frames.
    pub const ERR_TTR_EMPTY_TRACE: &str = "ERR_TTR_EMPTY_TRACE";
    /// Replayed decision does not match captured decision.
    pub const ERR_TTR_DIVERGENCE: &str = "ERR_TTR_DIVERGENCE";
    /// Deterministic clock moved backwards.
    pub const ERR_TTR_CLOCK_REGRESSION: &str = "ERR_TTR_CLOCK_REGRESSION";
    /// Step navigation moved past trace boundaries.
    pub const ERR_TTR_STEP_OUT_OF_BOUNDS: &str = "ERR_TTR_STEP_OUT_OF_BOUNDS";
    /// Snapshot deserialization failed integrity check.
    pub const ERR_TTR_SNAPSHOT_CORRUPT: &str = "ERR_TTR_SNAPSHOT_CORRUPT";
    /// Replay seed does not match capture seed.
    pub const ERR_TTR_SEED_MISMATCH: &str = "ERR_TTR_SEED_MISMATCH";
}

// ---------------------------------------------------------------------------
// Invariant constants
// ---------------------------------------------------------------------------

pub mod invariants {
    /// Identical seed + input => byte-for-byte equivalent control decisions.
    pub const INV_TTR_DETERMINISTIC: &str = "INV-TTR-DETERMINISTIC";
    /// Every frame contains full state for decision reconstruction.
    pub const INV_TTR_FRAME_COMPLETE: &str = "INV-TTR-FRAME-COMPLETE";
    /// Deterministic clock advances monotonically within a session.
    pub const INV_TTR_CLOCK_MONOTONIC: &str = "INV-TTR-CLOCK-MONOTONIC";
    /// Divergence halts replay with structured explanation.
    pub const INV_TTR_DIVERGENCE_DETECTED: &str = "INV-TTR-DIVERGENCE-DETECTED";
    /// Snapshots carry a versioned schema tag.
    pub const INV_TTR_SNAPSHOT_SCHEMA: &str = "INV-TTR-SNAPSHOT-SCHEMA";
    /// Forward/backward stepping without state corruption.
    pub const INV_TTR_STEP_NAVIGATION: &str = "INV-TTR-STEP-NAVIGATION";
}

// ---------------------------------------------------------------------------
// Deterministic clock
// ---------------------------------------------------------------------------

/// A deterministic clock that replaces wallclock time during capture and replay.
///
/// INV-TTR-CLOCK-MONOTONIC: the tick value advances monotonically; any attempt
/// to set the clock backwards produces an error.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeterministicClock {
    tick: u64,
}

impl DeterministicClock {
    /// Create a new deterministic clock starting at tick 0.
    pub fn new() -> Self {
        Self { tick: 0 }
    }

    /// Create a deterministic clock starting at a given tick.
    pub fn from_tick(tick: u64) -> Self {
        Self { tick }
    }

    /// Return the current tick.
    pub fn now(&self) -> u64 {
        self.tick
    }

    /// Advance the clock to the given tick.
    ///
    /// Returns `Err` with [`error_codes::ERR_TTR_CLOCK_REGRESSION`] if the new
    /// tick is less than the current tick.
    pub fn advance_to(&mut self, new_tick: u64) -> Result<(), TimeTravelError> {
        if new_tick < self.tick {
            return Err(TimeTravelError::ClockRegression {
                current: self.tick,
                attempted: new_tick,
            });
        }
        self.tick = new_tick;
        Ok(())
    }

    /// Advance the clock by one tick and return the new value.
    pub fn tick(&mut self) -> u64 {
        self.tick += 1;
        self.tick
    }
}

impl Default for DeterministicClock {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Control decision
// ---------------------------------------------------------------------------

/// A control decision recorded during workflow execution.
///
/// INV-TTR-FRAME-COMPLETE: each decision carries enough context to be
/// independently verified during replay.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlDecision {
    /// Opaque decision identifier (deterministic from seed).
    pub decision_id: String,
    /// The decision payload bytes (e.g. serialized action).
    pub payload: Vec<u8>,
    /// Contextual metadata, deterministically ordered.
    pub metadata: BTreeMap<String, String>,
}

impl ControlDecision {
    /// Compute a SHA-256 digest of this decision for comparison.
    pub fn digest(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.decision_id.as_bytes());
        hasher.update(&self.payload);
        for (k, v) in &self.metadata {
            hasher.update(k.as_bytes());
            hasher.update(v.as_bytes());
        }
        hex::encode(hasher.finalize())
    }
}

// ---------------------------------------------------------------------------
// Capture frame
// ---------------------------------------------------------------------------

/// A single captured frame in the execution trace.
///
/// INV-TTR-FRAME-COMPLETE: the frame stores the deterministic clock tick,
/// the input hash, and the resulting control decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaptureFrame {
    /// Monotonic frame index (0-based).
    pub frame_index: u64,
    /// Deterministic clock tick when this frame was recorded.
    pub clock_tick: u64,
    /// SHA-256 hash of the input that produced this decision.
    pub input_hash: String,
    /// The control decision captured at this frame.
    pub decision: ControlDecision,
    /// Event code emitted for this frame.
    pub event_code: String,
}

// ---------------------------------------------------------------------------
// Workflow snapshot
// ---------------------------------------------------------------------------

/// A complete serializable snapshot of a captured workflow execution.
///
/// INV-TTR-SNAPSHOT-SCHEMA: carries `schema_version` for backward detection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkflowSnapshot {
    /// Schema version tag.
    pub schema_version: String,
    /// Unique snapshot identifier.
    pub snapshot_id: String,
    /// The seed used for deterministic execution.
    pub seed: u64,
    /// Total number of frames in the trace.
    pub frame_count: u64,
    /// The captured frames, in order.
    pub frames: Vec<CaptureFrame>,
    /// SHA-256 digest of the entire frame sequence for integrity.
    pub integrity_digest: String,
    /// Arbitrary metadata, deterministically ordered.
    pub metadata: BTreeMap<String, String>,
}

impl WorkflowSnapshot {
    /// Compute the integrity digest from the frame sequence.
    pub fn compute_integrity_digest(frames: &[CaptureFrame]) -> String {
        let mut hasher = Sha256::new();
        for f in frames {
            hasher.update(f.frame_index.to_le_bytes());
            hasher.update(b"|");
            hasher.update(f.clock_tick.to_le_bytes());
            hasher.update(b"|");
            hasher.update(f.input_hash.as_bytes());
            hasher.update(b"|");
            hasher.update(f.decision.digest().as_bytes());
            hasher.update(b"|");
        }
        hex::encode(hasher.finalize())
    }

    /// Verify the snapshot integrity against its stored digest.
    pub fn verify_integrity(&self) -> bool {
        let computed = Self::compute_integrity_digest(&self.frames);
        computed == self.integrity_digest
    }

    /// Serialize this snapshot to JSON bytes.
    pub fn to_json_bytes(&self) -> Result<Vec<u8>, TimeTravelError> {
        serde_json::to_vec(self).map_err(|e| TimeTravelError::SnapshotCorrupt {
            detail: format!("serialization failed: {e}"),
        })
    }

    /// Deserialize a snapshot from JSON bytes, verifying integrity.
    ///
    /// INV-TTR-SNAPSHOT-SCHEMA: rejects snapshots that fail the integrity check.
    pub fn from_json_bytes(data: &[u8]) -> Result<Self, TimeTravelError> {
        let snap: Self =
            serde_json::from_slice(data).map_err(|e| TimeTravelError::SnapshotCorrupt {
                detail: format!("deserialization failed: {e}"),
            })?;
        if !snap.verify_integrity() {
            return Err(TimeTravelError::SnapshotCorrupt {
                detail: "integrity digest mismatch".to_string(),
            });
        }
        Ok(snap)
    }
}

// ---------------------------------------------------------------------------
// Divergence explanation
// ---------------------------------------------------------------------------

/// Structured explanation of a replay divergence.
///
/// INV-TTR-DIVERGENCE-DETECTED: this is produced when a replayed decision
/// does not match the captured decision at the same frame index.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DivergenceExplanation {
    /// Frame index where divergence was detected.
    pub frame_index: u64,
    /// Clock tick at which divergence occurred.
    pub clock_tick: u64,
    /// Digest of the expected (captured) decision.
    pub expected_digest: String,
    /// Digest of the actual (replayed) decision.
    pub actual_digest: String,
    /// Human-readable explanation of what diverged.
    pub explanation: String,
    /// Event code for this divergence.
    pub event_code: String,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors produced by the time-travel runtime.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TimeTravelError {
    /// Replay attempted on an empty trace.
    EmptyTrace { code: String },
    /// Replayed decision diverges from captured decision.
    Divergence { explanation: DivergenceExplanation },
    /// Deterministic clock moved backwards.
    ClockRegression { current: u64, attempted: u64 },
    /// Step index out of bounds.
    StepOutOfBounds { requested: u64, total_frames: u64 },
    /// Snapshot integrity check failed.
    SnapshotCorrupt { detail: String },
    /// Replay seed does not match capture seed.
    SeedMismatch { capture_seed: u64, replay_seed: u64 },
}

impl TimeTravelError {
    /// Return the canonical error code for this error.
    pub fn code(&self) -> &'static str {
        match self {
            Self::EmptyTrace { .. } => error_codes::ERR_TTR_EMPTY_TRACE,
            Self::Divergence { .. } => error_codes::ERR_TTR_DIVERGENCE,
            Self::ClockRegression { .. } => error_codes::ERR_TTR_CLOCK_REGRESSION,
            Self::StepOutOfBounds { .. } => error_codes::ERR_TTR_STEP_OUT_OF_BOUNDS,
            Self::SnapshotCorrupt { .. } => error_codes::ERR_TTR_SNAPSHOT_CORRUPT,
            Self::SeedMismatch { .. } => error_codes::ERR_TTR_SEED_MISMATCH,
        }
    }
}

impl fmt::Display for TimeTravelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyTrace { code } => write!(f, "[{code}] replay attempted on empty trace"),
            Self::Divergence { explanation } => {
                write!(
                    f,
                    "[{}] divergence at frame {}: {}",
                    error_codes::ERR_TTR_DIVERGENCE,
                    explanation.frame_index,
                    explanation.explanation,
                )
            }
            Self::ClockRegression { current, attempted } => {
                write!(
                    f,
                    "[{}] clock regression: current={current}, attempted={attempted}",
                    error_codes::ERR_TTR_CLOCK_REGRESSION,
                )
            }
            Self::StepOutOfBounds {
                requested,
                total_frames,
            } => {
                write!(
                    f,
                    "[{}] step {requested} out of bounds (total frames: {total_frames})",
                    error_codes::ERR_TTR_STEP_OUT_OF_BOUNDS,
                )
            }
            Self::SnapshotCorrupt { detail } => {
                write!(
                    f,
                    "[{}] snapshot corrupt: {detail}",
                    error_codes::ERR_TTR_SNAPSHOT_CORRUPT,
                )
            }
            Self::SeedMismatch {
                capture_seed,
                replay_seed,
            } => {
                write!(
                    f,
                    "[{}] seed mismatch: capture={capture_seed}, replay={replay_seed}",
                    error_codes::ERR_TTR_SEED_MISMATCH,
                )
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Capture session
// ---------------------------------------------------------------------------

/// A live capture session that records frames as a workflow executes.
pub struct CaptureSession {
    snapshot_id: String,
    seed: u64,
    clock: DeterministicClock,
    frames: Vec<CaptureFrame>,
    events: Vec<String>,
}

impl CaptureSession {
    /// Start a new capture session.
    pub fn start(snapshot_id: impl Into<String>, seed: u64) -> Self {
        let mut session = Self {
            snapshot_id: snapshot_id.into(),
            seed,
            clock: DeterministicClock::new(),
            frames: Vec::new(),
            events: Vec::new(),
        };
        session.events.push(event_codes::TTR_001.to_string());
        session
    }

    /// Record a frame.
    ///
    /// INV-TTR-CLOCK-MONOTONIC: the provided tick must be >= current clock tick.
    /// INV-TTR-FRAME-COMPLETE: the frame stores all context needed for reconstruction.
    pub fn capture_frame(
        &mut self,
        tick: u64,
        input: &[u8],
        decision: ControlDecision,
    ) -> Result<&CaptureFrame, TimeTravelError> {
        self.clock.advance_to(tick)?;
        let input_hash = hash_bytes(input);
        let frame = CaptureFrame {
            frame_index: self.frames.len() as u64,
            clock_tick: tick,
            input_hash,
            decision,
            event_code: event_codes::TTR_002.to_string(),
        };
        self.frames.push(frame);
        self.events.push(event_codes::TTR_002.to_string());
        Ok(self.frames.last().expect("frames non-empty after push"))
    }

    /// Return the number of captured frames.
    pub fn frame_count(&self) -> usize {
        self.frames.len()
    }

    /// Return the current clock tick.
    pub fn clock_tick(&self) -> u64 {
        self.clock.now()
    }

    /// Return the events emitted so far.
    pub fn events(&self) -> &[String] {
        &self.events
    }

    /// Finalize the capture session into a [`WorkflowSnapshot`].
    pub fn finalize(mut self) -> WorkflowSnapshot {
        self.events.push(event_codes::TTR_009.to_string());
        let integrity_digest = WorkflowSnapshot::compute_integrity_digest(&self.frames);
        WorkflowSnapshot {
            schema_version: SCHEMA_VERSION.to_string(),
            snapshot_id: self.snapshot_id,
            seed: self.seed,
            frame_count: self.frames.len() as u64,
            frames: self.frames,
            integrity_digest,
            metadata: BTreeMap::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// Replay session
// ---------------------------------------------------------------------------

/// A replay session that steps through a captured workflow snapshot.
///
/// INV-TTR-STEP-NAVIGATION: supports both forward and backward stepping.
#[derive(Debug)]
pub struct ReplaySession {
    snapshot: WorkflowSnapshot,
    cursor: u64,
    #[allow(dead_code)]
    seed: u64,
    events: Vec<String>,
}

impl ReplaySession {
    /// Start a replay session from a snapshot.
    ///
    /// INV-TTR-DETERMINISTIC: the replay seed must match the capture seed.
    pub fn start(snapshot: WorkflowSnapshot, seed: u64) -> Result<Self, TimeTravelError> {
        if snapshot.frames.is_empty() {
            return Err(TimeTravelError::EmptyTrace {
                code: error_codes::ERR_TTR_EMPTY_TRACE.to_string(),
            });
        }
        if snapshot.seed != seed {
            return Err(TimeTravelError::SeedMismatch {
                capture_seed: snapshot.seed,
                replay_seed: seed,
            });
        }
        let events = vec![event_codes::TTR_003.to_string()];
        Ok(Self {
            snapshot,
            cursor: 0,
            seed,
            events,
        })
    }

    /// Return the current frame index (cursor position).
    pub fn cursor(&self) -> u64 {
        self.cursor
    }

    /// Return the total number of frames in the trace.
    pub fn total_frames(&self) -> u64 {
        self.snapshot.frame_count
    }

    /// Return the current frame (at the cursor).
    pub fn current_frame(&self) -> Option<&CaptureFrame> {
        self.snapshot.frames.get(self.cursor as usize)
    }

    /// Step the replay forward by one frame.
    ///
    /// INV-TTR-STEP-NAVIGATION: fails if already at the last frame.
    pub fn step_forward(&mut self) -> Result<&CaptureFrame, TimeTravelError> {
        let next = self.cursor + 1;
        if next >= self.snapshot.frame_count {
            return Err(TimeTravelError::StepOutOfBounds {
                requested: next,
                total_frames: self.snapshot.frame_count,
            });
        }
        self.cursor = next;
        self.events.push(event_codes::TTR_004.to_string());
        Ok(&self.snapshot.frames[self.cursor as usize])
    }

    /// Step the replay backward by one frame.
    ///
    /// INV-TTR-STEP-NAVIGATION: fails if already at frame 0.
    pub fn step_backward(&mut self) -> Result<&CaptureFrame, TimeTravelError> {
        if self.cursor == 0 {
            return Err(TimeTravelError::StepOutOfBounds {
                requested: 0,
                total_frames: self.snapshot.frame_count,
            });
        }
        self.cursor -= 1;
        self.events.push(event_codes::TTR_005.to_string());
        Ok(&self.snapshot.frames[self.cursor as usize])
    }

    /// Jump to a specific frame index.
    pub fn jump_to(&mut self, frame_index: u64) -> Result<&CaptureFrame, TimeTravelError> {
        if frame_index >= self.snapshot.frame_count {
            return Err(TimeTravelError::StepOutOfBounds {
                requested: frame_index,
                total_frames: self.snapshot.frame_count,
            });
        }
        if frame_index > self.cursor {
            self.events.push(event_codes::TTR_004.to_string());
        } else if frame_index < self.cursor {
            self.events.push(event_codes::TTR_005.to_string());
        }
        self.cursor = frame_index;
        Ok(&self.snapshot.frames[self.cursor as usize])
    }

    /// Verify that a replayed decision matches the captured decision at the
    /// current cursor position.
    ///
    /// INV-TTR-DIVERGENCE-DETECTED: returns a [`DivergenceExplanation`] on mismatch.
    /// INV-TTR-DETERMINISTIC: identical seed + input => matching digest.
    pub fn verify_decision(&mut self, replayed: &ControlDecision) -> Result<(), TimeTravelError> {
        let frame = &self.snapshot.frames[self.cursor as usize];
        let expected_digest = frame.decision.digest();
        let actual_digest = replayed.digest();
        if expected_digest != actual_digest {
            let explanation = DivergenceExplanation {
                frame_index: frame.frame_index,
                clock_tick: frame.clock_tick,
                expected_digest,
                actual_digest,
                explanation: format!(
                    "replayed decision_id='{}' diverges from captured decision_id='{}'",
                    replayed.decision_id, frame.decision.decision_id,
                ),
                event_code: event_codes::TTR_006.to_string(),
            };
            self.events.push(event_codes::TTR_006.to_string());
            return Err(TimeTravelError::Divergence { explanation });
        }
        Ok(())
    }

    /// Return the events emitted so far.
    pub fn events(&self) -> &[String] {
        &self.events
    }

    /// Complete the replay session.
    pub fn complete(mut self) -> Vec<String> {
        self.events.push(event_codes::TTR_010.to_string());
        self.events
    }
}

// ---------------------------------------------------------------------------
// TimeTravelRuntime (top-level facade)
// ---------------------------------------------------------------------------

/// Top-level runtime for time-travel capture and replay of extension-host workflows.
///
/// Uses BTreeMap for deterministic ordering of all internal maps.
pub struct TimeTravelRuntime {
    /// Registry of completed snapshots, keyed by snapshot_id.
    snapshots: BTreeMap<String, WorkflowSnapshot>,
}

impl TimeTravelRuntime {
    /// Create a new empty runtime.
    pub fn new() -> Self {
        Self {
            snapshots: BTreeMap::new(),
        }
    }

    /// Begin a new capture session.
    pub fn begin_capture(&self, snapshot_id: impl Into<String>, seed: u64) -> CaptureSession {
        CaptureSession::start(snapshot_id, seed)
    }

    /// Store a finalized snapshot in the runtime registry.
    pub fn store_snapshot(&mut self, snapshot: WorkflowSnapshot) {
        self.snapshots
            .insert(snapshot.snapshot_id.clone(), snapshot);
    }

    /// Retrieve a snapshot by id.
    pub fn get_snapshot(&self, snapshot_id: &str) -> Option<&WorkflowSnapshot> {
        self.snapshots.get(snapshot_id)
    }

    /// List all snapshot ids in deterministic order.
    pub fn snapshot_ids(&self) -> Vec<&str> {
        self.snapshots.keys().map(|s| s.as_str()).collect()
    }

    /// Begin a replay session for the given snapshot id.
    pub fn begin_replay(
        &self,
        snapshot_id: &str,
        seed: u64,
    ) -> Result<ReplaySession, TimeTravelError> {
        let snapshot =
            self.snapshots
                .get(snapshot_id)
                .ok_or_else(|| TimeTravelError::EmptyTrace {
                    code: error_codes::ERR_TTR_EMPTY_TRACE.to_string(),
                })?;
        ReplaySession::start(snapshot.clone(), seed)
    }

    /// Serialize a snapshot to JSON bytes (event TTR_007).
    pub fn serialize_snapshot(&self, snapshot_id: &str) -> Result<Vec<u8>, TimeTravelError> {
        let snap =
            self.snapshots
                .get(snapshot_id)
                .ok_or_else(|| TimeTravelError::SnapshotCorrupt {
                    detail: format!("snapshot '{snapshot_id}' not found"),
                })?;
        snap.to_json_bytes()
    }

    /// Deserialize and store a snapshot from JSON bytes (event TTR_008).
    pub fn load_snapshot(&mut self, data: &[u8]) -> Result<String, TimeTravelError> {
        let snap = WorkflowSnapshot::from_json_bytes(data)?;
        let id = snap.snapshot_id.clone();
        self.store_snapshot(snap);
        Ok(id)
    }
}

impl Default for TimeTravelRuntime {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Compute a SHA-256 hex digest of raw bytes.
fn hash_bytes(input: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input);
    hex::encode(hasher.finalize())
}

/// Build a deterministic control decision from seed, tick, and input.
///
/// This is the canonical decision function used to demonstrate byte-for-byte
/// replay equivalence.
pub fn deterministic_decision(seed: u64, tick: u64, input: &[u8]) -> ControlDecision {
    let mut hasher = Sha256::new();
    hasher.update(seed.to_le_bytes());
    hasher.update(b"|");
    hasher.update(tick.to_le_bytes());
    hasher.update(b"|");
    hasher.update(input);
    let digest = hex::encode(hasher.finalize());
    let decision_id = format!("dec-{}-{}", tick, &digest[..8]);
    let mut metadata = BTreeMap::new();
    metadata.insert("seed".to_string(), seed.to_string());
    metadata.insert("tick".to_string(), tick.to_string());
    metadata.insert("input_len".to_string(), input.len().to_string());
    ControlDecision {
        decision_id,
        payload: digest.as_bytes().to_vec(),
        metadata,
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -- Helper ---------------------------------------------------------------

    fn make_decision(id: &str, payload: &[u8]) -> ControlDecision {
        let mut metadata = BTreeMap::new();
        metadata.insert("key".to_string(), "value".to_string());
        ControlDecision {
            decision_id: id.to_string(),
            payload: payload.to_vec(),
            metadata,
        }
    }

    fn simple_capture(seed: u64, inputs: &[&[u8]]) -> WorkflowSnapshot {
        let mut session = CaptureSession::start("snap-test", seed);
        for (i, input) in inputs.iter().enumerate() {
            let decision = deterministic_decision(seed, i as u64 + 1, input);
            session
                .capture_frame(i as u64 + 1, input, decision)
                .unwrap();
        }
        session.finalize()
    }

    // -- DeterministicClock ---------------------------------------------------

    #[test]
    fn clock_starts_at_zero() {
        let clock = DeterministicClock::new();
        assert_eq!(clock.now(), 0);
    }

    #[test]
    fn clock_tick_advances() {
        let mut clock = DeterministicClock::new();
        assert_eq!(clock.tick(), 1);
        assert_eq!(clock.tick(), 2);
        assert_eq!(clock.now(), 2);
    }

    #[test]
    fn clock_advance_to_succeeds() {
        let mut clock = DeterministicClock::new();
        assert!(clock.advance_to(10).is_ok());
        assert_eq!(clock.now(), 10);
        // Same tick is allowed.
        assert!(clock.advance_to(10).is_ok());
    }

    #[test]
    fn clock_advance_to_rejects_regression() {
        let mut clock = DeterministicClock::from_tick(10);
        let err = clock.advance_to(5).unwrap_err();
        assert_eq!(err.code(), error_codes::ERR_TTR_CLOCK_REGRESSION);
    }

    // -- ControlDecision ------------------------------------------------------

    #[test]
    fn decision_digest_is_deterministic() {
        let d1 = make_decision("d1", b"payload");
        let d2 = make_decision("d1", b"payload");
        assert_eq!(d1.digest(), d2.digest());
    }

    #[test]
    fn decision_digest_differs_on_payload_change() {
        let d1 = make_decision("d1", b"payload-a");
        let d2 = make_decision("d1", b"payload-b");
        assert_ne!(d1.digest(), d2.digest());
    }

    // -- CaptureSession -------------------------------------------------------

    #[test]
    fn capture_session_records_frames() {
        let mut session = CaptureSession::start("snap-1", 42);
        let d = make_decision("d1", b"p1");
        session.capture_frame(1, b"input1", d).unwrap();
        assert_eq!(session.frame_count(), 1);
    }

    #[test]
    fn capture_session_rejects_clock_regression() {
        let mut session = CaptureSession::start("snap-1", 42);
        let d1 = make_decision("d1", b"p1");
        session.capture_frame(10, b"i1", d1).unwrap();
        let d2 = make_decision("d2", b"p2");
        let err = session.capture_frame(5, b"i2", d2).unwrap_err();
        assert_eq!(err.code(), error_codes::ERR_TTR_CLOCK_REGRESSION);
    }

    #[test]
    fn capture_finalize_produces_snapshot() {
        let snap = simple_capture(42, &[b"a", b"b", b"c"]);
        assert_eq!(snap.frame_count, 3);
        assert_eq!(snap.schema_version, SCHEMA_VERSION);
        assert_eq!(snap.seed, 42);
        assert!(snap.verify_integrity());
    }

    #[test]
    fn capture_session_emits_events() {
        let mut session = CaptureSession::start("snap-1", 42);
        assert_eq!(session.events(), &[event_codes::TTR_001]);
        let d = make_decision("d1", b"p1");
        session.capture_frame(1, b"i", d).unwrap();
        assert_eq!(session.events().len(), 2);
        assert_eq!(session.events()[1], event_codes::TTR_002);
    }

    // -- WorkflowSnapshot -----------------------------------------------------

    #[test]
    fn snapshot_integrity_passes() {
        let snap = simple_capture(42, &[b"a"]);
        assert!(snap.verify_integrity());
    }

    #[test]
    fn snapshot_integrity_fails_on_tamper() {
        let mut snap = simple_capture(42, &[b"a"]);
        snap.integrity_digest = "tampered".to_string();
        assert!(!snap.verify_integrity());
    }

    #[test]
    fn snapshot_round_trip_json() {
        let snap = simple_capture(42, &[b"a", b"b"]);
        let bytes = snap.to_json_bytes().unwrap();
        let restored = WorkflowSnapshot::from_json_bytes(&bytes).unwrap();
        assert_eq!(snap, restored);
    }

    #[test]
    fn snapshot_from_corrupt_bytes() {
        let err = WorkflowSnapshot::from_json_bytes(b"not json").unwrap_err();
        assert_eq!(err.code(), error_codes::ERR_TTR_SNAPSHOT_CORRUPT);
    }

    // -- ReplaySession --------------------------------------------------------

    #[test]
    fn replay_rejects_empty_trace() {
        let snap = WorkflowSnapshot {
            schema_version: SCHEMA_VERSION.to_string(),
            snapshot_id: "empty".to_string(),
            seed: 1,
            frame_count: 0,
            frames: vec![],
            integrity_digest: WorkflowSnapshot::compute_integrity_digest(&[]),
            metadata: BTreeMap::new(),
        };
        let err = ReplaySession::start(snap, 1).unwrap_err();
        assert_eq!(err.code(), error_codes::ERR_TTR_EMPTY_TRACE);
    }

    #[test]
    fn replay_rejects_seed_mismatch() {
        let snap = simple_capture(42, &[b"a"]);
        let err = ReplaySession::start(snap, 99).unwrap_err();
        assert_eq!(err.code(), error_codes::ERR_TTR_SEED_MISMATCH);
    }

    #[test]
    fn replay_step_forward() {
        let snap = simple_capture(42, &[b"a", b"b", b"c"]);
        let mut session = ReplaySession::start(snap, 42).unwrap();
        assert_eq!(session.cursor(), 0);
        let frame = session.step_forward().unwrap();
        assert_eq!(frame.frame_index, 1);
        assert_eq!(session.cursor(), 1);
    }

    #[test]
    fn replay_step_backward() {
        let snap = simple_capture(42, &[b"a", b"b", b"c"]);
        let mut session = ReplaySession::start(snap, 42).unwrap();
        session.step_forward().unwrap();
        session.step_forward().unwrap();
        assert_eq!(session.cursor(), 2);
        let frame = session.step_backward().unwrap();
        assert_eq!(frame.frame_index, 1);
    }

    #[test]
    fn replay_step_forward_out_of_bounds() {
        let snap = simple_capture(42, &[b"a"]);
        let mut session = ReplaySession::start(snap, 42).unwrap();
        let err = session.step_forward().unwrap_err();
        assert_eq!(err.code(), error_codes::ERR_TTR_STEP_OUT_OF_BOUNDS);
    }

    #[test]
    fn replay_step_backward_at_zero() {
        let snap = simple_capture(42, &[b"a"]);
        let mut session = ReplaySession::start(snap, 42).unwrap();
        let err = session.step_backward().unwrap_err();
        assert_eq!(err.code(), error_codes::ERR_TTR_STEP_OUT_OF_BOUNDS);
    }

    #[test]
    fn replay_jump_to() {
        let snap = simple_capture(42, &[b"a", b"b", b"c"]);
        let mut session = ReplaySession::start(snap, 42).unwrap();
        let frame = session.jump_to(2).unwrap();
        assert_eq!(frame.frame_index, 2);
        assert_eq!(session.cursor(), 2);
    }

    #[test]
    fn replay_jump_to_out_of_bounds() {
        let snap = simple_capture(42, &[b"a"]);
        let mut session = ReplaySession::start(snap, 42).unwrap();
        let err = session.jump_to(5).unwrap_err();
        assert_eq!(err.code(), error_codes::ERR_TTR_STEP_OUT_OF_BOUNDS);
    }

    // -- Divergence detection -------------------------------------------------

    #[test]
    fn verify_decision_detects_divergence() {
        let snap = simple_capture(42, &[b"a"]);
        let mut session = ReplaySession::start(snap, 42).unwrap();
        let bad_decision = make_decision("wrong", b"wrong-payload");
        let err = session.verify_decision(&bad_decision).unwrap_err();
        assert_eq!(err.code(), error_codes::ERR_TTR_DIVERGENCE);
    }

    #[test]
    fn verify_decision_accepts_matching() {
        let snap = simple_capture(42, &[b"a"]);
        let expected_decision = deterministic_decision(42, 1, b"a");
        let mut session = ReplaySession::start(snap, 42).unwrap();
        assert!(session.verify_decision(&expected_decision).is_ok());
    }

    // -- TimeTravelRuntime ----------------------------------------------------

    #[test]
    fn runtime_store_and_retrieve_snapshot() {
        let mut rt = TimeTravelRuntime::new();
        let snap = simple_capture(42, &[b"a"]);
        rt.store_snapshot(snap);
        assert!(rt.get_snapshot("snap-test").is_some());
        assert_eq!(rt.snapshot_ids(), vec!["snap-test"]);
    }

    #[test]
    fn runtime_begin_replay() {
        let mut rt = TimeTravelRuntime::new();
        let snap = simple_capture(42, &[b"a"]);
        rt.store_snapshot(snap);
        let session = rt.begin_replay("snap-test", 42).unwrap();
        assert_eq!(session.total_frames(), 1);
    }

    #[test]
    fn runtime_serialize_and_load() {
        let mut rt = TimeTravelRuntime::new();
        let snap = simple_capture(42, &[b"a", b"b"]);
        rt.store_snapshot(snap);
        let bytes = rt.serialize_snapshot("snap-test").unwrap();
        let mut rt2 = TimeTravelRuntime::new();
        let id = rt2.load_snapshot(&bytes).unwrap();
        assert_eq!(id, "snap-test");
        assert!(rt2.get_snapshot("snap-test").is_some());
    }

    // -- Byte-for-byte replay equivalence (acceptance criterion 1) -----------

    #[test]
    fn byte_for_byte_replay_equivalence() {
        let seed = 12345u64;
        let inputs: Vec<&[u8]> = vec![b"input-alpha", b"input-beta", b"input-gamma"];

        // Capture run 1
        let snap1 = simple_capture(seed, &inputs);
        // Capture run 2 (same seed, same inputs)
        let snap2 = simple_capture(seed, &inputs);

        // Every frame must have identical decision digests
        for (f1, f2) in snap1.frames.iter().zip(snap2.frames.iter()) {
            assert_eq!(
                f1.decision.digest(),
                f2.decision.digest(),
                "frame {} diverged",
                f1.frame_index
            );
        }

        // Replay against captured snapshot must verify all frames
        let mut session = ReplaySession::start(snap1.clone(), seed).unwrap();
        for input in &inputs {
            let tick = session.cursor() as u64 + 1;
            let replayed = deterministic_decision(seed, tick, input);
            session.verify_decision(&replayed).unwrap();
            if session.cursor() + 1 < session.total_frames() {
                session.step_forward().unwrap();
            }
        }
    }

    // -- deterministic_decision -----------------------------------------------

    #[test]
    fn deterministic_decision_stable() {
        let d1 = deterministic_decision(42, 1, b"hello");
        let d2 = deterministic_decision(42, 1, b"hello");
        assert_eq!(d1.digest(), d2.digest());
        assert_eq!(d1.decision_id, d2.decision_id);
    }

    #[test]
    fn deterministic_decision_varies_with_seed() {
        let d1 = deterministic_decision(1, 1, b"hello");
        let d2 = deterministic_decision(2, 1, b"hello");
        assert_ne!(d1.digest(), d2.digest());
    }

    #[test]
    fn deterministic_decision_varies_with_input() {
        let d1 = deterministic_decision(42, 1, b"alpha");
        let d2 = deterministic_decision(42, 1, b"beta");
        assert_ne!(d1.digest(), d2.digest());
    }

    // -- BTreeMap deterministic ordering --------------------------------------

    #[test]
    fn btreemap_ordering_is_deterministic() {
        let mut m1 = BTreeMap::new();
        m1.insert("z".to_string(), "1".to_string());
        m1.insert("a".to_string(), "2".to_string());
        m1.insert("m".to_string(), "3".to_string());
        let mut m2 = BTreeMap::new();
        m2.insert("m".to_string(), "3".to_string());
        m2.insert("a".to_string(), "2".to_string());
        m2.insert("z".to_string(), "1".to_string());
        let keys1: Vec<_> = m1.keys().collect();
        let keys2: Vec<_> = m2.keys().collect();
        assert_eq!(keys1, keys2);
    }

    // -- Error display --------------------------------------------------------

    #[test]
    fn error_display_contains_code() {
        let err = TimeTravelError::EmptyTrace {
            code: error_codes::ERR_TTR_EMPTY_TRACE.to_string(),
        };
        let msg = format!("{err}");
        assert!(msg.contains(error_codes::ERR_TTR_EMPTY_TRACE));
    }

    // -- Replay complete emits TTR_010 ----------------------------------------

    #[test]
    fn replay_complete_emits_event() {
        let snap = simple_capture(42, &[b"a"]);
        let session = ReplaySession::start(snap, 42).unwrap();
        let events = session.complete();
        assert!(events.contains(&event_codes::TTR_010.to_string()));
    }
}
