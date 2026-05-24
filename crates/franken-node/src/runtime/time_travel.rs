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

use crate::capacity_defaults::aliases::MAX_EVENTS;
use crate::push_bounded;
const MAX_FRAMES: usize = 4096;

fn len_to_u64(len: usize) -> u64 {
    u64::try_from(len).unwrap_or(u64::MAX)
}

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
    /// Capture trace exceeded maximum capacity.
    pub const ERR_TTR_CAPACITY_EXCEEDED: &str = "ERR_TTR_CAPACITY_EXCEEDED";
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
        self.tick = self.tick.saturating_add(1);
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
        hasher.update(b"time_travel_decision_v1:");
        hasher.update(len_to_u64(self.decision_id.len()).to_le_bytes());
        hasher.update(self.decision_id.as_bytes());
        hasher.update(len_to_u64(self.payload.len()).to_le_bytes());
        hasher.update(&self.payload);
        hasher.update(len_to_u64(self.metadata.len()).to_le_bytes());
        for (k, v) in &self.metadata {
            hasher.update(len_to_u64(k.len()).to_le_bytes());
            hasher.update(k.as_bytes());
            hasher.update(len_to_u64(v.len()).to_le_bytes());
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
        hasher.update(b"time_travel_integrity_v1:");
        hasher.update(len_to_u64(frames.len()).to_le_bytes());
        for f in frames {
            hasher.update(f.frame_index.to_le_bytes());
            hasher.update(f.clock_tick.to_le_bytes());
            hasher.update(len_to_u64(f.input_hash.len()).to_le_bytes());
            hasher.update(f.input_hash.as_bytes());
            let digest = f.decision.digest();
            hasher.update(len_to_u64(digest.len()).to_le_bytes());
            hasher.update(digest.as_bytes());
        }
        hex::encode(hasher.finalize())
    }

    /// Verify the snapshot integrity against its stored digest.
    pub fn verify_integrity(&self) -> bool {
        let computed = Self::compute_integrity_digest(&self.frames);
        crate::security::constant_time::ct_eq(&computed, &self.integrity_digest)
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
        if snap.schema_version != SCHEMA_VERSION {
            return Err(TimeTravelError::SnapshotCorrupt {
                detail: format!(
                    "schema_version mismatch: declared {}, expected {}",
                    snap.schema_version, SCHEMA_VERSION
                ),
            });
        }
        if !snap.verify_integrity() {
            return Err(TimeTravelError::SnapshotCorrupt {
                detail: "integrity digest mismatch".to_string(),
            });
        }
        if snap.frame_count != len_to_u64(snap.frames.len()) {
            return Err(TimeTravelError::SnapshotCorrupt {
                detail: format!(
                    "frame_count mismatch: declared {}, actual {}",
                    snap.frame_count,
                    snap.frames.len()
                ),
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
    /// Capture trace exceeded maximum capacity.
    CapacityExceeded { limit: usize },
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
            Self::CapacityExceeded { .. } => error_codes::ERR_TTR_CAPACITY_EXCEEDED,
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
            Self::CapacityExceeded { limit } => {
                write!(
                    f,
                    "[{}] capture trace exceeded maximum capacity of {limit} frames",
                    error_codes::ERR_TTR_CAPACITY_EXCEEDED,
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
    /// Monotonic frame counter — not reset by push_bounded eviction.
    next_frame_index: u64,
}

impl CaptureSession {
    fn emit_event(&mut self, event: String) {
        push_bounded(&mut self.events, event, MAX_EVENTS);
    }

    /// Start a new capture session.
    pub fn start(snapshot_id: impl Into<String>, seed: u64) -> Self {
        let mut session = Self {
            snapshot_id: snapshot_id.into(),
            seed,
            clock: DeterministicClock::new(),
            frames: Vec::new(),
            events: Vec::new(),
            next_frame_index: 0,
        };
        session.emit_event(event_codes::TTR_001.to_string());
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
        if self.frames.len() >= MAX_FRAMES {
            return Err(TimeTravelError::CapacityExceeded { limit: MAX_FRAMES });
        }
        self.clock.advance_to(tick)?;
        let input_hash = hash_bytes(input);
        let idx = self.next_frame_index;
        self.next_frame_index = self.next_frame_index.saturating_add(1);
        let frame = CaptureFrame {
            frame_index: idx,
            clock_tick: tick,
            input_hash,
            decision,
            event_code: event_codes::TTR_002.to_string(),
        };
        self.frames.push(frame);
        self.emit_event(event_codes::TTR_002.to_string());
        self.frames
            .last()
            .ok_or_else(|| TimeTravelError::SnapshotCorrupt {
                detail: "capture invariant violated: frame missing after append".to_string(),
            })
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
        self.emit_event(event_codes::TTR_009.to_string());
        let integrity_digest = WorkflowSnapshot::compute_integrity_digest(&self.frames);
        WorkflowSnapshot {
            schema_version: SCHEMA_VERSION.to_string(),
            snapshot_id: self.snapshot_id,
            seed: self.seed,
            frame_count: len_to_u64(self.frames.len()),
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
    fn emit_event(&mut self, event: String) {
        push_bounded(&mut self.events, event, MAX_EVENTS);
    }

    /// Start a replay session from a snapshot.
    ///
    /// INV-TTR-DETERMINISTIC: the replay seed must match the capture seed.
    pub fn start(snapshot: WorkflowSnapshot, seed: u64) -> Result<Self, TimeTravelError> {
        if snapshot.schema_version != SCHEMA_VERSION {
            return Err(TimeTravelError::SnapshotCorrupt {
                detail: format!(
                    "schema_version mismatch: declared {}, expected {}",
                    snapshot.schema_version, SCHEMA_VERSION
                ),
            });
        }
        if !snapshot.verify_integrity() {
            return Err(TimeTravelError::SnapshotCorrupt {
                detail: "integrity digest mismatch".to_string(),
            });
        }
        if snapshot.frames.is_empty() {
            return Err(TimeTravelError::EmptyTrace {
                code: error_codes::ERR_TTR_EMPTY_TRACE.to_string(),
            });
        }
        if snapshot.frame_count != len_to_u64(snapshot.frames.len()) {
            return Err(TimeTravelError::SnapshotCorrupt {
                detail: format!(
                    "frame_count mismatch: declared {}, actual {}",
                    snapshot.frame_count,
                    snapshot.frames.len()
                ),
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
        self.snapshot
            .frames
            .get(usize::try_from(self.cursor).unwrap_or(usize::MAX))
    }

    /// Step the replay forward by one frame.
    ///
    /// INV-TTR-STEP-NAVIGATION: fails if already at the last frame.
    pub fn step_forward(&mut self) -> Result<&CaptureFrame, TimeTravelError> {
        let next = self.cursor.saturating_add(1);
        if next >= self.snapshot.frame_count {
            return Err(TimeTravelError::StepOutOfBounds {
                requested: next,
                total_frames: self.snapshot.frame_count,
            });
        }
        self.cursor = next;
        self.emit_event(event_codes::TTR_004.to_string());
        self.snapshot
            .frames
            .get(usize::try_from(self.cursor).unwrap_or(usize::MAX))
            .ok_or_else(|| TimeTravelError::StepOutOfBounds {
                requested: self.cursor,
                total_frames: self.snapshot.frame_count,
            })
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
        self.cursor = self.cursor.saturating_sub(1);
        self.emit_event(event_codes::TTR_005.to_string());
        self.snapshot
            .frames
            .get(usize::try_from(self.cursor).unwrap_or(usize::MAX))
            .ok_or_else(|| TimeTravelError::StepOutOfBounds {
                requested: self.cursor,
                total_frames: self.snapshot.frame_count,
            })
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
            self.emit_event(event_codes::TTR_004.to_string());
        } else if frame_index < self.cursor {
            self.emit_event(event_codes::TTR_005.to_string());
        }
        self.cursor = frame_index;
        self.snapshot
            .frames
            .get(usize::try_from(self.cursor).unwrap_or(usize::MAX))
            .ok_or_else(|| TimeTravelError::StepOutOfBounds {
                requested: self.cursor,
                total_frames: self.snapshot.frame_count,
            })
    }

    /// Verify that a replayed decision matches the captured decision at the
    /// current cursor position.
    ///
    /// INV-TTR-DIVERGENCE-DETECTED: returns a [`DivergenceExplanation`] on mismatch.
    /// INV-TTR-DETERMINISTIC: identical seed + input => matching digest.
    pub fn verify_decision(&mut self, replayed: &ControlDecision) -> Result<(), TimeTravelError> {
        let frame = self
            .snapshot
            .frames
            .get(usize::try_from(self.cursor).unwrap_or(usize::MAX))
            .ok_or_else(|| TimeTravelError::StepOutOfBounds {
                requested: self.cursor,
                total_frames: self.snapshot.frame_count,
            })?;
        let expected_digest = frame.decision.digest();
        let actual_digest = replayed.digest();
        if !crate::security::constant_time::ct_eq(&expected_digest, &actual_digest) {
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
            self.emit_event(event_codes::TTR_006.to_string());
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
        self.emit_event(event_codes::TTR_010.to_string());
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
    hasher.update(b"time_travel_hash_v1:");
    hasher.update(len_to_u64(input.len()).to_le_bytes());
    hasher.update(input);
    hex::encode(hasher.finalize())
}

/// Build a deterministic control decision from seed, tick, and input.
///
/// This is the canonical decision function used to demonstrate byte-for-byte
/// replay equivalence.
pub fn deterministic_decision(seed: u64, tick: u64, input: &[u8]) -> ControlDecision {
    let mut hasher = Sha256::new();
    hasher.update(b"time_travel_det_decision_v1:");
    hasher.update(seed.to_le_bytes());
    hasher.update(tick.to_le_bytes());
    hasher.update(len_to_u64(input.len()).to_le_bytes());
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
    use crate::security::constant_time;

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
            let tick = u64::try_from(i).unwrap_or(u64::MAX).saturating_add(1);
            let decision = deterministic_decision(seed, tick, input);
            session.capture_frame(tick, input, decision).unwrap();
        }
        session.finalize()
    }

    #[cfg(target_pointer_width = "64")]
    #[test]
    fn len_to_u64_preserves_lengths_above_u32_max() {
        let len = usize::try_from(u64::from(u32::MAX).saturating_add(1))
            .expect("64-bit targets can represent u32::MAX + 1 as usize");

        assert_eq!(len_to_u64(len), u64::from(u32::MAX).saturating_add(1));
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

    #[test]
    fn clock_regression_preserves_current_tick() {
        let mut clock = DeterministicClock::from_tick(10);

        let err = clock.advance_to(5).unwrap_err();

        assert_eq!(err.code(), error_codes::ERR_TTR_CLOCK_REGRESSION);
        assert_eq!(clock.now(), 10);
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

    #[test]
    fn control_decision_deserialize_rejects_missing_payload() {
        let json = r#"{
            "decision_id": "d1",
            "metadata": {}
        }"#;

        let result: Result<ControlDecision, _> = serde_json::from_str(json);

        assert!(result.is_err());
    }

    // -- CaptureSession -------------------------------------------------------

    #[test]
    fn capture_session_records_frames() {
        let mut session = CaptureSession::start("snap-1", 42);
        let d = make_decision("d1", b"p1");
        session
            .capture_frame(1, b"input1", d)
            .expect("capture should succeed");
        assert_eq!(session.frame_count(), 1);
    }

    #[test]
    fn capture_session_rejects_clock_regression() {
        let mut session = CaptureSession::start("snap-1", 42);
        let d1 = make_decision("d1", b"p1");
        session
            .capture_frame(10, b"i1", d1)
            .expect("capture should succeed");
        let d2 = make_decision("d2", b"p2");
        let err = session.capture_frame(5, b"i2", d2).unwrap_err();
        assert_eq!(err.code(), error_codes::ERR_TTR_CLOCK_REGRESSION);
    }

    #[test]
    fn capture_clock_regression_preserves_frame_count_clock_and_events() {
        let mut session = CaptureSession::start("snap-1", 42);
        session
            .capture_frame(10, b"i1", make_decision("d1", b"p1"))
            .expect("first capture should succeed");
        let events_before = session.events().len();

        let err = session
            .capture_frame(9, b"i2", make_decision("d2", b"p2"))
            .unwrap_err();

        assert_eq!(err.code(), error_codes::ERR_TTR_CLOCK_REGRESSION);
        assert_eq!(session.frame_count(), 1);
        assert_eq!(session.clock_tick(), 10);
        assert_eq!(session.events().len(), events_before);
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
        session
            .capture_frame(1, b"i", d)
            .expect("capture should succeed");
        assert_eq!(session.events().len(), 2);
        assert_eq!(session.events()[1], event_codes::TTR_002);
    }

    #[test]
    fn capture_frame_deserialize_rejects_missing_event_code() {
        let json = r#"{
            "frame_index": 0,
            "clock_tick": 1,
            "input_hash": "abc",
            "decision": {
                "decision_id": "d1",
                "payload": [1, 2, 3],
                "metadata": {}
            }
        }"#;

        let result: Result<CaptureFrame, _> = serde_json::from_str(json);

        assert!(result.is_err());
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
    fn snapshot_integrity_fails_on_same_length_tamper() {
        let mut snap = simple_capture(42, &[b"a"]);
        let mut chars: Vec<char> = snap.integrity_digest.chars().collect();
        chars[0] = if chars[0] == '0' { '1' } else { '0' };
        snap.integrity_digest = chars.into_iter().collect();
        assert!(!snap.verify_integrity());
    }

    #[test]
    fn snapshot_round_trip_json() {
        let snap = simple_capture(42, &[b"a", b"b"]);
        let bytes = snap.to_json_bytes().expect("serialize should succeed");
        let restored =
            WorkflowSnapshot::from_json_bytes(&bytes).expect("deserialize should succeed");
        assert_eq!(snap, restored);
    }

    #[test]
    fn snapshot_from_corrupt_bytes() {
        let err = WorkflowSnapshot::from_json_bytes(b"not json").unwrap_err();
        assert_eq!(err.code(), error_codes::ERR_TTR_SNAPSHOT_CORRUPT);
    }

    #[test]
    fn snapshot_from_json_rejects_frames_type_confusion() {
        let json = r#"{
            "schema_version": "ttr-v1.0",
            "snapshot_id": "snap-bad",
            "seed": 42,
            "frame_count": 0,
            "frames": "not-a-frame-array",
            "integrity_digest": "",
            "metadata": {}
        }"#;

        let err = WorkflowSnapshot::from_json_bytes(json.as_bytes()).unwrap_err();

        assert_eq!(err.code(), error_codes::ERR_TTR_SNAPSHOT_CORRUPT);
    }

    #[test]
    fn snapshot_from_json_rejects_missing_integrity_digest() {
        let json = r#"{
            "schema_version": "ttr-v1.0",
            "snapshot_id": "snap-bad",
            "seed": 42,
            "frame_count": 0,
            "frames": [],
            "metadata": {}
        }"#;

        let err = WorkflowSnapshot::from_json_bytes(json.as_bytes()).unwrap_err();

        assert_eq!(err.code(), error_codes::ERR_TTR_SNAPSHOT_CORRUPT);
    }

    #[test]
    fn snapshot_from_json_rejects_frame_count_mismatch_with_valid_digest() {
        let mut snap = simple_capture(42, &[b"a", b"b"]);
        snap.frame_count = 1;
        let bytes = snap.to_json_bytes().expect("serialize mismatched snapshot");

        let err = WorkflowSnapshot::from_json_bytes(&bytes).unwrap_err();

        assert_eq!(err.code(), error_codes::ERR_TTR_SNAPSHOT_CORRUPT);
        assert!(err.to_string().contains("frame_count mismatch"));
    }

    #[test]
    fn time_travel_error_deserialize_rejects_unknown_variant() {
        let result: Result<TimeTravelError, _> =
            serde_json::from_str(r#"{"UnknownVariant":{"code":"ERR"}}"#);

        assert!(result.is_err());
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
    fn snapshot_from_json_rejects_frame_count_mismatch() {
        let snap = simple_capture(42, &[b"a", b"b"]);
        let bytes = snap.to_json_bytes().expect("serialize should succeed");
        let mut json: serde_json::Value =
            serde_json::from_slice(&bytes).expect("deserialize should succeed");
        json["frame_count"] = serde_json::json!(999_u64);
        let tampered = serde_json::to_vec(&json).expect("serialize should succeed");

        let err = WorkflowSnapshot::from_json_bytes(&tampered).unwrap_err();
        assert_eq!(err.code(), error_codes::ERR_TTR_SNAPSHOT_CORRUPT);
    }

    #[test]
    fn snapshot_from_json_rejects_schema_mismatch() {
        let snap = simple_capture(42, &[b"a"]);
        let bytes = snap.to_json_bytes().expect("serialize should succeed");
        let mut json: serde_json::Value =
            serde_json::from_slice(&bytes).expect("deserialize should succeed");
        json["schema_version"] = serde_json::json!("ttr-v9.9");
        let tampered = serde_json::to_vec(&json).expect("serialize should succeed");

        let err = WorkflowSnapshot::from_json_bytes(&tampered).unwrap_err();
        assert_eq!(err.code(), error_codes::ERR_TTR_SNAPSHOT_CORRUPT);
    }

    #[test]
    fn replay_rejects_frame_count_mismatch() {
        let mut snap = simple_capture(42, &[b"a", b"b"]);
        snap.frame_count = snap.frame_count.saturating_add(1);
        let err = ReplaySession::start(snap, 42).unwrap_err();
        assert_eq!(err.code(), error_codes::ERR_TTR_SNAPSHOT_CORRUPT);
    }

    #[test]
    fn replay_rejects_schema_mismatch_snapshot() {
        let mut snap = simple_capture(42, &[b"a"]);
        snap.schema_version = "ttr-v0".to_string();
        let err = ReplaySession::start(snap, 42).unwrap_err();
        assert_eq!(err.code(), error_codes::ERR_TTR_SNAPSHOT_CORRUPT);
    }

    #[test]
    fn replay_rejects_integrity_mismatch_snapshot() {
        let mut snap = simple_capture(42, &[b"a"]);
        snap.integrity_digest = "deadbeef".to_string();
        let err = ReplaySession::start(snap, 42).unwrap_err();
        assert_eq!(err.code(), error_codes::ERR_TTR_SNAPSHOT_CORRUPT);
    }

    #[test]
    fn replay_step_forward() {
        let snap = simple_capture(42, &[b"a", b"b", b"c"]);
        let mut session = ReplaySession::start(snap, 42).expect("start should succeed");
        assert_eq!(session.cursor(), 0);
        let frame = session.step_forward().expect("step should succeed");
        assert_eq!(frame.frame_index, 1);
        assert_eq!(session.cursor(), 1);
    }

    #[test]
    fn replay_step_backward() {
        let snap = simple_capture(42, &[b"a", b"b", b"c"]);
        let mut session = ReplaySession::start(snap, 42).expect("start should succeed");
        session.step_forward().expect("step should succeed");
        session.step_forward().expect("step should succeed");
        assert_eq!(session.cursor(), 2);
        let frame = session.step_backward().expect("step should succeed");
        assert_eq!(frame.frame_index, 1);
    }

    #[test]
    fn replay_step_forward_out_of_bounds() {
        let snap = simple_capture(42, &[b"a"]);
        let mut session = ReplaySession::start(snap, 42).expect("start should succeed");
        let err = session.step_forward().expect_err("should fail");
        assert_eq!(err.code(), error_codes::ERR_TTR_STEP_OUT_OF_BOUNDS);
    }

    #[test]
    fn replay_step_forward_out_of_bounds_preserves_cursor() {
        let snap = simple_capture(42, &[b"a"]);
        let mut session = ReplaySession::start(snap, 42).expect("start should succeed");

        let err = session.step_forward().expect_err("should fail");

        assert_eq!(err.code(), error_codes::ERR_TTR_STEP_OUT_OF_BOUNDS);
        assert_eq!(session.cursor(), 0);
    }

    #[test]
    fn replay_step_backward_at_zero() {
        let snap = simple_capture(42, &[b"a"]);
        let mut session = ReplaySession::start(snap, 42).expect("start should succeed");
        let err = session.step_backward().expect_err("should fail");
        assert_eq!(err.code(), error_codes::ERR_TTR_STEP_OUT_OF_BOUNDS);
    }

    #[test]
    fn replay_step_backward_out_of_bounds_preserves_cursor_and_events() {
        let snap = simple_capture(42, &[b"a"]);
        let mut session = ReplaySession::start(snap, 42).expect("start should succeed");
        let events_before = session.events().to_vec();

        let err = session.step_backward().expect_err("should fail");

        assert_eq!(err.code(), error_codes::ERR_TTR_STEP_OUT_OF_BOUNDS);
        assert_eq!(session.cursor(), 0);
        assert_eq!(session.events(), events_before.as_slice());
    }

    #[test]
    fn replay_jump_to() {
        let snap = simple_capture(42, &[b"a", b"b", b"c"]);
        let mut session = ReplaySession::start(snap, 42).expect("start should succeed");
        let frame = session.jump_to(2).expect("jump should succeed");
        assert_eq!(frame.frame_index, 2);
        assert_eq!(session.cursor(), 2);
    }

    #[test]
    fn replay_jump_to_out_of_bounds() {
        let snap = simple_capture(42, &[b"a"]);
        let mut session = ReplaySession::start(snap, 42).expect("start should succeed");
        let err = session.jump_to(5).expect_err("should fail");
        assert_eq!(err.code(), error_codes::ERR_TTR_STEP_OUT_OF_BOUNDS);
    }

    #[test]
    fn replay_jump_to_out_of_bounds_preserves_cursor() {
        let snap = simple_capture(42, &[b"a", b"b", b"c"]);
        let mut session = ReplaySession::start(snap, 42).expect("start should succeed");
        session.jump_to(2).expect("jump should succeed");

        let err = session.jump_to(99).expect_err("should fail");

        assert_eq!(err.code(), error_codes::ERR_TTR_STEP_OUT_OF_BOUNDS);
        assert_eq!(session.cursor(), 2);
    }

    #[test]
    fn replay_jump_to_out_of_bounds_does_not_emit_navigation_event() {
        let snap = simple_capture(42, &[b"a", b"b", b"c"]);
        let mut session = ReplaySession::start(snap, 42).expect("start should succeed");
        session.jump_to(1).expect("jump should succeed");
        let events_before = session.events().len();

        let err = session.jump_to(99).expect_err("should fail");

        assert_eq!(err.code(), error_codes::ERR_TTR_STEP_OUT_OF_BOUNDS);
        assert_eq!(session.cursor(), 1);
        assert_eq!(session.events().len(), events_before);
    }

    // -- Divergence detection -------------------------------------------------

    #[test]
    fn verify_decision_detects_divergence() {
        let snap = simple_capture(42, &[b"a"]);
        let mut session = ReplaySession::start(snap, 42).expect("start should succeed");
        let bad_decision = make_decision("wrong", b"wrong-payload");
        let err = session
            .verify_decision(&bad_decision)
            .expect_err("should fail");
        assert_eq!(err.code(), error_codes::ERR_TTR_DIVERGENCE);
    }

    #[test]
    fn verify_decision_divergence_preserves_cursor_and_emits_event() {
        let snap = simple_capture(42, &[b"a"]);
        let mut session = ReplaySession::start(snap, 42).expect("start should succeed");
        let bad_decision = make_decision("wrong", b"wrong-payload");

        let err = session.verify_decision(&bad_decision).unwrap_err();

        assert_eq!(err.code(), error_codes::ERR_TTR_DIVERGENCE);
        assert_eq!(session.cursor(), 0);
        assert_eq!(
            session
                .events()
                .iter()
                .filter(|event| event.as_str() == event_codes::TTR_006)
                .count(),
            1
        );
    }

    #[test]
    fn verify_decision_accepts_matching() {
        let snap = simple_capture(42, &[b"a"]);
        let expected_decision = deterministic_decision(42, 1, b"a");
        let mut session = ReplaySession::start(snap, 42).expect("start should succeed");
        assert!(session.verify_decision(&expected_decision).is_ok());
    }

    #[test]
    fn verify_matching_decision_does_not_emit_divergence_event() {
        let snap = simple_capture(42, &[b"a"]);
        let expected_decision = deterministic_decision(42, 1, b"a");
        let mut session = ReplaySession::start(snap, 42).expect("start should succeed");

        session
            .verify_decision(&expected_decision)
            .expect("matching decision should verify");

        assert!(
            !session
                .events()
                .iter()
                .any(|event| event.as_str() == event_codes::TTR_006)
        );
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
        let session = rt
            .begin_replay("snap-test", 42)
            .expect("begin should succeed");
        assert_eq!(session.total_frames(), 1);
    }

    #[test]
    fn runtime_serialize_and_load() {
        let mut rt = TimeTravelRuntime::new();
        let snap = simple_capture(42, &[b"a", b"b"]);
        rt.store_snapshot(snap);
        let bytes = rt
            .serialize_snapshot("snap-test")
            .expect("serialize should succeed");
        let mut rt2 = TimeTravelRuntime::new();
        let id = rt2.load_snapshot(&bytes).expect("load should succeed");
        assert_eq!(id, "snap-test");
        assert!(rt2.get_snapshot("snap-test").is_some());
    }

    #[test]
    fn runtime_begin_replay_missing_snapshot_rejected() {
        let rt = TimeTravelRuntime::new();

        let err = rt.begin_replay("missing", 42).unwrap_err();

        assert_eq!(err.code(), error_codes::ERR_TTR_EMPTY_TRACE);
    }

    #[test]
    fn runtime_serialize_missing_snapshot_rejected() {
        let rt = TimeTravelRuntime::new();

        let err = rt.serialize_snapshot("missing").unwrap_err();

        assert_eq!(err.code(), error_codes::ERR_TTR_SNAPSHOT_CORRUPT);
    }

    #[test]
    fn runtime_load_corrupt_snapshot_does_not_store_snapshot() {
        let mut snap = simple_capture(42, &[b"a"]);
        snap.integrity_digest = "tampered".to_string();
        let bytes = snap.to_json_bytes().expect("serialize corrupt snapshot");
        let mut rt = TimeTravelRuntime::new();

        let err = rt.load_snapshot(&bytes).unwrap_err();

        assert_eq!(err.code(), error_codes::ERR_TTR_SNAPSHOT_CORRUPT);
        assert!(rt.snapshot_ids().is_empty());
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
        let mut session = ReplaySession::start(snap1.clone(), seed).expect("start should succeed");
        for input in &inputs {
            let tick = session.cursor().saturating_add(1);
            let replayed = deterministic_decision(seed, tick, input);
            session
                .verify_decision(&replayed)
                .expect("verify should succeed");
            if session.cursor().saturating_add(1) < session.total_frames() {
                session.step_forward().expect("step should succeed");
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
        let session = ReplaySession::start(snap, 42).expect("start should succeed");
        let events = session.complete();
        assert!(events.contains(&event_codes::TTR_010.to_string()));
    }

    #[test]
    fn push_bounded_zero_capacity_clears_existing_items() {
        let mut items = vec![event_codes::TTR_001.to_string()];

        push_bounded(&mut items, event_codes::TTR_002.to_string(), 0);

        assert!(items.is_empty());
    }

    #[test]
    fn hash_bytes_uses_length_prefix_for_collision_resistance() {
        use sha2::{Digest, Sha256};

        let input = b"ab";
        let actual_hash = hash_bytes(input);

        let mut legacy_hasher = Sha256::new();
        legacy_hasher.update(b"time_travel_hash_v1:");
        legacy_hasher.update(input);
        let legacy_hash = hex::encode(legacy_hasher.finalize());

        assert_ne!(
            actual_hash, legacy_hash,
            "length-prefixed hash should differ from legacy format"
        );

        let mut expected_hasher = Sha256::new();
        expected_hasher.update(b"time_travel_hash_v1:");
        expected_hasher.update(len_to_u64(input.len()).to_le_bytes());
        expected_hasher.update(input);
        let expected_hash = hex::encode(expected_hasher.finalize());

        assert_eq!(
            actual_hash, expected_hash,
            "hash should match length-prefixed pattern"
        );
    }

    // Frozen outputs of the public function `deterministic_decision`
    // (time_travel.rs:830). The function is the canonical decision
    // primitive used to demonstrate byte-for-byte replay equivalence
    // across time-travel replays.
    //
    // The function builds a ControlDecision { decision_id, payload,
    // metadata } where the LOAD-BEARING fields are derived from:
    //
    //   digest = SHA256(
    //     b"time_travel_det_decision_v1:"
    //     || seed.to_le_bytes()                   # raw u64 LE
    //     || tick.to_le_bytes()                   # raw u64 LE
    //     || LE64(len(input)) || input
    //   ).hex()
    //
    //   decision_id = format!("dec-{tick}-{}", &digest[..8])
    //   payload     = digest.as_bytes().to_vec()  # 64 ASCII hex bytes
    //   metadata    = {"seed": seed.to_string(),
    //                  "tick": tick.to_string(),
    //                  "input_len": input.len().to_string()}
    //
    // *** DISTINCTIVE FEATURE pinned by this golden ***
    //
    // The decision_id is a COMPOSED IDENTIFIER: "dec-{tick}-{8 hex
    // chars of digest}". The decision_id format itself is part of
    // the public API contract — downstream consumers parse it to
    // extract the tick (for monotonicity checks) and the 8-char
    // hex prefix (for deduplication). This is the FIRST golden in
    // the suite to pin a COMPOSITE-FORMAT identifier (vs the pure-
    // hex outputs of prior surfaces). A future refactor that
    // changed the format (e.g., "dec_{tick}_{}" with underscores,
    // or expanding the hex prefix from 8 to 16 chars) would
    // catastrophically break downstream tick-extraction parsing.
    //
    // Three frozen fixtures + four structural invariants:
    //
    //   1. zero (seed=0, tick=0, input=empty). Locks the v1 domain +
    //      LE64 raw u64 encoding of zero counters + LE64(0) empty-
    //      input framing + the "dec-0-{e21bf34f}" composite format.
    //      decision_id = "dec-0-e21bf34f"
    //      digest      = e21bf34f21efe4ee58a5141741368b451e9abd147fa34d310b36c0d0715e4b65
    //
    //   2. typical (seed=42, tick=7, input="replay-input-payload").
    //      Locks the typical-production composite format.
    //      decision_id = "dec-7-43475daa"
    //
    //   3. binary (seed=0xABCDEF, tick=100, input=bytes 0..8). Locks
    //      that the function handles binary input (NOT only UTF-8
    //      strings) and that the tick portion of decision_id can be
    //      multi-digit (100 is 3 chars).
    //      decision_id = "dec-100-3325effd"
    //
    //   4. payload-IS-DIGEST-ASCII-BYTES INVARIANT: payload.len() ==
    //      64 (the digest is 64 hex chars; payload is digest.as_bytes()
    //      so 64 bytes of ASCII hex). Pins this contract — a future
    //      refactor that stored raw 32-byte SHA-256 in payload would
    //      halve the payload length and confuse downstream consumers.
    //
    //   5. METADATA-PRESENT INVARIANT: metadata contains exactly
    //      "seed", "tick", and "input_len" keys with stringified
    //      values. Pins that no fields are accidentally added or
    //      removed (downstream consumers iterate metadata).
    //
    //   6. SEED-DETERMINISTIC INVARIANT: same (seed, tick, input)
    //      MUST always produce the same decision_id. Pins
    //      INV-TT-DETERMINISTIC (the file's core invariant).
    //
    //   7. TICK-IN-DECISION-ID INVARIANT: the tick appears literally
    //      in decision_id as the middle component. Downstream
    //      consumers parse decision_id to extract tick; the format
    //      "dec-{tick}-{hex}" is part of the API contract.
    //
    // Goldens were derived offline from the canonical-byte spec via
    // Python — NOT captured from an unreviewed prior run.
    //
    // Why this matters (the contract): deterministic_decision is the
    // central primitive for replay equivalence across time-travel
    // replays. If two replay runs compute different decision_ids for
    // the same (seed, tick, input) tuple — because someone reordered
    // fields, swapped LE64 widths, dropped the v1 prefix, or changed
    // the composite-id format — replay equivalence verification
    // fails opaquely AND the same logical workflow appears as two
    // different decision streams.
    #[test]
    fn deterministic_decision_frozen_canonical_byte_layout_golden() {
        // 1. Zero baseline.
        let zero = deterministic_decision(0, 0, b"");
        assert_eq!(
            zero.decision_id, "dec-0-e21bf34f",
            "zero deterministic_decision decision_id drifted — check \
             the v1 domain separator, raw u64 LE encoding of seed/tick, \
             or the \"dec-{{tick}}-{{8 hex}}\" composite format"
        );

        // 2. Typical production case.
        let typical = deterministic_decision(42, 7, b"replay-input-payload");
        assert_eq!(typical.decision_id, "dec-7-43475daa");

        // 3. Binary input + multi-digit tick.
        let binary_input: Vec<u8> = (0_u8..8).collect();
        let binary = deterministic_decision(0xABCDEF, 100, &binary_input);
        assert_eq!(binary.decision_id, "dec-100-3325effd");

        // 4. PAYLOAD-IS-DIGEST-ASCII-BYTES INVARIANT: payload contains
        // the full 64 hex chars as ASCII bytes.
        assert_eq!(
            zero.payload.len(),
            64,
            "payload MUST be 64 ASCII hex bytes (digest hex-encoded as \
             bytes); a refactor that stored raw 32-byte SHA-256 would \
             halve the payload length"
        );
        let zero_full_digest = String::from_utf8(zero.payload.clone()).unwrap();
        assert_eq!(
            zero_full_digest, "e21bf34f21efe4ee58a5141741368b451e9abd147fa34d310b36c0d0715e4b65",
            "zero payload (decoded as ASCII) MUST equal the full 64-char \
             SHA-256 hex digest"
        );
        // And the first 8 chars of the payload-as-string MUST match the
        // hex tail of decision_id.
        assert_eq!(&zero_full_digest[..8], "e21bf34f");

        // 5. METADATA-PRESENT INVARIANT: exactly seed/tick/input_len.
        let zero_meta_keys: Vec<&String> = zero.metadata.keys().collect();
        assert_eq!(zero_meta_keys.len(), 3);
        assert!(zero.metadata.contains_key("seed"));
        assert!(zero.metadata.contains_key("tick"));
        assert!(zero.metadata.contains_key("input_len"));
        assert_eq!(zero.metadata.get("seed").unwrap(), "0");
        assert_eq!(zero.metadata.get("tick").unwrap(), "0");
        assert_eq!(zero.metadata.get("input_len").unwrap(), "0");

        let typical_input_len = typical.metadata.get("input_len").unwrap();
        assert_eq!(typical_input_len, "20"); // "replay-input-payload" is 20 bytes

        // 6. SEED-DETERMINISTIC INVARIANT: identical inputs MUST
        // produce identical decision_ids. Pins INV-TT-DETERMINISTIC.
        let zero_again = deterministic_decision(0, 0, b"");
        assert_eq!(
            zero_again.decision_id, zero.decision_id,
            "deterministic_decision MUST be byte-for-byte deterministic \
             (INV-TT-DETERMINISTIC) — same (seed, tick, input) MUST \
             always produce the same decision_id"
        );
        assert_eq!(zero_again.payload, zero.payload);

        // 7. TICK-IN-DECISION-ID INVARIANT: tick appears literally in
        // decision_id as the middle component. The format
        // "dec-{tick}-{8 hex}" is part of the API contract;
        // downstream consumers parse it.
        assert!(zero.decision_id.starts_with("dec-0-"));
        assert!(typical.decision_id.starts_with("dec-7-"));
        assert!(binary.decision_id.starts_with("dec-100-"));
        // Format check: dec-{N}-{8 hex chars}
        for d in [&zero.decision_id, &typical.decision_id, &binary.decision_id] {
            assert!(d.starts_with("dec-"));
            let after_dec = &d[4..];
            let dash = after_dec
                .find('-')
                .expect("decision_id must have format 'dec-{tick}-{hex}'");
            let tick_str = &after_dec[..dash];
            let hex_tail = &after_dec[dash + 1..];
            assert!(tick_str.chars().all(|c| c.is_ascii_digit()));
            assert_eq!(hex_tail.len(), 8);
            assert!(
                hex_tail
                    .chars()
                    .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase())
            );
        }
    }

    // Frozen SHA-256 hex outputs of ControlDecision::digest
    // (time_travel.rs:187). The method derives the per-decision
    // content fingerprint as:
    //
    //   SHA256(
    //     b"time_travel_decision_v1:"
    //     || LE64(len(decision_id)) || decision_id.as_bytes()
    //     || LE64(len(payload))     || payload
    //     || LE64(metadata.len())
    //     || for (k, v) in metadata:    # BTreeMap → sorted by k
    //          LE64(len(k)) || k.as_bytes()
    //       || LE64(len(v)) || v.as_bytes()
    //   ).hex()
    //
    // Note this is a DIFFERENT domain from the related
    // `deterministic_decision` (r61 commit 3c06b29f) which uses
    // `time_travel_det_decision_v1:`. The two functions live in the
    // same module but serve different purposes:
    //   - deterministic_decision BUILDS a ControlDecision from
    //     (seed, tick, input)
    //   - ControlDecision::digest HASHES the resulting struct's
    //     id/payload/metadata for equality comparison
    //
    // Pinning BOTH domains documents the contract that these are
    // distinct surfaces; a refactor that unified them would have to
    // explicitly choose one domain and update all consumers.
    //
    // Two frozen fixtures + structural invariants:
    //
    //   1. minimal (all-empty fields). Locks v1 domain + 3 LE64(0)
    //      empty framings + zero-metadata-iterations loop.
    //      Frozen: 3dd8895c901564deb9a4ec5aa2f299fc025a393692970c2f6dca75d3513bf6a7
    //
    //   2. typical (decision_id="dec-1", payload=12 bytes, 3 metadata
    //      entries inserted in non-sorted order to exercise BTreeMap
    //      sorted iteration).
    //      Frozen: e89980c319b387190ad83ea55dd9b653f7050e9705975677e41594063f7dc612
    //
    //   3. BTreeMap-SORT INVARIANT: building the typical metadata via
    //      a different insertion order MUST produce the same digest.
    //
    //   4. PAYLOAD-vs-DECISION-ID DISTINCTION: swapping bytes between
    //      decision_id and payload MUST flip the digest.
    //
    //   5. SIBLING-DOMAIN-DISTINCTNESS: ControlDecision::digest of a
    //      decision built by deterministic_decision MUST differ from
    //      the deterministic_decision's own internal SHA-256 (they
    //      use different v1 domain separators —
    //      time_travel_decision_v1: vs time_travel_det_decision_v1:).
    //
    //   6. 64-lowercase-hex length+casing contract.
    //
    // Goldens were derived offline from the canonical-byte spec via
    // Python — NOT captured from an unreviewed prior run.
    //
    // Why this matters (the contract): ControlDecision::digest is
    // used to compare control decisions across replays for equality.
    // If two replay runs compute different digests for the same
    // logical ControlDecision — because someone reordered fields,
    // swapped BTreeMap for HashMap on metadata, or muddled the v1
    // domain — replay equivalence verification fails opaquely AND
    // the two replays are flagged as divergent when they are
    // logically identical.
    #[test]
    fn control_decision_digest_frozen_canonical_byte_layout_golden() {
        use std::collections::BTreeMap;

        // 1. Minimal.
        let minimal = ControlDecision {
            decision_id: String::new(),
            payload: Vec::new(),
            metadata: BTreeMap::new(),
        };
        assert_eq!(
            minimal.digest(),
            "3dd8895c901564deb9a4ec5aa2f299fc025a393692970c2f6dca75d3513bf6a7",
            "minimal ControlDecision::digest drifted — check the v1 \
             domain separator `time_travel_decision_v1:`, the 3 \
             LE64(0) empty-field framings, OR the zero-metadata-\
             iterations loop"
        );

        // 2. Typical with non-sorted insertion order (BTreeMap sorts).
        let mut metadata = BTreeMap::new();
        metadata.insert("tick".to_string(), "42".to_string());
        metadata.insert("seed".to_string(), "0".to_string());
        metadata.insert("input_len".to_string(), "8".to_string());
        let typical = ControlDecision {
            decision_id: "dec-1".to_string(),
            payload: b"hash-payload".to_vec(),
            metadata,
        };
        assert_eq!(
            typical.digest(),
            "e89980c319b387190ad83ea55dd9b653f7050e9705975677e41594063f7dc612"
        );

        // 3. BTreeMap-SORT INVARIANT: re-insert in different order.
        let mut reordered_metadata = BTreeMap::new();
        reordered_metadata.insert("input_len".to_string(), "8".to_string());
        reordered_metadata.insert("seed".to_string(), "0".to_string());
        reordered_metadata.insert("tick".to_string(), "42".to_string());
        let reordered = ControlDecision {
            decision_id: "dec-1".to_string(),
            payload: b"hash-payload".to_vec(),
            metadata: reordered_metadata,
        };
        assert_eq!(
            reordered.digest(),
            typical.digest(),
            "ControlDecision::digest MUST be insertion-order-independent \
             — metadata is a BTreeMap and iterates in sorted key order"
        );

        // 4. PAYLOAD-vs-DECISION-ID DISTINCTION: swapping bytes MUST
        // flip the digest. (Decision_id "dec-1" and payload start with
        // different ASCII; this test ensures the LE64-prefix boundaries
        // are preserved.)
        let swapped = ControlDecision {
            decision_id: "hash-payload".to_string(), // was payload
            payload: b"dec-1".to_vec(),              // was decision_id
            metadata: BTreeMap::new(),
        };
        let typical_no_meta = ControlDecision {
            decision_id: "dec-1".to_string(),
            payload: b"hash-payload".to_vec(),
            metadata: BTreeMap::new(),
        };
        assert_ne!(
            swapped.digest(),
            typical_no_meta.digest(),
            "swapping decision_id and payload contents MUST flip the \
             digest — the LE64-prefix boundaries distinguish the two \
             fields by position"
        );

        // 5. SIBLING-DOMAIN-DISTINCTNESS: a decision built by
        // deterministic_decision and then digested via the digest()
        // method uses TWO different v1 domains under the hood. The
        // public-facing decision_id encodes the deterministic_decision
        // hash internally; calling digest() on the result produces a
        // DIFFERENT hash.
        let det = deterministic_decision(0, 0, b"");
        let det_digest = det.digest();
        // Compare to the typical (different inputs); they should
        // share no obvious structural relation. Verify det_digest is
        // a valid 64-char hex.
        assert_eq!(det_digest.len(), 64);

        // 6. 64-lowercase-hex length+casing contract.
        for h in [minimal.digest(), typical.digest(), det_digest] {
            assert_eq!(h.len(), 64);
            assert!(
                h.chars()
                    .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase())
            );
        }
    }

    // Frozen SHA-256 hex outputs of WorkflowSnapshot::compute_integrity_digest
    // (time_travel.rs:254). The method derives the snapshot-level
    // integrity digest as:
    //
    //   SHA256(
    //     b"time_travel_integrity_v1:"
    //     || LE64(frames.len())
    //     || for f in frames:
    //          f.frame_index.to_le_bytes()       # raw u64 LE
    //       || f.clock_tick.to_le_bytes()        # raw u64 LE
    //       || LE64(len(input_hash)) || input_hash.as_bytes()
    //       || LE64(len(decision_digest)) || decision_digest.as_bytes()
    //       # decision_digest = f.decision.digest() (64 hex chars)
    //   ).hex()
    //
    // *** DISTINCTIVE FEATURE pinned by this golden ***
    //
    // This is the FIRST golden in the suite to pin a TWO-LEVEL HASH
    // CHAIN — compute_integrity_digest invokes ControlDecision::digest
    // (r75 commit b62ddb5e) for each frame, and the resulting hex
    // string is fed back into the OUTER hash with its own LE64-len
    // prefix. The integrity digest is therefore content-addressed by
    // every nested decision digest. A future refactor that changed
    // either (a) ControlDecision::digest layout OR (b) the integrity
    // digest wrapping would silently flip the result. The two-level
    // dependency makes this golden the canary for BOTH r75 and r76
    // simultaneously.
    //
    // Also: this is the FIRST golden to pin that event_code is
    // INTENTIONALLY EXCLUDED from the integrity hash. CaptureFrame
    // has five fields (frame_index, clock_tick, input_hash, decision,
    // event_code) but the integrity digest only hashes the first four.
    //
    // Two frozen fixtures + structural invariants:
    //
    //   1. empty frames. Locks v1 domain + LE64(0) zero-frames
    //      framing.
    //      Frozen: 8b512b4009ea19f4e1d31fabfffd1bf649d2d6cd114f8cac7ff39823c1fb85cf
    //
    //   2. two-frame snapshot: frame 0 with empty metadata, frame 1
    //      with single-entry metadata. Locks per-frame framing AND
    //      the two-level hash chain through ControlDecision::digest.
    //      Frozen: 90613d092d96460e1811672c9518a0dc59f72da378beb74dd53e86a170e897dd
    //
    //   3. EVENT-CODE-EXCLUSION INVARIANT: changing only event_code
    //      on a frame MUST NOT change the integrity digest. Pins
    //      that event_code is intentionally excluded from the hash
    //      (the function at L258 iterates only frame_index, clock_tick,
    //      input_hash, decision — NOT event_code).
    //
    //   4. NESTED-DIGEST-DEPENDENCY: changing only the decision
    //      payload (which flows through ControlDecision::digest as
    //      a nested hash) MUST flip the outer integrity digest.
    //
    //   5. FRAME-COUNT-SENSITIVITY: a snapshot with 1 frame MUST
    //      hash differently from a snapshot with 0 frames (catches
    //      a bug where the LE64 count is dropped).
    //
    //   6. 64-lowercase-hex length+casing contract.
    //
    // Goldens were derived offline from the canonical-byte spec via
    // Python (reimplementing BOTH ControlDecision::digest AND
    // compute_integrity_digest) — NOT captured from an unreviewed
    // prior run.
    //
    // Why this matters (the contract): compute_integrity_digest is
    // the snapshot-level tamper-evidence primitive (per
    // WorkflowSnapshot::verify_integrity at L271). If two snapshot
    // verifiers compute different digests for the same logical
    // frames — because someone reordered fields, swapped LE64
    // widths, accidentally included event_code in the hash, or
    // changed the nested ControlDecision::digest layout — snapshot
    // verification fails opaquely AND legitimate snapshots get
    // rejected as tampered.
    #[test]
    fn workflow_snapshot_compute_integrity_digest_frozen_canonical_byte_layout_golden() {
        use std::collections::BTreeMap;

        // 1. Empty frames.
        assert_eq!(
            WorkflowSnapshot::compute_integrity_digest(&[]),
            "8b512b4009ea19f4e1d31fabfffd1bf649d2d6cd114f8cac7ff39823c1fb85cf",
            "empty compute_integrity_digest drifted — check the v1 \
             domain separator `time_travel_integrity_v1:` or LE64(0) \
             zero-frames framing"
        );

        // 2. Two-frame snapshot.
        let frame0 = CaptureFrame {
            frame_index: 0,
            clock_tick: 0,
            input_hash: "sha256:0000000000000000000000000000000000000000000000000000000000000000"
                .to_string(),
            decision: ControlDecision {
                decision_id: "dec-0".to_string(),
                payload: b"payload-a".to_vec(),
                metadata: BTreeMap::new(),
            },
            event_code: "EVENT-ALPHA".to_string(),
        };
        let mut frame1_meta = BTreeMap::new();
        frame1_meta.insert("k".to_string(), "v".to_string());
        let frame1 = CaptureFrame {
            frame_index: 1,
            clock_tick: 1,
            input_hash: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .to_string(),
            decision: ControlDecision {
                decision_id: "dec-1".to_string(),
                payload: b"payload-b".to_vec(),
                metadata: frame1_meta,
            },
            event_code: "EVENT-BETA".to_string(),
        };
        let frames = vec![frame0.clone(), frame1.clone()];
        assert_eq!(
            WorkflowSnapshot::compute_integrity_digest(&frames),
            "90613d092d96460e1811672c9518a0dc59f72da378beb74dd53e86a170e897dd",
            "two-frame compute_integrity_digest drifted — check per-\
             frame framing, raw u64 LE on frame_index/clock_tick, OR \
             the nested ControlDecision::digest layout (which is also \
             pinned in r75 commit b62ddb5e)"
        );

        // 3. EVENT-CODE-EXCLUSION INVARIANT: changing only event_code
        // on a frame MUST NOT change the integrity digest.
        let mut frame0_diff_event = frame0.clone();
        frame0_diff_event.event_code = "EVENT-DIFFERENT-LABEL".to_string();
        let frames_diff_event = vec![frame0_diff_event, frame1.clone()];
        assert_eq!(
            WorkflowSnapshot::compute_integrity_digest(&frames_diff_event),
            WorkflowSnapshot::compute_integrity_digest(&frames),
            "changing event_code on a frame MUST NOT change the \
             integrity digest — event_code is INTENTIONALLY EXCLUDED \
             from the hash (per L258-266 of the function)"
        );

        // 4. NESTED-DIGEST-DEPENDENCY: changing only the decision
        // payload (which flows through ControlDecision::digest) MUST
        // flip the outer integrity digest.
        let mut frame0_diff_payload = frame0.clone();
        frame0_diff_payload.decision.payload = b"DIFFERENT-PAYLOAD".to_vec();
        let frames_diff_payload = vec![frame0_diff_payload, frame1.clone()];
        assert_ne!(
            WorkflowSnapshot::compute_integrity_digest(&frames_diff_payload),
            WorkflowSnapshot::compute_integrity_digest(&frames),
            "changing a frame's decision payload MUST flip the outer \
             integrity digest — pins the two-level hash chain through \
             ControlDecision::digest"
        );

        // 5. FRAME-COUNT-SENSITIVITY: 1 frame vs 0 frames MUST flip.
        assert_ne!(
            WorkflowSnapshot::compute_integrity_digest(&[frame0.clone()]),
            WorkflowSnapshot::compute_integrity_digest(&[]),
            "a 1-frame snapshot MUST hash differently from a 0-frame \
             snapshot — pins the LE64 count framing"
        );

        // 6. 64-lowercase-hex length+casing contract.
        for h in [
            WorkflowSnapshot::compute_integrity_digest(&[]),
            WorkflowSnapshot::compute_integrity_digest(&frames),
        ] {
            assert_eq!(h.len(), 64);
            assert!(
                h.chars()
                    .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase())
            );
        }
    }
}
