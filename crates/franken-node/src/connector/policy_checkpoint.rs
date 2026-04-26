//! bd-174: Policy checkpoint chain for product release channels.
//!
//! Provides a cryptographically-linked, append-only chain of policy checkpoints
//! across release channels (stable, beta, canary, custom). Each checkpoint
//! records the active policy hash, epoch, channel, and signer, and is linked
//! to its predecessor via a parent hash. The chain enforces monotonic sequencing,
//! parent-chain integrity, and canonical serialization for all hashing.
//!
//! # Invariants
//!
//! - INV-PCK-MONOTONIC: Sequence numbers are strictly monotonically increasing
//!   with no gaps.
//! - INV-PCK-PARENT-CHAIN: Every checkpoint's parent_hash matches its
//!   predecessor's checkpoint_hash.
//! - INV-PCK-HASH-INTEGRITY: checkpoint_hash is deterministically derived from
//!   the canonical serialization of all checkpoint fields.
//! - INV-PCK-APPEND-ONLY: The chain is strictly append-only.
//! - INV-PCK-CANONICAL-SER: All hashing uses canonical deterministic
//!   serialization (per bd-jjm).
//! - INV-PCK-MULTI-CHANNEL: Multiple release channels coexist in a single
//!   chain; policy_frontier() returns at most one checkpoint per channel.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::capacity_defaults::aliases::MAX_EVENTS;
use crate::security::constant_time;
const MAX_CHECKPOINTS: usize = 4096;

// ---------------------------------------------------------------------------
// Event codes
// ---------------------------------------------------------------------------

pub mod event_codes {
    /// Checkpoint created.
    pub const PCK_001_CHECKPOINT_CREATED: &str = "PCK-001";
    /// Chain verification completed.
    pub const PCK_002_CHECKPOINT_VERIFIED: &str = "PCK-002";
    /// Checkpoint rejected.
    pub const PCK_003_CHECKPOINT_REJECTED: &str = "PCK-003";
    /// Policy frontier queried.
    pub const PCK_004_CHECKPOINT_FRONTIER: &str = "PCK-004";
}

pub mod event_names {
    pub const CHECKPOINT_CREATED: &str = "CHECKPOINT_CREATED";
    pub const CHECKPOINT_VERIFIED: &str = "CHECKPOINT_VERIFIED";
    pub const CHECKPOINT_REJECTED: &str = "CHECKPOINT_REJECTED";
    pub const CHECKPOINT_FRONTIER: &str = "CHECKPOINT_FRONTIER";
}

// ---------------------------------------------------------------------------
// Error codes
// ---------------------------------------------------------------------------

pub mod error_codes {
    pub const CHECKPOINT_SEQ_VIOLATION: &str = "CHECKPOINT_SEQ_VIOLATION";
    pub const CHECKPOINT_PARENT_MISMATCH: &str = "CHECKPOINT_PARENT_MISMATCH";
    pub const CHECKPOINT_HASH_CHAIN_BREAK: &str = "CHECKPOINT_HASH_CHAIN_BREAK";
    pub const CHECKPOINT_EMPTY_CHAIN: &str = "CHECKPOINT_EMPTY_CHAIN";
    pub const CHECKPOINT_SERIALIZATION_ERROR: &str = "CHECKPOINT_SERIALIZATION_ERROR";
}

// ---------------------------------------------------------------------------
// ReleaseChannel
// ---------------------------------------------------------------------------

/// Product release channel identifier.
///
/// Covers the three standard channels plus a custom variant for
/// operator-defined channels.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ReleaseChannel {
    /// Production-ready general availability.
    Stable,
    /// Pre-release testing.
    Beta,
    /// Early-adopter experimental.
    Canary,
    /// Operator-defined channel.
    Custom(String),
}

impl ReleaseChannel {
    /// Returns a canonical string label for this channel.
    pub fn label(&self) -> String {
        match self {
            Self::Stable => "stable".to_string(),
            Self::Beta => "beta".to_string(),
            Self::Canary => "canary".to_string(),
            Self::Custom(name) => format!("custom:{name}"),
        }
    }
}

impl fmt::Display for ReleaseChannel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.label())
    }
}

// ---------------------------------------------------------------------------
// CheckpointChainError
// ---------------------------------------------------------------------------

/// Errors from policy checkpoint chain operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckpointChainError {
    /// Sequence number is non-monotonic or has a gap.
    SequenceViolation { expected: u64, actual: u64 },
    /// parent_hash does not match current chain head.
    ParentMismatch {
        expected: Option<String>,
        actual: Option<String>,
    },
    /// Hash chain integrity break detected during verification.
    HashChainBreak { index: usize, reason: String },
    /// Operation requires a non-empty chain.
    EmptyChain,
    /// Canonical serialization failure.
    SerializationFailure(String),
}

impl CheckpointChainError {
    /// Machine-readable error code.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::SequenceViolation { .. } => error_codes::CHECKPOINT_SEQ_VIOLATION,
            Self::ParentMismatch { .. } => error_codes::CHECKPOINT_PARENT_MISMATCH,
            Self::HashChainBreak { .. } => error_codes::CHECKPOINT_HASH_CHAIN_BREAK,
            Self::EmptyChain => error_codes::CHECKPOINT_EMPTY_CHAIN,
            Self::SerializationFailure(_) => error_codes::CHECKPOINT_SERIALIZATION_ERROR,
        }
    }
}

impl fmt::Display for CheckpointChainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SequenceViolation { expected, actual } => {
                write!(
                    f,
                    "{}: expected sequence {expected}, got {actual}",
                    self.code()
                )
            }
            Self::ParentMismatch { expected, actual } => {
                write!(
                    f,
                    "{}: expected parent {:?}, got {:?}",
                    self.code(),
                    expected,
                    actual
                )
            }
            Self::HashChainBreak { index, reason } => {
                write!(f, "{}: chain break at index {index}: {reason}", self.code())
            }
            Self::EmptyChain => write!(f, "{}: chain is empty", self.code()),
            Self::SerializationFailure(detail) => {
                write!(f, "{}: {detail}", self.code())
            }
        }
    }
}

impl std::error::Error for CheckpointChainError {}

// ---------------------------------------------------------------------------
// CheckpointChainEvent
// ---------------------------------------------------------------------------

/// Structured audit event emitted by chain operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckpointChainEvent {
    pub event_code: String,
    pub event_name: String,
    pub trace_id: String,
    pub epoch_id: u64,
    pub sequence: u64,
    pub channel: String,
    pub detail: String,
}

// ---------------------------------------------------------------------------
// PolicyCheckpoint
// ---------------------------------------------------------------------------

/// A single policy checkpoint in the chain.
///
/// Contains all fields required by the bd-174 specification:
/// sequence, epoch_id, channel, policy_hash, parent_hash,
/// timestamp, signer, and checkpoint_hash.
///
/// # INV-PCK-HASH-INTEGRITY
/// `checkpoint_hash` is deterministically derived from canonical
/// serialization of all other fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyCheckpoint {
    /// Monotonically increasing sequence number (per chain).
    pub sequence: u64,
    /// Epoch identifier for grouping checkpoints.
    pub epoch_id: u64,
    /// Which release channel this checkpoint covers.
    pub channel: ReleaseChannel,
    /// SHA-256 hash over the canonically-serialized policy document.
    pub policy_hash: String,
    /// Hash of the previous checkpoint (`None` for genesis).
    pub parent_hash: Option<String>,
    /// Unix timestamp (seconds) when the checkpoint was created.
    pub timestamp: u64,
    /// Identity of the entity that created this checkpoint.
    pub signer: String,
    /// Content-addressed hash of this checkpoint's canonical form.
    pub checkpoint_hash: String,
}

impl PolicyCheckpoint {
    /// Compute the canonical hash for a checkpoint from its fields.
    ///
    /// # INV-PCK-CANONICAL-SER
    /// Uses deterministic field ordering: sequence, epoch_id, channel,
    /// policy_hash, parent_hash, timestamp, signer. All values are
    /// encoded in a fixed canonical byte representation.
    fn compute_hash(
        sequence: u64,
        epoch_id: u64,
        channel: &ReleaseChannel,
        policy_hash: &str,
        parent_hash: Option<&str>,
        timestamp: u64,
        signer: &str,
    ) -> String {
        let mut hasher = Sha256::new();
        // Domain separation tag for policy checkpoints
        hasher.update(b"policy_checkpoint_hash_v1:");
        hasher.update(sequence.to_be_bytes());
        hasher.update(epoch_id.to_be_bytes());
        // Length-prefixed variable-length fields prevent collision via
        // embedded null bytes or field-boundary ambiguity.
        let channel_label = channel.label();
        hasher.update(len_to_u64(channel_label.len()).to_le_bytes());
        hasher.update(channel_label.as_bytes());
        hasher.update(len_to_u64(policy_hash.len()).to_le_bytes());
        hasher.update(policy_hash.as_bytes());
        let parent = parent_hash.unwrap_or("GENESIS");
        hasher.update(len_to_u64(parent.len()).to_le_bytes());
        hasher.update(parent.as_bytes());
        hasher.update(timestamp.to_be_bytes());
        hasher.update(len_to_u64(signer.len()).to_le_bytes());
        hasher.update(signer.as_bytes());
        hex::encode(hasher.finalize())
    }

    /// Verify that the stored checkpoint_hash matches a fresh computation
    /// from the checkpoint's fields.
    #[must_use]
    pub fn verify_hash(&self) -> bool {
        let computed = Self::compute_hash(
            self.sequence,
            self.epoch_id,
            &self.channel,
            &self.policy_hash,
            self.parent_hash.as_deref(),
            self.timestamp,
            &self.signer,
        );
        constant_time::ct_eq_bytes(computed.as_bytes(), self.checkpoint_hash.as_bytes())
    }

    /// Short hash prefix for logging (first 16 hex chars).
    #[must_use]
    pub fn short_hash(&self) -> &str {
        if self.checkpoint_hash.len() >= 16 {
            &self.checkpoint_hash[..16]
        } else {
            &self.checkpoint_hash
        }
    }
}

// ---------------------------------------------------------------------------
// PolicyCheckpointChain
// ---------------------------------------------------------------------------

/// Append-only chain of policy checkpoints with integrity enforcement.
///
/// Enforces INV-PCK-MONOTONIC, INV-PCK-PARENT-CHAIN, INV-PCK-HASH-INTEGRITY,
/// INV-PCK-APPEND-ONLY, INV-PCK-CANONICAL-SER, and INV-PCK-MULTI-CHANNEL.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyCheckpointChain {
    checkpoints: Vec<PolicyCheckpoint>,
    head_hash: Option<String>,
    next_seq: u64,
    events: Vec<CheckpointChainEvent>,
}

impl PolicyCheckpointChain {
    fn emit_rejection_event(
        &mut self,
        trace_id: &str,
        epoch_id: u64,
        sequence: u64,
        channel: &ReleaseChannel,
        detail: String,
    ) {
        push_bounded(
            &mut self.events,
            CheckpointChainEvent {
                event_code: event_codes::PCK_003_CHECKPOINT_REJECTED.to_string(),
                event_name: event_names::CHECKPOINT_REJECTED.to_string(),
                trace_id: trace_id.to_string(),
                epoch_id,
                sequence,
                channel: channel.label(),
                detail,
            },
            MAX_EVENTS,
        );
    }

    fn current_chain_violation(&self) -> Option<(usize, String)> {
        if let Err((index, error)) = self.verify_chain() {
            let reason = match error {
                CheckpointChainError::HashChainBreak { reason, .. } => reason,
                other => other.to_string(),
            };
            return Some((index, reason));
        }

        match self.checkpoints.last() {
            Some(last) => {
                let expected_head = Some(last.checkpoint_hash.as_str());
                let actual_head = self.head_hash.as_deref();
                let head_matches = match (expected_head, actual_head) {
                    (Some(expected), Some(actual)) => {
                        constant_time::ct_eq_bytes(expected.as_bytes(), actual.as_bytes())
                    }
                    (None, None) => true,
                    _ => false,
                };
                if !head_matches {
                    return Some((
                        self.checkpoints.len().saturating_sub(1),
                        format!(
                            "head_hash mismatch: expected {:?}, got {:?}",
                            expected_head, actual_head
                        ),
                    ));
                }

                let expected_next = len_to_u64(self.checkpoints.len());
                if self.next_seq != expected_next {
                    return Some((
                        self.checkpoints.len(),
                        format!(
                            "next_seq mismatch: expected {expected_next}, got {}",
                            self.next_seq
                        ),
                    ));
                }
            }
            None => {
                if self.head_hash.is_some() {
                    return Some((
                        0,
                        format!(
                            "head_hash mismatch: expected {:?}, got {:?}",
                            Option::<&str>::None,
                            self.head_hash.as_deref()
                        ),
                    ));
                }
                if self.next_seq != 0 {
                    return Some((
                        0,
                        format!("next_seq mismatch: expected 0, got {}", self.next_seq),
                    ));
                }
            }
        }

        None
    }

    fn reject_if_chain_invalid(
        &mut self,
        trace_id: &str,
        epoch_id: u64,
        sequence: u64,
        channel: &ReleaseChannel,
    ) -> Result<(), CheckpointChainError> {
        if let Some((index, reason)) = self.current_chain_violation() {
            self.emit_rejection_event(
                trace_id,
                epoch_id,
                sequence,
                channel,
                format!(
                    "CHECKPOINT_HASH_CHAIN_BREAK: existing chain invalid at index {index}: {reason}"
                ),
            );
            return Err(CheckpointChainError::HashChainBreak { index, reason });
        }

        Ok(())
    }

    /// Create a new empty chain.
    #[must_use]
    pub fn new() -> Self {
        Self {
            checkpoints: Vec::new(),
            head_hash: None,
            next_seq: 0,
            events: Vec::new(),
        }
    }

    /// Append a new checkpoint to the chain.
    ///
    /// # INV-PCK-MONOTONIC
    /// The checkpoint is assigned the next monotonic sequence number.
    ///
    /// # INV-PCK-PARENT-CHAIN
    /// The parent_hash is set to the current chain head hash.
    ///
    /// # Errors
    ///
    /// This method does not return errors under normal operation because it
    /// automatically assigns the correct sequence and parent_hash. The
    /// returned reference points to the newly appended checkpoint.
    pub fn create_checkpoint(
        &mut self,
        epoch_id: u64,
        channel: ReleaseChannel,
        policy_hash: &str,
        signer: &str,
        trace_id: &str,
    ) -> Result<&PolicyCheckpoint, CheckpointChainError> {
        self.reject_if_chain_invalid(trace_id, epoch_id, self.next_seq, &channel)?;
        if let Err(err) = validate_checkpoint_fields(&channel, policy_hash, signer, trace_id) {
            self.emit_rejection_event(trace_id, epoch_id, self.next_seq, &channel, err.to_string());
            return Err(err);
        }

        let sequence = self.next_seq;
        let parent_hash = self.head_hash.clone();
        let timestamp = now_unix_secs();

        let checkpoint_hash = PolicyCheckpoint::compute_hash(
            sequence,
            epoch_id,
            &channel,
            policy_hash,
            parent_hash.as_deref(),
            timestamp,
            signer,
        );

        let checkpoint = PolicyCheckpoint {
            sequence,
            epoch_id,
            channel: channel.clone(),
            policy_hash: policy_hash.to_string(),
            parent_hash,
            timestamp,
            signer: signer.to_string(),
            checkpoint_hash: checkpoint_hash.clone(),
        };

        // Cannot use push_bounded here: evicting oldest checkpoints would
        // shift indices so that cp.sequence != enumerate-index, violating
        // INV-PCK-MONOTONIC and breaking verify_chain(). Reject at capacity.
        if self.checkpoints.len() >= MAX_CHECKPOINTS {
            self.emit_rejection_event(
                trace_id,
                epoch_id,
                sequence,
                &channel,
                "CHECKPOINT_HASH_CHAIN_BREAK: chain at capacity (MAX_CHECKPOINTS reached)"
                    .to_string(),
            );
            return Err(CheckpointChainError::HashChainBreak {
                index: MAX_CHECKPOINTS,
                reason: "chain at capacity (MAX_CHECKPOINTS reached)".to_string(),
            });
        }
        self.checkpoints.push(checkpoint);
        self.head_hash = Some(checkpoint_hash);
        self.next_seq = sequence.saturating_add(1);

        push_bounded(
            &mut self.events,
            CheckpointChainEvent {
                event_code: event_codes::PCK_001_CHECKPOINT_CREATED.to_string(),
                event_name: event_names::CHECKPOINT_CREATED.to_string(),
                trace_id: trace_id.to_string(),
                epoch_id,
                sequence,
                channel: channel.label(),
                detail: format!(
                    "checkpoint created: seq={sequence} epoch={epoch_id} channel={channel}"
                ),
            },
            MAX_EVENTS,
        );

        self.checkpoints
            .last()
            .ok_or_else(|| CheckpointChainError::HashChainBreak {
                index: self.checkpoints.len(),
                reason: "checkpoint append invariant violated: chain empty after push".to_string(),
            })
    }

    /// Append a pre-built checkpoint, enforcing sequence and parent-chain
    /// invariants.
    ///
    /// # INV-PCK-MONOTONIC
    /// The checkpoint's sequence must equal `self.next_seq`.
    ///
    /// # INV-PCK-PARENT-CHAIN
    /// The checkpoint's parent_hash must match `self.head_hash`.
    ///
    /// # Errors
    ///
    /// Returns `SequenceViolation` if the sequence is wrong, or
    /// `ParentMismatch` if the parent_hash is wrong, or `HashChainBreak`
    /// if the checkpoint hash does not match canonical serialization.
    pub fn append_checkpoint(
        &mut self,
        checkpoint: PolicyCheckpoint,
        trace_id: &str,
    ) -> Result<&PolicyCheckpoint, CheckpointChainError> {
        self.reject_if_chain_invalid(
            trace_id,
            checkpoint.epoch_id,
            checkpoint.sequence,
            &checkpoint.channel,
        )?;
        if let Err(err) = validate_checkpoint_fields(
            &checkpoint.channel,
            &checkpoint.policy_hash,
            &checkpoint.signer,
            trace_id,
        ) {
            self.emit_rejection_event(
                trace_id,
                checkpoint.epoch_id,
                checkpoint.sequence,
                &checkpoint.channel,
                err.to_string(),
            );
            return Err(err);
        }

        // INV-PCK-MONOTONIC
        if checkpoint.sequence != self.next_seq {
            self.emit_rejection_event(
                trace_id,
                checkpoint.epoch_id,
                checkpoint.sequence,
                &checkpoint.channel,
                format!(
                    "CHECKPOINT_SEQ_VIOLATION: expected={}, actual={}",
                    self.next_seq, checkpoint.sequence
                ),
            );
            return Err(CheckpointChainError::SequenceViolation {
                expected: self.next_seq,
                actual: checkpoint.sequence,
            });
        }

        // INV-PCK-PARENT-CHAIN
        let parent_match = match (&checkpoint.parent_hash, &self.head_hash) {
            (Some(a), Some(b)) => constant_time::ct_eq_bytes(a.as_bytes(), b.as_bytes()),
            (None, None) => true,
            _ => false,
        };
        if !parent_match {
            self.emit_rejection_event(
                trace_id,
                checkpoint.epoch_id,
                checkpoint.sequence,
                &checkpoint.channel,
                format!(
                    "CHECKPOINT_PARENT_MISMATCH: expected={:?}, actual={:?}",
                    self.head_hash, checkpoint.parent_hash
                ),
            );
            return Err(CheckpointChainError::ParentMismatch {
                expected: self.head_hash.clone(),
                actual: checkpoint.parent_hash,
            });
        }

        if !checkpoint.verify_hash() {
            self.emit_rejection_event(
                trace_id,
                checkpoint.epoch_id,
                checkpoint.sequence,
                &checkpoint.channel,
                "CHECKPOINT_HASH_CHAIN_BREAK: checkpoint_hash does not match canonical serialization"
                    .to_string(),
            );
            return Err(CheckpointChainError::HashChainBreak {
                index: checkpoint.sequence as usize,
                reason: "checkpoint_hash does not match canonical serialization".to_string(),
            });
        }

        let hash = checkpoint.checkpoint_hash.clone();
        let seq = checkpoint.sequence;
        let epoch = checkpoint.epoch_id;
        let channel_label = checkpoint.channel.label();

        // Cannot use push_bounded: same INV-PCK-MONOTONIC reasoning as
        // create_checkpoint — eviction breaks verify_chain().
        if self.checkpoints.len() >= MAX_CHECKPOINTS {
            self.emit_rejection_event(
                trace_id,
                checkpoint.epoch_id,
                checkpoint.sequence,
                &checkpoint.channel,
                "CHECKPOINT_HASH_CHAIN_BREAK: chain at capacity (MAX_CHECKPOINTS reached)"
                    .to_string(),
            );
            return Err(CheckpointChainError::HashChainBreak {
                index: MAX_CHECKPOINTS,
                reason: "chain at capacity (MAX_CHECKPOINTS reached)".to_string(),
            });
        }
        self.checkpoints.push(checkpoint);
        self.head_hash = Some(hash);
        self.next_seq = seq.saturating_add(1);

        push_bounded(
            &mut self.events,
            CheckpointChainEvent {
                event_code: event_codes::PCK_001_CHECKPOINT_CREATED.to_string(),
                event_name: event_names::CHECKPOINT_CREATED.to_string(),
                trace_id: trace_id.to_string(),
                epoch_id: epoch,
                sequence: seq,
                channel: channel_label,
                detail: format!("checkpoint appended: seq={seq} epoch={epoch}"),
            },
            MAX_EVENTS,
        );

        self.checkpoints
            .last()
            .ok_or_else(|| CheckpointChainError::HashChainBreak {
                index: self.checkpoints.len(),
                reason: "checkpoint append invariant violated: chain empty after push".to_string(),
            })
    }

    /// Verify the entire chain in O(n) time.
    ///
    /// # INV-PCK-HASH-INTEGRITY
    /// Re-computes each checkpoint's hash and verifies it matches.
    ///
    /// # INV-PCK-PARENT-CHAIN
    /// Verifies that each checkpoint's parent_hash matches its predecessor.
    ///
    /// # INV-PCK-MONOTONIC
    /// Verifies that sequence numbers are strictly monotonically increasing
    /// starting from 0 with no gaps.
    ///
    /// Returns `Ok(chain_length)` on success, or
    /// `Err((violation_index, error))` on the first violation.
    pub fn verify_chain(&self) -> Result<usize, (usize, CheckpointChainError)> {
        let mut prev_hash: Option<&str> = None;

        for (i, cp) in self.checkpoints.iter().enumerate() {
            // INV-PCK-MONOTONIC: sequence must equal index
            if cp.sequence != i as u64 {
                return Err((
                    i,
                    CheckpointChainError::HashChainBreak {
                        index: i,
                        reason: format!("sequence mismatch: expected {}, got {}", i, cp.sequence),
                    },
                ));
            }

            // INV-PCK-PARENT-CHAIN: parent_hash must match predecessor
            let expected_parent = prev_hash;
            let actual_parent = cp.parent_hash.as_deref();
            let parent_match = match (expected_parent, actual_parent) {
                (Some(a), Some(b)) => constant_time::ct_eq_bytes(a.as_bytes(), b.as_bytes()),
                (None, None) => true,
                _ => false,
            };
            if !parent_match {
                return Err((
                    i,
                    CheckpointChainError::HashChainBreak {
                        index: i,
                        reason: format!(
                            "parent_hash mismatch: expected {:?}, got {:?}",
                            expected_parent, actual_parent
                        ),
                    },
                ));
            }

            // INV-PCK-HASH-INTEGRITY: recompute and compare
            if !cp.verify_hash() {
                return Err((
                    i,
                    CheckpointChainError::HashChainBreak {
                        index: i,
                        reason: "checkpoint_hash does not match recomputed hash".to_string(),
                    },
                ));
            }

            prev_hash = Some(&cp.checkpoint_hash);
        }

        Ok(self.checkpoints.len())
    }

    /// Return the most recent checkpoint for a given release channel.
    ///
    /// # INV-PCK-MULTI-CHANNEL
    /// Scans the chain in reverse to find the latest checkpoint matching
    /// the requested channel.
    #[must_use]
    pub fn latest_for_channel(&self, channel: &ReleaseChannel) -> Option<&PolicyCheckpoint> {
        self.checkpoints
            .iter()
            .rev()
            .find(|cp| &cp.channel == channel)
    }

    /// Return the latest checkpoint per channel (the policy frontier).
    ///
    /// Used by downstream bd-2ms for divergence detection.
    ///
    /// # INV-PCK-MULTI-CHANNEL
    /// Returns at most one checkpoint per distinct channel.
    #[must_use]
    pub fn policy_frontier(&self) -> Vec<(ReleaseChannel, &PolicyCheckpoint)> {
        let mut frontier: BTreeMap<String, (ReleaseChannel, &PolicyCheckpoint)> = BTreeMap::new();
        for cp in &self.checkpoints {
            let key = cp.channel.label();
            frontier.insert(key, (cp.channel.clone(), cp));
        }
        let mut result: Vec<(ReleaseChannel, &PolicyCheckpoint)> = frontier.into_values().collect();
        result.sort_by_key(|(_, cp)| cp.sequence);
        result
    }

    /// Number of checkpoints in the chain.
    #[must_use]
    pub fn len(&self) -> usize {
        self.checkpoints.len()
    }

    /// Returns `true` if the chain has no checkpoints.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.checkpoints.is_empty()
    }

    /// Read-only access to the checkpoint list.
    #[must_use]
    pub fn checkpoints(&self) -> &[PolicyCheckpoint] {
        &self.checkpoints
    }

    /// Read-only access to the event log.
    #[must_use]
    pub fn events(&self) -> &[CheckpointChainEvent] {
        &self.events
    }

    /// The hash of the current chain head (latest checkpoint).
    #[must_use]
    pub fn head_hash(&self) -> Option<&str> {
        self.head_hash.as_deref()
    }

    /// The next expected sequence number.
    #[must_use]
    pub fn next_seq(&self) -> u64 {
        self.next_seq
    }

    /// Distinct channels that have at least one checkpoint.
    #[must_use]
    pub fn channels(&self) -> Vec<ReleaseChannel> {
        let mut seen: BTreeMap<String, ReleaseChannel> = BTreeMap::new();
        for cp in &self.checkpoints {
            seen.entry(cp.channel.label())
                .or_insert_with(|| cp.channel.clone());
        }
        let mut channels: Vec<ReleaseChannel> = seen.into_values().collect();
        channels.sort_by_key(|c| c.label());
        channels
    }

    /// Tamper with a checkpoint's policy_hash for testing purposes.
    /// This is only available in test builds.
    #[cfg(test)]
    pub fn tamper_policy_hash(&mut self, index: usize, new_hash: &str) {
        if let Some(cp) = self.checkpoints.get_mut(index) {
            cp.policy_hash = new_hash.to_string();
        }
    }

    /// Tamper with a checkpoint's checkpoint_hash for testing purposes.
    #[cfg(test)]
    pub fn tamper_checkpoint_hash(&mut self, index: usize, new_hash: &str) {
        if let Some(cp) = self.checkpoints.get_mut(index) {
            cp.checkpoint_hash = new_hash.to_string();
        }
    }

    /// Tamper with a checkpoint's parent_hash for testing purposes.
    #[cfg(test)]
    pub fn tamper_parent_hash(&mut self, index: usize, new_hash: Option<String>) {
        if let Some(cp) = self.checkpoints.get_mut(index) {
            cp.parent_hash = new_hash;
        }
    }

    /// Tamper with a checkpoint's sequence for testing purposes.
    #[cfg(test)]
    pub fn tamper_sequence(&mut self, index: usize, new_seq: u64) {
        if let Some(cp) = self.checkpoints.get_mut(index) {
            cp.sequence = new_seq;
        }
    }

    /// Tamper with the cached chain head hash for testing purposes.
    #[cfg(test)]
    pub fn tamper_head_hash(&mut self, new_head_hash: Option<String>) {
        self.head_hash = new_head_hash;
    }

    /// Tamper with the cached next sequence number for testing purposes.
    #[cfg(test)]
    pub fn tamper_next_seq(&mut self, new_next_seq: u64) {
        self.next_seq = new_next_seq;
    }
}

impl Default for PolicyCheckpointChain {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn validate_canonical_nonempty_field(
    field_name: &str,
    value: &str,
) -> Result<(), CheckpointChainError> {
    if value.trim().is_empty() {
        return Err(CheckpointChainError::SerializationFailure(format!(
            "{field_name} must be non-empty"
        )));
    }
    if value.trim() != value {
        return Err(CheckpointChainError::SerializationFailure(format!(
            "{field_name} must not contain surrounding whitespace"
        )));
    }
    if value.chars().any(char::is_control) {
        return Err(CheckpointChainError::SerializationFailure(format!(
            "{field_name} must not contain control characters"
        )));
    }
    Ok(())
}

fn validate_release_channel(channel: &ReleaseChannel) -> Result<(), CheckpointChainError> {
    if let ReleaseChannel::Custom(name) = channel {
        validate_canonical_nonempty_field("custom channel", name)?;
    }
    Ok(())
}

fn validate_checkpoint_fields(
    channel: &ReleaseChannel,
    policy_hash: &str,
    signer: &str,
    trace_id: &str,
) -> Result<(), CheckpointChainError> {
    validate_release_channel(channel)?;
    validate_canonical_nonempty_field("policy_hash", policy_hash)?;
    validate_canonical_nonempty_field("signer", signer)?;
    validate_canonical_nonempty_field("trace_id", trace_id)?;
    Ok(())
}

fn len_to_u64(len: usize) -> u64 {
    u64::try_from(len).unwrap_or(u64::MAX)
}

fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Compute SHA-256 hex digest of arbitrary data.
pub fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"policy_checkpoint_generic_v1:");
    hasher.update(data);
    hex::encode(hasher.finalize())
}

// ---------------------------------------------------------------------------
// Bounded push helper
// ---------------------------------------------------------------------------

fn push_bounded<T>(items: &mut Vec<T>, item: T, cap: usize) {
    if cap == 0 {
        items.clear();
        return;
    }

    if items.len() >= cap {
        let overflow = items.len().saturating_sub(cap).saturating_add(1);
        items.drain(0..overflow);
    }
    items.push(item);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn same_len_tamper(value: &str) -> String {
        let mut bytes = value.as_bytes().to_vec();
        if let Some(first) = bytes.first_mut() {
            *first = if *first == b'0' { b'1' } else { b'0' };
        } else {
            bytes.push(b'0');
        }
        String::from_utf8(bytes).expect("test hashes are ASCII")
    }

    fn assert_create_checkpoint_input_rejected(
        channel: ReleaseChannel,
        policy_hash: &str,
        signer: &str,
        trace_id: &str,
        expected_detail: &str,
    ) {
        let mut chain = PolicyCheckpointChain::new();
        let err = chain
            .create_checkpoint(1, channel, policy_hash, signer, trace_id)
            .expect_err("invalid checkpoint input must be rejected");

        assert_eq!(err.code(), error_codes::CHECKPOINT_SERIALIZATION_ERROR);
        assert!(err.to_string().contains(expected_detail));
        assert!(chain.is_empty());
        assert_eq!(chain.next_seq(), 0);
        assert!(chain.head_hash().is_none());

        let events = chain.events();
        assert_eq!(events.len(), 1);
        let rejection = &events[0];
        assert_eq!(
            rejection.event_code,
            event_codes::PCK_003_CHECKPOINT_REJECTED
        );
        assert_eq!(rejection.event_name, event_names::CHECKPOINT_REJECTED);
        assert_eq!(rejection.sequence, 0);
        assert!(rejection.detail.contains(expected_detail));
    }

    fn checkpoint_for_append(
        chain: &PolicyCheckpointChain,
        channel: ReleaseChannel,
        policy_hash: &str,
        signer: &str,
    ) -> PolicyCheckpoint {
        let sequence = chain.next_seq();
        let epoch_id = 2;
        let parent_hash = chain.head_hash().map(str::to_string);
        let timestamp = 2000;
        let checkpoint_hash = PolicyCheckpoint::compute_hash(
            sequence,
            epoch_id,
            &channel,
            policy_hash,
            parent_hash.as_deref(),
            timestamp,
            signer,
        );
        PolicyCheckpoint {
            sequence,
            epoch_id,
            channel,
            policy_hash: policy_hash.to_string(),
            parent_hash,
            timestamp,
            signer: signer.to_string(),
            checkpoint_hash,
        }
    }

    fn assert_append_checkpoint_input_rejected(
        channel: ReleaseChannel,
        policy_hash: &str,
        signer: &str,
        trace_id: &str,
        expected_detail: &str,
    ) {
        let mut chain = PolicyCheckpointChain::new();
        let original_head = chain
            .create_checkpoint(
                1,
                ReleaseChannel::Stable,
                "seed-policy",
                "alice",
                "seed-trace",
            )
            .expect("seed checkpoint")
            .checkpoint_hash
            .clone();
        let checkpoint = checkpoint_for_append(&chain, channel, policy_hash, signer);
        let starting_events = chain.events().len();

        let err = chain
            .append_checkpoint(checkpoint, trace_id)
            .expect_err("invalid checkpoint append input must be rejected");

        assert_eq!(err.code(), error_codes::CHECKPOINT_SERIALIZATION_ERROR);
        assert!(err.to_string().contains(expected_detail));
        assert_eq!(chain.len(), 1);
        assert_eq!(chain.next_seq(), 1);
        assert_eq!(chain.head_hash(), Some(original_head.as_str()));

        let rejection = chain
            .events()
            .last()
            .expect("invalid append should emit a rejection event");
        assert_eq!(chain.events().len(), starting_events + 1);
        assert_eq!(
            rejection.event_code,
            event_codes::PCK_003_CHECKPOINT_REJECTED
        );
        assert_eq!(rejection.event_name, event_names::CHECKPOINT_REJECTED);
        assert!(rejection.detail.contains(expected_detail));
    }

    // ── ReleaseChannel tests ─────────────────────────────────────────

    #[test]
    fn test_release_channel_labels() {
        assert_eq!(ReleaseChannel::Stable.label(), "stable");
        assert_eq!(ReleaseChannel::Beta.label(), "beta");
        assert_eq!(ReleaseChannel::Canary.label(), "canary");
        assert_eq!(
            ReleaseChannel::Custom("nightly".into()).label(),
            "custom:nightly"
        );
    }

    #[test]
    fn test_release_channel_display() {
        assert_eq!(format!("{}", ReleaseChannel::Stable), "stable");
        assert_eq!(
            format!("{}", ReleaseChannel::Custom("x".into())),
            "custom:x"
        );
    }

    #[test]
    fn test_release_channel_equality() {
        assert_eq!(ReleaseChannel::Stable, ReleaseChannel::Stable);
        assert_ne!(ReleaseChannel::Stable, ReleaseChannel::Beta);
        assert_eq!(
            ReleaseChannel::Custom("a".into()),
            ReleaseChannel::Custom("a".into())
        );
        assert_ne!(
            ReleaseChannel::Custom("a".into()),
            ReleaseChannel::Custom("b".into())
        );
    }

    #[test]
    fn test_release_channel_deserialize_rejects_unknown_variant() {
        let result: Result<ReleaseChannel, _> = serde_json::from_str(r#""nightly""#);

        assert!(result.is_err());
    }

    // ── CheckpointChainError tests ───────────────────────────────────

    #[test]
    fn test_error_codes() {
        let e1 = CheckpointChainError::SequenceViolation {
            expected: 0,
            actual: 5,
        };
        assert_eq!(e1.code(), "CHECKPOINT_SEQ_VIOLATION");

        let e2 = CheckpointChainError::ParentMismatch {
            expected: None,
            actual: Some("abc".into()),
        };
        assert_eq!(e2.code(), "CHECKPOINT_PARENT_MISMATCH");

        let e3 = CheckpointChainError::HashChainBreak {
            index: 3,
            reason: "mismatch".into(),
        };
        assert_eq!(e3.code(), "CHECKPOINT_HASH_CHAIN_BREAK");

        let e4 = CheckpointChainError::EmptyChain;
        assert_eq!(e4.code(), "CHECKPOINT_EMPTY_CHAIN");

        let e5 = CheckpointChainError::SerializationFailure("bad".into());
        assert_eq!(e5.code(), "CHECKPOINT_SERIALIZATION_ERROR");
    }

    #[test]
    fn test_error_display() {
        let e = CheckpointChainError::SequenceViolation {
            expected: 3,
            actual: 7,
        };
        let s = e.to_string();
        assert!(s.contains("CHECKPOINT_SEQ_VIOLATION"));
        assert!(s.contains("expected sequence 3"));
        assert!(s.contains("got 7"));
    }

    // ── PolicyCheckpoint tests ───────────────────────────────────────

    #[test]
    fn test_checkpoint_hash_deterministic() {
        let h1 = PolicyCheckpoint::compute_hash(
            0,
            1,
            &ReleaseChannel::Stable,
            "abc123",
            None,
            1000,
            "alice",
        );
        let h2 = PolicyCheckpoint::compute_hash(
            0,
            1,
            &ReleaseChannel::Stable,
            "abc123",
            None,
            1000,
            "alice",
        );
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64);
    }

    #[test]
    fn test_checkpoint_hash_varies_with_sequence() {
        let h1 =
            PolicyCheckpoint::compute_hash(0, 1, &ReleaseChannel::Stable, "abc", None, 1000, "a");
        let h2 =
            PolicyCheckpoint::compute_hash(1, 1, &ReleaseChannel::Stable, "abc", None, 1000, "a");
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_checkpoint_hash_varies_with_channel() {
        let h1 =
            PolicyCheckpoint::compute_hash(0, 1, &ReleaseChannel::Stable, "abc", None, 1000, "a");
        let h2 =
            PolicyCheckpoint::compute_hash(0, 1, &ReleaseChannel::Beta, "abc", None, 1000, "a");
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_checkpoint_hash_varies_with_policy_hash() {
        let h1 =
            PolicyCheckpoint::compute_hash(0, 1, &ReleaseChannel::Stable, "aaa", None, 1000, "a");
        let h2 =
            PolicyCheckpoint::compute_hash(0, 1, &ReleaseChannel::Stable, "bbb", None, 1000, "a");
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_checkpoint_hash_varies_with_parent() {
        let h1 =
            PolicyCheckpoint::compute_hash(0, 1, &ReleaseChannel::Stable, "abc", None, 1000, "a");
        let h2 = PolicyCheckpoint::compute_hash(
            0,
            1,
            &ReleaseChannel::Stable,
            "abc",
            Some("parent123"),
            1000,
            "a",
        );
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_checkpoint_hash_varies_with_signer() {
        let h1 = PolicyCheckpoint::compute_hash(
            0,
            1,
            &ReleaseChannel::Stable,
            "abc",
            None,
            1000,
            "alice",
        );
        let h2 =
            PolicyCheckpoint::compute_hash(0, 1, &ReleaseChannel::Stable, "abc", None, 1000, "bob");
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_checkpoint_verify_hash_valid() {
        let hash = PolicyCheckpoint::compute_hash(
            0,
            1,
            &ReleaseChannel::Stable,
            "policy_abc",
            None,
            1000,
            "alice",
        );
        let cp = PolicyCheckpoint {
            sequence: 0,
            epoch_id: 1,
            channel: ReleaseChannel::Stable,
            policy_hash: "policy_abc".to_string(),
            parent_hash: None,
            timestamp: 1000,
            signer: "alice".to_string(),
            checkpoint_hash: hash,
        };
        assert!(cp.verify_hash());
    }

    #[test]
    fn test_checkpoint_verify_hash_tampered() {
        let hash = PolicyCheckpoint::compute_hash(
            0,
            1,
            &ReleaseChannel::Stable,
            "policy_abc",
            None,
            1000,
            "alice",
        );
        let cp = PolicyCheckpoint {
            sequence: 0,
            epoch_id: 1,
            channel: ReleaseChannel::Stable,
            policy_hash: "policy_TAMPERED".to_string(),
            parent_hash: None,
            timestamp: 1000,
            signer: "alice".to_string(),
            checkpoint_hash: hash,
        };
        assert!(!cp.verify_hash());
    }

    #[test]
    fn test_checkpoint_verify_hash_rejects_same_length_digest_tamper() {
        let hash = PolicyCheckpoint::compute_hash(
            0,
            1,
            &ReleaseChannel::Stable,
            "policy_abc",
            None,
            1000,
            "alice",
        );
        let mut cp = PolicyCheckpoint {
            sequence: 0,
            epoch_id: 1,
            channel: ReleaseChannel::Stable,
            policy_hash: "policy_abc".to_string(),
            parent_hash: None,
            timestamp: 1000,
            signer: "alice".to_string(),
            checkpoint_hash: hash.clone(),
        };
        cp.checkpoint_hash = same_len_tamper(&cp.checkpoint_hash);

        assert_eq!(cp.checkpoint_hash.len(), hash.len());
        assert!(!cp.verify_hash());
    }

    #[test]
    fn test_checkpoint_short_hash() {
        let cp = PolicyCheckpoint {
            sequence: 0,
            epoch_id: 1,
            channel: ReleaseChannel::Stable,
            policy_hash: "abc".to_string(),
            parent_hash: None,
            timestamp: 1000,
            signer: "alice".to_string(),
            checkpoint_hash: "a".repeat(64),
        };
        assert_eq!(cp.short_hash().len(), 16);
    }

    // ── PolicyCheckpointChain: basic operations ─────────────────────

    #[test]
    fn test_new_chain_is_empty() {
        let chain = PolicyCheckpointChain::new();
        assert!(chain.is_empty());
        assert_eq!(chain.len(), 0);
        assert!(chain.head_hash().is_none());
        assert_eq!(chain.next_seq(), 0);
    }

    #[test]
    fn test_default_chain_is_empty() {
        let chain = PolicyCheckpointChain::default();
        assert!(chain.is_empty());
    }

    #[test]
    fn test_create_genesis_checkpoint() {
        let mut chain = PolicyCheckpointChain::new();
        let cp = chain
            .create_checkpoint(1, ReleaseChannel::Stable, "hash_0", "alice", "trace-1")
            .expect("genesis");
        assert_eq!(cp.sequence, 0);
        assert_eq!(cp.epoch_id, 1);
        assert_eq!(cp.channel, ReleaseChannel::Stable);
        assert_eq!(cp.policy_hash, "hash_0");
        assert!(cp.parent_hash.is_none());
        assert_eq!(cp.signer, "alice");
        assert_eq!(cp.checkpoint_hash.len(), 64);
        assert_eq!(chain.len(), 1);
        assert!(!chain.is_empty());
    }

    #[test]
    fn test_create_sequential_checkpoints() {
        let mut chain = PolicyCheckpointChain::new();
        let cp0 = chain
            .create_checkpoint(1, ReleaseChannel::Stable, "h0", "a", "t")
            .unwrap()
            .clone();
        let cp1 = chain
            .create_checkpoint(1, ReleaseChannel::Beta, "h1", "b", "t")
            .unwrap()
            .clone();

        assert_eq!(cp0.sequence, 0);
        assert_eq!(cp1.sequence, 1);
        assert_eq!(
            cp1.parent_hash.as_deref(),
            Some(cp0.checkpoint_hash.as_str())
        );
        assert_eq!(chain.len(), 2);
        assert_eq!(chain.next_seq(), 2);
    }

    #[test]
    fn negative_create_rejects_empty_policy_hash_without_mutation() {
        assert_create_checkpoint_input_rejected(
            ReleaseChannel::Stable,
            "",
            "alice",
            "trace-policy",
            "policy_hash must be non-empty",
        );
    }

    #[test]
    fn negative_create_rejects_padded_policy_hash_without_mutation() {
        assert_create_checkpoint_input_rejected(
            ReleaseChannel::Stable,
            " policy ",
            "alice",
            "trace-policy",
            "policy_hash must not contain surrounding whitespace",
        );
    }

    #[test]
    fn negative_create_rejects_empty_signer_without_mutation() {
        assert_create_checkpoint_input_rejected(
            ReleaseChannel::Beta,
            "policy",
            "",
            "trace-signer",
            "signer must be non-empty",
        );
    }

    #[test]
    fn negative_create_rejects_control_char_signer_without_mutation() {
        assert_create_checkpoint_input_rejected(
            ReleaseChannel::Beta,
            "policy",
            "ali\nce",
            "trace-signer",
            "signer must not contain control characters",
        );
    }

    #[test]
    fn negative_create_rejects_empty_trace_id_without_mutation() {
        assert_create_checkpoint_input_rejected(
            ReleaseChannel::Canary,
            "policy",
            "alice",
            "",
            "trace_id must be non-empty",
        );
    }

    #[test]
    fn negative_create_rejects_padded_trace_id_without_mutation() {
        assert_create_checkpoint_input_rejected(
            ReleaseChannel::Canary,
            "policy",
            "alice",
            " trace ",
            "trace_id must not contain surrounding whitespace",
        );
    }

    #[test]
    fn negative_create_rejects_empty_custom_channel_without_mutation() {
        assert_create_checkpoint_input_rejected(
            ReleaseChannel::Custom(String::new()),
            "policy",
            "alice",
            "trace-channel",
            "custom channel must be non-empty",
        );
    }

    #[test]
    fn negative_create_rejects_padded_custom_channel_without_mutation() {
        assert_create_checkpoint_input_rejected(
            ReleaseChannel::Custom(" nightly ".to_string()),
            "policy",
            "alice",
            "trace-channel",
            "custom channel must not contain surrounding whitespace",
        );
    }

    #[test]
    fn test_create_rejects_existing_invalid_chain_contents() {
        let mut chain = PolicyCheckpointChain::new();
        chain
            .create_checkpoint(1, ReleaseChannel::Stable, "h0", "alice", "trace-create")
            .expect("seed checkpoint");
        chain.tamper_policy_hash(0, "TAMPERED");

        let err = chain
            .create_checkpoint(2, ReleaseChannel::Beta, "h1", "alice", "trace-reject")
            .expect_err("invalid existing chain must reject new create");
        match err {
            CheckpointChainError::HashChainBreak { index, reason } => {
                assert_eq!(index, 0);
                assert_eq!(reason, "checkpoint_hash does not match recomputed hash");
            }
            _ => unreachable!("wrong error variant"),
        }

        assert_eq!(chain.len(), 1);
        assert_eq!(chain.next_seq(), 1);

        let rejection = chain
            .events()
            .last()
            .expect("invalid create should emit a rejection event");
        assert_eq!(
            rejection.event_code,
            event_codes::PCK_003_CHECKPOINT_REJECTED
        );
        assert_eq!(rejection.event_name, event_names::CHECKPOINT_REJECTED);
        assert_eq!(rejection.trace_id, "trace-reject");
        assert_eq!(rejection.epoch_id, 2);
        assert_eq!(rejection.sequence, 1);
        assert_eq!(rejection.channel, "beta");
        assert_eq!(
            rejection.detail,
            "CHECKPOINT_HASH_CHAIN_BREAK: existing chain invalid at index 0: checkpoint_hash does not match recomputed hash"
        );
    }

    #[test]
    fn test_create_rejects_existing_head_hash_mismatch() {
        let mut chain = PolicyCheckpointChain::new();
        let original_head = chain
            .create_checkpoint(1, ReleaseChannel::Stable, "h0", "alice", "trace-create")
            .expect("seed checkpoint")
            .checkpoint_hash
            .clone();
        chain.tamper_head_hash(Some("wrong-head".to_string()));

        let err = chain
            .create_checkpoint(2, ReleaseChannel::Beta, "h1", "alice", "trace-head")
            .expect_err("head hash mismatch must reject create");

        match err {
            CheckpointChainError::HashChainBreak { index, reason } => {
                assert_eq!(index, 0);
                assert!(reason.contains("head_hash mismatch"));
                assert!(reason.contains("wrong-head"));
            }
            _ => unreachable!("wrong error variant"),
        }
        assert_eq!(chain.len(), 1);
        assert_eq!(chain.head_hash(), Some("wrong-head"));
        assert_ne!(chain.head_hash(), Some(original_head.as_str()));
        assert_eq!(
            chain.events().last().unwrap().event_code,
            event_codes::PCK_003_CHECKPOINT_REJECTED
        );
    }

    #[test]
    fn test_create_rejects_empty_chain_with_tampered_next_seq() {
        let mut chain = PolicyCheckpointChain::new();
        chain.tamper_next_seq(7);

        let err = chain
            .create_checkpoint(1, ReleaseChannel::Stable, "h0", "alice", "trace-next-seq")
            .expect_err("tampered empty-chain next_seq must reject create");

        match err {
            CheckpointChainError::HashChainBreak { index, reason } => {
                assert_eq!(index, 0);
                assert_eq!(reason, "next_seq mismatch: expected 0, got 7");
            }
            _ => unreachable!("wrong error variant"),
        }
        assert!(chain.is_empty());
        assert_eq!(chain.next_seq(), 7);
    }

    // ── append_checkpoint with enforcement ──────────────────────────

    #[test]
    fn test_append_accepts_valid_checkpoint_and_updates_chain_state() {
        let mut chain = PolicyCheckpointChain::new();
        let create_trace_id = "trace-create";
        let append_trace_id = "trace-append";
        let head = chain
            .create_checkpoint(1, ReleaseChannel::Stable, "h0", "alice", create_trace_id)
            .unwrap()
            .checkpoint_hash
            .clone();

        let appended = PolicyCheckpoint {
            sequence: chain.next_seq(),
            epoch_id: 1,
            channel: ReleaseChannel::Beta,
            policy_hash: "h1".to_string(),
            parent_hash: Some(head.clone()),
            timestamp: 1000,
            signer: "alice".to_string(),
            checkpoint_hash: PolicyCheckpoint::compute_hash(
                chain.next_seq(),
                1,
                &ReleaseChannel::Beta,
                "h1",
                Some(head.as_str()),
                1000,
                "alice",
            ),
        };
        let expected_hash = appended.checkpoint_hash.clone();

        let appended = chain.append_checkpoint(appended, append_trace_id).unwrap();
        assert_eq!(appended.sequence, 1);
        assert_eq!(appended.parent_hash.as_deref(), Some(head.as_str()));
        assert_eq!(appended.checkpoint_hash, expected_hash);
        assert_eq!(chain.len(), 2);
        assert_eq!(chain.next_seq(), 2);
        assert_eq!(chain.head_hash(), Some(expected_hash.as_str()));
        assert_eq!(chain.verify_chain(), Ok(2));

        let events = chain.events();
        assert_eq!(events.len(), 2);
        let last_event = events.last().unwrap();
        assert_eq!(
            last_event.event_code,
            event_codes::PCK_001_CHECKPOINT_CREATED
        );
        assert_eq!(last_event.event_name, event_names::CHECKPOINT_CREATED);
        assert_eq!(last_event.trace_id, append_trace_id);
        assert_eq!(last_event.epoch_id, 1);
        assert_eq!(last_event.sequence, 1);
        assert_eq!(last_event.channel, "beta");
        assert_eq!(last_event.detail, "checkpoint appended: seq=1 epoch=1");
    }

    #[test]
    fn negative_append_rejects_empty_policy_hash_without_mutation() {
        assert_append_checkpoint_input_rejected(
            ReleaseChannel::Beta,
            "",
            "alice",
            "trace-append-policy",
            "policy_hash must be non-empty",
        );
    }

    #[test]
    fn negative_append_rejects_padded_signer_without_mutation() {
        assert_append_checkpoint_input_rejected(
            ReleaseChannel::Beta,
            "policy",
            " alice ",
            "trace-append-signer",
            "signer must not contain surrounding whitespace",
        );
    }

    #[test]
    fn negative_append_rejects_control_char_trace_id_without_mutation() {
        assert_append_checkpoint_input_rejected(
            ReleaseChannel::Canary,
            "policy",
            "alice",
            "trace\nappend",
            "trace_id must not contain control characters",
        );
    }

    #[test]
    fn negative_append_rejects_empty_custom_channel_without_mutation() {
        assert_append_checkpoint_input_rejected(
            ReleaseChannel::Custom(String::new()),
            "policy",
            "alice",
            "trace-append-channel",
            "custom channel must be non-empty",
        );
    }

    #[test]
    fn test_append_rejects_wrong_sequence() {
        let mut chain = PolicyCheckpointChain::new();
        chain
            .create_checkpoint(1, ReleaseChannel::Stable, "h0", "a", "t")
            .unwrap();

        let bad_cp = PolicyCheckpoint {
            sequence: 5, // should be 1
            epoch_id: 1,
            channel: ReleaseChannel::Stable,
            policy_hash: "h1".to_string(),
            parent_hash: chain.head_hash().map(String::from),
            timestamp: 1000,
            signer: "a".to_string(),
            checkpoint_hash: "x".repeat(64),
        };
        let err = chain.append_checkpoint(bad_cp, "t").unwrap_err();
        assert_eq!(err.code(), "CHECKPOINT_SEQ_VIOLATION");
        match err {
            CheckpointChainError::SequenceViolation { expected, actual } => {
                assert_eq!(expected, 1);
                assert_eq!(actual, 5);
            }
            _ => unreachable!("wrong error variant"),
        }
    }

    #[test]
    fn test_append_rejects_duplicate_sequence() {
        let mut chain = PolicyCheckpointChain::new();
        chain
            .create_checkpoint(1, ReleaseChannel::Stable, "h0", "a", "t")
            .unwrap();

        let bad_cp = PolicyCheckpoint {
            sequence: 0, // duplicate of existing
            epoch_id: 1,
            channel: ReleaseChannel::Stable,
            policy_hash: "h1".to_string(),
            parent_hash: chain.head_hash().map(String::from),
            timestamp: 1000,
            signer: "a".to_string(),
            checkpoint_hash: "x".repeat(64),
        };
        let err = chain.append_checkpoint(bad_cp, "t").unwrap_err();
        assert_eq!(err.code(), "CHECKPOINT_SEQ_VIOLATION");
    }

    #[test]
    fn test_append_rejects_wrong_parent_hash() {
        let mut chain = PolicyCheckpointChain::new();
        chain
            .create_checkpoint(1, ReleaseChannel::Stable, "h0", "a", "t")
            .unwrap();

        let bad_cp = PolicyCheckpoint {
            sequence: 1,
            epoch_id: 1,
            channel: ReleaseChannel::Stable,
            policy_hash: "h1".to_string(),
            parent_hash: Some("WRONG_PARENT".to_string()),
            timestamp: 1000,
            signer: "a".to_string(),
            checkpoint_hash: "x".repeat(64),
        };
        let err = chain.append_checkpoint(bad_cp, "t").unwrap_err();
        assert_eq!(err.code(), "CHECKPOINT_PARENT_MISMATCH");
    }

    #[test]
    fn test_append_rejects_same_length_parent_hash_tamper() {
        let mut chain = PolicyCheckpointChain::new();
        let head = chain
            .create_checkpoint(1, ReleaseChannel::Stable, "h0", "a", "t")
            .unwrap()
            .checkpoint_hash
            .clone();
        let bad_parent = same_len_tamper(&head);
        let bad_cp = PolicyCheckpoint {
            sequence: chain.next_seq(),
            epoch_id: 1,
            channel: ReleaseChannel::Beta,
            policy_hash: "h1".to_string(),
            parent_hash: Some(bad_parent.clone()),
            timestamp: 1000,
            signer: "a".to_string(),
            checkpoint_hash: PolicyCheckpoint::compute_hash(
                chain.next_seq(),
                1,
                &ReleaseChannel::Beta,
                "h1",
                Some(bad_parent.as_str()),
                1000,
                "a",
            ),
        };

        let err = chain
            .append_checkpoint(bad_cp, "trace-parent-same-len")
            .expect_err("same-length parent tamper must reject append");

        assert_eq!(bad_parent.len(), head.len());
        assert_eq!(err.code(), error_codes::CHECKPOINT_PARENT_MISMATCH);
        assert_eq!(chain.len(), 1);
        assert_eq!(chain.head_hash(), Some(head.as_str()));
    }

    #[test]
    fn test_append_rejects_genesis_with_parent_hash() {
        let mut chain = PolicyCheckpointChain::new();
        let bad_cp = PolicyCheckpoint {
            sequence: 0,
            epoch_id: 1,
            channel: ReleaseChannel::Stable,
            policy_hash: "h0".to_string(),
            parent_hash: Some("unexpected-parent".to_string()),
            timestamp: 1000,
            signer: "alice".to_string(),
            checkpoint_hash: PolicyCheckpoint::compute_hash(
                0,
                1,
                &ReleaseChannel::Stable,
                "h0",
                Some("unexpected-parent"),
                1000,
                "alice",
            ),
        };

        let err = chain
            .append_checkpoint(bad_cp, "trace-parent")
            .expect_err("genesis checkpoint with parent must be rejected");

        assert_eq!(err.code(), error_codes::CHECKPOINT_PARENT_MISMATCH);
        assert!(chain.is_empty());
        assert_eq!(
            chain.events().last().unwrap().event_code,
            event_codes::PCK_003_CHECKPOINT_REJECTED
        );
    }

    #[test]
    fn test_append_rejects_genesis_with_invalid_hash() {
        let mut chain = PolicyCheckpointChain::new();
        let bad_cp = PolicyCheckpoint {
            sequence: 0,
            epoch_id: 1,
            channel: ReleaseChannel::Stable,
            policy_hash: "h0".to_string(),
            parent_hash: None,
            timestamp: 1000,
            signer: "alice".to_string(),
            checkpoint_hash: "bad-hash".to_string(),
        };

        let err = chain
            .append_checkpoint(bad_cp, "trace-bad-hash")
            .expect_err("genesis checkpoint with bad hash must be rejected");

        match err {
            CheckpointChainError::HashChainBreak { index, reason } => {
                assert_eq!(index, 0);
                assert_eq!(
                    reason,
                    "checkpoint_hash does not match canonical serialization"
                );
            }
            _ => unreachable!("wrong error variant"),
        }
        assert!(chain.is_empty());
    }

    #[test]
    fn test_append_rejects_invalid_checkpoint_hash() {
        let mut chain = PolicyCheckpointChain::new();
        let head = chain
            .create_checkpoint(1, ReleaseChannel::Stable, "h0", "a", "t")
            .unwrap()
            .checkpoint_hash
            .clone();

        let bad_cp = PolicyCheckpoint {
            sequence: 1,
            epoch_id: 1,
            channel: ReleaseChannel::Beta,
            policy_hash: "h1".to_string(),
            parent_hash: Some(head.clone()),
            timestamp: 1000,
            signer: "a".to_string(),
            checkpoint_hash: "f".repeat(64),
        };

        let err = chain.append_checkpoint(bad_cp, "t").unwrap_err();
        assert_eq!(err.code(), "CHECKPOINT_HASH_CHAIN_BREAK");
        match err {
            CheckpointChainError::HashChainBreak { index, reason } => {
                assert_eq!(index, 1);
                assert_eq!(
                    reason,
                    "checkpoint_hash does not match canonical serialization"
                );
            }
            _ => unreachable!("wrong error variant"),
        }
        assert_eq!(chain.len(), 1);
        assert_eq!(chain.next_seq(), 1);
        assert_eq!(chain.head_hash(), Some(head.as_str()));

        let rejection = chain
            .events()
            .last()
            .expect("invalid append should emit a rejection event");
        assert_eq!(
            rejection.event_code,
            event_codes::PCK_003_CHECKPOINT_REJECTED
        );
        assert_eq!(rejection.event_name, event_names::CHECKPOINT_REJECTED);
        assert_eq!(rejection.trace_id, "t");
        assert_eq!(rejection.epoch_id, 1);
        assert_eq!(rejection.sequence, 1);
        assert_eq!(rejection.channel, "beta");
        assert_eq!(
            rejection.detail,
            "CHECKPOINT_HASH_CHAIN_BREAK: checkpoint_hash does not match canonical serialization"
        );
    }

    #[test]
    fn test_append_rejects_next_seq_mismatch_in_existing_chain_state() {
        let mut chain = PolicyCheckpointChain::new();
        let head = chain
            .create_checkpoint(1, ReleaseChannel::Stable, "h0", "alice", "trace-create")
            .expect("seed checkpoint")
            .checkpoint_hash
            .clone();
        chain.tamper_next_seq(99);

        let checkpoint = PolicyCheckpoint {
            sequence: 99,
            epoch_id: 2,
            channel: ReleaseChannel::Beta,
            policy_hash: "h1".to_string(),
            parent_hash: Some(head.clone()),
            timestamp: 1000,
            signer: "alice".to_string(),
            checkpoint_hash: PolicyCheckpoint::compute_hash(
                99,
                2,
                &ReleaseChannel::Beta,
                "h1",
                Some(head.as_str()),
                1000,
                "alice",
            ),
        };

        let err = chain
            .append_checkpoint(checkpoint, "trace-append-reject")
            .expect_err("invalid existing chain state must reject append");
        match err {
            CheckpointChainError::HashChainBreak { index, reason } => {
                assert_eq!(index, 1);
                assert_eq!(reason, "next_seq mismatch: expected 1, got 99");
            }
            _ => unreachable!("wrong error variant"),
        }

        assert_eq!(chain.len(), 1);
        assert_eq!(chain.next_seq(), 99);
        assert_eq!(chain.head_hash(), Some(head.as_str()));

        let rejection = chain
            .events()
            .last()
            .expect("invalid append should emit a rejection event");
        assert_eq!(
            rejection.event_code,
            event_codes::PCK_003_CHECKPOINT_REJECTED
        );
        assert_eq!(rejection.event_name, event_names::CHECKPOINT_REJECTED);
        assert_eq!(rejection.trace_id, "trace-append-reject");
        assert_eq!(rejection.epoch_id, 2);
        assert_eq!(rejection.sequence, 99);
        assert_eq!(rejection.channel, "beta");
        assert_eq!(
            rejection.detail,
            "CHECKPOINT_HASH_CHAIN_BREAK: existing chain invalid at index 1: next_seq mismatch: expected 1, got 99"
        );
    }

    // ── verify_chain ─────────────────────────────────────────────────

    #[test]
    fn test_verify_empty_chain() {
        let chain = PolicyCheckpointChain::new();
        assert_eq!(chain.verify_chain(), Ok(0));
    }

    #[test]
    fn test_verify_valid_chain() {
        let mut chain = PolicyCheckpointChain::new();
        for i in 0..10 {
            chain
                .create_checkpoint(
                    1,
                    ReleaseChannel::Stable,
                    &format!("policy_{i}"),
                    "alice",
                    "trace",
                )
                .unwrap();
        }
        assert_eq!(chain.verify_chain(), Ok(10));
    }

    #[test]
    fn test_verify_detects_tampered_policy_hash() {
        let mut chain = PolicyCheckpointChain::new();
        for i in 0..5 {
            chain
                .create_checkpoint(1, ReleaseChannel::Stable, &format!("p{i}"), "a", "t")
                .unwrap();
        }
        chain.tamper_policy_hash(2, "TAMPERED");
        let result = chain.verify_chain();
        assert!(result.is_err());
        let (idx, _err) = result.unwrap_err();
        assert_eq!(idx, 2);
    }

    #[test]
    fn test_verify_detects_tampered_checkpoint_hash() {
        let mut chain = PolicyCheckpointChain::new();
        for i in 0..5 {
            chain
                .create_checkpoint(1, ReleaseChannel::Stable, &format!("p{i}"), "a", "t")
                .unwrap();
        }
        chain.tamper_checkpoint_hash(1, &"f".repeat(64));
        let result = chain.verify_chain();
        assert!(result.is_err());
        let (idx, _) = result.unwrap_err();
        assert_eq!(idx, 1);
    }

    #[test]
    fn test_verify_detects_same_length_checkpoint_hash_tamper() {
        let mut chain = PolicyCheckpointChain::new();
        for i in 0..3 {
            chain
                .create_checkpoint(1, ReleaseChannel::Stable, &format!("p{i}"), "a", "t")
                .unwrap();
        }
        let tampered = same_len_tamper(&chain.checkpoints()[1].checkpoint_hash);
        chain.tamper_checkpoint_hash(1, &tampered);

        let (idx, err) = chain
            .verify_chain()
            .expect_err("same-length checkpoint tamper must break verification");

        assert_eq!(idx, 1);
        match err {
            CheckpointChainError::HashChainBreak { index, reason } => {
                assert_eq!(index, 1);
                assert_eq!(reason, "checkpoint_hash does not match recomputed hash");
            }
            _ => unreachable!("wrong error variant"),
        }
    }

    #[test]
    fn test_verify_detects_tampered_parent_hash() {
        let mut chain = PolicyCheckpointChain::new();
        for i in 0..5 {
            chain
                .create_checkpoint(1, ReleaseChannel::Stable, &format!("p{i}"), "a", "t")
                .unwrap();
        }
        chain.tamper_parent_hash(3, Some("FORGED".to_string()));
        let result = chain.verify_chain();
        assert!(result.is_err());
        let (idx, _) = result.unwrap_err();
        assert_eq!(idx, 3);
    }

    #[test]
    fn test_verify_detects_same_length_parent_hash_tamper() {
        let mut chain = PolicyCheckpointChain::new();
        for i in 0..4 {
            chain
                .create_checkpoint(1, ReleaseChannel::Stable, &format!("p{i}"), "a", "t")
                .unwrap();
        }
        let parent = chain.checkpoints()[2]
            .parent_hash
            .as_ref()
            .expect("non-genesis parent")
            .clone();
        chain.tamper_parent_hash(2, Some(same_len_tamper(&parent)));

        let (idx, err) = chain
            .verify_chain()
            .expect_err("same-length parent tamper must break verification");

        assert_eq!(idx, 2);
        match err {
            CheckpointChainError::HashChainBreak { index, reason } => {
                assert_eq!(index, 2);
                assert!(reason.contains("parent_hash mismatch"));
            }
            _ => unreachable!("wrong error variant"),
        }
    }

    #[test]
    fn test_verify_detects_tampered_sequence() {
        let mut chain = PolicyCheckpointChain::new();
        for i in 0..5 {
            chain
                .create_checkpoint(1, ReleaseChannel::Stable, &format!("p{i}"), "a", "t")
                .unwrap();
        }
        chain.tamper_sequence(2, 99);
        let result = chain.verify_chain();
        assert!(result.is_err());
        let (idx, _) = result.unwrap_err();
        assert_eq!(idx, 2);
    }

    #[test]
    fn test_verify_single_bit_flip_detection() {
        let mut chain = PolicyCheckpointChain::new();
        chain
            .create_checkpoint(1, ReleaseChannel::Stable, "policy_a", "alice", "t")
            .unwrap();
        chain
            .create_checkpoint(1, ReleaseChannel::Stable, "policy_b", "alice", "t")
            .unwrap();

        // Flip one character in policy_hash (simulates bit-flip)
        let original = chain.checkpoints()[1].policy_hash.clone();
        let flipped = if let Some(rest) = original.strip_prefix('a') {
            format!("b{rest}")
        } else {
            format!("a{}", &original[1..])
        };
        chain.tamper_policy_hash(1, &flipped);
        let result = chain.verify_chain();
        assert!(result.is_err());
        let (idx, _) = result.unwrap_err();
        assert_eq!(idx, 1);
    }

    // ── latest_for_channel ──────────────────────────────────────────

    #[test]
    fn test_latest_for_channel_empty() {
        let chain = PolicyCheckpointChain::new();
        assert!(chain.latest_for_channel(&ReleaseChannel::Stable).is_none());
    }

    #[test]
    fn test_latest_for_channel_single() {
        let mut chain = PolicyCheckpointChain::new();
        chain
            .create_checkpoint(1, ReleaseChannel::Stable, "h0", "a", "t")
            .unwrap();
        let latest = chain.latest_for_channel(&ReleaseChannel::Stable);
        assert!(latest.is_some());
        assert_eq!(latest.unwrap().sequence, 0);
    }

    #[test]
    fn test_latest_for_channel_multi() {
        let mut chain = PolicyCheckpointChain::new();
        chain
            .create_checkpoint(1, ReleaseChannel::Stable, "s0", "a", "t")
            .unwrap();
        chain
            .create_checkpoint(1, ReleaseChannel::Beta, "b0", "a", "t")
            .unwrap();
        chain
            .create_checkpoint(1, ReleaseChannel::Stable, "s1", "a", "t")
            .unwrap();
        chain
            .create_checkpoint(1, ReleaseChannel::Canary, "c0", "a", "t")
            .unwrap();

        let latest_stable = chain.latest_for_channel(&ReleaseChannel::Stable).unwrap();
        assert_eq!(latest_stable.sequence, 2);
        assert_eq!(latest_stable.policy_hash, "s1");

        let latest_beta = chain.latest_for_channel(&ReleaseChannel::Beta).unwrap();
        assert_eq!(latest_beta.sequence, 1);

        let latest_canary = chain.latest_for_channel(&ReleaseChannel::Canary).unwrap();
        assert_eq!(latest_canary.sequence, 3);

        assert!(
            chain
                .latest_for_channel(&ReleaseChannel::Custom("nightly".into()))
                .is_none()
        );
    }

    // ── policy_frontier ──────────────────────────────────────────────

    #[test]
    fn test_policy_frontier_empty() {
        let chain = PolicyCheckpointChain::new();
        assert!(chain.policy_frontier().is_empty());
    }

    #[test]
    fn test_policy_frontier_multi_channel() {
        let mut chain = PolicyCheckpointChain::new();
        chain
            .create_checkpoint(1, ReleaseChannel::Stable, "s0", "a", "t")
            .unwrap();
        chain
            .create_checkpoint(1, ReleaseChannel::Beta, "b0", "a", "t")
            .unwrap();
        chain
            .create_checkpoint(1, ReleaseChannel::Canary, "c0", "a", "t")
            .unwrap();
        chain
            .create_checkpoint(1, ReleaseChannel::Stable, "s1", "a", "t")
            .unwrap();

        let frontier = chain.policy_frontier();
        assert_eq!(frontier.len(), 3);

        // Verify we get the latest for each channel
        for (ch, cp) in &frontier {
            match ch {
                ReleaseChannel::Stable => {
                    assert_eq!(cp.policy_hash, "s1");
                    assert_eq!(cp.sequence, 3);
                }
                ReleaseChannel::Beta => {
                    assert_eq!(cp.policy_hash, "b0");
                    assert_eq!(cp.sequence, 1);
                }
                ReleaseChannel::Canary => {
                    assert_eq!(cp.policy_hash, "c0");
                    assert_eq!(cp.sequence, 2);
                }
                _ => unreachable!("unexpected channel"),
            }
        }
    }

    #[test]
    fn test_policy_frontier_with_custom_channel() {
        let mut chain = PolicyCheckpointChain::new();
        chain
            .create_checkpoint(1, ReleaseChannel::Stable, "s0", "a", "t")
            .unwrap();
        chain
            .create_checkpoint(1, ReleaseChannel::Custom("nightly".into()), "n0", "a", "t")
            .unwrap();

        let frontier = chain.policy_frontier();
        assert_eq!(frontier.len(), 2);
    }

    // ── channels ─────────────────────────────────────────────────────

    #[test]
    fn test_channels_empty() {
        let chain = PolicyCheckpointChain::new();
        assert!(chain.channels().is_empty());
    }

    #[test]
    fn test_channels_distinct() {
        let mut chain = PolicyCheckpointChain::new();
        chain
            .create_checkpoint(1, ReleaseChannel::Stable, "s", "a", "t")
            .unwrap();
        chain
            .create_checkpoint(1, ReleaseChannel::Beta, "b", "a", "t")
            .unwrap();
        chain
            .create_checkpoint(1, ReleaseChannel::Stable, "s2", "a", "t")
            .unwrap();

        let channels = chain.channels();
        assert_eq!(channels.len(), 2);
    }

    // ── events ───────────────────────────────────────────────────────

    #[test]
    fn test_events_emitted_on_create() {
        let mut chain = PolicyCheckpointChain::new();
        chain
            .create_checkpoint(1, ReleaseChannel::Stable, "h0", "alice", "trace-abc")
            .unwrap();

        let events = chain.events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_code, "PCK-001");
        assert_eq!(events[0].event_name, "CHECKPOINT_CREATED");
        assert_eq!(events[0].trace_id, "trace-abc");
        assert_eq!(events[0].epoch_id, 1);
        assert_eq!(events[0].sequence, 0);
        assert_eq!(events[0].channel, "stable");
    }

    #[test]
    fn test_events_emitted_on_rejection() {
        let mut chain = PolicyCheckpointChain::new();
        chain
            .create_checkpoint(1, ReleaseChannel::Stable, "h0", "a", "t")
            .unwrap();

        let bad = PolicyCheckpoint {
            sequence: 99,
            epoch_id: 1,
            channel: ReleaseChannel::Stable,
            policy_hash: "x".to_string(),
            parent_hash: chain.head_hash().map(String::from),
            timestamp: 0,
            signer: "a".to_string(),
            checkpoint_hash: "x".repeat(64),
        };
        let _ = chain.append_checkpoint(bad, "trace-reject");

        let events = chain.events();
        assert!(events.iter().any(|e| e.event_code == "PCK-003"
            && e.event_name == "CHECKPOINT_REJECTED"
            && e.trace_id == "trace-reject"));
    }

    #[test]
    fn test_push_bounded_zero_capacity_clears_existing_items() {
        let mut items = vec![1, 2, 3];

        push_bounded(&mut items, 4, 0);

        assert!(items.is_empty());
    }

    #[test]
    fn test_push_bounded_zero_capacity_drops_new_item() {
        let mut items = Vec::new();

        push_bounded(&mut items, "dropped", 0);

        assert!(items.is_empty());
    }

    #[test]
    fn test_create_checkpoint_capacity_rejection_emits_event() {
        let mut chain = PolicyCheckpointChain::new();
        for seq in 0..MAX_CHECKPOINTS {
            chain
                .create_checkpoint(
                    1,
                    ReleaseChannel::Stable,
                    &format!("policy-{seq}"),
                    "alice",
                    "trace-fill",
                )
                .expect("fill chain");
        }

        let err = chain
            .create_checkpoint(
                2,
                ReleaseChannel::Beta,
                "overflow",
                "alice",
                "trace-cap-create",
            )
            .expect_err("full chain must reject create");
        match err {
            CheckpointChainError::HashChainBreak { index, reason } => {
                assert_eq!(index, MAX_CHECKPOINTS);
                assert_eq!(reason, "chain at capacity (MAX_CHECKPOINTS reached)");
            }
            _ => unreachable!("wrong error variant"),
        }
        assert_eq!(chain.len(), MAX_CHECKPOINTS);
        assert_eq!(chain.next_seq(), MAX_CHECKPOINTS as u64);

        let rejection = chain.events().last().expect("capacity rejection event");
        assert_eq!(
            rejection.event_code,
            event_codes::PCK_003_CHECKPOINT_REJECTED
        );
        assert_eq!(rejection.event_name, event_names::CHECKPOINT_REJECTED);
        assert_eq!(rejection.trace_id, "trace-cap-create");
        assert_eq!(rejection.epoch_id, 2);
        assert_eq!(rejection.sequence, MAX_CHECKPOINTS as u64);
        assert_eq!(rejection.channel, "beta");
        assert_eq!(
            rejection.detail,
            "CHECKPOINT_HASH_CHAIN_BREAK: chain at capacity (MAX_CHECKPOINTS reached)"
        );
    }

    #[test]
    fn test_append_checkpoint_capacity_rejection_emits_event() {
        let mut chain = PolicyCheckpointChain::new();
        for seq in 0..MAX_CHECKPOINTS {
            chain
                .create_checkpoint(
                    1,
                    ReleaseChannel::Stable,
                    &format!("policy-{seq}"),
                    "alice",
                    "trace-fill",
                )
                .expect("fill chain");
        }
        let head = chain
            .head_hash()
            .expect("filled chain should have head")
            .to_string();
        let next_seq = chain.next_seq();

        let checkpoint = PolicyCheckpoint {
            sequence: next_seq,
            epoch_id: 2,
            channel: ReleaseChannel::Beta,
            policy_hash: "overflow".to_string(),
            parent_hash: Some(head.clone()),
            timestamp: 1000,
            signer: "alice".to_string(),
            checkpoint_hash: PolicyCheckpoint::compute_hash(
                next_seq,
                2,
                &ReleaseChannel::Beta,
                "overflow",
                Some(head.as_str()),
                1000,
                "alice",
            ),
        };

        let err = chain
            .append_checkpoint(checkpoint, "trace-cap-append")
            .expect_err("full chain must reject append");
        match err {
            CheckpointChainError::HashChainBreak { index, reason } => {
                assert_eq!(index, MAX_CHECKPOINTS);
                assert_eq!(reason, "chain at capacity (MAX_CHECKPOINTS reached)");
            }
            _ => unreachable!("wrong error variant"),
        }
        assert_eq!(chain.len(), MAX_CHECKPOINTS);
        assert_eq!(chain.next_seq(), next_seq);
        assert_eq!(chain.head_hash(), Some(head.as_str()));

        let rejection = chain.events().last().expect("capacity rejection event");
        assert_eq!(
            rejection.event_code,
            event_codes::PCK_003_CHECKPOINT_REJECTED
        );
        assert_eq!(rejection.event_name, event_names::CHECKPOINT_REJECTED);
        assert_eq!(rejection.trace_id, "trace-cap-append");
        assert_eq!(rejection.epoch_id, 2);
        assert_eq!(rejection.sequence, next_seq);
        assert_eq!(rejection.channel, "beta");
        assert_eq!(
            rejection.detail,
            "CHECKPOINT_HASH_CHAIN_BREAK: chain at capacity (MAX_CHECKPOINTS reached)"
        );
    }

    // ── Large chain test (100+ checkpoints) ──────────────────────────

    #[test]
    fn test_chain_100_plus_checkpoints() {
        let mut chain = PolicyCheckpointChain::new();
        let channels = [
            ReleaseChannel::Stable,
            ReleaseChannel::Beta,
            ReleaseChannel::Canary,
        ];

        for i in 0..150 {
            let channel = channels[i % 3].clone();
            let policy_hash = sha256_hex(format!("policy-doc-v{i}").as_bytes());
            chain
                .create_checkpoint(i as u64 / 50, channel, &policy_hash, "signer-ci", "trace")
                .unwrap();
        }

        assert_eq!(chain.len(), 150);
        assert_eq!(chain.verify_chain(), Ok(150));

        let frontier = chain.policy_frontier();
        assert_eq!(frontier.len(), 3);

        // Each channel should have the latest
        for (ch, cp) in &frontier {
            match ch {
                ReleaseChannel::Stable => assert_eq!(cp.sequence, 147),
                ReleaseChannel::Beta => assert_eq!(cp.sequence, 148),
                ReleaseChannel::Canary => assert_eq!(cp.sequence, 149),
                _ => unreachable!("unexpected"),
            }
        }
    }

    // ── Epoch boundary test ──────────────────────────────────────────

    #[test]
    fn test_epoch_boundary_continuity() {
        let mut chain = PolicyCheckpointChain::new();
        // Epoch 1
        chain
            .create_checkpoint(1, ReleaseChannel::Stable, "e1_p0", "a", "t")
            .unwrap();
        chain
            .create_checkpoint(1, ReleaseChannel::Stable, "e1_p1", "a", "t")
            .unwrap();
        // Epoch 2 boundary
        chain
            .create_checkpoint(2, ReleaseChannel::Stable, "e2_p0", "a", "t")
            .unwrap();

        assert_eq!(chain.verify_chain(), Ok(3));
        let checkpoints = chain.checkpoints();
        assert_eq!(checkpoints[0].epoch_id, 1);
        assert_eq!(checkpoints[2].epoch_id, 2);
        // Parent chain is continuous across epoch boundary
        assert_eq!(
            checkpoints[2].parent_hash.as_deref(),
            Some(checkpoints[1].checkpoint_hash.as_str())
        );
    }

    // ── Serde round-trip ─────────────────────────────────────────────

    #[test]
    fn test_checkpoint_serde() {
        let hash = PolicyCheckpoint::compute_hash(
            0,
            1,
            &ReleaseChannel::Stable,
            "abc",
            None,
            1000,
            "alice",
        );
        let cp = PolicyCheckpoint {
            sequence: 0,
            epoch_id: 1,
            channel: ReleaseChannel::Stable,
            policy_hash: "abc".to_string(),
            parent_hash: None,
            timestamp: 1000,
            signer: "alice".to_string(),
            checkpoint_hash: hash,
        };
        let json = serde_json::to_string(&cp).unwrap();
        let parsed: PolicyCheckpoint = serde_json::from_str(&json).unwrap();
        assert_eq!(cp, parsed);
    }

    #[test]
    fn test_checkpoint_deserialize_rejects_missing_checkpoint_hash() {
        let json = r#"{
            "sequence": 0,
            "epoch_id": 1,
            "channel": "Stable",
            "policy_hash": "abc",
            "parent_hash": null,
            "timestamp": 1000,
            "signer": "alice"
        }"#;

        let result: Result<PolicyCheckpoint, _> = serde_json::from_str(json);

        assert!(result.is_err());
    }

    #[test]
    fn test_checkpoint_deserialize_rejects_channel_type_confusion() {
        let json = r#"{
            "sequence": 0,
            "epoch_id": 1,
            "channel": {"Stable": true},
            "policy_hash": "abc",
            "parent_hash": null,
            "timestamp": 1000,
            "signer": "alice",
            "checkpoint_hash": "abc"
        }"#;

        let result: Result<PolicyCheckpoint, _> = serde_json::from_str(json);

        assert!(result.is_err());
    }

    #[test]
    fn test_chain_serde_round_trip() {
        let mut chain = PolicyCheckpointChain::new();
        chain
            .create_checkpoint(1, ReleaseChannel::Stable, "h0", "a", "t")
            .unwrap();
        chain
            .create_checkpoint(1, ReleaseChannel::Beta, "h1", "b", "t")
            .unwrap();

        let json = serde_json::to_string(&chain).unwrap();
        let parsed: PolicyCheckpointChain = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed.verify_chain(), Ok(2));
    }

    #[test]
    fn test_chain_deserialize_rejects_negative_next_seq() {
        let json = r#"{
            "checkpoints": [],
            "head_hash": null,
            "next_seq": -1,
            "events": []
        }"#;

        let result: Result<PolicyCheckpointChain, _> = serde_json::from_str(json);

        assert!(result.is_err());
    }

    #[test]
    fn test_release_channel_serde() {
        let channels = vec![
            ReleaseChannel::Stable,
            ReleaseChannel::Beta,
            ReleaseChannel::Canary,
            ReleaseChannel::Custom("nightly".into()),
        ];
        for ch in channels {
            let json = serde_json::to_string(&ch).unwrap();
            let parsed: ReleaseChannel = serde_json::from_str(&json).unwrap();
            assert_eq!(ch, parsed);
        }
    }

    // ── Send + Sync ──────────────────────────────────────────────────

    #[test]
    fn test_types_send_sync() {
        fn assert_send<T: Send>() {}
        fn assert_sync<T: Sync>() {}

        assert_send::<ReleaseChannel>();
        assert_sync::<ReleaseChannel>();
        assert_send::<PolicyCheckpoint>();
        assert_sync::<PolicyCheckpoint>();
        assert_send::<PolicyCheckpointChain>();
        assert_sync::<PolicyCheckpointChain>();
        assert_send::<CheckpointChainError>();
        assert_sync::<CheckpointChainError>();
        assert_send::<CheckpointChainEvent>();
        assert_sync::<CheckpointChainEvent>();
    }

    // ── sha256_hex helper ────────────────────────────────────────────

    #[test]
    fn test_sha256_hex_deterministic() {
        let h1 = sha256_hex(b"test");
        let h2 = sha256_hex(b"test");
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64);
    }

    #[test]
    fn test_sha256_hex_different_inputs() {
        assert_ne!(sha256_hex(b"a"), sha256_hex(b"b"));
    }

    /// Regression: null-byte delimiter hash collision.
    /// Two inputs that would collide under null-byte separation must produce
    /// distinct hashes with length-prefixed encoding.
    #[test]
    fn test_compute_hash_resists_null_byte_collision() {
        // policy_hash="abc\x00GENESIS" with no parent vs policy_hash="abc" with parent="GENESIS"
        let h1 = PolicyCheckpoint::compute_hash(
            1,
            1,
            &ReleaseChannel::Stable,
            "abc\x00GENESIS",
            None,
            1000,
            "signer",
        );
        let h2 = PolicyCheckpoint::compute_hash(
            1,
            1,
            &ReleaseChannel::Stable,
            "abc",
            Some("GENESIS"),
            1000,
            "signer",
        );
        assert_ne!(
            h1, h2,
            "length-prefixed encoding must prevent null-byte boundary collision"
        );
    }

    /// Regression: field boundary collision.
    /// policy_hash="ab" + signer="cdef" must differ from policy_hash="abcd" + signer="ef".
    #[test]
    fn test_compute_hash_resists_field_boundary_collision() {
        let h1 = PolicyCheckpoint::compute_hash(
            1,
            1,
            &ReleaseChannel::Stable,
            "ab",
            Some("parent"),
            1000,
            "cdef",
        );
        let h2 = PolicyCheckpoint::compute_hash(
            1,
            1,
            &ReleaseChannel::Stable,
            "abcd",
            Some("parent"),
            1000,
            "ef",
        );
        assert_ne!(
            h1, h2,
            "length-prefixed encoding must prevent field boundary collision"
        );
    }

    #[test]
    fn test_compute_hash_resists_custom_channel_policy_boundary_collision() {
        let h1 = PolicyCheckpoint::compute_hash(
            1,
            1,
            &ReleaseChannel::Custom("ab".to_string()),
            "c",
            Some("parent"),
            1000,
            "signer",
        );
        let h2 = PolicyCheckpoint::compute_hash(
            1,
            1,
            &ReleaseChannel::Custom("a".to_string()),
            "bc",
            Some("parent"),
            1000,
            "signer",
        );

        assert_ne!(
            h1, h2,
            "length-prefixed channel labels must prevent custom-channel boundary collision"
        );
    }

    #[test]
    fn negative_push_bounded_zero_capacity_clears_existing_items() {
        let mut items = vec!["old".to_string()];

        push_bounded(&mut items, "new".to_string(), 0);

        assert!(items.is_empty());
    }

    #[test]
    fn negative_push_bounded_overfull_cap_one_keeps_only_newest_item() {
        let mut items = vec!["oldest".to_string(), "middle".to_string()];

        push_bounded(&mut items, "newest".to_string(), 1);

        assert_eq!(items, vec!["newest".to_string()]);
    }

    #[test]
    fn negative_checkpoint_deserialize_rejects_missing_signer() {
        let json = r#"{
            "sequence": 0,
            "epoch_id": 1,
            "channel": "Stable",
            "policy_hash": "abc",
            "parent_hash": null,
            "timestamp": 1000,
            "checkpoint_hash": "abc"
        }"#;

        let err = serde_json::from_str::<PolicyCheckpoint>(json).unwrap_err();

        assert!(err.to_string().contains("signer"));
    }

    #[test]
    fn negative_checkpoint_deserialize_rejects_string_sequence() {
        let json = r#"{
            "sequence": "0",
            "epoch_id": 1,
            "channel": "Stable",
            "policy_hash": "abc",
            "parent_hash": null,
            "timestamp": 1000,
            "signer": "alice",
            "checkpoint_hash": "abc"
        }"#;

        let err = serde_json::from_str::<PolicyCheckpoint>(json).unwrap_err();

        assert!(err.to_string().contains("invalid type"));
    }

    #[test]
    fn negative_chain_deserialize_rejects_missing_checkpoints() {
        let json = r#"{
            "head_hash": null,
            "next_seq": 0,
            "events": []
        }"#;

        let err = serde_json::from_str::<PolicyCheckpointChain>(json).unwrap_err();

        assert!(err.to_string().contains("checkpoints"));
    }

    #[test]
    fn negative_chain_deserialize_rejects_scalar_events() {
        let json = r#"{
            "checkpoints": [],
            "head_hash": null,
            "next_seq": 0,
            "events": "not-a-list"
        }"#;

        let err = serde_json::from_str::<PolicyCheckpointChain>(json).unwrap_err();

        assert!(err.to_string().contains("invalid type"));
    }

    #[test]
    fn negative_event_deserialize_rejects_missing_event_code() {
        let json = r#"{
            "event_name": "CHECKPOINT_CREATED",
            "trace_id": "trace-1",
            "epoch_id": 1,
            "sequence": 0,
            "channel": "stable",
            "detail": "created"
        }"#;

        let err = serde_json::from_str::<CheckpointChainEvent>(json).unwrap_err();

        assert!(err.to_string().contains("event_code"));
    }

    #[test]
    fn negative_release_channel_deserialize_rejects_scalar_custom_payload() {
        let err = serde_json::from_str::<ReleaseChannel>(r#"{"Custom":123}"#).unwrap_err();

        assert!(err.to_string().contains("invalid type"));
    }
}
