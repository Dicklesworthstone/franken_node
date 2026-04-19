//! bd-3g4k: Hash-chained VEF receipt stream with deterministic checkpoints.
//!
//! This module implements the append-only receipt chain that turns isolated
//! `ExecutionReceipt` objects into a tamper-evident, reproducible history.
//!
//! Invariants:
//! - INV-VEF-CHAIN-APPEND-ONLY: entries can only be appended, never mutated.
//! - INV-VEF-CHAIN-DETERMINISTIC: identical receipt sequences yield identical chain hashes.
//! - INV-VEF-CHAIN-CHECKPOINT-REPRODUCIBLE: checkpoints recompute to the same commitment hash.
//! - INV-VEF-CHAIN-FAIL-CLOSED: tampering is detected and reported with stable error codes.

use super::connector::vef_execution_receipt::{ExecutionReceipt, receipt_hash_sha256};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;

/// Constant-time string comparison (inline to avoid cross-crate path issues in test harnesses).
fn ct_eq_inline(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut acc = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        acc |= x ^ y;
    }
    acc == 0
}
use std::sync::{Arc, Mutex};

fn constant_time_eq(a: &str, b: &str) -> bool {
    let a_bytes = a.as_bytes();
    let b_bytes = b.as_bytes();
    if a_bytes.len() != b_bytes.len() {
        return false;
    }
    let mut diff = 0u8;
    for (lhs, rhs) in a_bytes.iter().zip(b_bytes.iter()) {
        diff |= *lhs ^ *rhs;
    }
    diff == 0
}

use frankenengine_node::capacity_defaults::aliases::{MAX_CHAIN_ENTRIES, MAX_CHECKPOINTS};

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

/// Stable schema version for chain serialization and hash material.
pub const RECEIPT_CHAIN_SCHEMA_VERSION: &str = "vef-receipt-chain-v1";

/// Stable chain invariants for documentation/checker parity.
#[allow(dead_code)]
pub const INV_VEF_CHAIN_APPEND_ONLY: &str = "INV-VEF-CHAIN-APPEND-ONLY";
#[allow(dead_code)]
pub const INV_VEF_CHAIN_DETERMINISTIC: &str = "INV-VEF-CHAIN-DETERMINISTIC";
#[allow(dead_code)]
pub const INV_VEF_CHAIN_CHECKPOINT_REPRODUCIBLE: &str = "INV-VEF-CHAIN-CHECKPOINT-REPRODUCIBLE";
#[allow(dead_code)]
pub const INV_VEF_CHAIN_FAIL_CLOSED: &str = "INV-VEF-CHAIN-FAIL-CLOSED";

/// Genesis predecessor hash used for entry index 0.
pub const GENESIS_PREV_HASH: &str =
    "sha256:0000000000000000000000000000000000000000000000000000000000000000";

pub mod event_codes {
    /// A receipt was appended to the chain.
    pub const VEF_CHAIN_001_APPENDED: &str = "VEF-CHAIN-001";
    /// A checkpoint commitment was created.
    pub const VEF_CHAIN_002_CHECKPOINT: &str = "VEF-CHAIN-002";
    /// Chain verification succeeded.
    pub const VEF_CHAIN_003_VERIFIED: &str = "VEF-CHAIN-003";
    /// Tamper or integrity failure.
    pub const VEF_CHAIN_ERR_001_TAMPER: &str = "VEF-CHAIN-ERR-001";
    /// Invalid checkpoint commitment.
    pub const VEF_CHAIN_ERR_002_CHECKPOINT: &str = "VEF-CHAIN-ERR-002";
    /// Invalid sequencing/linkage for entries.
    pub const VEF_CHAIN_ERR_003_SEQUENCE: &str = "VEF-CHAIN-ERR-003";
    /// Internal serialization/hashing failure.
    pub const VEF_CHAIN_ERR_004_INTERNAL: &str = "VEF-CHAIN-ERR-004";
}

pub mod error_codes {
    pub const ERR_VEF_CHAIN_TAMPER: &str = "ERR-VEF-CHAIN-TAMPER";
    pub const ERR_VEF_CHAIN_CHECKPOINT: &str = "ERR-VEF-CHAIN-CHECKPOINT";
    pub const ERR_VEF_CHAIN_SEQUENCE: &str = "ERR-VEF-CHAIN-SEQUENCE";
    pub const ERR_VEF_CHAIN_INTERNAL: &str = "ERR-VEF-CHAIN-INTERNAL";
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainError {
    pub code: String,
    pub event_code: String,
    pub message: String,
}

impl ChainError {
    fn tamper(message: impl Into<String>) -> Self {
        Self {
            code: error_codes::ERR_VEF_CHAIN_TAMPER.to_string(),
            event_code: event_codes::VEF_CHAIN_ERR_001_TAMPER.to_string(),
            message: message.into(),
        }
    }

    fn checkpoint(message: impl Into<String>) -> Self {
        Self {
            code: error_codes::ERR_VEF_CHAIN_CHECKPOINT.to_string(),
            event_code: event_codes::VEF_CHAIN_ERR_002_CHECKPOINT.to_string(),
            message: message.into(),
        }
    }

    fn sequence(message: impl Into<String>) -> Self {
        Self {
            code: error_codes::ERR_VEF_CHAIN_SEQUENCE.to_string(),
            event_code: event_codes::VEF_CHAIN_ERR_003_SEQUENCE.to_string(),
            message: message.into(),
        }
    }

    fn internal(message: impl Into<String>) -> Self {
        Self {
            code: error_codes::ERR_VEF_CHAIN_INTERNAL.to_string(),
            event_code: event_codes::VEF_CHAIN_ERR_004_INTERNAL.to_string(),
            message: message.into(),
        }
    }
}

impl fmt::Display for ChainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}", self.code, self.message)
    }
}

impl std::error::Error for ChainError {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainEvent {
    pub event_code: String,
    pub trace_id: String,
    pub detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptChainConfig {
    /// Create a checkpoint every N appended entries (`0` disables count trigger).
    pub checkpoint_every_entries: usize,
    /// Create a checkpoint every N milliseconds (`0` disables time trigger).
    pub checkpoint_every_millis: u64,
}

impl Default for ReceiptChainConfig {
    fn default() -> Self {
        Self {
            checkpoint_every_entries: 64,
            checkpoint_every_millis: 0,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptChainEntry {
    pub index: u64,
    pub prev_chain_hash: String,
    pub receipt_hash: String,
    pub chain_hash: String,
    pub receipt: ExecutionReceipt,
    pub appended_at_millis: u64,
    pub trace_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptCheckpoint {
    /// Sequential checkpoint number in this stream.
    pub checkpoint_id: u64,
    pub start_index: u64,
    pub end_index: u64,
    pub entry_count: u64,
    pub chain_head_hash: String,
    pub commitment_hash: String,
    pub created_at_millis: u64,
    pub trace_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppendOutcome {
    pub entry: ReceiptChainEntry,
    pub checkpoint: Option<ReceiptCheckpoint>,
    pub events: Vec<ChainEvent>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptChain {
    pub schema_version: String,
    pub config: ReceiptChainConfig,
    entries: Vec<ReceiptChainEntry>,
    checkpoints: Vec<ReceiptCheckpoint>,
    last_checkpoint_entry: usize,
    next_checkpoint_id: u64,
}

impl ReceiptChain {
    pub fn new(config: ReceiptChainConfig) -> Self {
        Self {
            schema_version: RECEIPT_CHAIN_SCHEMA_VERSION.to_string(),
            config,
            entries: Vec::new(),
            checkpoints: Vec::new(),
            last_checkpoint_entry: 0,
            next_checkpoint_id: 0,
        }
    }

    pub fn entries(&self) -> &[ReceiptChainEntry] {
        &self.entries
    }

    pub fn checkpoints(&self) -> &[ReceiptCheckpoint] {
        &self.checkpoints
    }

    pub fn append(
        &mut self,
        receipt: ExecutionReceipt,
        appended_at_millis: u64,
        trace_id: impl Into<String>,
    ) -> Result<AppendOutcome, ChainError> {
        if self.entries.len() >= MAX_CHAIN_ENTRIES {
            return Err(ChainError::internal(format!(
                "chain capacity exhausted ({MAX_CHAIN_ENTRIES} entries)"
            )));
        }
        let trace_id = trace_id.into();
        let receipt_hash = receipt_hash_sha256(&receipt)
            .map_err(|err| ChainError::internal(format!("receipt hash failed: {err}")))?;
        let index = u64::try_from(self.entries.len()).unwrap_or(u64::MAX);
        let prev_chain_hash = self.entries.last().map_or_else(
            || GENESIS_PREV_HASH.to_string(),
            |entry| entry.chain_hash.clone(),
        );
        let chain_hash = compute_chain_hash(index, &prev_chain_hash, &receipt_hash)?;

        let entry = ReceiptChainEntry {
            index,
            prev_chain_hash,
            receipt_hash,
            chain_hash,
            receipt,
            appended_at_millis,
            trace_id: trace_id.clone(),
        };
        push_bounded(&mut self.entries, entry.clone(), MAX_CHAIN_ENTRIES);

        let mut events = vec![ChainEvent {
            event_code: event_codes::VEF_CHAIN_001_APPENDED.to_string(),
            trace_id: trace_id.clone(),
            detail: format!("entry={} appended", entry.index),
        }];

        let checkpoint = if self.should_checkpoint(appended_at_millis) {
            let checkpoint = self.build_checkpoint(appended_at_millis, trace_id.clone())?;
            events.push(ChainEvent {
                event_code: event_codes::VEF_CHAIN_002_CHECKPOINT.to_string(),
                trace_id: trace_id.clone(),
                detail: format!(
                    "checkpoint={} range={}..{}",
                    checkpoint.checkpoint_id, checkpoint.start_index, checkpoint.end_index
                ),
            });
            Some(checkpoint)
        } else {
            None
        };

        Ok(AppendOutcome {
            entry,
            checkpoint,
            events,
        })
    }

    pub fn force_checkpoint(
        &mut self,
        now_millis: u64,
        trace_id: impl Into<String>,
    ) -> Result<Option<ReceiptCheckpoint>, ChainError> {
        if self.entries.len() == self.last_checkpoint_entry {
            return Ok(None);
        }
        let checkpoint = self.build_checkpoint(now_millis, trace_id.into())?;
        Ok(Some(checkpoint))
    }

    pub fn verify_integrity(&self) -> Result<Vec<ChainEvent>, ChainError> {
        Self::verify_entries_and_checkpoints(&self.entries, &self.checkpoints)?;
        Ok(vec![ChainEvent {
            event_code: event_codes::VEF_CHAIN_003_VERIFIED.to_string(),
            trace_id: "vef-chain-verify".to_string(),
            detail: format!(
                "verified entries={} checkpoints={}",
                self.entries.len(),
                self.checkpoints.len()
            ),
        }])
    }

    pub fn verify_entries_and_checkpoints(
        entries: &[ReceiptChainEntry],
        checkpoints: &[ReceiptCheckpoint],
    ) -> Result<(), ChainError> {
        for (idx, entry) in entries.iter().enumerate() {
            let expected_index = u64::try_from(idx).unwrap_or(u64::MAX);
            if entry.index != expected_index {
                return Err(ChainError::sequence(format!(
                    "entry index mismatch at offset {idx}: got {}, expected {expected_index}",
                    entry.index
                )));
            }

            let recomputed_receipt_hash = receipt_hash_sha256(&entry.receipt)
                .map_err(|err| ChainError::internal(format!("receipt re-hash failed: {err}")))?;
            if !constant_time_eq(&entry.receipt_hash, &recomputed_receipt_hash) {
                return Err(ChainError::tamper(format!(
                    "receipt hash mismatch at entry {}",
                    entry.index
                )));
            }

            let expected_prev = if idx == 0 {
                GENESIS_PREV_HASH
            } else {
                entries[idx - 1].chain_hash.as_str()
            };
            if !constant_time_eq(&entry.prev_chain_hash, expected_prev) {
                return Err(ChainError::sequence(format!(
                    "prev chain hash mismatch at entry {}",
                    entry.index
                )));
            }

            let expected_chain_hash =
                compute_chain_hash(entry.index, expected_prev, &entry.receipt_hash)?;
            if !constant_time_eq(&entry.chain_hash, &expected_chain_hash) {
                return Err(ChainError::tamper(format!(
                    "chain hash mismatch at entry {}",
                    entry.index
                )));
            }
        }

        let mut last_checkpoint_end: Option<u64> = None;
        for (idx, checkpoint) in checkpoints.iter().enumerate() {
            if checkpoint.checkpoint_id != u64::try_from(idx).unwrap_or(u64::MAX) {
                return Err(ChainError::checkpoint(format!(
                    "checkpoint_id mismatch at offset {idx}: got {}, expected {}",
                    checkpoint.checkpoint_id, idx
                )));
            }
            if checkpoint.end_index < checkpoint.start_index {
                return Err(ChainError::checkpoint(format!(
                    "invalid checkpoint range {}..{}",
                    checkpoint.start_index, checkpoint.end_index
                )));
            }
            if checkpoint.end_index >= u64::try_from(entries.len()).unwrap_or(u64::MAX) {
                return Err(ChainError::checkpoint(format!(
                    "checkpoint {} end index {} out of bounds for {} entries",
                    checkpoint.checkpoint_id,
                    checkpoint.end_index,
                    entries.len()
                )));
            }
            if let Some(prev_end) = last_checkpoint_end
                && checkpoint.start_index <= prev_end
            {
                return Err(ChainError::checkpoint(format!(
                    "checkpoint {} overlaps previous checkpoint",
                    checkpoint.checkpoint_id
                )));
            }
            let expected_entry_count = checkpoint
                .end_index
                .saturating_sub(checkpoint.start_index)
                .saturating_add(1);
            if checkpoint.entry_count != expected_entry_count {
                return Err(ChainError::checkpoint(format!(
                    "checkpoint {} entry_count mismatch",
                    checkpoint.checkpoint_id
                )));
            }
            let chain_head_index = usize::try_from(checkpoint.end_index)
                .map_err(|_| ChainError::checkpoint("checkpoint end index overflows usize"))?;
            let chain_head = entries[chain_head_index].chain_hash.as_str();
            if !ct_eq_inline(&checkpoint.chain_head_hash, chain_head) {
                return Err(ChainError::checkpoint(format!(
                    "checkpoint {} chain head mismatch",
                    checkpoint.checkpoint_id
                )));
            }

            let expected_commitment = compute_checkpoint_commitment(
                checkpoint.start_index,
                checkpoint.end_index,
                chain_head,
                entries,
            )?;
            if !ct_eq_inline(&checkpoint.commitment_hash, &expected_commitment) {
                return Err(ChainError::checkpoint(format!(
                    "checkpoint {} commitment hash mismatch",
                    checkpoint.checkpoint_id
                )));
            }
            last_checkpoint_end = Some(checkpoint.end_index);
        }

        Ok(())
    }

    pub fn resume_from_snapshot(
        config: ReceiptChainConfig,
        entries: Vec<ReceiptChainEntry>,
        checkpoints: Vec<ReceiptCheckpoint>,
    ) -> Result<Self, ChainError> {
        Self::verify_entries_and_checkpoints(&entries, &checkpoints)?;
        let last_checkpoint_entry = checkpoints
            .last()
            .map(|checkpoint| {
                usize::try_from(checkpoint.end_index)
                    .unwrap_or(usize::MAX)
                    .saturating_add(1)
            })
            .unwrap_or(0);
        let next_checkpoint_id = checkpoints
            .iter()
            .map(|c| c.checkpoint_id)
            .max()
            .map(|id| id.saturating_add(1))
            .unwrap_or(0);
        Ok(Self {
            schema_version: RECEIPT_CHAIN_SCHEMA_VERSION.to_string(),
            config,
            entries,
            checkpoints,
            last_checkpoint_entry,
            next_checkpoint_id,
        })
    }

    fn should_checkpoint(&self, now_millis: u64) -> bool {
        let entries_since_last = self
            .entries
            .len()
            .saturating_sub(self.last_checkpoint_entry);
        if entries_since_last == 0 {
            return false;
        }
        if self.config.checkpoint_every_entries > 0
            && entries_since_last >= self.config.checkpoint_every_entries
        {
            return true;
        }
        if self.config.checkpoint_every_millis > 0 {
            let last_checkpoint_time = self
                .checkpoints
                .last()
                .map_or(0, |checkpoint| checkpoint.created_at_millis);
            let elapsed = now_millis.saturating_sub(last_checkpoint_time);
            if elapsed >= self.config.checkpoint_every_millis {
                return true;
            }
        }
        false
    }

    fn build_checkpoint(
        &mut self,
        now_millis: u64,
        trace_id: String,
    ) -> Result<ReceiptCheckpoint, ChainError> {
        let start_index = u64::try_from(self.last_checkpoint_entry).unwrap_or(u64::MAX);
        let end_entry_index = self
            .entries
            .len()
            .checked_sub(1)
            .ok_or_else(|| ChainError::checkpoint("cannot checkpoint empty entry set"))?;
        let end_index = u64::try_from(end_entry_index).unwrap_or(u64::MAX);
        let chain_head_hash = self.entries[end_entry_index].chain_hash.clone();
        let commitment_hash =
            compute_checkpoint_commitment(start_index, end_index, &chain_head_hash, &self.entries)?;

        let checkpoint = ReceiptCheckpoint {
            checkpoint_id: self.next_checkpoint_id,
            start_index,
            end_index,
            entry_count: end_index.saturating_sub(start_index).saturating_add(1),
            chain_head_hash,
            commitment_hash,
            created_at_millis: now_millis,
            trace_id,
        };
        self.next_checkpoint_id = self.next_checkpoint_id.saturating_add(1);
        push_bounded(&mut self.checkpoints, checkpoint.clone(), MAX_CHECKPOINTS);
        self.last_checkpoint_entry = self.entries.len();
        Ok(checkpoint)
    }
}

/// Thread-safe wrapper providing linearizable append semantics via `Mutex`.
#[derive(Clone, Debug)]
pub struct ConcurrentReceiptChain {
    inner: Arc<Mutex<ReceiptChain>>,
}

impl ConcurrentReceiptChain {
    pub fn new(config: ReceiptChainConfig) -> Self {
        Self {
            inner: Arc::new(Mutex::new(ReceiptChain::new(config))),
        }
    }

    pub fn append(
        &self,
        receipt: ExecutionReceipt,
        appended_at_millis: u64,
        trace_id: impl Into<String>,
    ) -> Result<AppendOutcome, ChainError> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| ChainError::internal("receipt chain mutex poisoned"))?;
        guard.append(receipt, appended_at_millis, trace_id)
    }

    #[allow(dead_code)]
    pub fn force_checkpoint(
        &self,
        now_millis: u64,
        trace_id: impl Into<String>,
    ) -> Result<Option<ReceiptCheckpoint>, ChainError> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| ChainError::internal("receipt chain mutex poisoned"))?;
        guard.force_checkpoint(now_millis, trace_id)
    }

    pub fn snapshot(&self) -> Result<ReceiptChain, ChainError> {
        self.inner
            .lock()
            .map(|guard| guard.clone())
            .map_err(|_| ChainError::internal("receipt chain mutex poisoned"))
    }
}

fn compute_chain_hash(
    index: u64,
    prev_chain_hash: &str,
    receipt_hash: &str,
) -> Result<String, ChainError> {
    #[derive(Serialize)]
    struct LinkMaterial<'a> {
        schema_version: &'a str,
        index: u64,
        prev_chain_hash: &'a str,
        receipt_hash: &'a str,
    }

    let material = LinkMaterial {
        schema_version: RECEIPT_CHAIN_SCHEMA_VERSION,
        index,
        prev_chain_hash,
        receipt_hash,
    };
    let bytes = serde_json::to_vec(&material)
        .map_err(|err| ChainError::internal(format!("failed to serialize link material: {err}")))?;
    let mut hasher = Sha256::new();
    hasher.update(b"receipt_chain_hash_v1:");
    hasher.update(u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_le_bytes());
    hasher.update(&bytes);
    Ok(format!("sha256:{:x}", hasher.finalize()))
}

fn compute_checkpoint_commitment(
    start_index: u64,
    end_index: u64,
    chain_head_hash: &str,
    entries: &[ReceiptChainEntry],
) -> Result<String, ChainError> {
    let start = usize::try_from(start_index)
        .map_err(|_| ChainError::checkpoint("checkpoint start index overflows usize"))?;
    let end = usize::try_from(end_index)
        .map_err(|_| ChainError::checkpoint("checkpoint end index overflows usize"))?;
    let range = entries
        .get(start..=end)
        .ok_or_else(|| ChainError::checkpoint("checkpoint range out of bounds"))?;
    let entry_hashes = range
        .iter()
        .map(|entry| entry.chain_hash.as_str())
        .collect::<Vec<_>>();

    #[derive(Serialize)]
    struct CheckpointMaterial<'a> {
        schema_version: &'a str,
        start_index: u64,
        end_index: u64,
        entry_count: u64,
        chain_head_hash: &'a str,
        entry_chain_hashes: Vec<&'a str>,
    }

    let material = CheckpointMaterial {
        schema_version: RECEIPT_CHAIN_SCHEMA_VERSION,
        start_index,
        end_index,
        entry_count: u64::try_from(range.len()).unwrap_or(u64::MAX),
        chain_head_hash,
        entry_chain_hashes: entry_hashes,
    };

    let bytes = serde_json::to_vec(&material).map_err(|err| {
        ChainError::internal(format!("failed to serialize checkpoint material: {err}"))
    })?;
    let mut hasher = Sha256::new();
    hasher.update(b"receipt_chain_hash_v1:");
    hasher.update(u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_le_bytes());
    hasher.update(&bytes);
    Ok(format!("sha256:{:x}", hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::super::connector::vef_execution_receipt::{
        ExecutionActionType, RECEIPT_SCHEMA_VERSION,
    };
    use super::*;
    use std::collections::BTreeMap;
    use std::thread;

    fn make_receipt(action_type: ExecutionActionType, sequence_number: u64) -> ExecutionReceipt {
        let mut capability_context = BTreeMap::new();
        capability_context.insert(
            "capability".to_string(),
            format!("capability-{sequence_number}"),
        );
        capability_context.insert("domain".to_string(), "runtime".to_string());
        capability_context.insert("scope".to_string(), "extensions".to_string());

        let hex = format!("{sequence_number:064x}");
        ExecutionReceipt {
            schema_version: RECEIPT_SCHEMA_VERSION.to_string(),
            action_type,
            capability_context,
            actor_identity: format!("agent-{sequence_number}"),
            artifact_identity: format!("artifact-{sequence_number}"),
            policy_snapshot_hash: format!("sha256:{hex}"),
            timestamp_millis: 1_700_000_000_000 + sequence_number,
            sequence_number,
            witness_references: vec![
                format!("witness-{}", sequence_number % 3),
                format!("witness-{}", (sequence_number + 1) % 3),
            ],
            trace_id: format!("trace-{sequence_number}"),
        }
    }

    fn tamper_same_length_hash(input: &str) -> String {
        let mut chars: Vec<char> = input.chars().collect();
        let idx = chars
            .iter()
            .position(|ch| *ch != '0')
            .unwrap_or(chars.len().saturating_sub(1));
        chars[idx] = if chars[idx] == '0' { '1' } else { '0' };
        chars.into_iter().collect()
    }

    #[test]
    fn append_creates_genesis_link_at_index_zero() {
        let mut chain = ReceiptChain::new(ReceiptChainConfig::default());
        let outcome = chain
            .append(
                make_receipt(ExecutionActionType::NetworkAccess, 1),
                1_700_000_100_000,
                "trace-a",
            )
            .unwrap();

        assert_eq!(outcome.entry.index, 0);
        assert_eq!(outcome.entry.prev_chain_hash, GENESIS_PREV_HASH);
        assert!(outcome.entry.chain_hash.starts_with("sha256:"));
        assert_eq!(chain.entries().len(), 1);
    }

    #[test]
    fn deterministic_chain_hash_for_identical_receipt_sequence() {
        let config = ReceiptChainConfig {
            checkpoint_every_entries: 2,
            checkpoint_every_millis: 0,
        };
        let mut first = ReceiptChain::new(config);
        let mut second = ReceiptChain::new(config);

        for seq in 0..4_u64 {
            first
                .append(
                    make_receipt(ExecutionActionType::FilesystemOperation, seq),
                    1_700_000_200_000 + seq,
                    "trace-first",
                )
                .unwrap();
            second
                .append(
                    make_receipt(ExecutionActionType::FilesystemOperation, seq),
                    1_700_000_200_000 + seq,
                    "trace-second",
                )
                .unwrap();
        }

        let first_fingerprint = first
            .entries()
            .iter()
            .map(|entry| {
                (
                    entry.index,
                    entry.prev_chain_hash.clone(),
                    entry.receipt_hash.clone(),
                    entry.chain_hash.clone(),
                    entry.receipt.clone(),
                )
            })
            .collect::<Vec<_>>();
        let second_fingerprint = second
            .entries()
            .iter()
            .map(|entry| {
                (
                    entry.index,
                    entry.prev_chain_hash.clone(),
                    entry.receipt_hash.clone(),
                    entry.chain_hash.clone(),
                    entry.receipt.clone(),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(first_fingerprint, second_fingerprint);
        let first_checkpoint_fingerprint = first
            .checkpoints()
            .iter()
            .map(|checkpoint| {
                (
                    checkpoint.checkpoint_id,
                    checkpoint.start_index,
                    checkpoint.end_index,
                    checkpoint.entry_count,
                    checkpoint.chain_head_hash.clone(),
                    checkpoint.commitment_hash.clone(),
                    checkpoint.created_at_millis,
                )
            })
            .collect::<Vec<_>>();
        let second_checkpoint_fingerprint = second
            .checkpoints()
            .iter()
            .map(|checkpoint| {
                (
                    checkpoint.checkpoint_id,
                    checkpoint.start_index,
                    checkpoint.end_index,
                    checkpoint.entry_count,
                    checkpoint.chain_head_hash.clone(),
                    checkpoint.commitment_hash.clone(),
                    checkpoint.created_at_millis,
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(first_checkpoint_fingerprint, second_checkpoint_fingerprint);
    }

    #[test]
    fn checkpoint_created_by_entry_interval() {
        let mut chain = ReceiptChain::new(ReceiptChainConfig {
            checkpoint_every_entries: 2,
            checkpoint_every_millis: 0,
        });
        let first = chain
            .append(
                make_receipt(ExecutionActionType::ProcessSpawn, 1),
                1_700_000_300_001,
                "trace-1",
            )
            .unwrap();
        assert!(first.checkpoint.is_none());

        let second = chain
            .append(
                make_receipt(ExecutionActionType::ProcessSpawn, 2),
                1_700_000_300_002,
                "trace-2",
            )
            .unwrap();
        assert!(second.checkpoint.is_some());
        assert_eq!(chain.checkpoints().len(), 1);
        assert_eq!(chain.checkpoints()[0].start_index, 0);
        assert_eq!(chain.checkpoints()[0].end_index, 1);
    }

    #[test]
    fn force_checkpoint_emits_commitment_for_uncheckpointed_tail() {
        let mut chain = ReceiptChain::new(ReceiptChainConfig {
            checkpoint_every_entries: 0,
            checkpoint_every_millis: 0,
        });
        for seq in 0..3_u64 {
            chain
                .append(
                    make_receipt(ExecutionActionType::SecretAccess, seq),
                    1_700_000_400_000 + seq,
                    "trace-force",
                )
                .unwrap();
        }
        let checkpoint = chain
            .force_checkpoint(1_700_000_400_999, "trace-force-checkpoint")
            .unwrap()
            .unwrap();
        assert_eq!(checkpoint.start_index, 0);
        assert_eq!(checkpoint.end_index, 2);
        assert_eq!(chain.checkpoints().len(), 1);
    }

    #[test]
    fn detect_tamper_when_receipt_content_is_modified() {
        let mut chain = ReceiptChain::new(ReceiptChainConfig {
            checkpoint_every_entries: 3,
            checkpoint_every_millis: 0,
        });
        for seq in 0..3_u64 {
            chain
                .append(
                    make_receipt(ExecutionActionType::PolicyTransition, seq),
                    1_700_000_500_000 + seq,
                    "trace-tamper-content",
                )
                .unwrap();
        }

        let mut tampered_entries = chain.entries().to_vec();
        tampered_entries[1].receipt.actor_identity = "attacker".to_string();

        let err =
            ReceiptChain::verify_entries_and_checkpoints(&tampered_entries, chain.checkpoints())
                .unwrap_err();
        assert_eq!(err.code, error_codes::ERR_VEF_CHAIN_TAMPER);
    }

    #[test]
    fn detect_tamper_when_receipt_hash_is_same_length_modified() {
        let mut chain = ReceiptChain::new(ReceiptChainConfig {
            checkpoint_every_entries: 0,
            checkpoint_every_millis: 0,
        });
        for seq in 0..3_u64 {
            chain
                .append(
                    make_receipt(ExecutionActionType::PolicyTransition, seq),
                    1_700_000_550_000 + seq,
                    "trace-tamper-receipt-hash",
                )
                .unwrap();
        }

        let mut tampered_entries = chain.entries().to_vec();
        tampered_entries[1].receipt_hash =
            tamper_same_length_hash(&tampered_entries[1].receipt_hash);

        let err =
            ReceiptChain::verify_entries_and_checkpoints(&tampered_entries, chain.checkpoints())
                .unwrap_err();
        assert_eq!(err.code, error_codes::ERR_VEF_CHAIN_TAMPER);
    }

    #[test]
    fn detect_tamper_when_chain_hash_is_same_length_modified() {
        let mut chain = ReceiptChain::new(ReceiptChainConfig {
            checkpoint_every_entries: 0,
            checkpoint_every_millis: 0,
        });
        for seq in 0..3_u64 {
            chain
                .append(
                    make_receipt(ExecutionActionType::PolicyTransition, seq),
                    1_700_000_575_000 + seq,
                    "trace-tamper-chain-hash",
                )
                .unwrap();
        }

        let mut tampered_entries = chain.entries().to_vec();
        tampered_entries[2].chain_hash = tamper_same_length_hash(&tampered_entries[2].chain_hash);

        let err =
            ReceiptChain::verify_entries_and_checkpoints(&tampered_entries, chain.checkpoints())
                .unwrap_err();
        assert_eq!(err.code, error_codes::ERR_VEF_CHAIN_TAMPER);
    }

    #[test]
    fn detect_tamper_when_entry_order_changes() {
        let mut chain = ReceiptChain::new(ReceiptChainConfig {
            checkpoint_every_entries: 0,
            checkpoint_every_millis: 0,
        });
        for seq in 0..4_u64 {
            chain
                .append(
                    make_receipt(ExecutionActionType::ArtifactPromotion, seq),
                    1_700_000_600_000 + seq,
                    "trace-reorder",
                )
                .unwrap();
        }

        let mut reordered = chain.entries().to_vec();
        reordered.swap(1, 2);
        let err = ReceiptChain::verify_entries_and_checkpoints(&reordered, chain.checkpoints())
            .unwrap_err();
        assert_eq!(err.code, error_codes::ERR_VEF_CHAIN_SEQUENCE);
    }

    #[test]
    fn detect_tamper_when_middle_entry_deleted() {
        let mut chain = ReceiptChain::new(ReceiptChainConfig::default());
        for seq in 0..4_u64 {
            chain
                .append(
                    make_receipt(ExecutionActionType::NetworkAccess, seq),
                    1_700_000_700_000 + seq,
                    "trace-delete",
                )
                .unwrap();
        }
        let mut shortened = chain.entries().to_vec();
        shortened.remove(2);

        let err = ReceiptChain::verify_entries_and_checkpoints(&shortened, chain.checkpoints())
            .unwrap_err();
        assert_eq!(err.code, error_codes::ERR_VEF_CHAIN_SEQUENCE);
    }

    #[test]
    fn detect_checkpoint_forgery() {
        let mut chain = ReceiptChain::new(ReceiptChainConfig {
            checkpoint_every_entries: 2,
            checkpoint_every_millis: 0,
        });
        for seq in 0..2_u64 {
            chain
                .append(
                    make_receipt(ExecutionActionType::FilesystemOperation, seq),
                    1_700_000_800_000 + seq,
                    "trace-forgery",
                )
                .unwrap();
        }
        let mut forged_checkpoints = chain.checkpoints().to_vec();
        forged_checkpoints[0].commitment_hash =
            "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_string();

        let err =
            ReceiptChain::verify_entries_and_checkpoints(chain.entries(), &forged_checkpoints)
                .unwrap_err();
        assert_eq!(err.code, error_codes::ERR_VEF_CHAIN_CHECKPOINT);
    }

    #[test]
    fn resume_from_snapshot_rebuilds_valid_chain_state() {
        let mut chain = ReceiptChain::new(ReceiptChainConfig {
            checkpoint_every_entries: 2,
            checkpoint_every_millis: 0,
        });
        for seq in 0..5_u64 {
            chain
                .append(
                    make_receipt(ExecutionActionType::PolicyTransition, seq),
                    1_700_000_900_000 + seq,
                    "trace-resume",
                )
                .unwrap();
        }
        let resumed = ReceiptChain::resume_from_snapshot(
            chain.config,
            chain.entries().to_vec(),
            chain.checkpoints().to_vec(),
        )
        .unwrap();
        resumed.verify_integrity().unwrap();
        assert_eq!(resumed.entries(), chain.entries());
        assert_eq!(resumed.checkpoints(), chain.checkpoints());
    }

    #[test]
    fn concurrent_append_preserves_linearizable_integrity() {
        let chain = ConcurrentReceiptChain::new(ReceiptChainConfig {
            checkpoint_every_entries: 0,
            checkpoint_every_millis: 0,
        });

        let mut handles = Vec::new();
        for seq in 0..16_u64 {
            let chain = chain.clone();
            handles.push(thread::spawn(move || {
                chain
                    .append(
                        make_receipt(ExecutionActionType::SecretAccess, seq),
                        1_700_001_000_000 + seq,
                        format!("trace-concurrent-{seq}"),
                    )
                    .unwrap();
            }));
        }

        for handle in handles {
            handle.join().unwrap();
        }

        let snapshot = chain.snapshot().unwrap();
        assert_eq!(snapshot.entries().len(), 16);
        snapshot.verify_integrity().unwrap();
    }

    #[test]
    fn verify_integrity_emits_verified_event() {
        let mut chain = ReceiptChain::new(ReceiptChainConfig {
            checkpoint_every_entries: 2,
            checkpoint_every_millis: 0,
        });
        chain
            .append(
                make_receipt(ExecutionActionType::NetworkAccess, 1),
                1_700_001_100_001,
                "trace-verify-1",
            )
            .unwrap();
        chain
            .append(
                make_receipt(ExecutionActionType::NetworkAccess, 2),
                1_700_001_100_002,
                "trace-verify-2",
            )
            .unwrap();
        let events = chain.verify_integrity().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_code, event_codes::VEF_CHAIN_003_VERIFIED);
    }

    #[test]
    fn invalid_checkpoint_range_is_rejected() {
        let mut chain = ReceiptChain::new(ReceiptChainConfig::default());
        chain
            .append(
                make_receipt(ExecutionActionType::ArtifactPromotion, 10),
                1_700_001_200_000,
                "trace-invalid-checkpoint",
            )
            .unwrap();

        let mut invalid = chain.checkpoints().to_vec();
        invalid.push(ReceiptCheckpoint {
            checkpoint_id: 0,
            start_index: 1,
            end_index: 0,
            entry_count: 0,
            chain_head_hash: "sha256:abc".to_string(),
            commitment_hash: "sha256:def".to_string(),
            created_at_millis: 1_700_001_200_999,
            trace_id: "trace-invalid".to_string(),
        });

        let err =
            ReceiptChain::verify_entries_and_checkpoints(chain.entries(), &invalid).unwrap_err();
        assert_eq!(err.code, error_codes::ERR_VEF_CHAIN_CHECKPOINT);
    }

    #[test]
    fn first_entry_with_nonzero_index_is_rejected() {
        let mut chain = ReceiptChain::new(ReceiptChainConfig::default());
        chain
            .append(
                make_receipt(ExecutionActionType::NetworkAccess, 20),
                1_700_001_300_000,
                "trace-bad-first-index",
            )
            .unwrap();
        let mut entries = chain.entries().to_vec();
        entries[0].index = 1;

        let err = ReceiptChain::verify_entries_and_checkpoints(&entries, chain.checkpoints())
            .unwrap_err();

        assert_eq!(err.code, error_codes::ERR_VEF_CHAIN_SEQUENCE);
        assert!(err.message.contains("entry index mismatch"));
    }

    #[test]
    fn first_entry_with_non_genesis_prev_hash_is_rejected() {
        let mut chain = ReceiptChain::new(ReceiptChainConfig::default());
        chain
            .append(
                make_receipt(ExecutionActionType::FilesystemOperation, 21),
                1_700_001_300_021,
                "trace-bad-genesis",
            )
            .unwrap();
        let mut entries = chain.entries().to_vec();
        entries[0].prev_chain_hash =
            "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_string();

        let err = ReceiptChain::verify_entries_and_checkpoints(&entries, chain.checkpoints())
            .unwrap_err();

        assert_eq!(err.code, error_codes::ERR_VEF_CHAIN_SEQUENCE);
        assert!(err.message.contains("prev chain hash mismatch"));
    }

    #[test]
    fn checkpoint_id_gap_is_rejected() {
        let mut chain = ReceiptChain::new(ReceiptChainConfig {
            checkpoint_every_entries: 2,
            checkpoint_every_millis: 0,
        });
        for seq in 30..32_u64 {
            chain
                .append(
                    make_receipt(ExecutionActionType::PolicyTransition, seq),
                    1_700_001_300_000 + seq,
                    "trace-checkpoint-id-gap",
                )
                .unwrap();
        }
        let mut checkpoints = chain.checkpoints().to_vec();
        checkpoints[0].checkpoint_id = 7;

        let err = ReceiptChain::verify_entries_and_checkpoints(chain.entries(), &checkpoints)
            .unwrap_err();

        assert_eq!(err.code, error_codes::ERR_VEF_CHAIN_CHECKPOINT);
        assert!(err.message.contains("checkpoint_id mismatch"));
    }

    #[test]
    fn checkpoint_end_index_out_of_bounds_is_rejected() {
        let mut chain = ReceiptChain::new(ReceiptChainConfig {
            checkpoint_every_entries: 2,
            checkpoint_every_millis: 0,
        });
        for seq in 40..42_u64 {
            chain
                .append(
                    make_receipt(ExecutionActionType::SecretAccess, seq),
                    1_700_001_400_000 + seq,
                    "trace-checkpoint-oob",
                )
                .unwrap();
        }
        let mut checkpoints = chain.checkpoints().to_vec();
        checkpoints[0].end_index = 9;

        let err = ReceiptChain::verify_entries_and_checkpoints(chain.entries(), &checkpoints)
            .unwrap_err();

        assert_eq!(err.code, error_codes::ERR_VEF_CHAIN_CHECKPOINT);
        assert!(err.message.contains("out of bounds"));
    }

    #[test]
    fn checkpoint_entry_count_mismatch_is_rejected() {
        let mut chain = ReceiptChain::new(ReceiptChainConfig {
            checkpoint_every_entries: 2,
            checkpoint_every_millis: 0,
        });
        for seq in 50..52_u64 {
            chain
                .append(
                    make_receipt(ExecutionActionType::ArtifactPromotion, seq),
                    1_700_001_500_000 + seq,
                    "trace-checkpoint-count",
                )
                .unwrap();
        }
        let mut checkpoints = chain.checkpoints().to_vec();
        checkpoints[0].entry_count = 99;

        let err = ReceiptChain::verify_entries_and_checkpoints(chain.entries(), &checkpoints)
            .unwrap_err();

        assert_eq!(err.code, error_codes::ERR_VEF_CHAIN_CHECKPOINT);
        assert!(err.message.contains("entry_count mismatch"));
    }

    #[test]
    fn checkpoint_chain_head_mismatch_is_rejected() {
        let mut chain = ReceiptChain::new(ReceiptChainConfig {
            checkpoint_every_entries: 2,
            checkpoint_every_millis: 0,
        });
        for seq in 60..62_u64 {
            chain
                .append(
                    make_receipt(ExecutionActionType::ProcessSpawn, seq),
                    1_700_001_600_000 + seq,
                    "trace-checkpoint-head",
                )
                .unwrap();
        }
        let mut checkpoints = chain.checkpoints().to_vec();
        checkpoints[0].chain_head_hash = tamper_same_length_hash(&checkpoints[0].chain_head_hash);

        let err = ReceiptChain::verify_entries_and_checkpoints(chain.entries(), &checkpoints)
            .unwrap_err();

        assert_eq!(err.code, error_codes::ERR_VEF_CHAIN_CHECKPOINT);
        assert!(err.message.contains("chain head mismatch"));
    }

    #[test]
    fn overlapping_checkpoints_are_rejected() {
        let mut chain = ReceiptChain::new(ReceiptChainConfig {
            checkpoint_every_entries: 2,
            checkpoint_every_millis: 0,
        });
        for seq in 70..74_u64 {
            chain
                .append(
                    make_receipt(ExecutionActionType::PolicyTransition, seq),
                    1_700_001_700_000 + seq,
                    "trace-checkpoint-overlap",
                )
                .unwrap();
        }
        let mut checkpoints = chain.checkpoints().to_vec();
        checkpoints[1].start_index = checkpoints[0].end_index;

        let err = ReceiptChain::verify_entries_and_checkpoints(chain.entries(), &checkpoints)
            .unwrap_err();

        assert_eq!(err.code, error_codes::ERR_VEF_CHAIN_CHECKPOINT);
        assert!(err.message.contains("overlaps previous checkpoint"));
    }

    #[test]
    fn resume_from_snapshot_rejects_tampered_receipt_hash() {
        let mut chain = ReceiptChain::new(ReceiptChainConfig {
            checkpoint_every_entries: 0,
            checkpoint_every_millis: 0,
        });
        for seq in 80..83_u64 {
            chain
                .append(
                    make_receipt(ExecutionActionType::NetworkAccess, seq),
                    1_700_001_800_000 + seq,
                    "trace-resume-tamper",
                )
                .unwrap();
        }
        let mut entries = chain.entries().to_vec();
        entries[2].receipt_hash = tamper_same_length_hash(&entries[2].receipt_hash);

        let err =
            ReceiptChain::resume_from_snapshot(chain.config, entries, chain.checkpoints().to_vec())
                .unwrap_err();

        assert_eq!(err.code, error_codes::ERR_VEF_CHAIN_TAMPER);
    }

    #[test]
    fn push_bounded_zero_capacity_clears_without_appending_entry() {
        let mut entries = vec![ReceiptChainEntry {
            index: 0,
            prev_chain_hash: GENESIS_PREV_HASH.to_string(),
            receipt_hash: "sha256:old".to_string(),
            chain_hash: "sha256:old-chain".to_string(),
            receipt: make_receipt(ExecutionActionType::NetworkAccess, 90),
            appended_at_millis: 1_700_001_900_000,
            trace_id: "trace-old".to_string(),
        }];
        let replacement = ReceiptChainEntry {
            index: 1,
            prev_chain_hash: "sha256:old-chain".to_string(),
            receipt_hash: "sha256:new".to_string(),
            chain_hash: "sha256:new-chain".to_string(),
            receipt: make_receipt(ExecutionActionType::NetworkAccess, 91),
            appended_at_millis: 1_700_001_900_001,
            trace_id: "trace-new".to_string(),
        };

        push_bounded(&mut entries, replacement, 0);

        assert!(entries.is_empty());
    }

    #[test]
    fn verify_integrity_rejects_internal_receipt_hash_tamper() {
        let mut chain = ReceiptChain::new(ReceiptChainConfig {
            checkpoint_every_entries: 0,
            checkpoint_every_millis: 0,
        });
        chain
            .append(
                make_receipt(ExecutionActionType::SecretAccess, 92),
                1_700_001_900_092,
                "trace-integrity-receipt",
            )
            .unwrap();
        chain.entries[0].receipt_hash = tamper_same_length_hash(&chain.entries[0].receipt_hash);

        let err = chain.verify_integrity().unwrap_err();

        assert_eq!(err.code, error_codes::ERR_VEF_CHAIN_TAMPER);
        assert!(err.message.contains("receipt hash mismatch"));
    }

    #[test]
    fn verify_integrity_rejects_internal_checkpoint_commitment_tamper() {
        let mut chain = ReceiptChain::new(ReceiptChainConfig {
            checkpoint_every_entries: 2,
            checkpoint_every_millis: 0,
        });
        for seq in 93..95_u64 {
            chain
                .append(
                    make_receipt(ExecutionActionType::FilesystemOperation, seq),
                    1_700_001_900_000 + seq,
                    "trace-integrity-checkpoint",
                )
                .unwrap();
        }
        chain.checkpoints[0].commitment_hash =
            tamper_same_length_hash(&chain.checkpoints[0].commitment_hash);

        let err = chain.verify_integrity().unwrap_err();

        assert_eq!(err.code, error_codes::ERR_VEF_CHAIN_CHECKPOINT);
        assert!(err.message.contains("commitment hash mismatch"));
    }

    #[test]
    fn checkpoint_without_entries_is_rejected() {
        let checkpoint = ReceiptCheckpoint {
            checkpoint_id: 0,
            start_index: 0,
            end_index: 0,
            entry_count: 1,
            chain_head_hash: "sha256:head".to_string(),
            commitment_hash: "sha256:commitment".to_string(),
            created_at_millis: 1_700_001_900_100,
            trace_id: "trace-empty-checkpoint".to_string(),
        };

        let err = ReceiptChain::verify_entries_and_checkpoints(&[], &[checkpoint]).unwrap_err();

        assert_eq!(err.code, error_codes::ERR_VEF_CHAIN_CHECKPOINT);
        assert!(err.message.contains("out of bounds"));
    }

    #[test]
    fn checkpoint_commitment_range_out_of_bounds_is_rejected() {
        let err = compute_checkpoint_commitment(1, 1, "sha256:head", &[]).unwrap_err();

        assert_eq!(err.code, error_codes::ERR_VEF_CHAIN_CHECKPOINT);
        assert!(err.message.contains("checkpoint range out of bounds"));
    }

    #[test]
    fn resume_from_snapshot_rejects_checkpoint_commitment_mismatch() {
        let mut chain = ReceiptChain::new(ReceiptChainConfig {
            checkpoint_every_entries: 2,
            checkpoint_every_millis: 0,
        });
        for seq in 96..98_u64 {
            chain
                .append(
                    make_receipt(ExecutionActionType::ArtifactPromotion, seq),
                    1_700_001_900_000 + seq,
                    "trace-resume-checkpoint-tamper",
                )
                .unwrap();
        }
        let mut checkpoints = chain.checkpoints().to_vec();
        checkpoints[0].commitment_hash = tamper_same_length_hash(&checkpoints[0].commitment_hash);

        let err =
            ReceiptChain::resume_from_snapshot(chain.config, chain.entries().to_vec(), checkpoints)
                .unwrap_err();

        assert_eq!(err.code, error_codes::ERR_VEF_CHAIN_CHECKPOINT);
        assert!(err.message.contains("commitment hash mismatch"));
    }

    #[test]
    fn ct_eq_inline_rejects_truncated_equal_prefix() {
        assert!(!ct_eq_inline("sha256:abcdef", "sha256:abc"));
    }

    #[test]
    fn constant_time_eq_rejects_same_length_hash_mutation() {
        let original = "sha256:abcdef0123456789";
        let mutated = "sha256:abcdef0123456788";

        assert!(!constant_time_eq(original, mutated));
    }

    #[test]
    fn chain_hash_length_prefixes_link_material() {
        #[derive(Serialize)]
        struct LinkMaterial<'a> {
            schema_version: &'a str,
            index: u64,
            prev_chain_hash: &'a str,
            receipt_hash: &'a str,
        }

        let material = LinkMaterial {
            schema_version: RECEIPT_CHAIN_SCHEMA_VERSION,
            index: 7,
            prev_chain_hash: GENESIS_PREV_HASH,
            receipt_hash: "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
        };
        let bytes = serde_json::to_vec(&material).unwrap();
        let mut expected_hasher = Sha256::new();
        expected_hasher.update(b"receipt_chain_hash_v1:");
        expected_hasher.update(u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_le_bytes());
        expected_hasher.update(&bytes);

        let mut unprefixed_hasher = Sha256::new();
        unprefixed_hasher.update(b"receipt_chain_hash_v1:");
        unprefixed_hasher.update(&bytes);

        let actual = compute_chain_hash(
            material.index,
            material.prev_chain_hash,
            material.receipt_hash,
        )
        .unwrap();
        let expected = format!("sha256:{:x}", expected_hasher.finalize());
        let unprefixed = format!("sha256:{:x}", unprefixed_hasher.finalize());

        assert_eq!(actual, expected);
        assert_ne!(actual, unprefixed);
    }

    #[test]
    fn checkpoint_commitment_length_prefixes_canonical_material() {
        #[derive(Serialize)]
        struct CheckpointMaterial<'a> {
            schema_version: &'a str,
            start_index: u64,
            end_index: u64,
            entry_count: u64,
            chain_head_hash: &'a str,
            entry_chain_hashes: Vec<&'a str>,
        }

        let mut chain = ReceiptChain::new(ReceiptChainConfig {
            checkpoint_every_entries: 0,
            checkpoint_every_millis: 0,
        });
        for seq in 0..2_u64 {
            chain
                .append(
                    make_receipt(ExecutionActionType::PolicyTransition, seq),
                    1_700_002_000_000_u64.saturating_add(seq),
                    "trace-length-prefix-checkpoint",
                )
                .unwrap();
        }

        let chain_head_hash = chain.entries()[1].chain_hash.as_str();
        let entry_chain_hashes = chain
            .entries()
            .iter()
            .map(|entry| entry.chain_hash.as_str())
            .collect::<Vec<_>>();
        let material = CheckpointMaterial {
            schema_version: RECEIPT_CHAIN_SCHEMA_VERSION,
            start_index: 0,
            end_index: 1,
            entry_count: 2,
            chain_head_hash,
            entry_chain_hashes,
        };
        let bytes = serde_json::to_vec(&material).unwrap();
        let mut expected_hasher = Sha256::new();
        expected_hasher.update(b"receipt_chain_hash_v1:");
        expected_hasher.update(u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_le_bytes());
        expected_hasher.update(&bytes);

        let mut unprefixed_hasher = Sha256::new();
        unprefixed_hasher.update(b"receipt_chain_hash_v1:");
        unprefixed_hasher.update(&bytes);

        let actual = compute_checkpoint_commitment(0, 1, chain_head_hash, chain.entries()).unwrap();
        let expected = format!("sha256:{:x}", expected_hasher.finalize());
        let unprefixed = format!("sha256:{:x}", unprefixed_hasher.finalize());

        assert_eq!(actual, expected);
        assert_ne!(actual, unprefixed);
    }
}
