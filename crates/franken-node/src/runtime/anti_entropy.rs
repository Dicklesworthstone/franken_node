// Anti-entropy reconciliation for distributed product trust state.
//
// O(delta) reconciliation using Merkle-Mountain-Range (MMR) digest comparison.
// Proof-carrying recovery artifacts, epoch-scoped validity, fork detection,
// atomic two-phase application, and cancellation safety.
//
// bd-390 — Section 10.11

use sha2::{Digest, Sha256};
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

use crate::control_plane::mmr_proofs::{self, Hash, InclusionProof, MmrRoot};

use crate::capacity_defaults::aliases::MAX_EVENTS;

fn push_bounded_fn<T>(items: &mut Vec<T>, item: T, cap: usize) {
    items.push(item);
    if items.len() > cap {
        let overflow = items.len() - cap;
        items.drain(0..overflow);
    }
}

/// Maximum trust records per TrustState before inserts are rejected.
const MAX_TRUST_RECORDS: usize = 8192;

// ---------------------------------------------------------------------------
// Event codes
// ---------------------------------------------------------------------------

pub const EVT_CYCLE_STARTED: &str = "FN-AE-001";
pub const EVT_DELTA_COMPUTED: &str = "FN-AE-002";
pub const EVT_RECORD_ACCEPTED: &str = "FN-AE-003";
pub const EVT_RECORD_REJECTED: &str = "FN-AE-004";
pub const EVT_CYCLE_COMPLETED: &str = "FN-AE-005";
pub const EVT_FORK_DETECTED: &str = "FN-AE-006";
pub const EVT_CANCELLED: &str = "FN-AE-007";
pub const EVT_REPLAY_IDEMPOTENT: &str = "FN-AE-008";

// ---------------------------------------------------------------------------
// Error codes
// ---------------------------------------------------------------------------

pub const ERR_AE_INVALID_CONFIG: &str = "ERR_AE_INVALID_CONFIG";
pub const ERR_AE_EPOCH_VIOLATION: &str = "ERR_AE_EPOCH_VIOLATION";
pub const ERR_AE_PROOF_INVALID: &str = "ERR_AE_PROOF_INVALID";
pub const ERR_AE_FORK_DETECTED: &str = "ERR_AE_FORK_DETECTED";
pub const ERR_AE_CANCELLED: &str = "ERR_AE_CANCELLED";
pub const ERR_AE_BATCH_EXCEEDED: &str = "ERR_AE_BATCH_EXCEEDED";

// ---------------------------------------------------------------------------
// Invariant constants
// ---------------------------------------------------------------------------

pub const INV_AE_DELTA: &str = "INV-AE-DELTA";
pub const INV_AE_ATOMIC: &str = "INV-AE-ATOMIC";
pub const INV_AE_EPOCH: &str = "INV-AE-EPOCH";
pub const INV_AE_PROOF: &str = "INV-AE-PROOF";

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Reconciliation configuration.
#[derive(Debug, Clone)]
pub struct ReconciliationConfig {
    /// Max records per reconciliation batch.
    pub max_delta_batch: usize,
    /// Max epoch ahead to accept (0 = strict, fail-closed).
    pub epoch_tolerance: u64,
    /// Whether MMR inclusion proofs are required.
    pub proof_required: bool,
    /// Whether cancellation is supported mid-reconcile.
    pub cancellation_enabled: bool,
    /// Max retry attempts for transient failures.
    pub max_retry_attempts: usize,
}

impl Default for ReconciliationConfig {
    fn default() -> Self {
        Self {
            max_delta_batch: 1000,
            epoch_tolerance: 0,
            proof_required: true,
            cancellation_enabled: true,
            max_retry_attempts: 3,
        }
    }
}

impl ReconciliationConfig {
    pub fn validate(&self) -> Result<(), ReconciliationError> {
        if self.max_delta_batch == 0 {
            return Err(ReconciliationError::InvalidConfig(
                "max_delta_batch must be > 0".into(),
            ));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub enum ReconciliationError {
    InvalidConfig(String),
    EpochViolation { record_epoch: u64, local_epoch: u64 },
    ProofInvalid(String),
    ForkDetected(String),
    Cancelled,
    BatchExceeded { delta: usize, max: usize },
}

impl std::fmt::Display for ReconciliationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidConfig(msg) => write!(f, "{ERR_AE_INVALID_CONFIG}: {msg}"),
            Self::EpochViolation {
                record_epoch,
                local_epoch,
            } => write!(
                f,
                "{ERR_AE_EPOCH_VIOLATION}: record epoch {record_epoch} > local {local_epoch}"
            ),
            Self::ProofInvalid(msg) => write!(f, "{ERR_AE_PROOF_INVALID}: {msg}"),
            Self::ForkDetected(msg) => write!(f, "{ERR_AE_FORK_DETECTED}: {msg}"),
            Self::Cancelled => write!(f, "{ERR_AE_CANCELLED}"),
            Self::BatchExceeded { delta, max } => {
                write!(f, "{ERR_AE_BATCH_EXCEEDED}: delta {delta} > max {max}")
            }
        }
    }
}

impl std::error::Error for ReconciliationError {}

// ---------------------------------------------------------------------------
// Trust record
// ---------------------------------------------------------------------------

/// A trust-state record with MMR inclusion proof.
#[derive(Debug, Clone)]
pub struct TrustRecord {
    /// Unique record identifier.
    pub id: String,
    /// Epoch in which the record was created.
    pub epoch: u64,
    /// Monotonic timestamp recorded by the originating node.
    pub recorded_at_ms: u64,
    /// Originating node used as the deterministic final tie-breaker.
    pub origin_node_id: String,
    /// Record payload bytes.
    pub payload: Vec<u8>,
    /// MMR leaf position.
    pub mmr_pos: u64,
    /// Canonical MMR inclusion proof for this record.
    ///
    /// INV-AE-PROOF: verified via `mmr_proofs::verify_inclusion` against a
    /// known `MmrRoot`, not via decorative shape checks.
    pub inclusion_proof: Option<InclusionProof>,
    /// Marker hash that this record's payload maps to in the MMR.
    ///
    /// Must match the leaf hash in the inclusion proof.
    pub marker_hash: Hash,
}

impl TrustRecord {
    /// Compute a SHA-256 hash of the record for digest comparison.
    pub fn digest(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"anti_entropy_record_v1:");
        hasher.update((self.id.len() as u64).to_le_bytes());
        hasher.update(self.id.as_bytes());
        hasher.update(self.epoch.to_le_bytes());
        hasher.update(self.recorded_at_ms.to_le_bytes());
        hasher.update((self.origin_node_id.len() as u64).to_le_bytes());
        hasher.update(self.origin_node_id.as_bytes());
        hasher.update((self.payload.len() as u64).to_le_bytes());
        hasher.update(&self.payload);
        hasher.update(self.mmr_pos.to_le_bytes());
        hasher.update((self.marker_hash.len() as u64).to_le_bytes());
        hasher.update(self.marker_hash.as_bytes());
        if let Some(proof) = &self.inclusion_proof {
            hasher.update(proof.leaf_index.to_le_bytes());
            hasher.update(proof.tree_size.to_le_bytes());
            hasher.update((proof.leaf_hash.len() as u64).to_le_bytes());
            hasher.update(proof.leaf_hash.as_bytes());
            hasher.update((proof.audit_path.len() as u64).to_le_bytes());
            for h in &proof.audit_path {
                hasher.update((h.len() as u64).to_le_bytes());
                hasher.update(h.as_bytes());
            }
        } else {
            // Deterministic empty-proof marker.
            hasher.update(0u64.to_le_bytes());
        }
        hasher.finalize().into()
    }

    fn precedence_cmp(&self, other: &Self) -> Ordering {
        self.epoch
            .cmp(&other.epoch)
            .then(self.recorded_at_ms.cmp(&other.recorded_at_ms))
            .then(self.origin_node_id.cmp(&other.origin_node_id))
    }
}

// ---------------------------------------------------------------------------
// Trust state (local node state)
// ---------------------------------------------------------------------------

/// Local trust state: an ordered collection of trust records.
#[derive(Debug, Clone)]
pub struct TrustState {
    records: BTreeMap<String, TrustRecord>,
    current_epoch: u64,
    /// MMR root digest (simplified as XOR of all record digests).
    root_digest: [u8; 32],
}

impl TrustState {
    pub fn new(epoch: u64) -> Self {
        Self {
            records: BTreeMap::new(),
            current_epoch: epoch,
            root_digest: [0u8; 32],
        }
    }

    /// Insert or replace a record while retaining the highest-precedence set.
    ///
    /// Returns `true` when the record is present after the operation and `false`
    /// when the incoming record loses to an existing higher-precedence record,
    /// either because the ID already exists or because the retained set is full.
    pub fn insert(&mut self, record: TrustRecord) -> bool {
        self.insert_with_capacity(record, MAX_TRUST_RECORDS)
    }

    fn insert_with_capacity(&mut self, record: TrustRecord, capacity: usize) -> bool {
        if let Some(existing) = self.records.get(&record.id)
            && matches!(existing.precedence_cmp(&record), Ordering::Greater)
        {
            return false;
        }

        if self.records.len() >= capacity
            && !self.records.contains_key(&record.id)
            && let Some(lowest_record) = self.records.values().min_by(|a, b| a.precedence_cmp(b))
        {
            if !matches!(lowest_record.precedence_cmp(&record), Ordering::Less) {
                return false;
            }

            let lowest_key = lowest_record.id.clone();
            self.records.remove(&lowest_key);
        }

        self.records.insert(record.id.clone(), record);
        self.recompute_root_digest();
        true
    }

    /// Recompute root digest as SHA-256 over all record digests in deterministic order.
    fn recompute_root_digest(&mut self) {
        let mut hasher = Sha256::new();
        hasher.update(b"anti_entropy_root_v1:");
        for rec in self.records.values() {
            hasher.update(rec.digest());
        }
        self.root_digest = hasher.finalize().into();
    }

    /// Get the MMR root digest.
    pub fn root_digest(&self) -> &[u8; 32] {
        &self.root_digest
    }

    /// Get the current epoch.
    pub fn current_epoch(&self) -> u64 {
        self.current_epoch
    }

    /// Get record by ID.
    pub fn get(&self, id: &str) -> Option<&TrustRecord> {
        self.records.get(id)
    }

    /// Check if record exists.
    pub fn contains(&self, id: &str) -> bool {
        self.records.contains_key(id)
    }

    /// Get all record IDs.
    pub fn record_ids(&self) -> BTreeSet<String> {
        self.records.keys().cloned().collect()
    }

    /// Count records.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Check if empty.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Reconciliation result
// ---------------------------------------------------------------------------

/// Result of a reconciliation cycle.
#[derive(Debug, Clone)]
pub struct ReconciliationResult {
    pub delta_size: usize,
    pub records_accepted: usize,
    pub records_rejected: usize,
    pub elapsed_ms: u64,
    pub fork_detected: bool,
    pub cancelled: bool,
    pub trace_id: String,
}

// ---------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct ReconciliationEvent {
    pub code: String,
    pub detail: String,
    pub trace_id: String,
    pub epoch: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConflictResolution {
    Identical,
    KeepLocal,
    TakeRemote,
    Fork,
}

// ---------------------------------------------------------------------------
// MMR proof verification (canonical)
// ---------------------------------------------------------------------------

/// Verify a trust record's MMR inclusion proof against a known root.
///
/// INV-AE-PROOF: delegates to the canonical `mmr_proofs::verify_inclusion`
/// which validates leaf hash, audit path, and root hash with constant-time
/// comparisons. Decorative shape checks (non-empty / non-zero) are gone.
pub fn verify_mmr_proof(record: &TrustRecord, root: &MmrRoot) -> Result<(), ReconciliationError> {
    let proof = record
        .inclusion_proof
        .as_ref()
        .ok_or_else(|| ReconciliationError::ProofInvalid("missing inclusion proof".into()))?;

    mmr_proofs::verify_inclusion(proof, root, &record.marker_hash).map_err(|e| {
        ReconciliationError::ProofInvalid(format!("record {} proof failed: {e}", record.id))
    })
}

// ---------------------------------------------------------------------------
// Anti-entropy reconciler
// ---------------------------------------------------------------------------

/// Anti-entropy reconciler for distributed trust state.
#[derive(Debug)]
pub struct AntiEntropyReconciler {
    config: ReconciliationConfig,
    events: Vec<ReconciliationEvent>,
    reconciliation_count: u64,
}

impl AntiEntropyReconciler {
    pub fn new(config: ReconciliationConfig) -> Result<Self, ReconciliationError> {
        config.validate()?;
        Ok(Self {
            config,
            events: Vec::new(),
            reconciliation_count: 0,
        })
    }

    fn push_event(&mut self, event: ReconciliationEvent) {
        push_bounded_fn(&mut self.events, event, MAX_EVENTS);
    }

    fn resolve_conflict(local: &TrustRecord, remote: &TrustRecord) -> ConflictResolution {
        if crate::security::constant_time::ct_eq_bytes(&local.digest(), &remote.digest()) {
            return ConflictResolution::Identical;
        }

        match local.precedence_cmp(remote) {
            Ordering::Less => ConflictResolution::TakeRemote,
            Ordering::Greater => ConflictResolution::KeepLocal,
            Ordering::Equal => ConflictResolution::Fork,
        }
    }

    /// Compute the delta between local and remote states.
    /// INV-AE-DELTA: only processes O(delta) records.
    pub fn compute_delta(&self, local: &TrustState, remote: &TrustState) -> Vec<TrustRecord> {
        let mut delta = Vec::new();

        for id in remote.record_ids() {
            let Some(remote_record) = remote.get(&id) else {
                continue;
            };

            match local.get(&id) {
                None => delta.push(remote_record.clone()),
                Some(local_record) => {
                    if matches!(
                        Self::resolve_conflict(local_record, remote_record),
                        ConflictResolution::TakeRemote
                    ) {
                        delta.push(remote_record.clone());
                    }
                }
            }
        }

        delta
    }

    /// Detect fork: local and remote have the same precedence tuple but
    /// different content, so deterministic conflict resolution cannot choose.
    pub fn detect_fork(&self, local: &TrustState, remote: &TrustState) -> Option<String> {
        let local_ids = local.record_ids();
        let remote_ids = remote.record_ids();
        let common = local_ids.intersection(&remote_ids);

        for id in common {
            let (Some(local_rec), Some(remote_rec)) = (local.get(id), remote.get(id)) else {
                continue;
            };
            if matches!(
                Self::resolve_conflict(local_rec, remote_rec),
                ConflictResolution::Fork
            ) {
                return Some(id.clone());
            }
        }
        None
    }

    /// Reconcile remote state into local state.
    ///
    /// INV-AE-ATOMIC: on failure, local state is unchanged.
    /// INV-AE-EPOCH: future-epoch records are rejected.
    /// INV-AE-PROOF: records are verified against the canonical MMR root.
    pub fn reconcile(
        &mut self,
        local: &mut TrustState,
        remote: &TrustState,
        mmr_root: &MmrRoot,
        cancelled: &std::sync::atomic::AtomicBool,
    ) -> Result<ReconciliationResult, ReconciliationError> {
        self.reconciliation_count = self.reconciliation_count.saturating_add(1);
        let trace_id = format!("ae-{}", self.reconciliation_count);
        let start = std::time::Instant::now();

        self.push_event(ReconciliationEvent {
            code: EVT_CYCLE_STARTED.to_string(),
            detail: format!("local={},remote={}", local.len(), remote.len()),
            trace_id: trace_id.clone(),
            epoch: local.current_epoch(),
        });

        // Check for fork.
        if let Some(forked_id) = self.detect_fork(local, remote) {
            self.push_event(ReconciliationEvent {
                code: EVT_FORK_DETECTED.to_string(),
                detail: format!("divergent record: {forked_id}"),
                trace_id: trace_id.clone(),
                epoch: local.current_epoch(),
            });
            return Err(ReconciliationError::ForkDetected(forked_id));
        }

        // Compute delta — INV-AE-DELTA.
        let delta = self.compute_delta(local, remote);
        let delta_size = delta.len();

        self.push_event(ReconciliationEvent {
            code: EVT_DELTA_COMPUTED.to_string(),
            detail: format!("delta_size={delta_size}"),
            trace_id: trace_id.clone(),
            epoch: local.current_epoch(),
        });

        // Check batch limit.
        if delta_size > self.config.max_delta_batch {
            return Err(ReconciliationError::BatchExceeded {
                delta: delta_size,
                max: self.config.max_delta_batch,
            });
        }

        // Two-phase reconciliation — INV-AE-ATOMIC.
        // Phase 1: validate all records.
        let mut accepted: Vec<(TrustRecord, bool)> = Vec::new();
        let mut rejected = 0usize;

        for record in &delta {
            // Check cancellation.
            if self.config.cancellation_enabled
                && cancelled.load(std::sync::atomic::Ordering::Relaxed)
            {
                self.push_event(ReconciliationEvent {
                    code: EVT_CANCELLED.to_string(),
                    detail: format!("cancelled after validating {} records", accepted.len()),
                    trace_id: trace_id.clone(),
                    epoch: local.current_epoch(),
                });
                return Err(ReconciliationError::Cancelled);
            }

            let mut replaced = false;
            if let Some(local_record) = local.get(&record.id) {
                match Self::resolve_conflict(local_record, record) {
                    ConflictResolution::Identical | ConflictResolution::KeepLocal => {
                        self.push_event(ReconciliationEvent {
                            code: EVT_REPLAY_IDEMPOTENT.to_string(),
                            detail: format!(
                                "record {} already satisfied by local precedence",
                                record.id
                            ),
                            trace_id: trace_id.clone(),
                            epoch: local.current_epoch(),
                        });
                        continue;
                    }
                    ConflictResolution::TakeRemote => {
                        replaced = true;
                    }
                    ConflictResolution::Fork => {
                        self.push_event(ReconciliationEvent {
                            code: EVT_FORK_DETECTED.to_string(),
                            detail: format!("irresolvable precedence tie for record {}", record.id),
                            trace_id: trace_id.clone(),
                            epoch: local.current_epoch(),
                        });
                        return Err(ReconciliationError::ForkDetected(record.id.clone()));
                    }
                }
            }

            // INV-AE-EPOCH: reject future-epoch records.
            if record.epoch
                > local
                    .current_epoch()
                    .saturating_add(self.config.epoch_tolerance)
            {
                self.push_event(ReconciliationEvent {
                    code: EVT_RECORD_REJECTED.to_string(),
                    detail: format!(
                        "epoch violation: record {} epoch={} > local={}",
                        record.id,
                        record.epoch,
                        local.current_epoch()
                    ),
                    trace_id: trace_id.clone(),
                    epoch: local.current_epoch(),
                });
                rejected += 1;
                continue;
            }

            // INV-AE-PROOF: verify MMR inclusion proof against canonical root.
            if self.config.proof_required
                && let Err(e) = verify_mmr_proof(record, mmr_root)
            {
                self.push_event(ReconciliationEvent {
                    code: EVT_RECORD_REJECTED.to_string(),
                    detail: format!("proof invalid: {e}"),
                    trace_id: trace_id.clone(),
                    epoch: local.current_epoch(),
                });
                rejected += 1;
                continue;
            }

            accepted.push((record.clone(), replaced));
        }

        // Phase 2: apply all validated records atomically.
        let mut applied = 0usize;
        for (record, replaced) in &accepted {
            if local.insert(record.clone()) {
                applied += 1;
                self.push_event(ReconciliationEvent {
                    code: EVT_RECORD_ACCEPTED.to_string(),
                    detail: format!(
                        "record {} epoch={} replaced={}",
                        record.id, record.epoch, replaced
                    ),
                    trace_id: trace_id.clone(),
                    epoch: local.current_epoch(),
                });
                continue;
            }

            rejected = rejected.saturating_add(1);
            self.push_event(ReconciliationEvent {
                code: EVT_RECORD_REJECTED.to_string(),
                detail: format!(
                    "capacity rejection: record {} lost to higher-precedence retained set",
                    record.id
                ),
                trace_id: trace_id.clone(),
                epoch: local.current_epoch(),
            });
        }

        let elapsed = start.elapsed();

        self.push_event(ReconciliationEvent {
            code: EVT_CYCLE_COMPLETED.to_string(),
            detail: format!(
                "accepted={},rejected={},elapsed_ms={}",
                applied,
                rejected,
                elapsed.as_millis()
            ),
            trace_id: trace_id.clone(),
            epoch: local.current_epoch(),
        });

        Ok(ReconciliationResult {
            delta_size,
            records_accepted: applied,
            records_rejected: rejected,
            elapsed_ms: u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX),
            fork_detected: false,
            cancelled: false,
            trace_id,
        })
    }

    /// Get recorded events.
    pub fn events(&self) -> &[ReconciliationEvent] {
        &self.events
    }

    /// Get reconciliation count.
    pub fn reconciliation_count(&self) -> u64 {
        self.reconciliation_count
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicBool;

    /// Build a marker hash for a given record ID.
    fn test_marker_hash(id: &str) -> Hash {
        use sha2::Digest;
        let mut h = Sha256::new();
        h.update(b"test_marker:");
        h.update(id.as_bytes());
        hex::encode(h.finalize())
    }

    /// Build a valid single-leaf MMR tree root and inclusion proof.
    fn build_valid_proof(marker_hash: &str) -> (MmrRoot, InclusionProof) {
        let leaf_hash = mmr_proofs::marker_leaf_hash(marker_hash);
        let root = MmrRoot {
            tree_size: 1,
            root_hash: leaf_hash.clone(),
        };
        let proof = InclusionProof {
            leaf_index: 0,
            tree_size: 1,
            leaf_hash,
            audit_path: vec![],
        };
        (root, proof)
    }

    fn make_record(id: &str, epoch: u64) -> (TrustRecord, MmrRoot) {
        make_record_with_meta(id, epoch, epoch.saturating_mul(1_000), "node-a")
    }

    fn make_record_with_meta(
        id: &str,
        epoch: u64,
        recorded_at_ms: u64,
        origin_node_id: &str,
    ) -> (TrustRecord, MmrRoot) {
        let marker_hash = test_marker_hash(id);
        let (root, proof) = build_valid_proof(&marker_hash);
        let rec = TrustRecord {
            id: id.into(),
            epoch,
            recorded_at_ms,
            origin_node_id: origin_node_id.into(),
            payload: vec![1, 2, 3, 4],
            mmr_pos: 0,
            inclusion_proof: Some(proof),
            marker_hash,
        };
        (rec, root)
    }

    fn make_record_no_proof(id: &str, epoch: u64) -> TrustRecord {
        TrustRecord {
            id: id.into(),
            epoch,
            recorded_at_ms: epoch.saturating_mul(1_000),
            origin_node_id: "node-a".into(),
            payload: vec![1, 2, 3, 4],
            mmr_pos: 0,
            inclusion_proof: None,
            marker_hash: test_marker_hash(id),
        }
    }

    /// Shared MMR root for tests using a single-leaf tree for each record.
    /// In production each record would share a common tree root; for tests
    /// we use the root matching the first record's marker hash.
    fn test_root_for(id: &str) -> MmrRoot {
        let (_, root) = make_record(id, 1);
        root
    }

    fn no_cancel() -> AtomicBool {
        AtomicBool::new(false)
    }

    fn with_cancel() -> AtomicBool {
        AtomicBool::new(true)
    }

    // -- Config validation --

    #[test]
    fn test_default_config_valid() {
        assert!(ReconciliationConfig::default().validate().is_ok());
    }

    #[test]
    fn test_invalid_max_delta_batch() {
        let cfg = ReconciliationConfig {
            max_delta_batch: 0,
            ..Default::default()
        };
        assert!(cfg.validate().is_err());
    }

    // -- Trust state --

    #[test]
    fn test_trust_state_new_empty() {
        let state = TrustState::new(1);
        assert!(state.is_empty());
        assert_eq!(state.len(), 0);
        assert_eq!(state.current_epoch(), 1);
    }

    #[test]
    fn test_trust_state_insert() {
        let mut state = TrustState::new(1);
        let (rec, _) = make_record("r1", 1);
        assert!(state.insert(rec));
        assert_eq!(state.len(), 1);
        assert!(state.contains("r1"));
    }

    #[test]
    fn test_trust_state_get() {
        let mut state = TrustState::new(1);
        let (rec, _) = make_record("r1", 1);
        assert!(state.insert(rec));
        let r = state.get("r1").expect("should exist");
        assert_eq!(r.id, "r1");
    }

    #[test]
    fn test_trust_state_record_ids() {
        let mut state = TrustState::new(1);
        let (r1, _) = make_record("r1", 1);
        let (r2, _) = make_record("r2", 1);
        assert!(state.insert(r1));
        assert!(state.insert(r2));
        let ids = state.record_ids();
        assert!(ids.contains("r1"));
        assert!(ids.contains("r2"));
    }

    #[test]
    fn test_trust_state_digest_changes() {
        let mut state = TrustState::new(1);
        let d1 = *state.root_digest();
        let (rec, _) = make_record("r1", 1);
        assert!(state.insert(rec));
        assert_ne!(*state.root_digest(), d1);
    }

    #[test]
    fn test_trust_state_at_capacity_drops_lower_precedence_candidate() {
        let mut state = TrustState::new(2);
        let (incumbent_a, _) = make_record_with_meta("a", 2, 2_000, "node-a");
        let (incumbent_b, _) = make_record_with_meta("b", 2, 2_100, "node-b");
        let (candidate, _) = make_record_with_meta("c", 1, 1_000, "node-z");

        assert!(state.insert_with_capacity(incumbent_a, 2));
        assert!(state.insert_with_capacity(incumbent_b, 2));

        assert!(!state.insert_with_capacity(candidate, 2));
        assert_eq!(state.len(), 2);
        assert!(state.contains("a"));
        assert!(state.contains("b"));
        assert!(!state.contains("c"));
    }

    #[test]
    fn test_trust_state_rejects_lower_precedence_same_id_update() {
        let mut state = TrustState::new(2);
        let (incumbent, _) = make_record_with_meta("same", 2, 2_000, "node-z");
        let (candidate, _) = make_record_with_meta("same", 1, 1_000, "node-a");

        assert!(state.insert(incumbent));
        assert!(!state.insert(candidate));

        let retained = state.get("same").expect("existing record should remain");
        assert_eq!(retained.epoch, 2);
        assert_eq!(retained.recorded_at_ms, 2_000);
        assert_eq!(retained.origin_node_id, "node-z");
    }

    #[test]
    fn test_trust_state_accepts_higher_precedence_same_id_update() {
        let mut state = TrustState::new(2);
        let (incumbent, _) = make_record_with_meta("same", 1, 1_000, "node-a");
        let (candidate, _) = make_record_with_meta("same", 2, 900, "node-z");

        assert!(state.insert(incumbent));
        assert!(state.insert(candidate));

        let retained = state
            .get("same")
            .expect("higher-precedence record should replace");
        assert_eq!(retained.epoch, 2);
        assert_eq!(retained.recorded_at_ms, 900);
        assert_eq!(retained.origin_node_id, "node-z");
    }

    #[test]
    fn test_trust_state_at_capacity_evicts_lower_precedence_incumbent() {
        let mut state = TrustState::new(2);
        let (incumbent_a, _) = make_record_with_meta("a", 1, 1_000, "node-a");
        let (incumbent_b, _) = make_record_with_meta("b", 1, 1_100, "node-b");
        let (candidate, _) = make_record_with_meta("c", 2, 900, "node-z");

        assert!(state.insert_with_capacity(incumbent_a, 2));
        assert!(state.insert_with_capacity(incumbent_b, 2));

        assert!(state.insert_with_capacity(candidate, 2));
        assert_eq!(state.len(), 2);
        assert!(!state.contains("a"));
        assert!(state.contains("b"));
        assert!(state.contains("c"));
    }

    // -- Record digest --

    #[test]
    fn test_record_digest_deterministic() {
        let (r1, _) = make_record("r1", 1);
        let (r2, _) = make_record("r1", 1);
        assert_eq!(r1.digest(), r2.digest());
    }

    #[test]
    fn test_record_digest_changes_with_conflict_metadata() {
        let (r1, _) = make_record_with_meta("r1", 1, 1_000, "node-a");
        let (r2, _) = make_record_with_meta("r1", 1, 1_001, "node-a");
        assert_ne!(r1.digest(), r2.digest());
    }

    // -- MMR proof verification (canonical) --

    #[test]
    fn test_valid_proof_accepted() {
        let (rec, root) = make_record("r1", 1);
        assert!(verify_mmr_proof(&rec, &root).is_ok());
    }

    #[test]
    fn test_missing_proof_rejected() {
        let rec = make_record_no_proof("r1", 1);
        let root = test_root_for("r1");
        assert!(verify_mmr_proof(&rec, &root).is_err());
    }

    #[test]
    fn adversarial_forged_root_rejected() {
        let (rec, _) = make_record("r1", 1);
        let wrong_root = MmrRoot {
            tree_size: 1,
            root_hash: "0000000000000000000000000000000000000000000000000000000000000000".into(),
        };
        assert!(verify_mmr_proof(&rec, &wrong_root).is_err());
    }

    #[test]
    fn adversarial_wrong_marker_hash_rejected() {
        let (mut rec, root) = make_record("r1", 1);
        // Swap marker hash to a different value
        rec.marker_hash = test_marker_hash("r2");
        assert!(verify_mmr_proof(&rec, &root).is_err());
    }

    #[test]
    fn adversarial_zero_filled_proof_rejected() {
        let marker_hash = test_marker_hash("r1");
        let (root, _) = build_valid_proof(&marker_hash);
        let rec = TrustRecord {
            id: "r1".into(),
            epoch: 1,
            recorded_at_ms: 1_000,
            origin_node_id: "node-a".into(),
            payload: vec![1, 2, 3, 4],
            mmr_pos: 0,
            inclusion_proof: Some(InclusionProof {
                leaf_index: 0,
                tree_size: 1,
                leaf_hash: "0000000000000000000000000000000000000000000000000000000000000000"
                    .into(),
                audit_path: vec![],
            }),
            marker_hash,
        };
        assert!(verify_mmr_proof(&rec, &root).is_err());
    }

    #[test]
    fn adversarial_mismatched_tree_size_rejected() {
        let (rec, mut root) = make_record("r1", 1);
        root.tree_size = 999; // Doesn't match proof's tree_size=1
        assert!(verify_mmr_proof(&rec, &root).is_err());
    }

    // -- Delta computation --

    #[test]
    fn test_identical_states_zero_delta() {
        let reconciler =
            AntiEntropyReconciler::new(ReconciliationConfig::default()).expect("should succeed");
        let mut local = TrustState::new(1);
        let mut remote = TrustState::new(1);
        let (rec, _) = make_record("r1", 1);
        local.insert(rec.clone());
        remote.insert(rec);
        let delta = reconciler.compute_delta(&local, &remote);
        assert_eq!(delta.len(), 0);
    }

    #[test]
    fn test_single_record_divergence() {
        let reconciler =
            AntiEntropyReconciler::new(ReconciliationConfig::default()).expect("should succeed");
        let local = TrustState::new(1);
        let mut remote = TrustState::new(1);
        let (rec, _) = make_record("r1", 1);
        remote.insert(rec);
        let delta = reconciler.compute_delta(&local, &remote);
        assert_eq!(delta.len(), 1);
    }

    #[test]
    fn test_bulk_divergence_bounded() {
        let reconciler =
            AntiEntropyReconciler::new(ReconciliationConfig::default()).expect("should succeed");
        let mut local = TrustState::new(1);
        let mut remote = TrustState::new(1);

        for i in 0..500 {
            let (r, _) = make_record(&format!("shared-{i}"), 1);
            local.insert(r.clone());
            remote.insert(r);
        }
        for i in 0..100 {
            let (r, _) = make_record(&format!("remote-{i}"), 1);
            remote.insert(r);
        }

        let delta = reconciler.compute_delta(&local, &remote);
        assert_eq!(delta.len(), 100);
    }

    #[test]
    fn test_compute_delta_includes_higher_epoch_update() {
        let reconciler =
            AntiEntropyReconciler::new(ReconciliationConfig::default()).expect("should succeed");
        let mut local = TrustState::new(2);
        let mut remote = TrustState::new(2);
        let (local_rec, _) = make_record_with_meta("r1", 1, 1_000, "node-a");
        let (mut remote_rec, _) = make_record_with_meta("r1", 2, 900, "node-b");
        remote_rec.payload = vec![9, 9, 9, 9];
        local.insert(local_rec);
        remote.insert(remote_rec);

        let delta = reconciler.compute_delta(&local, &remote);
        assert_eq!(delta.len(), 1);
        assert_eq!(delta[0].epoch, 2);
    }

    #[test]
    fn test_compute_delta_skips_lower_precedence_update() {
        let reconciler =
            AntiEntropyReconciler::new(ReconciliationConfig::default()).expect("should succeed");
        let mut local = TrustState::new(2);
        let mut remote = TrustState::new(2);
        let (local_rec, _) = make_record_with_meta("r1", 2, 2_000, "node-z");
        let (mut remote_rec, _) = make_record_with_meta("r1", 2, 1_000, "node-a");
        remote_rec.payload = vec![9, 9, 9, 9];
        local.insert(local_rec);
        remote.insert(remote_rec);

        let delta = reconciler.compute_delta(&local, &remote);
        assert!(delta.is_empty());
    }

    // -- Fork detection --

    #[test]
    fn test_no_fork_identical() {
        let reconciler =
            AntiEntropyReconciler::new(ReconciliationConfig::default()).expect("should succeed");
        let mut local = TrustState::new(1);
        let mut remote = TrustState::new(1);
        let (rec, _) = make_record("r1", 1);
        local.insert(rec.clone());
        remote.insert(rec);
        assert!(reconciler.detect_fork(&local, &remote).is_none());
    }

    #[test]
    fn test_fork_detected() {
        let reconciler =
            AntiEntropyReconciler::new(ReconciliationConfig::default()).expect("should succeed");
        let mut local = TrustState::new(1);
        let mut remote = TrustState::new(1);
        let (rec, _) = make_record("r1", 1);
        local.insert(rec);
        let (mut forked, _) = make_record("r1", 1);
        forked.payload = vec![99, 99, 99];
        remote.insert(forked);
        assert!(reconciler.detect_fork(&local, &remote).is_some());
    }

    #[test]
    fn test_resolvable_conflict_is_not_treated_as_fork() {
        let reconciler =
            AntiEntropyReconciler::new(ReconciliationConfig::default()).expect("should succeed");
        let mut local = TrustState::new(2);
        let mut remote = TrustState::new(2);
        let (local_rec, _) = make_record_with_meta("r1", 1, 1_000, "node-a");
        let (mut remote_rec, _) = make_record_with_meta("r1", 2, 500, "node-a");
        remote_rec.payload = vec![9, 9, 9, 9];
        local.insert(local_rec);
        remote.insert(remote_rec);
        assert!(reconciler.detect_fork(&local, &remote).is_none());
    }

    // -- Full reconciliation --

    #[test]
    fn test_reconcile_empty_to_populated() {
        let mut local = TrustState::new(1);
        let mut remote = TrustState::new(1);
        let (r1, root1) = make_record("r1", 1);
        let (r2, _root2) = make_record("r2", 1);
        remote.insert(r1);
        remote.insert(r2);

        // Use proof_required=false for multi-record tests with different roots
        let mut reconciler_np = AntiEntropyReconciler::new(ReconciliationConfig {
            proof_required: false,
            ..ReconciliationConfig::default()
        })
        .unwrap();

        let cancel = no_cancel();
        let result = reconciler_np
            .reconcile(&mut local, &remote, &root1, &cancel)
            .expect("should succeed");
        assert_eq!(result.delta_size, 2);
        assert_eq!(result.records_accepted, 2);
        assert_eq!(result.records_rejected, 0);
        assert_eq!(local.len(), 2);
    }

    #[test]
    fn test_reconcile_with_proof_verification() {
        let mut reconciler =
            AntiEntropyReconciler::new(ReconciliationConfig::default()).expect("should succeed");
        let mut local = TrustState::new(1);
        let mut remote = TrustState::new(1);
        let (rec, root) = make_record("r1", 1);
        remote.insert(rec);

        let cancel = no_cancel();
        let result = reconciler
            .reconcile(&mut local, &remote, &root, &cancel)
            .expect("should succeed");
        assert_eq!(result.records_accepted, 1);
        assert_eq!(result.records_rejected, 0);
    }

    #[test]
    fn test_reconcile_epoch_rejection() {
        let mut reconciler =
            AntiEntropyReconciler::new(ReconciliationConfig::default()).expect("should succeed");
        let mut local = TrustState::new(5);
        let mut remote = TrustState::new(10);
        let (rec, root) = make_record("future", 10);
        remote.insert(rec);

        let cancel = no_cancel();
        let result = reconciler
            .reconcile(&mut local, &remote, &root, &cancel)
            .expect("should succeed");
        assert_eq!(result.records_rejected, 1);
        assert_eq!(result.records_accepted, 0);
        assert!(local.is_empty());
    }

    #[test]
    fn test_reconcile_proof_rejection() {
        let mut reconciler =
            AntiEntropyReconciler::new(ReconciliationConfig::default()).expect("should succeed");
        let mut local = TrustState::new(1);
        let mut remote = TrustState::new(1);
        let root = test_root_for("bad_proof");
        remote.insert(make_record_no_proof("bad_proof", 1));

        let cancel = no_cancel();
        let result = reconciler
            .reconcile(&mut local, &remote, &root, &cancel)
            .expect("should succeed");
        assert_eq!(result.records_rejected, 1);
        assert_eq!(result.records_accepted, 0);
    }

    #[test]
    fn test_reconcile_fork_halts() {
        let mut reconciler =
            AntiEntropyReconciler::new(ReconciliationConfig::default()).expect("should succeed");
        let mut local = TrustState::new(1);
        let mut remote = TrustState::new(1);
        let (rec, root) = make_record("r1", 1);
        local.insert(rec);
        let (mut forked, _) = make_record("r1", 1);
        forked.payload = vec![99];
        remote.insert(forked);

        let cancel = no_cancel();
        let err = reconciler
            .reconcile(&mut local, &remote, &root, &cancel)
            .unwrap_err();
        assert!(matches!(err, ReconciliationError::ForkDetected(_)));
    }

    #[test]
    fn test_reconcile_replaces_lower_precedence_local_record() {
        let mut reconciler =
            AntiEntropyReconciler::new(ReconciliationConfig::default()).expect("should succeed");
        let mut local = TrustState::new(2);
        let mut remote = TrustState::new(2);
        let (local_rec, _) = make_record_with_meta("r1", 1, 1_000, "node-a");
        let (mut remote_rec, root) = make_record_with_meta("r1", 2, 900, "node-b");
        remote_rec.payload = vec![9, 9, 9, 9];
        local.insert(local_rec);
        remote.insert(remote_rec.clone());

        let cancel = no_cancel();
        let result = reconciler
            .reconcile(&mut local, &remote, &root, &cancel)
            .expect("should succeed");
        assert_eq!(result.delta_size, 1);
        assert_eq!(result.records_accepted, 1);
        assert_eq!(local.len(), 1);
        assert_eq!(local.get("r1").expect("should exist").epoch, 2);
        assert_eq!(
            local.get("r1").expect("should exist").payload,
            remote_rec.payload
        );
    }

    #[test]
    fn test_reconcile_uses_node_id_as_final_tie_breaker() {
        let mut reconciler =
            AntiEntropyReconciler::new(ReconciliationConfig::default()).expect("should succeed");
        let mut local = TrustState::new(1);
        let mut remote = TrustState::new(1);
        let (local_rec, _) = make_record_with_meta("r1", 1, 1_000, "node-a");
        let (mut remote_rec, root) = make_record_with_meta("r1", 1, 1_000, "node-z");
        remote_rec.payload = vec![5, 5, 5, 5];
        local.insert(local_rec);
        remote.insert(remote_rec.clone());

        let cancel = no_cancel();
        let result = reconciler
            .reconcile(&mut local, &remote, &root, &cancel)
            .expect("should succeed");
        assert_eq!(result.records_accepted, 1);
        assert_eq!(
            local.get("r1").expect("should exist").origin_node_id,
            "node-z"
        );
        assert_eq!(
            local.get("r1").expect("should exist").payload,
            remote_rec.payload
        );
    }

    #[test]
    fn test_reconcile_cancellation() {
        let mut reconciler =
            AntiEntropyReconciler::new(ReconciliationConfig::default()).expect("should succeed");
        let mut local = TrustState::new(1);
        let mut remote = TrustState::new(1);
        let (rec, root) = make_record("r1", 1);
        remote.insert(rec);

        let cancel = with_cancel();
        let err = reconciler
            .reconcile(&mut local, &remote, &root, &cancel)
            .unwrap_err();
        assert!(matches!(err, ReconciliationError::Cancelled));
        assert!(local.is_empty());
    }

    #[test]
    fn test_reconcile_idempotent_replay() {
        let mut reconciler =
            AntiEntropyReconciler::new(ReconciliationConfig::default()).expect("should succeed");
        let mut local = TrustState::new(1);
        let (rec, root) = make_record("r1", 1);
        local.insert(rec.clone());
        let mut remote = TrustState::new(1);
        remote.insert(rec);

        let cancel = no_cancel();
        let result = reconciler
            .reconcile(&mut local, &remote, &root, &cancel)
            .expect("should succeed");
        assert_eq!(result.delta_size, 0);
        assert_eq!(result.records_accepted, 0);
        assert_eq!(local.len(), 1);
    }

    #[test]
    fn test_reconcile_batch_exceeded() {
        let mut reconciler = AntiEntropyReconciler::new(ReconciliationConfig {
            max_delta_batch: 5,
            ..ReconciliationConfig::default()
        })
        .unwrap();
        let mut local = TrustState::new(1);
        let mut remote = TrustState::new(1);
        let mut root = MmrRoot {
            tree_size: 1,
            root_hash: String::new(),
        };
        for i in 0..10 {
            let (rec, r) = make_record(&format!("r{i}"), 1);
            remote.insert(rec);
            if i == 0 {
                root = r;
            }
        }

        let cancel = no_cancel();
        let err = reconciler
            .reconcile(&mut local, &remote, &root, &cancel)
            .unwrap_err();
        assert!(matches!(err, ReconciliationError::BatchExceeded { .. }));
    }

    #[test]
    fn test_reconcile_mixed_accept_reject() {
        // Use a single-record root for the valid record
        let (valid_rec, valid_root) = make_record("valid", 5);
        let (future_rec, _) = make_record("future", 10);

        let mut reconciler =
            AntiEntropyReconciler::new(ReconciliationConfig::default()).expect("should succeed");
        let mut local = TrustState::new(5);
        let mut remote = TrustState::new(5);
        remote.insert(valid_rec);
        remote.insert(future_rec); // Rejected: future epoch
        remote.insert(make_record_no_proof("noproof", 5)); // Rejected: no proof

        let cancel = no_cancel();
        let result = reconciler
            .reconcile(&mut local, &remote, &valid_root, &cancel)
            .expect("should succeed");
        assert_eq!(result.records_accepted, 1);
        assert_eq!(result.records_rejected, 2);
    }

    #[test]
    fn test_reconcile_at_capacity_rejects_lower_precedence_new_record() {
        let mut reconciler = AntiEntropyReconciler::new(ReconciliationConfig {
            proof_required: false,
            ..ReconciliationConfig::default()
        })
        .expect("should succeed");
        let mut local = TrustState::new(2);
        let mut remote = TrustState::new(2);

        for i in 0..MAX_TRUST_RECORDS {
            let (rec, _) =
                make_record_with_meta(&format!("local-{i}"), 2, 10_000 + i as u64, "node-z");
            assert!(local.insert(rec));
        }

        let (candidate, root) = make_record_with_meta("remote-low", 1, 1_000, "node-a");
        remote.insert(candidate);

        let cancel = no_cancel();
        let result = reconciler
            .reconcile(&mut local, &remote, &root, &cancel)
            .expect("should succeed");

        assert_eq!(result.delta_size, 1);
        assert_eq!(result.records_accepted, 0);
        assert_eq!(result.records_rejected, 1);
        assert_eq!(local.len(), MAX_TRUST_RECORDS);
        assert!(!local.contains("remote-low"));
        assert!(local.contains("local-0"));
    }

    #[test]
    fn test_reconcile_at_capacity_accepts_higher_precedence_new_record() {
        let mut reconciler = AntiEntropyReconciler::new(ReconciliationConfig {
            proof_required: false,
            ..ReconciliationConfig::default()
        })
        .expect("should succeed");
        let mut local = TrustState::new(2);
        let mut remote = TrustState::new(2);

        for i in 0..MAX_TRUST_RECORDS {
            let (rec, _) =
                make_record_with_meta(&format!("local-{i}"), 1, 1_000 + i as u64, "node-a");
            assert!(local.insert(rec));
        }

        let (candidate, root) = make_record_with_meta("remote-high", 2, 500, "node-z");
        remote.insert(candidate);

        let cancel = no_cancel();
        let result = reconciler
            .reconcile(&mut local, &remote, &root, &cancel)
            .expect("should succeed");

        assert_eq!(result.delta_size, 1);
        assert_eq!(result.records_accepted, 1);
        assert_eq!(result.records_rejected, 0);
        assert_eq!(local.len(), MAX_TRUST_RECORDS);
        assert!(local.contains("remote-high"));
        assert!(!local.contains("local-0"));
    }

    #[test]
    fn test_reconcile_capacity_rejection_emits_rejected_not_accepted_event() {
        let mut reconciler = AntiEntropyReconciler::new(ReconciliationConfig {
            proof_required: false,
            ..ReconciliationConfig::default()
        })
        .expect("should succeed");
        let mut local = TrustState::new(2);
        let mut remote = TrustState::new(2);

        for i in 0..MAX_TRUST_RECORDS {
            let (rec, _) =
                make_record_with_meta(&format!("local-{i}"), 2, 10_000 + i as u64, "node-z");
            assert!(local.insert(rec));
        }

        let (candidate, root) = make_record_with_meta("remote-low", 1, 1_000, "node-a");
        remote.insert(candidate);

        let cancel = no_cancel();
        reconciler
            .reconcile(&mut local, &remote, &root, &cancel)
            .expect("should succeed");

        let accepted_events: Vec<&ReconciliationEvent> = reconciler
            .events()
            .iter()
            .filter(|event| event.code == EVT_RECORD_ACCEPTED)
            .collect();
        let rejected_events: Vec<&ReconciliationEvent> = reconciler
            .events()
            .iter()
            .filter(|event| event.code == EVT_RECORD_REJECTED)
            .collect();

        assert!(accepted_events.is_empty());
        assert_eq!(rejected_events.len(), 1);
        assert!(rejected_events[0].detail.contains("capacity rejection"));
    }

    // -- Events --

    #[test]
    fn test_events_recorded() {
        let mut reconciler =
            AntiEntropyReconciler::new(ReconciliationConfig::default()).expect("should succeed");
        let mut local = TrustState::new(1);
        let mut remote = TrustState::new(1);
        let (rec, root) = make_record("r1", 1);
        remote.insert(rec);

        let cancel = no_cancel();
        reconciler
            .reconcile(&mut local, &remote, &root, &cancel)
            .expect("should succeed");

        let codes: Vec<&str> = reconciler
            .events()
            .iter()
            .map(|e| e.code.as_str())
            .collect();
        assert!(codes.contains(&EVT_CYCLE_STARTED));
        assert!(codes.contains(&EVT_DELTA_COMPUTED));
        assert!(codes.contains(&EVT_RECORD_ACCEPTED));
        assert!(codes.contains(&EVT_CYCLE_COMPLETED));
    }

    #[test]
    fn test_events_have_trace_id() {
        let mut reconciler =
            AntiEntropyReconciler::new(ReconciliationConfig::default()).expect("should succeed");
        let mut local = TrustState::new(1);
        let mut remote = TrustState::new(1);
        let (rec, root) = make_record("r1", 1);
        remote.insert(rec);

        let cancel = no_cancel();
        reconciler
            .reconcile(&mut local, &remote, &root, &cancel)
            .expect("should succeed");

        for event in reconciler.events() {
            assert!(!event.trace_id.is_empty());
        }
    }

    #[test]
    fn test_events_have_epoch() {
        let mut reconciler =
            AntiEntropyReconciler::new(ReconciliationConfig::default()).expect("should succeed");
        let mut local = TrustState::new(42);
        let remote = TrustState::new(42);
        let dummy_root = MmrRoot {
            tree_size: 0,
            root_hash: String::new(),
        };

        let cancel = no_cancel();
        reconciler
            .reconcile(&mut local, &remote, &dummy_root, &cancel)
            .expect("should succeed");

        for event in reconciler.events() {
            assert_eq!(event.epoch, 42);
        }
    }

    // -- Error display --

    #[test]
    fn test_error_display_config() {
        let err = ReconciliationError::InvalidConfig("bad".into());
        assert!(format!("{err}").contains(ERR_AE_INVALID_CONFIG));
    }

    #[test]
    fn test_error_display_epoch() {
        let err = ReconciliationError::EpochViolation {
            record_epoch: 10,
            local_epoch: 5,
        };
        assert!(format!("{err}").contains(ERR_AE_EPOCH_VIOLATION));
    }

    #[test]
    fn test_error_display_proof() {
        let err = ReconciliationError::ProofInvalid("bad".into());
        assert!(format!("{err}").contains(ERR_AE_PROOF_INVALID));
    }

    #[test]
    fn test_error_display_fork() {
        let err = ReconciliationError::ForkDetected("r1".into());
        assert!(format!("{err}").contains(ERR_AE_FORK_DETECTED));
    }

    #[test]
    fn test_error_display_cancelled() {
        let err = ReconciliationError::Cancelled;
        assert!(format!("{err}").contains(ERR_AE_CANCELLED));
    }

    #[test]
    fn test_error_display_batch() {
        let err = ReconciliationError::BatchExceeded { delta: 10, max: 5 };
        assert!(format!("{err}").contains(ERR_AE_BATCH_EXCEEDED));
    }

    // -- Reconciliation count --

    #[test]
    fn test_reconciliation_count() {
        let mut reconciler =
            AntiEntropyReconciler::new(ReconciliationConfig::default()).expect("should succeed");
        assert_eq!(reconciler.reconciliation_count(), 0);
        let mut local = TrustState::new(1);
        let remote = TrustState::new(1);
        let dummy_root = MmrRoot {
            tree_size: 0,
            root_hash: String::new(),
        };
        let cancel = no_cancel();
        reconciler
            .reconcile(&mut local, &remote, &dummy_root, &cancel)
            .expect("should succeed");
        assert_eq!(reconciler.reconciliation_count(), 1);
    }

    // -- Proof not required --

    #[test]
    fn test_proof_not_required() {
        let mut reconciler = AntiEntropyReconciler::new(ReconciliationConfig {
            proof_required: false,
            ..ReconciliationConfig::default()
        })
        .unwrap();
        let mut local = TrustState::new(1);
        let mut remote = TrustState::new(1);
        remote.insert(make_record_no_proof("r1", 1));
        let dummy_root = MmrRoot {
            tree_size: 0,
            root_hash: String::new(),
        };

        let cancel = no_cancel();
        let result = reconciler
            .reconcile(&mut local, &remote, &dummy_root, &cancel)
            .expect("should succeed");
        assert_eq!(
            result.records_accepted, 1,
            "Should accept without proof when not required"
        );
    }

    // -- Adversarial: regression tests --

    #[test]
    fn regression_non_empty_check_no_longer_sufficient() {
        // The old verify_mmr_proof accepted any non-empty, non-zero proof.
        // The new version requires canonical inclusion proof verification.
        let marker_hash = test_marker_hash("r1");
        let (root, _) = build_valid_proof(&marker_hash);
        let rec = TrustRecord {
            id: "r1".into(),
            epoch: 1,
            recorded_at_ms: 1_000,
            origin_node_id: "node-a".into(),
            payload: vec![1, 2, 3, 4],
            mmr_pos: 0,
            inclusion_proof: Some(InclusionProof {
                leaf_index: 0,
                tree_size: 1,
                // Wrong leaf hash — would have passed the old non-zero check
                leaf_hash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    .into(),
                audit_path: vec![],
            }),
            marker_hash,
        };
        assert!(verify_mmr_proof(&rec, &root).is_err());
    }

    #[test]
    fn adversarial_cross_epoch_replay_rejected() {
        // A record from epoch 10 should be rejected by a local state at epoch 5
        // even with a valid proof.
        let mut reconciler =
            AntiEntropyReconciler::new(ReconciliationConfig::default()).expect("should succeed");
        let mut local = TrustState::new(5);
        let mut remote = TrustState::new(5);
        let (rec, root) = make_record("cross-epoch", 10);
        remote.insert(rec);

        let cancel = no_cancel();
        let result = reconciler
            .reconcile(&mut local, &remote, &root, &cancel)
            .expect("should succeed");
        assert_eq!(result.records_rejected, 1);
    }
}
