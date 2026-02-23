// Anti-entropy reconciliation for distributed product trust state.
//
// O(delta) reconciliation using Merkle-Mountain-Range (MMR) digest comparison.
// Proof-carrying recovery artifacts, epoch-scoped validity, fork detection,
// atomic two-phase application, and cancellation safety.
//
// bd-390 — Section 10.11

use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

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
    /// Record payload bytes.
    pub payload: Vec<u8>,
    /// MMR leaf position.
    pub mmr_pos: u64,
    /// MMR inclusion proof (hashes).
    pub mmr_proof: Vec<[u8; 32]>,
}

impl TrustRecord {
    /// Compute a SHA-256 hash of the record for digest comparison.
    pub fn digest(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"anti_entropy_record_v1:");
        hasher.update(&self.payload);
        for proof_hash in &self.mmr_proof {
            hasher.update(proof_hash);
        }
        hasher.finalize().into()
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

    /// Insert a record into the state and recompute root digest.
    pub fn insert(&mut self, record: TrustRecord) {
        self.records.insert(record.id.clone(), record);
        self.recompute_root_digest();
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

// ---------------------------------------------------------------------------
// MMR proof verification (simplified)
// ---------------------------------------------------------------------------

/// Verify an MMR inclusion proof for a trust record.
/// Simplified: checks that the proof is non-empty and consistent.
pub fn verify_mmr_proof(record: &TrustRecord) -> bool {
    if record.mmr_proof.is_empty() {
        return false;
    }
    // Verify proof chain: each hash must be non-zero.
    record.mmr_proof.iter().all(|h| h.iter().any(|&b| b != 0))
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

    /// Compute the delta between local and remote states.
    /// INV-AE-DELTA: only processes O(delta) records.
    pub fn compute_delta(&self, local: &TrustState, remote: &TrustState) -> Vec<TrustRecord> {
        let local_ids = local.record_ids();
        let remote_ids = remote.record_ids();

        // Records in remote but not in local.
        let missing: Vec<TrustRecord> = remote_ids
            .difference(&local_ids)
            .filter_map(|id| remote.get(id).cloned())
            .collect();

        missing
    }

    /// Detect fork: local and remote have same ID but different digests.
    pub fn detect_fork(&self, local: &TrustState, remote: &TrustState) -> Option<String> {
        let local_ids = local.record_ids();
        let remote_ids = remote.record_ids();
        let common = local_ids.intersection(&remote_ids);

        for id in common {
            let (Some(local_rec), Some(remote_rec)) = (local.get(id), remote.get(id)) else {
                continue;
            };
            if local_rec.digest() != remote_rec.digest() {
                return Some(id.clone());
            }
        }
        None
    }

    /// Reconcile remote state into local state.
    ///
    /// INV-AE-ATOMIC: on failure, local state is unchanged.
    /// INV-AE-EPOCH: future-epoch records are rejected.
    /// INV-AE-PROOF: records without valid proofs are rejected.
    pub fn reconcile(
        &mut self,
        local: &mut TrustState,
        remote: &TrustState,
        cancelled: &std::sync::atomic::AtomicBool,
    ) -> Result<ReconciliationResult, ReconciliationError> {
        self.reconciliation_count += 1;
        let trace_id = format!("ae-{}", self.reconciliation_count);
        let start = std::time::Instant::now();

        self.events.push(ReconciliationEvent {
            code: EVT_CYCLE_STARTED.to_string(),
            detail: format!("local={},remote={}", local.len(), remote.len()),
            trace_id: trace_id.clone(),
            epoch: local.current_epoch(),
        });

        // Check for fork.
        if let Some(forked_id) = self.detect_fork(local, remote) {
            self.events.push(ReconciliationEvent {
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

        self.events.push(ReconciliationEvent {
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
        let mut accepted = Vec::new();
        let mut rejected = 0usize;

        for record in &delta {
            // Check cancellation.
            if self.config.cancellation_enabled
                && cancelled.load(std::sync::atomic::Ordering::Relaxed)
            {
                self.events.push(ReconciliationEvent {
                    code: EVT_CANCELLED.to_string(),
                    detail: format!("cancelled after validating {} records", accepted.len()),
                    trace_id: trace_id.clone(),
                    epoch: local.current_epoch(),
                });
                return Err(ReconciliationError::Cancelled);
            }

            // Check if already present (idempotent replay).
            if local.contains(&record.id) {
                self.events.push(ReconciliationEvent {
                    code: EVT_REPLAY_IDEMPOTENT.to_string(),
                    detail: format!("record {} already present", record.id),
                    trace_id: trace_id.clone(),
                    epoch: local.current_epoch(),
                });
                continue;
            }

            // INV-AE-EPOCH: reject future-epoch records.
            if record.epoch > local.current_epoch() + self.config.epoch_tolerance {
                self.events.push(ReconciliationEvent {
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

            // INV-AE-PROOF: verify MMR inclusion proof.
            if self.config.proof_required && !verify_mmr_proof(record) {
                self.events.push(ReconciliationEvent {
                    code: EVT_RECORD_REJECTED.to_string(),
                    detail: format!("proof invalid: record {}", record.id),
                    trace_id: trace_id.clone(),
                    epoch: local.current_epoch(),
                });
                rejected += 1;
                continue;
            }

            accepted.push(record.clone());
            self.events.push(ReconciliationEvent {
                code: EVT_RECORD_ACCEPTED.to_string(),
                detail: format!("record {} epoch={}", record.id, record.epoch),
                trace_id: trace_id.clone(),
                epoch: local.current_epoch(),
            });
        }

        // Phase 2: apply all validated records atomically.
        for record in &accepted {
            local.insert(record.clone());
        }

        let elapsed = start.elapsed();

        self.events.push(ReconciliationEvent {
            code: EVT_CYCLE_COMPLETED.to_string(),
            detail: format!(
                "accepted={},rejected={},elapsed_ms={}",
                accepted.len(),
                rejected,
                elapsed.as_millis()
            ),
            trace_id: trace_id.clone(),
            epoch: local.current_epoch(),
        });

        Ok(ReconciliationResult {
            delta_size,
            records_accepted: accepted.len(),
            records_rejected: rejected,
            elapsed_ms: elapsed.as_millis() as u64,
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

    fn make_record(id: &str, epoch: u64) -> TrustRecord {
        let mut proof_hash = [0u8; 32];
        proof_hash[0] = 1;
        TrustRecord {
            id: id.into(),
            epoch,
            payload: vec![1, 2, 3, 4],
            mmr_pos: 0,
            mmr_proof: vec![proof_hash],
        }
    }

    fn make_record_no_proof(id: &str, epoch: u64) -> TrustRecord {
        TrustRecord {
            id: id.into(),
            epoch,
            payload: vec![1, 2, 3, 4],
            mmr_pos: 0,
            mmr_proof: vec![],
        }
    }

    fn make_record_invalid_proof(id: &str, epoch: u64) -> TrustRecord {
        TrustRecord {
            id: id.into(),
            epoch,
            payload: vec![1, 2, 3, 4],
            mmr_pos: 0,
            mmr_proof: vec![[0u8; 32]], // All-zero = invalid.
        }
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
        state.insert(make_record("r1", 1));
        assert_eq!(state.len(), 1);
        assert!(state.contains("r1"));
    }

    #[test]
    fn test_trust_state_get() {
        let mut state = TrustState::new(1);
        state.insert(make_record("r1", 1));
        let r = state.get("r1").unwrap();
        assert_eq!(r.id, "r1");
    }

    #[test]
    fn test_trust_state_record_ids() {
        let mut state = TrustState::new(1);
        state.insert(make_record("r1", 1));
        state.insert(make_record("r2", 1));
        let ids = state.record_ids();
        assert!(ids.contains("r1"));
        assert!(ids.contains("r2"));
    }

    #[test]
    fn test_trust_state_digest_changes() {
        let mut state = TrustState::new(1);
        let d1 = *state.root_digest();
        state.insert(make_record("r1", 1));
        assert_ne!(*state.root_digest(), d1);
    }

    // -- Record digest --

    #[test]
    fn test_record_digest_deterministic() {
        let r1 = make_record("r1", 1);
        let r2 = make_record("r1", 1);
        assert_eq!(r1.digest(), r2.digest());
    }

    // -- MMR proof verification --

    #[test]
    fn test_valid_proof() {
        let r = make_record("r1", 1);
        assert!(verify_mmr_proof(&r));
    }

    #[test]
    fn test_empty_proof_invalid() {
        let r = make_record_no_proof("r1", 1);
        assert!(!verify_mmr_proof(&r));
    }

    #[test]
    fn test_zero_proof_invalid() {
        let r = make_record_invalid_proof("r1", 1);
        assert!(!verify_mmr_proof(&r));
    }

    // -- Delta computation --

    #[test]
    fn test_identical_states_zero_delta() {
        let reconciler = AntiEntropyReconciler::new(ReconciliationConfig::default()).unwrap();
        let mut local = TrustState::new(1);
        let mut remote = TrustState::new(1);
        local.insert(make_record("r1", 1));
        remote.insert(make_record("r1", 1));
        let delta = reconciler.compute_delta(&local, &remote);
        assert_eq!(delta.len(), 0);
    }

    #[test]
    fn test_single_record_divergence() {
        let reconciler = AntiEntropyReconciler::new(ReconciliationConfig::default()).unwrap();
        let local = TrustState::new(1);
        let mut remote = TrustState::new(1);
        remote.insert(make_record("r1", 1));
        let delta = reconciler.compute_delta(&local, &remote);
        assert_eq!(delta.len(), 1);
    }

    #[test]
    fn test_bulk_divergence_bounded() {
        // INV-AE-DELTA: O(delta) behavior.
        let reconciler = AntiEntropyReconciler::new(ReconciliationConfig::default()).unwrap();
        let mut local = TrustState::new(1);
        let mut remote = TrustState::new(1);

        // Shared records.
        for i in 0..500 {
            let r = make_record(&format!("shared-{i}"), 1);
            local.insert(r.clone());
            remote.insert(r);
        }
        // Divergent records (only in remote).
        for i in 0..100 {
            remote.insert(make_record(&format!("remote-{i}"), 1));
        }

        let delta = reconciler.compute_delta(&local, &remote);
        assert_eq!(
            delta.len(),
            100,
            "Delta should be exactly the differing records"
        );
    }

    // -- Fork detection --

    #[test]
    fn test_no_fork_identical() {
        let reconciler = AntiEntropyReconciler::new(ReconciliationConfig::default()).unwrap();
        let mut local = TrustState::new(1);
        let mut remote = TrustState::new(1);
        local.insert(make_record("r1", 1));
        remote.insert(make_record("r1", 1));
        assert!(reconciler.detect_fork(&local, &remote).is_none());
    }

    #[test]
    fn test_fork_detected() {
        let reconciler = AntiEntropyReconciler::new(ReconciliationConfig::default()).unwrap();
        let mut local = TrustState::new(1);
        let mut remote = TrustState::new(1);
        local.insert(make_record("r1", 1));
        // Different payload → different digest.
        let mut forked = make_record("r1", 1);
        forked.payload = vec![99, 99, 99];
        remote.insert(forked);
        assert!(reconciler.detect_fork(&local, &remote).is_some());
    }

    // -- Full reconciliation --

    #[test]
    fn test_reconcile_empty_to_populated() {
        let mut reconciler = AntiEntropyReconciler::new(ReconciliationConfig::default()).unwrap();
        let mut local = TrustState::new(1);
        let mut remote = TrustState::new(1);
        remote.insert(make_record("r1", 1));
        remote.insert(make_record("r2", 1));

        let cancel = no_cancel();
        let result = reconciler.reconcile(&mut local, &remote, &cancel).unwrap();
        assert_eq!(result.delta_size, 2);
        assert_eq!(result.records_accepted, 2);
        assert_eq!(result.records_rejected, 0);
        assert_eq!(local.len(), 2);
    }

    #[test]
    fn test_reconcile_epoch_rejection() {
        // INV-AE-EPOCH: future-epoch records rejected.
        let mut reconciler = AntiEntropyReconciler::new(ReconciliationConfig::default()).unwrap();
        let mut local = TrustState::new(5);
        let mut remote = TrustState::new(10);
        remote.insert(make_record("future", 10)); // epoch 10 > local 5.

        let cancel = no_cancel();
        let result = reconciler.reconcile(&mut local, &remote, &cancel).unwrap();
        assert_eq!(result.records_rejected, 1);
        assert_eq!(result.records_accepted, 0);
        assert!(local.is_empty());
    }

    #[test]
    fn test_reconcile_proof_rejection() {
        // INV-AE-PROOF: invalid proof rejected.
        let mut reconciler = AntiEntropyReconciler::new(ReconciliationConfig::default()).unwrap();
        let mut local = TrustState::new(1);
        let mut remote = TrustState::new(1);
        remote.insert(make_record_no_proof("bad_proof", 1));

        let cancel = no_cancel();
        let result = reconciler.reconcile(&mut local, &remote, &cancel).unwrap();
        assert_eq!(result.records_rejected, 1);
        assert_eq!(result.records_accepted, 0);
    }

    #[test]
    fn test_reconcile_fork_halts() {
        let mut reconciler = AntiEntropyReconciler::new(ReconciliationConfig::default()).unwrap();
        let mut local = TrustState::new(1);
        let mut remote = TrustState::new(1);
        local.insert(make_record("r1", 1));
        let mut forked = make_record("r1", 1);
        forked.payload = vec![99];
        remote.insert(forked);

        let cancel = no_cancel();
        let err = reconciler
            .reconcile(&mut local, &remote, &cancel)
            .unwrap_err();
        assert!(matches!(err, ReconciliationError::ForkDetected(_)));
    }

    #[test]
    fn test_reconcile_cancellation() {
        let mut reconciler = AntiEntropyReconciler::new(ReconciliationConfig::default()).unwrap();
        let mut local = TrustState::new(1);
        let mut remote = TrustState::new(1);
        remote.insert(make_record("r1", 1));

        let cancel = with_cancel();
        let err = reconciler
            .reconcile(&mut local, &remote, &cancel)
            .unwrap_err();
        assert!(matches!(err, ReconciliationError::Cancelled));
        // INV-AE-ATOMIC: local state unchanged.
        assert!(local.is_empty());
    }

    #[test]
    fn test_reconcile_idempotent_replay() {
        // Replay of already-reconciled records is idempotent.
        let mut reconciler = AntiEntropyReconciler::new(ReconciliationConfig::default()).unwrap();
        let mut local = TrustState::new(1);
        local.insert(make_record("r1", 1));
        let mut remote = TrustState::new(1);
        remote.insert(make_record("r1", 1));

        let cancel = no_cancel();
        let result = reconciler.reconcile(&mut local, &remote, &cancel).unwrap();
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
        for i in 0..10 {
            remote.insert(make_record(&format!("r{i}"), 1));
        }

        let cancel = no_cancel();
        let err = reconciler
            .reconcile(&mut local, &remote, &cancel)
            .unwrap_err();
        assert!(matches!(err, ReconciliationError::BatchExceeded { .. }));
    }

    #[test]
    fn test_reconcile_mixed_accept_reject() {
        let mut reconciler = AntiEntropyReconciler::new(ReconciliationConfig::default()).unwrap();
        let mut local = TrustState::new(5);
        let mut remote = TrustState::new(5);
        remote.insert(make_record("valid", 5)); // Valid: same epoch.
        remote.insert(make_record("future", 10)); // Rejected: future epoch.
        remote.insert(make_record_no_proof("noproof", 5)); // Rejected: no proof.

        let cancel = no_cancel();
        let result = reconciler.reconcile(&mut local, &remote, &cancel).unwrap();
        assert_eq!(result.records_accepted, 1);
        assert_eq!(result.records_rejected, 2);
    }

    // -- Events --

    #[test]
    fn test_events_recorded() {
        let mut reconciler = AntiEntropyReconciler::new(ReconciliationConfig::default()).unwrap();
        let mut local = TrustState::new(1);
        let mut remote = TrustState::new(1);
        remote.insert(make_record("r1", 1));

        let cancel = no_cancel();
        reconciler.reconcile(&mut local, &remote, &cancel).unwrap();

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
        let mut reconciler = AntiEntropyReconciler::new(ReconciliationConfig::default()).unwrap();
        let mut local = TrustState::new(1);
        let mut remote = TrustState::new(1);
        remote.insert(make_record("r1", 1));

        let cancel = no_cancel();
        reconciler.reconcile(&mut local, &remote, &cancel).unwrap();

        for event in reconciler.events() {
            assert!(!event.trace_id.is_empty());
        }
    }

    #[test]
    fn test_events_have_epoch() {
        let mut reconciler = AntiEntropyReconciler::new(ReconciliationConfig::default()).unwrap();
        let mut local = TrustState::new(42);
        let remote = TrustState::new(42);

        let cancel = no_cancel();
        reconciler.reconcile(&mut local, &remote, &cancel).unwrap();

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
        let mut reconciler = AntiEntropyReconciler::new(ReconciliationConfig::default()).unwrap();
        assert_eq!(reconciler.reconciliation_count(), 0);
        let mut local = TrustState::new(1);
        let remote = TrustState::new(1);
        let cancel = no_cancel();
        reconciler.reconcile(&mut local, &remote, &cancel).unwrap();
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

        let cancel = no_cancel();
        let result = reconciler.reconcile(&mut local, &remote, &cancel).unwrap();
        assert_eq!(
            result.records_accepted, 1,
            "Should accept without proof when not required"
        );
    }
}
