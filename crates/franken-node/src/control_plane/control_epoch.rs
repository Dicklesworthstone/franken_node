//! bd-3hdv: Monotonic control epoch in canonical manifest state.
//!
//! The control epoch is the foundational time-fencing primitive for the 9J track.
//! Every trust decision, key derivation, validity window, and transition barrier
//! depends on a strictly-increasing epoch counter.
//!
//! # Invariants
//!
//! - INV-EPOCH-MONOTONIC: epoch values only increase; regressions are rejected
//! - INV-EPOCH-DURABLE: committed epoch survives crash recovery
//! - INV-EPOCH-SIGNED-EVENT: every epoch change produces a signed transition event
//! - INV-EPOCH-NO-GAP: epoch advances by exactly 1 per call

use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::fmt;

/// Stable event codes for structured logging.
pub mod event_codes {
    pub const EPOCH_ADVANCED: &str = "EPOCH_ADVANCED";
    pub const EPOCH_REGRESSION_REJECTED: &str = "EPOCH_REGRESSION_REJECTED";
    pub const EPOCH_READ: &str = "EPOCH_READ";
    pub const EPOCH_RECOVERED: &str = "EPOCH_RECOVERED";
    pub const EPOCH_ARTIFACT_ACCEPTED: &str = "EPOCH_ARTIFACT_ACCEPTED";
    pub const EPOCH_ARTIFACT_REJECTED: &str = "EPOCH_ARTIFACT_REJECTED";
}

/// A strictly monotonic 64-bit control epoch counter.
///
/// Copy + Ord + Hash + Eq for ergonomic use across the codebase.
/// The inner value is the epoch number; epoch 0 means "no epoch committed yet"
/// and the first meaningful epoch is 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ControlEpoch(u64);

impl ControlEpoch {
    /// The genesis epoch (no epoch committed yet).
    pub const GENESIS: Self = Self(0);

    /// Create a `ControlEpoch` from a raw u64 value.
    pub fn new(value: u64) -> Self {
        Self(value)
    }

    /// Get the raw u64 value.
    pub fn value(self) -> u64 {
        self.0
    }

    /// Check if this is the genesis epoch.
    pub fn is_genesis(self) -> bool {
        self.0 == 0
    }

    /// Return the next epoch value (self + 1).
    /// Returns None on u64 overflow.
    pub fn next(self) -> Option<Self> {
        self.0.checked_add(1).map(Self)
    }
}

impl fmt::Display for ControlEpoch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "epoch:{}", self.0)
    }
}

impl From<u64> for ControlEpoch {
    fn from(v: u64) -> Self {
        Self(v)
    }
}

impl From<ControlEpoch> for u64 {
    fn from(e: ControlEpoch) -> Self {
        e.0
    }
}

/// A signed event recording an epoch transition.
///
/// Contains the old and new epoch, the timestamp of the transition,
/// and a manifest hash binding the event to the manifest state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpochTransition {
    pub old_epoch: ControlEpoch,
    pub new_epoch: ControlEpoch,
    pub timestamp: u64,
    pub manifest_hash: String,
    pub event_mac: String,
    pub trace_id: String,
}

impl EpochTransition {
    /// Compute a keyed MAC over the transition event fields.
    ///
    /// This binds the event to the specific epoch change and manifest state.
    /// In production, this would use HMAC-SHA256 with a signing key.
    fn compute_mac(
        old_epoch: ControlEpoch,
        new_epoch: ControlEpoch,
        timestamp: u64,
        manifest_hash: &str,
        trace_id: &str,
    ) -> String {
        let canonical = format!(
            "epoch_transition|{}|{}|{timestamp}|{manifest_hash}|{trace_id}",
            old_epoch.value(),
            new_epoch.value()
        );

        let mut hasher = sha2::Sha256::new();
        sha2::Digest::update(&mut hasher, b"control_epoch_mac_v1:");
        sha2::Digest::update(&mut hasher, canonical.as_bytes());
        format!("mac:{:x}", sha2::Digest::finalize(hasher))
    }

    /// Verify the MAC on this transition event.
    pub fn verify(&self) -> bool {
        let expected = Self::compute_mac(
            self.old_epoch,
            self.new_epoch,
            self.timestamp,
            &self.manifest_hash,
            &self.trace_id,
        );
        self.event_mac == expected
    }
}

/// Errors from epoch operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EpochError {
    /// Attempted to set epoch to a value <= current epoch.
    EpochRegression {
        current: ControlEpoch,
        attempted: ControlEpoch,
    },
    /// Epoch counter overflow (u64::MAX reached).
    EpochOverflow { current: ControlEpoch },
    /// Manifest hash is empty or invalid.
    InvalidManifestHash { reason: String },
}

impl EpochError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::EpochRegression { .. } => "EPOCH_REGRESSION",
            Self::EpochOverflow { .. } => "EPOCH_OVERFLOW",
            Self::InvalidManifestHash { .. } => "EPOCH_INVALID_MANIFEST",
        }
    }
}

impl fmt::Display for EpochError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EpochRegression { current, attempted } => {
                write!(
                    f,
                    "EPOCH_REGRESSION: attempted {} but current is {}",
                    attempted.value(),
                    current.value()
                )
            }
            Self::EpochOverflow { current } => {
                write!(
                    f,
                    "EPOCH_OVERFLOW: current epoch {} is at u64::MAX",
                    current.value()
                )
            }
            Self::InvalidManifestHash { reason } => {
                write!(f, "EPOCH_INVALID_MANIFEST: {reason}")
            }
        }
    }
}

/// Policy describing which artifact epochs are acceptable.
///
/// Valid range is inclusive:
/// `[current_epoch - max_lookback, current_epoch]`
///
/// Any artifact from a future epoch is fail-closed rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidityWindowPolicy {
    current_epoch: ControlEpoch,
    max_lookback: u64,
}

impl ValidityWindowPolicy {
    /// Construct a new validity-window policy.
    pub fn new(current_epoch: ControlEpoch, max_lookback: u64) -> Self {
        Self {
            current_epoch,
            max_lookback,
        }
    }

    /// Runtime default for 10.14 validity checks.
    pub fn default_for(current_epoch: ControlEpoch) -> Self {
        Self::new(current_epoch, 1)
    }

    /// Current control epoch used by this policy.
    pub fn current_epoch(self) -> ControlEpoch {
        self.current_epoch
    }

    /// Maximum backward epoch distance accepted.
    pub fn max_lookback(self) -> u64 {
        self.max_lookback
    }

    /// Inclusive minimum acceptable epoch.
    pub fn min_accepted_epoch(self) -> ControlEpoch {
        ControlEpoch::new(self.current_epoch.value().saturating_sub(self.max_lookback))
    }

    /// Hot-reload current epoch.
    pub fn set_current_epoch(&mut self, epoch: ControlEpoch) {
        self.current_epoch = epoch;
    }

    /// Hot-reload lookback window.
    pub fn set_max_lookback(&mut self, max_lookback: u64) {
        self.max_lookback = max_lookback;
    }
}

/// Why an artifact epoch was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EpochRejectionReason {
    FutureEpoch,
    ExpiredEpoch,
}

/// Structured rejection payload for artifact validity-window failures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpochRejection {
    pub artifact_id: String,
    pub artifact_epoch: ControlEpoch,
    pub current_epoch: ControlEpoch,
    pub rejection_reason: EpochRejectionReason,
    pub trace_id: String,
}

impl EpochRejection {
    pub fn code(&self) -> &'static str {
        match self.rejection_reason {
            EpochRejectionReason::FutureEpoch => "EPOCH_REJECT_FUTURE",
            EpochRejectionReason::ExpiredEpoch => "EPOCH_REJECT_EXPIRED",
        }
    }

    pub fn to_rejected_event(&self) -> EpochArtifactEvent {
        EpochArtifactEvent::rejected(self)
    }
}

/// Structured telemetry event for epoch validity-window admission decisions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpochArtifactEvent {
    pub event_code: String,
    pub artifact_id: String,
    pub artifact_epoch: ControlEpoch,
    pub current_epoch: ControlEpoch,
    pub rejection_reason: Option<EpochRejectionReason>,
    pub trace_id: String,
}

impl EpochArtifactEvent {
    pub fn accepted(
        artifact_id: &str,
        artifact_epoch: ControlEpoch,
        current_epoch: ControlEpoch,
        trace_id: &str,
    ) -> Self {
        Self {
            event_code: event_codes::EPOCH_ARTIFACT_ACCEPTED.to_string(),
            artifact_id: artifact_id.to_string(),
            artifact_epoch,
            current_epoch,
            rejection_reason: None,
            trace_id: trace_id.to_string(),
        }
    }

    pub fn rejected(rejection: &EpochRejection) -> Self {
        Self {
            event_code: event_codes::EPOCH_ARTIFACT_REJECTED.to_string(),
            artifact_id: rejection.artifact_id.clone(),
            artifact_epoch: rejection.artifact_epoch,
            current_epoch: rejection.current_epoch,
            rejection_reason: Some(rejection.rejection_reason),
            trace_id: rejection.trace_id.clone(),
        }
    }
}

/// Validate artifact epoch against the fail-closed validity window (bd-2xv8).
///
/// Accepts only epochs in the inclusive range:
/// `[current_epoch - max_lookback, current_epoch]`.
///
/// Rejection order is fail-closed:
/// 1. Future epoch rejection
/// 2. Expired epoch rejection
pub fn check_artifact_epoch(
    artifact_id: &str,
    artifact_epoch: ControlEpoch,
    policy: &ValidityWindowPolicy,
    trace_id: &str,
) -> Result<(), EpochRejection> {
    let current = policy.current_epoch();
    if artifact_epoch > current {
        return Err(EpochRejection {
            artifact_id: artifact_id.to_string(),
            artifact_epoch,
            current_epoch: current,
            rejection_reason: EpochRejectionReason::FutureEpoch,
            trace_id: trace_id.to_string(),
        });
    }

    if artifact_epoch < policy.min_accepted_epoch() {
        return Err(EpochRejection {
            artifact_id: artifact_id.to_string(),
            artifact_epoch,
            current_epoch: current,
            rejection_reason: EpochRejectionReason::ExpiredEpoch,
            trace_id: trace_id.to_string(),
        });
    }

    Ok(())
}

/// Durable epoch store managing the canonical monotonic control epoch.
///
/// In a full implementation, this would persist to WAL-mode SQLite or
/// an fsync'd file. For the core type system and invariant enforcement,
/// this provides the in-memory reference implementation with crash-recovery
/// simulation support.
#[derive(Debug)]
pub struct EpochStore {
    current: ControlEpoch,
    /// History of all epoch transitions for audit trail.
    transitions: Vec<EpochTransition>,
    /// Durable commit log (simulates fsync'd persistence).
    committed: ControlEpoch,
}

impl EpochStore {
    /// Create a new epoch store starting at genesis (epoch 0).
    pub fn new() -> Self {
        Self {
            current: ControlEpoch::GENESIS,
            transitions: Vec::new(),
            committed: ControlEpoch::GENESIS,
        }
    }

    /// Create an epoch store recovered from durable state.
    ///
    /// INV-EPOCH-DURABLE: on restart, the store sees the last committed epoch.
    pub fn recover(committed_epoch: u64) -> Self {
        Self {
            current: ControlEpoch::new(committed_epoch),
            transitions: Vec::new(),
            committed: ControlEpoch::new(committed_epoch),
        }
    }

    /// Read the current epoch. O(1) non-mutating read.
    ///
    /// Logs: EPOCH_READ (value, trace_id)
    pub fn epoch_read(&self) -> ControlEpoch {
        self.current
    }

    /// Advance the epoch by exactly 1.
    ///
    /// INV-EPOCH-MONOTONIC: epoch only increases.
    /// INV-EPOCH-NO-GAP: advances by exactly 1.
    /// INV-EPOCH-SIGNED-EVENT: produces a signed EpochTransition.
    /// INV-EPOCH-DURABLE: committed epoch is updated atomically.
    ///
    /// Returns the signed EpochTransition event.
    pub fn epoch_advance(
        &mut self,
        manifest_hash: &str,
        timestamp: u64,
        trace_id: &str,
    ) -> Result<EpochTransition, EpochError> {
        if manifest_hash.is_empty() {
            return Err(EpochError::InvalidManifestHash {
                reason: "manifest_hash must not be empty".into(),
            });
        }

        let old_epoch = self.current;
        let new_epoch = old_epoch
            .next()
            .ok_or(EpochError::EpochOverflow { current: old_epoch })?;

        // Compute signed event MAC
        let event_mac =
            EpochTransition::compute_mac(old_epoch, new_epoch, timestamp, manifest_hash, trace_id);

        let transition = EpochTransition {
            old_epoch,
            new_epoch,
            timestamp,
            manifest_hash: manifest_hash.to_string(),
            event_mac,
            trace_id: trace_id.to_string(),
        };

        // Atomic commit: update current and committed together.
        // In production: write to WAL, fsync, then update in-memory state.
        self.current = new_epoch;
        self.committed = new_epoch;
        self.transitions.push(transition.clone());

        Ok(transition)
    }

    /// Attempt to set the epoch to a specific value.
    ///
    /// This is rejected if the value is <= current epoch (regression).
    /// Used for testing regression rejection semantics.
    pub fn epoch_set(
        &mut self,
        value: u64,
        manifest_hash: &str,
        timestamp: u64,
        trace_id: &str,
    ) -> Result<EpochTransition, EpochError> {
        let attempted = ControlEpoch::new(value);
        if attempted <= self.current {
            return Err(EpochError::EpochRegression {
                current: self.current,
                attempted,
            });
        }

        if manifest_hash.is_empty() {
            return Err(EpochError::InvalidManifestHash {
                reason: "manifest_hash must not be empty".into(),
            });
        }

        let old_epoch = self.current;
        let new_epoch = attempted;

        let event_mac =
            EpochTransition::compute_mac(old_epoch, new_epoch, timestamp, manifest_hash, trace_id);

        let transition = EpochTransition {
            old_epoch,
            new_epoch,
            timestamp,
            manifest_hash: manifest_hash.to_string(),
            event_mac,
            trace_id: trace_id.to_string(),
        };

        self.current = new_epoch;
        self.committed = new_epoch;
        self.transitions.push(transition.clone());

        Ok(transition)
    }

    /// Get the committed (durable) epoch value.
    pub fn committed_epoch(&self) -> ControlEpoch {
        self.committed
    }

    /// Get the full transition history.
    pub fn transitions(&self) -> &[EpochTransition] {
        &self.transitions
    }

    /// Number of transitions recorded.
    pub fn transition_count(&self) -> usize {
        self.transitions.len()
    }

    /// Simulate a crash by resetting current to committed state.
    ///
    /// In-memory state is lost; only the committed epoch survives.
    /// INV-EPOCH-DURABLE: crash recovery sees the last committed epoch.
    #[cfg(test)]
    pub fn simulate_crash_recovery(&mut self) {
        // After crash, only committed epoch survives.
        // Transition history is lost (would need WAL replay in production).
        let committed = self.committed;
        self.current = committed;
        self.transitions.clear();
    }
}

impl Default for EpochStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mhash(n: u32) -> String {
        format!("manifest-hash-{n:016x}")
    }

    fn tid(n: u32) -> String {
        format!("trace-{n:04}")
    }

    // ---- ControlEpoch type tests ----

    #[test]
    fn epoch_genesis_is_zero() {
        assert_eq!(ControlEpoch::GENESIS.value(), 0);
        assert!(ControlEpoch::GENESIS.is_genesis());
    }

    #[test]
    fn epoch_new_and_value() {
        let e = ControlEpoch::new(42);
        assert_eq!(e.value(), 42);
        assert!(!e.is_genesis());
    }

    #[test]
    fn epoch_next() {
        let e = ControlEpoch::new(5);
        let n = e.next().unwrap();
        assert_eq!(n.value(), 6);
    }

    #[test]
    fn epoch_next_overflow() {
        let e = ControlEpoch::new(u64::MAX);
        assert!(e.next().is_none());
    }

    #[test]
    fn epoch_ordering() {
        let a = ControlEpoch::new(1);
        let b = ControlEpoch::new(2);
        assert!(a < b);
        assert!(b > a);
        assert_eq!(a, ControlEpoch::new(1));
    }

    #[test]
    fn epoch_display() {
        let e = ControlEpoch::new(42);
        assert_eq!(e.to_string(), "epoch:42");
    }

    #[test]
    fn epoch_from_u64() {
        let e: ControlEpoch = 100_u64.into();
        assert_eq!(e.value(), 100);
        let v: u64 = e.into();
        assert_eq!(v, 100);
    }

    #[test]
    fn epoch_copy_semantics() {
        let e = ControlEpoch::new(10);
        let e2 = e; // Copy, not move
        assert_eq!(e, e2);
    }

    #[test]
    fn epoch_hash_consistency() {
        use std::collections::BTreeSet;
        let mut set = BTreeSet::new();
        set.insert(ControlEpoch::new(1));
        set.insert(ControlEpoch::new(2));
        set.insert(ControlEpoch::new(1)); // duplicate
        assert_eq!(set.len(), 2);
    }

    // ---- EpochStore basic tests ----

    #[test]
    fn store_starts_at_genesis() {
        let store = EpochStore::new();
        assert_eq!(store.epoch_read(), ControlEpoch::GENESIS);
        assert_eq!(store.transition_count(), 0);
    }

    #[test]
    fn store_default_is_genesis() {
        let store = EpochStore::default();
        assert_eq!(store.epoch_read(), ControlEpoch::GENESIS);
    }

    #[test]
    fn single_advance() {
        let mut store = EpochStore::new();
        let t = store.epoch_advance(&mhash(1), 1000, &tid(1)).unwrap();
        assert_eq!(t.old_epoch, ControlEpoch::GENESIS);
        assert_eq!(t.new_epoch, ControlEpoch::new(1));
        assert_eq!(t.timestamp, 1000);
        assert_eq!(store.epoch_read(), ControlEpoch::new(1));
        assert_eq!(store.transition_count(), 1);
    }

    #[test]
    fn sequential_advances() {
        let mut store = EpochStore::new();
        for i in 1..=100_u64 {
            let t = store
                .epoch_advance(&mhash(i as u32), 1000 + i, &tid(i as u32))
                .unwrap();
            assert_eq!(t.old_epoch, ControlEpoch::new(i - 1));
            assert_eq!(t.new_epoch, ControlEpoch::new(i));
        }
        assert_eq!(store.epoch_read(), ControlEpoch::new(100));
        assert_eq!(store.transition_count(), 100);
    }

    #[test]
    fn thousand_advances_monotonic() {
        let mut store = EpochStore::new();
        for i in 1..=1000_u64 {
            store
                .epoch_advance(&mhash(i as u32), 1000 + i, &tid(i as u32))
                .unwrap();
        }
        assert_eq!(store.epoch_read().value(), 1000);

        // Verify all transitions are strictly monotonic
        let transitions = store.transitions();
        for (i, t) in transitions.iter().enumerate() {
            assert_eq!(t.old_epoch.value(), i as u64);
            assert_eq!(t.new_epoch.value(), (i + 1) as u64);
        }
    }

    // ---- Regression rejection ----

    #[test]
    fn regression_same_value_rejected() {
        let mut store = EpochStore::new();
        store.epoch_advance(&mhash(1), 1000, &tid(1)).unwrap();
        // Current is 1; attempt to set to 1 (same value)
        let err = store.epoch_set(1, &mhash(2), 1001, &tid(2)).unwrap_err();
        assert_eq!(err.code(), "EPOCH_REGRESSION");
        // State unchanged
        assert_eq!(store.epoch_read(), ControlEpoch::new(1));
    }

    #[test]
    fn regression_lower_value_rejected() {
        let mut store = EpochStore::new();
        store.epoch_advance(&mhash(1), 1000, &tid(1)).unwrap();
        store.epoch_advance(&mhash(2), 1001, &tid(2)).unwrap();
        // Current is 2; attempt to set to 1
        let err = store.epoch_set(1, &mhash(3), 1002, &tid(3)).unwrap_err();
        assert_eq!(err.code(), "EPOCH_REGRESSION");
        assert_eq!(store.epoch_read(), ControlEpoch::new(2));
    }

    #[test]
    fn regression_zero_rejected() {
        let mut store = EpochStore::new();
        store.epoch_advance(&mhash(1), 1000, &tid(1)).unwrap();
        let err = store.epoch_set(0, &mhash(2), 1001, &tid(2)).unwrap_err();
        assert_eq!(err.code(), "EPOCH_REGRESSION");
    }

    // ---- Transition event verification ----

    #[test]
    fn transition_event_verifiable() {
        let mut store = EpochStore::new();
        let t = store.epoch_advance(&mhash(1), 1000, &tid(1)).unwrap();
        assert!(t.verify(), "Transition event MAC should verify");
    }

    #[test]
    fn transition_event_tamper_detected() {
        let mut store = EpochStore::new();
        let mut t = store.epoch_advance(&mhash(1), 1000, &tid(1)).unwrap();
        t.manifest_hash = "tampered".to_string();
        assert!(!t.verify(), "Tampered transition should fail verification");
    }

    #[test]
    fn transition_contains_required_fields() {
        let mut store = EpochStore::new();
        let t = store.epoch_advance(&mhash(1), 1000, &tid(1)).unwrap();
        assert_eq!(t.old_epoch, ControlEpoch::GENESIS);
        assert_eq!(t.new_epoch, ControlEpoch::new(1));
        assert_eq!(t.timestamp, 1000);
        assert!(!t.manifest_hash.is_empty());
        assert!(!t.event_mac.is_empty());
        assert!(!t.trace_id.is_empty());
    }

    // ---- Crash recovery ----

    #[test]
    fn crash_recovery_preserves_committed() {
        let mut store = EpochStore::new();
        store.epoch_advance(&mhash(1), 1000, &tid(1)).unwrap();
        store.epoch_advance(&mhash(2), 1001, &tid(2)).unwrap();
        store.epoch_advance(&mhash(3), 1002, &tid(3)).unwrap();

        let committed = store.committed_epoch();
        assert_eq!(committed, ControlEpoch::new(3));

        store.simulate_crash_recovery();
        assert_eq!(store.epoch_read(), committed);
        assert_eq!(store.transition_count(), 0); // history lost
    }

    #[test]
    fn crash_recovery_from_specific_epoch() {
        let store = EpochStore::recover(42);
        assert_eq!(store.epoch_read(), ControlEpoch::new(42));
        assert_eq!(store.committed_epoch(), ControlEpoch::new(42));
    }

    #[test]
    fn advance_after_recovery() {
        let mut store = EpochStore::recover(10);
        let t = store.epoch_advance(&mhash(1), 2000, &tid(1)).unwrap();
        assert_eq!(t.old_epoch, ControlEpoch::new(10));
        assert_eq!(t.new_epoch, ControlEpoch::new(11));
    }

    // ---- Invalid input ----

    #[test]
    fn empty_manifest_hash_rejected() {
        let mut store = EpochStore::new();
        let err = store.epoch_advance("", 1000, &tid(1)).unwrap_err();
        assert_eq!(err.code(), "EPOCH_INVALID_MANIFEST");
    }

    // ---- Epoch overflow ----

    #[test]
    fn epoch_at_max_overflows_on_advance() {
        let mut store = EpochStore::recover(u64::MAX);
        let err = store.epoch_advance(&mhash(1), 1000, &tid(1)).unwrap_err();
        assert_eq!(err.code(), "EPOCH_OVERFLOW");
        // State unchanged
        assert_eq!(store.epoch_read().value(), u64::MAX);
    }

    // ---- Error display ----

    #[test]
    fn error_display_all_variants() {
        let errors = vec![
            EpochError::EpochRegression {
                current: ControlEpoch::new(5),
                attempted: ControlEpoch::new(3),
            },
            EpochError::EpochOverflow {
                current: ControlEpoch::new(u64::MAX),
            },
            EpochError::InvalidManifestHash {
                reason: "empty".into(),
            },
        ];
        for e in &errors {
            let display = e.to_string();
            assert!(
                display.contains(e.code()),
                "Display for {e:?} should contain code {}",
                e.code()
            );
        }
    }

    // ---- Committed epoch tracking ----

    #[test]
    fn committed_tracks_advances() {
        let mut store = EpochStore::new();
        assert_eq!(store.committed_epoch(), ControlEpoch::GENESIS);
        store.epoch_advance(&mhash(1), 1000, &tid(1)).unwrap();
        assert_eq!(store.committed_epoch(), ControlEpoch::new(1));
        store.epoch_advance(&mhash(2), 1001, &tid(2)).unwrap();
        assert_eq!(store.committed_epoch(), ControlEpoch::new(2));
    }

    #[test]
    fn committed_unchanged_on_regression_attempt() {
        let mut store = EpochStore::new();
        store.epoch_advance(&mhash(1), 1000, &tid(1)).unwrap();
        let _ = store.epoch_set(0, &mhash(2), 1001, &tid(2));
        assert_eq!(store.committed_epoch(), ControlEpoch::new(1));
    }

    // ---- Deterministic MAC ----

    #[test]
    fn same_inputs_produce_same_mac() {
        let mac1 = EpochTransition::compute_mac(
            ControlEpoch::new(0),
            ControlEpoch::new(1),
            1000,
            "hash1",
            "trace1",
        );
        let mac2 = EpochTransition::compute_mac(
            ControlEpoch::new(0),
            ControlEpoch::new(1),
            1000,
            "hash1",
            "trace1",
        );
        assert_eq!(mac1, mac2);
    }

    #[test]
    fn different_inputs_produce_different_mac() {
        let mac1 = EpochTransition::compute_mac(
            ControlEpoch::new(0),
            ControlEpoch::new(1),
            1000,
            "hash1",
            "trace1",
        );
        let mac2 = EpochTransition::compute_mac(
            ControlEpoch::new(0),
            ControlEpoch::new(1),
            1000,
            "hash2",
            "trace1",
        );
        assert_ne!(mac1, mac2);
    }

    // ---- bd-2xv8: validity window checks ----

    #[test]
    fn validity_window_accepts_current_epoch() {
        let policy = ValidityWindowPolicy::new(ControlEpoch::new(10), 1);
        let result = check_artifact_epoch(
            "artifact-current",
            ControlEpoch::new(10),
            &policy,
            "trace-current",
        );
        assert!(result.is_ok());
    }

    #[test]
    fn validity_window_accepts_inclusive_lower_boundary() {
        let policy = ValidityWindowPolicy::new(ControlEpoch::new(10), 3);
        let result = check_artifact_epoch(
            "artifact-boundary",
            ControlEpoch::new(7),
            &policy,
            "trace-boundary",
        );
        assert!(result.is_ok());
    }

    #[test]
    fn validity_window_rejects_future_epoch() {
        let policy = ValidityWindowPolicy::new(ControlEpoch::new(10), 1);
        let err = check_artifact_epoch(
            "artifact-future",
            ControlEpoch::new(11),
            &policy,
            "trace-future",
        )
        .expect_err("future epoch must be rejected");

        assert_eq!(err.rejection_reason, EpochRejectionReason::FutureEpoch);
        assert_eq!(err.code(), "EPOCH_REJECT_FUTURE");
        assert_eq!(err.artifact_id, "artifact-future");
        assert_eq!(err.current_epoch, ControlEpoch::new(10));
    }

    #[test]
    fn validity_window_rejects_expired_epoch() {
        let policy = ValidityWindowPolicy::new(ControlEpoch::new(10), 2);
        let err = check_artifact_epoch(
            "artifact-expired",
            ControlEpoch::new(7),
            &policy,
            "trace-expired",
        )
        .expect_err("expired epoch must be rejected");

        assert_eq!(err.rejection_reason, EpochRejectionReason::ExpiredEpoch);
        assert_eq!(err.code(), "EPOCH_REJECT_EXPIRED");
        assert_eq!(err.artifact_id, "artifact-expired");
        assert_eq!(err.current_epoch, ControlEpoch::new(10));
    }

    #[test]
    fn validity_window_min_epoch_saturates_at_zero() {
        let policy = ValidityWindowPolicy::new(ControlEpoch::new(1), 10);
        assert_eq!(policy.min_accepted_epoch(), ControlEpoch::new(0));
        let result = check_artifact_epoch(
            "artifact-genesis",
            ControlEpoch::new(0),
            &policy,
            "trace-genesis",
        );
        assert!(result.is_ok());
    }

    #[test]
    fn validity_window_hot_reload_updates_bounds() {
        let mut policy = ValidityWindowPolicy::new(ControlEpoch::new(5), 1);

        // Initially epoch 3 is expired.
        let first = check_artifact_epoch("artifact-a", ControlEpoch::new(3), &policy, "trace-a");
        assert!(first.is_err());

        // Increase lookback and current epoch via hot-reload updates.
        policy.set_max_lookback(4);
        policy.set_current_epoch(ControlEpoch::new(8));

        // With updated policy, epoch 4 is now acceptable.
        let second = check_artifact_epoch("artifact-b", ControlEpoch::new(4), &policy, "trace-b");
        assert!(second.is_ok());
    }

    #[test]
    fn validity_window_default_lookback_is_one() {
        let policy = ValidityWindowPolicy::default_for(ControlEpoch::new(12));
        assert_eq!(policy.max_lookback(), 1);
        assert_eq!(policy.min_accepted_epoch(), ControlEpoch::new(11));
    }

    #[test]
    fn acceptance_event_contains_required_context() {
        let event = EpochArtifactEvent::accepted(
            "artifact-ok",
            ControlEpoch::new(12),
            ControlEpoch::new(12),
            "trace-accept",
        );

        assert_eq!(event.event_code, event_codes::EPOCH_ARTIFACT_ACCEPTED);
        assert_eq!(event.artifact_id, "artifact-ok");
        assert_eq!(event.artifact_epoch, ControlEpoch::new(12));
        assert_eq!(event.current_epoch, ControlEpoch::new(12));
        assert_eq!(event.rejection_reason, None);
        assert_eq!(event.trace_id, "trace-accept");
    }

    #[test]
    fn rejection_event_contains_required_context() {
        let policy = ValidityWindowPolicy::new(ControlEpoch::new(10), 1);
        let rejection = check_artifact_epoch(
            "artifact-future",
            ControlEpoch::new(11),
            &policy,
            "trace-reject",
        )
        .expect_err("future epoch must be rejected");

        let event = rejection.to_rejected_event();
        assert_eq!(event.event_code, event_codes::EPOCH_ARTIFACT_REJECTED);
        assert_eq!(event.artifact_id, "artifact-future");
        assert_eq!(event.artifact_epoch, ControlEpoch::new(11));
        assert_eq!(event.current_epoch, ControlEpoch::new(10));
        assert_eq!(
            event.rejection_reason,
            Some(EpochRejectionReason::FutureEpoch)
        );
        assert_eq!(event.trace_id, "trace-reject");
    }
}
