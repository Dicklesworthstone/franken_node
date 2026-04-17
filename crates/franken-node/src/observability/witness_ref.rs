//! bd-1oof: Trace-witness references for high-impact evidence entries.
//!
//! High-impact control decisions (quarantine, release, escalate) need
//! traceable links to the observations that caused them. `WitnessRef`
//! embeds stable witness IDs into evidence entries, enabling operators
//! and replay tools to resolve the exact context of each decision.
//!
//! # Invariants
//!
//! - INV-WITNESS-PRESENCE: high-impact entries must have >= 1 witness ref
//! - INV-WITNESS-INTEGRITY: witness hash must match content when available
//! - INV-WITNESS-RESOLVABLE: replay_bundle_locator must be non-empty for resolution

use std::fmt;

use super::evidence_ledger::{DecisionKind, EvidenceEntry};
use crate::security::constant_time::ct_eq_bytes;

const MAX_REFS: usize = 4096;

fn push_bounded<T>(items: &mut Vec<T>, item: T, cap: usize) {
    if cap == 0 {
        items.clear();
        return;
    }
    if items.len() >= cap {
        let overflow = items.len().saturating_sub(cap).saturating_add(1);
        items.drain(0..overflow.min(items.len()));
    }
    items.push(item);
}

/// Stable event codes for structured logging.
pub mod event_codes {
    pub const WITNESS_ATTACHED: &str = "EVD-WITNESS-001";
    pub const WITNESS_VALIDATED: &str = "EVD-WITNESS-002";
    pub const WITNESS_BROKEN_REF: &str = "EVD-WITNESS-003";
    pub const WITNESS_HASH_MISMATCH: &str = "EVD-WITNESS-004";
}

// ── WitnessId ──────────────────────────────────────────────────────

/// Stable, unique identifier for a witness observation.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WitnessId(pub String);

impl WitnessId {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for WitnessId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

// ── WitnessKind ────────────────────────────────────────────────────

/// Classification of the witness observation type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WitnessKind {
    /// Telemetry metric snapshot.
    Telemetry,
    /// System state snapshot.
    StateSnapshot,
    /// Proof artifact (e.g., hash chain, MMR inclusion).
    ProofArtifact,
    /// External signal (e.g., operator input, remote attestation).
    ExternalSignal,
}

impl WitnessKind {
    /// Human-readable label.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Telemetry => "telemetry",
            Self::StateSnapshot => "state_snapshot",
            Self::ProofArtifact => "proof_artifact",
            Self::ExternalSignal => "external_signal",
        }
    }

    /// All variants.
    pub fn all() -> &'static [WitnessKind] {
        &[
            Self::Telemetry,
            Self::StateSnapshot,
            Self::ProofArtifact,
            Self::ExternalSignal,
        ]
    }
}

impl fmt::Display for WitnessKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

// ── WitnessRef ─────────────────────────────────────────────────────

/// A reference to a witness observation backing an evidence entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WitnessRef {
    /// Stable identifier for this witness.
    pub witness_id: WitnessId,
    /// Kind of observation.
    pub witness_kind: WitnessKind,
    /// Optional locator for the replay bundle containing the full witness.
    pub replay_bundle_locator: Option<String>,
    /// SHA-256 hash of the witness content for tamper detection.
    pub integrity_hash: [u8; 32],
}

impl WitnessRef {
    /// Create a new witness reference.
    pub fn new(id: impl Into<String>, kind: WitnessKind, hash: [u8; 32]) -> Self {
        Self {
            witness_id: WitnessId::new(id),
            witness_kind: kind,
            replay_bundle_locator: None,
            integrity_hash: hash,
        }
    }

    /// Set the replay bundle locator.
    pub fn with_locator(mut self, locator: impl Into<String>) -> Self {
        self.replay_bundle_locator = Some(locator.into());
        self
    }

    /// Format integrity hash as hex string.
    pub fn hash_hex(&self) -> String {
        self.integrity_hash
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }
}

// ── WitnessSet ─────────────────────────────────────────────────────

/// A set of witness references attached to an evidence entry.
#[derive(Debug, Clone, Default)]
pub struct WitnessSet {
    refs: Vec<WitnessRef>,
}

impl WitnessSet {
    pub fn new() -> Self {
        Self { refs: Vec::new() }
    }

    /// Add a witness reference.
    pub fn add(&mut self, witness: WitnessRef) {
        push_bounded(&mut self.refs, witness, MAX_REFS);
    }

    /// Number of witness references.
    pub fn len(&self) -> usize {
        self.refs.len()
    }

    /// Whether the set is empty.
    pub fn is_empty(&self) -> bool {
        self.refs.is_empty()
    }

    /// Get all witness references.
    pub fn refs(&self) -> &[WitnessRef] {
        &self.refs
    }

    /// Check for duplicate witness IDs.
    pub fn has_duplicates(&self) -> bool {
        let mut seen = std::collections::BTreeSet::new();
        for w in &self.refs {
            if !seen.insert(&w.witness_id) {
                return true;
            }
        }
        false
    }
}

// ── High-impact classification ─────────────────────────────────────

/// Decision kinds that require witness references.
const HIGH_IMPACT_KINDS: &[DecisionKind] = &[
    DecisionKind::Quarantine,
    DecisionKind::Release,
    DecisionKind::Escalate,
];

/// Check if an evidence entry is high-impact (requires witness refs).
pub fn is_high_impact(entry: &EvidenceEntry) -> bool {
    HIGH_IMPACT_KINDS.contains(&entry.decision_kind)
}

/// Get all high-impact decision kinds.
pub fn high_impact_kinds() -> &'static [DecisionKind] {
    HIGH_IMPACT_KINDS
}

// ── Validation errors ──────────────────────────────────────────────

/// Errors from witness reference validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WitnessValidationError {
    /// High-impact entry with no witness references.
    MissingWitnesses {
        entry_id: String,
        decision_kind: String,
    },
    /// Witness integrity hash doesn't match content.
    IntegrityHashMismatch {
        entry_id: String,
        witness_id: String,
        expected_hex: String,
        actual_hex: String,
    },
    /// Replay bundle locator is empty/unresolvable.
    UnresolvableLocator {
        entry_id: String,
        witness_id: String,
    },
    /// Duplicate witness IDs on the same entry.
    DuplicateWitnessId {
        entry_id: String,
        witness_id: String,
    },
}

impl WitnessValidationError {
    /// Stable error code for each variant.
    pub fn code(&self) -> &'static str {
        match self {
            Self::MissingWitnesses { .. } => "ERR_MISSING_WITNESSES",
            Self::IntegrityHashMismatch { .. } => "ERR_INTEGRITY_HASH_MISMATCH",
            Self::UnresolvableLocator { .. } => "ERR_UNRESOLVABLE_LOCATOR",
            Self::DuplicateWitnessId { .. } => "ERR_DUPLICATE_WITNESS_ID",
        }
    }
}

impl fmt::Display for WitnessValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingWitnesses {
                entry_id,
                decision_kind,
            } => {
                write!(
                    f,
                    "{}: entry={}, kind={}",
                    event_codes::WITNESS_BROKEN_REF,
                    entry_id,
                    decision_kind
                )
            }
            Self::IntegrityHashMismatch {
                entry_id,
                witness_id,
                expected_hex,
                actual_hex,
            } => {
                write!(
                    f,
                    "{}: entry={}, witness={}, expected={}, actual={}",
                    event_codes::WITNESS_HASH_MISMATCH,
                    entry_id,
                    witness_id,
                    expected_hex,
                    actual_hex
                )
            }
            Self::UnresolvableLocator {
                entry_id,
                witness_id,
            } => {
                write!(
                    f,
                    "{}: entry={}, witness={}",
                    event_codes::WITNESS_BROKEN_REF,
                    entry_id,
                    witness_id
                )
            }
            Self::DuplicateWitnessId {
                entry_id,
                witness_id,
            } => {
                write!(
                    f,
                    "{}: entry={}, duplicate witness={}",
                    event_codes::WITNESS_BROKEN_REF,
                    entry_id,
                    witness_id
                )
            }
        }
    }
}

impl std::error::Error for WitnessValidationError {}

// ── WitnessValidator ───────────────────────────────────────────────

/// Validator that checks witness reference completeness and integrity.
///
/// INV-WITNESS-PRESENCE: all high-impact entries must have witness refs.
/// INV-WITNESS-INTEGRITY: hashes must match when content is available.
/// INV-WITNESS-RESOLVABLE: locators must be non-empty for resolution.
#[derive(Debug)]
pub struct WitnessValidator {
    /// Require resolvable locators (stricter mode).
    require_locators: bool,
    /// Count of validated entries.
    validated_count: u64,
    /// Count of rejected entries.
    rejected_count: u64,
}

impl WitnessValidator {
    /// Create a validator with default settings.
    pub fn new() -> Self {
        Self {
            require_locators: false,
            validated_count: 0,
            rejected_count: 0,
        }
    }

    /// Create a validator that also requires locators on every witness.
    pub fn strict() -> Self {
        Self {
            require_locators: true,
            validated_count: 0,
            rejected_count: 0,
        }
    }

    /// Get count of validated entries.
    pub fn validated_count(&self) -> u64 {
        self.validated_count
    }

    /// Get count of rejected entries.
    pub fn rejected_count(&self) -> u64 {
        self.rejected_count
    }

    /// Validate witness references for a given evidence entry.
    ///
    /// Returns Ok(()) if validation passes, Err with first failure otherwise.
    pub fn validate(
        &mut self,
        entry: &EvidenceEntry,
        witnesses: &WitnessSet,
    ) -> Result<(), WitnessValidationError> {
        let entry_id = entry.decision_id.clone();

        // Check presence for high-impact entries
        if is_high_impact(entry) && witnesses.is_empty() {
            self.rejected_count = self.rejected_count.saturating_add(1);
            return Err(WitnessValidationError::MissingWitnesses {
                entry_id,
                decision_kind: entry.decision_kind.label().to_string(),
            });
        }

        // Check for duplicates
        if witnesses.has_duplicates() {
            self.rejected_count = self.rejected_count.saturating_add(1);
            // Find the first duplicate
            let mut seen = std::collections::BTreeSet::new();
            for w in witnesses.refs() {
                if !seen.insert(&w.witness_id) {
                    return Err(WitnessValidationError::DuplicateWitnessId {
                        entry_id,
                        witness_id: w.witness_id.as_str().to_string(),
                    });
                }
            }
        }

        // Check locators if required
        if self.require_locators {
            for w in witnesses.refs() {
                let needs_rejection = match &w.replay_bundle_locator {
                    None => true,
                    Some(s) if s.trim().is_empty() => true,
                    _ => false,
                };
                if needs_rejection {
                    self.rejected_count = self.rejected_count.saturating_add(1);
                    return Err(WitnessValidationError::UnresolvableLocator {
                        entry_id,
                        witness_id: w.witness_id.as_str().to_string(),
                    });
                }
            }
        }

        self.validated_count = self.validated_count.saturating_add(1);
        Ok(())
    }

    /// Validate a witness against expected content hash.
    pub fn verify_integrity(
        &mut self,
        entry_id: &str,
        witness: &WitnessRef,
        actual_content_hash: &[u8; 32],
    ) -> Result<(), WitnessValidationError> {
        if !ct_eq_bytes(&witness.integrity_hash, actual_content_hash) {
            self.rejected_count = self.rejected_count.saturating_add(1);
            return Err(WitnessValidationError::IntegrityHashMismatch {
                entry_id: entry_id.to_string(),
                witness_id: witness.witness_id.as_str().to_string(),
                expected_hex: witness.hash_hex(),
                actual_hex: actual_content_hash
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect(),
            });
        }
        Ok(())
    }

    /// Generate a coverage audit report.
    pub fn coverage_audit(entries_with_witnesses: &[(EvidenceEntry, WitnessSet)]) -> WitnessAudit {
        let mut total_entries = 0u64;
        let mut high_impact_entries = 0u64;
        let mut high_impact_with_witnesses = 0u64;
        let mut total_witnesses = 0u64;
        let mut witness_kind_counts = std::collections::BTreeMap::new();

        for (entry, witnesses) in entries_with_witnesses {
            total_entries = total_entries.saturating_add(1);
            if is_high_impact(entry) {
                high_impact_entries = high_impact_entries.saturating_add(1);
                if !witnesses.is_empty() {
                    high_impact_with_witnesses = high_impact_with_witnesses.saturating_add(1);
                }
            }
            for w in witnesses.refs() {
                total_witnesses = total_witnesses.saturating_add(1);
                let count = witness_kind_counts
                    .entry(w.witness_kind.label().to_string())
                    .or_insert(0u64);
                *count = count.saturating_add(1);
            }
        }

        WitnessAudit {
            total_entries,
            high_impact_entries,
            high_impact_with_witnesses,
            total_witnesses,
            coverage_pct: if high_impact_entries > 0 {
                (high_impact_with_witnesses as f64 / high_impact_entries as f64) * 100.0
            } else {
                100.0
            },
            witness_kind_counts,
        }
    }
}

impl Default for WitnessValidator {
    fn default() -> Self {
        Self::new()
    }
}

// ── WitnessAudit ───────────────────────────────────────────────────

/// Summary of witness coverage across a set of evidence entries.
#[derive(Debug, Clone)]
pub struct WitnessAudit {
    pub total_entries: u64,
    pub high_impact_entries: u64,
    pub high_impact_with_witnesses: u64,
    pub total_witnesses: u64,
    pub coverage_pct: f64,
    pub witness_kind_counts: std::collections::BTreeMap<String, u64>,
}

impl WitnessAudit {
    /// Whether coverage is 100% for high-impact entries.
    pub fn is_complete(&self) -> bool {
        self.high_impact_entries == self.high_impact_with_witnesses
    }
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_hash(seed: u8) -> [u8; 32] {
        let mut hash = [0u8; 32];
        hash[0] = seed;
        hash[31] = seed;
        hash
    }

    fn make_entry(kind: DecisionKind) -> EvidenceEntry {
        EvidenceEntry {
            schema_version: "1.0".to_string(),
            entry_id: None,
            decision_id: "DEC-001".to_string(),
            decision_kind: kind,
            decision_time: String::new(),
            timestamp_ms: 1000,
            trace_id: "trace-test".to_string(),
            epoch_id: 1,
            payload: serde_json::json!({}),
            size_bytes: 0,
        }
    }

    fn make_witness(id: &str, kind: WitnessKind) -> WitnessRef {
        WitnessRef::new(id, kind, make_hash(1))
    }

    // ── WitnessId tests ──

    #[test]
    fn witness_id_display() {
        let id = WitnessId::new("WIT-001");
        assert_eq!(id.to_string(), "WIT-001");
        assert_eq!(id.as_str(), "WIT-001");
    }

    #[test]
    fn witness_id_equality() {
        let a = WitnessId::new("WIT-001");
        let b = WitnessId::new("WIT-001");
        assert_eq!(a, b);
    }

    // ── WitnessKind tests ──

    #[test]
    fn witness_kind_labels() {
        assert_eq!(WitnessKind::Telemetry.label(), "telemetry");
        assert_eq!(WitnessKind::StateSnapshot.label(), "state_snapshot");
        assert_eq!(WitnessKind::ProofArtifact.label(), "proof_artifact");
        assert_eq!(WitnessKind::ExternalSignal.label(), "external_signal");
    }

    #[test]
    fn witness_kind_all_four_variants() {
        assert_eq!(WitnessKind::all().len(), 4);
    }

    #[test]
    fn witness_kind_display() {
        assert_eq!(WitnessKind::Telemetry.to_string(), "telemetry");
    }

    // ── WitnessRef tests ──

    #[test]
    fn witness_ref_creation() {
        let w = make_witness("WIT-001", WitnessKind::Telemetry);
        assert_eq!(w.witness_id.as_str(), "WIT-001");
        assert_eq!(w.witness_kind, WitnessKind::Telemetry);
        assert!(w.replay_bundle_locator.is_none());
    }

    #[test]
    fn witness_ref_with_locator() {
        let w = make_witness("WIT-001", WitnessKind::Telemetry)
            .with_locator("file:///replay/bundle-001.jsonl");
        assert_eq!(
            w.replay_bundle_locator.as_deref(),
            Some("file:///replay/bundle-001.jsonl")
        );
    }

    #[test]
    fn witness_ref_hash_hex() {
        let mut hash = [0u8; 32];
        hash[0] = 0xab;
        hash[1] = 0xcd;
        let w = WitnessRef::new("WIT-001", WitnessKind::Telemetry, hash);
        let hex = w.hash_hex();
        assert!(hex.starts_with("abcd"));
        assert_eq!(hex.len(), 64);
    }

    // ── WitnessSet tests ──

    #[test]
    fn witness_set_empty() {
        let set = WitnessSet::new();
        assert!(set.is_empty());
        assert_eq!(set.len(), 0);
    }

    #[test]
    fn witness_set_add() {
        let mut set = WitnessSet::new();
        set.add(make_witness("WIT-001", WitnessKind::Telemetry));
        set.add(make_witness("WIT-002", WitnessKind::StateSnapshot));
        assert_eq!(set.len(), 2);
        assert!(!set.is_empty());
    }

    #[test]
    fn witness_set_no_duplicates() {
        let mut set = WitnessSet::new();
        set.add(make_witness("WIT-001", WitnessKind::Telemetry));
        set.add(make_witness("WIT-002", WitnessKind::StateSnapshot));
        assert!(!set.has_duplicates());
    }

    #[test]
    fn witness_set_detects_duplicates() {
        let mut set = WitnessSet::new();
        set.add(make_witness("WIT-001", WitnessKind::Telemetry));
        set.add(make_witness("WIT-001", WitnessKind::StateSnapshot));
        assert!(set.has_duplicates());
    }

    // ── is_high_impact tests ──

    #[test]
    fn quarantine_is_high_impact() {
        let entry = make_entry(DecisionKind::Quarantine);
        assert!(is_high_impact(&entry));
    }

    #[test]
    fn release_is_high_impact() {
        let entry = make_entry(DecisionKind::Release);
        assert!(is_high_impact(&entry));
    }

    #[test]
    fn escalate_is_high_impact() {
        let entry = make_entry(DecisionKind::Escalate);
        assert!(is_high_impact(&entry));
    }

    #[test]
    fn admit_is_not_high_impact() {
        let entry = make_entry(DecisionKind::Admit);
        assert!(!is_high_impact(&entry));
    }

    #[test]
    fn deny_is_not_high_impact() {
        let entry = make_entry(DecisionKind::Deny);
        assert!(!is_high_impact(&entry));
    }

    #[test]
    fn rollback_is_not_high_impact() {
        let entry = make_entry(DecisionKind::Rollback);
        assert!(!is_high_impact(&entry));
    }

    #[test]
    fn throttle_is_not_high_impact() {
        let entry = make_entry(DecisionKind::Throttle);
        assert!(!is_high_impact(&entry));
    }

    #[test]
    fn all_decision_kinds_classified() {
        // Ensure we've covered every DecisionKind variant
        let all_kinds = [
            DecisionKind::Admit,
            DecisionKind::Deny,
            DecisionKind::Quarantine,
            DecisionKind::Release,
            DecisionKind::Rollback,
            DecisionKind::Throttle,
            DecisionKind::Escalate,
        ];
        let high = all_kinds
            .iter()
            .filter(|k| HIGH_IMPACT_KINDS.contains(k))
            .count();
        let low = all_kinds
            .iter()
            .filter(|k| !HIGH_IMPACT_KINDS.contains(k))
            .count();
        assert_eq!(high, 3); // Quarantine, Release, Escalate
        assert_eq!(low, 4); // Admit, Deny, Rollback, Throttle
    }

    // ── WitnessValidator: basic validation ──

    #[test]
    fn high_impact_with_witnesses_passes() {
        let mut validator = WitnessValidator::new();
        let entry = make_entry(DecisionKind::Quarantine);
        let mut witnesses = WitnessSet::new();
        witnesses.add(make_witness("WIT-001", WitnessKind::StateSnapshot));

        let result = validator.validate(&entry, &witnesses);
        assert!(result.is_ok());
        assert_eq!(validator.validated_count(), 1);
    }

    #[test]
    fn high_impact_without_witnesses_rejected() {
        let mut validator = WitnessValidator::new();
        let entry = make_entry(DecisionKind::Quarantine);
        let witnesses = WitnessSet::new();

        let result = validator.validate(&entry, &witnesses);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), "ERR_MISSING_WITNESSES");
        assert_eq!(validator.rejected_count(), 1);
    }

    #[test]
    fn non_high_impact_without_witnesses_passes() {
        let mut validator = WitnessValidator::new();
        let entry = make_entry(DecisionKind::Admit);
        let witnesses = WitnessSet::new();

        let result = validator.validate(&entry, &witnesses);
        assert!(result.is_ok());
    }

    #[test]
    fn non_high_impact_with_witnesses_passes() {
        let mut validator = WitnessValidator::new();
        let entry = make_entry(DecisionKind::Admit);
        let mut witnesses = WitnessSet::new();
        witnesses.add(make_witness("WIT-001", WitnessKind::Telemetry));

        let result = validator.validate(&entry, &witnesses);
        assert!(result.is_ok());
    }

    #[test]
    fn duplicate_witness_ids_rejected() {
        let mut validator = WitnessValidator::new();
        let entry = make_entry(DecisionKind::Quarantine);
        let mut witnesses = WitnessSet::new();
        witnesses.add(make_witness("WIT-001", WitnessKind::Telemetry));
        witnesses.add(make_witness("WIT-001", WitnessKind::StateSnapshot));

        let result = validator.validate(&entry, &witnesses);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), "ERR_DUPLICATE_WITNESS_ID");
    }

    // ── Strict mode: locator required ──

    #[test]
    fn strict_mode_requires_locator() {
        let mut validator = WitnessValidator::strict();
        let entry = make_entry(DecisionKind::Quarantine);
        let mut witnesses = WitnessSet::new();
        witnesses.add(make_witness("WIT-001", WitnessKind::Telemetry));
        // No locator set

        let result = validator.validate(&entry, &witnesses);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), "ERR_UNRESOLVABLE_LOCATOR");
    }

    #[test]
    fn strict_mode_with_locator_passes() {
        let mut validator = WitnessValidator::strict();
        let entry = make_entry(DecisionKind::Quarantine);
        let mut witnesses = WitnessSet::new();
        witnesses.add(
            make_witness("WIT-001", WitnessKind::Telemetry)
                .with_locator("file:///bundles/replay-001.jsonl"),
        );

        let result = validator.validate(&entry, &witnesses);
        assert!(result.is_ok());
    }

    #[test]
    fn strict_mode_empty_locator_rejected() {
        let mut validator = WitnessValidator::strict();
        let entry = make_entry(DecisionKind::Release);
        let mut witnesses = WitnessSet::new();
        witnesses.add(
            make_witness("WIT-001", WitnessKind::Telemetry).with_locator(""), // empty locator
        );

        let result = validator.validate(&entry, &witnesses);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), "ERR_UNRESOLVABLE_LOCATOR");
    }

    // ── Integrity verification ──

    #[test]
    fn integrity_hash_matches() {
        let mut validator = WitnessValidator::new();
        let witness = make_witness("WIT-001", WitnessKind::Telemetry);
        let actual = make_hash(1); // same hash

        let result = validator.verify_integrity("DEC-001", &witness, &actual);
        assert!(result.is_ok());
    }

    #[test]
    fn integrity_hash_mismatch_rejected() {
        let mut validator = WitnessValidator::new();
        let witness = make_witness("WIT-001", WitnessKind::Telemetry);
        let actual = make_hash(99); // different hash

        let result = validator.verify_integrity("DEC-001", &witness, &actual);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), "ERR_INTEGRITY_HASH_MISMATCH");
    }

    // ── Error display ──

    #[test]
    fn validation_error_display_missing() {
        let err = WitnessValidationError::MissingWitnesses {
            entry_id: "DEC-001".into(),
            decision_kind: "quarantine".into(),
        };
        let display = err.to_string();
        assert!(display.contains("EVD-WITNESS-003"));
        assert!(display.contains("quarantine"));
    }

    #[test]
    fn validation_error_display_hash_mismatch() {
        let err = WitnessValidationError::IntegrityHashMismatch {
            entry_id: "DEC-001".into(),
            witness_id: "WIT-001".into(),
            expected_hex: "ab".into(),
            actual_hex: "cd".into(),
        };
        let display = err.to_string();
        assert!(display.contains("EVD-WITNESS-004"));
    }

    // ── Coverage audit ──

    #[test]
    fn coverage_audit_complete() {
        let mut set1 = WitnessSet::new();
        set1.add(make_witness("WIT-001", WitnessKind::Telemetry));

        let mut set2 = WitnessSet::new();
        set2.add(make_witness("WIT-002", WitnessKind::StateSnapshot));

        let entries = vec![
            (make_entry(DecisionKind::Quarantine), set1),
            (make_entry(DecisionKind::Release), set2),
            (make_entry(DecisionKind::Admit), WitnessSet::new()),
        ];

        let audit = WitnessValidator::coverage_audit(&entries);
        assert_eq!(audit.total_entries, 3);
        assert_eq!(audit.high_impact_entries, 2);
        assert_eq!(audit.high_impact_with_witnesses, 2);
        assert_eq!(audit.total_witnesses, 2);
        assert!(audit.is_complete());
        assert!((audit.coverage_pct - 100.0).abs() < f64::EPSILON);
    }

    #[test]
    fn coverage_audit_incomplete() {
        let entries = vec![
            (make_entry(DecisionKind::Quarantine), WitnessSet::new()),
            (make_entry(DecisionKind::Admit), WitnessSet::new()),
        ];

        let audit = WitnessValidator::coverage_audit(&entries);
        assert_eq!(audit.high_impact_entries, 1);
        assert_eq!(audit.high_impact_with_witnesses, 0);
        assert!(!audit.is_complete());
        assert!((audit.coverage_pct - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn coverage_audit_no_high_impact() {
        let entries = vec![
            (make_entry(DecisionKind::Admit), WitnessSet::new()),
            (make_entry(DecisionKind::Deny), WitnessSet::new()),
        ];

        let audit = WitnessValidator::coverage_audit(&entries);
        assert!(audit.is_complete()); // No high-impact = 100% coverage
    }

    #[test]
    fn coverage_audit_witness_kind_counts() {
        let mut set = WitnessSet::new();
        set.add(make_witness("WIT-001", WitnessKind::Telemetry));
        set.add(make_witness("WIT-002", WitnessKind::Telemetry));
        set.add(make_witness("WIT-003", WitnessKind::ProofArtifact));

        let entries = vec![(make_entry(DecisionKind::Escalate), set)];

        let audit = WitnessValidator::coverage_audit(&entries);
        assert_eq!(
            *audit
                .witness_kind_counts
                .get("telemetry")
                .expect("should succeed"),
            2
        );
        assert_eq!(
            *audit
                .witness_kind_counts
                .get("proof_artifact")
                .expect("should succeed"),
            1
        );
    }

    // ── All three high-impact kinds require witnesses ──

    #[test]
    fn all_high_impact_kinds_require_witnesses() {
        for kind in high_impact_kinds() {
            let mut validator = WitnessValidator::new();
            let entry = make_entry(*kind);
            let witnesses = WitnessSet::new();

            let result = validator.validate(&entry, &witnesses);
            assert!(
                result.is_err(),
                "kind {} should require witnesses",
                kind.label()
            );
        }
    }

    // ── Multiple witnesses on single entry ──

    #[test]
    fn multiple_witnesses_preserves_ordering() {
        let mut set = WitnessSet::new();
        set.add(make_witness("WIT-A", WitnessKind::Telemetry));
        set.add(make_witness("WIT-B", WitnessKind::StateSnapshot));
        set.add(make_witness("WIT-C", WitnessKind::ProofArtifact));

        let refs = set.refs();
        assert_eq!(refs[0].witness_id.as_str(), "WIT-A");
        assert_eq!(refs[1].witness_id.as_str(), "WIT-B");
        assert_eq!(refs[2].witness_id.as_str(), "WIT-C");
    }

    // ── Validator counters ──

    #[test]
    fn validator_counters_accumulate() {
        let mut validator = WitnessValidator::new();

        // Pass
        let entry1 = make_entry(DecisionKind::Quarantine);
        let mut set1 = WitnessSet::new();
        set1.add(make_witness("WIT-001", WitnessKind::Telemetry));
        validator.validate(&entry1, &set1).expect("should succeed");

        // Fail
        let entry2 = make_entry(DecisionKind::Release);
        let set2 = WitnessSet::new();
        let _ = validator.validate(&entry2, &set2);

        assert_eq!(validator.validated_count(), 1);
        assert_eq!(validator.rejected_count(), 1);
    }

    mod metamorphic_witness_tests {
        use super::*;

        fn set_with(witnesses: &[(&str, WitnessKind)]) -> WitnessSet {
            let mut set = WitnessSet::new();
            for (id, kind) in witnesses {
                set.add(make_witness(id, *kind));
            }
            set
        }

        fn locator_set(witnesses: &[(&str, WitnessKind, &str)]) -> WitnessSet {
            let mut set = WitnessSet::new();
            for (id, kind, locator) in witnesses {
                set.add(make_witness(id, *kind).with_locator(*locator));
            }
            set
        }

        fn assert_audit_counts_eq(left: &WitnessAudit, right: &WitnessAudit) {
            assert_eq!(left.total_entries, right.total_entries);
            assert_eq!(left.high_impact_entries, right.high_impact_entries);
            assert_eq!(
                left.high_impact_with_witnesses,
                right.high_impact_with_witnesses
            );
            assert_eq!(left.total_witnesses, right.total_witnesses);
            assert!((left.coverage_pct - right.coverage_pct).abs() < f64::EPSILON);
            assert_eq!(left.witness_kind_counts, right.witness_kind_counts);
        }

        #[test]
        fn coverage_audit_is_invariant_under_entry_permutation() {
            let entries = vec![
                (
                    make_entry(DecisionKind::Quarantine),
                    set_with(&[("WIT-A", WitnessKind::Telemetry)]),
                ),
                (make_entry(DecisionKind::Release), WitnessSet::new()),
                (
                    make_entry(DecisionKind::Admit),
                    set_with(&[("WIT-B", WitnessKind::ProofArtifact)]),
                ),
                (
                    make_entry(DecisionKind::Escalate),
                    set_with(&[("WIT-C", WitnessKind::StateSnapshot)]),
                ),
            ];
            let mut reversed = entries.clone();
            reversed.reverse();

            let baseline = WitnessValidator::coverage_audit(&entries);
            let permuted = WitnessValidator::coverage_audit(&reversed);

            assert_audit_counts_eq(&baseline, &permuted);
        }

        #[test]
        fn adding_low_impact_entry_preserves_high_impact_coverage_ratio() {
            let baseline_entries = vec![
                (
                    make_entry(DecisionKind::Quarantine),
                    set_with(&[("WIT-A", WitnessKind::Telemetry)]),
                ),
                (make_entry(DecisionKind::Release), WitnessSet::new()),
            ];
            let mut expanded_entries = baseline_entries.clone();
            expanded_entries.push((make_entry(DecisionKind::Deny), WitnessSet::new()));

            let baseline = WitnessValidator::coverage_audit(&baseline_entries);
            let expanded = WitnessValidator::coverage_audit(&expanded_entries);

            assert_eq!(expanded.total_entries, baseline.total_entries + 1);
            assert_eq!(expanded.high_impact_entries, baseline.high_impact_entries);
            assert_eq!(
                expanded.high_impact_with_witnesses,
                baseline.high_impact_with_witnesses
            );
            assert!((expanded.coverage_pct - baseline.coverage_pct).abs() < f64::EPSILON);
        }

        #[test]
        fn adding_witness_to_missing_high_impact_entry_increases_coverage() {
            let incomplete_entries = vec![
                (
                    make_entry(DecisionKind::Quarantine),
                    set_with(&[("WIT-A", WitnessKind::Telemetry)]),
                ),
                (make_entry(DecisionKind::Release), WitnessSet::new()),
            ];
            let complete_entries = vec![
                (
                    make_entry(DecisionKind::Quarantine),
                    set_with(&[("WIT-A", WitnessKind::Telemetry)]),
                ),
                (
                    make_entry(DecisionKind::Release),
                    set_with(&[("WIT-B", WitnessKind::ExternalSignal)]),
                ),
            ];

            let incomplete = WitnessValidator::coverage_audit(&incomplete_entries);
            let complete = WitnessValidator::coverage_audit(&complete_entries);

            assert_eq!(complete.high_impact_entries, incomplete.high_impact_entries);
            assert_eq!(
                complete.high_impact_with_witnesses,
                incomplete.high_impact_with_witnesses + 1
            );
            assert!(complete.coverage_pct > incomplete.coverage_pct);
            assert!(complete.is_complete());
        }

        #[test]
        fn adding_witness_changes_only_matching_kind_count_and_total() {
            let baseline_entries = vec![(
                make_entry(DecisionKind::Escalate),
                set_with(&[
                    ("WIT-A", WitnessKind::Telemetry),
                    ("WIT-B", WitnessKind::ProofArtifact),
                ]),
            )];
            let expanded_entries = vec![(
                make_entry(DecisionKind::Escalate),
                set_with(&[
                    ("WIT-A", WitnessKind::Telemetry),
                    ("WIT-B", WitnessKind::ProofArtifact),
                    ("WIT-C", WitnessKind::Telemetry),
                ]),
            )];

            let baseline = WitnessValidator::coverage_audit(&baseline_entries);
            let expanded = WitnessValidator::coverage_audit(&expanded_entries);

            assert_eq!(expanded.total_witnesses, baseline.total_witnesses + 1);
            assert_eq!(
                expanded.witness_kind_counts.get("telemetry"),
                Some(&(baseline.witness_kind_counts["telemetry"] + 1))
            );
            assert_eq!(
                expanded.witness_kind_counts.get("proof_artifact"),
                baseline.witness_kind_counts.get("proof_artifact")
            );
            assert_eq!(
                expanded.witness_kind_counts.get("state_snapshot"),
                baseline.witness_kind_counts.get("state_snapshot")
            );
            assert_eq!(
                expanded.witness_kind_counts.get("external_signal"),
                baseline.witness_kind_counts.get("external_signal")
            );
        }

        #[test]
        fn strict_mode_is_monotonic_over_lenient_locator_policy() {
            let entry = make_entry(DecisionKind::Quarantine);
            let witnesses_without_locator = set_with(&[("WIT-A", WitnessKind::Telemetry)]);
            let witnesses_with_locator = locator_set(&[(
                "WIT-A",
                WitnessKind::Telemetry,
                "file:///bundles/replay-001.jsonl",
            )]);

            assert!(
                WitnessValidator::new()
                    .validate(&entry, &witnesses_without_locator)
                    .is_ok()
            );
            assert!(
                WitnessValidator::strict()
                    .validate(&entry, &witnesses_without_locator)
                    .is_err()
            );
            assert!(
                WitnessValidator::strict()
                    .validate(&entry, &witnesses_with_locator)
                    .is_ok()
            );
        }

        #[test]
        fn strict_mode_rejects_whitespace_only_locator() {
            let entry = make_entry(DecisionKind::Quarantine);
            let witnesses = locator_set(&[("WIT-A", WitnessKind::Telemetry, " \t\n ")]);
            let mut validator = WitnessValidator::strict();

            let err = validator
                .validate(&entry, &witnesses)
                .expect_err("whitespace locator should be unresolvable");

            assert_eq!(err.code(), "ERR_UNRESOLVABLE_LOCATOR");
            assert_eq!(validator.validated_count(), 0);
            assert_eq!(validator.rejected_count(), 1);
        }

        #[test]
        fn duplicate_rejection_is_invariant_to_duplicate_position() {
            let entry = make_entry(DecisionKind::Release);
            let adjacent = set_with(&[
                ("WIT-A", WitnessKind::Telemetry),
                ("WIT-A", WitnessKind::ProofArtifact),
                ("WIT-B", WitnessKind::StateSnapshot),
            ]);
            let separated = set_with(&[
                ("WIT-A", WitnessKind::Telemetry),
                ("WIT-B", WitnessKind::StateSnapshot),
                ("WIT-A", WitnessKind::ProofArtifact),
            ]);

            let adjacent_err = WitnessValidator::new()
                .validate(&entry, &adjacent)
                .expect_err("adjacent duplicate should fail");
            let separated_err = WitnessValidator::new()
                .validate(&entry, &separated)
                .expect_err("separated duplicate should fail");

            assert_eq!(adjacent_err.code(), "ERR_DUPLICATE_WITNESS_ID");
            assert_eq!(separated_err.code(), "ERR_DUPLICATE_WITNESS_ID");
            assert_eq!(adjacent_err, separated_err);
        }

        #[test]
        fn duplicate_rejection_does_not_increment_validated_count() {
            let entry = make_entry(DecisionKind::Escalate);
            let witnesses = set_with(&[
                ("WIT-A", WitnessKind::Telemetry),
                ("WIT-A", WitnessKind::ProofArtifact),
            ]);
            let mut validator = WitnessValidator::new();

            let err = validator
                .validate(&entry, &witnesses)
                .expect_err("duplicate witness id should fail");

            assert_eq!(err.code(), "ERR_DUPLICATE_WITNESS_ID");
            assert_eq!(validator.validated_count(), 0);
            assert_eq!(validator.rejected_count(), 1);
        }

        #[test]
        fn integrity_verification_fails_on_single_bit_mutation_then_recovers() {
            let witness = make_witness("WIT-A", WitnessKind::Telemetry);
            let mut mutated_hash = witness.integrity_hash;
            mutated_hash[7] ^= 0b0000_0001;

            assert!(
                WitnessValidator::new()
                    .verify_integrity("DEC-001", &witness, &mutated_hash)
                    .is_err()
            );

            mutated_hash[7] ^= 0b0000_0001;
            assert!(
                WitnessValidator::new()
                    .verify_integrity("DEC-001", &witness, &mutated_hash)
                    .is_ok()
            );
        }

        #[test]
        fn non_high_impact_kinds_accept_empty_witness_sets() {
            for kind in [
                DecisionKind::Admit,
                DecisionKind::Deny,
                DecisionKind::Rollback,
                DecisionKind::Throttle,
            ] {
                assert!(
                    WitnessValidator::new()
                        .validate(&make_entry(kind), &WitnessSet::new())
                        .is_ok(),
                    "{} should not require a witness set",
                    kind.label()
                );
            }
        }

        #[test]
        fn push_bounded_zero_capacity_discards_without_panic() {
            let mut values = vec![1, 2, 3];

            push_bounded(&mut values, 4, 0);

            assert!(values.is_empty());
        }

        #[test]
        fn push_bounded_keeps_most_recent_items_when_over_capacity() {
            let mut values = Vec::new();

            for value in 0..5 {
                push_bounded(&mut values, value, 3);
            }

            assert_eq!(values, vec![2, 3, 4]);
        }

        #[test]
        fn push_bounded_massive_overflow_maintains_capacity_bound() {
            let mut values = vec![1, 2];

            // Try to add items far exceeding capacity
            for value in 3..=100_000 {
                push_bounded(&mut values, value, 5); // Capacity of 5
            }

            assert_eq!(values.len(), 5);
            assert_eq!(values, vec![99996, 99997, 99998, 99999, 100000]);
        }

        #[test]
        fn push_bounded_capacity_exactly_at_current_length_maintains_bound() {
            let mut values = vec![1, 2, 3];

            push_bounded(&mut values, 4, 3); // Capacity equals current length

            assert_eq!(values.len(), 3);
            assert_eq!(values, vec![2, 3, 4]); // Oldest item (1) evicted
        }
    }

    // ── Comprehensive negative-path edge case tests ──────────────────────

    mod witness_negative_path_edge_tests {
        use super::*;

        #[test]
        fn negative_witness_id_with_extreme_unicode_and_control_patterns() {
            // Test witness IDs with problematic Unicode and control character patterns
            let malicious_witness_patterns = [
                "WIT\u{202E}spoofed", // Right-to-left override
                "WIT\u{200B}\u{FEFF}\u{034F}", // Zero-width/invisible chars
                "WIT\x00null\r\n\t\x1b[31mred\x1b[0m", // Null + control + ANSI
                "WIT\u{1F4A9}\u{1F525}\u{1F4AF}", // Emoji sequence
                "WIT\u{FFFF}\u{10FFFF}", // Max Unicode codepoints
                "\u{0301}\u{0300}WIT\u{0302}", // Combining diacritical marks
                "WIT\u{1D11E}\u{1D122}", // Musical symbols (outside BMP)
                "WIT".repeat(10000), // Extremely long identifier
                "", // Empty witness ID
                "WIT\"/><script>alert('xss')</script>", // XSS injection attempt
                "WIT\":{\"injected\":true,\"evil\":\"", // JSON injection attempt
                "WIT../../../etc/passwd", // Path traversal attempt
                "WIT\r\n\r\n{\"http_header\":\"injection\"}", // HTTP header injection
            ];

            for pattern in &malicious_witness_patterns {
                let witness_id = WitnessId::new(pattern);
                let witness = WitnessRef::new(pattern, WitnessKind::ExternalSignal, make_hash(42))
                    .with_locator("file:///test/replay.jsonl");

                // Basic operations should work
                assert_eq!(witness_id.as_str(), *pattern);
                assert_eq!(witness_id.to_string(), *pattern);

                // Witness creation should work
                assert_eq!(witness.witness_id.as_str(), *pattern);

                // Should work in witness sets
                let mut set = WitnessSet::new();
                set.add(witness);
                assert_eq!(set.len(), 1);
                assert!(!set.has_duplicates());
                assert_eq!(set.refs()[0].witness_id.as_str(), *pattern);

                // Should work with validation (depending on entry type)
                let high_impact_entry = make_entry(DecisionKind::Quarantine);
                let mut validator = WitnessValidator::new();
                let validation_result = validator.validate(&high_impact_entry, &set);
                assert!(validation_result.is_ok(), "witness ID pattern should be accepted: {}", pattern.escape_unicode());

                // Should work with strict validation too
                let mut strict_validator = WitnessValidator::strict();
                let strict_result = strict_validator.validate(&high_impact_entry, &set);
                assert!(strict_result.is_ok(), "witness ID pattern should work with strict validator: {}", pattern.escape_unicode());
            }
        }

        #[test]
        fn negative_replay_bundle_locator_injection_and_traversal_attacks() {
            // Test replay bundle locators with various injection and traversal attacks
            let malicious_locators = [
                "file:///../../../etc/passwd", // Path traversal
                "file:///C:\\Windows\\System32\\config\\sam", // Windows system files
                "file:///dev/null", // Device files
                "file:///proc/self/mem", // Process memory
                "http://evil.com/steal.php?data=", // HTTP exfiltration attempt
                "javascript:alert('xss')", // JavaScript injection
                "data:text/html,<script>alert('xss')</script>", // Data URL injection
                "ftp://attacker.com/upload/", // FTP upload attempt
                "file:///var/log/auth.log", // Log files
                "smb://evil.com/share/malware.exe", // SMB injection
                "\x00/etc/passwd", // Null byte injection
                "file:///replay.jsonl\r\nHost: evil.com", // HTTP header injection
                "file:///replay.jsonl#fragment<script>", // Fragment injection
                "file:///replay.jsonl?param=<script>alert(1)</script>", // Query injection
                "file://" + &"A".repeat(100000), // Extremely long path
                "file://\u{202E}normal.jsonl\u{202D}evil.exe", // Bidirectional text attack
            ];

            for malicious_locator in &malicious_locators {
                let witness = WitnessRef::new("WIT-001", WitnessKind::ProofArtifact, make_hash(1))
                    .with_locator(malicious_locator);

                // Basic locator access should work
                assert_eq!(witness.replay_bundle_locator.as_deref(), Some(*malicious_locator));

                // Should work in witness sets
                let mut set = WitnessSet::new();
                set.add(witness);
                assert_eq!(set.len(), 1);

                // Validation should handle malicious locators gracefully
                let entry = make_entry(DecisionKind::Escalate);
                let mut validator = WitnessValidator::new();
                let result = validator.validate(&entry, &set);
                assert!(result.is_ok(), "non-strict validation should accept any locator: {}", malicious_locator);

                // Strict validation should accept non-empty locators (even malicious ones)
                let mut strict_validator = WitnessValidator::strict();
                let strict_result = strict_validator.validate(&entry, &set);
                assert!(strict_result.is_ok(), "strict validation should accept non-empty locator: {}", malicious_locator);

                // Coverage audit should handle malicious locators without crashing
                let entries_with_witnesses = vec![(entry, set)];
                let audit = WitnessValidator::coverage_audit(&entries_with_witnesses);
                assert_eq!(audit.total_entries, 1);
                assert_eq!(audit.high_impact_entries, 1);
                assert_eq!(audit.high_impact_with_witnesses, 1);
                assert!(audit.is_complete());
            }
        }

        #[test]
        fn negative_integrity_hash_manipulation_and_collision_simulation() {
            // Test integrity hash handling with various attack patterns
            let collision_simulation_hashes = [
                [0u8; 32], // All zeros
                [0xFF; 32], // All ones
                // Alternating pattern
                {
                    let mut hash = [0u8; 32];
                    for i in 0..32 { hash[i] = if i % 2 == 0 { 0x55 } else { 0xAA }; }
                    hash
                },
                // Sequential pattern
                {
                    let mut hash = [0u8; 32];
                    for i in 0..32 { hash[i] = i as u8; }
                    hash
                },
                // Pathological bit patterns that might confuse hex encoding
                {
                    let mut hash = [0u8; 32];
                    hash[0] = 0xDE; hash[1] = 0xAD; hash[2] = 0xBE; hash[3] = 0xEF;
                    hash[28] = 0xCA; hash[29] = 0xFE; hash[30] = 0xBA; hash[31] = 0xBE;
                    hash
                },
            ];

            for (i, test_hash) in collision_simulation_hashes.iter().enumerate() {
                let witness = WitnessRef::new(format!("WIT-HASH-{}", i), WitnessKind::StateSnapshot, *test_hash);

                // Hash hex encoding should work correctly
                let hex = witness.hash_hex();
                assert_eq!(hex.len(), 64); // 32 bytes * 2 hex chars
                assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));

                // Should be able to verify integrity with correct hash
                let mut validator = WitnessValidator::new();
                let verify_result = validator.verify_integrity("DEC-HASH-TEST", &witness, test_hash);
                assert!(verify_result.is_ok(), "integrity verification should pass with matching hash");

                // Should fail with different hash
                let mut different_hash = *test_hash;
                different_hash[15] ^= 0x01; // Flip one bit
                let verify_mismatch = validator.verify_integrity("DEC-HASH-TEST", &witness, &different_hash);
                assert!(verify_mismatch.is_err(), "integrity verification should fail with mismatched hash");

                if let Err(err) = verify_mismatch {
                    assert_eq!(err.code(), "ERR_INTEGRITY_HASH_MISMATCH");
                    let display = err.to_string();
                    assert!(display.contains("EVD-WITNESS-004"));
                    assert!(display.contains(&hex));
                }

                // Should work in witness sets and validation
                let mut set = WitnessSet::new();
                set.add(witness);
                let entry = make_entry(DecisionKind::Release);
                let validation_result = WitnessValidator::new().validate(&entry, &set);
                assert!(validation_result.is_ok(), "validation should work with any hash pattern");
            }
        }

        #[test]
        fn negative_witness_set_capacity_overflow_with_massive_insertions() {
            // Test witness set behavior under extreme capacity pressure
            let mut set = WitnessSet::new();

            // Test adding witnesses beyond MAX_REFS capacity
            for i in 0..MAX_REFS + 1000 {
                let witness = WitnessRef::new(
                    format!("WIT-OVERFLOW-{:08}", i),
                    match i % 4 {
                        0 => WitnessKind::Telemetry,
                        1 => WitnessKind::StateSnapshot,
                        2 => WitnessKind::ProofArtifact,
                        _ => WitnessKind::ExternalSignal,
                    },
                    {
                        let mut hash = [0u8; 32];
                        // Create unique hash for each witness
                        hash[0] = (i & 0xFF) as u8;
                        hash[1] = ((i >> 8) & 0xFF) as u8;
                        hash[2] = ((i >> 16) & 0xFF) as u8;
                        hash[3] = ((i >> 24) & 0xFF) as u8;
                        hash
                    },
                );
                set.add(witness);
            }

            // Should be bounded at MAX_REFS capacity
            assert_eq!(set.len(), MAX_REFS);
            assert!(!set.is_empty());

            // Should contain the most recent witnesses (due to push_bounded behavior)
            let refs = set.refs();
            assert_eq!(refs.len(), MAX_REFS);

            // Verify no duplicates even at capacity
            assert!(!set.has_duplicates());

            // Should work with validation
            let entry = make_entry(DecisionKind::Quarantine);
            let mut validator = WitnessValidator::new();
            let validation_result = validator.validate(&entry, &set);
            assert!(validation_result.is_ok(), "validation should work with max capacity witness set");

            // Coverage audit should handle large witness sets
            let entries_with_witnesses = vec![(entry, set)];
            let audit = WitnessValidator::coverage_audit(&entries_with_witnesses);
            assert_eq!(audit.total_entries, 1);
            assert_eq!(audit.total_witnesses, MAX_REFS as u64);
            assert!(audit.is_complete());

            // Verify witness kind counts sum to total
            let total_kinds: u64 = audit.witness_kind_counts.values().sum();
            assert_eq!(total_kinds, MAX_REFS as u64);
        }

        #[test]
        fn negative_validator_arithmetic_overflow_boundary_testing() {
            // Test validator counter handling at arithmetic boundaries
            let mut validator = WitnessValidator::new();

            // Manually set counters to near overflow values (simulating long-running validator)
            validator.validated_count = u64::MAX - 5;
            validator.rejected_count = u64::MAX - 3;

            let high_impact_entry = make_entry(DecisionKind::Escalate);
            let mut good_witnesses = WitnessSet::new();
            good_witnesses.add(make_witness("WIT-GOOD", WitnessKind::Telemetry));

            let bad_witnesses = WitnessSet::new(); // Empty for high-impact = rejection

            // Test successful validation with counter near overflow
            for _ in 0..5 {
                let result = validator.validate(&high_impact_entry, &good_witnesses);
                assert!(result.is_ok(), "validation should succeed even near counter overflow");
            }

            // Should saturate at u64::MAX, not wrap around
            assert_eq!(validator.validated_count(), u64::MAX);

            // Test rejection with counter near overflow
            for _ in 0..3 {
                let result = validator.validate(&high_impact_entry, &bad_witnesses);
                assert!(result.is_err(), "validation should fail for missing witnesses");
            }

            // Should saturate at u64::MAX, not wrap around
            assert_eq!(validator.rejected_count(), u64::MAX);

            // Test integrity verification with saturated counters
            let witness = make_witness("WIT-INTEGRITY", WitnessKind::ProofArtifact);
            let wrong_hash = make_hash(99);
            let integrity_result = validator.verify_integrity("DEC-INTEGRITY", &witness, &wrong_hash);
            assert!(integrity_result.is_err(), "integrity verification should still work with saturated counters");
            assert_eq!(validator.rejected_count(), u64::MAX); // Should remain saturated
        }

        #[test]
        fn negative_coverage_audit_with_pathological_witness_kind_distributions() {
            // Test coverage audit with extreme witness kind distributions
            let mut entries_with_witnesses = Vec::new();

            // Pattern 1: Single entry with massive number of same-kind witnesses
            let mut massive_telemetry_set = WitnessSet::new();
            for i in 0..1000 {
                massive_telemetry_set.add(WitnessRef::new(
                    format!("TELEMETRY-{:04}", i),
                    WitnessKind::Telemetry,
                    make_hash((i % 256) as u8),
                ));
            }
            entries_with_witnesses.push((make_entry(DecisionKind::Quarantine), massive_telemetry_set));

            // Pattern 2: Many entries with single witnesses of different kinds
            for (i, &kind) in WitnessKind::all().iter().enumerate() {
                for j in 0..100 {
                    let mut single_witness_set = WitnessSet::new();
                    single_witness_set.add(WitnessRef::new(
                        format!("{}-SINGLE-{:03}-{:03}", kind.label().to_uppercase(), i, j),
                        kind,
                        make_hash(((i * 100 + j) % 256) as u8),
                    ));
                    entries_with_witnesses.push((make_entry(DecisionKind::Release), single_witness_set));
                }
            }

            // Pattern 3: Mixed high-impact and non-high-impact entries
            for i in 0..50 {
                entries_with_witnesses.push((make_entry(DecisionKind::Admit), WitnessSet::new())); // Non-high-impact, no witnesses
                let mut mixed_set = WitnessSet::new();
                for kind in WitnessKind::all() {
                    mixed_set.add(WitnessRef::new(
                        format!("MIXED-{:02}-{}", i, kind.label()),
                        *kind,
                        make_hash(((i as u8) ^ (kind.label().as_bytes()[0])) % 256),
                    ));
                }
                entries_with_witnesses.push((make_entry(DecisionKind::Escalate), mixed_set));
            }

            // Generate audit
            let audit = WitnessValidator::coverage_audit(&entries_with_witnesses);

            // Verify arithmetic correctness
            assert_eq!(audit.total_entries, entries_with_witnesses.len() as u64);

            let expected_high_impact = entries_with_witnesses.iter().filter(|(entry, _)| is_high_impact(entry)).count() as u64;
            assert_eq!(audit.high_impact_entries, expected_high_impact);

            let expected_high_impact_with_witnesses = entries_with_witnesses.iter()
                .filter(|(entry, witnesses)| is_high_impact(entry) && !witnesses.is_empty())
                .count() as u64;
            assert_eq!(audit.high_impact_with_witnesses, expected_high_impact_with_witnesses);

            let expected_total_witnesses: u64 = entries_with_witnesses.iter()
                .map(|(_, witnesses)| witnesses.len() as u64)
                .sum();
            assert_eq!(audit.total_witnesses, expected_total_witnesses);

            // Verify coverage percentage calculation
            let expected_coverage = if audit.high_impact_entries > 0 {
                (audit.high_impact_with_witnesses as f64 / audit.high_impact_entries as f64) * 100.0
            } else {
                100.0
            };
            assert!((audit.coverage_pct - expected_coverage).abs() < f64::EPSILON);

            // Verify witness kind counts
            let total_kind_count: u64 = audit.witness_kind_counts.values().sum();
            assert_eq!(total_kind_count, audit.total_witnesses);

            // Should have counts for all witness kinds that were used
            for kind in WitnessKind::all() {
                let expected_count = entries_with_witnesses.iter()
                    .flat_map(|(_, witnesses)| witnesses.refs())
                    .filter(|w| w.witness_kind == *kind)
                    .count() as u64;

                if expected_count > 0 {
                    assert_eq!(audit.witness_kind_counts.get(kind.label()), Some(&expected_count));
                }
            }
        }

        #[test]
        fn negative_witness_validation_error_display_injection_resistance() {
            // Test validation error display with injection attempts in error fields
            let injection_patterns = [
                "DEC\x00null\r\ninjection", // Null + CRLF injection
                "DEC\u{202E}spoofed", // Right-to-left override
                "DEC<script>alert('xss')</script>", // XSS attempt
                "DEC\r\n\r\nHTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>", // HTTP response injection
                "DEC\t\x08\x7F\x1b[31mred\x1b[0m", // Control chars + ANSI escape
                "DEC\"},{\"injected\":true,\"evil\":\"", // JSON injection attempt
            ];

            for pattern in &injection_patterns {
                // Test MissingWitnesses error with injected entry_id and decision_kind
                let missing_error = WitnessValidationError::MissingWitnesses {
                    entry_id: pattern.to_string(),
                    decision_kind: pattern.to_string(),
                };
                let display = missing_error.to_string();
                assert!(display.contains("EVD-WITNESS-003"));
                // Display should contain the injection pattern (not sanitized, but contained)
                assert!(display.contains(pattern));

                // Test IntegrityHashMismatch error with injected fields
                let mismatch_error = WitnessValidationError::IntegrityHashMismatch {
                    entry_id: pattern.to_string(),
                    witness_id: format!("WIT-{}", pattern),
                    expected_hex: format!("EXPECTED-{}", pattern),
                    actual_hex: format!("ACTUAL-{}", pattern),
                };
                let mismatch_display = mismatch_error.to_string();
                assert!(mismatch_display.contains("EVD-WITNESS-004"));
                assert!(mismatch_display.contains(pattern));

                // Test UnresolvableLocator error
                let unresolvable_error = WitnessValidationError::UnresolvableLocator {
                    entry_id: pattern.to_string(),
                    witness_id: format!("WIT-{}", pattern),
                };
                let unresolvable_display = unresolvable_error.to_string();
                assert!(unresolvable_display.contains("EVD-WITNESS-003"));
                assert!(unresolvable_display.contains(pattern));

                // Test DuplicateWitnessId error
                let duplicate_error = WitnessValidationError::DuplicateWitnessId {
                    entry_id: pattern.to_string(),
                    witness_id: format!("WIT-{}", pattern),
                };
                let duplicate_display = duplicate_error.to_string();
                assert!(duplicate_display.contains("EVD-WITNESS-003"));
                assert!(duplicate_display.contains(pattern));

                // Verify error code stability despite injection
                assert_eq!(missing_error.code(), "ERR_MISSING_WITNESSES");
                assert_eq!(mismatch_error.code(), "ERR_INTEGRITY_HASH_MISMATCH");
                assert_eq!(unresolvable_error.code(), "ERR_UNRESOLVABLE_LOCATOR");
                assert_eq!(duplicate_error.code(), "ERR_DUPLICATE_WITNESS_ID");
            }
        }

        #[test]
        fn negative_concurrent_validator_state_consistency_under_rapid_operations() {
            // Test validator state consistency under rapid validation operations
            let mut validator = WitnessValidator::new();

            // Create test data
            let high_impact_entry = make_entry(DecisionKind::Quarantine);
            let low_impact_entry = make_entry(DecisionKind::Admit);
            let good_witnesses = {
                let mut set = WitnessSet::new();
                set.add(make_witness("WIT-GOOD", WitnessKind::Telemetry));
                set
            };
            let bad_witnesses = WitnessSet::new(); // Empty = missing witnesses for high-impact
            let duplicate_witnesses = {
                let mut set = WitnessSet::new();
                set.add(make_witness("WIT-DUP", WitnessKind::Telemetry));
                set.add(make_witness("WIT-DUP", WitnessKind::StateSnapshot)); // Duplicate ID
                set
            };

            // Simulate rapid operations that mix successes and failures
            let operations = [
                (&high_impact_entry, &good_witnesses, true),   // Should succeed
                (&low_impact_entry, &bad_witnesses, true),     // Should succeed (low impact can have no witnesses)
                (&high_impact_entry, &bad_witnesses, false),   // Should fail (missing witnesses)
                (&high_impact_entry, &duplicate_witnesses, false), // Should fail (duplicate IDs)
                (&low_impact_entry, &good_witnesses, true),    // Should succeed
            ];

            let mut expected_validated = 0u64;
            let mut expected_rejected = 0u64;

            for (i, &(entry, witnesses, should_succeed)) in operations.iter().enumerate() {
                let result = validator.validate(entry, witnesses);

                if should_succeed {
                    assert!(result.is_ok(), "operation {} should succeed", i);
                    expected_validated = expected_validated.saturating_add(1);
                } else {
                    assert!(result.is_err(), "operation {} should fail", i);
                    expected_rejected = expected_rejected.saturating_add(1);
                }

                // Verify counters are consistent after each operation
                assert_eq!(validator.validated_count(), expected_validated);
                assert_eq!(validator.rejected_count(), expected_rejected);
            }

            // Test integrity verification operations mixed in
            let witness_with_hash = make_witness("WIT-INTEGRITY", WitnessKind::ProofArtifact);
            let correct_hash = witness_with_hash.integrity_hash;
            let wrong_hash = make_hash(255);

            for i in 0..10 {
                if i % 2 == 0 {
                    let result = validator.verify_integrity("DEC-INTEGRITY-GOOD", &witness_with_hash, &correct_hash);
                    assert!(result.is_ok(), "integrity verification {} should succeed", i);
                } else {
                    let result = validator.verify_integrity("DEC-INTEGRITY-BAD", &witness_with_hash, &wrong_hash);
                    assert!(result.is_err(), "integrity verification {} should fail", i);
                    expected_rejected = expected_rejected.saturating_add(1);
                }

                // Verify counters remain consistent
                assert_eq!(validator.rejected_count(), expected_rejected);
            }

            // Final consistency check
            assert_eq!(validator.validated_count(), expected_validated);
            assert_eq!(validator.rejected_count(), expected_rejected);
        }

        #[test]
        fn negative_witness_kind_exhaustive_boundary_testing() {
            // Test all witness kinds with various edge cases
            for &kind in WitnessKind::all() {
                // Test basic properties
                let label = kind.label();
                assert!(!label.is_empty());
                assert!(label.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'));

                // Test display consistency
                assert_eq!(kind.to_string(), label);

                // Test with extreme witness IDs
                let extreme_ids = [
                    "".to_string(), // Empty
                    "X".repeat(100000), // Very long
                    "\x00\x01\x02".to_string(), // Binary data
                    "\u{1F4A9}".repeat(1000), // Unicode spam
                ];

                for extreme_id in &extreme_ids {
                    let witness = WitnessRef::new(extreme_id, kind, make_hash(42));
                    assert_eq!(witness.witness_kind, kind);
                    assert_eq!(witness.witness_id.as_str(), extreme_id);

                    // Should work in witness sets
                    let mut set = WitnessSet::new();
                    set.add(witness);
                    assert_eq!(set.len(), 1);
                    assert!(!set.has_duplicates());

                    // Should work in coverage audit
                    let entries = vec![(make_entry(DecisionKind::Escalate), set)];
                    let audit = WitnessValidator::coverage_audit(&entries);
                    assert_eq!(audit.witness_kind_counts.get(label), Some(&1));
                }
            }

            // Verify all witness kinds are distinct
            let labels: Vec<&str> = WitnessKind::all().iter().map(|k| k.label()).collect();
            let mut unique_labels = labels.clone();
            unique_labels.sort();
            unique_labels.dedup();
            assert_eq!(labels.len(), unique_labels.len(), "all witness kind labels should be unique");

            // Verify total count is stable
            assert_eq!(WitnessKind::all().len(), 4, "total witness kind count should remain stable");
        }
    }
}
