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
        self.refs.push(witness);
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
            self.rejected_count += 1;
            return Err(WitnessValidationError::MissingWitnesses {
                entry_id,
                decision_kind: entry.decision_kind.label().to_string(),
            });
        }

        // Check for duplicates
        if witnesses.has_duplicates() {
            self.rejected_count += 1;
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
                    Some(s) if s.is_empty() => true,
                    _ => false,
                };
                if needs_rejection {
                    self.rejected_count += 1;
                    return Err(WitnessValidationError::UnresolvableLocator {
                        entry_id,
                        witness_id: w.witness_id.as_str().to_string(),
                    });
                }
            }
        }

        self.validated_count += 1;
        Ok(())
    }

    /// Validate a witness against expected content hash.
    pub fn verify_integrity(
        &mut self,
        entry_id: &str,
        witness: &WitnessRef,
        actual_content_hash: &[u8; 32],
    ) -> Result<(), WitnessValidationError> {
        if witness.integrity_hash != *actual_content_hash {
            self.rejected_count += 1;
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
            total_entries += 1;
            if is_high_impact(entry) {
                high_impact_entries += 1;
                if !witnesses.is_empty() {
                    high_impact_with_witnesses += 1;
                }
            }
            for w in witnesses.refs() {
                total_witnesses += 1;
                *witness_kind_counts
                    .entry(w.witness_kind.label().to_string())
                    .or_insert(0u64) += 1;
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
        assert_eq!(*audit.witness_kind_counts.get("telemetry").unwrap(), 2);
        assert_eq!(*audit.witness_kind_counts.get("proof_artifact").unwrap(), 1);
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
        validator.validate(&entry1, &set1).unwrap();

        // Fail
        let entry2 = make_entry(DecisionKind::Release);
        let set2 = WitnessSet::new();
        let _ = validator.validate(&entry2, &set2);

        assert_eq!(validator.validated_count(), 1);
        assert_eq!(validator.rejected_count(), 1);
    }
}
