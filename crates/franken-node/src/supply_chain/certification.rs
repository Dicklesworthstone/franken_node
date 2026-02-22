//! bd-273: Extension certification levels tied to policy controls.
//!
//! Certification maps provenance (bd-1ah), reputation (bd-ml1), and manifest
//! capabilities (bd-1gx) into a single policy-actionable classification. Each
//! certification level enables or restricts capabilities, deployment contexts,
//! and operational permissions.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::reputation::ReputationTier;

// ── Event codes ──────────────────────────────────────────────────────────────

pub const CERTIFICATION_EVALUATED: &str = "CERTIFICATION_EVALUATED";
pub const CERTIFICATION_ASSIGNED: &str = "CERTIFICATION_ASSIGNED";
pub const CERTIFICATION_PROMOTED: &str = "CERTIFICATION_PROMOTED";
pub const CERTIFICATION_DEMOTED: &str = "CERTIFICATION_DEMOTED";
pub const CERTIFICATION_POLICY_ENFORCED: &str = "CERTIFICATION_POLICY_ENFORCED";
pub const CERTIFICATION_GATE_PASS: &str = "CERTIFICATION_GATE_PASS";
pub const CERTIFICATION_GATE_REJECT: &str = "CERTIFICATION_GATE_REJECT";

// ── Errors ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, thiserror::Error)]
pub enum CertificationError {
    #[error("extension `{0}` not found in certification registry")]
    ExtensionNotFound(String),
    #[error("certification level `{requested:?}` requires evidence: {missing}")]
    MissingEvidence {
        requested: CertificationLevel,
        missing: String,
    },
    #[error("cannot promote from `{from:?}` to `{to:?}`: must be adjacent levels")]
    InvalidPromotion {
        from: CertificationLevel,
        to: CertificationLevel,
    },
    #[error("capability `{capability}` not allowed at certification level `{level:?}`")]
    CapabilityDenied {
        capability: String,
        level: CertificationLevel,
    },
    #[error(
        "deployment context `{context:?}` requires minimum certification `{required:?}`, got `{actual:?}`"
    )]
    InsufficientCertification {
        context: DeploymentContext,
        required: CertificationLevel,
        actual: CertificationLevel,
    },
    #[error("certification audit trail integrity violation")]
    AuditIntegrityViolation,
}

// ── Certification levels ─────────────────────────────────────────────────────

/// Extension certification levels, from least to most trusted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CertificationLevel {
    /// No certification. Extension has not been evaluated.
    Uncertified,
    /// Basic: publisher identity verified, manifest declared.
    Basic,
    /// Standard: provenance chain verified, reputation above threshold.
    Standard,
    /// Verified: reproducible build evidence, extended test coverage.
    Verified,
    /// Audited: independent third-party audit attestation.
    Audited,
}

impl CertificationLevel {
    /// Numeric rank for ordering.
    #[must_use]
    pub fn rank(self) -> u8 {
        match self {
            Self::Uncertified => 0,
            Self::Basic => 1,
            Self::Standard => 2,
            Self::Verified => 3,
            Self::Audited => 4,
        }
    }

    /// Check if this level meets a minimum requirement.
    #[must_use]
    pub fn meets_minimum(self, minimum: Self) -> bool {
        self.rank() >= minimum.rank()
    }

    /// Description of what this level signifies.
    #[must_use]
    pub fn description(self) -> &'static str {
        match self {
            Self::Uncertified => "No certification. Extension has not been evaluated.",
            Self::Basic => "Publisher identity verified. Manifest capabilities declared.",
            Self::Standard => "Provenance chain verified. Publisher reputation above threshold.",
            Self::Verified => "Reproducible build evidence. Extended test coverage confirmed.",
            Self::Audited => "Independent third-party audit attestation completed.",
        }
    }
}

impl std::fmt::Display for CertificationLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Uncertified => write!(f, "uncertified"),
            Self::Basic => write!(f, "basic"),
            Self::Standard => write!(f, "standard"),
            Self::Verified => write!(f, "verified"),
            Self::Audited => write!(f, "audited"),
        }
    }
}

// ── Deployment contexts ──────────────────────────────────────────────────────

/// Deployment contexts with different certification requirements.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentContext {
    Development,
    Staging,
    Production,
}

impl DeploymentContext {
    /// Minimum certification level required for this context.
    #[must_use]
    pub fn minimum_certification(self) -> CertificationLevel {
        match self {
            Self::Development => CertificationLevel::Uncertified,
            Self::Staging => CertificationLevel::Basic,
            Self::Production => CertificationLevel::Standard,
        }
    }
}

// ── Certification criteria ───────────────────────────────────────────────────

/// Provenance level used for certification evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProvenanceLevel {
    None,
    PublisherSigned,
    SignedReproducible,
    IndependentReproduced,
}

/// Input data for certification evaluation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CertificationInput {
    /// Extension identifier.
    pub extension_id: String,
    /// Extension version.
    pub version: String,
    /// Publisher identifier.
    pub publisher_id: String,
    /// Provenance level from attestation verification.
    pub provenance_level: ProvenanceLevel,
    /// Publisher reputation tier.
    pub reputation_tier: ReputationTier,
    /// Publisher reputation score (0..=100).
    pub reputation_score: f64,
    /// Declared capabilities from manifest.
    pub capabilities: BTreeSet<String>,
    /// Whether test coverage evidence is provided.
    pub has_test_coverage_evidence: bool,
    /// Minimum test coverage percentage if evidence is provided.
    pub test_coverage_pct: Option<f64>,
    /// Whether reproducible build evidence is provided.
    pub has_reproducible_build_evidence: bool,
    /// Whether third-party audit attestation is provided.
    pub has_audit_attestation: bool,
    /// Audit attestation details if provided.
    pub audit_attestation: Option<AuditAttestation>,
}

/// Third-party audit attestation details.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuditAttestation {
    pub auditor_id: String,
    pub audit_date: String,
    pub scope: String,
    pub findings_summary: String,
    pub attestation_hash: String,
}

// ── Certification evaluation ─────────────────────────────────────────────────

/// Result of certification evaluation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CertificationResult {
    /// Extension identifier.
    pub extension_id: String,
    /// Assigned certification level.
    pub level: CertificationLevel,
    /// Explanation of why this level was assigned.
    pub explanation: String,
    /// Criteria that were satisfied.
    pub satisfied_criteria: Vec<String>,
    /// Criteria that were not satisfied (blocking next level).
    pub unsatisfied_criteria: Vec<String>,
    /// Maximum achievable level given current evidence.
    pub max_achievable: CertificationLevel,
}

/// Evaluate the certification level for an extension.
///
/// This is a deterministic function: same inputs produce identical results.
#[must_use]
pub fn evaluate_certification(input: &CertificationInput) -> CertificationResult {
    let mut satisfied = Vec::new();
    let mut unsatisfied = Vec::new();

    // Basic criteria: publisher identity and manifest.
    let has_publisher = !input.publisher_id.is_empty();
    let has_manifest = !input.extension_id.is_empty() && !input.version.is_empty();
    if has_publisher {
        satisfied.push("publisher_identity_verified".to_owned());
    } else {
        unsatisfied.push("publisher_identity_verified".to_owned());
    }
    if has_manifest {
        satisfied.push("manifest_declared".to_owned());
    } else {
        unsatisfied.push("manifest_declared".to_owned());
    }

    // Standard criteria: provenance + reputation.
    let has_provenance = input.provenance_level >= ProvenanceLevel::PublisherSigned;
    let has_reputation = input.reputation_tier >= ReputationTier::Provisional;
    if has_provenance {
        satisfied.push("provenance_chain_verified".to_owned());
    } else {
        unsatisfied.push("provenance_chain_verified".to_owned());
    }
    if has_reputation {
        satisfied.push("reputation_above_threshold".to_owned());
    } else {
        unsatisfied.push("reputation_above_threshold".to_owned());
    }

    // Verified criteria: reproducible build + test coverage.
    if input.has_reproducible_build_evidence {
        satisfied.push("reproducible_build_evidence".to_owned());
    } else {
        unsatisfied.push("reproducible_build_evidence".to_owned());
    }
    let adequate_coverage = input.test_coverage_pct.is_some_and(|pct| pct >= 80.0);
    if input.has_test_coverage_evidence && adequate_coverage {
        satisfied.push("test_coverage_above_80pct".to_owned());
    } else {
        unsatisfied.push("test_coverage_above_80pct".to_owned());
    }

    // Audited criteria: third-party attestation.
    if input.has_audit_attestation && input.audit_attestation.is_some() {
        satisfied.push("third_party_audit_attestation".to_owned());
    } else {
        unsatisfied.push("third_party_audit_attestation".to_owned());
    }

    // Determine level based on satisfied criteria.
    let basic_met = has_publisher && has_manifest;
    let standard_met = basic_met && has_provenance && has_reputation;
    let verified_met = standard_met
        && input.has_reproducible_build_evidence
        && input.has_test_coverage_evidence
        && adequate_coverage;
    let audited_met =
        verified_met && input.has_audit_attestation && input.audit_attestation.is_some();

    let level = if audited_met {
        CertificationLevel::Audited
    } else if verified_met {
        CertificationLevel::Verified
    } else if standard_met {
        CertificationLevel::Standard
    } else if basic_met {
        CertificationLevel::Basic
    } else {
        CertificationLevel::Uncertified
    };

    let max_achievable = level; // Current evidence determines max.

    let explanation = format!(
        "Extension '{}' v{} certified at level '{}': {} criteria satisfied, {} unsatisfied.",
        input.extension_id,
        input.version,
        level,
        satisfied.len(),
        unsatisfied.len(),
    );

    CertificationResult {
        extension_id: input.extension_id.clone(),
        level,
        explanation,
        satisfied_criteria: satisfied,
        unsatisfied_criteria: unsatisfied,
        max_achievable,
    }
}

// ── Capability policy ────────────────────────────────────────────────────────

/// Capability categories for policy enforcement.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityCategory {
    FileRead,
    FileWrite,
    NetworkAccess,
    ProcessSpawn,
    CryptoOperations,
    SystemConfiguration,
}

/// Check whether a capability is allowed at a given certification level.
#[must_use]
pub fn is_capability_allowed(capability: &CapabilityCategory, level: CertificationLevel) -> bool {
    match (capability, level) {
        // Uncertified: minimal — read-only file access only.
        (CapabilityCategory::FileRead, CertificationLevel::Uncertified) => true,
        (_, CertificationLevel::Uncertified) => false,

        // Basic: file read/write.
        (
            CapabilityCategory::FileRead | CapabilityCategory::FileWrite,
            CertificationLevel::Basic,
        ) => true,
        (_, CertificationLevel::Basic) => false,

        // Standard: file + network + crypto.
        (
            CapabilityCategory::FileRead
            | CapabilityCategory::FileWrite
            | CapabilityCategory::NetworkAccess
            | CapabilityCategory::CryptoOperations,
            CertificationLevel::Standard,
        ) => true,
        (_, CertificationLevel::Standard) => false,

        // Verified: all except system configuration.
        (CapabilityCategory::SystemConfiguration, CertificationLevel::Verified) => false,
        (_, CertificationLevel::Verified) => true,

        // Audited: all capabilities.
        (_, CertificationLevel::Audited) => true,
    }
}

/// Get the full capability allow list for a certification level.
#[must_use]
pub fn capability_policy(level: CertificationLevel) -> BTreeSet<CapabilityCategory> {
    let all_caps = [
        CapabilityCategory::FileRead,
        CapabilityCategory::FileWrite,
        CapabilityCategory::NetworkAccess,
        CapabilityCategory::ProcessSpawn,
        CapabilityCategory::CryptoOperations,
        CapabilityCategory::SystemConfiguration,
    ];
    all_caps
        .into_iter()
        .filter(|cap| is_capability_allowed(cap, level))
        .collect()
}

// ── Certification registry ───────────────────────────────────────────────────

/// A certification record for a specific extension version.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CertificationRecord {
    /// Extension identifier.
    pub extension_id: String,
    /// Extension version.
    pub version: String,
    /// Current certification level.
    pub level: CertificationLevel,
    /// Timestamp of last evaluation.
    pub evaluated_at: String,
    /// Full evaluation result.
    pub evaluation: CertificationResult,
}

/// Audit entry for certification changes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CertificationAuditEntry {
    /// Monotonic sequence number.
    pub sequence: u64,
    /// Hash of previous entry.
    pub prev_hash: String,
    /// Hash of this entry.
    pub entry_hash: String,
    /// Timestamp.
    pub timestamp: String,
    /// Extension affected.
    pub extension_id: String,
    /// Event.
    pub event: CertificationAuditEvent,
}

/// Events in the certification audit trail.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CertificationAuditEvent {
    Evaluated {
        result: CertificationResult,
    },
    Promoted {
        from: CertificationLevel,
        to: CertificationLevel,
        evidence_ref: String,
    },
    Demoted {
        from: CertificationLevel,
        to: CertificationLevel,
        reason: String,
    },
    PolicyEnforced {
        capability: String,
        level: CertificationLevel,
        allowed: bool,
    },
}

/// The certification registry manages extension certification state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificationRegistry {
    records: BTreeMap<String, CertificationRecord>,
    audit_trail: Vec<CertificationAuditEntry>,
    next_sequence: u64,
}

impl Default for CertificationRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl CertificationRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self {
            records: BTreeMap::new(),
            audit_trail: Vec::new(),
            next_sequence: 0,
        }
    }

    /// Evaluate and register a certification for an extension.
    pub fn evaluate_and_register(
        &mut self,
        input: &CertificationInput,
        timestamp: &str,
    ) -> CertificationResult {
        let result = evaluate_certification(input);

        let key = format!("{}@{}", input.extension_id, input.version);
        let record = CertificationRecord {
            extension_id: input.extension_id.clone(),
            version: input.version.clone(),
            level: result.level,
            evaluated_at: timestamp.to_owned(),
            evaluation: result.clone(),
        };
        self.records.insert(key, record);

        self.append_audit_entry(
            &input.extension_id,
            timestamp,
            CertificationAuditEvent::Evaluated {
                result: result.clone(),
            },
        );

        result
    }

    /// Promote an extension to a higher certification level.
    pub fn promote(
        &mut self,
        extension_id: &str,
        version: &str,
        new_level: CertificationLevel,
        evidence_ref: &str,
        timestamp: &str,
    ) -> Result<(), CertificationError> {
        let key = format!("{extension_id}@{version}");
        let record = self
            .records
            .get_mut(&key)
            .ok_or_else(|| CertificationError::ExtensionNotFound(key.clone()))?;

        let old_level = record.level;
        if new_level.rank() <= old_level.rank() {
            return Err(CertificationError::InvalidPromotion {
                from: old_level,
                to: new_level,
            });
        }
        if new_level.rank() - old_level.rank() > 1 {
            return Err(CertificationError::InvalidPromotion {
                from: old_level,
                to: new_level,
            });
        }

        record.level = new_level;
        record.evaluated_at = timestamp.to_owned();

        self.append_audit_entry(
            extension_id,
            timestamp,
            CertificationAuditEvent::Promoted {
                from: old_level,
                to: new_level,
                evidence_ref: evidence_ref.to_owned(),
            },
        );

        Ok(())
    }

    /// Demote an extension's certification due to trust degradation.
    pub fn demote(
        &mut self,
        extension_id: &str,
        version: &str,
        new_level: CertificationLevel,
        reason: &str,
        timestamp: &str,
    ) -> Result<(), CertificationError> {
        let key = format!("{extension_id}@{version}");
        let record = self
            .records
            .get_mut(&key)
            .ok_or_else(|| CertificationError::ExtensionNotFound(key.clone()))?;

        let old_level = record.level;
        record.level = new_level;
        record.evaluated_at = timestamp.to_owned();

        self.append_audit_entry(
            extension_id,
            timestamp,
            CertificationAuditEvent::Demoted {
                from: old_level,
                to: new_level,
                reason: reason.to_owned(),
            },
        );

        Ok(())
    }

    /// Check deployment gate: does the extension's certification meet context requirements?
    pub fn check_deployment_gate(
        &self,
        extension_id: &str,
        version: &str,
        context: DeploymentContext,
    ) -> Result<(), CertificationError> {
        let key = format!("{extension_id}@{version}");
        let record = self
            .records
            .get(&key)
            .ok_or_else(|| CertificationError::ExtensionNotFound(key.clone()))?;

        let required = context.minimum_certification();
        if record.level.meets_minimum(required) {
            Ok(())
        } else {
            Err(CertificationError::InsufficientCertification {
                context,
                required,
                actual: record.level,
            })
        }
    }

    /// Check capability gate: is a specific capability allowed?
    pub fn check_capability_gate(
        &self,
        extension_id: &str,
        version: &str,
        capability: &CapabilityCategory,
    ) -> Result<(), CertificationError> {
        let key = format!("{extension_id}@{version}");
        let record = self
            .records
            .get(&key)
            .ok_or(CertificationError::ExtensionNotFound(key))?;

        if is_capability_allowed(capability, record.level) {
            Ok(())
        } else {
            Err(CertificationError::CapabilityDenied {
                capability: format!("{capability:?}"),
                level: record.level,
            })
        }
    }

    /// Get a certification record.
    pub fn get_record(
        &self,
        extension_id: &str,
        version: &str,
    ) -> Result<&CertificationRecord, CertificationError> {
        let key = format!("{extension_id}@{version}");
        self.records
            .get(&key)
            .ok_or(CertificationError::ExtensionNotFound(key))
    }

    /// Query audit trail for an extension.
    #[must_use]
    pub fn query_audit_trail(&self, extension_id: &str) -> Vec<&CertificationAuditEntry> {
        self.audit_trail
            .iter()
            .filter(|e| e.extension_id == extension_id)
            .collect()
    }

    /// Verify audit trail integrity via hash chain.
    pub fn verify_audit_integrity(&self) -> Result<(), CertificationError> {
        let mut expected_prev = String::new();
        for entry in &self.audit_trail {
            if entry.prev_hash != expected_prev {
                return Err(CertificationError::AuditIntegrityViolation);
            }
            let computed = compute_entry_hash(entry);
            if computed != entry.entry_hash {
                return Err(CertificationError::AuditIntegrityViolation);
            }
            expected_prev = entry.entry_hash.clone();
        }
        Ok(())
    }

    /// Total registered extensions.
    #[must_use]
    pub fn record_count(&self) -> usize {
        self.records.len()
    }

    /// Total audit entries.
    #[must_use]
    pub fn audit_trail_len(&self) -> usize {
        self.audit_trail.len()
    }

    // ── Internal ─────────────────────────────────────────────────────────

    fn append_audit_entry(
        &mut self,
        extension_id: &str,
        timestamp: &str,
        event: CertificationAuditEvent,
    ) {
        let prev_hash = self
            .audit_trail
            .last()
            .map_or(String::new(), |e| e.entry_hash.clone());

        let sequence = self.next_sequence;
        self.next_sequence += 1;

        let mut entry = CertificationAuditEntry {
            sequence,
            prev_hash,
            entry_hash: String::new(),
            timestamp: timestamp.to_owned(),
            extension_id: extension_id.to_owned(),
            event,
        };
        entry.entry_hash = compute_entry_hash(&entry);
        self.audit_trail.push(entry);
    }
}

fn compute_entry_hash(entry: &CertificationAuditEntry) -> String {
    let payload = format!(
        "{}:{}:{}:{}",
        entry.sequence,
        entry.prev_hash,
        entry.timestamp,
        serde_json::to_string(&entry.event).unwrap_or_default()
    );
    let digest = Sha256::digest(payload.as_bytes());
    format!("sha256:{}", hex::encode(digest))
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn ts(n: u32) -> String {
        format!("2026-01-{n:02}T00:00:00Z")
    }

    fn make_input(
        ext_id: &str,
        provenance: ProvenanceLevel,
        reputation: ReputationTier,
        score: f64,
    ) -> CertificationInput {
        CertificationInput {
            extension_id: ext_id.to_owned(),
            version: "1.0.0".to_owned(),
            publisher_id: "pub-test".to_owned(),
            provenance_level: provenance,
            reputation_tier: reputation,
            reputation_score: score,
            capabilities: BTreeSet::from(["file_read".to_owned()]),
            has_test_coverage_evidence: false,
            test_coverage_pct: None,
            has_reproducible_build_evidence: false,
            has_audit_attestation: false,
            audit_attestation: None,
        }
    }

    #[test]
    fn test_uncertified_without_publisher() {
        let mut input = make_input(
            "ext-1",
            ProvenanceLevel::None,
            ReputationTier::Untrusted,
            10.0,
        );
        input.publisher_id = String::new();
        let result = evaluate_certification(&input);
        assert_eq!(result.level, CertificationLevel::Uncertified);
    }

    #[test]
    fn test_basic_with_publisher_and_manifest() {
        let input = make_input(
            "ext-1",
            ProvenanceLevel::None,
            ReputationTier::Untrusted,
            10.0,
        );
        let result = evaluate_certification(&input);
        assert_eq!(result.level, CertificationLevel::Basic);
        assert!(
            result
                .satisfied_criteria
                .contains(&"publisher_identity_verified".to_owned())
        );
        assert!(
            result
                .satisfied_criteria
                .contains(&"manifest_declared".to_owned())
        );
    }

    #[test]
    fn test_standard_with_provenance_and_reputation() {
        let input = make_input(
            "ext-1",
            ProvenanceLevel::PublisherSigned,
            ReputationTier::Provisional,
            30.0,
        );
        let result = evaluate_certification(&input);
        assert_eq!(result.level, CertificationLevel::Standard);
    }

    #[test]
    fn test_verified_with_build_and_coverage() {
        let mut input = make_input(
            "ext-1",
            ProvenanceLevel::SignedReproducible,
            ReputationTier::Established,
            60.0,
        );
        input.has_reproducible_build_evidence = true;
        input.has_test_coverage_evidence = true;
        input.test_coverage_pct = Some(90.0);
        let result = evaluate_certification(&input);
        assert_eq!(result.level, CertificationLevel::Verified);
    }

    #[test]
    fn test_audited_with_attestation() {
        let mut input = make_input(
            "ext-1",
            ProvenanceLevel::IndependentReproduced,
            ReputationTier::Trusted,
            90.0,
        );
        input.has_reproducible_build_evidence = true;
        input.has_test_coverage_evidence = true;
        input.test_coverage_pct = Some(95.0);
        input.has_audit_attestation = true;
        input.audit_attestation = Some(AuditAttestation {
            auditor_id: "auditor-1".to_owned(),
            audit_date: "2026-01-15".to_owned(),
            scope: "full security audit".to_owned(),
            findings_summary: "no critical findings".to_owned(),
            attestation_hash: "sha256:abc123".to_owned(),
        });
        let result = evaluate_certification(&input);
        assert_eq!(result.level, CertificationLevel::Audited);
    }

    #[test]
    fn test_insufficient_coverage_blocks_verified() {
        let mut input = make_input(
            "ext-1",
            ProvenanceLevel::SignedReproducible,
            ReputationTier::Established,
            60.0,
        );
        input.has_reproducible_build_evidence = true;
        input.has_test_coverage_evidence = true;
        input.test_coverage_pct = Some(50.0); // Below 80% threshold
        let result = evaluate_certification(&input);
        assert_eq!(result.level, CertificationLevel::Standard);
    }

    #[test]
    fn test_deterministic_evaluation() {
        let input = make_input(
            "ext-1",
            ProvenanceLevel::PublisherSigned,
            ReputationTier::Established,
            60.0,
        );
        let r1 = evaluate_certification(&input);
        let r2 = evaluate_certification(&input);
        assert_eq!(r1.level, r2.level);
        assert_eq!(r1.satisfied_criteria, r2.satisfied_criteria);
        assert_eq!(r1.unsatisfied_criteria, r2.unsatisfied_criteria);
    }

    #[test]
    fn test_capability_policy_uncertified() {
        let caps = capability_policy(CertificationLevel::Uncertified);
        assert!(caps.contains(&CapabilityCategory::FileRead));
        assert!(!caps.contains(&CapabilityCategory::NetworkAccess));
        assert!(!caps.contains(&CapabilityCategory::ProcessSpawn));
    }

    #[test]
    fn test_capability_policy_standard() {
        let caps = capability_policy(CertificationLevel::Standard);
        assert!(caps.contains(&CapabilityCategory::FileRead));
        assert!(caps.contains(&CapabilityCategory::NetworkAccess));
        assert!(!caps.contains(&CapabilityCategory::ProcessSpawn));
    }

    #[test]
    fn test_capability_policy_audited() {
        let caps = capability_policy(CertificationLevel::Audited);
        assert_eq!(caps.len(), 6); // All capabilities allowed
    }

    #[test]
    fn test_deployment_gate_development() {
        let mut reg = CertificationRegistry::new();
        let input = make_input(
            "ext-1",
            ProvenanceLevel::None,
            ReputationTier::Untrusted,
            5.0,
        );
        // Even uncertified (actually Basic since publisher is set)
        reg.evaluate_and_register(&input, &ts(1));
        assert!(
            reg.check_deployment_gate("ext-1", "1.0.0", DeploymentContext::Development)
                .is_ok()
        );
    }

    #[test]
    fn test_deployment_gate_production_rejects_basic() {
        let mut reg = CertificationRegistry::new();
        let input = make_input(
            "ext-1",
            ProvenanceLevel::None,
            ReputationTier::Untrusted,
            5.0,
        );
        reg.evaluate_and_register(&input, &ts(1));
        let result = reg.check_deployment_gate("ext-1", "1.0.0", DeploymentContext::Production);
        assert!(matches!(
            result,
            Err(CertificationError::InsufficientCertification { .. })
        ));
    }

    #[test]
    fn test_promotion_adjacent_only() {
        let mut reg = CertificationRegistry::new();
        let input = make_input(
            "ext-1",
            ProvenanceLevel::None,
            ReputationTier::Untrusted,
            5.0,
        );
        reg.evaluate_and_register(&input, &ts(1));

        // Skip from Basic to Verified should fail.
        let result = reg.promote(
            "ext-1",
            "1.0.0",
            CertificationLevel::Verified,
            "evidence-ref",
            &ts(2),
        );
        assert!(matches!(
            result,
            Err(CertificationError::InvalidPromotion { .. })
        ));

        // Adjacent promotion Basic -> Standard should succeed.
        let result = reg.promote(
            "ext-1",
            "1.0.0",
            CertificationLevel::Standard,
            "evidence-ref",
            &ts(3),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_demotion_on_trust_degradation() {
        let mut reg = CertificationRegistry::new();
        let input = make_input(
            "ext-1",
            ProvenanceLevel::PublisherSigned,
            ReputationTier::Established,
            60.0,
        );
        reg.evaluate_and_register(&input, &ts(1));
        assert_eq!(
            reg.get_record("ext-1", "1.0.0").unwrap().level,
            CertificationLevel::Standard
        );

        // Demote due to reputation drop.
        reg.demote(
            "ext-1",
            "1.0.0",
            CertificationLevel::Basic,
            "publisher reputation dropped below threshold",
            &ts(2),
        )
        .unwrap();
        assert_eq!(
            reg.get_record("ext-1", "1.0.0").unwrap().level,
            CertificationLevel::Basic
        );
    }

    #[test]
    fn test_audit_trail_integrity() {
        let mut reg = CertificationRegistry::new();
        let input = make_input(
            "ext-1",
            ProvenanceLevel::PublisherSigned,
            ReputationTier::Provisional,
            30.0,
        );
        reg.evaluate_and_register(&input, &ts(1));
        reg.promote(
            "ext-1",
            "1.0.0",
            CertificationLevel::Verified,
            "ev-ref",
            &ts(2),
        )
        .unwrap();

        reg.verify_audit_integrity().unwrap();
        assert!(reg.audit_trail_len() >= 2);
    }

    #[test]
    fn test_audit_query_by_extension() {
        let mut reg = CertificationRegistry::new();
        let input1 = make_input(
            "ext-a",
            ProvenanceLevel::None,
            ReputationTier::Untrusted,
            5.0,
        );
        let input2 = make_input(
            "ext-b",
            ProvenanceLevel::None,
            ReputationTier::Untrusted,
            5.0,
        );
        reg.evaluate_and_register(&input1, &ts(1));
        reg.evaluate_and_register(&input2, &ts(2));

        let trail_a = reg.query_audit_trail("ext-a");
        let trail_b = reg.query_audit_trail("ext-b");
        assert_eq!(trail_a.len(), 1);
        assert_eq!(trail_b.len(), 1);
    }

    #[test]
    fn test_level_ordering() {
        assert!(CertificationLevel::Audited > CertificationLevel::Verified);
        assert!(CertificationLevel::Verified > CertificationLevel::Standard);
        assert!(CertificationLevel::Standard > CertificationLevel::Basic);
        assert!(CertificationLevel::Basic > CertificationLevel::Uncertified);
    }

    #[test]
    fn test_meets_minimum() {
        assert!(CertificationLevel::Standard.meets_minimum(CertificationLevel::Basic));
        assert!(CertificationLevel::Basic.meets_minimum(CertificationLevel::Basic));
        assert!(!CertificationLevel::Basic.meets_minimum(CertificationLevel::Standard));
    }

    #[test]
    fn test_evaluation_explanation_present() {
        let input = make_input(
            "ext-1",
            ProvenanceLevel::PublisherSigned,
            ReputationTier::Provisional,
            25.0,
        );
        let result = evaluate_certification(&input);
        assert!(!result.explanation.is_empty());
        assert!(result.explanation.contains("ext-1"));
    }
}
