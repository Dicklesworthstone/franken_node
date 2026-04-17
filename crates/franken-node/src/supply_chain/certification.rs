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
use crate::security::constant_time::ct_eq_bytes;

const MAX_AUDIT_TRAIL: usize = 4096;

// ── Event codes ──────────────────────────────────────────────────────────────

pub const CERTIFICATION_EVALUATED: &str = "CERTIFICATION_EVALUATED";
pub const CERTIFICATION_ASSIGNED: &str = "CERTIFICATION_ASSIGNED";
pub const CERTIFICATION_PROMOTED: &str = "CERTIFICATION_PROMOTED";
pub const CERTIFICATION_DEMOTED: &str = "CERTIFICATION_DEMOTED";
pub const CERTIFICATION_POLICY_ENFORCED: &str = "CERTIFICATION_POLICY_ENFORCED";
pub const CERTIFICATION_GATE_PASS: &str = "CERTIFICATION_GATE_PASS";
pub const CERTIFICATION_GATE_REJECT: &str = "CERTIFICATION_GATE_REJECT";
pub const CERTIFICATION_EVIDENCE_MISSING: &str = "CERTIFICATION_EVIDENCE_MISSING";
pub const CERTIFICATION_EVIDENCE_VALIDATED: &str = "CERTIFICATION_EVIDENCE_VALIDATED";

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
    #[error("cannot demote from `{from:?}` to `{to:?}`: must be adjacent levels")]
    InvalidDemotion {
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
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default,
)]
#[serde(rename_all = "snake_case")]
pub enum CertificationLevel {
    /// No certification. Extension has not been evaluated.
    #[default]
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
    /// Verified evidence references binding this input to upstream verification.
    /// At minimum, provenance and reputation evidence must be provided.
    pub evidence_refs: Vec<VerifiedEvidenceRef>,
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

// ── Evidence binding types ───────────────────────────────────────────────────

/// Evidence type categories for verified evidence references.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceType {
    ProvenanceChain,
    ReputationSignal,
    TestCoverageReport,
    AuditReport,
    ManifestAdmission,
    RevocationCheck,
}

/// A reference to a verified upstream evidence record. Trust cards and
/// certification results carry these to prove their decisions are grounded
/// in canonical verification, not caller-supplied assertions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedEvidenceRef {
    pub evidence_id: String,
    pub evidence_type: EvidenceType,
    pub verified_at_epoch: u64,
    pub verification_receipt_hash: String,
}

/// Derivation metadata linking downstream trust decisions to upstream evidence.
/// Every trust card and certification result carries this so another verifier
/// can reconstruct why a decision was made.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DerivationMetadata {
    pub evidence_refs: Vec<VerifiedEvidenceRef>,
    pub derived_at_epoch: u64,
    pub derivation_chain_hash: String,
}

/// Compute a domain-separated hash over the derivation evidence chain.
pub(crate) fn compute_derivation_hash(refs: &[VerifiedEvidenceRef], derived_at: u64) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"certification_derivation_v1:");
    hasher.update(derived_at.to_le_bytes());
    hasher.update(len_to_u64(refs.len()).to_le_bytes());
    for r in refs {
        hasher.update(len_to_u64(r.evidence_id.len()).to_le_bytes());
        hasher.update(r.evidence_id.as_bytes());
        let type_tag = serde_json::to_string(&r.evidence_type).unwrap_or_default();
        hasher.update(len_to_u64(type_tag.len()).to_le_bytes());
        hasher.update(type_tag.as_bytes());
        hasher.update(r.verified_at_epoch.to_le_bytes());
        hasher.update(len_to_u64(r.verification_receipt_hash.len()).to_le_bytes());
        hasher.update(r.verification_receipt_hash.as_bytes());
    }
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

fn len_to_u64(len: usize) -> u64 {
    u64::try_from(len).unwrap_or(u64::MAX)
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
    /// Derivation metadata linking this result to verified upstream evidence.
    pub derivation: Option<DerivationMetadata>,
    /// Whether this level was set by a manual promotion/demotion rather than
    /// evidence-based evaluation. When `true`, `satisfied_criteria` and
    /// `unsatisfied_criteria` reflect the *original* evidence-derived
    /// evaluation, not the current (manually adjusted) level. Downstream
    /// readers must use `evidence_derived_level` (not `level`) to interpret
    /// the criteria lists.
    #[serde(default)]
    pub manually_adjusted: bool,
    /// The certification level that the evidence actually supports.
    /// Equals `level` for evidence-based evaluations; after a manual
    /// promotion or demotion this preserves the original evidence-derived
    /// level so downstream readers can detect the gap.
    #[serde(default)]
    pub evidence_derived_level: CertificationLevel,
}

/// Evaluate the certification level for an extension.
///
/// This is a deterministic function: same inputs produce identical results.
#[must_use]
pub fn evaluate_certification(input: &CertificationInput) -> CertificationResult {
    // Evidence binding gate: at least one evidence reference is required.
    // Without verified evidence, certification cannot proceed (fail-closed).
    if input.evidence_refs.is_empty() {
        return CertificationResult {
            extension_id: input.extension_id.clone(),
            level: CertificationLevel::Uncertified,
            explanation: "No verified evidence references provided; certification \
                          requires upstream evidence binding."
                .to_string(),
            satisfied_criteria: vec![],
            unsatisfied_criteria: vec!["evidence_binding_present".to_owned()],
            max_achievable: CertificationLevel::Uncertified,
            derivation: None,
            manually_adjusted: false,
            evidence_derived_level: CertificationLevel::Uncertified,
        };
    }

    let mut satisfied = Vec::new();
    let mut unsatisfied = Vec::new();

    // Basic criteria: publisher identity and manifest.
    let has_publisher = !input.publisher_id.trim().is_empty();
    let has_manifest = !input.extension_id.trim().is_empty() && !input.version.trim().is_empty();
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
    let adequate_coverage = input
        .test_coverage_pct
        .is_some_and(|pct| pct.is_finite() && pct >= 80.0);
    if input.has_test_coverage_evidence && adequate_coverage {
        satisfied.push("test_coverage_above_80pct".to_owned());
    } else {
        unsatisfied.push("test_coverage_above_80pct".to_owned());
    }

    // Audited criteria: third-party attestation.
    // Validate attestation structure: auditor_id, scope, and hash format must
    // be non-trivial to prevent acceptance of obviously-fake attestations.
    let attestation_valid = input.has_audit_attestation
        && input.audit_attestation.as_ref().is_some_and(|att| {
            !att.auditor_id.trim().is_empty()
                && !att.scope.trim().is_empty()
                && att.attestation_hash.starts_with("sha256:")
                && att.attestation_hash.len() == 71 // "sha256:" (7) + 64 hex chars
                && att.attestation_hash[7..].bytes().all(|b| b.is_ascii_hexdigit())
        });
    if attestation_valid {
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
    let audited_met = verified_met && attestation_valid;

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

    let derivation_hash = compute_derivation_hash(&input.evidence_refs, 0);
    let derivation = DerivationMetadata {
        evidence_refs: input.evidence_refs.clone(),
        derived_at_epoch: 0, // Caller-supplied via evaluate_and_register timestamp
        derivation_chain_hash: derivation_hash,
    };

    CertificationResult {
        extension_id: input.extension_id.clone(),
        level,
        explanation,
        satisfied_criteria: satisfied,
        unsatisfied_criteria: unsatisfied,
        max_achievable,
        derivation: Some(derivation),
        manually_adjusted: false,
        evidence_derived_level: level,
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
    /// Latest evaluation snapshot. Manual promotions/demotions update the
    /// adjudicated level and explanation, but preserve evidence-derived criteria,
    /// derivation metadata, and maximum achievable level.
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
    /// Anchor hash: entry_hash of the most recently evicted audit entry.
    chain_anchor_hash: Option<String>,
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
            chain_anchor_hash: None,
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
        // Fail-closed: cannot promote above evidence-derived max_achievable.
        // Without this guard, repeated adjacent promote() calls could
        // escalate a Basic-evidence extension to Audited, granting
        // SystemConfiguration capability access beyond what evidence supports.
        if new_level.rank() > record.evaluation.max_achievable.rank() {
            return Err(CertificationError::InvalidPromotion {
                from: old_level,
                to: new_level,
            });
        }

        record.level = new_level;
        record.evaluated_at = timestamp.to_owned();
        Self::refresh_manual_evaluation(
            record,
            old_level,
            new_level,
            &format!("promotion recorded with evidence ref `{evidence_ref}`"),
        );

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
        if new_level.rank() >= old_level.rank() {
            return Err(CertificationError::InvalidDemotion {
                from: old_level,
                to: new_level,
            });
        }
        if old_level.rank() - new_level.rank() > 1 {
            return Err(CertificationError::InvalidDemotion {
                from: old_level,
                to: new_level,
            });
        }

        record.level = new_level;
        record.evaluated_at = timestamp.to_owned();
        Self::refresh_manual_evaluation(
            record,
            old_level,
            new_level,
            &format!("demotion recorded: {reason}"),
        );

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
        let genesis = String::new();
        let first_expected = self.chain_anchor_hash.as_ref().unwrap_or(&genesis);
        for (i, entry) in self.audit_trail.iter().enumerate() {
            let expected_prev = if i == 0 {
                first_expected
            } else {
                &self.audit_trail[i - 1].entry_hash
            };
            if !ct_eq_bytes(entry.prev_hash.as_bytes(), expected_prev.as_bytes()) {
                return Err(CertificationError::AuditIntegrityViolation);
            }
            let computed = compute_entry_hash(entry);
            if !ct_eq_bytes(computed.as_bytes(), entry.entry_hash.as_bytes()) {
                return Err(CertificationError::AuditIntegrityViolation);
            }
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
            .map(|e| e.entry_hash.clone())
            .or_else(|| self.chain_anchor_hash.clone())
            .unwrap_or_default();

        let sequence = self.next_sequence;
        self.next_sequence = self.next_sequence.saturating_add(1);

        let mut entry = CertificationAuditEntry {
            sequence,
            prev_hash,
            entry_hash: String::new(),
            timestamp: timestamp.to_owned(),
            extension_id: extension_id.to_owned(),
            event,
        };
        entry.entry_hash = compute_entry_hash(&entry);
        if self.audit_trail.len() >= MAX_AUDIT_TRAIL {
            let overflow = self
                .audit_trail
                .len()
                .saturating_sub(MAX_AUDIT_TRAIL)
                .saturating_add(1)
                .min(self.audit_trail.len());
            if overflow > 0 {
                self.chain_anchor_hash =
                    Some(self.audit_trail[overflow - 1].entry_hash.clone());
            }
            self.audit_trail.drain(0..overflow);
        }
        self.audit_trail.push(entry);
    }

    fn refresh_manual_evaluation(
        record: &mut CertificationRecord,
        old_level: CertificationLevel,
        new_level: CertificationLevel,
        detail: &str,
    ) {
        let evidence_max = record.evaluation.max_achievable;
        // Preserve the evidence-derived level before overwriting.
        if !record.evaluation.manually_adjusted {
            record.evaluation.evidence_derived_level = record.evaluation.level;
        }
        record.evaluation.level = new_level;
        record.evaluation.manually_adjusted = true;
        record.evaluation.explanation = format!(
            "Extension '{}' v{} manually adjusted from '{}' to '{}' at {}: {}. \
             Evidence-derived max remains '{}'; criteria and derivation remain \
             bound to the original verified evidence.",
            record.extension_id,
            record.version,
            old_level,
            new_level,
            record.evaluated_at,
            detail,
            evidence_max
        );
    }
}

fn compute_entry_hash(entry: &CertificationAuditEntry) -> String {
    let event_json =
        serde_json::to_string(&entry.event).unwrap_or_else(|e| format!("__serde_err:{e}"));
    let mut hasher = Sha256::new();
    hasher.update(b"certification_hash_v1:");
    hasher.update(entry.sequence.to_le_bytes());
    for field in [
        entry.prev_hash.as_str(),
        entry.timestamp.as_str(),
        entry.extension_id.as_str(),
        event_json.as_str(),
    ] {
        hasher.update(len_to_u64(field.len()).to_le_bytes());
        hasher.update(field.as_bytes());
    }
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn ts(n: u32) -> String {
        format!("2026-01-{n:02}T00:00:00Z")
    }

    fn sample_evidence_refs() -> Vec<VerifiedEvidenceRef> {
        vec![
            VerifiedEvidenceRef {
                evidence_id: "ev-prov-001".to_string(),
                evidence_type: EvidenceType::ProvenanceChain,
                verified_at_epoch: 1000,
                verification_receipt_hash: "a".repeat(64),
            },
            VerifiedEvidenceRef {
                evidence_id: "ev-rep-001".to_string(),
                evidence_type: EvidenceType::ReputationSignal,
                verified_at_epoch: 1000,
                verification_receipt_hash: "b".repeat(64),
            },
        ]
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
            evidence_refs: sample_evidence_refs(),
        }
    }

    /// Build an input whose evidence evaluates to Verified
    /// (max_achievable = Verified). Requires Standard criteria plus
    /// reproducible build evidence and test coverage above 80%.
    fn make_verified_input(ext_id: &str) -> CertificationInput {
        CertificationInput {
            extension_id: ext_id.to_owned(),
            version: "1.0.0".to_owned(),
            publisher_id: "pub-test".to_owned(),
            provenance_level: ProvenanceLevel::PublisherSigned,
            reputation_tier: ReputationTier::Established,
            reputation_score: 60.0,
            capabilities: BTreeSet::from(["file_read".to_owned()]),
            has_test_coverage_evidence: true,
            test_coverage_pct: Some(90.0),
            has_reproducible_build_evidence: true,
            has_audit_attestation: false,
            audit_attestation: None,
            evidence_refs: sample_evidence_refs(),
        }
    }

    fn valid_attestation() -> AuditAttestation {
        AuditAttestation {
            auditor_id: "auditor-1".to_owned(),
            audit_date: "2026-01-15".to_owned(),
            scope: "full security audit".to_owned(),
            findings_summary: "no critical findings".to_owned(),
            attestation_hash:
                "sha256:a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90"
                    .to_owned(),
        }
    }

    fn tamper_same_length(hash: &str) -> String {
        assert!(!hash.is_empty(), "hash cannot be empty");
        let mut bytes = hash.as_bytes().to_vec();
        bytes[0] = if bytes[0] == b'0' { b'1' } else { b'0' };
        String::from_utf8(bytes).expect("hash should remain valid utf-8")
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
    fn test_whitespace_publisher_blocks_basic_certification() {
        let mut input = make_input(
            "ext-1",
            ProvenanceLevel::PublisherSigned,
            ReputationTier::Established,
            60.0,
        );
        input.publisher_id = "   ".to_owned();

        let result = evaluate_certification(&input);

        assert_eq!(result.level, CertificationLevel::Uncertified);
        assert!(
            result
                .unsatisfied_criteria
                .contains(&"publisher_identity_verified".to_owned())
        );
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
    fn test_whitespace_extension_id_blocks_manifest_declared() {
        let input = make_input(
            "   ",
            ProvenanceLevel::PublisherSigned,
            ReputationTier::Established,
            60.0,
        );

        let result = evaluate_certification(&input);

        assert_eq!(result.level, CertificationLevel::Uncertified);
        assert!(
            result
                .unsatisfied_criteria
                .contains(&"manifest_declared".to_owned())
        );
    }

    #[test]
    fn test_whitespace_version_blocks_manifest_declared() {
        let mut input = make_input(
            "ext-1",
            ProvenanceLevel::PublisherSigned,
            ReputationTier::Established,
            60.0,
        );
        input.version = "\t ".to_owned();

        let result = evaluate_certification(&input);

        assert_eq!(result.level, CertificationLevel::Uncertified);
        assert!(
            result
                .unsatisfied_criteria
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
            attestation_hash:
                "sha256:a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90".to_owned(),
        });
        let result = evaluate_certification(&input);
        assert_eq!(result.level, CertificationLevel::Audited);
    }

    #[test]
    fn test_audited_rejects_fake_attestation_hash() {
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
            attestation_hash: "sha256:abc123".to_owned(), // too short — fake
        });
        let result = evaluate_certification(&input);
        // Must NOT reach Audited with a malformed hash.
        assert_ne!(result.level, CertificationLevel::Audited);
        assert_eq!(result.level, CertificationLevel::Verified);
    }

    #[test]
    fn test_audited_rejects_empty_auditor_id() {
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
            auditor_id: String::new(), // empty auditor
            audit_date: "2026-01-15".to_owned(),
            scope: "full security audit".to_owned(),
            findings_summary: "no critical findings".to_owned(),
            attestation_hash:
                "sha256:a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90".to_owned(),
        });
        let result = evaluate_certification(&input);
        assert_ne!(result.level, CertificationLevel::Audited);
    }

    #[test]
    fn test_audited_rejects_whitespace_auditor_id() {
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
        let mut attestation = valid_attestation();
        attestation.auditor_id = " \t ".to_owned();
        input.audit_attestation = Some(attestation);

        let result = evaluate_certification(&input);

        assert_eq!(result.level, CertificationLevel::Verified);
        assert!(
            result
                .unsatisfied_criteria
                .contains(&"third_party_audit_attestation".to_owned())
        );
    }

    #[test]
    fn test_audited_rejects_empty_attestation_scope() {
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
            scope: String::new(),
            findings_summary: "no critical findings".to_owned(),
            attestation_hash:
                "sha256:a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90".to_owned(),
        });

        let result = evaluate_certification(&input);

        assert_eq!(result.level, CertificationLevel::Verified);
        assert!(
            result
                .unsatisfied_criteria
                .contains(&"third_party_audit_attestation".to_owned())
        );
    }

    #[test]
    fn test_audited_rejects_whitespace_attestation_scope() {
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
        let mut attestation = valid_attestation();
        attestation.scope = " \n ".to_owned();
        input.audit_attestation = Some(attestation);

        let result = evaluate_certification(&input);

        assert_eq!(result.level, CertificationLevel::Verified);
        assert_ne!(result.max_achievable, CertificationLevel::Audited);
    }

    #[test]
    fn test_audited_rejects_non_hex_attestation_hash() {
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
            attestation_hash: format!("sha256:{}", "g".repeat(64)),
        });

        let result = evaluate_certification(&input);

        assert_eq!(result.level, CertificationLevel::Verified);
        assert_ne!(result.max_achievable, CertificationLevel::Audited);
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
    fn test_missing_coverage_percentage_blocks_verified() {
        let mut input = make_input(
            "ext-1",
            ProvenanceLevel::SignedReproducible,
            ReputationTier::Established,
            60.0,
        );
        input.has_reproducible_build_evidence = true;
        input.has_test_coverage_evidence = true;
        input.test_coverage_pct = None;

        let result = evaluate_certification(&input);

        assert_eq!(result.level, CertificationLevel::Standard);
        assert!(
            result
                .unsatisfied_criteria
                .contains(&"test_coverage_above_80pct".to_owned())
        );
    }

    #[test]
    fn test_coverage_percentage_without_evidence_flag_blocks_verified() {
        let mut input = make_input(
            "ext-1",
            ProvenanceLevel::SignedReproducible,
            ReputationTier::Established,
            60.0,
        );
        input.has_reproducible_build_evidence = true;
        input.has_test_coverage_evidence = false;
        input.test_coverage_pct = Some(95.0);

        let result = evaluate_certification(&input);

        assert_eq!(result.level, CertificationLevel::Standard);
        assert!(
            result
                .unsatisfied_criteria
                .contains(&"test_coverage_above_80pct".to_owned())
        );
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
    fn test_deployment_gate_rejects_unknown_extension() {
        let reg = CertificationRegistry::new();

        let result =
            reg.check_deployment_gate("missing-ext", "1.0.0", DeploymentContext::Development);

        assert!(matches!(
            result,
            Err(CertificationError::ExtensionNotFound(key)) if key == "missing-ext@1.0.0"
        ));
    }

    #[test]
    fn test_staging_deployment_rejects_uncertified_result() {
        let mut reg = CertificationRegistry::new();
        let mut input = make_input(
            "ext-uncertified",
            ProvenanceLevel::PublisherSigned,
            ReputationTier::Established,
            60.0,
        );
        input.evidence_refs.clear();
        reg.evaluate_and_register(&input, &ts(1));

        let result =
            reg.check_deployment_gate("ext-uncertified", "1.0.0", DeploymentContext::Staging);

        assert!(matches!(
            result,
            Err(CertificationError::InsufficientCertification {
                context: DeploymentContext::Staging,
                required: CertificationLevel::Basic,
                actual: CertificationLevel::Uncertified,
            })
        ));
    }

    #[test]
    fn test_capability_gate_rejects_unknown_extension() {
        let reg = CertificationRegistry::new();

        let result =
            reg.check_capability_gate("missing-ext", "1.0.0", &CapabilityCategory::FileRead);

        assert!(matches!(
            result,
            Err(CertificationError::ExtensionNotFound(key)) if key == "missing-ext@1.0.0"
        ));
    }

    #[test]
    fn test_capability_gate_denies_process_spawn_for_standard() {
        let mut reg = CertificationRegistry::new();
        let input = make_input(
            "ext-1",
            ProvenanceLevel::PublisherSigned,
            ReputationTier::Established,
            60.0,
        );
        reg.evaluate_and_register(&input, &ts(1));

        let result = reg.check_capability_gate("ext-1", "1.0.0", &CapabilityCategory::ProcessSpawn);

        assert!(matches!(
            result,
            Err(CertificationError::CapabilityDenied {
                capability,
                level: CertificationLevel::Standard,
            }) if capability == "ProcessSpawn"
        ));
    }

    #[test]
    fn test_promotion_adjacent_only() {
        let mut reg = CertificationRegistry::new();
        // Use Standard-level evidence so max_achievable = Standard.
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

        // Demote Standard -> Basic so we can test adjacent promotion.
        reg.demote(
            "ext-1",
            "1.0.0",
            CertificationLevel::Basic,
            "setup demotion for promotion test",
            &ts(2),
        )
        .unwrap();

        // Skip from Basic to Verified should fail (non-adjacent + above max_achievable).
        let result = reg.promote(
            "ext-1",
            "1.0.0",
            CertificationLevel::Verified,
            "evidence-ref",
            &ts(3),
        );
        assert!(matches!(
            result,
            Err(CertificationError::InvalidPromotion { .. })
        ));

        // Adjacent promotion Basic -> Standard should succeed (within max_achievable).
        let result = reg.promote(
            "ext-1",
            "1.0.0",
            CertificationLevel::Standard,
            "evidence-ref",
            &ts(4),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_promotion_refreshes_embedded_evaluation_snapshot() {
        let mut reg = CertificationRegistry::new();
        // Use Verified-level evidence so max_achievable = Verified.
        let input = make_verified_input("ext-1");
        reg.evaluate_and_register(&input, &ts(1));
        // Demote to Standard so we can test Standard → Verified promotion.
        reg.demote(
            "ext-1",
            "1.0.0",
            CertificationLevel::Standard,
            "setup for promotion test",
            &ts(2),
        )
        .unwrap();
        let before = reg.get_record("ext-1", "1.0.0").unwrap().evaluation.clone();

        reg.promote(
            "ext-1",
            "1.0.0",
            CertificationLevel::Verified,
            "ev-ref",
            &ts(3),
        )
        .unwrap();

        let record = reg.get_record("ext-1", "1.0.0").unwrap();
        assert_eq!(record.level, CertificationLevel::Verified);
        assert_eq!(record.evaluation.level, CertificationLevel::Verified);
        assert_eq!(
            record.evaluation.satisfied_criteria,
            before.satisfied_criteria
        );
        assert_eq!(
            record.evaluation.unsatisfied_criteria,
            before.unsatisfied_criteria
        );
        assert_eq!(record.evaluation.max_achievable, before.max_achievable);
        assert_eq!(record.evaluation.derivation, before.derivation);
        assert!(record.evaluation.explanation.contains("manually adjusted"));
        assert!(record.evaluation.explanation.contains("max remains"));
        assert!(record.evaluation.explanation.contains("remain bound"));
        assert!(record.evaluation.explanation.contains("verified"));
        // bd-1wpq: manually_adjusted flag and evidence_derived_level
        assert!(record.evaluation.manually_adjusted);
        assert_eq!(
            record.evaluation.evidence_derived_level, before.evidence_derived_level,
            "evidence_derived_level must be preserved across manual adjustments"
        );
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
    fn test_demotion_refreshes_embedded_evaluation_snapshot() {
        let mut reg = CertificationRegistry::new();
        let input = make_input(
            "ext-1",
            ProvenanceLevel::PublisherSigned,
            ReputationTier::Established,
            60.0,
        );
        reg.evaluate_and_register(&input, &ts(1));
        let before = reg.get_record("ext-1", "1.0.0").unwrap().evaluation.clone();

        reg.demote(
            "ext-1",
            "1.0.0",
            CertificationLevel::Basic,
            "trust degradation",
            &ts(2),
        )
        .unwrap();

        let record = reg.get_record("ext-1", "1.0.0").unwrap();
        assert_eq!(record.level, CertificationLevel::Basic);
        assert_eq!(record.evaluation.level, CertificationLevel::Basic);
        assert_eq!(
            record.evaluation.satisfied_criteria,
            before.satisfied_criteria
        );
        assert_eq!(
            record.evaluation.unsatisfied_criteria,
            before.unsatisfied_criteria
        );
        assert_eq!(record.evaluation.max_achievable, before.max_achievable);
        assert_eq!(record.evaluation.derivation, before.derivation);
        assert!(record.evaluation.explanation.contains("trust degradation"));
        assert!(record.evaluation.explanation.contains("max remains"));
        assert!(record.evaluation.explanation.contains("remain bound"));
        assert!(record.evaluation.explanation.contains("basic"));
        // bd-1wpq: manually_adjusted flag and evidence_derived_level
        assert!(record.evaluation.manually_adjusted);
        assert_eq!(
            record.evaluation.evidence_derived_level, before.evidence_derived_level,
            "evidence_derived_level must preserve the original evidence-backed level"
        );
    }

    #[test]
    fn test_demotion_non_adjacent_rejected() {
        let mut reg = CertificationRegistry::new();
        let mut input = make_input(
            "ext-1",
            ProvenanceLevel::SignedReproducible,
            ReputationTier::Trusted,
            90.0,
        );
        input.has_reproducible_build_evidence = true;
        input.has_test_coverage_evidence = true;
        input.test_coverage_pct = Some(90.0);
        reg.evaluate_and_register(&input, &ts(1));
        assert_eq!(
            reg.get_record("ext-1", "1.0.0").unwrap().level,
            CertificationLevel::Verified
        );
        // Verified (rank 3) to Basic (rank 1) is a 2-rank jump — must be rejected.
        let err = reg
            .demote(
                "ext-1",
                "1.0.0",
                CertificationLevel::Basic,
                "non-adjacent demotion",
                &ts(2),
            )
            .unwrap_err();
        assert!(
            matches!(err, CertificationError::InvalidDemotion { .. }),
            "expected InvalidDemotion, got {err:?}"
        );
    }

    #[test]
    fn test_demotion_same_level_rejected() {
        let mut reg = CertificationRegistry::new();
        let input = make_input(
            "ext-1",
            ProvenanceLevel::PublisherSigned,
            ReputationTier::Established,
            60.0,
        );
        reg.evaluate_and_register(&input, &ts(1));
        // Standard → Standard is not a demotion.
        let err = reg
            .demote(
                "ext-1",
                "1.0.0",
                CertificationLevel::Standard,
                "same level",
                &ts(2),
            )
            .unwrap_err();
        assert!(
            matches!(err, CertificationError::InvalidDemotion { .. }),
            "expected InvalidDemotion, got {err:?}"
        );
    }

    #[test]
    fn test_promote_unknown_extension_does_not_append_audit_entry() {
        let mut reg = CertificationRegistry::new();

        let err = reg
            .promote(
                "missing-ext",
                "1.0.0",
                CertificationLevel::Basic,
                "evidence-ref",
                &ts(1),
            )
            .unwrap_err();

        assert!(
            matches!(err, CertificationError::ExtensionNotFound(key) if key == "missing-ext@1.0.0")
        );
        assert_eq!(reg.record_count(), 0);
        assert_eq!(reg.audit_trail_len(), 0);
    }

    #[test]
    fn test_demote_unknown_extension_does_not_append_audit_entry() {
        let mut reg = CertificationRegistry::new();

        let err = reg
            .demote(
                "missing-ext",
                "1.0.0",
                CertificationLevel::Uncertified,
                "missing record",
                &ts(1),
            )
            .unwrap_err();

        assert!(
            matches!(err, CertificationError::ExtensionNotFound(key) if key == "missing-ext@1.0.0")
        );
        assert_eq!(reg.record_count(), 0);
        assert_eq!(reg.audit_trail_len(), 0);
    }

    #[test]
    fn test_audit_trail_integrity() {
        let mut reg = CertificationRegistry::new();
        // Use Verified-level evidence so max_achievable = Verified.
        let input = make_verified_input("ext-1");
        reg.evaluate_and_register(&input, &ts(1));
        // Demote to Standard so we can test Standard → Verified promotion.
        reg.demote(
            "ext-1",
            "1.0.0",
            CertificationLevel::Standard,
            "setup for audit trail test",
            &ts(2),
        )
        .unwrap();
        reg.promote(
            "ext-1",
            "1.0.0",
            CertificationLevel::Verified,
            "ev-ref",
            &ts(3),
        )
        .unwrap();

        reg.verify_audit_integrity().unwrap();
        assert_eq!(reg.audit_trail_len(), 3);
    }

    #[test]
    fn test_audit_trail_integrity_detects_same_length_hash_tamper() {
        let mut reg = CertificationRegistry::new();
        // Use Verified-level evidence so max_achievable = Verified.
        let input = make_verified_input("ext-1");
        reg.evaluate_and_register(&input, &ts(1));
        // Demote to Standard so we can test Standard → Verified promotion.
        reg.demote(
            "ext-1",
            "1.0.0",
            CertificationLevel::Standard,
            "setup for tamper test",
            &ts(2),
        )
        .unwrap();
        reg.promote(
            "ext-1",
            "1.0.0",
            CertificationLevel::Verified,
            "ev-ref",
            &ts(3),
        )
        .unwrap();

        let last = reg.audit_trail.last_mut().expect("audit entry");
        last.entry_hash = tamper_same_length(&last.entry_hash);

        assert!(matches!(
            reg.verify_audit_integrity(),
            Err(CertificationError::AuditIntegrityViolation)
        ));
    }

    #[test]
    fn test_audit_trail_integrity_detects_prev_hash_tamper() {
        let mut reg = CertificationRegistry::new();
        let input = make_verified_input("ext-prev-tamper");
        reg.evaluate_and_register(&input, &ts(1));
        reg.demote(
            "ext-prev-tamper",
            "1.0.0",
            CertificationLevel::Standard,
            "setup second audit entry",
            &ts(2),
        )
        .unwrap();

        reg.audit_trail[1].prev_hash = tamper_same_length(&reg.audit_trail[1].prev_hash);

        assert!(matches!(
            reg.verify_audit_integrity(),
            Err(CertificationError::AuditIntegrityViolation)
        ));
    }

    #[test]
    fn test_audit_trail_integrity_detects_entry_payload_tamper() {
        let mut reg = CertificationRegistry::new();
        let input = make_verified_input("ext-payload-tamper");
        reg.evaluate_and_register(&input, &ts(1));

        reg.audit_trail[0].extension_id = "ext-payload-tampered".to_owned();

        assert!(matches!(
            reg.verify_audit_integrity(),
            Err(CertificationError::AuditIntegrityViolation)
        ));
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

    // ── Evidence binding adversarial tests ──────────────────────────────

    #[test]
    fn test_no_evidence_returns_uncertified() {
        let mut input = make_input(
            "ext-1",
            ProvenanceLevel::PublisherSigned,
            ReputationTier::Established,
            60.0,
        );
        input.evidence_refs = vec![];
        let result = evaluate_certification(&input);
        assert_eq!(result.level, CertificationLevel::Uncertified);
        assert!(result.derivation.is_none());
        assert!(
            result
                .unsatisfied_criteria
                .contains(&"evidence_binding_present".to_owned())
        );
    }

    #[test]
    fn test_nan_coverage_blocks_verified() {
        let mut input = make_input(
            "ext-1",
            ProvenanceLevel::SignedReproducible,
            ReputationTier::Established,
            60.0,
        );
        input.has_reproducible_build_evidence = true;
        input.has_test_coverage_evidence = true;
        input.test_coverage_pct = Some(f64::NAN);
        let result = evaluate_certification(&input);
        // NaN is not >= 80.0, so Verified is blocked — should be Standard.
        assert_eq!(result.level, CertificationLevel::Standard);
    }

    #[test]
    fn test_inf_coverage_blocks_verified() {
        let mut input = make_input(
            "ext-1",
            ProvenanceLevel::SignedReproducible,
            ReputationTier::Established,
            60.0,
        );
        input.has_reproducible_build_evidence = true;
        input.has_test_coverage_evidence = true;
        input.test_coverage_pct = Some(f64::INFINITY);
        let result = evaluate_certification(&input);
        // Infinity is not finite, so Verified is blocked — should be Standard.
        assert_eq!(result.level, CertificationLevel::Standard);
    }

    #[test]
    fn test_derivation_metadata_present_with_evidence() {
        let input = make_input(
            "ext-1",
            ProvenanceLevel::PublisherSigned,
            ReputationTier::Provisional,
            30.0,
        );
        let result = evaluate_certification(&input);
        let derivation = result
            .derivation
            .as_ref()
            .expect("derivation must be present");
        assert_eq!(derivation.evidence_refs.len(), 2);
        assert!(derivation.derivation_chain_hash.starts_with("sha256:"));
    }

    #[test]
    fn test_derivation_hash_deterministic() {
        let refs = sample_evidence_refs();
        let h1 = compute_derivation_hash(&refs, 42);
        let h2 = compute_derivation_hash(&refs, 42);
        assert_eq!(h1, h2);
        // Different epoch produces different hash.
        let h3 = compute_derivation_hash(&refs, 43);
        assert_ne!(h1, h3);
    }

    #[test]
    fn test_derivation_hash_changes_when_receipt_hash_changes() {
        let mut refs = sample_evidence_refs();
        let original = compute_derivation_hash(&refs, 42);
        refs[0].verification_receipt_hash = "c".repeat(64);
        let changed = compute_derivation_hash(&refs, 42);

        assert!(!ct_eq_bytes(original.as_bytes(), changed.as_bytes()));
    }

    #[test]
    fn promotion_preserves_evidence_criteria_while_updating_effective_level() {
        // Use Standard-level evidence (max_achievable = Standard), demote to Basic,
        // then promote back to Standard to verify evidence criteria are preserved.
        let mut reg = CertificationRegistry::new();
        let input = make_input(
            "ext-p",
            ProvenanceLevel::PublisherSigned,
            ReputationTier::Established,
            60.0,
        );
        reg.evaluate_and_register(&input, &ts(1));
        assert_eq!(
            reg.get_record("ext-p", "1.0.0").unwrap().level,
            CertificationLevel::Standard
        );
        // Demote to Basic for the promotion test.
        reg.demote(
            "ext-p",
            "1.0.0",
            CertificationLevel::Basic,
            "setup demotion for evidence-preservation test",
            &ts(2),
        )
        .unwrap();
        let before = reg.get_record("ext-p", "1.0.0").unwrap().evaluation.clone();

        reg.promote(
            "ext-p",
            "1.0.0",
            CertificationLevel::Standard,
            "manual-ev",
            &ts(3),
        )
        .unwrap();

        let after = reg.get_record("ext-p", "1.0.0").unwrap();
        assert_eq!(after.level, CertificationLevel::Standard);
        assert_eq!(after.evaluation.level, CertificationLevel::Standard);
        assert_eq!(
            after.evaluation.satisfied_criteria,
            before.satisfied_criteria
        );
        assert_eq!(
            after.evaluation.unsatisfied_criteria,
            before.unsatisfied_criteria
        );
        assert_eq!(after.evaluation.max_achievable, before.max_achievable);
        assert_eq!(after.evaluation.derivation, before.derivation);
        assert!(after.evaluation.manually_adjusted);
        assert_eq!(
            after.evaluation.evidence_derived_level, before.evidence_derived_level,
            "evidence_derived_level must be preserved across manual adjustments"
        );
    }

    #[test]
    fn demotion_preserves_evidence_criteria_while_updating_effective_level() {
        // Start at Standard (provenance+reputation met), demote to Basic.
        let mut reg = CertificationRegistry::new();
        let input = make_input(
            "ext-d",
            ProvenanceLevel::PublisherSigned,
            ReputationTier::Established,
            60.0,
        );
        reg.evaluate_and_register(&input, &ts(1));
        assert_eq!(
            reg.get_record("ext-d", "1.0.0").unwrap().level,
            CertificationLevel::Standard
        );
        let before = reg.get_record("ext-d", "1.0.0").unwrap().evaluation.clone();

        reg.demote(
            "ext-d",
            "1.0.0",
            CertificationLevel::Basic,
            "trust loss",
            &ts(2),
        )
        .unwrap();

        let after = reg.get_record("ext-d", "1.0.0").unwrap();
        assert_eq!(after.level, CertificationLevel::Basic);
        assert_eq!(after.evaluation.level, CertificationLevel::Basic);
        assert_eq!(
            after.evaluation.satisfied_criteria,
            before.satisfied_criteria
        );
        assert_eq!(
            after.evaluation.unsatisfied_criteria,
            before.unsatisfied_criteria
        );
        assert_eq!(after.evaluation.max_achievable, before.max_achievable);
        assert_eq!(after.evaluation.derivation, before.derivation);
        assert!(after.evaluation.manually_adjusted);
        assert_eq!(
            after.evaluation.evidence_derived_level,
            before.evidence_derived_level
        );
    }

    #[test]
    fn test_evaluate_sets_consistent_evidence_derived_level() {
        // Evidence-based evaluation: manually_adjusted is false and
        // evidence_derived_level equals level.
        let mut reg = CertificationRegistry::new();
        let input = make_input(
            "ext-ev",
            ProvenanceLevel::PublisherSigned,
            ReputationTier::Established,
            60.0,
        );
        let result = reg.evaluate_and_register(&input, &ts(1));
        assert!(!result.manually_adjusted);
        assert_eq!(result.evidence_derived_level, result.level);
        assert_eq!(result.evidence_derived_level, CertificationLevel::Standard);
    }

    #[test]
    fn test_promote_demote_preserves_evidence_derived_level_across_adjustments() {
        // Promote then demote: evidence_derived_level stays at the original
        // evidence-backed level throughout.
        let mut reg = CertificationRegistry::new();
        // Use Verified-level evidence so max_achievable = Verified.
        let input = make_verified_input("ext-pd");
        reg.evaluate_and_register(&input, &ts(1));
        let original_level = reg.get_record("ext-pd", "1.0.0").unwrap().evaluation.level;
        assert_eq!(original_level, CertificationLevel::Verified);

        // Demote Verified -> Standard (setup for promote/demote cycle).
        reg.demote(
            "ext-pd",
            "1.0.0",
            CertificationLevel::Standard,
            "setup demotion",
            &ts(2),
        )
        .unwrap();

        // Promote Standard -> Verified (within max_achievable).
        reg.promote(
            "ext-pd",
            "1.0.0",
            CertificationLevel::Verified,
            "ev1",
            &ts(3),
        )
        .unwrap();
        let after_promote = reg.get_record("ext-pd", "1.0.0").unwrap();
        assert_eq!(after_promote.evaluation.level, CertificationLevel::Verified);
        assert!(after_promote.evaluation.manually_adjusted);
        assert_eq!(
            after_promote.evaluation.evidence_derived_level,
            CertificationLevel::Verified
        );

        // Demote Verified -> Standard
        reg.demote(
            "ext-pd",
            "1.0.0",
            CertificationLevel::Standard,
            "reason",
            &ts(4),
        )
        .unwrap();
        let after_demote = reg.get_record("ext-pd", "1.0.0").unwrap();
        assert_eq!(after_demote.evaluation.level, CertificationLevel::Standard);
        assert!(after_demote.evaluation.manually_adjusted);
        // evidence_derived_level remains at the original evidence-backed level
        assert_eq!(
            after_demote.evaluation.evidence_derived_level,
            CertificationLevel::Verified
        );
    }

    // === bd-CrimsonCrane: promote() must not exceed max_achievable ===

    #[test]
    fn promote_above_max_achievable_rejected() {
        // Register an extension that evaluates to Basic (max_achievable = Basic).
        let mut reg = CertificationRegistry::new();
        let input = make_input(
            "ext-escalation",
            ProvenanceLevel::None,
            ReputationTier::Untrusted,
            10.0,
        );
        let result = reg.evaluate_and_register(&input, &ts(1));
        assert_eq!(result.level, CertificationLevel::Basic);
        assert_eq!(result.max_achievable, CertificationLevel::Basic);

        // Promoting from Basic → Standard must fail because max_achievable is Basic.
        let err = reg
            .promote(
                "ext-escalation",
                "1.0.0",
                CertificationLevel::Standard,
                "fake-evidence",
                &ts(2),
            )
            .unwrap_err();
        assert!(
            matches!(err, CertificationError::InvalidPromotion { .. }),
            "promote above max_achievable must be rejected"
        );

        // Level must remain at Basic.
        let record = reg.get_record("ext-escalation", "1.0.0").unwrap();
        assert_eq!(record.level, CertificationLevel::Basic);
    }
}
