//! bd-3ort: Proof-presence requirement for quarantine promotion in
//! high-assurance modes.
//!
//! Extends the quarantine promotion gate with an `AssuranceMode` that
//! requires cryptographic proof bundles before artifacts enter the trusted set.
//!
//! # Invariants
//!
//! - INV-HA-PROOF-REQUIRED: HighAssurance promotion fails without proof bundle
//! - INV-HA-FAIL-CLOSED: any missing proof → artifact stays quarantined
//! - INV-HA-MODE-POLICY: mode switch requires explicit policy authorization

use std::fmt;

/// Stable event codes for structured logging.
pub mod event_codes {
    pub const PROMOTION_APPROVED: &str = "QUARANTINE_PROMOTION_APPROVED";
    pub const PROMOTION_DENIED: &str = "QUARANTINE_PROMOTION_DENIED";
    pub const MODE_CHANGED: &str = "ASSURANCE_MODE_CHANGED";
}

// ── AssuranceMode ───────────────────────────────────────────────────

/// Deployment assurance level for quarantine promotion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AssuranceMode {
    /// Standard mode: existing behavior, proof optional.
    Standard,
    /// High-assurance mode: proof bundle required.
    HighAssurance,
}

impl AssuranceMode {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Standard => "standard",
            Self::HighAssurance => "high_assurance",
        }
    }

    pub fn requires_proof(&self) -> bool {
        matches!(self, Self::HighAssurance)
    }
}

impl fmt::Display for AssuranceMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

// ── ObjectClass ─────────────────────────────────────────────────────

/// Object class determines proof requirements.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ObjectClass {
    /// Critical markers: full proof chain required.
    CriticalMarker,
    /// State objects: integrity proof required.
    StateObject,
    /// Telemetry artifacts: integrity hash only.
    TelemetryArtifact,
    /// Configuration objects: schema proof required.
    ConfigObject,
}

impl ObjectClass {
    pub fn label(&self) -> &'static str {
        match self {
            Self::CriticalMarker => "critical_marker",
            Self::StateObject => "state_object",
            Self::TelemetryArtifact => "telemetry_artifact",
            Self::ConfigObject => "config_object",
        }
    }

    pub fn all() -> &'static [ObjectClass] {
        &[
            Self::CriticalMarker,
            Self::StateObject,
            Self::TelemetryArtifact,
            Self::ConfigObject,
        ]
    }
}

impl fmt::Display for ObjectClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

// ── ProofRequirement ────────────────────────────────────────────────

/// What proof is required for a given object class in high-assurance mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProofRequirement {
    /// Full proof chain (merkle + hash + signature).
    FullProofChain,
    /// Integrity proof (hash + signature).
    IntegrityProof,
    /// Integrity hash only.
    IntegrityHash,
    /// Schema conformance proof.
    SchemaProof,
}

impl ProofRequirement {
    pub fn label(&self) -> &'static str {
        match self {
            Self::FullProofChain => "full_proof_chain",
            Self::IntegrityProof => "integrity_proof",
            Self::IntegrityHash => "integrity_hash",
            Self::SchemaProof => "schema_proof",
        }
    }
}

impl fmt::Display for ProofRequirement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// Get the proof requirement for an object class.
pub fn proof_requirement_for(class: ObjectClass) -> ProofRequirement {
    match class {
        ObjectClass::CriticalMarker => ProofRequirement::FullProofChain,
        ObjectClass::StateObject => ProofRequirement::IntegrityProof,
        ObjectClass::TelemetryArtifact => ProofRequirement::IntegrityHash,
        ObjectClass::ConfigObject => ProofRequirement::SchemaProof,
    }
}

// ── ProofBundle ─────────────────────────────────────────────────────

/// A proof bundle attached to an artifact for promotion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofBundle {
    /// Whether a full proof chain is present.
    pub has_proof_chain: bool,
    /// Whether an integrity proof (hash + signature) is present.
    pub has_integrity_proof: bool,
    /// Whether an integrity hash is present.
    pub has_integrity_hash: bool,
    /// Whether a schema conformance proof is present.
    pub has_schema_proof: bool,
}

impl ProofBundle {
    /// Empty proof bundle (nothing attached).
    pub fn empty() -> Self {
        Self {
            has_proof_chain: false,
            has_integrity_proof: false,
            has_integrity_hash: false,
            has_schema_proof: false,
        }
    }

    /// Full proof bundle (everything present).
    pub fn full() -> Self {
        Self {
            has_proof_chain: true,
            has_integrity_proof: true,
            has_integrity_hash: true,
            has_schema_proof: true,
        }
    }

    /// Check if the bundle satisfies a given requirement.
    pub fn satisfies(&self, requirement: ProofRequirement) -> bool {
        match requirement {
            ProofRequirement::FullProofChain => self.has_proof_chain,
            ProofRequirement::IntegrityProof => self.has_integrity_proof,
            ProofRequirement::IntegrityHash => self.has_integrity_hash,
            ProofRequirement::SchemaProof => self.has_schema_proof,
        }
    }
}

// ── PromotionDenial ─────────────────────────────────────────────────

/// Reason a high-assurance promotion was denied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PromotionDenialReason {
    /// Proof bundle missing entirely.
    ProofBundleMissing {
        artifact_id: String,
        object_class: ObjectClass,
    },
    /// Proof bundle present but insufficient for requirement.
    ProofBundleInsufficient {
        artifact_id: String,
        object_class: ObjectClass,
        required: ProofRequirement,
    },
    /// Mode downgrade unauthorized.
    UnauthorizedModeDowngrade {
        from: AssuranceMode,
        to: AssuranceMode,
    },
}

impl PromotionDenialReason {
    pub fn code(&self) -> &'static str {
        match self {
            Self::ProofBundleMissing { .. } => "PROMOTION_DENIED_PROOF_BUNDLE_MISSING",
            Self::ProofBundleInsufficient { .. } => "PROMOTION_DENIED_PROOF_INSUFFICIENT",
            Self::UnauthorizedModeDowngrade { .. } => "MODE_DOWNGRADE_UNAUTHORIZED",
        }
    }
}

impl fmt::Display for PromotionDenialReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ProofBundleMissing {
                artifact_id,
                object_class,
            } => {
                write!(
                    f,
                    "{}: artifact={artifact_id}, class={object_class}",
                    self.code()
                )
            }
            Self::ProofBundleInsufficient {
                artifact_id,
                object_class,
                required,
            } => {
                write!(
                    f,
                    "{}: artifact={artifact_id}, class={object_class}, required={required}",
                    self.code()
                )
            }
            Self::UnauthorizedModeDowngrade { from, to } => {
                write!(f, "{}: from={from}, to={to}", self.code())
            }
        }
    }
}

// ── PolicyAuthorization ─────────────────────────────────────────────

/// Authorization for mode changes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyAuthorization {
    pub policy_ref: String,
    pub authorizer_id: String,
    pub timestamp_ms: u64,
}

// ── HighAssuranceGate ───────────────────────────────────────────────

/// Gate that enforces proof-presence for quarantine promotion.
///
/// INV-HA-PROOF-REQUIRED: HighAssurance mode requires proof bundle.
/// INV-HA-FAIL-CLOSED: missing proof → denied.
/// INV-HA-MODE-POLICY: mode change requires policy authorization.
#[derive(Debug)]
pub struct HighAssuranceGate {
    mode: AssuranceMode,
    /// Approvals count.
    approvals: u64,
    /// Denials count.
    denials: u64,
    /// Mode changes count.
    mode_changes: u64,
}

impl HighAssuranceGate {
    pub fn new(mode: AssuranceMode) -> Self {
        Self {
            mode,
            approvals: 0,
            denials: 0,
            mode_changes: 0,
        }
    }

    pub fn standard() -> Self {
        Self::new(AssuranceMode::Standard)
    }

    pub fn high_assurance() -> Self {
        Self::new(AssuranceMode::HighAssurance)
    }

    pub fn mode(&self) -> AssuranceMode {
        self.mode
    }

    pub fn approvals(&self) -> u64 {
        self.approvals
    }

    pub fn denials(&self) -> u64 {
        self.denials
    }

    pub fn mode_changes(&self) -> u64 {
        self.mode_changes
    }

    /// Evaluate whether an artifact can be promoted.
    ///
    /// In Standard mode, proof is optional (always approved if present check is skipped).
    /// In HighAssurance mode, the proof bundle must satisfy the object class requirement.
    pub fn evaluate(
        &mut self,
        artifact_id: &str,
        object_class: ObjectClass,
        proof_bundle: Option<&ProofBundle>,
    ) -> Result<(), PromotionDenialReason> {
        if self.mode == AssuranceMode::Standard {
            self.approvals += 1;
            return Ok(());
        }

        // HighAssurance mode: proof required
        let bundle = match proof_bundle {
            Some(b) => b,
            None => {
                self.denials += 1;
                return Err(PromotionDenialReason::ProofBundleMissing {
                    artifact_id: artifact_id.into(),
                    object_class,
                });
            }
        };

        let requirement = proof_requirement_for(object_class);
        if !bundle.satisfies(requirement) {
            self.denials += 1;
            return Err(PromotionDenialReason::ProofBundleInsufficient {
                artifact_id: artifact_id.into(),
                object_class,
                required: requirement,
            });
        }

        self.approvals += 1;
        Ok(())
    }

    /// Switch assurance mode with policy authorization.
    ///
    /// INV-HA-MODE-POLICY: requires explicit authorization.
    /// Downgrade from HighAssurance to Standard requires authorization.
    pub fn switch_mode(
        &mut self,
        new_mode: AssuranceMode,
        authorization: Option<&PolicyAuthorization>,
    ) -> Result<(), PromotionDenialReason> {
        if self.mode == new_mode {
            return Ok(()); // no-op
        }

        // Downgrade requires authorization
        if self.mode == AssuranceMode::HighAssurance && new_mode == AssuranceMode::Standard
            && authorization.is_none()
        {
            return Err(PromotionDenialReason::UnauthorizedModeDowngrade {
                from: self.mode,
                to: new_mode,
            });
        }

        self.mode = new_mode;
        self.mode_changes += 1;
        Ok(())
    }

    /// Generate promotion matrix for all object classes.
    pub fn promotion_matrix(&self) -> Vec<PromotionMatrixEntry> {
        ObjectClass::all()
            .iter()
            .map(|&class| {
                let requirement = proof_requirement_for(class);
                PromotionMatrixEntry {
                    object_class: class,
                    assurance_mode: self.mode,
                    proof_required: self.mode.requires_proof(),
                    proof_requirement: if self.mode.requires_proof() {
                        Some(requirement)
                    } else {
                        None
                    },
                }
            })
            .collect()
    }
}

/// An entry in the promotion matrix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PromotionMatrixEntry {
    pub object_class: ObjectClass,
    pub assurance_mode: AssuranceMode,
    pub proof_required: bool,
    pub proof_requirement: Option<ProofRequirement>,
}

impl PromotionMatrixEntry {
    pub fn to_json(&self) -> String {
        let req = match &self.proof_requirement {
            Some(r) => format!("\"{}\"", r.label()),
            None => "null".to_string(),
        };
        format!(
            r#"{{"object_class":"{}","assurance_mode":"{}","proof_required":{},"proof_requirement":{}}}"#,
            self.object_class.label(),
            self.assurance_mode.label(),
            self.proof_required,
            req,
        )
    }
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── AssuranceMode ──

    #[test]
    fn assurance_mode_labels() {
        assert_eq!(AssuranceMode::Standard.label(), "standard");
        assert_eq!(AssuranceMode::HighAssurance.label(), "high_assurance");
    }

    #[test]
    fn assurance_mode_display() {
        assert_eq!(AssuranceMode::Standard.to_string(), "standard");
        assert_eq!(AssuranceMode::HighAssurance.to_string(), "high_assurance");
    }

    #[test]
    fn assurance_mode_requires_proof() {
        assert!(!AssuranceMode::Standard.requires_proof());
        assert!(AssuranceMode::HighAssurance.requires_proof());
    }

    // ── ObjectClass ──

    #[test]
    fn object_class_labels() {
        assert_eq!(ObjectClass::CriticalMarker.label(), "critical_marker");
        assert_eq!(ObjectClass::StateObject.label(), "state_object");
        assert_eq!(ObjectClass::TelemetryArtifact.label(), "telemetry_artifact");
        assert_eq!(ObjectClass::ConfigObject.label(), "config_object");
    }

    #[test]
    fn object_class_all_four() {
        assert_eq!(ObjectClass::all().len(), 4);
    }

    #[test]
    fn object_class_display() {
        assert_eq!(ObjectClass::CriticalMarker.to_string(), "critical_marker");
    }

    // ── ProofRequirement ──

    #[test]
    fn proof_requirement_labels() {
        assert_eq!(ProofRequirement::FullProofChain.label(), "full_proof_chain");
        assert_eq!(ProofRequirement::IntegrityProof.label(), "integrity_proof");
        assert_eq!(ProofRequirement::IntegrityHash.label(), "integrity_hash");
        assert_eq!(ProofRequirement::SchemaProof.label(), "schema_proof");
    }

    #[test]
    fn proof_requirement_mapping() {
        assert_eq!(
            proof_requirement_for(ObjectClass::CriticalMarker),
            ProofRequirement::FullProofChain
        );
        assert_eq!(
            proof_requirement_for(ObjectClass::StateObject),
            ProofRequirement::IntegrityProof
        );
        assert_eq!(
            proof_requirement_for(ObjectClass::TelemetryArtifact),
            ProofRequirement::IntegrityHash
        );
        assert_eq!(
            proof_requirement_for(ObjectClass::ConfigObject),
            ProofRequirement::SchemaProof
        );
    }

    // ── ProofBundle ──

    #[test]
    fn empty_proof_bundle() {
        let b = ProofBundle::empty();
        assert!(!b.has_proof_chain);
        assert!(!b.has_integrity_proof);
        assert!(!b.has_integrity_hash);
        assert!(!b.has_schema_proof);
    }

    #[test]
    fn full_proof_bundle() {
        let b = ProofBundle::full();
        assert!(b.has_proof_chain);
        assert!(b.has_integrity_proof);
        assert!(b.has_integrity_hash);
        assert!(b.has_schema_proof);
    }

    #[test]
    fn proof_bundle_satisfies_check() {
        let b = ProofBundle {
            has_proof_chain: false,
            has_integrity_proof: true,
            has_integrity_hash: true,
            has_schema_proof: false,
        };
        assert!(!b.satisfies(ProofRequirement::FullProofChain));
        assert!(b.satisfies(ProofRequirement::IntegrityProof));
        assert!(b.satisfies(ProofRequirement::IntegrityHash));
        assert!(!b.satisfies(ProofRequirement::SchemaProof));
    }

    // ── HighAssuranceGate: Standard mode ──

    #[test]
    fn standard_mode_allows_without_proof() {
        let mut gate = HighAssuranceGate::standard();
        let result = gate.evaluate("art-1", ObjectClass::CriticalMarker, None);
        assert!(result.is_ok());
        assert_eq!(gate.approvals(), 1);
    }

    #[test]
    fn standard_mode_allows_with_proof() {
        let mut gate = HighAssuranceGate::standard();
        let bundle = ProofBundle::full();
        let result = gate.evaluate("art-1", ObjectClass::CriticalMarker, Some(&bundle));
        assert!(result.is_ok());
    }

    // ── HighAssuranceGate: HighAssurance mode ──

    #[test]
    fn high_assurance_rejects_without_proof() {
        let mut gate = HighAssuranceGate::high_assurance();
        let result = gate.evaluate("art-1", ObjectClass::CriticalMarker, None);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code(), "PROMOTION_DENIED_PROOF_BUNDLE_MISSING");
        assert_eq!(gate.denials(), 1);
    }

    #[test]
    fn high_assurance_rejects_insufficient_proof() {
        let mut gate = HighAssuranceGate::high_assurance();
        let bundle = ProofBundle {
            has_proof_chain: false,
            has_integrity_proof: true,
            has_integrity_hash: true,
            has_schema_proof: false,
        };
        // CriticalMarker requires FullProofChain
        let result = gate.evaluate("art-1", ObjectClass::CriticalMarker, Some(&bundle));
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().code(),
            "PROMOTION_DENIED_PROOF_INSUFFICIENT"
        );
    }

    #[test]
    fn high_assurance_approves_with_full_proof() {
        let mut gate = HighAssuranceGate::high_assurance();
        let bundle = ProofBundle::full();
        let result = gate.evaluate("art-1", ObjectClass::CriticalMarker, Some(&bundle));
        assert!(result.is_ok());
        assert_eq!(gate.approvals(), 1);
    }

    #[test]
    fn high_assurance_per_class_enforcement() {
        let mut gate = HighAssuranceGate::high_assurance();

        // TelemetryArtifact only needs IntegrityHash
        let bundle = ProofBundle {
            has_proof_chain: false,
            has_integrity_proof: false,
            has_integrity_hash: true,
            has_schema_proof: false,
        };
        assert!(
            gate.evaluate("tel-1", ObjectClass::TelemetryArtifact, Some(&bundle))
                .is_ok()
        );

        // StateObject needs IntegrityProof
        let bundle2 = ProofBundle {
            has_proof_chain: false,
            has_integrity_proof: true,
            has_integrity_hash: true,
            has_schema_proof: false,
        };
        assert!(
            gate.evaluate("state-1", ObjectClass::StateObject, Some(&bundle2))
                .is_ok()
        );

        // ConfigObject needs SchemaProof
        let bundle3 = ProofBundle {
            has_proof_chain: false,
            has_integrity_proof: false,
            has_integrity_hash: false,
            has_schema_proof: true,
        };
        assert!(
            gate.evaluate("cfg-1", ObjectClass::ConfigObject, Some(&bundle3))
                .is_ok()
        );
    }

    #[test]
    fn high_assurance_each_class_has_requirement() {
        for class in ObjectClass::all() {
            let req = proof_requirement_for(*class);
            // Every class maps to a valid requirement
            assert!(!req.label().is_empty());
        }
    }

    // ── Mode switching ──

    #[test]
    fn upgrade_to_high_assurance_no_auth_needed() {
        let mut gate = HighAssuranceGate::standard();
        let result = gate.switch_mode(AssuranceMode::HighAssurance, None);
        assert!(result.is_ok());
        assert_eq!(gate.mode(), AssuranceMode::HighAssurance);
        assert_eq!(gate.mode_changes(), 1);
    }

    #[test]
    fn downgrade_without_auth_rejected() {
        let mut gate = HighAssuranceGate::high_assurance();
        let result = gate.switch_mode(AssuranceMode::Standard, None);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), "MODE_DOWNGRADE_UNAUTHORIZED");
        assert_eq!(gate.mode(), AssuranceMode::HighAssurance); // unchanged
    }

    #[test]
    fn downgrade_with_auth_allowed() {
        let mut gate = HighAssuranceGate::high_assurance();
        let auth = PolicyAuthorization {
            policy_ref: "POL-001".into(),
            authorizer_id: "admin".into(),
            timestamp_ms: 1000,
        };
        let result = gate.switch_mode(AssuranceMode::Standard, Some(&auth));
        assert!(result.is_ok());
        assert_eq!(gate.mode(), AssuranceMode::Standard);
        assert_eq!(gate.mode_changes(), 1);
    }

    #[test]
    fn same_mode_switch_is_noop() {
        let mut gate = HighAssuranceGate::standard();
        let result = gate.switch_mode(AssuranceMode::Standard, None);
        assert!(result.is_ok());
        assert_eq!(gate.mode_changes(), 0); // no change recorded
    }

    // ── Counters ──

    #[test]
    fn counters_accumulate() {
        let mut gate = HighAssuranceGate::high_assurance();
        let bundle = ProofBundle::full();

        gate.evaluate("a1", ObjectClass::CriticalMarker, Some(&bundle))
            .unwrap();
        gate.evaluate("a2", ObjectClass::CriticalMarker, Some(&bundle))
            .unwrap();
        let _ = gate.evaluate("a3", ObjectClass::CriticalMarker, None);

        assert_eq!(gate.approvals(), 2);
        assert_eq!(gate.denials(), 1);
    }

    // ── Promotion matrix ──

    #[test]
    fn promotion_matrix_standard_mode() {
        let gate = HighAssuranceGate::standard();
        let matrix = gate.promotion_matrix();
        assert_eq!(matrix.len(), 4);
        for entry in &matrix {
            assert!(!entry.proof_required);
            assert!(entry.proof_requirement.is_none());
        }
    }

    #[test]
    fn promotion_matrix_high_assurance_mode() {
        let gate = HighAssuranceGate::high_assurance();
        let matrix = gate.promotion_matrix();
        assert_eq!(matrix.len(), 4);
        for entry in &matrix {
            assert!(entry.proof_required);
            assert!(entry.proof_requirement.is_some());
        }
    }

    #[test]
    fn promotion_matrix_per_class_requirements() {
        let gate = HighAssuranceGate::high_assurance();
        let matrix = gate.promotion_matrix();

        let critical = matrix
            .iter()
            .find(|e| e.object_class == ObjectClass::CriticalMarker)
            .unwrap();
        assert_eq!(
            critical.proof_requirement,
            Some(ProofRequirement::FullProofChain)
        );

        let state = matrix
            .iter()
            .find(|e| e.object_class == ObjectClass::StateObject)
            .unwrap();
        assert_eq!(
            state.proof_requirement,
            Some(ProofRequirement::IntegrityProof)
        );

        let telemetry = matrix
            .iter()
            .find(|e| e.object_class == ObjectClass::TelemetryArtifact)
            .unwrap();
        assert_eq!(
            telemetry.proof_requirement,
            Some(ProofRequirement::IntegrityHash)
        );

        let config = matrix
            .iter()
            .find(|e| e.object_class == ObjectClass::ConfigObject)
            .unwrap();
        assert_eq!(
            config.proof_requirement,
            Some(ProofRequirement::SchemaProof)
        );
    }

    #[test]
    fn matrix_entry_to_json() {
        let entry = PromotionMatrixEntry {
            object_class: ObjectClass::CriticalMarker,
            assurance_mode: AssuranceMode::HighAssurance,
            proof_required: true,
            proof_requirement: Some(ProofRequirement::FullProofChain),
        };
        let json = entry.to_json();
        assert!(json.contains("critical_marker"));
        assert!(json.contains("high_assurance"));
        assert!(json.contains("full_proof_chain"));
    }

    // ── Denial display ──

    #[test]
    fn denial_reason_codes() {
        let d1 = PromotionDenialReason::ProofBundleMissing {
            artifact_id: "a1".into(),
            object_class: ObjectClass::CriticalMarker,
        };
        assert_eq!(d1.code(), "PROMOTION_DENIED_PROOF_BUNDLE_MISSING");

        let d2 = PromotionDenialReason::ProofBundleInsufficient {
            artifact_id: "a1".into(),
            object_class: ObjectClass::CriticalMarker,
            required: ProofRequirement::FullProofChain,
        };
        assert_eq!(d2.code(), "PROMOTION_DENIED_PROOF_INSUFFICIENT");

        let d3 = PromotionDenialReason::UnauthorizedModeDowngrade {
            from: AssuranceMode::HighAssurance,
            to: AssuranceMode::Standard,
        };
        assert_eq!(d3.code(), "MODE_DOWNGRADE_UNAUTHORIZED");
    }

    #[test]
    fn denial_reason_display() {
        let d = PromotionDenialReason::ProofBundleMissing {
            artifact_id: "art-1".into(),
            object_class: ObjectClass::CriticalMarker,
        };
        let s = d.to_string();
        assert!(s.contains("PROMOTION_DENIED_PROOF_BUNDLE_MISSING"));
        assert!(s.contains("art-1"));
    }

    // ── Adversarial: partial/forged bundle ──

    #[test]
    fn partial_bundle_rejected_for_critical() {
        let mut gate = HighAssuranceGate::high_assurance();
        // Has everything EXCEPT the proof chain
        let bundle = ProofBundle {
            has_proof_chain: false,
            has_integrity_proof: true,
            has_integrity_hash: true,
            has_schema_proof: true,
        };
        assert!(
            gate.evaluate("crit-1", ObjectClass::CriticalMarker, Some(&bundle))
                .is_err()
        );
    }

    #[test]
    fn mode_downgrade_via_direct_mutation_blocked() {
        let mut gate = HighAssuranceGate::high_assurance();
        // Try to downgrade without auth — must be rejected
        assert!(gate.switch_mode(AssuranceMode::Standard, None).is_err());
        // Mode must remain HighAssurance
        assert_eq!(gate.mode(), AssuranceMode::HighAssurance);
    }

    // ── Gate defaults ──

    #[test]
    fn gate_defaults() {
        let gate = HighAssuranceGate::standard();
        assert_eq!(gate.mode(), AssuranceMode::Standard);
        assert_eq!(gate.approvals(), 0);
        assert_eq!(gate.denials(), 0);
        assert_eq!(gate.mode_changes(), 0);
    }

    #[test]
    fn gate_high_assurance_defaults() {
        let gate = HighAssuranceGate::high_assurance();
        assert_eq!(gate.mode(), AssuranceMode::HighAssurance);
    }
}
