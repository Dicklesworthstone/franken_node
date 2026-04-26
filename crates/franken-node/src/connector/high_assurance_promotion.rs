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

impl PolicyAuthorization {
    fn is_valid(&self) -> bool {
        !self.policy_ref.trim().is_empty()
            && !self.authorizer_id.trim().is_empty()
            && self.timestamp_ms != 0
    }
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
            self.approvals = self.approvals.saturating_add(1);
            return Ok(());
        }

        // HighAssurance mode: proof required
        let bundle = match proof_bundle {
            Some(b) => b,
            None => {
                self.denials = self.denials.saturating_add(1);
                return Err(PromotionDenialReason::ProofBundleMissing {
                    artifact_id: artifact_id.into(),
                    object_class,
                });
            }
        };

        let requirement = proof_requirement_for(object_class);
        if !bundle.satisfies(requirement) {
            self.denials = self.denials.saturating_add(1);
            return Err(PromotionDenialReason::ProofBundleInsufficient {
                artifact_id: artifact_id.into(),
                object_class,
                required: requirement,
            });
        }

        self.approvals = self.approvals.saturating_add(1);
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
        if self.mode == AssuranceMode::HighAssurance
            && new_mode == AssuranceMode::Standard
            && !authorization.is_some_and(PolicyAuthorization::is_valid)
        {
            return Err(PromotionDenialReason::UnauthorizedModeDowngrade {
                from: self.mode,
                to: new_mode,
            });
        }

        self.mode = new_mode;
        self.mode_changes = self.mode_changes.saturating_add(1);
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
    fn high_assurance_missing_proof_does_not_increment_approvals() {
        let mut gate = HighAssuranceGate::high_assurance();

        let result = gate.evaluate("art-1", ObjectClass::CriticalMarker, None);

        assert!(matches!(
            result,
            Err(PromotionDenialReason::ProofBundleMissing { .. })
        ));
        assert_eq!(gate.approvals(), 0);
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
    fn high_assurance_insufficient_proof_does_not_increment_approvals() {
        let mut gate = HighAssuranceGate::high_assurance();
        let bundle = ProofBundle {
            has_proof_chain: false,
            has_integrity_proof: true,
            has_integrity_hash: true,
            has_schema_proof: true,
        };

        let result = gate.evaluate("art-1", ObjectClass::CriticalMarker, Some(&bundle));

        assert!(matches!(
            result,
            Err(PromotionDenialReason::ProofBundleInsufficient { .. })
        ));
        assert_eq!(gate.approvals(), 0);
        assert_eq!(gate.denials(), 1);
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

    #[test]
    fn state_object_rejects_hash_only_bundle() {
        let mut gate = HighAssuranceGate::high_assurance();
        let bundle = ProofBundle {
            has_proof_chain: false,
            has_integrity_proof: false,
            has_integrity_hash: true,
            has_schema_proof: false,
        };

        let result = gate.evaluate("state-1", ObjectClass::StateObject, Some(&bundle));

        assert!(matches!(
            result,
            Err(PromotionDenialReason::ProofBundleInsufficient {
                required: ProofRequirement::IntegrityProof,
                ..
            })
        ));
    }

    #[test]
    fn telemetry_artifact_rejects_signature_without_hash() {
        let mut gate = HighAssuranceGate::high_assurance();
        let bundle = ProofBundle {
            has_proof_chain: false,
            has_integrity_proof: true,
            has_integrity_hash: false,
            has_schema_proof: false,
        };

        let result = gate.evaluate("tel-1", ObjectClass::TelemetryArtifact, Some(&bundle));

        assert!(matches!(
            result,
            Err(PromotionDenialReason::ProofBundleInsufficient {
                required: ProofRequirement::IntegrityHash,
                ..
            })
        ));
    }

    #[test]
    fn config_object_rejects_full_chain_without_schema_proof() {
        let mut gate = HighAssuranceGate::high_assurance();
        let bundle = ProofBundle {
            has_proof_chain: true,
            has_integrity_proof: true,
            has_integrity_hash: true,
            has_schema_proof: false,
        };

        let result = gate.evaluate("cfg-1", ObjectClass::ConfigObject, Some(&bundle));

        assert!(matches!(
            result,
            Err(PromotionDenialReason::ProofBundleInsufficient {
                required: ProofRequirement::SchemaProof,
                ..
            })
        ));
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
    fn downgrade_without_auth_does_not_increment_mode_changes() {
        let mut gate = HighAssuranceGate::high_assurance();

        let result = gate.switch_mode(AssuranceMode::Standard, None);

        assert!(matches!(
            result,
            Err(PromotionDenialReason::UnauthorizedModeDowngrade { .. })
        ));
        assert_eq!(gate.mode(), AssuranceMode::HighAssurance);
        assert_eq!(gate.mode_changes(), 0);
    }

    #[test]
    fn downgrade_with_empty_policy_ref_rejected() {
        let mut gate = HighAssuranceGate::high_assurance();
        let auth = PolicyAuthorization {
            policy_ref: " ".into(),
            authorizer_id: "admin".into(),
            timestamp_ms: 1000,
        };

        let result = gate.switch_mode(AssuranceMode::Standard, Some(&auth));

        assert!(matches!(
            result,
            Err(PromotionDenialReason::UnauthorizedModeDowngrade { .. })
        ));
        assert_eq!(gate.mode(), AssuranceMode::HighAssurance);
        assert_eq!(gate.mode_changes(), 0);
    }

    #[test]
    fn downgrade_with_empty_authorizer_rejected() {
        let mut gate = HighAssuranceGate::high_assurance();
        let auth = PolicyAuthorization {
            policy_ref: "POL-001".into(),
            authorizer_id: "".into(),
            timestamp_ms: 1000,
        };

        let result = gate.switch_mode(AssuranceMode::Standard, Some(&auth));

        assert!(matches!(
            result,
            Err(PromotionDenialReason::UnauthorizedModeDowngrade { .. })
        ));
        assert_eq!(gate.mode(), AssuranceMode::HighAssurance);
        assert_eq!(gate.mode_changes(), 0);
    }

    #[test]
    fn downgrade_with_zero_timestamp_rejected() {
        let mut gate = HighAssuranceGate::high_assurance();
        let auth = PolicyAuthorization {
            policy_ref: "POL-001".into(),
            authorizer_id: "admin".into(),
            timestamp_ms: 0,
        };

        let result = gate.switch_mode(AssuranceMode::Standard, Some(&auth));

        assert!(matches!(
            result,
            Err(PromotionDenialReason::UnauthorizedModeDowngrade { .. })
        ));
        assert_eq!(gate.mode(), AssuranceMode::HighAssurance);
        assert_eq!(gate.mode_changes(), 0);
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
            .expect("should evaluate");
        gate.evaluate("a2", ObjectClass::CriticalMarker, Some(&bundle))
            .expect("should evaluate");
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
            .expect("should evaluate");
        assert_eq!(
            critical.proof_requirement,
            Some(ProofRequirement::FullProofChain)
        );

        let state = matrix
            .iter()
            .find(|e| e.object_class == ObjectClass::StateObject)
            .expect("should evaluate");
        assert_eq!(
            state.proof_requirement,
            Some(ProofRequirement::IntegrityProof)
        );

        let telemetry = matrix
            .iter()
            .find(|e| e.object_class == ObjectClass::TelemetryArtifact)
            .expect("should evaluate");
        assert_eq!(
            telemetry.proof_requirement,
            Some(ProofRequirement::IntegrityHash)
        );

        let config = matrix
            .iter()
            .find(|e| e.object_class == ObjectClass::ConfigObject)
            .expect("should evaluate");
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

    // ---------------------------------------------------------------------------
    // NEGATIVE-PATH TESTS: Security hardening for high-assurance promotion
    // ---------------------------------------------------------------------------

    #[test]
    fn negative_unicode_injection_in_artifact_ids_and_policy_references() {
        let mut gate = HighAssuranceGate::high_assurance();

        // BiDi override attack in artifact ID
        let malicious_artifact_id = "\u{202E}trojan\u{202D}legitimate_artifact";
        let bundle = ProofBundle::full();

        let result = gate.evaluate(
            malicious_artifact_id,
            ObjectClass::CriticalMarker,
            Some(&bundle),
        );
        assert!(result.is_ok()); // Should process but preserve the malicious ID

        // Zero-width character injection
        let zero_width_id = "normal\u{200B}\u{200C}\u{200D}\u{FEFF}hidden_payload";
        let result2 = gate.evaluate(zero_width_id, ObjectClass::StateObject, Some(&bundle));
        assert!(result2.is_ok());

        // Test Unicode injection in policy authorization
        let unicode_policy_auth = PolicyAuthorization {
            policy_ref: "\u{202E}ycilop_ekal\u{202D}real_policy_POL-001".to_string(),
            authorizer_id: "admin\u{0000}\ninjection\u{FEFF}".to_string(),
            timestamp_ms: 1000,
        };

        // Should still validate as "valid" since we preserve input for analysis
        assert!(unicode_policy_auth.is_valid());

        // Test mode downgrade with Unicode injection in authorization
        let result3 = gate.switch_mode(AssuranceMode::Standard, Some(&unicode_policy_auth));
        assert!(result3.is_ok()); // Should succeed since auth is technically valid

        // Path traversal injection in artifact ID
        let path_traversal_id = "../../../etc/passwd\0\nmalicious_path";
        let result4 = gate.evaluate(path_traversal_id, ObjectClass::ConfigObject, Some(&bundle));
        assert!(result4.is_ok());

        // Verify counters updated correctly despite Unicode attacks
        assert_eq!(gate.approvals(), 4);
    }

    #[test]
    fn negative_proof_bundle_forgery_and_manipulation_attacks() {
        let mut gate = HighAssuranceGate::high_assurance();

        // Test proof bundle with contradictory states (logical impossibility)
        let contradictory_bundle = ProofBundle {
            has_proof_chain: true,
            has_integrity_proof: false, // Contradiction: chain implies integrity
            has_integrity_hash: false,  // Another contradiction
            has_schema_proof: true,
        };

        // Should still check against requirements regardless of internal contradictions
        let result = gate.evaluate(
            "contradictory",
            ObjectClass::CriticalMarker,
            Some(&contradictory_bundle),
        );
        assert!(result.is_ok()); // has_proof_chain=true satisfies FullProofChain

        // Test edge case: all proofs false but claim to be "full"
        let fake_full_bundle = ProofBundle {
            has_proof_chain: false,
            has_integrity_proof: false,
            has_integrity_hash: false,
            has_schema_proof: false,
        };

        let result2 = gate.evaluate(
            "fake_full",
            ObjectClass::CriticalMarker,
            Some(&fake_full_bundle),
        );
        assert!(result2.is_err()); // Should fail - no actual proof

        // Test proof requirement bypassing attempts for each class
        let hash_only_bundle = ProofBundle {
            has_proof_chain: false,
            has_integrity_proof: false,
            has_integrity_hash: true,
            has_schema_proof: false,
        };

        // Try to use hash-only for classes that require more
        let bypass_attempts = vec![
            (
                ObjectClass::CriticalMarker,
                ProofRequirement::FullProofChain,
            ),
            (ObjectClass::StateObject, ProofRequirement::IntegrityProof),
            (ObjectClass::ConfigObject, ProofRequirement::SchemaProof),
        ];

        for (class, expected_req) in bypass_attempts {
            let result = gate.evaluate(
                &format!("bypass_{}", class.label()),
                class,
                Some(&hash_only_bundle),
            );

            if class == ObjectClass::TelemetryArtifact {
                assert!(result.is_ok()); // This class only needs IntegrityHash
            } else {
                assert!(result.is_err()); // Others should fail
                if let Err(PromotionDenialReason::ProofBundleInsufficient { required, .. }) = result
                {
                    assert_eq!(required, expected_req);
                }
            }
        }
    }

    #[test]
    fn negative_counter_overflow_and_arithmetic_boundary_attacks() {
        let mut gate = HighAssuranceGate::high_assurance();
        let bundle = ProofBundle::full();

        // Test approval counter near overflow boundary
        gate.approvals = u64::MAX - 5;
        for i in 0..10 {
            let result = gate.evaluate(
                &format!("overflow_test_{}", i),
                ObjectClass::CriticalMarker,
                Some(&bundle),
            );
            assert!(result.is_ok());
        }

        // Verify saturating arithmetic prevented overflow
        assert_eq!(gate.approvals(), u64::MAX);

        // Reset and test denial counter overflow
        let mut denial_gate = HighAssuranceGate::high_assurance();
        denial_gate.denials = u64::MAX - 3;

        for i in 0..8 {
            let result = denial_gate.evaluate(
                &format!("denial_overflow_{}", i),
                ObjectClass::CriticalMarker,
                None,
            );
            assert!(result.is_err());
        }

        // Verify denials saturated correctly
        assert_eq!(denial_gate.denials(), u64::MAX);

        // Test mode_changes counter overflow
        let mut mode_gate = HighAssuranceGate::standard();
        mode_gate.mode_changes = u64::MAX - 2;

        let auth = PolicyAuthorization {
            policy_ref: "POL-001".to_string(),
            authorizer_id: "admin".to_string(),
            timestamp_ms: 1000,
        };

        // Multiple mode switches to test overflow protection
        for _ in 0..5 {
            let _ = mode_gate.switch_mode(AssuranceMode::HighAssurance, None);
            let _ = mode_gate.switch_mode(AssuranceMode::Standard, Some(&auth));
        }

        assert_eq!(mode_gate.mode_changes(), u64::MAX);

        // Test arithmetic edge cases with zero values
        let mut zero_gate = HighAssuranceGate::high_assurance();
        assert_eq!(zero_gate.approvals(), 0);
        assert_eq!(zero_gate.denials(), 0);
        assert_eq!(zero_gate.mode_changes(), 0);

        // Verify operations work correctly from zero state
        let _ = zero_gate.evaluate("zero_test", ObjectClass::CriticalMarker, None);
        assert_eq!(zero_gate.denials(), 1);
    }

    #[test]
    fn negative_policy_authorization_bypass_and_forgery_attacks() {
        let mut gate = HighAssuranceGate::high_assurance();

        // Test authorization with malicious field injections
        let malicious_auth = PolicyAuthorization {
            policy_ref: "POL-001\0DROP TABLE policies;\nGRANT ALL".to_string(),
            authorizer_id: "admin'; DELETE FROM users; --".to_string(),
            timestamp_ms: u64::MAX, // Extreme timestamp
        };

        // Should be considered "valid" since fields are non-empty
        assert!(malicious_auth.is_valid());

        let result = gate.switch_mode(AssuranceMode::Standard, Some(&malicious_auth));
        assert!(result.is_ok()); // Dangerous but technically valid auth

        // Test authorization bypass with whitespace manipulation
        let whitespace_auth = PolicyAuthorization {
            policy_ref: "\n\t\r POL-001 \t\n".to_string(),
            authorizer_id: "\u{00A0}\u{2000}\u{2001}admin\u{2028}".to_string(), // Unicode whitespace
            timestamp_ms: 1,
        };

        assert!(whitespace_auth.is_valid()); // Non-empty after trim

        // Test timestamp manipulation attacks
        let timestamp_attacks = vec![
            PolicyAuthorization {
                policy_ref: "POL-001".to_string(),
                authorizer_id: "admin".to_string(),
                timestamp_ms: 0, // Should be invalid
            },
            PolicyAuthorization {
                policy_ref: "POL-001".to_string(),
                authorizer_id: "admin".to_string(),
                timestamp_ms: u64::MAX - 1, // Near overflow
            },
            PolicyAuthorization {
                policy_ref: "POL-001".to_string(),
                authorizer_id: "admin".to_string(),
                timestamp_ms: 1, // Minimal valid timestamp
            },
        ];

        for (i, auth) in timestamp_attacks.iter().enumerate() {
            let is_zero = auth.timestamp_ms == 0;
            assert_eq!(!auth.is_valid(), is_zero); // Only zero timestamp should be invalid

            let mut test_gate = HighAssuranceGate::high_assurance();
            let result = test_gate.switch_mode(AssuranceMode::Standard, Some(auth));

            if is_zero {
                assert!(result.is_err());
                assert!(matches!(
                    result,
                    Err(PromotionDenialReason::UnauthorizedModeDowngrade { .. })
                ));
            } else {
                assert!(result.is_ok());
            }
        }

        // Test authorization field length attacks
        let long_field_auth = PolicyAuthorization {
            policy_ref: "A".repeat(100_000),    // Very long policy reference
            authorizer_id: "B".repeat(100_000), // Very long authorizer ID
            timestamp_ms: 1000,
        };

        assert!(long_field_auth.is_valid());

        let mut long_gate = HighAssuranceGate::high_assurance();
        let result = long_gate.switch_mode(AssuranceMode::Standard, Some(&long_field_auth));
        assert!(result.is_ok()); // Should handle long strings gracefully
    }

    #[test]
    fn negative_concurrent_access_safety_and_race_conditions() {
        use std::sync::{Arc, Mutex};
        use std::thread;

        let gate = Arc::new(Mutex::new(HighAssuranceGate::high_assurance()));
        let mut handles = vec![];

        // Spawn threads performing concurrent evaluations and mode switches
        for thread_id in 0..8 {
            let gate_clone = Arc::clone(&gate);
            let handle = thread::spawn(move || {
                let bundle = ProofBundle::full();
                let auth = PolicyAuthorization {
                    policy_ref: format!("POL-{:03}", thread_id),
                    authorizer_id: format!("admin_{}", thread_id),
                    timestamp_ms: 1000 + thread_id as u64,
                };

                for op_id in 0..100 {
                    let mut gate = gate_clone.lock().unwrap();

                    // Concurrent evaluations
                    let artifact_id = format!("thread_{}_artifact_{}", thread_id, op_id);
                    let _ = gate.evaluate(&artifact_id, ObjectClass::CriticalMarker, Some(&bundle));

                    // Some denials mixed in
                    if op_id % 10 == 0 {
                        let _ = gate.evaluate(&artifact_id, ObjectClass::CriticalMarker, None);
                    }

                    // Concurrent mode switches (should be safe due to lock)
                    if op_id % 20 == 0 {
                        let _ = gate.switch_mode(AssuranceMode::Standard, Some(&auth));
                        let _ = gate.switch_mode(AssuranceMode::HighAssurance, None);
                    }
                }
            });
            handles.push(handle);
        }

        // Wait for all threads
        for handle in handles {
            handle.join().unwrap();
        }

        // Verify final state consistency
        let final_gate = gate.lock().unwrap();
        let total_approvals = final_gate.approvals();
        let total_denials = final_gate.denials();
        let total_mode_changes = final_gate.mode_changes();

        // Should have reasonable totals from 8 threads * 100 ops each
        assert!(total_approvals > 0);
        assert!(total_denials > 0); // Some should have failed
        assert!(total_mode_changes > 0); // Some mode switches should have occurred

        // Verify no counter overflow occurred
        assert!(total_approvals <= 8 * 100);
        assert!(total_denials <= 8 * 10); // Max 10 denials per thread
    }

    #[test]
    fn negative_json_serialization_injection_and_corruption_attacks() {
        let gate = HighAssuranceGate::high_assurance();
        let matrix = gate.promotion_matrix();

        // Test JSON output for injection vulnerabilities
        for entry in &matrix {
            let json = entry.to_json();

            // Verify JSON is well-formed (no injection)
            assert!(json.starts_with('{'));
            assert!(json.ends_with('}'));
            assert!(json.contains("object_class"));
            assert!(json.contains("assurance_mode"));
            assert!(json.contains("proof_required"));
            assert!(json.contains("proof_requirement"));

            // Verify no unescaped control characters
            assert!(!json.contains('\0'));
            assert!(!json.contains('\n'));
            assert!(!json.contains('\r'));
            assert!(!json.contains('\t'));
        }

        // Test with crafted object class names (simulate if they could be injected)
        let malicious_entry = PromotionMatrixEntry {
            object_class: ObjectClass::CriticalMarker, // Would be "critical_marker" in JSON
            assurance_mode: AssuranceMode::HighAssurance,
            proof_required: true,
            proof_requirement: Some(ProofRequirement::FullProofChain),
        };

        let json = malicious_entry.to_json();

        // Verify proper JSON escaping and structure
        assert!(json.contains("\"critical_marker\""));
        assert!(json.contains("\"high_assurance\""));
        assert!(json.contains("\"full_proof_chain\""));
        assert!(json.contains("true"));

        // Test edge cases in JSON generation
        let edge_cases = vec![
            PromotionMatrixEntry {
                object_class: ObjectClass::TelemetryArtifact,
                assurance_mode: AssuranceMode::Standard,
                proof_required: false,
                proof_requirement: None, // null in JSON
            },
            PromotionMatrixEntry {
                object_class: ObjectClass::ConfigObject,
                assurance_mode: AssuranceMode::HighAssurance,
                proof_required: true,
                proof_requirement: Some(ProofRequirement::SchemaProof),
            },
        ];

        for entry in edge_cases {
            let json = entry.to_json();

            if entry.proof_requirement.is_none() {
                assert!(json.contains("null"));
            } else {
                assert!(!json.contains("null"));
                assert!(json.contains("\"schema_proof\""));
            }

            // Verify boolean serialization
            if entry.proof_required {
                assert!(json.contains("true"));
            } else {
                assert!(json.contains("false"));
            }
        }
    }

    #[test]
    fn negative_mode_switching_state_corruption_and_bypass_attempts() {
        let mut gate = HighAssuranceGate::high_assurance();

        // Verify initial state
        assert_eq!(gate.mode(), AssuranceMode::HighAssurance);
        assert_eq!(gate.mode_changes(), 0);

        // Test rapid mode switching to detect state corruption
        let auth = PolicyAuthorization {
            policy_ref: "POL-RAPID".to_string(),
            authorizer_id: "admin".to_string(),
            timestamp_ms: 1000,
        };

        for i in 0..1000 {
            let target_mode = if i % 2 == 0 {
                AssuranceMode::Standard
            } else {
                AssuranceMode::HighAssurance
            };

            let auth_opt = if target_mode == AssuranceMode::Standard {
                Some(&auth)
            } else {
                None
            };

            let result = gate.switch_mode(target_mode, auth_opt);
            assert!(result.is_ok());
            assert_eq!(gate.mode(), target_mode);
        }

        // Verify mode changes counter tracked correctly
        assert_eq!(gate.mode_changes(), 999); // 1000 switches, but first was HighAssurance->Standard

        // Test concurrent evaluation during mode switching vulnerability window
        let bundle = ProofBundle::empty();

        // Switch to standard mode
        let _ = gate.switch_mode(AssuranceMode::Standard, Some(&auth));

        // Evaluation should use current mode (Standard = no proof required)
        let result = gate.evaluate("during_switch", ObjectClass::CriticalMarker, Some(&bundle));
        assert!(result.is_ok()); // Standard mode allows empty bundle

        // Switch back to high assurance
        let _ = gate.switch_mode(AssuranceMode::HighAssurance, None);

        // Same bundle should now be rejected
        let result2 = gate.evaluate("after_switch", ObjectClass::CriticalMarker, Some(&bundle));
        assert!(result2.is_err()); // HighAssurance mode rejects empty bundle

        // Test invalid authorization replay attacks
        let used_auth = PolicyAuthorization {
            policy_ref: "POL-USED".to_string(),
            authorizer_id: "admin".to_string(),
            timestamp_ms: 500, // Earlier timestamp
        };

        // Should still work (no timestamp ordering enforced)
        let result3 = gate.switch_mode(AssuranceMode::Standard, Some(&used_auth));
        assert!(result3.is_ok());

        // Test authorization with extreme edge values
        let edge_auth = PolicyAuthorization {
            policy_ref: "A".to_string(),    // Single character
            authorizer_id: "B".to_string(), // Single character
            timestamp_ms: 1,                // Minimum valid timestamp
        };

        let result4 = gate.switch_mode(AssuranceMode::HighAssurance, None);
        assert!(result4.is_ok());

        let result5 = gate.switch_mode(AssuranceMode::Standard, Some(&edge_auth));
        assert!(result5.is_ok()); // Should accept minimal valid auth
    }

    #[test]
    fn negative_proof_requirement_logic_bypass_and_class_confusion_attacks() {
        let mut gate = HighAssuranceGate::high_assurance();

        // Test class confusion attacks - using wrong proof for different classes
        let proofs_by_type = vec![
            (
                "full_chain",
                ProofBundle {
                    has_proof_chain: true,
                    has_integrity_proof: false,
                    has_integrity_hash: false,
                    has_schema_proof: false,
                },
            ),
            (
                "integrity_proof",
                ProofBundle {
                    has_proof_chain: false,
                    has_integrity_proof: true,
                    has_integrity_hash: false,
                    has_schema_proof: false,
                },
            ),
            (
                "integrity_hash",
                ProofBundle {
                    has_proof_chain: false,
                    has_integrity_proof: false,
                    has_integrity_hash: true,
                    has_schema_proof: false,
                },
            ),
            (
                "schema_proof",
                ProofBundle {
                    has_proof_chain: false,
                    has_integrity_proof: false,
                    has_integrity_hash: false,
                    has_schema_proof: true,
                },
            ),
        ];

        // Test each proof type against each object class
        for (proof_name, bundle) in &proofs_by_type {
            for &class in ObjectClass::all() {
                let artifact_id = format!("{}_{}", proof_name, class.label());
                let result = gate.evaluate(&artifact_id, class, Some(bundle));

                let expected_requirement = proof_requirement_for(class);
                let should_succeed = bundle.satisfies(expected_requirement);

                if should_succeed {
                    assert!(
                        result.is_ok(),
                        "Expected success for {} with {} proof",
                        class.label(),
                        proof_name
                    );
                } else {
                    assert!(
                        result.is_err(),
                        "Expected failure for {} with {} proof",
                        class.label(),
                        proof_name
                    );

                    if let Err(PromotionDenialReason::ProofBundleInsufficient {
                        required, ..
                    }) = result
                    {
                        assert_eq!(required, expected_requirement);
                    }
                }
            }
        }

        // Test proof requirement enumeration completeness
        let all_requirements = vec![
            ProofRequirement::FullProofChain,
            ProofRequirement::IntegrityProof,
            ProofRequirement::IntegrityHash,
            ProofRequirement::SchemaProof,
        ];

        for requirement in &all_requirements {
            // Each requirement should have a non-empty label
            assert!(!requirement.label().is_empty());

            // Each requirement should have a valid Display implementation
            let display_str = requirement.to_string();
            assert!(!display_str.is_empty());
            assert_eq!(display_str, requirement.label());
        }

        // Test mapping coverage - every object class should map to a requirement
        for &class in ObjectClass::all() {
            let requirement = proof_requirement_for(class);
            assert!(all_requirements.contains(&requirement));
        }

        // Test proof bundle satisfies logic edge cases
        let contradictory_bundle = ProofBundle {
            has_proof_chain: true,      // Should imply others are also true
            has_integrity_proof: false, // But they're false - logical inconsistency
            has_integrity_hash: false,
            has_schema_proof: false,
        };

        // Each requirement should be checked independently
        assert!(contradictory_bundle.satisfies(ProofRequirement::FullProofChain));
        assert!(!contradictory_bundle.satisfies(ProofRequirement::IntegrityProof));
        assert!(!contradictory_bundle.satisfies(ProofRequirement::IntegrityHash));
        assert!(!contradictory_bundle.satisfies(ProofRequirement::SchemaProof));
    }
}
