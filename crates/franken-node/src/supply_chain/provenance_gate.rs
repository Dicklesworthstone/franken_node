//! Provenance/attestation policy gates (bd-3i9o).
//!
//! Enforces required attestation types, minimum build assurance levels,
//! and trusted builder constraints. Non-compliant artifacts are blocked
//! pre-activation.

use serde::{Deserialize, Serialize};
use std::fmt;

const RESERVED_ARTIFACT_ID: &str = "<unknown>";

// ── Types ───────────────────────────────────────────────────────────

/// Supported attestation types.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationType {
    Slsa,
    Sigstore,
    InToto,
    Custom(String),
}

impl fmt::Display for AttestationType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Slsa => write!(f, "slsa"),
            Self::Sigstore => write!(f, "sigstore"),
            Self::InToto => write!(f, "in_toto"),
            Self::Custom(name) => write!(f, "custom:{name}"),
        }
    }
}

/// Build assurance levels, ordered by strength.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BuildAssurance {
    None,
    Basic,
    Verified,
    Hardened,
}

impl BuildAssurance {
    pub fn level(&self) -> u8 {
        match self {
            Self::None => 0,
            Self::Basic => 1,
            Self::Verified => 2,
            Self::Hardened => 3,
        }
    }

    pub fn meets_minimum(&self, minimum: BuildAssurance) -> bool {
        self.level() >= minimum.level()
    }
}

impl fmt::Display for BuildAssurance {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => write!(f, "none"),
            Self::Basic => write!(f, "basic"),
            Self::Verified => write!(f, "verified"),
            Self::Hardened => write!(f, "hardened"),
        }
    }
}

/// Provenance policy for artifact admission.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvenancePolicy {
    pub required_attestations: Vec<AttestationType>,
    pub min_build_assurance: BuildAssurance,
    pub trusted_builders: Vec<String>,
}

impl ProvenancePolicy {
    pub fn validate(&self) -> Result<(), ProvenanceError> {
        if self.trusted_builders.is_empty() {
            return Err(ProvenanceError::PolicyInvalid {
                reason: "trusted_builders must not be empty".to_string(),
            });
        }
        if self
            .trusted_builders
            .iter()
            .any(|builder| builder.trim().is_empty())
        {
            return Err(ProvenanceError::PolicyInvalid {
                reason: "trusted_builders must not contain empty builder IDs".to_string(),
            });
        }
        if self
            .trusted_builders
            .iter()
            .any(|builder| builder.trim() != builder)
        {
            return Err(ProvenanceError::PolicyInvalid {
                reason: "trusted_builders must not contain surrounding whitespace".to_string(),
            });
        }
        for attestation in &self.required_attestations {
            if let AttestationType::Custom(name) = attestation {
                if name.trim().is_empty() {
                    return Err(ProvenanceError::PolicyInvalid {
                        reason: "custom attestation names must not be empty".to_string(),
                    });
                }
                if name.trim() != name {
                    return Err(ProvenanceError::PolicyInvalid {
                        reason: "custom attestation names must not contain surrounding whitespace"
                            .to_string(),
                    });
                }
            }
        }
        Ok(())
    }
}

/// Provenance information for an artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactProvenance {
    pub artifact_id: String,
    pub connector_id: String,
    pub attestations: Vec<AttestationType>,
    pub build_assurance: BuildAssurance,
    pub builder_id: String,
}

// ── Gate decision ───────────────────────────────────────────────────

/// Result of the provenance gate evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateDecision {
    pub artifact_id: String,
    pub passed: bool,
    pub missing_attestations: Vec<AttestationType>,
    pub assurance_ok: bool,
    pub builder_trusted: bool,
    pub failure_reason: Option<GateFailure>,
    pub trace_id: String,
    pub timestamp: String,
}

/// Reason for gate failure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GateFailure {
    MissingAttestation {
        types: Vec<AttestationType>,
    },
    InsufficientAssurance {
        have: BuildAssurance,
        need: BuildAssurance,
    },
    UntrustedBuilder {
        builder_id: String,
    },
    InvalidArtifactId {
        reason: String,
    },
    PolicyInvalid {
        reason: String,
    },
}

impl fmt::Display for GateFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingAttestation { types } => {
                write!(f, "PROV_ATTEST_MISSING: {:?}", types)
            }
            Self::InsufficientAssurance { have, need } => {
                write!(f, "PROV_ASSURANCE_LOW: have={have}, need={need}")
            }
            Self::UntrustedBuilder { builder_id } => {
                write!(f, "PROV_BUILDER_UNTRUSTED: {builder_id}")
            }
            Self::InvalidArtifactId { reason } => {
                write!(f, "PROV_ARTIFACT_INVALID: {reason}")
            }
            Self::PolicyInvalid { reason } => {
                write!(f, "PROV_POLICY_INVALID: {reason}")
            }
        }
    }
}

// ── Gate evaluation ─────────────────────────────────────────────────

/// Evaluate an artifact against the provenance policy.
pub fn evaluate_gate(
    policy: &ProvenancePolicy,
    provenance: &ArtifactProvenance,
    trace_id: &str,
    timestamp: &str,
) -> GateDecision {
    let missing: Vec<AttestationType> = policy
        .required_attestations
        .iter()
        .filter(|req| !provenance.attestations.contains(req))
        .cloned()
        .collect();

    let assurance_ok = provenance
        .build_assurance
        .meets_minimum(policy.min_build_assurance);
    let builder_trusted = policy.trusted_builders.contains(&provenance.builder_id);

    if let Err(ProvenanceError::PolicyInvalid { reason }) = policy.validate() {
        return GateDecision {
            artifact_id: provenance.artifact_id.clone(),
            passed: false,
            missing_attestations: missing,
            assurance_ok,
            builder_trusted: false,
            failure_reason: Some(GateFailure::PolicyInvalid { reason }),
            trace_id: trace_id.to_string(),
            timestamp: timestamp.to_string(),
        };
    }

    if let Some(reason) = invalid_artifact_id_reason(&provenance.artifact_id) {
        return GateDecision {
            artifact_id: provenance.artifact_id.clone(),
            passed: false,
            missing_attestations: missing,
            assurance_ok,
            builder_trusted,
            failure_reason: Some(GateFailure::InvalidArtifactId { reason }),
            trace_id: trace_id.to_string(),
            timestamp: timestamp.to_string(),
        };
    }

    let passed = missing.is_empty() && assurance_ok && builder_trusted;

    let failure_reason = if passed {
        None
    } else if !missing.is_empty() {
        Some(GateFailure::MissingAttestation {
            types: missing.clone(),
        })
    } else if !assurance_ok {
        Some(GateFailure::InsufficientAssurance {
            have: provenance.build_assurance,
            need: policy.min_build_assurance,
        })
    } else {
        Some(GateFailure::UntrustedBuilder {
            builder_id: provenance.builder_id.clone(),
        })
    };

    GateDecision {
        artifact_id: provenance.artifact_id.clone(),
        passed,
        missing_attestations: missing,
        assurance_ok,
        builder_trusted,
        failure_reason,
        trace_id: trace_id.to_string(),
        timestamp: timestamp.to_string(),
    }
}

fn invalid_artifact_id_reason(artifact_id: &str) -> Option<String> {
    let trimmed = artifact_id.trim();
    if trimmed.is_empty() {
        return Some("artifact_id is empty".to_string());
    }
    if trimmed == RESERVED_ARTIFACT_ID {
        return Some(format!("artifact_id is reserved: {:?}", artifact_id));
    }
    if artifact_id.contains('\0') {
        return Some("artifact_id contains null byte".to_string());
    }
    if trimmed != artifact_id {
        return Some("artifact_id contains leading or trailing whitespace".to_string());
    }
    None
}

// ── Errors ──────────────────────────────────────────────────────────

/// Errors for provenance gate operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProvenanceError {
    #[serde(rename = "PROV_ATTEST_MISSING")]
    AttestMissing { types: Vec<String> },
    #[serde(rename = "PROV_ASSURANCE_LOW")]
    AssuranceLow { have: String, need: String },
    #[serde(rename = "PROV_BUILDER_UNTRUSTED")]
    BuilderUntrusted { builder_id: String },
    #[serde(rename = "PROV_POLICY_INVALID")]
    PolicyInvalid { reason: String },
}

impl fmt::Display for ProvenanceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AttestMissing { types } => {
                write!(f, "PROV_ATTEST_MISSING: {types:?}")
            }
            Self::AssuranceLow { have, need } => {
                write!(f, "PROV_ASSURANCE_LOW: have={have}, need={need}")
            }
            Self::BuilderUntrusted { builder_id } => {
                write!(f, "PROV_BUILDER_UNTRUSTED: {builder_id}")
            }
            Self::PolicyInvalid { reason } => {
                write!(f, "PROV_POLICY_INVALID: {reason}")
            }
        }
    }
}

impl std::error::Error for ProvenanceError {}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn test_policy() -> ProvenancePolicy {
        ProvenancePolicy {
            required_attestations: vec![AttestationType::Slsa, AttestationType::Sigstore],
            min_build_assurance: BuildAssurance::Verified,
            trusted_builders: vec!["builder-alpha".into(), "builder-beta".into()],
        }
    }

    fn good_provenance() -> ArtifactProvenance {
        ArtifactProvenance {
            artifact_id: "art-1".into(),
            connector_id: "conn-1".into(),
            attestations: vec![AttestationType::Slsa, AttestationType::Sigstore],
            build_assurance: BuildAssurance::Hardened,
            builder_id: "builder-alpha".into(),
        }
    }

    fn sorted_attestations(attestations: &[AttestationType]) -> Vec<String> {
        let mut names: Vec<String> = attestations
            .iter()
            .map(std::string::ToString::to_string)
            .collect();
        names.sort();
        names
    }

    fn assert_same_semantics(left: &GateDecision, right: &GateDecision) {
        assert_eq!(left.artifact_id, right.artifact_id);
        assert_eq!(left.passed, right.passed);
        assert_eq!(left.assurance_ok, right.assurance_ok);
        assert_eq!(left.builder_trusted, right.builder_trusted);
        assert_eq!(
            sorted_attestations(&left.missing_attestations),
            sorted_attestations(&right.missing_attestations)
        );
        assert_eq!(left.failure_reason, right.failure_reason);
    }

    // === BuildAssurance ===

    #[test]
    fn assurance_levels_ordered() {
        assert!(BuildAssurance::None.level() < BuildAssurance::Basic.level());
        assert!(BuildAssurance::Basic.level() < BuildAssurance::Verified.level());
        assert!(BuildAssurance::Verified.level() < BuildAssurance::Hardened.level());
    }

    #[test]
    fn assurance_meets_minimum() {
        assert!(BuildAssurance::Hardened.meets_minimum(BuildAssurance::Verified));
        assert!(BuildAssurance::Verified.meets_minimum(BuildAssurance::Verified));
        assert!(!BuildAssurance::Basic.meets_minimum(BuildAssurance::Verified));
    }

    // === evaluate_gate ===

    #[test]
    fn full_compliance_passes() {
        let result = evaluate_gate(&test_policy(), &good_provenance(), "t1", "ts");
        assert!(result.passed);
        assert!(result.missing_attestations.is_empty());
        assert!(result.assurance_ok);
        assert!(result.builder_trusted);
    }

    #[test]
    fn missing_attestation_blocks() {
        let mut prov = good_provenance();
        prov.attestations = vec![AttestationType::Slsa]; // missing sigstore
        let result = evaluate_gate(&test_policy(), &prov, "t2", "ts");
        assert!(!result.passed);
        assert_eq!(result.missing_attestations, vec![AttestationType::Sigstore]);
    }

    #[test]
    fn low_assurance_blocks() {
        let mut prov = good_provenance();
        prov.build_assurance = BuildAssurance::Basic;
        let result = evaluate_gate(&test_policy(), &prov, "t3", "ts");
        assert!(!result.passed);
        assert!(!result.assurance_ok);
    }

    #[test]
    fn untrusted_builder_blocks() {
        let mut prov = good_provenance();
        prov.builder_id = "rogue-builder".into();
        let result = evaluate_gate(&test_policy(), &prov, "t4", "ts");
        assert!(!result.passed);
        assert!(!result.builder_trusted);
    }

    #[test]
    fn all_failures_reported() {
        let prov = ArtifactProvenance {
            artifact_id: "art-bad".into(),
            connector_id: "conn-bad".into(),
            attestations: vec![],
            build_assurance: BuildAssurance::None,
            builder_id: "rogue".into(),
        };
        let result = evaluate_gate(&test_policy(), &prov, "t5", "ts");
        assert!(!result.passed);
        assert!(!result.missing_attestations.is_empty());
        assert!(!result.assurance_ok);
        assert!(!result.builder_trusted);
    }

    #[test]
    fn invalid_artifact_id_blocks() {
        let mut prov = good_provenance();
        prov.artifact_id.clear();
        let result = evaluate_gate(&test_policy(), &prov, "t-invalid-art", "ts");
        assert!(!result.passed);
        assert!(matches!(
            result.failure_reason,
            Some(GateFailure::InvalidArtifactId { .. })
        ));
    }

    #[test]
    fn reserved_artifact_id_blocks() {
        let mut prov = good_provenance();
        prov.artifact_id = RESERVED_ARTIFACT_ID.to_string();
        let result = evaluate_gate(&test_policy(), &prov, "t-reserved-art", "ts");
        assert!(!result.passed);
        assert!(matches!(
            result.failure_reason,
            Some(GateFailure::InvalidArtifactId { .. })
        ));
    }

    #[test]
    fn whitespace_artifact_id_blocks() {
        let mut prov = good_provenance();
        prov.artifact_id = " art-1 ".to_string();
        let result = evaluate_gate(&test_policy(), &prov, "t-ws-art", "ts");
        assert!(!result.passed);
        assert!(matches!(
            result.failure_reason,
            Some(GateFailure::InvalidArtifactId { .. })
        ));
    }

    #[test]
    fn gate_has_trace_id() {
        let result = evaluate_gate(&test_policy(), &good_provenance(), "trace-xyz", "ts");
        assert_eq!(result.trace_id, "trace-xyz");
    }

    // === Negative path precedence ===

    #[test]
    fn invalid_policy_precedence_keeps_policy_reason_for_empty_artifact() {
        let policy = ProvenancePolicy {
            required_attestations: vec![AttestationType::Slsa],
            min_build_assurance: BuildAssurance::Verified,
            trusted_builders: vec![],
        };
        let mut provenance = good_provenance();
        provenance.artifact_id.clear();

        let result = evaluate_gate(&policy, &provenance, "neg-policy-first", "ts");

        assert!(!result.passed);
        assert!(matches!(
            result.failure_reason,
            Some(GateFailure::PolicyInvalid { .. })
        ));
    }

    #[test]
    fn invalid_artifact_id_precedes_missing_attestation() {
        let mut provenance = good_provenance();
        provenance.artifact_id.clear();
        provenance.attestations.clear();

        let result = evaluate_gate(&test_policy(), &provenance, "neg-artifact-first", "ts");

        assert!(!result.passed);
        assert_eq!(
            sorted_attestations(&result.missing_attestations),
            vec!["sigstore".to_string(), "slsa".to_string()]
        );
        assert!(matches!(
            result.failure_reason,
            Some(GateFailure::InvalidArtifactId { .. })
        ));
    }

    #[test]
    fn null_byte_artifact_id_blocks() {
        let mut provenance = good_provenance();
        provenance.artifact_id = "artifact\0shadow".to_string();

        let result = evaluate_gate(&test_policy(), &provenance, "neg-nul-artifact", "ts");

        assert!(!result.passed);
        assert!(matches!(
            result.failure_reason,
            Some(GateFailure::InvalidArtifactId { ref reason })
                if reason == "artifact_id contains null byte"
        ));
    }

    #[test]
    fn missing_attestation_precedes_low_assurance_and_untrusted_builder() {
        let mut provenance = good_provenance();
        provenance.attestations.clear();
        provenance.build_assurance = BuildAssurance::None;
        provenance.builder_id = "rogue-builder".into();

        let result = evaluate_gate(&test_policy(), &provenance, "neg-missing-first", "ts");

        assert!(!result.passed);
        assert!(!result.assurance_ok);
        assert!(!result.builder_trusted);
        assert!(matches!(
            result.failure_reason,
            Some(GateFailure::MissingAttestation { .. })
        ));
    }

    #[test]
    fn low_assurance_precedes_untrusted_builder_when_attestations_present() {
        let mut provenance = good_provenance();
        provenance.build_assurance = BuildAssurance::Basic;
        provenance.builder_id = "rogue-builder".into();

        let result = evaluate_gate(&test_policy(), &provenance, "neg-assurance-first", "ts");

        assert!(!result.passed);
        assert!(result.missing_attestations.is_empty());
        assert!(!result.assurance_ok);
        assert!(!result.builder_trusted);
        assert!(matches!(
            result.failure_reason,
            Some(GateFailure::InsufficientAssurance {
                have: BuildAssurance::Basic,
                need: BuildAssurance::Verified,
            })
        ));
    }

    #[test]
    fn custom_attestation_name_mismatch_is_missing_required_custom() {
        let policy = ProvenancePolicy {
            required_attestations: vec![AttestationType::Custom("sbom".into())],
            min_build_assurance: BuildAssurance::None,
            trusted_builders: vec!["builder-alpha".into()],
        };
        let mut provenance = good_provenance();
        provenance.attestations = vec![AttestationType::Custom("SBOM".into())];

        let result = evaluate_gate(&policy, &provenance, "neg-custom-case", "ts");

        assert!(!result.passed);
        assert_eq!(
            result.missing_attestations,
            vec![AttestationType::Custom("sbom".into())]
        );
        assert!(matches!(
            result.failure_reason,
            Some(GateFailure::MissingAttestation { .. })
        ));
    }

    #[test]
    fn duplicate_trusted_builders_do_not_trust_unlisted_builder() {
        let policy = ProvenancePolicy {
            required_attestations: vec![],
            min_build_assurance: BuildAssurance::None,
            trusted_builders: vec!["builder-alpha".into(), "builder-alpha".into()],
        };
        let mut provenance = good_provenance();
        provenance.builder_id = "builder-omega".into();

        let result = evaluate_gate(&policy, &provenance, "neg-builder-dup", "ts");

        assert!(!result.passed);
        assert!(result.missing_attestations.is_empty());
        assert!(result.assurance_ok);
        assert!(!result.builder_trusted);
        assert!(matches!(
            result.failure_reason,
            Some(GateFailure::UntrustedBuilder { ref builder_id })
                if builder_id == "builder-omega"
        ));
    }

    #[test]
    fn serde_rejects_unknown_build_assurance() {
        let json = r#"{
            "artifact_id":"art-1",
            "connector_id":"conn-1",
            "attestations":["slsa"],
            "build_assurance":"root",
            "builder_id":"builder-alpha"
        }"#;

        let result = serde_json::from_str::<ArtifactProvenance>(json);

        assert!(result.is_err());
    }

    // === Metamorphic relations ===

    #[test]
    fn mr_provenance_attestation_order_is_semantics_invariant() {
        let policy = test_policy();
        let original = good_provenance();
        let mut reordered = original.clone();
        reordered.attestations.reverse();

        let baseline = evaluate_gate(&policy, &original, "mr-order-a", "ts");
        let transformed = evaluate_gate(&policy, &reordered, "mr-order-b", "ts");

        assert_same_semantics(&baseline, &transformed);
        assert!(transformed.passed);
    }

    #[test]
    fn mr_required_attestation_order_preserves_missing_set() {
        let mut policy = test_policy();
        let mut reordered_policy = policy.clone();
        reordered_policy.required_attestations.reverse();

        let mut provenance = good_provenance();
        provenance.attestations.clear();

        let baseline = evaluate_gate(&policy, &provenance, "mr-required-a", "ts");
        let transformed = evaluate_gate(&reordered_policy, &provenance, "mr-required-b", "ts");

        assert!(!baseline.passed);
        assert!(!transformed.passed);
        assert_eq!(
            sorted_attestations(&baseline.missing_attestations),
            sorted_attestations(&transformed.missing_attestations)
        );
        assert_eq!(
            sorted_attestations(&baseline.missing_attestations),
            vec!["sigstore".to_string(), "slsa".to_string()]
        );
        policy.required_attestations.reverse();
        assert_eq!(policy, reordered_policy);
    }

    #[test]
    fn mr_extra_irrelevant_attestation_preserves_passing_decision() {
        let policy = test_policy();
        let original = good_provenance();
        let mut enriched = original.clone();
        enriched
            .attestations
            .push(AttestationType::Custom("sbom".into()));

        let baseline = evaluate_gate(&policy, &original, "mr-extra-a", "ts");
        let transformed = evaluate_gate(&policy, &enriched, "mr-extra-b", "ts");

        assert_same_semantics(&baseline, &transformed);
        assert!(transformed.passed);
    }

    #[test]
    fn mr_adding_missing_required_attestation_repairs_only_missing_dimension() {
        let policy = test_policy();
        let mut missing_sigstore = good_provenance();
        missing_sigstore.attestations = vec![AttestationType::Slsa];

        let mut repaired = missing_sigstore.clone();
        repaired.attestations.push(AttestationType::Sigstore);

        let before = evaluate_gate(&policy, &missing_sigstore, "mr-repair-a", "ts");
        let after = evaluate_gate(&policy, &repaired, "mr-repair-b", "ts");

        assert!(!before.passed);
        assert_eq!(before.missing_attestations, vec![AttestationType::Sigstore]);
        assert!(before.assurance_ok);
        assert!(before.builder_trusted);
        assert!(after.passed);
        assert!(after.missing_attestations.is_empty());
        assert_eq!(before.assurance_ok, after.assurance_ok);
        assert_eq!(before.builder_trusted, after.builder_trusted);
    }

    #[test]
    fn mr_strengthening_assurance_preserves_admission() {
        let policy = test_policy();
        let mut verified = good_provenance();
        verified.build_assurance = BuildAssurance::Verified;
        let mut hardened = verified.clone();
        hardened.build_assurance = BuildAssurance::Hardened;

        let verified_decision = evaluate_gate(&policy, &verified, "mr-assurance-a", "ts");
        let hardened_decision = evaluate_gate(&policy, &hardened, "mr-assurance-b", "ts");

        assert!(verified_decision.passed);
        assert!(hardened_decision.passed);
        assert_eq!(
            verified_decision.missing_attestations,
            hardened_decision.missing_attestations
        );
        assert!(hardened_decision.assurance_ok);
        assert_eq!(
            verified_decision.builder_trusted,
            hardened_decision.builder_trusted
        );
    }

    #[test]
    fn mr_weakening_assurance_cannot_improve_decision() {
        let policy = test_policy();
        let mut verified = good_provenance();
        verified.build_assurance = BuildAssurance::Verified;
        let mut weakened = verified.clone();
        weakened.build_assurance = BuildAssurance::Basic;

        let before = evaluate_gate(&policy, &verified, "mr-weaken-a", "ts");
        let after = evaluate_gate(&policy, &weakened, "mr-weaken-b", "ts");

        assert!(before.passed);
        assert!(!after.passed);
        assert!(!after.assurance_ok);
        assert_eq!(before.builder_trusted, after.builder_trusted);
        assert!(matches!(
            after.failure_reason,
            Some(GateFailure::InsufficientAssurance {
                have: BuildAssurance::Basic,
                need: BuildAssurance::Verified,
            })
        ));
    }

    #[test]
    fn mr_trusted_builder_order_is_semantics_invariant() {
        let policy = test_policy();
        let mut reordered_policy = policy.clone();
        reordered_policy.trusted_builders.reverse();
        let provenance = good_provenance();

        let baseline = evaluate_gate(&policy, &provenance, "mr-builder-order-a", "ts");
        let transformed = evaluate_gate(&reordered_policy, &provenance, "mr-builder-order-b", "ts");

        assert_same_semantics(&baseline, &transformed);
        assert!(transformed.passed);
    }

    #[test]
    fn mr_expanding_trusted_builders_preserves_existing_admission() {
        let policy = test_policy();
        let mut expanded_policy = policy.clone();
        expanded_policy
            .trusted_builders
            .push("builder-gamma".into());
        let provenance = good_provenance();

        let baseline = evaluate_gate(&policy, &provenance, "mr-builder-expand-a", "ts");
        let transformed = evaluate_gate(&expanded_policy, &provenance, "mr-builder-expand-b", "ts");

        assert_same_semantics(&baseline, &transformed);
        assert!(transformed.passed);
    }

    #[test]
    fn mr_trace_and_timestamp_do_not_change_gate_semantics() {
        let policy = test_policy();
        let provenance = good_provenance();

        let baseline = evaluate_gate(&policy, &provenance, "trace-a", "2026-04-17T00:00:00Z");
        let transformed = evaluate_gate(&policy, &provenance, "trace-b", "2026-04-17T01:00:00Z");

        assert_same_semantics(&baseline, &transformed);
        assert_eq!(baseline.trace_id, "trace-a");
        assert_eq!(transformed.trace_id, "trace-b");
        assert_eq!(baseline.timestamp, "2026-04-17T00:00:00Z");
        assert_eq!(transformed.timestamp, "2026-04-17T01:00:00Z");
    }

    #[test]
    fn mr_duplicate_present_attestations_do_not_mask_missing_required_type() {
        let policy = test_policy();
        let mut duplicated = good_provenance();
        duplicated.attestations = vec![AttestationType::Slsa, AttestationType::Slsa];

        let decision = evaluate_gate(&policy, &duplicated, "mr-duplicate", "ts");

        assert!(!decision.passed);
        assert_eq!(
            decision.missing_attestations,
            vec![AttestationType::Sigstore]
        );
        assert!(matches!(
            decision.failure_reason,
            Some(GateFailure::MissingAttestation { ref types })
                if types == &vec![AttestationType::Sigstore]
        ));
    }

    #[test]
    fn mr_adding_required_attestation_can_only_narrow_policy() {
        let policy = test_policy();
        let mut narrowed_policy = policy.clone();
        narrowed_policy
            .required_attestations
            .push(AttestationType::InToto);
        let provenance = good_provenance();

        let baseline = evaluate_gate(&policy, &provenance, "mr-narrow-a", "ts");
        let transformed = evaluate_gate(&narrowed_policy, &provenance, "mr-narrow-b", "ts");

        assert!(baseline.passed);
        assert!(!transformed.passed);
        assert_eq!(
            transformed.missing_attestations,
            vec![AttestationType::InToto]
        );
        assert!(transformed.assurance_ok);
        assert!(transformed.builder_trusted);
    }

    #[test]
    fn mr_compound_reorder_enrich_and_strengthen_preserves_passing_decision() {
        let policy = test_policy();
        let original = good_provenance();
        let mut transformed_policy = policy.clone();
        transformed_policy.required_attestations.reverse();
        transformed_policy.trusted_builders.reverse();

        let mut transformed_provenance = original.clone();
        transformed_provenance.attestations.reverse();
        transformed_provenance
            .attestations
            .push(AttestationType::Custom("vex".into()));
        transformed_provenance.build_assurance = BuildAssurance::Hardened;

        let baseline = evaluate_gate(&policy, &original, "mr-compound-a", "ts");
        let transformed = evaluate_gate(
            &transformed_policy,
            &transformed_provenance,
            "mr-compound-b",
            "ts",
        );

        assert!(baseline.passed);
        assert!(transformed.passed);
        assert!(transformed.missing_attestations.is_empty());
        assert_eq!(baseline.assurance_ok, transformed.assurance_ok);
        assert_eq!(baseline.builder_trusted, transformed.builder_trusted);
    }

    // === AttestationType ===

    #[test]
    fn attestation_display() {
        assert_eq!(AttestationType::Slsa.to_string(), "slsa");
        assert_eq!(AttestationType::Sigstore.to_string(), "sigstore");
        assert_eq!(AttestationType::InToto.to_string(), "in_toto");
        assert_eq!(
            AttestationType::Custom("foo".into()).to_string(),
            "custom:foo"
        );
    }

    // === Policy validation ===

    #[test]
    fn empty_builders_invalid() {
        let policy = ProvenancePolicy {
            required_attestations: vec![],
            min_build_assurance: BuildAssurance::None,
            trusted_builders: vec![],
        };
        assert!(policy.validate().is_err());
    }

    #[test]
    fn valid_policy_passes() {
        assert!(test_policy().validate().is_ok());
    }

    #[test]
    fn whitespace_only_trusted_builder_policy_is_invalid() {
        let policy = ProvenancePolicy {
            required_attestations: vec![AttestationType::Slsa],
            min_build_assurance: BuildAssurance::Basic,
            trusted_builders: vec![" \t ".to_string()],
        };

        let err = policy
            .validate()
            .expect_err("blank trusted builder must fail closed");

        assert!(matches!(
            err,
            ProvenanceError::PolicyInvalid { reason }
                if reason.contains("empty builder IDs")
        ));
    }

    #[test]
    fn trusted_builder_with_surrounding_whitespace_policy_is_invalid() {
        let policy = ProvenancePolicy {
            required_attestations: vec![AttestationType::Slsa],
            min_build_assurance: BuildAssurance::Basic,
            trusted_builders: vec![" builder-alpha".to_string()],
        };

        let err = policy
            .validate()
            .expect_err("trusted builder aliases must be canonical");

        assert!(matches!(
            err,
            ProvenanceError::PolicyInvalid { reason }
                if reason.contains("surrounding whitespace")
        ));
    }

    #[test]
    fn gate_rejects_policy_with_whitespace_builder_even_if_provenance_matches() {
        let policy = ProvenancePolicy {
            required_attestations: vec![AttestationType::Slsa, AttestationType::Sigstore],
            min_build_assurance: BuildAssurance::Basic,
            trusted_builders: vec![" builder-alpha ".to_string()],
        };
        let mut provenance = good_provenance();
        provenance.builder_id = " builder-alpha ".to_string();

        let decision = evaluate_gate(&policy, &provenance, "t-builder-policy-ws", "ts");

        assert!(!decision.passed);
        assert!(!decision.builder_trusted);
        assert!(matches!(
            decision.failure_reason,
            Some(GateFailure::PolicyInvalid { ref reason })
                if reason.contains("surrounding whitespace")
        ));
    }

    #[test]
    fn empty_required_custom_attestation_policy_is_invalid() {
        let policy = ProvenancePolicy {
            required_attestations: vec![AttestationType::Custom(String::new())],
            min_build_assurance: BuildAssurance::Basic,
            trusted_builders: vec!["builder-alpha".to_string()],
        };

        let err = policy
            .validate()
            .expect_err("blank custom attestation names must fail closed");

        assert!(matches!(
            err,
            ProvenanceError::PolicyInvalid { reason }
                if reason.contains("custom attestation names must not be empty")
        ));
    }

    #[test]
    fn whitespace_required_custom_attestation_policy_is_invalid() {
        let policy = ProvenancePolicy {
            required_attestations: vec![AttestationType::Custom(" sbom ".to_string())],
            min_build_assurance: BuildAssurance::Basic,
            trusted_builders: vec!["builder-alpha".to_string()],
        };

        let err = policy
            .validate()
            .expect_err("custom attestation names must be canonical");

        assert!(matches!(
            err,
            ProvenanceError::PolicyInvalid { reason }
                if reason.contains("custom attestation names must not contain surrounding whitespace")
        ));
    }

    #[test]
    fn invalid_custom_attestation_policy_precedes_matching_provenance_claim() {
        let policy = ProvenancePolicy {
            required_attestations: vec![AttestationType::Custom(String::new())],
            min_build_assurance: BuildAssurance::Basic,
            trusted_builders: vec!["builder-alpha".to_string()],
        };
        let mut provenance = good_provenance();
        provenance.attestations = vec![AttestationType::Custom(String::new())];

        let decision = evaluate_gate(&policy, &provenance, "t-empty-custom-policy", "ts");

        assert!(!decision.passed);
        assert!(!decision.builder_trusted);
        assert!(matches!(
            decision.failure_reason,
            Some(GateFailure::PolicyInvalid { ref reason })
                if reason.contains("custom attestation names")
        ));
    }

    #[test]
    fn invalid_policy_fails_closed_with_policy_invalid_reason() {
        let policy = ProvenancePolicy {
            required_attestations: vec![AttestationType::Slsa],
            min_build_assurance: BuildAssurance::Verified,
            trusted_builders: vec![],
        };

        let result = evaluate_gate(&policy, &good_provenance(), "t-invalid", "ts");
        assert!(!result.passed);
        assert!(result.assurance_ok);
        assert!(!result.builder_trusted);
        assert!(result.missing_attestations.is_empty());
        assert!(matches!(
            result.failure_reason,
            Some(GateFailure::PolicyInvalid { .. })
        ));
    }

    // === GateFailure display ===

    #[test]
    fn failure_display_messages() {
        let f1 = GateFailure::MissingAttestation {
            types: vec![AttestationType::Slsa],
        };
        assert!(f1.to_string().contains("PROV_ATTEST_MISSING"));

        let f2 = GateFailure::InsufficientAssurance {
            have: BuildAssurance::Basic,
            need: BuildAssurance::Verified,
        };
        assert!(f2.to_string().contains("PROV_ASSURANCE_LOW"));

        let f3 = GateFailure::UntrustedBuilder {
            builder_id: "rogue".into(),
        };
        assert!(f3.to_string().contains("PROV_BUILDER_UNTRUSTED"));

        let f4 = GateFailure::InvalidArtifactId {
            reason: "bad".into(),
        };
        assert!(f4.to_string().contains("PROV_ARTIFACT_INVALID"));

        let f5 = GateFailure::PolicyInvalid {
            reason: "bad".into(),
        };
        assert!(f5.to_string().contains("PROV_POLICY_INVALID"));
    }

    #[test]
    fn invalid_policy_with_reserved_artifact_reports_policy_invalid() {
        let policy = ProvenancePolicy {
            required_attestations: vec![AttestationType::Slsa],
            min_build_assurance: BuildAssurance::Hardened,
            trusted_builders: Vec::new(),
        };
        let mut provenance = good_provenance();
        provenance.artifact_id = RESERVED_ARTIFACT_ID.to_string();

        let decision = evaluate_gate(&policy, &provenance, "t-policy-first", "ts");

        assert!(!decision.passed);
        assert!(matches!(
            decision.failure_reason,
            Some(GateFailure::PolicyInvalid { .. })
        ));
    }

    #[test]
    fn invalid_artifact_id_precedes_other_gate_failures() {
        let policy = test_policy();
        let mut provenance = good_provenance();
        provenance.artifact_id = " \t ".to_string();
        provenance.attestations.clear();
        provenance.build_assurance = BuildAssurance::None;
        provenance.builder_id = "rogue-builder".to_string();

        let decision = evaluate_gate(&policy, &provenance, "t-artifact-first", "ts");

        assert!(!decision.passed);
        assert!(!decision.assurance_ok);
        assert!(!decision.builder_trusted);
        assert!(matches!(
            decision.failure_reason,
            Some(GateFailure::InvalidArtifactId { ref reason })
                if reason.contains("empty")
        ));
    }

    #[test]
    fn builder_id_with_trailing_space_is_not_trusted_alias() {
        let policy = test_policy();
        let mut provenance = good_provenance();
        provenance.builder_id = "builder-alpha ".to_string();

        let decision = evaluate_gate(&policy, &provenance, "t-builder-space", "ts");

        assert!(!decision.passed);
        assert!(decision.missing_attestations.is_empty());
        assert!(decision.assurance_ok);
        assert!(!decision.builder_trusted);
        assert!(matches!(
            decision.failure_reason,
            Some(GateFailure::UntrustedBuilder { ref builder_id })
                if builder_id == "builder-alpha "
        ));
    }

    #[test]
    fn empty_custom_attestation_name_is_not_satisfied_by_named_custom() {
        let policy = ProvenancePolicy {
            required_attestations: vec![AttestationType::Custom(String::new())],
            min_build_assurance: BuildAssurance::Basic,
            trusted_builders: vec!["builder-alpha".to_string()],
        };
        let mut provenance = good_provenance();
        provenance.attestations = vec![AttestationType::Custom("vex".to_string())];

        let decision = evaluate_gate(&policy, &provenance, "t-empty-custom", "ts");

        assert!(!decision.passed);
        assert!(matches!(
            decision.failure_reason,
            Some(GateFailure::PolicyInvalid { ref reason })
                if reason.contains("custom attestation names must not be empty")
        ));
    }

    #[test]
    fn serde_rejects_unknown_build_assurance_variant() {
        let err = serde_json::from_str::<BuildAssurance>(r#""super_hardened""#)
            .expect_err("unknown build assurance must be rejected");

        assert!(err.to_string().contains("unknown variant"));
    }

    #[test]
    fn serde_rejects_unknown_gate_failure_variant() {
        let err = serde_json::from_str::<GateFailure>(r#"{"policy_bypass":{}}"#)
            .expect_err("unknown gate failure must be rejected");

        assert!(err.to_string().contains("unknown variant"));
    }

    #[test]
    fn serde_rejects_policy_missing_trusted_builders() {
        let value = serde_json::json!({
            "required_attestations": ["slsa"],
            "min_build_assurance": "verified"
        });

        let err = serde_json::from_value::<ProvenancePolicy>(value)
            .expect_err("missing trusted_builders must fail deserialization");

        assert!(err.to_string().contains("trusted_builders"));
    }

    #[test]
    fn serde_rejects_provenance_attestations_as_object() {
        let value = serde_json::json!({
            "artifact_id": "art-1",
            "connector_id": "conn-1",
            "attestations": {"slsa": true},
            "build_assurance": "verified",
            "builder_id": "builder-alpha"
        });

        let err = serde_json::from_value::<ArtifactProvenance>(value)
            .expect_err("object attestations must fail deserialization");

        assert!(err.to_string().contains("attestations"));
    }

    // === Serde ===

    #[test]
    fn serde_roundtrip_decision() {
        let result = evaluate_gate(&test_policy(), &good_provenance(), "t6", "ts");
        let json = serde_json::to_string(&result).unwrap();
        let parsed: GateDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(result, parsed);
    }

    #[test]
    fn serde_roundtrip_provenance() {
        let prov = good_provenance();
        let json = serde_json::to_string(&prov).unwrap();
        let parsed: ArtifactProvenance = serde_json::from_str(&json).unwrap();
        assert_eq!(prov, parsed);
    }

    // === Error display ===

    #[test]
    fn error_display_messages() {
        let e1 = ProvenanceError::AttestMissing {
            types: vec!["slsa".into()],
        };
        assert!(e1.to_string().contains("PROV_ATTEST_MISSING"));

        let e2 = ProvenanceError::AssuranceLow {
            have: "basic".into(),
            need: "verified".into(),
        };
        assert!(e2.to_string().contains("PROV_ASSURANCE_LOW"));

        let e3 = ProvenanceError::BuilderUntrusted {
            builder_id: "x".into(),
        };
        assert!(e3.to_string().contains("PROV_BUILDER_UNTRUSTED"));

        let e4 = ProvenanceError::PolicyInvalid {
            reason: "bad".into(),
        };
        assert!(e4.to_string().contains("PROV_POLICY_INVALID"));
    }
}
