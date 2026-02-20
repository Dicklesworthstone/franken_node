//! Provenance/attestation policy gates (bd-3i9o).
//!
//! Enforces required attestation types, minimum build assurance levels,
//! and trusted builder constraints. Non-compliant artifacts are blocked
//! pre-activation.

use serde::{Deserialize, Serialize};
use std::fmt;

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
    // Check attestations
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
    fn gate_has_trace_id() {
        let result = evaluate_gate(&test_policy(), &good_provenance(), "trace-xyz", "ts");
        assert_eq!(result.trace_id, "trace-xyz");
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

        let f4 = GateFailure::PolicyInvalid {
            reason: "bad".into(),
        };
        assert!(f4.to_string().contains("PROV_POLICY_INVALID"));
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
