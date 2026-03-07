// SPDX-License-Identifier: MIT
// [10.18] bd-3pds — Integrate VEF evidence into verifier SDK replay capsules
// and external verification APIs.

use std::collections::BTreeMap;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

// ── Capacity limits ─────────────────────────────────────────────────
const MAX_AUDIT_LOG_ENTRIES: usize = 4096;
const MAX_EVIDENCE: usize = 4096;

fn push_bounded<T>(items: &mut Vec<T>, item: T, cap: usize) {
    items.push(item);
    if items.len() > cap {
        let overflow = items.len() - cap;
        items.drain(0..overflow);
    }
}

// ── Schema ──────────────────────────────────────────────────────────
pub const SCHEMA_VERSION: &str = "evidence-capsule-v1.0";

// ── Event codes ─────────────────────────────────────────────────────
pub const EVIDENCE_CAPSULE_CREATED: &str = "EVIDENCE_CAPSULE_CREATED";
pub const EVIDENCE_CAPSULE_SEALED: &str = "EVIDENCE_CAPSULE_SEALED";
pub const EVIDENCE_CAPSULE_EXPORTED: &str = "EVIDENCE_CAPSULE_EXPORTED";
pub const EVIDENCE_CAPSULE_VERIFIED: &str = "EVIDENCE_CAPSULE_VERIFIED";
pub const EVIDENCE_CAPSULE_REJECTED: &str = "EVIDENCE_CAPSULE_REJECTED";

// ── Error codes ─────────────────────────────────────────────────────
pub const ERR_CAPSULE_EMPTY_EVIDENCE: &str = "ERR_CAPSULE_EMPTY_EVIDENCE";
pub const ERR_CAPSULE_SEAL_FAILED: &str = "ERR_CAPSULE_SEAL_FAILED";
pub const ERR_CAPSULE_SCHEMA_MISMATCH: &str = "ERR_CAPSULE_SCHEMA_MISMATCH";
pub const ERR_CAPSULE_PROOF_MISSING: &str = "ERR_CAPSULE_PROOF_MISSING";
pub const ERR_CAPSULE_REPLAY_DIVERGED: &str = "ERR_CAPSULE_REPLAY_DIVERGED";
pub const ERR_CAPSULE_EXPORT_FAILED: &str = "ERR_CAPSULE_EXPORT_FAILED";

// ── Invariants ──────────────────────────────────────────────────────
// INV-EVIDENCE-CAPSULE-COMPLETE: capsule must contain all required evidence
// INV-EVIDENCE-CAPSULE-SEALED: sealed capsules are immutable
// INV-EVIDENCE-CAPSULE-VERIFIABLE: exported capsules must be independently verifiable
// INV-EVIDENCE-CAPSULE-SCHEMA-STABLE: schema version must match expected format

/// VEF evidence record to embed in capsule.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct VefEvidence {
    pub receipt_chain_commitment: String,
    pub proof_id: String,
    pub proof_type: String,
    pub window_start: u64,
    pub window_end: u64,
    pub verified: bool,
    pub policy_constraints: Vec<String>,
}

/// Replay capsule with VEF evidence integration.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct EvidenceCapsule {
    pub capsule_id: String,
    pub schema_version: String,
    pub created_at_epoch: u64,
    pub evidence: Vec<VefEvidence>,
    pub metadata: BTreeMap<String, String>,
    sealed: bool,
}

impl EvidenceCapsule {
    pub fn new(capsule_id: String, created_at_epoch: u64) -> Self {
        Self {
            capsule_id,
            schema_version: SCHEMA_VERSION.into(),
            created_at_epoch,
            evidence: Vec::new(),
            metadata: BTreeMap::new(),
            sealed: false,
        }
    }

    pub fn is_sealed(&self) -> bool {
        self.sealed
    }

    /// Add VEF evidence to the capsule.
    ///
    /// INV-EVIDENCE-CAPSULE-SEALED: rejects if sealed
    pub fn add_evidence(&mut self, ev: VefEvidence) -> Result<(), CapsuleError> {
        if self.sealed {
            return Err(CapsuleError::AlreadySealed);
        }
        push_bounded(&mut self.evidence, ev, MAX_EVIDENCE);
        Ok(())
    }

    /// Add metadata.
    pub fn set_metadata(&mut self, key: String, value: String) -> Result<(), CapsuleError> {
        if self.sealed {
            return Err(CapsuleError::AlreadySealed);
        }
        self.metadata.insert(key, value);
        Ok(())
    }

    /// Seal the capsule, making it immutable.
    ///
    /// INV-EVIDENCE-CAPSULE-COMPLETE: requires at least one evidence
    pub fn seal(&mut self) -> Result<(), CapsuleError> {
        if self.sealed {
            return Err(CapsuleError::AlreadySealed);
        }
        if self.evidence.is_empty() {
            return Err(CapsuleError::EmptyEvidence);
        }
        // INV-EVIDENCE-CAPSULE-SCHEMA-STABLE
        if self.schema_version != SCHEMA_VERSION {
            return Err(CapsuleError::SchemaMismatch {
                expected: SCHEMA_VERSION.into(),
                got: self.schema_version.clone(),
            });
        }
        self.sealed = true;
        Ok(())
    }

    /// Verify all evidence in the capsule.
    ///
    /// INV-EVIDENCE-CAPSULE-VERIFIABLE
    pub fn verify_all(&self) -> CapsuleVerificationResult {
        if !self.sealed {
            return CapsuleVerificationResult {
                valid: false,
                checked: 0,
                passed: 0,
                failures: vec!["capsule not sealed".into()],
            };
        }

        let mut passed = 0;
        let mut failures = Vec::new();

        for ev in &self.evidence {
            if ev.verified && !ev.receipt_chain_commitment.is_empty() && !ev.proof_id.is_empty() {
                passed += 1;
            } else {
                let mut reasons = Vec::new();
                if !ev.verified {
                    reasons.push("not verified");
                }
                if ev.receipt_chain_commitment.is_empty() {
                    reasons.push("empty commitment");
                }
                if ev.proof_id.is_empty() {
                    reasons.push("empty proof_id");
                }
                failures.push(format!("evidence {}: {}", ev.proof_id, reasons.join(", ")));
            }
        }

        CapsuleVerificationResult {
            valid: failures.is_empty(),
            checked: self.evidence.len(),
            passed,
            failures,
        }
    }

    pub fn evidence_count(&self) -> usize {
        self.evidence.len()
    }
}

/// Result of capsule verification.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct CapsuleVerificationResult {
    pub valid: bool,
    pub checked: usize,
    pub passed: usize,
    pub failures: Vec<String>,
}

/// Capsule errors.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum CapsuleError {
    EmptyEvidence,
    AlreadySealed,
    SchemaMismatch { expected: String, got: String },
    ProofMissing { detail: String },
    ReplayDiverged { detail: String },
    ExportFailed { detail: String },
}

impl std::fmt::Display for CapsuleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyEvidence => write!(f, "{ERR_CAPSULE_EMPTY_EVIDENCE}"),
            Self::AlreadySealed => write!(f, "{ERR_CAPSULE_SEAL_FAILED}: already sealed"),
            Self::SchemaMismatch { expected, got } => {
                write!(f, "{ERR_CAPSULE_SCHEMA_MISMATCH}: expected={expected}, got={got}")
            }
            Self::ProofMissing { detail } => {
                write!(f, "{ERR_CAPSULE_PROOF_MISSING}: {detail}")
            }
            Self::ReplayDiverged { detail } => {
                write!(f, "{ERR_CAPSULE_REPLAY_DIVERGED}: {detail}")
            }
            Self::ExportFailed { detail } => {
                write!(f, "{ERR_CAPSULE_EXPORT_FAILED}: {detail}")
            }
        }
    }
}

/// External verification API endpoint descriptor.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ExternalVerifierEndpoint {
    pub name: String,
    pub url: String,
    pub supported_schemas: Vec<String>,
}

/// Export manifest for external verification.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ExportManifest {
    pub capsule_id: String,
    pub evidence_count: usize,
    pub schema_version: String,
    pub target_endpoint: String,
}

/// Registry for external verifier endpoints.
pub struct VerifierRegistry {
    endpoints: BTreeMap<String, ExternalVerifierEndpoint>,
    audit_log: Vec<String>,
}

impl VerifierRegistry {
    pub fn new() -> Self {
        Self {
            endpoints: BTreeMap::new(),
            audit_log: Vec::new(),
        }
    }

    pub fn register(&mut self, endpoint: ExternalVerifierEndpoint) {
        self.endpoints.insert(endpoint.name.clone(), endpoint);
    }

    pub fn export_capsule(
        &mut self,
        capsule: &EvidenceCapsule,
        target: &str,
    ) -> Result<ExportManifest, CapsuleError> {
        if !capsule.is_sealed() {
            return Err(CapsuleError::ExportFailed {
                detail: "capsule not sealed".into(),
            });
        }

        let endpoint = self
            .endpoints
            .get(target)
            .ok_or(CapsuleError::ExportFailed {
                detail: format!("unknown endpoint: {target}"),
            })?;

        if !endpoint
            .supported_schemas
            .iter()
            .any(|s| s == &capsule.schema_version)
        {
            return Err(CapsuleError::SchemaMismatch {
                expected: endpoint.supported_schemas.join(", "),
                got: capsule.schema_version.clone(),
            });
        }

        push_bounded(&mut self.audit_log, format!(
            "{}: capsule={} target={}",
            EVIDENCE_CAPSULE_EXPORTED, capsule.capsule_id, target
        ), MAX_AUDIT_LOG_ENTRIES);

        Ok(ExportManifest {
            capsule_id: capsule.capsule_id.clone(),
            evidence_count: capsule.evidence_count(),
            schema_version: capsule.schema_version.clone(),
            target_endpoint: target.into(),
        })
    }

    pub fn endpoints(&self) -> &BTreeMap<String, ExternalVerifierEndpoint> {
        &self.endpoints
    }

    pub fn audit_log(&self) -> &[String] {
        &self.audit_log
    }
}

impl Default for VerifierRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ── Tests ───────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;

    fn test_evidence() -> VefEvidence {
        VefEvidence {
            receipt_chain_commitment: "commit-abc".into(),
            proof_id: "proof-1".into(),
            proof_type: "snark".into(),
            window_start: 0,
            window_end: 100,
            verified: true,
            policy_constraints: vec!["no-network".into()],
        }
    }

    fn sealed_capsule() -> EvidenceCapsule {
        let mut c = EvidenceCapsule::new("cap-1".into(), 1000);
        c.add_evidence(test_evidence()).unwrap();
        c.seal().unwrap();
        c
    }

    #[test]
    fn test_schema_version() {
        assert_eq!(SCHEMA_VERSION, "evidence-capsule-v1.0");
    }

    #[test]
    fn test_create_capsule() {
        let c = EvidenceCapsule::new("c1".into(), 1000);
        assert!(!c.is_sealed());
        assert_eq!(c.evidence_count(), 0);
    }

    #[test]
    fn test_add_evidence() {
        let mut c = EvidenceCapsule::new("c1".into(), 1000);
        assert!(c.add_evidence(test_evidence()).is_ok());
        assert_eq!(c.evidence_count(), 1);
    }

    #[test]
    fn test_seal_ok() {
        let mut c = EvidenceCapsule::new("c1".into(), 1000);
        c.add_evidence(test_evidence()).unwrap();
        assert!(c.seal().is_ok());
        assert!(c.is_sealed());
    }

    #[test]
    fn test_seal_empty_rejected() {
        let mut c = EvidenceCapsule::new("c1".into(), 1000);
        assert!(matches!(c.seal(), Err(CapsuleError::EmptyEvidence)));
    }

    #[test]
    fn test_add_after_seal_rejected() {
        let mut c = sealed_capsule();
        assert!(matches!(
            c.add_evidence(test_evidence()),
            Err(CapsuleError::AlreadySealed)
        ));
    }

    #[test]
    fn test_double_seal_rejected() {
        let mut c = sealed_capsule();
        assert!(matches!(c.seal(), Err(CapsuleError::AlreadySealed)));
    }

    #[test]
    fn test_verify_all_ok() {
        let c = sealed_capsule();
        let result = c.verify_all();
        assert!(result.valid);
        assert_eq!(result.passed, 1);
    }

    #[test]
    fn test_verify_unsealed_fails() {
        let mut c = EvidenceCapsule::new("c1".into(), 1000);
        c.add_evidence(test_evidence()).unwrap();
        let result = c.verify_all();
        assert!(!result.valid);
    }

    #[test]
    fn test_verify_unverified_evidence() {
        let mut c = EvidenceCapsule::new("c1".into(), 1000);
        let mut ev = test_evidence();
        ev.verified = false;
        c.add_evidence(ev).unwrap();
        c.seal().unwrap();
        let result = c.verify_all();
        assert!(!result.valid);
    }

    #[test]
    fn test_metadata() {
        let mut c = EvidenceCapsule::new("c1".into(), 1000);
        c.set_metadata("key".into(), "val".into()).unwrap();
        assert_eq!(c.metadata.get("key").unwrap(), "val");
    }

    #[test]
    fn test_metadata_after_seal() {
        let mut c = sealed_capsule();
        assert!(matches!(
            c.set_metadata("k".into(), "v".into()),
            Err(CapsuleError::AlreadySealed)
        ));
    }

    #[test]
    fn test_verifier_registry() {
        let mut reg = VerifierRegistry::new();
        reg.register(ExternalVerifierEndpoint {
            name: "ext-1".into(),
            url: "https://example.com/verify".into(),
            supported_schemas: vec![SCHEMA_VERSION.into()],
        });
        assert_eq!(reg.endpoints().len(), 1);
    }

    #[test]
    fn test_export_capsule_ok() {
        let mut reg = VerifierRegistry::new();
        reg.register(ExternalVerifierEndpoint {
            name: "ext-1".into(),
            url: "https://example.com/verify".into(),
            supported_schemas: vec![SCHEMA_VERSION.into()],
        });
        let c = sealed_capsule();
        let manifest = reg.export_capsule(&c, "ext-1").unwrap();
        assert_eq!(manifest.evidence_count, 1);
    }

    #[test]
    fn test_export_unsealed_rejected() {
        let mut reg = VerifierRegistry::new();
        reg.register(ExternalVerifierEndpoint {
            name: "ext-1".into(),
            url: "https://example.com".into(),
            supported_schemas: vec![SCHEMA_VERSION.into()],
        });
        let c = EvidenceCapsule::new("c1".into(), 1000);
        assert!(matches!(
            reg.export_capsule(&c, "ext-1"),
            Err(CapsuleError::ExportFailed { .. })
        ));
    }

    #[test]
    fn test_export_unknown_endpoint() {
        let mut reg = VerifierRegistry::new();
        let c = sealed_capsule();
        assert!(matches!(
            reg.export_capsule(&c, "nope"),
            Err(CapsuleError::ExportFailed { .. })
        ));
    }

    #[test]
    fn test_export_schema_mismatch() {
        let mut reg = VerifierRegistry::new();
        reg.register(ExternalVerifierEndpoint {
            name: "ext-1".into(),
            url: "https://example.com".into(),
            supported_schemas: vec!["other-v2.0".into()],
        });
        let c = sealed_capsule();
        assert!(matches!(
            reg.export_capsule(&c, "ext-1"),
            Err(CapsuleError::SchemaMismatch { .. })
        ));
    }

    #[test]
    fn test_error_display() {
        let e = CapsuleError::EmptyEvidence;
        assert!(e.to_string().contains(ERR_CAPSULE_EMPTY_EVIDENCE));
    }

    #[test]
    fn test_verify_empty_commitment() {
        let mut c = EvidenceCapsule::new("c1".into(), 1000);
        let mut ev = test_evidence();
        ev.receipt_chain_commitment = String::new();
        c.add_evidence(ev).unwrap();
        c.seal().unwrap();
        let result = c.verify_all();
        assert!(!result.valid);
    }

    #[test]
    fn test_multiple_evidence() {
        let mut c = EvidenceCapsule::new("c1".into(), 1000);
        c.add_evidence(test_evidence()).unwrap();
        let mut ev2 = test_evidence();
        ev2.proof_id = "proof-2".into();
        c.add_evidence(ev2).unwrap();
        c.seal().unwrap();
        let result = c.verify_all();
        assert!(result.valid);
        assert_eq!(result.checked, 2);
        assert_eq!(result.passed, 2);
    }

    #[test]
    fn test_default_registry() {
        let reg = VerifierRegistry::default();
        assert!(reg.endpoints().is_empty());
    }

    #[test]
    fn test_audit_log_on_export() {
        let mut reg = VerifierRegistry::new();
        reg.register(ExternalVerifierEndpoint {
            name: "ext-1".into(),
            url: "https://example.com".into(),
            supported_schemas: vec![SCHEMA_VERSION.into()],
        });
        let c = sealed_capsule();
        reg.export_capsule(&c, "ext-1").unwrap();
        assert_eq!(reg.audit_log().len(), 1);
        assert!(reg.audit_log()[0].contains(EVIDENCE_CAPSULE_EXPORTED));
    }
}
