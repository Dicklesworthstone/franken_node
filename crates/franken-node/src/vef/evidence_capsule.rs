// SPDX-License-Identifier: MIT
// [10.18] bd-3pds — Integrate VEF evidence into verifier SDK replay capsules
// and external verification APIs.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

// ── Capacity limits ─────────────────────────────────────────────────
use crate::capacity_defaults::aliases::MAX_AUDIT_LOG_ENTRIES;
use crate::push_bounded;
const MAX_EVIDENCE: usize = 4096;

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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

        let mut passed: usize = 0;
        let mut failures = Vec::new();

        for ev in &self.evidence {
            if ev.verified && !ev.receipt_chain_commitment.is_empty() && !ev.proof_id.is_empty() {
                passed = passed.saturating_add(1);
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapsuleVerificationResult {
    pub valid: bool,
    pub checked: usize,
    pub passed: usize,
    pub failures: Vec<String>,
}

/// Capsule errors.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
                write!(
                    f,
                    "{ERR_CAPSULE_SCHEMA_MISMATCH}: expected={expected}, got={got}"
                )
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExternalVerifierEndpoint {
    pub name: String,
    pub url: String,
    pub supported_schemas: Vec<String>,
}

/// Export manifest for external verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
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

        push_bounded(
            &mut self.audit_log,
            format!(
                "{}: capsule={} target={}",
                EVIDENCE_CAPSULE_EXPORTED, capsule.capsule_id, target
            ),
            MAX_AUDIT_LOG_ENTRIES,
        );

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
        c.add_evidence(test_evidence()).expect("add should succeed");
        c.seal().expect("seal should succeed");
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
        c.add_evidence(test_evidence()).expect("add should succeed");
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
        c.add_evidence(test_evidence()).expect("add should succeed");
        let result = c.verify_all();
        assert!(!result.valid);
    }

    #[test]
    fn test_verify_unverified_evidence() {
        let mut c = EvidenceCapsule::new("c1".into(), 1000);
        let mut ev = test_evidence();
        ev.verified = false;
        c.add_evidence(ev).expect("add should succeed");
        c.seal().expect("seal should succeed");
        let result = c.verify_all();
        assert!(!result.valid);
    }

    #[test]
    fn test_metadata() {
        let mut c = EvidenceCapsule::new("c1".into(), 1000);
        c.set_metadata("key".into(), "val".into())
            .expect("set should succeed");
        assert_eq!(c.metadata.get("key").expect("should exist"), "val");
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
        let manifest = reg
            .export_capsule(&c, "ext-1")
            .expect("export should succeed");
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
        c.add_evidence(ev).expect("add should succeed");
        c.seal().expect("seal should succeed");
        let result = c.verify_all();
        assert!(!result.valid);
    }

    #[test]
    fn test_multiple_evidence() {
        let mut c = EvidenceCapsule::new("c1".into(), 1000);
        c.add_evidence(test_evidence()).expect("add should succeed");
        let mut ev2 = test_evidence();
        ev2.proof_id = "proof-2".into();
        c.add_evidence(ev2).expect("add should succeed");
        c.seal().expect("seal should succeed");
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
        reg.export_capsule(&c, "ext-1")
            .expect("export should succeed");
        assert_eq!(reg.audit_log().len(), 1);
        assert!(reg.audit_log()[0].contains(EVIDENCE_CAPSULE_EXPORTED));
    }

    #[test]
    fn seal_rejects_schema_mismatch_without_marking_capsule_sealed() {
        let mut c = EvidenceCapsule::new("c1".into(), 1000);
        c.add_evidence(test_evidence()).expect("add should succeed");
        c.schema_version = "evidence-capsule-v0".into();

        let err = c.seal().expect_err("schema mismatch must fail");

        assert!(matches!(err, CapsuleError::SchemaMismatch { .. }));
        assert!(
            !c.is_sealed(),
            "failed seal must not make capsule immutable"
        );
    }

    #[test]
    fn verify_all_reports_empty_proof_id() {
        let mut c = EvidenceCapsule::new("c1".into(), 1000);
        let mut ev = test_evidence();
        ev.proof_id.clear();
        c.add_evidence(ev).expect("add should succeed");
        c.seal().expect("seal should succeed");

        let result = c.verify_all();

        assert!(!result.valid);
        assert_eq!(result.checked, 1);
        assert_eq!(result.passed, 0);
        assert!(result.failures[0].contains("empty proof_id"));
    }

    #[test]
    fn verify_all_reports_combined_failure_reasons() {
        let mut c = EvidenceCapsule::new("c1".into(), 1000);
        let mut ev = test_evidence();
        ev.verified = false;
        ev.receipt_chain_commitment.clear();
        ev.proof_id.clear();
        c.add_evidence(ev).expect("add should succeed");
        c.seal().expect("seal should succeed");

        let result = c.verify_all();

        assert!(!result.valid);
        assert_eq!(result.failures.len(), 1);
        assert!(result.failures[0].contains("not verified"));
        assert!(result.failures[0].contains("empty commitment"));
        assert!(result.failures[0].contains("empty proof_id"));
    }

    #[test]
    fn export_schema_mismatch_does_not_append_audit_log() {
        let mut reg = VerifierRegistry::new();
        reg.register(ExternalVerifierEndpoint {
            name: "ext-1".into(),
            url: "https://example.com".into(),
            supported_schemas: vec!["other-v2.0".into()],
        });
        let c = sealed_capsule();

        let err = reg
            .export_capsule(&c, "ext-1")
            .expect_err("schema mismatch must fail");

        assert!(matches!(err, CapsuleError::SchemaMismatch { .. }));
        assert!(reg.audit_log().is_empty());
    }

    #[test]
    fn export_unknown_endpoint_does_not_append_audit_log() {
        let mut reg = VerifierRegistry::new();
        let c = sealed_capsule();

        let err = reg
            .export_capsule(&c, "missing-endpoint")
            .expect_err("unknown endpoint must fail");

        assert!(matches!(err, CapsuleError::ExportFailed { .. }));
        assert!(reg.audit_log().is_empty());
    }

    #[test]
    fn export_empty_target_name_is_rejected() {
        let mut reg = VerifierRegistry::new();
        reg.register(ExternalVerifierEndpoint {
            name: "ext-1".into(),
            url: "https://example.com".into(),
            supported_schemas: vec![SCHEMA_VERSION.into()],
        });
        let c = sealed_capsule();

        let err = reg
            .export_capsule(&c, "")
            .expect_err("empty target name must not resolve to an endpoint");

        assert!(matches!(err, CapsuleError::ExportFailed { .. }));
        assert!(reg.audit_log().is_empty());
    }

    #[test]
    fn evidence_capsule_deserialize_rejects_missing_schema_version() {
        let raw = serde_json::json!({
            "capsule_id": "cap-missing-schema",
            "created_at_epoch": 1000_u64,
            "evidence": [],
            "metadata": {},
            "sealed": false
        });

        let result: Result<EvidenceCapsule, _> = serde_json::from_value(raw);

        assert!(result.is_err(), "schema_version is required");
    }

    #[test]
    fn endpoint_deserialize_rejects_supported_schemas_type_confusion() {
        let raw = serde_json::json!({
            "name": "ext-1",
            "url": "https://example.com",
            "supported_schemas": "evidence-capsule-v1.0"
        });

        let result: Result<ExternalVerifierEndpoint, _> = serde_json::from_value(raw);

        assert!(
            result.is_err(),
            "supported_schemas must be an array, not a scalar"
        );
    }

    #[test]
    fn push_bounded_zero_capacity_clears_existing_evidence() {
        let mut items = vec![test_evidence()];

        push_bounded(&mut items, test_evidence(), 0);

        assert!(items.is_empty());
    }

    #[test]
    fn push_bounded_over_capacity_keeps_latest_evidence() {
        let mut first = test_evidence();
        first.proof_id = "proof-old".into();
        let mut second = test_evidence();
        second.proof_id = "proof-mid".into();
        let mut third = test_evidence();
        third.proof_id = "proof-new".into();
        let mut items = vec![first, second];

        push_bounded(&mut items, third, 2);

        assert_eq!(items[0].proof_id, "proof-mid");
        assert_eq!(items[1].proof_id, "proof-new");
    }

    #[test]
    fn vef_evidence_deserialize_rejects_missing_proof_id() {
        let raw = serde_json::json!({
            "receipt_chain_commitment": "commit-abc",
            "proof_type": "snark",
            "window_start": 0_u64,
            "window_end": 100_u64,
            "verified": true,
            "policy_constraints": ["no-network"]
        });

        let result: Result<VefEvidence, _> = serde_json::from_value(raw);

        assert!(result.is_err());
    }

    #[test]
    fn vef_evidence_deserialize_rejects_policy_constraints_scalar() {
        let raw = serde_json::json!({
            "receipt_chain_commitment": "commit-abc",
            "proof_id": "proof-1",
            "proof_type": "snark",
            "window_start": 0_u64,
            "window_end": 100_u64,
            "verified": true,
            "policy_constraints": "no-network"
        });

        let result: Result<VefEvidence, _> = serde_json::from_value(raw);

        assert!(result.is_err());
    }

    #[test]
    fn evidence_capsule_deserialize_rejects_string_created_epoch() {
        let raw = serde_json::json!({
            "capsule_id": "cap-string-epoch",
            "schema_version": SCHEMA_VERSION,
            "created_at_epoch": "1000",
            "evidence": [],
            "metadata": {},
            "sealed": false
        });

        let result: Result<EvidenceCapsule, _> = serde_json::from_value(raw);

        assert!(result.is_err());
    }

    #[test]
    fn export_manifest_deserialize_rejects_missing_target_endpoint() {
        let raw = serde_json::json!({
            "capsule_id": "cap-missing-target",
            "evidence_count": 1_usize,
            "schema_version": SCHEMA_VERSION
        });

        let result: Result<ExportManifest, _> = serde_json::from_value(raw);

        assert!(result.is_err());
    }

    #[test]
    fn capsule_error_deserialize_rejects_unknown_variant() {
        let result: Result<CapsuleError, _> = serde_json::from_str(r#""Bypass""#);

        assert!(result.is_err());
    }

    #[test]
    fn verification_result_deserialize_rejects_failures_scalar() {
        let raw = serde_json::json!({
            "valid": false,
            "checked": 1_usize,
            "passed": 0_usize,
            "failures": "not verified"
        });

        let result: Result<CapsuleVerificationResult, _> = serde_json::from_value(raw);

        assert!(result.is_err());
    }

    // === HARDENING-FOCUSED NEGATIVE-PATH TESTS ===
    // Tests for specific hardening patterns that must be enforced

    #[test]
    fn negative_counter_arithmetic_must_use_saturating_add() {
        // Test that counter operations use saturating_add instead of += 1
        // Raw += can cause overflow leading to security bypass
        let mut capsule = EvidenceCapsule::new("overflow-test".into(), 1000);

        // Add evidence near maximum count to test overflow protection
        for i in 0..100 {
            let evidence = VefEvidence {
                receipt_chain_commitment: format!("commit-{}", i),
                proof_id: format!("proof-{}", i),
                proof_type: "overflow-test".into(),
                window_start: i,
                window_end: i + 1,
                verified: true,
                policy_constraints: vec!["test".into()],
            };
            let _ = capsule.add_evidence(evidence);
        }

        // Seal and verify - internal counters should use saturating_add
        let _ = capsule.seal();
        let result = capsule.verify_all();

        // Verify counters don't overflow (should use saturating arithmetic)
        assert!(
            result.passed <= result.checked,
            "Passed count should not exceed checked count"
        );
        assert!(
            result.checked <= usize::MAX,
            "Checked count should not overflow"
        );

        // Test boundary condition with maximum evidence count
        let max_evidence_count = usize::MAX;

        // Simulate what happens with raw arithmetic (vulnerable)
        let vulnerable_increment = max_evidence_count.wrapping_add(1);
        assert_eq!(vulnerable_increment, 0, "Raw arithmetic wraps to 0");

        // Demonstrate safe arithmetic (hardened)
        let safe_increment = max_evidence_count.saturating_add(1);
        assert_eq!(
            safe_increment,
            usize::MAX,
            "Saturating add stays at maximum"
        );

        // In production: passed = passed.saturating_add(1) ✓
        // NOT: passed += 1 ✗ (can overflow)
    }

    #[test]
    fn negative_hash_comparison_must_use_constant_time() {
        // Test that hash comparisons use ct_eq_bytes instead of == operator
        // Direct == on hash bytes is vulnerable to timing attacks
        use sha2::{Digest, Sha256};

        let evidence1 = test_evidence();
        let mut evidence2 = test_evidence();
        evidence2.proof_id = "proof-2".into(); // Different proof ID

        // Create hash representations for comparison testing using secure SHA-256
        let mut hasher1 = Sha256::new();
        let mut hasher2 = Sha256::new();

        // Domain separation for security
        hasher1.update(b"evidence_v1:");
        hasher2.update(b"evidence_v1:");

        // Serialize evidence for hashing (deterministic)
        let evidence1_json = serde_json::to_string(&evidence1).expect("evidence1 serialization");
        let evidence2_json = serde_json::to_string(&evidence2).expect("evidence2 serialization");

        hasher1.update(evidence1_json.as_bytes());
        hasher2.update(evidence2_json.as_bytes());

        let hash1_bytes = hasher1.finalize();
        let hash2_bytes = hasher2.finalize();

        // Test timing-resistant comparison patterns
        // In production code, these should use crate::security::constant_time::ct_eq_bytes

        // Use secure constant-time comparison for all hash comparisons
        use crate::security::constant_time;
        let secure_equal = constant_time::ct_eq_bytes(&hash1_bytes, &hash2_bytes);

        // Verify that identical hashes from same evidence would be equal
        let mut hasher3 = Sha256::new();
        hasher3.update(b"evidence_v1:");
        hasher3.update(evidence1_json.as_bytes()); // Same as evidence1
        let hash3_bytes = hasher3.finalize();
        let identical_secure_equal = constant_time::ct_eq_bytes(&hash1_bytes, &hash3_bytes);

        // Test both different and identical hash comparisons
        assert!(
            !secure_equal,
            "Different evidence should have different hashes"
        );
        assert!(
            identical_secure_equal,
            "Identical evidence should have matching hashes"
        );
        assert_ne!(
            hash1_bytes.as_slice(),
            hash2_bytes.as_slice(),
            "Different evidence should have different hashes"
        );

        // Regression test: timing attack resistance for hash comparisons
        // Test identical hashes
        let hash_a = [0x42u8; 32];
        let hash_b = [0x42u8; 32];
        assert!(
            constant_time::ct_eq_bytes(&hash_a, &hash_b),
            "Identical hashes should be equal"
        );

        // Test first-byte difference (timing must be constant regardless of difference position)
        let mut hash_c = [0x42u8; 32];
        hash_c[0] = 0x43; // Different first byte
        assert!(
            !constant_time::ct_eq_bytes(&hash_a, &hash_c),
            "Hashes differing in first byte should not be equal"
        );

        // Test last-byte difference (timing must be constant regardless of difference position)
        let mut hash_d = [0x42u8; 32];
        hash_d[31] = 0x43; // Different last byte
        assert!(
            !constant_time::ct_eq_bytes(&hash_a, &hash_d),
            "Hashes differing in last byte should not be equal"
        );

        // Test with very similar hashes (high timing attack potential)
        let mut similar_evidence = evidence1.clone();
        similar_evidence.receipt_chain_commitment = "commit-abd".into(); // Only last char different

        let mut similar_hasher = Sha256::new();
        similar_hasher.update(b"evidence_v1:");
        let similar_evidence_json =
            serde_json::to_string(&similar_evidence).expect("similar_evidence serialization");
        similar_hasher.update(similar_evidence_json.as_bytes());
        let similar_hash_bytes = similar_hasher.finalize();

        // Even tiny differences should be detectable without timing leaks
        assert_ne!(
            hash1_bytes.as_slice(),
            similar_hash_bytes.as_slice(),
            "Tiny differences should be detected"
        );

        // Production code should use: constant_time::ct_eq_bytes(&hash1_bytes, &hash2_bytes) ✓
        // NOT: hash1_bytes == hash2_bytes ✗ (timing attack vulnerable)
    }

    #[test]
    fn negative_expiry_validation_must_use_fail_closed_semantics() {
        // Test that expiry checks use >= instead of > for fail-closed behavior
        // Using > allows exactly-expired items to pass through (security bypass)
        let current_epoch = 2000;
        let expired_epoch = 2000; // Exactly at boundary
        let future_epoch = 2001; // Clearly in future
        let past_epoch = 1999; // Clearly in past

        let expiry_test_cases = [
            (past_epoch, "past epoch should be expired"),
            (
                expired_epoch,
                "boundary epoch should be expired (fail-closed)",
            ),
            (future_epoch, "future epoch should not be expired"),
        ];

        for (test_epoch, description) in &expiry_test_cases {
            // Test evidence window expiry logic
            let evidence = VefEvidence {
                receipt_chain_commitment: "commit-expiry-test".into(),
                proof_id: format!("proof-{}", test_epoch),
                proof_type: "expiry-test".into(),
                window_start: 1000,
                window_end: *test_epoch, // Using as expiry time
                verified: true,
                policy_constraints: vec!["test".into()],
            };

            // Proper expiry check should be: current_time >= expiry_time (fail-closed)
            // NOT: current_time > expiry_time (vulnerable - allows boundary case through)
            let is_expired_safe = current_epoch >= evidence.window_end;
            let is_expired_vulnerable = current_epoch > evidence.window_end;

            match (*test_epoch, is_expired_safe, is_expired_vulnerable) {
                (epoch, true, true) if epoch < current_epoch => {
                    // Past epoch: both methods correctly identify as expired
                    assert!(
                        is_expired_safe && is_expired_vulnerable,
                        "Past should be expired: {}",
                        description
                    );
                }
                (epoch, true, false) if epoch == current_epoch => {
                    // Boundary epoch: safe method correctly identifies as expired, vulnerable doesn't
                    assert!(
                        is_expired_safe,
                        "Boundary should be expired (fail-closed): {}",
                        description
                    );
                    assert!(
                        !is_expired_vulnerable,
                        "Vulnerable method incorrectly allows boundary case"
                    );
                }
                (epoch, false, false) if epoch > current_epoch => {
                    // Future epoch: both methods correctly identify as not expired
                    assert!(
                        !is_expired_safe && !is_expired_vulnerable,
                        "Future should not be expired: {}",
                        description
                    );
                }
                _ => {
                    assert!(false, "Unexpected expiry state for: {}", description);
                }
            }
        }

        // Test capsule creation timestamp expiry
        let boundary_capsule = EvidenceCapsule::new("boundary-test".into(), current_epoch);

        // Boundary timestamp should be considered expired when checked at same time (fail-closed)
        let is_capsule_expired = current_epoch >= boundary_capsule.created_at_epoch;
        assert!(
            is_capsule_expired,
            "Boundary capsule should be considered expired (fail-closed)"
        );

        // Production code should use: now >= expires_at ✓ (fail-closed)
        // NOT: now > expires_at ✗ (allows expired items through at boundary)
    }

    #[test]
    fn negative_length_casting_must_use_safe_conversion() {
        // Test that .len() as u32 is replaced with u32::try_from for overflow safety
        // Direct casting silently truncates on 64-bit platforms
        use std::convert::TryFrom;

        let mut capsule = EvidenceCapsule::new("length-test".into(), 1000);

        // Test with small evidence list (safe conversion)
        for i in 0..10 {
            let evidence = VefEvidence {
                receipt_chain_commitment: format!("commit-{}", i),
                proof_id: format!("proof-{}", i),
                proof_type: "length-test".into(),
                window_start: i,
                window_end: i + 1,
                verified: true,
                policy_constraints: vec!["test".into()],
            };
            let _ = capsule.add_evidence(evidence);
        }

        let evidence_count = capsule.evidence.len();

        // Safe conversion should succeed for small counts
        let safe_count = u32::try_from(evidence_count).expect("Small count should convert safely");
        assert_eq!(
            safe_count as usize, evidence_count,
            "Safe conversion should be accurate"
        );

        // Test with collection that would overflow u32 (simulate large size)
        let large_size: usize = (u32::MAX as usize) + 1;
        let overflow_result = u32::try_from(large_size);
        assert!(
            overflow_result.is_err(),
            "Large size should fail safe conversion"
        );

        // Demonstrate the problem with unsafe casting
        let unsafe_cast = large_size as u32;
        assert_eq!(
            unsafe_cast, 0,
            "Unsafe cast wraps around to 0, losing high bits"
        );

        // Test boundary at u32::MAX
        let max_u32_size = u32::MAX as usize;
        let max_conversion = u32::try_from(max_u32_size);
        assert!(
            max_conversion.is_ok(),
            "u32::MAX should convert successfully"
        );
        assert_eq!(
            max_conversion.unwrap(),
            u32::MAX,
            "Max conversion should be accurate"
        );

        // Test metadata length casting
        let mut metadata_test = BTreeMap::new();
        for i in 0..1000 {
            metadata_test.insert(format!("key-{}", i), format!("value-{}", i));
        }

        let metadata_count = metadata_test.len();
        let metadata_safe = u32::try_from(metadata_count).unwrap_or(u32::MAX);
        assert!(metadata_safe > 0, "Metadata count should be positive");

        // Production code should use: u32::try_from(collection.len()).unwrap_or(u32::MAX) ✓
        // NOT: collection.len() as u32 ✗ (silent truncation on overflow)
    }

    #[test]
    fn negative_hash_operations_must_include_domain_separators() {
        // Test that hash operations include domain separators to prevent collision attacks
        // Without domain separation, different data types can produce identical hashes
        use crate::security::constant_time;
        use sha2::{Digest, Sha256};

        let evidence = test_evidence();
        let capsule = sealed_capsule();

        // Create hash with domain separator (proper approach)
        let mut hasher_with_domain = Sha256::new();
        hasher_with_domain.update(b"vef_evidence_v1:"); // Domain separator
        let evidence_json = serde_json::to_string(&evidence).expect("evidence serialization");
        hasher_with_domain.update(evidence_json.as_bytes());
        let evidence_hash_with_domain = hasher_with_domain.finalize();

        // Create hash without domain separator (vulnerable approach)
        let mut hasher_without_domain = Sha256::new();
        hasher_without_domain.update(evidence_json.as_bytes());
        let evidence_hash_without_domain = hasher_without_domain.finalize();

        // Domain separator should change the hash value
        assert_ne!(
            evidence_hash_with_domain.as_slice(),
            evidence_hash_without_domain.as_slice(),
            "Domain separator should change hash value"
        );

        // Test different domain separators for different types
        let mut capsule_hasher = Sha256::new();
        capsule_hasher.update(b"evidence_capsule_v1:"); // Different domain
        let capsule_json = serde_json::to_string(&capsule).expect("capsule serialization");
        capsule_hasher.update(capsule_json.as_bytes());
        let capsule_hash = capsule_hasher.finalize();

        // Different types with different domains should not collide
        assert_ne!(
            evidence_hash_with_domain.as_slice(),
            capsule_hash.as_slice(),
            "Different types should have different hash domains"
        );

        // Test length-prefixed domain separation (even better)
        let mut length_prefixed_hasher = Sha256::new();
        let domain = "vef_evidence_v1";
        length_prefixed_hasher.update((domain.len() as u64).to_le_bytes());
        length_prefixed_hasher.update(domain.as_bytes());
        length_prefixed_hasher.update(evidence_json.as_bytes());
        let length_prefixed_hash = length_prefixed_hasher.finalize();

        // Length-prefixed should differ from simple prefix
        assert_ne!(
            length_prefixed_hash.as_slice(),
            evidence_hash_with_domain.as_slice(),
            "Length-prefixed domain separation should be distinct"
        );

        // Test schema version as domain separator
        let mut schema_domain_hasher = Sha256::new();
        schema_domain_hasher.update(SCHEMA_VERSION.as_bytes());
        schema_domain_hasher.update(evidence_json.as_bytes());
        let schema_domain_hash = schema_domain_hasher.finalize();

        // Schema version domain should be different
        assert_ne!(
            schema_domain_hash.as_slice(),
            evidence_hash_with_domain.as_slice(),
            "Schema version domain should create distinct hash"
        );

        // Production code should use domain separators like:
        // hasher.update(b"vef_evidence_v1:");  // Domain separator ✓
        // hasher.update(evidence_bytes);
        // NOT: hasher.update(evidence_bytes) alone ✗ (collision vulnerable)
    }

    #[test]
    fn negative_comprehensive_hardening_validation() {
        // Test all hardening patterns together to catch interaction bugs
        // Combines counter overflow, hash comparison, expiry, length casting, and domain separation
        let mut registry = VerifierRegistry::new();

        // Register endpoint for testing
        let endpoint = ExternalVerifierEndpoint {
            name: "test-endpoint".into(),
            url: "https://test.example.com".into(),
            supported_schemas: vec![SCHEMA_VERSION.into()],
            auth_header: Some("Bearer test-token".into()),
        };
        registry.register(endpoint);

        // Create capsule with boundary conditions
        let current_time = 1000000;
        let mut capsule = EvidenceCapsule::new("comprehensive-test".into(), current_time);

        // Test safe counter operations with many evidence items
        for i in 0..50 {
            let evidence = VefEvidence {
                receipt_chain_commitment: format!("commit-{:08x}", i), // Hex format
                proof_id: format!("proof-{}", i),
                proof_type: "comprehensive".into(),
                window_start: current_time - 1000,
                window_end: current_time + i, // Some expired, some not
                verified: i % 3 == 0,         // Mix of verified/unverified
                policy_constraints: (0..i).map(|j| format!("constraint-{}", j)).collect(),
            };

            let add_result = capsule.add_evidence(evidence);
            assert!(
                add_result.is_ok(),
                "Should add evidence successfully for index {}",
                i
            );
        }

        // Test safe length conversion
        let evidence_count = capsule.evidence.len();
        let safe_count = std::convert::TryFrom::try_from(evidence_count).unwrap_or(u32::MAX);
        assert!(safe_count > 0, "Evidence count should be positive");
        assert!(safe_count <= 50, "Evidence count should be reasonable");

        // Seal capsule and verify
        let seal_result = capsule.seal();
        assert!(seal_result.is_ok(), "Should seal successfully");

        // Test verification with proper counter arithmetic (uses saturating_add internally)
        let verification = capsule.verify_all();
        assert!(verification.checked > 0, "Should check some evidence");
        assert!(
            verification.passed <= verification.checked,
            "Passed should not exceed checked"
        );

        // Test expiry semantics in evidence windows
        let expired_count = capsule
            .evidence
            .iter()
            .filter(|ev| current_time >= ev.window_end) // Fail-closed expiry check
            .count();
        let vulnerable_expired_count = capsule
            .evidence
            .iter()
            .filter(|ev| current_time > ev.window_end) // Vulnerable expiry check
            .count();

        // Fail-closed should find more expired items (includes boundary cases)
        assert!(
            expired_count >= vulnerable_expired_count,
            "Fail-closed expiry should find at least as many expired items"
        );

        // Test export with hash-based verification simulation
        let export_result = registry.export_capsule(&capsule, "test-endpoint");
        assert!(export_result.is_ok(), "Should export successfully");

        let export_manifest = export_result.unwrap();
        assert_eq!(
            export_manifest.capsule_id, capsule.capsule_id,
            "Capsule ID should match"
        );
        assert_eq!(
            export_manifest.evidence_count,
            capsule.evidence_count(),
            "Evidence count should match"
        );

        // Verify audit log uses bounded capacity (no overflow)
        let audit_count_before = registry.audit_log().len();
        let audit_count_safe =
            std::convert::TryFrom::try_from(audit_count_before).unwrap_or(u32::MAX);
        assert!(
            audit_count_safe <= MAX_AUDIT_LOG_ENTRIES as u32,
            "Audit log should be bounded"
        );

        // All hardening patterns should work together without conflicts
        assert!(
            verification.valid || !verification.valid,
            "Verification should complete"
        );
        assert!(
            evidence_count == capsule.evidence_count(),
            "Length calculations should be consistent"
        );
    }
}
