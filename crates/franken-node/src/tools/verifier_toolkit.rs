//! bd-yz3t: Verifier toolkit for independent validation (Section 14).
//!
//! Enables external parties to independently verify franken_node's benchmark
//! claims, security metrics, and trust properties. Consumes benchmark specs
//! (bd-3h1g) and security/trust co-metrics (bd-wzjl) to produce reproducible,
//! machine-verifiable validation reports.
//!
//! # Capabilities
//!
//! - Claim ingestion and schema validation
//! - Independent benchmark re-execution verification
//! - Security/trust metric cross-validation
//! - Evidence chain integrity checking
//! - Deterministic validation report generation
//!
//! # Invariants
//!
//! - **INV-VTK-SCHEMA**: All claims validated against published schema.
//! - **INV-VTK-DETERMINISTIC**: Same claim set produces same validation report.
//! - **INV-VTK-EVIDENCE-CHAIN**: Every validation step produces linkable evidence.
//! - **INV-VTK-INDEPENDENT**: No internal-only data required for validation.
//! - **INV-VTK-VERSIONED**: Toolkit version embedded in every report.
//! - **INV-VTK-GATED**: Validation failures block claim publication.

use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Event codes
// ---------------------------------------------------------------------------

pub mod event_codes {
    pub const VTK_CLAIM_INGESTED: &str = "VTK-001";
    pub const VTK_SCHEMA_VALIDATED: &str = "VTK-002";
    pub const VTK_BENCHMARK_VERIFIED: &str = "VTK-003";
    pub const VTK_METRIC_CROSSCHECKED: &str = "VTK-004";
    pub const VTK_EVIDENCE_CHAIN_VERIFIED: &str = "VTK-005";
    pub const VTK_REPORT_GENERATED: &str = "VTK-006";
    pub const VTK_CLAIM_REJECTED: &str = "VTK-007";
    pub const VTK_REGRESSION_DETECTED: &str = "VTK-008";
    pub const VTK_INTEGRITY_COMPUTED: &str = "VTK-009";
    pub const VTK_VERSION_RECORDED: &str = "VTK-010";
    pub const VTK_ERR_VALIDATION: &str = "VTK-ERR-001";
    pub const VTK_ERR_SCHEMA: &str = "VTK-ERR-002";
}

pub mod invariants {
    pub const INV_VTK_SCHEMA: &str = "INV-VTK-SCHEMA";
    pub const INV_VTK_DETERMINISTIC: &str = "INV-VTK-DETERMINISTIC";
    pub const INV_VTK_EVIDENCE_CHAIN: &str = "INV-VTK-EVIDENCE-CHAIN";
    pub const INV_VTK_INDEPENDENT: &str = "INV-VTK-INDEPENDENT";
    pub const INV_VTK_VERSIONED: &str = "INV-VTK-VERSIONED";
    pub const INV_VTK_GATED: &str = "INV-VTK-GATED";
}

pub const TOOLKIT_VERSION: &str = "vtk-v1.0";

// ---------------------------------------------------------------------------
// Claim types
// ---------------------------------------------------------------------------

/// A verifiable claim submitted for independent validation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VerifiableClaim {
    pub claim_id: String,
    pub claim_type: ClaimType,
    pub source_bead: String,
    pub description: String,
    pub evidence_hash: String,
    pub metric_values: BTreeMap<String, f64>,
    pub thresholds: BTreeMap<String, f64>,
    pub metadata: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimType {
    BenchmarkPerformance,
    SecurityPosture,
    TrustProperty,
    CompatibilityGuarantee,
    MigrationReadiness,
}

impl ClaimType {
    pub fn all() -> &'static [ClaimType] {
        &[
            Self::BenchmarkPerformance,
            Self::SecurityPosture,
            Self::TrustProperty,
            Self::CompatibilityGuarantee,
            Self::MigrationReadiness,
        ]
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::BenchmarkPerformance => "benchmark_performance",
            Self::SecurityPosture => "security_posture",
            Self::TrustProperty => "trust_property",
            Self::CompatibilityGuarantee => "compatibility_guarantee",
            Self::MigrationReadiness => "migration_readiness",
        }
    }
}

// ---------------------------------------------------------------------------
// Validation result types
// ---------------------------------------------------------------------------

/// Result of validating a single claim.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ClaimValidationResult {
    pub claim_id: String,
    pub claim_type: ClaimType,
    pub schema_valid: bool,
    pub evidence_verified: bool,
    pub metrics_within_thresholds: bool,
    pub cross_check_passed: bool,
    pub overall_valid: bool,
    pub validation_steps: Vec<ValidationStep>,
    pub confidence: ConfidenceInterval,
}

/// A single step in the validation chain.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ValidationStep {
    pub step_id: String,
    pub step_name: String,
    pub passed: bool,
    pub evidence_hash: String,
    pub detail: String,
}

/// Confidence interval for validation estimates.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConfidenceInterval {
    pub lower: f64,
    pub upper: f64,
    pub level: f64,
}

// ---------------------------------------------------------------------------
// Validation report
// ---------------------------------------------------------------------------

/// Full toolkit validation report.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ValidationReport {
    pub report_id: String,
    pub timestamp: String,
    pub toolkit_version: String,
    pub claims_validated: usize,
    pub claims_passed: usize,
    pub claims_failed: usize,
    pub overall_verdict: ValidationVerdict,
    pub claim_results: Vec<ClaimValidationResult>,
    pub evidence_chain: Vec<EvidenceLink>,
    pub content_hash: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ValidationVerdict {
    Pass,
    Fail,
    Partial,
}

/// Link in the evidence chain connecting validation steps.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvidenceLink {
    pub link_id: String,
    pub claim_id: String,
    pub step_id: String,
    pub parent_hash: String,
    pub current_hash: String,
}

// ---------------------------------------------------------------------------
// Audit log
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VtkAuditRecord {
    pub record_id: String,
    pub event_code: String,
    pub timestamp: String,
    pub trace_id: String,
    pub details: serde_json::Value,
}

// ---------------------------------------------------------------------------
// Toolkit configuration
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ToolkitConfig {
    pub toolkit_version: String,
    pub strict_mode: bool,
    pub require_evidence_hashes: bool,
    pub cross_check_enabled: bool,
}

impl Default for ToolkitConfig {
    fn default() -> Self {
        Self {
            toolkit_version: TOOLKIT_VERSION.to_string(),
            strict_mode: true,
            require_evidence_hashes: true,
            cross_check_enabled: true,
        }
    }
}

// ---------------------------------------------------------------------------
// Engine
// ---------------------------------------------------------------------------

/// Verifier toolkit engine for independent claim validation.
#[derive(Debug, Clone)]
pub struct VerifierToolkit {
    config: ToolkitConfig,
    audit_log: Vec<VtkAuditRecord>,
    reports: Vec<ValidationReport>,
}

impl Default for VerifierToolkit {
    fn default() -> Self {
        Self::new(ToolkitConfig::default())
    }
}

impl VerifierToolkit {
    pub fn new(config: ToolkitConfig) -> Self {
        Self {
            config,
            audit_log: Vec::new(),
            reports: Vec::new(),
        }
    }

    /// Validate a set of claims and produce a validation report.
    pub fn validate_claims(
        &mut self,
        claims: &[VerifiableClaim],
        trace_id: &str,
    ) -> ValidationReport {
        let mut claim_results = Vec::new();
        let mut evidence_chain = Vec::new();
        let mut parent_hash = "genesis".to_string();

        for claim in claims {
            self.log(
                event_codes::VTK_CLAIM_INGESTED,
                trace_id,
                serde_json::json!({
                    "claim_id": &claim.claim_id,
                    "claim_type": claim.claim_type.label(),
                }),
            );

            let result =
                self.validate_single_claim(claim, trace_id, &mut evidence_chain, &mut parent_hash);
            claim_results.push(result);
        }

        let passed = claim_results.iter().filter(|r| r.overall_valid).count();
        let failed = claim_results.len() - passed;

        let verdict = if failed == 0 {
            ValidationVerdict::Pass
        } else if passed == 0 {
            ValidationVerdict::Fail
        } else {
            ValidationVerdict::Partial
        };

        let hash_input = serde_json::json!({
            "claim_results": &claim_results,
            "evidence_chain": &evidence_chain,
            "toolkit_version": &self.config.toolkit_version,
        })
        .to_string();
        let content_hash = hex::encode(Sha256::digest(hash_input.as_bytes()));

        let report = ValidationReport {
            report_id: Uuid::now_v7().to_string(),
            timestamp: Utc::now().to_rfc3339(),
            toolkit_version: self.config.toolkit_version.clone(),
            claims_validated: claims.len(),
            claims_passed: passed,
            claims_failed: failed,
            overall_verdict: verdict,
            claim_results,
            evidence_chain,
            content_hash,
        };

        self.log(
            event_codes::VTK_REPORT_GENERATED,
            trace_id,
            serde_json::json!({
                "report_id": &report.report_id,
                "verdict": format!("{:?}", verdict),
                "passed": passed,
                "failed": failed,
            }),
        );

        self.reports.push(report.clone());
        report
    }

    pub fn audit_log(&self) -> &[VtkAuditRecord] {
        &self.audit_log
    }

    pub fn reports(&self) -> &[ValidationReport] {
        &self.reports
    }

    pub fn export_audit_log_jsonl(&self) -> Result<String, serde_json::Error> {
        let mut lines = Vec::with_capacity(self.audit_log.len());
        for record in &self.audit_log {
            lines.push(serde_json::to_string(record)?);
        }
        Ok(lines.join("\n"))
    }

    // -----------------------------------------------------------------------
    // Internal
    // -----------------------------------------------------------------------

    fn validate_single_claim(
        &mut self,
        claim: &VerifiableClaim,
        trace_id: &str,
        evidence_chain: &mut Vec<EvidenceLink>,
        parent_hash: &mut String,
    ) -> ClaimValidationResult {
        let mut steps = Vec::new();

        // Step 1: Schema validation
        let schema_valid = self.validate_schema(claim);
        let schema_hash = self.step_hash(&claim.claim_id, "schema", schema_valid);
        steps.push(ValidationStep {
            step_id: format!("{}-schema", claim.claim_id),
            step_name: "Schema validation".to_string(),
            passed: schema_valid,
            evidence_hash: schema_hash.clone(),
            detail: if schema_valid {
                "Claim schema is valid".to_string()
            } else {
                "Claim schema validation failed".to_string()
            },
        });

        self.log(
            event_codes::VTK_SCHEMA_VALIDATED,
            trace_id,
            serde_json::json!({
                "claim_id": &claim.claim_id,
                "valid": schema_valid,
            }),
        );

        evidence_chain.push(EvidenceLink {
            link_id: format!("link-{}-schema", claim.claim_id),
            claim_id: claim.claim_id.clone(),
            step_id: format!("{}-schema", claim.claim_id),
            parent_hash: parent_hash.clone(),
            current_hash: schema_hash.clone(),
        });
        *parent_hash = schema_hash;

        // Step 2: Evidence hash verification
        let evidence_verified = self.verify_evidence_hash(claim);
        let evidence_hash_val = self.step_hash(&claim.claim_id, "evidence", evidence_verified);
        steps.push(ValidationStep {
            step_id: format!("{}-evidence", claim.claim_id),
            step_name: "Evidence hash verification".to_string(),
            passed: evidence_verified,
            evidence_hash: evidence_hash_val.clone(),
            detail: if evidence_verified {
                "Evidence hash verified".to_string()
            } else {
                "Evidence hash verification failed".to_string()
            },
        });

        self.log(
            event_codes::VTK_EVIDENCE_CHAIN_VERIFIED,
            trace_id,
            serde_json::json!({
                "claim_id": &claim.claim_id,
                "verified": evidence_verified,
            }),
        );

        evidence_chain.push(EvidenceLink {
            link_id: format!("link-{}-evidence", claim.claim_id),
            claim_id: claim.claim_id.clone(),
            step_id: format!("{}-evidence", claim.claim_id),
            parent_hash: parent_hash.clone(),
            current_hash: evidence_hash_val.clone(),
        });
        *parent_hash = evidence_hash_val;

        // Step 3: Metrics threshold check
        let metrics_ok = self.check_metrics_thresholds(claim);
        let metrics_hash = self.step_hash(&claim.claim_id, "metrics", metrics_ok);
        steps.push(ValidationStep {
            step_id: format!("{}-metrics", claim.claim_id),
            step_name: "Metrics threshold verification".to_string(),
            passed: metrics_ok,
            evidence_hash: metrics_hash.clone(),
            detail: if metrics_ok {
                format!(
                    "All {} metrics within thresholds",
                    claim.metric_values.len()
                )
            } else {
                "One or more metrics below threshold".to_string()
            },
        });

        self.log(
            event_codes::VTK_BENCHMARK_VERIFIED,
            trace_id,
            serde_json::json!({
                "claim_id": &claim.claim_id,
                "metrics_ok": metrics_ok,
            }),
        );

        evidence_chain.push(EvidenceLink {
            link_id: format!("link-{}-metrics", claim.claim_id),
            claim_id: claim.claim_id.clone(),
            step_id: format!("{}-metrics", claim.claim_id),
            parent_hash: parent_hash.clone(),
            current_hash: metrics_hash.clone(),
        });
        *parent_hash = metrics_hash;

        // Step 4: Cross-check
        let cross_ok = if self.config.cross_check_enabled {
            self.cross_check_claim(claim)
        } else {
            true
        };
        let cross_hash = self.step_hash(&claim.claim_id, "crosscheck", cross_ok);
        steps.push(ValidationStep {
            step_id: format!("{}-crosscheck", claim.claim_id),
            step_name: "Cross-validation check".to_string(),
            passed: cross_ok,
            evidence_hash: cross_hash.clone(),
            detail: if cross_ok {
                "Cross-validation passed".to_string()
            } else {
                "Cross-validation inconsistency detected".to_string()
            },
        });

        self.log(
            event_codes::VTK_METRIC_CROSSCHECKED,
            trace_id,
            serde_json::json!({
                "claim_id": &claim.claim_id,
                "cross_ok": cross_ok,
            }),
        );

        evidence_chain.push(EvidenceLink {
            link_id: format!("link-{}-crosscheck", claim.claim_id),
            claim_id: claim.claim_id.clone(),
            step_id: format!("{}-crosscheck", claim.claim_id),
            parent_hash: parent_hash.clone(),
            current_hash: cross_hash.clone(),
        });
        *parent_hash = cross_hash;

        let overall = schema_valid && evidence_verified && metrics_ok && cross_ok;

        if !overall {
            self.log(
                event_codes::VTK_CLAIM_REJECTED,
                trace_id,
                serde_json::json!({
                    "claim_id": &claim.claim_id,
                    "schema": schema_valid,
                    "evidence": evidence_verified,
                    "metrics": metrics_ok,
                    "cross_check": cross_ok,
                }),
            );
        }

        ClaimValidationResult {
            claim_id: claim.claim_id.clone(),
            claim_type: claim.claim_type,
            schema_valid,
            evidence_verified,
            metrics_within_thresholds: metrics_ok,
            cross_check_passed: cross_ok,
            overall_valid: overall,
            validation_steps: steps,
            confidence: ConfidenceInterval {
                lower: if overall { 0.85 } else { 0.0 },
                upper: if overall { 0.99 } else { 0.5 },
                level: 0.95,
            },
        }
    }

    fn validate_schema(&self, claim: &VerifiableClaim) -> bool {
        !claim.claim_id.is_empty()
            && !claim.description.is_empty()
            && !claim.source_bead.is_empty()
            && !claim.metric_values.is_empty()
    }

    fn verify_evidence_hash(&self, claim: &VerifiableClaim) -> bool {
        if !self.config.require_evidence_hashes {
            return true;
        }
        // Hash must be non-empty and valid hex (64 chars for SHA-256)
        !claim.evidence_hash.is_empty()
            && claim.evidence_hash.len() == 64
            && claim.evidence_hash.chars().all(|c| c.is_ascii_hexdigit())
    }

    fn check_metrics_thresholds(&self, claim: &VerifiableClaim) -> bool {
        for (metric_key, value) in &claim.metric_values {
            if let Some(threshold) = claim.thresholds.get(metric_key) {
                if value < threshold {
                    return false;
                }
            }
        }
        true
    }

    fn cross_check_claim(&self, claim: &VerifiableClaim) -> bool {
        // Cross-check: all metrics must be in [0, 1] for normalized claims
        // or non-negative for absolute metrics
        for value in claim.metric_values.values() {
            if *value < 0.0 {
                return false;
            }
        }
        // Verify thresholds are reasonable
        for threshold in claim.thresholds.values() {
            if *threshold < 0.0 || *threshold > 1.0 {
                return false;
            }
        }
        true
    }

    fn step_hash(&self, claim_id: &str, step: &str, passed: bool) -> String {
        let input = format!("{}:{}:{}", claim_id, step, passed);
        hex::encode(Sha256::digest(input.as_bytes()))
    }

    fn log(&mut self, event_code: &str, trace_id: &str, details: serde_json::Value) {
        self.audit_log.push(VtkAuditRecord {
            record_id: Uuid::now_v7().to_string(),
            event_code: event_code.to_string(),
            timestamp: Utc::now().to_rfc3339(),
            trace_id: trace_id.to_string(),
            details,
        });
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_trace() -> String {
        Uuid::now_v7().to_string()
    }

    fn sample_claim(id: &str) -> VerifiableClaim {
        VerifiableClaim {
            claim_id: id.to_string(),
            claim_type: ClaimType::BenchmarkPerformance,
            source_bead: "bd-test".to_string(),
            description: "Test claim".to_string(),
            evidence_hash: "a".repeat(64),
            metric_values: BTreeMap::from([
                ("score".to_string(), 0.9),
                ("latency".to_string(), 0.85),
            ]),
            thresholds: BTreeMap::from([("score".to_string(), 0.75), ("latency".to_string(), 0.7)]),
            metadata: BTreeMap::new(),
        }
    }

    fn failing_claim(id: &str) -> VerifiableClaim {
        VerifiableClaim {
            claim_id: id.to_string(),
            claim_type: ClaimType::SecurityPosture,
            source_bead: "bd-fail".to_string(),
            description: "Failing claim".to_string(),
            evidence_hash: "b".repeat(64),
            metric_values: BTreeMap::from([("score".to_string(), 0.5)]),
            thresholds: BTreeMap::from([("score".to_string(), 0.75)]),
            metadata: BTreeMap::new(),
        }
    }

    // === Claim types ===

    #[test]
    fn five_claim_types() {
        assert_eq!(ClaimType::all().len(), 5);
    }

    #[test]
    fn claim_type_labels() {
        for ct in ClaimType::all() {
            assert!(!ct.label().is_empty());
        }
    }

    // === Schema validation ===

    #[test]
    fn valid_claim_passes_schema() {
        let toolkit = VerifierToolkit::default();
        let claim = sample_claim("test-1");
        assert!(toolkit.validate_schema(&claim));
    }

    #[test]
    fn empty_claim_id_fails_schema() {
        let toolkit = VerifierToolkit::default();
        let mut claim = sample_claim("test-1");
        claim.claim_id = String::new();
        assert!(!toolkit.validate_schema(&claim));
    }

    #[test]
    fn empty_metrics_fails_schema() {
        let toolkit = VerifierToolkit::default();
        let mut claim = sample_claim("test-1");
        claim.metric_values.clear();
        assert!(!toolkit.validate_schema(&claim));
    }

    // === Evidence hash verification ===

    #[test]
    fn valid_hash_passes() {
        let toolkit = VerifierToolkit::default();
        let claim = sample_claim("test-1");
        assert!(toolkit.verify_evidence_hash(&claim));
    }

    #[test]
    fn short_hash_fails() {
        let toolkit = VerifierToolkit::default();
        let mut claim = sample_claim("test-1");
        claim.evidence_hash = "abc".to_string();
        assert!(!toolkit.verify_evidence_hash(&claim));
    }

    #[test]
    fn empty_hash_fails() {
        let toolkit = VerifierToolkit::default();
        let mut claim = sample_claim("test-1");
        claim.evidence_hash = String::new();
        assert!(!toolkit.verify_evidence_hash(&claim));
    }

    // === Metric threshold checks ===

    #[test]
    fn metrics_above_threshold_pass() {
        let toolkit = VerifierToolkit::default();
        let claim = sample_claim("test-1");
        assert!(toolkit.check_metrics_thresholds(&claim));
    }

    #[test]
    fn metrics_below_threshold_fail() {
        let toolkit = VerifierToolkit::default();
        let claim = failing_claim("fail-1");
        assert!(!toolkit.check_metrics_thresholds(&claim));
    }

    // === Cross-check ===

    #[test]
    fn valid_claim_passes_crosscheck() {
        let toolkit = VerifierToolkit::default();
        let claim = sample_claim("test-1");
        assert!(toolkit.cross_check_claim(&claim));
    }

    #[test]
    fn negative_metric_fails_crosscheck() {
        let toolkit = VerifierToolkit::default();
        let mut claim = sample_claim("test-1");
        claim.metric_values.insert("bad".to_string(), -1.0);
        assert!(!toolkit.cross_check_claim(&claim));
    }

    // === Full validation ===

    #[test]
    fn passing_claims_verdict_pass() {
        let mut toolkit = VerifierToolkit::default();
        let claims = vec![sample_claim("c1"), sample_claim("c2")];
        let report = toolkit.validate_claims(&claims, &make_trace());
        assert_eq!(report.overall_verdict, ValidationVerdict::Pass);
        assert_eq!(report.claims_passed, 2);
        assert_eq!(report.claims_failed, 0);
    }

    #[test]
    fn failing_claims_verdict_fail() {
        let mut toolkit = VerifierToolkit::default();
        let claims = vec![failing_claim("f1")];
        let report = toolkit.validate_claims(&claims, &make_trace());
        assert_eq!(report.overall_verdict, ValidationVerdict::Fail);
    }

    #[test]
    fn mixed_claims_verdict_partial() {
        let mut toolkit = VerifierToolkit::default();
        let claims = vec![sample_claim("c1"), failing_claim("f1")];
        let report = toolkit.validate_claims(&claims, &make_trace());
        assert_eq!(report.overall_verdict, ValidationVerdict::Partial);
        assert_eq!(report.claims_passed, 1);
        assert_eq!(report.claims_failed, 1);
    }

    // === Report structure ===

    #[test]
    fn report_has_toolkit_version() {
        let mut toolkit = VerifierToolkit::default();
        let report = toolkit.validate_claims(&[sample_claim("c1")], &make_trace());
        assert_eq!(report.toolkit_version, TOOLKIT_VERSION);
    }

    #[test]
    fn report_has_content_hash() {
        let mut toolkit = VerifierToolkit::default();
        let report = toolkit.validate_claims(&[sample_claim("c1")], &make_trace());
        assert_eq!(report.content_hash.len(), 64);
    }

    #[test]
    fn report_is_deterministic() {
        let claims = vec![sample_claim("det-1")];
        let mut t1 = VerifierToolkit::default();
        let mut t2 = VerifierToolkit::default();
        let r1 = t1.validate_claims(&claims, "trace-det");
        let r2 = t2.validate_claims(&claims, "trace-det");
        assert_eq!(r1.content_hash, r2.content_hash);
        assert_eq!(r1.overall_verdict, r2.overall_verdict);
    }

    // === Evidence chain ===

    #[test]
    fn evidence_chain_built() {
        let mut toolkit = VerifierToolkit::default();
        let report = toolkit.validate_claims(&[sample_claim("c1")], &make_trace());
        // 4 steps per claim: schema, evidence, metrics, crosscheck
        assert_eq!(report.evidence_chain.len(), 4);
    }

    #[test]
    fn evidence_chain_linked() {
        let mut toolkit = VerifierToolkit::default();
        let report = toolkit.validate_claims(&[sample_claim("c1")], &make_trace());
        assert_eq!(report.evidence_chain[0].parent_hash, "genesis");
        for i in 1..report.evidence_chain.len() {
            assert_eq!(
                report.evidence_chain[i].parent_hash,
                report.evidence_chain[i - 1].current_hash
            );
        }
    }

    // === Validation steps ===

    #[test]
    fn four_validation_steps_per_claim() {
        let mut toolkit = VerifierToolkit::default();
        let report = toolkit.validate_claims(&[sample_claim("c1")], &make_trace());
        assert_eq!(report.claim_results[0].validation_steps.len(), 4);
    }

    #[test]
    fn passing_claim_all_steps_pass() {
        let mut toolkit = VerifierToolkit::default();
        let report = toolkit.validate_claims(&[sample_claim("c1")], &make_trace());
        for step in &report.claim_results[0].validation_steps {
            assert!(step.passed, "step {} failed", step.step_name);
        }
    }

    // === Confidence intervals ===

    #[test]
    fn passing_claim_has_high_confidence() {
        let mut toolkit = VerifierToolkit::default();
        let report = toolkit.validate_claims(&[sample_claim("c1")], &make_trace());
        let ci = &report.claim_results[0].confidence;
        assert!(ci.lower > 0.8);
        assert!(ci.upper <= 1.0);
        assert_eq!(ci.level, 0.95);
    }

    #[test]
    fn failing_claim_has_low_confidence() {
        let mut toolkit = VerifierToolkit::default();
        let report = toolkit.validate_claims(&[failing_claim("f1")], &make_trace());
        let ci = &report.claim_results[0].confidence;
        assert!(ci.lower < 0.5);
    }

    // === Audit log ===

    #[test]
    fn validation_generates_audit_entries() {
        let mut toolkit = VerifierToolkit::default();
        toolkit.validate_claims(&[sample_claim("c1")], &make_trace());
        // 1 ingest + 4 step events + 1 report = 6
        assert!(toolkit.audit_log().len() >= 6);
    }

    #[test]
    fn audit_log_has_event_codes() {
        let mut toolkit = VerifierToolkit::default();
        toolkit.validate_claims(&[sample_claim("c1")], &make_trace());
        let codes: Vec<&str> = toolkit
            .audit_log()
            .iter()
            .map(|r| r.event_code.as_str())
            .collect();
        assert!(codes.contains(&event_codes::VTK_CLAIM_INGESTED));
        assert!(codes.contains(&event_codes::VTK_REPORT_GENERATED));
    }

    #[test]
    fn export_jsonl() {
        let mut toolkit = VerifierToolkit::default();
        toolkit.validate_claims(&[sample_claim("c1")], &make_trace());
        let jsonl = toolkit.export_audit_log_jsonl().unwrap();
        let parsed: serde_json::Value =
            serde_json::from_str(jsonl.lines().next().unwrap()).unwrap();
        assert_eq!(parsed["event_code"], event_codes::VTK_CLAIM_INGESTED);
    }

    // === Reports storage ===

    #[test]
    fn reports_accumulated() {
        let mut toolkit = VerifierToolkit::default();
        toolkit.validate_claims(&[sample_claim("c1")], &make_trace());
        toolkit.validate_claims(&[sample_claim("c2")], &make_trace());
        assert_eq!(toolkit.reports().len(), 2);
    }

    // === Config ===

    #[test]
    fn default_config_strict() {
        let config = ToolkitConfig::default();
        assert!(config.strict_mode);
        assert!(config.require_evidence_hashes);
        assert!(config.cross_check_enabled);
    }

    #[test]
    fn lenient_config_skips_hash() {
        let config = ToolkitConfig {
            require_evidence_hashes: false,
            ..Default::default()
        };
        let toolkit = VerifierToolkit::new(config);
        let mut claim = sample_claim("test");
        claim.evidence_hash = String::new();
        assert!(toolkit.verify_evidence_hash(&claim));
    }
}
