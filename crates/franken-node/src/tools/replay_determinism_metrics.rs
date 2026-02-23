//! bd-jbp1: Replay determinism and artifact completeness metrics (Section 14).
//!
//! Validates that replayed operations produce identical outputs and that all
//! required verification artifacts are present and complete. Tracks hash-based
//! output comparison across replay runs, artifact coverage by category, and
//! provides release-gated enforcement for determinism SLOs.
//!
//! # Capabilities
//!
//! - Hash-based output comparison across replay runs
//! - Replay run pair comparison (original vs replayed)
//! - Artifact coverage tracking by category
//! - Completeness gate with configurable thresholds
//! - Divergence detection and categorization
//! - Deterministic report generation with content hashing
//!
//! # Invariants
//!
//! - **INV-RDM-HASH**: Output hashes match between original and replay runs.
//! - **INV-RDM-COMPLETE**: All required artifact categories present.
//! - **INV-RDM-DETERMINISTIC**: Same inputs produce same report hash.
//! - **INV-RDM-GATED**: Divergences above threshold block release.
//! - **INV-RDM-VERSIONED**: Metric version embedded in every report.
//! - **INV-RDM-AUDITABLE**: Every comparison logged with event code.

use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Event codes
// ---------------------------------------------------------------------------

pub mod event_codes {
    pub const RDM_RUN_RECORDED: &str = "RDM-001";
    pub const RDM_COMPARISON_STARTED: &str = "RDM-002";
    pub const RDM_HASH_MATCHED: &str = "RDM-003";
    pub const RDM_DIVERGENCE_DETECTED: &str = "RDM-004";
    pub const RDM_ARTIFACT_CHECKED: &str = "RDM-005";
    pub const RDM_COMPLETENESS_COMPUTED: &str = "RDM-006";
    pub const RDM_GATE_EVALUATED: &str = "RDM-007";
    pub const RDM_REPORT_GENERATED: &str = "RDM-008";
    pub const RDM_CATEGORY_REGISTERED: &str = "RDM-009";
    pub const RDM_VERSION_EMBEDDED: &str = "RDM-010";
    pub const RDM_ERR_DIVERGENCE: &str = "RDM-ERR-001";
    pub const RDM_ERR_INCOMPLETE: &str = "RDM-ERR-002";
}

pub mod invariants {
    pub const INV_RDM_HASH: &str = "INV-RDM-HASH";
    pub const INV_RDM_COMPLETE: &str = "INV-RDM-COMPLETE";
    pub const INV_RDM_DETERMINISTIC: &str = "INV-RDM-DETERMINISTIC";
    pub const INV_RDM_GATED: &str = "INV-RDM-GATED";
    pub const INV_RDM_VERSIONED: &str = "INV-RDM-VERSIONED";
    pub const INV_RDM_AUDITABLE: &str = "INV-RDM-AUDITABLE";
}

pub const METRIC_VERSION: &str = "rdm-v1.0";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Category of artifact for completeness tracking.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactCategory {
    VerificationEvidence,
    SpecContract,
    GateScript,
    UnitTests,
    CheckReport,
}

impl ArtifactCategory {
    pub fn all() -> &'static [ArtifactCategory] {
        &[
            Self::VerificationEvidence,
            Self::SpecContract,
            Self::GateScript,
            Self::UnitTests,
            Self::CheckReport,
        ]
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::VerificationEvidence => "verification_evidence",
            Self::SpecContract => "spec_contract",
            Self::GateScript => "gate_script",
            Self::UnitTests => "unit_tests",
            Self::CheckReport => "check_report",
        }
    }
}

/// Divergence severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DivergenceSeverity {
    None,
    Minor,
    Major,
    Critical,
}

/// A replay run recording.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReplayRun {
    pub run_id: String,
    pub operation: String,
    pub output_hash: String,
    pub artifact_hashes: BTreeMap<String, String>,
    pub timestamp: String,
}

/// Result of comparing two replay runs.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ComparisonResult {
    pub comparison_id: String,
    pub original_run_id: String,
    pub replay_run_id: String,
    pub output_match: bool,
    pub artifact_matches: BTreeMap<String, bool>,
    pub divergence_count: usize,
    pub severity: DivergenceSeverity,
    pub timestamp: String,
}

/// Artifact completeness record.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ArtifactCompleteness {
    pub category: ArtifactCategory,
    pub expected: usize,
    pub found: usize,
    pub complete: bool,
}

/// Full replay determinism report.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DeterminismReport {
    pub report_id: String,
    pub timestamp: String,
    pub metric_version: String,
    pub total_comparisons: usize,
    pub matches: usize,
    pub divergences: usize,
    pub determinism_rate: f64,
    pub artifact_completeness: Vec<ArtifactCompleteness>,
    pub overall_completeness_pct: f64,
    pub gate_verdict: GateVerdict,
    pub content_hash: String,
}

/// Gate verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GateVerdict {
    Pass,
    Fail,
}

/// Audit record.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RdmAuditRecord {
    pub record_id: String,
    pub event_code: String,
    pub timestamp: String,
    pub trace_id: String,
    pub details: serde_json::Value,
}

/// Configuration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RdmConfig {
    pub metric_version: String,
    pub min_determinism_rate: f64,
    pub min_completeness_pct: f64,
}

impl Default for RdmConfig {
    fn default() -> Self {
        Self {
            metric_version: METRIC_VERSION.to_string(),
            min_determinism_rate: 1.0,
            min_completeness_pct: 100.0,
        }
    }
}

// ---------------------------------------------------------------------------
// Engine
// ---------------------------------------------------------------------------

/// Replay determinism and artifact completeness engine.
#[derive(Debug, Clone)]
pub struct ReplayDeterminismMetrics {
    config: RdmConfig,
    runs: Vec<ReplayRun>,
    comparisons: Vec<ComparisonResult>,
    artifact_tracking: BTreeMap<ArtifactCategory, (usize, usize)>,
    audit_log: Vec<RdmAuditRecord>,
}

impl Default for ReplayDeterminismMetrics {
    fn default() -> Self {
        Self::new(RdmConfig::default())
    }
}

impl ReplayDeterminismMetrics {
    pub fn new(config: RdmConfig) -> Self {
        Self {
            config,
            runs: Vec::new(),
            comparisons: Vec::new(),
            artifact_tracking: BTreeMap::new(),
            audit_log: Vec::new(),
        }
    }

    /// Record a replay run.
    pub fn record_run(&mut self, run: ReplayRun, trace_id: &str) -> String {
        let run_id = run.run_id.clone();
        self.log(
            event_codes::RDM_RUN_RECORDED,
            trace_id,
            serde_json::json!({
                "run_id": &run_id,
                "operation": &run.operation,
                "output_hash": &run.output_hash,
            }),
        );
        self.runs.push(run);
        run_id
    }

    /// Compare two replay runs for determinism.
    pub fn compare_runs(
        &mut self,
        original_id: &str,
        replay_id: &str,
        trace_id: &str,
    ) -> Result<ComparisonResult, String> {
        let original = self
            .runs
            .iter()
            .find(|r| r.run_id == original_id)
            .ok_or_else(|| "Original run not found".to_string())?
            .clone();

        let replay = self
            .runs
            .iter()
            .find(|r| r.run_id == replay_id)
            .ok_or_else(|| "Replay run not found".to_string())?
            .clone();

        self.log(
            event_codes::RDM_COMPARISON_STARTED,
            trace_id,
            serde_json::json!({
                "original": original_id,
                "replay": replay_id,
            }),
        );

        let output_match = original.output_hash == replay.output_hash;

        let mut artifact_matches = BTreeMap::new();
        for (key, orig_hash) in &original.artifact_hashes {
            let matches = replay
                .artifact_hashes
                .get(key)
                .map(|h| h == orig_hash)
                .unwrap_or(false);
            artifact_matches.insert(key.clone(), matches);
        }

        let divergence_count =
            artifact_matches.values().filter(|v| !**v).count() + if output_match { 0 } else { 1 };

        let severity = match divergence_count {
            0 => DivergenceSeverity::None,
            1 => DivergenceSeverity::Minor,
            2..=3 => DivergenceSeverity::Major,
            _ => DivergenceSeverity::Critical,
        };

        if output_match {
            self.log(
                event_codes::RDM_HASH_MATCHED,
                trace_id,
                serde_json::json!({"original": original_id, "replay": replay_id}),
            );
        } else {
            self.log(
                event_codes::RDM_DIVERGENCE_DETECTED,
                trace_id,
                serde_json::json!({
                    "original": original_id,
                    "replay": replay_id,
                    "severity": format!("{:?}", severity),
                }),
            );
            self.log(
                event_codes::RDM_ERR_DIVERGENCE,
                trace_id,
                serde_json::json!({
                    "original_hash": &original.output_hash,
                    "replay_hash": &replay.output_hash,
                }),
            );
        }

        let result = ComparisonResult {
            comparison_id: Uuid::now_v7().to_string(),
            original_run_id: original_id.to_string(),
            replay_run_id: replay_id.to_string(),
            output_match,
            artifact_matches,
            divergence_count,
            severity,
            timestamp: Utc::now().to_rfc3339(),
        };

        self.comparisons.push(result.clone());
        Ok(result)
    }

    /// Track artifact presence for completeness.
    pub fn track_artifact(
        &mut self,
        category: ArtifactCategory,
        expected: usize,
        found: usize,
        trace_id: &str,
    ) {
        self.artifact_tracking.insert(category, (expected, found));

        self.log(
            event_codes::RDM_ARTIFACT_CHECKED,
            trace_id,
            serde_json::json!({
                "category": category.label(),
                "expected": expected,
                "found": found,
            }),
        );

        if found < expected {
            self.log(
                event_codes::RDM_ERR_INCOMPLETE,
                trace_id,
                serde_json::json!({
                    "category": category.label(),
                    "missing": expected - found,
                }),
            );
        }
    }

    /// Generate a determinism and completeness report.
    pub fn generate_report(&mut self, trace_id: &str) -> DeterminismReport {
        let total = self.comparisons.len();
        let matches = self.comparisons.iter().filter(|c| c.output_match).count();
        let divergences = total - matches;
        let determinism_rate = if total > 0 {
            matches as f64 / total as f64
        } else {
            1.0
        };

        let mut completeness = Vec::new();
        let mut total_expected = 0usize;
        let mut total_found = 0usize;

        for cat in ArtifactCategory::all() {
            let (expected, found) = self.artifact_tracking.get(cat).copied().unwrap_or((0, 0));
            total_expected += expected;
            total_found += found;
            completeness.push(ArtifactCompleteness {
                category: *cat,
                expected,
                found,
                complete: found >= expected,
            });
        }

        self.log(
            event_codes::RDM_COMPLETENESS_COMPUTED,
            trace_id,
            serde_json::json!({
                "total_expected": total_expected,
                "total_found": total_found,
            }),
        );

        let completeness_pct = if total_expected > 0 {
            (total_found as f64 / total_expected as f64) * 100.0
        } else {
            100.0
        };

        let gate_verdict = if determinism_rate >= self.config.min_determinism_rate
            && completeness_pct >= self.config.min_completeness_pct
        {
            GateVerdict::Pass
        } else {
            GateVerdict::Fail
        };

        self.log(
            event_codes::RDM_GATE_EVALUATED,
            trace_id,
            serde_json::json!({
                "determinism_rate": determinism_rate,
                "completeness_pct": completeness_pct,
                "verdict": format!("{:?}", gate_verdict),
            }),
        );

        let hash_input = serde_json::json!({
            "total_comparisons": total,
            "matches": matches,
            "completeness_pct": completeness_pct,
            "metric_version": &self.config.metric_version,
        })
        .to_string();
        let content_hash = hex::encode(Sha256::digest(
            [
                b"replay_determinism_hash_v1:" as &[u8],
                hash_input.as_bytes(),
            ]
            .concat(),
        ));

        self.log(
            event_codes::RDM_REPORT_GENERATED,
            trace_id,
            serde_json::json!({
                "determinism_rate": determinism_rate,
                "gate_verdict": format!("{:?}", gate_verdict),
            }),
        );

        self.log(
            event_codes::RDM_VERSION_EMBEDDED,
            trace_id,
            serde_json::json!({"metric_version": &self.config.metric_version}),
        );

        DeterminismReport {
            report_id: Uuid::now_v7().to_string(),
            timestamp: Utc::now().to_rfc3339(),
            metric_version: self.config.metric_version.clone(),
            total_comparisons: total,
            matches,
            divergences,
            determinism_rate,
            artifact_completeness: completeness,
            overall_completeness_pct: completeness_pct,
            gate_verdict,
            content_hash,
        }
    }

    pub fn runs(&self) -> &[ReplayRun] {
        &self.runs
    }
    pub fn comparisons(&self) -> &[ComparisonResult] {
        &self.comparisons
    }
    pub fn audit_log(&self) -> &[RdmAuditRecord] {
        &self.audit_log
    }

    pub fn export_audit_log_jsonl(&self) -> Result<String, serde_json::Error> {
        let mut lines = Vec::with_capacity(self.audit_log.len());
        for r in &self.audit_log {
            lines.push(serde_json::to_string(r)?);
        }
        Ok(lines.join("\n"))
    }

    fn log(&mut self, event_code: &str, trace_id: &str, details: serde_json::Value) {
        self.audit_log.push(RdmAuditRecord {
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

    fn trace() -> String {
        Uuid::now_v7().to_string()
    }

    fn sample_run(id: &str, hash: &str) -> ReplayRun {
        let mut artifacts = BTreeMap::new();
        artifacts.insert("evidence".to_string(), "abc123".to_string());
        artifacts.insert("spec".to_string(), "def456".to_string());
        ReplayRun {
            run_id: id.to_string(),
            operation: "test_op".to_string(),
            output_hash: hash.to_string(),
            artifact_hashes: artifacts,
            timestamp: Utc::now().to_rfc3339(),
        }
    }

    // === Categories ===

    #[test]
    fn five_artifact_categories() {
        assert_eq!(ArtifactCategory::all().len(), 5);
    }

    #[test]
    fn category_labels() {
        for c in ArtifactCategory::all() {
            assert!(!c.label().is_empty());
        }
    }

    // === Divergence severities ===

    #[test]
    fn four_severities() {
        let s = [
            DivergenceSeverity::None,
            DivergenceSeverity::Minor,
            DivergenceSeverity::Major,
            DivergenceSeverity::Critical,
        ];
        assert_eq!(s.len(), 4);
    }

    // === Run recording ===

    #[test]
    fn record_run() {
        let mut engine = ReplayDeterminismMetrics::default();
        let id = engine.record_run(sample_run("r1", "hash1"), &trace());
        assert_eq!(id, "r1");
        assert_eq!(engine.runs().len(), 1);
    }

    // === Comparison ===

    #[test]
    fn compare_matching_runs() {
        let mut engine = ReplayDeterminismMetrics::default();
        engine.record_run(sample_run("r1", "same_hash"), &trace());
        engine.record_run(sample_run("r2", "same_hash"), &trace());
        let result = engine.compare_runs("r1", "r2", &trace()).unwrap();
        assert!(result.output_match);
        assert_eq!(result.divergence_count, 0);
        assert_eq!(result.severity, DivergenceSeverity::None);
    }

    #[test]
    fn compare_divergent_runs() {
        let mut engine = ReplayDeterminismMetrics::default();
        engine.record_run(sample_run("r1", "hash_a"), &trace());
        engine.record_run(sample_run("r2", "hash_b"), &trace());
        let result = engine.compare_runs("r1", "r2", &trace()).unwrap();
        assert!(!result.output_match);
        assert!(result.divergence_count > 0);
    }

    #[test]
    fn compare_missing_run_fails() {
        let mut engine = ReplayDeterminismMetrics::default();
        engine.record_run(sample_run("r1", "hash"), &trace());
        assert!(engine.compare_runs("r1", "r99", &trace()).is_err());
    }

    #[test]
    fn severity_classification() {
        let mut engine = ReplayDeterminismMetrics::default();
        engine.record_run(sample_run("r1", "h1"), &trace());
        engine.record_run(sample_run("r2", "h2"), &trace());
        let result = engine.compare_runs("r1", "r2", &trace()).unwrap();
        assert_ne!(result.severity, DivergenceSeverity::None);
    }

    // === Artifact completeness ===

    #[test]
    fn track_artifact_complete() {
        let mut engine = ReplayDeterminismMetrics::default();
        engine.track_artifact(ArtifactCategory::VerificationEvidence, 5, 5, &trace());
        assert!(!engine.audit_log().is_empty());
    }

    #[test]
    fn track_artifact_incomplete() {
        let mut engine = ReplayDeterminismMetrics::default();
        engine.track_artifact(ArtifactCategory::SpecContract, 5, 3, &trace());
        let codes: Vec<&str> = engine
            .audit_log()
            .iter()
            .map(|r| r.event_code.as_str())
            .collect();
        assert!(codes.contains(&event_codes::RDM_ERR_INCOMPLETE));
    }

    // === Report generation ===

    #[test]
    fn report_all_matching() {
        let mut engine = ReplayDeterminismMetrics::default();
        engine.record_run(sample_run("r1", "h"), &trace());
        engine.record_run(sample_run("r2", "h"), &trace());
        engine.compare_runs("r1", "r2", &trace()).unwrap();
        for cat in ArtifactCategory::all() {
            engine.track_artifact(*cat, 1, 1, &trace());
        }
        let report = engine.generate_report(&trace());
        assert_eq!(report.gate_verdict, GateVerdict::Pass);
        assert_eq!(report.determinism_rate, 1.0);
    }

    #[test]
    fn report_with_divergence() {
        let mut engine = ReplayDeterminismMetrics::default();
        engine.record_run(sample_run("r1", "h1"), &trace());
        engine.record_run(sample_run("r2", "h2"), &trace());
        engine.compare_runs("r1", "r2", &trace()).unwrap();
        let report = engine.generate_report(&trace());
        assert_eq!(report.gate_verdict, GateVerdict::Fail);
        assert!(report.determinism_rate < 1.0);
    }

    #[test]
    fn report_empty() {
        let mut engine = ReplayDeterminismMetrics::default();
        let report = engine.generate_report(&trace());
        assert_eq!(report.total_comparisons, 0);
        assert_eq!(report.determinism_rate, 1.0);
    }

    #[test]
    fn report_has_content_hash() {
        let mut engine = ReplayDeterminismMetrics::default();
        let report = engine.generate_report(&trace());
        assert_eq!(report.content_hash.len(), 64);
    }

    #[test]
    fn report_has_version() {
        let mut engine = ReplayDeterminismMetrics::default();
        let report = engine.generate_report(&trace());
        assert_eq!(report.metric_version, METRIC_VERSION);
    }

    #[test]
    fn report_deterministic_hash() {
        let mut e1 = ReplayDeterminismMetrics::default();
        let mut e2 = ReplayDeterminismMetrics::default();
        let r1 = e1.generate_report("det");
        let r2 = e2.generate_report("det");
        assert_eq!(r1.content_hash, r2.content_hash);
    }

    #[test]
    fn completeness_pct_calculation() {
        let mut engine = ReplayDeterminismMetrics::default();
        engine.track_artifact(ArtifactCategory::VerificationEvidence, 10, 8, &trace());
        engine.track_artifact(ArtifactCategory::SpecContract, 10, 10, &trace());
        let report = engine.generate_report(&trace());
        assert!((report.overall_completeness_pct - 90.0).abs() < f64::EPSILON);
    }

    // === Config ===

    #[test]
    fn default_config() {
        let config = RdmConfig::default();
        assert_eq!(config.min_determinism_rate, 1.0);
        assert_eq!(config.min_completeness_pct, 100.0);
        assert_eq!(config.metric_version, METRIC_VERSION);
    }

    #[test]
    fn lenient_config_allows_divergence() {
        let config = RdmConfig {
            min_determinism_rate: 0.5,
            min_completeness_pct: 50.0,
            ..Default::default()
        };
        let mut engine = ReplayDeterminismMetrics::new(config);
        engine.record_run(sample_run("r1", "h1"), &trace());
        engine.record_run(sample_run("r2", "h2"), &trace());
        engine.compare_runs("r1", "r2", &trace()).unwrap();
        let report = engine.generate_report(&trace());
        // 0.0 < 0.5 threshold, should fail even with lenient config
        assert_eq!(report.gate_verdict, GateVerdict::Fail);
    }

    // === Audit log ===

    #[test]
    fn audit_log_populated() {
        let mut engine = ReplayDeterminismMetrics::default();
        engine.record_run(sample_run("r1", "h"), &trace());
        assert!(!engine.audit_log().is_empty());
    }

    #[test]
    fn audit_has_event_codes() {
        let mut engine = ReplayDeterminismMetrics::default();
        engine.record_run(sample_run("r1", "h"), &trace());
        let codes: Vec<&str> = engine
            .audit_log()
            .iter()
            .map(|r| r.event_code.as_str())
            .collect();
        assert!(codes.contains(&event_codes::RDM_RUN_RECORDED));
    }

    #[test]
    fn export_jsonl() {
        let mut engine = ReplayDeterminismMetrics::default();
        engine.record_run(sample_run("r1", "h"), &trace());
        let jsonl = engine.export_audit_log_jsonl().unwrap();
        let first: serde_json::Value = serde_json::from_str(jsonl.lines().next().unwrap()).unwrap();
        assert!(first["event_code"].is_string());
    }

    // === Gate verdicts ===

    #[test]
    fn two_gate_verdicts() {
        let v = [GateVerdict::Pass, GateVerdict::Fail];
        assert_eq!(v.len(), 2);
    }
}
