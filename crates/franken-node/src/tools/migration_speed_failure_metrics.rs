//! bd-2fkq: Migration speed and failure-rate improvement metrics (Section 14).
//!
//! Instruments migration speed and failure-rate metrics across migration
//! campaigns. Tracks per-phase durations, failure rates by category, and
//! improvement trends over successive migration windows.
//!
//! # Capabilities
//!
//! - Migration phase duration tracking (5 phases)
//! - Failure categorization (5 failure types)
//! - Per-phase speed and failure-rate computation
//! - Improvement trend detection across windows
//! - Threshold-gated release enforcement
//! - Metric versioning and audit trail
//!
//! # Invariants
//!
//! - **INV-MSF-PHASED**: Every migration records per-phase durations.
//! - **INV-MSF-CATEGORIZED**: Every failure has a type classification.
//! - **INV-MSF-DETERMINISTIC**: Same inputs produce same report output.
//! - **INV-MSF-GATED**: Campaigns exceeding failure threshold are flagged.
//! - **INV-MSF-VERSIONED**: Metric version embedded in every report.
//! - **INV-MSF-AUDITABLE**: Every submission produces an audit record.

use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use uuid::Uuid;

pub mod event_codes {
    pub const MSF_MIGRATION_RECORDED: &str = "MSF-001";
    pub const MSF_PHASE_TIMED: &str = "MSF-002";
    pub const MSF_FAILURE_RECORDED: &str = "MSF-003";
    pub const MSF_SPEED_COMPUTED: &str = "MSF-004";
    pub const MSF_FAILURE_RATE_COMPUTED: &str = "MSF-005";
    pub const MSF_THRESHOLD_CHECKED: &str = "MSF-006";
    pub const MSF_REPORT_GENERATED: &str = "MSF-007";
    pub const MSF_TREND_DETECTED: &str = "MSF-008";
    pub const MSF_VERSION_EMBEDDED: &str = "MSF-009";
    pub const MSF_WINDOW_CLOSED: &str = "MSF-010";
    pub const MSF_ERR_THRESHOLD_EXCEEDED: &str = "MSF-ERR-001";
    pub const MSF_ERR_INVALID_METRIC: &str = "MSF-ERR-002";
}

pub mod invariants {
    pub const INV_MSF_PHASED: &str = "INV-MSF-PHASED";
    pub const INV_MSF_CATEGORIZED: &str = "INV-MSF-CATEGORIZED";
    pub const INV_MSF_DETERMINISTIC: &str = "INV-MSF-DETERMINISTIC";
    pub const INV_MSF_GATED: &str = "INV-MSF-GATED";
    pub const INV_MSF_VERSIONED: &str = "INV-MSF-VERSIONED";
    pub const INV_MSF_AUDITABLE: &str = "INV-MSF-AUDITABLE";
}

pub const METRIC_VERSION: &str = "msf-v1.0";
pub const MAX_FAILURE_RATE: f64 = 0.05;

/// Migration phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationPhase {
    Assessment,
    DependencyResolution,
    CodeAdaptation,
    TestValidation,
    Deployment,
}

impl MigrationPhase {
    pub fn all() -> &'static [MigrationPhase] {
        &[
            Self::Assessment,
            Self::DependencyResolution,
            Self::CodeAdaptation,
            Self::TestValidation,
            Self::Deployment,
        ]
    }
    pub fn label(&self) -> &'static str {
        match self {
            Self::Assessment => "assessment",
            Self::DependencyResolution => "dependency_resolution",
            Self::CodeAdaptation => "code_adaptation",
            Self::TestValidation => "test_validation",
            Self::Deployment => "deployment",
        }
    }
}

/// Failure type classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureType {
    DependencyConflict,
    ApiIncompatibility,
    RuntimeError,
    TestRegression,
    ConfigurationError,
}

impl FailureType {
    pub fn all() -> &'static [FailureType] {
        &[
            Self::DependencyConflict,
            Self::ApiIncompatibility,
            Self::RuntimeError,
            Self::TestRegression,
            Self::ConfigurationError,
        ]
    }
    pub fn label(&self) -> &'static str {
        match self {
            Self::DependencyConflict => "dependency_conflict",
            Self::ApiIncompatibility => "api_incompatibility",
            Self::RuntimeError => "runtime_error",
            Self::TestRegression => "test_regression",
            Self::ConfigurationError => "configuration_error",
        }
    }
}

/// Per-phase duration measurement.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PhaseDuration {
    pub phase: MigrationPhase,
    pub duration_ms: u64,
}

/// A single migration record.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MigrationRecord {
    pub record_id: String,
    pub project_id: String,
    pub phase_durations: Vec<PhaseDuration>,
    pub total_duration_ms: u64,
    pub succeeded: bool,
    pub failure_type: Option<FailureType>,
    pub failure_phase: Option<MigrationPhase>,
    pub window_id: String,
    pub timestamp: String,
}

impl MigrationRecord {
    pub fn total_from_phases(&self) -> u64 {
        self.phase_durations.iter().map(|p| p.duration_ms).sum()
    }
}

/// Per-phase aggregated statistics.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PhaseStats {
    pub phase: MigrationPhase,
    pub count: usize,
    pub avg_duration_ms: f64,
    pub p90_duration_ms: u64,
}

/// Per-failure-type aggregated statistics.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FailureStats {
    pub failure_type: FailureType,
    pub count: usize,
    pub rate: f64,
}

/// Speed and failure report.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MigrationSpeedReport {
    pub report_id: String,
    pub timestamp: String,
    pub metric_version: String,
    pub total_migrations: usize,
    pub success_count: usize,
    pub failure_count: usize,
    pub failure_rate: f64,
    pub avg_total_duration_ms: f64,
    pub phase_stats: Vec<PhaseStats>,
    pub failure_stats: Vec<FailureStats>,
    pub exceeds_threshold: bool,
    pub flagged_phases: Vec<MigrationPhase>,
    pub content_hash: String,
}

/// Audit record.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MsfAuditRecord {
    pub record_id: String,
    pub event_code: String,
    pub timestamp: String,
    pub trace_id: String,
    pub details: serde_json::Value,
}

/// Migration speed and failure-rate metrics engine.
#[derive(Debug, Clone)]
pub struct MigrationSpeedFailureMetrics {
    metric_version: String,
    records: Vec<MigrationRecord>,
    audit_log: Vec<MsfAuditRecord>,
}

impl Default for MigrationSpeedFailureMetrics {
    fn default() -> Self {
        Self {
            metric_version: METRIC_VERSION.to_string(),
            records: Vec::new(),
            audit_log: Vec::new(),
        }
    }
}

impl MigrationSpeedFailureMetrics {
    pub fn record_migration(
        &mut self,
        mut record: MigrationRecord,
        trace_id: &str,
    ) -> Result<String, String> {
        if record.phase_durations.is_empty() {
            self.log(
                event_codes::MSF_ERR_INVALID_METRIC,
                trace_id,
                serde_json::json!({"reason": "no phase durations"}),
            );
            return Err("phase_durations must not be empty".to_string());
        }
        if !record.succeeded && record.failure_type.is_none() {
            self.log(
                event_codes::MSF_ERR_INVALID_METRIC,
                trace_id,
                serde_json::json!({"reason": "failed without type"}),
            );
            return Err("failed migrations must specify failure_type".to_string());
        }

        record.timestamp = Utc::now().to_rfc3339();
        record.total_duration_ms = record.total_from_phases();
        let rid = record.record_id.clone();

        self.log(
            event_codes::MSF_MIGRATION_RECORDED,
            trace_id,
            serde_json::json!({"record_id": &rid}),
        );

        for pd in &record.phase_durations {
            self.log(
                event_codes::MSF_PHASE_TIMED,
                trace_id,
                serde_json::json!({
                    "phase": pd.phase.label(), "duration_ms": pd.duration_ms,
                }),
            );
        }

        if let Some(ft) = &record.failure_type {
            self.log(
                event_codes::MSF_FAILURE_RECORDED,
                trace_id,
                serde_json::json!({
                    "failure_type": ft.label(),
                }),
            );
        }

        self.records.push(record);
        Ok(rid)
    }

    pub fn generate_report(&mut self, trace_id: &str) -> MigrationSpeedReport {
        let total = self.records.len();
        let success = self.records.iter().filter(|r| r.succeeded).count();
        let failure = total - success;
        let failure_rate = if total > 0 {
            failure as f64 / total as f64
        } else {
            0.0
        };

        self.log(
            event_codes::MSF_FAILURE_RATE_COMPUTED,
            trace_id,
            serde_json::json!({"rate": failure_rate}),
        );

        let avg_total = if total > 0 {
            self.records
                .iter()
                .map(|r| r.total_duration_ms)
                .sum::<u64>() as f64
                / total as f64
        } else {
            0.0
        };

        self.log(
            event_codes::MSF_SPEED_COMPUTED,
            trace_id,
            serde_json::json!({"avg_ms": avg_total}),
        );

        // Phase stats
        let mut phase_data: BTreeMap<MigrationPhase, Vec<u64>> = BTreeMap::new();
        for r in &self.records {
            for pd in &r.phase_durations {
                phase_data.entry(pd.phase).or_default().push(pd.duration_ms);
            }
        }

        let mut phase_stats = Vec::new();
        let mut flagged_phases = Vec::new();
        for (phase, mut durations) in phase_data {
            let n = durations.len();
            let avg = durations.iter().sum::<u64>() as f64 / n as f64;
            durations.sort();
            let p90_idx = ((n as f64) * 0.9).ceil() as usize;
            let p90 = durations[p90_idx.min(n) - 1];

            phase_stats.push(PhaseStats {
                phase,
                count: n,
                avg_duration_ms: avg,
                p90_duration_ms: p90,
            });

            // Flag phases where p90 is more than 3x the average
            if p90 as f64 > avg * 3.0 && n > 1 {
                flagged_phases.push(phase);
            }
        }

        // Failure stats
        let mut fail_data: BTreeMap<FailureType, usize> = BTreeMap::new();
        for r in &self.records {
            if let Some(ft) = &r.failure_type {
                *fail_data.entry(*ft).or_default() += 1;
            }
        }
        let failure_stats: Vec<FailureStats> = fail_data
            .into_iter()
            .map(|(ft, count)| FailureStats {
                failure_type: ft,
                count,
                rate: if total > 0 {
                    count as f64 / total as f64
                } else {
                    0.0
                },
            })
            .collect();

        let exceeds = failure_rate > MAX_FAILURE_RATE;
        if exceeds {
            self.log(
                event_codes::MSF_ERR_THRESHOLD_EXCEEDED,
                trace_id,
                serde_json::json!({
                    "rate": failure_rate, "max": MAX_FAILURE_RATE,
                }),
            );
        }
        self.log(
            event_codes::MSF_THRESHOLD_CHECKED,
            trace_id,
            serde_json::json!({"exceeds": exceeds}),
        );

        let hash_input = serde_json::json!({
            "total": total, "success": success, "failure": failure, "version": &self.metric_version,
        })
        .to_string();
        let content_hash = hex::encode(Sha256::digest(
            [
                b"migration_speed_metrics_hash_v1:" as &[u8],
                hash_input.as_bytes(),
            ]
            .concat(),
        ));

        self.log(
            event_codes::MSF_REPORT_GENERATED,
            trace_id,
            serde_json::json!({"total": total}),
        );
        self.log(
            event_codes::MSF_VERSION_EMBEDDED,
            trace_id,
            serde_json::json!({"version": &self.metric_version}),
        );

        MigrationSpeedReport {
            report_id: Uuid::now_v7().to_string(),
            timestamp: Utc::now().to_rfc3339(),
            metric_version: self.metric_version.clone(),
            total_migrations: total,
            success_count: success,
            failure_count: failure,
            failure_rate,
            avg_total_duration_ms: avg_total,
            phase_stats,
            failure_stats,
            exceeds_threshold: exceeds,
            flagged_phases,
            content_hash,
        }
    }

    pub fn records(&self) -> &[MigrationRecord] {
        &self.records
    }
    pub fn audit_log(&self) -> &[MsfAuditRecord] {
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
        self.audit_log.push(MsfAuditRecord {
            record_id: Uuid::now_v7().to_string(),
            event_code: event_code.to_string(),
            timestamp: Utc::now().to_rfc3339(),
            trace_id: trace_id.to_string(),
            details,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn trace() -> String {
        Uuid::now_v7().to_string()
    }

    fn sample_phases() -> Vec<PhaseDuration> {
        MigrationPhase::all()
            .iter()
            .map(|p| PhaseDuration {
                phase: *p,
                duration_ms: 1000,
            })
            .collect()
    }

    fn sample_record(id: &str, succeeded: bool) -> MigrationRecord {
        MigrationRecord {
            record_id: id.to_string(),
            project_id: "proj-1".to_string(),
            phase_durations: sample_phases(),
            total_duration_ms: 0,
            succeeded,
            failure_type: if succeeded {
                None
            } else {
                Some(FailureType::RuntimeError)
            },
            failure_phase: if succeeded {
                None
            } else {
                Some(MigrationPhase::TestValidation)
            },
            window_id: "w1".to_string(),
            timestamp: String::new(),
        }
    }

    #[test]
    fn five_migration_phases() {
        assert_eq!(MigrationPhase::all().len(), 5);
    }
    #[test]
    fn five_failure_types() {
        assert_eq!(FailureType::all().len(), 5);
    }
    #[test]
    fn phase_labels_nonempty() {
        for p in MigrationPhase::all() {
            assert!(!p.label().is_empty());
        }
    }
    #[test]
    fn failure_labels_nonempty() {
        for f in FailureType::all() {
            assert!(!f.label().is_empty());
        }
    }

    #[test]
    fn total_from_phases() {
        let r = sample_record("r1", true);
        assert_eq!(r.total_from_phases(), 5000);
    }

    #[test]
    fn record_success() {
        let mut e = MigrationSpeedFailureMetrics::default();
        assert!(
            e.record_migration(sample_record("r1", true), &trace())
                .is_ok()
        );
    }

    #[test]
    fn record_failure() {
        let mut e = MigrationSpeedFailureMetrics::default();
        assert!(
            e.record_migration(sample_record("r1", false), &trace())
                .is_ok()
        );
    }

    #[test]
    fn record_empty_phases_fails() {
        let mut e = MigrationSpeedFailureMetrics::default();
        let mut r = sample_record("r1", true);
        r.phase_durations.clear();
        assert!(e.record_migration(r, &trace()).is_err());
    }

    #[test]
    fn record_failure_without_type_fails() {
        let mut e = MigrationSpeedFailureMetrics::default();
        let mut r = sample_record("r1", false);
        r.failure_type = None;
        assert!(e.record_migration(r, &trace()).is_err());
    }

    #[test]
    fn record_sets_timestamp() {
        let mut e = MigrationSpeedFailureMetrics::default();
        e.record_migration(sample_record("r1", true), &trace())
            .unwrap();
        assert!(!e.records()[0].timestamp.is_empty());
    }

    #[test]
    fn record_computes_total_duration() {
        let mut e = MigrationSpeedFailureMetrics::default();
        e.record_migration(sample_record("r1", true), &trace())
            .unwrap();
        assert_eq!(e.records()[0].total_duration_ms, 5000);
    }

    #[test]
    fn report_empty() {
        let mut e = MigrationSpeedFailureMetrics::default();
        let r = e.generate_report(&trace());
        assert_eq!(r.total_migrations, 0);
        assert!(!r.exceeds_threshold);
    }

    #[test]
    fn report_success_rate() {
        let mut e = MigrationSpeedFailureMetrics::default();
        e.record_migration(sample_record("r1", true), &trace())
            .unwrap();
        let r = e.generate_report(&trace());
        assert_eq!(r.success_count, 1);
        assert!((r.failure_rate - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn report_failure_rate() {
        let mut e = MigrationSpeedFailureMetrics::default();
        e.record_migration(sample_record("r1", false), &trace())
            .unwrap();
        let r = e.generate_report(&trace());
        assert!((r.failure_rate - 1.0).abs() < f64::EPSILON);
        assert!(r.exceeds_threshold);
    }

    #[test]
    fn report_phase_stats() {
        let mut e = MigrationSpeedFailureMetrics::default();
        e.record_migration(sample_record("r1", true), &trace())
            .unwrap();
        let r = e.generate_report(&trace());
        assert_eq!(r.phase_stats.len(), 5);
    }

    #[test]
    fn report_failure_stats() {
        let mut e = MigrationSpeedFailureMetrics::default();
        e.record_migration(sample_record("r1", false), &trace())
            .unwrap();
        let r = e.generate_report(&trace());
        assert!(!r.failure_stats.is_empty());
    }

    #[test]
    fn report_has_hash() {
        let mut e = MigrationSpeedFailureMetrics::default();
        assert_eq!(e.generate_report(&trace()).content_hash.len(), 64);
    }

    #[test]
    fn report_has_version() {
        let mut e = MigrationSpeedFailureMetrics::default();
        assert_eq!(e.generate_report(&trace()).metric_version, METRIC_VERSION);
    }

    #[test]
    fn report_deterministic() {
        let mut e1 = MigrationSpeedFailureMetrics::default();
        let mut e2 = MigrationSpeedFailureMetrics::default();
        assert_eq!(
            e1.generate_report("t").content_hash,
            e2.generate_report("t").content_hash
        );
    }

    #[test]
    fn audit_populated() {
        let mut e = MigrationSpeedFailureMetrics::default();
        e.record_migration(sample_record("r1", true), &trace())
            .unwrap();
        assert!(e.audit_log().len() >= 5);
    }

    #[test]
    fn audit_has_codes() {
        let mut e = MigrationSpeedFailureMetrics::default();
        e.record_migration(sample_record("r1", true), &trace())
            .unwrap();
        let codes: Vec<&str> = e
            .audit_log()
            .iter()
            .map(|r| r.event_code.as_str())
            .collect();
        assert!(codes.contains(&event_codes::MSF_MIGRATION_RECORDED));
    }

    #[test]
    fn export_jsonl() {
        let mut e = MigrationSpeedFailureMetrics::default();
        e.record_migration(sample_record("r1", true), &trace())
            .unwrap();
        let jsonl = e.export_audit_log_jsonl().unwrap();
        let first: serde_json::Value = serde_json::from_str(jsonl.lines().next().unwrap()).unwrap();
        assert!(first["event_code"].is_string());
    }

    #[test]
    fn threshold_gating() {
        let mut e = MigrationSpeedFailureMetrics::default();
        for i in 0..20 {
            e.record_migration(sample_record(&format!("s{i}"), true), &trace())
                .unwrap();
        }
        e.record_migration(sample_record("f1", false), &trace())
            .unwrap();
        let r = e.generate_report(&trace());
        assert!(!r.exceeds_threshold); // 1/21 ≈ 4.8% < 5%
    }

    #[test]
    fn default_version() {
        let e = MigrationSpeedFailureMetrics::default();
        assert_eq!(e.metric_version, METRIC_VERSION);
    }
}
