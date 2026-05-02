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
use crate::capacity_defaults::aliases::MAX_AUDIT_LOG_ENTRIES;
use crate::push_bounded;
const MAX_RECORDS: usize = 4096;

fn hash_f64(hasher: &mut Sha256, value: f64) {
    if value.is_finite() {
        hasher.update(value.to_le_bytes());
    } else {
        hasher.update(f64::NAN.to_le_bytes());
    }
}

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
        self.phase_durations
            .iter()
            .map(|p| p.duration_ms)
            .fold(0u64, |a, b| a.saturating_add(b))
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
        if record.record_id.trim().is_empty() {
            self.log(
                event_codes::MSF_ERR_INVALID_METRIC,
                trace_id,
                serde_json::json!({"reason": "empty record_id"}),
            );
            return Err("record_id must be non-empty".to_string());
        }
        if record.project_id.trim().is_empty() {
            self.log(
                event_codes::MSF_ERR_INVALID_METRIC,
                trace_id,
                serde_json::json!({"reason": "empty project_id"}),
            );
            return Err("project_id must be non-empty".to_string());
        }
        if record.window_id.trim().is_empty() {
            self.log(
                event_codes::MSF_ERR_INVALID_METRIC,
                trace_id,
                serde_json::json!({"reason": "empty window_id"}),
            );
            return Err("window_id must be non-empty".to_string());
        }
        if record.phase_durations.is_empty() {
            self.log(
                event_codes::MSF_ERR_INVALID_METRIC,
                trace_id,
                serde_json::json!({"reason": "no phase durations"}),
            );
            return Err("phase_durations must not be empty".to_string());
        }
        let mut seen_phases = std::collections::BTreeSet::new();
        for duration in &record.phase_durations {
            if !seen_phases.insert(duration.phase) {
                self.log(
                    event_codes::MSF_ERR_INVALID_METRIC,
                    trace_id,
                    serde_json::json!({
                        "reason": "duplicate phase duration",
                        "phase": duration.phase.label(),
                    }),
                );
                return Err("phase_durations must not contain duplicate phases".to_string());
            }
        }
        for phase in MigrationPhase::all() {
            if !seen_phases.contains(phase) {
                self.log(
                    event_codes::MSF_ERR_INVALID_METRIC,
                    trace_id,
                    serde_json::json!({
                        "reason": "missing phase duration",
                        "phase": phase.label(),
                    }),
                );
                return Err("phase_durations must cover every migration phase".to_string());
            }
        }
        if !record.succeeded && record.failure_type.is_none() {
            self.log(
                event_codes::MSF_ERR_INVALID_METRIC,
                trace_id,
                serde_json::json!({"reason": "failed without type"}),
            );
            return Err("failed migrations must specify failure_type".to_string());
        }
        if !record.succeeded && record.failure_phase.is_none() {
            self.log(
                event_codes::MSF_ERR_INVALID_METRIC,
                trace_id,
                serde_json::json!({"reason": "failed without phase"}),
            );
            return Err("failed migrations must specify failure_phase".to_string());
        }
        if record.succeeded && (record.failure_type.is_some() || record.failure_phase.is_some()) {
            self.log(
                event_codes::MSF_ERR_INVALID_METRIC,
                trace_id,
                serde_json::json!({"reason": "successful record with failure metadata"}),
            );
            return Err("successful migrations must not include failure metadata".to_string());
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

        push_bounded(&mut self.records, record, MAX_RECORDS);
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
                .fold(0u64, |a, b| a.saturating_add(b)) as f64
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
            if n == 0 {
                continue;
            }
            let avg = durations.iter().fold(0u64, |a, b| a.saturating_add(*b)) as f64 / n as f64;
            durations.sort();
            let p90_idx = ((n as f64) * 0.9).ceil() as usize;
            let p90 = durations[p90_idx.min(n).saturating_sub(1).max(0)];

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
                let count = fail_data.entry(*ft).or_default();
                *count = count.saturating_add(1);
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

        let content_hash = {
            let mut h = Sha256::new();
            h.update(b"migration_speed_metrics_hash_v1:");
            h.update((u64::try_from(self.metric_version.len()).unwrap_or(u64::MAX)).to_le_bytes());
            h.update(self.metric_version.as_bytes());
            h.update((total as u64).to_le_bytes());
            h.update((success as u64).to_le_bytes());
            h.update((failure as u64).to_le_bytes());
            hash_f64(&mut h, failure_rate);
            hash_f64(&mut h, avg_total);
            h.update([u8::from(exceeds)]);
            h.update((u64::try_from(phase_stats.len()).unwrap_or(u64::MAX)).to_le_bytes());
            for phase_stat in &phase_stats {
                let label = phase_stat.phase.label();
                h.update((u64::try_from(label.len()).unwrap_or(u64::MAX)).to_le_bytes());
                h.update(label.as_bytes());
                h.update((phase_stat.count as u64).to_le_bytes());
                hash_f64(&mut h, phase_stat.avg_duration_ms);
                h.update(phase_stat.p90_duration_ms.to_le_bytes());
            }
            h.update((u64::try_from(flagged_phases.len()).unwrap_or(u64::MAX)).to_le_bytes());
            for phase in &flagged_phases {
                let label = phase.label();
                h.update((u64::try_from(label.len()).unwrap_or(u64::MAX)).to_le_bytes());
                h.update(label.as_bytes());
            }
            h.update((u64::try_from(failure_stats.len()).unwrap_or(u64::MAX)).to_le_bytes());
            for failure_stat in &failure_stats {
                let label = failure_stat.failure_type.label();
                h.update((u64::try_from(label.len()).unwrap_or(u64::MAX)).to_le_bytes());
                h.update(label.as_bytes());
                h.update((failure_stat.count as u64).to_le_bytes());
                hash_f64(&mut h, failure_stat.rate);
            }
            hex::encode(h.finalize())
        };

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
        push_bounded(
            &mut self.audit_log,
            MsfAuditRecord {
                record_id: Uuid::now_v7().to_string(),
                event_code: event_code.to_string(),
                timestamp: Utc::now().to_rfc3339(),
                trace_id: trace_id.to_string(),
                details,
            },
            MAX_AUDIT_LOG_ENTRIES,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn trace() -> String {
        Uuid::now_v7().to_string()
    }

    fn record_with_durations_and_failure(
        id: &str,
        durations: [u64; 5],
        failure_type: Option<FailureType>,
    ) -> MigrationRecord {
        let succeeded = failure_type.is_none();
        MigrationRecord {
            record_id: id.to_string(),
            project_id: "proj-1".to_string(),
            phase_durations: MigrationPhase::all()
                .iter()
                .copied()
                .zip(durations)
                .map(|(phase, duration_ms)| PhaseDuration { phase, duration_ms })
                .collect(),
            total_duration_ms: 0,
            succeeded,
            failure_type,
            failure_phase: (!succeeded).then_some(MigrationPhase::TestValidation),
            window_id: "w1".to_string(),
            timestamp: String::new(),
        }
    }

    fn sample_record(id: &str, succeeded: bool) -> MigrationRecord {
        record_with_durations_and_failure(
            id,
            [1000, 1000, 1000, 1000, 1000],
            if succeeded {
                None
            } else {
                Some(FailureType::RuntimeError)
            },
        )
    }

    fn has_invalid_reason(e: &MigrationSpeedFailureMetrics, reason: &str) -> bool {
        e.audit_log().iter().any(|entry| {
            entry.event_code == event_codes::MSF_ERR_INVALID_METRIC
                && entry
                    .details
                    .get("reason")
                    .and_then(serde_json::Value::as_str)
                    == Some(reason)
        })
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
    fn push_bounded_zero_capacity_drops_existing_and_new_items() {
        let mut items = vec![1, 2, 3];

        push_bounded(&mut items, 4, 0);

        assert!(items.is_empty());
    }

    #[test]
    fn empty_phase_record_is_rejected_without_storage() {
        let mut e = MigrationSpeedFailureMetrics::default();
        let mut r = sample_record("bad-empty", true);
        r.phase_durations.clear();

        let err = e.record_migration(r, "trace-empty").unwrap_err();

        assert!(err.contains("phase_durations"));
        assert!(e.records().is_empty());
        assert_eq!(e.audit_log().len(), 1);
        assert!(has_invalid_reason(&e, "no phase durations"));
    }

    #[test]
    fn failed_record_without_type_is_rejected_before_storage() {
        let mut e = MigrationSpeedFailureMetrics::default();
        let mut r = sample_record("bad-no-type", false);
        r.failure_type = None;
        r.failure_phase = None;

        let err = e.record_migration(r, "trace-no-type").unwrap_err();

        assert!(err.contains("failure_type"));
        assert!(e.records().is_empty());
        assert_eq!(e.audit_log().len(), 1);
        assert!(has_invalid_reason(&e, "failed without type"));
        assert!(!has_invalid_reason(&e, "failed without phase"));
    }

    #[test]
    fn failed_record_without_phase_is_rejected_before_storage() {
        let mut e = MigrationSpeedFailureMetrics::default();
        let mut r = sample_record("bad-no-phase", false);
        r.failure_phase = None;

        let err = e.record_migration(r, "trace-no-phase").unwrap_err();

        assert!(err.contains("failure_phase"));
        assert!(e.records().is_empty());
        assert_eq!(e.audit_log().len(), 1);
        assert!(has_invalid_reason(&e, "failed without phase"));
    }

    #[test]
    fn successful_record_with_failure_type_is_rejected() {
        let mut e = MigrationSpeedFailureMetrics::default();
        let mut r = sample_record("bad-success-type", true);
        r.failure_type = Some(FailureType::RuntimeError);

        let err = e.record_migration(r, "trace-success-type").unwrap_err();

        assert!(err.contains("failure metadata"));
        assert!(e.records().is_empty());
        assert_eq!(e.audit_log().len(), 1);
        assert!(has_invalid_reason(
            &e,
            "successful record with failure metadata"
        ));
    }

    #[test]
    fn successful_record_with_failure_phase_is_rejected() {
        let mut e = MigrationSpeedFailureMetrics::default();
        let mut r = sample_record("bad-success-phase", true);
        r.failure_phase = Some(MigrationPhase::Deployment);

        let err = e.record_migration(r, "trace-success-phase").unwrap_err();

        assert!(err.contains("failure metadata"));
        assert!(e.records().is_empty());
        assert_eq!(e.audit_log().len(), 1);
        assert!(has_invalid_reason(
            &e,
            "successful record with failure metadata"
        ));
    }

    #[test]
    fn total_from_phases_saturates_on_overflow() {
        let mut r = sample_record("overflow", true);
        r.phase_durations = vec![
            PhaseDuration {
                phase: MigrationPhase::Assessment,
                duration_ms: u64::MAX,
            },
            PhaseDuration {
                phase: MigrationPhase::Deployment,
                duration_ms: 10,
            },
        ];

        assert_eq!(r.total_from_phases(), u64::MAX);
    }

    #[test]
    fn failure_rate_equal_to_threshold_is_not_exceeded() {
        let mut e = MigrationSpeedFailureMetrics::default();
        for i in 0..19 {
            e.record_migration(sample_record(&format!("s{i}"), true), &trace())
                .unwrap();
        }
        e.record_migration(sample_record("f-threshold", false), &trace())
            .unwrap();

        let r = e.generate_report(&trace());

        assert_eq!(r.total_migrations, 20);
        assert_eq!(r.failure_count, 1);
        assert!(!r.exceeds_threshold);
        assert!(
            !e.audit_log()
                .iter()
                .any(|entry| entry.event_code == event_codes::MSF_ERR_THRESHOLD_EXCEEDED)
        );
    }

    #[test]
    fn empty_audit_log_exports_empty_jsonl() {
        let e = MigrationSpeedFailureMetrics::default();

        assert_eq!(e.export_audit_log_jsonl().unwrap(), "");
    }

    #[test]
    fn blank_record_id_is_rejected_without_storage() {
        let mut e = MigrationSpeedFailureMetrics::default();
        let mut r = sample_record("blank-record", true);
        r.record_id.clear();

        let err = e.record_migration(r, "trace-blank-record").unwrap_err();

        assert!(err.contains("record_id"));
        assert!(e.records().is_empty());
        assert!(has_invalid_reason(&e, "empty record_id"));
    }

    #[test]
    fn whitespace_project_id_is_rejected_without_storage() {
        let mut e = MigrationSpeedFailureMetrics::default();
        let mut r = sample_record("blank-project", true);
        r.project_id = "   ".to_string();

        let err = e.record_migration(r, "trace-blank-project").unwrap_err();

        assert!(err.contains("project_id"));
        assert!(e.records().is_empty());
        assert!(has_invalid_reason(&e, "empty project_id"));
    }

    #[test]
    fn blank_window_id_is_rejected_without_storage() {
        let mut e = MigrationSpeedFailureMetrics::default();
        let mut r = sample_record("blank-window", true);
        r.window_id = "\t".to_string();

        let err = e.record_migration(r, "trace-blank-window").unwrap_err();

        assert!(err.contains("window_id"));
        assert!(e.records().is_empty());
        assert!(has_invalid_reason(&e, "empty window_id"));
    }

    #[test]
    fn duplicate_phase_duration_is_rejected() {
        let mut e = MigrationSpeedFailureMetrics::default();
        let mut r = sample_record("duplicate-phase", true);
        r.phase_durations[1].phase = r.phase_durations[0].phase;

        let err = e.record_migration(r, "trace-duplicate-phase").unwrap_err();

        assert!(err.contains("duplicate"));
        assert!(e.records().is_empty());
        assert!(has_invalid_reason(&e, "duplicate phase duration"));
    }

    #[test]
    fn missing_phase_duration_is_rejected() {
        let mut e = MigrationSpeedFailureMetrics::default();
        let mut r = sample_record("missing-phase", true);
        r.phase_durations.pop();

        let err = e.record_migration(r, "trace-missing-phase").unwrap_err();

        assert!(err.contains("cover every migration phase"));
        assert!(e.records().is_empty());
        assert!(has_invalid_reason(&e, "missing phase duration"));
    }

    #[test]
    fn rejected_missing_phase_preserves_existing_records() {
        let mut e = MigrationSpeedFailureMetrics::default();
        e.record_migration(sample_record("kept", true), &trace())
            .unwrap();
        let mut rejected = sample_record("missing-after-kept", true);
        rejected.phase_durations.pop();

        let err = e
            .record_migration(rejected, &trace())
            .expect_err("missing phase should fail");

        assert!(err.contains("cover every migration phase"));
        assert_eq!(e.records().len(), 1);
        assert_eq!(e.records()[0].record_id, "kept");
    }

    #[test]
    fn invalid_identifier_takes_precedence_over_phase_validation() {
        let mut e = MigrationSpeedFailureMetrics::default();
        let mut r = sample_record("precedence", true);
        r.record_id.clear();
        r.phase_durations.clear();

        let err = e.record_migration(r, "trace-precedence").unwrap_err();

        assert!(err.contains("record_id"));
        assert_eq!(e.audit_log().len(), 1);
        assert!(has_invalid_reason(&e, "empty record_id"));
        assert!(!has_invalid_reason(&e, "no phase durations"));
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
    fn phase_stats_change_hash_when_distribution_changes() {
        let mut e1 = MigrationSpeedFailureMetrics::default();
        let mut e2 = MigrationSpeedFailureMetrics::default();

        e1.record_migration(
            record_with_durations_and_failure("r1", [1000, 1000, 1000, 1000, 1000], None),
            &trace(),
        )
        .unwrap();
        e2.record_migration(
            record_with_durations_and_failure("r1", [2000, 1000, 1000, 500, 500], None),
            &trace(),
        )
        .unwrap();

        let r1 = e1.generate_report("t");
        let r2 = e2.generate_report("t");

        assert_eq!(r1.total_migrations, r2.total_migrations);
        assert_eq!(r1.success_count, r2.success_count);
        assert_eq!(r1.failure_count, r2.failure_count);
        assert_eq!(r1.avg_total_duration_ms, r2.avg_total_duration_ms);
        assert_eq!(r1.flagged_phases, r2.flagged_phases);
        assert_ne!(r1.phase_stats, r2.phase_stats);
        assert_ne!(r1.content_hash, r2.content_hash);
    }

    #[test]
    fn failure_stats_change_hash_when_distribution_changes() {
        let mut e1 = MigrationSpeedFailureMetrics::default();
        let mut e2 = MigrationSpeedFailureMetrics::default();

        e1.record_migration(
            record_with_durations_and_failure(
                "r1",
                [1000, 1000, 1000, 1000, 1000],
                Some(FailureType::RuntimeError),
            ),
            &trace(),
        )
        .unwrap();
        e1.record_migration(
            record_with_durations_and_failure(
                "r2",
                [1000, 1000, 1000, 1000, 1000],
                Some(FailureType::RuntimeError),
            ),
            &trace(),
        )
        .unwrap();

        e2.record_migration(
            record_with_durations_and_failure(
                "r1",
                [1000, 1000, 1000, 1000, 1000],
                Some(FailureType::RuntimeError),
            ),
            &trace(),
        )
        .unwrap();
        e2.record_migration(
            record_with_durations_and_failure(
                "r2",
                [1000, 1000, 1000, 1000, 1000],
                Some(FailureType::ApiIncompatibility),
            ),
            &trace(),
        )
        .unwrap();

        let r1 = e1.generate_report("t");
        let r2 = e2.generate_report("t");

        assert_eq!(r1.total_migrations, r2.total_migrations);
        assert_eq!(r1.success_count, r2.success_count);
        assert_eq!(r1.failure_count, r2.failure_count);
        assert_eq!(r1.failure_rate, r2.failure_rate);
        assert_eq!(r1.avg_total_duration_ms, r2.avg_total_duration_ms);
        assert_eq!(r1.phase_stats, r2.phase_stats);
        assert_eq!(r1.flagged_phases, r2.flagged_phases);
        assert_ne!(r1.failure_stats, r2.failure_stats);
        assert_ne!(r1.content_hash, r2.content_hash);
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
