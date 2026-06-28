//! Validation proof economics and SLO report for operator visibility.
//!
//! Provides deterministic machine-readable ledger explaining capacity consumption
//! and savings from validation proof work. Derives metrics from validation broker
//! status, proof coalescer decisions, debt ledger entries, and flight recorder
//! artifacts to report economics and SLO compliance.

use crate::ops::validation_broker::{ProofEvidenceSource, ValidationProofStatus};
use crate::ops::validation_proof_debt_ledger::{
    ValidationProofDebtClass, ValidationProofDebtLedger, ValidationProofDebtState,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const VALIDATION_PROOF_ECONOMICS_SCHEMA_VERSION: &str =
    "franken-node/validation-proof-economics/v1";

/// Deterministic validation proof economics and SLO report.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ValidationProofEconomicsReport {
    pub schema_version: String,
    pub generated_at: DateTime<Utc>,
    pub reporting_period: EconomicsReportingPeriod,
    pub summary: EconomicsSummary,
    pub slo_compliance: SloComplianceStatus,
    pub economics_breakdown: EconomicsBreakdown,
    pub groupings: EconomicsGroupings,
}

/// Time period covered by the economics report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EconomicsReportingPeriod {
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
    pub duration_seconds: u64,
}

/// High-level summary of economics and savings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EconomicsSummary {
    /// Total duplicate proofs avoided through coalescing.
    pub duplicate_proofs_avoided: usize,
    /// Estimated worker time saved in seconds from coalescing/reuse.
    pub worker_time_saved_seconds: u64,
    /// Current queue debt count (blocked/retryable proofs).
    pub queue_debt_count: usize,
    /// Number of stale producers detected.
    pub stale_producer_count: usize,
    /// Source-only blocker count preventing proof execution.
    pub source_only_blocker_count: usize,
    /// Product failure count (not worker infrastructure).
    pub product_failure_count: usize,
    /// Retryable worker infrastructure failure count.
    pub retryable_worker_infra_failure_count: usize,
    /// Number of proofs at risk of starvation.
    pub starvation_risk_count: usize,
    /// SLO breach count across all tracked metrics.
    pub slo_breach_count: usize,
}

/// SLO compliance status for validation proof work.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SloComplianceStatus {
    /// Overall SLO compliance health.
    pub overall_status: SloStatus,
    /// Per-SLO metric compliance details.
    pub slo_metrics: Vec<SloMetricStatus>,
}

/// SLO compliance status levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SloStatus {
    Compliant,
    Warning,
    Breach,
    Unknown,
}

/// Individual SLO metric compliance status.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SloMetricStatus {
    pub metric_name: String,
    pub target_value: f64,
    pub current_value: f64,
    pub status: SloStatus,
    pub breach_threshold: f64,
    pub warning_threshold: f64,
}

/// Economics breakdown by various dimensions.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EconomicsBreakdown {
    /// Savings from proof coalescing/reuse by evidence source.
    pub savings_by_evidence_source: BTreeMap<String, EconomicsSavings>,
    /// Debt breakdown by blocker class.
    pub debt_by_blocker_class: BTreeMap<String, DebtClassMetrics>,
    /// Failure breakdown by error class.
    pub failures_by_error_class: BTreeMap<String, FailureClassMetrics>,
}

/// Economic savings metrics for a specific category.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EconomicsSavings {
    pub duplicate_proofs_avoided: usize,
    pub estimated_time_saved_seconds: u64,
    pub reuse_count: usize,
    pub coalescing_count: usize,
}

/// Debt metrics for a specific blocker class.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DebtClassMetrics {
    pub blocked_count: usize,
    pub retryable_count: usize,
    pub total_debt: usize,
    pub average_age_seconds: f64,
    pub starvation_risk: bool,
}

/// Failure metrics for a specific error class.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FailureClassMetrics {
    pub failure_count: usize,
    pub retry_count: usize,
    pub success_after_retry_count: usize,
    pub permanent_failure_count: usize,
}

/// Stable groupings for economics analysis.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EconomicsGroupings {
    /// Economics grouped by bead ID.
    pub by_bead_id: BTreeMap<String, BeadEconomicsGroup>,
    /// Economics grouped by proof work key.
    pub by_proof_work_key: BTreeMap<String, ProofWorkKeyEconomicsGroup>,
    /// Economics grouped by agent.
    pub by_agent: BTreeMap<String, AgentEconomicsGroup>,
    /// Economics grouped by decision class.
    pub by_decision_class: BTreeMap<String, DecisionClassEconomicsGroup>,
}

/// Economics metrics grouped by bead ID.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BeadEconomicsGroup {
    pub bead_id: String,
    pub proof_count: usize,
    pub duplicate_avoided: usize,
    pub time_saved_seconds: u64,
    pub debt_count: usize,
    pub failure_count: usize,
    pub slo_breach_count: usize,
}

/// Economics metrics grouped by proof work key.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProofWorkKeyEconomicsGroup {
    pub proof_work_key: String,
    pub execution_count: usize,
    pub coalescing_savings: usize,
    pub cache_hit_count: usize,
    pub total_execution_time_seconds: u64,
    pub average_execution_time_seconds: f64,
}

/// Economics metrics grouped by agent.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AgentEconomicsGroup {
    pub agent: String,
    pub requests_submitted: usize,
    pub proofs_completed: usize,
    pub time_saved_from_coalescing: u64,
    pub debt_contributed: usize,
    pub failure_rate: f64,
}

/// Economics metrics grouped by decision class.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DecisionClassEconomicsGroup {
    pub decision_class: String,
    pub decision_count: usize,
    pub success_count: usize,
    pub failure_count: usize,
    pub average_decision_time_ms: f64,
    pub resource_utilization: f64,
}

/// Generator for validation proof economics reports.
pub struct ValidationProofEconomicsGenerator {
    /// SLO targets for various metrics.
    slo_targets: SloTargets,
}

/// SLO target configuration.
#[derive(Debug, Clone)]
pub struct SloTargets {
    pub max_queue_depth: usize,
    pub max_average_wait_time_seconds: f64,
    pub max_failure_rate: f64,
    pub max_debt_age_seconds: f64,
    pub min_coalescing_efficiency: f64,
}

impl Default for SloTargets {
    fn default() -> Self {
        Self {
            max_queue_depth: 100,
            max_average_wait_time_seconds: 300.0, // 5 minutes
            max_failure_rate: 0.05,               // 5%
            max_debt_age_seconds: 1800.0,         // 30 minutes
            min_coalescing_efficiency: 0.20,      // 20% savings
        }
    }
}

impl ValidationProofEconomicsGenerator {
    /// Create a new economics generator with default SLO targets.
    #[must_use]
    pub fn new() -> Self {
        Self {
            slo_targets: SloTargets::default(),
        }
    }

    /// Create a new economics generator with custom SLO targets.
    #[must_use]
    pub fn with_slo_targets(slo_targets: SloTargets) -> Self {
        Self { slo_targets }
    }

    /// Generate economics report from validation proof status entries.
    pub fn generate_report(
        &self,
        proof_statuses: &[ValidationProofStatus],
        debt_ledger: &ValidationProofDebtLedger,
        reporting_period: EconomicsReportingPeriod,
    ) -> ValidationProofEconomicsReport {
        let generated_at = Utc::now();

        // Calculate summary metrics
        let summary = self.calculate_summary(proof_statuses, debt_ledger, generated_at);

        // Check SLO compliance
        let slo_compliance = self.calculate_slo_compliance(&summary, proof_statuses);

        // Generate economics breakdown
        let economics_breakdown =
            self.calculate_economics_breakdown(proof_statuses, debt_ledger, generated_at);

        // Generate stable groupings
        let groupings = self.calculate_groupings(proof_statuses, debt_ledger);

        ValidationProofEconomicsReport {
            schema_version: VALIDATION_PROOF_ECONOMICS_SCHEMA_VERSION.to_string(),
            generated_at,
            reporting_period,
            summary,
            slo_compliance,
            economics_breakdown,
            groupings,
        }
    }

    fn calculate_summary(
        &self,
        proof_statuses: &[ValidationProofStatus],
        debt_ledger: &ValidationProofDebtLedger,
        generated_at: DateTime<Utc>,
    ) -> EconomicsSummary {
        let mut duplicate_proofs_avoided = 0usize;
        let mut worker_time_saved_seconds = 0u64;
        let mut stale_producer_count = 0usize;
        let mut source_only_blocker_count = 0usize;
        let mut product_failure_count = 0usize;
        let mut retryable_worker_infra_failure_count = 0usize;
        let mut starvation_risk_count = 0usize;

        // Analyze proof statuses for economics
        for status in proof_statuses {
            if status.deduplicated {
                duplicate_proofs_avoided = duplicate_proofs_avoided.saturating_add(1);
                // Estimate time saved: assume average proof takes 60 seconds
                worker_time_saved_seconds = worker_time_saved_seconds.saturating_add(60);
            }

            // Count failures by type
            match status.proof_source {
                ProofEvidenceSource::CoalescerRejected => {
                    product_failure_count = product_failure_count.saturating_add(1);
                }
                ProofEvidenceSource::Unknown => {
                    retryable_worker_infra_failure_count =
                        retryable_worker_infra_failure_count.saturating_add(1);
                }
                ProofEvidenceSource::SourceOnlyFallback => {
                    source_only_blocker_count = source_only_blocker_count.saturating_add(1);
                }
                _ => {}
            }
        }

        // Analyze debt ledger for additional metrics
        let queue_debt_count = debt_ledger.entries.len();

        for entry in &debt_ledger.entries {
            if matches!(entry.debt_class, ValidationProofDebtClass::StaleLease) {
                stale_producer_count = stale_producer_count.saturating_add(1);
            }

            // Check for starvation risk (debt older than threshold)
            let age_seconds = (generated_at - entry.observed_at).num_seconds().max(0) as u64;
            if age_seconds > self.slo_targets.max_debt_age_seconds as u64 {
                starvation_risk_count = starvation_risk_count.saturating_add(1);
            }
        }

        // Calculate SLO breaches (simplified for now)
        let slo_breach_count = if queue_debt_count > self.slo_targets.max_queue_depth {
            1
        } else {
            0
        };

        EconomicsSummary {
            duplicate_proofs_avoided,
            worker_time_saved_seconds,
            queue_debt_count,
            stale_producer_count,
            source_only_blocker_count,
            product_failure_count,
            retryable_worker_infra_failure_count,
            starvation_risk_count,
            slo_breach_count,
        }
    }

    fn calculate_slo_compliance(
        &self,
        summary: &EconomicsSummary,
        proof_statuses: &[ValidationProofStatus],
    ) -> SloComplianceStatus {
        let mut slo_metrics = Vec::new();

        // Queue depth SLO
        let queue_depth_status = if summary.queue_debt_count > self.slo_targets.max_queue_depth {
            SloStatus::Breach
        } else if summary.queue_debt_count > (self.slo_targets.max_queue_depth * 80 / 100) {
            SloStatus::Warning
        } else {
            SloStatus::Compliant
        };

        slo_metrics.push(SloMetricStatus {
            metric_name: "queue_depth".to_string(),
            target_value: self.slo_targets.max_queue_depth as f64,
            current_value: summary.queue_debt_count as f64,
            status: queue_depth_status,
            breach_threshold: self.slo_targets.max_queue_depth as f64,
            warning_threshold: (self.slo_targets.max_queue_depth * 80 / 100) as f64,
        });

        // Failure rate SLO
        let total_proofs = proof_statuses.len();
        let failure_rate = if total_proofs > 0 {
            (summary.product_failure_count + summary.retryable_worker_infra_failure_count) as f64
                / total_proofs as f64
        } else {
            0.0
        };

        let failure_rate_status = if failure_rate > self.slo_targets.max_failure_rate {
            SloStatus::Breach
        } else if failure_rate > (self.slo_targets.max_failure_rate * 0.8) {
            SloStatus::Warning
        } else {
            SloStatus::Compliant
        };

        slo_metrics.push(SloMetricStatus {
            metric_name: "failure_rate".to_string(),
            target_value: self.slo_targets.max_failure_rate,
            current_value: failure_rate,
            status: failure_rate_status,
            breach_threshold: self.slo_targets.max_failure_rate,
            warning_threshold: self.slo_targets.max_failure_rate * 0.8,
        });

        // Determine overall status
        let overall_status = if slo_metrics.iter().any(|m| m.status == SloStatus::Breach) {
            SloStatus::Breach
        } else if slo_metrics.iter().any(|m| m.status == SloStatus::Warning) {
            SloStatus::Warning
        } else {
            SloStatus::Compliant
        };

        SloComplianceStatus {
            overall_status,
            slo_metrics,
        }
    }

    fn calculate_economics_breakdown(
        &self,
        proof_statuses: &[ValidationProofStatus],
        debt_ledger: &ValidationProofDebtLedger,
        generated_at: DateTime<Utc>,
    ) -> EconomicsBreakdown {
        let mut savings_by_evidence_source = BTreeMap::new();
        let mut debt_by_blocker_class = BTreeMap::new();
        let failures_by_error_class = BTreeMap::new();

        // Analyze savings by evidence source
        for status in proof_statuses {
            let source_key = status.proof_source.as_str().to_string();
            let savings = savings_by_evidence_source
                .entry(source_key)
                .or_insert_with(|| EconomicsSavings {
                    duplicate_proofs_avoided: 0,
                    estimated_time_saved_seconds: 0,
                    reuse_count: 0,
                    coalescing_count: 0,
                });

            if status.deduplicated {
                savings.duplicate_proofs_avoided =
                    savings.duplicate_proofs_avoided.saturating_add(1);
                savings.estimated_time_saved_seconds =
                    savings.estimated_time_saved_seconds.saturating_add(60);
            }

            match status.proof_source {
                ProofEvidenceSource::ProofCacheHit => {
                    savings.reuse_count = savings.reuse_count.saturating_add(1);
                }
                ProofEvidenceSource::CoalescedCompleted => {
                    savings.coalescing_count = savings.coalescing_count.saturating_add(1);
                }
                _ => {}
            }
        }

        // Analyze debt by blocker class
        for entry in &debt_ledger.entries {
            let class_key = entry.debt_class.as_str().to_string();
            let metrics =
                debt_by_blocker_class
                    .entry(class_key)
                    .or_insert_with(|| DebtClassMetrics {
                        blocked_count: 0,
                        retryable_count: 0,
                        total_debt: 0,
                        average_age_seconds: 0.0,
                        starvation_risk: false,
                    });

            metrics.total_debt = metrics.total_debt.saturating_add(1);

            match entry.debt_state {
                ValidationProofDebtState::Blocked => {
                    metrics.blocked_count = metrics.blocked_count.saturating_add(1);
                }
                ValidationProofDebtState::Retryable => {
                    metrics.retryable_count = metrics.retryable_count.saturating_add(1);
                }
                ValidationProofDebtState::Informational => {}
            }

            let age_seconds = (generated_at - entry.observed_at).num_seconds().max(0) as u64;
            if age_seconds > self.slo_targets.max_debt_age_seconds as u64 {
                metrics.starvation_risk = true;
            }
        }

        // Calculate average ages
        for entry in &debt_ledger.entries {
            let class_key = entry.debt_class.as_str().to_string();
            if let Some(metrics) = debt_by_blocker_class.get_mut(&class_key)
                && metrics.total_debt > 0
            {
                let age_seconds = (generated_at - entry.observed_at).num_seconds().max(0) as f64;
                metrics.average_age_seconds = (metrics.average_age_seconds
                    * (metrics.total_debt.saturating_sub(1)) as f64
                    + age_seconds)
                    / metrics.total_debt as f64;
            }
        }

        EconomicsBreakdown {
            savings_by_evidence_source,
            debt_by_blocker_class,
            failures_by_error_class,
        }
    }

    fn calculate_groupings(
        &self,
        proof_statuses: &[ValidationProofStatus],
        debt_ledger: &ValidationProofDebtLedger,
    ) -> EconomicsGroupings {
        let mut by_bead_id = BTreeMap::new();
        let by_proof_work_key = BTreeMap::new();
        let by_agent = BTreeMap::new();
        let by_decision_class = BTreeMap::new();

        // Group by bead ID
        for status in proof_statuses {
            let group =
                by_bead_id
                    .entry(status.bead_id.clone())
                    .or_insert_with(|| BeadEconomicsGroup {
                        bead_id: status.bead_id.clone(),
                        proof_count: 0,
                        duplicate_avoided: 0,
                        time_saved_seconds: 0,
                        debt_count: 0,
                        failure_count: 0,
                        slo_breach_count: 0,
                    });

            group.proof_count = group.proof_count.saturating_add(1);

            if status.deduplicated {
                group.duplicate_avoided = group.duplicate_avoided.saturating_add(1);
                group.time_saved_seconds = group.time_saved_seconds.saturating_add(60);
            }

            match status.proof_source {
                ProofEvidenceSource::CoalescerRejected | ProofEvidenceSource::Unknown => {
                    group.failure_count = group.failure_count.saturating_add(1);
                }
                _ => {}
            }
        }

        // Add debt counts to bead groups
        for entry in &debt_ledger.entries {
            if let Some(group) = by_bead_id.get_mut(&entry.bead_id) {
                group.debt_count = group.debt_count.saturating_add(1);
            }
        }

        EconomicsGroupings {
            by_bead_id,
            by_proof_work_key,
            by_agent,
            by_decision_class,
        }
    }
}

impl Default for ValidationProofEconomicsGenerator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ops::validation_broker::{
        DigestRef, ProofStatusKind, QueueState, TimeoutClass, ValidationErrorClass, ValidationExit,
        ValidationExitKind,
    };
    use crate::ops::validation_proof_debt_ledger::{
        ValidationProofDebtLedgerEntry, ValidationProofDebtLedgerSummary,
    };

    fn sample_proof_status(
        bead_id: &str,
        deduplicated: bool,
        source: ProofEvidenceSource,
    ) -> ValidationProofStatus {
        ValidationProofStatus {
            schema_version: "test-v1".to_string(),
            bead_id: bead_id.to_string(),
            thread_id: "test-thread".to_string(),
            request_id: Some("test-request".to_string()),
            queue_id: Some("test-queue".to_string()),
            status: ProofStatusKind::Passed,
            proof_source: source,
            queue_state: Some(QueueState::Completed),
            deduplicated,
            queue_depth: 0,
            artifact_paths: None,
            command_digest: Some(DigestRef::sha256(bead_id.as_bytes())),
            exit: Some(ValidationExit {
                kind: ValidationExitKind::Success,
                code: Some(0),
                signal: None,
                timeout_class: TimeoutClass::None,
                error_class: ValidationErrorClass::None,
                retryable: false,
            }),
            reason: None,
            proof_coalescer: None,
            proof_cache: None,
            readiness_ref: None,
            flight_recorder_ref: None,
            observed_at: Utc::now(),
        }
    }

    fn sample_debt_ledger() -> ValidationProofDebtLedger {
        ValidationProofDebtLedger {
            schema_version: "test-v1".to_string(),
            generated_at: Utc::now(),
            summary: ValidationProofDebtLedgerSummary {
                total_entries: 2,
                retryable_entries: 1,
                blocked_entries: 1,
                stale_entries: 0,
                product_failures: 0,
                source_only_fallbacks: 0,
                proof_cache_reuses: 0,
                entries_blocking_other_beads: 0,
                by_class: BTreeMap::new(),
            },
            entries: vec![
                ValidationProofDebtLedgerEntry {
                    bead_id: "test-bead-1".to_string(),
                    thread_id: "thread-1".to_string(),
                    request_id: Some("req-1".to_string()),
                    queue_id: Some("queue-1".to_string()),
                    owner_agent: Some("agent-1".to_string()),
                    producer_bead_id: None,
                    debt_class: ValidationProofDebtClass::CargoContention,
                    debt_state: ValidationProofDebtState::Blocked,
                    freshness: crate::ops::validation_proof_debt_ledger::ValidationProofDebtFreshness::Fresh,
                    status: "blocked".to_string(),
                    proof_source: "fresh_execution".to_string(),
                    queue_state: Some("waiting".to_string()),
                    deduplicated: false,
                    retryable: true,
                    product_failure: false,
                    blocks_other_bead: false,
                    command_digest_hex: Some("abcd".to_string()),
                    latest_recorder_path: Some("/tmp/recorder.log".to_string()),
                    receipt_path: None,
                    cache_key_hex: None,
                    worker_id: Some("worker-1".to_string()),
                    reason_code: Some("cargo_contention".to_string()),
                    event_code: Some("lock_wait".to_string()),
                    required_action: "retry_later".to_string(),
                    diagnostic: "cargo lock contention".to_string(),
                    freshness_expires_at: None,
                    observed_at: Utc::now() - chrono::Duration::seconds(3600),
                },
                ValidationProofDebtLedgerEntry {
                    bead_id: "test-bead-2".to_string(),
                    thread_id: "thread-2".to_string(),
                    request_id: Some("req-2".to_string()),
                    queue_id: Some("queue-2".to_string()),
                    owner_agent: Some("agent-2".to_string()),
                    producer_bead_id: None,
                    debt_class: ValidationProofDebtClass::WorkerInfra,
                    debt_state: ValidationProofDebtState::Retryable,
                    freshness: crate::ops::validation_proof_debt_ledger::ValidationProofDebtFreshness::Fresh,
                    status: "retryable".to_string(),
                    proof_source: "worker_failure".to_string(),
                    queue_state: Some("retry_queue".to_string()),
                    deduplicated: false,
                    retryable: true,
                    product_failure: false,
                    blocks_other_bead: false,
                    command_digest_hex: Some("efgh".to_string()),
                    latest_recorder_path: Some("/tmp/recorder2.log".to_string()),
                    receipt_path: None,
                    cache_key_hex: None,
                    worker_id: Some("worker-2".to_string()),
                    reason_code: Some("worker_timeout".to_string()),
                    event_code: Some("ssh_timeout".to_string()),
                    required_action: "retry_with_backoff".to_string(),
                    diagnostic: "worker ssh timeout".to_string(),
                    freshness_expires_at: None,
                    observed_at: Utc::now() - chrono::Duration::seconds(900),
                },
            ],
        }
    }

    #[test]
    fn test_economics_generator_creation() {
        let generator = ValidationProofEconomicsGenerator::new();
        assert_eq!(generator.slo_targets.max_queue_depth, 100);

        let custom_generator = ValidationProofEconomicsGenerator::with_slo_targets(SloTargets {
            max_queue_depth: 200,
            ..SloTargets::default()
        });
        assert_eq!(custom_generator.slo_targets.max_queue_depth, 200);
    }

    #[test]
    fn test_economics_report_generation() {
        let generator = ValidationProofEconomicsGenerator::new();

        let proof_statuses = vec![
            sample_proof_status("test-bead-1", true, ProofEvidenceSource::CoalescedCompleted),
            sample_proof_status("test-bead-2", false, ProofEvidenceSource::CoalescerRejected),
            sample_proof_status("test-bead-3", true, ProofEvidenceSource::ProofCacheHit),
        ];

        let debt_ledger = sample_debt_ledger();

        let reporting_period = EconomicsReportingPeriod {
            start_time: Utc::now() - chrono::Duration::hours(1),
            end_time: Utc::now(),
            duration_seconds: 3600,
        };

        let report = generator.generate_report(&proof_statuses, &debt_ledger, reporting_period);

        assert_eq!(
            report.schema_version,
            VALIDATION_PROOF_ECONOMICS_SCHEMA_VERSION
        );
        assert_eq!(report.summary.duplicate_proofs_avoided, 2);
        assert_eq!(report.summary.worker_time_saved_seconds, 120); // 2 * 60 seconds
        assert_eq!(report.summary.queue_debt_count, 2);
        assert_eq!(report.summary.product_failure_count, 1);
    }

    #[test]
    fn test_slo_compliance_calculation() {
        let generator = ValidationProofEconomicsGenerator::with_slo_targets(SloTargets {
            max_queue_depth: 1, // Set low to trigger breach
            max_failure_rate: 0.1,
            ..SloTargets::default()
        });

        let proof_statuses = vec![sample_proof_status(
            "test-bead-1",
            false,
            ProofEvidenceSource::CoalescerRejected,
        )];

        let debt_ledger = sample_debt_ledger(); // Has 2 entries

        let reporting_period = EconomicsReportingPeriod {
            start_time: Utc::now() - chrono::Duration::hours(1),
            end_time: Utc::now(),
            duration_seconds: 3600,
        };

        let report = generator.generate_report(&proof_statuses, &debt_ledger, reporting_period);

        // Queue depth should be in breach (2 > 1)
        assert_eq!(report.slo_compliance.overall_status, SloStatus::Breach);

        let queue_depth_metric = report
            .slo_compliance
            .slo_metrics
            .iter()
            .find(|m| m.metric_name == "queue_depth")
            .expect("queue_depth metric should exist");

        assert_eq!(queue_depth_metric.status, SloStatus::Breach);
        assert_eq!(queue_depth_metric.current_value, 2.0);
    }

    #[test]
    fn test_economics_breakdown() {
        let generator = ValidationProofEconomicsGenerator::new();

        let proof_statuses = vec![
            sample_proof_status("test-bead-1", true, ProofEvidenceSource::CoalescedCompleted),
            sample_proof_status("test-bead-2", false, ProofEvidenceSource::ProofCacheHit),
        ];

        let debt_ledger = sample_debt_ledger();

        let reporting_period = EconomicsReportingPeriod {
            start_time: Utc::now() - chrono::Duration::hours(1),
            end_time: Utc::now(),
            duration_seconds: 3600,
        };

        let report = generator.generate_report(&proof_statuses, &debt_ledger, reporting_period);

        // Check savings by evidence source
        // Key is `ProofEvidenceSource::as_str()` (snake_case, validation_broker.rs:293),
        // not the PascalCase variant name.
        let coalescing_savings = report
            .economics_breakdown
            .savings_by_evidence_source
            .get("coalesced_completed")
            .expect("Coalescing savings should exist");

        assert_eq!(coalescing_savings.duplicate_proofs_avoided, 1);
        assert_eq!(coalescing_savings.coalescing_count, 1);

        // Check debt by blocker class
        let cargo_contention_debt = report
            .economics_breakdown
            .debt_by_blocker_class
            .get("cargo_contention")
            .expect("CargoContention debt should exist");

        assert_eq!(cargo_contention_debt.total_debt, 1);
        assert_eq!(cargo_contention_debt.blocked_count, 1);
    }

    #[test]
    fn test_groupings_by_bead_id() {
        let generator = ValidationProofEconomicsGenerator::new();

        let proof_statuses = vec![
            sample_proof_status("bead-a", true, ProofEvidenceSource::CoalescedCompleted),
            sample_proof_status("bead-a", false, ProofEvidenceSource::FreshExecution),
            sample_proof_status("bead-b", true, ProofEvidenceSource::ProofCacheHit),
        ];

        let debt_ledger = sample_debt_ledger();

        let reporting_period = EconomicsReportingPeriod {
            start_time: Utc::now() - chrono::Duration::hours(1),
            end_time: Utc::now(),
            duration_seconds: 3600,
        };

        let report = generator.generate_report(&proof_statuses, &debt_ledger, reporting_period);

        // Check bead-a grouping
        let bead_a_group = report
            .groupings
            .by_bead_id
            .get("bead-a")
            .expect("bead-a group should exist");

        assert_eq!(bead_a_group.proof_count, 2);
        assert_eq!(bead_a_group.duplicate_avoided, 1);
        assert_eq!(bead_a_group.time_saved_seconds, 60);

        // Check bead-b grouping
        let bead_b_group = report
            .groupings
            .by_bead_id
            .get("bead-b")
            .expect("bead-b group should exist");

        assert_eq!(bead_b_group.proof_count, 1);
        assert_eq!(bead_b_group.duplicate_avoided, 1);
        assert_eq!(bead_b_group.time_saved_seconds, 60);
    }
}
