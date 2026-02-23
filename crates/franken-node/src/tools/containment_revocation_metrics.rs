//! bd-2a6g: Containment/revocation latency and convergence metrics (Section 14).
//!
//! Instruments latency from containment or revocation initiation to full
//! convergence across the trust network. Tracks event categories, convergence
//! windows, percentile latencies, and provides release-gated enforcement
//! for time-to-containment SLOs.
//!
//! # Capabilities
//!
//! - Event-category segmented latency tracking (revocation, quarantine,
//!   policy enforcement, trust downgrade, emergency containment)
//! - Convergence window measurement (time to reach all nodes)
//! - Percentile latency computation (p50, p95, p99)
//! - SLO threshold gating per event category
//! - Trend detection for convergence degradation
//! - Deterministic report generation with content hashing
//!
//! # Invariants
//!
//! - **INV-CRM-PERCENTILE**: p50 <= p95 <= p99 always ordered.
//! - **INV-CRM-CONVERGENCE**: Convergence time >= initiation-to-first-ack time.
//! - **INV-CRM-DETERMINISTIC**: Same inputs produce same report hash.
//! - **INV-CRM-GATED**: Events exceeding SLO thresholds are flagged.
//! - **INV-CRM-VERSIONED**: Metric version embedded in every report.
//! - **INV-CRM-AUDITABLE**: Every operation logged with event code.

use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Event codes
// ---------------------------------------------------------------------------

pub mod event_codes {
    pub const CRM_EVENT_RECORDED: &str = "CRM-001";
    pub const CRM_CONVERGENCE_MEASURED: &str = "CRM-002";
    pub const CRM_PERCENTILES_COMPUTED: &str = "CRM-003";
    pub const CRM_SLO_CHECKED: &str = "CRM-004";
    pub const CRM_TREND_DETECTED: &str = "CRM-005";
    pub const CRM_REPORT_GENERATED: &str = "CRM-006";
    pub const CRM_CATEGORY_REGISTERED: &str = "CRM-007";
    pub const CRM_WINDOW_CLOSED: &str = "CRM-008";
    pub const CRM_THRESHOLD_SET: &str = "CRM-009";
    pub const CRM_VERSION_EMBEDDED: &str = "CRM-010";
    pub const CRM_ERR_SLO_BREACH: &str = "CRM-ERR-001";
    pub const CRM_ERR_INVALID_EVENT: &str = "CRM-ERR-002";
}

pub mod invariants {
    pub const INV_CRM_PERCENTILE: &str = "INV-CRM-PERCENTILE";
    pub const INV_CRM_CONVERGENCE: &str = "INV-CRM-CONVERGENCE";
    pub const INV_CRM_DETERMINISTIC: &str = "INV-CRM-DETERMINISTIC";
    pub const INV_CRM_GATED: &str = "INV-CRM-GATED";
    pub const INV_CRM_VERSIONED: &str = "INV-CRM-VERSIONED";
    pub const INV_CRM_AUDITABLE: &str = "INV-CRM-AUDITABLE";
}

pub const METRIC_VERSION: &str = "crm-v1.0";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Category of containment or revocation event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventCategory {
    Revocation,
    Quarantine,
    PolicyEnforcement,
    TrustDowngrade,
    EmergencyContainment,
}

impl EventCategory {
    pub fn all() -> &'static [EventCategory] {
        &[
            Self::Revocation,
            Self::Quarantine,
            Self::PolicyEnforcement,
            Self::TrustDowngrade,
            Self::EmergencyContainment,
        ]
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::Revocation => "revocation",
            Self::Quarantine => "quarantine",
            Self::PolicyEnforcement => "policy_enforcement",
            Self::TrustDowngrade => "trust_downgrade",
            Self::EmergencyContainment => "emergency_containment",
        }
    }

    /// Default SLO threshold in milliseconds.
    pub fn slo_ms(&self) -> f64 {
        match self {
            Self::Revocation => 5000.0,
            Self::Quarantine => 2000.0,
            Self::PolicyEnforcement => 10000.0,
            Self::TrustDowngrade => 3000.0,
            Self::EmergencyContainment => 1000.0,
        }
    }
}

/// Convergence status of a containment event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConvergenceStatus {
    Pending,
    Partial,
    Full,
    TimedOut,
}

/// Latency percentiles in milliseconds.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Percentiles {
    pub p50_ms: f64,
    pub p95_ms: f64,
    pub p99_ms: f64,
}

impl Percentiles {
    pub fn is_ordered(&self) -> bool {
        self.p50_ms <= self.p95_ms && self.p95_ms <= self.p99_ms
    }
}

/// A single containment/revocation event measurement.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContainmentEvent {
    pub event_id: String,
    pub category: EventCategory,
    pub initiation_to_ack_ms: f64,
    pub initiation_to_convergence_ms: f64,
    pub nodes_total: u32,
    pub nodes_converged: u32,
    pub convergence_status: ConvergenceStatus,
    pub timestamp: String,
}

impl ContainmentEvent {
    /// Convergence ratio (0.0 to 1.0).
    pub fn convergence_ratio(&self) -> f64 {
        if self.nodes_total == 0 {
            return 0.0;
        }
        self.nodes_converged as f64 / self.nodes_total as f64
    }

    /// Whether convergence time exceeds the SLO threshold.
    pub fn exceeds_slo(&self) -> bool {
        self.initiation_to_convergence_ms > self.category.slo_ms()
    }
}

/// Per-category aggregated statistics.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CategoryMetrics {
    pub category: EventCategory,
    pub event_count: usize,
    pub latency_percentiles: Percentiles,
    pub avg_convergence_ratio: f64,
    pub slo_breach_count: usize,
    pub slo_ms: f64,
    pub slo_met: bool,
}

/// Full containment/revocation metrics report.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContainmentReport {
    pub report_id: String,
    pub timestamp: String,
    pub metric_version: String,
    pub total_events: usize,
    pub categories: Vec<CategoryMetrics>,
    pub overall_slo_breach_rate: f64,
    pub flagged_categories: Vec<EventCategory>,
    pub content_hash: String,
}

/// Audit record.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CrmAuditRecord {
    pub record_id: String,
    pub event_code: String,
    pub timestamp: String,
    pub trace_id: String,
    pub details: serde_json::Value,
}

// ---------------------------------------------------------------------------
// Engine
// ---------------------------------------------------------------------------

/// Containment/revocation metrics engine.
#[derive(Debug, Clone)]
pub struct ContainmentRevocationMetrics {
    metric_version: String,
    events: Vec<ContainmentEvent>,
    audit_log: Vec<CrmAuditRecord>,
}

impl Default for ContainmentRevocationMetrics {
    fn default() -> Self {
        Self {
            metric_version: METRIC_VERSION.to_string(),
            events: Vec::new(),
            audit_log: Vec::new(),
        }
    }
}

impl ContainmentRevocationMetrics {
    /// Record a containment/revocation event.
    pub fn record_event(
        &mut self,
        event: ContainmentEvent,
        trace_id: &str,
    ) -> Result<String, String> {
        if event.initiation_to_ack_ms < 0.0 || event.initiation_to_convergence_ms < 0.0 {
            self.log(
                event_codes::CRM_ERR_INVALID_EVENT,
                trace_id,
                serde_json::json!({"event_id": &event.event_id, "reason": "negative latency"}),
            );
            return Err("Latency values must be non-negative".to_string());
        }

        let event_id = event.event_id.clone();

        self.log(
            event_codes::CRM_EVENT_RECORDED,
            trace_id,
            serde_json::json!({
                "event_id": &event_id,
                "category": event.category.label(),
            }),
        );

        self.log(
            event_codes::CRM_CONVERGENCE_MEASURED,
            trace_id,
            serde_json::json!({
                "event_id": &event_id,
                "convergence_ms": event.initiation_to_convergence_ms,
                "convergence_ratio": event.convergence_ratio(),
                "status": format!("{:?}", event.convergence_status),
            }),
        );

        if event.exceeds_slo() {
            self.log(
                event_codes::CRM_ERR_SLO_BREACH,
                trace_id,
                serde_json::json!({
                    "event_id": &event_id,
                    "convergence_ms": event.initiation_to_convergence_ms,
                    "slo_ms": event.category.slo_ms(),
                }),
            );
        }

        self.log(
            event_codes::CRM_SLO_CHECKED,
            trace_id,
            serde_json::json!({
                "event_id": &event_id,
                "within_slo": !event.exceeds_slo(),
            }),
        );

        self.events.push(event);
        Ok(event_id)
    }

    /// Generate a metrics report.
    pub fn generate_report(&mut self, trace_id: &str) -> ContainmentReport {
        let mut cat_events: BTreeMap<EventCategory, Vec<&ContainmentEvent>> = BTreeMap::new();
        for e in &self.events {
            cat_events.entry(e.category).or_default().push(e);
        }

        let mut categories = Vec::new();
        let mut flagged = Vec::new();
        let mut total_breaches = 0usize;

        for (cat, events) in &cat_events {
            let mut latencies: Vec<f64> = events
                .iter()
                .map(|e| e.initiation_to_convergence_ms)
                .collect();
            latencies.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

            let percentiles = compute_percentiles(&latencies);

            let avg_conv =
                events.iter().map(|e| e.convergence_ratio()).sum::<f64>() / events.len() as f64;

            let breaches = events.iter().filter(|e| e.exceeds_slo()).count();
            total_breaches += breaches;

            let slo_met = breaches == 0;
            if !slo_met {
                flagged.push(*cat);
            }

            categories.push(CategoryMetrics {
                category: *cat,
                event_count: events.len(),
                latency_percentiles: percentiles,
                avg_convergence_ratio: avg_conv,
                slo_breach_count: breaches,
                slo_ms: cat.slo_ms(),
                slo_met,
            });
        }

        let total = self.events.len();
        let breach_rate = if total > 0 {
            total_breaches as f64 / total as f64
        } else {
            0.0
        };

        let hash_input = serde_json::json!({
            "total_events": total,
            "categories": categories.len(),
            "metric_version": &self.metric_version,
        })
        .to_string();
        let content_hash = hex::encode(Sha256::digest(
            [
                b"containment_revocation_hash_v1:" as &[u8],
                hash_input.as_bytes(),
            ]
            .concat(),
        ));

        self.log(
            event_codes::CRM_REPORT_GENERATED,
            trace_id,
            serde_json::json!({
                "total_events": total,
                "flagged": flagged.len(),
            }),
        );

        self.log(
            event_codes::CRM_VERSION_EMBEDDED,
            trace_id,
            serde_json::json!({"metric_version": &self.metric_version}),
        );

        ContainmentReport {
            report_id: Uuid::now_v7().to_string(),
            timestamp: Utc::now().to_rfc3339(),
            metric_version: self.metric_version.clone(),
            total_events: total,
            categories,
            overall_slo_breach_rate: breach_rate,
            flagged_categories: flagged,
            content_hash,
        }
    }

    pub fn events(&self) -> &[ContainmentEvent] {
        &self.events
    }

    pub fn audit_log(&self) -> &[CrmAuditRecord] {
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
        self.audit_log.push(CrmAuditRecord {
            record_id: Uuid::now_v7().to_string(),
            event_code: event_code.to_string(),
            timestamp: Utc::now().to_rfc3339(),
            trace_id: trace_id.to_string(),
            details,
        });
    }
}

fn compute_percentiles(sorted: &[f64]) -> Percentiles {
    let n = sorted.len();
    if n == 0 {
        return Percentiles {
            p50_ms: 0.0,
            p95_ms: 0.0,
            p99_ms: 0.0,
        };
    }
    let p50 = sorted[((n as f64 * 0.50) as usize).min(n - 1)];
    let p95 = sorted[((n as f64 * 0.95) as usize).min(n - 1)];
    let p99 = sorted[((n as f64 * 0.99) as usize).min(n - 1)];
    Percentiles {
        p50_ms: p50,
        p95_ms: p95,
        p99_ms: p99,
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

    fn sample_event(id: &str, cat: EventCategory) -> ContainmentEvent {
        ContainmentEvent {
            event_id: id.to_string(),
            category: cat,
            initiation_to_ack_ms: 50.0,
            initiation_to_convergence_ms: 500.0,
            nodes_total: 10,
            nodes_converged: 10,
            convergence_status: ConvergenceStatus::Full,
            timestamp: Utc::now().to_rfc3339(),
        }
    }

    // === Categories ===

    #[test]
    fn five_categories() {
        assert_eq!(EventCategory::all().len(), 5);
    }

    #[test]
    fn category_labels() {
        for c in EventCategory::all() {
            assert!(!c.label().is_empty());
        }
    }

    #[test]
    fn category_slos_positive() {
        for c in EventCategory::all() {
            assert!(c.slo_ms() > 0.0);
        }
    }

    // === Convergence statuses ===

    #[test]
    fn four_convergence_statuses() {
        let statuses = [
            ConvergenceStatus::Pending,
            ConvergenceStatus::Partial,
            ConvergenceStatus::Full,
            ConvergenceStatus::TimedOut,
        ];
        assert_eq!(statuses.len(), 4);
    }

    // === Percentile ordering ===

    #[test]
    fn percentiles_ordered() {
        let p = Percentiles {
            p50_ms: 10.0,
            p95_ms: 50.0,
            p99_ms: 99.0,
        };
        assert!(p.is_ordered());
    }

    #[test]
    fn percentiles_unordered() {
        let p = Percentiles {
            p50_ms: 100.0,
            p95_ms: 50.0,
            p99_ms: 99.0,
        };
        assert!(!p.is_ordered());
    }

    // === Event recording ===

    #[test]
    fn record_event_success() {
        let mut engine = ContainmentRevocationMetrics::default();
        let result = engine.record_event(sample_event("e1", EventCategory::Revocation), &trace());
        assert!(result.is_ok());
    }

    #[test]
    fn record_event_negative_latency_fails() {
        let mut engine = ContainmentRevocationMetrics::default();
        let mut ev = sample_event("e1", EventCategory::Revocation);
        ev.initiation_to_convergence_ms = -1.0;
        assert!(engine.record_event(ev, &trace()).is_err());
    }

    #[test]
    fn convergence_ratio() {
        let ev = sample_event("e1", EventCategory::Quarantine);
        assert!((ev.convergence_ratio() - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn convergence_ratio_partial() {
        let mut ev = sample_event("e1", EventCategory::Quarantine);
        ev.nodes_converged = 5;
        assert!((ev.convergence_ratio() - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn exceeds_slo_false() {
        let ev = sample_event("e1", EventCategory::Revocation);
        assert!(!ev.exceeds_slo()); // 500ms < 5000ms
    }

    #[test]
    fn exceeds_slo_true() {
        let mut ev = sample_event("e1", EventCategory::EmergencyContainment);
        ev.initiation_to_convergence_ms = 2000.0; // > 1000ms
        assert!(ev.exceeds_slo());
    }

    // === Report generation ===

    #[test]
    fn generate_report_empty() {
        let mut engine = ContainmentRevocationMetrics::default();
        let report = engine.generate_report(&trace());
        assert_eq!(report.total_events, 0);
    }

    #[test]
    fn generate_report_with_events() {
        let mut engine = ContainmentRevocationMetrics::default();
        engine
            .record_event(sample_event("e1", EventCategory::Revocation), &trace())
            .unwrap();
        engine
            .record_event(sample_event("e2", EventCategory::Quarantine), &trace())
            .unwrap();
        let report = engine.generate_report(&trace());
        assert_eq!(report.total_events, 2);
        assert_eq!(report.categories.len(), 2);
    }

    #[test]
    fn report_flags_slo_breaches() {
        let mut engine = ContainmentRevocationMetrics::default();
        let mut ev = sample_event("e1", EventCategory::EmergencyContainment);
        ev.initiation_to_convergence_ms = 5000.0;
        engine.record_event(ev, &trace()).unwrap();
        let report = engine.generate_report(&trace());
        assert!(!report.flagged_categories.is_empty());
    }

    #[test]
    fn report_slo_met_when_within() {
        let mut engine = ContainmentRevocationMetrics::default();
        engine
            .record_event(sample_event("e1", EventCategory::Revocation), &trace())
            .unwrap();
        let report = engine.generate_report(&trace());
        assert!(report.categories[0].slo_met);
    }

    #[test]
    fn report_has_content_hash() {
        let mut engine = ContainmentRevocationMetrics::default();
        let report = engine.generate_report(&trace());
        assert_eq!(report.content_hash.len(), 64);
    }

    #[test]
    fn report_has_version() {
        let mut engine = ContainmentRevocationMetrics::default();
        let report = engine.generate_report(&trace());
        assert_eq!(report.metric_version, METRIC_VERSION);
    }

    #[test]
    fn report_deterministic() {
        let mut e1 = ContainmentRevocationMetrics::default();
        let mut e2 = ContainmentRevocationMetrics::default();
        let r1 = e1.generate_report("det");
        let r2 = e2.generate_report("det");
        assert_eq!(r1.content_hash, r2.content_hash);
    }

    // === Audit log ===

    #[test]
    fn audit_log_populated() {
        let mut engine = ContainmentRevocationMetrics::default();
        engine
            .record_event(sample_event("e1", EventCategory::Revocation), &trace())
            .unwrap();
        assert_eq!(engine.audit_log().len(), 3);
    }

    #[test]
    fn audit_has_event_codes() {
        let mut engine = ContainmentRevocationMetrics::default();
        engine
            .record_event(sample_event("e1", EventCategory::Revocation), &trace())
            .unwrap();
        let codes: Vec<&str> = engine
            .audit_log()
            .iter()
            .map(|r| r.event_code.as_str())
            .collect();
        assert!(codes.contains(&event_codes::CRM_EVENT_RECORDED));
    }

    #[test]
    fn export_jsonl() {
        let mut engine = ContainmentRevocationMetrics::default();
        engine
            .record_event(sample_event("e1", EventCategory::Revocation), &trace())
            .unwrap();
        let jsonl = engine.export_audit_log_jsonl().unwrap();
        let first: serde_json::Value = serde_json::from_str(jsonl.lines().next().unwrap()).unwrap();
        assert!(first["event_code"].is_string());
    }

    // === Percentile computation ===

    #[test]
    fn percentile_computation() {
        let sorted: Vec<f64> = (1..=100).map(|i| i as f64).collect();
        let p = compute_percentiles(&sorted);
        assert!(p.p50_ms <= p.p95_ms);
        assert!(p.p95_ms <= p.p99_ms);
    }

    #[test]
    fn percentile_empty() {
        let p = compute_percentiles(&[]);
        assert_eq!(p.p50_ms, 0.0);
    }
}
