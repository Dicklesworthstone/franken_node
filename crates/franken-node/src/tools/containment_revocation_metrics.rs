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

use crate::capacity_defaults::aliases::{MAX_AUDIT_LOG_ENTRIES, MAX_EVENTS};

fn push_bounded<T>(items: &mut Vec<T>, item: T, cap: usize) {
    if cap == 0 {
        items.clear();
        return;
    }
    if items.len() >= cap {
        let overflow = items.len().saturating_sub(cap).saturating_add(1);
        items.drain(0..overflow);
    }
    items.push(item);
}

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
        self.p50_ms.is_finite()
            && self.p95_ms.is_finite()
            && self.p99_ms.is_finite()
            && self.p50_ms <= self.p95_ms
            && self.p95_ms <= self.p99_ms
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
        !self.initiation_to_convergence_ms.is_finite()
            || self.initiation_to_convergence_ms >= self.category.slo_ms()
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
        if event.event_id.trim().is_empty() {
            self.log(
                event_codes::CRM_ERR_INVALID_EVENT,
                trace_id,
                serde_json::json!({"event_id": &event.event_id, "reason": "empty event_id"}),
            );
            return Err("event_id must be non-empty".to_string());
        }
        if !event.initiation_to_ack_ms.is_finite()
            || !event.initiation_to_convergence_ms.is_finite()
            || event.initiation_to_ack_ms < 0.0
            || event.initiation_to_convergence_ms < 0.0
        {
            self.log(
                event_codes::CRM_ERR_INVALID_EVENT,
                trace_id,
                serde_json::json!({"event_id": &event.event_id, "reason": "negative latency"}),
            );
            return Err("Latency values must be non-negative".to_string());
        }
        if event.initiation_to_convergence_ms < event.initiation_to_ack_ms {
            self.log(
                event_codes::CRM_ERR_INVALID_EVENT,
                trace_id,
                serde_json::json!({
                    "event_id": &event.event_id,
                    "reason": "convergence before acknowledgement"
                }),
            );
            return Err(
                "Convergence latency must be greater than or equal to acknowledgement latency"
                    .to_string(),
            );
        }
        if event.nodes_converged > event.nodes_total {
            self.log(
                event_codes::CRM_ERR_INVALID_EVENT,
                trace_id,
                serde_json::json!({
                    "event_id": &event.event_id,
                    "reason": "nodes_converged exceeds nodes_total",
                    "nodes_converged": event.nodes_converged,
                    "nodes_total": event.nodes_total,
                }),
            );
            return Err("nodes_converged must be less than or equal to nodes_total".to_string());
        }
        if event.nodes_total == 0 {
            self.log(
                event_codes::CRM_ERR_INVALID_EVENT,
                trace_id,
                serde_json::json!({
                    "event_id": &event.event_id,
                    "reason": "nodes_total must be > 0",
                }),
            );
            return Err("nodes_total must be > 0".to_string());
        }
        if event.convergence_status == ConvergenceStatus::Full
            && event.nodes_converged != event.nodes_total
        {
            self.log(
                event_codes::CRM_ERR_INVALID_EVENT,
                trace_id,
                serde_json::json!({
                    "event_id": &event.event_id,
                    "reason": "full convergence requires all nodes",
                    "nodes_converged": event.nodes_converged,
                    "nodes_total": event.nodes_total,
                }),
            );
            return Err("full convergence requires all nodes to be converged".to_string());
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

        push_bounded(&mut self.events, event, MAX_EVENTS);
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
            latencies.sort_by(|a, b| a.total_cmp(b));

            let percentiles = compute_percentiles(&latencies);

            let avg_conv =
                events.iter().map(|e| e.convergence_ratio()).sum::<f64>() / events.len() as f64;

            let breaches = events.iter().filter(|e| e.exceeds_slo()).count();
            total_breaches = total_breaches.saturating_add(breaches);

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

        let content_hash = compute_report_content_hash(
            total,
            &categories,
            breach_rate,
            &flagged,
            &self.metric_version,
        );

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
        push_bounded(
            &mut self.audit_log,
            CrmAuditRecord {
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

fn compute_report_content_hash(
    total_events: usize,
    categories: &[CategoryMetrics],
    overall_slo_breach_rate: f64,
    flagged_categories: &[EventCategory],
    metric_version: &str,
) -> String {
    let hash_input = serde_json::json!({
        "total_events": total_events,
        "categories": categories,
        "overall_slo_breach_rate": overall_slo_breach_rate,
        "flagged_categories": flagged_categories,
        "metric_version": metric_version,
    })
    .to_string();
    let mut hasher = Sha256::new();
    hasher.update(b"containment_revocation_hash_v1:");
    hasher.update(
        u64::try_from(hash_input.len())
            .unwrap_or(u64::MAX)
            .to_le_bytes(),
    );
    hasher.update(hash_input.as_bytes());
    hex::encode(hasher.finalize())
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

    #[test]
    fn percentiles_non_finite_are_not_ordered() {
        let infinite = Percentiles {
            p50_ms: f64::INFINITY,
            p95_ms: f64::INFINITY,
            p99_ms: f64::INFINITY,
        };
        let nan = Percentiles {
            p50_ms: 10.0,
            p95_ms: f64::NAN,
            p99_ms: 99.0,
        };

        assert!(!infinite.is_ordered());
        assert!(!nan.is_ordered());
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

    #[test]
    fn non_finite_convergence_exceeds_slo_fail_closed() {
        let mut ev = sample_event("nan-slo", EventCategory::EmergencyContainment);
        ev.initiation_to_convergence_ms = f64::NAN;

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
    fn report_hash_length_prefixes_serialized_payload() {
        let hash_input = serde_json::json!({
            "total_events": 0usize,
            "categories": Vec::<CategoryMetrics>::new(),
            "overall_slo_breach_rate": 0.0,
            "flagged_categories": Vec::<EventCategory>::new(),
            "metric_version": METRIC_VERSION,
        })
        .to_string();

        let actual = compute_report_content_hash(0, &[], 0.0, &[], METRIC_VERSION);

        let mut expected = Sha256::new();
        expected.update(b"containment_revocation_hash_v1:");
        expected.update(
            u64::try_from(hash_input.len())
                .unwrap_or(u64::MAX)
                .to_le_bytes(),
        );
        expected.update(hash_input.as_bytes());

        let mut legacy_unframed = Sha256::new();
        legacy_unframed.update(b"containment_revocation_hash_v1:");
        legacy_unframed.update(hash_input.as_bytes());

        assert_eq!(actual, hex::encode(expected.finalize()));
        assert_ne!(actual, hex::encode(legacy_unframed.finalize()));
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

    #[test]
    fn report_hash_changes_when_category_details_change_with_same_totals() {
        let mut base = ContainmentRevocationMetrics::default();
        let mut changed = ContainmentRevocationMetrics::default();

        let base_a = sample_event("base-a", EventCategory::Revocation);
        let base_b = sample_event("base-b", EventCategory::Revocation);
        base.record_event(base_a, &trace()).unwrap();
        base.record_event(base_b.clone(), &trace()).unwrap();

        let mut changed_b = base_b;
        changed_b.initiation_to_convergence_ms = 750.0;
        changed
            .record_event(
                sample_event("changed-a", EventCategory::Revocation),
                &trace(),
            )
            .unwrap();
        changed.record_event(changed_b, &trace()).unwrap();

        let base_report = base.generate_report("hash-category-base");
        let changed_report = changed.generate_report("hash-category-changed");

        assert_eq!(base_report.total_events, changed_report.total_events);
        assert_eq!(
            base_report.categories.len(),
            changed_report.categories.len()
        );
        assert_eq!(
            base_report.flagged_categories,
            changed_report.flagged_categories
        );
        assert_eq!(
            base_report.overall_slo_breach_rate,
            changed_report.overall_slo_breach_rate
        );
        assert_ne!(base_report.categories, changed_report.categories);
        assert_ne!(base_report.content_hash, changed_report.content_hash);
    }

    #[test]
    fn report_hash_changes_when_flagged_categories_change_with_same_totals() {
        let mut clean = ContainmentRevocationMetrics::default();
        let mut flagged = ContainmentRevocationMetrics::default();

        clean
            .record_event(sample_event("clean-r", EventCategory::Revocation), &trace())
            .unwrap();
        clean
            .record_event(sample_event("clean-q", EventCategory::Quarantine), &trace())
            .unwrap();

        flagged
            .record_event(
                sample_event("flagged-r", EventCategory::Revocation),
                &trace(),
            )
            .unwrap();
        let mut slo_breach = sample_event("flagged-q", EventCategory::Quarantine);
        slo_breach.initiation_to_convergence_ms = 2500.0;
        flagged.record_event(slo_breach, &trace()).unwrap();

        let clean_report = clean.generate_report("hash-flagged-clean");
        let flagged_report = flagged.generate_report("hash-flagged-flagged");

        assert_eq!(clean_report.total_events, flagged_report.total_events);
        assert_eq!(
            clean_report.categories.len(),
            flagged_report.categories.len()
        );
        assert_ne!(
            clean_report.flagged_categories,
            flagged_report.flagged_categories
        );
        assert_ne!(clean_report.content_hash, flagged_report.content_hash);
    }

    #[test]
    fn report_hash_changes_when_breach_rate_changes_with_same_flagged_categories() {
        let mut partial = ContainmentRevocationMetrics::default();
        let mut full = ContainmentRevocationMetrics::default();

        let mut partial_breach = sample_event("partial-breach", EventCategory::Revocation);
        partial_breach.initiation_to_convergence_ms = 6000.0;
        partial.record_event(partial_breach, &trace()).unwrap();
        partial
            .record_event(
                sample_event("partial-ok", EventCategory::Revocation),
                &trace(),
            )
            .unwrap();

        let mut full_a = sample_event("full-a", EventCategory::Revocation);
        full_a.initiation_to_convergence_ms = 6000.0;
        let mut full_b = sample_event("full-b", EventCategory::Revocation);
        full_b.initiation_to_convergence_ms = 7000.0;
        full.record_event(full_a, &trace()).unwrap();
        full.record_event(full_b, &trace()).unwrap();

        let partial_report = partial.generate_report("hash-breach-partial");
        let full_report = full.generate_report("hash-breach-full");

        assert_eq!(partial_report.total_events, full_report.total_events);
        assert_eq!(
            partial_report.categories.len(),
            full_report.categories.len()
        );
        assert_eq!(
            partial_report.flagged_categories,
            full_report.flagged_categories
        );
        assert_ne!(
            partial_report.overall_slo_breach_rate,
            full_report.overall_slo_breach_rate
        );
        assert_ne!(partial_report.content_hash, full_report.content_hash);
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

    #[test]
    fn nan_convergence_latency_rejected() {
        let mut engine = ContainmentRevocationMetrics::default();
        let mut ev = sample_event("e1", EventCategory::Revocation);
        ev.initiation_to_convergence_ms = f64::NAN;
        assert!(engine.record_event(ev, &trace()).is_err());
    }

    #[test]
    fn nan_ack_latency_rejected() {
        let mut engine = ContainmentRevocationMetrics::default();
        let mut ev = sample_event("e1", EventCategory::Revocation);
        ev.initiation_to_ack_ms = f64::NAN;
        assert!(engine.record_event(ev, &trace()).is_err());
    }

    #[test]
    fn inf_convergence_latency_rejected() {
        let mut engine = ContainmentRevocationMetrics::default();
        let mut ev = sample_event("e1", EventCategory::Revocation);
        ev.initiation_to_convergence_ms = f64::INFINITY;
        assert!(engine.record_event(ev, &trace()).is_err());
    }

    #[test]
    fn neg_inf_ack_latency_rejected() {
        let mut engine = ContainmentRevocationMetrics::default();
        let mut ev = sample_event("e1", EventCategory::Revocation);
        ev.initiation_to_ack_ms = f64::NEG_INFINITY;
        assert!(engine.record_event(ev, &trace()).is_err());
    }

    #[test]
    fn convergence_before_ack_latency_rejected() {
        let mut engine = ContainmentRevocationMetrics::default();
        let mut ev = sample_event("converged-too-soon", EventCategory::Revocation);
        ev.initiation_to_ack_ms = 800.0;
        ev.initiation_to_convergence_ms = 500.0;
        let err = engine.record_event(ev, "trace-convergence").unwrap_err();

        assert!(err.contains("Convergence latency"));
        assert!(engine.events().is_empty());
    }

    #[test]
    fn convergence_before_ack_logs_only_invalid_event() {
        let mut engine = ContainmentRevocationMetrics::default();
        let mut ev = sample_event("bad-order", EventCategory::Quarantine);
        ev.initiation_to_ack_ms = 1000.0;
        ev.initiation_to_convergence_ms = 999.0;

        assert!(engine.record_event(ev, "trace-bad-order").is_err());
        assert_eq!(engine.audit_log().len(), 1);
        assert_eq!(
            engine.audit_log()[0].event_code,
            event_codes::CRM_ERR_INVALID_EVENT
        );
        assert_eq!(engine.audit_log()[0].trace_id, "trace-bad-order");
        assert_eq!(
            engine.audit_log()[0].details["reason"],
            "convergence before acknowledgement"
        );
    }

    #[test]
    fn nodes_converged_above_total_rejected() {
        let mut engine = ContainmentRevocationMetrics::default();
        let mut ev = sample_event("impossible-ratio", EventCategory::PolicyEnforcement);
        ev.nodes_total = 4;
        ev.nodes_converged = 5;
        let err = engine.record_event(ev, "trace-impossible").unwrap_err();

        assert!(err.contains("nodes_converged"));
        assert!(engine.events().is_empty());
    }

    #[test]
    fn zero_total_with_converged_nodes_rejected() {
        let mut engine = ContainmentRevocationMetrics::default();
        let mut ev = sample_event("zero-total", EventCategory::TrustDowngrade);
        ev.nodes_total = 0;
        ev.nodes_converged = 1;

        assert!(engine.record_event(ev, "trace-zero-total").is_err());
        assert!(engine.events().is_empty());
        assert_eq!(
            engine.audit_log()[0].details["reason"],
            "nodes_converged exceeds nodes_total"
        );
    }

    #[test]
    fn rejected_node_count_does_not_emit_success_audit_events() {
        let mut engine = ContainmentRevocationMetrics::default();
        let mut ev = sample_event("bad-node-count", EventCategory::EmergencyContainment);
        ev.nodes_total = 1;
        ev.nodes_converged = 2;

        assert!(engine.record_event(ev, "trace-node-count").is_err());
        let codes: Vec<&str> = engine
            .audit_log()
            .iter()
            .map(|record| record.event_code.as_str())
            .collect();
        assert_eq!(codes, vec![event_codes::CRM_ERR_INVALID_EVENT]);
        assert!(!codes.contains(&event_codes::CRM_EVENT_RECORDED));
        assert!(!codes.contains(&event_codes::CRM_CONVERGENCE_MEASURED));
        assert!(!codes.contains(&event_codes::CRM_SLO_CHECKED));
    }

    #[test]
    fn report_after_only_rejected_events_stays_empty() {
        let mut engine = ContainmentRevocationMetrics::default();
        let mut ev = sample_event("rejected-only", EventCategory::Revocation);
        ev.initiation_to_ack_ms = 250.0;
        ev.initiation_to_convergence_ms = 249.0;

        assert!(engine.record_event(ev, "trace-rejected").is_err());
        let report = engine.generate_report("trace-report");

        assert_eq!(report.total_events, 0);
        assert!(report.categories.is_empty());
        assert!(report.flagged_categories.is_empty());
        assert_eq!(report.overall_slo_breach_rate, 0.0);
    }

    #[test]
    fn invalid_latency_takes_precedence_over_node_count_rejection() {
        let mut engine = ContainmentRevocationMetrics::default();
        let mut ev = sample_event("multi-invalid", EventCategory::Quarantine);
        ev.initiation_to_ack_ms = -1.0;
        ev.nodes_total = 1;
        ev.nodes_converged = 2;

        assert!(engine.record_event(ev, "trace-precedence").is_err());
        assert_eq!(engine.audit_log().len(), 1);
        assert_eq!(engine.audit_log()[0].details["reason"], "negative latency");
    }

    #[test]
    fn blank_event_id_takes_precedence_over_latency_and_node_count_rejection() {
        let mut engine = ContainmentRevocationMetrics::default();
        let mut ev = sample_event("blank-first", EventCategory::EmergencyContainment);
        ev.event_id = " ".to_string();
        ev.initiation_to_ack_ms = -5.0;
        ev.nodes_total = 1;
        ev.nodes_converged = 2;

        let err = engine
            .record_event(ev, "trace-blank-precedence")
            .expect_err("blank event id should fail before other validation");

        assert!(err.contains("event_id"));
        assert!(engine.events().is_empty());
        assert_eq!(engine.audit_log().len(), 1);
        assert_eq!(engine.audit_log()[0].details["reason"], "empty event_id");
    }

    #[test]
    fn negative_latency_takes_precedence_over_convergence_order() {
        let mut engine = ContainmentRevocationMetrics::default();
        let mut ev = sample_event("negative-before-order", EventCategory::Revocation);
        ev.initiation_to_ack_ms = 100.0;
        ev.initiation_to_convergence_ms = -1.0;

        let err = engine
            .record_event(ev, "trace-negative-before-order")
            .expect_err("negative convergence should fail before ordering check");

        assert!(err.contains("Latency values"));
        assert!(engine.events().is_empty());
        assert_eq!(engine.audit_log()[0].details["reason"], "negative latency");
    }

    #[test]
    fn blank_event_id_is_rejected_without_storing_event() {
        let mut engine = ContainmentRevocationMetrics::default();
        let mut ev = sample_event("blank-id", EventCategory::Revocation);
        ev.event_id.clear();

        let err = engine
            .record_event(ev, "trace-blank-id")
            .expect_err("blank event id should fail");

        assert!(err.contains("event_id"));
        assert!(engine.events().is_empty());
        assert_eq!(engine.audit_log()[0].details["reason"], "empty event_id");
    }

    #[test]
    fn whitespace_event_id_is_rejected_without_success_audit() {
        let mut engine = ContainmentRevocationMetrics::default();
        let mut ev = sample_event("whitespace-id", EventCategory::Quarantine);
        ev.event_id = "   ".to_string();

        assert!(engine.record_event(ev, "trace-whitespace-id").is_err());

        let codes: Vec<&str> = engine
            .audit_log()
            .iter()
            .map(|record| record.event_code.as_str())
            .collect();
        assert_eq!(codes, vec![event_codes::CRM_ERR_INVALID_EVENT]);
    }

    #[test]
    fn zero_total_zero_converged_nodes_is_rejected() {
        let mut engine = ContainmentRevocationMetrics::default();
        let mut ev = sample_event("zero-zero", EventCategory::PolicyEnforcement);
        ev.nodes_total = 0;
        ev.nodes_converged = 0;
        ev.convergence_status = ConvergenceStatus::Pending;

        let err = engine
            .record_event(ev, "trace-zero-zero")
            .expect_err("zero-node events should fail");

        assert!(err.contains("nodes_total"));
        assert!(engine.events().is_empty());
    }

    #[test]
    fn full_status_with_partial_nodes_is_rejected() {
        let mut engine = ContainmentRevocationMetrics::default();
        let mut ev = sample_event("full-but-partial", EventCategory::TrustDowngrade);
        ev.nodes_total = 10;
        ev.nodes_converged = 9;
        ev.convergence_status = ConvergenceStatus::Full;

        let err = engine
            .record_event(ev, "trace-full-partial")
            .expect_err("full status with partial convergence should fail");

        assert!(err.contains("full convergence"));
        assert!(engine.events().is_empty());
        assert_eq!(
            engine.audit_log()[0].details["reason"],
            "full convergence requires all nodes"
        );
    }

    #[test]
    fn rejected_blank_event_report_remains_empty() {
        let mut engine = ContainmentRevocationMetrics::default();
        let mut ev = sample_event("blank-report", EventCategory::EmergencyContainment);
        ev.event_id = "\t".to_string();

        assert!(engine.record_event(ev, "trace-blank-report").is_err());

        let report = engine.generate_report("trace-after-blank");
        assert_eq!(report.total_events, 0);
        assert!(report.categories.is_empty());
        assert!(report.flagged_categories.is_empty());
    }

    #[test]
    fn invalid_full_status_preserves_existing_events() {
        let mut engine = ContainmentRevocationMetrics::default();
        engine
            .record_event(sample_event("kept", EventCategory::Revocation), &trace())
            .unwrap();
        let mut rejected = sample_event("bad-full", EventCategory::Revocation);
        rejected.nodes_converged = 9;
        rejected.convergence_status = ConvergenceStatus::Full;

        let err = engine
            .record_event(rejected, &trace())
            .expect_err("invalid full status should fail");

        assert!(err.contains("full convergence"));
        assert_eq!(engine.events().len(), 1);
        assert_eq!(engine.events()[0].event_id, "kept");
    }

    #[test]
    fn convergence_order_rejection_preserves_existing_events() {
        let mut engine = ContainmentRevocationMetrics::default();
        engine
            .record_event(
                sample_event("kept-order", EventCategory::Quarantine),
                &trace(),
            )
            .unwrap();
        let mut rejected = sample_event("bad-order-after-kept", EventCategory::Quarantine);
        rejected.initiation_to_ack_ms = 750.0;
        rejected.initiation_to_convergence_ms = 700.0;

        let err = engine
            .record_event(rejected, "trace-order-preserve")
            .expect_err("bad convergence order should fail");

        assert!(err.contains("Convergence latency"));
        assert_eq!(engine.events().len(), 1);
        assert_eq!(engine.events()[0].event_id, "kept-order");
    }

    #[test]
    fn full_status_partial_nodes_takes_precedence_over_slo_breach_logging() {
        let mut engine = ContainmentRevocationMetrics::default();
        let mut ev = sample_event("full-partial-slo", EventCategory::EmergencyContainment);
        ev.nodes_total = 10;
        ev.nodes_converged = 9;
        ev.convergence_status = ConvergenceStatus::Full;
        ev.initiation_to_convergence_ms = EventCategory::EmergencyContainment.slo_ms();

        let err = engine
            .record_event(ev, "trace-full-before-slo")
            .expect_err("invalid full status should fail before SLO logging");

        assert!(err.contains("full convergence"));
        assert!(engine.events().is_empty());
        assert_eq!(engine.audit_log().len(), 1);
        assert_eq!(
            engine.audit_log()[0].event_code,
            event_codes::CRM_ERR_INVALID_EVENT
        );
        assert!(
            !engine
                .audit_log()
                .iter()
                .any(|record| record.event_code == event_codes::CRM_ERR_SLO_BREACH)
        );
    }

    #[test]
    fn rejected_slo_shaped_event_does_not_flag_clean_report() {
        let mut engine = ContainmentRevocationMetrics::default();
        engine
            .record_event(
                sample_event("kept-clean", EventCategory::Revocation),
                &trace(),
            )
            .unwrap();
        let mut rejected = sample_event("rejected-slo-shaped", EventCategory::EmergencyContainment);
        rejected.nodes_total = 2;
        rejected.nodes_converged = 3;
        rejected.initiation_to_convergence_ms = 10_000.0;

        assert!(
            engine
                .record_event(rejected, "trace-rejected-slo-shaped")
                .is_err()
        );
        let report = engine.generate_report("trace-clean-report-after-reject");

        assert_eq!(report.total_events, 1);
        assert!(report.flagged_categories.is_empty());
        assert!((report.overall_slo_breach_rate - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn exact_slo_boundary_is_flagged_fail_closed() {
        let mut engine = ContainmentRevocationMetrics::default();
        let mut ev = sample_event("exact-slo", EventCategory::EmergencyContainment);
        ev.initiation_to_convergence_ms = EventCategory::EmergencyContainment.slo_ms();

        engine.record_event(ev, "trace-exact-slo").unwrap();
        let report = engine.generate_report("trace-exact-slo-report");

        assert_eq!(
            report.flagged_categories,
            vec![EventCategory::EmergencyContainment]
        );
        assert_eq!(report.categories[0].slo_breach_count, 1);
        assert!(
            engine
                .audit_log()
                .iter()
                .any(|record| record.event_code == event_codes::CRM_ERR_SLO_BREACH)
        );
    }

    #[test]
    fn export_empty_audit_log_is_empty_string() {
        let engine = ContainmentRevocationMetrics::default();

        let jsonl = engine.export_audit_log_jsonl().unwrap();

        assert!(jsonl.is_empty());
    }

    #[test]
    fn push_bounded_zero_capacity_discards_without_panic() {
        let mut items = vec![1_u8, 2, 3];

        push_bounded(&mut items, 4, 0);

        assert!(items.is_empty());
    }
}
