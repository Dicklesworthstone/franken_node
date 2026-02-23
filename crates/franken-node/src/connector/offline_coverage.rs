//! bd-29w6: Offline coverage tracker and SLO dashboards.
//!
//! Continuous coverage metrics, SLO breach alerts, traceable dashboard values.

use std::collections::BTreeMap;

/// SLO target definition.
#[derive(Debug, Clone)]
pub struct SloTarget {
    pub metric_name: String,
    pub threshold: f64,
    pub breach_action: String,
}

/// Raw coverage event.
#[derive(Debug, Clone)]
pub struct CoverageEvent {
    pub artifact_id: String,
    pub available: bool,
    pub timestamp: u64,
    pub scope: String,
}

/// Computed coverage metrics.
#[derive(Debug, Clone)]
pub struct CoverageMetrics {
    pub coverage_ratio: f64,
    pub availability_ratio: f64,
    pub repair_debt_count: usize,
    pub total_artifacts: usize,
    pub available_count: usize,
    pub scope: String,
}

/// SLO breach alert.
#[derive(Debug, Clone)]
pub struct SloBreachAlert {
    pub slo_name: String,
    pub actual_value: f64,
    pub threshold: f64,
    pub breach_time: u64,
    pub trace_id: String,
}

/// Dashboard snapshot.
#[derive(Debug, Clone)]
pub struct DashboardSnapshot {
    pub metrics: Vec<CoverageMetrics>,
    pub alerts: Vec<SloBreachAlert>,
    pub event_count: usize,
    pub trace_id: String,
    pub timestamp: String,
}

/// Errors from coverage tracking.
#[derive(Debug, Clone, PartialEq)]
pub enum CoverageError {
    SloBreach {
        slo_name: String,
        actual: f64,
        threshold: f64,
    },
    InvalidEvent {
        reason: String,
    },
    NoEvents {
        scope: String,
    },
    ScopeUnknown {
        scope: String,
    },
}

impl CoverageError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::SloBreach { .. } => "OCT_SLO_BREACH",
            Self::InvalidEvent { .. } => "OCT_INVALID_EVENT",
            Self::NoEvents { .. } => "OCT_NO_EVENTS",
            Self::ScopeUnknown { .. } => "OCT_SCOPE_UNKNOWN",
        }
    }
}

impl std::fmt::Display for CoverageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SloBreach {
                slo_name,
                actual,
                threshold,
            } => {
                write!(f, "OCT_SLO_BREACH: {slo_name} {actual:.2} < {threshold:.2}")
            }
            Self::InvalidEvent { reason } => write!(f, "OCT_INVALID_EVENT: {reason}"),
            Self::NoEvents { scope } => write!(f, "OCT_NO_EVENTS: {scope}"),
            Self::ScopeUnknown { scope } => write!(f, "OCT_SCOPE_UNKNOWN: {scope}"),
        }
    }
}

/// Validate a coverage event.
fn validate_event(event: &CoverageEvent) -> Result<(), CoverageError> {
    if event.artifact_id.is_empty() {
        return Err(CoverageError::InvalidEvent {
            reason: "empty artifact_id".into(),
        });
    }
    if event.scope.is_empty() {
        return Err(CoverageError::InvalidEvent {
            reason: "empty scope".into(),
        });
    }
    Ok(())
}

/// Per-scope tracker state.
#[derive(Debug, Clone, Default)]
struct ScopeState {
    /// Latest status per artifact_id. true = available.
    artifacts: BTreeMap<String, bool>,
    event_count: usize,
}

/// Offline coverage tracker.
#[derive(Default)]
pub struct OfflineCoverageTracker {
    scopes: BTreeMap<String, ScopeState>,
    all_events: Vec<CoverageEvent>,
}

impl OfflineCoverageTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a coverage event.
    ///
    /// INV-OCT-CONTINUOUS: metrics updated immediately.
    pub fn record_event(&mut self, event: CoverageEvent) -> Result<(), CoverageError> {
        validate_event(&event)?;
        let scope = self.scopes.entry(event.scope.clone()).or_default();
        scope
            .artifacts
            .insert(event.artifact_id.clone(), event.available);
        scope.event_count += 1;
        self.all_events.push(event);
        Ok(())
    }

    /// Compute metrics for a scope.
    ///
    /// INV-OCT-DETERMINISTIC: same events → same metrics.
    pub fn compute_metrics(&self, scope: &str) -> Result<CoverageMetrics, CoverageError> {
        let state = self
            .scopes
            .get(scope)
            .ok_or_else(|| CoverageError::ScopeUnknown {
                scope: scope.into(),
            })?;

        if state.artifacts.is_empty() {
            return Err(CoverageError::NoEvents {
                scope: scope.into(),
            });
        }

        let total = state.artifacts.len();
        let available = state.artifacts.values().filter(|&&v| v).count();
        let repair_debt = total - available;
        let coverage_ratio = available as f64 / total as f64;
        let availability_ratio = coverage_ratio; // in this model, coverage = availability

        Ok(CoverageMetrics {
            coverage_ratio,
            availability_ratio,
            repair_debt_count: repair_debt,
            total_artifacts: total,
            available_count: available,
            scope: scope.to_string(),
        })
    }

    /// Check SLO targets against current metrics.
    ///
    /// INV-OCT-SLO-BREACH: returns alerts for any breached SLO.
    pub fn check_slos(
        &self,
        targets: &[SloTarget],
        scope: &str,
        now: u64,
        trace_id: &str,
    ) -> Result<Vec<SloBreachAlert>, CoverageError> {
        let metrics = self.compute_metrics(scope)?;
        let mut alerts = Vec::new();

        for target in targets {
            let actual = match target.metric_name.as_str() {
                "coverage" => metrics.coverage_ratio,
                "availability" => metrics.availability_ratio,
                "repair_debt" => metrics.repair_debt_count as f64,
                _ => continue,
            };

            // For repair_debt, breach = actual > threshold (debt too high)
            // For coverage/availability, breach = actual < threshold (ratio too low)
            let breached = if target.metric_name == "repair_debt" {
                actual > target.threshold
            } else {
                actual < target.threshold
            };

            if breached {
                alerts.push(SloBreachAlert {
                    slo_name: target.metric_name.clone(),
                    actual_value: actual,
                    threshold: target.threshold,
                    breach_time: now,
                    trace_id: trace_id.to_string(),
                });
            }
        }

        Ok(alerts)
    }

    /// Generate a dashboard snapshot.
    ///
    /// INV-OCT-TRACEABLE: snapshot includes event count for traceability.
    pub fn dashboard_snapshot(&self, trace_id: &str, timestamp: &str) -> DashboardSnapshot {
        let mut metrics = Vec::new();
        let mut scope_names: Vec<&String> = self.scopes.keys().collect();
        scope_names.sort(); // deterministic ordering

        for scope in scope_names {
            if let Ok(m) = self.compute_metrics(scope) {
                metrics.push(m);
            }
        }

        DashboardSnapshot {
            metrics,
            alerts: Vec::new(),
            event_count: self.all_events.len(),
            trace_id: trace_id.to_string(),
            timestamp: timestamp.to_string(),
        }
    }

    /// Total events recorded.
    pub fn event_count(&self) -> usize {
        self.all_events.len()
    }

    /// Known scopes.
    pub fn scope_count(&self) -> usize {
        self.scopes.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(id: &str, available: bool, ts: u64, scope: &str) -> CoverageEvent {
        CoverageEvent {
            artifact_id: id.into(),
            available,
            timestamp: ts,
            scope: scope.into(),
        }
    }

    fn slo(name: &str, threshold: f64) -> SloTarget {
        SloTarget {
            metric_name: name.into(),
            threshold,
            breach_action: "alert".into(),
        }
    }

    #[test]
    fn record_and_compute_coverage() {
        let mut t = OfflineCoverageTracker::new();
        t.record_event(ev("a1", true, 100, "prod")).unwrap();
        t.record_event(ev("a2", true, 101, "prod")).unwrap();
        t.record_event(ev("a3", false, 102, "prod")).unwrap();
        let m = t.compute_metrics("prod").unwrap();
        assert_eq!(m.total_artifacts, 3);
        assert_eq!(m.available_count, 2);
        assert!((m.coverage_ratio - 2.0 / 3.0).abs() < 1e-10);
    }

    #[test]
    fn repair_debt_counted() {
        let mut t = OfflineCoverageTracker::new();
        t.record_event(ev("a1", true, 100, "prod")).unwrap();
        t.record_event(ev("a2", false, 101, "prod")).unwrap();
        t.record_event(ev("a3", false, 102, "prod")).unwrap();
        let m = t.compute_metrics("prod").unwrap();
        assert_eq!(m.repair_debt_count, 2);
    }

    #[test]
    fn latest_event_wins() {
        let mut t = OfflineCoverageTracker::new();
        t.record_event(ev("a1", true, 100, "prod")).unwrap();
        t.record_event(ev("a1", false, 200, "prod")).unwrap();
        let m = t.compute_metrics("prod").unwrap();
        assert_eq!(m.available_count, 0);
    }

    #[test]
    fn slo_breach_detected() {
        let mut t = OfflineCoverageTracker::new();
        t.record_event(ev("a1", true, 100, "prod")).unwrap();
        t.record_event(ev("a2", false, 101, "prod")).unwrap();
        let targets = vec![slo("coverage", 0.9)];
        let alerts = t.check_slos(&targets, "prod", 200, "tr").unwrap();
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].slo_name, "coverage");
    }

    #[test]
    fn slo_no_breach_when_healthy() {
        let mut t = OfflineCoverageTracker::new();
        t.record_event(ev("a1", true, 100, "prod")).unwrap();
        t.record_event(ev("a2", true, 101, "prod")).unwrap();
        let targets = vec![slo("coverage", 0.9)];
        let alerts = t.check_slos(&targets, "prod", 200, "tr").unwrap();
        assert!(alerts.is_empty());
    }

    #[test]
    fn repair_debt_slo_breach() {
        let mut t = OfflineCoverageTracker::new();
        t.record_event(ev("a1", false, 100, "prod")).unwrap();
        t.record_event(ev("a2", false, 101, "prod")).unwrap();
        t.record_event(ev("a3", false, 102, "prod")).unwrap();
        let targets = vec![slo("repair_debt", 2.0)];
        let alerts = t.check_slos(&targets, "prod", 200, "tr").unwrap();
        assert_eq!(alerts.len(), 1);
    }

    #[test]
    fn scope_isolation() {
        let mut t = OfflineCoverageTracker::new();
        t.record_event(ev("a1", true, 100, "prod")).unwrap();
        t.record_event(ev("a2", false, 101, "staging")).unwrap();
        let prod = t.compute_metrics("prod").unwrap();
        let staging = t.compute_metrics("staging").unwrap();
        assert!((prod.coverage_ratio - 1.0).abs() < 1e-10);
        assert!((staging.coverage_ratio - 0.0).abs() < 1e-10);
    }

    #[test]
    fn unknown_scope_error() {
        let t = OfflineCoverageTracker::new();
        let err = t.compute_metrics("nonexistent").unwrap_err();
        assert_eq!(err.code(), "OCT_SCOPE_UNKNOWN");
    }

    #[test]
    fn invalid_event_empty_id() {
        let mut t = OfflineCoverageTracker::new();
        let err = t.record_event(ev("", true, 100, "prod")).unwrap_err();
        assert_eq!(err.code(), "OCT_INVALID_EVENT");
    }

    #[test]
    fn invalid_event_empty_scope() {
        let mut t = OfflineCoverageTracker::new();
        let err = t.record_event(ev("a1", true, 100, "")).unwrap_err();
        assert_eq!(err.code(), "OCT_INVALID_EVENT");
    }

    #[test]
    fn dashboard_snapshot_has_all_scopes() {
        let mut t = OfflineCoverageTracker::new();
        t.record_event(ev("a1", true, 100, "prod")).unwrap();
        t.record_event(ev("a2", true, 101, "staging")).unwrap();
        let snap = t.dashboard_snapshot("tr", "ts");
        assert_eq!(snap.metrics.len(), 2);
        assert_eq!(snap.event_count, 2);
    }

    #[test]
    fn dashboard_deterministic_order() {
        let mut t = OfflineCoverageTracker::new();
        t.record_event(ev("a1", true, 100, "z-scope")).unwrap();
        t.record_event(ev("a2", true, 101, "a-scope")).unwrap();
        let s1 = t.dashboard_snapshot("tr", "ts");
        let s2 = t.dashboard_snapshot("tr", "ts");
        assert_eq!(s1.metrics[0].scope, "a-scope");
        assert_eq!(s1.metrics[0].scope, s2.metrics[0].scope);
    }

    #[test]
    fn error_codes_all_present() {
        assert_eq!(
            CoverageError::SloBreach {
                slo_name: "x".into(),
                actual: 0.0,
                threshold: 0.0
            }
            .code(),
            "OCT_SLO_BREACH"
        );
        assert_eq!(
            CoverageError::InvalidEvent { reason: "x".into() }.code(),
            "OCT_INVALID_EVENT"
        );
        assert_eq!(
            CoverageError::NoEvents { scope: "x".into() }.code(),
            "OCT_NO_EVENTS"
        );
        assert_eq!(
            CoverageError::ScopeUnknown { scope: "x".into() }.code(),
            "OCT_SCOPE_UNKNOWN"
        );
    }

    #[test]
    fn error_display() {
        let e = CoverageError::SloBreach {
            slo_name: "cov".into(),
            actual: 0.5,
            threshold: 0.9,
        };
        assert!(e.to_string().contains("OCT_SLO_BREACH"));
    }

    #[test]
    fn event_and_scope_count() {
        let mut t = OfflineCoverageTracker::new();
        t.record_event(ev("a1", true, 100, "prod")).unwrap();
        t.record_event(ev("a2", true, 101, "staging")).unwrap();
        assert_eq!(t.event_count(), 2);
        assert_eq!(t.scope_count(), 2);
    }

    #[test]
    fn full_coverage_ratio() {
        let mut t = OfflineCoverageTracker::new();
        t.record_event(ev("a1", true, 100, "prod")).unwrap();
        t.record_event(ev("a2", true, 101, "prod")).unwrap();
        let m = t.compute_metrics("prod").unwrap();
        assert!((m.coverage_ratio - 1.0).abs() < 1e-10);
        assert_eq!(m.repair_debt_count, 0);
    }

    #[test]
    fn zero_coverage_ratio() {
        let mut t = OfflineCoverageTracker::new();
        t.record_event(ev("a1", false, 100, "prod")).unwrap();
        t.record_event(ev("a2", false, 101, "prod")).unwrap();
        let m = t.compute_metrics("prod").unwrap();
        assert!((m.coverage_ratio - 0.0).abs() < 1e-10);
    }

    #[test]
    fn snapshot_trace() {
        let t = OfflineCoverageTracker::new();
        let snap = t.dashboard_snapshot("trace-x", "2026-01-01");
        assert_eq!(snap.trace_id, "trace-x");
    }
}
