//! bd-29w6: Offline coverage tracker and SLO dashboards.
//!
//! Continuous coverage metrics, SLO breach alerts, traceable dashboard values.

use std::collections::BTreeMap;

const RESERVED_ARTIFACT_ID: &str = "<unknown>";

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
    UnknownMetric {
        metric_name: String,
    },
}

impl CoverageError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::SloBreach { .. } => "OCT_SLO_BREACH",
            Self::InvalidEvent { .. } => "OCT_INVALID_EVENT",
            Self::NoEvents { .. } => "OCT_NO_EVENTS",
            Self::ScopeUnknown { .. } => "OCT_SCOPE_UNKNOWN",
            Self::UnknownMetric { .. } => "OCT_UNKNOWN_METRIC",
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
                let is_repair_debt = slo_name == "repair_debt";
                let (actual_fmt, threshold_fmt) = if is_repair_debt {
                    (format!("{actual:.0}"), format!("{threshold:.0}"))
                } else {
                    (
                        format!("{:.2}%", actual * 100.0),
                        format!("{:.2}%", threshold * 100.0),
                    )
                };
                let comparator = if is_repair_debt { ">" } else { "<" };
                write!(
                    f,
                    "OCT_SLO_BREACH: {slo_name} {actual_fmt} {comparator} {threshold_fmt}"
                )
            }
            Self::InvalidEvent { reason } => write!(f, "OCT_INVALID_EVENT: {reason}"),
            Self::NoEvents { scope } => write!(f, "OCT_NO_EVENTS: {scope}"),
            Self::ScopeUnknown { scope } => write!(f, "OCT_SCOPE_UNKNOWN: {scope}"),
            Self::UnknownMetric { metric_name } => {
                write!(f, "OCT_UNKNOWN_METRIC: {metric_name}")
            }
        }
    }
}

/// Validate a coverage event.
fn validate_event(event: &CoverageEvent) -> Result<(), CoverageError> {
    let artifact_id = event.artifact_id.trim();
    if artifact_id.is_empty() {
        return Err(CoverageError::InvalidEvent {
            reason: "empty artifact_id".into(),
        });
    }
    if artifact_id == RESERVED_ARTIFACT_ID {
        return Err(CoverageError::InvalidEvent {
            reason: format!("artifact_id is reserved: {:?}", event.artifact_id),
        });
    }
    if event.artifact_id != artifact_id {
        return Err(CoverageError::InvalidEvent {
            reason: "artifact_id contains leading or trailing whitespace".into(),
        });
    }
    if event.artifact_id.contains('\0') {
        return Err(CoverageError::InvalidEvent {
            reason: "artifact_id must not contain null bytes".into(),
        });
    }
    let scope = event.scope.trim();
    if scope.is_empty() {
        return Err(CoverageError::InvalidEvent {
            reason: "empty scope".into(),
        });
    }
    if event.scope != scope {
        return Err(CoverageError::InvalidEvent {
            reason: "scope contains leading or trailing whitespace".into(),
        });
    }
    if event.scope.contains('\0') {
        return Err(CoverageError::InvalidEvent {
            reason: "scope must not contain null bytes".into(),
        });
    }
    Ok(())
}

/// Per-scope tracker state.
#[derive(Debug, Clone, Default)]
struct ScopeState {
    /// Latest status per artifact_id with event timestamp.
    artifacts: BTreeMap<String, ArtifactState>,
    event_count: usize,
}

#[derive(Debug, Clone, Copy)]
struct ArtifactState {
    available: bool,
    timestamp: u64,
}

use crate::capacity_defaults::aliases::MAX_EVENTS;

/// Offline coverage tracker.
#[derive(Default)]
pub struct OfflineCoverageTracker {
    scopes: BTreeMap<String, ScopeState>,
    all_events: Vec<CoverageEvent>,
    total_events: usize,
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
        match scope.artifacts.get(&event.artifact_id).copied() {
            // Ignore stale out-of-order telemetry updates.
            Some(existing) if event.timestamp < existing.timestamp => {}
            // Tie-breaker for same-timestamp updates is fail-closed:
            // if any report says unavailable, keep unavailable.
            Some(existing) if event.timestamp == existing.timestamp => {
                scope.artifacts.insert(
                    event.artifact_id.clone(),
                    ArtifactState {
                        available: existing.available && event.available,
                        timestamp: existing.timestamp,
                    },
                );
            }
            _ => {
                scope.artifacts.insert(
                    event.artifact_id.clone(),
                    ArtifactState {
                        available: event.available,
                        timestamp: event.timestamp,
                    },
                );
            }
        }
        scope.event_count = scope.event_count.saturating_add(1);
        push_bounded(&mut self.all_events, event, MAX_EVENTS);
        self.total_events = self.total_events.saturating_add(1);
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
        let available = state
            .artifacts
            .values()
            .filter(|entry| entry.available)
            .count();
        let repair_debt = total.saturating_sub(available);
        let coverage_ratio = if total == 0 {
            0.0
        } else {
            available as f64 / total as f64
        };
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
                _ => {
                    return Err(CoverageError::UnknownMetric {
                        metric_name: target.metric_name.clone(),
                    });
                }
            };

            // For repair_debt, breach = actual > threshold (debt too high)
            // For coverage/availability, breach = actual < threshold (ratio too low)
            // Fail-closed: NaN/Inf threshold → always breach (conservative)
            let breached = !target.threshold.is_finite()
                || if target.metric_name == "repair_debt" {
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
            event_count: self.total_events,
            trace_id: trace_id.to_string(),
            timestamp: timestamp.to_string(),
        }
    }

    /// Total events recorded.
    pub fn event_count(&self) -> usize {
        self.total_events
    }

    /// Known scopes.
    pub fn scope_count(&self) -> usize {
        self.scopes.len()
    }
}

/// Push an item to a bounded Vec, evicting oldest entries if at capacity.
fn push_bounded<T>(vec: &mut Vec<T>, item: T, max: usize) {
    if max == 0 {
        vec.clear();
        return;
    }
    if vec.len() >= max {
        let overflow = vec.len().saturating_sub(max).saturating_add(1);
        vec.drain(0..overflow.min(vec.len()));
    }
    vec.push(item);
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
    fn stale_event_does_not_override_newer_state() {
        let mut t = OfflineCoverageTracker::new();
        t.record_event(ev("a1", false, 200, "prod")).unwrap();
        // Older telemetry arrives late and must be ignored.
        t.record_event(ev("a1", true, 100, "prod")).unwrap();
        let m = t.compute_metrics("prod").unwrap();
        assert_eq!(m.available_count, 0);
    }

    #[test]
    fn equal_timestamp_tie_breaks_fail_closed() {
        let mut t = OfflineCoverageTracker::new();
        t.record_event(ev("a1", true, 200, "prod")).unwrap();
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
    fn invalid_event_reserved_id() {
        let mut t = OfflineCoverageTracker::new();
        let err = t
            .record_event(ev("<unknown>", true, 100, "prod"))
            .unwrap_err();
        assert_eq!(err.code(), "OCT_INVALID_EVENT");
    }

    #[test]
    fn invalid_event_whitespace_id() {
        let mut t = OfflineCoverageTracker::new();
        let err = t.record_event(ev("   ", true, 100, "prod")).unwrap_err();
        assert_eq!(err.code(), "OCT_INVALID_EVENT");
    }

    #[test]
    fn invalid_event_whitespace_scope() {
        let mut t = OfflineCoverageTracker::new();
        let err = t.record_event(ev("a1", true, 100, "   ")).unwrap_err();
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
        assert_eq!(
            CoverageError::UnknownMetric {
                metric_name: "x".into()
            }
            .code(),
            "OCT_UNKNOWN_METRIC"
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
    fn event_count_tracks_total_events_after_eviction() {
        let mut t = OfflineCoverageTracker::new();
        let total = MAX_EVENTS + 3;
        for i in 0..total {
            t.record_event(ev("a1", true, i as u64, "prod")).unwrap();
        }
        assert_eq!(t.event_count(), total);
        let snap = t.dashboard_snapshot("tr", "ts");
        assert_eq!(snap.event_count, total);
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
    fn nan_slo_threshold_triggers_breach() {
        let mut t = OfflineCoverageTracker::new();
        t.record_event(ev("a1", true, 100, "prod")).unwrap();
        let alerts = t
            .check_slos(&[slo("coverage", f64::NAN)], "prod", 200, "trace-nan")
            .unwrap();
        assert_eq!(
            alerts.len(),
            1,
            "NaN threshold must trigger SLO breach (fail-closed)"
        );
    }

    #[test]
    fn inf_slo_threshold_triggers_breach() {
        let mut t = OfflineCoverageTracker::new();
        t.record_event(ev("a1", true, 100, "prod")).unwrap();
        let alerts = t
            .check_slos(&[slo("coverage", f64::INFINITY)], "prod", 200, "trace-inf")
            .unwrap();
        assert_eq!(
            alerts.len(),
            1,
            "Inf threshold must trigger SLO breach (fail-closed)"
        );
    }

    #[test]
    fn unknown_slo_metric_rejected() {
        let mut t = OfflineCoverageTracker::new();
        t.record_event(ev("a1", true, 100, "prod")).unwrap();
        let err = t
            .check_slos(
                &[slo("availability_pct_typo", 0.9)],
                "prod",
                200,
                "trace-typo",
            )
            .unwrap_err();
        assert_eq!(err.code(), "OCT_UNKNOWN_METRIC");
    }

    #[test]
    fn snapshot_trace() {
        let t = OfflineCoverageTracker::new();
        let snap = t.dashboard_snapshot("trace-x", "2026-01-01");
        assert_eq!(snap.trace_id, "trace-x");
    }

    #[test]
    fn slo_breach_display_formats_percentages() {
        let err = CoverageError::SloBreach {
            slo_name: "coverage".into(),
            actual: 0.5,
            threshold: 0.9,
        };
        let rendered = err.to_string();
        assert!(rendered.contains("50.00%"));
        assert!(rendered.contains("90.00%"));
        assert!(rendered.contains(" < "));
    }

    #[test]
    fn slo_breach_display_formats_repair_debt_as_count() {
        let err = CoverageError::SloBreach {
            slo_name: "repair_debt".into(),
            actual: 3.0,
            threshold: 2.0,
        };
        let rendered = err.to_string();
        assert!(rendered.contains("3"));
        assert!(rendered.contains("2"));
        assert!(!rendered.contains('%'));
        assert!(rendered.contains(" > "));
        assert!(!rendered.contains(" < "));
    }

    #[test]
    fn invalid_event_with_leading_artifact_whitespace_is_not_recorded() {
        let mut t = OfflineCoverageTracker::new();

        let err = t.record_event(ev(" a1", true, 100, "prod")).unwrap_err();

        assert_eq!(err.code(), "OCT_INVALID_EVENT");
        assert_eq!(t.event_count(), 0);
        assert_eq!(t.scope_count(), 0);
    }

    #[test]
    fn invalid_event_with_trailing_scope_whitespace_is_not_recorded() {
        let mut t = OfflineCoverageTracker::new();

        let err = t.record_event(ev("a1", true, 100, "prod ")).unwrap_err();

        assert_eq!(err.code(), "OCT_INVALID_EVENT");
        assert_eq!(t.event_count(), 0);
        assert_eq!(t.scope_count(), 0);
    }

    #[test]
    fn invalid_reserved_artifact_with_padding_is_rejected_as_reserved() {
        let event = ev(" <unknown> ", true, 100, "prod");

        let err = validate_event(&event).unwrap_err();

        match err {
            CoverageError::InvalidEvent { reason } => {
                assert!(reason.contains("reserved"));
                assert!(reason.contains("<unknown>"));
            }
            other => unreachable!("expected invalid event, got {other:?}"),
        }
    }

    #[test]
    fn invalid_event_after_valid_event_preserves_existing_metrics() {
        let mut t = OfflineCoverageTracker::new();
        t.record_event(ev("a1", true, 100, "prod")).unwrap();

        let err = t.record_event(ev("bad", true, 101, " prod")).unwrap_err();
        let metrics = t.compute_metrics("prod").unwrap();

        assert_eq!(err.code(), "OCT_INVALID_EVENT");
        assert_eq!(t.event_count(), 1);
        assert_eq!(t.scope_count(), 1);
        assert_eq!(metrics.total_artifacts, 1);
        assert_eq!(metrics.available_count, 1);
    }

    #[test]
    fn compute_metrics_scope_lookup_is_case_sensitive() {
        let mut t = OfflineCoverageTracker::new();
        t.record_event(ev("a1", true, 100, "prod")).unwrap();

        let err = t.compute_metrics("PROD").unwrap_err();

        assert_eq!(
            err,
            CoverageError::ScopeUnknown {
                scope: "PROD".into()
            }
        );
    }

    #[test]
    fn check_slos_unknown_scope_fails_before_metric_name_validation() {
        let t = OfflineCoverageTracker::new();

        let err = t
            .check_slos(&[slo("not_a_metric", 0.9)], "missing", 200, "trace-missing")
            .unwrap_err();

        assert_eq!(
            err,
            CoverageError::ScopeUnknown {
                scope: "missing".into()
            }
        );
    }

    #[test]
    fn unknown_metric_error_preserves_metric_name() {
        let mut t = OfflineCoverageTracker::new();
        t.record_event(ev("a1", true, 100, "prod")).unwrap();

        let err = t
            .check_slos(
                &[slo("coverage_percent", 0.9)],
                "prod",
                200,
                "trace-bad-metric",
            )
            .unwrap_err();

        assert_eq!(
            err,
            CoverageError::UnknownMetric {
                metric_name: "coverage_percent".into()
            }
        );
    }

    #[test]
    fn negative_infinity_threshold_triggers_fail_closed_breach() {
        let mut t = OfflineCoverageTracker::new();
        t.record_event(ev("a1", true, 100, "prod")).unwrap();

        let alerts = t
            .check_slos(
                &[slo("availability", f64::NEG_INFINITY)],
                "prod",
                200,
                "trace-neg-inf",
            )
            .unwrap();

        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].slo_name, "availability");
        assert_eq!(alerts[0].trace_id, "trace-neg-inf");
    }

    #[test]
    fn push_bounded_zero_capacity_clears_existing_events() {
        let mut events = vec![ev("old", true, 100, "prod")];

        push_bounded(&mut events, ev("new", false, 101, "prod"), 0);

        assert!(events.is_empty());
    }

    #[test]
    fn push_bounded_evicts_oldest_when_capacity_already_exceeded() {
        let mut events = vec![
            ev("old-1", true, 100, "prod"),
            ev("old-2", true, 101, "prod"),
            ev("old-3", true, 102, "prod"),
        ];

        push_bounded(&mut events, ev("new", false, 103, "prod"), 2);

        assert_eq!(events.len(), 2);
        assert_eq!(events[0].artifact_id, "old-3");
        assert_eq!(events[1].artifact_id, "new");
    }

    #[test]
    fn check_slos_empty_target_list_returns_no_alerts() {
        let mut t = OfflineCoverageTracker::new();
        t.record_event(ev("a1", false, 100, "prod")).unwrap();

        let alerts = t
            .check_slos(&[], "prod", 200, "trace-empty-targets")
            .unwrap();

        assert!(alerts.is_empty());
    }

    #[test]
    fn repair_debt_negative_threshold_triggers_breach() {
        let mut t = OfflineCoverageTracker::new();
        t.record_event(ev("a1", true, 100, "prod")).unwrap();

        let alerts = t
            .check_slos(&[slo("repair_debt", -1.0)], "prod", 200, "trace-neg-debt")
            .unwrap();

        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].slo_name, "repair_debt");
        assert_eq!(alerts[0].actual_value, 0.0);
        assert_eq!(alerts[0].threshold, -1.0);
    }

    #[test]
    fn repair_debt_nan_threshold_triggers_fail_closed_breach() {
        let mut t = OfflineCoverageTracker::new();
        t.record_event(ev("a1", true, 100, "prod")).unwrap();

        let alerts = t
            .check_slos(
                &[slo("repair_debt", f64::NAN)],
                "prod",
                200,
                "trace-debt-nan",
            )
            .unwrap();

        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].slo_name, "repair_debt");
        assert!(alerts[0].threshold.is_nan());
    }

    #[test]
    fn compute_metrics_rejects_scope_with_trailing_whitespace() {
        let mut t = OfflineCoverageTracker::new();
        t.record_event(ev("a1", true, 100, "prod")).unwrap();

        let err = t.compute_metrics("prod ").unwrap_err();

        assert_eq!(
            err,
            CoverageError::ScopeUnknown {
                scope: "prod ".into()
            }
        );
    }

    #[test]
    fn null_byte_artifact_id_is_rejected_without_mutation() {
        let mut t = OfflineCoverageTracker::new();

        let err = t
            .record_event(ev("artifact\0id", true, 100, "prod"))
            .unwrap_err();

        assert_eq!(err.code(), "OCT_INVALID_EVENT");
        assert!(err.to_string().contains("null bytes"));
        assert_eq!(t.event_count(), 0);
        assert_eq!(t.scope_count(), 0);
    }

    #[test]
    fn null_byte_scope_is_rejected_without_mutation() {
        let mut t = OfflineCoverageTracker::new();

        let err = t
            .record_event(ev("a1", true, 100, "prod\0shadow"))
            .unwrap_err();

        assert_eq!(err.code(), "OCT_INVALID_EVENT");
        assert!(err.to_string().contains("null bytes"));
        assert_eq!(t.event_count(), 0);
        assert_eq!(t.scope_count(), 0);
    }

    #[test]
    fn equal_timestamp_unavailable_then_available_remains_unavailable() {
        let mut t = OfflineCoverageTracker::new();
        t.record_event(ev("a1", false, 200, "prod")).unwrap();
        t.record_event(ev("a1", true, 200, "prod")).unwrap();

        let m = t.compute_metrics("prod").unwrap();

        assert_eq!(m.total_artifacts, 1);
        assert_eq!(m.available_count, 0);
        assert_eq!(m.repair_debt_count, 1);
    }

    #[test]
    fn stale_unavailable_event_does_not_override_newer_available_state() {
        let mut t = OfflineCoverageTracker::new();
        t.record_event(ev("a1", true, 200, "prod")).unwrap();
        t.record_event(ev("a1", false, 100, "prod")).unwrap();

        let m = t.compute_metrics("prod").unwrap();

        assert_eq!(m.available_count, 1);
        assert_eq!(m.repair_debt_count, 0);
        assert_eq!(t.event_count(), 2);
    }

    #[test]
    fn coverage_threshold_just_above_actual_triggers_breach() {
        let mut t = OfflineCoverageTracker::new();
        t.record_event(ev("a1", true, 100, "prod")).unwrap();
        t.record_event(ev("a2", false, 101, "prod")).unwrap();

        let alerts = t
            .check_slos(&[slo("coverage", 0.500_001)], "prod", 200, "trace-edge")
            .unwrap();

        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].slo_name, "coverage");
        assert_eq!(alerts[0].actual_value, 0.5);
        assert_eq!(alerts[0].trace_id, "trace-edge");
    }

    #[test]
    fn unknown_metric_after_valid_target_returns_error() {
        let mut t = OfflineCoverageTracker::new();
        t.record_event(ev("a1", false, 100, "prod")).unwrap();

        let err = t
            .check_slos(
                &[slo("coverage", 0.9), slo("not_a_real_metric", 1.0)],
                "prod",
                200,
                "trace-mixed-targets",
            )
            .unwrap_err();

        assert_eq!(
            err,
            CoverageError::UnknownMetric {
                metric_name: "not_a_real_metric".into()
            }
        );
    }

    #[test]
    fn invalid_event_between_valid_updates_does_not_change_metrics() {
        let mut t = OfflineCoverageTracker::new();
        t.record_event(ev("a1", true, 100, "prod")).unwrap();
        let before = t.compute_metrics("prod").unwrap();

        let err = t
            .record_event(ev("bad\0id", false, 101, "prod"))
            .unwrap_err();
        let after = t.compute_metrics("prod").unwrap();

        assert_eq!(err.code(), "OCT_INVALID_EVENT");
        assert_eq!(before.available_count, after.available_count);
        assert_eq!(before.repair_debt_count, after.repair_debt_count);
        assert_eq!(t.event_count(), 1);
    }

    #[test]
    fn invalid_empty_scope_after_valid_event_does_not_create_scope() {
        let mut t = OfflineCoverageTracker::new();
        t.record_event(ev("a1", true, 100, "prod")).unwrap();

        let err = t.record_event(ev("a2", false, 101, "")).unwrap_err();

        assert_eq!(err.code(), "OCT_INVALID_EVENT");
        assert_eq!(t.event_count(), 1);
        assert_eq!(t.scope_count(), 1);
        assert!(t.compute_metrics("prod").is_ok());
    }

    #[test]
    fn invalid_reserved_artifact_after_valid_event_preserves_metrics() {
        let mut t = OfflineCoverageTracker::new();
        t.record_event(ev("a1", true, 100, "prod")).unwrap();
        let before = t.compute_metrics("prod").unwrap();

        let err = t
            .record_event(ev(RESERVED_ARTIFACT_ID, false, 101, "prod"))
            .unwrap_err();
        let after = t.compute_metrics("prod").unwrap();

        assert_eq!(err.code(), "OCT_INVALID_EVENT");
        assert_eq!(before.available_count, after.available_count);
        assert_eq!(before.total_artifacts, after.total_artifacts);
        assert_eq!(t.event_count(), 1);
    }

    #[test]
    fn compute_metrics_rejects_scope_with_leading_whitespace() {
        let mut t = OfflineCoverageTracker::new();
        t.record_event(ev("a1", true, 100, "prod")).unwrap();

        let err = t.compute_metrics(" prod").unwrap_err();

        assert_eq!(
            err,
            CoverageError::ScopeUnknown {
                scope: " prod".into()
            }
        );
    }

    #[test]
    fn check_slos_rejects_case_mismatched_metric_name() {
        let mut t = OfflineCoverageTracker::new();
        t.record_event(ev("a1", true, 100, "prod")).unwrap();

        let err = t
            .check_slos(&[slo("Coverage", 0.9)], "prod", 200, "trace-case-metric")
            .unwrap_err();

        assert_eq!(
            err,
            CoverageError::UnknownMetric {
                metric_name: "Coverage".into()
            }
        );
    }

    #[test]
    fn check_slos_rejects_metric_name_with_trailing_whitespace() {
        let mut t = OfflineCoverageTracker::new();
        t.record_event(ev("a1", true, 100, "prod")).unwrap();

        let err = t
            .check_slos(
                &[slo("availability ", 0.9)],
                "prod",
                200,
                "trace-space-metric",
            )
            .unwrap_err();

        assert_eq!(
            err,
            CoverageError::UnknownMetric {
                metric_name: "availability ".into()
            }
        );
    }

    #[test]
    fn unknown_metric_first_prevents_partial_alert_success() {
        let mut t = OfflineCoverageTracker::new();
        t.record_event(ev("a1", false, 100, "prod")).unwrap();

        let err = t
            .check_slos(
                &[slo("not_a_real_metric", 1.0), slo("coverage", 0.9)],
                "prod",
                200,
                "trace-unknown-first",
            )
            .unwrap_err();

        assert_eq!(
            err,
            CoverageError::UnknownMetric {
                metric_name: "not_a_real_metric".into()
            }
        );
    }

    #[test]
    fn availability_threshold_above_one_triggers_breach() {
        let mut t = OfflineCoverageTracker::new();
        t.record_event(ev("a1", true, 100, "prod")).unwrap();

        let alerts = t
            .check_slos(&[slo("availability", 1.01)], "prod", 200, "trace-over-one")
            .unwrap();

        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].slo_name, "availability");
        assert_eq!(alerts[0].actual_value, 1.0);
        assert_eq!(alerts[0].threshold, 1.01);
    }

    #[test]
    fn repair_debt_threshold_just_below_actual_triggers_breach() {
        let mut t = OfflineCoverageTracker::new();
        t.record_event(ev("a1", false, 100, "prod")).unwrap();

        let alerts = t
            .check_slos(
                &[slo("repair_debt", 0.999)],
                "prod",
                200,
                "trace-debt-edge",
            )
            .unwrap();

        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].slo_name, "repair_debt");
        assert_eq!(alerts[0].actual_value, 1.0);
        assert_eq!(alerts[0].threshold, 0.999);
    }
}
