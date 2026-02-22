//! bd-4jh9: VEF degraded-mode policy for proof lag/outage with explicit SLOs.
//!
//! Implements three degraded-mode tiers (`restricted`, `quarantine`, `halt`)
//! for the Verifiable Execution Fabric proof pipeline. Mode transitions are
//! deterministic, auditable, and recoverable.
//!
//! Structured logging codes:
//! - `VEF-DEGRADE-001` — mode transition
//! - `VEF-DEGRADE-002` — SLO breach detected
//! - `VEF-DEGRADE-003` — recovery initiated
//! - `VEF-DEGRADE-004` — recovery complete
//! - `VEF-DEGRADE-ERR-001` — transition failure

use serde::{Deserialize, Serialize};

// ── Audit event codes ───────────────────────────────────────────────────

pub const VEF_DEGRADE_001: &str = "VEF-DEGRADE-001";
pub const VEF_DEGRADE_002: &str = "VEF-DEGRADE-002";
pub const VEF_DEGRADE_003: &str = "VEF-DEGRADE-003";
pub const VEF_DEGRADE_004: &str = "VEF-DEGRADE-004";
pub const VEF_DEGRADE_ERR_001: &str = "VEF-DEGRADE-ERR-001";

// ── Degraded-mode tiers ─────────────────────────────────────────────────

/// The four possible states of the VEF proof pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VefMode {
    Normal,
    Restricted,
    Quarantine,
    Halt,
}

impl VefMode {
    /// Numeric severity: higher = more degraded.
    #[must_use]
    pub fn severity(self) -> u8 {
        match self {
            Self::Normal => 0,
            Self::Restricted => 1,
            Self::Quarantine => 2,
            Self::Halt => 3,
        }
    }

    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::Restricted => "restricted",
            Self::Quarantine => "quarantine",
            Self::Halt => "halt",
        }
    }
}

// ── SLO thresholds ──────────────────────────────────────────────────────

/// SLO threshold set for a single tier boundary.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProofLagSlo {
    pub max_proof_lag_secs: u64,
    pub max_backlog_depth: u64,
    pub max_error_rate: f64,
}

impl ProofLagSlo {
    #[must_use]
    pub fn new(max_proof_lag_secs: u64, max_backlog_depth: u64, max_error_rate: f64) -> Self {
        Self {
            max_proof_lag_secs,
            max_backlog_depth,
            max_error_rate,
        }
    }

    /// Returns true if any metric in `metrics` breaches this SLO.
    #[must_use]
    pub fn breached_by(&self, metrics: &ProofLagMetrics) -> bool {
        metrics.proof_lag_secs > self.max_proof_lag_secs
            || metrics.backlog_depth > self.max_backlog_depth
            || metrics.error_rate > self.max_error_rate
    }

    /// Returns the name of the first metric that breaches this SLO, if any.
    #[must_use]
    pub fn first_breached_metric(&self, metrics: &ProofLagMetrics) -> Option<&'static str> {
        if metrics.proof_lag_secs > self.max_proof_lag_secs {
            Some("proof_lag_secs")
        } else if metrics.backlog_depth > self.max_backlog_depth {
            Some("backlog_depth")
        } else if metrics.error_rate > self.max_error_rate {
            Some("error_rate")
        } else {
            None
        }
    }
}

// ── Configuration ───────────────────────────────────────────────────────

/// Policy-configurable degraded-mode configuration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VefDegradedModeConfig {
    pub restricted_slo: ProofLagSlo,
    pub quarantine_slo: ProofLagSlo,
    pub halt_multiplier: f64,
    pub halt_error_rate: f64,
    pub halt_heartbeat_timeout_secs: u64,
    pub stabilization_window_secs: u64,
}

impl Default for VefDegradedModeConfig {
    fn default() -> Self {
        Self {
            restricted_slo: ProofLagSlo::new(300, 100, 0.10),
            quarantine_slo: ProofLagSlo::new(900, 500, 0.30),
            halt_multiplier: 2.0,
            halt_error_rate: 0.50,
            halt_heartbeat_timeout_secs: 60,
            stabilization_window_secs: 120,
        }
    }
}

impl VefDegradedModeConfig {
    /// Compute the halt-tier SLO from quarantine thresholds and multiplier.
    #[must_use]
    pub fn halt_slo(&self) -> ProofLagSlo {
        ProofLagSlo {
            max_proof_lag_secs: (self.quarantine_slo.max_proof_lag_secs as f64
                * self.halt_multiplier) as u64,
            max_backlog_depth: (self.quarantine_slo.max_backlog_depth as f64 * self.halt_multiplier)
                as u64,
            max_error_rate: self.halt_error_rate,
        }
    }
}

// ── Proof lag metrics ───────────────────────────────────────────────────

/// Snapshot of proof pipeline health metrics.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProofLagMetrics {
    pub proof_lag_secs: u64,
    pub backlog_depth: u64,
    pub error_rate: f64,
    pub heartbeat_age_secs: u64,
}

impl ProofLagMetrics {
    #[must_use]
    pub fn healthy() -> Self {
        Self {
            proof_lag_secs: 0,
            backlog_depth: 0,
            error_rate: 0.0,
            heartbeat_age_secs: 0,
        }
    }
}

// ── Action classification ───────────────────────────────────────────────

/// Whether an action is high-risk (blocked in quarantine) or low-risk.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ActionRisk {
    HighRisk,
    LowRisk,
    HealthCheck,
}

/// Decision result for a VEF-gated action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VefActionDecision {
    pub permitted: bool,
    pub mode: VefMode,
    pub annotation: Option<String>,
}

// ── Audit events ────────────────────────────────────────────────────────

/// Structured audit event for VEF mode transitions.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VefModeTransitionEvent {
    pub event_code: String,
    pub timestamp_secs: u64,
    pub current_mode: VefMode,
    pub target_mode: VefMode,
    pub triggering_metric: String,
    pub metric_value: f64,
    pub slo_threshold: f64,
    pub correlation_id: String,
}

/// SLO breach detection event.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VefSloBreachEvent {
    pub event_code: String,
    pub timestamp_secs: u64,
    pub metric_name: String,
    pub observed_value: f64,
    pub threshold: f64,
    pub tier: VefMode,
    pub correlation_id: String,
}

/// Recovery initiated event.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VefRecoveryInitiatedEvent {
    pub event_code: String,
    pub timestamp_secs: u64,
    pub from_mode: VefMode,
    pub correlation_id: String,
}

/// Recovery receipt emitted on de-escalation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VefRecoveryReceipt {
    pub event_code: String,
    pub timestamp_secs: u64,
    pub degraded_mode_duration_secs: u64,
    pub actions_affected: u64,
    pub recovery_trigger: String,
    pub pipeline_health_at_recovery: ProofLagMetrics,
    pub from_mode: VefMode,
    pub to_mode: VefMode,
    pub correlation_id: String,
}

/// Union of all VEF degraded-mode audit events.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "event_type", rename_all = "snake_case")]
pub enum VefDegradedModeEvent {
    ModeTransition(VefModeTransitionEvent),
    SloBreach(VefSloBreachEvent),
    RecoveryInitiated(VefRecoveryInitiatedEvent),
    RecoveryComplete(VefRecoveryReceipt),
    TransitionError(VefTransitionErrorEvent),
}

impl VefDegradedModeEvent {
    #[must_use]
    pub fn code(&self) -> &str {
        match self {
            Self::ModeTransition(e) => &e.event_code,
            Self::SloBreach(e) => &e.event_code,
            Self::RecoveryInitiated(e) => &e.event_code,
            Self::RecoveryComplete(e) => &e.event_code,
            Self::TransitionError(e) => &e.event_code,
        }
    }
}

/// Transition error event.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VefTransitionErrorEvent {
    pub event_code: String,
    pub timestamp_secs: u64,
    pub current_mode: VefMode,
    pub attempted_mode: VefMode,
    pub reason: String,
    pub correlation_id: String,
}

// ── Engine ──────────────────────────────────────────────────────────────

/// Internal context for a degraded-mode session.
#[derive(Debug, Clone)]
struct DegradedContext {
    entered_at_secs: u64,
    mode: VefMode,
    actions_affected: u64,
    stabilization_started_at_secs: Option<u64>,
    stabilization_target: Option<VefMode>,
}

/// The VEF degraded-mode policy engine.
///
/// INV-VEF-DM-DETERMINISTIC: identical metric sequences produce identical
/// mode transition traces.
#[derive(Debug, Clone)]
pub struct VefDegradedModeEngine {
    config: VefDegradedModeConfig,
    mode: VefMode,
    context: Option<DegradedContext>,
    audit_log: Vec<VefDegradedModeEvent>,
}

impl VefDegradedModeEngine {
    #[must_use]
    pub fn new(config: VefDegradedModeConfig) -> Self {
        Self {
            config,
            mode: VefMode::Normal,
            context: None,
            audit_log: Vec::new(),
        }
    }

    #[must_use]
    pub fn mode(&self) -> VefMode {
        self.mode
    }

    #[must_use]
    pub fn audit_log(&self) -> &[VefDegradedModeEvent] {
        &self.audit_log
    }

    #[must_use]
    pub fn config(&self) -> &VefDegradedModeConfig {
        &self.config
    }

    /// Determine the target mode based on current metrics.
    /// INV-VEF-DM-DETERMINISTIC: pure function of metrics + config.
    #[must_use]
    pub fn target_mode_for_metrics(&self, metrics: &ProofLagMetrics) -> VefMode {
        let halt_slo = self.config.halt_slo();

        // Check halt first (heartbeat timeout OR SLO breach)
        if metrics.heartbeat_age_secs > self.config.halt_heartbeat_timeout_secs
            || halt_slo.breached_by(metrics)
        {
            return VefMode::Halt;
        }
        // Check quarantine
        if self.config.quarantine_slo.breached_by(metrics) {
            return VefMode::Quarantine;
        }
        // Check restricted
        if self.config.restricted_slo.breached_by(metrics) {
            return VefMode::Restricted;
        }
        VefMode::Normal
    }

    /// Observe new metrics and potentially transition mode.
    ///
    /// Escalation is immediate; de-escalation requires stabilization window.
    pub fn observe_metrics(
        &mut self,
        metrics: &ProofLagMetrics,
        now_secs: u64,
        correlation_id: &str,
    ) {
        let target = self.target_mode_for_metrics(metrics);

        if target.severity() > self.mode.severity() {
            // INV-VEF-DM-ESCALATE-IMMEDIATE: escalate immediately
            self.escalate(target, metrics, now_secs, correlation_id);
        } else if target.severity() < self.mode.severity() {
            // INV-VEF-DM-DEESCALATE-STABILIZED: de-escalate requires stabilization
            self.maybe_deescalate(target, metrics, now_secs, correlation_id);
        } else {
            // Same mode: reset stabilization if we were stabilizing toward a different target
            if let Some(ctx) = &mut self.context {
                if ctx.stabilization_target.is_some_and(|t| t != target) {
                    ctx.stabilization_started_at_secs = None;
                    ctx.stabilization_target = None;
                }
            }
        }
    }

    /// Evaluate whether an action is permitted in the current mode.
    #[must_use]
    pub fn evaluate_action(
        &mut self,
        action_risk: ActionRisk,
        action_name: &str,
    ) -> VefActionDecision {
        let (permitted, annotation) = match self.mode {
            VefMode::Normal => (true, None),
            VefMode::Restricted => (
                true,
                Some(format!(
                    "vef_restricted: action {} proceeds with enhanced monitoring",
                    action_name
                )),
            ),
            VefMode::Quarantine => match action_risk {
                ActionRisk::HighRisk => (
                    false,
                    Some(format!(
                        "vef_quarantine: high-risk action {} blocked",
                        action_name
                    )),
                ),
                ActionRisk::LowRisk | ActionRisk::HealthCheck => (
                    true,
                    Some(format!(
                        "vef_quarantine: action {} permitted with warning",
                        action_name
                    )),
                ),
            },
            VefMode::Halt => match action_risk {
                ActionRisk::HealthCheck => (
                    true,
                    Some(format!("vef_halt: health-check {} permitted", action_name)),
                ),
                _ => (
                    false,
                    Some(format!(
                        "vef_halt: action {} blocked until recovery",
                        action_name
                    )),
                ),
            },
        };

        // Track affected actions in degraded mode
        if self.mode != VefMode::Normal {
            if let Some(ctx) = &mut self.context {
                ctx.actions_affected += 1;
            }
        }

        VefActionDecision {
            permitted,
            mode: self.mode,
            annotation,
        }
    }

    // ── Internal transition helpers ─────────────────────────────────────

    fn escalate(
        &mut self,
        target: VefMode,
        metrics: &ProofLagMetrics,
        now_secs: u64,
        correlation_id: &str,
    ) {
        let (triggering_metric, metric_value, slo_threshold) =
            self.find_breach_details(target, metrics);

        // Emit SLO breach event
        self.audit_log
            .push(VefDegradedModeEvent::SloBreach(VefSloBreachEvent {
                event_code: VEF_DEGRADE_002.to_string(),
                timestamp_secs: now_secs,
                metric_name: triggering_metric.to_string(),
                observed_value: metric_value,
                threshold: slo_threshold,
                tier: target,
                correlation_id: correlation_id.to_string(),
            }));

        // Emit mode transition event
        self.audit_log.push(VefDegradedModeEvent::ModeTransition(
            VefModeTransitionEvent {
                event_code: VEF_DEGRADE_001.to_string(),
                timestamp_secs: now_secs,
                current_mode: self.mode,
                target_mode: target,
                triggering_metric: triggering_metric.to_string(),
                metric_value,
                slo_threshold,
                correlation_id: correlation_id.to_string(),
            },
        ));

        let prev_actions = self.context.as_ref().map_or(0, |ctx| ctx.actions_affected);

        self.mode = target;
        self.context = Some(DegradedContext {
            entered_at_secs: self
                .context
                .as_ref()
                .map_or(now_secs, |ctx| ctx.entered_at_secs),
            mode: target,
            actions_affected: prev_actions,
            stabilization_started_at_secs: None,
            stabilization_target: None,
        });
    }

    fn maybe_deescalate(
        &mut self,
        target: VefMode,
        metrics: &ProofLagMetrics,
        now_secs: u64,
        correlation_id: &str,
    ) {
        // Step-down: de-escalate one tier at a time
        let next_down = match self.mode {
            VefMode::Halt => VefMode::Quarantine,
            VefMode::Quarantine => VefMode::Restricted,
            VefMode::Restricted => VefMode::Normal,
            VefMode::Normal => return,
        };

        // Only consider stepping down if target severity allows it
        if next_down.severity() < target.severity() {
            return;
        }

        let ctx = match &mut self.context {
            Some(ctx) => ctx,
            None => return,
        };

        // Check if stabilization is already tracking this target
        match ctx.stabilization_started_at_secs {
            None => {
                // Start stabilization window
                ctx.stabilization_started_at_secs = Some(now_secs);
                ctx.stabilization_target = Some(next_down);
                self.audit_log.push(VefDegradedModeEvent::RecoveryInitiated(
                    VefRecoveryInitiatedEvent {
                        event_code: VEF_DEGRADE_003.to_string(),
                        timestamp_secs: now_secs,
                        from_mode: self.mode,
                        correlation_id: correlation_id.to_string(),
                    },
                ));
            }
            Some(started) => {
                let stable_for = now_secs.saturating_sub(started);
                if stable_for >= self.config.stabilization_window_secs {
                    // Stabilization complete: emit recovery receipt and step down
                    let duration = now_secs.saturating_sub(ctx.entered_at_secs);
                    let actions_affected = ctx.actions_affected;

                    self.audit_log.push(VefDegradedModeEvent::RecoveryComplete(
                        VefRecoveryReceipt {
                            event_code: VEF_DEGRADE_004.to_string(),
                            timestamp_secs: now_secs,
                            degraded_mode_duration_secs: duration,
                            actions_affected,
                            recovery_trigger: format!(
                                "all_metrics_below_{}_slo",
                                next_down.label()
                            ),
                            pipeline_health_at_recovery: metrics.clone(),
                            from_mode: self.mode,
                            to_mode: next_down,
                            correlation_id: correlation_id.to_string(),
                        },
                    ));

                    // Emit mode transition event
                    let (triggering_metric, metric_value, slo_threshold) = (
                        "recovery_stabilized",
                        0.0_f64,
                        self.config.stabilization_window_secs as f64,
                    );
                    self.audit_log.push(VefDegradedModeEvent::ModeTransition(
                        VefModeTransitionEvent {
                            event_code: VEF_DEGRADE_001.to_string(),
                            timestamp_secs: now_secs,
                            current_mode: self.mode,
                            target_mode: next_down,
                            triggering_metric: triggering_metric.to_string(),
                            metric_value,
                            slo_threshold,
                            correlation_id: correlation_id.to_string(),
                        },
                    ));

                    self.mode = next_down;
                    if next_down == VefMode::Normal {
                        self.context = None;
                    } else {
                        // Reset stabilization for potential further de-escalation
                        let ctx = self.context.as_mut().unwrap();
                        ctx.mode = next_down;
                        ctx.stabilization_started_at_secs = None;
                        ctx.stabilization_target = None;
                    }
                }
                // else: still waiting for stabilization window
            }
        }
    }

    fn find_breach_details(
        &self,
        target: VefMode,
        metrics: &ProofLagMetrics,
    ) -> (&'static str, f64, f64) {
        let slo = match target {
            VefMode::Halt => {
                // Check heartbeat first
                if metrics.heartbeat_age_secs > self.config.halt_heartbeat_timeout_secs {
                    return (
                        "heartbeat_age_secs",
                        metrics.heartbeat_age_secs as f64,
                        self.config.halt_heartbeat_timeout_secs as f64,
                    );
                }
                self.config.halt_slo()
            }
            VefMode::Quarantine => self.config.quarantine_slo.clone(),
            VefMode::Restricted => self.config.restricted_slo.clone(),
            VefMode::Normal => {
                return ("none", 0.0, 0.0);
            }
        };

        if metrics.proof_lag_secs > slo.max_proof_lag_secs {
            (
                "proof_lag_secs",
                metrics.proof_lag_secs as f64,
                slo.max_proof_lag_secs as f64,
            )
        } else if metrics.backlog_depth > slo.max_backlog_depth {
            (
                "backlog_depth",
                metrics.backlog_depth as f64,
                slo.max_backlog_depth as f64,
            )
        } else if metrics.error_rate > slo.max_error_rate {
            ("error_rate", metrics.error_rate, slo.max_error_rate)
        } else {
            ("unknown", 0.0, 0.0)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_engine() -> VefDegradedModeEngine {
        VefDegradedModeEngine::new(VefDegradedModeConfig::default())
    }

    // ── Tier semantics ──────────────────────────────────────────────────

    #[test]
    fn normal_mode_by_default() {
        let engine = default_engine();
        assert_eq!(engine.mode(), VefMode::Normal);
        assert!(engine.audit_log().is_empty());
    }

    #[test]
    fn restricted_on_proof_lag_breach() {
        let mut engine = default_engine();
        let metrics = ProofLagMetrics {
            proof_lag_secs: 301,
            backlog_depth: 0,
            error_rate: 0.0,
            heartbeat_age_secs: 0,
        };
        engine.observe_metrics(&metrics, 1000, "corr-1");
        assert_eq!(engine.mode(), VefMode::Restricted);
    }

    #[test]
    fn restricted_on_backlog_breach() {
        let mut engine = default_engine();
        let metrics = ProofLagMetrics {
            proof_lag_secs: 0,
            backlog_depth: 101,
            error_rate: 0.0,
            heartbeat_age_secs: 0,
        };
        engine.observe_metrics(&metrics, 1000, "corr-2");
        assert_eq!(engine.mode(), VefMode::Restricted);
    }

    #[test]
    fn restricted_on_error_rate_breach() {
        let mut engine = default_engine();
        let metrics = ProofLagMetrics {
            proof_lag_secs: 0,
            backlog_depth: 0,
            error_rate: 0.11,
            heartbeat_age_secs: 0,
        };
        engine.observe_metrics(&metrics, 1000, "corr-3");
        assert_eq!(engine.mode(), VefMode::Restricted);
    }

    #[test]
    fn quarantine_on_slo_breach() {
        let mut engine = default_engine();
        let metrics = ProofLagMetrics {
            proof_lag_secs: 901,
            backlog_depth: 0,
            error_rate: 0.0,
            heartbeat_age_secs: 0,
        };
        engine.observe_metrics(&metrics, 1000, "corr-4");
        assert_eq!(engine.mode(), VefMode::Quarantine);
    }

    #[test]
    fn halt_on_critical_lag() {
        let mut engine = default_engine();
        let metrics = ProofLagMetrics {
            proof_lag_secs: 1801,
            backlog_depth: 0,
            error_rate: 0.0,
            heartbeat_age_secs: 0,
        };
        engine.observe_metrics(&metrics, 1000, "corr-5");
        assert_eq!(engine.mode(), VefMode::Halt);
    }

    #[test]
    fn halt_on_heartbeat_timeout() {
        let mut engine = default_engine();
        let metrics = ProofLagMetrics {
            proof_lag_secs: 0,
            backlog_depth: 0,
            error_rate: 0.0,
            heartbeat_age_secs: 61,
        };
        engine.observe_metrics(&metrics, 1000, "corr-6");
        assert_eq!(engine.mode(), VefMode::Halt);
    }

    #[test]
    fn halt_on_error_rate_critical() {
        let mut engine = default_engine();
        let metrics = ProofLagMetrics {
            proof_lag_secs: 0,
            backlog_depth: 0,
            error_rate: 0.51,
            heartbeat_age_secs: 0,
        };
        engine.observe_metrics(&metrics, 1000, "corr-7");
        assert_eq!(engine.mode(), VefMode::Halt);
    }

    // ── Transition paths ────────────────────────────────────────────────

    #[test]
    fn normal_to_restricted_to_quarantine_escalation() {
        let mut engine = default_engine();

        // Normal -> Restricted
        let m1 = ProofLagMetrics {
            proof_lag_secs: 301,
            backlog_depth: 0,
            error_rate: 0.0,
            heartbeat_age_secs: 0,
        };
        engine.observe_metrics(&m1, 1000, "corr-esc");
        assert_eq!(engine.mode(), VefMode::Restricted);

        // Restricted -> Quarantine
        let m2 = ProofLagMetrics {
            proof_lag_secs: 901,
            backlog_depth: 0,
            error_rate: 0.0,
            heartbeat_age_secs: 0,
        };
        engine.observe_metrics(&m2, 1100, "corr-esc");
        assert_eq!(engine.mode(), VefMode::Quarantine);
    }

    #[test]
    fn skip_restricted_direct_to_quarantine() {
        let mut engine = default_engine();
        let metrics = ProofLagMetrics {
            proof_lag_secs: 901,
            backlog_depth: 0,
            error_rate: 0.0,
            heartbeat_age_secs: 0,
        };
        engine.observe_metrics(&metrics, 1000, "corr-skip");
        assert_eq!(engine.mode(), VefMode::Quarantine);
    }

    #[test]
    fn skip_to_halt_directly() {
        let mut engine = default_engine();
        let metrics = ProofLagMetrics {
            proof_lag_secs: 1801,
            backlog_depth: 0,
            error_rate: 0.0,
            heartbeat_age_secs: 0,
        };
        engine.observe_metrics(&metrics, 1000, "corr-direct-halt");
        assert_eq!(engine.mode(), VefMode::Halt);
    }

    // ── De-escalation ───────────────────────────────────────────────────

    #[test]
    fn deescalation_requires_stabilization_window() {
        let mut engine = default_engine();

        // Escalate to restricted
        let bad = ProofLagMetrics {
            proof_lag_secs: 301,
            backlog_depth: 0,
            error_rate: 0.0,
            heartbeat_age_secs: 0,
        };
        engine.observe_metrics(&bad, 1000, "corr-deesc");
        assert_eq!(engine.mode(), VefMode::Restricted);

        // Metrics recover
        let good = ProofLagMetrics::healthy();

        // First observation: starts stabilization
        engine.observe_metrics(&good, 1050, "corr-deesc");
        assert_eq!(engine.mode(), VefMode::Restricted); // still restricted

        // Before window elapses
        engine.observe_metrics(&good, 1169, "corr-deesc");
        assert_eq!(engine.mode(), VefMode::Restricted);

        // After window elapses (120s)
        engine.observe_metrics(&good, 1170, "corr-deesc");
        assert_eq!(engine.mode(), VefMode::Normal);
    }

    #[test]
    fn deescalation_resets_on_metric_regression() {
        let mut engine = default_engine();

        // Escalate to restricted
        let bad = ProofLagMetrics {
            proof_lag_secs: 301,
            backlog_depth: 0,
            error_rate: 0.0,
            heartbeat_age_secs: 0,
        };
        engine.observe_metrics(&bad, 1000, "corr-regress");
        assert_eq!(engine.mode(), VefMode::Restricted);

        // Start recovery
        let good = ProofLagMetrics::healthy();
        engine.observe_metrics(&good, 1050, "corr-regress");

        // Regress: metrics bad again -> escalate back
        engine.observe_metrics(&bad, 1100, "corr-regress");
        assert_eq!(engine.mode(), VefMode::Restricted);

        // Re-start recovery
        engine.observe_metrics(&good, 1200, "corr-regress");
        // Must wait full window again
        engine.observe_metrics(&good, 1319, "corr-regress");
        assert_eq!(engine.mode(), VefMode::Restricted);
        engine.observe_metrics(&good, 1320, "corr-regress");
        assert_eq!(engine.mode(), VefMode::Normal);
    }

    #[test]
    fn halt_deescalates_through_quarantine_restricted() {
        let mut engine = default_engine();

        // Escalate to halt
        let halt_metrics = ProofLagMetrics {
            proof_lag_secs: 1801,
            backlog_depth: 0,
            error_rate: 0.0,
            heartbeat_age_secs: 0,
        };
        engine.observe_metrics(&halt_metrics, 1000, "corr-step");
        assert_eq!(engine.mode(), VefMode::Halt);

        // Metrics improve to quarantine-level
        let quarantine_metrics = ProofLagMetrics {
            proof_lag_secs: 500,
            backlog_depth: 0,
            error_rate: 0.0,
            heartbeat_age_secs: 0,
        };
        engine.observe_metrics(&quarantine_metrics, 1050, "corr-step");
        assert_eq!(engine.mode(), VefMode::Halt); // stabilizing
        engine.observe_metrics(&quarantine_metrics, 1170, "corr-step");
        assert_eq!(engine.mode(), VefMode::Quarantine); // stepped down

        // Metrics improve to restricted-level
        let restricted_metrics = ProofLagMetrics {
            proof_lag_secs: 200,
            backlog_depth: 0,
            error_rate: 0.0,
            heartbeat_age_secs: 0,
        };
        engine.observe_metrics(&restricted_metrics, 1200, "corr-step");
        assert_eq!(engine.mode(), VefMode::Quarantine); // stabilizing
        engine.observe_metrics(&restricted_metrics, 1320, "corr-step");
        assert_eq!(engine.mode(), VefMode::Restricted); // stepped down

        // Metrics fully recover
        let healthy = ProofLagMetrics::healthy();
        engine.observe_metrics(&healthy, 1350, "corr-step");
        assert_eq!(engine.mode(), VefMode::Restricted); // stabilizing
        engine.observe_metrics(&healthy, 1470, "corr-step");
        assert_eq!(engine.mode(), VefMode::Normal);
    }

    // ── Determinism ─────────────────────────────────────────────────────

    #[test]
    fn deterministic_identical_metric_sequences() {
        let metric_sequence = vec![
            (
                ProofLagMetrics {
                    proof_lag_secs: 301,
                    backlog_depth: 0,
                    error_rate: 0.0,
                    heartbeat_age_secs: 0,
                },
                1000u64,
            ),
            (
                ProofLagMetrics {
                    proof_lag_secs: 901,
                    backlog_depth: 0,
                    error_rate: 0.0,
                    heartbeat_age_secs: 0,
                },
                1100,
            ),
            (ProofLagMetrics::healthy(), 1200),
            (ProofLagMetrics::healthy(), 1320),
        ];

        let mut run1 = default_engine();
        let mut run2 = default_engine();

        for (m, t) in &metric_sequence {
            run1.observe_metrics(m, *t, "det-1");
            run2.observe_metrics(m, *t, "det-2");
        }

        assert_eq!(run1.mode(), run2.mode());
        assert_eq!(run1.audit_log().len(), run2.audit_log().len());
        for (e1, e2) in run1.audit_log().iter().zip(run2.audit_log().iter()) {
            assert_eq!(e1.code(), e2.code());
        }
    }

    // ── Audit events ────────────────────────────────────────────────────

    #[test]
    fn escalation_emits_slo_breach_and_transition_events() {
        let mut engine = default_engine();
        let metrics = ProofLagMetrics {
            proof_lag_secs: 301,
            backlog_depth: 0,
            error_rate: 0.0,
            heartbeat_age_secs: 0,
        };
        engine.observe_metrics(&metrics, 1000, "corr-audit");

        let codes: Vec<&str> = engine.audit_log().iter().map(|e| e.code()).collect();
        assert!(codes.contains(&VEF_DEGRADE_002), "SLO breach event");
        assert!(codes.contains(&VEF_DEGRADE_001), "mode transition event");
    }

    #[test]
    fn deescalation_emits_recovery_receipt() {
        let mut engine = default_engine();

        let bad = ProofLagMetrics {
            proof_lag_secs: 301,
            backlog_depth: 0,
            error_rate: 0.0,
            heartbeat_age_secs: 0,
        };
        engine.observe_metrics(&bad, 1000, "corr-receipt");

        let good = ProofLagMetrics::healthy();
        engine.observe_metrics(&good, 1050, "corr-receipt");
        engine.observe_metrics(&good, 1170, "corr-receipt");

        let codes: Vec<&str> = engine.audit_log().iter().map(|e| e.code()).collect();
        assert!(codes.contains(&VEF_DEGRADE_003), "recovery initiated event");
        assert!(
            codes.contains(&VEF_DEGRADE_004),
            "recovery complete receipt"
        );

        // Verify receipt fields
        let receipt = engine
            .audit_log()
            .iter()
            .find_map(|e| {
                if let VefDegradedModeEvent::RecoveryComplete(r) = e {
                    Some(r)
                } else {
                    None
                }
            })
            .expect("recovery receipt");
        assert!(receipt.degraded_mode_duration_secs > 0);
        assert_eq!(receipt.from_mode, VefMode::Restricted);
        assert_eq!(receipt.to_mode, VefMode::Normal);
    }

    #[test]
    fn transition_event_has_required_fields() {
        let mut engine = default_engine();
        let metrics = ProofLagMetrics {
            proof_lag_secs: 301,
            backlog_depth: 0,
            error_rate: 0.0,
            heartbeat_age_secs: 0,
        };
        engine.observe_metrics(&metrics, 1000, "corr-fields");

        let transition = engine
            .audit_log()
            .iter()
            .find_map(|e| {
                if let VefDegradedModeEvent::ModeTransition(t) = e {
                    Some(t)
                } else {
                    None
                }
            })
            .expect("transition event");

        assert_eq!(transition.current_mode, VefMode::Normal);
        assert_eq!(transition.target_mode, VefMode::Restricted);
        assert_eq!(transition.triggering_metric, "proof_lag_secs");
        assert_eq!(transition.metric_value, 301.0);
        assert_eq!(transition.slo_threshold, 300.0);
        assert_eq!(transition.timestamp_secs, 1000);
        assert_eq!(transition.correlation_id, "corr-fields");
    }

    // ── Action evaluation ───────────────────────────────────────────────

    #[test]
    fn normal_permits_all() {
        let mut engine = default_engine();
        let d = engine.evaluate_action(ActionRisk::HighRisk, "policy.change");
        assert!(d.permitted);
        assert!(d.annotation.is_none());
    }

    #[test]
    fn restricted_permits_with_annotation() {
        let mut engine = default_engine();
        engine.observe_metrics(
            &ProofLagMetrics {
                proof_lag_secs: 301,
                backlog_depth: 0,
                error_rate: 0.0,
                heartbeat_age_secs: 0,
            },
            1000,
            "corr",
        );
        let d = engine.evaluate_action(ActionRisk::HighRisk, "policy.change");
        assert!(d.permitted);
        assert!(d.annotation.is_some());
    }

    #[test]
    fn quarantine_blocks_high_risk() {
        let mut engine = default_engine();
        engine.observe_metrics(
            &ProofLagMetrics {
                proof_lag_secs: 901,
                backlog_depth: 0,
                error_rate: 0.0,
                heartbeat_age_secs: 0,
            },
            1000,
            "corr",
        );
        let high = engine.evaluate_action(ActionRisk::HighRisk, "policy.change");
        assert!(!high.permitted);
        let low = engine.evaluate_action(ActionRisk::LowRisk, "read.data");
        assert!(low.permitted);
    }

    #[test]
    fn halt_blocks_all_except_health_check() {
        let mut engine = default_engine();
        engine.observe_metrics(
            &ProofLagMetrics {
                proof_lag_secs: 1801,
                backlog_depth: 0,
                error_rate: 0.0,
                heartbeat_age_secs: 0,
            },
            1000,
            "corr",
        );
        let high = engine.evaluate_action(ActionRisk::HighRisk, "policy.change");
        assert!(!high.permitted);
        let low = engine.evaluate_action(ActionRisk::LowRisk, "read.data");
        assert!(!low.permitted);
        let health = engine.evaluate_action(ActionRisk::HealthCheck, "health.check");
        assert!(health.permitted);
    }

    // ── SLO configuration ───────────────────────────────────────────────

    #[test]
    fn custom_slo_thresholds() {
        let config = VefDegradedModeConfig {
            restricted_slo: ProofLagSlo::new(60, 10, 0.05),
            quarantine_slo: ProofLagSlo::new(180, 50, 0.15),
            halt_multiplier: 3.0,
            halt_error_rate: 0.40,
            halt_heartbeat_timeout_secs: 30,
            stabilization_window_secs: 60,
        };
        let mut engine = VefDegradedModeEngine::new(config);

        // Should be restricted at 61s lag (not 301)
        let metrics = ProofLagMetrics {
            proof_lag_secs: 61,
            backlog_depth: 0,
            error_rate: 0.0,
            heartbeat_age_secs: 0,
        };
        engine.observe_metrics(&metrics, 1000, "custom");
        assert_eq!(engine.mode(), VefMode::Restricted);
    }

    #[test]
    fn custom_stabilization_window() {
        let config = VefDegradedModeConfig {
            stabilization_window_secs: 30,
            ..VefDegradedModeConfig::default()
        };
        let mut engine = VefDegradedModeEngine::new(config);

        let bad = ProofLagMetrics {
            proof_lag_secs: 301,
            backlog_depth: 0,
            error_rate: 0.0,
            heartbeat_age_secs: 0,
        };
        engine.observe_metrics(&bad, 1000, "corr");

        let good = ProofLagMetrics::healthy();
        engine.observe_metrics(&good, 1050, "corr");
        engine.observe_metrics(&good, 1079, "corr");
        assert_eq!(engine.mode(), VefMode::Restricted);
        engine.observe_metrics(&good, 1080, "corr");
        assert_eq!(engine.mode(), VefMode::Normal);
    }

    // ── Recovery receipt fields ──────────────────────────────────────────

    #[test]
    fn recovery_receipt_includes_pipeline_health() {
        let mut engine = default_engine();

        let bad = ProofLagMetrics {
            proof_lag_secs: 301,
            backlog_depth: 50,
            error_rate: 0.05,
            heartbeat_age_secs: 10,
        };
        engine.observe_metrics(&bad, 1000, "corr-health");

        // Perform some actions to increment counter
        engine.evaluate_action(ActionRisk::HighRisk, "policy.change");
        engine.evaluate_action(ActionRisk::LowRisk, "read.data");

        let good = ProofLagMetrics {
            proof_lag_secs: 10,
            backlog_depth: 2,
            error_rate: 0.01,
            heartbeat_age_secs: 1,
        };
        engine.observe_metrics(&good, 1050, "corr-health");
        engine.observe_metrics(&good, 1170, "corr-health");

        let receipt = engine
            .audit_log()
            .iter()
            .find_map(|e| {
                if let VefDegradedModeEvent::RecoveryComplete(r) = e {
                    Some(r)
                } else {
                    None
                }
            })
            .expect("recovery receipt");

        assert_eq!(receipt.pipeline_health_at_recovery.proof_lag_secs, 10);
        assert_eq!(receipt.pipeline_health_at_recovery.backlog_depth, 2);
        assert_eq!(receipt.actions_affected, 2);
        assert!(receipt.degraded_mode_duration_secs >= 170);
    }

    // ── Mode severity ordering ──────────────────────────────────────────

    #[test]
    fn mode_severity_ordering() {
        assert!(VefMode::Normal.severity() < VefMode::Restricted.severity());
        assert!(VefMode::Restricted.severity() < VefMode::Quarantine.severity());
        assert!(VefMode::Quarantine.severity() < VefMode::Halt.severity());
    }

    #[test]
    fn mode_labels() {
        assert_eq!(VefMode::Normal.label(), "normal");
        assert_eq!(VefMode::Restricted.label(), "restricted");
        assert_eq!(VefMode::Quarantine.label(), "quarantine");
        assert_eq!(VefMode::Halt.label(), "halt");
    }

    // ── No silent transitions ───────────────────────────────────────────

    #[test]
    fn no_silent_transitions() {
        let mut engine = default_engine();

        // Full lifecycle
        let bad = ProofLagMetrics {
            proof_lag_secs: 301,
            backlog_depth: 0,
            error_rate: 0.0,
            heartbeat_age_secs: 0,
        };
        engine.observe_metrics(&bad, 1000, "corr-silent");
        let good = ProofLagMetrics::healthy();
        engine.observe_metrics(&good, 1050, "corr-silent");
        engine.observe_metrics(&good, 1170, "corr-silent");

        // Every mode change should have a transition event
        let transitions: Vec<_> = engine
            .audit_log()
            .iter()
            .filter(|e| matches!(e, VefDegradedModeEvent::ModeTransition(_)))
            .collect();

        // Normal -> Restricted (1 transition) + Restricted -> Normal (1 transition)
        assert_eq!(transitions.len(), 2, "expected 2 transition events");
    }
}
