//! bd-3nr: Degraded-mode policy behavior with mandatory audit events.
//!
//! Deterministic state machine for trust-staleness degradation semantics:
//! - entry and exit are audited with stable event codes,
//! - action handling is risk-tiered in degraded/suspended states,
//! - mandatory audit ticks are enforced with missed-event alerts,
//! - recovery requires all criteria to hold for a stabilization window.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

pub const DEGRADED_MODE_ENTERED: &str = "DEGRADED_MODE_ENTERED";
pub const DEGRADED_MODE_EXITED: &str = "DEGRADED_MODE_EXITED";
pub const DEGRADED_MODE_SUSPENDED: &str = "DEGRADED_MODE_SUSPENDED";
pub const DEGRADED_ACTION_BLOCKED: &str = "DEGRADED_ACTION_BLOCKED";
pub const DEGRADED_ACTION_ANNOTATED: &str = "DEGRADED_ACTION_ANNOTATED";
pub const TRUST_INPUT_STALE: &str = "TRUST_INPUT_STALE";
pub const TRUST_INPUT_REFRESHED: &str = "TRUST_INPUT_REFRESHED";
pub const AUDIT_EVENT_MISSED: &str = "AUDIT_EVENT_MISSED";

const DEFAULT_MANDATORY_AUDIT_INTERVAL_SECS: u64 = 60;
const DEFAULT_STABILIZATION_WINDOW_SECS: u64 = 300;
const DEFAULT_MAX_DEGRADED_DURATION_SECS: u64 = 3_600;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DegradedModePolicy {
    pub mode_name: String,
    pub trigger_conditions: Vec<TriggerCondition>,
    pub permitted_actions: BTreeSet<String>,
    pub denied_actions: BTreeSet<String>,
    pub mandatory_audit_events: Vec<AuditEventSpec>,
    pub auto_recovery_criteria: Vec<RecoveryCriterion>,
    pub mandatory_audit_interval_secs: u64,
    pub stabilization_window_secs: u64,
    pub max_degraded_duration_secs: u64,
}

impl DegradedModePolicy {
    #[must_use]
    pub fn new(mode_name: impl Into<String>) -> Self {
        Self {
            mode_name: mode_name.into(),
            trigger_conditions: Vec::new(),
            permitted_actions: BTreeSet::new(),
            denied_actions: BTreeSet::new(),
            mandatory_audit_events: Vec::new(),
            auto_recovery_criteria: Vec::new(),
            mandatory_audit_interval_secs: DEFAULT_MANDATORY_AUDIT_INTERVAL_SECS,
            stabilization_window_secs: DEFAULT_STABILIZATION_WINDOW_SECS,
            max_degraded_duration_secs: DEFAULT_MAX_DEGRADED_DURATION_SECS,
        }
    }

    #[must_use]
    pub fn with_trigger(mut self, trigger: TriggerCondition) -> Self {
        self.trigger_conditions.push(trigger);
        self
    }

    #[must_use]
    pub fn with_denied_action(mut self, action: impl Into<String>) -> Self {
        self.denied_actions.insert(action.into());
        self
    }

    #[must_use]
    pub fn with_permitted_action(mut self, action: impl Into<String>) -> Self {
        self.permitted_actions.insert(action.into());
        self
    }

    #[must_use]
    pub fn with_mandatory_audit_event(mut self, spec: AuditEventSpec) -> Self {
        self.mandatory_audit_events.push(spec);
        self
    }

    #[must_use]
    pub fn with_recovery_criterion(mut self, criterion: RecoveryCriterion) -> Self {
        self.auto_recovery_criteria.push(criterion);
        self
    }

    #[must_use]
    pub fn with_stabilization_window(mut self, secs: u64) -> Self {
        self.stabilization_window_secs = secs.max(1);
        self
    }

    #[must_use]
    pub fn with_max_degraded_duration(mut self, secs: u64) -> Self {
        self.max_degraded_duration_secs = secs.max(1);
        self
    }

    #[must_use]
    pub fn with_mandatory_interval(mut self, secs: u64) -> Self {
        self.mandatory_audit_interval_secs = secs.max(1);
        self
    }

    #[must_use]
    pub fn sorted_denied_actions(&self) -> Vec<String> {
        let mut actions: Vec<String> = self.denied_actions.iter().cloned().collect();
        actions.sort_unstable();
        actions
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum TriggerCondition {
    HealthGateFailed(String),
    CapabilityUnavailable(String),
    ErrorRateExceeded { threshold: f64, window_secs: u64 },
    ManualActivation(String),
}

impl TriggerCondition {
    #[must_use]
    pub fn label(&self) -> String {
        match self {
            Self::HealthGateFailed(gate_name) => format!("health_gate_failed:{gate_name}"),
            Self::CapabilityUnavailable(capability_id) => {
                format!("capability_unavailable:{capability_id}")
            }
            Self::ErrorRateExceeded {
                threshold,
                window_secs,
            } => format!("error_rate_exceeded:{threshold:.4}:{window_secs}"),
            Self::ManualActivation(operator_id) => format!("manual_activation:{operator_id}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEventSpec {
    pub event_code: String,
    pub interval_secs: u64,
}

impl AuditEventSpec {
    #[must_use]
    pub fn new(event_code: impl Into<String>, interval_secs: u64) -> Self {
        Self {
            event_code: event_code.into(),
            interval_secs: interval_secs.max(1),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum RecoveryCriterion {
    HealthGateRestored(String),
    CapabilityAvailable(String),
    ErrorRateBelow { threshold: f64, window_secs: u64 },
    OperatorAcknowledged(String),
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct RecoveryStatus {
    pub healthy_gates: BTreeSet<String>,
    pub available_capabilities: BTreeSet<String>,
    pub observed_error_rate: Option<f64>,
    pub acknowledged_operators: BTreeSet<String>,
}

impl RecoveryStatus {
    #[must_use]
    pub fn with_healthy_gate(mut self, gate_name: impl Into<String>) -> Self {
        self.healthy_gates.insert(gate_name.into());
        self
    }

    #[must_use]
    pub fn with_available_capability(mut self, capability_id: impl Into<String>) -> Self {
        self.available_capabilities.insert(capability_id.into());
        self
    }

    #[must_use]
    pub fn with_error_rate(mut self, rate: f64) -> Self {
        self.observed_error_rate = Some(rate);
        self
    }

    #[must_use]
    pub fn with_acknowledged_operator(mut self, operator_id: impl Into<String>) -> Self {
        self.acknowledged_operators.insert(operator_id.into());
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DegradedModeState {
    Normal,
    Degraded,
    Suspended,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DegradedModeEnteredEvent {
    pub timestamp_secs: u64,
    pub mode_name: String,
    pub triggering_condition: String,
    pub active_policy_version: String,
    pub denied_actions: Vec<String>,
    pub trace_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DegradedModeActionAudit {
    pub timestamp_secs: u64,
    pub action_name: String,
    pub actor: String,
    pub permitted: bool,
    pub denial_reason: Option<String>,
    pub trace_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MandatoryAuditTickEvent {
    pub timestamp_secs: u64,
    pub event_code: String,
    pub trace_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEventMissedEvent {
    pub timestamp_secs: u64,
    pub event_code: String,
    pub expected_timestamp_secs: u64,
    pub trace_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DegradedModeExitedEvent {
    pub timestamp_secs: u64,
    pub mode_name: String,
    pub active_policy_version: String,
    pub trace_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DegradedModeSuspendedEvent {
    pub timestamp_secs: u64,
    pub mode_name: String,
    pub active_policy_version: String,
    pub reason: String,
    pub trace_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustInputStateEvent {
    pub timestamp_secs: u64,
    pub input_label: String,
    pub mode_name: String,
    pub trace_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event_type", rename_all = "snake_case")]
pub enum DegradedModeAuditEvent {
    DegradedModeEntered(DegradedModeEnteredEvent),
    DegradedModeExited(DegradedModeExitedEvent),
    DegradedModeSuspended(DegradedModeSuspendedEvent),
    DegradedModeActionAudit(DegradedModeActionAudit),
    MandatoryAuditTick(MandatoryAuditTickEvent),
    AuditEventMissed(AuditEventMissedEvent),
    TrustInputStale(TrustInputStateEvent),
    TrustInputRefreshed(TrustInputStateEvent),
}

impl DegradedModeAuditEvent {
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::DegradedModeEntered(_) => DEGRADED_MODE_ENTERED,
            Self::DegradedModeExited(_) => DEGRADED_MODE_EXITED,
            Self::DegradedModeSuspended(_) => DEGRADED_MODE_SUSPENDED,
            Self::DegradedModeActionAudit(action) => {
                if action.permitted {
                    DEGRADED_ACTION_ANNOTATED
                } else {
                    DEGRADED_ACTION_BLOCKED
                }
            }
            Self::MandatoryAuditTick(_) => "MANDATORY_AUDIT_TICK",
            Self::AuditEventMissed(_) => AUDIT_EVENT_MISSED,
            Self::TrustInputStale(_) => TRUST_INPUT_STALE,
            Self::TrustInputRefreshed(_) => TRUST_INPUT_REFRESHED,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionDecision {
    pub permitted: bool,
    pub degraded_annotation: bool,
    pub denial_reason: Option<String>,
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum DegradedModePolicyError {
    #[error("trigger condition is not configured for this policy: {0}")]
    TriggerNotConfigured(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DegradedContext {
    entered_at_secs: u64,
    trigger_label: String,
    active_policy_version: String,
    stabilization_started_at_secs: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct DegradedModePolicyEngine {
    policy: DegradedModePolicy,
    state: DegradedModeState,
    context: Option<DegradedContext>,
    audit_log: Vec<DegradedModeAuditEvent>,
    mandatory_event_last_emitted: BTreeMap<String, u64>,
}

impl DegradedModePolicyEngine {
    #[must_use]
    pub fn new(policy: DegradedModePolicy) -> Self {
        Self {
            policy,
            state: DegradedModeState::Normal,
            context: None,
            audit_log: Vec::new(),
            mandatory_event_last_emitted: BTreeMap::new(),
        }
    }

    #[must_use]
    pub fn state(&self) -> DegradedModeState {
        self.state.clone()
    }

    #[must_use]
    pub fn audit_log(&self) -> &[DegradedModeAuditEvent] {
        &self.audit_log
    }

    pub fn activate(
        &mut self,
        trigger: TriggerCondition,
        now_secs: u64,
        active_policy_version: impl Into<String>,
        trace_id: impl Into<String>,
    ) -> Result<(), DegradedModePolicyError> {
        let trigger_label = trigger.label();
        if !self.trigger_is_configured(&trigger) {
            return Err(DegradedModePolicyError::TriggerNotConfigured(trigger_label));
        }

        let active_policy_version = active_policy_version.into();
        let trace_id = trace_id.into();
        let mode_name = self.policy.mode_name.clone();
        let denied_actions = self.policy.sorted_denied_actions();

        self.audit_log.push(DegradedModeAuditEvent::TrustInputStale(
            TrustInputStateEvent {
                timestamp_secs: now_secs,
                input_label: trigger.label(),
                mode_name: mode_name.clone(),
                trace_id: trace_id.clone(),
            },
        ));
        self.audit_log
            .push(DegradedModeAuditEvent::DegradedModeEntered(
                DegradedModeEnteredEvent {
                    timestamp_secs: now_secs,
                    mode_name,
                    triggering_condition: trigger.label(),
                    active_policy_version: active_policy_version.clone(),
                    denied_actions,
                    trace_id: trace_id.clone(),
                },
            ));

        self.state = DegradedModeState::Degraded;
        self.context = Some(DegradedContext {
            entered_at_secs: now_secs,
            trigger_label,
            active_policy_version,
            stabilization_started_at_secs: None,
        });
        self.initialize_mandatory_event_cursors(now_secs);
        Ok(())
    }

    #[must_use]
    pub fn evaluate_action(
        &mut self,
        action_name: &str,
        actor: &str,
        now_secs: u64,
        trace_id: &str,
    ) -> ActionDecision {
        let (permitted, degraded_annotation, denial_reason) = match self.state {
            DegradedModeState::Normal => (true, false, None),
            DegradedModeState::Degraded => {
                if self.policy.denied_actions.contains(action_name) {
                    (false, true, Some(format!("denied_actions.{action_name}")))
                } else {
                    (true, true, None)
                }
            }
            DegradedModeState::Suspended => {
                if self.policy.permitted_actions.contains(action_name) {
                    (true, true, None)
                } else {
                    (
                        false,
                        true,
                        Some(format!("suspended_mode_blocks_non_essential:{action_name}")),
                    )
                }
            }
        };

        if !matches!(self.state, DegradedModeState::Normal) {
            self.audit_log
                .push(DegradedModeAuditEvent::DegradedModeActionAudit(
                    DegradedModeActionAudit {
                        timestamp_secs: now_secs,
                        action_name: action_name.to_string(),
                        actor: actor.to_string(),
                        permitted,
                        denial_reason: denial_reason.clone(),
                        trace_id: trace_id.to_string(),
                    },
                ));
        }

        ActionDecision {
            permitted,
            degraded_annotation,
            denial_reason,
        }
    }

    pub fn tick_mandatory_audits(&mut self, now_secs: u64, trace_id: &str) {
        if matches!(self.state, DegradedModeState::Normal) {
            return;
        }

        for spec in &self.policy.mandatory_audit_events {
            let interval = spec
                .interval_secs
                .max(self.policy.mandatory_audit_interval_secs);
            let last = *self
                .mandatory_event_last_emitted
                .get(&spec.event_code)
                .unwrap_or(&now_secs);
            let expected = last.saturating_add(interval);

            if now_secs >= expected.saturating_add(interval) {
                self.audit_log
                    .push(DegradedModeAuditEvent::AuditEventMissed(
                        AuditEventMissedEvent {
                            timestamp_secs: now_secs,
                            event_code: spec.event_code.clone(),
                            expected_timestamp_secs: expected,
                            trace_id: trace_id.to_string(),
                        },
                    ));
            }

            if now_secs >= expected {
                self.audit_log
                    .push(DegradedModeAuditEvent::MandatoryAuditTick(
                        MandatoryAuditTickEvent {
                            timestamp_secs: now_secs,
                            event_code: spec.event_code.clone(),
                            trace_id: trace_id.to_string(),
                        },
                    ));
                self.mandatory_event_last_emitted
                    .insert(spec.event_code.clone(), now_secs);
            }
        }
    }

    pub fn maybe_escalate_to_suspended(&mut self, now_secs: u64, trace_id: &str) {
        if !matches!(self.state, DegradedModeState::Degraded) {
            return;
        }

        let Some(context) = &self.context else {
            return;
        };
        let degraded_duration = now_secs.saturating_sub(context.entered_at_secs);
        if degraded_duration < self.policy.max_degraded_duration_secs {
            return;
        }

        self.state = DegradedModeState::Suspended;
        self.audit_log
            .push(DegradedModeAuditEvent::DegradedModeSuspended(
                DegradedModeSuspendedEvent {
                    timestamp_secs: now_secs,
                    mode_name: self.policy.mode_name.clone(),
                    active_policy_version: context.active_policy_version.clone(),
                    reason: format!(
                        "degraded_duration_exceeded:{}s",
                        self.policy.max_degraded_duration_secs
                    ),
                    trace_id: trace_id.to_string(),
                },
            ));
    }

    pub fn observe_recovery(&mut self, status: &RecoveryStatus, now_secs: u64, trace_id: &str) {
        if matches!(self.state, DegradedModeState::Normal) {
            return;
        }
        let all_met = self.all_recovery_criteria_satisfied(status);
        let Some(context) = self.context.as_mut() else {
            return;
        };

        if !all_met {
            context.stabilization_started_at_secs = None;
            return;
        }

        if context.stabilization_started_at_secs.is_none() {
            context.stabilization_started_at_secs = Some(now_secs);
            self.audit_log
                .push(DegradedModeAuditEvent::TrustInputRefreshed(
                    TrustInputStateEvent {
                        timestamp_secs: now_secs,
                        input_label: context.trigger_label.clone(),
                        mode_name: self.policy.mode_name.clone(),
                        trace_id: trace_id.to_string(),
                    },
                ));
            return;
        }

        let stabilization_started = context.stabilization_started_at_secs.unwrap_or(now_secs);
        let stable_for = now_secs.saturating_sub(stabilization_started);
        if stable_for < self.policy.stabilization_window_secs {
            return;
        }

        self.audit_log
            .push(DegradedModeAuditEvent::DegradedModeExited(
                DegradedModeExitedEvent {
                    timestamp_secs: now_secs,
                    mode_name: self.policy.mode_name.clone(),
                    active_policy_version: context.active_policy_version.clone(),
                    trace_id: trace_id.to_string(),
                },
            ));
        self.state = DegradedModeState::Normal;
        self.context = None;
        self.mandatory_event_last_emitted.clear();
    }

    fn trigger_is_configured(&self, trigger: &TriggerCondition) -> bool {
        self.policy
            .trigger_conditions
            .iter()
            .any(|configured| configured.label() == trigger.label())
    }

    fn initialize_mandatory_event_cursors(&mut self, now_secs: u64) {
        self.mandatory_event_last_emitted.clear();
        for spec in &self.policy.mandatory_audit_events {
            self.mandatory_event_last_emitted
                .insert(spec.event_code.clone(), now_secs);
        }
    }

    fn all_recovery_criteria_satisfied(&self, status: &RecoveryStatus) -> bool {
        if self.policy.auto_recovery_criteria.is_empty() {
            return false;
        }

        self.policy
            .auto_recovery_criteria
            .iter()
            .all(|criterion| criterion_satisfied(criterion, status))
    }
}

fn criterion_satisfied(criterion: &RecoveryCriterion, status: &RecoveryStatus) -> bool {
    match criterion {
        RecoveryCriterion::HealthGateRestored(gate_name) => {
            status.healthy_gates.contains(gate_name)
        }
        RecoveryCriterion::CapabilityAvailable(capability_id) => {
            status.available_capabilities.contains(capability_id)
        }
        RecoveryCriterion::ErrorRateBelow { threshold, .. } => status
            .observed_error_rate
            .is_some_and(|rate| rate <= *threshold),
        RecoveryCriterion::OperatorAcknowledged(operator_id) => {
            status.acknowledged_operators.contains(operator_id)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_policy() -> DegradedModePolicy {
        DegradedModePolicy::new("trust-input-stale")
            .with_trigger(TriggerCondition::HealthGateFailed(
                "revocation_frontier".to_string(),
            ))
            .with_trigger(TriggerCondition::CapabilityUnavailable(
                "federation_peer".to_string(),
            ))
            .with_trigger(TriggerCondition::ErrorRateExceeded {
                threshold: 0.15,
                window_secs: 60,
            })
            .with_trigger(TriggerCondition::ManualActivation("operator-1".to_string()))
            .with_denied_action("policy.change")
            .with_denied_action("key.rotate")
            .with_permitted_action("health.check")
            .with_mandatory_audit_event(AuditEventSpec::new("DEGRADED_HEARTBEAT", 60))
            .with_recovery_criterion(RecoveryCriterion::HealthGateRestored(
                "revocation_frontier".to_string(),
            ))
            .with_recovery_criterion(RecoveryCriterion::CapabilityAvailable(
                "federation_peer".to_string(),
            ))
            .with_recovery_criterion(RecoveryCriterion::ErrorRateBelow {
                threshold: 0.05,
                window_secs: 300,
            })
            .with_stabilization_window(300)
            .with_max_degraded_duration(120)
    }

    #[test]
    fn trigger_variant_health_gate_activation() {
        let mut engine = DegradedModePolicyEngine::new(base_policy());
        engine
            .activate(
                TriggerCondition::HealthGateFailed("revocation_frontier".to_string()),
                1_000,
                "1.0.0",
                "trace-1",
            )
            .expect("activate");
        assert_eq!(engine.state(), DegradedModeState::Degraded);
        assert!(
            matches!(
                engine.audit_log()[1],
                DegradedModeAuditEvent::DegradedModeEntered(_)
            ),
            "entry event must exist"
        );
    }

    #[test]
    fn trigger_variant_capability_unavailable_activation() {
        let mut engine = DegradedModePolicyEngine::new(base_policy());
        engine
            .activate(
                TriggerCondition::CapabilityUnavailable("federation_peer".to_string()),
                1_000,
                "1.0.0",
                "trace-2",
            )
            .expect("activate");
        assert_eq!(engine.state(), DegradedModeState::Degraded);
    }

    #[test]
    fn trigger_variant_error_rate_exceeded_activation() {
        let mut engine = DegradedModePolicyEngine::new(base_policy());
        engine
            .activate(
                TriggerCondition::ErrorRateExceeded {
                    threshold: 0.15,
                    window_secs: 60,
                },
                1_000,
                "1.0.0",
                "trace-3",
            )
            .expect("activate");
        assert_eq!(engine.state(), DegradedModeState::Degraded);
    }

    #[test]
    fn trigger_variant_manual_activation() {
        let mut engine = DegradedModePolicyEngine::new(base_policy());
        engine
            .activate(
                TriggerCondition::ManualActivation("operator-1".to_string()),
                1_000,
                "1.0.0",
                "trace-4",
            )
            .expect("activate");
        assert_eq!(engine.state(), DegradedModeState::Degraded);
    }

    #[test]
    fn denied_action_emits_blocked_audit() {
        let mut engine = DegradedModePolicyEngine::new(base_policy());
        engine
            .activate(
                TriggerCondition::HealthGateFailed("revocation_frontier".to_string()),
                1_000,
                "1.0.0",
                "trace-action",
            )
            .expect("activate");

        let decision = engine.evaluate_action("policy.change", "alice", 1_005, "trace-action");
        assert!(!decision.permitted);
        assert_eq!(
            decision.denial_reason,
            Some("denied_actions.policy.change".to_string())
        );
        let last = engine.audit_log().last().expect("audit");
        assert_eq!(last.code(), DEGRADED_ACTION_BLOCKED);
    }

    #[test]
    fn mandatory_tick_and_missed_alert_fire() {
        let mut engine = DegradedModePolicyEngine::new(base_policy());
        engine
            .activate(
                TriggerCondition::HealthGateFailed("revocation_frontier".to_string()),
                10_000,
                "1.0.0",
                "trace-tick",
            )
            .expect("activate");

        engine.tick_mandatory_audits(10_061, "trace-tick");
        assert!(
            engine
                .audit_log()
                .iter()
                .any(|event| matches!(event, DegradedModeAuditEvent::MandatoryAuditTick(_)))
        );

        engine.tick_mandatory_audits(10_190, "trace-tick");
        assert!(
            engine
                .audit_log()
                .iter()
                .any(|event| matches!(event, DegradedModeAuditEvent::AuditEventMissed(_))),
            "missing tick alert must be emitted when interval is skipped"
        );
    }

    #[test]
    fn stabilization_window_required_for_exit() {
        let mut engine = DegradedModePolicyEngine::new(base_policy());
        engine
            .activate(
                TriggerCondition::HealthGateFailed("revocation_frontier".to_string()),
                1_000,
                "1.0.0",
                "trace-rec",
            )
            .expect("activate");

        let status = RecoveryStatus::default()
            .with_healthy_gate("revocation_frontier")
            .with_available_capability("federation_peer")
            .with_error_rate(0.01);

        engine.observe_recovery(&status, 1_050, "trace-rec");
        assert_eq!(engine.state(), DegradedModeState::Degraded);
        engine.observe_recovery(&status, 1_349, "trace-rec");
        assert_eq!(engine.state(), DegradedModeState::Degraded);
        engine.observe_recovery(&status, 1_350, "trace-rec");
        assert_eq!(engine.state(), DegradedModeState::Normal);
        assert!(
            engine
                .audit_log()
                .iter()
                .any(|event| matches!(event, DegradedModeAuditEvent::DegradedModeExited(_)))
        );
    }

    #[test]
    fn degraded_duration_escalates_to_suspended() {
        let mut engine = DegradedModePolicyEngine::new(base_policy());
        engine
            .activate(
                TriggerCondition::HealthGateFailed("revocation_frontier".to_string()),
                2_000,
                "1.0.0",
                "trace-suspend",
            )
            .expect("activate");
        engine.maybe_escalate_to_suspended(2_120, "trace-suspend");
        assert_eq!(engine.state(), DegradedModeState::Suspended);
        assert!(
            engine
                .audit_log()
                .iter()
                .any(|event| matches!(event, DegradedModeAuditEvent::DegradedModeSuspended(_)))
        );
    }

    #[test]
    fn suspended_blocks_non_essential_actions() {
        let mut engine = DegradedModePolicyEngine::new(base_policy());
        engine
            .activate(
                TriggerCondition::HealthGateFailed("revocation_frontier".to_string()),
                2_000,
                "1.0.0",
                "trace-suspended-action",
            )
            .expect("activate");
        engine.maybe_escalate_to_suspended(2_120, "trace-suspended-action");
        let blocked = engine.evaluate_action("policy.change", "alice", 2_121, "trace");
        assert!(!blocked.permitted);
        let allowed = engine.evaluate_action("health.check", "alice", 2_122, "trace");
        assert!(allowed.permitted);
    }
}
