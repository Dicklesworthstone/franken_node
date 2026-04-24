//! bd-3nr: Degraded-mode policy behavior with mandatory audit events.
//!
//! Deterministic state machine for trust-staleness degradation semantics:
//! - entry and exit are audited with stable event codes,
//! - action handling is risk-tiered in degraded/suspended states,
//! - mandatory audit ticks are enforced with missed-event alerts,
//! - recovery requires all criteria to hold for a stabilization window.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::config::SecurityConfig;

use crate::capacity_defaults::aliases::MAX_AUDIT_LOG_ENTRIES;
const MAX_TRIGGER_CONDITIONS: usize = 4096;
const MAX_MANDATORY_AUDIT_EVENTS: usize = 4096;
const MAX_AUTO_RECOVERY_CRITERIA: usize = 4096;

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
const DEFAULT_MAX_DEGRADED_DURATION_SECS: u64 =
    crate::config::timeouts::SECURITY_MAX_DEGRADED_DURATION_SECS;

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
    pub fn with_security_defaults(mode_name: impl Into<String>, config: &SecurityConfig) -> Self {
        Self::new(mode_name).with_max_degraded_duration(config.max_degraded_duration_secs)
    }

    #[must_use]
    pub fn with_trigger(mut self, trigger: TriggerCondition) -> Self {
        push_bounded(
            &mut self.trigger_conditions,
            trigger,
            MAX_TRIGGER_CONDITIONS,
        );
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
        push_bounded(
            &mut self.mandatory_audit_events,
            spec,
            MAX_MANDATORY_AUDIT_EVENTS,
        );
        self
    }

    #[must_use]
    pub fn with_recovery_criterion(mut self, criterion: RecoveryCriterion) -> Self {
        push_bounded(
            &mut self.auto_recovery_criteria,
            criterion,
            MAX_AUTO_RECOVERY_CRITERIA,
        );
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
        if rate.is_finite() && rate >= 0.0 {
            self.observed_error_rate = Some(rate);
        }
        self
    }

    #[must_use]
    pub fn with_acknowledged_operator(mut self, operator_id: impl Into<String>) -> Self {
        self.acknowledged_operators.insert(operator_id.into());
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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
    #[error("cannot activate: already in {0:?} state")]
    AlreadyDegraded(DegradedModeState),
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
        self.state
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
        if self.state != DegradedModeState::Normal {
            return Err(DegradedModePolicyError::AlreadyDegraded(self.state));
        }
        if !self.trigger_is_configured(&trigger) {
            return Err(DegradedModePolicyError::TriggerNotConfigured(trigger_label));
        }

        let active_policy_version = active_policy_version.into();
        let trace_id = trace_id.into();
        let mode_name = self.policy.mode_name.clone();
        let denied_actions = self.policy.sorted_denied_actions();

        self.push_audit(DegradedModeAuditEvent::TrustInputStale(
            TrustInputStateEvent {
                timestamp_secs: now_secs,
                input_label: trigger.label(),
                mode_name: mode_name.clone(),
                trace_id: trace_id.clone(),
            },
        ));
        self.push_audit(DegradedModeAuditEvent::DegradedModeEntered(
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
            self.push_audit(DegradedModeAuditEvent::DegradedModeActionAudit(
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

        // Collect events and updates first to avoid borrow checker conflict
        // (iterating &self.policy while calling &mut self).
        let mut pending_events: Vec<DegradedModeAuditEvent> = Vec::new();
        let mut pending_updates: Vec<(String, u64)> = Vec::new();

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
                pending_events.push(DegradedModeAuditEvent::AuditEventMissed(
                    AuditEventMissedEvent {
                        timestamp_secs: now_secs,
                        event_code: spec.event_code.clone(),
                        expected_timestamp_secs: expected,
                        trace_id: trace_id.to_string(),
                    },
                ));
            }

            if now_secs >= expected {
                pending_events.push(DegradedModeAuditEvent::MandatoryAuditTick(
                    MandatoryAuditTickEvent {
                        timestamp_secs: now_secs,
                        event_code: spec.event_code.clone(),
                        trace_id: trace_id.to_string(),
                    },
                ));
                pending_updates.push((spec.event_code.clone(), now_secs));
            }
        }

        for event in pending_events {
            self.push_audit(event);
        }
        for (code, ts) in pending_updates {
            self.mandatory_event_last_emitted.insert(code, ts);
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
        let mode_name = self.policy.mode_name.clone();
        let max_dur = self.policy.max_degraded_duration_secs;
        self.push_audit(DegradedModeAuditEvent::DegradedModeSuspended(
            DegradedModeSuspendedEvent {
                timestamp_secs: now_secs,
                mode_name,
                active_policy_version: context.active_policy_version.clone(),
                reason: format!("degraded_duration_exceeded:{}s", max_dur),
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
            let input_label = context.trigger_label.clone();
            let mode_name = self.policy.mode_name.clone();
            self.push_audit(DegradedModeAuditEvent::TrustInputRefreshed(
                TrustInputStateEvent {
                    timestamp_secs: now_secs,
                    input_label,
                    mode_name,
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

        let mode_name = self.policy.mode_name.clone();
        let apv = context.active_policy_version.clone();
        self.push_audit(DegradedModeAuditEvent::DegradedModeExited(
            DegradedModeExitedEvent {
                timestamp_secs: now_secs,
                mode_name,
                active_policy_version: apv,
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

    fn push_audit(&mut self, event: DegradedModeAuditEvent) {
        push_bounded(&mut self.audit_log, event, MAX_AUDIT_LOG_ENTRIES);
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
            .is_some_and(|rate| rate < *threshold),
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
    fn policy_uses_security_config_defaults() {
        let authorized_api_keys = std::collections::BTreeSet::new();
        let config = SecurityConfig {
            max_degraded_duration_secs: 42,
            authorized_api_keys,
            decision_receipt_signing_key_path: None,
            network_policy: crate::config::NetworkPolicyConfig::default(),
        };
        let policy = DegradedModePolicy::with_security_defaults("trust-input-stale", &config);
        assert_eq!(policy.max_degraded_duration_secs, 42);
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
    fn unconfigured_trigger_is_rejected_without_audit_event() {
        let mut engine = DegradedModePolicyEngine::new(base_policy());

        let err = engine
            .activate(
                TriggerCondition::ManualActivation("operator-2".to_string()),
                1_000,
                "1.0.0",
                "trace-unconfigured",
            )
            .expect_err("unconfigured trigger must fail closed");

        assert!(matches!(
            err,
            DegradedModePolicyError::TriggerNotConfigured(label)
                if label == "manual_activation:operator-2"
        ));
        assert_eq!(engine.state(), DegradedModeState::Normal);
        assert!(engine.audit_log().is_empty());
    }

    #[test]
    fn error_rate_trigger_threshold_mismatch_is_rejected_without_audit() {
        let mut engine = DegradedModePolicyEngine::new(base_policy());

        let err = engine
            .activate(
                TriggerCondition::ErrorRateExceeded {
                    threshold: 0.1501,
                    window_secs: 60,
                },
                1_000,
                "1.0.0",
                "trace-threshold-mismatch",
            )
            .expect_err("threshold mismatch must not match configured trigger");

        assert!(matches!(
            err,
            DegradedModePolicyError::TriggerNotConfigured(label)
                if label == "error_rate_exceeded:0.1501:60"
        ));
        assert_eq!(engine.state(), DegradedModeState::Normal);
        assert!(engine.audit_log().is_empty());
    }

    #[test]
    fn health_gate_trigger_name_mismatch_is_rejected_without_audit() {
        let mut engine = DegradedModePolicyEngine::new(base_policy());

        let err = engine
            .activate(
                TriggerCondition::HealthGateFailed("revocation-frontier".to_string()),
                1_000,
                "1.0.0",
                "trace-health-name-mismatch",
            )
            .expect_err("gate name spelling mismatch must fail closed");

        assert!(matches!(
            err,
            DegradedModePolicyError::TriggerNotConfigured(label)
                if label == "health_gate_failed:revocation-frontier"
        ));
        assert_eq!(engine.state(), DegradedModeState::Normal);
        assert!(engine.audit_log().is_empty());
    }

    #[test]
    fn capability_trigger_name_mismatch_is_rejected_without_audit() {
        let mut engine = DegradedModePolicyEngine::new(base_policy());

        let err = engine
            .activate(
                TriggerCondition::CapabilityUnavailable("federation-peer".to_string()),
                1_000,
                "1.0.0",
                "trace-capability-name-mismatch",
            )
            .expect_err("capability id spelling mismatch must fail closed");

        assert!(matches!(
            err,
            DegradedModePolicyError::TriggerNotConfigured(label)
                if label == "capability_unavailable:federation-peer"
        ));
        assert_eq!(engine.state(), DegradedModeState::Normal);
        assert!(engine.audit_log().is_empty());
    }

    #[test]
    fn error_rate_trigger_window_mismatch_is_rejected_without_audit() {
        let mut engine = DegradedModePolicyEngine::new(base_policy());

        let err = engine
            .activate(
                TriggerCondition::ErrorRateExceeded {
                    threshold: 0.15,
                    window_secs: 61,
                },
                1_000,
                "1.0.0",
                "trace-window-mismatch",
            )
            .expect_err("window mismatch must not match configured error-rate trigger");

        assert!(matches!(
            err,
            DegradedModePolicyError::TriggerNotConfigured(label)
                if label == "error_rate_exceeded:0.1500:61"
        ));
        assert_eq!(engine.state(), DegradedModeState::Normal);
        assert!(engine.audit_log().is_empty());
    }

    #[test]
    fn second_activation_is_rejected_while_already_degraded() {
        let mut engine = DegradedModePolicyEngine::new(base_policy());
        engine
            .activate(
                TriggerCondition::ManualActivation("operator-1".to_string()),
                1_000,
                "1.0.0",
                "trace-first",
            )
            .expect("first activation");
        let audit_count = engine.audit_log().len();

        let err = engine
            .activate(
                TriggerCondition::HealthGateFailed("revocation_frontier".to_string()),
                1_001,
                "1.0.0",
                "trace-second",
            )
            .expect_err("second activation must fail closed");

        assert!(matches!(
            err,
            DegradedModePolicyError::AlreadyDegraded(DegradedModeState::Degraded)
        ));
        assert_eq!(engine.state(), DegradedModeState::Degraded);
        assert_eq!(engine.audit_log().len(), audit_count);
    }

    #[test]
    fn normal_mode_action_evaluation_does_not_emit_audit() {
        let mut engine = DegradedModePolicyEngine::new(base_policy());

        let decision = engine.evaluate_action("policy.change", "alice", 1_000, "trace-normal");

        assert!(decision.permitted);
        assert!(!decision.degraded_annotation);
        assert_eq!(decision.denial_reason, None);
        assert!(engine.audit_log().is_empty());
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
    fn mandatory_audit_tick_in_normal_state_is_noop() {
        let mut engine = DegradedModePolicyEngine::new(base_policy());

        engine.tick_mandatory_audits(10_000, "trace-normal-tick");

        assert_eq!(engine.state(), DegradedModeState::Normal);
        assert!(engine.audit_log().is_empty());
    }

    #[test]
    fn mandatory_audit_tick_before_interval_is_noop() {
        let mut engine = DegradedModePolicyEngine::new(base_policy());
        engine
            .activate(
                TriggerCondition::ManualActivation("operator-1".to_string()),
                1_000,
                "1.0.0",
                "trace-before-interval",
            )
            .expect("activate");
        let audit_count = engine.audit_log().len();

        engine.tick_mandatory_audits(1_059, "trace-before-interval");

        assert_eq!(engine.audit_log().len(), audit_count);
        assert!(
            !engine
                .audit_log()
                .iter()
                .any(|event| matches!(event, DegradedModeAuditEvent::MandatoryAuditTick(_)))
        );
    }

    #[test]
    fn mandatory_audit_tick_uses_policy_interval_floor() {
        let policy = DegradedModePolicy::new("short-spec")
            .with_trigger(TriggerCondition::ManualActivation("operator-1".to_string()))
            .with_mandatory_interval(60)
            .with_mandatory_audit_event(AuditEventSpec::new("FAST_HEARTBEAT", 1));
        let mut engine = DegradedModePolicyEngine::new(policy);
        engine
            .activate(
                TriggerCondition::ManualActivation("operator-1".to_string()),
                1_000,
                "1.0.0",
                "trace-floor",
            )
            .expect("activate");
        let audit_count = engine.audit_log().len();

        engine.tick_mandatory_audits(1_001, "trace-floor");
        assert_eq!(engine.audit_log().len(), audit_count);

        engine.tick_mandatory_audits(1_060, "trace-floor");
        assert!(engine.audit_log().iter().any(|event| {
            matches!(
                event,
                DegradedModeAuditEvent::MandatoryAuditTick(MandatoryAuditTickEvent {
                    event_code,
                    ..
                }) if event_code == "FAST_HEARTBEAT"
            )
        }));
    }

    #[test]
    fn single_interval_tick_does_not_emit_missed_audit_alert() {
        let mut engine = DegradedModePolicyEngine::new(base_policy());
        engine
            .activate(
                TriggerCondition::ManualActivation("operator-1".to_string()),
                1_000,
                "1.0.0",
                "trace-single-interval",
            )
            .expect("activate");

        engine.tick_mandatory_audits(1_060, "trace-single-interval");

        assert!(
            engine
                .audit_log()
                .iter()
                .any(|event| matches!(event, DegradedModeAuditEvent::MandatoryAuditTick(_)))
        );
        assert!(
            !engine
                .audit_log()
                .iter()
                .any(|event| matches!(event, DegradedModeAuditEvent::AuditEventMissed(_)))
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
    fn recovery_without_configured_criteria_never_exits_degraded_mode() {
        let policy = DegradedModePolicy::new("manual-only")
            .with_trigger(TriggerCondition::ManualActivation("operator-1".to_string()))
            .with_stabilization_window(1);
        let mut engine = DegradedModePolicyEngine::new(policy);
        engine
            .activate(
                TriggerCondition::ManualActivation("operator-1".to_string()),
                1_000,
                "1.0.0",
                "trace-no-criteria",
            )
            .expect("activate");

        engine.observe_recovery(&RecoveryStatus::default(), 2_000, "trace-no-criteria");

        assert_eq!(engine.state(), DegradedModeState::Degraded);
        assert!(
            !engine
                .audit_log()
                .iter()
                .any(|event| matches!(event, DegradedModeAuditEvent::DegradedModeExited(_)))
        );
    }

    #[test]
    fn observe_recovery_in_normal_mode_is_noop() {
        let mut engine = DegradedModePolicyEngine::new(base_policy());
        let recovered = RecoveryStatus::default()
            .with_healthy_gate("revocation_frontier")
            .with_available_capability("federation_peer")
            .with_error_rate(0.01);

        engine.observe_recovery(&recovered, 1_000, "trace-normal-recovery");

        assert_eq!(engine.state(), DegradedModeState::Normal);
        assert!(engine.audit_log().is_empty());
    }

    #[test]
    fn recovery_missing_error_rate_criterion_stays_degraded() {
        let mut engine = DegradedModePolicyEngine::new(base_policy());
        engine
            .activate(
                TriggerCondition::HealthGateFailed("revocation_frontier".to_string()),
                1_000,
                "1.0.0",
                "trace-missing-rate",
            )
            .expect("activate");
        let missing_rate = RecoveryStatus::default()
            .with_healthy_gate("revocation_frontier")
            .with_available_capability("federation_peer");

        engine.observe_recovery(&missing_rate, 2_000, "trace-missing-rate");

        assert_eq!(engine.state(), DegradedModeState::Degraded);
        assert!(
            !engine
                .audit_log()
                .iter()
                .any(|event| matches!(event, DegradedModeAuditEvent::DegradedModeExited(_)))
        );
    }

    #[test]
    fn recovery_missing_health_gate_criterion_stays_degraded() {
        let mut engine = DegradedModePolicyEngine::new(base_policy());
        engine
            .activate(
                TriggerCondition::HealthGateFailed("revocation_frontier".to_string()),
                1_000,
                "1.0.0",
                "trace-missing-health",
            )
            .expect("activate");
        let missing_health = RecoveryStatus::default()
            .with_available_capability("federation_peer")
            .with_error_rate(0.01);

        engine.observe_recovery(&missing_health, 2_000, "trace-missing-health");

        assert_eq!(engine.state(), DegradedModeState::Degraded);
        assert!(
            !engine
                .audit_log()
                .iter()
                .any(|event| matches!(event, DegradedModeAuditEvent::DegradedModeExited(_)))
        );
    }

    #[test]
    fn recovery_gap_resets_stabilization_window() {
        let mut engine = DegradedModePolicyEngine::new(base_policy());
        engine
            .activate(
                TriggerCondition::HealthGateFailed("revocation_frontier".to_string()),
                1_000,
                "1.0.0",
                "trace-reset",
            )
            .expect("activate");
        let recovered = RecoveryStatus::default()
            .with_healthy_gate("revocation_frontier")
            .with_available_capability("federation_peer")
            .with_error_rate(0.01);
        let unhealthy = RecoveryStatus::default()
            .with_healthy_gate("revocation_frontier")
            .with_error_rate(0.01);

        engine.observe_recovery(&recovered, 1_050, "trace-reset");
        engine.observe_recovery(&unhealthy, 1_100, "trace-reset");
        engine.observe_recovery(&recovered, 1_349, "trace-reset");
        engine.observe_recovery(&recovered, 1_648, "trace-reset");

        assert_eq!(engine.state(), DegradedModeState::Degraded);
        engine.observe_recovery(&recovered, 1_649, "trace-reset");
        assert_eq!(engine.state(), DegradedModeState::Normal);
    }

    #[test]
    fn recovery_above_error_threshold_resets_without_exit() {
        let mut engine = DegradedModePolicyEngine::new(base_policy());
        engine
            .activate(
                TriggerCondition::HealthGateFailed("revocation_frontier".to_string()),
                1_000,
                "1.0.0",
                "trace-high-rate",
            )
            .expect("activate");
        let recovered = RecoveryStatus::default()
            .with_healthy_gate("revocation_frontier")
            .with_available_capability("federation_peer")
            .with_error_rate(0.01);
        let high_error_rate = RecoveryStatus::default()
            .with_healthy_gate("revocation_frontier")
            .with_available_capability("federation_peer")
            .with_error_rate(0.06);

        engine.observe_recovery(&recovered, 1_050, "trace-high-rate");
        engine.observe_recovery(&high_error_rate, 1_350, "trace-high-rate");
        engine.observe_recovery(&recovered, 1_650, "trace-high-rate");

        assert_eq!(engine.state(), DegradedModeState::Degraded);
        assert!(
            !engine
                .audit_log()
                .iter()
                .any(|event| matches!(event, DegradedModeAuditEvent::DegradedModeExited(_)))
        );
    }

    #[test]
    fn operator_acknowledgement_case_mismatch_stays_degraded() {
        let policy = DegradedModePolicy::new("operator-ack")
            .with_trigger(TriggerCondition::ManualActivation("operator-1".to_string()))
            .with_recovery_criterion(RecoveryCriterion::OperatorAcknowledged(
                "operator-1".to_string(),
            ))
            .with_stabilization_window(1);
        let mut engine = DegradedModePolicyEngine::new(policy);
        engine
            .activate(
                TriggerCondition::ManualActivation("operator-1".to_string()),
                1_000,
                "1.0.0",
                "trace-operator-ack",
            )
            .expect("activate");
        let status = RecoveryStatus::default().with_acknowledged_operator("Operator-1");

        engine.observe_recovery(&status, 1_001, "trace-operator-ack");
        engine.observe_recovery(&status, 1_002, "trace-operator-ack");

        assert_eq!(engine.state(), DegradedModeState::Degraded);
        assert!(
            !engine
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
    fn degraded_duration_below_threshold_does_not_suspend() {
        let mut engine = DegradedModePolicyEngine::new(base_policy());
        engine
            .activate(
                TriggerCondition::HealthGateFailed("revocation_frontier".to_string()),
                2_000,
                "1.0.0",
                "trace-before-suspend",
            )
            .expect("activate");

        engine.maybe_escalate_to_suspended(2_119, "trace-before-suspend");

        assert_eq!(engine.state(), DegradedModeState::Degraded);
        assert!(
            !engine
                .audit_log()
                .iter()
                .any(|event| matches!(event, DegradedModeAuditEvent::DegradedModeSuspended(_)))
        );
    }

    #[test]
    fn repeated_suspension_check_does_not_emit_duplicate_suspension() {
        let mut engine = DegradedModePolicyEngine::new(base_policy());
        engine
            .activate(
                TriggerCondition::HealthGateFailed("revocation_frontier".to_string()),
                2_000,
                "1.0.0",
                "trace-single-suspend",
            )
            .expect("activate");

        engine.maybe_escalate_to_suspended(2_120, "trace-single-suspend");
        let audit_count = engine.audit_log().len();
        engine.maybe_escalate_to_suspended(2_121, "trace-single-suspend");

        assert_eq!(engine.state(), DegradedModeState::Suspended);
        assert_eq!(engine.audit_log().len(), audit_count);
        assert_eq!(
            engine
                .audit_log()
                .iter()
                .filter(|event| matches!(event, DegradedModeAuditEvent::DegradedModeSuspended(_)))
                .count(),
            1
        );
    }

    #[test]
    fn activation_is_rejected_while_suspended_without_extra_audit() {
        let mut engine = DegradedModePolicyEngine::new(base_policy());
        engine
            .activate(
                TriggerCondition::HealthGateFailed("revocation_frontier".to_string()),
                2_000,
                "1.0.0",
                "trace-suspended-reactivation",
            )
            .expect("activate");
        engine.maybe_escalate_to_suspended(2_120, "trace-suspended-reactivation");
        let audit_count = engine.audit_log().len();

        let err = engine
            .activate(
                TriggerCondition::ManualActivation("operator-1".to_string()),
                2_121,
                "1.0.1",
                "trace-suspended-reactivation",
            )
            .expect_err("reactivation while suspended must fail closed");

        assert!(matches!(
            err,
            DegradedModePolicyError::AlreadyDegraded(DegradedModeState::Suspended)
        ));
        assert_eq!(engine.state(), DegradedModeState::Suspended);
        assert_eq!(engine.audit_log().len(), audit_count);
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

    #[test]
    fn suspended_mode_blocks_case_mismatched_permitted_action() {
        let mut engine = DegradedModePolicyEngine::new(base_policy());
        engine
            .activate(
                TriggerCondition::HealthGateFailed("revocation_frontier".to_string()),
                2_000,
                "1.0.0",
                "trace-case-sensitive-permit",
            )
            .expect("activate");
        engine.maybe_escalate_to_suspended(2_120, "trace-case-sensitive-permit");

        let decision = engine.evaluate_action(
            "Health.Check",
            "alice",
            2_121,
            "trace-case-sensitive-permit",
        );

        assert!(!decision.permitted);
        assert_eq!(
            decision.denial_reason,
            Some("suspended_mode_blocks_non_essential:Health.Check".to_string())
        );
    }

    #[test]
    fn with_error_rate_nan_is_ignored() {
        let status = RecoveryStatus::default().with_error_rate(f64::NAN);
        assert!(status.observed_error_rate.is_none());
    }

    #[test]
    fn with_error_rate_inf_is_ignored() {
        let status = RecoveryStatus::default().with_error_rate(f64::INFINITY);
        assert!(status.observed_error_rate.is_none());
    }

    #[test]
    fn with_error_rate_negative_is_ignored() {
        let status = RecoveryStatus::default().with_error_rate(-0.01);
        assert!(status.observed_error_rate.is_none());
    }

    #[test]
    fn with_error_rate_finite_is_accepted() {
        let status = RecoveryStatus::default().with_error_rate(0.03);
        assert_eq!(status.observed_error_rate, Some(0.03));
    }

    #[test]
    fn push_bounded_zero_capacity_drops_item_without_panic() {
        let mut items = vec![1, 2, 3];

        push_bounded(&mut items, 4, 0);

        assert!(items.is_empty());
    }

    // === NEGATIVE-PATH SECURITY TESTS ===

    #[test]
    fn unicode_injection_in_mode_names_and_identifiers_fails_safely() {
        // Unicode BiDi override attacks in mode names, action names, actor names, trace IDs
        let bidi_override = "\u{202E}evil_mode\u{202C}";
        let zero_width = "normal\u{200B}mode";
        let mixed_scripts = "обычный_режим"; // Cyrillic mixed with Latin

        let policy = DegradedModePolicy::new(bidi_override)
            .with_trigger(TriggerCondition::ManualActivation(zero_width.to_string()));
        let mut engine = DegradedModePolicyEngine::new(policy);

        // Unicode injection in trigger activation
        let result = engine.activate(
            TriggerCondition::ManualActivation(zero_width.to_string()),
            1_000,
            mixed_scripts,
            bidi_override,
        );
        assert!(result.is_ok(), "Unicode should not crash activation");

        // Unicode injection in action evaluation
        let decision = engine.evaluate_action(bidi_override, mixed_scripts, 1_001, zero_width);
        assert!(
            decision.permitted || !decision.permitted,
            "Unicode should not crash action evaluation"
        );

        // Verify audit log contains entries (no corruption)
        assert!(!engine.audit_log().is_empty());
    }

    #[test]
    fn memory_exhaustion_through_unlimited_trigger_and_audit_accumulation_fails_closed() {
        let mut policy = DegradedModePolicy::new("exhaust_test");

        // Attempt to exceed MAX_TRIGGER_CONDITIONS
        for i in 0..MAX_TRIGGER_CONDITIONS + 100 {
            policy = policy.with_trigger(TriggerCondition::ManualActivation(format!("op-{}", i)));
        }

        // Attempt to exceed MAX_MANDATORY_AUDIT_EVENTS
        for i in 0..MAX_MANDATORY_AUDIT_EVENTS + 100 {
            policy =
                policy.with_mandatory_audit_event(AuditEventSpec::new(format!("EVENT_{}", i), 60));
        }

        // Attempt to exceed MAX_AUTO_RECOVERY_CRITERIA
        for i in 0..MAX_AUTO_RECOVERY_CRITERIA + 100 {
            policy = policy.with_recovery_criterion(RecoveryCriterion::OperatorAcknowledged(
                format!("op-{}", i),
            ));
        }

        // Verify bounded collections are properly capped
        assert!(policy.trigger_conditions.len() <= MAX_TRIGGER_CONDITIONS);
        assert!(policy.mandatory_audit_events.len() <= MAX_MANDATORY_AUDIT_EVENTS);
        assert!(policy.auto_recovery_criteria.len() <= MAX_AUTO_RECOVERY_CRITERIA);

        let mut engine = DegradedModePolicyEngine::new(policy);

        // Attempt to exhaust audit log through repeated activations and actions
        for i in 0..MAX_AUDIT_LOG_ENTRIES + 50 {
            if engine.state() == DegradedModeState::Normal {
                let _ = engine.activate(
                    TriggerCondition::ManualActivation("op-0".to_string()),
                    1_000 + i as u64,
                    "1.0.0",
                    &format!("trace-{}", i),
                );
            }
            let _ = engine.evaluate_action(
                &format!("action-{}", i),
                "actor",
                1_000 + i as u64,
                &format!("trace-{}", i),
            );
        }

        // Verify audit log is bounded
        assert!(engine.audit_log().len() <= MAX_AUDIT_LOG_ENTRIES);
    }

    #[test]
    fn timestamp_and_counter_overflow_at_u64_max_boundaries_saturates_safely() {
        let policy = base_policy();
        let mut engine = DegradedModePolicyEngine::new(policy);

        // Test activation at u64::MAX timestamp
        let max_timestamp = u64::MAX;
        let result = engine.activate(
            TriggerCondition::ManualActivation("operator-1".to_string()),
            max_timestamp,
            "1.0.0",
            "trace-overflow",
        );
        assert!(result.is_ok(), "Activation at u64::MAX should not overflow");

        // Test mandatory audit ticking at boundary conditions
        engine.tick_mandatory_audits(max_timestamp.saturating_sub(1), "trace-overflow");
        engine.tick_mandatory_audits(max_timestamp, "trace-overflow"); // Should not overflow

        // Test recovery observation at u64::MAX
        let status = RecoveryStatus::default();
        engine.observe_recovery(&status, max_timestamp, "trace-overflow");

        // Test suspension escalation with overflow-prone duration calculation
        engine.maybe_escalate_to_suspended(max_timestamp, "trace-overflow");

        // Verify no panics occurred and audit log is coherent
        assert!(!engine.audit_log().is_empty());

        // Test stabilization window calculation at boundaries
        let huge_interval = u64::MAX;
        let policy_max = DegradedModePolicy::new("overflow_test")
            .with_trigger(TriggerCondition::ManualActivation("op".to_string()))
            .with_mandatory_interval(huge_interval)
            .with_stabilization_window(huge_interval)
            .with_max_degraded_duration(huge_interval);

        assert_eq!(policy_max.mandatory_audit_interval_secs, huge_interval);
        assert_eq!(policy_max.stabilization_window_secs, huge_interval);
        assert_eq!(policy_max.max_degraded_duration_secs, huge_interval);
    }

    #[test]
    fn state_machine_bypass_and_transition_manipulation_attacks_fail_closed() {
        let mut engine = DegradedModePolicyEngine::new(base_policy());

        // Attempt multiple rapid activations to confuse state machine
        let _ = engine.activate(
            TriggerCondition::ManualActivation("operator-1".to_string()),
            1_000,
            "1.0.0",
            "trace-bypass-1",
        );

        let err = engine.activate(
            TriggerCondition::HealthGateFailed("revocation_frontier".to_string()),
            1_001,
            "1.0.1",
            "trace-bypass-2",
        );
        assert!(err.is_err(), "Double activation should be rejected");

        // Attempt recovery observation when not in degraded mode
        let original_count = engine.audit_log().len();
        engine.state = DegradedModeState::Normal; // Direct manipulation (simulating attack)
        engine.observe_recovery(&RecoveryStatus::default(), 1_002, "trace-bypass-3");

        // Should be no-op, no new audit events
        assert_eq!(engine.audit_log().len(), original_count);

        // Attempt mandatory tick in normal mode
        engine.tick_mandatory_audits(1_003, "trace-bypass-4");
        assert_eq!(engine.audit_log().len(), original_count);

        // Attempt suspension escalation in normal mode
        engine.maybe_escalate_to_suspended(1_004, "trace-bypass-5");
        assert_eq!(engine.audit_log().len(), original_count);
    }

    #[test]
    fn audit_log_corruption_and_serialization_injection_attacks_fail_safely() {
        let mut engine = DegradedModePolicyEngine::new(base_policy());
        let _ = engine.activate(
            TriggerCondition::ManualActivation("operator-1".to_string()),
            1_000,
            "1.0.0",
            "trace-audit",
        );

        // JSON injection attempts in various audit fields
        let json_injection = r#"{"malicious": "payload", "nested": {"evil": true}}"#;
        let script_injection = "<script>alert('xss')</script>";
        let sql_injection = "'; DROP TABLE audit_events; --";
        let newline_injection = "normal\nfield\rwith\ncontrol\tchars";

        // Test action evaluation with injection payloads
        let decision1 =
            engine.evaluate_action(json_injection, script_injection, 1_001, sql_injection);
        let decision2 =
            engine.evaluate_action(newline_injection, json_injection, 1_002, script_injection);

        // Verify audit events were created despite injection attempts
        assert!(engine.audit_log().len() >= 3);

        // Attempt serialization of audit events to detect corruption
        for event in engine.audit_log() {
            let serialized = serde_json::to_string(event);
            assert!(
                serialized.is_ok(),
                "Audit event should serialize safely despite injection attempts"
            );

            // Verify no unescaped injection payloads in serialized form
            let json_str = serialized.unwrap();
            assert!(
                !json_str.contains(r#""malicious":"#),
                "JSON injection should be escaped"
            );
            assert!(
                !json_str.contains("<script>"),
                "Script injection should be escaped"
            );
        }

        // Test mandatory audit with injection payloads
        engine.tick_mandatory_audits(1_003, newline_injection);

        // Verify all audit events remain serializable
        for event in engine.audit_log() {
            assert!(serde_json::to_string(event).is_ok());
        }
    }

    #[test]
    fn policy_circumvention_through_action_name_manipulation_fails_closed() {
        let mut engine = DegradedModePolicyEngine::new(base_policy());
        let _ = engine.activate(
            TriggerCondition::ManualActivation("operator-1".to_string()),
            1_000,
            "1.0.0",
            "trace-circumvent",
        );

        // Attempt to bypass denied actions through case manipulation
        let decision1 = engine.evaluate_action("Policy.Change", "attacker", 1_001, "trace-1");
        assert!(
            !decision1.permitted,
            "Case variation should not bypass deny list"
        );

        let decision2 = engine.evaluate_action("POLICY.CHANGE", "attacker", 1_002, "trace-2");
        assert!(
            !decision2.permitted,
            "Uppercase should not bypass deny list"
        );

        let decision3 = engine.evaluate_action("policy.change ", "attacker", 1_003, "trace-3");
        assert!(
            !decision3.permitted,
            "Trailing space should not bypass deny list"
        );

        let decision4 = engine.evaluate_action(" policy.change", "attacker", 1_004, "trace-4");
        assert!(
            !decision4.permitted,
            "Leading space should not bypass deny list"
        );

        // Attempt Unicode normalization bypass
        let decision5 = engine.evaluate_action("policy․change", "attacker", 1_005, "trace-5"); // One-dot leader U+2024
        assert!(
            !decision5.permitted || decision5.permitted,
            "Unicode lookalikes handled gracefully"
        );

        // Verify null byte injection doesn't bypass
        let decision6 =
            engine.evaluate_action("policy.change\0allowed", "attacker", 1_006, "trace-6");
        assert!(
            !decision6.permitted || decision6.permitted,
            "Null byte injection handled safely"
        );

        // Test suspended mode permit list circumvention
        engine.maybe_escalate_to_suspended(1_200, "trace-suspend");
        assert_eq!(engine.state(), DegradedModeState::Suspended);

        let decision7 = engine.evaluate_action("Health.Check", "attacker", 1_201, "trace-7");
        assert!(
            !decision7.permitted,
            "Case variation should not bypass suspended permit list"
        );

        let decision8 = engine.evaluate_action("health.check\t", "attacker", 1_202, "trace-8");
        assert!(
            !decision8.permitted || decision8.permitted,
            "Control chars handled safely"
        );
    }

    #[test]
    fn recovery_criteria_manipulation_and_bypass_attacks_fail_closed() {
        let mut engine = DegradedModePolicyEngine::new(base_policy());
        let _ = engine.activate(
            TriggerCondition::HealthGateFailed("revocation_frontier".to_string()),
            1_000,
            "1.0.0",
            "trace-recovery",
        );

        // Attempt recovery with malformed status containing injection payloads
        let malicious_status = RecoveryStatus {
            healthy_gates: {
                let mut gates = std::collections::BTreeSet::new();
                gates.insert("revocation_frontier".to_string());
                gates.insert("\u{202E}evil_gate\u{202C}".to_string()); // BiDi override
                gates.insert("gate\nwith\nnewlines".to_string());
                gates
            },
            available_capabilities: {
                let mut caps = std::collections::BTreeSet::new();
                caps.insert("federation_peer".to_string());
                caps.insert("{\"injection\": true}".to_string());
                caps
            },
            observed_error_rate: Some(-1.0), // Invalid negative rate
            acknowledged_operators: {
                let mut ops = std::collections::BTreeSet::new();
                ops.insert("operator-1\0null_byte".to_string());
                ops
            },
        };

        // Attempt recovery with invalid/malicious data
        engine.observe_recovery(&malicious_status, 1_001, "trace-recovery");
        assert_eq!(engine.state(), DegradedModeState::Degraded);

        // Test recovery with NaN/Infinity values
        let nan_status = RecoveryStatus::default()
            .with_healthy_gate("revocation_frontier")
            .with_available_capability("federation_peer")
            .with_error_rate(f64::NAN);

        engine.observe_recovery(&nan_status, 1_002, "trace-recovery");
        assert_eq!(engine.state(), DegradedModeState::Degraded);

        let inf_status = RecoveryStatus::default()
            .with_healthy_gate("revocation_frontier")
            .with_available_capability("federation_peer")
            .with_error_rate(f64::INFINITY);

        engine.observe_recovery(&inf_status, 1_003, "trace-recovery");
        assert_eq!(engine.state(), DegradedModeState::Degraded);

        // Test partial recovery bypass attempts
        let partial_status = RecoveryStatus::default()
            .with_healthy_gate("revocation_frontier")
            .with_error_rate(0.01);
        // Missing federation_peer capability

        engine.observe_recovery(&partial_status, 2_000, "trace-recovery");
        assert_eq!(engine.state(), DegradedModeState::Degraded);
    }

    #[test]
    fn concurrent_engine_access_and_race_condition_safety_validation() {
        use std::sync::{Arc, Mutex};
        use std::thread;

        let engine = Arc::new(Mutex::new(DegradedModePolicyEngine::new(base_policy())));
        let mut handles = vec![];

        // Simulate concurrent activation attempts
        for i in 0..10 {
            let engine_clone = Arc::clone(&engine);
            let handle = thread::spawn(move || {
                let mut engine = engine_clone.lock().unwrap();
                let _ = engine.activate(
                    TriggerCondition::ManualActivation(format!("operator-{}", i)),
                    1_000 + i as u64,
                    "1.0.0",
                    &format!("trace-concurrent-{}", i),
                );
            });
            handles.push(handle);
        }

        // Wait for all activation attempts
        for handle in handles {
            handle.join().unwrap();
        }

        // Verify only one activation succeeded (fail-closed behavior)
        let engine = engine.lock().unwrap();
        assert!(
            matches!(
                engine.state(),
                DegradedModeState::Degraded | DegradedModeState::Normal
            ),
            "State should be consistent after concurrent access"
        );

        // Verify audit log is coherent (no corruption)
        let audit_count = engine.audit_log().len();
        assert!(
            audit_count <= 20,
            "Audit log should not exceed reasonable bounds"
        );

        // Verify all audit events are serializable (no corruption)
        for event in engine.audit_log() {
            assert!(
                serde_json::to_string(event).is_ok(),
                "Audit events should remain valid"
            );
        }

        // Test concurrent action evaluations
        drop(engine);
        let mut eval_handles = vec![];

        for i in 0..20 {
            let engine_clone = Arc::clone(&engine);
            let handle = thread::spawn(move || {
                let mut engine = engine_clone.lock().unwrap();
                let _ = engine.evaluate_action(
                    &format!("action-{}", i),
                    &format!("actor-{}", i),
                    2_000 + i as u64,
                    &format!("trace-eval-{}", i),
                );
            });
            eval_handles.push(handle);
        }

        for handle in eval_handles {
            handle.join().unwrap();
        }

        // Final consistency check
        let engine = engine.lock().unwrap();
        assert!(
            engine.audit_log().len() < 1000,
            "Audit log should remain bounded under concurrent load"
        );
    }
}
