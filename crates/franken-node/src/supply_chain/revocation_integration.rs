//! Revocation propagation + freshness integration for extension workflows (bd-12q).
//!
//! Integrates canonical revocation primitives from 10.13:
//! - monotonic revocation head registry (`bd-y7lu`)
//! - safety-tier freshness gate (`bd-1m8r`)

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::security::revocation_freshness::{
    FreshnessCheck, FreshnessPolicy, SafetyTier, evaluate_freshness,
};
use crate::supply_chain::revocation_registry::{
    RevocationError, RevocationHead, RevocationRegistry,
};

/// Extension lifecycle operations that require revocation integration checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExtensionOperation {
    Install,
    Update,
    Load,
    Invoke,
    Uninstall,
    BackgroundRefresh,
}

/// Safety tiers for extension operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExtensionSafetyTier {
    Low,
    Medium,
    High,
}

impl ExtensionSafetyTier {
    #[must_use]
    pub fn for_operation(operation: ExtensionOperation) -> Self {
        match operation {
            ExtensionOperation::Install | ExtensionOperation::Update | ExtensionOperation::Load => {
                Self::Medium
            }
            ExtensionOperation::Invoke => Self::High,
            ExtensionOperation::Uninstall | ExtensionOperation::BackgroundRefresh => Self::Low,
        }
    }
}

/// Revocation integration policy thresholds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevocationIntegrationPolicy {
    pub low_tier_max_age_secs: u64,
    pub medium_tier_max_age_secs: u64,
    pub high_tier_max_age_secs: u64,
    pub propagation_sla_secs: u64,
}

impl RevocationIntegrationPolicy {
    #[must_use]
    pub fn default_policy() -> Self {
        Self {
            low_tier_max_age_secs: 6 * 60 * 60,
            medium_tier_max_age_secs: 5 * 60,
            high_tier_max_age_secs: 60 * 60,
            propagation_sla_secs: 60,
        }
    }

    #[must_use]
    pub fn max_age_for_tier(&self, tier: ExtensionSafetyTier) -> u64 {
        match tier {
            ExtensionSafetyTier::Low => self.low_tier_max_age_secs,
            ExtensionSafetyTier::Medium => self.medium_tier_max_age_secs,
            ExtensionSafetyTier::High => self.high_tier_max_age_secs,
        }
    }
}

/// Structured event codes for revocation integration decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RevocationIntegrationEvent {
    ExtensionRevocationCheckPassed,
    ExtensionRevocationCheckFailed,
    ExtensionRevocationStaleWarning,
    RevocationPropagationReceived,
    RevocationCascadeInitiated,
}

/// Decision status for extension revocation checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevocationDecisionStatus {
    Passed,
    FailedStale,
    FailedRevoked,
    FailedUnavailable,
    WarnStale,
}

/// Input context for extension revocation checks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtensionOperationContext {
    pub extension_id: String,
    pub operation: ExtensionOperation,
    pub safety_tier: ExtensionSafetyTier,
    pub zone_id: String,
    pub revocation_data_age_secs: u64,
    pub now_epoch: u64,
    pub trace_id: String,
    pub dependent_extensions: Vec<String>,
    pub active_sessions: Vec<String>,
}

/// Propagation update event from the canonical revocation feed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PropagationUpdate {
    pub zone_id: String,
    pub sequence: u64,
    pub revoked_extension_id: String,
    pub reason: String,
    pub published_at_epoch: u64,
    pub received_at_epoch: u64,
    pub trace_id: String,
}

/// Result of processing a propagation update.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PropagationResult {
    pub accepted: bool,
    pub revocation_head: u64,
    pub latency_secs: u64,
    pub within_sla: bool,
    pub event: RevocationIntegrationEvent,
    pub error_code: Option<String>,
    pub trace_id: String,
}

/// Detailed revocation decision for extension lifecycle operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevocationCheckDecision {
    pub extension_id: String,
    pub operation: ExtensionOperation,
    pub safety_tier: ExtensionSafetyTier,
    pub status: RevocationDecisionStatus,
    pub allowed: bool,
    pub revocation_head: Option<u64>,
    pub staleness_secs: u64,
    pub max_allowed_staleness_secs: u64,
    pub error_code: Option<String>,
    pub event: RevocationIntegrationEvent,
    pub cascade_actions: Vec<String>,
    pub trace_id: String,
}

/// Ledger entry for audit/compliance evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevocationLedgerEntry {
    pub extension_id: String,
    pub operation: ExtensionOperation,
    pub decision_status: RevocationDecisionStatus,
    pub event: RevocationIntegrationEvent,
    pub error_code: Option<String>,
    pub revocation_head: Option<u64>,
    pub staleness_secs: u64,
    pub max_allowed_staleness_secs: u64,
    pub timestamp_epoch: u64,
    pub trace_id: String,
}

/// Event stream entry for structured logs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevocationEventRecord {
    pub event: RevocationIntegrationEvent,
    pub extension_id: Option<String>,
    pub zone_id: String,
    pub revocation_head: Option<u64>,
    pub staleness_secs: Option<u64>,
    pub trace_id: String,
}

/// Integration error for propagation processing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RevocationIntegrationError {
    RegistryUnavailable { code: String, message: String },
}

impl RevocationIntegrationError {
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::RegistryUnavailable { .. } => "REVOCATION_DATA_UNAVAILABLE",
        }
    }
}

/// Canonical revocation integration engine for extension workflows.
#[derive(Debug)]
pub struct RevocationIntegrationEngine {
    policy: RevocationIntegrationPolicy,
    freshness_policy: FreshnessPolicy,
    registry: RevocationRegistry,
    last_seen_heads: HashMap<String, u64>,
    pub evidence_ledger: Vec<RevocationLedgerEntry>,
    pub events: Vec<RevocationEventRecord>,
}

impl RevocationIntegrationEngine {
    #[must_use]
    pub fn new(policy: RevocationIntegrationPolicy) -> Self {
        // Reuse 10.13 safety-tier freshness gate with explicit tier mapping:
        // - high extension tier -> Risky freshness threshold
        // - medium extension tier -> Dangerous freshness threshold
        // - low extension tier -> handled as warning-only window
        let freshness_policy = FreshnessPolicy {
            risky_max_age_secs: policy.high_tier_max_age_secs,
            dangerous_max_age_secs: policy.medium_tier_max_age_secs,
        };

        Self {
            policy,
            freshness_policy,
            registry: RevocationRegistry::new(),
            last_seen_heads: HashMap::new(),
            evidence_ledger: Vec::new(),
            events: Vec::new(),
        }
    }

    pub fn init_zone(&mut self, zone_id: &str) {
        self.registry.init_zone(zone_id);
        self.last_seen_heads.entry(zone_id.to_string()).or_insert(0);
    }

    pub fn process_propagation(
        &mut self,
        update: &PropagationUpdate,
    ) -> Result<PropagationResult, RevocationIntegrationError> {
        let head = RevocationHead {
            zone_id: update.zone_id.clone(),
            sequence: update.sequence,
            revoked_artifact: update.revoked_extension_id.clone(),
            reason: update.reason.clone(),
            timestamp: update.received_at_epoch.to_string(),
            trace_id: update.trace_id.clone(),
        };

        let revocation_head = self
            .registry
            .advance_head(head)
            .map_err(map_registry_error)?;

        let latency_secs = update
            .received_at_epoch
            .saturating_sub(update.published_at_epoch);
        let within_sla = latency_secs <= self.policy.propagation_sla_secs;

        self.last_seen_heads
            .insert(update.zone_id.clone(), revocation_head);

        let error_code = if within_sla {
            None
        } else {
            Some("REVOCATION_PROPAGATION_SLA_MISSED".to_string())
        };

        self.push_event(RevocationEventRecord {
            event: RevocationIntegrationEvent::RevocationPropagationReceived,
            extension_id: Some(update.revoked_extension_id.clone()),
            zone_id: update.zone_id.clone(),
            revocation_head: Some(revocation_head),
            staleness_secs: Some(latency_secs),
            trace_id: update.trace_id.clone(),
        });

        Ok(PropagationResult {
            accepted: true,
            revocation_head,
            latency_secs,
            within_sla,
            event: RevocationIntegrationEvent::RevocationPropagationReceived,
            error_code,
            trace_id: update.trace_id.clone(),
        })
    }

    #[must_use]
    pub fn evaluate_operation(
        &mut self,
        context: &ExtensionOperationContext,
    ) -> RevocationCheckDecision {
        let max_allowed = self.policy.max_age_for_tier(context.safety_tier);

        let head = match self.registry.current_head(&context.zone_id) {
            Ok(value) => value,
            Err(error) => {
                return self.unavailable_decision(
                    context,
                    max_allowed,
                    format!("{}", error),
                    Some(error.code().to_string()),
                );
            }
        };

        if let Some(last_seen) = self.last_seen_heads.get(&context.zone_id)
            && head < *last_seen
        {
            return self.unavailable_decision(
                context,
                max_allowed,
                format!(
                    "revocation head regressed for zone {}: current={} last_seen={}",
                    context.zone_id, head, last_seen
                ),
                Some("REVOCATION_HEAD_REGRESSION".to_string()),
            );
        }

        self.last_seen_heads.insert(context.zone_id.clone(), head);

        let revoked = match self
            .registry
            .is_revoked(&context.zone_id, &context.extension_id)
        {
            Ok(value) => value,
            Err(error) => {
                return self.unavailable_decision(
                    context,
                    max_allowed,
                    format!("{}", error),
                    Some(error.code().to_string()),
                );
            }
        };

        if revoked {
            let mut cascade_actions = Vec::new();
            for dependent in &context.dependent_extensions {
                cascade_actions.push(format!(
                    "notify dependent extension {dependent} for quarantine"
                ));
            }
            for session in &context.active_sessions {
                cascade_actions.push(format!("terminate active session {session}"));
            }

            self.push_event(RevocationEventRecord {
                event: RevocationIntegrationEvent::RevocationCascadeInitiated,
                extension_id: Some(context.extension_id.clone()),
                zone_id: context.zone_id.clone(),
                revocation_head: Some(head),
                staleness_secs: Some(context.revocation_data_age_secs),
                trace_id: context.trace_id.clone(),
            });

            let decision = RevocationCheckDecision {
                extension_id: context.extension_id.clone(),
                operation: context.operation,
                safety_tier: context.safety_tier,
                status: RevocationDecisionStatus::FailedRevoked,
                allowed: false,
                revocation_head: Some(head),
                staleness_secs: context.revocation_data_age_secs,
                max_allowed_staleness_secs: max_allowed,
                error_code: Some("REVOCATION_EXTENSION_REVOKED".to_string()),
                event: RevocationIntegrationEvent::ExtensionRevocationCheckFailed,
                cascade_actions,
                trace_id: context.trace_id.clone(),
            };
            self.record_decision(context.now_epoch, &decision, &context.zone_id);
            return decision;
        }

        match context.safety_tier {
            ExtensionSafetyTier::Low => {
                if context.revocation_data_age_secs > max_allowed {
                    let decision = RevocationCheckDecision {
                        extension_id: context.extension_id.clone(),
                        operation: context.operation,
                        safety_tier: context.safety_tier,
                        status: RevocationDecisionStatus::WarnStale,
                        allowed: true,
                        revocation_head: Some(head),
                        staleness_secs: context.revocation_data_age_secs,
                        max_allowed_staleness_secs: max_allowed,
                        error_code: None,
                        event: RevocationIntegrationEvent::ExtensionRevocationStaleWarning,
                        cascade_actions: Vec::new(),
                        trace_id: context.trace_id.clone(),
                    };
                    self.record_decision(context.now_epoch, &decision, &context.zone_id);
                    decision
                } else {
                    let decision = RevocationCheckDecision {
                        extension_id: context.extension_id.clone(),
                        operation: context.operation,
                        safety_tier: context.safety_tier,
                        status: RevocationDecisionStatus::Passed,
                        allowed: true,
                        revocation_head: Some(head),
                        staleness_secs: context.revocation_data_age_secs,
                        max_allowed_staleness_secs: max_allowed,
                        error_code: None,
                        event: RevocationIntegrationEvent::ExtensionRevocationCheckPassed,
                        cascade_actions: Vec::new(),
                        trace_id: context.trace_id.clone(),
                    };
                    self.record_decision(context.now_epoch, &decision, &context.zone_id);
                    decision
                }
            }
            ExtensionSafetyTier::Medium | ExtensionSafetyTier::High => {
                let mapped_tier = if context.safety_tier == ExtensionSafetyTier::High {
                    SafetyTier::Risky
                } else {
                    SafetyTier::Dangerous
                };

                let freshness = evaluate_freshness(
                    &self.freshness_policy,
                    &FreshnessCheck {
                        action_id: context.extension_id.clone(),
                        tier: mapped_tier,
                        revocation_age_secs: context.revocation_data_age_secs,
                        trace_id: context.trace_id.clone(),
                        timestamp: context.now_epoch.to_string(),
                    },
                    None,
                );

                match freshness {
                    Ok(_) => {
                        let decision = RevocationCheckDecision {
                            extension_id: context.extension_id.clone(),
                            operation: context.operation,
                            safety_tier: context.safety_tier,
                            status: RevocationDecisionStatus::Passed,
                            allowed: true,
                            revocation_head: Some(head),
                            staleness_secs: context.revocation_data_age_secs,
                            max_allowed_staleness_secs: max_allowed,
                            error_code: None,
                            event: RevocationIntegrationEvent::ExtensionRevocationCheckPassed,
                            cascade_actions: Vec::new(),
                            trace_id: context.trace_id.clone(),
                        };
                        self.record_decision(context.now_epoch, &decision, &context.zone_id);
                        decision
                    }
                    Err(_) => {
                        let decision = RevocationCheckDecision {
                            extension_id: context.extension_id.clone(),
                            operation: context.operation,
                            safety_tier: context.safety_tier,
                            status: RevocationDecisionStatus::FailedStale,
                            allowed: false,
                            revocation_head: Some(head),
                            staleness_secs: context.revocation_data_age_secs,
                            max_allowed_staleness_secs: max_allowed,
                            error_code: Some("REVOCATION_DATA_STALE".to_string()),
                            event: RevocationIntegrationEvent::ExtensionRevocationCheckFailed,
                            cascade_actions: Vec::new(),
                            trace_id: context.trace_id.clone(),
                        };
                        self.record_decision(context.now_epoch, &decision, &context.zone_id);
                        decision
                    }
                }
            }
        }
    }

    fn unavailable_decision(
        &mut self,
        context: &ExtensionOperationContext,
        max_allowed: u64,
        message: String,
        error_code: Option<String>,
    ) -> RevocationCheckDecision {
        let decision = RevocationCheckDecision {
            extension_id: context.extension_id.clone(),
            operation: context.operation,
            safety_tier: context.safety_tier,
            status: RevocationDecisionStatus::FailedUnavailable,
            allowed: false,
            revocation_head: None,
            staleness_secs: context.revocation_data_age_secs,
            max_allowed_staleness_secs: max_allowed,
            error_code: error_code.or(Some("REVOCATION_DATA_UNAVAILABLE".to_string())),
            event: RevocationIntegrationEvent::ExtensionRevocationCheckFailed,
            cascade_actions: Vec::new(),
            trace_id: context.trace_id.clone(),
        };

        self.record_decision(context.now_epoch, &decision, &context.zone_id);
        self.push_event(RevocationEventRecord {
            event: RevocationIntegrationEvent::ExtensionRevocationCheckFailed,
            extension_id: Some(context.extension_id.clone()),
            zone_id: context.zone_id.clone(),
            revocation_head: None,
            staleness_secs: Some(context.revocation_data_age_secs),
            trace_id: format!("{}:{message}", context.trace_id),
        });
        decision
    }

    fn record_decision(
        &mut self,
        now_epoch: u64,
        decision: &RevocationCheckDecision,
        zone_id: &str,
    ) {
        self.evidence_ledger.push(RevocationLedgerEntry {
            extension_id: decision.extension_id.clone(),
            operation: decision.operation,
            decision_status: decision.status,
            event: decision.event,
            error_code: decision.error_code.clone(),
            revocation_head: decision.revocation_head,
            staleness_secs: decision.staleness_secs,
            max_allowed_staleness_secs: decision.max_allowed_staleness_secs,
            timestamp_epoch: now_epoch,
            trace_id: decision.trace_id.clone(),
        });

        self.push_event(RevocationEventRecord {
            event: decision.event,
            extension_id: Some(decision.extension_id.clone()),
            zone_id: zone_id.to_string(),
            revocation_head: decision.revocation_head,
            staleness_secs: Some(decision.staleness_secs),
            trace_id: decision.trace_id.clone(),
        });
    }

    fn push_event(&mut self, event: RevocationEventRecord) {
        self.events.push(event);
    }
}

fn map_registry_error(error: RevocationError) -> RevocationIntegrationError {
    RevocationIntegrationError::RegistryUnavailable {
        code: error.code().to_string(),
        message: error.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn engine() -> RevocationIntegrationEngine {
        let mut engine =
            RevocationIntegrationEngine::new(RevocationIntegrationPolicy::default_policy());
        engine.init_zone("prod");
        engine
    }

    fn propagation_update(
        sequence: u64,
        extension: &str,
        published: u64,
        received: u64,
    ) -> PropagationUpdate {
        PropagationUpdate {
            zone_id: "prod".to_string(),
            sequence,
            revoked_extension_id: extension.to_string(),
            reason: "compromised".to_string(),
            published_at_epoch: published,
            received_at_epoch: received,
            trace_id: format!("trace-prop-{sequence}"),
        }
    }

    fn operation_context(
        extension_id: &str,
        operation: ExtensionOperation,
        safety_tier: ExtensionSafetyTier,
        age_secs: u64,
    ) -> ExtensionOperationContext {
        ExtensionOperationContext {
            extension_id: extension_id.to_string(),
            operation,
            safety_tier,
            zone_id: "prod".to_string(),
            revocation_data_age_secs: age_secs,
            now_epoch: 2_000,
            trace_id: format!("trace-{extension_id}"),
            dependent_extensions: vec!["dep-a".to_string()],
            active_sessions: vec!["sess-1".to_string()],
        }
    }

    #[test]
    fn high_safety_stale_is_denied() {
        let mut engine = engine();
        engine
            .process_propagation(&propagation_update(1, "other-ext", 1_900, 1_905))
            .expect("propagation");

        let decision = engine.evaluate_operation(&operation_context(
            "target-ext",
            ExtensionOperation::Invoke,
            ExtensionSafetyTier::High,
            4_000,
        ));

        assert!(!decision.allowed);
        assert_eq!(decision.status, RevocationDecisionStatus::FailedStale);
        assert_eq!(
            decision.error_code.as_deref(),
            Some("REVOCATION_DATA_STALE")
        );
        assert_eq!(
            decision.event,
            RevocationIntegrationEvent::ExtensionRevocationCheckFailed
        );
    }

    #[test]
    fn low_safety_stale_warns_but_allows() {
        let mut engine = engine();
        engine
            .process_propagation(&propagation_update(1, "other-ext", 1_900, 1_905))
            .expect("propagation");

        let decision = engine.evaluate_operation(&operation_context(
            "target-ext",
            ExtensionOperation::BackgroundRefresh,
            ExtensionSafetyTier::Low,
            30_000,
        ));

        assert!(decision.allowed);
        assert_eq!(decision.status, RevocationDecisionStatus::WarnStale);
        assert_eq!(
            decision.event,
            RevocationIntegrationEvent::ExtensionRevocationStaleWarning
        );
    }

    #[test]
    fn revoked_extension_triggers_cascade() {
        let mut engine = engine();
        engine
            .process_propagation(&propagation_update(1, "target-ext", 1_900, 1_901))
            .expect("propagation");

        let decision = engine.evaluate_operation(&operation_context(
            "target-ext",
            ExtensionOperation::Install,
            ExtensionSafetyTier::Medium,
            120,
        ));

        assert!(!decision.allowed);
        assert_eq!(decision.status, RevocationDecisionStatus::FailedRevoked);
        assert_eq!(
            decision.error_code.as_deref(),
            Some("REVOCATION_EXTENSION_REVOKED")
        );
        assert_eq!(decision.cascade_actions.len(), 2);
        assert!(engine.events.iter().any(|event| {
            event.event == RevocationIntegrationEvent::RevocationCascadeInitiated
                && event.extension_id.as_deref() == Some("target-ext")
        }));
    }

    #[test]
    fn monotonic_head_regression_is_rejected_fail_closed() {
        let mut engine = engine();
        engine
            .process_propagation(&propagation_update(2, "other-ext", 1_900, 1_901))
            .expect("propagation");

        // Simulate local state remembering a newer head than registry reports.
        engine.last_seen_heads.insert("prod".to_string(), 5);

        let decision = engine.evaluate_operation(&operation_context(
            "target-ext",
            ExtensionOperation::Load,
            ExtensionSafetyTier::Medium,
            100,
        ));

        assert!(!decision.allowed);
        assert_eq!(decision.status, RevocationDecisionStatus::FailedUnavailable);
        assert_eq!(
            decision.error_code.as_deref(),
            Some("REVOCATION_HEAD_REGRESSION")
        );
    }

    #[test]
    fn propagation_sla_miss_is_recorded() {
        let mut engine = engine();
        let result = engine
            .process_propagation(&propagation_update(1, "other-ext", 1_000, 1_090))
            .expect("propagation");

        assert!(result.accepted);
        assert!(!result.within_sla);
        assert_eq!(
            result.error_code.as_deref(),
            Some("REVOCATION_PROPAGATION_SLA_MISSED")
        );
    }

    #[test]
    fn evidence_ledger_captures_all_decisions() {
        let mut engine = engine();
        engine
            .process_propagation(&propagation_update(1, "other-ext", 1_900, 1_905))
            .expect("propagation");

        let _ = engine.evaluate_operation(&operation_context(
            "target-ext",
            ExtensionOperation::Install,
            ExtensionSafetyTier::Medium,
            120,
        ));
        let _ = engine.evaluate_operation(&operation_context(
            "target-ext",
            ExtensionOperation::BackgroundRefresh,
            ExtensionSafetyTier::Low,
            30_000,
        ));

        assert_eq!(engine.evidence_ledger.len(), 2);
        assert_eq!(
            engine.evidence_ledger[0].event,
            RevocationIntegrationEvent::ExtensionRevocationCheckPassed
        );
        assert_eq!(
            engine.evidence_ledger[1].event,
            RevocationIntegrationEvent::ExtensionRevocationStaleWarning
        );
    }
}
