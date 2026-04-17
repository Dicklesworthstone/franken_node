// SPDX-License-Identifier: MIT
// [10.18] bd-8qlj — Integrate VEF verification state into high-risk
// control transitions and action authorization.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::capacity_defaults::aliases::MAX_AUDIT_LOG_ENTRIES;

// ── Schema ──────────────────────────────────────────────────────────
pub const SCHEMA_VERSION: &str = "verification-state-v1.0";

// ── Event codes ─────────────────────────────────────────────────────
pub const VEF_STATE_TRANSITION_REQUESTED: &str = "VEF_STATE_TRANSITION_REQUESTED";
pub const VEF_STATE_TRANSITION_APPROVED: &str = "VEF_STATE_TRANSITION_APPROVED";
pub const VEF_STATE_TRANSITION_BLOCKED: &str = "VEF_STATE_TRANSITION_BLOCKED";
pub const VEF_STATE_ACTION_AUTHORIZED: &str = "VEF_STATE_ACTION_AUTHORIZED";
pub const VEF_STATE_ACTION_DENIED: &str = "VEF_STATE_ACTION_DENIED";

// ── Error codes ─────────────────────────────────────────────────────
pub const ERR_VEF_STATE_NO_PROOF: &str = "ERR_VEF_STATE_NO_PROOF";
pub const ERR_VEF_STATE_STALE_PROOF: &str = "ERR_VEF_STATE_STALE_PROOF";
pub const ERR_VEF_STATE_INVALID_TRANSITION: &str = "ERR_VEF_STATE_INVALID_TRANSITION";
pub const ERR_VEF_STATE_RISK_EXCEEDED: &str = "ERR_VEF_STATE_RISK_EXCEEDED";
pub const ERR_VEF_STATE_POLICY_MISSING: &str = "ERR_VEF_STATE_POLICY_MISSING";

// ── Invariants ──────────────────────────────────────────────────────
// INV-VEF-STATE-FAIL-CLOSED: missing/stale proof blocks transition
// INV-VEF-STATE-RISK-BOUND: high-risk actions require fresh proof
// INV-VEF-STATE-AUDIT-TRAIL: all transitions and decisions audited
// INV-VEF-STATE-NO-ESCALATION: cannot move to higher risk without proof

/// Risk level for actions and transitions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

/// Verification proof status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofStatus {
    pub proof_id: String,
    pub verified: bool,
    pub verified_at_epoch: u64,
    pub max_age_seconds: u64,
}

impl ProofStatus {
    pub fn is_fresh(&self, current_epoch: u64) -> bool {
        let age = current_epoch.saturating_sub(self.verified_at_epoch);
        self.verified && age < self.max_age_seconds
    }
}

/// Control state for an entity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlState {
    pub entity_id: String,
    pub current_risk_level: RiskLevel,
    pub proof: Option<ProofStatus>,
    pub transition_count: u64,
}

/// Transition request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransitionRequest {
    pub entity_id: String,
    pub target_risk_level: RiskLevel,
    pub action: String,
    pub requested_at_epoch: u64,
}

/// Transition result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransitionResult {
    Approved,
    Blocked { reason: String },
}

/// Action authorization request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionRequest {
    pub entity_id: String,
    pub action: String,
    pub required_risk_level: RiskLevel,
    pub requested_at_epoch: u64,
}

/// Action authorization result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ActionResult {
    Authorized,
    Denied { reason: String },
}

/// Errors from verification state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VefStateError {
    NoProof {
        entity_id: String,
    },
    StaleProof {
        entity_id: String,
        age: u64,
    },
    InvalidTransition {
        from: RiskLevel,
        to: RiskLevel,
    },
    RiskExceeded {
        required: RiskLevel,
        current: RiskLevel,
    },
    PolicyMissing {
        entity_id: String,
    },
}

impl std::fmt::Display for VefStateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoProof { entity_id } => write!(f, "{ERR_VEF_STATE_NO_PROOF}: {entity_id}"),
            Self::StaleProof { entity_id, age } => {
                write!(f, "{ERR_VEF_STATE_STALE_PROOF}: {entity_id} age={age}s")
            }
            Self::InvalidTransition { from, to } => {
                write!(f, "{ERR_VEF_STATE_INVALID_TRANSITION}: {from:?}->{to:?}")
            }
            Self::RiskExceeded { required, current } => {
                write!(
                    f,
                    "{ERR_VEF_STATE_RISK_EXCEEDED}: need={required:?} have={current:?}"
                )
            }
            Self::PolicyMissing { entity_id } => {
                write!(f, "{ERR_VEF_STATE_POLICY_MISSING}: {entity_id}")
            }
        }
    }
}

/// Audit entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateAuditEntry {
    pub event_code: String,
    pub entity_id: String,
    pub detail: String,
}

/// VEF verification state manager.
///
/// INV-VEF-STATE-FAIL-CLOSED: default deny
/// INV-VEF-STATE-AUDIT-TRAIL: all decisions logged
pub struct VerificationStateManager {
    states: BTreeMap<String, ControlState>,
    audit_log: Vec<StateAuditEntry>,
}

impl VerificationStateManager {
    pub fn new() -> Self {
        Self {
            states: BTreeMap::new(),
            audit_log: Vec::new(),
        }
    }

    fn emit_audit(&mut self, entry: StateAuditEntry) {
        push_bounded(&mut self.audit_log, entry, MAX_AUDIT_LOG_ENTRIES);
    }

    pub fn register_entity(&mut self, entity_id: &str) {
        self.states.insert(
            entity_id.into(),
            ControlState {
                entity_id: entity_id.into(),
                current_risk_level: RiskLevel::Low,
                proof: None,
                transition_count: 0,
            },
        );
    }

    pub fn attach_proof(
        &mut self,
        entity_id: &str,
        proof: ProofStatus,
    ) -> Result<(), VefStateError> {
        let state = self
            .states
            .get_mut(entity_id)
            .ok_or(VefStateError::PolicyMissing {
                entity_id: entity_id.into(),
            })?;
        state.proof = Some(proof);
        Ok(())
    }

    /// Request a control transition.
    ///
    /// INV-VEF-STATE-NO-ESCALATION: escalation requires fresh proof
    /// INV-VEF-STATE-FAIL-CLOSED: missing proof blocks
    pub fn request_transition(
        &mut self,
        req: &TransitionRequest,
    ) -> Result<TransitionResult, VefStateError> {
        self.emit_audit(StateAuditEntry {
            event_code: VEF_STATE_TRANSITION_REQUESTED.into(),
            entity_id: req.entity_id.clone(),
            detail: format!("target={:?}", req.target_risk_level),
        });

        let (current_risk_level, proof) = match self.states.get(&req.entity_id) {
            Some(state) => (state.current_risk_level, state.proof.clone()),
            None => {
                self.emit_audit(StateAuditEntry {
                    event_code: VEF_STATE_TRANSITION_BLOCKED.into(),
                    entity_id: req.entity_id.clone(),
                    detail: ERR_VEF_STATE_POLICY_MISSING.into(),
                });
                return Err(VefStateError::PolicyMissing {
                    entity_id: req.entity_id.clone(),
                });
            }
        };

        // Escalation check — INV-VEF-STATE-NO-ESCALATION
        if req.target_risk_level > current_risk_level {
            match proof.as_ref() {
                None => {
                    self.emit_audit(StateAuditEntry {
                        event_code: VEF_STATE_TRANSITION_BLOCKED.into(),
                        entity_id: req.entity_id.clone(),
                        detail: ERR_VEF_STATE_NO_PROOF.into(),
                    });
                    return Err(VefStateError::NoProof {
                        entity_id: req.entity_id.clone(),
                    });
                }
                Some(proof) if !proof.is_fresh(req.requested_at_epoch) => {
                    let age = req
                        .requested_at_epoch
                        .saturating_sub(proof.verified_at_epoch);
                    self.emit_audit(StateAuditEntry {
                        event_code: VEF_STATE_TRANSITION_BLOCKED.into(),
                        entity_id: req.entity_id.clone(),
                        detail: ERR_VEF_STATE_STALE_PROOF.into(),
                    });
                    return Err(VefStateError::StaleProof {
                        entity_id: req.entity_id.clone(),
                        age,
                    });
                }
                _ => {}
            }
        }

        // Apply transition
        let state = match self.states.get_mut(&req.entity_id) {
            Some(state) => state,
            None => {
                self.emit_audit(StateAuditEntry {
                    event_code: VEF_STATE_TRANSITION_BLOCKED.into(),
                    entity_id: req.entity_id.clone(),
                    detail: ERR_VEF_STATE_POLICY_MISSING.into(),
                });
                return Err(VefStateError::PolicyMissing {
                    entity_id: req.entity_id.clone(),
                });
            }
        };
        state.current_risk_level = req.target_risk_level;
        state.transition_count = state.transition_count.saturating_add(1);

        self.emit_audit(StateAuditEntry {
            event_code: VEF_STATE_TRANSITION_APPROVED.into(),
            entity_id: req.entity_id.clone(),
            detail: format!("now={:?}", req.target_risk_level),
        });

        Ok(TransitionResult::Approved)
    }

    /// Authorize an action based on current verification state.
    ///
    /// INV-VEF-STATE-RISK-BOUND: high-risk actions need fresh proof
    pub fn authorize_action(&mut self, req: &ActionRequest) -> Result<ActionResult, VefStateError> {
        let (current_risk_level, proof) = match self.states.get(&req.entity_id) {
            Some(state) => (state.current_risk_level, state.proof.clone()),
            None => {
                self.emit_audit(StateAuditEntry {
                    event_code: VEF_STATE_ACTION_DENIED.into(),
                    entity_id: req.entity_id.clone(),
                    detail: ERR_VEF_STATE_POLICY_MISSING.into(),
                });
                return Err(VefStateError::PolicyMissing {
                    entity_id: req.entity_id.clone(),
                });
            }
        };

        // Risk level check
        if req.required_risk_level > current_risk_level {
            self.emit_audit(StateAuditEntry {
                event_code: VEF_STATE_ACTION_DENIED.into(),
                entity_id: req.entity_id.clone(),
                detail: format!(
                    "need={:?} have={:?}",
                    req.required_risk_level, current_risk_level
                ),
            });
            return Ok(ActionResult::Denied {
                reason: format!(
                    "current risk {:?} < required {:?}",
                    current_risk_level, req.required_risk_level
                ),
            });
        }

        // For High/Critical, require fresh proof — INV-VEF-STATE-RISK-BOUND
        if req.required_risk_level >= RiskLevel::High {
            match proof.as_ref() {
                None => {
                    self.emit_audit(StateAuditEntry {
                        event_code: VEF_STATE_ACTION_DENIED.into(),
                        entity_id: req.entity_id.clone(),
                        detail: "no proof for high-risk action".into(),
                    });
                    return Err(VefStateError::NoProof {
                        entity_id: req.entity_id.clone(),
                    });
                }
                Some(proof) if !proof.is_fresh(req.requested_at_epoch) => {
                    let age = req
                        .requested_at_epoch
                        .saturating_sub(proof.verified_at_epoch);
                    self.emit_audit(StateAuditEntry {
                        event_code: VEF_STATE_ACTION_DENIED.into(),
                        entity_id: req.entity_id.clone(),
                        detail: format!("{ERR_VEF_STATE_STALE_PROOF}: age={age}s"),
                    });
                    return Err(VefStateError::StaleProof {
                        entity_id: req.entity_id.clone(),
                        age,
                    });
                }
                _ => {}
            }
        }

        self.emit_audit(StateAuditEntry {
            event_code: VEF_STATE_ACTION_AUTHORIZED.into(),
            entity_id: req.entity_id.clone(),
            detail: req.action.clone(),
        });

        Ok(ActionResult::Authorized)
    }

    pub fn state(&self, entity_id: &str) -> Option<&ControlState> {
        self.states.get(entity_id)
    }

    pub fn audit_log(&self) -> &[StateAuditEntry] {
        &self.audit_log
    }
}

impl Default for VerificationStateManager {
    fn default() -> Self {
        Self::new()
    }
}

fn push_bounded<T>(items: &mut Vec<T>, item: T, cap: usize) {
    if cap == 0 {
        items.clear();
        return;
    }
    if items.len() >= cap {
        let overflow = items.len().saturating_sub(cap).saturating_add(1);
        items.drain(0..overflow.min(items.len()));
    }
    items.push(item);
}

// ── Tests ───────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;

    fn fresh_proof() -> ProofStatus {
        ProofStatus {
            proof_id: "proof-1".into(),
            verified: true,
            verified_at_epoch: 1000,
            max_age_seconds: 3600,
        }
    }

    fn setup_manager() -> VerificationStateManager {
        let mut mgr = VerificationStateManager::new();
        mgr.register_entity("ext-1");
        mgr
    }

    #[test]
    fn test_schema_version() {
        assert_eq!(SCHEMA_VERSION, "verification-state-v1.0");
    }

    #[test]
    fn test_register_entity() {
        let mgr = setup_manager();
        let state = mgr.state("ext-1").unwrap();
        assert_eq!(state.current_risk_level, RiskLevel::Low);
    }

    #[test]
    fn test_attach_proof() {
        let mut mgr = setup_manager();
        assert!(mgr.attach_proof("ext-1", fresh_proof()).is_ok());
        assert!(mgr.state("ext-1").unwrap().proof.is_some());
    }

    #[test]
    fn test_attach_proof_unknown_entity() {
        let mut mgr = setup_manager();
        assert!(matches!(
            mgr.attach_proof("unknown", fresh_proof()),
            Err(VefStateError::PolicyMissing { .. })
        ));
    }

    #[test]
    fn test_transition_escalation_with_proof() {
        let mut mgr = setup_manager();
        mgr.attach_proof("ext-1", fresh_proof()).unwrap();
        let req = TransitionRequest {
            entity_id: "ext-1".into(),
            target_risk_level: RiskLevel::High,
            action: "elevate".into(),
            requested_at_epoch: 1100,
        };
        assert!(matches!(
            mgr.request_transition(&req),
            Ok(TransitionResult::Approved)
        ));
    }

    #[test]
    fn test_transition_escalation_without_proof() {
        let mut mgr = setup_manager();
        let req = TransitionRequest {
            entity_id: "ext-1".into(),
            target_risk_level: RiskLevel::High,
            action: "elevate".into(),
            requested_at_epoch: 1100,
        };
        assert!(matches!(
            mgr.request_transition(&req),
            Err(VefStateError::NoProof { .. })
        ));
    }

    #[test]
    fn test_transition_escalation_stale_proof() {
        let mut mgr = setup_manager();
        mgr.attach_proof("ext-1", fresh_proof()).unwrap();
        let req = TransitionRequest {
            entity_id: "ext-1".into(),
            target_risk_level: RiskLevel::High,
            action: "elevate".into(),
            requested_at_epoch: 100_000, // way past max age
        };
        assert!(matches!(
            mgr.request_transition(&req),
            Err(VefStateError::StaleProof { .. })
        ));
    }

    #[test]
    fn test_transition_escalation_unverified_proof_fails_closed() {
        let mut mgr = setup_manager();
        mgr.attach_proof(
            "ext-1",
            ProofStatus {
                proof_id: "proof-unverified".into(),
                verified: false,
                verified_at_epoch: 1000,
                max_age_seconds: 3600,
            },
        )
        .unwrap();
        let req = TransitionRequest {
            entity_id: "ext-1".into(),
            target_risk_level: RiskLevel::High,
            action: "elevate".into(),
            requested_at_epoch: 1000,
        };

        assert!(matches!(
            mgr.request_transition(&req),
            Err(VefStateError::StaleProof { .. })
        ));
        let state = mgr.state("ext-1").expect("entity should remain registered");
        assert_eq!(state.current_risk_level, RiskLevel::Low);
        assert_eq!(state.transition_count, 0);
    }

    #[test]
    fn test_transition_escalation_boundary_age_is_stale() {
        let mut mgr = setup_manager();
        mgr.attach_proof(
            "ext-1",
            ProofStatus {
                proof_id: "proof-boundary".into(),
                verified: true,
                verified_at_epoch: 1000,
                max_age_seconds: 100,
            },
        )
        .unwrap();
        let req = TransitionRequest {
            entity_id: "ext-1".into(),
            target_risk_level: RiskLevel::High,
            action: "elevate".into(),
            requested_at_epoch: 1100,
        };

        assert_eq!(
            mgr.request_transition(&req),
            Err(VefStateError::StaleProof {
                entity_id: "ext-1".into(),
                age: 100,
            })
        );
        assert_eq!(mgr.state("ext-1").unwrap().transition_count, 0);
    }

    #[test]
    fn test_downgrade_no_proof_needed() {
        let mut mgr = setup_manager();
        mgr.attach_proof("ext-1", fresh_proof()).unwrap();
        // First escalate
        let up = TransitionRequest {
            entity_id: "ext-1".into(),
            target_risk_level: RiskLevel::High,
            action: "up".into(),
            requested_at_epoch: 1100,
        };
        mgr.request_transition(&up).unwrap();
        // Now downgrade without fresh proof
        let down = TransitionRequest {
            entity_id: "ext-1".into(),
            target_risk_level: RiskLevel::Low,
            action: "down".into(),
            requested_at_epoch: 200_000,
        };
        assert!(matches!(
            mgr.request_transition(&down),
            Ok(TransitionResult::Approved)
        ));
    }

    #[test]
    fn test_authorize_low_risk_ok() {
        let mut mgr = setup_manager();
        let req = ActionRequest {
            entity_id: "ext-1".into(),
            action: "read".into(),
            required_risk_level: RiskLevel::Low,
            requested_at_epoch: 1000,
        };
        assert!(matches!(
            mgr.authorize_action(&req),
            Ok(ActionResult::Authorized)
        ));
    }

    #[test]
    fn test_authorize_high_risk_denied_stale_proof_emits_audit() {
        let mut mgr = setup_manager();
        mgr.attach_proof("ext-1", fresh_proof()).unwrap();
        let up = TransitionRequest {
            entity_id: "ext-1".into(),
            target_risk_level: RiskLevel::Critical,
            action: "up".into(),
            requested_at_epoch: 1100,
        };
        mgr.request_transition(&up).unwrap();
        // Now try action at epoch way past proof freshness
        let req = ActionRequest {
            entity_id: "ext-1".into(),
            action: "deploy".into(),
            required_risk_level: RiskLevel::High,
            requested_at_epoch: 200_000,
        };
        assert!(matches!(
            mgr.authorize_action(&req),
            Err(VefStateError::StaleProof { .. })
        ));
        let last = mgr
            .audit_log()
            .last()
            .expect("stale-proof denial should be audited");
        assert_eq!(last.event_code, VEF_STATE_ACTION_DENIED);
        assert_eq!(last.entity_id, "ext-1");
        assert!(last.detail.contains(ERR_VEF_STATE_STALE_PROOF));
    }

    #[test]
    fn test_authorize_insufficient_risk_level() {
        let mut mgr = setup_manager(); // entity at Low
        let req = ActionRequest {
            entity_id: "ext-1".into(),
            action: "deploy".into(),
            required_risk_level: RiskLevel::Medium,
            requested_at_epoch: 1000,
        };
        assert!(matches!(
            mgr.authorize_action(&req),
            Ok(ActionResult::Denied { .. })
        ));
    }

    #[test]
    fn test_authorize_high_risk_without_proof_fails_closed_when_state_is_high() {
        let mut mgr = setup_manager();
        mgr.states
            .get_mut("ext-1")
            .expect("registered entity should exist")
            .current_risk_level = RiskLevel::High;
        let req = ActionRequest {
            entity_id: "ext-1".into(),
            action: "deploy".into(),
            required_risk_level: RiskLevel::High,
            requested_at_epoch: 1000,
        };

        assert_eq!(
            mgr.authorize_action(&req),
            Err(VefStateError::NoProof {
                entity_id: "ext-1".into(),
            })
        );
        let last = mgr.audit_log().last().expect("denial should be audited");
        assert_eq!(last.event_code, VEF_STATE_ACTION_DENIED);
        assert!(last.detail.contains("no proof"));
    }

    #[test]
    fn test_authorize_critical_with_unverified_proof_fails_closed() {
        let mut mgr = setup_manager();
        {
            let state = mgr
                .states
                .get_mut("ext-1")
                .expect("registered entity should exist");
            state.current_risk_level = RiskLevel::Critical;
            state.proof = Some(ProofStatus {
                proof_id: "proof-unverified".into(),
                verified: false,
                verified_at_epoch: 1000,
                max_age_seconds: 3600,
            });
        }
        let req = ActionRequest {
            entity_id: "ext-1".into(),
            action: "root-operation".into(),
            required_risk_level: RiskLevel::Critical,
            requested_at_epoch: 1000,
        };

        assert!(matches!(
            mgr.authorize_action(&req),
            Err(VefStateError::StaleProof { .. })
        ));
        assert!(
            !mgr.audit_log()
                .iter()
                .any(|entry| entry.event_code == VEF_STATE_ACTION_AUTHORIZED)
        );
    }

    #[test]
    fn test_authorize_boundary_age_high_risk_proof_is_stale() {
        let mut mgr = setup_manager();
        {
            let state = mgr
                .states
                .get_mut("ext-1")
                .expect("registered entity should exist");
            state.current_risk_level = RiskLevel::High;
            state.proof = Some(ProofStatus {
                proof_id: "proof-boundary".into(),
                verified: true,
                verified_at_epoch: 1000,
                max_age_seconds: 50,
            });
        }
        let req = ActionRequest {
            entity_id: "ext-1".into(),
            action: "deploy".into(),
            required_risk_level: RiskLevel::High,
            requested_at_epoch: 1050,
        };

        assert_eq!(
            mgr.authorize_action(&req),
            Err(VefStateError::StaleProof {
                entity_id: "ext-1".into(),
                age: 50,
            })
        );
    }

    #[test]
    fn test_audit_log_populated() {
        let mut mgr = setup_manager();
        mgr.attach_proof("ext-1", fresh_proof()).unwrap();
        let req = TransitionRequest {
            entity_id: "ext-1".into(),
            target_risk_level: RiskLevel::Medium,
            action: "test".into(),
            requested_at_epoch: 1100,
        };
        mgr.request_transition(&req).unwrap();
        assert_eq!(mgr.audit_log().len(), 2);
    }

    #[test]
    fn test_transition_count() {
        let mut mgr = setup_manager();
        mgr.attach_proof("ext-1", fresh_proof()).unwrap();
        let req = TransitionRequest {
            entity_id: "ext-1".into(),
            target_risk_level: RiskLevel::Medium,
            action: "test".into(),
            requested_at_epoch: 1100,
        };
        mgr.request_transition(&req).unwrap();
        assert_eq!(mgr.state("ext-1").unwrap().transition_count, 1);
    }

    #[test]
    fn test_proof_freshness() {
        let p = fresh_proof();
        assert!(p.is_fresh(1500)); // age 500 < 3600
        assert!(!p.is_fresh(10000)); // age 9000 > 3600
    }

    #[test]
    fn test_proof_freshness_rejects_unverified_even_at_issue_epoch() {
        let p = ProofStatus {
            proof_id: "proof-unverified".into(),
            verified: false,
            verified_at_epoch: 1000,
            max_age_seconds: 3600,
        };

        assert!(!p.is_fresh(1000));
    }

    #[test]
    fn test_proof_freshness_rejects_exact_expiry_boundary() {
        let p = ProofStatus {
            proof_id: "proof-boundary".into(),
            verified: true,
            verified_at_epoch: 1000,
            max_age_seconds: 10,
        };

        assert!(!p.is_fresh(1010));
    }

    #[test]
    fn test_push_bounded_zero_capacity_clears_without_retaining_new_item() {
        let mut audit = vec![
            StateAuditEntry {
                event_code: VEF_STATE_ACTION_AUTHORIZED.into(),
                entity_id: "old-a".into(),
                detail: "old".into(),
            },
            StateAuditEntry {
                event_code: VEF_STATE_ACTION_DENIED.into(),
                entity_id: "old-b".into(),
                detail: "old".into(),
            },
        ];

        push_bounded(
            &mut audit,
            StateAuditEntry {
                event_code: VEF_STATE_TRANSITION_BLOCKED.into(),
                entity_id: "new".into(),
                detail: "ignored".into(),
            },
            0,
        );

        assert!(audit.is_empty());
    }

    #[test]
    fn test_zero_max_age_proof_blocks_escalation_at_issue_epoch() {
        let mut mgr = setup_manager();
        mgr.attach_proof(
            "ext-1",
            ProofStatus {
                proof_id: "proof-zero-age".into(),
                verified: true,
                verified_at_epoch: 1000,
                max_age_seconds: 0,
            },
        )
        .unwrap();
        let req = TransitionRequest {
            entity_id: "ext-1".into(),
            target_risk_level: RiskLevel::Medium,
            action: "elevate".into(),
            requested_at_epoch: 1000,
        };

        assert_eq!(
            mgr.request_transition(&req),
            Err(VefStateError::StaleProof {
                entity_id: "ext-1".into(),
                age: 0,
            })
        );
        let state = mgr.state("ext-1").expect("entity should remain registered");
        assert_eq!(state.current_risk_level, RiskLevel::Low);
        assert_eq!(state.transition_count, 0);
    }

    #[test]
    fn test_failed_no_proof_transition_preserves_state_and_audit_order() {
        let mut mgr = setup_manager();
        let req = TransitionRequest {
            entity_id: "ext-1".into(),
            target_risk_level: RiskLevel::Critical,
            action: "critical-up".into(),
            requested_at_epoch: 1100,
        };

        assert_eq!(
            mgr.request_transition(&req),
            Err(VefStateError::NoProof {
                entity_id: "ext-1".into(),
            })
        );

        let state = mgr.state("ext-1").expect("entity should remain registered");
        assert_eq!(state.current_risk_level, RiskLevel::Low);
        assert_eq!(state.transition_count, 0);
        assert_eq!(mgr.audit_log().len(), 2);
        assert_eq!(
            mgr.audit_log()[0].event_code,
            VEF_STATE_TRANSITION_REQUESTED
        );
        assert_eq!(mgr.audit_log()[1].event_code, VEF_STATE_TRANSITION_BLOCKED);
    }

    #[test]
    fn test_failed_stale_transition_preserves_existing_state() {
        let mut mgr = setup_manager();
        {
            let state = mgr
                .states
                .get_mut("ext-1")
                .expect("registered entity should exist");
            state.current_risk_level = RiskLevel::Medium;
            state.transition_count = 3;
            state.proof = Some(ProofStatus {
                proof_id: "proof-stale".into(),
                verified: true,
                verified_at_epoch: 1000,
                max_age_seconds: 10,
            });
        }
        let req = TransitionRequest {
            entity_id: "ext-1".into(),
            target_risk_level: RiskLevel::Critical,
            action: "critical-up".into(),
            requested_at_epoch: 1010,
        };

        assert_eq!(
            mgr.request_transition(&req),
            Err(VefStateError::StaleProof {
                entity_id: "ext-1".into(),
                age: 10,
            })
        );
        let state = mgr.state("ext-1").expect("entity should remain registered");
        assert_eq!(state.current_risk_level, RiskLevel::Medium);
        assert_eq!(state.transition_count, 3);
    }

    #[test]
    fn test_insufficient_risk_denial_precedes_no_proof_error() {
        let mut mgr = setup_manager();
        let req = ActionRequest {
            entity_id: "ext-1".into(),
            action: "deploy".into(),
            required_risk_level: RiskLevel::High,
            requested_at_epoch: 1100,
        };

        let result = mgr.authorize_action(&req);

        assert!(matches!(result, Ok(ActionResult::Denied { .. })));
        assert_eq!(mgr.audit_log().len(), 1);
        assert_eq!(mgr.audit_log()[0].event_code, VEF_STATE_ACTION_DENIED);
        assert!(mgr.audit_log()[0].detail.contains("need=High have=Low"));
    }

    #[test]
    fn test_medium_action_denial_does_not_require_or_consume_proof() {
        let mut mgr = setup_manager();
        let req = ActionRequest {
            entity_id: "ext-1".into(),
            action: "moderate-change".into(),
            required_risk_level: RiskLevel::Medium,
            requested_at_epoch: 1100,
        };

        let result = mgr.authorize_action(&req);

        assert!(matches!(result, Ok(ActionResult::Denied { .. })));
        let state = mgr.state("ext-1").expect("entity should remain registered");
        assert!(state.proof.is_none());
        assert_eq!(state.current_risk_level, RiskLevel::Low);
    }

    #[test]
    fn test_failed_high_risk_action_without_proof_never_authorizes() {
        let mut mgr = setup_manager();
        mgr.states
            .get_mut("ext-1")
            .expect("registered entity should exist")
            .current_risk_level = RiskLevel::High;
        let req = ActionRequest {
            entity_id: "ext-1".into(),
            action: "deploy".into(),
            required_risk_level: RiskLevel::High,
            requested_at_epoch: 1100,
        };

        assert!(matches!(
            mgr.authorize_action(&req),
            Err(VefStateError::NoProof { .. })
        ));
        assert!(
            !mgr.audit_log()
                .iter()
                .any(|entry| entry.event_code == VEF_STATE_ACTION_AUTHORIZED)
        );
    }

    #[test]
    fn test_attach_proof_unknown_entity_does_not_create_state_or_audit() {
        let mut mgr = setup_manager();

        assert_eq!(
            mgr.attach_proof("missing-entity", fresh_proof()),
            Err(VefStateError::PolicyMissing {
                entity_id: "missing-entity".into(),
            })
        );

        assert!(mgr.state("missing-entity").is_none());
        assert!(mgr.audit_log().is_empty());
    }

    #[test]
    fn test_risk_level_ordering() {
        assert!(RiskLevel::Low < RiskLevel::Medium);
        assert!(RiskLevel::Medium < RiskLevel::High);
        assert!(RiskLevel::High < RiskLevel::Critical);
    }

    #[test]
    fn test_error_display() {
        let e = VefStateError::NoProof {
            entity_id: "x".into(),
        };
        assert!(e.to_string().contains(ERR_VEF_STATE_NO_PROOF));
    }

    #[test]
    fn test_default_manager() {
        let mgr = VerificationStateManager::default();
        assert!(mgr.audit_log().is_empty());
    }

    #[test]
    fn test_authorize_high_risk_with_fresh_proof() {
        let mut mgr = setup_manager();
        mgr.attach_proof("ext-1", fresh_proof()).unwrap();
        let up = TransitionRequest {
            entity_id: "ext-1".into(),
            target_risk_level: RiskLevel::High,
            action: "up".into(),
            requested_at_epoch: 1100,
        };
        mgr.request_transition(&up).unwrap();
        let req = ActionRequest {
            entity_id: "ext-1".into(),
            action: "critical-op".into(),
            required_risk_level: RiskLevel::High,
            requested_at_epoch: 1200,
        };
        assert!(matches!(
            mgr.authorize_action(&req),
            Ok(ActionResult::Authorized)
        ));
    }

    #[test]
    fn test_unknown_entity_transition_emits_blocked_audit() {
        let mut mgr = setup_manager();
        let req = TransitionRequest {
            entity_id: "nope".into(),
            target_risk_level: RiskLevel::High,
            action: "x".into(),
            requested_at_epoch: 1000,
        };
        assert!(matches!(
            mgr.request_transition(&req),
            Err(VefStateError::PolicyMissing { .. })
        ));
        assert_eq!(mgr.audit_log().len(), 2);
        let last = mgr.audit_log().last().expect("audit entry should exist");
        assert_eq!(last.event_code, VEF_STATE_TRANSITION_BLOCKED);
        assert_eq!(last.entity_id, "nope");
        assert_eq!(last.detail, ERR_VEF_STATE_POLICY_MISSING);
        assert!(mgr.state("nope").is_none());
    }

    #[test]
    fn test_unknown_entity_action_emits_audit() {
        let mut mgr = setup_manager();
        let req = ActionRequest {
            entity_id: "nope".into(),
            action: "deploy".into(),
            required_risk_level: RiskLevel::High,
            requested_at_epoch: 1000,
        };
        assert!(matches!(
            mgr.authorize_action(&req),
            Err(VefStateError::PolicyMissing { .. })
        ));
        assert_eq!(mgr.audit_log().len(), 1);
        let last = mgr.audit_log().last().expect("audit entry should exist");
        assert_eq!(last.event_code, VEF_STATE_ACTION_DENIED);
        assert_eq!(last.entity_id, "nope");
        assert_eq!(last.detail, ERR_VEF_STATE_POLICY_MISSING);
    }
}
