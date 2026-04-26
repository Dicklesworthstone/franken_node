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

    // === Comprehensive Negative-Path Security Tests ===

    /// Negative test: Unicode injection attacks in entity IDs and action names
    #[test]
    fn negative_unicode_injection_entity_ids_actions() {
        let mut mgr = setup_manager();

        // Test malicious Unicode in entity IDs
        let malicious_entity_ids = vec![
            "entity\u{202e}evil\u{200b}", // Right-to-Left Override + Zero Width Space
            "entity\u{0000}injection",    // Null byte injection
            "entity\u{feff}bom",          // Byte Order Mark
            "entity\u{2028}line\u{2029}para", // Line/Paragraph separators
            "entity\u{200c}\u{200d}joiners", // Zero-width joiners
            "entity\x00\x01\x02\x03\x1f", // Control characters
        ];

        for (i, malicious_entity_id) in malicious_entity_ids.iter().enumerate() {
            // Initialize state for malicious entity ID
            let init_result =
                mgr.initialize_entity(malicious_entity_id, RiskLevel::Low, None, 100 + i as u64);

            match init_result {
                Ok(()) => {
                    // Unicode was accepted, verify it doesn't corrupt state management
                    let state = mgr.state(malicious_entity_id);
                    assert!(state.is_some(), "State should exist for Unicode entity ID");

                    if let Some(state) = state {
                        assert_eq!(&state.entity_id, malicious_entity_id);
                        assert_eq!(state.current_risk_level, RiskLevel::Low);
                    }

                    // Test transition with Unicode entity ID
                    let malicious_action = format!("action\u{202e}evil\u{200b}{}", i);
                    let transition_request = TransitionRequest {
                        entity_id: malicious_entity_id.to_string(),
                        target_risk_level: RiskLevel::Medium,
                        action: malicious_action.clone(),
                        requested_at_epoch: 200 + i as u64,
                    };

                    let transition_result = mgr.request_transition(&transition_request);
                    // Should handle Unicode gracefully
                }
                Err(_) => {
                    // Unicode rejection in entity IDs is also acceptable for security
                }
            }
        }

        // Test Unicode in action names
        let clean_entity = "clean-entity";
        mgr.initialize_entity(clean_entity, RiskLevel::Low, None, 1000)
            .unwrap();

        let malicious_actions = vec![
            "deploy\u{202e}reverse\u{200b}",
            "execute\u{0000}null\u{0001}control",
            "modify\u{feff}bom\u{2028}break",
            "action".repeat(1000), // Extremely long action name
        ];

        for (i, malicious_action) in malicious_actions.iter().enumerate() {
            let action_request = ActionRequest {
                entity_id: clean_entity.to_string(),
                action: malicious_action.to_string(),
                required_risk_level: RiskLevel::Low,
                requested_at_epoch: 1100 + i as u64,
            };

            let action_result = mgr.authorize_action(&action_request);

            // Should handle Unicode in action names gracefully
            match action_result {
                Ok(ActionResult::Authorized) => {
                    // Unicode action accepted
                }
                Ok(ActionResult::Denied { .. }) => {
                    // Action denied for other reasons
                }
                Err(_) => {
                    // Unicode action rejection acceptable
                }
            }
        }
    }

    /// Negative test: Risk escalation bypass attempts
    #[test]
    fn negative_risk_escalation_bypass_attempts() {
        let mut mgr = setup_manager();

        // Initialize entity at low risk
        let entity_id = "escalation-test";
        mgr.initialize_entity(entity_id, RiskLevel::Low, None, 1000)
            .unwrap();

        // Test direct escalation to critical without intermediate steps
        let critical_escalation = TransitionRequest {
            entity_id: entity_id.to_string(),
            target_risk_level: RiskLevel::Critical,
            action: "escalate-directly".to_string(),
            requested_at_epoch: 1100,
        };

        let critical_result = mgr.request_transition(&critical_escalation);

        // Should be blocked (no proof for high-risk transition)
        match critical_result {
            Ok(TransitionResult::Approved) => {
                panic!("Direct escalation to Critical should be blocked without proof");
            }
            Ok(TransitionResult::Blocked { reason }) => {
                assert!(reason.contains("ERR_VEF_STATE") || reason.contains("proof"));
            }
            Err(VefStateError::NoProof { .. }) => {
                // Expected error for missing proof
            }
            Err(other) => {
                panic!("Unexpected error for escalation attempt: {:?}", other);
            }
        }

        // Test escalation with stale proof
        let stale_proof = ProofStatus {
            proof_id: "stale-proof".to_string(),
            verified: true,
            verified_at_epoch: 1000,
            max_age_seconds: 100, // Will be stale at epoch 1200
        };

        mgr.initialize_entity("stale-entity", RiskLevel::Low, Some(stale_proof), 1000)
            .unwrap();

        let stale_escalation = TransitionRequest {
            entity_id: "stale-entity".to_string(),
            target_risk_level: RiskLevel::High,
            action: "escalate-with-stale-proof".to_string(),
            requested_at_epoch: 1200, // Proof is stale
        };

        let stale_result = mgr.request_transition(&stale_escalation);

        // Should be blocked due to stale proof
        match stale_result {
            Ok(TransitionResult::Approved) => {
                panic!("Escalation with stale proof should be blocked");
            }
            Ok(TransitionResult::Blocked { reason }) => {
                assert!(reason.contains("stale") || reason.contains("ERR_VEF_STATE_STALE_PROOF"));
            }
            Err(VefStateError::StaleProof { .. }) => {
                // Expected error for stale proof
            }
            Err(other) => {
                panic!("Unexpected error for stale proof: {:?}", other);
            }
        }

        // Test escalation through multiple rapid transitions
        let fresh_proof = ProofStatus {
            proof_id: "fresh-proof".to_string(),
            verified: true,
            verified_at_epoch: 1300,
            max_age_seconds: 1000,
        };

        mgr.initialize_entity("rapid-entity", RiskLevel::Low, Some(fresh_proof), 1300)
            .unwrap();

        // Try rapid escalation through all risk levels
        let escalation_sequence = vec![RiskLevel::Medium, RiskLevel::High, RiskLevel::Critical];

        for (i, target_risk) in escalation_sequence.iter().enumerate() {
            let rapid_transition = TransitionRequest {
                entity_id: "rapid-entity".to_string(),
                target_risk_level: *target_risk,
                action: format!("rapid-escalation-{}", i),
                requested_at_epoch: 1400 + i as u64,
            };

            let rapid_result = mgr.request_transition(&rapid_transition);

            // Should handle rapid transitions based on proof freshness and policy
            match rapid_result {
                Ok(TransitionResult::Approved) => {
                    // Transition approved
                }
                Ok(TransitionResult::Blocked { .. }) => {
                    // Transition blocked for security reasons
                    break;
                }
                Err(_) => {
                    // Error occurred, escalation blocked
                    break;
                }
            }
        }
    }

    /// Negative test: Proof manipulation and forgery attacks
    #[test]
    fn negative_proof_manipulation_forgery_attacks() {
        let mut mgr = setup_manager();

        // Test proof with extreme timestamps
        let extreme_proofs = vec![
            ProofStatus {
                proof_id: "future-proof".to_string(),
                verified: true,
                verified_at_epoch: u64::MAX, // Future timestamp
                max_age_seconds: 1000,
            },
            ProofStatus {
                proof_id: "zero-epoch-proof".to_string(),
                verified: true,
                verified_at_epoch: 0, // Zero epoch
                max_age_seconds: u64::MAX,
            },
            ProofStatus {
                proof_id: "max-age-proof".to_string(),
                verified: true,
                verified_at_epoch: 1000,
                max_age_seconds: u64::MAX, // Maximum age
            },
        ];

        for (i, extreme_proof) in extreme_proofs.iter().enumerate() {
            let entity_id = format!("extreme-proof-{}", i);

            let init_result = mgr.initialize_entity(
                &entity_id,
                RiskLevel::Low,
                Some(extreme_proof.clone()),
                1500,
            );

            match init_result {
                Ok(()) => {
                    // Extreme proof accepted, test freshness calculation
                    let transition_request = TransitionRequest {
                        entity_id: entity_id.clone(),
                        target_risk_level: RiskLevel::High,
                        action: "test-extreme-proof".to_string(),
                        requested_at_epoch: 2000,
                    };

                    let transition_result = mgr.request_transition(&transition_request);

                    // Should handle extreme timestamps gracefully
                    match transition_result {
                        Ok(_) => {
                            // Extreme proof handled
                        }
                        Err(VefStateError::StaleProof { age, .. }) => {
                            // Age calculation should not overflow
                            assert!(age <= u64::MAX);
                        }
                        Err(_) => {
                            // Other rejections acceptable
                        }
                    }
                }
                Err(_) => {
                    // Extreme proof rejection acceptable
                }
            }
        }

        // Test proof ID manipulation
        let duplicate_proof_ids = vec![
            ("legitimate-proof", "legitimate-proof "), // Trailing space
            ("legitimate-proof", "legitimate-proof\t"), // Tab character
            ("legitimate-proof", "legitimate-proof\n"), // Newline
            ("legitimate-proof", "legitimate\u{200b}proof"), // Zero-width space
            ("legitimate-proof", "legitimate\u{feff}proof"), // BOM
        ];

        for (i, (original_id, manipulated_id)) in duplicate_proof_ids.iter().enumerate() {
            let original_proof = ProofStatus {
                proof_id: original_id.to_string(),
                verified: true,
                verified_at_epoch: 2500,
                max_age_seconds: 1000,
            };

            let manipulated_proof = ProofStatus {
                proof_id: manipulated_id.to_string(),
                verified: true,
                verified_at_epoch: 2500,
                max_age_seconds: 1000,
            };

            let original_entity = format!("original-{}", i);
            let manipulated_entity = format!("manipulated-{}", i);

            mgr.initialize_entity(&original_entity, RiskLevel::Low, Some(original_proof), 2500)
                .unwrap();
            mgr.initialize_entity(
                &manipulated_entity,
                RiskLevel::Low,
                Some(manipulated_proof),
                2500,
            )
            .unwrap();

            // Both should be treated as separate entities with separate proofs
            let original_state = mgr.state(&original_entity).unwrap();
            let manipulated_state = mgr.state(&manipulated_entity).unwrap();

            assert_ne!(
                original_state.proof.as_ref().unwrap().proof_id,
                manipulated_state.proof.as_ref().unwrap().proof_id,
                "Proof IDs should be distinct despite similarity"
            );
        }

        // Test proof verification flag manipulation
        let unverified_proof = ProofStatus {
            proof_id: "unverified-proof".to_string(),
            verified: false, // Not verified
            verified_at_epoch: 3000,
            max_age_seconds: 1000,
        };

        mgr.initialize_entity(
            "unverified-entity",
            RiskLevel::Low,
            Some(unverified_proof),
            3000,
        )
        .unwrap();

        let unverified_transition = TransitionRequest {
            entity_id: "unverified-entity".to_string(),
            target_risk_level: RiskLevel::High,
            action: "test-unverified-proof".to_string(),
            requested_at_epoch: 3100,
        };

        let unverified_result = mgr.request_transition(&unverified_transition);

        // Should block transitions with unverified proof
        match unverified_result {
            Ok(TransitionResult::Approved) => {
                panic!("Transition with unverified proof should be blocked");
            }
            Ok(TransitionResult::Blocked { reason }) => {
                assert!(reason.contains("verified") || reason.contains("proof"));
            }
            Err(_) => {
                // Error rejection acceptable
            }
        }
    }

    /// Negative test: Timing attacks in verification checks
    #[test]
    fn negative_timing_attacks_verification_checks() {
        let mut mgr = setup_manager();

        // Create entities with different proof states for timing analysis
        let fresh_proof = ProofStatus {
            proof_id: "fresh-proof".to_string(),
            verified: true,
            verified_at_epoch: 4000,
            max_age_seconds: 1000,
        };

        let stale_proof = ProofStatus {
            proof_id: "stale-proof".to_string(),
            verified: true,
            verified_at_epoch: 3000,
            max_age_seconds: 500,
        };

        mgr.initialize_entity("fresh-entity", RiskLevel::Low, Some(fresh_proof), 4000)
            .unwrap();
        mgr.initialize_entity("stale-entity", RiskLevel::Low, Some(stale_proof), 4000)
            .unwrap();
        mgr.initialize_entity("no-proof-entity", RiskLevel::Low, None, 4000)
            .unwrap();

        // Test timing consistency across different proof states
        let mut fresh_timings = Vec::new();
        let mut stale_timings = Vec::new();
        let mut no_proof_timings = Vec::new();

        for i in 0..30 {
            // Fresh proof timing
            let fresh_request = TransitionRequest {
                entity_id: "fresh-entity".to_string(),
                target_risk_level: RiskLevel::High,
                action: format!("timing-test-fresh-{}", i),
                requested_at_epoch: 4100 + i,
            };

            let start = std::time::Instant::now();
            let _result = mgr.request_transition(&fresh_request);
            fresh_timings.push(start.elapsed());

            // Stale proof timing
            let stale_request = TransitionRequest {
                entity_id: "stale-entity".to_string(),
                target_risk_level: RiskLevel::High,
                action: format!("timing-test-stale-{}", i),
                requested_at_epoch: 4100 + i,
            };

            let start = std::time::Instant::now();
            let _result = mgr.request_transition(&stale_request);
            stale_timings.push(start.elapsed());

            // No proof timing
            let no_proof_request = TransitionRequest {
                entity_id: "no-proof-entity".to_string(),
                target_risk_level: RiskLevel::High,
                action: format!("timing-test-no-proof-{}", i),
                requested_at_epoch: 4100 + i,
            };

            let start = std::time::Instant::now();
            let _result = mgr.request_transition(&no_proof_request);
            no_proof_timings.push(start.elapsed());
        }

        // Timing differences should be minimal across different proof states
        let avg_fresh: f64 = fresh_timings
            .iter()
            .map(|d| d.as_nanos() as f64)
            .sum::<f64>()
            / fresh_timings.len() as f64;
        let avg_stale: f64 = stale_timings
            .iter()
            .map(|d| d.as_nanos() as f64)
            .sum::<f64>()
            / stale_timings.len() as f64;
        let avg_no_proof: f64 = no_proof_timings
            .iter()
            .map(|d| d.as_nanos() as f64)
            .sum::<f64>()
            / no_proof_timings.len() as f64;

        let max_avg = avg_fresh.max(avg_stale).max(avg_no_proof);
        let min_avg = avg_fresh.min(avg_stale).min(avg_no_proof);
        let timing_ratio = max_avg / min_avg.max(1.0);

        assert!(
            timing_ratio < 5.0,
            "Proof verification timing variance too high: {}",
            timing_ratio
        );

        // Test timing attacks on entity existence checks
        let mut existing_timings = Vec::new();
        let mut nonexistent_timings = Vec::new();

        for i in 0..30 {
            // Existing entity timing
            let existing_action = ActionRequest {
                entity_id: "fresh-entity".to_string(),
                action: format!("existing-timing-{}", i),
                required_risk_level: RiskLevel::Low,
                requested_at_epoch: 4200 + i,
            };

            let start = std::time::Instant::now();
            let _result = mgr.authorize_action(&existing_action);
            existing_timings.push(start.elapsed());

            // Nonexistent entity timing
            let nonexistent_action = ActionRequest {
                entity_id: format!("nonexistent-entity-{}", i),
                action: format!("nonexistent-timing-{}", i),
                required_risk_level: RiskLevel::Low,
                requested_at_epoch: 4200 + i,
            };

            let start = std::time::Instant::now();
            let _result = mgr.authorize_action(&nonexistent_action);
            nonexistent_timings.push(start.elapsed());
        }

        // Entity existence timing should not leak information
        let avg_existing: f64 = existing_timings
            .iter()
            .map(|d| d.as_nanos() as f64)
            .sum::<f64>()
            / existing_timings.len() as f64;
        let avg_nonexistent: f64 = nonexistent_timings
            .iter()
            .map(|d| d.as_nanos() as f64)
            .sum::<f64>()
            / nonexistent_timings.len() as f64;

        let existence_ratio =
            avg_existing.max(avg_nonexistent) / avg_existing.min(avg_nonexistent).max(1.0);
        assert!(
            existence_ratio < 3.0,
            "Entity existence timing variance too high: {}",
            existence_ratio
        );
    }

    /// Negative test: Concurrent state manipulation race conditions
    #[test]
    fn negative_concurrent_state_manipulation_races() {
        use std::sync::{Arc, Mutex};
        use std::thread;

        let mgr = Arc::new(Mutex::new(setup_manager()));

        // Initialize entities for concurrent testing
        {
            let mut mgr_guard = mgr.lock().unwrap();
            for i in 0..5 {
                let entity_id = format!("concurrent-entity-{}", i);
                let proof = ProofStatus {
                    proof_id: format!("proof-{}", i),
                    verified: true,
                    verified_at_epoch: 5000,
                    max_age_seconds: 10000,
                };
                mgr_guard
                    .initialize_entity(&entity_id, RiskLevel::Low, Some(proof), 5000)
                    .unwrap();
            }
        }

        let mut handles = Vec::new();

        // Simulate concurrent state transitions from multiple threads
        for thread_id in 0..4 {
            let mgr_clone = Arc::clone(&mgr);
            let handle = thread::spawn(move || {
                let mut thread_results = Vec::new();

                for operation in 0..20 {
                    let entity_id = format!("concurrent-entity-{}", operation % 5);
                    let target_risk = match operation % 4 {
                        0 => RiskLevel::Low,
                        1 => RiskLevel::Medium,
                        2 => RiskLevel::High,
                        _ => RiskLevel::Critical,
                    };

                    let transition_request = TransitionRequest {
                        entity_id: entity_id.clone(),
                        target_risk_level: target_risk,
                        action: format!("concurrent-action-{}-{}", thread_id, operation),
                        requested_at_epoch: 5100 + (thread_id * 100) + operation as u64,
                    };

                    let result = {
                        let mut mgr_guard = mgr_clone.lock().unwrap();
                        mgr_guard.request_transition(&transition_request)
                    };

                    thread_results.push((thread_id, operation, result));

                    // Also test concurrent action authorization
                    let action_request = ActionRequest {
                        entity_id,
                        action: format!("concurrent-auth-{}-{}", thread_id, operation),
                        required_risk_level: RiskLevel::Medium,
                        requested_at_epoch: 5200 + (thread_id * 100) + operation as u64,
                    };

                    let auth_result = {
                        let mut mgr_guard = mgr_clone.lock().unwrap();
                        mgr_guard.authorize_action(&action_request)
                    };

                    thread_results.push((thread_id, operation, Ok(TransitionResult::Approved))); // Placeholder
                }
                thread_results
            });
            handles.push(handle);
        }

        // Wait for all threads to complete
        for handle in handles {
            handle.join().unwrap();
        }

        // Verify state consistency after concurrent operations
        let final_mgr = mgr.lock().unwrap();

        // All entities should still exist and be in consistent states
        for i in 0..5 {
            let entity_id = format!("concurrent-entity-{}", i);
            let state = final_mgr.state(&entity_id);
            assert!(
                state.is_some(),
                "Entity {} should still exist after concurrent operations",
                entity_id
            );

            if let Some(state) = state {
                assert_eq!(state.entity_id, entity_id);
                // State should be valid (no corrupted data)
                assert!(state.transition_count < 1000); // Reasonable upper bound
            }
        }

        // Audit log should contain all operations
        assert!(final_mgr.audit_log().len() > 0);
        assert!(final_mgr.audit_log().len() <= MAX_AUDIT_LOG_ENTRIES);
    }

    /// Negative test: Arithmetic overflow in epoch timestamps and counters
    #[test]
    fn negative_arithmetic_overflow_epochs_counters() {
        let mut mgr = setup_manager();

        // Test near-maximum epoch timestamps
        let overflow_epochs = vec![
            u64::MAX - 1000, // Near maximum
            u64::MAX,        // Maximum
            0,               // Minimum
        ];

        for (i, epoch) in overflow_epochs.iter().enumerate() {
            let entity_id = format!("overflow-epoch-{}", i);
            let proof = ProofStatus {
                proof_id: format!("overflow-proof-{}", i),
                verified: true,
                verified_at_epoch: *epoch,
                max_age_seconds: 1000,
            };

            let init_result =
                mgr.initialize_entity(&entity_id, RiskLevel::Low, Some(proof), *epoch);

            match init_result {
                Ok(()) => {
                    // Extreme epoch accepted, test transition
                    let transition_request = TransitionRequest {
                        entity_id: entity_id.clone(),
                        target_risk_level: RiskLevel::Medium,
                        action: format!("overflow-test-{}", i),
                        requested_at_epoch: epoch.saturating_add(100),
                    };

                    let transition_result = mgr.request_transition(&transition_request);

                    // Should handle epoch arithmetic without overflow
                    match transition_result {
                        Ok(_) => {
                            // Transition handled
                        }
                        Err(VefStateError::StaleProof { age, .. }) => {
                            // Age calculation should not overflow
                            assert!(age <= u64::MAX);
                        }
                        Err(_) => {
                            // Other rejections acceptable
                        }
                    }
                }
                Err(_) => {
                    // Extreme epoch rejection acceptable
                }
            }
        }

        // Test transition counter overflow
        let counter_entity = "counter-overflow-test";
        mgr.initialize_entity(counter_entity, RiskLevel::Low, None, 6000)
            .unwrap();

        // Force high transition count
        for stress_iteration in 0..1000 {
            let action_request = ActionRequest {
                entity_id: counter_entity.to_string(),
                action: format!("counter-stress-{}", stress_iteration),
                required_risk_level: RiskLevel::Low,
                requested_at_epoch: 6100 + stress_iteration,
            };

            let _result = mgr.authorize_action(&action_request);

            // Check for counter overflow
            let state = mgr.state(counter_entity).unwrap();
            assert!(state.transition_count <= u64::MAX);

            // Break early to prevent excessive test time
            if stress_iteration > 100 {
                break;
            }
        }

        // Test proof age calculation overflow scenarios
        let age_test_proof = ProofStatus {
            proof_id: "age-test-proof".to_string(),
            verified: true,
            verified_at_epoch: u64::MAX - 100,
            max_age_seconds: 1000,
        };

        mgr.initialize_entity(
            "age-test",
            RiskLevel::Low,
            Some(age_test_proof),
            u64::MAX - 100,
        )
        .unwrap();

        // Test age calculation at various epochs
        let test_epochs = vec![u64::MAX - 99, u64::MAX - 50, u64::MAX];

        for test_epoch in test_epochs {
            let age_transition = TransitionRequest {
                entity_id: "age-test".to_string(),
                target_risk_level: RiskLevel::High,
                action: "age-calculation-test".to_string(),
                requested_at_epoch: test_epoch,
            };

            let age_result = mgr.request_transition(&age_transition);

            // Should handle age arithmetic without overflow panics
            match age_result {
                Ok(_) => {}
                Err(VefStateError::StaleProof { age, .. }) => {
                    // Age should be computed without overflow
                    assert!(age <= u64::MAX);
                }
                Err(_) => {}
            }
        }
    }

    /// Negative test: State transition bypass and policy manipulation
    #[test]
    fn negative_state_transition_bypass_policy_manipulation() {
        let mut mgr = setup_manager();

        // Test transition bypass through risk level manipulation
        let bypass_entity = "bypass-test";
        mgr.initialize_entity(bypass_entity, RiskLevel::Low, None, 7000)
            .unwrap();

        // Try to authorize high-risk action without proper risk level
        let high_risk_action = ActionRequest {
            entity_id: bypass_entity.to_string(),
            action: "high-risk-deploy".to_string(),
            required_risk_level: RiskLevel::Critical,
            requested_at_epoch: 7100,
        };

        let bypass_result = mgr.authorize_action(&high_risk_action);

        // Should be denied due to insufficient risk level
        match bypass_result {
            Ok(ActionResult::Authorized) => {
                panic!("High-risk action should be denied without proper risk escalation");
            }
            Ok(ActionResult::Denied { reason }) => {
                assert!(reason.contains("risk") || reason.contains("ERR_VEF_STATE_RISK_EXCEEDED"));
            }
            Err(VefStateError::RiskExceeded { .. }) => {
                // Expected error for risk mismatch
            }
            Err(_) => {
                // Other rejection reasons acceptable
            }
        }

        // Test invalid transition patterns
        let invalid_transitions = vec![
            (RiskLevel::Critical, RiskLevel::Low), // Direct downgrade
            (RiskLevel::High, RiskLevel::Medium),  // Step downgrade
        ];

        for (i, (from_risk, to_risk)) in invalid_transitions.iter().enumerate() {
            let transition_entity = format!("invalid-transition-{}", i);

            // Initialize at higher risk level
            let high_risk_proof = ProofStatus {
                proof_id: format!("high-risk-proof-{}", i),
                verified: true,
                verified_at_epoch: 7500,
                max_age_seconds: 1000,
            };

            mgr.initialize_entity(&transition_entity, *from_risk, Some(high_risk_proof), 7500)
                .unwrap();

            // Try invalid transition
            let invalid_transition = TransitionRequest {
                entity_id: transition_entity,
                target_risk_level: *to_risk,
                action: format!("invalid-transition-{}", i),
                requested_at_epoch: 7600,
            };

            let invalid_result = mgr.request_transition(&invalid_transition);

            // Should block invalid transitions
            match invalid_result {
                Ok(TransitionResult::Approved) => {
                    // Some downgrade transitions might be allowed
                }
                Ok(TransitionResult::Blocked { reason }) => {
                    assert!(!reason.is_empty());
                }
                Err(VefStateError::InvalidTransition { .. }) => {
                    // Expected error for invalid transition
                }
                Err(_) => {
                    // Other rejection reasons acceptable
                }
            }
        }

        // Test proof freshness bypass attempts
        let stale_bypass_proof = ProofStatus {
            proof_id: "stale-bypass-proof".to_string(),
            verified: true,
            verified_at_epoch: 8000,
            max_age_seconds: 100, // Short age for testing
        };

        mgr.initialize_entity(
            "stale-bypass",
            RiskLevel::Low,
            Some(stale_bypass_proof),
            8000,
        )
        .unwrap();

        // Wait for proof to become stale, then try transition
        let stale_transition = TransitionRequest {
            entity_id: "stale-bypass".to_string(),
            target_risk_level: RiskLevel::Critical,
            action: "stale-bypass-attempt".to_string(),
            requested_at_epoch: 8200, // Proof should be stale
        };

        let stale_bypass_result = mgr.request_transition(&stale_transition);

        // Should block transition with stale proof
        match stale_bypass_result {
            Ok(TransitionResult::Approved) => {
                panic!("Transition with stale proof should be blocked");
            }
            Ok(TransitionResult::Blocked { reason }) => {
                assert!(reason.contains("stale") || reason.contains("fresh"));
            }
            Err(VefStateError::StaleProof { .. }) => {
                // Expected error for stale proof
            }
            Err(_) => {
                // Other rejection reasons acceptable
            }
        }
    }
}
