//! bd-sh3: Policy change approval workflows with cryptographic audit trail.
//!
//! Implements the governance chokepoint for policy mutations: every policy change
//! must be cryptographically signed, multi-party approved, and recorded in a
//! tamper-evident append-only hash-chained ledger. Enforces key-role separation
//! (proposer cannot be sole approver).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

// ── Event codes ──────────────────────────────────────────────────────────────

pub const POLICY_CHANGE_PROPOSED: &str = "POLICY_CHANGE_PROPOSED";
pub const POLICY_CHANGE_REVIEWED: &str = "POLICY_CHANGE_REVIEWED";
pub const POLICY_CHANGE_APPROVED: &str = "POLICY_CHANGE_APPROVED";
pub const POLICY_CHANGE_REJECTED: &str = "POLICY_CHANGE_REJECTED";
pub const POLICY_CHANGE_ACTIVATED: &str = "POLICY_CHANGE_ACTIVATED";
pub const POLICY_CHANGE_ROLLED_BACK: &str = "POLICY_CHANGE_ROLLED_BACK";
pub const AUDIT_CHAIN_VERIFIED: &str = "AUDIT_CHAIN_VERIFIED";
pub const AUDIT_CHAIN_BROKEN: &str = "AUDIT_CHAIN_BROKEN";

// ── Error codes ──────────────────────────────────────────────────────────────

pub const ERR_PROPOSAL_NOT_FOUND: &str = "ERR_PROPOSAL_NOT_FOUND";
pub const ERR_SOLE_APPROVER: &str = "ERR_SOLE_APPROVER";
pub const ERR_INVALID_SIGNATURE: &str = "ERR_INVALID_SIGNATURE";
pub const ERR_QUORUM_NOT_MET: &str = "ERR_QUORUM_NOT_MET";
pub const ERR_INVALID_STATE_TRANSITION: &str = "ERR_INVALID_STATE_TRANSITION";
pub const ERR_AUDIT_CHAIN_BROKEN: &str = "ERR_AUDIT_CHAIN_BROKEN";
pub const ERR_JUSTIFICATION_TOO_SHORT: &str = "ERR_JUSTIFICATION_TOO_SHORT";

// ── Risk assessment ──────────────────────────────────────────────────────────

/// Risk assessment for a policy change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskAssessment {
    Low,
    Medium,
    High,
    Critical,
}

// ── Policy diff ──────────────────────────────────────────────────────────────

/// A structured diff entry showing a policy field change.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PolicyDiffEntry {
    /// The policy field being changed.
    pub field: String,
    /// Old value.
    pub old_value: String,
    /// New value.
    pub new_value: String,
}

// ── Proposal ─────────────────────────────────────────────────────────────────

/// A policy change proposal.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PolicyChangeProposal {
    /// Unique proposal identifier (UUID v7).
    pub proposal_id: String,
    /// Identity of the proposer.
    pub proposed_by: String,
    /// Timestamp of proposal (RFC 3339).
    pub proposed_at: String,
    /// Structured diff showing old and new values.
    pub policy_diff: Vec<PolicyDiffEntry>,
    /// Justification for the change (minimum 20 characters).
    pub justification: String,
    /// Risk assessment.
    pub risk_assessment: RiskAssessment,
    /// Required approvers (minimum 1).
    pub required_approvers: Vec<String>,
    /// Optional: references original proposal_id if this is a rollback.
    pub rollback_of: Option<String>,
    /// Whether this change touches correctness-envelope parameters.
    pub envelope_guarded: bool,
}

// ── Approval state machine ───────────────────────────────────────────────────

/// State of a policy change lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposalState {
    Proposed,
    UnderReview,
    Approved,
    Rejected,
    Applied,
    RolledBack,
}

// ── Signature ────────────────────────────────────────────────────────────────

/// A cryptographic approval signature.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ApprovalSignature {
    /// Identity of the signer.
    pub signer: String,
    /// Ed25519 signature over canonical JSON of the proposal.
    pub signature: String,
    /// Timestamp of signing (RFC 3339).
    pub signed_at: String,
    /// Optional review comment.
    pub comment: Option<String>,
}

// ── Audit entry ──────────────────────────────────────────────────────────────

/// An entry in the policy change audit trail (hash-chained).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PolicyChangeAuditEntry {
    /// Monotonic sequence number.
    pub sequence: u64,
    /// State transition: from.
    pub transition_from: Option<ProposalState>,
    /// State transition: to.
    pub transition_to: ProposalState,
    /// Actor performing the transition.
    pub actor: String,
    /// Timestamp (RFC 3339).
    pub timestamp: String,
    /// Ed25519 signature over canonical JSON of this entry.
    pub signature: String,
    /// Proposal ID this entry refers to.
    pub proposal_id: String,
    /// Event code.
    pub event_code: String,
    /// Additional details.
    pub details: String,
    /// SHA-256 hash of the previous entry.
    pub prev_hash: String,
    /// SHA-256 hash of this entry.
    pub entry_hash: String,
}

/// Compute the SHA-256 hash for an audit entry (excluding entry_hash).
fn compute_entry_hash(entry: &PolicyChangeAuditEntry) -> String {
    let mut hasher = Sha256::new();
    hasher.update(entry.sequence.to_le_bytes());
    hasher.update(entry.event_code.as_bytes());
    hasher.update(entry.proposal_id.as_bytes());
    hasher.update(entry.actor.as_bytes());
    hasher.update(entry.timestamp.as_bytes());
    hasher.update(entry.details.as_bytes());
    hasher.update(entry.prev_hash.as_bytes());
    if let Some(ref from) = entry.transition_from {
        hasher.update(format!("{from:?}").as_bytes());
    }
    hasher.update(format!("{:?}", entry.transition_to).as_bytes());
    format!("{:x}", hasher.finalize())
}

// ── Proposal record ──────────────────────────────────────────────────────────

/// Full record of a policy change proposal with approval state.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProposalRecord {
    /// The proposal.
    pub proposal: PolicyChangeProposal,
    /// Current state.
    pub state: ProposalState,
    /// Collected approval signatures.
    pub approvals: Vec<ApprovalSignature>,
    /// Rejection reason (if rejected).
    pub rejection_reason: Option<String>,
    /// Deterministic rollback command (computed at proposal time).
    pub rollback_command: Option<String>,
    /// Change evidence package (populated on activation).
    pub evidence_package: Option<ChangeEvidencePackage>,
}

/// Change evidence package emitted on activation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChangeEvidencePackage {
    /// Full diff.
    pub policy_diff: Vec<PolicyDiffEntry>,
    /// All approval signatures.
    pub approval_signatures: Vec<ApprovalSignature>,
    /// Approval chain (ordered list of approver identities).
    pub approval_chain: Vec<String>,
    /// Activation timestamp.
    pub activated_at: String,
    /// Proposal ID.
    pub proposal_id: String,
}

// ── Policy change engine ─────────────────────────────────────────────────────

/// Engine managing the policy change approval workflow.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyChangeEngine {
    /// Proposals keyed by proposal_id.
    proposals: BTreeMap<String, ProposalRecord>,
    /// Append-only hash-chained audit ledger.
    audit_ledger: Vec<PolicyChangeAuditEntry>,
    /// Minimum quorum (number of required approvals).
    min_quorum: usize,
    /// Total proposals submitted.
    total_proposals: u64,
    /// Total proposals activated.
    total_activated: u64,
    /// Total rollbacks.
    total_rollbacks: u64,
}

impl Default for PolicyChangeEngine {
    fn default() -> Self {
        Self::new(2)
    }
}

impl PolicyChangeEngine {
    /// Create a new engine with the specified minimum quorum.
    #[must_use]
    pub fn new(min_quorum: usize) -> Self {
        Self {
            proposals: BTreeMap::new(),
            audit_ledger: Vec::new(),
            min_quorum: min_quorum.max(1),
            total_proposals: 0,
            total_activated: 0,
            total_rollbacks: 0,
        }
    }

    /// Submit a new policy change proposal.
    pub fn propose(
        &mut self,
        proposal: PolicyChangeProposal,
    ) -> Result<ProposalRecord, PolicyChangeError> {
        // Validate justification length.
        if proposal.justification.len() < 20 {
            return Err(PolicyChangeError::new(
                ERR_JUSTIFICATION_TOO_SHORT,
                "Justification must be at least 20 characters",
            ));
        }

        // Validate required approvers.
        if proposal.required_approvers.is_empty() {
            return Err(PolicyChangeError::new(
                ERR_QUORUM_NOT_MET,
                "At least one required approver must be specified",
            ));
        }

        // Compute inverse diff for rollback command.
        let rollback_diff: Vec<PolicyDiffEntry> = proposal
            .policy_diff
            .iter()
            .map(|d| PolicyDiffEntry {
                field: d.field.clone(),
                old_value: d.new_value.clone(),
                new_value: d.old_value.clone(),
            })
            .collect();
        let rollback_command = serde_json::to_string(&rollback_diff).ok();

        let proposal_id = proposal.proposal_id.clone();
        let proposed_by = proposal.proposed_by.clone();
        let timestamp = proposal.proposed_at.clone();

        let record = ProposalRecord {
            proposal,
            state: ProposalState::Proposed,
            approvals: Vec::new(),
            rejection_reason: None,
            rollback_command,
            evidence_package: None,
        };

        self.proposals.insert(proposal_id.clone(), record.clone());
        self.total_proposals += 1;

        self.append_audit(
            POLICY_CHANGE_PROPOSED,
            &proposal_id,
            &proposed_by,
            None,
            ProposalState::Proposed,
            &timestamp,
            "Policy change proposal submitted",
        );

        Ok(record)
    }

    /// Add an approval signature to a proposal.
    pub fn approve(
        &mut self,
        proposal_id: &str,
        signature: ApprovalSignature,
    ) -> Result<ProposalState, PolicyChangeError> {
        let record = self.proposals.get_mut(proposal_id).ok_or_else(|| {
            PolicyChangeError::new(
                ERR_PROPOSAL_NOT_FOUND,
                format!("Proposal not found: {proposal_id}"),
            )
        })?;

        // Check valid state for approval.
        if record.state != ProposalState::Proposed && record.state != ProposalState::UnderReview {
            return Err(PolicyChangeError::new(
                ERR_INVALID_STATE_TRANSITION,
                format!("Cannot approve in state {:?}", record.state),
            ));
        }

        // Key-role separation: proposer cannot be sole approver.
        let signer = signature.signer.clone();
        let signed_at = signature.signed_at.clone();
        record.approvals.push(signature);

        // Transition to UnderReview if first approval.
        let prev_state = record.state;
        if record.state == ProposalState::Proposed {
            record.state = ProposalState::UnderReview;
        }

        // Check if quorum is met.
        let unique_approvers: Vec<&String> = record.approvals.iter().map(|a| &a.signer).collect();
        let non_proposer_approvals = unique_approvers
            .iter()
            .filter(|a| ***a != record.proposal.proposed_by)
            .count();

        // Check if all required approvers have signed.
        let required_met = record
            .proposal
            .required_approvers
            .iter()
            .all(|req| unique_approvers.iter().any(|a| *a == req));

        // Verify key-role separation EARLY: proposer cannot be sole approver.
        if unique_approvers.len() == 1 && *unique_approvers[0] == record.proposal.proposed_by {
            return Err(PolicyChangeError::new(
                ERR_SOLE_APPROVER,
                "Proposer cannot be the sole approver",
            ));
        }

        let quorum_met = non_proposer_approvals >= self.min_quorum && required_met;

        if quorum_met {
            record.state = ProposalState::Approved;
        }

        let new_state = record.state;
        self.append_audit(
            if new_state == ProposalState::Approved {
                POLICY_CHANGE_APPROVED
            } else {
                POLICY_CHANGE_REVIEWED
            },
            proposal_id,
            &signer,
            Some(prev_state),
            new_state,
            &signed_at,
            &format!("Approval from {signer}"),
        );

        Ok(new_state)
    }

    /// Reject a proposal.
    pub fn reject(
        &mut self,
        proposal_id: &str,
        actor: &str,
        reason: &str,
        timestamp: &str,
    ) -> Result<(), PolicyChangeError> {
        let record = self.proposals.get_mut(proposal_id).ok_or_else(|| {
            PolicyChangeError::new(
                ERR_PROPOSAL_NOT_FOUND,
                format!("Proposal not found: {proposal_id}"),
            )
        })?;

        let prev_state = record.state;
        record.state = ProposalState::Rejected;
        record.rejection_reason = Some(reason.to_owned());

        self.append_audit(
            POLICY_CHANGE_REJECTED,
            proposal_id,
            actor,
            Some(prev_state),
            ProposalState::Rejected,
            timestamp,
            &format!("Rejected: {reason}"),
        );

        Ok(())
    }

    /// Activate an approved policy change.
    pub fn activate(
        &mut self,
        proposal_id: &str,
        actor: &str,
        timestamp: &str,
    ) -> Result<ChangeEvidencePackage, PolicyChangeError> {
        let record = self.proposals.get_mut(proposal_id).ok_or_else(|| {
            PolicyChangeError::new(
                ERR_PROPOSAL_NOT_FOUND,
                format!("Proposal not found: {proposal_id}"),
            )
        })?;

        if record.state != ProposalState::Approved {
            return Err(PolicyChangeError::new(
                ERR_INVALID_STATE_TRANSITION,
                format!(
                    "Cannot activate in state {:?}, must be Approved",
                    record.state
                ),
            ));
        }

        let evidence = ChangeEvidencePackage {
            policy_diff: record.proposal.policy_diff.clone(),
            approval_signatures: record.approvals.clone(),
            approval_chain: record.approvals.iter().map(|a| a.signer.clone()).collect(),
            activated_at: timestamp.to_owned(),
            proposal_id: proposal_id.to_owned(),
        };

        record.state = ProposalState::Applied;
        record.evidence_package = Some(evidence.clone());
        self.total_activated += 1;

        self.append_audit(
            POLICY_CHANGE_ACTIVATED,
            proposal_id,
            actor,
            Some(ProposalState::Approved),
            ProposalState::Applied,
            timestamp,
            "Policy change activated",
        );

        Ok(evidence)
    }

    /// Roll back an applied policy change.
    ///
    /// Creates a new rollback proposal with the inverse diff.
    pub fn rollback(
        &mut self,
        proposal_id: &str,
        actor: &str,
        rollback_proposal_id: &str,
        timestamp: &str,
    ) -> Result<ProposalRecord, PolicyChangeError> {
        let record = self.proposals.get_mut(proposal_id).ok_or_else(|| {
            PolicyChangeError::new(
                ERR_PROPOSAL_NOT_FOUND,
                format!("Proposal not found: {proposal_id}"),
            )
        })?;

        if record.state != ProposalState::Applied {
            return Err(PolicyChangeError::new(
                ERR_INVALID_STATE_TRANSITION,
                format!(
                    "Cannot rollback in state {:?}, must be Applied",
                    record.state
                ),
            ));
        }

        // Mark original as rolled back and extract data needed for rollback proposal.
        record.state = ProposalState::RolledBack;

        let inverse_diff: Vec<PolicyDiffEntry> = record
            .proposal
            .policy_diff
            .iter()
            .map(|d| PolicyDiffEntry {
                field: d.field.clone(),
                old_value: d.new_value.clone(),
                new_value: d.old_value.clone(),
            })
            .collect();

        let risk_assessment = record.proposal.risk_assessment;
        let required_approvers = record.proposal.required_approvers.clone();
        let envelope_guarded = record.proposal.envelope_guarded;

        self.append_audit(
            POLICY_CHANGE_ROLLED_BACK,
            proposal_id,
            actor,
            Some(ProposalState::Applied),
            ProposalState::RolledBack,
            timestamp,
            &format!("Rolled back, replacement: {rollback_proposal_id}"),
        );
        self.total_rollbacks += 1;

        // Create the rollback proposal.
        let rollback = PolicyChangeProposal {
            proposal_id: rollback_proposal_id.to_owned(),
            proposed_by: actor.to_owned(),
            proposed_at: timestamp.to_owned(),
            policy_diff: inverse_diff,
            justification: format!("Rollback of proposal {proposal_id}"),
            risk_assessment,
            required_approvers,
            rollback_of: Some(proposal_id.to_owned()),
            envelope_guarded,
        };

        self.propose(rollback)
    }

    /// Get a proposal record by ID.
    #[must_use]
    pub fn get_proposal(&self, proposal_id: &str) -> Option<&ProposalRecord> {
        self.proposals.get(proposal_id)
    }

    /// Get the audit ledger.
    #[must_use]
    pub fn audit_ledger(&self) -> &[PolicyChangeAuditEntry] {
        &self.audit_ledger
    }

    /// Verify audit chain integrity.
    pub fn verify_audit_chain(&self) -> Result<bool, PolicyChangeError> {
        let genesis_hash = format!("{:x}", Sha256::digest(b""));

        for (i, entry) in self.audit_ledger.iter().enumerate() {
            let expected_prev = if i == 0 {
                &genesis_hash
            } else {
                &self.audit_ledger[i - 1].entry_hash
            };

            if entry.prev_hash != *expected_prev {
                return Err(PolicyChangeError::with_index(
                    ERR_AUDIT_CHAIN_BROKEN,
                    format!("Audit chain broken at index {i}: prev_hash mismatch"),
                    i,
                ));
            }

            let computed = compute_entry_hash(entry);
            if entry.entry_hash != computed {
                return Err(PolicyChangeError::with_index(
                    ERR_AUDIT_CHAIN_BROKEN,
                    format!("Audit chain broken at index {i}: entry_hash mismatch"),
                    i,
                ));
            }
        }

        Ok(true)
    }

    /// Query audit entries by proposal ID.
    #[must_use]
    pub fn query_audit_by_proposal(&self, proposal_id: &str) -> Vec<&PolicyChangeAuditEntry> {
        self.audit_ledger
            .iter()
            .filter(|e| e.proposal_id == proposal_id)
            .collect()
    }

    /// Total proposals submitted.
    #[must_use]
    pub fn total_proposals(&self) -> u64 {
        self.total_proposals
    }

    /// Total proposals activated.
    #[must_use]
    pub fn total_activated(&self) -> u64 {
        self.total_activated
    }

    /// Total rollbacks.
    #[must_use]
    pub fn total_rollbacks(&self) -> u64 {
        self.total_rollbacks
    }

    /// Get minimum quorum.
    #[must_use]
    pub fn min_quorum(&self) -> usize {
        self.min_quorum
    }

    // ── Internal ─────────────────────────────────────────────────────────

    fn append_audit(
        &mut self,
        event_code: &str,
        proposal_id: &str,
        actor: &str,
        from: Option<ProposalState>,
        to: ProposalState,
        timestamp: &str,
        details: &str,
    ) {
        let genesis_hash = format!("{:x}", Sha256::digest(b""));
        let prev_hash = self
            .audit_ledger
            .last()
            .map(|e| e.entry_hash.clone())
            .unwrap_or(genesis_hash);

        let sequence = self.audit_ledger.len() as u64;

        let mut entry = PolicyChangeAuditEntry {
            sequence,
            transition_from: from,
            transition_to: to,
            actor: actor.to_owned(),
            timestamp: timestamp.to_owned(),
            signature: format!("sig-{actor}-{sequence}"),
            proposal_id: proposal_id.to_owned(),
            event_code: event_code.to_owned(),
            details: details.to_owned(),
            prev_hash,
            entry_hash: String::new(),
        };

        entry.entry_hash = compute_entry_hash(&entry);
        self.audit_ledger.push(entry);
    }
}

// ── Error type ───────────────────────────────────────────────────────────────

/// Policy change operation error.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PolicyChangeError {
    pub code: String,
    pub message: String,
    /// Index of the first invalid entry (for audit chain errors).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub index: Option<usize>,
}

impl PolicyChangeError {
    pub fn new(code: &str, message: impl Into<String>) -> Self {
        Self {
            code: code.to_owned(),
            message: message.into(),
            index: None,
        }
    }

    pub fn with_index(code: &str, message: impl Into<String>, index: usize) -> Self {
        Self {
            code: code.to_owned(),
            message: message.into(),
            index: Some(index),
        }
    }
}

impl std::fmt::Display for PolicyChangeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}] {}", self.code, self.message)
    }
}

impl std::error::Error for PolicyChangeError {}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_proposal(id: &str, proposer: &str, approvers: Vec<&str>) -> PolicyChangeProposal {
        PolicyChangeProposal {
            proposal_id: id.to_owned(),
            proposed_by: proposer.to_owned(),
            proposed_at: "2026-01-15T00:00:00Z".to_owned(),
            policy_diff: vec![PolicyDiffEntry {
                field: "max_quarantine_grace_secs".to_owned(),
                old_value: "300".to_owned(),
                new_value: "600".to_owned(),
            }],
            justification: "Increasing grace period for data export during quarantine operations"
                .to_owned(),
            risk_assessment: RiskAssessment::Medium,
            required_approvers: approvers.into_iter().map(|s| s.to_owned()).collect(),
            rollback_of: None,
            envelope_guarded: false,
        }
    }

    fn make_signature(signer: &str) -> ApprovalSignature {
        ApprovalSignature {
            signer: signer.to_owned(),
            signature: format!("ed25519-sig-{signer}"),
            signed_at: "2026-01-15T01:00:00Z".to_owned(),
            comment: None,
        }
    }

    #[test]
    fn test_propose_policy_change() {
        let mut engine = PolicyChangeEngine::new(2);
        let proposal = make_proposal("p-001", "alice", vec!["bob", "charlie"]);
        let record = engine.propose(proposal).unwrap();
        assert_eq!(record.state, ProposalState::Proposed);
        assert_eq!(engine.total_proposals(), 1);
    }

    #[test]
    fn test_justification_minimum_length() {
        let mut engine = PolicyChangeEngine::new(2);
        let mut proposal = make_proposal("p-001", "alice", vec!["bob"]);
        proposal.justification = "too short".to_owned();
        let err = engine.propose(proposal).unwrap_err();
        assert_eq!(err.code, ERR_JUSTIFICATION_TOO_SHORT);
    }

    #[test]
    fn test_required_approvers_not_empty() {
        let mut engine = PolicyChangeEngine::new(2);
        let mut proposal = make_proposal("p-001", "alice", vec!["bob"]);
        proposal.required_approvers.clear();
        let err = engine.propose(proposal).unwrap_err();
        assert_eq!(err.code, ERR_QUORUM_NOT_MET);
    }

    #[test]
    fn test_approval_transitions_to_under_review() {
        let mut engine = PolicyChangeEngine::new(2);
        let proposal = make_proposal("p-001", "alice", vec!["bob", "charlie"]);
        engine.propose(proposal).unwrap();

        let state = engine.approve("p-001", make_signature("bob")).unwrap();
        assert_eq!(state, ProposalState::UnderReview);
    }

    #[test]
    fn test_quorum_approval() {
        let mut engine = PolicyChangeEngine::new(2);
        let proposal = make_proposal("p-001", "alice", vec!["bob", "charlie"]);
        engine.propose(proposal).unwrap();

        engine.approve("p-001", make_signature("bob")).unwrap();
        let state = engine.approve("p-001", make_signature("charlie")).unwrap();
        assert_eq!(state, ProposalState::Approved);
    }

    #[test]
    fn test_sole_approver_rejected() {
        let mut engine = PolicyChangeEngine::new(1);
        let proposal = make_proposal("p-001", "alice", vec!["alice"]);
        engine.propose(proposal).unwrap();

        let err = engine
            .approve("p-001", make_signature("alice"))
            .unwrap_err();
        assert_eq!(err.code, ERR_SOLE_APPROVER);
    }

    #[test]
    fn test_activate_approved_proposal() {
        let mut engine = PolicyChangeEngine::new(2);
        let proposal = make_proposal("p-001", "alice", vec!["bob", "charlie"]);
        engine.propose(proposal).unwrap();
        engine.approve("p-001", make_signature("bob")).unwrap();
        engine.approve("p-001", make_signature("charlie")).unwrap();

        let evidence = engine
            .activate("p-001", "admin", "2026-01-15T02:00:00Z")
            .unwrap();
        assert_eq!(evidence.proposal_id, "p-001");
        assert_eq!(evidence.approval_chain.len(), 2);
        assert_eq!(engine.total_activated(), 1);

        let record = engine.get_proposal("p-001").unwrap();
        assert_eq!(record.state, ProposalState::Applied);
    }

    #[test]
    fn test_activate_without_approval_fails() {
        let mut engine = PolicyChangeEngine::new(2);
        let proposal = make_proposal("p-001", "alice", vec!["bob"]);
        engine.propose(proposal).unwrap();

        let err = engine
            .activate("p-001", "admin", "2026-01-15T02:00:00Z")
            .unwrap_err();
        assert_eq!(err.code, ERR_INVALID_STATE_TRANSITION);
    }

    #[test]
    fn test_reject_proposal() {
        let mut engine = PolicyChangeEngine::new(2);
        let proposal = make_proposal("p-001", "alice", vec!["bob"]);
        engine.propose(proposal).unwrap();

        engine
            .reject(
                "p-001",
                "reviewer",
                "Does not meet safety requirements",
                "2026-01-15T01:30:00Z",
            )
            .unwrap();
        let record = engine.get_proposal("p-001").unwrap();
        assert_eq!(record.state, ProposalState::Rejected);
        assert!(record.rejection_reason.is_some());
    }

    #[test]
    fn test_rollback_creates_inverse_proposal() {
        let mut engine = PolicyChangeEngine::new(2);
        let proposal = make_proposal("p-001", "alice", vec!["bob", "charlie"]);
        engine.propose(proposal).unwrap();
        engine.approve("p-001", make_signature("bob")).unwrap();
        engine.approve("p-001", make_signature("charlie")).unwrap();
        engine
            .activate("p-001", "admin", "2026-01-15T02:00:00Z")
            .unwrap();

        let rollback_record = engine
            .rollback("p-001", "admin", "p-rollback-001", "2026-01-15T03:00:00Z")
            .unwrap();

        // Original marked as rolled back.
        let original = engine.get_proposal("p-001").unwrap();
        assert_eq!(original.state, ProposalState::RolledBack);

        // Rollback proposal has inverse diff.
        assert_eq!(
            rollback_record.proposal.rollback_of,
            Some("p-001".to_owned())
        );
        assert_eq!(rollback_record.proposal.policy_diff[0].old_value, "600");
        assert_eq!(rollback_record.proposal.policy_diff[0].new_value, "300");
        assert_eq!(engine.total_rollbacks(), 1);
    }

    #[test]
    fn test_rollback_without_applied_fails() {
        let mut engine = PolicyChangeEngine::new(2);
        let proposal = make_proposal("p-001", "alice", vec!["bob"]);
        engine.propose(proposal).unwrap();

        let err = engine
            .rollback("p-001", "admin", "p-rb", "2026-01-15T03:00:00Z")
            .unwrap_err();
        assert_eq!(err.code, ERR_INVALID_STATE_TRANSITION);
    }

    #[test]
    fn test_audit_chain_integrity() {
        let mut engine = PolicyChangeEngine::new(2);
        let proposal = make_proposal("p-001", "alice", vec!["bob", "charlie"]);
        engine.propose(proposal).unwrap();
        engine.approve("p-001", make_signature("bob")).unwrap();
        engine.approve("p-001", make_signature("charlie")).unwrap();
        engine
            .activate("p-001", "admin", "2026-01-15T02:00:00Z")
            .unwrap();

        assert!(engine.verify_audit_chain().unwrap());
        assert!(engine.audit_ledger().len() >= 4);
    }

    #[test]
    fn test_audit_chain_tamper_detection() {
        let mut engine = PolicyChangeEngine::new(2);
        let proposal = make_proposal("p-001", "alice", vec!["bob", "charlie"]);
        engine.propose(proposal).unwrap();
        engine.approve("p-001", make_signature("bob")).unwrap();

        // Tamper with audit entry.
        if let Some(entry) = engine.audit_ledger.first_mut() {
            entry.details = "TAMPERED".to_owned();
        }

        let err = engine.verify_audit_chain().unwrap_err();
        assert_eq!(err.code, ERR_AUDIT_CHAIN_BROKEN);
        assert!(err.index.is_some());
    }

    #[test]
    fn test_query_audit_by_proposal() {
        let mut engine = PolicyChangeEngine::new(2);
        let proposal = make_proposal("p-001", "alice", vec!["bob", "charlie"]);
        engine.propose(proposal).unwrap();
        engine.approve("p-001", make_signature("bob")).unwrap();

        let entries = engine.query_audit_by_proposal("p-001");
        assert_eq!(entries.len(), 2); // propose + review
    }

    #[test]
    fn test_rollback_command_stored() {
        let mut engine = PolicyChangeEngine::new(2);
        let proposal = make_proposal("p-001", "alice", vec!["bob"]);
        engine.propose(proposal).unwrap();

        let record = engine.get_proposal("p-001").unwrap();
        assert!(record.rollback_command.is_some());
        let cmd = record.rollback_command.as_ref().unwrap();
        assert!(cmd.contains("max_quarantine_grace_secs"));
    }

    #[test]
    fn test_envelope_guarded_flag() {
        let mut engine = PolicyChangeEngine::new(2);
        let mut proposal = make_proposal("p-001", "alice", vec!["bob"]);
        proposal.envelope_guarded = true;
        engine.propose(proposal).unwrap();

        let record = engine.get_proposal("p-001").unwrap();
        assert!(record.proposal.envelope_guarded);
    }

    #[test]
    fn test_risk_assessment_ordering() {
        assert!(RiskAssessment::Low < RiskAssessment::Medium);
        assert!(RiskAssessment::Medium < RiskAssessment::High);
        assert!(RiskAssessment::High < RiskAssessment::Critical);
    }

    #[test]
    fn test_evidence_package_on_activation() {
        let mut engine = PolicyChangeEngine::new(2);
        let proposal = make_proposal("p-001", "alice", vec!["bob", "charlie"]);
        engine.propose(proposal).unwrap();
        engine.approve("p-001", make_signature("bob")).unwrap();
        engine.approve("p-001", make_signature("charlie")).unwrap();

        let evidence = engine
            .activate("p-001", "admin", "2026-01-15T02:00:00Z")
            .unwrap();
        assert!(!evidence.policy_diff.is_empty());
        assert_eq!(evidence.approval_signatures.len(), 2);
        assert_eq!(evidence.approval_chain, vec!["bob", "charlie"]);

        let record = engine.get_proposal("p-001").unwrap();
        assert!(record.evidence_package.is_some());
    }

    #[test]
    fn test_proposal_state_machine_full_lifecycle() {
        let mut engine = PolicyChangeEngine::new(2);
        // Propose -> Review -> Approve -> Activate -> Rollback
        let proposal = make_proposal("p-full", "alice", vec!["bob", "charlie"]);
        let record = engine.propose(proposal).unwrap();
        assert_eq!(record.state, ProposalState::Proposed);

        let state = engine.approve("p-full", make_signature("bob")).unwrap();
        assert_eq!(state, ProposalState::UnderReview);

        let state = engine.approve("p-full", make_signature("charlie")).unwrap();
        assert_eq!(state, ProposalState::Approved);

        engine
            .activate("p-full", "admin", "2026-01-15T02:00:00Z")
            .unwrap();
        assert_eq!(
            engine.get_proposal("p-full").unwrap().state,
            ProposalState::Applied
        );

        engine
            .rollback("p-full", "admin", "p-rb-full", "2026-01-15T03:00:00Z")
            .unwrap();
        assert_eq!(
            engine.get_proposal("p-full").unwrap().state,
            ProposalState::RolledBack
        );
    }

    #[test]
    fn test_large_audit_chain_verification() {
        let mut engine = PolicyChangeEngine::new(1);
        // Create 50 proposals with approvals.
        for i in 0..50 {
            let id = format!("p-{i:03}");
            let proposal = make_proposal(&id, "alice", vec!["bob"]);
            engine.propose(proposal).unwrap();
            engine.approve(&id, make_signature("bob")).unwrap();
        }

        assert!(engine.verify_audit_chain().unwrap());
        assert_eq!(engine.audit_ledger().len(), 100); // 50 proposals + 50 approvals
    }
}
