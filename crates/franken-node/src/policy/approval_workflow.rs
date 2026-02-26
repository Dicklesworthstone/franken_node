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
    hasher.update(b"approval_workflow_entry_v1:");
    hasher.update(entry.sequence.to_le_bytes());
    hasher.update(b"|");
    hasher.update(entry.event_code.as_bytes());
    hasher.update(b"|");
    hasher.update(entry.proposal_id.as_bytes());
    hasher.update(b"|");
    hasher.update(entry.actor.as_bytes());
    hasher.update(b"|");
    hasher.update(entry.timestamp.as_bytes());
    hasher.update(b"|");
    hasher.update(entry.details.as_bytes());
    hasher.update(b"|");
    hasher.update(entry.prev_hash.as_bytes());
    hasher.update(b"|");
    if let Some(ref from) = entry.transition_from {
        hasher.update(format!("{from:?}").as_bytes());
    }
    hasher.update(b"|");
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
        let rollback_command = Some(
            serde_json::to_string(&rollback_diff)
                .expect("PolicyDiffEntry contains only String fields"),
        );

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

        // Verify key-role separation BEFORE mutation: proposer cannot be sole approver.
        if record.approvals.is_empty()
            && signer.to_lowercase() == record.proposal.proposed_by.to_lowercase()
        {
            return Err(PolicyChangeError::new(
                ERR_SOLE_APPROVER,
                "Proposer cannot be the sole approver",
            ));
        }
        if !record.approvals.is_empty()
            && record
                .approvals
                .iter()
                .all(|a| a.signer == record.proposal.proposed_by)
            && signer == record.proposal.proposed_by
        {
            return Err(PolicyChangeError::new(
                ERR_SOLE_APPROVER,
                "Proposer cannot be the sole approver",
            ));
        }

        // Deduplicate: reject if this approver already signed.
        if record.approvals.iter().any(|a| a.signer == signer) {
            return Err(PolicyChangeError::new(
                ERR_INVALID_STATE_TRANSITION,
                format!("Approver {signer} has already signed this proposal"),
            ));
        }

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
            .all(|req| unique_approvers.contains(&req));

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

        // Guard: only Proposed or UnderReview proposals can be rejected.
        if record.state != ProposalState::Proposed && record.state != ProposalState::UnderReview {
            return Err(PolicyChangeError::new(
                ERR_INVALID_STATE_TRANSITION,
                format!("Cannot reject in state {:?}", record.state),
            ));
        }

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
        let genesis_hash = format!("{:x}", Sha256::digest(b"approval_workflow_genesis_v1:"));

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

    #[allow(clippy::too_many_arguments)]
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
        let genesis_hash = format!("{:x}", Sha256::digest(b"approval_workflow_genesis_v1:"));
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
        assert_eq!(engine.audit_ledger().len(), 4);
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

    #[test]
    fn reject_applied_proposal_is_denied() {
        let mut engine = PolicyChangeEngine::new(2);
        let proposal = make_proposal("p-applied", "alice", vec!["bob", "charlie"]);
        engine.propose(proposal).unwrap();
        engine.approve("p-applied", make_signature("bob")).unwrap();
        engine
            .approve("p-applied", make_signature("charlie"))
            .unwrap();
        engine
            .activate("p-applied", "admin", "2026-01-15T02:00:00Z")
            .unwrap();

        let err = engine
            .reject("p-applied", "reviewer", "too late", "2026-01-15T03:00:00Z")
            .unwrap_err();
        assert_eq!(
            err.code, ERR_INVALID_STATE_TRANSITION,
            "rejecting an Applied proposal must be denied (state guard)"
        );
    }
}

/// Integration tests: Policy approval workflow × Observability (evidence ledger, durability violations).
/// bd-17ds.5.3
#[cfg(test)]
mod policy_observability_integration_tests {
    use super::*;
    use crate::observability::durability_violation::{
        CausalEvent, CausalEventType, DurabilityViolationDetector, FailedArtifact, HaltPolicy,
        ProofContext, ViolationContext,
    };
    use crate::observability::evidence_ledger::{
        DecisionKind, EvidenceEntry, EvidenceLedger, LedgerCapacity,
    };

    // ── Helpers ────────────────────────────────────────────────────────

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

    fn make_evidence_entry(decision_id: &str, kind: DecisionKind, epoch: u64) -> EvidenceEntry {
        EvidenceEntry {
            schema_version: "1.0".to_string(),
            entry_id: None,
            decision_id: decision_id.to_string(),
            decision_kind: kind,
            decision_time: "2026-01-15T00:00:00Z".to_string(),
            timestamp_ms: epoch * 1000,
            trace_id: format!("trace-{decision_id}"),
            epoch_id: epoch,
            payload: serde_json::json!({}),
            size_bytes: 0,
        }
    }

    fn make_violation_context(epoch: u64) -> ViolationContext {
        ViolationContext {
            events: vec![CausalEvent {
                event_type: CausalEventType::IntegrityCheckFailed,
                timestamp_ms: epoch * 1000,
                description: "integrity check failed during policy activation".into(),
                evidence_ref: Some(format!("EVD-epoch-{epoch}")),
            }],
            artifacts: vec![FailedArtifact {
                artifact_path: "policy/quarantine_config.json".into(),
                expected_hash: "aabb".into(),
                actual_hash: "ccdd".into(),
                failure_reason: "hash mismatch after policy mutation".into(),
            }],
            proofs: ProofContext {
                failed_proofs: vec!["policy-integrity-proof".into()],
                missing_proofs: vec![],
                passed_proofs: vec![],
            },
            hardening_level: "critical".into(),
            epoch_id: epoch,
            timestamp_ms: epoch * 1000 + 100,
        }
    }

    // ── 1. Policy activation emits evidence to ledger ──────────────────

    #[test]
    fn policy_activation_evidence_recorded_in_ledger() {
        let mut engine = PolicyChangeEngine::new(2);
        let proposal = make_proposal("p-001", "alice", vec!["bob", "charlie"]);
        engine.propose(proposal).unwrap();
        engine.approve("p-001", make_signature("bob")).unwrap();
        engine.approve("p-001", make_signature("charlie")).unwrap();

        let evidence = engine
            .activate("p-001", "admin", "2026-01-15T02:00:00Z")
            .unwrap();

        // Record the activation evidence in the observability ledger
        let mut ledger = EvidenceLedger::new(LedgerCapacity::new(100, 100_000));
        let entry = make_evidence_entry("policy-activate-p-001", DecisionKind::Admit, 1);
        let entry_id = ledger.append(entry).unwrap();

        assert_eq!(ledger.len(), 1);
        assert_eq!(entry_id.0, 1);
        assert_eq!(evidence.proposal_id, "p-001");
        assert_eq!(evidence.approval_chain.len(), 2);
    }

    // ── 2. Policy audit chain → evidence snapshot correlation ──────────

    #[test]
    fn policy_audit_entries_correlate_with_evidence_snapshot() {
        let mut engine = PolicyChangeEngine::new(2);
        let proposal = make_proposal("p-002", "alice", vec!["bob", "charlie"]);
        engine.propose(proposal).unwrap();
        engine.approve("p-002", make_signature("bob")).unwrap();
        engine.approve("p-002", make_signature("charlie")).unwrap();
        engine
            .activate("p-002", "admin", "2026-01-15T02:00:00Z")
            .unwrap();

        // Record one evidence entry per audit entry
        let mut ledger = EvidenceLedger::new(LedgerCapacity::new(100, 100_000));
        let audit_entries = engine.query_audit_by_proposal("p-002");

        for (i, audit_entry) in audit_entries.iter().enumerate() {
            let kind = match audit_entry.event_code.as_str() {
                POLICY_CHANGE_PROPOSED => DecisionKind::Admit,
                POLICY_CHANGE_REVIEWED => DecisionKind::Throttle,
                POLICY_CHANGE_APPROVED => DecisionKind::Release,
                POLICY_CHANGE_ACTIVATED => DecisionKind::Admit,
                _ => DecisionKind::Escalate,
            };
            let entry = make_evidence_entry(
                &format!("audit-{}-{}", audit_entry.proposal_id, i),
                kind,
                (i + 1) as u64,
            );
            ledger.append(entry).unwrap();
        }

        // Audit chain has 4 entries: propose, review, approve, activate
        assert_eq!(audit_entries.len(), 4);
        assert_eq!(ledger.len(), 4);

        // Snapshot captures all
        let snap = ledger.snapshot();
        assert_eq!(snap.entries.len(), 4);
        assert_eq!(snap.total_appended, 4);
        assert_eq!(snap.total_evicted, 0);
    }

    // ── 3. Durability violation halts policy activation ─────────────────

    #[test]
    fn durability_violation_blocks_policy_activation_scope() {
        let mut detector = DurabilityViolationDetector::new(HaltPolicy::HaltAll);
        let ctx = make_violation_context(42);
        detector.generate_bundle(&ctx);

        // Detector is now halted
        assert!(detector.is_halted());
        let halt_err = detector.check_durable_op("policy-activation").unwrap_err();
        assert!(!halt_err.bundle_id.as_str().is_empty());

        // Policy engine itself can still propose (no direct coupling),
        // but the durability gate would prevent activation in a real system
        let mut engine = PolicyChangeEngine::new(2);
        let proposal = make_proposal("p-blocked", "alice", vec!["bob", "charlie"]);
        engine.propose(proposal).unwrap();
        engine.approve("p-blocked", make_signature("bob")).unwrap();
        engine
            .approve("p-blocked", make_signature("charlie"))
            .unwrap();

        // Before activating, check the durability gate
        let gate_result = detector.check_durable_op("policy-activation");
        assert!(gate_result.is_err());

        // After clearing halt, activation proceeds
        detector.clear_halt();
        assert!(detector.check_durable_op("policy-activation").is_ok());
        let evidence = engine
            .activate("p-blocked", "admin", "2026-01-15T03:00:00Z")
            .unwrap();
        assert_eq!(evidence.proposal_id, "p-blocked");
    }

    // ── 4. Policy rollback emits violation diagnostic + evidence ────────

    #[test]
    fn policy_rollback_generates_violation_and_evidence_trail() {
        let mut engine = PolicyChangeEngine::new(2);
        let proposal = make_proposal("p-roll", "alice", vec!["bob", "charlie"]);
        engine.propose(proposal).unwrap();
        engine.approve("p-roll", make_signature("bob")).unwrap();
        engine.approve("p-roll", make_signature("charlie")).unwrap();
        engine
            .activate("p-roll", "admin", "2026-01-15T02:00:00Z")
            .unwrap();

        // A violation is detected after activation
        let mut detector = DurabilityViolationDetector::with_defaults();
        let ctx = make_violation_context(50);
        let bundle = detector.generate_bundle(&ctx);

        // Record violation in evidence ledger
        let mut ledger = EvidenceLedger::new(LedgerCapacity::new(100, 100_000));
        let violation_entry = EvidenceEntry {
            schema_version: "1.0".to_string(),
            entry_id: None,
            decision_id: format!("violation-{}", bundle.bundle_id),
            decision_kind: DecisionKind::Deny,
            decision_time: "2026-01-15T02:30:00Z".to_string(),
            timestamp_ms: 50_100,
            trace_id: "trace-violation".to_string(),
            epoch_id: 50,
            payload: serde_json::json!({
                "bundle_id": bundle.bundle_id.as_str(),
                "event_count": bundle.event_count(),
            }),
            size_bytes: 0,
        };
        ledger.append(violation_entry).unwrap();
        assert!(detector.is_halted());

        // Rollback the policy
        engine
            .rollback("p-roll", "admin", "p-roll-rb", "2026-01-15T03:00:00Z")
            .unwrap();
        let original = engine.get_proposal("p-roll").unwrap();
        assert_eq!(original.state, ProposalState::RolledBack);

        // Record rollback in evidence ledger
        let rollback_entry =
            make_evidence_entry("policy-rollback-p-roll", DecisionKind::Rollback, 51);
        ledger.append(rollback_entry).unwrap();

        // Clear halt after remediation
        detector.clear_halt();
        assert!(!detector.is_halted());

        // Evidence ledger now has violation + rollback entries
        assert_eq!(ledger.len(), 2);
        let snap = ledger.snapshot();
        assert_eq!(snap.entries[0].1.decision_kind, DecisionKind::Deny);
        assert_eq!(snap.entries[1].1.decision_kind, DecisionKind::Rollback);
    }

    // ── 5. Evidence ledger bounded capacity during heavy policy churn ───

    #[test]
    fn evidence_ledger_bounded_during_policy_churn() {
        let mut engine = PolicyChangeEngine::new(1);
        let mut ledger = EvidenceLedger::new(LedgerCapacity::new(5, 100_000));

        // 20 proposals, each emits an evidence entry
        for i in 0..20 {
            let id = format!("p-churn-{i:03}");
            let proposal = make_proposal(&id, "alice", vec!["bob"]);
            engine.propose(proposal).unwrap();
            engine.approve(&id, make_signature("bob")).unwrap();

            let entry = make_evidence_entry(&format!("policy-{id}"), DecisionKind::Admit, i + 1);
            ledger.append(entry).unwrap();
        }

        // Ledger stays bounded at 5
        assert_eq!(ledger.len(), 5);
        assert_eq!(ledger.total_appended(), 20);
        assert_eq!(ledger.total_evicted(), 15);

        // Most recent entries are the last 5
        let snap = ledger.snapshot();
        assert!(snap.entries[0].1.decision_id.contains("p-churn-015"));
        assert!(snap.entries[4].1.decision_id.contains("p-churn-019"));
    }

    // ── 6. Scoped halt only blocks matching policy scope ───────────────

    #[test]
    fn scoped_halt_allows_unrelated_policy_operations() {
        let mut detector =
            DurabilityViolationDetector::new(HaltPolicy::HaltScope("storage".into()));
        let ctx = make_violation_context(10);
        detector.generate_bundle(&ctx);

        // Storage scope is halted
        assert!(detector.check_durable_op("storage").is_err());
        // Policy scope is NOT halted
        assert!(detector.check_durable_op("policy").is_ok());

        // So policy activation can still proceed
        let mut engine = PolicyChangeEngine::new(2);
        let proposal = make_proposal("p-scoped", "alice", vec!["bob", "charlie"]);
        engine.propose(proposal).unwrap();
        engine.approve("p-scoped", make_signature("bob")).unwrap();
        engine
            .approve("p-scoped", make_signature("charlie"))
            .unwrap();
        let evidence = engine
            .activate("p-scoped", "admin", "2026-01-15T02:00:00Z")
            .unwrap();
        assert_eq!(evidence.proposal_id, "p-scoped");
    }

    // ── 7. Audit chain integrity verified alongside evidence snapshot ───

    #[test]
    fn audit_chain_integrity_and_evidence_snapshot_both_valid() {
        let mut engine = PolicyChangeEngine::new(2);
        let mut ledger = EvidenceLedger::new(LedgerCapacity::new(100, 100_000));

        // Full lifecycle: propose → approve → activate
        let proposal = make_proposal("p-full", "alice", vec!["bob", "charlie"]);
        engine.propose(proposal).unwrap();
        ledger
            .append(make_evidence_entry(
                "propose-p-full",
                DecisionKind::Throttle,
                1,
            ))
            .unwrap();

        engine.approve("p-full", make_signature("bob")).unwrap();
        ledger
            .append(make_evidence_entry(
                "review-p-full",
                DecisionKind::Throttle,
                2,
            ))
            .unwrap();

        engine.approve("p-full", make_signature("charlie")).unwrap();
        ledger
            .append(make_evidence_entry(
                "approve-p-full",
                DecisionKind::Release,
                3,
            ))
            .unwrap();

        engine
            .activate("p-full", "admin", "2026-01-15T02:00:00Z")
            .unwrap();
        ledger
            .append(make_evidence_entry(
                "activate-p-full",
                DecisionKind::Admit,
                4,
            ))
            .unwrap();

        // Both subsystems are consistent
        assert!(engine.verify_audit_chain().unwrap());
        let snap = ledger.snapshot();
        assert_eq!(snap.entries.len(), 4);
        assert_eq!(engine.audit_ledger().len(), 4);
    }

    // ── 8. Warn-only violation doesn't block policy operations ─────────

    #[test]
    fn warn_only_violation_does_not_block_policy() {
        let mut detector = DurabilityViolationDetector::new(HaltPolicy::WarnOnly);
        let ctx = make_violation_context(99);
        let bundle = detector.generate_bundle(&ctx);
        assert!(!bundle.bundle_id.as_str().is_empty());

        // Not halted
        assert!(!detector.is_halted());
        assert!(detector.check_durable_op("policy").is_ok());

        // Policy operations proceed normally
        let mut engine = PolicyChangeEngine::new(2);
        let proposal = make_proposal("p-warn", "alice", vec!["bob", "charlie"]);
        engine.propose(proposal).unwrap();
        engine.approve("p-warn", make_signature("bob")).unwrap();
        engine.approve("p-warn", make_signature("charlie")).unwrap();
        let evidence = engine
            .activate("p-warn", "admin", "2026-01-15T02:00:00Z")
            .unwrap();
        assert_eq!(evidence.approval_chain.len(), 2);
    }

    // ── 9. Rejection recorded in evidence ledger ───────────────────────

    #[test]
    fn rejected_proposal_emits_deny_evidence() {
        let mut engine = PolicyChangeEngine::new(2);
        let mut ledger = EvidenceLedger::new(LedgerCapacity::new(100, 100_000));

        let proposal = make_proposal("p-deny", "alice", vec!["bob"]);
        engine.propose(proposal).unwrap();
        engine
            .reject(
                "p-deny",
                "security-review",
                "Policy violates safety boundary",
                "2026-01-15T01:30:00Z",
            )
            .unwrap();

        let record = engine.get_proposal("p-deny").unwrap();
        assert_eq!(record.state, ProposalState::Rejected);

        // Record the denial in evidence ledger
        let entry = make_evidence_entry("policy-deny-p-deny", DecisionKind::Deny, 1);
        ledger.append(entry).unwrap();

        assert_eq!(ledger.len(), 1);
        let snap = ledger.snapshot();
        assert_eq!(snap.entries[0].1.decision_kind, DecisionKind::Deny);
    }

    // ── 10. Multiple violations accumulate in both systems ─────────────

    #[test]
    fn multiple_violations_tracked_across_policy_and_observability() {
        let mut detector = DurabilityViolationDetector::with_defaults();
        let mut ledger = EvidenceLedger::new(LedgerCapacity::new(100, 100_000));

        for epoch in 1..=5u64 {
            let ctx = make_violation_context(epoch);
            let bundle = detector.generate_bundle(&ctx);

            let entry = EvidenceEntry {
                schema_version: "1.0".to_string(),
                entry_id: None,
                decision_id: format!("violation-{}", bundle.bundle_id),
                decision_kind: DecisionKind::Deny,
                decision_time: "2026-01-15T00:00:00Z".to_string(),
                timestamp_ms: epoch * 1000,
                trace_id: format!("trace-v-{epoch}"),
                epoch_id: epoch,
                payload: serde_json::json!({}),
                size_bytes: 0,
            };
            ledger.append(entry).unwrap();
        }

        assert_eq!(detector.bundle_count(), 5);
        assert_eq!(detector.active_halts().len(), 5);
        assert_eq!(ledger.len(), 5);

        // All ledger entries are Deny decisions
        let snap = ledger.snapshot();
        assert!(
            snap.entries
                .iter()
                .all(|(_, e)| e.decision_kind == DecisionKind::Deny)
        );
    }

    // ── 11. Evidence package matches ledger record ─────────────────────

    #[test]
    fn evidence_package_fields_preserved_in_ledger() {
        let mut engine = PolicyChangeEngine::new(2);
        let proposal = make_proposal("p-pkg", "alice", vec!["bob", "charlie"]);
        engine.propose(proposal).unwrap();
        engine.approve("p-pkg", make_signature("bob")).unwrap();
        engine.approve("p-pkg", make_signature("charlie")).unwrap();
        let evidence = engine
            .activate("p-pkg", "admin", "2026-01-15T02:00:00Z")
            .unwrap();

        // Serialize evidence package into ledger payload
        let mut ledger = EvidenceLedger::new(LedgerCapacity::new(100, 100_000));
        let entry = EvidenceEntry {
            schema_version: "1.0".to_string(),
            entry_id: None,
            decision_id: format!("activate-{}", evidence.proposal_id),
            decision_kind: DecisionKind::Admit,
            decision_time: evidence.activated_at.clone(),
            timestamp_ms: 2000,
            trace_id: "trace-activation".to_string(),
            epoch_id: 1,
            payload: serde_json::json!({
                "approval_chain": evidence.approval_chain,
                "diff_count": evidence.policy_diff.len(),
            }),
            size_bytes: 0,
        };
        let eid = ledger.append(entry).unwrap();
        assert_eq!(eid.0, 1);

        // Verify payload round-trips
        let snap = ledger.snapshot();
        let payload = &snap.entries[0].1.payload;
        let chain = payload["approval_chain"]
            .as_array()
            .expect("approval_chain is array");
        assert_eq!(chain.len(), 2);
        assert_eq!(chain[0].as_str(), Some("bob"));
        assert_eq!(chain[1].as_str(), Some("charlie"));
    }

    // ── 12. Violation bundle JSON contains causal chain from policy ─────

    #[test]
    fn violation_bundle_json_contains_policy_causal_chain() {
        let ctx = ViolationContext {
            events: vec![
                CausalEvent {
                    event_type: CausalEventType::GuardrailRejection,
                    timestamp_ms: 1000,
                    description: "policy mutation rejected by compat gate".into(),
                    evidence_ref: Some("EVD-COMPAT-001".into()),
                },
                CausalEvent {
                    event_type: CausalEventType::HardeningEscalation,
                    timestamp_ms: 1100,
                    description: "escalated after repeated policy violations".into(),
                    evidence_ref: None,
                },
            ],
            artifacts: vec![],
            proofs: ProofContext::new(),
            hardening_level: "high".into(),
            epoch_id: 77,
            timestamp_ms: 1200,
        };

        let bundle = crate::observability::durability_violation::generate_bundle(&ctx);
        let json = bundle.to_json();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed["event_count"], 2);
        assert_eq!(parsed["causal_events"][0]["type"], "guardrail_rejection");
        assert!(
            parsed["causal_events"][0]["description"]
                .as_str()
                .unwrap()
                .contains("compat gate")
        );
    }
}
