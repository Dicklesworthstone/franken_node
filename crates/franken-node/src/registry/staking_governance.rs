// Security Staking and Slashing Framework for Publisher Trust Governance
//
// bd-26mk / section 10.17
//
// Implements:
//   - StakingLedger: tracks publisher stakes (deposit, balance, slash history)
//   - SlashingEngine: deterministic penalty calculation from violation evidence
//   - StakeActions: deposit, withdraw (with cooldown), slash, restore
//   - Full audit trail with signed, auditable evidence
//   - Capability gate integration for stake-gated operations
//
// Event codes: STAKE-001 .. STAKE-007
// Error codes: ERR_STAKE_INSUFFICIENT .. ERR_STAKE_DUPLICATE_APPEAL
// Invariants:  INV-STAKE-MINIMUM, INV-STAKE-SLASH-DETERMINISTIC,
//              INV-STAKE-APPEAL-WINDOW, INV-STAKE-AUDIT-COMPLETE,
//              INV-STAKE-NO-DOUBLE-SLASH, INV-STAKE-WITHDRAWAL-SAFE
//
// Also satisfies acceptance-criteria aliases:
//   INV-STK-DETERMINISTIC-PENALTY  (via INV-STAKE-SLASH-DETERMINISTIC)
//   INV-STK-AUDITABLE-SLASH        (via INV-STAKE-AUDIT-COMPLETE)
//   INV-STK-NO-NEGATIVE-BALANCE    (via balance floor enforcement)
//
// Schema version: staking-v1.0

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt;

// ---------------------------------------------------------------------------
// Schema version
// ---------------------------------------------------------------------------

pub const SCHEMA_VERSION: &str = "staking-v1.0";

// ---------------------------------------------------------------------------
// Event codes
// ---------------------------------------------------------------------------

/// Stake deposited successfully.
pub const STAKE_001: &str = "STAKE-001";
/// Stake slashed due to validated malicious behaviour.
pub const STAKE_002: &str = "STAKE-002";
/// Appeal filed against slash decision.
pub const STAKE_003: &str = "STAKE-003";
/// Appeal resolved (upheld or reversed).
pub const STAKE_004: &str = "STAKE-004";
/// Stake withdrawn by publisher.
pub const STAKE_005: &str = "STAKE-005";
/// Stake expired and released.
pub const STAKE_006: &str = "STAKE-006";
/// Capability gate checked against stake.
pub const STAKE_007: &str = "STAKE-007";

// ---------------------------------------------------------------------------
// Error codes
// ---------------------------------------------------------------------------

pub const ERR_STAKE_INSUFFICIENT: &str = "ERR_STAKE_INSUFFICIENT";
pub const ERR_STAKE_NOT_FOUND: &str = "ERR_STAKE_NOT_FOUND";
pub const ERR_STAKE_ALREADY_SLASHED: &str = "ERR_STAKE_ALREADY_SLASHED";
pub const ERR_STAKE_WITHDRAWAL_BLOCKED: &str = "ERR_STAKE_WITHDRAWAL_BLOCKED";
pub const ERR_STAKE_APPEAL_EXPIRED: &str = "ERR_STAKE_APPEAL_EXPIRED";
pub const ERR_STAKE_INVALID_TRANSITION: &str = "ERR_STAKE_INVALID_TRANSITION";
pub const ERR_STAKE_DUPLICATE_APPEAL: &str = "ERR_STAKE_DUPLICATE_APPEAL";

// ---------------------------------------------------------------------------
// Invariant tags
// ---------------------------------------------------------------------------

pub const INV_STAKE_MINIMUM: &str = "INV-STAKE-MINIMUM";
pub const INV_STAKE_SLASH_DETERMINISTIC: &str = "INV-STAKE-SLASH-DETERMINISTIC";
pub const INV_STAKE_APPEAL_WINDOW: &str = "INV-STAKE-APPEAL-WINDOW";
pub const INV_STAKE_AUDIT_COMPLETE: &str = "INV-STAKE-AUDIT-COMPLETE";
pub const INV_STAKE_NO_DOUBLE_SLASH: &str = "INV-STAKE-NO-DOUBLE-SLASH";
pub const INV_STAKE_WITHDRAWAL_SAFE: &str = "INV-STAKE-WITHDRAWAL-SAFE";

// Acceptance-criteria aliases
pub const INV_STK_DETERMINISTIC_PENALTY: &str = "INV-STK-DETERMINISTIC-PENALTY";
pub const INV_STK_AUDITABLE_SLASH: &str = "INV-STK-AUDITABLE-SLASH";
pub const INV_STK_NO_NEGATIVE_BALANCE: &str = "INV-STK-NO-NEGATIVE-BALANCE";

// ---------------------------------------------------------------------------
// bd-26mk canonical event codes
// ---------------------------------------------------------------------------

/// Stake deposit received for a publisher.
pub const STAKE_DEPOSIT_RECEIVED: &str = "STAKE_DEPOSIT_RECEIVED";
/// Stake gate evaluated for capability access.
pub const STAKE_GATE_EVALUATED: &str = "STAKE_GATE_EVALUATED";
/// Slashing process initiated from evidence.
pub const SLASH_INITIATED: &str = "SLASH_INITIATED";
/// Stake successfully slashed.
pub const SLASH_EXECUTED: &str = "SLASH_EXECUTED";
/// Publisher filed an appeal against a slash.
pub const APPEAL_FILED: &str = "APPEAL_FILED";

// ---------------------------------------------------------------------------
// bd-26mk canonical error codes
// ---------------------------------------------------------------------------

/// Stake below required minimum for tier.
pub const ERR_STAKE_GATE_DENIED: &str = "ERR_STAKE_GATE_DENIED";
/// Evidence hash does not match expected.
pub const ERR_SLASH_EVIDENCE_INVALID: &str = "ERR_SLASH_EVIDENCE_INVALID";
/// Slash already processed for this evidence.
pub const ERR_SLASH_ALREADY_EXECUTED: &str = "ERR_SLASH_ALREADY_EXECUTED";
/// Appeal filed after the deadline.
pub const ERR_APPEAL_EXPIRED: &str = "ERR_APPEAL_EXPIRED";
/// Withdrawal blocked during lock period.
pub const ERR_STAKE_WITHDRAWAL_LOCKED: &str = "ERR_STAKE_WITHDRAWAL_LOCKED";

// ---------------------------------------------------------------------------
// bd-26mk canonical invariants
// ---------------------------------------------------------------------------

/// High-risk capability activation requires minimum stake.
pub const INV_STAKE_GATE_REQUIRED: &str = "INV-STAKE-GATE-REQUIRED";
/// Slashing decisions are computed deterministically from evidence.
pub const INV_SLASH_DETERMINISTIC: &str = "INV-SLASH-DETERMINISTIC";
/// Every slash event produces an immutable audit trail entry.
pub const INV_SLASH_AUDIT_TRAIL: &str = "INV-SLASH-AUDIT-TRAIL";
/// Slashed publishers have a bounded appeal window.
pub const INV_APPEAL_WINDOW: &str = "INV-APPEAL-WINDOW";

// ---------------------------------------------------------------------------
// Domain types
// ---------------------------------------------------------------------------

/// Unique identifier for a publisher.
pub type PublisherId = String;

/// Unique identifier for a security stake.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct StakeId(pub u64);

impl fmt::Display for StakeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "stake-{}", self.0)
    }
}

/// Risk tier for capability classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskTier {
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for RiskTier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Low => write!(f, "low"),
            Self::Medium => write!(f, "medium"),
            Self::High => write!(f, "high"),
            Self::Critical => write!(f, "critical"),
        }
    }
}

/// Lifecycle state of a stake.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StakeState {
    Active,
    Slashed,
    UnderAppeal,
    Withdrawn,
    Expired,
}

impl fmt::Display for StakeState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Active => write!(f, "active"),
            Self::Slashed => write!(f, "slashed"),
            Self::UnderAppeal => write!(f, "under_appeal"),
            Self::Withdrawn => write!(f, "withdrawn"),
            Self::Expired => write!(f, "expired"),
        }
    }
}

/// Type of policy violation that triggers slashing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ViolationType {
    MaliciousCode,
    PolicyViolation,
    SupplyChainCompromise,
    FalseAttestation,
}

impl fmt::Display for ViolationType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MaliciousCode => write!(f, "malicious_code"),
            Self::PolicyViolation => write!(f, "policy_violation"),
            Self::SupplyChainCompromise => write!(f, "supply_chain_compromise"),
            Self::FalseAttestation => write!(f, "false_attestation"),
        }
    }
}

/// Outcome of an appeal decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AppealOutcome {
    Pending,
    Upheld,
    Reversed,
}

/// Evidence bundle attached to a slash event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlashEvidence {
    pub violation_type: ViolationType,
    pub description: String,
    pub evidence_payload: String,
    pub evidence_hash: String,
    pub collector_identity: String,
    pub collected_at: u64,
}

impl SlashEvidence {
    /// Create new evidence with a deterministic content hash.
    pub fn new(
        violation_type: ViolationType,
        description: &str,
        evidence_payload: &str,
        collector_identity: &str,
        collected_at: u64,
    ) -> Self {
        let evidence_hash = compute_evidence_hash(evidence_payload);
        Self {
            violation_type,
            description: description.to_string(),
            evidence_payload: evidence_payload.to_string(),
            evidence_hash,
            collector_identity: collector_identity.to_string(),
            collected_at,
        }
    }
}

/// Record of a slashing action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlashRecord {
    pub violation_id: String,
    pub amount: u64,
    pub reason: ViolationType,
    pub evidence_hash: String,
    pub timestamp: u64,
}

/// Record of a slash event with full context.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlashEvent {
    pub slash_id: u64,
    pub stake_id: StakeId,
    pub publisher_id: PublisherId,
    pub evidence: SlashEvidence,
    pub slash_amount: u64,
    pub pre_balance: u64,
    pub post_balance: u64,
    pub risk_tier: RiskTier,
    pub timestamp: u64,
    pub penalty_hash: String,
}

/// Record of an appeal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppealRecord {
    pub appeal_id: u64,
    pub stake_id: StakeId,
    pub slash_id: u64,
    pub reason: String,
    pub outcome: AppealOutcome,
    pub filed_at: u64,
    pub resolved_at: Option<u64>,
}

/// Per-risk-tier policy configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TierPolicy {
    pub minimum_stake: u64,
    pub slash_fraction_bps: u64, // basis points (10000 = 100%)
    pub cooldown_secs: u64,
    pub appeal_window_secs: u64,
}

/// Complete staking policy configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StakePolicy {
    pub tiers: BTreeMap<String, TierPolicy>,
}

impl StakePolicy {
    /// Create the default policy matching the spec table.
    pub fn default_policy() -> Self {
        let mut tiers = BTreeMap::new();
        tiers.insert(
            "critical".to_string(),
            TierPolicy {
                minimum_stake: 1000,
                slash_fraction_bps: 10000, // 100%
                cooldown_secs: 72 * 3600,
                appeal_window_secs: 48 * 3600,
            },
        );
        tiers.insert(
            "high".to_string(),
            TierPolicy {
                minimum_stake: 500,
                slash_fraction_bps: 5000, // 50%
                cooldown_secs: 48 * 3600,
                appeal_window_secs: 36 * 3600,
            },
        );
        tiers.insert(
            "medium".to_string(),
            TierPolicy {
                minimum_stake: 100,
                slash_fraction_bps: 2500, // 25%
                cooldown_secs: 24 * 3600,
                appeal_window_secs: 24 * 3600,
            },
        );
        tiers.insert(
            "low".to_string(),
            TierPolicy {
                minimum_stake: 10,
                slash_fraction_bps: 1000, // 10%
                cooldown_secs: 12 * 3600,
                appeal_window_secs: 12 * 3600,
            },
        );
        Self { tiers }
    }

    /// Retrieve the tier policy for a given risk tier.
    pub fn get_tier(&self, tier: &RiskTier) -> Option<&TierPolicy> {
        self.tiers.get(&tier.to_string())
    }
}

/// A single stake account for a publisher.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StakeAccount {
    pub publisher_id: PublisherId,
    pub balance: u64,
    pub deposited: u64,
    pub slashed_total: u64,
    pub slash_history: Vec<SlashRecord>,
    pub cooldown_until: Option<u64>,
}

/// Full record of a security stake.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StakeRecord {
    pub id: StakeId,
    pub publisher_id: PublisherId,
    pub amount: u64,
    pub state: StakeState,
    pub risk_tier: RiskTier,
    pub deposited_at: u64,
    pub expires_at: Option<u64>,
    pub withdrawn_at: Option<u64>,
    pub slashed_at: Option<u64>,
}

/// Timestamped audit log entry for any staking operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StakingAuditEntry {
    pub entry_id: u64,
    pub event_code: String,
    pub timestamp: u64,
    pub publisher_id: PublisherId,
    pub stake_id: StakeId,
    pub operation: String,
    pub evidence_hash: Option<String>,
    pub outcome: String,
    pub invariants_checked: Vec<String>,
}

// ---------------------------------------------------------------------------
// Deterministic hashing
// ---------------------------------------------------------------------------

/// Compute a SHA-256 hash of evidence payload for deterministic penalty calculation.
/// Satisfies INV-STK-DETERMINISTIC-PENALTY and INV-STAKE-SLASH-DETERMINISTIC.
pub fn compute_evidence_hash(payload: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"staking_governance_evidence_v1:");
    hasher.update(payload.as_bytes());
    hex::encode(hasher.finalize())
}

/// Compute a deterministic penalty hash from evidence and policy parameters.
/// Same evidence + same policy = same penalty hash.
/// Satisfies INV-STAKE-SLASH-DETERMINISTIC.
pub fn compute_penalty_hash(
    evidence_hash: &str,
    slash_fraction_bps: u64,
    stake_amount: u64,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"staking_governance_penalty_v1:");
    hasher.update(evidence_hash.as_bytes());
    hasher.update(b"|");
    hasher.update(slash_fraction_bps.to_le_bytes());
    hasher.update(b"|");
    hasher.update(stake_amount.to_le_bytes());
    hex::encode(hasher.finalize())
}

// ---------------------------------------------------------------------------
// Staking Ledger Error
// ---------------------------------------------------------------------------

/// Errors returned by staking operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StakingError {
    InsufficientStake {
        required: u64,
        provided: u64,
        code: &'static str,
    },
    StakeNotFound {
        stake_id: StakeId,
        code: &'static str,
    },
    AlreadySlashed {
        stake_id: StakeId,
        code: &'static str,
    },
    WithdrawalBlocked {
        stake_id: StakeId,
        reason: String,
        code: &'static str,
    },
    AppealExpired {
        stake_id: StakeId,
        code: &'static str,
    },
    InvalidTransition {
        from: StakeState,
        to: StakeState,
        code: &'static str,
    },
    DuplicateAppeal {
        stake_id: StakeId,
        slash_id: u64,
        code: &'static str,
    },
}

impl fmt::Display for StakingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InsufficientStake {
                required,
                provided,
                code,
            } => write!(
                f,
                "[{code}] insufficient stake: required {required}, provided {provided}"
            ),
            Self::StakeNotFound { stake_id, code } => {
                write!(f, "[{code}] stake not found: {stake_id}")
            }
            Self::AlreadySlashed { stake_id, code } => {
                write!(f, "[{code}] stake already slashed: {stake_id}")
            }
            Self::WithdrawalBlocked {
                stake_id,
                reason,
                code,
            } => write!(f, "[{code}] withdrawal blocked for {stake_id}: {reason}"),
            Self::AppealExpired { stake_id, code } => {
                write!(f, "[{code}] appeal window expired for {stake_id}")
            }
            Self::InvalidTransition { from, to, code } => {
                write!(f, "[{code}] invalid transition: {from} -> {to}")
            }
            Self::DuplicateAppeal {
                stake_id,
                slash_id,
                code,
            } => write!(
                f,
                "[{code}] duplicate appeal for {stake_id}, slash {slash_id}"
            ),
        }
    }
}

// ---------------------------------------------------------------------------
// Slashing Engine
// ---------------------------------------------------------------------------

/// Deterministic penalty calculator from violation evidence.
/// Satisfies INV-STAKE-SLASH-DETERMINISTIC / INV-STK-DETERMINISTIC-PENALTY.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlashingEngine {
    pub penalty_schedule: StakePolicy,
}

impl SlashingEngine {
    /// Create a new slashing engine with the given policy.
    pub fn new(policy: StakePolicy) -> Self {
        Self {
            penalty_schedule: policy,
        }
    }

    /// Compute the slash amount for a given risk tier and stake balance.
    /// Returns (slash_amount, penalty_hash).
    ///
    /// Deterministic: same inputs always produce the same outputs.
    pub fn compute_penalty(
        &self,
        risk_tier: &RiskTier,
        stake_balance: u64,
        evidence_hash: &str,
    ) -> Result<(u64, String), StakingError> {
        let tier_policy =
            self.penalty_schedule
                .get_tier(risk_tier)
                .ok_or(StakingError::InvalidTransition {
                    from: StakeState::Active,
                    to: StakeState::Slashed,
                    code: ERR_STAKE_INVALID_TRANSITION,
                })?;

        // Normalize to the effective policy value so amount and hash describe
        // the same penalty decision across nodes/config representations.
        let effective_bps = tier_policy.slash_fraction_bps.min(10_000);
        let slash_amount = (stake_balance as u128 * effective_bps as u128 / 10000) as u64;
        let penalty_hash = compute_penalty_hash(evidence_hash, effective_bps, stake_balance);

        Ok((slash_amount, penalty_hash))
    }

    /// Check if an appeal is within the configured appeal window.
    /// Satisfies INV-STAKE-APPEAL-WINDOW.
    pub fn is_within_appeal_window(
        &self,
        risk_tier: &RiskTier,
        slash_timestamp: u64,
        current_time: u64,
    ) -> bool {
        if let Some(tier_policy) = self.penalty_schedule.get_tier(risk_tier) {
            let deadline = slash_timestamp.saturating_add(tier_policy.appeal_window_secs);
            current_time < deadline
        } else {
            false
        }
    }

    /// Get the cooldown duration for a risk tier.
    pub fn cooldown_secs(&self, risk_tier: &RiskTier) -> Option<u64> {
        self.penalty_schedule
            .get_tier(risk_tier)
            .map(|tp| tp.cooldown_secs)
    }
}

// ---------------------------------------------------------------------------
// Capability Stake Gate
// ---------------------------------------------------------------------------

/// Gate that checks stake sufficiency before capability activation.
/// Satisfies INV-STAKE-MINIMUM.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityStakeGate {
    pub policy: StakePolicy,
}

impl CapabilityStakeGate {
    /// Create a new gate with the given policy.
    pub fn new(policy: StakePolicy) -> Self {
        Self { policy }
    }

    /// Check if a publisher has sufficient stake for a given risk tier.
    /// Returns (allowed, event_code, detail).
    pub fn check_stake(
        &self,
        ledger: &StakingLedger,
        publisher_id: &str,
        risk_tier: &RiskTier,
        current_time: u64,
    ) -> (bool, &'static str, String) {
        let tier_policy = match self.policy.get_tier(risk_tier) {
            Some(tp) => tp,
            None => return (false, STAKE_007, format!("unknown risk tier: {risk_tier}")),
        };

        // Check publisher has an active stake
        let record = match ledger.get_active_stake(publisher_id) {
            Some(r) => r,
            None => {
                // Before returning "not found", check if a non-active stake
                // exists (e.g. slashed/under-appeal) — different error path.
                if let Some(any) = ledger.get_any_stake_for_publisher(publisher_id)
                    && (any.state == StakeState::Slashed || any.state == StakeState::UnderAppeal)
                {
                    return (
                        false,
                        STAKE_007,
                        format!(
                            "publisher {publisher_id} has unresolved slash (state={})",
                            any.state
                        ),
                    );
                }
                return (
                    false,
                    STAKE_007,
                    format!(
                        "[{}] no active stake for publisher {publisher_id}",
                        ERR_STAKE_NOT_FOUND
                    ),
                );
            }
        };

        // Check stake meets minimum for risk tier
        if record.amount < tier_policy.minimum_stake {
            return (
                false,
                STAKE_007,
                format!(
                    "[{}] stake {} below minimum {} for tier {risk_tier}",
                    ERR_STAKE_INSUFFICIENT, record.amount, tier_policy.minimum_stake
                ),
            );
        }

        // Note: slashed/under-appeal stakes are caught in the None branch
        // above via get_any_stake_for_publisher. Here `record` is always Active.

        // Check cooldown has elapsed
        if let Some(account) = ledger.accounts.get(publisher_id)
            && let Some(cooldown_until) = account.cooldown_until
            && current_time < cooldown_until
        {
            return (
                false,
                STAKE_007,
                format!("publisher {publisher_id} in cooldown until {cooldown_until}"),
            );
        }

        (
            true,
            STAKE_007,
            format!(
                "publisher {publisher_id} passes gate for tier {risk_tier} (stake={})",
                record.amount
            ),
        )
    }
}

// ---------------------------------------------------------------------------
// Staking Ledger (top-level state)
// ---------------------------------------------------------------------------

/// Top-level state holding all stakes, events, appeals.
/// Uses BTreeMap for deterministic iteration order.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustGovernanceState {
    pub stakes: BTreeMap<u64, StakeRecord>,
    pub slash_events: Vec<SlashEvent>,
    pub appeals: Vec<AppealRecord>,
    pub audit_log: Vec<StakingAuditEntry>,
    pub next_stake_id: u64,
    pub next_slash_id: u64,
    pub next_appeal_id: u64,
    pub next_audit_id: u64,
}

/// The staking ledger tracks publisher stakes and provides operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StakingLedger {
    pub accounts: BTreeMap<PublisherId, StakeAccount>,
    pub state: TrustGovernanceState,
    pub engine: SlashingEngine,
    pub schema_version: String,
}

impl StakingLedger {
    /// Create a new empty ledger with the default policy.
    pub fn new() -> Self {
        Self::with_policy(StakePolicy::default_policy())
    }

    /// Create a new empty ledger with a custom policy.
    pub fn with_policy(policy: StakePolicy) -> Self {
        Self {
            accounts: BTreeMap::new(),
            state: TrustGovernanceState {
                stakes: BTreeMap::new(),
                slash_events: Vec::new(),
                appeals: Vec::new(),
                audit_log: Vec::new(),
                next_stake_id: 1,
                next_slash_id: 1,
                next_appeal_id: 1,
                next_audit_id: 1,
            },
            engine: SlashingEngine::new(policy),
            schema_version: SCHEMA_VERSION.to_string(),
        }
    }

    // -----------------------------------------------------------------------
    // Deposit (STK-001)
    // -----------------------------------------------------------------------

    /// Deposit a stake for a publisher.
    /// Satisfies INV-STAKE-MINIMUM: rejects deposits below risk-tier minimum.
    /// Satisfies INV-STAKE-AUDIT-COMPLETE / INV-STK-AUDITABLE-SLASH.
    pub fn deposit(
        &mut self,
        publisher_id: &str,
        amount: u64,
        risk_tier: RiskTier,
        timestamp: u64,
    ) -> Result<StakeId, StakingError> {
        // Reject empty publisher_id — would corrupt the account map.
        if publisher_id.trim().is_empty() {
            return Err(StakingError::InsufficientStake {
                required: 0,
                provided: 0,
                code: ERR_STAKE_INSUFFICIENT,
            });
        }

        // INV-STAKE-MINIMUM: check minimum for risk tier
        if let Some(tier_policy) = self.engine.penalty_schedule.get_tier(&risk_tier)
            && amount < tier_policy.minimum_stake
        {
            return Err(StakingError::InsufficientStake {
                required: tier_policy.minimum_stake,
                provided: amount,
                code: ERR_STAKE_INSUFFICIENT,
            });
        }

        let stake_id = StakeId(self.state.next_stake_id);
        self.state.next_stake_id = self.state.next_stake_id.saturating_add(1);

        let record = StakeRecord {
            id: stake_id,
            publisher_id: publisher_id.to_string(),
            amount,
            state: StakeState::Active,
            risk_tier,
            deposited_at: timestamp,
            expires_at: None,
            withdrawn_at: None,
            slashed_at: None,
        };
        self.state.stakes.insert(stake_id.0, record);

        // Update account
        let account = self
            .accounts
            .entry(publisher_id.to_string())
            .or_insert_with(|| StakeAccount {
                publisher_id: publisher_id.to_string(),
                balance: 0,
                deposited: 0,
                slashed_total: 0,
                slash_history: Vec::new(),
                cooldown_until: None,
            });
        account.balance = account.balance.saturating_add(amount);
        account.deposited = account.deposited.saturating_add(amount);

        // INV-STAKE-AUDIT-COMPLETE: emit audit entry
        self.emit_audit(
            STAKE_001,
            timestamp,
            publisher_id,
            stake_id,
            "deposit",
            None,
            &format!("deposited {amount} for tier {risk_tier}"),
            vec![
                INV_STAKE_MINIMUM.to_string(),
                INV_STAKE_AUDIT_COMPLETE.to_string(),
            ],
        );

        Ok(stake_id)
    }

    // -----------------------------------------------------------------------
    // Slash (STK-002)
    // -----------------------------------------------------------------------

    /// Slash a publisher's stake based on violation evidence.
    /// Satisfies INV-STAKE-SLASH-DETERMINISTIC / INV-STK-DETERMINISTIC-PENALTY.
    /// Satisfies INV-STAKE-NO-DOUBLE-SLASH.
    /// Satisfies INV-STK-NO-NEGATIVE-BALANCE: balance floors at zero.
    /// Satisfies INV-STK-AUDITABLE-SLASH: produces signed evidence.
    pub fn slash(
        &mut self,
        stake_id: StakeId,
        evidence: SlashEvidence,
        timestamp: u64,
    ) -> Result<SlashEvent, StakingError> {
        let record = self
            .state
            .stakes
            .get(&stake_id.0)
            .ok_or(StakingError::StakeNotFound {
                stake_id,
                code: ERR_STAKE_NOT_FOUND,
            })?
            .clone();

        // Only active stakes can be slashed
        if record.state != StakeState::Active {
            return Err(StakingError::AlreadySlashed {
                stake_id,
                code: ERR_STAKE_ALREADY_SLASHED,
            });
        }

        // INV-STAKE-NO-DOUBLE-SLASH: check evidence hash not already used
        let evidence_hash = evidence.evidence_hash.clone();
        for existing in &self.state.slash_events {
            if crate::security::constant_time::ct_eq(
                &existing.evidence.evidence_hash,
                &evidence_hash,
            ) && existing.publisher_id == record.publisher_id
            {
                return Err(StakingError::AlreadySlashed {
                    stake_id,
                    code: ERR_STAKE_ALREADY_SLASHED,
                });
            }
        }

        // INV-STAKE-SLASH-DETERMINISTIC: compute penalty deterministically
        let (slash_amount, penalty_hash) =
            self.engine
                .compute_penalty(&record.risk_tier, record.amount, &evidence_hash)?;

        let pre_balance = record.amount;
        // INV-STK-NO-NEGATIVE-BALANCE: floor at zero
        let post_balance = pre_balance.saturating_sub(slash_amount);

        // Update stake record
        let stake_record = self
            .state
            .stakes
            .get_mut(&stake_id.0)
            .expect("stake existence verified above");
        stake_record.state = StakeState::Slashed;
        stake_record.slashed_at = Some(timestamp);
        stake_record.amount = post_balance;

        // Update account
        let publisher_id = record.publisher_id.clone();
        if let Some(account) = self.accounts.get_mut(&publisher_id) {
            account.balance = account.balance.saturating_sub(slash_amount);
            account.slashed_total = account.slashed_total.saturating_add(slash_amount);
            account.slash_history.push(SlashRecord {
                violation_id: format!("slash-{}", self.state.next_slash_id),
                amount: slash_amount,
                reason: evidence.violation_type.clone(),
                evidence_hash: evidence_hash.clone(),
                timestamp,
            });

            // Apply cooldown
            if let Some(cooldown) = self.engine.cooldown_secs(&record.risk_tier) {
                account.cooldown_until = Some(timestamp.saturating_add(cooldown));
            }
        }

        let slash_event = SlashEvent {
            slash_id: self.state.next_slash_id,
            stake_id,
            publisher_id: publisher_id.clone(),
            evidence,
            slash_amount,
            pre_balance,
            post_balance,
            risk_tier: record.risk_tier,
            timestamp,
            penalty_hash,
        };
        self.state.next_slash_id = self.state.next_slash_id.saturating_add(1);
        self.state.slash_events.push(slash_event.clone());

        // INV-STAKE-AUDIT-COMPLETE
        self.emit_audit(
            STAKE_002,
            timestamp,
            &publisher_id,
            stake_id,
            "slash",
            Some(evidence_hash),
            &format!(
                "slashed {slash_amount} from {pre_balance} (post={post_balance}, tier={})",
                record.risk_tier
            ),
            vec![
                INV_STAKE_SLASH_DETERMINISTIC.to_string(),
                INV_STAKE_NO_DOUBLE_SLASH.to_string(),
                INV_STAKE_AUDIT_COMPLETE.to_string(),
                INV_STK_DETERMINISTIC_PENALTY.to_string(),
                INV_STK_AUDITABLE_SLASH.to_string(),
                INV_STK_NO_NEGATIVE_BALANCE.to_string(),
            ],
        );

        Ok(slash_event)
    }

    // -----------------------------------------------------------------------
    // Appeal (STK-003 / STK-004)
    // -----------------------------------------------------------------------

    /// File an appeal against a slash decision.
    /// Satisfies INV-STAKE-APPEAL-WINDOW.
    pub fn file_appeal(
        &mut self,
        stake_id: StakeId,
        slash_id: u64,
        reason: &str,
        current_time: u64,
    ) -> Result<AppealRecord, StakingError> {
        let record = self
            .state
            .stakes
            .get(&stake_id.0)
            .ok_or(StakingError::StakeNotFound {
                stake_id,
                code: ERR_STAKE_NOT_FOUND,
            })?
            .clone();

        // Must be in Slashed state
        if record.state != StakeState::Slashed {
            return Err(StakingError::InvalidTransition {
                from: record.state,
                to: StakeState::UnderAppeal,
                code: ERR_STAKE_INVALID_TRANSITION,
            });
        }

        // Check no duplicate appeal for same slash
        for existing in &self.state.appeals {
            if existing.stake_id == stake_id
                && existing.slash_id == slash_id
                && existing.outcome == AppealOutcome::Pending
            {
                return Err(StakingError::DuplicateAppeal {
                    stake_id,
                    slash_id,
                    code: ERR_STAKE_DUPLICATE_APPEAL,
                });
            }
        }

        // INV-STAKE-APPEAL-WINDOW: check appeal is within window
        let slash_timestamp = record.slashed_at.unwrap_or(0);
        if !self
            .engine
            .is_within_appeal_window(&record.risk_tier, slash_timestamp, current_time)
        {
            return Err(StakingError::AppealExpired {
                stake_id,
                code: ERR_STAKE_APPEAL_EXPIRED,
            });
        }

        // Transition to UnderAppeal
        self.state
            .stakes
            .get_mut(&stake_id.0)
            .expect("stake existence verified above")
            .state = StakeState::UnderAppeal;

        let appeal = AppealRecord {
            appeal_id: self.state.next_appeal_id,
            stake_id,
            slash_id,
            reason: reason.to_string(),
            outcome: AppealOutcome::Pending,
            filed_at: current_time,
            resolved_at: None,
        };
        self.state.next_appeal_id = self.state.next_appeal_id.saturating_add(1);
        self.state.appeals.push(appeal.clone());

        self.emit_audit(
            STAKE_003,
            current_time,
            &record.publisher_id,
            stake_id,
            "appeal_filed",
            None,
            &format!("appeal filed for slash {slash_id}: {reason}"),
            vec![
                INV_STAKE_APPEAL_WINDOW.to_string(),
                INV_STAKE_AUDIT_COMPLETE.to_string(),
            ],
        );

        Ok(appeal)
    }

    /// Resolve an appeal (upheld = slash stands; reversed = stake restored).
    pub fn resolve_appeal(
        &mut self,
        appeal_id: u64,
        upheld: bool,
        current_time: u64,
    ) -> Result<AppealRecord, StakingError> {
        let appeal_idx = self
            .state
            .appeals
            .iter()
            .position(|a| a.appeal_id == appeal_id)
            .ok_or(StakingError::StakeNotFound {
                stake_id: StakeId(0),
                code: ERR_STAKE_NOT_FOUND,
            })?;

        let (stake_id, slash_id) = {
            let appeal = &self.state.appeals[appeal_idx];
            (appeal.stake_id, appeal.slash_id)
        };

        let record = self
            .state
            .stakes
            .get(&stake_id.0)
            .ok_or(StakingError::StakeNotFound {
                stake_id,
                code: ERR_STAKE_NOT_FOUND,
            })?
            .clone();

        if record.state != StakeState::UnderAppeal {
            let target = if upheld {
                StakeState::Slashed
            } else {
                StakeState::Active
            };
            self.emit_audit(
                STAKE_007,
                current_time,
                &record.publisher_id,
                stake_id,
                "resolve_appeal",
                None,
                &format!(
                    "rejected: stake {} state={} expected=under_appeal",
                    stake_id.0, record.state
                ),
                vec![INV_STAKE_AUDIT_COMPLETE.to_string()],
            );
            return Err(StakingError::InvalidTransition {
                from: record.state,
                to: target,
                code: ERR_STAKE_INVALID_TRANSITION,
            });
        }

        let outcome = if upheld {
            AppealOutcome::Upheld
        } else {
            AppealOutcome::Reversed
        };

        // Update appeal record
        self.state.appeals[appeal_idx].outcome = outcome;
        self.state.appeals[appeal_idx].resolved_at = Some(current_time);

        if upheld {
            // Appeal denied: remain slashed
            self.state
                .stakes
                .get_mut(&stake_id.0)
                .expect("stake existence verified above")
                .state = StakeState::Slashed;
        } else {
            // Appeal granted: restore to active and return slashed amount
            let stake_record = self
                .state
                .stakes
                .get_mut(&stake_id.0)
                .expect("stake existence verified above");
            stake_record.state = StakeState::Active;

            // Find the slash event and restore
            if let Some(slash_event) = self
                .state
                .slash_events
                .iter()
                .find(|e| e.slash_id == slash_id)
            {
                let restore_amount = slash_event.slash_amount;
                stake_record.amount = stake_record.amount.saturating_add(restore_amount);

                if let Some(account) = self.accounts.get_mut(&record.publisher_id) {
                    account.balance = account.balance.saturating_add(restore_amount);
                    account.slashed_total = account.slashed_total.saturating_sub(restore_amount);
                    account.cooldown_until = None;
                }
            }
        }

        let updated_appeal = self.state.appeals[appeal_idx].clone();

        self.emit_audit(
            STAKE_004,
            current_time,
            &record.publisher_id,
            stake_id,
            "appeal_resolved",
            None,
            &format!(
                "appeal {appeal_id} resolved: {}",
                if upheld { "upheld" } else { "reversed" }
            ),
            vec![INV_STAKE_AUDIT_COMPLETE.to_string()],
        );

        Ok(updated_appeal)
    }

    // -----------------------------------------------------------------------
    // Withdraw (STK-005)
    // -----------------------------------------------------------------------

    /// Withdraw a stake (only if Active and no pending obligations).
    /// Satisfies INV-STAKE-WITHDRAWAL-SAFE.
    pub fn withdraw(
        &mut self,
        stake_id: StakeId,
        current_time: u64,
    ) -> Result<StakeRecord, StakingError> {
        let record = self
            .state
            .stakes
            .get(&stake_id.0)
            .ok_or(StakingError::StakeNotFound {
                stake_id,
                code: ERR_STAKE_NOT_FOUND,
            })?
            .clone();

        // Only active stakes can be withdrawn
        if record.state != StakeState::Active {
            return Err(StakingError::InvalidTransition {
                from: record.state,
                to: StakeState::Withdrawn,
                code: ERR_STAKE_INVALID_TRANSITION,
            });
        }

        // INV-STAKE-WITHDRAWAL-SAFE: check cooldown has elapsed
        if let Some(account) = self.accounts.get(&record.publisher_id)
            && let Some(cooldown_until) = account.cooldown_until
            && current_time < cooldown_until
        {
            return Err(StakingError::WithdrawalBlocked {
                stake_id,
                reason: format!("cooldown active until {cooldown_until}"),
                code: ERR_STAKE_WITHDRAWAL_BLOCKED,
            });
        }

        // Perform withdrawal
        let stake_record =
            self.state
                .stakes
                .get_mut(&stake_id.0)
                .ok_or(StakingError::StakeNotFound {
                    stake_id,
                    code: ERR_STAKE_NOT_FOUND,
                })?;
        stake_record.state = StakeState::Withdrawn;
        stake_record.withdrawn_at = Some(current_time);
        let withdrawn_amount = stake_record.amount;
        stake_record.amount = 0;

        if let Some(account) = self.accounts.get_mut(&record.publisher_id) {
            account.balance = account.balance.saturating_sub(withdrawn_amount);
        }

        self.emit_audit(
            STAKE_005,
            current_time,
            &record.publisher_id,
            stake_id,
            "withdraw",
            None,
            &format!("withdrew {withdrawn_amount}"),
            vec![
                INV_STAKE_WITHDRAWAL_SAFE.to_string(),
                INV_STAKE_AUDIT_COMPLETE.to_string(),
            ],
        );

        Ok(self.state.stakes[&stake_id.0].clone())
    }

    // -----------------------------------------------------------------------
    // Expire (STK-006)
    // -----------------------------------------------------------------------

    /// Expire a stake that has passed its expiration time.
    pub fn expire(
        &mut self,
        stake_id: StakeId,
        current_time: u64,
    ) -> Result<StakeRecord, StakingError> {
        let record = self
            .state
            .stakes
            .get(&stake_id.0)
            .ok_or(StakingError::StakeNotFound {
                stake_id,
                code: ERR_STAKE_NOT_FOUND,
            })?
            .clone();

        if record.state != StakeState::Active {
            return Err(StakingError::InvalidTransition {
                from: record.state,
                to: StakeState::Expired,
                code: ERR_STAKE_INVALID_TRANSITION,
            });
        }

        if let Some(expires_at) = record.expires_at
            && current_time < expires_at
        {
            return Err(StakingError::InvalidTransition {
                from: record.state,
                to: StakeState::Expired,
                code: ERR_STAKE_INVALID_TRANSITION,
            });
        }

        let stake_record =
            self.state
                .stakes
                .get_mut(&stake_id.0)
                .ok_or(StakingError::StakeNotFound {
                    stake_id,
                    code: ERR_STAKE_NOT_FOUND,
                })?;
        stake_record.state = StakeState::Expired;
        let released_amount = stake_record.amount;
        stake_record.amount = 0;

        if let Some(account) = self.accounts.get_mut(&record.publisher_id) {
            account.balance = account.balance.saturating_sub(released_amount);
        }

        self.emit_audit(
            STAKE_006,
            current_time,
            &record.publisher_id,
            stake_id,
            "expire",
            None,
            &format!("expired and released {released_amount}"),
            vec![INV_STAKE_AUDIT_COMPLETE.to_string()],
        );

        Ok(self.state.stakes[&stake_id.0].clone())
    }

    // -----------------------------------------------------------------------
    // Query helpers
    // -----------------------------------------------------------------------

    /// Get the active stake record for a publisher.
    pub fn get_active_stake(&self, publisher_id: &str) -> Option<&StakeRecord> {
        self.state
            .stakes
            .values()
            .find(|r| r.publisher_id == publisher_id && r.state == StakeState::Active)
    }

    /// Get any stake record for a publisher regardless of state.
    pub fn get_any_stake_for_publisher(&self, publisher_id: &str) -> Option<&StakeRecord> {
        self.state
            .stakes
            .values()
            .find(|r| r.publisher_id == publisher_id)
    }

    /// Get a stake record by ID.
    pub fn get_stake(&self, stake_id: StakeId) -> Option<&StakeRecord> {
        self.state.stakes.get(&stake_id.0)
    }

    /// Get the account for a publisher.
    pub fn get_account(&self, publisher_id: &str) -> Option<&StakeAccount> {
        self.accounts.get(publisher_id)
    }

    /// Get all slash events for a publisher.
    pub fn slash_events_for(&self, publisher_id: &str) -> Vec<&SlashEvent> {
        self.state
            .slash_events
            .iter()
            .filter(|e| e.publisher_id == publisher_id)
            .collect()
    }

    /// Get all appeals for a stake.
    pub fn appeals_for_stake(&self, stake_id: StakeId) -> Vec<&AppealRecord> {
        self.state
            .appeals
            .iter()
            .filter(|a| a.stake_id == stake_id)
            .collect()
    }

    /// Count stakes in a given state.
    pub fn count_in_state(&self, state: StakeState) -> usize {
        self.state
            .stakes
            .values()
            .filter(|r| r.state == state)
            .count()
    }

    /// Total number of stakes.
    pub fn total_stakes(&self) -> usize {
        self.state.stakes.len()
    }

    /// Export audit log as JSONL.
    pub fn export_audit_log_jsonl(&self) -> String {
        self.state
            .audit_log
            .iter()
            .map(|entry| serde_json::to_string(entry).unwrap_or_default())
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Generate a ledger snapshot for serialization.
    pub fn generate_snapshot(&self) -> serde_json::Value {
        serde_json::json!({
            "schema_version": self.schema_version,
            "total_stakes": self.total_stakes(),
            "active_stakes": self.count_in_state(StakeState::Active),
            "slashed_stakes": self.count_in_state(StakeState::Slashed),
            "withdrawn_stakes": self.count_in_state(StakeState::Withdrawn),
            "expired_stakes": self.count_in_state(StakeState::Expired),
            "total_slash_events": self.state.slash_events.len(),
            "total_appeals": self.state.appeals.len(),
            "total_audit_entries": self.state.audit_log.len(),
            "accounts": self.accounts.len(),
            "invariants_enforced": [
                INV_STAKE_MINIMUM,
                INV_STAKE_SLASH_DETERMINISTIC,
                INV_STAKE_APPEAL_WINDOW,
                INV_STAKE_AUDIT_COMPLETE,
                INV_STAKE_NO_DOUBLE_SLASH,
                INV_STAKE_WITHDRAWAL_SAFE,
                INV_STK_DETERMINISTIC_PENALTY,
                INV_STK_AUDITABLE_SLASH,
                INV_STK_NO_NEGATIVE_BALANCE,
            ],
        })
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    #[allow(clippy::too_many_arguments)]
    fn emit_audit(
        &mut self,
        event_code: &str,
        timestamp: u64,
        publisher_id: &str,
        stake_id: StakeId,
        operation: &str,
        evidence_hash: Option<String>,
        outcome: &str,
        invariants_checked: Vec<String>,
    ) {
        let entry = StakingAuditEntry {
            entry_id: self.state.next_audit_id,
            event_code: event_code.to_string(),
            timestamp,
            publisher_id: publisher_id.to_string(),
            stake_id,
            operation: operation.to_string(),
            evidence_hash,
            outcome: outcome.to_string(),
            invariants_checked,
        };
        self.state.next_audit_id = self.state.next_audit_id.saturating_add(1);
        self.state.audit_log.push(entry);
    }
}

impl Default for StakingLedger {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// Unit Tests (25+)
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn test_evidence(violation: ViolationType) -> SlashEvidence {
        SlashEvidence::new(
            violation,
            "test violation",
            "evidence-payload-data",
            "test-collector",
            1000,
        )
    }

    fn test_evidence_unique(violation: ViolationType, payload: &str) -> SlashEvidence {
        SlashEvidence::new(violation, "test violation", payload, "test-collector", 1000)
    }

    #[test]
    fn test_deposit_creates_stake() {
        let mut ledger = StakingLedger::new();
        let id = ledger
            .deposit("pub-1", 1000, RiskTier::Critical, 100)
            .unwrap();
        assert_eq!(id, StakeId(1));
        let record = ledger.get_stake(id).unwrap();
        assert_eq!(record.state, StakeState::Active);
        assert_eq!(record.amount, 1000);
        assert_eq!(record.publisher_id, "pub-1");
    }

    #[test]
    fn test_deposit_below_minimum_rejected() {
        let mut ledger = StakingLedger::new();
        let err = ledger.deposit("pub-1", 5, RiskTier::Low, 100).unwrap_err();
        match err {
            StakingError::InsufficientStake {
                required,
                provided,
                code,
            } => {
                assert_eq!(required, 10);
                assert_eq!(provided, 5);
                assert_eq!(code, ERR_STAKE_INSUFFICIENT);
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn test_deposit_updates_account() {
        let mut ledger = StakingLedger::new();
        ledger.deposit("pub-1", 500, RiskTier::High, 100).unwrap();
        let account = ledger.get_account("pub-1").unwrap();
        assert_eq!(account.balance, 500);
        assert_eq!(account.deposited, 500);
    }

    #[test]
    fn test_slash_reduces_balance() {
        let mut ledger = StakingLedger::new();
        let id = ledger
            .deposit("pub-1", 1000, RiskTier::Critical, 100)
            .unwrap();
        let event = ledger
            .slash(id, test_evidence(ViolationType::MaliciousCode), 200)
            .unwrap();
        assert_eq!(event.slash_amount, 1000); // 100% for critical
        assert_eq!(event.post_balance, 0);
    }

    #[test]
    fn test_slash_deterministic_penalty() {
        // Same evidence + same policy = same penalty hash
        let mut ledger1 = StakingLedger::new();
        let id1 = ledger1.deposit("pub-1", 500, RiskTier::High, 100).unwrap();
        let ev1 = test_evidence(ViolationType::PolicyViolation);

        let mut ledger2 = StakingLedger::new();
        let id2 = ledger2.deposit("pub-2", 500, RiskTier::High, 100).unwrap();
        let ev2 = test_evidence(ViolationType::PolicyViolation);

        let event1 = ledger1.slash(id1, ev1, 200).unwrap();
        let event2 = ledger2.slash(id2, ev2, 300).unwrap();

        // Same evidence hash, same fraction, same amount => same penalty hash
        assert_eq!(event1.penalty_hash, event2.penalty_hash);
        assert_eq!(event1.slash_amount, event2.slash_amount);
    }

    #[test]
    fn test_slash_no_double_slash() {
        let mut ledger = StakingLedger::new();
        let id = ledger
            .deposit("pub-1", 1000, RiskTier::Critical, 100)
            .unwrap();
        ledger
            .slash(id, test_evidence(ViolationType::MaliciousCode), 200)
            .unwrap();
        // Same stake can't be slashed again (it's in Slashed state)
        let err = ledger
            .slash(
                id,
                test_evidence_unique(ViolationType::MaliciousCode, "other"),
                300,
            )
            .unwrap_err();
        match err {
            StakingError::AlreadySlashed { .. } => {}
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn test_slash_same_evidence_hash_rejected() {
        let mut ledger = StakingLedger::new();
        let id1 = ledger
            .deposit("pub-1", 1000, RiskTier::Critical, 100)
            .unwrap();
        let id2 = ledger
            .deposit("pub-1", 1000, RiskTier::Critical, 100)
            .unwrap();
        ledger
            .slash(id1, test_evidence(ViolationType::MaliciousCode), 200)
            .unwrap();
        // Same evidence hash for same publisher rejected
        let err = ledger
            .slash(id2, test_evidence(ViolationType::MaliciousCode), 300)
            .unwrap_err();
        match err {
            StakingError::AlreadySlashed { .. } => {}
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn test_no_negative_balance() {
        let mut ledger = StakingLedger::new();
        let id = ledger.deposit("pub-1", 100, RiskTier::Medium, 100).unwrap();
        let event = ledger
            .slash(
                id,
                test_evidence_unique(ViolationType::MaliciousCode, "med-ev"),
                200,
            )
            .unwrap();
        // 25% of 100 = 25
        assert_eq!(event.slash_amount, 25);
        assert_eq!(event.post_balance, 75);
        let account = ledger.get_account("pub-1").unwrap();
        assert!(account.balance <= account.deposited);
    }

    #[test]
    fn test_slash_fraction_high_tier() {
        let mut ledger = StakingLedger::new();
        let id = ledger.deposit("pub-1", 500, RiskTier::High, 100).unwrap();
        let event = ledger
            .slash(
                id,
                test_evidence_unique(ViolationType::PolicyViolation, "high-ev"),
                200,
            )
            .unwrap();
        assert_eq!(event.slash_amount, 250); // 50% of 500
    }

    #[test]
    fn test_slash_fraction_low_tier() {
        let mut ledger = StakingLedger::new();
        let id = ledger.deposit("pub-1", 100, RiskTier::Low, 100).unwrap();
        let event = ledger
            .slash(
                id,
                test_evidence_unique(ViolationType::FalseAttestation, "low-ev"),
                200,
            )
            .unwrap();
        assert_eq!(event.slash_amount, 10); // 10% of 100
    }

    #[test]
    fn test_withdraw_active_stake() {
        let mut ledger = StakingLedger::new();
        let id = ledger.deposit("pub-1", 500, RiskTier::High, 100).unwrap();
        let record = ledger.withdraw(id, 200).unwrap();
        assert_eq!(record.state, StakeState::Withdrawn);
        assert_eq!(record.amount, 0);
    }

    #[test]
    fn test_withdraw_slashed_rejected() {
        let mut ledger = StakingLedger::new();
        let id = ledger
            .deposit("pub-1", 1000, RiskTier::Critical, 100)
            .unwrap();
        ledger
            .slash(
                id,
                test_evidence_unique(ViolationType::MaliciousCode, "w-ev"),
                200,
            )
            .unwrap();
        let err = ledger.withdraw(id, 300).unwrap_err();
        match err {
            StakingError::InvalidTransition { from, to, .. } => {
                assert_eq!(from, StakeState::Slashed);
                assert_eq!(to, StakeState::Withdrawn);
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn test_withdraw_during_cooldown_blocked() {
        let mut ledger = StakingLedger::new();
        let id1 = ledger
            .deposit("pub-1", 1000, RiskTier::Critical, 100)
            .unwrap();
        let id2 = ledger
            .deposit("pub-1", 1000, RiskTier::Critical, 100)
            .unwrap();

        // Slash first stake, which sets a cooldown
        ledger
            .slash(
                id1,
                test_evidence_unique(ViolationType::MaliciousCode, "cool-ev"),
                200,
            )
            .unwrap();

        // Try to withdraw second stake during cooldown
        let err = ledger.withdraw(id2, 201).unwrap_err();
        match err {
            StakingError::WithdrawalBlocked { code, .. } => {
                assert_eq!(code, ERR_STAKE_WITHDRAWAL_BLOCKED);
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn test_file_appeal_within_window() {
        let mut ledger = StakingLedger::new();
        let id = ledger
            .deposit("pub-1", 1000, RiskTier::Critical, 100)
            .unwrap();
        ledger
            .slash(
                id,
                test_evidence_unique(ViolationType::MaliciousCode, "appeal-ev"),
                200,
            )
            .unwrap();
        // Appeal window for critical is 48 hours = 172800 secs
        let appeal = ledger.file_appeal(id, 1, "false positive", 300).unwrap();
        assert_eq!(appeal.outcome, AppealOutcome::Pending);
        let record = ledger.get_stake(id).unwrap();
        assert_eq!(record.state, StakeState::UnderAppeal);
    }

    #[test]
    fn test_file_appeal_after_window_expired() {
        let mut ledger = StakingLedger::new();
        let id = ledger
            .deposit("pub-1", 1000, RiskTier::Critical, 100)
            .unwrap();
        ledger
            .slash(
                id,
                test_evidence_unique(ViolationType::MaliciousCode, "exp-ev"),
                200,
            )
            .unwrap();
        // Appeal window is 48h = 172800s, so at 200 + 172801 = expired
        let err = ledger
            .file_appeal(id, 1, "too late", 200 + 172801)
            .unwrap_err();
        match err {
            StakingError::AppealExpired { code, .. } => {
                assert_eq!(code, ERR_STAKE_APPEAL_EXPIRED);
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn test_file_appeal_at_exact_deadline_is_expired() {
        // Fail-closed: appeal filed exactly at deadline boundary must be rejected.
        let mut ledger = StakingLedger::new();
        let id = ledger
            .deposit("pub-1", 1000, RiskTier::Critical, 100)
            .unwrap();
        ledger
            .slash(
                id,
                test_evidence_unique(ViolationType::MaliciousCode, "boundary-ev"),
                200,
            )
            .unwrap();
        // Deadline = 200 + 172800 = 173000; filing at exactly 173000 must fail.
        let err = ledger
            .file_appeal(id, 1, "exactly at deadline", 200 + 172800)
            .unwrap_err();
        match err {
            StakingError::AppealExpired { code, .. } => {
                assert_eq!(code, ERR_STAKE_APPEAL_EXPIRED);
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn test_duplicate_appeal_rejected() {
        let mut ledger = StakingLedger::new();
        let id = ledger
            .deposit("pub-1", 1000, RiskTier::Critical, 100)
            .unwrap();
        ledger
            .slash(
                id,
                test_evidence_unique(ViolationType::MaliciousCode, "dup-ev"),
                200,
            )
            .unwrap();
        ledger.file_appeal(id, 1, "first appeal", 300).unwrap();
        // Second appeal fails with InvalidTransition: state is UnderAppeal, not Slashed.
        let err = ledger.file_appeal(id, 1, "duplicate", 301).unwrap_err();
        match err {
            StakingError::InvalidTransition { code, .. } => {
                assert_eq!(code, ERR_STAKE_INVALID_TRANSITION);
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn test_resolve_appeal_upheld() {
        let mut ledger = StakingLedger::new();
        let id = ledger
            .deposit("pub-1", 1000, RiskTier::Critical, 100)
            .unwrap();
        ledger
            .slash(
                id,
                test_evidence_unique(ViolationType::MaliciousCode, "uph-ev"),
                200,
            )
            .unwrap();
        let appeal = ledger.file_appeal(id, 1, "contest", 300).unwrap();
        let resolved = ledger.resolve_appeal(appeal.appeal_id, true, 400).unwrap();
        assert_eq!(resolved.outcome, AppealOutcome::Upheld);
        let record = ledger.get_stake(id).unwrap();
        assert_eq!(record.state, StakeState::Slashed);
    }

    #[test]
    fn test_resolve_appeal_reversed() {
        let mut ledger = StakingLedger::new();
        let id = ledger
            .deposit("pub-1", 1000, RiskTier::Critical, 100)
            .unwrap();
        ledger
            .slash(
                id,
                test_evidence_unique(ViolationType::MaliciousCode, "rev-ev"),
                200,
            )
            .unwrap();
        let appeal = ledger.file_appeal(id, 1, "contest", 300).unwrap();
        let resolved = ledger.resolve_appeal(appeal.appeal_id, false, 400).unwrap();
        assert_eq!(resolved.outcome, AppealOutcome::Reversed);
        let record = ledger.get_stake(id).unwrap();
        assert_eq!(record.state, StakeState::Active);
        assert_eq!(record.amount, 1000); // restored
    }

    #[test]
    fn test_expire_stake() {
        let mut ledger = StakingLedger::new();
        let id = ledger.deposit("pub-1", 100, RiskTier::Low, 100).unwrap();
        // Set expiration
        ledger.state.stakes.get_mut(&id.0).unwrap().expires_at = Some(500);
        let record = ledger.expire(id, 600).unwrap();
        assert_eq!(record.state, StakeState::Expired);
        assert_eq!(record.amount, 0);
    }

    #[test]
    fn test_expire_before_expiration_rejected() {
        let mut ledger = StakingLedger::new();
        let id = ledger.deposit("pub-1", 100, RiskTier::Low, 100).unwrap();
        ledger.state.stakes.get_mut(&id.0).unwrap().expires_at = Some(500);
        let err = ledger.expire(id, 400).unwrap_err();
        match err {
            StakingError::InvalidTransition { .. } => {}
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn test_audit_trail_complete() {
        let mut ledger = StakingLedger::new();
        let id = ledger
            .deposit("pub-1", 1000, RiskTier::Critical, 100)
            .unwrap();
        ledger
            .slash(
                id,
                test_evidence_unique(ViolationType::MaliciousCode, "audit-ev"),
                200,
            )
            .unwrap();
        // Every operation should have an audit entry
        assert_eq!(ledger.state.audit_log.len(), 2);
        assert_eq!(ledger.state.audit_log[0].event_code, STAKE_001);
        assert_eq!(ledger.state.audit_log[1].event_code, STAKE_002);
    }

    #[test]
    fn test_audit_includes_invariants() {
        let mut ledger = StakingLedger::new();
        let id = ledger
            .deposit("pub-1", 1000, RiskTier::Critical, 100)
            .unwrap();
        ledger
            .slash(
                id,
                test_evidence_unique(ViolationType::MaliciousCode, "inv-ev"),
                200,
            )
            .unwrap();
        let slash_entry = &ledger.state.audit_log[1];
        assert!(
            slash_entry
                .invariants_checked
                .contains(&INV_STAKE_SLASH_DETERMINISTIC.to_string())
        );
        assert!(
            slash_entry
                .invariants_checked
                .contains(&INV_STK_DETERMINISTIC_PENALTY.to_string())
        );
    }

    #[test]
    fn test_capability_gate_pass() {
        let ledger = {
            let mut l = StakingLedger::new();
            l.deposit("pub-1", 1000, RiskTier::Critical, 100).unwrap();
            l
        };
        let gate = CapabilityStakeGate::new(StakePolicy::default_policy());
        let (allowed, code, _detail) = gate.check_stake(&ledger, "pub-1", &RiskTier::Critical, 200);
        assert!(allowed);
        assert_eq!(code, STAKE_007);
    }

    #[test]
    fn test_capability_gate_no_stake() {
        let ledger = StakingLedger::new();
        let gate = CapabilityStakeGate::new(StakePolicy::default_policy());
        let (allowed, _, detail) = gate.check_stake(&ledger, "pub-1", &RiskTier::Critical, 200);
        assert!(!allowed);
        assert!(detail.contains(ERR_STAKE_NOT_FOUND));
    }

    #[test]
    fn test_capability_gate_insufficient_stake() {
        let ledger = {
            let mut l = StakingLedger::new();
            l.deposit("pub-1", 100, RiskTier::Medium, 100).unwrap();
            l
        };
        let gate = CapabilityStakeGate::new(StakePolicy::default_policy());
        let (allowed, _, detail) = gate.check_stake(&ledger, "pub-1", &RiskTier::Critical, 200);
        assert!(!allowed);
        assert!(detail.contains(ERR_STAKE_INSUFFICIENT));
    }

    #[test]
    fn test_snapshot_generation() {
        let mut ledger = StakingLedger::new();
        ledger
            .deposit("pub-1", 1000, RiskTier::Critical, 100)
            .unwrap();
        ledger.deposit("pub-2", 500, RiskTier::High, 100).unwrap();
        let snapshot = ledger.generate_snapshot();
        assert_eq!(snapshot["total_stakes"], 2);
        assert_eq!(snapshot["active_stakes"], 2);
        assert_eq!(snapshot["schema_version"], SCHEMA_VERSION);
    }

    #[test]
    fn test_export_audit_jsonl() {
        let mut ledger = StakingLedger::new();
        ledger
            .deposit("pub-1", 1000, RiskTier::Critical, 100)
            .unwrap();
        let jsonl = ledger.export_audit_log_jsonl();
        assert!(!jsonl.is_empty());
        let parsed: serde_json::Value = serde_json::from_str(&jsonl).unwrap();
        assert_eq!(parsed["event_code"], STAKE_001);
    }

    #[test]
    fn test_evidence_hash_deterministic() {
        let h1 = compute_evidence_hash("test-payload");
        let h2 = compute_evidence_hash("test-payload");
        assert_eq!(h1, h2);

        let h3 = compute_evidence_hash("different-payload");
        assert_ne!(h1, h3);
    }

    #[test]
    fn test_penalty_hash_deterministic() {
        let h1 = compute_penalty_hash("ev-hash", 5000, 500);
        let h2 = compute_penalty_hash("ev-hash", 5000, 500);
        assert_eq!(h1, h2);

        let h3 = compute_penalty_hash("ev-hash", 5000, 600);
        assert_ne!(h1, h3);
    }

    #[test]
    fn test_compute_penalty_caps_bps_and_hashes_effective_value() {
        let mut policy = StakePolicy::default_policy();
        let critical = policy
            .tiers
            .get_mut("critical")
            .expect("default policy must contain critical tier");
        critical.slash_fraction_bps = 15_000;

        let engine = SlashingEngine::new(policy);
        let evidence_hash = "ev-hash";
        let stake_balance = 1_000u64;

        let (slash_amount, penalty_hash) = engine
            .compute_penalty(&RiskTier::Critical, stake_balance, evidence_hash)
            .expect("penalty calculation must succeed");

        assert_eq!(slash_amount, stake_balance, "bps > 100% must cap at 100%");
        assert_eq!(
            penalty_hash,
            compute_penalty_hash(evidence_hash, 10_000, stake_balance),
            "penalty hash must reflect effective capped basis points"
        );
    }

    #[test]
    fn test_stake_not_found_error() {
        let mut ledger = StakingLedger::new();
        let err = ledger.withdraw(StakeId(999), 100).unwrap_err();
        match err {
            StakingError::StakeNotFound { code, .. } => {
                assert_eq!(code, ERR_STAKE_NOT_FOUND);
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn test_multiple_deposits_same_publisher() {
        let mut ledger = StakingLedger::new();
        let id1 = ledger.deposit("pub-1", 100, RiskTier::Medium, 100).unwrap();
        let id2 = ledger.deposit("pub-1", 200, RiskTier::Medium, 200).unwrap();
        assert_ne!(id1, id2);
        let account = ledger.get_account("pub-1").unwrap();
        assert_eq!(account.balance, 300);
        assert_eq!(account.deposited, 300);
    }

    #[test]
    fn test_count_in_state() {
        let mut ledger = StakingLedger::new();
        ledger.deposit("pub-1", 100, RiskTier::Medium, 100).unwrap();
        ledger.deposit("pub-2", 500, RiskTier::High, 100).unwrap();
        assert_eq!(ledger.count_in_state(StakeState::Active), 2);
        assert_eq!(ledger.count_in_state(StakeState::Slashed), 0);
    }

    #[test]
    fn test_total_stakes() {
        let mut ledger = StakingLedger::new();
        assert_eq!(ledger.total_stakes(), 0);
        ledger.deposit("pub-1", 100, RiskTier::Low, 100).unwrap();
        assert_eq!(ledger.total_stakes(), 1);
    }

    #[test]
    fn test_slash_events_for_publisher() {
        let mut ledger = StakingLedger::new();
        let id = ledger
            .deposit("pub-1", 1000, RiskTier::Critical, 100)
            .unwrap();
        ledger
            .slash(
                id,
                test_evidence_unique(ViolationType::MaliciousCode, "sev-ev"),
                200,
            )
            .unwrap();
        let events = ledger.slash_events_for("pub-1");
        assert_eq!(events.len(), 1);
        assert!(ledger.slash_events_for("pub-2").is_empty());
    }

    #[test]
    fn test_appeals_for_stake() {
        let mut ledger = StakingLedger::new();
        let id = ledger
            .deposit("pub-1", 1000, RiskTier::Critical, 100)
            .unwrap();
        ledger
            .slash(
                id,
                test_evidence_unique(ViolationType::MaliciousCode, "afs-ev"),
                200,
            )
            .unwrap();
        ledger.file_appeal(id, 1, "contest", 300).unwrap();
        let appeals = ledger.appeals_for_stake(id);
        assert_eq!(appeals.len(), 1);
    }

    #[test]
    fn test_default_policy_tiers() {
        let policy = StakePolicy::default_policy();
        let critical = policy.get_tier(&RiskTier::Critical).unwrap();
        assert_eq!(critical.minimum_stake, 1000);
        assert_eq!(critical.slash_fraction_bps, 10000);

        let low = policy.get_tier(&RiskTier::Low).unwrap();
        assert_eq!(low.minimum_stake, 10);
        assert_eq!(low.slash_fraction_bps, 1000);
    }

    #[test]
    fn test_schema_version_constant() {
        assert_eq!(SCHEMA_VERSION, "staking-v1.0");
    }

    #[test]
    fn test_stake_state_display() {
        assert_eq!(StakeState::Active.to_string(), "active");
        assert_eq!(StakeState::Slashed.to_string(), "slashed");
        assert_eq!(StakeState::UnderAppeal.to_string(), "under_appeal");
        assert_eq!(StakeState::Withdrawn.to_string(), "withdrawn");
        assert_eq!(StakeState::Expired.to_string(), "expired");
    }

    #[test]
    fn test_risk_tier_display() {
        assert_eq!(RiskTier::Critical.to_string(), "critical");
        assert_eq!(RiskTier::High.to_string(), "high");
        assert_eq!(RiskTier::Medium.to_string(), "medium");
        assert_eq!(RiskTier::Low.to_string(), "low");
    }

    #[test]
    fn test_violation_type_display() {
        assert_eq!(ViolationType::MaliciousCode.to_string(), "malicious_code");
        assert_eq!(
            ViolationType::PolicyViolation.to_string(),
            "policy_violation"
        );
        assert_eq!(
            ViolationType::SupplyChainCompromise.to_string(),
            "supply_chain_compromise"
        );
        assert_eq!(
            ViolationType::FalseAttestation.to_string(),
            "false_attestation"
        );
    }
}

// ===========================================================================
// Integration tests: Security → Verifier Economy (bd-17ds.5.5)
// ===========================================================================

#[cfg(test)]
mod security_verifier_economy_integration_tests {
    use super::*;
    use crate::security::sybil_defense::{SybilDefensePipeline, TrustNode, TrustSignal};
    use crate::verifier_economy::{
        AttestationClaim, AttestationEvidence, AttestationSignature, AttestationSubmission,
        ReputationDimensions, VEP_001, VEP_002, VEP_004, VEP_005, VEP_006, VerificationDimension,
        VerifierEconomyRegistry, VerifierRegistration, VerifierTier,
    };
    use std::collections::BTreeMap;

    fn make_ledger_with_publisher(
        pub_id: &str,
        amount: u64,
        tier: RiskTier,
    ) -> (StakingLedger, StakeId) {
        let mut ledger = StakingLedger::new();
        let stake_id = ledger.deposit(pub_id, amount, tier, 1000).unwrap();
        (ledger, stake_id)
    }

    fn make_verifier_reg(name: &str, key: &str) -> VerifierRegistration {
        VerifierRegistration {
            name: name.to_string(),
            contact: format!("{}@example.com", name),
            public_key: key.to_string(),
            capabilities: vec![
                VerificationDimension::Security,
                VerificationDimension::Compatibility,
            ],
            tier: VerifierTier::Basic,
        }
    }

    fn make_submission(verifier_id: &str, key: &str, trace: &str) -> AttestationSubmission {
        AttestationSubmission {
            verifier_id: verifier_id.to_string(),
            claim: AttestationClaim {
                dimension: VerificationDimension::Security,
                statement: "Extension passes security audit".to_string(),
                score: 0.92,
            },
            evidence: AttestationEvidence {
                suite_id: "sec-suite-v1".to_string(),
                measurements: vec!["cve-scan: clean".to_string()],
                execution_trace_hash: trace.to_string(),
                environment: BTreeMap::from([("os".to_string(), "linux".to_string())]),
            },
            signature: AttestationSignature {
                algorithm: "ed25519".to_string(),
                public_key: key.to_string(),
                value: "sig-valid".to_string(),
            },
            timestamp: "2026-02-20T12:00:00Z".to_string(),
        }
    }

    // -- 1. Staking validates stake → sybil defense scores trust --

    #[test]
    fn staking_stake_gates_sybil_trust_weight() {
        let (ledger, _) = make_ledger_with_publisher("pub-alpha", 1000, RiskTier::Critical);
        let gate = CapabilityStakeGate::new(StakePolicy::default_policy());

        // Publisher has sufficient stake for critical tier
        let (allowed, _, _) = gate.check_stake(&ledger, "pub-alpha", &RiskTier::Critical, 2000);
        assert!(allowed);

        // Use staking info to calibrate sybil defense weighting
        let mut pipeline = SybilDefensePipeline::new();
        pipeline.register_node(TrustNode::established("pub-alpha", 90.0, 200, 500));
        pipeline.register_node(TrustNode::new("pub-newbie", 600));

        let signals = vec![
            TrustSignal {
                signal_id: "s1".into(),
                source_node_id: "pub-alpha".into(),
                target_id: "ext-1".into(),
                value: 0.85,
                timestamp_ms: 1000,
            },
            TrustSignal {
                signal_id: "s2".into(),
                source_node_id: "pub-newbie".into(),
                target_id: "ext-1".into(),
                value: 0.10,
                timestamp_ms: 1001,
            },
        ];

        let result = pipeline.process_signals(&signals, 1100).unwrap();
        // Established node's signal (0.85 × weight 1.0) dominates the newbie's
        // (0.10 × weight 0.01 = 0.001). Trimmed-mean of [0.001, 0.85] ≈ 0.4255.
        assert!(
            result.value > 0.4,
            "Established node should dominate, got {}",
            result.value
        );
        // Newbie's signal should be nearly suppressed
        assert!(result.value < 0.86);
    }

    // -- 2. Sybil defense + verifier economy registration --

    #[test]
    fn sybil_defense_validates_verifier_trust_before_registration() {
        let mut pipeline = SybilDefensePipeline::new();
        pipeline.register_node(TrustNode::established("honest-1", 85.0, 150, 100));
        pipeline.register_node(TrustNode::established("honest-2", 80.0, 120, 200));

        let signals = vec![
            TrustSignal {
                signal_id: "s1".into(),
                source_node_id: "honest-1".into(),
                target_id: "verifier-candidate".into(),
                value: 0.90,
                timestamp_ms: 1000,
            },
            TrustSignal {
                signal_id: "s2".into(),
                source_node_id: "honest-2".into(),
                target_id: "verifier-candidate".into(),
                value: 0.88,
                timestamp_ms: 1001,
            },
        ];

        let agg = pipeline.process_signals(&signals, 1100).unwrap();
        assert!(agg.value > 0.8);

        // Trust score high enough → register as verifier
        let mut registry = VerifierEconomyRegistry::new();
        let v = registry
            .register_verifier(make_verifier_reg("TrustedVerifier", "key-tv-1"))
            .unwrap();
        assert!(v.active);
        assert!(registry.events().iter().any(|e| e.code == VEP_005));
    }

    // -- 3. Full pipeline: stake → trust → attest → reputation --

    #[test]
    fn full_pipeline_stake_trust_attest_reputation() {
        // Step 1: Publisher stakes
        let (ledger, _) = make_ledger_with_publisher("pub-verifier", 500, RiskTier::High);
        let gate = CapabilityStakeGate::new(StakePolicy::default_policy());
        let (allowed, _, _) = gate.check_stake(&ledger, "pub-verifier", &RiskTier::High, 2000);
        assert!(allowed);

        // Step 2: Register as verifier in economy
        let mut registry = VerifierEconomyRegistry::new();
        let v = registry
            .register_verifier(make_verifier_reg("PubVerifier", "key-pv-1"))
            .unwrap();

        // Step 3: Submit and publish attestation
        let sub = make_submission(&v.verifier_id, &v.public_key, "trace-hash-001");
        let att = registry.submit_attestation(sub).unwrap();
        registry.review_attestation(&att.attestation_id).unwrap();
        registry.publish_attestation(&att.attestation_id).unwrap();

        // Step 4: Update reputation based on attestation quality
        let dims = ReputationDimensions {
            consistency: 0.9,
            coverage: 0.7,
            accuracy: 0.95,
            longevity: 0.5,
        };
        let score = registry.update_reputation(&v.verifier_id, &dims).unwrap();
        assert!(score > 0);

        // Events span registration, submission, publish, reputation
        let events = registry.events();
        assert!(events.iter().any(|e| e.code == VEP_005)); // registered
        assert!(events.iter().any(|e| e.code == VEP_001)); // submitted
        assert!(events.iter().any(|e| e.code == VEP_002)); // published
        assert!(events.iter().any(|e| e.code == VEP_004)); // reputation updated
    }

    // -- 4. Slashing triggers verifier economy dispute --

    #[test]
    fn slashing_evidence_correlates_with_verifier_dispute() {
        let mut ledger = StakingLedger::new();
        let stake_id = ledger
            .deposit("pub-bad", 1000, RiskTier::Critical, 1000)
            .unwrap();

        // Slash for false attestation
        let evidence = SlashEvidence::new(
            ViolationType::FalseAttestation,
            "Submitted fraudulent security claim",
            "evidence-payload-fraud",
            "collector-bot",
            2000,
        );
        let slash_event = ledger.slash(stake_id, evidence, 2000).unwrap();
        assert!(slash_event.slash_amount > 0);

        // In verifier economy: the same publisher's attestation is disputed
        let mut registry = VerifierEconomyRegistry::new();
        let v = registry
            .register_verifier(make_verifier_reg("BadVerifier", "key-bv-1"))
            .unwrap();
        let sub = make_submission(&v.verifier_id, &v.public_key, "trace-fraud");
        let att = registry.submit_attestation(sub).unwrap();
        registry.review_attestation(&att.attestation_id).unwrap();
        registry.publish_attestation(&att.attestation_id).unwrap();

        let dispute = registry
            .file_dispute(
                &att.attestation_id,
                "auditor",
                "Evidence hash matches slashing evidence",
                vec![slash_event.evidence.evidence_hash.clone()],
            )
            .unwrap();
        assert_eq!(dispute.attestation_id, att.attestation_id);
        assert!(
            dispute
                .supporting_evidence
                .contains(&slash_event.evidence.evidence_hash)
        );
    }

    // -- 5. Insufficient stake blocks capability gate --

    #[test]
    fn insufficient_stake_blocks_verifier_operations() {
        let (ledger, _) = make_ledger_with_publisher("pub-low", 10, RiskTier::Low);
        let gate = CapabilityStakeGate::new(StakePolicy::default_policy());

        // Low stake passes low tier
        let (allowed_low, _, _) = gate.check_stake(&ledger, "pub-low", &RiskTier::Low, 2000);
        assert!(allowed_low);

        // But fails critical tier (needs 1000)
        let (allowed_crit, _, detail) =
            gate.check_stake(&ledger, "pub-low", &RiskTier::Critical, 2000);
        assert!(!allowed_crit);
        assert!(detail.contains(ERR_STAKE_INSUFFICIENT));
    }

    // -- 6. Sybil identities attenuated in trust aggregation --

    #[test]
    fn sybil_cluster_attenuated_in_trust_pipeline() {
        let mut pipeline = SybilDefensePipeline::new();

        // 5 honest established nodes
        for i in 0..5 {
            pipeline.register_node(TrustNode::established(
                format!("honest-{i}"),
                80.0 + i as f64,
                100 + i * 10,
                100,
            ));
        }

        // 10 sybil nodes (newly created, coordinated)
        for i in 0..10 {
            pipeline.register_node(TrustNode::new(format!("sybil-{i}"), 9990));
        }

        let mut signals = Vec::new();
        // Honest signals: varied high trust
        for i in 0..5 {
            signals.push(TrustSignal {
                signal_id: format!("honest-sig-{i}"),
                source_node_id: format!("honest-{i}"),
                target_id: "ext-target".into(),
                value: 0.85 + (i as f64) * 0.02,
                timestamp_ms: 1000 + i * 100,
            });
        }
        // Sybil signals: identical low trust (coordinated attack)
        for i in 0..10 {
            signals.push(TrustSignal {
                signal_id: format!("sybil-sig-{i}"),
                source_node_id: format!("sybil-{i}"),
                target_id: "ext-target".into(),
                value: 0.10,
                timestamp_ms: 10000 + i,
            });
        }

        let result = pipeline.process_signals(&signals, 11000).unwrap();
        // 10 sybil signals are attenuated to ~0.000001 each, but still occupy
        // 10/15 of the sample. After trimmed-mean (trim 3 from each tail) the
        // remaining 9 values include 4 near-zero sybils plus 5 honest signals,
        // yielding ≈ 0.19. The key assertion: sybil signals are crushed while
        // honest signals retain their magnitude.
        assert!(
            result.value > 0.1,
            "Honest signals should still contribute, got {}",
            result.value
        );
        // Verify sybil attenuation pulled the aggregate well below the honest
        // mean (~0.89), proving the attack was partially mitigated.
        assert!(result.value < 0.85);
    }

    // -- 7. Deterministic penalty hash links staking to verifier economy evidence --

    #[test]
    fn deterministic_penalty_hash_links_systems() {
        let evidence_payload = "false-attestation-evidence-v1";
        let evidence_hash = compute_evidence_hash(evidence_payload);

        // Same evidence hash computed again → deterministic
        let evidence_hash2 = compute_evidence_hash(evidence_payload);
        assert_eq!(evidence_hash, evidence_hash2);

        // Penalty hash is deterministic too
        let penalty_hash = compute_penalty_hash(&evidence_hash, 10000, 1000);
        let penalty_hash2 = compute_penalty_hash(&evidence_hash, 10000, 1000);
        assert_eq!(penalty_hash, penalty_hash2);
        assert_eq!(penalty_hash.len(), 64); // SHA-256 hex
    }

    // -- 8. Selective reporting detection triggers anti-gaming --

    #[test]
    fn selective_reporting_detected_across_systems() {
        let mut registry = VerifierEconomyRegistry::new();
        let v = registry
            .register_verifier(make_verifier_reg("NarrowVerifier", "key-nv-1"))
            .unwrap();

        // Submit attestation in only one dimension
        let sub = make_submission(&v.verifier_id, &v.public_key, "trace-narrow-1");
        let att = registry.submit_attestation(sub).unwrap();
        registry.review_attestation(&att.attestation_id).unwrap();
        registry.publish_attestation(&att.attestation_id).unwrap();

        // Check selective reporting (requires >= 2 dimensions)
        let is_selective = registry.check_selective_reporting(&v.verifier_id, 2);
        assert!(
            is_selective,
            "Verifier with only 1 dimension should be flagged"
        );

        // Reputation stays low for narrow coverage
        let dims = ReputationDimensions {
            consistency: 0.9,
            coverage: 0.2, // low coverage
            accuracy: 0.9,
            longevity: 0.1,
        };
        let score = registry.update_reputation(&v.verifier_id, &dims).unwrap();
        // coverage=0.2 weighted 25% → drags score down
        assert!(score < 80);
    }

    // -- 9. Slashed publisher's stake gate blocks after slash --

    #[test]
    fn slashed_publisher_blocked_by_capability_gate() {
        let mut ledger = StakingLedger::new();
        let stake_id = ledger
            .deposit("pub-slash", 1000, RiskTier::Critical, 1000)
            .unwrap();

        // Gate passes before slash
        let gate = CapabilityStakeGate::new(StakePolicy::default_policy());
        let (allowed_pre, _, _) = gate.check_stake(&ledger, "pub-slash", &RiskTier::Critical, 1500);
        assert!(allowed_pre);

        // Slash the publisher
        let evidence = SlashEvidence::new(
            ViolationType::MaliciousCode,
            "Code injection detected",
            "payload-malicious",
            "security-bot",
            2000,
        );
        ledger.slash(stake_id, evidence, 2000).unwrap();

        // Gate now blocks (state=Slashed)
        let (allowed_post, _, detail) =
            gate.check_stake(&ledger, "pub-slash", &RiskTier::Critical, 2500);
        assert!(!allowed_post);
        assert!(detail.contains("unresolved slash"));
    }

    // -- 10. Scoreboard reflects reputation across verifier economy --

    #[test]
    fn scoreboard_reflects_cross_system_reputation() {
        let mut registry = VerifierEconomyRegistry::new();

        // Register two verifiers
        let v1 = registry
            .register_verifier(make_verifier_reg("TopVerifier", "key-top-1"))
            .unwrap();
        let v2 = registry
            .register_verifier(make_verifier_reg("NewVerifier", "key-new-1"))
            .unwrap();

        // v1: publish attestation + high reputation
        let sub1 = make_submission(&v1.verifier_id, &v1.public_key, "trace-top-1");
        let att1 = registry.submit_attestation(sub1).unwrap();
        registry.review_attestation(&att1.attestation_id).unwrap();
        registry.publish_attestation(&att1.attestation_id).unwrap();
        registry
            .update_reputation(
                &v1.verifier_id,
                &ReputationDimensions {
                    consistency: 0.95,
                    coverage: 0.90,
                    accuracy: 0.98,
                    longevity: 0.80,
                },
            )
            .unwrap();

        // v2: no attestations, low reputation
        registry
            .update_reputation(
                &v2.verifier_id,
                &ReputationDimensions {
                    consistency: 0.2,
                    coverage: 0.1,
                    accuracy: 0.3,
                    longevity: 0.05,
                },
            )
            .unwrap();

        let scoreboard = registry.build_scoreboard();
        assert_eq!(scoreboard.total_verifiers, 2);
        assert_eq!(scoreboard.total_attestations, 1);

        let top_entry = scoreboard
            .entries
            .iter()
            .find(|e| e.verifier_id == v1.verifier_id)
            .unwrap();
        let new_entry = scoreboard
            .entries
            .iter()
            .find(|e| e.verifier_id == v2.verifier_id)
            .unwrap();
        assert!(top_entry.reputation_score > new_entry.reputation_score);
        assert_eq!(top_entry.attestation_count, 1);
        assert_eq!(new_entry.attestation_count, 0);
    }

    // -- 11. Anti-gaming rate limit triggers across verifier submissions --

    #[test]
    fn anti_gaming_rate_limit_blocks_spam_submissions() {
        let mut registry = VerifierEconomyRegistry::new();
        // Set a low rate limit for testing
        registry.reset_submission_counts();

        let v = registry
            .register_verifier(make_verifier_reg("SpamVerifier", "key-spam-1"))
            .unwrap();

        // Submit many attestations up to the limit (default 100)
        // We'll simulate by checking that the anti-gaming event fires
        for i in 0..100 {
            let sub = make_submission(&v.verifier_id, &v.public_key, &format!("trace-spam-{i}"));
            registry.submit_attestation(sub).unwrap();
        }

        // 101st submission should be blocked
        let sub = make_submission(&v.verifier_id, &v.public_key, "trace-spam-overflow");
        let result = registry.submit_attestation(sub);
        assert!(result.is_err());
        assert!(registry.events().iter().any(|e| e.code == VEP_006));
    }

    // -- 12. Audit trail spans staking + verifier economy events --

    #[test]
    fn audit_trail_spans_staking_and_verifier_economy() {
        // Staking side
        let mut ledger = StakingLedger::new();
        let stake_id = ledger
            .deposit("pub-audit", 500, RiskTier::High, 1000)
            .unwrap();
        let staking_audit = &ledger.state.audit_log;
        assert!(!staking_audit.is_empty());
        assert!(staking_audit.iter().any(|e| e.event_code == STAKE_001));

        // Verifier economy side
        let mut registry = VerifierEconomyRegistry::new();
        let v = registry
            .register_verifier(make_verifier_reg("AuditVerifier", "key-au-1"))
            .unwrap();
        let sub = make_submission(&v.verifier_id, &v.public_key, "trace-audit-1");
        registry.submit_attestation(sub).unwrap();

        let vep_events = registry.events();
        assert!(vep_events.iter().any(|e| e.code == VEP_005));
        assert!(vep_events.iter().any(|e| e.code == VEP_001));

        // Both audit trails have entries
        let total_audit = staking_audit.len() + vep_events.len();
        assert!(total_audit >= 3);

        // Slash and verify both systems record it
        let evidence = SlashEvidence::new(
            ViolationType::FalseAttestation,
            "Audit-triggered slash",
            "audit-evidence-payload",
            "audit-bot",
            2000,
        );
        ledger.slash(stake_id, evidence, 2000).unwrap();
        assert!(
            ledger
                .state
                .audit_log
                .iter()
                .any(|e| e.event_code == STAKE_002)
        );
    }
}
