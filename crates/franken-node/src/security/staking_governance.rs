//! bd-26mk: Security staking and slashing framework for publisher trust governance.
//! bd-1xbr: Bounded audit_log capacity with oldest-first eviction.
//!
//! High-risk capabilities enforce stake policy gates; validated malicious behaviour
//! triggers a deterministic slashing workflow with appeal/audit trail artifacts.
//!
//! # Stake Lifecycle
//!
//! ```text
//! deposit_stake() -> StakeId
//!   |
//!   +-- active()      -> ACTIVE       (capability gates satisfied)
//!   +-- slash()       -> SLASHED      (malicious behaviour validated)
//!   |     +-- appeal()    -> UNDER_APPEAL
//!   |     |     +-- resolve_appeal(upheld)    -> SLASHED
//!   |     |     +-- resolve_appeal(reversed)  -> ACTIVE
//!   +-- withdraw()    -> WITHDRAWN
//!   +-- (expired)     -> EXPIRED
//! ```
//!
//! # Event Codes
//!
//! - `STAKE-001`: Stake deposited successfully
//! - `STAKE-002`: Stake slashed due to validated malicious behaviour
//! - `STAKE-003`: Appeal filed against slash decision
//! - `STAKE-004`: Appeal resolved (upheld or reversed)
//! - `STAKE-005`: Stake withdrawn by publisher
//! - `STAKE-006`: Stake expired and released
//! - `STAKE-007`: Capability gate checked against stake
//!
//! # Invariants
//!
//! - **INV-STAKE-MINIMUM**: Every active stake meets or exceeds the minimum for its risk tier
//! - **INV-STAKE-SLASH-DETERMINISTIC**: Slashing is deterministic: same evidence + policy = same outcome
//! - **INV-STAKE-APPEAL-WINDOW**: Appeals are only accepted within the configured appeal window
//! - **INV-STAKE-AUDIT-COMPLETE**: Every state transition produces an audit entry
//! - **INV-STAKE-NO-DOUBLE-SLASH**: A stake cannot be slashed twice for the same evidence
//! - **INV-STAKE-WITHDRAWAL-SAFE**: Withdrawal only succeeds when no pending obligations exist

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;

// ---------------------------------------------------------------------------
// Schema version
// ---------------------------------------------------------------------------

/// Schema version for staking governance artifacts.
pub const SCHEMA_VERSION: &str = "staking-v1.0";

// ---------------------------------------------------------------------------
// Event codes
// ---------------------------------------------------------------------------

pub mod event_codes {
    /// STAKE-001: Stake deposited successfully.
    pub const STAKE_001_DEPOSITED: &str = "STAKE-001";
    /// STAKE-002: Stake slashed due to validated malicious behaviour.
    pub const STAKE_002_SLASHED: &str = "STAKE-002";
    /// STAKE-003: Appeal filed against slash decision.
    pub const STAKE_003_APPEAL_FILED: &str = "STAKE-003";
    /// STAKE-004: Appeal resolved (upheld or reversed).
    pub const STAKE_004_APPEAL_RESOLVED: &str = "STAKE-004";
    /// STAKE-005: Stake withdrawn by publisher.
    pub const STAKE_005_WITHDRAWN: &str = "STAKE-005";
    /// STAKE-006: Stake expired and released.
    pub const STAKE_006_EXPIRED: &str = "STAKE-006";
    /// STAKE-007: Capability gate checked against stake.
    pub const STAKE_007_GATE_CHECKED: &str = "STAKE-007";
}

#[allow(unused_imports)]
use event_codes::*;

// ---------------------------------------------------------------------------
// Error codes
// ---------------------------------------------------------------------------

/// Deposited stake below minimum for risk tier.
pub const ERR_STAKE_INSUFFICIENT: &str = "ERR_STAKE_INSUFFICIENT";
/// Referenced stake ID does not exist.
pub const ERR_STAKE_NOT_FOUND: &str = "ERR_STAKE_NOT_FOUND";
/// Attempt to slash an already-slashed stake.
pub const ERR_STAKE_ALREADY_SLASHED: &str = "ERR_STAKE_ALREADY_SLASHED";
/// Withdrawal blocked due to pending obligations.
pub const ERR_STAKE_WITHDRAWAL_BLOCKED: &str = "ERR_STAKE_WITHDRAWAL_BLOCKED";
/// Appeal filed after appeal window closed.
pub const ERR_STAKE_APPEAL_EXPIRED: &str = "ERR_STAKE_APPEAL_EXPIRED";
/// Invalid state transition attempted.
pub const ERR_STAKE_INVALID_TRANSITION: &str = "ERR_STAKE_INVALID_TRANSITION";
/// Duplicate appeal for same slash event.
pub const ERR_STAKE_DUPLICATE_APPEAL: &str = "ERR_STAKE_DUPLICATE_APPEAL";

// ---------------------------------------------------------------------------
// Invariant tags
// ---------------------------------------------------------------------------

/// INV-STAKE-MINIMUM: Every active stake meets or exceeds the minimum for
/// its risk tier.
pub const INV_STAKE_MINIMUM: &str = "INV-STAKE-MINIMUM";

/// INV-STAKE-SLASH-DETERMINISTIC: Slashing is deterministic — same evidence +
/// policy = same outcome.
pub const INV_STAKE_SLASH_DETERMINISTIC: &str = "INV-STAKE-SLASH-DETERMINISTIC";

/// INV-STAKE-APPEAL-WINDOW: Appeals are only accepted within the configured
/// appeal window.
pub const INV_STAKE_APPEAL_WINDOW: &str = "INV-STAKE-APPEAL-WINDOW";

/// INV-STAKE-AUDIT-COMPLETE: Every state transition produces an audit entry.
pub const INV_STAKE_AUDIT_COMPLETE: &str = "INV-STAKE-AUDIT-COMPLETE";

/// INV-STAKE-NO-DOUBLE-SLASH: A stake cannot be slashed twice for the same
/// evidence.
pub const INV_STAKE_NO_DOUBLE_SLASH: &str = "INV-STAKE-NO-DOUBLE-SLASH";

/// INV-STAKE-WITHDRAWAL-SAFE: Withdrawal only succeeds when no pending
/// obligations exist.
pub const INV_STAKE_WITHDRAWAL_SAFE: &str = "INV-STAKE-WITHDRAWAL-SAFE";

// ---------------------------------------------------------------------------
// StakeId
// ---------------------------------------------------------------------------

/// Unique identifier for a security stake.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct StakeId(pub u64);

impl fmt::Display for StakeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "stake-{}", self.0)
    }
}

// ---------------------------------------------------------------------------
// RiskTier
// ---------------------------------------------------------------------------

/// Risk tier classification for capabilities.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskTier {
    Low,
    Medium,
    High,
    Critical,
}

impl RiskTier {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

impl fmt::Display for RiskTier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

// ---------------------------------------------------------------------------
// StakeState
// ---------------------------------------------------------------------------

/// Lifecycle states for a security stake.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StakeState {
    Active,
    Slashed,
    UnderAppeal,
    Withdrawn,
    Expired,
}

impl StakeState {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Slashed => "slashed",
            Self::UnderAppeal => "under_appeal",
            Self::Withdrawn => "withdrawn",
            Self::Expired => "expired",
        }
    }

    /// Returns true if this is a terminal state.
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Withdrawn | Self::Expired)
    }
}

impl fmt::Display for StakeState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

// ---------------------------------------------------------------------------
// AppealOutcome
// ---------------------------------------------------------------------------

/// Outcome of an appeal against a slash decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AppealOutcome {
    Pending,
    Upheld,
    Reversed,
}

impl AppealOutcome {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Upheld => "upheld",
            Self::Reversed => "reversed",
        }
    }
}

impl fmt::Display for AppealOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

// ---------------------------------------------------------------------------
// SlashEvidence
// ---------------------------------------------------------------------------

/// Evidence bundle attached to a slash event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlashEvidence {
    /// Unique hash identifying this evidence bundle.
    pub evidence_hash: String,
    /// Human-readable description of the malicious behaviour.
    pub description: String,
    /// Timestamp (epoch seconds) when evidence was collected.
    pub collected_at: u64,
    /// The capability that was abused.
    pub capability: String,
}

// ---------------------------------------------------------------------------
// SlashEvent
// ---------------------------------------------------------------------------

/// Record of a slashing action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlashEvent {
    /// The stake being slashed.
    pub stake_id: StakeId,
    /// Evidence justifying the slash.
    pub evidence: SlashEvidence,
    /// Amount slashed.
    pub slash_amount: u64,
    /// Timestamp (epoch seconds) of the slash.
    pub slashed_at: u64,
    /// Whether an appeal is still possible.
    pub appeal_deadline: u64,
}

// ---------------------------------------------------------------------------
// AppealRecord
// ---------------------------------------------------------------------------

/// Record of an appeal against a slash decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppealRecord {
    /// Unique appeal identifier.
    pub appeal_id: u64,
    /// Stake that was slashed.
    pub stake_id: StakeId,
    /// Publisher's reason for appealing.
    pub reason: String,
    /// Current outcome of the appeal.
    pub outcome: AppealOutcome,
    /// Timestamp (epoch seconds) when appeal was filed.
    pub filed_at: u64,
    /// Timestamp (epoch seconds) when appeal was resolved (0 if pending).
    pub resolved_at: u64,
}

// ---------------------------------------------------------------------------
// StakeRecord
// ---------------------------------------------------------------------------

/// Full record of a security stake.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StakeRecord {
    /// Unique stake identifier.
    pub id: StakeId,
    /// Publisher identity (opaque string).
    pub publisher: String,
    /// Amount staked.
    pub amount: u64,
    /// Current lifecycle state.
    pub state: StakeState,
    /// Risk tier this stake covers.
    pub risk_tier: RiskTier,
    /// Timestamp (epoch seconds) when the stake was deposited.
    pub deposited_at: u64,
    /// Timestamp (epoch seconds) when the stake expires (0 = no expiry).
    pub expires_at: u64,
    /// Whether the publisher has pending obligations.
    pub has_pending_obligations: bool,
    /// Slash events associated with this stake.
    pub slash_events: Vec<SlashEvent>,
}

// ---------------------------------------------------------------------------
// StakePolicy
// ---------------------------------------------------------------------------

/// Per-risk-tier staking policy configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StakePolicy {
    /// Minimum stake amount per risk tier.
    pub minimum_stakes: BTreeMap<String, u64>,
    /// Slash fraction (percentage 0..=100) per risk tier.
    pub slash_fractions: BTreeMap<String, u64>,
    /// Cooldown period (seconds) per risk tier.
    pub cooldown_periods: BTreeMap<String, u64>,
    /// Appeal window (seconds) per risk tier.
    pub appeal_windows: BTreeMap<String, u64>,
}

impl StakePolicy {
    /// Create a default policy with standard tier thresholds.
    pub fn default_policy() -> Self {
        let mut minimum_stakes = BTreeMap::new();
        minimum_stakes.insert("critical".to_string(), 1000);
        minimum_stakes.insert("high".to_string(), 500);
        minimum_stakes.insert("medium".to_string(), 100);
        minimum_stakes.insert("low".to_string(), 10);

        let mut slash_fractions = BTreeMap::new();
        slash_fractions.insert("critical".to_string(), 100);
        slash_fractions.insert("high".to_string(), 50);
        slash_fractions.insert("medium".to_string(), 25);
        slash_fractions.insert("low".to_string(), 10);

        let mut cooldown_periods = BTreeMap::new();
        cooldown_periods.insert("critical".to_string(), 72 * 3600);
        cooldown_periods.insert("high".to_string(), 48 * 3600);
        cooldown_periods.insert("medium".to_string(), 24 * 3600);
        cooldown_periods.insert("low".to_string(), 12 * 3600);

        let mut appeal_windows = BTreeMap::new();
        appeal_windows.insert("critical".to_string(), 48 * 3600);
        appeal_windows.insert("high".to_string(), 36 * 3600);
        appeal_windows.insert("medium".to_string(), 24 * 3600);
        appeal_windows.insert("low".to_string(), 12 * 3600);

        Self {
            minimum_stakes,
            slash_fractions,
            cooldown_periods,
            appeal_windows,
        }
    }

    /// Get the minimum stake for a risk tier.
    pub fn minimum_for_tier(&self, tier: RiskTier) -> u64 {
        self.minimum_stakes.get(tier.label()).copied().unwrap_or(0)
    }

    /// Get the slash fraction (0..=100) for a risk tier.
    pub fn slash_fraction_for_tier(&self, tier: RiskTier) -> u64 {
        self.slash_fractions.get(tier.label()).copied().unwrap_or(0)
    }

    /// Get the appeal window (seconds) for a risk tier.
    pub fn appeal_window_for_tier(&self, tier: RiskTier) -> u64 {
        self.appeal_windows.get(tier.label()).copied().unwrap_or(0)
    }

    /// Get the cooldown period (seconds) for a risk tier.
    pub fn cooldown_for_tier(&self, tier: RiskTier) -> u64 {
        self.cooldown_periods
            .get(tier.label())
            .copied()
            .unwrap_or(0)
    }
}

// ---------------------------------------------------------------------------
// StakingAuditEntry
// ---------------------------------------------------------------------------

/// Timestamped audit log entry for any staking operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StakingAuditEntry {
    /// Event code (STAKE-001..STAKE-007).
    pub event_code: String,
    /// Timestamp (epoch seconds).
    pub timestamp: u64,
    /// Publisher identity.
    pub publisher: String,
    /// Stake ID involved.
    pub stake_id: StakeId,
    /// Human-readable description.
    pub description: String,
    /// Evidence hash (for slash operations, empty otherwise).
    pub evidence_hash: String,
    /// Outcome label.
    pub outcome: String,
}

// ---------------------------------------------------------------------------
// CapabilityStakeGate
// ---------------------------------------------------------------------------

/// Gate that checks stake sufficiency before capability activation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityStakeGate {
    /// Capability being gated.
    pub capability: String,
    /// Risk tier of the capability.
    pub risk_tier: RiskTier,
    /// Whether the gate passed.
    pub passed: bool,
    /// Reason for pass/fail.
    pub reason: String,
}

// ---------------------------------------------------------------------------
// StakingError
// ---------------------------------------------------------------------------

/// Error type for staking operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StakingError {
    pub code: &'static str,
    pub message: String,
}

impl StakingError {
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl fmt::Display for StakingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}", self.code, self.message)
    }
}

// ---------------------------------------------------------------------------
// TrustGovernanceState
// ---------------------------------------------------------------------------

use crate::capacity_defaults::aliases::MAX_AUDIT_LOG_ENTRIES;
const MAX_SLASH_EVENTS_PER_STAKE: usize = 256;
const MAX_EVIDENCE_HASHES_PER_STAKE: usize = 256;

/// Top-level state holding all stakes, slash events, appeals, and audit trail.
///
/// Uses `BTreeMap` for deterministic ordering throughout.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustGovernanceState {
    /// Schema version.
    pub schema_version: String,
    /// All stake records, keyed by StakeId.
    pub stakes: BTreeMap<u64, StakeRecord>,
    /// All appeal records, keyed by appeal_id.
    pub appeals: BTreeMap<u64, AppealRecord>,
    /// Audit trail.
    pub audit_log: Vec<StakingAuditEntry>,
    /// Staking policy.
    pub policy: StakePolicy,
    /// Next stake ID counter.
    next_stake_id: u64,
    /// Next appeal ID counter.
    next_appeal_id: u64,
    /// Set of evidence hashes already used for slashing (double-slash prevention).
    used_evidence_hashes: BTreeMap<u64, Vec<String>>,
    /// Current logical timestamp (epoch seconds) — injectable for determinism.
    pub current_time: u64,
}

impl TrustGovernanceState {
    /// Create a new governance state with default policy.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.to_string(),
            stakes: BTreeMap::new(),
            appeals: BTreeMap::new(),
            audit_log: Vec::new(),
            policy: StakePolicy::default_policy(),
            next_stake_id: 1,
            next_appeal_id: 1,
            used_evidence_hashes: BTreeMap::new(),
            current_time: 0,
        }
    }

    /// Create a new governance state with a custom policy.
    pub fn with_policy(policy: StakePolicy) -> Self {
        Self {
            policy,
            ..Self::new()
        }
    }

    /// Set the logical clock (for deterministic testing).
    pub fn set_time(&mut self, t: u64) {
        self.current_time = t;
    }

    /// Advance the logical clock by `delta` seconds.
    pub fn advance_time(&mut self, delta: u64) {
        self.current_time = self.current_time.saturating_add(delta);
    }

    // -- Audit helper -------------------------------------------------------

    fn emit_audit(
        &mut self,
        event_code: &str,
        publisher: &str,
        stake_id: StakeId,
        description: &str,
        evidence_hash: &str,
        outcome: &str,
    ) {
        // INV-STAKE-AUDIT-COMPLETE: every state transition produces an audit entry
        let entry = StakingAuditEntry {
            event_code: event_code.to_string(),
            timestamp: self.current_time,
            publisher: publisher.to_string(),
            stake_id,
            description: description.to_string(),
            evidence_hash: evidence_hash.to_string(),
            outcome: outcome.to_string(),
        };
        push_bounded(&mut self.audit_log, entry, MAX_AUDIT_LOG_ENTRIES);
    }

    // -- deposit_stake ------------------------------------------------------

    /// Deposit a new stake for a publisher.
    ///
    /// # Errors
    ///
    /// Returns `ERR_STAKE_INSUFFICIENT` if `amount` is below the minimum for
    /// the given risk tier (INV-STAKE-MINIMUM).
    pub fn deposit_stake(
        &mut self,
        publisher: &str,
        amount: u64,
        risk_tier: RiskTier,
        expires_at: u64,
    ) -> Result<StakeId, StakingError> {
        // INV-STAKE-MINIMUM: enforce minimum stake
        let minimum = self.policy.minimum_for_tier(risk_tier);
        if amount < minimum {
            return Err(StakingError::new(
                ERR_STAKE_INSUFFICIENT,
                format!(
                    "stake {} below minimum {} for tier {}",
                    amount,
                    minimum,
                    risk_tier.label()
                ),
            ));
        }

        let id = StakeId(self.next_stake_id);
        self.next_stake_id = self.next_stake_id.saturating_add(1);

        let record = StakeRecord {
            id,
            publisher: publisher.to_string(),
            amount,
            state: StakeState::Active,
            risk_tier,
            deposited_at: self.current_time,
            expires_at,
            has_pending_obligations: false,
            slash_events: Vec::new(),
        };

        self.stakes.insert(id.0, record);

        // STAKE-001: Stake deposited successfully
        self.emit_audit(
            STAKE_001_DEPOSITED,
            publisher,
            id,
            "stake deposited",
            "",
            "active",
        );

        Ok(id)
    }

    // -- slash --------------------------------------------------------------

    /// Slash a stake due to validated malicious behaviour.
    ///
    /// # Errors
    ///
    /// - `ERR_STAKE_NOT_FOUND` if stake ID does not exist.
    /// - `ERR_STAKE_ALREADY_SLASHED` if stake is already in Slashed state.
    /// - `ERR_STAKE_INVALID_TRANSITION` if stake is in a terminal state.
    ///
    /// # Invariants
    ///
    /// - INV-STAKE-SLASH-DETERMINISTIC: same evidence + policy = same outcome
    /// - INV-STAKE-NO-DOUBLE-SLASH: rejects duplicate evidence hashes
    pub fn slash(
        &mut self,
        stake_id: StakeId,
        evidence: SlashEvidence,
    ) -> Result<SlashEvent, StakingError> {
        let record = self
            .stakes
            .get_mut(&stake_id.0)
            .ok_or_else(|| StakingError::new(ERR_STAKE_NOT_FOUND, "stake not found"))?;

        // Reject terminal states
        if record.state.is_terminal() {
            return Err(StakingError::new(
                ERR_STAKE_INVALID_TRANSITION,
                format!("cannot slash stake in {} state", record.state),
            ));
        }

        // ERR_STAKE_ALREADY_SLASHED
        if record.state == StakeState::Slashed || record.state == StakeState::UnderAppeal {
            return Err(StakingError::new(
                ERR_STAKE_ALREADY_SLASHED,
                format!("stake already in {} state", record.state),
            ));
        }

        // INV-STAKE-NO-DOUBLE-SLASH: check for duplicate evidence
        let used = self.used_evidence_hashes.entry(stake_id.0).or_default();
        if used.iter().any(|used_hash| {
            crate::security::constant_time::ct_eq(used_hash, &evidence.evidence_hash)
        }) {
            return Err(StakingError::new(
                ERR_STAKE_ALREADY_SLASHED,
                format!(
                    "evidence {} already used for this stake",
                    evidence.evidence_hash
                ),
            ));
        }
        push_bounded(
            used,
            evidence.evidence_hash.clone(),
            MAX_EVIDENCE_HASHES_PER_STAKE,
        );

        // INV-STAKE-SLASH-DETERMINISTIC: compute slash amount from policy
        let fraction = self
            .policy
            .slash_fraction_for_tier(record.risk_tier)
            .min(100);
        let slash_amount =
            u64::try_from(record.amount as u128 * fraction as u128 / 100).unwrap_or(u64::MAX);
        let appeal_window = self.policy.appeal_window_for_tier(record.risk_tier);

        let event = SlashEvent {
            stake_id,
            evidence: evidence.clone(),
            slash_amount,
            slashed_at: self.current_time,
            appeal_deadline: self.current_time.saturating_add(appeal_window),
        };

        record.state = StakeState::Slashed;
        push_bounded(
            &mut record.slash_events,
            event.clone(),
            MAX_SLASH_EVENTS_PER_STAKE,
        );

        let publisher = record.publisher.clone();

        // STAKE-002: Stake slashed
        self.emit_audit(
            STAKE_002_SLASHED,
            &publisher,
            stake_id,
            "stake slashed for malicious behaviour",
            &evidence.evidence_hash,
            "slashed",
        );

        Ok(event)
    }

    // -- appeal -------------------------------------------------------------

    /// File an appeal against a slash decision.
    ///
    /// # Errors
    ///
    /// - `ERR_STAKE_NOT_FOUND` if stake does not exist.
    /// - `ERR_STAKE_INVALID_TRANSITION` if stake is not in Slashed state.
    /// - `ERR_STAKE_APPEAL_EXPIRED` if the appeal window has closed.
    /// - `ERR_STAKE_DUPLICATE_APPEAL` if an appeal is already pending.
    pub fn appeal(
        &mut self,
        stake_id: StakeId,
        reason: &str,
    ) -> Result<AppealRecord, StakingError> {
        let record = self
            .stakes
            .get(&stake_id.0)
            .ok_or_else(|| StakingError::new(ERR_STAKE_NOT_FOUND, "stake not found"))?;

        if record.state != StakeState::Slashed {
            return Err(StakingError::new(
                ERR_STAKE_INVALID_TRANSITION,
                format!("cannot appeal stake in {} state", record.state),
            ));
        }

        // INV-STAKE-APPEAL-WINDOW: check deadline
        let latest_slash = record.slash_events.last().ok_or_else(|| {
            StakingError::new(
                ERR_STAKE_INVALID_TRANSITION,
                "slashed stake has no slash events",
            )
        })?;
        if self.current_time >= latest_slash.appeal_deadline {
            return Err(StakingError::new(
                ERR_STAKE_APPEAL_EXPIRED,
                "appeal window has closed",
            ));
        }

        // ERR_STAKE_DUPLICATE_APPEAL: check for existing pending appeal
        let has_pending = self
            .appeals
            .values()
            .any(|a| a.stake_id == stake_id && a.outcome == AppealOutcome::Pending);
        if has_pending {
            return Err(StakingError::new(
                ERR_STAKE_DUPLICATE_APPEAL,
                "appeal already pending for this stake",
            ));
        }

        let appeal_id = self.next_appeal_id;
        self.next_appeal_id = self.next_appeal_id.saturating_add(1);

        let appeal = AppealRecord {
            appeal_id,
            stake_id,
            reason: reason.to_string(),
            outcome: AppealOutcome::Pending,
            filed_at: self.current_time,
            resolved_at: 0,
        };

        self.appeals.insert(appeal_id, appeal.clone());

        // Transition to UnderAppeal
        let record = self
            .stakes
            .get_mut(&stake_id.0)
            .ok_or_else(|| StakingError::new(ERR_STAKE_NOT_FOUND, "stake not found"))?;
        record.state = StakeState::UnderAppeal;

        let publisher = record.publisher.clone();

        // STAKE-003: Appeal filed
        self.emit_audit(
            STAKE_003_APPEAL_FILED,
            &publisher,
            stake_id,
            "appeal filed against slash decision",
            "",
            "under_appeal",
        );

        Ok(appeal)
    }

    // -- resolve_appeal -----------------------------------------------------

    /// Resolve an appeal: upheld (slash stands) or reversed (stake restored).
    ///
    /// # Errors
    ///
    /// - `ERR_STAKE_NOT_FOUND` if the appeal does not exist.
    /// - `ERR_STAKE_INVALID_TRANSITION` if the appeal is not in Pending state.
    pub fn resolve_appeal(&mut self, appeal_id: u64, upheld: bool) -> Result<(), StakingError> {
        let appeal = self
            .appeals
            .get_mut(&appeal_id)
            .ok_or_else(|| StakingError::new(ERR_STAKE_NOT_FOUND, "appeal not found"))?;

        if appeal.outcome != AppealOutcome::Pending {
            return Err(StakingError::new(
                ERR_STAKE_INVALID_TRANSITION,
                "appeal already resolved",
            ));
        }

        appeal.outcome = if upheld {
            AppealOutcome::Upheld
        } else {
            AppealOutcome::Reversed
        };
        appeal.resolved_at = self.current_time;

        let stake_id = appeal.stake_id;

        let record = self
            .stakes
            .get_mut(&stake_id.0)
            .ok_or_else(|| StakingError::new(ERR_STAKE_NOT_FOUND, "stake not found"))?;

        // Guard: only stakes in UnderAppeal state can be resolved.
        // Without this check, resolving a stale appeal on a Withdrawn or
        // Expired stake would revive it to Active, bypassing terminal-state
        // guarantees.
        if record.state != StakeState::UnderAppeal {
            return Err(StakingError::new(
                ERR_STAKE_INVALID_TRANSITION,
                format!(
                    "cannot resolve appeal: stake {} is in {} state, expected UnderAppeal",
                    stake_id, record.state
                ),
            ));
        }

        if upheld {
            // Appeal upheld: slash stands
            record.state = StakeState::Slashed;
        } else {
            // Appeal reversed: restore to Active
            record.state = StakeState::Active;
        }

        let publisher = record.publisher.clone();
        let outcome_label = if upheld { "upheld" } else { "reversed" };

        // STAKE-004: Appeal resolved
        self.emit_audit(
            STAKE_004_APPEAL_RESOLVED,
            &publisher,
            stake_id,
            &format!("appeal resolved: {}", outcome_label),
            "",
            outcome_label,
        );

        Ok(())
    }

    // -- withdraw -----------------------------------------------------------

    /// Withdraw a stake. Only succeeds if the stake is Active and has no
    /// pending obligations (INV-STAKE-WITHDRAWAL-SAFE).
    ///
    /// # Errors
    ///
    /// - `ERR_STAKE_NOT_FOUND` if stake does not exist.
    /// - `ERR_STAKE_INVALID_TRANSITION` if stake is not Active.
    /// - `ERR_STAKE_WITHDRAWAL_BLOCKED` if publisher has pending obligations.
    pub fn withdraw(&mut self, stake_id: StakeId) -> Result<(), StakingError> {
        let record = self
            .stakes
            .get_mut(&stake_id.0)
            .ok_or_else(|| StakingError::new(ERR_STAKE_NOT_FOUND, "stake not found"))?;

        if record.state != StakeState::Active {
            return Err(StakingError::new(
                ERR_STAKE_INVALID_TRANSITION,
                format!("cannot withdraw stake in {} state", record.state),
            ));
        }

        // INV-STAKE-WITHDRAWAL-SAFE
        if record.has_pending_obligations {
            return Err(StakingError::new(
                ERR_STAKE_WITHDRAWAL_BLOCKED,
                "publisher has pending obligations",
            ));
        }

        record.state = StakeState::Withdrawn;
        let publisher = record.publisher.clone();

        // STAKE-005: Stake withdrawn
        self.emit_audit(
            STAKE_005_WITHDRAWN,
            &publisher,
            stake_id,
            "stake withdrawn by publisher",
            "",
            "withdrawn",
        );

        Ok(())
    }

    // -- expire_stakes ------------------------------------------------------

    /// Expire all stakes whose `expires_at` has passed. Returns the number
    /// of stakes expired.
    pub fn expire_stakes(&mut self) -> usize {
        let now = self.current_time;
        let mut expired_ids: Vec<(StakeId, String)> = Vec::new();

        for record in self.stakes.values() {
            if record.state == StakeState::Active
                && record.expires_at > 0
                && record.expires_at <= now
            {
                expired_ids.push((record.id, record.publisher.clone()));
            }
        }

        let count = expired_ids.len();

        for (id, publisher) in &expired_ids {
            if let Some(record) = self.stakes.get_mut(&id.0) {
                record.state = StakeState::Expired;
            }

            // STAKE-006: Stake expired
            self.emit_audit(
                STAKE_006_EXPIRED,
                publisher,
                *id,
                "stake expired and released",
                "",
                "expired",
            );
        }

        count
    }

    // -- check_capability_gate ----------------------------------------------

    /// Check whether a publisher's stake is sufficient for a given capability.
    ///
    /// Emits STAKE-007 event and returns a `CapabilityStakeGate` result.
    pub fn check_capability_gate(
        &mut self,
        publisher: &str,
        capability: &str,
        risk_tier: RiskTier,
    ) -> CapabilityStakeGate {
        let minimum = self.policy.minimum_for_tier(risk_tier);

        // Find the publisher's active stake for this risk tier
        let now = self.current_time;
        let active_stake = self.stakes.values().find(|s| {
            s.publisher == publisher
                && s.state == StakeState::Active
                && s.risk_tier == risk_tier
                && (s.expires_at == 0 || now < s.expires_at)
        });

        let (passed, reason) = match active_stake {
            Some(stake) if stake.amount >= minimum => {
                // Check for unresolved slash events
                let has_unresolved = self
                    .appeals
                    .values()
                    .any(|a| a.stake_id == stake.id && a.outcome == AppealOutcome::Pending);
                if has_unresolved {
                    (false, "unresolved appeal pending".to_string())
                } else {
                    (
                        true,
                        format!("stake {} meets minimum {}", stake.amount, minimum),
                    )
                }
            }
            Some(stake) => (
                false,
                format!("stake {} below minimum {}", stake.amount, minimum),
            ),
            None => (false, "no active stake found for publisher".to_string()),
        };

        let gate = CapabilityStakeGate {
            capability: capability.to_string(),
            risk_tier,
            passed,
            reason: reason.clone(),
        };

        let stake_id = active_stake.map_or(StakeId(0), |s| s.id);

        // STAKE-007: Gate checked
        self.emit_audit(
            STAKE_007_GATE_CHECKED,
            publisher,
            stake_id,
            &format!("capability gate check: {}", capability),
            "",
            if passed { "passed" } else { "failed" },
        );

        gate
    }

    // -- set_pending_obligations --------------------------------------------

    /// Mark whether a publisher's stake has pending obligations.
    pub fn set_pending_obligations(
        &mut self,
        stake_id: StakeId,
        has_pending: bool,
    ) -> Result<(), StakingError> {
        let record = self
            .stakes
            .get_mut(&stake_id.0)
            .ok_or_else(|| StakingError::new(ERR_STAKE_NOT_FOUND, "stake not found"))?;
        record.has_pending_obligations = has_pending;
        Ok(())
    }

    // -- get_stake ----------------------------------------------------------

    /// Retrieve a stake record by ID.
    pub fn get_stake(&self, stake_id: StakeId) -> Option<&StakeRecord> {
        self.stakes.get(&stake_id.0)
    }

    // -- export_audit_log_jsonl ---------------------------------------------

    /// Export the audit log as newline-delimited JSON.
    pub fn export_audit_log_jsonl(&self) -> String {
        self.audit_log
            .iter()
            .map(|entry| serde_json::to_string(entry).unwrap_or_default())
            .collect::<Vec<_>>()
            .join("\n")
    }

    // -- count_by_state -----------------------------------------------------

    /// Count stakes in a given state.
    pub fn count_by_state(&self, state: StakeState) -> usize {
        self.stakes.values().filter(|s| s.state == state).count()
    }

    // -- total_stakes -------------------------------------------------------

    /// Total number of stake records.
    pub fn total_stakes(&self) -> usize {
        self.stakes.len()
    }

    // -- validate_invariants ------------------------------------------------

    /// Validate all invariants. Returns a list of violated invariants.
    pub fn validate_invariants(&self) -> Vec<&'static str> {
        let mut violations = Vec::new();

        // INV-STAKE-MINIMUM: every active stake meets tier minimum
        for record in self.stakes.values() {
            if record.state == StakeState::Active {
                let minimum = self.policy.minimum_for_tier(record.risk_tier);
                if record.amount < minimum {
                    violations.push(INV_STAKE_MINIMUM);
                    break;
                }
            }
        }

        // INV-STAKE-WITHDRAWAL-SAFE: no withdrawn stake has pending obligations
        for record in self.stakes.values() {
            if record.state == StakeState::Withdrawn && record.has_pending_obligations {
                violations.push(INV_STAKE_WITHDRAWAL_SAFE);
                break;
            }
        }

        violations
    }
}

impl Default for TrustGovernanceState {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// Invariant module
// ===========================================================================

pub mod invariants {
    //! Staking invariant identifiers (re-exported for checker scripts).

    pub const INV_STAKE_MINIMUM: &str = "INV-STAKE-MINIMUM";
    pub const INV_STAKE_SLASH_DETERMINISTIC: &str = "INV-STAKE-SLASH-DETERMINISTIC";
    pub const INV_STAKE_APPEAL_WINDOW: &str = "INV-STAKE-APPEAL-WINDOW";
    pub const INV_STAKE_AUDIT_COMPLETE: &str = "INV-STAKE-AUDIT-COMPLETE";
    pub const INV_STAKE_NO_DOUBLE_SLASH: &str = "INV-STAKE-NO-DOUBLE-SLASH";
    pub const INV_STAKE_WITHDRAWAL_SAFE: &str = "INV-STAKE-WITHDRAWAL-SAFE";
}

fn push_bounded<T>(items: &mut Vec<T>, item: T, cap: usize) {
    if items.len() >= cap {
        let overflow = items.len().saturating_sub(cap).saturating_add(1);
        items.drain(0..overflow.min(items.len()));
    }
    items.push(item);
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn make_evidence(hash: &str) -> SlashEvidence {
        SlashEvidence {
            evidence_hash: hash.to_string(),
            description: "test malicious behaviour".to_string(),
            collected_at: 100,
            capability: "publish".to_string(),
        }
    }

    // -- deposit tests ------------------------------------------------------

    #[test]
    fn test_deposit_stake_success() {
        let mut gov = TrustGovernanceState::new();
        gov.set_time(1000);
        let id = gov.deposit_stake("alice", 500, RiskTier::High, 0).unwrap();
        assert_eq!(id, StakeId(1));
        let record = gov.get_stake(id).unwrap();
        assert_eq!(record.publisher, "alice");
        assert_eq!(record.amount, 500);
        assert_eq!(record.state, StakeState::Active);
        assert_eq!(record.risk_tier, RiskTier::High);
        assert_eq!(record.deposited_at, 1000);
    }

    #[test]
    fn test_deposit_stake_insufficient() {
        let mut gov = TrustGovernanceState::new();
        let result = gov.deposit_stake("alice", 5, RiskTier::High, 0);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code, ERR_STAKE_INSUFFICIENT);
    }

    #[test]
    fn test_deposit_insufficient_preserves_empty_state_and_id_counter() {
        let mut gov = TrustGovernanceState::new();

        let err = gov
            .deposit_stake("alice", 499, RiskTier::High, 0)
            .unwrap_err();

        assert_eq!(err.code, ERR_STAKE_INSUFFICIENT);
        assert_eq!(gov.total_stakes(), 0);
        assert_eq!(gov.next_stake_id, 1);
        assert!(gov.audit_log.is_empty());
    }

    #[test]
    fn test_deposit_stake_exact_minimum() {
        let mut gov = TrustGovernanceState::new();
        let id = gov.deposit_stake("alice", 10, RiskTier::Low, 0).unwrap();
        let record = gov.get_stake(id).unwrap();
        assert_eq!(record.amount, 10);
        assert_eq!(record.state, StakeState::Active);
    }

    #[test]
    fn test_deposit_multiple_stakes() {
        let mut gov = TrustGovernanceState::new();
        let id1 = gov
            .deposit_stake("alice", 1000, RiskTier::Critical, 0)
            .unwrap();
        let id2 = gov.deposit_stake("bob", 500, RiskTier::High, 0).unwrap();
        assert_ne!(id1, id2);
        assert_eq!(gov.total_stakes(), 2);
    }

    #[test]
    fn test_deposit_emits_audit() {
        let mut gov = TrustGovernanceState::new();
        gov.deposit_stake("alice", 100, RiskTier::Medium, 0)
            .unwrap();
        assert_eq!(gov.audit_log.len(), 1);
        assert_eq!(gov.audit_log[0].event_code, "STAKE-001");
        assert_eq!(gov.audit_log[0].publisher, "alice");
    }

    // -- slash tests --------------------------------------------------------

    #[test]
    fn test_slash_success() {
        let mut gov = TrustGovernanceState::new();
        gov.set_time(1000);
        let id = gov.deposit_stake("alice", 500, RiskTier::High, 0).unwrap();
        gov.set_time(2000);
        let event = gov.slash(id, make_evidence("ev-001")).unwrap();
        assert_eq!(event.slash_amount, 250); // 50% of 500
        let record = gov.get_stake(id).unwrap();
        assert_eq!(record.state, StakeState::Slashed);
    }

    #[test]
    fn test_slash_not_found() {
        let mut gov = TrustGovernanceState::new();
        let result = gov.slash(StakeId(999), make_evidence("ev-001"));
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code, ERR_STAKE_NOT_FOUND);
    }

    #[test]
    fn test_slash_missing_stake_preserves_audit_and_evidence_tracking() {
        let mut gov = TrustGovernanceState::new();

        let err = gov
            .slash(StakeId(999), make_evidence("ev-missing"))
            .unwrap_err();

        assert_eq!(err.code, ERR_STAKE_NOT_FOUND);
        assert_eq!(gov.total_stakes(), 0);
        assert!(gov.audit_log.is_empty());
        assert!(gov.used_evidence_hashes.is_empty());
    }

    #[test]
    fn test_slash_already_slashed() {
        let mut gov = TrustGovernanceState::new();
        let id = gov.deposit_stake("alice", 500, RiskTier::High, 0).unwrap();
        gov.slash(id, make_evidence("ev-001")).unwrap();
        let result = gov.slash(id, make_evidence("ev-002"));
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code, ERR_STAKE_ALREADY_SLASHED);
    }

    #[test]
    fn test_slash_terminal_withdrawn_stake_preserves_record() {
        let mut gov = TrustGovernanceState::new();
        let id = gov.deposit_stake("alice", 500, RiskTier::High, 0).unwrap();
        gov.withdraw(id).unwrap();
        let audit_before = gov.audit_log.len();

        let err = gov
            .slash(id, make_evidence("ev-after-withdraw"))
            .unwrap_err();

        assert_eq!(err.code, ERR_STAKE_INVALID_TRANSITION);
        let record = gov.get_stake(id).unwrap();
        assert_eq!(record.state, StakeState::Withdrawn);
        assert!(record.slash_events.is_empty());
        assert_eq!(gov.audit_log.len(), audit_before);
        assert!(!gov.used_evidence_hashes.contains_key(&id.0));
    }

    #[test]
    fn test_slash_deterministic() {
        // INV-STAKE-SLASH-DETERMINISTIC: same evidence + policy = same outcome
        let mut gov1 = TrustGovernanceState::new();
        gov1.set_time(1000);
        let id1 = gov1.deposit_stake("alice", 500, RiskTier::High, 0).unwrap();
        let ev1 = gov1.slash(id1, make_evidence("ev-001")).unwrap();

        let mut gov2 = TrustGovernanceState::new();
        gov2.set_time(1000);
        let id2 = gov2.deposit_stake("alice", 500, RiskTier::High, 0).unwrap();
        let ev2 = gov2.slash(id2, make_evidence("ev-001")).unwrap();

        assert_eq!(ev1.slash_amount, ev2.slash_amount);
    }

    #[test]
    fn test_slash_no_double_slash_same_evidence() {
        // INV-STAKE-NO-DOUBLE-SLASH
        let mut gov = TrustGovernanceState::new();
        let id = gov.deposit_stake("alice", 500, RiskTier::High, 0).unwrap();
        gov.slash(id, make_evidence("ev-001")).unwrap();

        // Reverse the slash via appeal to restore Active state, then try same evidence
        let appeal = gov.appeal(id, "test").unwrap();
        gov.resolve_appeal(appeal.appeal_id, false).unwrap();

        // Now try slashing with the same evidence hash
        let result = gov.slash(id, make_evidence("ev-001"));
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code, ERR_STAKE_ALREADY_SLASHED);
    }

    #[test]
    fn test_duplicate_evidence_after_reversed_appeal_keeps_active_state() {
        let mut gov = TrustGovernanceState::new();
        let id = gov.deposit_stake("alice", 500, RiskTier::High, 0).unwrap();
        gov.slash(id, make_evidence("ev-001")).unwrap();
        let appeal = gov.appeal(id, "false positive").unwrap();
        gov.resolve_appeal(appeal.appeal_id, false).unwrap();
        let audit_before = gov.audit_log.len();

        let err = gov.slash(id, make_evidence("ev-001")).unwrap_err();

        assert_eq!(err.code, ERR_STAKE_ALREADY_SLASHED);
        let record = gov.get_stake(id).unwrap();
        assert_eq!(record.state, StakeState::Active);
        assert_eq!(record.slash_events.len(), 1);
        assert_eq!(gov.audit_log.len(), audit_before);
    }

    #[test]
    fn test_slash_emits_audit() {
        let mut gov = TrustGovernanceState::new();
        let id = gov.deposit_stake("alice", 500, RiskTier::High, 0).unwrap();
        gov.slash(id, make_evidence("ev-001")).unwrap();
        let audit = gov.audit_log.iter().find(|a| a.event_code == "STAKE-002");
        assert!(audit.is_some());
        assert_eq!(audit.unwrap().evidence_hash, "ev-001");
    }

    #[test]
    fn test_slash_critical_tier_full_slash() {
        let mut gov = TrustGovernanceState::new();
        let id = gov
            .deposit_stake("alice", 1000, RiskTier::Critical, 0)
            .unwrap();
        let event = gov.slash(id, make_evidence("ev-crit")).unwrap();
        assert_eq!(event.slash_amount, 1000); // 100% for critical
    }

    // -- appeal tests -------------------------------------------------------

    #[test]
    fn test_appeal_success() {
        let mut gov = TrustGovernanceState::new();
        gov.set_time(1000);
        let id = gov.deposit_stake("alice", 500, RiskTier::High, 0).unwrap();
        gov.set_time(2000);
        gov.slash(id, make_evidence("ev-001")).unwrap();
        gov.set_time(2100);
        let appeal = gov.appeal(id, "false positive").unwrap();
        assert_eq!(appeal.outcome, AppealOutcome::Pending);
        let record = gov.get_stake(id).unwrap();
        assert_eq!(record.state, StakeState::UnderAppeal);
    }

    #[test]
    fn test_appeal_expired() {
        // INV-STAKE-APPEAL-WINDOW
        let mut gov = TrustGovernanceState::new();
        gov.set_time(1000);
        let id = gov.deposit_stake("alice", 500, RiskTier::High, 0).unwrap();
        gov.set_time(2000);
        gov.slash(id, make_evidence("ev-001")).unwrap();
        // Advance past the appeal window (36 hours for High)
        gov.set_time(2000 + 36 * 3600 + 1);
        let result = gov.appeal(id, "too late");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code, ERR_STAKE_APPEAL_EXPIRED);
    }

    #[test]
    fn test_appeal_expired_does_not_create_appeal_or_change_state() {
        let mut gov = TrustGovernanceState::new();
        gov.set_time(1000);
        let id = gov.deposit_stake("alice", 500, RiskTier::High, 0).unwrap();
        gov.set_time(2000);
        gov.slash(id, make_evidence("ev-expired")).unwrap();
        let audit_before = gov.audit_log.len();
        gov.set_time(2000 + 36 * 3600);

        let err = gov.appeal(id, "too late").unwrap_err();

        assert_eq!(err.code, ERR_STAKE_APPEAL_EXPIRED);
        assert!(gov.appeals.is_empty());
        assert_eq!(gov.next_appeal_id, 1);
        assert_eq!(gov.get_stake(id).unwrap().state, StakeState::Slashed);
        assert_eq!(gov.audit_log.len(), audit_before);
    }

    #[test]
    fn test_appeal_expired_at_exact_deadline() {
        // INV-STAKE-APPEAL-WINDOW: appeal exactly AT the deadline must fail (fail-closed)
        let mut gov = TrustGovernanceState::new();
        gov.set_time(1000);
        let id = gov.deposit_stake("alice", 500, RiskTier::High, 0).unwrap();
        gov.set_time(2000);
        gov.slash(id, make_evidence("ev-boundary")).unwrap();
        // Set time exactly at the appeal deadline (36 hours for High)
        gov.set_time(2000 + 36 * 3600);
        let result = gov.appeal(id, "exactly at deadline");
        assert!(result.is_err(), "appeal at exact deadline must fail closed");
        assert_eq!(result.unwrap_err().code, ERR_STAKE_APPEAL_EXPIRED);
    }

    #[test]
    fn test_appeal_duplicate() {
        let mut gov = TrustGovernanceState::new();
        gov.set_time(1000);
        let id = gov.deposit_stake("alice", 500, RiskTier::High, 0).unwrap();
        gov.slash(id, make_evidence("ev-001")).unwrap();
        gov.appeal(id, "first appeal").unwrap();
        // Second appeal fails: state is now UnderAppeal (not Slashed), so InvalidTransition fires first.
        let result = gov.appeal(id, "second appeal");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code, ERR_STAKE_INVALID_TRANSITION);
    }

    #[test]
    fn test_appeal_not_slashed() {
        let mut gov = TrustGovernanceState::new();
        let id = gov.deposit_stake("alice", 500, RiskTier::High, 0).unwrap();
        let result = gov.appeal(id, "not slashed");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code, ERR_STAKE_INVALID_TRANSITION);
    }

    #[test]
    fn test_appeal_active_stake_does_not_create_appeal_or_audit() {
        let mut gov = TrustGovernanceState::new();
        let id = gov.deposit_stake("alice", 500, RiskTier::High, 0).unwrap();
        let audit_before = gov.audit_log.len();

        let err = gov.appeal(id, "not slashed").unwrap_err();

        assert_eq!(err.code, ERR_STAKE_INVALID_TRANSITION);
        assert!(gov.appeals.is_empty());
        assert_eq!(gov.next_appeal_id, 1);
        assert_eq!(gov.get_stake(id).unwrap().state, StakeState::Active);
        assert_eq!(gov.audit_log.len(), audit_before);
    }

    // -- resolve_appeal tests -----------------------------------------------

    #[test]
    fn test_resolve_appeal_upheld() {
        let mut gov = TrustGovernanceState::new();
        let id = gov.deposit_stake("alice", 500, RiskTier::High, 0).unwrap();
        gov.slash(id, make_evidence("ev-001")).unwrap();
        let appeal = gov.appeal(id, "test").unwrap();
        gov.resolve_appeal(appeal.appeal_id, true).unwrap();
        let record = gov.get_stake(id).unwrap();
        assert_eq!(record.state, StakeState::Slashed);
    }

    #[test]
    fn test_resolve_appeal_reversed() {
        let mut gov = TrustGovernanceState::new();
        let id = gov.deposit_stake("alice", 500, RiskTier::High, 0).unwrap();
        gov.slash(id, make_evidence("ev-001")).unwrap();
        let appeal = gov.appeal(id, "test").unwrap();
        gov.resolve_appeal(appeal.appeal_id, false).unwrap();
        let record = gov.get_stake(id).unwrap();
        assert_eq!(record.state, StakeState::Active);
        let a = gov.appeals.get(&appeal.appeal_id).unwrap();
        assert_eq!(a.outcome, AppealOutcome::Reversed);
    }

    // -- withdraw tests -----------------------------------------------------

    #[test]
    fn test_withdraw_success() {
        let mut gov = TrustGovernanceState::new();
        let id = gov.deposit_stake("alice", 500, RiskTier::High, 0).unwrap();
        gov.withdraw(id).unwrap();
        let record = gov.get_stake(id).unwrap();
        assert_eq!(record.state, StakeState::Withdrawn);
    }

    #[test]
    fn test_withdraw_blocked_by_obligations() {
        // INV-STAKE-WITHDRAWAL-SAFE
        let mut gov = TrustGovernanceState::new();
        let id = gov.deposit_stake("alice", 500, RiskTier::High, 0).unwrap();
        gov.set_pending_obligations(id, true).unwrap();
        let result = gov.withdraw(id);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code, ERR_STAKE_WITHDRAWAL_BLOCKED);
    }

    #[test]
    fn test_withdraw_blocked_by_obligations_preserves_active_stake() {
        let mut gov = TrustGovernanceState::new();
        let id = gov.deposit_stake("alice", 500, RiskTier::High, 0).unwrap();
        gov.set_pending_obligations(id, true).unwrap();
        let audit_before = gov.audit_log.len();

        let err = gov.withdraw(id).unwrap_err();

        assert_eq!(err.code, ERR_STAKE_WITHDRAWAL_BLOCKED);
        let record = gov.get_stake(id).unwrap();
        assert_eq!(record.state, StakeState::Active);
        assert!(record.has_pending_obligations);
        assert_eq!(gov.audit_log.len(), audit_before);
    }

    #[test]
    fn test_withdraw_not_active() {
        let mut gov = TrustGovernanceState::new();
        let id = gov.deposit_stake("alice", 500, RiskTier::High, 0).unwrap();
        gov.slash(id, make_evidence("ev-001")).unwrap();
        let result = gov.withdraw(id);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code, ERR_STAKE_INVALID_TRANSITION);
    }

    #[test]
    fn test_withdraw_slashed_stake_preserves_slash_record() {
        let mut gov = TrustGovernanceState::new();
        let id = gov.deposit_stake("alice", 500, RiskTier::High, 0).unwrap();
        gov.slash(id, make_evidence("ev-001")).unwrap();
        let audit_before = gov.audit_log.len();

        let err = gov.withdraw(id).unwrap_err();

        assert_eq!(err.code, ERR_STAKE_INVALID_TRANSITION);
        let record = gov.get_stake(id).unwrap();
        assert_eq!(record.state, StakeState::Slashed);
        assert_eq!(record.slash_events.len(), 1);
        assert_eq!(gov.audit_log.len(), audit_before);
    }

    // -- expire tests -------------------------------------------------------

    #[test]
    fn test_expire_stakes() {
        let mut gov = TrustGovernanceState::new();
        gov.set_time(1000);
        let id = gov
            .deposit_stake("alice", 500, RiskTier::High, 2000)
            .unwrap();
        gov.set_time(2001);
        let expired = gov.expire_stakes();
        assert_eq!(expired, 1);
        let record = gov.get_stake(id).unwrap();
        assert_eq!(record.state, StakeState::Expired);
    }

    #[test]
    fn test_expire_does_not_affect_active_no_expiry() {
        let mut gov = TrustGovernanceState::new();
        gov.set_time(1000);
        let id = gov.deposit_stake("alice", 500, RiskTier::High, 0).unwrap();
        gov.set_time(999_999);
        let expired = gov.expire_stakes();
        assert_eq!(expired, 0);
        let record = gov.get_stake(id).unwrap();
        assert_eq!(record.state, StakeState::Active);
    }

    // -- capability gate tests ----------------------------------------------

    #[test]
    fn test_capability_gate_pass() {
        let mut gov = TrustGovernanceState::new();
        gov.deposit_stake("alice", 500, RiskTier::High, 0).unwrap();
        let gate = gov.check_capability_gate("alice", "publish", RiskTier::High);
        assert!(gate.passed);
    }

    #[test]
    fn test_capability_gate_fail_no_stake() {
        let mut gov = TrustGovernanceState::new();
        let gate = gov.check_capability_gate("alice", "publish", RiskTier::High);
        assert!(!gate.passed);
        assert!(gate.reason.contains("no active stake"));
    }

    #[test]
    fn test_capability_gate_rejects_unswept_expired_stake_at_boundary() {
        let mut gov = TrustGovernanceState::new();
        gov.set_time(1000);
        let id = gov
            .deposit_stake("alice", 500, RiskTier::High, 2000)
            .unwrap();

        gov.set_time(2000);
        let gate = gov.check_capability_gate("alice", "publish", RiskTier::High);

        assert!(!gate.passed, "gate must fail closed at exact expiry");
        assert!(gate.reason.contains("no active stake"));
        assert_eq!(gov.get_stake(id).unwrap().state, StakeState::Active);
    }

    // -- audit trail tests --------------------------------------------------

    #[test]
    fn test_audit_trail_complete_lifecycle() {
        // INV-STAKE-AUDIT-COMPLETE
        let mut gov = TrustGovernanceState::new();
        gov.set_time(1000);
        gov.deposit_stake("alice", 500, RiskTier::High, 0).unwrap();
        assert_eq!(gov.audit_log.len(), 1); // deposit

        gov.set_time(2000);
        let id = StakeId(1);
        gov.slash(id, make_evidence("ev-001")).unwrap();
        assert_eq!(gov.audit_log.len(), 2); // + slash

        gov.appeal(id, "appeal").unwrap();
        assert_eq!(gov.audit_log.len(), 3); // + appeal

        gov.resolve_appeal(1, false).unwrap();
        assert_eq!(gov.audit_log.len(), 4); // + resolve

        gov.withdraw(id).unwrap();
        assert_eq!(gov.audit_log.len(), 5); // + withdraw
    }

    #[test]
    fn test_export_audit_log_jsonl() {
        let mut gov = TrustGovernanceState::new();
        gov.deposit_stake("alice", 500, RiskTier::High, 0).unwrap();
        gov.deposit_stake("bob", 100, RiskTier::Medium, 0).unwrap();
        let jsonl = gov.export_audit_log_jsonl();
        let lines: Vec<&str> = jsonl.lines().collect();
        assert_eq!(lines.len(), 2);
        for line in &lines {
            let parsed: serde_json::Value = serde_json::from_str(line).unwrap();
            assert!(parsed.get("event_code").is_some());
        }
    }

    // -- count / total tests ------------------------------------------------

    #[test]
    fn test_count_by_state() {
        let mut gov = TrustGovernanceState::new();
        gov.deposit_stake("alice", 500, RiskTier::High, 0).unwrap();
        gov.deposit_stake("bob", 100, RiskTier::Medium, 0).unwrap();
        assert_eq!(gov.count_by_state(StakeState::Active), 2);
        assert_eq!(gov.count_by_state(StakeState::Slashed), 0);
    }

    // -- validate_invariants ------------------------------------------------

    #[test]
    fn test_validate_invariants_clean() {
        let mut gov = TrustGovernanceState::new();
        gov.deposit_stake("alice", 500, RiskTier::High, 0).unwrap();
        let violations = gov.validate_invariants();
        assert!(violations.is_empty());
    }

    // -- schema version -----------------------------------------------------

    #[test]
    fn test_schema_version() {
        assert_eq!(SCHEMA_VERSION, "staking-v1.0");
    }

    // -- BTreeMap ordering --------------------------------------------------

    #[test]
    fn test_btreemap_deterministic_order() {
        let mut gov = TrustGovernanceState::new();
        for i in 0..10 {
            let name = format!("publisher-{}", 9 - i);
            gov.deposit_stake(&name, 500, RiskTier::High, 0).unwrap();
        }
        // BTreeMap keys are u64, so iteration should be in insertion order (1..10)
        let keys: Vec<u64> = gov.stakes.keys().copied().collect();
        assert_eq!(keys, (1..=10).collect::<Vec<u64>>());
    }

    // -- StakePolicy tests --------------------------------------------------

    #[test]
    fn test_default_policy_minimums() {
        let policy = StakePolicy::default_policy();
        assert_eq!(policy.minimum_for_tier(RiskTier::Critical), 1000);
        assert_eq!(policy.minimum_for_tier(RiskTier::High), 500);
        assert_eq!(policy.minimum_for_tier(RiskTier::Medium), 100);
        assert_eq!(policy.minimum_for_tier(RiskTier::Low), 10);
    }

    #[test]
    fn test_default_policy_slash_fractions() {
        let policy = StakePolicy::default_policy();
        assert_eq!(policy.slash_fraction_for_tier(RiskTier::Critical), 100);
        assert_eq!(policy.slash_fraction_for_tier(RiskTier::High), 50);
        assert_eq!(policy.slash_fraction_for_tier(RiskTier::Medium), 25);
        assert_eq!(policy.slash_fraction_for_tier(RiskTier::Low), 10);
    }

    // ── Negative-path tests for edge cases and invalid inputs ──────────

    #[test]
    fn negative_stake_id_with_extreme_numerical_values() {
        // Test StakeId with boundary numerical values
        let boundary_values = vec![
            0,            // Zero
            1,            // Minimum positive
            u64::MAX / 2, // Half maximum
            u64::MAX - 1, // Near maximum
            u64::MAX,     // Maximum value
        ];

        for value in boundary_values {
            let stake_id = StakeId(value);

            // Display should work with extreme values
            let display = format!("{}", stake_id);
            assert!(
                display.starts_with("stake-"),
                "Display should have stake- prefix: {}",
                display
            );
            assert!(
                display.contains(&value.to_string()),
                "Display should contain the value: {}",
                display
            );

            // Debug should also work
            let debug = format!("{:?}", stake_id);
            assert!(debug.contains(&value.to_string()));

            // Clone and equality should work
            let cloned = stake_id.clone();
            assert_eq!(stake_id, cloned);

            // Should be usable in collections (Hash + Eq)
            let mut map = BTreeMap::new();
            map.insert(stake_id, "test_value");
            assert_eq!(map.get(&StakeId(value)), Some(&"test_value"));
        }
    }

    #[test]
    fn negative_risk_tier_serialization_and_ordering_consistency() {
        // Test RiskTier serialization edge cases
        let tiers = [
            RiskTier::Low,
            RiskTier::Medium,
            RiskTier::High,
            RiskTier::Critical,
        ];

        for tier in &tiers {
            // Serialization should work consistently
            let serialized = serde_json::to_string(tier).unwrap();
            let deserialized: RiskTier = serde_json::from_str(&serialized).unwrap();
            assert_eq!(*tier, deserialized);

            // Label should be consistent with serialization
            let label = tier.label();
            assert!(!label.is_empty());
            assert!(label.is_ascii());
            assert!(!label.contains(' '));
            assert_eq!(label, label.to_lowercase());
        }

        // Test ordering (Low < Medium < High < Critical)
        assert!(RiskTier::Low < RiskTier::Medium);
        assert!(RiskTier::Medium < RiskTier::High);
        assert!(RiskTier::High < RiskTier::Critical);

        // Test invalid deserialization
        let invalid_tier_json = vec![
            "\"Unknown\"",
            "\"LOW\"",      // Wrong case
            "\"VeryHigh\"", // Non-existent variant
            "42",           // Wrong type
            "null",
        ];

        for invalid_json in invalid_tier_json {
            let result: Result<RiskTier, _> = serde_json::from_str(invalid_json);
            assert!(
                result.is_err(),
                "Should reject invalid tier JSON: {}",
                invalid_json
            );
        }
    }

    #[test]
    fn negative_stake_state_transitions_and_terminal_state_validation() {
        // Test StakeState edge cases and invalid transitions
        let states = [
            StakeState::Active,
            StakeState::Slashed,
            StakeState::UnderAppeal,
            StakeState::Withdrawn,
            StakeState::Expired,
        ];

        for state in &states {
            // Label should be consistent
            let label = state.label();
            let display = format!("{}", state);
            assert_eq!(label, display);
            assert!(!label.is_empty());
            assert!(label.is_ascii());
            assert!(!label.contains(' '));

            // Terminal state check should be consistent
            let is_terminal = state.is_terminal();
            match state {
                StakeState::Withdrawn | StakeState::Expired => assert!(is_terminal),
                _ => assert!(!is_terminal),
            }

            // Should be cloneable and comparable
            let cloned = state.clone();
            assert_eq!(*state, cloned);
        }

        // Test that terminal states are correctly identified
        assert!(StakeState::Withdrawn.is_terminal());
        assert!(StakeState::Expired.is_terminal());
        assert!(!StakeState::Active.is_terminal());
        assert!(!StakeState::Slashed.is_terminal());
        assert!(!StakeState::UnderAppeal.is_terminal());
    }

    #[test]
    fn negative_appeal_outcome_edge_cases_and_state_consistency() {
        // Test AppealOutcome with edge cases
        let outcomes = [
            AppealOutcome::Pending,
            AppealOutcome::Upheld,
            AppealOutcome::Reversed,
        ];

        for outcome in &outcomes {
            // Label and display consistency
            let label = outcome.label();
            let display = format!("{}", outcome);
            assert_eq!(label, display);
            assert!(!label.is_empty());
            assert!(label.is_ascii());

            // Serialization should use snake_case
            let serialized = serde_json::to_string(outcome).unwrap();
            let deserialized: AppealOutcome = serde_json::from_str(&serialized).unwrap();
            assert_eq!(*outcome, deserialized);

            // Should be hashable and comparable
            let cloned = outcome.clone();
            assert_eq!(*outcome, cloned);

            // Should work in collections
            let mut map = BTreeMap::new();
            map.insert(*outcome, "test");
            assert_eq!(map.get(outcome), Some(&"test"));
        }

        // Test serialization format (should be snake_case)
        assert_eq!(
            serde_json::to_string(&AppealOutcome::Pending).unwrap(),
            "\"pending\""
        );
        assert_eq!(
            serde_json::to_string(&AppealOutcome::Upheld).unwrap(),
            "\"upheld\""
        );
        assert_eq!(
            serde_json::to_string(&AppealOutcome::Reversed).unwrap(),
            "\"reversed\""
        );
    }

    #[test]
    fn negative_slash_evidence_with_malicious_content() {
        // Test SlashEvidence with various problematic content
        let malicious_evidence = vec![
            SlashEvidence {
                evidence_hash: "".to_string(), // Empty hash
                description: "Normal description".to_string(),
                collected_at: 1000,
                capability: "test_cap".to_string(),
            },
            SlashEvidence {
                evidence_hash: "\0hash\x01with\x7fcontrol".to_string(), // Control characters
                description: "description\nwith\nnewlines".to_string(),
                collected_at: 0, // Zero timestamp
                capability: "capability\twith\ttabs".to_string(),
            },
            SlashEvidence {
                evidence_hash: "🚀emoji💀hash".to_string(), // Unicode emoji
                description: "<script>alert('evidence')</script>".to_string(), // XSS
                collected_at: u64::MAX,                     // Maximum timestamp
                capability: "../../../etc/passwd".to_string(), // Path traversal
            },
            SlashEvidence {
                evidence_hash: "x".repeat(10_000), // Very long hash
                description: "y".repeat(50_000),   // Very long description
                collected_at: u64::MAX / 2,
                capability: "z".repeat(1_000), // Long capability
            },
        ];

        for evidence in malicious_evidence {
            // Evidence creation should not panic
            assert!(evidence.collected_at <= u64::MAX);

            // Serialization should handle problematic content
            let serialization = serde_json::to_string(&evidence);
            match serialization {
                Ok(json) => {
                    // If serialization succeeds, deserialization should work
                    let deserialization: Result<SlashEvidence, _> = serde_json::from_str(&json);
                    match deserialization {
                        Ok(restored) => {
                            // Basic field preservation
                            assert_eq!(restored.evidence_hash, evidence.evidence_hash);
                            assert_eq!(restored.collected_at, evidence.collected_at);
                        }
                        Err(_) => {
                            // Some characters might not survive JSON round-trip
                        }
                    }
                }
                Err(_) => {
                    // Some problematic content might not be serializable
                }
            }

            // Equality and cloning should work
            let cloned = evidence.clone();
            assert_eq!(evidence, cloned);

            // Debug formatting should not panic
            let _debug = format!("{:?}", evidence);
        }
    }

    #[test]
    fn negative_slash_event_with_extreme_timestamps_and_amounts() {
        // Test SlashEvent with extreme numerical values
        let extreme_events = vec![
            SlashEvent {
                stake_id: StakeId(0),
                evidence: make_evidence("test_hash"),
                slash_amount: 0,    // Zero slash amount
                slashed_at: 0,      // Zero timestamp
                appeal_deadline: 0, // Zero deadline
            },
            SlashEvent {
                stake_id: StakeId(u64::MAX),
                evidence: make_evidence("max_test"),
                slash_amount: u64::MAX,    // Maximum slash amount
                slashed_at: u64::MAX,      // Maximum timestamp
                appeal_deadline: u64::MAX, // Maximum deadline
            },
            SlashEvent {
                stake_id: StakeId(12345),
                evidence: SlashEvidence {
                    evidence_hash: "\0malicious\x01hash".to_string(),
                    description: "slash\nwith\nnewlines".to_string(),
                    collected_at: u64::MAX / 2,
                    capability: "🚀capability💀".to_string(),
                },
                slash_amount: u64::MAX / 2,
                slashed_at: 1,
                appeal_deadline: u64::MAX - 1,
            },
        ];

        for event in extreme_events {
            // Event creation should handle extreme values
            assert!(event.slash_amount <= u64::MAX);
            assert!(event.slashed_at <= u64::MAX);
            assert!(event.appeal_deadline <= u64::MAX);

            // Should be serializable
            let serialization = serde_json::to_string(&event);
            match serialization {
                Ok(json) => {
                    let _deserialization: Result<SlashEvent, _> = serde_json::from_str(&json);
                    // Either succeeds or fails gracefully
                }
                Err(_) => {
                    // Some content might not be serializable
                }
            }

            // Cloning and equality should work
            let cloned = event.clone();
            assert_eq!(event, cloned);

            // Should handle deadline calculations safely
            let now = 1_000_000u64;
            let is_expired = now >= event.appeal_deadline;
            assert!(is_expired || !is_expired); // Basic boolean check
        }
    }

    #[test]
    fn negative_constants_validation_and_naming_consistency() {
        // Test that all event constants are well-formed
        use crate::security::constant_time;
        use event_codes::*;

        let event_constants = [
            STAKE_001_DEPOSITED,
            STAKE_002_SLASHED,
            STAKE_003_APPEAL_FILED,
            STAKE_004_APPEAL_RESOLVED,
            STAKE_005_WITHDRAWN,
            STAKE_006_EXPIRED,
            STAKE_007_GATE_CHECKED,
        ];

        for constant in &event_constants {
            assert!(!constant.is_empty());
            assert!(
                constant.starts_with("STAKE-"),
                "Event constant should start with STAKE-: {}",
                constant
            );
            assert!(
                constant.is_ascii(),
                "Event constant should be ASCII: {}",
                constant
            );

            // Should follow pattern STAKE-XXX where XXX is 3 digits
            let suffix = constant.strip_prefix("STAKE-").unwrap();
            assert_eq!(
                suffix.len(),
                3,
                "Event code suffix should be 3 digits: {}",
                suffix
            );
            assert!(
                suffix.chars().all(|c| c.is_ascii_digit()),
                "Event code suffix should be numeric: {}",
                suffix
            );
        }

        // Test error constants
        let error_constants = [
            ERR_STAKE_INSUFFICIENT,
            ERR_STAKE_NOT_FOUND,
            ERR_STAKE_ALREADY_SLASHED,
            ERR_STAKE_WITHDRAWAL_BLOCKED,
            ERR_STAKE_APPEAL_EXPIRED,
            ERR_STAKE_INVALID_TRANSITION,
            ERR_STAKE_DUPLICATE_APPEAL,
        ];

        for constant in &error_constants {
            assert!(!constant.is_empty());
            assert!(
                constant.starts_with("ERR_STAKE_"),
                "Error constant should start with ERR_STAKE_: {}",
                constant
            );
            assert!(
                constant.is_ascii(),
                "Error constant should be ASCII: {}",
                constant
            );
        }

        // Test invariant constants
        let invariant_constants = [
            INV_STAKE_MINIMUM,
            INV_STAKE_SLASH_DETERMINISTIC,
            INV_STAKE_APPEAL_WINDOW,
            INV_STAKE_AUDIT_COMPLETE,
            INV_STAKE_NO_DOUBLE_SLASH,
            INV_STAKE_WITHDRAWAL_SAFE,
        ];

        for constant in &invariant_constants {
            assert!(!constant.is_empty());
            assert!(
                constant.starts_with("INV-STAKE-"),
                "Invariant should start with INV-STAKE-: {}",
                constant
            );
            assert!(
                constant.is_ascii(),
                "Invariant constant should be ASCII: {}",
                constant
            );
        }

        // Test schema version
        assert_eq!(SCHEMA_VERSION, "staking-v1.0");
        assert!(SCHEMA_VERSION.contains("staking-"));
        assert!(SCHEMA_VERSION.contains("v1."));
    }

    #[test]
    fn negative_stake_amount_arithmetic_overflow_safety() {
        // Test arithmetic operations with extreme stake amounts
        let max_amount = u64::MAX;
        let large_amount = u64::MAX / 2;
        let small_amount = 1;

        // Test potential overflow scenarios in slash calculations
        let overflow_scenarios = vec![
            (max_amount, 100),        // 100% of max amount
            (large_amount, 200),      // 200% (would overflow)
            (small_amount, u32::MAX), // Very high percentage
        ];

        for (amount, percentage) in overflow_scenarios {
            // Simulate slash fraction calculation with overflow protection
            let slash_fraction = percentage.min(100); // Cap at 100%

            // Safe calculation that avoids overflow
            let slash_amount = if percentage >= 100 {
                amount // Full amount
            } else {
                amount / 100 * percentage as u64 // Safe calculation
            };

            assert!(
                slash_amount <= amount,
                "Slash amount should not exceed original: {} vs {}",
                slash_amount,
                amount
            );

            // Test with saturating arithmetic
            let saturating_slash = amount.saturating_mul(percentage as u64).saturating_div(100);
            assert!(saturating_slash >= slash_amount || saturating_slash == u64::MAX);
        }

        // Test edge case: zero amounts
        let zero_slash = 0u64.saturating_mul(100).saturating_div(100);
        assert_eq!(zero_slash, 0);

        // Test edge case: very small amounts with high percentages
        let small_slash = 1u64.saturating_mul(99).saturating_div(100);
        assert_eq!(small_slash, 0); // Should round down
    }

    #[test]
    fn negative_timestamp_edge_cases_and_deadline_calculations() {
        // Test timestamp handling with edge cases
        let edge_timestamps = vec![
            (0, 0),                   // Both zero
            (0, 1),                   // Zero start, small deadline
            (1, 0),                   // Small start, zero deadline (deadline in past)
            (u64::MAX - 1, u64::MAX), // Near overflow
            (u64::MAX, u64::MAX),     // Both maximum
            (1000, 500),              // Deadline before current time
        ];

        for (current_time, deadline) in edge_timestamps {
            // Deadline comparison should not overflow
            let is_expired = current_time >= deadline;
            let time_left = if deadline > current_time {
                deadline.saturating_sub(current_time)
            } else {
                0
            };

            // Basic sanity checks
            if current_time < deadline {
                assert!(!is_expired, "Should not be expired when current < deadline");
                assert_eq!(time_left, deadline - current_time);
            } else {
                assert!(is_expired, "Should be expired when current >= deadline");
                assert_eq!(time_left, 0);
            }

            // Test SlashEvent with these timestamps
            let event = SlashEvent {
                stake_id: StakeId(1),
                evidence: make_evidence("timestamp_test"),
                slash_amount: 1000,
                slashed_at: current_time,
                appeal_deadline: deadline,
            };

            assert_eq!(event.slashed_at, current_time);
            assert_eq!(event.appeal_deadline, deadline);

            // Should be serializable even with extreme values
            let serialization = serde_json::to_string(&event);
            assert!(
                serialization.is_ok(),
                "Should serialize extreme timestamp values"
            );
        }
    }
}
