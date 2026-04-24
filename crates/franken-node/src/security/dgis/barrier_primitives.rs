//! Trust barrier primitives and policy wiring for the DGIS enforcement layer (bd-1tnu).
//!
//! Four barrier categories:
//! 1. **Behavioral sandbox escalation** — tighten sandbox constraints on high-risk nodes
//! 2. **Composition firewall** — prevent transitive capability leakage across boundaries
//! 3. **Verified-fork pinning** — lock deps to verified fork snapshots with signature checks
//! 4. **Staged rollout fences** — gate updates through progressive deployment phases
//!
//! All primitives are independently testable, composable (multiple barriers per node),
//! and produce audit receipts for every enforcement action.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt;
use uuid::Uuid;

use crate::runtime::clock;
use crate::security::constant_time;

// ---------------------------------------------------------------------------
// Event codes (structured logging)
// ---------------------------------------------------------------------------

use crate::capacity_defaults::aliases::MAX_AUDIT_LOG_ENTRIES;

/// Maximum number of barriers per node before oldest-first eviction.
const MAX_BARRIERS_PER_NODE: usize = 256;

/// Maximum number of audit receipts a single barrier plan may emit.
const MAX_BARRIER_RECEIPTS: usize = 1024;

/// Stable event codes for DGIS barrier enforcement.
pub mod event_codes {
    pub const BARRIER_APPLIED: &str = "DGIS-BARRIER-001";
    pub const BARRIER_REMOVED: &str = "DGIS-BARRIER-002";
    pub const BARRIER_OVERRIDDEN: &str = "DGIS-BARRIER-003";
    pub const BARRIER_EXPIRED: &str = "DGIS-BARRIER-004";
    pub const BARRIER_CHECK_PASSED: &str = "DGIS-BARRIER-005";
    pub const BARRIER_CHECK_DENIED: &str = "DGIS-BARRIER-006";
    pub const BARRIER_CHECK_NOT_APPLICABLE: &str = "DGIS-BARRIER-007";
    pub const SANDBOX_ESCALATED: &str = "DGIS-BARRIER-010";
    pub const FIREWALL_ENFORCED: &str = "DGIS-BARRIER-020";
    pub const FORK_PIN_VERIFIED: &str = "DGIS-BARRIER-030";
    pub const FORK_PIN_REJECTED: &str = "DGIS-BARRIER-031";
    pub const ROLLOUT_FENCE_ADVANCED: &str = "DGIS-BARRIER-040";
    pub const ROLLOUT_FENCE_BLOCKED: &str = "DGIS-BARRIER-041";
    pub const ROLLOUT_FENCE_ROLLED_BACK: &str = "DGIS-BARRIER-042";
    pub const COMPOSITION_ERROR: &str = "DGIS-BARRIER-ERR-001";
    pub const OVERRIDE_INVALID: &str = "DGIS-BARRIER-ERR-002";
}

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum BarrierError {
    #[error("barrier check denied: node={node_id}, barrier={barrier_type}, reason={reason}")]
    CheckDenied {
        node_id: String,
        barrier_type: String,
        reason: String,
    },
    #[error("sandbox escalation failed: {0}")]
    SandboxEscalation(String),
    #[error(
        "composition firewall violation: capability '{capability}' leaked across boundary '{boundary}'"
    )]
    FirewallViolation {
        capability: String,
        boundary: String,
    },
    #[error("fork pin verification failed: {0}")]
    ForkPinVerification(String),
    #[error("rollout fence blocked: phase={phase}, reason={reason}")]
    RolloutFenceBlocked { phase: String, reason: String },
    #[error("override rejected: {0}")]
    OverrideRejected(String),
    #[error("barrier composition conflict: {0}")]
    CompositionConflict(String),
    #[error("invalid progression criteria: {0}")]
    InvalidProgressionCriteria(String),
    #[error("barrier expired: barrier={barrier_id}, expires_at={expires_at}, reason={reason}")]
    BarrierExpired {
        barrier_id: String,
        expires_at: String,
        reason: String,
    },
    #[error("barrier not found: {0}")]
    NotFound(String),
    #[error("barrier plan too large: count={count}, cap={cap}")]
    PlanTooLarge { count: usize, cap: usize },
}

// ---------------------------------------------------------------------------
// Barrier types
// ---------------------------------------------------------------------------

/// The four categories of barrier primitives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BarrierType {
    SandboxEscalation,
    CompositionFirewall,
    VerifiedForkPin,
    StagedRolloutFence,
}

impl BarrierType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::SandboxEscalation => "sandbox_escalation",
            Self::CompositionFirewall => "composition_firewall",
            Self::VerifiedForkPin => "verified_fork_pin",
            Self::StagedRolloutFence => "staged_rollout_fence",
        }
    }
}

impl fmt::Display for BarrierType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Risk level
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

impl RiskLevel {
    pub fn numeric(&self) -> u8 {
        match self {
            Self::Low => 1,
            Self::Medium => 2,
            Self::High => 3,
            Self::Critical => 4,
        }
    }
}

// ---------------------------------------------------------------------------
// Sandbox escalation
// ---------------------------------------------------------------------------

/// Sandbox profile tier for escalation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SandboxTier {
    Permissive,
    Moderate,
    Strict,
    Isolated,
}

impl SandboxTier {
    pub fn level(&self) -> u8 {
        match self {
            Self::Permissive => 0,
            Self::Moderate => 1,
            Self::Strict => 2,
            Self::Isolated => 3,
        }
    }

    /// Returns true if `target` is a tighter tier (escalation).
    pub fn is_escalation_to(&self, target: &SandboxTier) -> bool {
        target.level() > self.level()
    }
}

impl fmt::Display for SandboxTier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Permissive => write!(f, "permissive"),
            Self::Moderate => write!(f, "moderate"),
            Self::Strict => write!(f, "strict"),
            Self::Isolated => write!(f, "isolated"),
        }
    }
}

/// Configuration for sandbox escalation on a specific node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxEscalationConfig {
    pub min_tier: SandboxTier,
    pub denied_capabilities: Vec<String>,
    pub risk_threshold: RiskLevel,
}

// ---------------------------------------------------------------------------
// Composition firewall
// ---------------------------------------------------------------------------

/// Configuration for composition firewall on a dependency boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompositionFirewallConfig {
    pub boundary_id: String,
    pub blocked_capabilities: Vec<String>,
    pub allow_list: Vec<String>,
}

// ---------------------------------------------------------------------------
// Verified-fork pinning
// ---------------------------------------------------------------------------

/// Configuration for pinning a dependency to a verified fork.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedForkPinConfig {
    pub fork_url: String,
    pub pinned_commit: String,
    pub signature_pubkey_hex: String,
    pub expected_digest: String,
}

// ---------------------------------------------------------------------------
// Staged rollout fences
// ---------------------------------------------------------------------------

/// Rollout phase identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RolloutPhase {
    Canary,
    Limited,
    Progressive,
    General,
}

impl RolloutPhase {
    pub fn ordinal(&self) -> u8 {
        match self {
            Self::Canary => 0,
            Self::Limited => 1,
            Self::Progressive => 2,
            Self::General => 3,
        }
    }

    pub fn next(&self) -> Option<RolloutPhase> {
        match self {
            Self::Canary => Some(Self::Limited),
            Self::Limited => Some(Self::Progressive),
            Self::Progressive => Some(Self::General),
            Self::General => None,
        }
    }
}

impl fmt::Display for RolloutPhase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Canary => write!(f, "canary"),
            Self::Limited => write!(f, "limited"),
            Self::Progressive => write!(f, "progressive"),
            Self::General => write!(f, "general"),
        }
    }
}

/// Progression criteria for advancing a rollout fence.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "ProgressionCriteriaWire")]
pub struct ProgressionCriteria {
    pub min_soak_seconds: u64,
    pub max_error_rate: f64,
    pub min_success_count: u64,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
struct ProgressionCriteriaWire {
    min_soak_seconds: u64,
    max_error_rate: f64,
    min_success_count: u64,
}

impl Default for ProgressionCriteria {
    fn default() -> Self {
        Self::new(3600, 0.01, 100).expect("default progression criteria must be valid")
    }
}

impl ProgressionCriteria {
    pub fn new(
        min_soak_seconds: u64,
        max_error_rate: f64,
        min_success_count: u64,
    ) -> Result<Self, BarrierError> {
        Self::validate_max_error_rate(max_error_rate)?;
        Ok(Self {
            min_soak_seconds,
            max_error_rate,
            min_success_count,
        })
    }

    pub fn set_max_error_rate(&mut self, max_error_rate: f64) -> Result<(), BarrierError> {
        Self::validate_max_error_rate(max_error_rate)?;
        self.max_error_rate = max_error_rate;
        Ok(())
    }

    pub fn validate(&self) -> Result<(), BarrierError> {
        Self::validate_max_error_rate(self.max_error_rate)
    }

    fn validate_max_error_rate(max_error_rate: f64) -> Result<(), BarrierError> {
        if !max_error_rate.is_finite() || !(0.0..=1.0).contains(&max_error_rate) {
            return Err(BarrierError::InvalidProgressionCriteria(format!(
                "max_error_rate must be finite and within [0.0, 1.0] (got {max_error_rate})"
            )));
        }
        Ok(())
    }
}

impl TryFrom<ProgressionCriteriaWire> for ProgressionCriteria {
    type Error = BarrierError;

    fn try_from(value: ProgressionCriteriaWire) -> Result<Self, Self::Error> {
        Self::new(
            value.min_soak_seconds,
            value.max_error_rate,
            value.min_success_count,
        )
    }
}

/// Configuration for staged rollout fence.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StagedRolloutFenceConfig {
    pub initial_phase: RolloutPhase,
    pub progression_criteria: BTreeMap<String, ProgressionCriteria>,
    pub auto_rollback_on_breach: bool,
}

impl StagedRolloutFenceConfig {
    pub fn validate(&self) -> Result<(), BarrierError> {
        for (phase, criteria) in &self.progression_criteria {
            criteria.validate().map_err(|err| match err {
                BarrierError::InvalidProgressionCriteria(message) => {
                    BarrierError::InvalidProgressionCriteria(format!(
                        "phase '{phase}' has invalid criteria: {message}"
                    ))
                }
                other => other,
            })?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Unified barrier instance
// ---------------------------------------------------------------------------

/// A barrier applied to a specific dependency graph node.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Barrier {
    pub barrier_id: String,
    pub node_id: String,
    pub barrier_type: BarrierType,
    pub config: BarrierConfig,
    pub applied_at: String,
    pub expires_at: Option<String>,
    pub source_plan_id: Option<String>,
}

/// Type-safe barrier configuration variants.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum BarrierConfig {
    SandboxEscalation(SandboxEscalationConfig),
    CompositionFirewall(CompositionFirewallConfig),
    VerifiedForkPin(VerifiedForkPinConfig),
    StagedRolloutFence(StagedRolloutFenceConfig),
}

impl BarrierConfig {
    pub fn barrier_type(&self) -> BarrierType {
        match self {
            Self::SandboxEscalation(_) => BarrierType::SandboxEscalation,
            Self::CompositionFirewall(_) => BarrierType::CompositionFirewall,
            Self::VerifiedForkPin(_) => BarrierType::VerifiedForkPin,
            Self::StagedRolloutFence(_) => BarrierType::StagedRolloutFence,
        }
    }
}

// ---------------------------------------------------------------------------
// Override justification
// ---------------------------------------------------------------------------

/// Signed override justification for bypassing a barrier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OverrideJustification {
    pub override_id: String,
    pub principal_identity: String,
    pub reason: String,
    pub timestamp: String,
    pub signature_hex: String,
}

impl OverrideJustification {
    /// Validate that required fields are present and non-empty.
    pub fn validate(&self) -> Result<(), BarrierError> {
        if self.override_id.trim().is_empty() {
            return Err(BarrierError::OverrideRejected(
                "override_id is required".to_string(),
            ));
        }
        if self.principal_identity.trim().is_empty() {
            return Err(BarrierError::OverrideRejected(
                "principal_identity is required".to_string(),
            ));
        }
        if self.reason.trim().is_empty() {
            return Err(BarrierError::OverrideRejected(
                "reason is required".to_string(),
            ));
        }
        if self.timestamp.trim().is_empty() {
            return Err(BarrierError::OverrideRejected(
                "timestamp is required".to_string(),
            ));
        }
        if self.signature_hex.trim().is_empty() {
            return Err(BarrierError::OverrideRejected(
                "signature is required".to_string(),
            ));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Audit receipt
// ---------------------------------------------------------------------------

/// Audit receipt emitted for every barrier enforcement action.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BarrierAuditReceipt {
    pub receipt_id: String,
    pub event_code: String,
    pub barrier_id: String,
    pub node_id: String,
    pub barrier_type: BarrierType,
    pub action: BarrierAction,
    pub timestamp: String,
    pub trace_id: String,
    pub details: serde_json::Value,
    pub override_justification: Option<OverrideJustification>,
}

/// Actions recorded in audit receipts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BarrierAction {
    Applied,
    Removed,
    CheckPassed,
    NotApplicable,
    CheckDenied,
    Overridden,
    Expired,
    PhaseAdvanced,
    RolledBack,
}

impl BarrierAuditReceipt {
    pub fn new(
        event_code: &str,
        barrier: &Barrier,
        action: BarrierAction,
        trace_id: &str,
        details: serde_json::Value,
    ) -> Self {
        Self {
            receipt_id: Uuid::now_v7().to_string(),
            event_code: event_code.to_string(),
            barrier_id: barrier.barrier_id.clone(),
            node_id: barrier.node_id.clone(),
            barrier_type: barrier.barrier_type,
            action,
            timestamp: clock::wall_now().to_rfc3339(),
            trace_id: trace_id.to_string(),
            details,
            override_justification: None,
        }
    }

    pub fn with_override(mut self, justification: OverrideJustification) -> Self {
        self.override_justification = Some(justification);
        self
    }

    /// Compute a deterministic hash of this receipt for chain-linking.
    pub fn content_hash(&self) -> Result<String, serde_json::Error> {
        let canonical = serde_json::to_string(self)?;
        let mut hasher = Sha256::new();
        hasher.update(b"barrier_primitives_content_hash_v1:");
        hasher.update(len_to_u64(canonical.len()).to_le_bytes());
        hasher.update(canonical.as_bytes());
        let digest = hasher.finalize();
        Ok(hex::encode(digest))
    }
}

fn len_to_u64(len: usize) -> u64 {
    u64::try_from(len).unwrap_or(u64::MAX)
}

// ---------------------------------------------------------------------------
// Rollout state tracking
// ---------------------------------------------------------------------------

/// Tracks the current phase and metrics for a staged rollout fence.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RolloutState {
    pub current_phase: RolloutPhase,
    pub phase_entered_at: String,
    pub success_count: u64,
    pub error_count: u64,
    pub total_count: u64,
}

impl RolloutState {
    pub fn new(phase: RolloutPhase) -> Self {
        Self {
            current_phase: phase,
            phase_entered_at: clock::wall_now().to_rfc3339(),
            success_count: 0,
            error_count: 0,
            total_count: 0,
        }
    }

    pub fn error_rate(&self) -> f64 {
        if self.total_count == 0 {
            return 0.0;
        }
        let rate = self.error_count as f64 / self.total_count as f64;
        if !rate.is_finite() {
            return 0.0; // fail-closed on NaN/Inf
        }
        rate
    }

    pub fn record_success(&mut self) {
        self.success_count = self.success_count.saturating_add(1);
        self.total_count = self.total_count.saturating_add(1);
    }

    pub fn record_error(&mut self) {
        self.error_count = self.error_count.saturating_add(1);
        self.total_count = self.total_count.saturating_add(1);
    }
}

// ---------------------------------------------------------------------------
// Barrier enforcement engine
// ---------------------------------------------------------------------------

/// The barrier enforcement engine manages applied barriers and produces audit receipts.
#[derive(Debug, Clone)]
pub struct BarrierEngine {
    barriers: BTreeMap<String, Barrier>,
    node_barriers: BTreeMap<String, Vec<String>>,
    rollout_states: BTreeMap<String, RolloutState>,
    audit_log: Vec<BarrierAuditReceipt>,
}

impl Default for BarrierEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl BarrierEngine {
    pub fn new() -> Self {
        Self {
            barriers: BTreeMap::new(),
            node_barriers: BTreeMap::new(),
            rollout_states: BTreeMap::new(),
            audit_log: Vec::new(),
        }
    }

    /// Apply a barrier to a node. Emits an audit receipt.
    pub fn apply_barrier(
        &mut self,
        barrier: Barrier,
        trace_id: &str,
    ) -> Result<BarrierAuditReceipt, BarrierError> {
        if self.barriers.contains_key(&barrier.barrier_id) {
            return Err(BarrierError::CompositionConflict(format!(
                "barrier id {} already exists",
                barrier.barrier_id
            )));
        }

        // Check composition validity before applying
        self.check_composition_validity(&barrier)?;

        let receipt = BarrierAuditReceipt::new(
            event_codes::BARRIER_APPLIED,
            &barrier,
            BarrierAction::Applied,
            trace_id,
            serde_json::json!({
                "barrier_config": barrier.config,
                "source_plan_id": barrier.source_plan_id,
            }),
        );

        // Initialize rollout state if this is a staged rollout fence
        if let BarrierConfig::StagedRolloutFence(ref cfg) = barrier.config {
            self.rollout_states.insert(
                barrier.barrier_id.clone(),
                RolloutState::new(cfg.initial_phase),
            );
        }

        let barrier_id = barrier.barrier_id.clone();
        let node_id = barrier.node_id.clone();

        self.barriers.insert(barrier_id.clone(), barrier);
        let node_list = self.node_barriers.entry(node_id).or_default();
        push_bounded(node_list, barrier_id, MAX_BARRIERS_PER_NODE);

        self.push_audit(receipt.clone());
        Ok(receipt)
    }

    /// Remove a barrier by ID. Emits an audit receipt.
    pub fn remove_barrier(
        &mut self,
        barrier_id: &str,
        trace_id: &str,
    ) -> Result<BarrierAuditReceipt, BarrierError> {
        let barrier = self
            .barriers
            .remove(barrier_id)
            .ok_or_else(|| BarrierError::NotFound(barrier_id.to_string()))?;

        let receipt = BarrierAuditReceipt::new(
            event_codes::BARRIER_REMOVED,
            &barrier,
            BarrierAction::Removed,
            trace_id,
            serde_json::json!({}),
        );

        if let Some(ids) = self.node_barriers.get_mut(&barrier.node_id) {
            ids.retain(|id| id != barrier_id);
        }
        self.rollout_states.remove(barrier_id);
        self.push_audit(receipt.clone());
        Ok(receipt)
    }

    /// Override a barrier with signed justification. Emits an audit receipt.
    pub fn override_barrier(
        &mut self,
        barrier_id: &str,
        justification: OverrideJustification,
        trace_id: &str,
    ) -> Result<BarrierAuditReceipt, BarrierError> {
        justification.validate()?;

        let barrier = self
            .barriers
            .get(barrier_id)
            .ok_or_else(|| BarrierError::NotFound(barrier_id.to_string()))?;

        let receipt = BarrierAuditReceipt::new(
            event_codes::BARRIER_OVERRIDDEN,
            barrier,
            BarrierAction::Overridden,
            trace_id,
            serde_json::json!({
                "principal": justification.principal_identity,
                "reason": justification.reason,
            }),
        )
        .with_override(justification);

        self.push_audit(receipt.clone());
        Ok(receipt)
    }

    // -----------------------------------------------------------------------
    // Sandbox escalation enforcement
    // -----------------------------------------------------------------------

    /// Check if a capability request is allowed under sandbox escalation barriers.
    pub fn check_sandbox_escalation(
        &mut self,
        node_id: &str,
        requested_capability: &str,
        current_tier: SandboxTier,
        trace_id: &str,
    ) -> Result<BarrierAuditReceipt, BarrierError> {
        let barrier_ids = self.get_node_barrier_ids(node_id);
        let mut matched_barrier = None;

        for barrier_id in &barrier_ids {
            let Some(barrier) = self.barriers.get(barrier_id).cloned() else {
                continue;
            };
            if !matches!(barrier.config, BarrierConfig::SandboxEscalation(_)) {
                continue;
            }
            self.enforce_barrier_not_expired(&barrier, trace_id)?;
            if let BarrierConfig::SandboxEscalation(ref cfg) = barrier.config {
                if matched_barrier.is_none() {
                    matched_barrier = Some(barrier.clone());
                }

                // Enforce minimum tier
                if current_tier.level() < cfg.min_tier.level() {
                    let receipt = BarrierAuditReceipt::new(
                        event_codes::BARRIER_CHECK_DENIED,
                        &barrier,
                        BarrierAction::CheckDenied,
                        trace_id,
                        serde_json::json!({
                            "reason": "sandbox tier below minimum",
                            "current_tier": format!("{current_tier}"),
                            "required_tier": format!("{}", cfg.min_tier),
                        }),
                    );
                    self.push_audit(receipt);
                    return Err(BarrierError::SandboxEscalation(format!(
                        "node {node_id} requires at least {}, currently at {current_tier}",
                        cfg.min_tier
                    )));
                }

                // Check denied capabilities
                if cfg
                    .denied_capabilities
                    .contains(&requested_capability.to_string())
                {
                    let receipt = BarrierAuditReceipt::new(
                        event_codes::BARRIER_CHECK_DENIED,
                        &barrier,
                        BarrierAction::CheckDenied,
                        trace_id,
                        serde_json::json!({
                            "reason": "capability denied by sandbox escalation",
                            "capability": requested_capability,
                        }),
                    );
                    self.push_audit(receipt);
                    return Err(BarrierError::SandboxEscalation(format!(
                        "capability '{requested_capability}' denied on node {node_id}"
                    )));
                }
            }
        }

        let receipt = matched_barrier.map_or_else(
            || {
                self.make_not_applicable_receipt(
                    node_id,
                    BarrierType::SandboxEscalation,
                    trace_id,
                    serde_json::json!({
                        "reason": "no_sandbox_barrier_configured",
                        "capability": requested_capability,
                        "tier": format!("{current_tier}"),
                    }),
                )
            },
            |barrier| {
                BarrierAuditReceipt::new(
                    event_codes::SANDBOX_ESCALATED,
                    &barrier,
                    BarrierAction::CheckPassed,
                    trace_id,
                    serde_json::json!({
                        "capability": requested_capability,
                        "tier": format!("{current_tier}"),
                    }),
                )
            },
        );
        self.push_audit(receipt.clone());
        Ok(receipt)
    }

    // -----------------------------------------------------------------------
    // Composition firewall enforcement
    // -----------------------------------------------------------------------

    /// Check if a capability crosses a composition firewall boundary.
    pub fn check_composition_firewall(
        &mut self,
        node_id: &str,
        capability: &str,
        target_boundary: &str,
        trace_id: &str,
    ) -> Result<BarrierAuditReceipt, BarrierError> {
        let barrier_ids = self.get_node_barrier_ids(node_id);
        let mut matched_barrier = None;

        for barrier_id in &barrier_ids {
            let Some(barrier) = self.barriers.get(barrier_id).cloned() else {
                continue;
            };
            let matches_boundary = matches!(
                &barrier.config,
                BarrierConfig::CompositionFirewall(cfg) if cfg.boundary_id == target_boundary
            );
            if !matches_boundary {
                continue;
            }
            self.enforce_barrier_not_expired(&barrier, trace_id)?;
            if let BarrierConfig::CompositionFirewall(ref cfg) = barrier.config {
                if matched_barrier.is_none() {
                    matched_barrier = Some(barrier.clone());
                }

                // Capability blocked unless in allow list
                let is_allowed = cfg.allow_list.contains(&capability.to_string());
                let is_blocked = cfg.blocked_capabilities.contains(&capability.to_string());

                if is_blocked && !is_allowed {
                    let receipt = BarrierAuditReceipt::new(
                        event_codes::BARRIER_CHECK_DENIED,
                        &barrier,
                        BarrierAction::CheckDenied,
                        trace_id,
                        serde_json::json!({
                            "reason": "capability blocked by composition firewall",
                            "capability": capability,
                            "boundary": target_boundary,
                        }),
                    );
                    self.push_audit(receipt);
                    return Err(BarrierError::FirewallViolation {
                        capability: capability.to_string(),
                        boundary: target_boundary.to_string(),
                    });
                }
            }
        }

        let receipt = matched_barrier.map_or_else(
            || {
                self.make_not_applicable_receipt(
                    node_id,
                    BarrierType::CompositionFirewall,
                    trace_id,
                    serde_json::json!({
                        "reason": "no_matching_firewall_boundary",
                        "capability": capability,
                        "boundary": target_boundary,
                    }),
                )
            },
            |barrier| {
                BarrierAuditReceipt::new(
                    event_codes::FIREWALL_ENFORCED,
                    &barrier,
                    BarrierAction::CheckPassed,
                    trace_id,
                    serde_json::json!({
                        "capability": capability,
                        "boundary": target_boundary,
                    }),
                )
            },
        );
        self.push_audit(receipt.clone());
        Ok(receipt)
    }

    // -----------------------------------------------------------------------
    // Verified-fork pinning enforcement
    // -----------------------------------------------------------------------

    /// Verify that a dependency artifact matches its pinned fork digest.
    pub fn check_fork_pin(
        &mut self,
        node_id: &str,
        artifact_digest: &str,
        trace_id: &str,
    ) -> Result<BarrierAuditReceipt, BarrierError> {
        let barrier_ids = self.get_node_barrier_ids(node_id);
        let mut matched_barrier = None;

        for barrier_id in &barrier_ids {
            let Some(barrier) = self.barriers.get(barrier_id).cloned() else {
                continue;
            };
            if !matches!(barrier.config, BarrierConfig::VerifiedForkPin(_)) {
                continue;
            }
            self.enforce_barrier_not_expired(&barrier, trace_id)?;
            if let BarrierConfig::VerifiedForkPin(ref cfg) = barrier.config {
                if matched_barrier.is_none() {
                    matched_barrier = Some(barrier.clone());
                }

                if !constant_time::ct_eq(&cfg.expected_digest, artifact_digest) {
                    let receipt = BarrierAuditReceipt::new(
                        event_codes::FORK_PIN_REJECTED,
                        &barrier,
                        BarrierAction::CheckDenied,
                        trace_id,
                        serde_json::json!({
                            "expected_digest": cfg.expected_digest,
                            "actual_digest": artifact_digest,
                            "pinned_commit": cfg.pinned_commit,
                        }),
                    );
                    self.push_audit(receipt);
                    return Err(BarrierError::ForkPinVerification(format!(
                        "digest mismatch for node {node_id}: expected {}, got {artifact_digest}",
                        cfg.expected_digest
                    )));
                }
            }
        }

        let receipt = matched_barrier.map_or_else(
            || {
                self.make_not_applicable_receipt(
                    node_id,
                    BarrierType::VerifiedForkPin,
                    trace_id,
                    serde_json::json!({
                        "reason": "no_verified_fork_barrier_configured",
                        "artifact_digest": artifact_digest,
                    }),
                )
            },
            |barrier| {
                BarrierAuditReceipt::new(
                    event_codes::FORK_PIN_VERIFIED,
                    &barrier,
                    BarrierAction::CheckPassed,
                    trace_id,
                    serde_json::json!({
                        "artifact_digest": artifact_digest,
                    }),
                )
            },
        );
        self.push_audit(receipt.clone());
        Ok(receipt)
    }

    // -----------------------------------------------------------------------
    // Staged rollout fence enforcement
    // -----------------------------------------------------------------------

    /// Check if the current rollout phase permits the operation.
    pub fn check_rollout_fence(
        &mut self,
        barrier_id: &str,
        required_phase: RolloutPhase,
        trace_id: &str,
    ) -> Result<BarrierAuditReceipt, BarrierError> {
        let barrier = self
            .barriers
            .get(barrier_id)
            .ok_or_else(|| BarrierError::NotFound(barrier_id.to_string()))?
            .clone();

        self.enforce_barrier_not_expired(&barrier, trace_id)?;

        let state = self
            .rollout_states
            .get(barrier_id)
            .cloned()
            .ok_or_else(|| BarrierError::NotFound(format!("rollout state for {barrier_id}")))?;

        if state.current_phase.ordinal() < required_phase.ordinal() {
            let receipt = BarrierAuditReceipt::new(
                event_codes::ROLLOUT_FENCE_BLOCKED,
                &barrier,
                BarrierAction::CheckDenied,
                trace_id,
                serde_json::json!({
                    "current_phase": format!("{}", state.current_phase),
                    "required_phase": format!("{required_phase}"),
                }),
            );
            self.push_audit(receipt);
            return Err(BarrierError::RolloutFenceBlocked {
                phase: format!("{}", state.current_phase),
                reason: format!(
                    "requires phase {required_phase}, currently at {}",
                    state.current_phase
                ),
            });
        }

        let receipt = BarrierAuditReceipt::new(
            event_codes::BARRIER_CHECK_PASSED,
            &barrier,
            BarrierAction::CheckPassed,
            trace_id,
            serde_json::json!({
                "current_phase": format!("{}", state.current_phase),
                "required_phase": format!("{required_phase}"),
            }),
        );
        self.push_audit(receipt.clone());
        Ok(receipt)
    }

    /// Advance a rollout fence to its next phase.
    pub fn advance_rollout_phase(
        &mut self,
        barrier_id: &str,
        trace_id: &str,
    ) -> Result<BarrierAuditReceipt, BarrierError> {
        let barrier = self
            .barriers
            .get(barrier_id)
            .ok_or_else(|| BarrierError::NotFound(barrier_id.to_string()))?
            .clone();

        self.enforce_barrier_not_expired(&barrier, trace_id)?;

        let state = self
            .rollout_states
            .get_mut(barrier_id)
            .ok_or_else(|| BarrierError::NotFound(format!("rollout state for {barrier_id}")))?;

        let next_phase =
            state
                .current_phase
                .next()
                .ok_or_else(|| BarrierError::RolloutFenceBlocked {
                    phase: format!("{}", state.current_phase),
                    reason: "already at final phase".to_string(),
                })?;

        let old_phase = state.current_phase;
        state.current_phase = next_phase;
        state.phase_entered_at = clock::wall_now().to_rfc3339();
        state.success_count = 0;
        state.error_count = 0;
        state.total_count = 0;

        let receipt = BarrierAuditReceipt::new(
            event_codes::ROLLOUT_FENCE_ADVANCED,
            &barrier,
            BarrierAction::PhaseAdvanced,
            trace_id,
            serde_json::json!({
                "from_phase": format!("{old_phase}"),
                "to_phase": format!("{next_phase}"),
            }),
        );
        self.push_audit(receipt.clone());
        Ok(receipt)
    }

    /// Rollback a rollout fence to canary phase.
    pub fn rollback_rollout(
        &mut self,
        barrier_id: &str,
        trace_id: &str,
    ) -> Result<BarrierAuditReceipt, BarrierError> {
        let barrier = self
            .barriers
            .get(barrier_id)
            .ok_or_else(|| BarrierError::NotFound(barrier_id.to_string()))?
            .clone();

        let state = self
            .rollout_states
            .get_mut(barrier_id)
            .ok_or_else(|| BarrierError::NotFound(format!("rollout state for {barrier_id}")))?;

        let old_phase = state.current_phase;
        state.current_phase = RolloutPhase::Canary;
        state.phase_entered_at = clock::wall_now().to_rfc3339();
        state.success_count = 0;
        state.error_count = 0;
        state.total_count = 0;

        let receipt = BarrierAuditReceipt::new(
            event_codes::ROLLOUT_FENCE_ROLLED_BACK,
            &barrier,
            BarrierAction::RolledBack,
            trace_id,
            serde_json::json!({
                "from_phase": format!("{old_phase}"),
                "to_phase": "canary",
            }),
        );
        self.push_audit(receipt.clone());
        Ok(receipt)
    }

    /// Record a rollout observation (success or error).
    pub fn record_rollout_observation(
        &mut self,
        barrier_id: &str,
        success: bool,
    ) -> Result<(), BarrierError> {
        let state = self
            .rollout_states
            .get_mut(barrier_id)
            .ok_or_else(|| BarrierError::NotFound(format!("rollout state for {barrier_id}")))?;

        if success {
            state.record_success();
        } else {
            state.record_error();
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Query / accessors
    // -----------------------------------------------------------------------

    /// Get all barriers applied to a node.
    pub fn get_node_barriers(&self, node_id: &str) -> Vec<&Barrier> {
        self.node_barriers
            .get(node_id)
            .map(|ids| ids.iter().filter_map(|id| self.barriers.get(id)).collect())
            .unwrap_or_default()
    }

    /// Get the current rollout state for a fence barrier.
    pub fn get_rollout_state(&self, barrier_id: &str) -> Option<&RolloutState> {
        self.rollout_states.get(barrier_id)
    }

    /// Get the full audit log.
    pub fn audit_log(&self) -> &[BarrierAuditReceipt] {
        &self.audit_log
    }

    /// Get a barrier by ID.
    pub fn get_barrier(&self, barrier_id: &str) -> Option<&Barrier> {
        self.barriers.get(barrier_id)
    }

    /// Return count of active barriers.
    pub fn active_barrier_count(&self) -> usize {
        self.barriers.len()
    }

    /// Export audit log as JSONL.
    pub fn export_audit_log_jsonl(&self) -> Result<String, serde_json::Error> {
        let mut lines = Vec::with_capacity(self.audit_log.len());
        for receipt in &self.audit_log {
            lines.push(serde_json::to_string(receipt)?);
        }
        Ok(lines.join("\n"))
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    fn push_audit(&mut self, entry: BarrierAuditReceipt) {
        push_bounded(&mut self.audit_log, entry, MAX_AUDIT_LOG_ENTRIES);
    }

    fn get_node_barrier_ids(&self, node_id: &str) -> Vec<String> {
        self.node_barriers.get(node_id).cloned().unwrap_or_default()
    }

    fn enforce_barrier_not_expired(
        &mut self,
        barrier: &Barrier,
        trace_id: &str,
    ) -> Result<(), BarrierError> {
        let Some(expires_at) = &barrier.expires_at else {
            return Ok(());
        };

        let expiry = DateTime::parse_from_rfc3339(expires_at).map_err(|_| {
            self.push_expired_receipt(barrier, trace_id, "invalid expires_at timestamp");
            BarrierError::BarrierExpired {
                barrier_id: barrier.barrier_id.clone(),
                expires_at: expires_at.clone(),
                reason: "invalid expires_at timestamp".to_string(),
            }
        })?;

        if clock::wall_now() >= expiry.with_timezone(&Utc) {
            self.push_expired_receipt(barrier, trace_id, "now >= expires_at");
            return Err(BarrierError::BarrierExpired {
                barrier_id: barrier.barrier_id.clone(),
                expires_at: expires_at.clone(),
                reason: "now >= expires_at".to_string(),
            });
        }

        Ok(())
    }

    fn push_expired_receipt(&mut self, barrier: &Barrier, trace_id: &str, reason: &str) {
        let receipt = BarrierAuditReceipt::new(
            event_codes::BARRIER_EXPIRED,
            barrier,
            BarrierAction::Expired,
            trace_id,
            serde_json::json!({
                "reason": reason,
                "expires_at": barrier.expires_at.clone(),
            }),
        );
        self.push_audit(receipt);
    }

    /// Check that a new barrier does not conflict with existing barriers on the same node.
    fn check_composition_validity(&self, barrier: &Barrier) -> Result<(), BarrierError> {
        if let BarrierConfig::StagedRolloutFence(ref cfg) = barrier.config {
            cfg.validate()?;
        }
        let existing = self.get_node_barriers(&barrier.node_id);
        for existing_barrier in existing {
            // Two sandbox escalation barriers with conflicting tiers
            if let (
                BarrierConfig::SandboxEscalation(new_cfg),
                BarrierConfig::SandboxEscalation(old_cfg),
            ) = (&barrier.config, &existing_barrier.config)
            {
                // Allow composition: the stricter tier wins. No conflict.
                let _ = (new_cfg, old_cfg);
            }

            // Two rollout fences on the same node are not allowed
            if matches!(barrier.config, BarrierConfig::StagedRolloutFence(_))
                && matches!(
                    existing_barrier.config,
                    BarrierConfig::StagedRolloutFence(_)
                )
            {
                return Err(BarrierError::CompositionConflict(format!(
                    "node {} already has a staged rollout fence ({})",
                    barrier.node_id, existing_barrier.barrier_id
                )));
            }
        }
        Ok(())
    }

    /// Create an explicit receipt for a node that has no matching authoritative barrier.
    fn make_not_applicable_receipt(
        &self,
        node_id: &str,
        barrier_type: BarrierType,
        trace_id: &str,
        details: serde_json::Value,
    ) -> BarrierAuditReceipt {
        BarrierAuditReceipt {
            receipt_id: Uuid::now_v7().to_string(),
            event_code: event_codes::BARRIER_CHECK_NOT_APPLICABLE.to_string(),
            barrier_id: format!("not-applicable:{barrier_type}:{node_id}"),
            node_id: node_id.to_string(),
            barrier_type,
            action: BarrierAction::NotApplicable,
            timestamp: clock::wall_now().to_rfc3339(),
            trace_id: trace_id.to_string(),
            details,
            override_justification: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Barrier plan (policy engine wiring)
// ---------------------------------------------------------------------------

/// A barrier plan translates immunization planner recommendations into enforceable barriers.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BarrierPlan {
    pub plan_id: String,
    pub created_at: String,
    pub barriers: Vec<Barrier>,
}

impl BarrierPlan {
    /// Apply all barriers in this plan to the engine.
    pub fn apply_to(
        &self,
        engine: &mut BarrierEngine,
        trace_id: &str,
    ) -> Result<Vec<BarrierAuditReceipt>, BarrierError> {
        if self.barriers.len() > MAX_BARRIER_RECEIPTS {
            return Err(BarrierError::PlanTooLarge {
                count: self.barriers.len(),
                cap: MAX_BARRIER_RECEIPTS,
            });
        }

        let mut receipts = Vec::with_capacity(self.barriers.len().min(MAX_BARRIER_RECEIPTS));
        for barrier in &self.barriers {
            let mut b = barrier.clone();
            b.source_plan_id = Some(self.plan_id.clone());
            push_bounded(
                &mut receipts,
                engine.apply_barrier(b, trace_id)?,
                MAX_BARRIER_RECEIPTS,
            );
        }
        Ok(receipts)
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_trace_id() -> String {
        Uuid::now_v7().to_string()
    }

    fn make_sandbox_barrier(node_id: &str, min_tier: SandboxTier) -> Barrier {
        Barrier {
            barrier_id: Uuid::now_v7().to_string(),
            node_id: node_id.to_string(),
            barrier_type: BarrierType::SandboxEscalation,
            config: BarrierConfig::SandboxEscalation(SandboxEscalationConfig {
                min_tier,
                denied_capabilities: vec!["network_raw".to_string(), "fs_write_root".to_string()],
                risk_threshold: RiskLevel::High,
            }),
            applied_at: clock::wall_now().to_rfc3339(),
            expires_at: None,
            source_plan_id: None,
        }
    }

    fn make_firewall_barrier(node_id: &str, boundary: &str) -> Barrier {
        Barrier {
            barrier_id: Uuid::now_v7().to_string(),
            node_id: node_id.to_string(),
            barrier_type: BarrierType::CompositionFirewall,
            config: BarrierConfig::CompositionFirewall(CompositionFirewallConfig {
                boundary_id: boundary.to_string(),
                blocked_capabilities: vec!["exec_child".to_string(), "network_raw".to_string()],
                allow_list: vec!["network_raw".to_string()],
            }),
            applied_at: clock::wall_now().to_rfc3339(),
            expires_at: None,
            source_plan_id: None,
        }
    }

    fn make_fork_pin_barrier(node_id: &str, expected_digest: &str) -> Barrier {
        Barrier {
            barrier_id: Uuid::now_v7().to_string(),
            node_id: node_id.to_string(),
            barrier_type: BarrierType::VerifiedForkPin,
            config: BarrierConfig::VerifiedForkPin(VerifiedForkPinConfig {
                fork_url: "https://github.com/example/fork".to_string(),
                pinned_commit: "abc123def456".to_string(),
                signature_pubkey_hex: "deadbeef".to_string(),
                expected_digest: expected_digest.to_string(),
            }),
            applied_at: clock::wall_now().to_rfc3339(),
            expires_at: None,
            source_plan_id: None,
        }
    }

    fn make_rollout_barrier(node_id: &str) -> Barrier {
        let mut criteria = BTreeMap::new();
        criteria.insert(
            "canary".to_string(),
            ProgressionCriteria::new(60, 0.05, 10).expect("test rollout criteria must be valid"),
        );
        Barrier {
            barrier_id: Uuid::now_v7().to_string(),
            node_id: node_id.to_string(),
            barrier_type: BarrierType::StagedRolloutFence,
            config: BarrierConfig::StagedRolloutFence(StagedRolloutFenceConfig {
                initial_phase: RolloutPhase::Canary,
                progression_criteria: criteria,
                auto_rollback_on_breach: true,
            }),
            applied_at: clock::wall_now().to_rfc3339(),
            expires_at: None,
            source_plan_id: None,
        }
    }

    fn with_expiry(mut barrier: Barrier, expires_at: String) -> Barrier {
        barrier.expires_at = Some(expires_at);
        barrier
    }

    fn make_override_justification() -> OverrideJustification {
        OverrideJustification {
            override_id: Uuid::now_v7().to_string(),
            principal_identity: "admin@example.com".to_string(),
            reason: "emergency fix".to_string(),
            timestamp: clock::wall_now().to_rfc3339(),
            signature_hex: "deadbeef01020304".to_string(),
        }
    }

    // === Sandbox escalation tests ===

    #[test]
    fn sandbox_escalation_denies_below_min_tier() {
        let mut engine = BarrierEngine::new();
        let barrier = make_sandbox_barrier("node-a", SandboxTier::Strict);
        let trace = make_trace_id();
        engine.apply_barrier(barrier, &trace).unwrap();

        let result = engine.check_sandbox_escalation(
            "node-a",
            "network_http",
            SandboxTier::Moderate,
            &trace,
        );
        assert!(result.is_err());
        match result.unwrap_err() {
            BarrierError::SandboxEscalation(msg) => {
                assert!(msg.contains("node-a"));
                assert!(msg.contains("strict"));
            }
            other => unreachable!("unexpected error: {other}"),
        }
    }

    #[test]
    fn sandbox_escalation_allows_at_min_tier() {
        let mut engine = BarrierEngine::new();
        let barrier = make_sandbox_barrier("node-b", SandboxTier::Strict);
        let barrier_id = barrier.barrier_id.clone();
        let trace = make_trace_id();
        engine.apply_barrier(barrier, &trace).unwrap();

        let receipt = engine
            .check_sandbox_escalation("node-b", "network_http", SandboxTier::Strict, &trace)
            .unwrap();
        assert_eq!(receipt.barrier_id, barrier_id);
        assert_eq!(receipt.event_code, event_codes::SANDBOX_ESCALATED);
        assert_eq!(receipt.action, BarrierAction::CheckPassed);
    }

    #[test]
    fn sandbox_escalation_denies_blocked_capability() {
        let mut engine = BarrierEngine::new();
        let barrier = make_sandbox_barrier("node-c", SandboxTier::Permissive);
        let trace = make_trace_id();
        engine.apply_barrier(barrier, &trace).unwrap();

        let result =
            engine.check_sandbox_escalation("node-c", "network_raw", SandboxTier::Isolated, &trace);
        assert!(result.is_err());
    }

    #[test]
    fn sandbox_escalation_allows_unblocked_capability() {
        let mut engine = BarrierEngine::new();
        let barrier = make_sandbox_barrier("node-d", SandboxTier::Permissive);
        let trace = make_trace_id();
        engine.apply_barrier(barrier, &trace).unwrap();

        let result = engine.check_sandbox_escalation(
            "node-d",
            "network_http",
            SandboxTier::Moderate,
            &trace,
        );
        assert!(result.is_ok());
    }

    // === Composition firewall tests ===

    #[test]
    fn firewall_blocks_capability_across_boundary() {
        let mut engine = BarrierEngine::new();
        let barrier = make_firewall_barrier("node-e", "trust-boundary-1");
        let trace = make_trace_id();
        engine.apply_barrier(barrier, &trace).unwrap();

        let result =
            engine.check_composition_firewall("node-e", "exec_child", "trust-boundary-1", &trace);
        assert!(result.is_err());
        match result.unwrap_err() {
            BarrierError::FirewallViolation {
                capability,
                boundary,
            } => {
                assert_eq!(capability, "exec_child");
                assert_eq!(boundary, "trust-boundary-1");
            }
            other => unreachable!("unexpected error: {other}"),
        }
    }

    #[test]
    fn firewall_allows_capability_in_allow_list() {
        let mut engine = BarrierEngine::new();
        let barrier = make_firewall_barrier("node-f", "trust-boundary-1");
        let barrier_id = barrier.barrier_id.clone();
        let trace = make_trace_id();
        engine.apply_barrier(barrier, &trace).unwrap();

        // network_raw is in both blocked and allow_list; allow_list wins
        let receipt = engine
            .check_composition_firewall("node-f", "network_raw", "trust-boundary-1", &trace)
            .unwrap();
        assert_eq!(receipt.barrier_id, barrier_id);
        assert_eq!(receipt.event_code, event_codes::FIREWALL_ENFORCED);
        assert_eq!(receipt.action, BarrierAction::CheckPassed);
    }

    #[test]
    fn firewall_allows_unrelated_boundary() {
        let mut engine = BarrierEngine::new();
        let barrier = make_firewall_barrier("node-g", "trust-boundary-1");
        let trace = make_trace_id();
        engine.apply_barrier(barrier, &trace).unwrap();

        let result =
            engine.check_composition_firewall("node-g", "exec_child", "other-boundary", &trace);
        assert!(result.is_ok());
    }

    // === Verified-fork pin tests ===

    #[test]
    fn fork_pin_rejects_digest_mismatch() {
        let mut engine = BarrierEngine::new();
        let barrier = make_fork_pin_barrier("dep-x", "sha256:aabbccdd");
        let trace = make_trace_id();
        engine.apply_barrier(barrier, &trace).unwrap();

        let result = engine.check_fork_pin("dep-x", "sha256:wrong", &trace);
        assert!(result.is_err());
    }

    #[test]
    fn fork_pin_accepts_matching_digest() {
        let mut engine = BarrierEngine::new();
        let barrier = make_fork_pin_barrier("dep-y", "sha256:aabbccdd");
        let barrier_id = barrier.barrier_id.clone();
        let trace = make_trace_id();
        engine.apply_barrier(barrier, &trace).unwrap();

        let receipt = engine
            .check_fork_pin("dep-y", "sha256:aabbccdd", &trace)
            .unwrap();
        assert_eq!(receipt.barrier_id, barrier_id);
        assert_eq!(receipt.event_code, event_codes::FORK_PIN_VERIFIED);
        assert_eq!(receipt.action, BarrierAction::CheckPassed);
    }

    // === Staged rollout fence tests ===

    #[test]
    fn rollout_fence_blocks_ahead_of_current_phase() {
        let mut engine = BarrierEngine::new();
        let barrier = make_rollout_barrier("dep-z");
        let barrier_id = barrier.barrier_id.clone();
        let trace = make_trace_id();
        engine.apply_barrier(barrier, &trace).unwrap();

        // Current phase is canary, requesting general should fail
        let result = engine.check_rollout_fence(&barrier_id, RolloutPhase::General, &trace);
        assert!(result.is_err());
    }

    #[test]
    fn rollout_fence_allows_at_current_phase() {
        let mut engine = BarrierEngine::new();
        let barrier = make_rollout_barrier("dep-w");
        let barrier_id = barrier.barrier_id.clone();
        let trace = make_trace_id();
        engine.apply_barrier(barrier, &trace).unwrap();

        let result = engine.check_rollout_fence(&barrier_id, RolloutPhase::Canary, &trace);
        assert!(result.is_ok());
    }

    #[test]
    fn rollout_fence_fails_closed_at_expiry_boundary() {
        let mut engine = BarrierEngine::new();
        let barrier = with_expiry(
            make_rollout_barrier("expired-rollout"),
            clock::wall_now().to_rfc3339(),
        );
        let barrier_id = barrier.barrier_id.clone();
        let trace = make_trace_id();
        engine.apply_barrier(barrier, &trace).unwrap();

        let err = engine
            .check_rollout_fence(&barrier_id, RolloutPhase::Canary, &trace)
            .unwrap_err();

        assert!(matches!(
            err,
            BarrierError::BarrierExpired { barrier_id: expired_id, reason, .. }
                if expired_id == barrier_id && reason == "now >= expires_at"
        ));
        let receipt = engine.audit_log().last().expect("expired receipt");
        assert_eq!(receipt.event_code, event_codes::BARRIER_EXPIRED);
        assert_eq!(receipt.action, BarrierAction::Expired);
        assert_eq!(receipt.barrier_id, barrier_id);
        assert_eq!(receipt.details["reason"], "now >= expires_at");
    }

    #[test]
    fn rollout_fence_advances_phase() {
        let mut engine = BarrierEngine::new();
        let barrier = make_rollout_barrier("dep-v");
        let barrier_id = barrier.barrier_id.clone();
        let trace = make_trace_id();
        engine.apply_barrier(barrier, &trace).unwrap();

        let receipt = engine.advance_rollout_phase(&barrier_id, &trace).unwrap();
        assert_eq!(receipt.action, BarrierAction::PhaseAdvanced);

        let state = engine.get_rollout_state(&barrier_id).unwrap();
        assert_eq!(state.current_phase, RolloutPhase::Limited);
    }

    #[test]
    fn rollout_fence_rollback_resets_to_canary() {
        let mut engine = BarrierEngine::new();
        let barrier = make_rollout_barrier("dep-u");
        let barrier_id = barrier.barrier_id.clone();
        let trace = make_trace_id();
        engine.apply_barrier(barrier, &trace).unwrap();
        engine.advance_rollout_phase(&barrier_id, &trace).unwrap();
        engine.advance_rollout_phase(&barrier_id, &trace).unwrap();

        let receipt = engine.rollback_rollout(&barrier_id, &trace).unwrap();
        assert_eq!(receipt.action, BarrierAction::RolledBack);

        let state = engine.get_rollout_state(&barrier_id).unwrap();
        assert_eq!(state.current_phase, RolloutPhase::Canary);
    }

    #[test]
    fn rollout_observation_tracking() {
        let mut engine = BarrierEngine::new();
        let barrier = make_rollout_barrier("dep-t");
        let barrier_id = barrier.barrier_id.clone();
        let trace = make_trace_id();
        engine.apply_barrier(barrier, &trace).unwrap();

        engine
            .record_rollout_observation(&barrier_id, true)
            .unwrap();
        engine
            .record_rollout_observation(&barrier_id, true)
            .unwrap();
        engine
            .record_rollout_observation(&barrier_id, false)
            .unwrap();

        let state = engine.get_rollout_state(&barrier_id).unwrap();
        assert_eq!(state.success_count, 2);
        assert_eq!(state.error_count, 1);
        assert_eq!(state.total_count, 3);
        assert!((state.error_rate() - 1.0 / 3.0).abs() < f64::EPSILON);
    }

    // === Override tests ===

    #[test]
    fn override_requires_signature() {
        let mut engine = BarrierEngine::new();
        let barrier = make_sandbox_barrier("node-h", SandboxTier::Strict);
        let barrier_id = barrier.barrier_id.clone();
        let trace = make_trace_id();
        engine.apply_barrier(barrier, &trace).unwrap();

        let bad_justification = OverrideJustification {
            override_id: Uuid::now_v7().to_string(),
            principal_identity: "admin@example.com".to_string(),
            reason: "emergency fix".to_string(),
            timestamp: clock::wall_now().to_rfc3339(),
            signature_hex: String::new(), // empty!
        };

        let result = engine.override_barrier(&barrier_id, bad_justification, &trace);
        assert!(result.is_err());
    }

    #[test]
    fn override_with_valid_justification_succeeds() {
        let mut engine = BarrierEngine::new();
        let barrier = make_sandbox_barrier("node-i", SandboxTier::Strict);
        let barrier_id = barrier.barrier_id.clone();
        let trace = make_trace_id();
        engine.apply_barrier(barrier, &trace).unwrap();

        let justification = OverrideJustification {
            override_id: Uuid::now_v7().to_string(),
            principal_identity: "admin@example.com".to_string(),
            reason: "emergency production fix".to_string(),
            timestamp: clock::wall_now().to_rfc3339(),
            signature_hex: "deadbeef01020304".to_string(),
        };

        let receipt = engine
            .override_barrier(&barrier_id, justification, &trace)
            .unwrap();
        assert_eq!(receipt.action, BarrierAction::Overridden);
        assert!(receipt.override_justification.is_some());
    }

    // === Composition tests ===

    #[test]
    fn multiple_barriers_on_same_node_compose() {
        let mut engine = BarrierEngine::new();
        let trace = make_trace_id();

        let sandbox = make_sandbox_barrier("multi-node", SandboxTier::Strict);
        let firewall = make_firewall_barrier("multi-node", "boundary-x");
        let pin = make_fork_pin_barrier("multi-node", "sha256:112233");

        engine.apply_barrier(sandbox, &trace).unwrap();
        engine.apply_barrier(firewall, &trace).unwrap();
        engine.apply_barrier(pin, &trace).unwrap();

        let barriers = engine.get_node_barriers("multi-node");
        assert_eq!(barriers.len(), 3);
    }

    #[test]
    fn two_rollout_fences_on_same_node_conflict() {
        let mut engine = BarrierEngine::new();
        let trace = make_trace_id();

        let fence1 = make_rollout_barrier("same-node");
        let fence2 = make_rollout_barrier("same-node");

        engine.apply_barrier(fence1, &trace).unwrap();
        let result = engine.apply_barrier(fence2, &trace);
        assert!(result.is_err());
        match result.unwrap_err() {
            BarrierError::CompositionConflict(msg) => {
                assert!(msg.contains("same-node"));
            }
            other => unreachable!("unexpected error: {other}"),
        }
    }

    // === Barrier removal test ===

    #[test]
    fn barrier_removal_emits_receipt() {
        let mut engine = BarrierEngine::new();
        let barrier = make_sandbox_barrier("node-j", SandboxTier::Moderate);
        let barrier_id = barrier.barrier_id.clone();
        let trace = make_trace_id();
        engine.apply_barrier(barrier, &trace).unwrap();

        let receipt = engine.remove_barrier(&barrier_id, &trace).unwrap();
        assert_eq!(receipt.action, BarrierAction::Removed);
        assert_eq!(engine.active_barrier_count(), 0);
    }

    // === Audit log tests ===

    #[test]
    fn audit_log_records_all_actions() {
        let mut engine = BarrierEngine::new();
        let trace = make_trace_id();

        let barrier = make_sandbox_barrier("audit-node", SandboxTier::Moderate);
        let barrier_id = barrier.barrier_id.clone();
        engine.apply_barrier(barrier, &trace).unwrap();

        engine
            .check_sandbox_escalation("audit-node", "network_http", SandboxTier::Strict, &trace)
            .unwrap();

        engine.remove_barrier(&barrier_id, &trace).unwrap();

        let log = engine.audit_log();
        assert_eq!(log.len(), 3);
        assert_eq!(log[0].action, BarrierAction::Applied);
        assert_eq!(log[1].action, BarrierAction::CheckPassed);
        assert_eq!(log[2].action, BarrierAction::Removed);
    }

    #[test]
    fn audit_receipt_content_hash_is_deterministic() {
        let receipt = BarrierAuditReceipt {
            receipt_id: "test-receipt-1".to_string(),
            event_code: event_codes::BARRIER_APPLIED.to_string(),
            barrier_id: "barrier-1".to_string(),
            node_id: "node-1".to_string(),
            barrier_type: BarrierType::SandboxEscalation,
            action: BarrierAction::Applied,
            timestamp: "2026-02-20T00:00:00Z".to_string(),
            trace_id: "trace-1".to_string(),
            details: serde_json::json!({"key": "value"}),
            override_justification: None,
        };

        let hash1 = receipt.content_hash().unwrap();
        let hash2 = receipt.content_hash().unwrap();
        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 64); // SHA-256 hex
    }

    #[test]
    fn progression_criteria_constructor_rejects_invalid_error_rates() {
        for invalid_rate in [f64::NAN, f64::INFINITY, -0.01, 1.01] {
            let err = ProgressionCriteria::new(60, invalid_rate, 10).unwrap_err();
            assert!(matches!(err, BarrierError::InvalidProgressionCriteria(_)));
        }
    }

    #[test]
    fn progression_criteria_setter_rejects_invalid_error_rates() {
        let mut criteria = ProgressionCriteria::new(60, 0.05, 10).unwrap();

        for invalid_rate in [f64::NAN, f64::INFINITY, -0.01, 1.01] {
            let err = criteria.set_max_error_rate(invalid_rate).unwrap_err();
            assert!(matches!(err, BarrierError::InvalidProgressionCriteria(_)));
            assert_eq!(criteria.max_error_rate, 0.05);
        }
    }

    #[test]
    fn apply_barrier_rejects_rollout_with_invalid_error_rates() {
        for invalid_rate in [f64::NAN, f64::INFINITY, -0.01, 1.01] {
            let mut criteria = BTreeMap::new();
            criteria.insert(
                "canary".to_string(),
                ProgressionCriteria {
                    min_soak_seconds: 60,
                    max_error_rate: invalid_rate,
                    min_success_count: 10,
                },
            );

            let barrier = Barrier {
                barrier_id: Uuid::now_v7().to_string(),
                node_id: "invalid-rollout-node".to_string(),
                barrier_type: BarrierType::StagedRolloutFence,
                config: BarrierConfig::StagedRolloutFence(StagedRolloutFenceConfig {
                    initial_phase: RolloutPhase::Canary,
                    progression_criteria: criteria,
                    auto_rollback_on_breach: true,
                }),
                applied_at: clock::wall_now().to_rfc3339(),
                expires_at: None,
                source_plan_id: None,
            };

            let err = BarrierEngine::new()
                .apply_barrier(barrier, &make_trace_id())
                .unwrap_err();
            assert!(matches!(err, BarrierError::InvalidProgressionCriteria(_)));
        }
    }

    #[test]
    fn export_audit_log_jsonl_format() {
        let mut engine = BarrierEngine::new();
        let trace = make_trace_id();
        let barrier = make_sandbox_barrier("jsonl-node", SandboxTier::Moderate);
        engine.apply_barrier(barrier, &trace).unwrap();

        let jsonl = engine.export_audit_log_jsonl().unwrap();
        let lines: Vec<&str> = jsonl.lines().collect();
        assert_eq!(lines.len(), 1);
        let parsed: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(parsed["action"], "applied");
    }

    // === Barrier plan tests ===

    #[test]
    fn barrier_plan_applies_all_barriers() {
        let mut engine = BarrierEngine::new();
        let trace = make_trace_id();

        let plan = BarrierPlan {
            plan_id: "plan-001".to_string(),
            created_at: clock::wall_now().to_rfc3339(),
            barriers: vec![
                make_sandbox_barrier("plan-node-1", SandboxTier::Strict),
                make_firewall_barrier("plan-node-2", "boundary-plan"),
                make_fork_pin_barrier("plan-node-3", "sha256:plandigest"),
            ],
        };

        let receipts = plan.apply_to(&mut engine, &trace).unwrap();
        assert_eq!(receipts.len(), 3);
        assert_eq!(engine.active_barrier_count(), 3);

        // Verify source_plan_id is set
        for barrier in engine.barriers.values() {
            assert_eq!(barrier.source_plan_id.as_deref(), Some("plan-001"));
        }
    }

    #[test]
    fn barrier_plan_rejects_oversized_receipt_vector_before_applying() {
        let mut engine = BarrierEngine::new();
        let trace = make_trace_id();
        let barriers = (0..=MAX_BARRIER_RECEIPTS)
            .map(|i| make_sandbox_barrier(&format!("oversized-plan-node-{i}"), SandboxTier::Strict))
            .collect();
        let plan = BarrierPlan {
            plan_id: "oversized-plan".to_string(),
            created_at: clock::wall_now().to_rfc3339(),
            barriers,
        };

        let err = plan.apply_to(&mut engine, &trace).unwrap_err();

        assert!(matches!(
            err,
            BarrierError::PlanTooLarge { count, cap }
                if count == MAX_BARRIER_RECEIPTS + 1 && cap == MAX_BARRIER_RECEIPTS
        ));
        assert_eq!(
            engine.active_barrier_count(),
            0,
            "oversized plans must fail before applying any barrier"
        );
    }

    // === Explicit no-barrier behavior ===

    #[test]
    fn check_passes_when_no_barriers_exist() {
        let mut engine = BarrierEngine::new();
        let trace = make_trace_id();

        let sandbox_receipt = engine
            .check_sandbox_escalation(
                "unbarriered-node",
                "anything",
                SandboxTier::Permissive,
                &trace,
            )
            .unwrap();
        assert_eq!(
            sandbox_receipt.event_code,
            event_codes::BARRIER_CHECK_NOT_APPLICABLE
        );
        assert_eq!(sandbox_receipt.action, BarrierAction::NotApplicable);
        assert!(sandbox_receipt.barrier_id.starts_with("not-applicable:"));

        let firewall_receipt = engine
            .check_composition_firewall("unbarriered-node", "exec_child", "any-boundary", &trace)
            .unwrap();
        assert_eq!(
            firewall_receipt.event_code,
            event_codes::BARRIER_CHECK_NOT_APPLICABLE
        );
        assert_eq!(firewall_receipt.action, BarrierAction::NotApplicable);
        assert_eq!(
            firewall_receipt.details["reason"],
            serde_json::json!("no_matching_firewall_boundary")
        );

        let fork_pin_receipt = engine
            .check_fork_pin("unbarriered-node", "any-digest", &trace)
            .unwrap();
        assert_eq!(
            fork_pin_receipt.event_code,
            event_codes::BARRIER_CHECK_NOT_APPLICABLE
        );
        assert_eq!(fork_pin_receipt.action, BarrierAction::NotApplicable);
    }

    #[test]
    fn check_returns_not_applicable_when_only_other_barrier_kinds_exist() {
        let mut engine = BarrierEngine::new();
        let trace = make_trace_id();

        engine
            .apply_barrier(make_firewall_barrier("mixed-node", "boundary-a"), &trace)
            .unwrap();

        let sandbox_receipt = engine
            .check_sandbox_escalation(
                "mixed-node",
                "network_http",
                SandboxTier::Permissive,
                &trace,
            )
            .unwrap();
        assert_eq!(
            sandbox_receipt.event_code,
            event_codes::BARRIER_CHECK_NOT_APPLICABLE
        );
        assert_eq!(sandbox_receipt.action, BarrierAction::NotApplicable);
        assert_eq!(
            sandbox_receipt.details["reason"],
            serde_json::json!("no_sandbox_barrier_configured")
        );

        let firewall_receipt = engine
            .check_composition_firewall("mixed-node", "exec_child", "boundary-b", &trace)
            .unwrap();
        assert_eq!(
            firewall_receipt.event_code,
            event_codes::BARRIER_CHECK_NOT_APPLICABLE
        );
        assert_eq!(firewall_receipt.action, BarrierAction::NotApplicable);
        assert_eq!(
            firewall_receipt.details["reason"],
            serde_json::json!("no_matching_firewall_boundary")
        );

        let fork_pin_receipt = engine
            .check_fork_pin("mixed-node", "sha256:any-digest", &trace)
            .unwrap();
        assert_eq!(
            fork_pin_receipt.event_code,
            event_codes::BARRIER_CHECK_NOT_APPLICABLE
        );
        assert_eq!(fork_pin_receipt.action, BarrierAction::NotApplicable);
        assert_eq!(
            fork_pin_receipt.details["reason"],
            serde_json::json!("no_verified_fork_barrier_configured")
        );
    }

    #[test]
    fn audit_log_and_jsonl_export_preserve_not_applicable_receipts() {
        let mut engine = BarrierEngine::new();
        let trace = make_trace_id();

        engine
            .check_sandbox_escalation(
                "audit-unbarriered-node",
                "network_http",
                SandboxTier::Permissive,
                &trace,
            )
            .unwrap();
        engine
            .check_composition_firewall(
                "audit-unbarriered-node",
                "exec_child",
                "missing-boundary",
                &trace,
            )
            .unwrap();
        engine
            .check_fork_pin("audit-unbarriered-node", "sha256:any-digest", &trace)
            .unwrap();

        let log = engine.audit_log();
        assert_eq!(log.len(), 3);
        assert!(
            log.iter()
                .all(|receipt| receipt.event_code == event_codes::BARRIER_CHECK_NOT_APPLICABLE)
        );
        assert!(
            log.iter()
                .all(|receipt| receipt.action == BarrierAction::NotApplicable)
        );
        assert!(
            log.iter()
                .all(|receipt| receipt.barrier_id.starts_with("not-applicable:"))
        );
        assert_eq!(
            log.iter()
                .map(|receipt| receipt.details["reason"].as_str().unwrap())
                .collect::<Vec<_>>(),
            vec![
                "no_sandbox_barrier_configured",
                "no_matching_firewall_boundary",
                "no_verified_fork_barrier_configured",
            ]
        );

        let jsonl = engine.export_audit_log_jsonl().unwrap();
        let lines: Vec<&str> = jsonl.lines().collect();
        assert_eq!(lines.len(), 3);

        for line in lines {
            let parsed: serde_json::Value = serde_json::from_str(line).unwrap();
            assert_eq!(
                parsed["event_code"],
                serde_json::json!(event_codes::BARRIER_CHECK_NOT_APPLICABLE)
            );
            assert_eq!(parsed["action"], serde_json::json!("not_applicable"));
            assert!(
                parsed["barrier_id"]
                    .as_str()
                    .unwrap()
                    .starts_with("not-applicable:")
            );
        }
    }

    #[test]
    fn duplicate_barrier_id_is_rejected_before_node_routing_is_corrupted() {
        let mut engine = BarrierEngine::new();
        let trace = make_trace_id();

        let barrier = make_sandbox_barrier("node-a", SandboxTier::Strict);
        let duplicate_id = barrier.barrier_id.clone();
        engine.apply_barrier(barrier, &trace).unwrap();

        let mut duplicate = make_fork_pin_barrier("node-b", "sha256:112233");
        duplicate.barrier_id = duplicate_id;

        let err = engine.apply_barrier(duplicate, &trace).unwrap_err();
        match err {
            BarrierError::CompositionConflict(message) => {
                assert!(message.contains("barrier id"));
            }
            other => unreachable!("unexpected error: {other}"),
        }

        assert_eq!(engine.get_node_barriers("node-a").len(), 1);
        assert!(engine.get_node_barriers("node-b").is_empty());
        assert!(
            engine
                .check_sandbox_escalation("node-a", "network_http", SandboxTier::Moderate, &trace)
                .is_err()
        );
    }

    #[test]
    fn push_bounded_zero_capacity_clears_existing_items() {
        let mut items = vec!["stale-a", "stale-b"];

        push_bounded(&mut items, "new", 0);

        assert!(
            items.is_empty(),
            "zero-capacity bounded vectors must not retain stale entries"
        );
    }

    #[test]
    fn remove_unknown_barrier_returns_not_found_without_audit() {
        let mut engine = BarrierEngine::new();
        let trace = make_trace_id();

        let err = engine
            .remove_barrier("missing-barrier", &trace)
            .unwrap_err();

        assert!(matches!(
            err,
            BarrierError::NotFound(message) if message == "missing-barrier"
        ));
        assert!(
            engine.audit_log().is_empty(),
            "failed removals must not emit misleading removal receipts"
        );
    }

    #[test]
    fn override_empty_principal_rejected_before_barrier_lookup() {
        let mut engine = BarrierEngine::new();
        let trace = make_trace_id();
        let mut justification = make_override_justification();
        justification.principal_identity.clear();

        let err = engine
            .override_barrier("missing-barrier", justification, &trace)
            .unwrap_err();

        assert!(matches!(
            err,
            BarrierError::OverrideRejected(message) if message.contains("principal_identity")
        ));
        assert!(engine.audit_log().is_empty());
    }

    #[test]
    fn override_empty_reason_rejected_without_audit_receipt() {
        let mut engine = BarrierEngine::new();
        let trace = make_trace_id();
        let barrier = make_sandbox_barrier("override-node", SandboxTier::Strict);
        let barrier_id = barrier.barrier_id.clone();
        engine.apply_barrier(barrier, &trace).unwrap();
        let audit_count_before = engine.audit_log().len();

        let mut justification = make_override_justification();
        justification.reason.clear();
        let err = engine
            .override_barrier(&barrier_id, justification, &trace)
            .unwrap_err();

        assert!(matches!(
            err,
            BarrierError::OverrideRejected(message) if message.contains("reason")
        ));
        assert_eq!(
            engine.audit_log().len(),
            audit_count_before,
            "invalid overrides must not append override receipts"
        );
    }

    #[test]
    fn override_missing_barrier_with_valid_justification_returns_not_found() {
        let mut engine = BarrierEngine::new();
        let trace = make_trace_id();

        let err = engine
            .override_barrier("missing-barrier", make_override_justification(), &trace)
            .unwrap_err();

        assert!(matches!(
            err,
            BarrierError::NotFound(message) if message == "missing-barrier"
        ));
        assert!(engine.audit_log().is_empty());
    }

    #[test]
    fn rollout_check_on_non_rollout_barrier_returns_missing_state() {
        let mut engine = BarrierEngine::new();
        let trace = make_trace_id();
        let barrier = make_sandbox_barrier("not-rollout", SandboxTier::Strict);
        let barrier_id = barrier.barrier_id.clone();
        engine.apply_barrier(barrier, &trace).unwrap();

        let err = engine
            .check_rollout_fence(&barrier_id, RolloutPhase::Canary, &trace)
            .unwrap_err();

        assert!(matches!(
            err,
            BarrierError::NotFound(message) if message.contains("rollout state")
        ));
    }

    #[test]
    fn advancing_final_rollout_phase_is_rejected() {
        let mut engine = BarrierEngine::new();
        let trace = make_trace_id();
        let barrier = make_rollout_barrier("final-phase-node");
        let barrier_id = barrier.barrier_id.clone();
        engine.apply_barrier(barrier, &trace).unwrap();
        engine.advance_rollout_phase(&barrier_id, &trace).unwrap();
        engine.advance_rollout_phase(&barrier_id, &trace).unwrap();
        engine.advance_rollout_phase(&barrier_id, &trace).unwrap();

        let err = engine
            .advance_rollout_phase(&barrier_id, &trace)
            .unwrap_err();

        assert!(matches!(
            err,
            BarrierError::RolloutFenceBlocked { phase, reason }
                if phase == "general" && reason.contains("final phase")
        ));
    }

    #[test]
    fn rollout_observation_for_unknown_barrier_returns_not_found() {
        let mut engine = BarrierEngine::new();

        let err = engine
            .record_rollout_observation("missing-rollout", false)
            .unwrap_err();

        assert!(matches!(
            err,
            BarrierError::NotFound(message) if message.contains("missing-rollout")
        ));
    }

    #[test]
    fn plan_apply_stops_after_duplicate_and_keeps_prior_application() {
        let mut engine = BarrierEngine::new();
        let trace = make_trace_id();
        let first = make_sandbox_barrier("plan-dup-a", SandboxTier::Strict);
        let duplicate_id = first.barrier_id.clone();
        let mut second = make_fork_pin_barrier("plan-dup-b", "sha256:dup");
        second.barrier_id = duplicate_id;
        let plan = BarrierPlan {
            plan_id: "plan-with-duplicate".to_string(),
            created_at: clock::wall_now().to_rfc3339(),
            barriers: vec![first, second],
        };

        let err = plan.apply_to(&mut engine, &trace).unwrap_err();

        assert!(matches!(
            err,
            BarrierError::CompositionConflict(message) if message.contains("barrier id")
        ));
        assert_eq!(
            engine.active_barrier_count(),
            1,
            "plan application should stop at the duplicate without rolling back prior receipts"
        );
        assert_eq!(engine.get_node_barriers("plan-dup-a").len(), 1);
        assert!(engine.get_node_barriers("plan-dup-b").is_empty());
    }

    fn assert_json_rejected<T>(json: &str)
    where
        T: serde::de::DeserializeOwned,
    {
        assert!(
            serde_json::from_str::<T>(json).is_err(),
            "malformed json should be rejected: {json}"
        );
    }

    #[test]
    fn serde_rejects_unknown_barrier_type_variant() {
        assert_json_rejected::<BarrierType>(r#""runtime_freeze""#);
    }

    #[test]
    fn serde_rejects_unknown_risk_level_variant() {
        assert_json_rejected::<RiskLevel>(r#""urgent""#);
    }

    #[test]
    fn serde_rejects_numeric_sandbox_tier() {
        assert_json_rejected::<SandboxTier>("3");
    }

    #[test]
    fn serde_rejects_unknown_rollout_phase_variant() {
        assert_json_rejected::<RolloutPhase>(r#""general_availability""#);
    }

    #[test]
    fn serde_rejects_progression_criteria_string_error_rate() {
        assert_json_rejected::<ProgressionCriteria>(
            r#"{
                "min_soak_seconds": 60,
                "max_error_rate": "0.05",
                "min_success_count": 10
            }"#,
        );
    }

    #[test]
    fn serde_rejects_progression_criteria_negative_error_rate() {
        assert_json_rejected::<ProgressionCriteria>(
            r#"{
                "min_soak_seconds": 60,
                "max_error_rate": -0.01,
                "min_success_count": 10
            }"#,
        );
    }

    #[test]
    fn serde_rejects_progression_criteria_error_rate_above_one() {
        assert_json_rejected::<ProgressionCriteria>(
            r#"{
                "min_soak_seconds": 60,
                "max_error_rate": 1.01,
                "min_success_count": 10
            }"#,
        );
    }

    #[test]
    fn serde_rejects_barrier_config_missing_type_tag() {
        assert_json_rejected::<BarrierConfig>(
            r#"{
                "min_tier": "strict",
                "denied_capabilities": [],
                "risk_threshold": "high"
            }"#,
        );
    }

    #[test]
    fn serde_rejects_barrier_config_unknown_type_tag() {
        assert_json_rejected::<BarrierConfig>(
            r#"{
                "type": "ambient_bypass",
                "boundary_id": "trust-boundary",
                "blocked_capabilities": [],
                "allow_list": []
            }"#,
        );
    }

    #[test]
    fn serde_rejects_barrier_missing_config() {
        assert_json_rejected::<Barrier>(
            r#"{
                "barrier_id": "barrier-1",
                "node_id": "node-1",
                "barrier_type": "sandbox_escalation",
                "applied_at": "2026-02-20T00:00:00Z",
                "expires_at": null,
                "source_plan_id": null
            }"#,
        );
    }

    #[test]
    fn serde_rejects_override_justification_numeric_signature() {
        assert_json_rejected::<OverrideJustification>(
            r#"{
                "override_id": "override-1",
                "principal_identity": "admin@example.com",
                "reason": "break-glass",
                "timestamp": "2026-02-20T00:00:00Z",
                "signature_hex": 12345
            }"#,
        );
    }

    #[test]
    fn serde_rejects_audit_receipt_hyphenated_action() {
        assert_json_rejected::<BarrierAuditReceipt>(
            r#"{
                "receipt_id": "receipt-1",
                "event_code": "DGIS-BARRIER-005",
                "barrier_id": "barrier-1",
                "node_id": "node-1",
                "barrier_type": "sandbox_escalation",
                "action": "check-passed",
                "timestamp": "2026-02-20T00:00:00Z",
                "trace_id": "trace-1",
                "details": {},
                "override_justification": null
            }"#,
        );
    }

    #[test]
    fn override_whitespace_override_id_rejected_before_barrier_lookup() {
        let mut engine = BarrierEngine::new();
        let trace = make_trace_id();
        let mut justification = make_override_justification();
        justification.override_id = " \n ".to_string();

        let err = engine
            .override_barrier("missing-barrier", justification, &trace)
            .unwrap_err();

        assert!(matches!(
            err,
            BarrierError::OverrideRejected(message) if message.contains("override_id")
        ));
        assert!(engine.audit_log().is_empty());
    }

    #[test]
    fn override_whitespace_principal_rejected_before_barrier_lookup() {
        let mut engine = BarrierEngine::new();
        let trace = make_trace_id();
        let mut justification = make_override_justification();
        justification.principal_identity = " \t ".to_string();

        let err = engine
            .override_barrier("missing-barrier", justification, &trace)
            .unwrap_err();

        assert!(matches!(
            err,
            BarrierError::OverrideRejected(message) if message.contains("principal_identity")
        ));
        assert!(engine.audit_log().is_empty());
    }

    #[test]
    fn override_whitespace_reason_rejected_without_audit_receipt() {
        let mut engine = BarrierEngine::new();
        let trace = make_trace_id();
        let barrier = make_sandbox_barrier("override-whitespace-reason", SandboxTier::Strict);
        let barrier_id = barrier.barrier_id.clone();
        engine.apply_barrier(barrier, &trace).unwrap();
        let audit_count_before = engine.audit_log().len();
        let mut justification = make_override_justification();
        justification.reason = "\n\t".to_string();

        let err = engine
            .override_barrier(&barrier_id, justification, &trace)
            .unwrap_err();

        assert!(matches!(
            err,
            BarrierError::OverrideRejected(message) if message.contains("reason")
        ));
        assert_eq!(engine.audit_log().len(), audit_count_before);
    }

    #[test]
    fn override_whitespace_timestamp_rejected_without_audit_receipt() {
        let mut engine = BarrierEngine::new();
        let trace = make_trace_id();
        let barrier = make_sandbox_barrier("override-whitespace-timestamp", SandboxTier::Strict);
        let barrier_id = barrier.barrier_id.clone();
        engine.apply_barrier(barrier, &trace).unwrap();
        let audit_count_before = engine.audit_log().len();
        let mut justification = make_override_justification();
        justification.timestamp = "   ".to_string();

        let err = engine
            .override_barrier(&barrier_id, justification, &trace)
            .unwrap_err();

        assert!(matches!(
            err,
            BarrierError::OverrideRejected(message) if message.contains("timestamp")
        ));
        assert_eq!(engine.audit_log().len(), audit_count_before);
    }

    #[test]
    fn override_whitespace_signature_rejected_without_audit_receipt() {
        let mut engine = BarrierEngine::new();
        let trace = make_trace_id();
        let barrier = make_sandbox_barrier("override-whitespace-signature", SandboxTier::Strict);
        let barrier_id = barrier.barrier_id.clone();
        engine.apply_barrier(barrier, &trace).unwrap();
        let audit_count_before = engine.audit_log().len();
        let mut justification = make_override_justification();
        justification.signature_hex = "\r\n".to_string();

        let err = engine
            .override_barrier(&barrier_id, justification, &trace)
            .unwrap_err();

        assert!(matches!(
            err,
            BarrierError::OverrideRejected(message) if message.contains("signature")
        ));
        assert_eq!(engine.audit_log().len(), audit_count_before);
    }

    #[test]
    fn override_multiple_blank_fields_reports_override_id_first() {
        let mut justification = make_override_justification();
        justification.override_id.clear();
        justification.principal_identity.clear();
        justification.reason.clear();

        let err = justification
            .validate()
            .expect_err("override_id should be the first rejected field");

        assert!(matches!(
            err,
            BarrierError::OverrideRejected(message)
                if message.contains("override_id") && !message.contains("principal_identity")
        ));
    }

    #[test]
    fn push_bounded_overfull_input_uses_saturating_eviction_math() {
        let mut items = vec![1_u8, 2, 3, 4, 5];

        push_bounded(&mut items, 6, 2);

        assert_eq!(items, vec![5, 6]);
    }
}
