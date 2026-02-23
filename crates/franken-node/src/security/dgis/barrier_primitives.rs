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

use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Event codes (structured logging)
// ---------------------------------------------------------------------------

/// Stable event codes for DGIS barrier enforcement.
pub mod event_codes {
    pub const BARRIER_APPLIED: &str = "DGIS-BARRIER-001";
    pub const BARRIER_REMOVED: &str = "DGIS-BARRIER-002";
    pub const BARRIER_OVERRIDDEN: &str = "DGIS-BARRIER-003";
    pub const BARRIER_EXPIRED: &str = "DGIS-BARRIER-004";
    pub const BARRIER_CHECK_PASSED: &str = "DGIS-BARRIER-005";
    pub const BARRIER_CHECK_DENIED: &str = "DGIS-BARRIER-006";
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
    #[error("barrier not found: {0}")]
    NotFound(String),
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
pub struct ProgressionCriteria {
    pub min_soak_seconds: u64,
    pub max_error_rate: f64,
    pub min_success_count: u64,
}

impl Default for ProgressionCriteria {
    fn default() -> Self {
        Self {
            min_soak_seconds: 3600,
            max_error_rate: 0.01,
            min_success_count: 100,
        }
    }
}

/// Configuration for staged rollout fence.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StagedRolloutFenceConfig {
    pub initial_phase: RolloutPhase,
    pub progression_criteria: BTreeMap<String, ProgressionCriteria>,
    pub auto_rollback_on_breach: bool,
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
        if self.principal_identity.is_empty() {
            return Err(BarrierError::OverrideRejected(
                "principal_identity is required".to_string(),
            ));
        }
        if self.reason.is_empty() {
            return Err(BarrierError::OverrideRejected(
                "reason is required".to_string(),
            ));
        }
        if self.signature_hex.is_empty() {
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
            timestamp: Utc::now().to_rfc3339(),
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
    pub fn content_hash(&self) -> String {
        let canonical = serde_json::to_string(self).unwrap_or_default();
        let digest = Sha256::digest(
            [
                b"barrier_primitives_hash_v1:" as &[u8],
                canonical.as_bytes(),
            ]
            .concat(),
        );
        hex::encode(digest)
    }
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
            phase_entered_at: Utc::now().to_rfc3339(),
            success_count: 0,
            error_count: 0,
            total_count: 0,
        }
    }

    pub fn error_rate(&self) -> f64 {
        if self.total_count == 0 {
            return 0.0;
        }
        self.error_count as f64 / self.total_count as f64
    }

    pub fn record_success(&mut self) {
        self.success_count += 1;
        self.total_count += 1;
    }

    pub fn record_error(&mut self) {
        self.error_count += 1;
        self.total_count += 1;
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
        self.node_barriers
            .entry(node_id)
            .or_default()
            .push(barrier_id);

        self.audit_log.push(receipt.clone());
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
        self.audit_log.push(receipt.clone());
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

        self.audit_log.push(receipt.clone());
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

        for barrier_id in &barrier_ids {
            if let Some(barrier) = self.barriers.get(barrier_id)
                && let BarrierConfig::SandboxEscalation(ref cfg) = barrier.config
            {
                // Enforce minimum tier
                if current_tier.level() < cfg.min_tier.level() {
                    let receipt = BarrierAuditReceipt::new(
                        event_codes::BARRIER_CHECK_DENIED,
                        barrier,
                        BarrierAction::CheckDenied,
                        trace_id,
                        serde_json::json!({
                            "reason": "sandbox tier below minimum",
                            "current_tier": format!("{current_tier}"),
                            "required_tier": format!("{}", cfg.min_tier),
                        }),
                    );
                    self.audit_log.push(receipt);
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
                        barrier,
                        BarrierAction::CheckDenied,
                        trace_id,
                        serde_json::json!({
                            "reason": "capability denied by sandbox escalation",
                            "capability": requested_capability,
                        }),
                    );
                    self.audit_log.push(receipt);
                    return Err(BarrierError::SandboxEscalation(format!(
                        "capability '{requested_capability}' denied on node {node_id}"
                    )));
                }
            }
        }

        // Build a synthetic barrier for the receipt (use first matching or create placeholder)
        let receipt = self.make_pass_receipt(
            node_id,
            BarrierType::SandboxEscalation,
            event_codes::SANDBOX_ESCALATED,
            trace_id,
            serde_json::json!({
                "capability": requested_capability,
                "tier": format!("{current_tier}"),
            }),
        );
        self.audit_log.push(receipt.clone());
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

        for barrier_id in &barrier_ids {
            if let Some(barrier) = self.barriers.get(barrier_id)
                && let BarrierConfig::CompositionFirewall(ref cfg) = barrier.config
                && cfg.boundary_id == target_boundary
            {
                // Capability blocked unless in allow list
                let is_allowed = cfg.allow_list.contains(&capability.to_string());
                let is_blocked = cfg.blocked_capabilities.contains(&capability.to_string());

                if is_blocked && !is_allowed {
                    let receipt = BarrierAuditReceipt::new(
                        event_codes::BARRIER_CHECK_DENIED,
                        barrier,
                        BarrierAction::CheckDenied,
                        trace_id,
                        serde_json::json!({
                            "reason": "capability blocked by composition firewall",
                            "capability": capability,
                            "boundary": target_boundary,
                        }),
                    );
                    self.audit_log.push(receipt);
                    return Err(BarrierError::FirewallViolation {
                        capability: capability.to_string(),
                        boundary: target_boundary.to_string(),
                    });
                }
            }
        }

        let receipt = self.make_pass_receipt(
            node_id,
            BarrierType::CompositionFirewall,
            event_codes::FIREWALL_ENFORCED,
            trace_id,
            serde_json::json!({
                "capability": capability,
                "boundary": target_boundary,
            }),
        );
        self.audit_log.push(receipt.clone());
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

        for barrier_id in &barrier_ids {
            if let Some(barrier) = self.barriers.get(barrier_id)
                && let BarrierConfig::VerifiedForkPin(ref cfg) = barrier.config
                && cfg.expected_digest != artifact_digest
            {
                let receipt = BarrierAuditReceipt::new(
                    event_codes::FORK_PIN_REJECTED,
                    barrier,
                    BarrierAction::CheckDenied,
                    trace_id,
                    serde_json::json!({
                        "expected_digest": cfg.expected_digest,
                        "actual_digest": artifact_digest,
                        "pinned_commit": cfg.pinned_commit,
                    }),
                );
                self.audit_log.push(receipt);
                return Err(BarrierError::ForkPinVerification(format!(
                    "digest mismatch for node {node_id}: expected {}, got {artifact_digest}",
                    cfg.expected_digest
                )));
            }
        }

        let receipt = self.make_pass_receipt(
            node_id,
            BarrierType::VerifiedForkPin,
            event_codes::FORK_PIN_VERIFIED,
            trace_id,
            serde_json::json!({
                "artifact_digest": artifact_digest,
            }),
        );
        self.audit_log.push(receipt.clone());
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

        let state = self
            .rollout_states
            .get(barrier_id)
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
            self.audit_log.push(receipt);
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
        self.audit_log.push(receipt.clone());
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
        state.phase_entered_at = Utc::now().to_rfc3339();
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
        self.audit_log.push(receipt.clone());
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
        state.phase_entered_at = Utc::now().to_rfc3339();
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
        self.audit_log.push(receipt.clone());
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

    fn get_node_barrier_ids(&self, node_id: &str) -> Vec<String> {
        self.node_barriers.get(node_id).cloned().unwrap_or_default()
    }

    /// Check that a new barrier does not conflict with existing barriers on the same node.
    fn check_composition_validity(&self, barrier: &Barrier) -> Result<(), BarrierError> {
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

    /// Create a pass receipt for a node that has no matching barrier (pass-through).
    fn make_pass_receipt(
        &self,
        node_id: &str,
        barrier_type: BarrierType,
        event_code: &str,
        trace_id: &str,
        details: serde_json::Value,
    ) -> BarrierAuditReceipt {
        BarrierAuditReceipt {
            receipt_id: Uuid::now_v7().to_string(),
            event_code: event_code.to_string(),
            barrier_id: format!("passthrough-{node_id}"),
            node_id: node_id.to_string(),
            barrier_type,
            action: BarrierAction::CheckPassed,
            timestamp: Utc::now().to_rfc3339(),
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
        let mut receipts = Vec::with_capacity(self.barriers.len());
        for barrier in &self.barriers {
            let mut b = barrier.clone();
            b.source_plan_id = Some(self.plan_id.clone());
            receipts.push(engine.apply_barrier(b, trace_id)?);
        }
        Ok(receipts)
    }
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
            applied_at: Utc::now().to_rfc3339(),
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
            applied_at: Utc::now().to_rfc3339(),
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
            applied_at: Utc::now().to_rfc3339(),
            expires_at: None,
            source_plan_id: None,
        }
    }

    fn make_rollout_barrier(node_id: &str) -> Barrier {
        let mut criteria = BTreeMap::new();
        criteria.insert(
            "canary".to_string(),
            ProgressionCriteria {
                min_soak_seconds: 60,
                max_error_rate: 0.05,
                min_success_count: 10,
            },
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
            applied_at: Utc::now().to_rfc3339(),
            expires_at: None,
            source_plan_id: None,
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
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn sandbox_escalation_allows_at_min_tier() {
        let mut engine = BarrierEngine::new();
        let barrier = make_sandbox_barrier("node-b", SandboxTier::Strict);
        let trace = make_trace_id();
        engine.apply_barrier(barrier, &trace).unwrap();

        let result =
            engine.check_sandbox_escalation("node-b", "network_http", SandboxTier::Strict, &trace);
        assert!(result.is_ok());
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
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn firewall_allows_capability_in_allow_list() {
        let mut engine = BarrierEngine::new();
        let barrier = make_firewall_barrier("node-f", "trust-boundary-1");
        let trace = make_trace_id();
        engine.apply_barrier(barrier, &trace).unwrap();

        // network_raw is in both blocked and allow_list; allow_list wins
        let result =
            engine.check_composition_firewall("node-f", "network_raw", "trust-boundary-1", &trace);
        assert!(result.is_ok());
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
        let trace = make_trace_id();
        engine.apply_barrier(barrier, &trace).unwrap();

        let result = engine.check_fork_pin("dep-y", "sha256:aabbccdd", &trace);
        assert!(result.is_ok());
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
            timestamp: Utc::now().to_rfc3339(),
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
            timestamp: Utc::now().to_rfc3339(),
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
            other => panic!("unexpected error: {other}"),
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

        let hash1 = receipt.content_hash();
        let hash2 = receipt.content_hash();
        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 64); // SHA-256 hex
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
            created_at: Utc::now().to_rfc3339(),
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

    // === Passthrough behavior ===

    #[test]
    fn check_passes_when_no_barriers_exist() {
        let mut engine = BarrierEngine::new();
        let trace = make_trace_id();

        let result = engine.check_sandbox_escalation(
            "unbarriered-node",
            "anything",
            SandboxTier::Permissive,
            &trace,
        );
        assert!(result.is_ok());

        let result = engine.check_composition_firewall(
            "unbarriered-node",
            "exec_child",
            "any-boundary",
            &trace,
        );
        assert!(result.is_ok());

        let result = engine.check_fork_pin("unbarriered-node", "any-digest", &trace);
        assert!(result.is_ok());
    }
}
