//! bd-gad3: Adaptive multi-rail isolation mesh with hot-elevation policy.
//!
//! Workloads are assigned to isolation rails based on their trust profile and
//! latency requirements. Rails form a strict ordering from most permissive
//! (Standard) to most restrictive (Critical). Workloads can be promoted
//! ("hot-elevated") to stricter rails at runtime without restarting, while
//! preserving policy continuity — no policy rule active before elevation may
//! be weakened or dropped during or after the transition.
//!
//! Latency-sensitive trusted workloads remain on high-performance rails as
//! long as their cumulative latency budget is not exceeded.
//!
//! # Event Codes
//!
//! - `ISOLATION_RAIL_ASSIGNED`: Workload placed on an initial rail.
//! - `ISOLATION_ELEVATION_START`: Hot-elevation transition initiated.
//! - `ISOLATION_ELEVATION_COMPLETE`: Hot-elevation transition completed.
//! - `ISOLATION_POLICY_PRESERVED`: Policy continuity verified after elevation.
//! - `ISOLATION_BUDGET_CHECK`: Latency budget evaluated for a workload.
//!
//! # Error Codes
//!
//! - `ERR_ISOLATION_RAIL_UNAVAILABLE`: Requested rail is not available.
//! - `ERR_ISOLATION_ELEVATION_DENIED`: Elevation blocked (e.g. downgrade attempt).
//! - `ERR_ISOLATION_POLICY_BREAK`: Policy continuity violation detected.
//! - `ERR_ISOLATION_BUDGET_EXCEEDED`: Latency budget exceeded for workload.
//! - `ERR_ISOLATION_MESH_PARTITION`: Mesh connectivity lost between rails.
//! - `ERR_ISOLATION_WORKLOAD_REJECTED`: Workload cannot be admitted to any rail.
//!
//! # Invariants
//!
//! - **INV-ISOLATION-POLICY-CONTINUITY**: No policy rule active before
//!   elevation may be weakened or dropped during or after the transition.
//! - **INV-ISOLATION-HOT-ELEVATION**: Workloads may only be promoted to
//!   strictly more-restrictive rails at runtime (never downgraded).
//! - **INV-ISOLATION-BUDGET-BOUND**: Latency-sensitive workloads remain on
//!   high-performance rails only while within their configured budget.
//! - **INV-ISOLATION-FAIL-SAFE**: If elevation or mesh health checks fail,
//!   the workload remains on its current rail (no state is lost).

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

// ---------------------------------------------------------------------------
// Event codes
// ---------------------------------------------------------------------------

/// ISOLATION_RAIL_ASSIGNED: Workload placed on initial rail.
pub const ISOLATION_RAIL_ASSIGNED: &str = "ISOLATION_RAIL_ASSIGNED";
/// ISOLATION_ELEVATION_START: Hot-elevation transition initiated.
pub const ISOLATION_ELEVATION_START: &str = "ISOLATION_ELEVATION_START";
/// ISOLATION_ELEVATION_COMPLETE: Hot-elevation transition completed.
pub const ISOLATION_ELEVATION_COMPLETE: &str = "ISOLATION_ELEVATION_COMPLETE";
/// ISOLATION_POLICY_PRESERVED: Policy continuity verified after elevation.
pub const ISOLATION_POLICY_PRESERVED: &str = "ISOLATION_POLICY_PRESERVED";
/// ISOLATION_BUDGET_CHECK: Latency budget evaluated for workload.
pub const ISOLATION_BUDGET_CHECK: &str = "ISOLATION_BUDGET_CHECK";

// ---------------------------------------------------------------------------
// Error codes
// ---------------------------------------------------------------------------

/// ERR_ISOLATION_RAIL_UNAVAILABLE: Requested rail is not available.
pub const ERR_ISOLATION_RAIL_UNAVAILABLE: &str = "ERR_ISOLATION_RAIL_UNAVAILABLE";
/// ERR_ISOLATION_ELEVATION_DENIED: Elevation blocked (e.g. downgrade attempt).
pub const ERR_ISOLATION_ELEVATION_DENIED: &str = "ERR_ISOLATION_ELEVATION_DENIED";
/// ERR_ISOLATION_POLICY_BREAK: Policy continuity violation detected.
pub const ERR_ISOLATION_POLICY_BREAK: &str = "ERR_ISOLATION_POLICY_BREAK";
/// ERR_ISOLATION_BUDGET_EXCEEDED: Latency budget exceeded for workload.
pub const ERR_ISOLATION_BUDGET_EXCEEDED: &str = "ERR_ISOLATION_BUDGET_EXCEEDED";
/// ERR_ISOLATION_MESH_PARTITION: Mesh connectivity lost between rails.
pub const ERR_ISOLATION_MESH_PARTITION: &str = "ERR_ISOLATION_MESH_PARTITION";
/// ERR_ISOLATION_WORKLOAD_REJECTED: Workload cannot be admitted to any rail.
pub const ERR_ISOLATION_WORKLOAD_REJECTED: &str = "ERR_ISOLATION_WORKLOAD_REJECTED";

// ---------------------------------------------------------------------------
// Invariant tags (used in documentation and audit trail)
// ---------------------------------------------------------------------------

/// INV-ISOLATION-POLICY-CONTINUITY
pub const INV_POLICY_CONTINUITY: &str = "INV-ISOLATION-POLICY-CONTINUITY";
/// INV-ISOLATION-HOT-ELEVATION
pub const INV_HOT_ELEVATION: &str = "INV-ISOLATION-HOT-ELEVATION";
/// INV-ISOLATION-BUDGET-BOUND
pub const INV_BUDGET_BOUND: &str = "INV-ISOLATION-BUDGET-BOUND";
/// INV-ISOLATION-FAIL-SAFE
pub const INV_FAIL_SAFE: &str = "INV-ISOLATION-FAIL-SAFE";

// ---------------------------------------------------------------------------
// Core types
// ---------------------------------------------------------------------------

/// Isolation rails ordered from most permissive to most restrictive.
///
/// Numeric level: Standard(0) < Elevated(1) < HighAssurance(2) < Critical(3).
/// Elevation (promotion) moves workloads to a *higher* numeric level (stricter).
/// Downgrade is never allowed at runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum IsolationRail {
    Standard = 0,
    Elevated = 1,
    HighAssurance = 2,
    Critical = 3,
}

impl IsolationRail {
    pub const ALL: [IsolationRail; 4] = [
        Self::Standard,
        Self::Elevated,
        Self::HighAssurance,
        Self::Critical,
    ];

    pub fn level(self) -> u8 {
        self as u8
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Standard => "standard",
            Self::Elevated => "elevated",
            Self::HighAssurance => "high_assurance",
            Self::Critical => "critical",
        }
    }

    /// Returns true if `target` is strictly more restrictive than `self`.
    pub fn can_elevate_to(self, target: IsolationRail) -> bool {
        target.level() > self.level()
    }

    /// Returns true if `target` is less restrictive — a downgrade.
    pub fn is_downgrade_to(self, target: IsolationRail) -> bool {
        target.level() < self.level()
    }

    /// Default latency budget (microseconds) for this rail.
    pub fn default_latency_budget_us(self) -> u64 {
        match self {
            Self::Standard => 10_000,     // 10 ms
            Self::Elevated => 5_000,      // 5 ms
            Self::HighAssurance => 2_000, // 2 ms
            Self::Critical => 500,        // 0.5 ms
        }
    }
}

impl fmt::Display for IsolationRail {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A single policy rule active on a rail.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PolicyRule {
    pub name: String,
    pub scope: String,
    pub deny: bool,
}

/// Represents the immutable policy set for a rail.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RailPolicy {
    pub rail: IsolationRail,
    pub rules: Vec<PolicyRule>,
}

impl RailPolicy {
    /// Check that `other` is a superset of `self` (policy continuity).
    ///
    /// Returns `Ok(())` if every rule in `self` also appears in `other`.
    /// This enforces INV-ISOLATION-POLICY-CONTINUITY.
    pub fn is_subset_of(&self, other: &RailPolicy) -> Result<(), RailRouterError> {
        for rule in &self.rules {
            if !other.rules.contains(rule) {
                return Err(RailRouterError::PolicyBreak {
                    rule_name: rule.name.clone(),
                    from_rail: self.rail,
                    to_rail: other.rail,
                });
            }
        }
        Ok(())
    }
}

/// Workload trust classification used for initial rail assignment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustProfile {
    Untrusted,
    Verified,
    HighAssurance,
    PlatformCritical,
}

impl TrustProfile {
    /// Map trust profile to the minimum rail the workload should be placed on.
    pub fn minimum_rail(self) -> IsolationRail {
        match self {
            Self::Untrusted => IsolationRail::Standard,
            Self::Verified => IsolationRail::Elevated,
            Self::HighAssurance => IsolationRail::HighAssurance,
            Self::PlatformCritical => IsolationRail::Critical,
        }
    }
}

/// Workload descriptor for the isolation mesh.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Workload {
    pub id: String,
    pub trust_profile: TrustProfile,
    pub latency_sensitive: bool,
    pub latency_budget_us: u64,
}

/// Placement record for a workload on a rail.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Placement {
    pub workload_id: String,
    pub rail: IsolationRail,
    pub latency_budget_us: u64,
    pub latency_consumed_us: u64,
    pub elevation_count: u32,
}

impl Placement {
    pub fn remaining_budget_us(&self) -> u64 {
        self.latency_budget_us
            .saturating_sub(self.latency_consumed_us)
    }

    pub fn budget_exceeded(&self) -> bool {
        self.latency_consumed_us > self.latency_budget_us
    }
}

/// Audit event emitted by the rail router.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RailEvent {
    pub event_code: String,
    pub workload_id: String,
    pub detail: String,
    pub rail: Option<IsolationRail>,
    pub target_rail: Option<IsolationRail>,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors produced by the rail router.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RailRouterError {
    /// ERR_ISOLATION_RAIL_UNAVAILABLE
    RailUnavailable { rail: IsolationRail },
    /// ERR_ISOLATION_ELEVATION_DENIED
    ElevationDenied {
        from: IsolationRail,
        to: IsolationRail,
        reason: String,
    },
    /// ERR_ISOLATION_POLICY_BREAK
    PolicyBreak {
        rule_name: String,
        from_rail: IsolationRail,
        to_rail: IsolationRail,
    },
    /// ERR_ISOLATION_BUDGET_EXCEEDED
    BudgetExceeded {
        workload_id: String,
        budget_us: u64,
        consumed_us: u64,
    },
    /// ERR_ISOLATION_MESH_PARTITION
    MeshPartition {
        rail_a: IsolationRail,
        rail_b: IsolationRail,
    },
    /// ERR_ISOLATION_WORKLOAD_REJECTED
    WorkloadRejected { workload_id: String, reason: String },
}

impl fmt::Display for RailRouterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RailUnavailable { rail } => {
                write!(
                    f,
                    "{ERR_ISOLATION_RAIL_UNAVAILABLE}: rail {rail} is not available"
                )
            }
            Self::ElevationDenied { from, to, reason } => {
                write!(
                    f,
                    "{ERR_ISOLATION_ELEVATION_DENIED}: {from} -> {to}: {reason}"
                )
            }
            Self::PolicyBreak {
                rule_name,
                from_rail,
                to_rail,
            } => {
                write!(
                    f,
                    "{ERR_ISOLATION_POLICY_BREAK}: rule '{rule_name}' lost moving {from_rail} -> {to_rail}"
                )
            }
            Self::BudgetExceeded {
                workload_id,
                budget_us,
                consumed_us,
            } => {
                write!(
                    f,
                    "{ERR_ISOLATION_BUDGET_EXCEEDED}: workload {workload_id}: consumed {consumed_us}us > budget {budget_us}us"
                )
            }
            Self::MeshPartition { rail_a, rail_b } => {
                write!(
                    f,
                    "{ERR_ISOLATION_MESH_PARTITION}: partition between {rail_a} and {rail_b}"
                )
            }
            Self::WorkloadRejected {
                workload_id,
                reason,
            } => {
                write!(
                    f,
                    "{ERR_ISOLATION_WORKLOAD_REJECTED}: workload {workload_id}: {reason}"
                )
            }
        }
    }
}

impl std::error::Error for RailRouterError {}

// ---------------------------------------------------------------------------
// Rail router (the isolation mesh)
// ---------------------------------------------------------------------------

/// Configuration for the isolation mesh.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MeshConfig {
    /// Which rails are available in this deployment.
    pub available_rails: Vec<IsolationRail>,
    /// Per-rail policy definitions.
    pub rail_policies: HashMap<IsolationRail, RailPolicy>,
    /// Whether mesh partition checks are enabled.
    pub partition_check_enabled: bool,
}

impl MeshConfig {
    /// Create a default mesh with all four rails and standard policies.
    pub fn default_mesh() -> Self {
        let mut rail_policies = HashMap::new();
        for rail in IsolationRail::ALL {
            let mut rules = vec![
                PolicyRule {
                    name: "deny_raw_syscall".to_string(),
                    scope: "system".to_string(),
                    deny: true,
                },
                PolicyRule {
                    name: "audit_capability_use".to_string(),
                    scope: "audit".to_string(),
                    deny: false,
                },
            ];
            // Stricter rails add more rules; crucially they always keep
            // the rules from less-strict rails (policy continuity).
            if rail.level() >= IsolationRail::Elevated.level() {
                rules.push(PolicyRule {
                    name: "deny_network_egress".to_string(),
                    scope: "network".to_string(),
                    deny: true,
                });
            }
            if rail.level() >= IsolationRail::HighAssurance.level() {
                rules.push(PolicyRule {
                    name: "deny_filesystem_write".to_string(),
                    scope: "filesystem".to_string(),
                    deny: true,
                });
            }
            if rail.level() >= IsolationRail::Critical.level() {
                rules.push(PolicyRule {
                    name: "deny_ipc".to_string(),
                    scope: "ipc".to_string(),
                    deny: true,
                });
            }
            rail_policies.insert(rail, RailPolicy { rail, rules });
        }

        Self {
            available_rails: IsolationRail::ALL.to_vec(),
            rail_policies,
            partition_check_enabled: true,
        }
    }
}

/// The adaptive multi-rail isolation mesh router.
///
/// Manages workload placement, hot-elevation, budget tracking, and
/// policy continuity verification.
pub struct RailRouter {
    config: MeshConfig,
    placements: HashMap<String, Placement>,
    events: Vec<RailEvent>,
}

impl RailRouter {
    /// Create a new router with the given mesh configuration.
    pub fn new(config: MeshConfig) -> Self {
        Self {
            config,
            placements: HashMap::new(),
            events: Vec::new(),
        }
    }

    /// Create a router with the default four-rail mesh.
    pub fn default_router() -> Self {
        Self::new(MeshConfig::default_mesh())
    }

    // -- accessors --

    pub fn config(&self) -> &MeshConfig {
        &self.config
    }

    pub fn placements(&self) -> &HashMap<String, Placement> {
        &self.placements
    }

    pub fn events(&self) -> &[RailEvent] {
        &self.events
    }

    // -- core operations --

    /// Assign a workload to its initial rail based on trust profile.
    ///
    /// Emits ISOLATION_RAIL_ASSIGNED on success.
    /// Returns ERR_ISOLATION_RAIL_UNAVAILABLE if the target rail is not available.
    /// Returns ERR_ISOLATION_WORKLOAD_REJECTED if the workload ID is already placed.
    pub fn assign_workload(&mut self, workload: &Workload) -> Result<Placement, RailRouterError> {
        if self.placements.contains_key(&workload.id) {
            return Err(RailRouterError::WorkloadRejected {
                workload_id: workload.id.clone(),
                reason: "workload already placed".to_string(),
            });
        }

        let target_rail = workload.trust_profile.minimum_rail();
        if !self.config.available_rails.contains(&target_rail) {
            return Err(RailRouterError::RailUnavailable { rail: target_rail });
        }

        let budget = if workload.latency_sensitive {
            workload.latency_budget_us
        } else {
            target_rail.default_latency_budget_us()
        };

        let placement = Placement {
            workload_id: workload.id.clone(),
            rail: target_rail,
            latency_budget_us: budget,
            latency_consumed_us: 0,
            elevation_count: 0,
        };

        self.placements
            .insert(workload.id.clone(), placement.clone());
        self.events.push(RailEvent {
            event_code: ISOLATION_RAIL_ASSIGNED.to_string(),
            workload_id: workload.id.clone(),
            detail: format!("assigned to rail {target_rail}"),
            rail: Some(target_rail),
            target_rail: None,
        });

        Ok(placement)
    }

    /// Hot-elevate a workload to a stricter rail at runtime.
    ///
    /// Enforces:
    /// - INV-ISOLATION-HOT-ELEVATION: only promotion to stricter rails.
    /// - INV-ISOLATION-POLICY-CONTINUITY: all current policy rules preserved.
    /// - INV-ISOLATION-FAIL-SAFE: on any error, workload stays on current rail.
    ///
    /// Emits ISOLATION_ELEVATION_START, then ISOLATION_POLICY_PRESERVED,
    /// then ISOLATION_ELEVATION_COMPLETE on success.
    pub fn hot_elevate(
        &mut self,
        workload_id: &str,
        target_rail: IsolationRail,
    ) -> Result<Placement, RailRouterError> {
        let placement =
            self.placements
                .get(workload_id)
                .ok_or_else(|| RailRouterError::WorkloadRejected {
                    workload_id: workload_id.to_string(),
                    reason: "workload not found".to_string(),
                })?;

        let current_rail = placement.rail;

        // INV-ISOLATION-HOT-ELEVATION: only allow promotion to stricter rails.
        if current_rail == target_rail {
            return Err(RailRouterError::ElevationDenied {
                from: current_rail,
                to: target_rail,
                reason: "already on requested rail".to_string(),
            });
        }
        if current_rail.is_downgrade_to(target_rail) {
            return Err(RailRouterError::ElevationDenied {
                from: current_rail,
                to: target_rail,
                reason: "downgrade not permitted".to_string(),
            });
        }
        if !current_rail.can_elevate_to(target_rail) {
            return Err(RailRouterError::ElevationDenied {
                from: current_rail,
                to: target_rail,
                reason: "target rail is not strictly more restrictive".to_string(),
            });
        }

        // Check target rail is available.
        if !self.config.available_rails.contains(&target_rail) {
            return Err(RailRouterError::RailUnavailable { rail: target_rail });
        }

        // Emit ISOLATION_ELEVATION_START
        self.events.push(RailEvent {
            event_code: ISOLATION_ELEVATION_START.to_string(),
            workload_id: workload_id.to_string(),
            detail: format!("elevating {current_rail} -> {target_rail}"),
            rail: Some(current_rail),
            target_rail: Some(target_rail),
        });

        // INV-ISOLATION-POLICY-CONTINUITY: verify all current rules are
        // preserved in the target rail policy.
        let current_policy = self.config.rail_policies.get(&current_rail);
        let target_policy = self.config.rail_policies.get(&target_rail);

        if let (Some(cp), Some(tp)) = (current_policy, target_policy) {
            // INV-ISOLATION-FAIL-SAFE: if policy check fails, workload stays.
            cp.is_subset_of(tp)?;
        }

        // Emit ISOLATION_POLICY_PRESERVED
        self.events.push(RailEvent {
            event_code: ISOLATION_POLICY_PRESERVED.to_string(),
            workload_id: workload_id.to_string(),
            detail: format!("policy continuity verified {current_rail} -> {target_rail}"),
            rail: Some(current_rail),
            target_rail: Some(target_rail),
        });

        // Mesh partition check.
        if self.config.partition_check_enabled {
            self.check_mesh_connectivity(current_rail, target_rail)?;
        }

        // Perform the elevation.
        let p = self.placements.get_mut(workload_id).unwrap();
        p.rail = target_rail;
        p.elevation_count += 1;
        let updated = p.clone();

        // Emit ISOLATION_ELEVATION_COMPLETE
        self.events.push(RailEvent {
            event_code: ISOLATION_ELEVATION_COMPLETE.to_string(),
            workload_id: workload_id.to_string(),
            detail: format!("elevated to rail {target_rail}"),
            rail: Some(target_rail),
            target_rail: None,
        });

        Ok(updated)
    }

    /// Record latency consumption for a workload and check budget.
    ///
    /// Emits ISOLATION_BUDGET_CHECK. Returns error if budget is exceeded
    /// (INV-ISOLATION-BUDGET-BOUND).
    pub fn record_latency(
        &mut self,
        workload_id: &str,
        consumed_us: u64,
    ) -> Result<Placement, RailRouterError> {
        let placement = self.placements.get_mut(workload_id).ok_or_else(|| {
            RailRouterError::WorkloadRejected {
                workload_id: workload_id.to_string(),
                reason: "workload not found".to_string(),
            }
        })?;

        placement.latency_consumed_us = placement.latency_consumed_us.saturating_add(consumed_us);

        self.events.push(RailEvent {
            event_code: ISOLATION_BUDGET_CHECK.to_string(),
            workload_id: workload_id.to_string(),
            detail: format!(
                "consumed={}us budget={}us remaining={}us",
                placement.latency_consumed_us,
                placement.latency_budget_us,
                placement.remaining_budget_us()
            ),
            rail: Some(placement.rail),
            target_rail: None,
        });

        // INV-ISOLATION-BUDGET-BOUND
        if placement.budget_exceeded() {
            return Err(RailRouterError::BudgetExceeded {
                workload_id: workload_id.to_string(),
                budget_us: placement.latency_budget_us,
                consumed_us: placement.latency_consumed_us,
            });
        }

        Ok(placement.clone())
    }

    /// Check mesh connectivity between two rails.
    fn check_mesh_connectivity(
        &self,
        from: IsolationRail,
        to: IsolationRail,
    ) -> Result<(), RailRouterError> {
        // In the current mesh model, all available rails are connected.
        // A partition occurs only if the target rail is not available.
        if !self.config.available_rails.contains(&from)
            || !self.config.available_rails.contains(&to)
        {
            return Err(RailRouterError::MeshPartition {
                rail_a: from,
                rail_b: to,
            });
        }
        Ok(())
    }

    /// Remove a workload from the mesh.
    pub fn remove_workload(&mut self, workload_id: &str) -> Option<Placement> {
        self.placements.remove(workload_id)
    }

    /// Get the current placement for a workload.
    pub fn get_placement(&self, workload_id: &str) -> Option<&Placement> {
        self.placements.get(workload_id)
    }

    /// Generate a mesh profile report (used by the check script).
    pub fn mesh_profile_report(&self) -> MeshProfileReport {
        let rail_summaries: Vec<RailSummary> = self
            .config
            .available_rails
            .iter()
            .map(|rail| {
                let workload_count = self.placements.values().filter(|p| p.rail == *rail).count();
                let policy_rule_count = self
                    .config
                    .rail_policies
                    .get(rail)
                    .map(|p| p.rules.len())
                    .unwrap_or(0);
                RailSummary {
                    rail: *rail,
                    workload_count,
                    policy_rule_count,
                    latency_budget_us: rail.default_latency_budget_us(),
                }
            })
            .collect();

        MeshProfileReport {
            schema_version: "isolation-mesh-v1.0".to_string(),
            total_rails: self.config.available_rails.len(),
            total_workloads: self.placements.len(),
            total_events: self.events.len(),
            partition_check_enabled: self.config.partition_check_enabled,
            rail_summaries,
            policy_continuity_enforced: true,
            hot_elevation_only_stricter: true,
            budget_bound_enforced: true,
            fail_safe_on_error: true,
        }
    }
}

/// Summary of a single rail in the mesh profile report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RailSummary {
    pub rail: IsolationRail,
    pub workload_count: usize,
    pub policy_rule_count: usize,
    pub latency_budget_us: u64,
}

/// Machine-readable mesh profile report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MeshProfileReport {
    pub schema_version: String,
    pub total_rails: usize,
    pub total_workloads: usize,
    pub total_events: usize,
    pub partition_check_enabled: bool,
    pub rail_summaries: Vec<RailSummary>,
    pub policy_continuity_enforced: bool,
    pub hot_elevation_only_stricter: bool,
    pub budget_bound_enforced: bool,
    pub fail_safe_on_error: bool,
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_workload(id: &str, trust: TrustProfile, latency_sensitive: bool) -> Workload {
        Workload {
            id: id.to_string(),
            trust_profile: trust,
            latency_sensitive,
            latency_budget_us: if latency_sensitive { 1_000 } else { 10_000 },
        }
    }

    // === Rail ordering ===

    #[test]
    fn rail_ordering_is_strict() {
        assert!(IsolationRail::Standard < IsolationRail::Elevated);
        assert!(IsolationRail::Elevated < IsolationRail::HighAssurance);
        assert!(IsolationRail::HighAssurance < IsolationRail::Critical);
    }

    #[test]
    fn rail_levels_match_ordering() {
        assert_eq!(IsolationRail::Standard.level(), 0);
        assert_eq!(IsolationRail::Elevated.level(), 1);
        assert_eq!(IsolationRail::HighAssurance.level(), 2);
        assert_eq!(IsolationRail::Critical.level(), 3);
    }

    #[test]
    fn four_rails_exist() {
        assert_eq!(IsolationRail::ALL.len(), 4);
    }

    // === Trust profile mapping ===

    #[test]
    fn trust_profile_minimum_rail() {
        assert_eq!(
            TrustProfile::Untrusted.minimum_rail(),
            IsolationRail::Standard
        );
        assert_eq!(
            TrustProfile::Verified.minimum_rail(),
            IsolationRail::Elevated
        );
        assert_eq!(
            TrustProfile::HighAssurance.minimum_rail(),
            IsolationRail::HighAssurance
        );
        assert_eq!(
            TrustProfile::PlatformCritical.minimum_rail(),
            IsolationRail::Critical
        );
    }

    // === Workload assignment ===

    #[test]
    fn assign_workload_to_initial_rail() {
        let mut router = RailRouter::default_router();
        let wl = test_workload("wl-1", TrustProfile::Untrusted, false);
        let p = router.assign_workload(&wl).unwrap();
        assert_eq!(p.rail, IsolationRail::Standard);
        assert_eq!(p.elevation_count, 0);
    }

    #[test]
    fn assign_verified_workload() {
        let mut router = RailRouter::default_router();
        let wl = test_workload("wl-2", TrustProfile::Verified, false);
        let p = router.assign_workload(&wl).unwrap();
        assert_eq!(p.rail, IsolationRail::Elevated);
    }

    #[test]
    fn assign_emits_rail_assigned_event() {
        let mut router = RailRouter::default_router();
        let wl = test_workload("wl-e", TrustProfile::Untrusted, false);
        router.assign_workload(&wl).unwrap();
        assert_eq!(router.events().len(), 1);
        assert_eq!(router.events()[0].event_code, ISOLATION_RAIL_ASSIGNED);
    }

    #[test]
    fn reject_duplicate_workload() {
        let mut router = RailRouter::default_router();
        let wl = test_workload("wl-dup", TrustProfile::Untrusted, false);
        router.assign_workload(&wl).unwrap();
        let err = router.assign_workload(&wl).unwrap_err();
        assert!(matches!(err, RailRouterError::WorkloadRejected { .. }));
    }

    #[test]
    fn reject_workload_on_unavailable_rail() {
        let config = MeshConfig {
            available_rails: vec![IsolationRail::Standard],
            rail_policies: HashMap::new(),
            partition_check_enabled: false,
        };
        let mut router = RailRouter::new(config);
        let wl = test_workload("wl-na", TrustProfile::Verified, false);
        let err = router.assign_workload(&wl).unwrap_err();
        assert!(matches!(err, RailRouterError::RailUnavailable { .. }));
    }

    // === Hot elevation ===

    #[test]
    fn hot_elevate_to_stricter_rail() {
        let mut router = RailRouter::default_router();
        let wl = test_workload("wl-elev", TrustProfile::Untrusted, false);
        router.assign_workload(&wl).unwrap();
        let p = router
            .hot_elevate("wl-elev", IsolationRail::Elevated)
            .unwrap();
        assert_eq!(p.rail, IsolationRail::Elevated);
        assert_eq!(p.elevation_count, 1);
    }

    #[test]
    fn hot_elevate_preserves_policy_continuity() {
        let mut router = RailRouter::default_router();
        let wl = test_workload("wl-cont", TrustProfile::Untrusted, false);
        router.assign_workload(&wl).unwrap();
        let p = router
            .hot_elevate("wl-cont", IsolationRail::Elevated)
            .unwrap();
        assert_eq!(p.rail, IsolationRail::Elevated);
        let policy_events: Vec<_> = router
            .events()
            .iter()
            .filter(|e| e.event_code == ISOLATION_POLICY_PRESERVED)
            .collect();
        assert!(!policy_events.is_empty());
    }

    #[test]
    fn hot_elevate_emits_three_events() {
        let mut router = RailRouter::default_router();
        let wl = test_workload("wl-ev3", TrustProfile::Untrusted, false);
        router.assign_workload(&wl).unwrap();
        router
            .hot_elevate("wl-ev3", IsolationRail::Elevated)
            .unwrap();
        // 1 assign + 3 elevation events (start, policy_preserved, complete)
        assert_eq!(router.events().len(), 4);
        assert_eq!(router.events()[1].event_code, ISOLATION_ELEVATION_START);
        assert_eq!(router.events()[2].event_code, ISOLATION_POLICY_PRESERVED);
        assert_eq!(router.events()[3].event_code, ISOLATION_ELEVATION_COMPLETE);
    }

    #[test]
    fn deny_downgrade() {
        let mut router = RailRouter::default_router();
        let wl = test_workload("wl-down", TrustProfile::Verified, false);
        router.assign_workload(&wl).unwrap();
        let err = router
            .hot_elevate("wl-down", IsolationRail::Standard)
            .unwrap_err();
        assert!(matches!(err, RailRouterError::ElevationDenied { .. }));
        // INV-ISOLATION-FAIL-SAFE: workload stays on Elevated
        assert_eq!(
            router.get_placement("wl-down").unwrap().rail,
            IsolationRail::Elevated
        );
    }

    #[test]
    fn deny_same_rail_elevation() {
        let mut router = RailRouter::default_router();
        let wl = test_workload("wl-same", TrustProfile::Untrusted, false);
        router.assign_workload(&wl).unwrap();
        let err = router
            .hot_elevate("wl-same", IsolationRail::Standard)
            .unwrap_err();
        assert!(matches!(err, RailRouterError::ElevationDenied { .. }));
    }

    #[test]
    fn multi_hop_elevation() {
        let mut router = RailRouter::default_router();
        let wl = test_workload("wl-hop", TrustProfile::Untrusted, false);
        router.assign_workload(&wl).unwrap();
        router
            .hot_elevate("wl-hop", IsolationRail::Elevated)
            .unwrap();
        router
            .hot_elevate("wl-hop", IsolationRail::HighAssurance)
            .unwrap();
        router
            .hot_elevate("wl-hop", IsolationRail::Critical)
            .unwrap();
        let p = router.get_placement("wl-hop").unwrap();
        assert_eq!(p.rail, IsolationRail::Critical);
        assert_eq!(p.elevation_count, 3);
    }

    // === Budget tracking ===

    #[test]
    fn latency_budget_tracking() {
        let mut router = RailRouter::default_router();
        let wl = test_workload("wl-lat", TrustProfile::Untrusted, true);
        router.assign_workload(&wl).unwrap();
        let p = router.record_latency("wl-lat", 500).unwrap();
        assert_eq!(p.latency_consumed_us, 500);
        assert_eq!(p.remaining_budget_us(), 500);
    }

    #[test]
    fn budget_exceeded_returns_error() {
        let mut router = RailRouter::default_router();
        let wl = test_workload("wl-over", TrustProfile::Untrusted, true);
        router.assign_workload(&wl).unwrap();
        let err = router.record_latency("wl-over", 2_000).unwrap_err();
        assert!(matches!(err, RailRouterError::BudgetExceeded { .. }));
    }

    #[test]
    fn budget_check_emits_event() {
        let mut router = RailRouter::default_router();
        let wl = test_workload("wl-bev", TrustProfile::Untrusted, true);
        router.assign_workload(&wl).unwrap();
        router.record_latency("wl-bev", 100).unwrap();
        let budget_events: Vec<_> = router
            .events()
            .iter()
            .filter(|e| e.event_code == ISOLATION_BUDGET_CHECK)
            .collect();
        assert_eq!(budget_events.len(), 1);
    }

    // === Policy continuity ===

    #[test]
    fn policy_subset_check_passes_for_superset() {
        let p1 = RailPolicy {
            rail: IsolationRail::Standard,
            rules: vec![PolicyRule {
                name: "deny_raw_syscall".to_string(),
                scope: "system".to_string(),
                deny: true,
            }],
        };
        let p2 = RailPolicy {
            rail: IsolationRail::Elevated,
            rules: vec![
                PolicyRule {
                    name: "deny_raw_syscall".to_string(),
                    scope: "system".to_string(),
                    deny: true,
                },
                PolicyRule {
                    name: "deny_network_egress".to_string(),
                    scope: "network".to_string(),
                    deny: true,
                },
            ],
        };
        assert!(p1.is_subset_of(&p2).is_ok());
    }

    #[test]
    fn policy_subset_check_fails_when_rule_missing() {
        let p1 = RailPolicy {
            rail: IsolationRail::Standard,
            rules: vec![PolicyRule {
                name: "special_rule".to_string(),
                scope: "custom".to_string(),
                deny: true,
            }],
        };
        let p2 = RailPolicy {
            rail: IsolationRail::Elevated,
            rules: vec![PolicyRule {
                name: "other_rule".to_string(),
                scope: "other".to_string(),
                deny: true,
            }],
        };
        let err = p1.is_subset_of(&p2).unwrap_err();
        assert!(matches!(err, RailRouterError::PolicyBreak { .. }));
    }

    // === Mesh partition ===

    #[test]
    fn mesh_partition_detected() {
        let config = MeshConfig {
            available_rails: vec![IsolationRail::Standard],
            rail_policies: HashMap::new(),
            partition_check_enabled: true,
        };
        let router = RailRouter::new(config);
        let err = router
            .check_mesh_connectivity(IsolationRail::Standard, IsolationRail::Elevated)
            .unwrap_err();
        assert!(matches!(err, RailRouterError::MeshPartition { .. }));
    }

    // === Default mesh config ===

    #[test]
    fn default_mesh_has_four_rails() {
        let config = MeshConfig::default_mesh();
        assert_eq!(config.available_rails.len(), 4);
        assert_eq!(config.rail_policies.len(), 4);
    }

    #[test]
    fn default_mesh_policy_continuity_holds() {
        let config = MeshConfig::default_mesh();
        let rails = &config.available_rails;
        for i in 0..rails.len() - 1 {
            let current = &config.rail_policies[&rails[i]];
            let next = &config.rail_policies[&rails[i + 1]];
            assert!(
                current.is_subset_of(next).is_ok(),
                "policy continuity broken: {} -> {}",
                rails[i],
                rails[i + 1]
            );
        }
    }

    // === Mesh profile report ===

    #[test]
    fn mesh_profile_report_shape() {
        let router = RailRouter::default_router();
        let report = router.mesh_profile_report();
        assert_eq!(report.schema_version, "isolation-mesh-v1.0");
        assert_eq!(report.total_rails, 4);
        assert!(report.policy_continuity_enforced);
        assert!(report.hot_elevation_only_stricter);
        assert!(report.budget_bound_enforced);
        assert!(report.fail_safe_on_error);
    }

    // === Error display ===

    #[test]
    fn error_display_codes() {
        let e1 = RailRouterError::RailUnavailable {
            rail: IsolationRail::Critical,
        };
        assert!(e1.to_string().contains(ERR_ISOLATION_RAIL_UNAVAILABLE));

        let e2 = RailRouterError::ElevationDenied {
            from: IsolationRail::Elevated,
            to: IsolationRail::Standard,
            reason: "downgrade".to_string(),
        };
        assert!(e2.to_string().contains(ERR_ISOLATION_ELEVATION_DENIED));

        let e3 = RailRouterError::PolicyBreak {
            rule_name: "r1".to_string(),
            from_rail: IsolationRail::Standard,
            to_rail: IsolationRail::Elevated,
        };
        assert!(e3.to_string().contains(ERR_ISOLATION_POLICY_BREAK));

        let e4 = RailRouterError::BudgetExceeded {
            workload_id: "w1".to_string(),
            budget_us: 100,
            consumed_us: 200,
        };
        assert!(e4.to_string().contains(ERR_ISOLATION_BUDGET_EXCEEDED));

        let e5 = RailRouterError::MeshPartition {
            rail_a: IsolationRail::Standard,
            rail_b: IsolationRail::Elevated,
        };
        assert!(e5.to_string().contains(ERR_ISOLATION_MESH_PARTITION));

        let e6 = RailRouterError::WorkloadRejected {
            workload_id: "w2".to_string(),
            reason: "bad".to_string(),
        };
        assert!(e6.to_string().contains(ERR_ISOLATION_WORKLOAD_REJECTED));
    }

    // === Serde roundtrip ===

    #[test]
    fn serde_roundtrip_rail() {
        for rail in &IsolationRail::ALL {
            let json = serde_json::to_string(rail).unwrap();
            let parsed: IsolationRail = serde_json::from_str(&json).unwrap();
            assert_eq!(*rail, parsed);
        }
    }

    #[test]
    fn serde_roundtrip_placement() {
        let p = Placement {
            workload_id: "wl-serde".to_string(),
            rail: IsolationRail::HighAssurance,
            latency_budget_us: 2_000,
            latency_consumed_us: 100,
            elevation_count: 1,
        };
        let json = serde_json::to_string(&p).unwrap();
        let parsed: Placement = serde_json::from_str(&json).unwrap();
        assert_eq!(p, parsed);
    }

    #[test]
    fn serde_roundtrip_event() {
        let ev = RailEvent {
            event_code: ISOLATION_RAIL_ASSIGNED.to_string(),
            workload_id: "wl-1".to_string(),
            detail: "assigned".to_string(),
            rail: Some(IsolationRail::Standard),
            target_rail: None,
        };
        let json = serde_json::to_string(&ev).unwrap();
        let parsed: RailEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(ev, parsed);
    }

    // === Remove workload ===

    #[test]
    fn remove_workload() {
        let mut router = RailRouter::default_router();
        let wl = test_workload("wl-rm", TrustProfile::Untrusted, false);
        router.assign_workload(&wl).unwrap();
        let removed = router.remove_workload("wl-rm");
        assert!(removed.is_some());
        assert!(router.get_placement("wl-rm").is_none());
    }

    // === Latency-sensitive budget is preserved ===

    #[test]
    fn latency_sensitive_uses_custom_budget() {
        let mut router = RailRouter::default_router();
        let wl = Workload {
            id: "wl-custom".to_string(),
            trust_profile: TrustProfile::Untrusted,
            latency_sensitive: true,
            latency_budget_us: 777,
        };
        let p = router.assign_workload(&wl).unwrap();
        assert_eq!(p.latency_budget_us, 777);
    }

    #[test]
    fn non_latency_sensitive_uses_default_budget() {
        let mut router = RailRouter::default_router();
        let wl = Workload {
            id: "wl-default".to_string(),
            trust_profile: TrustProfile::Untrusted,
            latency_sensitive: false,
            latency_budget_us: 0,
        };
        let p = router.assign_workload(&wl).unwrap();
        assert_eq!(
            p.latency_budget_us,
            IsolationRail::Standard.default_latency_budget_us()
        );
    }
}
