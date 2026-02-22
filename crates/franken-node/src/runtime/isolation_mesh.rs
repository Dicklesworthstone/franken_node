//! bd-gad3: Adaptive multi-rail isolation mesh with hot-elevation policy.
//!
//! Provides a runtime mesh of isolation rails at varying strictness levels.
//! Workloads can be promoted ("elevated") to stricter rails at runtime without
//! losing policy continuity, but can never be demoted. Latency-sensitive trusted
//! workloads remain on high-performance rails within their configured budget.
//!
//! # Invariants
//!
//! - INV-MESH-MONOTONIC-ELEVATION: workload isolation level can only increase
//! - INV-MESH-POLICY-CONTINUITY: policy envelope preserved across elevation
//! - INV-MESH-ATOMIC-TRANSITION: no inconsistent policy during elevation
//! - INV-MESH-LATENCY-BUDGET: elevation respects workload latency budget
//! - INV-MESH-DETERMINISTIC-TOPOLOGY: BTreeMap ensures deterministic ordering
//! - INV-MESH-FAIL-CLOSED: unknown rails, invalid policies, demotions fail closed

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;

/// Schema version for isolation mesh reports.
pub const SCHEMA_VERSION: &str = "isolation-mesh-v1.0";

// ---------------------------------------------------------------------------
// Event codes
// ---------------------------------------------------------------------------
pub mod event_codes {
    /// Workload placed on initial rail.
    pub const MESH_001: &str = "MESH_001";
    /// Hot-elevation completed successfully.
    pub const MESH_002: &str = "MESH_002";
    /// Elevation denied: policy violation.
    pub const MESH_003: &str = "MESH_003";
    /// Elevation denied: latency budget exceeded.
    pub const MESH_004: &str = "MESH_004";
    /// Workload removed from mesh.
    pub const MESH_005: &str = "MESH_005";
    /// Mesh topology reloaded.
    pub const MESH_006: &str = "MESH_006";
    /// Demotion attempt blocked.
    pub const MESH_007: &str = "MESH_007";
}

// ---------------------------------------------------------------------------
// Error codes
// ---------------------------------------------------------------------------
pub mod error_codes {
    pub const ERR_MESH_UNKNOWN_RAIL: &str = "ERR_MESH_UNKNOWN_RAIL";
    pub const ERR_MESH_UNKNOWN_WORKLOAD: &str = "ERR_MESH_UNKNOWN_WORKLOAD";
    pub const ERR_MESH_ELEVATION_DENIED: &str = "ERR_MESH_ELEVATION_DENIED";
    pub const ERR_MESH_DEMOTION_FORBIDDEN: &str = "ERR_MESH_DEMOTION_FORBIDDEN";
    pub const ERR_MESH_LATENCY_EXCEEDED: &str = "ERR_MESH_LATENCY_EXCEEDED";
    pub const ERR_MESH_RAIL_AT_CAPACITY: &str = "ERR_MESH_RAIL_AT_CAPACITY";
    pub const ERR_MESH_DUPLICATE_WORKLOAD: &str = "ERR_MESH_DUPLICATE_WORKLOAD";
    pub const ERR_MESH_INVALID_TOPOLOGY: &str = "ERR_MESH_INVALID_TOPOLOGY";
}

// ---------------------------------------------------------------------------
// Invariants
// ---------------------------------------------------------------------------
pub mod invariants {
    pub const INV_MESH_MONOTONIC_ELEVATION: &str = "INV-MESH-MONOTONIC-ELEVATION";
    pub const INV_MESH_POLICY_CONTINUITY: &str = "INV-MESH-POLICY-CONTINUITY";
    pub const INV_MESH_ATOMIC_TRANSITION: &str = "INV-MESH-ATOMIC-TRANSITION";
    pub const INV_MESH_LATENCY_BUDGET: &str = "INV-MESH-LATENCY-BUDGET";
    pub const INV_MESH_DETERMINISTIC_TOPOLOGY: &str = "INV-MESH-DETERMINISTIC-TOPOLOGY";
    pub const INV_MESH_FAIL_CLOSED: &str = "INV-MESH-FAIL-CLOSED";
}

// ---------------------------------------------------------------------------
// IsolationRailLevel: ordered from least to most strict
// ---------------------------------------------------------------------------
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum IsolationRailLevel {
    /// Default shared-memory rail -- lowest isolation.
    Shared = 0,
    /// Separate process boundary.
    ProcessIsolated = 1,
    /// Sandboxed execution with capability filtering.
    SandboxIsolated = 2,
    /// Hardware-backed isolation (TEE / enclave).
    HardwareIsolated = 3,
}

impl IsolationRailLevel {
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Shared => "shared",
            Self::ProcessIsolated => "process_isolated",
            Self::SandboxIsolated => "sandbox_isolated",
            Self::HardwareIsolated => "hardware_isolated",
        }
    }

    #[must_use]
    pub fn strictness(&self) -> u8 {
        *self as u8
    }

    /// Returns `true` when `target` is strictly more isolated than `self`.
    #[must_use]
    pub fn can_elevate_to(&self, target: &Self) -> bool {
        target.strictness() > self.strictness()
    }

    /// All levels in order of increasing strictness.
    #[must_use]
    pub fn all() -> &'static [Self] {
        &[
            Self::Shared,
            Self::ProcessIsolated,
            Self::SandboxIsolated,
            Self::HardwareIsolated,
        ]
    }
}

impl fmt::Display for IsolationRailLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// ---------------------------------------------------------------------------
// IsolationRail: a named rail in the mesh
// ---------------------------------------------------------------------------
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IsolationRail {
    pub rail_id: String,
    pub level: IsolationRailLevel,
    /// Maximum additional latency (in microseconds) incurred by this rail.
    pub latency_overhead_us: u64,
    /// Maximum number of workloads that can run concurrently on this rail.
    pub capacity: usize,
}

// ---------------------------------------------------------------------------
// ElevationPolicy
// ---------------------------------------------------------------------------
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ElevationPolicy {
    /// Whether elevation is permitted for the workload at all.
    pub elevation_allowed: bool,
    /// Maximum target level the workload may be elevated to.
    pub max_target_level: IsolationRailLevel,
    /// Whether the workload's latency budget must be preserved during promotion.
    pub preserve_latency_budget: bool,
    /// Latency budget in microseconds -- elevation is rejected if target rail
    /// overhead would exceed this.
    pub latency_budget_us: u64,
}

impl ElevationPolicy {
    /// Check whether this policy permits elevation to `target_level` with
    /// `target_latency_overhead_us`.
    pub fn permits_elevation(
        &self,
        current_level: &IsolationRailLevel,
        target_level: &IsolationRailLevel,
        target_latency_overhead_us: u64,
    ) -> Result<(), MeshError> {
        // INV-MESH-FAIL-CLOSED: elevation must be explicitly allowed
        if !self.elevation_allowed {
            return Err(MeshError::ElevationDenied {
                reason: "elevation_allowed=false".to_string(),
            });
        }

        // INV-MESH-MONOTONIC-ELEVATION: only upward transitions
        if !current_level.can_elevate_to(target_level) {
            if target_level == current_level {
                return Err(MeshError::ElevationDenied {
                    reason: format!(
                        "already at level {}",
                        current_level.as_str()
                    ),
                });
            }
            return Err(MeshError::DemotionForbidden {
                current: *current_level,
                requested: *target_level,
            });
        }

        // Check against max target level
        if target_level.strictness() > self.max_target_level.strictness() {
            return Err(MeshError::ElevationDenied {
                reason: format!(
                    "target {} exceeds max_target_level {}",
                    target_level.as_str(),
                    self.max_target_level.as_str()
                ),
            });
        }

        // INV-MESH-LATENCY-BUDGET: respect latency budget
        if self.preserve_latency_budget && target_latency_overhead_us > self.latency_budget_us {
            return Err(MeshError::LatencyExceeded {
                budget_us: self.latency_budget_us,
                actual_us: target_latency_overhead_us,
            });
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// MeshEvent
// ---------------------------------------------------------------------------
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MeshEvent {
    pub event_code: String,
    pub workload_id: String,
    pub rail_id: String,
    pub now_ms: u64,
    pub detail: String,
}

// ---------------------------------------------------------------------------
// MeshError
// ---------------------------------------------------------------------------
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MeshError {
    UnknownRail { rail_id: String },
    UnknownWorkload { workload_id: String },
    ElevationDenied { reason: String },
    DemotionForbidden { current: IsolationRailLevel, requested: IsolationRailLevel },
    LatencyExceeded { budget_us: u64, actual_us: u64 },
    RailAtCapacity { rail_id: String, capacity: usize },
    DuplicateWorkload { workload_id: String },
    InvalidTopology { detail: String },
}

impl MeshError {
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::UnknownRail { .. } => error_codes::ERR_MESH_UNKNOWN_RAIL,
            Self::UnknownWorkload { .. } => error_codes::ERR_MESH_UNKNOWN_WORKLOAD,
            Self::ElevationDenied { .. } => error_codes::ERR_MESH_ELEVATION_DENIED,
            Self::DemotionForbidden { .. } => error_codes::ERR_MESH_DEMOTION_FORBIDDEN,
            Self::LatencyExceeded { .. } => error_codes::ERR_MESH_LATENCY_EXCEEDED,
            Self::RailAtCapacity { .. } => error_codes::ERR_MESH_RAIL_AT_CAPACITY,
            Self::DuplicateWorkload { .. } => error_codes::ERR_MESH_DUPLICATE_WORKLOAD,
            Self::InvalidTopology { .. } => error_codes::ERR_MESH_INVALID_TOPOLOGY,
        }
    }
}

impl fmt::Display for MeshError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownRail { rail_id } => {
                write!(f, "{}: rail_id={rail_id}", self.code())
            }
            Self::UnknownWorkload { workload_id } => {
                write!(f, "{}: workload_id={workload_id}", self.code())
            }
            Self::ElevationDenied { reason } => {
                write!(f, "{}: {reason}", self.code())
            }
            Self::DemotionForbidden { current, requested } => {
                write!(
                    f,
                    "{}: current={} requested={}",
                    self.code(),
                    current.as_str(),
                    requested.as_str()
                )
            }
            Self::LatencyExceeded {
                budget_us,
                actual_us,
            } => {
                write!(
                    f,
                    "{}: budget_us={budget_us} actual_us={actual_us}",
                    self.code()
                )
            }
            Self::RailAtCapacity { rail_id, capacity } => {
                write!(
                    f,
                    "{}: rail_id={rail_id} capacity={capacity}",
                    self.code()
                )
            }
            Self::DuplicateWorkload { workload_id } => {
                write!(f, "{}: workload_id={workload_id}", self.code())
            }
            Self::InvalidTopology { detail } => {
                write!(f, "{}: {detail}", self.code())
            }
        }
    }
}

impl std::error::Error for MeshError {}

// ---------------------------------------------------------------------------
// RailState: per-rail runtime bookkeeping
// ---------------------------------------------------------------------------
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RailState {
    pub rail_id: String,
    pub active_count: usize,
    pub total_placed: u64,
    pub total_elevated_in: u64,
    pub total_elevated_out: u64,
    pub total_removed: u64,
}

impl RailState {
    fn new(rail_id: &str) -> Self {
        Self {
            rail_id: rail_id.to_string(),
            active_count: 0,
            total_placed: 0,
            total_elevated_in: 0,
            total_elevated_out: 0,
            total_removed: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// ElevationRecord: audit trail entry for a single elevation
// ---------------------------------------------------------------------------
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ElevationRecord {
    pub from_rail_id: String,
    pub from_level: IsolationRailLevel,
    pub to_rail_id: String,
    pub to_level: IsolationRailLevel,
    pub at_ms: u64,
}

// ---------------------------------------------------------------------------
// WorkloadPlacement: current rail + full elevation history
// ---------------------------------------------------------------------------
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkloadPlacement {
    pub workload_id: String,
    pub current_rail_id: String,
    pub current_level: IsolationRailLevel,
    pub policy: ElevationPolicy,
    pub placed_at_ms: u64,
    pub elevation_history: Vec<ElevationRecord>,
}

// ---------------------------------------------------------------------------
// MeshTopology: the configured set of rails
// ---------------------------------------------------------------------------
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MeshTopology {
    /// Rails keyed by rail_id, BTreeMap for INV-MESH-DETERMINISTIC-TOPOLOGY.
    pub rails: BTreeMap<String, IsolationRail>,
}

impl MeshTopology {
    /// Validate topology invariants.
    pub fn validate(&self) -> Result<(), MeshError> {
        if self.rails.is_empty() {
            return Err(MeshError::InvalidTopology {
                detail: "topology must contain at least one rail".to_string(),
            });
        }
        for (id, rail) in &self.rails {
            if id != &rail.rail_id {
                return Err(MeshError::InvalidTopology {
                    detail: format!(
                        "rail_id mismatch: key={id} value={}",
                        rail.rail_id
                    ),
                });
            }
            if rail.capacity == 0 {
                return Err(MeshError::InvalidTopology {
                    detail: format!("rail {} capacity must be > 0", id),
                });
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// IsolationMesh: the core runtime mesh
// ---------------------------------------------------------------------------
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IsolationMesh {
    topology: MeshTopology,
    /// Workloads keyed by workload_id. BTreeMap for deterministic ordering.
    workloads: BTreeMap<String, WorkloadPlacement>,
    /// Per-rail state keyed by rail_id.
    rail_states: BTreeMap<String, RailState>,
    /// Structured event log.
    events: Vec<MeshEvent>,
    /// Monotonic sequence for event ordering.
    event_seq: u64,
}

impl IsolationMesh {
    /// Create a new mesh with the given topology.
    pub fn new(topology: MeshTopology) -> Result<Self, MeshError> {
        topology.validate()?;
        let mut rail_states = BTreeMap::new();
        for rail_id in topology.rails.keys() {
            rail_states.insert(rail_id.clone(), RailState::new(rail_id));
        }
        Ok(Self {
            topology,
            workloads: BTreeMap::new(),
            rail_states,
            events: Vec::new(),
            event_seq: 0,
        })
    }

    /// Read-only access to current topology.
    #[must_use]
    pub fn topology(&self) -> &MeshTopology {
        &self.topology
    }

    /// Read-only access to workload placements.
    #[must_use]
    pub fn workloads(&self) -> &BTreeMap<String, WorkloadPlacement> {
        &self.workloads
    }

    /// Read-only access to per-rail states.
    #[must_use]
    pub fn rail_states(&self) -> &BTreeMap<String, RailState> {
        &self.rail_states
    }

    /// Full event log.
    #[must_use]
    pub fn events(&self) -> &[MeshEvent] {
        &self.events
    }

    // -----------------------------------------------------------------------
    // Place a workload on an initial rail
    // -----------------------------------------------------------------------
    pub fn place_workload(
        &mut self,
        workload_id: &str,
        rail_id: &str,
        policy: ElevationPolicy,
        now_ms: u64,
    ) -> Result<WorkloadPlacement, MeshError> {
        // Fail-closed: unknown rail
        let rail = self.topology.rails.get(rail_id).ok_or_else(|| {
            MeshError::UnknownRail {
                rail_id: rail_id.to_string(),
            }
        })?;

        // Duplicate workload
        if self.workloads.contains_key(workload_id) {
            return Err(MeshError::DuplicateWorkload {
                workload_id: workload_id.to_string(),
            });
        }

        // Rail capacity
        let state = self.rail_states.get(rail_id).ok_or_else(|| {
            MeshError::UnknownRail {
                rail_id: rail_id.to_string(),
            }
        })?;
        if state.active_count >= rail.capacity {
            return Err(MeshError::RailAtCapacity {
                rail_id: rail_id.to_string(),
                capacity: rail.capacity,
            });
        }

        let placement = WorkloadPlacement {
            workload_id: workload_id.to_string(),
            current_rail_id: rail_id.to_string(),
            current_level: rail.level,
            policy,
            placed_at_ms: now_ms,
            elevation_history: Vec::new(),
        };

        self.workloads
            .insert(workload_id.to_string(), placement.clone());

        let rs = self
            .rail_states
            .get_mut(rail_id)
            .expect("rail state must exist");
        rs.active_count = rs.active_count.saturating_add(1);
        rs.total_placed = rs.total_placed.saturating_add(1);

        self.push_event(
            event_codes::MESH_001,
            workload_id,
            rail_id,
            now_ms,
            format!("level={}", rail.level.as_str()),
        );

        Ok(placement)
    }

    // -----------------------------------------------------------------------
    // Hot-elevate a workload to a stricter rail
    // -----------------------------------------------------------------------
    pub fn elevate_workload(
        &mut self,
        workload_id: &str,
        target_rail_id: &str,
        now_ms: u64,
    ) -> Result<WorkloadPlacement, MeshError> {
        // Fail-closed: unknown target rail
        let target_rail =
            self.topology.rails.get(target_rail_id).ok_or_else(|| {
                MeshError::UnknownRail {
                    rail_id: target_rail_id.to_string(),
                }
            })?;
        let target_level = target_rail.level;
        let target_latency = target_rail.latency_overhead_us;
        let target_capacity = target_rail.capacity;

        // Fail-closed: unknown workload
        let placement =
            self.workloads.get(workload_id).ok_or_else(|| {
                MeshError::UnknownWorkload {
                    workload_id: workload_id.to_string(),
                }
            })?;
        let current_level = placement.current_level;
        let old_rail_id = placement.current_rail_id.clone();

        // INV-MESH-MONOTONIC-ELEVATION + INV-MESH-POLICY-CONTINUITY + INV-MESH-LATENCY-BUDGET
        // Check demotion before policy check so we emit MESH_007 specifically
        if target_level < current_level {
            self.push_event(
                event_codes::MESH_007,
                workload_id,
                target_rail_id,
                now_ms,
                format!(
                    "current={} requested={}",
                    current_level.as_str(),
                    target_level.as_str()
                ),
            );
            return Err(MeshError::DemotionForbidden {
                current: current_level,
                requested: target_level,
            });
        }

        // Policy check
        if let Err(e) = placement.policy.permits_elevation(
            &current_level,
            &target_level,
            target_latency,
        ) {
            let event_code = match &e {
                MeshError::LatencyExceeded { .. } => event_codes::MESH_004,
                _ => event_codes::MESH_003,
            };
            self.push_event(
                event_code,
                workload_id,
                target_rail_id,
                now_ms,
                format!("{e}"),
            );
            return Err(e);
        }

        // Target rail capacity
        let target_state = self.rail_states.get(target_rail_id).ok_or_else(|| {
            MeshError::UnknownRail {
                rail_id: target_rail_id.to_string(),
            }
        })?;
        if target_state.active_count >= target_capacity {
            return Err(MeshError::RailAtCapacity {
                rail_id: target_rail_id.to_string(),
                capacity: target_capacity,
            });
        }

        // INV-MESH-ATOMIC-TRANSITION: perform the transition
        // Decrement old rail
        if let Some(old_state) = self.rail_states.get_mut(&old_rail_id) {
            old_state.active_count = old_state.active_count.saturating_sub(1);
            old_state.total_elevated_out = old_state.total_elevated_out.saturating_add(1);
        }

        // Increment new rail
        let new_state = self
            .rail_states
            .get_mut(target_rail_id)
            .expect("target rail state must exist");
        new_state.active_count = new_state.active_count.saturating_add(1);
        new_state.total_elevated_in = new_state.total_elevated_in.saturating_add(1);

        // Update workload placement -- INV-MESH-POLICY-CONTINUITY: policy preserved
        let placement = self
            .workloads
            .get_mut(workload_id)
            .expect("workload must exist");
        placement.elevation_history.push(ElevationRecord {
            from_rail_id: old_rail_id,
            from_level: current_level,
            to_rail_id: target_rail_id.to_string(),
            to_level: target_level,
            at_ms: now_ms,
        });
        placement.current_rail_id = target_rail_id.to_string();
        placement.current_level = target_level;

        self.push_event(
            event_codes::MESH_002,
            workload_id,
            target_rail_id,
            now_ms,
            format!(
                "from={} to={}",
                current_level.as_str(),
                target_level.as_str()
            ),
        );

        Ok(placement.clone())
    }

    // -----------------------------------------------------------------------
    // Remove a workload from the mesh
    // -----------------------------------------------------------------------
    pub fn remove_workload(
        &mut self,
        workload_id: &str,
        now_ms: u64,
    ) -> Result<WorkloadPlacement, MeshError> {
        let placement = self.workloads.remove(workload_id).ok_or_else(|| {
            MeshError::UnknownWorkload {
                workload_id: workload_id.to_string(),
            }
        })?;

        if let Some(rs) = self.rail_states.get_mut(&placement.current_rail_id) {
            rs.active_count = rs.active_count.saturating_sub(1);
            rs.total_removed = rs.total_removed.saturating_add(1);
        }

        self.push_event(
            event_codes::MESH_005,
            workload_id,
            &placement.current_rail_id,
            now_ms,
            format!("level={}", placement.current_level.as_str()),
        );

        Ok(placement)
    }

    // -----------------------------------------------------------------------
    // Reload topology at runtime
    // -----------------------------------------------------------------------
    pub fn reload_topology(
        &mut self,
        new_topology: MeshTopology,
        now_ms: u64,
    ) -> Result<(), MeshError> {
        new_topology.validate()?;

        // Ensure all rails that currently host workloads still exist
        for (wid, placement) in &self.workloads {
            if !new_topology.rails.contains_key(&placement.current_rail_id) {
                return Err(MeshError::InvalidTopology {
                    detail: format!(
                        "rail {} still hosts workload {wid}",
                        placement.current_rail_id
                    ),
                });
            }
        }

        // Add state for any new rails; keep state for existing ones
        for rail_id in new_topology.rails.keys() {
            self.rail_states
                .entry(rail_id.clone())
                .or_insert_with(|| RailState::new(rail_id));
        }

        self.topology = new_topology;

        self.push_event(
            event_codes::MESH_006,
            "topology",
            "all",
            now_ms,
            format!("rails={}", self.topology.rails.len()),
        );

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------
    fn push_event(
        &mut self,
        code: &str,
        workload_id: &str,
        rail_id: &str,
        now_ms: u64,
        detail: String,
    ) {
        self.event_seq = self.event_seq.saturating_add(1);
        self.events.push(MeshEvent {
            event_code: code.to_string(),
            workload_id: workload_id.to_string(),
            rail_id: rail_id.to_string(),
            now_ms,
            detail,
        });
    }
}

// ===========================================================================
// Tests
// ===========================================================================
#[cfg(test)]
mod tests {
    use super::*;

    fn shared_rail() -> IsolationRail {
        IsolationRail {
            rail_id: "shared-1".to_string(),
            level: IsolationRailLevel::Shared,
            latency_overhead_us: 10,
            capacity: 4,
        }
    }

    fn process_rail() -> IsolationRail {
        IsolationRail {
            rail_id: "proc-1".to_string(),
            level: IsolationRailLevel::ProcessIsolated,
            latency_overhead_us: 50,
            capacity: 4,
        }
    }

    fn sandbox_rail() -> IsolationRail {
        IsolationRail {
            rail_id: "sandbox-1".to_string(),
            level: IsolationRailLevel::SandboxIsolated,
            latency_overhead_us: 200,
            capacity: 2,
        }
    }

    fn hw_rail() -> IsolationRail {
        IsolationRail {
            rail_id: "hw-1".to_string(),
            level: IsolationRailLevel::HardwareIsolated,
            latency_overhead_us: 500,
            capacity: 1,
        }
    }

    fn test_topology() -> MeshTopology {
        let mut rails = BTreeMap::new();
        for r in [shared_rail(), process_rail(), sandbox_rail(), hw_rail()] {
            rails.insert(r.rail_id.clone(), r);
        }
        MeshTopology { rails }
    }

    fn permissive_policy() -> ElevationPolicy {
        ElevationPolicy {
            elevation_allowed: true,
            max_target_level: IsolationRailLevel::HardwareIsolated,
            preserve_latency_budget: false,
            latency_budget_us: 0,
        }
    }

    fn budget_policy(budget_us: u64) -> ElevationPolicy {
        ElevationPolicy {
            elevation_allowed: true,
            max_target_level: IsolationRailLevel::HardwareIsolated,
            preserve_latency_budget: true,
            latency_budget_us: budget_us,
        }
    }

    fn no_elevation_policy() -> ElevationPolicy {
        ElevationPolicy {
            elevation_allowed: false,
            max_target_level: IsolationRailLevel::Shared,
            preserve_latency_budget: false,
            latency_budget_us: 0,
        }
    }

    // --- topology validation ---

    #[test]
    fn empty_topology_rejected() {
        let topo = MeshTopology {
            rails: BTreeMap::new(),
        };
        let err = IsolationMesh::new(topo).expect_err("empty topology");
        assert_eq!(err.code(), error_codes::ERR_MESH_INVALID_TOPOLOGY);
    }

    #[test]
    fn zero_capacity_rail_rejected() {
        let mut rails = BTreeMap::new();
        rails.insert(
            "r".to_string(),
            IsolationRail {
                rail_id: "r".to_string(),
                level: IsolationRailLevel::Shared,
                latency_overhead_us: 0,
                capacity: 0,
            },
        );
        let topo = MeshTopology { rails };
        let err = IsolationMesh::new(topo).expect_err("zero capacity");
        assert_eq!(err.code(), error_codes::ERR_MESH_INVALID_TOPOLOGY);
    }

    #[test]
    fn mismatched_rail_id_rejected() {
        let mut rails = BTreeMap::new();
        rails.insert(
            "wrong-key".to_string(),
            IsolationRail {
                rail_id: "right-id".to_string(),
                level: IsolationRailLevel::Shared,
                latency_overhead_us: 0,
                capacity: 1,
            },
        );
        let topo = MeshTopology { rails };
        let err = IsolationMesh::new(topo).expect_err("mismatch");
        assert_eq!(err.code(), error_codes::ERR_MESH_INVALID_TOPOLOGY);
    }

    // --- place workload ---

    #[test]
    fn place_workload_happy_path() {
        let mut mesh = IsolationMesh::new(test_topology()).expect("mesh");
        let p = mesh
            .place_workload("w1", "shared-1", permissive_policy(), 1)
            .expect("place");
        assert_eq!(p.current_rail_id, "shared-1");
        assert_eq!(p.current_level, IsolationRailLevel::Shared);
        assert!(p.elevation_history.is_empty());

        let rs = mesh.rail_states().get("shared-1").unwrap();
        assert_eq!(rs.active_count, 1);
        assert_eq!(rs.total_placed, 1);
    }

    #[test]
    fn place_on_unknown_rail_fails_closed() {
        let mut mesh = IsolationMesh::new(test_topology()).expect("mesh");
        let err = mesh
            .place_workload("w1", "nonexistent", permissive_policy(), 1)
            .expect_err("unknown rail");
        assert_eq!(err.code(), error_codes::ERR_MESH_UNKNOWN_RAIL);
    }

    #[test]
    fn duplicate_workload_rejected() {
        let mut mesh = IsolationMesh::new(test_topology()).expect("mesh");
        mesh.place_workload("w1", "shared-1", permissive_policy(), 1)
            .expect("first");
        let err = mesh
            .place_workload("w1", "proc-1", permissive_policy(), 2)
            .expect_err("dup");
        assert_eq!(err.code(), error_codes::ERR_MESH_DUPLICATE_WORKLOAD);
    }

    #[test]
    fn rail_at_capacity_rejected() {
        let mut rails = BTreeMap::new();
        rails.insert(
            "tiny".to_string(),
            IsolationRail {
                rail_id: "tiny".to_string(),
                level: IsolationRailLevel::Shared,
                latency_overhead_us: 0,
                capacity: 1,
            },
        );
        let mut mesh = IsolationMesh::new(MeshTopology { rails }).expect("mesh");
        mesh.place_workload("w1", "tiny", permissive_policy(), 1)
            .expect("first");
        let err = mesh
            .place_workload("w2", "tiny", permissive_policy(), 2)
            .expect_err("at capacity");
        assert_eq!(err.code(), error_codes::ERR_MESH_RAIL_AT_CAPACITY);
    }

    // --- hot elevation ---

    #[test]
    fn elevate_shared_to_process_succeeds() {
        let mut mesh = IsolationMesh::new(test_topology()).expect("mesh");
        mesh.place_workload("w1", "shared-1", permissive_policy(), 1)
            .expect("place");
        let p = mesh.elevate_workload("w1", "proc-1", 2).expect("elevate");
        assert_eq!(p.current_rail_id, "proc-1");
        assert_eq!(p.current_level, IsolationRailLevel::ProcessIsolated);
        assert_eq!(p.elevation_history.len(), 1);

        // Old rail decremented, new rail incremented
        assert_eq!(mesh.rail_states().get("shared-1").unwrap().active_count, 0);
        assert_eq!(mesh.rail_states().get("proc-1").unwrap().active_count, 1);
    }

    #[test]
    fn multi_step_elevation_preserves_history() {
        let mut mesh = IsolationMesh::new(test_topology()).expect("mesh");
        mesh.place_workload("w1", "shared-1", permissive_policy(), 1)
            .expect("place");
        mesh.elevate_workload("w1", "proc-1", 2).expect("step 1");
        let p = mesh
            .elevate_workload("w1", "sandbox-1", 3)
            .expect("step 2");
        assert_eq!(p.elevation_history.len(), 2);
        assert_eq!(p.current_level, IsolationRailLevel::SandboxIsolated);
    }

    #[test]
    fn demotion_forbidden_fails_closed() {
        let mut mesh = IsolationMesh::new(test_topology()).expect("mesh");
        mesh.place_workload("w1", "proc-1", permissive_policy(), 1)
            .expect("place");
        let err = mesh
            .elevate_workload("w1", "shared-1", 2)
            .expect_err("demotion");
        assert_eq!(err.code(), error_codes::ERR_MESH_DEMOTION_FORBIDDEN);

        // MESH_007 event emitted
        let has_007 = mesh
            .events()
            .iter()
            .any(|e| e.event_code == event_codes::MESH_007);
        assert!(has_007, "MESH_007 event must be emitted for demotion");
    }

    #[test]
    fn elevation_denied_when_policy_disallows() {
        let mut mesh = IsolationMesh::new(test_topology()).expect("mesh");
        mesh.place_workload("w1", "shared-1", no_elevation_policy(), 1)
            .expect("place");
        let err = mesh
            .elevate_workload("w1", "proc-1", 2)
            .expect_err("denied");
        assert_eq!(err.code(), error_codes::ERR_MESH_ELEVATION_DENIED);
    }

    #[test]
    fn latency_budget_blocks_expensive_elevation() {
        let mut mesh = IsolationMesh::new(test_topology()).expect("mesh");
        // Budget 30us -- process rail costs 50us
        mesh.place_workload("w1", "shared-1", budget_policy(30), 1)
            .expect("place");
        let err = mesh
            .elevate_workload("w1", "proc-1", 2)
            .expect_err("latency exceeded");
        assert_eq!(err.code(), error_codes::ERR_MESH_LATENCY_EXCEEDED);
    }

    #[test]
    fn latency_budget_allows_cheap_elevation() {
        let mut mesh = IsolationMesh::new(test_topology()).expect("mesh");
        // Budget 100us -- process rail costs 50us
        mesh.place_workload("w1", "shared-1", budget_policy(100), 1)
            .expect("place");
        let p = mesh.elevate_workload("w1", "proc-1", 2).expect("ok");
        assert_eq!(p.current_level, IsolationRailLevel::ProcessIsolated);
    }

    #[test]
    fn elevate_to_same_level_denied() {
        let mut mesh = IsolationMesh::new(test_topology()).expect("mesh");
        mesh.place_workload("w1", "shared-1", permissive_policy(), 1)
            .expect("place");
        let err = mesh
            .elevate_workload("w1", "shared-1", 2)
            .expect_err("same level");
        assert_eq!(err.code(), error_codes::ERR_MESH_ELEVATION_DENIED);
    }

    #[test]
    fn elevate_unknown_workload_fails_closed() {
        let mut mesh = IsolationMesh::new(test_topology()).expect("mesh");
        let err = mesh
            .elevate_workload("ghost", "proc-1", 1)
            .expect_err("unknown workload");
        assert_eq!(err.code(), error_codes::ERR_MESH_UNKNOWN_WORKLOAD);
    }

    #[test]
    fn elevate_to_unknown_rail_fails_closed() {
        let mut mesh = IsolationMesh::new(test_topology()).expect("mesh");
        mesh.place_workload("w1", "shared-1", permissive_policy(), 1)
            .expect("place");
        let err = mesh
            .elevate_workload("w1", "nowhere", 2)
            .expect_err("unknown rail");
        assert_eq!(err.code(), error_codes::ERR_MESH_UNKNOWN_RAIL);
    }

    #[test]
    fn elevation_blocked_when_target_rail_full() {
        let mut mesh = IsolationMesh::new(test_topology()).expect("mesh");
        // hw-1 has capacity 1
        mesh.place_workload("w1", "proc-1", permissive_policy(), 1)
            .expect("place w1");
        mesh.place_workload("w2", "shared-1", permissive_policy(), 2)
            .expect("place w2");
        mesh.elevate_workload("w1", "hw-1", 3).expect("w1 to hw");
        let err = mesh
            .elevate_workload("w2", "hw-1", 4)
            .expect_err("hw full");
        assert_eq!(err.code(), error_codes::ERR_MESH_RAIL_AT_CAPACITY);
    }

    // --- remove workload ---

    #[test]
    fn remove_workload_releases_capacity() {
        let mut mesh = IsolationMesh::new(test_topology()).expect("mesh");
        mesh.place_workload("w1", "shared-1", permissive_policy(), 1)
            .expect("place");
        let removed = mesh.remove_workload("w1", 2).expect("remove");
        assert_eq!(removed.workload_id, "w1");

        assert_eq!(mesh.rail_states().get("shared-1").unwrap().active_count, 0);
        assert_eq!(mesh.rail_states().get("shared-1").unwrap().total_removed, 1);
        assert!(mesh.workloads().is_empty());
    }

    #[test]
    fn remove_unknown_workload_fails_closed() {
        let mut mesh = IsolationMesh::new(test_topology()).expect("mesh");
        let err = mesh
            .remove_workload("ghost", 1)
            .expect_err("unknown workload");
        assert_eq!(err.code(), error_codes::ERR_MESH_UNKNOWN_WORKLOAD);
    }

    // --- topology reload ---

    #[test]
    fn reload_topology_adds_new_rails() {
        let mut mesh = IsolationMesh::new(test_topology()).expect("mesh");
        let mut new_topo = test_topology();
        new_topo.rails.insert(
            "extra".to_string(),
            IsolationRail {
                rail_id: "extra".to_string(),
                level: IsolationRailLevel::SandboxIsolated,
                latency_overhead_us: 100,
                capacity: 2,
            },
        );
        mesh.reload_topology(new_topo, 5).expect("reload");
        assert!(mesh.topology().rails.contains_key("extra"));
        assert!(mesh.rail_states().contains_key("extra"));
    }

    #[test]
    fn reload_rejects_removal_of_rail_with_active_workloads() {
        let mut mesh = IsolationMesh::new(test_topology()).expect("mesh");
        mesh.place_workload("w1", "shared-1", permissive_policy(), 1)
            .expect("place");

        let mut slim = BTreeMap::new();
        slim.insert("proc-1".to_string(), process_rail());
        let err = mesh
            .reload_topology(MeshTopology { rails: slim }, 2)
            .expect_err("rail still hosts workload");
        assert_eq!(err.code(), error_codes::ERR_MESH_INVALID_TOPOLOGY);
    }

    // --- event codes ---

    #[test]
    fn events_use_stable_codes() {
        let mut mesh = IsolationMesh::new(test_topology()).expect("mesh");
        mesh.place_workload("w1", "shared-1", permissive_policy(), 1)
            .expect("place");
        mesh.elevate_workload("w1", "proc-1", 2).expect("elevate");
        mesh.remove_workload("w1", 3).expect("remove");

        let codes: Vec<&str> = mesh.events().iter().map(|e| e.event_code.as_str()).collect();
        assert!(codes.contains(&event_codes::MESH_001));
        assert!(codes.contains(&event_codes::MESH_002));
        assert!(codes.contains(&event_codes::MESH_005));
    }

    #[test]
    fn mesh_006_emitted_on_reload() {
        let mut mesh = IsolationMesh::new(test_topology()).expect("mesh");
        mesh.reload_topology(test_topology(), 10).expect("reload");
        let has_006 = mesh
            .events()
            .iter()
            .any(|e| e.event_code == event_codes::MESH_006);
        assert!(has_006);
    }

    // --- isolation level ordering ---

    #[test]
    fn isolation_levels_ordered_by_strictness() {
        assert!(IsolationRailLevel::Shared < IsolationRailLevel::ProcessIsolated);
        assert!(IsolationRailLevel::ProcessIsolated < IsolationRailLevel::SandboxIsolated);
        assert!(IsolationRailLevel::SandboxIsolated < IsolationRailLevel::HardwareIsolated);
    }

    #[test]
    fn can_elevate_to_only_upward() {
        let shared = IsolationRailLevel::Shared;
        let proc = IsolationRailLevel::ProcessIsolated;
        assert!(shared.can_elevate_to(&proc));
        assert!(!proc.can_elevate_to(&shared));
        assert!(!shared.can_elevate_to(&shared));
    }

    // --- policy enforcement ---

    #[test]
    fn policy_max_target_level_enforced() {
        let policy = ElevationPolicy {
            elevation_allowed: true,
            max_target_level: IsolationRailLevel::ProcessIsolated,
            preserve_latency_budget: false,
            latency_budget_us: 0,
        };
        let result = policy.permits_elevation(
            &IsolationRailLevel::Shared,
            &IsolationRailLevel::SandboxIsolated,
            0,
        );
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code(), error_codes::ERR_MESH_ELEVATION_DENIED);
    }

    // --- deterministic ordering ---

    #[test]
    fn btreemap_ensures_deterministic_rail_iteration() {
        let mesh = IsolationMesh::new(test_topology()).expect("mesh");
        let keys: Vec<&String> = mesh.topology().rails.keys().collect();
        let mut sorted_keys = keys.clone();
        sorted_keys.sort();
        assert_eq!(keys, sorted_keys, "BTreeMap must iterate in sorted order");
    }

    // --- policy continuity across elevation ---

    #[test]
    fn policy_preserved_across_elevation() {
        let mut mesh = IsolationMesh::new(test_topology()).expect("mesh");
        let policy = budget_policy(100);
        mesh.place_workload("w1", "shared-1", policy.clone(), 1)
            .expect("place");
        let p = mesh.elevate_workload("w1", "proc-1", 2).expect("elevate");
        assert_eq!(p.policy, policy, "INV-MESH-POLICY-CONTINUITY violated");
    }

    // --- error Display ---

    #[test]
    fn error_display_includes_code() {
        let err = MeshError::UnknownRail {
            rail_id: "x".to_string(),
        };
        let s = format!("{err}");
        assert!(s.contains(error_codes::ERR_MESH_UNKNOWN_RAIL));
    }

    // --- all isolation levels enumerable ---

    #[test]
    fn all_levels_returns_four_items() {
        assert_eq!(IsolationRailLevel::all().len(), 4);
    }
}
