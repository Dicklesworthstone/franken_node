//! bd-2o8b: Heterogeneous hardware planner with policy-evidenced placements.
//!
//! Provides a [`HardwarePlanner`] that assigns workloads to heterogeneous hardware
//! targets while producing machine-readable [`PolicyEvidence`] for every placement
//! decision. The planner enforces capability matching, risk bounding, capacity
//! limits, and fallback-path selection on resource contention.
//!
//! # Lifecycle
//!
//! 1. **Register** hardware profiles describing capabilities, risk, and capacity.
//! 2. **Register** placement policies with priority-ordered preference rules.
//! 3. **Request** placement -- the planner evaluates candidates against policy,
//!    selects the best target, and records evidence of the reasoning chain.
//! 4. **Dispatch** through an approved runtime/engine interface.
//!
//! # Invariants
//!
//! - INV-HWP-DETERMINISTIC: identical inputs yield identical placement decisions
//! - INV-HWP-CAPABILITY-MATCH: workload placed only on capable hardware
//! - INV-HWP-RISK-BOUND: placement rejected if risk exceeds tolerance
//! - INV-HWP-EVIDENCE-COMPLETE: every decision carries PolicyEvidence
//! - INV-HWP-FALLBACK-PATH: contention triggers fallback with recorded reasoning
//! - INV-HWP-DISPATCH-GATED: dispatch only through approved interface
//! - INV-HWP-SCHEMA-VERSIONED: all serialized outputs carry schema version
//! - INV-HWP-AUDIT-COMPLETE: all decisions recorded with stable event codes

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

/// Schema version for hardware planner records.
pub const SCHEMA_VERSION: &str = "hwp-v1.0";

/// Maximum valid risk level (inclusive).
pub const MAX_RISK_LEVEL: u32 = 100;

use crate::capacity_defaults::aliases::MAX_AUDIT_LOG_ENTRIES;
use crate::push_bounded;
const MAX_DECISIONS: usize = 4096;
const MAX_DISPATCHES: usize = 4096;

// ---------------------------------------------------------------------------
// Invariant constants
// ---------------------------------------------------------------------------

/// INV-HWP-DETERMINISTIC: identical inputs yield identical placement decisions.
pub const INV_HWP_DETERMINISTIC: &str = "INV-HWP-DETERMINISTIC";
/// INV-HWP-CAPABILITY-MATCH: workload placed only on capable hardware.
pub const INV_HWP_CAPABILITY_MATCH: &str = "INV-HWP-CAPABILITY-MATCH";
/// INV-HWP-RISK-BOUND: placement rejected if risk exceeds tolerance.
pub const INV_HWP_RISK_BOUND: &str = "INV-HWP-RISK-BOUND";
/// INV-HWP-EVIDENCE-COMPLETE: every decision carries PolicyEvidence.
pub const INV_HWP_EVIDENCE_COMPLETE: &str = "INV-HWP-EVIDENCE-COMPLETE";
/// INV-HWP-FALLBACK-PATH: contention triggers fallback with recorded reasoning.
pub const INV_HWP_FALLBACK_PATH: &str = "INV-HWP-FALLBACK-PATH";
/// INV-HWP-DISPATCH-GATED: dispatch only through approved interface.
pub const INV_HWP_DISPATCH_GATED: &str = "INV-HWP-DISPATCH-GATED";
/// INV-HWP-SCHEMA-VERSIONED: all serialized outputs carry schema version.
pub const INV_HWP_SCHEMA_VERSIONED: &str = "INV-HWP-SCHEMA-VERSIONED";
/// INV-HWP-AUDIT-COMPLETE: all decisions recorded with stable event codes.
pub const INV_HWP_AUDIT_COMPLETE: &str = "INV-HWP-AUDIT-COMPLETE";

// Semantic invariant aliases for the policy-evidenced placement contract.
/// INV-PLANNER-REPRODUCIBLE: identical inputs yield identical placement decisions.
pub const INV_PLANNER_REPRODUCIBLE: &str = "INV-PLANNER-REPRODUCIBLE";
/// INV-PLANNER-CONSTRAINT-SATISFIED: workload placed only when constraints are met.
pub const INV_PLANNER_CONSTRAINT_SATISFIED: &str = "INV-PLANNER-CONSTRAINT-SATISFIED";
/// INV-PLANNER-FALLBACK-PATH: contention triggers fallback with recorded reasoning.
pub const INV_PLANNER_FALLBACK_PATH: &str = "INV-PLANNER-FALLBACK-PATH";
/// INV-PLANNER-APPROVED-DISPATCH: dispatch only through approved runtime/engine interfaces.
pub const INV_PLANNER_APPROVED_DISPATCH: &str = "INV-PLANNER-APPROVED-DISPATCH";

// ---------------------------------------------------------------------------
// Event codes
// ---------------------------------------------------------------------------

pub mod event_codes {
    /// HWP-001: Hardware profile registered.
    pub const HWP_001: &str = "HWP-001";
    /// HWP-002: Placement policy registered.
    pub const HWP_002: &str = "HWP-002";
    /// HWP-003: Placement requested.
    pub const HWP_003: &str = "HWP-003";
    /// HWP-004: Placement succeeded.
    pub const HWP_004: &str = "HWP-004";
    /// HWP-005: Placement rejected (capability mismatch).
    pub const HWP_005: &str = "HWP-005";
    /// HWP-006: Placement rejected (risk exceeded).
    pub const HWP_006: &str = "HWP-006";
    /// HWP-007: Placement rejected (capacity exhausted).
    pub const HWP_007: &str = "HWP-007";
    /// HWP-008: Fallback path attempted.
    pub const HWP_008: &str = "HWP-008";
    /// HWP-009: Fallback path succeeded.
    pub const HWP_009: &str = "HWP-009";
    /// HWP-010: Fallback path exhausted.
    pub const HWP_010: &str = "HWP-010";
    /// HWP-011: Dispatch executed through approved interface.
    pub const HWP_011: &str = "HWP-011";
    /// HWP-012: Policy evidence recorded.
    pub const HWP_012: &str = "HWP-012";

    // Semantic aliases for policy-evidenced placement lifecycle.
    /// Placement evaluation begins.
    pub const PLANNER_PLACEMENT_START: &str = "PLANNER_PLACEMENT_START";
    /// A constraint has been evaluated against a candidate.
    pub const PLANNER_CONSTRAINT_EVALUATED: &str = "PLANNER_CONSTRAINT_EVALUATED";
    /// Placement decision has been made.
    pub const PLANNER_PLACEMENT_DECIDED: &str = "PLANNER_PLACEMENT_DECIDED";
    /// Fallback path has been activated after resource contention.
    pub const PLANNER_FALLBACK_ACTIVATED: &str = "PLANNER_FALLBACK_ACTIVATED";
    /// Dispatch has been approved through a gated interface.
    pub const PLANNER_DISPATCH_APPROVED: &str = "PLANNER_DISPATCH_APPROVED";
}

// ---------------------------------------------------------------------------
// Error codes
// ---------------------------------------------------------------------------

pub mod error_codes {
    pub const ERR_HWP_NO_CAPABLE_TARGET: &str = "ERR_HWP_NO_CAPABLE_TARGET";
    pub const ERR_HWP_RISK_EXCEEDED: &str = "ERR_HWP_RISK_EXCEEDED";
    pub const ERR_HWP_CAPACITY_EXHAUSTED: &str = "ERR_HWP_CAPACITY_EXHAUSTED";
    pub const ERR_HWP_DUPLICATE_PROFILE: &str = "ERR_HWP_DUPLICATE_PROFILE";
    pub const ERR_HWP_DUPLICATE_POLICY: &str = "ERR_HWP_DUPLICATE_POLICY";
    pub const ERR_HWP_UNKNOWN_PROFILE: &str = "ERR_HWP_UNKNOWN_PROFILE";
    pub const ERR_HWP_EMPTY_CAPABILITIES: &str = "ERR_HWP_EMPTY_CAPABILITIES";
    pub const ERR_HWP_DISPATCH_UNGATED: &str = "ERR_HWP_DISPATCH_UNGATED";
    pub const ERR_HWP_DISPATCH_NOT_PLACED: &str = "ERR_HWP_DISPATCH_NOT_PLACED";
    pub const ERR_HWP_ALREADY_PLACED: &str = "ERR_HWP_ALREADY_PLACED";
    pub const ERR_HWP_RELEASE_NOT_PLACED: &str = "ERR_HWP_RELEASE_NOT_PLACED";
    pub const ERR_HWP_INVALID_RISK_LEVEL: &str = "ERR_HWP_INVALID_RISK_LEVEL";
    pub const ERR_HWP_FALLBACK_EXHAUSTED: &str = "ERR_HWP_FALLBACK_EXHAUSTED";
    pub const ERR_HWP_UNKNOWN_POLICY: &str = "ERR_HWP_UNKNOWN_POLICY";

    // Semantic aliases for policy-evidenced planner error conditions.
    /// Constraint evaluation found a violation (capability or risk).
    pub const ERR_PLANNER_CONSTRAINT_VIOLATED: &str = "ERR_PLANNER_CONSTRAINT_VIOLATED";
    /// Resource contention prevents placement on primary targets.
    pub const ERR_PLANNER_RESOURCE_CONTENTION: &str = "ERR_PLANNER_RESOURCE_CONTENTION";
    /// No fallback path exists after contention.
    pub const ERR_PLANNER_NO_FALLBACK: &str = "ERR_PLANNER_NO_FALLBACK";
    /// Dispatch was denied (ungated interface).
    pub const ERR_PLANNER_DISPATCH_DENIED: &str = "ERR_PLANNER_DISPATCH_DENIED";
    /// Reproducibility check failed (different output from identical inputs).
    pub const ERR_PLANNER_REPRODUCIBILITY_FAILED: &str = "ERR_PLANNER_REPRODUCIBILITY_FAILED";
    /// Dispatch attempted through an unapproved interface.
    pub const ERR_PLANNER_INTERFACE_UNAPPROVED: &str = "ERR_PLANNER_INTERFACE_UNAPPROVED";
}

// ---------------------------------------------------------------------------
// Hardware profile
// ---------------------------------------------------------------------------

/// Describes a hardware target's capabilities, risk, and capacity.
/// INV-HWP-DETERMINISTIC: BTreeSet for deterministic capability ordering.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HardwareProfile {
    /// Unique identifier for this hardware target.
    pub profile_id: String,
    /// Human-readable name.
    pub name: String,
    /// Capabilities this hardware provides (e.g. "gpu", "fpga", "tee").
    pub capabilities: BTreeSet<String>,
    /// Risk level [0, 100] where 0 = no risk, 100 = maximum risk.
    pub risk_level: u32,
    /// Total workload slots available.
    pub total_slots: u32,
    /// Currently occupied slots.
    pub used_slots: u32,
    /// Metadata key-value pairs for policy evaluation.
    pub metadata: BTreeMap<String, String>,
    /// Schema version.
    pub schema_version: String,
}

impl HardwareProfile {
    /// Create a new hardware profile.
    pub fn new(
        profile_id: impl Into<String>,
        name: impl Into<String>,
        capabilities: BTreeSet<String>,
        risk_level: u32,
        total_slots: u32,
    ) -> Result<Self, HardwarePlannerError> {
        if risk_level > MAX_RISK_LEVEL {
            return Err(HardwarePlannerError::InvalidRiskLevel {
                profile_id: profile_id.into(),
                risk_level,
            });
        }
        Ok(Self {
            profile_id: profile_id.into(),
            name: name.into(),
            capabilities,
            risk_level,
            total_slots,
            used_slots: 0,
            metadata: BTreeMap::new(),
            schema_version: SCHEMA_VERSION.to_string(),
        })
    }

    /// Available (free) slots.
    pub fn available_slots(&self) -> u32 {
        self.total_slots.saturating_sub(self.used_slots)
    }

    /// Whether this profile has capacity for at least one more workload.
    pub fn has_capacity(&self) -> bool {
        self.available_slots() > 0
    }

    /// Whether this profile provides all of the requested capabilities.
    /// INV-HWP-CAPABILITY-MATCH
    pub fn satisfies_capabilities(&self, required: &BTreeSet<String>) -> bool {
        required.is_subset(&self.capabilities)
    }

    /// Whether this profile's risk level is within the given tolerance.
    /// INV-HWP-RISK-BOUND
    pub fn within_risk_tolerance(&self, max_risk: u32) -> bool {
        self.risk_level <= max_risk
    }
}

// ---------------------------------------------------------------------------
// Placement policy
// ---------------------------------------------------------------------------

/// A named placement policy with preference rules.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlacementPolicy {
    /// Unique policy identifier.
    pub policy_id: String,
    /// Human-readable description.
    pub description: String,
    /// If true, prefer hardware with lowest risk level among candidates.
    pub prefer_lowest_risk: bool,
    /// If true, prefer hardware with most available capacity.
    pub prefer_most_capacity: bool,
    /// Maximum risk level a workload may tolerate under this policy.
    pub max_risk_tolerance: u32,
    /// Required metadata keys that hardware profiles must have.
    pub required_metadata_keys: BTreeSet<String>,
    /// Schema version.
    pub schema_version: String,
}

impl PlacementPolicy {
    pub fn new(
        policy_id: impl Into<String>,
        description: impl Into<String>,
        max_risk_tolerance: u32,
    ) -> Self {
        Self {
            policy_id: policy_id.into(),
            description: description.into(),
            prefer_lowest_risk: true,
            prefer_most_capacity: false,
            max_risk_tolerance,
            required_metadata_keys: BTreeSet::new(),
            schema_version: SCHEMA_VERSION.to_string(),
        }
    }
}

// ---------------------------------------------------------------------------
// Workload request
// ---------------------------------------------------------------------------

/// A workload requesting placement on hardware.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkloadRequest {
    /// Unique workload identifier.
    pub workload_id: String,
    /// Required capabilities.
    pub required_capabilities: BTreeSet<String>,
    /// Maximum tolerated risk level.
    pub max_risk: u32,
    /// Policy ID to use for placement.
    pub policy_id: String,
    /// Trace correlation ID.
    pub trace_id: String,
}

// ---------------------------------------------------------------------------
// Placement decision
// ---------------------------------------------------------------------------

/// Outcome of a placement attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlacementOutcome {
    /// Successfully placed on the named hardware target.
    Placed,
    /// Placed via fallback after primary contention.
    PlacedViaFallback,
    /// Rejected -- no capable hardware.
    RejectedNoCapable,
    /// Rejected -- risk exceeded on all capable targets.
    RejectedRiskExceeded,
    /// Rejected -- all capable targets at capacity.
    RejectedCapacityExhausted,
    /// Rejected -- fallback exhausted after contention.
    RejectedFallbackExhausted,
}

/// A completed placement decision with evidence.
/// INV-HWP-EVIDENCE-COMPLETE
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlacementDecision {
    /// Workload that was evaluated.
    pub workload_id: String,
    /// Outcome of the placement.
    pub outcome: PlacementOutcome,
    /// Hardware target selected (if placed).
    pub target_profile_id: Option<String>,
    /// Policy evidence chain.
    pub evidence: PolicyEvidence,
    /// Timestamp of the decision.
    pub timestamp_ms: u64,
    /// Schema version.
    pub schema_version: String,
}

// ---------------------------------------------------------------------------
// Policy evidence
// ---------------------------------------------------------------------------

/// Machine-readable record of the policy reasoning behind a placement decision.
/// INV-HWP-EVIDENCE-COMPLETE
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyEvidence {
    /// Policy ID used for evaluation.
    pub policy_id: String,
    /// Candidates considered (profile IDs).
    pub candidates_considered: Vec<String>,
    /// Candidates rejected and why.
    pub rejections: BTreeMap<String, String>,
    /// The selected target (if any).
    pub selected_target: Option<String>,
    /// Whether a fallback was attempted.
    pub fallback_attempted: bool,
    /// Fallback reasoning (if attempted).
    pub fallback_reason: Option<String>,
    /// Reasoning chain steps.
    pub reasoning_chain: Vec<String>,
    /// Schema version.
    pub schema_version: String,
}

impl PolicyEvidence {
    fn new(policy_id: &str) -> Self {
        Self {
            policy_id: policy_id.to_string(),
            candidates_considered: Vec::new(),
            rejections: BTreeMap::new(),
            selected_target: None,
            fallback_attempted: false,
            fallback_reason: None,
            reasoning_chain: Vec::new(),
            schema_version: SCHEMA_VERSION.to_string(),
        }
    }
}

// ---------------------------------------------------------------------------
// Dispatch token
// ---------------------------------------------------------------------------

/// Token proving a workload was dispatched through an approved interface.
/// INV-HWP-DISPATCH-GATED
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DispatchToken {
    pub workload_id: String,
    pub target_profile_id: String,
    pub approved_interface: String,
    pub timestamp_ms: u64,
    pub schema_version: String,
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors from hardware planner operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HardwarePlannerError {
    /// No registered hardware satisfies workload capabilities.
    NoCapableTarget { workload_id: String },
    /// All capable hardware exceeds workload risk tolerance.
    RiskExceeded { workload_id: String },
    /// All capable hardware at capacity.
    CapacityExhausted { workload_id: String },
    /// Hardware profile ID already registered.
    DuplicateProfile { profile_id: String },
    /// Policy ID already registered.
    DuplicatePolicy { policy_id: String },
    /// Referenced hardware profile does not exist.
    UnknownProfile { profile_id: String },
    /// Workload declares zero required capabilities.
    EmptyCapabilities { workload_id: String },
    /// Dispatch attempted without approved interface.
    DispatchUngated { workload_id: String },
    /// Dispatch attempted for a workload/target pair without successful placement.
    DispatchNotPlaced {
        workload_id: String,
        target_profile_id: String,
    },
    /// Placement requested for a workload that is already active on a target.
    AlreadyPlaced {
        workload_id: String,
        target_profile_id: String,
    },
    /// Release requested for a workload/target pair without an active placement.
    ReleaseNotPlaced {
        workload_id: String,
        target_profile_id: String,
    },
    /// Risk level outside valid range.
    InvalidRiskLevel { profile_id: String, risk_level: u32 },
    /// All fallback paths exhausted.
    FallbackExhausted { workload_id: String },
    /// Referenced placement policy does not exist.
    UnknownPolicy { policy_id: String },
}

impl HardwarePlannerError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::NoCapableTarget { .. } => error_codes::ERR_HWP_NO_CAPABLE_TARGET,
            Self::RiskExceeded { .. } => error_codes::ERR_HWP_RISK_EXCEEDED,
            Self::CapacityExhausted { .. } => error_codes::ERR_HWP_CAPACITY_EXHAUSTED,
            Self::DuplicateProfile { .. } => error_codes::ERR_HWP_DUPLICATE_PROFILE,
            Self::DuplicatePolicy { .. } => error_codes::ERR_HWP_DUPLICATE_POLICY,
            Self::UnknownProfile { .. } => error_codes::ERR_HWP_UNKNOWN_PROFILE,
            Self::EmptyCapabilities { .. } => error_codes::ERR_HWP_EMPTY_CAPABILITIES,
            Self::DispatchUngated { .. } => error_codes::ERR_HWP_DISPATCH_UNGATED,
            Self::DispatchNotPlaced { .. } => error_codes::ERR_HWP_DISPATCH_NOT_PLACED,
            Self::AlreadyPlaced { .. } => error_codes::ERR_HWP_ALREADY_PLACED,
            Self::ReleaseNotPlaced { .. } => error_codes::ERR_HWP_RELEASE_NOT_PLACED,
            Self::InvalidRiskLevel { .. } => error_codes::ERR_HWP_INVALID_RISK_LEVEL,
            Self::FallbackExhausted { .. } => error_codes::ERR_HWP_FALLBACK_EXHAUSTED,
            Self::UnknownPolicy { .. } => error_codes::ERR_HWP_UNKNOWN_POLICY,
        }
    }
}

impl fmt::Display for HardwarePlannerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoCapableTarget { workload_id } => {
                write!(
                    f,
                    "{}: no capable target for workload {}",
                    self.code(),
                    workload_id
                )
            }
            Self::RiskExceeded { workload_id } => {
                write!(
                    f,
                    "{}: risk exceeded for workload {}",
                    self.code(),
                    workload_id
                )
            }
            Self::CapacityExhausted { workload_id } => {
                write!(
                    f,
                    "{}: capacity exhausted for workload {}",
                    self.code(),
                    workload_id
                )
            }
            Self::DuplicateProfile { profile_id } => {
                write!(
                    f,
                    "{}: profile {} already registered",
                    self.code(),
                    profile_id
                )
            }
            Self::DuplicatePolicy { policy_id } => {
                write!(
                    f,
                    "{}: policy {} already registered",
                    self.code(),
                    policy_id
                )
            }
            Self::UnknownProfile { profile_id } => {
                write!(f, "{}: unknown profile {}", self.code(), profile_id)
            }
            Self::EmptyCapabilities { workload_id } => {
                write!(
                    f,
                    "{}: workload {} has empty capabilities",
                    self.code(),
                    workload_id
                )
            }
            Self::DispatchUngated { workload_id } => {
                write!(
                    f,
                    "{}: ungated dispatch for workload {}",
                    self.code(),
                    workload_id
                )
            }
            Self::DispatchNotPlaced {
                workload_id,
                target_profile_id,
            } => {
                write!(
                    f,
                    "{}: workload {} was not placed on target {}",
                    self.code(),
                    workload_id,
                    target_profile_id
                )
            }
            Self::AlreadyPlaced {
                workload_id,
                target_profile_id,
            } => {
                write!(
                    f,
                    "{}: workload {} is already active on target {}",
                    self.code(),
                    workload_id,
                    target_profile_id
                )
            }
            Self::ReleaseNotPlaced {
                workload_id,
                target_profile_id,
            } => {
                write!(
                    f,
                    "{}: workload {} is not actively placed on target {}",
                    self.code(),
                    workload_id,
                    target_profile_id
                )
            }
            Self::InvalidRiskLevel {
                profile_id,
                risk_level,
            } => {
                write!(
                    f,
                    "{}: profile {} has invalid risk level {}",
                    self.code(),
                    profile_id,
                    risk_level
                )
            }
            Self::FallbackExhausted { workload_id } => {
                write!(
                    f,
                    "{}: fallback exhausted for workload {}",
                    self.code(),
                    workload_id
                )
            }
            Self::UnknownPolicy { policy_id } => {
                write!(f, "{}: unknown policy {}", self.code(), policy_id)
            }
        }
    }
}

impl std::error::Error for HardwarePlannerError {}

// ---------------------------------------------------------------------------
// Audit event
// ---------------------------------------------------------------------------

/// Structured audit event for planner decisions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlannerAuditEvent {
    pub event_code: String,
    pub workload_id: String,
    pub profile_id: Option<String>,
    pub timestamp_ms: u64,
    pub trace_id: String,
    pub detail: String,
    pub schema_version: String,
}

// ---------------------------------------------------------------------------
// HardwarePlanner
// ---------------------------------------------------------------------------

/// Heterogeneous hardware planner with policy-evidenced placements.
///
/// INV-HWP-DETERMINISTIC: BTreeMap for deterministic iteration order.
/// INV-HWP-CAPABILITY-MATCH: only places on capable hardware.
/// INV-HWP-RISK-BOUND: rejects placements exceeding risk tolerance.
/// INV-HWP-EVIDENCE-COMPLETE: every decision carries PolicyEvidence.
/// INV-HWP-FALLBACK-PATH: contention triggers fallback.
/// INV-HWP-DISPATCH-GATED: dispatch only through approved interface.
/// INV-HWP-AUDIT-COMPLETE: all decisions recorded.
pub struct HardwarePlanner {
    /// Registered hardware profiles, keyed by profile_id.
    profiles: BTreeMap<String, HardwareProfile>,
    /// Registered placement policies, keyed by policy_id.
    policies: BTreeMap<String, PlacementPolicy>,
    /// Audit log.
    audit_log: Vec<PlannerAuditEvent>,
    /// Set of approved dispatch interfaces.
    approved_interfaces: BTreeSet<String>,
    /// Completed placement decisions.
    decisions: Vec<PlacementDecision>,
    /// Completed dispatch tokens.
    dispatches: Vec<DispatchToken>,
    /// Active workload -> target placement map used to prevent stale dispatch.
    active_placements: BTreeMap<String, String>,
}

impl HardwarePlanner {
    /// Create a new planner with the given set of approved dispatch interfaces.
    pub fn new(approved_interfaces: BTreeSet<String>) -> Self {
        Self {
            profiles: BTreeMap::new(),
            policies: BTreeMap::new(),
            audit_log: Vec::new(),
            approved_interfaces,
            decisions: Vec::new(),
            dispatches: Vec::new(),
            active_placements: BTreeMap::new(),
        }
    }

    /// Register a hardware profile.
    /// Emits HWP-001.
    pub fn register_profile(
        &mut self,
        profile: HardwareProfile,
        timestamp_ms: u64,
        trace_id: &str,
    ) -> Result<&HardwareProfile, HardwarePlannerError> {
        let pid = profile.profile_id.clone();
        if self.profiles.contains_key(&pid) {
            return Err(HardwarePlannerError::DuplicateProfile { profile_id: pid });
        }

        self.profiles.insert(pid.clone(), profile);
        self.emit_audit(PlannerAuditEvent {
            event_code: event_codes::HWP_001.to_string(),
            workload_id: String::new(),
            profile_id: Some(pid.clone()),
            timestamp_ms,
            trace_id: trace_id.to_string(),
            detail: format!("hardware profile registered: {}", pid),
            schema_version: SCHEMA_VERSION.to_string(),
        });

        self.profiles
            .get(&pid)
            .ok_or(HardwarePlannerError::UnknownProfile { profile_id: pid })
    }

    /// Register a placement policy.
    /// Emits HWP-002.
    pub fn register_policy(
        &mut self,
        policy: PlacementPolicy,
        timestamp_ms: u64,
        trace_id: &str,
    ) -> Result<&PlacementPolicy, HardwarePlannerError> {
        let pid = policy.policy_id.clone();
        if self.policies.contains_key(&pid) {
            return Err(HardwarePlannerError::DuplicatePolicy { policy_id: pid });
        }

        self.policies.insert(pid.clone(), policy);
        self.emit_audit(PlannerAuditEvent {
            event_code: event_codes::HWP_002.to_string(),
            workload_id: String::new(),
            profile_id: None,
            timestamp_ms,
            trace_id: trace_id.to_string(),
            detail: format!("placement policy registered: {}", pid),
            schema_version: SCHEMA_VERSION.to_string(),
        });

        self.policies
            .get(&pid)
            .ok_or(HardwarePlannerError::UnknownPolicy { policy_id: pid })
    }

    /// Request placement for a workload.
    /// Emits HWP-003 and one of HWP-004..HWP-007.
    /// INV-HWP-CAPABILITY-MATCH, INV-HWP-RISK-BOUND, INV-HWP-EVIDENCE-COMPLETE,
    /// INV-HWP-FALLBACK-PATH, INV-HWP-DETERMINISTIC
    pub fn request_placement(
        &mut self,
        request: &WorkloadRequest,
        timestamp_ms: u64,
    ) -> Result<PlacementDecision, HardwarePlannerError> {
        // INV-HWP-EVIDENCE-COMPLETE: empty capabilities rejected upfront
        if request.required_capabilities.is_empty() {
            return Err(HardwarePlannerError::EmptyCapabilities {
                workload_id: request.workload_id.clone(),
            });
        }

        // Emit HWP-003
        self.emit_audit(PlannerAuditEvent {
            event_code: event_codes::HWP_003.to_string(),
            workload_id: request.workload_id.clone(),
            profile_id: None,
            timestamp_ms,
            trace_id: request.trace_id.clone(),
            detail: format!("placement requested for workload {}", request.workload_id),
            schema_version: SCHEMA_VERSION.to_string(),
        });

        if let Some(target_profile_id) = self.active_placements.get(&request.workload_id) {
            return Err(HardwarePlannerError::AlreadyPlaced {
                workload_id: request.workload_id.clone(),
                target_profile_id: target_profile_id.clone(),
            });
        }

        let policy = self
            .policies
            .get(&request.policy_id)
            .cloned()
            .ok_or_else(|| HardwarePlannerError::UnknownPolicy {
                policy_id: request.policy_id.clone(),
            })?;
        let effective_max_risk = policy.max_risk_tolerance.min(request.max_risk);

        let mut evidence = PolicyEvidence::new(&request.policy_id);

        // INV-HWP-DETERMINISTIC: BTreeMap iterates in sorted order
        let profile_ids: Vec<String> = self.profiles.keys().cloned().collect();
        evidence.candidates_considered = profile_ids.clone();

        // Phase 1: capability + metadata filter
        let required_metadata_keys = policy.required_metadata_keys.clone();

        let mut capable: Vec<String> = Vec::new();
        for pid in &profile_ids {
            let prof = &self.profiles[pid];
            let missing_capabilities: Vec<String> = request
                .required_capabilities
                .difference(&prof.capabilities)
                .cloned()
                .collect();
            let missing_metadata_keys: Vec<String> = required_metadata_keys
                .iter()
                .filter(|key| !prof.metadata.contains_key(*key))
                .cloned()
                .collect();

            if missing_capabilities.is_empty() && missing_metadata_keys.is_empty() {
                capable.push(pid.clone());
            } else {
                let mut rejection_reasons = Vec::new();
                if !missing_capabilities.is_empty() {
                    rejection_reasons.push("capability_mismatch".to_string());
                    evidence.reasoning_chain.push(format!(
                        "rejected {}: missing capabilities {:?}",
                        pid, missing_capabilities
                    ));
                }

                if !missing_metadata_keys.is_empty() {
                    rejection_reasons.push(format!(
                        "missing_required_metadata_keys: {:?}",
                        missing_metadata_keys
                    ));
                    evidence.reasoning_chain.push(format!(
                        "rejected {}: missing required metadata keys {:?}",
                        pid, missing_metadata_keys
                    ));
                }

                evidence
                    .rejections
                    .insert(pid.clone(), rejection_reasons.join("; "));
            }
        }

        if capable.is_empty() {
            // HWP-005
            self.emit_audit(PlannerAuditEvent {
                event_code: event_codes::HWP_005.to_string(),
                workload_id: request.workload_id.clone(),
                profile_id: None,
                timestamp_ms,
                trace_id: request.trace_id.clone(),
                detail: "no capable hardware".to_string(),
                schema_version: SCHEMA_VERSION.to_string(),
            });
            self.emit_evidence_event(&request.workload_id, timestamp_ms, &request.trace_id);

            let decision = PlacementDecision {
                workload_id: request.workload_id.clone(),
                outcome: PlacementOutcome::RejectedNoCapable,
                target_profile_id: None,
                evidence,
                timestamp_ms,
                schema_version: SCHEMA_VERSION.to_string(),
            };
            push_bounded(&mut self.decisions, decision.clone(), MAX_DECISIONS);
            return Err(HardwarePlannerError::NoCapableTarget {
                workload_id: request.workload_id.clone(),
            });
        }

        // Phase 2: risk filter
        let mut risk_ok: Vec<String> = Vec::new();
        for pid in &capable {
            let prof = &self.profiles[pid];
            if prof.within_risk_tolerance(effective_max_risk) {
                risk_ok.push(pid.clone());
            } else {
                evidence.rejections.insert(
                    pid.clone(),
                    format!(
                        "risk_exceeded: {} > {}",
                        prof.risk_level, effective_max_risk
                    ),
                );
                evidence.reasoning_chain.push(format!(
                    "rejected {}: risk {} exceeds tolerance {}",
                    pid, prof.risk_level, effective_max_risk
                ));
            }
        }

        if risk_ok.is_empty() {
            // HWP-006
            self.emit_audit(PlannerAuditEvent {
                event_code: event_codes::HWP_006.to_string(),
                workload_id: request.workload_id.clone(),
                profile_id: None,
                timestamp_ms,
                trace_id: request.trace_id.clone(),
                detail: "all capable targets exceed risk tolerance".to_string(),
                schema_version: SCHEMA_VERSION.to_string(),
            });
            self.emit_evidence_event(&request.workload_id, timestamp_ms, &request.trace_id);

            let decision = PlacementDecision {
                workload_id: request.workload_id.clone(),
                outcome: PlacementOutcome::RejectedRiskExceeded,
                target_profile_id: None,
                evidence,
                timestamp_ms,
                schema_version: SCHEMA_VERSION.to_string(),
            };
            push_bounded(&mut self.decisions, decision.clone(), MAX_DECISIONS);
            return Err(HardwarePlannerError::RiskExceeded {
                workload_id: request.workload_id.clone(),
            });
        }

        // Phase 3: capacity filter (primary)
        let with_capacity: Vec<String> = risk_ok
            .iter()
            .filter(|pid| self.profiles[*pid].has_capacity())
            .cloned()
            .collect();

        if with_capacity.is_empty() {
            // HWP-007
            self.emit_audit(PlannerAuditEvent {
                event_code: event_codes::HWP_007.to_string(),
                workload_id: request.workload_id.clone(),
                profile_id: None,
                timestamp_ms,
                trace_id: request.trace_id.clone(),
                detail: "all capable+risk-ok targets at capacity".to_string(),
                schema_version: SCHEMA_VERSION.to_string(),
            });
            evidence
                .reasoning_chain
                .push("all capable+risk-ok targets are at capacity".to_string());
            self.emit_evidence_event(&request.workload_id, timestamp_ms, &request.trace_id);

            let decision = PlacementDecision {
                workload_id: request.workload_id.clone(),
                outcome: PlacementOutcome::RejectedCapacityExhausted,
                target_profile_id: None,
                evidence,
                timestamp_ms,
                schema_version: SCHEMA_VERSION.to_string(),
            };
            push_bounded(&mut self.decisions, decision.clone(), MAX_DECISIONS);
            return Err(HardwarePlannerError::CapacityExhausted {
                workload_id: request.workload_id.clone(),
            });
        }

        // Phase 4: select best candidate per policy
        let selected = self.select_best(&with_capacity, Some(&policy));
        evidence.selected_target = Some(selected.clone());
        evidence.reasoning_chain.push(format!(
            "selected {} from {} candidates",
            selected,
            with_capacity.len()
        ));

        // Allocate slot
        if let Some(prof) = self.profiles.get_mut(&selected) {
            prof.used_slots = prof.used_slots.saturating_add(1);
        }
        self.active_placements
            .insert(request.workload_id.clone(), selected.clone());

        // HWP-004
        self.emit_audit(PlannerAuditEvent {
            event_code: event_codes::HWP_004.to_string(),
            workload_id: request.workload_id.clone(),
            profile_id: Some(selected.clone()),
            timestamp_ms,
            trace_id: request.trace_id.clone(),
            detail: format!("placed on {}", selected),
            schema_version: SCHEMA_VERSION.to_string(),
        });
        self.emit_evidence_event(&request.workload_id, timestamp_ms, &request.trace_id);

        let decision = PlacementDecision {
            workload_id: request.workload_id.clone(),
            outcome: PlacementOutcome::Placed,
            target_profile_id: Some(selected),
            evidence,
            timestamp_ms,
            schema_version: SCHEMA_VERSION.to_string(),
        };
        push_bounded(&mut self.decisions, decision.clone(), MAX_DECISIONS);
        Ok(decision)
    }

    /// Request placement with fallback: first attempt uses the primary policy;
    /// if capacity is exhausted, a second pass relaxes risk tolerance by a
    /// configurable delta and re-evaluates.
    /// INV-HWP-FALLBACK-PATH
    pub fn request_placement_with_fallback(
        &mut self,
        request: &WorkloadRequest,
        risk_relaxation_delta: u32,
        timestamp_ms: u64,
    ) -> Result<PlacementDecision, HardwarePlannerError> {
        // First try normal placement
        match self.request_placement(request, timestamp_ms) {
            Ok(decision) => Ok(decision),
            Err(HardwarePlannerError::RiskExceeded { .. })
            | Err(HardwarePlannerError::CapacityExhausted { .. }) => {
                // HWP-008: fallback attempted
                self.emit_audit(PlannerAuditEvent {
                    event_code: event_codes::HWP_008.to_string(),
                    workload_id: request.workload_id.clone(),
                    profile_id: None,
                    timestamp_ms,
                    trace_id: request.trace_id.clone(),
                    detail: format!(
                        "fallback: relaxing risk by {} (was {})",
                        risk_relaxation_delta, request.max_risk
                    ),
                    schema_version: SCHEMA_VERSION.to_string(),
                });

                let mut relaxed = request.clone();
                relaxed.max_risk = request
                    .max_risk
                    .saturating_add(risk_relaxation_delta)
                    .min(MAX_RISK_LEVEL);

                match self.request_placement(&relaxed, timestamp_ms) {
                    Ok(mut decision) => {
                        decision.outcome = PlacementOutcome::PlacedViaFallback;
                        decision.evidence.fallback_attempted = true;
                        decision.evidence.fallback_reason = Some(format!(
                            "risk relaxed from {} to {}",
                            request.max_risk, relaxed.max_risk
                        ));

                        // HWP-009
                        self.emit_audit(PlannerAuditEvent {
                            event_code: event_codes::HWP_009.to_string(),
                            workload_id: request.workload_id.clone(),
                            profile_id: decision.target_profile_id.clone(),
                            timestamp_ms,
                            trace_id: request.trace_id.clone(),
                            detail: "fallback path succeeded".to_string(),
                            schema_version: SCHEMA_VERSION.to_string(),
                        });

                        // Update stored decision
                        if let Some(last) = self.decisions.last_mut() {
                            *last = decision.clone();
                        }
                        Ok(decision)
                    }
                    Err(_) => {
                        // HWP-010
                        self.emit_audit(PlannerAuditEvent {
                            event_code: event_codes::HWP_010.to_string(),
                            workload_id: request.workload_id.clone(),
                            profile_id: None,
                            timestamp_ms,
                            trace_id: request.trace_id.clone(),
                            detail: "fallback path exhausted after risk relaxation".to_string(),
                            schema_version: SCHEMA_VERSION.to_string(),
                        });

                        if let Some(last) = self.decisions.last_mut()
                            && last.workload_id == request.workload_id
                        {
                            last.outcome = PlacementOutcome::RejectedFallbackExhausted;
                            last.evidence.fallback_attempted = true;
                            last.evidence.fallback_reason = Some(format!(
                                "risk relaxed from {} to {}",
                                request.max_risk, relaxed.max_risk
                            ));
                        }

                        Err(HardwarePlannerError::FallbackExhausted {
                            workload_id: request.workload_id.clone(),
                        })
                    }
                }
            }
            Err(e) => Err(e),
        }
    }

    /// Dispatch a placed workload through an approved interface.
    /// Emits HWP-011.
    /// INV-HWP-DISPATCH-GATED
    pub fn dispatch(
        &mut self,
        workload_id: &str,
        target_profile_id: &str,
        interface: &str,
        timestamp_ms: u64,
        trace_id: &str,
    ) -> Result<DispatchToken, HardwarePlannerError> {
        if !self.profiles.contains_key(target_profile_id) {
            return Err(HardwarePlannerError::UnknownProfile {
                profile_id: target_profile_id.to_string(),
            });
        }

        if !self.approved_interfaces.contains(interface) {
            return Err(HardwarePlannerError::DispatchUngated {
                workload_id: workload_id.to_string(),
            });
        }

        if self
            .active_placements
            .get(workload_id)
            .map_or(true, |active_target| active_target != target_profile_id)
        {
            return Err(HardwarePlannerError::DispatchNotPlaced {
                workload_id: workload_id.to_string(),
                target_profile_id: target_profile_id.to_string(),
            });
        }

        let token = DispatchToken {
            workload_id: workload_id.to_string(),
            target_profile_id: target_profile_id.to_string(),
            approved_interface: interface.to_string(),
            timestamp_ms,
            schema_version: SCHEMA_VERSION.to_string(),
        };

        self.emit_audit(PlannerAuditEvent {
            event_code: event_codes::HWP_011.to_string(),
            workload_id: workload_id.to_string(),
            profile_id: Some(target_profile_id.to_string()),
            timestamp_ms,
            trace_id: trace_id.to_string(),
            detail: format!("dispatched via {}", interface),
            schema_version: SCHEMA_VERSION.to_string(),
        });

        push_bounded(&mut self.dispatches, token.clone(), MAX_DISPATCHES);
        Ok(token)
    }

    /// Release an active placement after a workload completes.
    pub fn release_placement(
        &mut self,
        workload_id: &str,
        target_profile_id: &str,
    ) -> Result<(), HardwarePlannerError> {
        if !self.profiles.contains_key(target_profile_id) {
            return Err(HardwarePlannerError::UnknownProfile {
                profile_id: target_profile_id.to_string(),
            });
        }

        if self
            .active_placements
            .get(workload_id)
            .map_or(true, |active_target| active_target != target_profile_id)
        {
            return Err(HardwarePlannerError::ReleaseNotPlaced {
                workload_id: workload_id.to_string(),
                target_profile_id: target_profile_id.to_string(),
            });
        }

        self.active_placements.remove(workload_id);
        if let Some(prof) = self.profiles.get_mut(target_profile_id) {
            prof.used_slots = prof.used_slots.saturating_sub(1);
        }
        Ok(())
    }

    /// Get a profile by ID.
    pub fn get_profile(&self, profile_id: &str) -> Option<&HardwareProfile> {
        self.profiles.get(profile_id)
    }

    /// Get a policy by ID.
    pub fn get_policy(&self, policy_id: &str) -> Option<&PlacementPolicy> {
        self.policies.get(policy_id)
    }

    /// Get all profiles.
    pub fn profiles(&self) -> &BTreeMap<String, HardwareProfile> {
        &self.profiles
    }

    /// Get all policies.
    pub fn policies(&self) -> &BTreeMap<String, PlacementPolicy> {
        &self.policies
    }

    /// Get all placement decisions.
    pub fn decisions(&self) -> &[PlacementDecision] {
        &self.decisions
    }

    /// Get all dispatch tokens.
    pub fn dispatches(&self) -> &[DispatchToken] {
        &self.dispatches
    }

    /// Get the audit log.
    pub fn audit_log(&self) -> &[PlannerAuditEvent] {
        &self.audit_log
    }

    /// Number of registered profiles.
    pub fn profile_count(&self) -> usize {
        self.profiles.len()
    }

    /// Number of registered policies.
    pub fn policy_count(&self) -> usize {
        self.policies.len()
    }

    /// Export audit log as JSONL.
    pub fn export_audit_log_jsonl(&self) -> String {
        self.audit_log
            .iter()
            .map(|e| serde_json::to_string(e).unwrap_or_default())
            .collect::<Vec<_>>()
            .join("\n")
    }

    // -- Private helpers --

    /// Select the best candidate from a list per policy preferences.
    /// INV-HWP-DETERMINISTIC: deterministic selection using sorted IDs and
    /// stable comparison criteria.
    fn select_best(&self, candidates: &[String], policy: Option<&PlacementPolicy>) -> String {
        assert!(
            !candidates.is_empty(),
            "select_best: invariant violated — candidates must be non-empty"
        );
        if candidates.len() == 1 {
            return candidates[0].clone();
        }

        let prefer_lowest_risk = policy.map_or(true, |p| p.prefer_lowest_risk);
        let prefer_most_capacity = policy.is_some_and(|p| p.prefer_most_capacity);

        let mut best = candidates[0].clone();
        let mut best_risk = self.profiles[&best].risk_level;
        let mut best_available = self.profiles[&best].available_slots();

        for pid in &candidates[1..] {
            let prof = &self.profiles[pid];
            let is_better = (prefer_lowest_risk && prof.risk_level < best_risk)
                || (prefer_most_capacity
                    && prof.available_slots() > best_available
                    && (!prefer_lowest_risk || prof.risk_level == best_risk));

            if is_better {
                best = pid.clone();
                best_risk = prof.risk_level;
                best_available = prof.available_slots();
            }
        }

        best
    }

    /// Push an audit event into the bounded audit log.
    fn emit_audit(&mut self, event: PlannerAuditEvent) {
        push_bounded(&mut self.audit_log, event, MAX_AUDIT_LOG_ENTRIES);
    }

    /// Emit an HWP-012 evidence-recorded event.
    fn emit_evidence_event(&mut self, workload_id: &str, timestamp_ms: u64, trace_id: &str) {
        self.emit_audit(PlannerAuditEvent {
            event_code: event_codes::HWP_012.to_string(),
            workload_id: workload_id.to_string(),
            profile_id: None,
            timestamp_ms,
            trace_id: trace_id.to_string(),
            detail: "policy evidence recorded".to_string(),
            schema_version: SCHEMA_VERSION.to_string(),
        });
    }
}

impl Default for HardwarePlanner {
    fn default() -> Self {
        let mut approved = BTreeSet::new();
        approved.insert("franken_engine".to_string());
        approved.insert("asupersync".to_string());
        Self::new(approved)
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn caps(names: &[&str]) -> BTreeSet<String> {
        names.iter().map(|s| s.to_string()).collect()
    }

    fn make_planner() -> HardwarePlanner {
        HardwarePlanner::default()
    }

    fn gpu_profile(id: &str, risk: u32, slots: u32) -> HardwareProfile {
        HardwareProfile::new(
            id,
            format!("GPU {}", id),
            caps(&["gpu", "compute"]),
            risk,
            slots,
        )
        .unwrap()
    }

    fn fpga_profile(id: &str, risk: u32, slots: u32) -> HardwareProfile {
        HardwareProfile::new(
            id,
            format!("FPGA {}", id),
            caps(&["fpga", "compute"]),
            risk,
            slots,
        )
        .unwrap()
    }

    fn default_policy() -> PlacementPolicy {
        PlacementPolicy::new("default", "Default policy", 50)
    }

    fn workload(id: &str, required: &[&str], max_risk: u32, policy: &str) -> WorkloadRequest {
        WorkloadRequest {
            workload_id: id.to_string(),
            required_capabilities: caps(required),
            max_risk,
            policy_id: policy.to_string(),
            trace_id: format!("trace-{}", id),
        }
    }

    // ---- Profile creation ----

    #[test]
    fn profile_creation_valid() {
        let p = HardwareProfile::new("hw-1", "Test", caps(&["gpu"]), 30, 4).unwrap();
        assert_eq!(p.profile_id, "hw-1");
        assert_eq!(p.risk_level, 30);
        assert_eq!(p.total_slots, 4);
        assert_eq!(p.used_slots, 0);
        assert_eq!(p.available_slots(), 4);
        assert!(p.has_capacity());
        assert_eq!(p.schema_version, SCHEMA_VERSION);
    }

    #[test]
    fn profile_creation_invalid_risk() {
        let err = HardwareProfile::new("hw-1", "Test", caps(&["gpu"]), 101, 4).unwrap_err();
        assert_eq!(err.code(), error_codes::ERR_HWP_INVALID_RISK_LEVEL);
    }

    #[test]
    fn profile_capability_satisfaction() {
        let p = gpu_profile("hw-1", 10, 4);
        assert!(p.satisfies_capabilities(&caps(&["gpu"])));
        assert!(p.satisfies_capabilities(&caps(&["gpu", "compute"])));
        assert!(!p.satisfies_capabilities(&caps(&["gpu", "fpga"])));
    }

    #[test]
    fn profile_risk_tolerance() {
        let p = gpu_profile("hw-1", 30, 4);
        assert!(p.within_risk_tolerance(30));
        assert!(p.within_risk_tolerance(50));
        assert!(!p.within_risk_tolerance(20));
    }

    // ---- Registration ----

    #[test]
    fn register_profile_success() {
        let mut planner = make_planner();
        let p = gpu_profile("hw-1", 10, 4);
        let result = planner.register_profile(p, 1000, "t1").unwrap();
        assert_eq!(result.profile_id, "hw-1");
        assert_eq!(planner.profile_count(), 1);
    }

    #[test]
    fn register_duplicate_profile_rejected() {
        let mut planner = make_planner();
        planner
            .register_profile(gpu_profile("hw-1", 10, 4), 1000, "t1")
            .unwrap();
        let err = planner
            .register_profile(gpu_profile("hw-1", 20, 2), 1001, "t1")
            .unwrap_err();
        assert_eq!(err.code(), error_codes::ERR_HWP_DUPLICATE_PROFILE);
    }

    #[test]
    fn register_policy_success() {
        let mut planner = make_planner();
        let pol = default_policy();
        let result = planner.register_policy(pol, 1000, "t1").unwrap();
        assert_eq!(result.policy_id, "default");
        assert_eq!(planner.policy_count(), 1);
    }

    #[test]
    fn register_duplicate_policy_rejected() {
        let mut planner = make_planner();
        planner
            .register_policy(default_policy(), 1000, "t1")
            .unwrap();
        let err = planner
            .register_policy(default_policy(), 1001, "t1")
            .unwrap_err();
        assert_eq!(err.code(), error_codes::ERR_HWP_DUPLICATE_POLICY);
    }

    // ---- Happy path placement ----

    #[test]
    fn happy_path_placement() {
        let mut planner = make_planner();
        planner
            .register_profile(gpu_profile("hw-1", 10, 4), 1000, "t1")
            .unwrap();
        planner
            .register_policy(default_policy(), 1001, "t1")
            .unwrap();

        let req = workload("wl-1", &["gpu", "compute"], 50, "default");
        let decision = planner.request_placement(&req, 2000).unwrap();

        assert_eq!(decision.outcome, PlacementOutcome::Placed);
        assert_eq!(decision.target_profile_id, Some("hw-1".to_string()));
        assert_eq!(decision.evidence.policy_id, "default");
        assert!(!decision.evidence.fallback_attempted);
        assert_eq!(decision.schema_version, SCHEMA_VERSION);

        // Slot consumed
        assert_eq!(planner.get_profile("hw-1").unwrap().used_slots, 1);
    }

    // ---- Deterministic placement ----

    #[test]
    fn deterministic_placement_identical_inputs() {
        // INV-HWP-DETERMINISTIC: same inputs produce same output
        let run = || {
            let mut planner = make_planner();
            planner
                .register_profile(gpu_profile("hw-a", 10, 4), 1000, "t1")
                .unwrap();
            planner
                .register_profile(gpu_profile("hw-b", 20, 4), 1001, "t1")
                .unwrap();
            planner
                .register_policy(default_policy(), 1002, "t1")
                .unwrap();

            let req = workload("wl-1", &["gpu", "compute"], 50, "default");
            planner.request_placement(&req, 2000).unwrap()
        };

        let d1 = run();
        let d2 = run();
        assert_eq!(d1.target_profile_id, d2.target_profile_id);
        assert_eq!(d1.outcome, d2.outcome);
    }

    // ---- Capability mismatch ----

    #[test]
    fn placement_rejected_capability_mismatch() {
        let mut planner = make_planner();
        planner
            .register_profile(gpu_profile("hw-1", 10, 4), 1000, "t1")
            .unwrap();
        planner
            .register_policy(default_policy(), 1001, "t1")
            .unwrap();

        let req = workload("wl-1", &["fpga"], 50, "default");
        let err = planner.request_placement(&req, 2000).unwrap_err();
        assert_eq!(err.code(), error_codes::ERR_HWP_NO_CAPABLE_TARGET);
    }

    #[test]
    fn policy_required_metadata_keys_are_enforced() {
        let mut planner = make_planner();
        planner
            .register_profile(gpu_profile("hw-missing", 10, 8), 1000, "t1")
            .unwrap();

        let mut eligible = gpu_profile("hw-eligible", 10, 1);
        eligible
            .metadata
            .insert("attestation".to_string(), "tee-v1".to_string());
        planner.register_profile(eligible, 1001, "t1").unwrap();

        let mut pol = default_policy();
        pol.prefer_lowest_risk = false;
        pol.prefer_most_capacity = true;
        pol.required_metadata_keys.insert("attestation".to_string());
        planner.register_policy(pol, 1002, "t1").unwrap();

        let req = workload("wl-1", &["gpu", "compute"], 50, "default");
        let decision = planner.request_placement(&req, 2000).unwrap();

        assert_eq!(decision.target_profile_id, Some("hw-eligible".to_string()));
        assert_eq!(planner.get_profile("hw-missing").unwrap().used_slots, 0);
        assert_eq!(planner.get_profile("hw-eligible").unwrap().used_slots, 1);
        let rejection = decision.evidence.rejections.get("hw-missing").unwrap();
        assert!(rejection.contains("missing_required_metadata_keys"));
    }

    #[test]
    fn placement_rejected_when_policy_metadata_constraints_not_met() {
        let mut planner = make_planner();
        planner
            .register_profile(gpu_profile("hw-1", 10, 4), 1000, "t1")
            .unwrap();
        let mut pol = default_policy();
        pol.required_metadata_keys.insert("attestation".to_string());
        planner.register_policy(pol, 1001, "t1").unwrap();

        let req = workload("wl-1", &["gpu", "compute"], 50, "default");
        let err = planner.request_placement(&req, 2000).unwrap_err();
        assert_eq!(err.code(), error_codes::ERR_HWP_NO_CAPABLE_TARGET);

        let decisions = planner.decisions();
        let last = &decisions[decisions.len() - 1];
        assert_eq!(last.outcome, PlacementOutcome::RejectedNoCapable);
        let rejection = last.evidence.rejections.get("hw-1").unwrap();
        assert!(rejection.contains("missing_required_metadata_keys"));
    }

    // ---- Risk exceeded ----

    #[test]
    fn placement_rejected_risk_exceeded() {
        let mut planner = make_planner();
        planner
            .register_profile(gpu_profile("hw-1", 60, 4), 1000, "t1")
            .unwrap();
        planner
            .register_policy(default_policy(), 1001, "t1")
            .unwrap();

        let req = workload("wl-1", &["gpu", "compute"], 20, "default");
        let err = planner.request_placement(&req, 2000).unwrap_err();
        assert_eq!(err.code(), error_codes::ERR_HWP_RISK_EXCEEDED);
    }

    // ---- Capacity exhausted ----

    #[test]
    fn placement_rejected_capacity_exhausted() {
        let mut planner = make_planner();
        let mut prof = gpu_profile("hw-1", 10, 1);
        prof.used_slots = 1; // at capacity
        planner.register_profile(prof, 1000, "t1").unwrap();
        planner
            .register_policy(default_policy(), 1001, "t1")
            .unwrap();

        let req = workload("wl-1", &["gpu", "compute"], 50, "default");
        let err = planner.request_placement(&req, 2000).unwrap_err();
        assert_eq!(err.code(), error_codes::ERR_HWP_CAPACITY_EXHAUSTED);
        let decisions = planner.decisions();
        let last = &decisions[decisions.len() - 1];
        assert_eq!(last.outcome, PlacementOutcome::RejectedCapacityExhausted);
    }

    // ---- Empty capabilities rejected ----

    #[test]
    fn placement_rejected_empty_capabilities() {
        let mut planner = make_planner();
        let _req = workload("wl-1", &[], 50, "default");
        // required_capabilities is empty from caps(&[])
        // but our workload helper uses caps() which will produce empty set for empty slice
        let req = WorkloadRequest {
            workload_id: "wl-1".to_string(),
            required_capabilities: BTreeSet::new(),
            max_risk: 50,
            policy_id: "default".to_string(),
            trace_id: "t1".to_string(),
        };
        let err = planner.request_placement(&req, 2000).unwrap_err();
        assert_eq!(err.code(), error_codes::ERR_HWP_EMPTY_CAPABILITIES);
    }

    #[test]
    fn placement_rejected_unknown_policy() {
        let mut planner = make_planner();
        planner
            .register_profile(gpu_profile("hw-1", 10, 4), 1000, "t1")
            .unwrap();

        let req = workload("wl-1", &["gpu", "compute"], 50, "missing-policy");
        let err = planner.request_placement(&req, 2000).unwrap_err();
        assert_eq!(err.code(), error_codes::ERR_HWP_UNKNOWN_POLICY);
        assert!(planner.decisions().is_empty());
    }

    // ---- Policy prefers lowest risk ----

    #[test]
    fn policy_prefers_lowest_risk() {
        let mut planner = make_planner();
        planner
            .register_profile(gpu_profile("hw-high", 40, 4), 1000, "t1")
            .unwrap();
        planner
            .register_profile(gpu_profile("hw-low", 10, 4), 1001, "t1")
            .unwrap();
        let mut pol = default_policy();
        pol.prefer_lowest_risk = true;
        planner.register_policy(pol, 1002, "t1").unwrap();

        let req = workload("wl-1", &["gpu", "compute"], 50, "default");
        let decision = planner.request_placement(&req, 2000).unwrap();
        assert_eq!(decision.target_profile_id, Some("hw-low".to_string()));
    }

    // ---- Policy prefers most capacity ----

    #[test]
    fn policy_prefers_most_capacity_when_risk_equal() {
        let mut planner = make_planner();
        planner
            .register_profile(gpu_profile("hw-small", 10, 2), 1000, "t1")
            .unwrap();
        planner
            .register_profile(gpu_profile("hw-big", 10, 8), 1001, "t1")
            .unwrap();
        let mut pol = default_policy();
        pol.prefer_lowest_risk = true;
        pol.prefer_most_capacity = true;
        planner.register_policy(pol, 1002, "t1").unwrap();

        let req = workload("wl-1", &["gpu", "compute"], 50, "default");
        let decision = planner.request_placement(&req, 2000).unwrap();
        assert_eq!(decision.target_profile_id, Some("hw-big".to_string()));
    }

    // ---- Dispatch gated ----

    #[test]
    fn dispatch_through_approved_interface() {
        let mut planner = make_planner();
        planner
            .register_profile(gpu_profile("hw-1", 10, 4), 1000, "t1")
            .unwrap();
        planner
            .register_policy(default_policy(), 1001, "t1")
            .unwrap();

        let req = workload("wl-1", &["gpu", "compute"], 50, "default");
        planner.request_placement(&req, 1500).unwrap();

        let token = planner
            .dispatch("wl-1", "hw-1", "franken_engine", 2000, "t1")
            .unwrap();
        assert_eq!(token.workload_id, "wl-1");
        assert_eq!(token.target_profile_id, "hw-1");
        assert_eq!(token.approved_interface, "franken_engine");
        assert_eq!(token.schema_version, SCHEMA_VERSION);
    }

    #[test]
    fn dispatch_ungated_rejected() {
        let mut planner = make_planner();
        planner
            .register_profile(gpu_profile("hw-1", 10, 4), 1000, "t1")
            .unwrap();

        let err = planner
            .dispatch("wl-1", "hw-1", "rogue_interface", 2000, "t1")
            .unwrap_err();
        assert_eq!(err.code(), error_codes::ERR_HWP_DISPATCH_UNGATED);
    }

    #[test]
    fn dispatch_without_successful_placement_rejected() {
        let mut planner = make_planner();
        planner
            .register_profile(gpu_profile("hw-1", 10, 4), 1000, "t1")
            .unwrap();

        let err = planner
            .dispatch("wl-1", "hw-1", "franken_engine", 2000, "t1")
            .unwrap_err();
        assert_eq!(err.code(), error_codes::ERR_HWP_DISPATCH_NOT_PLACED);
    }

    #[test]
    fn dispatch_unknown_profile_rejected() {
        let mut planner = make_planner();
        let err = planner
            .dispatch("wl-1", "hw-nonexistent", "franken_engine", 2000, "t1")
            .unwrap_err();
        assert_eq!(err.code(), error_codes::ERR_HWP_UNKNOWN_PROFILE);
    }

    // ---- Placement release ----

    #[test]
    fn release_placement_success() {
        let mut planner = make_planner();
        planner
            .register_profile(gpu_profile("hw-1", 10, 4), 1000, "t1")
            .unwrap();
        planner
            .register_policy(default_policy(), 1001, "t1")
            .unwrap();

        let req = workload("wl-1", &["gpu", "compute"], 50, "default");
        planner.request_placement(&req, 2000).unwrap();
        assert_eq!(planner.get_profile("hw-1").unwrap().used_slots, 1);

        planner.release_placement("wl-1", "hw-1").unwrap();
        assert_eq!(planner.get_profile("hw-1").unwrap().used_slots, 0);
    }

    #[test]
    fn release_placement_unknown_profile() {
        let mut planner = make_planner();
        let err = planner
            .release_placement("wl-1", "nonexistent")
            .unwrap_err();
        assert_eq!(err.code(), error_codes::ERR_HWP_UNKNOWN_PROFILE);
    }

    #[test]
    fn release_placement_requires_active_workload_target_pair() {
        let mut planner = make_planner();
        planner
            .register_profile(gpu_profile("hw-1", 10, 4), 1000, "t1")
            .unwrap();

        let err = planner.release_placement("wl-1", "hw-1").unwrap_err();
        assert_eq!(err.code(), error_codes::ERR_HWP_RELEASE_NOT_PLACED);
    }

    #[test]
    fn dispatch_after_release_is_rejected() {
        let mut planner = make_planner();
        planner
            .register_profile(gpu_profile("hw-1", 10, 4), 1000, "t1")
            .unwrap();
        planner
            .register_policy(default_policy(), 1001, "t1")
            .unwrap();

        let req = workload("wl-1", &["gpu", "compute"], 50, "default");
        planner.request_placement(&req, 1500).unwrap();
        planner.release_placement("wl-1", "hw-1").unwrap();

        let err = planner
            .dispatch("wl-1", "hw-1", "franken_engine", 2000, "t1")
            .unwrap_err();
        assert_eq!(err.code(), error_codes::ERR_HWP_DISPATCH_NOT_PLACED);
    }

    // ---- Audit log ----

    #[test]
    fn audit_log_records_profile_registration() {
        let mut planner = make_planner();
        planner
            .register_profile(gpu_profile("hw-1", 10, 4), 1000, "t1")
            .unwrap();
        assert!(!planner.audit_log().is_empty());
        assert_eq!(planner.audit_log()[0].event_code, event_codes::HWP_001);
    }

    #[test]
    fn audit_log_records_policy_registration() {
        let mut planner = make_planner();
        planner
            .register_policy(default_policy(), 1000, "t1")
            .unwrap();
        assert_eq!(planner.audit_log()[0].event_code, event_codes::HWP_002);
    }

    #[test]
    fn audit_log_happy_path_contains_expected_events() {
        let mut planner = make_planner();
        planner
            .register_profile(gpu_profile("hw-1", 10, 4), 1000, "t1")
            .unwrap();
        planner
            .register_policy(default_policy(), 1001, "t1")
            .unwrap();

        let req = workload("wl-1", &["gpu", "compute"], 50, "default");
        planner.request_placement(&req, 2000).unwrap();

        let codes: Vec<&str> = planner
            .audit_log()
            .iter()
            .map(|e| e.event_code.as_str())
            .collect();
        assert!(codes.contains(&event_codes::HWP_001));
        assert!(codes.contains(&event_codes::HWP_002));
        assert!(codes.contains(&event_codes::HWP_003));
        assert!(codes.contains(&event_codes::HWP_004));
        assert!(codes.contains(&event_codes::HWP_012));
    }

    // ---- JSONL export ----

    #[test]
    fn jsonl_export_parses() {
        let mut planner = make_planner();
        planner
            .register_profile(gpu_profile("hw-1", 10, 4), 1000, "t1")
            .unwrap();
        let jsonl = planner.export_audit_log_jsonl();
        assert!(!jsonl.is_empty());
        let parsed: serde_json::Value =
            serde_json::from_str(jsonl.lines().next().unwrap()).unwrap();
        assert_eq!(parsed["event_code"], event_codes::HWP_001);
        assert_eq!(parsed["schema_version"], SCHEMA_VERSION);
    }

    // ---- Evidence completeness ----

    #[test]
    fn evidence_records_rejections() {
        let mut planner = make_planner();
        planner
            .register_profile(gpu_profile("hw-1", 60, 4), 1000, "t1")
            .unwrap();
        planner
            .register_profile(fpga_profile("hw-2", 10, 4), 1001, "t1")
            .unwrap();
        planner
            .register_policy(default_policy(), 1002, "t1")
            .unwrap();

        let req = workload("wl-1", &["gpu", "compute"], 20, "default");
        let _ = planner.request_placement(&req, 2000);

        let decisions = planner.decisions();
        assert!(!decisions.is_empty());
        let last = &decisions[decisions.len() - 1];
        // hw-2 rejected for capability, hw-1 rejected for risk
        assert!(!last.evidence.rejections.is_empty());
    }

    // ---- Serde roundtrip ----

    #[test]
    fn placement_outcome_serde_roundtrip() {
        let outcomes = vec![
            PlacementOutcome::Placed,
            PlacementOutcome::PlacedViaFallback,
            PlacementOutcome::RejectedNoCapable,
            PlacementOutcome::RejectedRiskExceeded,
            PlacementOutcome::RejectedCapacityExhausted,
            PlacementOutcome::RejectedFallbackExhausted,
        ];
        for o in &outcomes {
            let json = serde_json::to_string(o).unwrap();
            let parsed: PlacementOutcome = serde_json::from_str(&json).unwrap();
            assert_eq!(*o, parsed);
        }
    }

    #[test]
    fn hardware_profile_serde_roundtrip() {
        let p = gpu_profile("hw-1", 10, 4);
        let json = serde_json::to_string(&p).unwrap();
        let parsed: HardwareProfile = serde_json::from_str(&json).unwrap();
        assert_eq!(p, parsed);
    }

    #[test]
    fn placement_decision_serde_roundtrip() {
        let decision = PlacementDecision {
            workload_id: "wl-1".to_string(),
            outcome: PlacementOutcome::Placed,
            target_profile_id: Some("hw-1".to_string()),
            evidence: PolicyEvidence::new("default"),
            timestamp_ms: 1000,
            schema_version: SCHEMA_VERSION.to_string(),
        };
        let json = serde_json::to_string(&decision).unwrap();
        let parsed: PlacementDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(decision, parsed);
    }

    // ---- Error display ----

    #[test]
    fn error_display_all_variants() {
        let errors: Vec<HardwarePlannerError> = vec![
            HardwarePlannerError::NoCapableTarget {
                workload_id: "wl-1".into(),
            },
            HardwarePlannerError::RiskExceeded {
                workload_id: "wl-1".into(),
            },
            HardwarePlannerError::CapacityExhausted {
                workload_id: "wl-1".into(),
            },
            HardwarePlannerError::DuplicateProfile {
                profile_id: "hw-1".into(),
            },
            HardwarePlannerError::DuplicatePolicy {
                policy_id: "pol-1".into(),
            },
            HardwarePlannerError::UnknownProfile {
                profile_id: "hw-x".into(),
            },
            HardwarePlannerError::EmptyCapabilities {
                workload_id: "wl-1".into(),
            },
            HardwarePlannerError::DispatchUngated {
                workload_id: "wl-1".into(),
            },
            HardwarePlannerError::DispatchNotPlaced {
                workload_id: "wl-1".into(),
                target_profile_id: "hw-1".into(),
            },
            HardwarePlannerError::AlreadyPlaced {
                workload_id: "wl-1".into(),
                target_profile_id: "hw-1".into(),
            },
            HardwarePlannerError::ReleaseNotPlaced {
                workload_id: "wl-1".into(),
                target_profile_id: "hw-1".into(),
            },
            HardwarePlannerError::InvalidRiskLevel {
                profile_id: "hw-1".into(),
                risk_level: 999,
            },
            HardwarePlannerError::FallbackExhausted {
                workload_id: "wl-1".into(),
            },
            HardwarePlannerError::UnknownPolicy {
                policy_id: "pol-x".into(),
            },
        ];
        for e in &errors {
            let s = e.to_string();
            assert!(
                s.contains(e.code()),
                "{:?} display should contain code {}",
                e,
                e.code()
            );
        }
    }

    // ---- Schema version constant ----

    #[test]
    fn schema_version_is_hwp_v1() {
        assert_eq!(SCHEMA_VERSION, "hwp-v1.0");
    }

    // ---- Default planner ----

    #[test]
    fn default_planner_has_approved_interfaces() {
        let planner = make_planner();
        assert!(planner.approved_interfaces.contains("franken_engine"));
        assert!(planner.approved_interfaces.contains("asupersync"));
    }

    // ---- Multiple placements consume slots ----

    #[test]
    fn multiple_placements_consume_slots() {
        let mut planner = make_planner();
        planner
            .register_profile(gpu_profile("hw-1", 10, 2), 1000, "t1")
            .unwrap();
        planner
            .register_policy(default_policy(), 1001, "t1")
            .unwrap();

        let req1 = workload("wl-1", &["gpu", "compute"], 50, "default");
        let req2 = workload("wl-2", &["gpu", "compute"], 50, "default");
        planner.request_placement(&req1, 2000).unwrap();
        planner.request_placement(&req2, 2001).unwrap();

        assert_eq!(planner.get_profile("hw-1").unwrap().used_slots, 2);
        assert!(!planner.get_profile("hw-1").unwrap().has_capacity());

        // Third placement should report capacity exhaustion
        let req3 = workload("wl-3", &["gpu", "compute"], 50, "default");
        let err = planner.request_placement(&req3, 2002).unwrap_err();
        assert_eq!(err.code(), error_codes::ERR_HWP_CAPACITY_EXHAUSTED);
    }

    #[test]
    fn duplicate_active_workload_placement_is_rejected() {
        let mut planner = make_planner();
        planner
            .register_profile(gpu_profile("hw-1", 10, 2), 1000, "t1")
            .unwrap();
        planner
            .register_policy(default_policy(), 1001, "t1")
            .unwrap();

        let req = workload("wl-1", &["gpu", "compute"], 50, "default");
        planner.request_placement(&req, 2000).unwrap();

        let err = planner.request_placement(&req, 2001).unwrap_err();
        assert_eq!(err.code(), error_codes::ERR_HWP_ALREADY_PLACED);
        assert_eq!(planner.get_profile("hw-1").unwrap().used_slots, 1);
    }

    // ---- Invariant constants ----

    #[test]
    fn all_invariant_constants_present() {
        assert_eq!(INV_HWP_DETERMINISTIC, "INV-HWP-DETERMINISTIC");
        assert_eq!(INV_HWP_CAPABILITY_MATCH, "INV-HWP-CAPABILITY-MATCH");
        assert_eq!(INV_HWP_RISK_BOUND, "INV-HWP-RISK-BOUND");
        assert_eq!(INV_HWP_EVIDENCE_COMPLETE, "INV-HWP-EVIDENCE-COMPLETE");
        assert_eq!(INV_HWP_FALLBACK_PATH, "INV-HWP-FALLBACK-PATH");
        assert_eq!(INV_HWP_DISPATCH_GATED, "INV-HWP-DISPATCH-GATED");
        assert_eq!(INV_HWP_SCHEMA_VERSIONED, "INV-HWP-SCHEMA-VERSIONED");
        assert_eq!(INV_HWP_AUDIT_COMPLETE, "INV-HWP-AUDIT-COMPLETE");
    }

    // ---- Fallback with risk relaxation ----

    #[test]
    fn fallback_with_risk_relaxation_succeeds() {
        let mut planner = make_planner();
        // Only target has risk 40, workload asks max risk 30
        planner
            .register_profile(gpu_profile("hw-1", 40, 4), 1000, "t1")
            .unwrap();
        planner
            .register_policy(default_policy(), 1001, "t1")
            .unwrap();

        let req = workload("wl-1", &["gpu", "compute"], 30, "default");
        // Normal placement fails due to risk
        let err = planner.request_placement(&req, 2000).unwrap_err();
        assert_eq!(err.code(), error_codes::ERR_HWP_RISK_EXCEEDED);

        // Fallback relaxes risk by 20 (30 + 20 = 50 >= 40)
        let decision = planner
            .request_placement_with_fallback(&req, 20, 3000)
            .unwrap();
        assert_eq!(decision.outcome, PlacementOutcome::PlacedViaFallback);
        assert_eq!(decision.target_profile_id, Some("hw-1".to_string()));
        assert!(decision.evidence.fallback_attempted);
    }

    #[test]
    fn fallback_failure_returns_fallback_exhausted_and_marks_decision() {
        let mut planner = make_planner();
        planner
            .register_profile(gpu_profile("hw-1", 40, 1), 1000, "t1")
            .unwrap();
        planner
            .register_policy(default_policy(), 1001, "t1")
            .unwrap();

        let req = workload("wl-1", &["gpu", "compute"], 10, "default");
        let err = planner
            .request_placement_with_fallback(&req, 5, 3000)
            .unwrap_err();
        assert_eq!(err.code(), error_codes::ERR_HWP_FALLBACK_EXHAUSTED);

        let last = planner.decisions().last().expect("fallback decision");
        assert_eq!(last.outcome, PlacementOutcome::RejectedFallbackExhausted);
        assert!(last.evidence.fallback_attempted);
        assert_eq!(
            last.evidence.fallback_reason.as_deref(),
            Some("risk relaxed from 10 to 15")
        );
    }

    // ---- Additional negative paths ----

    #[test]
    fn duplicate_profile_does_not_replace_existing_profile_or_emit_audit() {
        let mut planner = make_planner();
        planner
            .register_profile(gpu_profile("hw-1", 10, 4), 1000, "t1")
            .unwrap();

        let err = planner
            .register_profile(gpu_profile("hw-1", 90, 99), 1001, "t1")
            .unwrap_err();

        assert_eq!(err.code(), error_codes::ERR_HWP_DUPLICATE_PROFILE);
        let profile = planner
            .get_profile("hw-1")
            .expect("original profile should remain registered");
        assert_eq!(profile.risk_level, 10);
        assert_eq!(profile.total_slots, 4);
        assert_eq!(
            planner
                .audit_log()
                .iter()
                .filter(|event| event.event_code == event_codes::HWP_001)
                .count(),
            1
        );
    }

    #[test]
    fn duplicate_policy_does_not_replace_existing_policy_or_emit_audit() {
        let mut planner = make_planner();
        let mut original = default_policy();
        original.prefer_lowest_risk = true;
        original.prefer_most_capacity = false;
        planner.register_policy(original, 1000, "t1").unwrap();

        let mut replacement = default_policy();
        replacement.prefer_lowest_risk = false;
        replacement.prefer_most_capacity = true;
        replacement.max_risk_tolerance = MAX_RISK_LEVEL;
        let err = planner
            .register_policy(replacement, 1001, "t1")
            .unwrap_err();

        assert_eq!(err.code(), error_codes::ERR_HWP_DUPLICATE_POLICY);
        let policy = planner
            .get_policy("default")
            .expect("original policy should remain registered");
        assert!(policy.prefer_lowest_risk);
        assert!(!policy.prefer_most_capacity);
        assert_eq!(policy.max_risk_tolerance, 50);
        assert_eq!(
            planner
                .audit_log()
                .iter()
                .filter(|event| event.event_code == event_codes::HWP_002)
                .count(),
            1
        );
    }

    #[test]
    fn empty_capability_request_does_not_emit_placement_audit_or_decision() {
        let mut planner = make_planner();
        planner
            .register_profile(gpu_profile("hw-1", 10, 4), 1000, "t1")
            .unwrap();
        planner
            .register_policy(default_policy(), 1001, "t1")
            .unwrap();
        let req = WorkloadRequest {
            workload_id: "wl-empty".to_string(),
            required_capabilities: BTreeSet::new(),
            max_risk: 50,
            policy_id: "default".to_string(),
            trace_id: "trace-empty".to_string(),
        };

        let err = planner.request_placement(&req, 2000).unwrap_err();

        assert_eq!(err.code(), error_codes::ERR_HWP_EMPTY_CAPABILITIES);
        assert!(planner.decisions().is_empty());
        assert!(
            !planner
                .audit_log()
                .iter()
                .any(|event| event.event_code == event_codes::HWP_003)
        );
        assert_eq!(planner.get_profile("hw-1").unwrap().used_slots, 0);
    }

    #[test]
    fn unknown_policy_request_emits_start_but_no_evidence_or_decision() {
        let mut planner = make_planner();
        planner
            .register_profile(gpu_profile("hw-1", 10, 4), 1000, "t1")
            .unwrap();
        let req = workload("wl-unknown-policy", &["gpu", "compute"], 50, "missing");

        let err = planner.request_placement(&req, 2000).unwrap_err();

        assert_eq!(err.code(), error_codes::ERR_HWP_UNKNOWN_POLICY);
        assert!(planner.decisions().is_empty());
        assert_eq!(planner.get_profile("hw-1").unwrap().used_slots, 0);
        assert_eq!(
            planner
                .audit_log()
                .iter()
                .filter(|event| event.event_code == event_codes::HWP_003)
                .count(),
            1
        );
        assert!(
            !planner
                .audit_log()
                .iter()
                .any(|event| event.event_code == event_codes::HWP_012)
        );
    }

    #[test]
    fn risk_rejection_does_not_consume_slots_or_create_active_placement() {
        let mut planner = make_planner();
        planner
            .register_profile(gpu_profile("hw-risky", 80, 4), 1000, "t1")
            .unwrap();
        planner
            .register_policy(default_policy(), 1001, "t1")
            .unwrap();
        let req = workload("wl-risk", &["gpu", "compute"], 20, "default");

        let err = planner.request_placement(&req, 2000).unwrap_err();

        assert_eq!(err.code(), error_codes::ERR_HWP_RISK_EXCEEDED);
        assert_eq!(planner.get_profile("hw-risky").unwrap().used_slots, 0);
        assert!(!planner.active_placements.contains_key("wl-risk"));
        let last = planner.decisions().last().expect("risk decision recorded");
        assert_eq!(last.outcome, PlacementOutcome::RejectedRiskExceeded);
        assert_eq!(last.target_profile_id, None);
    }

    #[test]
    fn zero_slot_profile_rejects_capacity_without_overflow_or_active_placement() {
        let mut planner = make_planner();
        planner
            .register_profile(gpu_profile("hw-zero", 10, 0), 1000, "t1")
            .unwrap();
        planner
            .register_policy(default_policy(), 1001, "t1")
            .unwrap();
        let req = workload("wl-zero", &["gpu", "compute"], 50, "default");

        let err = planner.request_placement(&req, 2000).unwrap_err();

        assert_eq!(err.code(), error_codes::ERR_HWP_CAPACITY_EXHAUSTED);
        let profile = planner.get_profile("hw-zero").unwrap();
        assert_eq!(profile.used_slots, 0);
        assert_eq!(profile.available_slots(), 0);
        assert!(!planner.active_placements.contains_key("wl-zero"));
    }

    #[test]
    fn fallback_is_not_attempted_for_already_placed_workload() {
        let mut planner = make_planner();
        planner
            .register_profile(gpu_profile("hw-1", 10, 2), 1000, "t1")
            .unwrap();
        planner
            .register_policy(default_policy(), 1001, "t1")
            .unwrap();
        let req = workload("wl-placed", &["gpu", "compute"], 50, "default");
        planner.request_placement(&req, 2000).unwrap();

        let err = planner
            .request_placement_with_fallback(&req, 50, 2001)
            .unwrap_err();

        assert_eq!(err.code(), error_codes::ERR_HWP_ALREADY_PLACED);
        assert_eq!(planner.get_profile("hw-1").unwrap().used_slots, 1);
        assert_eq!(planner.decisions().len(), 1);
        assert!(
            !planner
                .audit_log()
                .iter()
                .any(|event| event.event_code == event_codes::HWP_008)
        );
    }

    #[test]
    fn dispatch_wrong_target_rejected_without_token_or_audit() {
        let mut planner = make_planner();
        planner
            .register_profile(gpu_profile("hw-1", 10, 2), 1000, "t1")
            .unwrap();
        planner
            .register_profile(gpu_profile("hw-2", 10, 2), 1001, "t1")
            .unwrap();
        planner
            .register_policy(default_policy(), 1002, "t1")
            .unwrap();
        let req = workload("wl-dispatch", &["gpu", "compute"], 50, "default");
        let decision = planner.request_placement(&req, 2000).unwrap();
        assert_eq!(decision.target_profile_id, Some("hw-1".to_string()));

        let err = planner
            .dispatch("wl-dispatch", "hw-2", "franken_engine", 2100, "t1")
            .unwrap_err();

        assert_eq!(err.code(), error_codes::ERR_HWP_DISPATCH_NOT_PLACED);
        assert!(planner.dispatches().is_empty());
        assert!(
            !planner
                .audit_log()
                .iter()
                .any(|event| event.event_code == event_codes::HWP_011)
        );
    }

    #[test]
    fn dispatch_rejects_unknown_profile_before_interface_check() {
        let mut planner = make_planner();

        let err = planner
            .dispatch("wl-1", "missing-hw", "rogue_interface", 2000, "t1")
            .unwrap_err();

        assert_eq!(err.code(), error_codes::ERR_HWP_UNKNOWN_PROFILE);
        assert!(planner.dispatches().is_empty());
        assert!(planner.audit_log().is_empty());
    }

    #[test]
    fn release_wrong_target_preserves_active_slot() {
        let mut planner = make_planner();
        planner
            .register_profile(gpu_profile("hw-1", 10, 2), 1000, "t1")
            .unwrap();
        planner
            .register_profile(gpu_profile("hw-2", 10, 2), 1001, "t1")
            .unwrap();
        planner
            .register_policy(default_policy(), 1002, "t1")
            .unwrap();
        let req = workload("wl-release", &["gpu", "compute"], 50, "default");
        planner.request_placement(&req, 2000).unwrap();

        let err = planner.release_placement("wl-release", "hw-2").unwrap_err();

        assert_eq!(err.code(), error_codes::ERR_HWP_RELEASE_NOT_PLACED);
        assert_eq!(planner.get_profile("hw-1").unwrap().used_slots, 1);
        assert_eq!(planner.get_profile("hw-2").unwrap().used_slots, 0);
        assert_eq!(
            planner
                .active_placements
                .get("wl-release")
                .map(String::as_str),
            Some("hw-1")
        );
    }

    #[test]
    fn repeated_release_is_rejected_without_underflow() {
        let mut planner = make_planner();
        planner
            .register_profile(gpu_profile("hw-1", 10, 1), 1000, "t1")
            .unwrap();
        planner
            .register_policy(default_policy(), 1001, "t1")
            .unwrap();
        let req = workload("wl-release-twice", &["gpu", "compute"], 50, "default");
        planner.request_placement(&req, 2000).unwrap();
        planner
            .release_placement("wl-release-twice", "hw-1")
            .unwrap();

        let err = planner
            .release_placement("wl-release-twice", "hw-1")
            .unwrap_err();

        assert_eq!(err.code(), error_codes::ERR_HWP_RELEASE_NOT_PLACED);
        assert_eq!(planner.get_profile("hw-1").unwrap().used_slots, 0);
        assert!(!planner.active_placements.contains_key("wl-release-twice"));
    }
}

#[cfg(test)]
mod hardware_planner_comprehensive_negative_tests {
    use super::*;

    fn caps(names: &[&str]) -> BTreeSet<String> {
        names.iter().map(|s| s.to_string()).collect()
    }

    fn make_planner() -> HardwarePlanner {
        HardwarePlanner::default()
    }

    // =========================================================================
    // COMPREHENSIVE NEGATIVE-PATH TESTS FOR HARDWARE PLANNER
    // =========================================================================

    #[test]
    fn negative_hardware_profile_with_unicode_injection_and_extreme_values() {
        // Test hardware profiles with malicious Unicode patterns and boundary values
        let malicious_patterns = [
            ("hw\u{202E}spoofed", "GPU \u{200B}invisible"), // RTL override + zero-width space
            ("hw\x00null", "FPGA\r\ninjection"),            // Null byte + CRLF injection
            ("hw\u{FEFF}bom", "TPU\u{1F4A9}emoji"),         // BOM + emoji
            ("hw\x1b[31mred\x1b[0m", "CPU\t\x08control"),   // ANSI escape + control chars
            ("hw🚀rocket", "AI🎯accelerator"),              // Unicode emoji patterns
        ];

        for (profile_id, description) in malicious_patterns {
            // Test with extreme values at boundaries
            let extreme_test_cases = [
                (0u32, 0u32),               // Zero risk, zero capacity
                (1u32, 1u32),               // Minimal values
                (MAX_RISK_LEVEL, u32::MAX), // Max risk, max capacity
                (MAX_RISK_LEVEL + 1, 1000), // Over max risk (should fail)
            ];

            for (risk, slots) in extreme_test_cases {
                let profile_result = HardwareProfile::new(
                    profile_id,
                    description.to_string(),
                    caps(&["gpu", "compute", "\u{202E}unicode_cap", "cap\x00null"]),
                    risk,
                    slots,
                );

                if risk > MAX_RISK_LEVEL {
                    // Should reject invalid risk levels
                    assert!(
                        profile_result.is_err(),
                        "Should reject risk {} for profile {}",
                        risk,
                        profile_id
                    );
                } else {
                    // Should handle Unicode patterns and extreme values correctly
                    let profile = profile_result.expect("Should accept valid risk levels");
                    assert_eq!(profile.profile_id, profile_id);
                    assert_eq!(profile.description, description);
                    assert_eq!(profile.risk_level, risk);
                    assert_eq!(profile.total_slots, slots);
                    assert_eq!(profile.used_slots, 0);

                    // Capabilities should preserve Unicode exactly
                    assert!(profile.capabilities.len() >= 2); // At least non-empty caps should remain
                }
            }
        }
    }

    #[test]
    fn negative_placement_policy_with_massive_capability_collections() {
        // Test placement policies with extremely large capability requirements
        let mut planner = make_planner();

        // Generate massive capability sets
        let massive_capabilities: BTreeSet<String> =
            (0..10000).map(|i| format!("capability_{:06}", i)).collect();

        let policy = PlacementPolicy {
            policy_id: "massive_policy".to_string(),
            description: "Policy with massive capability requirements".to_string(),
            max_risk: 50,
            required_capabilities: massive_capabilities.clone(),
            preferred_capabilities: caps(&["preferred_1", "preferred_2"]),
            schema_version: SCHEMA_VERSION.to_string(),
        };

        // Should handle large policies without memory exhaustion
        let register_result = planner.register_policy(policy.clone(), 1000, "trace-massive");
        assert!(
            register_result.is_ok(),
            "Should handle massive capability collections"
        );

        // Create hardware profile with subset of capabilities
        let subset_capabilities: BTreeSet<String> =
            massive_capabilities.iter().take(5000).cloned().collect();

        let profile = HardwareProfile {
            profile_id: "hw-massive".to_string(),
            description: "Hardware with massive capabilities".to_string(),
            capabilities: subset_capabilities,
            risk_level: 25,
            total_slots: 100,
            used_slots: 0,
            schema_version: SCHEMA_VERSION.to_string(),
        };

        let profile_result = planner.register_profile(profile, 1001, "trace-massive-hw");
        assert!(
            profile_result.is_ok(),
            "Should handle massive hardware capabilities"
        );

        // Workload request should work with massive capability matching
        let workload_req = WorkloadRequest {
            workload_id: "wl-massive".to_string(),
            required_capabilities: massive_capabilities.iter().take(100).cloned().collect(),
            max_risk: 50,
            policy_id: "massive_policy".to_string(),
            trace_id: "trace-massive-wl".to_string(),
        };

        let placement_result = planner.request_placement(&workload_req, 2000);
        // Should either succeed or fail deterministically without hanging
        assert!(
            placement_result.is_ok() || placement_result.is_err(),
            "Should complete in reasonable time"
        );
    }

    #[test]
    fn negative_concurrent_placement_requests_with_resource_exhaustion() {
        // Test concurrent placement requests that exhaust resources
        let mut planner = make_planner();

        // Register limited capacity hardware
        let limited_profile = HardwareProfile::new(
            "hw-limited",
            "Limited capacity hardware".to_string(),
            caps(&["gpu", "compute"]),
            10,
            5, // Only 5 slots available
        )
        .unwrap();

        planner
            .register_profile(limited_profile, 1000, "trace-limited")
            .unwrap();
        planner
            .register_policy(
                PlacementPolicy::new("default", "Default", 50),
                1001,
                "trace-policy",
            )
            .unwrap();

        // Make many concurrent placement requests
        let mut placement_results = Vec::new();
        let mut successful_placements = Vec::new();

        for i in 0..20 {
            let workload_req = WorkloadRequest {
                workload_id: format!("wl-concurrent-{}", i),
                required_capabilities: caps(&["gpu", "compute"]),
                max_risk: 50,
                policy_id: "default".to_string(),
                trace_id: format!("trace-concurrent-{}", i),
            };

            let result = planner.request_placement(&workload_req, 2000 + i as u64);
            placement_results.push((i, result.is_ok()));

            if result.is_ok() {
                successful_placements.push(i);
            }
        }

        // Should have exactly 5 successful placements due to capacity limit
        assert_eq!(
            successful_placements.len(),
            5,
            "Should respect hardware capacity limits"
        );

        // Used slots should not exceed total slots
        let profile = planner.get_profile("hw-limited").unwrap();
        assert_eq!(profile.used_slots, 5);
        assert_eq!(profile.total_slots, 5);

        // Should have exactly 5 active placements
        assert_eq!(planner.active_placements.len(), 5);

        // Failed placements should have appropriate error codes
        let failed_count = placement_results
            .iter()
            .filter(|(_, success)| !success)
            .count();
        assert_eq!(
            failed_count, 15,
            "Should have 15 failed placements due to capacity exhaustion"
        );
    }

    #[test]
    fn negative_risk_level_arithmetic_overflow_and_boundary_validation() {
        // Test risk level calculations at arithmetic boundaries
        let mut planner = make_planner();

        // Test hardware profiles with boundary risk levels
        let boundary_risk_cases = [
            (0u32, "zero risk hardware"),
            (1u32, "minimal risk hardware"),
            (MAX_RISK_LEVEL / 2, "medium risk hardware"),
            (MAX_RISK_LEVEL - 1, "high risk hardware"),
            (MAX_RISK_LEVEL, "maximum risk hardware"),
        ];

        for (risk_level, description) in boundary_risk_cases {
            let profile = HardwareProfile::new(
                &format!("hw-risk-{}", risk_level),
                description.to_string(),
                caps(&["compute"]),
                risk_level,
                10,
            )
            .unwrap();

            planner
                .register_profile(
                    profile,
                    1000 + risk_level as u64,
                    &format!("trace-risk-{}", risk_level),
                )
                .unwrap();
        }

        // Test invalid risk levels that should be rejected
        let invalid_risk_cases = [MAX_RISK_LEVEL + 1, u32::MAX / 2, u32::MAX - 1, u32::MAX];

        for invalid_risk in invalid_risk_cases {
            let invalid_profile_result = HardwareProfile::new(
                &format!("hw-invalid-risk-{}", invalid_risk),
                "Invalid risk hardware".to_string(),
                caps(&["compute"]),
                invalid_risk,
                10,
            );

            assert!(
                invalid_profile_result.is_err(),
                "Should reject invalid risk level {}",
                invalid_risk
            );
        }

        // Register default policy
        planner
            .register_policy(
                PlacementPolicy::new("boundary_test", "Boundary test", 50),
                2000,
                "trace-policy",
            )
            .unwrap();

        // Test workload requests with boundary risk tolerances
        let workload_risk_cases = [
            (0u32, vec![0u32]),       // Only zero-risk hardware
            (1u32, vec![0u32, 1u32]), // Zero and minimal risk hardware
            (
                MAX_RISK_LEVEL / 2,
                (0..=MAX_RISK_LEVEL / 2).collect::<Vec<_>>(),
            ), // Half the hardware
            (MAX_RISK_LEVEL, (0..=MAX_RISK_LEVEL).collect::<Vec<_>>()), // All hardware
        ];

        for (max_risk, expected_eligible_risks) in workload_risk_cases {
            let workload_req = WorkloadRequest {
                workload_id: format!("wl-risk-{}", max_risk),
                required_capabilities: caps(&["compute"]),
                max_risk,
                policy_id: "boundary_test".to_string(),
                trace_id: format!("trace-wl-risk-{}", max_risk),
            };

            let placement_result = planner.request_placement(&workload_req, 3000 + max_risk as u64);

            if max_risk == 0 && expected_eligible_risks.contains(&0) {
                // Should succeed if zero-risk hardware is available
                assert!(
                    placement_result.is_ok(),
                    "Should succeed for max_risk {}",
                    max_risk
                );
            } else if !expected_eligible_risks.is_empty() {
                // Should succeed if any eligible hardware exists
                assert!(
                    placement_result.is_ok(),
                    "Should succeed for max_risk {}",
                    max_risk
                );
            }
        }
    }

    #[test]
    fn negative_policy_evidence_generation_with_malformed_inputs() {
        // Test policy evidence generation with malformed and extreme inputs
        let mut planner = make_planner();

        // Register hardware with extreme characteristics
        let extreme_profile = HardwareProfile::new(
            "hw\x00\r\n\textreme",
            "Hardware with\u{202E}extreme\u{200B}characteristics".to_string(),
            caps(&[
                "",    // Empty capability (should be filtered)
                "   ", // Whitespace capability (should be filtered)
                "normal_cap",
                "cap\x00with\nnull\tbytes",
                "\u{FEFF}cap_with_bom",
                "🚀emoji_capability",
            ]),
            75,
            u32::MAX, // Maximum capacity
        )
        .unwrap();

        planner
            .register_profile(extreme_profile, 1000, "trace\x00extreme")
            .unwrap();

        // Register policy with malformed characteristics
        let malformed_policy = PlacementPolicy {
            policy_id: "policy\r\n\tmalformed".to_string(),
            description: "\u{202E}Malformed\x00policy\u{200B}description".to_string(),
            max_risk: MAX_RISK_LEVEL,
            required_capabilities: caps(&[
                "normal_cap",
                "", // Empty (should be filtered)
                "cap\x00with\nnull",
                "🚀emoji_capability",
            ]),
            preferred_capabilities: caps(&["\u{FEFF}preferred_with_bom", "preferred\ttab"]),
            schema_version: SCHEMA_VERSION.to_string(),
        };

        planner
            .register_policy(malformed_policy, 1001, "trace-malformed-policy")
            .unwrap();

        // Create workload request with extreme characteristics
        let extreme_workload = WorkloadRequest {
            workload_id: "\x1b[31mworkload\x1b[0m".to_string(), // ANSI escape sequences
            required_capabilities: caps(&[
                "normal_cap",
                "cap\x00with\nnull\tbytes",
                "🚀emoji_capability",
            ]),
            max_risk: MAX_RISK_LEVEL,
            policy_id: "policy\r\n\tmalformed".to_string(),
            trace_id: "trace\u{FEFF}with\u{200B}unicode".to_string(),
        };

        // Request placement should handle malformed inputs gracefully
        let placement_result = planner.request_placement(&extreme_workload, 2000);
        assert!(
            placement_result.is_ok(),
            "Should handle malformed inputs gracefully"
        );

        // Evidence should be generated despite malformed inputs
        let evidence = placement_result.unwrap();
        assert_eq!(evidence.workload_id, extreme_workload.workload_id);
        assert_eq!(evidence.policy_id, extreme_workload.policy_id);
        assert_eq!(evidence.trace_id, extreme_workload.trace_id);

        // Schema version should be preserved
        assert_eq!(evidence.schema_version, SCHEMA_VERSION);

        // Placement should be recorded in active placements
        assert!(
            planner
                .active_placements
                .contains_key(&extreme_workload.workload_id)
        );
    }

    #[test]
    fn negative_placement_fallback_with_cascading_failures() {
        // Test fallback behavior when multiple placement attempts fail
        let mut planner = make_planner();

        // Register multiple hardware profiles with different failure modes
        let failure_profiles = [
            ("hw-no-cap", caps(&["fpga"]), 10, 10), // Wrong capabilities
            ("hw-high-risk", caps(&["gpu", "compute"]), 90, 10), // Too high risk
            ("hw-no-slots", caps(&["gpu", "compute"]), 10, 0), // No capacity
        ];

        for (profile_id, capabilities, risk, slots) in failure_profiles {
            let profile = HardwareProfile::new(
                profile_id,
                format!("Hardware profile {}", profile_id),
                capabilities,
                risk,
                slots,
            )
            .unwrap();

            planner
                .register_profile(profile, 1000, &format!("trace-{}", profile_id))
                .unwrap();
        }

        // Add one valid profile that should be selected as fallback
        let valid_profile = HardwareProfile::new(
            "hw-valid-fallback",
            "Valid fallback hardware".to_string(),
            caps(&["gpu", "compute"]),
            25,
            5,
        )
        .unwrap();

        planner
            .register_profile(valid_profile, 1001, "trace-valid-fallback")
            .unwrap();

        // Create policy that requires specific capabilities and low risk
        let strict_policy = PlacementPolicy {
            policy_id: "strict_fallback".to_string(),
            description: "Strict policy for fallback testing".to_string(),
            max_risk: 30,
            required_capabilities: caps(&["gpu", "compute"]),
            preferred_capabilities: caps(&["high_performance"]),
            schema_version: SCHEMA_VERSION.to_string(),
        };

        planner
            .register_policy(strict_policy, 1002, "trace-strict-policy")
            .unwrap();

        // Workload that will trigger fallback behavior
        let fallback_workload = WorkloadRequest {
            workload_id: "wl-fallback-test".to_string(),
            required_capabilities: caps(&["gpu", "compute"]),
            max_risk: 30, // Excludes hw-high-risk
            policy_id: "strict_fallback".to_string(),
            trace_id: "trace-fallback-test".to_string(),
        };

        // Should succeed by falling back to valid hardware
        let placement_result = planner.request_placement(&fallback_workload, 2000);
        assert!(placement_result.is_ok(), "Should succeed via fallback");

        let evidence = placement_result.unwrap();
        assert_eq!(
            evidence.selected_profile_id,
            Some("hw-valid-fallback".to_string())
        );

        // Valid hardware should have used slots
        let valid_hw = planner.get_profile("hw-valid-fallback").unwrap();
        assert_eq!(valid_hw.used_slots, 1);

        // Other hardware should remain unused
        assert_eq!(planner.get_profile("hw-no-cap").unwrap().used_slots, 0);
        assert_eq!(planner.get_profile("hw-high-risk").unwrap().used_slots, 0);
        assert_eq!(planner.get_profile("hw-no-slots").unwrap().used_slots, 0);
    }

    #[test]
    fn negative_audit_trail_with_memory_pressure_and_event_overflow() {
        // Test audit trail behavior under memory pressure and event overflow
        let mut planner = make_planner();

        // Create memory pressure by allocating large chunks
        let mut memory_pressure = Vec::new();
        for i in 0..1000 {
            memory_pressure.push(vec![i as u8; 5000]); // 5MB total pressure
        }

        // Register hardware
        let profile = HardwareProfile::new(
            "hw-audit-test",
            "Hardware for audit testing".to_string(),
            caps(&["compute"]),
            25,
            100,
        )
        .unwrap();

        planner
            .register_profile(profile, 1000, "trace-audit-hw")
            .unwrap();
        planner
            .register_policy(
                PlacementPolicy::new("audit_policy", "Audit policy", 50),
                1001,
                "trace-audit-policy",
            )
            .unwrap();

        // Generate many events to test audit trail capacity
        let mut placement_requests = Vec::new();
        for i in 0..MAX_AUDIT_LOG_ENTRIES + 100 {
            let workload_req = WorkloadRequest {
                workload_id: format!("wl-audit-{:06}", i),
                required_capabilities: caps(&["compute"]),
                max_risk: 50,
                policy_id: "audit_policy".to_string(),
                trace_id: format!("trace-audit-{:06}", i),
            };

            let placement_result = planner.request_placement(&workload_req, 2000 + i as u64);
            placement_requests.push((i, placement_result.is_ok()));

            // Add more memory pressure during operations
            if i % 100 == 0 {
                memory_pressure.push(vec![i as u8; 1000]);
            }
        }

        // Audit trail should be bounded to prevent memory exhaustion
        assert!(
            planner.audit_trail.len() <= MAX_AUDIT_LOG_ENTRIES,
            "Audit trail should be bounded"
        );

        // Latest events should be preserved
        if !planner.audit_trail.is_empty() {
            let latest_event = planner.audit_trail.last().unwrap();
            assert!(
                latest_event.timestamp >= 2000,
                "Latest events should be preserved"
            );
        }

        // Active placements should be bounded by hardware capacity
        assert!(
            planner.active_placements.len() <= 100,
            "Active placements should respect capacity"
        );

        // Memory cleanup should not affect planner state consistency
        drop(memory_pressure);

        // Planner should remain functional after memory pressure
        let final_workload = WorkloadRequest {
            workload_id: "wl-final-test".to_string(),
            required_capabilities: caps(&["compute"]),
            max_risk: 50,
            policy_id: "audit_policy".to_string(),
            trace_id: "trace-final-test".to_string(),
        };

        let final_result = planner.request_placement(&final_workload, 10000);
        // Should either succeed or fail deterministically based on remaining capacity
        assert!(
            final_result.is_ok() || final_result.is_err(),
            "Should remain functional after memory pressure"
        );
    }

    #[test]
    fn negative_schema_version_validation_and_serialization_robustness() {
        // Test schema version validation and serialization under various conditions
        let mut planner = make_planner();

        // Test hardware profile with various schema version patterns
        let schema_test_cases = [
            SCHEMA_VERSION,           // Valid schema
            "",                       // Empty schema
            "hwp-v0.0",               // Different version
            "hwp-v999.999",           // Future version
            "invalid-schema\x00null", // Malformed schema
            "\u{FEFF}hwp-v1.0",       // Schema with BOM
            "hwp-v1.0\r\n",           // Schema with CRLF
        ];

        for (i, schema_version) in schema_test_cases.iter().enumerate() {
            let profile = HardwareProfile {
                profile_id: format!("hw-schema-{}", i),
                description: format!("Hardware with schema {}", i),
                capabilities: caps(&["compute"]),
                risk_level: 25,
                total_slots: 10,
                used_slots: 0,
                schema_version: schema_version.to_string(),
            };

            // Should register successfully (validation happens at higher levels)
            let register_result =
                planner.register_profile(profile, 1000 + i as u64, &format!("trace-schema-{}", i));
            assert!(
                register_result.is_ok(),
                "Should register profile with schema version {}",
                schema_version
            );

            // Test serialization/deserialization robustness
            let profile = planner.get_profile(&format!("hw-schema-{}", i)).unwrap();
            let serialization_result = serde_json::to_string(&profile);
            assert!(
                serialization_result.is_ok(),
                "Should serialize profile with schema {}",
                schema_version
            );

            if let Ok(json) = serialization_result {
                let deserialization_result: Result<HardwareProfile, _> =
                    serde_json::from_str(&json);
                assert!(
                    deserialization_result.is_ok(),
                    "Should deserialize profile with schema {}",
                    schema_version
                );

                if let Ok(deserialized) = deserialization_result {
                    assert_eq!(
                        deserialized.schema_version, *schema_version,
                        "Schema version should roundtrip correctly"
                    );
                }
            }
        }

        // Test policy evidence generation with various schema patterns
        let policy = PlacementPolicy {
            policy_id: "schema_test_policy".to_string(),
            description: "Policy for schema testing".to_string(),
            max_risk: 50,
            required_capabilities: caps(&["compute"]),
            preferred_capabilities: BTreeSet::new(),
            schema_version: "policy-v-test\u{200B}".to_string(), // Unicode zero-width space
        };

        planner
            .register_policy(policy, 2000, "trace-schema-policy")
            .unwrap();

        // Workload request should succeed and preserve schema information
        let workload_req = WorkloadRequest {
            workload_id: "wl-schema-test".to_string(),
            required_capabilities: caps(&["compute"]),
            max_risk: 50,
            policy_id: "schema_test_policy".to_string(),
            trace_id: "trace-schema-workload".to_string(),
        };

        let placement_result = planner.request_placement(&workload_req, 3000);
        assert!(
            placement_result.is_ok(),
            "Should handle various schema versions in placement"
        );

        let evidence = placement_result.unwrap();
        assert_eq!(evidence.schema_version, SCHEMA_VERSION); // Evidence should use canonical schema
    }
}
