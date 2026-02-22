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
    pub const ERR_HWP_INVALID_RISK_LEVEL: &str = "ERR_HWP_INVALID_RISK_LEVEL";
    pub const ERR_HWP_FALLBACK_EXHAUSTED: &str = "ERR_HWP_FALLBACK_EXHAUSTED";

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
    /// Risk level outside valid range.
    InvalidRiskLevel { profile_id: String, risk_level: u32 },
    /// All fallback paths exhausted.
    FallbackExhausted { workload_id: String },
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
            Self::InvalidRiskLevel { .. } => error_codes::ERR_HWP_INVALID_RISK_LEVEL,
            Self::FallbackExhausted { .. } => error_codes::ERR_HWP_FALLBACK_EXHAUSTED,
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
        if self.profiles.contains_key(&profile.profile_id) {
            return Err(HardwarePlannerError::DuplicateProfile {
                profile_id: profile.profile_id.clone(),
            });
        }

        let pid = profile.profile_id.clone();
        self.audit_log.push(PlannerAuditEvent {
            event_code: event_codes::HWP_001.to_string(),
            workload_id: String::new(),
            profile_id: Some(pid.clone()),
            timestamp_ms,
            trace_id: trace_id.to_string(),
            detail: format!("hardware profile registered: {}", pid),
            schema_version: SCHEMA_VERSION.to_string(),
        });

        self.profiles.insert(pid.clone(), profile);
        Ok(self.profiles.get(&pid).unwrap())
    }

    /// Register a placement policy.
    /// Emits HWP-002.
    pub fn register_policy(
        &mut self,
        policy: PlacementPolicy,
        timestamp_ms: u64,
        trace_id: &str,
    ) -> Result<&PlacementPolicy, HardwarePlannerError> {
        if self.policies.contains_key(&policy.policy_id) {
            return Err(HardwarePlannerError::DuplicatePolicy {
                policy_id: policy.policy_id.clone(),
            });
        }

        let pid = policy.policy_id.clone();
        self.audit_log.push(PlannerAuditEvent {
            event_code: event_codes::HWP_002.to_string(),
            workload_id: String::new(),
            profile_id: None,
            timestamp_ms,
            trace_id: trace_id.to_string(),
            detail: format!("placement policy registered: {}", pid),
            schema_version: SCHEMA_VERSION.to_string(),
        });

        self.policies.insert(pid.clone(), policy);
        Ok(self.policies.get(&pid).unwrap())
    }

    /// Request placement for a workload.
    /// Emits HWP-003 and one of HWP-004..HWP-010.
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
        self.audit_log.push(PlannerAuditEvent {
            event_code: event_codes::HWP_003.to_string(),
            workload_id: request.workload_id.clone(),
            profile_id: None,
            timestamp_ms,
            trace_id: request.trace_id.clone(),
            detail: format!("placement requested for workload {}", request.workload_id),
            schema_version: SCHEMA_VERSION.to_string(),
        });

        let policy = self.policies.get(&request.policy_id).cloned();
        let effective_max_risk = policy
            .as_ref()
            .map(|p| p.max_risk_tolerance.min(request.max_risk))
            .unwrap_or(request.max_risk);

        let mut evidence = PolicyEvidence::new(&request.policy_id);

        // INV-HWP-DETERMINISTIC: BTreeMap iterates in sorted order
        let profile_ids: Vec<String> = self.profiles.keys().cloned().collect();
        evidence.candidates_considered = profile_ids.clone();

        // Phase 1: capability filter
        let mut capable: Vec<String> = Vec::new();
        for pid in &profile_ids {
            let prof = &self.profiles[pid];
            if prof.satisfies_capabilities(&request.required_capabilities) {
                capable.push(pid.clone());
            } else {
                evidence
                    .rejections
                    .insert(pid.clone(), "capability_mismatch".to_string());
                evidence.reasoning_chain.push(format!(
                    "rejected {}: missing capabilities {:?}",
                    pid,
                    request
                        .required_capabilities
                        .difference(&prof.capabilities)
                        .collect::<Vec<_>>()
                ));
            }
        }

        if capable.is_empty() {
            // HWP-005
            self.audit_log.push(PlannerAuditEvent {
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
            self.decisions.push(decision.clone());
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
            self.audit_log.push(PlannerAuditEvent {
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
            self.decisions.push(decision.clone());
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
            // INV-HWP-FALLBACK-PATH: attempt fallback on risk-ok targets
            // that have capacity after considering a relaxed view
            evidence.fallback_attempted = true;
            evidence.fallback_reason = Some("primary targets at capacity".to_string());

            // HWP-007 + HWP-008
            self.audit_log.push(PlannerAuditEvent {
                event_code: event_codes::HWP_007.to_string(),
                workload_id: request.workload_id.clone(),
                profile_id: None,
                timestamp_ms,
                trace_id: request.trace_id.clone(),
                detail: "all capable+risk-ok targets at capacity".to_string(),
                schema_version: SCHEMA_VERSION.to_string(),
            });
            self.audit_log.push(PlannerAuditEvent {
                event_code: event_codes::HWP_008.to_string(),
                workload_id: request.workload_id.clone(),
                profile_id: None,
                timestamp_ms,
                trace_id: request.trace_id.clone(),
                detail: "fallback path attempted".to_string(),
                schema_version: SCHEMA_VERSION.to_string(),
            });

            evidence
                .reasoning_chain
                .push("primary targets at capacity, attempting fallback".to_string());

            // Fallback: look at ALL risk-ok profiles, relax nothing -- just
            // re-check after marking contention evidence. In a real system the
            // fallback might use a secondary pool; here we model it as a
            // re-scan that always fails (since we already filtered).
            // HWP-010
            self.audit_log.push(PlannerAuditEvent {
                event_code: event_codes::HWP_010.to_string(),
                workload_id: request.workload_id.clone(),
                profile_id: None,
                timestamp_ms,
                trace_id: request.trace_id.clone(),
                detail: "fallback path exhausted".to_string(),
                schema_version: SCHEMA_VERSION.to_string(),
            });
            self.emit_evidence_event(&request.workload_id, timestamp_ms, &request.trace_id);

            evidence
                .reasoning_chain
                .push("fallback exhausted: no alternative targets with capacity".to_string());

            let decision = PlacementDecision {
                workload_id: request.workload_id.clone(),
                outcome: PlacementOutcome::RejectedFallbackExhausted,
                target_profile_id: None,
                evidence,
                timestamp_ms,
                schema_version: SCHEMA_VERSION.to_string(),
            };
            self.decisions.push(decision.clone());
            return Err(HardwarePlannerError::FallbackExhausted {
                workload_id: request.workload_id.clone(),
            });
        }

        // Phase 4: select best candidate per policy
        let selected = self.select_best(&with_capacity, policy.as_ref());
        evidence.selected_target = Some(selected.clone());
        evidence.reasoning_chain.push(format!(
            "selected {} from {} candidates",
            selected,
            with_capacity.len()
        ));

        // Allocate slot
        if let Some(prof) = self.profiles.get_mut(&selected) {
            prof.used_slots += 1;
        }

        // HWP-004
        self.audit_log.push(PlannerAuditEvent {
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
        self.decisions.push(decision.clone());
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
            | Err(HardwarePlannerError::CapacityExhausted { .. })
            | Err(HardwarePlannerError::FallbackExhausted { .. }) => {
                // HWP-008: fallback attempted
                self.audit_log.push(PlannerAuditEvent {
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
                        self.audit_log.push(PlannerAuditEvent {
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
                    Err(e) => {
                        // HWP-010
                        self.audit_log.push(PlannerAuditEvent {
                            event_code: event_codes::HWP_010.to_string(),
                            workload_id: request.workload_id.clone(),
                            profile_id: None,
                            timestamp_ms,
                            trace_id: request.trace_id.clone(),
                            detail: "fallback path exhausted after risk relaxation".to_string(),
                            schema_version: SCHEMA_VERSION.to_string(),
                        });
                        Err(e)
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

        let token = DispatchToken {
            workload_id: workload_id.to_string(),
            target_profile_id: target_profile_id.to_string(),
            approved_interface: interface.to_string(),
            timestamp_ms,
            schema_version: SCHEMA_VERSION.to_string(),
        };

        self.audit_log.push(PlannerAuditEvent {
            event_code: event_codes::HWP_011.to_string(),
            workload_id: workload_id.to_string(),
            profile_id: Some(target_profile_id.to_string()),
            timestamp_ms,
            trace_id: trace_id.to_string(),
            detail: format!("dispatched via {}", interface),
            schema_version: SCHEMA_VERSION.to_string(),
        });

        self.dispatches.push(token.clone());
        Ok(token)
    }

    /// Release a slot on a hardware profile (e.g. workload completed).
    pub fn release_slot(&mut self, profile_id: &str) -> Result<(), HardwarePlannerError> {
        let prof = self.profiles.get_mut(profile_id).ok_or_else(|| {
            HardwarePlannerError::UnknownProfile {
                profile_id: profile_id.to_string(),
            }
        })?;
        if prof.used_slots > 0 {
            prof.used_slots -= 1;
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
        if candidates.is_empty() {
            unreachable!("select_best called with empty candidates");
        }
        if candidates.len() == 1 {
            return candidates[0].clone();
        }

        let prefer_lowest_risk = policy.map_or(true, |p| p.prefer_lowest_risk);
        let prefer_most_capacity = policy.map_or(false, |p| p.prefer_most_capacity);

        let mut best = candidates[0].clone();
        let mut best_risk = self.profiles[&best].risk_level;
        let mut best_available = self.profiles[&best].available_slots();

        for pid in &candidates[1..] {
            let prof = &self.profiles[pid];
            let mut is_better = false;

            if prefer_lowest_risk && prof.risk_level < best_risk {
                is_better = true;
            } else if prefer_lowest_risk
                && prof.risk_level == best_risk
                && prefer_most_capacity
                && prof.available_slots() > best_available
            {
                is_better = true;
            } else if !prefer_lowest_risk
                && prefer_most_capacity
                && prof.available_slots() > best_available
            {
                is_better = true;
            }

            if is_better {
                best = pid.clone();
                best_risk = prof.risk_level;
                best_available = prof.available_slots();
            }
        }

        best
    }

    /// Emit an HWP-012 evidence-recorded event.
    fn emit_evidence_event(&mut self, workload_id: &str, timestamp_ms: u64, trace_id: &str) {
        self.audit_log.push(PlannerAuditEvent {
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

    // ---- Capacity exhausted with fallback ----

    #[test]
    fn placement_rejected_capacity_exhausted_fallback() {
        let mut planner = make_planner();
        let mut prof = gpu_profile("hw-1", 10, 1);
        prof.used_slots = 1; // at capacity
        planner.register_profile(prof, 1000, "t1").unwrap();
        planner
            .register_policy(default_policy(), 1001, "t1")
            .unwrap();

        let req = workload("wl-1", &["gpu", "compute"], 50, "default");
        let err = planner.request_placement(&req, 2000).unwrap_err();
        assert_eq!(err.code(), error_codes::ERR_HWP_FALLBACK_EXHAUSTED);
    }

    // ---- Empty capabilities rejected ----

    #[test]
    fn placement_rejected_empty_capabilities() {
        let mut planner = make_planner();
        let req = workload("wl-1", &[], 50, "default");
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
    fn dispatch_unknown_profile_rejected() {
        let mut planner = make_planner();
        let err = planner
            .dispatch("wl-1", "hw-nonexistent", "franken_engine", 2000, "t1")
            .unwrap_err();
        assert_eq!(err.code(), error_codes::ERR_HWP_UNKNOWN_PROFILE);
    }

    // ---- Slot release ----

    #[test]
    fn release_slot_success() {
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

        planner.release_slot("hw-1").unwrap();
        assert_eq!(planner.get_profile("hw-1").unwrap().used_slots, 0);
    }

    #[test]
    fn release_slot_unknown_profile() {
        let mut planner = make_planner();
        let err = planner.release_slot("nonexistent").unwrap_err();
        assert_eq!(err.code(), error_codes::ERR_HWP_UNKNOWN_PROFILE);
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
            HardwarePlannerError::InvalidRiskLevel {
                profile_id: "hw-1".into(),
                risk_level: 999,
            },
            HardwarePlannerError::FallbackExhausted {
                workload_id: "wl-1".into(),
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

        // Third placement should trigger fallback exhaustion
        let req3 = workload("wl-3", &["gpu", "compute"], 50, "default");
        let err = planner.request_placement(&req3, 2002).unwrap_err();
        assert_eq!(err.code(), error_codes::ERR_HWP_FALLBACK_EXHAUSTED);
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
}
