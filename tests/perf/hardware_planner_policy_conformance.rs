//! bd-2o8b: Policy conformance tests for the heterogeneous hardware planner.
//!
//! Validates that placement decisions satisfy capability/risk constraints, remain
//! reproducible from identical inputs, report policy reasoning and fallback paths
//! on resource contention, and dispatch only through approved interfaces.
//!
//! # Event Codes
//!
//! - `PLANNER_PLACEMENT_START`
//! - `PLANNER_CONSTRAINT_EVALUATED`
//! - `PLANNER_PLACEMENT_DECIDED`
//! - `PLANNER_FALLBACK_ACTIVATED`
//! - `PLANNER_DISPATCH_APPROVED`
//!
//! # Error Codes
//!
//! - `ERR_PLANNER_CONSTRAINT_VIOLATED`
//! - `ERR_PLANNER_RESOURCE_CONTENTION`
//! - `ERR_PLANNER_NO_FALLBACK`
//! - `ERR_PLANNER_DISPATCH_DENIED`
//! - `ERR_PLANNER_REPRODUCIBILITY_FAILED`
//! - `ERR_PLANNER_INTERFACE_UNAPPROVED`
//!
//! # Invariants
//!
//! - `INV-PLANNER-REPRODUCIBLE`
//! - `INV-PLANNER-CONSTRAINT-SATISFIED`
//! - `INV-PLANNER-FALLBACK-PATH`
//! - `INV-PLANNER-APPROVED-DISPATCH`

use franken_node::runtime::hardware_planner::{
    event_codes, error_codes,
    HardwarePlanner, HardwareProfile, PlacementPolicy, WorkloadRequest,
    PlacementOutcome, SCHEMA_VERSION,
    INV_PLANNER_REPRODUCIBLE, INV_PLANNER_CONSTRAINT_SATISFIED,
    INV_PLANNER_FALLBACK_PATH, INV_PLANNER_APPROVED_DISPATCH,
};
use std::collections::BTreeSet;

fn caps(names: &[&str]) -> BTreeSet<String> {
    names.iter().map(|s| s.to_string()).collect()
}

fn gpu_profile(id: &str, risk: u32, slots: u32) -> HardwareProfile {
    HardwareProfile::new(id, format!("GPU {}", id), caps(&["gpu", "compute"]), risk, slots).unwrap()
}

fn fpga_profile(id: &str, risk: u32, slots: u32) -> HardwareProfile {
    HardwareProfile::new(id, format!("FPGA {}", id), caps(&["fpga", "compute"]), risk, slots).unwrap()
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

// ---------------------------------------------------------------------------
// INV-PLANNER-REPRODUCIBLE tests
// ---------------------------------------------------------------------------

/// INV-PLANNER-REPRODUCIBLE: identical inputs yield identical placement decisions.
#[test]
fn reproducible_placement_identical_inputs() {
    let _ = INV_PLANNER_REPRODUCIBLE; // reference invariant constant
    let run = || {
        let mut planner = HardwarePlanner::default();
        planner.register_profile(gpu_profile("hw-a", 10, 4), 1000, "t1").unwrap();
        planner.register_profile(gpu_profile("hw-b", 20, 4), 1001, "t1").unwrap();
        planner.register_profile(fpga_profile("hw-c", 5, 2), 1002, "t1").unwrap();
        planner.register_policy(default_policy(), 1003, "t1").unwrap();

        let req = workload("wl-1", &["gpu", "compute"], 50, "default");
        planner.request_placement(&req, 2000).unwrap()
    };

    let d1 = run();
    let d2 = run();
    assert_eq!(d1.target_profile_id, d2.target_profile_id);
    assert_eq!(d1.outcome, d2.outcome);
    assert_eq!(d1.evidence.reasoning_chain, d2.evidence.reasoning_chain);
}

/// INV-PLANNER-REPRODUCIBLE: multiple runs with same multi-workload sequence
/// produce identical audit logs.
#[test]
fn reproducible_multi_workload_sequence() {
    let run = || {
        let mut planner = HardwarePlanner::default();
        planner.register_profile(gpu_profile("hw-1", 10, 2), 1000, "t1").unwrap();
        planner.register_profile(gpu_profile("hw-2", 30, 3), 1001, "t1").unwrap();
        planner.register_policy(default_policy(), 1002, "t1").unwrap();

        for i in 0..3 {
            let req = workload(&format!("wl-{}", i), &["gpu", "compute"], 50, "default");
            let _ = planner.request_placement(&req, 2000 + i as u64);
        }
        planner.export_audit_log_jsonl()
    };

    let log1 = run();
    let log2 = run();
    assert_eq!(log1, log2);
}

// ---------------------------------------------------------------------------
// INV-PLANNER-CONSTRAINT-SATISFIED tests
// ---------------------------------------------------------------------------

/// INV-PLANNER-CONSTRAINT-SATISFIED: capability mismatch rejects placement.
#[test]
fn constraint_capability_mismatch_rejects() {
    let _ = INV_PLANNER_CONSTRAINT_SATISFIED;
    let mut planner = HardwarePlanner::default();
    planner.register_profile(gpu_profile("hw-1", 10, 4), 1000, "t1").unwrap();
    planner.register_policy(default_policy(), 1001, "t1").unwrap();

    let req = workload("wl-1", &["fpga"], 50, "default");
    let err = planner.request_placement(&req, 2000).unwrap_err();
    assert_eq!(err.code(), error_codes::ERR_HWP_NO_CAPABLE_TARGET);
}

/// INV-PLANNER-CONSTRAINT-SATISFIED: risk exceeding tolerance rejects placement.
#[test]
fn constraint_risk_exceeded_rejects() {
    let _ = INV_PLANNER_CONSTRAINT_SATISFIED;
    let mut planner = HardwarePlanner::default();
    planner.register_profile(gpu_profile("hw-1", 60, 4), 1000, "t1").unwrap();
    planner.register_policy(default_policy(), 1001, "t1").unwrap();

    let req = workload("wl-1", &["gpu", "compute"], 20, "default");
    let err = planner.request_placement(&req, 2000).unwrap_err();
    assert_eq!(err.code(), error_codes::ERR_HWP_RISK_EXCEEDED);
}

/// INV-PLANNER-CONSTRAINT-SATISFIED: evidence records rejections for all
/// non-matching candidates.
#[test]
fn constraint_evidence_records_rejections() {
    let _ = INV_PLANNER_CONSTRAINT_SATISFIED;
    let mut planner = HardwarePlanner::default();
    planner.register_profile(gpu_profile("hw-1", 60, 4), 1000, "t1").unwrap();
    planner.register_profile(fpga_profile("hw-2", 10, 4), 1001, "t1").unwrap();
    planner.register_policy(default_policy(), 1002, "t1").unwrap();

    let req = workload("wl-1", &["gpu", "compute"], 20, "default");
    let _ = planner.request_placement(&req, 2000);

    let decisions = planner.decisions();
    assert!(!decisions.is_empty());
    let last = &decisions[decisions.len() - 1];
    // hw-2 rejected for capability, hw-1 rejected for risk
    assert!(last.evidence.rejections.len() >= 2);
}

// ---------------------------------------------------------------------------
// INV-PLANNER-FALLBACK-PATH tests
// ---------------------------------------------------------------------------

/// INV-PLANNER-FALLBACK-PATH: capacity exhaustion triggers fallback.
#[test]
fn fallback_triggered_on_capacity_exhaustion() {
    let _ = INV_PLANNER_FALLBACK_PATH;
    let mut planner = HardwarePlanner::default();
    let mut prof = gpu_profile("hw-1", 10, 1);
    prof.used_slots = 1; // at capacity
    planner.register_profile(prof, 1000, "t1").unwrap();
    planner.register_policy(default_policy(), 1001, "t1").unwrap();

    let req = workload("wl-1", &["gpu", "compute"], 50, "default");
    let err = planner.request_placement(&req, 2000).unwrap_err();
    assert_eq!(err.code(), error_codes::ERR_HWP_FALLBACK_EXHAUSTED);

    // Verify fallback was attempted in audit log
    let codes: Vec<&str> = planner.audit_log().iter().map(|e| e.event_code.as_str()).collect();
    assert!(codes.contains(&event_codes::HWP_008)); // fallback attempted
    assert!(codes.contains(&event_codes::HWP_010)); // fallback exhausted
}

/// INV-PLANNER-FALLBACK-PATH: risk relaxation fallback succeeds.
#[test]
fn fallback_with_risk_relaxation_succeeds() {
    let _ = INV_PLANNER_FALLBACK_PATH;
    let mut planner = HardwarePlanner::default();
    planner.register_profile(gpu_profile("hw-1", 40, 4), 1000, "t1").unwrap();
    planner.register_policy(default_policy(), 1001, "t1").unwrap();

    let req = workload("wl-1", &["gpu", "compute"], 30, "default");
    let decision = planner.request_placement_with_fallback(&req, 20, 3000).unwrap();
    assert_eq!(decision.outcome, PlacementOutcome::PlacedViaFallback);
    assert!(decision.evidence.fallback_attempted);
    assert!(decision.evidence.fallback_reason.is_some());
}

/// INV-PLANNER-FALLBACK-PATH: fallback evidence records reasoning.
#[test]
fn fallback_evidence_records_reasoning() {
    let _ = INV_PLANNER_FALLBACK_PATH;
    let mut planner = HardwarePlanner::default();
    let mut prof = gpu_profile("hw-1", 10, 1);
    prof.used_slots = 1;
    planner.register_profile(prof, 1000, "t1").unwrap();
    planner.register_policy(default_policy(), 1001, "t1").unwrap();

    let req = workload("wl-1", &["gpu", "compute"], 50, "default");
    let _ = planner.request_placement(&req, 2000);

    let decisions = planner.decisions();
    let last = &decisions[decisions.len() - 1];
    assert!(last.evidence.fallback_attempted);
    assert!(!last.evidence.reasoning_chain.is_empty());
}

// ---------------------------------------------------------------------------
// INV-PLANNER-APPROVED-DISPATCH tests
// ---------------------------------------------------------------------------

/// INV-PLANNER-APPROVED-DISPATCH: dispatch through approved interface succeeds.
#[test]
fn dispatch_through_approved_interface() {
    let _ = INV_PLANNER_APPROVED_DISPATCH;
    let mut planner = HardwarePlanner::default();
    planner.register_profile(gpu_profile("hw-1", 10, 4), 1000, "t1").unwrap();

    let token = planner.dispatch("wl-1", "hw-1", "franken_engine", 2000, "t1").unwrap();
    assert_eq!(token.approved_interface, "franken_engine");
    assert_eq!(token.schema_version, SCHEMA_VERSION);
}

/// INV-PLANNER-APPROVED-DISPATCH: dispatch through unapproved interface is rejected.
#[test]
fn dispatch_unapproved_interface_rejected() {
    let _ = INV_PLANNER_APPROVED_DISPATCH;
    let mut planner = HardwarePlanner::default();
    planner.register_profile(gpu_profile("hw-1", 10, 4), 1000, "t1").unwrap();

    let err = planner.dispatch("wl-1", "hw-1", "rogue_interface", 2000, "t1").unwrap_err();
    assert_eq!(err.code(), error_codes::ERR_HWP_DISPATCH_UNGATED);
}

// ---------------------------------------------------------------------------
// Event code presence tests
// ---------------------------------------------------------------------------

#[test]
fn event_codes_are_defined() {
    assert_eq!(event_codes::PLANNER_PLACEMENT_START, "PLANNER_PLACEMENT_START");
    assert_eq!(event_codes::PLANNER_CONSTRAINT_EVALUATED, "PLANNER_CONSTRAINT_EVALUATED");
    assert_eq!(event_codes::PLANNER_PLACEMENT_DECIDED, "PLANNER_PLACEMENT_DECIDED");
    assert_eq!(event_codes::PLANNER_FALLBACK_ACTIVATED, "PLANNER_FALLBACK_ACTIVATED");
    assert_eq!(event_codes::PLANNER_DISPATCH_APPROVED, "PLANNER_DISPATCH_APPROVED");
}

#[test]
fn error_codes_are_defined() {
    assert_eq!(error_codes::ERR_PLANNER_CONSTRAINT_VIOLATED, "ERR_PLANNER_CONSTRAINT_VIOLATED");
    assert_eq!(error_codes::ERR_PLANNER_RESOURCE_CONTENTION, "ERR_PLANNER_RESOURCE_CONTENTION");
    assert_eq!(error_codes::ERR_PLANNER_NO_FALLBACK, "ERR_PLANNER_NO_FALLBACK");
    assert_eq!(error_codes::ERR_PLANNER_DISPATCH_DENIED, "ERR_PLANNER_DISPATCH_DENIED");
    assert_eq!(error_codes::ERR_PLANNER_REPRODUCIBILITY_FAILED, "ERR_PLANNER_REPRODUCIBILITY_FAILED");
    assert_eq!(error_codes::ERR_PLANNER_INTERFACE_UNAPPROVED, "ERR_PLANNER_INTERFACE_UNAPPROVED");
}

// ---------------------------------------------------------------------------
// Schema version consistency
// ---------------------------------------------------------------------------

#[test]
fn schema_version_propagates_to_all_records() {
    let mut planner = HardwarePlanner::default();
    planner.register_profile(gpu_profile("hw-1", 10, 4), 1000, "t1").unwrap();
    planner.register_policy(default_policy(), 1001, "t1").unwrap();

    let req = workload("wl-1", &["gpu", "compute"], 50, "default");
    let decision = planner.request_placement(&req, 2000).unwrap();

    assert_eq!(decision.schema_version, SCHEMA_VERSION);
    assert_eq!(decision.evidence.schema_version, SCHEMA_VERSION);

    for event in planner.audit_log() {
        assert_eq!(event.schema_version, SCHEMA_VERSION);
    }
}

// ---------------------------------------------------------------------------
// Audit completeness
// ---------------------------------------------------------------------------

#[test]
fn audit_log_covers_full_lifecycle() {
    let mut planner = HardwarePlanner::default();
    planner.register_profile(gpu_profile("hw-1", 10, 4), 1000, "t1").unwrap();
    planner.register_policy(default_policy(), 1001, "t1").unwrap();

    let req = workload("wl-1", &["gpu", "compute"], 50, "default");
    planner.request_placement(&req, 2000).unwrap();
    planner.dispatch("wl-1", "hw-1", "franken_engine", 3000, "t1").unwrap();

    let codes: Vec<&str> = planner.audit_log().iter().map(|e| e.event_code.as_str()).collect();
    // Registration events
    assert!(codes.contains(&event_codes::HWP_001)); // profile registered
    assert!(codes.contains(&event_codes::HWP_002)); // policy registered
    // Placement events
    assert!(codes.contains(&event_codes::HWP_003)); // placement requested
    assert!(codes.contains(&event_codes::HWP_004)); // placed
    assert!(codes.contains(&event_codes::HWP_012)); // evidence recorded
    // Dispatch event
    assert!(codes.contains(&event_codes::HWP_011)); // dispatched
}
