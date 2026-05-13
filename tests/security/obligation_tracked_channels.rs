//! Security regression tests for bd-1n5p obligation-tracked two-phase channels.
//!
//! These tests exercise the public connector obligation tracker across the
//! critical publish/revoke/quarantine/migration flows required by the bead.

use frankenengine_node::connector::obligation_tracker::{
    FlowObligationCounts, ObligationFlow, ObligationId, ObligationState, ObligationTracker,
    event_codes,
};

const START_MS: u64 = 1_000;
const TRACE_ID: &str = "obl-security-test";

fn critical_flows() -> [ObligationFlow; 4] {
    [
        ObligationFlow::Publish,
        ObligationFlow::Revoke,
        ObligationFlow::Quarantine,
        ObligationFlow::Migration,
    ]
}

fn count_for<'a>(
    counts: &'a [FlowObligationCounts],
    flow: &ObligationFlow,
) -> &'a FlowObligationCounts {
    counts
        .iter()
        .find(|counts| counts.flow == flow.as_str())
        .expect("flow count should be present")
}

fn reserve_effect(
    tracker: &mut ObligationTracker,
    flow: ObligationFlow,
    effect: &str,
    now_ms: u64,
) -> ObligationId {
    let payload = format!("{}:{effect}", flow.as_str()).into_bytes();
    tracker
        .try_reserve(flow, payload, now_ms, TRACE_ID)
        .expect("critical flow reserve should succeed")
}

#[test]
fn critical_flows_commit_without_leaks() {
    let mut tracker = ObligationTracker::with_leak_timeout(1);
    let mut reserved = Vec::new();

    for flow in critical_flows() {
        for effect in ["db_write", "notification", "state_transition"] {
            let obligation_id = reserve_effect(&mut tracker, flow.clone(), effect, START_MS);
            reserved.push(obligation_id);
        }
    }

    for (offset, obligation_id) in reserved.iter().enumerate() {
        let offset_ms = u64::try_from(offset).expect("offset should fit in u64");
        tracker
            .commit(obligation_id, START_MS + 10 + offset_ms, TRACE_ID)
            .expect("committed critical flow obligation should resolve");
    }

    let scan = tracker.run_leak_scan(START_MS + 5_000, TRACE_ID);
    assert_eq!(scan.leaked, 0);
    assert_eq!(tracker.count_in_state(ObligationState::Reserved), 0);
    assert_eq!(
        tracker.count_in_state(ObligationState::Committed),
        reserved.len()
    );

    let counts = tracker.per_flow_counts();
    for flow in critical_flows() {
        let count = count_for(&counts, &flow);
        assert_eq!(count.reserved, 0);
        assert_eq!(count.committed, 3);
        assert_eq!(count.rolled_back, 0);
        assert_eq!(count.leaked, 0);
    }

    let report = tracker.generate_leak_oracle_report();
    assert_eq!(report.total_leaks, 0);
    assert_eq!(report.verdict, "PASS");

    let audit = tracker.export_audit_log_jsonl();
    assert!(audit.contains(event_codes::OBL_RESERVED));
    assert!(audit.contains(event_codes::OBL_COMMITTED));
    assert!(audit.contains(event_codes::OBL_SCAN_COMPLETED));
}

#[test]
fn cancellation_rolls_back_every_reserved_obligation() {
    let mut tracker = ObligationTracker::with_leak_timeout(1);
    let mut reserved = Vec::new();

    for flow in critical_flows() {
        let prepare_id = reserve_effect(&mut tracker, flow.clone(), "prepare", START_MS);
        let notify_id = reserve_effect(&mut tracker, flow.clone(), "notify", START_MS + 1);
        reserved.push(prepare_id);
        reserved.push(notify_id);
    }

    for (offset, obligation_id) in reserved.iter().enumerate() {
        let offset_ms = u64::try_from(offset).expect("offset should fit in u64");
        tracker
            .rollback(obligation_id, START_MS + 20 + offset_ms, TRACE_ID)
            .expect("cancelled critical flow obligation should roll back");
    }

    let scan = tracker.run_leak_scan(START_MS + 10_000, TRACE_ID);
    assert_eq!(scan.leaked, 0);
    assert!(scan.leaked_ids.is_empty());
    assert_eq!(tracker.count_in_state(ObligationState::Reserved), 0);
    assert_eq!(
        tracker.count_in_state(ObligationState::RolledBack),
        reserved.len()
    );

    let report = tracker.generate_leak_oracle_report();
    assert_eq!(report.total_leaks, 0);
    assert_eq!(report.verdict, "PASS");

    let audit = tracker.export_audit_log_jsonl();
    assert!(audit.contains(event_codes::OBL_ROLLED_BACK));
    assert!(audit.contains(event_codes::OBL_SCAN_COMPLETED));
}

#[test]
fn dropped_guard_rolls_back_before_oracle_scan() {
    let mut tracker = ObligationTracker::with_leak_timeout(1);
    let obligation_id = {
        let guard = tracker
            .reserve_guard(
                ObligationFlow::Quarantine,
                b"quarantine:state_transition".to_vec(),
                START_MS,
                TRACE_ID,
            )
            .expect("guard reservation should succeed");
        guard.obligation_id.clone()
    };

    let obligation = tracker
        .get_obligation(&obligation_id)
        .expect("guarded obligation should remain auditable");
    assert_eq!(obligation.state, ObligationState::RolledBack);

    let scan = tracker.run_leak_scan(START_MS + 10_000, TRACE_ID);
    assert_eq!(scan.leaked, 0);
    assert_eq!(tracker.count_in_state(ObligationState::Reserved), 0);
    assert_eq!(tracker.count_in_state(ObligationState::RolledBack), 1);

    let audit = tracker.export_audit_log_jsonl();
    assert!(audit.contains(event_codes::OBL_ROLLED_BACK));
    assert!(audit.contains("obligation rolled back by guard drop"));
}

#[test]
fn unresolved_reserved_obligation_is_reported_as_leak() {
    let mut tracker = ObligationTracker::with_leak_timeout(1);
    let obligation_id = reserve_effect(
        &mut tracker,
        ObligationFlow::Migration,
        "schema_update",
        START_MS,
    );

    let scan = tracker.run_leak_scan(START_MS + 5_000, TRACE_ID);
    assert_eq!(scan.leaked, 1);
    assert_eq!(scan.leaked_ids, vec![obligation_id.0.clone()]);

    let obligation = tracker
        .get_obligation(&obligation_id)
        .expect("leaked obligation remains auditable");
    assert_eq!(obligation.state, ObligationState::Leaked);

    let report = tracker.generate_leak_oracle_report();
    assert_eq!(report.total_leaks, 1);
    assert_eq!(report.verdict, "FAIL");

    let audit = tracker.export_audit_log_jsonl();
    assert!(audit.contains(event_codes::OBL_LEAK_DETECTED));
    assert!(audit.contains(event_codes::OBL_SCAN_COMPLETED));
}
