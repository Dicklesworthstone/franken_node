use std::collections::{BTreeMap, BTreeSet};

use frankenengine_node::connector::cancellation_protocol::{
    CancellationBudget, CancellationPhase, CancellationProtocol, WorkflowKind, error_codes,
    event_codes,
};
use frankenengine_node::connector::health_gate::{
    HealthGateError, HealthGateResult, standard_checks,
};
use frankenengine_node::connector::lease_service::{LeaseError, LeasePurpose, LeaseService};
use frankenengine_node::connector::lifecycle::{ConnectorState, LifecycleError, transition};
use serde_json::{Value, json};

const CONNECTOR_ID: &str = "jcq1z-connector";
const TRACE_ID: &str = "trace-jcq1z-connector";
const TIMESTAMP: &str = "2026-05-14T00:00:00Z";

struct LifecycleHarness {
    states: BTreeMap<String, ConnectorState>,
    live_connectors: BTreeSet<String>,
    leases: LeaseService,
    events: Vec<Value>,
    now: u64,
    sequence: u64,
}

impl LifecycleHarness {
    fn new() -> Self {
        Self {
            states: BTreeMap::new(),
            live_connectors: BTreeSet::new(),
            leases: LeaseService::new(),
            events: Vec::new(),
            now: 1_000,
            sequence: 0,
        }
    }

    fn now(&mut self) -> u64 {
        self.now = self.now.saturating_add(1);
        self.now
    }

    fn state(&self, connector_id: &str) -> ConnectorState {
        self.states
            .get(connector_id)
            .copied()
            .unwrap_or(ConnectorState::Discovered)
    }

    fn transition(
        &mut self,
        connector_id: &str,
        target: ConnectorState,
    ) -> Result<ConnectorState, LifecycleError> {
        let from = self.state(connector_id);
        let result = transition(from, target);
        self.sequence = self.sequence.saturating_add(1);

        let event = json!({
            "event": "connector_lifecycle_transition",
            "suite": "connector_jcq1z_lifecycle_stress",
            "connector_id": connector_id,
            "sequence": self.sequence,
            "from_state": from.as_str(),
            "to_state": target.as_str(),
            "success": result.is_ok(),
            "error": result.as_ref().err().map(ToString::to_string),
        });
        eprintln!(
            "{}",
            serde_json::to_string(&event).expect("event serializes")
        );
        self.events.push(event);

        let next = result?;
        self.states.insert(connector_id.to_string(), next);
        match next {
            ConnectorState::Active => {
                self.live_connectors.insert(connector_id.to_string());
            }
            ConnectorState::Stopped | ConnectorState::Failed => {
                self.live_connectors.remove(connector_id);
            }
            ConnectorState::Discovered
            | ConnectorState::Verified
            | ConnectorState::Installed
            | ConnectorState::Configured
            | ConnectorState::Paused
            | ConnectorState::Cancelling => {}
        }
        Ok(next)
    }

    fn progress_to_active(&mut self, connector_id: &str) {
        for target in [
            ConnectorState::Verified,
            ConnectorState::Installed,
            ConnectorState::Configured,
            ConnectorState::Active,
        ] {
            self.transition(connector_id, target)
                .expect("happy-path connector transition should be legal");
        }
    }

    fn grant_operation_lease(&mut self, connector_id: &str, holder: &str, ttl_secs: u64) -> String {
        let now = self.now();
        let lease = self
            .leases
            .grant(
                holder,
                LeasePurpose::Operation,
                ttl_secs,
                now,
                TRACE_ID,
                TIMESTAMP,
            )
            .expect("operation lease should be granted");
        assert_eq!(lease.holder, holder);
        assert!(lease.is_active(now));

        let decision = self
            .leases
            .use_lease(
                &lease.lease_id,
                LeasePurpose::Operation,
                now,
                TRACE_ID,
                TIMESTAMP,
            )
            .expect("fresh operation lease should be usable");
        assert!(decision.allowed);
        assert_eq!(decision.reason, "lease valid");

        self.events.push(json!({
            "event": "connector_lifecycle_lease",
            "suite": "connector_jcq1z_lifecycle_stress",
            "connector_id": connector_id,
            "lease_id": lease.lease_id,
            "holder": holder,
            "purpose": LeasePurpose::Operation.to_string(),
        }));

        lease.lease_id
    }
}

fn assert_audit_jsonl(protocol: &CancellationProtocol, expected_trace_id: &str) {
    let jsonl = protocol.export_audit_log_jsonl();
    assert!(!jsonl.trim().is_empty());
    for line in jsonl.lines() {
        let event: Value =
            serde_json::from_str(line).expect("cancellation audit event must be JSON");
        assert_eq!(event["schema_version"], json!("cancel-v1.0"));
        assert_eq!(event["trace_id"], json!(expected_trace_id));
        assert!(
            event["event_code"]
                .as_str()
                .expect("event code")
                .starts_with("CAN-")
        );
    }
}

#[test]
fn replacement_executes_real_lifecycle_health_lease_and_cancellation_path() {
    let mut harness = LifecycleHarness::new();

    let health = HealthGateResult::evaluate(standard_checks(true, true, true, true));
    assert!(health.gate_passed);
    assert!(HealthGateError::from_result(&health).is_none());

    harness.progress_to_active(CONNECTOR_ID);
    assert_eq!(harness.state(CONNECTOR_ID), ConnectorState::Active);
    assert!(harness.live_connectors.contains(CONNECTOR_ID));
    let lease_id = harness.grant_operation_lease(CONNECTOR_ID, "owner-primary", 30);
    let active_count_time = harness.now();
    assert_eq!(harness.leases.active_count(active_count_time), 1);

    let mut protocol = CancellationProtocol::for_workflow(&WorkflowKind::Lifecycle, TRACE_ID);
    protocol.resource_guard_mut().acquire(&lease_id);
    protocol.register_child();
    protocol.complete_child();
    assert_eq!(protocol.inflight_children(), 0);

    let request = protocol
        .request()
        .expect("cancellation request should start from idle");
    assert_eq!(request.to, CancellationPhase::Requested);
    harness
        .transition(CONNECTOR_ID, ConnectorState::Cancelling)
        .expect("active connector can enter cancelling");

    let drain = protocol
        .drain(250)
        .expect("drain should fit lifecycle cleanup budget");
    assert_eq!(drain.to, CancellationPhase::Draining);
    assert_eq!(drain.event_code, event_codes::CAN_003);
    assert!(protocol.resource_guard_mut().release(&lease_id));

    let finalize = protocol
        .finalize()
        .expect("finalize should complete after successful drain");
    assert_eq!(finalize.to, CancellationPhase::Completed);
    assert!(finalize.error.is_none());
    harness
        .transition(CONNECTOR_ID, ConnectorState::Stopped)
        .expect("cancelling connector can stop");

    assert_eq!(harness.state(CONNECTOR_ID), ConnectorState::Stopped);
    assert!(!harness.live_connectors.contains(CONNECTOR_ID));
    assert!(protocol.is_completed());
    assert!(!protocol.was_force_finalized());

    let audit_codes: Vec<&str> = protocol
        .audit_log()
        .iter()
        .map(|event| event.event_code.as_str())
        .collect();
    assert_eq!(
        audit_codes,
        vec![
            event_codes::CAN_001,
            event_codes::CAN_002,
            event_codes::CAN_003,
            event_codes::CAN_005,
        ]
    );
    assert_audit_jsonl(&protocol, TRACE_ID);
}

#[test]
fn replacement_rejects_illegal_transition_and_failed_health_activation() {
    let mut harness = LifecycleHarness::new();

    let illegal = harness
        .transition("illegal-skip", ConnectorState::Active)
        .expect_err("discovered connector cannot skip directly to active");
    assert!(matches!(&illegal, LifecycleError::IllegalTransition { .. }));
    if let LifecycleError::IllegalTransition {
        from,
        to,
        permitted,
    } = illegal
    {
        assert_eq!(from, ConnectorState::Discovered);
        assert_eq!(to, ConnectorState::Active);
        assert_eq!(
            permitted,
            vec![ConnectorState::Verified, ConnectorState::Failed]
        );
    }
    assert_eq!(harness.state("illegal-skip"), ConnectorState::Discovered);

    for target in [
        ConnectorState::Verified,
        ConnectorState::Installed,
        ConnectorState::Configured,
    ] {
        harness
            .transition("health-blocked", target)
            .expect("setup transition should be legal");
    }
    let failed_health = HealthGateResult::evaluate(standard_checks(true, false, true, true));
    assert!(!failed_health.gate_passed);
    let err = HealthGateError::from_result(&failed_health)
        .expect("failed health gate should produce error evidence");
    assert_eq!(err.code, "HEALTH_GATE_FAILED");
    assert_eq!(err.failing_checks, vec!["readiness".to_string()]);

    assert_eq!(harness.state("health-blocked"), ConnectorState::Configured);
    harness.events.push(json!({
        "event": "connector_lifecycle_activation_blocked",
        "suite": "connector_jcq1z_lifecycle_stress",
        "connector_id": "health-blocked",
        "state": harness.state("health-blocked").as_str(),
        "error_code": err.code,
        "failing_checks": err.failing_checks,
    }));
    assert_eq!(harness.state("health-blocked"), ConnectorState::Configured);
}

#[test]
fn replacement_stresses_many_connectors_without_leaks_or_state_drift() {
    let mut harness = LifecycleHarness::new();
    let sequence = [
        ConnectorState::Verified,
        ConnectorState::Installed,
        ConnectorState::Configured,
        ConnectorState::Active,
        ConnectorState::Paused,
        ConnectorState::Active,
        ConnectorState::Cancelling,
        ConnectorState::Stopped,
    ];

    for connector_index in 0..32 {
        let connector_id = format!("stress-connector-{connector_index:02}");
        let health = HealthGateResult::evaluate(standard_checks(true, true, true, true));
        assert!(health.gate_passed);

        for target in sequence {
            harness
                .transition(&connector_id, target)
                .expect("stress lifecycle transition should be legal");
            if target == ConnectorState::Active {
                let holder = format!("owner-{connector_index:02}-{}", harness.sequence);
                harness.grant_operation_lease(&connector_id, &holder, 120);
            }
        }

        assert_eq!(harness.state(&connector_id), ConnectorState::Stopped);
    }

    assert!(harness.live_connectors.is_empty());
    assert_eq!(harness.states.len(), 32);
    assert!(
        harness
            .states
            .values()
            .all(|state| *state == ConnectorState::Stopped)
    );
    assert_eq!(harness.events.len(), 32 * 10);
    let active_count_time = harness.now();
    assert_eq!(harness.leases.active_count(active_count_time), 64);

    let serialized =
        serde_json::to_string(&harness.events).expect("stress event summary should serialize");
    let decoded: Vec<Value> =
        serde_json::from_str(&serialized).expect("stress event summary should parse");
    assert_eq!(decoded.len(), harness.events.len());
}

#[test]
fn replacement_rejects_stale_wrong_purpose_and_revoked_leases() {
    let mut leases = LeaseService::new();
    let state_write = leases
        .grant(
            "state-writer",
            LeasePurpose::StateWrite,
            5,
            100,
            TRACE_ID,
            TIMESTAMP,
        )
        .expect("state-write lease should be granted");
    leases
        .use_lease(
            &state_write.lease_id,
            LeasePurpose::StateWrite,
            104,
            TRACE_ID,
            TIMESTAMP,
        )
        .expect("lease should be valid before expiry boundary");

    let stale = leases
        .use_lease(
            &state_write.lease_id,
            LeasePurpose::StateWrite,
            105,
            TRACE_ID,
            TIMESTAMP,
        )
        .expect_err("lease use at exact expiry boundary must fail closed");
    assert!(matches!(stale, LeaseError::StaleUse { .. }));

    let operation = leases
        .grant(
            "operator",
            LeasePurpose::Operation,
            60,
            200,
            TRACE_ID,
            TIMESTAMP,
        )
        .expect("operation lease should be granted after stale sweep");
    let purpose = leases
        .use_lease(
            &operation.lease_id,
            LeasePurpose::MigrationHandoff,
            201,
            TRACE_ID,
            TIMESTAMP,
        )
        .expect_err("wrong-purpose lease use must fail");
    assert!(matches!(purpose, LeaseError::PurposeMismatch { .. }));

    leases
        .revoke(&operation.lease_id, TRACE_ID, TIMESTAMP)
        .expect("revocation should succeed");
    let revoked = leases
        .use_lease(
            &operation.lease_id,
            LeasePurpose::Operation,
            202,
            TRACE_ID,
            TIMESTAMP,
        )
        .expect_err("revoked lease must be stale for use");
    assert!(matches!(revoked, LeaseError::StaleUse { .. }));
    assert!(
        leases
            .decisions
            .iter()
            .any(|decision| !decision.allowed && decision.reason == "lease expired")
    );
    assert!(
        leases
            .decisions
            .iter()
            .any(|decision| !decision.allowed && decision.reason.contains("purpose mismatch"))
    );
}

#[test]
fn replacement_force_finalize_audits_timeout_and_resource_cleanup() {
    let mut harness = LifecycleHarness::new();
    harness.progress_to_active(CONNECTOR_ID);

    let mut protocol = CancellationProtocol::new(
        CancellationBudget::new(WorkflowKind::Lifecycle.as_str(), 10),
        TRACE_ID,
    );
    protocol.resource_guard_mut().acquire("runtime-session");
    protocol
        .request()
        .expect("request should begin cancellation");
    harness
        .transition(CONNECTOR_ID, ConnectorState::Cancelling)
        .expect("active connector can enter cancelling");

    let drain = protocol
        .drain(10)
        .expect("budget boundary should force-finalize with evidence");
    assert_eq!(drain.to, CancellationPhase::Completed);
    assert_eq!(drain.event_code, event_codes::CAN_004);
    assert!(drain.force_finalized);
    let error = drain
        .error
        .as_deref()
        .expect("force-finalized drain must include error evidence");
    assert!(error.contains(error_codes::ERR_CANCEL_DRAIN_TIMEOUT));
    assert!(error.contains(error_codes::ERR_CANCEL_LEAK));

    harness
        .transition(CONNECTOR_ID, ConnectorState::Stopped)
        .expect("force-finalized connector can commit stopped state");
    assert!(protocol.is_completed());
    assert!(protocol.was_force_finalized());
    assert!(!protocol.resource_guard().has_leaks());

    let audit_codes: Vec<&str> = protocol
        .audit_log()
        .iter()
        .map(|event| event.event_code.as_str())
        .collect();
    assert_eq!(
        audit_codes,
        vec![
            event_codes::CAN_001,
            event_codes::CAN_002,
            event_codes::CAN_004,
            event_codes::CAN_006,
            event_codes::CAN_005,
        ]
    );
    assert_audit_jsonl(&protocol, TRACE_ID);
}
