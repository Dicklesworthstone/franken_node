use std::collections::BTreeSet;

use frankenengine_node::connector::cancellation_protocol::{
    error_codes, event_codes, CancellationBudget, CancellationPhase, CancellationProtocol,
    WorkflowKind, SCHEMA_VERSION,
};
use frankenengine_node::connector::health_gate::{
    standard_checks, HealthGateError, HealthGateResult,
};
use frankenengine_node::connector::lifecycle::{transition, ConnectorState};
use frankenengine_node::connector::trace_context::{TraceContext, TraceStore, TracedArtifact};
use serde_json::{json, Value};

const CONNECTOR_ID: &str = "connector-public-api-e2e";
const SUITE: &str = "connector_lifecycle_public_api_e2e";

struct ConnectorLifecycleTrace {
    connector_id: &'static str,
    trace_id: String,
    root: TraceContext,
    next_span: u64,
    store: TraceStore,
    artifacts: Vec<TracedArtifact>,
    events: Vec<Value>,
}

impl ConnectorLifecycleTrace {
    fn new(connector_id: &'static str) -> Self {
        let trace_id = "c011ec70111122223333444455556666".to_string();
        let root = TraceContext {
            trace_id: trace_id.clone(),
            span_id: span_id(1),
            parent_span_id: None,
            timestamp: timestamp(0),
        };
        let mut store = TraceStore::new();
        store
            .record(&root)
            .expect("root connector lifecycle trace context should be valid");

        Self {
            connector_id,
            trace_id,
            root: root.clone(),
            next_span: 2,
            store,
            artifacts: vec![TracedArtifact {
                artifact_id: format!("connector-lifecycle/{connector_id}/root"),
                artifact_type: "connector_lifecycle_trace_root".to_string(),
                trace_context: Some(root),
            }],
            events: Vec::new(),
        }
    }

    fn record_phase(
        &mut self,
        phase: &str,
        event_code: &str,
        from: ConnectorState,
        to: ConnectorState,
        extra: Value,
    ) {
        let span = span_id(self.next_span);
        let ctx = self.root.child(&span, &timestamp(self.next_span));
        self.next_span = self.next_span.saturating_add(1);
        self.store
            .record(&ctx)
            .expect("connector lifecycle child span should stitch to root");
        self.artifacts.push(TracedArtifact {
            artifact_id: format!(
                "connector-lifecycle/{}/{phase}/{event_code}/{}",
                self.connector_id, ctx.span_id
            ),
            artifact_type: "connector_lifecycle_event".to_string(),
            trace_context: Some(ctx.clone()),
        });

        let mut event = json!({
            "event": "connector_lifecycle_phase",
            "suite": SUITE,
            "connector_id": self.connector_id,
            "trace_id": ctx.trace_id,
            "span_id": ctx.span_id,
            "parent_span_id": ctx.parent_span_id,
            "phase": phase,
            "event_code": event_code,
            "from_state": from.as_str(),
            "to_state": to.as_str(),
        });
        if let Some(extra_object) = extra.as_object() {
            let event_object = event
                .as_object_mut()
                .expect("structured lifecycle event must be a JSON object");
            for (key, value) in extra_object {
                event_object.insert(key.clone(), value.clone());
            }
        }

        tracing::info!(
            suite = SUITE,
            connector_id = self.connector_id,
            trace_id = %self.trace_id,
            span_id = %span,
            phase,
            event_code,
            from_state = from.as_str(),
            to_state = to.as_str(),
            "connector lifecycle public API event"
        );

        let line = serde_json::to_string(&event)
            .expect("structured connector lifecycle event should serialize as JSON");
        eprintln!("{line}");
        self.events.push(event);
    }
}

fn span_id(n: u64) -> String {
    format!("{n:016x}")
}

fn timestamp(step: u64) -> String {
    format!("2026-04-25T00:00:{step:02}Z")
}

fn transition_state(state: &mut ConnectorState, to: ConnectorState) -> ConnectorState {
    let from = *state;
    *state = transition(from, to).expect("connector lifecycle transition should be legal");
    from
}

fn field<'a>(event: &'a Value, key: &str) -> &'a str {
    event
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("structured lifecycle event missing string field {key}"))
}

fn assert_stitchable_trace(trace: &ConnectorLifecycleTrace, expected_phases: &[&str]) {
    let report = TraceStore::check_conformance(&trace.artifacts);
    assert_eq!(
        report.verdict, "PASS",
        "trace conformance violations: {:?}",
        report.violations
    );
    assert_eq!(report.trace_id, trace.trace_id);
    assert_eq!(report.total_artifacts, trace.events.len().saturating_add(1));

    let stitched = trace.store.stitch(&trace.trace_id);
    assert_eq!(stitched.len(), trace.events.len().saturating_add(1));

    let span_ids: BTreeSet<&str> = stitched.iter().map(|ctx| ctx.span_id.as_str()).collect();
    assert!(span_ids.contains(trace.root.span_id.as_str()));

    for event in &trace.events {
        for key in [
            "event",
            "suite",
            "connector_id",
            "trace_id",
            "span_id",
            "parent_span_id",
            "phase",
            "event_code",
            "from_state",
            "to_state",
        ] {
            assert!(event.get(key).is_some(), "missing structured field {key}");
        }
        assert_eq!(field(event, "event"), "connector_lifecycle_phase");
        assert_eq!(field(event, "suite"), SUITE);
        assert_eq!(field(event, "connector_id"), trace.connector_id);
        assert_eq!(field(event, "trace_id"), trace.trace_id);
        assert_eq!(field(event, "parent_span_id"), trace.root.span_id);
        assert!(span_ids.contains(field(event, "span_id")));

        let json_line =
            serde_json::to_string(event).expect("structured event should serialize to JSON");
        let round_tripped: Value =
            serde_json::from_str(&json_line).expect("structured event JSON should parse");
        assert_eq!(&round_tripped, event);
    }

    let phases: BTreeSet<&str> = trace
        .events
        .iter()
        .map(|event| field(event, "phase"))
        .collect();
    let expected: BTreeSet<&str> = expected_phases.iter().copied().collect();
    assert_eq!(phases, expected);
}

fn assert_audit_jsonl_is_structured(protocol: &CancellationProtocol, trace_id: &str) {
    let jsonl = protocol.export_audit_log_jsonl();
    assert!(!jsonl.trim().is_empty());

    for line in jsonl.lines() {
        let event: Value =
            serde_json::from_str(line).expect("cancellation audit event should be JSON");
        assert_eq!(field(&event, "schema_version"), SCHEMA_VERSION);
        assert_eq!(field(&event, "trace_id"), trace_id);
        assert!(field(&event, "event_code").starts_with("CAN-"));
        assert!(event.get("phase").is_some());
        assert!(event.get("workflow").is_some());
        assert!(event.get("detail").is_some());
    }
}

#[test]
fn connector_public_api_init_run_teardown_emits_stitchable_trace() {
    let mut trace = ConnectorLifecycleTrace::new(CONNECTOR_ID);
    let mut state = ConnectorState::Discovered;

    let health = HealthGateResult::evaluate(standard_checks(true, true, true, true));
    assert!(health.gate_passed);
    assert!(HealthGateError::from_result(&health).is_none());
    trace.record_phase(
        "init",
        "CONN-LC-HEALTH-PASS",
        state,
        state,
        json!({
            "health_gate_passed": health.gate_passed,
            "required_failures": health.failing_required(),
        }),
    );

    for (event_code, target) in [
        ("CONN-LC-INIT-VERIFIED", ConnectorState::Verified),
        ("CONN-LC-INIT-INSTALLED", ConnectorState::Installed),
        ("CONN-LC-INIT-CONFIGURED", ConnectorState::Configured),
    ] {
        let from = transition_state(&mut state, target);
        trace.record_phase(
            "init",
            event_code,
            from,
            state,
            json!({ "health_gate_passed": health.gate_passed }),
        );
    }

    let mut protocol =
        CancellationProtocol::for_workflow(&WorkflowKind::Lifecycle, &trace.trace_id);
    protocol.resource_guard_mut().acquire("runtime-session");
    protocol.register_child();
    assert_eq!(protocol.inflight_children(), 1);

    let from = transition_state(&mut state, ConnectorState::Active);
    trace.record_phase(
        "run",
        "CONN-LC-RUN-ACTIVE",
        from,
        state,
        json!({
            "health_gate_passed": health.gate_passed,
            "resource": "runtime-session",
            "resource_held": protocol.resource_guard().has_leaks(),
            "inflight_children": protocol.inflight_children(),
        }),
    );

    protocol.complete_child();
    assert_eq!(protocol.inflight_children(), 0);

    let request = protocol
        .request()
        .expect("teardown request should be valid from idle cancellation phase");
    assert_eq!(request.to, CancellationPhase::Requested);
    let from = transition_state(&mut state, ConnectorState::Cancelling);
    trace.record_phase(
        "teardown",
        &request.event_code,
        from,
        state,
        json!({
            "cancel_phase": protocol.phase().to_string(),
            "force_finalized": request.force_finalized,
        }),
    );

    let drain = protocol
        .drain(250)
        .expect("teardown drain should fit within lifecycle budget");
    assert_eq!(drain.event_code, event_codes::CAN_003);
    assert_eq!(drain.to, CancellationPhase::Draining);
    trace.record_phase(
        "teardown",
        &drain.event_code,
        state,
        state,
        json!({
            "cancel_phase": protocol.phase().to_string(),
            "force_finalized": drain.force_finalized,
        }),
    );

    assert!(protocol.resource_guard_mut().release("runtime-session"));
    let finalize = protocol
        .finalize()
        .expect("teardown finalize should complete after a successful drain");
    assert_eq!(finalize.event_code, event_codes::CAN_005);
    assert_eq!(finalize.to, CancellationPhase::Completed);
    assert!(finalize.error.is_none());
    let from = transition_state(&mut state, ConnectorState::Stopped);
    trace.record_phase(
        "teardown",
        &finalize.event_code,
        from,
        state,
        json!({
            "cancel_phase": protocol.phase().to_string(),
            "force_finalized": finalize.force_finalized,
            "resource_leak": protocol.resource_guard().has_leaks(),
        }),
    );

    assert_eq!(state, ConnectorState::Stopped);
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

    assert_audit_jsonl_is_structured(&protocol, &trace.trace_id);
    assert_stitchable_trace(&trace, &["init", "run", "teardown"]);
}

#[test]
fn connector_public_api_run_blocked_by_failed_health_gate_is_traced() {
    let mut trace = ConnectorLifecycleTrace::new(CONNECTOR_ID);
    let mut state = ConnectorState::Discovered;
    for target in [
        ConnectorState::Verified,
        ConnectorState::Installed,
        ConnectorState::Configured,
    ] {
        transition_state(&mut state, target);
    }
    assert_eq!(state, ConnectorState::Configured);

    let health = HealthGateResult::evaluate(standard_checks(true, false, true, true));
    assert!(!health.gate_passed);
    let err = HealthGateError::from_result(&health).expect("failed gate should produce an error");
    assert_eq!(err.code, "HEALTH_GATE_FAILED");
    assert_eq!(err.failing_checks, vec!["readiness".to_string()]);

    trace.record_phase(
        "run",
        "CONN-LC-RUN-BLOCKED",
        state,
        state,
        json!({
            "health_gate_passed": health.gate_passed,
            "error_code": err.code,
            "failing_checks": err.failing_checks,
        }),
    );

    assert_eq!(state, ConnectorState::Configured);
    assert_eq!(field(&trace.events[0], "event_code"), "CONN-LC-RUN-BLOCKED");
    assert_eq!(trace.events[0]["health_gate_passed"], json!(false));
    assert_stitchable_trace(&trace, &["run"]);
}

#[test]
fn connector_public_api_teardown_timeout_force_finalize_is_audited() {
    let mut trace = ConnectorLifecycleTrace::new(CONNECTOR_ID);
    let mut state = ConnectorState::Discovered;
    for target in [
        ConnectorState::Verified,
        ConnectorState::Installed,
        ConnectorState::Configured,
        ConnectorState::Active,
    ] {
        transition_state(&mut state, target);
    }
    assert_eq!(state, ConnectorState::Active);

    let mut protocol = CancellationProtocol::new(
        CancellationBudget::new(WorkflowKind::Lifecycle.as_str(), 10),
        &trace.trace_id,
    );
    protocol.resource_guard_mut().acquire("runtime-session");
    protocol
        .request()
        .expect("teardown request should begin timeout path");
    let from = transition_state(&mut state, ConnectorState::Cancelling);
    trace.record_phase(
        "teardown",
        event_codes::CAN_001,
        from,
        state,
        json!({
            "cancel_phase": protocol.phase().to_string(),
            "budget_ms": protocol.budget().timeout_ms,
        }),
    );

    let drain = protocol
        .drain(10)
        .expect("budget boundary should force-finalize instead of panicking");
    assert_eq!(drain.event_code, event_codes::CAN_004);
    assert_eq!(drain.to, CancellationPhase::Completed);
    assert!(drain.force_finalized);
    let error = drain
        .error
        .as_deref()
        .expect("force-finalized drain should return error evidence");
    assert!(error.contains(error_codes::ERR_CANCEL_DRAIN_TIMEOUT));
    assert!(error.contains(error_codes::ERR_CANCEL_LEAK));

    let from = transition_state(&mut state, ConnectorState::Stopped);
    trace.record_phase(
        "teardown",
        event_codes::CAN_004,
        from,
        state,
        json!({
            "cancel_phase": protocol.phase().to_string(),
            "force_finalized": drain.force_finalized,
            "error": error,
        }),
    );

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

    assert_audit_jsonl_is_structured(&protocol, &trace.trace_id);
    assert_stitchable_trace(&trace, &["teardown"]);
}
