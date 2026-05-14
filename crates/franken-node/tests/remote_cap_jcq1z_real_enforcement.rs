use frankenengine_node::remote::eviction_saga::RemoteCapLookup;
use frankenengine_node::remote::remote_bulkhead::{
    BackpressurePolicy, BulkheadError, RemoteBulkhead, event_codes,
};
use frankenengine_node::security::remote_cap::{
    CapabilityGate, CapabilityProvider, ConnectivityMode, RemoteCap, RemoteCapError,
    RemoteOperation, RemoteScope,
};
use serde_json::json;

const ISSUER: &str = "jcq1z-ops-control-plane";
const BASE_TIME: u64 = 1_700_400_000;
const API_PREFIX: &str = "https://api.example.com/root/";
const API_ENDPOINT: &str = "https://api.example.com/root/jobs/42";
const TELEMETRY_PREFIX: &str = "https://telemetry.example.com/push";
const TELEMETRY_ENDPOINT: &str = "https://telemetry.example.com/push/runtime";
const COMPUTE_PREFIX: &str = "wss://compute.example.com/jobs";
const COMPUTE_ENDPOINT: &str = "wss://compute.example.com/jobs/lease-7";

fn test_key_material() -> String {
    ["jcq1z", "remote", "cap", "key", "2026", "worker"].join("-")
}

fn provider() -> CapabilityProvider {
    let key_material = test_key_material();
    CapabilityProvider::new(&key_material).expect("remote cap provider key material must be valid")
}

fn gate() -> CapabilityGate {
    let key_material = test_key_material();
    CapabilityGate::new(&key_material).expect("remote cap gate key material must be valid")
}

fn full_scope() -> RemoteScope {
    RemoteScope::new(
        vec![
            RemoteOperation::NetworkEgress,
            RemoteOperation::TelemetryExport,
            RemoteOperation::RemoteComputation,
        ],
        vec![
            API_PREFIX.to_string(),
            TELEMETRY_PREFIX.to_string(),
            COMPUTE_PREFIX.to_string(),
        ],
    )
}

fn telemetry_only_scope() -> RemoteScope {
    RemoteScope::new(
        vec![RemoteOperation::TelemetryExport],
        vec![TELEMETRY_PREFIX.to_string()],
    )
}

fn issue_cap(scope: RemoteScope, single_use: bool, trace_id: &str) -> RemoteCap {
    provider()
        .issue(ISSUER, scope, BASE_TIME, 3_600, true, single_use, trace_id)
        .expect("authorized remote cap issue should succeed")
        .0
}

fn lookup_from_auth(result: &Result<(), RemoteCapError>) -> RemoteCapLookup {
    if result.is_ok() {
        RemoteCapLookup::Granted
    } else {
        RemoteCapLookup::Denied
    }
}

fn assert_last_denial(gate: &CapabilityGate, code: &str) {
    let event = gate
        .audit_log()
        .last()
        .expect("denial must be audited by capability gate");
    assert!(!event.allowed);
    assert_eq!(event.event_code, "REMOTECAP_DENIED");
    assert_eq!(event.denial_code.as_deref(), Some(code));
}

fn emit_case(name: &str, allowed: bool, detail: serde_json::Value) {
    eprintln!(
        "{}",
        json!({
            "suite": "remote_cap_jcq1z_real_enforcement",
            "case": name,
            "allowed": allowed,
            "detail": detail,
        })
    );
}

#[test]
fn replacement_authorizes_real_capability_then_admits_bulkhead_permit() {
    let cap = issue_cap(full_scope(), false, "trace-jcq1z-issue-basic");
    let mut gate = gate();
    let mut bulkhead =
        RemoteBulkhead::new(2, BackpressurePolicy::Reject, 50).expect("valid bulkhead config");

    let authorization = gate.authorize_network(
        Some(&cap),
        RemoteOperation::NetworkEgress,
        API_ENDPOINT,
        BASE_TIME + 10,
        "trace-jcq1z-authorize-basic",
    );
    assert!(authorization.is_ok());

    let permit = bulkhead
        .acquire(lookup_from_auth(&authorization), "jcq1z-basic-request", 10)
        .expect("validated remote cap should admit a bulkhead permit");
    assert_eq!(bulkhead.current_in_flight(), 1);
    assert_eq!(bulkhead.queue_depth(), 0);

    bulkhead
        .release(permit, 11)
        .expect("issued permit should release cleanly");
    assert_eq!(bulkhead.current_in_flight(), 0);

    let gate_events = gate.audit_log();
    assert_eq!(gate_events.len(), 1);
    assert!(gate_events[0].allowed);
    assert_eq!(gate_events[0].event_code, "REMOTECAP_CONSUMED");
    assert_eq!(
        gate_events[0].operation,
        Some(RemoteOperation::NetworkEgress)
    );

    let bulkhead_event_codes: Vec<_> = bulkhead
        .events()
        .iter()
        .map(|event| event.event_code.as_str())
        .collect();
    assert_eq!(
        bulkhead_event_codes,
        vec![
            event_codes::RB_PERMIT_ACQUIRED,
            event_codes::RB_PERMIT_RELEASED
        ]
    );

    emit_case(
        "authorize_then_bulkhead",
        true,
        json!({
            "token_id": cap.token_id(),
            "gate_events": gate_events.len(),
            "bulkhead_events": bulkhead.events().len(),
        }),
    );
}

#[test]
fn replacement_denies_missing_scope_revoked_and_local_only_remote_access() {
    let mut gate = gate();
    let missing = gate.authorize_network(
        None,
        RemoteOperation::NetworkEgress,
        API_ENDPOINT,
        BASE_TIME + 1,
        "trace-jcq1z-missing",
    );
    assert!(matches!(missing, Err(RemoteCapError::Missing)));
    assert_last_denial(&gate, "REMOTECAP_MISSING");

    let mut bulkhead =
        RemoteBulkhead::new(1, BackpressurePolicy::Reject, 50).expect("valid bulkhead config");
    let bulkhead_denial = bulkhead
        .acquire(lookup_from_auth(&missing), "missing-cap-request", 1)
        .expect_err("denied remote cap must not enter bulkhead");
    assert!(matches!(bulkhead_denial, BulkheadError::RemoteCapRequired));
    assert_eq!(bulkhead.current_in_flight(), 0);

    let telemetry_cap = issue_cap(
        telemetry_only_scope(),
        false,
        "trace-jcq1z-issue-telemetry-only",
    );
    let out_of_scope = gate.authorize_network(
        Some(&telemetry_cap),
        RemoteOperation::RemoteComputation,
        COMPUTE_ENDPOINT,
        BASE_TIME + 2,
        "trace-jcq1z-scope-denied",
    );
    assert!(matches!(
        out_of_scope,
        Err(RemoteCapError::ScopeDenied {
            operation: RemoteOperation::RemoteComputation,
            ..
        })
    ));
    assert_last_denial(&gate, "REMOTECAP_SCOPE_DENIED");

    let revocable = issue_cap(full_scope(), false, "trace-jcq1z-issue-revocable");
    gate.revoke(&revocable, BASE_TIME + 3, "trace-jcq1z-revoke");
    let revoked = gate.authorize_network(
        Some(&revocable),
        RemoteOperation::TelemetryExport,
        TELEMETRY_ENDPOINT,
        BASE_TIME + 4,
        "trace-jcq1z-after-revoke",
    );
    assert!(matches!(revoked, Err(RemoteCapError::Revoked { .. })));
    assert_last_denial(&gate, "REMOTECAP_REVOKED");

    let key_material = test_key_material();
    let mut local_gate = CapabilityGate::with_mode(&key_material, ConnectivityMode::LocalOnly)
        .expect("local-only gate should build");
    let local_only = local_gate.authorize_network(
        Some(&issue_cap(
            full_scope(),
            false,
            "trace-jcq1z-issue-local-only",
        )),
        RemoteOperation::NetworkEgress,
        API_ENDPOINT,
        BASE_TIME + 5,
        "trace-jcq1z-local-only-denied",
    );
    assert!(matches!(
        local_only,
        Err(RemoteCapError::ConnectivityModeDenied { .. })
    ));
    assert_last_denial(&local_gate, "REMOTECAP_CONNECTIVITY_MODE_DENIED");

    emit_case(
        "fail_closed_denials",
        false,
        json!({
            "missing_code": "REMOTECAP_MISSING",
            "scope_code": "REMOTECAP_SCOPE_DENIED",
            "revoked_code": "REMOTECAP_REVOKED",
            "local_only_code": "REMOTECAP_CONNECTIVITY_MODE_DENIED",
        }),
    );
}

#[test]
fn replacement_recheck_preserves_single_use_cap_until_first_authorization() {
    let cap = issue_cap(full_scope(), true, "trace-jcq1z-issue-single-use");
    let mut gate = gate();

    for idx in 0..3 {
        gate.recheck_network(
            Some(&cap),
            RemoteOperation::TelemetryExport,
            TELEMETRY_ENDPOINT,
            BASE_TIME + 10 + idx,
            &format!("trace-jcq1z-recheck-{idx}"),
        )
        .expect("preflight recheck must not consume a single-use token");
    }

    gate.authorize_network(
        Some(&cap),
        RemoteOperation::TelemetryExport,
        TELEMETRY_ENDPOINT,
        BASE_TIME + 20,
        "trace-jcq1z-single-use-first",
    )
    .expect("first single-use authorization should pass");

    let replay = gate
        .authorize_network(
            Some(&cap),
            RemoteOperation::TelemetryExport,
            TELEMETRY_ENDPOINT,
            BASE_TIME + 21,
            "trace-jcq1z-single-use-replay",
        )
        .expect_err("second single-use authorization must fail closed");
    assert_eq!(replay.code(), "REMOTECAP_REPLAY");
    assert_last_denial(&gate, "REMOTECAP_REPLAY");

    let event_codes: Vec<_> = gate
        .audit_log()
        .iter()
        .map(|event| event.event_code.as_str())
        .collect();
    assert_eq!(
        event_codes,
        vec![
            "REMOTECAP_RECHECK_PASSED",
            "REMOTECAP_RECHECK_PASSED",
            "REMOTECAP_RECHECK_PASSED",
            "REMOTECAP_CONSUMED",
            "REMOTECAP_DENIED",
        ]
    );

    emit_case(
        "single_use_recheck_then_replay",
        false,
        json!({
            "token_id": cap.token_id(),
            "audit_events": event_codes,
        }),
    );
}

#[test]
fn replacement_rejects_adversarial_endpoint_boundaries_without_bulkhead_admission() {
    let cap = issue_cap(full_scope(), false, "trace-jcq1z-issue-adversarial");
    let adversarial_endpoints = [
        "",
        "https://api.example.com/root/../admin",
        "https://api.example.com/root/%2e%2e/admin",
        "https://api.example.com/root\\admin",
        "https://api.example.com/root/\u{202e}admin",
        "https://api.example.com/rootevil/jobs/42",
        "file:///etc/passwd",
    ];

    let mut denied = 0;
    for (idx, endpoint) in adversarial_endpoints.iter().enumerate() {
        let mut gate = gate();
        let result = gate.authorize_network(
            Some(&cap),
            RemoteOperation::NetworkEgress,
            endpoint,
            BASE_TIME + 100 + idx as u64,
            &format!("trace-jcq1z-adversarial-{idx}"),
        );
        assert!(
            matches!(result, Err(RemoteCapError::ScopeDenied { .. })),
            "endpoint {endpoint:?} must fail closed"
        );
        assert_last_denial(&gate, "REMOTECAP_SCOPE_DENIED");

        let mut bulkhead =
            RemoteBulkhead::new(1, BackpressurePolicy::Reject, 50).expect("valid bulkhead config");
        let err = bulkhead
            .acquire(
                lookup_from_auth(&result),
                &format!("adversarial-request-{idx}"),
                100 + idx as u64,
            )
            .expect_err("denied endpoint must not admit remote work");
        assert!(matches!(err, BulkheadError::RemoteCapRequired));
        denied += 1;
    }

    emit_case(
        "adversarial_endpoint_boundaries",
        false,
        json!({
            "denied": denied,
            "total": adversarial_endpoints.len(),
        }),
    );
    assert_eq!(denied, adversarial_endpoints.len());
}

#[test]
fn replacement_stresses_reusable_cap_without_losing_gate_or_bulkhead_accounting() {
    let cap = issue_cap(full_scope(), false, "trace-jcq1z-issue-stress");
    let mut gate = gate();
    let mut bulkhead = RemoteBulkhead::new(
        4,
        BackpressurePolicy::Queue {
            max_depth: 8,
            timeout_ms: 25,
        },
        100,
    )
    .expect("valid bulkhead config");

    let mut summaries = Vec::new();
    for idx in 0..32 {
        let endpoint = match idx % 3 {
            0 => API_ENDPOINT,
            1 => TELEMETRY_ENDPOINT,
            _ => COMPUTE_ENDPOINT,
        };
        let operation = match idx % 3 {
            0 => RemoteOperation::NetworkEgress,
            1 => RemoteOperation::TelemetryExport,
            _ => RemoteOperation::RemoteComputation,
        };

        let authorization = gate.authorize_network(
            Some(&cap),
            operation,
            endpoint,
            BASE_TIME + 200 + idx,
            &format!("trace-jcq1z-stress-auth-{idx}"),
        );
        assert!(
            authorization.is_ok(),
            "stress authorization {idx} should pass"
        );

        let request_id = format!("stress-request-{idx:02}");
        let permit = bulkhead
            .acquire(lookup_from_auth(&authorization), &request_id, 200 + idx)
            .expect("stress request should acquire within sequential harness");
        assert_eq!(bulkhead.current_in_flight(), 1);
        bulkhead
            .release(permit, 201 + idx)
            .expect("stress permit should release");
        assert_eq!(bulkhead.current_in_flight(), 0);

        summaries.push(json!({
            "idx": idx,
            "request_id": request_id,
            "operation": operation.as_str(),
            "endpoint": endpoint,
        }));
    }

    assert_eq!(gate.audit_log().len(), 32);
    assert!(gate.audit_log().iter().all(|event| event.allowed));
    assert_eq!(bulkhead.events().len(), 64);
    assert_eq!(bulkhead.queue_depth(), 0);
    assert_eq!(bulkhead.current_in_flight(), 0);

    let serialized = serde_json::to_string(&summaries).expect("stress summary must serialize");
    let parsed: serde_json::Value =
        serde_json::from_str(&serialized).expect("stress summary must parse");
    assert_eq!(parsed.as_array().expect("summary array").len(), 32);

    emit_case(
        "sequential_stress_accounting",
        true,
        json!({
            "gate_events": gate.audit_log().len(),
            "bulkhead_events": bulkhead.events().len(),
            "summary_rows": parsed.as_array().expect("summary array").len(),
        }),
    );
}
