#![no_main]
#![forbid(unsafe_code)]

use arbitrary::Arbitrary;
use frankenengine_node::security::remote_cap::{
    CapabilityGate, CapabilityProvider, ConnectivityMode, RemoteCapError, RemoteOperation,
    RemoteScope,
};
use libfuzzer_sys::fuzz_target;

const SIGNING_MATERIAL: &str = "r79-cap-scope-material-4f716d9a2c5e8b10";
const NOW: u64 = 1_700_000_000;
const MAX_STRING_CHARS: usize = 256;
const MAX_SCOPE_ITEMS: usize = 32;

#[derive(Debug, Arbitrary)]
struct RemoteCapScopeCase {
    operations: Vec<FuzzOperation>,
    endpoint_prefixes: Vec<String>,
    requested_operation: FuzzOperation,
    requested_endpoint: String,
    issuer: String,
    trace_id: String,
    ttl_hint: u16,
}

#[derive(Debug, Clone, Copy, Arbitrary)]
enum FuzzOperation {
    NetworkEgress,
    FederationSync,
    RevocationFetch,
    RemoteAttestationVerify,
    TelemetryExport,
    RemoteComputation,
    ArtifactUpload,
}

fuzz_target!(|case: RemoteCapScopeCase| {
    fuzz_remote_cap_scope_check(case);
});

fn fuzz_remote_cap_scope_check(case: RemoteCapScopeCase) {
    let operations: Vec<RemoteOperation> = case
        .operations
        .into_iter()
        .take(MAX_SCOPE_ITEMS)
        .map(FuzzOperation::into_operation)
        .collect();
    let prefixes = bounded_strings(case.endpoint_prefixes);
    let scope = RemoteScope::new(operations, prefixes);
    let requested_operation = case.requested_operation.into_operation();
    let requested_endpoint = bounded_string(case.requested_endpoint);
    let issuer = bounded_string(case.issuer);
    let trace_id = bounded_string(case.trace_id);
    let ttl = u64::from(case.ttl_hint % 3600).saturating_add(2);

    assert_endpoint_delimiter_boundaries(&scope);

    let Ok(provider) = CapabilityProvider::new(SIGNING_MATERIAL) else {
        return;
    };
    let Ok((cap, _)) = provider.issue(&issuer, scope.clone(), NOW, ttl, true, false, &trace_id)
    else {
        return;
    };

    let expected_allowed =
        scope.allows_operation(requested_operation) && scope.allows_endpoint(&requested_endpoint);
    let Ok(mut gate) = CapabilityGate::new(SIGNING_MATERIAL) else {
        return;
    };
    let audit_len_before = gate.audit_log().len();
    let result = gate.authorize_network(
        Some(&cap),
        requested_operation,
        &requested_endpoint,
        NOW.saturating_add(1),
        "trace-scope-check",
    );
    assert_eq!(
        result.is_ok(),
        expected_allowed,
        "scope authorization result diverged from RemoteScope predicate"
    );
    assert_scope_audit(
        &gate,
        audit_len_before,
        &result,
        requested_operation,
        &requested_endpoint,
        "trace-scope-check",
        NOW.saturating_add(1),
        expected_allowed,
    );

    let Ok(mut local_gate) =
        CapabilityGate::with_mode(SIGNING_MATERIAL, ConnectivityMode::LocalOnly)
    else {
        return;
    };
    let local_audit_len_before = local_gate.audit_log().len();
    let local_result = local_gate.authorize_network(
        Some(&cap),
        requested_operation,
        &requested_endpoint,
        NOW.saturating_add(1),
        "trace-local-only-deny",
    );
    assert!(
        local_result.is_err(),
        "local-only connectivity mode must deny remote capability use"
    );
    assert_connectivity_audit(
        &local_gate,
        local_audit_len_before,
        &local_result,
        requested_operation,
        &requested_endpoint,
    );
}

fn assert_endpoint_delimiter_boundaries(scope: &RemoteScope) {
    for prefix in scope.endpoint_prefixes() {
        if prefix.is_empty() || prefix.ends_with('/') || prefix.ends_with(':') {
            continue;
        }
        let shifted = format!("{prefix}evil");
        let singleton_scope =
            RemoteScope::new(vec![RemoteOperation::NetworkEgress], vec![prefix.clone()]);
        assert!(
            !singleton_scope.allows_endpoint(&shifted),
            "endpoint prefix matched across a non-delimited boundary"
        );
    }
}

fn assert_scope_audit(
    gate: &CapabilityGate,
    audit_len_before: usize,
    result: &Result<(), RemoteCapError>,
    operation: RemoteOperation,
    endpoint: &str,
    trace_id: &str,
    now_epoch_secs: u64,
    expected_allowed: bool,
) {
    assert_eq!(gate.audit_log().len(), audit_len_before.saturating_add(1));
    let Some(event) = gate.audit_log().last() else {
        return;
    };
    assert_eq!(event.allowed, result.is_ok());
    assert_eq!(event.allowed, expected_allowed);
    assert_eq!(event.operation, Some(operation));
    assert_eq!(event.endpoint.as_deref(), Some(endpoint));
    assert_eq!(event.trace_id, trace_id);
    assert_eq!(event.timestamp_epoch_secs, now_epoch_secs);

    if expected_allowed {
        assert_eq!(event.event_code, "REMOTECAP_CONSUMED");
        assert_eq!(event.legacy_event_code, "RC_CHECK_PASSED");
        assert!(event.denial_code.is_none());
    } else {
        assert!(matches!(result, Err(RemoteCapError::ScopeDenied { .. })));
        assert_eq!(event.event_code, "REMOTECAP_DENIED");
        assert_eq!(event.legacy_event_code, "RC_CHECK_DENIED");
        assert_eq!(event.denial_code.as_deref(), Some("REMOTECAP_SCOPE_DENIED"));
    }
}

fn assert_connectivity_audit(
    gate: &CapabilityGate,
    audit_len_before: usize,
    result: &Result<(), RemoteCapError>,
    operation: RemoteOperation,
    endpoint: &str,
) {
    assert!(matches!(
        result,
        Err(RemoteCapError::ConnectivityModeDenied { .. })
    ));
    assert_eq!(gate.audit_log().len(), audit_len_before.saturating_add(1));
    let Some(event) = gate.audit_log().last() else {
        return;
    };
    assert!(!event.allowed);
    assert_eq!(event.event_code, "REMOTECAP_DENIED");
    assert_eq!(event.legacy_event_code, "RC_CHECK_DENIED");
    assert_eq!(
        event.denial_code.as_deref(),
        Some("REMOTECAP_CONNECTIVITY_MODE_DENIED")
    );
    assert_eq!(event.operation, Some(operation));
    assert_eq!(event.endpoint.as_deref(), Some(endpoint));
    assert_eq!(event.trace_id, "trace-local-only-deny");
}

impl FuzzOperation {
    fn into_operation(self) -> RemoteOperation {
        match self {
            Self::NetworkEgress => RemoteOperation::NetworkEgress,
            Self::FederationSync => RemoteOperation::FederationSync,
            Self::RevocationFetch => RemoteOperation::RevocationFetch,
            Self::RemoteAttestationVerify => RemoteOperation::RemoteAttestationVerify,
            Self::TelemetryExport => RemoteOperation::TelemetryExport,
            Self::RemoteComputation => RemoteOperation::RemoteComputation,
            Self::ArtifactUpload => RemoteOperation::ArtifactUpload,
        }
    }
}

fn bounded_strings(values: Vec<String>) -> Vec<String> {
    values
        .into_iter()
        .take(MAX_SCOPE_ITEMS)
        .map(bounded_string)
        .filter(|value| !value.trim().is_empty())
        .collect()
}

fn bounded_string(value: String) -> String {
    value.chars().take(MAX_STRING_CHARS).collect()
}
