use frankenengine_node::security::remote_cap::{
    CapabilityGate, CapabilityProvider, ConnectivityMode, RemoteCap, RemoteOperation, RemoteScope,
};

const KEY_MATERIAL: &str = "r12-capability-gate-fuzz-secret-7d9f1a2c9b8e6f4a";
const ISSUED_AT: u64 = 1_700_000_000;

#[derive(Clone, Copy)]
struct CapabilityGateFuzzCase {
    label: &'static str,
    issued_operation: RemoteOperation,
    attempted_operation: RemoteOperation,
    prefix: &'static str,
    endpoint: &'static str,
    ttl_secs: u64,
    now_epoch_secs: u64,
    mode: ConnectivityMode,
    expected_error_code: Option<&'static str>,
}

fn provider() -> Result<CapabilityProvider, String> {
    CapabilityProvider::new(KEY_MATERIAL).map_err(|err| err.to_string())
}

fn issue_case_cap(case: &CapabilityGateFuzzCase) -> Result<RemoteCap, String> {
    let scope = RemoteScope::new(vec![case.issued_operation], vec![case.prefix.to_string()]);
    let (cap, _) = provider()?
        .issue(
            "r12-capability-fuzz",
            scope,
            ISSUED_AT,
            case.ttl_secs,
            true,
            false,
            case.label,
        )
        .map_err(|err| err.to_string())?;
    Ok(cap)
}

fn assert_gate_case(case: &CapabilityGateFuzzCase) -> Result<(), String> {
    let cap = issue_case_cap(case)?;
    let mut gate =
        CapabilityGate::with_mode(KEY_MATERIAL, case.mode).map_err(|err| err.to_string())?;
    let result = gate.authorize_network(
        Some(&cap),
        case.attempted_operation,
        case.endpoint,
        case.now_epoch_secs,
        case.label,
    );

    match case.expected_error_code {
        Some(expected_code) => {
            let Err(err) = result else {
                return Err(format!("{} should fail closed", case.label));
            };
            assert_eq!(
                err.code(),
                expected_code,
                "{} denial code mismatch",
                case.label
            );
            let Some(event) = gate.audit_log().last() else {
                return Err(format!("{} denial must be audited", case.label));
            };
            assert!(
                !event.allowed,
                "{} denial audit must be fail-closed",
                case.label
            );
            assert_eq!(
                event.denial_code.as_deref(),
                Some(expected_code),
                "{} denial audit code mismatch",
                case.label
            );
        }
        None => {
            assert!(result.is_ok(), "{} should authorize", case.label);
            let Some(event) = gate.audit_log().last() else {
                return Err(format!("{} authorization must be audited", case.label));
            };
            assert!(event.allowed, "{} audit should record an allow", case.label);
            assert_eq!(event.denial_code.as_deref(), None);
        }
    }

    Ok(())
}

#[test]
fn capability_gate_structure_aware_fuzz_seed_matrix() -> Result<(), String> {
    let cases = [
        CapabilityGateFuzzCase {
            label: "valid telemetry endpoint under declared prefix",
            issued_operation: RemoteOperation::TelemetryExport,
            attempted_operation: RemoteOperation::TelemetryExport,
            prefix: "https://telemetry.example.com/v1",
            endpoint: "https://telemetry.example.com/v1/push",
            ttl_secs: 300,
            now_epoch_secs: ISSUED_AT + 1,
            mode: ConnectivityMode::Connected,
            expected_error_code: None,
        },
        CapabilityGateFuzzCase {
            label: "expiry boundary rejects at exact expires_at",
            issued_operation: RemoteOperation::TelemetryExport,
            attempted_operation: RemoteOperation::TelemetryExport,
            prefix: "https://telemetry.example.com/v1",
            endpoint: "https://telemetry.example.com/v1/push",
            ttl_secs: 60,
            now_epoch_secs: ISSUED_AT + 60,
            mode: ConnectivityMode::Connected,
            expected_error_code: Some("REMOTECAP_EXPIRED"),
        },
        CapabilityGateFuzzCase {
            label: "sibling host prefix confusion fails closed",
            issued_operation: RemoteOperation::NetworkEgress,
            attempted_operation: RemoteOperation::NetworkEgress,
            prefix: "https://api.example.com",
            endpoint: "https://api.example.com.evil/jobs",
            ttl_secs: 300,
            now_epoch_secs: ISSUED_AT + 1,
            mode: ConnectivityMode::Connected,
            expected_error_code: Some("REMOTECAP_SCOPE_DENIED"),
        },
        CapabilityGateFuzzCase {
            label: "encoded traversal under path prefix fails closed",
            issued_operation: RemoteOperation::NetworkEgress,
            attempted_operation: RemoteOperation::NetworkEgress,
            prefix: "https://api.example.com/root/",
            endpoint: "https://api.example.com/root/%2e%2e/admin",
            ttl_secs: 300,
            now_epoch_secs: ISSUED_AT + 1,
            mode: ConnectivityMode::Connected,
            expected_error_code: Some("REMOTECAP_SCOPE_DENIED"),
        },
        CapabilityGateFuzzCase {
            label: "operation escalation fails closed",
            issued_operation: RemoteOperation::TelemetryExport,
            attempted_operation: RemoteOperation::FederationSync,
            prefix: "https://telemetry.example.com",
            endpoint: "https://telemetry.example.com/push",
            ttl_secs: 300,
            now_epoch_secs: ISSUED_AT + 1,
            mode: ConnectivityMode::Connected,
            expected_error_code: Some("REMOTECAP_SCOPE_DENIED"),
        },
        CapabilityGateFuzzCase {
            label: "local only mode denies network even with valid token",
            issued_operation: RemoteOperation::TelemetryExport,
            attempted_operation: RemoteOperation::TelemetryExport,
            prefix: "https://telemetry.example.com",
            endpoint: "https://telemetry.example.com/push",
            ttl_secs: 300,
            now_epoch_secs: ISSUED_AT + 1,
            mode: ConnectivityMode::LocalOnly,
            expected_error_code: Some("REMOTECAP_CONNECTIVITY_MODE_DENIED"),
        },
    ];

    for case in &cases {
        assert_gate_case(case)?;
    }

    Ok(())
}

#[test]
fn capability_gate_mutated_signature_seed_corpus_fails_closed() -> Result<(), String> {
    let base_case = CapabilityGateFuzzCase {
        label: "signature mutation seed",
        issued_operation: RemoteOperation::TelemetryExport,
        attempted_operation: RemoteOperation::TelemetryExport,
        prefix: "https://telemetry.example.com",
        endpoint: "https://telemetry.example.com/push",
        ttl_secs: 300,
        now_epoch_secs: ISSUED_AT + 1,
        mode: ConnectivityMode::Connected,
        expected_error_code: Some("REMOTECAP_INVALID"),
    };
    let cap = issue_case_cap(&base_case)?;
    let mut signature_seeds = vec![
        String::new(),
        "0".to_string(),
        "not-hex-signature".to_string(),
        "deadbeef".to_string(),
    ];
    signature_seeds.push("a".repeat(128));

    for signature in signature_seeds {
        let mut value = serde_json::to_value(&cap).map_err(|err| err.to_string())?;
        let Some(cap_fields) = value.as_object_mut() else {
            return Err("serialized capability must be a JSON object".to_string());
        };
        cap_fields.insert(
            "signature".to_string(),
            serde_json::Value::String(signature),
        );
        let mutated_cap: RemoteCap =
            serde_json::from_value(value).map_err(|err| err.to_string())?;
        let mut gate = CapabilityGate::with_mode(KEY_MATERIAL, base_case.mode)
            .map_err(|err| err.to_string())?;
        let result = gate.authorize_network(
            Some(&mutated_cap),
            base_case.attempted_operation,
            base_case.endpoint,
            base_case.now_epoch_secs,
            base_case.label,
        );

        let Err(err) = result else {
            return Err("mutated signature seed should fail closed".to_string());
        };
        assert_eq!(err.code(), "REMOTECAP_INVALID");
        let Some(event) = gate.audit_log().last() else {
            return Err("mutated signature denial must be audited".to_string());
        };
        assert!(!event.allowed);
        assert_eq!(event.denial_code.as_deref(), Some("REMOTECAP_INVALID"));
    }

    Ok(())
}
