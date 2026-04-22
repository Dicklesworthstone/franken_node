#![no_main]

use arbitrary::Arbitrary;
use frankenengine_node::security::remote_cap::{
    CapabilityGate, CapabilityProvider, ConnectivityMode, RemoteCap, RemoteCapError,
    RemoteOperation, RemoteScope,
};
use libfuzzer_sys::fuzz_target;
use serde::{de::DeserializeOwned, Serialize};

const SECRET: &str = "remote-cap-token-parse-fuzz-secret";
const NOW: u64 = 1_700_000_000;
const MAX_RAW_JSON_BYTES: usize = 64 * 1024;
const MAX_STRING_CHARS: usize = 256;
const MAX_SCOPE_ITEMS: usize = 32;

fuzz_target!(|case: RemoteCapTokenParseCase| {
    fuzz_raw_token_json(
        &case.raw_json,
        case.operation.into_operation(),
        &case.requested_endpoint,
    );
    fuzz_token_shaped_json(
        &case.token_shape,
        case.operation.into_operation(),
        &case.requested_endpoint,
    );
    fuzz_issued_token_roundtrip(case);
});

fn fuzz_raw_token_json(bytes: &[u8], operation: RemoteOperation, endpoint: &str) {
    if bytes.len() > MAX_RAW_JSON_BYTES {
        return;
    }

    let endpoint = bounded_text(endpoint, "https://fuzz.example.com/api/resource");
    let _ = serde_json::from_slice::<serde_json::Value>(bytes);
    if let Ok(cap) = serde_json::from_slice::<RemoteCap>(bytes) {
        json_roundtrip(&cap);
        exercise_parsed_cap(&cap, operation, &endpoint, NOW.saturating_add(1));
    }
    if let Ok(scope) = serde_json::from_slice::<RemoteScope>(bytes) {
        json_roundtrip(&scope);
        assert_scope_predicates_are_stable(&scope, operation, &endpoint);
    }
    if let Ok(error) = serde_json::from_slice::<RemoteCapError>(bytes) {
        json_roundtrip(&error);
        assert!(!error.code().is_empty());
        assert!(!error.to_string().is_empty());
    }
}

fn fuzz_token_shaped_json(shape: &RemoteCapTokenShape, operation: RemoteOperation, endpoint: &str) {
    let object = serde_json::json!({
        "token_id": bounded_text(&shape.token_id, "token-shape"),
        "issuer_identity": bounded_text(&shape.issuer_identity, "issuer-shape"),
        "issued_at_epoch_secs": shape.issued_at_epoch_secs,
        "expires_at_epoch_secs": shape.expires_at_epoch_secs,
        "scope": {
            "operations": operation_values(&shape.operations),
            "endpoint_prefixes": bounded_strings(&shape.endpoint_prefixes),
        },
        "signature": bounded_text(&shape.signature, "signature-shape"),
        "single_use": shape.single_use,
    });
    let encoded = serde_json::to_vec(&object).expect("token-shaped JSON must serialize");
    if let Ok(cap) = serde_json::from_slice::<RemoteCap>(&encoded) {
        json_roundtrip(&cap);
        exercise_parsed_cap(
            &cap,
            operation,
            &bounded_text(endpoint, "https://fuzz.example.com/api/resource"),
            NOW.saturating_add(1),
        );
    }
}

fn fuzz_issued_token_roundtrip(case: RemoteCapTokenParseCase) {
    let operation = case.operation.into_operation();
    let issuer = bounded_text(&case.issuer_identity, "issuer-fuzz");
    let trace_id = bounded_text(&case.trace_id, "trace-fuzz");
    let mut prefixes = bounded_strings(&case.endpoint_prefixes);
    if prefixes.is_empty() {
        prefixes.push("https://fuzz.example.com/api".to_string());
    }
    let scope = RemoteScope::new(vec![operation], prefixes);
    let Some(prefix) = scope.endpoint_prefixes().first() else {
        return;
    };
    let endpoint = endpoint_for_prefix(prefix);
    let ttl = u64::from(case.ttl_hint % 3600).saturating_add(2);
    let provider = CapabilityProvider::new(SECRET);
    let Ok((cap, _audit)) = provider.issue(
        &issuer,
        scope.clone(),
        NOW,
        ttl,
        true,
        case.single_use,
        &trace_id,
    ) else {
        return;
    };

    let encoded = serde_json::to_vec(&cap).expect("issued remote cap must serialize");
    let decoded =
        serde_json::from_slice::<RemoteCap>(&encoded).expect("issued remote cap must deserialize");
    assert_eq!(decoded, cap);
    assert_scope_predicates_are_stable(decoded.scope(), operation, &endpoint);

    let mut gate = CapabilityGate::new(SECRET);
    gate.authorize_network(
        Some(&decoded),
        operation,
        &endpoint,
        NOW.saturating_add(1),
        "trace-valid-token-parse",
    )
    .expect("fresh parsed remote cap must authorize its issued scope");

    let mut local_gate = CapabilityGate::with_mode(SECRET, ConnectivityMode::LocalOnly);
    assert!(
        local_gate
            .recheck_network(
                Some(&decoded),
                operation,
                &endpoint,
                NOW.saturating_add(1),
                "trace-local-mode-parse",
            )
            .is_err(),
        "local-only mode must deny parsed remote capability tokens"
    );

    if let Some(tampered) = tamper_issued_token(&encoded, case.mutation) {
        let Ok(tampered_cap) = serde_json::from_slice::<RemoteCap>(&tampered) else {
            return;
        };
        let mut tampered_gate = CapabilityGate::new(SECRET);
        let result = tampered_gate.recheck_network(
            Some(&tampered_cap),
            operation,
            &endpoint,
            NOW.saturating_add(1),
            "trace-tampered-token-parse",
        );
        assert!(
            result.is_err(),
            "tampered parsed remote cap unexpectedly authorized"
        );
    }
}

fn exercise_parsed_cap(cap: &RemoteCap, operation: RemoteOperation, endpoint: &str, now: u64) {
    let mut gate = CapabilityGate::new(SECRET);
    let _ = gate.recheck_network(Some(cap), operation, endpoint, now, "trace-raw-token-parse");

    let mut local_gate = CapabilityGate::with_mode(SECRET, ConnectivityMode::LocalOnly);
    assert!(
        local_gate
            .recheck_network(
                Some(cap),
                operation,
                endpoint,
                now,
                "trace-raw-token-local-only",
            )
            .is_err(),
        "local-only mode must fail closed for any parsed remote cap"
    );
}

fn assert_scope_predicates_are_stable(
    scope: &RemoteScope,
    operation: RemoteOperation,
    endpoint: &str,
) {
    let allows_operation = scope.allows_operation(operation);
    let allows_endpoint = scope.allows_endpoint(endpoint);
    let reparsed = serde_json::from_slice::<RemoteScope>(
        &serde_json::to_vec(scope).expect("remote scope JSON encode"),
    )
    .expect("remote scope JSON decode");
    assert_eq!(reparsed.allows_operation(operation), allows_operation);
    assert_eq!(reparsed.allows_endpoint(endpoint), allows_endpoint);
}

fn tamper_issued_token(encoded: &[u8], mutation: TokenMutation) -> Option<Vec<u8>> {
    let mut value = serde_json::from_slice::<serde_json::Value>(encoded).ok()?;
    let object = value.as_object_mut()?;
    match mutation {
        TokenMutation::None => return None,
        TokenMutation::TokenId => {
            object.insert(
                "token_id".to_string(),
                serde_json::Value::String("tampered-token-id".to_string()),
            );
        }
        TokenMutation::Issuer => {
            object.insert(
                "issuer_identity".to_string(),
                serde_json::Value::String("tampered-issuer".to_string()),
            );
        }
        TokenMutation::Signature => {
            object.insert(
                "signature".to_string(),
                serde_json::Value::String("00".repeat(32)),
            );
        }
        TokenMutation::Expiry => {
            object.insert(
                "expires_at_epoch_secs".to_string(),
                serde_json::Value::Number(serde_json::Number::from(NOW)),
            );
        }
        TokenMutation::SingleUse => {
            let current = object
                .get("single_use")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false);
            object.insert("single_use".to_string(), serde_json::Value::Bool(!current));
        }
        TokenMutation::ScopeOperation => {
            if let Some(scope) = object
                .get_mut("scope")
                .and_then(serde_json::Value::as_object_mut)
            {
                scope.insert("operations".to_string(), serde_json::json!([]));
            }
        }
        TokenMutation::ScopeEndpoint => {
            if let Some(scope) = object
                .get_mut("scope")
                .and_then(serde_json::Value::as_object_mut)
            {
                scope.insert(
                    "endpoint_prefixes".to_string(),
                    serde_json::json!(["https://tampered.example.com"]),
                );
            }
        }
        TokenMutation::DeleteSignature => {
            object.remove("signature");
        }
    }
    serde_json::to_vec(&value).ok()
}

fn json_roundtrip<T>(value: &T)
where
    T: Serialize + DeserializeOwned + PartialEq + core::fmt::Debug,
{
    let encoded = serde_json::to_vec(value).expect("remote cap JSON encode");
    let decoded = serde_json::from_slice::<T>(&encoded).expect("remote cap JSON decode");
    assert_eq!(&decoded, value);
}

fn operation_values(operations: &[FuzzOperationField]) -> Vec<serde_json::Value> {
    operations
        .iter()
        .take(MAX_SCOPE_ITEMS)
        .map(FuzzOperationField::to_value)
        .collect()
}

fn bounded_strings(values: &[String]) -> Vec<String> {
    values
        .iter()
        .take(MAX_SCOPE_ITEMS)
        .map(|value| bounded_text(value, ""))
        .filter(|value| !value.trim().is_empty())
        .collect()
}

fn bounded_text(value: &str, fallback: &str) -> String {
    let text = value.chars().take(MAX_STRING_CHARS).collect::<String>();
    if text.trim().is_empty() {
        fallback.to_string()
    } else {
        text
    }
}

fn endpoint_for_prefix(prefix: &str) -> String {
    if prefix.ends_with('/') || prefix.ends_with(':') {
        format!("{prefix}resource")
    } else {
        format!("{prefix}/resource")
    }
}

#[derive(Debug, Arbitrary)]
struct RemoteCapTokenParseCase {
    raw_json: Vec<u8>,
    token_shape: RemoteCapTokenShape,
    issuer_identity: String,
    trace_id: String,
    endpoint_prefixes: Vec<String>,
    operation: FuzzOperation,
    requested_endpoint: String,
    ttl_hint: u16,
    single_use: bool,
    mutation: TokenMutation,
}

#[derive(Debug, Arbitrary)]
struct RemoteCapTokenShape {
    token_id: String,
    issuer_identity: String,
    issued_at_epoch_secs: u64,
    expires_at_epoch_secs: u64,
    operations: Vec<FuzzOperationField>,
    endpoint_prefixes: Vec<String>,
    signature: String,
    single_use: bool,
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

#[derive(Debug, Clone, Copy, Arbitrary)]
enum FuzzOperationField {
    Valid(FuzzOperation),
    Unknown,
    Empty,
    Uppercase,
    Number,
}

impl FuzzOperationField {
    fn to_value(self) -> serde_json::Value {
        match self {
            Self::Valid(operation) => {
                serde_json::Value::String(operation.into_operation().as_str().to_string())
            }
            Self::Unknown => serde_json::Value::String("unknown_remote_operation".to_string()),
            Self::Empty => serde_json::Value::String(String::new()),
            Self::Uppercase => serde_json::Value::String("NETWORK_EGRESS".to_string()),
            Self::Number => serde_json::Value::Number(serde_json::Number::from(7)),
        }
    }
}

#[derive(Debug, Clone, Copy, Arbitrary)]
enum TokenMutation {
    None,
    TokenId,
    Issuer,
    Signature,
    Expiry,
    SingleUse,
    ScopeOperation,
    ScopeEndpoint,
    DeleteSignature,
}
