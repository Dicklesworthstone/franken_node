#![no_main]

use arbitrary::Arbitrary;
use frankenengine_node::security::remote_cap::{
    CapabilityGate, CapabilityProvider, RemoteCap, RemoteOperation, RemoteScope,
};
use libfuzzer_sys::fuzz_target;

const SECRET: &str = "capability-token-parser-fuzz-secret";
const NOW: u64 = 1_700_000_000;
const MAX_RAW_BYTES: usize = 16 * 1024;
const MAX_STRING_CHARS: usize = 256;
const MAX_SCOPE_ITEMS: usize = 16;

#[derive(Debug, Arbitrary)]
struct CapabilityTokenParserCase {
    raw_json: Vec<u8>,
    issuer: String,
    trace_id: String,
    endpoint_prefixes: Vec<String>,
    operation: FuzzOperation,
    tamper: TokenTamper,
    single_use: bool,
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

#[derive(Debug, Arbitrary)]
enum TokenTamper {
    None,
    TokenId,
    Issuer,
    Signature,
    Expiry,
    ScopeOperation,
    ScopeEndpoint,
    DeleteSignature,
}

fuzz_target!(|case: CapabilityTokenParserCase| {
    fuzz_capability_token_parser(case);
});

fn fuzz_capability_token_parser(case: CapabilityTokenParserCase) {
    if case.raw_json.len() <= MAX_RAW_BYTES {
        parse_and_authorize_raw_json(&case.raw_json, case.operation.into_operation());
    }

    let operation = case.operation.into_operation();
    let issuer = bounded_string(case.issuer);
    let trace_id = bounded_string(case.trace_id);
    let mut prefixes = bounded_strings(case.endpoint_prefixes);
    if prefixes.is_empty() {
        prefixes.push("https://fuzz.example.com/api".to_string());
    }
    let scope = RemoteScope::new(vec![operation], prefixes);
    let Some(allowed_prefix) = scope.endpoint_prefixes().first() else {
        return;
    };
    let allowed_endpoint = endpoint_for_prefix(allowed_prefix);
    let ttl = u64::from(case.ttl_hint % 3600).saturating_add(2);

    let Ok(provider) = CapabilityProvider::new(SECRET) else {
        return;
    };
    let Ok((cap, _)) = provider.issue(&issuer, scope, NOW, ttl, true, case.single_use, &trace_id)
    else {
        return;
    };

    let encoded = serde_json::to_vec(&cap).expect("issued capability token must serialize");
    let decoded =
        serde_json::from_slice::<RemoteCap>(&encoded).expect("issued capability token must parse");
    let mut gate = CapabilityGate::new(SECRET).expect("valid capability gate");
    gate.authorize_network(
        Some(&decoded),
        operation,
        &allowed_endpoint,
        NOW.saturating_add(1),
        "trace-valid-token",
    )
    .expect("fresh parsed capability token must authorize its issued scope");

    if let Some(tampered) = tamper_token_json(&encoded, case.tamper) {
        let Ok(tampered_cap) = serde_json::from_slice::<RemoteCap>(&tampered) else {
            return;
        };
        let Ok(mut tampered_gate) = CapabilityGate::new(SECRET) else {
            return;
        };
        let result = tampered_gate.authorize_network(
            Some(&tampered_cap),
            operation,
            &allowed_endpoint,
            NOW.saturating_add(1),
            "trace-tampered-token",
        );
        assert!(
            result.is_err(),
            "tampered capability token unexpectedly authorized"
        );
    }
}

fn parse_and_authorize_raw_json(bytes: &[u8], operation: RemoteOperation) {
    let _ = serde_json::from_slice::<serde_json::Value>(bytes);
    if let Ok(cap) = serde_json::from_slice::<RemoteCap>(bytes) {
        let mut gate = CapabilityGate::new(SECRET).expect("valid capability gate");
        let _ = gate.authorize_network(
            Some(&cap),
            operation,
            "https://fuzz.example.com/api/resource",
            NOW.saturating_add(1),
            "trace-raw-token",
        );
    }
}

fn tamper_token_json(encoded: &[u8], tamper: TokenTamper) -> Option<Vec<u8>> {
    let mut value = serde_json::from_slice::<serde_json::Value>(encoded).ok()?;
    let object = value.as_object_mut()?;
    match tamper {
        TokenTamper::None => return None,
        TokenTamper::TokenId => {
            object.insert(
                "token_id".to_string(),
                serde_json::Value::String("forged-token-id".to_string()),
            );
        }
        TokenTamper::Issuer => {
            object.insert(
                "issuer_identity".to_string(),
                serde_json::Value::String("forged-issuer".to_string()),
            );
        }
        TokenTamper::Signature => {
            object.insert(
                "signature".to_string(),
                serde_json::Value::String("00".repeat(32)),
            );
        }
        TokenTamper::Expiry => {
            object.insert(
                "expires_at_epoch_secs".to_string(),
                serde_json::Value::Number(serde_json::Number::from(NOW)),
            );
        }
        TokenTamper::ScopeOperation => {
            if let Some(scope) = object
                .get_mut("scope")
                .and_then(serde_json::Value::as_object_mut)
            {
                scope.insert("operations".to_string(), serde_json::json!([]));
            }
        }
        TokenTamper::ScopeEndpoint => {
            if let Some(scope) = object
                .get_mut("scope")
                .and_then(serde_json::Value::as_object_mut)
            {
                scope.insert(
                    "endpoint_prefixes".to_string(),
                    serde_json::json!(["https://forged.example.com"]),
                );
            }
        }
        TokenTamper::DeleteSignature => {
            object.remove("signature");
        }
    }
    serde_json::to_vec(&value).ok()
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

fn endpoint_for_prefix(prefix: &str) -> String {
    if prefix.ends_with('/') || prefix.ends_with(':') {
        format!("{prefix}resource")
    } else {
        format!("{prefix}/resource")
    }
}
