//! Native-capture inspection without linking the engine or executing its input.
//!
//! Called only after the enclosing incident bundle passes the auditor-supplied
//! Ed25519 anchor and replay-structure checks. Raw JSON is signed as a string:
//! outer duplicate-key checks cannot see duplicate members inside that string.
//! This module checks its own envelope/digest and terminal declaration, not IR
//! correctness, provider outcomes, cleanup certification or replayability.

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use super::{IncidentBundleError, UnambiguousJson, ct_str_eq};

const CAPTURE_SCHEMA: &str = "franken-node/native-replay-capture/v2";
const MAX_PAYLOAD_BYTES: usize = 4 * 1024 * 1024;
const ENVELOPE_FIELDS: &[&str] = &["schema_version", "payload_json", "payload_sha256"];
const PAYLOAD_FIELDS: &[&str] = &[
    "package", "orchestrator", "runtime", "ambient_authority",
    "host_io_exception_provenance", "process_argv", "host_effect_transcript", "expected",
];
const COMPLETED_FIELDS: &[&str] = &[
    "terminal_state", "trace_id", "ir4_witness", "execution_value",
    "instructions_executed", "console_output", "nondeterminism_trace", "lane", "decisions",
];
const EXCEPTION_FIELDS: &[&str] = &[
    "terminal_state", "trace_id", "exception_value", "console_output",
];
const ENGINE_FAILURE_FIELDS: &[&str] = &[
    "terminal_state", "trace_id", "reason", "diagnostic", "console_output",
];

type Result<T> = std::result::Result<T, IncidentBundleError>;

/// The producer's authenticated terminal declaration, not an executed result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapturedNativeTerminalState {
    Completed,
    UncaughtException,
    EngineFailure,
}

/// Metadata derived from a capture carried by an authenticated incident bundle.
/// No source, arguments, environment values or diagnostics are returned. A
/// successful inspection is NOT a claim of native-execution equivalence or a
/// substitute for `incident replay --execute` and its consumption checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedNativeCaptureMetadata {
    pub payload_sha256: String,
    pub payload_bytes: usize,
    pub captured_terminal_state: CapturedNativeTerminalState,
    /// Count of recorded host-I/O exchanges; their semantic results are not
    /// verified here, and process effects are not included in this count.
    pub host_io_exchange_count: usize,
}

fn invalid(field: &str, reason: &'static str) -> IncidentBundleError {
    // All callers supply a fixed field path, never a private captured value.
    IncidentBundleError::Structure {
        path: format!("$.initial_state_snapshot.native_replay{field}"),
        reason,
    }
}

fn object<'a>(value: &'a Value, field: &str) -> Result<&'a Map<String, Value>> {
    value.as_object().ok_or_else(|| invalid(field, "expected object"))
}

fn text<'a>(value: &'a Value, field: &str) -> Result<&'a str> {
    value.as_str().ok_or_else(|| invalid(field, "expected string"))
}

fn array<'a>(value: &'a Value, field: &str) -> Result<&'a [Value]> {
    value.as_array().map(Vec::as_slice)
        .ok_or_else(|| invalid(field, "expected array"))
}

fn exact<'a>(
    value: &'a Value,
    field: &str,
    required: &[&str],
    optional: &[&str],
) -> Result<&'a Map<String, Value>> {
    let map = object(value, field)?;
    if required.iter().any(|key| !map.contains_key(*key))
        || map.keys().any(|key| !required.contains(&key.as_str()) && !optional.contains(&key.as_str()))
    {
        return Err(invalid(field, "missing or unknown native capture field"));
    }
    Ok(map)
}

fn nonblank<'a>(value: &'a Value, field: &str) -> Result<&'a str> {
    let value = text(value, field)?;
    if value.trim().is_empty() {
        return Err(invalid(field, "empty native capture identity"));
    }
    Ok(value)
}

fn terminal(payload: &Value) -> Result<CapturedNativeTerminalState> {
    let expected = &payload["expected"];
    object(expected, ".payload.expected")?;
    let state = match text(&expected["terminal_state"], ".payload.expected.terminal_state")? {
        "completed" => {
            exact(expected, ".payload.expected", COMPLETED_FIELDS, &["exit_code"])?;
            object(&expected["ir4_witness"], ".payload.expected.ir4_witness")?;
            object(&expected["nondeterminism_trace"], ".payload.expected.nondeterminism_trace")?;
            text(&expected["execution_value"], ".payload.expected.execution_value")?;
            text(&expected["lane"], ".payload.expected.lane")?;
            if expected["instructions_executed"].as_u64().is_none() {
                return Err(invalid(".payload.expected.instructions_executed", "expected unsigned integer"));
            }
            if let Some(exit) = expected.get("exit_code") {
                if !exit.is_null() && !exit.as_i64().is_some_and(|code| i32::try_from(code).is_ok()) {
                    return Err(invalid(".payload.expected.exit_code", "expected null or i32 exit code"));
                }
            }
            CapturedNativeTerminalState::Completed
        }
        "uncaught_exception" => {
            exact(expected, ".payload.expected", EXCEPTION_FIELDS, &[])?;
            // Throwing an empty string is a legitimate guest exception.
            text(&expected["exception_value"], ".payload.expected.exception_value")?;
            CapturedNativeTerminalState::UncaughtException
        }
        "engine_failure" => {
            exact(expected, ".payload.expected", ENGINE_FAILURE_FIELDS, &[])?;
            let diagnostic = text(&expected["diagnostic"], ".payload.expected.diagnostic")?;
            if diagnostic.is_empty() || diagnostic.len() > 4096 {
                return Err(invalid(".payload.expected.diagnostic", "expected bounded native diagnostic"));
            }
            let reason = &expected["reason"];
            object(reason, ".payload.expected.reason")?;
            match text(&reason["kind"], ".payload.expected.reason.kind")? {
                "capability_denied" => {
                    exact(reason, ".payload.expected.reason", &["kind", "capability"], &[])?;
                    nonblank(&reason["capability"], ".payload.expected.reason.capability")?;
                }
                "instruction_budget_exhausted" => {
                    exact(reason, ".payload.expected.reason", &["kind", "budget"], &[])?;
                    let budget = reason["budget"].as_u64()
                        .ok_or_else(|| invalid(".payload.expected.reason.budget", "expected unsigned integer"))?;
                    let execution = &payload["runtime"]["execution"];
                    if execution["deterministic_budget"].as_u64() != Some(budget)
                        && execution["throughput_budget"].as_u64() != Some(budget)
                    {
                        return Err(invalid(".payload.expected.reason.budget", "instruction limit is not bound to captured runtime settings"));
                    }
                }
                _ => return Err(invalid(".payload.expected.reason.kind", "unsupported native stopping reason")),
            }
            CapturedNativeTerminalState::EngineFailure
        }
        _ => return Err(invalid(".payload.expected.terminal_state", "unsupported native terminal state")),
    };
    nonblank(&expected["trace_id"], ".payload.expected.trace_id")?;
    for entry in array(&expected["console_output"], ".payload.expected.console_output")? {
        object(entry, ".payload.expected.console_output[]")?;
        text(&entry["message"], ".payload.expected.console_output[].message")?;
    }
    Ok(state)
}

pub(super) fn verify(initial: &Value) -> Result<Option<VerifiedNativeCaptureMetadata>> {
    let Some(capture) = initial.get("native_replay") else { return Ok(None); };
    let envelope = exact(capture, "", ENVELOPE_FIELDS, &[])?;
    if text(&envelope["schema_version"], ".schema_version")? != CAPTURE_SCHEMA {
        return Err(invalid(".schema_version", "unsupported native capture schema"));
    }
    let raw = text(&envelope["payload_json"], ".payload_json")?;
    if raw.is_empty() || raw.len() > MAX_PAYLOAD_BYTES {
        return Err(invalid(".payload_json", "native payload must contain 1..=4194304 bytes"));
    }
    let digest = hex::encode(Sha256::digest(raw.as_bytes()));
    if !ct_str_eq(text(&envelope["payload_sha256"], ".payload_sha256")?, &digest) {
        return Err(invalid(".payload_sha256", "does not match the exact captured payload bytes"));
    }
    // Do not canonicalize or regenerate raw: even whitespace is part of its
    // authenticated digest. The inner parser rejects ambiguity independently.
    let UnambiguousJson(payload) = serde_json::from_str(raw)
        .map_err(|_| invalid(".payload_json", "native payload must be unambiguous JSON"))?;
    exact(&payload, ".payload", PAYLOAD_FIELDS, &["process"])?;
    for field in ["package", "orchestrator", "runtime"] {
        object(&payload[field], ".payload.settings")?;
    }
    nonblank(&payload["package"]["extension_id"], ".payload.package.extension_id")?;
    nonblank(&payload["package"]["source"], ".payload.package.source")?;
    for capability in array(&payload["package"]["capabilities"], ".payload.package.capabilities")? {
        nonblank(capability, ".payload.package.capabilities[]")?;
    }
    for arg in array(&payload["process_argv"], ".payload.process_argv")? {
        text(arg, ".payload.process_argv[]")?;
    }
    match text(&payload["ambient_authority"], ".payload.ambient_authority")? {
        "deny_all" | "trusted_process_shape" => {}
        _ => return Err(invalid(".payload.ambient_authority", "unsupported captured ambient grant")),
    }
    text(&payload["host_io_exception_provenance"], ".payload.host_io_exception_provenance")?;
    if let Some(process) = payload.get("process").filter(|value| !value.is_null()) {
        object(process, ".payload.process")?;
    }
    let exchanges = array(&payload["host_effect_transcript"], ".payload.host_effect_transcript")?;
    for exchange in exchanges {
        let pair = array(exchange, ".payload.host_effect_transcript[]")?;
        if pair.len() != 2 {
            return Err(invalid(".payload.host_effect_transcript[]", "expected request/outcome pair"));
        }
        object(&pair[0], ".payload.host_effect_transcript[].request")?;
        let outcome = object(&pair[1], ".payload.host_effect_transcript[].outcome")?;
        if outcome.len() != 1 || !(outcome.contains_key("Ok") || outcome.contains_key("Err")) {
            return Err(invalid(".payload.host_effect_transcript[].outcome", "expected one result outcome"));
        }
    }
    let captured_terminal_state = terminal(&payload)?;
    Ok(Some(VerifiedNativeCaptureMetadata {
        payload_sha256: digest,
        payload_bytes: raw.len(),
        captured_terminal_state,
        host_io_exchange_count: exchanges.len(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // Minimal metadata fixtures, not claims of valid engine IR or actual guest
    // execution. Engine settings, IR and transcript semantics still require
    // the product's native replay validator and re-execution.
    fn payload(state: &str) -> Value {
        let mut expected = json!({"terminal_state":state,"trace_id":"trace-1","console_output":[]});
        match state {
            "completed" => {
                expected["ir4_witness"] = json!({});
                expected["execution_value"] = json!("42");
                expected["instructions_executed"] = json!(7);
                expected["nondeterminism_trace"] = json!({});
                expected["lane"] = json!("deterministic");
                expected["exit_code"] = Value::Null;
                expected["decisions"] = Value::Null;
            }
            "uncaught_exception" => expected["exception_value"] = json!(""),
            "engine_failure" => {
                expected["reason"] = json!({"kind":"instruction_budget_exhausted","budget":100});
                expected["diagnostic"] = json!("instruction budget exhausted");
            }
            _ => {}
        }
        json!({
            "package":{"extension_id":"test","source":"throw '';","capabilities":["builtin"]},
            "orchestrator":{},"runtime":{"execution":{"deterministic_budget":100,"throughput_budget":200}},
            "ambient_authority":"deny_all","host_io_exception_provenance":"provider_internal",
            "process_argv":[],"host_effect_transcript":[],"expected":expected
        })
    }

    fn captured_raw(raw: String) -> Value {
        json!({"native_replay":{
            "schema_version":CAPTURE_SCHEMA,"payload_sha256":hex::encode(Sha256::digest(raw.as_bytes())),
            "payload_json":raw
        }})
    }

    fn captured(payload: &Value) -> Value { captured_raw(serde_json::to_string(payload).unwrap()) }

    #[test]
    fn captures_keep_distinct_terminal_declarations_and_absent_capture_is_not_successful_execution() {
        assert_eq!(verify(&json!({})).unwrap(), None);
        for (state, expected) in [
            ("completed", CapturedNativeTerminalState::Completed),
            ("uncaught_exception", CapturedNativeTerminalState::UncaughtException),
            ("engine_failure", CapturedNativeTerminalState::EngineFailure),
        ] {
            let capture = captured(&payload(state));
            let metadata = verify(&capture).unwrap().unwrap();
            assert_eq!(metadata.captured_terminal_state, expected);
            assert_eq!(metadata.payload_sha256, capture["native_replay"]["payload_sha256"]);
            assert_eq!(metadata.host_io_exchange_count, 0);
        }
    }

    #[test]
    fn nested_ambiguity_cannot_hide_inside_an_authentic_raw_json_string() {
        let raw = serde_json::to_string(&payload("uncaught_exception")).unwrap();
        for (needle, replacement) in [
            ("\"trace_id\":", "\"trace_id\":\"other\",\"trace_id\":"),
            ("\"trace_id\":", "\"trace\\u005fid\":\"other\",\"trace_id\":"),
            ("\"runtime\":", "\"runtime\":{},\"runtime\":"),
        ] {
            assert!(raw.contains(needle));
            let duplicate = raw.replacen(needle, replacement, 1);
            assert_eq!(serde_json::from_str::<Value>(&duplicate).unwrap(), serde_json::from_str::<Value>(&raw).unwrap());
            let error = verify(&captured_raw(duplicate)).unwrap_err();
            assert!(matches!(error, IncidentBundleError::Structure { reason: "native payload must be unambiguous JSON", .. }));
        }
    }

    #[test]
    fn envelope_limits_exact_bytes_and_schema_are_enforced_before_payload_use() {
        let value = payload("completed");
        let mut capture = captured(&value);
        capture["native_replay"]["payload_json"] = json!(format!("{} ", capture["native_replay"]["payload_json"].as_str().unwrap()));
        assert!(verify(&capture).is_err());
        let raw = serde_json::to_string_pretty(&value).unwrap();
        assert_eq!(verify(&captured_raw(raw.clone())).unwrap().unwrap().payload_bytes, raw.len());
        for raw in [String::new(), " ".repeat(MAX_PAYLOAD_BYTES + 1), "{} {}".into(), "[1]".into()] {
            assert!(verify(&captured_raw(raw)).is_err());
        }
        for key in ENVELOPE_FIELDS {
            let mut capture = captured(&value);
            capture["native_replay"].as_object_mut().unwrap().remove(*key);
            assert!(verify(&capture).is_err());
        }
        let mut capture = captured(&value);
        capture["native_replay"]["schema_version"] = json!("franken-node/native-replay-capture/v99");
        assert!(verify(&capture).is_err());
        assert!(verify(&json!({"native_replay":null})).is_err());
    }

    #[test]
    fn failed_prefixes_cannot_manufacture_completed_witness_fields() {
        for state in ["uncaught_exception", "engine_failure"] {
            for field in ["ir4_witness", "instructions_executed", "nondeterminism_trace", "exit_code", "decisions"] {
                let mut value = payload(state);
                value["expected"][field] = Value::Null;
                assert!(verify(&captured(&value)).is_err(), "{state}: {field}");
            }
        }
        for state in ["cancelled", "panicked", "timeout", "unknown"] {
            assert!(verify(&captured(&payload(state))).is_err());
        }
    }

    #[test]
    fn native_reasons_need_their_own_typed_shape_and_bound_budget() {
        let mut value = payload("engine_failure");
        value["expected"]["reason"] = json!({"kind":"capability_denied","capability":"env_read"});
        assert!(verify(&captured(&value)).is_ok());
        for reason in [
            json!({"kind":"instruction_budget_exhausted","budget":99}),
            json!({"kind":"instruction_budget_exhausted","budget":-1}),
            json!({"kind":"instruction_budget_exhausted","budget":100,"capability":"env_read"}),
            json!({"kind":"capability_denied","capability":""}),
            json!({"kind":"watchdog_timeout"}),
        ] {
            value["expected"]["reason"] = reason;
            assert!(verify(&captured(&value)).is_err());
        }
        let mut value = payload("uncaught_exception");
        value["expected"]["exception_value"] = json!("instruction budget exhausted");
        assert_eq!(verify(&captured(&value)).unwrap().unwrap().captured_terminal_state,
            CapturedNativeTerminalState::UncaughtException);
    }

    #[test]
    fn metadata_never_echoes_private_source_arguments_or_diagnostics() {
        let secret = "PRIVATE-SENTINEL-δ";
        let mut value = payload("engine_failure");
        value["package"]["source"] = json!(secret);
        value["process_argv"] = json!([secret]);
        value["expected"]["diagnostic"] = json!(secret);
        assert!(!format!("{:?}", verify(&captured(&value)).unwrap()).contains(secret));
        value["expected"]["reason"]["kind"] = json!(secret);
        let error = verify(&captured(&value)).unwrap_err();
        assert!(!format!("{error:?}: {error}").contains(secret));
    }
}
