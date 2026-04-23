//! RemoteCap CLI wire conformance harness.
//!
//! This is a spec-derived, process-based harness for the operator-facing
//! `franken-node remotecap ... --json` command surface. It verifies that the
//! JSON wire shape remains parseable and carries the contract fields required
//! by `docs/specs/remote_cap_contract.md`.

use assert_cmd::Command;
use serde_json::Value;
use std::collections::BTreeSet;
use std::fs;
use tempfile::TempDir;

const REMOTECAP_SPEC: &str = include_str!("../../../docs/specs/remote_cap_contract.md");
const REMOTECAP_TEST_KEY: &str = "remotecap-cli-wire-conformance-key";

#[derive(Debug, Clone, Copy)]
struct WireClause {
    spec_marker: &'static str,
    level: &'static str,
    test_case: &'static str,
}

const WIRE_CLAUSES: &[WireClause] = &[
    WireClause {
        spec_marker: "RemoteCap",
        level: "MUST",
        test_case: "issue emits signed token fields",
    },
    WireClause {
        spec_marker: "CapabilityProvider",
        level: "MUST",
        test_case: "issue emits REMOTECAP_ISSUED audit event",
    },
    WireClause {
        spec_marker: "CapabilityGate",
        level: "MUST",
        test_case: "verify/use emit structured audit events",
    },
    WireClause {
        spec_marker: "Verify the token (without consuming single-use tokens)",
        level: "MUST",
        test_case: "verify requires operation and endpoint scope arguments",
    },
    WireClause {
        spec_marker: "INV-REMOTECAP-AUDIT",
        level: "MUST",
        test_case: "all JSON command responses preserve trace IDs",
    },
    WireClause {
        spec_marker: "Use the token for a network operation",
        level: "MUST",
        test_case: "use authorizes the scoped endpoint",
    },
    WireClause {
        spec_marker: "Revoke the token when done",
        level: "MUST",
        test_case: "revoke emits revocation wire receipt",
    },
];

#[test]
fn remotecap_cli_wire_matrix_covers_required_spec_clauses() -> Result<(), String> {
    let tested_markers = WIRE_CLAUSES
        .iter()
        .map(|clause| clause.spec_marker)
        .collect::<BTreeSet<_>>();

    assert!(
        WIRE_CLAUSES.iter().all(|clause| clause.level == "MUST"),
        "this harness intentionally covers only mandatory RemoteCap wire clauses"
    );
    assert!(
        WIRE_CLAUSES
            .iter()
            .all(|clause| !clause.test_case.trim().is_empty()),
        "every conformance row must name the exercised test case"
    );
    for marker in tested_markers {
        if !REMOTECAP_SPEC.contains(marker) {
            return Err(format!(
                "RemoteCap conformance marker `{marker}` must remain anchored in the spec"
            ));
        }
    }

    Ok(())
}

#[test]
fn remotecap_verify_contract_documents_scope_authorization_args() -> Result<(), String> {
    let verify_block = REMOTECAP_SPEC
        .split("# Verify the token (without consuming single-use tokens)")
        .nth(1)
        .and_then(|tail| tail.split("# Use the token for a network operation").next())
        .ok_or_else(|| "RemoteCap spec must include the verify command block".to_string())?;

    for required in [
        "--token-file capability.json",
        "--operation network_egress",
        "--endpoint https://api.example.com/v1/status",
        "--json",
    ] {
        assert!(
            verify_block.contains(required),
            "RemoteCap verify spec must document `{required}`"
        );
    }
    assert!(
        REMOTECAP_SPEC.contains("FRANKEN_NODE_REMOTECAP_KEY"),
        "RemoteCap spec must document the implemented signing key environment variable"
    );
    assert!(
        !REMOTECAP_SPEC.contains("FRANKEN_NODE_REMOTECAP_SECRET"),
        "RemoteCap spec must not document the stale signing key environment variable"
    );

    Ok(())
}

#[test]
fn remotecap_cli_json_wire_lifecycle_conforms_to_contract() -> Result<(), String> {
    let workspace = TempDir::new().map_err(|err| format!("workspace: {err}"))?;

    let mut issue_cmd = remotecap_cmd(&workspace)?;
    issue_cmd.args([
        "issue",
        "--scope",
        "network_egress,telemetry_export",
        "--endpoint",
        "https://api.example.com",
        "--endpoint",
        "https://metrics.example.com",
        "--ttl",
        "15m",
        "--issuer",
        "operator-wire-conformance",
        "--operator-approved",
        "--single-use",
        "--trace-id",
        "trace-wire-issue",
        "--json",
    ]);
    let issue = run_json(&mut issue_cmd, "remotecap issue --json")?;
    assert_issue_wire(&issue)?;

    let token_id = expect_string(&issue["token"]["token_id"], "issue.token.token_id")?.to_string();
    let full_response_path = workspace.path().join("capability-response.json");
    let token_path = workspace.path().join("capability-token.json");
    write_json(&full_response_path, &issue)?;
    write_json(&token_path, &issue["token"])?;

    let mut verify_cmd = remotecap_cmd(&workspace)?;
    verify_cmd
        .arg("verify")
        .arg("--token-file")
        .arg(&full_response_path)
        .args([
            "--operation",
            "network_egress",
            "--endpoint",
            "https://api.example.com/v1/status",
            "--trace-id",
            "trace-wire-verify",
            "--json",
        ]);
    let verify = run_json(&mut verify_cmd, "remotecap verify --json")?;
    assert_bool(&verify["valid"], true, "verify.valid")?;
    assert_bool(&verify["authorized"], true, "verify.authorized")?;
    assert_eq!(verify["token_id"].as_str(), Some(token_id.as_str()));
    assert_eq!(verify["operation"].as_str(), Some("network_egress"));
    assert_eq!(
        verify["endpoint"].as_str(),
        Some("https://api.example.com/v1/status")
    );
    assert_audit_event(
        &verify["audit_event"],
        "REMOTECAP_RECHECK_PASSED",
        "trace-wire-verify",
        true,
    )?;

    let mut use_cmd = remotecap_cmd(&workspace)?;
    use_cmd
        .arg("use")
        .arg("--token-file")
        .arg(&token_path)
        .args([
            "--operation",
            "network_egress",
            "--endpoint",
            "https://api.example.com/v1/status",
            "--trace-id",
            "trace-wire-use",
            "--json",
        ]);
    let used = run_json(&mut use_cmd, "remotecap use --json")?;
    assert_bool(&used["allowed"], true, "use.allowed")?;
    assert_eq!(used["token_id"].as_str(), Some(token_id.as_str()));
    assert_eq!(used["operation"].as_str(), Some("network_egress"));
    assert_eq!(
        used["endpoint"].as_str(),
        Some("https://api.example.com/v1/status")
    );
    assert_audit_event(
        &used["audit_event"],
        "REMOTECAP_CONSUMED",
        "trace-wire-use",
        true,
    )?;

    let mut revoke_cmd = remotecap_cmd(&workspace)?;
    revoke_cmd
        .arg("revoke")
        .arg("--token-file")
        .arg(&token_path)
        .args(["--trace-id", "trace-wire-revoke", "--json"]);
    let revoked = run_json(&mut revoke_cmd, "remotecap revoke --json")?;
    assert_bool(&revoked["revoked"], true, "revoke.revoked")?;
    assert_eq!(revoked["token_id"].as_str(), Some(token_id.as_str()));
    assert_audit_event(
        &revoked["audit_event"],
        "REMOTECAP_REVOKED",
        "trace-wire-revoke",
        true,
    )?;

    Ok(())
}

fn remotecap_cmd(workspace: &TempDir) -> Result<Command, String> {
    let mut cmd = Command::cargo_bin("franken-node")
        .map_err(|err| format!("franken-node binary should resolve: {err}"))?;
    cmd.current_dir(workspace.path())
        .env("FRANKEN_NODE_REMOTECAP_KEY", REMOTECAP_TEST_KEY)
        .arg("remotecap");
    Ok(cmd)
}

fn run_json(cmd: &mut Command, label: &str) -> Result<Value, String> {
    let output = cmd.assert().success().get_output().stdout.clone();
    serde_json::from_slice(&output).map_err(|err| {
        format!(
            "{label} stdout must be JSON: {err}\nstdout:\n{}",
            String::from_utf8_lossy(&output)
        )
    })
}

fn write_json(path: &std::path::Path, value: &Value) -> Result<(), String> {
    let bytes = serde_json::to_vec_pretty(value).map_err(|err| format!("serialize json: {err}"))?;
    fs::write(path, bytes).map_err(|err| format!("write json {}: {err}", path.display()))
}

fn assert_issue_wire(value: &Value) -> Result<(), String> {
    assert_eq!(value["ttl_secs"].as_u64(), Some(900));
    assert!(
        value["issued_at_epoch_secs"].is_u64(),
        "issued_at_epoch_secs must be an integer"
    );

    let capability_payload = expect_object(&value["token"], "issue.token")?;
    expect_string(&capability_payload["token_id"], "issue.token.token_id")?;
    assert_eq!(
        capability_payload["issuer_identity"].as_str(),
        Some("operator-wire-conformance")
    );
    assert!(capability_payload["issued_at_epoch_secs"].is_u64());
    assert!(capability_payload["expires_at_epoch_secs"].is_u64());
    expect_string(&capability_payload["signature"], "issue.token.signature")?;
    assert_bool(
        &capability_payload["single_use"],
        true,
        "issue.token.single_use",
    )?;

    let scope = expect_object(&capability_payload["scope"], "issue.token.scope")?;
    assert_array_contains(
        &scope["operations"],
        &["network_egress", "telemetry_export"],
        "issue.token.scope.operations",
    )?;
    assert_array_contains(
        &scope["endpoint_prefixes"],
        &["https://api.example.com", "https://metrics.example.com"],
        "issue.token.scope.endpoint_prefixes",
    )?;
    assert_audit_event(
        &value["audit_event"],
        "REMOTECAP_ISSUED",
        "trace-wire-issue",
        true,
    )?;

    Ok(())
}

fn assert_audit_event(
    value: &Value,
    event_code: &str,
    trace_id: &str,
    allowed: bool,
) -> Result<(), String> {
    let event = expect_object(value, "audit_event")?;
    assert_eq!(event["event_code"].as_str(), Some(event_code));
    expect_string(&event["legacy_event_code"], "audit_event.legacy_event_code")?;
    assert_eq!(event["trace_id"].as_str(), Some(trace_id));
    assert!(event["timestamp_epoch_secs"].is_u64());
    assert_bool(&event["allowed"], allowed, "audit_event.allowed")?;
    Ok(())
}

fn expect_object<'a>(
    value: &'a Value,
    context: &str,
) -> Result<&'a serde_json::Map<String, Value>, String> {
    value
        .as_object()
        .ok_or_else(|| format!("{context} must be a JSON object"))
}

fn expect_string<'a>(value: &'a Value, context: &str) -> Result<&'a str, String> {
    value
        .as_str()
        .filter(|text| !text.is_empty())
        .ok_or_else(|| format!("{context} must be a non-empty string"))
}

fn assert_bool(value: &Value, expected: bool, context: &str) -> Result<(), String> {
    if value.as_bool() == Some(expected) {
        Ok(())
    } else {
        Err(format!("{context} must be boolean {expected}"))
    }
}

fn assert_array_contains(value: &Value, expected: &[&str], context: &str) -> Result<(), String> {
    let actual = value
        .as_array()
        .ok_or_else(|| format!("{context} must be an array"))?;
    for item in expected {
        if !actual.iter().any(|value| value.as_str() == Some(item)) {
            return Err(format!(
                "{context} must contain `{item}`; actual={actual:?}"
            ));
        }
    }
    Ok(())
}
