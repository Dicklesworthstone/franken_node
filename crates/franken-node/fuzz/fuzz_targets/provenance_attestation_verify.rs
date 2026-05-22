#![no_main]

use frankenengine_node::supply_chain::provenance::{
    ProvenanceAttestation, VerificationPolicy, canonical_attestation_json, enforce_fail_closed,
    required_downstream_gates, verify_and_project_gates, verify_attestation_chain,
};
use libfuzzer_sys::fuzz_target;
use serde_json::Value;

const MAX_INPUT_BYTES: usize = 128 * 1024;
const MAX_TRACE_BYTES: usize = 256;
const DEFAULT_NOW_EPOCH: u64 = 1_700_000_400;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_BYTES {
        return;
    }

    if let Ok(attestation) = serde_json::from_slice::<ProvenanceAttestation>(data) {
        exercise_attestation(
            &attestation,
            &VerificationPolicy::production_default(),
            "raw",
        );
        exercise_attestation(
            &attestation,
            &VerificationPolicy::development_profile(),
            "raw-dev",
        );
    }

    let Ok(value) = serde_json::from_slice::<Value>(data) else {
        return;
    };

    if let Ok(attestation) = serde_json::from_value::<ProvenanceAttestation>(value.clone()) {
        exercise_attestation(
            &attestation,
            &VerificationPolicy::production_default(),
            "value",
        );
    }

    let Some(object) = value.as_object() else {
        return;
    };

    let policy = object
        .get("policy")
        .and_then(|policy| serde_json::from_value::<VerificationPolicy>(policy.clone()).ok())
        .unwrap_or_else(VerificationPolicy::production_default);
    let now_epoch = object
        .get("now_epoch")
        .and_then(Value::as_u64)
        .unwrap_or(DEFAULT_NOW_EPOCH);
    let trace_id = object
        .get("trace_id")
        .and_then(Value::as_str)
        .map(|trace| bounded_string(trace, MAX_TRACE_BYTES))
        .unwrap_or_else(|| "fuzz-trace".to_string());

    if let Some(attestation_value) = object.get("attestation") {
        if let Ok(attestation) =
            serde_json::from_value::<ProvenanceAttestation>(attestation_value.clone())
        {
            exercise_attestation_with_trace(&attestation, &policy, now_epoch, &trace_id);
        }
    }
});

fn exercise_attestation(
    attestation: &ProvenanceAttestation,
    policy: &VerificationPolicy,
    trace_id: &str,
) {
    exercise_attestation_with_trace(attestation, policy, DEFAULT_NOW_EPOCH, trace_id);
}

fn exercise_attestation_with_trace(
    attestation: &ProvenanceAttestation,
    policy: &VerificationPolicy,
    now_epoch: u64,
    trace_id: &str,
) {
    let report = verify_attestation_chain(attestation, policy, now_epoch, trace_id);
    let repeated = verify_attestation_chain(attestation, policy, now_epoch, trace_id);
    assert_eq!(
        report, repeated,
        "provenance verification report must be deterministic"
    );
    assert_eq!(
        report.trace_id, trace_id,
        "verification report must preserve trace_id"
    );

    if report.chain_valid {
        enforce_fail_closed(&report).expect("valid report must pass fail-closed enforcement");
        assert!(
            report.issues.iter().all(|issue| issue.allow_in_cached_mode),
            "valid reports may only carry cached-mode-allowed issues"
        );
    } else {
        let failure =
            enforce_fail_closed(&report).expect_err("invalid report must fail closed with cause");
        assert!(
            report
                .issues
                .iter()
                .any(|issue| issue.code == failure.code && issue.link_role == failure.broken_link),
            "fail-closed error must be derived from a recorded issue"
        );
    }

    let outcome = verify_and_project_gates(attestation, policy, now_epoch, trace_id);
    assert_eq!(
        outcome.report, report,
        "projected verification outcome must reuse the verifier report"
    );
    let expected_gates = if report.chain_valid {
        required_downstream_gates(report.provenance_level)
    } else {
        frankenengine_node::supply_chain::provenance::DownstreamGateRequirements::deny_all()
    };
    assert_eq!(
        outcome.downstream_gates, expected_gates,
        "invalid provenance must deny downstream gates and valid provenance must map by level"
    );

    if let Ok(canonical) = canonical_attestation_json(attestation) {
        let reparsed = serde_json::from_str::<ProvenanceAttestation>(&canonical)
            .expect("canonical attestation JSON must parse");
        assert_eq!(
            &reparsed, attestation,
            "canonical attestation JSON must round-trip"
        );
    }
}

fn bounded_string(value: &str, max_bytes: usize) -> String {
    if value.len() <= max_bytes {
        return value.to_string();
    }

    let mut out = String::with_capacity(max_bytes);
    for ch in value.chars() {
        if out.len().saturating_add(ch.len_utf8()) > max_bytes {
            break;
        }
        out.push(ch);
    }
    out
}
