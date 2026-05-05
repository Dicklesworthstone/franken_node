//! Extension artifact contract conformance harness.
//!
//! This table-driven harness maps the artifact admission/enforcement invariants
//! to concrete fixtures, expected event/error codes, and pass/fail verdicts.

use std::collections::BTreeSet;

use frankenengine_node::extensions::artifact_contract::{
    AdmissionConfig, AdmissionDenialReason, AdmissionGate, AdmissionOutcome, CapabilityContract,
    CapabilityEntry, DriftCheckResult, EnforcementEngine, ExtensionArtifact, SCHEMA_VERSION,
    error_codes, event_codes, invariants, make_artifact, make_contract,
};
use serde_json::{Value, json};

mod bounded_input_policy_contract;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RequirementLevel {
    Must,
}

impl RequirementLevel {
    fn as_str(self) -> &'static str {
        match self {
            Self::Must => "MUST",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Verdict {
    Pass,
    Fail,
}

impl Verdict {
    fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Fail => "fail",
        }
    }
}

#[derive(Clone, Copy)]
struct ConformanceCase {
    id: &'static str,
    invariant: &'static str,
    level: RequirementLevel,
    fixture: &'static str,
    expected_code: &'static str,
    run: fn() -> Result<(), String>,
}

struct CaseResult {
    id: &'static str,
    invariant: &'static str,
    level: RequirementLevel,
    fixture: &'static str,
    expected_code: &'static str,
    verdict: Verdict,
    detail: String,
}

fn capabilities() -> Vec<CapabilityEntry> {
    vec![
        CapabilityEntry {
            capability_id: "fs.read".to_string(),
            scope: "filesystem:read".to_string(),
            max_calls_per_epoch: 100,
        },
        CapabilityEntry {
            capability_id: "net.egress".to_string(),
            scope: "network:egress".to_string(),
            max_calls_per_epoch: 10,
        },
    ]
}

fn trusted_gate() -> Result<AdmissionGate, String> {
    let mut config = AdmissionConfig::new(SCHEMA_VERSION);
    config
        .with_signer("signer-A")
        .map_err(|error| format!("trusted signer fixture should register: {error}"))?;
    Ok(AdmissionGate::new(config))
}

fn signed_contract() -> CapabilityContract {
    make_contract(
        "contract-1",
        "ext-alpha",
        capabilities(),
        "signer-A",
        SCHEMA_VERSION,
        1,
    )
}

fn signed_artifact() -> ExtensionArtifact {
    make_artifact("artifact-1", "ext-alpha", signed_contract())
}

fn require(condition: bool, message: impl Into<String>) -> Result<(), String> {
    if condition {
        Ok(())
    } else {
        Err(message.into())
    }
}

fn denied(outcome: AdmissionOutcome) -> Result<(AdmissionDenialReason, String), String> {
    match outcome {
        AdmissionOutcome::Denied { reason, event_code } => Ok((reason, event_code)),
        AdmissionOutcome::Accepted { event_code, .. } => Err(format!(
            "expected admission denial, got accepted event `{event_code}`"
        )),
    }
}

fn accepted(outcome: AdmissionOutcome) -> Result<(String, String, String), String> {
    match outcome {
        AdmissionOutcome::Accepted {
            contract_id,
            extension_id,
            event_code,
        } => Ok((contract_id, extension_id, event_code)),
        AdmissionOutcome::Denied { reason, event_code } => Err(format!(
            "expected admission acceptance, got `{event_code}` with reason `{}`",
            reason.code()
        )),
    }
}

fn case_missing_contract_denies() -> Result<(), String> {
    let mut artifact = signed_artifact();
    artifact.capability_contract = None;

    let (reason, event_code) = denied((trusted_gate()?).evaluate(&artifact))?;
    require(
        reason == AdmissionDenialReason::MissingContract,
        format!("expected missing-contract denial, got {reason:?}"),
    )?;
    require(
        event_code == error_codes::ERR_ARTIFACT_ADMISSION_DENIED,
        format!("expected admission-denied event, got `{event_code}`"),
    )?;
    require(
        reason.code() == error_codes::ERR_ARTIFACT_MISSING_CONTRACT,
        format!("expected missing-contract code, got `{}`", reason.code()),
    )
}

fn case_signature_tamper_denies() -> Result<(), String> {
    let mut artifact = signed_artifact();
    let Some(contract) = artifact.capability_contract.as_mut() else {
        return Err("signed artifact fixture must carry a contract".to_string());
    };
    let Some(first_capability) = contract.capabilities.first_mut() else {
        return Err("signed contract fixture must carry a capability".to_string());
    };
    first_capability.max_calls_per_epoch = first_capability.max_calls_per_epoch.saturating_add(1);

    let (reason, event_code) = denied((trusted_gate()?).evaluate(&artifact))?;
    require(
        matches!(reason, AdmissionDenialReason::SignatureInvalid),
        format!("expected signature-invalid denial, got {reason:?}"),
    )?;
    require(
        event_code == error_codes::ERR_ARTIFACT_ADMISSION_DENIED,
        format!("expected admission-denied event, got `{event_code}`"),
    )?;
    require(
        reason.code() == error_codes::ERR_ARTIFACT_SIGNATURE_INVALID,
        format!("expected signature-invalid code, got `{}`", reason.code()),
    )
}

fn case_capability_envelope_only_allows_declared_ids() -> Result<(), String> {
    let contract = signed_contract();
    let artifact = make_artifact("artifact-1", "ext-alpha", contract.clone());
    let (contract_id, extension_id, event_code) = accepted((trusted_gate()?).evaluate(&artifact))?;
    require(
        event_code == event_codes::ARTIFACT_ADMISSION_ACCEPTED,
        format!("expected accepted event, got `{event_code}`"),
    )?;
    require(contract_id == "contract-1", "accepted contract id drifted")?;
    require(extension_id == "ext-alpha", "accepted extension id drifted")?;

    let engine = EnforcementEngine::from_contract(&contract);
    require(
        engine.contract_id() == "contract-1",
        "engine contract id drifted",
    )?;
    require(
        engine.admitted_count() == 2,
        "engine admitted-count drifted",
    )?;
    require(
        engine.is_permitted("fs.read"),
        "declared fs.read capability must be permitted",
    )?;
    require(
        engine.is_permitted("net.egress"),
        "declared net.egress capability must be permitted",
    )?;
    require(
        !engine.is_permitted("process.spawn"),
        "undeclared process.spawn capability must be denied",
    )
}

fn case_exact_active_capabilities_have_no_drift() -> Result<(), String> {
    let engine = EnforcementEngine::from_contract(&signed_contract());
    match engine.check_drift(&["net.egress".to_string(), "fs.read".to_string()]) {
        DriftCheckResult::NoDrift { event_code } => require(
            event_code == event_codes::ARTIFACT_ENFORCEMENT_CHECK,
            format!("expected enforcement-check event, got `{event_code}`"),
        ),
        DriftCheckResult::DriftDetected { missing, extra, .. } => Err(format!(
            "expected no drift, got missing={missing:?} extra={extra:?}"
        )),
    }
}

fn case_missing_and_extra_active_capabilities_detect_drift() -> Result<(), String> {
    let engine = EnforcementEngine::from_contract(&signed_contract());
    match engine.check_drift(&["fs.read".to_string(), "process.spawn".to_string()]) {
        DriftCheckResult::DriftDetected {
            missing,
            extra,
            event_code,
        } => {
            require(
                event_code == event_codes::ARTIFACT_DRIFT_DETECTED,
                format!("expected drift-detected event, got `{event_code}`"),
            )?;
            require(
                missing == vec!["net.egress".to_string()],
                format!("expected net.egress missing, got {missing:?}"),
            )?;
            require(
                extra == vec!["process.spawn".to_string()],
                format!("expected process.spawn extra, got {extra:?}"),
            )
        }
        DriftCheckResult::NoDrift { event_code } => Err(format!(
            "expected drift detection, got no-drift event `{event_code}`"
        )),
    }
}

fn case_duplicate_capability_denies() -> Result<(), String> {
    let mut contract_capabilities = capabilities();
    contract_capabilities.push(CapabilityEntry {
        capability_id: "fs.read".to_string(),
        scope: "filesystem:read".to_string(),
        max_calls_per_epoch: 1,
    });
    let contract = make_contract(
        "contract-duplicate-capability",
        "ext-alpha",
        contract_capabilities,
        "signer-A",
        SCHEMA_VERSION,
        1,
    );
    let artifact = make_artifact("artifact-duplicate-capability", "ext-alpha", contract);

    let (reason, event_code) = denied((trusted_gate()?).evaluate(&artifact))?;
    require(
        matches!(reason, AdmissionDenialReason::InvalidCapability { .. }),
        format!("expected invalid-capability denial, got {reason:?}"),
    )?;
    require(
        event_code == error_codes::ERR_ARTIFACT_ADMISSION_DENIED,
        format!("expected admission-denied event, got `{event_code}`"),
    )?;
    require(
        reason.code() == error_codes::ERR_ARTIFACT_INVALID_CAPABILITY,
        format!("expected invalid-capability code, got `{}`", reason.code()),
    )
}

fn case_schema_mismatch_denies() -> Result<(), String> {
    let contract = make_contract(
        "contract-schema-mismatch",
        "ext-alpha",
        capabilities(),
        "signer-A",
        "capability-artifact-v0.9",
        1,
    );
    let artifact = make_artifact("artifact-schema-mismatch", "ext-alpha", contract);

    let (reason, event_code) = denied((trusted_gate()?).evaluate(&artifact))?;
    require(
        matches!(reason, AdmissionDenialReason::SchemaMismatch { .. }),
        format!("expected schema-mismatch denial, got {reason:?}"),
    )?;
    require(
        event_code == error_codes::ERR_ARTIFACT_ADMISSION_DENIED,
        format!("expected admission-denied event, got `{event_code}`"),
    )?;
    require(
        reason.code() == error_codes::ERR_ARTIFACT_SCHEMA_MISMATCH,
        format!("expected schema-mismatch code, got `{}`", reason.code()),
    )
}

fn conformance_cases() -> Vec<ConformanceCase> {
    vec![
        ConformanceCase {
            id: "artifact_missing_contract_fails_closed",
            invariant: invariants::INV_ARTIFACT_FAIL_CLOSED,
            level: RequirementLevel::Must,
            fixture: "missing_contract",
            expected_code: error_codes::ERR_ARTIFACT_MISSING_CONTRACT,
            run: case_missing_contract_denies,
        },
        ConformanceCase {
            id: "artifact_tampered_signature_fails_closed",
            invariant: invariants::INV_ARTIFACT_SIGNED_CONTRACT,
            level: RequirementLevel::Must,
            fixture: "tampered_contract_after_signature",
            expected_code: error_codes::ERR_ARTIFACT_SIGNATURE_INVALID,
            run: case_signature_tamper_denies,
        },
        ConformanceCase {
            id: "artifact_envelope_denies_undeclared_capabilities",
            invariant: invariants::INV_ARTIFACT_CAPABILITY_ENVELOPE,
            level: RequirementLevel::Must,
            fixture: "accepted_contract_runtime_envelope",
            expected_code: event_codes::ARTIFACT_ADMISSION_ACCEPTED,
            run: case_capability_envelope_only_allows_declared_ids,
        },
        ConformanceCase {
            id: "artifact_exact_active_set_has_no_drift",
            invariant: invariants::INV_ARTIFACT_NO_DRIFT,
            level: RequirementLevel::Must,
            fixture: "active_capabilities_match_contract",
            expected_code: event_codes::ARTIFACT_ENFORCEMENT_CHECK,
            run: case_exact_active_capabilities_have_no_drift,
        },
        ConformanceCase {
            id: "artifact_missing_and_extra_active_set_detects_drift",
            invariant: invariants::INV_ARTIFACT_NO_DRIFT,
            level: RequirementLevel::Must,
            fixture: "active_capabilities_missing_and_extra",
            expected_code: event_codes::ARTIFACT_DRIFT_DETECTED,
            run: case_missing_and_extra_active_capabilities_detect_drift,
        },
        ConformanceCase {
            id: "artifact_duplicate_capability_fails_closed",
            invariant: invariants::INV_ARTIFACT_FAIL_CLOSED,
            level: RequirementLevel::Must,
            fixture: "duplicate_capability_id",
            expected_code: error_codes::ERR_ARTIFACT_INVALID_CAPABILITY,
            run: case_duplicate_capability_denies,
        },
        ConformanceCase {
            id: "artifact_schema_mismatch_fails_closed",
            invariant: invariants::INV_ARTIFACT_FAIL_CLOSED,
            level: RequirementLevel::Must,
            fixture: "schema_version_mismatch",
            expected_code: error_codes::ERR_ARTIFACT_SCHEMA_MISMATCH,
            run: case_schema_mismatch_denies,
        },
    ]
}

fn run_case(conformance_case: ConformanceCase) -> CaseResult {
    match (conformance_case.run)() {
        Ok(()) => CaseResult {
            id: conformance_case.id,
            invariant: conformance_case.invariant,
            level: conformance_case.level,
            fixture: conformance_case.fixture,
            expected_code: conformance_case.expected_code,
            verdict: Verdict::Pass,
            detail: "fixture matched expected event/error code".to_string(),
        },
        Err(detail) => CaseResult {
            id: conformance_case.id,
            invariant: conformance_case.invariant,
            level: conformance_case.level,
            fixture: conformance_case.fixture,
            expected_code: conformance_case.expected_code,
            verdict: Verdict::Fail,
            detail,
        },
    }
}

fn render_report(results: &[CaseResult]) -> Value {
    let rows = results
        .iter()
        .map(|result| {
            json!({
                "id": result.id,
                "invariant": result.invariant,
                "level": result.level.as_str(),
                "fixture": result.fixture,
                "expected_code": result.expected_code,
                "verdict": result.verdict.as_str(),
                "detail": result.detail,
            })
        })
        .collect::<Vec<_>>();
    let total_cases = results.len();
    let passed_cases = results
        .iter()
        .filter(|result| result.verdict == Verdict::Pass)
        .count();

    json!({
        "schema_version": "franken-node/extension-artifact-contract-conformance/v1",
        "total_cases": total_cases,
        "passed_cases": passed_cases,
        "required_score": "100%",
        "matrix": rows,
    })
}

#[test]
fn extension_artifact_contract_conformance_matrix_covers_all_musts() -> Result<(), String> {
    let cases = conformance_cases();
    let results = cases.into_iter().map(run_case).collect::<Vec<_>>();
    let report = render_report(&results);
    let report_text = serde_json::to_string_pretty(&report)
        .unwrap_or_else(|error| format!("failed to render conformance report: {error}"));

    let failed_cases = results
        .iter()
        .filter(|result| result.verdict == Verdict::Fail)
        .map(|result| result.id)
        .collect::<Vec<_>>();
    require(
        failed_cases.is_empty(),
        format!("extension artifact conformance failures: {failed_cases:?}\n{report_text}"),
    )?;

    let required_invariants = [
        invariants::INV_ARTIFACT_FAIL_CLOSED,
        invariants::INV_ARTIFACT_CAPABILITY_ENVELOPE,
        invariants::INV_ARTIFACT_NO_DRIFT,
        invariants::INV_ARTIFACT_SIGNED_CONTRACT,
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();
    let covered_invariants = results
        .iter()
        .filter(|result| result.level == RequirementLevel::Must)
        .map(|result| result.invariant)
        .collect::<BTreeSet<_>>();
    require(
        required_invariants.is_subset(&covered_invariants),
        format!(
            "extension artifact conformance matrix missing invariants; required={required_invariants:?} covered={covered_invariants:?}\n{report_text}"
        ),
    )?;

    let must_total = results
        .iter()
        .filter(|result| result.level == RequirementLevel::Must)
        .count();
    let must_passed = results
        .iter()
        .filter(|result| result.level == RequirementLevel::Must && result.verdict == Verdict::Pass)
        .count();
    require(must_total > 0, "conformance matrix must include MUST rows")?;
    require(
        must_passed == must_total,
        format!("all MUST rows must pass: {must_passed}/{must_total}\n{report_text}"),
    )?;

    Ok(())
}

#[test]
fn extension_artifact_contract_error_code_surface_is_stable() -> Result<(), String> {
    require(
        AdmissionDenialReason::MissingContract.code() == error_codes::ERR_ARTIFACT_MISSING_CONTRACT,
        "missing-contract error code drifted",
    )?;
    require(
        AdmissionDenialReason::InvalidContract {
            detail: "fixture".to_string(),
        }
        .code()
            == error_codes::ERR_ARTIFACT_INVALID_CONTRACT,
        "invalid-contract error code drifted",
    )?;
    require(
        AdmissionDenialReason::InvalidCapability {
            detail: "fixture".to_string(),
        }
        .code()
            == error_codes::ERR_ARTIFACT_INVALID_CAPABILITY,
        "invalid-capability error code drifted",
    )?;
    require(
        AdmissionDenialReason::SignatureInvalid.code()
            == error_codes::ERR_ARTIFACT_SIGNATURE_INVALID,
        "signature-invalid error code drifted",
    )?;
    require(
        AdmissionDenialReason::SchemaMismatch {
            expected: SCHEMA_VERSION.to_string(),
            actual: "capability-artifact-v0.9".to_string(),
        }
        .code()
            == error_codes::ERR_ARTIFACT_SCHEMA_MISMATCH,
        "schema-mismatch error code drifted",
    )
}
