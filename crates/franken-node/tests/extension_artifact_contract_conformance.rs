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
use frankenengine_node::supply_chain::certification::{EvidenceType, VerifiedEvidenceRef};
use frankenengine_node::supply_chain::trust_card::{
    BehavioralProfile, CapabilityDeclaration, CapabilityRisk, CertificationLevel,
    ExtensionIdentity, ProvenanceSummary, PublisherIdentity, ReputationTrend, RevocationStatus,
    RiskAssessment, RiskLevel, TrustCardInput, TrustCardRegistry,
};
use serde_json::{Value, json};

mod bounded_input_policy_contract;

// API-DRIFT REMEDIATION (bd-rjc2m.5): AdmissionGate::evaluate() gained two parameters
// (trust_registry: Option<&mut TrustCardRegistry>, now_secs: u64) and now fails closed
// (TrustRevoked) when no registry/card is available — so each case evaluates against a
// seeded trust registry (see trusted_registry()) at a fixed deterministic timestamp.
const ADMISSION_NOW_SECS: u64 = 1_750_000_000;

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

/// Build a TrustCardRegistry seeded with a valid (non-revoked, non-quarantined) trust card
/// for the fixture extension, so the admission gate's trust check (INV-ARTIFACT-TRUST-VALIDATED)
/// passes and the downstream signature/schema/capability invariants can be exercised.
/// The gate fails closed with TrustRevoked when no registry (or no card) is available.
fn trusted_registry() -> Result<TrustCardRegistry, String> {
    let mut registry = TrustCardRegistry::new(300, b"extension-artifact-conformance-trust-key-v1");
    let input = TrustCardInput {
        extension: ExtensionIdentity {
            extension_id: "ext-alpha".to_string(),
            version: "1.0.0".to_string(),
        },
        publisher: PublisherIdentity {
            publisher_id: "publisher:artifact-conformance".to_string(),
            display_name: "Artifact Conformance Publisher".to_string(),
        },
        certification_level: CertificationLevel::Silver,
        capability_declarations: vec![CapabilityDeclaration {
            name: "fs.read".to_string(),
            description: "filesystem read capability".to_string(),
            risk: CapabilityRisk::Medium,
        }],
        behavioral_profile: BehavioralProfile {
            network_access: true,
            filesystem_access: true,
            subprocess_access: false,
            profile_summary: "artifact conformance fixture profile".to_string(),
        },
        revocation_status: RevocationStatus::Active,
        provenance_summary: ProvenanceSummary {
            attestation_level: "conformance-fixture".to_string(),
            source_uri: "conformance://ext-alpha".to_string(),
            artifact_hashes: vec!["sha256:".to_string() + &"c".repeat(64)],
            verified_at: "2026-06-01T00:00:00Z".to_string(),
        },
        reputation_score_basis_points: 9_000,
        reputation_trend: ReputationTrend::Stable,
        active_quarantine: false,
        dependency_trust_summary: Vec::new(),
        last_verified_timestamp: "2026-06-01T00:00:00Z".to_string(),
        user_facing_risk_assessment: RiskAssessment {
            level: RiskLevel::Medium,
            summary: "artifact conformance fixture".to_string(),
        },
        evidence_refs: vec![VerifiedEvidenceRef {
            evidence_id: "artifact-conformance-evidence".to_string(),
            evidence_type: EvidenceType::TestCoverageReport,
            verified_at_epoch: ADMISSION_NOW_SECS,
            verification_receipt_hash: "a".repeat(64),
        }],
    };
    registry
        .create(input, ADMISSION_NOW_SECS, "artifact-conformance-trust-seed")
        .map_err(|error| format!("trust card seed should succeed: {error}"))?;
    Ok(registry)
}

/// Evaluate an artifact through a trusted gate with a seeded trust registry.
fn evaluate_with_trust(artifact: &ExtensionArtifact) -> Result<AdmissionOutcome, String> {
    let gate = trusted_gate()?;
    let mut trust_registry = trusted_registry()?;
    Ok(gate.evaluate(artifact, Some(&mut trust_registry), ADMISSION_NOW_SECS))
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

    let (reason, event_code) = denied(evaluate_with_trust(&artifact)?)?;
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

    let (reason, event_code) = denied(evaluate_with_trust(&artifact)?)?;
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
    let (contract_id, extension_id, event_code) = accepted(evaluate_with_trust(&artifact)?)?;
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

    let (reason, event_code) = denied(evaluate_with_trust(&artifact)?)?;
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

    let (reason, event_code) = denied(evaluate_with_trust(&artifact)?)?;
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
