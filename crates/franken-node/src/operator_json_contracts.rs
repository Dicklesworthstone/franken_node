//! Registry for operator-facing JSON output contracts.
//!
//! The registry records which CLI/API JSON outputs are stable automation contracts and which
//! fields are volatile diagnostics. It does not provide compatibility shims; producers must bump
//! the owning schema version when a required field is renamed or removed.

use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeSet;

pub const REGISTRY_SCHEMA_ID: &str = "franken-node/operator-json-contract-registry";
pub const REGISTRY_SCHEMA_VERSION: &str = crate::schema_versions::OPERATOR_JSON_CONTRACT_REGISTRY;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OperatorJsonSurface {
    DoctorReport,
    VerifyReleaseReport,
    FleetReconcileReport,
    TrustCardExport,
    IncidentBundle,
    BenchRunReport,
    RuntimeEpochReport,
    RemoteCapabilityIssueReport,
}

impl OperatorJsonSurface {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DoctorReport => "doctor_report",
            Self::VerifyReleaseReport => "verify_release_report",
            Self::FleetReconcileReport => "fleet_reconcile_report",
            Self::TrustCardExport => "trust_card_export",
            Self::IncidentBundle => "incident_bundle",
            Self::BenchRunReport => "bench_run_report",
            Self::RuntimeEpochReport => "runtime_epoch_report",
            Self::RemoteCapabilityIssueReport => "remote_capability_issue_report",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FieldRole {
    RequiredContract,
    OptionalAdditive,
    VolatileDiagnostic,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RedactionKind {
    Timestamp,
    Path,
    Signature,
    Digest,
    Trace,
    Duration,
    Environment,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct RedactionGuidance {
    pub field_pattern: &'static str,
    pub kind: RedactionKind,
    pub guidance: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct OperatorJsonContract {
    pub surface: OperatorJsonSurface,
    pub command_or_route: &'static str,
    pub schema_id: &'static str,
    pub schema_version: &'static str,
    pub required_fields: &'static [&'static str],
    pub optional_fields: &'static [&'static str],
    pub volatile_fields: &'static [&'static str],
    pub owner_tests: &'static [&'static str],
    pub owner_gates: &'static [&'static str],
    pub notes: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "code", rename_all = "snake_case")]
pub enum OperatorJsonContractError {
    MissingRequiredField {
        surface: OperatorJsonSurface,
        field_path: String,
    },
    NullRequiredField {
        surface: OperatorJsonSurface,
        field_path: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OperatorJsonRegistryReport {
    pub schema_id: &'static str,
    pub schema_version: &'static str,
    pub contract_count: usize,
    pub surfaces: Vec<&'static str>,
    pub redaction_guidance: &'static [RedactionGuidance],
}

const DOCTOR_REQUIRED: &[&str] = &[
    "command",
    "trace_id",
    "generated_at_utc",
    "selected_profile",
    "overall_status",
    "status_counts",
    "checks",
];
const DOCTOR_OPTIONAL: &[&str] = &[
    "source_path",
    "structured_logs",
    "merge_decision_count",
    "merge_decisions",
];
const DOCTOR_VOLATILE: &[&str] = &["generated_at_utc", "trace_id", "duration_ms", "source_path"];

const VERIFY_RELEASE_REQUIRED: &[&str] = &[
    "release_path",
    "manifest_signature_ok",
    "results",
    "overall_pass",
    "unlisted_artifact_count",
];
const VERIFY_RELEASE_OPTIONAL: &[&str] = &["results.failure_reason", "results.key_id"];
const VERIFY_RELEASE_VOLATILE: &[&str] = &["release_path", "results.key_id"];

const FLEET_RECONCILE_REQUIRED: &[&str] = &[
    "action",
    "action.event_code",
    "convergence_receipt",
    "convergence_receipt.schema_version",
    "status",
    "state_dir",
    "state",
];
const FLEET_RECONCILE_OPTIONAL: &[&str] = &[
    "convergence_receipt.signature",
    "stale_nodes",
    "active_incidents",
    "state.actions",
    "state.nodes",
];
const FLEET_RECONCILE_VOLATILE: &[&str] = &[
    "action.operation_id",
    "action.receipt",
    "convergence_receipt.completed_at",
    "convergence_receipt.signature",
    "state_dir",
];

const TRUST_CARD_REQUIRED: &[&str] = &[
    "schema_version",
    "extension",
    "publisher",
    "trust_card_version",
    "card_hash",
    "registry_signature",
    "revocation_status",
];
const TRUST_CARD_OPTIONAL: &[&str] = &[
    "audit_history",
    "behavioral_profile",
    "capability_declarations",
    "derivation_evidence",
    "dependency_trust_summary",
];
const TRUST_CARD_VOLATILE: &[&str] = &[
    "audit_history.timestamp",
    "card_hash",
    "last_verified_timestamp",
    "registry_signature",
];

const INCIDENT_BUNDLE_REQUIRED: &[&str] = &[
    "schema_version",
    "incident_id",
    "collected_at",
    "trace_id",
    "severity",
    "timeline",
    "signature",
];
const INCIDENT_BUNDLE_OPTIONAL: &[&str] = &[
    "initial_state_snapshot",
    "metadata",
    "policy_version",
    "detector",
];
const INCIDENT_BUNDLE_VOLATILE: &[&str] = &[
    "collected_at",
    "trace_id",
    "signature.key_id",
    "signature.signature_hex",
];

const BENCH_RUN_REQUIRED: &[&str] = &[
    "suite_version",
    "scoring_formula_version",
    "timestamp_utc",
    "profile",
    "trace_id",
    "events",
    "scenarios",
];
const BENCH_RUN_OPTIONAL: &[&str] = &[
    "hardware_profile",
    "runtime_versions",
    "evidence_path",
    "sample_policy",
];
const BENCH_RUN_VOLATILE: &[&str] = &[
    "timestamp_utc",
    "trace_id",
    "git_revision",
    "hardware_profile",
    "runtime_versions",
];

const RUNTIME_EPOCH_REQUIRED: &[&str] = &[
    "schema_version",
    "command",
    "local_epoch",
    "peer_epoch",
    "verdict",
    "epoch_delta",
];
const RUNTIME_EPOCH_OPTIONAL: &[&str] = &[];
const RUNTIME_EPOCH_VOLATILE: &[&str] = &[];

const REMOTECAP_ISSUE_REQUIRED: &[&str] = &[
    "token",
    "token.token_id",
    "token.scope",
    "audit_event",
    "audit_event.event_code",
    "ttl_secs",
    "issued_at_epoch_secs",
];
const REMOTECAP_ISSUE_OPTIONAL: &[&str] = &[
    "audit_event.legacy_event_code",
    "audit_event.denial_code",
    "audit_event.operation",
    "audit_event.endpoint",
];
const REMOTECAP_ISSUE_VOLATILE: &[&str] = &[
    "token.token_id",
    "token.signature",
    "audit_event.token_id",
    "audit_event.trace_id",
];

pub const REDACTION_GUIDANCE: &[RedactionGuidance] = &[
    RedactionGuidance {
        field_pattern: "*timestamp*|*generated_at*|*completed_at*|*issued_at*",
        kind: RedactionKind::Timestamp,
        guidance: "Normalize to a deterministic placeholder before golden comparison.",
    },
    RedactionGuidance {
        field_pattern: "*path*|state_dir|release_path|evidence_path",
        kind: RedactionKind::Path,
        guidance: "Scrub absolute roots while preserving relative artifact identity.",
    },
    RedactionGuidance {
        field_pattern: "*signature*|*public_key*|*key_id*",
        kind: RedactionKind::Signature,
        guidance: "Preserve field presence and algorithm metadata; redact key and signature bytes.",
    },
    RedactionGuidance {
        field_pattern: "*hash*|*digest*|*sha256*",
        kind: RedactionKind::Digest,
        guidance: "Keep domain and field names stable; redact digest bytes only when fixture inputs vary.",
    },
    RedactionGuidance {
        field_pattern: "trace_id|operation_id|receipt_id|token_id",
        kind: RedactionKind::Trace,
        guidance: "Use deterministic fixture identifiers or stable placeholders.",
    },
    RedactionGuidance {
        field_pattern: "*duration*|elapsed_ms",
        kind: RedactionKind::Duration,
        guidance: "Clamp or replace runtime durations before snapshot comparison.",
    },
    RedactionGuidance {
        field_pattern: "hardware_profile|runtime_versions|git_revision",
        kind: RedactionKind::Environment,
        guidance: "Record the field as diagnostic unless a test fixture pins the environment.",
    },
];

const CONTRACTS: &[OperatorJsonContract] = &[
    OperatorJsonContract {
        surface: OperatorJsonSurface::DoctorReport,
        command_or_route: "franken-node doctor --json",
        schema_id: "franken-node/operator/doctor-report",
        schema_version: "doctor-report-v1",
        required_fields: DOCTOR_REQUIRED,
        optional_fields: DOCTOR_OPTIONAL,
        volatile_fields: DOCTOR_VOLATILE,
        owner_tests: &[
            "crates/franken-node/tests/doctor_json_schema_conformance.rs",
            "crates/franken-node/tests/cli_subcommand_goldens.rs",
        ],
        owner_gates: &["tests/test_doctor_command_diagnostics_gate.py"],
        notes: "Doctor output has no producer-emitted schema_version yet; this registry pins the automation contract.",
    },
    OperatorJsonContract {
        surface: OperatorJsonSurface::VerifyReleaseReport,
        command_or_route: "franken-node verify release --json",
        schema_id: "franken-node/operator/verify-release-report",
        schema_version: crate::schema_versions::VERIFY_CLI_CONTRACT,
        required_fields: VERIFY_RELEASE_REQUIRED,
        optional_fields: VERIFY_RELEASE_OPTIONAL,
        volatile_fields: VERIFY_RELEASE_VOLATILE,
        owner_tests: &["crates/franken-node/tests/verify_release_cli_e2e.rs"],
        owner_gates: &["tests/test_check_verifier_contract.py"],
        notes: "Release verification JSON is the stable artifact consumed by release automation.",
    },
    OperatorJsonContract {
        surface: OperatorJsonSurface::FleetReconcileReport,
        command_or_route: "franken-node fleet reconcile --json",
        schema_id: "franken-node/operator/fleet-reconcile-report",
        schema_version: "fleet-reconcile-report-v1",
        required_fields: FLEET_RECONCILE_REQUIRED,
        optional_fields: FLEET_RECONCILE_OPTIONAL,
        volatile_fields: FLEET_RECONCILE_VOLATILE,
        owner_tests: &["crates/franken-node/tests/fleet_cli_e2e.rs"],
        owner_gates: &["scripts/check_fleet_quarantine.py"],
        notes: "Fleet reports nest signed receipts; field presence is stable while signature bytes are volatile.",
    },
    OperatorJsonContract {
        surface: OperatorJsonSurface::TrustCardExport,
        command_or_route: "franken-node trust-card export --json",
        schema_id: "franken-node/operator/trust-card-export",
        schema_version: "trust-card-export-v1",
        required_fields: TRUST_CARD_REQUIRED,
        optional_fields: TRUST_CARD_OPTIONAL,
        volatile_fields: TRUST_CARD_VOLATILE,
        owner_tests: &[
            "crates/franken-node/tests/trust_card_wire_conformance.rs",
            "crates/franken-node/tests/trust_card_cross_version_conformance.rs",
        ],
        owner_gates: &["scripts/check_trust_card.py"],
        notes: "Trust-card export is consumed as evidence; additive optional fields are allowed.",
    },
    OperatorJsonContract {
        surface: OperatorJsonSurface::IncidentBundle,
        command_or_route: "franken-node incident bundle --json",
        schema_id: "franken-node/operator/incident-bundle",
        schema_version: "incident-bundle-v1",
        required_fields: INCIDENT_BUNDLE_REQUIRED,
        optional_fields: INCIDENT_BUNDLE_OPTIONAL,
        volatile_fields: INCIDENT_BUNDLE_VOLATILE,
        owner_tests: &["crates/franken-node/tests/incident_cli_e2e.rs"],
        owner_gates: &["scripts/check_incident_bundles.py"],
        notes: "Incident bundle JSON must expose missing or tampered evidence instead of omitting it.",
    },
    OperatorJsonContract {
        surface: OperatorJsonSurface::BenchRunReport,
        command_or_route: "franken-node bench run --json",
        schema_id: "franken-node/operator/bench-run-report",
        schema_version: crate::schema_versions::BENCHMARK_SUITE_VERSION,
        required_fields: BENCH_RUN_REQUIRED,
        optional_fields: BENCH_RUN_OPTIONAL,
        volatile_fields: BENCH_RUN_VOLATILE,
        owner_tests: &["crates/franken-node/tests/bench_run_e2e.rs"],
        owner_gates: &["scripts/check_benchmark_suite.py"],
        notes: "Benchmark JSON separates fixture-only evidence from release-grade performance claims.",
    },
    OperatorJsonContract {
        surface: OperatorJsonSurface::RuntimeEpochReport,
        command_or_route: "franken-node runtime epoch --json",
        schema_id: "franken-node/operator/runtime-epoch-report",
        schema_version: "runtime-epoch-v1",
        required_fields: RUNTIME_EPOCH_REQUIRED,
        optional_fields: RUNTIME_EPOCH_OPTIONAL,
        volatile_fields: RUNTIME_EPOCH_VOLATILE,
        owner_tests: &["crates/franken-node/tests/runtime_cli_e2e.rs"],
        owner_gates: &[],
        notes: "Runtime epoch mismatch JSON is a compact operator diagnostic surface.",
    },
    OperatorJsonContract {
        surface: OperatorJsonSurface::RemoteCapabilityIssueReport,
        command_or_route: "franken-node remotecap issue --json",
        schema_id: "franken-node/operator/remotecap-issue-report",
        schema_version: "remotecap-issue-report-v1",
        required_fields: REMOTECAP_ISSUE_REQUIRED,
        optional_fields: REMOTECAP_ISSUE_OPTIONAL,
        volatile_fields: REMOTECAP_ISSUE_VOLATILE,
        owner_tests: &["crates/franken-node/tests/remotecap_cli_e2e.rs"],
        owner_gates: &["scripts/check_verifier_replay_operator_e2e.py"],
        notes: "Remote capability issue JSON includes token and audit-event envelopes.",
    },
];

pub fn all_operator_json_contracts() -> &'static [OperatorJsonContract] {
    CONTRACTS
}

pub fn operator_json_contract(
    surface: OperatorJsonSurface,
) -> Option<&'static OperatorJsonContract> {
    CONTRACTS
        .iter()
        .find(|contract| contract.surface == surface)
}

pub fn operator_json_registry_report() -> OperatorJsonRegistryReport {
    OperatorJsonRegistryReport {
        schema_id: REGISTRY_SCHEMA_ID,
        schema_version: REGISTRY_SCHEMA_VERSION,
        contract_count: CONTRACTS.len(),
        surfaces: CONTRACTS
            .iter()
            .map(|contract| contract.surface.as_str())
            .collect(),
        redaction_guidance: REDACTION_GUIDANCE,
    }
}

pub fn validate_operator_json_value(
    surface: OperatorJsonSurface,
    value: &Value,
) -> Result<(), Vec<OperatorJsonContractError>> {
    let contract = operator_json_contract(surface)
        .expect("operator JSON surface must be registered before validation");
    let mut errors = Vec::new();

    for required in contract.required_fields {
        match field_at_path(value, required) {
            Some(Value::Null) => errors.push(OperatorJsonContractError::NullRequiredField {
                surface,
                field_path: (*required).to_string(),
            }),
            Some(_) => {}
            None => errors.push(OperatorJsonContractError::MissingRequiredField {
                surface,
                field_path: (*required).to_string(),
            }),
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

pub fn registered_surface_names() -> BTreeSet<&'static str> {
    CONTRACTS
        .iter()
        .map(|contract| contract.surface.as_str())
        .collect()
}

fn field_at_path<'a>(value: &'a Value, path: &str) -> Option<&'a Value> {
    let mut current = value;
    for segment in path.split('.') {
        current = current.as_object()?.get(segment)?;
    }
    Some(current)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_has_unique_surfaces_and_schema_ids() {
        let mut surfaces = BTreeSet::new();
        let mut schema_ids = BTreeSet::new();
        for contract in all_operator_json_contracts() {
            assert!(surfaces.insert(contract.surface.as_str()));
            assert!(schema_ids.insert(contract.schema_id));
            assert!(!contract.required_fields.is_empty());
            assert!(!contract.owner_tests.is_empty());
        }
        assert!(all_operator_json_contracts().len() >= 5);
        assert_eq!(surfaces.len(), all_operator_json_contracts().len());
        assert_eq!(schema_ids.len(), all_operator_json_contracts().len());
    }

    #[test]
    fn validator_allows_additive_optional_fields() {
        let mut value = serde_json::json!({
            "release_path": "/tmp/release",
            "manifest_signature_ok": true,
            "results": [],
            "overall_pass": true,
            "unlisted_artifact_count": 0,
            "future_optional_field": {"kept": true}
        });
        validate_operator_json_value(OperatorJsonSurface::VerifyReleaseReport, &value)
            .expect("additive optional field should not break contract");

        value.as_object_mut().unwrap().remove("overall_pass");
        let errors = validate_operator_json_value(OperatorJsonSurface::VerifyReleaseReport, &value)
            .expect_err("missing required field should fail");
        assert_eq!(
            errors,
            vec![OperatorJsonContractError::MissingRequiredField {
                surface: OperatorJsonSurface::VerifyReleaseReport,
                field_path: "overall_pass".to_string(),
            }]
        );
    }
}
