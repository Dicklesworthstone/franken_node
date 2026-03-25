//! Centralized schema version registry.
//!
//! All protocol schema version strings are defined here to provide a single
//! point of reference during protocol evolution.  When bumping a schema version,
//! update the constant here and grep for its old value to find any hardcoded
//! references that were missed.
//!
//! **Note:** existing modules still define their own local copies.  This registry
//! is the *authoritative* catalogue — a future migration task will re-export from
//! here.

// ── Runtime & Scheduling ───────────────────────────────────────────
pub const LANE_SCHEDULER: &str = "ls-v1.0";
pub const TIME_TRAVEL: &str = "ttr-v1.0";
pub const TIME_TRAVEL_ENGINE: &str = "ttr-v1.0";
pub const CANCELLABLE_TASK: &str = "cxt-v1.0";
pub const ISOLATION_MESH: &str = "isolation-mesh-v1.0";
pub const OBLIGATION_CHANNEL: &str = "och-v1.0";
pub const REGION_TREE: &str = "region-v1.0";
pub const NVERSION_ORACLE: &str = "nvo-v1.0";
pub const OPTIMIZATION_GOVERNOR: &str = "gov-v1.0";
pub const HARDWARE_PLANNER: &str = "hwp-v1.0";
pub const INCIDENT_LAB: &str = "incident-lab-v1.0";
pub const AUTHORITY_AUDIT: &str = "aa-v1.0";
pub const SPECULATION_PROOF_EXECUTOR: &str = "speculation-proof-v1.0";

// ── Control Plane ──────────────────────────────────────────────────
pub const TRANSITION_ABORT: &str = "ta-v1.0";
pub const CONTROL_LANE_POLICY: &str = "clp-v1.0";
pub const CONTROL_LANE_MAPPING: &str = "clm-v1.0";
pub const DPOR_EXPLORATION: &str = "dpor-v1.0";
pub const ROOT_POINTER_FORMAT: &str = "v1";
pub const EPOCH_TRANSITION_BARRIER: &str = "eb-v1.0";
pub const CANCELLATION_INJECTION: &str = "ci-v1.0";
pub const CANCELLATION_PROTOCOL: &str = "cp-v1.0";

// ── Connector ──────────────────────────────────────────────────────
pub const OBLIGATION_TRACKER: &str = "obl-v1.0";
pub const MIGRATION_PIPELINE: &str = "pipe-v1.0";
pub const SUPERVISION: &str = "sup-v1.0";
pub const CAPABILITY_GUARD: &str = "cap-v1.0";
pub const CAPABILITY_ARTIFACT: &str = "cart-v1.0";
pub const CLAIM_COMPILER: &str = "claim-compiler-v1.0";
pub const CONNECTOR_VERIFIER_SDK: &str = "ver-v1.0";
pub const N_VERSION_ORACLE: &str = "n-version-oracle-v1.0";
pub const TRANSPORT_FAULT_GATE: &str = "tfg-v1.0";
pub const CANCEL_INJECTION_GATE: &str = "cig-v1.0";
pub const DPOR_SCHEDULE_GATE: &str = "dsg-v1.0";
pub const SAGA: &str = "saga-v1.0";
pub const EVICTION_SAGA: &str = "es-v1.0";
pub const MIGRATION_ARTIFACT: &str = "ma-v1.0";
pub const CONNECTOR_CANCELLATION_PROTOCOL: &str = "cancel-v1.0";
pub const UNIVERSAL_VERIFIER_SDK: &str = "vsdk-v1.0";
pub const VEF_EXECUTION_RECEIPT: &str = "vef-execution-receipt-v1";
pub const VEF_POLICY_LANGUAGE: &str = "vef-policy-lang-v1";
pub const VEF_CONSTRAINT_COMPILER: &str = "vef-constraint-compiler-v1";
pub const VEF_POLICY_CONSTRAINTS: &str = "vef-policy-constraints-v1";

// ── Verifier & Evidence ────────────────────────────────────────────
pub const VERIFIER_SDK_API: &str = "1.0.0";
pub const VERIFIER_SDK_SCHEMA_TAG: &str = "vsk-v1.0";
pub const SDK_REPLAY_CAPSULE: &str = "replay-capsule-v1";
pub const VEP_REPLAY_CAPSULE: &str = "vep-replay-capsule-v2";
pub const VEF_CONSTRAINT_COMPILER_SCHEMA: &str = "vef-constraints-v1.0";
pub const VEF_CONSTRAINT_COMPILER_VERSION: &str = "1.0.0";
pub const VEF_EVIDENCE_CAPSULE: &str = "evidence-capsule-v1.0";
pub const VEF_VERIFICATION_STATE: &str = "verification-state-v1.0";
pub const VEF_PROOF_SCHEDULER: &str = "vef-proof-scheduler-v1";
pub const VEF_PROOF_GENERATOR: &str = "vef-proof-generator-v1";
pub const VEF_PROOF_GENERATOR_FORMAT: &str = "1.0.0";
pub const VEF_PROOF_VERIFIER: &str = "vef-proof-verifier-v1";
pub const VEF_PROOF_SERVICE: &str = "vef-proof-service-v1";
pub const VEF_SDK_INTEGRATION: &str = "vef-sdk-integration-v1";
pub const VEF_SDK_INTEGRATION_FORMAT: &str = "1.0.0";
pub const VEF_SDK_INTEGRATION_MIN_FORMAT: &str = "1.0.0";
pub const VEF_RECEIPT_CHAIN: &str = "vef-receipt-chain-v1";
pub const VEF_CONTROL_INTEGRATION: &str = "vef-control-integration-v1";

// ── Extensions ─────────────────────────────────────────────────────
pub const CAPABILITY_ARTIFACT_CONTRACT: &str = "capability-artifact-v1.0";

// ── Claims ─────────────────────────────────────────────────────────
pub const CLAIMS_CLAIM_COMPILER: &str = "claim-compiler-v1.0";

// ── Conformance ────────────────────────────────────────────────────
pub const CONFORMANCE_SUITE_SCHEMA: &str = "cs-v1.0";
pub const CONFORMANCE_SUITE_VERSION: &str = "1.0.0";

// ── Security ───────────────────────────────────────────────────────
pub const INTENT_FIREWALL: &str = "fw-v1.0";
pub const ZK_ATTESTATION: &str = "zka-v1.0";
pub const STAKING_GOVERNANCE: &str = "staking-v1.0";
pub const LINEAGE_TRACKER: &str = "ifl-v1.0";

// ── Registry ───────────────────────────────────────────────────────
pub const REGISTRY_STAKING_GOVERNANCE: &str = "staking-v1.0";

// ── Storage ────────────────────────────────────────────────────────
pub const STORAGE_MODEL: &str = "1.0.0";

// ── Supply Chain ───────────────────────────────────────────────────
pub const MANIFEST: &str = "1.0";
pub const EXTENSION_REGISTRY: &str = "ser-v2.0";
pub const MIGRATION_KIT: &str = "mke-v1.0";

// ── Remote ─────────────────────────────────────────────────────────
pub const IDEMPOTENCY_STORE: &str = "ids-v1.0";
pub const REMOTE_EVICTION_SAGA: &str = "es-v1.0";
pub const VIRTUAL_TRANSPORT_FAULTS: &str = "vtf-v1.0";

// ── Testing ────────────────────────────────────────────────────────
pub const SCENARIO_BUILDER: &str = "sb-v1.0";
pub const VIRTUAL_TRANSPORT: &str = "vt-v1.0";
pub const LAB_RUNTIME: &str = "lab-v1.0";

// ── Tools ──────────────────────────────────────────────────────────
pub const MIGRATION_INCIDENT_DATASETS: &str = "rds-v1.0";
pub const REPORT_OUTPUT_CONTRACT: &str = "roc-v1.0";
pub const SECURITY_TRUST_METRICS: &str = "secm-v1";
pub const BENCHMARK_SUITE_SCORING: &str = "sf-v1";
pub const BENCHMARK_SUITE_VERSION: &str = "1.0.0";
pub const BENCHMARK_METHODOLOGY: &str = "bmp-v1.0";
pub const VERIFIER_BENCHMARK_RELEASES: &str = "vbr-v1.0";
pub const SECURITY_OPS_CASE_STUDIES: &str = "csc-v1.0";
pub const FRONTIER_DEMO_GATE: &str = "demo-v1.0";
pub const EXTERNAL_REPLICATION_CLAIMS: &str = "erc-v1.0";
pub const COMPATIBILITY_CORRECTNESS_METRICS: &str = "ccm-v1.0";
pub const TRUST_ECONOMICS_DASHBOARD: &str = "ted-v1.0";
pub const MIGRATION_SPEED_FAILURE_METRICS: &str = "msf-v1.0";
pub const ENTERPRISE_GOVERNANCE: &str = "egi-v1.0";
pub const ADVERSARIAL_RESILIENCE_METRICS: &str = "arm-v1.0";
pub const MIGRATION_VALIDATION_COHORTS: &str = "mvc-v1.0";
pub const TRANSPARENT_REPORTS: &str = "tr-v1.0";
pub const PARTNER_LIGHTHOUSE_PROGRAMS: &str = "plp-v1.0";
pub const SAFE_EXTENSION_ONBOARDING: &str = "seo-v1.0";
pub const VERIFIER_TOOLKIT: &str = "vtk-v1.0";
pub const REDTEAM_EVALUATIONS: &str = "rte-v1.0";
pub const REPLAY_DETERMINISM_METRICS: &str = "rdm-v1.0";
pub const PERFORMANCE_HARDENING_METRICS: &str = "phm-v1.0";
pub const CONTAINMENT_REVOCATION_METRICS: &str = "crm-v1.0";
pub const VEF_PERF_BUDGET_GATE: &str = "1.0.0";
pub const COUNTERFACTUAL_REPLAY_ENGINE: &str = "counterfactual-v1";
pub const REPLAY_BUNDLE_POLICY: &str = "0.1.0";

// ── CLI ────────────────────────────────────────────────────────────
pub const VERIFY_CLI_CONTRACT: &str = "3.0.0";

// ── Verifier Economy ──────────────────────────────────────────────
// (re-states VEP_REPLAY_CAPSULE above; included for completeness of origin tracking)

// ── Utility ────────────────────────────────────────────────────────

/// Return all registered schema versions as `(name, version)` pairs.
/// Useful for diagnostics (e.g., `franken-node doctor --versions`).
pub fn all_versions() -> Vec<(&'static str, &'static str)> {
    vec![
        // Runtime & Scheduling
        ("lane_scheduler", LANE_SCHEDULER),
        ("time_travel", TIME_TRAVEL),
        ("time_travel_engine", TIME_TRAVEL_ENGINE),
        ("cancellable_task", CANCELLABLE_TASK),
        ("isolation_mesh", ISOLATION_MESH),
        ("obligation_channel", OBLIGATION_CHANNEL),
        ("region_tree", REGION_TREE),
        ("nversion_oracle", NVERSION_ORACLE),
        ("optimization_governor", OPTIMIZATION_GOVERNOR),
        ("hardware_planner", HARDWARE_PLANNER),
        ("incident_lab", INCIDENT_LAB),
        ("authority_audit", AUTHORITY_AUDIT),
        ("speculation_proof_executor", SPECULATION_PROOF_EXECUTOR),
        // Control Plane
        ("transition_abort", TRANSITION_ABORT),
        ("control_lane_policy", CONTROL_LANE_POLICY),
        ("control_lane_mapping", CONTROL_LANE_MAPPING),
        ("dpor_exploration", DPOR_EXPLORATION),
        ("root_pointer_format", ROOT_POINTER_FORMAT),
        ("epoch_transition_barrier", EPOCH_TRANSITION_BARRIER),
        ("cancellation_injection", CANCELLATION_INJECTION),
        ("cancellation_protocol", CANCELLATION_PROTOCOL),
        // Connector
        ("obligation_tracker", OBLIGATION_TRACKER),
        ("migration_pipeline", MIGRATION_PIPELINE),
        ("supervision", SUPERVISION),
        ("capability_guard", CAPABILITY_GUARD),
        ("capability_artifact", CAPABILITY_ARTIFACT),
        ("claim_compiler", CLAIM_COMPILER),
        ("connector_verifier_sdk", CONNECTOR_VERIFIER_SDK),
        ("n_version_oracle", N_VERSION_ORACLE),
        ("transport_fault_gate", TRANSPORT_FAULT_GATE),
        ("cancel_injection_gate", CANCEL_INJECTION_GATE),
        ("dpor_schedule_gate", DPOR_SCHEDULE_GATE),
        ("saga", SAGA),
        ("eviction_saga", EVICTION_SAGA),
        ("migration_artifact", MIGRATION_ARTIFACT),
        (
            "connector_cancellation_protocol",
            CONNECTOR_CANCELLATION_PROTOCOL,
        ),
        ("universal_verifier_sdk", UNIVERSAL_VERIFIER_SDK),
        ("vef_execution_receipt", VEF_EXECUTION_RECEIPT),
        ("vef_policy_language", VEF_POLICY_LANGUAGE),
        ("vef_constraint_compiler", VEF_CONSTRAINT_COMPILER),
        ("vef_policy_constraints", VEF_POLICY_CONSTRAINTS),
        // Verifier & Evidence
        ("verifier_sdk_api", VERIFIER_SDK_API),
        ("verifier_sdk_schema_tag", VERIFIER_SDK_SCHEMA_TAG),
        ("sdk_replay_capsule", SDK_REPLAY_CAPSULE),
        ("vep_replay_capsule", VEP_REPLAY_CAPSULE),
        (
            "vef_constraint_compiler_schema",
            VEF_CONSTRAINT_COMPILER_SCHEMA,
        ),
        (
            "vef_constraint_compiler_version",
            VEF_CONSTRAINT_COMPILER_VERSION,
        ),
        ("vef_evidence_capsule", VEF_EVIDENCE_CAPSULE),
        ("vef_verification_state", VEF_VERIFICATION_STATE),
        ("vef_proof_scheduler", VEF_PROOF_SCHEDULER),
        ("vef_proof_generator", VEF_PROOF_GENERATOR),
        ("vef_proof_generator_format", VEF_PROOF_GENERATOR_FORMAT),
        ("vef_proof_verifier", VEF_PROOF_VERIFIER),
        ("vef_proof_service", VEF_PROOF_SERVICE),
        ("vef_sdk_integration", VEF_SDK_INTEGRATION),
        ("vef_sdk_integration_format", VEF_SDK_INTEGRATION_FORMAT),
        (
            "vef_sdk_integration_min_format",
            VEF_SDK_INTEGRATION_MIN_FORMAT,
        ),
        ("vef_receipt_chain", VEF_RECEIPT_CHAIN),
        ("vef_control_integration", VEF_CONTROL_INTEGRATION),
        // Extensions
        ("capability_artifact_contract", CAPABILITY_ARTIFACT_CONTRACT),
        // Claims
        ("claims_claim_compiler", CLAIMS_CLAIM_COMPILER),
        // Conformance
        ("conformance_suite_schema", CONFORMANCE_SUITE_SCHEMA),
        ("conformance_suite_version", CONFORMANCE_SUITE_VERSION),
        // Security
        ("intent_firewall", INTENT_FIREWALL),
        ("zk_attestation", ZK_ATTESTATION),
        ("staking_governance", STAKING_GOVERNANCE),
        ("lineage_tracker", LINEAGE_TRACKER),
        // Registry
        ("registry_staking_governance", REGISTRY_STAKING_GOVERNANCE),
        // Storage
        ("storage_model", STORAGE_MODEL),
        // Supply Chain
        ("manifest", MANIFEST),
        ("extension_registry", EXTENSION_REGISTRY),
        ("migration_kit", MIGRATION_KIT),
        // Remote
        ("idempotency_store", IDEMPOTENCY_STORE),
        ("remote_eviction_saga", REMOTE_EVICTION_SAGA),
        ("virtual_transport_faults", VIRTUAL_TRANSPORT_FAULTS),
        // Testing
        ("scenario_builder", SCENARIO_BUILDER),
        ("virtual_transport", VIRTUAL_TRANSPORT),
        ("lab_runtime", LAB_RUNTIME),
        // Tools
        ("migration_incident_datasets", MIGRATION_INCIDENT_DATASETS),
        ("report_output_contract", REPORT_OUTPUT_CONTRACT),
        ("security_trust_metrics", SECURITY_TRUST_METRICS),
        ("benchmark_suite_scoring", BENCHMARK_SUITE_SCORING),
        ("benchmark_suite_version", BENCHMARK_SUITE_VERSION),
        ("benchmark_methodology", BENCHMARK_METHODOLOGY),
        ("verifier_benchmark_releases", VERIFIER_BENCHMARK_RELEASES),
        ("security_ops_case_studies", SECURITY_OPS_CASE_STUDIES),
        ("frontier_demo_gate", FRONTIER_DEMO_GATE),
        ("external_replication_claims", EXTERNAL_REPLICATION_CLAIMS),
        (
            "compatibility_correctness_metrics",
            COMPATIBILITY_CORRECTNESS_METRICS,
        ),
        ("trust_economics_dashboard", TRUST_ECONOMICS_DASHBOARD),
        (
            "migration_speed_failure_metrics",
            MIGRATION_SPEED_FAILURE_METRICS,
        ),
        ("enterprise_governance", ENTERPRISE_GOVERNANCE),
        (
            "adversarial_resilience_metrics",
            ADVERSARIAL_RESILIENCE_METRICS,
        ),
        ("migration_validation_cohorts", MIGRATION_VALIDATION_COHORTS),
        ("transparent_reports", TRANSPARENT_REPORTS),
        ("partner_lighthouse_programs", PARTNER_LIGHTHOUSE_PROGRAMS),
        ("safe_extension_onboarding", SAFE_EXTENSION_ONBOARDING),
        ("verifier_toolkit", VERIFIER_TOOLKIT),
        ("redteam_evaluations", REDTEAM_EVALUATIONS),
        ("replay_determinism_metrics", REPLAY_DETERMINISM_METRICS),
        (
            "performance_hardening_metrics",
            PERFORMANCE_HARDENING_METRICS,
        ),
        (
            "containment_revocation_metrics",
            CONTAINMENT_REVOCATION_METRICS,
        ),
        ("vef_perf_budget_gate", VEF_PERF_BUDGET_GATE),
        ("counterfactual_replay_engine", COUNTERFACTUAL_REPLAY_ENGINE),
        ("replay_bundle_policy", REPLAY_BUNDLE_POLICY),
        // CLI
        ("verify_cli_contract", VERIFY_CLI_CONTRACT),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_versions_returns_nonempty() {
        let versions = all_versions();
        assert!(!versions.is_empty());
    }

    #[test]
    fn all_versions_has_no_duplicate_names() {
        let versions = all_versions();
        let mut names: Vec<&str> = versions.iter().map(|(name, _)| *name).collect();
        names.sort();
        let before = names.len();
        names.dedup();
        assert_eq!(
            before,
            names.len(),
            "duplicate name found in all_versions()"
        );
    }

    #[test]
    fn all_versions_has_no_empty_values() {
        for (name, value) in all_versions() {
            assert!(!name.is_empty(), "empty name in all_versions()");
            assert!(
                !value.is_empty(),
                "empty value for {name} in all_versions()"
            );
        }
    }

    #[test]
    #[cfg(feature = "extended-surfaces")]
    fn representative_runtime_and_connector_versions_match_authoritative_sources() {
        assert_eq!(
            NVERSION_ORACLE,
            crate::runtime::nversion_oracle::SCHEMA_VERSION
        );
        assert_eq!(
            N_VERSION_ORACLE,
            crate::connector::n_version_oracle::SCHEMA_VERSION
        );
        assert_eq!(
            DPOR_EXPLORATION,
            crate::control_plane::dpor_exploration::SCHEMA_VERSION
        );
    }

    #[test]
    fn representative_supply_chain_and_storage_versions_match_authoritative_sources() {
        assert_eq!(
            EXTENSION_REGISTRY,
            crate::supply_chain::extension_registry::REGISTRY_VERSION
        );
        assert_eq!(STORAGE_MODEL, crate::storage::models::MODEL_SCHEMA_VERSION);
    }

    #[test]
    #[cfg(feature = "extended-surfaces")]
    fn representative_tool_versions_match_authoritative_sources() {
        assert_eq!(
            BENCHMARK_SUITE_SCORING,
            crate::tools::benchmark_suite::SCORING_FORMULA_VERSION
        );
        assert_eq!(
            BENCHMARK_SUITE_VERSION,
            crate::tools::benchmark_suite::SUITE_VERSION
        );
        assert_eq!(
            BENCHMARK_METHODOLOGY,
            crate::tools::benchmark_methodology::PUB_VERSION
        );
        assert_eq!(
            VERIFIER_BENCHMARK_RELEASES,
            crate::tools::verifier_benchmark_releases::SCHEMA_VERSION
        );
    }
}
