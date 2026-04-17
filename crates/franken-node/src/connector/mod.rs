pub mod activation_pipeline;
pub mod admission_budget;
pub mod anti_amplification;
pub mod artifact_persistence;
pub mod bocpd;
pub mod cancel_injection_gate;
pub mod cancellation_protocol;
pub mod canonical_serializer;
pub mod capability_artifact;
pub mod capability_guard;
pub mod claim_compiler;
#[cfg(any(test, feature = "extended-surfaces"))]
pub mod conformance_profile;
pub mod control_channel;
pub mod control_evidence;
pub mod control_evidence_replay;
pub mod crdt;
pub mod device_profile;
pub mod diagnostic_registry;
pub mod dpor_schedule_gate;
pub mod durability;
pub mod durable_claim_gate;
pub mod ecosystem_compliance;
pub mod ecosystem_registry;
pub mod ecosystem_reputation;
pub mod error_code_registry;
pub mod error_surface;
pub mod eviction_saga;
#[cfg(any(test, feature = "extended-surfaces"))]
pub mod execution_scorer;
pub mod fencing;
pub mod frame_parser;
#[cfg(any(test, feature = "extended-surfaces"))]
pub mod fuzz_corpus;
#[cfg(any(test, feature = "extended-surfaces"))]
pub mod golden_vectors;
pub mod health_gate;
#[cfg(any(test, feature = "extended-surfaces"))]
pub mod high_assurance_promotion;
#[cfg(any(test, feature = "extended-surfaces"))]
pub mod incident_bundle_retention;
#[cfg(any(test, feature = "extended-surfaces"))]
pub mod interop_suite;
pub mod lease_conflict;
#[cfg(any(test, feature = "extended-surfaces"))]
pub mod lease_coordinator;
#[cfg(any(test, feature = "extended-surfaces"))]
pub mod lease_service;
pub mod lifecycle;
#[cfg(any(test, feature = "extended-surfaces"))]
pub mod manifest_negotiation;
pub mod migration_artifact;
pub mod migration_pipeline;
#[cfg(any(test, feature = "extended-surfaces"))]
pub mod n_version_oracle;
pub mod obligation_tracker;
#[cfg(any(test, feature = "extended-surfaces"))]
pub mod offline_coverage;
#[cfg(any(test, feature = "extended-surfaces"))]
pub mod operator_intelligence;
pub mod perf_budget_guard;
pub mod policy_checkpoint;
pub mod prestage_engine;
#[cfg(any(test, feature = "extended-surfaces"))]
pub mod quarantine_promotion;
pub mod quarantine_store;
#[cfg(any(test, feature = "extended-surfaces"))]
pub mod region_ownership;
pub mod repair_controller;
#[cfg(any(test, feature = "extended-surfaces"))]
pub mod retention_policy;
#[cfg(any(test, feature = "extended-surfaces"))]
pub mod rollback_bundle;
pub mod rollout_state;
pub mod saga;
pub mod schema_migration;
#[cfg(any(test, feature = "extended-surfaces"))]
pub mod snapshot_policy;
pub mod state_model;
pub mod supervision;
pub mod telemetry_namespace;
pub mod tiered_trust_storage;
pub mod trace_context;
pub mod transport_fault_gate;
pub mod trust_fabric;
pub mod trust_object_id;
pub mod trust_zone;
#[cfg(any(test, feature = "extended-surfaces"))]
pub mod universal_verifier_sdk;
pub mod vef_claim_integration;
pub mod vef_execution_receipt;
#[cfg(any(test, feature = "extended-surfaces"))]
pub mod vef_perf_budget;
pub mod vef_policy_constraints;
#[cfg(any(test, feature = "extended-surfaces"))]
pub mod verifier_sdk;

#[cfg(test)]
mod bocpd_conformance_tests;
#[cfg(test)]
mod test_bocpd_hardening;

#[cfg(test)]
mod public_surface_negative_tests {
    use super::error_code_registry::{
        ErrorCodeRegistration, ErrorCodeRegistry, RecoveryInfo, RegistryError, Severity,
    };
    use super::frame_parser::{
        FrameInput, GuardrailViolation, ParserConfig, ParserError, check_batch, check_frame,
        validate_config,
    };
    use super::trust_object_id::{IdError, IdRegistry, TrustObjectId};

    fn parser_config() -> ParserConfig {
        ParserConfig {
            max_frame_bytes: 16,
            max_nesting_depth: 4,
            max_decode_cpu_ms: 8,
        }
    }

    fn frame(
        frame_id: &str,
        raw_bytes_len: u64,
        nesting_depth: u32,
        decode_cpu_ms: u64,
    ) -> FrameInput {
        FrameInput {
            frame_id: frame_id.to_string(),
            raw_bytes_len,
            nesting_depth,
            decode_cpu_ms,
        }
    }

    fn recovery(retryable: bool, recovery_hint: &str) -> RecoveryInfo {
        RecoveryInfo {
            retryable,
            retry_after_ms: if retryable { Some(100) } else { None },
            recovery_hint: recovery_hint.to_string(),
        }
    }

    #[test]
    fn negative_parser_zero_size_config_preempts_empty_frame_id() {
        let mut config = parser_config();
        config.max_frame_bytes = 0;

        let err = check_frame(&frame("", 32, 1, 1), &config, "ts").unwrap_err();

        assert!(matches!(
            err,
            ParserError::InvalidConfig { ref reason }
                if reason == "max_frame_bytes must be > 0"
        ));
    }

    #[test]
    fn negative_parser_exact_limits_emit_all_public_violations() {
        let config = parser_config();

        let (verdict, audit) = check_frame(&frame("frame-limit", 16, 4, 8), &config, "ts")
            .expect("limit-bound frame should produce a blocking verdict");

        assert!(!verdict.allowed);
        assert_eq!(
            verdict.violations,
            vec![
                GuardrailViolation::SizeExceeded {
                    actual: 16,
                    limit: 16,
                },
                GuardrailViolation::DepthExceeded {
                    actual: 4,
                    limit: 4,
                },
                GuardrailViolation::CpuExceeded {
                    actual: 8,
                    limit: 8,
                },
            ]
        );
        assert_eq!(audit.verdict, "BLOCK");
    }

    #[test]
    fn negative_parser_batch_aborts_on_malformed_middle_frame() {
        let config = parser_config();
        let frames = vec![
            frame("frame-ok", 1, 1, 1),
            frame("", 1, 1, 1),
            frame("frame-after-error", 1, 1, 1),
        ];

        let err = check_batch(&frames, &config, "ts").unwrap_err();

        assert!(matches!(
            err,
            ParserError::MalformedFrame { ref frame_id, .. } if frame_id == "(empty)"
        ));
    }

    #[test]
    fn negative_trust_object_id_rejects_wrong_algorithm_token() {
        let candidate = format!("ext:blake3:{}", "a".repeat(64));

        let err = TrustObjectId::parse(&candidate).unwrap_err();

        assert!(matches!(err, IdError::InvalidFormat { .. }));
    }

    #[test]
    fn negative_trust_object_id_rejects_trailing_context_segment() {
        let candidate = format!("pchk:1:2:{}:tail", "b".repeat(64));

        let err = TrustObjectId::parse(&candidate).unwrap_err();

        assert!(matches!(err, IdError::MalformedDigest { .. }));
    }

    #[test]
    fn negative_id_registry_rejects_prefix_without_colon() {
        let registry = IdRegistry::new();

        assert!(!registry.is_valid_prefix("ext"));
        assert!(!registry.is_valid_prefix("pchk"));
    }

    #[test]
    fn negative_error_registry_rejects_subsystem_without_separator_suffix() {
        let mut registry = ErrorCodeRegistry::new();
        let registration = ErrorCodeRegistration {
            code: "FRANKEN_CONNECTOR".to_string(),
            severity: Severity::Transient,
            recovery: recovery(true, "retry after fixing namespace"),
            description: "namespace must include a code suffix".to_string(),
            version: 1,
        };

        let err = registry.register(&registration).unwrap_err();

        assert!(matches!(err, RegistryError::InvalidNamespace(_)));
        assert!(registry.is_empty());
    }

    #[test]
    fn negative_error_registry_rejects_empty_code_suffix_after_subsystem() {
        let mut registry = ErrorCodeRegistry::new();
        let registration = ErrorCodeRegistration {
            code: "FRANKEN_CONNECTOR_".to_string(),
            severity: Severity::Transient,
            recovery: recovery(true, "retry after adding a code suffix"),
            description: "namespace suffix must not be empty".to_string(),
            version: 1,
        };

        let err = registry.register(&registration).unwrap_err();

        assert!(matches!(err, RegistryError::InvalidNamespace(_)));
        assert!(registry.is_empty());
    }

    #[test]
    fn negative_parser_zero_depth_config_reports_specific_reason() {
        let mut config = parser_config();
        config.max_nesting_depth = 0;

        let err = validate_config(&config).unwrap_err();

        assert!(matches!(
            err,
            ParserError::InvalidConfig { ref reason }
                if reason == "max_nesting_depth must be > 0"
        ));
    }

    #[test]
    fn negative_parser_zero_cpu_config_reports_specific_reason() {
        let mut config = parser_config();
        config.max_decode_cpu_ms = 0;

        let err = validate_config(&config).unwrap_err();

        assert!(matches!(
            err,
            ParserError::InvalidConfig { ref reason }
                if reason == "max_decode_cpu_ms must be > 0"
        ));
    }

    #[test]
    fn negative_parser_whitespace_frame_id_reports_placeholder() {
        let err = check_frame(&frame(" \n\t ", 1, 1, 1), &parser_config(), "ts").unwrap_err();

        assert!(matches!(
            err,
            ParserError::MalformedFrame { ref frame_id, ref reason }
                if frame_id == "(empty)" && reason == "frame_id must not be empty"
        ));
    }

    #[test]
    fn negative_parser_size_boundary_blocks_without_other_violations() {
        let (verdict, audit) = check_frame(&frame("size-only", 16, 1, 1), &parser_config(), "ts")
            .expect("size boundary should produce a blocking verdict");

        assert!(!verdict.allowed);
        assert_eq!(
            verdict.violations,
            vec![GuardrailViolation::SizeExceeded {
                actual: 16,
                limit: 16,
            }]
        );
        assert_eq!(audit.verdict, "BLOCK");
    }

    #[test]
    fn negative_parser_cpu_boundary_blocks_without_other_violations() {
        let (verdict, audit) = check_frame(&frame("cpu-only", 1, 1, 8), &parser_config(), "ts")
            .expect("cpu boundary should produce a blocking verdict");

        assert!(!verdict.allowed);
        assert_eq!(
            verdict.violations,
            vec![GuardrailViolation::CpuExceeded {
                actual: 8,
                limit: 8,
            }]
        );
        assert_eq!(audit.verdict, "BLOCK");
    }

    #[test]
    fn negative_parser_batch_invalid_config_preempts_frame_validation() {
        let mut config = parser_config();
        config.max_decode_cpu_ms = 0;
        let frames = vec![frame("", 32, 4, 8)];

        let err = check_batch(&frames, &config, "ts").unwrap_err();

        assert!(matches!(
            err,
            ParserError::InvalidConfig { ref reason }
                if reason == "max_decode_cpu_ms must be > 0"
        ));
    }

    #[test]
    fn negative_error_registry_rejects_frozen_recovery_change() {
        let mut registry = ErrorCodeRegistry::new();
        let original = ErrorCodeRegistration {
            code: "FRANKEN_CONNECTOR_FROZEN_RECOVERY".to_string(),
            severity: Severity::Transient,
            recovery: recovery(true, "retry after original backoff"),
            description: "frozen recovery contract".to_string(),
            version: 1,
        };
        let changed = ErrorCodeRegistration {
            code: "FRANKEN_CONNECTOR_FROZEN_RECOVERY".to_string(),
            severity: Severity::Transient,
            recovery: recovery(true, "retry after changed backoff"),
            description: "frozen recovery contract drift".to_string(),
            version: 2,
        };

        registry
            .register(&original)
            .expect("initial registration should succeed");
        registry
            .freeze("FRANKEN_CONNECTOR_FROZEN_RECOVERY")
            .expect("registered code should freeze");
        let err = registry.register(&changed).unwrap_err();

        assert!(matches!(
            err,
            RegistryError::FrozenConflict(code) if code == "FRANKEN_CONNECTOR_FROZEN_RECOVERY"
        ));
        let entry = registry
            .get("FRANKEN_CONNECTOR_FROZEN_RECOVERY")
            .expect("original frozen entry should remain present");
        assert_eq!(entry.version, 1);
        assert_eq!(entry.recovery.recovery_hint, "retry after original backoff");
    }
}

#[cfg(test)]
mod connector_root_negative_tests {
    use super::error_code_registry::{
        ErrorCodeRegistration, ErrorCodeRegistry, RecoveryInfo, RegistryError, Severity,
    };

    fn recovery(retryable: bool, retry_after_ms: Option<u64>, recovery_hint: &str) -> RecoveryInfo {
        RecoveryInfo {
            retryable,
            retry_after_ms,
            recovery_hint: recovery_hint.to_string(),
        }
    }

    fn registration(
        code: &str,
        severity: Severity,
        recovery: RecoveryInfo,
        version: u32,
    ) -> ErrorCodeRegistration {
        ErrorCodeRegistration {
            code: code.to_string(),
            severity,
            recovery,
            description: format!("description for {code}"),
            version,
        }
    }

    fn assert_invalid_namespace_rejected(code: &str) {
        let mut registry = ErrorCodeRegistry::new();
        let reg = registration(
            code,
            Severity::Transient,
            recovery(true, Some(100), "retry after fixing namespace"),
            1,
        );

        let err = registry.register(&reg).unwrap_err();

        assert!(matches!(
            err,
            RegistryError::InvalidNamespace(rejected) if rejected == code
        ));
        assert!(registry.is_empty());
    }

    #[test]
    fn connector_root_rejects_lowercase_code_suffix() {
        assert_invalid_namespace_rejected("FRANKEN_CONNECTOR_timeout");
    }

    #[test]
    fn connector_root_rejects_trailing_underscore_code_suffix() {
        assert_invalid_namespace_rejected("FRANKEN_CONNECTOR_TIMEOUT_");
    }

    #[test]
    fn connector_root_rejects_double_separator_code_suffix() {
        assert_invalid_namespace_rejected("FRANKEN_CONNECTOR__TIMEOUT");
    }

    #[test]
    fn connector_root_rejects_hyphenated_code_suffix() {
        assert_invalid_namespace_rejected("FRANKEN_CONNECTOR_TIME-OUT");
    }

    #[test]
    fn connector_root_rejects_nul_byte_code_suffix() {
        assert_invalid_namespace_rejected("FRANKEN_CONNECTOR_TIMEOUT\0NUL");
    }

    #[test]
    fn connector_root_rejects_non_ascii_code_suffix() {
        assert_invalid_namespace_rejected("FRANKEN_CONNECTOR_TIMEOUT_\u{03b2}");
    }

    #[test]
    fn connector_root_rejects_whitespace_only_recovery_hint() {
        let mut registry = ErrorCodeRegistry::new();
        let reg = registration(
            "FRANKEN_CONNECTOR_WHITESPACE_HINT",
            Severity::Transient,
            recovery(true, Some(100), " \n\t "),
            1,
        );

        let err = registry.register(&reg).unwrap_err();

        assert!(matches!(
            err,
            RegistryError::MissingRecovery(code) if code == "FRANKEN_CONNECTOR_WHITESPACE_HINT"
        ));
        assert!(registry.is_empty());
    }

    #[test]
    fn connector_root_rejects_code_without_franken_namespace() {
        let mut registry = ErrorCodeRegistry::new();
        let reg = registration(
            "CONNECTOR_TIMEOUT",
            Severity::Transient,
            recovery(true, Some(100), "retry later"),
            1,
        );

        let err = registry.register(&reg).unwrap_err();

        assert!(matches!(
            err,
            RegistryError::InvalidNamespace(code) if code == "CONNECTOR_TIMEOUT"
        ));
        assert!(registry.is_empty());
    }

    #[test]
    fn connector_root_rejects_unknown_franken_subsystem() {
        let mut registry = ErrorCodeRegistry::new();
        let reg = registration(
            "FRANKEN_UNKNOWN_TIMEOUT",
            Severity::Transient,
            recovery(true, Some(100), "retry later"),
            1,
        );

        let err = registry.register(&reg).unwrap_err();

        assert!(matches!(err, RegistryError::InvalidNamespace(_)));
        assert_eq!(registry.len(), 0);
    }

    #[test]
    fn connector_root_rejects_nonfatal_code_without_recovery_hint() {
        let mut registry = ErrorCodeRegistry::new();
        let reg = registration(
            "FRANKEN_CONNECTOR_NO_HINT",
            Severity::Degraded,
            recovery(false, None, ""),
            1,
        );

        let err = registry.register(&reg).unwrap_err();

        assert!(matches!(
            err,
            RegistryError::MissingRecovery(code) if code == "FRANKEN_CONNECTOR_NO_HINT"
        ));
        assert!(registry.get("FRANKEN_CONNECTOR_NO_HINT").is_none());
    }

    #[test]
    fn connector_root_rejects_retryable_fatal_code() {
        let mut registry = ErrorCodeRegistry::new();
        let reg = registration(
            "FRANKEN_CONNECTOR_FATAL_RETRY",
            Severity::Fatal,
            recovery(true, Some(50), "fatal errors must escalate"),
            1,
        );

        let err = registry.register(&reg).unwrap_err();

        assert!(matches!(
            err,
            RegistryError::MissingRecovery(code) if code == "FRANKEN_CONNECTOR_FATAL_RETRY"
        ));
        assert!(registry.catalog().is_empty());
    }

    #[test]
    fn connector_root_rejects_duplicate_unfrozen_code() {
        let mut registry = ErrorCodeRegistry::new();
        let first = registration(
            "FRANKEN_CONNECTOR_DUPLICATE",
            Severity::Transient,
            recovery(true, Some(25), "retry duplicate fixture"),
            1,
        );
        let second = registration(
            "FRANKEN_CONNECTOR_DUPLICATE",
            Severity::Transient,
            recovery(true, Some(25), "retry duplicate fixture"),
            2,
        );

        registry
            .register(&first)
            .expect("first registration should succeed");
        let err = registry.register(&second).unwrap_err();

        assert!(matches!(
            err,
            RegistryError::DuplicateCode(code) if code == "FRANKEN_CONNECTOR_DUPLICATE"
        ));
        assert_eq!(registry.len(), 1);
    }

    #[test]
    fn connector_root_rejects_freeze_for_missing_code() {
        let mut registry = ErrorCodeRegistry::new();

        let err = registry.freeze("FRANKEN_CONNECTOR_MISSING").unwrap_err();

        assert!(matches!(
            err,
            RegistryError::NotFound(code) if code == "FRANKEN_CONNECTOR_MISSING"
        ));
        assert!(registry.is_empty());
    }

    #[test]
    fn connector_root_rejects_frozen_same_version_reregistration() {
        let mut registry = ErrorCodeRegistry::new();
        let reg = registration(
            "FRANKEN_CONNECTOR_FROZEN_SAME",
            Severity::Transient,
            recovery(true, Some(25), "retry after backoff"),
            1,
        );

        registry
            .register(&reg)
            .expect("initial registration should succeed");
        registry
            .freeze("FRANKEN_CONNECTOR_FROZEN_SAME")
            .expect("registered code should freeze");
        let err = registry.register(&reg).unwrap_err();

        assert!(matches!(
            err,
            RegistryError::FrozenConflict(code) if code == "FRANKEN_CONNECTOR_FROZEN_SAME"
        ));
    }

    #[test]
    fn connector_root_rejects_frozen_severity_change() {
        let mut registry = ErrorCodeRegistry::new();
        let original = registration(
            "FRANKEN_CONNECTOR_FROZEN_SEVERITY",
            Severity::Transient,
            recovery(true, Some(25), "retry after backoff"),
            1,
        );
        let changed = registration(
            "FRANKEN_CONNECTOR_FROZEN_SEVERITY",
            Severity::Fatal,
            recovery(false, None, "escalate immediately"),
            2,
        );

        registry
            .register(&original)
            .expect("initial registration should succeed");
        registry
            .freeze("FRANKEN_CONNECTOR_FROZEN_SEVERITY")
            .expect("registered code should freeze");
        let err = registry.register(&changed).unwrap_err();

        assert!(matches!(
            err,
            RegistryError::FrozenConflict(code) if code == "FRANKEN_CONNECTOR_FROZEN_SEVERITY"
        ));
    }
}
