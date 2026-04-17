pub mod frankensqlite_adapter;
pub mod models;
pub mod retrievability_gate;

#[cfg(test)]
mod storage_conformance_tests;

#[cfg(test)]
mod negative_path_tests {
    use super::frankensqlite_adapter::{
        AdapterConfig, AdapterError, DurabilityTier, FrankensqliteAdapter, PersistenceClass,
        ReadResult, SchemaVersion, WriteResult, event_codes,
    };
    use super::retrievability_gate::{
        ArtifactId, ERR_HASH_MISMATCH, ERR_INVALID_ARTIFACT_ID, ERR_INVALID_SEGMENT_ID,
        ERR_LATENCY_EXCEEDED, ERR_TARGET_UNREACHABLE, ProofFailureReason, RG_EVICTION_BLOCKED,
        RG_PROOF_FAILED, RetrievabilityConfig, RetrievabilityGate, SegmentId, StorageTier,
        TargetTierState,
    };
    use crate::security::constant_time::ct_eq_bytes;

    fn artifact(value: &str) -> ArtifactId {
        ArtifactId(value.to_string())
    }

    fn segment(value: &str) -> SegmentId {
        SegmentId(value.to_string())
    }

    fn reachable_state(hash: &str, latency_ms: u64) -> TargetTierState {
        TargetTierState {
            content_hash: hash.to_string(),
            reachable: true,
            fetch_latency_ms: latency_ms,
        }
    }

    #[test]
    fn empty_adapter_does_not_pass_gate() {
        let adapter = FrankensqliteAdapter::default();

        assert!(!adapter.gate_pass());
        assert_eq!(adapter.summary().total_writes, 0);
        assert_eq!(adapter.summary().write_failures, 0);
    }

    #[test]
    fn duplicate_audit_write_does_not_increment_successful_writes() {
        let mut adapter = FrankensqliteAdapter::default();
        adapter
            .write(PersistenceClass::AuditLog, "audit-key", b"first")
            .expect("initial write should succeed");

        let err = adapter
            .write(PersistenceClass::AuditLog, "audit-key", b"second")
            .unwrap_err();

        assert!(matches!(err, AdapterError::WriteFailure { .. }));
        assert_eq!(adapter.summary().total_writes, 1);
        assert_eq!(adapter.summary().write_failures, 1);
        assert!(adapter.events().iter().any(|event| {
            event.code == event_codes::FRANKENSQLITE_WRITE_FAIL
                && event.detail.contains("duplicate audit log")
        }));
    }

    #[test]
    fn missing_cache_read_returns_no_value() {
        let mut adapter = FrankensqliteAdapter::default();

        let result = adapter.read(PersistenceClass::Cache, "missing-cache-key");

        assert!(!result.found);
        assert!(result.value.is_none());
        assert!(result.cache_hit);
        assert_eq!(adapter.summary().total_reads, 1);
    }

    #[test]
    fn invalid_artifact_id_records_failed_receipt() {
        let mut gate = RetrievabilityGate::new(RetrievabilityConfig::default());

        let err = gate
            .check_retrievability(
                &artifact("<unknown>"),
                &segment("segment-ok"),
                StorageTier::L2Warm,
                StorageTier::L3Archive,
                "hash",
            )
            .unwrap_err();

        assert_eq!(err.code, ERR_INVALID_ARTIFACT_ID);
        assert_eq!(gate.failed_count(), 1);
        assert_eq!(gate.passed_count(), 0);
    }

    #[test]
    fn invalid_segment_id_records_failed_receipt() {
        let mut gate = RetrievabilityGate::new(RetrievabilityConfig::default());

        let err = gate
            .check_retrievability(
                &artifact("artifact-ok"),
                &segment(" segment-with-padding "),
                StorageTier::L2Warm,
                StorageTier::L3Archive,
                "hash",
            )
            .unwrap_err();

        assert_eq!(err.code, ERR_INVALID_SEGMENT_ID);
        assert_eq!(gate.failed_count(), 1);
        assert_eq!(gate.passed_count(), 0);
    }

    #[test]
    fn missing_registered_target_fails_closed() {
        let mut gate = RetrievabilityGate::new(RetrievabilityConfig::default());

        let err = gate
            .check_retrievability(
                &artifact("artifact-missing-target"),
                &segment("segment-missing-target"),
                StorageTier::L2Warm,
                StorageTier::L3Archive,
                "hash",
            )
            .unwrap_err();

        assert_eq!(err.code, ERR_TARGET_UNREACHABLE);
        assert_eq!(gate.failed_count(), 1);
        assert_eq!(gate.passed_count(), 0);
    }

    #[test]
    fn exact_latency_limit_fails_closed() {
        let mut gate = RetrievabilityGate::new(RetrievabilityConfig {
            max_latency_ms: 25,
            require_hash_match: true,
        });
        let artifact = artifact("artifact-latency");
        let segment = segment("segment-latency");
        gate.register_target(
            &artifact,
            &segment,
            StorageTier::L3Archive,
            reachable_state("hash", 25),
        );

        let err = gate
            .check_retrievability(
                &artifact,
                &segment,
                StorageTier::L2Warm,
                StorageTier::L3Archive,
                "hash",
            )
            .unwrap_err();

        assert_eq!(err.code, ERR_LATENCY_EXCEEDED);
        assert_eq!(gate.failed_count(), 1);
    }

    #[test]
    fn strict_hash_mismatch_blocks_eviction_event() {
        let mut gate = RetrievabilityGate::new(RetrievabilityConfig::default());
        let artifact = artifact("artifact-hash-mismatch");
        let segment = segment("segment-hash-mismatch");
        gate.register_target(
            &artifact,
            &segment,
            StorageTier::L3Archive,
            reachable_state("actual-hash", 1),
        );

        let err = gate
            .attempt_eviction(&artifact, &segment, "expected-hash")
            .unwrap_err();

        assert_eq!(err.code, ERR_HASH_MISMATCH);
        assert_eq!(gate.failed_count(), 1);
        assert!(
            gate.events()
                .iter()
                .any(|event| event.code == RG_EVICTION_BLOCKED)
        );
    }

    #[test]
    fn blank_artifact_id_blocks_eviction_and_records_failed_proof() {
        let mut gate = RetrievabilityGate::new(RetrievabilityConfig::default());

        let err = gate
            .attempt_eviction(
                &artifact(" artifact-with-padding "),
                &segment("segment-ok"),
                "hash",
            )
            .unwrap_err();

        assert_eq!(err.code, ERR_INVALID_ARTIFACT_ID);
        assert_eq!(gate.failed_count(), 1);
        assert!(gate.events().iter().any(|event| {
            event.code == RG_PROOF_FAILED && event.detail.contains("leading or trailing whitespace")
        }));
        assert!(
            gate.events()
                .iter()
                .any(|event| event.code == RG_EVICTION_BLOCKED)
        );
    }

    #[test]
    fn empty_segment_id_blocks_eviction_and_keeps_pass_count_zero() {
        let mut gate = RetrievabilityGate::new(RetrievabilityConfig::default());

        let err = gate
            .attempt_eviction(&artifact("artifact-ok"), &segment(""), "hash")
            .unwrap_err();

        assert_eq!(err.code, ERR_INVALID_SEGMENT_ID);
        assert_eq!(gate.failed_count(), 1);
        assert_eq!(gate.passed_count(), 0);
        assert!(gate.receipts().iter().all(|receipt| !receipt.passed));
    }

    #[test]
    fn registered_unreachable_target_records_empty_observed_content() {
        let mut gate = RetrievabilityGate::new(RetrievabilityConfig::default());
        let artifact = artifact("artifact-unreachable");
        let segment = segment("segment-unreachable");
        gate.register_target(
            &artifact,
            &segment,
            StorageTier::L3Archive,
            TargetTierState {
                content_hash: "observed-but-unreachable".to_string(),
                reachable: false,
                fetch_latency_ms: 1,
            },
        );

        let err = gate
            .check_retrievability(
                &artifact,
                &segment,
                StorageTier::L2Warm,
                StorageTier::L3Archive,
                "expected",
            )
            .unwrap_err();

        assert_eq!(err.code, ERR_TARGET_UNREACHABLE);
        let receipt = gate.receipts().last().expect("failed receipt should exist");
        assert!(!receipt.passed);
        assert!(receipt.content_hash.is_empty());
        assert_eq!(receipt.latency_ms, 0);
    }

    #[test]
    fn hash_mismatch_reason_preserves_expected_and_actual_values() {
        let mut gate = RetrievabilityGate::new(RetrievabilityConfig::default());
        let artifact = artifact("artifact-mismatch-detail");
        let segment = segment("segment-mismatch-detail");
        gate.register_target(
            &artifact,
            &segment,
            StorageTier::L3Archive,
            reachable_state("actual-digest", 1),
        );

        let err = gate
            .check_retrievability(
                &artifact,
                &segment,
                StorageTier::L2Warm,
                StorageTier::L3Archive,
                "expected-digest",
            )
            .unwrap_err();

        assert_eq!(err.code, ERR_HASH_MISMATCH);
        let ProofFailureReason::HashMismatch { expected, actual } = err.reason else {
            panic!("expected hash mismatch reason");
        };
        assert!(ct_eq_bytes(expected.as_bytes(), b"expected-digest"));
        assert!(ct_eq_bytes(actual.as_bytes(), b"actual-digest"));
    }

    #[test]
    fn latency_failure_precedes_hash_mismatch_when_both_are_bad() {
        let mut gate = RetrievabilityGate::new(RetrievabilityConfig {
            max_latency_ms: 10,
            require_hash_match: true,
        });
        let artifact = artifact("artifact-latency-before-hash");
        let segment = segment("segment-latency-before-hash");
        gate.register_target(
            &artifact,
            &segment,
            StorageTier::L3Archive,
            reachable_state("actual-digest", 10),
        );

        let err = gate
            .check_retrievability(
                &artifact,
                &segment,
                StorageTier::L2Warm,
                StorageTier::L3Archive,
                "expected-digest",
            )
            .unwrap_err();

        assert_eq!(err.code, ERR_LATENCY_EXCEEDED);
        assert!(matches!(
            err.reason,
            ProofFailureReason::LatencyExceeded {
                limit_ms: 10,
                actual_ms: 10
            }
        ));
    }

    #[test]
    fn schema_migration_rejects_current_version_without_advancing() {
        let mut adapter = FrankensqliteAdapter::default();
        let before = adapter.schema_version();

        let err = adapter
            .migrate(before, "duplicate version")
            .expect_err("current schema version must not be re-applied");

        assert!(matches!(
            err,
            AdapterError::SchemaMigrationFailed { version, ref reason }
                if version == before && reason.contains("already applied")
        ));
        assert_eq!(adapter.schema_version(), before);
        assert!(!adapter.gate_pass());
    }

    #[test]
    fn persistence_class_deserialize_rejects_label_form() {
        let result = serde_json::from_str::<PersistenceClass>("\"audit_log\"");

        assert!(result.is_err());
    }

    #[test]
    fn durability_tier_deserialize_rejects_label_form() {
        let result = serde_json::from_str::<DurabilityTier>("\"tier1_wal_crash_safe\"");

        assert!(result.is_err());
    }

    #[test]
    fn adapter_config_deserialize_rejects_string_pool_size() {
        let result = serde_json::from_value::<AdapterConfig>(serde_json::json!({
            "db_path": "/tmp/franken-node.db",
            "pool_size": "4",
            "wal_enabled": true,
            "flush_interval_ms": 250
        }));

        assert!(result.is_err());
    }

    #[test]
    fn adapter_config_deserialize_rejects_missing_wal_flag() {
        let result = serde_json::from_value::<AdapterConfig>(serde_json::json!({
            "db_path": "/tmp/franken-node.db",
            "pool_size": 4,
            "flush_interval_ms": 250
        }));

        assert!(result.is_err());
    }

    #[test]
    fn schema_version_deserialize_rejects_string_version() {
        let result = serde_json::from_value::<SchemaVersion>(serde_json::json!({
            "version": "1",
            "applied_at": "2026-04-17T00:00:00Z",
            "description": "initial schema"
        }));

        assert!(result.is_err());
    }

    #[test]
    fn write_result_deserialize_rejects_string_latency() {
        let result = serde_json::from_value::<WriteResult>(serde_json::json!({
            "success": true,
            "key": "audit-key",
            "persistence_class": "AuditLog",
            "tier": "Tier1",
            "latency_us": "10"
        }));

        assert!(result.is_err());
    }

    #[test]
    fn read_result_deserialize_rejects_string_value_payload() {
        let result = serde_json::from_value::<ReadResult>(serde_json::json!({
            "found": true,
            "key": "cache-key",
            "value": "not-bytes",
            "persistence_class": "Cache",
            "tier": "Tier2",
            "cache_hit": true
        }));

        assert!(result.is_err());
    }

    #[test]
    fn storage_tier_deserialize_rejects_label_form() {
        let result = serde_json::from_str::<StorageTier>("\"L3_archive\"");

        assert!(result.is_err());
    }

    #[test]
    fn proof_failure_reason_deserialize_rejects_missing_hash_actual() {
        let result = serde_json::from_value::<ProofFailureReason>(serde_json::json!({
            "HashMismatch": {
                "expected": "expected-digest"
            }
        }));

        assert!(result.is_err());
    }

    #[test]
    fn retrievability_config_deserialize_rejects_string_latency() {
        let result = serde_json::from_value::<RetrievabilityConfig>(serde_json::json!({
            "max_latency_ms": "5000",
            "require_hash_match": true
        }));

        assert!(result.is_err());
    }
}
