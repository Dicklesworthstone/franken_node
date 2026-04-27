use frankenengine_node::storage::frankensqlite_adapter::{
    AdapterSummary, CallerContext, FrankensqliteAdapter, FrankensqliteLegacySystemReadExt,
    PersistenceClass, ReadResult,
};
use frankenengine_node::storage::retrievability_gate::{
    ArtifactId, RG_EVICTION_BLOCKED, RetrievabilityConfig, RetrievabilityGate, SegmentId,
    StorageTier,
};
use serde_json::Value;

fn serialize<T: serde::Serialize>(value: &T) -> Value {
    serde_json::to_value(value).expect("serialization should succeed")
}

fn explicit_seeded_adapter(trace_id: &str) -> FrankensqliteAdapter {
    let caller = CallerContext::system("storage::metamorphic", trace_id);
    let mut adapter = FrankensqliteAdapter::default();

    adapter
        .write(&caller, PersistenceClass::AuditLog, "audit-1", b"first")
        .expect("first audit write should succeed");
    adapter
        .write(&caller, PersistenceClass::AuditLog, "audit-2", b"second")
        .expect("second audit write should succeed");
    adapter
        .write(
            &caller,
            PersistenceClass::ControlState,
            "control-1",
            b"state",
        )
        .expect("control-state write should succeed");
    adapter
        .write(
            &caller,
            PersistenceClass::Snapshot,
            "snapshot-1",
            b"snapshot",
        )
        .expect("snapshot write should succeed");

    adapter
}

#[allow(deprecated)]
fn legacy_seeded_adapter() -> FrankensqliteAdapter {
    let mut adapter = FrankensqliteAdapter::default();

    adapter
        .write_legacy(PersistenceClass::AuditLog, "audit-1", b"first")
        .expect("first audit write should succeed");
    adapter
        .write_legacy(PersistenceClass::AuditLog, "audit-2", b"second")
        .expect("second audit write should succeed");
    adapter
        .write_legacy(PersistenceClass::ControlState, "control-1", b"state")
        .expect("control-state write should succeed");
    adapter
        .write_legacy(PersistenceClass::Snapshot, "snapshot-1", b"snapshot")
        .expect("snapshot write should succeed");

    adapter
}

fn direct_read(
    adapter: &mut FrankensqliteAdapter,
    caller: &CallerContext,
    class: PersistenceClass,
    key: &str,
) -> ReadResult {
    adapter
        .read(caller, class, key)
        .expect("explicit read should succeed")
}

#[test]
#[allow(deprecated)]
fn explicit_and_legacy_calls_preserve_same_persistence_state() {
    let caller = CallerContext::system("storage::metamorphic", "trace-explicit-legacy");
    let mut explicit = explicit_seeded_adapter("trace-explicit");
    let mut legacy = legacy_seeded_adapter();

    let explicit_reads = [
        direct_read(
            &mut explicit,
            &caller,
            PersistenceClass::AuditLog,
            "audit-1",
        ),
        direct_read(
            &mut explicit,
            &caller,
            PersistenceClass::ControlState,
            "control-1",
        ),
        direct_read(
            &mut explicit,
            &caller,
            PersistenceClass::Snapshot,
            "snapshot-1",
        ),
    ];
    let legacy_reads = [
        legacy.read_legacy(PersistenceClass::AuditLog, "audit-1"),
        legacy.read_legacy(PersistenceClass::ControlState, "control-1"),
        legacy.read_legacy(PersistenceClass::Snapshot, "snapshot-1"),
    ];

    for (explicit_read, legacy_read) in explicit_reads.iter().zip(legacy_reads.iter()) {
        assert_eq!(serialize(explicit_read), serialize(legacy_read));
    }

    let explicit_replay = explicit.replay();
    let legacy_replay = legacy.replay();

    assert_eq!(explicit_replay, legacy_replay);
    assert_eq!(
        serialize(&explicit.summary()),
        serialize(&legacy.summary()),
        "summary should remain invariant under explicit vs legacy call surfaces"
    );
    assert_eq!(explicit.to_report(), legacy.to_report());
}

#[test]
fn replay_results_are_invariant_under_read_only_observation() {
    let read_only = CallerContext::read_only("observability::storage", "trace-read-only");

    let mut baseline = explicit_seeded_adapter("trace-baseline");
    let baseline_replay = baseline.replay();
    let baseline_summary: AdapterSummary = baseline.summary();

    let mut observed = explicit_seeded_adapter("trace-observed");
    assert!(
        direct_read(
            &mut observed,
            &read_only,
            PersistenceClass::ControlState,
            "control-1",
        )
        .found
    );
    assert!(
        !direct_read(
            &mut observed,
            &read_only,
            PersistenceClass::Snapshot,
            "missing-snapshot",
        )
        .found
    );
    let observed_replay = observed.replay();
    let observed_summary: AdapterSummary = observed.summary();

    assert_eq!(baseline_replay, observed_replay);
    assert_eq!(
        baseline_summary.replay_mismatches,
        observed_summary.replay_mismatches
    );
    assert_eq!(baseline.gate_pass(), observed.gate_pass());
}

#[test]
fn crash_recovery_tier1_count_is_invariant_under_tier3_cache_noise() {
    let caller = CallerContext::system("storage::metamorphic", "trace-tier1");

    let mut baseline = FrankensqliteAdapter::default();
    baseline
        .write(
            &caller,
            PersistenceClass::ControlState,
            "control-a",
            b"alpha",
        )
        .expect("control-state write should succeed");
    baseline
        .write(&caller, PersistenceClass::AuditLog, "audit-a", b"entry-a")
        .expect("audit-log write should succeed");
    baseline
        .write(
            &caller,
            PersistenceClass::Snapshot,
            "snapshot-a",
            b"snapshot",
        )
        .expect("snapshot write should succeed");

    let mut noisy = FrankensqliteAdapter::default();
    noisy
        .write(
            &caller,
            PersistenceClass::ControlState,
            "control-a",
            b"alpha",
        )
        .expect("control-state write should succeed");
    noisy
        .write(&caller, PersistenceClass::AuditLog, "audit-a", b"entry-a")
        .expect("audit-log write should succeed");
    noisy
        .write(
            &caller,
            PersistenceClass::Snapshot,
            "snapshot-a",
            b"snapshot",
        )
        .expect("snapshot write should succeed");
    for index in 0..32 {
        noisy
            .write(
                &caller,
                PersistenceClass::Cache,
                &format!("cache-{index}"),
                format!("ephemeral-{index}").as_bytes(),
            )
            .expect("cache noise should succeed");
    }

    assert_eq!(baseline.crash_recovery(), noisy.crash_recovery());
    assert_eq!(
        serialize(&direct_read(
            &mut baseline,
            &caller,
            PersistenceClass::ControlState,
            "control-a",
        )),
        serialize(&direct_read(
            &mut noisy,
            &caller,
            PersistenceClass::ControlState,
            "control-a",
        ))
    );
    assert_eq!(
        serialize(&direct_read(
            &mut baseline,
            &caller,
            PersistenceClass::AuditLog,
            "audit-a",
        )),
        serialize(&direct_read(
            &mut noisy,
            &caller,
            PersistenceClass::AuditLog,
            "audit-a",
        ))
    );
}

#[test]
fn direct_check_and_eviction_fail_closed_equivalently_for_invalid_artifact_ids() {
    let invalid_artifact = ArtifactId(" invalid-artifact ".to_string());
    let valid_segment = SegmentId("valid-segment".to_string());

    let mut direct_gate = RetrievabilityGate::new(RetrievabilityConfig::default());
    let direct_err = direct_gate
        .check_retrievability(
            &invalid_artifact,
            &valid_segment,
            StorageTier::L2Warm,
            StorageTier::L3Archive,
            "hash",
        )
        .expect_err("invalid artifact id should fail direct proof");

    let mut eviction_gate = RetrievabilityGate::new(RetrievabilityConfig::default());
    let eviction_err = eviction_gate
        .attempt_eviction(&invalid_artifact, &valid_segment, "hash")
        .expect_err("invalid artifact id should fail eviction proof");

    assert_eq!(direct_err.code, eviction_err.code);
    assert_eq!(direct_err.artifact_id, eviction_err.artifact_id);
    assert_eq!(direct_err.segment_id, eviction_err.segment_id);
    assert_eq!(
        direct_err.reason.to_string(),
        eviction_err.reason.to_string(),
        "invalid-id transform should preserve fail-closed semantics"
    );
    assert_eq!(direct_gate.failed_count(), 1);
    assert_eq!(eviction_gate.failed_count(), 1);
    assert!(
        eviction_gate
            .events()
            .iter()
            .any(|event| event.code == RG_EVICTION_BLOCKED),
        "eviction path should add the blocked-event refinement"
    );
}

#[test]
fn receipts_json_round_trip_preserves_failed_receipts() {
    let mut gate = RetrievabilityGate::new(RetrievabilityConfig::default());

    gate.check_retrievability(
        &ArtifactId("<unknown>".to_string()),
        &SegmentId("segment-invalid".to_string()),
        StorageTier::L2Warm,
        StorageTier::L3Archive,
        "hash",
    )
    .expect_err("reserved artifact id should fail");

    gate.check_retrievability(
        &ArtifactId("artifact-missing".to_string()),
        &SegmentId("segment-missing".to_string()),
        StorageTier::L2Warm,
        StorageTier::L3Archive,
        "hash",
    )
    .expect_err("missing target should fail");

    let receipts_from_json: Value =
        serde_json::from_str(&gate.receipts_json()).expect("receipts_json should parse");
    let live_receipts = serialize(&gate.receipts());

    assert_eq!(receipts_from_json, live_receipts);
    assert_eq!(gate.failed_count(), 2);
    assert_eq!(gate.passed_count(), 0);
}
