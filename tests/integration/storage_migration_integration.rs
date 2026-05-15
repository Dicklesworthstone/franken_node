//! Integration tests for bd-17ds.5.4 / bd-17ds.5.4.1: Storage → Migration → Rollback.
//!
//! Exercises the cross-subsystem boundary between:
//!   * `frankenengine_node::storage::retrievability_gate` (data-availability gate)
//!   * `frankenengine_node::connector::migration_artifact`  (pre-migration snapshot)
//!   * `frankenengine_node::connector::rollback_bundle`     (rollback / health)
//!
//! All instances are constructed with default config and the real types from
//! the production crate — no mocks. Each test logs entry/exit via `tracing::info!`
//! and state snapshots via `tracing::debug!`, gated through `init_tracing()` so
//! the subscriber is idempotent under `cargo test --test ...`.
//!
//! NOTE: `RetrievabilityGate::register_target` is `pub(crate)`, so the
//! "passes for available data" path is verified at the **proof-shape** level
//! (a `RetrievabilityProof` value of the expected variant after exercising the
//! public gate API) rather than by registering simulated L3 contents. The
//! rejection path is exercised through the public `attempt_eviction` entry.

use std::collections::BTreeMap;
use std::sync::Once;

use frankenengine_node::connector::migration_artifact::{
    ArtifactVersion, MigrationArtifact, SCHEMA_VERSION, compute_content_hash,
    generate_reference_artifact, validate_artifact, verify_artifact_signatures,
};
use frankenengine_node::connector::rollback_bundle::{
    BundleComponent, BundleStore, HealthCheckKind, RollbackBundleError, RollbackMode,
    StateSnapshot, sha256_hex,
};
use frankenengine_node::storage::retrievability_gate::{
    ArtifactId, ERR_INVALID_ARTIFACT_ID, ERR_INVALID_SEGMENT_ID, ERR_TARGET_UNREACHABLE,
    RG_EVICTION_BLOCKED, RetrievabilityConfig, RetrievabilityGate, SegmentId, StorageTier,
    TargetTierState, content_hash,
};
use frankenengine_node::storage::test_support::seed_retrievability_target;

static TRACING_INIT: Once = Once::new();

fn init_tracing() {
    TRACING_INIT.call_once(|| {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
            )
            .with_test_writer()
            .try_init();
    });
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn make_snapshot(version: &str, schema: &str) -> StateSnapshot {
    let mut config = BTreeMap::new();
    config.insert(
        "default".to_string(),
        sha256_hex(format!("config-{}", version).as_bytes()),
    );
    config.insert(
        "policy".to_string(),
        sha256_hex(format!("policy-{}", schema).as_bytes()),
    );
    StateSnapshot {
        config_checksums: config,
        schema_version: schema.to_string(),
        policy_set: "production".to_string(),
        binary_version: version.to_string(),
    }
}

fn make_components(seed: &str) -> Vec<BundleComponent> {
    vec![
        BundleComponent::new("binary_ref", 1, format!("binary-{}", seed).into_bytes()),
        BundleComponent::new(
            "config_diff",
            2,
            format!("config-diff-{}", seed).into_bytes(),
        ),
        BundleComponent::new(
            "state_reversal",
            3,
            format!("state-reversal-{}", seed).into_bytes(),
        ),
    ]
}

// ---------------------------------------------------------------------------
// Retrievability gate
// ---------------------------------------------------------------------------

#[test]
fn test_gate_passes_for_available_data() {
    init_tracing();
    tracing::info!(
        test = "test_gate_passes_for_available_data",
        phase = "enter"
    );

    let payload = b"payload-pass-01";
    let hash = content_hash(payload);
    let mut gate = RetrievabilityGate::new(RetrievabilityConfig::default());
    let artifact = ArtifactId("artifact-pass-01".to_string());
    let segment = SegmentId("seg-pass-01".to_string());

    seed_retrievability_target(
        &mut gate,
        &artifact,
        &segment,
        StorageTier::L3Archive,
        TargetTierState {
            content_hash: hash.clone(),
            reachable: true,
            fetch_latency_ms: 25,
        },
    );

    let permit = gate
        .attempt_eviction(&artifact, &segment, &hash)
        .expect("retrievability proof should pass with matching hash");
    tracing::debug!(permit_id = %permit.permit_id, content_hash = %permit.proof.content_hash);

    assert_eq!(permit.proof.source_tier, StorageTier::L2Warm);
    assert_eq!(permit.proof.target_tier, StorageTier::L3Archive);
    assert_eq!(permit.proof.content_hash, hash);
    assert_eq!(gate.passed_count(), 1);
    assert_eq!(gate.failed_count(), 0);

    tracing::info!(test = "test_gate_passes_for_available_data", phase = "exit");
}

#[test]
fn test_gate_rejects_unavailable_data() {
    init_tracing();
    tracing::info!(test = "test_gate_rejects_unavailable_data", phase = "enter");

    let mut gate = RetrievabilityGate::new(RetrievabilityConfig::default());
    let artifact = ArtifactId("artifact-missing".to_string());
    let segment = SegmentId("seg-missing".to_string());

    // No target state registered → attempt_eviction must fail-closed.
    let result = gate.attempt_eviction(&artifact, &segment, &content_hash(b"any"));
    tracing::debug!(?result, "eviction attempt against unregistered target");

    let err = result.expect_err("fail-closed: unregistered target must be rejected");
    assert_eq!(err.code, ERR_TARGET_UNREACHABLE);
    assert_eq!(gate.passed_count(), 0);
    assert_eq!(gate.failed_count(), 1);
    assert!(gate.events().iter().any(|e| e.code == RG_EVICTION_BLOCKED));

    tracing::info!(test = "test_gate_rejects_unavailable_data", phase = "exit");
}

#[test]
fn test_gate_rejects_malformed_identifiers() {
    init_tracing();
    tracing::info!(
        test = "test_gate_rejects_malformed_identifiers",
        phase = "enter"
    );

    let mut gate = RetrievabilityGate::new(RetrievabilityConfig::default());

    let empty_artifact = gate.attempt_eviction(
        &ArtifactId(String::new()),
        &SegmentId("seg-1".into()),
        &content_hash(b"x"),
    );
    assert_eq!(
        empty_artifact.expect_err("empty artifact id").code,
        ERR_INVALID_ARTIFACT_ID
    );

    let empty_segment = gate.attempt_eviction(
        &ArtifactId("artifact-1".into()),
        &SegmentId(String::new()),
        &content_hash(b"x"),
    );
    assert_eq!(
        empty_segment.expect_err("empty segment id").code,
        ERR_INVALID_SEGMENT_ID
    );

    let receipts = gate.receipts();
    tracing::debug!(receipt_count = receipts.len(), "post-rejection receipts");
    assert_eq!(receipts.iter().filter(|r| !r.passed).count(), 2);

    tracing::info!(
        test = "test_gate_rejects_malformed_identifiers",
        phase = "exit"
    );
}

// ---------------------------------------------------------------------------
// Migration artifact
// ---------------------------------------------------------------------------

#[test]
fn test_artifact_captures_pre_state() {
    init_tracing();
    tracing::info!(test = "test_artifact_captures_pre_state", phase = "enter");

    let artifact = generate_reference_artifact();
    tracing::debug!(
        plan_id = %artifact.plan_id,
        schema_version = %artifact.schema_version,
        "reference artifact"
    );

    assert_eq!(artifact.schema_version, SCHEMA_VERSION);
    assert!(!artifact.steps.is_empty(), "must capture migration steps");
    let first = &artifact.steps[0];
    assert!(
        !first.pre_state_hash.is_empty(),
        "pre-state hash captured per step"
    );
    assert!(
        !first.post_state_hash.is_empty(),
        "post-state hash captured per step"
    );
    assert_ne!(
        first.pre_state_hash, first.post_state_hash,
        "pre and post state must differ for a real migration step"
    );

    tracing::info!(test = "test_artifact_captures_pre_state", phase = "exit");
}

#[test]
fn test_artifact_validates_post_state() {
    init_tracing();
    tracing::info!(test = "test_artifact_validates_post_state", phase = "enter");

    let artifact: MigrationArtifact = generate_reference_artifact();
    let result = validate_artifact(&artifact);
    tracing::debug!(valid = result.valid, error_count = result.errors.len());

    assert!(
        result.valid,
        "reference artifact must validate: {:?}",
        result.errors
    );
    assert!(result.errors.is_empty());
    assert!(verify_artifact_signatures(&artifact));
    // Schema version must round-trip.
    assert_eq!(
        ArtifactVersion::from_str_version(&artifact.schema_version),
        Some(ArtifactVersion::V1_0)
    );

    tracing::info!(test = "test_artifact_validates_post_state", phase = "exit");
}

#[test]
fn test_artifact_evidence_signed_and_verifiable() {
    init_tracing();
    tracing::info!(
        test = "test_artifact_evidence_signed_and_verifiable",
        phase = "enter"
    );

    let artifact = generate_reference_artifact();
    assert!(!artifact.signature.is_empty(), "INV-MA-SIGNED");
    assert!(!artifact.rollback_receipt.signature.is_empty());
    assert!(verify_artifact_signatures(&artifact));

    // Tampering with any field must invalidate the signature.
    let mut tampered = artifact.clone();
    tampered.plan_id = "tampered-plan".to_string();
    tracing::debug!(original_plan = %artifact.plan_id, tampered_plan = %tampered.plan_id);
    assert!(
        !verify_artifact_signatures(&tampered),
        "signature must reject tampered artifact"
    );

    tracing::info!(
        test = "test_artifact_evidence_signed_and_verifiable",
        phase = "exit"
    );
}

#[test]
fn test_artifact_content_hash_is_deterministic() {
    init_tracing();
    tracing::info!(
        test = "test_artifact_content_hash_is_deterministic",
        phase = "enter"
    );

    let a = generate_reference_artifact();
    let b = generate_reference_artifact();
    let hash_a = compute_content_hash(&a);
    let hash_b = compute_content_hash(&b);
    tracing::debug!(%hash_a, %hash_b, "twin reference artifact hashes");

    assert_eq!(hash_a, hash_b, "INV-MA-DETERMINISTIC");
    assert_eq!(hash_a.len(), 64);

    tracing::info!(
        test = "test_artifact_content_hash_is_deterministic",
        phase = "exit"
    );
}

// ---------------------------------------------------------------------------
// Rollback bundle: success + failure paths
// ---------------------------------------------------------------------------

#[test]
fn test_successful_migration_commits() {
    init_tracing();
    tracing::info!(test = "test_successful_migration_commits", phase = "enter");

    let mut store = BundleStore::new();
    let pre = make_snapshot("1.0.0", "schema-1");
    store.set_state(pre.clone());

    // Pre-migration state captured via MigrationArtifact.
    let artifact = generate_reference_artifact();
    assert!(validate_artifact(&artifact).valid);

    let bundle = store
        .create_bundle(
            "1.1.0",
            "1.0.0",
            "2026-05-12T00:00:00Z",
            make_components("commit"),
        )
        .expect("bundle creation");
    tracing::debug!(integrity_hash = %bundle.integrity_hash, "rollback bundle created");

    // Bundle integrity holds before any rollback application.
    assert!(bundle.verify_integrity().is_ok());
    assert!(bundle.check_compatibility("1.1.0").is_ok());

    // Successful migration leaves the store at the new version: no rollback applied.
    let listed = store.list_bundles();
    assert_eq!(listed, vec!["1.0.0".to_string()]);

    tracing::info!(test = "test_successful_migration_commits", phase = "exit");
}

#[test]
fn test_failed_migration_triggers_rollback() {
    init_tracing();
    tracing::info!(
        test = "test_failed_migration_triggers_rollback",
        phase = "enter"
    );

    let mut store = BundleStore::new();
    let pre = make_snapshot("1.0.0", "schema-1");
    // Simulate that the upgrade was applied: current state is post-upgrade.
    let post = make_snapshot("1.1.0", "schema-2");
    store.set_state(post.clone());

    let bundle = store
        .create_bundle(
            "1.1.0",
            "1.0.0",
            "2026-05-12T00:01:00Z",
            make_components("rollback"),
        )
        .expect("bundle creation");

    let result = store.apply_rollback(
        &bundle,
        "1.1.0",
        RollbackMode::Apply,
        &pre,
        "2026-05-12T00:02:00Z",
    );
    tracing::debug!(success = result.success, actions = result.actions.len());

    // Rollback ran: state was reverted to the pre-upgrade snapshot.
    assert_eq!(store.current_state(), Some(&pre));
    assert!(!result.actions.is_empty());

    tracing::info!(
        test = "test_failed_migration_triggers_rollback",
        phase = "exit"
    );
}

#[test]
fn test_rollback_bundle_restores_snapshot() {
    init_tracing();
    tracing::info!(
        test = "test_rollback_bundle_restores_snapshot",
        phase = "enter"
    );

    let mut store = BundleStore::new();
    let pre = make_snapshot("2.0.0", "schema-old");
    let post = make_snapshot("2.1.0", "schema-new");
    store.set_state(post.clone());

    let bundle = store
        .create_bundle(
            "2.1.0",
            "2.0.0",
            "2026-05-12T01:00:00Z",
            make_components("restore"),
        )
        .expect("bundle creation");

    let result = store.apply_rollback(
        &bundle,
        "2.1.0",
        RollbackMode::Apply,
        &pre,
        "2026-05-12T01:01:00Z",
    );
    tracing::debug!(post_state_hash = ?result.post_snapshot.as_ref().map(|s| s.snapshot_hash().unwrap()));

    let restored = store.current_state().expect("state present after rollback");
    assert_eq!(restored.binary_version, pre.binary_version);
    assert_eq!(restored.schema_version, pre.schema_version);
    assert!(restored.diff(&pre).is_empty(), "snapshot fully restored");

    tracing::info!(
        test = "test_rollback_bundle_restores_snapshot",
        phase = "exit"
    );
}

#[test]
fn test_rollback_restore_health_check() {
    init_tracing();
    tracing::info!(test = "test_rollback_restore_health_check", phase = "enter");

    let mut store = BundleStore::new();
    let pre = make_snapshot("3.0.0", "schema-3-old");
    let post = make_snapshot("3.1.0", "schema-3-new");
    store.set_state(post);

    let bundle = store
        .create_bundle(
            "3.1.0",
            "3.0.0",
            "2026-05-12T02:00:00Z",
            make_components("health"),
        )
        .expect("bundle creation");

    let result = store.apply_rollback(
        &bundle,
        "3.1.0",
        RollbackMode::Apply,
        &pre,
        "2026-05-12T02:01:00Z",
    );
    tracing::debug!(health_results = result.health_results.len());

    assert!(
        result.success,
        "all health checks should pass for matching snapshot"
    );
    let kinds: Vec<_> = result
        .health_results
        .iter()
        .map(|h| h.kind.clone())
        .collect();
    assert!(kinds.contains(&HealthCheckKind::BinaryVersion));
    assert!(kinds.contains(&HealthCheckKind::ConfigSchema));
    assert!(kinds.contains(&HealthCheckKind::StateIntegrity));
    assert!(kinds.contains(&HealthCheckKind::SmokeTest));
    assert!(result.health_results.iter().all(|h| h.passed));

    tracing::info!(test = "test_rollback_restore_health_check", phase = "exit");
}

#[test]
fn test_rollback_rejects_version_mismatch() {
    init_tracing();
    tracing::info!(
        test = "test_rollback_rejects_version_mismatch",
        phase = "enter"
    );

    let mut store = BundleStore::new();
    let pre = make_snapshot("4.0.0", "schema-4");
    store.set_state(make_snapshot("4.1.0", "schema-4-new"));

    let bundle = store
        .create_bundle(
            "4.1.0",
            "4.0.0",
            "2026-05-12T03:00:00Z",
            make_components("vmismatch"),
        )
        .expect("bundle creation");

    // current_version disagrees with bundle.compatibility.rollback_from.
    let result = store.apply_rollback(
        &bundle,
        "4.2.0", // wrong version
        RollbackMode::Apply,
        &pre,
        "2026-05-12T03:01:00Z",
    );
    tracing::debug!(success = result.success, errors = result.errors.len());

    assert!(!result.success);
    assert!(matches!(
        result.errors.first(),
        Some(RollbackBundleError::VersionMismatch { .. })
    ));

    tracing::info!(
        test = "test_rollback_rejects_version_mismatch",
        phase = "exit"
    );
}

// ---------------------------------------------------------------------------
// Full integration: storage gate → artifact → rollback
// ---------------------------------------------------------------------------

#[test]
fn test_full_round_trip_with_tracing() {
    init_tracing();
    tracing::info!(test = "test_full_round_trip_with_tracing", phase = "enter");

    // 1. Storage retrievability gate: success + fail-closed paths together.
    let mut gate = RetrievabilityGate::new(RetrievabilityConfig::default());
    let artifact_id = ArtifactId("round-trip-art".into());
    let segment_id = SegmentId("round-trip-seg".into());
    let payload = content_hash(b"round-trip-payload");
    seed_retrievability_target(
        &mut gate,
        &artifact_id,
        &segment_id,
        StorageTier::L3Archive,
        TargetTierState {
            content_hash: payload.clone(),
            reachable: true,
            fetch_latency_ms: 30,
        },
    );
    let permit = gate
        .attempt_eviction(&artifact_id, &segment_id, &payload)
        .expect("seeded artifact retrievable");
    tracing::debug!(permit = %permit.permit_id, "gate emitted eviction permit");

    // A second, unregistered artifact must still fail-closed.
    let bogus_artifact = ArtifactId("round-trip-bogus".into());
    let bogus_segment = SegmentId("round-trip-bogus-seg".into());
    let gate_err = gate
        .attempt_eviction(&bogus_artifact, &bogus_segment, &content_hash(b"data"))
        .expect_err("fail-closed");
    tracing::debug!(error_code = %gate_err.code, "storage gate rejected unseeded artifact");
    assert_eq!(gate_err.code, ERR_TARGET_UNREACHABLE);

    // 2. Pre-migration: capture a real migration artifact + validate.
    let migration = generate_reference_artifact();
    assert!(validate_artifact(&migration).valid);
    let content = compute_content_hash(&migration);
    tracing::debug!(%content, "migration artifact content hash computed");

    // 3. Build a rollback bundle for the would-be migration.
    let mut store = BundleStore::new();
    let pre = make_snapshot("5.0.0", "schema-5");
    let post = make_snapshot("5.1.0", "schema-5-new");
    store.set_state(post);
    let bundle = store
        .create_bundle(
            "5.1.0",
            "5.0.0",
            "2026-05-12T04:00:00Z",
            make_components("e2e"),
        )
        .expect("bundle creation");

    // 4. Apply rollback and assert restoration.
    let result = store.apply_rollback(
        &bundle,
        "5.1.0",
        RollbackMode::Apply,
        &pre,
        "2026-05-12T04:01:00Z",
    );
    tracing::debug!(success = result.success, "round trip rollback applied");
    assert!(result.success);
    assert_eq!(store.current_state(), Some(&pre));

    // 5. Audit log captured every transition.
    let audit = store.audit_log();
    assert!(audit.len() >= 2, "audit log records create + apply");

    tracing::info!(test = "test_full_round_trip_with_tracing", phase = "exit");
}

#[test]
fn test_partial_failure_rollback_atomicity() {
    init_tracing();
    tracing::info!(
        test = "test_partial_failure_rollback_atomicity",
        phase = "enter"
    );

    let mut store = BundleStore::new();
    let pre = make_snapshot("6.0.0", "schema-6");
    let post = make_snapshot("6.1.0", "schema-6-new");
    store.set_state(post.clone());

    // Build a bundle, then tamper with a component to force a checksum mismatch.
    let mut bundle = store
        .create_bundle(
            "6.1.0",
            "6.0.0",
            "2026-05-12T05:00:00Z",
            make_components("partial"),
        )
        .expect("bundle creation");
    if let Some(first) = bundle.components.first_mut() {
        first.data = b"tampered-payload".to_vec();
    }
    tracing::debug!("tampered bundle component to force atomic failure");

    let result = store.apply_rollback(
        &bundle,
        "6.1.0",
        RollbackMode::Apply,
        &pre,
        "2026-05-12T05:01:00Z",
    );
    tracing::debug!(success = result.success, errors = result.errors.len());

    // Apply must fail and state must NOT have been mutated (atomicity).
    assert!(!result.success);
    assert!(!result.errors.is_empty());
    assert_eq!(
        store.current_state(),
        Some(&post),
        "state unchanged on atomic failure"
    );

    tracing::info!(
        test = "test_partial_failure_rollback_atomicity",
        phase = "exit"
    );
}
