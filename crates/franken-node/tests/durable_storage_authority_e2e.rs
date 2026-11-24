//! Integration coverage for the w0fc6.3 durable-storage surfaces:
//! the trust-card registry authority switch
//! ([`frankenengine_node::supply_chain::trust_card_registry_store`]) and the
//! evidence-ledger durable sink
//! ([`frankenengine_node::observability::evidence_ledger_durable`]).
//!
//! These tests live in a wired `[[test]]` target because `[lib] test = false`
//! keeps inline `#[cfg(test)]` suites out of `cargo test` (bd-rjc2m.21); both
//! surfaces are public API, so an integration target exercises them without
//! losing coverage (same rationale as `fleet_transport_durable_e2e`).
//!
//! Contracts under test:
//! * the frankensqlite store is the authoritative registry surface;
//! * the legacy JSON pair is a one-time import source that seeds the store;
//! * the stored signed high-water marker rejects snapshot rollback even when
//!   the snapshot row itself is tampered;
//! * every committed transaction survives process death on published fsqlite
//!   0.1.19 (proven here as reopen-after-drop; cross-process abort is proven
//!   for the identical pragma/transaction stack by
//!   `crash_child_commits_survive_sigkill_style_abort`);
//! * the durable evidence sink commits each newline-framed entry line and
//!   replaces the legacy spill tally once present.

use std::fs;
use std::io::Write as _;

use frankenengine_node::observability::evidence_ledger_durable::{
    DurableEvidenceLedger, DurableEvidenceSink, count_durable_entries,
};
use frankenengine_node::supply_chain::certification::{EvidenceType, VerifiedEvidenceRef};
use frankenengine_node::supply_chain::trust_card::{
    BehavioralProfile, CapabilityDeclaration, CapabilityRisk, CertificationLevel,
    ExtensionIdentity, ProvenanceSummary, PublisherIdentity, ReputationTrend, RevocationStatus,
    RiskAssessment, RiskLevel,
};
use frankenengine_node::supply_chain::trust_card::{
    SnapshotSourceContext, TrustCardError, TrustCardInput, TrustCardListFilter, TrustCardMutation,
    TrustCardRegistry,
};
use frankenengine_node::supply_chain::trust_card_registry_store::{
    TrustCardRegistryStore, authority_state_present, durable_store_authority_path,
    durable_store_path,
};

const REGISTRY_RELATIVE_PATH: &str = ".franken-node/state/trust-card-registry.v1.json";

fn fixture_input() -> TrustCardInput {
    TrustCardInput {
        extension: ExtensionIdentity {
            extension_id: "npm:@acme/auth-guard".to_string(),
            version: "2.1.0".to_string(),
        },
        publisher: PublisherIdentity {
            publisher_id: "pub-acme".to_string(),
            display_name: "Acme".to_string(),
        },
        certification_level: CertificationLevel::Silver,
        capability_declarations: vec![CapabilityDeclaration {
            name: "net_client".to_string(),
            description: "outbound https".to_string(),
            risk: CapabilityRisk::Medium,
        }],
        behavioral_profile: BehavioralProfile {
            network_access: true,
            filesystem_access: false,
            subprocess_access: false,
            profile_summary: "network-only extension".to_string(),
        },
        revocation_status: RevocationStatus::Active,
        provenance_summary: ProvenanceSummary {
            attestation_level: "verified".to_string(),
            source_uri: "https://registry.npmjs.org/@acme/auth-guard".to_string(),
            artifact_hashes: vec!["sha256:a".to_string()],
            verified_at: "2026-01-01T00:00:00Z".to_string(),
        },
        reputation_score_basis_points: 9_000,
        reputation_trend: ReputationTrend::Stable,
        active_quarantine: false,
        dependency_trust_summary: Vec::new(),
        last_verified_timestamp: "2026-01-01T00:00:00Z".to_string(),
        user_facing_risk_assessment: RiskAssessment {
            level: RiskLevel::Low,
            summary: "well-known publisher".to_string(),
        },
        evidence_refs: vec![VerifiedEvidenceRef {
            evidence_id: "ev-durable-001".to_string(),
            evidence_type: EvidenceType::ProvenanceChain,
            verified_at_epoch: 900,
            verification_receipt_hash: "a".repeat(64),
        }],
    }
}

fn persisted_registry(now_secs: u64) -> TrustCardRegistry {
    let mut registry = TrustCardRegistry::default();
    registry
        .create(fixture_input(), now_secs, "trace-durable-e2e")
        .expect("create fixture trust card");
    registry
}

fn revocation_mutation() -> TrustCardMutation {
    TrustCardMutation {
        certification_level: None,
        revocation_status: Some(RevocationStatus::Revoked {
            reason: "durable e2e rollback fixture".to_string(),
            revoked_at: "2026-01-01T00:01:00Z".to_string(),
        }),
        active_quarantine: Some(true),
        reputation_score_basis_points: Some(100),
        reputation_trend: Some(ReputationTrend::Declining),
        user_facing_risk_assessment: Some(RiskAssessment {
            level: RiskLevel::Critical,
            summary: "revoked in durable e2e fixture".to_string(),
        }),
        last_verified_timestamp: Some("2026-01-01T00:01:00Z".to_string()),
        evidence_refs: None,
    }
}

fn load(path: &std::path::Path) -> Result<TrustCardRegistry, String> {
    TrustCardRegistry::load_authoritative_state(path, 60, 2_000, SnapshotSourceContext::TrustedFile)
        .map_err(|err| err.to_string())
}

fn card_count(registry: &mut TrustCardRegistry, trace: &str) -> usize {
    registry
        .list(&TrustCardListFilter::empty(), trace, 2_000)
        .expect("list cards")
        .len()
}

// ── Trust-card registry authority ───────────────────────────────────

#[test]
fn persist_then_load_roundtrips_through_the_durable_store_without_json_files() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join(REGISTRY_RELATIVE_PATH);

    persisted_registry(1_000)
        .persist_authoritative_state(&path)
        .expect("persist");

    // Authority switch: only the database exists; the legacy JSON pair does not.
    assert!(
        !path.is_file(),
        "persist must not publish the legacy JSON snapshot anymore"
    );
    assert!(
        frankenengine_node::supply_chain::trust_card_registry_store::durable_store_path(&path)
            .is_file(),
        "persist must create the durable store"
    );

    let mut restored = load(&path).expect("load from durable store");
    assert_eq!(card_count(&mut restored, "trace-roundtrip"), 1);
}

/// This executable only observes whether dispatch launched a worker. It never
/// returns an engine response or substitutes for a successful guest execution.
#[cfg(all(feature = "engine", unix))]
fn dispatch_launch_probe(root: &std::path::Path) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt as _;

    let worker = root.join("dispatch-worker");
    fs::write(&worker, "#!/bin/sh\n: > \"$0.launched\"\nexit 91\n")
        .expect("write worker launch probe");
    fs::set_permissions(&worker, fs::Permissions::from_mode(0o700))
        .expect("make worker launch probe executable");
    worker
}

/// bd-zqz0q / bd-reality-20260923-26n9r.1: losing the entire authority between
/// preflight and dispatch must refuse just as losing an individual trusted
/// card does. In particular, balanced and legacy-risky must not silently skip
/// the execution-time recheck when both registry surfaces have disappeared.
#[cfg(all(feature = "engine", unix))]
#[test]
fn dispatch_refuses_registry_loss_after_preflight_before_worker_launch() {
    use frankenengine_node::config::{Config, PreferredRuntime, Profile};
    use frankenengine_node::ops::engine_dispatcher::EngineDispatcher;
    use frankenengine_node::supply_chain::trust_card_registry_store::{
        durable_store_path, record_revocation_frontier, registry_snapshot_path,
    };

    const NOW_SECS: u64 = 2_000;
    for profile in [Profile::Strict, Profile::Balanced, Profile::LegacyRisky] {
        let dir = tempfile::tempdir().expect("tempdir");
        let app = dir.path().join("app.js");
        fs::write(&app, "console.log('must not execute');\n").expect("write application");
        let worker = dispatch_launch_probe(dir.path());
        let mut config = Config::for_profile(profile);
        config.synthesize_init_security_defaults();
        let registry_path = registry_snapshot_path(dir.path());
        let mut registry =
            TrustCardRegistry::from_config(&config.trust).expect("configured trust registry");
        registry
            .create(fixture_input(), NOW_SECS, "trace-trust-loss-preflight")
            .expect("create trusted card");
        registry
            .persist_authoritative_state(&registry_path)
            .expect("persist authoritative trust state");
        record_revocation_frontier(
            &registry_path,
            &config.trust,
            NOW_SECS,
            "test: trust sync before dispatch",
        )
        .expect("record authenticated frontier");

        // Read and authenticate the real durable state before simulating loss.
        // The dispatcher receives the same trusted ID that preflight observed.
        let mut preflight_registry = TrustCardRegistry::load_authoritative_state_from_config(
            &registry_path,
            &config.trust,
            NOW_SECS,
            SnapshotSourceContext::TrustedFile,
        )
        .expect("preflight can read authoritative trust state");
        let trusted_card = preflight_registry
            .read(
                "npm:@acme/auth-guard",
                NOW_SECS,
                "trace-trust-loss-preflight",
            )
            .expect("preflight authenticates trust card")
            .expect("trusted card exists");
        assert_eq!(trusted_card.revocation_status, RevocationStatus::Active);
        let trusted_ids = vec![trusted_card.extension.extension_id];
        drop(preflight_registry);
        drop(registry);

        let state_dir = registry_path.parent().expect("state directory");
        let preserved_state = dir.path().join("state-before-trust-loss");
        fs::rename(state_dir, &preserved_state).expect("move authority away after preflight");
        assert!(!registry_path.exists());
        assert!(!durable_store_path(&registry_path).exists());

        let error = EngineDispatcher::new(None, PreferredRuntime::FrankenEngine)
            .with_native_session_worker_path(worker)
            .dispatch_run(&app, &config, &profile.to_string(), &trusted_ids, NOW_SECS)
            .expect_err("missing authority must block every profile")
            .to_string();
        assert!(
            error.contains("authoritative trust registry is missing after preflight"),
            "{profile}: expected the missing-authority refusal, got {error}"
        );
        assert!(
            error.contains("trust sync --force"),
            "{profile}: refusal must explain recovery: {error}"
        );
        assert!(
            !dir.path().join("dispatch-worker.launched").exists(),
            "{profile}: trust loss must refuse before launching any worker"
        );
        assert!(
            !state_dir.exists(),
            "{profile}: refusing trust loss must not recreate an empty authority"
        );
        assert!(
            preserved_state.join("trust-card-registry.v1.db").is_file(),
            "the original durable authority remains intact outside the active path"
        );
    }
}

/// An empty preflight dependency set still permits a standalone program to
/// reach worker launch. Besides guarding that contract, this proves the launch
/// observer above can detect an actual child process through this dispatcher.
#[cfg(all(feature = "engine", unix))]
#[test]
fn dispatch_without_trusted_dependencies_reaches_worker_launch() {
    use frankenengine_node::config::{Config, PreferredRuntime, Profile};
    use frankenengine_node::ops::engine_dispatcher::EngineDispatcher;

    let dir = tempfile::tempdir().expect("tempdir");
    let app = dir.path().join("app.js");
    fs::write(&app, "console.log('standalone');\n").expect("write application");
    let worker = dispatch_launch_probe(dir.path());
    let mut config = Config::for_profile(Profile::Balanced);
    config.synthesize_init_security_defaults();

    // The observer exits without executing JavaScript or speaking the private
    // worker protocol, so failure is expected after its launch.
    let error = EngineDispatcher::new(None, PreferredRuntime::FrankenEngine)
        .with_native_session_worker_path(worker)
        .dispatch_run(&app, &config, "balanced", &[], 2_000)
        .expect_err("launch observer does not produce an engine response")
        .to_string();
    assert!(
        !error.contains("authoritative trust registry is missing after preflight"),
        "a standalone run does not inherit a dependency trust requirement: {error}"
    );
    assert!(
        dir.path().join("dispatch-worker.launched").is_file(),
        "a dependency-free run must reach worker launch: {error}"
    );
}

/// A nested relative entry may load modules from its project root, so its
/// dependency preflight must consult that root's real durable authority too.
/// This drives the public CLI with an installed, revoked dependency; merely
/// checking the entrypoint's parent would skip preflight and execute it.
#[cfg(feature = "engine")]
#[test]
fn run_project_authority_nested_entry_blocks_revoked_root_dependency() {
    use frankenengine_node::config::{Config, Profile};
    use frankenengine_node::supply_chain::trust_card_registry_store::{
        record_revocation_frontier, registry_snapshot_path,
    };
    use std::process::Command;

    let dir = tempfile::tempdir().expect("tempdir");
    fs::create_dir_all(dir.path().join("src")).expect("create source directory");
    fs::create_dir_all(dir.path().join("node_modules/@acme/auth-guard"))
        .expect("install dependency directory");
    fs::write(
        dir.path().join("package.json"),
        r#"{"name":"project-root-trust","dependencies":{"@acme/auth-guard":"2.1.0"}}"#,
    )
    .expect("write root dependency manifest");
    fs::write(
        dir.path().join("src/main.js"),
        "require('@acme/auth-guard');\n\
         require('fs').writeFileSync('unexpected-effect.txt', 'executed');\n",
    )
    .expect("write nested entrypoint");
    fs::write(
        dir.path().join("node_modules/@acme/auth-guard/index.js"),
        "console.log('revoked-dependency-executed');\n",
    )
    .expect("install dependency source");

    let mut config = Config::for_profile(Profile::Balanced);
    config.synthesize_init_security_defaults();
    fs::write(
        dir.path().join("franken_node.toml"),
        config.to_toml().expect("serialize operator config"),
    )
    .expect("write operator config");
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock")
        .as_secs();
    let registry_path = registry_snapshot_path(dir.path());
    let mut registry =
        TrustCardRegistry::from_config(&config.trust).expect("configured authoritative registry");
    registry
        .create(fixture_input(), now_secs, "trace-nested-project-create")
        .expect("register installed dependency");
    registry
        .update(
            "npm:@acme/auth-guard",
            revocation_mutation(),
            now_secs,
            "trace-nested-project-revoke",
        )
        .expect("revoke installed dependency");
    registry
        .persist_authoritative_state(&registry_path)
        .expect("persist real durable authority");
    record_revocation_frontier(
        &registry_path,
        &config.trust,
        now_secs,
        "test: current revoked dependency",
    )
    .expect("record authenticated revocation frontier");
    drop(registry);

    for profile in ["strict", "balanced", "legacy-risky"] {
        let output = Command::new(env!("CARGO_BIN_EXE_franken-node"))
            .args([
                "run",
                "src/main.js",
                "--policy",
                profile,
                "--runtime",
                "franken-engine",
                "--engine-bin",
                env!("CARGO_BIN_EXE_franken-node"),
                "--json",
            ])
            .current_dir(dir.path())
            .output()
            .expect("run nested entry through actual CLI");
        assert!(
            !output.status.success(),
            "{profile}: a revoked root dependency must block nested entry execution"
        );
        let report: serde_json::Value =
            serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
                panic!(
                    "{profile}: expected blocked preflight JSON ({error}); stdout={} stderr={}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                )
            });
        assert_eq!(report["verdict"]["status"], "blocked", "{report}");
        assert_eq!(
            report["project_root"],
            dir.path()
                .canonicalize()
                .expect("canonical project root")
                .display()
                .to_string()
        );
        assert!(
            report["verdict"]["violations"]
                .as_array()
                .expect("preflight violations")
                .iter()
                .any(|violation| {
                    violation["kind"] == "revoked"
                        && violation["extension_id"] == "npm:@acme/auth-guard"
                }),
            "{profile}: refusal must come from the root's revoked card: {report}"
        );
        assert_eq!(report["receipt"]["decision"], "denied");
        assert!(
            !String::from_utf8_lossy(&output.stdout).contains("revoked-dependency-executed"),
            "the installed dependency must never execute"
        );
        assert!(!dir.path().join("unexpected-effect.txt").exists());
        assert!(!dir.path().join("src/unexpected-effect.txt").exists());
    }
}

#[test]
fn legacy_json_pair_imports_once_and_seeds_the_durable_store() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join(REGISTRY_RELATIVE_PATH);
    let legacy_json = frankenengine_node::supply_chain::trust_card::to_canonical_json(
        &persisted_registry(1_000).snapshot().expect("snapshot"),
    )
    .expect("encode legacy snapshot");
    fs::create_dir_all(path.parent().expect("parent")).expect("create state dir");
    fs::write(&path, &legacy_json).expect("write legacy snapshot only (no sidecar)");

    let mut first = load(&path).expect("first load takes the legacy import path");
    assert_eq!(card_count(&mut first, "trace-import"), 1);

    // The import seeded the store: deleting the legacy file must not matter.
    fs::remove_file(&path).expect("drop legacy snapshot");

    let mut second = load(&path).expect("second load reads the seeded durable store");
    assert_eq!(card_count(&mut second, "trace-import-2"), 1);
}

#[test]
fn stored_high_water_rejects_older_snapshot_row_tamper() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join(REGISTRY_RELATIVE_PATH);

    // Epoch-2 state becomes authoritative...
    let mut registry = persisted_registry(1_000);
    registry
        .update(
            "npm:@acme/auth-guard",
            revocation_mutation(),
            1_100,
            "trace-revoke",
        )
        .expect("revoke advances the epoch");
    registry
        .persist_authoritative_state(&path)
        .expect("persist epoch-2 state");

    // ...then an attacker rolls the snapshot row back to epoch-1 bytes while
    // the signed high-water row stays at epoch 2.
    let older_json = frankenengine_node::supply_chain::trust_card::to_canonical_json(
        &persisted_registry(1_000)
            .snapshot()
            .expect("epoch-1 snapshot"),
    )
    .expect("encode older snapshot");
    // The attacker edits the database directly (the one-time legacy importer
    // never overwrites existing rows, franken_node#4).
    let store = TrustCardRegistryStore::open(&path).expect("open store");
    store
        .with_immediate_transaction(|_connection, tx| {
            tx.execute_with_params(
                "UPDATE registry_state SET canonical_json = ?1 WHERE slot = 'snapshot';",
                &[fsqlite::SqliteValue::Text(older_json.as_str().into())],
            )
            .map_err(|err| TrustCardError::SnapshotWrite {
                path: path.clone(),
                detail: err.to_string(),
            })?;
            Ok(())
        })
        .expect("install older snapshot row");

    let err = load(&path).expect_err("older signed snapshot must be rejected");
    assert!(
        err.contains("rollback rejected") || err.contains("chain rejected"),
        "unexpected error: {err}"
    );
}

#[test]
fn reopened_store_sees_committed_state_after_drop() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join(REGISTRY_RELATIVE_PATH);
    persisted_registry(1_000)
        .persist_authoritative_state(&path)
        .expect("persist");

    {
        let store = TrustCardRegistryStore::open(&path).expect("open #1");
        assert!(store.load_state().expect("rows").is_some());
    } // dropped: connection closed

    let store = TrustCardRegistryStore::open(&path).expect("reopen after drop");
    let (snapshot_raw, high_water_raw) = store
        .load_state()
        .expect("rows after reopen")
        .expect("state");
    assert!(
        snapshot_raw.contains("npm:@acme/auth-guard"),
        "snapshot row must survive process-equivalent close/reopen"
    );
    assert!(
        high_water_raw.is_some(),
        "high-water row must accompany the snapshot"
    );
}

/// Materialize an older installation's authenticated JSON pair without
/// creating durable authority in the destination project.
fn write_legacy_registry(path: &std::path::Path, registry: &TrustCardRegistry) {
    let donor = tempfile::tempdir().expect("legacy donor");
    let donor_path = donor.path().join(REGISTRY_RELATIVE_PATH);
    registry
        .persist_authoritative_state(&donor_path)
        .expect("persist donor");
    let (snapshot, high_water) = TrustCardRegistryStore::open(&donor_path)
        .expect("open donor")
        .load_state()
        .expect("read donor")
        .expect("donor rows");
    fs::create_dir_all(path.parent().expect("parent")).expect("legacy state directory");
    fs::write(path, snapshot).expect("write legacy snapshot");
    let mut high_water_path = path.as_os_str().to_os_string();
    high_water_path.push(".high-water.json");
    fs::write(
        std::path::PathBuf::from(high_water_path),
        high_water.expect("signed high-water"),
    )
    .expect("write legacy high-water");
}

/// Bypass the guarded public writer to model incomplete storage left by
/// damage or an old installation. Every fault is committed in the real store.
fn damage_registry_rows(path: &std::path::Path, sql: &str) {
    use fsqlite::compat::TransactionExt as _;
    let connection =
        fsqlite::Connection::open(durable_store_path(path).to_string_lossy().as_ref())
            .expect("open fault injection connection");
    connection.query("PRAGMA journal_mode=WAL;").expect("WAL");
    connection.query("PRAGMA synchronous=FULL;").expect("FULL");
    let mut tx = connection.transaction().expect("fault transaction");
    tx.execute_batch(sql).expect("inject storage damage");
    tx.commit().expect("commit storage damage");
}

#[test]
fn takeover_preserves_revocation_when_database_is_lost_and_legacy_json_remains() {
    use frankenengine_node::supply_chain::trust_card_registry_store::read_revocation_frontier;
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join(REGISTRY_RELATIVE_PATH);
    write_legacy_registry(&path, &persisted_registry(1_000));
    let legacy_bytes = fs::read(&path).expect("retained legacy");
    let stale = load(&path).expect("first legacy import");
    let mut current = load(&path).expect("load current");
    current
        .update(
            "npm:@acme/auth-guard",
            revocation_mutation(),
            1_100,
            "trace-durable-revoke",
        )
        .expect("revoke");
    current
        .persist_authoritative_state(&path)
        .expect("commit revocation");
    assert!(durable_store_authority_path(&path).is_file());

    let db = durable_store_path(&path);
    let preserved = db.with_extension("db.preserved");
    fs::rename(&db, &preserved).expect("preserve missing authority");
    assert!(authority_state_present(&path));
    assert!(
        load(&path)
            .expect_err("legacy fallback denied")
            .contains("authority")
    );
    assert!(
        stale.persist_authoritative_state(&path).is_err(),
        "stale writer cannot recreate authority"
    );
    let config = frankenengine_node::config::Config::for_profile(
        frankenengine_node::config::Profile::Balanced,
    );
    assert!(read_revocation_frontier(&path, &config.trust).is_err());
    assert!(
        !db.exists(),
        "failed load and persist must not recreate the database"
    );
    assert_eq!(fs::read(&path).expect("legacy retained"), legacy_bytes);

    fs::rename(&preserved, &db).expect("restore committed authority");
    let mut restored = load(&path).expect("restored committed state");
    let card = restored
        .read("npm:@acme/auth-guard", 2_000, "trace-restored")
        .expect("read")
        .expect("card");
    assert!(matches!(
        card.revocation_status,
        RevocationStatus::Revoked { .. }
    ));
    assert!(card.active_quarantine);
}

#[test]
fn takeover_rejects_missing_rows_or_schema_before_legacy_import_or_stale_write() {
    for damage in [
        "DELETE FROM registry_state WHERE slot = 'snapshot';",
        "DELETE FROM registry_state WHERE slot = 'high_water';",
        "DELETE FROM registry_state;",
        "DROP TABLE registry_state; DROP TABLE registry_meta;",
    ] {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(REGISTRY_RELATIVE_PATH);
        write_legacy_registry(&path, &persisted_registry(1_000));
        let stale = load(&path).expect("import");
        let mut current = load(&path).expect("current");
        current
            .update(
                "npm:@acme/auth-guard",
                revocation_mutation(),
                1_100,
                "trace-revoke",
            )
            .expect("revoke");
        current.persist_authoritative_state(&path).expect("commit");
        damage_registry_rows(&path, damage);
        let error = load(&path).expect_err("incomplete authority must refuse");
        assert!(error.contains("authority"), "{damage}: {error}");
        assert!(stale.persist_authoritative_state(&path).is_err(), "{damage}");
        assert!(durable_store_authority_path(&path).is_file());
    }
}

#[test]
fn authenticated_pre_marker_database_is_adopted_before_returning_registry() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join(REGISTRY_RELATIVE_PATH);
    persisted_registry(1_000)
        .persist_authoritative_state(&path)
        .expect("persist");
    let marker = durable_store_authority_path(&path);
    fs::rename(&marker, marker.with_extension("authority.pre-upgrade"))
        .expect("model a database from before takeover markers");
    let adopted = load(&path).expect("authenticate and adopt existing authority");
    assert!(
        marker.is_file(),
        "authenticated load publishes the durable guard"
    );
    let db = durable_store_path(&path);
    fs::rename(&db, db.with_extension("db.preserved")).expect("lose adopted database");
    assert!(load(&path).is_err());
    assert!(adopted.persist_authoritative_state(&path).is_err());
    assert!(!db.exists());
}

#[test]
fn invalid_pre_marker_snapshot_does_not_publish_a_takeover_marker() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join(REGISTRY_RELATIVE_PATH);
    write_legacy_registry(&path, &persisted_registry(1_000));
    load(&path).expect("first import");
    let marker = durable_store_authority_path(&path);
    fs::rename(&marker, marker.with_extension("authority.pre-upgrade"))
        .expect("pre-marker fixture");
    damage_registry_rows(
        &path,
        "UPDATE registry_state SET canonical_json = '{}' WHERE slot = 'snapshot';",
    );
    assert!(
        load(&path).is_err(),
        "retained legacy does not replace invalid durable state"
    );
    assert!(
        !marker.exists(),
        "authentication must precede adoption of old state"
    );
}

#[test]
fn metadata_only_frontier_store_still_allows_first_authenticated_legacy_import() {
    use frankenengine_node::config::{Config, Profile};
    use frankenengine_node::supply_chain::trust_card_registry_store::{
        read_revocation_frontier, record_revocation_frontier,
    };
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join(REGISTRY_RELATIVE_PATH);
    let mut config = Config::for_profile(Profile::Balanced);
    config.synthesize_init_security_defaults();
    let frontier = record_revocation_frontier(&path, &config.trust, 1_000, "test:first-sync")
        .expect("metadata-only store");
    assert!(!durable_store_authority_path(&path).exists());
    let mut registry = TrustCardRegistry::from_config(&config.trust).expect("configured registry");
    registry
        .create(fixture_input(), 1_000, "trace-legacy")
        .expect("card");
    write_legacy_registry(&path, &registry);
    let mut loaded = TrustCardRegistry::load_authoritative_state_from_config(
        &path,
        &config.trust,
        2_000,
        SnapshotSourceContext::TrustedFile,
    )
    .expect("first import into metadata-only store");
    assert_eq!(card_count(&mut loaded, "trace-metadata-import"), 1);
    assert!(durable_store_authority_path(&path).is_file());
    assert_eq!(
        read_revocation_frontier(&path, &config.trust).expect("frontier retained"),
        Some(frontier)
    );
}

#[test]
fn interrupted_or_invalid_takeover_never_reinitializes_from_retained_legacy() {
    let donor = tempfile::tempdir().expect("donor");
    let donor_path = donor.path().join(REGISTRY_RELATIVE_PATH);
    persisted_registry(1_000)
        .persist_authoritative_state(&donor_path)
        .expect("donor");
    let valid_marker =
        fs::read(durable_store_authority_path(&donor_path)).expect("actual marker");
    for marker_bytes in [
        valid_marker,
        Vec::new(),
        b"unsupported takeover version".to_vec(),
    ] {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(REGISTRY_RELATIVE_PATH);
        let registry = persisted_registry(1_000);
        write_legacy_registry(&path, &registry);
        // This is the observable interrupted-first-commit state: an open
        // database with no committed snapshot and an already published guard.
        drop(TrustCardRegistryStore::open(&path).expect("empty database"));
        fs::write(durable_store_authority_path(&path), marker_bytes).expect("takeover boundary");
        assert!(authority_state_present(&path));
        assert!(load(&path).is_err());
        assert!(registry.persist_authoritative_state(&path).is_err());
    }
}

#[cfg(unix)]
#[test]
fn open_authority_handle_refuses_removed_or_replaced_database_before_mutation() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join(REGISTRY_RELATIVE_PATH);
    persisted_registry(1_000)
        .persist_authoritative_state(&path)
        .expect("persist");
    let store = TrustCardRegistryStore::open(&path).expect("long-lived authority handle");
    let db = durable_store_path(&path);
    fs::rename(&db, db.with_extension("db.preserved")).expect("move open authority");
    assert!(store.load_state().is_err());
    let ran = std::cell::Cell::new(false);
    assert!(
        store
            .with_immediate_transaction(|_, _| {
                ran.set(true);
                Ok(())
            })
            .is_err()
    );
    assert!(!ran.get(), "missing authority refuses before invoking the writer");
    fs::write(&db, []).expect("replace with empty database");
    assert!(
        store.load_state().is_err(),
        "old handle cannot authorize a replacement file"
    );
    assert!(
        store
            .with_immediate_transaction(|_, _| {
                ran.set(true);
                Ok(())
            })
            .is_err()
    );
    assert!(
        !ran.get(),
        "replacement authority refuses before invoking the writer"
    );
}

// ── Evidence-ledger durable sink ────────────────────────────────────

#[test]
fn evidence_sink_commits_fragments_and_survives_reopen() {
    let dir = tempfile::tempdir().expect("tempdir");
    let project_root = dir.path();
    {
        let mut sink = DurableEvidenceSink::open_default(project_root).expect("open sink");
        sink.write_all(br#"{"decision_id":"DEC-E2E-001""#)
            .expect("fragment 1");
        assert_eq!(sink.committed_entries(), 0);
        sink.write_all(b"}\n").expect("terminator");
        sink.write_all(br#"{"decision_id":"DEC-E2E-002"}"#)
            .expect("entry 2");
        sink.write_all(b"\n").expect("newline 2");
        assert_eq!(sink.committed_entries(), 2);
    }

    // Reopen-after-drop: committed transactions are visible to a fresh reader.
    let ledger = DurableEvidenceLedger::open_default(project_root).expect("reopen ledger");
    assert_eq!(ledger.count().expect("count"), 2);
    assert!(ledger.latest_recorded_at().expect("latest").is_some());
    assert_eq!(
        count_durable_entries(&project_root.join(".franken-node/state")).expect("durable count"),
        Some(2)
    );
}

#[test]
fn evidence_sink_invalid_line_is_rejected_not_stored() {
    let dir = tempfile::tempdir().expect("tempdir");
    let project_root = dir.path();
    let mut sink = DurableEvidenceSink::open_default(project_root).expect("open sink");
    sink.write_all(b"{definitely-not-json\n")
        .expect_err("invalid JSON must fail");
    sink.write_all(br#"{"decision_id":"DEC-E2E-OK"}"#)
        .expect("valid entry");
    sink.write_all(b"\n").expect("newline");
    assert_eq!(sink.committed_entries(), 1);

    let ledger = DurableEvidenceLedger::open_default(project_root).expect("reopen");
    assert_eq!(ledger.count().expect("count"), 1);
}

#[test]
fn legacy_spill_files_import_exactly_once_into_the_durable_store() {
    let dir = tempfile::tempdir().expect("tempdir");
    let state_dir = dir.path().join(".franken-node/state");
    fs::create_dir_all(&state_dir).expect("create state dir");
    fs::write(
        state_dir.join("durable_evidence_spill.jsonl"),
        "{\"decision_id\":\"LEG-001\"}\n{\"decision_id\":\"LEG-002\"}\n",
    )
    .expect("write legacy spill");

    // Without a database the ops metric falls back to the legacy files.
    assert_eq!(
        count_durable_entries(&state_dir).expect("no store yet"),
        None,
        "missing database must signal the legacy fallback"
    );

    let ledger = DurableEvidenceLedger::open(&state_dir).expect("open ledger");
    assert_eq!(ledger.import_legacy_spill().expect("first import"), 2);
    assert_eq!(ledger.import_legacy_spill().expect("second import"), 0);
    assert_eq!(ledger.count().expect("count"), 2);

    // Once the store exists its row count is the metric of record.
    assert_eq!(
        count_durable_entries(&state_dir).expect("store present"),
        Some(2)
    );
}
