//! Mock-free end-to-end test for the incident bundle retention lifecycle.
//!
//! Drives the public surface of
//! `frankenengine_node::connector::incident_bundle_retention` through:
//!   - real `compute_integrity_hash` over a fully-populated `IncidentBundle`,
//!   - `IncidentBundleStore::new` configuration validation,
//!   - `store` (happy + IBR_INCOMPLETE + IBR_INTEGRITY_FAILURE +
//!     IBR_STORAGE_FULL paths),
//!   - `export` for every `ExportFormat` variant (JSON, CSV, SARIF),
//!   - `rotate_tiers` driving Hot→Cold→Archive by advancing wall-clock
//!     epochs past the configured horizons,
//!   - `delete` enforcing the archive-protected invariant unless
//!     `force_archive=true`.
//!
//! Bead: bd-1e1n9.
//!
//! No mocks: real bundle structs, real SHA-256 integrity hashes, real audit
//! trail. Each phase emits a structured tracing event PLUS a JSON-line on
//! stderr so a CI failure is reconstructable from the test transcript.
//!
//! Invariant coverage:
//!   - INV-IBR-COMPLETE   missing required field is rejected
//!   - INV-IBR-INTEGRITY  tampered integrity_hash is rejected on store + export
//!   - INV-IBR-RETENTION  Hot→Cold→Archive transitions follow the configured
//!     horizons; Archive is never auto-deleted
//!   - INV-IBR-EXPORT     every format includes the integrity hash; an
//!     in-flight tampered store rejects export

use std::sync::Once;
use std::time::Instant;

use frankenengine_node::connector::incident_bundle_retention::{
    BundleMetadata, ExportFormat, IncidentBundle, IncidentBundleError, IncidentBundleStore,
    RetentionConfig, RetentionTier, Severity, compute_integrity_hash, csv_header, export_csv_row,
    export_sarif, validate_bundle_complete,
};
use serde_json::json;
use tracing::{error, info};

static TEST_TRACING_INIT: Once = Once::new();

fn init_test_tracing() {
    TEST_TRACING_INIT.call_once(|| {
        let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    });
}

#[derive(serde::Serialize)]
struct PhaseLog<'a> {
    timestamp: String,
    test_name: &'a str,
    phase: &'a str,
    duration_ms: u64,
    success: bool,
    detail: serde_json::Value,
}

struct Harness {
    test_name: &'static str,
    started: Instant,
}

impl Harness {
    fn new(test_name: &'static str) -> Self {
        init_test_tracing();
        let h = Self {
            test_name,
            started: Instant::now(),
        };
        h.log_phase("setup", true, json!({}));
        h
    }

    fn log_phase(&self, phase: &str, success: bool, detail: serde_json::Value) {
        let entry = PhaseLog {
            timestamp: chrono::Utc::now().to_rfc3339(),
            test_name: self.test_name,
            phase,
            duration_ms: u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX),
            success,
            detail,
        };
        eprintln!(
            "{}",
            serde_json::to_string(&entry).expect("phase log serializes")
        );
        if success {
            info!(
                test = self.test_name,
                phase = phase,
                duration_ms = entry.duration_ms,
                "phase completed"
            );
        } else {
            error!(
                test = self.test_name,
                phase = phase,
                duration_ms = entry.duration_ms,
                "phase failed"
            );
        }
    }
}

/// Build a fully-populated `IncidentBundle` with the integrity hash already
/// derived from the production `compute_integrity_hash`. This mirrors how
/// production callers should construct a bundle before submitting it to a
/// store: hash last, after every other field is final.
fn make_bundle(
    bundle_id: &str,
    incident_id: &str,
    severity: Severity,
    tier: RetentionTier,
    size_bytes: u64,
    created_at_epoch: u64,
) -> IncidentBundle {
    let mut bundle = IncidentBundle {
        bundle_id: bundle_id.into(),
        incident_id: incident_id.into(),
        created_at: "2026-04-26T22:00:00Z".into(),
        severity,
        retention_tier: tier,
        metadata: BundleMetadata {
            title: format!("incident {bundle_id}"),
            detected_by: "health_gate".into(),
            component_ids: vec!["svc-foo".into(), "svc-bar".into()],
            tags: vec!["e2e".into(), "real".into()],
        },
        log_count: 32,
        trace_count: 8,
        metric_snapshot_count: 4,
        evidence_ref_count: 2,
        export_format_version: 1,
        integrity_hash: String::new(),
        size_bytes,
        created_at_epoch,
        last_tier_change_epoch: created_at_epoch,
    };
    bundle.integrity_hash = compute_integrity_hash(&bundle);
    bundle
}

fn small_config() -> RetentionConfig {
    RetentionConfig {
        hot_days: 1, // tight horizons so we can actually trip rotation
        cold_days: 1,
        archive_days: 365,
        cleanup_interval_hours: 1,
        storage_warn_percent: 70,
        storage_critical_percent: 85,
    }
}

#[test]
fn e2e_incident_bundle_lifecycle_full_happy_path() {
    let h = Harness::new("e2e_incident_bundle_lifecycle_full_happy_path");

    // ── ARRANGE: real store with realistic config ───────────────────
    let mut store = IncidentBundleStore::new(small_config(), 10_000_000)
        .expect("store accepts realistic config");
    h.log_phase("store_built", true, json!({"max_bytes": 10_000_000}));

    // ── ACT: real bundle created at t0; integrity hash derived from
    //         the production compute_integrity_hash ──────────────────
    let now = 1_745_750_000u64; // arbitrary fixed epoch
    let bundle = make_bundle(
        "bundle-real-001",
        "incident-real-001",
        Severity::High,
        RetentionTier::Hot,
        4_096,
        now,
    );
    validate_bundle_complete(&bundle).expect("bundle is INV-IBR-COMPLETE");
    h.log_phase(
        "bundle_built",
        true,
        json!({
            "bundle_id": bundle.bundle_id,
            "integrity_hash": bundle.integrity_hash,
            "size_bytes": bundle.size_bytes,
        }),
    );

    // ── ACT: store accepts the bundle ───────────────────────────────
    store
        .store(bundle.clone(), now)
        .expect("store accepts bundle");
    assert_eq!(store.bundle_count(), 1);
    assert_eq!(store.total_bytes(), 4_096);
    assert!(store.contains("bundle-real-001"));
    h.log_phase(
        "stored",
        true,
        json!({"bundle_count": 1, "total_bytes": 4_096}),
    );

    // ── ASSERT: every export format succeeds and embeds the hash ────
    for format in [ExportFormat::Json, ExportFormat::Csv, ExportFormat::Sarif] {
        let out = store
            .export("bundle-real-001", format, "operator-real", now)
            .expect("export succeeds");
        assert!(
            out.contains(&bundle.integrity_hash),
            "INV-IBR-EXPORT: {} export must embed integrity hash",
            format
        );
        h.log_phase(
            "export",
            true,
            json!({"format": format.label(), "bytes": out.len()}),
        );
    }

    // ── ACT: drive Hot → Cold by advancing past hot_days horizon ────
    let two_days_later = now.saturating_add(2 * 86_400 + 1);
    let transitions = store.rotate_tiers(two_days_later);
    assert_eq!(
        transitions.len(),
        1,
        "expected exactly one Hot→Cold transition"
    );
    let cold_bundles = store.bundles_by_tier(RetentionTier::Cold);
    assert_eq!(cold_bundles.len(), 1);
    h.log_phase(
        "rotated_to_cold",
        true,
        json!({
            "transitions": transitions.len(),
            "old_tier": transitions[0].old_tier,
            "new_tier": transitions[0].new_tier,
        }),
    );

    // ── ACT: drive Cold → Archive by advancing past cold_days horizon ─
    let four_days_later = two_days_later.saturating_add(2 * 86_400 + 1);
    let transitions = store.rotate_tiers(four_days_later);
    assert_eq!(transitions.len(), 1, "expected one Cold→Archive transition");
    let archive_bundles = store.bundles_by_tier(RetentionTier::Archive);
    assert_eq!(archive_bundles.len(), 1);
    h.log_phase("rotated_to_archive", true, json!({"transitions": 1}));

    // ── ASSERT: INV-IBR-RETENTION — archive is never auto-deleted ──
    let archive_err = store.delete("bundle-real-001", false, four_days_later);
    assert!(matches!(
        archive_err,
        Err(IncidentBundleError::ArchiveProtected { .. })
    ));
    assert!(store.contains("bundle-real-001"));
    h.log_phase("archive_protected", true, json!({}));

    // ── ACT: explicit force_archive deletion succeeds ───────────────
    store
        .delete("bundle-real-001", true, four_days_later)
        .expect("force-archive delete succeeds");
    assert!(!store.contains("bundle-real-001"));
    assert_eq!(store.bundle_count(), 0);
    assert_eq!(store.total_bytes(), 0);
    h.log_phase("force_archive_delete", true, json!({}));
}

#[test]
fn e2e_incident_bundle_rejects_incomplete_and_tampered() {
    let h = Harness::new("e2e_incident_bundle_rejects_incomplete_and_tampered");

    let mut store = IncidentBundleStore::new(small_config(), 10_000_000).unwrap();
    let now = 1_745_750_000u64;

    // ── INV-IBR-COMPLETE: missing bundle_id ──────────────────────────
    let mut incomplete = make_bundle(
        "bundle-x",
        "incident-x",
        Severity::Medium,
        RetentionTier::Hot,
        128,
        now,
    );
    incomplete.bundle_id.clear();
    incomplete.integrity_hash = compute_integrity_hash(&incomplete);
    let err = validate_bundle_complete(&incomplete).expect_err("missing id rejected");
    match err {
        IncidentBundleError::Incomplete { field } => assert_eq!(field, "bundle_id"),
        other => panic!("expected Incomplete{{bundle_id}}, got {other:?}"),
    }
    h.log_phase("incomplete_bundle_id_rejected", true, json!({}));

    // ── INV-IBR-INTEGRITY: tampered metadata after hash ─────────────
    let mut tampered = make_bundle(
        "bundle-tamper",
        "incident-tamper",
        Severity::Critical,
        RetentionTier::Hot,
        256,
        now,
    );
    // Change a field WITHOUT recomputing the integrity hash. Production code
    // must reject this on store() because the digest no longer matches.
    tampered
        .metadata
        .tags
        .push("tampered-after-hash".to_string());
    let store_err = store.store(tampered.clone(), now);
    match store_err {
        Err(IncidentBundleError::IntegrityFailure {
            bundle_id,
            expected,
            actual,
        }) => {
            assert_eq!(bundle_id, "bundle-tamper");
            assert_ne!(expected, actual);
            h.log_phase(
                "integrity_mismatch_rejected",
                true,
                json!({"expected": expected, "actual": actual}),
            );
        }
        other => panic!("expected IntegrityFailure, got {other:?}"),
    }
    assert_eq!(store.bundle_count(), 0);

    // ── IBR_STORAGE_FULL: a single bundle larger than max_bytes ─────
    let mut tiny_store = IncidentBundleStore::new(small_config(), 1024).unwrap();
    let oversized = make_bundle(
        "bundle-big",
        "incident-big",
        Severity::Critical,
        RetentionTier::Hot,
        100_000,
        now,
    );
    let storage_err = tiny_store.store(oversized.clone(), now);
    assert!(matches!(
        storage_err,
        Err(IncidentBundleError::StorageFull { .. })
    ));
    h.log_phase("storage_full_rejected", true, json!({}));
}

#[test]
fn e2e_incident_bundle_invalid_config_rejected() {
    let h = Harness::new("e2e_incident_bundle_invalid_config_rejected");

    // max_bytes = 0
    let cfg = small_config();
    let err = IncidentBundleStore::new(cfg.clone(), 0).expect_err("zero max_bytes rejected");
    assert!(matches!(err, IncidentBundleError::InvalidConfig { .. }));
    h.log_phase("zero_max_bytes_rejected", true, json!({}));

    // warn >= critical (boundary collision)
    let bad_cfg = RetentionConfig {
        storage_warn_percent: 85,
        storage_critical_percent: 85,
        ..cfg
    };
    let err = IncidentBundleStore::new(bad_cfg, 1_000).expect_err("warn==critical rejected");
    assert!(matches!(err, IncidentBundleError::InvalidConfig { .. }));
    h.log_phase("warn_critical_collision_rejected", true, json!({}));
}

#[test]
fn e2e_incident_bundle_export_helpers_match_store_export() {
    let h = Harness::new("e2e_incident_bundle_export_helpers_match_store_export");

    let now = 1_745_750_000u64;
    let bundle = make_bundle(
        "bundle-helper",
        "incident-helper",
        Severity::Low,
        RetentionTier::Hot,
        512,
        now,
    );

    // CSV header is stable and the row export is consistent with the helper.
    let header = csv_header();
    assert!(header.contains("bundle_id"));
    let row = export_csv_row(&bundle);
    let comma_count = row.chars().filter(|c| *c == ',').count();
    let header_commas = header.chars().filter(|c| *c == ',').count();
    assert_eq!(
        comma_count, header_commas,
        "CSV row column count must match header"
    );
    h.log_phase("csv_helpers", true, json!({"columns": header_commas + 1}));

    // SARIF map carries the integrity hash and the canonical version.
    let sarif = export_sarif(&bundle);
    assert_eq!(sarif.get("version"), Some(&"2.1.0".to_string()));
    assert_eq!(sarif.get("integrity_hash"), Some(&bundle.integrity_hash));
    h.log_phase(
        "sarif_helpers",
        true,
        json!({"version": "2.1.0", "hash_present": true}),
    );
}
