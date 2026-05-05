use std::io::{self, Write};
use std::sync::{Arc, Mutex};

use ed25519_dalek::SigningKey;
use frankenengine_node::observability::durability_violation::{
    CausalEvent, CausalEventType, FailedArtifact, ProofContext, ViolationContext, generate_bundle,
};
use frankenengine_node::observability::evidence_ledger::{
    DecisionKind, EvidenceEntry, EvidenceLedger, LabSpillMode, LedgerCapacity, LedgerError,
    SharedEvidenceLedger, sign_evidence_entry, verify_evidence_entry,
};
use frankenengine_node::observability::metrics::{
    MetricKind, MetricSnapshot, MetricValidationError, MetricsRegistry,
};
use frankenengine_node::observability::witness_ref::{
    WitnessKind, WitnessRef, WitnessSet, WitnessValidator,
};

const EXPECTED_MAX_CAUSAL_EVENTS: usize = 1024;
const EXPECTED_MAX_FAILED_ARTIFACTS: usize = 512;
const EXPECTED_MAX_PROOF_REFS: usize = 256;

#[derive(Clone)]
struct CaptureWriter {
    buffer: Arc<Mutex<Vec<u8>>>,
}

impl Write for CaptureWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.buffer
            .lock()
            .map_err(|_| io::Error::other("capture buffer lock poisoned"))?
            .extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn misleading_size_entry(decision_id: &str, size_bytes: usize) -> EvidenceEntry {
    EvidenceEntry {
        schema_version: "1.0".to_string(),
        entry_id: None,
        decision_id: decision_id.to_string(),
        decision_kind: DecisionKind::Admit,
        decision_time: "2026-04-22T00:00:00Z".to_string(),
        timestamp_ms: 1_776_816_000_000,
        trace_id: format!("trace-{decision_id}"),
        epoch_id: 42,
        payload: serde_json::json!({"actual": "small"}),
        size_bytes,
        signature: String::new(),
        prev_entry_hash: String::new(),
    }
}

fn witness_entry(decision_id: &str) -> EvidenceEntry {
    EvidenceEntry {
        schema_version: "observability-witness-regression-v1".to_string(),
        entry_id: None,
        decision_id: decision_id.to_string(),
        decision_kind: DecisionKind::Release,
        decision_time: "2026-04-22T00:00:00Z".to_string(),
        timestamp_ms: 1_776_816_000_000,
        trace_id: format!("trace-{decision_id}"),
        epoch_id: 43,
        payload: serde_json::Value::Null,
        size_bytes: 0,
        signature: String::new(),
        prev_entry_hash: String::new(),
    }
}

fn witness_hash(seed: u8) -> [u8; 32] {
    let mut hash = [0_u8; 32];
    hash[0] = seed;
    hash[31] = seed;
    hash
}

fn witness_set_with_locator(locator: &str) -> WitnessSet {
    let mut witnesses = WitnessSet::new();
    witnesses.add(
        WitnessRef::new(
            "WIT-STRICT-LOCATOR",
            WitnessKind::ProofArtifact,
            witness_hash(7),
        )
        .with_locator(locator),
    );
    witnesses
}

#[test]
fn durability_violation_bundle_bounds_payload_before_hashing_and_emit() {
    let ctx = ViolationContext {
        events: (0..EXPECTED_MAX_CAUSAL_EVENTS + 3)
            .map(|idx| CausalEvent {
                event_type: CausalEventType::IntegrityCheckFailed,
                timestamp_ms: u64::try_from(idx).unwrap_or(u64::MAX),
                description: format!("event-{idx}"),
                evidence_ref: Some(format!("EVD-{idx}")),
            })
            .collect(),
        artifacts: (0..EXPECTED_MAX_FAILED_ARTIFACTS + 3)
            .map(|idx| FailedArtifact {
                artifact_path: format!("artifact-{idx}"),
                expected_hash: format!("expected-{idx}"),
                actual_hash: format!("actual-{idx}"),
                failure_reason: format!("reason-{idx}"),
            })
            .collect(),
        proofs: ProofContext {
            failed_proofs: (0..EXPECTED_MAX_PROOF_REFS + 3)
                .map(|idx| format!("failed-{idx}"))
                .collect(),
            missing_proofs: (0..EXPECTED_MAX_PROOF_REFS + 3)
                .map(|idx| format!("missing-{idx}"))
                .collect(),
            passed_proofs: (0..EXPECTED_MAX_PROOF_REFS + 3)
                .map(|idx| format!("passed-{idx}"))
                .collect(),
        },
        hardening_level: "critical".to_string(),
        epoch_id: 77,
        timestamp_ms: 5000,
    };
    let mut expected_bounded = ctx.clone();
    expected_bounded.ensure_bounded();

    let oversized_bundle = generate_bundle(&ctx);
    let bounded_bundle = generate_bundle(&expected_bounded);

    assert_eq!(oversized_bundle.bundle_id, bounded_bundle.bundle_id);
    assert_eq!(oversized_bundle.event_count(), EXPECTED_MAX_CAUSAL_EVENTS);
    assert_eq!(
        oversized_bundle.artifact_count(),
        EXPECTED_MAX_FAILED_ARTIFACTS
    );
    assert_eq!(
        oversized_bundle.proof_context.failed_proofs.len(),
        EXPECTED_MAX_PROOF_REFS
    );
    assert_eq!(
        oversized_bundle.proof_context.missing_proofs.len(),
        EXPECTED_MAX_PROOF_REFS
    );
    assert_eq!(
        oversized_bundle.proof_context.passed_proofs.len(),
        EXPECTED_MAX_PROOF_REFS
    );
    assert_eq!(
        oversized_bundle.causal_event_sequence,
        expected_bounded.events
    );
    assert_eq!(
        oversized_bundle.failed_artifacts,
        expected_bounded.artifacts
    );
    assert_eq!(oversized_bundle.proof_context, expected_bounded.proofs);
}

#[test]
fn observability_ledger_uses_server_computed_size_for_snapshot_and_spill() {
    let attacker_claimed_size = 1_000_000;
    let mut ledger = EvidenceLedger::new(LedgerCapacity::new(10, 10_000));

    ledger
        .append(misleading_size_entry(
            "observability-size-lie-snapshot",
            attacker_claimed_size,
        ))
        .expect("small payload should fit despite misleading size_bytes");
    let snapshot = ledger.snapshot();
    let stored = &snapshot.entries[0].1;

    assert_ne!(stored.size_bytes, attacker_claimed_size);
    assert_eq!(
        stored.size_bytes,
        serde_json::to_string(stored).unwrap().len()
    );
    assert_eq!(snapshot.current_bytes, stored.size_bytes);

    let buffer = Arc::new(Mutex::new(Vec::new()));
    let writer = CaptureWriter {
        buffer: Arc::clone(&buffer),
    };
    let mut spill = LabSpillMode::new(LedgerCapacity::new(10, 10_000), Box::new(writer));
    spill
        .append(misleading_size_entry(
            "observability-size-lie-spill",
            attacker_claimed_size,
        ))
        .expect("small payload should spill despite misleading size_bytes");

    let captured = String::from_utf8(buffer.lock().unwrap().clone()).unwrap();
    let spilled: EvidenceEntry = serde_json::from_str(captured.trim()).unwrap();
    let spilled_snapshot = spill.snapshot();
    let retained = &spilled_snapshot.entries[0].1;

    assert_ne!(spilled.size_bytes, attacker_claimed_size);
    assert_eq!(
        spilled.size_bytes,
        serde_json::to_string(&spilled).unwrap().len()
    );
    assert_eq!(retained.size_bytes, spilled.size_bytes);
    assert_eq!(spilled_snapshot.current_bytes, spilled.size_bytes);
}

#[test]
fn file_spill_reports_real_filesystem_usage_in_status() {
    let dir = tempfile::tempdir().expect("tempdir should be created");
    let spill_path = dir.path().join("evidence-spill-status.jsonl");
    let spill = LabSpillMode::with_file(LedgerCapacity::new(10, 10_000), &spill_path)
        .expect("file-backed spill should open");

    let total = fs2::total_space(dir.path()).expect("total space should be readable");
    let available = fs2::available_space(dir.path()).expect("available space should be readable");
    assert!(total > 0, "test filesystem should report total space");
    let expected_usage = total.saturating_sub(available.min(total)) as f64 / total as f64;

    let status = spill.circuit_breaker_status();
    assert_eq!(status.monitor_path.as_deref(), Some(dir.path()));
    assert_eq!(status.disk_usage, Some(expected_usage));
    assert!((0.0..=1.0).contains(&expected_usage));
}

#[test]
fn file_spill_zero_threshold_opens_circuit_before_jsonl_write() {
    let dir = tempfile::tempdir().expect("tempdir should be created");
    let spill_path = dir.path().join("evidence-spill-threshold.jsonl");
    let mut spill = LabSpillMode::with_file(LedgerCapacity::new(10, 10_000), &spill_path)
        .expect("file-backed spill should open");

    spill
        .set_disk_threshold(0.0)
        .expect("zero threshold should be accepted");
    let id = spill
        .append(misleading_size_entry("spill-circuit-open", 0))
        .expect("memory append should still succeed");
    let status = spill.circuit_breaker_status();

    assert_eq!(id.0, 1);
    assert!(status.is_open);
    assert!(!status.emergency_halt);
    assert!(status.disk_usage.is_some());
    assert_eq!(spill.len(), 1);

    spill
        .sync_evidence_durability()
        .expect("sync should succeed without a spill write");
    drop(spill);

    let content = std::fs::read_to_string(&spill_path).expect("spill file should be readable");
    assert!(
        content.is_empty(),
        "open circuit breaker should skip JSONL spill writes"
    );
}

#[test]
fn signed_ledger_snapshot_remains_verifiable_after_size_normalization() {
    let signing_key = SigningKey::from_bytes(&[11; 32]);
    let verifying_key = signing_key.verifying_key();
    let attacker_claimed_size = 1_000_000;
    let mut entry = misleading_size_entry("signed-size-normalization", attacker_claimed_size);
    entry.payload = serde_json::json!({
        "large_field": "x".repeat(512),
        "nested": {"value": 42}
    });
    sign_evidence_entry(&mut entry, &signing_key);
    let signature = entry.signature.clone();

    verify_evidence_entry(&entry, &verifying_key)
        .expect("freshly signed entry should verify before append");

    let mut ledger =
        EvidenceLedger::with_verifying_key(LedgerCapacity::new(10, 10_000), verifying_key);
    ledger
        .append(entry)
        .expect("valid signed entry should append");

    let snapshot = ledger.snapshot();
    let stored = &snapshot.entries[0].1;
    assert_ne!(stored.size_bytes, attacker_claimed_size);
    assert_eq!(stored.signature, signature);
    verify_evidence_entry(stored, &signing_key.verifying_key())
        .expect("ledger-normalized stored entry must remain signature-verifiable");
}

#[test]
fn signed_ledger_rejects_replay_after_retained_entry_eviction() {
    let signing_key = SigningKey::from_bytes(&[22; 32]);
    let verifying_key = signing_key.verifying_key();
    let mut ledger =
        EvidenceLedger::with_verifying_key(LedgerCapacity::new(2, 100_000), verifying_key);

    let mut first = misleading_size_entry("signed-replay-evicted-1", 0);
    first.timestamp_ms = 1_776_816_000_001;
    sign_evidence_entry(&mut first, &signing_key);

    let mut second = misleading_size_entry("signed-replay-evicted-2", 0);
    second.timestamp_ms = 1_776_816_000_002;
    sign_evidence_entry(&mut second, &signing_key);

    let mut third = misleading_size_entry("signed-replay-evicted-3", 0);
    third.timestamp_ms = 1_776_816_000_003;
    sign_evidence_entry(&mut third, &signing_key);

    ledger
        .append(first.clone())
        .expect("first signed append should succeed");
    ledger
        .append(second)
        .expect("second signed append should succeed");
    ledger
        .append(third)
        .expect("third signed append should evict the first retained entry");

    assert_eq!(ledger.len(), 2);
    assert_eq!(ledger.total_evicted(), 1);

    let replay = ledger.append(first);
    assert!(
        matches!(replay, Err(LedgerError::ReplayAttack { .. })),
        "replay prevention must outlive retained-entry eviction"
    );
}

#[test]
fn shared_observability_ledger_serves_parallel_read_snapshots() {
    let ledger = Arc::new(SharedEvidenceLedger::new(LedgerCapacity::new(10, 100_000)));
    for idx in 0..3 {
        ledger
            .append(misleading_size_entry(
                &format!("shared-ledger-rwlock-{idx}"),
                0,
            ))
            .expect("seed append should succeed");
    }

    let mut readers = Vec::new();
    for _ in 0..8 {
        let reader = Arc::clone(&ledger);
        readers.push(std::thread::spawn(move || {
            for _ in 0..25 {
                assert_eq!(reader.len(), 3);
                assert_eq!(reader.metrics().retained_entries, 3);
                assert_eq!(reader.snapshot().entries.len(), 3);
            }
        }));
    }

    for reader in readers {
        reader.join().expect("parallel ledger reader should finish");
    }
}

#[test]
fn shared_observability_ledger_len_and_is_empty_follow_retained_count() {
    let ledger = SharedEvidenceLedger::new(LedgerCapacity::new(2, 100_000));
    assert_eq!(ledger.len(), 0);
    assert!(ledger.is_empty());

    for idx in 0..3 {
        ledger
            .append(misleading_size_entry(&format!("shared-len-{idx}"), 0))
            .expect("append should succeed");
    }

    assert_eq!(ledger.len(), 2);
    assert!(!ledger.is_empty());
    assert_eq!(ledger.metrics().retained_entries, 2);
    assert_eq!(ledger.snapshot().entries.len(), 2);
}

#[test]
fn witness_strict_locator_accepts_safe_relative_paths() {
    let safe_locators = [
        "replay-001.jsonl",
        "bundles/replay-001.jsonl",
        "tenant_01/witness.proof",
        "evidence/bundle_2026-04-22.jsonl",
    ];

    for locator in safe_locators {
        let mut validator = WitnessValidator::strict();
        let entry = witness_entry("strict-witness-safe-locator");
        let witnesses = witness_set_with_locator(locator);

        let result = validator.validate(&entry, &witnesses);

        assert!(
            result.is_ok(),
            "safe locator should pass strict mode: {locator}: {result:?}"
        );
    }
}

#[test]
fn witness_strict_locator_rejects_traversal_and_network_locators() {
    let mut attack_locators = vec![
        "../secret.jsonl".to_string(),
        "bundles/../secret.jsonl".to_string(),
        "/tmp/replay.jsonl".to_string(),
        "//host/share/replay.jsonl".to_string(),
        "bundles//replay.jsonl".to_string(),
        "http://evil.example/replay.jsonl".to_string(),
        "https://evil.example/replay.jsonl".to_string(),
        "file:///tmp/replay.jsonl".to_string(),
        "@host/replay.jsonl".to_string(),
        "host@evil/replay.jsonl".to_string(),
        "C:/Windows/System32/config/SAM".to_string(),
        "bundles\\replay.jsonl".to_string(),
        "bundles/%2e%2e/passwd".to_string(),
        "bundles/replay%00.jsonl".to_string(),
        "bundles/replay.jsonl\0".to_string(),
        "bundles/replay.jsonl;rm".to_string(),
        "bundles/replay.jsonl?query".to_string(),
        "bundles/replay.jsonl#fragment".to_string(),
    ];
    attack_locators.push("a".repeat(513));

    for locator in attack_locators {
        let mut validator = WitnessValidator::strict();
        let entry = witness_entry("strict-witness-unsafe-locator");
        let witnesses = witness_set_with_locator(&locator);

        assert!(
            validator.validate(&entry, &witnesses).is_err(),
            "unsafe locator should fail closed in strict mode: {locator:?}"
        );
    }
}

#[test]
fn observability_metrics_registry_renders_operator_prometheus_snapshot() {
    let mut registry = MetricsRegistry::new();

    registry
        .record_gauge(
            "franken_node_health_pass",
            "Whether the latest operator health check passed.",
            1.0,
            &[("surface", "operator")],
        )
        .expect("health pass metric should be valid");
    registry
        .record_counter(
            "franken_node_fleet_active_quarantines",
            "Active fleet quarantine count.",
            2.0,
            &[("zone", "prod\"east\\a\nb")],
        )
        .expect("fleet quarantine metric should be valid");

    let rendered = registry.render_prometheus();

    assert!(
        rendered.contains(
            "# HELP franken_node_fleet_active_quarantines Active fleet quarantine count."
        )
    );
    assert!(rendered.contains("# TYPE franken_node_fleet_active_quarantines counter"));
    assert!(
        rendered
            .contains("franken_node_fleet_active_quarantines{zone=\"prod\\\"east\\\\a\\nb\"} 2")
    );
    assert!(rendered.contains("# TYPE franken_node_health_pass gauge"));
    assert!(rendered.contains("franken_node_health_pass{surface=\"operator\"} 1"));
}

#[test]
fn observability_metrics_registry_rejects_invalid_operator_metrics() {
    let invalid_name = MetricSnapshot::new("bad name", "help", MetricKind::Gauge, 1.0, vec![])
        .expect_err("metric names reject whitespace");
    assert!(matches!(
        invalid_name,
        MetricValidationError::InvalidMetricName { .. }
    ));

    let duplicate_label = MetricSnapshot::new(
        "franken_node_health_pass",
        "help",
        MetricKind::Gauge,
        1.0,
        vec![
            ("surface".to_owned(), "operator".to_owned()),
            ("surface".to_owned(), "fleet".to_owned()),
        ],
    )
    .expect_err("metric labels must be unique");
    assert!(matches!(
        duplicate_label,
        MetricValidationError::DuplicateLabelName { .. }
    ));

    let non_finite = MetricSnapshot::new(
        "franken_node_health_pass",
        "help",
        MetricKind::Gauge,
        f64::NAN,
        vec![],
    )
    .expect_err("metric values must be finite");
    assert!(matches!(
        non_finite,
        MetricValidationError::NonFiniteValue { .. }
    ));
}
