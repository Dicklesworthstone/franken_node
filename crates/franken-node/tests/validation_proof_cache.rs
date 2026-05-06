use chrono::{DateTime, TimeZone, Utc};
use frankenengine_node::ops::validation_broker::{
    CommandSpec, DigestRef, EnvironmentPolicy, FallbackPolicy, InputDigest, InputSet, OutputPolicy,
    RECEIPT_SCHEMA_VERSION, RchMode, RchReceipt, ReceiptArtifacts, ReceiptClassifications,
    ReceiptRequestRef, ReceiptTrust, SourceOnlyReason, TargetDirPolicy, TimeoutClass,
    ValidationBrokerRequest, ValidationErrorClass, ValidationExit, ValidationExitKind,
    ValidationPriority, ValidationReceipt, ValidationTiming,
};
use frankenengine_node::ops::validation_closeout::{
    ValidationCloseoutOptions, ValidationCloseoutStatus, build_validation_closeout_report,
    render_validation_closeout_json,
};
use frankenengine_node::ops::validation_proof_cache::{
    DirtyStatePolicy, GC_REPORT_SCHEMA_VERSION, ValidationProofCacheDecisionKind,
    ValidationProofCacheKey, ValidationProofCacheLookup, ValidationProofCacheQuotaPolicy,
    ValidationProofCacheRequiredAction, ValidationProofCacheScope, ValidationProofCacheStore,
    error_codes, render_validation_proof_cache_decision_human,
    render_validation_proof_cache_decision_json, validation_proof_cache_rejection_decision,
};
use frankenengine_node::ops::validation_readiness::{
    TrackedValidationBead, ValidationBeadState, ValidationReadinessInput,
    ValidationReadinessStatus, build_validation_readiness_report,
    render_validation_readiness_human,
};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Barrier, Mutex};
use std::thread;
use tempfile::TempDir;

const FIXTURE_JSON: &str = include_str!(
    "../../../artifacts/validation_broker/proof_cache/validation_proof_cache_fixtures.v1.json"
);
const E2E_MATRIX_JSON: &str = include_str!(
    "../../../artifacts/validation_broker/proof_cache/validation_proof_cache_e2e_matrix.v1.json"
);
const REQUIRED_LOG_FIELDS: [&str; 7] = [
    "trace_id",
    "cache_key",
    "decision",
    "reason_code",
    "receipt_path",
    "producer_agent",
    "bead_id",
];

fn ts(second: u32) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 5, 5, 12, 0, second)
        .single()
        .expect("valid timestamp")
}

fn command() -> CommandSpec {
    CommandSpec {
        program: "cargo".to_string(),
        argv: vec![
            "+nightly-2026-02-19".to_string(),
            "test".to_string(),
            "-p".to_string(),
            "frankenengine-node".to_string(),
            "--test".to_string(),
            "validation_proof_cache".to_string(),
        ],
        cwd: "/data/projects/franken_node".to_string(),
        environment_policy_id: "validation-broker/env-policy/v1".to_string(),
        target_dir_policy_id: "validation-broker/target-dir/off-repo/v1".to_string(),
    }
}

fn inputs() -> InputSet {
    InputSet {
        git_commit: "4c67da23".to_string(),
        dirty_worktree: false,
        changed_paths: vec!["crates/franken-node/src/ops/validation_proof_cache.rs".to_string()],
        content_digests: vec![InputDigest::new(
            "crates/franken-node/src/ops/validation_proof_cache.rs",
            b"validation-proof-cache-fixture",
            "fixture",
        )],
        feature_flags: vec!["external-commands".to_string(), "http-client".to_string()],
    }
}

fn request() -> ValidationBrokerRequest {
    ValidationBrokerRequest::new(
        "vbreq-bd-8j9au-1",
        "bd-8j9au",
        "bd-8j9au",
        "LavenderElk",
        ts(0),
        ValidationPriority::High,
        command(),
        inputs(),
        OutputPolicy {
            stdout_path: "artifacts/validation_broker/bd-8j9au/stdout.txt".to_string(),
            stderr_path: "artifacts/validation_broker/bd-8j9au/stderr.txt".to_string(),
            summary_path: "artifacts/validation_broker/bd-8j9au/summary.md".to_string(),
            receipt_path: "receipts/bd-8j9au.json".to_string(),
            retention: "until-closeout".to_string(),
        },
        FallbackPolicy {
            source_only_allowed: false,
            allowed_reasons: vec![SourceOnlyReason::DocsOnly],
        },
    )
}

fn receipt_with_expiry(freshness_expires_at: DateTime<Utc>) -> ValidationReceipt {
    let request = request();
    let command = request.command.clone();
    let command_digest = command.digest();
    ValidationReceipt {
        schema_version: RECEIPT_SCHEMA_VERSION.to_string(),
        receipt_id: "vbrcpt-bd-8j9au-1".to_string(),
        request_id: request.request_id.clone(),
        bead_id: request.bead_id.clone(),
        thread_id: request.thread_id.clone(),
        request_ref: ReceiptRequestRef {
            request_id: request.request_id.clone(),
            bead_id: request.bead_id.clone(),
            thread_id: request.thread_id.clone(),
            dedupe_key: DigestRef {
                algorithm: request.dedupe_key.algorithm.clone(),
                hex: request.dedupe_key.hex.clone(),
            },
            cross_thread_waiver: None,
        },
        command,
        command_digest,
        environment_policy: EnvironmentPolicy {
            policy_id: "validation-broker/env-policy/v1".to_string(),
            allowed_env: vec!["CARGO_TARGET_DIR".to_string()],
            redacted_env: Vec::new(),
            remote_required: true,
            network_policy: "rch-only".to_string(),
        },
        target_dir_policy: TargetDirPolicy {
            policy_id: "validation-broker/target-dir/off-repo/v1".to_string(),
            kind: "off-repo".to_string(),
            path: "/data/tmp/franken_node_validation_proof_cache".to_string(),
            path_digest: DigestRef::sha256(b"/data/tmp/franken_node_validation_proof_cache"),
            cleanup: "caller-owned".to_string(),
        },
        input_digests: request.inputs.content_digests.clone(),
        rch: RchReceipt {
            mode: RchMode::Remote,
            worker_id: Some("ts-test".to_string()),
            require_remote: true,
            capability_observation_id: None,
            worker_pool: "test".to_string(),
        },
        timing: ValidationTiming {
            started_at: ts(1),
            finished_at: ts(2),
            duration_ms: 1_000,
            freshness_expires_at,
        },
        exit: ValidationExit {
            kind: ValidationExitKind::Success,
            code: Some(0),
            signal: None,
            timeout_class: TimeoutClass::None,
            error_class: ValidationErrorClass::None,
            retryable: false,
        },
        artifacts: ReceiptArtifacts {
            stdout_path: "artifacts/validation_broker/bd-8j9au/stdout.txt".to_string(),
            stderr_path: "artifacts/validation_broker/bd-8j9au/stderr.txt".to_string(),
            summary_path: "artifacts/validation_broker/bd-8j9au/summary.md".to_string(),
            receipt_path: "receipts/bd-8j9au.json".to_string(),
            stdout_digest: DigestRef::sha256(b"stdout"),
            stderr_digest: DigestRef::sha256(b"stderr"),
        },
        trust: ReceiptTrust {
            generated_by: "validation-broker".to_string(),
            agent_name: "LavenderElk".to_string(),
            git_commit: "4c67da23".to_string(),
            dirty_worktree: false,
            freshness: "fresh".to_string(),
            signature_status: "unsigned-test".to_string(),
        },
        classifications: ReceiptClassifications {
            source_only_fallback: false,
            source_only_reason: None,
            doctor_readiness: "green".to_string(),
            ci_consumable: true,
        },
    }
}

fn fresh_receipt() -> ValidationReceipt {
    receipt_with_expiry(ts(50))
}

fn scope() -> ValidationProofCacheScope {
    ValidationProofCacheScope {
        dirty_state_policy: DirtyStatePolicy::CleanRequired,
        cargo_toolchain: "nightly-2026-02-19".to_string(),
        package: "frankenengine-node".to_string(),
        test_target: "validation_proof_cache".to_string(),
    }
}

fn write_receipt(root: &Path, receipt: &ValidationReceipt) -> (String, Vec<u8>) {
    let relative_path = format!("receipts/{}.json", receipt.bead_id);
    let path = root.join(&relative_path);
    fs::create_dir_all(path.parent().expect("receipt parent")).expect("receipt parent");
    let bytes = serde_json::to_vec_pretty(receipt).expect("receipt json");
    fs::write(&path, &bytes).expect("receipt written");
    (relative_path, bytes)
}

fn request_for(bead_id: &str, seed: &str) -> ValidationBrokerRequest {
    let input_path = format!("crates/franken-node/src/ops/validation_proof_cache_{seed}.rs");
    let inputs = InputSet {
        git_commit: format!("commit-{seed}"),
        dirty_worktree: false,
        changed_paths: vec![input_path.clone()],
        content_digests: vec![InputDigest::new(input_path, seed.as_bytes(), "fixture")],
        feature_flags: vec!["external-commands".to_string(), "http-client".to_string()],
    };
    ValidationBrokerRequest::new(
        format!("vbreq-{bead_id}-{seed}"),
        bead_id,
        bead_id,
        "LavenderElk",
        ts(0),
        ValidationPriority::High,
        command(),
        inputs,
        OutputPolicy {
            stdout_path: format!("artifacts/validation_broker/{bead_id}/stdout.txt"),
            stderr_path: format!("artifacts/validation_broker/{bead_id}/stderr.txt"),
            summary_path: format!("artifacts/validation_broker/{bead_id}/summary.md"),
            receipt_path: format!("receipts/{bead_id}.json"),
            retention: "until-closeout".to_string(),
        },
        FallbackPolicy {
            source_only_allowed: false,
            allowed_reasons: vec![SourceOnlyReason::DocsOnly],
        },
    )
}

fn receipt_for(
    bead_id: &str,
    seed: &str,
    freshness_expires_at: DateTime<Utc>,
) -> ValidationReceipt {
    let request = request_for(bead_id, seed);
    let mut receipt = receipt_with_expiry(freshness_expires_at);
    receipt.receipt_id = format!("vbrcpt-{bead_id}-{seed}");
    receipt.request_id = request.request_id.clone();
    receipt.bead_id = request.bead_id.clone();
    receipt.thread_id = request.thread_id.clone();
    receipt.request_ref = ReceiptRequestRef {
        request_id: request.request_id.clone(),
        bead_id: request.bead_id.clone(),
        thread_id: request.thread_id.clone(),
        dedupe_key: DigestRef {
            algorithm: request.dedupe_key.algorithm.clone(),
            hex: request.dedupe_key.hex.clone(),
        },
        cross_thread_waiver: None,
    };
    receipt.input_digests = request.inputs.content_digests.clone();
    receipt.artifacts.stdout_path = request.output_policy.stdout_path.clone();
    receipt.artifacts.stderr_path = request.output_policy.stderr_path.clone();
    receipt.artifacts.summary_path = request.output_policy.summary_path.clone();
    receipt.artifacts.receipt_path = request.output_policy.receipt_path.clone();
    receipt.trust.git_commit = request.inputs.git_commit.clone();
    receipt
}

fn insert_entry_for(
    store: &ValidationProofCacheStore,
    root: &Path,
    bead_id: &str,
    seed: &str,
    created_at: DateTime<Utc>,
    freshness_expires_at: DateTime<Utc>,
    mutate_entry: impl FnOnce(
        &mut frankenengine_node::ops::validation_proof_cache::ValidationProofCacheEntry,
    ),
) -> frankenengine_node::ops::validation_proof_cache::ValidationProofCacheEntry {
    let request = request_for(bead_id, seed);
    let receipt = receipt_for(bead_id, seed, freshness_expires_at);
    let (receipt_path, receipt_bytes) = write_receipt(root, &receipt);
    let key = ValidationProofCacheKey::from_request_and_receipt(&request, &receipt, scope())
        .expect("key");
    let mut entry = store
        .build_entry(
            key,
            receipt_path,
            &receipt,
            &receipt_bytes,
            "LavenderElk",
            created_at,
        )
        .expect("entry");
    entry.storage.bytes = 10;
    mutate_entry(&mut entry);
    store.put_entry(&entry).expect("entry persisted");
    entry
}

fn quota_policy() -> ValidationProofCacheQuotaPolicy {
    ValidationProofCacheQuotaPolicy {
        max_total_bytes: 1_000,
        max_entries: 10,
        max_age_seconds: 100,
        min_available_bytes: 100,
        active_beads: Vec::new(),
        expected_git_commit: None,
        expected_input_digests: Vec::new(),
        expected_dirty_state_policy: Some(DirtyStatePolicy::CleanRequired),
    }
}

fn populated_store(
    mutate_entry: impl FnOnce(
        &mut frankenengine_node::ops::validation_proof_cache::ValidationProofCacheEntry,
    ),
) -> (
    TempDir,
    ValidationProofCacheStore,
    ValidationProofCacheKey,
    frankenengine_node::ops::validation_proof_cache::ValidationProofCacheEntry,
) {
    let dir = TempDir::new().expect("tempdir");
    let store = ValidationProofCacheStore::new(dir.path());
    let request = request();
    let receipt = fresh_receipt();
    let (receipt_path, receipt_bytes) = write_receipt(dir.path(), &receipt);
    let key = ValidationProofCacheKey::from_request_and_receipt(&request, &receipt, scope())
        .expect("key");
    let mut entry = store
        .build_entry(
            key.clone(),
            receipt_path,
            &receipt,
            &receipt_bytes,
            "LavenderElk",
            ts(3),
        )
        .expect("entry");
    mutate_entry(&mut entry);
    store.put_entry(&entry).expect("entry persisted");
    (dir, store, key, entry)
}

fn count_entry_files(root: &Path) -> usize {
    fn visit(path: &Path, count: &mut usize) {
        for entry in fs::read_dir(path).expect("read proof-cache directory") {
            let entry = entry.expect("directory entry");
            let file_type = entry.file_type().expect("entry file type");
            if file_type.is_dir() {
                visit(&entry.path(), count);
            } else if file_type.is_file()
                && entry
                    .path()
                    .extension()
                    .and_then(|extension| extension.to_str())
                    .is_some_and(|extension| extension == "json")
            {
                *count = count.saturating_add(1);
            }
        }
    }

    let entries = root.join("entries");
    if !entries.exists() {
        return 0;
    }
    let mut count = 0;
    visit(&entries, &mut count);
    count
}

fn proof_cache_event(
    decision: &frankenengine_node::ops::validation_proof_cache::ValidationProofCacheDecision,
    producer_agent: &str,
    bead_id: &str,
    receipt_path: &str,
) -> serde_json::Value {
    serde_json::json!({
        "trace_id": decision.trace_id.as_str(),
        "cache_key": decision.cache_key.hex.as_str(),
        "decision": decision.decision.as_str(),
        "reason_code": decision.reason_code.as_str(),
        "receipt_path": receipt_path,
        "producer_agent": producer_agent,
        "bead_id": bead_id,
    })
}

fn append_log_event(path: &Path, event: &serde_json::Value) {
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .expect("event log open");
    writeln!(
        file,
        "{}",
        serde_json::to_string(event).expect("event log json")
    )
    .expect("event log write");
}

fn read_log_events(path: &Path) -> Vec<serde_json::Value> {
    fs::read_to_string(path)
        .expect("event log read")
        .lines()
        .map(|line| serde_json::from_str(line).expect("event log line"))
        .collect()
}

fn assert_log_event_fields(event: &serde_json::Value) {
    for field in REQUIRED_LOG_FIELDS {
        assert!(
            event
                .get(field)
                .and_then(serde_json::Value::as_str)
                .is_some_and(|value| !value.trim().is_empty()),
            "missing structured log field {field}: {event}"
        );
    }
}

#[test]
fn mock_free_e2e_concurrent_requests_converge_and_changed_digest_misses()
-> Result<(), Box<dyn std::error::Error>> {
    let dir = TempDir::new()?;
    let root = Arc::new(dir.path().to_path_buf());
    let receipt = receipt_for("bd-gcprh-equivalent", "equivalent", ts(50));
    let (receipt_path, receipt_bytes) = write_receipt(dir.path(), &receipt);
    let thread_count = 8;
    let barrier = Arc::new(Barrier::new(thread_count));
    let results = Arc::new(Mutex::new(Vec::<String>::new()));

    thread::scope(|thread_scope| {
        for _ in 0..thread_count {
            let root = Arc::clone(&root);
            let receipt = receipt.clone();
            let receipt_path = receipt_path.clone();
            let receipt_bytes = receipt_bytes.clone();
            let barrier = Arc::clone(&barrier);
            let results = Arc::clone(&results);

            thread_scope.spawn(move || {
                let store = ValidationProofCacheStore::new(root.as_path());
                let request = request_for("bd-gcprh-equivalent", "equivalent");
                let key =
                    ValidationProofCacheKey::from_request_and_receipt(&request, &receipt, scope())
                        .expect("concurrent key");
                let entry = store
                    .build_entry(
                        key,
                        receipt_path,
                        &receipt,
                        &receipt_bytes,
                        "PearlLeopard",
                        ts(3),
                    )
                    .expect("concurrent entry");
                barrier.wait();

                let outcome = store
                    .put_entry(&entry)
                    .map(|_| "stored".to_string())
                    .unwrap_or_else(|error| error.code().to_string());
                results.lock().expect("results lock").push(outcome);
            });
        }
    });

    let results = Arc::try_unwrap(results)
        .expect("results refs released")
        .into_inner()
        .expect("results lock released");
    assert_eq!(
        results
            .iter()
            .filter(|outcome| outcome.as_str() == "stored")
            .count(),
        1
    );
    assert_eq!(
        results
            .iter()
            .filter(|outcome| outcome.as_str() == error_codes::ERR_VPC_DUPLICATE_ENTRY)
            .count(),
        thread_count - 1
    );
    assert_eq!(count_entry_files(dir.path()), 1);

    let store = ValidationProofCacheStore::new(dir.path());
    let request = request_for("bd-gcprh-equivalent", "equivalent");
    let key = ValidationProofCacheKey::from_request_and_receipt(&request, &receipt, scope())?;
    let log_path: PathBuf = dir.path().join("proof-cache-events.ndjson");
    let lookup = store.lookup(&key, ts(4))?;
    let hit = match lookup {
        ValidationProofCacheLookup::Hit(hit) => hit,
        ValidationProofCacheLookup::Miss(decision) => {
            return Err(format!(
                "equivalent request should reuse one trusted cache entry, got {}",
                decision.reason_code
            )
            .into());
        }
    };
    let hit_event = proof_cache_event(
        &hit.decision,
        "PearlLeopard",
        &receipt.bead_id,
        &hit.entry.receipt_ref.path,
    );
    append_log_event(&log_path, &hit_event);

    let changed_request = request_for("bd-gcprh-changed", "changed");
    let changed_receipt = receipt_for("bd-gcprh-changed", "changed", ts(50));
    let (changed_receipt_path, changed_receipt_bytes) = write_receipt(dir.path(), &changed_receipt);
    let changed_key = ValidationProofCacheKey::from_request_and_receipt(
        &changed_request,
        &changed_receipt,
        scope(),
    )?;
    assert_ne!(key.hex, changed_key.hex);

    let changed_lookup = store.lookup(&changed_key, ts(4))?;
    let miss = match changed_lookup {
        ValidationProofCacheLookup::Miss(miss) => miss,
        ValidationProofCacheLookup::Hit(hit) => {
            return Err(format!(
                "changed input digest must miss before the new proof is written, reused {}",
                hit.entry.entry_id
            )
            .into());
        }
    };
    assert_eq!(miss.decision, ValidationProofCacheDecisionKind::Miss);
    assert_eq!(miss.reason_code, "VPC_MISS_NO_ENTRY");
    let miss_event = proof_cache_event(
        &miss,
        "PearlLeopard",
        &changed_receipt.bead_id,
        &changed_receipt_path,
    );
    append_log_event(&log_path, &miss_event);

    let changed_entry = store.build_entry(
        changed_key,
        changed_receipt_path,
        &changed_receipt,
        &changed_receipt_bytes,
        "PearlLeopard",
        ts(5),
    )?;
    store.put_entry(&changed_entry)?;
    assert_eq!(count_entry_files(dir.path()), 2);

    let events = read_log_events(&log_path);
    assert_eq!(events.len(), 2);
    for event in &events {
        assert_log_event_fields(event);
    }
    assert!(events.iter().any(|event| matches!(
        event.get("decision").and_then(serde_json::Value::as_str),
        Some("hit")
    )));
    assert!(events.iter().any(|event| matches!(
        event.get("decision").and_then(serde_json::Value::as_str),
        Some("miss")
    )));
    Ok(())
}

#[test]
fn stale_receipt_is_reported_in_readiness_and_closeout_outputs()
-> Result<(), Box<dyn std::error::Error>> {
    let stale_receipt = receipt_for("bd-gcprh-stale", "stale", ts(3));
    let readiness_input = ValidationReadinessInput {
        tracked_beads: vec![TrackedValidationBead::new(
            &stale_receipt.bead_id,
            ValidationBeadState::Closed,
        )],
        receipts: vec![stale_receipt.clone()],
        ..ValidationReadinessInput::default()
    };
    let readiness_report =
        build_validation_readiness_report(&readiness_input, "bd-gcprh-readiness", ts(4));
    let readiness_human = render_validation_readiness_human(&readiness_report);

    assert_eq!(
        readiness_report.overall_status,
        ValidationReadinessStatus::Fail
    );
    assert_eq!(readiness_report.summary.stale_receipt_count, 1);
    assert!(readiness_human.contains("stale_receipts=1"));
    assert!(readiness_human.contains("Receipt freshness failed"));

    let closeout_options =
        ValidationCloseoutOptions::new(&stale_receipt.bead_id, "bd-gcprh-closeout");
    let closeout_report =
        build_validation_closeout_report(&stale_receipt, &closeout_options, ts(4))?;
    let closeout_json = render_validation_closeout_json(&closeout_report)?;

    assert_eq!(closeout_report.status, ValidationCloseoutStatus::Stale);
    assert!(
        closeout_report
            .warnings
            .iter()
            .any(|warning| warning.contains("stale validation receipt is not closeout evidence"))
    );
    assert!(closeout_json.contains("stale validation receipt is not closeout evidence"));
    Ok(())
}

#[test]
fn cache_lookup_returns_hit_only_with_valid_receipt() {
    let (_dir, store, key, _entry) = populated_store(|_| {});

    let lookup = store.lookup(&key, ts(4)).expect("lookup");

    match lookup {
        ValidationProofCacheLookup::Hit(hit) => {
            assert_eq!(hit.receipt.receipt_id, "vbrcpt-bd-8j9au-1");
            assert_eq!(hit.decision.decision, ValidationProofCacheDecisionKind::Hit);
            assert_eq!(
                hit.decision.required_action,
                ValidationProofCacheRequiredAction::ReuseReceipt
            );
        }
        ValidationProofCacheLookup::Miss(decision) => {
            assert_eq!(decision.decision, ValidationProofCacheDecisionKind::Hit);
        }
    }
}

#[test]
fn cache_lookup_misses_without_entry() {
    let dir = TempDir::new().expect("tempdir");
    let store = ValidationProofCacheStore::new(dir.path());
    let request = request();
    let receipt = fresh_receipt();
    let key = ValidationProofCacheKey::from_request_and_receipt(&request, &receipt, scope())
        .expect("key");

    let lookup = store.lookup(&key, ts(4)).expect("lookup");

    match lookup {
        ValidationProofCacheLookup::Miss(decision) => {
            assert_eq!(decision.decision, ValidationProofCacheDecisionKind::Miss);
            assert!(decision.diagnostics.fail_closed);
        }
        ValidationProofCacheLookup::Hit(hit) => {
            assert_eq!(
                hit.decision.decision,
                ValidationProofCacheDecisionKind::Miss
            );
        }
    }
}

#[test]
fn decision_renderers_surface_hit_and_miss_diagnostics() {
    let (_dir, store, key, _entry) = populated_store(|_| {});
    let lookup = store.lookup(&key, ts(4)).expect("hit lookup");
    assert!(matches!(lookup, ValidationProofCacheLookup::Hit(_)));
    let hit = if let ValidationProofCacheLookup::Hit(hit) = lookup {
        hit
    } else {
        return;
    };
    let hit_json =
        render_validation_proof_cache_decision_json(&hit.decision).expect("hit decision json");
    let hit_human = render_validation_proof_cache_decision_human(&hit.decision);
    let reuse = hit
        .decision
        .to_broker_reuse_evidence()
        .expect("hit converts to broker reuse evidence");

    assert!(hit_json.contains("\"decision\": \"hit\""));
    assert!(hit_human.contains("decision=hit"));
    assert!(hit_human.contains("action=reuse_receipt"));
    assert_eq!(reuse.cache_key_hex, key.hex);
    assert_eq!(reuse.receipt_path, "receipts/bd-8j9au.json");

    let dir = TempDir::new().expect("tempdir");
    let empty_store = ValidationProofCacheStore::new(dir.path());
    let lookup = empty_store.lookup(&key, ts(4)).expect("miss lookup");
    assert!(matches!(lookup, ValidationProofCacheLookup::Miss(_)));
    let miss = if let ValidationProofCacheLookup::Miss(decision) = lookup {
        decision
    } else {
        return;
    };
    let miss_json = render_validation_proof_cache_decision_json(&miss).expect("miss decision json");
    let miss_human = render_validation_proof_cache_decision_human(&miss);

    assert!(miss_json.contains("\"decision\": \"miss\""));
    assert!(miss_human.contains("decision=miss"));
    assert!(miss_human.contains("fail_closed=true"));
    assert!(miss.to_broker_reuse_evidence().is_none());
}

#[test]
fn stale_receipt_fails_closed() {
    let dir = TempDir::new().expect("tempdir");
    let store = ValidationProofCacheStore::new(dir.path());
    let request = request();
    let receipt = receipt_with_expiry(ts(3));
    let (receipt_path, receipt_bytes) = write_receipt(dir.path(), &receipt);
    let key = ValidationProofCacheKey::from_request_and_receipt(&request, &receipt, scope())
        .expect("key");
    let entry = store
        .build_entry(
            key.clone(),
            receipt_path,
            &receipt,
            &receipt_bytes,
            "LavenderElk",
            ts(2),
        )
        .expect("entry");
    store.put_entry(&entry).expect("entry persisted");

    let err = store.lookup(&key, ts(4)).expect_err("stale entry rejects");

    assert_eq!(err.code(), error_codes::ERR_VPC_STALE_ENTRY);
    let decision =
        validation_proof_cache_rejection_decision(key, ts(4), "entries/stale.json", &err);
    let human = render_validation_proof_cache_decision_human(&decision);
    let json = render_validation_proof_cache_decision_json(&decision).expect("stale json");

    assert_eq!(decision.decision, ValidationProofCacheDecisionKind::Stale);
    assert_eq!(
        decision.required_action,
        ValidationProofCacheRequiredAction::RefreshValidation
    );
    assert!(human.contains("decision=stale"));
    assert!(json.contains("\"reason_code\": \"VPC_REJECT_STALE\""));
}

#[test]
fn receipt_digest_mismatch_fails_closed() {
    let (dir, store, key, _entry) = populated_store(|_| {});
    let receipt_path = dir.path().join("receipts/bd-8j9au.json");
    fs::write(
        receipt_path,
        serde_json::to_vec(&fresh_receipt()).expect("compact receipt json"),
    )
    .expect("receipt rewritten");

    let err = store
        .lookup(&key, ts(4))
        .expect_err("digest mismatch rejects");

    assert_eq!(err.code(), error_codes::ERR_VPC_RECEIPT_DIGEST_MISMATCH);
}

#[test]
fn command_digest_mismatch_fails_closed() {
    let (_dir, store, key, _entry) = populated_store(|entry| {
        entry.receipt_ref.command_digest.hex = "0".repeat(64);
    });

    let err = store
        .lookup(&key, ts(4))
        .expect_err("command mismatch rejects");

    assert_eq!(err.code(), error_codes::ERR_VPC_COMMAND_DIGEST_MISMATCH);
}

#[test]
fn input_digest_mismatch_fails_closed() {
    let (_dir, store, key, _entry) = populated_store(|entry| {
        let input_digest = entry
            .receipt_ref
            .input_digests
            .first_mut()
            .expect("entry has input digests");
        input_digest.hex = "1".repeat(64);
    });

    let err = store
        .lookup(&key, ts(4))
        .expect_err("input mismatch rejects");

    assert_eq!(err.code(), error_codes::ERR_VPC_INPUT_DIGEST_MISMATCH);
}

#[test]
fn policy_mismatch_fails_closed() {
    let (_dir, store, key, _entry) = populated_store(|entry| {
        entry.trust.target_dir_policy_id = "validation-broker/target-dir/repo-local/v1".to_string();
    });

    let err = store
        .lookup(&key, ts(4))
        .expect_err("policy mismatch rejects");

    assert_eq!(err.code(), error_codes::ERR_VPC_POLICY_MISMATCH);
}

#[test]
fn corrupted_entry_fails_closed() {
    let (_dir, store, key, _entry) = populated_store(|entry| {
        entry.invalidation.active = true;
        entry.invalidation.corrupted = true;
        entry.invalidation.reason = Some("fixture corruption".to_string());
    });

    let err = store
        .lookup(&key, ts(4))
        .expect_err("corrupted entry rejects");

    assert_eq!(err.code(), error_codes::ERR_VPC_CORRUPTED_ENTRY);
    let decision =
        validation_proof_cache_rejection_decision(key, ts(4), "entries/corrupt.json", &err);
    let human = render_validation_proof_cache_decision_human(&decision);
    let json = render_validation_proof_cache_decision_json(&decision).expect("corrupt json");

    assert_eq!(
        decision.decision,
        ValidationProofCacheDecisionKind::CorruptedEntry
    );
    assert_eq!(
        decision.required_action,
        ValidationProofCacheRequiredAction::RepairCache
    );
    assert!(human.contains("decision=corrupted_entry"));
    assert!(json.contains("\"reason_code\": \"VPC_REJECT_CORRUPTED\""));
}

#[test]
fn duplicate_entry_does_not_overwrite_existing_file() {
    let (_dir, store, _key, entry) = populated_store(|_| {});
    let path = store.entry_path(&entry.cache_key);
    let original = fs::read(&path).expect("original entry");

    let err = store.put_entry(&entry).expect_err("duplicate rejects");
    let after = fs::read(&path).expect("entry after duplicate attempt");

    assert_eq!(err.code(), error_codes::ERR_VPC_DUPLICATE_ENTRY);
    assert_eq!(original, after);
}

#[test]
fn preexisting_unrelated_entry_file_is_not_overwritten() {
    let dir = TempDir::new().expect("tempdir");
    let store = ValidationProofCacheStore::new(dir.path());
    let request = request();
    let receipt = fresh_receipt();
    let (receipt_path, receipt_bytes) = write_receipt(dir.path(), &receipt);
    let key = ValidationProofCacheKey::from_request_and_receipt(&request, &receipt, scope())
        .expect("key");
    let entry = store
        .build_entry(
            key.clone(),
            receipt_path,
            &receipt,
            &receipt_bytes,
            "LavenderElk",
            ts(3),
        )
        .expect("entry");
    let path = store.entry_path(&key);
    fs::create_dir_all(path.parent().expect("entry parent")).expect("entry parent");
    fs::write(&path, b"unrelated").expect("preexisting unrelated file");

    let err = store
        .put_entry(&entry)
        .expect_err("preexisting file rejects");
    let after = fs::read(&path).expect("preexisting after put");

    assert_eq!(err.code(), error_codes::ERR_VPC_DUPLICATE_ENTRY);
    assert_eq!(after, b"unrelated");
}

#[test]
fn quota_policy_refuses_disk_pressure_writes() {
    let dir = TempDir::new().expect("tempdir");
    let store = ValidationProofCacheStore::new(dir.path());
    let request = request_for("bd-pressure", "pressure");
    let receipt = receipt_for("bd-pressure", "pressure", ts(50));
    let (receipt_path, receipt_bytes) = write_receipt(dir.path(), &receipt);
    let key = ValidationProofCacheKey::from_request_and_receipt(&request, &receipt, scope())
        .expect("key");
    let entry = store
        .build_entry(
            key,
            receipt_path,
            &receipt,
            &receipt_bytes,
            "LavenderElk",
            ts(3),
        )
        .expect("entry");
    let policy = quota_policy();

    let err = store
        .put_entry_with_quota(&entry, &policy, 50, ts(4))
        .expect_err("disk pressure blocks writes");

    assert_eq!(err.code(), error_codes::ERR_VPC_QUOTA_BLOCKED);
}

#[test]
fn gc_report_removes_entries_past_max_age() {
    let dir = TempDir::new().expect("tempdir");
    let store = ValidationProofCacheStore::new(dir.path());
    let entry = insert_entry_for(&store, dir.path(), "bd-old", "old", ts(1), ts(50), |_| {});
    let mut policy = quota_policy();
    policy.max_age_seconds = 2;

    let report = store
        .plan_garbage_collection(&policy, ts(10), 1_000)
        .expect("gc report");

    assert_eq!(report.schema_version, GC_REPORT_SCHEMA_VERSION);
    assert_eq!(report.removed_entries.len(), 1);
    assert_eq!(report.removed_entries[0].entry_id, entry.entry_id);
    assert_eq!(
        report.removed_entries[0].reason_code,
        error_codes::ERR_VPC_STALE_ENTRY
    );
    assert!(report.kept_entries.is_empty());
}

#[test]
fn gc_report_rejects_missing_receipt_artifacts() {
    let dir = TempDir::new().expect("tempdir");
    let store = ValidationProofCacheStore::new(dir.path());
    let entry = insert_entry_for(
        &store,
        dir.path(),
        "bd-missing",
        "missing",
        ts(3),
        ts(50),
        |entry| {
            entry.receipt_ref.path = "receipts/missing-artifact.json".to_string();
        },
    );
    let policy = quota_policy();

    let report = store
        .plan_garbage_collection(&policy, ts(4), 1_000)
        .expect("gc report");

    assert_eq!(report.rejected_entries.len(), 1);
    assert_eq!(report.rejected_entries[0].entry_id, entry.entry_id);
    assert_eq!(
        report.rejected_entries[0].reason_code,
        error_codes::ERR_VPC_MALFORMED_ENTRY
    );
}

#[test]
fn gc_report_quarantines_corrupted_entries() {
    let dir = TempDir::new().expect("tempdir");
    let store = ValidationProofCacheStore::new(dir.path());
    let entry = insert_entry_for(
        &store,
        dir.path(),
        "bd-corrupt",
        "corrupt",
        ts(3),
        ts(50),
        |entry| {
            entry.invalidation.active = true;
            entry.invalidation.corrupted = true;
            entry.invalidation.reason = Some("test corruption".to_string());
        },
    );
    let policy = quota_policy();

    let report = store
        .plan_garbage_collection(&policy, ts(4), 1_000)
        .expect("gc report");

    assert_eq!(report.rejected_entries.len(), 1);
    assert_eq!(report.rejected_entries[0].entry_id, entry.entry_id);
    assert_eq!(
        report.rejected_entries[0].reason_code,
        error_codes::ERR_VPC_CORRUPTED_ENTRY
    );
}

#[test]
fn gc_quota_eviction_preserves_active_beads_when_possible() {
    let dir = TempDir::new().expect("tempdir");
    let store = ValidationProofCacheStore::new(dir.path());
    let active = insert_entry_for(
        &store,
        dir.path(),
        "bd-active",
        "active",
        ts(1),
        ts(20),
        |_| {},
    );
    let fresh = insert_entry_for(
        &store,
        dir.path(),
        "bd-fresh",
        "fresh",
        ts(3),
        ts(40),
        |_| {},
    );
    let old = insert_entry_for(&store, dir.path(), "bd-old", "old", ts(2), ts(30), |_| {});
    let mut policy = quota_policy();
    policy.max_entries = 2;
    policy.active_beads = vec!["bd-active".to_string()];
    let active_entry_path = store.entry_path(&active.cache_key);
    let active_receipt_path = dir.path().join(&active.receipt_ref.path);

    let report = store
        .plan_garbage_collection(&policy, ts(4), 1_000)
        .expect("gc report");
    let kept_ids = report
        .kept_entries
        .iter()
        .map(|entry| entry.entry_id.as_str())
        .collect::<Vec<_>>();
    let removed_ids = report
        .removed_entries
        .iter()
        .map(|entry| entry.entry_id.as_str())
        .collect::<Vec<_>>();

    assert!(kept_ids.contains(&active.entry_id.as_str()));
    assert!(kept_ids.contains(&fresh.entry_id.as_str()));
    assert!(removed_ids.contains(&old.entry_id.as_str()));
    assert!(active_entry_path.exists());
    assert!(active_receipt_path.exists());
}

#[test]
fn gc_report_rejects_input_and_dirty_policy_drift() {
    let dir = TempDir::new().expect("tempdir");
    let store = ValidationProofCacheStore::new(dir.path());
    let input_drift = insert_entry_for(
        &store,
        dir.path(),
        "bd-input-drift",
        "actual",
        ts(3),
        ts(50),
        |_| {},
    );
    let dirty_drift = insert_entry_for(
        &store,
        dir.path(),
        "bd-dirty-drift",
        "dirty",
        ts(3),
        ts(50),
        |_| {},
    );
    let mut policy = quota_policy();
    policy.expected_input_digests = request_for("bd-input-drift", "expected")
        .inputs
        .content_digests;

    let input_report = store
        .plan_garbage_collection(&policy, ts(4), 1_000)
        .expect("input drift gc report");

    assert!(input_report.rejected_entries.iter().any(|entry| {
        entry.entry_id == input_drift.entry_id
            && entry
                .reason_code
                .as_str()
                .eq(error_codes::ERR_VPC_INPUT_DIGEST_MISMATCH)
    }));

    policy.expected_input_digests = Vec::new();
    policy.expected_dirty_state_policy = Some(DirtyStatePolicy::SourceOnlyDocumented);
    let dirty_report = store
        .plan_garbage_collection(&policy, ts(4), 1_000)
        .expect("dirty drift gc report");

    assert!(dirty_report.rejected_entries.iter().any(|entry| {
        entry.entry_id == dirty_drift.entry_id
            && entry
                .reason_code
                .as_str()
                .eq(error_codes::ERR_VPC_DIRTY_STATE_MISMATCH)
    }));
}

#[test]
fn deterministic_contract_fixture_loads() {
    let fixture: serde_json::Value = serde_json::from_str(FIXTURE_JSON).expect("fixture json");

    assert_eq!(
        fixture["schema_version"],
        "franken-node/validation-proof-cache/fixtures/v1"
    );
    assert_eq!(
        fixture["valid_cache_keys"].as_array().expect("keys").len(),
        1
    );
    assert_eq!(
        fixture["valid_entries"].as_array().expect("entries").len(),
        1
    );
    assert_eq!(
        fixture["valid_gc_reports"]
            .as_array()
            .expect("gc reports")
            .len(),
        1
    );
}

#[test]
fn e2e_harness_matrix_loads_and_covers_required_cases() {
    let matrix: serde_json::Value = serde_json::from_str(E2E_MATRIX_JSON).expect("e2e matrix json");
    let fields = matrix["required_log_fields"]
        .as_array()
        .expect("required log fields")
        .iter()
        .map(|value| value.as_str().expect("log field string"))
        .collect::<Vec<_>>();
    let scenario_names = matrix["scenarios"]
        .as_array()
        .expect("scenarios")
        .iter()
        .map(|value| value["name"].as_str().expect("scenario name"))
        .collect::<Vec<_>>();

    assert_eq!(
        matrix["schema_version"],
        "franken-node/validation-proof-cache/e2e-harness-matrix/v1"
    );
    assert_eq!(matrix["bead_id"], "bd-gcprh");
    assert_eq!(matrix["registered_test_target"], "validation_proof_cache");
    assert_eq!(matrix["uses_real_temp_dirs"], true);
    assert_eq!(matrix["uses_real_artifact_files"], true);
    for field in REQUIRED_LOG_FIELDS {
        assert!(fields.contains(&field), "missing log field {field}");
    }
    for scenario in [
        "equivalent_concurrent_requests",
        "changed_input_digest_miss",
        "stale_receipt_readiness_closeout",
        "corrupted_cache_metadata",
        "quota_gc_preserves_active_artifacts",
        "structured_log_contract",
    ] {
        assert!(
            scenario_names.contains(&scenario),
            "missing e2e matrix scenario {scenario}"
        );
    }
}
