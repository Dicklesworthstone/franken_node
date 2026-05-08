use chrono::{DateTime, TimeZone, Utc};
use frankenengine_node::observability::validation_proof_economics::{
    EconomicsReportingPeriod, SloStatus, SloTargets, ValidationProofEconomicsGenerator,
};
use frankenengine_node::ops::validation_broker::{
    CommandSpec, DigestRef, EnvironmentPolicy, FallbackPolicy, FlightRecorderAdapterOutcomeClass,
    InputDigest, InputSet, OutputPolicy, ProofArtifactPaths, ProofEvidenceSource, ProofStatusKind,
    QueueState, RECEIPT_SCHEMA_VERSION, RchMode, RchReceipt, ReceiptArtifacts,
    ReceiptClassifications, ReceiptRequestRef, ReceiptTrust, SourceOnlyReason, TargetDirPolicy,
    TimeoutClass, ValidationBrokerRequest, ValidationErrorClass, ValidationExit,
    ValidationExitKind, ValidationFlightRecorderRef, ValidationPriority,
    ValidationProofCoalescerEvidence, ValidationProofStatus, ValidationReceipt, ValidationTiming,
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
use frankenengine_node::ops::validation_proof_coalescer::{
    CAPACITY_SNAPSHOT_SCHEMA_VERSION, CompleteLeaseRequest, CreateLeaseRequest,
    FenceStaleLeaseRequest, ValidationProofAdmissionDecision, ValidationProofAdmissionInput,
    ValidationProofAdmissionPolicy, ValidationProofCoalescerDecision,
    ValidationProofCoalescerDecisionKind, ValidationProofCoalescerOutcome,
    ValidationProofCoalescerReceiptRef, ValidationProofCoalescerRequiredAction,
    ValidationProofCoalescerStore, ValidationProofLeaseState, ValidationProofPriority,
    ValidationProofRchCapacitySnapshot, ValidationProofRchCommand,
    ValidationProofRchWorkerCapacity, ValidationProofTargetDirClass, ValidationProofWorkKey,
    ValidationProofWorkKeyParts, ValidationSwarmSchedulerCapacitySnapshot,
    ValidationSwarmSchedulerCoalescerState, ValidationSwarmSchedulerDecision,
    ValidationSwarmSchedulerDecisionKind, ValidationSwarmSchedulerDigestRef,
    ValidationSwarmSchedulerFlightRecorderState, ValidationSwarmSchedulerInput,
    ValidationSwarmSchedulerPolicy, ValidationSwarmSchedulerPriority,
    ValidationSwarmSchedulerProofDebtClass, ValidationSwarmSchedulerTargetDirClass,
    decide_validation_proof_admission, decide_validation_swarm_schedule,
    error_codes as coalescer_error_codes, order_validation_swarm_scheduler_inputs,
    reason_codes as coalescer_reason_codes,
};
use frankenengine_node::ops::validation_proof_debt_ledger::{
    ValidationProofDebtClass, build_validation_proof_debt_ledger,
};
use frankenengine_node::ops::validation_readiness::{
    TrackedValidationBead, ValidationBeadState, ValidationReadinessInput,
    ValidationReadinessStatus, build_validation_readiness_report,
    render_validation_readiness_human,
};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Barrier, Mutex};
use std::thread;
use tempfile::TempDir;

const FIXTURE_JSON: &str = include_str!(
    "../../../artifacts/validation_broker/proof_cache/validation_proof_cache_fixtures.v1.json"
);
const E2E_MATRIX_JSON: &str = include_str!(
    "../../../artifacts/validation_broker/proof_cache/validation_proof_cache_e2e_matrix.v1.json"
);
const COALESCER_STRESS_MATRIX_JSON: &str = include_str!(
    "../../../artifacts/validation_broker/proof_coalescer/validation_proof_coalescer_stress_matrix.v1.json"
);
const SWARM_SCHEDULER_STRESS_MATRIX_JSON: &str = include_str!(
    "../../../artifacts/validation_broker/swarm_scheduler/validation_swarm_scheduler_stress_matrix.v1.json"
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
const COALESCER_STRESS_ATTEMPTS: usize = 32;
const COALESCER_STRESS_BEAD: &str = "bd-co196";
const COALESCER_STRESS_RECEIPT_PATH: &str = "receipts/bd-co196-producer.json";
const SWARM_SCHEDULER_STRESS_ATTEMPTS: usize = 32;
const SWARM_SCHEDULER_STRESS_BEAD: &str = "bd-qtnmv";
const REQUIRED_COALESCER_LOG_FIELDS: [&str; 15] = [
    "trace_id",
    "proof_work_key",
    "proof_cache_key",
    "lease_id",
    "decision",
    "reason_code",
    "event_code",
    "producer_agent",
    "waiter_agent",
    "bead_id",
    "receipt_path",
    "cache_key",
    "fencing_token",
    "target_dir_policy_id",
    "dirty_state_policy",
];
const REQUIRED_SWARM_SCHEDULER_LOG_FIELDS: [&str; 13] = [
    "trace_id",
    "proof_work_key",
    "scheduler_decision",
    "agent",
    "bead_id",
    "artifact_path",
    "event_code",
    "required_action",
    "queue_age_ms",
    "fairness_bucket",
    "starvation_risk",
    "coalescer_state",
    "recorder_path",
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
        readiness_ref: None,
        flight_recorder_ref: None,
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

fn coalescer_command() -> CommandSpec {
    CommandSpec {
        program: "rch".to_string(),
        argv: vec![
            "exec".to_string(),
            "--".to_string(),
            "env".to_string(),
            "CARGO_TARGET_DIR=/tmp/rch_target_franken_node_pane_7".to_string(),
            "cargo".to_string(),
            "test".to_string(),
            "-p".to_string(),
            "frankenengine-node".to_string(),
            "--test".to_string(),
            "validation_proof_cache".to_string(),
        ],
        cwd: "/data/projects/franken_node".to_string(),
        environment_policy_id: "validation-proof-coalescer/env-policy/rch-only/v1".to_string(),
        target_dir_policy_id: "validation-proof-coalescer/target-dir/off-repo/v1".to_string(),
    }
}

fn coalescer_work_key(seed: &str) -> ValidationProofWorkKey {
    let command = coalescer_command();
    ValidationProofWorkKey::from_parts(ValidationProofWorkKeyParts {
        command_digest: command.digest(),
        input_digests: vec![InputDigest::new(
            format!("crates/franken-node/tests/validation_proof_cache.rs::{seed}"),
            seed.as_bytes(),
            "coalescer-stress",
        )],
        git_commit: format!("commit-bd-co196-{seed}"),
        dirty_worktree: false,
        dirty_state_policy: DirtyStatePolicy::CleanRequired,
        feature_flags: vec!["external-commands".to_string(), "http-client".to_string()],
        cargo_toolchain: "nightly-2026-02-19".to_string(),
        package: "frankenengine-node".to_string(),
        test_target: "validation_proof_cache".to_string(),
        environment_policy_id: command.environment_policy_id,
        target_dir_policy_id: command.target_dir_policy_id,
    })
    .expect("valid coalescer stress work key")
}

fn coalescer_create_request(
    seed: &str,
    agent: &str,
    bead_id: &str,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
) -> CreateLeaseRequest {
    let work_key = coalescer_work_key(seed);
    CreateLeaseRequest {
        rch_command: ValidationProofRchCommand {
            argv: coalescer_command().argv,
            command_digest: work_key.command_digest.clone(),
        },
        proof_work_key: work_key,
        owner_agent: agent.to_string(),
        owner_bead_id: bead_id.to_string(),
        trace_id: format!("trace-{bead_id}-{seed}-{agent}"),
        fencing_token: format!("fence-{bead_id}-{seed}-{agent}"),
        created_at,
        expires_at,
        admission_policy_id: "validation-proof-coalescer/admission/default/v1".to_string(),
    }
}

fn coalescer_receipt_ref(
    seed: &str,
    bead_id: &str,
    path: &str,
) -> ValidationProofCoalescerReceiptRef {
    let work_key = coalescer_work_key(seed);
    ValidationProofCoalescerReceiptRef {
        receipt_id: format!("vpco-receipt-{bead_id}-{seed}"),
        path: path.to_string(),
        bead_id: bead_id.to_string(),
        proof_cache_key_hex: work_key.proof_cache_key.hex,
    }
}

fn coalescer_capacity_snapshot(
    available_slots: u16,
    queue_depth: u16,
    degraded: bool,
    disk_pressure_warning: bool,
) -> ValidationProofRchCapacitySnapshot {
    ValidationProofRchCapacitySnapshot {
        schema_version: CAPACITY_SNAPSHOT_SCHEMA_VERSION.to_string(),
        observed_at: ts(30),
        workers: vec![ValidationProofRchWorkerCapacity {
            worker_id: "rch-worker-stress-1".to_string(),
            total_slots: available_slots.max(1),
            available_slots,
            queue_depth,
            degraded,
        }],
        queue_depth,
        oldest_queued_age_seconds: Some(30),
        disk_pressure_warning,
    }
}

fn coalescer_admission_input(
    trace_id: &str,
    available_slots: u16,
    queue_depth: u16,
    proof_priority: ValidationProofPriority,
    bead_priority: u8,
    timeout_budget_seconds: u64,
) -> ValidationProofAdmissionInput {
    ValidationProofAdmissionInput {
        trace_id: trace_id.to_string(),
        capacity_snapshot: coalescer_capacity_snapshot(available_slots, queue_depth, false, false),
        proof_priority,
        bead_priority,
        dirty_worktree: false,
        dirty_state_policy: DirtyStatePolicy::CleanRequired,
        target_dir_class: ValidationProofTargetDirClass::OffRepo,
        timeout_budget_seconds,
        current_queue_depth: 0,
    }
}

fn write_coalescer_receipt_with_subprocess(
    root: &Path,
    relative_path: &str,
    payload: &serde_json::Value,
) -> PathBuf {
    let path = root.join(relative_path);
    let parent = path.parent().expect("receipt parent");
    let bytes = serde_json::to_string_pretty(payload).expect("receipt payload json");
    fs::create_dir_all(parent).expect("receipt directory");
    let mut child = Command::new("tee")
        .arg(&path)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .expect("receipt subprocess launched");
    child
        .stdin
        .as_mut()
        .expect("receipt subprocess stdin")
        .write_all(bytes.as_bytes())
        .expect("receipt subprocess stdin write");
    let status = child.wait().expect("receipt subprocess wait");
    assert!(status.success(), "receipt subprocess failed: {status:?}");
    assert!(path.is_file(), "receipt subprocess did not create {path:?}");
    path
}

fn count_coalescer_lease_files(root: &Path) -> usize {
    fn visit(path: &Path, count: &mut usize) {
        for entry in fs::read_dir(path).expect("read coalescer lease directory") {
            let entry = entry.expect("coalescer lease directory entry");
            let file_type = entry.file_type().expect("coalescer lease entry file type");
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

    let leases = root.join("leases");
    if !leases.exists() {
        return 0;
    }
    let mut count = 0;
    visit(&leases, &mut count);
    count
}

fn coalescer_decision_log_event(
    decision: &ValidationProofCoalescerDecision,
    receipt_path: &str,
) -> serde_json::Value {
    let lease_ref = decision.lease_ref.as_ref();
    let producer_agent = lease_ref
        .map(|lease| lease.owner_agent.as_str())
        .unwrap_or(decision.agent_name.as_str());
    let waiter_agent = if matches!(
        decision.decision,
        ValidationProofCoalescerDecisionKind::JoinExistingProof
            | ValidationProofCoalescerDecisionKind::WaitForReceipt
            | ValidationProofCoalescerDecisionKind::RetryAfterStaleLease
            | ValidationProofCoalescerDecisionKind::RepairState
    ) {
        decision.agent_name.as_str()
    } else {
        "none"
    };
    serde_json::json!({
        "trace_id": decision.trace_id.as_str(),
        "proof_work_key": decision.proof_work_key.hex.as_str(),
        "proof_cache_key": decision.proof_work_key.proof_cache_key.hex.as_str(),
        "lease_id": lease_ref
            .map(|lease| lease.lease_id.as_str())
            .unwrap_or("no-lease"),
        "decision": decision.decision.as_str(),
        "reason_code": decision.reason_code.as_str(),
        "event_code": decision.diagnostics.event_code.as_str(),
        "producer_agent": producer_agent,
        "waiter_agent": waiter_agent,
        "bead_id": decision.bead_id.as_str(),
        "receipt_path": receipt_path,
        "cache_key": decision.proof_work_key.proof_cache_key.hex.as_str(),
        "fencing_token": lease_ref
            .map(|lease| lease.fencing_token.as_str())
            .unwrap_or("no-fence"),
        "target_dir_policy_id": decision.proof_work_key.target_dir_policy_id.as_str(),
        "dirty_state_policy": decision.proof_work_key.dirty_state_policy.as_str(),
    })
}

fn coalescer_admission_log_event(
    decision: &ValidationProofAdmissionDecision,
    work_key: &ValidationProofWorkKey,
    receipt_path: &str,
) -> serde_json::Value {
    serde_json::json!({
        "trace_id": decision.diagnostics.trace_id.as_str(),
        "proof_work_key": work_key.hex.as_str(),
        "proof_cache_key": work_key.proof_cache_key.hex.as_str(),
        "lease_id": "admission-only",
        "decision": decision.decision.as_str(),
        "reason_code": decision.reason_code.as_str(),
        "event_code": decision.diagnostics.event_code.as_str(),
        "producer_agent": "admission-policy",
        "waiter_agent": "none",
        "bead_id": COALESCER_STRESS_BEAD,
        "receipt_path": receipt_path,
        "cache_key": work_key.proof_cache_key.hex.as_str(),
        "fencing_token": "admission-only",
        "target_dir_policy_id": work_key.target_dir_policy_id.as_str(),
        "dirty_state_policy": work_key.dirty_state_policy.as_str(),
    })
}

fn assert_coalescer_log_event_fields(event: &serde_json::Value) {
    for field in REQUIRED_COALESCER_LOG_FIELDS {
        assert!(
            event
                .get(field)
                .and_then(serde_json::Value::as_str)
                .is_some_and(|value| !value.trim().is_empty()),
            "missing coalescer structured log field {field}: {event}"
        );
    }
}

fn swarm_scheduler_digest(material: &str) -> ValidationSwarmSchedulerDigestRef {
    ValidationSwarmSchedulerDigestRef::sha256_material(material)
}

fn swarm_scheduler_policy() -> ValidationSwarmSchedulerPolicy {
    ValidationSwarmSchedulerPolicy::default_policy("validation-swarm-scheduler/stress-policy/v1")
}

fn swarm_scheduler_capacity(
    slots_available: u16,
    queue_depth: u16,
    stale_active_builds: u16,
    disk_pressure_workers: u16,
) -> ValidationSwarmSchedulerCapacitySnapshot {
    ValidationSwarmSchedulerCapacitySnapshot {
        snapshot_id: format!(
            "vss-stress-capacity-{slots_available}-{queue_depth}-{stale_active_builds}-{disk_pressure_workers}"
        ),
        captured_at: ts(30),
        workers_total: 4,
        workers_healthy: 3,
        slots_total: 16,
        slots_available,
        queue_depth,
        stale_active_builds,
        disk_pressure_workers,
    }
}

fn swarm_scheduler_input(seed: &str, agent: &str) -> ValidationSwarmSchedulerInput {
    ValidationSwarmSchedulerInput {
        schema_version: frankenengine_node::ops::validation_proof_coalescer::SWARM_SCHEDULER_INPUT_SCHEMA_VERSION
            .to_string(),
        input_id: format!("vss-stress-{seed}-{agent}"),
        bead_id: SWARM_SCHEDULER_STRESS_BEAD.to_string(),
        agent_name: agent.to_string(),
        proof_work_key: swarm_scheduler_digest(&format!(
            "bd-qtnmv/proof-work/{seed}/cargo-test-validation-proof-cache"
        )),
        command_digest: swarm_scheduler_digest(&format!(
            "rch exec -- cargo test -p frankenengine-node --test validation_proof_cache {seed}"
        )),
        dirty_state_policy: DirtyStatePolicy::CleanRequired,
        target_dir_class: ValidationSwarmSchedulerTargetDirClass::OffRepo,
        capacity_snapshot: swarm_scheduler_capacity(8, 0, 0, 0),
        coalescer_state: ValidationSwarmSchedulerCoalescerState::None,
        flight_recorder_state: ValidationSwarmSchedulerFlightRecorderState::None,
        proof_debt_class: ValidationSwarmSchedulerProofDebtClass::None,
        queue_age_ms: 0,
        priority: ValidationSwarmSchedulerPriority::P2,
        timeout_budget_ms: 600_000,
        source_only_allowed: false,
        product_failure: false,
        worker_infra_retryable: false,
        artifact_valid: true,
    }
}

fn swarm_scheduler_decision(
    seed: &str,
    agent: &str,
    mutate: impl FnOnce(&mut ValidationSwarmSchedulerInput),
) -> ValidationSwarmSchedulerDecision {
    let mut input = swarm_scheduler_input(seed, agent);
    mutate(&mut input);
    decide_validation_swarm_schedule(&swarm_scheduler_policy(), &input, ts(40))
        .expect("scheduler decision")
}

fn swarm_scheduler_log_event(
    decision: &ValidationSwarmSchedulerDecision,
    phase: &str,
) -> serde_json::Value {
    serde_json::json!({
        "trace_id": decision.trace_id.as_str(),
        "phase": phase,
        "proof_work_key": decision.diagnostics.proof_work_key_hex.as_str(),
        "scheduler_decision": decision.decision.as_str(),
        "agent": decision.agent_name.as_str(),
        "bead_id": decision.bead_id.as_str(),
        "artifact_path": format!(
            "artifacts/validation_broker/swarm_scheduler/{phase}-{}.json",
            decision.decision.as_str()
        ),
        "event_code": decision.event_code.as_str(),
        "required_action": decision.required_action.as_str(),
        "queue_age_ms": decision.diagnostics.queue_age_ms.to_string(),
        "worker_id": "rch-worker-stress-1",
        "fairness_bucket": decision.fairness_bucket.as_str(),
        "starvation_risk": decision.starvation_risk.as_str(),
        "coalescer_state": decision.diagnostics.coalescer_state.as_str(),
        "recorder_path": decision
            .diagnostics
            .recorder_path
            .as_deref()
            .unwrap_or("no-recorder"),
    })
}

fn assert_swarm_scheduler_log_event_fields(event: &serde_json::Value) {
    for field in REQUIRED_SWARM_SCHEDULER_LOG_FIELDS {
        assert!(
            event
                .get(field)
                .and_then(serde_json::Value::as_str)
                .is_some_and(|value| !value.trim().is_empty()),
            "missing swarm scheduler structured log field {field}: {event}"
        );
    }
}

fn proof_status_from_scheduler_decision(
    decision: &ValidationSwarmSchedulerDecision,
) -> ValidationProofStatus {
    let mut status =
        ValidationProofStatus::unknown(&decision.bead_id, &decision.input_ref, decision.decided_at);
    status.request_id = Some(decision.input_ref.clone());
    status.command_digest = Some(DigestRef {
        algorithm: "sha256".to_string(),
        hex: decision.diagnostics.command_digest_hex.clone(),
    });
    status.reason = Some(format!(
        "{} {}",
        decision.decision.as_str(),
        decision.required_action.as_str()
    ));

    match decision.decision {
        ValidationSwarmSchedulerDecisionKind::RunNow => {
            status.status = ProofStatusKind::Passed;
            status.proof_source = ProofEvidenceSource::FreshExecution;
            status.artifact_paths = Some(ProofArtifactPaths {
                stdout_path: "artifacts/validation_broker/bd-qtnmv/stdout.txt".to_string(),
                stderr_path: "artifacts/validation_broker/bd-qtnmv/stderr.txt".to_string(),
                summary_path: "artifacts/validation_broker/bd-qtnmv/summary.json".to_string(),
                receipt_path: "receipts/bd-qtnmv-producer.json".to_string(),
            });
        }
        ValidationSwarmSchedulerDecisionKind::JoinExisting => {
            status.status = ProofStatusKind::Passed;
            status.proof_source = ProofEvidenceSource::CoalescedWaiter;
            status.deduplicated = true;
            status.proof_coalescer = Some(ValidationProofCoalescerEvidence {
                decision_id: decision.decision_id.clone(),
                proof_work_key_hex: decision.diagnostics.proof_work_key_hex.clone(),
                lease_id: "vss-stress-equivalent-lease".to_string(),
                lease_path:
                    "artifacts/validation_broker/proof_coalescer/vss-stress-equivalent.json"
                        .to_string(),
                lease_state: "running".to_string(),
                producer_agent: "stress-agent-00".to_string(),
                producer_bead_id: decision.bead_id.clone(),
                waiter_agent: Some(decision.agent_name.clone()),
                trace_id: decision.trace_id.clone(),
                receipt_id: None,
                receipt_path: None,
                proof_cache_key_hex: decision.diagnostics.proof_work_key_hex.clone(),
                reason_code: decision.reason_code.clone(),
                event_code: decision.event_code.clone(),
                required_action: decision.required_action.as_str().to_string(),
                diagnostic: decision.operator_message.clone(),
            });
        }
        ValidationSwarmSchedulerDecisionKind::WaitForCapacity
        | ValidationSwarmSchedulerDecisionKind::RejectLowPriority => {
            status.status = ProofStatusKind::Queued;
            status.proof_source = ProofEvidenceSource::BrokerQueue;
            status.queue_state = Some(QueueState::Queued);
            status.queue_depth = usize::from(decision.diagnostics.queue_depth);
            status.exit = Some(ValidationExit {
                kind: ValidationExitKind::Timeout,
                code: None,
                signal: None,
                timeout_class: TimeoutClass::QueueWait,
                error_class: ValidationErrorClass::EnvironmentContention,
                retryable: true,
            });
        }
        ValidationSwarmSchedulerDecisionKind::StealStaleWork => {
            status.status = ProofStatusKind::Running;
            status.proof_source = ProofEvidenceSource::CoalescedInflight;
            status.proof_coalescer = Some(ValidationProofCoalescerEvidence {
                decision_id: decision.decision_id.clone(),
                proof_work_key_hex: decision.diagnostics.proof_work_key_hex.clone(),
                lease_id: "vss-stale-producer-lease".to_string(),
                lease_path: "artifacts/validation_broker/proof_coalescer/stale.json".to_string(),
                lease_state: "stale".to_string(),
                producer_agent: "stale-producer".to_string(),
                producer_bead_id: decision.bead_id.clone(),
                waiter_agent: Some(decision.agent_name.clone()),
                trace_id: decision.trace_id.clone(),
                receipt_id: None,
                receipt_path: None,
                proof_cache_key_hex: decision.diagnostics.proof_work_key_hex.clone(),
                reason_code: decision.reason_code.clone(),
                event_code: decision.event_code.clone(),
                required_action: decision.required_action.as_str().to_string(),
                diagnostic: "stale lease requires a fresh fence before reuse".to_string(),
            });
        }
        ValidationSwarmSchedulerDecisionKind::RecordSourceOnlyBlocker => {
            status.status = ProofStatusKind::SourceOnly;
            status.proof_source = ProofEvidenceSource::SourceOnlyFallback;
            status.exit = Some(ValidationExit {
                kind: ValidationExitKind::SourceOnly,
                code: Some(0),
                signal: None,
                timeout_class: TimeoutClass::None,
                error_class: ValidationErrorClass::SourceOnly,
                retryable: false,
            });
        }
        ValidationSwarmSchedulerDecisionKind::FailClosedProduct => {
            status.status = ProofStatusKind::Failed;
            status.proof_source = ProofEvidenceSource::CoalescerRejected;
            status.exit = Some(ValidationExit {
                kind: ValidationExitKind::Failed,
                code: Some(101),
                signal: None,
                timeout_class: TimeoutClass::None,
                error_class: ValidationErrorClass::CompileError,
                retryable: false,
            });
            status.flight_recorder_ref = Some(ValidationFlightRecorderRef {
                schema_version: "franken-node/validation-flight-recorder-ref/v1".to_string(),
                attempt_path: "artifacts/validation_broker/flight_recorder/product_failure.json"
                    .to_string(),
                attempt_digest: DigestRef::sha256(b"bd-qtnmv-product-failure"),
                attempt_id: "bd-qtnmv-product-failure".to_string(),
                generated_at: decision.decided_at,
                freshness_expires_at: decision.freshness_expires_at,
                outcome_class: FlightRecorderAdapterOutcomeClass::CompileFailed,
                execution_mode: RchMode::Remote,
                worker_id: Some("rch-worker-stress-1".to_string()),
                reason_code: decision.reason_code.clone(),
            });
        }
        ValidationSwarmSchedulerDecisionKind::FailClosedInvalidArtifact => {
            status.status = ProofStatusKind::Failed;
            status.proof_source = ProofEvidenceSource::CoalescerRejected;
        }
    }

    status
}

#[derive(Debug)]
struct CoalescerStressAttempt {
    agent: String,
    outcome: ValidationProofCoalescerOutcome,
}

#[test]
fn mock_free_e2e_concurrent_proof_attempts_coalesce_and_handoff_receipt()
-> Result<(), Box<dyn std::error::Error>> {
    let dir = TempDir::new()?;
    let store_root = Arc::new(dir.path().to_path_buf());
    let log_path = dir.path().join("proof-coalescer-stress.ndjson");
    let barrier = Arc::new(Barrier::new(COALESCER_STRESS_ATTEMPTS));
    let attempts = Arc::new(Mutex::new(Vec::<CoalescerStressAttempt>::new()));

    thread::scope(|thread_scope| {
        for idx in 0..COALESCER_STRESS_ATTEMPTS {
            let root = Arc::clone(&store_root);
            let barrier = Arc::clone(&barrier);
            let attempts = Arc::clone(&attempts);

            thread_scope.spawn(move || {
                let agent = format!("stress-agent-{idx:02}");
                let request = coalescer_create_request(
                    "stress-equivalent",
                    &agent,
                    COALESCER_STRESS_BEAD,
                    ts(10),
                    ts(50),
                );
                let store = ValidationProofCoalescerStore::new(root.as_path());
                barrier.wait();
                let outcome = store.create_or_join(request).expect("coalescer attempt");
                attempts
                    .lock()
                    .expect("attempts lock")
                    .push(CoalescerStressAttempt { agent, outcome });
            });
        }
    });

    let mut attempts = Arc::try_unwrap(attempts)
        .expect("attempt refs released")
        .into_inner()
        .expect("attempts lock released");
    attempts.sort_by(|left, right| left.agent.cmp(&right.agent));
    for attempt in &attempts {
        append_log_event(
            &log_path,
            &coalescer_decision_log_event(&attempt.outcome.decision, COALESCER_STRESS_RECEIPT_PATH),
        );
    }

    let producer_count = attempts
        .iter()
        .filter(|attempt| {
            matches!(
                attempt.outcome.decision.decision,
                ValidationProofCoalescerDecisionKind::RunLocallyViaRch
            )
        })
        .count();
    let waiter_count = attempts
        .iter()
        .filter(|attempt| {
            matches!(
                attempt.outcome.decision.decision,
                ValidationProofCoalescerDecisionKind::JoinExistingProof
            )
        })
        .count();
    assert_eq!(
        producer_count, 1,
        "exactly one producer may launch RCH proof"
    );
    assert_eq!(
        waiter_count,
        COALESCER_STRESS_ATTEMPTS - 1,
        "equivalent attempts must join the in-flight proof"
    );
    assert_eq!(
        count_coalescer_lease_files(dir.path()),
        1,
        "equivalent attempts must persist one coalesced lease"
    );

    let producer = attempts
        .iter()
        .find(|attempt| {
            matches!(
                attempt.outcome.decision.decision,
                ValidationProofCoalescerDecisionKind::RunLocallyViaRch
            )
        })
        .expect("producer outcome");
    let producer_lease = producer
        .outcome
        .lease
        .as_ref()
        .expect("producer lease")
        .clone();
    assert!(producer.outcome.lease_path.is_file());
    let store = ValidationProofCoalescerStore::new(dir.path());
    let stored = store
        .read_lease(&producer_lease.proof_work_key)?
        .expect("stored coalesced lease");
    assert_eq!(stored.lease_id, producer_lease.lease_id);
    assert_eq!(stored.proof_work_key.hex, producer_lease.proof_work_key.hex);

    let receipt_payload = serde_json::json!({
        "bead_id": COALESCER_STRESS_BEAD,
        "lease_id": producer_lease.lease_id.as_str(),
        "producer_agent": producer_lease.owner_agent.as_str(),
        "proof_work_key": producer_lease.proof_work_key.hex.as_str(),
        "cache_key": producer_lease.proof_cache_key.hex.as_str(),
    });
    let receipt_path = write_coalescer_receipt_with_subprocess(
        dir.path(),
        COALESCER_STRESS_RECEIPT_PATH,
        &receipt_payload,
    );
    let completed = store.complete_lease(CompleteLeaseRequest {
        proof_work_key: producer_lease.proof_work_key.clone(),
        owner_agent: producer_lease.owner_agent.clone(),
        owner_bead_id: producer_lease.owner_bead_id.clone(),
        fencing_token: producer_lease.fencing_token.clone(),
        completed_at: ts(51),
        receipt_ref: coalescer_receipt_ref(
            "stress-equivalent",
            COALESCER_STRESS_BEAD,
            COALESCER_STRESS_RECEIPT_PATH,
        ),
    })?;
    assert_eq!(completed.state, ValidationProofLeaseState::Completed);
    assert_eq!(
        completed
            .receipt_ref
            .as_ref()
            .expect("completed receipt ref")
            .path,
        COALESCER_STRESS_RECEIPT_PATH
    );
    assert_eq!(
        completed
            .receipt_ref
            .as_ref()
            .expect("completed receipt ref")
            .proof_cache_key_hex,
        completed.proof_cache_key.hex
    );
    append_log_event(
        &log_path,
        &serde_json::json!({
            "trace_id": completed.diagnostics.trace_id.as_str(),
            "proof_work_key": completed.proof_work_key.hex.as_str(),
            "proof_cache_key": completed.proof_cache_key.hex.as_str(),
            "lease_id": completed.lease_id.as_str(),
            "decision": "coalesced_completed",
            "reason_code": completed.diagnostics.reason_code.as_str(),
            "event_code": completed.diagnostics.event_code.as_str(),
            "producer_agent": completed.owner_agent.as_str(),
            "waiter_agent": "none",
            "bead_id": completed.owner_bead_id.as_str(),
            "receipt_path": COALESCER_STRESS_RECEIPT_PATH,
            "cache_key": completed.proof_cache_key.hex.as_str(),
            "fencing_token": completed.fencing_token.as_str(),
            "target_dir_policy_id": completed.target_dir_policy_id.as_str(),
            "dirty_state_policy": completed.proof_work_key.dirty_state_policy.as_str(),
        }),
    );
    let receipt_json: serde_json::Value = serde_json::from_slice(&fs::read(&receipt_path)?)?;
    assert_eq!(
        receipt_json
            .get("lease_id")
            .and_then(serde_json::Value::as_str),
        Some(completed.lease_id.as_str())
    );

    let waiter_after_completion = store.create_or_join(coalescer_create_request(
        "stress-equivalent",
        "stress-agent-after-complete",
        COALESCER_STRESS_BEAD,
        ts(52),
        ts(59),
    ))?;
    assert_eq!(
        waiter_after_completion.decision.decision,
        ValidationProofCoalescerDecisionKind::WaitForReceipt
    );
    assert_eq!(
        waiter_after_completion.decision.required_action,
        ValidationProofCoalescerRequiredAction::WaitForReceipt
    );
    append_log_event(
        &log_path,
        &coalescer_decision_log_event(
            &waiter_after_completion.decision,
            COALESCER_STRESS_RECEIPT_PATH,
        ),
    );

    let changed = store.create_or_join(coalescer_create_request(
        "stress-changed",
        "stress-agent-changed",
        COALESCER_STRESS_BEAD,
        ts(20),
        ts(55),
    ))?;
    assert_eq!(
        changed.decision.decision,
        ValidationProofCoalescerDecisionKind::RunLocallyViaRch
    );
    assert_ne!(changed.lease_path, producer.outcome.lease_path);
    assert_eq!(
        count_coalescer_lease_files(dir.path()),
        2,
        "changed work key must allocate a separate lease"
    );
    append_log_event(
        &log_path,
        &coalescer_decision_log_event(&changed.decision, "receipts/bd-co196-changed.json"),
    );

    let stale_owner = store.create_or_join(coalescer_create_request(
        "stress-stale",
        "stress-agent-stale-owner",
        COALESCER_STRESS_BEAD,
        ts(1),
        ts(5),
    ))?;
    append_log_event(
        &log_path,
        &coalescer_decision_log_event(&stale_owner.decision, "receipts/bd-co196-stale.json"),
    );
    let stale_waiter = store.create_or_join(coalescer_create_request(
        "stress-stale",
        "stress-agent-stale-waiter",
        COALESCER_STRESS_BEAD,
        ts(10),
        ts(55),
    ))?;
    assert_eq!(
        stale_waiter.decision.decision,
        ValidationProofCoalescerDecisionKind::RetryAfterStaleLease
    );
    assert!(stale_waiter.decision.diagnostics.fail_closed);
    append_log_event(
        &log_path,
        &coalescer_decision_log_event(&stale_waiter.decision, "receipts/bd-co196-stale.json"),
    );

    let stale_lease = stale_owner
        .lease
        .as_ref()
        .expect("stale owner lease")
        .clone();
    let fenced = store.fence_stale_lease(FenceStaleLeaseRequest {
        proof_work_key: stale_lease.proof_work_key.clone(),
        owner_agent: "stress-agent-new-owner".to_string(),
        owner_bead_id: COALESCER_STRESS_BEAD.to_string(),
        trace_id: "trace-bd-co196-stale-fence".to_string(),
        fencing_token: format!("fence-{COALESCER_STRESS_BEAD}-stale-new-owner"),
        fenced_at: ts(11),
        expires_at: ts(55),
    })?;
    assert_eq!(
        fenced.decision.decision,
        ValidationProofCoalescerDecisionKind::RetryAfterStaleLease
    );
    assert_eq!(
        fenced.decision.required_action,
        ValidationProofCoalescerRequiredAction::RetryWithNewFence
    );
    append_log_event(
        &log_path,
        &coalescer_decision_log_event(&fenced.decision, "receipts/bd-co196-stale.json"),
    );

    let fenced_error = store
        .complete_lease(CompleteLeaseRequest {
            proof_work_key: stale_lease.proof_work_key.clone(),
            owner_agent: stale_lease.owner_agent.clone(),
            owner_bead_id: stale_lease.owner_bead_id.clone(),
            fencing_token: stale_lease.fencing_token.clone(),
            completed_at: ts(12),
            receipt_ref: coalescer_receipt_ref(
                "stress-stale",
                COALESCER_STRESS_BEAD,
                "receipts/bd-co196-stale.json",
            ),
        })
        .expect_err("old owner must be fenced after stale takeover");
    assert_eq!(
        fenced_error.code(),
        coalescer_error_codes::ERR_VPCO_FENCED_OWNER
    );

    let corrupt_key = coalescer_work_key("stress-corrupt");
    let corrupt_path = store.lease_path(&corrupt_key);
    fs::create_dir_all(corrupt_path.parent().expect("corrupt lease parent"))?;
    fs::write(&corrupt_path, b"{not-json")?;
    let corrupt = store.create_or_join(coalescer_create_request(
        "stress-corrupt",
        "stress-agent-corrupt",
        COALESCER_STRESS_BEAD,
        ts(13),
        ts(55),
    ))?;
    assert_eq!(
        corrupt.decision.decision,
        ValidationProofCoalescerDecisionKind::RepairState
    );
    assert!(corrupt.decision.diagnostics.fail_closed);
    append_log_event(
        &log_path,
        &coalescer_decision_log_event(&corrupt.decision, "receipts/bd-co196-corrupt.json"),
    );

    let policy = ValidationProofAdmissionPolicy::default_policy(
        "validation-proof-coalescer/stress-policy/v1",
    );
    let queued_input = coalescer_admission_input(
        "trace-bd-co196-capacity-queued",
        0,
        0,
        ValidationProofPriority::Low,
        4,
        1_000,
    );
    let queued = decide_validation_proof_admission(&policy, &queued_input)?;
    assert_eq!(
        queued.decision,
        ValidationProofCoalescerDecisionKind::QueuedByPolicy
    );
    assert_eq!(queued.reason_code, coalescer_reason_codes::QUEUE_CAPACITY);
    append_log_event(
        &log_path,
        &coalescer_admission_log_event(
            &queued,
            &coalescer_work_key("stress-capacity-queued"),
            "receipts/bd-co196-capacity.json",
        ),
    );

    let high_priority_input = coalescer_admission_input(
        "trace-bd-co196-capacity-admitted",
        1,
        0,
        ValidationProofPriority::High,
        1,
        600,
    );
    let admitted = decide_validation_proof_admission(&policy, &high_priority_input)?;
    assert_eq!(
        admitted.decision,
        ValidationProofCoalescerDecisionKind::RunLocallyViaRch
    );
    assert_eq!(
        admitted.required_action,
        ValidationProofCoalescerRequiredAction::StartRchValidation
    );
    append_log_event(
        &log_path,
        &coalescer_admission_log_event(
            &admitted,
            &coalescer_work_key("stress-capacity-admitted"),
            "receipts/bd-co196-capacity.json",
        ),
    );

    let rejected_input = coalescer_admission_input(
        "trace-bd-co196-capacity-rejected",
        1,
        16,
        ValidationProofPriority::High,
        1,
        600,
    );
    let rejected = decide_validation_proof_admission(&policy, &rejected_input)?;
    assert_eq!(
        rejected.decision,
        ValidationProofCoalescerDecisionKind::RejectCapacity
    );
    assert_eq!(
        rejected.reason_code,
        coalescer_reason_codes::REJECT_CAPACITY
    );
    assert!(rejected.diagnostics.fail_closed);
    append_log_event(
        &log_path,
        &coalescer_admission_log_event(
            &rejected,
            &coalescer_work_key("stress-capacity-rejected"),
            "receipts/bd-co196-capacity.json",
        ),
    );

    let events = read_log_events(&log_path);
    assert!(
        events.len() >= COALESCER_STRESS_ATTEMPTS + 10,
        "stress harness should log every coalescer assertion"
    );
    for event in &events {
        assert_coalescer_log_event_fields(event);
    }

    let matrix: serde_json::Value =
        serde_json::from_str(COALESCER_STRESS_MATRIX_JSON).expect("coalescer stress matrix json");
    assert_eq!(
        matrix.get("attempts").and_then(serde_json::Value::as_u64),
        Some(COALESCER_STRESS_ATTEMPTS as u64)
    );
    let matrix_fields = matrix
        .get("required_log_fields")
        .and_then(serde_json::Value::as_array)
        .expect("coalescer matrix fields");
    for field in REQUIRED_COALESCER_LOG_FIELDS {
        assert!(
            matrix_fields
                .iter()
                .any(|value| value.as_str() == Some(field)),
            "coalescer matrix missing required log field {field}"
        );
    }
    let matrix_scenarios = matrix
        .get("scenarios")
        .and_then(serde_json::Value::as_array)
        .expect("coalescer matrix scenarios");
    for scenario in matrix_scenarios {
        let name = scenario
            .get("name")
            .and_then(serde_json::Value::as_str)
            .expect("coalescer matrix scenario name");
        let expected_decision = scenario
            .get("expected_decision")
            .and_then(serde_json::Value::as_str)
            .expect("coalescer matrix expected decision");
        let expected_event_code = scenario
            .get("expected_event_code")
            .and_then(serde_json::Value::as_str)
            .expect("coalescer matrix expected event code");
        assert!(
            events.iter().any(|event| {
                event.get("decision").and_then(serde_json::Value::as_str) == Some(expected_decision)
                    && event.get("event_code").and_then(serde_json::Value::as_str)
                        == Some(expected_event_code)
            }),
            "missing coalescer stress scenario {name}: decision={expected_decision} event_code={expected_event_code}"
        );
    }
    Ok(())
}

#[test]
fn fixture_replay_swarm_scheduler_fairness_stress_matches_economics()
-> Result<(), Box<dyn std::error::Error>> {
    let dir = TempDir::new()?;
    let log_path = dir.path().join("swarm-scheduler-stress.ndjson");
    let policy = swarm_scheduler_policy();

    let mut decisions = Vec::new();
    let producer = swarm_scheduler_decision("equivalent", "stress-agent-00", |_| {});
    assert_eq!(
        producer.decision,
        ValidationSwarmSchedulerDecisionKind::RunNow
    );
    decisions.push(producer);

    for idx in 1..SWARM_SCHEDULER_STRESS_ATTEMPTS {
        let idx_u64 = u64::try_from(idx)?;
        let waiter =
            swarm_scheduler_decision("equivalent", &format!("stress-agent-{idx:02}"), |input| {
                input.coalescer_state = ValidationSwarmSchedulerCoalescerState::Running;
                input.queue_age_ms = 10_000 + idx_u64;
            });
        assert_eq!(
            waiter.decision,
            ValidationSwarmSchedulerDecisionKind::JoinExisting
        );
        decisions.push(waiter);
    }

    let fresh_low_priority = swarm_scheduler_decision("p4-fresh", "low-priority-fresh", |input| {
        input.priority = ValidationSwarmSchedulerPriority::P4;
        input.capacity_snapshot = swarm_scheduler_capacity(0, 96, 0, 0);
        input.queue_age_ms = 120_000;
    });
    assert_eq!(
        fresh_low_priority.decision,
        ValidationSwarmSchedulerDecisionKind::RejectLowPriority
    );

    let aged_low_priority = swarm_scheduler_decision("p4-aged", "low-priority-aged", |input| {
        input.priority = ValidationSwarmSchedulerPriority::P4;
        input.capacity_snapshot = swarm_scheduler_capacity(0, 96, 0, 0);
        input.queue_age_ms = 700_000;
    });
    assert_eq!(
        aged_low_priority.decision,
        ValidationSwarmSchedulerDecisionKind::WaitForCapacity
    );
    assert_eq!(aged_low_priority.fairness_bucket.as_str(), "aging");

    let stale_steal = swarm_scheduler_decision("stale-producer", "fresh-fence-agent", |input| {
        input.coalescer_state = ValidationSwarmSchedulerCoalescerState::Stale;
        input.proof_debt_class = ValidationSwarmSchedulerProofDebtClass::StaleProducer;
        input.queue_age_ms = 950_000;
    });
    assert_eq!(
        stale_steal.decision,
        ValidationSwarmSchedulerDecisionKind::StealStaleWork
    );
    assert!(stale_steal.diagnostics.fencing_token_digest.is_some());

    let source_only = swarm_scheduler_decision("source-only", "source-only-agent", |input| {
        input.proof_debt_class = ValidationSwarmSchedulerProofDebtClass::SourceOnly;
        input.flight_recorder_state =
            ValidationSwarmSchedulerFlightRecorderState::SourceOnlyBlocker;
        input.source_only_allowed = true;
        input.queue_age_ms = 950_000;
    });
    assert_eq!(
        source_only.decision,
        ValidationSwarmSchedulerDecisionKind::RecordSourceOnlyBlocker
    );
    assert!(source_only.fail_closed);

    let product_failure = swarm_scheduler_decision("product-failure", "product-agent", |input| {
        input.proof_debt_class = ValidationSwarmSchedulerProofDebtClass::ProductFailure;
        input.flight_recorder_state = ValidationSwarmSchedulerFlightRecorderState::ProductFailure;
        input.product_failure = true;
    });
    assert_eq!(
        product_failure.decision,
        ValidationSwarmSchedulerDecisionKind::FailClosedProduct
    );
    assert!(product_failure.fail_closed);

    decisions.extend([
        fresh_low_priority.clone(),
        aged_low_priority.clone(),
        stale_steal.clone(),
        source_only.clone(),
        product_failure.clone(),
    ]);

    let ordered_inputs = [
        swarm_scheduler_input("tie-right", "agent-b"),
        swarm_scheduler_input("tie-left", "agent-a"),
        {
            let mut aged = swarm_scheduler_input("aged-p4", "agent-c");
            aged.priority = ValidationSwarmSchedulerPriority::P4;
            aged.queue_age_ms = 700_000;
            aged
        },
        {
            let mut p0 = swarm_scheduler_input("p0", "agent-d");
            p0.priority = ValidationSwarmSchedulerPriority::P0;
            p0
        },
    ];
    let ordered = order_validation_swarm_scheduler_inputs(&policy, &ordered_inputs)?;
    assert_eq!(ordered[0].priority, ValidationSwarmSchedulerPriority::P0);
    assert_eq!(ordered[1].input_id, "vss-stress-aged-p4-agent-c");
    assert_eq!(ordered[2].agent_name, "agent-a");
    assert_eq!(ordered[3].agent_name, "agent-b");

    for decision in &decisions {
        append_log_event(
            &log_path,
            &swarm_scheduler_log_event(decision, decision.decision.as_str()),
        );
    }
    let events = read_log_events(&log_path);
    assert_eq!(events.len(), decisions.len());
    for event in &events {
        assert_swarm_scheduler_log_event_fields(event);
    }

    let mut statuses = decisions
        .iter()
        .map(proof_status_from_scheduler_decision)
        .collect::<Vec<_>>();
    statuses.retain(|status| {
        status.deduplicated
            || matches!(
                status.status,
                ProofStatusKind::Queued
                    | ProofStatusKind::Running
                    | ProofStatusKind::SourceOnly
                    | ProofStatusKind::Failed
            )
    });
    let debt_ledger = build_validation_proof_debt_ledger(
        &statuses,
        ts(41),
        [
            SWARM_SCHEDULER_STRESS_BEAD,
            "vss-stress-p4-aged-low-priority-aged",
        ],
    );
    assert_eq!(
        debt_ledger
            .summary
            .by_class
            .get(&ValidationProofDebtClass::WaitingForCapacity),
        Some(&2)
    );
    assert_eq!(
        debt_ledger
            .summary
            .by_class
            .get(&ValidationProofDebtClass::StaleLease),
        Some(&1)
    );
    assert_eq!(
        debt_ledger
            .summary
            .by_class
            .get(&ValidationProofDebtClass::SourceOnlyFallback),
        Some(&1)
    );
    assert_eq!(
        debt_ledger
            .summary
            .by_class
            .get(&ValidationProofDebtClass::ProductFailure),
        Some(&1)
    );

    let economics = ValidationProofEconomicsGenerator::with_slo_targets(SloTargets {
        max_queue_depth: 4,
        max_average_wait_time_seconds: 300.0,
        max_failure_rate: 0.50,
        max_debt_age_seconds: 10_000_000.0,
        min_coalescing_efficiency: 0.20,
    })
    .generate_report(
        &statuses,
        &debt_ledger,
        EconomicsReportingPeriod {
            start_time: ts(0),
            end_time: ts(60),
            duration_seconds: 60,
        },
    );
    assert_eq!(
        economics.summary.duplicate_proofs_avoided,
        SWARM_SCHEDULER_STRESS_ATTEMPTS - 1
    );
    assert_eq!(
        economics.summary.worker_time_saved_seconds,
        ((SWARM_SCHEDULER_STRESS_ATTEMPTS - 1) as u64).saturating_mul(60)
    );
    assert_eq!(economics.summary.queue_debt_count, 5);
    assert_eq!(economics.summary.stale_producer_count, 1);
    assert_eq!(economics.summary.source_only_blocker_count, 1);
    assert_eq!(economics.summary.product_failure_count, 1);
    assert_eq!(economics.summary.slo_breach_count, 1);
    assert_eq!(economics.slo_compliance.overall_status, SloStatus::Breach);

    let readiness_input = ValidationReadinessInput {
        proof_statuses: statuses,
        swarm_scheduler_decisions: decisions.clone(),
        ..ValidationReadinessInput::default()
    };
    let readiness =
        build_validation_readiness_report(&readiness_input, "bd-qtnmv-readiness", ts(41));
    assert_eq!(readiness.summary.swarm_scheduler.decisions, decisions.len());
    assert_eq!(readiness.summary.swarm_scheduler.capacity_waits, 1);
    assert_eq!(readiness.summary.swarm_scheduler.work_steals, 1);
    assert_eq!(readiness.summary.swarm_scheduler.source_only_blockers, 1);
    assert_eq!(readiness.summary.swarm_scheduler.product_failures, 1);
    assert!(
        readiness
            .summary
            .swarm_scheduler
            .decision_details
            .iter()
            .any(|detail| detail.slo_breached && detail.scheduler_decision == "steal_stale_work")
    );

    let matrix: serde_json::Value = serde_json::from_str(SWARM_SCHEDULER_STRESS_MATRIX_JSON)?;
    assert_eq!(
        matrix.get("attempts").and_then(serde_json::Value::as_u64),
        Some(SWARM_SCHEDULER_STRESS_ATTEMPTS as u64)
    );
    let matrix_scenarios = matrix
        .get("scenarios")
        .and_then(serde_json::Value::as_array)
        .expect("swarm scheduler matrix scenarios");
    for scenario in matrix_scenarios {
        let name = scenario
            .get("name")
            .and_then(serde_json::Value::as_str)
            .expect("swarm scheduler matrix scenario name");
        let expected_decision = scenario
            .get("expected_decision")
            .and_then(serde_json::Value::as_str)
            .expect("swarm scheduler matrix expected decision");
        assert!(
            events.iter().any(|event| {
                event
                    .get("scheduler_decision")
                    .and_then(serde_json::Value::as_str)
                    == Some(expected_decision)
            }),
            "missing swarm scheduler stress scenario {name}: decision={expected_decision}"
        );
    }
    Ok(())
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
