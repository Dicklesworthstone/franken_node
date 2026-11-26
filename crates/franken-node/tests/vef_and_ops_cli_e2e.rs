//! Mock-free end-to-end CLI integration tests for:
//! - `franken-node trust vef-prove` + `franken-node verify vef-proof` (Ed25519-signed VEF pipeline)
//! - `franken-node ops evidence-index` (metadata-only index + protected-source refusal)
//! - `franken-node ops swarm-handoff` (readiness, overlap risk, closed-bead audit, templates)

use ed25519_dalek::SigningKey;
use serde_json::{Value, json};
use std::path::Path;
use std::process::{Command, Output};
use tempfile::TempDir;

fn cli(workspace: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_franken-node"))
        .current_dir(workspace)
        .env_remove("FRANKEN_NODE_PROFILE")
        .args(args)
        .output()
        .unwrap_or_else(|err| panic!("failed running `{}`: {err}", args.join(" ")))
}

fn json_ok(workspace: &Path, args: &[&str]) -> Value {
    let out = cli(workspace, args);
    assert!(
        out.status.success(),
        "`{}` failed:\nstdout:\n{}\nstderr:\n{}",
        args.join(" "),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).unwrap_or_else(|err| {
        panic!(
            "`{}` stdout is not JSON ({err}):\n{}",
            args.join(" "),
            String::from_utf8_lossy(&out.stdout)
        )
    })
}

fn json_err(workspace: &Path, args: &[&str]) -> Value {
    let out = cli(workspace, args);
    assert!(
        !out.status.success(),
        "`{}` unexpectedly succeeded:\n{}",
        args.join(" "),
        String::from_utf8_lossy(&out.stdout)
    );
    serde_json::from_slice(&out.stdout).unwrap_or_else(|err| {
        panic!(
            "`{}` error stdout is not JSON ({err}):\nstdout:\n{}\nstderr:\n{}",
            args.join(" "),
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        )
    })
}

#[test]
fn vef_prove_and_verify_ed25519_roundtrip_and_tamper_refusals() {
    let dir = TempDir::new().expect("tempdir");
    let sk_path = dir.path().join("vef-signer.key");
    let pk_path = dir.path().join("vef-signer.pub");
    let wrong_pk_path = dir.path().join("wrong.pub");
    let bundle_path = dir.path().join("vef-bundle.json");

    let signing_key = SigningKey::from_bytes(&[0x42; 32]);
    let verifying_key = signing_key.verifying_key();
    let wrong_key = SigningKey::from_bytes(&[0x99; 32]).verifying_key();

    std::fs::write(&sk_path, hex::encode(signing_key.to_bytes())).expect("write sk");
    std::fs::write(&pk_path, hex::encode(verifying_key.to_bytes())).expect("write pk");
    std::fs::write(&wrong_pk_path, hex::encode(wrong_key.to_bytes())).expect("write wrong pk");

    let sk_str = sk_path.to_str().unwrap();
    let pk_str = pk_path.to_str().unwrap();
    let wrong_pk_str = wrong_pk_path.to_str().unwrap();
    let bundle_str = bundle_path.to_str().unwrap();

    let proved = json_ok(
        dir.path(),
        &[
            "trust",
            "vef-prove",
            "--policy-id",
            "prod-vef-policy",
            "--actor-identity",
            "operator:alice",
            "--artifact-identity",
            "sha256:deadbeef",
            "--signing-key",
            sk_str,
            "--now-ms",
            "1700000000000",
            "--validity-ms",
            "60000",
            "--output",
            bundle_str,
            "--json",
        ],
    );
    assert_eq!(
        proved["schema_version"],
        "franken-node/vef-signed-proof-bundle/v1"
    );
    assert_eq!(
        proved["signed_compliance_proof"]["backend_name"],
        "ed25519-receipt-window-v1"
    );
    assert_eq!(proved["receipt_entries"].as_array().unwrap().len(), 6);
    assert_eq!(proved["control_transition_allowed"], true);
    assert_eq!(proved["verification_state_allowed"], true);
    assert_eq!(
        proved["service_output"]["backend_id"],
        "ed25519_merkle_transparency_v1"
    );
    assert!(
        proved["service_output"]["proof_material"]
            .as_str()
            .unwrap_or("")
            .starts_with("ed25519_sig:")
    );
    assert_eq!(
        proved["service_output"]["verification_metadata"]["merkle_leaf_count"],
        "6"
    );
    assert_eq!(
        proved["service_input"]["metadata"]["control_context_schema"],
        "franken-node/vef-control-context/v1"
    );
    assert_eq!(proved["service_input"]["metadata"]["validity_ms"], "60000");
    assert_eq!(
        proved["service_input"]["metadata"]["expires_at_millis"],
        "1700000060000"
    );

    // 1. Valid verification with explicit trusted public key succeeds.
    let verified = json_ok(
        dir.path(),
        &[
            "verify",
            "vef-proof",
            bundle_str,
            "--trusted-public-key",
            pk_str,
            "--now-ms",
            "1700000010000",
            "--json",
        ],
    );
    assert_eq!(verified["ok"], true);
    assert_eq!(verified["backend_name"], "ed25519-receipt-window-v1");
    assert_eq!(verified["trust_anchor_source"], "explicit_flag");
    assert_eq!(verified["receipt_entry_count"], 6);
    assert_eq!(verified["capsule_verified"], true);
    assert_eq!(verified["control_transition_verdict"], "ALLOW");

    // 2. Self-asserted key without --trusted-public-key in uninitialized dir fails closed.
    let unanchored = json_err(
        dir.path(),
        &[
            "verify",
            "vef-proof",
            bundle_str,
            "--now-ms",
            "1700000010000",
            "--json",
        ],
    );
    assert_eq!(unanchored["ok"], false);
    assert!(
        unanchored["error"]
            .as_str()
            .unwrap_or_default()
            .contains("refuses self-asserted"),
        "{unanchored}"
    );

    // 3. Wrong trusted public key fails closed.
    let wrong_anchor = json_err(
        dir.path(),
        &[
            "verify",
            "vef-proof",
            bundle_str,
            "--trusted-public-key",
            wrong_pk_str,
            "--now-ms",
            "1700000010000",
            "--json",
        ],
    );
    assert_eq!(wrong_anchor["ok"], false);
    assert!(
        wrong_anchor["error"]
            .as_str()
            .unwrap_or_default()
            .contains("mismatch"),
        "{wrong_anchor}"
    );

    // 4. Expired proof fails closed.
    let expired = json_err(
        dir.path(),
        &[
            "verify",
            "vef-proof",
            bundle_str,
            "--trusted-public-key",
            pk_str,
            "--now-ms",
            "1700000090000",
            "--json",
        ],
    );
    assert_eq!(expired["ok"], false);

    // Previously these edits left both signatures intact while renewing an
    // expired proof or authorizing a different actor/artifact. Verify the
    // identity cases while the authentic proof is fresh so expiry cannot mask
    // a missing signature-to-control-context binding.
    for (name, patch, now) in [
        (
            "unsigned-time-renewal",
            json!({
                "generated_at_millis": 1700000090000_u64,
                "expires_at_millis": 1700000150000_u64,
            }),
            "1700000090000",
        ),
        (
            "unsigned-lifetime-extension",
            json!({
                "validity_ms": 600000_u64,
                "expires_at_millis": 1700000600000_u64,
            }),
            "1700000090000",
        ),
        (
            "actor-substitution",
            json!({"actor_identity": "operator:mallory"}),
            "1700000010000",
        ),
        (
            "artifact-substitution",
            json!({"artifact_identity": "sha256:substituted"}),
            "1700000010000",
        ),
    ] {
        let mut edited = proved.clone();
        for (field, value) in patch.as_object().unwrap() {
            edited[field] = value.clone();
        }
        assert_eq!(edited["service_output"], proved["service_output"]);
        assert_eq!(
            edited["signed_compliance_proof"],
            proved["signed_compliance_proof"]
        );
        let edited_path = dir.path().join(format!("{name}.json"));
        std::fs::write(&edited_path, serde_json::to_vec_pretty(&edited).unwrap()).unwrap();
        let err = json_err(
            dir.path(),
            &[
                "verify",
                "vef-proof",
                edited_path.to_str().unwrap(),
                "--trusted-public-key",
                pk_str,
                "--now-ms",
                now,
                "--json",
            ],
        );
        assert!(
            err["error"]
                .as_str()
                .unwrap_or_default()
                .contains("VEF signed control context"),
            "{name}: {err}"
        );
    }

    // 5. Downgrade attack to unkeyed reference backend ("test-hash") fails closed.
    let downgraded_path = dir.path().join("downgraded.json");
    let mut downgraded: Value =
        serde_json::from_slice(&std::fs::read(&bundle_path).unwrap()).unwrap();
    downgraded["signed_compliance_proof"]["backend_name"] = json!("test-hash");
    std::fs::write(
        &downgraded_path,
        serde_json::to_vec_pretty(&downgraded).unwrap(),
    )
    .unwrap();
    let downgrade_err = json_err(
        dir.path(),
        &[
            "verify",
            "vef-proof",
            downgraded_path.to_str().unwrap(),
            "--trusted-public-key",
            pk_str,
            "--now-ms",
            "1700000010000",
            "--json",
        ],
    );
    assert!(
        downgrade_err["error"]
            .as_str()
            .unwrap_or_default()
            .contains("unauthenticated VEF proof backend"),
        "{downgrade_err}"
    );

    // 6. Tampered Ed25519 signature byte fails closed.
    let tampered_path = dir.path().join("tampered.json");
    let mut tampered: Value =
        serde_json::from_slice(&std::fs::read(&bundle_path).unwrap()).unwrap();
    let first_byte = tampered["signed_compliance_proof"]["proof_data"][0]
        .as_u64()
        .unwrap();
    tampered["signed_compliance_proof"]["proof_data"][0] = json!((first_byte ^ 0xFF) & 0xFF);
    std::fs::write(
        &tampered_path,
        serde_json::to_vec_pretty(&tampered).unwrap(),
    )
    .unwrap();
    let tamper_err = json_err(
        dir.path(),
        &[
            "verify",
            "vef-proof",
            tampered_path.to_str().unwrap(),
            "--trusted-public-key",
            pk_str,
            "--now-ms",
            "1700000010000",
            "--json",
        ],
    );
    assert_eq!(tamper_err["ok"], false);
}

#[test]
fn ops_evidence_index_queries_metadata_and_rejects_protected_sources() {
    let dir = TempDir::new().expect("tempdir");
    std::fs::create_dir_all(dir.path().join(".beads")).unwrap();
    std::fs::create_dir_all(dir.path().join("docs/specs")).unwrap();
    std::fs::write(
        dir.path().join(".beads/issues.jsonl"),
        concat!(
            r#"{"id":"bd-vef-1","title":"Wire VEF proof pipeline","status":"closed","description":"Ed25519 receipt window proof"}"#,
            "\n",
            r#"{"id":"bd-dgis-2","title":"Immunize trust graph","status":"in_progress","description":"DGIS planner catalog"}"#,
            "\n"
        ),
    )
    .unwrap();
    std::fs::write(
        dir.path().join("docs/specs/vef_contract.md"),
        "# VEF Contract\n",
    )
    .unwrap();

    let out = json_ok(
        dir.path(),
        &[
            "ops",
            "evidence-index",
            "--root",
            ".",
            "--bead-id",
            "bd-vef-1",
            "--probe-source",
            ".beads/beads.db",
            "--probe-source",
            "../outside-escape.txt",
            "--json",
        ],
    );
    assert_eq!(
        out["schema_version"],
        "franken-node/ops-evidence-index-cli/v1"
    );
    assert_eq!(out["match_count"], 1);
    assert_eq!(out["matches"][0]["record"]["bead_id"], "bd-vef-1");

    let rejected = out["build_report"]["rejected_sources"]
        .as_array()
        .expect("rejected_sources");
    assert_eq!(rejected.len(), 2, "{rejected:?}");
    assert!(
        rejected
            .iter()
            .any(|r| r["source_path"] == ".beads/beads.db"
                && r["reason_code"] == "EVIDENCE_INDEX_PROTECTED_SOURCE_REJECTED"),
        "{rejected:?}"
    );
    assert!(
        rejected
            .iter()
            .any(|r| r["source_path"] == "../outside-escape.txt"
                && r["reason_code"] == "EVIDENCE_INDEX_INVALID_REPO_PATH"),
        "{rejected:?}"
    );
}

#[test]
fn ops_swarm_handoff_evaluates_beads_overlap_risk_and_compliance() {
    let dir = TempDir::new().expect("tempdir");
    std::fs::create_dir_all(dir.path().join(".beads")).unwrap();
    std::fs::write(
        dir.path().join(".beads/issues.jsonl"),
        concat!(
            r#"{"id":"bd-closed-1","title":"Landed slice","status":"closed","description":"Complete","close_reason":"Verified via rch cargo test"}"#,
            "\n",
            r#"{"id":"bd-active-2","title":"Active slice","status":"in_progress","assignee":"AgentAlpha","updated_at":"2020-01-01T00:00:00Z","description":"Working on main.rs"}"#,
            "\n",
            r#"{"id":"bd-open-3","title":"Ready slice","status":"open","description":"Unassigned ready bead"}"#,
            "\n"
        ),
    )
    .unwrap();

    let out = json_ok(
        dir.path(),
        &[
            "ops",
            "swarm-handoff",
            "--root",
            ".",
            "--trace-id",
            "trace-handoff-e2e",
            "--candidate-bead",
            "bd-active-2",
            "--candidate-path",
            "crates/franken-node/src/main.rs",
            "--json",
        ],
    );
    assert_eq!(
        out["schema_version"],
        "franken-node/ops-swarm-handoff-cli/v1"
    );
    assert_eq!(out["readiness"]["trace_id"], "trace-handoff-e2e");
    assert_eq!(out["readiness"]["decisions"].as_array().unwrap().len(), 2);
    assert_eq!(out["overlap_risk"]["bead_id"], "bd-active-2");
    assert_eq!(out["closed_bead_audits"].as_array().unwrap().len(), 1);
    assert!(out["bead_templates"].is_object(), "{out}");
    assert_eq!(out["operator_transcript_audit"]["status"], "pass");
}

#[test]
fn ops_swarm_scenario_and_fault_schedule_audit_execute_deterministically() {
    let dir = TempDir::new().expect("tempdir");
    let listed = json_ok(dir.path(), &["ops", "swarm-scenario", "--list", "--json"]);
    assert_eq!(
        listed["schema_version"],
        "franken-node/ops-swarm-scenario-cli/v1"
    );
    assert!(listed["scenario_count"].as_u64().unwrap() >= 8);

    let ws = dir.path().join("scenario-ws");
    let executed = json_ok(
        dir.path(),
        &[
            "ops",
            "swarm-scenario",
            "--scenario",
            "all-green-fleet-replay",
            "--workspace",
            ws.to_str().unwrap(),
            "--json",
        ],
    );
    assert_eq!(executed["report"]["verdict"], "pass");
    assert!(
        ws.join("scenario_artifacts/all-green-fleet-replay/incident_timeline.json")
            .is_file()
    );

    let unknown = json_err(
        dir.path(),
        &[
            "ops",
            "swarm-scenario",
            "--scenario",
            "does-not-exist",
            "--json",
        ],
    );
    assert_eq!(unknown["ok"], false);

    let audit = json_ok(
        dir.path(),
        &[
            "ops",
            "fault-schedule-audit",
            "--seeds",
            "42,137",
            "--messages-per-run",
            "16",
            "--dpor-time-budget-secs",
            "15",
            "--json",
        ],
    );
    assert_eq!(audit["ok"], true);
    assert_eq!(audit["transport_fault_gate"]["passed"], true);
    assert_eq!(audit["dpor_schedule_gate"]["passed"], true);
    assert_eq!(audit["dpor_schedule_gate"]["scenarios_explored"], 6);
    assert_eq!(audit["dpor_schedule_gate"]["total_violations"], 0);
    assert_eq!(audit["replay_bundle_adversarial_audit"]["passed"], true);
    assert_eq!(audit["replay_bundle_adversarial_audit"]["total_cases"], 9);
    assert_eq!(audit["replay_bundle_adversarial_audit"]["matched_cases"], 9);
    assert_eq!(audit["canonical_strategy_smoke"]["passed"], true);
    assert_eq!(audit["canonical_strategy_smoke"]["samples_per_family"], 4);
}

#[test]
fn trust_resolution_receipt_ed25519_roundtrip_budget_denial_and_tamper_refusal() {
    let dir = TempDir::new().expect("tempdir");
    let sk_path = dir.path().join("resolver.key");
    let pk_path = dir.path().join("resolver.pub");
    let wrong_pk_path = dir.path().join("wrong.pub");
    let receipt_path = dir.path().join("resolution-receipt.json");

    let sk = SigningKey::from_bytes(&[0x55; 32]);
    let pk = sk.verifying_key();
    let wrong_pk = SigningKey::from_bytes(&[0x77; 32]).verifying_key();

    std::fs::write(&sk_path, hex::encode(sk.to_bytes())).unwrap();
    std::fs::write(&pk_path, hex::encode(pk.to_bytes())).unwrap();
    std::fs::write(&wrong_pk_path, hex::encode(wrong_pk.to_bytes())).unwrap();

    let issued = json_ok(
        dir.path(),
        &[
            "trust",
            "resolution-receipt",
            "--package-name",
            "chalk",
            "--candidate-version",
            "5.3.0",
            "--signing-key",
            sk_path.to_str().unwrap(),
            "--output",
            receipt_path.to_str().unwrap(),
            "--json",
        ],
    );
    assert_eq!(issued["ok"], true);
    assert_eq!(issued["signed_receipt"]["receipt"]["decision"], "admit");
    assert_eq!(issued["capability_budget_metering"]["allowed"], true);

    let verified = json_ok(
        dir.path(),
        &[
            "trust",
            "resolution-receipt",
            "--verify",
            receipt_path.to_str().unwrap(),
            "--trusted-public-key",
            pk_path.to_str().unwrap(),
            "--json",
        ],
    );
    assert_eq!(verified["ok"], true);
    assert_eq!(verified["package_name"], "chalk");

    // Unanchored verification without --trusted-public-key must fail closed.
    let unanchored = json_err(
        dir.path(),
        &[
            "trust",
            "resolution-receipt",
            "--verify",
            receipt_path.to_str().unwrap(),
            "--json",
        ],
    );
    assert_eq!(unanchored["ok"], false);

    // Wrong public key must fail closed.
    let wrong = json_err(
        dir.path(),
        &[
            "trust",
            "resolution-receipt",
            "--verify",
            receipt_path.to_str().unwrap(),
            "--trusted-public-key",
            wrong_pk_path.to_str().unwrap(),
            "--json",
        ],
    );
    assert_eq!(wrong["ok"], false);

    // Enforced capability budget over-limit must fail closed.
    let over_budget = json_err(
        dir.path(),
        &[
            "trust",
            "resolution-receipt",
            "--package-name",
            "chalk",
            "--signing-key",
            sk_path.to_str().unwrap(),
            "--budget-mode",
            "enforced",
            "--max-resolve-effects",
            "2",
            "--used-resolve-effects",
            "2",
            "--json",
        ],
    );
    assert_eq!(over_budget["ok"], false);
    assert_eq!(over_budget["capability_budget_metering"]["allowed"], false);
}

#[test]
fn trust_ecosystem_telemetry_and_governance_audit_enforce_contracts() {
    let dir = TempDir::new().expect("tempdir");
    let telemetry = json_ok(
        dir.path(),
        &[
            "trust",
            "ecosystem-telemetry",
            "--enable-collection",
            "--json",
        ],
    );
    assert_eq!(
        telemetry["schema_version"],
        "franken-node/trust-ecosystem-telemetry-cli/v1"
    );
    assert_eq!(
        telemetry["health_export"]["compromise_reduction_metadata"]["availability"],
        "missing_upstream"
    );

    let gov_ok = json_ok(dir.path(), &["trust", "governance-audit", "--json"]);
    assert_eq!(gov_ok["ok"], true);
    assert_eq!(gov_ok["challenge_flow"]["promoted"], true);
    assert_eq!(gov_ok["staking_governance"]["gate_after"]["passed"], true);
    assert_eq!(gov_ok["intent_firewall"]["benign_verdict"], "allow");
    assert_eq!(gov_ok["intent_firewall"]["risky_verdict"], "deny");
    assert_eq!(gov_ok["key_role_separation"]["signing_role_verified"], true);
    assert_eq!(
        gov_ok["key_role_separation"]["cross_role_rebind_denied"],
        true
    );
    assert_eq!(
        gov_ok["key_role_separation"]["wrong_role_verify_denied"],
        true
    );
    assert_eq!(gov_ok["audience_token"]["verified"], true);
    assert_eq!(gov_ok["audience_token"]["replay_denied"], true);
    assert_eq!(gov_ok["trust_complexity"]["gate_pass"], true);
    assert_eq!(gov_ok["trust_complexity"]["replay_deterministic"], true);
    assert_eq!(gov_ok["trust_complexity"]["budget_exceeded_denied"], true);

    // Mismatched proof hash must fail closed.
    let gov_bad_proof = json_err(
        dir.path(),
        &[
            "trust",
            "governance-audit",
            "--submitted-proof-hash",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "--json",
        ],
    );
    assert_eq!(gov_bad_proof["ok"], false);
    assert_eq!(gov_bad_proof["challenge_flow"]["promoted"], false);

    // Insufficient stake for high tier (< 500) must fail closed.
    let gov_low_stake = json_err(
        dir.path(),
        &[
            "trust",
            "governance-audit",
            "--stake-amount",
            "10",
            "--risk-tier",
            "high",
            "--json",
        ],
    );
    assert_eq!(gov_low_stake["ok"], false);
    assert_eq!(
        gov_low_stake["staking_governance"]["gate_after"]["passed"],
        false
    );
}

#[test]
fn runtime_supervision_audit_verifies_lifecycle_and_fails_on_budget_exhaustion() {
    let dir = TempDir::new().expect("tempdir");
    let ok = json_ok(
        dir.path(),
        &[
            "runtime",
            "supervision-audit",
            "--strategy",
            "rest-for-one",
            "--max-restarts",
            "3",
            "--failures",
            "2",
            "--json",
        ],
    );
    assert_eq!(ok["ok"], true);
    assert_eq!(
        ok["cancellation"]["finalize_record"]["obligation_closure_proof"]["all_closed"],
        true
    );
    assert_eq!(ok["obligation_channel"]["outstanding_count"], 0);
    assert_eq!(ok["policy_checkpoint"]["verified_chain_len"], 1);
    assert_eq!(ok["capability_guard"]["undeclared_spawn_denied"], true);
    assert_eq!(ok["speculation_guard"]["activated_on_valid_proof"], true);
    assert_eq!(
        ok["speculation_guard"]["degraded_on_unapproved_interface"],
        true
    );
    assert_eq!(ok["optimization_governor_ville"]["shadow_approved"], true);
    assert_eq!(
        ok["optimization_governor_ville"]["ville_auto_reverted"],
        true
    );
    assert_eq!(
        ok["hash_provider"]["policy_keyed_digest_hex"]
            .as_str()
            .unwrap_or("")
            .len(),
        64
    );
    assert_eq!(ok["bocpd"]["posterior_valid"], true);
    assert_eq!(ok["bocpd"]["observations"], 16);
    assert_eq!(ok["tokio_drift"]["clean"], true);
    assert_eq!(ok["vef_degraded_mode"]["normal_permits_high_risk"], true);
    assert_eq!(ok["vef_degraded_mode"]["quarantine_blocks_high_risk"], true);
    assert_eq!(ok["vef_degraded_mode"]["escalated_mode"], "quarantine");

    let exhausted = json_err(
        dir.path(),
        &[
            "runtime",
            "supervision-audit",
            "--max-restarts",
            "1",
            "--failures",
            "2",
            "--json",
        ],
    );
    assert_eq!(exhausted["ok"], false);
}

#[test]
fn charter_substrates_sqlmodel_doctor_and_asupersync_fleet_agent_e2e() {
    let dir = TempDir::new().expect("tempdir");

    // 1. Default `fleet agent` activates the live `asupersync` control lane and initializes `fleet-state.db`.
    let agent_out = cli(
        dir.path(),
        &[
            "fleet",
            "agent",
            "--node-id",
            "node-charter-1",
            "--zone",
            "zone-charter",
            "--poll-interval-secs",
            "1",
            "--max-cycles",
            "1",
            "--json",
        ],
    );
    assert!(
        agent_out.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&agent_out.stdout),
        String::from_utf8_lossy(&agent_out.stderr)
    );
    let agent_stderr = String::from_utf8_lossy(&agent_out.stderr);
    assert!(
        agent_stderr.contains("ASUPERSYNC_CONTROL_LANE_ACTIVATED"),
        "expected ASUPERSYNC_CONTROL_LANE_ACTIVATED in stderr: {agent_stderr}"
    );
    assert!(
        agent_stderr.contains("charter_compliant_control_lane"),
        "expected charter_compliant_control_lane in stderr: {agent_stderr}"
    );

    // 2. Explicit `--fallback-file-transport` persists a durable AuditLog fallback receipt in `telemetry.db`.
    let fallback_out = cli(
        dir.path(),
        &[
            "fleet",
            "agent",
            "--node-id",
            "node-charter-1",
            "--zone",
            "zone-charter",
            "--poll-interval-secs",
            "1",
            "--max-cycles",
            "1",
            "--fallback-file-transport",
            "--json",
        ],
    );
    assert!(
        fallback_out.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&fallback_out.stdout),
        String::from_utf8_lossy(&fallback_out.stderr)
    );
    let fallback_stderr = String::from_utf8_lossy(&fallback_out.stderr);
    assert!(
        fallback_stderr.contains("FLEET_TRANSPORT_DEGRADED_FALLBACK")
            && fallback_stderr.contains("\"receipt_persisted\":true"),
        "expected persisted degraded fallback receipt in stderr: {fallback_stderr}"
    );

    // 3. `ops storage-schema-audit` introspects live `telemetry.db` + `fleet-state.db` against `sqlmodel_schema`.
    let schema_out = cli(
        dir.path(),
        &[
            "ops",
            "storage-schema-audit",
            "--workspace",
            dir.path().to_str().unwrap(),
            "--structured-logs-jsonl",
            "--json",
        ],
    );
    assert!(
        schema_out.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&schema_out.stdout),
        String::from_utf8_lossy(&schema_out.stderr)
    );
    let schema_json: Value = serde_json::from_slice(&schema_out.stdout).expect("schema audit json");
    assert_eq!(schema_json["ok"], true);
    assert_eq!(schema_json["canonical_domain_models"]["model_count"], 21);
    assert_eq!(
        schema_json["canonical_domain_models"]["generated_sqlite_ddl_count"],
        21
    );
    assert!(schema_json["live_store_count"].as_u64().unwrap_or(0) >= 2);
    assert_eq!(schema_json["drifted_store_count"], 0);
    assert!(
        String::from_utf8_lossy(&schema_out.stderr).contains("SQLMODEL_ROUND_TRIP_PASS"),
        "expected SQLMODEL_ROUND_TRIP_PASS JSONL event"
    );

    // 4. `doctor --json` and `doctor --screen` (`frankentui`) surface `DR-SQLMODEL-015` over the live workspace stores.
    let doc_json = json_ok(dir.path(), &["doctor", "--json"]);
    let checks = doc_json["checks"].as_array().expect("doctor checks array");
    let sqlmodel_check = checks
        .iter()
        .find(|c| c["code"] == "DR-SQLMODEL-015")
        .expect("DR-SQLMODEL-015 present when live SQLite stores exist");
    assert_eq!(sqlmodel_check["status"], "pass");

    let screen_out = cli(dir.path(), &["doctor", "--screen"]);
    assert!(
        screen_out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&screen_out.stderr)
    );
    let screen_text = String::from_utf8_lossy(&screen_out.stdout);
    assert!(
        screen_text.contains("DR-SQLMODEL-015"),
        "expected DR-SQLMODEL-015 in frankentui operator screen: {screen_text}"
    );
}

#[test]
fn ops_dgis_fixture_suite_and_migrate_kit_plan_cli_e2e() {
    let dir = TempDir::new().expect("tempdir");

    let dgis = json_ok(dir.path(), &["ops", "dgis-fixture-suite", "--json"]);
    assert_eq!(dgis["ok"], true);
    assert_eq!(dgis["fragility_suite"]["total_fixtures"], 10);
    assert_eq!(dgis["fragility_suite"]["passed_fixtures"], 10);
    assert!(dgis["graph_seed"]["node_count"].as_u64().unwrap_or(0) > 0);
    assert!(dgis["graph_seed"]["edge_count"].as_u64().unwrap_or(0) > 0);

    let kit = json_ok(
        dir.path(),
        &["migrate", "kit-plan", "--archetype", "fastify", "--json"],
    );
    assert_eq!(kit["ok"], true);
    assert_eq!(kit["kit"]["archetype"], "fastify");
    assert_eq!(kit["kit"]["step_count"], 5);
    assert_eq!(kit["project_scanner"]["source"], "archetype_probe");
    assert!(
        kit["project_scanner"]["apis_detected"]
            .as_u64()
            .unwrap_or(0)
            >= 4
    );

    let scan_proj = dir.path().join("sample_scan_project");
    std::fs::create_dir_all(&scan_proj).expect("create sample_scan_project");
    std::fs::write(
        scan_proj.join("index.js"),
        "const fs = require('fs'); const path = require('path'); fs.readFileSync(path.join('.', 'a')); eval('1+1');\n",
    )
    .expect("write index.js");
    let kit_with_proj = json_ok(
        dir.path(),
        &[
            "migrate",
            "kit-plan",
            "--archetype",
            "fastify",
            "--project-path",
            scan_proj.to_str().expect("scan_proj str"),
            "--json",
        ],
    );
    assert_eq!(kit_with_proj["project_scanner"]["source"], "project_path");
    assert!(
        kit_with_proj["project_scanner"]["apis_detected"]
            .as_u64()
            .unwrap_or(0)
            >= 3
    );
    assert_eq!(kit_with_proj["project_scanner"]["readiness"], "not-ready");
    assert!(
        kit_with_proj["project_scanner"]["risk_distribution"]["critical"]
            .as_u64()
            .unwrap_or(0)
            >= 1
    );
    assert_eq!(kit["activation_preview"]["live_execution"], false);
    assert_eq!(
        kit["activation_preview"]["default_executor_fails_closed"],
        true
    );
    assert_eq!(kit["activation_preview"]["completed"], true);
    assert_eq!(kit["activation_preview"]["stage_order_valid"], true);
    assert_eq!(kit["singularity_pipeline"]["stage"], "COMPLETE");
    assert_eq!(
        kit["singularity_pipeline"]["receipt_signature_verified"],
        true
    );
    assert_eq!(kit["tree_transaction_audit"]["valid"], true);
    assert_eq!(kit["migration_artifact_contract"]["artifact_valid"], true);
    assert_eq!(
        kit["migration_artifact_contract"]["artifact_signatures_verified"],
        true
    );
    assert_eq!(
        kit["migration_artifact_contract"]["behavioral_certificate_valid"],
        true
    );
    assert_eq!(
        kit["migration_artifact_contract"]["behavioral_certificate_signature_verified"],
        true
    );

    let bpet_cal = json_ok(
        dir.path(),
        &[
            "trust",
            "calibrate-conformal",
            "--builtin-benign-corpus",
            "--include-bpet-benchmark",
            "--json",
        ],
    );
    assert_eq!(
        bpet_cal["bpet_calibration_benchmark"]["schema_version"],
        "bpet.calibration_artifact.v1"
    );
    assert_eq!(
        bpet_cal["bpet_exchangeability_transfer"]["schema_version"],
        "bpet.corpus_exchangeability_transfer.v1"
    );
    assert_eq!(
        bpet_cal["bpet_trust_surface_assessment"]["schema_version"],
        "bpet-trust-surface-integration-v1"
    );

    let doc_el = json_ok(dir.path(), &["doctor", "expected-loss-actions", "--json"]);
    assert_eq!(doc_el["ville_martingale_gate"]["threshold_ppm"], 20_000_000);

    let bad_kit = json_err(
        dir.path(),
        &[
            "migrate",
            "kit-plan",
            "--archetype",
            "nonexistent",
            "--json",
        ],
    );
    assert_eq!(bad_kit["ok"], false);

    // Capsule inspection and minimization fail-closed refusal controls:
    let fake_capsule = dir.path().join("seed-capsule.json");
    std::fs::write(&fake_capsule, b"{\"not\":\"a-valid-capsule\"}").expect("write fake capsule");
    let candidate_dir = dir.path().join("candidate-proj");
    std::fs::create_dir_all(&candidate_dir).expect("create candidate dir");

    let missing_pin = json_err(
        dir.path(),
        &[
            "migrate",
            "kit-plan",
            "--capsule",
            fake_capsule.to_str().expect("utf8 path"),
            "--project-path",
            candidate_dir.to_str().expect("utf8 path"),
            "--json",
        ],
    );
    assert_eq!(missing_pin["ok"], false);
    assert!(
        missing_pin["error"]
            .as_str()
            .unwrap_or("")
            .contains("--capsule-sha256"),
        "expected missing --capsule-sha256 refusal: {missing_pin}"
    );

    let unpinned_inspect = json_err(
        dir.path(),
        &[
            "migrate",
            "kit-plan",
            "--capsule",
            fake_capsule.to_str().expect("utf8 path"),
            "--capsule-sha256",
            "not-a-hex-pin",
            "--project-path",
            candidate_dir.to_str().expect("utf8 path"),
            "--json",
        ],
    );
    assert_eq!(unpinned_inspect["ok"], false);
    assert!(
        unpinned_inspect["error"]
            .as_str()
            .unwrap_or("")
            .contains("independently pinned"),
        "expected source_fix::inspect pin format refusal: {unpinned_inspect}"
    );

    let fake_pin = "a".repeat(64);
    let minimize_refusal = json_err(
        dir.path(),
        &[
            "migrate",
            "kit-plan",
            "--capsule",
            fake_capsule.to_str().expect("utf8 path"),
            "--capsule-sha256",
            &fake_pin,
            "--minimize",
            "--bun-bin",
            "/bin/false",
            "--json",
        ],
    );
    assert_eq!(minimize_refusal["ok"], false);
}

#[test]
fn runtime_region_quiescence_and_trust_fabric_convergence_cli_e2e() {
    let dir = TempDir::new().expect("tempdir");

    let region_ok = json_ok(
        dir.path(),
        &["runtime", "region-quiescence-audit", "--json"],
    );
    assert_eq!(region_ok["ok"], true);
    assert_eq!(region_ok["region_tree"]["root_closed"], true);
    assert_eq!(region_ok["region_tree"]["forced_terminations"], 0);
    assert_eq!(region_ok["cancel_injection_gate"]["gate_passed"], true);
    assert_eq!(region_ok["saga"]["committed"], true);

    let region_halted = json_err(
        dir.path(),
        &[
            "runtime",
            "region-quiescence-audit",
            "--inject-durability-violation",
            "--json",
        ],
    );
    assert_eq!(region_halted["ok"], false);
    assert_eq!(region_halted["durability_violation"]["halted"], true);
    assert_eq!(
        region_halted["durability_violation"]["halt_blocks_durable_op"],
        true
    );

    let fabric_ok = json_ok(
        dir.path(),
        &[
            "trust",
            "fabric-convergence-audit",
            "--fleet-nodes",
            "4",
            "--json",
        ],
    );
    assert_eq!(fabric_ok["ok"], true);
    assert_eq!(fabric_ok["trust_fabric"]["converged"], true);
    assert_eq!(fabric_ok["claim_scoreboard"]["digest_verified"], true);
    assert_eq!(fabric_ok["ecosystem"]["tamper_free"], true);
    assert_eq!(fabric_ok["sybil_defense"]["ok"], true);
    assert_eq!(fabric_ok["sybil_defense"]["registered_nodes"], 11);

    let stale_revocation = json_err(
        dir.path(),
        &[
            "trust",
            "fabric-convergence-audit",
            "--revocation-age-secs",
            "999999",
            "--json",
        ],
    );
    assert_eq!(stale_revocation["ok"], false);
    assert_eq!(stale_revocation["revocation_freshness"]["allowed"], false);
}

#[test]
fn contract_transport_and_provenance_cohort_audits_enforce_contracts() {
    let dir = TempDir::new().expect("tempdir");

    let contract_ok = json_ok(
        dir.path(),
        &["ops", "contract-and-transport-audit", "--json"],
    );
    assert_eq!(
        contract_ok["schema_version"],
        "franken-node/ops-contract-and-transport-audit-cli/v1"
    );
    assert_eq!(contract_ok["ok"], true);
    assert_eq!(
        contract_ok["operator_json_contracts"]["doctor_live_valid"],
        true
    );
    assert_eq!(
        contract_ok["operator_json_contracts"]["runtime_epoch_valid"],
        true
    );
    assert_eq!(
        contract_ok["operator_json_contracts"]["missing_required_rejected"],
        true
    );
    assert_eq!(
        contract_ok["trace_correlation"]["orphan_span_rejected"],
        true
    );
    assert_eq!(
        contract_ok["anti_amplification"]["unauthenticated_flood_blocked"],
        true
    );
    assert_eq!(
        contract_ok["frame_guardrails"]["oversized_frame_blocked"],
        true
    );
    assert_eq!(
        contract_ok["checkpoint_guard"]["strict_uncheckpointed_violation_caught"],
        true
    );

    let prov_ok = json_ok(
        dir.path(),
        &["trust", "provenance-and-cohort-audit", "--json"],
    );
    assert_eq!(
        prov_ok["schema_version"],
        "franken-node/trust-provenance-and-cohort-audit-cli/v1"
    );
    assert_eq!(prov_ok["ok"], true);
    assert_eq!(prov_ok["provenance_gate"]["compliant_passed"], true);
    assert_eq!(prov_ok["provenance_gate"]["untrusted_rejected"], true);
    assert_eq!(
        prov_ok["bpet_cohort_baseline"]["event_code"],
        "BPET-COHORT-004"
    );
    assert_eq!(prov_ok["vef_claim_gate"]["compliant_claim_passed"], true);
    assert_eq!(prov_ok["vef_claim_gate"]["gap_claim_blocked"], true);
    assert_eq!(
        prov_ok["degraded_mode_audit"]["malformed_override_rejected"],
        true
    );

    // Requiring coverage above the 0.92 snapshot must fail closed.
    let prov_low_cov = json_err(
        dir.path(),
        &[
            "trust",
            "provenance-and-cohort-audit",
            "--min-coverage",
            "0.99",
            "--json",
        ],
    );
    assert_eq!(prov_low_cov["ok"], false);
    assert_eq!(
        prov_low_cov["vef_claim_gate"]["compliant_claim_passed"],
        false
    );
}
#[cfg(all(unix, feature = "engine"))]
#[test]
fn ops_session_inventory_empty_state_is_inspectable_without_provisioning_authority() {
    let dir = TempDir::new().expect("tempdir");
    let state_home = dir.path().join("operator-state");
    for verb in ["status", "recover"] {
        let out = Command::new(env!("CARGO_BIN_EXE_franken-node"))
            .current_dir(dir.path())
            .env_remove("FRANKEN_NODE_PROFILE")
            .env("XDG_STATE_HOME", &state_home)
            .args(["ops", "session-inventory", verb, "--json"])
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{verb}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let value: Value = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(value["quiescence_certified"], false);
        let status = if verb == "recover" {
            assert_eq!(value["recovered_sessions"], 0);
            assert_eq!(value["reclaimed_reserved_bytes"], 0);
            assert_eq!(value["before"], value["after"]);
            &value["after"]
        } else {
            &value
        };
        assert_eq!(status["store_present"], false);
        assert_eq!(status["retained_sessions"], 0);
        assert_eq!(status["pending_null_outcomes"], 0);
        assert_eq!(status["actual_bytes"], 0);
        assert_eq!(status["reserved_bytes"], 0);
        assert_eq!(status["capacity_exceeded"], false);
        assert_eq!(
            status["recovery_command"],
            "franken-node ops session-inventory recover --json"
        );
        assert!(
            !state_home.exists(),
            "inspection must not provision signing authority"
        );
    }

    let human = Command::new(env!("CARGO_BIN_EXE_franken-node"))
        .current_dir(dir.path())
        .env("XDG_STATE_HOME", &state_home)
        .args(["ops", "session-inventory", "status"])
        .output()
        .unwrap();
    assert!(human.status.success());
    let text = String::from_utf8(human.stdout).unwrap();
    assert!(text.contains("payload_bytes=0 reserved_bytes=0/"));
    assert!(text.contains("quiescence_certified=false"));
    assert!(!state_home.exists());
}

#[cfg(all(unix, feature = "engine"))]
#[test]
fn ops_session_inventory_refuses_a_linked_runtime_evidence_root() {
    use std::os::unix::fs::{PermissionsExt as _, symlink};

    let dir = TempDir::new().expect("tempdir");
    let state_home = dir.path().join("operator-state");
    let product = state_home.join("franken-node");
    std::fs::create_dir_all(&product).unwrap();
    std::fs::set_permissions(&product, std::fs::Permissions::from_mode(0o700)).unwrap();
    let outside = dir.path().join("outside");
    std::fs::create_dir(&outside).unwrap();
    let sentinel = outside.join("sentinel");
    std::fs::write(&sentinel, b"preserve retained evidence").unwrap();
    symlink(&outside, product.join("runtime-evidence")).unwrap();
    for verb in ["status", "recover"] {
        let out = Command::new(env!("CARGO_BIN_EXE_franken-node"))
            .current_dir(dir.path())
            .env_remove("FRANKEN_NODE_PROFILE")
            .env("XDG_STATE_HOME", &state_home)
            .args(["ops", "session-inventory", verb, "--json"])
            .output()
            .unwrap();
        assert!(!out.status.success());
        let value: Value = serde_json::from_slice(&out.stdout).unwrap();
        assert!(value.is_object());
        assert_eq!(
            std::fs::read(&sentinel).unwrap(),
            b"preserve retained evidence"
        );
        assert!(!outside.join("native-sessions.db").exists());
    }
}

#[test]
fn ops_session_inventory_json_parse_errors_use_the_specific_ops_surface() {
    let dir = TempDir::new().expect("tempdir");
    let out = Command::new(env!("CARGO_BIN_EXE_franken-node"))
        .current_dir(dir.path())
        .env_remove("FRANKEN_NODE_PROFILE")
        .args(["ops", "session-inventory", "recover", "--force", "--json"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    let value: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(value["schema_version"], "franken-node/ops-error-cli/v1");
    assert_eq!(value["command"], "ops.session-inventory");
}
