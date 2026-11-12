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
