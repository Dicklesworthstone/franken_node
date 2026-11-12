//! End-to-end CLI integration tests for:
//! - `franken-node trust-card reputation` (`tools::reputation_graph_apis`, IBD-9)
//! - `franken-node trust zk-attest` and `franken-node verify zk-attestation`
//!   (`security::zk_attestation`, independently pinned `zka-ristretto255-v3.0`
//!   + fail-closed `zka-v1.0`).

use std::path::Path;
use std::process::{Command, Output};

use serde_json::{Value, json};

fn cli(workspace: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_franken-node"))
        .current_dir(workspace)
        .env_remove("FRANKEN_NODE_PROFILE")
        .env_remove("FRANKEN_NODE_OSV_QUERY_URL")
        .args(args)
        .output()
        .unwrap_or_else(|error| panic!("`{}`: {error}", args.join(" ")))
}

fn json_ok(workspace: &Path, args: &[&str]) -> Value {
    let output = cli(workspace, args);
    assert!(
        output.status.success(),
        "`{}` failed:\nstdout:\n{}\nstderr:\n{}",
        args.join(" "),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "`{}` must emit JSON ({error}):\n{}",
            args.join(" "),
            String::from_utf8_lossy(&output.stdout)
        )
    })
}

fn json_fail(workspace: &Path, args: &[&str]) -> Value {
    let output = cli(workspace, args);
    assert!(
        !output.status.success(),
        "`{}` unexpectedly succeeded:\n{}",
        args.join(" "),
        String::from_utf8_lossy(&output.stdout)
    );
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "`{}` must emit single JSON error/rejection document ({error}):\nstdout:\n{}\nstderr:\n{}",
            args.join(" "),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

fn seeded_trust_workspace() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(
        dir.path().join("package.json"),
        r#"{"name":"reputation-app","version":"1.0.0","dependencies":{"web-kit":"^3.1.0","lib-core":"^2.0.0"}}"#,
    )
    .expect("package.json");
    std::fs::write(
        dir.path().join("package-lock.json"),
        r#"{
  "name": "reputation-app",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "packages": {
    "": {"name": "reputation-app", "version": "1.0.0",
         "dependencies": {"web-kit": "^3.1.0", "lib-core": "^2.0.0"}},
    "node_modules/web-kit": {"version": "3.1.4", "dependencies": {"lib-core": "^2.0.0"}},
    "node_modules/lib-core": {"version": "2.0.7", "dependencies": {"tiny-helper": "^1.0.0"}},
    "node_modules/tiny-helper": {"version": "1.0.2"}
  }
}"#,
    )
    .expect("package-lock.json");

    let init = cli(
        dir.path(),
        &["init", "--profile", "balanced", "--out-dir", "."],
    );
    assert!(
        init.status.success(),
        "init failed: {}",
        String::from_utf8_lossy(&init.stderr)
    );
    json_ok(dir.path(), &["trust", "scan", ".", "--json"]);
    dir
}

fn score_entry<'a>(report: &'a Value, node_id: &str) -> &'a Value {
    report["scores"]
        .as_array()
        .expect("scores array")
        .iter()
        .find(|entry| entry["node_id"] == node_id)
        .unwrap_or_else(|| panic!("score entry `{node_id}` missing from {report}"))
}

#[test]
fn trust_card_reputation_scores_registry_posture_quarantine_decay_and_subgraph() {
    let workspace = seeded_trust_workspace();

    let baseline = json_ok(workspace.path(), &["trust-card", "reputation", "--json"]);
    assert_eq!(
        baseline["schema_version"],
        "franken-node/trust-card-reputation-cli/v1"
    );
    assert_eq!(baseline["command"], "trust-card.reputation");
    assert_eq!(baseline["rga_schema_version"], "rga-v1.0");
    assert_eq!(baseline["snapshot"]["schema_version"], "rga-v1.0");
    assert!(
        baseline["snapshot"]["node_count"]
            .as_u64()
            .expect("node_count")
            >= 5,
        "{baseline}"
    );
    assert!(
        baseline["snapshot"]["edge_count"]
            .as_u64()
            .expect("edge_count")
            >= 6,
        "{baseline}"
    );
    assert!(
        baseline["audit_record_count"].as_u64().expect("audit") > 0,
        "{baseline}"
    );

    let baseline_tiny = score_entry(&baseline, "npm:tiny-helper")["composite_score"]
        .as_f64()
        .expect("baseline composite_score");

    // Quarantine `npm:tiny-helper` and verify reputation score drops below threshold
    // and `--extension` extracts the focused neighbor subgraph.
    json_ok(
        workspace.path(),
        &[
            "trust",
            "quarantine",
            "--artifact",
            "npm:tiny-helper",
            "--json",
        ],
    );

    let focused = json_ok(
        workspace.path(),
        &[
            "trust-card",
            "reputation",
            "--extension",
            "npm:tiny-helper",
            "--decay-steps",
            "2",
            "--json",
        ],
    );
    assert_eq!(focused["decay_steps"], 2);
    let scores = focused["scores"].as_array().expect("focused scores");
    assert_eq!(scores.len(), 1);
    let quarantined_tiny = &scores[0];
    assert_eq!(quarantined_tiny["node_id"], "npm:tiny-helper");
    assert_eq!(quarantined_tiny["meets_threshold"], false);
    let after_score = quarantined_tiny["composite_score"]
        .as_f64()
        .expect("after composite_score");
    assert!(
        after_score < baseline_tiny,
        "quarantine must degrade reputation score: before={baseline_tiny}, after={after_score}"
    );
    assert!(
        focused["focused_subgraph"]["nodes"]
            .as_array()
            .expect("subgraph nodes")
            .len()
            >= 2,
        "{focused}"
    );
    assert!(
        !focused["focused_subgraph"]["edges"]
            .as_array()
            .expect("subgraph edges")
            .is_empty(),
        "{focused}"
    );
}

#[test]
fn trust_card_reputation_fails_closed_when_registry_uninitialized() {
    let dir = tempfile::tempdir().expect("tempdir");
    let err = json_fail(dir.path(), &["trust-card", "reputation", "--json"]);
    assert_eq!(
        err["schema_version"],
        "franken-node/trust-card-error-cli/v1"
    );
    assert_eq!(err["command"], "trust-card.reputation");
    assert_eq!(err["ok"], false);
}

#[test]
fn zk_attest_and_verify_roundtrip_threshold_and_allowlist_without_witness_disclosure() {
    let dir = tempfile::tempdir().expect("tempdir");
    let thresh_bundle_path = dir.path().join("thresh-bundle.json");
    let thresh_bundle_str = thresh_bundle_path.display().to_string();

    // Secret attribute `58421` satisfies `>= 500` within 16-bit range `[500, 66036)`.
    let secret_str = "58421";
    let issued_raw = cli(
        dir.path(),
        &[
            "trust",
            "zk-attest",
            "--policy-id",
            "pol-thresh-prod",
            "--issuer",
            "ops-ca-v1",
            "--threshold",
            "500",
            "--range-bits",
            "16",
            "--private-value",
            secret_str,
            "--now-ms",
            "1700000000000",
            "--validity-ms",
            "600000",
            "--output",
            &thresh_bundle_str,
            "--json",
        ],
    );
    assert!(
        issued_raw.status.success(),
        "zk-attest failed:\n{}",
        String::from_utf8_lossy(&issued_raw.stderr)
    );
    let stdout_text = String::from_utf8_lossy(&issued_raw.stdout);
    let stderr_text = String::from_utf8_lossy(&issued_raw.stderr);
    let bundle_text = std::fs::read_to_string(&thresh_bundle_path).expect("bundle file");

    assert!(
        !stdout_text.contains(secret_str),
        "private witness leaked to stdout:\n{stdout_text}"
    );
    assert!(
        !stderr_text.contains(secret_str),
        "private witness leaked to stderr:\n{stderr_text}"
    );
    assert!(
        !bundle_text.contains(secret_str),
        "private witness leaked to bundle JSON:\n{bundle_text}"
    );

    let issued: Value = serde_json::from_str(&stdout_text).expect("issued JSON");
    assert_eq!(
        issued["schema_version"],
        "franken-node/trust-zk-attest-cli/v1"
    );
    assert_eq!(
        issued["bundle"]["attestation"]["payload"]["schema_version"],
        "zka-ristretto255-v3.0"
    );
    // Retain the pin from trusted issuance, independently of the candidate file.
    let trusted_threshold_params = issued["params_sha256"]
        .as_str()
        .expect("issued params hash");

    let verified = json_ok(
        dir.path(),
        &[
            "verify",
            "zk-attestation",
            &thresh_bundle_str,
            "--trusted-params-sha256",
            trusted_threshold_params,
            "--now-ms",
            "1700000100000",
            "--json",
        ],
    );
    assert_eq!(
        verified["schema_version"],
        "franken-node/verify-zk-attestation-cli/v1"
    );
    assert_eq!(verified["verified"], true);
    assert_eq!(verified["verified_params_sha256"], trusted_threshold_params);
    assert!(verified.get("error_code").is_none());

    // AllowlistMembership roundtrip: two distinct members produce indistinguishable valid proofs.
    let allow_bundle_a = dir.path().join("allow-a.json");
    let allow_bundle_b = dir.path().join("allow-b.json");
    let allow_a_str = allow_bundle_a.display().to_string();
    let allow_b_str = allow_bundle_b.display().to_string();

    let out_a = json_ok(
        dir.path(),
        &[
            "trust",
            "zk-attest",
            "--policy-id",
            "pol-allow-prod",
            "--issuer",
            "ops-ca-v1",
            "--allowlist",
            "101,2048,65535",
            "--private-value",
            "101",
            "--challenge-nonce",
            "fixed-nonce-allow",
            "--now-ms",
            "1700000000000",
            "--output",
            &allow_a_str,
            "--json",
        ],
    );
    let out_b = json_ok(
        dir.path(),
        &[
            "trust",
            "zk-attest",
            "--policy-id",
            "pol-allow-prod",
            "--issuer",
            "ops-ca-v1",
            "--allowlist",
            "101,2048,65535",
            "--private-value",
            "65535",
            "--challenge-nonce",
            "fixed-nonce-allow",
            "--now-ms",
            "1700000000000",
            "--output",
            &allow_b_str,
            "--json",
        ],
    );
    assert_ne!(
        out_a["bundle"]["attestation"]["payload"]["metadata_commitment"],
        out_b["bundle"]["attestation"]["payload"]["metadata_commitment"]
    );
    assert_eq!(out_a["params_sha256"], out_b["params_sha256"]);
    let trusted_allowlist_params = out_a["params_sha256"].as_str().expect("issued params hash");
    assert_eq!(
        out_a["bundle"]["attestation"]["payload"]["proof_bytes_hex"]
            .as_str()
            .expect("hex a")
            .len(),
        out_b["bundle"]["attestation"]["payload"]["proof_bytes_hex"]
            .as_str()
            .expect("hex b")
            .len(),
        "CDS94 OR-proof wire length must not leak matched allowlist branch"
    );

    for bundle_arg in [&allow_a_str, &allow_b_str] {
        let verified_allow = json_ok(
            dir.path(),
            &[
                "verify",
                "zk-attestation",
                bundle_arg,
                "--trusted-params-sha256",
                trusted_allowlist_params,
                "--now-ms",
                "1700000050000",
                "--json",
            ],
        );
        assert_eq!(verified_allow["verified"], true);
        assert_eq!(
            verified_allow["verified_params_sha256"],
            trusted_allowlist_params
        );
    }
}

#[test]
fn zk_verify_rejects_tampered_proof_unsatisfied_witness_and_legacy_v1_fail_closed() {
    let dir = tempfile::tempdir().expect("tempdir");

    // 1. Unsatisfied threshold predicate fails closed without echoing the private witness.
    let unsatisfied_secret = "499";
    let unsat = json_fail(
        dir.path(),
        &[
            "trust",
            "zk-attest",
            "--policy-id",
            "pol-unsat",
            "--issuer",
            "ops-ca",
            "--threshold",
            "500",
            "--private-value",
            unsatisfied_secret,
            "--json",
        ],
    );
    assert_eq!(unsat["schema_version"], "franken-node/trust-error-cli/v1");
    assert_eq!(unsat["command"], "trust.zk-attest");
    let err_msg = unsat["error"].as_str().expect("error text");
    assert!(
        err_msg.contains("ERR_ZKA_PREDICATE_UNSATISFIED"),
        "{err_msg}"
    );
    assert!(
        !err_msg.contains(unsatisfied_secret),
        "error message must not echo private witness: {err_msg}"
    );

    // 2. Tampered proof bytes fail closed with ERR_ZKA_WITNESS_INVALID.
    let bundle_path = dir.path().join("valid.json");
    let bundle_str = bundle_path.display().to_string();
    let issued = json_ok(
        dir.path(),
        &[
            "trust",
            "zk-attest",
            "--policy-id",
            "pol-tamper",
            "--issuer",
            "ops-ca",
            "--threshold",
            "100",
            "--private-value",
            "250",
            "--now-ms",
            "1700000000000",
            "--output",
            &bundle_str,
            "--json",
        ],
    );
    let trusted_params = issued["params_sha256"]
        .as_str()
        .expect("issued params hash");

    let mut tampered: Value =
        serde_json::from_slice(&std::fs::read(&bundle_path).expect("read")).expect("json");
    let orig_hex = tampered["attestation"]["payload"]["proof_bytes_hex"]
        .as_str()
        .expect("proof hex")
        .to_string();
    let mut chars: Vec<char> = orig_hex.chars().collect();
    let last_idx = chars.len() - 1;
    chars[last_idx] = if chars[last_idx] == '0' { '1' } else { '0' };
    let mutated_hex: String = chars.into_iter().collect();
    tampered["attestation"]["payload"]["proof_bytes_hex"] = json!(mutated_hex);

    let tampered_path = dir.path().join("tampered.json");
    std::fs::write(
        &tampered_path,
        serde_json::to_vec_pretty(&tampered).expect("encode"),
    )
    .expect("write tampered");

    let rejected_tamper = json_fail(
        dir.path(),
        &[
            "verify",
            "zk-attestation",
            &tampered_path.display().to_string(),
            "--trusted-params-sha256",
            trusted_params,
            "--now-ms",
            "1700000010000",
            "--json",
        ],
    );
    assert_eq!(rejected_tamper["verified"], false);
    assert_eq!(rejected_tamper["error_code"], "ERR_ZKA_WITNESS_INVALID");
    assert!(rejected_tamper.get("verified_params_sha256").is_none());

    // 3. Legacy zka-v1.0 attestation fails closed with ERR_ZKA_VERIFIER_UNAVAILABLE.
    let legacy_path = dir.path().join("legacy-v1.json");
    let legacy_payload = json!({
        "attestation_id": "att-legacy-01",
        "policy_id": "pol-legacy",
        "payload": {
            "schema_version": "zka-v1.0",
            "proof_bytes_hex": "deadbeef",
            "metadata_commitment": "cafebabe"
        },
        "outcome": "Pass",
        "status": "Active",
        "generated_at_ms": 1700000000000_u64,
        "expires_at_ms": 1700000600000_u64,
        "trace_id": "trace-legacy"
    });
    std::fs::write(
        &legacy_path,
        serde_json::to_vec_pretty(&legacy_payload).expect("encode legacy"),
    )
    .expect("write legacy");

    let rejected_legacy = json_fail(
        dir.path(),
        &[
            "verify",
            "zk-attestation",
            &legacy_path.display().to_string(),
            "--trusted-params-sha256",
            trusted_params,
            "--now-ms",
            "1700000010000",
            "--json",
        ],
    );
    assert_eq!(rejected_legacy["verified"], false);
    assert_eq!(
        rejected_legacy["error_code"],
        "ERR_ZKA_VERIFIER_UNAVAILABLE"
    );
    assert!(rejected_legacy.get("verified_params_sha256").is_none());
}

#[test]
fn zk_verify_requires_independent_policy_relation_issuer_epoch_and_challenge_pin() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut trusted_params = String::new();
    let mut trusted_bundle_path = String::new();

    // Every variant has a genuine valid proof and the same policy ID. Only the
    // first statement was selected by the verifier's independent trust policy.
    for (label, threshold, private_value, issuer, epoch, challenge) in [
        ("trusted", "100", "150", "ops-ca", "7", "expected-challenge"),
        ("weaker", "0", "1", "ops-ca", "7", "expected-challenge"),
        (
            "issuer",
            "100",
            "150",
            "foreign-ca",
            "7",
            "expected-challenge",
        ),
        ("epoch", "100", "150", "ops-ca", "6", "expected-challenge"),
        (
            "challenge",
            "100",
            "150",
            "ops-ca",
            "7",
            "foreign-challenge",
        ),
    ] {
        let bundle_path = dir.path().join(format!("{label}.json"));
        let bundle_arg = bundle_path.display().to_string();
        let issued = json_ok(
            dir.path(),
            &[
                "trust",
                "zk-attest",
                "--policy-id",
                "same-policy-id",
                "--issuer",
                issuer,
                "--threshold",
                threshold,
                "--range-bits",
                "8",
                "--private-value",
                private_value,
                "--epoch",
                epoch,
                "--challenge-nonce",
                challenge,
                "--now-ms",
                "1700000000000",
                "--output",
                &bundle_arg,
                "--json",
            ],
        );
        let issued_params = issued["params_sha256"]
            .as_str()
            .expect("issued params hash");
        assert_eq!(issued["bundle"]["policy"]["policy_id"], "same-policy-id");
        if label == "trusted" {
            trusted_params = issued_params.to_owned();
            trusted_bundle_path.clone_from(&bundle_arg);
        } else {
            assert_ne!(issued_params, trusted_params, "variant={label}");
        }

        if label == "weaker" {
            // An attacker may advertise its own pin inside the candidate. It
            // cannot replace the separately supplied verifier expectation.
            let mut candidate = issued["bundle"].clone();
            candidate["trusted_params_sha256"] = json!(issued_params);
            std::fs::write(
                &bundle_path,
                serde_json::to_vec(&candidate).expect("candidate JSON"),
            )
            .expect("write candidate pin");
        }

        // Positive control: each proof is cryptographically valid when its
        // complete statement is explicitly approved by the caller.
        let own_statement = json_ok(
            dir.path(),
            &[
                "verify",
                "zk-attestation",
                &bundle_arg,
                "--trusted-params-sha256",
                issued_params,
                "--now-ms",
                "1700000000001",
                "--json",
            ],
        );
        assert_eq!(own_statement["verified"], true);
        assert_eq!(own_statement["verified_params_sha256"], issued_params);

        if label != "trusted" {
            for (candidate, expected_pin) in [
                (bundle_arg.as_str(), trusted_params.as_str()),
                (trusted_bundle_path.as_str(), issued_params),
            ] {
                let rejected = json_fail(
                    dir.path(),
                    &[
                        "verify",
                        "zk-attestation",
                        candidate,
                        "--trusted-params-sha256",
                        expected_pin,
                        "--now-ms",
                        "1700000000001",
                        "--json",
                    ],
                );
                assert_eq!(rejected["verified"], false, "variant={label}");
                assert_eq!(rejected["error_code"], "ERR_ZKA_POLICY_MISMATCH");
                assert!(rejected.get("verified_params_sha256").is_none());
            }
        }
    }
}

#[test]
fn zk_verify_requires_canonical_external_pin_before_reading_candidate() {
    let dir = tempfile::tempdir().expect("tempdir");
    let missing_bundle = dir.path().join("not-present.json").display().to_string();
    let mut cases = vec![vec![
        "verify".to_owned(),
        "zk-attestation".to_owned(),
        missing_bundle.clone(),
        "--json".to_owned(),
    ]];
    for malformed in [
        String::new(),
        "a".repeat(63),
        "a".repeat(65),
        "A".repeat(64),
        "g".repeat(64),
        format!("sha256:{}", "a".repeat(64)),
        format!(" {}", "a".repeat(64)),
    ] {
        cases.push(vec![
            "verify".to_owned(),
            "zk-attestation".to_owned(),
            missing_bundle.clone(),
            "--trusted-params-sha256".to_owned(),
            malformed,
            "--json".to_owned(),
        ]);
    }
    for arguments in cases {
        let borrowed: Vec<_> = arguments.iter().map(String::as_str).collect();
        let rejected = json_fail(dir.path(), &borrowed);
        assert_eq!(
            rejected["schema_version"],
            "franken-node/verify-error-cli/v1"
        );
        assert_eq!(rejected["command"], "verify.zk-attestation");
        assert_eq!(rejected["ok"], false);
        let message = rejected["error"].as_str().expect("structured error");
        assert!(message.contains("--trusted-params-sha256"), "{message}");
        assert!(!message.contains("failed reading"), "{message}");
        assert!(rejected.get("verified_params_sha256").is_none());
    }
}
