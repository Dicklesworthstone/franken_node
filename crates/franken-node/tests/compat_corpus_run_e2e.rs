//! bd-kfseq — genuine compatibility-corpus lockstep runner.
//!
//! Two layers of coverage:
//! 1. Pure contract tests over `ops::compat_corpus_run` — manifest discovery
//!    validation (fail-closed on malformed corpora) and the results-document
//!    builder (digest binding, totals re-derivation, honest gate evaluation,
//!    ratchet baseline semantics, evidence-block carry-forward).
//! 2. A mock-free e2e that drives the real `franken-node ops
//!    compat-corpus-run` binary over a tiny two-case corpus: bun reference
//!    leg vs the native engine leg, adjudicated by the real oracle. Skipped
//!    when bun is not on PATH (the producer itself fails closed there).

use frankenengine_node::ops::close_condition::{
    COMPATIBILITY_CORPUS_ONLINE_PROVENANCE, compute_compatibility_corpus_result_digest,
};
use frankenengine_node::ops::compat_corpus_run::{
    CaseOutcome, build_corpus_results_document, discover_corpus,
};
use serde_json::{Value, json};
use std::path::Path;

fn write_family(
    root: &Path,
    dir_name: &str,
    family: &str,
    bead: &str,
    cases: &[(&str, &str, &str, &str, &str)],
) {
    let dir = root.join(dir_name);
    std::fs::create_dir_all(&dir).expect("create family dir");
    let mut manifest_cases = Vec::new();
    for (id, file, source, band, risk) in cases {
        std::fs::write(dir.join(file), source).expect("write case file");
        manifest_cases.push(json!({
            "id": id,
            "file": file,
            "api": "test.api",
            "requirement": "test requirement",
            "divergence_axes": ["output", "exit"],
            "band": band,
            "risk_band": risk,
        }));
    }
    let manifest = json!({
        "schema_version": "compat-corpus-fixture-v1",
        "api_family": family,
        "investigation_bead_id": bead,
        "cases": manifest_cases,
    });
    std::fs::write(
        dir.join("manifest.json"),
        serde_json::to_string_pretty(&manifest).expect("render manifest"),
    )
    .expect("write manifest");
}

#[test]
fn discover_corpus_resolves_valid_families_sorted() {
    let root = tempfile::TempDir::new().expect("tempdir");
    write_family(
        root.path(),
        "beta",
        "path",
        "bd-test1",
        &[(
            "tc::path::0001",
            "a.js",
            "console.log(1);\n",
            "core",
            "critical",
        )],
    );
    write_family(
        root.path(),
        "alpha",
        "fs",
        "bd-test2",
        &[("tc::fs::0001", "b.js", "console.log(2);\n", "edge", "low")],
    );
    let cases = discover_corpus(root.path()).expect("discover");
    assert_eq!(cases.len(), 2);
    // Sorted by directory name: alpha (fs) before beta (path).
    assert_eq!(cases[0].test_id, "tc::fs::0001");
    assert_eq!(cases[0].api_family, "fs");
    assert_eq!(cases[0].investigation_bead_id.as_deref(), Some("bd-test2"));
    assert_eq!(cases[1].test_id, "tc::path::0001");
}

#[test]
fn discover_corpus_refuses_duplicate_ids_across_families() {
    let root = tempfile::TempDir::new().expect("tempdir");
    write_family(
        root.path(),
        "one",
        "fs",
        "bd-x",
        &[("tc::dup::0001", "a.js", "console.log(1);\n", "core", "high")],
    );
    write_family(
        root.path(),
        "two",
        "path",
        "bd-x",
        &[("tc::dup::0001", "b.js", "console.log(2);\n", "core", "high")],
    );
    let err = discover_corpus(root.path()).expect_err("duplicate ids must refuse");
    assert!(err.to_string().contains("duplicate corpus case id"));
}

#[test]
fn discover_corpus_refuses_invalid_band_and_traversal_and_missing_file() {
    let root = tempfile::TempDir::new().expect("tempdir");
    write_family(
        root.path(),
        "bad-band",
        "fs",
        "bd-x",
        &[("tc::fs::0001", "a.js", "console.log(1);\n", "mega", "high")],
    );
    let err = discover_corpus(root.path()).expect_err("invalid band must refuse");
    assert!(err.to_string().contains("invalid band"));

    let root = tempfile::TempDir::new().expect("tempdir");
    write_family(
        root.path(),
        "trav",
        "fs",
        "bd-x",
        &[("tc::fs::0001", "a.js", "console.log(1);\n", "core", "high")],
    );
    // Rewrite the manifest with a traversal path after the helper validated one.
    let manifest = json!({
        "schema_version": "compat-corpus-fixture-v1",
        "api_family": "fs",
        "cases": [{"id": "tc::fs::0002", "file": "../escape.js", "band": "core", "risk_band": "high"}],
    });
    std::fs::write(
        root.path().join("trav/manifest.json"),
        serde_json::to_string(&manifest).expect("render"),
    )
    .expect("write");
    let err = discover_corpus(root.path()).expect_err("traversal must refuse");
    assert!(err.to_string().contains("must stay within"));

    let root = tempfile::TempDir::new().expect("tempdir");
    let dir = root.path().join("missing");
    std::fs::create_dir_all(&dir).expect("mkdir");
    let manifest = json!({
        "schema_version": "compat-corpus-fixture-v1",
        "api_family": "fs",
        "cases": [{"id": "tc::fs::0003", "file": "ghost.js", "band": "core", "risk_band": "high"}],
    });
    std::fs::write(
        dir.join("manifest.json"),
        serde_json::to_string(&manifest).expect("render"),
    )
    .expect("write");
    let err = discover_corpus(root.path()).expect_err("missing fixture must refuse");
    assert!(err.to_string().contains("fixture missing"));
}

fn outcome(
    test_id: &str,
    family: &str,
    band: &str,
    risk: &str,
    status: &'static str,
    bead: Option<&str>,
) -> CaseOutcome {
    CaseOutcome {
        test_id: test_id.to_string(),
        api_family: family.to_string(),
        band: band.to_string(),
        risk_band: risk.to_string(),
        status,
        failure_reason: (status == "fail")
            .then(|| "lockstep divergence: output mismatch vs bun reference".to_string()),
        investigation_bead_id: bead.map(str::to_string),
    }
}

#[test]
fn document_builder_binds_digest_and_rederives_totals_honestly() {
    let outcomes = vec![
        outcome(
            "tc::fs::0001",
            "fs",
            "core",
            "critical",
            "pass",
            Some("bd-a"),
        ),
        outcome("tc::fs::0002", "fs", "core", "high", "fail", Some("bd-a")),
        outcome(
            "tc::path::0001",
            "path",
            "high-value",
            "medium",
            "pass",
            Some("bd-b"),
        ),
        outcome(
            "tc::path::0002",
            "path",
            "edge",
            "low",
            "pass",
            Some("bd-b"),
        ),
    ];
    let doc = build_corpus_results_document(
        None,
        &outcomes,
        "compat-corpus-v1-testtesttest",
        "1.3.14",
        "2026-07-12T00:00:00Z",
        "corpus",
    )
    .expect("build document");

    assert_eq!(doc["totals"]["total_test_cases"], 4);
    assert_eq!(doc["totals"]["passed_test_cases"], 3);
    assert_eq!(doc["totals"]["failed_test_cases"], 1);
    assert_eq!(doc["totals"]["errored_test_cases"], 0);
    assert_eq!(doc["totals"]["overall_pass_rate_pct"], 75.0);
    assert_eq!(
        doc["corpus"]["provenance"],
        COMPATIBILITY_CORPUS_ONLINE_PROVENANCE
    );

    // The declared digest must recompute from the emitted per_test_results.
    let rows = doc["per_test_results"].as_array().expect("rows").clone();
    let recomputed = compute_compatibility_corpus_result_digest(&rows);
    assert_eq!(
        doc["corpus"]["result_digest"].as_str(),
        Some(recomputed.as_str())
    );

    // Honest gate evaluation: 75% < 95% => blocked with a measured reason.
    assert_eq!(doc["ci_gate"]["threshold_met"], false);
    assert_eq!(doc["ci_gate"]["release_blocked"], true);
    let reason = doc["ci_gate"]["release_blocked_reason"]
        .as_str()
        .expect("reason");
    assert!(
        reason.contains("75.00%"),
        "measured rate in reason: {reason}"
    );

    // Tracking entries cover exactly the failing tests, bound to the family bead.
    let tracking = doc["failing_tests_tracking"].as_array().expect("tracking");
    assert_eq!(tracking.len(), 1);
    assert_eq!(tracking[0]["test_id"], "tc::fs::0002");
    assert_eq!(tracking[0]["investigation_bead_id"], "bd-a");
    assert_eq!(tracking[0]["investigation_status"], "open");

    // First genuine run: the ratchet baseline resets with an explicit note.
    assert_eq!(doc["previous_release"]["overall_pass_rate_pct"], 75.0);
    assert!(
        doc["previous_release"]["note"]
            .as_str()
            .expect("note")
            .contains("first genuine lockstep-oracle-run baseline")
    );
    assert_eq!(doc["ci_gate"]["regression_detected"], false);
}

#[test]
fn document_builder_ratchets_only_against_genuine_previous_runs() {
    // Prior artifact with AUTHORED provenance: not a valid ratchet floor.
    let authored_existing = json!({
        "corpus": {"provenance": "authored-fixture-expectations",
                    "franken_node_version": "0.1.0-dev", "corpus_version": "old"},
        "totals": {"overall_pass_rate_pct": 98.75},
        "proof_carrying_effects": {"schema_version": "franken-node/l1-proof-carrying-effects/v2"},
    });
    let outcomes = vec![outcome(
        "tc::fs::0001",
        "fs",
        "core",
        "critical",
        "pass",
        None,
    )];
    let doc = build_corpus_results_document(
        Some(&authored_existing),
        &outcomes,
        "v",
        "1.3.14",
        "2026-07-12T00:00:00Z",
        "corpus",
    )
    .expect("build");
    assert_eq!(doc["ci_gate"]["regression_detected"], false);
    assert!(doc["previous_release"]["note"].is_string());
    // Evidence carry-forward: the proof block survives the rewrite verbatim.
    assert_eq!(
        doc["proof_carrying_effects"]["schema_version"],
        "franken-node/l1-proof-carrying-effects/v2"
    );

    // Prior artifact with GENUINE provenance and a higher rate: regression.
    let genuine_existing = json!({
        "corpus": {"provenance": COMPATIBILITY_CORPUS_ONLINE_PROVENANCE,
                    "franken_node_version": "0.1.0-dev", "corpus_version": "prev"},
        "totals": {"overall_pass_rate_pct": 99.0},
    });
    let doc = build_corpus_results_document(
        Some(&genuine_existing),
        &outcomes,
        "v",
        "1.3.14",
        "2026-07-12T00:00:00Z",
        "corpus",
    )
    .expect("build");
    assert_eq!(doc["previous_release"]["overall_pass_rate_pct"], 99.0);
    assert_eq!(doc["previous_release"]["corpus_version"], "prev");
    // 100% >= 99% => no regression this way round.
    assert_eq!(doc["ci_gate"]["regression_detected"], false);

    let failing = vec![
        outcome("tc::fs::0001", "fs", "core", "critical", "pass", None),
        outcome("tc::fs::0002", "fs", "core", "critical", "fail", None),
    ];
    let doc = build_corpus_results_document(
        Some(&genuine_existing),
        &failing,
        "v",
        "1.3.14",
        "2026-07-12T00:00:00Z",
        "corpus",
    )
    .expect("build");
    // 50% < 99% previous genuine rate => regression detected and blocked.
    assert_eq!(doc["ci_gate"]["regression_detected"], true);
    assert_eq!(doc["ci_gate"]["release_blocked"], true);
}

#[test]
fn document_builder_refuses_empty_and_unknown_statuses() {
    let err = build_corpus_results_document(None, &[], "v", "b", "t", "c")
        .expect_err("empty outcomes must refuse");
    assert!(err.to_string().contains("zero outcomes"));

    let bad = vec![outcome("tc::x::0001", "fs", "core", "high", "skip", None)];
    let err = build_corpus_results_document(None, &bad, "v", "b", "t", "c")
        .expect_err("unknown status must refuse");
    assert!(err.to_string().contains("unexpected status"));
}

/// Mock-free e2e: the real binary runs a tiny corpus across bun and the
/// native engine and emits a genuine, digest-bound artifact.
#[cfg(feature = "engine")]
#[test]
fn compat_corpus_run_cli_emits_genuine_digest_bound_artifact() {
    let bun_available = std::process::Command::new("bun")
        .arg("--version")
        .output()
        .is_ok_and(|output| output.status.success());
    if !bun_available {
        eprintln!(
            "SKIP compat_corpus_run_cli_emits_genuine_digest_bound_artifact: \
             bun is not on PATH; the corpus reference leg requires it"
        );
        return;
    }

    let work = tempfile::TempDir::new().expect("tempdir");
    let corpus_root = work.path().join("corpus");
    write_family(
        &corpus_root,
        "path",
        "path",
        "bd-e2e-corpus",
        &[
            (
                "tc::path::0001",
                "pure_compute.js",
                "const xs=[];for(let i=1;i<=3;i++)xs.push(i*i);console.log('r:'+xs.join(','));\n",
                "core",
                "critical",
            ),
            (
                "tc::path::0002",
                "runtime_fingerprint.js",
                "console.log(typeof Bun);\n",
                "core",
                "high",
            ),
        ],
    );

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_franken-node"))
        .args([
            "ops",
            "compat-corpus-run",
            "--corpus-root",
            "corpus",
            "--out",
            "artifacts/corpus_results.json",
            "--json",
        ])
        .current_dir(work.path())
        .output()
        .expect("spawn compat-corpus-run");
    assert!(
        output.status.success(),
        "compat-corpus-run failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let artifact: Value = serde_json::from_str(
        &std::fs::read_to_string(work.path().join("artifacts/corpus_results.json"))
            .expect("read artifact"),
    )
    .expect("parse artifact");

    assert_eq!(
        artifact["corpus"]["provenance"],
        COMPATIBILITY_CORPUS_ONLINE_PROVENANCE
    );
    assert_eq!(artifact["totals"]["total_test_cases"], 2);
    assert_eq!(artifact["totals"]["errored_test_cases"], 0);

    // The digest must recompute from the emitted rows (the same check the
    // close-condition L1 leg and the Python gate perform).
    let rows = artifact["per_test_results"]
        .as_array()
        .expect("rows")
        .clone();
    let recomputed = compute_compatibility_corpus_result_digest(&rows);
    assert_eq!(
        artifact["corpus"]["result_digest"].as_str(),
        Some(recomputed.as_str())
    );

    // Genuinely measured statuses: the pure-compute case agrees across
    // runtimes; the deliberate reference-runtime fingerprint differs and
    // must be a measured fail bound to the family's investigation bead.
    let status_of = |id: &str| {
        rows.iter()
            .find(|row| row["test_id"] == id)
            .map(|row| row["status"].as_str().expect("status").to_string())
            .expect("row present")
    };
    assert_eq!(status_of("tc::path::0001"), "pass");
    assert_eq!(status_of("tc::path::0002"), "fail");
    let tracking = artifact["failing_tests_tracking"]
        .as_array()
        .expect("tracking");
    assert!(
        tracking
            .iter()
            .any(|entry| entry["test_id"] == "tc::path::0002"
                && entry["investigation_bead_id"] == "bd-e2e-corpus"),
        "failing case must be tracked against the family bead: {tracking:?}"
    );

    // Honest gate state for a 50% run: blocked, no fabricated pass.
    assert_eq!(artifact["ci_gate"]["threshold_met"], false);
    assert_eq!(artifact["ci_gate"]["release_blocked"], true);
}
