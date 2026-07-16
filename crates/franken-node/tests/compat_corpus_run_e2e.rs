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
    CaseOutcome, MAX_CASE_FILE_BYTES, MAX_SUPPORT_FILES_PER_FAMILY, MAX_SUPPORT_FILES_TOTAL,
    MAX_SUPPORT_TOTAL_BYTES, build_corpus_results_document, content_addressed_corpus_version,
    discover_corpus, snapshot_corpus,
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
        let case_path = dir.join(file);
        if let Some(parent) = case_path.parent() {
            std::fs::create_dir_all(parent).expect("create case parent");
        }
        std::fs::write(case_path, source).expect("write case file");
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

fn write_manifest_only(root: &Path, dir_name: &str, id: &str, file: &str) {
    let dir = root.join(dir_name);
    std::fs::create_dir_all(&dir).expect("create manifest-only family");
    let manifest = json!({
        "schema_version": "compat-corpus-fixture-v1",
        "api_family": "stream",
        "investigation_bead_id": "bd-nc5b8",
        "cases": [{
            "id": id,
            "file": file,
            "band": "core",
            "risk_band": "critical",
        }],
    });
    std::fs::write(
        dir.join("manifest.json"),
        serde_json::to_vec_pretty(&manifest).expect("render manifest-only family"),
    )
    .expect("write manifest-only family");
}

#[cfg(unix)]
#[test]
fn snapshot_refuses_case_parent_and_support_symlinks() {
    use std::os::unix::fs::symlink;

    let outside = tempfile::TempDir::new().expect("outside tempdir");
    std::fs::write(outside.path().join("case.mjs"), "console.log('outside');\n")
        .expect("write outside case");

    let manifest_link = tempfile::TempDir::new().expect("manifest-link tempdir");
    let manifest_family = manifest_link.path().join("stream");
    std::fs::create_dir_all(&manifest_family).expect("create manifest-link family");
    let outside_manifest = json!({
        "schema_version": "compat-corpus-fixture-v1",
        "api_family": "stream",
        "cases": [{
            "id": "tc::stream::manifest-link",
            "file": "case.mjs",
            "band": "core",
            "risk_band": "critical",
        }],
    });
    std::fs::write(
        outside.path().join("manifest.json"),
        serde_json::to_vec(&outside_manifest).expect("render outside manifest"),
    )
    .expect("write outside manifest");
    symlink(
        outside.path().join("manifest.json"),
        manifest_family.join("manifest.json"),
    )
    .expect("symlink manifest");
    let error = discover_corpus(manifest_link.path()).expect_err("manifest symlink must refuse");
    assert!(error.to_string().contains("non-symlink manifest"));

    let direct = tempfile::TempDir::new().expect("direct tempdir");
    write_manifest_only(direct.path(), "stream", "tc::stream::direct", "case.mjs");
    symlink(
        outside.path().join("case.mjs"),
        direct.path().join("stream/case.mjs"),
    )
    .expect("symlink direct case");
    let cases = discover_corpus(direct.path()).expect("discover direct symlink case");
    let error = snapshot_corpus(direct.path(), &cases).expect_err("direct symlink must refuse");
    assert!(error.to_string().contains("symlink component"));

    let parent = tempfile::TempDir::new().expect("parent tempdir");
    write_manifest_only(
        parent.path(),
        "stream",
        "tc::stream::parent",
        "nested/case.mjs",
    );
    symlink(outside.path(), parent.path().join("stream/nested")).expect("symlink parent directory");
    let cases = discover_corpus(parent.path()).expect("discover parent symlink case");
    let error = snapshot_corpus(parent.path(), &cases).expect_err("parent symlink must refuse");
    assert!(error.to_string().contains("symlink component"));

    let support = tempfile::TempDir::new().expect("support tempdir");
    write_version_family(
        support.path(),
        "stream",
        "tc::stream::support",
        "console.log('case');\n",
    );
    symlink(
        outside.path().join("case.mjs"),
        support.path().join("stream/_support.mjs"),
    )
    .expect("symlink support file");
    let cases = discover_corpus(support.path()).expect("discover support symlink corpus");
    let error = snapshot_corpus(support.path(), &cases).expect_err("support symlink must refuse");
    assert!(error.to_string().contains("non-symlink"));
}

#[test]
fn snapshot_refuses_case_support_staging_collision() {
    let root = tempfile::TempDir::new().expect("tempdir");
    write_family(
        root.path(),
        "stream",
        "stream",
        "bd-nc5b8",
        &[(
            "tc::stream::collision",
            "_support.mjs",
            "console.log('case');\n",
            "core",
            "critical",
        )],
    );
    let cases = discover_corpus(root.path()).expect("discover collision corpus");
    let error = snapshot_corpus(root.path(), &cases).expect_err("collision must refuse");
    assert!(error.to_string().contains("case/support staging collision"));
}

#[test]
fn snapshot_freezes_case_and_support_bytes_after_capture() {
    let root = tempfile::TempDir::new().expect("tempdir");
    write_version_family(
        root.path(),
        "stream",
        "tc::stream::freeze",
        "console.log('before');\n",
    );
    std::fs::write(
        root.path().join("stream/_support.mjs"),
        "export const value = 'before';\n",
    )
    .expect("write original support");
    let cases = discover_corpus(root.path()).expect("discover freeze corpus");
    let snapshot = snapshot_corpus(root.path(), &cases).expect("capture snapshot");
    let captured_version =
        content_addressed_corpus_version(&snapshot).expect("hash captured snapshot");

    std::fs::write(
        root.path().join("stream/case.mjs"),
        "console.log('after');\n",
    )
    .expect("mutate case after snapshot");
    std::fs::write(
        root.path().join("stream/_support.mjs"),
        "export const value = 'after';\n",
    )
    .expect("mutate support after snapshot");

    assert_eq!(
        content_addressed_corpus_version(&snapshot).expect("rehash captured snapshot"),
        captured_version,
        "an existing snapshot must never re-read mutable corpus files"
    );
    let refreshed = snapshot_corpus(root.path(), &cases).expect("refresh snapshot");
    assert_ne!(
        content_addressed_corpus_version(&refreshed).expect("hash refreshed snapshot"),
        captured_version,
        "a new snapshot must observe the changed executable inputs"
    );
}

fn corpus_version(root: &Path) -> String {
    let cases = discover_corpus(root).expect("discover version fixture");
    let snapshot = snapshot_corpus(root, &cases).expect("snapshot version fixture");
    content_addressed_corpus_version(&snapshot).expect("hash version fixture")
}

fn write_version_family(root: &Path, dir_name: &str, id: &str, source: &str) {
    write_family(
        root,
        dir_name,
        "stream",
        "bd-b37oe",
        &[(id, "case.mjs", source, "core", "critical")],
    );
}

#[test]
fn corpus_version_binds_staged_support_content_and_set() {
    let without_support = tempfile::TempDir::new().expect("tempdir");
    write_version_family(
        without_support.path(),
        "stream",
        "tc::stream::0001",
        "console.log('case');\n",
    );

    let support_a = tempfile::TempDir::new().expect("tempdir");
    write_version_family(
        support_a.path(),
        "stream",
        "tc::stream::0001",
        "console.log('case');\n",
    );
    std::fs::write(
        support_a.path().join("stream/_support.mjs"),
        "export const value = 'a';\n",
    )
    .expect("write support a");

    let support_b = tempfile::TempDir::new().expect("tempdir");
    write_version_family(
        support_b.path(),
        "stream",
        "tc::stream::0001",
        "console.log('case');\n",
    );
    std::fs::write(
        support_b.path().join("stream/_support.mjs"),
        "export const value = 'b';\n",
    )
    .expect("write support b");

    let two_support_files = tempfile::TempDir::new().expect("tempdir");
    write_version_family(
        two_support_files.path(),
        "stream",
        "tc::stream::0001",
        "console.log('case');\n",
    );
    std::fs::write(
        two_support_files.path().join("stream/_support.mjs"),
        "export const value = 'a';\n",
    )
    .expect("write first support");
    std::fs::write(
        two_support_files.path().join("stream/_second.mjs"),
        "export const second = true;\n",
    )
    .expect("write second support");

    let versions = [
        corpus_version(without_support.path()),
        corpus_version(support_a.path()),
        corpus_version(support_b.path()),
        corpus_version(two_support_files.path()),
    ];
    assert_eq!(
        versions[0], "compat-corpus-v2-ba8b4bb95fd72d131fde268bf0e53106",
        "the canonical v2 framing stays byte-for-byte pinned"
    );
    assert_eq!(versions[0].len(), "compat-corpus-v2-".len() + 32);
    let unique: std::collections::BTreeSet<_> = versions.iter().collect();
    assert_eq!(
        unique.len(),
        versions.len(),
        "helper presence, content, and set must all affect the version: {versions:?}"
    );
}

#[test]
fn corpus_version_support_paths_are_relative_and_order_independent() {
    let first = tempfile::TempDir::new().expect("tempdir");
    write_version_family(
        first.path(),
        "beta",
        "tc::stream::0002",
        "console.log('beta');\n",
    );
    std::fs::write(first.path().join("beta/_z.mjs"), "export default 2;\n")
        .expect("write beta support");
    write_version_family(
        first.path(),
        "alpha",
        "tc::stream::0001",
        "console.log('alpha');\n",
    );
    std::fs::write(first.path().join("alpha/_z.mjs"), "export default 3;\n")
        .expect("write alpha z support");
    std::fs::write(first.path().join("alpha/_a.mjs"), "export default 1;\n")
        .expect("write alpha a support");

    let second = tempfile::TempDir::new().expect("tempdir");
    write_version_family(
        second.path(),
        "alpha",
        "tc::stream::0001",
        "console.log('alpha');\n",
    );
    std::fs::write(second.path().join("alpha/_a.mjs"), "export default 1;\n")
        .expect("write alpha a support");
    std::fs::write(second.path().join("alpha/_z.mjs"), "export default 3;\n")
        .expect("write alpha z support");
    write_version_family(
        second.path(),
        "beta",
        "tc::stream::0002",
        "console.log('beta');\n",
    );
    std::fs::write(second.path().join("beta/_z.mjs"), "export default 2;\n")
        .expect("write beta support");

    assert_eq!(
        corpus_version(first.path()),
        corpus_version(second.path()),
        "filesystem creation/traversal order must not affect the version"
    );

    let renamed = tempfile::TempDir::new().expect("tempdir");
    write_version_family(
        renamed.path(),
        "alpha",
        "tc::stream::0001",
        "console.log('alpha');\n",
    );
    std::fs::write(
        renamed.path().join("alpha/_renamed.mjs"),
        "export default 1;\n",
    )
    .expect("write renamed support");

    let alpha_only = tempfile::TempDir::new().expect("tempdir");
    write_version_family(
        alpha_only.path(),
        "alpha",
        "tc::stream::0001",
        "console.log('alpha');\n",
    );
    std::fs::write(
        alpha_only.path().join("alpha/_a.mjs"),
        "export default 1;\n",
    )
    .expect("write alpha-only support");

    assert_ne!(
        corpus_version(alpha_only.path()),
        corpus_version(renamed.path()),
        "the staged helper's corpus-relative path must affect the version"
    );
}

#[test]
fn corpus_version_binds_case_path_metadata_and_length_boundaries() {
    let path_a = tempfile::TempDir::new().expect("tempdir");
    write_family(
        path_a.path(),
        "stream",
        "stream",
        "bd-v1ccz",
        &[(
            "tc::stream::path",
            "a/case.mjs",
            "console.log('same');\n",
            "core",
            "critical",
        )],
    );
    let path_b = tempfile::TempDir::new().expect("tempdir");
    write_family(
        path_b.path(),
        "stream",
        "stream",
        "bd-v1ccz",
        &[(
            "tc::stream::path",
            "b/case.mjs",
            "console.log('same');\n",
            "core",
            "critical",
        )],
    );
    assert_ne!(
        corpus_version(path_a.path()),
        corpus_version(path_b.path()),
        "a behavior-relevant staged case path must affect the version"
    );

    let metadata_a = tempfile::TempDir::new().expect("tempdir");
    write_family(
        metadata_a.path(),
        "family",
        "stream",
        "bd-v1ccz",
        &[(
            "tc::metadata::0001",
            "case.mjs",
            "console.log('same');\n",
            "core",
            "critical",
        )],
    );
    let metadata_b = tempfile::TempDir::new().expect("tempdir");
    write_family(
        metadata_b.path(),
        "family",
        "timers",
        "bd-v1ccz",
        &[(
            "tc::metadata::0001",
            "case.mjs",
            "console.log('same');\n",
            "edge",
            "low",
        )],
    );
    assert_ne!(
        corpus_version(metadata_a.path()),
        corpus_version(metadata_b.path()),
        "family and gate metadata must affect the version"
    );

    // These two case records collide under the legacy delimiter framing:
    // `id='a', bytes='b\\x1f'` versus `id='a\\x1fb', bytes=''`.
    let boundary_a = tempfile::TempDir::new().expect("tempdir");
    write_version_family(boundary_a.path(), "stream", "a", "b\u{001f}");
    let boundary_b = tempfile::TempDir::new().expect("tempdir");
    write_version_family(boundary_b.path(), "stream", "a\u{001f}b", "");
    assert_ne!(
        corpus_version(boundary_a.path()),
        corpus_version(boundary_b.path()),
        "v2 length framing must separate legacy delimiter-boundary collisions"
    );
}

fn write_support_files(root: &Path, family: &str, count: usize, bytes: &[u8]) {
    for index in 0..count {
        std::fs::write(
            root.join(family).join(format!("_support_{index:03}.mjs")),
            bytes,
        )
        .expect("write bounded support fixture");
    }
}

#[test]
fn snapshot_enforces_per_family_and_global_support_count_bounds() {
    let exact = tempfile::TempDir::new().expect("tempdir");
    write_version_family(
        exact.path(),
        "stream",
        "tc::support::exact",
        "console.log('case');\n",
    );
    write_support_files(exact.path(), "stream", MAX_SUPPORT_FILES_PER_FAMILY, b"");
    let cases = discover_corpus(exact.path()).expect("discover exact support count");
    snapshot_corpus(exact.path(), &cases).expect("exact per-family support limit succeeds");

    let over_family = tempfile::TempDir::new().expect("tempdir");
    write_version_family(
        over_family.path(),
        "stream",
        "tc::support::over-family",
        "console.log('case');\n",
    );
    write_support_files(
        over_family.path(),
        "stream",
        MAX_SUPPORT_FILES_PER_FAMILY + 1,
        b"",
    );
    let cases = discover_corpus(over_family.path()).expect("discover over-family count");
    let error = snapshot_corpus(over_family.path(), &cases).expect_err("family count must refuse");
    assert!(error.to_string().contains("maximum is"));

    let over_global = tempfile::TempDir::new().expect("tempdir");
    let family_count = 3;
    let helpers_per_family = MAX_SUPPORT_FILES_TOTAL / family_count + 1;
    assert!(helpers_per_family <= MAX_SUPPORT_FILES_PER_FAMILY);
    for family_index in 0..family_count {
        let family = format!("family-{family_index}");
        let id = format!("tc::support::global::{family_index}");
        write_version_family(over_global.path(), &family, &id, "console.log('case');\n");
        write_support_files(over_global.path(), &family, helpers_per_family, b"");
    }
    let cases = discover_corpus(over_global.path()).expect("discover global count corpus");
    let error = snapshot_corpus(over_global.path(), &cases).expect_err("global count must refuse");
    assert!(error.to_string().contains("corpus has"));
}

#[test]
fn snapshot_enforces_combined_support_byte_bound() {
    assert_eq!(MAX_SUPPORT_TOTAL_BYTES % MAX_CASE_FILE_BYTES, 0);
    let files_at_limit = MAX_SUPPORT_TOTAL_BYTES / MAX_CASE_FILE_BYTES;
    let payload = vec![b'x'; MAX_CASE_FILE_BYTES];

    let exact = tempfile::TempDir::new().expect("tempdir");
    write_version_family(
        exact.path(),
        "stream",
        "tc::support-bytes::exact",
        "console.log('case');\n",
    );
    write_support_files(exact.path(), "stream", files_at_limit, &payload);
    let cases = discover_corpus(exact.path()).expect("discover exact byte corpus");
    snapshot_corpus(exact.path(), &cases).expect("exact support byte limit succeeds");

    let over = tempfile::TempDir::new().expect("tempdir");
    write_version_family(
        over.path(),
        "stream",
        "tc::support-bytes::over",
        "console.log('case');\n",
    );
    write_support_files(over.path(), "stream", files_at_limit + 1, &payload);
    let cases = discover_corpus(over.path()).expect("discover over-byte corpus");
    let error = snapshot_corpus(over.path(), &cases).expect_err("support bytes must refuse");
    assert!(error.to_string().contains("support-file snapshot exceeds"));
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

#[cfg(all(feature = "engine", unix))]
#[test]
fn compat_corpus_run_preflights_template_collisions_before_bun() {
    use std::os::unix::fs::PermissionsExt;

    let work = tempfile::TempDir::new().expect("tempdir");
    let corpus_root = work.path().join("corpus");
    write_family(
        &corpus_root,
        "collision",
        "path",
        "bd-nc5b8",
        &[
            (
                "tc::path::safe-before-collision",
                "safe.mjs",
                "console.log('must-not-run');\n",
                "core",
                "critical",
            ),
            (
                "tc::path::template-collision",
                "franken_node.toml",
                "console.log('must-not-run');\n",
                "core",
                "critical",
            ),
        ],
    );

    let fake_bin = work.path().join("fake-bin");
    std::fs::create_dir_all(&fake_bin).expect("create fake bin");
    let fake_bun = fake_bin.join("bun");
    std::fs::write(
        &fake_bun,
        "#!/bin/sh\nprintf invoked > \"$BUN_MARKER\"\nexit 99\n",
    )
    .expect("write fake bun");
    let mut permissions = std::fs::metadata(&fake_bun)
        .expect("fake bun metadata")
        .permissions();
    permissions.set_mode(0o700);
    std::fs::set_permissions(&fake_bun, permissions).expect("make fake bun executable");
    let marker = work.path().join("bun-invoked");

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
        .env("PATH", &fake_bin)
        .env("BUN_MARKER", &marker)
        .output()
        .expect("spawn collision preflight");
    assert!(!output.status.success(), "template collision must refuse");
    let diagnostic = format!(
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        diagnostic.contains("would overwrite workspace template entry"),
        "unexpected collision diagnostic: {diagnostic}"
    );
    assert!(
        !marker.exists(),
        "Bun must not be invoked before all staging targets pass preflight"
    );
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
            (
                "tc::path::0003",
                "relative_support_import.mjs",
                "import { message } from './_support.mjs'; console.log(message);\n",
                "core",
                "critical",
            ),
            (
                "tc::path::0004",
                "nested/relative_support_import.mjs",
                "import { message } from '../_support.mjs'; console.log(message);\n",
                "core",
                "critical",
            ),
            (
                "tc::path::0005",
                "nested/local_support_import.mjs",
                "import { localMessage } from './_local.mjs'; console.log(localMessage);\n",
                "core",
                "critical",
            ),
            (
                "tc::path::0006",
                "nested/deep/parent_support_import.mjs",
                "import { localMessage } from '../_local.mjs'; console.log(localMessage);\n",
                "core",
                "critical",
            ),
        ],
    );
    std::fs::write(
        corpus_root.join("path/_support.mjs"),
        "export const message = 'support-ok';\n",
    )
    .expect("write staged support module");
    std::fs::write(
        corpus_root.join("path/nested/_local.mjs"),
        "export const localMessage = 'local-support-ok';\n",
    )
    .expect("write nested staged support module");

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
    assert_eq!(artifact["totals"]["total_test_cases"], 6);
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
    assert_eq!(status_of("tc::path::0003"), "pass");
    assert_eq!(status_of("tc::path::0004"), "pass");
    assert_eq!(status_of("tc::path::0005"), "pass");
    assert_eq!(status_of("tc::path::0006"), "pass");
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

    // Honest gate state for an 83.33% run: blocked, no fabricated pass.
    assert_eq!(artifact["ci_gate"]["threshold_met"], false);
    assert_eq!(artifact["ci_gate"]["release_blocked"], true);
}
