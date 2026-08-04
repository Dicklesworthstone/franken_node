use ed25519_dalek::SigningKey;
use frankenengine_node::ops::close_condition::{
    CloseConditionReceipt, CloseConditionSigningMaterial, OracleColor,
    generate_close_condition_receipt,
};
use std::fs;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

struct FixtureRoot {
    _temp_dir: TempDir,
    root: PathBuf,
}

impl FixtureRoot {
    fn path(&self) -> &Path {
        &self.root
    }
}

fn write_fixture(path: &Path, contents: &str) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("fixture parent directory");
    }
    fs::write(path, contents).expect("fixture file");
}

/// bd-qr5i2.4: a genuine, re-derivable v2 proof-carrying evidence block (v1
/// declared-summary acceptance is retired; the L1 gate re-derives the
/// embedded chain).
fn l1_v2_proof_block() -> serde_json::Value {
    use frankenengine_node::runtime::effect_receipt::{
        EffectKind, EffectReceipt, EffectReceiptChain,
    };
    use frankenengine_node::storage::cas::content_hash;

    let mut chain = EffectReceiptChain::new();
    for (seq, kind) in [
        (0_u64, EffectKind::FsRead),
        (1, EffectKind::FsWrite),
        (2, EffectKind::HttpRequest),
    ] {
        let receipt = EffectReceipt::allowed(
            seq,
            "close-condition-path-gate",
            kind,
            "cap-l1-acceptance",
            content_hash(b"pre-state"),
            content_hash(b"args"),
            content_hash(b"result"),
            content_hash(b"post-state"),
            1_774_000_000_000,
        );
        chain.append(receipt).expect("append acceptance receipt");
    }
    serde_json::json!({
        "schema_version": "franken-node/l1-proof-carrying-effects/v2",
        "required_subjects": ["fs.read", "fs.write", "http.request"],
        "verified_subjects": ["fs.read", "fs.write", "http.request"],
        "effect_receipts_verified": 3,
        "invalid_receipts": 0,
        "receipt_chain_verified": true,
        "receipt_chain_entries": chain.entries()
    })
}

/// bd-ry7d1: a lockstep verdict block built through the real nversion-oracle
/// API so the L1 leg of these L2-focused regressions re-derives GREEN.
fn l1_lockstep_verdict_block() -> serde_json::Value {
    use frankenengine_node::runtime::nversion_oracle::{
        BoundaryScope, RuntimeEntry, RuntimeOracle,
    };

    let mut oracle = RuntimeOracle::new("l1-lockstep:path-gate-regressions", 100);
    for (id, is_reference) in [("bun", true), ("franken-engine-native", false)] {
        oracle
            .register_runtime(RuntimeEntry {
                runtime_id: id.to_string(),
                runtime_name: id.to_string(),
                version: "fixture".to_string(),
                is_reference,
            })
            .expect("register runtime");
    }
    let mut outputs = std::collections::BTreeMap::new();
    outputs.insert("bun".to_string(), b"l1-lockstep:ok\n".to_vec());
    outputs.insert(
        "franken-engine-native".to_string(),
        b"l1-lockstep:ok\n".to_vec(),
    );
    oracle
        .run_cross_check(
            "l1-lockstep:path-gate-regressions:check-0",
            BoundaryScope::IO,
            b"guest-src",
            &outputs,
        )
        .expect("cross check");
    let report = oracle.generate_report(1_774_000_000);
    serde_json::json!({
        "schema_version": "franken-node/l1-lockstep-verdict/v1",
        "trace_id": report.trace_id,
        "produced_at": "2026-07-10T00:00:00+00:00",
        "producer": "close-condition-path-gate-regressions",
        "guest_program_content_hash":
            frankenengine_node::storage::cas::content_hash(b"guest-src").as_str(),
        "runtimes": report.runtimes.keys().cloned().collect::<Vec<_>>(),
        "oracle_verdict": report.verdict.label(),
        "checks_total": report.checks.len(),
        "divergence_count": report.divergences.len(),
        "report": report,
    })
}

fn fixture_root_with_engine_paths(engine_path: &str, extension_host_path: &str) -> FixtureRoot {
    let temp_dir = TempDir::new().expect("fixture root");
    let root = temp_dir.path().join("workspace/franken_node");
    let engine_crates = temp_dir.path().join("workspace/franken_engine/crates");
    fs::create_dir_all(engine_crates.join("franken-engine")).expect("fixture engine crate");
    fs::create_dir_all(engine_crates.join("franken-extension-host"))
        .expect("fixture extension-host crate");

    write_fixture(
        &root.join("Cargo.toml"),
        r#"
[workspace]
members = ["crates/franken-node"]
"#,
    );
    write_fixture(
        &root.join("crates/franken-node/Cargo.toml"),
        &format!(
            r#"
[package]
name = "fixture-franken-node"
version = "0.1.0"
edition = "2024"

[dependencies]
frankenengine-engine = {{ path = "{engine_path}" }}
frankenengine-extension-host = {{ path = "{extension_host_path}" }}
"#
        ),
    );
    write_fixture(
        &root.join("crates/franken-node/src/lib.rs"),
        "pub fn fixture() -> bool { true }\n",
    );
    write_fixture(
        &root.join("docs/ENGINE_SPLIT_CONTRACT.md"),
        "franken_engine path dependencies MUST NOT be replaced by local engine crates.\n",
    );
    write_fixture(
        &root.join("docs/PRODUCT_CHARTER.md"),
        "Dual-oracle close condition requires all dimensions to be green.\n",
    );
    // bd-qr5i2.4: v1 declared-summary acceptance is retired; keep L1 GREEN
    // with v2 evidence carrying a genuine re-derivable receipt chain so these
    // regressions keep isolating the L2 path-gate behavior.
    // bd-ihusm: L1 also requires a genuine-oracle-run provenance plus a
    // digest-bound per-test result set, so the GREEN baseline carries both.
    let per_test_results: Vec<serde_json::Value> = (0..100)
        .map(|index| {
            serde_json::json!({
                "test_id": format!("tc::fs::{index:04}"),
                "api_family": "fs",
                "band": "core",
                "risk_band": "critical",
                "status": if index < 98 { "pass" } else { "fail" },
            })
        })
        .collect();
    let corpus = serde_json::json!({
        "corpus": {
            "corpus_version": "compat-corpus-test",
            "provenance": frankenengine_node::ops::close_condition::COMPATIBILITY_CORPUS_ONLINE_PROVENANCE,
            "result_digest": frankenengine_node::ops::close_condition::compute_compatibility_corpus_result_digest(&per_test_results),
        },
        "proof_carrying_effects": l1_v2_proof_block(),
        "thresholds": { "overall_pass_rate_min_pct": 95.0 },
        "totals": {
            "total_test_cases": 100,
            "passed_test_cases": 98,
            "failed_test_cases": 2,
            "errored_test_cases": 0,
            "skipped_test_cases": 0,
            "overall_pass_rate_pct": 98.0
        },
        "per_test_results": per_test_results
    });
    write_fixture(
        &root.join("artifacts/13/compatibility_corpus_results.json"),
        &serde_json::to_string_pretty(&corpus).expect("corpus fixture render"),
    );
    // bd-ry7d1: the gate also consumes the L1 verdict artifact (the file the
    // Python CI gate reads) and binds its proof-carrying copy to the corpus
    // copy, so the GREEN baseline for these L2 path-gate regressions carries
    // both, bound together, plus a re-derivable lockstep verdict.
    write_fixture(
        &root.join("artifacts/oracle/l1_product_verdict.json"),
        &serde_json::to_string_pretty(&serde_json::json!({
            "dimension": "l1_product",
            "verdict": "GREEN",
            "owner_track": "10.2",
            "timestamp": "2026-07-10T00:00:00+00:00",
            "evidence": {
                "proof_carrying_effects": corpus["proof_carrying_effects"].clone(),
                "lockstep_verdict": l1_lockstep_verdict_block(),
            },
        }))
        .expect("verdict artifact render"),
    );
    write_fixture(
        &root.join("artifacts/section/10.N/gate_verdict/bd-1neb_section_gate.json"),
        r#"{
  "gate": "section_10n_verification",
  "checks": [
    {
      "check_id": "10N-ORACLE",
      "name": "Dual-Oracle Close Condition Gate",
      "status": "PASS"
    }
  ]
}"#,
    );
    FixtureRoot {
        _temp_dir: temp_dir,
        root,
    }
}

fn generate_fixture_receipt(root: &Path) -> CloseConditionReceipt {
    let seed = [73_u8; 32];
    let signing_key = SigningKey::from_bytes(&seed);
    let signing_material = CloseConditionSigningMaterial {
        signing_key: &signing_key,
        key_source: "test-seed",
        signing_identity: "close-condition-path-gate-regression",
    };

    generate_close_condition_receipt(root, &signing_material).expect("close-condition receipt")
}

fn split_path_dependency_check_status(receipt: &CloseConditionReceipt) -> OracleColor {
    receipt
        .core
        .l2_engine_boundary_oracle
        .checks
        .iter()
        .find(|check| check.id == "SPLIT-PATH-DEPS")
        .expect("path dependency check")
        .status
        .clone()
}

fn split_no_internals_check_status(receipt: &CloseConditionReceipt) -> OracleColor {
    receipt
        .core
        .l2_engine_boundary_oracle
        .checks
        .iter()
        .find(|check| check.id == "SPLIT-NO-INTERNALS")
        .expect("no internals check")
        .status
        .clone()
}

mod ops {
    pub mod close_condition {
        use super::super::*;

        #[test]
        fn valid_engine_path_dependencies_are_accepted_with_canonical_sibling_crates() {
            let root = fixture_root_with_engine_paths(
                "../../../franken_engine/crates/franken-engine",
                "../../../franken_engine/crates/franken-extension-host",
            );
            let receipt = generate_fixture_receipt(root.path());

            assert_eq!(receipt.core.composite_verdict, OracleColor::Green);
            assert_eq!(
                split_path_dependency_check_status(&receipt),
                OracleColor::Green
            );
        }

        #[test]
        fn traversal_shaped_engine_path_dependencies_are_rejected() {
            let root = fixture_root_with_engine_paths(
                "../../../franken_engine/crates/../../evil",
                "../../../franken_engine/crates/franken-extension-host",
            );
            let receipt = generate_fixture_receipt(root.path());

            assert_eq!(receipt.core.composite_verdict, OracleColor::Red);
            assert_eq!(
                split_path_dependency_check_status(&receipt),
                OracleColor::Red
            );
            assert!(
                receipt
                    .core
                    .l2_engine_boundary_oracle
                    .blocking_findings
                    .iter()
                    .any(|finding| finding == "SPLIT-PATH-DEPS failed")
            );
        }

        #[test]
        fn substring_lookalike_engine_path_dependencies_are_rejected() {
            let root = fixture_root_with_engine_paths(
                "../../../not_franken_engine/crates/franken-engine",
                "../../../franken_engine/crates_but_not_really/franken-extension-host",
            );
            let receipt = generate_fixture_receipt(root.path());

            assert_eq!(receipt.core.composite_verdict, OracleColor::Red);
            assert_eq!(
                split_path_dependency_check_status(&receipt),
                OracleColor::Red
            );
        }

        #[test]
        fn string_literals_named_like_engine_internal_imports_are_not_violations() {
            let root = fixture_root_with_engine_paths(
                "../../../franken_engine/crates/franken-engine",
                "../../../franken_engine/crates/franken-extension-host",
            );
            write_fixture(
                &root.path().join("crates/franken-node/src/lib.rs"),
                r#"
pub const ENGINE_INTERNAL_IMPORT_EXAMPLE: &str = "use frankenengine_engine::internal";
pub const ENGINE_INTERNAL_MODULE_EXAMPLE: &str = "mod franken_engine";
pub fn fixture() -> bool { true }
"#,
            );

            let receipt = generate_fixture_receipt(root.path());

            assert_eq!(
                split_no_internals_check_status(&receipt),
                OracleColor::Green
            );
            assert!(
                receipt
                    .core
                    .l2_engine_boundary_oracle
                    .blocking_findings
                    .iter()
                    .all(|finding| finding != "SPLIT-NO-INTERNALS failed")
            );
        }
    }
}
