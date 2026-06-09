//! Integration conformance for the lockstep-oracle compat harness
//! (bd-f5b04.2.1.2).
//!
//! Exercises the public `api::compat_conformance` surface end-to-end against
//! the stable first-tranche contract layer (`api::compat_gate`) and the L1
//! product-oracle (`connector::n_version_oracle`). This is the normal-lane
//! (non-`#![cfg(test)]`) verification: it links the library and drives the
//! franken leg over REAL filesystem I/O in a tempdir, comparing it against the
//! deterministic spec reference, and proves the GREEN/RED signal + divergence
//! fixture emission behave as specified.
//!
//! Run: `rch exec -- cargo test -p frankenengine-node --no-default-features
//! --features control-plane --test compat_lockstep_oracle_conformance --
//! --nocapture`.

use std::collections::BTreeMap;

use frankenengine_node::api::compat_conformance::{
    CanonicalOutcome, CanonicalResult, CompatFixtureCase, CompatInput, ConformanceConfig,
    ConformanceLeg, ExternalProcessLeg, FrankenLeg, LegError, LockstepSignal, SPEC_RUNTIME_ID,
    SpecLeg, first_tranche_fixture_corpus, run_first_tranche_conformance,
    run_operation_conformance,
};
use frankenengine_node::api::compat_gate::{
    CompatOperationId, first_tranche_contract_for, first_tranche_operation_contracts,
};
use frankenengine_node::connector::n_version_oracle::ReleaseVerdict;

fn log(step: &str, detail: &str) {
    eprintln!("[compat-lockstep] {step}: {detail}");
}

#[test]
fn first_tranche_franken_vs_spec_is_green_across_all_operations() {
    let tmp = tempfile::tempdir().expect("tempdir");
    log("setup", &format!("sandbox root = {}", tmp.path().display()));
    let franken = FrankenLeg::new(tmp.path());
    let cfg = ConformanceConfig::default();

    let verdicts = run_first_tranche_conformance(&franken, &[], &cfg);
    assert_eq!(
        verdicts.len(),
        first_tranche_operation_contracts().len(),
        "one verdict per first-tranche operation"
    );

    for v in &verdicts {
        log(
            "verdict",
            &format!(
                "op={} signal={} cases={} refs={:?} divergences={}",
                v.operation_id,
                v.signal.as_str(),
                v.cases_tested,
                v.reference_runtimes,
                v.oracle.stats.total_divergences
            ),
        );
        assert_eq!(
            v.signal,
            LockstepSignal::Green,
            "operation {} must be GREEN (franken matches spec); diverged: {:?}",
            v.operation_id,
            v.diverged_boundaries
        );
        assert!(
            v.cases_tested >= 3,
            "operation {} should exercise >=3 cases, got {}",
            v.operation_id,
            v.cases_tested
        );
        assert!(
            v.reference_runtimes.iter().any(|r| r == SPEC_RUNTIME_ID),
            "spec reference leg must contribute for {}",
            v.operation_id
        );
        assert!(matches!(v.oracle.verdict, ReleaseVerdict::Passed));
        assert!(v.oracle.divergences.is_empty());
    }
}

#[test]
fn injected_divergence_yields_red_with_oracle_blocked_and_fixture_artifact() {
    // A franken leg that returns a wrong canonical outcome for every case.
    struct BrokenFranken;
    impl ConformanceLeg for BrokenFranken {
        fn runtime_id(&self) -> &str {
            "franken"
        }
        fn execute(&self, _case: &CompatFixtureCase) -> Result<CanonicalOutcome, LegError> {
            Ok(CanonicalOutcome::error("DELIBERATELY_WRONG"))
        }
    }

    let tmp = tempfile::tempdir().expect("tempdir");
    let fixtures = tmp.path().join("divergence_fixtures");
    let cfg = ConformanceConfig {
        timeout_ms: 2000,
        fixture_output_dir: Some(fixtures.clone()),
    };
    let spec = SpecLeg;
    let contract = first_tranche_contract_for(CompatOperationId::FsReadFile).expect("contract");
    let cases: Vec<CompatFixtureCase> = first_tranche_fixture_corpus()
        .into_iter()
        .filter(|c| c.operation_id() == CompatOperationId::FsReadFile)
        .collect();
    log("setup", &format!("fs.readFile cases = {}", cases.len()));

    let verdict = run_operation_conformance(contract, &cases, &BrokenFranken, &[&spec], &cfg);
    log(
        "verdict",
        &format!(
            "signal={} divergences={} emitted_fixtures={}",
            verdict.signal.as_str(),
            verdict.oracle.stats.total_divergences,
            verdict.emitted_fixtures.len()
        ),
    );

    assert_eq!(verdict.signal, LockstepSignal::Red);
    assert!(matches!(
        verdict.oracle.verdict,
        ReleaseVerdict::Blocked { .. }
    ));
    assert_eq!(verdict.diverged_boundaries.len(), cases.len());
    assert_eq!(verdict.emitted_fixtures.len(), cases.len());

    // Every emitted fixture exists on disk and round-trips as a DivergenceFixture.
    let on_disk: Vec<_> = std::fs::read_dir(&fixtures)
        .expect("fixture dir exists")
        .filter_map(Result::ok)
        .collect();
    assert_eq!(on_disk.len(), cases.len(), "one fixture per diverged case");
    for entry in on_disk {
        let bytes = std::fs::read(entry.path()).expect("read fixture");
        let parsed: serde_json::Value = serde_json::from_slice(&bytes).expect("valid json");
        assert_eq!(parsed["operation_id"], "compat:fs:readFile");
        assert_eq!(parsed["franken_outcome"]["outcome"], "error");
        assert_eq!(parsed["franken_outcome"]["code"], "DELIBERATELY_WRONG");
        // The spec reference recorded its own (correct) outcome.
        assert!(parsed["reference_outcomes"]["spec"].is_object());
    }
}

#[test]
fn missing_optional_runtime_is_skipped_not_failed() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let franken = FrankenLeg::new(tmp.path());
    let spec = SpecLeg;
    // An external leg whose binary does not exist: must be skipped, GREEN stays.
    let ghost = ExternalProcessLeg::new("ghost", "frnk-no-such-binary-xyz", tmp.path());
    let contract = first_tranche_contract_for(CompatOperationId::ProcessEnv).expect("contract");
    let cases: Vec<CompatFixtureCase> = first_tranche_fixture_corpus()
        .into_iter()
        .filter(|c| c.operation_id() == CompatOperationId::ProcessEnv)
        .collect();

    let verdict = run_operation_conformance(
        contract,
        &cases,
        &franken,
        &[&spec, &ghost],
        &ConformanceConfig::default(),
    );
    log(
        "verdict",
        &format!(
            "signal={} skipped_legs={:?} contributing_refs={:?}",
            verdict.signal.as_str(),
            verdict.skipped_legs,
            verdict.reference_runtimes
        ),
    );
    assert_eq!(verdict.signal, LockstepSignal::Green);
    assert!(verdict.skipped_legs.iter().any(|(r, _)| r == "ghost"));
    assert!(!verdict.reference_runtimes.iter().any(|r| r == "ghost"));
}

#[test]
fn franken_real_fs_roundtrip_and_node_error_parity() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let franken = FrankenLeg::new(tmp.path());

    // Real write then real read round-trip through the franken leg.
    let payload = b"real bytes on disk".to_vec();
    let write_case = CompatFixtureCase {
        case_name: "rt_write".to_string(),
        description: "write".to_string(),
        input: CompatInput::FsWrite {
            sandbox: Default::default(),
            path: "data.bin".to_string(),
            data: payload.clone(),
        },
        expected: CanonicalOutcome::Success {
            result: CanonicalResult::FsWrite {
                bytes_written: payload.len() as u64,
            },
        },
    };
    let write_outcome = franken.execute(&write_case).expect("write exec");
    assert_eq!(write_outcome, write_case.expected);
    log("fs", "write round-trip produced expected bytes_written");

    // ENOENT parity for a missing path (real stat).
    let enoent_case = CompatFixtureCase {
        case_name: "rt_enoent".to_string(),
        description: "missing".to_string(),
        input: CompatInput::FsRead {
            sandbox: Default::default(),
            path: "absent.bin".to_string(),
        },
        expected: CanonicalOutcome::error("ENOENT"),
    };
    let enoent_outcome = franken.execute(&enoent_case).expect("read exec");
    assert_eq!(enoent_outcome, CanonicalOutcome::error("ENOENT"));
    log("fs", "missing-path read produced ENOENT (Node parity)");
}

#[test]
fn process_env_lookup_against_controlled_snapshot() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let franken = FrankenLeg::new(tmp.path());
    let mut env = BTreeMap::new();
    env.insert("TOKEN".to_string(), "secret-value".to_string());

    let present = CompatFixtureCase {
        case_name: "env_present".to_string(),
        description: "present".to_string(),
        input: CompatInput::ProcessEnv {
            env: env.clone(),
            key: "TOKEN".to_string(),
        },
        // Independently derive the expected value hash via a second leg path:
        // the spec leg is the contract expectation, so we just assert present.
        expected: CanonicalOutcome::Success {
            result: CanonicalResult::ProcessEnv {
                present: true,
                value_sha256: None,
            },
        },
    };
    let outcome = franken.execute(&present).expect("env exec");
    assert!(
        matches!(
            &outcome,
            CanonicalOutcome::Success {
                result: CanonicalResult::ProcessEnv {
                    present: true,
                    value_sha256: Some(_),
                },
            }
        ),
        "expected present ProcessEnv with a value hash, got {outcome:?}"
    );
    log("env", "present key resolved with a value hash");
}
