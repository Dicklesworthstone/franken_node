//! Quantified admission of a captured Node/Bun/Franken project test cohort.
//!
//! One selected test is one observation, not one observation per output stream
//! or runtime. Wilson bounds are conditional on an independent, representative
//! Bernoulli sampling model; this module does NOT establish that model or turn
//! a curated deterministic suite into a production-safety probability. Reports
//! are trusted local evidence, not authenticated remote approval tokens.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;

pub const REPORT_SCHEMA: &str = "franken-node/product-validation-suite/v1";
const CONFIDENCE_SCHEMA: &str = "franken-node/rollout-cohort-confidence/v1";
const MAX_TESTS: u32 = 1024;
const Z_95: f64 = 1.959_963_984_540_054;

/// Measured suite coverage and a conditional two-sided 95% Wilson interval.
/// Not the operator-supplied health ceiling in RolloutState::confidence_score.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CohortConfidence {
    pub schema_version: String,
    pub evidence_sha256: String,
    pub candidate_input_sha256: String,
    pub total_tests: u32,
    pub matched_tests: u32,
    pub observed_match_rate: f64,
    pub wilson_lower_95: f64,
    pub wilson_upper_95: f64,
    /// Always false: independent sampling is a statistical assumption, not a
    /// fact inferred from unique filenames or agreement between runtimes.
    pub independent_sampling_verified: bool,
}

fn digest(value: &str) -> bool {
    value.len() == 64
        && value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn interval(matched: u32, total: u32) -> Result<(f64, f64, f64), String> {
    if total == 0 || total > MAX_TESTS || matched > total {
        return Err("cohort requires 1..=1024 tests and matched_tests <= total_tests".into());
    }
    let n = f64::from(total);
    let p = f64::from(matched) / n;
    let z2 = Z_95 * Z_95;
    let denominator = 1.0 + z2 / n;
    let center = (p + z2 / (2.0 * n)) / denominator;
    let radius = Z_95 * (p * (1.0 - p) / n + z2 / (4.0 * n * n)).sqrt() / denominator;
    let lower = if matched == 0 { 0.0 } else { (center - radius).max(0.0) };
    let upper = if matched == total { 1.0 } else { (center + radius).min(1.0) };
    Ok((p, lower, upper))
}

impl CohortConfidence {
    #[cfg(any(target_os = "linux", test))]
    fn new(evidence: String, input: String, matched: u32, total: u32) -> Result<Self, String> {
        let (rate, lower, upper) = interval(matched, total)?;
        let result = Self {
            schema_version: CONFIDENCE_SCHEMA.into(),
            evidence_sha256: evidence,
            candidate_input_sha256: input,
            total_tests: total,
            matched_tests: matched,
            observed_match_rate: rate,
            wilson_lower_95: lower,
            wilson_upper_95: upper,
            independent_sampling_verified: false,
        };
        result.validate()?;
        Ok(result)
    }

    /// Reject corrupt cached metadata. Promotion still requires a freshly
    /// assessed report; validating this stored record is not authorization.
    pub fn validate(&self) -> Result<(), String> {
        let expected = interval(self.matched_tests, self.total_tests)?;
        if self.schema_version != CONFIDENCE_SCHEMA
            || !digest(&self.evidence_sha256)
            || !digest(&self.candidate_input_sha256)
            || self.independent_sampling_verified
            || [
                (self.observed_match_rate, expected.0),
                (self.wilson_lower_95, expected.1),
                (self.wilson_upper_95, expected.2),
            ].into_iter().any(|(actual, expected)| {
                !actual.is_finite() || !(0.0..=1.0).contains(&actual)
                    || (actual - expected).abs() > 1e-12
            })
        {
            return Err("invalid or inconsistent rollout cohort confidence".into());
        }
        Ok(())
    }

    /// Bind all measured fields into the existing state digest, while retaining
    /// the distinction between an unkeyed digest and a signature.
    pub(super) fn update_digest(&self, hash: &mut Sha256) {
        for field in [&self.schema_version, &self.evidence_sha256, &self.candidate_input_sha256] {
            hash.update((field.len() as u64).to_le_bytes());
            hash.update(field.as_bytes());
        }
        hash.update(self.total_tests.to_le_bytes());
        hash.update(self.matched_tests.to_le_bytes());
        hash.update(self.observed_match_rate.to_le_bytes());
        hash.update(self.wilson_lower_95.to_le_bytes());
        hash.update(self.wilson_upper_95.to_le_bytes());
        hash.update([u8::from(self.independent_sampling_verified)]);
    }
}

/// Read no new executable authority and never execute guest code. Reuse the
/// checked-rewrite capture API and the product oracle's complete admission
/// checks instead of inventing a second input-hash or report-verdict algorithm.
///
/// The current tree includes configuration, dependencies, test inputs and
/// rollout state. Initialize rollout status BEFORE measuring; put the report
/// outside the project. Every successful transition changes the tree identity,
/// so another promotion needs a fresh measurement rather than replaying a flag.
#[cfg(target_os = "linux")]
pub fn assess(project: &Path, raw: &[u8]) -> Result<CohortConfidence, String> {
    use super::super::validation_suite::{
        product_oracle::ProductReport, rewrite_candidate::RewriteCandidate,
    };
    use std::time::{Duration, Instant};

    if raw.len() > 16 * 1024 * 1024 {
        return Err("cohort report exceeds 16 MiB".into());
    }
    let report: ProductReport = serde_json::from_slice(raw)
        .map_err(|error| format!("invalid product cohort report: {error}"))?;
    let deadline = Instant::now() + Duration::from_secs(30);
    let captured = RewriteCandidate::capture(project, deadline)
        .map_err(|error| format!("cannot capture current rollout project: {error:#}"))?;
    let tests = captured.test_inventory().map_err(|error| format!("{error:#}"))?;
    report.check_admission(&report.input_sha256, captured.input_sha256(), &tests)
        .map_err(|error| format!(
            "cohort admission refused: {error:#}; initialize rollout status before measuring and keep the report outside the project"
        ))?;
    // check_admission already demands distinct reference bytes. A rollout must
    // also reject a native role aliased to either reference executable.
    if report.native_runtime.sha256 == report.node_runtime.sha256
        || report.native_runtime.sha256 == report.bun_runtime.sha256
    {
        return Err("rollout cohort requires three distinct executable hashes".into());
    }
    captured.ensure_source_unchanged()
        .map_err(|error| format!("project changed during cohort admission: {error:#}"))?;
    let total = u32::try_from(tests.len()).map_err(|_| "cohort test count overflow")?;
    // A partial or failing cohort never reaches this boundary. In particular,
    // ERROR/INCONCLUSIVE is not evidence authorizing destructive restoration.
    CohortConfidence::new(
        hex::encode(Sha256::digest(raw)),
        captured.input_sha256().to_owned(),
        total,
        total,
    )
}

#[cfg(not(target_os = "linux"))]
pub fn assess(_project: &Path, _raw: &[u8]) -> Result<CohortConfidence, String> {
    Err("captured project-cohort rollout admission is supported on Linux only".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_all_pass_single_test_is_not_complete_confidence() {
        let (rate, lower, upper) = interval(1, 1).unwrap();
        assert_eq!(rate, 1.0);
        assert!((lower - 0.206_549_314_377_237_45).abs() < 1e-12);
        assert!((upper - 1.0).abs() < 1e-12);
    }

    #[test]
    fn sample_size_changes_the_conservative_admission_boundary() {
        assert!(interval(34, 34).unwrap().1 < 0.90);
        assert!(interval(35, 35).unwrap().1 > 0.90);
        assert!(interval(72, 72).unwrap().1 < 0.95);
        assert!(interval(73, 73).unwrap().1 > 0.95);
    }

    #[test]
    fn bounds_are_finite_ordered_and_monotone_for_all_fixture_counts() {
        for n in [1, 2, 10, 100, MAX_TESTS] {
            let mut last = 0.0;
            for k in 0..=n {
                let (p, lower, upper) = interval(k, n).unwrap();
                assert!(0.0 <= lower && lower <= p && p <= upper && upper <= 1.0);
                assert!(lower >= last);
                last = lower;
            }
        }
    }

    #[test]
    fn impossible_empty_and_unbounded_counts_are_refused() {
        for (k, n) in [(0, 0), (2, 1), (0, MAX_TESTS + 1), (u32::MAX, u32::MAX)] {
            assert!(interval(k, n).is_err());
        }
    }

    #[test]
    fn cached_confidence_cannot_claim_a_different_score_or_sampling_guarantee() {
        let original = CohortConfidence::new("a".repeat(64), "b".repeat(64), 40, 40).unwrap();
        for mutation in 0..7 {
            let mut changed = original.clone();
            match mutation {
                0 => changed.wilson_lower_95 = 1.0,
                1 => changed.wilson_upper_95 = f64::NAN,
                2 => changed.observed_match_rate = f64::INFINITY,
                3 => changed.evidence_sha256 = "not-a-digest".into(),
                4 => changed.total_tests = 1,
                5 => changed.independent_sampling_verified = true,
                6 => changed.schema_version = "future/v9".into(),
                _ => unreachable!(),
            }
            assert!(changed.validate().is_err(), "{mutation}");
        }
        let encoded = serde_json::to_vec(&original).unwrap();
        let decoded: CohortConfidence = serde_json::from_slice(&encoded).unwrap();
        decoded.validate().unwrap();
        assert_eq!(original, decoded);
    }
}

#[cfg(all(test, target_os = "linux"))]
mod admission_tests {
    use super::*;
    use super::super::{RolloutConfig, RolloutManager, RolloutStage};
    use super::super::super::validation_suite::{
        DeltaSummary, RunObservation, RuntimeIdentity, StreamObservation,
        product_oracle::{CaseOutcome, ProductCase, ProductReport},
        rewrite_candidate::RewriteCandidate,
    };
    use std::fs;
    use std::path::PathBuf;
    use std::time::{Duration, Instant};

    fn project(n: usize) -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        for index in 0..n {
            fs::write(root.path().join(format!("case-{index:04}.test.js")), "console.log(42);\n").unwrap();
        }
        root
    }

    /// Constructed wire-admission fixtures, NOT claims of live Node/Bun/Franken
    /// execution. Hash and inventory come from the real immutable capture API.
    /// The controller/recovery tests below use actual filesystem transactions.
    fn fixture(root: &Path) -> ProductReport {
        let captured = RewriteCandidate::capture(root, Instant::now() + Duration::from_secs(30)).unwrap();
        let tests = captured.test_inventory().unwrap();
        let runtime = |name: &str, marker: &str| RuntimeIdentity {
            executable: PathBuf::from(format!("/trusted/{name}")),
            sha256: marker.repeat(64),
            arguments_before_test: Vec::new(),
            arguments_after_test: Vec::new(),
        };
        let observation = RunObservation {
            exit_code: Some(0), signal: None,
            stdout: StreamObservation { bytes: 3, sha256: hex::encode(Sha256::digest(b"42\n")) },
            stderr: StreamObservation { bytes: 0, sha256: hex::encode(Sha256::digest(b"")) },
            workspace_delta: Some(DeltaSummary {
                sha256: hex::encode(Sha256::digest(b"[]")), changed_paths: 0,
                changes: Vec::new(), details_truncated: false,
            }),
        };
        ProductReport {
            schema_version: REPORT_SCHEMA.into(),
            scope: "captured-test-process-and-workspace-delta".into(),
            oracle: "L1-node-bun-franken-node".into(), release_certification: false,
            input_sha256: captured.input_sha256().into(),
            candidate_input_sha256: captured.input_sha256().into(),
            filesystem_comparison: true,
            filesystem_exclusions: vec!["**/.git".into(), ".franken-node".into()],
            node_runtime: runtime("node", "a"), bun_runtime: runtime("bun", "b"),
            native_runtime: runtime("franken-node", "c"), distinct_reference_binaries: true,
            total_tests: tests.len(), passed: tests.len(), failed: 0,
            reference_failures: 0, reference_divergences: 0, native_divergences: 0,
            errored: 0, skipped: 0, verdict: "PASS".into(),
            cases: tests.into_iter().map(|path| ProductCase {
                test: path.to_str().unwrap().into(), outcome: CaseOutcome::Match,
                node: Some(observation.clone()), bun: Some(observation.clone()),
                native: Some(observation.clone()), divergences: Vec::new(), errors: Vec::new(),
            }).collect(), errors: Vec::new(), failure_capture: None,
        }
    }

    fn write_report(report: &ProductReport, out: &Path) -> PathBuf {
        let path = out.join("cohort.json");
        fs::write(&path, serde_json::to_vec(report).unwrap()).unwrap();
        path
    }

    #[test]
    fn cohort_measurement_binds_captured_inputs_and_unique_test_inventory() {
        let root = project(40);
        let raw = serde_json::to_vec(&fixture(root.path())).unwrap();
        let confidence = assess(root.path(), &raw).unwrap();
        assert_eq!(confidence.total_tests, 40);
        assert_eq!(confidence.matched_tests, 40);
        assert!(confidence.wilson_lower_95 > 0.90 && confidence.wilson_lower_95 < 1.0);
        assert_eq!(confidence.evidence_sha256, hex::encode(Sha256::digest(&raw)));
        assert!(!confidence.independent_sampling_verified);
        fs::write(root.path().join("unmeasured-dependency.js"), "changed").unwrap();
        assert!(assess(root.path(), &raw).unwrap_err().contains("does not match"));
    }

    #[test]
    fn incomplete_failing_or_weakened_reports_cannot_supply_confidence() {
        let root = project(2);
        let original = fixture(root.path());
        for mutation in 0..12 {
            let mut changed = original.clone();
            match mutation {
                0 => changed.cases[0].native = None,
                1 => changed.cases[0].native.as_mut().unwrap().exit_code = Some(7),
                2 => changed.cases[0].bun.as_mut().unwrap().stdout.sha256 = "d".repeat(64),
                3 => changed.skipped = 1,
                4 => changed.errors.push("runtime changed".into()),
                5 => changed.filesystem_comparison = false,
                6 => changed.filesystem_exclusions.push("**/*".into()),
                7 => changed.cases[1] = changed.cases[0].clone(),
                8 => { changed.cases.pop().unwrap(); }
                9 => changed.release_certification = true,
                10 => changed.cases[0].errors.push("golden output mismatch".into()),
                11 => changed.passed = 1,
                _ => unreachable!(),
            }
            assert!(assess(root.path(), &serde_json::to_vec(&changed).unwrap()).is_err(), "{mutation}");
        }
    }

    #[test]
    fn runtime_aliases_and_forged_extra_confidence_fields_do_not_create_samples() {
        let root = project(1);
        let original = fixture(root.path());
        for alias in ["a", "b"] {
            let mut changed = original.clone();
            changed.native_runtime.sha256 = alias.repeat(64);
            assert!(assess(root.path(), &serde_json::to_vec(&changed).unwrap()).is_err());
        }
        let mut raw = serde_json::to_value(original).unwrap();
        raw["confidence_score"] = 1.0.into();
        raw["sample_count"] = 999999.into();
        let actual = assess(root.path(), &serde_json::to_vec(&raw).unwrap()).unwrap();
        assert_eq!(actual.total_tests, 1);
        assert!(actual.wilson_lower_95 < 0.21);
    }

    #[test]
    fn successful_measured_promotion_persists_confidence_and_requires_a_fresh_report() {
        let root = project(40);
        let output = tempfile::tempdir().unwrap();
        let manager = RolloutManager::new(root.path(), Some("cohort-promotion"));
        manager.load_or_init().unwrap();
        let config = RolloutConfig {
            lockstep_report: Some(write_report(&fixture(root.path()), output.path())),
            ..RolloutConfig::default()
        };
        let canary = manager.promote(&config, None, None).unwrap();
        assert_eq!(canary.stage, RolloutStage::Canary);
        let confidence = canary.validation_confidence.as_ref().unwrap();
        assert_eq!(confidence.total_tests, 40);
        assert!(confidence.wilson_lower_95 > 0.9);
        assert!(canary.render_human().contains("conditional Wilson"));
        let restarted = RolloutManager::new(root.path(), Some("cohort-promotion"));
        assert_eq!(restarted.status().unwrap().validation_confidence, canary.validation_confidence);
        assert!(restarted.promote(&config, None, None).is_err());
        assert_eq!(restarted.status().unwrap().stage, RolloutStage::Canary);
        write_report(&fixture(root.path()), output.path());
        let ramp = restarted.promote(&config, None, None).unwrap();
        assert_eq!(ramp.stage, RolloutStage::Ramp);
        assert_eq!(ramp.validation_confidence.unwrap().total_tests, 40); // NOT 80.
    }

    #[test]
    fn insufficient_samples_do_not_trigger_destructive_source_rollback() {
        use super::super::super::rewrite_transaction::{Edit, RewriteTransaction};
        use super::super::super::rollback;
        let root = project(1);
        fs::write(root.path().join("app.js"), b"original").unwrap();
        RewriteTransaction::open(root.path()).unwrap().apply(&[
            Edit { path: "app.js", before: b"original", after: b"candidate" },
        ]).unwrap();
        let history = rollback::run(root.path(), None, false);
        let id = &history.history[0].transaction_id;
        let manager = RolloutManager::new(root.path(), Some(id));
        let before = manager.load_or_init().unwrap();
        let output = tempfile::tempdir().unwrap();
        let config = RolloutConfig {
            lockstep_report: Some(write_report(&fixture(root.path()), output.path())),
            ..RolloutConfig::default()
        };
        let error = manager.promote(&config, None, None).unwrap_err();
        assert!(error.contains("insufficient cohort evidence"), "{error}");
        assert_eq!(manager.load_or_init().unwrap(), before);
        assert_eq!(fs::read(root.path().join("app.js")).unwrap(), b"candidate");
    }

    #[test]
    fn force_retains_the_low_measured_bound_instead_of_fabricating_confidence() {
        let root = project(1);
        let output = tempfile::tempdir().unwrap();
        let manager = RolloutManager::new(root.path(), Some("forced-cohort"));
        manager.load_or_init().unwrap();
        let config = RolloutConfig {
            force: true,
            lockstep_report: Some(write_report(&fixture(root.path()), output.path())),
            ..RolloutConfig::default()
        };
        let report = manager.promote(&config, None, None).unwrap();
        assert!(report.validation_confidence.unwrap().wilson_lower_95 < 0.21);
        let before = manager.load_or_init().unwrap();
        let mut forged = before.clone();
        forged.validation_confidence.as_mut().unwrap().wilson_lower_95 = 1.0;
        assert!(manager.persist(&forged).is_err());
        assert_eq!(manager.load_or_init().unwrap(), before);
        let unverified = manager.promote(&RolloutConfig { force: true, ..RolloutConfig::default() }, None, None).unwrap();
        assert!(unverified.validation_confidence.is_none());
        assert!(!unverified.lockstep_verified);
    }

    #[test]
    fn malformed_or_foreign_cohorts_do_not_modify_an_existing_rollout() {
        let root = project(40);
        let foreign = project(1);
        let output = tempfile::tempdir().unwrap();
        let manager = RolloutManager::new(root.path(), Some("bad-cohort"));
        let before = manager.load_or_init().unwrap();
        let config = RolloutConfig {
            lockstep_report: Some(write_report(&fixture(foreign.path()), output.path())),
            ..RolloutConfig::default()
        };
        assert!(manager.promote(&config, None, None).is_err());
        assert_eq!(manager.load_or_init().unwrap(), before);
        fs::write(config.lockstep_report.as_ref().unwrap(), b"{bad json").unwrap();
        assert!(manager.promote(&config, None, None).is_err());
        assert!(assess(root.path(), b"{}").is_err());
        assert_eq!(manager.load_or_init().unwrap(), before);
    }

    #[test]
    fn operator_rollback_invalidates_the_cohort_for_the_restored_tree() {
        let root = project(40);
        let output = tempfile::tempdir().unwrap();
        let manager = RolloutManager::new(root.path(), Some("cohort-abort"));
        manager.load_or_init().unwrap();
        let config = RolloutConfig {
            lockstep_report: Some(write_report(&fixture(root.path()), output.path())),
            ..RolloutConfig::default()
        };
        assert!(manager.promote(&config, None, None).unwrap().validation_confidence.is_some());
        let aborted = manager.rollback("operator abort").unwrap();
        assert!(!aborted.lockstep_verified);
        assert!(aborted.validation_confidence.is_none());
        assert!(manager.status().unwrap().validation_confidence.is_none());
    }
}
