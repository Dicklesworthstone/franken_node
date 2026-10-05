//! Three-runtime migration comparison for the L1 product oracle.
//!
//! Unlike the single-target lockstep harness, this executes the captured test
//! inventory: Node and Bun receive original inputs, native Franken receives
//! the optional rewritten candidate. Every leg runs once in its own workspace.
//! Two-reference disagreement is INCONCLUSIVE, never a majority-vote PASS.
//! This shares capture, inventory, runtime invocation, process supervision and
//! filesystem observation with native validation; it is not release certification.

use super::{
    CapturedInputs, DRAIN_TIMEOUT, Invocation, LEG_TIMEOUT, RunObservation, RuntimeIdentity,
    Snapshot, TOTAL_TIMEOUT, budget, matched_tests, observe, runtime_invocations, test_inventory,
    workspace_effects,
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Output;
use std::time::{Duration, Instant};

const ROLES: [&str; 3] = ["node", "bun", "native"];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CaseOutcome {
    Match,
    ReferenceFailure,
    ReferenceDivergence,
    NativeDivergence,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProductCase {
    pub test: String,
    pub outcome: CaseOutcome,
    pub node: Option<RunObservation>,
    pub bun: Option<RunObservation>,
    pub native: Option<RunObservation>,
    pub divergences: Vec<String>,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProductReport {
    pub schema_version: String,
    pub scope: String,
    pub oracle: String,
    pub release_certification: bool,
    pub input_sha256: String,
    pub candidate_input_sha256: String,
    pub filesystem_comparison: bool,
    pub filesystem_exclusions: Vec<String>,
    pub node_runtime: RuntimeIdentity,
    pub bun_runtime: RuntimeIdentity,
    pub native_runtime: RuntimeIdentity,
    /// Different executable bytes, not proof of independent implementations.
    pub distinct_reference_binaries: bool,
    pub total_tests: usize,
    pub passed: usize,
    pub failed: usize,
    pub reference_failures: usize,
    pub reference_divergences: usize,
    pub native_divergences: usize,
    pub errored: usize,
    pub skipped: usize,
    pub verdict: String,
    pub cases: Vec<ProductCase>,
    pub errors: Vec<String>,
    /// Optional live failure retention; never replaces the measured verdict.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_capture: Option<super::FailureCapture>,
}

impl ProductReport {
    /// Check a LIVE measurement against the caller's exact captured inputs and
    /// sorted test inventory before allowing a checked installation. This is
    /// consistency checking, not authentication: an unsigned imported report
    /// must never authorize source changes, even when all these checks pass.
    /// No pairwise projection, majority vote or summary-only PASS is sufficient.
    pub fn check_admission(
        &self,
        original_sha256: &str,
        candidate_sha256: &str,
        tests: &[PathBuf],
    ) -> Result<()> {
        let digest = |value: &str| {
            value.len() == 64
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        };
        ensure!(
            digest(original_sha256)
                && digest(candidate_sha256)
                && self.input_sha256 == original_sha256
                && self.candidate_input_sha256 == candidate_sha256,
            "three-runtime evidence does not match the captured original and prepared candidate"
        );
        ensure!(
            self.schema_version == "franken-node/product-validation-suite/v1"
                && self.oracle == "L1-node-bun-franken-node"
                && self.scope == "captured-test-process-and-workspace-delta"
                && !self.release_certification
                && self.filesystem_comparison
                && self
                    .filesystem_exclusions
                    .iter()
                    .map(String::as_str)
                    .eq(workspace_effects::EXCLUSIONS.iter().copied()),
            "three-runtime evidence has an unsupported or weakened comparison scope"
        );
        ensure!(
            self.distinct_reference_binaries && self.node_runtime.sha256 != self.bun_runtime.sha256,
            "three-runtime admission requires distinct reference executable hashes"
        );
        for runtime in [&self.node_runtime, &self.bun_runtime, &self.native_runtime] {
            ensure!(
                runtime.executable.is_absolute() && digest(&runtime.sha256),
                "three-runtime evidence contains an invalid runtime identity"
            );
        }
        ensure!(
            !tests.is_empty()
                && tests.windows(2).all(|pair| pair[0] < pair[1])
                && self.verdict == "PASS"
                && self.total_tests == tests.len()
                && self.cases.len() == tests.len()
                && self.passed == tests.len()
                && self.failed == 0
                && self.reference_failures == 0
                && self.reference_divergences == 0
                && self.native_divergences == 0
                && self.errored == 0
                && self.skipped == 0
                && self.errors.is_empty(),
            "three-runtime evidence is not a complete passing test suite"
        );
        for (test, row) in tests.iter().zip(&self.cases) {
            ensure!(
                test.to_str() == Some(row.test.as_str()),
                "three-runtime evidence test inventory differs from the captured inventory"
            );
            ensure!(
                row.outcome == CaseOutcome::Match
                    && row.errors.is_empty()
                    && row.divergences.is_empty(),
                "three-runtime evidence contains a nonmatching case: {}",
                row.test
            );
            let node = row.node.as_ref().context("missing Node process evidence")?;
            let bun = row.bun.as_ref().context("missing Bun process evidence")?;
            let native = row
                .native
                .as_ref()
                .context("missing native process evidence")?;
            for observation in [node, bun, native] {
                ensure!(
                    observation.exit_code == Some(0)
                        && observation.signal.is_none()
                        && digest(&observation.stdout.sha256)
                        && digest(&observation.stderr.sha256)
                        && observation
                            .workspace_delta
                            .as_ref()
                            .is_some_and(|delta| digest(&delta.sha256)),
                    "three-runtime evidence contains unsuccessful or incomplete observations: {}",
                    row.test
                );
            }
            // Compare observations, not just reported outcomes. Bun cannot
            // disappear or disagree only in filesystem effects at admission.
            ensure!(
                node == bun && node == native,
                "three-runtime evidence contains unequal process or workspace observations: {}",
                row.test
            );
        }
        Ok(())
    }
}

/// Run only after explicit operator approval of trusted project execution.
/// Both references run the original capture and native runs the candidate.
/// Missing/aliased Bun and mismatched inventories never trigger pair fallback.
pub fn run_project_comparison(
    project: &Path,
    migrated_project: Option<&Path>,
    native_executable: &Path,
    bun_executable: &Path,
    compare_filesystem: bool,
) -> Result<ProductReport> {
    let deadline = Instant::now() + TOTAL_TIMEOUT;
    let inputs = CapturedInputs::capture(project, migrated_project, deadline)?;
    run_captured(
        [&inputs.reference_root, &inputs.candidate_root],
        [&inputs.reference, inputs.candidate_snapshot()],
        native_executable,
        bun_executable,
        deadline,
        compare_filesystem,
    )
}

/// Execute checked rewrite's prepared in-memory candidate, never recapture
/// the caller's unchanged tree as the proposed rewrite.
pub(super) fn run_captured(
    projects: [&Path; 2],
    snapshots: [&Snapshot; 2],
    native_executable: &Path,
    bun_executable: &Path,
    deadline: Instant,
    compare_filesystem: bool,
) -> Result<ProductReport> {
    budget(deadline)?;
    matched_tests(snapshots[0], snapshots[1])?;
    let roots = [projects[0].canonicalize()?, projects[1].canonicalize()?];
    let (node, native) = runtime_invocations(native_executable)?;
    let bun = Invocation {
        executable: bun_executable
            .canonicalize()
            .context("resolve Bun executable")?,
        before: Vec::new(),
        after: Vec::new(),
    };
    let runtimes = [&node, &bun, &native];
    for (role, invocation) in ROLES.into_iter().zip(runtimes) {
        for root in &roots {
            ensure!(
                !invocation.executable.starts_with(root),
                "{role} runtime must be outside both measured projects"
            );
        }
        let metadata = fs::metadata(&invocation.executable)?;
        ensure!(
            metadata.is_file() && metadata.permissions().mode() & 0o111 != 0,
            "{role} runtime must be an executable regular file"
        );
    }
    // Different bytes do not authenticate brands; local selection is trusted.
    let identities = [
        node.identity(deadline)?,
        bun.identity(deadline)?,
        native.identity(deadline)?,
    ];
    ensure!(
        identities[0].sha256 != identities[1].sha256,
        "Node and Bun references must have distinct executable hashes"
    );
    execute(
        snapshots[0],
        snapshots[1],
        runtimes,
        identities,
        deadline,
        LEG_TIMEOUT,
        compare_filesystem,
    )
}

#[derive(Default)]
struct Leg {
    observation: Option<RunObservation>,
    output: Option<Output>,
    delta: Option<Vec<workspace_effects::Change>>,
    error: Option<String>,
}

fn measure(
    snapshot: &Snapshot,
    invocation: &Invocation,
    test: &Path,
    workspace: &Path,
    environment: &BTreeMap<OsString, OsString>,
    timing: (Instant, Duration),
    filesystem: bool,
) -> Leg {
    let (deadline, leg_timeout) = timing;
    let mut leg = Leg::default();
    let result = (|| -> Result<()> {
        budget(deadline)?;
        snapshot.stage(workspace, deadline)?;
        ensure!(
            workspace.join(test).is_file(),
            "discovered test is not a file"
        );
        let before = filesystem
            .then(|| workspace_effects::observe(workspace, deadline))
            .transpose()
            .context("initial workspace observation failed")?;
        budget(deadline)?;
        let timeout = leg_timeout.min(deadline.saturating_duration_since(Instant::now()));
        let output = test_inventory::run_test(
            snapshot,
            invocation,
            test,
            workspace,
            environment,
            (timeout, DRAIN_TIMEOUT),
        )
        .context("execution failed")?;
        // Keep completed evidence even when final filesystem collection fails.
        leg.observation = Some(observe(&output));
        leg.output = Some(output);
        if let Some(before) = before {
            let after = workspace_effects::observe(workspace, deadline)
                .context("final workspace observation failed")?;
            let delta = workspace_effects::delta(&before, &after);
            leg.observation
                .as_mut()
                .expect("process observed")
                .workspace_delta = Some(workspace_effects::summarize(&delta)?);
            leg.delta = Some(delta);
        }
        Ok(())
    })();
    if let Err(error) = result {
        leg.error = Some(format!("{error:#}"));
    }
    leg
}

fn differences(left: &Leg, right: &Leg, filesystem: bool) -> Vec<&'static str> {
    let (Some(left_output), Some(right_output)) = (&left.output, &right.output) else {
        return Vec::new();
    };
    let mut differences = Vec::new();
    if left_output.stdout != right_output.stdout {
        differences.push("stdout:byte_mismatch");
    }
    if left_output.stderr != right_output.stderr {
        differences.push("stderr:byte_mismatch");
    }
    if filesystem && left.delta.is_some() && right.delta.is_some() && left.delta != right.delta {
        differences.push("filesystem:workspace_delta_mismatch");
    }
    differences
}

fn classify(test: &Path, legs: [Leg; 3], filesystem: bool) -> ProductCase {
    let mut errors = Vec::new();
    let mut divergences = Vec::new();
    for (role, leg) in ROLES.into_iter().zip(&legs) {
        if let Some(error) = &leg.error {
            errors.push(format!("{role}: {error}"));
        }
        if leg.output.is_none() || leg.observation.is_none() || (filesystem && leg.delta.is_none())
        {
            errors.push(format!("{role}: incomplete observation"));
        }
        if leg
            .output
            .as_ref()
            .is_some_and(|output| !output.status.success())
        {
            divergences.push(format!("{role}:unsuccessful_exit"));
        }
    }
    let reference_differences = differences(&legs[0], &legs[1], filesystem);
    let native_differences = differences(&legs[0], &legs[2], filesystem);
    for (pair, channels) in [
        ("node/bun", &reference_differences),
        ("node/native", &native_differences),
    ] {
        divergences.extend(channels.iter().map(|channel| format!("{pair}:{channel}")));
    }
    let succeeded = |index: usize| {
        legs[index]
            .output
            .as_ref()
            .is_some_and(|output| output.status.success())
    };
    let outcome = if !errors.is_empty() {
        CaseOutcome::Error
    } else if !succeeded(0) || !succeeded(1) {
        CaseOutcome::ReferenceFailure
    } else if !reference_differences.is_empty() {
        CaseOutcome::ReferenceDivergence
    } else if !succeeded(2) || !native_differences.is_empty() {
        CaseOutcome::NativeDivergence
    } else {
        CaseOutcome::Match
    };
    let [node, bun, native] = legs;
    ProductCase {
        test: test.to_string_lossy().into_owned(),
        outcome,
        node: node.observation,
        bun: bun.observation,
        native: native.observation,
        divergences,
        errors,
    }
}

// Shared by live comparison and pinned replay; runtime commands stay local.
pub(super) fn execute(
    original: &Snapshot,
    candidate: &Snapshot,
    runtimes: [&Invocation; 3],
    identities: [RuntimeIdentity; 3],
    deadline: Instant,
    leg_timeout: Duration,
    filesystem: bool,
) -> Result<ProductReport> {
    let tests = matched_tests(original, candidate)?;
    let concurrency = test_inventory::concurrency(original)?;
    let [node_runtime, bun_runtime, native_runtime] = identities;
    let distinct_reference_binaries = node_runtime.sha256 != bun_runtime.sha256;
    let mut report = ProductReport {
        schema_version: "franken-node/product-validation-suite/v1".into(),
        scope: if filesystem {
            "captured-test-process-and-workspace-delta"
        } else {
            "captured-test-process-stdout-stderr-exit"
        }
        .into(),
        oracle: "L1-node-bun-franken-node".into(),
        release_certification: false,
        input_sha256: original.digest.clone(),
        candidate_input_sha256: candidate.digest.clone(),
        filesystem_comparison: filesystem,
        filesystem_exclusions: if filesystem {
            workspace_effects::EXCLUSIONS
                .iter()
                .map(|s| (*s).into())
                .collect()
        } else {
            Vec::new()
        },
        node_runtime,
        bun_runtime,
        native_runtime,
        distinct_reference_binaries,
        total_tests: tests.len(),
        passed: 0,
        failed: 0,
        reference_failures: 0,
        reference_divergences: 0,
        native_divergences: 0,
        errored: 0,
        skipped: tests.len(),
        verdict: "ERROR".into(),
        cases: Vec::new(),
        errors: Vec::new(),
        failure_capture: None,
    };
    let environment = std::env::vars_os().collect();
    let completed = test_inventory::run_scheduled(&tests, concurrency, deadline, |test| {
        budget(deadline)?;
        let case = tempfile::Builder::new()
            .prefix("franken-product-oracle-")
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir()
            .context("create private comparison workspace")?;
        let mut legs: [Leg; 3] = std::array::from_fn(|_| Leg::default());
        for (index, invocation) in runtimes.iter().enumerate() {
            let snapshot = if index == 2 { candidate } else { original };
            legs[index] = measure(
                snapshot,
                invocation,
                test,
                &case.path().join(ROLES[index]),
                &environment,
                (deadline, leg_timeout),
                filesystem,
            );
        }
        Ok(classify(test, legs, filesystem))
    })?;
    report.errors.extend(completed.errors);
    for row in completed.rows {
        report.skipped -= 1;
        match row.outcome {
            CaseOutcome::Match => report.passed += 1,
            CaseOutcome::Error => report.errored += 1,
            outcome => {
                report.failed += 1;
                match outcome {
                    CaseOutcome::ReferenceFailure => report.reference_failures += 1,
                    CaseOutcome::ReferenceDivergence => report.reference_divergences += 1,
                    CaseOutcome::NativeDivergence => report.native_divergences += 1,
                    _ => unreachable!(),
                }
            }
        }
        report.cases.push(row);
    }
    // Identity changes remain infrastructure errors after three-way agreement.
    for ((role, invocation), before) in ROLES.into_iter().zip(runtimes).zip([
        &report.node_runtime,
        &report.bun_runtime,
        &report.native_runtime,
    ]) {
        match invocation.identity(deadline) {
            Ok(after) if &after == before => {}
            Ok(_) => report.errors.push(format!(
                "{role} runtime executable changed during comparison"
            )),
            Err(error) => report
                .errors
                .push(format!("{role} runtime identity recheck failed: {error:#}")),
        }
    }
    report.verdict = if report.errored > 0 || report.skipped > 0 || !report.errors.is_empty() {
        "ERROR"
    } else if report.reference_failures > 0 || report.reference_divergences > 0 {
        "INCONCLUSIVE"
    } else if report.native_divergences > 0 {
        "FAIL"
    } else {
        "PASS"
    }
    .into();
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::super::node_on_path;
    use super::*;

    fn write(root: &Path, name: &str, text: &str) {
        let path = root.join(name);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, text).unwrap();
    }
    fn invocation(role: &str) -> Invocation {
        Invocation {
            executable: node_on_path().unwrap(),
            before: Vec::new(),
            after: vec![role.into()],
        }
    }
    // Explicit Node invocations with role arguments test orchestration, NOT
    // Bun/native compatibility. The public entrypoint refuses aliased references.
    fn measured(original: &Path, candidate: Option<&Path>, filesystem: bool) -> ProductReport {
        let deadline = Instant::now() + Duration::from_secs(120);
        let inputs = CapturedInputs::capture(original, candidate, deadline).unwrap();
        measured_inputs(&inputs, filesystem, deadline, Duration::from_secs(5))
    }
    fn measured_inputs(
        inputs: &CapturedInputs,
        filesystem: bool,
        deadline: Instant,
        timeout: Duration,
    ) -> ProductReport {
        let node = invocation("node");
        let bun = invocation("bun");
        let native = invocation("native");
        let identities = [
            node.identity(deadline).unwrap(),
            bun.identity(deadline).unwrap(),
            native.identity(deadline).unwrap(),
        ];
        execute(
            &inputs.reference,
            inputs.candidate_snapshot(),
            [&node, &bun, &native],
            identities,
            deadline,
            timeout,
            filesystem,
        )
        .unwrap()
    }

    fn concurrent_manifest(root: &Path, tests: &[&str], limit: usize) {
        write(root, ".franken-node/migration-tests.json", &serde_json::json!({
            "schema_version": "franken-node/migration-tests/v1",
            "tests": tests,
            "max_concurrent_tests": limit,
        }).to_string());
    }

    #[test]
    fn concurrent_cases_use_the_captured_plan_and_execute_every_role_once() {
        // Actual Node processes in all roles exercise scheduling, capture and
        // cleanup, NOT a claim that Node is an independent Bun/native oracle.
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let log = outside.path().join("runs");
        write(root.path(), "dependency", "captured");
        for name in ["a", "b"] {
            write(root.path(), &format!("{name}.test.js"), &format!(r#"
const fs = require('fs');
const role = process.argv[2];
const marker = {} + '/' + role;
(async () => {{
    if ('{name}' === 'a') {{
        const deadline = Date.now() + 4000;
        while (!fs.existsSync(marker) && Date.now() < deadline)
            await new Promise(resolve => setTimeout(resolve, 5));
        if (!fs.existsSync(marker)) throw new Error('concurrent peer did not execute');
    }} else fs.writeFileSync(marker, 'ready');
    const value = fs.readFileSync('dependency');
    fs.writeFileSync('artifact', value);
    fs.writeFileSync('dependency', 'guest mutation');
    fs.appendFileSync({}, '{name}:' + role + '\n');
    process.stdout.write(value);
}})().catch(error => {{ console.error(error.message); process.exitCode = 1; }});
"#, serde_json::to_string(outside.path()).unwrap(), serde_json::to_string(&log).unwrap()));
        }
        concurrent_manifest(root.path(), &["a.test.js", "b.test.js"], 2);
        let deadline = Instant::now() + Duration::from_secs(120);
        let inputs = CapturedInputs::capture(root.path(), None, deadline).unwrap();
        concurrent_manifest(root.path(), &["a.test.js", "b.test.js"], 1);
        write(root.path(), "dependency", "later source");
        let report = measured_inputs(&inputs, true, deadline, Duration::from_secs(8));
        assert_eq!(report.verdict, "PASS", "{report:#?}");
        assert_eq!((report.passed, report.errored, report.skipped), (2, 0, 0));
        assert_eq!(report.cases.iter().map(|row| row.test.as_str()).collect::<Vec<_>>(),
            ["a.test.js", "b.test.js"]);
        let runs = fs::read_to_string(log).unwrap();
        assert_eq!(runs.lines().count(), 6);
        for name in ["a", "b"] {
            assert_eq!(runs.lines().filter(|line| line.starts_with(name)).collect::<Vec<_>>(),
                [format!("{name}:node"), format!("{name}:bun"), format!("{name}:native")]);
        }
        for row in &report.cases {
            assert_eq!(row.node, row.bun);
            assert_eq!(row.node, row.native);
            assert_eq!(row.node.as_ref().unwrap().stdout.bytes, 8);
        }
        assert_eq!(fs::read(root.path().join("dependency")).unwrap(), b"later source");
        assert!(!root.path().join("artifact").exists());
    }

    #[test]
    fn concurrent_failures_keep_all_reference_native_and_error_classifications() {
        let root = tempfile::tempdir().unwrap();
        write(root.path(), "a.test.js", "console.log(process.argv.includes('native')?'bad':'ok');");
        write(root.path(), "b.test.js", "console.log(process.argv.includes('bun')?'bad':'ok');");
        write(root.path(), "c.test.js", "console.log('not the expected bytes');");
        write(root.path(), "expected.txt", "ok\n");
        write(root.path(), ".franken-node/migration-tests.json", &serde_json::json!({
            "schema_version": "franken-node/migration-tests/v1",
            "tests": ["a.test.js", "b.test.js", "c.test.js"],
            "max_concurrent_tests": 3,
            "expectations": {"c.test.js": {"stdout": "expected.txt"}},
        }).to_string());
        let report = measured(root.path(), None, true);
        assert_eq!(report.verdict, "ERROR", "{report:#?}");
        assert_eq!((report.passed, report.native_divergences, report.reference_divergences,
            report.errored, report.skipped), (0, 1, 1, 1, 0));
        assert_eq!(report.cases[0].outcome, CaseOutcome::NativeDivergence);
        assert_eq!(report.cases[1].outcome, CaseOutcome::ReferenceDivergence);
        assert_eq!(report.cases[2].outcome, CaseOutcome::Error);
        for row in &report.cases[..2] {
            assert!(row.node.is_some() && row.bun.is_some() && row.native.is_some());
        }
        assert_eq!(report.cases[2].errors.len(), 6);
        for role in ROLES {
            assert!(report.cases[2].errors.contains(&format!("{role}: incomplete observation")));
        }
    }

    #[test]
    fn a_concurrent_timeout_keeps_peer_cases_and_other_runtime_observations() {
        let root = tempfile::tempdir().unwrap();
        write(root.path(), "a.test.js",
            "if(process.argv.includes('bun'))setInterval(()=>{},1000);else console.log(42);");
        write(root.path(), "b.test.js", "console.log(42);");
        concurrent_manifest(root.path(), &["a.test.js", "b.test.js"], 2);
        let deadline = Instant::now() + Duration::from_secs(120);
        let inputs = CapturedInputs::capture(root.path(), None, deadline).unwrap();
        let report = measured_inputs(&inputs, true, deadline, Duration::from_secs(1));
        assert_eq!(report.verdict, "ERROR");
        assert_eq!((report.passed, report.errored, report.skipped), (1, 1, 0));
        assert!(report.cases[0].node.is_some());
        assert!(report.cases[0].bun.is_none());
        assert!(report.cases[0].native.is_some());
        assert_eq!(report.cases[1].outcome, CaseOutcome::Match);
    }

    #[test]
    fn parallel_and_serial_runs_preserve_binary_stdin_cwd_and_golden_file_evidence() {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir(root.path().join("nested")).unwrap();
        fs::write(root.path().join("request.bin"), [0, 255, 1, 10]).unwrap();
        for name in ["a", "b", "c"] {
            write(root.path(), &format!("{name}.test.js"),
                "const fs=require('fs');const b=fs.readFileSync(0);fs.writeFileSync('result.bin',b);process.stdout.write(b);");
        }
        let mut manifest = serde_json::json!({
            "schema_version": "franken-node/migration-tests/v1",
            "tests": ["a.test.js", "b.test.js", "c.test.js"],
            "max_concurrent_tests": 1,
            "execution": {}, "expectations": {},
        });
        for name in ["a.test.js", "b.test.js", "c.test.js"] {
            manifest["execution"][name] = serde_json::json!({
                "cwd": "nested", "stdin": "request.bin", "stdin_mode": "pipe",
            });
            manifest["expectations"][name] = serde_json::json!({
                "stdout": "request.bin", "files": {"nested/result.bin": "request.bin"},
            });
        }
        write(root.path(), ".franken-node/migration-tests.json", &manifest.to_string());
        let serial = measured(root.path(), None, true);
        manifest["max_concurrent_tests"] = 3.into();
        write(root.path(), ".franken-node/migration-tests.json", &manifest.to_string());
        let parallel = measured(root.path(), None, true);
        assert_eq!(serial.verdict, "PASS", "{serial:#?}");
        assert_eq!(parallel.verdict, "PASS", "{parallel:#?}");
        assert_eq!(serial.cases, parallel.cases);
        assert_ne!(serial.input_sha256, parallel.input_sha256);
        assert_eq!(fs::read(root.path().join("request.bin")).unwrap(), [0, 255, 1, 10]);
        assert!(!root.path().join("nested/result.bin").exists());
    }

    #[test]
    fn all_three_must_succeed_with_complete_equivalent_observations() {
        let root = tempfile::tempdir().unwrap();
        write(root.path(), "a.test.js", "console.log(42);");
        let report = measured(root.path(), None, true);
        assert_eq!(report.verdict, "PASS", "{report:#?}");
        assert_eq!(
            (
                report.total_tests,
                report.passed,
                report.failed,
                report.errored,
                report.skipped
            ),
            (1, 1, 0, 0, 0)
        );
        let row = &report.cases[0];
        assert_eq!(row.outcome, CaseOutcome::Match);
        assert_eq!(row.node, row.bun);
        assert_eq!(row.node, row.native);
        assert!(row.node.as_ref().unwrap().workspace_delta.is_some());
        assert!(!report.release_certification);
        assert!(!report.distinct_reference_binaries);
        assert_eq!(
            serde_json::from_slice::<ProductReport>(&serde_json::to_vec(&report).unwrap()).unwrap(),
            report
        );
    }

    #[test]
    fn native_matching_one_disagreeing_reference_is_not_a_pass() {
        let root = tempfile::tempdir().unwrap();
        write(
            root.path(),
            "a.test.js",
            "console.log(process.argv.includes('bun')?'bun':'node');",
        );
        write(root.path(), "b.test.js", "console.log(42);");
        let report = measured(root.path(), None, false);
        assert_eq!(report.verdict, "INCONCLUSIVE");
        assert_eq!(
            (
                report.reference_divergences,
                report.native_divergences,
                report.passed
            ),
            (1, 0, 1)
        );
        assert_eq!(report.cases[0].node, report.cases[0].native);
        assert_eq!(report.cases[0].outcome, CaseOutcome::ReferenceDivergence);
        assert!(
            report.cases[0]
                .divergences
                .contains(&"node/bun:stdout:byte_mismatch".into())
        );
    }

    #[test]
    fn matching_failures_are_reference_failures_not_compatibility() {
        let root = tempfile::tempdir().unwrap();
        write(root.path(), "a.test.js", "process.exit(7);");
        let report = measured(root.path(), None, false);
        assert_eq!(report.verdict, "INCONCLUSIVE");
        assert_eq!((report.reference_failures, report.passed), (1, 0));
        assert_eq!(report.cases[0].outcome, CaseOutcome::ReferenceFailure);
        assert_eq!(report.cases[0].native.as_ref().unwrap().exit_code, Some(7));
    }

    #[test]
    fn native_stdout_stderr_and_exit_regressions_are_identified_separately() {
        let root = tempfile::tempdir().unwrap();
        write(
            root.path(),
            "a.test.js",
            "console.log(process.argv.includes('native')?'bad':'ok');",
        );
        write(
            root.path(),
            "b.test.js",
            "console.error(process.argv.includes('native')?'bad':'ok');",
        );
        write(
            root.path(),
            "c.test.js",
            "process.exit(process.argv.includes('native')?7:0);",
        );
        let report = measured(root.path(), None, false);
        assert_eq!(report.verdict, "FAIL");
        assert_eq!(report.native_divergences, 3);
        for row in &report.cases {
            assert_eq!(row.outcome, CaseOutcome::NativeDivergence);
        }
        assert!(
            report.cases[0]
                .divergences
                .contains(&"node/native:stdout:byte_mismatch".into())
        );
        assert!(
            report.cases[1]
                .divergences
                .contains(&"node/native:stderr:byte_mismatch".into())
        );
        assert!(
            report.cases[2]
                .divergences
                .contains(&"native:unsuccessful_exit".into())
        );
    }

    #[test]
    fn original_goes_to_both_references_and_only_native_gets_the_candidate() {
        let original = tempfile::tempdir().unwrap();
        let candidate = tempfile::tempdir().unwrap();
        write(original.path(), "a.test.js", "console.log(6*7);");
        write(candidate.path(), "a.test.js", "console.log(42);");
        let report = measured(original.path(), Some(candidate.path()), true);
        assert_eq!(report.verdict, "PASS");
        assert_ne!(report.input_sha256, report.candidate_input_sha256);
        write(candidate.path(), "a.test.js", "console.log(43);");
        let report = measured(original.path(), Some(candidate.path()), true);
        assert_eq!(report.verdict, "FAIL");
        assert_eq!(report.cases[0].node, report.cases[0].bun);
        assert_ne!(report.cases[0].node, report.cases[0].native);
    }

    #[test]
    fn filesystem_only_reference_disagreement_blocks_agreement_with_one_reference() {
        let root = tempfile::tempdir().unwrap();
        write(
            root.path(),
            "a.test.js",
            "require('fs').writeFileSync('artifact',process.argv.includes('bun')?'bun':'node');",
        );
        let report = measured(root.path(), None, true);
        assert_eq!(report.verdict, "INCONCLUSIVE");
        let row = &report.cases[0];
        assert_eq!(
            row.node.as_ref().unwrap().stdout,
            row.bun.as_ref().unwrap().stdout
        );
        assert!(
            row.divergences
                .contains(&"node/bun:filesystem:workspace_delta_mismatch".into())
        );
        assert!(!root.path().join("artifact").exists());
    }

    #[test]
    fn filesystem_only_native_regression_and_complete_deltas_are_compared() {
        let root = tempfile::tempdir().unwrap();
        write(
            root.path(),
            "a.test.js",
            "const fs=require('fs'); for(let i=0;i<25;i++)fs.writeFileSync('file'+i,'same'); fs.writeFileSync('zz',process.argv.includes('native')?'bad':'ok');",
        );
        let report = measured(root.path(), None, true);
        assert_eq!(report.verdict, "FAIL");
        let row = &report.cases[0];
        assert!(
            row.node
                .as_ref()
                .unwrap()
                .workspace_delta
                .as_ref()
                .unwrap()
                .details_truncated
        );
        assert!(
            row.divergences
                .contains(&"node/native:filesystem:workspace_delta_mismatch".into())
        );
        assert_eq!(
            row.node.as_ref().unwrap().stdout,
            row.native.as_ref().unwrap().stdout
        );
    }

    #[test]
    fn every_case_and_leg_uses_fresh_captured_dependencies() {
        let root = tempfile::tempdir().unwrap();
        write(root.path(), "value", "captured");
        let source = "const fs=require('fs');console.log(fs.readFileSync('value','utf8'));fs.writeFileSync('value','changed');";
        write(root.path(), "a.test.js", source);
        write(root.path(), "b.test.js", source);
        let deadline = Instant::now() + Duration::from_secs(120);
        let inputs = CapturedInputs::capture(root.path(), None, deadline).unwrap();
        write(root.path(), "value", "later");
        let report = measured_inputs(&inputs, true, deadline, Duration::from_secs(5));
        assert_eq!(report.verdict, "PASS");
        assert_eq!(report.passed, 2);
        for row in &report.cases {
            assert_eq!(row.node.as_ref().unwrap().stdout.bytes, 9);
        }
        assert_eq!(
            fs::read_to_string(root.path().join("value")).unwrap(),
            "later"
        );
    }

    #[test]
    fn timeout_keeps_other_leg_evidence_and_later_cases() {
        let root = tempfile::tempdir().unwrap();
        write(
            root.path(),
            "a.test.js",
            "if(process.argv.includes('bun'))setInterval(()=>{},1000);else console.log('ok');",
        );
        write(root.path(), "b.test.js", "console.log(42);");
        let deadline = Instant::now() + Duration::from_secs(120);
        let inputs = CapturedInputs::capture(root.path(), None, deadline).unwrap();
        let report = measured_inputs(&inputs, false, deadline, Duration::from_secs(1));
        assert_eq!(report.verdict, "ERROR");
        assert_eq!((report.errored, report.passed, report.skipped), (1, 1, 0));
        assert!(report.cases[0].node.is_some());
        assert!(report.cases[0].bun.is_none());
        assert!(report.cases[0].native.is_some());
    }

    #[test]
    fn all_three_execute_exactly_once_per_selected_case() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let marker = outside.path().join("runs");
        write(
            root.path(),
            "scripts/check.js",
            &format!(
                "require('fs').appendFileSync({},process.argv[2]+'\\n');console.log(42);",
                serde_json::to_string(&marker).unwrap()
            ),
        );
        write(
            root.path(),
            "fixture.test.js",
            "throw new Error('not an entrypoint');",
        );
        write(
            root.path(),
            ".franken-node/migration-tests.json",
            r#"{"schema_version":"franken-node/migration-tests/v1","tests":["scripts/check.js"]}"#,
        );
        let report = measured(root.path(), None, true);
        assert_eq!(report.verdict, "PASS");
        assert_eq!(report.total_tests, 1);
        assert_eq!(fs::read_to_string(marker).unwrap(), "node\nbun\nnative\n");
    }

    #[test]
    fn public_oracle_refuses_copied_reference_binaries_before_guest_execution() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let marker = outside.path().join("executed");
        write(
            root.path(),
            "a.test.js",
            &format!(
                "require('fs').writeFileSync({},'bad');",
                serde_json::to_string(&marker).unwrap()
            ),
        );
        let renamed = outside.path().join("not-bun");
        fs::copy(node_on_path().unwrap(), &renamed).unwrap();
        let error =
            run_project_comparison(root.path(), None, Path::new("/bin/false"), &renamed, false)
                .unwrap_err();
        assert!(error.to_string().contains("distinct executable hashes"));
        assert!(!marker.exists());
    }

    #[test]
    fn invalid_inputs_missing_bun_and_in_project_runtimes_never_fall_back() {
        let root = tempfile::tempdir().unwrap();
        let candidate = tempfile::tempdir().unwrap();
        write(root.path(), "a.test.js", "console.log(42);");
        write(candidate.path(), "b.test.js", "console.log(42);");
        let absent = Path::new("/absent/franken-product-oracle-bun");
        assert!(
            run_project_comparison(
                root.path(),
                Some(candidate.path()),
                Path::new("/bin/false"),
                absent,
                false
            )
            .unwrap_err()
            .to_string()
            .contains("test inventories differ")
        );
        assert!(
            run_project_comparison(root.path(), None, Path::new("/bin/false"), absent, false)
                .unwrap_err()
                .to_string()
                .contains("resolve Bun")
        );
        let copied = root.path().join("bun");
        fs::copy("/bin/false", &copied).unwrap();
        assert!(
            run_project_comparison(root.path(), None, Path::new("/bin/false"), &copied, false)
                .unwrap_err()
                .to_string()
                .contains("outside both")
        );
    }

    #[test]
    fn single_reference_orchestration_evidence_cannot_authorize_product_admission() {
        let root = tempfile::tempdir().unwrap();
        write(root.path(), "a.test.js", "console.log(42);");
        let report = measured(root.path(), None, true);
        let tests = [PathBuf::from("a.test.js")];
        assert_eq!(report.verdict, "PASS");
        assert!(
            report
                .check_admission(&report.input_sha256, &report.candidate_input_sha256, &tests)
                .unwrap_err()
                .to_string()
                .contains("distinct reference")
        );
        let mut mislabelled = report.clone();
        mislabelled.distinct_reference_binaries = true;
        assert!(
            mislabelled
                .check_admission(&report.input_sha256, &report.candidate_input_sha256, &tests)
                .is_err()
        );
        assert!(
            report
                .check_admission(&"0".repeat(64), &report.candidate_input_sha256, &tests)
                .unwrap_err()
                .to_string()
                .contains("prepared candidate")
        );
    }

    #[test]
    fn captured_product_entrypoint_checks_inventory_and_deadline_before_runtime_access() {
        let original = tempfile::tempdir().unwrap();
        let candidate = tempfile::tempdir().unwrap();
        write(original.path(), "a.test.js", "console.log(42);");
        write(candidate.path(), "b.test.js", "console.log(42);");
        let deadline = Instant::now() + Duration::from_secs(10);
        let reference = Snapshot::capture(original.path(), deadline).unwrap();
        let changed = Snapshot::capture(candidate.path(), deadline).unwrap();
        let missing = Path::new("/absent/runtime");
        assert!(
            run_captured(
                [original.path(), candidate.path()],
                [&reference, &changed],
                missing,
                missing,
                deadline,
                true
            )
            .unwrap_err()
            .to_string()
            .contains("test inventories differ")
        );
        assert!(
            run_captured(
                [original.path(), original.path()],
                [&reference, &reference],
                missing,
                missing,
                Instant::now(),
                true
            )
            .unwrap_err()
            .to_string()
            .contains("budget")
        );
    }
}
