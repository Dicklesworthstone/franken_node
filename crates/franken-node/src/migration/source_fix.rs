//! Verify a proposed source repair against an immutable failure capsule.
//!
//! This is a child of product replay so both capsule codecs and their existing
//! reexecution/admission paths are reused. Neither the stored expected report
//! nor its content hash is rewritten to describe the repair. No source is
//! installed, no capsule is republished, and no recorded command is executed.
//! The caller must approve execution and independently authenticate the pin.

use super::super::super as pair;
use pair::{Invocation, Snapshot, TOTAL_TIMEOUT, budget, matched_tests, runtime_invocations};
use anyhow::{Context, Result, ensure};
use serde::Serialize;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

#[derive(Debug, Serialize)]
#[serde(tag = "oracle", content = "result", rename_all = "snake_case")]
pub enum ReplayEvidence {
    Pair(Box<pair::ReplayResult>),
    Product(Box<super::ReplayResult>),
}

impl ReplayEvidence {
    fn verdict(&self) -> &str {
        match self {
            Self::Pair(report) => &report.verdict,
            Self::Product(report) => &report.verdict,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct SourceFixReport {
    pub schema_version: String,
    pub verdict: String,
    /// Identity of the UNMODIFIED seed capsule, not a hash of repaired inputs.
    pub seed_content_sha256: String,
    pub input_sha256: String,
    pub captured_candidate_input_sha256: String,
    pub candidate_input_sha256: String,
    pub candidate_project: PathBuf,
    pub candidate_source_unchanged: bool,
    pub native_runtime_changed: bool,
    pub execution_performed: bool,
    pub environment_reproduced: bool,
    pub release_certification: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_recheck_error: Option<String>,
    /// Preserve every role and observation in its original report schema.
    pub replay: ReplayEvidence,
}

// Contains private source bytes; deliberately no Debug/Serialize.
enum Seed {
    Pair(Box<pair::Loaded>),
    Product(Box<super::Loaded>),
}

impl Seed {
    fn original(&self) -> &Snapshot {
        match self {
            Self::Pair(seed) => &seed.original,
            Self::Product(seed) => &seed.original,
        }
    }

    fn candidate(&self) -> &Snapshot {
        match self {
            Self::Pair(seed) => seed.candidate(),
            Self::Product(seed) => seed.candidate(),
        }
    }

    fn require_failure(&self) -> Result<()> {
        match self {
            Self::Pair(seed) => {
                let expected = &seed.capsule.payload.expected;
                ensure!(expected.verdict == "FAIL" && expected.cases.iter().all(|row|
                    row.reference.as_ref().is_some_and(|run|
                        run.exit_code == Some(0) && run.signal.is_none())),
                    "source fix requires a captured failure with successful references");
            }
            Self::Product(seed) => {
                let expected = &seed.capsule.payload.expected;
                ensure!(expected.verdict == "FAIL" && expected.reference_failures == 0
                    && expected.reference_divergences == 0,
                    "source fix requires a captured native failure with agreeing successful references");
            }
        }
        Ok(())
    }
}

struct Prepared {
    seed: Seed,
    seed_pin: String,
    original_hash: String,
    archived_candidate_hash: String,
    repaired_hash: String,
    project: PathBuf,
}

impl Prepared {
    fn capture(path: &Path, pin: &str, project: &Path, product: bool, deadline: Instant) -> Result<Self> {
        // Authenticate and validate the entire archive before accessing the
        // caller's proposed repair. Explicit role selection must match schema;
        // there is no product-to-pair fallback when Bun was not supplied.
        let mut seed = if product {
            Seed::Product(Box::new(super::load(path, Some(pin), deadline)?))
        } else {
            Seed::Pair(Box::new(pair::load(path, Some(pin), deadline)?))
        };
        seed.require_failure()?;
        let metadata = fs::symlink_metadata(project).context("inspect repaired project")?;
        ensure!(metadata.is_dir() && !metadata.is_symlink(),
            "repaired project must be an ordinary directory, not a symlink");
        let project = project.canonicalize().context("resolve repaired project")?;
        ensure!(!path.canonicalize()?.starts_with(&project),
            "seed capsule must be outside the repaired project");
        budget(deadline)?;
        let repair = Snapshot::capture(&project, deadline)?;
        // This also checks per-test cwd, argv, environment, input transport,
        // stdin bytes, concurrency, and independent output-oracle fixtures.
        // Source/module additions are allowed; weaker test conditions are not.
        matched_tests(seed.original(), &repair)?;
        let original_hash = seed.original().digest.clone();
        let archived_candidate_hash = seed.candidate().digest.clone();
        let repaired_hash = repair.digest.clone();
        match &mut seed {
            Seed::Pair(seed) => seed.candidate = Some(repair),
            Seed::Product(seed) => seed.candidate = Some(repair),
        }
        Ok(Self { seed, seed_pin: pin.into(), original_hash, archived_candidate_hash,
            repaired_hash, project })
    }

    fn execute(self, runtimes: &[&Invocation], deadline: Instant) -> Result<SourceFixReport> {
        budget(deadline)?;
        for runtime in runtimes {
            let executable = runtime.executable.canonicalize().context("resolve repair runtime")?;
            ensure!(!executable.starts_with(&self.project),
                "repair runtimes must be outside the repaired project");
        }
        let (replay, native_runtime_changed) = match self.seed {
            Seed::Pair(seed) => {
                ensure!(runtimes.len() == 2, "pair source fix requires exactly two runtime roles");
                let previous = seed.capsule.payload.expected.native_runtime.clone();
                let report = pair::reexecute(*seed, runtimes[0], runtimes[1], true, deadline)?;
                let changed = !pair::same_runtime(&previous, &report.validation.native_runtime);
                (ReplayEvidence::Pair(Box::new(report)), changed)
            }
            Seed::Product(seed) => {
                ensure!(runtimes.len() == 3, "product source fix requires all three runtime roles");
                let previous = seed.capsule.payload.expected.native_runtime.clone();
                let report = super::reexecute(*seed,
                    [runtimes[0], runtimes[1], runtimes[2]], true, deadline)?;
                let changed = !pair::same_runtime(&previous, &report.validation.native_runtime);
                (ReplayEvidence::Product(Box::new(report)), changed)
            }
        };
        // The executor used only captured bytes. Do not describe the CURRENT
        // repair as verified after an editor or a guest changed its live tree.
        // Preserve the completed measurement even when this recheck fails.
        let (unchanged, source_verdict, source_recheck_error) = match Snapshot::capture(&self.project, deadline) {
            Ok(current) if current.digest == self.repaired_hash => (true, "FIX_VERIFIED", None),
            Ok(_) => (false, "SOURCE_DRIFT", Some("repaired project changed during fix verification".into())),
            Err(error) => (false, "ERROR", Some(format!("repaired project recheck failed: {error:#}"))),
        };
        let verdict = if replay.verdict() == "FIX_VERIFIED" { source_verdict } else { replay.verdict() };
        Ok(SourceFixReport {
            schema_version: "franken-node/source-fix-verification/v1".into(),
            verdict: verdict.into(), seed_content_sha256: self.seed_pin,
            input_sha256: self.original_hash,
            captured_candidate_input_sha256: self.archived_candidate_hash,
            candidate_input_sha256: self.repaired_hash,
            candidate_project: self.project, candidate_source_unchanged: unchanged,
            native_runtime_changed, execution_performed: true,
            environment_reproduced: false, release_certification: false,
            source_recheck_error, replay,
        })
    }
}

/// Execute an independently pinned failure against a captured repair directory.
/// The operator approves both captured reference code and the proposed repair.
/// Reference identities/observations and the recorded comparison scope remain
/// mandatory. The native executable may also change, explicitly reported here.
/// Results are test-scoped measurements, NOT source-installation authorization.
pub fn verify(
    capsule: &Path,
    expected_sha256: &str,
    candidate_project: &Path,
    native: &Path,
    bun: Option<&Path>,
) -> Result<SourceFixReport> {
    let deadline = Instant::now() + TOTAL_TIMEOUT;
    let prepared = Prepared::capture(capsule, expected_sha256, candidate_project,
        bun.is_some(), deadline)?;
    // Resolve executables only AFTER admitting the pinned seed and repair.
    let (node, native) = runtime_invocations(native)?;
    if let Some(bun) = bun {
        let bun = Invocation { executable: bun.canonicalize().context("resolve Bun executable")?,
            before: vec![], after: vec![] };
        prepared.execute(&[&node, &bun, &native], deadline)
    } else {
        prepared.execute(&[&node, &native], deadline)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super as product;
    use std::collections::BTreeMap;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::time::Duration;

    fn deadline() -> Instant { Instant::now() + Duration::from_secs(120) }
    fn node() -> Invocation {
        pair::runtime_invocations(Path::new("/bin/false")).unwrap().0
    }
    fn write(root: &Path, path: &str, source: &str) {
        let path = root.join(path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, source).unwrap();
    }

    // Real Node/Node execution: these tests measure source repair and replay
    // orchestration, not successful execution by a Franken implementation.
    fn pair_seed(original: &Path, candidate: &Path, path: &Path) -> String {
        let original = Snapshot::capture(original, deadline()).unwrap();
        let candidate = Snapshot::capture(candidate, deadline()).unwrap();
        let expected = pair::execute_suite_pair(&original, &candidate, &node(), &node(),
            deadline(), Duration::from_secs(5), true).unwrap();
        let mut blobs = BTreeMap::new();
        let mut expanded = 0;
        let mut metadata = 0;
        let original = pair::store_snapshot(&original, &mut blobs, &mut expanded, &mut metadata, deadline()).unwrap();
        let candidate = pair::store_snapshot(&candidate, &mut blobs, &mut expanded, &mut metadata, deadline()).unwrap();
        let payload = pair::Payload {
            schema_version: pair::SCHEMA.into(), implementation_sha256: pair::implementation_hash(),
            original, candidate: Some(candidate),
            blobs: blobs.into_iter().map(|(sha256, hex)| pair::Blob { sha256, hex }).collect(), expected,
        };
        let pin = pair::payload_hash(&payload).unwrap();
        let capsule = pair::Capsule { payload, content_sha256: pin.clone() };
        fs::write(path, serde_json::to_vec(&capsule).unwrap()).unwrap();
        pin
    }

    fn projects() -> (tempfile::TempDir, tempfile::TempDir, tempfile::TempDir, tempfile::TempDir) {
        let original = tempfile::tempdir().unwrap();
        let broken = tempfile::tempdir().unwrap();
        let repaired = tempfile::tempdir().unwrap();
        let reports = tempfile::tempdir().unwrap();
        for (root, value) in [(original.path(), 42), (broken.path(), 43), (repaired.path(), 42)] {
            write(root, "case.test.cjs", "console.log(require('./helper.cjs'));");
            write(root, "helper.cjs", &format!("module.exports={value};"));
            write(root, "passing.test.cjs", "console.log('passing sibling');");
        }
        (original, broken, repaired, reports)
    }

    #[test]
    fn changed_dependency_and_new_module_verify_without_mutating_seed_or_original() {
        let (original, broken, repaired, reports) = projects();
        let capsule = reports.path().join("failure.json");
        let pin = pair_seed(original.path(), broken.path(), &capsule);
        let seed = fs::read(&capsule).unwrap();
        write(repaired.path(), "helper.cjs", "module.exports=require('./new.cjs');");
        write(repaired.path(), "new.cjs", "module.exports=6*7;");
        fs::set_permissions(repaired.path().join("helper.cjs"), fs::Permissions::from_mode(0o755)).unwrap();
        let prepared = Prepared::capture(&capsule, &pin, repaired.path(), false, deadline()).unwrap();
        let expected_hash = prepared.repaired_hash.clone();
        let result = prepared.execute(&[&node(), &node()], deadline()).unwrap();
        assert_eq!(result.verdict, "FIX_VERIFIED", "{result:#?}");
        assert!(result.candidate_source_unchanged);
        assert!(!result.native_runtime_changed);
        assert_eq!(result.seed_content_sha256, pin);
        assert_eq!(result.candidate_input_sha256, expected_hash);
        assert_ne!(result.candidate_input_sha256, result.captured_candidate_input_sha256);
        let ReplayEvidence::Pair(replayed) = &result.replay else { panic!("pair evidence required") };
        assert_eq!(replayed.validation.passed, 2);
        assert_eq!(replayed.validation.candidate_input_sha256, expected_hash);
        assert_eq!(fs::read(&capsule).unwrap(), seed);
        assert_eq!(fs::read_to_string(original.path().join("helper.cjs")).unwrap(), "module.exports=42;");
        assert_eq!(fs::read_to_string(broken.path().join("helper.cjs")).unwrap(), "module.exports=43;");
        assert!(!repaired.path().join(".migrate-backup").exists());
        assert!(!result.release_certification && !result.environment_reproduced);
    }

    #[test]
    fn unchanged_failure_and_new_failure_in_a_passing_sibling_do_not_verify() {
        let (original, broken, repaired, reports) = projects();
        let capsule = reports.path().join("failure.json");
        let pin = pair_seed(original.path(), broken.path(), &capsule);
        let broken_result = Prepared::capture(&capsule, &pin, broken.path(), false, deadline()).unwrap()
            .execute(&[&node(), &node()], deadline()).unwrap();
        assert_eq!(broken_result.verdict, "FIX_NOT_VERIFIED");
        write(repaired.path(), "passing.test.cjs", "process.exit(9);");
        let result = Prepared::capture(&capsule, &pin, repaired.path(), false, deadline()).unwrap()
            .execute(&[&node(), &node()], deadline()).unwrap();
        assert_eq!(result.verdict, "FIX_NOT_VERIFIED");
        let ReplayEvidence::Pair(replay) = result.replay else { panic!("pair") };
        assert_eq!((replay.validation.passed, replay.validation.failed), (1, 1));
    }

    #[test]
    fn live_source_drift_preserves_captured_pass_but_refuses_current_source_approval() {
        let (original, broken, repaired, reports) = projects();
        let capsule = reports.path().join("failure.json");
        let pin = pair_seed(original.path(), broken.path(), &capsule);
        let prepared = Prepared::capture(&capsule, &pin, repaired.path(), false, deadline()).unwrap();
        write(repaired.path(), "helper.cjs", "throw new Error('edited after capture');");
        let result = prepared.execute(&[&node(), &node()], deadline()).unwrap();
        assert_eq!(result.verdict, "SOURCE_DRIFT");
        assert!(!result.candidate_source_unchanged);
        assert!(result.source_recheck_error.as_ref().unwrap().contains("changed during"));
        assert_eq!(result.replay.verdict(), "FIX_VERIFIED");
    }

    #[test]
    fn reference_drift_is_not_rescued_by_a_repaired_candidate() {
        let (original, broken, repaired, reports) = projects();
        let state = reports.path().join("state");
        fs::write(&state, "before").unwrap();
        let reference = format!("console.log(require('fs').readFileSync({},'utf8'));",
            serde_json::to_string(&state).unwrap());
        write(original.path(), "case.test.cjs", &reference);
        let capsule = reports.path().join("failure.json");
        let pin = pair_seed(original.path(), broken.path(), &capsule);
        fs::write(&state, "after").unwrap();
        write(repaired.path(), "case.test.cjs", "console.log('after');");
        let result = Prepared::capture(&capsule, &pin, repaired.path(), false, deadline()).unwrap()
            .execute(&[&node(), &node()], deadline()).unwrap();
        assert_eq!(result.verdict, "REFERENCE_DRIFT");
        let ReplayEvidence::Pair(replay) = result.replay else { panic!("pair") };
        assert_eq!(replay.validation.verdict, "PASS");
        assert_eq!(replay.mismatched_tests, ["case.test.cjs"]);
    }

    #[test]
    fn admission_rejects_missing_tests_changed_oracles_and_changed_execution_before_runtime_lookup() {
        let (original, broken, repaired, reports) = projects();
        let manifest = r#"{"schema_version":"franken-node/migration-tests/v1","tests":["case.test.cjs","passing.test.cjs"],"execution":{"case.test.cjs":{"stdin":"request.bin","environment":{"APP_MODE":"captured"}}},"expectations":{"case.test.cjs":{"stdout":"golden.txt"}}}"#;
        for root in [original.path(), broken.path(), repaired.path()] {
            write(root, ".franken-node/migration-tests.json", manifest);
            write(root, "request.bin", "request");
            write(root, "golden.txt", "42\n");
        }
        // Keep golden expectations valid in the seed, and fail its other case.
        write(broken.path(), "helper.cjs", "module.exports=42;");
        write(broken.path(), "passing.test.cjs", "console.log('broken sibling');");
        let capsule = reports.path().join("failure.json");
        let pin = pair_seed(original.path(), broken.path(), &capsule);
        for (file, changed, restored) in [
            ("request.bin", "changed request", "request"),
            ("golden.txt", "wrong golden\n", "42\n"),
            (".franken-node/migration-tests.json", &manifest.replace("captured", "changed"), manifest),
            (".franken-node/migration-tests.json", &manifest.replace(",\"passing.test.cjs\"", ""), manifest),
        ] {
            write(repaired.path(), file, changed);
            assert!(verify(&capsule, &pin, repaired.path(), Path::new("/absent/native"), None).is_err());
            assert!(Prepared::capture(&capsule, &pin, repaired.path(), false, deadline()).is_err());
            write(repaired.path(), file, restored);
        }
    }

    #[test]
    fn capsule_pin_and_repair_path_boundaries_fail_before_execution() {
        let (original, broken, repaired, reports) = projects();
        let capsule = reports.path().join("failure.json");
        let pin = pair_seed(original.path(), broken.path(), &capsule);
        let error = Prepared::capture(&capsule, &"0".repeat(64), Path::new("/absent/repair"), false, deadline())
            .err().unwrap();
        assert!(error.to_string().contains("trusted hash"));
        let alias = reports.path().join("repair-link");
        symlink(repaired.path(), &alias).unwrap();
        assert!(Prepared::capture(&capsule, &pin, &alias, false, deadline()).is_err());
        let inside = repaired.path().join("seed.json");
        fs::copy(&capsule, &inside).unwrap();
        assert!(Prepared::capture(&inside, &pin, repaired.path(), false, deadline()).err().unwrap()
            .to_string().contains("outside"));
        assert!(Prepared::capture(&capsule, &pin, repaired.path(), true, deadline()).is_err());
    }

    #[test]
    fn captured_success_and_failed_reference_are_not_source_fix_seeds() {
        let (original, broken, repaired, reports) = projects();
        for (index, source) in ["console.log(42);", "process.exit(8);"].iter().enumerate() {
            write(original.path(), "case.test.cjs", source);
            write(broken.path(), "case.test.cjs", source);
            let path = reports.path().join(format!("seed-{index}.json"));
            let pin = pair_seed(original.path(), broken.path(), &path);
            assert!(Prepared::capture(&path, &pin, repaired.path(), false, deadline()).err().unwrap()
                .to_string().contains("successful references"));
        }
    }

    #[test]
    fn runtime_executable_inside_repair_is_not_run() {
        let (original, broken, repaired, reports) = projects();
        let capsule = reports.path().join("failure.json");
        let pin = pair_seed(original.path(), broken.path(), &capsule);
        let executable = repaired.path().join("runtime");
        fs::copy("/bin/false", &executable).unwrap();
        let prepared = Prepared::capture(&capsule, &pin, repaired.path(), false, deadline()).unwrap();
        let bad = Invocation { executable, before: vec![], after: vec![] };
        assert!(prepared.execute(&[&node(), &bad], deadline()).unwrap_err().to_string().contains("outside"));
    }

    fn product_seed(original: &Path, broken: &Path, path: &Path, second: &Invocation) -> String {
        let reference = Snapshot::capture(original, deadline()).unwrap();
        let candidate = Snapshot::capture(broken, deadline()).unwrap();
        let node = node();
        let runtimes = [&node, second, &node];
        let identities = [node.identity(deadline()).unwrap(), second.identity(deadline()).unwrap(),
            node.identity(deadline()).unwrap()];
        let expected = product::product_oracle::execute(&reference, &candidate, runtimes, identities,
            deadline(), Duration::from_secs(5), true).unwrap();
        let stored = product::stored(&reference, &candidate, deadline()).unwrap();
        let captured = product::captured(expected, [&reference, &candidate],
            [original.into(), broken.into()], stored).unwrap();
        captured.write_capsule(path).unwrap().content_sha256
    }

    #[test]
    fn product_source_repairs_keep_all_roles_and_do_not_downgrade_to_pair() {
        let original = tempfile::tempdir().unwrap();
        let broken = tempfile::tempdir().unwrap();
        let repair = tempfile::tempdir().unwrap();
        let out = tempfile::tempdir().unwrap();
        for (root, code) in [(original.path(), "globalThis.answer=42;"),
            (broken.path(), "process.exit(9);"), (repair.path(), "globalThis.answer=6*7;")] {
            write(root, "case.test.js", code);
        }
        // /bin/true is an explicitly named second reference for orchestration,
        // NOT a Bun implementation or a native compatibility claim.
        let second = Invocation { executable: PathBuf::from("/bin/true").canonicalize().unwrap(),
            before: vec![], after: vec![] };
        let path = out.path().join("product.json");
        let pin = product_seed(original.path(), broken.path(), &path, &second);
        let bytes = fs::read(&path).unwrap();
        assert!(Prepared::capture(&path, &pin, repair.path(), false, deadline()).is_err());
        let prepared = Prepared::capture(&path, &pin, repair.path(), true, deadline()).unwrap();
        let result = prepared.execute(&[&node(), &second, &node()], deadline()).unwrap();
        assert_eq!(result.verdict, "FIX_VERIFIED", "{result:#?}");
        assert_eq!(fs::read(&path).unwrap(), bytes);
        let ReplayEvidence::Product(replay) = result.replay else { panic!("all roles required") };
        assert_eq!(replay.validation.passed, 1);
        assert!(replay.validation.cases[0].bun.is_some());
        assert_eq!(replay.validation.candidate_input_sha256, result.candidate_input_sha256);
    }

    #[test]
    fn second_reference_only_drift_prevents_product_source_fix() {
        let original = tempfile::tempdir().unwrap();
        let broken = tempfile::tempdir().unwrap();
        let repair = tempfile::tempdir().unwrap();
        let out = tempfile::tempdir().unwrap();
        for (root, code) in [(original.path(), "globalThis.answer=42;"),
            (broken.path(), "process.exit(9);"), (repair.path(), "globalThis.answer=6*7;")] {
            write(root, "case.test.js", code);
        }
        let marker = out.path().join("changed");
        // Use a real shell solely to create a deterministic second-reference
        // observation change. No Bun/native implementation is substituted.
        let second = Invocation { executable: PathBuf::from("/bin/sh").canonicalize().unwrap(),
            before: vec!["-c".into(), format!("if test -f '{}'; then printf drift; fi", marker.display()).into(),
                "reference".into()], after: vec![] };
        let path = out.path().join("product.json");
        let pin = product_seed(original.path(), broken.path(), &path, &second);
        fs::write(&marker, "changed").unwrap();
        let result = Prepared::capture(&path, &pin, repair.path(), true, deadline()).unwrap()
            .execute(&[&node(), &second, &node()], deadline()).unwrap();
        assert_eq!(result.verdict, "REFERENCE_DRIFT", "{result:#?}");
        let ReplayEvidence::Product(replay) = result.replay else { panic!("product") };
        assert_eq!(replay.validation.reference_divergences, 1);
        assert_eq!(replay.mismatched_tests, ["case.test.js"]);
    }
}
