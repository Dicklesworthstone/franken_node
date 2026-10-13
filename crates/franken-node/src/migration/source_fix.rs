//! Verify a proposed source repair against an immutable failure capsule.
//!
//! This is a child of product replay so both capsule codecs and their existing
//! reexecution/admission paths are reused. Neither the stored expected report
//! nor its content hash is rewritten to describe the repair. No source is
//! installed, no capsule is republished, and no recorded command is executed.
//! The caller must approve execution and independently authenticate the pin.

use super::super::super as pair;
use pair::{Entry, EntryData, Invocation, Snapshot, TOTAL_TIMEOUT, budget, matched_tests, runtime_invocations};
use anyhow::{Context, Result, ensure};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
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

/// Describes source identity without exposing source bytes or link targets.
#[derive(Clone, Debug, Serialize)]
pub struct EntrySummary {
    pub kind: &'static str,
    pub mode: u32,
    pub bytes: usize,
    pub sha256: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct SourceChange {
    pub path: PathBuf,
    pub before: Option<EntrySummary>,
    pub after: Option<EntrySummary>,
}

#[derive(Clone, Debug, Serialize)]
pub struct SourceChanges {
    pub changed_paths: usize,
    pub added_paths: usize,
    pub removed_paths: usize,
    pub modified_paths: usize,
    /// Commits every sorted change, not merely the displayed prefix.
    pub sha256: String,
    pub changes: Vec<SourceChange>,
    pub details_truncated: bool,
}

/// An inspection describes bounded captured inputs. It does not run or approve
/// code; execution must receive an independently reviewed candidate input pin.
#[derive(Debug, Serialize)]
pub struct SourceFixInspection {
    pub schema_version: &'static str,
    pub verdict: &'static str,
    pub oracle: &'static str,
    pub seed_content_sha256: String,
    pub input_sha256: String,
    pub captured_candidate_input_sha256: String,
    pub candidate_input_sha256: String,
    pub candidate_project: PathBuf,
    pub protected_paths: Vec<PathBuf>,
    pub source_changes: SourceChanges,
    pub execution_performed: bool,
    pub environment_reproduced: bool,
    pub release_certification: bool,
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
    /// True only if an independent candidate hash matched BEFORE runtime lookup.
    pub candidate_input_approved: bool,
    pub protected_paths: Vec<PathBuf>,
    pub source_changes: SourceChanges,
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

fn same_entry(before: &Entry, after: &Entry) -> bool {
    before.mode == after.mode && match (&before.data, &after.data) {
        (EntryData::Directory, EntryData::Directory) => true,
        (EntryData::File(left), EntryData::File(right)) => left == right,
        (EntryData::Link(left), EntryData::Link(right)) => left == right,
        _ => false,
    }
}

/// Freeze the archived CANDIDATE harness, which may legitimately differ from
/// the original reference's harness after an earlier measured migration.
/// Ordinary migration/reduction can still rewrite tests; source-fix claims
/// must not repair an application by replacing its assertion with a constant.
fn frozen_harnesses(candidate: &Snapshot, repair: &Snapshot, deadline: Instant) -> Result<Vec<PathBuf>> {
    let mut paths: BTreeSet<_> = matched_tests(candidate, repair)?.into_iter().collect();
    let manifest = PathBuf::from(".franken-node/migration-tests.json");
    // Freeze even whitespace/permission changes to the declaration: the entire
    // captured test contract is fixed, not just the fields understood today.
    if candidate.entries.contains_key(&manifest) || repair.entries.contains_key(&manifest) {
        paths.insert(manifest);
    }
    for path in &paths {
        budget(deadline)?;
        let before = candidate.entries.get(path).context("frozen test input missing from capsule")?;
        let after = repair.entries.get(path).context("repair removed a frozen test input")?;
        ensure!(matches!(&before.data, EntryData::File(_))
            && matches!(&after.data, EntryData::File(_)) && same_entry(before, after),
            "repair changed frozen test input bytes, kind or permissions: {}", path.display());
    }
    Ok(paths.into_iter().collect())
}

fn entry_summary(entry: &Entry, deadline: Instant) -> Result<EntrySummary> {
    let (kind, data) = match &entry.data {
        EntryData::Directory => ("directory", None),
        EntryData::File(bytes) => ("file", Some(bytes.as_slice())),
        EntryData::Link(target) => ("symlink", Some(target.as_os_str().as_encoded_bytes())),
    };
    let sha256 = if let Some(bytes) = data {
        let mut hash = Sha256::new();
        for chunk in bytes.chunks(65536) {
            budget(deadline)?;
            hash.update(chunk);
        }
        Some(hex::encode(hash.finalize()))
    } else { None };
    Ok(EntrySummary { kind, mode: entry.mode, bytes: data.map_or(0, <[u8]>::len), sha256 })
}

fn source_changes(before: &Snapshot, after: &Snapshot, deadline: Instant) -> Result<SourceChanges> {
    let paths: BTreeSet<_> = before.entries.keys().chain(after.entries.keys()).collect();
    let mut result = SourceChanges { changed_paths: 0, added_paths: 0, removed_paths: 0,
        modified_paths: 0, sha256: String::new(), changes: Vec::new(), details_truncated: false };
    let mut hash = Sha256::new();
    hash.update(b"franken-node/source-fix-changes/v1\0");
    for path in paths {
        budget(deadline)?;
        let previous = before.entries.get(path);
        let next = after.entries.get(path);
        if previous.zip(next).is_some_and(|(left, right)| same_entry(left, right)) { continue; }
        let change = SourceChange { path: path.clone(),
            before: previous.map(|entry| entry_summary(entry, deadline)).transpose()?,
            after: next.map(|entry| entry_summary(entry, deadline)).transpose()? };
        result.changed_paths += 1;
        match (previous.is_some(), next.is_some()) {
            (false, true) => result.added_paths += 1,
            (true, false) => result.removed_paths += 1,
            _ => result.modified_paths += 1,
        }
        let encoded = serde_json::to_vec(&change)?;
        hash.update((encoded.len() as u64).to_le_bytes());
        hash.update(&encoded);
        if result.changes.len() < 64 { result.changes.push(change); }
    }
    result.sha256 = hex::encode(hash.finalize());
    result.details_truncated = result.changed_paths > result.changes.len();
    budget(deadline)?;
    Ok(result)
}

struct Prepared {
    seed: Seed,
    seed_pin: String,
    original_hash: String,
    archived_candidate_hash: String,
    repaired_hash: String,
    project: PathBuf,
    protected_paths: Vec<PathBuf>,
    changes: SourceChanges,
    approved: bool,
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
        matched_tests(seed.original(), &repair)?;
        let protected_paths = frozen_harnesses(seed.candidate(), &repair, deadline)?;
        let changes = source_changes(seed.candidate(), &repair, deadline)?;
        let original_hash = seed.original().digest.clone();
        let archived_candidate_hash = seed.candidate().digest.clone();
        let repaired_hash = repair.digest.clone();
        match &mut seed {
            Seed::Pair(seed) => seed.candidate = Some(repair),
            Seed::Product(seed) => seed.candidate = Some(repair),
        }
        Ok(Self { seed, seed_pin: pin.into(), original_hash, archived_candidate_hash,
            repaired_hash, project, protected_paths, changes, approved: false })
    }

    fn inspection(&self) -> SourceFixInspection {
        SourceFixInspection {
            schema_version: "franken-node/source-fix-inspection/v1", verdict: "INSPECTED",
            oracle: match &self.seed { Seed::Pair(_) => "pair", Seed::Product(_) => "product" },
            seed_content_sha256: self.seed_pin.clone(), input_sha256: self.original_hash.clone(),
            captured_candidate_input_sha256: self.archived_candidate_hash.clone(),
            candidate_input_sha256: self.repaired_hash.clone(), candidate_project: self.project.clone(),
            protected_paths: self.protected_paths.clone(), source_changes: self.changes.clone(),
            execution_performed: false, environment_reproduced: false, release_certification: false,
        }
    }

    fn approve(&mut self, pin: &str) -> Result<()> {
        ensure!(pair::is_hash(pin), "reviewed candidate SHA-256 must be 64 lowercase hexadecimal characters");
        ensure!(pin == self.repaired_hash, "repaired project does not match reviewed candidate input hash");
        self.approved = true;
        Ok(())
    }

    fn execute_selected(self, native: &Path, bun: Option<&Path>, deadline: Instant) -> Result<SourceFixReport> {
        // Resolve executables only AFTER admitting the pinned seed and repair.
        let (node, native) = runtime_invocations(native)?;
        if let Some(bun) = bun {
            let bun = Invocation { executable: bun.canonicalize().context("resolve Bun executable")?,
                before: vec![], after: vec![] };
            self.execute(&[&node, &bun, &native], deadline)
        } else {
            self.execute(&[&node, &native], deadline)
        }
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
            candidate_input_approved: self.approved, protected_paths: self.protected_paths,
            source_changes: self.changes, native_runtime_changed, execution_performed: true,
            environment_reproduced: false, release_certification: false,
            source_recheck_error, replay,
        })
    }
}

/// Inspect a pinned failure and proposed repair without runtime resolution,
/// execution, staging or writes. Review source changes independently; this
/// bounded metadata summary and input hash do not constitute code approval.
pub fn inspect(capsule: &Path, expected_sha256: &str, candidate_project: &Path) -> Result<SourceFixInspection> {
    ensure!(pair::is_hash(expected_sha256), "expected capsule SHA-256 must be independently pinned");
    let deadline = Instant::now() + TOTAL_TIMEOUT;
    let product = super::product_schema(capsule, deadline)?;
    Ok(Prepared::capture(capsule, expected_sha256, candidate_project, product, deadline)?.inspection())
}

/// Capture-now library operation for a caller that already approved execution.
/// It freezes the test contract but does not assert independent source approval.
/// Results are test-scoped measurements, NOT source-installation authorization.
pub fn verify(
    capsule: &Path,
    expected_sha256: &str,
    candidate_project: &Path,
    native: &Path,
    bun: Option<&Path>,
) -> Result<SourceFixReport> {
    let deadline = Instant::now() + TOTAL_TIMEOUT;
    Prepared::capture(capsule, expected_sha256, candidate_project, bun.is_some(), deadline)?
        .execute_selected(native, bun, deadline)
}

/// Review-then-execute operation: pin BOTH the failure and complete repair.
/// The repair is captured once and compared to the approval before resolving
/// any runtime. Later edits cannot replace the captured execution input.
pub fn verify_reviewed(
    capsule: &Path,
    expected_sha256: &str,
    candidate_project: &Path,
    candidate_input_sha256: &str,
    native: &Path,
    bun: Option<&Path>,
) -> Result<SourceFixReport> {
    ensure!(pair::is_hash(candidate_input_sha256), "reviewed candidate SHA-256 must be 64 lowercase hexadecimal characters");
    let deadline = Instant::now() + TOTAL_TIMEOUT;
    let mut prepared = Prepared::capture(capsule, expected_sha256, candidate_project, bun.is_some(), deadline)?;
    prepared.approve(candidate_input_sha256)?;
    prepared.execute_selected(native, bun, deadline)
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
            write(root, "passing.test.cjs", "console.log(require('./stable.cjs'));");
            write(root, "stable.cjs", "module.exports='passing sibling';");
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
        assert!(!result.native_runtime_changed && !result.candidate_input_approved);
        assert_eq!(result.seed_content_sha256, pin);
        assert_eq!(result.candidate_input_sha256, expected_hash);
        assert_ne!(result.candidate_input_sha256, result.captured_candidate_input_sha256);
        assert_eq!((result.source_changes.added_paths, result.source_changes.modified_paths), (1, 1));
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
        write(repaired.path(), "stable.cjs", "process.exit(9);");
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
        let reference = format!("module.exports=require('fs').readFileSync({},'utf8');",
            serde_json::to_string(&state).unwrap());
        write(original.path(), "helper.cjs", &reference);
        let capsule = reports.path().join("failure.json");
        let pin = pair_seed(original.path(), broken.path(), &capsule);
        fs::write(&state, "after").unwrap();
        write(repaired.path(), "helper.cjs", "module.exports='after';");
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
        write(broken.path(), "stable.cjs", "module.exports='broken sibling';");
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

    fn product_projects(original: &Path, broken: &Path, repair: &Path) {
        for (root, code) in [(original, "globalThis.answer=42;"),
            (broken, "process.exit(9);"), (repair, "globalThis.answer=6*7;")] {
            write(root, "case.test.js", "require('./helper.cjs');");
            write(root, "helper.cjs", code);
        }
    }

    #[test]
    fn product_source_repairs_keep_all_roles_and_do_not_downgrade_to_pair() {
        let original = tempfile::tempdir().unwrap();
        let broken = tempfile::tempdir().unwrap();
        let repair = tempfile::tempdir().unwrap();
        let out = tempfile::tempdir().unwrap();
        product_projects(original.path(), broken.path(), repair.path());
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
        write(repair.path(), "case.test.js", "void 0;");
        assert!(Prepared::capture(&path, &pin, repair.path(), true, deadline()).err().unwrap()
            .to_string().contains("frozen test input"));
    }

    #[test]
    fn second_reference_only_drift_prevents_product_source_fix() {
        let original = tempfile::tempdir().unwrap();
        let broken = tempfile::tempdir().unwrap();
        let repair = tempfile::tempdir().unwrap();
        let out = tempfile::tempdir().unwrap();
        product_projects(original.path(), broken.path(), repair.path());
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

    #[test]
    fn constant_output_replacement_of_a_failing_harness_is_refused_before_runtime_lookup() {
        let (original, broken, repaired, reports) = projects();
        let capsule = reports.path().join("failure.json");
        let pin = pair_seed(original.path(), broken.path(), &capsule);
        write(repaired.path(), "helper.cjs", "module.exports=43;");
        write(repaired.path(), "case.test.cjs", "console.log(42);");
        // The changed harness prints the reference answer while the application
        // is still broken. Matching output is not permission to change a test.
        let error = verify(&capsule, &pin, repaired.path(), Path::new("/absent/native"), None).unwrap_err();
        assert!(error.to_string().contains("frozen test input"), "{error:#}");
    }

    #[test]
    fn passing_harness_permission_and_manifest_only_changes_are_frozen() {
        let (original, broken, repaired, reports) = projects();
        let manifest = r#"{"schema_version":"franken-node/migration-tests/v1","tests":["case.test.cjs","passing.test.cjs"]}"#;
        for root in [original.path(), broken.path(), repaired.path()] {
            write(root, ".franken-node/migration-tests.json", manifest);
            fs::set_permissions(root.join("passing.test.cjs"), fs::Permissions::from_mode(0o644)).unwrap();
        }
        let capsule = reports.path().join("failure.json");
        let pin = pair_seed(original.path(), broken.path(), &capsule);
        fs::set_permissions(repaired.path().join("passing.test.cjs"), fs::Permissions::from_mode(0o755)).unwrap();
        assert!(inspect(&capsule, &pin, repaired.path()).unwrap_err().to_string().contains("frozen test input"));
        fs::set_permissions(repaired.path().join("passing.test.cjs"), fs::Permissions::from_mode(0o644)).unwrap();
        write(repaired.path(), ".franken-node/migration-tests.json", &format!("{manifest}\n"));
        assert!(inspect(&capsule, &pin, repaired.path()).unwrap_err().to_string().contains("frozen test input"));
    }

    #[test]
    fn frozen_contract_uses_the_archived_candidate_not_the_reference_source_spelling() {
        let (original, broken, repaired, reports) = projects();
        let harness = "console.log(require('./helper.cjs')); // measured candidate spelling\n";
        write(broken.path(), "case.test.cjs", harness);
        write(repaired.path(), "case.test.cjs", harness);
        let capsule = reports.path().join("failure.json");
        let pin = pair_seed(original.path(), broken.path(), &capsule);
        assert_eq!(inspect(&capsule, &pin, repaired.path()).unwrap().protected_paths,
            [PathBuf::from("case.test.cjs"), PathBuf::from("passing.test.cjs")]);
    }

    #[test]
    fn reviewed_pin_rejects_late_repair_substitution_before_runtime_resolution() {
        let (original, broken, repaired, reports) = projects();
        let capsule = reports.path().join("failure.json");
        let pin = pair_seed(original.path(), broken.path(), &capsule);
        let reviewed = inspect(&capsule, &pin, repaired.path()).unwrap();
        write(repaired.path(), "helper.cjs", "module.exports=99;");
        let error = verify_reviewed(&capsule, &pin, repaired.path(), &reviewed.candidate_input_sha256,
            Path::new("/missing/runtime"), None).unwrap_err();
        assert!(error.to_string().contains("reviewed candidate input hash"), "{error:#}");
    }

    #[test]
    fn independently_approved_bytes_are_captured_once_and_marked_separately_from_measurement() {
        let (original, broken, repaired, reports) = projects();
        let capsule = reports.path().join("failure.json");
        let pin = pair_seed(original.path(), broken.path(), &capsule);
        let inspected = inspect(&capsule, &pin, repaired.path()).unwrap();
        assert_eq!(inspected.verdict, "INSPECTED");
        assert!(!inspected.execution_performed);
        let serialized = serde_json::to_string(&inspected).unwrap();
        assert!(!serialized.contains("module.exports"));
        let mut prepared = Prepared::capture(&capsule, &pin, repaired.path(), false, deadline()).unwrap();
        prepared.approve(&inspected.candidate_input_sha256).unwrap();
        let result = prepared.execute(&[&node(), &node()], deadline()).unwrap();
        assert!(result.candidate_input_approved);
        assert_eq!(result.verdict, "FIX_VERIFIED");
        assert_eq!(result.source_changes.sha256, inspected.source_changes.sha256);
    }

    #[test]
    fn source_change_summary_commits_hidden_changes_and_mode_link_and_removal_identity() {
        let root = tempfile::tempdir().unwrap();
        for index in 0..70 { write(root.path(), &format!("file-{index:02}"), "before"); }
        let before = Snapshot::capture(root.path(), deadline()).unwrap();
        for index in 0..70 { write(root.path(), &format!("file-{index:02}"), "after"); }
        let after = Snapshot::capture(root.path(), deadline()).unwrap();
        let first = source_changes(&before, &after, deadline()).unwrap();
        assert_eq!((first.changed_paths, first.changes.len()), (70, 64));
        assert!(first.details_truncated);
        write(root.path(), "file-69", "a different hidden change");
        let second = source_changes(&before, &Snapshot::capture(root.path(), deadline()).unwrap(), deadline()).unwrap();
        assert_eq!(serde_json::to_value(&first.changes).unwrap(), serde_json::to_value(&second.changes).unwrap());
        assert_ne!(first.sha256, second.sha256);
        let mut entries = before.entries.clone();
        entries.remove(Path::new("file-00"));
        entries.get_mut(Path::new("file-01")).unwrap().mode = 0o700;
        entries.insert("alias".into(), Entry { mode: 0o777, data: EntryData::Link("file-02".into()) });
        let changed = source_changes(&before, &Snapshot::from_entries(entries), deadline()).unwrap();
        assert_eq!((changed.added_paths, changed.removed_paths, changed.modified_paths), (1, 1, 1));
        assert_eq!(changed.changes[0].after.as_ref().unwrap().kind, "symlink");
        assert!(source_changes(&before, &after, Instant::now()).is_err());
    }
}
