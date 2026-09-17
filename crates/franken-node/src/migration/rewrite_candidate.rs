//! Captured original/candidate inputs for checked rewrite installation.
//!
//! This is a child of the production validation suite, so it reuses the exact
//! capture, invocation, supervision and comparison implementations. Preparing
//! a candidate never executes code or edits the caller's source tree.

use super::{EntryData, FailureArchive, Snapshot, SuiteReport, budget, matched_tests, run_captured_with_archive};
use super::product_oracle::{self, ProductReport};
use anyhow::{Context, Result, ensure};
use std::collections::BTreeSet;
use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path, PathBuf};
use std::time::Instant;

pub struct Replacement<'a> {
    pub path: &'a str,
    pub before: &'a [u8],
    pub after: &'a [u8],
}

/// Contains private source bytes; deliberately has no Debug implementation.
pub struct RewriteCandidate {
    project: PathBuf,
    original: Snapshot,
    candidate: Option<Snapshot>,
    deadline: Instant,
}

impl RewriteCandidate {
    pub fn capture(project: &Path, deadline: Instant) -> Result<Self> {
        let project = project.canonicalize().context("resolve checked rewrite project")?;
        let original = Snapshot::capture(&project, deadline)?;
        ensure!(!original.tests()?.is_empty(), "checked rewrite requires a nonempty test inventory");
        Ok(Self { project, original, candidate: None, deadline })
    }

    pub fn input_sha256(&self) -> &str { &self.original.digest }

    /// Inspect the exact captured selection without resolving a runtime,
    /// executing a test, preparing replacements or touching the source tree.
    /// A later execution must capture/recheck its own inputs; this is not a
    /// reusable approval token or a claim that the selected tests passed.
    pub fn test_inventory(&self) -> Result<Vec<PathBuf>> {
        budget(self.deadline)?;
        self.original.tests()
    }

    /// Destination must not exist. The owner keeps its private parent alive.
    pub fn stage_original(&self, destination: &Path) -> Result<()> {
        self.original.stage(destination, self.deadline)
    }

    /// Validate every replacement before staging any of them. Only ordinary
    /// captured files may change; paths, links and the test inventory persist.
    pub fn prepare(&mut self, replacements: &[Replacement<'_>]) -> Result<()> {
        // A failed second preparation cannot leave an earlier candidate usable.
        self.candidate = None;
        ensure!(replacements.len() <= 1_000, "checked rewrite replacement count exceeded");
        let mut seen = BTreeSet::new();
        let mut total = 0_usize;
        for edit in replacements {
            budget(self.deadline)?;
            let path = Path::new(edit.path);
            ensure!(!edit.path.is_empty() && edit.path.len() <= super::MAX_PATH_BYTES
                && !edit.path.contains(['\\', '\0']) && !edit.path.chars().any(char::is_control)
                && path.components().all(|part| matches!(part, Component::Normal(_)))
                && path.components().map(|part| part.as_os_str().to_string_lossy()).collect::<Vec<_>>().join("/") == edit.path,
                "checked rewrite requires canonical relative replacement paths");
            ensure!(!path.components().any(|part| part.as_os_str() == ".git")
                && ![".migrate-backup", ".franken-node", ".franken-rewrite"].iter()
                    .any(|reserved| path.components().next().is_some_and(|part| part.as_os_str() == *reserved)),
                "checked rewrite cannot replace reserved metadata");
            ensure!(seen.insert(edit.path), "duplicate checked rewrite replacement");
            total = total.checked_add(edit.before.len()).and_then(|n| n.checked_add(edit.after.len()))
                .context("checked rewrite byte count overflow")?;
            ensure!(total <= super::MAX_PROJECT_BYTES && edit.before.len() <= 10 * 1024 * 1024
                && edit.after.len() <= 10 * 1024 * 1024, "checked rewrite replacement byte limit exceeded");
            let entry = self.original.entries.get(path).context("replacement is not a captured file")?;
            ensure!(matches!(&entry.data, EntryData::File(bytes) if bytes == edit.before),
                "checked rewrite preimage mismatch or nonregular target: {}", edit.path);
        }
        // Preserve each source file's mode inside an owner-only parent. The
        // directory must already be private when the first source byte lands.
        let temporary = tempfile::Builder::new().prefix("franken-rewrite-candidate-")
            .permissions(fs::Permissions::from_mode(0o700)).tempdir()?;
        let root = temporary.path().join("project");
        self.original.stage(&root, self.deadline)?;
        for edit in replacements {
            budget(self.deadline)?;
            let target = root.join(edit.path);
            let entry = &self.original.entries[Path::new(edit.path)];
            // The target and all its parents came from regular captured entries;
            // no guest has executed in this private workspace. Replace rather
            // than truncate so read-only source modes are faithfully preserved.
            let mut staged = tempfile::NamedTempFile::new_in(target.parent().context("replacement parent missing")?)?;
            staged.write_all(edit.after)?;
            staged.as_file().set_permissions(fs::Permissions::from_mode(entry.mode))?;
            staged.persist(&target).map_err(|error| error.error)?;
        }
        let candidate = Snapshot::capture(&root, self.deadline)?;
        matched_tests(&self.original, &candidate)?;
        self.candidate = Some(candidate);
        Ok(())
    }

    /// Check a LIVE executor result before installing this exact candidate.
    ///
    /// A PASS summary alone is not evidence: bind both input trees, every test
    /// counterpart and the comparison scope, and independently check the raw
    /// observations rather than trusting the divergence list. This checks
    /// consistency, not authenticity; unsigned reports loaded from disk or a
    /// remote party must not be used to authorize installation through this API.
    pub fn check_validation(&self, report: &SuiteReport) -> Result<()> {
        budget(self.deadline)?;
        let candidate = self.candidate.as_ref().context("checked rewrite candidate is not prepared")?;
        let tests = matched_tests(&self.original, candidate)?;
        ensure!(report.input_sha256 == self.original.digest
            && report.candidate_input_sha256 == candidate.digest,
            "validation evidence does not match the captured original and prepared candidate");
        ensure!(report.schema_version == "franken-node/native-validation-suite/v1"
            && report.scope == "captured-test-process-and-workspace-delta"
            && !report.release_certification && report.filesystem_comparison
            && report.filesystem_exclusions.iter().map(String::as_str)
                .eq(super::workspace_effects::EXCLUSIONS.iter().copied()),
            "validation evidence has an unsupported or weakened comparison scope");
        ensure!(report.verdict == "PASS" && report.total_tests == tests.len()
            && report.passed == tests.len() && report.failed == 0 && report.errored == 0
            && report.skipped == 0 && report.errors.is_empty() && report.cases.len() == tests.len(),
            "validation evidence is not a complete passing test suite");
        for (test, row) in tests.iter().zip(&report.cases) {
            ensure!(test.to_str() == Some(row.test.as_str()),
                "validation evidence test inventory differs from the captured inventory");
            ensure!(row.status == "PASS" && row.errors.is_empty() && row.divergences.is_empty(),
                "validation evidence contains a nonpassing case: {}", row.test);
            let reference = row.reference.as_ref().context("missing reference process evidence")?;
            let native = row.native.as_ref().context("missing candidate process evidence")?;
            ensure!(reference.exit_code == Some(0) && native.exit_code == Some(0)
                && reference.signal.is_none() && native.signal.is_none(),
                "validation evidence contains an unsuccessful process: {}", row.test);
            ensure!(reference.stdout == native.stdout && reference.stderr == native.stderr,
                "validation evidence contains unequal process output: {}", row.test);
            ensure!(reference.workspace_delta.is_some()
                && reference.workspace_delta == native.workspace_delta,
                "validation evidence contains missing or unequal workspace effects: {}", row.test);
        }
        Ok(())
    }

    /// Validate the prepared bytes. Caller-selected failure retention uses the
    /// same original and candidate snapshots; it neither installs nor reruns a
    /// rejected rewrite. A saved capsule is never installation authorization.
    pub fn validate_native(&self, native_executable: &Path) -> Result<SuiteReport> {
        self.validate_native_with(native_executable,
            || FailureArchive::from_environment([&self.project, &self.project]))
    }

    fn validate_native_with(&self, native_executable: &Path,
        archive: impl FnOnce() -> Result<Option<FailureArchive>>) -> Result<SuiteReport> {
        let candidate = self.candidate.as_ref().context("checked rewrite candidate is not prepared")?;
        budget(self.deadline)?;
        let archive = archive()?;
        run_captured_with_archive((&self.project, &self.project), (&self.original, candidate),
            native_executable, self.deadline, true, archive)
    }

    /// Execute Node and explicitly selected Bun on original inputs, and native
    /// Franken on the prepared candidate. No source recapture, two-leg fallback
    /// or second validation run is performed. The caller must approve execution.
    pub fn validate_product(&self, native_executable: &Path, bun_executable: &Path) -> Result<ProductReport> {
        let candidate = self.candidate.as_ref().context("checked rewrite candidate is not prepared")?;
        budget(self.deadline)?;
        product_oracle::run_captured([&self.project, &self.project], [&self.original, candidate],
            native_executable, bun_executable, self.deadline, true)
    }

    /// Keep both captured hashes and all three runtime observations at the
    /// installation boundary. Only a live executor result is admissible.
    pub fn check_product_validation(&self, report: &ProductReport) -> Result<()> {
        budget(self.deadline)?;
        let candidate = self.candidate.as_ref().context("checked rewrite candidate is not prepared")?;
        let tests = matched_tests(&self.original, candidate)?;
        report.check_admission(&self.original.digest, &candidate.digest, &tests)
    }

    /// The whole tree, including non-rewritten dependencies and configuration,
    /// must still match. This is a pre-install check, not an OS filesystem lock.
    pub fn ensure_source_unchanged(&self) -> Result<()> {
        let current = Snapshot::capture(&self.project, self.deadline)?;
        ensure!(current.digest == self.original.digest,
            "project changed during checked rewrite validation; refusing installation");
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn validate_node_pair(&self) -> Result<SuiteReport> {
        // Explicit Node/Node test commands measure the orchestrator, not native
        // Franken parity. This alternative is absent from production builds.
        let node = super::Invocation { executable: super::node_on_path()?, before: vec![], after: vec![] };
        super::execute_suite_pair(&self.original,
            self.candidate.as_ref().context("candidate not prepared")?,
            &node, &node, self.deadline, std::time::Duration::from_secs(5), true)
    }

    /// Test-only real Node/Bun/Node commands: exercise installation orchestration
    /// without pretending Node is native Franken. Absent from production builds.
    #[cfg(test)]
    pub fn validate_node_bun_node(&self, bun_executable: &Path) -> Result<ProductReport> {
        let candidate = self.candidate.as_ref().context("candidate not prepared")?;
        let node = super::Invocation { executable: super::node_on_path()?, before: vec![], after: vec![] };
        let bun = super::Invocation { executable: bun_executable.canonicalize()?, before: vec![], after: vec![] };
        let identities = [node.identity(self.deadline)?, bun.identity(self.deadline)?, node.identity(self.deadline)?];
        product_oracle::execute(&self.original, candidate, [&node, &bun, &node], identities,
            self.deadline, std::time::Duration::from_secs(5), true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn project() -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join("case.test.js"), "console.log(42);").unwrap();
        fs::write(root.path().join("config.json"), "{}").unwrap();
        root
    }
    fn capture(root: &Path) -> RewriteCandidate {
        RewriteCandidate::capture(root, Instant::now() + Duration::from_secs(90)).unwrap()
    }

    #[test]
    fn preparation_requires_exact_preimages_and_never_edits_sources() {
        let root = project();
        let mut candidate = capture(root.path());
        assert!(candidate.prepare(&[Replacement { path: "case.test.js", before: b"stale", after: b"changed" }]).is_err());
        assert!(candidate.validate_native(Path::new("/bin/false")).unwrap_err().to_string().contains("not prepared"));
        assert_eq!(fs::read(root.path().join("case.test.js")).unwrap(), b"console.log(42);");
    }

    #[test]
    fn equivalent_candidates_execute_from_captured_bytes() {
        let root = project();
        let mut candidate = capture(root.path());
        candidate.prepare(&[Replacement { path: "case.test.js", before: b"console.log(42);", after: b"console.log(6*7);" }]).unwrap();
        fs::write(root.path().join("case.test.js"), "process.exit(99);").unwrap();
        let report = candidate.validate_node_pair().unwrap();
        assert_eq!(report.verdict, "PASS", "{report:#?}");
        assert_ne!(report.input_sha256, report.candidate_input_sha256);
        candidate.check_validation(&report).unwrap();
        assert!(candidate.ensure_source_unchanged().is_err());
    }

    #[test]
    fn dependency_changes_invalidate_promotion_even_without_a_source_change() {
        let root = project();
        let candidate = capture(root.path());
        candidate.ensure_source_unchanged().unwrap();
        fs::write(root.path().join("config.json"), "{\"changed\":true}").unwrap();
        assert!(candidate.ensure_source_unchanged().unwrap_err().to_string().contains("project changed"));
    }

    #[test]
    fn filesystem_only_candidate_differences_are_measured() {
        let root = project();
        let before = "require('fs').writeFileSync('result','one');";
        fs::write(root.path().join("case.test.js"), before).unwrap();
        let mut candidate = capture(root.path());
        candidate.prepare(&[Replacement { path: "case.test.js", before: before.as_bytes(),
            after: b"require('fs').writeFileSync('result','two');" }]).unwrap();
        let report = candidate.validate_node_pair().unwrap();
        assert_eq!(report.verdict, "FAIL");
        assert_eq!(report.cases[0].divergences, ["filesystem:workspace_delta_mismatch"]);
        assert!(!root.path().join("result").exists());
    }

    #[test]
    fn invalid_paths_and_duplicate_targets_are_refused() {
        let root = project();
        for path in ["../case.test.js", "./case.test.js", "/case.test.js", ".migrate-backup/file", "config.json/../case.test.js"] {
            assert!(capture(root.path()).prepare(&[Replacement { path, before: b"", after: b"" }]).is_err());
        }
        let edits = [Replacement { path: "config.json", before: b"{}", after: b"{}" },
            Replacement { path: "config.json", before: b"{}", after: b"{}" }];
        assert!(capture(root.path()).prepare(&edits).unwrap_err().to_string().contains("duplicate"));
    }

    #[test]
    fn failed_repreparation_invalidates_the_previous_candidate() {
        let root = project();
        let mut candidate = capture(root.path());
        candidate.prepare(&[]).unwrap();
        assert!(candidate.prepare(&[Replacement { path: "absent", before: b"", after: b"" }]).is_err());
        assert!(candidate.validate_native(Path::new("/bin/false")).unwrap_err().to_string().contains("not prepared"));
    }

    #[test]
    fn empty_test_inventory_cannot_be_checked() {
        let root = tempfile::tempdir().unwrap();
        assert!(RewriteCandidate::capture(root.path(), Instant::now() + Duration::from_secs(5))
            .err().unwrap().to_string().contains("nonempty"));
    }

    #[test]
    fn a_passing_report_for_another_prepared_candidate_cannot_be_reused() {
        let root = project();
        let mut candidate = capture(root.path());
        candidate.prepare(&[]).unwrap();
        let report = candidate.validate_node_pair().unwrap();
        candidate.check_validation(&report).unwrap();
        candidate.prepare(&[Replacement { path: "config.json", before: b"{}", after: b"{\"changed\":true}" }]).unwrap();
        assert_eq!(candidate.input_sha256(), report.input_sha256);
        assert!(candidate.check_validation(&report).unwrap_err().to_string().contains("prepared candidate"));
        assert!(candidate.prepare(&[Replacement { path: "absent", before: b"", after: b"" }]).is_err());
        assert!(candidate.check_validation(&report).unwrap_err().to_string().contains("not prepared"));
    }

    #[test]
    fn summaries_cannot_hide_missing_duplicate_or_substituted_test_counterparts() {
        let root = project();
        fs::write(root.path().join("other.test.js"), "console.log(42);").unwrap();
        let mut candidate = capture(root.path());
        candidate.prepare(&[]).unwrap();
        let report = candidate.validate_node_pair().unwrap();
        candidate.check_validation(&report).unwrap();
        let mut missing = report.clone();
        missing.cases.pop();
        missing.total_tests -= 1;
        missing.passed -= 1;
        assert!(candidate.check_validation(&missing).is_err());
        let mut duplicate = report.clone();
        duplicate.cases[1] = duplicate.cases[0].clone();
        assert!(candidate.check_validation(&duplicate).is_err());
        let mut substituted = report.clone();
        substituted.cases[0].test = "unmeasured.test.js".into();
        assert!(candidate.check_validation(&substituted).is_err());
        let mut reordered = report;
        reordered.cases.swap(0, 1);
        assert!(candidate.check_validation(&reordered).is_err());
    }

    #[test]
    fn raw_observations_must_agree_even_when_divergences_are_empty() {
        let root = project();
        let mut candidate = capture(root.path());
        candidate.prepare(&[]).unwrap();
        let report = candidate.validate_node_pair().unwrap();
        candidate.check_validation(&report).unwrap();
        for mutate in [
            (|r: &mut SuiteReport| r.cases[0].native.as_mut().unwrap().stdout.sha256.push('0')) as fn(&mut SuiteReport),
            |r| r.cases[0].native.as_mut().unwrap().stderr.bytes += 1,
            |r| r.cases[0].native.as_mut().unwrap().workspace_delta.as_mut().unwrap().sha256.push('0'),
            |r| r.cases[0].native.as_mut().unwrap().workspace_delta = None,
            |r| r.cases[0].reference = None,
            |r| r.cases[0].native.as_mut().unwrap().exit_code = Some(7),
            |r| r.cases[0].reference.as_mut().unwrap().signal = Some(9),
        ] {
            let mut changed = report.clone();
            mutate(&mut changed);
            assert!(changed.cases[0].divergences.is_empty());
            assert!(candidate.check_validation(&changed).is_err(), "{changed:#?}");
        }
    }

    #[test]
    fn comparison_scope_and_complete_execution_are_mandatory() {
        let root = project();
        let mut candidate = capture(root.path());
        candidate.prepare(&[]).unwrap();
        let report = candidate.validate_node_pair().unwrap();
        candidate.check_validation(&report).unwrap();
        for mutate in [
            (|r: &mut SuiteReport| r.filesystem_comparison = false) as fn(&mut SuiteReport),
            |r| r.filesystem_exclusions.push("**/*".into()),
            |r| r.scope = "captured-test-process-stdout-stderr-exit".into(),
            |r| r.schema_version = "unknown/v2".into(),
            |r| r.input_sha256.push('0'),
            |r| r.release_certification = true,
            |r| r.skipped = 1,
            |r| r.failed = 1,
            |r| r.errored = 1,
            |r| r.errors.push("incomplete identity recheck".into()),
            |r| r.cases[0].errors.push("incomplete observation".into()),
            |r| r.cases[0].status = "ERROR".into(),
        ] {
            let mut changed = report.clone();
            mutate(&mut changed);
            assert!(candidate.check_validation(&changed).is_err(), "{changed:#?}");
        }
        candidate.deadline = Instant::now();
        assert!(candidate.check_validation(&report).is_err());
    }

    #[test]
    fn inventory_inspection_uses_captured_bytes_without_preparing_or_executing() {
        let root = project();
        let candidate = capture(root.path());
        fs::write(root.path().join("other.test.js"), "throw new Error('not captured');").unwrap();
        assert_eq!(candidate.test_inventory().unwrap(), [PathBuf::from("case.test.js")]);
        assert!(candidate.candidate.is_none());
        assert!(candidate.ensure_source_unchanged().is_err());
    }

    #[test]
    fn rejected_prepared_bytes_can_be_replayed_and_exported_without_installation() {
        use super::super::{FailureCapture, native_replay};
        let root = project();
        let outputs = tempfile::tempdir().unwrap();
        let mut candidate = capture(root.path());
        candidate.prepare(&[Replacement { path: "case.test.js", before: b"console.log(42);",
            after: b"console.log('prepared candidate');" }]).unwrap();
        let report = candidate.validate_native_with(Path::new("/bin/false"),
            || FailureArchive::reserve(outputs.path(), [root.path(), root.path()]).map(Some)).unwrap();
        assert_eq!(report.verdict, "FAIL");
        assert!(candidate.check_validation(&report).is_err());
        candidate.ensure_source_unchanged().unwrap();
        let Some(FailureCapture::Saved { capsule_path, content_sha256 }) = &report.failure_capture
            else { panic!("{report:#?}") };
        assert_ne!(report.input_sha256, report.candidate_input_sha256);
        let summary = native_replay::inspect(capsule_path).unwrap();
        assert_eq!(summary.input_sha256, candidate.original.digest);
        assert_eq!(summary.candidate_input_sha256, candidate.candidate.as_ref().unwrap().digest);
        let exported = native_replay::export_inputs(capsule_path, content_sha256, &outputs.path().join("reproducer")).unwrap();
        assert_eq!(fs::read(exported.destination.join("original/case.test.js")).unwrap(), b"console.log(42);");
        assert_eq!(fs::read(exported.destination.join("candidate/case.test.js")).unwrap(), b"console.log('prepared candidate');");
        let replayed = native_replay::replay(capsule_path, content_sha256, Path::new("/bin/false"), false).unwrap();
        assert_eq!(replayed.verdict, "REPRODUCED");
        assert_eq!(replayed.validation.cases, report.cases);
        assert_eq!(fs::read(root.path().join("case.test.js")).unwrap(), b"console.log(42);");
        assert!(!root.path().join(".migrate-backup").exists());
    }

    #[test]
    fn unprepared_expired_and_invalid_archive_requests_never_dispatch() {
        let root = project();
        let mut candidate = capture(root.path());
        let error = candidate.validate_native_with(Path::new("/absent/native"),
            || panic!("unprepared candidate cannot reserve storage")).unwrap_err();
        assert!(error.to_string().contains("not prepared"));
        candidate.prepare(&[]).unwrap();
        let error = candidate.validate_native_with(Path::new("/absent/native"),
            || FailureArchive::reserve(root.path(), [root.path(), root.path()]).map(Some)).unwrap_err();
        assert!(error.to_string().contains("outside"));
        candidate.deadline = Instant::now();
        let error = candidate.validate_native_with(Path::new("/absent/native"),
            || panic!("expired validation cannot reserve storage")).unwrap_err();
        assert!(error.to_string().contains("budget"));
        assert_eq!(fs::read(root.path().join("case.test.js")).unwrap(), b"console.log(42);");
    }

    #[test]
    fn three_runtime_candidate_validation_refuses_unprepared_expired_and_missing_references() {
        let root = project();
        let mut candidate = capture(root.path());
        let missing = Path::new("/absent/product-reference");
        assert!(candidate.validate_product(missing, missing).unwrap_err().to_string().contains("not prepared"));
        candidate.prepare(&[]).unwrap();
        assert!(candidate.validate_product(Path::new("/bin/false"), missing)
            .unwrap_err().to_string().contains("resolve Bun"));
        candidate.deadline = Instant::now();
        assert!(candidate.validate_product(missing, missing).unwrap_err().to_string().contains("budget"));
        assert_eq!(fs::read(root.path().join("case.test.js")).unwrap(), b"console.log(42);");
    }

    #[test]
    fn three_runtime_admission_stays_bound_to_preparation_and_operation_deadline() {
        let root = project();
        let mut candidate = capture(root.path());
        candidate.prepare(&[]).unwrap();
        // Same-Node roles deliberately prove refusal, not product equivalence.
        let report = candidate.validate_node_bun_node(&super::super::node_on_path().unwrap()).unwrap();
        assert!(candidate.check_product_validation(&report).unwrap_err().to_string().contains("distinct reference"));
        candidate.prepare(&[Replacement { path: "config.json", before: b"{}", after: b"{\"new\":true}" }]).unwrap();
        assert!(candidate.check_product_validation(&report).unwrap_err().to_string().contains("prepared candidate"));
        candidate.deadline = Instant::now();
        assert!(candidate.check_product_validation(&report).unwrap_err().to_string().contains("budget"));
    }
}
