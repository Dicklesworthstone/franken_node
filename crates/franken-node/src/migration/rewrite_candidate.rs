//! Captured original/candidate inputs for checked rewrite installation.
//!
//! This is a child of the production validation suite, so it reuses the exact
//! capture, invocation, supervision and comparison implementations. Preparing
//! a candidate never executes code or edits the caller's source tree.

use super::product_oracle::{self, ProductReport};
use super::{
    EntryData, FailureArchive, Snapshot, SuiteReport, budget, matched_tests,
    run_captured_with_archive,
};
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

/// New regular files with captured bytes and explicitly reviewed permissions.
/// Parents already exist in the original capture. Source bytes are not Debug.
pub struct Addition<'a> {
    pub path: &'a str,
    pub after: &'a [u8],
    pub mode: u32,
}

/// The complete installation plan. Consumers must not silently drop additions
/// after measuring the whole candidate. Contains private source bytes.
pub struct Changes<'a> {
    pub replacements: Vec<Replacement<'a>>,
    pub additions: Vec<Addition<'a>>,
}

fn change_path(value: &str) -> Result<&Path> {
    let path = Path::new(value);
    ensure!(
        !value.is_empty()
            && value.len() <= super::MAX_PATH_BYTES
            && !value.contains(['\\', '\0'])
            && !value.chars().any(char::is_control)
            && path.components().all(|part| matches!(part, Component::Normal(_)))
            && path.components().map(|part| part.as_os_str().to_string_lossy())
                .collect::<Vec<_>>().join("/") == value,
        "checked rewrite requires canonical relative replacement paths"
    );
    ensure!(
        !path.components().any(|part| part.as_os_str() == ".git")
            && ![".migrate-backup", ".franken-node", ".franken-rewrite"]
                .iter().any(|reserved| path.components().next()
                    .is_some_and(|part| part.as_os_str() == *reserved)),
        "checked rewrite cannot replace reserved metadata"
    );
    Ok(path)
}

/// Contains private source bytes; deliberately has no Debug implementation.
pub struct RewriteCandidate {
    project: PathBuf,
    original: Snapshot,
    candidate: Option<Snapshot>,
    candidate_project: Option<PathBuf>,
    deadline: Instant,
}

impl RewriteCandidate {
    pub fn capture(project: &Path, deadline: Instant) -> Result<Self> {
        let project = project
            .canonicalize()
            .context("resolve checked rewrite project")?;
        let original = Snapshot::capture(&project, deadline)?;
        ensure!(
            !original.tests()?.is_empty(),
            "checked rewrite requires a nonempty test inventory"
        );
        Ok(Self {
            project,
            original,
            candidate: None,
            candidate_project: None,
            deadline,
        })
    }

    pub fn input_sha256(&self) -> &str {
        &self.original.digest
    }

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

    /// Prepare an independently reviewed directory, not an imported verdict.
    /// Accept regular-file replacements and new regular files under existing
    /// directories. Removal, new directories, relinking and existing-mode edits
    /// are errors, never silently omitted. Reserved metadata and golden/request
    /// changes remain subject to the shared replacement/inventory checks.
    pub fn prepare_project(&mut self, project: &Path, expected_sha256: &str) -> Result<()> {
        self.candidate = None;
        self.candidate_project = None;
        ensure!(
            expected_sha256.len() == 64
                && expected_sha256.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "candidate approval must be 64 lowercase hexadecimal characters"
        );
        let project = project.canonicalize().context("resolve proposed migration")?;
        ensure!(
            project != self.project
                && !project.starts_with(&self.project)
                && !self.project.starts_with(&project),
            "original and proposed migration must be separate, non-nested directories"
        );
        let proposed = Snapshot::capture(&project, self.deadline)?;
        ensure!(proposed.digest == expected_sha256, "proposed migration does not match reviewed candidate hash");
        ensure!(
            self.original.entries.keys().all(|path| proposed.entries.contains_key(path)),
            "migration installation cannot remove or rename original entries"
        );
        let mut owned = Vec::new();
        for (path, before) in &self.original.entries {
            budget(self.deadline)?;
            let after = &proposed.entries[path];
            ensure!(before.mode == after.mode, "migration installation cannot change entry modes: {}", path.display());
            match (&before.data, &after.data) {
                (EntryData::File(before), EntryData::File(after)) => {
                    if before != after {
                        owned.push((path.to_str().context("migration path is not UTF-8")?.to_owned(),
                            before.clone(), after.as_slice()));
                    }
                }
                (EntryData::Directory, EntryData::Directory) => {}
                (EntryData::Link(before), EntryData::Link(after)) if before == after => {}
                _ => anyhow::bail!("migration installation cannot change entry kinds or links: {}", path.display()),
            }
        }
        let replacements: Vec<_> = owned.iter().map(|(path, before, after)| Replacement {
            path, before, after,
        }).collect();
        let mut additions = Vec::new();
        for (path, entry) in &proposed.entries {
            if !self.original.entries.contains_key(path) {
                let EntryData::File(after) = &entry.data else {
                    anyhow::bail!("migration additions must be regular files under existing directories: {}", path.display());
                };
                additions.push(Addition {
                    path: path.to_str().context("migration path is not UTF-8")?,
                    after,
                    mode: entry.mode,
                });
            }
        }
        self.prepare_changes(&replacements, &additions)?;
        if self.candidate.as_ref().map(|s| s.digest.as_str()) != Some(expected_sha256) {
            self.candidate = None;
            anyhow::bail!("prepared migration differs from the complete reviewed candidate");
        }
        self.candidate_project = Some(project);
        Ok(())
    }

    fn candidate_root(&self) -> &Path {
        self.candidate_project.as_deref().unwrap_or(&self.project)
    }

    /// Reject edits to an external proposal made while its captured version ran.
    /// This is a freshness check, never replacement of already measured bytes.
    pub fn ensure_candidate_source_unchanged(&self) -> Result<()> {
        let candidate = self.candidate.as_ref().context("checked rewrite candidate is not prepared")?;
        if let Some(project) = &self.candidate_project {
            ensure!(Snapshot::capture(project, self.deadline)?.digest == candidate.digest,
                "proposed migration changed during validation; refusing installation");
        }
        Ok(())
    }

    /// Borrow the exact captured before/after bytes. No source-tree reread or
    /// report decoding may redefine the installation after live validation.
    /// Replacement-only consumers must not silently omit newly added files.
    pub fn replacements(&self) -> Result<Vec<Replacement<'_>>> {
        let changes = self.changes()?;
        ensure!(changes.additions.is_empty(),
            "candidate creates files; consume the complete changes plan, not replacements alone");
        Ok(changes.replacements)
    }

    pub fn changes(&self) -> Result<Changes<'_>> {
        Ok(Changes {
            replacements: self.replacement_images()?,
            additions: self.additions()?,
        })
    }

    fn replacement_images(&self) -> Result<Vec<Replacement<'_>>> {
        budget(self.deadline)?;
        let candidate = self.candidate.as_ref().context("checked rewrite candidate is not prepared")?;
        let mut result = Vec::new();
        for (path, before) in &self.original.entries {
            if let (EntryData::File(before), EntryData::File(after)) =
                (&before.data, &candidate.entries[path].data)
                && before != after
            {
                result.push(Replacement {
                    path: path.to_str().context("migration path is not UTF-8")?,
                    before,
                    after,
                });
            }
        }
        Ok(result)
    }

    /// Borrow new-file bytes/modes from the prepared immutable capture, not
    /// from the on-disk candidate or a caller-supplied validation report.
    fn additions(&self) -> Result<Vec<Addition<'_>>> {
        budget(self.deadline)?;
        let candidate = self.candidate.as_ref().context("checked rewrite candidate is not prepared")?;
        let mut result = Vec::new();
        for (path, entry) in &candidate.entries {
            if !self.original.entries.contains_key(path) {
                let EntryData::File(after) = &entry.data else {
                    anyhow::bail!("prepared addition is not a regular file");
                };
                result.push(Addition {
                    path: path.to_str().context("migration path is not UTF-8")?,
                    after,
                    mode: entry.mode,
                });
            }
        }
        Ok(result)
    }

    /// Validate every replacement before staging any of them. This existing
    /// entrypoint does not infer new files from empty replacement preimages.
    pub fn prepare(&mut self, replacements: &[Replacement<'_>]) -> Result<()> {
        self.prepare_changes(replacements, &[])
    }

    fn prepare_changes(&mut self, replacements: &[Replacement<'_>], additions: &[Addition<'_>]) -> Result<()> {
        // A failed second preparation cannot leave an earlier candidate usable.
        self.candidate = None;
        self.candidate_project = None;
        ensure!(
            replacements.len().checked_add(additions.len()).is_some_and(|count| count <= 1_000),
            "checked rewrite replacement count exceeded"
        );
        let mut seen = BTreeSet::new();
        let mut total = 0_usize;
        for edit in replacements {
            budget(self.deadline)?;
            let path = change_path(edit.path)?;
            ensure!(
                seen.insert(edit.path),
                "duplicate checked rewrite replacement"
            );
            total = total
                .checked_add(edit.before.len())
                .and_then(|n| n.checked_add(edit.after.len()))
                .context("checked rewrite byte count overflow")?;
            ensure!(
                total <= super::MAX_PROJECT_BYTES
                    && edit.before.len() <= 10 * 1024 * 1024
                    && edit.after.len() <= 10 * 1024 * 1024,
                "checked rewrite replacement byte limit exceeded"
            );
            let entry = self
                .original
                .entries
                .get(path)
                .context("replacement is not a captured file")?;
            ensure!(
                matches!(&entry.data, EntryData::File(bytes) if bytes == edit.before),
                "checked rewrite preimage mismatch or nonregular target: {}",
                edit.path
            );
        }
        for addition in additions {
            budget(self.deadline)?;
            let path = change_path(addition.path)?;
            ensure!(seen.insert(addition.path), "duplicate checked rewrite target");
            ensure!(!self.original.entries.contains_key(path), "addition replaces an original entry");
            ensure!(addition.mode <= 0o777 && addition.mode & 0o400 != 0,
                "new files require ordinary owner-readable permissions");
            total = total.checked_add(addition.after.len()).context("checked rewrite byte count overflow")?;
            ensure!(total <= super::MAX_PROJECT_BYTES && addition.after.len() <= 10 * 1024 * 1024,
                "checked rewrite addition byte limit exceeded");
            for parent in path.ancestors().skip(1).filter(|parent| !parent.as_os_str().is_empty()) {
                ensure!(self.original.entries.get(parent)
                    .is_some_and(|entry| matches!(&entry.data, EntryData::Directory)),
                    "new file parents must be existing captured directories");
            }
        }
        // Preserve each source file's mode inside an owner-only parent. The
        // directory must already be private when the first source byte lands.
        let temporary = tempfile::Builder::new()
            .prefix("franken-rewrite-candidate-")
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir()?;
        let root = temporary.path().join("project");
        self.original.stage(&root, self.deadline)?;
        for edit in replacements {
            budget(self.deadline)?;
            let target = root.join(edit.path);
            let entry = &self.original.entries[Path::new(edit.path)];
            // The target and all its parents came from regular captured entries;
            // no guest has executed in this private workspace. Replace rather
            // than truncate so read-only source modes are faithfully preserved.
            let mut staged = tempfile::NamedTempFile::new_in(
                target.parent().context("replacement parent missing")?,
            )?;
            staged.write_all(edit.after)?;
            staged
                .as_file()
                .set_permissions(fs::Permissions::from_mode(entry.mode))?;
            staged.persist(&target).map_err(|error| error.error)?;
        }
        for addition in additions {
            budget(self.deadline)?;
            let target = root.join(addition.path);
            let mut staged = tempfile::NamedTempFile::new_in(
                target.parent().context("addition parent missing")?,
            )?;
            staged.write_all(addition.after)?;
            staged.as_file().set_permissions(fs::Permissions::from_mode(addition.mode))?;
            staged.persist_noclobber(&target).map_err(|error| error.error)?;
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
        let candidate = self
            .candidate
            .as_ref()
            .context("checked rewrite candidate is not prepared")?;
        let tests = matched_tests(&self.original, candidate)?;
        ensure!(
            report.input_sha256 == self.original.digest
                && report.candidate_input_sha256 == candidate.digest,
            "validation evidence does not match the captured original and prepared candidate"
        );
        ensure!(
            report.schema_version == "franken-node/native-validation-suite/v1"
                && report.scope == "captured-test-process-and-workspace-delta"
                && !report.release_certification
                && report.filesystem_comparison
                && report
                    .filesystem_exclusions
                    .iter()
                    .map(String::as_str)
                    .eq(super::workspace_effects::EXCLUSIONS.iter().copied()),
            "validation evidence has an unsupported or weakened comparison scope"
        );
        ensure!(
            report.verdict == "PASS"
                && report.total_tests == tests.len()
                && report.passed == tests.len()
                && report.failed == 0
                && report.errored == 0
                && report.skipped == 0
                && report.errors.is_empty()
                && report.cases.len() == tests.len(),
            "validation evidence is not a complete passing test suite"
        );
        for (test, row) in tests.iter().zip(&report.cases) {
            ensure!(
                test.to_str() == Some(row.test.as_str()),
                "validation evidence test inventory differs from the captured inventory"
            );
            ensure!(
                row.status == "PASS" && row.errors.is_empty() && row.divergences.is_empty(),
                "validation evidence contains a nonpassing case: {}",
                row.test
            );
            let reference = row
                .reference
                .as_ref()
                .context("missing reference process evidence")?;
            let native = row
                .native
                .as_ref()
                .context("missing candidate process evidence")?;
            ensure!(
                reference.exit_code == Some(0)
                    && native.exit_code == Some(0)
                    && reference.signal.is_none()
                    && native.signal.is_none(),
                "validation evidence contains an unsuccessful process: {}",
                row.test
            );
            ensure!(
                reference.stdout == native.stdout && reference.stderr == native.stderr,
                "validation evidence contains unequal process output: {}",
                row.test
            );
            ensure!(
                reference.workspace_delta.is_some()
                    && reference.workspace_delta == native.workspace_delta,
                "validation evidence contains missing or unequal workspace effects: {}",
                row.test
            );
        }
        Ok(())
    }

    /// Validate the prepared bytes. Caller-selected failure retention uses the
    /// same original and candidate snapshots; it neither installs nor reruns a
    /// rejected rewrite. A saved capsule is never installation authorization.
    pub fn validate_native(&self, native_executable: &Path) -> Result<SuiteReport> {
        self.validate_native_with(native_executable, || {
            FailureArchive::from_environment([&self.project, self.candidate_root()])
        })
    }

    fn validate_native_with(
        &self,
        native_executable: &Path,
        archive: impl FnOnce() -> Result<Option<FailureArchive>>,
    ) -> Result<SuiteReport> {
        let candidate = self
            .candidate
            .as_ref()
            .context("checked rewrite candidate is not prepared")?;
        budget(self.deadline)?;
        let archive = archive()?;
        run_captured_with_archive(
            (&self.project, self.candidate_root()),
            (&self.original, candidate),
            native_executable,
            self.deadline,
            true,
            archive,
        )
    }

    /// Execute Node and explicitly selected Bun on original inputs, and native
    /// Franken on the prepared candidate. No source recapture, two-leg fallback
    /// or second validation run is performed. The caller must approve execution.
    pub fn validate_product(
        &self,
        native_executable: &Path,
        bun_executable: &Path,
    ) -> Result<ProductReport> {
        self.validate_product_with(native_executable, bun_executable, || Ok(None))
    }

    /// The caller owns this operation's cancellation handle. A request stops
    /// active process groups and later case dispatch; it cannot be presented
    /// as passing evidence or as a native regression authorizing recovery.
    pub fn validate_product_cancellable(
        &self,
        native_executable: &Path,
        bun_executable: &Path,
        cancellation: &product_oracle::CancellationToken,
    ) -> Result<ProductReport> {
        self.validate_product_controlled(
            native_executable, bun_executable, || Ok(None), Some(cancellation),
        )
    }

    /// Primary-command variant that honors the caller's explicit failure
    /// directory selection. A rejected candidate retains all three legs, never
    /// a pair projection. Library callers can use validate_product for no I/O.
    pub fn validate_product_retaining_failures(
        &self,
        native_executable: &Path,
        bun_executable: &Path,
    ) -> Result<ProductReport> {
        self.validate_product_with(native_executable, bun_executable, || {
            FailureArchive::from_environment([&self.project, self.candidate_root()])
        })
    }

    fn validate_product_with(
        &self,
        native_executable: &Path,
        bun_executable: &Path,
        archive: impl FnOnce() -> Result<Option<FailureArchive>>,
    ) -> Result<ProductReport> {
        self.validate_product_controlled(native_executable, bun_executable, archive, None)
    }

    fn validate_product_controlled(
        &self,
        native_executable: &Path,
        bun_executable: &Path,
        archive: impl FnOnce() -> Result<Option<FailureArchive>>,
        cancellation: Option<&product_oracle::CancellationToken>,
    ) -> Result<ProductReport> {
        if let Some(cancellation) = cancellation {
            cancellation.check()?;
        }
        let candidate = self
            .candidate
            .as_ref()
            .context("checked rewrite candidate is not prepared")?;
        budget(self.deadline)?;
        let archive = archive()?;
        let mut report = product_oracle::run_captured_cancellable(
            [&self.project, self.candidate_root()],
            [&self.original, candidate],
            native_executable,
            bun_executable,
            self.deadline,
            true,
            cancellation,
        )?;
        if let Some(archive) = archive {
            report.failure_capture =
                archive.finish_product(&report, &self.original, candidate, self.deadline);
        }
        Ok(report)
    }

    /// Keep both captured hashes and all three runtime observations at the
    /// installation boundary. Only a live executor result is admissible.
    pub fn check_product_validation(&self, report: &ProductReport) -> Result<()> {
        budget(self.deadline)?;
        let candidate = self
            .candidate
            .as_ref()
            .context("checked rewrite candidate is not prepared")?;
        let tests = matched_tests(&self.original, candidate)?;
        report.check_admission(&self.original.digest, &candidate.digest, &tests)
    }

    /// The whole tree, including non-rewritten dependencies and configuration,
    /// must still match. This is a pre-install check, not an OS filesystem lock.
    pub fn ensure_source_unchanged(&self) -> Result<()> {
        let current = Snapshot::capture(&self.project, self.deadline)?;
        ensure!(
            current.digest == self.original.digest,
            "project changed during checked rewrite validation; refusing installation"
        );
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn validate_node_pair(&self) -> Result<SuiteReport> {
        // Explicit Node/Node test commands measure the orchestrator, not native
        // Franken parity. This alternative is absent from production builds.
        let node = super::Invocation {
            executable: super::node_on_path()?,
            before: vec![],
            after: vec![],
        };
        super::execute_suite_pair(
            &self.original,
            self.candidate.as_ref().context("candidate not prepared")?,
            &node,
            &node,
            self.deadline,
            std::time::Duration::from_secs(5),
            true,
        )
    }

    /// Test-only real Node/Bun/Node commands: exercise installation orchestration
    /// without pretending Node is native Franken. Absent from production builds.
    #[cfg(test)]
    pub fn validate_node_bun_node(&self, bun_executable: &Path) -> Result<ProductReport> {
        let candidate = self.candidate.as_ref().context("candidate not prepared")?;
        let node = super::Invocation {
            executable: super::node_on_path()?,
            before: vec![],
            after: vec![],
        };
        let bun = super::Invocation {
            executable: bun_executable.canonicalize()?,
            before: vec![],
            after: vec![],
        };
        let identities = [
            node.identity(self.deadline)?,
            bun.identity(self.deadline)?,
            node.identity(self.deadline)?,
        ];
        product_oracle::execute(
            &self.original,
            candidate,
            [&node, &bun, &node],
            identities,
            self.deadline,
            std::time::Duration::from_secs(5),
            true,
        )
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
        assert!(
            candidate
                .prepare(&[Replacement {
                    path: "case.test.js",
                    before: b"stale",
                    after: b"changed"
                }])
                .is_err()
        );
        assert!(
            candidate
                .validate_native(Path::new("/bin/false"))
                .unwrap_err()
                .to_string()
                .contains("not prepared")
        );
        assert_eq!(
            fs::read(root.path().join("case.test.js")).unwrap(),
            b"console.log(42);"
        );
    }

    #[test]
    fn equivalent_candidates_execute_from_captured_bytes() {
        let root = project();
        let mut candidate = capture(root.path());
        candidate
            .prepare(&[Replacement {
                path: "case.test.js",
                before: b"console.log(42);",
                after: b"console.log(6*7);",
            }])
            .unwrap();
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
        assert!(
            candidate
                .ensure_source_unchanged()
                .unwrap_err()
                .to_string()
                .contains("project changed")
        );
    }

    #[test]
    fn filesystem_only_candidate_differences_are_measured() {
        let root = project();
        let before = "require('fs').writeFileSync('result','one');";
        fs::write(root.path().join("case.test.js"), before).unwrap();
        let mut candidate = capture(root.path());
        candidate
            .prepare(&[Replacement {
                path: "case.test.js",
                before: before.as_bytes(),
                after: b"require('fs').writeFileSync('result','two');",
            }])
            .unwrap();
        let report = candidate.validate_node_pair().unwrap();
        assert_eq!(report.verdict, "FAIL");
        assert_eq!(
            report.cases[0].divergences,
            ["filesystem:workspace_delta_mismatch"]
        );
        assert!(!root.path().join("result").exists());
    }

    #[test]
    fn invalid_paths_and_duplicate_targets_are_refused() {
        let root = project();
        for path in [
            "../case.test.js",
            "./case.test.js",
            "/case.test.js",
            ".migrate-backup/file",
            "config.json/../case.test.js",
        ] {
            assert!(
                capture(root.path())
                    .prepare(&[Replacement {
                        path,
                        before: b"",
                        after: b""
                    }])
                    .is_err()
            );
        }
        let edits = [
            Replacement {
                path: "config.json",
                before: b"{}",
                after: b"{}",
            },
            Replacement {
                path: "config.json",
                before: b"{}",
                after: b"{}",
            },
        ];
        assert!(
            capture(root.path())
                .prepare(&edits)
                .unwrap_err()
                .to_string()
                .contains("duplicate")
        );
    }

    #[test]
    fn failed_repreparation_invalidates_the_previous_candidate() {
        let root = project();
        let mut candidate = capture(root.path());
        candidate.prepare(&[]).unwrap();
        assert!(
            candidate
                .prepare(&[Replacement {
                    path: "absent",
                    before: b"",
                    after: b""
                }])
                .is_err()
        );
        assert!(
            candidate
                .validate_native(Path::new("/bin/false"))
                .unwrap_err()
                .to_string()
                .contains("not prepared")
        );
    }

    #[test]
    fn empty_test_inventory_cannot_be_checked() {
        let root = tempfile::tempdir().unwrap();
        assert!(
            RewriteCandidate::capture(root.path(), Instant::now() + Duration::from_secs(5))
                .err()
                .unwrap()
                .to_string()
                .contains("nonempty")
        );
    }

    #[test]
    fn a_passing_report_for_another_prepared_candidate_cannot_be_reused() {
        let root = project();
        let mut candidate = capture(root.path());
        candidate.prepare(&[]).unwrap();
        let report = candidate.validate_node_pair().unwrap();
        candidate.check_validation(&report).unwrap();
        candidate
            .prepare(&[Replacement {
                path: "config.json",
                before: b"{}",
                after: b"{\"changed\":true}",
            }])
            .unwrap();
        assert_eq!(candidate.input_sha256(), report.input_sha256);
        assert!(
            candidate
                .check_validation(&report)
                .unwrap_err()
                .to_string()
                .contains("prepared candidate")
        );
        assert!(
            candidate
                .prepare(&[Replacement {
                    path: "absent",
                    before: b"",
                    after: b""
                }])
                .is_err()
        );
        assert!(
            candidate
                .check_validation(&report)
                .unwrap_err()
                .to_string()
                .contains("not prepared")
        );
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
            (|r: &mut SuiteReport| r.cases[0].native.as_mut().unwrap().stdout.sha256.push('0'))
                as fn(&mut SuiteReport),
            |r| r.cases[0].native.as_mut().unwrap().stderr.bytes += 1,
            |r| {
                r.cases[0]
                    .native
                    .as_mut()
                    .unwrap()
                    .workspace_delta
                    .as_mut()
                    .unwrap()
                    .sha256
                    .push('0')
            },
            |r| r.cases[0].native.as_mut().unwrap().workspace_delta = None,
            |r| r.cases[0].reference = None,
            |r| r.cases[0].native.as_mut().unwrap().exit_code = Some(7),
            |r| r.cases[0].reference.as_mut().unwrap().signal = Some(9),
        ] {
            let mut changed = report.clone();
            mutate(&mut changed);
            assert!(changed.cases[0].divergences.is_empty());
            assert!(
                candidate.check_validation(&changed).is_err(),
                "{changed:#?}"
            );
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
            assert!(
                candidate.check_validation(&changed).is_err(),
                "{changed:#?}"
            );
        }
        candidate.deadline = Instant::now();
        assert!(candidate.check_validation(&report).is_err());
    }

    #[test]
    fn inventory_inspection_uses_captured_bytes_without_preparing_or_executing() {
        let root = project();
        let candidate = capture(root.path());
        fs::write(
            root.path().join("other.test.js"),
            "throw new Error('not captured');",
        )
        .unwrap();
        assert_eq!(
            candidate.test_inventory().unwrap(),
            [PathBuf::from("case.test.js")]
        );
        assert!(candidate.candidate.is_none());
        assert!(candidate.ensure_source_unchanged().is_err());
    }

    #[test]
    fn rejected_prepared_bytes_can_be_replayed_and_exported_without_installation() {
        use super::super::{FailureCapture, native_replay};
        let root = project();
        let outputs = tempfile::tempdir().unwrap();
        let mut candidate = capture(root.path());
        candidate
            .prepare(&[Replacement {
                path: "case.test.js",
                before: b"console.log(42);",
                after: b"console.log('prepared candidate');",
            }])
            .unwrap();
        // A real, deliberately failing executable exercises refusal and capture;
        // it is not a replacement native engine or a compatibility claim.
        let report = candidate
            .validate_native_with(Path::new("/bin/false"), || {
                FailureArchive::reserve(outputs.path(), [root.path(), root.path()]).map(Some)
            })
            .unwrap();
        assert_eq!(report.verdict, "FAIL");
        assert!(candidate.check_validation(&report).is_err());
        candidate.ensure_source_unchanged().unwrap();
        let Some(FailureCapture::Saved {
            capsule_path,
            content_sha256,
        }) = &report.failure_capture
        else {
            panic!("{report:#?}")
        };
        assert_ne!(report.input_sha256, report.candidate_input_sha256);
        let summary = native_replay::inspect(capsule_path).unwrap();
        assert_eq!(summary.input_sha256, candidate.original.digest);
        assert_eq!(
            summary.candidate_input_sha256,
            candidate.candidate.as_ref().unwrap().digest
        );
        let exported = native_replay::export_inputs(
            capsule_path,
            content_sha256,
            &outputs.path().join("reproducer"),
        )
        .unwrap();
        assert_eq!(
            fs::read(exported.destination.join("original/case.test.js")).unwrap(),
            b"console.log(42);"
        );
        assert_eq!(
            fs::read(exported.destination.join("candidate/case.test.js")).unwrap(),
            b"console.log('prepared candidate');"
        );
        let replayed =
            native_replay::replay(capsule_path, content_sha256, Path::new("/bin/false"), false)
                .unwrap();
        assert_eq!(replayed.verdict, "REPRODUCED");
        assert_eq!(replayed.validation.cases, report.cases);
        assert_eq!(
            fs::read(root.path().join("case.test.js")).unwrap(),
            b"console.log(42);"
        );
        assert!(!root.path().join(".migrate-backup").exists());
    }

    #[test]
    fn unprepared_expired_and_invalid_archive_requests_never_dispatch() {
        let root = project();
        let mut candidate = capture(root.path());
        let error = candidate
            .validate_native_with(Path::new("/absent/native"), || {
                panic!("unprepared candidate cannot reserve storage")
            })
            .unwrap_err();
        assert!(error.to_string().contains("not prepared"));
        candidate.prepare(&[]).unwrap();
        let error = candidate
            .validate_native_with(Path::new("/absent/native"), || {
                FailureArchive::reserve(root.path(), [root.path(), root.path()]).map(Some)
            })
            .unwrap_err();
        assert!(error.to_string().contains("outside"));
        candidate.deadline = Instant::now();
        let error = candidate
            .validate_native_with(Path::new("absent/native"), || {
                panic!("expired validation cannot reserve storage")
            })
            .unwrap_err();
        assert!(error.to_string().contains("budget"));
        assert_eq!(
            fs::read(root.path().join("case.test.js")).unwrap(),
            b"console.log(42);"
        );
    }

    #[test]
    fn three_runtime_candidate_validation_refuses_unprepared_expired_and_missing_references() {
        let root = project();
        let mut candidate = capture(root.path());
        let missing = Path::new("/absent/product-reference");
        assert!(
            candidate
                .validate_product(missing, missing)
                .unwrap_err()
                .to_string()
                .contains("not prepared")
        );
        candidate.prepare(&[]).unwrap();
        assert!(
            candidate
                .validate_product(Path::new("/bin/false"), missing)
                .unwrap_err()
                .to_string()
                .contains("resolve Bun")
        );
        candidate.deadline = Instant::now();
        assert!(
            candidate
                .validate_product(missing, missing)
                .unwrap_err()
                .to_string()
                .contains("budget")
        );
        assert_eq!(
            fs::read(root.path().join("case.test.js")).unwrap(),
            b"console.log(42);"
        );
    }

    #[test]
    fn three_runtime_admission_stays_bound_to_preparation_and_operation_deadline() {
        let root = project();
        let mut candidate = capture(root.path());
        candidate.prepare(&[]).unwrap();
        // Same-Node roles deliberately prove refusal, not product equivalence.
        let report = candidate
            .validate_node_bun_node(&super::super::node_on_path().unwrap())
            .unwrap();
        assert!(
            candidate
                .check_product_validation(&report)
                .unwrap_err()
                .to_string()
                .contains("distinct reference")
        );
        candidate
            .prepare(&[Replacement {
                path: "config.json",
                before: b"{}",
                after: b"{\"new\":true}",
            }])
            .unwrap();
        assert!(
            candidate
                .check_product_validation(&report)
                .unwrap_err()
                .to_string()
                .contains("prepared candidate")
        );
        candidate.deadline = Instant::now();
        assert!(
            candidate
                .check_product_validation(&report)
                .unwrap_err()
                .to_string()
                .contains("budget")
        );
    }

    #[test]
    fn three_runtime_failure_retains_the_prepared_candidate_without_installation() {
        use super::super::native_replay::failure_capture::{FailureCapture, product};
        let root = project();
        let outputs = tempfile::tempdir().unwrap();
        let mut candidate = capture(root.path());
        candidate
            .prepare(&[Replacement {
                path: "case.test.js",
                before: b"console.log(42);",
                after: b"console.log('prepared only');",
            }])
            .unwrap();
        // Deliberately empty-output reference and failing native executable.
        let report = candidate
            .validate_product_with(Path::new("/bin/false"), Path::new("/bin/true"), || {
                FailureArchive::reserve(outputs.path(), [root.path(), root.path()]).map(Some)
            })
            .unwrap();
        assert_eq!(report.verdict, "INCONCLUSIVE");
        assert!(candidate.check_product_validation(&report).is_err());
        let Some(FailureCapture::Saved {
            capsule_path,
            content_sha256,
        }) = &report.failure_capture
        else {
            panic!("{report:#?}")
        };
        let exported = product::export_any(
            capsule_path,
            content_sha256,
            &outputs.path().join("reproducer"),
        )
        .unwrap();
        assert_eq!(
            exported.capsule.candidate_input_sha256,
            candidate.candidate.as_ref().unwrap().digest
        );
        assert_eq!(
            fs::read(exported.destination.join("candidate/case.test.js")).unwrap(),
            b"console.log('prepared only');"
        );
        let replayed = product::replay(
            capsule_path,
            content_sha256,
            Path::new("/bin/false"),
            Path::new("/bin/true"),
            false,
        )
        .unwrap();
        assert_eq!(replayed.verdict, "REPRODUCED");
        assert_eq!(replayed.validation.cases, report.cases);
        candidate.ensure_source_unchanged().unwrap();
        assert_eq!(
            fs::read(root.path().join("case.test.js")).unwrap(),
            b"console.log(42);"
        );
        assert!(!root.path().join(".migrate-backup").exists());
    }

    #[test]
    fn product_archive_preflight_cannot_be_bypassed_by_a_missing_runtime() {
        let root = project();
        let mut candidate = capture(root.path());
        let absent = Path::new("/absent/native");
        assert!(
            candidate
                .validate_product_with(absent, absent, || panic!(
                    "unprepared candidate must not reserve"
                ))
                .unwrap_err()
                .to_string()
                .contains("not prepared")
        );
        candidate.prepare(&[]).unwrap();
        assert!(
            candidate
                .validate_product_with(absent, absent, || FailureArchive::reserve(
                    root.path(),
                    [root.path(), root.path()]
                )
                .map(Some))
                .unwrap_err()
                .to_string()
                .contains("outside")
        );
        candidate.deadline = Instant::now();
        assert!(
            candidate
                .validate_product_with(absent, absent, || panic!(
                    "expired candidate must not reserve"
                ))
                .unwrap_err()
                .to_string()
                .contains("budget")
        );
    }
}

#[cfg(test)]
mod reviewed_directory_tests {
    use super::*;
    use std::os::unix::fs::symlink;

    fn pair() -> (tempfile::TempDir, PathBuf, PathBuf) {
        let root = tempfile::tempdir().unwrap();
        let original = root.path().join("original");
        let proposed = root.path().join("proposed");
        for path in [&original, &proposed] {
            fs::create_dir(path).unwrap();
            fs::write(path.join("case.test.cjs"), "console.log(40 + 2);\n").unwrap();
            fs::write(path.join("config.json"), "{}\n").unwrap();
            fs::set_permissions(path.join("config.json"), fs::Permissions::from_mode(0o644)).unwrap();
        }
        (root, original, proposed)
    }
    fn capture(path: &Path) -> RewriteCandidate {
        RewriteCandidate::capture(path, Instant::now() + std::time::Duration::from_secs(30)).unwrap()
    }
    fn pin(path: &Path) -> String {
        capture(path).input_sha256().into()
    }

    #[test]
    fn reviewed_directory_preserves_exact_bytes_and_does_not_install() {
        let (_root, original, proposed) = pair();
        fs::write(proposed.join("case.test.cjs"), "console.log(42);\n").unwrap();
        let mut plan = capture(&original);
        plan.prepare_project(&proposed, &pin(&proposed)).unwrap();
        let edits = plan.replacements().unwrap();
        assert_eq!(edits.len(), 1);
        assert_eq!(edits[0].path, "case.test.cjs");
        assert_eq!(edits[0].before, b"console.log(40 + 2);\n");
        assert_eq!(edits[0].after, b"console.log(42);\n");
        assert_eq!(fs::read(original.join("case.test.cjs")).unwrap(), edits[0].before);
        fs::write(proposed.join("case.test.cjs"), "process.exit(99);").unwrap();
        assert_eq!(plan.replacements().unwrap()[0].after, b"console.log(42);\n");
        assert!(plan.ensure_candidate_source_unchanged().is_err());
        plan.ensure_source_unchanged().unwrap();
    }

    #[test]
    fn identical_separate_tree_produces_an_explicit_empty_plan() {
        let (_root, original, proposed) = pair();
        let mut plan = capture(&original);
        plan.prepare_project(&proposed, &pin(&proposed)).unwrap();
        assert!(plan.replacements().unwrap().is_empty());
        plan.ensure_candidate_source_unchanged().unwrap();
    }

    #[test]
    fn wrong_pins_and_aliases_invalidate_an_earlier_preparation() {
        let (root, original, proposed) = pair();
        let alias = root.path().join("original-alias");
        symlink(&original, &alias).unwrap();
        let mut plan = capture(&original);
        let expected = pin(&proposed);
        for (path, bad_pin) in [(&proposed, "bad".to_owned()), (&proposed, "0".repeat(64)), (&alias, expected.clone())] {
            plan.prepare_project(&proposed, &expected).unwrap();
            assert!(plan.prepare_project(path, &bad_pin).is_err());
            assert!(plan.replacements().is_err());
        }
    }

    #[test]
    fn structural_mode_and_link_changes_are_never_partially_installed() {
        for mutation in 0..5 {
            let (_root, original, proposed) = pair();
            fs::write(proposed.join("case.test.cjs"), "console.log(42);\n").unwrap();
            match mutation {
                0 => fs::create_dir(proposed.join("new-directory")).unwrap(),
                1 => { fs::rename(proposed.join("config.json"), proposed.join("renamed.json")).unwrap(); }
                2 => fs::set_permissions(proposed.join("config.json"), fs::Permissions::from_mode(0o600)).unwrap(),
                3 => {
                    fs::rename(proposed.join("config.json"), proposed.join("saved.json")).unwrap();
                    symlink("saved.json", proposed.join("config.json")).unwrap();
                }
                _ => {
                    symlink("case.test.cjs", original.join("link.cjs")).unwrap();
                    symlink("config.json", proposed.join("link.cjs")).unwrap();
                }
            }
            let mut plan = capture(&original);
            assert!(plan.prepare_project(&proposed, &pin(&proposed)).is_err(), "mutation {mutation}");
            assert!(plan.replacements().is_err());
            assert_eq!(fs::read(original.join("case.test.cjs")).unwrap(), b"console.log(40 + 2);\n");
        }
    }

    #[test]
    fn reviewed_golden_or_reserved_metadata_changes_cannot_redefine_success() {
        for change_metadata in [false, true] {
            let (_root, original, proposed) = pair();
            for path in [&original, &proposed] {
                fs::create_dir(path.join(".franken-node")).unwrap();
                fs::write(path.join(".franken-node/migration-tests.json"),
                    r#"{"schema_version":"franken-node/migration-tests/v1","tests":["case.test.cjs"],"expectations":{"case.test.cjs":{"stdout":"expected.txt"}}}"#).unwrap();
                fs::write(path.join(".franken-node/authority.txt"), "original authority").unwrap();
                fs::write(path.join("expected.txt"), "42\n").unwrap();
            }
            let target = if change_metadata { ".franken-node/authority.txt" } else { "expected.txt" };
            fs::write(proposed.join(target), "redefined").unwrap();
            let mut plan = capture(&original);
            assert!(plan.prepare_project(&proposed, &pin(&proposed)).is_err());
            assert!(plan.replacements().is_err());
        }
    }

    #[test]
    fn proposed_tree_cannot_supply_the_runtime_executable() {
        let (_root, original, proposed) = pair();
        let mut plan = capture(&original);
        plan.prepare_project(&proposed, &pin(&proposed)).unwrap();
        let runtime = proposed.join("native-runtime");
        fs::copy("/bin/true", &runtime).unwrap();
        let error = plan.validate_product(&runtime, Path::new("/bin/false")).unwrap_err();
        assert!(format!("{error:#}").contains("outside both"), "{error:#}");
    }

    #[test]
    fn new_helper_executes_from_the_reviewed_capture_and_retains_its_exact_mode() {
        let (_root, original, proposed) = pair();
        fs::write(proposed.join("helper.cjs"), b"module.exports = 42;\n").unwrap();
        fs::set_permissions(proposed.join("helper.cjs"), fs::Permissions::from_mode(0o640)).unwrap();
        fs::write(proposed.join("case.test.cjs"), b"console.log(require('./helper.cjs'));\n").unwrap();
        let expected = pin(&proposed);
        let mut plan = capture(&original);
        plan.prepare_project(&proposed, &expected).unwrap();
        assert_eq!(plan.candidate.as_ref().unwrap().digest, expected);
        let additions = plan.additions().unwrap();
        assert_eq!(additions.len(), 1);
        assert_eq!(additions[0].path, "helper.cjs");
        assert_eq!(additions[0].after, b"module.exports = 42;\n");
        assert_eq!(additions[0].mode, 0o640);
        assert_eq!(plan.changes().unwrap().replacements.len(), 1);
        assert!(plan.replacements().is_err()); // No partial plan for an old consumer.
        // This explicit Node/Node path tests orchestration, not Franken parity.
        fs::write(proposed.join("helper.cjs"), b"throw new Error('later edit');\n").unwrap();
        let report = plan.validate_node_pair().unwrap();
        assert_eq!(report.verdict, "PASS", "{report:?}");
        plan.check_validation(&report).unwrap();
        assert_eq!(report.candidate_input_sha256, expected);
        assert!(plan.ensure_candidate_source_unchanged().is_err());
        plan.ensure_source_unchanged().unwrap();
        assert!(!original.join("helper.cjs").exists());
    }

    #[test]
    fn creation_only_and_empty_additions_are_not_empty_replacement_preimages() {
        let (_root, original, proposed) = pair();
        fs::write(proposed.join("empty.dat"), b"").unwrap();
        fs::set_permissions(proposed.join("empty.dat"), fs::Permissions::from_mode(0o400)).unwrap();
        let mut plan = capture(&original);
        plan.prepare_project(&proposed, &pin(&proposed)).unwrap();
        assert!(plan.changes().unwrap().replacements.is_empty());
        assert!(plan.replacements().is_err());
        let additions = plan.additions().unwrap();
        assert_eq!(additions.len(), 1);
        assert_eq!(additions[0].path, "empty.dat");
        assert!(additions[0].after.is_empty());
        assert_eq!(additions[0].mode, 0o400);
        assert!(plan.prepare(&[Replacement { path: "empty.dat", before: b"", after: b"new" }]).is_err());
        assert!(plan.additions().is_err());
        assert!(!original.join("empty.dat").exists());
    }

    #[test]
    fn additions_cannot_change_test_inventory_authority_directories_or_links() {
        for mutation in 0..4 {
            let (_root, original, proposed) = pair();
            for root in [&original, &proposed] {
                fs::create_dir(root.join(".franken-node")).unwrap();
            }
            match mutation {
                0 => fs::write(proposed.join("extra.test.cjs"), "console.log(42);").unwrap(),
                1 => fs::write(proposed.join(".franken-node/authority"), "new authority").unwrap(),
                2 => fs::create_dir(proposed.join("new-directory")).unwrap(),
                _ => symlink("config.json", proposed.join("linked-helper.cjs")).unwrap(),
            }
            let mut plan = capture(&original);
            plan.prepare(&[]).unwrap();
            assert!(plan.prepare_project(&proposed, &pin(&proposed)).is_err(), "{mutation}");
            assert!(plan.additions().is_err());
            assert!(plan.replacements().is_err());
            assert_eq!(fs::read(original.join("case.test.cjs")).unwrap(), b"console.log(40 + 2);\n");
        }
    }

    #[test]
    fn direct_addition_preparation_checks_absence_parent_paths_modes_and_limits() {
        let (_root, original, _) = pair();
        let mut plan = capture(&original);
        for path in ["config.json", "../helper.cjs", "/helper.cjs", "a//b", ".franken-node/new", "missing/helper.cjs"] {
            assert!(plan.prepare_changes(&[], &[Addition { path, after: b"new", mode: 0o600 }]).is_err(), "{path}");
            assert!(plan.additions().is_err());
        }
        for mode in [0, 0o200, 0o4644] {
            assert!(plan.prepare_changes(&[], &[Addition { path: "helper.cjs", after: b"new", mode }]).is_err());
        }
        let oversized = vec![0; 10 * 1024 * 1024 + 1];
        assert!(plan.prepare_changes(&[], &[Addition { path: "helper.cjs", after: &oversized, mode: 0o600 }]).is_err());
        assert!(plan.prepare_changes(&[], &[
            Addition { path: "helper.cjs", after: b"one", mode: 0o600 },
            Addition { path: "helper.cjs", after: b"two", mode: 0o600 },
        ]).is_err());
        assert!(!original.join("helper.cjs").exists());
        assert!(!original.join(".migrate-backup").exists());
    }

    #[test]
    fn new_helpers_do_not_permit_golden_or_application_request_substitution() {
        for request in [false, true] {
            let (_root, original, proposed) = pair();
            for root in [&original, &proposed] {
                fs::create_dir(root.join(".franken-node")).unwrap();
                fs::write(root.join("expected.txt"), "42\n").unwrap();
                fs::write(root.join(".franken-node/migration-tests.json"),
                    r#"{"schema_version":"franken-node/migration-tests/v1","tests":["case.test.cjs"],"expectations":{"case.test.cjs":{"stdout":"expected.txt"}}}"#).unwrap();
            }
            fs::write(proposed.join("helper.cjs"), "module.exports = 42;").unwrap();
            if request {
                fs::write(proposed.join(".franken-node/migration-tests.json"),
                    r#"{"schema_version":"franken-node/migration-tests/v1","tests":["case.test.cjs"],"execution":{"case.test.cjs":{"arguments":["different-request"]}},"expectations":{"case.test.cjs":{"stdout":"expected.txt"}}}"#).unwrap();
            } else {
                fs::write(proposed.join("expected.txt"), "redefined\n").unwrap();
            }
            let mut plan = capture(&original);
            assert!(plan.prepare_project(&proposed, &pin(&proposed)).is_err());
            assert!(plan.additions().is_err());
            assert!(!original.join("helper.cjs").exists());
        }
    }
}
