//! Captured original/candidate inputs for checked rewrite installation.
//!
//! This is a child of the production validation suite, so it reuses the exact
//! capture, invocation, supervision and comparison implementations. Preparing
//! a candidate never executes code or edits the caller's source tree.

use super::{EntryData, Snapshot, SuiteReport, budget, matched_tests, run_captured};
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
        let temporary = tempfile::Builder::new().prefix("franken-rewrite-candidate-").tempdir()?;
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

    pub fn validate_native(&self, native_executable: &Path) -> Result<SuiteReport> {
        let candidate = self.candidate.as_ref().context("checked rewrite candidate is not prepared")?;
        run_captured((&self.project, &self.project), (&self.original, candidate),
            native_executable, self.deadline, true)
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
}
