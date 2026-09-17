//! Automatic retention for live product validation failures.
//!
//! The operator explicitly selects an existing directory through
//! FRANKEN_NODE_MIGRATION_FAILURE_DIR. Nothing is persisted by default. Reserve
//! private storage before dispatch; archive only the immutable inputs actually
//! measured, never a recapture or a second execution after the failure.

use super::{Blob, Capsule, CapturedRun, Payload, SCHEMA, Snapshot, SuiteReport,
    budget, complete_report, implementation_hash, payload_hash, store_snapshot};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::Instant;

#[path = "product_replay.rs"]
pub mod product;

pub const DIRECTORY_ENV: &str = "FRANKEN_NODE_MIGRATION_FAILURE_DIR";

/// Diagnostic attachment, not a replacement for the measured suite verdict.
/// A saved capsule contains private source/dependency/configuration bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum FailureCapture {
    Saved { capsule_path: PathBuf, content_sha256: String },
    Unavailable { reason: String },
}

/// Holds an exclusively created, mode-0700 reservation across guest execution.
/// No Debug/Serialize: the capability and its paths are not implicit telemetry.
pub struct FailureArchive {
    directory: tempfile::TempDir,
    projects: [PathBuf; 2],
}

impl FailureArchive {
    /// Caller-controlled configuration only. An empty or invalid selection is
    /// an error before runtime dispatch, not silent permission to skip capture.
    pub fn from_environment(projects: [&Path; 2]) -> Result<Option<Self>> {
        std::env::var_os(DIRECTORY_ENV).map(|path| Self::reserve(Path::new(&path), projects)
            .with_context(|| format!("prepare {DIRECTORY_ENV}"))).transpose()
    }

    pub fn reserve(directory: &Path, projects: [&Path; 2]) -> Result<Self> {
        ensure!(directory.is_absolute(), "failure archive directory must be an absolute path");
        let metadata = fs::symlink_metadata(directory).context("inspect failure archive directory")?;
        ensure!(metadata.is_dir() && !metadata.is_symlink(),
            "failure archive directory must be an existing ordinary directory, not a symlink");
        let directory = directory.canonicalize()?;
        let projects = [projects[0].canonicalize()?, projects[1].canonicalize()?];
        for project in &projects {
            ensure!(!directory.starts_with(project), "failure archive directory must be outside both input projects");
        }
        // tempfile directories default to 0777 masked by the caller's umask,
        // unlike its private files. Set permissions AT CREATION, not after
        // source material or archive names have become visible to other users.
        let directory = tempfile::Builder::new().prefix("franken-migration-failure-")
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir_in(directory).context("reserve private failure archive storage")?;
        ensure!(fs::symlink_metadata(directory.path())?.permissions().mode() & 0o077 == 0,
            "failure archive reservation is accessible to other users");
        Ok(Self { directory, projects })
    }

    /// Only the live executor may provide this report. Importing arbitrary
    /// reports cannot authenticate an execution, even when hashes agree.
    /// Publication/limit failures do not erase evidence or change FAIL to PASS.
    pub(in super::super) fn finish(self, report: &SuiteReport, original: &Snapshot,
        candidate: &Snapshot, deadline: Instant) -> Option<FailureCapture> {
        if report.verdict == "PASS" { return None; }
        let result = (|| -> Result<FailureCapture> {
            budget(deadline)?;
            ensure!(report.verdict == "FAIL", "incomplete or infrastructure-error runs are not replayable");
            complete_report(report, original, candidate)?;
            let mut blobs = BTreeMap::new();
            let mut expanded = 0;
            let mut metadata = 0;
            let stored_original = store_snapshot(original, &mut blobs, &mut expanded, &mut metadata, deadline)?;
            let stored_candidate = if original.digest == candidate.digest { None } else {
                Some(store_snapshot(candidate, &mut blobs, &mut expanded, &mut metadata, deadline)?)
            };
            let payload = Payload { schema_version: SCHEMA.into(), implementation_sha256: implementation_hash(),
                original: stored_original, candidate: stored_candidate,
                blobs: blobs.into_iter().map(|(sha256, hex)| Blob { sha256, hex }).collect(), expected: report.clone() };
            let content_sha256 = payload_hash(&payload)?;
            budget(deadline)?;
            let captured = CapturedRun { report: report.clone(), capsule: Capsule { payload, content_sha256 },
                projects: self.projects.clone(), unavailable: None };
            let path = self.directory.path().join("failure.json");
            let summary = captured.write_capsule(&path)?;
            fs::File::open(self.directory.path())?.sync_all()?;
            budget(deadline)?;
            Ok(FailureCapture::Saved { capsule_path: path, content_sha256: summary.content_sha256 })
        })();
        match result {
            Ok(saved) => {
                // Retain only a fully published archive. The caller owns its
                // retention lifecycle; successful validations leave no archive.
                let _retained_directory = self.directory.keep();
                Some(saved)
            }
            Err(error) => Some(FailureCapture::Unavailable { reason: format!("{error:#}") }),
        }
    }

    /// Retain complete native failures OR reference disagreements in the
    /// three-runtime schema. No extra executions and no Node/native projection.
    pub(in super::super) fn finish_product(self, report: &super::super::product_oracle::ProductReport,
        original: &Snapshot, candidate: &Snapshot, deadline: Instant) -> Option<FailureCapture> {
        if report.verdict == "PASS" { return None; }
        let result = (|| -> Result<FailureCapture> {
            budget(deadline)?;
            ensure!(matches!(report.verdict.as_str(), "FAIL" | "INCONCLUSIVE"),
                "incomplete or infrastructure-error product runs are not replayable");
            let captured = product::from_measured(report, [original, candidate], self.projects.clone(), deadline)?;
            let path = self.directory.path().join("failure.json");
            let summary = captured.write_capsule(&path)?;
            fs::File::open(self.directory.path())?.sync_all()?;
            budget(deadline)?;
            Ok(FailureCapture::Saved { capsule_path: path, content_sha256: summary.content_sha256 })
        })();
        match result {
            Ok(saved) => { let _retained_directory = self.directory.keep(); Some(saved) }
            Err(error) => Some(FailureCapture::Unavailable { reason: format!("{error:#}") }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::{inspect, load, reexecute};
    use super::super::super::{Invocation, execute_suite_pair, node_on_path};
    use std::os::unix::fs::symlink;
    use std::time::Duration;

    fn deadline() -> Instant { Instant::now() + Duration::from_secs(90) }
    fn measured(root: &Path, candidate: bool) -> (Snapshot, SuiteReport) {
        let snapshot = Snapshot::capture(root, deadline()).unwrap();
        let reference = Invocation { executable: node_on_path().unwrap(), before: vec![], after: vec![] };
        let native = Invocation { after: if candidate { vec!["candidate".into()] } else { vec![] }, ..reference.clone() };
        let report = execute_suite_pair(&snapshot, &snapshot, &reference, &native,
            deadline(), Duration::from_secs(5), true).unwrap();
        (snapshot, report)
    }
    fn project() -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join("case.test.js"),
            "console.log(process.argv.includes('candidate') ? 'wrong' : 'right');").unwrap();
        root
    }

    #[test]
    fn automatic_retention_uses_measured_bytes_and_survives_return_without_rerunning() {
        let root = project();
        let output = tempfile::tempdir().unwrap();
        let archive = FailureArchive::reserve(output.path(), [root.path(), root.path()]).unwrap();
        let (snapshot, report) = measured(root.path(), true);
        let measured_report = report.clone();
        fs::write(root.path().join("case.test.js"), "throw new Error('later source');").unwrap();
        let saved = archive.finish(&report, &snapshot, &snapshot, deadline()).unwrap();
        let FailureCapture::Saved { capsule_path, content_sha256 } = &saved else { panic!("{saved:?}") };
        assert_eq!(report, measured_report);
        assert_eq!(fs::metadata(capsule_path).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(fs::metadata(capsule_path.parent().unwrap()).unwrap().permissions().mode() & 0o777, 0o700);
        let summary = inspect(capsule_path).unwrap();
        assert_eq!(summary.content_sha256, *content_sha256);
        assert_eq!(summary.captured_verdict, "FAIL");
        let loaded = load(capsule_path, Some(content_sha256), deadline()).unwrap();
        assert_eq!(loaded.original.digest, snapshot.digest);
        assert!(loaded.candidate.is_none());
        assert_eq!(loaded.capsule.payload.expected, report);
        let reference = Invocation { executable: node_on_path().unwrap(), before: vec![], after: vec![] };
        let native = Invocation { after: vec!["candidate".into()], ..reference.clone() };
        let replayed = reexecute(loaded, &reference, &native, false, deadline()).unwrap();
        assert_eq!(replayed.verdict, "REPRODUCED");
        assert_eq!(replayed.validation.verdict, "FAIL");
        assert_eq!(fs::read_to_string(root.path().join("case.test.js")).unwrap(), "throw new Error('later source');");
        let json = serde_json::to_string(&saved).unwrap();
        assert!(!json.contains("console.log") && !json.contains("later source"));
        assert_eq!(serde_json::from_str::<FailureCapture>(&json).unwrap(), saved);
    }

    #[test]
    fn pass_leaves_no_archive_and_incomplete_failure_cannot_become_replayable() {
        let root = project();
        let output = tempfile::tempdir().unwrap();
        let (snapshot, report) = measured(root.path(), false);
        let archive = FailureArchive::reserve(output.path(), [root.path(), root.path()]).unwrap();
        assert!(archive.finish(&report, &snapshot, &snapshot, deadline()).is_none());
        assert_eq!(fs::read_dir(output.path()).unwrap().count(), 0);
        let mut incomplete = report;
        incomplete.verdict = "ERROR".into();
        incomplete.errors.push("runtime identity recheck failed".into());
        let before = incomplete.clone();
        let archive = FailureArchive::reserve(output.path(), [root.path(), root.path()]).unwrap();
        let capture = archive.finish(&incomplete, &snapshot, &snapshot, deadline()).unwrap();
        assert!(matches!(capture, FailureCapture::Unavailable { reason } if reason.contains("not replayable")));
        assert_eq!(incomplete, before);
        assert_eq!(fs::read_dir(output.path()).unwrap().count(), 0);
    }

    #[test]
    fn misbound_evidence_deadlines_and_publication_errors_do_not_erase_the_failure() {
        let root = project();
        let output = tempfile::tempdir().unwrap();
        let (snapshot, report) = measured(root.path(), true);
        let original = report.clone();
        for fault in 0..3 {
            let archive = FailureArchive::reserve(output.path(), [root.path(), root.path()]).unwrap();
            let mut input = report.clone();
            if fault == 0 { input.candidate_input_sha256 = "0".repeat(64); }
            if fault == 1 { fs::create_dir(archive.directory.path().join("failure.json")).unwrap(); }
            let deadline = if fault == 2 { Instant::now() } else { deadline() };
            let capture = archive.finish(&input, &snapshot, &snapshot, deadline).unwrap();
            assert!(matches!(capture, FailureCapture::Unavailable { .. }));
            assert_eq!(input.verdict, "FAIL");
            assert_eq!(input.cases, original.cases);
            assert_eq!(fs::read_dir(output.path()).unwrap().count(), 0);
        }
    }

    #[test]
    fn reservation_refuses_ambiguous_or_in_project_storage_before_dispatch() {
        let root = project();
        let candidate = tempfile::tempdir().unwrap();
        let output = tempfile::tempdir().unwrap();
        for path in [Path::new(""), Path::new("relative"), root.path(), candidate.path(),
            &root.path().join("case.test.js"), &output.path().join("absent")] {
            assert!(FailureArchive::reserve(path, [root.path(), candidate.path()]).is_err(), "{path:?}");
        }
        fs::create_dir(root.path().join("captures")).unwrap();
        assert!(FailureArchive::reserve(&root.path().join("captures"), [root.path(), candidate.path()]).is_err());
        let alias = output.path().join("alias");
        symlink(output.path(), &alias).unwrap();
        assert!(FailureArchive::reserve(&alias, [root.path(), candidate.path()]).is_err());
        assert_eq!(fs::read_dir(root.path().join("captures")).unwrap().count(), 0);
    }

    #[test]
    fn reservation_is_private_before_any_runtime_or_archive_write() {
        let root = project();
        let output = tempfile::tempdir().unwrap();
        let archive = FailureArchive::reserve(output.path(), [root.path(), root.path()]).unwrap();
        let path = archive.directory.path().to_path_buf();
        assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o700);
        assert_eq!(fs::read_dir(&path).unwrap().count(), 0);
        drop(archive);
        assert!(!path.exists());
    }

    #[test]
    fn product_retention_preserves_reference_disagreement_without_rerunning() {
        let root = project();
        let out = tempfile::tempdir().unwrap();
        let marker = out.path().join("runs");
        let source = format!("require('fs').appendFileSync({},'once');console.log('reference');",
            serde_json::to_string(&marker).unwrap());
        fs::write(root.path().join("case.test.js"), &source).unwrap();
        let snapshot = Snapshot::capture(root.path(), deadline()).unwrap();
        let archive = FailureArchive::reserve(out.path(), [root.path(), root.path()]).unwrap();
        // Deliberate empty-output reference and failed candidate, not Bun/Franken.
        let report = super::super::super::product_oracle::run_captured([root.path(), root.path()],
            [&snapshot, &snapshot], Path::new("/bin/false"), Path::new("/bin/true"), deadline(), true).unwrap();
        assert_eq!(report.verdict, "INCONCLUSIVE");
        let original = report.clone();
        fs::write(root.path().join("case.test.js"), "later source").unwrap();
        let saved = archive.finish_product(&report, &snapshot, &snapshot, deadline()).unwrap();
        let FailureCapture::Saved { capsule_path, content_sha256 } = saved else { panic!("{saved:?}") };
        assert_eq!(report, original);
        assert_eq!(fs::read_to_string(marker).unwrap(), "once");
        assert_eq!(product::inspect_any(&capsule_path).unwrap().captured_verdict, "INCONCLUSIVE");
        let exported = product::export_any(&capsule_path, &content_sha256, &out.path().join("export")).unwrap();
        assert_eq!(fs::read_to_string(exported.destination.join("original/case.test.js")).unwrap(), source);
        let manifest: serde_json::Value = serde_json::from_slice(&fs::read(exported.destination.join("reproducer.json")).unwrap()).unwrap();
        assert_eq!(manifest["expected"]["cases"], serde_json::to_value(report.cases).unwrap());
    }
}
