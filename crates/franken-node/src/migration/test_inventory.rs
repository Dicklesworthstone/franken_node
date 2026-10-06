//! Test selection and execution settings from captured inputs, never the
//! mutable source tree. Invalid manifests fail closed without heuristic fallback.

use super::{
    Entry, EntryData, Invocation, MAX_PATH_BYTES, MAX_TESTS, Snapshot, excluded_from_discovery,
    is_test,
};
use anyhow::{Context, Result, bail, ensure};
use rustix::fs::{Mode, OFlags, open, openat};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs::File;
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use std::process::Output;
use std::time::{Duration, Instant};

#[path = "test_execution.rs"]
mod execution;

pub(super) use scheduler::run_scheduled;

pub(super) const MAX_CONCURRENT_TESTS: usize = 4;

fn sequential() -> usize {
    1
}

const MANIFEST_PATH: &str = ".franken-node/migration-tests.json";
const MANIFEST_SCHEMA: &str = "franken-node/migration-tests/v1";
const MAX_MANIFEST_BYTES: usize = 64 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema_version: String,
    tests: Vec<String>,
    /// Explicit permission to overlap independent tests, not proof that their
    /// external effects are isolated. Omission keeps historical serial order.
    #[serde(default = "sequential")]
    max_concurrent_tests: usize,
    #[serde(default, deserialize_with = "execution::unique_map")]
    execution: BTreeMap<String, execution::Settings>,
    #[serde(default, deserialize_with = "execution::unique_map")]
    expectations: BTreeMap<String, Expectations>,
}

#[derive(Debug, Default, PartialEq, Eq)]
struct TestSettings {
    execution: execution::Settings,
    expectations: Expectations,
}

#[derive(Debug, PartialEq, Eq)]
struct Inventory {
    tests: BTreeMap<PathBuf, TestSettings>,
    max_concurrent_tests: usize,
}

/// An independent, captured oracle. Agreement between two runtimes alone can
/// otherwise accept two implementations that produce the same wrong output.
/// Missing fields preserve comparison-only behavior; an explicit expectation
/// must name at least one regular, bounded fixture. Null is not an assertion.
#[derive(Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Expectations {
    #[serde(default, deserialize_with = "expectation_field")]
    stdout: Option<String>,
    #[serde(default, deserialize_with = "expectation_field")]
    stderr: Option<String>,
    #[serde(default, deserialize_with = "execution::unique_map")]
    files: BTreeMap<String, String>,
}

fn expectation_field<'de, D>(deserializer: D) -> std::result::Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    String::deserialize(deserializer).map(Some)
}

const MAX_EXPECTATION_BYTES: usize = 1024 * 1024;
const MAX_EXPECTED_FILES: usize = 64;

fn expectation_path(name: &str) -> Result<&Path> {
    let path = Path::new(name);
    ensure!(
        !name.is_empty()
            && name.len() <= MAX_PATH_BYTES
            && !name.contains('\\')
            && !name.chars().any(char::is_control)
            && path
                .components()
                .all(|part| matches!(part, Component::Normal(_)))
            && path
                .components()
                .map(|part| part.as_os_str().to_string_lossy())
                .collect::<Vec<_>>()
                .join("/")
                == name,
        "expectation paths must be canonical project-relative paths"
    );
    ensure!(
        !excluded_from_discovery(path)
            && !path.components().any(|part| matches!(
                part.as_os_str().to_str(),
                Some(".franken-rewrite" | ".beads")
            )),
        "expectations cannot select dependencies, backups or reserved state"
    );
    Ok(path)
}

fn expectation_bytes<'a>(entries: &'a BTreeMap<PathBuf, Entry>, name: &str) -> Result<&'a [u8]> {
    let path = expectation_path(name)?;
    for parent in path
        .ancestors()
        .skip(1)
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        ensure!(
            matches!(
                entries.get(parent).map(|entry| &entry.data),
                Some(EntryData::Directory)
            ),
            "expectation fixtures must have ordinary captured directory parents"
        );
    }
    let Some(Entry {
        data: EntryData::File(bytes),
        ..
    }) = entries.get(path)
    else {
        bail!("expectation fixture must be a regular captured file");
    };
    ensure!(
        bytes.len() <= MAX_EXPECTATION_BYTES,
        "captured expectation fixture exceeds 1 MiB"
    );
    Ok(bytes)
}

impl Expectations {
    fn fixtures(&self) -> impl Iterator<Item = (&'static str, &str)> {
        [
            ("stdout", self.stdout.as_deref()),
            ("stderr", self.stderr.as_deref()),
        ]
        .into_iter()
        .filter_map(|(stream, path)| path.map(|path| (stream, path)))
        .chain(self.files.values().map(|path| ("file", path.as_str())))
    }

    fn validate(&self, entries: &BTreeMap<PathBuf, Entry>) -> Result<()> {
        ensure!(
            self.stdout.is_some() || self.stderr.is_some() || !self.files.is_empty(),
            "explicit output expectations must not be empty"
        );
        ensure!(
            self.files.len() <= MAX_EXPECTED_FILES,
            "at most 64 file output expectations per test"
        );
        for target in self.files.keys() {
            // Targets are workspace-root-relative, not relative to a harness's
            // cwd. They may be created by the guest, so need not be captured.
            expectation_path(target)?;
        }
        for (_, name) in self.fixtures() {
            expectation_bytes(entries, name)?;
        }
        Ok(())
    }

    fn matched(&self, original: &Snapshot, candidate: &Snapshot) -> Result<()> {
        for (stream, name) in self.fixtures() {
            ensure!(
                expectation_bytes(&original.entries, name)?
                    == expectation_bytes(&candidate.entries, name)?,
                "captured {stream} expectation bytes differ between original and candidate"
            );
        }
        Ok(())
    }

    fn check(&self, snapshot: &Snapshot, output: &Output) -> Result<()> {
        for (stream, name, actual) in [
            ("stdout", self.stdout.as_deref(), output.stdout.as_slice()),
            ("stderr", self.stderr.as_deref(), output.stderr.as_slice()),
        ] {
            if let Some(name) = name {
                // Deliberately do not put expected or actual bytes in errors:
                // stdout/stderr can contain credentials or private input data.
                ensure!(
                    expectation_bytes(&snapshot.entries, name)? == actual,
                    "test {stream} does not match its captured output expectation"
                );
            }
        }
        // Do not normalize exit status or streams. The existing paired oracle
        // must still reject failed processes and any cross-runtime divergence.
        Ok(())
    }

    fn pin_workspace(&self, workspace: &Path) -> Result<Option<File>> {
        if self.files.is_empty() {
            return Ok(None);
        }
        // Pin the directory BEFORE guest execution. A later rename or symlink
        // at the workspace pathname must not redirect our verification reads.
        let fd = open(
            workspace,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .context("pin output expectation workspace")?;
        Ok(Some(File::from(fd)))
    }

    fn check_files(
        &self,
        snapshot: &Snapshot,
        workspace: Option<&File>,
        deadline: Instant,
    ) -> Result<()> {
        if self.files.is_empty() {
            return Ok(());
        }
        let workspace = workspace.context("output expectation workspace was not pinned")?;
        for (target, fixture) in &self.files {
            let expected = expectation_bytes(&snapshot.entries, fixture)?;
            check_output_file(workspace, target, expected, deadline)
                .with_context(|| format!("file output expectation failed: {target}"))?;
        }
        Ok(())
    }
}

fn check_output_file(workspace: &File, name: &str, expected: &[u8], deadline: Instant) -> Result<()> {
    let path = expectation_path(name)?;
    let mut parent = workspace.try_clone()?;
    let mut parts = path.components().peekable();
    while let Some(part) = parts.next() {
        ensure!(
            Instant::now() < deadline,
            "file output expectation budget exhausted"
        );
        let last = parts.peek().is_none();
        let mut flags = OFlags::RDONLY
            | OFlags::NOFOLLOW
            | OFlags::CLOEXEC
            | OFlags::NONBLOCK
            | OFlags::NOCTTY;
        if !last {
            flags |= OFlags::DIRECTORY;
        }
        // Open one component at a time relative to an already-open directory.
        // NOFOLLOW on the leaf alone would still follow a replaced parent.
        let fd = openat(&parent, part.as_os_str(), flags, Mode::empty())
            .context("file output must exist without traversing symlinks")?;
        let mut file = File::from(fd);
        if !last {
            parent = file;
            continue;
        }
        let before = file.metadata()?;
        ensure!(before.is_file(), "file output must be a regular file");
        ensure!(
            before.len() == expected.len() as u64,
            "file output length differs from captured expectation"
        );
        let mut offset = 0_usize;
        let mut chunk = [0_u8; 8192];
        loop {
            ensure!(
                Instant::now() < deadline,
                "file output expectation budget exhausted"
            );
            let count = file.read(&mut chunk).context("read file output")?;
            if count == 0 {
                break;
            }
            ensure!(
                count <= expected.len().saturating_sub(offset)
                    && expected[offset..offset + count] == chunk[..count],
                "file output does not match its captured expectation"
            );
            offset += count;
        }
        ensure!(
            offset == expected.len(),
            "file output ended before captured expectation"
        );
        ensure!(
            super::same_file_version(&before, &file.metadata()?),
            "file output changed while checking its expectation"
        );
        return Ok(());
    }
    bail!("file output requires a nonempty relative path")
}

pub(super) fn discover(entries: &BTreeMap<PathBuf, Entry>) -> Result<Vec<PathBuf>> {
    Ok(inventory(entries)?.tests.into_keys().collect())
}

/// Read the execution bound from the same immutable manifest as the inventory.
/// Never consult an environment variable or recapture a mutable manifest.
pub(super) fn concurrency(snapshot: &Snapshot) -> Result<usize> {
    Ok(inventory(&snapshot.entries)?.max_concurrent_tests)
}

fn inventory(entries: &BTreeMap<PathBuf, Entry>) -> Result<Inventory> {
    // Capture deliberately does not descend through symlinks. Do not silently
    // ignore a manifest hidden behind a linked configuration directory.
    ensure!(
        !entries
            .get(Path::new(".franken-node"))
            .is_some_and(|entry| matches!(entry.data, EntryData::Link(_))),
        "migration test configuration directory must not be a symlink"
    );
    let Some(entry) = entries.get(Path::new(MANIFEST_PATH)) else {
        let tests: BTreeMap<_, _> = entries
            .iter()
            .filter(|(path, entry)| !matches!(entry.data, EntryData::Directory) && is_test(path))
            .map(|(path, _)| (path.clone(), TestSettings::default()))
            .collect();
        ensure!(
            tests.len() <= MAX_TESTS,
            "native validation test limit exceeded"
        );
        return Ok(Inventory {
            tests,
            max_concurrent_tests: 1,
        });
    };
    let EntryData::File(bytes) = &entry.data else {
        bail!("migration test manifest must be a regular captured file");
    };
    ensure!(
        bytes.len() <= MAX_MANIFEST_BYTES,
        "migration test manifest exceeds the 64 KiB limit"
    );
    let manifest: Manifest =
        serde_json::from_slice(bytes).context("invalid migration test manifest")?;
    ensure!(
        manifest.schema_version == MANIFEST_SCHEMA,
        "unsupported migration test manifest schema"
    );
    ensure!(
        (1..=MAX_CONCURRENT_TESTS).contains(&manifest.max_concurrent_tests),
        "max_concurrent_tests must be in 1..=4"
    );
    ensure!(
        !manifest.tests.is_empty(),
        "explicit migration test inventory must not be empty"
    );
    ensure!(
        manifest.tests.len() <= MAX_TESTS,
        "native validation test limit exceeded"
    );
    let mut selected = BTreeMap::new();
    for name in manifest.tests {
        let path = Path::new(&name);
        ensure!(
            !name.is_empty()
                && name.len() <= MAX_PATH_BYTES
                && !name.contains('\\')
                && !name.chars().any(char::is_control)
                && path
                    .components()
                    .all(|part| matches!(part, Component::Normal(_)))
                && path
                    .components()
                    .map(|part| part.as_os_str().to_string_lossy())
                    .collect::<Vec<_>>()
                    .join("/")
                    == name,
            "migration test paths must be canonical project-relative paths: {name:?}"
        );
        ensure!(
            !excluded_from_discovery(path),
            "migration test manifest cannot select dependencies, backups or reserved state: {name}"
        );
        ensure!(
            path.extension()
                .and_then(|extension| extension.to_str())
                .is_some_and(
                    |extension| ["js", "mjs", "cjs", "ts", "mts", "cts"].contains(&extension)
                ),
            "migration test manifest requires a standalone JS/TS entrypoint: {name}"
        );
        ensure!(
            matches!(
                entries.get(path).map(|entry| &entry.data),
                Some(EntryData::File(_))
            ),
            "migration test entrypoint is missing or is not a regular captured file: {name}"
        );
        ensure!(
            selected
                .insert(path.to_path_buf(), TestSettings::default())
                .is_none(),
            "duplicate migration test entrypoint: {name}"
        );
    }
    for (name, mut settings) in manifest.execution {
        let path = Path::new(&name);
        // Path equality can normalize interior ./ segments, so require exact
        // canonical spelling before looking up the already validated test.
        ensure!(
            !name.is_empty()
                && path
                    .components()
                    .all(|part| matches!(part, Component::Normal(_)))
                && name
                    == path
                        .components()
                        .map(|part| part.as_os_str().to_string_lossy())
                        .collect::<Vec<_>>()
                        .join("/"),
            "noncanonical execution test key"
        );
        let target = selected
            .get_mut(path)
            .context("execution settings refer to an unselected test")?;
        execution::validate(&mut settings, entries, path)?;
        target.execution = settings;
    }
    for (name, expectations) in manifest.expectations {
        let path = expectation_path(&name)?;
        let target = selected
            .get_mut(path)
            .context("output expectations refer to an unselected test")?;
        expectations.validate(entries)?;
        target.expectations = expectations;
    }
    Ok(Inventory {
        tests: selected,
        max_concurrent_tests: manifest.max_concurrent_tests,
    })
}

/// Identical test paths are not sufficient: a candidate cannot change the
/// input request, working directory or configuration that defines the test.
/// Used by live runs, checked preparation, imported capsules and reduction.
pub(super) fn matched_execution(original: &Snapshot, candidate: &Snapshot) -> Result<()> {
    let reference = inventory(&original.entries)?;
    let native = inventory(&candidate.entries)?;
    ensure!(
        reference == native,
        "test execution settings differ between original and candidate"
    );
    for settings in reference.tests.values() {
        ensure!(
            execution::input(&settings.execution, original)?
                == execution::input(&settings.execution, candidate)?,
            "captured test stdin bytes differ between original and candidate"
        );
        settings.expectations.matched(original, candidate)?;
    }
    Ok(())
}

pub(super) fn run_test(
    snapshot: &Snapshot,
    invocation: &Invocation,
    test: &Path,
    workspace: &Path,
    environment: &BTreeMap<OsString, OsString>,
    timing: (Duration, Duration),
) -> Result<Output> {
    run_test_cancellable(snapshot, invocation, test, workspace, environment, timing, None)
}

pub(super) fn run_test_cancellable(
    snapshot: &Snapshot,
    invocation: &Invocation,
    test: &Path,
    workspace: &Path,
    environment: &BTreeMap<OsString, OsString>,
    timing: (Duration, Duration),
    cancellation: Option<&super::smoke_supervisor::CancellationToken>,
) -> Result<Output> {
    if let Some(cancellation) = cancellation {
        cancellation.check()?;
    }
    let deadline = Instant::now()
        .checked_add(timing.0)
        .context("test execution deadline overflow")?;
    let tests = inventory(&snapshot.entries)?;
    let settings = tests.tests
        .get(test)
        .context("test is not present in the captured execution inventory")?;
    let output_workspace = settings.expectations.pin_workspace(workspace)?;
    let output = execution::run(
        snapshot,
        &settings.execution,
        test,
        invocation,
        workspace,
        environment,
        (deadline, timing.1, cancellation),
    )?;
    settings.expectations.check(snapshot, &output)?;
    settings
        .expectations
        .check_files(snapshot, output_workspace.as_ref(), deadline)?;
    if let Some(cancellation) = cancellation {
        cancellation.check()?;
    }
    Ok(output)
}

#[cfg(test)]
#[path = "test_expectations_tests.rs"]
mod expectation_tests;

#[cfg(test)]
#[path = "file_expectations_tests.rs"]
mod file_expectation_tests;

#[cfg(test)]
mod tests {
    use super::super::rewrite_candidate::{Replacement, RewriteCandidate};
    use super::super::{
        Invocation, Snapshot, execute_suite_pair, matched_tests, node_on_path, run_if_present,
    };
    use super::*;
    use std::fs;
    use std::os::unix::fs::symlink;
    use std::time::{Duration, Instant};

    fn write(root: &Path, name: &str, content: &str) {
        let path = root.join(name);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, content).unwrap();
    }

    fn manifest(root: &Path, tests: &[&str]) {
        write(
            root,
            MANIFEST_PATH,
            &serde_json::json!({
                "schema_version": MANIFEST_SCHEMA, "tests": tests,
            })
            .to_string(),
        );
    }

    #[test]
    fn concurrency_defaults_to_serial_and_requires_a_bounded_explicit_integer() {
        let root = tempfile::tempdir().unwrap();
        write(root.path(), "a.test.js", "console.log(42);");
        assert_eq!(concurrency(&snapshot(root.path())).unwrap(), 1);
        manifest(root.path(), &["a.test.js"]);
        assert_eq!(concurrency(&snapshot(root.path())).unwrap(), 1);
        for limit in 1..=MAX_CONCURRENT_TESTS {
            write(root.path(), MANIFEST_PATH, &format!(
                r#"{{"schema_version":"{MANIFEST_SCHEMA}","tests":["a.test.js"],"max_concurrent_tests":{limit}}}"#
            ));
            assert_eq!(concurrency(&snapshot(root.path())).unwrap(), limit);
        }
        for value in ["0", "5", "-1", "1.5", "null", "true", "\"2\"", "18446744073709551616"] {
            write(root.path(), MANIFEST_PATH, &format!(
                r#"{{"schema_version":"{MANIFEST_SCHEMA}","tests":["a.test.js"],"max_concurrent_tests":{value}}}"#
            ));
            assert!(discover(&snapshot(root.path()).entries).is_err(), "{value}");
        }
    }

    #[test]
    fn candidate_cannot_change_the_captured_concurrency_grant() {
        let original = tempfile::tempdir().unwrap();
        let candidate = tempfile::tempdir().unwrap();
        for root in [original.path(), candidate.path()] {
            write(root, "a.test.js", "console.log(42);");
            manifest(root, &["a.test.js"]);
        }
        let reference = snapshot(original.path());
        assert!(matched_tests(&reference, &snapshot(candidate.path())).is_ok());
        write(candidate.path(), MANIFEST_PATH, &format!(
            r#"{{"schema_version":"{MANIFEST_SCHEMA}","tests":["a.test.js"],"max_concurrent_tests":2}}"#
        ));
        assert!(matched_tests(&reference, &snapshot(candidate.path())).is_err());
        // Explicit one and an omitted bound have the same execution policy.
        write(candidate.path(), MANIFEST_PATH, &format!(
            r#"{{"schema_version":"{MANIFEST_SCHEMA}","tests":["a.test.js"],"max_concurrent_tests":1}}"#
        ));
        assert!(matched_tests(&reference, &snapshot(candidate.path())).is_ok());
    }

    #[test]
    fn concurrency_is_immutable_and_duplicate_grants_fail_closed() {
        let root = tempfile::tempdir().unwrap();
        write(root.path(), "a.test.js", "console.log(42);");
        write(root.path(), MANIFEST_PATH, &format!(
            r#"{{"schema_version":"{MANIFEST_SCHEMA}","tests":["a.test.js"],"max_concurrent_tests":3}}"#
        ));
        let captured = snapshot(root.path());
        manifest(root.path(), &["a.test.js"]);
        assert_eq!(concurrency(&captured).unwrap(), 3);
        assert_eq!(concurrency(&snapshot(root.path())).unwrap(), 1);
        assert_ne!(captured.digest, snapshot(root.path()).digest);
        write(root.path(), MANIFEST_PATH, &format!(
            r#"{{"schema_version":"{MANIFEST_SCHEMA}","tests":["a.test.js"],"max_concurrent_tests":1,"max_concurrent_tests":4}}"#
        ));
        assert!(discover(&snapshot(root.path()).entries).is_err());
    }

    fn snapshot(root: &Path) -> Snapshot {
        Snapshot::capture(root, Instant::now() + Duration::from_secs(60)).unwrap()
    }

    #[test]
    fn absent_manifest_preserves_discovery_including_an_empty_inventory() {
        let root = tempfile::tempdir().unwrap();
        assert!(discover(&snapshot(root.path()).entries).unwrap().is_empty());
        write(
            root.path(),
            "test/helper.js",
            "// previous discovery behavior",
        );
        write(root.path(), "z.test.js", "// discovered");
        write(
            root.path(),
            "scripts/check.js",
            "// not selected implicitly",
        );
        write(root.path(), "node_modules/vendor/a.test.js", "// excluded");
        assert_eq!(
            discover(&snapshot(root.path()).entries).unwrap(),
            [PathBuf::from("test/helper.js"), PathBuf::from("z.test.js")]
        );
    }

    #[test]
    fn explicit_monorepo_harnesses_are_sorted_without_implicit_helpers() {
        let root = tempfile::tempdir().unwrap();
        for name in [
            "packages/a/check.mjs",
            "packages/b/verify.cjs",
            "test/fixture.js",
        ] {
            write(root.path(), name, "// source");
        }
        manifest(
            root.path(),
            &["packages/b/verify.cjs", "packages/a/check.mjs"],
        );
        assert_eq!(
            discover(&snapshot(root.path()).entries).unwrap(),
            [
                PathBuf::from("packages/a/check.mjs"),
                PathBuf::from("packages/b/verify.cjs")
            ]
        );
    }

    #[test]
    fn invalid_manifests_never_fall_back_to_a_passing_heuristic_suite() {
        let root = tempfile::tempdir().unwrap();
        write(root.path(), "ok.test.js", "console.log('ok');");
        for raw in [
            "{",
            "null",
            "[]",
            r#"{"schema_version":"unknown/v2","tests":["ok.test.js"]}"#,
            r#"{"schema_version":"franken-node/migration-tests/v1","tests":[]}"#,
            r#"{"schema_version":"franken-node/migration-tests/v1"}"#,
            r#"{"schema_version":"franken-node/migration-tests/v1","tests":"ok.test.js"}"#,
            r#"{"schema_version":"franken-node/migration-tests/v1","tests":["ok.test.js"],"ignore_failures":true}"#,
            r#"{"schema_version":"franken-node/migration-tests/v1","tests":["ok.test.js"],"tests":[]}"#,
        ] {
            write(root.path(), MANIFEST_PATH, raw);
            assert!(discover(&snapshot(root.path()).entries).is_err(), "{raw}");
            assert!(run_if_present(root.path()).is_err(), "{raw}");
        }
    }

    #[test]
    fn duplicate_missing_unsupported_and_noncanonical_entries_are_rejected() {
        let root = tempfile::tempdir().unwrap();
        write(root.path(), "scripts/check.js", "console.log('ok');");
        write(root.path(), "scripts/check.txt", "not a program");
        for name in [
            "",
            "../check.js",
            "/check.js",
            "./scripts/check.js",
            "scripts//check.js",
            "scripts/../scripts/check.js",
            "scripts/check.js/",
            "scripts\\check.js",
            "scripts/check\n.js",
            "missing.js",
            "scripts/check.txt",
        ] {
            manifest(root.path(), &[name]);
            assert!(
                discover(&snapshot(root.path()).entries).is_err(),
                "{name:?}"
            );
        }
        manifest(root.path(), &["scripts/check.js", "scripts/check.js"]);
        assert!(
            discover(&snapshot(root.path()).entries)
                .unwrap_err()
                .to_string()
                .contains("duplicate")
        );
    }

    #[test]
    fn vendor_tests_and_reserved_metadata_cannot_be_selected_explicitly() {
        let root = tempfile::tempdir().unwrap();
        for name in [
            "node_modules/vendor/run.js",
            ".franken-node/run.js",
            ".migrate-backup/run.js",
            "packages/a/node_modules/vendor/run.js",
            "packages/a/.git/run.js",
        ] {
            write(root.path(), name, "console.log('excluded');");
            manifest(root.path(), &[name]);
            assert!(discover(&snapshot(root.path()).entries).is_err(), "{name}");
        }
    }

    #[test]
    fn symlinked_manifest_directory_manifest_and_entrypoint_are_refused() {
        let root = tempfile::tempdir().unwrap();
        write(root.path(), "scripts/check.js", "console.log('ok');");
        symlink("check.js", root.path().join("scripts/link.js")).unwrap();
        manifest(root.path(), &["scripts/link.js"]);
        assert!(discover(&snapshot(root.path()).entries).is_err());

        let root = tempfile::tempdir().unwrap();
        write(
            root.path(),
            "config/manifest.json",
            r#"{"schema_version":"franken-node/migration-tests/v1","tests":["ok.test.js"]}"#,
        );
        write(root.path(), "ok.test.js", "console.log('ok');");
        fs::create_dir(root.path().join(".franken-node")).unwrap();
        symlink("../config/manifest.json", root.path().join(MANIFEST_PATH)).unwrap();
        assert!(discover(&snapshot(root.path()).entries).is_err());

        let root = tempfile::tempdir().unwrap();
        write(root.path(), "config/migration-tests.json", "{}");
        write(root.path(), "ok.test.js", "console.log('ok');");
        symlink("config", root.path().join(".franken-node")).unwrap();
        assert!(discover(&snapshot(root.path()).entries).is_err());
    }

    #[test]
    fn manifest_size_and_inventory_limits_fail_closed() {
        let root = tempfile::tempdir().unwrap();
        write(
            root.path(),
            MANIFEST_PATH,
            &" ".repeat(MAX_MANIFEST_BYTES + 1),
        );
        assert!(
            discover(&snapshot(root.path()).entries)
                .unwrap_err()
                .to_string()
                .contains("64 KiB")
        );
        write(root.path(), "a.js", "console.log('ok');");
        manifest(root.path(), &vec!["a.js"; MAX_TESTS + 1]);
        assert!(
            discover(&snapshot(root.path()).entries)
                .unwrap_err()
                .to_string()
                .contains("test limit")
        );
    }

    #[test]
    fn captured_manifest_and_selected_files_survive_source_tree_changes() {
        let root = tempfile::tempdir().unwrap();
        write(root.path(), "scripts/check.js", "console.log('captured');");
        manifest(root.path(), &["scripts/check.js"]);
        let captured = snapshot(root.path());
        manifest(root.path(), &["missing.js"]);
        write(root.path(), "scripts/check.js", "process.exit(99);");
        assert_eq!(
            discover(&captured.entries).unwrap(),
            [PathBuf::from("scripts/check.js")]
        );
        assert_ne!(captured.digest, snapshot(root.path()).digest);
    }

    #[test]
    fn candidate_manifest_cannot_drop_or_substitute_reference_test_counterparts() {
        let original = tempfile::tempdir().unwrap();
        let candidate = tempfile::tempdir().unwrap();
        for root in [original.path(), candidate.path()] {
            write(root, "scripts/a.js", "console.log('a');");
            write(root, "scripts/b.js", "console.log('b');");
        }
        manifest(original.path(), &["scripts/a.js"]);
        manifest(candidate.path(), &["scripts/b.js"]);
        assert!(matched_tests(&snapshot(original.path()), &snapshot(candidate.path())).is_err());
        manifest(original.path(), &["scripts/a.js", "scripts/b.js"]);
        assert!(matched_tests(&snapshot(original.path()), &snapshot(candidate.path())).is_err());
    }

    // These are real Node/Node runs of the production orchestrator, NOT claims
    // of native Franken compatibility or third-party test-framework support.
    #[test]
    fn explicit_harnesses_execute_without_running_fixture_helpers() {
        let root = tempfile::tempdir().unwrap();
        write(root.path(), "packages/a/check.js", "console.log('a');");
        write(root.path(), "packages/b/verify.cjs", "console.log('b');");
        write(
            root.path(),
            "test/fixture.js",
            "throw new Error('helper is not an entrypoint');",
        );
        manifest(
            root.path(),
            &["packages/b/verify.cjs", "packages/a/check.js"],
        );
        let captured = snapshot(root.path());
        let node = Invocation {
            executable: node_on_path().unwrap(),
            before: vec![],
            after: vec![],
        };
        let report = execute_suite_pair(
            &captured,
            &captured,
            &node,
            &node,
            Instant::now() + Duration::from_secs(90),
            Duration::from_secs(5),
            true,
        )
        .unwrap();
        assert_eq!(report.verdict, "PASS", "{report:#?}");
        assert_eq!((report.total_tests, report.passed), (2, 2));
        assert_eq!(
            report
                .cases
                .iter()
                .map(|row| row.test.as_str())
                .collect::<Vec<_>>(),
            ["packages/a/check.js", "packages/b/verify.cjs"]
        );
        assert!(!report.release_certification);
    }

    #[test]
    fn a_selected_failing_harness_is_not_omitted_or_downgraded_to_smoke() {
        let root = tempfile::tempdir().unwrap();
        write(root.path(), "scripts/check.js", "process.exit(7);");
        manifest(root.path(), &["scripts/check.js"]);
        let captured = snapshot(root.path());
        let node = Invocation {
            executable: node_on_path().unwrap(),
            before: vec![],
            after: vec![],
        };
        let report = execute_suite_pair(
            &captured,
            &captured,
            &node,
            &node,
            Instant::now() + Duration::from_secs(90),
            Duration::from_secs(5),
            true,
        )
        .unwrap();
        assert_eq!(report.verdict, "FAIL");
        assert_eq!(
            (report.total_tests, report.failed, report.skipped),
            (1, 1, 0)
        );
        assert_eq!(
            report.cases[0].reference.as_ref().unwrap().exit_code,
            Some(7)
        );
        assert_eq!(report.cases[0].native.as_ref().unwrap().exit_code, Some(7));
    }

    #[test]
    fn checked_candidates_use_the_manifest_without_heuristic_test_names() {
        let root = tempfile::tempdir().unwrap();
        write(root.path(), "scripts/check.js", "console.log(42);");
        manifest(root.path(), &["scripts/check.js"]);
        let mut candidate =
            RewriteCandidate::capture(root.path(), Instant::now() + Duration::from_secs(90))
                .unwrap();
        candidate
            .prepare(&[Replacement {
                path: "scripts/check.js",
                before: b"console.log(42);",
                after: b"console.log(6*7);",
            }])
            .unwrap();
        let report = candidate.validate_node_pair().unwrap();
        candidate.check_validation(&report).unwrap();
        assert_eq!(report.cases[0].test, "scripts/check.js");
        assert_ne!(report.input_sha256, report.candidate_input_sha256);
        candidate.ensure_source_unchanged().unwrap();
        let raw = fs::read(root.path().join(MANIFEST_PATH)).unwrap();
        assert!(
            candidate
                .prepare(&[Replacement {
                    path: MANIFEST_PATH,
                    before: &raw,
                    after: b"{}"
                }])
                .unwrap_err()
                .to_string()
                .contains("reserved metadata")
        );
    }
}

/// Bounded, ordered case execution. Keeping the scheduler beside the captured
/// settings also binds its implementation into the existing replay source hash.
mod scheduler {
    use super::MAX_CONCURRENT_TESTS;
    use anyhow::{Result, ensure};
    use std::thread;
    use std::time::Instant;

    pub(in super::super) struct Scheduled<T> {
        pub(in super::super) rows: Vec<T>,
        pub(in super::super) errors: Vec<String>,
    }

    /// Each task owns a complete case, whose runtime legs remain sequential.
    /// Tasks borrow immutable captures and must enforce the original deadline;
    /// the scheduler never grants a fresh time allowance. Batches bound active
    /// work and preserve inventory order independent of completion order.
    pub(in super::super) fn run_scheduled<T: Sync, R: Send>(
        items: &[T],
        concurrency: usize,
        deadline: Instant,
        task: impl Fn(&T) -> Result<R> + Sync,
    ) -> Result<Scheduled<R>> {
        ensure!(
            (1..=MAX_CONCURRENT_TESTS).contains(&concurrency),
            "max_concurrent_tests must be in 1..=4"
        );
        let mut completed = Scheduled {
            rows: Vec::new(),
            errors: Vec::new(),
        };
        for batch in items.chunks(concurrency) {
            if Instant::now() >= deadline {
                completed.errors.push("native validation total budget exhausted".into());
                break;
            }
            if concurrency == 1 {
                // No thread or scheduling change for existing serial suites.
                match task(&batch[0]) {
                    Ok(row) => completed.rows.push(row),
                    Err(error) => completed.errors.push(format!("test scheduling failed: {error:#}")),
                }
            } else {
                thread::scope(|scope| {
                    let mut handles = Vec::with_capacity(batch.len());
                    let mut launch_error = None;
                    for item in batch {
                        if Instant::now() >= deadline {
                            launch_error = Some("native validation total budget exhausted".into());
                            break;
                        }
                        let task = &task;
                        match thread::Builder::new()
                            .name("franken-validation-case".into())
                            .spawn_scoped(scope, move || task(item))
                        {
                            Ok(handle) => handles.push(handle),
                            Err(error) => {
                                launch_error = Some(format!("cannot start validation worker: {error}"));
                                break;
                            }
                        }
                    }
                    // Always join all started workers, even after a launch
                    // failure or worker panic. A panic becomes an incomplete
                    // suite, never a fabricated row or a detached process.
                    for handle in handles {
                        match handle.join() {
                            Ok(Ok(row)) => completed.rows.push(row),
                            Ok(Err(error)) => completed.errors.push(format!("test scheduling failed: {error:#}")),
                            Err(_) => completed.errors.push("validation worker panicked; incomplete suite".into()),
                        }
                    }
                    if let Some(error) = launch_error {
                        completed.errors.push(error);
                    }
                });
            }
            if !completed.errors.is_empty() {
                break;
            }
        }
        Ok(completed)
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::{Condvar, Mutex};
        use std::time::Duration;

        fn deadline() -> Instant {
            Instant::now() + Duration::from_secs(30)
        }

        #[test]
        fn serial_default_uses_the_caller_thread_and_inventory_order() {
            let caller = thread::current().id();
            let seen = Mutex::new(Vec::new());
            let result = run_scheduled(&[0, 1, 2], 1, deadline(), |item| {
                assert_eq!(thread::current().id(), caller);
                seen.lock().unwrap().push(*item);
                Ok(*item)
            }).unwrap();
            assert_eq!(result.rows, [0, 1, 2]);
            assert_eq!(*seen.lock().unwrap(), [0, 1, 2]);
            assert!(result.errors.is_empty());
        }

        #[test]
        fn cases_actually_overlap_but_results_keep_inventory_order() {
            // A bounded handshake proves overlap without a timing speedup
            // assertion. Serial dispatch cannot satisfy the first case.
            let second_finished = (Mutex::new(false), Condvar::new());
            let result = run_scheduled(&[0, 1], 2, deadline(), |item| {
                if *item == 0 {
                    let (finished, _) = second_finished.1.wait_timeout_while(
                        second_finished.0.lock().unwrap(),
                        Duration::from_secs(5),
                        |finished| !*finished,
                    ).unwrap();
                    ensure!(*finished, "second case did not overlap the first");
                } else {
                    *second_finished.0.lock().unwrap() = true;
                    second_finished.1.notify_all();
                }
                Ok(*item)
            }).unwrap();
            assert_eq!(result.rows, [0, 1]);
            assert!(result.errors.is_empty(), "{:?}", result.errors);
        }

        #[test]
        fn concurrency_is_bounded_and_every_case_executes_once() {
            let active = AtomicUsize::new(0);
            let peak = AtomicUsize::new(0);
            let seen: Vec<AtomicUsize> = (0..17).map(|_| AtomicUsize::new(0)).collect();
            let items: Vec<usize> = (0..seen.len()).collect();
            let result = run_scheduled(&items, 4, deadline(), |item| {
                let count = active.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(count, Ordering::SeqCst);
                seen[*item].fetch_add(1, Ordering::SeqCst);
                thread::yield_now();
                active.fetch_sub(1, Ordering::SeqCst);
                Ok(*item)
            }).unwrap();
            assert_eq!(result.rows, items);
            assert!(result.errors.is_empty());
            assert!((1..=4).contains(&peak.load(Ordering::SeqCst)));
            assert_eq!(active.load(Ordering::SeqCst), 0);
            assert!(seen.iter().all(|count| count.load(Ordering::SeqCst) == 1));
        }

        #[test]
        fn a_failed_worker_retains_other_results_and_stops_later_batches() {
            let seen = Mutex::new(Vec::new());
            let result = run_scheduled(&[0, 1, 2, 3], 2, deadline(), |item| {
                seen.lock().unwrap().push(*item);
                ensure!(*item != 0, "case setup failed");
                Ok(*item)
            }).unwrap();
            assert_eq!(result.rows, [1]);
            assert_eq!(result.errors.len(), 1);
            assert!(result.errors[0].contains("case setup failed"));
            let mut seen = seen.into_inner().unwrap();
            seen.sort();
            assert_eq!(seen, [0, 1]);
        }

        #[test]
        fn a_panicked_worker_is_joined_without_erasing_its_peers() {
            let finished = AtomicUsize::new(0);
            let result = run_scheduled(&[0, 1, 2, 3], 2, deadline(), |item| {
                if *item == 0 {
                    panic!("injected worker panic");
                }
                finished.fetch_add(1, Ordering::SeqCst);
                Ok(*item)
            }).unwrap();
            assert_eq!(result.rows, [1]);
            assert_eq!(finished.load(Ordering::SeqCst), 1);
            assert_eq!(result.errors, ["validation worker panicked; incomplete suite"]);
        }

        #[test]
        fn invalid_limits_and_expired_budgets_never_dispatch_a_task() {
            let calls = AtomicUsize::new(0);
            for limit in [0, MAX_CONCURRENT_TESTS + 1, usize::MAX] {
                assert!(run_scheduled(&[0], limit, deadline(), |_| {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                }).is_err());
            }
            for limit in [1, 4] {
                let result = run_scheduled(&[0, 1], limit, Instant::now(), |_| {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                }).unwrap();
                assert!(result.rows.is_empty());
                assert_eq!(result.errors, ["native validation total budget exhausted"]);
            }
            assert_eq!(calls.load(Ordering::SeqCst), 0);
        }
    }
}
