//! Test selection and execution settings from captured inputs, never the
//! mutable source tree. Invalid manifests fail closed without heuristic fallback.

use super::{
    Entry, EntryData, Invocation, MAX_PATH_BYTES, MAX_TESTS, Snapshot, excluded_from_discovery,
    is_test,
};
use anyhow::{Context, Result, bail, ensure};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Component, Path, PathBuf};
use std::process::Output;
use std::time::{Duration, Instant};

#[path = "test_execution.rs"]
mod execution;

const MANIFEST_PATH: &str = ".franken-node/migration-tests.json";
const MANIFEST_SCHEMA: &str = "franken-node/migration-tests/v1";
const MAX_MANIFEST_BYTES: usize = 64 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema_version: String,
    tests: Vec<String>,
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
}

fn expectation_field<'de, D>(deserializer: D) -> std::result::Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    String::deserialize(deserializer).map(Some)
}

const MAX_EXPECTATION_BYTES: usize = 1024 * 1024;

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
        [("stdout", self.stdout.as_deref()), ("stderr", self.stderr.as_deref())]
            .into_iter()
            .filter_map(|(stream, path)| path.map(|path| (stream, path)))
    }

    fn validate(&self, entries: &BTreeMap<PathBuf, Entry>) -> Result<()> {
        ensure!(
            self.stdout.is_some() || self.stderr.is_some(),
            "explicit output expectations must not be empty"
        );
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
}

pub(super) fn discover(entries: &BTreeMap<PathBuf, Entry>) -> Result<Vec<PathBuf>> {
    Ok(inventory(entries)?.into_keys().collect())
}

fn inventory(entries: &BTreeMap<PathBuf, Entry>) -> Result<BTreeMap<PathBuf, TestSettings>> {
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
        return Ok(tests);
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
    Ok(selected)
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
    for settings in reference.values() {
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
    let deadline = Instant::now()
        .checked_add(timing.0)
        .context("test execution deadline overflow")?;
    let tests = inventory(&snapshot.entries)?;
    let settings = tests
        .get(test)
        .context("test is not present in the captured execution inventory")?;
    let output = execution::run(
        snapshot,
        &settings.execution,
        test,
        invocation,
        workspace,
        environment,
        (deadline, timing.1),
    )?;
    settings.expectations.check(snapshot, &output)?;
    Ok(output)
}

#[cfg(test)]
#[path = "test_expectations_tests.rs"]
mod expectation_tests;

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
