//! Execution-backed project test validation for the native migration command.
//!
//! Both runtimes receive fresh copies of one bounded input capture for EACH
//! case. Only successful exits and exact stdout/stderr bytes establish a pass.
//! This is a process-output comparison, not filesystem-effect equivalence,
//! release certification, deterministic replay, or an OS sandbox. Trusted code
//! can still access ambient credentials, absolute paths and external services.

use super::smoke_supervisor;
use anyhow::{Context, Result, bail, ensure};
use rustix::fs::{Mode, OFlags, open};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs::{self, File, Metadata};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::os::unix::process::ExitStatusExt;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Output};
use std::time::{Duration, Instant};

const MAX_ENTRIES: usize = 50_000;
const MAX_PROJECT_BYTES: usize = 256 * 1024 * 1024;
const MAX_TESTS: usize = 1024;
const MAX_PATH_BYTES: usize = 4096;
const MAX_EXECUTABLE_BYTES: u64 = 512 * 1024 * 1024;
const TOTAL_TIMEOUT: Duration = Duration::from_secs(300);
const LEG_TIMEOUT: Duration = Duration::from_secs(30);
const DRAIN_TIMEOUT: Duration = Duration::from_secs(1);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamObservation {
    pub bytes: usize,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunObservation {
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
    pub stdout: StreamObservation,
    pub stderr: StreamObservation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TestCaseResult {
    pub test: String,
    pub status: String,
    pub reference: Option<RunObservation>,
    pub native: Option<RunObservation>,
    pub divergences: Vec<String>,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeIdentity {
    pub executable: PathBuf,
    pub sha256: String,
    pub arguments_before_test: Vec<OsString>,
    pub arguments_after_test: Vec<OsString>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SuiteReport {
    pub schema_version: String,
    pub scope: String,
    pub release_certification: bool,
    pub input_sha256: String,
    pub reference_runtime: RuntimeIdentity,
    pub native_runtime: RuntimeIdentity,
    pub total_tests: usize,
    pub passed: usize,
    pub failed: usize,
    pub errored: usize,
    pub skipped: usize,
    pub verdict: String,
    pub cases: Vec<TestCaseResult>,
    pub errors: Vec<String>,
}

#[derive(Clone)]
enum EntryData {
    Directory,
    File(Vec<u8>),
    Link(PathBuf),
}

#[derive(Clone)]
struct Entry {
    mode: u32,
    data: EntryData,
}

struct Snapshot {
    entries: BTreeMap<PathBuf, Entry>,
    digest: String,
}

fn budget(deadline: Instant) -> Result<()> {
    ensure!(Instant::now() < deadline, "native validation total budget exhausted");
    Ok(())
}

fn excluded_from_discovery(path: &Path) -> bool {
    path.components().any(|part| matches!(part, Component::Normal(name)
        if ["node_modules", ".git", ".migrate-backup", ".franken-node"].iter().any(|skip| name == *skip)))
}

fn is_test(path: &Path) -> bool {
    if excluded_from_discovery(path) {
        return false;
    }
    let name = path.file_name().and_then(|name| name.to_str()).unwrap_or("");
    let extension = path.extension().and_then(|ext| ext.to_str()).unwrap_or("");
    let supported = ["js", "mjs", "cjs", "ts", "mts", "cts"].contains(&extension);
    supported && (name.strip_suffix(extension).is_some_and(|stem|
        stem.ends_with(".test.") || stem.ends_with(".spec."))
        || path.parent().is_some_and(|parent| parent.components().any(|part|
            matches!(part, Component::Normal(name) if name == "test" || name == "__tests__"))))
}

fn same_file_version(left: &Metadata, right: &Metadata) -> bool {
    left.dev() == right.dev() && left.ino() == right.ino()
        && left.size() == right.size() && left.mode() == right.mode()
        && left.mtime() == right.mtime() && left.mtime_nsec() == right.mtime_nsec()
        && left.ctime() == right.ctime() && left.ctime_nsec() == right.ctime_nsec()
}

fn open_regular(path: &Path) -> Result<File> {
    let file = File::from(open(path, OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty()).with_context(|| format!("open {}", path.display()))?);
    ensure!(file.metadata()?.is_file(), "nonregular input: {}", path.display());
    Ok(file)
}

// Preserve relative link chains, including retargetable intermediate links.
// Absolute internal links are made relative to the captured project root.
fn captured_link(root: &Path, path: &Path) -> Result<PathBuf> {
    let resolved = path.canonicalize()?;
    let relative = resolved.strip_prefix(root).context("external workspace symlink refused")?;
    ensure!(!relative.components().any(|part| part.as_os_str() == ".git"), "link into excluded .git refused");
    let raw = fs::read_link(path)?;
    let parent = path.parent().context("symlink parent missing")?;
    let mut lexical = PathBuf::new();
    for part in parent.join(&raw).components() {
        match part {
            Component::ParentDir => { ensure!(lexical.pop(), "symlink escapes filesystem root"); }
            Component::CurDir => {}
            _ => lexical.push(part.as_os_str()),
        }
    }
    let target = lexical.strip_prefix(root).context("external lexical symlink refused")?;
    ensure!(!target.components().any(|part| part.as_os_str() == ".git"), "link into excluded .git refused");
    if raw.is_relative() {
        return Ok(raw);
    }
    let mut rebased = PathBuf::new();
    for _ in parent.strip_prefix(root)?.components() { rebased.push(".."); }
    rebased.push(target);
    Ok(rebased)
}

impl Snapshot {
    fn capture(root: &Path, deadline: Instant) -> Result<Self> {
        let root = root.canonicalize()?;
        ensure!(root.is_dir(), "native validation project must be a directory");
        let mut entries = BTreeMap::new();
        let mut pending = vec![root.clone()];
        let mut total_bytes = 0_usize;
        while let Some(directory) = pending.pop() {
            budget(deadline)?;
            for item in fs::read_dir(directory)? {
                budget(deadline)?;
                let path = item?.path();
                if path.file_name().is_some_and(|name| name == ".git") { continue; }
                ensure!(entries.len() < MAX_ENTRIES, "native validation entry limit exceeded");
                let relative = path.strip_prefix(&root)?.to_path_buf();
                let text = relative.to_str().context("non-UTF-8 workspace path refused")?;
                ensure!(text.len() <= MAX_PATH_BYTES, "workspace path too long");
                let metadata = fs::symlink_metadata(&path)?;
                let data = if metadata.is_symlink() {
                    EntryData::Link(captured_link(&root, &path)?)
                } else if metadata.is_dir() {
                    pending.push(path.clone());
                    EntryData::Directory
                } else if metadata.is_file() {
                    ensure!(metadata.nlink() == 1, "hard-linked workspace files require explicit isolation");
                    let mut file = open_regular(&path)?;
                    let before = file.metadata()?;
                    ensure!(same_file_version(&metadata, &before), "input changed before capture");
                    let remaining = MAX_PROJECT_BYTES - total_bytes;
                    ensure!(before.len() <= remaining as u64, "native validation input byte limit exceeded");
                    let mut bytes = Vec::new();
                    let mut chunk = [0_u8; 65536];
                    loop {
                        budget(deadline)?;
                        let request = chunk.len().min(remaining.saturating_sub(bytes.len()).saturating_add(1));
                        let read = file.read(&mut chunk[..request])?;
                        if read == 0 { break; }
                        ensure!(bytes.len() + read <= remaining, "native validation input byte limit exceeded");
                        bytes.extend_from_slice(&chunk[..read]);
                    }
                    ensure!(same_file_version(&before, &file.metadata()?), "input changed during capture");
                    total_bytes += bytes.len();
                    EntryData::File(bytes)
                } else {
                    bail!("nonregular workspace input refused: {}", relative.display());
                };
                entries.insert(relative, Entry { mode: metadata.mode() & 0o777, data });
            }
        }
        let mut hash = Sha256::new();
        hash.update(b"franken-node/native-validation-input/v1\0");
        for (path, entry) in &entries {
            let (kind, bytes) = match &entry.data {
                EntryData::Directory => (b'd', &b""[..]),
                EntryData::File(bytes) => (b'f', bytes.as_slice()),
                EntryData::Link(target) => (b'l', target.as_os_str().as_encoded_bytes()),
            };
            for part in [path.as_os_str().as_encoded_bytes(), &entry.mode.to_le_bytes(), &[kind], bytes] {
                hash.update((part.len() as u64).to_le_bytes());
                hash.update(part);
            }
        }
        Ok(Self { entries, digest: format!("{:x}", hash.finalize()) })
    }

    fn tests(&self) -> Result<Vec<PathBuf>> {
        let tests: Vec<_> = self.entries.iter().filter(|(path, entry)|
            !matches!(entry.data, EntryData::Directory) && is_test(path)).map(|(path, _)| path.clone()).collect();
        ensure!(tests.len() <= MAX_TESTS, "native validation test limit exceeded");
        Ok(tests)
    }

    fn stage(&self, destination: &Path, deadline: Instant) -> Result<()> {
        fs::create_dir(destination)?;
        for (relative, entry) in &self.entries {
            budget(deadline)?;
            let path = destination.join(relative);
            match &entry.data {
                EntryData::Directory => fs::create_dir(path)?,
                EntryData::File(bytes) => {
                    fs::write(&path, bytes)?;
                    fs::set_permissions(path, fs::Permissions::from_mode(entry.mode))?;
                }
                EntryData::Link(target) => symlink(target, path)?,
            }
        }
        for (relative, entry) in self.entries.iter().rev() {
            if matches!(entry.data, EntryData::Directory) {
                fs::set_permissions(destination.join(relative), fs::Permissions::from_mode(entry.mode))?;
            }
        }
        Ok(())
    }
}

#[derive(Clone)]
struct Invocation {
    executable: PathBuf,
    before: Vec<OsString>,
    after: Vec<OsString>,
}

impl Invocation {
    fn identity(&self, deadline: Instant) -> Result<RuntimeIdentity> {
        let mut file = open_regular(&self.executable)?;
        let before = file.metadata()?;
        ensure!(before.len() <= MAX_EXECUTABLE_BYTES, "runtime binary too large");
        let mut hash = Sha256::new();
        let mut total = 0_u64;
        let mut buffer = [0_u8; 65536];
        loop {
            budget(deadline)?;
            let count = file.read(&mut buffer)?;
            if count == 0 { break; }
            total += count as u64;
            ensure!(total <= MAX_EXECUTABLE_BYTES, "runtime binary grew beyond limit");
            hash.update(&buffer[..count]);
        }
        ensure!(same_file_version(&before, &file.metadata()?), "runtime binary changed during hashing");
        Ok(RuntimeIdentity { executable: self.executable.clone(), sha256: format!("{:x}", hash.finalize()),
            arguments_before_test: self.before.clone(), arguments_after_test: self.after.clone() })
    }

    fn command(&self, test: &Path, workspace: &Path, environment: &BTreeMap<OsString, OsString>) -> Command {
        let mut command = Command::new(&self.executable);
        command.args(&self.before).arg(Path::new(".").join(test)).args(&self.after)
            .current_dir(workspace).env_clear().envs(environment)
            .env_remove("FRANKEN_NODE_ALLOW_DEGRADED_RUNTIME_FALLBACK");
        command
    }
}

fn node_on_path() -> Result<PathBuf> {
    for directory in std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default()) {
        // Never search a staged project or an implicit current-directory PATH.
        if !directory.is_absolute() { continue; }
        let candidate = directory.join("node");
        if let Ok(metadata) = fs::metadata(&candidate)
            && metadata.is_file() && metadata.mode() & 0o111 != 0 {
            return candidate.canonicalize().context("resolve reference Node executable");
        }
    }
    bail!("project test validation requires Node on an absolute PATH entry; native success alone is not equivalence")
}

fn observe(output: &Output) -> RunObservation {
    let stream = |bytes: &[u8]| StreamObservation { bytes: bytes.len(), sha256: format!("{:x}", Sha256::digest(bytes)) };
    RunObservation { exit_code: output.status.code(), signal: output.status.signal(),
        stdout: stream(&output.stdout), stderr: stream(&output.stderr) }
}

fn execute_suite(snapshot: &Snapshot, reference: &Invocation, native: &Invocation,
    deadline: Instant, leg_timeout: Duration) -> Result<SuiteReport> {
    let tests = snapshot.tests()?;
    ensure!(!tests.is_empty(), "empty test suite cannot pass");
    let mut report = SuiteReport {
        schema_version: "franken-node/native-validation-suite/v1".into(),
        scope: "captured-test-process-stdout-stderr-exit".into(), release_certification: false,
        input_sha256: snapshot.digest.clone(), reference_runtime: reference.identity(deadline)?,
        native_runtime: native.identity(deadline)?, total_tests: tests.len(), passed: 0, failed: 0,
        errored: 0, skipped: tests.len(), verdict: "ERROR".into(), cases: Vec::new(), errors: Vec::new(),
    };
    let environment = std::env::vars_os().collect();
    for test in tests {
        if let Err(error) = budget(deadline) { report.errors.push(error.to_string()); break; }
        let mut row = TestCaseResult { test: test.to_string_lossy().into_owned(), status: "ERROR".into(),
            reference: None, native: None, divergences: Vec::new(), errors: Vec::new() };
        let result = (|| -> Result<()> {
            let case = tempfile::Builder::new().prefix("franken-native-validation-").tempdir()?;
            let mut outputs = Vec::new();
            for (name, invocation) in [("reference", reference), ("native", native)] {
                let workspace = case.path().join(name);
                snapshot.stage(&workspace, deadline)?;
                ensure!(workspace.join(&test).is_file(), "discovered test is not a file");
                budget(deadline)?;
                let timeout = leg_timeout.min(deadline.saturating_duration_since(Instant::now()));
                let output = smoke_supervisor::run_command_with_timeout(
                    &mut invocation.command(&test, &workspace, &environment), timeout, DRAIN_TIMEOUT)
                    .with_context(|| format!("{name} execution failed"))?;
                let observation = observe(&output);
                if name == "reference" { row.reference = Some(observation); } else { row.native = Some(observation); }
                if !output.status.success() { row.divergences.push(format!("{name}:unsuccessful_exit")); }
                outputs.push(output);
            }
            if outputs[0].stdout != outputs[1].stdout { row.divergences.push("stdout:byte_mismatch".into()); }
            if outputs[0].stderr != outputs[1].stderr { row.divergences.push("stderr:byte_mismatch".into()); }
            Ok(())
        })();
        report.skipped -= 1;
        match result {
            Err(error) => { row.errors.push(format!("{error:#}")); report.errored += 1; }
            Ok(()) if row.divergences.is_empty() => { row.status = "PASS".into(); report.passed += 1; }
            Ok(()) => { row.status = "FAIL".into(); report.failed += 1; }
        }
        report.cases.push(row);
    }
    // Identity checks after execution are mandatory, even when all cases agree.
    for (invocation, before) in [(reference, &report.reference_runtime), (native, &report.native_runtime)] {
        match invocation.identity(deadline) {
            Ok(after) if &after == before => {}
            Ok(_) => report.errors.push("runtime executable changed during validation".into()),
            Err(error) => report.errors.push(format!("runtime identity recheck failed: {error:#}")),
        }
    }
    report.verdict = if report.errored > 0 || report.skipped > 0 || !report.errors.is_empty() { "ERROR" }
        else if report.failed > 0 { "FAIL" } else { "PASS" }.into();
    Ok(report)
}

/// Called by native `migrate validate` after static admission. No tests retains
/// the existing entrypoint smoke behavior; discovered tests may never fall back
/// to a smoke PASS after a missing reference, capture failure or test failure.
pub fn run_if_present(project: &Path) -> Result<Option<SuiteReport>> {
    let deadline = Instant::now() + TOTAL_TIMEOUT;
    let snapshot = Snapshot::capture(project, deadline)?;
    if snapshot.tests()?.is_empty() { return Ok(None); }
    run_captured(project, &snapshot, &std::env::current_exe()?, deadline).map(Some)
}

/// Execute a nonempty captured project suite using an explicitly selected
/// native product binary. This also supports independent CLI/library callers
/// without incorrectly re-executing their own embedding process as a runtime.
pub fn run_project(project: &Path, native_executable: &Path) -> Result<SuiteReport> {
    let deadline = Instant::now() + TOTAL_TIMEOUT;
    let snapshot = Snapshot::capture(project, deadline)?;
    ensure!(!snapshot.tests()?.is_empty(), "no tests discovered; an empty suite cannot pass");
    run_captured(project, &snapshot, native_executable, deadline)
}

fn run_captured(project: &Path, snapshot: &Snapshot, native_executable: &Path,
    deadline: Instant) -> Result<SuiteReport> {
    let executable = native_executable.canonicalize()?;
    let native = Invocation { executable: executable.clone(), before: vec!["run".into()],
        after: vec!["--runtime".into(), "franken-engine".into(), "--engine-bin".into(),
            executable.into_os_string(), "--console-only".into()] };
    let reference = Invocation { executable: node_on_path()?, before: vec![], after: vec![] };
    ensure!(!reference.executable.starts_with(project.canonicalize()?), "reference runtime must be outside the measured project");
    ensure!(!native.executable.starts_with(project.canonicalize()?), "native runtime must be outside the measured project");
    execute_suite(snapshot, &reference, &native, deadline, LEG_TIMEOUT)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> tempfile::TempDir {
        tempfile::tempdir().expect("project")
    }

    fn write(root: &Path, path: &str, source: &str) {
        let path = root.join(path);
        fs::create_dir_all(path.parent().expect("parent")).expect("directories");
        fs::write(path, source).expect("source");
    }

    fn node(candidate: bool) -> Invocation {
        Invocation { executable: node_on_path().expect("real Node required"), before: Vec::new(),
            after: if candidate { vec!["candidate".into()] } else { Vec::new() } }
    }

    fn measured(root: &Path) -> SuiteReport {
        let deadline = Instant::now() + Duration::from_secs(20);
        let snapshot = Snapshot::capture(root, deadline).expect("capture");
        execute_suite(&snapshot, &node(false), &node(true), deadline, Duration::from_secs(3)).expect("execute")
    }

    // All process tests name real Node executables for BOTH roles. They prove
    // the production orchestrator, not native Franken compatibility.
    #[test]
    fn matching_real_processes_have_complete_nonempty_evidence() {
        let project = fixture();
        write(project.path(), "ok.test.js", "console.log('ok');");
        let report = measured(project.path());
        assert_eq!(report.verdict, "PASS");
        assert_eq!((report.total_tests, report.passed, report.failed, report.errored, report.skipped), (1, 1, 0, 0, 0));
        let row = &report.cases[0];
        assert_eq!(row.reference, row.native);
        assert_eq!(row.native.as_ref().unwrap().stdout.bytes, 3);
        assert!(!report.release_certification);
        assert_eq!(report.reference_runtime.executable, node(false).executable);
        let encoded = serde_json::to_vec(&report).expect("serialize");
        assert_eq!(serde_json::from_slice::<SuiteReport>(&encoded).unwrap(), report);
    }

    #[test]
    fn stdout_difference_blocks_the_suite() {
        let project = fixture();
        write(project.path(), "case.test.js", "console.log(process.argv.includes('candidate') ? 'wrong' : 'right');");
        let report = measured(project.path());
        assert_eq!(report.verdict, "FAIL");
        assert_eq!(report.cases[0].divergences, ["stdout:byte_mismatch"]);
    }

    #[test]
    fn stderr_difference_is_not_hidden_by_equal_stdout() {
        let project = fixture();
        write(project.path(), "case.test.js", "console.log('same'); console.error(process.argv.includes('candidate') ? 'wrong' : 'right');");
        let report = measured(project.path());
        assert_eq!(report.verdict, "FAIL");
        assert_eq!(report.cases[0].divergences, ["stderr:byte_mismatch"]);
    }

    #[test]
    fn matching_failed_processes_never_pass() {
        let project = fixture();
        write(project.path(), "case.test.js", "process.exit(7);");
        let report = measured(project.path());
        assert_eq!(report.verdict, "FAIL");
        assert_eq!(report.cases[0].reference.as_ref().unwrap().exit_code, Some(7));
        assert_eq!(report.cases[0].native.as_ref().unwrap().exit_code, Some(7));
        assert_eq!(report.cases[0].divergences.len(), 2);
    }

    #[test]
    fn matching_signals_never_pass() {
        let project = fixture();
        write(project.path(), "case.test.js", "process.kill(process.pid,'SIGTERM');");
        let report = measured(project.path());
        assert_eq!(report.verdict, "FAIL");
        assert!(report.cases[0].reference.as_ref().unwrap().signal.is_some());
    }

    #[test]
    fn later_pass_does_not_erase_an_earlier_failure() {
        let project = fixture();
        write(project.path(), "a.test.js", "process.exit(3);");
        write(project.path(), "z.test.js", "console.log('ok');");
        let report = measured(project.path());
        assert_eq!(report.verdict, "FAIL");
        assert_eq!((report.passed, report.failed, report.skipped), (1, 1, 0));
        assert_eq!(report.cases[1].status, "PASS");
    }

    #[test]
    fn every_case_and_leg_starts_from_captured_bytes() {
        let project = fixture();
        write(project.path(), "value.txt", "original");
        let source = "const fs=require('fs'); console.log(fs.readFileSync('value.txt','utf8')); fs.writeFileSync('value.txt','changed');";
        write(project.path(), "a.test.js", source);
        write(project.path(), "b.test.js", source);
        let report = measured(project.path());
        assert_eq!(report.verdict, "PASS");
        for row in &report.cases {
            assert_eq!(row.reference.as_ref().unwrap().stdout.sha256, format!("{:x}", Sha256::digest(b"original\n")));
        }
        assert_eq!(fs::read_to_string(project.path().join("value.txt")).unwrap(), "original");
    }

    #[test]
    fn source_tree_changes_after_capture_do_not_change_execution() {
        let project = fixture();
        write(project.path(), "case.test.js", "console.log('captured');");
        let deadline = Instant::now() + Duration::from_secs(10);
        let snapshot = Snapshot::capture(project.path(), deadline).unwrap();
        write(project.path(), "case.test.js", "process.exit(99);");
        let report = execute_suite(&snapshot, &node(false), &node(true), deadline, Duration::from_secs(3)).unwrap();
        assert_eq!(report.verdict, "PASS");
        assert_eq!(report.cases[0].native.as_ref().unwrap().stdout.bytes, 9);
        assert_eq!(fs::read_to_string(project.path().join("case.test.js")).unwrap(), "process.exit(99);");
    }

    #[test]
    fn dependencies_are_staged_without_running_vendor_tests() {
        let project = fixture();
        write(project.path(), "node_modules/pkg/index.js", "module.exports=42;");
        write(project.path(), "node_modules/pkg/vendor.test.js", "process.exit(8);");
        write(project.path(), "case.test.js", "console.log(require('pkg'));");
        let report = measured(project.path());
        assert_eq!(report.verdict, "PASS");
        assert_eq!(report.total_tests, 1);
    }

    #[test]
    fn exact_bytes_preserve_newline_and_invalid_utf8_differences() {
        for source in [
            "process.stdout.write(process.argv.includes('candidate') ? 'ok' : 'ok\\n');",
            "process.stdout.write(Buffer.from([process.argv.includes('candidate') ? 255 : 254]));",
            "console.log(process.argv.includes('candidate') ? 'pid=2' : 'pid=1');",
        ] {
            let project = fixture();
            write(project.path(), "case.test.js", source);
            assert_eq!(measured(project.path()).verdict, "FAIL");
        }
    }

    #[test]
    fn metacharacters_in_case_names_are_literal_arguments() {
        let project = fixture();
        write(project.path(), "case;touch NEVER.test.js", "console.log('literal');");
        assert_eq!(measured(project.path()).verdict, "PASS");
        assert!(!project.path().join("NEVER.test.js").exists());
    }

    #[test]
    fn timeout_retains_reference_measurement_and_never_passes() {
        let project = fixture();
        write(project.path(), "case.test.js", "console.log('start'); if(process.argv.includes('candidate')) setInterval(()=>{},1000);");
        let deadline = Instant::now() + Duration::from_secs(10);
        let snapshot = Snapshot::capture(project.path(), deadline).unwrap();
        let report = execute_suite(&snapshot, &node(false), &node(true), deadline, Duration::from_millis(300)).unwrap();
        assert_eq!(report.verdict, "ERROR");
        assert_eq!(report.errored, 1);
        assert!(report.cases[0].reference.is_some());
        assert!(report.cases[0].native.is_none());
        assert!(report.cases[0].errors[0].contains("timed out"));
    }

    #[test]
    fn output_overflow_is_not_a_truncated_prefix_pass() {
        let project = fixture();
        write(project.path(), "case.test.js", "process.stdout.write('x'.repeat(17*1024*1024));");
        let report = measured(project.path());
        assert_eq!(report.verdict, "ERROR");
        assert_eq!(report.passed, 0);
        assert!(report.cases[0].errors[0].contains("exceeds"));
    }

    #[test]
    fn infrastructure_error_does_not_erase_remaining_cases() {
        let project = fixture();
        write(project.path(), "a.test.js", "process.stdout.write('x'.repeat(17*1024*1024));");
        write(project.path(), "b.test.js", "console.log('ok');");
        let report = measured(project.path());
        assert_eq!((report.errored, report.passed, report.skipped), (1, 1, 0));
        assert_eq!(report.verdict, "ERROR");
    }

    #[test]
    fn missing_executable_is_an_error_before_guest_execution() {
        let project = fixture();
        write(project.path(), "case.test.js", "require('fs').writeFileSync('never','ran');");
        let deadline = Instant::now() + Duration::from_secs(10);
        let snapshot = Snapshot::capture(project.path(), deadline).unwrap();
        let absent = Invocation { executable: project.path().join("absent"), before: vec![], after: vec![] };
        assert!(execute_suite(&snapshot, &absent, &node(true), deadline, Duration::from_secs(1)).is_err());
        assert!(!project.path().join("never").exists());
        assert!(run_project(project.path(), &absent.executable).is_err());
    }

    #[test]
    fn empty_project_keeps_smoke_fallback_but_empty_suite_cannot_pass() {
        let project = fixture();
        write(project.path(), "index.js", "console.log('app');");
        assert!(run_if_present(project.path()).unwrap().is_none());
        let deadline = Instant::now() + Duration::from_secs(5);
        let snapshot = Snapshot::capture(project.path(), deadline).unwrap();
        assert!(execute_suite(&snapshot, &node(false), &node(true), deadline, Duration::from_secs(1)).is_err());
    }

    #[test]
    fn discovery_is_sorted_and_excludes_state_and_backups() {
        let project = fixture();
        for path in ["z.spec.mjs", "test/plain.js", "a.test.ts", "__tests__/nested/x.cjs",
            "node_modules/pkg/x.test.js", ".migrate-backup/a.test.js", ".franken-node/x.test.js", "helper.js", "name.test.helper.js"] {
            write(project.path(), path, "//fixture");
        }
        let snapshot = Snapshot::capture(project.path(), Instant::now() + Duration::from_secs(5)).unwrap();
        let found: Vec<_> = snapshot.tests().unwrap().into_iter().map(|path| path.to_string_lossy().into_owned()).collect();
        assert_eq!(found, ["__tests__/nested/x.cjs", "a.test.ts", "test/plain.js", "z.spec.mjs"]);
    }

    #[test]
    fn external_symlinks_are_refused() {
        let project = fixture();
        symlink("/etc/passwd", project.path().join("external")).unwrap();
        assert!(Snapshot::capture(project.path(), Instant::now() + Duration::from_secs(5)).is_err());
    }

    #[test]
    fn symlink_into_excluded_git_is_refused() {
        let project = fixture();
        write(project.path(), ".git/config", "sensitive");
        symlink(".git/config", project.path().join("alias")).unwrap();
        assert!(Snapshot::capture(project.path(), Instant::now() + Duration::from_secs(5)).is_err());
    }

    #[test]
    fn internal_link_chains_preserve_retargeting_semantics() {
        let project = fixture();
        write(project.path(), "first", "first");
        write(project.path(), "second", "second");
        symlink("first", project.path().join("middle")).unwrap();
        symlink(project.path().join("middle"), project.path().join("alias")).unwrap();
        write(project.path(), "case.test.js", "const fs=require('fs'); fs.unlinkSync('middle'); fs.symlinkSync('second','middle'); console.log(fs.readFileSync('alias','utf8'));");
        let report = measured(project.path());
        assert_eq!(report.verdict, "PASS");
        assert_eq!(report.cases[0].native.as_ref().unwrap().stdout.sha256, format!("{:x}", Sha256::digest(b"second\n")));
        assert_eq!(fs::read_link(project.path().join("middle")).unwrap(), Path::new("first"));
    }

    #[test]
    fn hardlinks_are_refused_rather_than_silently_changing_alias_semantics() {
        let project = fixture();
        write(project.path(), "first", "bytes");
        fs::hard_link(project.path().join("first"), project.path().join("second")).unwrap();
        assert!(Snapshot::capture(project.path(), Instant::now() + Duration::from_secs(5)).is_err());
    }

    #[test]
    fn special_files_cannot_block_capture() {
        let project = fixture();
        let _listener = std::os::unix::net::UnixListener::bind(project.path().join("socket")).unwrap();
        assert!(Snapshot::capture(project.path(), Instant::now() + Duration::from_secs(5)).is_err());
    }

    #[test]
    fn oversized_sparse_file_is_refused_before_allocating_its_contents() {
        let project = fixture();
        File::create(project.path().join("huge")).unwrap().set_len(MAX_PROJECT_BYTES as u64 + 1).unwrap();
        assert!(Snapshot::capture(project.path(), Instant::now() + Duration::from_secs(5)).is_err());
    }

    #[test]
    fn capture_identity_binds_file_content_and_permissions() {
        let project = fixture();
        write(project.path(), "case.test.js", "console.log('ok');");
        fs::set_permissions(project.path().join("case.test.js"), fs::Permissions::from_mode(0o644)).unwrap();
        let capture = || Snapshot::capture(project.path(), Instant::now() + Duration::from_secs(5)).unwrap().digest;
        let original = capture();
        assert_eq!(original, capture());
        fs::set_permissions(project.path().join("case.test.js"), fs::Permissions::from_mode(0o600)).unwrap();
        assert_ne!(original, capture());
        let changed_mode = capture();
        write(project.path(), "case.test.js", "console.log('changed');");
        assert_ne!(changed_mode, capture());
    }

    #[test]
    fn deadlines_fail_before_staging_or_execution() {
        let project = fixture();
        write(project.path(), "case.test.js", "console.log('ok');");
        assert!(Snapshot::capture(project.path(), Instant::now()).is_err());
        let snapshot = Snapshot::capture(project.path(), Instant::now() + Duration::from_secs(5)).unwrap();
        assert!(execute_suite(&snapshot, &node(false), &node(true), Instant::now(), Duration::from_secs(1)).is_err());
    }

    #[test]
    fn native_command_uses_relative_case_and_disables_degraded_fallback() {
        let invocation = Invocation { executable: PathBuf::from("/trusted/native"), before: vec!["run".into()],
            after: vec!["--runtime".into(), "franken-engine".into(), "--console-only".into()] };
        let environment = BTreeMap::from([("FRANKEN_NODE_ALLOW_DEGRADED_RUNTIME_FALLBACK".into(), "1".into())]);
        let command = invocation.command(Path::new("tests/a.test.js"), Path::new("/workspace"), &environment);
        let args: Vec<_> = command.get_args().map(|arg| arg.to_string_lossy().into_owned()).collect();
        assert_eq!(args, ["run", "./tests/a.test.js", "--runtime", "franken-engine", "--console-only"]);
        assert!(command.get_envs().all(|(key, value)| key != "FRANKEN_NODE_ALLOW_DEGRADED_RUNTIME_FALLBACK" || value.is_none()));
    }
}
