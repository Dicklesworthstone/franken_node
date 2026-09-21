//! Per-harness execution settings read from immutable captured inputs.
//!
//! Settings describe a standalone script, not a shell/package-manager command.
//! They cannot select runtimes, enable fallback, or alter comparison limits.
//! Only declared application-environment overrides are captured: the remaining
//! ambient environment and external effects are NOT reproduced or sandboxed.
//!
//! For example, an execution entry may select
//! `{"stdin":"fixtures/request.bin","stdin_mode":"pipe"}`. The captured
//! fixture still has the same 1 MiB limit and regular-file admission rules;
//! only its delivery transport changes. Omitted mode is `file`. Pipe input
//! supports EOF-terminated byte requests, not an interactive terminal or a
//! conversation protocol. Queuing all bytes does not prove guest consumption.

use super::super::{Entry, EntryData, Invocation, MAX_PATH_BYTES, Snapshot, excluded_from_discovery, smoke_supervisor};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Deserializer, de::{MapAccess, Visitor}};
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fmt;
use std::marker::PhantomData;
use std::path::{Component, Path, PathBuf};
use std::process::Output;
use std::time::{Duration, Instant};

/// Transport is observable to the guest and therefore part of the captured
/// execution contract. Missing mode retains the historical redirected file;
/// pipe mode must be explicitly selected, even for an empty input fixture.
#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(super) enum StdinMode {
    #[default]
    File,
    Pipe,
}

/// Environment values can be sensitive; Debug deliberately excludes them.
#[derive(Clone, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct Settings {
    #[serde(default)]
    pub(super) cwd: Option<String>,
    #[serde(default)]
    pub(super) stdin: Option<String>,
    #[serde(default)]
    pub(super) stdin_mode: StdinMode,
    #[serde(default, deserialize_with = "unique_map")]
    pub(super) environment: BTreeMap<String, Option<String>>,
}

impl fmt::Debug for Settings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Settings").field("cwd", &self.cwd).field("stdin", &self.stdin)
            .field("stdin_mode", &self.stdin_mode)
            .field("environment_count", &self.environment.len()).finish_non_exhaustive()
    }
}

/// Serde's ordinary map deserializer overwrites duplicate keys. Ambiguous
/// test settings and environment assignments must instead be rejected.
pub(super) fn unique_map<'de, D, T>(deserializer: D) -> std::result::Result<BTreeMap<String, T>, D::Error>
where D: Deserializer<'de>, T: Deserialize<'de> {
    struct Unique<T>(PhantomData<T>);
    impl<'de, T: Deserialize<'de>> Visitor<'de> for Unique<T> {
        type Value = BTreeMap<String, T>;
        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("an object with unique keys")
        }
        fn visit_map<M: MapAccess<'de>>(self, mut input: M) -> std::result::Result<Self::Value, M::Error> {
            let mut output = BTreeMap::new();
            while let Some((name, value)) = input.next_entry::<String, T>()? {
                if output.insert(name, value).is_some() {
                    return Err(serde::de::Error::custom("duplicate execution-setting or environment key"));
                }
            }
            Ok(output)
        }
    }
    deserializer.deserialize_map(Unique(PhantomData))
}

fn captured_path<'a>(entries: &BTreeMap<PathBuf, Entry>, name: &'a str) -> Result<&'a Path> {
    let path = Path::new(name);
    ensure!(!name.is_empty() && name.len() <= MAX_PATH_BYTES && !name.contains('\\')
        && !name.chars().any(char::is_control)
        && path.components().all(|part| matches!(part, Component::Normal(_)))
        && path.components().map(|part| part.as_os_str().to_string_lossy()).collect::<Vec<_>>().join("/") == name,
        "execution paths must be canonical project-relative paths");
    ensure!(!excluded_from_discovery(path)
        && !path.components().any(|part| matches!(part.as_os_str().to_str(), Some(".franken-rewrite" | ".beads"))),
        "execution paths cannot select dependencies, backups or reserved state");
    for parent in path.ancestors().skip(1).filter(|parent| !parent.as_os_str().is_empty()) {
        ensure!(matches!(entries.get(parent).map(|entry| &entry.data), Some(EntryData::Directory)),
            "execution paths must have ordinary captured directory parents");
    }
    Ok(path)
}

fn application_variable(name: &str) -> bool {
    if name.is_empty() || name.len() > 128 { return false; }
    let mut bytes = name.bytes();
    if !bytes.next().is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_')
        || !bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_') { return false; }
    // NODE_ENV is an application-mode convention, not a runtime option.
    if name == "NODE_ENV" { return true; }
    let upper = name.to_ascii_uppercase();
    !["NODE_", "BUN_", "FRANKEN_", "LD_", "DYLD_", "RUST_", "CARGO_", "NPM_"]
        .iter().any(|prefix| upper.starts_with(prefix))
        && !matches!(upper.as_str(), "PATH" | "HOME" | "PWD" | "OLDPWD" | "TMPDIR" | "TMP" | "TEMP"
            | "SHELL" | "ENV" | "BASH_ENV" | "IFS" | "CDPATH" | "GCONV_PATH")
}

pub(super) fn validate(settings: &mut Settings, entries: &BTreeMap<PathBuf, Entry>, test: &Path) -> Result<()> {
    ensure!(settings.stdin_mode != StdinMode::Pipe || settings.stdin.is_some(),
        "pipe stdin mode requires an explicit captured stdin file");
    if settings.cwd.as_deref() == Some(".") { settings.cwd = None; }
    if let Some(name) = &settings.cwd {
        let path = captured_path(entries, name)?;
        ensure!(matches!(entries.get(path).map(|entry| &entry.data), Some(EntryData::Directory)),
            "test working directory must be an ordinary captured directory");
    }
    // The primary runtime rejects parent traversal and absolute script paths.
    // Keep this boundary; do not use privileged argv or disable its validation.
    script_from(Path::new(settings.cwd.as_deref().unwrap_or("")), test)?;
    if let Some(name) = &settings.stdin {
        let path = captured_path(entries, name)?;
        let Some(Entry { data: EntryData::File(bytes), .. }) = entries.get(path) else {
            anyhow::bail!("test stdin must be an ordinary captured file");
        };
        ensure!(bytes.len() <= smoke_supervisor::MAX_INPUT_BYTES, "captured test stdin exceeds 1 MiB");
    }
    ensure!(settings.environment.len() <= 64, "at most 64 application environment overrides per test");
    let mut bytes = 0_usize;
    for (name, value) in &settings.environment {
        ensure!(application_variable(name), "test environment cannot override runtime, loader or operator controls");
        ensure!(value.as_ref().is_none_or(|value| value.len() <= 4096 && !value.contains('\0')),
            "test environment value exceeds 4096 bytes or contains NUL");
        bytes += name.len() + value.as_ref().map_or(0, String::len);
    }
    ensure!(bytes <= 16 * 1024, "test environment exceeds 16 KiB");
    Ok(())
}

pub(super) fn input<'a>(settings: &Settings, snapshot: &'a Snapshot) -> Result<Option<&'a [u8]>> {
    settings.stdin.as_deref().map(|name| {
        match snapshot.entries.get(Path::new(name)).map(|entry| &entry.data) {
            Some(EntryData::File(bytes)) => Ok(bytes.as_slice()),
            _ => anyhow::bail!("captured stdin file is unavailable"),
        }
    }).transpose()
}

fn script_from(cwd: &Path, script: &Path) -> Result<PathBuf> {
    let relative = script.strip_prefix(cwd).context("test entrypoint must be inside its working directory")?;
    ensure!(!relative.as_os_str().is_empty(), "test entrypoint cannot be its working directory");
    Ok(relative.to_path_buf())
}

pub(super) fn run(snapshot: &Snapshot, settings: &Settings, test: &Path, invocation: &Invocation,
    workspace: &Path, environment: &BTreeMap<OsString, OsString>, timing: (Instant, Duration)) -> Result<Output> {
    let cwd = Path::new(settings.cwd.as_deref().unwrap_or(""));
    let mut command = invocation.command(&script_from(cwd, test)?, &workspace.join(cwd), environment);
    for (name, value) in &settings.environment {
        match value {
            Some(value) => { command.env(name, value); }
            None => { command.env_remove(name); }
        }
    }
    let bytes = input(settings, snapshot)?;
    let remaining = timing.0.saturating_duration_since(Instant::now());
    ensure!(!remaining.is_zero(), "test execution setup exhausted the runtime budget");
    // Mode participates in Settings equality, so paired validation, checked
    // rewrites and capsule replay cannot substitute file input for pipe input.
    // Both transports use the same exclusive child owner and output checks.
    match (settings.stdin_mode, bytes) {
        (StdinMode::File, Some(bytes)) => smoke_supervisor::run_command_with_input(&mut command, remaining, timing.1, Some(bytes)),
        (StdinMode::File, None) => smoke_supervisor::run_command_with_timeout(&mut command, remaining, timing.1),
        (StdinMode::Pipe, Some(bytes)) => smoke_supervisor::run_command_with_pipe_input(&mut command, remaining, timing.1, bytes),
        (StdinMode::Pipe, None) => anyhow::bail!("pipe stdin mode requires an explicit captured stdin file"),
    }.context("execute captured test settings")
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::{inventory, matched_execution, run_test};
    use super::super::super::{execute_suite_pair, matched_tests, native_replay, node_on_path,
        product_oracle, rewrite_candidate::{Replacement, RewriteCandidate}};
    use std::fs;
    use std::os::unix::fs::symlink;

    const TEST: &str = "packages/api/check.cjs";
    fn put(root: &Path, name: &str, bytes: &[u8]) {
        let path = root.join(name);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, bytes).unwrap();
    }
    fn manifest(root: &Path, execution: serde_json::Value) {
        put(root, ".franken-node/migration-tests.json", &serde_json::to_vec(&serde_json::json!({
            "schema_version":"franken-node/migration-tests/v1", "tests":[TEST], "execution": execution,
        })).unwrap());
    }
    fn fixture() -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        put(root.path(), TEST, b"const fs=require('fs');process.stdout.write(fs.readFileSync(0));console.log(process.env.APP_MODE,fs.readFileSync('local.txt','utf8'),process.env.DROP_ME===undefined);fs.writeFileSync('artifact','ok');");
        put(root.path(), "packages/api/local.txt", b"package-local");
        put(root.path(), "fixtures/input.bin", &[0, 255, b'x', b'\n']);
        manifest(root.path(), serde_json::json!({(TEST):{
            "cwd":"packages/api", "stdin":"fixtures/input.bin",
            "environment":{"APP_MODE":"captured", "DROP_ME":null}
        }}));
        root
    }
    fn snapshot(root: &Path) -> Snapshot {
        Snapshot::capture(root, Instant::now() + Duration::from_secs(60)).unwrap()
    }
    fn node() -> Invocation { Invocation { executable: node_on_path().unwrap(), before: vec![], after: vec![] } }

    #[test]
    fn captured_cwd_environment_and_binary_input_execute_in_each_fresh_workspace() {
        let root = fixture();
        let captured = snapshot(root.path());
        put(root.path(), "fixtures/input.bin", b"later input");
        manifest(root.path(), serde_json::json!({(TEST):{"cwd":"."}}));
        let report = execute_suite_pair(&captured, &captured, &node(), &node(),
            Instant::now() + Duration::from_secs(120), Duration::from_secs(5), true).unwrap();
        assert_eq!(report.verdict, "PASS", "{report:#?}");
        let expected = [vec![0,255,b'x',b'\n'], b"captured package-local true\n".to_vec()].concat();
        use sha2::Digest;
        assert_eq!(report.cases[0].reference.as_ref().unwrap().stdout.sha256, hex::encode(sha2::Sha256::digest(expected)));
        let delta = report.cases[0].reference.as_ref().unwrap().workspace_delta.as_ref().unwrap();
        assert_eq!(delta.changed_paths, 1);
        assert!(serde_json::to_string(delta).unwrap().contains("packages/api/artifact"));
        assert!(!root.path().join("packages/api/artifact").exists());
        assert!(!root.path().join("artifact").exists());
    }

    #[test]
    fn candidate_cannot_change_settings_or_input_bytes_before_runtime_resolution() {
        let original = fixture();
        let candidate = fixture();
        let before = snapshot(original.path());
        matched_tests(&before, &snapshot(candidate.path())).unwrap();
        for settings in [serde_json::json!({"cwd":"."}),
            serde_json::json!({"environment":{"APP_MODE":"different"}}),
            serde_json::json!({"stdin":"packages/api/local.txt"})] {
            manifest(candidate.path(), serde_json::json!({(TEST):settings}));
            assert!(matched_tests(&before, &snapshot(candidate.path())).is_err());
        }
        let candidate = fixture();
        put(candidate.path(), "fixtures/input.bin", b"substituted");
        assert!(matched_execution(&before, &snapshot(candidate.path())).unwrap_err().to_string().contains("stdin bytes differ"));
    }

    #[test]
    fn unknown_tests_and_unsafe_missing_linked_or_reserved_inputs_fail_closed() {
        let root = fixture();
        symlink("packages/api", root.path().join("alias")).unwrap();
        symlink("input.bin", root.path().join("fixtures/linked")).unwrap();
        for settings in [serde_json::json!({"cwd":"../outside"}), serde_json::json!({"cwd":"./packages/api"}),
            serde_json::json!({"cwd":"missing"}), serde_json::json!({"cwd":"alias"}),
            serde_json::json!({"cwd":"packages/api/local.txt"}), serde_json::json!({"stdin":"fixtures/linked"}),
            serde_json::json!({"stdin":"/etc/passwd"}), serde_json::json!({"stdin":"missing"}),
            serde_json::json!({"stdin":"packages/api"}), serde_json::json!({"stdin":".franken-node/migration-tests.json"}),
            serde_json::json!({"stdin":"fixtures\\input.bin"}), serde_json::json!({"args":["--eval","bad"]}),
            serde_json::json!({"timeout":999})] {
            manifest(root.path(), serde_json::json!({(TEST):settings}));
            assert!(inventory(&snapshot(root.path()).entries).is_err());
        }
        manifest(root.path(), serde_json::json!({"unselected.cjs":{}}));
        assert!(inventory(&snapshot(root.path()).entries).unwrap_err().to_string().contains("unselected"));
    }

    #[test]
    fn ambiguous_duplicate_settings_and_environment_keys_are_rejected() {
        let root = fixture();
        for execution in [
            r#"{"packages/api/check.cjs":{},"packages/api/check.cjs":{"cwd":"packages/api"}}"#,
            r#"{"packages/api/check.cjs":{"environment":{"APP_MODE":"one","APP_MODE":"two"}}}"#,
            r#"{"packages/api/check.cjs":{"cwd":"packages/api","cwd":"."}}"#,
        ] {
            let raw = format!(r#"{{"schema_version":"franken-node/migration-tests/v1","tests":["{TEST}"],"execution":{execution}}}"#);
            put(root.path(), ".franken-node/migration-tests.json", raw.as_bytes());
            assert!(inventory(&snapshot(root.path()).entries).is_err());
        }
    }

    #[test]
    fn only_bounded_application_environment_overrides_are_accepted() {
        let entries = BTreeMap::new();
        for name in ["NODE_OPTIONS", "BUN_OPTIONS", "PATH", "LD_PRELOAD", "DYLD_INSERT_LIBRARIES", "HOME",
            "FRANKEN_NODE_ALLOW_DEGRADED_RUNTIME_FALLBACK", "FRANKEN_NODE_MIGRATION_FAILURE_DIR",
            "RUST_LOG", "BASH_ENV", "", "1NAME", "NAME=VALUE"] {
            let mut settings = Settings { environment: BTreeMap::from([(name.into(), Some("value".into()))]), ..Settings::default() };
            assert!(validate(&mut settings, &entries, Path::new(TEST)).is_err(), "{name}");
        }
        let mut settings = Settings { environment: BTreeMap::from([("APP_MODE".into(), Some("test".into())),
            ("NODE_ENV".into(), Some("test".into())), ("UNSET_ME".into(), None)]), ..Settings::default() };
        validate(&mut settings, &entries, Path::new(TEST)).unwrap();
        for value in ["x".repeat(4097), "embedded\0nul".into()] {
            settings.environment.insert("APP_MODE".into(), Some(value));
            assert!(validate(&mut settings, &entries, Path::new(TEST)).is_err());
        }
        settings.environment = (0..65).map(|i| (format!("APP_{i}"), None)).collect();
        assert!(validate(&mut settings, &entries, Path::new(TEST)).is_err());
        settings.environment = (0..5).map(|i| (format!("APP_{i}"), Some("x".repeat(4096)))).collect();
        assert!(validate(&mut settings, &entries, Path::new(TEST)).is_err());
        let settings = Settings { environment: BTreeMap::from([("APP_SECRET".into(), Some("private-value".into()))]), ..Settings::default() };
        assert!(!format!("{settings:?}").contains("private-value"));
    }

    #[test]
    fn stdin_size_and_root_directory_defaults_are_checked_before_execution() {
        let root = fixture();
        put(root.path(), "fixtures/input.bin", &vec![0; smoke_supervisor::MAX_INPUT_BYTES + 1]);
        assert!(inventory(&snapshot(root.path()).entries).is_err());
        let mut root_settings = Settings { cwd: Some(".".into()), ..Settings::default() };
        validate(&mut root_settings, &BTreeMap::new(), Path::new(TEST)).unwrap();
        assert!(root_settings == Settings::default());
        assert!(script_from(Path::new("packages/api"), Path::new("scripts/check.cjs")).is_err());
        assert_eq!(script_from(Path::new("packages/api"), Path::new(TEST)).unwrap(), Path::new("check.cjs"));
        assert_eq!(script_from(Path::new(""), Path::new(TEST)).unwrap(), Path::new(TEST));
    }

    #[test]
    fn working_directory_cannot_require_parent_traversal_in_the_runtime_command() {
        let root = fixture();
        manifest(root.path(), serde_json::json!({(TEST):{"cwd":"fixtures"}}));
        let error = inventory(&snapshot(root.path()).entries).unwrap_err();
        assert!(error.to_string().contains("entrypoint must be inside"));
        let path = script_from(Path::new("packages"), Path::new(TEST)).unwrap();
        let runtime = node();
        let environment = BTreeMap::new();
        let command = runtime.command(&path, root.path(), &environment);
        assert_eq!(command.get_args().next().unwrap(), "./api/check.cjs");
    }

    #[test]
    fn checked_rewrites_measure_configured_harnesses_and_refuse_input_substitution() {
        let root = fixture();
        let mut candidate = RewriteCandidate::capture(root.path(), Instant::now() + Duration::from_secs(120)).unwrap();
        let before = fs::read(root.path().join(TEST)).unwrap();
        let mut after = b"// equivalent candidate\n".to_vec();
        after.extend_from_slice(&before);
        candidate.prepare(&[Replacement { path:TEST, before:&before, after:&after }]).unwrap();
        let report = candidate.validate_node_pair().unwrap();
        candidate.check_validation(&report).unwrap();
        candidate.ensure_source_unchanged().unwrap();
        let input = fs::read(root.path().join("fixtures/input.bin")).unwrap();
        assert!(candidate.prepare(&[Replacement {path:"fixtures/input.bin", before:&input, after:b"different"}])
            .unwrap_err().to_string().contains("stdin bytes differ"));
    }

    #[test]
    fn per_case_overrides_remove_values_without_mutating_the_base_environment() {
        let root = fixture();
        put(root.path(), "scripts/other.cjs", b"console.log(process.env.APP_MODE,process.env.DROP_ME);console.log(require('fs').readFileSync(0).length);");
        put(root.path(), ".franken-node/migration-tests.json", br#"{"schema_version":"franken-node/migration-tests/v1","tests":["packages/api/check.cjs","scripts/other.cjs"],"execution":{"packages/api/check.cjs":{"cwd":"packages/api","stdin":"fixtures/input.bin","environment":{"APP_MODE":"captured","DROP_ME":null}}}}"#);
        let captured = snapshot(root.path());
        let workspaces = tempfile::tempdir().unwrap();
        let environment = BTreeMap::from([(OsString::from("APP_MODE"), OsString::from("ambient")),
            (OsString::from("DROP_ME"), OsString::from("retained"))]);
        for (index, test) in [TEST, "scripts/other.cjs"].into_iter().enumerate() {
            let workspace = workspaces.path().join(index.to_string());
            captured.stage(&workspace, Instant::now() + Duration::from_secs(30)).unwrap();
            let output = run_test(&captured, &node(), Path::new(test), &workspace, &environment,
                (Duration::from_secs(5), Duration::from_secs(1))).unwrap();
            assert!(output.status.success());
            if index == 0 { assert!(output.stdout.ends_with(b"captured package-local true\n")); }
            else { assert_eq!(output.stdout, b"ambient retained\n0\n"); }
        }
        assert_eq!(environment[&OsString::from("APP_MODE")], "ambient");
    }

    #[test]
    fn all_three_legs_share_settings_and_record_effects_from_the_workspace_root() {
        let root = fixture();
        let captured = snapshot(root.path());
        let runtime = node();
        let deadline = Instant::now() + Duration::from_secs(120);
        let identity = runtime.identity(deadline).unwrap();
        // Explicit Node/Node/Node exercises orchestration, not brand independence.
        let report = product_oracle::execute(&captured, &captured, [&runtime, &runtime, &runtime],
            [identity.clone(), identity.clone(), identity], deadline, Duration::from_secs(5), true).unwrap();
        assert_eq!(report.verdict, "PASS", "{report:#?}");
        assert_eq!(report.cases[0].node, report.cases[0].bun);
        assert_eq!(report.cases[0].node, report.cases[0].native);
        assert!(!report.distinct_reference_binaries);
        assert!(serde_json::to_string(&report.cases[0]).unwrap().contains("packages/api/artifact"));
    }

    #[test]
    fn pair_and_product_capsules_replay_settings_and_fixture_bytes_not_later_sources() {
        use native_replay::failure_capture::product;
        for three in [false, true] {
            let root = fixture();
            let output = tempfile::tempdir().unwrap();
            let capsule = output.path().join("input-capsule.json");
            let (pin, cases) = if three {
                // Deliberate empty reference and failing candidate, not Bun/native implementations.
                let captured = product::capture_project(root.path(), None, Path::new("/bin/false"), Path::new("/bin/true"), true).unwrap();
                assert_eq!(captured.report.verdict, "INCONCLUSIVE");
                (captured.write_capsule(&capsule).unwrap().content_sha256, serde_json::to_value(&captured.report.cases).unwrap())
            } else {
                let captured = native_replay::capture_project(root.path(), None, Path::new("/bin/false"), true).unwrap();
                assert_eq!(captured.report.verdict, "FAIL");
                (captured.write_capsule(&capsule).unwrap().content_sha256, serde_json::to_value(&captured.report.cases).unwrap())
            };
            put(root.path(), "fixtures/input.bin", b"changed request");
            put(root.path(), "packages/api/local.txt", b"later package");
            manifest(root.path(), serde_json::json!({}));
            let replay = if three {
                serde_json::to_value(product::replay(&capsule, &pin, Path::new("/bin/false"), Path::new("/bin/true"), false).unwrap()).unwrap()
            } else {
                serde_json::to_value(native_replay::replay(&capsule, &pin, Path::new("/bin/false"), false).unwrap()).unwrap()
            };
            assert_eq!(replay["verdict"], "REPRODUCED");
            assert_eq!(replay["validation"]["cases"], cases);
            assert!(!root.path().join("packages/api/artifact").exists());
            assert_eq!(fs::read(root.path().join("fixtures/input.bin")).unwrap(), b"changed request");
        }
    }

    fn pipe_fixture() -> tempfile::TempDir {
        let root = fixture();
        put(root.path(), TEST, br#"
const fs = require('fs');
if (!fs.fstatSync(0).isFIFO()) throw new Error('pipe transport required');
const chunks = [];
process.stdin.on('data', chunk => chunks.push(chunk));
process.stdin.on('end', () => {
    process.stdout.write(Buffer.concat(chunks));
    fs.writeFileSync('artifact', 'pipe');
});
"#);
        manifest(root.path(), serde_json::json!({(TEST):{
            "cwd":"packages/api", "stdin":"fixtures/input.bin", "stdin_mode":"pipe"
        }}));
        root
    }

    fn execute_captured(captured: &Snapshot) -> Output {
        let root = tempfile::tempdir().unwrap();
        let workspace = root.path().join("workspace");
        captured.stage(&workspace, Instant::now() + Duration::from_secs(30)).unwrap();
        run_test(captured, &node(), Path::new(TEST), &workspace, &BTreeMap::new(),
            (Duration::from_secs(5), Duration::from_secs(1))).unwrap()
    }

    #[test]
    fn pipe_manifest_runs_async_stdin_from_the_snapshot_not_the_mutable_source() {
        let root = pipe_fixture();
        let captured = snapshot(root.path());
        put(root.path(), "fixtures/input.bin", b"substituted after capture");
        manifest(root.path(), serde_json::json!({(TEST):{
            "cwd":"packages/api", "stdin":"fixtures/input.bin", "stdin_mode":"file"
        }}));
        let output = execute_captured(&captured);
        assert!(output.status.success(), "{output:?}");
        assert_eq!(output.stdout, [0, 255, b'x', b'\n']);
        assert!(output.stderr.is_empty());
        assert!(!root.path().join("packages/api/artifact").exists());
    }

    #[test]
    fn pipe_mode_rejects_missing_input_unknown_types_and_duplicate_declarations() {
        let root = fixture();
        for settings in [
            serde_json::json!({"stdin_mode":"pipe"}),
            serde_json::json!({"stdin_mode":"pipe", "stdin":null}),
            serde_json::json!({"stdin_mode":"terminal", "stdin":"fixtures/input.bin"}),
            serde_json::json!({"stdin_mode":null, "stdin":"fixtures/input.bin"}),
            serde_json::json!({"stdin_mode":true, "stdin":"fixtures/input.bin"}),
            serde_json::json!({"stdin_mode":[], "stdin":"fixtures/input.bin"}),
        ] {
            manifest(root.path(), serde_json::json!({(TEST):settings}));
            assert!(inventory(&snapshot(root.path()).entries).is_err());
        }
        let raw = format!(r#"{{"schema_version":"franken-node/migration-tests/v1","tests":["{TEST}"],"execution":{{"{TEST}":{{"stdin":"fixtures/input.bin","stdin_mode":"file","stdin_mode":"pipe"}}}}}}"#);
        put(root.path(), ".franken-node/migration-tests.json", raw.as_bytes());
        assert!(inventory(&snapshot(root.path()).entries).is_err());
    }

    #[test]
    fn candidate_cannot_substitute_input_transport_but_explicit_file_matches_default() {
        let original = pipe_fixture();
        let candidate = pipe_fixture();
        let before = snapshot(original.path());
        matched_tests(&before, &snapshot(candidate.path())).unwrap();
        for mode in [None, Some("file")] {
            let mut settings = serde_json::json!({"cwd":"packages/api", "stdin":"fixtures/input.bin"});
            if let Some(mode) = mode { settings["stdin_mode"] = mode.into(); }
            manifest(candidate.path(), serde_json::json!({(TEST):settings}));
            let error = matched_execution(&before, &snapshot(candidate.path())).unwrap_err();
            assert!(error.to_string().contains("execution settings differ"));
        }
        manifest(original.path(), serde_json::json!({(TEST):{
            "cwd":"packages/api", "stdin":"fixtures/input.bin"
        }}));
        matched_execution(&snapshot(original.path()), &snapshot(candidate.path())).unwrap();
    }

    #[test]
    fn default_file_explicit_file_and_pipe_keep_distinct_descriptor_semantics() {
        let root = fixture();
        put(root.path(), TEST, b"const fs=require('fs');const st=fs.fstatSync(0);process.stdout.write(st.isFIFO()?'pipe':st.isFile()?'file':'other');");
        // Empty requests distinguish descriptors without asserting that a
        // program which never reads consumed any supplied application bytes.
        put(root.path(), "fixtures/input.bin", b"");
        for (mode, expected) in [(None, "file"), (Some("file"), "file"), (Some("pipe"), "pipe")] {
            let mut settings = serde_json::json!({"stdin":"fixtures/input.bin"});
            if let Some(mode) = mode { settings["stdin_mode"] = mode.into(); }
            manifest(root.path(), serde_json::json!({(TEST):settings}));
            let output = execute_captured(&snapshot(root.path()));
            assert!(output.status.success(), "{output:?}");
            assert_eq!(output.stdout, expected.as_bytes());
        }
    }

    #[test]
    fn explicit_empty_pipe_request_delivers_end_to_the_async_harness() {
        let root = pipe_fixture();
        put(root.path(), "fixtures/input.bin", b"");
        let output = execute_captured(&snapshot(root.path()));
        assert!(output.status.success(), "{output:?}");
        assert!(output.stdout.is_empty());
        assert!(output.stderr.is_empty());
    }

    #[test]
    fn pipe_mode_works_in_pair_and_three_role_validation_with_workspace_effects() {
        let root = pipe_fixture();
        let captured = snapshot(root.path());
        let runtime = node();
        let deadline = Instant::now() + Duration::from_secs(120);
        let pair = execute_suite_pair(&captured, &captured, &runtime, &runtime,
            deadline, Duration::from_secs(5), true).unwrap();
        assert_eq!(pair.verdict, "PASS", "{pair:#?}");
        assert_eq!(pair.cases[0].reference, pair.cases[0].native);
        assert_eq!(pair.cases[0].reference.as_ref().unwrap().workspace_delta.as_ref().unwrap().changed_paths, 1);
        let identity = runtime.identity(deadline).unwrap();
        // All roles deliberately use Node: this proves the native Rust
        // orchestration, NOT independent runtime brands or Franken parity.
        let product = product_oracle::execute(&captured, &captured, [&runtime, &runtime, &runtime],
            [identity.clone(), identity.clone(), identity], deadline, Duration::from_secs(5), true).unwrap();
        assert_eq!(product.verdict, "PASS", "{product:#?}");
        assert_eq!(product.cases[0].node, product.cases[0].bun);
        assert_eq!(product.cases[0].node, product.cases[0].native);
        assert!(!product.distinct_reference_binaries);
        assert!(!product.release_certification);
    }

    #[test]
    fn pipe_mode_capsules_preserve_transport_and_request_across_pair_and_product_replay() {
        use native_replay::failure_capture::product;
        for three in [false, true] {
            let root = pipe_fixture();
            let output = tempfile::tempdir().unwrap();
            let capsule = output.path().join("pipe-input-capsule.json");
            let (pin, cases) = if three {
                // /bin/false is an explicitly failing leg, never a Bun or
                // Franken substitute claimed to pass compatibility. Nonzero
                // native failures stay observable even with partial input.
                let captured = product::capture_project(root.path(), None,
                    Path::new("/bin/false"), Path::new("/bin/false"), true).unwrap();
                assert_eq!(captured.report.verdict, "INCONCLUSIVE");
                (captured.write_capsule(&capsule).unwrap().content_sha256,
                    serde_json::to_value(&captured.report.cases).unwrap())
            } else {
                let captured = native_replay::capture_project(root.path(), None, Path::new("/bin/false"), true).unwrap();
                assert_eq!(captured.report.verdict, "FAIL");
                (captured.write_capsule(&capsule).unwrap().content_sha256,
                    serde_json::to_value(&captured.report.cases).unwrap())
            };
            let capsule_bytes = fs::read(&capsule).unwrap();
            put(root.path(), "fixtures/input.bin", b"later request");
            manifest(root.path(), serde_json::json!({(TEST):{
                "cwd":"packages/api", "stdin":"fixtures/input.bin", "stdin_mode":"file"
            }}));
            let replay = if three {
                serde_json::to_value(product::replay(&capsule, &pin,
                    Path::new("/bin/false"), Path::new("/bin/false"), false).unwrap()).unwrap()
            } else {
                serde_json::to_value(native_replay::replay(&capsule, &pin, Path::new("/bin/false"), false).unwrap()).unwrap()
            };
            assert_eq!(replay["verdict"], "REPRODUCED");
            assert_eq!(replay["validation"]["cases"], cases);
            assert_eq!(fs::read(&capsule).unwrap(), capsule_bytes);
            assert_eq!(fs::read(root.path().join("fixtures/input.bin")).unwrap(), b"later request");
            assert!(!root.path().join("packages/api/artifact").exists());
        }
    }
}
