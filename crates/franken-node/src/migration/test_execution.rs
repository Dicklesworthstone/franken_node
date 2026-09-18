//! Per-harness execution settings read from immutable captured inputs.
//!
//! Settings describe a standalone script, not a shell/package-manager command.
//! They cannot select runtimes, enable fallback, or alter comparison limits.
//! Only declared application-environment overrides are captured: the remaining
//! ambient environment and external effects are NOT reproduced or sandboxed.

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

/// Environment values can be sensitive; deliberately not Debug or Serialize.
#[derive(Clone, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct Settings {
    #[serde(default)]
    pub(super) cwd: Option<String>,
    #[serde(default)]
    pub(super) stdin: Option<String>,
    #[serde(default, deserialize_with = "unique_map")]
    pub(super) environment: BTreeMap<String, Option<String>>,
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

pub(super) fn validate(settings: &mut Settings, entries: &BTreeMap<PathBuf, Entry>) -> Result<()> {
    if settings.cwd.as_deref() == Some(".") { settings.cwd = None; }
    if let Some(name) = &settings.cwd {
        let path = captured_path(entries, name)?;
        ensure!(matches!(entries.get(path).map(|entry| &entry.data), Some(EntryData::Directory)),
            "test working directory must be an ordinary captured directory");
    }
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

// Compute a literal script argument relative to the selected working directory.
// The validated endpoints are inside the workspace; introduced .. components
// only return to their common captured ancestor, never outside the workspace.
fn script_from(cwd: &Path, script: &Path) -> PathBuf {
    let from: Vec<_> = cwd.components().collect();
    let to: Vec<_> = script.components().collect();
    let shared = from.iter().zip(&to).take_while(|(left, right)| left == right).count();
    let mut result = PathBuf::new();
    for _ in shared..from.len() { result.push(".."); }
    for part in &to[shared..] { result.push(part.as_os_str()); }
    result
}

pub(super) fn run(snapshot: &Snapshot, settings: &Settings, test: &Path, invocation: &Invocation,
    workspace: &Path, environment: &BTreeMap<OsString, OsString>, timing: (Instant, Duration)) -> Result<Output> {
    let cwd = Path::new(settings.cwd.as_deref().unwrap_or(""));
    let mut command = invocation.command(&script_from(cwd, test), &workspace.join(cwd), environment);
    for (name, value) in &settings.environment {
        match value {
            Some(value) => { command.env(name, value); }
            None => { command.env_remove(name); }
        }
    }
    let bytes = input(settings, snapshot)?;
    let remaining = timing.0.saturating_duration_since(Instant::now());
    ensure!(!remaining.is_zero(), "test execution setup exhausted the runtime budget");
    smoke_supervisor::run_command_with_input(&mut command, remaining, timing.1, bytes)
        .context("execute captured test settings")
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::{inventory, matched_execution};
    use super::super::super::{execute_suite_pair, matched_tests, node_on_path, rewrite_candidate::{Replacement, RewriteCandidate}};
    use std::fs;
    use std::os::unix::fs::symlink;

    fn put(root: &Path, name: &str, bytes: &[u8]) {
        let path = root.join(name);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, bytes).unwrap();
    }
    fn manifest(root: &Path, execution: serde_json::Value) {
        put(root, ".franken-node/migration-tests.json", &serde_json::to_vec(&serde_json::json!({
            "schema_version":"franken-node/migration-tests/v1", "tests":["scripts/check.cjs"],
            "execution": execution,
        })).unwrap());
    }
    fn fixture() -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        put(root.path(), "scripts/check.cjs", b"const fs=require('fs');process.stdout.write(fs.readFileSync(0));console.log(process.env.APP_MODE,fs.readFileSync('local.txt','utf8'),process.env.DROP_ME===undefined);fs.writeFileSync('artifact','ok');");
        put(root.path(), "packages/api/local.txt", b"package-local");
        put(root.path(), "fixtures/input.bin", &[0, 255, b'x', b'\n']);
        manifest(root.path(), serde_json::json!({"scripts/check.cjs":{
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
        manifest(root.path(), serde_json::json!({"scripts/check.cjs":{"cwd":"scripts"}}));
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
        for settings in [serde_json::json!({"cwd":"scripts"}),
            serde_json::json!({"environment":{"APP_MODE":"different"}}),
            serde_json::json!({"stdin":"packages/api/local.txt"})] {
            manifest(candidate.path(), serde_json::json!({"scripts/check.cjs":settings}));
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
            manifest(root.path(), serde_json::json!({"scripts/check.cjs":settings}));
            assert!(inventory(&snapshot(root.path()).entries).is_err());
        }
        manifest(root.path(), serde_json::json!({"unselected.cjs":{}}));
        assert!(inventory(&snapshot(root.path()).entries).unwrap_err().to_string().contains("unselected"));
    }

    #[test]
    fn ambiguous_duplicate_settings_and_environment_keys_are_rejected() {
        let root = fixture();
        for execution in [
            r#"{"scripts/check.cjs":{},"scripts/check.cjs":{"cwd":"packages/api"}}"#,
            r#"{"scripts/check.cjs":{"environment":{"APP_MODE":"one","APP_MODE":"two"}}}"#,
            r#"{"scripts/check.cjs":{"cwd":"packages/api","cwd":"scripts"}}"#,
        ] {
            let raw = format!(r#"{{"schema_version":"franken-node/migration-tests/v1","tests":["scripts/check.cjs"],"execution":{execution}}}"#);
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
            assert!(validate(&mut settings, &entries).is_err(), "{name}");
        }
        let mut settings = Settings { environment: BTreeMap::from([("APP_MODE".into(), Some("test".into())),
            ("NODE_ENV".into(), Some("test".into())), ("UNSET_ME".into(), None)]), ..Settings::default() };
        validate(&mut settings, &entries).unwrap();
        for value in ["x".repeat(4097), "embedded\0nul".into()] {
            settings.environment.insert("APP_MODE".into(), Some(value));
            assert!(validate(&mut settings, &entries).is_err());
        }
        settings.environment = (0..65).map(|i| (format!("APP_{i}"), None)).collect();
        assert!(validate(&mut settings, &entries).is_err());
        settings.environment = (0..5).map(|i| (format!("APP_{i}"), Some("x".repeat(4096)))).collect();
        assert!(validate(&mut settings, &entries).is_err());
    }

    #[test]
    fn stdin_size_and_root_directory_defaults_are_checked_before_execution() {
        let root = fixture();
        put(root.path(), "fixtures/input.bin", &vec![0; smoke_supervisor::MAX_INPUT_BYTES + 1]);
        assert!(inventory(&snapshot(root.path()).entries).is_err());
        let mut root_settings = Settings { cwd: Some(".".into()), ..Settings::default() };
        validate(&mut root_settings, &BTreeMap::new()).unwrap();
        assert!(root_settings == Settings::default());
        assert_eq!(script_from(Path::new("packages/api"), Path::new("scripts/check.cjs")), Path::new("../../scripts/check.cjs"));
        assert_eq!(script_from(Path::new("packages/api"), Path::new("packages/api/check.cjs")), Path::new("check.cjs"));
        assert_eq!(script_from(Path::new(""), Path::new("scripts/check.cjs")), Path::new("scripts/check.cjs"));
    }

    #[test]
    fn checked_rewrites_measure_configured_harnesses_and_refuse_input_substitution() {
        let root = fixture();
        let mut candidate = RewriteCandidate::capture(root.path(), Instant::now() + Duration::from_secs(120)).unwrap();
        let before = fs::read(root.path().join("scripts/check.cjs")).unwrap();
        let mut after = b"// equivalent candidate\n".to_vec();
        after.extend_from_slice(&before);
        candidate.prepare(&[Replacement { path:"scripts/check.cjs", before:&before, after:&after }]).unwrap();
        let report = candidate.validate_node_pair().unwrap();
        candidate.check_validation(&report).unwrap();
        candidate.ensure_source_unchanged().unwrap();
        let input = fs::read(root.path().join("fixtures/input.bin")).unwrap();
        assert!(candidate.prepare(&[Replacement {path:"fixtures/input.bin", before:&input, after:b"different"}])
            .unwrap_err().to_string().contains("stdin bytes differ"));
    }
}
