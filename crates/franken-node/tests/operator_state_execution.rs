//! Operator configuration and credential files are not guest source or data.
//! These regressions use the real CLI configuration resolver and native worker.
#![cfg(unix)]

use frankenengine_node::config::{Config, Profile};
use frankenengine_node::ops::engine_dispatcher::{
    EngineDispatcher, RunProjectPaths, RunTrustRequirements,
};
use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};

struct Project {
    _directory: tempfile::TempDir,
    root: PathBuf,
    state_home: PathBuf,
    config: Config,
}

impl Project {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("project");
        fs::create_dir_all(root.join("config")).unwrap();
        let mut config = Config::for_profile(Profile::LegacyRisky);
        config.synthesize_init_security_defaults();
        Self {
            state_home: directory.path().join("outside-state"),
            _directory: directory,
            root,
            config,
        }
    }

    fn write_config(&self) -> String {
        let contents = self.config.to_toml().unwrap();
        fs::write(self.root.join("config/operator.toml"), &contents).unwrap();
        contents
    }

    fn run(&self, extra: &[&str]) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_franken-node"));
        command
            .current_dir(&self.root)
            .env("XDG_STATE_HOME", &self.state_home);
        for (name, _) in std::env::vars_os() {
            if name
                .to_str()
                .is_some_and(|name| name.starts_with("FRANKEN_NODE_"))
            {
                command.env_remove(name);
            }
        }
        command
            .args([
                "run",
                "app.cjs",
                "--config",
                "config/operator.toml",
                "--runtime",
                "franken-engine",
            ])
            .args(extra)
            .output()
            .expect("execute actual franken-node CLI")
    }
}

fn combined(output: &Output) -> String {
    format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

#[test]
fn conventional_operator_aliases_retain_their_ordinary_targets() {
    use std::os::unix::fs::symlink;

    let project = Project::new();
    let root = project.root.canonicalize().unwrap();
    fs::create_dir(root.join("control-store")).unwrap();
    fs::write(root.join("control-store/index.js"), "console.log(1);\n").unwrap();
    fs::write(root.join("control-store/private.json"), "{}").unwrap();
    assert!(
        EngineDispatcher::operator_protected_paths_with_defaults(&[], &root, &root)
            .unwrap()
            .is_empty()
    );
    // Casefolded reservation also applies on a case-sensitive host.
    symlink("control-store", root.join(".FRANKEN-NODE")).unwrap();
    let retained =
        EngineDispatcher::operator_protected_paths_with_defaults(&[], &root, &root).unwrap();
    assert!(retained.contains(&root.join("control-store")));
    let requirements = RunTrustRequirements::default()
        .with_operator_protected_paths(retained)
        .unwrap();
    assert!(
        requirements
            .verify_operator_module_path(&root, "control-store/private.json")
            .is_err()
    );
    let selected = RunProjectPaths::resolve(std::path::Path::new("control-store"), &root)
        .expect("ordinary target resolves before independent operator admission");
    let retained = EngineDispatcher::operator_protected_paths_with_defaults(
        &[],
        selected.project_root(),
        &root,
    )
    .unwrap();
    assert!(
        RunTrustRequirements::default()
            .with_operator_protected_paths(retained)
            .unwrap()
            .verify_operator_source_authority(&selected)
            .is_err()
    );
    assert!(RunProjectPaths::resolve(std::path::Path::new(".FRANKEN-NODE"), &root).is_err());
}

#[test]
fn future_operator_files_retain_directory_aliases_and_wire_requirements() {
    use std::os::unix::fs::symlink;

    let project = Project::new();
    let root = project.root.canonicalize().unwrap();
    fs::create_dir(root.join("credentials")).unwrap();
    symlink("credentials", root.join("credential-alias")).unwrap();
    let retained = RunTrustRequirements::default()
        .with_operator_protected_paths(vec![root.join("credential-alias/future.key")])
        .unwrap();
    assert!(
        retained
            .operator_protected_paths()
            .contains(&root.join("credentials/future.key"))
    );
    // The source resolver records a non-directory traversal as a missing
    // target. Auditing that negative probe must preserve ordinary resolution
    // while still finding protected identities among its ancestors.
    fs::write(root.join("ordinary-file"), "ordinary").unwrap();
    fs::write(root.join("credentials/regular"), "operator").unwrap();
    symlink(
        "ordinary-file/../ordinary-file",
        root.join("non-directory-link"),
    )
    .unwrap();
    let directory_boundary = RunTrustRequirements::default()
        .with_operator_protected_paths(vec![root.join("credentials")])
        .unwrap();
    for probe in ["ordinary-file/absent.json", "non-directory-link"] {
        directory_boundary
            .verify_operator_module_path(&root, probe)
            .unwrap();
    }
    assert!(
        directory_boundary
            .verify_operator_module_path(&root, "credential-alias/regular/absent.json")
            .is_err(),
        "a negative probe through a protected alias must remain refused"
    );
    let wire = serde_json::to_value(&retained).unwrap();
    let decoded: RunTrustRequirements = serde_json::from_value(wire).unwrap();
    assert_eq!(decoded, retained);
    assert_eq!(
        serde_json::to_value(RunTrustRequirements::default()).unwrap()["operator_protected_paths"],
        serde_json::json!([])
    );
    assert!(
        RunTrustRequirements::default()
            .with_operator_protected_paths(vec![PathBuf::from("relative.key")])
            .is_err()
    );
}

#[test]
fn explicit_live_loader_is_refused_for_a_custom_in_project_config() {
    let mut project = Project::new();
    project.config.runtime.frozen_modules = Some(false);
    project.write_config();
    fs::write(
        project.root.join("app.cjs"),
        "console.log('GUEST_EXECUTED');\n",
    )
    .unwrap();
    let output = project.run(&["--json"]);
    let text = combined(&output);
    assert!(!output.status.success(), "{text}");
    assert!(text.contains("--frozen-modules"), "{text}");
    assert!(text.contains("operator state"), "{text}");
    assert!(!text.contains("GUEST_EXECUTED"), "{text}");
}

#[cfg(feature = "engine")]
#[test]
fn automatic_capture_runs_an_ordinary_project_with_custom_operator_config() {
    let project = Project::new();
    project.write_config();
    fs::write(
        project.root.join("ordinary.json"),
        r#"{"answer":"ORDINARY_MODULE_OK"}"#,
    )
    .unwrap();
    fs::write(
        project.root.join("app.cjs"),
        "console.log(require('./ordinary.json').answer);\n",
    )
    .unwrap();
    let output = project.run(&["--console-only"]);
    let text = combined(&output);
    assert!(output.status.success(), "{text}");
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("ORDINARY_MODULE_OK"),
        "{text}"
    );
}

#[cfg(feature = "engine")]
#[test]
fn guest_filesystem_read_cannot_expose_the_active_custom_config() {
    let project = Project::new();
    let original = project.write_config();
    let secret = project
        .config
        .security
        .authorized_api_keys
        .iter()
        .next()
        .unwrap();
    fs::write(project.root.join("ordinary.txt"), "ORDINARY_READ_OK").unwrap();
    fs::write(
        project.root.join("app.cjs"),
        r#"const fs = require('fs');
console.log(fs.readFileSync('ordinary.txt', 'utf8'));
console.log(fs.readFileSync('config/operator.toml', 'utf8'));
console.log('AFTER_PROTECTED_READ');
"#,
    )
    .unwrap();
    let output = project.run(&["--json"]);
    let text = combined(&output);
    assert!(!output.status.success(), "{text}");
    assert!(text.contains("ORDINARY_READ_OK"), "{text}");
    assert!(text.contains("operator_state"), "{text}");
    assert!(!text.contains("AFTER_PROTECTED_READ"), "{text}");
    assert!(!text.contains(secret), "{text}");
    assert_eq!(
        fs::read_to_string(project.root.join("config/operator.toml")).unwrap(),
        original
    );
}

#[cfg(feature = "engine")]
#[test]
fn guest_filesystem_write_cannot_replace_the_active_custom_config() {
    let project = Project::new();
    let original = project.write_config();
    fs::write(
        project.root.join("app.cjs"),
        r#"const fs = require('fs');
fs.writeFileSync('ordinary-output.txt', 'ORDINARY_WRITE_OK');
fs.writeFileSync('config/operator.toml', 'changed-by-guest');
console.log('AFTER_PROTECTED_WRITE');
"#,
    )
    .unwrap();
    let output = project.run(&["--json"]);
    let text = combined(&output);
    assert!(!output.status.success(), "{text}");
    assert_eq!(
        fs::read_to_string(project.root.join("ordinary-output.txt")).unwrap(),
        "ORDINARY_WRITE_OK"
    );
    assert!(text.contains("operator_state"), "{text}");
    assert!(!text.contains("AFTER_PROTECTED_WRITE"), "{text}");
    assert_eq!(
        fs::read_to_string(project.root.join("config/operator.toml")).unwrap(),
        original
    );
}

#[cfg(feature = "engine")]
#[test]
fn receipt_key_uses_invocation_relative_protection_before_replay_export() {
    let mut project = Project::new();
    project.config.security.decision_receipt_signing_key_path =
        Some(PathBuf::from("keys/signing.json"));
    project.write_config();
    fs::create_dir(project.root.join("keys")).unwrap();
    fs::write(
        project.root.join("keys/signing.json"),
        r#"{"secret":"PRIVATE_RECEIPT_KEY_MUST_NOT_LEAK"}"#,
    )
    .unwrap();
    fs::write(
        project.root.join("app.cjs"),
        "console.log(require('./keys/signing.json').secret);\n",
    )
    .unwrap();
    let output = project.run(&["--capture-replay", "--json"]);
    let text = combined(&output);
    assert!(!output.status.success(), "{text}");
    assert!(text.contains("protected operator state"), "{text}");
    assert!(
        !text.contains("PRIVATE_RECEIPT_KEY_MUST_NOT_LEAK"),
        "{text}"
    );
}
