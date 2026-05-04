use assert_cmd::Command;
use insta::Settings;
use insta::assert_snapshot;
use std::fs;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

#[path = "migrate_golden_helpers.rs"]
mod migrate_golden_helpers;

use migrate_golden_helpers::{fixture_path, pretty_json_stdout};

fn copy_fixture_to_temp(fixture: &str) -> TempDir {
    let temp_dir = TempDir::new().expect("temp project dir");
    copy_dir_recursive(&fixture_path(fixture), temp_dir.path()).expect("copy fixture project");
    temp_dir
}

fn crate_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn output_artifact_path(test_name: &str, relative_leaf: &str) -> (TempDir, PathBuf, String) {
    let root = crate_root();
    let artifact_root = root.join("target/migrate-rewrite-golden-output");
    fs::create_dir_all(&artifact_root).expect("test output artifact root");
    let temp = tempfile::Builder::new()
        .prefix(test_name)
        .tempdir_in(&artifact_root)
        .expect("test output artifact temp dir");
    let output_path = temp.path().join(relative_leaf);
    let output_arg = output_path
        .strip_prefix(&root)
        .expect("artifact path must stay below crate root")
        .to_string_lossy()
        .to_string();
    (temp, output_path, output_arg)
}

fn copy_dir_recursive(source: &Path, destination: &Path) -> std::io::Result<()> {
    fs::create_dir_all(destination)?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let source_path = entry.path();
        let destination_path = destination.join(entry.file_name());
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            copy_dir_recursive(&source_path, &destination_path)?;
        } else if file_type.is_file() {
            fs::copy(&source_path, &destination_path)?;
        }
    }
    Ok(())
}

fn with_rewrite_snapshot_settings<R>(
    project_path: &Path,
    rollback_path: &Path,
    assertion: impl FnOnce() -> R,
) -> R {
    let mut settings = Settings::clone_current();
    settings.set_snapshot_path(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/goldens")
            .join("migrate_rewrite"),
    );
    settings.set_prepend_module_to_snapshot(false);
    settings.set_omit_expression(true);
    settings.add_filter(
        &regex::escape(&rollback_path.display().to_string()),
        "[ROLLBACK_PLAN]",
    );
    settings.add_filter(
        r"target/migrate-rewrite-golden-output/\S+/rollback-plan\.json",
        "[ROLLBACK_PLAN]",
    );
    settings.add_filter(
        &regex::escape(&project_path.display().to_string()),
        "[PROJECT]",
    );
    settings.add_filter(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})?",
        "[TIMESTAMP]",
    );
    settings.bind(assertion)
}

#[test]
fn migrate_rewrite_shell_commonjs_dry_run_matches_golden() {
    let project = copy_fixture_to_temp("rewrite_shell_commonjs");
    let (_rollback_temp, rollback_path, rollback_arg) =
        output_artifact_path("shell_commonjs", "rollback-plan.json");

    let mut command = Command::cargo_bin("franken-node").expect("franken-node binary");
    let assertion = command
        .current_dir(crate_root())
        .args([
            "migrate",
            "rewrite",
            project.path().to_str().expect("utf-8 project path"),
            "--emit-rollback",
            &rollback_arg,
        ])
        .assert()
        .success();

    let stdout = String::from_utf8_lossy(&assertion.get_output().stdout);
    let stderr = String::from_utf8_lossy(&assertion.get_output().stderr);
    let rollback_json = pretty_json_stdout(
        "migrate rewrite rollback plan",
        &fs::read(&rollback_path).expect("rollback artifact written"),
    );

    with_rewrite_snapshot_settings(project.path(), &rollback_path, || {
        assert_snapshot!("shell_commonjs_stdout", stdout);
        assert_snapshot!("shell_commonjs_stderr", stderr);
        assert_snapshot!("shell_commonjs_rollback_plan", rollback_json);
    });
}
