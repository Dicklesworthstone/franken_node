//! End-to-end topology queries through the production native executable.
use serde_json::{Value, json};
use std::fs;
use std::path::Path;
use std::process::{Command, Output};
use tempfile::TempDir;

fn put(root: &Path, path: &str, value: Value) {
    let destination = root.join(path);
    fs::create_dir_all(destination.parent().unwrap()).unwrap();
    fs::write(destination, serde_json::to_vec(&value).unwrap()).unwrap();
}

fn fixture(packages: Value) -> TempDir {
    let temp = tempfile::tempdir().unwrap();
    put(temp.path(), "package.json", json!({"name":"root", "version":"1.0.0",
        "workspaces":["packages/*"], "dependencies":{"dep":"*"}}));
    put(temp.path(), "packages/a/package.json", json!({"name":"app-a", "dependencies":{"dep":"*"}}));
    put(temp.path(), "packages/b/package.json", json!({"name":"app-b", "dependencies":{"dep":"*"}}));
    put(temp.path(), "package-lock.json", json!({"lockfileVersion":3, "packages":packages}));
    temp
}

fn invoke(root: &Path, args: &[&str]) -> (Output, Value) {
    let output = Command::new(env!("CARGO_BIN_EXE_franken-module-graph"))
        .arg(root).args(args).output().unwrap();
    let value = serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|error| panic!("{error}: {}", String::from_utf8_lossy(&output.stderr)));
    (output, value)
}

fn selected(root: &Path, importer: &str, name: &str) -> Value {
    let (output, value) = invoke(root, &["--importer", importer, "--dependency", name]);
    assert!(output.status.success(), "{value}");
    value
}

#[path = "support/topology.rs"]
mod regressions;
