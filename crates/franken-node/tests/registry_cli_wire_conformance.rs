//! Registry CLI wire conformance harness.
//!
//! This is a spec-derived, process-based harness for the operator-facing
//! `franken-node registry ...` command surface. The registry CLI currently
//! emits stable human/key-value wire output rather than `--json`; this harness
//! treats that wire format as the contract and anchors each assertion to
//! `docs/specs/section_10_0/bd-2ac_contract.md`.

use assert_cmd::Command;
use frankenengine_node::supply_chain::artifact_signing::KeyId;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;
use tempfile::TempDir;

const REGISTRY_CLI_SPEC: &str = include_str!("../../../docs/specs/section_10_0/bd-2ac_contract.md");
const REGISTRY_PUBLISH_KEY_BYTES: [u8; 32] = [42_u8; 32];

#[derive(Debug, Clone, Copy)]
struct WireClause {
    spec_marker: &'static str,
    level: &'static str,
    test_case: &'static str,
}

const WIRE_CLAUSES: &[WireClause] = &[
    WireClause {
        spec_marker: "franken-node registry publish",
        level: "MUST",
        test_case: "publish command is executable",
    },
    WireClause {
        spec_marker: "registry search",
        level: "MUST",
        test_case: "search command reports published extension rows",
    },
    WireClause {
        spec_marker: "registry publish` requires `--signing-key <path>`",
        level: "MUST",
        test_case: "publish without signing key fails closed",
    },
    WireClause {
        spec_marker: "key file must decode to a 32-byte Ed25519 private key",
        level: "MUST",
        test_case: "publish accepts an operator-managed 32-byte Ed25519 key",
    },
    WireClause {
        spec_marker: "Human-readable publish output must report the resulting `publisher_key_id`",
        level: "MUST",
        test_case: "publish output includes publisher_key_id",
    },
    WireClause {
        spec_marker: "signing-key source/path",
        level: "MUST",
        test_case: "publish output includes signing key source and path",
    },
    WireClause {
        spec_marker: "INV-SER-SIGNED",
        level: "MUST",
        test_case: "local manifest carries signature material and verifies",
    },
    WireClause {
        spec_marker: "INV-SER-PROVENANCE",
        level: "MUST",
        test_case: "local manifest carries non-empty provenance fields",
    },
];

#[test]
fn registry_cli_wire_matrix_covers_required_spec_clauses() -> Result<(), String> {
    let tested_markers = WIRE_CLAUSES
        .iter()
        .map(|clause| clause.spec_marker)
        .collect::<BTreeSet<_>>();

    assert!(
        WIRE_CLAUSES.iter().all(|clause| clause.level == "MUST"),
        "this harness intentionally covers mandatory registry CLI wire clauses"
    );
    assert!(
        WIRE_CLAUSES
            .iter()
            .all(|clause| !clause.test_case.trim().is_empty()),
        "every conformance row must name the exercised test case"
    );
    for marker in tested_markers {
        if !REGISTRY_CLI_SPEC.contains(marker) {
            return Err(format!(
                "registry conformance marker `{marker}` must remain anchored in the spec"
            ));
        }
    }

    Ok(())
}

#[test]
fn registry_publish_search_verify_gc_wire_conforms_to_contract() -> Result<(), String> {
    let workspace = registry_workspace()?;
    let signing_key_path = workspace.path().join("keys/publisher.ed25519");
    write_signing_key(&signing_key_path)?;
    let signing_key_arg = signing_key_path.to_string_lossy().to_string();
    let expected_key_id = KeyId::from_verifying_key(
        &ed25519_dalek::SigningKey::from_bytes(&REGISTRY_PUBLISH_KEY_BYTES).verifying_key(),
    )
    .to_string();

    // `--version` is a required clap arg, so it must be supplied to reach the
    // custom `--signing-key` validation this assertion targets.
    let missing_key = registry_cmd(
        &workspace,
        &["publish", "plugin.fnext", "--version", "1.0.0"],
    )?
    .assert()
    .failure()
    .get_output()
    .stderr
    .clone();
    let missing_key_stderr = String::from_utf8_lossy(&missing_key);
    assert!(
        missing_key_stderr.contains("registry publish requires --signing-key"),
        "missing-key error must name required signing key flag: {missing_key_stderr}"
    );

    let first_publish = publish_plugin(
        &workspace,
        &signing_key_arg,
        "1.0.0",
        b"first registry payload",
    )?;
    assert_eq!(
        first_publish.fields.get("status"),
        Some(&"active".to_string())
    );
    assert_eq!(
        first_publish.fields.get("publisher_key_id"),
        Some(&expected_key_id)
    );
    assert_eq!(
        first_publish.fields.get("signing_key_source"),
        Some(&"cli".to_string())
    );
    assert_eq!(
        first_publish.fields.get("signing_key_path"),
        Some(&signing_key_arg)
    );
    assert_eq!(
        first_publish.fields.get("integrity"),
        Some(&"verified".to_string())
    );
    assert_registry_relative_path(
        first_publish.required("artifact_path")?,
        ".franken-node/state/registry/artifacts/",
    )?;
    assert_registry_relative_path(
        first_publish.required("manifest_path")?,
        ".franken-node/state/registry/artifacts/",
    )?;

    let manifest = read_manifest(workspace.path(), first_publish.required("manifest_path")?)?;
    assert_manifest_wire_contract(&manifest, &expected_key_id)?;

    let verify_stdout = registry_cmd(
        &workspace,
        &["verify", first_publish.required("extension_id")?],
    )?
    .assert()
    .success()
    .get_output()
    .stdout
    .clone();
    let verify =
        parse_prefixed_fields(&String::from_utf8_lossy(&verify_stdout), "registry verify:")?;
    assert_eq!(
        verify.fields.get("extension_id"),
        first_publish.fields.get("extension_id")
    );
    assert_eq!(
        verify.fields.get("integrity"),
        Some(&"verified".to_string())
    );
    assert_eq!(verify.fields.get("archived"), Some(&"false".to_string()));

    let search_stdout = registry_cmd(&workspace, &["search", "plugin", "--min-assurance", "1"])?
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    assert_search_wire_row(
        &String::from_utf8_lossy(&search_stdout),
        first_publish.required("extension_id")?,
        "verified",
    )?;

    let _second_publish = publish_plugin(
        &workspace,
        &signing_key_arg,
        "2.0.0",
        b"second registry payload",
    )?;
    let gc_stdout = registry_cmd(&workspace, &["gc", "--keep", "1"])?
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let gc = parse_prefixed_fields(&String::from_utf8_lossy(&gc_stdout), "registry gc:")?;
    assert_eq!(gc.fields.get("keep"), Some(&"1".to_string()));
    assert_eq!(gc.fields.get("lineages"), Some(&"1".to_string()));
    assert_eq!(gc.fields.get("archived"), Some(&"1".to_string()));
    assert_registry_relative_path(
        gc.required("archive_root")?,
        ".franken-node/state/registry/archive",
    )?;

    let archived_verify_stdout = registry_cmd(
        &workspace,
        &["verify", first_publish.required("extension_id")?],
    )?
    .assert()
    .success()
    .get_output()
    .stdout
    .clone();
    let archived_verify = parse_prefixed_fields(
        &String::from_utf8_lossy(&archived_verify_stdout),
        "registry verify:",
    )?;
    assert_eq!(
        archived_verify.fields.get("integrity"),
        Some(&"verified".to_string())
    );
    assert_eq!(
        archived_verify.fields.get("archived"),
        Some(&"true".to_string())
    );
    assert_registry_relative_path(
        archived_verify.required("manifest_path")?,
        ".franken-node/state/registry/archive/",
    )?;

    Ok(())
}

#[derive(Debug)]
struct ParsedFields {
    fields: BTreeMap<String, String>,
}

impl ParsedFields {
    fn required(&self, field: &str) -> Result<&str, String> {
        self.fields
            .get(field)
            .map(String::as_str)
            .ok_or_else(|| format!("missing `{field}` in parsed fields: {:?}", self.fields))
    }
}

fn registry_workspace() -> Result<TempDir, String> {
    let dir = tempfile::tempdir().map_err(|err| format!("tempdir: {err}"))?;
    fs::write(dir.path().join("plugin.fnext"), b"initial registry payload")
        .map_err(|err| format!("write package: {err}"))?;
    run_git(dir.path(), &["init", "-b", "main"])?;
    run_git(
        dir.path(),
        &["config", "user.email", "registry@example.com"],
    )?;
    run_git(
        dir.path(),
        &["config", "user.name", "Registry Wire Conformance"],
    )?;
    run_git(
        dir.path(),
        &[
            "remote",
            "add",
            "origin",
            "https://example.com/acme/plugin.git",
        ],
    )?;
    run_git(dir.path(), &["add", "plugin.fnext"])?;
    run_git(dir.path(), &["commit", "-m", "initial"])?;
    Ok(dir)
}

fn run_git(workspace: &Path, args: &[&str]) -> Result<(), String> {
    let status = std::process::Command::new("git")
        .current_dir(workspace)
        .args(args)
        .status()
        .map_err(|err| format!("failed running `git {}`: {err}", args.join(" ")))?;
    if !status.success() {
        return Err(format!("git command failed: git {}", args.join(" ")));
    }
    Ok(())
}

fn write_signing_key(path: &Path) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|err| format!("create key dir: {err}"))?;
    }
    fs::write(path, hex::encode(REGISTRY_PUBLISH_KEY_BYTES))
        .map_err(|err| format!("write signing key {}: {err}", path.display()))
}

fn publish_plugin(
    workspace: &TempDir,
    signing_key_arg: &str,
    version: &str,
    payload: &[u8],
) -> Result<ParsedFields, String> {
    fs::write(workspace.path().join("plugin.fnext"), payload)
        .map_err(|err| format!("rewrite package: {err}"))?;
    run_git(workspace.path(), &["add", "plugin.fnext"])?;
    run_git(workspace.path(), &["commit", "-m", "update-plugin"])?;

    let output = registry_cmd(
        workspace,
        &[
            "publish",
            "plugin.fnext",
            "--version",
            version,
            "--signing-key",
            signing_key_arg,
        ],
    )?
    .assert()
    .success()
    .get_output()
    .stdout
    .clone();
    parse_prefixed_fields(&String::from_utf8_lossy(&output), "registry publish:")
}

fn registry_cmd(workspace: &TempDir, args: &[&str]) -> Result<Command, String> {
    let mut cmd = Command::cargo_bin("franken-node")
        .map_err(|err| format!("franken-node binary should resolve: {err}"))?;
    cmd.current_dir(workspace.path()).arg("registry").args(args);
    Ok(cmd)
}

fn parse_prefixed_fields(stdout: &str, prefix: &str) -> Result<ParsedFields, String> {
    let line = stdout
        .lines()
        .find(|line| line.starts_with(prefix))
        .ok_or_else(|| format!("missing `{prefix}` line in stdout:\n{stdout}"))?;
    let fields = line[prefix.len()..]
        .split_whitespace()
        .filter_map(|token| {
            token
                .split_once('=')
                .map(|(key, value)| (key.to_string(), value.to_string()))
        })
        .collect::<BTreeMap<_, _>>();
    Ok(ParsedFields { fields })
}

fn assert_registry_relative_path(path: &str, expected_prefix: &str) -> Result<(), String> {
    if !path.starts_with(expected_prefix) {
        return Err(format!(
            "registry path `{path}` must start with `{expected_prefix}`"
        ));
    }
    if path.contains("..") || path.starts_with('/') || path.contains('\\') || path.contains('\0') {
        return Err(format!(
            "registry path `{path}` must be relative and traversal-safe"
        ));
    }
    Ok(())
}

fn read_manifest(workspace: &Path, relative_path: &str) -> Result<Value, String> {
    assert_registry_relative_path(relative_path, ".franken-node/state/registry/artifacts/")?;
    let manifest_path = workspace.join(relative_path);
    let raw = fs::read_to_string(&manifest_path)
        .map_err(|err| format!("read manifest {}: {err}", manifest_path.display()))?;
    serde_json::from_str(&raw)
        .map_err(|err| format!("parse manifest {}: {err}", manifest_path.display()))
}

fn assert_manifest_wire_contract(manifest: &Value, expected_key_id: &str) -> Result<(), String> {
    assert_eq!(
        manifest["schema_version"].as_str(),
        Some("franken-node/local-registry-artifact-manifest/v1")
    );
    expect_prefixed_string(manifest, "artifact_sha256", "sha256:")?;
    assert!(
        manifest["artifact_size_bytes"]
            .as_u64()
            .is_some_and(|size| size > 0),
        "manifest artifact_size_bytes must be a positive integer"
    );
    expect_non_empty_string(manifest, "manifest_bytes_b64")?;
    expect_non_empty_string(manifest, "publisher_public_key_hex")?;

    let extension = manifest
        .get("extension")
        .and_then(Value::as_object)
        .ok_or_else(|| "manifest.extension must be an object".to_string())?;
    assert_eq!(
        extension.get("status").and_then(Value::as_str),
        Some("active")
    );
    assert_eq!(
        extension
            .get("signature")
            .and_then(|signature| signature.get("key_id"))
            .and_then(Value::as_str),
        Some(expected_key_id)
    );
    expect_nested_non_empty_string(extension, &["signature", "algorithm"])?;
    let signature_bytes = extension
        .get("signature")
        .and_then(|signature| signature.get("signature_bytes"))
        .and_then(Value::as_array)
        .ok_or_else(|| "signature.signature_bytes must be an array".to_string())?;
    assert_eq!(
        signature_bytes.len(),
        64,
        "signature.signature_bytes must carry an Ed25519 signature"
    );
    expect_non_empty_map_string(extension, "publisher_id")?;
    for field in [
        "source_repository_url",
        "build_system_identifier",
        "builder_identity",
        "vcs_commit_sha",
        "reproducibility_hash",
        "input_hash",
        "output_hash",
    ] {
        expect_nested_non_empty_string(extension, &["provenance", field])?;
    }
    assert!(
        extension
            .get("provenance")
            .and_then(|provenance| provenance.get("links"))
            .and_then(Value::as_array)
            .is_some_and(|links| !links.is_empty()),
        "manifest.extension.provenance.links must contain the attestation chain"
    );
    assert!(
        extension
            .get("versions")
            .and_then(Value::as_array)
            .is_some_and(|versions| !versions.is_empty()),
        "manifest.extension.versions must contain a registered version"
    );

    Ok(())
}

fn expect_prefixed_string(value: &Value, field: &str, prefix: &str) -> Result<(), String> {
    let actual = expect_non_empty_string(value, field)?;
    if !actual.starts_with(prefix) {
        return Err(format!(
            "{field} value `{actual}` must start with `{prefix}`"
        ));
    }
    Ok(())
}

fn expect_non_empty_string<'a>(value: &'a Value, field: &str) -> Result<&'a str, String> {
    value
        .get(field)
        .and_then(Value::as_str)
        .filter(|text| !text.trim().is_empty())
        .ok_or_else(|| format!("{field} must be a non-empty string"))
}

fn expect_non_empty_map_string<'a>(
    object: &'a serde_json::Map<String, Value>,
    field: &str,
) -> Result<&'a str, String> {
    object
        .get(field)
        .and_then(Value::as_str)
        .filter(|text| !text.trim().is_empty())
        .ok_or_else(|| format!("{field} must be a non-empty string"))
}

fn expect_nested_non_empty_string<'a>(
    object: &'a serde_json::Map<String, Value>,
    path: &[&str],
) -> Result<&'a str, String> {
    let mut current = object
        .get(path[0])
        .ok_or_else(|| format!("{} missing", path.join(".")))?;
    for segment in &path[1..] {
        current = current
            .get(*segment)
            .ok_or_else(|| format!("{} missing", path.join(".")))?;
    }
    current
        .as_str()
        .filter(|text| !text.trim().is_empty())
        .ok_or_else(|| format!("{} must be a non-empty string", path.join(".")))
}

fn assert_search_wire_row(
    stdout: &str,
    extension_id: &str,
    expected_integrity: &str,
) -> Result<(), String> {
    let mut lines = stdout.lines();
    let header = lines
        .next()
        .ok_or_else(|| format!("search stdout must include header: {stdout}"))?;
    if !header.starts_with("registry search: query=`plugin` min_assurance=1") {
        return Err(format!("unexpected registry search header: {header}"));
    }
    let columns = lines
        .next()
        .ok_or_else(|| format!("search stdout must include columns: {stdout}"))?;
    assert_eq!(
        columns,
        "extension_id | name | publisher | status | assurance | artifact_path | integrity"
    );
    let separator = lines
        .next()
        .ok_or_else(|| format!("search stdout must include separator: {stdout}"))?;
    assert_eq!(
        separator,
        "------------ | ---- | --------- | ------ | --------- | ------------- | ---------"
    );

    let row = lines
        .find(|line| line.starts_with(extension_id))
        .ok_or_else(|| format!("search stdout missing extension row {extension_id}:\n{stdout}"))?;
    let cells = row.split(" | ").collect::<Vec<_>>();
    if cells.len() != 7 {
        return Err(format!("search row must contain 7 cells, got {cells:?}"));
    }
    assert_eq!(cells[0], extension_id);
    assert_eq!(cells[1], "plugin");
    assert_eq!(cells[3], "active");
    assert_registry_relative_path(cells[5], ".franken-node/state/registry/artifacts/")?;
    assert_eq!(cells[6], expected_integrity);
    Ok(())
}
