use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::{Arc, Mutex, Once};
use std::thread;
use std::time::{Duration, Instant};

use frankenengine_node::control_plane::fleet_transport::{
    FileFleetTransport, FleetAction, FleetTransport, NodeHealth, NodeStatus,
};
use frankenengine_node::supply_chain::trust_card::{
    TrustCardListFilter, TrustCardMutation, TrustCardRegistry, fixture_registry,
};
use serde_json::Value;

const FIXTURE_RECEIPT_KEY_ID: &str = "72416df9f1dcd9b3";

static TEST_TRACING_INIT: Once = Once::new();

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|path| path.parent())
        .expect("workspace root")
        .to_path_buf()
}

fn resolve_binary_path() -> PathBuf {
    if let Some(exe) = std::env::var_os("CARGO_BIN_EXE_franken-node") {
        return PathBuf::from(exe);
    }
    repo_root().join("target/debug/franken-node")
}

fn run_cli_in_workspace(workspace: &Path, args: &[&str]) -> Output {
    run_cli_in_workspace_with_env(workspace, args, &[])
}

fn run_cli_in_workspace_with_env(workspace: &Path, args: &[&str], env: &[(&str, &str)]) -> Output {
    let binary_path = resolve_binary_path();
    assert!(
        binary_path.is_file(),
        "franken-node binary not found at {}",
        binary_path.display()
    );
    let mut command = Command::new(&binary_path);
    command.current_dir(workspace).args(args);
    for (key, value) in env {
        command.env(key, value);
    }
    command
        .output()
        .unwrap_or_else(|err| panic!("failed running `{}`: {err}", args.join(" ")))
}

fn read_http_request(stream: &mut impl Read) -> String {
    let mut buffer = Vec::new();
    let mut chunk = [0_u8; 1024];

    loop {
        let bytes_read = stream.read(&mut chunk).expect("read request chunk");
        if bytes_read == 0 {
            break;
        }
        buffer.extend_from_slice(&chunk[..bytes_read]);

        let Some(headers_end) = buffer.windows(4).position(|window| window == b"\r\n\r\n") else {
            continue;
        };
        let headers = String::from_utf8_lossy(&buffer[..headers_end + 4]);
        let content_length = headers
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("Content-Length")
                    .then(|| value.trim().parse::<usize>().ok())
                    .flatten()
            })
            .unwrap_or(0);
        let total_length = headers_end + 4 + content_length;
        if buffer.len() >= total_length {
            break;
        }
    }

    String::from_utf8_lossy(&buffer).to_string()
}

fn spawn_osv_fixture_server() -> (String, Arc<Mutex<Vec<String>>>, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind OSV fixture server");
    let address = format!("http://{}", listener.local_addr().expect("local addr"));
    let requests = Arc::new(Mutex::new(Vec::new()));
    let captured_requests = Arc::clone(&requests);

    let handle = thread::spawn(move || {
        for stream in listener.incoming().take(2) {
            let mut stream = stream.expect("accept fixture connection");
            let request = read_http_request(&mut stream);
            let body = request
                .split("\r\n\r\n")
                .nth(1)
                .unwrap_or_default()
                .to_string();
            captured_requests
                .lock()
                .expect("lock requests")
                .push(body.clone());

            let (status_code, status_text, response_body) = if body.contains("\"@acme/auth-guard\"")
            {
                (
                    200,
                    "OK",
                    r#"{"vulns":[{"id":"OSV-2026-0001"}]}"#.to_string(),
                )
            } else if body.contains("\"@beta/telemetry-bridge\"") {
                (
                    503,
                    "Service Unavailable",
                    r#"{"error":"upstream unavailable"}"#.to_string(),
                )
            } else {
                (
                    404,
                    "Not Found",
                    r#"{"error":"unexpected package"}"#.to_string(),
                )
            };

            let response = format!(
                "HTTP/1.1 {status_code} {status_text}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                response_body.len(),
                response_body
            );
            stream
                .write_all(response.as_bytes())
                .expect("write fixture response");
        }
    });

    (format!("{address}/query"), requests, handle)
}

fn spawn_osv_observer_server() -> (String, Arc<Mutex<usize>>, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind observer server");
    listener
        .set_nonblocking(true)
        .expect("set observer listener nonblocking");
    let address = format!("http://{}", listener.local_addr().expect("local addr"));
    let request_count = Arc::new(Mutex::new(0_usize));
    let captured_count = Arc::clone(&request_count);

    let handle = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let _ = read_http_request(&mut stream);
                    *captured_count.lock().expect("lock observer count") += 1;
                    let response_body = r#"{"vulns":[]}"#;
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        response_body.len(),
                        response_body
                    );
                    stream
                        .write_all(response.as_bytes())
                        .expect("write observer response");
                }
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(err) => panic!("observer accept failed: {err}"),
            }
        }
    });

    (format!("{address}/query"), request_count, handle)
}

fn seeded_fixture_trust_workspace_with_timestamp(now_secs: u64) -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    fs::write(
        dir.path().join("franken_node.toml"),
        "profile = \"balanced\"\n",
    )
    .expect("write config");

    let registry = fixture_registry(now_secs).expect("fixture registry");
    let path = dir
        .path()
        .join(".franken-node/state/trust-card-registry.v1.json");
    registry
        .persist_authoritative_state(&path)
        .expect("persist trust registry");
    fs::write(
        dir.path()
            .join(".franken-node/state/trust-card-registry.fixture-source.json"),
        concat!(
            "{\n",
            "  \"source_helper\": \"fixture_registry\",\n",
            "  \"purpose\": \"trust-cli-e2e deterministic fixture seed\",\n",
            "  \"authoritative_state_path\": \".franken-node/state/trust-card-registry.v1.json\"\n",
            "}\n"
        ),
    )
    .expect("write fixture metadata");
    dir
}

fn seeded_fixture_trust_workspace() -> tempfile::TempDir {
    seeded_fixture_trust_workspace_with_timestamp(1_000)
}

fn rewrite_fixture_last_verified_timestamps(workspace: &Path, now_secs: u64) {
    let registry_path = workspace.join(".franken-node/state/trust-card-registry.v1.json");
    let mut registry = TrustCardRegistry::load_authoritative_state(&registry_path, 60, now_secs)
        .expect("load authoritative trust registry");
    let cards = registry
        .list(
            &TrustCardListFilter::empty(),
            "trace-cli-test-refresh-list",
            now_secs,
        )
        .expect("list authoritative trust registry");
    let timestamp = chrono::DateTime::from_timestamp(now_secs as i64, 0)
        .expect("valid test timestamp")
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);

    for card in cards {
        registry
            .update(
                &card.extension.extension_id,
                TrustCardMutation {
                    certification_level: None,
                    revocation_status: None,
                    active_quarantine: None,
                    reputation_score_basis_points: None,
                    reputation_trend: None,
                    user_facing_risk_assessment: None,
                    last_verified_timestamp: Some(timestamp.clone()),
                    evidence_refs: None,
                },
                now_secs,
                "trace-cli-test-refresh-update",
            )
            .expect("refresh trust card timestamp");
    }

    registry
        .persist_authoritative_state(&registry_path)
        .expect("persist refreshed trust registry");
}

fn config_only_workspace() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    fs::write(
        dir.path().join("franken_node.toml"),
        "profile = \"balanced\"\n",
    )
    .expect("write config");
    dir
}

fn scannable_trust_workspace() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    fs::write(
        dir.path().join("franken_node.toml"),
        "profile = \"balanced\"\n",
    )
    .expect("write config");
    fs::write(
        dir.path().join("package.json"),
        r#"{
  "name": "scan-fixture",
  "version": "1.0.0",
  "dependencies": {
    "react": "^19.2.0"
  },
  "devDependencies": {
    "typescript": "^5.8.3"
  },
  "optionalDependencies": {
    "@types/node": "^24.9.2"
  }
}
"#,
    )
    .expect("write package manifest");
    fs::write(
        dir.path().join("package-lock.json"),
        r#"{
  "name": "scan-fixture",
  "lockfileVersion": 3,
  "packages": {
    "": {
      "name": "scan-fixture",
      "version": "1.0.0"
    },
    "node_modules/react": {
      "version": "19.2.4",
      "integrity": "sha512-AQIDBA=="
    },
    "node_modules/typescript": {
      "version": "5.8.3",
      "integrity": "sha512-BQYHCA=="
    },
    "node_modules/@types/node": {
      "version": "24.9.2",
      "integrity": "sha512-CQoLDA=="
    }
  }
}
"#,
    )
    .expect("write package lockfile");
    dir
}

fn write_run_package_manifest(workspace: &Path, dependencies: &[(&str, &str)]) {
    let dependency_map = dependencies
        .iter()
        .map(|(name, version)| ((*name).to_string(), Value::String((*version).to_string())))
        .collect::<serde_json::Map<String, Value>>();
    let manifest = serde_json::json!({
        "name": "trust-gate-e2e",
        "version": "1.0.0",
        "main": "index.js",
        "dependencies": dependency_map,
    });
    fs::write(
        workspace.join("package.json"),
        serde_json::to_string_pretty(&manifest).expect("manifest"),
    )
    .expect("write package.json");
    fs::write(workspace.join("index.js"), "console.log('hello');\n").expect("write index.js");
}

#[cfg(unix)]
fn write_fake_runtime(runtime_dir: &Path, name: &str, marker: &str) {
    use std::os::unix::fs::PermissionsExt;

    fs::create_dir_all(runtime_dir).expect("create runtime dir");
    let script_path = runtime_dir.join(name);
    fs::write(
        &script_path,
        format!(
            "#!/bin/sh\nprintf 'runtime={marker} target=%s policy=%s\\n' \"$1\" \"$FRANKEN_NODE_REQUESTED_POLICY_MODE\"\n"
        ),
    )
    .expect("write fake runtime");
    let mut permissions = fs::metadata(&script_path).expect("metadata").permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&script_path, permissions).expect("chmod fake runtime");
}

fn parse_json_stdout(output: &Output, context: &str) -> Value {
    let stdout = String::from_utf8_lossy(&output.stdout);
    serde_json::from_str(&stdout)
        .unwrap_or_else(|err| panic!("{context} should emit valid JSON: {err}\nstdout:\n{stdout}"))
}

fn parse_json_stderr(output: &Output, context: &str) -> Value {
    let stderr = String::from_utf8_lossy(&output.stderr);
    serde_json::from_str(&stderr)
        .unwrap_or_else(|err| panic!("{context} should emit valid JSON: {err}\nstderr:\n{stderr}"))
}

fn init_test_tracing() {
    TEST_TRACING_INIT.call_once(|| {
        let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    });
}

fn log_pipeline_step(step_number: usize, step_name: &str, expected_outcome: &str) {
    init_test_tracing();
    tracing::info!(step_number, step_name, expected_outcome);
}

fn manifest_dependency_map(entries: &[(&str, &str)]) -> serde_json::Map<String, Value> {
    entries
        .iter()
        .map(|(name, version)| ((*name).to_string(), Value::String((*version).to_string())))
        .collect()
}

fn write_pipeline_package_manifest(
    workspace: &Path,
    dependencies: &[(&str, &str)],
    dev_dependencies: &[(&str, &str)],
    optional_dependencies: &[(&str, &str)],
) {
    let manifest = serde_json::json!({
        "name": "full-pipeline-e2e",
        "version": "1.0.0",
        "main": "index.js",
        "dependencies": manifest_dependency_map(dependencies),
        "devDependencies": manifest_dependency_map(dev_dependencies),
        "optionalDependencies": manifest_dependency_map(optional_dependencies),
    });
    fs::write(
        workspace.join("package.json"),
        serde_json::to_string_pretty(&manifest).expect("manifest"),
    )
    .expect("write package.json");
    fs::write(workspace.join("index.js"), "console.log('pipeline ok');\n").expect("write index.js");
}

fn write_pipeline_lockfile(workspace: &Path) {
    fs::write(
        workspace.join("package-lock.json"),
        r#"{
  "name": "full-pipeline-e2e",
  "lockfileVersion": 3,
  "packages": {
    "": {
      "name": "full-pipeline-e2e",
      "version": "1.0.0"
    },
    "node_modules/react": {
      "version": "19.2.4",
      "integrity": "sha512-AQIDBA=="
    },
    "node_modules/typescript": {
      "version": "5.8.3",
      "integrity": "sha512-BQYHCA=="
    },
    "node_modules/@types/node": {
      "version": "24.9.2",
      "integrity": "sha512-CQoLDA=="
    }
  }
}
"#,
    )
    .expect("write package lockfile");
}

#[cfg(unix)]
fn runtime_bin_path(name: &str) -> PathBuf {
    let path = std::env::var_os("PATH").expect("PATH must be set for runtime discovery");
    std::env::split_paths(&path)
        .map(|dir| dir.join(name))
        .find(|candidate| candidate.is_file())
        .unwrap_or_else(|| panic!("required runtime `{name}` missing from PATH"))
}

#[cfg(unix)]
fn runtime_path_env(required: &[&str]) -> String {
    let mut directories = Vec::new();
    for name in required {
        let parent = runtime_bin_path(name)
            .parent()
            .expect("runtime parent dir")
            .to_path_buf();
        if !directories.iter().any(|existing: &PathBuf| existing == &parent) {
            directories.push(parent);
        }
    }
    std::env::join_paths(directories)
        .expect("join runtime PATH")
        .to_string_lossy()
        .into_owned()
}

fn write_runtime_probe_script(workspace: &Path, entrypoint: &str, marker: &str) {
    fs::write(
        workspace.join(entrypoint),
        format!(
            r#"const path = require("path");
console.log(JSON.stringify({{
  marker: "{marker}",
  runtime: path.basename(process.argv0),
  release: process.release?.name ?? null,
  policy: process.env.FRANKEN_NODE_REQUESTED_POLICY_MODE ?? null
}}));
"#
        ),
    )
    .expect("write runtime probe script");
}

fn parse_captured_runtime_probe(run_payload: &Value, context: &str) -> Value {
    let stdout = run_payload["dispatch"]["captured_output"]["stdout"]
        .as_str()
        .unwrap_or_else(|| panic!("{context} should capture runtime stdout"));
    let trimmed = stdout.trim();
    serde_json::from_str(trimmed).unwrap_or_else(|err| {
        panic!("{context} should capture a runtime probe json line: {err}\nstdout:\n{trimmed}")
    })
}

fn collect_workspace_entries(root: &Path, current: &Path, entries: &mut Vec<String>) {
    let mut children = fs::read_dir(current)
        .unwrap_or_else(|err| panic!("read_dir {}: {err}", current.display()))
        .map(|entry| entry.expect("dir entry").path())
        .collect::<Vec<_>>();
    children.sort();

    for child in children {
        let relative = child
            .strip_prefix(root)
            .expect("child under root")
            .display()
            .to_string();
        if child.is_dir() {
            entries.push(format!("{relative}/"));
            collect_workspace_entries(root, &child, entries);
        } else {
            entries.push(relative);
        }
    }
}

fn collect_state_file_dumps(root: &Path, current: &Path, dumps: &mut Vec<String>) {
    let mut children = fs::read_dir(current)
        .unwrap_or_else(|err| panic!("read_dir {}: {err}", current.display()))
        .map(|entry| entry.expect("dir entry").path())
        .collect::<Vec<_>>();
    children.sort();

    for child in children {
        if child.is_dir() {
            collect_state_file_dumps(root, &child, dumps);
            continue;
        }

        let relative = child
            .strip_prefix(root)
            .expect("state file under root")
            .display()
            .to_string();
        let raw = fs::read(&child).unwrap_or_else(|err| panic!("read {}: {err}", child.display()));
        dumps.push(format!(
            "-- {relative} --\n{}",
            if raw.len() > 4_096 {
                format!("{}...\n<truncated>", String::from_utf8_lossy(&raw[..4_096]))
            } else {
                String::from_utf8_lossy(&raw).into_owned()
            }
        ));
    }
}

fn workspace_diagnostics(workspace: &Path) -> String {
    let mut entries = Vec::new();
    collect_workspace_entries(workspace, workspace, &mut entries);
    let listing = if entries.is_empty() {
        "<empty>".to_string()
    } else {
        entries.join("\n")
    };

    let state_root = workspace.join(".franken-node/state");
    let state_dump = if state_root.is_dir() {
        let mut dumps = Vec::new();
        collect_state_file_dumps(workspace, &state_root, &mut dumps);
        if dumps.is_empty() {
            "<state dir empty>".to_string()
        } else {
            dumps.join("\n")
        }
    } else {
        "<state dir missing>".to_string()
    };

    format!("workspace files:\n{listing}\n\nstate files:\n{state_dump}")
}

fn panic_with_command_diagnostics(
    context: &str,
    workspace: &Path,
    args: &[&str],
    output: &Output,
) -> ! {
    panic!(
        "{context} failed\ncommand: franken-node {}\nstatus: {}\nstdout:\n{}\nstderr:\n{}\n{}",
        args.join(" "),
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
        workspace_diagnostics(workspace),
    );
}

fn ensure_command_success(context: &str, workspace: &Path, args: &[&str], output: &Output) {
    if !output.status.success() {
        panic_with_command_diagnostics(context, workspace, args, output);
    }
}

fn read_json_file(path: &Path, context: &str) -> Value {
    let raw = fs::read_to_string(path)
        .unwrap_or_else(|err| panic!("failed reading {context} {}: {err}", path.display()));
    serde_json::from_str(&raw)
        .unwrap_or_else(|err| panic!("failed parsing {context} {} as json: {err}", path.display()))
}

fn shared_fleet_transport(shared_state_dir: &Path) -> FileFleetTransport {
    let mut transport = FileFleetTransport::new(shared_state_dir);
    transport.initialize().expect("initialize fleet transport");
    transport
}

fn write_receipt_signing_key(path: &Path) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("create key dir");
    }
    fs::write(path, hex::encode([42_u8; 32])).expect("write receipt signing key");
}

#[test]
fn trust_card_displays_known_extension_details() {
    let workspace = seeded_fixture_trust_workspace();
    let output = run_cli_in_workspace(workspace.path(), &["trust", "card", "npm:@acme/auth-guard"]);
    assert!(
        output.status.success(),
        "trust card failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("extension: npm:@acme/auth-guard@1.4.2"));
    assert!(stdout.contains("publisher: Acme Security"));
    assert!(stdout.contains("risk: Low"));
}

#[cfg(unix)]
#[test]
fn run_missing_registry_suggests_init_scan() {
    let workspace = config_only_workspace();
    write_run_package_manifest(workspace.path(), &[("@acme/auth-guard", "^1.4.2")]);
    let runtime_dir = workspace.path().join("fake-bin");
    write_fake_runtime(&runtime_dir, "node", "node");

    let output = run_cli_in_workspace_with_env(
        workspace.path(),
        &["run", "--policy", "strict", "--runtime", "node", "."],
        &[
            ("PATH", runtime_dir.to_str().expect("utf8 path")),
            ("FRANKEN_ENGINE_BIN", ""),
            ("FRANKEN_NODE_ENGINE_BINARY_PATH", ""),
        ],
    );

    assert!(
        output.status.success(),
        "run should succeed when the registry is missing but the runtime exists: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("authoritative trust registry missing"));
    assert!(stderr.contains("fix_command=franken-node init --profile strict --scan"));
}

#[test]
fn run_json_emits_blocked_preflight_verdict_for_revoked_dependency() {
    let workspace = seeded_fixture_trust_workspace();
    write_run_package_manifest(workspace.path(), &[("@beta/telemetry-bridge", "^0.9.1")]);

    let output = run_cli_in_workspace(
        workspace.path(),
        &["run", "--policy", "strict", "--json", "."],
    );
    assert!(
        !output.status.success(),
        "run should block on revoked dependency"
    );

    let payload = parse_json_stdout(&output, "run --json blocked preflight");
    assert_eq!(payload["verdict"]["status"], "blocked");
    let violations = payload["verdict"]["violations"]
        .as_array()
        .expect("violations array");
    assert!(
        violations
            .iter()
            .any(|violation| violation["kind"] == "revoked")
    );
    assert_eq!(
        payload["receipt"]["action_name"],
        "run_preflight_trust_gate"
    );
    assert_eq!(payload["receipt"]["decision"], "denied");
}

#[test]
fn run_blocked_preflight_error_suggests_trust_list() {
    let workspace = seeded_fixture_trust_workspace();
    write_run_package_manifest(workspace.path(), &[("@beta/telemetry-bridge", "^0.9.1")]);

    let output = run_cli_in_workspace(workspace.path(), &["run", "--policy", "strict", "."]);
    assert!(
        !output.status.success(),
        "run should block on revoked dependency"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("run blocked by trust preflight"));
    assert!(stderr.contains("fix_command=franken-node trust list --revoked true"));
}

#[cfg(unix)]
#[test]
fn run_explicit_runtime_missing_returns_127() {
    let workspace = seeded_fixture_trust_workspace();
    write_run_package_manifest(workspace.path(), &[]);
    let empty_path = workspace.path().join("empty-bin");
    fs::create_dir_all(&empty_path).expect("create empty PATH dir");

    let output = run_cli_in_workspace_with_env(
        workspace.path(),
        &["run", "--policy", "balanced", "--runtime", "node", "."],
        &[
            ("PATH", empty_path.to_str().expect("utf8 path")),
            ("FRANKEN_ENGINE_BIN", ""),
            ("FRANKEN_NODE_ENGINE_BINARY_PATH", ""),
        ],
    );

    assert_eq!(output.status.code(), Some(127));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("requested runtime `node` was not found"));
    assert!(stderr.contains("fix_command=franken-node run --runtime auto ."));
    assert!(stderr.contains("help_url=https://nodejs.org/en/download"));
    assert!(stderr.contains("help_url=https://bun.sh/docs/installation"));
}

#[cfg(unix)]
#[test]
fn run_respects_configured_preferred_runtime_over_bun_heuristics() {
    let workspace = seeded_fixture_trust_workspace();
    fs::write(
        workspace.path().join("package.json"),
        serde_json::to_string_pretty(&serde_json::json!({
            "name": "trust-gate-e2e",
            "version": "1.0.0",
            "main": "index.js",
            "packageManager": "bun@1.2.0",
            "dependencies": {}
        }))
        .expect("manifest"),
    )
    .expect("write package.json");
    write_runtime_probe_script(workspace.path(), "index.js", "preferred-runtime");
    fs::write(workspace.path().join("bun.lockb"), "").expect("write bun.lockb");
    fs::write(
        workspace.path().join("franken_node.toml"),
        r#"
[runtime]
preferred = "node"
"#,
    )
    .expect("write config");

    let runtime_path = runtime_path_env(&["node", "bun"]);

    let output = run_cli_in_workspace_with_env(
        workspace.path(),
        &["run", "--policy", "balanced", "--json", "."],
        &[
            ("PATH", runtime_path.as_str()),
            ("FRANKEN_ENGINE_BIN", ""),
            ("FRANKEN_NODE_ENGINE_BINARY_PATH", ""),
        ],
    );

    assert!(
        output.status.success(),
        "run should succeed with configured preferred runtime: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let preflight_payload = parse_json_stderr(&output, "preferred runtime preflight");
    let run_payload = parse_json_stdout(&output, "preferred runtime completion");
    let runtime_probe =
        parse_captured_runtime_probe(&run_payload, "preferred runtime captured output");

    assert_eq!(preflight_payload["verdict"]["status"], "passed");
    assert_eq!(run_payload["dispatch"]["runtime"], "node");
    assert_eq!(runtime_probe["marker"], "preferred-runtime");
    assert_eq!(runtime_probe["runtime"], "node");
    assert_eq!(runtime_probe["release"], "node");
    assert_eq!(runtime_probe["policy"], "balanced");
}

#[test]
fn trust_list_filters_critical_revoked_cards() {
    let workspace = seeded_fixture_trust_workspace();
    let output = run_cli_in_workspace(
        workspace.path(),
        &["trust", "list", "--risk", "critical", "--revoked", "true"],
    );
    assert!(
        output.status.success(),
        "trust list failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("npm:@beta/telemetry-bridge"));
    assert!(stdout.contains("revoked:publisher key compromised"));
    assert!(!stdout.contains("npm:@acme/auth-guard"));
}

#[test]
fn trust_list_filters_low_active_cards() {
    let workspace = seeded_fixture_trust_workspace();
    let output = run_cli_in_workspace(
        workspace.path(),
        &["trust", "list", "--risk", "low", "--revoked", "false"],
    );
    assert!(
        output.status.success(),
        "trust list failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("npm:@acme/auth-guard"));
    assert!(stdout.contains("active"));
    assert!(!stdout.contains("npm:@beta/telemetry-bridge"));
}

#[test]
fn trust_list_rejects_unknown_risk_value() {
    let output = run_cli_in_workspace(
        repo_root().as_path(),
        &["trust", "list", "--risk", "severe"],
    );
    assert!(
        !output.status.success(),
        "expected failure for unknown risk, got status {}",
        output.status
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("invalid --risk `severe`"));
}

#[test]
fn trust_revoke_marks_target_as_revoked() {
    let workspace = seeded_fixture_trust_workspace();
    let output = run_cli_in_workspace(
        workspace.path(),
        &["trust", "revoke", "npm:@acme/auth-guard"],
    );
    assert!(
        output.status.success(),
        "trust revoke failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("extension: npm:@acme/auth-guard@1.4.2"));
    assert!(stdout.contains("revocation: revoked (manual revoke via franken-node trust revoke)"));
    assert!(stdout.contains("quarantine: true"));

    let persisted =
        run_cli_in_workspace(workspace.path(), &["trust", "card", "npm:@acme/auth-guard"]);
    assert!(
        persisted.status.success(),
        "persisted trust card read failed: {}",
        String::from_utf8_lossy(&persisted.stderr)
    );
    let persisted_stdout = String::from_utf8_lossy(&persisted.stdout);
    assert!(
        persisted_stdout
            .contains("revocation: revoked (manual revoke via franken-node trust revoke)")
    );
    assert!(persisted_stdout.contains("quarantine: true"));
}

#[test]
fn trust_revoke_fails_for_unknown_extension() {
    let workspace = seeded_fixture_trust_workspace();
    let output = run_cli_in_workspace(
        workspace.path(),
        &["trust", "revoke", "npm:@does-not/exist"],
    );
    assert!(
        !output.status.success(),
        "trust revoke should fail for unknown extension"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("trust card not found"));
    assert!(stderr.contains("fix_command=franken-node trust scan ."));
}

#[test]
fn trust_quarantine_supports_sha256_artifact_scope() {
    let workspace = seeded_fixture_trust_workspace();
    let output = run_cli_in_workspace(
        workspace.path(),
        &["trust", "quarantine", "--artifact", "sha256:deadbeef"],
    );
    assert!(
        output.status.success(),
        "trust quarantine failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("quarantine applied: artifact=sha256:deadbeef"));
    assert!(stdout.contains("affected_cards=2"));
    assert!(stdout.contains("npm:@acme/auth-guard"));
    assert!(stdout.contains("npm:@beta/telemetry-bridge"));
}

#[test]
fn trust_quarantine_propagates_through_fleet_transport_pipeline() {
    let workspace = seeded_fixture_trust_workspace();
    let shared_fleet_dir = workspace.path().join("fleet-shared");
    let fleet_state_env = shared_fleet_dir
        .to_str()
        .expect("shared fleet state dir should be utf8");
    let env = [("FRANKEN_NODE_FLEET_STATE_DIR", fleet_state_env)];
    let mut transport = shared_fleet_transport(&shared_fleet_dir);

    for node_id in ["node-a", "node-b", "node-c"] {
        let node_workspace = workspace.path().join("nodes").join(node_id);
        fs::create_dir_all(node_workspace.join(".franken-node/state"))
            .expect("create simulated node state dir");
        transport
            .upsert_node_status(&NodeStatus {
                zone_id: "zone-shared".to_string(),
                node_id: node_id.to_string(),
                last_seen: chrono::Utc::now(),
                quarantine_version: 0,
                health: NodeHealth::Healthy,
            })
            .expect("seed node status");
    }

    let quarantine_output = run_cli_in_workspace_with_env(
        workspace.path(),
        &["trust", "quarantine", "--artifact", "sha256:deadbeef"],
        &env,
    );
    assert!(
        quarantine_output.status.success(),
        "trust quarantine failed: {}",
        String::from_utf8_lossy(&quarantine_output.stderr)
    );
    let quarantine_stdout = String::from_utf8_lossy(&quarantine_output.stdout);
    let incident_id = quarantine_stdout
        .lines()
        .find_map(|line| line.strip_prefix("fleet propagation incident="))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| {
            panic!(
                "trust quarantine did not emit a fleet incident id\nstdout:\n{}",
                quarantine_stdout
            )
        })
        .to_string();

    let propagation_deadline = Instant::now() + Duration::from_secs(1);
    let quarantine_version = loop {
        let actions = transport.list_actions().expect("list fleet actions");
        if let Some(version) = actions.iter().find_map(|record| match &record.action {
            FleetAction::Quarantine {
                incident_id: action_incident_id,
                quarantine_version,
                ..
            } if action_incident_id == &incident_id => Some(*quarantine_version),
            _ => None,
        }) {
            break version;
        }
        assert!(
            Instant::now() < propagation_deadline,
            "quarantine action did not reach shared fleet state within 1s\nstdout:\n{}",
            quarantine_stdout
        );
        thread::sleep(Duration::from_millis(10));
    };

    let status_payload = parse_json_stdout(
        &run_cli_in_workspace_with_env(workspace.path(), &["fleet", "status", "--json"], &env),
        "fleet status after trust quarantine",
    );
    assert_eq!(
        status_payload["state"]["nodes"]
            .as_array()
            .expect("fleet state nodes array")
            .len(),
        3,
        "fleet status should report all simulated nodes: {status_payload:#}"
    );
    assert_eq!(
        status_payload["status"]["total_nodes"], 3,
        "fleet status should show three simulated nodes: {status_payload:#}"
    );
    assert_eq!(
        status_payload["status"]["active_quarantines"], 1,
        "fleet status should show one active quarantine after trust quarantine: {status_payload:#}"
    );

    for node_id in ["node-a", "node-b", "node-c"] {
        transport
            .upsert_node_status(&NodeStatus {
                zone_id: "zone-shared".to_string(),
                node_id: node_id.to_string(),
                last_seen: chrono::Utc::now(),
                quarantine_version,
                health: NodeHealth::Healthy,
            })
            .expect("advance node convergence");
    }

    let converge_started = Instant::now();
    let converged_payload = loop {
        let payload = parse_json_stdout(
            &run_cli_in_workspace_with_env(workspace.path(), &["fleet", "status", "--json"], &env),
            "fleet status while waiting for convergence",
        );
        let progress = payload["status"]["pending_convergences"][0]["progress_pct"].as_u64();
        if progress == Some(100) {
            break payload;
        }
        assert!(
            converge_started.elapsed() < Duration::from_secs(1),
            "fleet convergence did not reach 100% within 1s: {payload:#}"
        );
        thread::sleep(Duration::from_millis(10));
    };
    assert_eq!(
        converged_payload["status"]["pending_convergences"][0]["phase"], "Converged",
        "fleet convergence should be marked converged: {converged_payload:#}"
    );

    let release_output = run_cli_in_workspace_with_env(
        workspace.path(),
        &[
            "fleet",
            "release",
            "--incident",
            incident_id.as_str(),
            "--json",
        ],
        &env,
    );
    assert!(
        release_output.status.success(),
        "fleet release failed: {}",
        String::from_utf8_lossy(&release_output.stderr)
    );
    let release_payload = parse_json_stdout(&release_output, "fleet release json");
    assert_eq!(release_payload["action"]["action_type"], "release");

    let released_status = parse_json_stdout(
        &run_cli_in_workspace_with_env(workspace.path(), &["fleet", "status", "--json"], &env),
        "fleet status after release",
    );
    assert_eq!(
        released_status["status"]["active_quarantines"], 0,
        "fleet release should clear active quarantines: {released_status:#}"
    );
    assert!(
        released_status["status"]["pending_convergences"]
            .as_array()
            .expect("pending convergences array")
            .is_empty(),
        "fleet release should clear pending convergence state: {released_status:#}"
    );
}

#[test]
fn trust_revoke_receipt_export_fails_before_mutation_when_key_missing() {
    let workspace = seeded_fixture_trust_workspace();
    let receipt_out = workspace.path().join("artifacts/revoke-receipts.json");
    let output = run_cli_in_workspace(
        workspace.path(),
        &[
            "trust",
            "revoke",
            "npm:@acme/auth-guard",
            "--receipt-out",
            receipt_out.to_str().expect("utf8 receipt path"),
        ],
    );
    assert!(
        !output.status.success(),
        "expected receipt export without a key to fail"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("receipt export requested but no signing key was configured"));
    assert!(stderr.contains("fix_command=mkdir -p .franken-node/keys && openssl rand -hex 32 > .franken-node/keys/receipt-signing.key"));
    assert!(
        !receipt_out.exists(),
        "receipt export should not be written on failure"
    );

    let persisted =
        run_cli_in_workspace(workspace.path(), &["trust", "card", "npm:@acme/auth-guard"]);
    assert!(
        persisted.status.success(),
        "persisted read should still succeed"
    );
    let persisted_stdout = String::from_utf8_lossy(&persisted.stdout);
    assert!(!persisted_stdout.contains("manual revoke via franken-node trust revoke"));
}

#[test]
fn trust_revoke_receipt_export_succeeds_with_cli_signing_key() {
    let workspace = seeded_fixture_trust_workspace();
    let key_path = workspace.path().join("keys/receipt-signing.key");
    write_receipt_signing_key(&key_path);
    let receipt_out = workspace.path().join("artifacts/revoke-receipts.json");
    let receipt_summary_out = workspace.path().join("artifacts/revoke-receipts.md");

    let output = run_cli_in_workspace(
        workspace.path(),
        &[
            "trust",
            "revoke",
            "npm:@acme/auth-guard",
            "--receipt-signing-key",
            key_path.to_str().expect("utf8 key path"),
            "--receipt-out",
            receipt_out.to_str().expect("utf8 receipt path"),
            "--receipt-summary-out",
            receipt_summary_out.to_str().expect("utf8 summary path"),
        ],
    );
    assert!(
        output.status.success(),
        "trust revoke with explicit signing key failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("signing_source=cli"));
    assert!(stderr.contains(FIXTURE_RECEIPT_KEY_ID));

    let exported = fs::read_to_string(&receipt_out).expect("read receipt export");
    let payload: Value = serde_json::from_str(&exported).expect("receipt export json");
    let receipts = payload.as_array().expect("receipt export array");
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0]["action_name"], "revocation");
    assert_eq!(receipts[0]["signer_key_id"], FIXTURE_RECEIPT_KEY_ID);

    let summary = fs::read_to_string(&receipt_summary_out).expect("read summary export");
    assert!(summary.contains("Signed Decision Receipts"));
    assert!(summary.contains("Key ID"));
}

#[test]
fn trust_quarantine_receipt_export_fails_before_mutation_when_key_missing() {
    let workspace = seeded_fixture_trust_workspace();
    let receipt_out = workspace.path().join("artifacts/quarantine-receipts.json");
    let output = run_cli_in_workspace(
        workspace.path(),
        &[
            "trust",
            "quarantine",
            "--artifact",
            "sha256:deadbeef",
            "--receipt-out",
            receipt_out.to_str().expect("utf8 receipt path"),
        ],
    );
    assert!(
        !output.status.success(),
        "expected receipt export without a key to fail"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("receipt export requested but no signing key was configured"));
    assert!(stderr.contains("fix_command=mkdir -p .franken-node/keys && openssl rand -hex 32 > .franken-node/keys/receipt-signing.key"));
    assert!(
        !receipt_out.exists(),
        "receipt export should not be written on failure"
    );
}

#[test]
fn trust_quarantine_receipt_export_uses_env_signing_key() {
    let workspace = seeded_fixture_trust_workspace();
    let key_path = workspace.path().join("keys/receipt-signing.key");
    write_receipt_signing_key(&key_path);
    let receipt_out = workspace.path().join("artifacts/quarantine-receipts.json");

    let output = run_cli_in_workspace_with_env(
        workspace.path(),
        &[
            "trust",
            "quarantine",
            "--artifact",
            "sha256:deadbeef",
            "--receipt-out",
            receipt_out.to_str().expect("utf8 receipt path"),
        ],
        &[(
            "FRANKEN_NODE_SECURITY_DECISION_RECEIPT_SIGNING_KEY_PATH",
            key_path.to_str().expect("utf8 key path"),
        )],
    );
    assert!(
        output.status.success(),
        "trust quarantine with env signing key failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("signing_source=env"));

    let exported = fs::read_to_string(&receipt_out).expect("read receipt export");
    let payload: Value = serde_json::from_str(&exported).expect("receipt export json");
    let receipts = payload.as_array().expect("receipt export array");
    assert_eq!(receipts[0]["action_name"], "quarantine");
    assert_eq!(receipts[0]["signer_key_id"], FIXTURE_RECEIPT_KEY_ID);
}

#[test]
fn trust_quarantine_receipt_export_uses_config_signing_key() {
    let workspace = seeded_fixture_trust_workspace();
    fs::write(
        workspace.path().join("franken_node.toml"),
        "profile = \"balanced\"\n\n[security]\ndecision_receipt_signing_key_path = \"keys/receipt-signing.key\"\n",
    )
    .expect("rewrite config");
    let key_path = workspace.path().join("keys/receipt-signing.key");
    write_receipt_signing_key(&key_path);
    let receipt_out = workspace.path().join("artifacts/quarantine-receipts.json");

    let output = run_cli_in_workspace(
        workspace.path(),
        &[
            "trust",
            "quarantine",
            "--artifact",
            "sha256:deadbeef",
            "--receipt-out",
            receipt_out.to_str().expect("utf8 receipt path"),
        ],
    );
    assert!(
        output.status.success(),
        "trust quarantine with config signing key failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("signing_source=config"));

    let exported = fs::read_to_string(&receipt_out).expect("read receipt export");
    let payload: Value = serde_json::from_str(&exported).expect("receipt export json");
    let receipts = payload.as_array().expect("receipt export array");
    assert_eq!(receipts[0]["signer_key_id"], FIXTURE_RECEIPT_KEY_ID);
}

#[test]
fn trust_sync_reports_summary_counts() {
    let workspace = seeded_fixture_trust_workspace();
    let (osv_url, requests, server) = spawn_osv_fixture_server();
    let output = run_cli_in_workspace_with_env(
        workspace.path(),
        &["trust", "sync", "--force"],
        &[("FRANKEN_NODE_OSV_QUERY_URL", osv_url.as_str())],
    );
    assert!(
        output.status.success(),
        "trust sync failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("trust sync completed: force=true"));
    assert!(stdout.contains("cards=2"));
    assert!(stdout.contains("refreshed=1"));
    assert!(stdout.contains("vulnerabilities=1"));
    assert!(stdout.contains("network_errors=1"));
    assert!(stdout.contains("revoked=1"));
    assert!(stdout.contains("quarantined=1"));

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("warning: @beta/telemetry-bridge"));

    let exported = run_cli_in_workspace(
        workspace.path(),
        &["trust-card", "export", "npm:@acme/auth-guard", "--json"],
    );
    assert!(
        exported.status.success(),
        "trust-card export after trust sync failed: {}",
        String::from_utf8_lossy(&exported.stderr)
    );
    let payload = parse_json_stdout(&exported, "trust-card export after trust sync");
    assert_eq!(payload["user_facing_risk_assessment"]["level"], "high");
    assert!(
        payload["user_facing_risk_assessment"]["summary"]
            .as_str()
            .expect("risk summary")
            .contains("OSV-2026-0001")
    );

    server.join().expect("join OSV fixture server");
    assert_eq!(requests.lock().expect("lock requests").len(), 2);
}

#[test]
fn trust_sync_without_force_skips_fresh_network_refresh() {
    let now_secs = chrono::Utc::now().timestamp() as u64;
    let workspace = seeded_fixture_trust_workspace_with_timestamp(now_secs);
    rewrite_fixture_last_verified_timestamps(workspace.path(), now_secs);
    let (osv_url, request_count, server) = spawn_osv_observer_server();
    let output = run_cli_in_workspace_with_env(
        workspace.path(),
        &["trust", "sync"],
        &[("FRANKEN_NODE_OSV_QUERY_URL", osv_url.as_str())],
    );
    assert!(
        output.status.success(),
        "trust sync without force failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("force=false"));
    assert!(stdout.contains("refreshed=0"));
    assert!(stdout.contains("vulnerabilities=0"));
    assert!(stdout.contains("cache_hits=2"));

    server.join().expect("join observer server");
    assert_eq!(*request_count.lock().expect("lock observer count"), 0);
}

#[test]
fn trust_scan_seeds_registry_from_manifest_and_lockfile() {
    let workspace = scannable_trust_workspace();
    let output = run_cli_in_workspace(workspace.path(), &["trust", "scan", "."]);
    assert!(
        output.status.success(),
        "trust scan failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("created=3"));
    assert!(stdout.contains("npm:react@19.2.4"));
    assert!(stdout.contains("npm:typescript@5.8.3"));
    assert!(stdout.contains("npm:@types/node@24.9.2"));

    let listed = run_cli_in_workspace(workspace.path(), &["trust", "list"]);
    assert!(
        listed.status.success(),
        "trust list failed after scan: {}",
        String::from_utf8_lossy(&listed.stderr)
    );
    let listed_stdout = String::from_utf8_lossy(&listed.stdout);
    assert!(listed_stdout.contains("npm:react"));
    assert!(listed_stdout.contains("npm:typescript"));
    assert!(listed_stdout.contains("npm:@types/node"));

    let exported = run_cli_in_workspace(
        workspace.path(),
        &["trust-card", "export", "npm:react", "--json"],
    );
    assert!(
        exported.status.success(),
        "trust-card export after scan failed: {}",
        String::from_utf8_lossy(&exported.stderr)
    );
    let payload = parse_json_stdout(&exported, "trust-card export after scan");
    assert_eq!(payload["extension"]["version"], "19.2.4");
    assert_eq!(
        payload["provenance_summary"]["artifact_hashes"][0],
        "sha512:01020304"
    );
}

#[test]
fn trust_scan_is_idempotent() {
    let workspace = scannable_trust_workspace();
    let first = run_cli_in_workspace(workspace.path(), &["trust", "scan", "."]);
    assert!(
        first.status.success(),
        "initial trust scan failed: {}",
        String::from_utf8_lossy(&first.stderr)
    );

    let second = run_cli_in_workspace(workspace.path(), &["trust", "scan", "."]);
    assert!(
        second.status.success(),
        "second trust scan failed: {}",
        String::from_utf8_lossy(&second.stderr)
    );
    let stdout = String::from_utf8_lossy(&second.stdout);
    assert!(stdout.contains("created=0"));
    assert!(stdout.contains("skipped_existing=3"));
}

#[test]
fn trust_scan_fails_when_package_manifest_is_missing() {
    let workspace = config_only_workspace();
    let output = run_cli_in_workspace(workspace.path(), &["trust", "scan", "."]);
    assert!(
        !output.status.success(),
        "trust scan should fail when package.json is absent"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("package.json not found at project path"));
}

#[test]
fn init_scan_populates_trust_registry() {
    let workspace = tempfile::tempdir().expect("tempdir");
    fs::write(
        workspace.path().join("package.json"),
        r#"{
  "name": "init-scan-fixture",
  "version": "1.0.0",
  "dependencies": {
    "react": "^19.2.0"
  }
}
"#,
    )
    .expect("write package manifest");
    fs::write(
        workspace.path().join("package-lock.json"),
        r#"{
  "name": "init-scan-fixture",
  "lockfileVersion": 3,
  "packages": {
    "": {
      "name": "init-scan-fixture",
      "version": "1.0.0"
    },
    "node_modules/react": {
      "version": "19.2.4",
      "integrity": "sha512-AQIDBA=="
    }
  }
}
"#,
    )
    .expect("write package lockfile");

    let output = run_cli_in_workspace(workspace.path(), &["init", "--out-dir", ".", "--scan"]);
    assert!(
        output.status.success(),
        "init --scan failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let registry_path = workspace
        .path()
        .join(".franken-node/state/trust-card-registry.v1.json");
    let registry = fs::read_to_string(&registry_path).expect("read trust registry");
    assert!(registry.contains("npm:react"));
    assert!(registry.contains("19.2.4"));
}

#[cfg(unix)]
#[test]
fn full_init_to_run_pipeline_empty_registry_warns_on_untracked_dependency_json() {
    let started = Instant::now();
    let workspace = tempfile::tempdir().expect("tempdir");
    write_run_package_manifest(workspace.path(), &[("left-pad", "^1.3.0")]);
    write_runtime_probe_script(workspace.path(), "index.js", "empty-registry");

    log_pipeline_step(
        1,
        "init_without_scan",
        "init bootstraps config and an empty trust registry",
    );
    let init_args = ["init", "--json", "--out-dir", "."];
    let init_output = run_cli_in_workspace(workspace.path(), &init_args);
    ensure_command_success(
        "init without scan",
        workspace.path(),
        &init_args,
        &init_output,
    );

    let init_payload = parse_json_stdout(&init_output, "init --json full pipeline empty registry");
    assert2::assert!(init_payload["command"] == "init");
    assert2::assert!(init_payload["trust_scan"].is_null());
    assert2::assert!(
        workspace
            .path()
            .join(".franken-node/state/trust-card-registry.v1.json")
            .is_file()
    );

    log_pipeline_step(
        2,
        "run_with_empty_registry",
        "run succeeds and surfaces an untracked dependency warning in JSON",
    );
    let runtime_path = runtime_path_env(&["node"]);
    let run_args = [
        "run",
        "--policy",
        "balanced",
        "--runtime",
        "node",
        "--json",
        ".",
    ];
    let run_output = run_cli_in_workspace_with_env(
        workspace.path(),
        &run_args,
        &[
            ("PATH", runtime_path.as_str()),
            ("FRANKEN_ENGINE_BIN", ""),
            ("FRANKEN_NODE_ENGINE_BINARY_PATH", ""),
        ],
    );
    ensure_command_success(
        "run with empty registry",
        workspace.path(),
        &run_args,
        &run_output,
    );

    let preflight_payload =
        parse_json_stderr(&run_output, "run --json preflight empty registry pipeline");
    let run_payload = parse_json_stdout(&run_output, "run --json completion empty registry");
    let results = run_payload["preflight"]["verdict"]["results"]
        .as_array()
        .expect("results array");
    let warnings = run_payload["preflight"]["verdict"]["warnings"]
        .as_array()
        .expect("warnings array");
    let receipt_path = PathBuf::from(
        run_payload["receipt_path"]
            .as_str()
            .expect("receipt path string"),
    );

    assert2::assert!(preflight_payload["verdict"]["status"] == "passed");
    assert2::assert!(run_payload["success"].as_bool() == Some(true));
    assert2::assert!(run_payload["dispatch"]["runtime"] == "node");
    let runtime_probe =
        parse_captured_runtime_probe(&run_payload, "empty registry captured output");
    assert2::assert!(runtime_probe["marker"] == "empty-registry");
    assert2::assert!(runtime_probe["runtime"] == "node");
    assert2::assert!(runtime_probe["release"] == "node");
    assert2::assert!(runtime_probe["policy"] == "balanced");
    assert2::assert!(warnings.len() == 1);
    assert2::assert!(results.len() == 1);
    assert2::assert!(results[0]["status"] == "untracked");
    assert2::assert!(results[0]["extension_id"] == "npm:left-pad");
    assert2::assert!(receipt_path.is_file());

    let receipt_payload = read_json_file(&receipt_path, "run receipt");
    assert2::assert!(receipt_payload["receipt_id"] == run_payload["receipt"]["receipt_id"]);
    assert2::assert!(receipt_payload["preflight_verdict"]["status"] == "passed");
    assert2::assert!(started.elapsed() < Duration::from_secs(30));
}

#[cfg(unix)]
#[test]
fn full_init_to_run_pipeline_with_trust_data_reports_trusted_extensions_json() {
    let started = Instant::now();
    let workspace = tempfile::tempdir().expect("tempdir");
    write_pipeline_package_manifest(
        workspace.path(),
        &[("react", "^19.2.0")],
        &[("typescript", "^5.8.3")],
        &[("@types/node", "^24.9.2")],
    );
    write_pipeline_lockfile(workspace.path());
    write_runtime_probe_script(workspace.path(), "index.js", "trusted-registry");

    log_pipeline_step(
        1,
        "init_with_scan",
        "init bootstraps state and populates trust cards",
    );
    let init_args = ["init", "--json", "--out-dir", ".", "--scan"];
    let init_output = run_cli_in_workspace(workspace.path(), &init_args);
    ensure_command_success("init with scan", workspace.path(), &init_args, &init_output);

    let init_payload = parse_json_stdout(&init_output, "init --json full pipeline trust data");
    let trust_scan = init_payload["trust_scan"]
        .as_object()
        .expect("trust_scan object");
    let scan_items = trust_scan["items"].as_array().expect("trust scan items");
    assert2::assert!(init_payload["command"] == "init");
    assert2::assert!(trust_scan["created_cards"] == 3);
    assert2::assert!(scan_items.len() == 3);

    log_pipeline_step(
        2,
        "run_with_scanned_registry",
        "run succeeds and reports trusted per-extension JSON results",
    );
    let runtime_path = runtime_path_env(&["node"]);
    let run_args = [
        "run",
        "--policy",
        "balanced",
        "--runtime",
        "node",
        "--json",
        ".",
    ];
    let run_output = run_cli_in_workspace_with_env(
        workspace.path(),
        &run_args,
        &[
            ("PATH", runtime_path.as_str()),
            ("FRANKEN_ENGINE_BIN", ""),
            ("FRANKEN_NODE_ENGINE_BINARY_PATH", ""),
        ],
    );
    ensure_command_success(
        "run with populated trust registry",
        workspace.path(),
        &run_args,
        &run_output,
    );

    let preflight_payload = parse_json_stderr(
        &run_output,
        "run --json preflight populated registry pipeline",
    );
    let run_payload = parse_json_stdout(&run_output, "run --json completion populated registry");
    let results = run_payload["preflight"]["verdict"]["results"]
        .as_array()
        .expect("results array");
    let receipt_path = PathBuf::from(
        run_payload["receipt_path"]
            .as_str()
            .expect("receipt path string"),
    );

    assert2::assert!(preflight_payload["verdict"]["status"] == "passed");
    assert2::assert!(run_payload["success"].as_bool() == Some(true));
    assert2::assert!(
        run_payload["preflight"]["verdict"]["warnings"]
            .as_array()
            .expect("warnings array")
            .is_empty()
    );
    let runtime_probe =
        parse_captured_runtime_probe(&run_payload, "trusted registry captured output");
    assert2::assert!(runtime_probe["marker"] == "trusted-registry");
    assert2::assert!(runtime_probe["runtime"] == "node");
    assert2::assert!(runtime_probe["release"] == "node");
    assert2::assert!(runtime_probe["policy"] == "balanced");
    assert2::assert!(results.len() == 3);
    assert2::assert!(results.iter().all(|result| result["status"] == "trusted"));
    assert2::assert!(
        results
            .iter()
            .any(|result| result["extension_id"] == "npm:react")
    );
    assert2::assert!(
        results
            .iter()
            .any(|result| result["extension_id"] == "npm:typescript")
    );
    assert2::assert!(
        results
            .iter()
            .any(|result| result["extension_id"] == "npm:@types/node")
    );
    assert2::assert!(run_payload["receipt"]["violation_count"] == 0);
    assert2::assert!(receipt_path.is_file());
    assert2::assert!(started.elapsed() < Duration::from_secs(30));
}

#[test]
fn full_init_to_run_pipeline_revoked_extension_blocks_in_strict_json() {
    let started = Instant::now();
    let workspace = tempfile::tempdir().expect("tempdir");
    write_run_package_manifest(workspace.path(), &[("@beta/telemetry-bridge", "^0.9.1")]);

    log_pipeline_step(
        1,
        "init_with_scan",
        "init bootstraps state and seeds the dependency trust card",
    );
    let init_args = ["init", "--json", "--out-dir", ".", "--scan"];
    let init_output = run_cli_in_workspace(workspace.path(), &init_args);
    ensure_command_success(
        "init with scan before revoke",
        workspace.path(),
        &init_args,
        &init_output,
    );
    let init_payload = parse_json_stdout(&init_output, "init --json revoke pipeline");
    assert2::assert!(init_payload["trust_scan"]["created_cards"] == 1);

    log_pipeline_step(
        2,
        "revoke_dependency",
        "trust revoke marks the scanned dependency as revoked",
    );
    let revoke_args = ["trust", "revoke", "npm:@beta/telemetry-bridge"];
    let revoke_output = run_cli_in_workspace(workspace.path(), &revoke_args);
    ensure_command_success(
        "trust revoke after init scan",
        workspace.path(),
        &revoke_args,
        &revoke_output,
    );
    let revoke_stdout = String::from_utf8_lossy(&revoke_output.stdout);
    assert2::assert!(revoke_stdout.contains("revocation: revoked"));

    log_pipeline_step(
        3,
        "strict_run_blocked",
        "run --policy strict blocks and emits a revoked violation JSON payload",
    );
    let run_args = ["run", "--policy", "strict", "--json", "."];
    let run_output = run_cli_in_workspace(workspace.path(), &run_args);
    if run_output.status.success() {
        panic_with_command_diagnostics(
            "strict run should have been blocked",
            workspace.path(),
            &run_args,
            &run_output,
        );
    }

    let run_payload = parse_json_stdout(&run_output, "run --json strict blocked pipeline");
    let violations = run_payload["verdict"]["violations"]
        .as_array()
        .expect("violations array");
    let results = run_payload["verdict"]["results"]
        .as_array()
        .expect("results array");

    assert2::assert!(run_payload["verdict"]["status"] == "blocked");
    assert2::assert!(run_payload["receipt"]["decision"] == "denied");
    assert2::assert!(
        violations
            .iter()
            .any(|violation| violation["kind"] == "revoked")
    );
    assert2::assert!(results.iter().any(|result| result["status"] == "revoked"));
    assert2::assert!(
        results
            .iter()
            .any(|result| result["extension_id"] == "npm:@beta/telemetry-bridge")
    );
    assert2::assert!(started.elapsed() < Duration::from_secs(30));
}

#[test]
fn trust_card_export_requires_json_flag() {
    let output = run_cli_in_workspace(
        repo_root().as_path(),
        &["trust-card", "export", "npm:@acme/auth-guard"],
    );
    assert!(
        !output.status.success(),
        "trust-card export without --json should fail"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("`trust-card export` requires `--json`"));
}

#[test]
fn trust_card_export_emits_known_card_json() {
    let workspace = seeded_fixture_trust_workspace();
    let output = run_cli_in_workspace(
        workspace.path(),
        &["trust-card", "export", "npm:@acme/auth-guard", "--json"],
    );
    assert!(
        output.status.success(),
        "trust-card export failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let payload = parse_json_stdout(&output, "trust-card export");
    assert_eq!(payload["extension"]["extension_id"], "npm:@acme/auth-guard");
    assert_eq!(payload["extension"]["version"], "1.4.2");
    assert_eq!(payload["publisher"]["display_name"], "Acme Security");
    assert_eq!(payload["user_facing_risk_assessment"]["level"], "low");
}

#[test]
fn trust_card_list_filters_by_publisher() {
    let workspace = seeded_fixture_trust_workspace();
    let output = run_cli_in_workspace(
        workspace.path(),
        &["trust-card", "list", "--publisher", "pub-acme"],
    );
    assert!(
        output.status.success(),
        "trust-card list failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("extension | publisher | cert | reputation | status"));
    assert!(stdout.contains("npm:@acme/auth-guard | pub-acme | Gold | 920bp (Improving) | active"));
    assert!(!stdout.contains("npm:@beta/telemetry-bridge"));
}

#[test]
fn trust_card_list_rejects_zero_page() {
    let workspace = seeded_fixture_trust_workspace();
    let output = run_cli_in_workspace(workspace.path(), &["trust-card", "list", "--page", "0"]);
    assert!(
        !output.status.success(),
        "trust-card list with page 0 should fail"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("invalid pagination: page=0, per_page=20"));
}

#[test]
fn trust_card_compare_reports_expected_differences() {
    let workspace = seeded_fixture_trust_workspace();
    let output = run_cli_in_workspace(
        workspace.path(),
        &[
            "trust-card",
            "compare",
            "npm:@acme/auth-guard",
            "npm:@beta/telemetry-bridge",
        ],
    );
    assert!(
        output.status.success(),
        "trust-card compare failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("compare npm:@acme/auth-guard vs npm:@beta/telemetry-bridge:"));
    assert!(stdout.contains("- certification_level: gold -> bronze"));
    assert!(stdout.contains("- extension_version: 1.4.2 -> 0.9.1"));
    assert!(stdout.contains("- active_quarantine: false -> true"));
}

#[test]
fn trust_card_diff_reports_version_history_changes() {
    let workspace = seeded_fixture_trust_workspace();
    let output = run_cli_in_workspace(
        workspace.path(),
        &["trust-card", "diff", "npm:@beta/telemetry-bridge", "1", "2"],
    );
    assert!(
        output.status.success(),
        "trust-card diff failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("compare npm:@beta/telemetry-bridge@1 vs npm:@beta/telemetry-bridge@2:")
    );
    assert!(stdout.contains("- certification_level: silver -> bronze"));
    assert!(stdout.contains("- reputation_score_basis_points: 680 -> 410"));
    assert!(stdout.contains("- revocation_status: active -> revoked"));
}

#[test]
fn trust_commands_fail_closed_without_authoritative_registry_state() {
    let workspace = config_only_workspace();
    let output = run_cli_in_workspace(workspace.path(), &["trust", "card", "npm:@acme/auth-guard"]);
    assert!(
        !output.status.success(),
        "trust card should fail when authoritative registry state is missing"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("authoritative trust-card registry not initialized"));
}
