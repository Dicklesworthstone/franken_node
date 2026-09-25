//! End-to-end regression test for `franken-node init` first-run bootstrap.
//!
//! Before the bridge-plan fix at `config.rs::Config::resolve_with_bootstrap`,
//! running `franken-node init` on a directory with no existing
//! `franken_node.toml` failed fail-closed with:
//!
//!     config validation failed: trust.registry_signing_key must be configured
//!
//! followed (once the operator hand-crafted a partial config) by:
//!
//!     config validation failed: security.authorized_api_keys must be explicitly configured
//!
//! Both are fail-closed security boundaries that `init` is meant to *populate*,
//! not depend on. The reality-check skill flagged this as the single most
//! visible operator-on-ramp bug. This integration test pins the fixed
//! behavior: `init` succeeds on an empty directory, writes a complete
//! `franken_node.toml` with synthesized values, and the resulting config
//! passes `Config::resolve` on the next invocation (no second-run regression).
//!
//! Additionally, this file asserts that the trust-card registry written by
//! init is HMAC-signed with the config's signing key (not the in-crate
//! `DEFAULT_REGISTRY_KEY` placeholder) so subsequent `trust list` / `trust
//! card` calls can re-validate it cleanly. See `main.rs::bootstrap_state_directory`
//! for the corresponding production-code change.

use std::process::Command;
use tempfile::TempDir;

/// Locate the debug binary produced by the workspace build.
///
/// Tests under `crates/franken-node/tests/` build alongside the binary, so we
/// can rely on `CARGO_BIN_EXE_franken-node` (set by Cargo for integration
/// tests) when present, falling back to the conventional debug path.
fn franken_node_binary() -> std::path::PathBuf {
    if let Some(p) = std::option_env!("CARGO_BIN_EXE_franken-node") {
        return std::path::PathBuf::from(p);
    }
    // Conventional fallback: workspace target dir relative to this crate.
    let crate_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    crate_dir
        .parent() // crates/
        .and_then(|p| p.parent()) // workspace root
        .unwrap_or_else(|| crate_dir.as_path().parent().unwrap())
        .join("target")
        .join("debug")
        .join("franken-node")
}

/// Quick gate: skip the test cleanly if the binary isn't built. This keeps
/// the suite green for fresh checkouts where `cargo test` is run before
/// `cargo build --bin franken-node`, while still asserting on dev machines
/// and CI where the binary exists.
fn require_binary() -> Option<std::path::PathBuf> {
    let bin = franken_node_binary();
    if bin.exists() {
        Some(bin)
    } else {
        eprintln!(
            "skipping init_bootstrap_smoke: binary not found at {} \
             (build with `cargo build -p frankenengine-node --bin franken-node`)",
            bin.display()
        );
        None
    }
}

#[test]
fn init_succeeds_on_empty_directory_and_synthesizes_security_defaults() {
    let Some(bin) = require_binary() else { return };

    let tmp = TempDir::new().expect("tempdir");
    let root = tmp.path();

    // Sanity check: there is NO franken_node.toml in this directory yet.
    assert!(
        !root.join("franken_node.toml").exists(),
        "tempdir should start without a config file"
    );

    let output = Command::new(&bin)
        .args(["init", "--profile", "balanced", "--out-dir", ".", "--json"])
        .current_dir(root)
        .output()
        .expect("invoke init");

    assert!(
        output.status.success(),
        "init must succeed on a fresh empty directory (this is the bootstrap surface!) \
         exit={} stderr=\n{}\nstdout=\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&output.stdout),
    );

    let report: serde_json::Value = serde_json::from_slice(&output.stdout)
        .expect("init --json must produce parseable JSON on stdout");
    assert_eq!(report["schema_version"], "franken-node/init-cli/v1");
    assert_eq!(report["command"], "init");

    // The synthesized values must be reported back to the operator so they
    // know what just landed in the config file.
    let synthesis = &report["bootstrap_synthesis"];
    assert!(
        synthesis["registry_signing_key_generated"]
            .as_bool()
            .unwrap_or(false),
        "init should have synthesized trust.registry_signing_key on first run; \
         got bootstrap_synthesis={synthesis}"
    );
    let api_keys = synthesis["authorized_api_keys_generated"]
        .as_array()
        .expect("authorized_api_keys_generated must be an array");
    assert!(
        !api_keys.is_empty(),
        "init should have synthesized at least one authorized_api_key; \
         got {synthesis}"
    );

    // The written config must contain the synthesized values verbatim so
    // subsequent `Config::resolve` calls see them.
    let toml_path = root.join("franken_node.toml");
    assert!(toml_path.is_file(), "franken_node.toml should now exist");
    let toml_body = std::fs::read_to_string(&toml_path).expect("read franken_node.toml");
    assert!(
        toml_body.contains("registry_signing_key"),
        "written config must carry the synthesized registry_signing_key"
    );
    assert!(
        toml_body.contains("authorized_api_keys"),
        "written config must carry the synthesized authorized_api_keys"
    );

    // The state subtree must exist with the trust-card registry primed in its
    // durable frankensqlite store (the legacy JSON pair is no longer written).
    assert!(
        root.join(".franken-node/state/trust-card-registry.v1.db")
            .is_file(),
        "init must create the durable trust-card registry store under state/"
    );
    assert!(
        root.join(".franken-node/.gitignore").is_file(),
        "init must create a .gitignore that excludes keys/ and execution-receipts/"
    );
}

#[test]
fn init_is_idempotent_with_overwrite_preserving_signing_key() {
    let Some(bin) = require_binary() else { return };

    let tmp = TempDir::new().expect("tempdir");
    let root = tmp.path();

    // First init.
    let first = Command::new(&bin)
        .args(["init", "--profile", "balanced", "--out-dir", ".", "--json"])
        .current_dir(root)
        .output()
        .expect("invoke init #1");
    assert!(first.status.success(), "first init must succeed");
    let toml_body_first = std::fs::read_to_string(root.join("franken_node.toml"))
        .expect("read first franken_node.toml");

    // Second init with --overwrite must succeed AND must PRESERVE the
    // already-synthesized registry signing key. Synthesis only fires when
    // the field is `None`; the second pass loads the existing config (which
    // now has the key from run #1) and re-serializes it. This is the
    // security-correct behavior: regenerating the key on every init would
    // invalidate every trust card / receipt / bundle signed under the prior
    // key, silently breaking the operator's evidence chain.
    let second = Command::new(&bin)
        .args([
            "init",
            "--profile",
            "balanced",
            "--out-dir",
            ".",
            "--overwrite",
            "--json",
        ])
        .current_dir(root)
        .output()
        .expect("invoke init #2");
    assert!(
        second.status.success(),
        "second init --overwrite must succeed; exit={} stderr=\n{}",
        second.status,
        String::from_utf8_lossy(&second.stderr),
    );
    let toml_body_second = std::fs::read_to_string(root.join("franken_node.toml"))
        .expect("read second franken_node.toml");

    assert_eq!(
        toml_body_first, toml_body_second,
        "second init --overwrite should be a no-op on the config (preserving \
         the synthesized signing key); regenerating would invalidate prior \
         trust artifacts signed under the previous key"
    );

    // Also confirm that the second run's JSON report shows synthesis DID
    // NOT fire (the key was already present in the loaded config).
    let report: serde_json::Value = serde_json::from_slice(&second.stdout)
        .expect("init --json must produce parseable JSON on stdout");
    let synthesis = &report["bootstrap_synthesis"];
    assert!(
        !synthesis["registry_signing_key_generated"]
            .as_bool()
            .unwrap_or(true),
        "second init must NOT synthesize a new signing key when one already \
         exists in the loaded config; got bootstrap_synthesis={synthesis}"
    );
}

#[test]
fn config_resolved_from_init_output_is_valid_for_subsequent_commands() {
    let Some(bin) = require_binary() else { return };

    let tmp = TempDir::new().expect("tempdir");
    let root = tmp.path();

    // Bootstrap with init.
    let init = Command::new(&bin)
        .args(["init", "--profile", "balanced", "--out-dir", "."])
        .current_dir(root)
        .output()
        .expect("invoke init");
    assert!(
        init.status.success(),
        "init must succeed before round-trip check: stderr=\n{}",
        String::from_utf8_lossy(&init.stderr)
    );

    // Doctor reads the just-written config; if init's TOML couldn't be
    // parsed back by `Config::resolve`, this fails with a TOML parse error
    // (this was the `[security.network_policy]` round-trip bug the bridge
    // plan fixed in `SecurityOverrides`).
    let doctor = Command::new(&bin)
        .args(["doctor", "--json"])
        .current_dir(root)
        .output()
        .expect("invoke doctor");
    assert!(
        doctor.status.success(),
        "doctor must accept the config init just wrote; exit={} stderr=\n{}",
        doctor.status,
        String::from_utf8_lossy(&doctor.stderr),
    );

    // trust list must succeed on the empty registry init created — this is
    // the high-water signature regression: pre-fix, init wrote the registry
    // with DEFAULT_REGISTRY_KEY while trust list re-validated with the
    // operator's key.
    let trust_list = Command::new(&bin)
        .args(["trust", "list"])
        .current_dir(root)
        .output()
        .expect("invoke trust list");
    assert!(
        trust_list.status.success(),
        "trust list must succeed on the post-init empty registry; exit={} stderr=\n{}",
        trust_list.status,
        String::from_utf8_lossy(&trust_list.stderr),
    );
}

fn assert_init_json_error(output: &std::process::Output, error_needle: &str) {
    assert!(
        !output.status.success(),
        "init --json should fail closed; stderr=\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let payload: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("init --json failure stdout must be JSON");
    assert_eq!(payload["schema_version"], "franken-node/init-error-cli/v1");
    assert_eq!(payload["command"], "init");
    assert_eq!(payload["ok"], false);
    let error = payload["error"].as_str().unwrap_or_default();
    assert!(
        error.contains(error_needle),
        "init --json error must name the failure: {payload}"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("Error: "),
        "--json must not append a second human Error line after the JSON report: {stderr}"
    );
}

#[test]
fn init_scan_no_state_json_fails_closed() {
    let Some(bin) = require_binary() else { return };
    let tmp = TempDir::new().expect("tempdir");
    let output = Command::new(&bin)
        .args([
            "init",
            "--profile",
            "balanced",
            "--out-dir",
            ".",
            "--scan",
            "--no-state",
            "--json",
        ])
        .current_dir(tmp.path())
        .output()
        .expect("invoke init --scan --no-state --json");
    assert_init_json_error(
        &output,
        "`init --scan` requires state bootstrapping; remove `--no-state`",
    );
}

#[test]
fn init_existing_files_json_fails_closed_without_overwrite() {
    let Some(bin) = require_binary() else { return };
    let tmp = TempDir::new().expect("tempdir");
    let first = Command::new(&bin)
        .args(["init", "--profile", "balanced", "--out-dir", ".", "--json"])
        .current_dir(tmp.path())
        .output()
        .expect("invoke first init");
    assert!(first.status.success(), "first init must succeed");

    let second = Command::new(&bin)
        .args(["init", "--profile", "balanced", "--out-dir", ".", "--json"])
        .current_dir(tmp.path())
        .output()
        .expect("invoke second init without overwrite");
    assert_init_json_error(&second, "init target already contains generated files");
}

#[test]
fn init_overwrite_and_backup_json_fails_closed() {
    let Some(bin) = require_binary() else { return };
    let tmp = TempDir::new().expect("tempdir");
    let output = Command::new(&bin)
        .args([
            "init",
            "--profile",
            "balanced",
            "--out-dir",
            ".",
            "--overwrite",
            "--backup-existing",
            "--json",
        ])
        .current_dir(tmp.path())
        .output()
        .expect("invoke init --overwrite --backup-existing --json");
    assert_init_json_error(
        &output,
        "--overwrite and --backup-existing are mutually exclusive",
    );
}

fn init_file_action(report: &serde_json::Value, path_suffix: &str) -> String {
    report["file_actions"]
        .as_array()
        .expect("init file_actions")
        .iter()
        .find(|action| {
            action["path"]
                .as_str()
                .is_some_and(|path| path.ends_with(path_suffix))
        })
        .and_then(|action| action["action"].as_str())
        .unwrap_or_else(|| panic!("no init file action for {path_suffix}: {report}"))
        .to_string()
}

/// bd-reality-20260923-26n9r.11: `init` provisions the RemoteCap signing key
/// and a trust-scan egress token scoped to the public metadata endpoints, so
/// `trust scan --deep/--audit` and `trust sync` work without env setup.
#[test]
fn init_provisions_trust_scan_remotecap_key_and_scoped_token() {
    let Some(bin) = require_binary() else { return };
    let tmp = TempDir::new().expect("tempdir");
    let root = tmp.path();
    let run = |args: &[&str]| {
        Command::new(&bin)
            .args(args)
            .env_remove("FRANKEN_NODE_REMOTECAP_KEY")
            .env_remove("FRANKEN_NODE_TRUST_SCAN_REMOTECAP_TOKEN")
            .current_dir(root)
            .output()
            .expect("invoke franken-node")
    };
    let init = |args: &[&str]| {
        let output = run(args);
        assert!(
            output.status.success(),
            "init failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice::<serde_json::Value>(&output.stdout).expect("init --json")
    };
    let key_suffix = ".franken-node/keys/remotecap-signing.key";
    let token_suffix = ".franken-node/remotecap/trust-scan-token.json";
    let receipt_key_suffix = ".franken-node/keys/receipt-signing.key";

    let first = init(&["init", "--profile", "balanced", "--out-dir", ".", "--json"]);
    assert_eq!(init_file_action(&first, key_suffix), "created");
    assert_eq!(init_file_action(&first, token_suffix), "created");
    assert_eq!(init_file_action(&first, receipt_key_suffix), "created");
    for suffix in [key_suffix, receipt_key_suffix] {
        let key = std::fs::read_to_string(root.join(suffix)).expect("read signing key");
        assert_eq!(key.len(), 64, "{suffix}: 32 random bytes, hex encoded");
        assert!(key.bytes().all(|byte| byte.is_ascii_hexdigit()));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        for suffix in [key_suffix, token_suffix, receipt_key_suffix] {
            let mode = std::fs::metadata(root.join(suffix))
                .expect("stat provisioned file")
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600, "{suffix} must be private");
        }
    }
    let gitignore =
        std::fs::read_to_string(root.join(".franken-node/.gitignore")).expect("read .gitignore");
    assert!(gitignore.contains("remotecap/trust-scan-token.json"));

    // The token verifies under the provisioned key for the metadata hosts and
    // for nothing else.
    let verify = |endpoint: &str| {
        run(&[
            "remotecap",
            "verify",
            "--token-file",
            token_suffix,
            "--operation",
            "network_egress",
            "--endpoint",
            endpoint,
            "--json",
        ])
    };
    for endpoint in [
        "https://registry.npmjs.org/lodash",
        "https://api.deps.dev/v3alpha/systems/npm/packages/lodash",
        "https://api.osv.dev/v1/query",
    ] {
        let output = verify(endpoint);
        assert!(
            output.status.success(),
            "{endpoint}: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    assert!(
        !verify("https://evil.example/exfil").status.success(),
        "the default token must not authorize other hosts"
    );

    // A second init keeps both.
    let token_before = std::fs::read(root.join(token_suffix)).expect("read token");
    let second = init(&[
        "init",
        "--profile",
        "balanced",
        "--out-dir",
        ".",
        "--overwrite",
        "--json",
    ]);
    assert_eq!(init_file_action(&second, key_suffix), "skipped_existing");
    assert_eq!(init_file_action(&second, token_suffix), "skipped_existing");
    assert_eq!(
        init_file_action(&second, receipt_key_suffix),
        "skipped_existing"
    );
    assert_eq!(
        std::fs::read(root.join(token_suffix)).expect("reread token"),
        token_before
    );

    // Receipt export now finds and parses the provisioned default key: the
    // close-condition command gets past key loading and fails later, on the
    // oracle inputs this bare workspace does not have.
    let close_condition = run(&["doctor", "close-condition", "--json"]);
    assert!(!close_condition.status.success());
    let stdout = String::from_utf8_lossy(&close_condition.stdout);
    assert!(
        !stdout.contains("no signing key was configured") && !stdout.contains("failed decoding"),
        "the init-provisioned receipt key must be found and parsed: {stdout}"
    );
    assert!(
        stdout.contains("failed generating close-condition receipt"),
        "{stdout}"
    );
}
