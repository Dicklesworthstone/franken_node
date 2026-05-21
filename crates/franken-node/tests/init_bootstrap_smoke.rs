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

    // The state subtree must exist with the trust-card registry primed.
    assert!(
        root.join(".franken-node/state/trust-card-registry.v1.json")
            .is_file(),
        "init must create an empty trust-card registry under state/"
    );
    assert!(
        root.join(".franken-node/state/trust-card-registry.v1.json.high-water.json")
            .is_file(),
        "init must create a matching high-water file"
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
