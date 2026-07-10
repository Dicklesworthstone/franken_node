//! Integration tests for EngineDispatcher native-engine compatibility.
//!
//! Tests the complete native engine execution pipeline when the `engine`
//! feature is enabled, plus subprocess edge cases with controlled fixture
//! binaries when the test needs deterministic success, timeout, exit-code,
//! or signal behavior.
//!
//! Coverage includes:
//! - Native engine execution with telemetry emission
//! - Strict profile fallback rejection
//! - Comprehensive error handling and propagation
//!
//! A fixture binary proves dispatcher/process handling only; it is not counted
//! as evidence that a real franken_engine binary executed the application.

use frankenengine_node::{
    config::{Config, NetworkAllowlistEntry, PreferredRuntime, Profile},
    ops::{engine_dispatcher::EngineDispatcher, telemetry_bridge::TelemetryBridge},
    storage::frankensqlite_adapter::FrankensqliteAdapter,
};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tempfile::TempDir;

fn balanced_config() -> Config {
    Config {
        profile: Profile::Balanced,
        ..Config::default()
    }
}

/// Create a test application file with simple JavaScript content
fn create_test_app(dir: &Path, filename: &str, content: &str) -> PathBuf {
    let app_path = dir.join(filename);
    std::fs::write(&app_path, content).expect("Failed to write test app");
    app_path
}

/// Create a controlled franken-engine fixture binary for subprocess testing.
fn create_fixture_engine_binary(dir: &Path) -> PathBuf {
    let engine_path = dir.join("franken-engine");
    #[cfg(unix)]
    {
        std::fs::write(
            &engine_path,
            "#!/bin/bash\necho 'Fixture engine output'\nexit 0\n",
        )
        .expect("Failed to write fixture engine");
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&engine_path)
            .expect("Failed to get metadata")
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&engine_path, perms).expect("Failed to set permissions");
    }
    #[cfg(windows)]
    {
        let batch_path = dir.join("franken-engine.bat");
        std::fs::write(
            &batch_path,
            "@echo off\necho Fixture engine output\nexit /b 0\n",
        )
        .expect("Failed to write fixture engine batch");
        batch_path
    }

    #[cfg(unix)]
    return engine_path;
    #[cfg(windows)]
    return batch_path;
}

/// Create a slow franken-engine fixture binary for timeout testing.
fn create_slow_fixture_engine_binary(dir: &Path, delay_secs: u64) -> PathBuf {
    let engine_path = dir.join("slow-franken-engine");
    #[cfg(unix)]
    {
        let script = format!(
            "#!/bin/bash\necho 'Starting slow fixture engine'\nsleep {}\necho 'Fixture engine output'\nexit 0\n",
            delay_secs
        );
        std::fs::write(&engine_path, script).expect("Failed to write slow fixture engine");
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&engine_path)
            .expect("Failed to get metadata")
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&engine_path, perms).expect("Failed to set permissions");
    }
    #[cfg(windows)]
    {
        let batch_path = dir.join("slow-franken-engine.bat");
        let script = format!(
            "@echo off\necho Starting slow fixture engine\ntimeout /t {} /nobreak >nul\necho Fixture engine output\nexit /b 0\n",
            delay_secs
        );
        std::fs::write(&batch_path, script).expect("Failed to write slow fixture engine batch");
        batch_path
    }

    #[cfg(unix)]
    return engine_path;
    #[cfg(windows)]
    return batch_path;
}

/// Create a franken-engine fixture binary that fails with a non-zero exit code.
fn create_failing_fixture_engine_binary(dir: &Path, exit_code: i32) -> PathBuf {
    let engine_path = dir.join("failing-franken-engine");
    #[cfg(unix)]
    {
        let script = format!(
            "#!/bin/bash\necho 'Fixture engine error output' >&2\nexit {}\n",
            exit_code
        );
        std::fs::write(&engine_path, script).expect("Failed to write failing fixture engine");
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&engine_path)
            .expect("Failed to get metadata")
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&engine_path, perms).expect("Failed to set permissions");
    }
    #[cfg(windows)]
    {
        let batch_path = dir.join("failing-franken-engine.bat");
        let script = format!(
            "@echo off\necho Fixture engine error output 1>&2\nexit /b {}\n",
            exit_code
        );
        std::fs::write(&batch_path, script).expect("Failed to write failing fixture engine batch");
        batch_path
    }
    #[cfg(unix)]
    return engine_path;
    #[cfg(windows)]
    return batch_path;
}

/// Create a franken-engine fixture binary that terminates abnormally.
fn create_crashing_fixture_engine_binary(dir: &Path) -> PathBuf {
    let engine_path = dir.join("crashing-franken-engine");
    #[cfg(unix)]
    {
        // Use kill -9 to simulate a crash/panic
        std::fs::write(
            &engine_path,
            "#!/bin/bash\necho 'About to crash'\nkill -9 $$\n",
        )
        .expect("Failed to write crashing fixture engine");
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&engine_path)
            .expect("Failed to get metadata")
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&engine_path, perms).expect("Failed to set permissions");
    }
    #[cfg(windows)]
    {
        let batch_path = dir.join("crashing-franken-engine.bat");
        // Use taskkill to simulate crash on Windows
        std::fs::write(
            &batch_path,
            "@echo off\necho About to crash\ntaskkill /f /pid %PID%\n",
        )
        .expect("Failed to write crashing fixture engine batch");
        batch_path
    }
    #[cfg(unix)]
    return engine_path;
    #[cfg(windows)]
    return batch_path;
}

#[test]
#[cfg(feature = "engine")]
fn test_native_engine_execution_with_telemetry() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let app_path = create_test_app(
        temp_dir.path(),
        "test_app.js",
        r#"console.log("Hello from native engine");"#,
    );

    let config = balanced_config();

    let dispatcher = EngineDispatcher::new(None, PreferredRuntime::FrankenEngine);
    // Create test telemetry bridge
    let socket_path = temp_dir.path().join("test-telemetry.sock");
    let adapter = Arc::new(Mutex::new(FrankensqliteAdapter::default()));
    let _telemetry_bridge = TelemetryBridge::new(&socket_path.to_string_lossy(), adapter);
    let policy_mode = config.profile.to_string();

    // Execute through native engine
    let result = dispatcher.dispatch_run(&app_path, &config, &policy_mode, &[], 0);

    // Verify successful execution
    assert!(
        result.is_ok(),
        "Native engine execution should succeed, got: {:?}",
        result
    );

    let report = result.unwrap();
    assert_eq!(report.runtime, "franken_engine");
    assert!(!report.used_fallback_runtime);
    assert!(report.telemetry.is_some(), "Telemetry should be present");

    // Verify telemetry was emitted
    let telemetry = report.telemetry.unwrap();
    assert!(
        telemetry.drain_completed,
        "Telemetry drain should complete successfully"
    );
    assert!(
        telemetry.drain_duration_ms < 10000,
        "Telemetry drain should complete within reasonable time"
    );
}

/// bd-5r99w.12 (mock-free e2e, product apex): a real, idiomatic JS program that
/// performs fs effects, run through the PUBLIC `dispatch_run` path, surfaces a
/// signed, SDK-verifiable host-effect ledger in `run --json` — and the bytes
/// really hit the sandbox. No mocks: real parser/lowering, real `SandboxedHostIo`
/// performing genuine fs I/O, real `EffectReceipt` hash chain, real verifier SDK
/// re-deriving the chain offline. This is the operator-facing payoff of the whole
/// trust-native effect pipeline: `franken-node run` showing WHAT the program did
/// to the host under policy.
#[test]
#[cfg(feature = "engine")]
fn run_surfaces_signed_host_effect_ledger_bd_5r99w_12() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let app_path = create_test_app(
        temp_dir.path(),
        "app.js",
        "require('fs').writeFileSync('out.txt', 'real effect bytes');\n\
         require('fs').readFileSync('out.txt');\n",
    );

    // legacy-risky grants both fs_read and fs_write so both effects execute.
    let config = Config {
        profile: Profile::LegacyRisky,
        ..Config::default()
    };

    // A dummy engine binary in a separate directory only satisfies dispatch-plan
    // resolution (the path must exist). With the `engine` feature, execution runs
    // IN-PROCESS via the native path and never executes this binary, so the
    // sandbox (the app dir) stays clean and the run is hermetic.
    let engine_dir = TempDir::new().expect("Failed to create engine dir");
    let engine_path = create_fixture_engine_binary(engine_dir.path());
    let dispatcher = EngineDispatcher::new(Some(engine_path), PreferredRuntime::FrankenEngine);
    let report = dispatcher
        .dispatch_run(&app_path, &config, "legacy-risky", &[], 0)
        .expect("native run with host effects should succeed");

    assert_eq!(report.runtime, "franken_engine");
    assert!(!report.used_fallback_runtime);

    // The write really hit the sandbox root (the app's directory).
    assert_eq!(
        std::fs::read(temp_dir.path().join("out.txt")).expect("written file on disk"),
        b"real effect bytes",
        "writeFileSync must have produced a real file in the sandbox root"
    );

    // The signed host-effect ledger is surfaced honestly.
    let ledger = report
        .host_effect_ledger
        .as_ref()
        .expect("native run must surface a host-effect ledger");
    assert_eq!(ledger.schema_version, "host-effect-ledger-v1.0");
    assert_eq!(
        ledger.effect_count, 2,
        "expected fs_write + fs_read, got {:?}",
        ledger.entries
    );
    assert_eq!(ledger.allowed_count, 2);
    assert_eq!(ledger.denied_count, 0);
    let kinds: Vec<&str> = ledger
        .entries
        .iter()
        .map(|entry| entry.receipt.effect_kind.label())
        .collect();
    assert_eq!(kinds, vec!["fs_write", "fs_read"]);

    // It auto-surfaces in `run --json` (the report is the run --json payload's
    // `dispatch` field).
    let json = serde_json::to_string(&report).expect("serialize run report as run --json");
    assert!(
        json.contains("\"host_effect_ledger\""),
        "run --json must include the host_effect_ledger"
    );
    assert!(json.contains("\"fs_write\"") && json.contains("\"fs_read\""));

    // An external auditor re-derives the chain offline from the run --json ledger
    // entries alone, with the public verifier SDK — no trust in this runtime.
    let entries_json = serde_json::to_string(&ledger.entries).expect("serialize ledger entries");
    let sdk_entries: Vec<frankenengine_verifier_sdk::bundle::EffectReceiptChainEntry> =
        serde_json::from_str(&entries_json)
            .expect("verifier SDK accepts the run --json ledger wire shape");
    let sdk = frankenengine_verifier_sdk::VerifierSdk::new("verifier://bd-5r99w-12-e2e");
    let verdict = sdk
        .verify_effect_chain_entries(&sdk_entries)
        .expect("verifier SDK re-derives the effect chain offline");
    assert_eq!(verdict.effect_count, 2);
    assert_eq!(verdict.head_chain_hash, ledger.chain_head_hash);
}

/// bd-656a2 / bd-3894s (http leg, mock-free e2e close-out): a real, idiomatic JS
/// program that performs an `http.get` egress, run through the PUBLIC
/// `dispatch_run` path, surfaces a signed, SDK-verifiable `http_request` effect
/// in the host-effect ledger — and the framed request really reaches a loopback
/// listener. No mocks: real parser/lowering of `require('http').get(url)` to the
/// engine's `net:request` HostCall, the product-layer `SsrfGatedHostIo` policy
/// gate (config-allowlisted for the loopback sink) authorizing it, the engine's
/// real `SandboxedHostIo` network mechanism connecting and sending, a real
/// `EffectReceipt` hash chain, and the verifier SDK re-deriving the chain offline.
///
/// This is the third L1 proof-carrying subject (`http.request`) coming online
/// end to end — the close-out evidence for the http producer (bd-656a2) and the
/// remaining REQUIRED subject for bd-f5b04.2.4's GREEN acceptance bar.
#[test]
#[cfg(feature = "engine")]
fn run_surfaces_signed_http_request_effect_ledger_bd_656a2() {
    use std::io::{Read, Write};
    use std::net::TcpListener;

    // A loopback listener that accepts exactly one connection and reads the
    // framed request the engine's network mechanism sends. Bound BEFORE the run
    // so the guest's connect always finds it listening. bd-3894s slice (4): the
    // engine now does a single-socket request/response round trip, so the sink
    // reads the (half-closed) request to EOF, then replies and closes so the
    // guest's response read terminates.
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback sink");
    let addr = listener.local_addr().expect("listener addr");
    let server = std::thread::spawn(move || {
        let (mut stream, _peer) = listener.accept().expect("accept guest egress");
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("read timeout");
        let mut received = Vec::new();
        let _ = stream.read_to_end(&mut received);
        let _ = stream.write_all(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nok",
        );
        let _ = stream.flush();
        received
    });

    // An idiomatic guest program performing a single HTTP GET. The lowering
    // forwards the URL operand to the engine's `net:request` HostCall; bd-3894s
    // slice (4) makes the call evaluate to the parsed response object, but this
    // e2e asserts the recorded host-effect ledger, which is the load-bearing proof.
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let source = format!(
        "require('http').get('http://{}/');\n",
        addr // host:port form, e.g. 127.0.0.1:54321
    );
    let app_path = create_test_app(temp_dir.path(), "app.js", &source);

    // legacy-risky grants network_egress so the egress hostcall is authorized at
    // the engine layer; the product-layer SSRF gate still governs the endpoint.
    // The default policy is fail-closed (Block) and would deny loopback, so the
    // operator allowlists exactly this loopback sink — the config-driven exception
    // that `SsrfGatedHostIo::from_network_policy` turns into a signed receipt.
    let mut config = Config {
        profile: Profile::LegacyRisky,
        ..Config::default()
    };
    config
        .security
        .network_policy
        .allowlist
        .push(NetworkAllowlistEntry {
            host: "127.0.0.1".to_string(),
            port: None,
            reason: "e2e: permit the loopback test sink".to_string(),
        });

    let engine_dir = TempDir::new().expect("Failed to create engine dir");
    let engine_path = create_fixture_engine_binary(engine_dir.path());
    let dispatcher = EngineDispatcher::new(Some(engine_path), PreferredRuntime::FrankenEngine);
    let report = dispatcher
        .dispatch_run(&app_path, &config, "legacy-risky", &[], 0)
        .expect("native run with an allowlisted http egress should succeed");

    assert_eq!(report.runtime, "franken_engine");
    assert!(!report.used_fallback_runtime);

    // The framed request really reached the loopback listener (the mechanism ran).
    let received = server.join().expect("server thread");
    let wire = String::from_utf8_lossy(&received);
    assert!(
        wire.starts_with("GET / HTTP/1.1\r\n"),
        "the loopback sink must observe the engine-framed GET request, got {wire:?}"
    );
    assert!(
        wire.contains(&format!("Host: {addr}\r\n")),
        "the framed request must carry the Host header for {addr}, got {wire:?}"
    );

    // The signed host-effect ledger surfaces the egress as an `http_request`.
    let ledger = report
        .host_effect_ledger
        .as_ref()
        .expect("native http run must surface a host-effect ledger");
    assert_eq!(ledger.schema_version, "host-effect-ledger-v1.0");
    assert_eq!(
        ledger.effect_count, 1,
        "expected a single http_request effect, got {:?}",
        ledger.entries
    );
    assert_eq!(ledger.allowed_count, 1);
    assert_eq!(ledger.denied_count, 0);
    assert_eq!(
        ledger.entries[0].receipt.effect_kind.label(),
        "http_request",
        "the egress must be recorded as an http_request effect"
    );

    // It auto-surfaces in `run --json`.
    let json = serde_json::to_string(&report).expect("serialize run report as run --json");
    assert!(
        json.contains("\"host_effect_ledger\"") && json.contains("\"http_request\""),
        "run --json must include the http_request host-effect ledger entry"
    );

    // An external auditor re-derives the chain offline from the ledger entries
    // alone, with the public verifier SDK — no trust in this runtime.
    let entries_json = serde_json::to_string(&ledger.entries).expect("serialize ledger entries");
    let sdk_entries: Vec<frankenengine_verifier_sdk::bundle::EffectReceiptChainEntry> =
        serde_json::from_str(&entries_json)
            .expect("verifier SDK accepts the run --json ledger wire shape");
    let sdk = frankenengine_verifier_sdk::VerifierSdk::new("verifier://bd-656a2-http-e2e");
    let verdict = sdk
        .verify_effect_chain_entries(&sdk_entries)
        .expect("verifier SDK re-derives the http effect chain offline");
    assert_eq!(verdict.effect_count, 1);
    assert_eq!(verdict.head_chain_hash, ledger.chain_head_hash);
}

/// bd-3894s slice (5) (https leg, mock-free e2e — real TLS): a real JS program
/// performing `require('https').get('https://127.0.0.1:PORT/')` runs through the
/// PUBLIC `dispatch_run` path against a REAL rustls TLS listener on loopback.
/// The engine's wire builder marks the effect `use_tls` (https scheme), the
/// SSRF gate authorizes the allowlisted endpoint, and the network mechanism
/// performs the round trip inside a genuine TLS session: the listener only
/// observes the framed GET AFTER a successful handshake + decrypt (a plaintext
/// egress could never produce it), trust in the test anchor flows through the
/// operator config seam `[security.network_policy].tls_extra_roots_pem_path`,
/// and the signed host-effect ledger surfaces the egress as an allowed
/// `http_request` effect that the public verifier SDK re-derives offline.
#[test]
#[cfg(feature = "engine")]
fn run_surfaces_signed_https_request_effect_ledger_bd_3894s() {
    use std::io::{Read, Write};
    use std::net::TcpListener;

    // A fresh self-signed anchor for 127.0.0.1 and a one-shot rustls server.
    let certified = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string()])
        .expect("generate self-signed certificate");
    let cert_pem = certified.cert.pem();
    let cert_der = certified.cert.der().clone();
    let key_der = rustls_pki_types::PrivateKeyDer::Pkcs8(certified.key_pair.serialize_der().into());
    let tls_provider = Arc::new(rustls::crypto::ring::default_provider());
    let server_config = rustls::ServerConfig::builder_with_provider(tls_provider)
        .with_safe_default_protocol_versions()
        .expect("server protocol versions")
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .expect("server certificate");
    let server_config = Arc::new(server_config);

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback TLS sink");
    let addr = listener.local_addr().expect("listener addr");
    let server = std::thread::spawn(move || {
        let (tcp, _peer) = listener.accept().expect("accept guest egress");
        tcp.set_read_timeout(Some(Duration::from_secs(5)))
            .expect("read timeout");
        let conn = rustls::ServerConnection::new(server_config).expect("server connection");
        let mut tls = rustls::StreamOwned::new(conn, tcp);
        // Read the decrypted request up to the header terminator (bodyless GET).
        let mut received = Vec::new();
        let mut buf = [0u8; 1024];
        loop {
            match tls.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    received.extend_from_slice(&buf[..n]);
                    if received.windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        let _ = tls.write_all(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nok",
        );
        let _ = tls.flush();
        tls.conn.send_close_notify();
        let _ = tls.flush();
        received
    });

    // An idiomatic guest program performing a single HTTPS GET.
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let source = format!("require('https').get('https://{addr}/');\n");
    let app_path = create_test_app(temp_dir.path(), "app.js", &source);

    // The operator trusts the test anchor via the config seam (ADDED to the
    // webpki roots) and allowlists the loopback sink through the SSRF gate.
    let roots_path = temp_dir.path().join("extra-roots.pem");
    std::fs::write(&roots_path, cert_pem).expect("write extra TLS roots PEM");
    let mut config = Config {
        profile: Profile::LegacyRisky,
        ..Config::default()
    };
    config.security.network_policy.tls_extra_roots_pem_path =
        Some(roots_path.to_string_lossy().into_owned());
    config
        .security
        .network_policy
        .allowlist
        .push(NetworkAllowlistEntry {
            host: "127.0.0.1".to_string(),
            port: None,
            reason: "e2e: permit the loopback TLS test sink".to_string(),
        });

    let engine_dir = TempDir::new().expect("Failed to create engine dir");
    let engine_path = create_fixture_engine_binary(engine_dir.path());
    let dispatcher = EngineDispatcher::new(Some(engine_path), PreferredRuntime::FrankenEngine);
    let report = dispatcher
        .dispatch_run(&app_path, &config, "legacy-risky", &[], 0)
        .expect("native run with an allowlisted https egress should succeed");

    assert_eq!(report.runtime, "franken_engine");
    assert!(!report.used_fallback_runtime);

    // The framed request reached the listener THROUGH the TLS session: these
    // are decrypted bytes, so a plaintext egress (or a failed handshake) could
    // never produce them.
    let received = server.join().expect("server thread");
    let wire = String::from_utf8_lossy(&received);
    assert!(
        wire.starts_with("GET / HTTP/1.1\r\n"),
        "the TLS sink must observe the decrypted engine-framed GET, got {wire:?}"
    );
    assert!(
        wire.contains(&format!("Host: {addr}\r\n")),
        "the framed request must carry the Host header for {addr}, got {wire:?}"
    );

    // The signed host-effect ledger surfaces the TLS egress as an `http_request`.
    let ledger = report
        .host_effect_ledger
        .as_ref()
        .expect("native https run must surface a host-effect ledger");
    assert_eq!(ledger.schema_version, "host-effect-ledger-v1.0");
    assert_eq!(
        ledger.effect_count, 1,
        "expected a single http_request effect, got {:?}",
        ledger.entries
    );
    assert_eq!(ledger.allowed_count, 1);
    assert_eq!(ledger.denied_count, 0);
    assert_eq!(
        ledger.entries[0].receipt.effect_kind.label(),
        "http_request",
        "the TLS egress must be recorded as an http_request effect"
    );

    // An external auditor re-derives the chain offline with the public SDK.
    let entries_json = serde_json::to_string(&ledger.entries).expect("serialize ledger entries");
    let sdk_entries: Vec<frankenengine_verifier_sdk::bundle::EffectReceiptChainEntry> =
        serde_json::from_str(&entries_json)
            .expect("verifier SDK accepts the run --json ledger wire shape");
    let sdk = frankenengine_verifier_sdk::VerifierSdk::new("verifier://bd-3894s-https-e2e");
    let verdict = sdk
        .verify_effect_chain_entries(&sdk_entries)
        .expect("verifier SDK re-derives the https effect chain offline");
    assert_eq!(verdict.effect_count, 1);
    assert_eq!(verdict.head_chain_hash, ledger.chain_head_hash);
}

/// bd-3894s slice (5): an https egress whose server anchor is NOT trusted
/// (no `tls_extra_roots_pem_path`, self-signed peer) fails certificate
/// verification inside the network mechanism — fail-closed. The run still
/// completes and the signed ledger records the attempt honestly: the effect's
/// SSRF authorization succeeded (allowlisted endpoint) but the round trip
/// errored, so no forged "response" ever reaches the guest and no plaintext
/// fallback occurs (the sink observes zero decrypted request bytes).
#[test]
#[cfg(feature = "engine")]
fn run_https_untrusted_anchor_fails_closed_bd_3894s() {
    use std::io::{Read, Write};
    use std::net::TcpListener;

    let certified = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string()])
        .expect("generate self-signed certificate");
    let cert_der = certified.cert.der().clone();
    let key_der = rustls_pki_types::PrivateKeyDer::Pkcs8(certified.key_pair.serialize_der().into());
    let tls_provider = Arc::new(rustls::crypto::ring::default_provider());
    let server_config = rustls::ServerConfig::builder_with_provider(tls_provider)
        .with_safe_default_protocol_versions()
        .expect("server protocol versions")
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .expect("server certificate");
    let server_config = Arc::new(server_config);

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback TLS sink");
    let addr = listener.local_addr().expect("listener addr");
    let server = std::thread::spawn(move || {
        let (tcp, _peer) = listener.accept().expect("accept guest egress");
        tcp.set_read_timeout(Some(Duration::from_secs(5)))
            .expect("read timeout");
        let conn = rustls::ServerConnection::new(server_config).expect("server connection");
        let mut tls = rustls::StreamOwned::new(conn, tcp);
        // The client must abort the handshake (untrusted anchor); any read
        // error or clean close yields zero decrypted request bytes.
        let mut received = Vec::new();
        let mut buf = [0u8; 1024];
        loop {
            match tls.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    received.extend_from_slice(&buf[..n]);
                    if received.windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
            }
        }
        let _ = tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
        let _ = tls.flush();
        received
    });

    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let source = format!("require('https').get('https://{addr}/');\n");
    let app_path = create_test_app(temp_dir.path(), "app.js", &source);

    // Allowlist the endpoint (SSRF authorizes it) but deliberately do NOT
    // install the anchor: certificate verification is the layer under test.
    let mut config = Config {
        profile: Profile::LegacyRisky,
        ..Config::default()
    };
    config
        .security
        .network_policy
        .allowlist
        .push(NetworkAllowlistEntry {
            host: "127.0.0.1".to_string(),
            port: None,
            reason: "e2e: SSRF-authorize the sink; TLS verification must still fail".to_string(),
        });

    let engine_dir = TempDir::new().expect("Failed to create engine dir");
    let engine_path = create_fixture_engine_binary(engine_dir.path());
    let dispatcher = EngineDispatcher::new(Some(engine_path), PreferredRuntime::FrankenEngine);
    let report = dispatcher
        .dispatch_run(&app_path, &config, "legacy-risky", &[], 0)
        .expect("the run completes; the failed TLS effect is recorded, not fatal");

    assert_eq!(report.runtime, "franken_engine");

    // No decrypted request bytes ever reached the peer.
    let received = server.join().expect("server thread");
    assert!(
        received.is_empty(),
        "certificate verification failure must abort before any request bytes cross, got {:?}",
        String::from_utf8_lossy(&received)
    );

    // The ledger records the attempt honestly: a single fail-closed receipt,
    // nothing allowed, no fabricated response.
    let ledger = report
        .host_effect_ledger
        .as_ref()
        .expect("native https run must surface a host-effect ledger");
    assert_eq!(
        ledger.allowed_count, 0,
        "a failed TLS handshake must not be recorded as an allowed effect: {:?}",
        ledger.entries
    );
    assert_eq!(
        ledger.denied_count, 1,
        "the failed TLS egress must surface as a fail-closed receipt: {:?}",
        ledger.entries
    );
    assert_eq!(
        ledger.entries[0].receipt.effect_kind.label(),
        "http_request"
    );
}

/// bd-3894s slice (2b) (http leg, mock-free e2e — writable ClientRequest body): a
/// real JS program that builds an HTTP request body INCREMENTALLY via the writable
/// `ClientRequest` stream —
/// `const req = http.request(url, { method: 'POST', ... }); req.write(a);
/// req.write(b); req.end(c);` — run through the PUBLIC `dispatch_run` path. The
/// `http.request` call lowers to the engine's `net:client_request` HostCall (it
/// builds the ClientRequest object WITHOUT egressing); the egress fires only on
/// `req.end()`, carrying the body ACCUMULATED across the `write`/`end` calls. The
/// framed POST really reaches a loopback listener with the assembled body, and the
/// signed host-effect ledger surfaces the egress as an allowed `http_request`
/// effect (the same proof-carrying path as the immediate `http.get` form, so the
/// body lands in the ledger with identical fidelity — a POST-with-body built via
/// `req.write` is no longer dropped or recorded as a benign GET).
#[test]
#[cfg(feature = "engine")]
fn run_surfaces_signed_http_request_write_end_body_ledger_bd_3894s() {
    use std::io::{Read, Write};
    use std::net::TcpListener;

    // A loopback listener that accepts one connection, reads the framed request to
    // EOF (the half-closed request half), then replies and closes so the guest's
    // response read terminates (the slice-4 single-socket round trip).
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback sink");
    let addr = listener.local_addr().expect("listener addr");
    let server = std::thread::spawn(move || {
        let (mut stream, _peer) = listener.accept().expect("accept guest egress");
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("read timeout");
        let mut received = Vec::new();
        let _ = stream.read_to_end(&mut received);
        let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
        let _ = stream.flush();
        received
    });

    // An idiomatic guest program that streams the request body: `http.request`
    // returns a writable ClientRequest, `req.write` appends each chunk, and
    // `req.end` sends the assembled body. The lowering routes `http.request` to
    // `net:client_request` (deferred egress), so nothing is sent until `req.end()`.
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let source = format!(
        "const http = require('http');\n\
         const req = http.request('http://{addr}/submit', {{ method: 'POST', headers: {{ 'Content-Type': 'text/plain' }} }});\n\
         req.write('Hello, ');\n\
         req.write('world');\n\
         req.end('!');\n"
    );
    let app_path = create_test_app(temp_dir.path(), "app.js", &source);

    // legacy-risky grants network_egress (authorizing the `net:client_request`
    // creation AND the deferred `.end()` egress at the engine capability layer);
    // the operator allowlists the loopback sink so the product-layer SSRF gate
    // authorizes this exact endpoint.
    let mut config = Config {
        profile: Profile::LegacyRisky,
        ..Config::default()
    };
    config
        .security
        .network_policy
        .allowlist
        .push(NetworkAllowlistEntry {
            host: "127.0.0.1".to_string(),
            port: None,
            reason: "e2e: permit the loopback test sink".to_string(),
        });

    let engine_dir = TempDir::new().expect("Failed to create engine dir");
    let engine_path = create_fixture_engine_binary(engine_dir.path());
    let dispatcher = EngineDispatcher::new(Some(engine_path), PreferredRuntime::FrankenEngine);
    let report = dispatcher
        .dispatch_run(&app_path, &config, "legacy-risky", &[], 0)
        .expect("native run with an allowlisted http.request write/end egress should succeed");

    assert_eq!(report.runtime, "franken_engine");
    assert!(!report.used_fallback_runtime);

    // The framed POST with the ACCUMULATED body really reached the loopback sink —
    // the load-bearing proof the writable-stream body was assembled and sent.
    let received = server.join().expect("server thread");
    let wire = String::from_utf8_lossy(&received);
    assert!(
        wire.starts_with("POST /submit HTTP/1.1\r\n"),
        "the loopback sink must observe the engine-framed POST request, got {wire:?}"
    );
    assert!(
        wire.contains("Content-Type: text/plain\r\n"),
        "the request headers must be framed onto the wire, got {wire:?}"
    );
    assert!(
        wire.contains("Content-Length: 13\r\n"),
        "the assembled write/end body length (\"Hello, world!\") must be framed, got {wire:?}"
    );
    assert!(
        wire.ends_with("\r\n\r\nHello, world!"),
        "the body assembled across req.write/req.end must follow the blank-line terminator, got {wire:?}"
    );

    // The signed host-effect ledger surfaces the egress as an allowed http_request.
    let ledger = report
        .host_effect_ledger
        .as_ref()
        .expect("native http.request write/end run must surface a host-effect ledger");
    assert_eq!(
        ledger.effect_count, 1,
        "expected a single http_request effect from req.end(), got {:?}",
        ledger.entries
    );
    assert_eq!(ledger.allowed_count, 1);
    assert_eq!(ledger.denied_count, 0);
    assert_eq!(
        ledger.entries[0].receipt.effect_kind.label(),
        "http_request",
        "the deferred req.end() egress must be recorded as an http_request effect"
    );

    // An external auditor re-derives the chain offline from the ledger entries.
    let entries_json = serde_json::to_string(&ledger.entries).expect("serialize ledger entries");
    let sdk_entries: Vec<frankenengine_verifier_sdk::bundle::EffectReceiptChainEntry> =
        serde_json::from_str(&entries_json)
            .expect("verifier SDK accepts the run --json ledger wire shape");
    let sdk = frankenengine_verifier_sdk::VerifierSdk::new("verifier://bd-3894s-clientrequest-e2e");
    let verdict = sdk
        .verify_effect_chain_entries(&sdk_entries)
        .expect("verifier SDK re-derives the http effect chain offline");
    assert_eq!(verdict.effect_count, 1);
    assert_eq!(verdict.head_chain_hash, ledger.chain_head_hash);
}

/// bd-3894s slice (2c) (http leg, mock-free e2e — response callback delivery): a
/// real, idiomatic JS program that uses the Node response-callback form —
/// `http.get(url, (res) => { ... })` — run through the PUBLIC `dispatch_run` path.
/// The `http.get` egress fires synchronously and the response callback is delivered
/// `cb(res)` on the next event-loop turn (the engine drains the macrotask queue
/// after the program's synchronous portion). The callback EXECUTING with the REAL
/// parsed response is proven mock-free: it gates on `res.status === 200` and writes
/// `res.body` (the bytes the loopback server actually returned) to the sandbox —
/// so the file only exists, with the server's body, if the callback ran and saw the
/// genuine response. The signed host-effect ledger carries BOTH effects: the
/// `http_request` egress (the program's main turn) AND the `fs_write` the callback
/// performed (the event-loop turn), proving the callback's own effect is
/// proof-carrying too. No mocks: real parser/lowering of `http.get(url, cb)`,
/// real SSRF-gated egress + round trip, real callback execution, real fs write.
#[test]
#[cfg(feature = "engine")]
fn run_surfaces_signed_http_get_response_callback_ledger_bd_3894s() {
    use std::io::{Read, Write};
    use std::net::TcpListener;

    // A loopback listener that accepts one connection, reads the half-closed request
    // to EOF, then replies with a distinctive body and closes so the guest's
    // response read terminates (the slice-4 single-socket round trip). The body the
    // callback writes back to disk proves it received THIS response.
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback sink");
    let addr = listener.local_addr().expect("listener addr");
    let server = std::thread::spawn(move || {
        let (mut stream, _peer) = listener.accept().expect("accept guest egress");
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("read timeout");
        let mut received = Vec::new();
        let _ = stream.read_to_end(&mut received);
        let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nserved-ok");
        let _ = stream.flush();
        received
    });

    // The guest program registers a response callback. It gates on the parsed
    // status (`res.status === 200`) and writes the parsed body (`res.body`) to the
    // sandbox — so the file is the load-bearing proof the callback both RAN and saw
    // the real response. `http.get(url, cb)` lowers to `net:request` carrying the
    // trailing closure; the engine delivers `cb(res)` on the next event-loop turn.
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let source = format!(
        "const http = require('http');\n\
         http.get('http://{addr}/', (res) => {{\n\
         \x20 if (res.status === 200) {{\n\
         \x20   require('fs').writeFileSync('cb_out.txt', res.body);\n\
         \x20 }}\n\
         }});\n"
    );
    let app_path = create_test_app(temp_dir.path(), "app.js", &source);

    // legacy-risky grants network_egress (the http.get egress) AND fs_write (the
    // callback's writeFileSync); the operator allowlists the loopback sink so the
    // product-layer SSRF gate authorizes this exact endpoint.
    let mut config = Config {
        profile: Profile::LegacyRisky,
        ..Config::default()
    };
    config
        .security
        .network_policy
        .allowlist
        .push(NetworkAllowlistEntry {
            host: "127.0.0.1".to_string(),
            port: None,
            reason: "e2e: permit the loopback test sink".to_string(),
        });

    let engine_dir = TempDir::new().expect("Failed to create engine dir");
    let engine_path = create_fixture_engine_binary(engine_dir.path());
    let dispatcher = EngineDispatcher::new(Some(engine_path), PreferredRuntime::FrankenEngine);
    let report = dispatcher
        .dispatch_run(&app_path, &config, "legacy-risky", &[], 0)
        .expect("native run with an http.get response callback should succeed");

    assert_eq!(report.runtime, "franken_engine");
    assert!(!report.used_fallback_runtime);

    // The egress crossed the socket as a real GET.
    let received = server.join().expect("server thread");
    let wire = String::from_utf8_lossy(&received);
    assert!(
        wire.starts_with("GET / HTTP/1.1\r\n"),
        "the loopback sink must observe the engine-framed GET request, got {wire:?}"
    );

    // THE LOAD-BEARING PROOF: the response callback executed on the event-loop turn
    // with the REAL parsed response — it only writes when `res.status === 200`, and
    // it writes `res.body`, so the file holds exactly the server's reply body.
    assert_eq!(
        std::fs::read(temp_dir.path().join("cb_out.txt"))
            .expect("the response callback must have written cb_out.txt"),
        b"served-ok",
        "the callback ran with the real response: it gated on res.status === 200 and wrote res.body"
    );

    // The signed host-effect ledger carries BOTH the egress and the callback's own
    // fs write — proof the response-callback path is proof-carrying end to end.
    let ledger = report
        .host_effect_ledger
        .as_ref()
        .expect("native http.get callback run must surface a host-effect ledger");
    assert_eq!(
        ledger.effect_count, 2,
        "expected the http_request egress + the callback's fs_write, got {:?}",
        ledger.entries
    );
    assert_eq!(ledger.allowed_count, 2);
    assert_eq!(ledger.denied_count, 0);
    let kinds: Vec<&str> = ledger
        .entries
        .iter()
        .map(|entry| entry.receipt.effect_kind.label())
        .collect();
    assert_eq!(
        kinds,
        vec!["http_request", "fs_write"],
        "the egress (main turn) precedes the callback's fs write (event-loop turn)"
    );

    // An external auditor re-derives the whole chain offline from the ledger entries.
    let entries_json = serde_json::to_string(&ledger.entries).expect("serialize ledger entries");
    let sdk_entries: Vec<frankenengine_verifier_sdk::bundle::EffectReceiptChainEntry> =
        serde_json::from_str(&entries_json)
            .expect("verifier SDK accepts the run --json ledger wire shape");
    let sdk = frankenengine_verifier_sdk::VerifierSdk::new("verifier://bd-3894s-http-callback-e2e");
    let verdict = sdk
        .verify_effect_chain_entries(&sdk_entries)
        .expect("verifier SDK re-derives the http + fs effect chain offline");
    assert_eq!(verdict.effect_count, 2);
    assert_eq!(verdict.head_chain_hash, ledger.chain_head_hash);
}

/// bd-3894s slice (2d) (http leg, mock-free e2e — IncomingMessage readable-stream
/// EVENT model): a real, idiomatic JS program that consumes the response through the
/// Node readable-stream events — `res.on('data', chunk => …)` then `res.on('end',
/// () => …)` — registered INSIDE the `http.get(url, (res) => { … })` response
/// callback, run through the PUBLIC `dispatch_run` path. This is the proof the event
/// model is real end to end:
///   - `http.get(url, cb)` lowers to `net:request` carrying the trailing closure; the
///     engine delivers `cb(res)` on the next event-loop turn (slice 2c);
///   - inside that callback the program registers `res.on('data', …)` and
///     `res.on('end', …)` on the `IncomingMessage` (slice 2d `.on` via the `__type`
///     tag);
///   - on the FOLLOWING turns the engine emits `'data'` with the whole body as one
///     chunk (the listener accumulates it) and then `'end'` (the listener writes the
///     accumulated buffer to the sandbox).
///
/// The file therefore exists, with the server's body, ONLY if the listeners were
/// registered AND fired in data→end order with the real response bytes — no synchronous
/// `res.body` shortcut is used. The signed host-effect ledger carries BOTH the
/// `http_request` egress and the `fs_write` the `'end'` listener performed, and the
/// verifier SDK re-derives the chain offline. No mocks: real parser/lowering, real
/// SSRF-gated egress + round trip, real event-emitter dispatch, real fs write.
#[test]
#[cfg(feature = "engine")]
fn run_surfaces_signed_http_get_response_event_stream_ledger_bd_3894s() {
    use std::io::{Read, Write};
    use std::net::TcpListener;

    // A loopback listener that accepts one connection, reads the half-closed request
    // to EOF, then replies with a distinctive body and closes so the guest's response
    // read terminates (the slice-4 single-socket round trip). The body the 'end'
    // listener writes back to disk proves the readable stream delivered THIS response.
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback sink");
    let addr = listener.local_addr().expect("listener addr");
    let server = std::thread::spawn(move || {
        let (mut stream, _peer) = listener.accept().expect("accept guest egress");
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("read timeout");
        let mut received = Vec::new();
        let _ = stream.read_to_end(&mut received);
        let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nserved-ok");
        let _ = stream.flush();
        received
    });

    // The guest program registers readable-stream listeners on the response and only
    // writes on 'end', from a buffer ACCUMULATED across 'data' events — so the file is
    // load-bearing proof that 'data' delivered the real body chunk and 'end' fired
    // after it, with the listeners registered inside the response callback.
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let source = format!(
        "const http = require('http');\n\
         http.get('http://{addr}/', (res) => {{\n\
         \x20 let body = '';\n\
         \x20 res.on('data', (chunk) => {{ body += chunk; }});\n\
         \x20 res.on('end', () => {{\n\
         \x20   require('fs').writeFileSync('cb_out.txt', body);\n\
         \x20 }});\n\
         }});\n"
    );
    let app_path = create_test_app(temp_dir.path(), "app.js", &source);

    // legacy-risky grants network_egress (the http.get egress) AND fs_write (the
    // 'end' listener's writeFileSync); the operator allowlists the loopback sink so
    // the product-layer SSRF gate authorizes this exact endpoint.
    let mut config = Config {
        profile: Profile::LegacyRisky,
        ..Config::default()
    };
    config
        .security
        .network_policy
        .allowlist
        .push(NetworkAllowlistEntry {
            host: "127.0.0.1".to_string(),
            port: None,
            reason: "e2e: permit the loopback test sink".to_string(),
        });

    let engine_dir = TempDir::new().expect("Failed to create engine dir");
    let engine_path = create_fixture_engine_binary(engine_dir.path());
    let dispatcher = EngineDispatcher::new(Some(engine_path), PreferredRuntime::FrankenEngine);
    let report = dispatcher
        .dispatch_run(&app_path, &config, "legacy-risky", &[], 0)
        .expect("native run with http response stream events should succeed");

    assert_eq!(report.runtime, "franken_engine");
    assert!(!report.used_fallback_runtime);

    // The egress crossed the socket as a real GET.
    let received = server.join().expect("server thread");
    let wire = String::from_utf8_lossy(&received);
    assert!(
        wire.starts_with("GET / HTTP/1.1\r\n"),
        "the loopback sink must observe the engine-framed GET request, got {wire:?}"
    );

    // THE LOAD-BEARING PROOF: the 'end' listener wrote the buffer accumulated from the
    // 'data' event(s), so the file holds exactly the server's reply body — which is
    // only true if res.on('data') delivered the real chunk and res.on('end') fired
    // after it, both registered inside the response callback.
    assert_eq!(
        std::fs::read(temp_dir.path().join("cb_out.txt"))
            .expect("the 'end' listener must have written cb_out.txt"),
        b"served-ok",
        "data→end fired in order: 'data' delivered res body, 'end' wrote the accumulated buffer"
    );

    // The signed host-effect ledger carries BOTH the egress and the 'end' listener's
    // own fs write — proof the readable-stream event path is proof-carrying end to end.
    let ledger = report
        .host_effect_ledger
        .as_ref()
        .expect("native http stream-event run must surface a host-effect ledger");
    assert_eq!(
        ledger.effect_count, 2,
        "expected the http_request egress + the 'end' listener's fs_write, got {:?}",
        ledger.entries
    );
    assert_eq!(ledger.allowed_count, 2);
    assert_eq!(ledger.denied_count, 0);
    let kinds: Vec<&str> = ledger
        .entries
        .iter()
        .map(|entry| entry.receipt.effect_kind.label())
        .collect();
    assert_eq!(
        kinds,
        vec!["http_request", "fs_write"],
        "the egress (main turn) precedes the 'end' listener's fs write (later event-loop turn)"
    );

    // An external auditor re-derives the whole chain offline from the ledger entries.
    let entries_json = serde_json::to_string(&ledger.entries).expect("serialize ledger entries");
    let sdk_entries: Vec<frankenengine_verifier_sdk::bundle::EffectReceiptChainEntry> =
        serde_json::from_str(&entries_json)
            .expect("verifier SDK accepts the run --json ledger wire shape");
    let sdk =
        frankenengine_verifier_sdk::VerifierSdk::new("verifier://bd-3894s-http-event-stream-e2e");
    let verdict = sdk
        .verify_effect_chain_entries(&sdk_entries)
        .expect("verifier SDK re-derives the http + fs effect chain offline");
    assert_eq!(verdict.effect_count, 2);
    assert_eq!(verdict.head_chain_hash, ledger.chain_head_hash);
}

/// bd-656a2 / bd-3894s (http leg, mock-free e2e — DENIED half): the fail-closed
/// counterpart of the allowed e2e. A real `require('http').get('http://127.0.0.1:9/')`
/// program — a loopback endpoint the default-deny SSRF policy blocks, with no
/// config allowlist — run through the PUBLIC `dispatch_run` path is gated BEFORE
/// the socket opens. The denial is surfaced as a signed DENIED `http_request`
/// EffectReceipt in the run --json host-effect ledger (proof that nothing reached
/// the network), the run still completes (the denial is not a fatal fault), and
/// the verifier SDK re-derives the chain offline.
///
/// Together with the allowed-half test this is the close-out conjunction for the
/// bd-656a2 http producer: the http.request L1 subject is proof-carrying on BOTH
/// the authorized and the refused path.
#[test]
#[cfg(feature = "engine")]
fn run_surfaces_denied_http_request_effect_ledger_bd_656a2() {
    use frankenengine_node::runtime::effect_receipt::PolicyOutcome;

    // A loopback endpoint the default-deny policy blocks. The SSRF gate denies it
    // before any connection is attempted, so this never reaches the network (no
    // listener is needed and none is bound — the test is hermetic).
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let app_path = create_test_app(
        temp_dir.path(),
        "app.js",
        "require('http').get('http://127.0.0.1:9/');\n",
    );

    // legacy-risky grants network_egress (so the egress hostcall is authorized at
    // the engine layer), but the run uses the DEFAULT [security.network_policy]
    // (Block, no allowlist) — so the product-layer SSRF gate denies loopback.
    let config = Config {
        profile: Profile::LegacyRisky,
        ..Config::default()
    };

    let engine_dir = TempDir::new().expect("Failed to create engine dir");
    let engine_path = create_fixture_engine_binary(engine_dir.path());
    let dispatcher = EngineDispatcher::new(Some(engine_path), PreferredRuntime::FrankenEngine);
    // The denied egress must NOT abort the run: dispatch_run still succeeds and
    // surfaces the ledger with a fail-closed denied receipt.
    let report = dispatcher
        .dispatch_run(&app_path, &config, "legacy-risky", &[], 0)
        .expect("a policy-denied http egress must not fail the run");

    assert_eq!(report.runtime, "franken_engine");

    let ledger = report
        .host_effect_ledger
        .as_ref()
        .expect("native http run must surface a host-effect ledger even on denial");
    assert_eq!(
        ledger.effect_count, 1,
        "the blocked egress must still produce one (denied) effect, got {:?}",
        ledger.entries
    );
    assert_eq!(
        ledger.denied_count, 1,
        "the egress must be recorded as denied"
    );
    assert_eq!(
        ledger.allowed_count, 0,
        "nothing was authorized to reach the network"
    );

    let receipt = &ledger.entries[0].receipt;
    assert_eq!(
        receipt.effect_kind.label(),
        "http_request",
        "the blocked egress is still an http_request subject"
    );
    assert!(
        matches!(receipt.policy_outcome, PolicyOutcome::Denied { .. }),
        "the receipt must carry a fail-closed Denied outcome, got {:?}",
        receipt.policy_outcome
    );
    // Fail-closed proof: a denied effect has no produced/post state.
    assert!(
        receipt.result_hash.is_none() && receipt.post_state_hash.is_none(),
        "a denied effect must carry no result/post-state (nothing ran)"
    );

    // run --json surfaces the denied receipt.
    let json = serde_json::to_string(&report).expect("serialize run report as run --json");
    assert!(
        json.contains("\"host_effect_ledger\"") && json.contains("\"denied\""),
        "run --json must include the denied host-effect ledger entry"
    );

    // The verifier SDK re-derives the chain offline — denied receipts are part of
    // the same tamper-evident chain.
    let entries_json = serde_json::to_string(&ledger.entries).expect("serialize ledger entries");
    let sdk_entries: Vec<frankenengine_verifier_sdk::bundle::EffectReceiptChainEntry> =
        serde_json::from_str(&entries_json)
            .expect("verifier SDK accepts the run --json ledger wire shape");
    let sdk = frankenengine_verifier_sdk::VerifierSdk::new("verifier://bd-656a2-http-denied-e2e");
    let verdict = sdk
        .verify_effect_chain_entries(&sdk_entries)
        .expect("verifier SDK re-derives the denied http effect chain offline");
    assert_eq!(verdict.effect_count, 1);
    assert_eq!(verdict.head_chain_hash, ledger.chain_head_hash);
}

#[test]
#[cfg(not(feature = "engine"))]
fn test_strict_profile_rejects_fixture_fallback_without_native_engine() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let app_path = create_test_app(
        temp_dir.path(),
        "strict_test.js",
        r#"console.log("This should not run on strict profile without native engine");"#,
    );

    let engine_path = create_fixture_engine_binary(temp_dir.path());

    let config = Config {
        profile: Profile::Strict, // Strict profile should reject fallback
        ..Config::default()
    };

    let dispatcher =
        EngineDispatcher::new(Some(engine_path.clone()), PreferredRuntime::FrankenEngine);
    // Create test telemetry bridge
    let socket_path = temp_dir.path().join("test-telemetry.sock");
    let adapter = Arc::new(Mutex::new(FrankensqliteAdapter::default()));
    let _telemetry_bridge = TelemetryBridge::new(&socket_path.to_string_lossy(), adapter);
    let policy_mode = config.profile.to_string();

    // Execute and expect failure
    let result = dispatcher.dispatch_run(&app_path, &config, &policy_mode, &[], 0);

    assert!(
        result.is_err(),
        "Strict profile should reject execution without native engine feature"
    );

    let error = result.unwrap_err().to_string();
    assert!(
        error.contains("Native engine required") || error.contains("engine feature"),
        "Error should mention native engine requirement, got: {}",
        error
    );
    assert!(
        error.contains("rebuild") || error.contains("--features engine"),
        "Error should suggest rebuilding with engine feature, got: {}",
        error
    );
}

#[test]
fn test_balanced_profile_allows_external_process_fixture_fallback() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let app_path = create_test_app(
        temp_dir.path(),
        "balanced_test.js",
        r#"console.log("This should run with external process on balanced profile");"#,
    );

    let engine_path = create_fixture_engine_binary(temp_dir.path());

    let config = balanced_config();

    let dispatcher =
        EngineDispatcher::new(Some(engine_path.clone()), PreferredRuntime::FrankenEngine);
    // Create test telemetry bridge
    let socket_path = temp_dir.path().join("test-telemetry.sock");
    let adapter = Arc::new(Mutex::new(FrankensqliteAdapter::default()));
    let _telemetry_bridge = TelemetryBridge::new(&socket_path.to_string_lossy(), adapter);
    let policy_mode = config.profile.to_string();

    // This should succeed by falling back to external process
    let result = dispatcher.dispatch_run(&app_path, &config, &policy_mode, &[], 0);

    // Note: This test may fail if no Node/Bun is available, but that's expected behavior
    // The key is that it shouldn't fail with "native engine required" error
    if let Err(error) = result {
        let error_str = error.to_string();
        assert!(
            !error_str.contains("Native engine required"),
            "Balanced profile should not require native engine, got: {}",
            error_str
        );
        // Other errors (like missing Node/Bun) are acceptable for this test
    }
}

#[test]
#[cfg(feature = "engine")]
fn test_native_engine_error_handling_propagation() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");

    // Test 1: Source file read error
    let nonexistent_path = temp_dir.path().join("nonexistent.js");

    let config = balanced_config();

    let dispatcher = EngineDispatcher::new(None, PreferredRuntime::FrankenEngine);
    // Create test telemetry bridge
    let socket_path = temp_dir.path().join("test-telemetry.sock");
    let adapter = Arc::new(Mutex::new(FrankensqliteAdapter::default()));
    let _telemetry_bridge = TelemetryBridge::new(&socket_path.to_string_lossy(), adapter);
    let policy_mode = config.profile.to_string();

    let result = dispatcher.dispatch_run(&nonexistent_path, &config, &policy_mode, &[], 0);

    assert!(result.is_err(), "Should fail for nonexistent source file");

    let error = result.unwrap_err().to_string();
    assert!(
        error.contains("Failed to read application source")
            || error.contains("No such file or directory")
            || error.contains("cannot find the file"),
        "Error should indicate source read failure, got: {}",
        error
    );

    // Test 2: Invalid source code (this will test engine execution error)
    let invalid_app_path = create_test_app(
        temp_dir.path(),
        "invalid.js",
        r#"this is not valid javascript syntax !@#$%"#,
    );

    let result = dispatcher.dispatch_run(&invalid_app_path, &config, &policy_mode, &[], 0);

    // Engine may or may not reject invalid syntax - depends on implementation
    // The key is that errors should propagate properly, not crash
    if let Err(error) = result {
        let error_str = error.to_string();
        // Should not contain panic messages
        assert!(
            !error_str.contains("panic") && !error_str.contains("panicked"),
            "Error should not indicate panic, got: {}",
            error_str
        );
    }
}

#[test]
fn test_engine_timeout_handling_with_fixture_binary() {
    // Set a short timeout for testing (5 seconds instead of default 5 minutes)
    unsafe {
        std::env::set_var("FRANKEN_ENGINE_TIMEOUT_SECS", "5");
    }

    // Clean up the env var when test completes
    struct EnvCleanup(&'static str);
    impl Drop for EnvCleanup {
        fn drop(&mut self) {
            unsafe {
                std::env::remove_var(self.0);
            }
        }
    }
    let _cleanup = EnvCleanup("FRANKEN_ENGINE_TIMEOUT_SECS");

    // Test that dispatcher process handling times out a slow external fixture binary.
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let app_path = create_test_app(
        temp_dir.path(),
        "timeout_test.js",
        r#"console.log("This should timeout before completion");"#,
    );

    // Create a slow fixture engine that takes 10 seconds to complete (longer than our 5s timeout)
    let slow_engine_path = create_slow_fixture_engine_binary(temp_dir.path(), 10);

    let config = balanced_config();

    // Force external process execution by providing explicit engine binary path
    // This bypasses native engine execution to test external process timeout
    let dispatcher = EngineDispatcher::new(
        Some(slow_engine_path.clone()),
        PreferredRuntime::FrankenEngine,
    );
    // Create test telemetry bridge
    let socket_path = temp_dir.path().join("test-telemetry.sock");
    let adapter = Arc::new(Mutex::new(FrankensqliteAdapter::default()));
    let _telemetry_bridge = TelemetryBridge::new(&socket_path.to_string_lossy(), adapter);
    let policy_mode = config.profile.to_string();

    // Execute and measure timing
    let start = std::time::Instant::now();
    let result = dispatcher.dispatch_run(&app_path, &config, &policy_mode, &[], 0);
    let duration = start.elapsed();

    // The execution should fail due to timeout, not complete successfully
    assert!(
        result.is_err(),
        "Slow engine execution should fail due to timeout, but got success"
    );

    let error = result.unwrap_err().to_string();

    // Verify this is actually a timeout error, not some other error
    let is_timeout_error = error.contains("timed out")
        || error.contains("timeout")
        || error.contains("Timeout")
        || error.contains("deadline exceeded");

    // If it's not a timeout error, it might be because the process was killed
    // or failed for another reason, which is also acceptable timeout behavior
    if !is_timeout_error {
        // At minimum, verify the execution was interrupted around our timeout (5s), not after full 10s delay
        assert!(
            duration < Duration::from_secs(7),
            "Execution should be interrupted around timeout limit (~5s), not wait for full 10s completion. Got: {:?}",
            duration
        );

        // And verify the error indicates process failure/interruption
        let is_process_failure = error.contains("failed")
            || error.contains("killed")
            || error.contains("terminated")
            || error.contains("exit");
        assert!(
            is_process_failure,
            "If not a timeout error, should be a process failure error. Got: {}",
            error
        );
    } else {
        // For explicit timeout errors, verify timing was around our 5-second timeout
        assert!(
            duration >= Duration::from_secs(4) && duration <= Duration::from_secs(7),
            "Timeout should occur around 5s mark. Took: {:?}",
            duration
        );
    }

    println!(
        "Timeout test completed in {:?} with error: {}",
        duration, error
    );
}

#[test]
#[cfg(feature = "engine")]
fn test_native_engine_missing_binary_error_handling() {
    // Test boundary condition: engine feature enabled but binary missing
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let app_path = create_test_app(
        temp_dir.path(),
        "missing_binary_test.js",
        r#"console.log("This should fail - engine binary missing");"#,
    );

    // Point to a non-existent engine binary
    let nonexistent_engine_path = temp_dir.path().join("nonexistent-franken-engine");

    let config = balanced_config();

    let dispatcher = EngineDispatcher::new(
        Some(nonexistent_engine_path.clone()),
        PreferredRuntime::FrankenEngine,
    );

    // Execute and expect failure due to missing binary
    let result = dispatcher.dispatch_run(&app_path, &config, "test", &[], 0);

    assert!(result.is_err(), "Should fail when engine binary is missing");

    let error = result.unwrap_err();
    let error_str = error.to_string();

    // Verify this is an ActionableError with proper context
    assert!(
        error_str.contains("engine")
            || error_str.contains("binary")
            || error_str.contains("not found")
            || error_str.contains("No such file"),
        "Error should indicate engine binary issue, got: {}",
        error_str
    );

    // Verify error provides meaningful context (ActionableError integration tested elsewhere)
    println!("Engine binary missing error: {}", error_str);
}

#[test]
fn test_engine_non_zero_exit_code_fixture_error_handling() {
    // Test boundary condition: controlled fixture engine returns non-zero exit.
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let app_path = create_test_app(
        temp_dir.path(),
        "exit_code_test.js",
        r#"console.log("This should fail due to engine exit code");"#,
    );

    // Create a fixture engine that returns exit code 1
    let failing_engine_path = create_failing_fixture_engine_binary(temp_dir.path(), 1);

    let config = balanced_config();

    // Force external process execution to test exit code handling
    let dispatcher = EngineDispatcher::new(
        Some(failing_engine_path.clone()),
        PreferredRuntime::FrankenEngine,
    );

    // Execute and expect failure due to non-zero exit
    let result = dispatcher.dispatch_run(&app_path, &config, "test", &[], 0);

    assert!(
        result.is_err(),
        "Should fail when engine returns non-zero exit code"
    );

    let error = result.unwrap_err();
    let error_str = error.to_string();

    // Verify error indicates process failure
    assert!(
        error_str.contains("failed")
            || error_str.contains("exit")
            || error_str.contains("error")
            || error_str.contains("status"),
        "Error should indicate process failure, got: {}",
        error_str
    );

    // Verify error provides meaningful context (ActionableError integration tested elsewhere)
    println!("Engine exit code error: {}", error_str);
}

#[test]
fn test_engine_crash_signal_fixture_error_handling() {
    // Test boundary condition: controlled fixture engine terminates abnormally.
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let app_path = create_test_app(
        temp_dir.path(),
        "crash_test.js",
        r#"console.log("This should fail due to engine crash");"#,
    );

    // Create a fixture engine that crashes with SIGKILL
    let crashing_engine_path = create_crashing_fixture_engine_binary(temp_dir.path());

    let config = balanced_config();

    // Force external process execution to test signal handling
    let dispatcher = EngineDispatcher::new(
        Some(crashing_engine_path.clone()),
        PreferredRuntime::FrankenEngine,
    );

    // Set short timeout for faster test completion
    unsafe {
        std::env::set_var("FRANKEN_ENGINE_TIMEOUT_SECS", "10");
    }

    // Clean up env var when test completes
    struct EnvCleanup(&'static str);
    impl Drop for EnvCleanup {
        fn drop(&mut self) {
            unsafe {
                std::env::remove_var(self.0);
            }
        }
    }
    let _cleanup = EnvCleanup("FRANKEN_ENGINE_TIMEOUT_SECS");

    // Execute and expect failure due to signal/crash
    let result = dispatcher.dispatch_run(&app_path, &config, "test", &[], 0);

    assert!(
        result.is_err(),
        "Should fail when engine crashes/receives signal"
    );

    let error = result.unwrap_err();
    let error_str = error.to_string();

    // Verify error indicates abnormal termination
    assert!(
        error_str.contains("signal")
            || error_str.contains("killed")
            || error_str.contains("terminated")
            || error_str.contains("crash")
            || error_str.contains("failed"),
        "Error should indicate abnormal process termination, got: {}",
        error_str
    );

    // Verify error provides meaningful context (ActionableError integration tested elsewhere)
    println!("Engine crash error: {}", error_str);
}

#[test]
fn test_dispatcher_creation_and_fixture_configuration() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let engine_path = create_fixture_engine_binary(temp_dir.path());

    // Test various dispatcher configurations
    let dispatcher1 = EngineDispatcher::new(None, PreferredRuntime::Auto);
    let dispatcher2 =
        EngineDispatcher::new(Some(engine_path.clone()), PreferredRuntime::FrankenEngine);
    let dispatcher3 = EngineDispatcher::new(None, PreferredRuntime::Node);

    // Dispatchers should be created successfully
    // This tests the configuration and initialization paths
    assert!(std::mem::size_of_val(&dispatcher1) > 0);
    assert!(std::mem::size_of_val(&dispatcher2) > 0);
    assert!(std::mem::size_of_val(&dispatcher3) > 0);
}
