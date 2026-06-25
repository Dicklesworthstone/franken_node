//! bd-656a2 (http leg, T3/T4): integration coverage for the product-layer SSRF
//! egress gate (`SsrfGatedHostIo`).
//!
//! The crate-root `#![cfg(any(not(test), franken_node_inline_tests))]` gates the
//! lib's inline `#[cfg(test)]` modules out of the normal `cargo test` lane, so
//! the gate is verified here through the crate's PUBLIC API against the real,
//! not-test library — independent of the (separately tracked) broken inline
//! lane. The decision tests use a mock inner provider; the "allowed" path drives
//! the REAL engine `SandboxedHostIo` network mechanism against a loopback
//! listener with NO mocks, proving gate -> mechanism delegation end to end.

#![cfg(feature = "engine")]

use std::io::Read;
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use frankenengine_extension_host::host_io::{
    HostIoCapability, HostIoError, HostIoOutcome, HostIoProvider, HostIoRequest, HostIoResponse,
    SandboxedHostIo,
};
use frankenengine_node::ops::ssrf_gated_host_io::SsrfGatedHostIo;
use frankenengine_node::security::ssrf_policy::SsrfPolicyTemplate;

/// Mock inner provider that records the requests forwarded to it (via a shared
/// handle the test keeps after the provider is moved into the gate) and always
/// succeeds — so a test asserts purely on the GATE's allow/deny decision: was
/// the inner mechanism reached?
#[derive(Debug)]
struct RecordingInner {
    seen: Arc<Mutex<Vec<HostIoRequest>>>,
}

impl HostIoProvider for RecordingInner {
    fn name(&self) -> &str {
        "recording-inner"
    }

    fn perform(&self, request: &HostIoRequest, _granted: &[HostIoCapability]) -> HostIoOutcome {
        self.seen.lock().unwrap().push(request.clone());
        Ok(match request {
            HostIoRequest::FsRead { .. } => HostIoResponse::FsRead { bytes: Vec::new() },
            HostIoRequest::FsWrite { .. } => HostIoResponse::FsWrite { bytes_written: 0 },
            HostIoRequest::NetworkSend { payload, .. } => HostIoResponse::NetworkSend {
                bytes_sent: payload.len() as u64,
            },
            HostIoRequest::NetworkRecv { .. } => HostIoResponse::NetworkRecv { bytes: Vec::new() },
        })
    }
}

/// A template that blocks nothing — lets a test authorize an otherwise
/// SSRF-blocked loopback endpoint without a signed allowlist receipt.
fn permissive_template() -> SsrfPolicyTemplate {
    SsrfPolicyTemplate {
        connector_id: "test-permissive".to_string(),
        blocked_cidrs: Vec::new(),
        allowlist: Vec::new(),
        audit_log: Vec::new(),
    }
}

fn net_send(endpoint: &str) -> HostIoRequest {
    HostIoRequest::NetworkSend {
        endpoint: endpoint.to_string(),
        payload: b"GET / HTTP/1.1\r\nHost: x\r\n\r\n".to_vec(),
    }
}

#[test]
fn default_policy_denies_loopback_egress() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let gated = SsrfGatedHostIo::new(RecordingInner { seen: seen.clone() }, "trace-loopback");
    let outcome = gated.perform(
        &net_send("127.0.0.1:8080"),
        &[HostIoCapability::NetworkSend],
    );
    assert!(
        matches!(outcome, Err(HostIoError::Denied { .. })),
        "loopback egress must be SSRF-denied, got {outcome:?}"
    );
    assert!(
        seen.lock().unwrap().is_empty(),
        "a denied egress must never reach the inner network mechanism"
    );
    assert_eq!(
        gated.audit_records().len(),
        1,
        "the SSRF decision must be audited"
    );
}

#[test]
fn default_policy_denies_cloud_metadata_egress() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let gated = SsrfGatedHostIo::new(RecordingInner { seen: seen.clone() }, "trace-metadata");
    let outcome = gated.perform(
        &net_send("169.254.169.254:80"),
        &[HostIoCapability::NetworkSend],
    );
    assert!(
        matches!(outcome, Err(HostIoError::Denied { .. })),
        "cloud-metadata (link-local) egress must be SSRF-denied, got {outcome:?}"
    );
    assert!(seen.lock().unwrap().is_empty());
}

#[test]
fn malformed_endpoint_denies_fail_closed() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    // Even under a permissive policy an unparseable endpoint (no port) must deny.
    let gated = SsrfGatedHostIo::with_policy(
        RecordingInner { seen: seen.clone() },
        permissive_template(),
        "trace-malformed",
    );
    let outcome = gated.perform(&net_send("not-a-host"), &[HostIoCapability::NetworkSend]);
    assert!(
        matches!(outcome, Err(HostIoError::Denied { .. })),
        "an unparseable endpoint must deny fail-closed, got {outcome:?}"
    );
    assert!(seen.lock().unwrap().is_empty());
}

#[test]
fn filesystem_effects_bypass_the_ssrf_gate() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let gated = SsrfGatedHostIo::new(RecordingInner { seen: seen.clone() }, "trace-fs");
    let outcome = gated.perform(
        &HostIoRequest::FsRead {
            path: "report.txt".to_string(),
        },
        &[HostIoCapability::FsRead],
    );
    assert!(
        matches!(outcome, Ok(HostIoResponse::FsRead { .. })),
        "filesystem effects must pass through the gate untouched, got {outcome:?}"
    );
    assert_eq!(
        seen.lock().unwrap().len(),
        1,
        "the fs effect must reach the inner provider"
    );
}

/// Mock-free: a policy-permitted egress is delegated to the REAL engine
/// `SandboxedHostIo` network mechanism and reaches a loopback listener. Proves
/// the gate -> mechanism delegation end to end (the allowed half of the http
/// producer's acceptance bar, at the host-I/O layer).
#[test]
fn permitted_egress_reaches_real_loopback_listener() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let addr = listener.local_addr().expect("listener addr");
    let server = std::thread::spawn(move || {
        let (mut stream, _peer) = listener.accept().expect("accept egress");
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("read timeout");
        let mut buf = vec![0u8; 256];
        let n = stream.read(&mut buf).unwrap_or(0);
        buf.truncate(n);
        buf
    });

    // The sandboxed provider needs a real fs root for its fs arms; the network
    // arm ignores it.
    let mut root = std::env::temp_dir();
    root.push(format!("franken_node_ssrf_gate_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).expect("scratch root");

    let inner = SandboxedHostIo::with_root(&root).expect("sandboxed provider");
    // A permissive template authorizes the loopback endpoint that the default
    // policy would (correctly) block.
    let gated = SsrfGatedHostIo::with_policy(inner, permissive_template(), "trace-allow");

    let endpoint = addr.to_string();
    let outcome = gated.perform(&net_send(&endpoint), &[HostIoCapability::NetworkSend]);
    assert!(
        matches!(outcome, Ok(HostIoResponse::NetworkSend { .. })),
        "a policy-permitted egress must be performed by the real mechanism, got {outcome:?}"
    );

    let received = server.join().expect("server thread");
    let wire = String::from_utf8_lossy(&received);
    assert!(
        wire.starts_with("GET / HTTP/1.1\r\n"),
        "the loopback listener must observe the framed request, got {wire:?}"
    );

    let _ = std::fs::remove_dir_all(&root);
}

/// The default policy denies loopback even when wrapping the real
/// `SandboxedHostIo`: no connection is attempted (fail-closed before the socket).
#[test]
fn default_policy_blocks_real_mechanism_for_loopback() {
    let mut root = std::env::temp_dir();
    root.push(format!("franken_node_ssrf_block_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).expect("scratch root");

    let inner = SandboxedHostIo::with_root(&root).expect("sandboxed provider");
    let gated = SsrfGatedHostIo::new(inner, "trace-block-real");
    let outcome = gated.perform(&net_send("127.0.0.1:9"), &[HostIoCapability::NetworkSend]);
    assert!(
        matches!(outcome, Err(HostIoError::Denied { .. })),
        "the default policy must block loopback before the real mechanism connects, got {outcome:?}"
    );

    let _ = std::fs::remove_dir_all(&root);
}
