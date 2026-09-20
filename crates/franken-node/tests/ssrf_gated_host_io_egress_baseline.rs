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
    FsMetaResult, HostIoCapability, HostIoError, HostIoOutcome, HostIoProvider, HostIoRequest,
    HostIoResponse, SandboxedHostIo,
};
use frankenengine_node::config::{NetworkAllowlistEntry, NetworkPolicyConfig, SsrfEnforcementMode};
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

impl frankenengine_node::ops::ssrf_gated_host_io::PinnedNetworkProvider for RecordingInner {}

impl HostIoProvider for RecordingInner {
    fn name(&self) -> &str {
        "recording-inner"
    }

    fn perform(&self, request: &HostIoRequest, _granted: &[HostIoCapability]) -> HostIoOutcome {
        self.seen.lock().unwrap().push(request.clone());
        Ok(match request {
            HostIoRequest::FsRead { .. } => HostIoResponse::FsRead { bytes: Vec::new() },
            HostIoRequest::FsWrite { .. } => HostIoResponse::FsWrite { bytes_written: 0 },
            HostIoRequest::FsMeta { .. } => HostIoResponse::FsMeta {
                result: FsMetaResult::Unit,
            },
            HostIoRequest::NetworkSend { payload, .. } => HostIoResponse::NetworkSend {
                bytes_sent: payload.len() as u64,
            },
            HostIoRequest::NetworkRecv { .. } => HostIoResponse::NetworkRecv { bytes: Vec::new() },
            HostIoRequest::NetworkRequest { .. } => HostIoResponse::NetworkRequest {
                response: b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".to_vec(),
            },
            HostIoRequest::RandomRead { byte_len } => HostIoResponse::RandomRead {
                bytes: vec![0; usize::try_from(*byte_len).expect("bounded test request")],
            },
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

// bd-3894s slice (4): the single-socket round-trip variant the http leg now uses.
fn net_request(endpoint: &str) -> HostIoRequest {
    HostIoRequest::NetworkRequest {
        endpoint: endpoint.to_string(),
        payload: b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n".to_vec(),
        max_len: 4096,
        use_tls: false,
    }
}

// bd-3894s slice (5): the TLS-marked round trip (an https guest URL) — the SSRF
// gate must treat it exactly like the plaintext form (scheme carries no policy
// privilege).
fn net_request_tls(endpoint: &str) -> HostIoRequest {
    HostIoRequest::NetworkRequest {
        endpoint: endpoint.to_string(),
        payload: b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n".to_vec(),
        max_len: 4096,
        use_tls: true,
    }
}

/// bd-3894s slice (5): a TLS-marked round trip is SSRF-gated identically to the
/// plaintext form — an https URL must not smuggle an egress past the gate.
#[test]
fn default_policy_denies_loopback_tls_round_trip_bd_3894s() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let gated = SsrfGatedHostIo::new(RecordingInner { seen: seen.clone() }, "trace-tls-roundtrip");
    let outcome = gated.perform(
        &net_request_tls("127.0.0.1:8443"),
        &[HostIoCapability::NetworkSend],
    );
    assert!(
        matches!(outcome, Err(HostIoError::Denied { .. })),
        "a loopback TLS round trip must be SSRF-denied, got {outcome:?}"
    );
    assert!(
        seen.lock().unwrap().is_empty(),
        "the inner mechanism must never see a denied TLS round trip"
    );
}

/// bd-3894s slice (4): a `NetworkRequest` round trip is an egress and MUST be
/// SSRF-gated exactly like `NetworkSend` — a loopback target is denied before the
/// inner mechanism ever sees it. This is the regression guarding against the
/// round-trip variant slipping past the gate.
#[test]
fn default_policy_denies_loopback_round_trip() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let gated = SsrfGatedHostIo::new(RecordingInner { seen: seen.clone() }, "trace-roundtrip");
    let outcome = gated.perform(
        &net_request("127.0.0.1:8080"),
        &[HostIoCapability::NetworkSend],
    );
    assert!(
        matches!(outcome, Err(HostIoError::Denied { .. })),
        "a loopback round trip must be SSRF-denied, got {outcome:?}"
    );
    assert!(
        seen.lock().unwrap().is_empty(),
        "a denied round trip must never reach the inner network mechanism"
    );
}

/// bd-3894s slice (4): an allowlisted endpoint authorizes the round trip and it
/// reaches the inner mechanism (mirrors the `NetworkSend` allow path).
#[test]
fn permissive_policy_allows_round_trip() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let gated = SsrfGatedHostIo::with_policy(
        RecordingInner { seen: seen.clone() },
        permissive_template(),
        "trace-roundtrip-allow",
    );
    let outcome = gated.perform(
        &net_request("127.0.0.1:8080"),
        &[HostIoCapability::NetworkSend],
    );
    assert!(
        matches!(outcome, Ok(HostIoResponse::NetworkRequest { .. })),
        "an allowlisted round trip must reach the inner mechanism, got {outcome:?}"
    );
    assert_eq!(
        seen.lock().unwrap().len(),
        1,
        "the authorized round trip must be delegated to the inner provider exactly once"
    );
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

/// bd-3894s (slice 6): the default `[security.network_policy]` (Block mode, no
/// allowlist) wired through `from_network_policy` denies loopback egress — the
/// config path is fail-closed by default, matching `new`.
#[test]
fn from_network_policy_block_default_denies_loopback() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let policy = NetworkPolicyConfig::default();
    let gated = SsrfGatedHostIo::from_network_policy(
        RecordingInner { seen: seen.clone() },
        &policy,
        "trace-cfg-block",
    );
    let outcome = gated.perform(
        &net_send("127.0.0.1:8080"),
        &[HostIoCapability::NetworkSend],
    );
    assert!(
        matches!(outcome, Err(HostIoError::Denied { .. })),
        "default config (Block) must deny loopback, got {outcome:?}"
    );
    assert!(
        seen.lock().unwrap().is_empty(),
        "a config-denied egress must never reach the inner mechanism"
    );
}

/// bd-3894s (slice 6): a config allowlist entry for the loopback host bypasses
/// the matched default-deny CIDR (via the synthesized `PolicyReceipt`), so the
/// egress reaches the inner mechanism. This is the operator-controlled exception
/// that lets a specific internal endpoint through under an otherwise default-deny
/// policy.
#[test]
fn from_network_policy_allowlist_permits_loopback() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let mut policy = NetworkPolicyConfig::default();
    policy.allowlist.push(NetworkAllowlistEntry {
        host: "127.0.0.1".to_string(),
        port: None,
        reason: "test: permit local sink".to_string(),
    });
    let gated = SsrfGatedHostIo::from_network_policy(
        RecordingInner { seen: seen.clone() },
        &policy,
        "trace-cfg-allow",
    );
    let outcome = gated.perform(
        &net_send("127.0.0.1:8080"),
        &[HostIoCapability::NetworkSend],
    );
    assert!(
        matches!(outcome, Ok(HostIoResponse::NetworkSend { .. })),
        "an allowlisted loopback host must be permitted, got {outcome:?}"
    );
    assert_eq!(
        seen.lock().unwrap().len(),
        1,
        "the allowlisted egress must reach the inner mechanism"
    );
}

/// bd-3894s (slice 6): explicit operator opt-out (`ssrf_enforcement = "none"`)
/// empties the deny-list, so even loopback is permitted. Still routed through the
/// gate (the decision is audited), but the policy authorizes it.
#[test]
fn from_network_policy_enforcement_none_permits_loopback() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let policy = NetworkPolicyConfig {
        ssrf_enforcement: SsrfEnforcementMode::None,
        ..NetworkPolicyConfig::default()
    };
    let gated = SsrfGatedHostIo::from_network_policy(
        RecordingInner { seen: seen.clone() },
        &policy,
        "trace-cfg-none",
    );
    let outcome = gated.perform(
        &net_send("127.0.0.1:8080"),
        &[HostIoCapability::NetworkSend],
    );
    assert!(
        matches!(outcome, Ok(HostIoResponse::NetworkSend { .. })),
        "ssrf_enforcement=none must permit loopback, got {outcome:?}"
    );
    assert_eq!(seen.lock().unwrap().len(), 1);
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

// Keep these tests in this registered integration target: ordinary cargo test
// does not execute the product library's inline test modules.
#[cfg(unix)]
mod flow_gate_regressions {
    use super::*;
    use frankenengine_extension_host::host_io::{FsOperation, HostIoExceptionProvenance};
    use frankenengine_node::ops::flow_gated_host_io::FlowGatedHostIo;
    use std::path::Path;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const NETWORK_PROBE: &str = "test network mechanism reached";

    /// Real sandboxed filesystem with a network-only test double. The distinct
    /// Io error proves delegation without pretending an external request ran.
    /// The final test below uses the real network mechanism as well.
    #[derive(Debug)]
    struct NetworkProbe {
        inner: SandboxedHostIo,
        calls: Arc<AtomicUsize>,
    }

    impl HostIoProvider for NetworkProbe {
        fn name(&self) -> &str {
            "flow-test-network-probe"
        }

        fn filesystem_exception_provenance(&self) -> HostIoExceptionProvenance {
            self.inner.filesystem_exception_provenance()
        }

        fn perform(&self, request: &HostIoRequest, granted: &[HostIoCapability]) -> HostIoOutcome {
            let capability = request.required_capability();
            if !granted.contains(&capability) {
                return Err(HostIoError::CapabilityMissing { capability });
            }
            match request {
                HostIoRequest::NetworkSend { .. }
                | HostIoRequest::NetworkRequest { .. }
                | HostIoRequest::NetworkRecv { .. } => {
                    self.calls.fetch_add(1, Ordering::SeqCst);
                    Err(HostIoError::Io {
                        detail: NETWORK_PROBE.to_string(),
                    })
                }
                _ => self.inner.perform(request, granted),
            }
        }
    }

    fn probe(root: &Path, calls: &Arc<AtomicUsize>) -> FlowGatedHostIo<NetworkProbe> {
        FlowGatedHostIo::new(
            NetworkProbe {
                inner: SandboxedHostIo::with_root(root).expect("sandboxed filesystem"),
                calls: Arc::clone(calls),
            },
            "flow-integration",
        )
    }

    fn sinks(payload: &[u8]) -> [HostIoRequest; 3] {
        [
            HostIoRequest::NetworkSend {
                endpoint: "127.0.0.1:9".into(),
                payload: payload.to_vec(),
            },
            HostIoRequest::NetworkRequest {
                endpoint: "127.0.0.1:9".into(),
                payload: payload.to_vec(),
                max_len: 4096,
                use_tls: false,
            },
            HostIoRequest::NetworkRequest {
                endpoint: "127.0.0.1:9".into(),
                payload: payload.to_vec(),
                max_len: 4096,
                use_tls: true,
            },
        ]
    }

    fn assert_flow_denied(
        gate: &impl HostIoProvider,
        calls: &AtomicUsize,
        request: &HostIoRequest,
    ) {
        let before = calls.load(Ordering::SeqCst);
        let outcome = gate.perform(request, &[request.required_capability()]);
        assert!(
            matches!(&outcome, Err(HostIoError::Denied { reason }) if reason.starts_with("flow_policy:")),
            "expected flow-policy denial, got {outcome:?}"
        );
        assert_eq!(calls.load(Ordering::SeqCst), before, "denied effect delegated");
    }

    fn assert_probe_reached(
        gate: &impl HostIoProvider,
        calls: &AtomicUsize,
        request: &HostIoRequest,
    ) {
        let before = calls.load(Ordering::SeqCst);
        let outcome = gate.perform(request, &[request.required_capability()]);
        assert_eq!(
            outcome,
            Err(HostIoError::Io {
                detail: NETWORK_PROBE.to_string(),
            })
        );
        assert_eq!(calls.load(Ordering::SeqCst), before + 1);
    }

    fn read_path(gate: &impl HostIoProvider, path: &str, expected: &[u8]) {
        assert_eq!(
            gate.perform(
                &HostIoRequest::FsRead { path: path.into() },
                &[HostIoCapability::FsRead],
            ),
            Ok(HostIoResponse::FsRead {
                bytes: expected.to_vec(),
            })
        );
    }

    fn meta(operation: FsOperation, path: &str, arguments: Vec<String>) -> HostIoRequest {
        HostIoRequest::FsMeta {
            operation,
            path: path.into(),
            arguments,
            data: Vec::new(),
        }
    }

    fn open_fd(gate: &impl HostIoProvider, path: &str) -> u64 {
        let outcome = gate.perform(
            &meta(FsOperation::Open, path, vec!["flags=r".into()]),
            &[HostIoCapability::FsWrite],
        );
        match outcome {
            Ok(HostIoResponse::FsMeta {
                result: FsMetaResult::Unsigned(fd),
            }) => fd,
            other => panic!("expected an opened descriptor, got {other:?}"),
        }
    }

    fn read_fd(gate: &impl HostIoProvider, fd: u64, ignored_path: &str, expected: &[u8]) {
        let request = meta(
            FsOperation::ReadFd,
            ignored_path,
            vec![
                format!("fd={fd}"),
                format!("length={}", expected.len()),
                "position=0".into(),
            ],
        );
        assert_eq!(
            gate.perform(&request, &[HostIoCapability::FsRead]),
            Ok(HostIoResponse::FsMeta {
                result: FsMetaResult::Bytes(expected.to_vec()),
            })
        );
    }

    #[test]
    fn untrackable_sensitive_reads_deny_all_payload_sinks_without_delegation() {
        for size in [1, 7, 64 * 1024 + 1] {
            let root = tempfile::tempdir().expect("scratch root");
            let secret = vec![b'x'; size];
            std::fs::write(root.path().join(".env"), &secret).expect("secret fixture");
            let calls = Arc::new(AtomicUsize::new(0));
            let gate = probe(root.path(), &calls);
            read_path(&gate, ".env", &secret);
            for payload in [b"".as_slice(), b"public".as_slice(), secret.as_slice()] {
                for request in sinks(payload) {
                    assert_flow_denied(&gate, &calls, &request);
                }
            }
            // Egress refusal must not disable local filesystem work.
            let write = HostIoRequest::FsWrite {
                path: "local.txt".into(),
                data: b"ok".to_vec(),
            };
            assert_eq!(
                gate.perform(&write, &[HostIoCapability::FsWrite]),
                Ok(HostIoResponse::FsWrite { bytes_written: 2 })
            );
            assert_eq!(
                std::fs::read(root.path().join("local.txt")).expect("local copy"),
                b"ok"
            );
        }
    }

    #[test]
    fn exact_sample_boundaries_reject_framed_secrets_but_allow_public_payloads() {
        for size in [8, 64 * 1024] {
            let root = tempfile::tempdir().expect("scratch root");
            let secret = vec![0x91; size];
            std::fs::write(root.path().join(".env"), &secret).expect("binary secret");
            let calls = Arc::new(AtomicUsize::new(0));
            let gate = probe(root.path(), &calls);
            read_path(&gate, ".env", &secret);
            let mut framed = b"header:".to_vec();
            framed.extend_from_slice(&secret);
            framed.extend_from_slice(b":trailer");
            for request in sinks(&framed) {
                assert_flow_denied(&gate, &calls, &request);
            }
            for request in sinks(b"public") {
                assert_probe_reached(&gate, &calls, &request);
            }
        }
    }

    #[test]
    fn sample_budget_deduplicates_before_capacity_and_never_forgets_overflow() {
        let root = tempfile::tempdir().expect("scratch root");
        let calls = Arc::new(AtomicUsize::new(0));
        let gate = probe(root.path(), &calls);
        for index in 0..16 {
            let sample = format!("secret-token-{index:04}");
            std::fs::write(root.path().join(".env"), &sample).expect("rotate secret");
            read_path(&gate, ".env", sample.as_bytes());
        }
        std::fs::write(root.path().join(".env"), b"secret-token-0000").expect("reread secret");
        read_path(&gate, ".env", b"secret-token-0000");
        assert_probe_reached(&gate, &calls, &sinks(b"public")[0]);
        assert_flow_denied(&gate, &calls, &sinks(b"secret-token-0000")[0]);
        std::fs::write(root.path().join(".env"), b"seventeenth-secret").expect("overflow secret");
        read_path(&gate, ".env", b"seventeenth-secret");
        for request in sinks(b"public").into_iter().chain(sinks(b"")) {
            assert_flow_denied(&gate, &calls, &request);
        }
    }

    #[test]
    fn empty_failed_and_nonsensitive_reads_do_not_close_egress() {
        let root = tempfile::tempdir().expect("scratch root");
        let calls = Arc::new(AtomicUsize::new(0));
        let gate = probe(root.path(), &calls);
        std::fs::write(root.path().join(".env"), b"").expect("empty secret");
        for _ in 0..17 {
            read_path(&gate, ".env", b"");
        }
        std::fs::write(root.path().join("public.txt"), b"x").expect("short public file");
        read_path(&gate, "public.txt", b"x");
        std::fs::write(root.path().join(".env"), b"unread-secret").expect("unread secret");
        assert!(matches!(
            gate.perform(
                &HostIoRequest::FsRead { path: ".env".into() },
                &[],
            ),
            Err(HostIoError::CapabilityMissing { .. })
        ));
        assert!(
            gate.perform(
                &HostIoRequest::FsRead {
                    path: ".env.missing".into(),
                },
                &[HostIoCapability::FsRead],
            )
            .is_err()
        );
        assert_probe_reached(&gate, &calls, &sinks(b"public")[0]);
    }

    #[test]
    fn descriptor_reads_use_open_provenance_not_the_ignored_request_path() {
        let root = tempfile::tempdir().expect("scratch root");
        std::fs::write(root.path().join(".env"), b"descriptor-secret").expect("secret fixture");
        std::fs::write(root.path().join("public.txt"), b"public-file-bytes")
            .expect("public fixture");
        let calls = Arc::new(AtomicUsize::new(0));
        let gate = probe(root.path(), &calls);
        let secret_fd = open_fd(&gate, ".env");
        read_fd(&gate, secret_fd, "public.txt", b"");
        assert_probe_reached(&gate, &calls, &sinks(b"public")[0]);
        read_fd(&gate, secret_fd, "public.txt", b"descriptor-secret");
        for request in sinks(b"prefix:descriptor-secret:suffix") {
            assert_flow_denied(&gate, &calls, &request);
        }
        let public_fd = open_fd(&gate, "public.txt");
        read_fd(&gate, public_fd, ".env", b"public-file-bytes");
        assert_probe_reached(&gate, &calls, &sinks(b"public-file-bytes")[0]);
    }

    #[test]
    fn failed_close_keeps_provenance_and_successful_close_keeps_observed_secrets() {
        let root = tempfile::tempdir().expect("scratch root");
        std::fs::write(root.path().join(".env"), b"descriptor-secret").expect("secret fixture");
        let calls = Arc::new(AtomicUsize::new(0));
        let gate = probe(root.path(), &calls);
        let fd = open_fd(&gate, ".env");
        let close = meta(FsOperation::CloseFd, "", vec![format!("fd={fd}")]);
        assert!(matches!(
            gate.perform(&close, &[]),
            Err(HostIoError::CapabilityMissing { .. })
        ));
        read_fd(&gate, fd, "", b"descriptor-secret");
        assert_flow_denied(&gate, &calls, &sinks(b"descriptor-secret")[0]);
        assert_eq!(
            gate.perform(&close, &[HostIoCapability::FsWrite]),
            Ok(HostIoResponse::FsMeta {
                result: FsMetaResult::Unit,
            })
        );
        assert_flow_denied(&gate, &calls, &sinks(b"descriptor-secret")[0]);
    }

    #[test]
    fn successful_reads_from_preexisting_untracked_descriptors_are_sensitive() {
        let root = tempfile::tempdir().expect("scratch root");
        std::fs::write(root.path().join(".env"), b"untracked-secret").expect("secret fixture");
        let inner = SandboxedHostIo::with_root(root.path()).expect("sandboxed filesystem");
        let fd = inner.open_fd(".env", "r").expect("open before wrapping");
        let calls = Arc::new(AtomicUsize::new(0));
        let gate = FlowGatedHostIo::new(
            NetworkProbe {
                inner,
                calls: Arc::clone(&calls),
            },
            "untracked-descriptor",
        );
        read_fd(&gate, fd, "public.txt", b"untracked-secret");
        assert_flow_denied(&gate, &calls, &sinks(b"untracked-secret")[0]);
    }

    #[test]
    fn metadata_results_and_exception_provenance_remain_unchanged() {
        let root = tempfile::tempdir().expect("scratch root");
        std::fs::write(root.path().join(".env"), b"tiny").expect("unread secret fixture");
        let calls = Arc::new(AtomicUsize::new(0));
        let gate = probe(root.path(), &calls);
        assert_eq!(
            gate.filesystem_exception_provenance(),
            HostIoExceptionProvenance::ProviderInternal
        );
        assert_eq!(
            gate.perform(
                &meta(FsOperation::Exists, ".env", Vec::new()),
                &[HostIoCapability::FsRead],
            ),
            Ok(HostIoResponse::FsMeta {
                result: FsMetaResult::Bool(true),
            })
        );
        assert_probe_reached(&gate, &calls, &sinks(b"public")[0]);
    }

    #[test]
    fn debug_output_redacts_source_bytes_and_inner_provider() {
        let root = tempfile::tempdir().expect("scratch root");
        let secret = b"never-print-this-secret";
        std::fs::write(root.path().join(".env"), secret).expect("secret fixture");
        let calls = Arc::new(AtomicUsize::new(0));
        let gate = probe(root.path(), &calls);
        read_path(&gate, ".env", secret);
        let debug = format!("{gate:?}");
        assert!(!debug.contains("never-print-this-secret"));
        assert!(!debug.contains(&format!("{secret:?}")));
        assert!(!debug.contains("NetworkProbe"));
    }

    #[test]
    fn destinations_are_checked_before_network_delegation_including_receive() {
        let root = tempfile::tempdir().expect("scratch root");
        std::fs::write(root.path().join(".env"), b"secret-host-label")
            .expect("hostname secret fixture");
        let calls = Arc::new(AtomicUsize::new(0));
        let gate = probe(root.path(), &calls);
        read_path(&gate, ".env", b"secret-host-label");
        let forbidden_endpoint = "secret-host-label.example.invalid:443";
        for mut request in sinks(b"") {
            match &mut request {
                HostIoRequest::NetworkSend { endpoint, .. }
                | HostIoRequest::NetworkRequest { endpoint, .. } => {
                    *endpoint = forbidden_endpoint.into();
                }
                other => panic!("unexpected payload sink: {other:?}"),
            }
            assert_flow_denied(&gate, &calls, &request);
        }
        let forbidden_receive = HostIoRequest::NetworkRecv {
            endpoint: forbidden_endpoint.into(),
            max_len: 4096,
        };
        assert_flow_denied(&gate, &calls, &forbidden_receive);
        let public_receive = HostIoRequest::NetworkRecv {
            endpoint: "public.example.invalid:443".into(),
            max_len: 4096,
        };
        assert_probe_reached(&gate, &calls, &public_receive);
    }

    #[test]
    fn incomplete_tracking_cannot_be_bypassed_with_a_receive_only_connection() {
        let root = tempfile::tempdir().expect("scratch root");
        std::fs::write(root.path().join(".env"), b"x").expect("untrackable secret");
        let calls = Arc::new(AtomicUsize::new(0));
        let gate = probe(root.path(), &calls);
        read_path(&gate, ".env", b"x");
        assert_flow_denied(
            &gate,
            &calls,
            &HostIoRequest::NetworkRecv {
                endpoint: "public.example.invalid:443".into(),
                max_len: 4096,
            },
        );
    }

    #[test]
    fn composed_gates_block_secret_socket_and_send_public_bytes_to_real_listener() {
        let root = tempfile::tempdir().expect("scratch root");
        let secret = b"real-loopback-secret";
        std::fs::write(root.path().join(".env"), secret).expect("secret fixture");
        let listener = TcpListener::bind("127.0.0.1:0").expect("loopback listener");
        listener.set_nonblocking(true).expect("bounded accept");
        let endpoint = listener
            .local_addr()
            .expect("listener address")
            .to_string();
        let inner = SandboxedHostIo::with_root(root.path()).expect("real provider");
        let gate = FlowGatedHostIo::new(
            SsrfGatedHostIo::with_policy(inner, permissive_template(), "endpoint-allowed"),
            "real-flow-gate",
        );
        read_path(&gate, ".env", secret);
        let forbidden = HostIoRequest::NetworkSend {
            endpoint: endpoint.clone(),
            payload: secret.to_vec(),
        };
        assert!(matches!(
            gate.perform(&forbidden, &[HostIoCapability::NetworkSend]),
            Err(HostIoError::Denied { .. })
        ));
        assert!(
            matches!(listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
        );
        let public = b"public data";
        let permitted = HostIoRequest::NetworkSend {
            endpoint,
            payload: public.to_vec(),
        };
        assert_eq!(
            gate.perform(&permitted, &[HostIoCapability::NetworkSend]),
            Ok(HostIoResponse::NetworkSend {
                bytes_sent: u64::try_from(public.len()).expect("small payload"),
            })
        );
        let (mut stream, _) = listener.accept().expect("public connection");
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("bounded read");
        let mut received = Vec::new();
        stream.read_to_end(&mut received).expect("read public bytes");
        assert_eq!(received.as_slice(), public);
    }
}
