//! Public-API dual-stack policy tests, included in the registered egress target.
//! Public addresses use an observing provider, never Internet access. Actual
//! IPv6 socket/TLS behavior is exercised separately by the local TLS fixtures.
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use frankenengine_extension_host::host_io::{
    HostIoCapability, HostIoOutcome, HostIoProvider, HostIoRequest, HostIoResponse,
};
use frankenengine_node::ops::ssrf_gated_host_io::{
    EndpointResolver, PinnedNetworkProvider, SsrfGatedHostIo,
};
use frankenengine_node::security::network_guard::{Action, Protocol};
use frankenengine_node::security::ssrf_policy::{CidrRange, SsrfPolicyTemplate};

const PUBLIC_V6: &str = "2001:4860:4860::8888";
const PUBLIC_V4: &str = "93.184.216.34";

#[derive(Debug, Default)]
struct Observed {
    dns: AtomicUsize,
    effects: Mutex<Vec<(HostIoRequest, SocketAddr)>>,
}

#[derive(Debug)]
struct Resolver {
    state: Arc<Observed>,
    answers: Vec<IpAddr>,
}
impl EndpointResolver for Resolver {
    fn resolve(&self, _: &str, _: u16) -> io::Result<Vec<IpAddr>> {
        self.state.dns.fetch_add(1, Ordering::SeqCst);
        Ok(self.answers.clone())
    }
}

#[derive(Debug)]
struct Provider(Arc<Observed>);
impl HostIoProvider for Provider {
    fn name(&self) -> &str {
        "dual-stack-observer"
    }
    fn perform(&self, _: &HostIoRequest, _: &[HostIoCapability]) -> HostIoOutcome {
        panic!("unpinned delegation is forbidden");
    }
}
impl PinnedNetworkProvider for Provider {
    fn supports_pinned_tls(&self) -> bool {
        true
    }
    fn perform_pinned_network(
        &self,
        request: &HostIoRequest,
        grants: &[HostIoCapability],
        address: SocketAddr,
        deadline: Instant,
    ) -> HostIoOutcome {
        assert!(grants.contains(&request.required_capability()));
        assert!(Instant::now() < deadline);
        self.0
            .effects
            .lock()
            .unwrap()
            .push((request.clone(), address));
        Ok(HostIoResponse::NetworkRequest {
            response: b"observed".to_vec(),
        })
    }
}

fn requests(endpoint: &str) -> [HostIoRequest; 4] {
    [
        HostIoRequest::NetworkSend {
            endpoint: endpoint.into(),
            payload: vec![0, 255],
        },
        HostIoRequest::NetworkRecv {
            endpoint: endpoint.into(),
            max_len: 8192,
        },
        HostIoRequest::NetworkRequest {
            endpoint: endpoint.into(),
            payload: vec![0, 255],
            max_len: 8192,
            use_tls: false,
        },
        HostIoRequest::NetworkRequest {
            endpoint: endpoint.into(),
            payload: vec![0, 255],
            max_len: 8192,
            use_tls: true,
        },
    ]
}

fn exercise(
    policy: SsrfPolicyTemplate,
    endpoint: &str,
    answers: &[&str],
    allowed: bool,
    dns: usize,
) {
    for request in requests(endpoint) {
        let state = Arc::new(Observed::default());
        let gate = SsrfGatedHostIo::with_resolver(
            Provider(Arc::clone(&state)),
            policy.clone(),
            "dual-stack",
            Resolver {
                state: Arc::clone(&state),
                answers: answers.iter().map(|ip| ip.parse().unwrap()).collect(),
            },
        );
        let original = request.clone();
        let result = gate.perform(&request, &[request.required_capability()]);
        assert_eq!(
            result.is_ok(),
            allowed,
            "{endpoint}, {answers:?}: {result:?}"
        );
        assert_eq!(request, original);
        assert_eq!(state.dns.load(Ordering::SeqCst), dns);
        let effects = state.effects.lock().unwrap();
        assert_eq!(effects.len(), usize::from(allowed));
        if allowed {
            assert_eq!(
                effects[0].0, original,
                "identity, payload and limits are preserved"
            );
            let expected = if dns == 0 {
                endpoint.parse().unwrap()
            } else {
                SocketAddr::new(answers[0].parse().unwrap(), 443)
            };
            assert_eq!(effects[0].1, expected);
        }
        assert_eq!(gate.audit_records().len(), 1);
        assert_eq!(
            gate.audit_records()[0].action,
            if allowed { Action::Allow } else { Action::Deny }
        );
    }
}

fn policy() -> SsrfPolicyTemplate {
    SsrfPolicyTemplate::default_template("dual-stack".into())
}

#[test]
fn public_ipv6_literals_and_dual_stack_dns_reach_the_pinned_provider() {
    for host in [PUBLIC_V6, "2606:4700:4700::1111"] {
        exercise(policy(), &format!("[{host}]:443"), &[], true, 0);
        exercise(policy(), "service.invalid:443", &[host], true, 1);
    }
    for answers in [[PUBLIC_V6, PUBLIC_V4], [PUBLIC_V4, PUBLIC_V6]] {
        exercise(policy(), "service.invalid:443", &answers, true, 1);
    }
}

#[test]
fn private_special_or_embedded_private_answer_blocks_every_network_variant() {
    for denied in [
        "::",
        "::1",
        "fd00:ec2::254",
        "fe80::1",
        "fec0::1",
        "ff02::1",
        "::ffff:127.0.0.1",
        "::ffff:169.254.169.254",
        "64:ff9b::a9fe:a9fe",
        "64:ff9b::a00:1",
        "64:ff9b:1::1",
        "2001:db8::1",
        "2002:7f00:1::1",
        "3fff::1",
    ] {
        exercise(policy(), &format!("[{denied}]:443"), &[], false, 0);
        exercise(
            policy(),
            "service.invalid:443",
            &[PUBLIC_V6, denied],
            false,
            1,
        );
        exercise(
            policy(),
            "service.invalid:443",
            &[denied, PUBLIC_V4],
            false,
            1,
        );
    }
}

#[test]
fn mapped_and_nat64_public_addresses_inherit_custom_ipv4_restrictions() {
    for address in ["::ffff:8.8.8.8", "64:ff9b::808:808"] {
        exercise(policy(), &format!("[{address}]:443"), &[], true, 0);
        exercise(policy(), "service.invalid:443", &[address], true, 1);
        let mut restricted = policy();
        restricted
            .blocked_cidrs
            .push(CidrRange::new([8, 8, 8, 0], 24, "operator-rule"));
        exercise(
            restricted.clone(),
            &format!("[{address}]:443"),
            &[],
            false,
            0,
        );
        exercise(
            restricted,
            "service.invalid:443",
            &[PUBLIC_V6, address],
            false,
            1,
        );
    }
}

#[test]
fn literal_exceptions_normalize_only_valid_numeric_spellings_and_keep_port_scope() {
    let mut allowed = policy();
    allowed
        .add_allowlist(
            "fd00:0:0:0:0:0:0:1",
            Some(443),
            "internal service",
            "trace",
            "time",
        )
        .unwrap();
    exercise(allowed.clone(), "[FD00::1]:443", &[], true, 0);
    exercise(allowed.clone(), "[fd00::1]:444", &[], false, 0);
    exercise(allowed.clone(), "[fd00::2]:443", &[], false, 0);
    for invalid in [
        "[[fd00::1]]:443",
        "[fd00::1%3]:443",
        "[fd00::1]:+443",
        "fd00::1:443",
    ] {
        exercise(allowed.clone(), invalid, &[], false, 0);
    }
}

#[test]
fn hostname_allowlist_never_exempts_private_ipv6_dns_evidence() {
    let mut allowed = policy();
    allowed
        .add_allowlist(
            "service.invalid",
            Some(443),
            "known DNS service",
            "trace",
            "time",
        )
        .unwrap();
    for address in ["fd00::1", "::1", "::ffff:127.0.0.1"] {
        exercise(
            allowed.clone(),
            "service.invalid:443",
            &[PUBLIC_V6, address],
            false,
            1,
        );
    }
}

#[test]
fn helper_literal_and_dns_policy_classifications_agree_and_preserve_serialized_templates() {
    let before = policy();
    let serialized = serde_json::to_string(&before).unwrap();
    let mut restored: SsrfPolicyTemplate = serde_json::from_str(&serialized).unwrap();
    assert_eq!(restored.blocked_cidrs.len(), 7);
    for address in [
        PUBLIC_V6,
        "2606:4700:4700::1111",
        "::ffff:8.8.8.8",
        "64:ff9b::808:808",
        "fd00::1",
        "::",
        "2001:db8::1",
        "64:ff9b::a9fe:a9fe",
    ] {
        let denied = SsrfPolicyTemplate::is_private_ip(address);
        for host in [address.to_string(), format!("[{address}]")] {
            assert_eq!(
                restored
                    .check_ssrf(&host, 443, Protocol::Http, "trace", "time")
                    .is_err(),
                denied,
                "{host}"
            );
        }
        assert_eq!(
            restored
                .check_ssrf_resolved_ips(
                    "service.invalid",
                    &[address.parse().unwrap()],
                    443,
                    Protocol::Tcp,
                    "trace",
                    "time"
                )
                .is_err(),
            denied,
            "{address}"
        );
    }
}

#[derive(Debug)]
struct AdmittedSet {
    request: HostIoRequest,
    destinations: Vec<SocketAddr>,
    deadline: Instant,
}

#[derive(Debug)]
struct SetProvider(Arc<Mutex<Vec<AdmittedSet>>>);
impl HostIoProvider for SetProvider {
    fn name(&self) -> &str {
        "approved-set-observer"
    }
    fn perform(&self, _: &HostIoRequest, _: &[HostIoCapability]) -> HostIoOutcome {
        panic!("ordinary execution must not be used for an approved address set");
    }
}
impl PinnedNetworkProvider for SetProvider {
    fn supports_pinned_tls(&self) -> bool {
        true
    }
    fn perform_pinned_network_candidates(
        &self,
        request: &HostIoRequest,
        grants: &[HostIoCapability],
        destinations: &[SocketAddr],
        deadline: Instant,
    ) -> HostIoOutcome {
        assert!(grants.contains(&request.required_capability()));
        self.0.lock().unwrap().push(AdmittedSet {
            request: request.clone(),
            destinations: destinations.to_vec(),
            deadline,
        });
        Ok(HostIoResponse::NetworkRequest {
            response: Vec::new(),
        })
    }
}

#[test]
fn gate_passes_the_whole_approved_set_once_with_stable_order_and_no_duplicates() {
    for request in requests("service.invalid:443") {
        let state = Arc::new(Observed::default());
        let admitted = Arc::new(Mutex::new(Vec::new()));
        let gate = SsrfGatedHostIo::with_resolver(
            SetProvider(Arc::clone(&admitted)),
            policy(),
            "approved-set",
            Resolver {
                state: Arc::clone(&state),
                answers: [PUBLIC_V6, PUBLIC_V4, PUBLIC_V6, PUBLIC_V4]
                    .iter()
                    .map(|ip| ip.parse().unwrap())
                    .collect(),
            },
        );
        let before = Instant::now();
        assert!(
            gate.perform(&request, &[request.required_capability()])
                .is_ok()
        );
        assert_eq!(state.dns.load(Ordering::SeqCst), 1);
        let calls = admitted.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].request, request);
        assert_eq!(
            calls[0].destinations,
            [
                SocketAddr::new(PUBLIC_V6.parse().unwrap(), 443),
                SocketAddr::new(PUBLIC_V4.parse().unwrap(), 443),
            ]
        );
        assert!(calls[0].deadline > before);
        assert!(calls[0].deadline <= before + Duration::from_secs(11));
        assert_eq!(gate.audit_records().len(), 1);
    }
}

#[test]
fn no_approved_set_reaches_transport_when_any_answer_is_denied_or_capacity_overflows() {
    for answers in [
        vec![
            PUBLIC_V6.parse().unwrap(),
            "fd00::1".parse().unwrap(),
            PUBLIC_V4.parse().unwrap(),
        ],
        vec![PUBLIC_V6.parse().unwrap(); 65],
        Vec::new(),
    ] {
        let state = Arc::new(Observed::default());
        let admitted = Arc::new(Mutex::new(Vec::new()));
        let gate = SsrfGatedHostIo::with_resolver(
            SetProvider(Arc::clone(&admitted)),
            policy(),
            "invalid-set",
            Resolver { state, answers },
        );
        for request in requests("service.invalid:443") {
            assert!(
                gate.perform(&request, &[request.required_capability()])
                    .is_err()
            );
        }
        assert!(admitted.lock().unwrap().is_empty());
    }
}

#[test]
fn singleton_provider_default_validates_the_full_set_before_executing_once() {
    let observed = Arc::new(Observed::default());
    let provider = Provider(Arc::clone(&observed));
    let request = requests("service.invalid:443")[3].clone();
    let first = SocketAddr::new(PUBLIC_V4.parse().unwrap(), 443);
    let second = SocketAddr::new(PUBLIC_V6.parse().unwrap(), 443);
    let wrong_port = SocketAddr::new(second.ip(), 444);
    let deadline = Instant::now() + Duration::from_secs(5);
    for destinations in [vec![], vec![first; 65], vec![first, wrong_port]] {
        assert!(
            provider
                .perform_pinned_network_candidates(
                    &request,
                    &[HostIoCapability::NetworkSend],
                    &destinations,
                    deadline
                )
                .is_err()
        );
    }
    assert!(observed.effects.lock().unwrap().is_empty());
    assert!(
        provider
            .perform_pinned_network_candidates(
                &request,
                &[HostIoCapability::NetworkSend],
                &[first, second],
                deadline
            )
            .is_ok()
    );
    assert_eq!(*observed.effects.lock().unwrap(), vec![(request, first)]);
}

/// Supervised runtime coverage in the registered egress target. Only the
/// pausing/observing fixtures simulate DNS or transport; the TLS and concurrent
/// response-wait cases use the actual engine provider on loopback sockets.
mod operation_control {
    use super::{Observed, PUBLIC_V4, PUBLIC_V6, Resolver, policy, requests};
    use std::io::{self, Read, Write};
    use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex, mpsc};
    use std::thread::{self, JoinHandle};
    use std::time::{Duration, Instant};

    use frankenengine_extension_host::host_io::{
        HostIoCapability, HostIoControl, HostIoError, HostIoExceptionProvenance, HostIoOutcome,
        HostIoProvider, HostIoRequest, HostIoResponse, SandboxedHostIo, UnrestrictedHostIoControl,
    };
    use frankenengine_node::config::{NetworkAllowlistEntry, NetworkPolicyConfig};
    use frankenengine_node::ops::ssrf_gated_host_io::{
        EndpointResolver, PinnedNetworkProvider, SSRF_EGRESS_POLICY_BLOCK_MARKER, SsrfGatedHostIo,
    };
    use frankenengine_node::security::network_guard::Action;
    use frankenengine_node::security::ssrf_policy::SsrfPolicyTemplate;

    const REPLY: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";

    #[derive(Debug, Default)]
    struct Signal(AtomicBool);

    impl HostIoControl for Signal {
        fn checkpoint(&self) -> Result<(), HostIoError> {
            if self.0.load(Ordering::Acquire) {
                // A badly classified custom supervisor diagnostic must not
                // become a catchable guest Fs error or disclose its contents.
                Err(HostIoError::Fs {
                    code: "EIO".into(),
                    detail: "private-control-diagnostic".into(),
                })
            } else {
                Ok(())
            }
        }
    }

    fn assert_cancelled(outcome: HostIoOutcome) {
        assert_eq!(
            outcome,
            Err(HostIoError::Denied {
                reason: "HOST_IO_EXECUTION_CANCELLED".into(),
            })
        );
    }

    fn request(host: &str, port: u16, tls: bool) -> HostIoRequest {
        HostIoRequest::NetworkRequest {
            endpoint: format!("{host}:{port}"),
            payload: format!("GET / HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n").into_bytes(),
            max_len: 4096,
            use_tls: tls,
        }
    }

    fn local_policy(host: &str, port: u16) -> SsrfPolicyTemplate {
        let mut policy = policy();
        policy
            .add_allowlist(host, Some(port), "local cancellation fixture", "control", "time")
            .unwrap();
        policy
    }

    fn listener() -> TcpListener {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        listener
    }

    fn accept(listener: &TcpListener) -> TcpStream {
        let deadline = Instant::now() + Duration::from_secs(3);
        let stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline => {
                    thread::sleep(Duration::from_millis(1));
                }
                other => panic!("bounded local accept failed: {other:?}"),
            }
        };
        stream.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        stream.set_write_timeout(Some(Duration::from_secs(2))).unwrap();
        stream
    }

    fn read_request(stream: &mut TcpStream) {
        let mut bytes = Vec::new();
        while bytes.len() < 8192 && !bytes.ends_with(b"\r\n\r\n") {
            let mut byte = [0_u8];
            stream.read_exact(&mut byte).unwrap();
            bytes.push(byte[0]);
        }
        assert!(bytes.starts_with(b"GET / HTTP/1.1\r\n"));
        assert!(bytes.ends_with(b"\r\n\r\n"));
    }

    fn start(
        gate: Arc<dyn HostIoProvider>,
        request: HostIoRequest,
        control: Arc<dyn HostIoControl>,
    ) -> (JoinHandle<()>, mpsc::Receiver<HostIoOutcome>) {
        let (send, receive) = mpsc::channel();
        let worker = thread::spawn(move || {
            let result = gate.perform_controlled(&request, &[request.required_capability()], control);
            let _ = send.send(result);
        });
        (worker, receive)
    }

    fn finish(worker: JoinHandle<()>, receive: mpsc::Receiver<HostIoOutcome>) -> HostIoOutcome {
        let result = receive.recv_timeout(Duration::from_secs(3));
        // Native fixtures retain a five-second absolute deadline even if the
        // assertion fails. Join the caller rather than leave a detached test.
        worker.join().unwrap();
        result.expect("supervised operation did not finish within the test wait bound")
    }

    #[derive(Debug)]
    struct PausingDns(mpsc::SyncSender<()>);

    impl EndpointResolver for PausingDns {
        fn resolve(&self, _: &str, _: u16) -> io::Result<Vec<IpAddr>> {
            panic!("supervised DNS must not fall back to unscoped lookup")
        }

        fn resolve_controlled_until(
            &self, _: &str, _: u16, deadline: Instant, control: Arc<dyn HostIoControl>,
        ) -> io::Result<Vec<IpAddr>> {
            self.0.try_send(()).expect("announce DNS wait without blocking");
            loop {
                control.checkpoint().map_err(|_| {
                    io::Error::new(io::ErrorKind::PermissionDenied, "private-dns-diagnostic")
                })?;
                if Instant::now() >= deadline {
                    return Err(io::Error::new(io::ErrorKind::TimedOut, "fixture deadline"));
                }
                thread::sleep(Duration::from_millis(1));
            }
        }
    }

    #[test]
    fn cancellation_interrupts_cooperative_dns_without_authorizing_a_socket() {
        let root = tempfile::tempdir().unwrap();
        let listener = listener();
        let port = listener.local_addr().unwrap().port();
        let inner = SandboxedHostIo::with_root(root.path()).unwrap()
            .with_network_timeout(Duration::from_secs(5)).unwrap();
        let revocation = inner.network_revocation();
        let (entered, waiting) = mpsc::sync_channel(1);
        let gate = Arc::new(SsrfGatedHostIo::with_resolver(
            inner, local_policy("localhost", port), "cancel-dns", PausingDns(entered),
        ));
        let signal = Arc::new(Signal::default());
        let (worker, result) = start(gate.clone(), request("localhost", port, true), signal.clone());
        let announced = waiting.recv_timeout(Duration::from_secs(3));
        signal.0.store(true, Ordering::Release);
        let outcome = finish(worker, result);
        announced.expect("DNS phase was entered");
        assert_cancelled(outcome);
        assert_eq!(listener.accept().unwrap_err().kind(), io::ErrorKind::WouldBlock);
        assert!(!revocation.is_revoked(), "per-execution cancellation cannot revoke the provider");
        let audit = gate.audit_records();
        assert_eq!(audit.len(), 1);
        assert_eq!(audit[0].action, Action::Deny);
        assert_eq!(audit[0].cidr_matched.as_deref(), Some("network_execution_cancelled"));
        assert!(!format!("{audit:?}").contains("private-dns-diagnostic"));
    }

    #[test]
    fn cancellation_reaches_the_native_socket_beneath_a_stalled_tls_handshake() {
        let root = tempfile::tempdir().unwrap();
        let listener = listener();
        let address = listener.local_addr().unwrap();
        let inner = SandboxedHostIo::with_root(root.path()).unwrap()
            .with_network_timeout(Duration::from_secs(5)).unwrap();
        let revocation = inner.network_revocation();
        let observed = Arc::new(Observed::default());
        let gate = Arc::new(SsrfGatedHostIo::with_resolver(
            inner, local_policy("localhost", address.port()), "cancel-tls",
            Resolver { state: observed.clone(), answers: vec![address.ip()] },
        ));
        let signal = Arc::new(Signal::default());
        let (worker, result) = start(gate.clone(), request("localhost", address.port(), true), signal.clone());
        let mut peer = accept(&listener);
        let mut first = [0_u8];
        peer.read_exact(&mut first).unwrap();
        assert_eq!(first[0], 22, "TLS ClientHello must precede application bytes");
        // Keep the peer open without a ServerHello. EOF must not be what
        // releases the engine's wait, and no certificate exception is granted.
        signal.0.store(true, Ordering::Release);
        assert_cancelled(finish(worker, result));
        assert!(!revocation.is_revoked());
        assert_eq!(observed.dns.load(Ordering::SeqCst), 1);
        assert!(gate.audit_records().iter().any(|entry|
            entry.cidr_matched.as_deref() == Some("network_execution_cancelled")));
        drop(peer);
    }

    #[test]
    fn cancelling_one_native_response_wait_does_not_cancel_a_concurrent_sibling() {
        let root = tempfile::tempdir().unwrap();
        let first = listener();
        let second = listener();
        let first_port = first.local_addr().unwrap().port();
        let second_port = second.local_addr().unwrap().port();
        let inner = SandboxedHostIo::with_root(root.path()).unwrap()
            .with_network_timeout(Duration::from_secs(5)).unwrap();
        let revocation = inner.network_revocation();
        let mut config = NetworkPolicyConfig::default();
        for port in [first_port, second_port] {
            config.allowlist.push(NetworkAllowlistEntry {
                host: "127.0.0.1".into(), port: Some(port), reason: "local shared-provider fixture".into(),
            });
        }
        let gate = Arc::new(SsrfGatedHostIo::from_network_policy(inner, &config, "shared-control"));
        let cancelled = Arc::new(Signal::default());
        let survivor = Arc::new(Signal::default());
        let (first_worker, first_result) = start(
            gate.clone(), request("127.0.0.1", first_port, false), cancelled.clone(),
        );
        let mut first_peer = accept(&first);
        read_request(&mut first_peer);
        let (second_worker, second_result) = start(
            gate.clone(), request("127.0.0.1", second_port, false), survivor,
        );
        let mut second_peer = accept(&second);
        read_request(&mut second_peer);
        cancelled.0.store(true, Ordering::Release);
        // Keep both peers open: only the first execution's signal changes.
        let cancelled_result = finish(first_worker, first_result);
        second_peer.write_all(REPLY).unwrap();
        let successful_result = finish(second_worker, second_result);
        assert_cancelled(cancelled_result);
        assert_eq!(successful_result, Ok(HostIoResponse::NetworkRequest { response: REPLY.to_vec() }));
        assert!(!revocation.is_revoked());
        assert_eq!(gate.audit_records().iter().filter(|entry|
            entry.cidr_matched.as_deref() == Some("network_execution_cancelled")).count(), 1);
    }

    #[derive(Debug)]
    struct NoNetwork;

    impl HostIoProvider for NoNetwork {
        fn name(&self) -> &str { "never-delegated" }
        fn perform(&self, _: &HostIoRequest, _: &[HostIoCapability]) -> HostIoOutcome {
            panic!("a refused operation reached plain transport")
        }
    }

    impl PinnedNetworkProvider for NoNetwork {
        fn supports_pinned_tls(&self) -> bool { true }
        fn perform_pinned_network_candidates_controlled(
            &self, _: &HostIoRequest, _: &[HostIoCapability], _: &[SocketAddr],
            _: Instant, _: Arc<dyn HostIoControl>,
        ) -> HostIoOutcome {
            panic!("a refused operation reached pinned transport")
        }
    }

    #[derive(Debug)]
    struct CancellingLegacyDns { signal: Arc<Signal>, fail: bool }

    impl EndpointResolver for CancellingLegacyDns {
        fn resolve(&self, _: &str, _: u16) -> io::Result<Vec<IpAddr>> {
            self.signal.0.store(true, Ordering::Release);
            if self.fail { Err(io::Error::other("private-legacy-dns-failure")) }
            else { Ok(vec![PUBLIC_V4.parse().unwrap()]) }
        }
    }

    #[test]
    fn custom_dns_adapter_checks_cancellation_on_success_and_failure() {
        for fail in [false, true] {
            let signal = Arc::new(Signal::default());
            let gate = SsrfGatedHostIo::with_resolver(
                NoNetwork, policy(), "legacy-control",
                CancellingLegacyDns { signal: signal.clone(), fail },
            );
            assert_cancelled(gate.perform_controlled(
                &request("never-connect.invalid", 443, true), &[HostIoCapability::NetworkSend], signal,
            ));
            assert_eq!(gate.audit_records()[0].cidr_matched.as_deref(), Some("network_execution_cancelled"));
        }
    }

    #[derive(Debug)]
    struct ResettingTransport { signal: Arc<Signal>, calls: Arc<AtomicUsize> }

    impl HostIoProvider for ResettingTransport {
        fn name(&self) -> &str { "resetting-control-observer" }
        fn perform(&self, _: &HostIoRequest, _: &[HostIoCapability]) -> HostIoOutcome {
            panic!("supervised operation used plain transport")
        }
    }

    impl PinnedNetworkProvider for ResettingTransport {
        fn supports_pinned_tls(&self) -> bool { true }
        fn perform_pinned_network_candidates_controlled(
            &self, _: &HostIoRequest, _: &[HostIoCapability], _: &[SocketAddr],
            _: Instant, control: Arc<dyn HostIoControl>,
        ) -> HostIoOutcome {
            if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
                self.signal.0.store(true, Ordering::Release);
                assert!(control.checkpoint().is_err());
                self.signal.0.store(false, Ordering::Release);
            } else { control.checkpoint()?; }
            // Deliberately buggy provider: returning bytes after it observed
            // denial must not turn the whole supervised operation into success.
            Ok(HostIoResponse::NetworkRequest { response: REPLY.to_vec() })
        }
    }

    #[test]
    fn transport_refusal_cannot_be_reset_into_success_or_poison_the_next_operation() {
        let signal = Arc::new(Signal::default());
        let calls = Arc::new(AtomicUsize::new(0));
        let observed = Arc::new(Observed::default());
        let gate = SsrfGatedHostIo::with_resolver(
            ResettingTransport { signal: signal.clone(), calls: calls.clone() },
            policy(), "sticky-transport",
            Resolver { state: observed.clone(), answers: vec![PUBLIC_V4.parse().unwrap()] },
        );
        let original = request("never-connect.invalid", 443, true);
        assert_cancelled(gate.perform_controlled(&original, &[HostIoCapability::NetworkSend], signal.clone()));
        assert_eq!(
            gate.perform_controlled(&original, &[HostIoCapability::NetworkSend], signal),
            Ok(HostIoResponse::NetworkRequest { response: REPLY.to_vec() }),
        );
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(observed.dns.load(Ordering::SeqCst), 2);
    }

    #[derive(Debug)]
    struct NonNetwork { expected: Arc<dyn HostIoControl>, calls: Mutex<Vec<HostIoRequest>> }

    impl HostIoProvider for NonNetwork {
        fn name(&self) -> &str { "non-network-control-observer" }
        fn filesystem_exception_provenance(&self) -> HostIoExceptionProvenance {
            HostIoExceptionProvenance::ProviderInternal
        }
        fn perform(&self, _: &HostIoRequest, _: &[HostIoCapability]) -> HostIoOutcome {
            panic!("supervised operation lost its control")
        }
        fn perform_controlled(
            &self, request: &HostIoRequest, _: &[HostIoCapability], control: Arc<dyn HostIoControl>,
        ) -> HostIoOutcome {
            assert!(Arc::ptr_eq(&self.expected, &control));
            control.checkpoint()?;
            self.calls.lock().unwrap().push(request.clone());
            Ok(match request {
                HostIoRequest::FsRead { .. } => HostIoResponse::FsRead { bytes: vec![1, 2] },
                HostIoRequest::RandomRead { .. } => HostIoResponse::RandomRead { bytes: vec![3, 4] },
                HostIoRequest::EnvRead { .. } => HostIoResponse::EnvRead { value: Some("captured".into()) },
                _ => panic!("unexpected non-network fixture"),
            })
        }
    }

    #[test]
    fn non_network_effects_keep_the_original_control_and_exception_provenance() {
        let control: Arc<dyn HostIoControl> = Arc::new(UnrestrictedHostIoControl);
        let gate = SsrfGatedHostIo::new(
            NonNetwork { expected: control.clone(), calls: Mutex::new(Vec::new()) }, "non-network",
        );
        assert_eq!(gate.filesystem_exception_provenance(), HostIoExceptionProvenance::ProviderInternal);
        for (request, expected) in [
            (HostIoRequest::FsRead { path: "input.txt".into() }, HostIoResponse::FsRead { bytes: vec![1, 2] }),
            (HostIoRequest::RandomRead { byte_len: 2 }, HostIoResponse::RandomRead { bytes: vec![3, 4] }),
            (HostIoRequest::EnvRead { name: "EXPLICIT_FIXTURE".into() }, HostIoResponse::EnvRead { value: Some("captured".into()) }),
        ] {
            assert_eq!(gate.perform_controlled(&request, &[request.required_capability()], control.clone()), Ok(expected));
        }
        assert!(gate.audit_records().is_empty());
    }

    #[test]
    fn supervised_resolution_still_checks_every_address_and_answer_limit() {
        for (answers, marker) in [
            (vec![PUBLIC_V6.parse().unwrap(), "fd00::1".parse().unwrap(), PUBLIC_V4.parse().unwrap()], SSRF_EGRESS_POLICY_BLOCK_MARKER),
            (vec![PUBLIC_V4.parse().unwrap(); 65], "dns_answer_limit_exceeded"),
            (vec![], "dns_resolution_required"),
        ] {
            let observed = Arc::new(Observed::default());
            let gate = SsrfGatedHostIo::with_resolver(
                NoNetwork, policy(), "controlled-address-set", Resolver { state: observed.clone(), answers },
            );
            for request in requests("never-connect.invalid:443") {
                let result = gate.perform_controlled(
                    &request, &[request.required_capability()], Arc::new(UnrestrictedHostIoControl),
                );
                assert!(matches!(result, Err(HostIoError::Denied { reason }) if reason.contains(marker)));
            }
            assert_eq!(observed.dns.load(Ordering::SeqCst), 4);
            assert!(gate.audit_records().iter().all(|entry| entry.action == Action::Deny));
        }
    }
}
