//! Live TLS and deadline coverage, included by ssrf_gated_host_io_egress.
//! All sockets are local. An .invalid authority proves that the connection
//! cannot succeed by silently doing a second system-DNS lookup.

use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use frankenengine_extension_host::host_io::{
    HostIoCapability, HostIoError, HostIoOutcome, HostIoProvider, HostIoRequest,
    HostIoResponse, SandboxedHostIo,
};
use frankenengine_node::config::{NetworkAllowlistEntry, NetworkPolicyConfig};
use frankenengine_node::ops::flow_gated_host_io::FlowGatedHostIo;
use frankenengine_node::ops::ssrf_gated_host_io::{
    EndpointResolver, PinnedNetworkProvider, SsrfGatedHostIo, SystemEndpointResolver,
};
use frankenengine_node::security::network_guard::Action;
use frankenengine_node::security::ssrf_policy::SsrfPolicyTemplate;

const AUTHORITY: &str = "pinned-tls.invalid";
const REPLY: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";

#[derive(Debug)]
struct FixedDns {
    ip: IpAddr,
    calls: Arc<AtomicUsize>,
}

impl EndpointResolver for FixedDns {
    fn resolve(&self, _: &str, _: u16) -> io::Result<Vec<IpAddr>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(vec![self.ip])
    }
}

fn exception(host: &str, port: u16) -> SsrfPolicyTemplate {
    let mut policy = SsrfPolicyTemplate::default_template("pinned-tls".into());
    policy.add_allowlist(host, Some(port), "local TLS integration fixture",
        "pinned-tls", "2026-09-20T00:00:00Z").unwrap();
    policy
}

fn transport_fixture_policy() -> SsrfPolicyTemplate {
    // These .invalid-name tests exercise the real transport on a local socket.
    // A hostname allowlist entry deliberately does NOT bypass private DNS
    // checks. Use an explicit test-only CIDR opt-out, with separate tests below
    // proving production defaults and hostname exceptions still deny rebinding.
    let mut policy = SsrfPolicyTemplate::default_template("local-transport-fixture".into());
    policy.blocked_cidrs.clear();
    policy
}

fn request(host: &str, port: u16, max_len: u64) -> HostIoRequest {
    HostIoRequest::NetworkRequest {
        endpoint: format!("{host}:{port}"),
        payload: format!("GET /pinned HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: keep-alive\r\n\r\n").into_bytes(),
        max_len,
        use_tls: true,
    }
}

#[derive(Debug)]
struct Peer {
    sni: Option<String>,
    request: Vec<u8>,
}

fn tls_peer(
    listener: TcpListener,
    key: &rcgen::CertifiedKey,
    response: Vec<u8>,
) -> std::thread::JoinHandle<Peer> {
    use rustls_pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
    let config = rustls::ServerConfig::builder_with_provider(
        Arc::new(rustls::crypto::ring::default_provider()),
    )
    .with_safe_default_protocol_versions().unwrap()
    .with_no_client_auth()
    .with_single_cert(vec![key.cert.der().clone()], PrivateKeyDer::Pkcs8(
        PrivatePkcs8KeyDer::from(key.key_pair.serialize_der()),
    )).unwrap();
    listener.set_nonblocking(true).unwrap();
    std::thread::spawn(move || {
        let end = Instant::now() + Duration::from_secs(5);
        let socket = loop {
            match listener.accept() {
                Ok((socket, _)) => break socket,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock && Instant::now() < end => {
                    std::thread::sleep(Duration::from_millis(1));
                }
                other => panic!("bounded TLS accept failed: {other:?}"),
            }
        };
        socket.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        socket.set_write_timeout(Some(Duration::from_secs(2))).unwrap();
        let connection = rustls::ServerConnection::new(Arc::new(config)).unwrap();
        let mut tls = rustls::StreamOwned::new(connection, socket);
        let mut bytes = Vec::new();
        let mut byte = [0_u8; 1];
        while bytes.len() < 8192 && !bytes.ends_with(b"\r\n\r\n") {
            match tls.read(&mut byte) {
                Ok(1) => bytes.push(byte[0]),
                _ => return Peer { sni: tls.conn.server_name().map(str::to_owned), request: bytes },
            }
        }
        let sni = tls.conn.server_name().map(str::to_owned);
        let _ = tls.write_all(&response);
        let _ = tls.flush();
        // No close_notify: self-delimited HTTP must complete, truncated HTTP
        // must fail, and close-delimited HTTP must not turn this into clean EOF.
        Peer { sni, request: bytes }
    })
}

#[test]
fn permitted_hostname_https_uses_the_pinned_socket_and_original_identity() {
    let root = tempfile::tempdir().unwrap();
    let key = rcgen::generate_simple_self_signed(vec![AUTHORITY.into()]).unwrap();
    let inner = SandboxedHostIo::with_root(root.path()).unwrap()
        .with_extra_tls_roots_pem(key.cert.pem().as_bytes()).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = tls_peer(listener, &key, REPLY.to_vec());
    let calls = Arc::new(AtomicUsize::new(0));
    let gate = SsrfGatedHostIo::with_resolver(inner, transport_fixture_policy(),
        "pinned-tls", FixedDns { ip: address.ip(), calls: Arc::clone(&calls) });
    let original = request(AUTHORITY, address.port(), 4096);
    let before = original.clone();
    let result = gate.perform(&original, &[HostIoCapability::NetworkSend]);
    let peer = server.join().unwrap();
    assert_eq!(result, Ok(HostIoResponse::NetworkRequest { response: REPLY.to_vec() }));
    assert_eq!(peer.sni.as_deref(), Some(AUTHORITY));
    let HostIoRequest::NetworkRequest { payload, .. } = before else { unreachable!() };
    assert_eq!(peer.request, payload);
    assert_eq!(original, request(AUTHORITY, address.port(), 4096));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let audit = gate.audit_records();
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0].host, AUTHORITY);
    assert!(!audit[0].allowlisted);
}

#[test]
fn configured_production_constructor_enables_hostname_tls_without_an_opt_in() {
    let root = tempfile::tempdir().unwrap();
    let key = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let inner = SandboxedHostIo::with_root(root.path()).unwrap()
        .with_extra_tls_roots_pem(key.cert.pem().as_bytes()).unwrap();
    // Bind the system's preferred localhost family, matching the real resolver.
    // This exercises the production constructor and OS resolver, not FixedDns.
    let addresses = SystemEndpointResolver.resolve("localhost", 443).unwrap();
    let ip = addresses[0];
    assert!(ip.is_loopback());
    let listener = TcpListener::bind(SocketAddr::new(ip, 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tls_peer(listener, &key, REPLY.to_vec());
    let mut config = NetworkPolicyConfig::default();
    config.allowlist.push(NetworkAllowlistEntry {
        host: "localhost".into(), port: Some(port), reason: "local TLS fixture".into(),
    });
    let gate = SsrfGatedHostIo::from_network_policy(inner, &config, "configured-tls");
    let result = gate.perform(&request("localhost", port, 4096), &[HostIoCapability::NetworkSend]);
    let peer = server.join().unwrap();
    assert_eq!(result, Ok(HostIoResponse::NetworkRequest { response: REPLY.to_vec() }));
    assert_eq!(peer.sni.as_deref(), Some("localhost"));
    assert!(!peer.request.is_empty());
    assert!(gate.audit_records()[0].allowlisted);
}

#[test]
fn certificate_trust_and_hostname_failures_never_send_http_or_retry() {
    for (name, trust) in [(AUTHORITY, false), ("wrong-name.invalid", true)] {
        let root = tempfile::tempdir().unwrap();
        let key = rcgen::generate_simple_self_signed(vec![name.into()]).unwrap();
        let mut inner = SandboxedHostIo::with_root(root.path()).unwrap();
        if trust {
            inner = inner.with_extra_tls_roots_pem(key.cert.pem().as_bytes()).unwrap();
        }
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = tls_peer(listener, &key, REPLY.to_vec());
        let calls = Arc::new(AtomicUsize::new(0));
        let gate = SsrfGatedHostIo::with_resolver(inner, transport_fixture_policy(),
            "bad-tls", FixedDns { ip: address.ip(), calls: Arc::clone(&calls) });
        let result = gate.perform(&request(AUTHORITY, address.port(), 4096), &[HostIoCapability::NetworkSend]);
        let peer = server.join().unwrap();
        assert!(matches!(result, Err(HostIoError::Io { .. })), "{name}: {result:?}");
        assert_eq!(peer.sni.as_deref(), Some(AUTHORITY));
        assert!(peer.request.is_empty(), "application bytes preceded TLS authentication");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
}

#[test]
fn hostname_https_does_not_bypass_default_private_destination_denial() {
    let root = tempfile::tempdir().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let gate = SsrfGatedHostIo::with_resolver(SandboxedHostIo::with_root(root.path()).unwrap(),
        SsrfPolicyTemplate::default_template("deny-tls".into()), "deny-tls",
        FixedDns { ip: address.ip(), calls: Arc::clone(&calls) });
    assert!(matches!(gate.perform(&request(AUTHORITY, address.port(), 4096),
        &[HostIoCapability::NetworkSend]), Err(HostIoError::Denied { .. })));
    assert_eq!(listener.accept().unwrap_err().kind(), io::ErrorKind::WouldBlock);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(gate.audit_records()[0].action, Action::Deny);
}

#[test]
fn tls_response_caps_truncation_and_unclean_eof_remain_fail_closed() {
    let mut oversized = b"HTTP/1.1 200 OK\r\nContent-Length: 8192\r\n\r\n".to_vec();
    oversized.extend_from_slice(&vec![b'x'; 8192]);
    for response in [oversized, b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nx".to_vec(),
        b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nunterminated".to_vec()] {
        let root = tempfile::tempdir().unwrap();
        let key = rcgen::generate_simple_self_signed(vec![AUTHORITY.into()]).unwrap();
        let inner = SandboxedHostIo::with_root(root.path()).unwrap()
            .with_extra_tls_roots_pem(key.cert.pem().as_bytes()).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = tls_peer(listener, &key, response);
        let calls = Arc::new(AtomicUsize::new(0));
        let gate = SsrfGatedHostIo::with_resolver(inner, transport_fixture_policy(),
            "framing", FixedDns { ip: address.ip(), calls: Arc::clone(&calls) });
        let result = gate.perform(&request(AUTHORITY, address.port(), 4096), &[HostIoCapability::NetworkSend]);
        let peer = server.join().unwrap();
        assert!(!peer.request.is_empty());
        assert!(matches!(result, Err(HostIoError::Io { .. })), "{result:?}");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
}

#[test]
fn stalled_tls_handshake_obeys_the_configured_whole_effect_budget() {
    let root = tempfile::tempdir().unwrap();
    let inner = SandboxedHostIo::with_root(root.path()).unwrap()
        .with_network_timeout(Duration::from_millis(60)).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let gate = SsrfGatedHostIo::with_resolver(inner, transport_fixture_policy(),
        "stalled-tls", FixedDns { ip: address.ip(), calls: Arc::clone(&calls) });
    // The listener accepts TCP in the kernel but never sends a ServerHello.
    let started = Instant::now();
    let result = gate.perform(&request(AUTHORITY, address.port(), 4096), &[HostIoCapability::NetworkSend]);
    assert!(matches!(result, Err(HostIoError::Io { .. })), "{result:?}");
    assert!(started.elapsed() < Duration::from_secs(3));
    let (mut socket, _) = listener.accept().expect("a TLS connection was attempted");
    socket.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
    let mut first = [0_u8; 1];
    socket.read_exact(&mut first).unwrap();
    assert_eq!(first[0], 22, "the wire starts with a TLS handshake, not HTTP");
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn information_flow_denial_precedes_dns_even_for_supported_hostname_https() {
    let root = tempfile::tempdir().unwrap();
    let secret = b"never-egress-this-secret";
    std::fs::write(root.path().join(".env"), secret).unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let ssrf = SsrfGatedHostIo::with_resolver(SandboxedHostIo::with_root(root.path()).unwrap(),
        exception(AUTHORITY, 443), "flow-tls",
        FixedDns { ip: "127.0.0.1".parse().unwrap(), calls: Arc::clone(&calls) });
    let flow = FlowGatedHostIo::new(ssrf, "flow-tls");
    assert!(flow.perform(&HostIoRequest::FsRead { path: ".env".into() }, &[HostIoCapability::FsRead]).is_ok());
    let forbidden = HostIoRequest::NetworkRequest {
        endpoint: format!("{AUTHORITY}:443"), payload: secret.to_vec(), max_len: 4096, use_tls: true,
    };
    assert!(matches!(flow.perform(&forbidden, &[HostIoCapability::NetworkSend]),
        Err(HostIoError::Denied { reason }) if reason.starts_with("flow_policy:")));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[derive(Debug, Default)]
struct BudgetState {
    resolved_until: Mutex<Option<Instant>>,
    executed_until: Mutex<Option<Instant>>,
    calls: AtomicUsize,
}

#[derive(Debug)]
struct BudgetProbe {
    state: Arc<BudgetState>,
    timeout: Duration,
}

impl HostIoProvider for BudgetProbe {
    fn name(&self) -> &str { "budget-contract-probe" }
    fn perform(&self, _: &HostIoRequest, _: &[HostIoCapability]) -> HostIoOutcome {
        panic!("the gate must use explicit pinned execution");
    }
}

impl PinnedNetworkProvider for BudgetProbe {
    fn network_timeout(&self) -> Duration { self.timeout }
    fn supports_pinned_tls(&self) -> bool { true }
    fn perform_pinned_network(&self, request: &HostIoRequest, _: &[HostIoCapability],
        address: SocketAddr, deadline: Instant) -> HostIoOutcome {
        assert_eq!(request, &self::request(AUTHORITY, 443, 4096));
        assert_eq!(address, "93.184.216.34:443".parse().unwrap());
        *self.state.executed_until.lock().unwrap() = Some(deadline);
        self.state.calls.fetch_add(1, Ordering::SeqCst);
        Ok(HostIoResponse::NetworkRequest { response: REPLY.to_vec() })
    }
}

#[derive(Debug)]
struct BudgetResolver {
    state: Arc<BudgetState>,
    late: bool,
}

impl EndpointResolver for BudgetResolver {
    fn resolve(&self, _: &str, _: u16) -> io::Result<Vec<IpAddr>> {
        panic!("the gate must supply its absolute deadline");
    }
    fn resolve_until(&self, _: &str, _: u16, deadline: Instant) -> io::Result<Vec<IpAddr>> {
        *self.state.resolved_until.lock().unwrap() = Some(deadline);
        if self.late {
            while Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(1));
            }
        }
        Ok(vec!["93.184.216.34".parse().unwrap()])
    }
}

#[test]
fn dns_and_transport_receive_the_identical_absolute_deadline() {
    let state = Arc::new(BudgetState::default());
    let gate = SsrfGatedHostIo::with_resolver(
        BudgetProbe { state: Arc::clone(&state), timeout: Duration::from_secs(5) },
        SsrfPolicyTemplate::default_template("budget".into()), "budget",
        BudgetResolver { state: Arc::clone(&state), late: false });
    assert!(gate.perform(&request(AUTHORITY, 443, 4096), &[HostIoCapability::NetworkSend]).is_ok());
    assert_eq!(*state.resolved_until.lock().unwrap(), *state.executed_until.lock().unwrap());
    assert_eq!(state.calls.load(Ordering::SeqCst), 1);
}

#[test]
fn late_dns_results_cannot_restart_the_budget_or_authorize_a_socket() {
    let state = Arc::new(BudgetState::default());
    let gate = SsrfGatedHostIo::with_resolver(
        BudgetProbe { state: Arc::clone(&state), timeout: Duration::from_millis(2) },
        SsrfPolicyTemplate::default_template("late".into()), "late",
        BudgetResolver { state: Arc::clone(&state), late: true });
    assert!(matches!(gate.perform(&request(AUTHORITY, 443, 4096), &[HostIoCapability::NetworkSend]),
        Err(HostIoError::Denied { reason }) if reason.contains("network_deadline_exceeded")));
    assert_eq!(state.calls.load(Ordering::SeqCst), 0);
    assert_eq!(gate.audit_records()[0].cidr_matched.as_deref(), Some("network_deadline_exceeded"));
}

#[derive(Debug)]
struct UnavailableResolver(io::ErrorKind);
impl EndpointResolver for UnavailableResolver {
    fn resolve(&self, _: &str, _: u16) -> io::Result<Vec<IpAddr>> {
        Err(io::Error::new(self.0, "injected resolver admission failure"))
    }
}

#[test]
fn resolver_saturation_and_timeout_are_audited_without_network_delegation() {
    for (kind, code) in [(io::ErrorKind::WouldBlock, "dns_capacity_exhausted"),
        (io::ErrorKind::TimedOut, "network_deadline_exceeded")] {
        let state = Arc::new(BudgetState::default());
        let gate = SsrfGatedHostIo::with_resolver(
            BudgetProbe { state: Arc::clone(&state), timeout: Duration::from_secs(5) },
            exception(AUTHORITY, 443), "unavailable", UnavailableResolver(kind));
        assert!(matches!(gate.perform(&request(AUTHORITY, 443, 4096), &[HostIoCapability::NetworkSend]),
            Err(HostIoError::Denied { .. })));
        assert_eq!(state.calls.load(Ordering::SeqCst), 0);
        let audit = gate.audit_records();
        assert_eq!(audit.len(), 1);
        assert_eq!(audit[0].cidr_matched.as_deref(), Some(code));
        assert_eq!(audit[0].action, Action::Deny);
    }
}

#[test]
fn system_resolver_rejects_expired_and_malformed_requests_without_dns() {
    let resolver = SystemEndpointResolver;
    assert_eq!(resolver.resolve_until("127.0.0.1", 80, Instant::now()).unwrap_err().kind(), io::ErrorKind::TimedOut);
    for host in ["user@host", "127.1", "host/path", "host\0", "[::1"] {
        assert_eq!(resolver.resolve_until(host, 80, Instant::now() + Duration::from_secs(1))
            .unwrap_err().kind(), io::ErrorKind::InvalidInput, "{host}");
    }
}

#[test]
fn ipv6_literal_https_uses_exact_ip_certificate_and_never_dns_or_sni() {
    let root = tempfile::tempdir().unwrap();
    let key = rcgen::generate_simple_self_signed(vec!["::1".into()]).unwrap();
    let inner = SandboxedHostIo::with_root(root.path()).unwrap()
        .with_extra_tls_roots_pem(key.cert.pem().as_bytes()).unwrap();
    // IPv6 availability is required in this native lane: never report a skipped
    // connection as proof of IPv6 support.
    let listener = TcpListener::bind("[::1]:0").expect("IPv6 loopback required");
    let port = listener.local_addr().unwrap().port();
    let server = tls_peer(listener, &key, REPLY.to_vec());
    let calls = Arc::new(AtomicUsize::new(0));
    let gate = SsrfGatedHostIo::with_resolver(inner, exception("0:0:0:0:0:0:0:1", port),
        "ipv6-tls", FixedDns { ip: "127.0.0.1".parse().unwrap(), calls: Arc::clone(&calls) });
    let original = request("[::1]", port, 4096);
    let result = gate.perform(&original, &[HostIoCapability::NetworkSend]);
    let peer = server.join().unwrap();
    assert_eq!(result, Ok(HostIoResponse::NetworkRequest { response: REPLY.to_vec() }));
    assert!(peer.sni.is_none(), "IP identities do not send DNS SNI");
    let HostIoRequest::NetworkRequest { payload, .. } = original else { unreachable!() };
    assert_eq!(peer.request, payload);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert!(gate.audit_records()[0].allowlisted);
}

#[test]
fn ipv6_literal_https_rejects_trusted_wrong_ip_certificates_before_application_bytes() {
    let root = tempfile::tempdir().unwrap();
    let key = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
    let inner = SandboxedHostIo::with_root(root.path()).unwrap()
        .with_extra_tls_roots_pem(key.cert.pem().as_bytes()).unwrap();
    let listener = TcpListener::bind("[::1]:0").expect("IPv6 loopback required");
    let port = listener.local_addr().unwrap().port();
    let server = tls_peer(listener, &key, REPLY.to_vec());
    let calls = Arc::new(AtomicUsize::new(0));
    let gate = SsrfGatedHostIo::with_resolver(inner, exception("::1", port),
        "ipv6-wrong-identity", FixedDns { ip: "::1".parse().unwrap(), calls: Arc::clone(&calls) });
    let result = gate.perform(&request("[::1]", port, 4096), &[HostIoCapability::NetworkSend]);
    let peer = server.join().unwrap();
    assert!(matches!(result, Err(HostIoError::Io { .. })), "{result:?}");
    assert!(peer.request.is_empty());
    assert!(peer.sni.is_none());
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[derive(Debug)]
struct AddressSetDns {
    addresses: Vec<IpAddr>,
    calls: Arc<AtomicUsize>,
}

impl EndpointResolver for AddressSetDns {
    fn resolve(&self, _: &str, _: u16) -> io::Result<Vec<IpAddr>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(self.addresses.clone())
    }
}

#[test]
fn approved_connection_failover_reaches_ipv4_and_ipv6_tls_without_resolving_again() {
    for bind in ["127.0.0.1:0", "[::1]:0"] {
        let root = tempfile::tempdir().unwrap();
        let key = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let inner = SandboxedHostIo::with_root(root.path()).unwrap()
            .with_extra_tls_roots_pem(key.cert.pem().as_bytes()).unwrap();
        let listener = TcpListener::bind(bind).expect("local IPv4/IPv6 required");
        let live = listener.local_addr().unwrap();
        let server = tls_peer(listener, &key, REPLY.to_vec());
        let calls = Arc::new(AtomicUsize::new(0));
        // localhost's explicit local exception permits both loopback families;
        // ordinary DNS-hostname exceptions remain unable to bypass CIDRs.
        let gate = SsrfGatedHostIo::with_resolver(inner, exception("localhost", live.port()),
            "approved-failover", AddressSetDns {
                addresses: vec!["127.0.0.2".parse().unwrap(), live.ip(), live.ip()],
                calls: Arc::clone(&calls),
            });
        let original = request("localhost", live.port(), 4096);
        let result = gate.perform(&original, &[HostIoCapability::NetworkSend]);
        let peer = server.join().unwrap();
        assert_eq!(result, Ok(HostIoResponse::NetworkRequest { response: REPLY.to_vec() }));
        assert_eq!(peer.sni.as_deref(), Some("localhost"));
        let HostIoRequest::NetworkRequest { payload, .. } = original else { unreachable!() };
        assert_eq!(peer.request, payload);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(gate.audit_records().len(), 1);
    }
}

#[test]
fn tls_authentication_and_partial_http_failures_never_replay_on_another_candidate() {
    for wrong_identity in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let cert_name = if wrong_identity { "wrong.invalid" } else { "localhost" };
        let key = rcgen::generate_simple_self_signed(vec![cert_name.into()]).unwrap();
        let inner = SandboxedHostIo::with_root(root.path()).unwrap()
            .with_extra_tls_roots_pem(key.cert.pem().as_bytes()).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let first = listener.local_addr().unwrap();
        let second = TcpListener::bind(SocketAddr::new("127.0.0.2".parse().unwrap(), first.port())).unwrap();
        second.set_nonblocking(true).unwrap();
        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nx".to_vec();
        let server = tls_peer(listener, &key, response);
        let calls = Arc::new(AtomicUsize::new(0));
        let gate = SsrfGatedHostIo::with_resolver(inner, exception("localhost", first.port()),
            "no-effect-retry", AddressSetDns {
                addresses: vec![first.ip(), second.local_addr().unwrap().ip()],
                calls: Arc::clone(&calls),
            });
        let original = request("localhost", first.port(), 4096);
        let result = gate.perform(&original, &[HostIoCapability::NetworkSend]);
        let peer = server.join().unwrap();
        assert!(matches!(result, Err(HostIoError::Io { .. })), "{result:?}");
        if wrong_identity {
            assert!(peer.request.is_empty());
        } else {
            let HostIoRequest::NetworkRequest { payload, .. } = original else { unreachable!() };
            assert_eq!(peer.request, payload);
        }
        // Even a speculative losing TCP socket must receive no TLS or guest
        // bytes. The connection selector owns and closes losers before I/O.
        match second.accept() {
            Ok((mut socket, _)) => {
                socket.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
                let mut byte = [0; 1];
                assert_eq!(socket.read(&mut byte).unwrap(), 0);
            }
            Err(error) => assert_eq!(error.kind(), io::ErrorKind::WouldBlock),
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(gate.audit_records().len(), 1);
    }
}
