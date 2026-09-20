//! Registered public-API coverage for SSRF admission and pinned network I/O.
//!
//! The baseline suite retains its real-socket and filesystem flow-policy
//! regressions. New tests run here, not in the separately gated inline lane.

#![cfg(feature = "engine")]

#[path = "ssrf_gated_host_io_egress_baseline.rs"]
mod baseline;
#[path = "ssrf_pinned_tls.rs"]
mod pinned_tls;
#[path = "ssrf_dual_stack.rs"]
mod dual_stack;

mod dns_pinning {
    use std::io::{self, Read, Write};
    use std::net::{IpAddr, TcpListener};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use frankenengine_extension_host::host_io::{
        HostIoCapability, HostIoError, HostIoExceptionProvenance, HostIoOutcome, HostIoProvider,
        HostIoRequest, HostIoResponse, SandboxedHostIo,
    };
    use frankenengine_node::ops::ssrf_gated_host_io::{EndpointResolver, SsrfGatedHostIo};
    use frankenengine_node::security::network_guard::Action;
    use frankenengine_node::security::ssrf_policy::{
        AllowlistEntry, PolicyReceipt, SsrfPolicyTemplate,
    };

    #[derive(Debug, Default)]
    struct Observed {
        dns_calls: AtomicUsize,
        requests: Mutex<Vec<(HostIoRequest, Vec<HostIoCapability>)>>,
    }

    #[derive(Debug)]
    struct ResolverPlan {
        addresses: Vec<IpAddr>,
        fail: bool,
        rebind: bool,
    }

    impl ResolverPlan {
        fn addresses(addresses: &[&str]) -> Self {
            Self {
                addresses: addresses.iter().map(|ip| ip.parse().unwrap()).collect(),
                fail: false,
                rebind: false,
            }
        }
    }

    #[derive(Debug)]
    struct ControlledResolver {
        observed: Arc<Observed>,
        plan: ResolverPlan,
    }

    impl EndpointResolver for ControlledResolver {
        fn resolve(&self, _: &str, _: u16) -> io::Result<Vec<IpAddr>> {
            let previous = self.observed.dns_calls.fetch_add(1, Ordering::SeqCst);
            if self.plan.fail {
                return Err(io::Error::other("injected DNS failure"));
            }
            if self.plan.rebind && previous > 0 {
                return Ok(vec!["127.0.0.1".parse().unwrap()]);
            }
            Ok(self.plan.addresses.clone())
        }
    }

    /// Deliberately does not check capabilities: the gate must reject before
    /// DNS even when wrapping a permissive provider.
    #[derive(Debug)]
    struct Recorder {
        observed: Arc<Observed>,
        fail: bool,
    }

    impl frankenengine_node::ops::ssrf_gated_host_io::PinnedNetworkProvider for Recorder {}

    impl HostIoProvider for Recorder {
        fn name(&self) -> &str {
            "dns-pinning-recorder"
        }

        fn filesystem_exception_provenance(&self) -> HostIoExceptionProvenance {
            HostIoExceptionProvenance::ProviderInternal
        }

        fn perform(&self, request: &HostIoRequest, granted: &[HostIoCapability]) -> HostIoOutcome {
            self.observed.requests.lock().unwrap().push((request.clone(), granted.to_vec()));
            if self.fail {
                return Err(HostIoError::Io { detail: "injected inner failure".into() });
            }
            Ok(match request {
                HostIoRequest::NetworkSend { payload, .. } => HostIoResponse::NetworkSend {
                    bytes_sent: u64::try_from(payload.len()).unwrap(),
                },
                HostIoRequest::NetworkRecv { .. } => HostIoResponse::NetworkRecv {
                    bytes: vec![0, 255],
                },
                HostIoRequest::NetworkRequest { .. } => HostIoResponse::NetworkRequest {
                    response: b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".to_vec(),
                },
                HostIoRequest::FsRead { .. } => HostIoResponse::FsRead { bytes: b"local".to_vec() },
                HostIoRequest::RandomRead { byte_len } => HostIoResponse::RandomRead {
                    bytes: vec![7; usize::try_from(*byte_len).unwrap()],
                },
                other => panic!("unexpected fixture request: {other:?}"),
            })
        }
    }

    struct Harness {
        observed: Arc<Observed>,
        gate: SsrfGatedHostIo<Recorder, ControlledResolver>,
    }

    fn policy() -> SsrfPolicyTemplate {
        SsrfPolicyTemplate::default_template("pinning-policy".into())
    }

    fn exception_policy(host: &str, port: u16) -> SsrfPolicyTemplate {
        let mut policy = policy();
        policy.allowlist.push(AllowlistEntry {
            host: host.into(),
            port: Some(port),
            reason: "explicit test endpoint".into(),
            receipt: PolicyReceipt {
                receipt_id: "pinning-receipt".into(),
                connector_id: policy.connector_id.clone(),
                host: host.into(),
                issued_at: "2026-09-19T00:00:00Z".into(),
                reason: "explicit test endpoint".into(),
                trace_id: "pinning-integration".into(),
            },
        });
        policy
    }

    fn harness(policy: SsrfPolicyTemplate, plan: ResolverPlan, fail_inner: bool) -> Harness {
        let observed = Arc::new(Observed::default());
        let gate = SsrfGatedHostIo::with_resolver(
            Recorder { observed: Arc::clone(&observed), fail: fail_inner },
            policy,
            "pinning-integration",
            ControlledResolver { observed: Arc::clone(&observed), plan },
        );
        Harness { observed, gate }
    }

    fn network_requests(endpoint: &str) -> [HostIoRequest; 3] {
        [
            HostIoRequest::NetworkSend { endpoint: endpoint.into(), payload: vec![0, 1, 255, 128] },
            HostIoRequest::NetworkRecv { endpoint: endpoint.into(), max_len: 123 },
            HostIoRequest::NetworkRequest {
                endpoint: endpoint.into(),
                payload: b"GET / HTTP/1.1\r\nHost: service.example\r\n\r\n".to_vec(),
                max_len: 4567,
                use_tls: false,
            },
        ]
    }

    fn tls_request(endpoint: &str) -> HostIoRequest {
        HostIoRequest::NetworkRequest {
            endpoint: endpoint.into(),
            payload: b"GET / HTTP/1.1\r\nHost: service.example\r\n\r\n".to_vec(),
            max_len: 4096,
            use_tls: true,
        }
    }

    fn assert_not_delegated(harness: &Harness) {
        assert!(harness.observed.requests.lock().unwrap().is_empty());
    }

    fn assert_admission_audit(harness: &Harness, code: &str) {
        let records = harness.gate.audit_records();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].action, Action::Deny);
        assert_eq!(records[0].cidr_matched.as_deref(), Some(code));
        assert_eq!(records[0].trace_id, "pinning-integration");
        assert!(!records[0].allowlisted);
    }

    #[test]
    fn all_network_variants_require_capability_before_dns() {
        for request in network_requests("service.example:80").into_iter()
            .chain([tls_request("service.example:443")]) {
            let harness = harness(policy(), ResolverPlan::addresses(&["93.184.216.34"]), false);
            let required = request.required_capability();
            let outcome = harness.gate.perform(&request, &[HostIoCapability::RandomRead]);
            assert_eq!(outcome, Err(HostIoError::CapabilityMissing { capability: required }));
            assert_eq!(harness.observed.dns_calls.load(Ordering::SeqCst), 0);
            assert_not_delegated(&harness);
            assert_admission_audit(&harness, "capability_missing");
        }
    }

    #[test]
    fn send_receive_and_round_trip_pin_only_endpoint_and_preserve_grants() {
        let originals = network_requests("service.example:80");
        let expected = network_requests("93.184.216.34:80");
        let grants = [HostIoCapability::NetworkSend, HostIoCapability::NetworkRecv, HostIoCapability::RandomRead];
        for (original, pinned) in originals.into_iter().zip(expected) {
            let harness = harness(policy(), ResolverPlan::addresses(&["93.184.216.34"]), false);
            let before = original.clone();
            assert!(harness.gate.perform(&original, &grants).is_ok());
            assert_eq!(original, before, "the transcript request must remain unchanged");
            assert_eq!(harness.observed.dns_calls.load(Ordering::SeqCst), 1);
            assert_eq!(*harness.observed.requests.lock().unwrap(), vec![(pinned, grants.to_vec())]);
            assert_eq!(harness.gate.audit_records()[0].host, "service.example");
        }
    }

    #[test]
    fn a_later_rebound_answer_cannot_reuse_an_earlier_authorization() {
        let mut plan = ResolverPlan::addresses(&["93.184.216.34"]);
        plan.rebind = true;
        let harness = harness(policy(), plan, false);
        let request = network_requests("service.example:80")[0].clone();
        let grants = [HostIoCapability::NetworkSend];
        assert!(harness.gate.perform(&request, &grants).is_ok());
        assert_eq!(harness.observed.dns_calls.load(Ordering::SeqCst), 1);
        assert_eq!(harness.observed.requests.lock().unwrap()[0].0, network_requests("93.184.216.34:80")[0]);
        assert!(matches!(harness.gate.perform(&request, &grants), Err(HostIoError::Denied { .. })));
        assert_eq!(harness.observed.dns_calls.load(Ordering::SeqCst), 2);
        assert_eq!(harness.observed.requests.lock().unwrap().len(), 1);
        let records = harness.gate.audit_records();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].action, Action::Allow);
        assert_eq!(records[1].action, Action::Deny);
    }

    #[test]
    fn a_denied_answer_anywhere_in_the_dns_set_blocks_delegation() {
        for addresses in [
            ["93.184.216.34", "127.0.0.1"], ["10.0.0.1", "93.184.216.34"],
            ["93.184.216.34", "169.254.169.254"], ["93.184.216.34", "::1"],
        ] {
            let harness = harness(policy(), ResolverPlan::addresses(&addresses), false);
            let request = network_requests("service.example:80")[0].clone();
            assert!(matches!(harness.gate.perform(&request, &[HostIoCapability::NetworkSend]), Err(HostIoError::Denied { .. })));
            assert_not_delegated(&harness);
            assert_eq!(harness.gate.audit_records()[0].action, Action::Deny);
        }
    }

    #[test]
    fn exceptions_cannot_bypass_empty_failed_or_overflowing_dns_answers() {
        let empty = ResolverPlan::addresses(&[]);
        let mut failed = ResolverPlan::addresses(&[]);
        failed.fail = true;
        let mut overflow = ResolverPlan::addresses(&[]);
        overflow.addresses = vec!["93.184.216.34".parse().unwrap(); 65];
        for (plan, code) in [(empty, "dns_resolution_required"), (failed, "dns_resolution_failed"), (overflow, "dns_answer_limit_exceeded")] {
            let harness = harness(exception_policy("service.example", 80), plan, false);
            let request = network_requests("service.example:80")[0].clone();
            assert!(matches!(harness.gate.perform(&request, &[HostIoCapability::NetworkSend]), Err(HostIoError::Denied { .. })));
            assert_not_delegated(&harness);
            assert_admission_audit(&harness, code);
        }
    }

    #[test]
    fn malformed_endpoints_are_rejected_and_audited_without_dns() {
        let mut endpoints: Vec<String> = [
            "", ":80", "host", "host:0", "host:+80", "host:65536",
            "http://host:80", "user@host:80", "host/path:80", "host\\path:80",
            " host:80", "host\r\n:80", "host\0:80", "a..b:80", "host..:80",
            "[127.0.0.1]:80", "::1:80", "[::1:80", "[fe80::1%eth0]:80",
            "127.1:80", "2130706433:80", "0x7f000001:80", "0177.0.0.1:80",
            "127.0.0.1.:80", "-host:80", "host-:80", "höst.example:80",
        ].into_iter().map(str::to_string).collect();
        endpoints.push(format!("{}.example:80", "a".repeat(64)));
        endpoints.push(format!("{}:80", "a".repeat(4096)));
        for endpoint in endpoints {
            let harness = harness(policy(), ResolverPlan::addresses(&["93.184.216.34"]), false);
            let request = network_requests(&endpoint)[0].clone();
            assert!(matches!(harness.gate.perform(&request, &[HostIoCapability::NetworkSend]), Err(HostIoError::Denied { .. })), "{endpoint:?}");
            assert_eq!(harness.observed.dns_calls.load(Ordering::SeqCst), 0);
            assert_not_delegated(&harness);
            assert_admission_audit(&harness, "invalid_endpoint");
            assert!(harness.gate.audit_records()[0].host.chars().count() <= 260);
        }
    }

    #[test]
    fn hostname_exception_cannot_authorize_private_dns_answers_on_either_port() {
        let harness = harness(exception_policy("service.example", 80), ResolverPlan::addresses(&["127.0.0.1"]), false);
        let grants = [HostIoCapability::NetworkSend];
        let allowed = network_requests("Service.Example.:80")[0].clone();
        assert!(matches!(harness.gate.perform(&allowed, &grants), Err(HostIoError::Denied { .. })));
        assert!(!harness.gate.audit_records()[0].allowlisted);
        let wrong_port = network_requests("service.example:81")[0].clone();
        assert!(matches!(harness.gate.perform(&wrong_port, &grants), Err(HostIoError::Denied { .. })));
        assert!(harness.observed.requests.lock().unwrap().is_empty());
    }

    #[test]
    fn numeric_endpoints_bypass_dns_and_keep_tls_ip_identity() {
        for request in network_requests("93.184.216.34:443").into_iter().chain([tls_request("93.184.216.34:443")]) {
            let harness = harness(policy(), ResolverPlan::addresses(&[]), false);
            let grants = [request.required_capability()];
            assert!(harness.gate.perform(&request, &grants).is_ok());
            assert_eq!(harness.observed.dns_calls.load(Ordering::SeqCst), 0);
            assert_eq!(*harness.observed.requests.lock().unwrap(), vec![(request, grants.to_vec())]);
        }
        let harness = harness(exception_policy("[::1]", 443), ResolverPlan::addresses(&[]), false);
        let request = tls_request("[::1]:443");
        assert!(harness.gate.perform(&request, &[HostIoCapability::NetworkSend]).is_ok());
        assert_eq!(harness.observed.dns_calls.load(Ordering::SeqCst), 0);
        assert_eq!(harness.observed.requests.lock().unwrap()[0].0, request);
    }

    #[test]
    fn hostname_tls_cannot_use_an_exception_to_skip_address_pinning() {
        let harness = harness(exception_policy("service.example", 443), ResolverPlan::addresses(&["93.184.216.34"]), false);
        let outcome = harness.gate.perform(&tls_request("service.example:443"), &[HostIoCapability::NetworkSend]);
        assert!(matches!(outcome, Err(HostIoError::Denied { reason }) if reason.contains("tls_address_pinning_unavailable")));
        assert_eq!(harness.observed.dns_calls.load(Ordering::SeqCst), 0);
        assert_not_delegated(&harness);
        assert_admission_audit(&harness, "tls_address_pinning_unavailable");
    }

    #[test]
    fn an_inner_failure_is_propagated_without_retrying_a_side_effect() {
        let harness = harness(policy(), ResolverPlan::addresses(&["93.184.216.34", "8.8.8.8"]), true);
        let request = network_requests("service.example:80")[0].clone();
        assert_eq!(harness.gate.perform(&request, &[HostIoCapability::NetworkSend]), Err(HostIoError::Io { detail: "injected inner failure".into() }));
        assert_eq!(harness.observed.dns_calls.load(Ordering::SeqCst), 1);
        assert_eq!(harness.observed.requests.lock().unwrap().len(), 1);
    }

    #[test]
    fn local_effects_and_filesystem_exception_provenance_pass_through() {
        let harness = harness(policy(), ResolverPlan::addresses(&[]), false);
        assert_eq!(harness.gate.filesystem_exception_provenance(), HostIoExceptionProvenance::ProviderInternal);
        for request in [HostIoRequest::FsRead { path: "local.txt".into() }, HostIoRequest::RandomRead { byte_len: 2 }] {
            let grants = [request.required_capability()];
            assert!(harness.gate.perform(&request, &grants).is_ok());
            assert_eq!(harness.observed.requests.lock().unwrap().last().unwrap(), &(request, grants.to_vec()));
        }
        assert_eq!(harness.observed.dns_calls.load(Ordering::SeqCst), 0);
        assert!(harness.gate.audit_records().is_empty());
    }

    #[test]
    fn pinned_hostname_round_trip_reaches_real_socket_with_original_host_header() {
        let root = tempfile::tempdir().expect("sandbox root");
        let inner = SandboxedHostIo::with_root(root.path()).expect("real mechanism");
        let listener = TcpListener::bind("127.0.0.1:0").expect("loopback listener");
        listener.set_nonblocking(true).expect("bounded accept");
        let port = listener.local_addr().unwrap().port();
        let payload = format!("GET /pinned HTTP/1.1\r\nHost: pinned-egress.invalid:{port}\r\nConnection: close\r\n\r\n").into_bytes();
        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK".to_vec();
        let server_response = response.clone();
        let server = std::thread::spawn(move || -> io::Result<Vec<u8>> {
            let deadline = Instant::now() + Duration::from_secs(5);
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
                    Err(error) => return Err(error),
                }
            };
            stream.set_read_timeout(Some(Duration::from_secs(5)))?;
            stream.set_write_timeout(Some(Duration::from_secs(5)))?;
            let mut received = Vec::new();
            while !received.windows(4).any(|window| window == b"\r\n\r\n") {
                let mut buffer = [0; 1024];
                let count = stream.read(&mut buffer)?;
                if count == 0 || received.len() + count > 4096 {
                    return Err(io::Error::other("incomplete or oversized request"));
                }
                received.extend_from_slice(&buffer[..count]);
            }
            stream.write_all(&server_response)?;
            Ok(received)
        });
        let observed = Arc::new(Observed::default());
        // Transport-only fixture: authorize the local listener explicitly by
        // disabling IPv4 CIDR blocking, not by weakening DNS rebinding policy.
        let mut transport_policy = policy();
        transport_policy.blocked_cidrs.clear();
        let gate = SsrfGatedHostIo::with_resolver(
            inner, transport_policy, "pinning-integration",
            ControlledResolver { observed: Arc::clone(&observed), plan: ResolverPlan::addresses(&["127.0.0.1"]) },
        );
        let request = HostIoRequest::NetworkRequest {
            endpoint: format!("pinned-egress.invalid:{port}"), payload: payload.clone(), max_len: 4096, use_tls: false,
        };
        let outcome = gate.perform(&request, &[HostIoCapability::NetworkSend]);
        let received = server.join().expect("listener thread").expect("HTTP exchange");
        assert_eq!(outcome, Ok(HostIoResponse::NetworkRequest { response }));
        assert_eq!(received, payload);
        assert_eq!(observed.dns_calls.load(Ordering::SeqCst), 1);
        let records = gate.audit_records();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].host, "pinned-egress.invalid");
        assert!(!records[0].allowlisted);
    }
}
