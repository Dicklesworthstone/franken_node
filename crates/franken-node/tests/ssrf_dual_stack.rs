//! Public-API dual-stack policy tests, included in the registered egress target.
//! Public addresses use an observing provider, never Internet access. Actual
//! IPv6 socket/TLS behavior is exercised separately by the local TLS fixtures.
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

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
struct Resolver { state: Arc<Observed>, answers: Vec<IpAddr> }
impl EndpointResolver for Resolver {
    fn resolve(&self, _: &str, _: u16) -> io::Result<Vec<IpAddr>> {
        self.state.dns.fetch_add(1, Ordering::SeqCst);
        Ok(self.answers.clone())
    }
}

#[derive(Debug)]
struct Provider(Arc<Observed>);
impl HostIoProvider for Provider {
    fn name(&self) -> &str { "dual-stack-observer" }
    fn perform(&self, _: &HostIoRequest, _: &[HostIoCapability]) -> HostIoOutcome {
        panic!("unpinned delegation is forbidden");
    }
}
impl PinnedNetworkProvider for Provider {
    fn supports_pinned_tls(&self) -> bool { true }
    fn perform_pinned_network(&self, request: &HostIoRequest, grants: &[HostIoCapability],
        address: SocketAddr, deadline: Instant) -> HostIoOutcome {
        assert!(grants.contains(&request.required_capability()));
        assert!(Instant::now() < deadline);
        self.0.effects.lock().unwrap().push((request.clone(), address));
        Ok(HostIoResponse::NetworkRequest { response: b"observed".to_vec() })
    }
}

fn requests(endpoint: &str) -> [HostIoRequest; 4] {
    [
        HostIoRequest::NetworkSend { endpoint: endpoint.into(), payload: vec![0, 255] },
        HostIoRequest::NetworkRecv { endpoint: endpoint.into(), max_len: 8192 },
        HostIoRequest::NetworkRequest { endpoint: endpoint.into(), payload: vec![0, 255], max_len: 8192, use_tls: false },
        HostIoRequest::NetworkRequest { endpoint: endpoint.into(), payload: vec![0, 255], max_len: 8192, use_tls: true },
    ]
}

fn exercise(policy: SsrfPolicyTemplate, endpoint: &str, answers: &[&str], allowed: bool, dns: usize) {
    for request in requests(endpoint) {
        let state = Arc::new(Observed::default());
        let gate = SsrfGatedHostIo::with_resolver(
            Provider(Arc::clone(&state)), policy.clone(), "dual-stack",
            Resolver { state: Arc::clone(&state), answers: answers.iter().map(|ip| ip.parse().unwrap()).collect() },
        );
        let original = request.clone();
        let result = gate.perform(&request, &[request.required_capability()]);
        assert_eq!(result.is_ok(), allowed, "{endpoint}, {answers:?}: {result:?}");
        assert_eq!(request, original);
        assert_eq!(state.dns.load(Ordering::SeqCst), dns);
        let effects = state.effects.lock().unwrap();
        assert_eq!(effects.len(), usize::from(allowed));
        if allowed {
            assert_eq!(effects[0].0, original, "identity, payload and limits are preserved");
            let expected = if dns == 0 { endpoint.parse().unwrap() }
                else { SocketAddr::new(answers[0].parse().unwrap(), 443) };
            assert_eq!(effects[0].1, expected);
        }
        assert_eq!(gate.audit_records().len(), 1);
        assert_eq!(gate.audit_records()[0].action, if allowed { Action::Allow } else { Action::Deny });
    }
}

fn policy() -> SsrfPolicyTemplate { SsrfPolicyTemplate::default_template("dual-stack".into()) }

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
    for denied in ["::", "::1", "fd00:ec2::254", "fe80::1", "fec0::1", "ff02::1",
        "::ffff:127.0.0.1", "::ffff:169.254.169.254", "64:ff9b::a9fe:a9fe",
        "64:ff9b::a00:1", "64:ff9b:1::1", "2001:db8::1", "2002:7f00:1::1", "3fff::1"] {
        exercise(policy(), &format!("[{denied}]:443"), &[], false, 0);
        exercise(policy(), "service.invalid:443", &[PUBLIC_V6, denied], false, 1);
        exercise(policy(), "service.invalid:443", &[denied, PUBLIC_V4], false, 1);
    }
}

#[test]
fn mapped_and_nat64_public_addresses_inherit_custom_ipv4_restrictions() {
    for address in ["::ffff:8.8.8.8", "64:ff9b::808:808"] {
        exercise(policy(), &format!("[{address}]:443"), &[], true, 0);
        exercise(policy(), "service.invalid:443", &[address], true, 1);
        let mut restricted = policy();
        restricted.blocked_cidrs.push(CidrRange::new([8, 8, 8, 0], 24, "operator-rule"));
        exercise(restricted.clone(), &format!("[{address}]:443"), &[], false, 0);
        exercise(restricted, "service.invalid:443", &[PUBLIC_V6, address], false, 1);
    }
}

#[test]
fn literal_exceptions_normalize_only_valid_numeric_spellings_and_keep_port_scope() {
    let mut allowed = policy();
    allowed.add_allowlist("fd00:0:0:0:0:0:0:1", Some(443), "internal service", "trace", "time").unwrap();
    exercise(allowed.clone(), "[FD00::1]:443", &[], true, 0);
    exercise(allowed.clone(), "[fd00::1]:444", &[], false, 0);
    exercise(allowed.clone(), "[fd00::2]:443", &[], false, 0);
    for invalid in ["[[fd00::1]]:443", "[fd00::1%3]:443", "[fd00::1]:+443", "fd00::1:443"] {
        exercise(allowed.clone(), invalid, &[], false, 0);
    }
}

#[test]
fn hostname_allowlist_never_exempts_private_ipv6_dns_evidence() {
    let mut allowed = policy();
    allowed.add_allowlist("service.invalid", Some(443), "known DNS service", "trace", "time").unwrap();
    for address in ["fd00::1", "::1", "::ffff:127.0.0.1"] {
        exercise(allowed.clone(), "service.invalid:443", &[PUBLIC_V6, address], false, 1);
    }
}

#[test]
fn helper_literal_and_dns_policy_classifications_agree_and_preserve_serialized_templates() {
    let before = policy();
    let serialized = serde_json::to_string(&before).unwrap();
    let mut restored: SsrfPolicyTemplate = serde_json::from_str(&serialized).unwrap();
    assert_eq!(restored.blocked_cidrs.len(), 7);
    for address in [PUBLIC_V6, "2606:4700:4700::1111", "::ffff:8.8.8.8", "64:ff9b::808:808",
        "fd00::1", "::", "2001:db8::1", "64:ff9b::a9fe:a9fe"] {
        let denied = SsrfPolicyTemplate::is_private_ip(address);
        for host in [address.to_string(), format!("[{address}]")] {
            assert_eq!(restored.check_ssrf(&host, 443, Protocol::Http, "trace", "time").is_err(), denied, "{host}");
        }
        assert_eq!(restored.check_ssrf_resolved_ips("service.invalid", &[address.parse().unwrap()],
            443, Protocol::Tcp, "trace", "time").is_err(), denied, "{address}");
    }
}
