//! bd-656a2: product-layer SSRF gate for guest network egress.
//!
//! The sibling engine's `SandboxedHostIo` is the network *mechanism*: it performs
//! raw, capability-checked, byte/time-bounded TCP I/O but performs **no** endpoint
//! policy check. Per the engine-split contract the engine is the mechanism and
//! `franken_node` owns the policy — so this wrapper is that policy. Before any
//! guest `NetworkSend`/`NetworkRecv`/`NetworkRequest` reaches the socket,
//! [`SsrfGatedHostIo`] checks its capability, resolves and checks the endpoint,
//! then pins delegation to one of those exact addresses. Passing the original
//! hostname to the mechanism would allow a second DNS lookup to rebind an
//! approved name to a private IP. Filesystem and entropy effects carry no
//! endpoint and pass straight through.
//!
//! HTTP payloads (including the original Host header) are never rewritten.
//! Hostname-based TLS currently fails closed: the engine uses one endpoint for
//! both connection routing and certificate identity, so replacing that hostname
//! with an IP would break identity verification. Supporting it safely requires
//! an engine API separating the pinned socket address from the TLS server name;
//! re-resolving the hostname or disabling certificate checks is not a fallback.
//! TLS requests whose identity is already an IP literal remain supported.
//!
//! Behavioral coverage also lives in the registered integration suite
//! `crates/franken-node/tests/ssrf_gated_host_io_egress.rs`. The crate-root
//! `franken_node_inline_tests` configuration controls the inline unit-test lane.

#[cfg(feature = "engine")]
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
#[cfg(feature = "engine")]
use std::sync::Mutex;

#[cfg(feature = "engine")]
use frankenengine_extension_host::host_io::{
    HostIoCapability, HostIoError, HostIoExceptionProvenance, HostIoOutcome, HostIoProvider,
    HostIoRequest,
};

#[cfg(feature = "engine")]
use crate::capacity_defaults::aliases::MAX_AUDIT_LOG_ENTRIES;
#[cfg(feature = "engine")]
use crate::config::{NetworkPolicyConfig, SsrfEnforcementMode};
#[cfg(feature = "engine")]
use crate::security::network_guard::{Action, Protocol};
#[cfg(feature = "engine")]
use crate::security::ssrf_policy::{
    AllowlistEntry, PolicyReceipt, SsrfAuditRecord, SsrfPolicyTemplate,
};

// A 253-byte DNS name, optional trailing dot, colon, and five port digits.
#[cfg(feature = "engine")]
const MAX_ENDPOINT_LEN: usize = 260;
#[cfg(feature = "engine")]
const MAX_RESOLVED_ADDRESSES: usize = 64;

/// Trusted product-side resolver. Answers are checked in their entirety (unless
/// the host has an explicit policy exception) before any address is delegated.
/// Implementations must not perform the guest effect. This seam permits
/// controlled resolvers and deterministic DNS-race tests.
#[cfg(feature = "engine")]
pub trait EndpointResolver: core::fmt::Debug + Send + Sync {
    fn resolve(&self, host: &str, port: u16) -> std::io::Result<Vec<IpAddr>>;
}

/// System DNS resolution. This synchronous resolver has no interruptible DNS
/// deadline; callers needing one must supply a suitably bounded resolver.
#[cfg(feature = "engine")]
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemEndpointResolver;

#[cfg(feature = "engine")]
impl EndpointResolver for SystemEndpointResolver {
    fn resolve(&self, host: &str, port: u16) -> std::io::Result<Vec<IpAddr>> {
        (host, port).to_socket_addrs().map(|addresses| {
            // Retain an overflow sentinel: silently truncating would hide a
            // denied answer beyond the prefix inspected by the policy.
            addresses
                .take(MAX_RESOLVED_ADDRESSES + 1)
                .map(|address| address.ip())
                .collect()
        })
    }
}

/// Parse only unambiguous socket endpoints before invoking a resolver. Preserve
/// hostname spelling for receipts; IPv6 literals require brackets. DNS names
/// must be ASCII (international names must already be encoded as A-labels).
#[cfg(feature = "engine")]
fn split_host_port(endpoint: &str) -> Option<(&str, u16)> {
    if endpoint.len() > MAX_ENDPOINT_LEN || !endpoint.is_ascii() {
        return None;
    }
    let (host, port_str) = endpoint.rsplit_once(':')?;
    if host.is_empty()
        || port_str.is_empty()
        || port_str.len() > 5
        || !port_str.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    let port = port_str.parse::<u16>().ok()?;
    if port == 0 {
        return None;
    }
    if host.starts_with('[') {
        host.strip_prefix('[')?
            .strip_suffix(']')?
            .parse::<Ipv6Addr>()
            .ok()?;
    } else {
        let canonical = host.strip_suffix('.').unwrap_or(host);
        if canonical.is_empty() || canonical.len() > 253 {
            return None;
        }
        for label in canonical.split('.') {
            let bytes = label.as_bytes();
            if bytes.is_empty()
                || bytes.len() > 63
                || !bytes[0].is_ascii_alphanumeric()
                || !bytes[bytes.len() - 1].is_ascii_alphanumeric()
                || !bytes
                    .iter()
                    .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
            {
                return None;
            }
        }
        // Prevent libc-style integer, octal, hex, shortened, or trailing-dot
        // IPv4 aliases from being treated as DNS names before policy admission.
        let numeric_alias = canonical.split('.').all(|label| {
            label.bytes().all(|byte| byte.is_ascii_digit())
                || label
                    .strip_prefix("0x")
                    .or_else(|| label.strip_prefix("0X"))
                    .is_some_and(|digits| {
                        !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_hexdigit())
                    })
        });
        if numeric_alias && host.parse::<Ipv4Addr>().is_err() {
            return None;
        }
    }
    Some((host, port))
}

#[cfg(feature = "engine")]
fn literal_ip(host: &str) -> Option<IpAddr> {
    host.strip_prefix('[')
        .and_then(|address| address.strip_suffix(']'))
        .unwrap_or(host)
        .parse()
        .ok()
}

/// Build the run's SSRF policy from `[security.network_policy]`. Enforcement
/// remains fail-safe: Monitor is treated as Block; only explicit opt-out empties
/// the IPv4 deny-list. The canonical policy still controls unsupported IP forms.
#[cfg(feature = "engine")]
fn build_ssrf_template(policy: &NetworkPolicyConfig, trace_id: &str) -> SsrfPolicyTemplate {
    let connector_id = format!("run:{trace_id}");
    let enforce = policy.ssrf_protection_enabled
        && !matches!(policy.ssrf_enforcement, SsrfEnforcementMode::None);
    let mut template = if enforce {
        SsrfPolicyTemplate::default_template(connector_id.clone())
    } else {
        SsrfPolicyTemplate {
            connector_id: connector_id.clone(),
            blocked_cidrs: Vec::new(),
            allowlist: Vec::new(),
            audit_log: Vec::new(),
        }
    };
    let issued_at = chrono::Utc::now().to_rfc3339();
    for entry in &policy.allowlist {
        template.allowlist.push(AllowlistEntry {
            host: entry.host.clone(),
            port: entry.port,
            reason: entry.reason.clone(),
            receipt: PolicyReceipt {
                receipt_id: format!("cfg-allow:{}", entry.host),
                connector_id: connector_id.clone(),
                host: entry.host.clone(),
                issued_at: issued_at.clone(),
                reason: entry.reason.clone(),
                trace_id: trace_id.to_string(),
            },
        });
    }
    template
}

/// A host-I/O decorator binding every network authorization to its connect IP.
#[cfg(feature = "engine")]
#[derive(Debug)]
pub struct SsrfGatedHostIo<P: HostIoProvider, R: EndpointResolver = SystemEndpointResolver> {
    inner: P,
    policy: Mutex<SsrfPolicyTemplate>,
    trace_id: String,
    resolver: R,
}

#[cfg(feature = "engine")]
impl<P: HostIoProvider> SsrfGatedHostIo<P> {
    /// Wrap `inner` with the default-deny SSRF policy.
    pub fn new(inner: P, trace_id: impl Into<String>) -> Self {
        let trace_id = trace_id.into();
        let policy = SsrfPolicyTemplate::default_template(format!("run:{trace_id}"));
        Self::with_policy(inner, policy, trace_id)
    }

    /// Wrap `inner` with an explicit policy and the system resolver.
    pub fn with_policy(inner: P, policy: SsrfPolicyTemplate, trace_id: impl Into<String>) -> Self {
        Self::with_resolver(inner, policy, trace_id, SystemEndpointResolver)
    }

    /// Apply the run's configured CIDR exceptions and enforcement mode. Neither
    /// an allowlist entry nor disabling CIDR enforcement disables address
    /// pinning or permits hostname TLS through an unpinned transport.
    pub fn from_network_policy(
        inner: P,
        policy: &NetworkPolicyConfig,
        trace_id: impl Into<String>,
    ) -> Self {
        let trace_id = trace_id.into();
        let template = build_ssrf_template(policy, &trace_id);
        Self::with_policy(inner, template, trace_id)
    }
}

#[cfg(feature = "engine")]
impl<P: HostIoProvider, R: EndpointResolver> SsrfGatedHostIo<P, R> {
    /// Install a trusted resolver while retaining the same policy checks and
    /// pinned delegation as the production system-resolver path.
    pub fn with_resolver(
        inner: P,
        policy: SsrfPolicyTemplate,
        trace_id: impl Into<String>,
        resolver: R,
    ) -> Self {
        Self {
            inner,
            policy: Mutex::new(policy),
            trace_id: trace_id.into(),
            resolver,
        }
    }

    /// Snapshot the accumulated endpoint policy decisions for the evidence ledger.
    #[must_use]
    pub fn audit_records(&self) -> Vec<SsrfAuditRecord> {
        self.policy
            .lock()
            .map(|policy| policy.audit_log.clone())
            .unwrap_or_default()
    }

    /// Admission failures happen before the canonical CIDR check. Retain them
    /// in the same bounded ledger rather than silently losing denied effects.
    /// A poisoned ledger never makes the caller's rejection permissive.
    fn record_denial(&self, host: &str, port: u16, code: &'static str) {
        if let Ok(mut policy) = self.policy.lock() {
            let record = SsrfAuditRecord {
                connector_id: policy.connector_id.clone(),
                timestamp: chrono::Utc::now().to_rfc3339(),
                host: host.chars().take(MAX_ENDPOINT_LEN).collect(),
                port,
                action: Action::Deny,
                cidr_matched: Some(code.to_string()),
                allowlisted: false,
                trace_id: self.trace_id.clone(),
            };
            crate::push_bounded(&mut policy.audit_log, record, MAX_AUDIT_LOG_ENTRIES);
        }
    }

    fn deny(&self, host: &str, port: u16, code: &'static str) -> HostIoError {
        self.record_denial(host, port, code);
        let bounded_host: String = host.chars().take(MAX_ENDPOINT_LEN).collect();
        HostIoError::Denied {
            reason: format!("ssrf: {code} for {bounded_host:?}:{port}"),
        }
    }

    fn gate_endpoint(
        &self,
        request: &HostIoRequest,
        endpoint: &str,
        use_tls: bool,
        granted: &[HostIoCapability],
    ) -> Result<SocketAddr, HostIoError> {
        // DNS is itself a network effect: an unprivileged guest must not even
        // reach the resolver. Use the engine's authoritative capability mapping.
        let capability = request.required_capability();
        if !granted.contains(&capability) {
            let (host, port) = split_host_port(endpoint).unwrap_or((endpoint, 0));
            self.record_denial(host, port, "capability_missing");
            return Err(HostIoError::CapabilityMissing { capability });
        }
        let Some((host, port)) = split_host_port(endpoint) else {
            return Err(self.deny(endpoint, 0, "invalid_endpoint"));
        };
        let literal = literal_ip(host);
        if use_tls && literal.is_none() {
            return Err(self.deny(host, port, "tls_address_pinning_unavailable"));
        }
        let resolved = match literal {
            Some(address) => vec![address],
            None => self
                .resolver
                .resolve(host, port)
                .map_err(|_| self.deny(host, port, "dns_resolution_failed"))?,
        };
        if resolved.len() > MAX_RESOLVED_ADDRESSES {
            return Err(self.deny(host, port, "dns_answer_limit_exceeded"));
        }
        // Even an explicit hostname exception cannot authorize an absent
        // address or cause the mechanism to fall back to another DNS lookup.
        let selected = resolved
            .first()
            .copied()
            .ok_or_else(|| self.deny(host, port, "dns_resolution_required"))?;
        let timestamp = chrono::Utc::now().to_rfc3339();
        let mut policy = self.policy.lock().map_err(|_| HostIoError::Denied {
            reason: "ssrf: policy lock poisoned".to_string(),
        })?;
        match policy.check_ssrf_resolved_ips(
            host,
            &resolved,
            port,
            Protocol::Http,
            &self.trace_id,
            &timestamp,
        ) {
            // Keep resolver order, but do not retry a potentially side-effecting
            // request after delegation. Every non-exempt candidate was checked.
            Ok(Action::Allow) => Ok(SocketAddr::new(selected, port)),
            Ok(Action::Deny) | Err(_) => Err(HostIoError::Denied {
                reason: format!("ssrf: egress to {host}:{port} blocked by policy"),
            }),
        }
    }
}

#[cfg(feature = "engine")]
impl<P: HostIoProvider, R: EndpointResolver> HostIoProvider for SsrfGatedHostIo<P, R> {
    fn name(&self) -> &str {
        "ssrf-gated-host-io"
    }

    fn filesystem_exception_provenance(&self) -> HostIoExceptionProvenance {
        self.inner.filesystem_exception_provenance()
    }

    fn perform(&self, request: &HostIoRequest, granted: &[HostIoCapability]) -> HostIoOutcome {
        // This match is exhaustive so a new network request cannot silently
        // bypass admission. Only the connect endpoint changes, never wire bytes,
        // reply limits, TLS mode, or the original transcript request.
        let pinned = match request {
            HostIoRequest::NetworkSend { endpoint, payload } => HostIoRequest::NetworkSend {
                endpoint: self
                    .gate_endpoint(request, endpoint, false, granted)?
                    .to_string(),
                payload: payload.clone(),
            },
            HostIoRequest::NetworkRecv { endpoint, max_len } => HostIoRequest::NetworkRecv {
                endpoint: self
                    .gate_endpoint(request, endpoint, false, granted)?
                    .to_string(),
                max_len: *max_len,
            },
            HostIoRequest::NetworkRequest {
                endpoint,
                payload,
                max_len,
                use_tls,
            } => HostIoRequest::NetworkRequest {
                endpoint: self
                    .gate_endpoint(request, endpoint, *use_tls, granted)?
                    .to_string(),
                payload: payload.clone(),
                max_len: *max_len,
                use_tls: *use_tls,
            },
            HostIoRequest::FsRead { .. }
            | HostIoRequest::FsWrite { .. }
            | HostIoRequest::FsMeta { .. }
            | HostIoRequest::RandomRead { .. } => return self.inner.perform(request, granted),
        };
        self.inner.perform(&pinned, granted)
    }
}

#[cfg(all(test, feature = "engine"))]
mod tests {
    use super::*;
    use frankenengine_extension_host::host_io::HostIoResponse;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Debug)]
    struct RecordingInner(Arc<Mutex<Vec<HostIoRequest>>>);

    impl HostIoProvider for RecordingInner {
        fn name(&self) -> &str {
            "pinning-test"
        }

        fn perform(&self, request: &HostIoRequest, _: &[HostIoCapability]) -> HostIoOutcome {
            self.0.lock().unwrap().push(request.clone());
            Ok(HostIoResponse::NetworkSend { bytes_sent: 0 })
        }
    }

    #[derive(Debug)]
    struct Answers {
        calls: Arc<AtomicUsize>,
        first: Vec<IpAddr>,
    }

    impl EndpointResolver for Answers {
        fn resolve(&self, _: &str, _: u16) -> std::io::Result<Vec<IpAddr>> {
            if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
                Ok(self.first.clone())
            } else {
                Ok(vec!["127.0.0.1".parse().unwrap()])
            }
        }
    }

    fn request(endpoint: &str, use_tls: bool) -> HostIoRequest {
        HostIoRequest::NetworkRequest {
            endpoint: endpoint.into(),
            payload: b"GET / HTTP/1.1\r\nHost: service.example\r\n\r\n".to_vec(),
            max_len: 4096,
            use_tls,
        }
    }

    #[test]
    fn hostname_is_resolved_once_and_only_the_checked_address_is_delegated() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let calls = Arc::new(AtomicUsize::new(0));
        let gate = SsrfGatedHostIo::with_resolver(
            RecordingInner(Arc::clone(&seen)),
            SsrfPolicyTemplate::default_template("pinning".into()),
            "pinning",
            Answers {
                calls: Arc::clone(&calls),
                first: vec!["93.184.216.34".parse().unwrap()],
            },
        );
        let original = request("service.example:80", false);
        let before = original.clone();
        assert!(gate.perform(&original, &[HostIoCapability::NetworkSend]).is_ok());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(original, before);
        assert_eq!(*seen.lock().unwrap(), vec![request("93.184.216.34:80", false)]);
        assert_eq!(gate.audit_records()[0].host, "service.example");
        assert!(gate.perform(&original, &[HostIoCapability::NetworkSend]).is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(seen.lock().unwrap().len(), 1);
    }

    #[test]
    fn every_resolved_address_is_checked_before_delegating() {
        for addresses in [
            vec!["93.184.216.34", "127.0.0.1"],
            vec!["169.254.169.254", "93.184.216.34"],
            vec![],
        ] {
            let seen = Arc::new(Mutex::new(Vec::new()));
            let gate = SsrfGatedHostIo::with_resolver(
                RecordingInner(Arc::clone(&seen)),
                SsrfPolicyTemplate::default_template("mixed".into()),
                "mixed",
                Answers {
                    calls: Arc::new(AtomicUsize::new(0)),
                    first: addresses.iter().map(|ip| ip.parse().unwrap()).collect(),
                },
            );
            assert!(
                gate.perform(
                    &request("service.example:80", false),
                    &[HostIoCapability::NetworkSend],
                )
                .is_err()
            );
            assert!(seen.lock().unwrap().is_empty());
        }
    }

    #[test]
    fn hostname_tls_fails_closed_without_changing_certificate_identity() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let calls = Arc::new(AtomicUsize::new(0));
        let gate = SsrfGatedHostIo::with_resolver(
            RecordingInner(Arc::clone(&seen)),
            SsrfPolicyTemplate::default_template("tls".into()),
            "tls",
            Answers {
                calls: Arc::clone(&calls),
                first: Vec::new(),
            },
        );
        let outcome = gate.perform(
            &request("service.example:443", true),
            &[HostIoCapability::NetworkSend],
        );
        assert!(matches!(outcome, Err(HostIoError::Denied { reason })
            if reason.contains("tls_address_pinning_unavailable")));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert!(seen.lock().unwrap().is_empty());
        let numeric = request("93.184.216.34:443", true);
        assert!(gate.perform(&numeric, &[HostIoCapability::NetworkSend]).is_ok());
        assert_eq!(*seen.lock().unwrap(), vec![numeric]);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn missing_capability_never_reaches_dns_or_the_inner_provider() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let calls = Arc::new(AtomicUsize::new(0));
        let gate = SsrfGatedHostIo::with_resolver(
            RecordingInner(Arc::clone(&seen)),
            SsrfPolicyTemplate::default_template("capability".into()),
            "capability",
            Answers {
                calls: Arc::clone(&calls),
                first: vec!["93.184.216.34".parse().unwrap()],
            },
        );
        assert!(matches!(
            gate.perform(&request("service.example:80", false), &[]),
            Err(HostIoError::CapabilityMissing {
                capability: HostIoCapability::NetworkSend,
            })
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert!(seen.lock().unwrap().is_empty());
        assert_eq!(gate.audit_records()[0].action, Action::Deny);
    }

    #[test]
    fn socket_endpoint_parser_rejects_ambiguous_or_non_socket_inputs() {
        for endpoint in [
            "", "service.example", ":80", "host:0", "host:+80", "host:65536",
            "http://host:80", "user@host:80", "host/path:80", "host\\path:80",
            " host:80", "host :80", "host\r\n:80", "host\0:80", "a..b:80",
            "host..:80", "[127.0.0.1]:80", "::1:80", "[::1:80", "::1]:80",
            "[fe80::1%eth0]:80", "127.1:80", "2130706433:80", "0x7f000001:80",
            "0177.0.0.1:80", "127.0.0.1.:80", "-host:80", "host-:80",
        ] {
            assert!(split_host_port(endpoint).is_none(), "{endpoint:?}");
        }
        for endpoint in [
            "service.example:80", "Service.Example.:443", "localhost:1",
            "93.184.216.34:65535", "[::1]:443", "[2001:4860:4860::8888]:53",
        ] {
            assert!(split_host_port(endpoint).is_some(), "{endpoint:?}");
        }
    }
}
