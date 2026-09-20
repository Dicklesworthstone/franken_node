//! bd-656a2: product-layer SSRF gate for guest network egress.
//!
//! The sibling engine's `SandboxedHostIo` is the network *mechanism*: it performs
//! raw, capability-checked, byte/time-bounded TCP I/O but performs **no** endpoint
//! policy check. Per the engine-split contract the engine is the mechanism and
//! `franken_node` owns the policy — so this wrapper is that policy. Before any
//! guest `NetworkSend`/`NetworkRecv`/`NetworkRequest` reaches the socket,
//! [`SsrfGatedHostIo`] resolves and checks the endpoint, then pins delegation to
//! one of those exact addresses. Passing the original hostname to the mechanism
//! would allow a second DNS lookup to rebind an approved name to a private IP.
//! Filesystem and entropy effects carry no endpoint and pass straight through.
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
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
#[cfg(feature = "engine")]
use std::sync::Mutex;

#[cfg(feature = "engine")]
use frankenengine_extension_host::host_io::{
    HostIoCapability, HostIoError, HostIoExceptionProvenance, HostIoOutcome, HostIoProvider,
    HostIoRequest,
};

#[cfg(feature = "engine")]
use crate::config::{NetworkPolicyConfig, SsrfEnforcementMode};
#[cfg(feature = "engine")]
use crate::security::network_guard::{Action, Protocol};
#[cfg(feature = "engine")]
use crate::security::ssrf_policy::{
    AllowlistEntry, PolicyReceipt, SsrfAuditRecord, SsrfPolicyTemplate,
};

/// Trusted product-side resolver. Answers are checked in their entirety before
/// any address is delegated; implementations must not perform the guest effect.
/// This seam permits controlled resolvers and deterministic DNS-race tests.
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
        (host, port)
            .to_socket_addrs()
            .map(|addresses| addresses.map(|address| address.ip()).collect())
    }
}

/// Split a connect endpoint without changing the spelling used for policy
/// evaluation. IPv6 addresses must still satisfy the canonical SSRF policy.
#[cfg(feature = "engine")]
fn split_host_port(endpoint: &str) -> Option<(&str, u16)> {
    let (host, port_str) = endpoint.rsplit_once(':')?;
    if host.is_empty() {
        return None;
    }
    let port = port_str.parse::<u16>().ok()?;
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

    fn gate_endpoint(&self, endpoint: &str, use_tls: bool) -> Result<SocketAddr, HostIoError> {
        let Some((host, port)) = split_host_port(endpoint) else {
            return Err(HostIoError::Denied {
                reason: format!("ssrf: cannot parse network endpoint {endpoint:?}"),
            });
        };
        let literal = literal_ip(host);
        if use_tls && literal.is_none() {
            return Err(HostIoError::Denied {
                reason: "ssrf: tls_address_pinning_unavailable: hostname TLS requires separate connect-address and certificate-identity support".to_string(),
            });
        }
        let resolved = match literal {
            Some(address) => vec![address],
            None => self.resolver.resolve(host, port).unwrap_or_default(),
        };
        // Even an explicit hostname exception cannot authorize an absent
        // address or cause the mechanism to fall back to another DNS lookup.
        let selected = resolved.first().copied().ok_or_else(|| HostIoError::Denied {
            reason: format!("ssrf: dns_resolution_required for {host}:{port}"),
        })?;
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
            // request after delegation. Every candidate was checked above.
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
                endpoint: self.gate_endpoint(endpoint, false)?.to_string(),
                payload: payload.clone(),
            },
            HostIoRequest::NetworkRecv { endpoint, max_len } => HostIoRequest::NetworkRecv {
                endpoint: self.gate_endpoint(endpoint, false)?.to_string(),
                max_len: *max_len,
            },
            HostIoRequest::NetworkRequest {
                endpoint,
                payload,
                max_len,
                use_tls,
            } => HostIoRequest::NetworkRequest {
                endpoint: self.gate_endpoint(endpoint, *use_tls)?.to_string(),
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
        // A subsequent effect resolves afresh; the rebound private answer is
        // refused, rather than inheriting the previous request's authorization.
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
            assert!(gate.perform(&request("service.example:80", false),
                &[HostIoCapability::NetworkSend]).is_err());
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
            Answers { calls: Arc::clone(&calls), first: Vec::new() },
        );
        let outcome = gate.perform(&request("service.example:443", true),
            &[HostIoCapability::NetworkSend]);
        assert!(matches!(outcome, Err(HostIoError::Denied { reason })
            if reason.contains("tls_address_pinning_unavailable")));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert!(seen.lock().unwrap().is_empty());
        let numeric = request("93.184.216.34:443", true);
        assert!(gate.perform(&numeric, &[HostIoCapability::NetworkSend]).is_ok());
        assert_eq!(*seen.lock().unwrap(), vec![numeric]);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }
}
