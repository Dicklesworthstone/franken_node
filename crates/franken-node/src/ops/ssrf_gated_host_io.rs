//! Product-layer SSRF admission and address-pinned guest network execution.
//!
//! Policy stays in franken_node; DNS/socket/TLS mechanisms stay in the engine.
//! Network effects are capability-checked before DNS and resolved answers are
//! checked against policy before selecting a connect address. Configured native
//! execution passes the complete approved set separately from the request: HTTPS
//! authenticates the original hostname, never the routing IP. The native
//! provider retains its roots, byte limits and one deadline spanning DNS,
//! connection, handshake and response. Filesystem and entropy pass through.
//! Production DNS uses that same provider's revocation scope and execution
//! control. One operation-local latch spans admission and pinned transport;
//! cancellation never revokes a shared provider or creates a DNS worker here.

#[cfg(feature = "engine")]
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
#[cfg(feature = "engine")]
use std::sync::{Arc, Mutex};
#[cfg(feature = "engine")]
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(feature = "engine")]
use std::time::{Duration, Instant};

#[cfg(feature = "engine")]
use frankenengine_extension_host::host_io::{
    HostIoCapability, HostIoControl, HostIoError, HostIoExceptionProvenance, HostIoOutcome,
    HostIoProvider, HostIoRequest, SANDBOXED_HOST_IO_NETWORK_TIMEOUT, SandboxedHostIo,
    UnrestrictedHostIoControl,
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

#[cfg(feature = "engine")]
const MAX_ENDPOINT_LEN: usize = 260;
#[cfg(feature = "engine")]
const MAX_RESOLVED_ADDRESSES: usize = 64;

/// Leads the denial reason of every effect the SSRF policy itself refused
/// (a resolved address in a denied CIDR, metadata endpoints, ...), as opposed
/// to the gate's operational refusals (DNS failure, deadline, missing TLS
/// pinning). The run path counts ledger denials carrying it as SSRF violations
/// for automatic dependency quarantine, so the two must stay one string.
pub const SSRF_EGRESS_POLICY_BLOCK_MARKER: &str = "ssrf: egress to ";

/// Trusted resolver: returns address evidence, never performs the guest effect.
/// The default adapter checks before and after a synchronous custom resolution
/// but cannot interrupt an arbitrary implementation. Custom blocking resolvers
/// must override `resolve_until` to bound caller waiting. SystemEndpointResolver
/// uses the engine's bounded shared worker admission, not the default adapter.
#[cfg(feature = "engine")]
pub trait EndpointResolver: core::fmt::Debug + Send + Sync {
    fn resolve(&self, host: &str, port: u16) -> std::io::Result<Vec<IpAddr>>;

    fn resolve_until(
        &self,
        host: &str,
        port: u16,
        deadline: Instant,
    ) -> std::io::Result<Vec<IpAddr>> {
        ensure_time_remaining(deadline)?;
        let result = self.resolve(host, port)?;
        ensure_time_remaining(deadline)?;
        Ok(result)
    }

    /// Cooperatively cancellable lookup. The default brackets the existing
    /// resolver but cannot interrupt its implementation. Blocking custom
    /// resolvers must override this method and poll `control` during waits.
    /// The production constructor instead selects provider-owned native DNS.
    fn resolve_controlled_until(
        &self,
        host: &str,
        port: u16,
        deadline: Instant,
        control: Arc<dyn HostIoControl>,
    ) -> std::io::Result<Vec<IpAddr>> {
        check_control_io(control.as_ref())?;
        let result = self.resolve_until(host, port, deadline);
        check_control_io(control.as_ref())?;
        ensure_time_remaining(deadline)?;
        result
    }
}

#[cfg(feature = "engine")]
const NETWORK_EXECUTION_CANCELLED: &str = "HOST_IO_EXECUTION_CANCELLED";

#[cfg(feature = "engine")]
fn cancelled() -> HostIoError {
    HostIoError::Denied {
        reason: NETWORK_EXECUTION_CANCELLED.into(),
    }
}

#[cfg(feature = "engine")]
fn check_control_io(control: &dyn HostIoControl) -> std::io::Result<()> {
    control.checkpoint().map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::PermissionDenied, NETWORK_EXECUTION_CANCELLED)
    })
}

/// The engine's DNS and pinned-I/O APIs each own their inner control latch.
/// Keep an outer latch across BOTH calls, including product-policy admission,
/// so a resettable signal cannot revive a refusal observed in the DNS phase.
/// Only this request retains it; a subsequent request gets a fresh instance.
#[cfg(feature = "engine")]
#[derive(Debug)]
struct NetworkOperationControl {
    source: Arc<dyn HostIoControl>,
    refused: AtomicBool,
}

#[cfg(feature = "engine")]
impl HostIoControl for NetworkOperationControl {
    fn checkpoint(&self) -> Result<(), HostIoError> {
        if !self.refused.load(Ordering::Acquire) && self.source.checkpoint().is_err() {
            self.refused.store(true, Ordering::Release);
        }
        if self.refused.load(Ordering::Acquire) {
            Err(cancelled())
        } else {
            Ok(())
        }
    }
}

#[cfg(feature = "engine")]
fn ensure_time_remaining(deadline: Instant) -> std::io::Result<()> {
    if Instant::now() >= deadline {
        return Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "network effect deadline exceeded",
        ));
    }
    Ok(())
}

/// System DNS uses the process-wide bounded engine resolver. Timed-out lookups
/// retain their slots until libc returns. No DNS worker may connect.
#[cfg(feature = "engine")]
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemEndpointResolver;

#[cfg(feature = "engine")]
impl EndpointResolver for SystemEndpointResolver {
    fn resolve(&self, host: &str, port: u16) -> std::io::Result<Vec<IpAddr>> {
        let deadline = Instant::now()
            .checked_add(SANDBOXED_HOST_IO_NETWORK_TIMEOUT)
            .ok_or_else(|| std::io::Error::other("network deadline overflow"))?;
        self.resolve_until(host, port, deadline)
    }

    fn resolve_until(
        &self,
        host: &str,
        port: u16,
        deadline: Instant,
    ) -> std::io::Result<Vec<IpAddr>> {
        if host.len() > MAX_ENDPOINT_LEN {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "hostname too long",
            ));
        }
        let endpoint = format!("{host}:{port}");
        if split_host_port(&endpoint).is_none() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "invalid endpoint",
            ));
        }
        SandboxedHostIo::resolve_network_endpoint_until(&endpoint, deadline)
            .map(|addresses| addresses.into_iter().map(|address| address.ip()).collect())
    }
}

/// Explicit host contract for preserving a product-authorized connect address.
/// Implementations must never resolve the original endpoint again or restart
/// the supplied deadline. TLS support is opt-in, not inferred from a name.
///
/// The default delegates a numeric endpoint and rejects hostname TLS rather
/// than changing certificate identity. Custom blocking providers must override
/// execution to enforce the deadline during their own I/O, not merely before
/// and after it. SandboxedHostIo supplies that stronger implementation.
#[cfg(feature = "engine")]
pub trait PinnedNetworkProvider: HostIoProvider {
    fn network_timeout(&self) -> Duration {
        SANDBOXED_HOST_IO_NETWORK_TIMEOUT
    }

    fn supports_pinned_tls(&self) -> bool {
        false
    }

    /// DNS evidence under this provider's control, before product IP approval.
    /// This MUST NOT connect or perform the request. The default has the same
    /// pre/post cancellation limitation as a custom EndpointResolver; native
    /// providers override it with interruptible waiting on bounded engine DNS.
    fn resolve_pinned_endpoint_until(
        &self,
        host: &str,
        port: u16,
        deadline: Instant,
        control: Arc<dyn HostIoControl>,
    ) -> std::io::Result<Vec<IpAddr>> {
        SystemEndpointResolver.resolve_controlled_until(host, port, deadline, control)
    }

    fn perform_pinned_network(
        &self,
        request: &HostIoRequest,
        granted: &[HostIoCapability],
        destination: SocketAddr,
        deadline: Instant,
    ) -> HostIoOutcome {
        perform_numeric_network(self, request, granted, destination, deadline)
    }

    /// A provider may try another approved address only while establishing TCP,
    /// before TLS or application I/O. The default deliberately calls the
    /// singleton method once: an arbitrary provider's error does not prove that
    /// its side effect never happened. Native execution overrides this method
    /// with the engine's owned connection selection and shared deadline.
    fn perform_pinned_network_candidates(
        &self,
        request: &HostIoRequest,
        granted: &[HostIoCapability],
        destinations: &[SocketAddr],
        deadline: Instant,
    ) -> HostIoOutcome {
        let first = validate_pinned_candidates(request, granted, destinations, deadline)?;
        self.perform_pinned_network(request, granted, first, deadline)
    }

    /// The same execution under the engine's operation-local supervisor. The
    /// default keeps the numeric-only contract and forwards the control to the
    /// wrapped provider's `perform_controlled`, never dropping it.
    fn perform_pinned_network_candidates_controlled(
        &self,
        request: &HostIoRequest,
        granted: &[HostIoCapability],
        destinations: &[SocketAddr],
        deadline: Instant,
        control: Arc<dyn HostIoControl>,
    ) -> HostIoOutcome {
        let first = validate_pinned_candidates(request, granted, destinations, deadline)?;
        perform_numeric_network_with(request, granted, first, deadline, |pinned| {
            self.perform_controlled(pinned, granted, control)
        })
    }
}

#[cfg(feature = "engine")]
impl PinnedNetworkProvider for SandboxedHostIo {
    fn network_timeout(&self) -> Duration {
        SandboxedHostIo::network_timeout(self)
    }

    fn supports_pinned_tls(&self) -> bool {
        true
    }

    fn resolve_pinned_endpoint_until(
        &self,
        host: &str,
        port: u16,
        deadline: Instant,
        control: Arc<dyn HostIoControl>,
    ) -> std::io::Result<Vec<IpAddr>> {
        let endpoint = format!("{host}:{port}");
        if split_host_port(&endpoint).is_none() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "invalid endpoint",
            ));
        }
        SandboxedHostIo::resolve_network_endpoint_controlled_until(
            self, &endpoint, deadline, control,
        )
        .map(|addresses| addresses.into_iter().map(|address| address.ip()).collect())
    }

    fn perform_pinned_network(
        &self,
        request: &HostIoRequest,
        granted: &[HostIoCapability],
        destination: SocketAddr,
        deadline: Instant,
    ) -> HostIoOutcome {
        SandboxedHostIo::perform_pinned_network(self, request, granted, destination, deadline)
    }

    fn perform_pinned_network_candidates(
        &self,
        request: &HostIoRequest,
        granted: &[HostIoCapability],
        destinations: &[SocketAddr],
        deadline: Instant,
    ) -> HostIoOutcome {
        SandboxedHostIo::perform_pinned_network_candidates(
            self,
            request,
            granted,
            destinations,
            deadline,
        )
    }

    fn perform_pinned_network_candidates_controlled(
        &self,
        request: &HostIoRequest,
        granted: &[HostIoCapability],
        destinations: &[SocketAddr],
        deadline: Instant,
        control: Arc<dyn HostIoControl>,
    ) -> HostIoOutcome {
        SandboxedHostIo::perform_pinned_network_candidates_controlled(
            self,
            request,
            granted,
            destinations,
            deadline,
            control,
        )
    }
}

#[cfg(feature = "engine")]
fn validate_pinned_candidates(
    request: &HostIoRequest,
    granted: &[HostIoCapability],
    destinations: &[SocketAddr],
    deadline: Instant,
) -> Result<SocketAddr, HostIoError> {
    let capability = request.required_capability();
    if !granted.contains(&capability) {
        return Err(HostIoError::CapabilityMissing { capability });
    }
    ensure_time_remaining(deadline).map_err(|error| HostIoError::Io {
        detail: error.to_string(),
    })?;
    let invalid = || HostIoError::Denied {
        reason: "ssrf: invalid pinned destination set".to_string(),
    };
    if destinations.is_empty() || destinations.len() > MAX_RESOLVED_ADDRESSES {
        return Err(invalid());
    }
    let endpoint = match request {
        HostIoRequest::NetworkSend { endpoint, .. }
        | HostIoRequest::NetworkRecv { endpoint, .. }
        | HostIoRequest::NetworkRequest { endpoint, .. } => endpoint,
        _ => return Err(invalid()),
    };
    let (host, port) = split_host_port(endpoint).ok_or_else(invalid)?;
    let literal = literal_ip(host);
    if destinations
        .iter()
        .any(|address| address.port() != port || literal.is_some_and(|ip| ip != address.ip()))
    {
        return Err(invalid());
    }
    Ok(destinations[0])
}

#[cfg(feature = "engine")]
fn perform_numeric_network_candidates<P: HostIoProvider + ?Sized>(
    provider: &P,
    request: &HostIoRequest,
    granted: &[HostIoCapability],
    destinations: &[SocketAddr],
    deadline: Instant,
) -> HostIoOutcome {
    let first = validate_pinned_candidates(request, granted, destinations, deadline)?;
    perform_numeric_network(provider, request, granted, first, deadline)
}

#[cfg(feature = "engine")]
fn perform_numeric_network_candidates_controlled<P: HostIoProvider + ?Sized>(
    provider: &P,
    request: &HostIoRequest,
    granted: &[HostIoCapability],
    destinations: &[SocketAddr],
    deadline: Instant,
    control: Arc<dyn HostIoControl>,
) -> HostIoOutcome {
    let first = validate_pinned_candidates(request, granted, destinations, deadline)?;
    perform_numeric_network_with(request, granted, first, deadline, |pinned| {
        provider.perform_controlled(pinned, granted, control)
    })
}

/// Numeric-only delegation is safe for an arbitrary HostIoProvider: a DNS
/// hostname is never passed downstream, and TLS identities are never rewritten.
#[cfg(feature = "engine")]
fn perform_numeric_network<P: HostIoProvider + ?Sized>(
    provider: &P,
    request: &HostIoRequest,
    granted: &[HostIoCapability],
    destination: SocketAddr,
    deadline: Instant,
) -> HostIoOutcome {
    perform_numeric_network_with(request, granted, destination, deadline, |pinned| {
        provider.perform(pinned, granted)
    })
}

/// Rewrite `request` to its numeric, policy-approved `destination` and hand it
/// to `execute` (the wrapped provider's plain or supervised entry).
#[cfg(feature = "engine")]
fn perform_numeric_network_with(
    request: &HostIoRequest,
    granted: &[HostIoCapability],
    destination: SocketAddr,
    deadline: Instant,
    execute: impl FnOnce(&HostIoRequest) -> HostIoOutcome,
) -> HostIoOutcome {
    let capability = request.required_capability();
    if !granted.contains(&capability) {
        return Err(HostIoError::CapabilityMissing { capability });
    }
    let timeout = |error: std::io::Error| HostIoError::Io {
        detail: error.to_string(),
    };
    ensure_time_remaining(deadline).map_err(timeout)?;
    let original = match request {
        HostIoRequest::NetworkSend { endpoint, .. }
        | HostIoRequest::NetworkRecv { endpoint, .. }
        | HostIoRequest::NetworkRequest { endpoint, .. } => endpoint,
        _ => {
            return Err(HostIoError::Denied {
                reason: "ssrf: pinned transport requires a network request".to_string(),
            });
        }
    };
    let invalid = || HostIoError::Denied {
        reason: "ssrf: pinned transport authority mismatch".to_string(),
    };
    let (host, port) = split_host_port(original).ok_or_else(invalid)?;
    if port != destination.port()
        || literal_ip(host).is_some_and(|address| address != destination.ip())
    {
        return Err(invalid());
    }
    let endpoint = destination.to_string();
    let pinned = match request {
        HostIoRequest::NetworkSend { payload, .. } => HostIoRequest::NetworkSend {
            endpoint,
            payload: payload.clone(),
        },
        HostIoRequest::NetworkRecv { max_len, .. } => HostIoRequest::NetworkRecv {
            endpoint,
            max_len: *max_len,
        },
        HostIoRequest::NetworkRequest {
            payload,
            max_len,
            use_tls,
            ..
        } => {
            if *use_tls && literal_ip(host).is_none() {
                return Err(HostIoError::Denied {
                    reason: "ssrf: tls_address_pinning_unavailable".to_string(),
                });
            }
            HostIoRequest::NetworkRequest {
                endpoint,
                payload: payload.clone(),
                max_len: *max_len,
                use_tls: *use_tls,
            }
        }
        _ => unreachable!("non-network requests were rejected before delegation"),
    };
    let outcome = execute(&pinned);
    ensure_time_remaining(deadline).map_err(timeout)?;
    outcome
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

#[cfg(feature = "engine")]
type PinnedExecutor<P> =
    fn(&P, &HostIoRequest, &[HostIoCapability], &[SocketAddr], Instant) -> HostIoOutcome;

#[cfg(feature = "engine")]
type PinnedControlledExecutor<P> = fn(
    &P,
    &HostIoRequest,
    &[HostIoCapability],
    &[SocketAddr],
    Instant,
    Arc<dyn HostIoControl>,
) -> HostIoOutcome;

#[cfg(feature = "engine")]
type EndpointLookup<P, R> = fn(
    &P,
    &R,
    &str,
    u16,
    Instant,
    Arc<dyn HostIoControl>,
) -> std::io::Result<Vec<IpAddr>>;

/// A host-I/O decorator binding every network authorization to its connect IP.
/// The transport contract is chosen once at construction, never from a provider
/// name or guest input. Function pointers preserve generic non-network wrappers
/// without claiming that arbitrary providers implement hostname TLS.
#[cfg(feature = "engine")]
#[derive(Debug)]
pub struct SsrfGatedHostIo<P: HostIoProvider, R: EndpointResolver = SystemEndpointResolver> {
    inner: P,
    policy: Mutex<SsrfPolicyTemplate>,
    trace_id: String,
    resolver: R,
    resolve_network: EndpointLookup<P, R>,
    timeout: fn(&P) -> Duration,
    tls_supported: fn(&P) -> bool,
    execute_network: PinnedExecutor<P>,
    execute_network_controlled: PinnedControlledExecutor<P>,
}

#[cfg(feature = "engine")]
impl<P: HostIoProvider> SsrfGatedHostIo<P> {
    /// Wrap any provider with default SSRF policy and numeric-only transport.
    /// For native hostname HTTPS and provider-specific deadlines, use
    /// `from_network_policy` or `with_resolver` with a PinnedNetworkProvider.
    pub fn new(inner: P, trace_id: impl Into<String>) -> Self {
        let trace_id = trace_id.into();
        let policy = SsrfPolicyTemplate::default_template(format!("run:{trace_id}"));
        Self::with_policy(inner, policy, trace_id)
    }

    /// Use an explicit policy with generic numeric-only transport. This does
    /// not assert hostname TLS support for an otherwise arbitrary host provider.
    pub fn with_policy(inner: P, policy: SsrfPolicyTemplate, trace_id: impl Into<String>) -> Self {
        Self {
            inner,
            policy: Mutex::new(policy),
            trace_id: trace_id.into(),
            resolver: SystemEndpointResolver,
            resolve_network: |_, resolver, host, port, deadline, control| {
                resolver.resolve_controlled_until(host, port, deadline, control)
            },
            timeout: |_| SANDBOXED_HOST_IO_NETWORK_TIMEOUT,
            tls_supported: |_| false,
            execute_network: perform_numeric_network_candidates::<P>,
            execute_network_controlled: perform_numeric_network_candidates_controlled::<P>,
        }
    }
}

#[cfg(feature = "engine")]
impl<P: PinnedNetworkProvider> SsrfGatedHostIo<P> {
    /// Production run constructor. SandboxedHostIo supplies pinned HTTPS
    /// automatically, using its existing operator roots and limits. DNS waiting
    /// and transport share the native provider's revocation scope. No opt-out,
    /// environment flag, second DNS lookup, or plaintext fallback is used.
    pub fn from_network_policy(
        inner: P,
        policy: &NetworkPolicyConfig,
        trace_id: impl Into<String>,
    ) -> Self {
        let trace_id = trace_id.into();
        let template = build_ssrf_template(policy, &trace_id);
        let mut gate = Self::with_resolver(inner, template, trace_id, SystemEndpointResolver);
        gate.resolve_network = |inner, _, host, port, deadline, control| {
            inner.resolve_pinned_endpoint_until(host, port, deadline, control)
        };
        gate
    }
}

#[cfg(feature = "engine")]
impl<P: PinnedNetworkProvider, R: EndpointResolver> SsrfGatedHostIo<P, R> {
    /// Select the provider's pinned transport and an explicitly supplied DNS
    /// implementation. The resolver owns interruptibility during its lookup;
    /// use from_network_policy for the native provider's scoped DNS instead.
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
            resolve_network: |_, resolver, host, port, deadline, control| {
                resolver.resolve_controlled_until(host, port, deadline, control)
            },
            timeout: P::network_timeout,
            tls_supported: P::supports_pinned_tls,
            execute_network: P::perform_pinned_network_candidates,
            execute_network_controlled: P::perform_pinned_network_candidates_controlled,
        }
    }
}

#[cfg(feature = "engine")]
impl<P: HostIoProvider, R: EndpointResolver> SsrfGatedHostIo<P, R> {
    #[must_use]
    pub fn audit_records(&self) -> Vec<SsrfAuditRecord> {
        self.policy
            .lock()
            .map(|policy| policy.audit_log.clone())
            .unwrap_or_default()
    }

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

    fn check_operation(
        &self,
        control: &dyn HostIoControl,
        host: &str,
        port: u16,
    ) -> Result<(), HostIoError> {
        control.checkpoint().map_err(|_| {
            // Cancellation is operational, not an SSRF violation that could
            // quarantine a dependency. Never echo the supervisor's diagnostic.
            self.record_denial(host, port, "network_execution_cancelled");
            cancelled()
        })
    }

    fn gate_endpoint(
        &self,
        request: &HostIoRequest,
        endpoint: &str,
        use_tls: bool,
        granted: &[HostIoCapability],
        control: Arc<dyn HostIoControl>,
    ) -> Result<(Vec<SocketAddr>, Instant), HostIoError> {
        let started = Instant::now();
        let capability = request.required_capability();
        if !granted.contains(&capability) {
            let (host, port) = split_host_port(endpoint).unwrap_or((endpoint, 0));
            self.record_denial(host, port, "capability_missing");
            return Err(HostIoError::CapabilityMissing { capability });
        }
        let Some((host, port)) = split_host_port(endpoint) else {
            return Err(self.deny(endpoint, 0, "invalid_endpoint"));
        };
        self.check_operation(control.as_ref(), host, port)?;
        let literal = literal_ip(host);
        if use_tls && literal.is_none() && !(self.tls_supported)(&self.inner) {
            return Err(self.deny(host, port, "tls_address_pinning_unavailable"));
        }
        let duration = (self.timeout)(&self.inner);
        let deadline = started
            .checked_add(duration)
            .filter(|_| !duration.is_zero())
            .ok_or_else(|| self.deny(host, port, "invalid_network_timeout"))?;
        ensure_time_remaining(deadline)
            .map_err(|_| self.deny(host, port, "network_deadline_exceeded"))?;
        let resolution = match literal {
            Some(address) => Ok(vec![address]),
            None => (self.resolve_network)(
                &self.inner, &self.resolver, host, port, deadline, Arc::clone(&control),
            ),
        };
        // Check failures as well as successes. Cancellation observed inside
        // DNS is a sticky host denial, not a catchable guest I/O exception.
        self.check_operation(control.as_ref(), host, port)?;
        let resolved = resolution.map_err(|error| {
            let code = match error.kind() {
                std::io::ErrorKind::TimedOut => "network_deadline_exceeded",
                std::io::ErrorKind::WouldBlock => "dns_capacity_exhausted",
                std::io::ErrorKind::InvalidData => "dns_answer_limit_exceeded",
                std::io::ErrorKind::NotFound => "dns_resolution_required",
                std::io::ErrorKind::PermissionDenied => "dns_resolution_refused",
                _ => "dns_resolution_failed",
            };
            self.deny(host, port, code)
        })?;
        ensure_time_remaining(deadline)
            .map_err(|_| self.deny(host, port, "network_deadline_exceeded"))?;
        if resolved.len() > MAX_RESOLVED_ADDRESSES {
            return Err(self.deny(host, port, "dns_answer_limit_exceeded"));
        }
        if resolved.is_empty() {
            return Err(self.deny(host, port, "dns_resolution_required"));
        }
        let timestamp = chrono::Utc::now().to_rfc3339();
        let mut policy = self.policy.lock().map_err(|_| HostIoError::Denied {
            reason: "ssrf: policy lock poisoned".to_string(),
        })?;
        let decision = policy.check_ssrf_resolved_ips(
            host,
            &resolved,
            port,
            Protocol::Http,
            &self.trace_id,
            &timestamp,
        );
        drop(policy);
        self.check_operation(control.as_ref(), host, port)?;
        ensure_time_remaining(deadline)
            .map_err(|_| self.deny(host, port, "network_deadline_exceeded"))?;
        match decision {
            Ok(Action::Allow) => {
                // Never truncate before admission: a denied or excessive
                // later answer must block the entire operation. Deduplicate
                // only the fully checked set, preserving resolver preference.
                let mut addresses = Vec::with_capacity(resolved.len());
                for ip in resolved {
                    let address = SocketAddr::new(ip, port);
                    if !addresses.contains(&address) {
                        addresses.push(address);
                    }
                }
                Ok((addresses, deadline))
            }
            Ok(Action::Deny) | Err(_) => Err(HostIoError::Denied {
                reason: format!("{SSRF_EGRESS_POLICY_BLOCK_MARKER}{host}:{port} blocked by policy"),
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
        let (endpoint, use_tls) = match request {
            HostIoRequest::NetworkSend { endpoint, .. }
            | HostIoRequest::NetworkRecv { endpoint, .. } => (endpoint, false),
            HostIoRequest::NetworkRequest {
                endpoint, use_tls, ..
            } => (endpoint, *use_tls),
            HostIoRequest::FsRead { .. }
            | HostIoRequest::FsWrite { .. }
            | HostIoRequest::FsMeta { .. }
            | HostIoRequest::RandomRead { .. } => return self.inner.perform(request, granted),
        };
        let (addresses, deadline) = self.gate_endpoint(
            request, endpoint, use_tls, granted, Arc::new(UnrestrictedHostIoControl),
        )?;
        (self.execute_network)(&self.inner, request, granted, &addresses, deadline)
    }

    /// The engine drives every effect through this supervised entry. The SSRF
    /// gate retains the same policy, but cancellation now spans DNS admission
    /// as well as pinned transport. The shared latch is not stored on `inner`
    /// and non-network requests still receive the original control unchanged.
    fn perform_controlled(
        &self,
        request: &HostIoRequest,
        granted: &[HostIoCapability],
        control: Arc<dyn HostIoControl>,
    ) -> HostIoOutcome {
        let (endpoint, use_tls) = match request {
            HostIoRequest::NetworkSend { endpoint, .. }
            | HostIoRequest::NetworkRecv { endpoint, .. } => (endpoint, false),
            HostIoRequest::NetworkRequest {
                endpoint, use_tls, ..
            } => (endpoint, *use_tls),
            HostIoRequest::FsRead { .. }
            | HostIoRequest::FsWrite { .. }
            | HostIoRequest::FsMeta { .. }
            | HostIoRequest::RandomRead { .. } => {
                return self.inner.perform_controlled(request, granted, control);
            }
        };
        let control: Arc<dyn HostIoControl> = Arc::new(NetworkOperationControl {
            source: control,
            refused: AtomicBool::new(false),
        });
        let (addresses, deadline) = self.gate_endpoint(
            request, endpoint, use_tls, granted, Arc::clone(&control),
        )?;
        let outcome = (self.execute_network_controlled)(
            &self.inner,
            request,
            granted,
            &addresses,
            deadline,
            Arc::clone(&control),
        );
        let (host, port) = split_host_port(endpoint).expect("admitted endpoint");
        self.check_operation(control.as_ref(), host, port)?;
        outcome
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

        fn perform_controlled(
            &self,
            request: &HostIoRequest,
            granted: &[HostIoCapability],
            control: Arc<dyn HostIoControl>,
        ) -> HostIoOutcome {
            control.checkpoint()?;
            self.perform(request, granted)
        }
    }

    impl PinnedNetworkProvider for RecordingInner {}

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
        assert!(
            gate.perform(&original, &[HostIoCapability::NetworkSend])
                .is_ok()
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(original, before);
        assert_eq!(
            *seen.lock().unwrap(),
            vec![request("93.184.216.34:80", false)]
        );
        assert_eq!(gate.audit_records()[0].host, "service.example");
        assert!(
            gate.perform(&original, &[HostIoCapability::NetworkSend])
                .is_err()
        );
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
                    &[HostIoCapability::NetworkSend]
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
        assert!(
            gate.perform(&numeric, &[HostIoCapability::NetworkSend])
                .is_ok()
        );
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
                capability: HostIoCapability::NetworkSend
            })
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert!(seen.lock().unwrap().is_empty());
        assert_eq!(gate.audit_records()[0].action, Action::Deny);
    }

    #[test]
    fn socket_endpoint_parser_rejects_ambiguous_or_non_socket_inputs() {
        for endpoint in [
            "",
            "service.example",
            ":80",
            "host:0",
            "host:+80",
            "host:65536",
            "http://host:80",
            "user@host:80",
            "host/path:80",
            "host\\path:80",
            " host:80",
            "host :80",
            "host\r\n:80",
            "host\0:80",
            "a..b:80",
            "host..:80",
            "[127.0.0.1]:80",
            "::1:80",
            "[::1:80",
            "::1]:80",
            "[fe80::1%eth0]:80",
            "127.1:80",
            "2130706433:80",
            "0x7f000001:80",
            "0177.0.0.1:80",
            "127.0.0.1.:80",
            "-host:80",
            "host-:80",
        ] {
            assert!(split_host_port(endpoint).is_none(), "{endpoint:?}");
        }
        for endpoint in [
            "service.example:80",
            "Service.Example.:443",
            "localhost:1",
            "93.184.216.34:65535",
            "[::1]:443",
            "[2001:4860:4860::8888]:53",
        ] {
            assert!(split_host_port(endpoint).is_some(), "{endpoint:?}");
        }
    }

    #[test]
    fn arbitrary_non_network_provider_can_be_wrapped_without_claiming_tls_support() {
        #[derive(Debug)]
        struct EntropyOnly;
        impl HostIoProvider for EntropyOnly {
            fn name(&self) -> &str {
                "entropy-only"
            }
            fn perform(&self, request: &HostIoRequest, _: &[HostIoCapability]) -> HostIoOutcome {
                match request {
                    HostIoRequest::RandomRead { byte_len } => Ok(HostIoResponse::RandomRead {
                        bytes: vec![9; usize::try_from(*byte_len).unwrap()],
                    }),
                    _ => panic!("unsupported network transport was reached"),
                }
            }
        }
        let gate = SsrfGatedHostIo::new(EntropyOnly, "generic-provider");
        assert_eq!(
            gate.perform(
                &HostIoRequest::RandomRead { byte_len: 2 },
                &[HostIoCapability::RandomRead]
            ),
            Ok(HostIoResponse::RandomRead { bytes: vec![9, 9] })
        );
        assert!(matches!(gate.perform(&request("service.invalid:443", true),
            &[HostIoCapability::NetworkSend]), Err(HostIoError::Denied { reason })
            if reason.contains("tls_address_pinning_unavailable")));
    }

    #[test]
    fn numeric_transport_refuses_port_or_literal_identity_retargeting() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let provider = RecordingInner(Arc::clone(&seen));
        let original = request("93.184.216.34:443", true);
        for address in ["93.184.216.34:80", "127.0.0.1:443"] {
            assert!(
                perform_numeric_network(
                    &provider,
                    &original,
                    &[HostIoCapability::NetworkSend],
                    address.parse().unwrap(),
                    Instant::now() + Duration::from_secs(1)
                )
                .is_err()
            );
        }
        assert!(seen.lock().unwrap().is_empty());
    }

    #[derive(Debug, Default)]
    struct Signal(AtomicBool);

    impl HostIoControl for Signal {
        fn checkpoint(&self) -> Result<(), HostIoError> {
            if self.0.load(Ordering::Acquire) {
                Err(HostIoError::Fs {
                    code: "EIO".into(),
                    detail: "private-supervisor-detail".into(),
                })
            } else {
                Ok(())
            }
        }
    }

    fn assert_cancelled(outcome: HostIoOutcome) {
        assert_eq!(outcome, Err(cancelled()));
    }

    #[test]
    fn cancelled_network_variants_do_not_reach_dns_or_transport() {
        for endpoint in ["service.example:80", "93.184.216.34:80"] {
            for original in [
                HostIoRequest::NetworkSend { endpoint: endpoint.into(), payload: vec![1] },
                HostIoRequest::NetworkRecv { endpoint: endpoint.into(), max_len: 1 },
                request(endpoint, false),
            ] {
                let seen = Arc::new(Mutex::new(Vec::new()));
                let calls = Arc::new(AtomicUsize::new(0));
                let gate = SsrfGatedHostIo::with_resolver(
                    RecordingInner(Arc::clone(&seen)),
                    SsrfPolicyTemplate::default_template("cancelled".into()),
                    "cancelled",
                    Answers { calls: Arc::clone(&calls), first: vec![] },
                );
                assert_cancelled(gate.perform_controlled(
                    &original,
                    &[original.required_capability()],
                    Arc::new(Signal(AtomicBool::new(true))),
                ));
                assert_eq!(calls.load(Ordering::SeqCst), 0);
                assert!(seen.lock().unwrap().is_empty());
                let audit = gate.audit_records();
                assert_eq!(audit.len(), 1);
                assert_eq!(audit[0].cidr_matched.as_deref(), Some("network_execution_cancelled"));
                assert!(!format!("{audit:?}").contains("private-supervisor-detail"));
            }
        }
    }

    #[test]
    fn missing_network_capability_remains_a_pre_dns_admission_check() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let calls = Arc::new(AtomicUsize::new(0));
        let gate = SsrfGatedHostIo::with_resolver(
            RecordingInner(Arc::clone(&seen)),
            SsrfPolicyTemplate::default_template("capability-first".into()),
            "capability-first",
            Answers { calls: Arc::clone(&calls), first: vec![] },
        );
        assert_eq!(
            gate.perform_controlled(
                &request("service.example:80", false), &[],
                Arc::new(Signal(AtomicBool::new(true))),
            ),
            Err(HostIoError::CapabilityMissing { capability: HostIoCapability::NetworkSend }),
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert!(seen.lock().unwrap().is_empty());
        assert_eq!(gate.audit_records()[0].cidr_matched.as_deref(), Some("capability_missing"));
    }

    #[derive(Debug)]
    struct RefuseOnceDns {
        signal: Arc<Signal>,
        calls: AtomicUsize,
    }

    impl EndpointResolver for RefuseOnceDns {
        fn resolve(&self, _: &str, _: u16) -> std::io::Result<Vec<IpAddr>> {
            panic!("controlled lookup must not fall back to unscoped DNS")
        }

        fn resolve_controlled_until(
            &self, _: &str, _: u16, deadline: Instant, control: Arc<dyn HostIoControl>,
        ) -> std::io::Result<Vec<IpAddr>> {
            ensure_time_remaining(deadline)?;
            if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
                self.signal.0.store(true, Ordering::Release);
                assert!(control.checkpoint().is_err());
                self.signal.0.store(false, Ordering::Release);
            }
            // Even a buggy resolver returning success after observing denial
            // cannot revive this operation. A later operation may proceed.
            Ok(vec!["93.184.216.34".parse().unwrap()])
        }
    }

    #[test]
    fn dns_refusal_stays_latched_through_admission_but_not_the_next_request() {
        let signal = Arc::new(Signal::default());
        let seen = Arc::new(Mutex::new(Vec::new()));
        let gate = SsrfGatedHostIo::with_resolver(
            RecordingInner(Arc::clone(&seen)),
            SsrfPolicyTemplate::default_template("sticky-dns".into()),
            "sticky-dns",
            RefuseOnceDns { signal: Arc::clone(&signal), calls: AtomicUsize::new(0) },
        );
        let original = request("service.example:80", false);
        assert_cancelled(gate.perform_controlled(
            &original, &[HostIoCapability::NetworkSend], signal.clone(),
        ));
        assert!(seen.lock().unwrap().is_empty());
        assert!(gate.perform_controlled(
            &original, &[HostIoCapability::NetworkSend], signal,
        ).is_ok());
        assert_eq!(seen.lock().unwrap().len(), 1);
    }

    #[derive(Debug, Default)]
    struct ProviderDns {
        admission: Mutex<Option<(Instant, Arc<dyn HostIoControl>)>>,
        calls: AtomicUsize,
    }

    impl HostIoProvider for ProviderDns {
        fn name(&self) -> &str { "provider-dns-test" }
        fn perform(&self, _: &HostIoRequest, _: &[HostIoCapability]) -> HostIoOutcome {
            panic!("pinned supervised transport is required")
        }
    }

    impl PinnedNetworkProvider for ProviderDns {
        fn supports_pinned_tls(&self) -> bool { true }

        fn resolve_pinned_endpoint_until(
            &self, host: &str, port: u16, deadline: Instant, control: Arc<dyn HostIoControl>,
        ) -> std::io::Result<Vec<IpAddr>> {
            assert_eq!((host, port), ("provider-dns.invalid", 443));
            check_control_io(control.as_ref())?;
            self.calls.fetch_add(1, Ordering::SeqCst);
            *self.admission.lock().unwrap() = Some((deadline, control));
            Ok(vec!["93.184.216.34".parse().unwrap()])
        }

        fn perform_pinned_network_candidates_controlled(
            &self, request: &HostIoRequest, _: &[HostIoCapability],
            addresses: &[SocketAddr], deadline: Instant, control: Arc<dyn HostIoControl>,
        ) -> HostIoOutcome {
            let admission = self.admission.lock().unwrap();
            let (dns_deadline, dns_control) = admission.as_ref().expect("provider DNS was used");
            assert_eq!(*dns_deadline, deadline);
            assert!(Arc::ptr_eq(dns_control, &control));
            assert_eq!(addresses, &["93.184.216.34:443".parse::<SocketAddr>().unwrap()]);
            assert!(matches!(request, HostIoRequest::NetworkRequest { endpoint, use_tls: true, .. }
                if endpoint == "provider-dns.invalid:443"));
            control.checkpoint()?;
            Ok(HostIoResponse::NetworkSend { bytes_sent: 0 })
        }
    }

    #[test]
    fn production_constructor_shares_provider_dns_control_deadline_and_tls_identity() {
        let gate = SsrfGatedHostIo::from_network_policy(
            ProviderDns::default(), &NetworkPolicyConfig::default(), "provider-dns",
        );
        assert!(gate.perform_controlled(
            &request("provider-dns.invalid:443", true),
            &[HostIoCapability::NetworkSend], Arc::new(UnrestrictedHostIoControl),
        ).is_ok());
        assert_eq!(gate.inner.calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn native_provider_revocation_refuses_dns_before_ip_policy_admission() {
        let root = tempfile::tempdir().unwrap();
        let inner = SandboxedHostIo::with_root(root.path()).unwrap();
        inner.network_revocation().revoke();
        let gate = SsrfGatedHostIo::from_network_policy(
            inner, &NetworkPolicyConfig::default(), "revoked-dns",
        );
        let original = request("must-not-resolve.invalid:443", true);
        for controlled in [false, true] {
            let outcome = if controlled {
                gate.perform_controlled(&original, &[HostIoCapability::NetworkSend],
                    Arc::new(UnrestrictedHostIoControl))
            } else { gate.perform(&original, &[HostIoCapability::NetworkSend]) };
            assert!(matches!(outcome, Err(HostIoError::Denied { reason })
                if reason.contains("dns_resolution_refused")
                    && !reason.contains(SSRF_EGRESS_POLICY_BLOCK_MARKER)));
        }
        let audit = gate.audit_records();
        assert_eq!(audit.len(), 2);
        assert!(audit.iter().all(|entry| entry.action == Action::Deny
            && entry.cidr_matched.as_deref() == Some("dns_resolution_refused")));
    }
}
