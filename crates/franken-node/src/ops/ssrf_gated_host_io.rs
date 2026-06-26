//! bd-656a2: product-layer SSRF gate for guest network egress.
//!
//! The sibling engine's `SandboxedHostIo` is the network *mechanism*: it performs
//! raw, capability-checked, byte/time-bounded TCP I/O but performs **no** endpoint
//! policy check. Per the engine-split contract the engine is the mechanism and
//! `franken_node` owns the policy — so this wrapper is that policy. Before any
//! guest `NetworkSend`/`NetworkRecv`/`NetworkRequest` reaches the socket, [`SsrfGatedHostIo`]
//! resolves the endpoint and evaluates it against the franken_node SSRF policy
//! (default-deny loopback / link-local / RFC1918 / CGNAT / cloud-metadata
//! ranges). Allowed egress is delegated to the wrapped provider; denied egress
//! fails closed as a recorded denial that never reaches the network. Filesystem
//! effects carry no endpoint and pass straight through.
//!
//! This is the load-bearing security control that makes the engine's JS
//! `http.get`/`http.request` -> `net:request` lowering safe to activate on the
//! `franken-node run` path: without it, a guest program could drive the engine's
//! network mechanism to an internal/metadata endpoint (a classic SSRF) because
//! the run path grants `network_egress` under the balanced/legacy profiles.
//!
//! Behavioral coverage lives in the integration suite
//! `crates/franken-node/tests/ssrf_gated_host_io_egress.rs` (the crate-root
//! `#![cfg(any(not(test), franken_node_inline_tests))]` gates inline `#[cfg(test)]`
//! modules out of the normal `cargo test` lane, so the gate is verified through
//! the public API against the real library).

#[cfg(feature = "engine")]
use std::net::{IpAddr, ToSocketAddrs};
#[cfg(feature = "engine")]
use std::sync::Mutex;

#[cfg(feature = "engine")]
use frankenengine_extension_host::host_io::{
    HostIoCapability, HostIoError, HostIoOutcome, HostIoProvider, HostIoRequest,
};

#[cfg(feature = "engine")]
use crate::config::{NetworkPolicyConfig, SsrfEnforcementMode};
#[cfg(feature = "engine")]
use crate::security::network_guard::{Action, Protocol};
#[cfg(feature = "engine")]
use crate::security::ssrf_policy::{
    AllowlistEntry, PolicyReceipt, SsrfAuditRecord, SsrfPolicyTemplate,
};

/// Split a `host:port` connect endpoint (as framed by the engine's
/// `http_request_to_wire`) into its host and port components. Uses the last `:`
/// so bare IPv4 `host:port` parses correctly; bracketed IPv6 literals
/// (`[::1]:80`) are left with their brackets, which resolve/deny fail-closed
/// downstream (IPv6 egress is not supported in this slice). Returns `None` when
/// the port is absent or not a valid `u16`.
#[cfg(feature = "engine")]
fn split_host_port(endpoint: &str) -> Option<(&str, u16)> {
    let (host, port_str) = endpoint.rsplit_once(':')?;
    if host.is_empty() {
        return None;
    }
    let port = port_str.parse::<u16>().ok()?;
    Some((host, port))
}

/// Build the [`SsrfPolicyTemplate`] that governs a run from its
/// `[security.network_policy]` config. See [`SsrfGatedHostIo::from_network_policy`]
/// for the enforcement-mode mapping (fail-safe; only an explicit opt-out empties
/// the deny-list).
#[cfg(feature = "engine")]
fn build_ssrf_template(policy: &NetworkPolicyConfig, trace_id: &str) -> SsrfPolicyTemplate {
    let connector_id = format!("run:{trace_id}");
    // Enforcement is ON unless the operator explicitly opts out (mode `None` or
    // the deprecated `ssrf_protection_enabled = false`). `Monitor` is treated as
    // `Block` here — fail-safe; we never weaken the gate on an ambiguous config.
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

/// A [`HostIoProvider`] decorator that enforces the franken_node SSRF policy on
/// every network egress before delegating to the wrapped provider.
#[cfg(feature = "engine")]
#[derive(Debug)]
pub struct SsrfGatedHostIo<P: HostIoProvider> {
    inner: P,
    policy: Mutex<SsrfPolicyTemplate>,
    trace_id: String,
}

#[cfg(feature = "engine")]
impl<P: HostIoProvider> SsrfGatedHostIo<P> {
    /// Wrap `inner` with the default-deny SSRF policy (blocks loopback,
    /// link-local, RFC1918, CGNAT, and cloud-metadata ranges). `trace_id`
    /// labels the SSRF audit records emitted by each decision.
    pub fn new(inner: P, trace_id: impl Into<String>) -> Self {
        let trace_id = trace_id.into();
        let policy = SsrfPolicyTemplate::default_template(format!("run:{trace_id}"));
        Self {
            inner,
            policy: Mutex::new(policy),
            trace_id,
        }
    }

    /// Wrap `inner` with an explicit policy template. Used by config-driven
    /// wiring (allowlist exceptions carried by signed policy receipts) and by
    /// tests that inject a template permitting an otherwise-blocked endpoint.
    pub fn with_policy(inner: P, policy: SsrfPolicyTemplate, trace_id: impl Into<String>) -> Self {
        Self {
            inner,
            policy: Mutex::new(policy),
            trace_id: trace_id.into(),
        }
    }

    /// Wrap `inner` with the SSRF policy derived from franken_node's
    /// `[security.network_policy]` configuration — the constructor the run path
    /// uses so an operator's `franken-node.toml` actually governs guest egress.
    ///
    /// Enforcement mapping (fail-safe): `Block` and `Monitor` both keep the
    /// standard default-deny CIDR set (loopback / link-local / RFC1918 / CGNAT /
    /// metadata); `Monitor`'s log-but-allow nuance is a follow-up and is treated
    /// as `Block` here so we never silently weaken the gate. Only an explicit
    /// `ssrf_enforcement = "none"` (or the deprecated `ssrf_protection_enabled =
    /// false`) yields an empty deny-list (operator opt-out — still audited, still
    /// the load-bearing decision point). `block_cloud_metadata = false` is NOT
    /// honored in this slice: the metadata range stays blocked (fail-safe);
    /// un-blocking it is deferred rather than risk an SSRF footgun.
    ///
    /// Each config allowlist entry becomes an [`AllowlistEntry`] carrying a
    /// synthesized [`PolicyReceipt`] (the run is the issuing authority), so an
    /// allowlisted host bypasses the matched CIDR exactly as a signed exception
    /// would.
    pub fn from_network_policy(
        inner: P,
        policy: &NetworkPolicyConfig,
        trace_id: impl Into<String>,
    ) -> Self {
        let trace_id = trace_id.into();
        let template = build_ssrf_template(policy, &trace_id);
        Self::with_policy(inner, template, trace_id)
    }

    /// Snapshot the accumulated SSRF audit records (one per allow/deny decision)
    /// for surfacing into the evidence ledger alongside the host-effect ledger.
    #[must_use]
    pub fn audit_records(&self) -> Vec<SsrfAuditRecord> {
        self.policy
            .lock()
            .map(|policy| policy.audit_log.clone())
            .unwrap_or_default()
    }

    /// Evaluate `endpoint` against the SSRF policy. `Ok(())` authorizes the
    /// egress; `Err(Denied)` fails it closed (and is recorded by the engine's
    /// host-I/O transcript as a denied effect). Endpoint-parse and DNS-resolution
    /// failures deny fail-closed.
    fn gate_endpoint(&self, endpoint: &str) -> Result<(), HostIoError> {
        let Some((host, port)) = split_host_port(endpoint) else {
            return Err(HostIoError::Denied {
                reason: format!("ssrf: cannot parse network endpoint {endpoint:?}"),
            });
        };
        // Resolve to concrete IPs and deny if any resolved address is blocked.
        // An empty/failed resolution denies fail-closed via the policy's
        // `dns_resolution_required` path.
        let resolved: Vec<IpAddr> = (host, port)
            .to_socket_addrs()
            .map(|addrs| addrs.map(|addr| addr.ip()).collect())
            .unwrap_or_default();
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
            Ok(Action::Allow) => Ok(()),
            Ok(Action::Deny) | Err(_) => Err(HostIoError::Denied {
                reason: format!("ssrf: egress to {host}:{port} blocked by policy"),
            }),
        }
    }
}

#[cfg(feature = "engine")]
impl<P: HostIoProvider> HostIoProvider for SsrfGatedHostIo<P> {
    fn name(&self) -> &str {
        "ssrf-gated-host-io"
    }

    fn perform(&self, request: &HostIoRequest, granted: &[HostIoCapability]) -> HostIoOutcome {
        match request {
            // bd-3894s slice (4): the single-socket `NetworkRequest` round trip is
            // an egress and MUST be gated exactly like `NetworkSend`. (This match is
            // exhaustive on purpose: a new network request variant fails the build
            // here until it is gated, so there is no silent SSRF-bypass path.)
            HostIoRequest::NetworkSend { endpoint, .. }
            | HostIoRequest::NetworkRecv { endpoint, .. }
            | HostIoRequest::NetworkRequest { endpoint, .. } => {
                self.gate_endpoint(endpoint)?;
                self.inner.perform(request, granted)
            }
            // Filesystem effects carry no network endpoint: delegate unchanged.
            HostIoRequest::FsRead { .. } | HostIoRequest::FsWrite { .. } => {
                self.inner.perform(request, granted)
            }
        }
    }
}
