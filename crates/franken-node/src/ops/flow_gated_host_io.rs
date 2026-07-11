//! bd-n1bym: product-layer information-flow gate for guest host effects.
//!
//! [`super::ssrf_gated_host_io::SsrfGatedHostIo`] gates egress by ENDPOINT (is
//! this host/IP allowed?). This gate is its complement: it gates egress by
//! DATA (do these bytes carry a secret this run read?). Together they close the
//! exfiltration gap — the SSRF gate stops a leak to a blocked endpoint, and
//! this gate stops a leak of secret-labeled bytes to an *allowed* endpoint,
//! before any socket opens.
//!
//! Mechanism. The gate is stateful for the lifetime of one run. A guest
//! `fs.read` of a recognized secret-bearing file
//! ([`crate::security::lineage_tracker::classify_sensitive_source_path`] — the
//! `.env` family, PEM/key/SSH/PKCS#12/credential files) has its bytes retained
//! as a secret *sample* (bounded). Before any subsequent network egress
//! (`NetworkSend` / `NetworkRequest`), the gate checks whether the outbound
//! bytes CONTAIN a secret sample; if so — and absent a valid declassification
//! (operator-authorized override, not yet wired) — the egress fails closed
//! with [`HostIoError::Denied`] and never reaches the wrapped provider. The
//! engine's host-I/O transcript records the denial, so the signed host-effect
//! ledger surfaces it as a flow BLOCK exactly as a byte-verbatim exfil would.
//!
//! Containment (not exact-hash) is required because an http egress payload is
//! the *framed* request (headers + body) — the secret appears as a substring.
//!
//! Scope. This gate prevents secret NETWORK egress only. A local `fs.write`
//! that copies a secret is labeled by the ledger for evidence but is not an
//! external sink and is not blocked here. Following a secret through an
//! in-guest transform (base64, concat) needs per-datum lineage the transcript
//! does not carry (engine-side). Behavioral coverage lives in
//! `crates/franken-node/tests/native_engine_compat.rs`.

#[cfg(feature = "engine")]
use std::sync::Mutex;

#[cfg(feature = "engine")]
use frankenengine_extension_host::host_io::{
    HostIoCapability, HostIoError, HostIoOutcome, HostIoProvider, HostIoRequest, HostIoResponse,
};

#[cfg(feature = "engine")]
use crate::security::lineage_tracker::classify_sensitive_source_path;

/// Reject trivially short reads (a handful of bytes could coincidentally appear
/// in unrelated payloads) and cap sample size / count to bound the containment
/// search. Kept identical to the ledger-builder's flow-labeling bounds so the
/// gate's prevention and the ledger's evidence agree on what counts as secret.
#[cfg(feature = "engine")]
const MIN_SECRET_SAMPLE_LEN: usize = 8;
#[cfg(feature = "engine")]
const MAX_SECRET_SAMPLE_LEN: usize = 64 * 1024;
#[cfg(feature = "engine")]
const MAX_SECRET_SAMPLES: usize = 16;

/// True when `needle` occurs as a contiguous subsequence of `haystack`.
#[cfg(feature = "engine")]
fn slice_contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && needle.len() <= haystack.len()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

/// A [`HostIoProvider`] decorator that fails a network egress closed when its
/// bytes carry a secret this run read. Wrap it OUTSIDE the SSRF gate so a
/// secret-carrying egress is refused before endpoint evaluation.
#[cfg(feature = "engine")]
#[derive(Debug)]
pub struct FlowGatedHostIo<P: HostIoProvider> {
    inner: P,
    /// Secret-source byte samples observed during this run (bounded).
    secrets: Mutex<Vec<Vec<u8>>>,
    trace_id: String,
}

#[cfg(feature = "engine")]
impl<P: HostIoProvider> FlowGatedHostIo<P> {
    /// Wrap `inner`. `trace_id` labels the gate's denials for correlation.
    pub fn new(inner: P, trace_id: impl Into<String>) -> Self {
        Self {
            inner,
            secrets: Mutex::new(Vec::new()),
            trace_id: trace_id.into(),
        }
    }

    /// Retain a sensitive read's bytes as a secret sample (bounded).
    fn record_secret(&self, bytes: &[u8]) {
        if !(MIN_SECRET_SAMPLE_LEN..=MAX_SECRET_SAMPLE_LEN).contains(&bytes.len()) {
            return;
        }
        if let Ok(mut secrets) = self.secrets.lock()
            && secrets.len() < MAX_SECRET_SAMPLES
            && !secrets.iter().any(|existing| existing == bytes)
        {
            secrets.push(bytes.to_vec());
        }
    }

    /// `Ok(())` authorizes the egress; `Err(Denied)` fails it closed when the
    /// outbound bytes contain a retained secret sample. A poisoned lock denies
    /// fail-closed (never weaken the gate on an internal error).
    fn gate_outbound(&self, outbound: &[u8]) -> Result<(), HostIoError> {
        if outbound.is_empty() {
            return Ok(());
        }
        let carries_secret = match self.secrets.lock() {
            Ok(secrets) => secrets
                .iter()
                .any(|sample| slice_contains(outbound, sample)),
            Err(_) => {
                return Err(HostIoError::Denied {
                    reason: format!(
                        "flow_policy: secret sample lock poisoned during egress ({})",
                        self.trace_id
                    ),
                });
            }
        };
        if carries_secret {
            return Err(HostIoError::Denied {
                reason: format!(
                    "flow_policy: forbidden-labeled (secret-source) bytes reached a network sink without declassification ({})",
                    self.trace_id
                ),
            });
        }
        Ok(())
    }
}

#[cfg(feature = "engine")]
impl<P: HostIoProvider> HostIoProvider for FlowGatedHostIo<P> {
    fn name(&self) -> &str {
        "flow-gated-host-io"
    }

    fn perform(&self, request: &HostIoRequest, granted: &[HostIoCapability]) -> HostIoOutcome {
        match request {
            // Network egress is a sink: check the outbound bytes BEFORE the
            // effect so a secret-carrying egress never opens a socket. (This
            // arm is deliberately explicit: a new network egress variant fails
            // the build here until it is gated, so there is no silent bypass.)
            HostIoRequest::NetworkSend { payload, .. }
            | HostIoRequest::NetworkRequest { payload, .. } => {
                self.gate_outbound(payload)?;
                self.inner.perform(request, granted)
            }
            // A sensitive read registers a secret sample AFTER it succeeds; the
            // read itself is a source, not a sink, and is never blocked.
            HostIoRequest::FsRead { path } => {
                let outcome = self.inner.perform(request, granted);
                if classify_sensitive_source_path(path).is_some()
                    && let Ok(HostIoResponse::FsRead { bytes }) = &outcome
                {
                    self.record_secret(bytes);
                }
                outcome
            }
            // Inbound receive and local filesystem writes are not external
            // network sinks: delegate unchanged (the ledger still labels a
            // secret-carrying fs_write for evidence).
            HostIoRequest::NetworkRecv { .. } | HostIoRequest::FsWrite { .. } => {
                self.inner.perform(request, granted)
            }
        }
    }
}
