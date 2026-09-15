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
//! A nonempty sensitive read that cannot be retained within the sample bounds
//! makes tracking incomplete for the rest of the run. Local I/O still works,
//! but network egress fails closed rather than forgetting an exposed secret.
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
    HostIoCapability, HostIoError, HostIoExceptionProvenance, HostIoOutcome, HostIoProvider,
    HostIoRequest, HostIoResponse,
};

#[cfg(feature = "engine")]
use crate::security::lineage_tracker::classify_sensitive_source_path;

/// Bounds for exact containment tracking. Reads outside these bounds are NOT
/// public: a nonempty untrackable read permanently closes the network gate.
/// Empty reads reveal no bytes and do not consume the sample budget.
#[cfg(feature = "engine")]
const MIN_SECRET_SAMPLE_LEN: usize = 8;
#[cfg(feature = "engine")]
const MAX_SECRET_SAMPLE_LEN: usize = 64 * 1024;
#[cfg(feature = "engine")]
const MAX_SECRET_SAMPLES: usize = 16;

#[cfg(feature = "engine")]
#[derive(Default)]
struct SecretSamples {
    samples: Vec<Vec<u8>>,
    /// Sticky: dropping a sample must never restore permission to exfiltrate it.
    incomplete: bool,
}

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
pub struct FlowGatedHostIo<P: HostIoProvider> {
    inner: P,
    /// Secret-source byte samples observed during this run (bounded).
    secrets: Mutex<SecretSamples>,
    trace_id: String,
}

// Never derive Debug for this provider: the retained source bytes are secrets,
// including when a poisoned mutex still holds its previous contents. The
// wrapped provider may also hold sensitive state and must not be formatted.
#[cfg(feature = "engine")]
impl<P: HostIoProvider> std::fmt::Debug for FlowGatedHostIo<P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FlowGatedHostIo")
            .field("trace_id", &self.trace_id)
            .finish_non_exhaustive()
    }
}

#[cfg(feature = "engine")]
impl<P: HostIoProvider> FlowGatedHostIo<P> {
    /// Wrap `inner`. `trace_id` labels the gate's denials for correlation.
    pub fn new(inner: P, trace_id: impl Into<String>) -> Self {
        Self {
            inner,
            secrets: Mutex::new(SecretSamples::default()),
            trace_id: trace_id.into(),
        }
    }

    /// Retain a sensitive read's bytes, or close the network gate if retaining
    /// them is impossible. Repeated reads of an existing sample cost no budget.
    /// A poisoned lock is left poisoned; every subsequent egress will deny.
    fn record_secret(&self, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        if let Ok(mut secrets) = self.secrets.lock()
            && !secrets.incomplete
        {
            if !(MIN_SECRET_SAMPLE_LEN..=MAX_SECRET_SAMPLE_LEN).contains(&bytes.len()) {
                secrets.incomplete = true;
                return;
            }
            // Deduplicate before testing capacity: a full but complete sample
            // set remains complete when a known secret is reread.
            if secrets.samples.iter().any(|existing| existing == bytes) {
                return;
            }
            if secrets.samples.len() >= MAX_SECRET_SAMPLES {
                secrets.incomplete = true;
            } else {
                secrets.samples.push(bytes.to_vec());
            }
        }
    }

    /// `Ok(())` authorizes the egress; `Err(Denied)` fails it closed when the
    /// outbound bytes contain a retained secret sample. A poisoned lock denies
    /// fail-closed. Check tracking completeness even for empty payloads:
    /// connecting is still a host effect.
    fn gate_outbound(&self, outbound: &[u8]) -> Result<(), HostIoError> {
        let carries_secret = match self.secrets.lock() {
            Ok(secrets) if secrets.incomplete => {
                return Err(HostIoError::Denied {
                    reason: format!(
                        "flow_policy: incomplete secret tracking; network egress denied ({})",
                        self.trace_id
                    ),
                });
            }
            Ok(secrets) => secrets
                .samples
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

    fn filesystem_exception_provenance(&self) -> HostIoExceptionProvenance {
        self.inner.filesystem_exception_provenance()
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
            // Inbound receive and local filesystem mutations are not external
            // network sinks: delegate unchanged (the ledger still labels
            // secret-carrying write-class input for evidence). `FsMeta`
            // arguments are operation metadata, not bytes read from a file;
            // even read-class metadata results therefore must not become
            // secret samples. Its `data` field is used only by write-class
            // operations such as append and remains a local sink here.
            HostIoRequest::NetworkRecv { .. }
            | HostIoRequest::FsWrite { .. }
            | HostIoRequest::FsMeta { .. }
            | HostIoRequest::RandomRead { .. } => self.inner.perform(request, granted),
        }
    }
}

#[cfg(all(test, feature = "engine"))]
mod tests {
    use super::*;
    use frankenengine_extension_host::host_io::DenyAllHostIo;

    fn gate() -> FlowGatedHostIo<DenyAllHostIo> {
        FlowGatedHostIo::new(DenyAllHostIo, "flow-regression")
    }

    fn assert_denied(gate: &FlowGatedHostIo<DenyAllHostIo>, payload: &[u8]) {
        assert!(matches!(
            gate.gate_outbound(payload),
            Err(HostIoError::Denied { .. })
        ));
    }

    #[test]
    fn retained_samples_block_containment_not_unrelated_payloads() {
        for length in [MIN_SECRET_SAMPLE_LEN, MAX_SECRET_SAMPLE_LEN] {
            let gate = gate();
            let secret = vec![b'x'; length];
            gate.record_secret(&secret);
            let mut framed = b"header:".to_vec();
            framed.extend_from_slice(&secret);
            framed.extend_from_slice(b":trailer");
            assert_denied(&gate, &framed);
            assert!(gate.gate_outbound(b"unrelated public payload").is_ok());
            assert!(gate.gate_outbound(b"").is_ok());
        }
    }

    #[test]
    fn untrackable_nonempty_reads_close_egress_without_retaining_bytes() {
        for length in [1, MIN_SECRET_SAMPLE_LEN - 1, MAX_SECRET_SAMPLE_LEN + 1] {
            let gate = gate();
            gate.record_secret(&vec![b'x'; length]);
            assert!(gate.secrets.lock().expect("sample state").samples.is_empty());
            assert_denied(&gate, b"unrelated public payload");
            assert_denied(&gate, b"");
            gate.record_secret(b"");
            gate.record_secret(b"a later trackable secret");
            assert_denied(&gate, b"still denied");
        }
    }

    #[test]
    fn full_sample_budget_allows_duplicates_but_not_forgotten_secrets() {
        let gate = gate();
        for index in 0..MAX_SECRET_SAMPLES {
            gate.record_secret(format!("sensitive-sample-{index:04}").as_bytes());
        }
        gate.record_secret(b"sensitive-sample-0000");
        assert!(gate.gate_outbound(b"public").is_ok());
        assert_denied(&gate, b"header:sensitive-sample-0000:trailer");
        gate.record_secret(b"one more distinct sensitive sample");
        assert_denied(&gate, b"public");
        assert_denied(&gate, b"");
        let secrets = gate.secrets.lock().expect("sample state");
        assert_eq!(secrets.samples.len(), MAX_SECRET_SAMPLES);
        assert!(secrets.incomplete);
    }

    #[test]
    fn empty_reads_do_not_consume_sample_budget_or_close_egress() {
        let gate = gate();
        for _ in 0..=MAX_SECRET_SAMPLES {
            gate.record_secret(b"");
        }
        let secrets = gate.secrets.lock().expect("sample state");
        assert!(secrets.samples.is_empty());
        assert!(!secrets.incomplete);
        drop(secrets);
        assert!(gate.gate_outbound(b"public").is_ok());
        assert!(gate.gate_outbound(b"").is_ok());
    }

    #[test]
    fn poisoned_tracking_denies_even_empty_outbound_payloads() {
        let gate = gate();
        let result = std::panic::catch_unwind(|| {
            let _guard = gate.secrets.lock().expect("sample state");
            panic!("poison secret tracking for regression coverage");
        });
        assert!(result.is_err());
        gate.record_secret(b"a later secret must not recover the lock");
        assert_denied(&gate, b"public");
        assert_denied(&gate, b"");
    }

    #[test]
    fn debug_never_formats_secret_samples_or_the_wrapped_provider() {
        let gate = gate();
        let secret = b"secret-must-not-reach-debug";
        gate.record_secret(secret);
        let debug = format!("{gate:?}");
        assert!(debug.contains("flow-regression"));
        assert!(!debug.contains("secret-must-not-reach-debug"));
        assert!(!debug.contains(&format!("{secret:?}")));
        assert!(!debug.contains("DenyAllHostIo"));
    }
}
