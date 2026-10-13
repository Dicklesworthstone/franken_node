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
//! as a secret *sample* (bounded). Explicit, capability-authorized environment
//! read responses are also sensitive sources, regardless of the variable name.
//! This provider never reads the ambient process environment itself. Descriptor
//! reads carry the classification captured at successful open and any later
//! inherited source classification; unknown descriptors are treated as sensitive.
//! Copy and rename propagate sensitivity before the effect, including a copy
//! that writes before failing. Ordinary writes, append and descriptor writes
//! containing a known sample also label their destination before delegation.
//! Observed rename/symlink relationships remain live: a later sensitive write
//! or copy into their target reclassifies aliases and already-open descriptors.
//! Before any subsequent network effect, the gate checks whether the outbound
//! payload or destination CONTAINS a secret sample, literally or as a direct
//! hex/base64/base64url encoding; if so — and absent a valid declassification
//! (operator-authorized override, not yet wired) — the effect fails closed with
//! [`HostIoError::Denied`] and never reaches the wrapped provider. The engine's
//! host-I/O transcript records the denial.
//!
//! Containment (not exact-hash) is required because an http egress payload is
//! the *framed* request (headers + body) — the secret appears as a substring.
//! Destination strings are also outbound data: DNS can disclose a hostname
//! before a socket opens, and even `NetworkRecv` initiates a fresh connection.
//! A nonempty sensitive read that cannot be retained within the sample bounds
//! makes tracking incomplete for the rest of the run. Local I/O still works,
//! but network effects fail closed rather than forgetting an exposed secret.
//!
//! File provenance uses conservative, case-insensitive basename labels, matching
//! the existing sensitive-source classifier without assuming a provider's root.
//! Moving directories or switching between absolute and relative paths cannot
//! shed a derived label. Unrelated files with the same basename may therefore
//! be overclassified. Labels persist for the run, including after failed I/O,
//! unlink, replacement, or overwrite; label-budget exhaustion closes egress.
//! This is not inode tracking and does not discover pre-existing filesystem
//! aliases or mutations made outside this provider.
//!
//! Scope. This gate prevents secret NETWORK egress only. A local `fs.write`
//! that copies a secret is not an external sink and is not blocked here. Its
//! destination remains sensitive so later partial reads cannot launder the
//! bytes through a public-looking filename or descriptor. Encoded matching
//! covers one direct encoding of a complete sample, including padded/unpadded
//! base64 and mixed-case hex. Arbitrary slicing before a write, nested encodings,
//! or encoding a sample together with other data still need per-datum engine
//! lineage; this is not a general taint engine. Behavioral coverage lives in
//! `crates/franken-node/tests/native_engine_compat.rs` and the registered
//! `ssrf_gated_host_io_egress` integration target.

#[cfg(feature = "engine")]
use std::collections::{BTreeMap, BTreeSet};
#[cfg(feature = "engine")]
use std::path::Path;
#[cfg(feature = "engine")]
use std::sync::{Arc, Mutex};

#[cfg(feature = "engine")]
use base64::Engine as _;
#[cfg(feature = "engine")]
use frankenengine_extension_host::host_io::{
    FsMetaResult, FsOperation, HostIoCapability, HostIoControl, HostIoError,
    HostIoExceptionProvenance, HostIoOutcome, HostIoProvider, HostIoRequest, HostIoResponse,
};

#[cfg(feature = "engine")]
use crate::security::lineage_tracker::classify_sensitive_source_path;

/// Bounds for containment tracking. Reads outside these bounds are NOT public:
/// a nonempty untrackable read permanently closes the network gate. Each source
/// owns four bounded patterns and their u32 failure tables (under 29 MiB total
/// pattern storage at the maximum sample count). Encodings do not consume extra
/// source slots. Empty reads reveal no bytes and do not consume the budget.
#[cfg(feature = "engine")]
const MIN_SECRET_SAMPLE_LEN: usize = 8;
#[cfg(feature = "engine")]
const MAX_SECRET_SAMPLE_LEN: usize = 64 * 1024;
#[cfg(feature = "engine")]
const MAX_SECRET_SAMPLES: usize = 16;
/// Untracked descriptors remain readable, but their bytes are sensitive. Never
/// evict an active descriptor and accidentally classify an unknown one public.
#[cfg(feature = "engine")]
const MAX_TRACKED_DESCRIPTORS: usize = 1_024;
#[cfg(feature = "engine")]
const MAX_DERIVED_SOURCE_NAMES: usize = 1_024;
#[cfg(feature = "engine")]
const MAX_SOURCE_NAME_BYTES: usize = 4_096;
#[cfg(feature = "engine")]
const MAX_FILE_ALIAS_EDGES: usize = 1_024;

#[cfg(feature = "engine")]
struct DescriptorSource {
    name: Option<String>,
    sensitive_at_open: bool,
}

/// No stored label is ever evicted or downgraded. Name-based overclassification
/// is preferable to claiming an inode identity the provider does not expose.
#[cfg(feature = "engine")]
#[derive(Default)]
struct FileLineage {
    sensitive_names: BTreeSet<String>,
    /// Sticky, undirected name relationships for objects reached by rename or
    /// symlink. Copies deliberately do NOT equate identities: later mutations
    /// of an independent public copy must not mark its original source secret.
    aliases: BTreeMap<String, BTreeSet<String>>,
    alias_edge_count: usize,
    incomplete: bool,
}

#[cfg(feature = "engine")]
fn source_name(path: &str) -> Option<String> {
    let name = Path::new(path).file_name()?.to_str()?;
    if name.is_empty() || name.len() > MAX_SOURCE_NAME_BYTES || name.contains('\0') {
        return None;
    }
    Some(name.to_ascii_lowercase())
}

#[cfg(feature = "engine")]
impl FileLineage {
    fn is_sensitive(&self, path: &str) -> bool {
        if classify_sensitive_source_path(path).is_some() {
            return true;
        }
        let Some(name) = source_name(path) else {
            return true;
        };
        // Each name is visited once. The stored edge cap also bounds this
        // traversal and its temporary worklist, including cycles/self-links.
        let mut visited = BTreeSet::new();
        let mut pending = vec![name.as_str()];
        while let Some(current) = pending.pop() {
            if !visited.insert(current) {
                continue;
            }
            if classify_sensitive_source_path(current).is_some()
                || self.sensitive_names.contains(current)
            {
                return true;
            }
            if let Some(neighbors) = self.aliases.get(current) {
                pending.extend(neighbors.iter().map(String::as_str));
            }
        }
        false
    }

    fn link_names(&mut self, source: &str, destination: &str) {
        let (Some(left), Some(right)) = (source_name(source), source_name(destination)) else {
            // For example, a link to a directory '..' has no final source
            // name. Its alias cannot be declared public on that basis.
            self.mark_sensitive(destination);
            return;
        };
        if left == right {
            return;
        }
        if self
            .aliases
            .get(&left)
            .is_some_and(|neighbors| neighbors.contains(&right))
        {
            return;
        }
        if self.alias_edge_count >= MAX_FILE_ALIAS_EDGES {
            self.incomplete = true;
        } else {
            self.aliases
                .entry(left.clone())
                .or_default()
                .insert(right.clone());
            self.aliases.entry(right).or_default().insert(left);
            self.alias_edge_count += 1;
        }
    }

    fn mark_sensitive(&mut self, path: &str) {
        let Some(name) = source_name(path) else {
            self.incomplete = true;
            return;
        };
        if self.sensitive_names.contains(&name) {
            return;
        }
        if self.sensitive_names.len() >= MAX_DERIVED_SOURCE_NAMES {
            self.incomplete = true;
        } else {
            self.sensitive_names.insert(name);
        }
    }

    fn prepare_transfer(&mut self, operation: FsOperation, source: &str, destination: &str) {
        if matches!(operation, FsOperation::Rename | FsOperation::Symlink) {
            self.link_names(source, destination);
        }
        if self.is_sensitive(source) {
            self.mark_sensitive(destination);
        }
        // An already-open source descriptor still refers to the renamed file.
        // Never leave it public when its new name is a protected source name.
        if operation == FsOperation::Rename && self.is_sensitive(destination) {
            self.mark_sensitive(source);
        }
    }
}

/// Compiled KMP pattern. Neither bytes nor failure tables implement Debug:
/// even derived encodings and prefix lengths disclose protected source data.
/// Compilation is linear in the bounded sample; matching is linear in outbound
/// bytes and allocates nothing, including adversarial repeated-prefix inputs.
#[cfg(feature = "engine")]
struct SecretPattern {
    bytes: Vec<u8>,
    failure: Vec<u32>,
    ascii_case_insensitive: bool,
}

#[cfg(feature = "engine")]
impl SecretPattern {
    fn new(mut bytes: Vec<u8>, ascii_case_insensitive: bool) -> Self {
        if ascii_case_insensitive {
            bytes.make_ascii_lowercase();
        }
        let mut failure = vec![0_u32; bytes.len()];
        let mut matched = 0;
        for index in 1..bytes.len() {
            while matched > 0 && bytes[index] != bytes[matched] {
                matched = failure[matched - 1] as usize;
            }
            if bytes[index] == bytes[matched] {
                matched += 1;
            }
            failure[index] = u32::try_from(matched).expect("bounded secret pattern length");
        }
        Self {
            bytes,
            failure,
            ascii_case_insensitive,
        }
    }

    fn occurs_in(&self, outbound: &[u8]) -> bool {
        if self.bytes.is_empty() || self.bytes.len() > outbound.len() {
            return false;
        }
        let mut matched = 0;
        for byte in outbound {
            let byte = if self.ascii_case_insensitive {
                byte.to_ascii_lowercase()
            } else {
                *byte
            };
            while matched > 0 && byte != self.bytes[matched] {
                matched = self.failure[matched - 1] as usize;
            }
            if byte == self.bytes[matched] {
                matched += 1;
                if matched == self.bytes.len() {
                    return true;
                }
            }
        }
        false
    }
}

#[cfg(feature = "engine")]
struct SecretSample {
    patterns: [SecretPattern; 4],
}

#[cfg(feature = "engine")]
impl SecretSample {
    fn new(bytes: &[u8]) -> Self {
        use base64::engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD};
        Self {
            patterns: [
                SecretPattern::new(bytes.to_vec(), false),
                SecretPattern::new(hex::encode(bytes).into_bytes(), true),
                // Omitting terminal padding matches both padded and unpadded
                // forms as substrings. Base64 itself remains case-sensitive.
                SecretPattern::new(STANDARD_NO_PAD.encode(bytes).into_bytes(), false),
                SecretPattern::new(URL_SAFE_NO_PAD.encode(bytes).into_bytes(), false),
            ],
        }
    }

    fn source_bytes(&self) -> &[u8] {
        &self.patterns[0].bytes
    }

    fn occurs_in(&self, outbound: &[u8]) -> bool {
        self.patterns.iter().any(|pattern| pattern.occurs_in(outbound))
    }
}

#[cfg(feature = "engine")]
#[derive(Default)]
struct SecretSamples {
    samples: Vec<SecretSample>,
    /// Sticky: dropping a sample must never restore permission to exfiltrate it.
    incomplete: bool,
}

/// Match the host provider's first `fd=` argument semantics, including refusing
/// an invalid first value rather than silently selecting a later duplicate.
#[cfg(feature = "engine")]
fn descriptor_argument(arguments: &[String]) -> Option<u64> {
    arguments
        .iter()
        .find_map(|argument| argument.strip_prefix("fd="))
        .and_then(|value| value.parse().ok())
}

/// A [`HostIoProvider`] decorator that fails a network egress closed when its
/// bytes carry a secret this run read. Wrap it OUTSIDE the SSRF gate so a
/// secret-carrying egress is refused before endpoint evaluation.
#[cfg(feature = "engine")]
pub struct FlowGatedHostIo<P: HostIoProvider> {
    inner: P,
    /// Secret-source byte samples observed during this run (bounded).
    secrets: Mutex<SecretSamples>,
    /// Open guest descriptor -> whether its source is sensitive. Hold this
    /// lock across descriptor effects AND updates so concurrent close/reopen
    /// cannot change a read's provenance between the effect and observation.
    descriptors: Mutex<BTreeMap<u64, DescriptorSource>>,
    /// Lock order: lineage -> descriptors -> samples. Held through filesystem
    /// effects/observations and network authorization/delegation, so a write into
    /// an open file cannot race a read or a network authorization on this gate.
    lineage: Mutex<FileLineage>,
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
            descriptors: Mutex::new(BTreeMap::new()),
            lineage: Mutex::new(FileLineage::default()),
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
            if secrets
                .samples
                .iter()
                .any(|existing| existing.source_bytes() == bytes)
            {
                return;
            }
            if secrets.samples.len() >= MAX_SECRET_SAMPLES {
                secrets.incomplete = true;
            } else {
                secrets.samples.push(SecretSample::new(bytes));
            }
        }
    }

    /// Classification is not an authorization to deny local writes. Once
    /// tracking is incomplete or poisoned, nonempty writes conservatively carry
    /// sensitivity; neither a write nor an overwrite may restore egress.
    fn write_carries_secret(&self, data: &[u8]) -> bool {
        if data.is_empty() {
            return false;
        }
        match self.secrets.lock() {
            Ok(secrets) => {
                secrets.incomplete || secrets.samples.iter().any(|sample| sample.occurs_in(data))
            }
            Err(_) => true,
        }
    }

    /// Descriptor writes must use the identity captured at open, never the
    /// guest-supplied path field. Retain labels even if the provider reports an
    /// error after a partial write. Unknown identities close egress instead of
    /// guessing a destination; local descriptor I/O is still delegated.
    fn perform_descriptor_write(
        &self,
        arguments: &[String],
        data: &[u8],
        lineage: &mut FileLineage,
        perform_inner: &dyn Fn() -> HostIoOutcome,
    ) -> HostIoOutcome {
        let descriptors = self.descriptors.lock().map_err(|_| HostIoError::Denied {
            reason: format!(
                "flow_policy: descriptor tracking lock poisoned ({})",
                self.trace_id
            ),
        })?;
        if self.write_carries_secret(data) {
            match descriptor_argument(arguments)
                .and_then(|fd| descriptors.get(&fd))
                .and_then(|source| source.name.as_deref())
            {
                Some(name) => lineage.mark_sensitive(name),
                None => lineage.incomplete = true,
            }
        }
        perform_inner()
    }

    fn perform_descriptor_operation(
        &self,
        operation: FsOperation,
        path: &str,
        arguments: &[String],
        lineage: &FileLineage,
        perform_inner: &dyn Fn() -> HostIoOutcome,
    ) -> HostIoOutcome {
        let mut descriptors = self.descriptors.lock().map_err(|_| HostIoError::Denied {
            reason: format!(
                "flow_policy: descriptor tracking lock poisoned ({})",
                self.trace_id
            ),
        })?;
        let outcome = perform_inner();
        let Ok(response) = &outcome else {
            // A denied open/close must not create or erase provenance.
            return outcome;
        };
        match (operation, response) {
            (
                FsOperation::Open,
                HostIoResponse::FsMeta {
                    result: FsMetaResult::Unsigned(fd),
                },
            ) => {
                if descriptors.len() < MAX_TRACKED_DESCRIPTORS || descriptors.contains_key(fd) {
                    descriptors.insert(
                        *fd,
                        DescriptorSource {
                            name: source_name(path),
                            sensitive_at_open: lineage.is_sensitive(path),
                        },
                    );
                }
            }
            (
                FsOperation::ReadFd,
                HostIoResponse::FsMeta {
                    result: FsMetaResult::Bytes(bytes),
                },
            ) => {
                let known_public = descriptor_argument(arguments)
                    .and_then(|fd| descriptors.get(&fd))
                    .is_some_and(|source| {
                        !source.sensitive_at_open
                            && source
                                .name
                                .as_ref()
                                .is_some_and(|name| !lineage.is_sensitive(name))
                    });
                if !known_public {
                    self.record_secret(bytes);
                }
            }
            (
                FsOperation::CloseFd,
                HostIoResponse::FsMeta {
                    result: FsMetaResult::Unit,
                },
            ) => {
                if let Some(fd) = descriptor_argument(arguments) {
                    descriptors.remove(&fd);
                }
                // Previously returned bytes remain sensitive after close.
            }
            _ => {
                return Err(HostIoError::Denied {
                    reason: format!(
                        "flow_policy: invalid descriptor effect response ({})",
                        self.trace_id
                    ),
                });
            }
        }
        outcome
    }

    /// `Ok(())` authorizes the egress; `Err(Denied)` fails it closed when the
    /// outbound bytes contain a retained secret sample. A poisoned lock denies
    /// fail-closed. Check tracking completeness even for empty payloads:
    /// connecting is still a host effect.
    fn check_outbound(&self, outbound: &[u8], lineage: &FileLineage) -> Result<(), HostIoError> {
        if lineage.incomplete {
            return Err(HostIoError::Denied {
                reason: format!(
                    "flow_policy: incomplete file lineage; network egress denied ({})",
                    self.trace_id
                ),
            });
        }
        if self.descriptors.is_poisoned() {
            return Err(HostIoError::Denied {
                reason: format!(
                    "flow_policy: descriptor tracking lock poisoned ({})",
                    self.trace_id
                ),
            });
        }
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
                .any(|sample| sample.occurs_in(outbound)),
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

    #[cfg(test)]
    fn gate_outbound(&self, outbound: &[u8]) -> Result<(), HostIoError> {
        let lineage = self.lineage.lock().map_err(|_| HostIoError::Denied {
            reason: "flow_policy: file lineage lock poisoned".to_string(),
        })?;
        self.check_outbound(outbound, &lineage)
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
        self.gate(request, granted, &|request, granted| {
            self.inner.perform(request, granted)
        })
    }

    /// The engine drives every effect through this entry with an
    /// operation-local supervisor; forwarding it (not calling the wrapped
    /// `perform`) keeps network I/O interruptible and reachable at all.
    fn perform_controlled(
        &self,
        request: &HostIoRequest,
        granted: &[HostIoCapability],
        control: Arc<dyn HostIoControl>,
    ) -> HostIoOutcome {
        self.gate(request, granted, &|request, granted| {
            self.inner
                .perform_controlled(request, granted, Arc::clone(&control))
        })
    }
}

#[cfg(feature = "engine")]
impl<P: HostIoProvider> FlowGatedHostIo<P> {
    /// Apply the flow policy, reaching the wrapped provider only via
    /// `dispatch` (plain or supervised, chosen by the caller).
    fn gate(
        &self,
        request: &HostIoRequest,
        granted: &[HostIoCapability],
        dispatch: &dyn Fn(&HostIoRequest, &[HostIoCapability]) -> HostIoOutcome,
    ) -> HostIoOutcome {
        // A request lacking authority must not mutate provenance or reach the
        // underlying mechanism. This check does not grant any extra read I/O.
        let capability = request.required_capability();
        if !granted.contains(&capability) {
            return Err(HostIoError::CapabilityMissing { capability });
        }
        let mut lineage = self.lineage.lock().map_err(|_| HostIoError::Denied {
            reason: format!(
                "flow_policy: file lineage lock poisoned ({})",
                self.trace_id
            ),
        })?;
        match request {
            // Check both channels before the effect: a hostname can disclose
            // secret data during DNS resolution even with an empty payload.
            HostIoRequest::NetworkSend { endpoint, payload }
            | HostIoRequest::NetworkRequest {
                endpoint, payload, ..
            } => {
                self.check_outbound(endpoint.as_bytes(), &lineage)?;
                self.check_outbound(payload, &lineage)?;
                dispatch(request, granted)
            }
            // Receive opens a new outbound socket too. It has no payload, but
            // its endpoint is still a sink and incomplete tracking must deny.
            HostIoRequest::NetworkRecv { endpoint, .. } => {
                self.check_outbound(endpoint.as_bytes(), &lineage)?;
                dispatch(request, granted)
            }
            HostIoRequest::EnvRead { .. } => {
                let outcome = dispatch(request, granted);
                if let Ok(HostIoResponse::EnvRead { value: Some(value) }) = &outcome {
                    self.record_secret(value.as_bytes());
                }
                outcome
            }
            // A sensitive read registers a secret sample AFTER it succeeds; the
            // read itself is a source, not a sink, and is never blocked.
            HostIoRequest::FsRead { path } => {
                let outcome = dispatch(request, granted);
                if lineage.is_sensitive(path)
                    && let Ok(HostIoResponse::FsRead { bytes }) = &outcome
                {
                    self.record_secret(bytes);
                }
                outcome
            }
            HostIoRequest::FsWrite { path, data }
            | HostIoRequest::FsMeta {
                operation: FsOperation::Write | FsOperation::Append,
                path,
                data,
                ..
            } => {
                if self.write_carries_secret(data) {
                    lineage.mark_sensitive(path);
                }
                dispatch(request, granted)
            }
            HostIoRequest::FsMeta {
                operation: FsOperation::WriteFd,
                arguments,
                data,
                ..
            } => self.perform_descriptor_write(arguments, data, &mut lineage, &|| {
                dispatch(request, granted)
            }),
            HostIoRequest::FsMeta {
                operation:
                    operation @ (FsOperation::Open | FsOperation::ReadFd | FsOperation::CloseFd),
                path,
                arguments,
                ..
            } => self.perform_descriptor_operation(*operation, path, arguments, &lineage, &|| {
                dispatch(request, granted)
            }),
            HostIoRequest::FsMeta {
                operation:
                    operation @ (FsOperation::CopyFile | FsOperation::Rename | FsOperation::Symlink),
                path,
                arguments,
                ..
            } => {
                // Match the host's FIRST positional destination argument.
                // Copy may write bytes and then fail (including in chmod), so
                // waiting for a successful result would leave a laundering path.
                if let Some(destination) = arguments.first() {
                    lineage.prepare_transfer(*operation, path, destination);
                }
                dispatch(request, granted)
            }
            // Metadata and entropy are not secret byte sources. In particular,
            // stat/readlink results are not file contents, and mutation metadata
            // must not clear labels recorded by an earlier write.
            HostIoRequest::FsMeta { .. } | HostIoRequest::RandomRead { .. } => {
                dispatch(request, granted)
            }
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

    /// Exercise the actual policy/delegation seam with a prescribed provider
    /// result, including a failure after a write may already have taken effect.
    fn dispatch_outcome(
        gate: &FlowGatedHostIo<DenyAllHostIo>,
        request: &HostIoRequest,
        outcome: HostIoOutcome,
    ) -> HostIoOutcome {
        gate.gate(request, &[request.required_capability()], &|_, _| {
            outcome.clone()
        })
    }

    fn open_test_descriptor(gate: &FlowGatedHostIo<DenyAllHostIo>, path: &str, fd: u64) {
        let request = HostIoRequest::FsMeta {
            operation: FsOperation::Open,
            path: path.into(),
            arguments: vec!["flags=r+".into()],
            data: Vec::new(),
        };
        dispatch_outcome(
            gate,
            &request,
            Ok(HostIoResponse::FsMeta {
                result: FsMetaResult::Unsigned(fd),
            }),
        )
        .expect("open fixture descriptor");
    }

    fn read_test_descriptor(gate: &FlowGatedHostIo<DenyAllHostIo>, fd: u64, bytes: &[u8]) {
        let request = HostIoRequest::FsMeta {
            operation: FsOperation::ReadFd,
            path: String::new(),
            arguments: vec![format!("fd={fd}")],
            data: Vec::new(),
        };
        dispatch_outcome(
            gate,
            &request,
            Ok(HostIoResponse::FsMeta {
                result: FsMetaResult::Bytes(bytes.to_vec()),
            }),
        )
        .expect("read fixture descriptor");
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
            assert!(
                gate.secrets
                    .lock()
                    .expect("sample state")
                    .samples
                    .is_empty()
            );
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

    #[test]
    fn descriptor_argument_matches_host_first_value_semantics() {
        assert_eq!(descriptor_argument(&[]), None);
        assert_eq!(
            descriptor_argument(&["path=7".into(), "fd=12".into()]),
            Some(12)
        );
        assert_eq!(
            descriptor_argument(&["fd=12".into(), "fd=7".into()]),
            Some(12)
        );
        assert_eq!(
            descriptor_argument(&["fd=12".into(), "fd=7".into()]),
            Some(12)
        );
        assert_eq!(
            descriptor_argument(&["fd=invalid".into(), "fd=7".into()]),
            None
        );
        assert_eq!(descriptor_argument(&["fd=-1".into()]), None);
        assert_eq!(
            descriptor_argument(&["fd=18446744073709551616".into()]),
            None
        );
    }

    #[test]
    fn poisoned_descriptor_tracking_closes_network_egress() {
        let gate = gate();
        let result = std::panic::catch_unwind(|| {
            let _guard = gate.descriptors.lock().expect("descriptor state");
            panic!("poison descriptor tracking for regression coverage");
        });
        assert!(result.is_err());
        assert_denied(&gate, b"public");
        assert_denied(&gate, b"");
    }

    #[test]
    fn destination_strings_are_sinks_for_every_network_variant() {
        let gate = gate();
        gate.record_secret(b"secret-host-label");
        let endpoint = "secret-host-label.example.invalid:443";
        let requests = [
            HostIoRequest::NetworkSend {
                endpoint: endpoint.into(),
                payload: Vec::new(),
            },
            HostIoRequest::NetworkRequest {
                endpoint: endpoint.into(),
                payload: Vec::new(),
                max_len: 1,
                use_tls: false,
            },
            HostIoRequest::NetworkRequest {
                endpoint: endpoint.into(),
                payload: Vec::new(),
                max_len: 1,
                use_tls: true,
            },
            HostIoRequest::NetworkRecv {
                endpoint: endpoint.into(),
                max_len: 1,
            },
        ];
        for request in requests {
            let outcome = gate.perform(&request, &[request.required_capability()]);
            assert!(matches!(
                outcome,
                Err(HostIoError::Denied { reason }) if reason.starts_with("flow_policy:")
            ));
        }
        let public_receive = HostIoRequest::NetworkRecv {
            endpoint: "public.example.invalid:443".into(),
            max_len: 1,
        };
        let granted = [HostIoCapability::NetworkRecv];
        assert_eq!(
            gate.perform(&public_receive, &granted),
            DenyAllHostIo.perform(&public_receive, &granted)
        );
    }

    #[test]
    fn incomplete_tracking_denies_receive_only_connections() {
        let gate = gate();
        gate.record_secret(b"x");
        let request = HostIoRequest::NetworkRecv {
            endpoint: "public.example.invalid:443".into(),
            max_len: 1,
        };
        let outcome = gate.perform(&request, &[HostIoCapability::NetworkRecv]);
        assert!(matches!(
            outcome,
            Err(HostIoError::Denied { reason }) if reason.starts_with("flow_policy:")
        ));
    }

    #[test]
    fn copies_and_renames_propagate_without_a_prior_read() {
        let mut lineage = FileLineage::default();
        lineage.prepare_transfer(FsOperation::CopyFile, ".env", "staging/cache");
        lineage.prepare_transfer(FsOperation::Rename, "staging/cache", "upload/body");
        assert!(lineage.is_sensitive("/different/provider/root/upload/body"));
        assert!(lineage.is_sensitive("./upload/body"));
        assert!(lineage.is_sensitive("staging/cache"));
        assert!(!lineage.is_sensitive("body-public"));
    }

    #[test]
    fn public_transfers_do_not_mark_sensitive_names() {
        let mut lineage = FileLineage::default();
        for index in 0..64 {
            lineage.prepare_transfer(FsOperation::CopyFile, "public", &format!("copy-{index}"));
            lineage.prepare_transfer(FsOperation::Rename, "public", &format!("move-{index}"));
        }
        assert!(lineage.sensitive_names.is_empty());
        assert!(!lineage.incomplete);
    }

    #[test]
    fn protected_rename_destination_taints_existing_source_identity() {
        let mut lineage = FileLineage::default();
        lineage.prepare_transfer(FsOperation::Rename, "public", ".env");
        assert!(lineage.is_sensitive("public"));
        // A copy creates a new object, unlike rename; the public source stays public.
        let mut copied = FileLineage::default();
        copied.prepare_transfer(FsOperation::CopyFile, "public", ".env");
        assert!(!copied.is_sensitive("public"));
    }

    #[test]
    fn derived_name_exhaustion_closes_egress_and_never_evicts() {
        let gate = gate();
        {
            let mut lineage = gate.lineage.lock().expect("lineage");
            for index in 0..MAX_DERIVED_SOURCE_NAMES {
                lineage.mark_sensitive(&format!("file-{index}"));
            }
            lineage.mark_sensitive("file-0");
            assert!(!lineage.incomplete);
            lineage.mark_sensitive("overflow");
            assert!(lineage.incomplete);
            assert_eq!(lineage.sensitive_names.len(), MAX_DERIVED_SOURCE_NAMES);
            assert!(lineage.is_sensitive("file-0"));
        }
        assert_denied(&gate, b"");
        assert_denied(&gate, b"public payload");
    }

    #[test]
    fn untrackable_source_names_never_become_public() {
        let mut lineage = FileLineage::default();
        assert!(lineage.is_sensitive(""));
        assert!(lineage.is_sensitive("../"));
        assert!(lineage.is_sensitive(".env/."));
        lineage.mark_sensitive(&"x".repeat(MAX_SOURCE_NAME_BYTES + 1));
        assert!(lineage.incomplete);
        assert!(lineage.sensitive_names.is_empty());
    }

    #[test]
    fn missing_capability_cannot_poison_source_provenance() {
        let gate = gate();
        let request = HostIoRequest::FsMeta {
            operation: FsOperation::CopyFile,
            path: ".env".into(),
            arguments: vec!["otherwise-public".into()],
            data: Vec::new(),
        };
        assert!(matches!(
            gate.perform(&request, &[]),
            Err(HostIoError::CapabilityMissing { .. })
        ));
        assert!(
            !gate
                .lineage
                .lock()
                .expect("lineage")
                .is_sensitive("otherwise-public")
        );
    }

    #[test]
    fn poisoned_lineage_denies_network_and_is_not_recovered() {
        let gate = gate();
        let poisoned = std::panic::catch_unwind(|| {
            let _guard = gate.lineage.lock().expect("lineage");
            panic!("poison lineage for regression coverage");
        });
        assert!(poisoned.is_err());
        assert_denied(&gate, b"");
        let request = HostIoRequest::NetworkRecv {
            endpoint: "public.example.invalid:443".into(),
            max_len: 1,
        };
        assert!(matches!(
            gate.perform(&request, &[HostIoCapability::NetworkRecv]),
            Err(HostIoError::Denied { reason }) if reason.starts_with("flow_policy:")));
    }

    #[test]
    fn aliases_and_renamed_descriptors_follow_later_target_taint() {
        let mut lineage = FileLineage::default();
        lineage.prepare_transfer(FsOperation::Symlink, "target", "alias");
        lineage.prepare_transfer(FsOperation::Rename, "alias", "moved-alias");
        lineage.prepare_transfer(FsOperation::Rename, "target", "new-target");
        assert!(!lineage.is_sensitive("moved-alias"));
        lineage.prepare_transfer(FsOperation::CopyFile, ".env", "new-target");
        for name in ["target", "new-target", "alias", "moved-alias"] {
            assert!(lineage.is_sensitive(name), "lost taint at {name}");
        }
    }

    #[test]
    fn public_copy_does_not_alias_its_source_for_later_taint() {
        let mut lineage = FileLineage::default();
        lineage.prepare_transfer(FsOperation::CopyFile, "source", "copy");
        lineage.prepare_transfer(FsOperation::CopyFile, ".env", "copy");
        assert!(lineage.is_sensitive("copy"));
        assert!(!lineage.is_sensitive("source"));
    }

    #[test]
    fn alias_cycles_are_bounded_and_duplicate_edges_cost_no_budget() {
        let mut lineage = FileLineage::default();
        lineage.link_names("a", "b");
        lineage.link_names("b", "c");
        lineage.link_names("c", "a");
        lineage.link_names("b", "a");
        lineage.link_names("a", "a");
        assert_eq!(lineage.alias_edge_count, 3);
        assert!(!lineage.is_sensitive("a"));
        lineage.mark_sensitive("c");
        assert!(lineage.is_sensitive("a"));
        assert!(lineage.is_sensitive("b"));
    }

    #[test]
    fn alias_exhaustion_is_sticky_and_retains_old_relationships() {
        let gate = gate();
        {
            let mut lineage = gate.lineage.lock().expect("lineage");
            for index in 0..MAX_FILE_ALIAS_EDGES {
                lineage.link_names("target", &format!("alias-{index}"));
            }
            lineage.link_names("alias-0", "target");
            assert!(!lineage.incomplete);
            lineage.link_names("target", "one-too-many");
            assert!(lineage.incomplete);
            assert_eq!(lineage.alias_edge_count, MAX_FILE_ALIAS_EDGES);
            lineage.mark_sensitive("target");
            assert!(lineage.is_sensitive("alias-0"));
        }
        assert_denied(&gate, b"");
        assert_denied(&gate, b"public");
    }

    #[test]
    fn encoded_samples_block_both_base64_alphabets_padding_and_hex_case() {
        use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
        for length in [8, 9, 10] {
            let gate = gate();
            // Force both alphabet-specific characters and all padding lengths.
            let secret = [0xfb, 0xff, 0xff, 0xab, 0xcd, 0xef, 0x7f, 0x01, 0x02, 0x03];
            let secret = &secret[..length];
            gate.record_secret(secret);
            let mixed_hex: String = hex::encode(secret)
                .chars()
                .enumerate()
                .map(|(index, value)| {
                    if index % 2 == 0 {
                        value.to_ascii_uppercase()
                    } else {
                        value
                    }
                })
                .collect();
            for encoded in [
                STANDARD.encode(secret),
                STANDARD_NO_PAD.encode(secret),
                URL_SAFE.encode(secret),
                URL_SAFE_NO_PAD.encode(secret),
                hex::encode(secret),
                hex::encode_upper(secret),
                mixed_hex,
            ] {
                assert_denied(&gate, format!("header:{encoded}:trailer").as_bytes());
            }
            assert!(gate.gate_outbound(b"unrelated public data").is_ok());
            let samples = gate.secrets.lock().expect("sample state");
            assert_eq!(samples.samples.len(), 1);
            assert!(!samples.incomplete);
        }
    }

    #[test]
    fn compiled_matcher_agrees_with_containment_for_overlaps_and_case() {
        for needle in [
            b"a".as_slice(),
            b"aaaab",
            b"ababa",
            b"aabaaa",
            b"ABcd",
            b"\0\xff\0",
        ] {
            for fold in [false, true] {
                let pattern = SecretPattern::new(needle.to_vec(), fold);
                for haystack in [
                    b"".as_slice(),
                    b"aaaaaaaab",
                    b"abababababa",
                    b"aabaaabaaa",
                    b"xxaBcDyy",
                    b"\0\0\xff\0",
                ] {
                    let expected = haystack.windows(needle.len()).any(|window| {
                        if fold {
                            window.eq_ignore_ascii_case(needle)
                        } else {
                            window == needle
                        }
                    });
                    assert_eq!(pattern.occurs_in(haystack), expected);
                }
            }
        }
        assert!(!SecretPattern::new(Vec::new(), false).occurs_in(b"public"));
        let pattern = SecretPattern::new(
            [vec![b'a'; MAX_SECRET_SAMPLE_LEN - 1], vec![b'b']].concat(),
            false,
        );
        assert!(!pattern.occurs_in(&vec![b'a'; MAX_SECRET_SAMPLE_LEN * 4]));
    }

    #[test]
    fn encoded_network_requests_are_denied_before_provider_dispatch() {
        use base64::engine::general_purpose::STANDARD;
        use std::sync::atomic::{AtomicUsize, Ordering};

        #[derive(Debug)]
        struct ObservingHost {
            network_calls: Arc<AtomicUsize>,
        }
        impl HostIoProvider for ObservingHost {
            fn name(&self) -> &str {
                "flow-regression-provider"
            }

            fn perform(&self, request: &HostIoRequest, _: &[HostIoCapability]) -> HostIoOutcome {
                if matches!(request, HostIoRequest::FsRead { .. }) {
                    return Ok(HostIoResponse::FsRead {
                        bytes: b"secret-token".to_vec(),
                    });
                }
                self.network_calls.fetch_add(1, Ordering::SeqCst);
                Err(HostIoError::Io {
                    detail: "provider reached".into(),
                })
            }
        }
        let calls = Arc::new(AtomicUsize::new(0));
        let gate = FlowGatedHostIo::new(
            ObservingHost {
                network_calls: Arc::clone(&calls),
            },
            "encoded-egress",
        );
        let read = HostIoRequest::FsRead {
            path: ".env".into(),
        };
        gate.perform(&read, &[read.required_capability()])
            .expect("protected read");
        let encoded = STANDARD.encode(b"secret-token").into_bytes();
        let secret_endpoint = format!("{}.example.invalid:443", hex::encode(b"secret-token"));
        for request in [
            HostIoRequest::NetworkSend {
                endpoint: "public.example.invalid:443".into(),
                payload: encoded.clone(),
            },
            HostIoRequest::NetworkRequest {
                endpoint: "public.example.invalid:443".into(),
                payload: encoded,
                max_len: 1,
                use_tls: true,
            },
            HostIoRequest::NetworkSend {
                endpoint: secret_endpoint.clone(),
                payload: Vec::new(),
            },
            HostIoRequest::NetworkRequest {
                endpoint: secret_endpoint.clone(),
                payload: Vec::new(),
                max_len: 1,
                use_tls: false,
            },
            HostIoRequest::NetworkRecv {
                endpoint: secret_endpoint,
                max_len: 1,
            },
        ] {
            assert!(matches!(
                gate.perform(&request, &[request.required_capability()]),
                Err(HostIoError::Denied { reason }) if reason.starts_with("flow_policy:")
            ));
        }
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        let public = HostIoRequest::NetworkRecv {
            endpoint: "public.example.invalid:443".into(),
            max_len: 1,
        };
        assert!(matches!(
            gate.perform(&public, &[public.required_capability()]),
            Err(HostIoError::Io { .. })
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn writes_and_appends_label_aliases_and_open_descriptors_even_after_failure() {
        for operation in [None, Some(FsOperation::Write), Some(FsOperation::Append)] {
            for fail_after_write in [false, true] {
                for encoded in [false, true] {
                    let gate = gate();
                    gate.record_secret(b"secret-token");
                    gate.lineage
                        .lock()
                        .expect("lineage")
                        .prepare_transfer(FsOperation::Symlink, "cache", "alias");
                    open_test_descriptor(&gate, "alias", 7);
                    let data = if encoded {
                        hex::encode(b"secret-token").into_bytes()
                    } else {
                        b"secret-token".to_vec()
                    };
                    let fragment = data[..8].to_vec();
                    // A fragment is not a complete original sample. The later
                    // denial must come from the write's inherited source label.
                    assert!(gate.gate_outbound(&fragment).is_ok());
                    let request = match operation {
                        None => HostIoRequest::FsWrite {
                            path: "cache".into(),
                            data,
                        },
                        Some(operation) => HostIoRequest::FsMeta {
                            operation,
                            path: "cache".into(),
                            arguments: Vec::new(),
                            data,
                        },
                    };
                    let expected = if fail_after_write {
                        Err(HostIoError::Io {
                            detail: "fixture: partial write before failure".into(),
                        })
                    } else if operation.is_none() {
                        Ok(HostIoResponse::FsWrite { bytes_written: 8 })
                    } else {
                        Ok(HostIoResponse::FsMeta {
                            result: FsMetaResult::Unit,
                        })
                    };
                    assert_eq!(dispatch_outcome(&gate, &request, expected.clone()), expected);
                    {
                        let lineage = gate.lineage.lock().expect("lineage");
                        assert!(lineage.is_sensitive("cache"));
                        assert!(lineage.is_sensitive("alias"));
                        assert!(!lineage.is_sensitive("public"));
                    }
                    read_test_descriptor(&gate, 7, &fragment);
                    assert_denied(&gate, &fragment);
                    assert!(gate.gate_outbound(b"unrelated public payload").is_ok());
                }
            }
        }
    }

    #[test]
    fn descriptor_writes_use_captured_identity_and_first_fd_not_guest_path() {
        for fail_after_write in [false, true] {
            let gate = gate();
            gate.record_secret(b"secret-token");
            open_test_descriptor(&gate, "cache", 7);
            open_test_descriptor(&gate, "public", 8);
            let request = HostIoRequest::FsMeta {
                operation: FsOperation::WriteFd,
                path: "forged-destination".into(),
                arguments: vec!["fd=7".into(), "fd=8".into()],
                data: hex::encode(b"secret-token").into_bytes(),
            };
            let expected = if fail_after_write {
                Err(HostIoError::Io {
                    detail: "fixture: partial descriptor write".into(),
                })
            } else {
                Ok(HostIoResponse::FsMeta {
                    result: FsMetaResult::Unsigned(8),
                })
            };
            assert_eq!(dispatch_outcome(&gate, &request, expected.clone()), expected);
            {
                let lineage = gate.lineage.lock().expect("lineage");
                assert!(lineage.is_sensitive("cache"));
                assert!(!lineage.is_sensitive("public"));
                assert!(!lineage.is_sensitive("forged-destination"));
                assert!(!lineage.incomplete);
            }
            let fragment = b"73656372";
            assert!(gate.gate_outbound(fragment).is_ok());
            read_test_descriptor(&gate, 7, fragment);
            assert_denied(&gate, fragment);
        }
    }

    #[test]
    fn unknown_descriptor_secret_writes_close_egress_without_guessing_identity() {
        for arguments in [
            Vec::new(),
            vec!["fd=99".into()],
            vec!["fd=invalid".into(), "fd=7".into()],
        ] {
            let gate = gate();
            gate.record_secret(b"secret-token");
            open_test_descriptor(&gate, "public", 7);
            let request = HostIoRequest::FsMeta {
                operation: FsOperation::WriteFd,
                path: "claimed-destination".into(),
                arguments,
                data: b"secret-token".to_vec(),
            };
            let expected = Err(HostIoError::Io {
                detail: "fixture: descriptor write failed".into(),
            });
            assert_eq!(dispatch_outcome(&gate, &request, expected.clone()), expected);
            {
                let lineage = gate.lineage.lock().expect("lineage");
                assert!(lineage.incomplete);
                assert!(!lineage.is_sensitive("public"));
                assert!(!lineage.is_sensitive("claimed-destination"));
            }
            assert_denied(&gate, b"");
            assert_denied(&gate, b"public payload");
        }
    }

    #[test]
    fn public_and_empty_writes_stay_public_and_overwrites_cannot_clear_labels() {
        let gate = gate();
        gate.record_secret(b"secret-token");
        open_test_descriptor(&gate, "public", 7);
        for data in [Vec::new(), b"public payload".to_vec()] {
            for request in [
                HostIoRequest::FsWrite {
                    path: "public".into(),
                    data: data.clone(),
                },
                HostIoRequest::FsMeta {
                    operation: FsOperation::Append,
                    path: "public".into(),
                    arguments: Vec::new(),
                    data: data.clone(),
                },
                HostIoRequest::FsMeta {
                    operation: FsOperation::WriteFd,
                    path: "ignored".into(),
                    arguments: vec!["fd=7".into()],
                    data: data.clone(),
                },
            ] {
                // A failed ordinary write also must not taint an unrelated file.
                let expected = Err(HostIoError::Io {
                    detail: "fixture: public write failure".into(),
                });
                assert_eq!(dispatch_outcome(&gate, &request, expected.clone()), expected);
            }
        }
        assert!(!gate.lineage.lock().expect("lineage").is_sensitive("public"));
        assert!(gate.gate_outbound(b"public payload").is_ok());
        for data in [b"secret-token".to_vec(), b"public overwrite".to_vec()] {
            let request = HostIoRequest::FsWrite {
                path: "cache".into(),
                data,
            };
            dispatch_outcome(
                &gate,
                &request,
                Ok(HostIoResponse::FsWrite { bytes_written: 12 }),
            )
            .expect("local write is allowed");
        }
        assert!(gate.lineage.lock().expect("lineage").is_sensitive("cache"));
    }

    #[test]
    fn write_capability_is_checked_before_any_label_or_incomplete_state_changes() {
        let gate = gate();
        gate.record_secret(b"secret-token");
        for request in [
            HostIoRequest::FsWrite {
                path: "public".into(),
                data: b"secret-token".to_vec(),
            },
            HostIoRequest::FsMeta {
                operation: FsOperation::Append,
                path: "public".into(),
                arguments: Vec::new(),
                data: b"secret-token".to_vec(),
            },
            HostIoRequest::FsMeta {
                operation: FsOperation::WriteFd,
                path: "public".into(),
                arguments: vec!["fd=99".into()],
                data: b"secret-token".to_vec(),
            },
        ] {
            assert!(matches!(
                gate.perform(&request, &[]),
                Err(HostIoError::CapabilityMissing { .. })
            ));
        }
        let lineage = gate.lineage.lock().expect("lineage");
        assert!(lineage.sensitive_names.is_empty());
        assert!(!lineage.incomplete);
        drop(lineage);
        assert!(gate.gate_outbound(b"public payload").is_ok());
    }

    #[test]
    fn incomplete_or_poisoned_sample_tracking_keeps_nonempty_writes_sensitive() {
        for poison in [false, true] {
            let gate = gate();
            if poison {
                assert!(std::panic::catch_unwind(|| {
                    let _guard = gate.secrets.lock().expect("sample state");
                    panic!("fixture: poison sample tracking");
                })
                .is_err());
            } else {
                gate.record_secret(b"x");
            }
            for (path, data) in [("cache", b"public".as_slice()), ("empty", b"".as_slice())] {
                let request = HostIoRequest::FsWrite {
                    path: path.into(),
                    data: data.to_vec(),
                };
                dispatch_outcome(
                    &gate,
                    &request,
                    Ok(HostIoResponse::FsWrite {
                        bytes_written: u64::try_from(data.len()).expect("fixture size"),
                    }),
                )
                .expect("tracking failure does not block local writes");
            }
            {
                let lineage = gate.lineage.lock().expect("lineage");
                assert!(lineage.is_sensitive("cache"));
                assert!(!lineage.is_sensitive("empty"));
            }
            assert_denied(&gate, b"public payload");
            assert_denied(&gate, b"");
        }
    }

    #[test]
    fn explicit_environment_values_are_sensitive_regardless_of_variable_name() {
        use base64::engine::general_purpose::STANDARD;

        let gate = gate();
        let request = HostIoRequest::EnvRead {
            name: "PUBLIC_LOOKING_NAME".into(),
        };
        let expected = Ok(HostIoResponse::EnvRead {
            value: Some("secret-token".into()),
        });
        assert_eq!(dispatch_outcome(&gate, &request, expected.clone()), expected);
        assert_denied(&gate, b"header:secret-token:trailer");
        assert_denied(&gate, STANDARD.encode(b"secret-token").as_bytes());
        assert_denied(&gate, hex::encode_upper(b"secret-token").as_bytes());
        assert!(gate.gate_outbound(b"public payload").is_ok());
        // Repeated environment reads share the same source budget as files.
        dispatch_outcome(&gate, &request, expected).expect("repeated environment read");
        assert_eq!(gate.secrets.lock().expect("sample state").samples.len(), 1);
    }

    #[test]
    fn absent_empty_and_failed_environment_reads_do_not_consume_samples() {
        let gate = gate();
        let request = HostIoRequest::EnvRead {
            name: "EXPLICIT_FIXTURE_NAME".into(),
        };
        for expected in [
            Ok(HostIoResponse::EnvRead { value: None }),
            Ok(HostIoResponse::EnvRead {
                value: Some(String::new()),
            }),
            Err(HostIoError::Io {
                detail: "fixture: environment unavailable".into(),
            }),
        ] {
            assert_eq!(dispatch_outcome(&gate, &request, expected.clone()), expected);
        }
        let samples = gate.secrets.lock().expect("sample state");
        assert!(samples.samples.is_empty());
        assert!(!samples.incomplete);
        drop(samples);
        assert!(gate.gate_outbound(b"public payload").is_ok());
    }

    #[test]
    fn environment_capability_precedes_observation_and_short_values_fail_closed() {
        let gate = gate();
        let request = HostIoRequest::EnvRead {
            name: "EXPLICIT_FIXTURE_NAME".into(),
        };
        let outcome = gate.gate(&request, &[], &|_, _| {
            panic!("missing environment capability must never delegate")
        });
        assert!(matches!(outcome, Err(HostIoError::CapabilityMissing { .. })));
        assert!(gate.secrets.lock().expect("sample state").samples.is_empty());
        assert!(gate.gate_outbound(b"public payload").is_ok());
        dispatch_outcome(
            &gate,
            &request,
            Ok(HostIoResponse::EnvRead {
                value: Some("x".into()),
            }),
        )
        .expect("short environment source remains readable");
        assert_denied(&gate, b"public payload");
        assert_denied(&gate, b"");
    }
}
