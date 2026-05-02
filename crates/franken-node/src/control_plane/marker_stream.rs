//! bd-126h: Append-only marker stream for high-impact control events.
//!
//! Maintains a hash-chained, dense-sequence, append-only log of control events.
//! Invariant breaks trigger hard alerts via stable error codes.
//! Torn-tail recovery is deterministic.

use sha2::Digest;
use std::fmt;

use crate::push_bounded;

/// Maximum markers before oldest-first eviction.
const MAX_MARKERS: usize = 4096;

/// Genesis sentinel hash for sequence 0 (no predecessor).
const GENESIS_PREV_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Maximum divergence comparisons to prevent memory exhaustion during binary search.
/// Limits memory usage when attackers control input to create large shared lengths.
const MAX_DIVERGENCE_COMPARISONS: usize = 64;

fn len_to_u64(len: usize) -> u64 {
    u64::try_from(len).unwrap_or(u64::MAX)
}

fn sequence_offset(base: u64, sequence: u64) -> Option<usize> {
    if sequence < base {
        return None;
    }
    usize::try_from(sequence - base).ok()
}

/// High-impact control event categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MarkerEventType {
    TrustDecision,
    RevocationEvent,
    QuarantineAction,
    PolicyChange,
    EpochTransition,
    IncidentEscalation,
}

impl MarkerEventType {
    pub fn label(&self) -> &'static str {
        match self {
            Self::TrustDecision => "trust_decision",
            Self::RevocationEvent => "revocation_event",
            Self::QuarantineAction => "quarantine_action",
            Self::PolicyChange => "policy_change",
            Self::EpochTransition => "epoch_transition",
            Self::IncidentEscalation => "incident_escalation",
        }
    }

    pub fn from_label(s: &str) -> Option<Self> {
        match s {
            "trust_decision" => Some(Self::TrustDecision),
            "revocation_event" => Some(Self::RevocationEvent),
            "quarantine_action" => Some(Self::QuarantineAction),
            "policy_change" => Some(Self::PolicyChange),
            "epoch_transition" => Some(Self::EpochTransition),
            "incident_escalation" => Some(Self::IncidentEscalation),
            _ => None,
        }
    }

    pub fn all() -> &'static [MarkerEventType] {
        &[
            Self::TrustDecision,
            Self::RevocationEvent,
            Self::QuarantineAction,
            Self::PolicyChange,
            Self::EpochTransition,
            Self::IncidentEscalation,
        ]
    }
}

/// A single entry in the append-only marker stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Marker {
    pub sequence: u64,
    pub event_type: MarkerEventType,
    pub payload_hash: String,
    pub prev_hash: String,
    pub marker_hash: String,
    pub timestamp: u64,
    pub trace_id: String,
}

impl Marker {
    /// Compute the canonical hash for this marker.
    ///
    /// Compute length-prefixed hash over all marker fields.
    fn compute_hash(
        sequence: u64,
        event_type: MarkerEventType,
        payload_hash: &str,
        prev_hash: &str,
        timestamp: u64,
        trace_id: &str,
    ) -> String {
        let mut hasher = sha2::Sha256::new();
        sha2::Digest::update(&mut hasher, b"marker_stream_v1:");
        sha2::Digest::update(&mut hasher, sequence.to_le_bytes());
        for field in [event_type.label(), payload_hash, prev_hash] {
            sha2::Digest::update(&mut hasher, len_to_u64(field.len()).to_le_bytes());
            sha2::Digest::update(&mut hasher, field.as_bytes());
        }
        sha2::Digest::update(&mut hasher, timestamp.to_le_bytes());
        sha2::Digest::update(&mut hasher, len_to_u64(trace_id.len()).to_le_bytes());
        sha2::Digest::update(&mut hasher, trace_id.as_bytes());
        hex::encode(sha2::Digest::finalize(hasher))
    }
}

/// Hash type used in divergence results and evidence payloads.
pub type Hash = String;

/// One hash-comparison step captured while searching for divergence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DivergenceComparison {
    pub sequence: u64,
    pub matched: bool,
    pub local_hash_prefix: String,
    pub remote_hash_prefix: String,
}

/// Evidence emitted by the divergence finder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DivergenceEvidence {
    pub comparison_count: usize,
    pub comparisons: Vec<DivergenceComparison>,
}

/// Deterministic divergence search output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DivergenceResult {
    /// Whether a common prefix exists.
    pub has_common_prefix: bool,
    /// Last sequence in the common prefix when `has_common_prefix=true`.
    pub common_prefix_seq: u64,
    /// Whether the two streams diverge.
    pub has_divergence: bool,
    /// First sequence where the two streams differ when `has_divergence=true`.
    /// For identical streams this is the shared length.
    pub divergence_seq: u64,
    /// Local hash at divergence sequence (if one exists).
    pub local_hash_at_divergence: Option<Hash>,
    /// Remote hash at divergence sequence (if one exists).
    pub remote_hash_at_divergence: Option<Hash>,
    /// Full comparison evidence and count.
    pub evidence: DivergenceEvidence,
}

fn hash_prefix(hash: &str) -> String {
    hash.chars().take(16).collect()
}

fn compare_marker_hash_at(
    local: &MarkerStream,
    remote: &MarkerStream,
    sequence: u64,
    comparisons: &mut Vec<DivergenceComparison>,
) -> bool {
    let (Some(local_marker), Some(remote_marker)) = (local.get(sequence), remote.get(sequence))
    else {
        return false;
    };
    let local_hash = &local_marker.marker_hash;
    let remote_hash = &remote_marker.marker_hash;
    let matched = crate::security::constant_time::ct_eq(local_hash, remote_hash);

    push_bounded(
        comparisons,
        DivergenceComparison {
            sequence,
            matched,
            local_hash_prefix: hash_prefix(local_hash),
            remote_hash_prefix: hash_prefix(remote_hash),
        },
        MAX_DIVERGENCE_COMPARISONS,
    );

    matched
}

/// Find the first divergence point between two marker streams (bd-xwk5).
///
/// Returns:
/// - greatest common prefix sequence
/// - first divergence sequence
/// - per-side hashes at divergence
/// - search evidence including comparison trace
///
/// The comparison strategy is logarithmic over the shared prefix length.
pub fn find_divergence_point(local: &MarkerStream, remote: &MarkerStream) -> DivergenceResult {
    let local_len = len_to_u64(local.len());
    let remote_len = len_to_u64(remote.len());
    let shared_len = local_len.min(remote_len);
    let mut comparisons = Vec::new();

    // Degenerate case: one or both streams empty.
    if shared_len == 0 {
        let has_divergence = local_len != remote_len;
        return DivergenceResult {
            has_common_prefix: false,
            common_prefix_seq: 0,
            has_divergence,
            divergence_seq: 0,
            local_hash_at_divergence: local.marker_by_sequence(0).map(|m| m.marker_hash.clone()),
            remote_hash_at_divergence: remote.marker_by_sequence(0).map(|m| m.marker_hash.clone()),
            evidence: DivergenceEvidence {
                comparison_count: 0,
                comparisons,
            },
        };
    }

    // Binary search for first mismatch over [0, shared_len).
    let mut lo = 0_u64;
    let mut hi = shared_len;
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        if compare_marker_hash_at(local, remote, mid, &mut comparisons) {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }

    let (has_divergence, divergence_seq) = if lo < shared_len {
        (true, lo)
    } else if local_len != remote_len {
        (true, shared_len)
    } else {
        (false, shared_len)
    };

    let has_common_prefix = divergence_seq > 0;
    let common_prefix_seq = if has_common_prefix {
        divergence_seq - 1
    } else {
        0
    };

    DivergenceResult {
        has_common_prefix,
        common_prefix_seq,
        has_divergence,
        divergence_seq,
        local_hash_at_divergence: local
            .marker_by_sequence(divergence_seq)
            .map(|m| m.marker_hash.clone()),
        remote_hash_at_divergence: remote
            .marker_by_sequence(divergence_seq)
            .map(|m| m.marker_hash.clone()),
        evidence: DivergenceEvidence {
            comparison_count: comparisons.len(),
            comparisons,
        },
    }
}

/// Errors from marker stream operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MarkerStreamError {
    SequenceGap {
        expected: u64,
        got: u64,
    },
    HashChainBreak {
        sequence: u64,
        expected: String,
        got: String,
    },
    TimeRegression {
        sequence: u64,
        prev_ts: u64,
        got_ts: u64,
    },
    EmptyStream,
    IntegrityFailure {
        sequence: u64,
        detail: String,
    },
    TornTail {
        sequence: u64,
        marker_hash: String,
    },
    InvalidPayload {
        reason: String,
    },
}

impl MarkerStreamError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::SequenceGap { .. } => "MKS_SEQUENCE_GAP",
            Self::HashChainBreak { .. } => "MKS_HASH_CHAIN_BREAK",
            Self::TimeRegression { .. } => "MKS_TIME_REGRESSION",
            Self::EmptyStream => "MKS_EMPTY_STREAM",
            Self::IntegrityFailure { .. } => "MKS_INTEGRITY_FAILURE",
            Self::TornTail { .. } => "MKS_TORN_TAIL",
            Self::InvalidPayload { .. } => "MKS_INVALID_PAYLOAD",
        }
    }
}

impl fmt::Display for MarkerStreamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SequenceGap { expected, got } => {
                write!(f, "MKS_SEQUENCE_GAP: expected seq {expected}, got {got}")
            }
            Self::HashChainBreak {
                sequence,
                expected,
                got,
            } => write!(
                f,
                "MKS_HASH_CHAIN_BREAK: at seq {sequence}, expected {expected}, got {got}"
            ),
            Self::TimeRegression {
                sequence,
                prev_ts,
                got_ts,
            } => write!(
                f,
                "MKS_TIME_REGRESSION: at seq {sequence}, prev_ts={prev_ts}, got_ts={got_ts}"
            ),
            Self::EmptyStream => write!(f, "MKS_EMPTY_STREAM: operation requires non-empty stream"),
            Self::IntegrityFailure { sequence, detail } => {
                write!(f, "MKS_INTEGRITY_FAILURE: at seq {sequence}: {detail}")
            }
            Self::TornTail {
                sequence,
                marker_hash,
            } => write!(f, "MKS_TORN_TAIL: seq {sequence}, hash={marker_hash}"),
            Self::InvalidPayload { reason } => write!(f, "MKS_INVALID_PAYLOAD: {reason}"),
        }
    }
}

/// Append-only marker stream with dense sequence and hash-chain invariants.
#[derive(Debug)]
pub struct MarkerStream {
    markers: Vec<Marker>,
    /// Tracks the total number of markers ever appended, even after
    /// oldest entries are drained by the capacity bound.
    total_appended: u64,
    /// Anchor hash: marker_hash of the most recently evicted marker.
    /// Used to maintain hash-chain integrity after capacity-bound eviction
    /// so that verify_integrity can validate the first retained marker's prev_hash.
    chain_anchor_hash: Option<String>,
}

impl MarkerStream {
    /// Create a new empty marker stream.
    pub fn new() -> Self {
        Self {
            markers: Vec::new(),
            total_appended: 0,
            chain_anchor_hash: None,
        }
    }

    /// Append a new marker to the stream.
    ///
    /// INV-MKS-APPEND-ONLY: only appends allowed.
    /// INV-MKS-DENSE-SEQUENCE: enforced via next expected sequence.
    /// INV-MKS-HASH-CHAIN: prev_hash computed from preceding marker.
    /// INV-MKS-MONOTONIC-TIME: timestamp >= predecessor's timestamp.
    pub fn append(
        &mut self,
        event_type: MarkerEventType,
        payload_hash: &str,
        timestamp: u64,
        trace_id: &str,
    ) -> Result<&Marker, MarkerStreamError> {
        // Validate payload hash
        if payload_hash.trim().is_empty() {
            return Err(MarkerStreamError::InvalidPayload {
                reason: "payload_hash must not be empty".into(),
            });
        }
        if trace_id.trim().is_empty() {
            return Err(MarkerStreamError::InvalidPayload {
                reason: "trace_id must not be empty".into(),
            });
        }

        let next_seq = self.total_appended;

        // Determine prev_hash and check monotonic time
        let prev_hash = if let Some(head) = self.markers.last() {
            // INV-MKS-MONOTONIC-TIME
            if timestamp < head.timestamp {
                return Err(MarkerStreamError::TimeRegression {
                    sequence: next_seq,
                    prev_ts: head.timestamp,
                    got_ts: timestamp,
                });
            }
            head.marker_hash.clone()
        } else {
            self.chain_anchor_hash
                .clone()
                .unwrap_or_else(|| GENESIS_PREV_HASH.to_string())
        };

        let marker_hash = Marker::compute_hash(
            next_seq,
            event_type,
            payload_hash,
            &prev_hash,
            timestamp,
            trace_id,
        );

        let marker = Marker {
            sequence: next_seq,
            event_type,
            payload_hash: payload_hash.to_string(),
            prev_hash,
            marker_hash,
            timestamp,
            trace_id: trace_id.to_string(),
        };

        if self.markers.len() >= MAX_MARKERS {
            let overflow = self
                .markers
                .len()
                .saturating_sub(MAX_MARKERS)
                .saturating_add(1);
            self.chain_anchor_hash =
                Some(self.markers[overflow.saturating_sub(1)].marker_hash.clone());
            self.markers.drain(0..overflow.min(self.markers.len()));
        }
        self.markers.push(marker);
        self.total_appended = self.total_appended.saturating_add(1);
        self.markers
            .last()
            .ok_or_else(|| MarkerStreamError::IntegrityFailure {
                sequence: next_seq,
                detail: "marker append invariant violated: stream empty after push".to_string(),
            })
    }

    /// Get the most recent marker.
    pub fn head(&self) -> Option<&Marker> {
        self.markers.last()
    }

    /// Get marker at a specific sequence number. O(1) lookup.
    pub fn get(&self, sequence: u64) -> Option<&Marker> {
        let base = self.markers.first().map_or(0, |m| m.sequence);
        self.markers.get(sequence_offset(base, sequence)?)
    }

    /// Number of markers in the stream.
    pub fn len(&self) -> usize {
        self.markers.len()
    }

    /// Whether the stream is empty.
    pub fn is_empty(&self) -> bool {
        self.markers.is_empty()
    }

    /// Get markers in a sequence range (inclusive start, exclusive end).
    pub fn range(&self, start: u64, end: u64) -> &[Marker] {
        let base = self.markers.first().map_or(0, |m| m.sequence);
        let adj_start = if start < base {
            0
        } else {
            usize::try_from(start - base).unwrap_or(usize::MAX)
        };
        let adj_end = if end <= base {
            0
        } else {
            usize::try_from(end - base)
                .unwrap_or(usize::MAX)
                .min(self.markers.len())
        };
        if adj_start >= adj_end {
            return &[];
        }
        &self.markers[adj_start..adj_end]
    }

    /// O(1) marker lookup by sequence number (bd-129f).
    ///
    /// Since the stream is dense (sequence N lives at index N), this is a
    /// direct array index operation with O(1) complexity.
    ///
    /// Returns `None` for out-of-range sequences without panicking.
    pub fn marker_by_sequence(&self, seq: u64) -> Option<&Marker> {
        let base = self.markers.first().map_or(0, |m| m.sequence);
        self.markers.get(sequence_offset(base, seq)?)
    }

    /// O(log N) timestamp-to-sequence binary search (bd-129f).
    ///
    /// Because markers are appended with monotonically non-decreasing timestamps
    /// (INV-MKS-MONOTONIC-TIME), binary search is valid.
    ///
    /// Returns the sequence number of the most recent marker at or before `ts`.
    /// - If `ts` is before the first marker's timestamp, returns `None`.
    /// - If `ts` is at or after the last marker's timestamp, returns the last sequence.
    /// - For timestamps between markers, returns the marker just before `ts`.
    pub fn sequence_by_timestamp(&self, ts: u64) -> Option<u64> {
        if self.markers.is_empty() {
            return None;
        }

        // If ts is before the first marker, no result
        if ts < self.markers[0].timestamp {
            return None;
        }

        // Binary search for the rightmost marker with timestamp <= ts
        let mut lo = 0_usize;
        let mut hi = self.markers.len(); // exclusive upper bound
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            if self.markers[mid].timestamp <= ts {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        // lo - 1 is the rightmost index where timestamp <= ts
        if lo == 0 {
            return None;
        }
        Some(self.markers[lo - 1].sequence)
    }

    /// Get the first marker (sequence 0).
    pub fn first(&self) -> Option<&Marker> {
        self.markers.first()
    }

    /// Verify the integrity of the entire chain.
    ///
    /// INV-MKS-DENSE-SEQUENCE: sequence numbers are 0,1,2,...
    /// INV-MKS-HASH-CHAIN: each marker's prev_hash matches predecessor's marker_hash.
    /// INV-MKS-MONOTONIC-TIME: timestamps are non-decreasing.
    pub fn verify_integrity(&self) -> Result<(), MarkerStreamError> {
        let base_seq = self.markers.first().map_or(0, |m| m.sequence);
        for (i, marker) in self.markers.iter().enumerate() {
            let expected_seq = base_seq.saturating_add(len_to_u64(i));

            // Dense sequence check
            if marker.sequence != expected_seq {
                return Err(MarkerStreamError::IntegrityFailure {
                    sequence: expected_seq,
                    detail: format!(
                        "sequence mismatch: expected {expected_seq}, found {}",
                        marker.sequence
                    ),
                });
            }

            // Hash chain check: use chain_anchor_hash for the first retained marker after eviction
            let expected_prev = if i == 0 {
                if base_seq == 0 {
                    GENESIS_PREV_HASH.to_string()
                } else {
                    self.chain_anchor_hash
                        .clone()
                        .unwrap_or_else(|| marker.prev_hash.clone())
                }
            } else {
                self.markers[i - 1].marker_hash.clone()
            };

            if !crate::security::constant_time::ct_eq(&marker.prev_hash, &expected_prev) {
                return Err(MarkerStreamError::HashChainBreak {
                    sequence: expected_seq,
                    expected: expected_prev,
                    got: marker.prev_hash.clone(),
                });
            }

            // Recompute marker hash and verify
            let recomputed = Marker::compute_hash(
                marker.sequence,
                marker.event_type,
                &marker.payload_hash,
                &marker.prev_hash,
                marker.timestamp,
                &marker.trace_id,
            );
            if !crate::security::constant_time::ct_eq(&marker.marker_hash, &recomputed) {
                return Err(MarkerStreamError::IntegrityFailure {
                    sequence: expected_seq,
                    detail: format!(
                        "marker_hash mismatch: stored={}, recomputed={recomputed}",
                        marker.marker_hash
                    ),
                });
            }

            // Monotonic time check
            if i > 0 && marker.timestamp < self.markers[i - 1].timestamp {
                return Err(MarkerStreamError::IntegrityFailure {
                    sequence: expected_seq,
                    detail: format!(
                        "time regression: {} < {}",
                        marker.timestamp,
                        self.markers[i - 1].timestamp
                    ),
                });
            }
        }

        Ok(())
    }

    /// Recover from a torn tail (corrupt last marker).
    ///
    /// INV-MKS-TORN-TAIL: if the last marker's hash doesn't match recomputation,
    /// remove it and return the discarded marker. Returns None if stream is healthy.
    pub fn recover_torn_tail(&mut self) -> Option<Marker> {
        let last = self.markers.last()?;

        let recomputed = Marker::compute_hash(
            last.sequence,
            last.event_type,
            &last.payload_hash,
            &last.prev_hash,
            last.timestamp,
            &last.trace_id,
        );

        if !crate::security::constant_time::ct_eq(&last.marker_hash, &recomputed) {
            self.markers.pop()
        } else {
            None
        }
    }

    /// Inject a marker directly for testing torn-tail recovery.
    ///
    /// Validates structural fields (non-empty event type, trace_id, payload_hash)
    /// but skips chain-hash continuity to allow simulating torn-tail scenarios.
    #[cfg(test)]
    fn inject_for_test(&mut self, marker: Marker) {
        assert!(
            !marker.trace_id.is_empty(),
            "inject_for_test: trace_id must be non-empty"
        );
        assert!(
            !marker.payload_hash.is_empty(),
            "inject_for_test: payload_hash must be non-empty"
        );
        self.markers.push(marker);
    }
}

impl Default for MarkerStream {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        DivergenceResult, GENESIS_PREV_HASH, MAX_MARKERS, Marker, MarkerEventType, MarkerStream,
        MarkerStreamError, find_divergence_point, len_to_u64,
    };
    use crate::security::constant_time;

    fn trace(n: u32) -> String {
        format!("trace-{n:04}")
    }

    fn payload(n: u32) -> String {
        format!("payload-hash-{n:016x}", n = n)
    }

    fn build_shared_stream(count: u64) -> MarkerStream {
        let mut stream = MarkerStream::new();
        for i in 0..count {
            let event = MarkerEventType::all()[(i as usize) % MarkerEventType::all().len()];
            let payload = format!("shared-payload-{i:06}");
            let trace = format!("shared-trace-{i:06}");
            stream
                .append(event, &payload, 1000 + i, &trace)
                .expect("append shared marker");
        }
        stream
    }

    fn build_divergence_pair(
        total: u64,
        divergence_at: Option<u64>,
    ) -> (MarkerStream, MarkerStream) {
        let mut local = MarkerStream::new();
        let mut remote = MarkerStream::new();

        for i in 0..total {
            let event = MarkerEventType::all()[(i as usize) % MarkerEventType::all().len()];
            let trace = format!("trace-{i:06}");

            let (local_payload, remote_payload) = match divergence_at {
                Some(point) if i >= point => (
                    format!("local-payload-{i:06}"),
                    format!("remote-payload-{i:06}"),
                ),
                _ => {
                    let shared = format!("shared-payload-{i:06}");
                    (shared.clone(), shared)
                }
            };

            local
                .append(event, &local_payload, 1000 + i, &trace)
                .expect("append local marker");
            remote
                .append(event, &remote_payload, 1000 + i, &trace)
                .expect("append remote marker");
        }

        (local, remote)
    }

    fn ceil_log2(n: u64) -> u32 {
        if n <= 1 {
            0
        } else {
            64 - (n - 1).leading_zeros()
        }
    }

    fn hash_without_marker_domain(
        sequence: u64,
        event_type: MarkerEventType,
        payload_hash: &str,
        prev_hash: &str,
        timestamp: u64,
        trace_id: &str,
    ) -> String {
        let mut hasher = sha2::Sha256::new();
        sha2::Digest::update(&mut hasher, sequence.to_le_bytes());
        for field in [event_type.label(), payload_hash, prev_hash] {
            sha2::Digest::update(&mut hasher, len_to_u64(field.len()).to_le_bytes());
            sha2::Digest::update(&mut hasher, field.as_bytes());
        }
        sha2::Digest::update(&mut hasher, timestamp.to_le_bytes());
        sha2::Digest::update(&mut hasher, len_to_u64(trace_id.len()).to_le_bytes());
        sha2::Digest::update(&mut hasher, trace_id.as_bytes());
        hex::encode(sha2::Digest::finalize(hasher))
    }

    #[test]
    fn len_to_u64_never_truncates_lengths() {
        assert_eq!(len_to_u64(0), 0);
        assert_eq!(len_to_u64(1), 1);
        assert_eq!(len_to_u64(4096), 4096);
        assert_eq!(
            len_to_u64(usize::MAX),
            u64::try_from(usize::MAX).unwrap_or(u64::MAX)
        );
    }

    #[test]
    fn marker_hash_keeps_domain_separator() {
        let canonical = Marker::compute_hash(
            7,
            MarkerEventType::PolicyChange,
            "payload",
            "prev",
            1234,
            "trace",
        );
        let without_domain = hash_without_marker_domain(
            7,
            MarkerEventType::PolicyChange,
            "payload",
            "prev",
            1234,
            "trace",
        );

        assert!(!crate::security::constant_time::ct_eq(
            &canonical,
            &without_domain
        ));
    }

    #[test]
    fn marker_hash_length_prefixes_reject_concat_ambiguity() {
        let left = Marker::compute_hash(1, MarkerEventType::TrustDecision, "ab", "c", 99, "trace");
        let right = Marker::compute_hash(1, MarkerEventType::TrustDecision, "a", "bc", 99, "trace");

        assert!(!crate::security::constant_time::ct_eq(&left, &right));
    }

    #[test]
    fn get_rejects_sequence_before_retained_base_after_eviction() {
        let count = u64::try_from(MAX_MARKERS)
            .expect("MAX_MARKERS fits u64")
            .saturating_add(8);
        let stream = build_shared_stream(count);
        let first_retained = stream.first().expect("retained marker").sequence;

        assert!(first_retained > 0);
        assert!(stream.get(first_retained - 1).is_none());
        assert!(stream.marker_by_sequence(first_retained - 1).is_none());
    }

    #[test]
    fn huge_future_sequence_lookup_is_rejected_without_truncation() {
        let stream = build_shared_stream(3);

        assert!(stream.get(u64::MAX).is_none());
        assert!(stream.marker_by_sequence(u64::MAX).is_none());
    }

    #[test]
    fn range_before_retained_base_is_empty_after_eviction() {
        let count = u64::try_from(MAX_MARKERS)
            .expect("MAX_MARKERS fits u64")
            .saturating_add(8);
        let stream = build_shared_stream(count);
        let first_retained = stream.first().expect("retained marker").sequence;

        assert!(stream.range(0, first_retained).is_empty());
    }

    #[test]
    fn range_with_huge_end_clamps_to_retained_window() {
        let stream = build_shared_stream(5);
        let all = stream.range(0, u64::MAX);

        assert_eq!(all.len(), stream.len());
        assert_eq!(all.first().expect("first marker").sequence, 0);
        assert_eq!(all.last().expect("last marker").sequence, 4);
    }

    #[test]
    fn range_with_huge_start_after_window_is_empty() {
        let stream = build_shared_stream(5);

        assert!(stream.range(u64::MAX - 1, u64::MAX).is_empty());
    }

    // ---- Basic append and retrieval ----

    #[test]
    fn append_single_marker() {
        let mut stream = MarkerStream::new();
        let m = stream
            .append(MarkerEventType::TrustDecision, &payload(1), 1000, &trace(1))
            .unwrap();
        assert_eq!(m.sequence, 0);
        assert_eq!(m.event_type, MarkerEventType::TrustDecision);
        assert_eq!(m.prev_hash, GENESIS_PREV_HASH);
        assert_eq!(stream.len(), 1);
    }

    #[test]
    fn append_multiple_markers() {
        let mut stream = MarkerStream::new();
        stream
            .append(MarkerEventType::TrustDecision, &payload(1), 1000, &trace(1))
            .unwrap();
        stream
            .append(
                MarkerEventType::RevocationEvent,
                &payload(2),
                1001,
                &trace(2),
            )
            .unwrap();
        stream
            .append(
                MarkerEventType::QuarantineAction,
                &payload(3),
                1002,
                &trace(3),
            )
            .unwrap();
        assert_eq!(stream.len(), 3);
    }

    #[test]
    fn dense_sequence_numbers() {
        let mut stream = MarkerStream::new();
        for i in 0..10 {
            stream
                .append(
                    MarkerEventType::PolicyChange,
                    &payload(i),
                    1000 + u64::from(i),
                    &trace(i),
                )
                .unwrap();
        }
        for i in 0..10 {
            let m = stream.get(i as u64).unwrap();
            assert_eq!(m.sequence, i as u64);
        }
    }

    #[test]
    fn head_returns_latest() {
        let mut stream = MarkerStream::new();
        assert!(stream.head().is_none());
        stream
            .append(MarkerEventType::TrustDecision, &payload(1), 1000, &trace(1))
            .unwrap();
        assert_eq!(stream.head().unwrap().sequence, 0);
        stream
            .append(
                MarkerEventType::RevocationEvent,
                &payload(2),
                1001,
                &trace(2),
            )
            .unwrap();
        assert_eq!(stream.head().unwrap().sequence, 1);
    }

    #[test]
    fn get_by_sequence() {
        let mut stream = MarkerStream::new();
        stream
            .append(MarkerEventType::TrustDecision, &payload(1), 1000, &trace(1))
            .unwrap();
        stream
            .append(
                MarkerEventType::RevocationEvent,
                &payload(2),
                1001,
                &trace(2),
            )
            .unwrap();
        assert!(stream.get(0).is_some());
        assert!(stream.get(1).is_some());
        assert!(stream.get(2).is_none());
    }

    #[test]
    fn range_query() {
        let mut stream = MarkerStream::new();
        for i in 0..5 {
            stream
                .append(
                    MarkerEventType::PolicyChange,
                    &payload(i),
                    1000 + u64::from(i),
                    &trace(i),
                )
                .unwrap();
        }
        let r = stream.range(1, 4);
        assert_eq!(r.len(), 3);
        assert_eq!(r[0].sequence, 1);
        assert_eq!(r[2].sequence, 3);
    }

    #[test]
    fn range_empty_for_invalid_bounds() {
        let mut stream = MarkerStream::new();
        stream
            .append(MarkerEventType::PolicyChange, &payload(0), 1000, &trace(0))
            .unwrap();
        assert!(stream.range(5, 10).is_empty());
        assert!(stream.range(1, 0).is_empty());
    }

    // ---- Hash chain invariant ----

    #[test]
    fn hash_chain_links_correctly() {
        let mut stream = MarkerStream::new();
        stream
            .append(MarkerEventType::TrustDecision, &payload(1), 1000, &trace(1))
            .unwrap();
        let first_hash = stream.get(0).unwrap().marker_hash.clone();
        stream
            .append(
                MarkerEventType::RevocationEvent,
                &payload(2),
                1001,
                &trace(2),
            )
            .unwrap();
        assert_eq!(stream.get(1).unwrap().prev_hash, first_hash);
    }

    #[test]
    fn first_marker_has_genesis_prev_hash() {
        let mut stream = MarkerStream::new();
        stream
            .append(MarkerEventType::TrustDecision, &payload(1), 1000, &trace(1))
            .unwrap();
        assert_eq!(stream.get(0).unwrap().prev_hash, GENESIS_PREV_HASH);
    }

    // ---- Monotonic time invariant ----

    #[test]
    fn monotonic_time_equal_allowed() {
        let mut stream = MarkerStream::new();
        stream
            .append(MarkerEventType::TrustDecision, &payload(1), 1000, &trace(1))
            .unwrap();
        // Same timestamp is fine (non-decreasing)
        stream
            .append(
                MarkerEventType::RevocationEvent,
                &payload(2),
                1000,
                &trace(2),
            )
            .unwrap();
        assert_eq!(stream.len(), 2);
    }

    #[test]
    fn time_regression_rejected() {
        let mut stream = MarkerStream::new();
        stream
            .append(MarkerEventType::TrustDecision, &payload(1), 1000, &trace(1))
            .unwrap();
        let err = stream
            .append(
                MarkerEventType::RevocationEvent,
                &payload(2),
                999,
                &trace(2),
            )
            .unwrap_err();
        assert_eq!(err.code(), "MKS_TIME_REGRESSION");
        // Stream unchanged after rejection
        assert_eq!(stream.len(), 1);
    }

    // ---- Invalid payload ----

    #[test]
    fn empty_payload_hash_rejected() {
        let mut stream = MarkerStream::new();
        let err = stream
            .append(MarkerEventType::TrustDecision, "", 1000, &trace(1))
            .unwrap_err();
        assert_eq!(err.code(), "MKS_INVALID_PAYLOAD");
    }

    // ---- Negative regression tests ----

    #[test]
    fn empty_payload_rejection_does_not_advance_sequence() {
        let mut stream = MarkerStream::new();
        let err = stream
            .append(MarkerEventType::TrustDecision, "", 1000, &trace(1))
            .unwrap_err();

        assert_eq!(err.code(), "MKS_INVALID_PAYLOAD");
        let marker = stream
            .append(MarkerEventType::TrustDecision, &payload(1), 1001, &trace(2))
            .unwrap();
        assert_eq!(marker.sequence, 0);
        assert_eq!(stream.len(), 1);
    }

    #[test]
    fn time_regression_rejection_does_not_skip_sequence() {
        let mut stream = MarkerStream::new();
        stream
            .append(MarkerEventType::TrustDecision, &payload(1), 1000, &trace(1))
            .unwrap();
        let err = stream
            .append(
                MarkerEventType::RevocationEvent,
                &payload(2),
                999,
                &trace(2),
            )
            .unwrap_err();

        assert_eq!(err.code(), "MKS_TIME_REGRESSION");
        let marker = stream
            .append(
                MarkerEventType::RevocationEvent,
                &payload(3),
                1001,
                &trace(3),
            )
            .unwrap();
        assert_eq!(marker.sequence, 1);
        assert_eq!(stream.len(), 2);
    }

    #[test]
    fn verify_integrity_detects_injected_sequence_gap() {
        let mut base = MarkerStream::new();
        base.append(MarkerEventType::TrustDecision, &payload(1), 1000, &trace(1))
            .unwrap();
        let first = base.get(0).unwrap().clone();
        let gap_marker = Marker {
            sequence: 2,
            event_type: MarkerEventType::PolicyChange,
            payload_hash: payload(2),
            prev_hash: first.marker_hash.clone(),
            marker_hash: Marker::compute_hash(
                2,
                MarkerEventType::PolicyChange,
                &payload(2),
                &first.marker_hash,
                1001,
                &trace(2),
            ),
            timestamp: 1001,
            trace_id: trace(2),
        };
        let mut stream = MarkerStream::new();
        stream.inject_for_test(first);
        stream.inject_for_test(gap_marker);

        let err = stream.verify_integrity().unwrap_err();

        assert_eq!(err.code(), "MKS_INTEGRITY_FAILURE");
        assert!(err.to_string().contains("sequence mismatch"));
    }

    #[test]
    fn verify_integrity_detects_marker_hash_mismatch_with_valid_chain() {
        let mut stream = MarkerStream::new();
        stream
            .append(MarkerEventType::TrustDecision, &payload(1), 1000, &trace(1))
            .unwrap();
        stream
            .append(
                MarkerEventType::RevocationEvent,
                &payload(2),
                1001,
                &trace(2),
            )
            .unwrap();
        let first = stream.get(0).unwrap().clone();
        let mut second = stream.get(1).unwrap().clone();
        second.marker_hash = "wrong-but-prev-chain-remains-valid".to_string();
        let mut corrupted = MarkerStream::new();
        corrupted.inject_for_test(first);
        corrupted.inject_for_test(second);

        let err = corrupted.verify_integrity().unwrap_err();

        assert_eq!(err.code(), "MKS_INTEGRITY_FAILURE");
        assert!(err.to_string().contains("marker_hash mismatch"));
    }

    #[test]
    fn verify_integrity_detects_injected_time_regression() {
        let mut base = MarkerStream::new();
        base.append(MarkerEventType::TrustDecision, &payload(1), 1000, &trace(1))
            .unwrap();
        let first = base.get(0).unwrap().clone();
        let regressed = Marker {
            sequence: 1,
            event_type: MarkerEventType::RevocationEvent,
            payload_hash: payload(2),
            prev_hash: first.marker_hash.clone(),
            marker_hash: Marker::compute_hash(
                1,
                MarkerEventType::RevocationEvent,
                &payload(2),
                &first.marker_hash,
                999,
                &trace(2),
            ),
            timestamp: 999,
            trace_id: trace(2),
        };
        let mut stream = MarkerStream::new();
        stream.inject_for_test(first);
        stream.inject_for_test(regressed);

        let err = stream.verify_integrity().unwrap_err();

        assert_eq!(err.code(), "MKS_INTEGRITY_FAILURE");
        assert!(err.to_string().contains("time regression"));
    }

    #[test]
    fn recover_torn_tail_does_not_mask_non_tail_corruption() {
        let mut stream = MarkerStream::new();
        stream
            .append(MarkerEventType::TrustDecision, &payload(1), 1000, &trace(1))
            .unwrap();
        stream
            .append(
                MarkerEventType::RevocationEvent,
                &payload(2),
                1001,
                &trace(2),
            )
            .unwrap();
        let mut first = stream.get(0).unwrap().clone();
        let second = stream.get(1).unwrap().clone();
        first.marker_hash = "non-tail-corruption".to_string();
        let mut corrupted = MarkerStream::new();
        corrupted.inject_for_test(first);
        corrupted.inject_for_test(second);

        assert!(corrupted.recover_torn_tail().is_none());
        assert_eq!(
            corrupted.verify_integrity().unwrap_err().code(),
            "MKS_INTEGRITY_FAILURE"
        );
    }

    #[test]
    fn lookup_before_evicted_base_returns_none() {
        let mut stream = MarkerStream::new();
        for i in 0..(MAX_MARKERS + 2) {
            let n = u32::try_from(i).expect("test marker index fits u32");
            let ts = 1000_u64.saturating_add(u64::try_from(i).expect("usize fits u64"));
            stream
                .append(MarkerEventType::PolicyChange, &payload(n), ts, &trace(n))
                .unwrap();
        }

        assert!(stream.get(0).is_none());
        assert!(stream.marker_by_sequence(1).is_none());
        assert!(stream.range(0, 2).is_empty());
        assert_eq!(stream.len(), MAX_MARKERS);
    }

    #[test]
    fn event_type_from_label_rejects_near_misses() {
        for label in [
            "",
            "TRUST_DECISION",
            "trust_decision ",
            " trust_decision",
            "trust-decision",
            "policy/change",
        ] {
            assert!(MarkerEventType::from_label(label).is_none());
        }
    }

    #[test]
    fn whitespace_payload_hash_rejected_without_advancing_sequence() {
        let mut stream = MarkerStream::new();
        let err = stream
            .append(MarkerEventType::TrustDecision, " \t\n", 1000, &trace(1))
            .unwrap_err();

        assert_eq!(err.code(), "MKS_INVALID_PAYLOAD");
        assert!(err.to_string().contains("payload_hash"));
        let marker = stream
            .append(MarkerEventType::TrustDecision, &payload(1), 1001, &trace(2))
            .unwrap();
        assert_eq!(marker.sequence, 0);
        assert_eq!(stream.len(), 1);
    }

    #[test]
    fn empty_trace_id_rejected_without_advancing_sequence() {
        let mut stream = MarkerStream::new();
        let err = stream
            .append(MarkerEventType::PolicyChange, &payload(1), 1000, "")
            .unwrap_err();

        assert_eq!(err.code(), "MKS_INVALID_PAYLOAD");
        assert!(err.to_string().contains("trace_id"));
        let marker = stream
            .append(MarkerEventType::PolicyChange, &payload(2), 1001, &trace(2))
            .unwrap();
        assert_eq!(marker.sequence, 0);
    }

    #[test]
    fn whitespace_trace_id_rejected_without_advancing_sequence() {
        let mut stream = MarkerStream::new();
        let err = stream
            .append(MarkerEventType::EpochTransition, &payload(1), 1000, "   ")
            .unwrap_err();

        assert_eq!(err.code(), "MKS_INVALID_PAYLOAD");
        assert!(err.to_string().contains("trace_id"));
        assert!(stream.is_empty());
    }

    #[test]
    fn invalid_payload_takes_precedence_over_time_regression() {
        let mut stream = MarkerStream::new();
        stream
            .append(MarkerEventType::TrustDecision, &payload(1), 1000, &trace(1))
            .unwrap();

        let err = stream
            .append(MarkerEventType::TrustDecision, "", 999, &trace(2))
            .unwrap_err();

        assert_eq!(err.code(), "MKS_INVALID_PAYLOAD");
        assert_eq!(stream.len(), 1);
        assert_eq!(stream.head().expect("head").sequence, 0);
    }

    #[test]
    fn invalid_trace_takes_precedence_over_time_regression() {
        let mut stream = MarkerStream::new();
        stream
            .append(MarkerEventType::TrustDecision, &payload(1), 1000, &trace(1))
            .unwrap();

        let err = stream
            .append(MarkerEventType::TrustDecision, &payload(2), 999, "\n")
            .unwrap_err();

        assert_eq!(err.code(), "MKS_INVALID_PAYLOAD");
        assert_eq!(stream.len(), 1);
        assert_eq!(stream.head().expect("head").sequence, 0);
    }

    #[test]
    fn failed_trace_validation_preserves_next_valid_sequence() {
        let mut stream = MarkerStream::new();
        stream
            .append(MarkerEventType::PolicyChange, &payload(1), 1000, &trace(1))
            .unwrap();
        let _ = stream.append(MarkerEventType::PolicyChange, &payload(2), 1001, "\t");

        let marker = stream
            .append(MarkerEventType::PolicyChange, &payload(3), 1002, &trace(3))
            .unwrap();

        assert_eq!(marker.sequence, 1);
        assert_eq!(stream.len(), 2);
    }

    // ---- Integrity verification ----

    #[test]
    fn verify_integrity_empty_stream() {
        let stream = MarkerStream::new();
        stream.verify_integrity().unwrap();
    }

    #[test]
    fn verify_integrity_valid_stream() {
        let mut stream = MarkerStream::new();
        for i in 0..20 {
            stream
                .append(
                    MarkerEventType::PolicyChange,
                    &payload(i),
                    1000 + u64::from(i),
                    &trace(i),
                )
                .unwrap();
        }
        stream.verify_integrity().unwrap();
    }

    #[test]
    fn verify_integrity_detects_hash_chain_break() {
        let mut stream = MarkerStream::new();
        stream
            .append(MarkerEventType::TrustDecision, &payload(1), 1000, &trace(1))
            .unwrap();
        stream
            .append(
                MarkerEventType::RevocationEvent,
                &payload(2),
                1001,
                &trace(2),
            )
            .unwrap();

        // Corrupt the prev_hash of the second marker while keeping a valid-looking marker_hash
        let first = stream.get(0).unwrap().clone();
        let corrupted = Marker {
            sequence: 1,
            event_type: MarkerEventType::RevocationEvent,
            payload_hash: payload(2),
            prev_hash: "corrupted_hash_not_matching_first".into(),
            marker_hash: "also_wrong".into(),
            timestamp: 1001,
            trace_id: trace(2),
        };

        // Replace via raw injection after clearing
        let mut new_stream = MarkerStream::new();
        new_stream.inject_for_test(first);
        new_stream.inject_for_test(corrupted);

        // Integrity check detects corruption (either chain break or hash mismatch)
        let err = new_stream.verify_integrity().unwrap_err();
        let code = err.code();
        assert!(
            code == "MKS_HASH_CHAIN_BREAK" || code == "MKS_INTEGRITY_FAILURE",
            "expected chain break or integrity failure, got {code}"
        );
    }

    // ---- Torn tail recovery ----

    #[test]
    fn recover_torn_tail_healthy_stream() {
        let mut stream = MarkerStream::new();
        stream
            .append(MarkerEventType::TrustDecision, &payload(1), 1000, &trace(1))
            .unwrap();
        assert!(stream.recover_torn_tail().is_none());
        assert_eq!(stream.len(), 1);
    }

    #[test]
    fn recover_torn_tail_corrupt_last() {
        let mut stream = MarkerStream::new();
        stream
            .append(MarkerEventType::TrustDecision, &payload(1), 1000, &trace(1))
            .unwrap();

        // Inject a corrupt marker as tail
        let corrupt = Marker {
            sequence: 1,
            event_type: MarkerEventType::RevocationEvent,
            payload_hash: payload(2),
            prev_hash: stream.head().unwrap().marker_hash.clone(),
            marker_hash: "corrupt_marker_hash_not_matching".into(),
            timestamp: 1001,
            trace_id: trace(2),
        };
        stream.inject_for_test(corrupt);
        assert_eq!(stream.len(), 2);

        // Recovery should remove the corrupt tail
        let discarded = stream.recover_torn_tail().unwrap();
        assert_eq!(discarded.sequence, 1);
        assert_eq!(stream.len(), 1);

        // Stream should be healthy now
        stream.verify_integrity().unwrap();
    }

    #[test]
    fn recover_torn_tail_empty_stream() {
        let mut stream = MarkerStream::new();
        assert!(stream.recover_torn_tail().is_none());
    }

    // ---- Event type coverage ----

    #[test]
    fn all_event_types_appendable() {
        let mut stream = MarkerStream::new();
        for (i, et) in MarkerEventType::all().iter().enumerate() {
            stream
                .append(*et, &payload(i as u32), 1000 + i as u64, &trace(i as u32))
                .unwrap();
        }
        assert_eq!(stream.len(), MarkerEventType::all().len());
        stream.verify_integrity().unwrap();
    }

    #[test]
    fn event_type_label_roundtrip() {
        for et in MarkerEventType::all() {
            let label = et.label();
            let parsed = MarkerEventType::from_label(label).unwrap();
            assert_eq!(*et, parsed);
        }
    }

    #[test]
    fn event_type_unknown_label() {
        assert!(MarkerEventType::from_label("unknown").is_none());
    }

    // ---- Error code coverage ----

    #[test]
    fn error_codes_all_present() {
        assert_eq!(
            MarkerStreamError::SequenceGap {
                expected: 0,
                got: 1
            }
            .code(),
            "MKS_SEQUENCE_GAP"
        );
        assert_eq!(
            MarkerStreamError::HashChainBreak {
                sequence: 0,
                expected: "a".into(),
                got: "b".into()
            }
            .code(),
            "MKS_HASH_CHAIN_BREAK"
        );
        assert_eq!(
            MarkerStreamError::TimeRegression {
                sequence: 0,
                prev_ts: 1,
                got_ts: 0
            }
            .code(),
            "MKS_TIME_REGRESSION"
        );
        assert_eq!(MarkerStreamError::EmptyStream.code(), "MKS_EMPTY_STREAM");
        assert_eq!(
            MarkerStreamError::IntegrityFailure {
                sequence: 0,
                detail: "".into()
            }
            .code(),
            "MKS_INTEGRITY_FAILURE"
        );
        assert_eq!(
            MarkerStreamError::TornTail {
                sequence: 0,
                marker_hash: "".into()
            }
            .code(),
            "MKS_TORN_TAIL"
        );
        assert_eq!(
            MarkerStreamError::InvalidPayload { reason: "".into() }.code(),
            "MKS_INVALID_PAYLOAD"
        );
    }

    #[test]
    fn error_display_all_variants() {
        let errors: Vec<MarkerStreamError> = vec![
            MarkerStreamError::SequenceGap {
                expected: 1,
                got: 3,
            },
            MarkerStreamError::HashChainBreak {
                sequence: 2,
                expected: "a".into(),
                got: "b".into(),
            },
            MarkerStreamError::TimeRegression {
                sequence: 1,
                prev_ts: 100,
                got_ts: 50,
            },
            MarkerStreamError::EmptyStream,
            MarkerStreamError::IntegrityFailure {
                sequence: 0,
                detail: "test".into(),
            },
            MarkerStreamError::TornTail {
                sequence: 0,
                marker_hash: "h".into(),
            },
            MarkerStreamError::InvalidPayload {
                reason: "empty".into(),
            },
        ];
        for e in &errors {
            let display = e.to_string();
            assert!(
                display.contains(e.code()),
                "Display for {e:?} should contain code {}",
                e.code()
            );
        }
    }

    // ---- Deterministic hashing ----

    #[test]
    fn same_inputs_produce_same_hash() {
        let h1 = Marker::compute_hash(0, MarkerEventType::TrustDecision, "ph", "prev", 1000, "t1");
        let h2 = Marker::compute_hash(0, MarkerEventType::TrustDecision, "ph", "prev", 1000, "t1");
        assert_eq!(h1, h2);
    }

    #[test]
    fn different_inputs_produce_different_hash() {
        let h1 = Marker::compute_hash(0, MarkerEventType::TrustDecision, "ph1", "prev", 1000, "t1");
        let h2 = Marker::compute_hash(0, MarkerEventType::TrustDecision, "ph2", "prev", 1000, "t1");
        assert_ne!(h1, h2);
    }

    // ---- Stream properties ----

    #[test]
    fn is_empty_and_default() {
        let stream = MarkerStream::default();
        assert!(stream.is_empty());
        assert_eq!(stream.len(), 0);
    }

    #[test]
    fn large_stream_integrity() {
        let mut stream = MarkerStream::new();
        for i in 0..1000 {
            stream
                .append(
                    MarkerEventType::all()[i % MarkerEventType::all().len()],
                    &payload(i as u32),
                    1000 + i as u64,
                    &trace(i as u32),
                )
                .unwrap();
        }
        assert_eq!(stream.len(), 1000);
        stream.verify_integrity().unwrap();
    }

    // ---- bd-129f: O(1) sequence lookup ----

    #[test]
    fn marker_by_sequence_first() {
        let mut stream = MarkerStream::new();
        stream
            .append(MarkerEventType::TrustDecision, &payload(1), 1000, &trace(1))
            .unwrap();
        stream
            .append(
                MarkerEventType::RevocationEvent,
                &payload(2),
                1001,
                &trace(2),
            )
            .unwrap();
        let m = stream.marker_by_sequence(0).unwrap();
        assert_eq!(m.sequence, 0);
        assert_eq!(m.event_type, MarkerEventType::TrustDecision);
    }

    #[test]
    fn marker_by_sequence_last() {
        let mut stream = MarkerStream::new();
        for i in 0..10 {
            stream
                .append(
                    MarkerEventType::PolicyChange,
                    &payload(i),
                    1000 + u64::from(i),
                    &trace(i),
                )
                .unwrap();
        }
        let m = stream.marker_by_sequence(9).unwrap();
        assert_eq!(m.sequence, 9);
    }

    #[test]
    fn marker_by_sequence_middle() {
        let mut stream = MarkerStream::new();
        for i in 0..10 {
            stream
                .append(
                    MarkerEventType::PolicyChange,
                    &payload(i),
                    1000 + u64::from(i),
                    &trace(i),
                )
                .unwrap();
        }
        let m = stream.marker_by_sequence(5).unwrap();
        assert_eq!(m.sequence, 5);
    }

    #[test]
    fn marker_by_sequence_out_of_range() {
        let mut stream = MarkerStream::new();
        stream
            .append(MarkerEventType::TrustDecision, &payload(1), 1000, &trace(1))
            .unwrap();
        assert!(stream.marker_by_sequence(1).is_none());
        assert!(stream.marker_by_sequence(100).is_none());
        assert!(stream.marker_by_sequence(u64::MAX).is_none());
    }

    #[test]
    fn marker_by_sequence_empty_stream() {
        let stream = MarkerStream::new();
        assert!(stream.marker_by_sequence(0).is_none());
    }

    // ---- bd-129f: O(log N) timestamp-to-sequence search ----

    #[test]
    fn sequence_by_timestamp_exact_match() {
        let mut stream = MarkerStream::new();
        stream
            .append(MarkerEventType::TrustDecision, &payload(1), 1000, &trace(1))
            .unwrap();
        stream
            .append(
                MarkerEventType::RevocationEvent,
                &payload(2),
                2000,
                &trace(2),
            )
            .unwrap();
        stream
            .append(MarkerEventType::PolicyChange, &payload(3), 3000, &trace(3))
            .unwrap();

        assert_eq!(stream.sequence_by_timestamp(1000), Some(0));
        assert_eq!(stream.sequence_by_timestamp(2000), Some(1));
        assert_eq!(stream.sequence_by_timestamp(3000), Some(2));
    }

    #[test]
    fn sequence_by_timestamp_between_markers() {
        let mut stream = MarkerStream::new();
        stream
            .append(MarkerEventType::TrustDecision, &payload(1), 1000, &trace(1))
            .unwrap();
        stream
            .append(
                MarkerEventType::RevocationEvent,
                &payload(2),
                2000,
                &trace(2),
            )
            .unwrap();
        stream
            .append(MarkerEventType::PolicyChange, &payload(3), 3000, &trace(3))
            .unwrap();

        // Between first and second -> returns first (most recent at or before)
        assert_eq!(stream.sequence_by_timestamp(1500), Some(0));
        // Between second and third -> returns second
        assert_eq!(stream.sequence_by_timestamp(2500), Some(1));
    }

    #[test]
    fn sequence_by_timestamp_before_first() {
        let mut stream = MarkerStream::new();
        stream
            .append(MarkerEventType::TrustDecision, &payload(1), 1000, &trace(1))
            .unwrap();
        assert_eq!(stream.sequence_by_timestamp(999), None);
        assert_eq!(stream.sequence_by_timestamp(0), None);
    }

    #[test]
    fn sequence_by_timestamp_after_last() {
        let mut stream = MarkerStream::new();
        stream
            .append(MarkerEventType::TrustDecision, &payload(1), 1000, &trace(1))
            .unwrap();
        stream
            .append(
                MarkerEventType::RevocationEvent,
                &payload(2),
                2000,
                &trace(2),
            )
            .unwrap();
        assert_eq!(stream.sequence_by_timestamp(5000), Some(1));
        assert_eq!(stream.sequence_by_timestamp(u64::MAX), Some(1));
    }

    #[test]
    fn sequence_by_timestamp_empty_stream() {
        let stream = MarkerStream::new();
        assert_eq!(stream.sequence_by_timestamp(1000), None);
    }

    #[test]
    fn sequence_by_timestamp_single_marker() {
        let mut stream = MarkerStream::new();
        stream
            .append(MarkerEventType::TrustDecision, &payload(1), 1000, &trace(1))
            .unwrap();
        assert_eq!(stream.sequence_by_timestamp(999), None);
        assert_eq!(stream.sequence_by_timestamp(1000), Some(0));
        assert_eq!(stream.sequence_by_timestamp(1001), Some(0));
    }

    #[test]
    fn sequence_by_timestamp_duplicate_timestamps() {
        let mut stream = MarkerStream::new();
        // Multiple markers at same timestamp
        stream
            .append(MarkerEventType::TrustDecision, &payload(1), 1000, &trace(1))
            .unwrap();
        stream
            .append(
                MarkerEventType::RevocationEvent,
                &payload(2),
                1000,
                &trace(2),
            )
            .unwrap();
        stream
            .append(MarkerEventType::PolicyChange, &payload(3), 1000, &trace(3))
            .unwrap();
        stream
            .append(
                MarkerEventType::QuarantineAction,
                &payload(4),
                2000,
                &trace(4),
            )
            .unwrap();

        // At ts=1000, should return the last marker with that timestamp (seq 2)
        assert_eq!(stream.sequence_by_timestamp(1000), Some(2));
        assert_eq!(stream.sequence_by_timestamp(1500), Some(2));
        assert_eq!(stream.sequence_by_timestamp(2000), Some(3));
    }

    #[test]
    fn sequence_by_timestamp_large_stream() {
        let mut stream = MarkerStream::new();
        let count = 10_000_u64;
        for i in 0..count {
            stream
                .append(
                    MarkerEventType::all()[(i as usize) % MarkerEventType::all().len()],
                    &payload(i as u32),
                    1000 + i * 10, // timestamps: 1000, 1010, 1020, ...
                    &trace(i as u32),
                )
                .unwrap();
        }

        // With MAX_MARKERS=4096, only the last 4096 markers are retained.
        // Retained markers: sequences 5904..=9999, timestamps 60040..=100990.
        let first_retained = count - (MAX_MARKERS as u64);

        // Timestamps before retained range return None
        assert_eq!(stream.sequence_by_timestamp(1000), None);

        // Exact match for first retained marker
        let first_ts = 1000 + first_retained * 10;
        assert_eq!(stream.sequence_by_timestamp(first_ts), Some(first_retained));

        // Last marker
        assert_eq!(stream.sequence_by_timestamp(1000 + 9999 * 10), Some(9999));

        // Between retained markers
        assert_eq!(
            stream.sequence_by_timestamp(first_ts + 5),
            Some(first_retained)
        );
    }

    #[test]
    fn first_marker_accessor() {
        let mut stream = MarkerStream::new();
        assert!(stream.first().is_none());
        stream
            .append(MarkerEventType::TrustDecision, &payload(1), 1000, &trace(1))
            .unwrap();
        stream
            .append(
                MarkerEventType::RevocationEvent,
                &payload(2),
                2000,
                &trace(2),
            )
            .unwrap();
        assert_eq!(stream.first().unwrap().sequence, 0);
    }

    #[test]
    fn marker_by_sequence_matches_get() {
        let mut stream = MarkerStream::new();
        for i in 0..100 {
            stream
                .append(
                    MarkerEventType::PolicyChange,
                    &payload(i),
                    1000 + u64::from(i),
                    &trace(i),
                )
                .unwrap();
        }
        // marker_by_sequence and get should return identical results
        for i in 0..100 {
            assert_eq!(stream.marker_by_sequence(i), stream.get(i));
        }
    }

    // ---- bd-xwk5: Divergence detection ----

    #[test]
    fn divergence_identical_streams_report_no_divergence() {
        let (local, remote) = build_divergence_pair(128, None);
        let result = find_divergence_point(&local, &remote);

        assert!(!result.has_divergence);
        assert!(result.has_common_prefix);
        assert_eq!(result.common_prefix_seq, 127);
        assert_eq!(result.divergence_seq, 128);
        assert!(result.local_hash_at_divergence.is_none());
        assert!(result.remote_hash_at_divergence.is_none());
    }

    #[test]
    fn divergence_at_sequence_zero_reports_no_common_prefix() {
        let (local, remote) = build_divergence_pair(64, Some(0));
        let result = find_divergence_point(&local, &remote);

        assert!(result.has_divergence);
        assert!(!result.has_common_prefix);
        assert_eq!(result.common_prefix_seq, 0);
        assert_eq!(result.divergence_seq, 0);
        assert!(result.local_hash_at_divergence.is_some());
        assert!(result.remote_hash_at_divergence.is_some());
    }

    #[test]
    fn divergence_after_large_common_prefix_reports_exact_boundary() {
        let (local, remote) = build_divergence_pair(1_400, Some(1_000));
        let result = find_divergence_point(&local, &remote);

        assert!(result.has_divergence);
        assert!(result.has_common_prefix);
        assert_eq!(result.common_prefix_seq, 999);
        assert_eq!(result.divergence_seq, 1_000);
        assert_ne!(
            result.local_hash_at_divergence,
            result.remote_hash_at_divergence
        );
    }

    #[test]
    fn divergence_when_lengths_differ_but_prefix_matches() {
        let local = build_shared_stream(300);
        let remote = build_shared_stream(200);
        let result = find_divergence_point(&local, &remote);

        assert!(result.has_divergence);
        assert!(result.has_common_prefix);
        assert_eq!(result.common_prefix_seq, 199);
        assert_eq!(result.divergence_seq, 200);
        assert!(result.local_hash_at_divergence.is_some());
        assert!(result.remote_hash_at_divergence.is_none());
    }

    #[test]
    fn divergence_empty_vs_non_empty() {
        let local = MarkerStream::new();
        let remote = build_shared_stream(5);
        let result = find_divergence_point(&local, &remote);

        assert!(result.has_divergence);
        assert!(!result.has_common_prefix);
        assert_eq!(result.divergence_seq, 0);
        assert!(result.local_hash_at_divergence.is_none());
        assert!(result.remote_hash_at_divergence.is_some());
    }

    #[test]
    fn divergence_result_is_symmetric_modulo_local_remote_hashes() {
        let (a, b) = build_divergence_pair(1_024, Some(400));
        let ab = find_divergence_point(&a, &b);
        let ba = find_divergence_point(&b, &a);

        assert_eq!(ab.has_divergence, ba.has_divergence);
        assert_eq!(ab.has_common_prefix, ba.has_common_prefix);
        assert_eq!(ab.common_prefix_seq, ba.common_prefix_seq);
        assert_eq!(ab.divergence_seq, ba.divergence_seq);
        assert_eq!(ab.local_hash_at_divergence, ba.remote_hash_at_divergence);
        assert_eq!(ab.remote_hash_at_divergence, ba.local_hash_at_divergence);
    }

    #[test]
    fn divergence_comparison_count_is_logarithmic() {
        let size = 10_000_u64;
        let (local, remote) = build_divergence_pair(size, Some(7_777));
        let result = find_divergence_point(&local, &remote);
        let bound = ceil_log2(size) as usize;

        assert!(
            result.evidence.comparison_count <= bound,
            "comparison count {} exceeded logarithmic bound {}",
            result.evidence.comparison_count,
            bound
        );
    }
}
