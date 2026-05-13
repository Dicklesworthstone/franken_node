//! bd-1hj3 / bd-1hj3.1: Local ATC signal extraction pipeline.
//!
//! Plan reference: §10.19 — Adversarial Trust Commons Execution Track (9M).
//!
//! Extracts privacy-preserving local signals from raw operator-visible events
//! (trust cards, adversary graph snapshots, control-plane events) into a
//! canonical [`AtcLocalSignal`] form that is safe to share with the federated
//! intelligence layer. The extractor enforces three properties:
//!
//! 1. **Determinism** — Identical inputs (raw event JSON + policy) produce
//!    identical signal IDs and identical canonical payload hashes.
//! 2. **Redaction** — Fields listed in [`ExtractionPolicy::redact_fields`]
//!    never appear in the redacted payload, even if present in the raw event.
//! 3. **Replay auditability** — The signal contains a deterministic
//!    `signal_id`, a `payload_hash` over the redacted payload, and a
//!    `trace_id` echoed from the raw event so the same signal can be
//!    regenerated and verified independently from the same source bytes.
//!
//! # Hardening pattern (matches the rest of the federation module)
//!
//! - First hasher update is the domain separator `b"atc_signal_v1:"` to
//!   prevent cross-pipeline collisions with other federation hashes.
//! - Every variable-length field fed to the hasher is length-prefixed via
//!   `(len as u64).to_le_bytes()` to prevent boundary collisions when two
//!   concatenations differ only in where one field ends and the next begins.
//! - Counter-style integers use `saturating_add`/`saturating_sub`.
//! - Audit log uses [`push_bounded`] with [`MAX_AUDIT_LOG_ENTRIES`].
//! - Module forbids unsafe via the workspace-wide `#![forbid(unsafe_code)]`.
//!
//! # Why blake3 is *not* a hard dep here
//!
//! The crate's `blake3` dep is optional (see `Cargo.toml`). To keep the
//! extractor functional in the default feature set used by the swarm's
//! `rch exec -- cargo check -p frankenengine-node`, the canonical hash is
//! computed with `sha2::Sha256` — exactly like the existing federation
//! modules (`atc_participation_weighting.rs`, `atc_reciprocity.rs`). The
//! `b"atc_signal_v1:"` domain separator and length-prefix discipline carry
//! the security properties the plan calls out; the underlying primitive can
//! be upgraded to blake3 in a follow-up bead without changing the
//! extractor's public surface.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

use crate::capacity_defaults::aliases::MAX_AUDIT_LOG_ENTRIES;
use crate::push_bounded;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Domain separator for the signal ID hash. Required first-hasher-update so
/// no other federation pipeline can produce a colliding `signal_id`.
const DOMAIN_SEPARATOR: &[u8] = b"atc_signal_v1:";

/// Domain separator for the payload hash.
const PAYLOAD_DOMAIN_SEPARATOR: &[u8] = b"atc_signal_payload_v1:";

/// Hard cap on the number of fields that may survive into the redacted
/// payload regardless of policy, to guarantee bounded extraction cost.
const MAX_REDACTED_FIELDS: usize = 64;

/// Hard cap on the length of any single field name accepted from the
/// policy or the raw event. Larger names are rejected as malformed input.
const MAX_FIELD_NAME_BYTES: usize = 256;

/// Hard cap on the length of any single redacted-payload value (after
/// stringification). Values longer than this are rejected so the redacted
/// payload size is bounded before the `max_payload_bytes` check.
const MAX_VALUE_BYTES: usize = 16 * 1024;

// ---------------------------------------------------------------------------
// Event codes (stable, structured-log-friendly)
// ---------------------------------------------------------------------------

pub mod event_codes {
    /// ATC-EXTRACT-001: Signal successfully extracted.
    pub const SIGNAL_EXTRACTED: &str = "ATC-EXTRACT-001";
    /// ATC-EXTRACT-002: Signal kind was filtered by policy.
    pub const KIND_FILTERED: &str = "ATC-EXTRACT-002";
    /// ATC-EXTRACT-003: Field was redacted per policy.
    pub const FIELD_REDACTED: &str = "ATC-EXTRACT-003";
    /// ATC-EXTRACT-ERR-001: Required field missing from raw event.
    pub const MISSING_FIELD: &str = "ATC-EXTRACT-ERR-001";
    /// ATC-EXTRACT-ERR-002: Unknown / unsupported signal kind discriminant.
    pub const UNKNOWN_KIND: &str = "ATC-EXTRACT-ERR-002";
    /// ATC-EXTRACT-ERR-003: Redacted payload exceeds `max_payload_bytes`.
    pub const PAYLOAD_TOO_LARGE: &str = "ATC-EXTRACT-ERR-003";
    /// ATC-EXTRACT-ERR-004: Malformed event shape (non-object, wrong type).
    pub const MALFORMED_EVENT: &str = "ATC-EXTRACT-ERR-004";
    /// ATC-EXTRACT-ERR-005: Field name or value exceeded hard length bound.
    pub const FIELD_OUT_OF_BOUNDS: &str = "ATC-EXTRACT-ERR-005";
}

// ---------------------------------------------------------------------------
// Invariant tags (referenced by tests and verification evidence)
// ---------------------------------------------------------------------------

pub mod invariants {
    /// Identical (raw_event, policy) inputs MUST yield identical signals.
    pub const INV_ATC_EXTRACT_DETERMINISM: &str = "INV-ATC-EXTRACT-DETERMINISM";
    /// Redacted fields MUST NOT appear in [`AtcLocalSignal::redacted_payload`].
    pub const INV_ATC_EXTRACT_REDACTION: &str = "INV-ATC-EXTRACT-REDACTION";
    /// `payload_hash` MUST be collision-resistant across field-boundary moves.
    pub const INV_ATC_EXTRACT_LENGTH_PREFIX: &str = "INV-ATC-EXTRACT-LENGTH-PREFIX";
    /// `max_payload_bytes` MUST be enforced fail-closed.
    pub const INV_ATC_EXTRACT_SIZE_BOUND: &str = "INV-ATC-EXTRACT-SIZE-BOUND";
    /// Disallowed [`SignalKind`] discriminants MUST be rejected pre-emit.
    pub const INV_ATC_EXTRACT_KIND_FILTER: &str = "INV-ATC-EXTRACT-KIND-FILTER";
}

// ---------------------------------------------------------------------------
// Signal kind
// ---------------------------------------------------------------------------

/// Discriminant for an ATC local signal. The string form is part of the
/// hash input, so adding a new variant changes the wire schema.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum SignalKind {
    /// Anomaly observation derived from the adversary graph / detector output.
    AnomalyObservation,
    /// Delta against a previously published trust card.
    TrustCardDelta,
    /// Hint that an operator-local revocation candidate has been observed.
    RevocationHint,
    /// Quarantine event emitted by the local quarantine registry.
    QuarantineEvent,
}

impl SignalKind {
    /// Stable wire-string for hashing and event-type matching.
    pub const fn as_str(self) -> &'static str {
        match self {
            SignalKind::AnomalyObservation => "anomaly_observation",
            SignalKind::TrustCardDelta => "trust_card_delta",
            SignalKind::RevocationHint => "revocation_hint",
            SignalKind::QuarantineEvent => "quarantine_event",
        }
    }

    /// Inverse of [`Self::as_str`]. Returns `None` for unknown strings.
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "anomaly_observation" => Some(SignalKind::AnomalyObservation),
            "trust_card_delta" => Some(SignalKind::TrustCardDelta),
            "revocation_hint" => Some(SignalKind::RevocationHint),
            "quarantine_event" => Some(SignalKind::QuarantineEvent),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Extraction policy
// ---------------------------------------------------------------------------

/// Operator-controlled policy that governs what survives extraction.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExtractionPolicy {
    /// Field names that MUST be dropped before the signal leaves the node.
    pub redact_fields: Vec<String>,
    /// Hard cap on the serialized redacted payload size in bytes.
    pub max_payload_bytes: usize,
    /// Allow-list of signal kinds. An event whose kind is not in this set is
    /// rejected with [`ExtractionError::KindFiltered`].
    pub allowed_kinds: BTreeSet<SignalKind>,
}

impl ExtractionPolicy {
    /// Permissive default policy: allow every kind, redact nothing, 16 KiB
    /// payload ceiling. Intended for tests and conformance fixtures, NOT for
    /// production deployments.
    pub fn permissive_for_tests() -> Self {
        let mut allowed = BTreeSet::new();
        allowed.insert(SignalKind::AnomalyObservation);
        allowed.insert(SignalKind::TrustCardDelta);
        allowed.insert(SignalKind::RevocationHint);
        allowed.insert(SignalKind::QuarantineEvent);
        Self {
            redact_fields: Vec::new(),
            max_payload_bytes: 16 * 1024,
            allowed_kinds: allowed,
        }
    }
}

// ---------------------------------------------------------------------------
// Output signal
// ---------------------------------------------------------------------------

/// Canonical local signal emitted by [`extract_signal`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AtcLocalSignal {
    /// Deterministic ID = sha256(domain_sep || lp(trace_id) || lp(kind) || lp(epoch_le)).
    pub signal_id: String,
    /// Discriminant.
    pub kind: SignalKind,
    /// Source control-plane epoch the event was observed in.
    pub source_epoch: u64,
    /// Hex sha256 over the canonical, redacted, length-prefixed payload.
    pub payload_hash: String,
    /// Hex public key of the contributor that emitted the source event.
    pub contributor_pubkey_hex: String,
    /// Sorted (BTreeMap) field-name → stringified value, with redactions
    /// removed and value sizes bounded.
    pub redacted_payload: BTreeMap<String, String>,
    /// Echoed correlation ID from the raw event. Length-prefixed in the
    /// signal_id and payload_hash inputs.
    pub trace_id: String,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors surfaced by [`extract_signal`]. Each variant carries the event
/// code stable string so callers can route on it without string-matching.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ExtractionError {
    #[error("missing required field: {field} (code={code})")]
    MissingField { field: &'static str, code: &'static str },
    #[error("unknown signal kind: {kind:?} (code={code})")]
    UnknownKind { kind: String, code: &'static str },
    #[error("signal kind {kind:?} is not in policy allowed_kinds (code={code})")]
    KindFiltered { kind: SignalKind, code: &'static str },
    #[error("redacted payload size {size} exceeds max_payload_bytes {limit} (code={code})")]
    PayloadTooLarge { size: usize, limit: usize, code: &'static str },
    #[error("malformed raw event: {reason} (code={code})")]
    Malformed { reason: String, code: &'static str },
    #[error("field name or value out of bounds: {detail} (code={code})")]
    OutOfBounds { detail: String, code: &'static str },
}

impl ExtractionError {
    /// Stable structured-log code for the error.
    pub fn code(&self) -> &'static str {
        match self {
            ExtractionError::MissingField { code, .. } => code,
            ExtractionError::UnknownKind { code, .. } => code,
            ExtractionError::KindFiltered { code, .. } => code,
            ExtractionError::PayloadTooLarge { code, .. } => code,
            ExtractionError::Malformed { code, .. } => code,
            ExtractionError::OutOfBounds { code, .. } => code,
        }
    }
}

/// Convenience alias used throughout the module.
pub type Result<T> = std::result::Result<T, ExtractionError>;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Extract a canonical [`AtcLocalSignal`] from a raw event JSON value.
///
/// Expected raw shape (top-level object):
/// ```json
/// {
///   "event_type": "anomaly_observation" | "trust_card_delta" | "revocation_hint" | "quarantine_event",
///   "trace_id": "<correlation-id>",
///   "source_epoch": 42,
///   "contributor_pubkey_hex": "<hex>",
///   "payload": { "<field>": <scalar>, ... }
/// }
/// ```
///
/// All four top-level scalars (`event_type`, `trace_id`, `source_epoch`,
/// `contributor_pubkey_hex`) are required. `payload` is optional; missing
/// payload is treated as an empty object.
pub fn extract_signal(
    raw_event: &serde_json::Value,
    policy: &ExtractionPolicy,
) -> Result<AtcLocalSignal> {
    let obj = raw_event.as_object().ok_or_else(|| ExtractionError::Malformed {
        reason: "raw event is not a JSON object".to_string(),
        code: event_codes::MALFORMED_EVENT,
    })?;

    // ---- required scalars ------------------------------------------------
    let event_type_str = require_str(obj, "event_type")?;
    let kind = SignalKind::from_str(event_type_str).ok_or_else(|| ExtractionError::UnknownKind {
        kind: event_type_str.to_string(),
        code: event_codes::UNKNOWN_KIND,
    })?;

    if !policy.allowed_kinds.contains(&kind) {
        return Err(ExtractionError::KindFiltered {
            kind,
            code: event_codes::KIND_FILTERED,
        });
    }

    let trace_id = require_str(obj, "trace_id")?.to_string();
    bounds_check_value("trace_id", &trace_id)?;

    let source_epoch = obj
        .get("source_epoch")
        .and_then(|v| v.as_u64())
        .ok_or(ExtractionError::MissingField {
            field: "source_epoch",
            code: event_codes::MISSING_FIELD,
        })?;

    let contributor_pubkey_hex = require_str(obj, "contributor_pubkey_hex")?.to_string();
    bounds_check_value("contributor_pubkey_hex", &contributor_pubkey_hex)?;

    // ---- redacted payload ------------------------------------------------
    let redact: BTreeSet<&str> = policy.redact_fields.iter().map(String::as_str).collect();

    let mut redacted_payload: BTreeMap<String, String> = BTreeMap::new();

    if let Some(payload_val) = obj.get("payload") {
        let payload_obj = payload_val.as_object().ok_or_else(|| ExtractionError::Malformed {
            reason: "payload is present but not a JSON object".to_string(),
            code: event_codes::MALFORMED_EVENT,
        })?;

        for (k, v) in payload_obj {
            if k.len() > MAX_FIELD_NAME_BYTES {
                return Err(ExtractionError::OutOfBounds {
                    detail: format!("field name length {} > {}", k.len(), MAX_FIELD_NAME_BYTES),
                    code: event_codes::FIELD_OUT_OF_BOUNDS,
                });
            }
            if redact.contains(k.as_str()) {
                continue;
            }
            let stringified = stringify_scalar(v).ok_or_else(|| ExtractionError::Malformed {
                reason: format!("payload field {k:?} is not a scalar value"),
                code: event_codes::MALFORMED_EVENT,
            })?;
            bounds_check_value(k, &stringified)?;
            if redacted_payload.len() >= MAX_REDACTED_FIELDS {
                return Err(ExtractionError::OutOfBounds {
                    detail: format!(
                        "redacted payload field count exceeded {MAX_REDACTED_FIELDS}"
                    ),
                    code: event_codes::FIELD_OUT_OF_BOUNDS,
                });
            }
            redacted_payload.insert(k.clone(), stringified);
        }
    }

    // ---- size enforcement ------------------------------------------------
    // Compute the serialized size deterministically: BTreeMap iterates in
    // sorted order, and we sum (len(name) + 1 + len(value) + 1) per entry to
    // avoid materializing the JSON string twice.
    let mut estimated_size: usize = 0;
    for (k, v) in &redacted_payload {
        estimated_size = estimated_size
            .saturating_add(k.len())
            .saturating_add(v.len())
            .saturating_add(2);
    }
    if estimated_size > policy.max_payload_bytes {
        return Err(ExtractionError::PayloadTooLarge {
            size: estimated_size,
            limit: policy.max_payload_bytes,
            code: event_codes::PAYLOAD_TOO_LARGE,
        });
    }

    // ---- canonical hashes ------------------------------------------------
    let signal_id = compute_signal_id(&trace_id, kind, source_epoch);
    let payload_hash = compute_payload_hash(&redacted_payload);

    Ok(AtcLocalSignal {
        signal_id,
        kind,
        source_epoch,
        payload_hash,
        contributor_pubkey_hex,
        redacted_payload,
        trace_id,
    })
}

// ---------------------------------------------------------------------------
// Audit log helper (replay-auditable extraction stream)
// ---------------------------------------------------------------------------

/// Bounded audit record stream. Each [`extract_signal`] call should be
/// recorded here by the caller; the recorder is intentionally separate from
/// the pure [`extract_signal`] function so the function stays deterministic
/// and side-effect-free.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ExtractionAuditLog {
    entries: Vec<AuditEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub signal_id: String,
    pub kind: SignalKind,
    pub source_epoch: u64,
    pub trace_id: String,
    /// Stable event code string (see [`event_codes`]). Stored as `String` so
    /// the audit log can round-trip through serde without requiring a
    /// `'static`-lifetime input string.
    pub event_code: String,
}

impl ExtractionAuditLog {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a successful extraction. Uses [`push_bounded`] to cap memory
    /// growth at [`MAX_AUDIT_LOG_ENTRIES`].
    pub fn record_ok(&mut self, sig: &AtcLocalSignal) {
        push_bounded(
            &mut self.entries,
            AuditEntry {
                signal_id: sig.signal_id.clone(),
                kind: sig.kind,
                source_epoch: sig.source_epoch,
                trace_id: sig.trace_id.clone(),
                event_code: event_codes::SIGNAL_EXTRACTED.to_string(),
            },
            MAX_AUDIT_LOG_ENTRIES,
        );
    }

    pub fn entries(&self) -> &[AuditEntry] {
        &self.entries
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn require_str<'a>(
    obj: &'a serde_json::Map<String, serde_json::Value>,
    field: &'static str,
) -> Result<&'a str> {
    obj.get(field)
        .and_then(|v| v.as_str())
        .ok_or(ExtractionError::MissingField {
            field,
            code: event_codes::MISSING_FIELD,
        })
}

fn bounds_check_value(name: &str, v: &str) -> Result<()> {
    if v.len() > MAX_VALUE_BYTES {
        return Err(ExtractionError::OutOfBounds {
            detail: format!("value for {name:?} has {} bytes > {}", v.len(), MAX_VALUE_BYTES),
            code: event_codes::FIELD_OUT_OF_BOUNDS,
        });
    }
    Ok(())
}

/// Stringify a JSON scalar (string, number, bool, null) to a canonical form.
/// Returns `None` for arrays / objects, which are rejected as non-scalar.
fn stringify_scalar(v: &serde_json::Value) -> Option<String> {
    match v {
        serde_json::Value::Null => Some("null".to_string()),
        serde_json::Value::Bool(b) => Some(b.to_string()),
        serde_json::Value::Number(n) => Some(n.to_string()),
        serde_json::Value::String(s) => Some(s.clone()),
        _ => None,
    }
}

/// Length-prefixed hash update.
fn update_lp(hasher: &mut Sha256, bytes: &[u8]) {
    let len = bytes.len() as u64;
    hasher.update(len.to_le_bytes());
    hasher.update(bytes);
}

fn compute_signal_id(trace_id: &str, kind: SignalKind, source_epoch: u64) -> String {
    let mut hasher = Sha256::new();
    // Domain separator MUST be the first update.
    hasher.update(DOMAIN_SEPARATOR);
    update_lp(&mut hasher, trace_id.as_bytes());
    update_lp(&mut hasher, kind.as_str().as_bytes());
    // Fixed-width integers are safe to feed directly with no length prefix.
    hasher.update(source_epoch.to_le_bytes());
    hex::encode(hasher.finalize())
}

fn compute_payload_hash(payload: &BTreeMap<String, String>) -> String {
    let mut hasher = Sha256::new();
    hasher.update(PAYLOAD_DOMAIN_SEPARATOR);
    // Count is fixed-width and not length-prefixed; it bounds the loop.
    let count = payload.len() as u64;
    hasher.update(count.to_le_bytes());
    for (k, v) in payload {
        // Each (k, v) is length-prefixed independently so that moving a byte
        // from k into v (or vice versa) yields a different hash.
        update_lp(&mut hasher, k.as_bytes());
        update_lp(&mut hasher, v.as_bytes());
    }
    hex::encode(hasher.finalize())
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample_event(kind: &str) -> serde_json::Value {
        json!({
            "event_type": kind,
            "trace_id": "trace-abc-123",
            "source_epoch": 42_u64,
            "contributor_pubkey_hex": "deadbeef",
            "payload": {
                "host": "node-1",
                "score": 0.91,
                "secret_token": "REDACT-ME",
                "category": "supply_chain",
            }
        })
    }

    fn policy_with_redactions() -> ExtractionPolicy {
        let mut p = ExtractionPolicy::permissive_for_tests();
        p.redact_fields.push("secret_token".to_string());
        p
    }

    // 1. Determinism — same input twice => identical signal_id + payload_hash.
    #[test]
    fn determinism_same_input_same_signal() {
        let policy = policy_with_redactions();
        let ev = sample_event("anomaly_observation");
        let a = extract_signal(&ev, &policy).expect("extract a");
        let b = extract_signal(&ev, &policy).expect("extract b");
        assert_eq!(a.signal_id, b.signal_id);
        assert_eq!(a.payload_hash, b.payload_hash);
        assert_eq!(a.redacted_payload, b.redacted_payload);
    }

    // 2. Determinism across kinds — different kind, same trace, must differ.
    #[test]
    fn determinism_kind_changes_signal_id() {
        let policy = policy_with_redactions();
        let a = extract_signal(&sample_event("anomaly_observation"), &policy).unwrap();
        let b = extract_signal(&sample_event("trust_card_delta"), &policy).unwrap();
        assert_ne!(a.signal_id, b.signal_id);
    }

    // 3. Redaction — listed field MUST NOT appear in redacted_payload.
    #[test]
    fn redaction_drops_listed_fields() {
        let policy = policy_with_redactions();
        let sig = extract_signal(&sample_event("anomaly_observation"), &policy).unwrap();
        assert!(!sig.redacted_payload.contains_key("secret_token"));
        assert!(sig.redacted_payload.contains_key("host"));
        assert!(sig.redacted_payload.contains_key("category"));
    }

    // 4. Redaction changes payload_hash deterministically.
    #[test]
    fn redaction_changes_payload_hash() {
        let permissive = ExtractionPolicy::permissive_for_tests();
        let strict = policy_with_redactions();
        let a = extract_signal(&sample_event("anomaly_observation"), &permissive).unwrap();
        let b = extract_signal(&sample_event("anomaly_observation"), &strict).unwrap();
        assert_ne!(a.payload_hash, b.payload_hash);
    }

    // 5. Length-prefix collision resistance — payloads that would alias under
    //    naive concat must have distinct payload_hash values.
    #[test]
    fn length_prefix_collision_resistance() {
        // (k="ab", v="cd") vs (k="abc", v="d") concatenate to the same bytes
        // "abcd" without length-prefix. With length-prefix the hashes differ.
        let mut p1 = BTreeMap::new();
        p1.insert("ab".to_string(), "cd".to_string());
        let mut p2 = BTreeMap::new();
        p2.insert("abc".to_string(), "d".to_string());
        assert_ne!(compute_payload_hash(&p1), compute_payload_hash(&p2));
    }

    // 6. Length-prefix collision resistance across signal_id (trace vs kind).
    #[test]
    fn length_prefix_collision_resistance_signal_id() {
        // trace_id="aanomaly_observation" + kind="" would collide with
        // trace_id="a" + kind="anomaly_observation" under naive concat.
        let a = compute_signal_id("aanomaly_observation", SignalKind::AnomalyObservation, 0);
        let b = compute_signal_id("a", SignalKind::AnomalyObservation, 0);
        assert_ne!(a, b);
    }

    // 7. max_payload_bytes is enforced fail-closed.
    #[test]
    fn max_payload_bytes_enforced() {
        let mut policy = ExtractionPolicy::permissive_for_tests();
        policy.max_payload_bytes = 4; // absurdly tight
        let err = extract_signal(&sample_event("anomaly_observation"), &policy)
            .expect_err("must reject");
        match err {
            ExtractionError::PayloadTooLarge { code, .. } => {
                assert_eq!(code, event_codes::PAYLOAD_TOO_LARGE);
            }
            other => panic!("expected PayloadTooLarge, got {other:?}"),
        }
    }

    // 8. Kind filtering — disallowed kind is rejected even if event is well-formed.
    #[test]
    fn kind_filtering_rejects_disallowed() {
        let mut policy = ExtractionPolicy::permissive_for_tests();
        policy.allowed_kinds.remove(&SignalKind::AnomalyObservation);
        let err = extract_signal(&sample_event("anomaly_observation"), &policy)
            .expect_err("must reject");
        match err {
            ExtractionError::KindFiltered { kind, code } => {
                assert_eq!(kind, SignalKind::AnomalyObservation);
                assert_eq!(code, event_codes::KIND_FILTERED);
            }
            other => panic!("expected KindFiltered, got {other:?}"),
        }
    }

    // 9. Unknown kind discriminant rejected.
    #[test]
    fn unknown_kind_rejected() {
        let policy = ExtractionPolicy::permissive_for_tests();
        let mut ev = sample_event("anomaly_observation");
        ev["event_type"] = json!("never_heard_of_it");
        let err = extract_signal(&ev, &policy).expect_err("must reject");
        match err {
            ExtractionError::UnknownKind { code, .. } => {
                assert_eq!(code, event_codes::UNKNOWN_KIND);
            }
            other => panic!("expected UnknownKind, got {other:?}"),
        }
    }

    // 10. Missing required field — trace_id absent.
    #[test]
    fn missing_field_rejected() {
        let policy = ExtractionPolicy::permissive_for_tests();
        let mut ev = sample_event("anomaly_observation");
        ev.as_object_mut().unwrap().remove("trace_id");
        let err = extract_signal(&ev, &policy).expect_err("must reject");
        match err {
            ExtractionError::MissingField { field, code } => {
                assert_eq!(field, "trace_id");
                assert_eq!(code, event_codes::MISSING_FIELD);
            }
            other => panic!("expected MissingField, got {other:?}"),
        }
    }

    // 11. Malformed top-level (not an object).
    #[test]
    fn malformed_top_level_rejected() {
        let policy = ExtractionPolicy::permissive_for_tests();
        let ev = json!([1, 2, 3]);
        let err = extract_signal(&ev, &policy).expect_err("must reject");
        match err {
            ExtractionError::Malformed { code, .. } => {
                assert_eq!(code, event_codes::MALFORMED_EVENT);
            }
            other => panic!("expected Malformed, got {other:?}"),
        }
    }

    // 12. Replay auditability — trace_id is echoed unchanged, and the audit
    //     log records exactly one entry per successful extraction.
    #[test]
    fn replay_auditability_and_audit_log() {
        let policy = policy_with_redactions();
        let mut log = ExtractionAuditLog::new();
        let sig = extract_signal(&sample_event("quarantine_event"), &policy).unwrap();
        log.record_ok(&sig);
        assert_eq!(sig.trace_id, "trace-abc-123");
        assert_eq!(log.entries().len(), 1);
        assert_eq!(log.entries()[0].signal_id, sig.signal_id);
        assert_eq!(log.entries()[0].event_code.as_str(), event_codes::SIGNAL_EXTRACTED);
    }

    // 13. Bonus: round-trip serde of the output signal preserves bytes.
    #[test]
    fn signal_serde_roundtrip() {
        let policy = policy_with_redactions();
        let sig = extract_signal(&sample_event("revocation_hint"), &policy).unwrap();
        let bytes = serde_json::to_vec(&sig).unwrap();
        let parsed: AtcLocalSignal = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(sig, parsed);
    }
}
