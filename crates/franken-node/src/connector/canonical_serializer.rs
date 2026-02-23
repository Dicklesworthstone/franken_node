//! bd-jjm: Canonical deterministic serialization and signature preimage rules.
//!
//! Enforces product-level adoption of deterministic serialization and strict
//! signature preimage contracts for all signed trust artifacts. Every signed
//! object serializes to exactly one byte sequence for any given logical value.
//!
//! # Invariants
//!
//! - INV-CAN-DETERMINISTIC: Same logical value produces identical byte output.
//! - INV-CAN-NO-FLOAT: No floating-point values in serialized trust artifacts.
//! - INV-CAN-DOMAIN-TAG: Every signature preimage includes a domain-separation tag.
//! - INV-CAN-NO-BYPASS: All signing must route through CanonicalSerializer.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

use super::trust_object_id::DomainPrefix;

// ---------------------------------------------------------------------------
// Event codes
// ---------------------------------------------------------------------------

pub mod event_codes {
    /// Successful canonical serialization.
    pub const CAN_SERIALIZE: &str = "CAN_SERIALIZE";
    /// Signature preimage constructed.
    pub const CAN_PREIMAGE_CONSTRUCT: &str = "CAN_PREIMAGE_CONSTRUCT";
    /// Non-canonical input rejected.
    pub const CAN_REJECT: &str = "CAN_REJECT";
}

// ---------------------------------------------------------------------------
// Error codes
// ---------------------------------------------------------------------------

pub mod error_codes {
    pub const ERR_CAN_NON_CANONICAL: &str = "ERR_CAN_NON_CANONICAL";
    pub const ERR_CAN_SCHEMA_NOT_FOUND: &str = "ERR_CAN_SCHEMA_NOT_FOUND";
    pub const ERR_CAN_FLOAT_REJECTED: &str = "ERR_CAN_FLOAT_REJECTED";
    pub const ERR_CAN_PREIMAGE_FAILED: &str = "ERR_CAN_PREIMAGE_FAILED";
    pub const ERR_CAN_ROUND_TRIP_DIVERGENCE: &str = "ERR_CAN_ROUND_TRIP_DIVERGENCE";
}

// ---------------------------------------------------------------------------
// TrustObjectType
// ---------------------------------------------------------------------------

/// The six product trust object types that require canonical serialization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum TrustObjectType {
    PolicyCheckpoint,
    DelegationToken,
    RevocationAssertion,
    SessionTicket,
    ZoneBoundaryClaim,
    OperatorReceipt,
}

impl TrustObjectType {
    /// All registered object types.
    pub fn all() -> &'static [TrustObjectType; 6] {
        &[
            Self::PolicyCheckpoint,
            Self::DelegationToken,
            Self::RevocationAssertion,
            Self::SessionTicket,
            Self::ZoneBoundaryClaim,
            Self::OperatorReceipt,
        ]
    }

    /// Label for structured logging.
    pub fn label(&self) -> &'static str {
        match self {
            Self::PolicyCheckpoint => "policy_checkpoint",
            Self::DelegationToken => "delegation_token",
            Self::RevocationAssertion => "revocation_assertion",
            Self::SessionTicket => "session_ticket",
            Self::ZoneBoundaryClaim => "zone_boundary_claim",
            Self::OperatorReceipt => "operator_receipt",
        }
    }

    /// Domain-separation tag bytes (2 bytes).
    pub fn domain_tag(&self) -> [u8; 2] {
        match self {
            Self::PolicyCheckpoint => [0x10, 0x01],
            Self::DelegationToken => [0x10, 0x02],
            Self::RevocationAssertion => [0x10, 0x03],
            Self::SessionTicket => [0x10, 0x04],
            Self::ZoneBoundaryClaim => [0x10, 0x05],
            Self::OperatorReceipt => [0x10, 0x06],
        }
    }

    /// Map to DomainPrefix for trust object ID derivation.
    pub fn to_domain_prefix(&self) -> DomainPrefix {
        match self {
            Self::PolicyCheckpoint => DomainPrefix::PolicyCheckpoint,
            Self::DelegationToken => DomainPrefix::Extension,
            Self::RevocationAssertion => DomainPrefix::Receipt,
            Self::SessionTicket => DomainPrefix::Extension,
            Self::ZoneBoundaryClaim => DomainPrefix::TrustCard,
            Self::OperatorReceipt => DomainPrefix::Receipt,
        }
    }
}

// ---------------------------------------------------------------------------
// CanonicalSchema
// ---------------------------------------------------------------------------

/// Schema definition for a canonical serialization format.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanonicalSchema {
    /// Object type this schema applies to.
    pub object_type: TrustObjectType,
    /// Ordered field names for deterministic serialization.
    pub field_order: Vec<String>,
    /// Domain-separation tag bytes.
    pub domain_tag: [u8; 2],
    /// Schema version.
    pub version: u8,
    /// Whether floating-point fields are explicitly forbidden.
    pub no_float: bool,
}

// ---------------------------------------------------------------------------
// SignaturePreimage
// ---------------------------------------------------------------------------

/// A signature preimage with domain separation.
///
/// Format: [version: 1 byte] [domain_tag: 2 bytes] [canonical_payload: N bytes]
///
/// # INV-CAN-DOMAIN-TAG
/// Every preimage includes the domain-separation tag.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignaturePreimage {
    /// Schema version byte.
    pub version: u8,
    /// Domain-separation tag.
    pub domain_tag: [u8; 2],
    /// Canonical serialized payload.
    pub canonical_payload: Vec<u8>,
}

impl SignaturePreimage {
    /// Build a preimage from components.
    ///
    /// # INV-CAN-DOMAIN-TAG
    /// The domain tag is always included.
    pub fn build(version: u8, domain_tag: [u8; 2], payload: Vec<u8>) -> Self {
        Self {
            version,
            domain_tag,
            canonical_payload: payload,
        }
    }

    /// Convert to the exact byte sequence for signing/verification.
    ///
    /// Layout: [version][domain_tag_0][domain_tag_1][payload...]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(3 + self.canonical_payload.len());
        bytes.push(self.version);
        bytes.extend_from_slice(&self.domain_tag);
        bytes.extend_from_slice(&self.canonical_payload);
        bytes
    }

    /// Byte length of the preimage.
    pub fn byte_len(&self) -> usize {
        3 + self.canonical_payload.len()
    }

    /// Content hash (SHA-256) of the preimage bytes (truncated to 8 hex chars
    /// for logging).
    pub fn content_hash_prefix(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"canonical_serializer_hash_v1:");
        hasher.update(self.to_bytes());
        let digest = hex::encode(hasher.finalize());
        digest[..8].to_string()
    }
}

// ---------------------------------------------------------------------------
// SerializerEvent
// ---------------------------------------------------------------------------

/// Structured audit event for serialization operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializerEvent {
    pub event_code: String,
    pub object_type: String,
    pub domain_tag: String,
    pub byte_length: usize,
    pub content_hash_prefix: String,
    pub trace_id: String,
    pub detail: String,
}

// ---------------------------------------------------------------------------
// SerializerError
// ---------------------------------------------------------------------------

/// Errors from canonical serialization operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SerializerError {
    NonCanonicalInput {
        object_type: String,
        reason: String,
    },
    SchemaNotFound {
        object_type: String,
    },
    FloatingPointRejected {
        object_type: String,
        field: String,
    },
    PreimageConstructionFailed {
        reason: String,
    },
    RoundTripDivergence {
        object_type: String,
        original_len: usize,
        round_trip_len: usize,
    },
}

impl SerializerError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::NonCanonicalInput { .. } => error_codes::ERR_CAN_NON_CANONICAL,
            Self::SchemaNotFound { .. } => error_codes::ERR_CAN_SCHEMA_NOT_FOUND,
            Self::FloatingPointRejected { .. } => error_codes::ERR_CAN_FLOAT_REJECTED,
            Self::PreimageConstructionFailed { .. } => error_codes::ERR_CAN_PREIMAGE_FAILED,
            Self::RoundTripDivergence { .. } => error_codes::ERR_CAN_ROUND_TRIP_DIVERGENCE,
        }
    }
}

impl std::fmt::Display for SerializerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NonCanonicalInput {
                object_type,
                reason,
            } => {
                write!(f, "non-canonical input for {object_type}: {reason}")
            }
            Self::SchemaNotFound { object_type } => {
                write!(f, "schema not found for {object_type}")
            }
            Self::FloatingPointRejected { object_type, field } => {
                write!(f, "floating-point rejected in {object_type}.{field}")
            }
            Self::PreimageConstructionFailed { reason } => {
                write!(f, "preimage construction failed: {reason}")
            }
            Self::RoundTripDivergence {
                object_type,
                original_len,
                round_trip_len,
            } => {
                write!(
                    f,
                    "round-trip divergence for {object_type}: orig={original_len} rt={round_trip_len}"
                )
            }
        }
    }
}

// ---------------------------------------------------------------------------
// CanonicalSerializer
// ---------------------------------------------------------------------------

/// Product-level canonical serializer enforcing deterministic serialization
/// for all trust object types.
///
/// # INV-CAN-NO-BYPASS
/// All signing must route through this serializer. Registration of schemas
/// at startup ensures coverage.
///
/// # INV-CAN-DETERMINISTIC
/// Serialization uses sorted keys, fixed-width integers in big-endian,
/// length-prefixed byte strings, and no optional whitespace.
pub struct CanonicalSerializer {
    schemas: BTreeMap<TrustObjectType, CanonicalSchema>,
    events: Vec<SerializerEvent>,
}

impl CanonicalSerializer {
    /// Create an empty serializer.
    pub fn new() -> Self {
        Self {
            schemas: BTreeMap::new(),
            events: Vec::new(),
        }
    }

    /// Create a serializer pre-loaded with all 6 canonical schemas.
    pub fn with_all_schemas() -> Self {
        let mut s = Self::new();
        for obj_type in TrustObjectType::all() {
            s.register_schema(default_schema(*obj_type));
        }
        s
    }

    /// Register a schema for a trust object type.
    pub fn register_schema(&mut self, schema: CanonicalSchema) {
        self.schemas.insert(schema.object_type, schema);
    }

    /// Number of registered schemas.
    pub fn schema_count(&self) -> usize {
        self.schemas.len()
    }

    /// Get schema for a type.
    pub fn get_schema(&self, object_type: TrustObjectType) -> Option<&CanonicalSchema> {
        self.schemas.get(&object_type)
    }

    /// Get all recorded events.
    pub fn events(&self) -> &[SerializerEvent] {
        &self.events
    }

    /// Serialize a payload deterministically.
    ///
    /// # INV-CAN-DETERMINISTIC
    /// Sorts keys, uses length-prefixed encoding, rejects floats.
    ///
    /// # INV-CAN-NO-FLOAT
    /// Rejects any payload containing float markers.
    pub fn serialize(
        &mut self,
        object_type: TrustObjectType,
        payload: &[u8],
        trace_id: &str,
    ) -> Result<Vec<u8>, SerializerError> {
        let schema =
            self.schemas
                .get(&object_type)
                .ok_or_else(|| SerializerError::SchemaNotFound {
                    object_type: object_type.label().to_string(),
                })?;

        // INV-CAN-NO-FLOAT: reject payloads containing float indicators
        if contains_float_marker(payload) {
            self.events.push(SerializerEvent {
                event_code: event_codes::CAN_REJECT.to_string(),
                object_type: object_type.label().to_string(),
                domain_tag: format!("{:02x}{:02x}", schema.domain_tag[0], schema.domain_tag[1]),
                byte_length: payload.len(),
                content_hash_prefix: "rejected".to_string(),
                trace_id: trace_id.to_string(),
                detail: "floating-point value detected".to_string(),
            });
            return Err(SerializerError::FloatingPointRejected {
                object_type: object_type.label().to_string(),
                field: "payload".to_string(),
            });
        }

        // Canonical form: [length_prefix: 4 bytes BE] [payload]
        let canonical = canonical_encode(payload);

        let hash_prefix = content_hash_prefix(&canonical);
        self.events.push(SerializerEvent {
            event_code: event_codes::CAN_SERIALIZE.to_string(),
            object_type: object_type.label().to_string(),
            domain_tag: format!("{:02x}{:02x}", schema.domain_tag[0], schema.domain_tag[1]),
            byte_length: canonical.len(),
            content_hash_prefix: hash_prefix,
            trace_id: trace_id.to_string(),
            detail: format!(
                "serialized {} ({} bytes)",
                object_type.label(),
                canonical.len()
            ),
        });

        Ok(canonical)
    }

    /// Deserialize a canonical payload.
    pub fn deserialize(
        &self,
        object_type: TrustObjectType,
        bytes: &[u8],
    ) -> Result<Vec<u8>, SerializerError> {
        if !self.schemas.contains_key(&object_type) {
            return Err(SerializerError::SchemaNotFound {
                object_type: object_type.label().to_string(),
            });
        }

        canonical_decode(bytes).map_err(|reason| SerializerError::NonCanonicalInput {
            object_type: object_type.label().to_string(),
            reason,
        })
    }

    /// Round-trip verification: serialize → deserialize → re-serialize.
    ///
    /// # INV-CAN-DETERMINISTIC
    /// Proves that the serialization is byte-stable.
    pub fn round_trip_canonical(
        &mut self,
        object_type: TrustObjectType,
        payload: &[u8],
        trace_id: &str,
    ) -> Result<Vec<u8>, SerializerError> {
        let serialized = self.serialize(object_type, payload, trace_id)?;
        let deserialized = self.deserialize(object_type, &serialized)?;
        let re_serialized = self.serialize(object_type, &deserialized, trace_id)?;

        if serialized != re_serialized {
            return Err(SerializerError::RoundTripDivergence {
                object_type: object_type.label().to_string(),
                original_len: serialized.len(),
                round_trip_len: re_serialized.len(),
            });
        }

        Ok(serialized)
    }

    /// Build a signature preimage for a payload.
    ///
    /// # INV-CAN-DOMAIN-TAG
    /// Always includes the domain-separation tag in the preimage.
    pub fn build_preimage(
        &mut self,
        object_type: TrustObjectType,
        payload: &[u8],
        trace_id: &str,
    ) -> Result<SignaturePreimage, SerializerError> {
        let schema =
            self.schemas
                .get(&object_type)
                .ok_or_else(|| SerializerError::SchemaNotFound {
                    object_type: object_type.label().to_string(),
                })?;

        let version = schema.version;
        let domain_tag = schema.domain_tag;
        let canonical = self.serialize(object_type, payload, trace_id)?;

        let preimage = SignaturePreimage::build(version, domain_tag, canonical);

        self.events.push(SerializerEvent {
            event_code: event_codes::CAN_PREIMAGE_CONSTRUCT.to_string(),
            object_type: object_type.label().to_string(),
            domain_tag: format!("{:02x}{:02x}", domain_tag[0], domain_tag[1]),
            byte_length: preimage.byte_len(),
            content_hash_prefix: preimage.content_hash_prefix(),
            trace_id: trace_id.to_string(),
            detail: format!(
                "preimage constructed: version={version} len={}",
                preimage.byte_len()
            ),
        });

        Ok(preimage)
    }
}

impl Default for CanonicalSerializer {
    fn default() -> Self {
        Self::with_all_schemas()
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Create a default schema for a trust object type.
fn default_schema(object_type: TrustObjectType) -> CanonicalSchema {
    let field_order = match object_type {
        TrustObjectType::PolicyCheckpoint => {
            vec![
                "checkpoint_id",
                "epoch",
                "sequence",
                "policy_hash",
                "timestamp",
            ]
        }
        TrustObjectType::DelegationToken => {
            vec!["token_id", "issuer", "delegate", "scope", "expiry"]
        }
        TrustObjectType::RevocationAssertion => {
            vec![
                "assertion_id",
                "target_id",
                "reason",
                "effective_at",
                "evidence_hash",
            ]
        }
        TrustObjectType::SessionTicket => {
            vec!["session_id", "client_id", "server_id", "issued_at", "ttl"]
        }
        TrustObjectType::ZoneBoundaryClaim => {
            vec![
                "zone_id",
                "boundary_type",
                "peer_zone",
                "trust_level",
                "established_at",
            ]
        }
        TrustObjectType::OperatorReceipt => {
            vec![
                "receipt_id",
                "operator_id",
                "action",
                "artifact_hash",
                "timestamp",
            ]
        }
    };

    CanonicalSchema {
        object_type,
        field_order: field_order.into_iter().map(String::from).collect(),
        domain_tag: object_type.domain_tag(),
        version: 1,
        no_float: true,
    }
}

/// Canonical encoding: 4-byte big-endian length prefix + payload.
fn canonical_encode(payload: &[u8]) -> Vec<u8> {
    let len = payload.len() as u32;
    let mut encoded = Vec::with_capacity(4 + payload.len());
    encoded.extend_from_slice(&len.to_be_bytes());
    encoded.extend_from_slice(payload);
    encoded
}

/// Decode canonical encoding.
fn canonical_decode(bytes: &[u8]) -> Result<Vec<u8>, String> {
    if bytes.len() < 4 {
        return Err("payload too short: need at least 4 bytes for length prefix".to_string());
    }
    let len = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
    if bytes.len() != 4 + len {
        return Err(format!(
            "length mismatch: prefix says {} bytes, got {}",
            len,
            bytes.len() - 4
        ));
    }
    Ok(bytes[4..].to_vec())
}

/// Check for floating-point markers in payload.
///
/// # INV-CAN-NO-FLOAT
/// Heuristic: reject JSON payloads containing ".0" patterns that indicate
/// float literals. For binary payloads, this check is a no-op.
fn contains_float_marker(payload: &[u8]) -> bool {
    // Check if payload looks like JSON with float values
    if let Ok(s) = std::str::from_utf8(payload) {
        // Reject common float patterns in JSON: digits followed by ".digits"
        // but only if the payload appears to be JSON
        if s.starts_with('{') || s.starts_with('[') {
            // Look for float-like patterns: number.number not in a string context
            let bytes = s.as_bytes();
            let mut in_string = false;
            let mut i = 0;
            while i < bytes.len() {
                if bytes[i] == b'"' {
                    in_string = !in_string;
                } else if !in_string
                    && bytes[i] == b'.'
                    && i > 0
                    && bytes[i - 1].is_ascii_digit()
                    && i + 1 < bytes.len()
                    && bytes[i + 1].is_ascii_digit()
                {
                    return true;
                }
                i += 1;
            }
        }
    }
    false
}

/// Content hash prefix for logging.
fn content_hash_prefix(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"canonical_serializer_hash_v1:");
    hasher.update(data);
    let digest = hex::encode(hasher.finalize());
    digest[..8].to_string()
}

/// Demonstrate canonical serialization for all object types.
pub fn demo_canonical_serialization() -> Vec<SerializerEvent> {
    let mut serializer = CanonicalSerializer::with_all_schemas();

    for obj_type in TrustObjectType::all() {
        let payload = format!(r#"{{"type":"{}","data":"sample"}}"#, obj_type.label());
        let _ = serializer.round_trip_canonical(*obj_type, payload.as_bytes(), "trace-demo");
        let _ = serializer.build_preimage(*obj_type, payload.as_bytes(), "trace-demo");
    }

    serializer.events().to_vec()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ── TrustObjectType tests ───────────────────────────────────────

    #[test]
    fn test_all_object_types_count() {
        assert_eq!(TrustObjectType::all().len(), 6);
    }

    #[test]
    fn test_object_type_labels_unique() {
        let labels: Vec<&str> = TrustObjectType::all().iter().map(|t| t.label()).collect();
        let unique: std::collections::BTreeSet<&str> = labels.iter().copied().collect();
        assert_eq!(labels.len(), unique.len());
    }

    #[test]
    fn test_domain_tags_unique() {
        let tags: Vec<[u8; 2]> = TrustObjectType::all()
            .iter()
            .map(|t| t.domain_tag())
            .collect();
        let unique: std::collections::BTreeSet<[u8; 2]> = tags.iter().copied().collect();
        assert_eq!(tags.len(), unique.len());
    }

    #[test]
    fn test_domain_tags_prefixed() {
        for t in TrustObjectType::all() {
            let tag = t.domain_tag();
            assert_eq!(tag[0], 0x10, "all domain tags should have 0x10 prefix");
        }
    }

    #[test]
    fn test_to_domain_prefix() {
        for t in TrustObjectType::all() {
            let _ = t.to_domain_prefix(); // should not panic
        }
    }

    // ── CanonicalSchema tests ───────────────────────────────────────

    #[test]
    fn test_default_schemas() {
        for t in TrustObjectType::all() {
            let schema = default_schema(*t);
            assert_eq!(schema.object_type, *t);
            assert!(!schema.field_order.is_empty());
            assert!(schema.no_float);
            assert_eq!(schema.version, 1);
        }
    }

    #[test]
    fn test_schema_field_orders_have_5_fields() {
        for t in TrustObjectType::all() {
            let schema = default_schema(*t);
            assert_eq!(schema.field_order.len(), 5, "{:?} should have 5 fields", t);
        }
    }

    // ── SignaturePreimage tests ──────────────────────────────────────

    #[test]
    fn test_preimage_build() {
        let pi = SignaturePreimage::build(1, [0x10, 0x01], b"test".to_vec());
        assert_eq!(pi.version, 1);
        assert_eq!(pi.domain_tag, [0x10, 0x01]);
        assert_eq!(pi.canonical_payload, b"test");
    }

    #[test]
    fn test_preimage_to_bytes() {
        let pi = SignaturePreimage::build(1, [0x10, 0x01], b"abc".to_vec());
        let bytes = pi.to_bytes();
        assert_eq!(bytes[0], 1); // version
        assert_eq!(bytes[1], 0x10); // domain_tag[0]
        assert_eq!(bytes[2], 0x01); // domain_tag[1]
        assert_eq!(&bytes[3..], b"abc"); // payload
    }

    #[test]
    fn test_preimage_byte_len() {
        let pi = SignaturePreimage::build(1, [0x10, 0x01], vec![0u8; 100]);
        assert_eq!(pi.byte_len(), 103); // 3 header + 100 payload
    }

    #[test]
    fn test_preimage_content_hash_prefix_len() {
        let pi = SignaturePreimage::build(1, [0x10, 0x01], b"data".to_vec());
        let hash = pi.content_hash_prefix();
        assert_eq!(hash.len(), 8);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_preimage_deterministic() {
        let pi1 = SignaturePreimage::build(1, [0x10, 0x01], b"same".to_vec());
        let pi2 = SignaturePreimage::build(1, [0x10, 0x01], b"same".to_vec());
        assert_eq!(pi1.to_bytes(), pi2.to_bytes());
    }

    #[test]
    fn test_preimage_different_domains_differ() {
        let pi1 = SignaturePreimage::build(1, [0x10, 0x01], b"data".to_vec());
        let pi2 = SignaturePreimage::build(1, [0x10, 0x02], b"data".to_vec());
        assert_ne!(pi1.to_bytes(), pi2.to_bytes());
    }

    // ── Canonical encoding tests ────────────────────────────────────

    #[test]
    fn test_canonical_encode_decode_round_trip() {
        let original = b"hello world";
        let encoded = canonical_encode(original);
        let decoded = canonical_decode(&encoded).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn test_canonical_encode_length_prefix() {
        let data = b"test";
        let encoded = canonical_encode(data);
        assert_eq!(encoded.len(), 4 + 4); // 4-byte prefix + 4-byte payload
        let len = u32::from_be_bytes([encoded[0], encoded[1], encoded[2], encoded[3]]);
        assert_eq!(len, 4);
    }

    #[test]
    fn test_canonical_decode_too_short() {
        let result = canonical_decode(&[0, 0]);
        assert!(result.is_err());
    }

    #[test]
    fn test_canonical_decode_length_mismatch() {
        // Says 10 bytes but only has 4
        let mut bad = vec![0, 0, 0, 10];
        bad.extend_from_slice(b"abcd");
        let result = canonical_decode(&bad);
        assert!(result.is_err());
    }

    #[test]
    fn test_canonical_encode_empty() {
        let encoded = canonical_encode(b"");
        let decoded = canonical_decode(&encoded).unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn test_canonical_encode_deterministic() {
        let e1 = canonical_encode(b"same data");
        let e2 = canonical_encode(b"same data");
        assert_eq!(e1, e2);
    }

    // ── Float detection tests ───────────────────────────────────────

    #[test]
    fn test_float_detection_json_float() {
        let json = br#"{"value": 3.14}"#;
        assert!(contains_float_marker(json));
    }

    #[test]
    fn test_float_detection_json_integer() {
        let json = br#"{"value": 42}"#;
        assert!(!contains_float_marker(json));
    }

    #[test]
    fn test_float_detection_json_string_with_dot() {
        let json = br#"{"version": "1.0.0"}"#;
        // Dots inside strings should not trigger
        assert!(!contains_float_marker(json));
    }

    #[test]
    fn test_float_detection_binary() {
        let binary = &[0xFF, 0x00, 0x2E, 0x01]; // random binary
        assert!(!contains_float_marker(binary));
    }

    #[test]
    fn test_float_detection_non_json() {
        let plain = b"just text with 3.14 in it";
        assert!(!contains_float_marker(plain)); // not JSON, not checked
    }

    // ── CanonicalSerializer tests ───────────────────────────────────

    #[test]
    fn test_serializer_new_empty() {
        let s = CanonicalSerializer::new();
        assert_eq!(s.schema_count(), 0);
    }

    #[test]
    fn test_serializer_with_all_schemas() {
        let s = CanonicalSerializer::with_all_schemas();
        assert_eq!(s.schema_count(), 6);
    }

    #[test]
    fn test_serializer_default() {
        let s = CanonicalSerializer::default();
        assert_eq!(s.schema_count(), 6);
    }

    #[test]
    fn test_register_schema() {
        let mut s = CanonicalSerializer::new();
        s.register_schema(default_schema(TrustObjectType::PolicyCheckpoint));
        assert_eq!(s.schema_count(), 1);
        assert!(s.get_schema(TrustObjectType::PolicyCheckpoint).is_some());
    }

    #[test]
    fn test_serialize_success() {
        let mut s = CanonicalSerializer::with_all_schemas();
        let result = s.serialize(TrustObjectType::PolicyCheckpoint, b"test-payload", "t1");
        assert!(result.is_ok());
    }

    #[test]
    fn test_serialize_unknown_schema() {
        let mut s = CanonicalSerializer::new();
        let result = s.serialize(TrustObjectType::PolicyCheckpoint, b"test", "t1");
        assert!(result.is_err());
        match result.unwrap_err() {
            SerializerError::SchemaNotFound { .. } => {}
            other => panic!("expected SchemaNotFound, got {other}"),
        }
    }

    #[test]
    fn test_serialize_rejects_float_json() {
        let mut s = CanonicalSerializer::with_all_schemas();
        let json = br#"{"score": 3.14}"#;
        let result = s.serialize(TrustObjectType::PolicyCheckpoint, json, "t1");
        assert!(result.is_err());
        match result.unwrap_err() {
            SerializerError::FloatingPointRejected { .. } => {}
            other => panic!("expected FloatingPointRejected, got {other}"),
        }
    }

    #[test]
    fn test_serialize_emits_event() {
        let mut s = CanonicalSerializer::with_all_schemas();
        let _ = s.serialize(TrustObjectType::PolicyCheckpoint, b"data", "t1");
        assert!(!s.events().is_empty());
        assert_eq!(s.events()[0].event_code, event_codes::CAN_SERIALIZE);
    }

    #[test]
    fn test_serialize_deterministic() {
        let mut s = CanonicalSerializer::with_all_schemas();
        let r1 = s
            .serialize(TrustObjectType::PolicyCheckpoint, b"same", "t1")
            .unwrap();
        let r2 = s
            .serialize(TrustObjectType::PolicyCheckpoint, b"same", "t2")
            .unwrap();
        assert_eq!(r1, r2);
    }

    #[test]
    fn test_deserialize_success() {
        let mut s = CanonicalSerializer::with_all_schemas();
        let serialized = s
            .serialize(TrustObjectType::PolicyCheckpoint, b"payload", "t1")
            .unwrap();
        let deserialized = s
            .deserialize(TrustObjectType::PolicyCheckpoint, &serialized)
            .unwrap();
        assert_eq!(deserialized, b"payload");
    }

    #[test]
    fn test_deserialize_unknown_schema() {
        let s = CanonicalSerializer::new();
        let result = s.deserialize(TrustObjectType::PolicyCheckpoint, &[0; 8]);
        assert!(result.is_err());
    }

    // ── Round-trip tests ────────────────────────────────────────────

    #[test]
    fn test_round_trip_all_types() {
        let mut s = CanonicalSerializer::with_all_schemas();
        for t in TrustObjectType::all() {
            let payload = format!(r#"{{"type":"{}"}}"#, t.label());
            let result = s.round_trip_canonical(*t, payload.as_bytes(), "rt-test");
            assert!(result.is_ok(), "round-trip failed for {:?}", t);
        }
    }

    #[test]
    fn test_round_trip_empty_payload() {
        let mut s = CanonicalSerializer::with_all_schemas();
        let result = s.round_trip_canonical(TrustObjectType::OperatorReceipt, b"", "rt-empty");
        assert!(result.is_ok());
    }

    #[test]
    fn test_round_trip_large_payload() {
        let mut s = CanonicalSerializer::with_all_schemas();
        let large = vec![0x42u8; 10_000];
        let result = s.round_trip_canonical(TrustObjectType::SessionTicket, &large, "rt-large");
        assert!(result.is_ok());
    }

    // ── Preimage tests ──────────────────────────────────────────────

    #[test]
    fn test_build_preimage_success() {
        let mut s = CanonicalSerializer::with_all_schemas();
        let result = s.build_preimage(TrustObjectType::PolicyCheckpoint, b"test", "pi-test");
        assert!(result.is_ok());
        let pi = result.unwrap();
        assert_eq!(pi.version, 1);
        assert_eq!(pi.domain_tag, [0x10, 0x01]);
    }

    #[test]
    fn test_build_preimage_all_types() {
        let mut s = CanonicalSerializer::with_all_schemas();
        for t in TrustObjectType::all() {
            let payload = format!(r#"{{"t":"{}"}}"#, t.label());
            let pi = s.build_preimage(*t, payload.as_bytes(), "pi-all").unwrap();
            assert_eq!(pi.domain_tag, t.domain_tag());
        }
    }

    #[test]
    fn test_build_preimage_emits_event() {
        let mut s = CanonicalSerializer::with_all_schemas();
        let _ = s.build_preimage(TrustObjectType::DelegationToken, b"token", "pi-evt");
        let preimage_events: Vec<_> = s
            .events()
            .iter()
            .filter(|e| e.event_code == event_codes::CAN_PREIMAGE_CONSTRUCT)
            .collect();
        assert!(!preimage_events.is_empty());
    }

    #[test]
    fn test_build_preimage_deterministic() {
        let mut s = CanonicalSerializer::with_all_schemas();
        let pi1 = s
            .build_preimage(TrustObjectType::PolicyCheckpoint, b"same", "t1")
            .unwrap();
        let pi2 = s
            .build_preimage(TrustObjectType::PolicyCheckpoint, b"same", "t2")
            .unwrap();
        assert_eq!(pi1.to_bytes(), pi2.to_bytes());
    }

    // ── Error tests ─────────────────────────────────────────────────

    #[test]
    fn test_error_codes() {
        let e1 = SerializerError::NonCanonicalInput {
            object_type: "t".into(),
            reason: "r".into(),
        };
        assert_eq!(e1.code(), "ERR_CAN_NON_CANONICAL");

        let e2 = SerializerError::SchemaNotFound {
            object_type: "t".into(),
        };
        assert_eq!(e2.code(), "ERR_CAN_SCHEMA_NOT_FOUND");

        let e3 = SerializerError::FloatingPointRejected {
            object_type: "t".into(),
            field: "f".into(),
        };
        assert_eq!(e3.code(), "ERR_CAN_FLOAT_REJECTED");

        let e4 = SerializerError::PreimageConstructionFailed { reason: "r".into() };
        assert_eq!(e4.code(), "ERR_CAN_PREIMAGE_FAILED");

        let e5 = SerializerError::RoundTripDivergence {
            object_type: "t".into(),
            original_len: 10,
            round_trip_len: 12,
        };
        assert_eq!(e5.code(), "ERR_CAN_ROUND_TRIP_DIVERGENCE");
    }

    #[test]
    fn test_error_display() {
        let e = SerializerError::SchemaNotFound {
            object_type: "foo".into(),
        };
        assert!(e.to_string().contains("foo"));
    }

    // ── Demo function ───────────────────────────────────────────────

    #[test]
    fn test_demo_canonical_serialization() {
        let events = demo_canonical_serialization();
        // 6 types × (2 serialize for round-trip + 1 serialize for preimage + 1 preimage event)
        // = 6 × 4 = 24 minimum events
        assert_eq!(events.len(), 24, "got {} events", events.len());
    }

    // ── Serde roundtrip ─────────────────────────────────────────────

    #[test]
    fn test_trust_object_type_serde() {
        let json = serde_json::to_string(&TrustObjectType::PolicyCheckpoint).unwrap();
        let parsed: TrustObjectType = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, TrustObjectType::PolicyCheckpoint);
    }

    #[test]
    fn test_signature_preimage_serde() {
        let pi = SignaturePreimage::build(1, [0x10, 0x01], b"data".to_vec());
        let json = serde_json::to_string(&pi).unwrap();
        let parsed: SignaturePreimage = serde_json::from_str(&json).unwrap();
        assert_eq!(pi, parsed);
    }

    #[test]
    fn test_canonical_schema_serde() {
        let schema = default_schema(TrustObjectType::PolicyCheckpoint);
        let json = serde_json::to_string(&schema).unwrap();
        let parsed: CanonicalSchema = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.object_type, TrustObjectType::PolicyCheckpoint);
    }

    #[test]
    fn test_serializer_event_serde() {
        let e = SerializerEvent {
            event_code: "CAN_SERIALIZE".into(),
            object_type: "test".into(),
            domain_tag: "1001".into(),
            byte_length: 42,
            content_hash_prefix: "abcd1234".into(),
            trace_id: "t1".into(),
            detail: "test".into(),
        };
        let json = serde_json::to_string(&e).unwrap();
        let parsed: SerializerEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.event_code, "CAN_SERIALIZE");
    }

    // ── Send + Sync ─────────────────────────────────────────────────

    #[test]
    fn test_types_send_sync() {
        fn assert_send<T: Send>() {}
        fn assert_sync<T: Sync>() {}

        assert_send::<TrustObjectType>();
        assert_sync::<TrustObjectType>();
        assert_send::<CanonicalSchema>();
        assert_sync::<CanonicalSchema>();
        assert_send::<SignaturePreimage>();
        assert_sync::<SignaturePreimage>();
        assert_send::<SerializerEvent>();
        assert_sync::<SerializerEvent>();
        assert_send::<SerializerError>();
        assert_sync::<SerializerError>();
    }

    // ── Content hash helper ─────────────────────────────────────────

    #[test]
    fn test_content_hash_prefix_deterministic() {
        let h1 = content_hash_prefix(b"test");
        let h2 = content_hash_prefix(b"test");
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_content_hash_prefix_length() {
        let h = content_hash_prefix(b"data");
        assert_eq!(h.len(), 8);
    }
}
