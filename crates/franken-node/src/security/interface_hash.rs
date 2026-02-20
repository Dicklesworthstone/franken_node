//! Domain-separated interface-hash verification and admission telemetry (bd-3n58).
//!
//! Hash derivation uses domain separation: `H(domain || ":" || data)` to
//! prevent cross-domain collisions. Invalid hashes block admission.
//! Telemetry tracks rejection code distribution.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::hash::{DefaultHasher, Hash, Hasher};

// ── Domain-separated hash ───────────────────────────────────────────

/// Compute a domain-separated hash: H(domain || ":" || data).
///
/// Uses SipHash (DefaultHasher) for deterministic, non-cryptographic
/// hashing. In production this would use SHA-256 or BLAKE3.
pub fn compute_hash(domain: &str, data: &[u8]) -> InterfaceHash {
    let mut hasher = DefaultHasher::new();
    // Domain separation: hash domain tag first, then separator, then data
    domain.hash(&mut hasher);
    ":".hash(&mut hasher);
    data.hash(&mut hasher);
    let hash_val = hasher.finish();

    InterfaceHash {
        domain: domain.to_string(),
        hash_hex: format!("{:016x}", hash_val),
        data_len: data.len(),
    }
}

/// Verify that `expected` matches the recomputed hash for the given domain and data.
pub fn verify_hash(
    expected: &InterfaceHash,
    domain: &str,
    data: &[u8],
) -> Result<(), RejectionCode> {
    // Check domain match first
    if expected.domain != domain {
        return Err(RejectionCode::DomainMismatch);
    }

    // Validate hash format
    if expected.hash_hex.len() != 16 || !expected.hash_hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(RejectionCode::MalformedHash);
    }

    // Recompute and compare
    let computed = compute_hash(domain, data);
    if computed.hash_hex != expected.hash_hex {
        return Err(RejectionCode::HashMismatch);
    }

    Ok(())
}

// ── Types ───────────────────────────────────────────────────────────

/// A domain-separated interface hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InterfaceHash {
    pub domain: String,
    pub hash_hex: String,
    pub data_len: usize,
}

/// Result of an admission check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdmissionCheck {
    pub connector_id: String,
    pub domain: String,
    pub admitted: bool,
    pub rejection_code: Option<RejectionCode>,
    pub trace_id: String,
    pub timestamp: String,
}

/// Reason for rejecting an interface hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RejectionCode {
    HashMismatch,
    DomainMismatch,
    ExpiredHash,
    MalformedHash,
}

impl fmt::Display for RejectionCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HashMismatch => write!(f, "IFACE_HASH_MISMATCH"),
            Self::DomainMismatch => write!(f, "IFACE_DOMAIN_MISMATCH"),
            Self::ExpiredHash => write!(f, "IFACE_HASH_EXPIRED"),
            Self::MalformedHash => write!(f, "IFACE_HASH_MALFORMED"),
        }
    }
}

// ── Admission telemetry ─────────────────────────────────────────────

/// Telemetry tracker for admission checks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdmissionTelemetry {
    pub total_checks: u64,
    pub total_admitted: u64,
    pub total_rejected: u64,
    pub rejection_distribution: HashMap<RejectionCode, u64>,
    pub checks: Vec<AdmissionCheck>,
}

impl AdmissionTelemetry {
    pub fn new() -> Self {
        Self {
            total_checks: 0,
            total_admitted: 0,
            total_rejected: 0,
            rejection_distribution: HashMap::new(),
            checks: Vec::new(),
        }
    }

    /// Run a full admission check, record telemetry, and return whether admitted.
    pub fn admit(
        &mut self,
        connector_id: &str,
        expected_hash: &InterfaceHash,
        domain: &str,
        data: &[u8],
        trace_id: &str,
        timestamp: &str,
    ) -> bool {
        self.total_checks += 1;

        let result = verify_hash(expected_hash, domain, data);
        let (admitted, rejection_code) = match result {
            Ok(()) => {
                self.total_admitted += 1;
                (true, None)
            }
            Err(code) => {
                self.total_rejected += 1;
                *self.rejection_distribution.entry(code).or_insert(0) += 1;
                (false, Some(code))
            }
        };

        self.checks.push(AdmissionCheck {
            connector_id: connector_id.to_string(),
            domain: domain.to_string(),
            admitted,
            rejection_code,
            trace_id: trace_id.to_string(),
            timestamp: timestamp.to_string(),
        });

        admitted
    }

    /// Get rejection distribution as sorted Vec for deterministic output.
    pub fn rejection_counts(&self) -> Vec<(RejectionCode, u64)> {
        let mut counts: Vec<_> = self
            .rejection_distribution
            .iter()
            .map(|(k, v)| (*k, *v))
            .collect();
        counts.sort_by_key(|(_, v)| std::cmp::Reverse(*v));
        counts
    }
}

// ── Errors ──────────────────────────────────────────────────────────

/// Errors for interface hash operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum InterfaceHashError {
    #[serde(rename = "IFACE_HASH_MISMATCH")]
    HashMismatch { expected: String, computed: String },
    #[serde(rename = "IFACE_DOMAIN_MISMATCH")]
    DomainMismatch { expected: String, actual: String },
    #[serde(rename = "IFACE_HASH_EXPIRED")]
    HashExpired { hash_hex: String },
    #[serde(rename = "IFACE_HASH_MALFORMED")]
    HashMalformed { hash_hex: String },
}

impl fmt::Display for InterfaceHashError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HashMismatch { expected, computed } => {
                write!(
                    f,
                    "IFACE_HASH_MISMATCH: expected={expected}, computed={computed}"
                )
            }
            Self::DomainMismatch { expected, actual } => {
                write!(
                    f,
                    "IFACE_DOMAIN_MISMATCH: expected={expected}, actual={actual}"
                )
            }
            Self::HashExpired { hash_hex } => {
                write!(f, "IFACE_HASH_EXPIRED: {hash_hex}")
            }
            Self::HashMalformed { hash_hex } => {
                write!(f, "IFACE_HASH_MALFORMED: {hash_hex}")
            }
        }
    }
}

impl std::error::Error for InterfaceHashError {}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // === compute_hash ===

    #[test]
    fn compute_hash_deterministic() {
        let h1 = compute_hash("connector.v1", b"hello");
        let h2 = compute_hash("connector.v1", b"hello");
        assert_eq!(h1, h2);
    }

    #[test]
    fn compute_hash_domain_separation() {
        let h1 = compute_hash("connector.v1", b"hello");
        let h2 = compute_hash("provider.v1", b"hello");
        assert_ne!(h1.hash_hex, h2.hash_hex);
    }

    #[test]
    fn compute_hash_different_data() {
        let h1 = compute_hash("connector.v1", b"hello");
        let h2 = compute_hash("connector.v1", b"world");
        assert_ne!(h1.hash_hex, h2.hash_hex);
    }

    #[test]
    fn compute_hash_records_domain() {
        let h = compute_hash("connector.v1", b"data");
        assert_eq!(h.domain, "connector.v1");
    }

    #[test]
    fn compute_hash_records_data_len() {
        let h = compute_hash("connector.v1", b"12345");
        assert_eq!(h.data_len, 5);
    }

    #[test]
    fn compute_hash_hex_format() {
        let h = compute_hash("test", b"data");
        assert_eq!(h.hash_hex.len(), 16);
        assert!(h.hash_hex.chars().all(|c| c.is_ascii_hexdigit()));
    }

    // === verify_hash ===

    #[test]
    fn verify_valid_hash() {
        let h = compute_hash("connector.v1", b"hello");
        assert!(verify_hash(&h, "connector.v1", b"hello").is_ok());
    }

    #[test]
    fn verify_hash_mismatch() {
        let h = compute_hash("connector.v1", b"hello");
        let result = verify_hash(&h, "connector.v1", b"wrong");
        assert_eq!(result, Err(RejectionCode::HashMismatch));
    }

    #[test]
    fn verify_domain_mismatch() {
        let h = compute_hash("connector.v1", b"hello");
        let result = verify_hash(&h, "provider.v1", b"hello");
        assert_eq!(result, Err(RejectionCode::DomainMismatch));
    }

    #[test]
    fn verify_malformed_hash() {
        let h = InterfaceHash {
            domain: "test".into(),
            hash_hex: "not-hex!!".into(),
            data_len: 0,
        };
        let result = verify_hash(&h, "test", b"data");
        assert_eq!(result, Err(RejectionCode::MalformedHash));
    }

    #[test]
    fn verify_wrong_length_hash() {
        let h = InterfaceHash {
            domain: "test".into(),
            hash_hex: "abc".into(),
            data_len: 0,
        };
        let result = verify_hash(&h, "test", b"data");
        assert_eq!(result, Err(RejectionCode::MalformedHash));
    }

    // === AdmissionTelemetry ===

    #[test]
    fn telemetry_admit_pass() {
        let mut tel = AdmissionTelemetry::new();
        let h = compute_hash("conn.v1", b"data");
        let admitted = tel.admit("conn-1", &h, "conn.v1", b"data", "t1", "ts");
        assert!(admitted);
        assert_eq!(tel.total_checks, 1);
        assert_eq!(tel.total_admitted, 1);
        assert_eq!(tel.total_rejected, 0);
    }

    #[test]
    fn telemetry_admit_reject() {
        let mut tel = AdmissionTelemetry::new();
        let h = compute_hash("conn.v1", b"data");
        let admitted = tel.admit("conn-1", &h, "conn.v1", b"wrong", "t2", "ts");
        assert!(!admitted);
        assert_eq!(tel.total_checks, 1);
        assert_eq!(tel.total_admitted, 0);
        assert_eq!(tel.total_rejected, 1);
    }

    #[test]
    fn telemetry_records_check() {
        let mut tel = AdmissionTelemetry::new();
        let h = compute_hash("conn.v1", b"data");
        tel.admit("conn-1", &h, "conn.v1", b"data", "trace-abc", "ts");
        assert_eq!(tel.checks.len(), 1);
        assert_eq!(tel.checks[0].trace_id, "trace-abc");
        assert!(tel.checks[0].admitted);
    }

    #[test]
    fn telemetry_rejection_distribution() {
        let mut tel = AdmissionTelemetry::new();
        let h = compute_hash("conn.v1", b"data");
        // Hash mismatch
        tel.admit("c1", &h, "conn.v1", b"wrong", "t1", "ts");
        // Domain mismatch
        tel.admit("c2", &h, "other.v1", b"data", "t2", "ts");
        // Another hash mismatch
        tel.admit("c3", &h, "conn.v1", b"also_wrong", "t3", "ts");

        assert_eq!(tel.total_rejected, 3);
        assert_eq!(tel.rejection_distribution[&RejectionCode::HashMismatch], 2);
        assert_eq!(
            tel.rejection_distribution[&RejectionCode::DomainMismatch],
            1
        );
    }

    #[test]
    fn telemetry_rejection_counts_sorted() {
        let mut tel = AdmissionTelemetry::new();
        let h = compute_hash("conn.v1", b"data");
        tel.admit("c1", &h, "conn.v1", b"wrong", "t1", "ts");
        tel.admit("c2", &h, "conn.v1", b"wrong2", "t2", "ts");
        tel.admit("c3", &h, "other.v1", b"data", "t3", "ts");

        let counts = tel.rejection_counts();
        assert!(counts[0].1 >= counts[1].1);
    }

    #[test]
    fn telemetry_mixed_admits_and_rejects() {
        let mut tel = AdmissionTelemetry::new();
        let h = compute_hash("conn.v1", b"data");
        assert!(tel.admit("c1", &h, "conn.v1", b"data", "t1", "ts"));
        assert!(!tel.admit("c2", &h, "conn.v1", b"bad", "t2", "ts"));
        assert!(tel.admit("c3", &h, "conn.v1", b"data", "t3", "ts"));

        assert_eq!(tel.total_checks, 3);
        assert_eq!(tel.total_admitted, 2);
        assert_eq!(tel.total_rejected, 1);
        assert_eq!(tel.checks.len(), 3);
    }

    // === Serde ===

    #[test]
    fn serde_roundtrip_interface_hash() {
        let h = compute_hash("test.v1", b"sample");
        let json = serde_json::to_string(&h).unwrap();
        let parsed: InterfaceHash = serde_json::from_str(&json).unwrap();
        assert_eq!(h, parsed);
    }

    #[test]
    fn serde_roundtrip_admission_check() {
        let check = AdmissionCheck {
            connector_id: "conn-1".into(),
            domain: "test.v1".into(),
            admitted: false,
            rejection_code: Some(RejectionCode::HashMismatch),
            trace_id: "t1".into(),
            timestamp: "ts".into(),
        };
        let json = serde_json::to_string(&check).unwrap();
        let parsed: AdmissionCheck = serde_json::from_str(&json).unwrap();
        assert_eq!(check, parsed);
    }

    // === Error display ===

    #[test]
    fn error_display_messages() {
        let e1 = InterfaceHashError::HashMismatch {
            expected: "aaa".into(),
            computed: "bbb".into(),
        };
        assert!(e1.to_string().contains("IFACE_HASH_MISMATCH"));

        let e2 = InterfaceHashError::DomainMismatch {
            expected: "a".into(),
            actual: "b".into(),
        };
        assert!(e2.to_string().contains("IFACE_DOMAIN_MISMATCH"));

        let e3 = InterfaceHashError::HashExpired {
            hash_hex: "abc".into(),
        };
        assert!(e3.to_string().contains("IFACE_HASH_EXPIRED"));

        let e4 = InterfaceHashError::HashMalformed {
            hash_hex: "xxx".into(),
        };
        assert!(e4.to_string().contains("IFACE_HASH_MALFORMED"));
    }

    // === RejectionCode display ===

    #[test]
    fn rejection_code_display() {
        assert_eq!(
            RejectionCode::HashMismatch.to_string(),
            "IFACE_HASH_MISMATCH"
        );
        assert_eq!(
            RejectionCode::DomainMismatch.to_string(),
            "IFACE_DOMAIN_MISMATCH"
        );
        assert_eq!(RejectionCode::ExpiredHash.to_string(), "IFACE_HASH_EXPIRED");
        assert_eq!(
            RejectionCode::MalformedHash.to_string(),
            "IFACE_HASH_MALFORMED"
        );
    }
}
