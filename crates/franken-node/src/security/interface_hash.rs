//! Domain-separated interface-hash verification and admission telemetry (bd-3n58).
//!
//! Hash derivation uses domain separation plus length-prefixed fields to prevent
//! cross-domain and transcript-boundary collisions. Invalid hashes block admission.
//! Telemetry tracks rejection code distribution.

use franken_security_macros::secure_hash;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;

use crate::capacity_defaults::aliases::MAX_AUDIT_LOG_ENTRIES;
use crate::push_bounded;

const MAX_TELEMETRY_FIELD_BYTES: usize = 4 * 1024;

// ── Domain-separated hash ───────────────────────────────────────────

/// Compute a domain-separated hash over length-prefixed domain and data fields.
///
/// Uses full-width SHA-256 output to preserve collision resistance.
pub fn compute_hash(domain: &str, data: &[u8]) -> InterfaceHash {
    let hash_hex = secure_hash!("interface_hash_v1:", domain.as_bytes(), data);

    InterfaceHash {
        domain: domain.to_string(),
        hash_hex,
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
    if expected.hash_hex.len() != 64 || !expected.hash_hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(RejectionCode::MalformedHash);
    }

    if expected.data_len != data.len() {
        return Err(RejectionCode::HashMismatch);
    }

    // Recompute and compare
    let computed = compute_hash(domain, data);
    if !crate::security::constant_time::ct_eq(
        &computed.hash_hex.to_ascii_lowercase(),
        &expected.hash_hex.to_ascii_lowercase(),
    ) {
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AdmissionTelemetry {
    pub total_checks: u64,
    pub total_admitted: u64,
    pub total_rejected: u64,
    pub rejection_distribution: BTreeMap<RejectionCode, u64>,
    pub checks: Vec<AdmissionCheck>,
}

impl AdmissionTelemetry {
    pub fn new() -> Self {
        Self::default()
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
        self.total_checks = self.total_checks.saturating_add(1);

        let result = verify_hash(expected_hash, domain, data);
        let (admitted, rejection_code) = match result {
            Ok(()) => {
                self.total_admitted = self.total_admitted.saturating_add(1);
                (true, None)
            }
            Err(code) => {
                self.total_rejected = self.total_rejected.saturating_add(1);
                let counter = self.rejection_distribution.entry(code).or_insert(0);
                *counter = counter.saturating_add(1);
                (false, Some(code))
            }
        };

        push_bounded(
            &mut self.checks,
            AdmissionCheck {
                connector_id: bounded_telemetry_field(connector_id),
                domain: bounded_telemetry_field(domain),
                admitted,
                rejection_code,
                trace_id: bounded_telemetry_field(trace_id),
                timestamp: bounded_telemetry_field(timestamp),
            },
            MAX_AUDIT_LOG_ENTRIES,
        );

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

fn bounded_telemetry_field(value: &str) -> String {
    if value.len() <= MAX_TELEMETRY_FIELD_BYTES {
        return value.to_string();
    }

    let mut end = MAX_TELEMETRY_FIELD_BYTES;
    while !value.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    value[..end].to_string()
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
            Self::HashMismatch { .. } => {
                write!(
                    f,
                    "IFACE_HASH_MISMATCH: expected and computed hashes redacted"
                )
            }
            Self::DomainMismatch { expected, actual } => {
                write!(
                    f,
                    "IFACE_DOMAIN_MISMATCH: expected={expected}, actual={actual}"
                )
            }
            Self::HashExpired { .. } => write!(f, "IFACE_HASH_EXPIRED: hash redacted"),
            Self::HashMalformed { .. } => write!(f, "IFACE_HASH_MALFORMED: hash redacted"),
        }
    }
}

impl std::error::Error for InterfaceHashError {}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::Digest;

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
        assert_eq!(h.hash_hex.len(), 64);
        assert!(h.hash_hex.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn compute_hash_length_prefixes_data_field() {
        let domain = "connector.v1";
        let data = b"payload";
        let h = compute_hash(domain, data);

        let mut expected = sha2::Sha256::new();
        sha2::Digest::update(&mut expected, b"interface_hash_v1:");
        sha2::Digest::update(
            &mut expected,
            u64::try_from(domain.len())
                .unwrap_or(u64::MAX)
                .to_le_bytes(),
        );
        sha2::Digest::update(&mut expected, domain.as_bytes());
        sha2::Digest::update(
            &mut expected,
            u64::try_from(data.len()).unwrap_or(u64::MAX).to_le_bytes(),
        );
        sha2::Digest::update(&mut expected, data);
        let expected_hash_hex = hex::encode(sha2::Digest::finalize(expected));

        let mut legacy_without_data_len = sha2::Sha256::new();
        sha2::Digest::update(&mut legacy_without_data_len, b"interface_hash_v1:");
        sha2::Digest::update(
            &mut legacy_without_data_len,
            u64::try_from(domain.len())
                .unwrap_or(u64::MAX)
                .to_le_bytes(),
        );
        sha2::Digest::update(&mut legacy_without_data_len, domain.as_bytes());
        sha2::Digest::update(&mut legacy_without_data_len, data);
        let legacy_hash_hex = hex::encode(sha2::Digest::finalize(legacy_without_data_len));

        assert_eq!(h.hash_hex, expected_hash_hex);
        assert_ne!(h.hash_hex, legacy_hash_hex);
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

    #[test]
    fn verify_uppercase_hash_hex() {
        let mut h = compute_hash("connector.v1", b"hello");
        h.hash_hex = h.hash_hex.to_ascii_uppercase();
        assert!(verify_hash(&h, "connector.v1", b"hello").is_ok());
    }

    #[test]
    fn verify_data_len_mismatch() {
        let mut h = compute_hash("connector.v1", b"hello");
        h.data_len = h.data_len.saturating_add(1);
        let result = verify_hash(&h, "connector.v1", b"hello");
        assert_eq!(result, Err(RejectionCode::HashMismatch));
    }

    #[test]
    fn verify_domain_mismatch_takes_precedence_over_malformed_hash() {
        let h = InterfaceHash {
            domain: "expected.v1".into(),
            hash_hex: "not-hex".into(),
            data_len: 4,
        };

        let result = verify_hash(&h, "actual.v1", b"data");

        assert_eq!(result, Err(RejectionCode::DomainMismatch));
    }

    #[test]
    fn verify_rejects_same_length_non_hex_hash() {
        let h = InterfaceHash {
            domain: "connector.v1".into(),
            hash_hex: "g".repeat(64),
            data_len: 4,
        };

        let result = verify_hash(&h, "connector.v1", b"data");

        assert_eq!(result, Err(RejectionCode::MalformedHash));
    }

    #[test]
    fn verify_rejects_single_nibble_tamper() {
        let mut h = compute_hash("connector.v1", b"data");
        h.hash_hex.replace_range(0..1, "0");
        let original = compute_hash("connector.v1", b"data");
        if crate::security::constant_time::ct_eq_bytes(
            h.hash_hex.as_bytes(),
            original.hash_hex.as_bytes(),
        ) {
            h.hash_hex.replace_range(0..1, "1");
        }

        let result = verify_hash(&h, "connector.v1", b"data");

        assert_eq!(result, Err(RejectionCode::HashMismatch));
    }

    #[test]
    fn verify_domain_is_case_sensitive() {
        let h = compute_hash("Connector.V1", b"data");

        let result = verify_hash(&h, "connector.v1", b"data");

        assert_eq!(result, Err(RejectionCode::DomainMismatch));
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
    fn telemetry_records_malformed_hash_rejection_code() {
        let mut tel = AdmissionTelemetry::new();
        let h = InterfaceHash {
            domain: "conn.v1".into(),
            hash_hex: "z".repeat(64),
            data_len: 4,
        };

        let admitted = tel.admit("conn-1", &h, "conn.v1", b"data", "trace-malformed", "ts");

        assert!(!admitted);
        assert_eq!(tel.total_checks, 1);
        assert_eq!(tel.total_rejected, 1);
        assert_eq!(tel.rejection_distribution[&RejectionCode::MalformedHash], 1);
        assert_eq!(
            tel.checks[0].rejection_code,
            Some(RejectionCode::MalformedHash)
        );
    }

    #[test]
    fn telemetry_records_requested_domain_on_domain_mismatch() {
        let mut tel = AdmissionTelemetry::new();
        let h = compute_hash("expected.v1", b"data");

        let admitted = tel.admit("conn-1", &h, "actual.v1", b"data", "trace-domain", "ts");

        assert!(!admitted);
        assert_eq!(tel.checks[0].domain, "actual.v1");
        assert_eq!(
            tel.checks[0].rejection_code,
            Some(RejectionCode::DomainMismatch)
        );
    }

    #[test]
    fn telemetry_total_checks_saturates_on_rejection() {
        let mut tel = AdmissionTelemetry::new();
        tel.total_checks = u64::MAX;
        tel.total_rejected = u64::MAX;
        let h = compute_hash("conn.v1", b"data");

        let admitted = tel.admit("conn-1", &h, "conn.v1", b"wrong", "trace-sat", "ts");

        assert!(!admitted);
        assert_eq!(tel.total_checks, u64::MAX);
        assert_eq!(tel.total_rejected, u64::MAX);
        assert_eq!(tel.rejection_distribution[&RejectionCode::HashMismatch], 1);
    }

    #[test]
    fn telemetry_total_admitted_saturates_on_success() {
        let mut tel = AdmissionTelemetry::new();
        tel.total_checks = u64::MAX;
        tel.total_admitted = u64::MAX;
        let h = compute_hash("conn.v1", b"data");

        let admitted = tel.admit("conn-1", &h, "conn.v1", b"data", "trace-sat-ok", "ts");

        assert!(admitted);
        assert_eq!(tel.total_checks, u64::MAX);
        assert_eq!(tel.total_admitted, u64::MAX);
        assert_eq!(tel.total_rejected, 0);
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
        let rendered = e1.to_string();
        assert!(rendered.contains("IFACE_HASH_MISMATCH"));
        assert!(!rendered.contains("aaa"));
        assert!(!rendered.contains("bbb"));

        let e2 = InterfaceHashError::DomainMismatch {
            expected: "a".into(),
            actual: "b".into(),
        };
        assert!(e2.to_string().contains("IFACE_DOMAIN_MISMATCH"));

        let e3 = InterfaceHashError::HashExpired {
            hash_hex: "abc".into(),
        };
        let rendered = e3.to_string();
        assert!(rendered.contains("IFACE_HASH_EXPIRED"));
        assert!(!rendered.contains("abc"));

        let e4 = InterfaceHashError::HashMalformed {
            hash_hex: "xxx".into(),
        };
        let rendered = e4.to_string();
        assert!(rendered.contains("IFACE_HASH_MALFORMED"));
        assert!(!rendered.contains("xxx"));
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

#[cfg(test)]
mod additional_negative_path_tests {
    use super::*;

    fn malformed_expected(hash_hex: &str, data_len: usize) -> InterfaceHash {
        InterfaceHash {
            domain: "connector.v1".to_string(),
            hash_hex: hash_hex.to_string(),
            data_len,
        }
    }

    #[test]
    fn verify_rejects_sha256_prefixed_hash_material() {
        let expected = malformed_expected(
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            4,
        );

        let result = verify_hash(&expected, "connector.v1", b"data");

        assert_eq!(result, Err(RejectionCode::MalformedHash));
    }

    #[test]
    fn verify_rejects_hash_material_with_embedded_whitespace() {
        let mut hash_hex = "a".repeat(64);
        hash_hex.replace_range(32..33, " ");
        let expected = malformed_expected(&hash_hex, 4);

        let result = verify_hash(&expected, "connector.v1", b"data");

        assert_eq!(result, Err(RejectionCode::MalformedHash));
    }

    #[test]
    fn verify_rejects_trailing_space_domain_without_normalizing() {
        let expected = compute_hash("connector.v1", b"data");

        let result = verify_hash(&expected, "connector.v1 ", b"data");

        assert_eq!(result, Err(RejectionCode::DomainMismatch));
    }

    #[test]
    fn verify_rejects_data_length_spoof_even_when_digest_matches() {
        let mut expected = compute_hash("connector.v1", b"data");
        expected.data_len = expected.data_len.saturating_sub(1);

        let result = verify_hash(&expected, "connector.v1", b"data");

        assert_eq!(result, Err(RejectionCode::HashMismatch));
    }

    #[test]
    fn verify_malformed_hash_takes_precedence_over_data_length_mismatch() {
        let expected = malformed_expected(&"z".repeat(64), usize::MAX);

        let result = verify_hash(&expected, "connector.v1", b"data");

        assert_eq!(result, Err(RejectionCode::MalformedHash));
    }

    #[test]
    fn telemetry_records_empty_hash_as_malformed_rejection() {
        let mut telemetry = AdmissionTelemetry::new();
        let expected = malformed_expected("", 4);

        let admitted = telemetry.admit(
            "conn-empty-hash",
            &expected,
            "connector.v1",
            b"data",
            "trace-empty-hash",
            "2026-04-17T00:00:00Z",
        );

        assert!(!admitted);
        assert_eq!(
            telemetry.checks[0].rejection_code,
            Some(RejectionCode::MalformedHash)
        );
        assert_eq!(
            telemetry.rejection_distribution[&RejectionCode::MalformedHash],
            1
        );
    }

    #[test]
    fn telemetry_rejection_counter_saturates_existing_bucket() {
        let mut telemetry = AdmissionTelemetry::new();
        telemetry
            .rejection_distribution
            .insert(RejectionCode::HashMismatch, u64::MAX);
        let expected = compute_hash("connector.v1", b"data");

        let admitted = telemetry.admit(
            "conn-saturated-bucket",
            &expected,
            "connector.v1",
            b"tampered",
            "trace-saturated-bucket",
            "2026-04-17T00:00:00Z",
        );

        assert!(!admitted);
        assert_eq!(
            telemetry.rejection_distribution[&RejectionCode::HashMismatch],
            u64::MAX
        );
    }

    #[test]
    fn serde_rejects_unknown_rejection_code_variant() {
        let result: Result<RejectionCode, _> = serde_json::from_str(r#""hash_confused""#);

        assert!(result.is_err());
    }
}

#[cfg(test)]
mod interface_hash_extra_negative_tests {
    use super::*;

    fn expected(hash_hex: &str, data_len: usize) -> InterfaceHash {
        InterfaceHash {
            domain: "iface.v1".to_string(),
            hash_hex: hash_hex.to_string(),
            data_len,
        }
    }

    #[test]
    fn verify_rejects_all_zero_full_width_digest_for_real_payload() {
        let result = verify_hash(&expected(&"0".repeat(64), 7), "iface.v1", b"payload");

        assert_eq!(result, Err(RejectionCode::HashMismatch));
    }

    #[test]
    fn verify_rejects_non_ascii_hash_material_even_at_sixty_four_bytes() {
        let result = verify_hash(&expected(&"é".repeat(32), 4), "iface.v1", b"data");

        assert_eq!(result, Err(RejectionCode::MalformedHash));
    }

    #[test]
    fn verify_rejects_empty_runtime_domain_for_nonempty_expected_domain() {
        let expected_hash = compute_hash("iface.v1", b"data");

        let result = verify_hash(&expected_hash, "", b"data");

        assert_eq!(result, Err(RejectionCode::DomainMismatch));
    }

    #[test]
    fn verify_rejects_nul_padded_domain_variant() {
        let expected_hash = compute_hash("iface.v1", b"data");

        let result = verify_hash(&expected_hash, "iface.v1\0", b"data");

        assert_eq!(result, Err(RejectionCode::DomainMismatch));
    }

    #[test]
    fn telemetry_counts_repeated_domain_mismatch_rejections() {
        let mut telemetry = AdmissionTelemetry::new();
        let expected_hash = compute_hash("iface.v1", b"data");

        let first = telemetry.admit("conn-a", &expected_hash, "other.v1", b"data", "t1", "ts");
        let second = telemetry.admit("conn-b", &expected_hash, "other.v1", b"data", "t2", "ts");

        assert!(!first);
        assert!(!second);
        assert_eq!(telemetry.total_rejected, 2);
        assert_eq!(
            telemetry.rejection_distribution[&RejectionCode::DomainMismatch],
            2
        );
    }

    #[test]
    fn telemetry_preserves_failed_connector_id_on_malformed_hash() {
        let mut telemetry = AdmissionTelemetry::new();
        let malformed = expected("not-a-valid-interface-hash", 4);

        let admitted = telemetry.admit(
            "connector-malformed",
            &malformed,
            "iface.v1",
            b"data",
            "trace-malformed",
            "2026-04-17T00:00:00Z",
        );

        assert!(!admitted);
        assert_eq!(telemetry.checks[0].connector_id, "connector-malformed");
        assert_eq!(
            telemetry.checks[0].rejection_code,
            Some(RejectionCode::MalformedHash)
        );
    }

    #[test]
    fn serde_rejects_wrong_data_len_type() {
        let result: Result<InterfaceHash, _> = serde_json::from_str(
            r#"{"domain":"iface.v1","hash_hex":"aaaaaaaa","data_len":"four"}"#,
        );

        assert!(result.is_err());
    }

    #[test]
    fn serde_rejects_unknown_admission_check_rejection_code() {
        let result: Result<AdmissionCheck, _> = serde_json::from_str(
            r#"{"connector_id":"c","domain":"d","admitted":false,"rejection_code":"confused","trace_id":"t","timestamp":"ts"}"#,
        );

        assert!(result.is_err());
    }
}

#[cfg(test)]
mod interface_hash_retention_negative_tests {
    use super::*;

    use crate::capacity_defaults::aliases::MAX_AUDIT_LOG_ENTRIES;

    fn malformed_expected(hash_hex: &str, data_len: usize) -> InterfaceHash {
        InterfaceHash {
            domain: "iface.v1".to_string(),
            hash_hex: hash_hex.to_string(),
            data_len,
        }
    }

    #[test]
    fn push_bounded_zero_capacity_clears_existing_items_without_panic() {
        let mut items = vec!["old-a", "old-b"];

        push_bounded(&mut items, "new", 0);

        assert!(items.is_empty());
    }

    #[test]
    fn push_bounded_capacity_one_drops_oldest_item() {
        let mut items = vec!["old"];

        push_bounded(&mut items, "new", 1);

        assert_eq!(items, vec!["new"]);
    }

    #[test]
    fn push_bounded_oversized_existing_vec_drains_down_to_latest_capacity() {
        let mut items = vec![1, 2, 3];

        push_bounded(&mut items, 4, 2);

        assert_eq!(items, vec![3, 4]);
    }

    #[test]
    fn verify_rejects_malformed_hash_before_data_len_spoof_when_hash_too_long() {
        let expected = malformed_expected(&"a".repeat(65), usize::MAX);

        let result = verify_hash(&expected, "iface.v1", b"data");

        assert_eq!(result, Err(RejectionCode::MalformedHash));
    }

    #[test]
    fn verify_rejects_empty_expected_domain_for_nonempty_runtime_domain() {
        let expected = compute_hash("", b"data");

        let result = verify_hash(&expected, "iface.v1", b"data");

        assert_eq!(result, Err(RejectionCode::DomainMismatch));
    }

    #[test]
    fn telemetry_records_data_length_spoof_as_hash_mismatch_rejection() {
        let mut telemetry = AdmissionTelemetry::new();
        let mut expected = compute_hash("iface.v1", b"data");
        expected.data_len = usize::MAX;

        let admitted = telemetry.admit(
            "conn-length-spoof",
            &expected,
            "iface.v1",
            b"data",
            "trace-length-spoof",
            "2026-04-17T00:00:00Z",
        );

        assert!(!admitted);
        assert_eq!(telemetry.total_rejected, 1);
        assert_eq!(
            telemetry.checks[0].rejection_code,
            Some(RejectionCode::HashMismatch)
        );
    }

    #[test]
    fn telemetry_domain_mismatch_bucket_saturates_when_already_max() {
        let mut telemetry = AdmissionTelemetry::new();
        telemetry
            .rejection_distribution
            .insert(RejectionCode::DomainMismatch, u64::MAX);
        let expected = compute_hash("iface.v1", b"data");

        let admitted = telemetry.admit(
            "conn-domain-saturated",
            &expected,
            "other.v1",
            b"data",
            "trace-domain-saturated",
            "2026-04-17T00:00:00Z",
        );

        assert!(!admitted);
        assert_eq!(
            telemetry.rejection_distribution[&RejectionCode::DomainMismatch],
            u64::MAX
        );
    }

    #[test]
    fn telemetry_bounded_checks_discards_oldest_entries_after_capacity() {
        let mut telemetry = AdmissionTelemetry::new();
        let expected = compute_hash("iface.v1", b"data");

        for i in 0..=MAX_AUDIT_LOG_ENTRIES {
            let connector_id = format!("conn-{i}");
            let trace_id = format!("trace-{i}");
            let admitted = telemetry.admit(
                &connector_id,
                &expected,
                "iface.v1",
                b"tampered",
                &trace_id,
                "2026-04-17T00:00:00Z",
            );
            assert!(!admitted);
        }

        assert_eq!(telemetry.checks.len(), MAX_AUDIT_LOG_ENTRIES);
        assert_eq!(telemetry.checks[0].connector_id, "conn-1");
        let expected_last_connector = format!("conn-{MAX_AUDIT_LOG_ENTRIES}");
        assert_eq!(
            telemetry
                .checks
                .last()
                .map(|check| check.connector_id.as_str()),
            Some(expected_last_connector.as_str())
        );
    }
}

#[cfg(test)]
mod interface_hash_boundary_negative_tests {
    use super::*;

    fn crafted_hash(hash_hex: &str, data_len: usize, domain: &str) -> InterfaceHash {
        InterfaceHash {
            domain: domain.to_string(),
            hash_hex: hash_hex.to_string(),
            data_len,
        }
    }

    #[test]
    fn verify_rejects_hash_material_with_embedded_nul_bytes() {
        let mut hash_with_nul = "a".repeat(32);
        hash_with_nul.push('\0');
        hash_with_nul.push_str(&"a".repeat(31));
        let expected = crafted_hash(&hash_with_nul, 4, "iface.v1");

        let result = verify_hash(&expected, "iface.v1", b"data");

        assert_eq!(result, Err(RejectionCode::MalformedHash));
    }

    #[test]
    fn verify_rejects_mixed_case_domain_without_normalization() {
        let expected_hash = compute_hash("Iface.V1", b"data");

        let result = verify_hash(&expected_hash, "iface.v1", b"data");

        assert_eq!(result, Err(RejectionCode::DomainMismatch));
    }

    #[test]
    fn verify_rejects_unicode_homograph_domain_variant() {
        let expected_hash = compute_hash("іface.v1", b"data");

        let result = verify_hash(&expected_hash, "iface.v1", b"data");

        assert_eq!(result, Err(RejectionCode::DomainMismatch));
    }

    #[test]
    fn verify_rejects_hash_with_embedded_control_characters() {
        let mut hash_with_control = "a".repeat(30);
        hash_with_control.push('\r');
        hash_with_control.push('\n');
        hash_with_control.push_str(&"a".repeat(32));
        let expected = crafted_hash(&hash_with_control, 4, "iface.v1");

        let result = verify_hash(&expected, "iface.v1", b"data");

        assert_eq!(result, Err(RejectionCode::MalformedHash));
    }

    #[test]
    fn telemetry_preserves_trace_id_on_hash_mismatch_even_when_zero_len_data() {
        let mut telemetry = AdmissionTelemetry::new();
        let expected_hash = compute_hash("iface.v1", b"");

        let admitted = telemetry.admit(
            "conn-zero-len",
            &expected_hash,
            "iface.v1",
            b"non-empty",
            "trace-zero-len-mismatch",
            "2026-04-17T00:00:00Z",
        );

        assert!(!admitted);
        assert_eq!(telemetry.checks[0].trace_id, "trace-zero-len-mismatch");
        assert_eq!(
            telemetry.checks[0].rejection_code,
            Some(RejectionCode::HashMismatch)
        );
    }

    #[test]
    fn telemetry_records_connector_id_when_domain_empty_for_expected_but_nonempty_for_runtime() {
        let mut telemetry = AdmissionTelemetry::new();
        let expected_hash = compute_hash("", b"data");

        let admitted = telemetry.admit(
            "conn-empty-expected-domain",
            &expected_hash,
            "nonempty.v1",
            b"data",
            "trace-empty-expected-domain",
            "2026-04-17T00:00:00Z",
        );

        assert!(!admitted);
        assert_eq!(
            telemetry.checks[0].connector_id,
            "conn-empty-expected-domain"
        );
        assert_eq!(telemetry.checks[0].domain, "nonempty.v1");
        assert_eq!(
            telemetry.checks[0].rejection_code,
            Some(RejectionCode::DomainMismatch)
        );
    }

    #[test]
    fn verify_rejects_data_len_underflow_spoof_without_comparison() {
        let mut expected = compute_hash("iface.v1", b"data");
        expected.data_len = 0;

        let result = verify_hash(&expected, "iface.v1", b"data");

        assert_eq!(result, Err(RejectionCode::HashMismatch));
    }

    #[test]
    fn serde_rejects_negative_data_len_field() {
        let result: Result<InterfaceHash, _> =
            serde_json::from_str(r#"{"domain":"iface.v1","hash_hex":"aaaa","data_len":-1}"#);

        assert!(result.is_err());
    }

    #[test]
    fn telemetry_malformed_hash_bucket_counter_saturates_existing_distribution_value() {
        let mut telemetry = AdmissionTelemetry::new();
        telemetry
            .rejection_distribution
            .insert(RejectionCode::MalformedHash, u64::MAX);
        let malformed = crafted_hash("not-hex-digits", 4, "iface.v1");

        let admitted = telemetry.admit(
            "conn-malformed-saturated",
            &malformed,
            "iface.v1",
            b"data",
            "trace-malformed-saturated",
            "2026-04-17T00:00:00Z",
        );

        assert!(!admitted);
        assert_eq!(
            telemetry.rejection_distribution[&RejectionCode::MalformedHash],
            u64::MAX
        );
    }

    #[test]
    fn verify_rejects_sixty_three_char_hex_hash_despite_valid_hex_chars() {
        let expected = crafted_hash(&"a".repeat(63), 4, "iface.v1");

        let result = verify_hash(&expected, "iface.v1", b"data");

        assert_eq!(result, Err(RejectionCode::MalformedHash));
    }
}

#[cfg(test)]
mod interface_hash_comprehensive_negative_tests {
    use super::*;

    #[test]
    fn negative_compute_hash_with_maximum_domain_and_data_sizes() {
        // Test with very large domain and data to stress hash computation
        let massive_domain = "domain.".repeat(10000) + "v1";
        let massive_data = vec![0xAB; 1000000]; // 1MB data

        let hash = compute_hash(&massive_domain, &massive_data);

        assert_eq!(hash.domain, massive_domain);
        assert_eq!(hash.data_len, 1000000);
        assert_eq!(hash.hash_hex.len(), 64);
        assert!(hash.hash_hex.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn negative_compute_hash_unicode_domain_collision_resistance() {
        // Test that Unicode normalization doesn't create hash collisions
        let nfc_domain = "café.v1"; // NFC normalized
        let nfd_domain = "cafe\u{0301}.v1"; // NFD normalized

        let hash_nfc = compute_hash(nfc_domain, b"data");
        let hash_nfd = compute_hash(nfd_domain, b"data");

        assert_ne!(hash_nfc.hash_hex, hash_nfd.hash_hex);
        assert_ne!(hash_nfc.domain, hash_nfd.domain);
    }

    #[test]
    fn negative_compute_hash_with_zero_length_domain_and_data() {
        // Test with empty domain and data
        let hash = compute_hash("", &[]);

        assert_eq!(hash.domain, "");
        assert_eq!(hash.data_len, 0);
        assert_eq!(hash.hash_hex.len(), 64);
        assert!(hash.hash_hex.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn negative_verify_hash_with_domain_containing_length_prefix_attack() {
        // Test domain collision attack using length prefix manipulation
        let domain_a = "\x04\x00\x00\x00\x00\x00\x00\x00test";
        let domain_b = "test";

        let hash_a = compute_hash(domain_a, b"data");
        let hash_b = compute_hash(domain_b, b"data");

        // Should produce different hashes due to length-prefixed encoding
        assert_ne!(hash_a.hash_hex, hash_b.hash_hex);

        // Cross-verification should fail
        assert_eq!(
            verify_hash(&hash_a, domain_b, b"data"),
            Err(RejectionCode::DomainMismatch)
        );
        assert_eq!(
            verify_hash(&hash_b, domain_a, b"data"),
            Err(RejectionCode::DomainMismatch)
        );
    }

    #[test]
    fn negative_verify_hash_timing_attack_resistance() {
        // Test that hash comparison is constant-time regardless of difference position
        let reference_hash = compute_hash("test.v1", b"reference_data");

        // Create hashes that differ early vs late
        let early_diff_hash = compute_hash("Xest.v1", b"reference_data");
        let late_diff_hash = compute_hash("test.vX", b"reference_data");

        // All should fail in constant time
        assert_eq!(
            verify_hash(&early_diff_hash, "test.v1", b"reference_data"),
            Err(RejectionCode::DomainMismatch)
        );
        assert_eq!(
            verify_hash(&late_diff_hash, "test.v1", b"reference_data"),
            Err(RejectionCode::DomainMismatch)
        );

        // Test with hash material differences
        let mut early_hash_diff = reference_hash.clone();
        let early_replacement = if reference_hash.hash_hex.as_bytes()[0] == b'0' {
            "1"
        } else {
            "0"
        };
        early_hash_diff
            .hash_hex
            .replace_range(0..1, early_replacement);
        let mut late_hash_diff = reference_hash.clone();
        let late_replacement = if reference_hash.hash_hex.as_bytes()[63] == b'0' {
            "1"
        } else {
            "0"
        };
        late_hash_diff
            .hash_hex
            .replace_range(63..64, late_replacement);

        assert_eq!(
            verify_hash(&early_hash_diff, "test.v1", b"reference_data"),
            Err(RejectionCode::HashMismatch)
        );
        assert_eq!(
            verify_hash(&late_hash_diff, "test.v1", b"reference_data"),
            Err(RejectionCode::HashMismatch)
        );
    }

    #[test]
    fn negative_admission_telemetry_with_massive_connector_and_trace_ids() {
        let mut telemetry = AdmissionTelemetry::new();
        let expected_hash = compute_hash("test.v1", b"data");

        // Test with very large string fields
        let massive_connector_id = "connector_".repeat(10000);
        let massive_trace_id = "trace_".repeat(10000);
        let massive_timestamp = "2026-04-17T00:00:00Z_".repeat(1000);

        let admitted = telemetry.admit(
            &massive_connector_id,
            &expected_hash,
            "test.v1",
            b"data",
            &massive_trace_id,
            &massive_timestamp,
        );

        assert!(admitted);
        assert_eq!(
            telemetry.checks[0].connector_id.len(),
            MAX_TELEMETRY_FIELD_BYTES
        );
        assert_eq!(
            telemetry.checks[0].trace_id.len(),
            MAX_TELEMETRY_FIELD_BYTES
        );
        assert_eq!(
            telemetry.checks[0].timestamp.len(),
            MAX_TELEMETRY_FIELD_BYTES
        );
        assert!(massive_connector_id.starts_with(&telemetry.checks[0].connector_id));
        assert!(massive_trace_id.starts_with(&telemetry.checks[0].trace_id));
        assert!(massive_timestamp.starts_with(&telemetry.checks[0].timestamp));
    }

    #[test]
    fn negative_admission_telemetry_truncates_on_utf8_boundary() {
        let oversized = format!("{}é", "a".repeat(MAX_TELEMETRY_FIELD_BYTES - 1));

        let bounded = bounded_telemetry_field(&oversized);

        assert_eq!(bounded.len(), MAX_TELEMETRY_FIELD_BYTES - 1);
        assert!(oversized.starts_with(&bounded));
    }

    #[test]
    fn negative_telemetry_concurrent_counter_saturation_scenarios() {
        let mut telemetry = AdmissionTelemetry::new();

        // Set all counters to near-maximum values
        telemetry.total_checks = u64::MAX - 1;
        telemetry.total_admitted = u64::MAX - 1;
        telemetry.total_rejected = u64::MAX - 1;

        let expected_hash = compute_hash("test.v1", b"data");

        // Test admission near overflow
        let admitted_success =
            telemetry.admit("conn-1", &expected_hash, "test.v1", b"data", "t1", "ts");
        assert!(admitted_success);
        assert_eq!(telemetry.total_checks, u64::MAX);
        assert_eq!(telemetry.total_admitted, u64::MAX);

        // Test rejection at maximum
        let admitted_failure =
            telemetry.admit("conn-2", &expected_hash, "test.v1", b"wrong", "t2", "ts");
        assert!(!admitted_failure);
        assert_eq!(telemetry.total_checks, u64::MAX); // Should saturate
        assert_eq!(telemetry.total_rejected, u64::MAX); // Should saturate
    }

    #[test]
    fn negative_serialization_with_extreme_unicode_values() {
        // Test serialization with extreme Unicode values
        let extreme_interface_hash = InterfaceHash {
            domain: "\u{10FFFF}".repeat(100), // Max Unicode codepoint
            hash_hex: "0123456789abcdef".repeat(4),
            data_len: usize::MAX,
        };

        // Should serialize/deserialize without panic
        let json = serde_json::to_string(&extreme_interface_hash).unwrap();
        let deserialized: InterfaceHash = serde_json::from_str(&json).unwrap();

        assert_eq!(extreme_interface_hash, deserialized);
    }

    #[test]
    fn negative_verify_hash_with_malicious_hex_patterns() {
        // Test with hex patterns that might bypass validation
        let malicious_patterns = [
            "0x" + &"a".repeat(62),                    // Hex prefix
            "a".repeat(32) + "G" + &"a".repeat(31),    // Invalid hex char in middle
            "a".repeat(32) + "\x00" + &"a".repeat(31), // Null byte in middle
            "a".repeat(32) + "\n" + &"a".repeat(31),   // Newline in middle
            "a".repeat(63) + "G",                      // Invalid char at end
        ];

        for pattern in malicious_patterns {
            let malformed_hash = InterfaceHash {
                domain: "test.v1".to_string(),
                hash_hex: pattern.clone(),
                data_len: 4,
            };

            let result = verify_hash(&malformed_hash, "test.v1", b"data");
            assert_eq!(
                result,
                Err(RejectionCode::MalformedHash),
                "Failed for pattern: {}",
                pattern
            );
        }
    }

    #[test]
    fn negative_domain_separator_collision_attack_resistance() {
        // Test that domain separator prevents collision attacks
        let data_with_separator = b"interface_hash_v1:malicious";
        let normal_data = b"normal";

        let hash_with_separator = compute_hash("attack", data_with_separator);
        let hash_normal = compute_hash("attack", normal_data);

        // Should produce different hashes
        assert_ne!(hash_with_separator.hash_hex, hash_normal.hash_hex);

        // Test with domain containing separator-like content
        let domain_with_separator = "interface_hash_v1:fake_domain";
        let hash_fake_domain = compute_hash(domain_with_separator, b"data");
        let hash_real_domain = compute_hash("real_domain", b"data");

        assert_ne!(hash_fake_domain.hash_hex, hash_real_domain.hash_hex);
    }

    #[test]
    fn negative_push_bounded_memory_behavior_with_large_items() {
        // Test push_bounded with large items to verify memory behavior
        let mut large_items: Vec<Vec<u8>> = Vec::new();

        // Fill with large items
        for i in 0..100 {
            large_items.push(vec![i as u8; 10000]); // 10KB items
        }

        // Push with smaller capacity to force eviction
        push_bounded(&mut large_items, vec![255u8; 10000], 50);

        assert_eq!(large_items.len(), 50);
        assert_eq!(large_items[0], vec![51u8; 10000]); // First remaining item
        assert_eq!(large_items[49], vec![255u8; 10000]); // New item
    }

    #[test]
    fn negative_rejection_counts_with_empty_distribution() {
        let telemetry = AdmissionTelemetry::new();

        let counts = telemetry.rejection_counts();

        assert!(counts.is_empty());
    }

    #[test]
    fn negative_rejection_counts_deterministic_ordering() {
        let mut telemetry = AdmissionTelemetry::new();

        // Create specific distribution
        telemetry
            .rejection_distribution
            .insert(RejectionCode::HashMismatch, 100);
        telemetry
            .rejection_distribution
            .insert(RejectionCode::DomainMismatch, 200);
        telemetry
            .rejection_distribution
            .insert(RejectionCode::MalformedHash, 50);

        let counts = telemetry.rejection_counts();

        // Should be sorted by count in descending order
        assert_eq!(counts[0], (RejectionCode::DomainMismatch, 200));
        assert_eq!(counts[1], (RejectionCode::HashMismatch, 100));
        assert_eq!(counts[2], (RejectionCode::MalformedHash, 50));
    }

    #[test]
    fn negative_verify_hash_with_data_length_overflow_attack() {
        // Test with data_len that could cause overflow in comparison
        let mut malicious_hash = compute_hash("test.v1", b"short");
        malicious_hash.data_len = usize::MAX;

        let result = verify_hash(&malicious_hash, "test.v1", b"short");

        assert_eq!(result, Err(RejectionCode::HashMismatch));
    }

    #[test]
    fn negative_interface_hash_error_display_with_extreme_values() {
        let error_with_long_strings = InterfaceHashError::HashMismatch {
            expected: "a".repeat(10000),
            computed: "b".repeat(10000),
        };

        let display = format!("{}", error_with_long_strings);

        assert!(display.contains("IFACE_HASH_MISMATCH"));
        assert!(display.len() < 128);
        assert!(!display.contains(&"a".repeat(32)));
        assert!(!display.contains(&"b".repeat(32)));
    }

    #[test]
    fn negative_admission_check_with_unicode_and_control_characters() {
        let check_with_unicode = AdmissionCheck {
            connector_id: "conn-🚀\n\r\t".to_string(),
            domain: "test\0domain.v1".to_string(),
            admitted: false,
            rejection_code: Some(RejectionCode::HashMismatch),
            trace_id: "\u{10FFFF}trace".to_string(),
            timestamp: "2026\u{200B}04\u{FEFF}17".to_string(),
        };

        // Should serialize without panic
        let json = serde_json::to_string(&check_with_unicode).unwrap();
        let deserialized: AdmissionCheck = serde_json::from_str(&json).unwrap();

        assert_eq!(check_with_unicode, deserialized);
    }
}

#[cfg(test)]
mod interface_hash_advanced_negative_tests {
    use super::*;
    use crate::security::constant_time;

    #[test]
    fn negative_verify_hash_with_lookalike_unicode_hex_characters() {
        // Test with Unicode characters that visually resemble hex digits
        let lookalike_hash = InterfaceHash {
            domain: "test.v1".to_string(),
            hash_hex: "а".repeat(32) + &"е".repeat(32), // Cyrillic 'а' and 'е' that look like 'a' and 'e'
            data_len: 4,
        };

        let result = verify_hash(&lookalike_hash, "test.v1", b"data");

        assert_eq!(result, Err(RejectionCode::MalformedHash));
    }

    #[test]
    fn negative_verify_hash_with_bidi_override_domain_attack() {
        // Test with BiDi override characters to create domain spoofing
        let bidi_domain = "test\u{202E}v1.malicious\u{202D}.v1";
        let spoofed_hash = compute_hash(&bidi_domain, b"data");

        let result = verify_hash(&spoofed_hash, "test.v1", b"data");

        assert_eq!(result, Err(RejectionCode::DomainMismatch));
    }

    #[test]
    fn negative_verify_hash_with_extremely_long_hex_string_memory_attack() {
        // Test with maliciously long hex string that might cause memory issues
        let extremely_long_hex = "a".repeat(1000000); // 1MB hex string
        let memory_attack_hash = InterfaceHash {
            domain: "test.v1".to_string(),
            hash_hex: extremely_long_hex,
            data_len: 4,
        };

        let result = verify_hash(&memory_attack_hash, "test.v1", b"data");

        assert_eq!(result, Err(RejectionCode::MalformedHash));
    }

    #[test]
    fn negative_verify_hash_with_mixed_case_transitions_and_invalid_chars() {
        // Test with valid hex chars but invalid transitions and case mixing
        let mixed_invalid = "0123456789abcdefABCDEF".repeat(3) + "GH"; // Ends with invalid chars
        let transition_attack = InterfaceHash {
            domain: "test.v1".to_string(),
            hash_hex: mixed_invalid,
            data_len: 4,
        };

        let result = verify_hash(&transition_attack, "test.v1", b"data");

        assert_eq!(result, Err(RejectionCode::MalformedHash));
    }

    #[test]
    fn negative_telemetry_under_extreme_memory_pressure_scenarios() {
        let mut telemetry = AdmissionTelemetry::new();

        // Pre-fill with maximum size strings to stress memory
        for i in 0..1000 {
            let expected_domain = format!("domain{}{}.v1", i, "x".repeat(10000));
            let massive_strings_hash = InterfaceHash {
                domain: expected_domain.clone(),
                hash_hex: "z".repeat(64), // Invalid but consistent length
                data_len: i,
            };

            let connector_id = format!("connector{}{}", i, "y".repeat(10000));
            let trace_id = format!("trace{}{}", i, "z".repeat(10000));

            let admitted = telemetry.admit(
                &connector_id,
                &massive_strings_hash,
                &expected_domain,
                b"data",
                &trace_id,
                "2026-04-17T00:00:00Z",
            );

            assert!(!admitted); // Should reject due to malformed hash
        }

        // Verify telemetry still functions correctly under stress
        assert_eq!(telemetry.total_rejected, 1000);
        assert!(
            telemetry
                .rejection_distribution
                .contains_key(&RejectionCode::MalformedHash)
        );
        assert!(telemetry.checks.iter().all(|check| {
            check.connector_id.len() <= MAX_TELEMETRY_FIELD_BYTES
                && check.domain.len() <= MAX_TELEMETRY_FIELD_BYTES
                && check.trace_id.len() <= MAX_TELEMETRY_FIELD_BYTES
        }));
    }

    #[test]
    fn negative_serialization_with_invalid_json_escape_sequences() {
        // Test deserialization with malformed JSON escape sequences
        let malformed_json_attempts = [
            r#"{"domain":"test\uXXXX.v1","hash_hex":"aaaa","data_len":4}"#, // Invalid Unicode escape
            r#"{"domain":"test.v1","hash_hex":"aaaa\","data_len":4}"#,      // Unterminated escape
            r#"{"domain":"test.v1","hash_hex":"\uD800aaaa","data_len":4}"#, // Unpaired surrogate
        ];

        for malformed_json in malformed_json_attempts {
            let result: Result<InterfaceHash, _> = serde_json::from_str(malformed_json);
            assert!(
                result.is_err(),
                "Should reject malformed JSON: {}",
                malformed_json
            );
        }
    }

    #[test]
    fn negative_domain_separator_injection_in_multiple_forms() {
        // Test various forms of separator injection in domains
        let separator_injection_domains = [
            "interface_hash_v1:",
            "prefix:interface_hash_v1:suffix",
            "test\x00interface_hash_v1:spoofed",
            "interface_hash_v1:\x00",
            "INTERFACE_HASH_V1:", // Case variant
        ];

        for malicious_domain in separator_injection_domains {
            let hash_a = compute_hash(malicious_domain, b"data");
            let hash_b = compute_hash("legitimate.v1", b"data");

            // Should produce different hashes
            assert_ne!(
                hash_a.hash_hex, hash_b.hash_hex,
                "Domain: {}",
                malicious_domain
            );

            // Cross-verification should fail
            let result = verify_hash(&hash_a, "legitimate.v1", b"data");
            assert_eq!(
                result,
                Err(RejectionCode::DomainMismatch),
                "Domain: {}",
                malicious_domain
            );
        }
    }

    #[test]
    fn negative_hash_hex_homograph_attack_patterns() {
        // Test with various homograph attack patterns in hex strings
        let homograph_patterns = [
            "0" + &"О".repeat(63), // Cyrillic capital O instead of zero
            "1" + &"l".repeat(63), // Lowercase L instead of one
            "a" + &"а".repeat(63), // Cyrillic 'а' instead of Latin 'a'
            "b" + &"Ь".repeat(63), // Cyrillic soft sign instead of 'b'
            "c" + &"с".repeat(63), // Cyrillic 'с' instead of Latin 'c'
            "d" + &"ԁ".repeat(63), // Cyrillic 'd' lookalike
            "e" + &"е".repeat(63), // Cyrillic 'е' instead of Latin 'e'
            "f" + &"𝒇".repeat(63), // Mathematical italic f instead of ASCII f
        ];

        for homograph_hex in homograph_patterns {
            let homograph_hash = InterfaceHash {
                domain: "test.v1".to_string(),
                hash_hex: homograph_hex.clone(),
                data_len: 4,
            };

            let result = verify_hash(&homograph_hash, "test.v1", b"data");
            assert_eq!(
                result,
                Err(RejectionCode::MalformedHash),
                "Failed for homograph: {}",
                homograph_hex
            );
        }
    }

    #[test]
    fn negative_push_bounded_with_zero_capacity_edge_case_behavior() {
        // Test push_bounded edge case with zero capacity and existing items
        let mut items = vec!["existing1", "existing2", "existing3"];

        push_bounded(&mut items, "new_item", 0);

        assert!(items.is_empty());

        // Test pushing another item with zero capacity
        push_bounded(&mut items, "second_new", 0);
        assert!(items.is_empty());
    }

    #[test]
    fn negative_admission_telemetry_counter_overflow_edge_cases() {
        let mut telemetry = AdmissionTelemetry::new();

        // Set counters to specific overflow-prone values
        telemetry.total_checks = u64::MAX - 2;
        telemetry.total_admitted = u64::MAX - 1;

        // Set a rejection counter to max
        telemetry
            .rejection_distribution
            .insert(RejectionCode::MalformedHash, u64::MAX);

        let valid_hash = compute_hash("test.v1", b"data");
        let malformed_hash = InterfaceHash {
            domain: "test.v1".to_string(),
            hash_hex: "invalid".to_string(),
            data_len: 4,
        };

        // Test successful admission at near-overflow
        let success1 = telemetry.admit("conn-1", &valid_hash, "test.v1", b"data", "t1", "ts");
        assert!(success1);
        assert_eq!(telemetry.total_checks, u64::MAX - 1);
        assert_eq!(telemetry.total_admitted, u64::MAX);

        // Test another successful admission at overflow boundary
        let success2 = telemetry.admit("conn-2", &valid_hash, "test.v1", b"data", "t2", "ts");
        assert!(success2);
        assert_eq!(telemetry.total_checks, u64::MAX);
        assert_eq!(telemetry.total_admitted, u64::MAX); // Should saturate

        // Test rejection with saturated counter
        let failure = telemetry.admit("conn-3", &malformed_hash, "test.v1", b"data", "t3", "ts");
        assert!(!failure);
        assert_eq!(telemetry.total_checks, u64::MAX); // Should remain saturated
        assert_eq!(
            telemetry.rejection_distribution[&RejectionCode::MalformedHash],
            u64::MAX
        ); // Should remain saturated
    }

    #[test]
    fn negative_compute_hash_with_adversarial_data_patterns() {
        // Test hash computation with adversarial data patterns that might cause issues
        let adversarial_data_patterns = [
            vec![0xFF; 1000000], // All-ones pattern, large size
            vec![0x00; 1000000], // All-zeros pattern, large size
            (0..256)
                .cycle()
                .take(1000000)
                .map(|x| x as u8)
                .collect::<Vec<_>>(), // Repeating pattern
            vec![0xAA, 0x55].repeat(500000), // Alternating bit pattern
            b"interface_hash_v1:".repeat(100000).into_bytes(), // Separator repeated
        ];

        for (i, adversarial_data) in adversarial_data_patterns.iter().enumerate() {
            let hash = compute_hash(&format!("test{}.v1", i), adversarial_data);

            // Should always produce valid output regardless of input
            assert_eq!(hash.hash_hex.len(), 64);
            assert!(hash.hash_hex.chars().all(|c| c.is_ascii_hexdigit()));
            assert_eq!(hash.data_len, adversarial_data.len());
            assert_eq!(hash.domain, format!("test{}.v1", i));

            // Verification should succeed for original
            assert!(verify_hash(&hash, &format!("test{}.v1", i), adversarial_data).is_ok());
        }
    }
}
