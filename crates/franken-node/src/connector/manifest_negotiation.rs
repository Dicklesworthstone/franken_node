//! Fail-closed manifest negotiation (bd-17mb).
//!
//! A connector manifest declares a SemVer version, required features,
//! and transport capabilities. The negotiation engine checks all three
//! against host capabilities and hard-fails activation on any mismatch.

use serde::{Deserialize, Serialize};
use std::fmt;

// ── SemVer ──────────────────────────────────────────────────────────

/// Semantic version with major.minor.patch ordering.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SemVer {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

impl SemVer {
    pub fn new(major: u32, minor: u32, patch: u32) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }

    /// Parse from "major.minor.patch" string.
    pub fn parse(s: &str) -> Result<Self, ManifestError> {
        let parts: Vec<&str> = s.split('.').collect();
        if parts.len() != 3 {
            return Err(ManifestError::ManifestInvalid {
                reason: format!("invalid semver: {s}"),
            });
        }
        let major = parts[0]
            .parse::<u32>()
            .map_err(|_| ManifestError::ManifestInvalid {
                reason: format!("invalid major: {}", parts[0]),
            })?;
        let minor = parts[1]
            .parse::<u32>()
            .map_err(|_| ManifestError::ManifestInvalid {
                reason: format!("invalid minor: {}", parts[1]),
            })?;
        let patch = parts[2]
            .parse::<u32>()
            .map_err(|_| ManifestError::ManifestInvalid {
                reason: format!("invalid patch: {}", parts[2]),
            })?;
        Ok(Self {
            major,
            minor,
            patch,
        })
    }
}

impl PartialOrd for SemVer {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for SemVer {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.major
            .cmp(&other.major)
            .then(self.minor.cmp(&other.minor))
            .then(self.patch.cmp(&other.patch))
    }
}

impl fmt::Display for SemVer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

// ── Transport capabilities ──────────────────────────────────────────

/// Transport capability required or available.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportCap {
    Http1,
    Http2,
    Http3,
    WebSocket,
    Grpc,
}

impl fmt::Display for TransportCap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Http1 => write!(f, "http1"),
            Self::Http2 => write!(f, "http2"),
            Self::Http3 => write!(f, "http3"),
            Self::WebSocket => write!(f, "websocket"),
            Self::Grpc => write!(f, "grpc"),
        }
    }
}

// ── Manifest and host capabilities ──────────────────────────────────

/// Connector manifest declaring version, features, and transport needs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectorManifest {
    pub connector_id: String,
    pub version: SemVer,
    pub required_features: Vec<String>,
    pub transport_caps: Vec<TransportCap>,
}

/// Host capabilities for negotiation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostCapabilities {
    pub min_version: SemVer,
    pub max_version: SemVer,
    pub available_features: Vec<String>,
    pub transport_caps: Vec<TransportCap>,
}

// ── Negotiation result ──────────────────────────────────────────────

/// Outcome of manifest negotiation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Accepted,
    Rejected { reason: String },
}

/// Full negotiation result with diagnostic details.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NegotiationResult {
    pub connector_id: String,
    pub outcome: Outcome,
    pub version_ok: bool,
    pub features_ok: bool,
    pub transport_ok: bool,
    pub missing_features: Vec<String>,
    pub missing_transports: Vec<TransportCap>,
    pub trace_id: String,
    pub timestamp: String,
}

// ── Core checks ─────────────────────────────────────────────────────

/// Check if a version falls within the supported range (inclusive).
pub fn check_version(version: &SemVer, min: &SemVer, max: &SemVer) -> bool {
    version >= min && version <= max
}

/// Return list of required features that are missing from available set.
pub fn check_features(required: &[String], available: &[String]) -> Vec<String> {
    required
        .iter()
        .filter(|f| !available.contains(f))
        .cloned()
        .collect()
}

/// Return list of required transport caps missing from available set.
pub fn check_transport(required: &[TransportCap], available: &[TransportCap]) -> Vec<TransportCap> {
    required
        .iter()
        .filter(|t| !available.contains(t))
        .copied()
        .collect()
}

/// Run fail-closed manifest negotiation.
pub fn negotiate(
    manifest: &ConnectorManifest,
    host: &HostCapabilities,
    trace_id: &str,
    timestamp: &str,
) -> NegotiationResult {
    let version_ok = check_version(&manifest.version, &host.min_version, &host.max_version);
    let missing_features = check_features(&manifest.required_features, &host.available_features);
    let missing_transports = check_transport(&manifest.transport_caps, &host.transport_caps);
    let features_ok = missing_features.is_empty();
    let transport_ok = missing_transports.is_empty();

    let outcome = if version_ok && features_ok && transport_ok {
        Outcome::Accepted
    } else {
        let mut reasons = Vec::new();
        if !version_ok {
            reasons.push(format!(
                "MANIFEST_VERSION_UNSUPPORTED: {} not in {}-{}",
                manifest.version, host.min_version, host.max_version
            ));
        }
        if !features_ok {
            reasons.push(format!("MANIFEST_FEATURE_MISSING: {:?}", missing_features));
        }
        if !transport_ok {
            reasons.push(format!(
                "MANIFEST_TRANSPORT_MISMATCH: {:?}",
                missing_transports
            ));
        }
        Outcome::Rejected {
            reason: reasons.join("; "),
        }
    };

    NegotiationResult {
        connector_id: manifest.connector_id.clone(),
        outcome,
        version_ok,
        features_ok,
        transport_ok,
        missing_features,
        missing_transports,
        trace_id: trace_id.to_string(),
        timestamp: timestamp.to_string(),
    }
}

// ── Errors ──────────────────────────────────────────────────────────

/// Errors for manifest negotiation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ManifestError {
    #[serde(rename = "MANIFEST_VERSION_UNSUPPORTED")]
    VersionUnsupported { version: String, range: String },
    #[serde(rename = "MANIFEST_FEATURE_MISSING")]
    FeatureMissing { features: Vec<String> },
    #[serde(rename = "MANIFEST_TRANSPORT_MISMATCH")]
    TransportMismatch { transports: Vec<String> },
    #[serde(rename = "MANIFEST_INVALID")]
    ManifestInvalid { reason: String },
}

impl fmt::Display for ManifestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::VersionUnsupported { version, range } => {
                write!(f, "MANIFEST_VERSION_UNSUPPORTED: {version} not in {range}")
            }
            Self::FeatureMissing { features } => {
                write!(f, "MANIFEST_FEATURE_MISSING: {features:?}")
            }
            Self::TransportMismatch { transports } => {
                write!(f, "MANIFEST_TRANSPORT_MISMATCH: {transports:?}")
            }
            Self::ManifestInvalid { reason } => {
                write!(f, "MANIFEST_INVALID: {reason}")
            }
        }
    }
}

impl std::error::Error for ManifestError {}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn host_caps() -> HostCapabilities {
        HostCapabilities {
            min_version: SemVer::new(1, 0, 0),
            max_version: SemVer::new(2, 99, 99),
            available_features: vec!["auth".into(), "streaming".into(), "batch".into()],
            transport_caps: vec![TransportCap::Http1, TransportCap::Http2, TransportCap::Grpc],
        }
    }

    fn good_manifest() -> ConnectorManifest {
        ConnectorManifest {
            connector_id: "conn-1".into(),
            version: SemVer::new(2, 1, 0),
            required_features: vec!["auth".into(), "streaming".into()],
            transport_caps: vec![TransportCap::Http2],
        }
    }

    // === SemVer ===

    #[test]
    fn semver_parse_valid() {
        let v = SemVer::parse("1.2.3").unwrap();
        assert_eq!(v, SemVer::new(1, 2, 3));
    }

    #[test]
    fn semver_parse_invalid() {
        assert!(SemVer::parse("1.2").is_err());
        assert!(SemVer::parse("a.b.c").is_err());
    }

    #[test]
    fn semver_ordering() {
        assert!(SemVer::new(2, 0, 0) > SemVer::new(1, 99, 99));
        assert!(SemVer::new(1, 1, 0) > SemVer::new(1, 0, 99));
        assert!(SemVer::new(1, 0, 1) > SemVer::new(1, 0, 0));
        assert!(SemVer::new(1, 0, 0) == SemVer::new(1, 0, 0));
    }

    #[test]
    fn semver_display() {
        assert_eq!(SemVer::new(1, 2, 3).to_string(), "1.2.3");
    }

    // === check_version ===

    #[test]
    fn version_in_range() {
        let min = SemVer::new(1, 0, 0);
        let max = SemVer::new(2, 0, 0);
        assert!(check_version(&SemVer::new(1, 5, 0), &min, &max));
        assert!(check_version(&SemVer::new(1, 0, 0), &min, &max));
        assert!(check_version(&SemVer::new(2, 0, 0), &min, &max));
    }

    #[test]
    fn version_out_of_range() {
        let min = SemVer::new(1, 0, 0);
        let max = SemVer::new(2, 0, 0);
        assert!(!check_version(&SemVer::new(0, 9, 0), &min, &max));
        assert!(!check_version(&SemVer::new(3, 0, 0), &min, &max));
    }

    #[test]
    fn version_semantic_not_lexical() {
        // "9.0.0" < "10.0.0" semantically but "9.0.0" > "10.0.0" lexically
        let min = SemVer::new(1, 0, 0);
        let max = SemVer::new(10, 0, 0);
        assert!(check_version(&SemVer::new(9, 0, 0), &min, &max));
    }

    // === check_features ===

    #[test]
    fn features_all_present() {
        let required = vec!["auth".into(), "batch".into()];
        let available = vec!["auth".into(), "batch".into(), "extra".into()];
        assert!(check_features(&required, &available).is_empty());
    }

    #[test]
    fn features_missing() {
        let required = vec!["auth".into(), "magic".into()];
        let available = vec!["auth".into()];
        let missing = check_features(&required, &available);
        assert_eq!(missing, vec!["magic".to_string()]);
    }

    // === check_transport ===

    #[test]
    fn transport_all_present() {
        let required = vec![TransportCap::Http2];
        let available = vec![TransportCap::Http1, TransportCap::Http2];
        assert!(check_transport(&required, &available).is_empty());
    }

    #[test]
    fn transport_missing() {
        let required = vec![TransportCap::Http3];
        let available = vec![TransportCap::Http1, TransportCap::Http2];
        let missing = check_transport(&required, &available);
        assert_eq!(missing, vec![TransportCap::Http3]);
    }

    // === negotiate ===

    #[test]
    fn negotiate_accepted() {
        let result = negotiate(&good_manifest(), &host_caps(), "t1", "ts");
        assert_eq!(result.outcome, Outcome::Accepted);
        assert!(result.version_ok);
        assert!(result.features_ok);
        assert!(result.transport_ok);
    }

    #[test]
    fn negotiate_rejected_version() {
        let mut m = good_manifest();
        m.version = SemVer::new(5, 0, 0);
        let result = negotiate(&m, &host_caps(), "t2", "ts");
        assert!(matches!(result.outcome, Outcome::Rejected { .. }));
        assert!(!result.version_ok);
    }

    #[test]
    fn negotiate_rejected_features() {
        let mut m = good_manifest();
        m.required_features.push("teleport".into());
        let result = negotiate(&m, &host_caps(), "t3", "ts");
        assert!(matches!(result.outcome, Outcome::Rejected { .. }));
        assert!(!result.features_ok);
        assert_eq!(result.missing_features, vec!["teleport".to_string()]);
    }

    #[test]
    fn negotiate_rejected_transport() {
        let mut m = good_manifest();
        m.transport_caps = vec![TransportCap::Http3];
        let result = negotiate(&m, &host_caps(), "t4", "ts");
        assert!(matches!(result.outcome, Outcome::Rejected { .. }));
        assert!(!result.transport_ok);
        assert_eq!(result.missing_transports, vec![TransportCap::Http3]);
    }

    #[test]
    fn negotiate_fail_closed_all_bad() {
        let m = ConnectorManifest {
            connector_id: "conn-bad".into(),
            version: SemVer::new(99, 0, 0),
            required_features: vec!["warp_drive".into()],
            transport_caps: vec![TransportCap::Http3],
        };
        let result = negotiate(&m, &host_caps(), "t5", "ts");
        assert!(matches!(result.outcome, Outcome::Rejected { .. }));
        assert!(!result.version_ok);
        assert!(!result.features_ok);
        assert!(!result.transport_ok);
    }

    #[test]
    fn negotiate_has_trace_id() {
        let result = negotiate(&good_manifest(), &host_caps(), "trace-xyz", "ts");
        assert_eq!(result.trace_id, "trace-xyz");
    }

    #[test]
    fn negotiate_rejected_reason_contains_error_code() {
        let mut m = good_manifest();
        m.version = SemVer::new(99, 0, 0);
        let result = negotiate(&m, &host_caps(), "t6", "ts");
        if let Outcome::Rejected { reason } = &result.outcome {
            assert!(reason.contains("MANIFEST_VERSION_UNSUPPORTED"));
        } else {
            unreachable!("expected rejected");
        }
    }

    // === Serde ===

    #[test]
    fn serde_roundtrip_result() {
        let result = negotiate(&good_manifest(), &host_caps(), "t7", "ts");
        let json = serde_json::to_string(&result).unwrap();
        let parsed: NegotiationResult = serde_json::from_str(&json).unwrap();
        assert_eq!(result.connector_id, parsed.connector_id);
    }

    #[test]
    fn serde_roundtrip_manifest() {
        let m = good_manifest();
        let json = serde_json::to_string(&m).unwrap();
        let parsed: ConnectorManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(m.connector_id, parsed.connector_id);
    }

    // === Error display ===

    #[test]
    fn error_display_messages() {
        let e1 = ManifestError::VersionUnsupported {
            version: "5.0.0".into(),
            range: "1.0.0-2.0.0".into(),
        };
        assert!(e1.to_string().contains("MANIFEST_VERSION_UNSUPPORTED"));

        let e2 = ManifestError::FeatureMissing {
            features: vec!["magic".into()],
        };
        assert!(e2.to_string().contains("MANIFEST_FEATURE_MISSING"));

        let e3 = ManifestError::TransportMismatch {
            transports: vec!["http3".into()],
        };
        assert!(e3.to_string().contains("MANIFEST_TRANSPORT_MISMATCH"));

        let e4 = ManifestError::ManifestInvalid {
            reason: "bad".into(),
        };
        assert!(e4.to_string().contains("MANIFEST_INVALID"));
    }
}
