//! bd-3ku8: Capability-carrying extension artifact admission and enforcement.
//!
//! Extension artifacts carry embedded capability contracts that declare the exact
//! set of capabilities the extension requires. Admission is fail-closed: missing or
//! invalid contracts cause immediate rejection. At runtime, the enforced capability
//! envelope must match the admitted contract without drift.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// Report schema version for capability artifact vectors.
pub const SCHEMA_VERSION: &str = "capability-artifact-v1.0";

// ---------------------------------------------------------------------------
// Event codes
// ---------------------------------------------------------------------------
pub mod event_codes {
    pub const ARTIFACT_ADMISSION_START: &str = "ARTIFACT_ADMISSION_START";
    pub const ARTIFACT_CAPABILITY_VALIDATED: &str = "ARTIFACT_CAPABILITY_VALIDATED";
    pub const ARTIFACT_ADMISSION_ACCEPTED: &str = "ARTIFACT_ADMISSION_ACCEPTED";
    pub const ARTIFACT_ENFORCEMENT_CHECK: &str = "ARTIFACT_ENFORCEMENT_CHECK";
    pub const ARTIFACT_DRIFT_DETECTED: &str = "ARTIFACT_DRIFT_DETECTED";
}

// ---------------------------------------------------------------------------
// Error codes
// ---------------------------------------------------------------------------
pub mod error_codes {
    pub const ERR_ARTIFACT_MISSING_CONTRACT: &str = "ERR_ARTIFACT_MISSING_CONTRACT";
    pub const ERR_ARTIFACT_INVALID_CAPABILITY: &str = "ERR_ARTIFACT_INVALID_CAPABILITY";
    pub const ERR_ARTIFACT_SIGNATURE_INVALID: &str = "ERR_ARTIFACT_SIGNATURE_INVALID";
    pub const ERR_ARTIFACT_SCHEMA_MISMATCH: &str = "ERR_ARTIFACT_SCHEMA_MISMATCH";
    pub const ERR_ARTIFACT_ENFORCEMENT_DRIFT: &str = "ERR_ARTIFACT_ENFORCEMENT_DRIFT";
    pub const ERR_ARTIFACT_ADMISSION_DENIED: &str = "ERR_ARTIFACT_ADMISSION_DENIED";
}

// ---------------------------------------------------------------------------
// Invariants
// ---------------------------------------------------------------------------
pub mod invariants {
    /// Admission denies any artifact whose capability contract is absent or invalid.
    pub const INV_ARTIFACT_FAIL_CLOSED: &str = "INV-ARTIFACT-FAIL-CLOSED";
    /// Runtime envelope exactly matches the admitted capability set.
    pub const INV_ARTIFACT_CAPABILITY_ENVELOPE: &str = "INV-ARTIFACT-CAPABILITY-ENVELOPE";
    /// No drift between admitted contract and runtime enforcement.
    pub const INV_ARTIFACT_NO_DRIFT: &str = "INV-ARTIFACT-NO-DRIFT";
    /// Capability contracts must carry a valid signature.
    pub const INV_ARTIFACT_SIGNED_CONTRACT: &str = "INV-ARTIFACT-SIGNED-CONTRACT";
}

// ---------------------------------------------------------------------------
// Data model
// ---------------------------------------------------------------------------

/// A single capability entry within a capability contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityEntry {
    pub capability_id: String,
    pub scope: String,
    pub max_calls_per_epoch: u64,
}

/// An embedded capability contract carried by an extension artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityContract {
    pub contract_id: String,
    pub extension_id: String,
    pub capabilities: Vec<CapabilityEntry>,
    pub signer_id: String,
    pub signature: String,
    pub schema_version: String,
    pub issued_epoch_ms: u64,
}

/// An extension artifact that may or may not carry a capability contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtensionArtifact {
    pub artifact_id: String,
    pub extension_id: String,
    pub capability_contract: Option<CapabilityContract>,
    pub payload_hash: String,
}

// ---------------------------------------------------------------------------
// Admission
// ---------------------------------------------------------------------------

/// Reason admission was denied.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdmissionDenialReason {
    MissingContract,
    InvalidCapability { detail: String },
    SignatureInvalid,
    SchemaMismatch { expected: String, actual: String },
}

impl AdmissionDenialReason {
    pub fn code(&self) -> &'static str {
        match self {
            Self::MissingContract => error_codes::ERR_ARTIFACT_MISSING_CONTRACT,
            Self::InvalidCapability { .. } => error_codes::ERR_ARTIFACT_INVALID_CAPABILITY,
            Self::SignatureInvalid => error_codes::ERR_ARTIFACT_SIGNATURE_INVALID,
            Self::SchemaMismatch { .. } => error_codes::ERR_ARTIFACT_SCHEMA_MISMATCH,
        }
    }
}

/// Outcome of artifact admission.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdmissionOutcome {
    Accepted {
        contract_id: String,
        extension_id: String,
        event_code: String,
    },
    Denied {
        reason: AdmissionDenialReason,
        event_code: String,
    },
}

/// Configuration for artifact admission gate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdmissionConfig {
    pub expected_schema_version: String,
    pub trusted_signers: Vec<String>,
}

impl AdmissionConfig {
    pub fn new(expected_schema_version: impl Into<String>) -> Self {
        Self {
            expected_schema_version: expected_schema_version.into(),
            trusted_signers: Vec::new(),
        }
    }

    pub fn with_signer(mut self, signer_id: impl Into<String>) -> Self {
        self.trusted_signers.push(signer_id.into());
        self
    }
}

/// Admission gate for capability-carrying extension artifacts.
///
/// INV-ARTIFACT-FAIL-CLOSED: admission denies any artifact whose capability
/// contract is absent, malformed, or fails validation.
/// INV-ARTIFACT-SIGNED-CONTRACT: capability contracts must carry a valid signature.
pub struct AdmissionGate {
    config: AdmissionConfig,
}

impl AdmissionGate {
    pub fn new(config: AdmissionConfig) -> Self {
        Self { config }
    }

    /// Evaluate whether an extension artifact should be admitted.
    ///
    /// INV-ARTIFACT-FAIL-CLOSED: returns Denied on any validation failure.
    /// INV-ARTIFACT-SIGNED-CONTRACT: signature must verify against trusted signers.
    pub fn evaluate(&self, artifact: &ExtensionArtifact) -> AdmissionOutcome {
        // INV-ARTIFACT-FAIL-CLOSED: missing contract -> deny
        let contract = match &artifact.capability_contract {
            Some(c) => c,
            None => {
                return AdmissionOutcome::Denied {
                    reason: AdmissionDenialReason::MissingContract,
                    event_code: error_codes::ERR_ARTIFACT_ADMISSION_DENIED.to_string(),
                };
            }
        };

        // Schema version check
        if contract.schema_version != self.config.expected_schema_version {
            return AdmissionOutcome::Denied {
                reason: AdmissionDenialReason::SchemaMismatch {
                    expected: self.config.expected_schema_version.clone(),
                    actual: contract.schema_version.clone(),
                },
                event_code: error_codes::ERR_ARTIFACT_ADMISSION_DENIED.to_string(),
            };
        }

        // Validate each capability entry
        for cap in &contract.capabilities {
            if cap.capability_id.is_empty() || cap.scope.is_empty() {
                return AdmissionOutcome::Denied {
                    reason: AdmissionDenialReason::InvalidCapability {
                        detail: format!(
                            "empty capability_id or scope in capability '{}'",
                            cap.capability_id
                        ),
                    },
                    event_code: error_codes::ERR_ARTIFACT_ADMISSION_DENIED.to_string(),
                };
            }
            if cap.max_calls_per_epoch == 0 {
                return AdmissionOutcome::Denied {
                    reason: AdmissionDenialReason::InvalidCapability {
                        detail: format!(
                            "max_calls_per_epoch must be > 0 for '{}'",
                            cap.capability_id
                        ),
                    },
                    event_code: error_codes::ERR_ARTIFACT_ADMISSION_DENIED.to_string(),
                };
            }
        }

        // INV-ARTIFACT-SIGNED-CONTRACT: verify signer is trusted and signature is valid
        if !self.config.trusted_signers.contains(&contract.signer_id) {
            return AdmissionOutcome::Denied {
                reason: AdmissionDenialReason::SignatureInvalid,
                event_code: error_codes::ERR_ARTIFACT_ADMISSION_DENIED.to_string(),
            };
        }

        if !verify_contract_signature(contract) {
            return AdmissionOutcome::Denied {
                reason: AdmissionDenialReason::SignatureInvalid,
                event_code: error_codes::ERR_ARTIFACT_ADMISSION_DENIED.to_string(),
            };
        }

        AdmissionOutcome::Accepted {
            contract_id: contract.contract_id.clone(),
            extension_id: contract.extension_id.clone(),
            event_code: event_codes::ARTIFACT_ADMISSION_ACCEPTED.to_string(),
        }
    }
}

// ---------------------------------------------------------------------------
// Runtime enforcement
// ---------------------------------------------------------------------------

/// Drift detection result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DriftCheckResult {
    NoDrift {
        event_code: String,
    },
    DriftDetected {
        missing: Vec<String>,
        extra: Vec<String>,
        event_code: String,
    },
}

/// Runtime enforcement engine that verifies active capabilities match
/// the admitted contract envelope.
///
/// INV-ARTIFACT-CAPABILITY-ENVELOPE: runtime envelope exactly matches admitted set.
/// INV-ARTIFACT-NO-DRIFT: no drift between admitted contract and runtime enforcement.
pub struct EnforcementEngine {
    /// The admitted capability contract.
    admitted_capabilities: BTreeMap<String, CapabilityEntry>,
    contract_id: String,
}

impl EnforcementEngine {
    /// Create an enforcement engine from an admitted contract.
    pub fn from_contract(contract: &CapabilityContract) -> Self {
        let mut admitted = BTreeMap::new();
        for cap in &contract.capabilities {
            admitted.insert(cap.capability_id.clone(), cap.clone());
        }
        Self {
            admitted_capabilities: admitted,
            contract_id: contract.contract_id.clone(),
        }
    }

    /// Check if a capability invocation is within the admitted envelope.
    ///
    /// INV-ARTIFACT-CAPABILITY-ENVELOPE: returns false if the capability is
    /// not in the admitted set.
    pub fn is_permitted(&self, capability_id: &str) -> bool {
        self.admitted_capabilities.contains_key(capability_id)
    }

    /// Perform a drift check between the admitted contract and the active capabilities.
    ///
    /// INV-ARTIFACT-NO-DRIFT: detects any mismatch between admitted and active sets.
    pub fn check_drift(&self, active_capabilities: &[String]) -> DriftCheckResult {
        let admitted_ids: Vec<String> = self.admitted_capabilities.keys().cloned().collect();
        let mut missing = Vec::new();
        let mut extra = Vec::new();

        for admitted_id in &admitted_ids {
            if !active_capabilities.contains(admitted_id) {
                missing.push(admitted_id.clone());
            }
        }

        for active_id in active_capabilities {
            if !self.admitted_capabilities.contains_key(active_id) {
                extra.push(active_id.clone());
            }
        }

        if missing.is_empty() && extra.is_empty() {
            DriftCheckResult::NoDrift {
                event_code: event_codes::ARTIFACT_ENFORCEMENT_CHECK.to_string(),
            }
        } else {
            DriftCheckResult::DriftDetected {
                missing,
                extra,
                event_code: event_codes::ARTIFACT_DRIFT_DETECTED.to_string(),
            }
        }
    }

    /// Return the contract ID of the admitted contract.
    pub fn contract_id(&self) -> &str {
        &self.contract_id
    }

    /// Return the count of admitted capabilities.
    pub fn admitted_count(&self) -> usize {
        self.admitted_capabilities.len()
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn digest_bytes(input: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"artifact_contract_digest_v1:");
    hasher.update(input);
    hex::encode(hasher.finalize())
}

fn verify_contract_signature(contract: &CapabilityContract) -> bool {
    let expected = compute_contract_signature(contract);
    contract.signature == expected
}

/// Compute the expected signature for a capability contract.
pub fn compute_contract_signature(contract: &CapabilityContract) -> String {
    let cap_ids: Vec<&str> = contract
        .capabilities
        .iter()
        .map(|c| c.capability_id.as_str())
        .collect();
    let payload = format!(
        "{}|{}|{}|{}|{}",
        contract.contract_id,
        contract.extension_id,
        cap_ids.join(","),
        contract.signer_id,
        contract.issued_epoch_ms
    );
    digest_bytes(payload.as_bytes())
}

/// Create a valid, signed capability contract for testing.
pub fn make_contract(
    contract_id: &str,
    extension_id: &str,
    capabilities: Vec<CapabilityEntry>,
    signer_id: &str,
    schema_version: &str,
    issued_epoch_ms: u64,
) -> CapabilityContract {
    let mut contract = CapabilityContract {
        contract_id: contract_id.to_string(),
        extension_id: extension_id.to_string(),
        capabilities,
        signer_id: signer_id.to_string(),
        signature: String::new(),
        schema_version: schema_version.to_string(),
        issued_epoch_ms,
    };
    contract.signature = compute_contract_signature(&contract);
    contract
}

/// Create a valid extension artifact with a signed contract for testing.
pub fn make_artifact(
    artifact_id: &str,
    extension_id: &str,
    contract: CapabilityContract,
) -> ExtensionArtifact {
    let payload_hash = digest_bytes(format!("{}:{}", artifact_id, extension_id).as_bytes());
    ExtensionArtifact {
        artifact_id: artifact_id.to_string(),
        extension_id: extension_id.to_string(),
        capability_contract: Some(contract),
        payload_hash,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_capabilities() -> Vec<CapabilityEntry> {
        vec![
            CapabilityEntry {
                capability_id: "fs.read".to_string(),
                scope: "filesystem:read".to_string(),
                max_calls_per_epoch: 1000,
            },
            CapabilityEntry {
                capability_id: "net.egress".to_string(),
                scope: "network:egress".to_string(),
                max_calls_per_epoch: 100,
            },
        ]
    }

    fn test_contract() -> CapabilityContract {
        make_contract(
            "contract-1",
            "ext-alpha",
            test_capabilities(),
            "signer-A",
            SCHEMA_VERSION,
            10_000,
        )
    }

    fn test_gate() -> AdmissionGate {
        let cfg = AdmissionConfig::new(SCHEMA_VERSION).with_signer("signer-A");
        AdmissionGate::new(cfg)
    }

    #[test]
    fn admission_rejects_missing_contract() {
        let gate = test_gate();
        let artifact = ExtensionArtifact {
            artifact_id: "a1".to_string(),
            extension_id: "ext-alpha".to_string(),
            capability_contract: None,
            payload_hash: "h1".to_string(),
        };
        let outcome = gate.evaluate(&artifact);
        assert!(matches!(
            outcome,
            AdmissionOutcome::Denied {
                reason: AdmissionDenialReason::MissingContract,
                ..
            }
        ));
    }

    #[test]
    fn admission_rejects_schema_mismatch() {
        let gate = test_gate();
        let contract = make_contract(
            "contract-1",
            "ext-alpha",
            test_capabilities(),
            "signer-A",
            "wrong-schema",
            10_000,
        );
        let artifact = make_artifact("a1", "ext-alpha", contract);
        let outcome = gate.evaluate(&artifact);
        assert!(matches!(
            outcome,
            AdmissionOutcome::Denied {
                reason: AdmissionDenialReason::SchemaMismatch { .. },
                ..
            }
        ));
    }

    #[test]
    fn admission_rejects_invalid_capability_empty_id() {
        let gate = test_gate();
        let caps = vec![CapabilityEntry {
            capability_id: "".to_string(),
            scope: "filesystem:read".to_string(),
            max_calls_per_epoch: 100,
        }];
        let contract = make_contract(
            "contract-1",
            "ext-alpha",
            caps,
            "signer-A",
            SCHEMA_VERSION,
            10_000,
        );
        let artifact = make_artifact("a1", "ext-alpha", contract);
        let outcome = gate.evaluate(&artifact);
        assert!(matches!(
            outcome,
            AdmissionOutcome::Denied {
                reason: AdmissionDenialReason::InvalidCapability { .. },
                ..
            }
        ));
    }

    #[test]
    fn admission_rejects_invalid_capability_zero_calls() {
        let gate = test_gate();
        let caps = vec![CapabilityEntry {
            capability_id: "fs.read".to_string(),
            scope: "filesystem:read".to_string(),
            max_calls_per_epoch: 0,
        }];
        let contract = make_contract(
            "contract-1",
            "ext-alpha",
            caps,
            "signer-A",
            SCHEMA_VERSION,
            10_000,
        );
        let artifact = make_artifact("a1", "ext-alpha", contract);
        let outcome = gate.evaluate(&artifact);
        assert!(matches!(
            outcome,
            AdmissionOutcome::Denied {
                reason: AdmissionDenialReason::InvalidCapability { .. },
                ..
            }
        ));
    }

    #[test]
    fn admission_rejects_untrusted_signer() {
        let gate = test_gate();
        let contract = make_contract(
            "contract-1",
            "ext-alpha",
            test_capabilities(),
            "untrusted-signer",
            SCHEMA_VERSION,
            10_000,
        );
        let artifact = make_artifact("a1", "ext-alpha", contract);
        let outcome = gate.evaluate(&artifact);
        assert!(matches!(
            outcome,
            AdmissionOutcome::Denied {
                reason: AdmissionDenialReason::SignatureInvalid,
                ..
            }
        ));
    }

    #[test]
    fn admission_rejects_tampered_signature() {
        let gate = test_gate();
        let mut contract = test_contract();
        contract.signature = "tampered-sig".to_string();
        let artifact = make_artifact("a1", "ext-alpha", contract);
        let outcome = gate.evaluate(&artifact);
        assert!(matches!(
            outcome,
            AdmissionOutcome::Denied {
                reason: AdmissionDenialReason::SignatureInvalid,
                ..
            }
        ));
    }

    #[test]
    fn admission_accepts_valid_artifact() {
        let gate = test_gate();
        let contract = test_contract();
        let artifact = make_artifact("a1", "ext-alpha", contract);
        let outcome = gate.evaluate(&artifact);
        assert!(matches!(outcome, AdmissionOutcome::Accepted { .. }));
    }

    #[test]
    fn enforcement_permits_admitted_capability() {
        let contract = test_contract();
        let engine = EnforcementEngine::from_contract(&contract);
        assert!(engine.is_permitted("fs.read"));
        assert!(engine.is_permitted("net.egress"));
        assert!(!engine.is_permitted("fs.write"));
    }

    #[test]
    fn enforcement_rejects_unadmitted_capability() {
        let contract = test_contract();
        let engine = EnforcementEngine::from_contract(&contract);
        assert!(!engine.is_permitted("crypto.sign"));
    }

    #[test]
    fn drift_check_no_drift() {
        let contract = test_contract();
        let engine = EnforcementEngine::from_contract(&contract);
        let active = vec!["fs.read".to_string(), "net.egress".to_string()];
        let result = engine.check_drift(&active);
        assert!(matches!(result, DriftCheckResult::NoDrift { .. }));
    }

    #[test]
    fn drift_check_detects_missing_capabilities() {
        let contract = test_contract();
        let engine = EnforcementEngine::from_contract(&contract);
        let active = vec!["fs.read".to_string()]; // missing net.egress
        let result = engine.check_drift(&active);
        match result {
            DriftCheckResult::DriftDetected { missing, extra, .. } => {
                assert!(missing.contains(&"net.egress".to_string()));
                assert!(extra.is_empty());
            }
            _ => panic!("expected drift detected"),
        }
    }

    #[test]
    fn drift_check_detects_extra_capabilities() {
        let contract = test_contract();
        let engine = EnforcementEngine::from_contract(&contract);
        let active = vec![
            "fs.read".to_string(),
            "net.egress".to_string(),
            "crypto.sign".to_string(),
        ];
        let result = engine.check_drift(&active);
        match result {
            DriftCheckResult::DriftDetected { missing, extra, .. } => {
                assert!(missing.is_empty());
                assert!(extra.contains(&"crypto.sign".to_string()));
            }
            _ => panic!("expected drift detected"),
        }
    }

    #[test]
    fn drift_check_detects_both_missing_and_extra() {
        let contract = test_contract();
        let engine = EnforcementEngine::from_contract(&contract);
        let active = vec!["crypto.sign".to_string()];
        let result = engine.check_drift(&active);
        match result {
            DriftCheckResult::DriftDetected { missing, extra, .. } => {
                assert!(!missing.is_empty());
                assert!(!extra.is_empty());
            }
            _ => panic!("expected drift detected"),
        }
    }

    #[test]
    fn contract_signature_is_deterministic() {
        let c1 = test_contract();
        let c2 = test_contract();
        assert_eq!(c1.signature, c2.signature);
    }

    #[test]
    fn admitted_count_matches_capabilities() {
        let contract = test_contract();
        let engine = EnforcementEngine::from_contract(&contract);
        assert_eq!(engine.admitted_count(), 2);
    }
}
