//! Offline verification for trust-native module-resolution receipts.

use ed25519_dalek::{Signature, VerifyingKey};
use hex::FromHex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fmt;
use subtle::ConstantTimeEq as _;

const RESOLUTION_RECEIPT_HASH_DOMAIN: &[u8] = b"franken-node/resolution-receipt/payload-hash/v1:";
const RESOLUTION_RECEIPT_SIGNATURE_DOMAIN: &[u8] = b"franken-node/resolution-receipt/signature/v1:";
const RESOLUTION_RECEIPT_SIGNER_KEY_ID_DOMAIN: &[u8] =
    b"franken-node/resolution-receipt/signer-key-id/v1:";
const SHA256_PREFIX: &str = "sha256:";
const SIGNATURE_HEX_LEN: usize = 128;
const MAX_CANDIDATES: usize = 1024;
const MAX_EVIDENCE_REFS: usize = 4096;
const MAX_TEXT_BYTES: usize = 4096;

pub const RESOLUTION_RECEIPT_SCHEMA_VERSION: &str = "resolution-receipt-v1";
pub const RESOLUTION_RECEIPT_SIGNATURE_ALGORITHM: &str = "ed25519-v1";
pub const RESOLUTION_RECEIPT_CRYPTO_SUITE: &str = "ed25519-v1";
pub const FN_VSDK_RESOLUTION_RECEIPT_START: &str = "FN-VSDK-RESOLUTION-RECEIPT-START";
pub const FN_VSDK_RESOLUTION_RECEIPT_VERIFIED: &str = "FN-VSDK-RESOLUTION-RECEIPT-VERIFIED";
pub const FN_VSDK_RESOLUTION_RECEIPT_PASS: &str = "FN-VSDK-RESOLUTION-RECEIPT-PASS";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdmissionProfile {
    Strict,
    Balanced,
    LegacyRisky,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdmissionDecision {
    Admit,
    Reject,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityBudgetMode {
    Advisory,
    Enforced,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustCardStatus {
    Trusted,
    Unknown,
    Quarantined,
    Revoked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskTier {
    Low,
    Moderate,
    High,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompatibilityStatus {
    Compatible,
    NeedsShim,
    Unknown,
    Divergent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevocationFreshness {
    Fresh,
    Stale,
    Missing,
    Revoked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResolutionRejectionReason {
    TrustCardQuarantined,
    TrustCardRevoked,
    CriticalRisk,
    CompatibilityDivergent,
    RevocationRevoked,
    ProfilePolicy,
    SupersededByPreferredCandidate,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CandidateAssessment {
    pub version: String,
    pub package_path: String,
    pub resolved_url: Option<String>,
    pub integrity: Option<String>,
    pub trust_card_ref: String,
    pub trust_status: TrustCardStatus,
    pub bpet_risk_ref: String,
    pub bpet_risk: RiskTier,
    pub dgis_risk_ref: String,
    pub dgis_risk: RiskTier,
    pub revocation_freshness_ref: String,
    pub revocation_freshness: RevocationFreshness,
    pub compat_oracle_ref: String,
    pub compat_status: CompatibilityStatus,
    pub capability_budget_ref: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RejectedAlternative {
    pub candidate: CandidateAssessment,
    pub reason: ResolutionRejectionReason,
    pub rationale: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolutionEvidenceRefs {
    pub trust_card_refs: Vec<String>,
    pub bpet_risk_refs: Vec<String>,
    pub dgis_risk_refs: Vec<String>,
    pub revocation_freshness_refs: Vec<String>,
    pub compat_oracle_refs: Vec<String>,
    pub capability_budget_refs: Vec<String>,
    pub policy_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolutionReceipt {
    pub schema_version: String,
    pub crypto_suite: String,
    pub receipt_id: String,
    pub issued_at_millis: u64,
    pub module_graph_hash: String,
    pub package_name: String,
    pub requested_range: String,
    pub policy_profile: AdmissionProfile,
    pub capability_budget_mode: CapabilityBudgetMode,
    pub decision: AdmissionDecision,
    pub selected_version: Option<CandidateAssessment>,
    pub rejected_alternatives: Vec<RejectedAlternative>,
    pub evidence_refs: ResolutionEvidenceRefs,
    pub rationale: String,
    pub canonical_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedResolutionReceipt {
    pub receipt: ResolutionReceipt,
    pub signer_key_id: String,
    pub signature_algorithm: String,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedResolutionReceipt {
    pub receipt_id: String,
    pub crypto_suite: String,
    pub package_name: String,
    pub requested_range: String,
    pub policy_profile: AdmissionProfile,
    pub capability_budget_mode: CapabilityBudgetMode,
    pub decision: AdmissionDecision,
    pub selected_version: Option<String>,
    pub rejected_alternative_count: usize,
    pub canonical_hash: String,
    pub signer_key_id: String,
    pub event_codes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct ResolutionReceiptPayload<'a> {
    schema_version: &'a str,
    crypto_suite: &'a str,
    receipt_id: &'a str,
    issued_at_millis: u64,
    module_graph_hash: &'a str,
    package_name: &'a str,
    requested_range: &'a str,
    policy_profile: AdmissionProfile,
    capability_budget_mode: CapabilityBudgetMode,
    decision: AdmissionDecision,
    selected_version: &'a Option<CandidateAssessment>,
    rejected_alternatives: &'a [RejectedAlternative],
    evidence_refs: &'a ResolutionEvidenceRefs,
    rationale: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolutionReceiptError {
    Json(String),
    NonCanonicalEncoding,
    BoundExceeded { surface: &'static str, max: usize },
    InvalidField { field: &'static str, reason: String },
    UnsupportedSchema { expected: String, actual: String },
    HashMismatch { expected: String, actual: String },
    SignerKeyMismatch { expected: String, actual: String },
    SignatureAlgorithmMismatch { expected: String, actual: String },
    SignatureHex(String),
    SignatureMalformed { length: usize },
    SignatureInvalid,
}

impl fmt::Display for ResolutionReceiptError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Json(source) => write!(formatter, "resolution receipt JSON error: {source}"),
            Self::NonCanonicalEncoding => {
                write!(formatter, "resolution receipt bytes are not canonical")
            }
            Self::BoundExceeded { surface, max } => {
                write!(
                    formatter,
                    "resolution receipt {surface} exceeds bound {max}"
                )
            }
            Self::InvalidField { field, reason } => {
                write!(
                    formatter,
                    "resolution receipt field {field} is invalid: {reason}"
                )
            }
            Self::UnsupportedSchema { expected, actual } => write!(
                formatter,
                "resolution receipt schema mismatch: expected {expected}, got {actual}"
            ),
            Self::HashMismatch {
                expected: _,
                actual: _,
            } => write!(
                formatter,
                "resolution receipt canonical hash mismatch (values redacted)"
            ),
            Self::SignerKeyMismatch {
                expected: _,
                actual: _,
            } => write!(
                formatter,
                "resolution receipt signer key id mismatch (values redacted)"
            ),
            Self::SignatureAlgorithmMismatch { expected, actual } => write!(
                formatter,
                "resolution receipt signature algorithm mismatch: expected {expected}, got {actual}"
            ),
            Self::SignatureHex(source) => {
                write!(
                    formatter,
                    "resolution receipt signature hex is invalid: {source}"
                )
            }
            Self::SignatureMalformed { length } => write!(
                formatter,
                "resolution receipt Ed25519 signature has invalid length {length}"
            ),
            Self::SignatureInvalid => write!(
                formatter,
                "resolution receipt Ed25519 signature verification failed"
            ),
        }
    }
}

impl std::error::Error for ResolutionReceiptError {}

pub type ResolutionReceiptResult<T> = Result<T, ResolutionReceiptError>;

pub fn verify_signed_resolution_receipt(
    verifying_key: &VerifyingKey,
    bytes: &[u8],
) -> ResolutionReceiptResult<VerifiedResolutionReceipt> {
    let signed: SignedResolutionReceipt = serde_json::from_slice(bytes)
        .map_err(|source| ResolutionReceiptError::Json(source.to_string()))?;
    let canonical = canonical_json_bytes(&signed)?;
    if canonical != bytes {
        return Err(ResolutionReceiptError::NonCanonicalEncoding);
    }
    validate_receipt(&signed.receipt)?;
    let expected_signature_algorithm =
        signature_algorithm_for_crypto_suite(&signed.receipt.crypto_suite)?;
    if !constant_time_eq(
        signed.signature_algorithm.as_str(),
        expected_signature_algorithm,
    ) {
        return Err(ResolutionReceiptError::SignatureAlgorithmMismatch {
            expected: expected_signature_algorithm.to_string(),
            actual: signed.signature_algorithm.clone(),
        });
    }
    let expected_key_id = signer_key_id(verifying_key);
    if !constant_time_eq(&expected_key_id, &signed.signer_key_id) {
        return Err(ResolutionReceiptError::SignerKeyMismatch {
            expected: expected_key_id,
            actual: signed.signer_key_id.clone(),
        });
    }
    if signed.signature.len() != SIGNATURE_HEX_LEN {
        return Err(ResolutionReceiptError::SignatureMalformed {
            length: signed.signature.len(),
        });
    }
    let signature_bytes = <[u8; 64]>::from_hex(signed.signature.as_str())
        .map_err(|source| ResolutionReceiptError::SignatureHex(source.to_string()))?;
    let signature = Signature::from_bytes(&signature_bytes);
    verifying_key
        .verify_strict(&signature_payload(&signed.receipt)?, &signature)
        .map_err(|_| ResolutionReceiptError::SignatureInvalid)?;

    Ok(VerifiedResolutionReceipt {
        receipt_id: signed.receipt.receipt_id,
        crypto_suite: signed.receipt.crypto_suite,
        package_name: signed.receipt.package_name,
        requested_range: signed.receipt.requested_range,
        policy_profile: signed.receipt.policy_profile,
        capability_budget_mode: signed.receipt.capability_budget_mode,
        decision: signed.receipt.decision,
        selected_version: signed
            .receipt
            .selected_version
            .map(|candidate| candidate.version),
        rejected_alternative_count: signed.receipt.rejected_alternatives.len(),
        canonical_hash: signed.receipt.canonical_hash,
        signer_key_id: signed.signer_key_id,
        event_codes: vec![
            FN_VSDK_RESOLUTION_RECEIPT_START.to_string(),
            FN_VSDK_RESOLUTION_RECEIPT_VERIFIED.to_string(),
            FN_VSDK_RESOLUTION_RECEIPT_PASS.to_string(),
        ],
    })
}

fn validate_receipt(receipt: &ResolutionReceipt) -> ResolutionReceiptResult<()> {
    if receipt.schema_version != RESOLUTION_RECEIPT_SCHEMA_VERSION {
        return Err(ResolutionReceiptError::UnsupportedSchema {
            expected: RESOLUTION_RECEIPT_SCHEMA_VERSION.to_string(),
            actual: receipt.schema_version.clone(),
        });
    }
    validate_crypto_suite("crypto_suite", &receipt.crypto_suite)?;
    validate_nonempty("receipt_id", &receipt.receipt_id)?;
    validate_sha256_hash("module_graph_hash", &receipt.module_graph_hash)?;
    validate_nonempty("package_name", &receipt.package_name)?;
    validate_nonempty("requested_range", &receipt.requested_range)?;
    validate_nonempty("rationale", &receipt.rationale)?;
    validate_sha256_hash("canonical_hash", &receipt.canonical_hash)?;
    ensure_bound(
        receipt.rejected_alternatives.len(),
        MAX_CANDIDATES,
        "rejected alternatives",
    )?;
    validate_evidence_refs(&receipt.evidence_refs)?;
    match receipt.decision {
        AdmissionDecision::Admit => {
            let Some(selected) = &receipt.selected_version else {
                return Err(ResolutionReceiptError::InvalidField {
                    field: "selected_version",
                    reason: "admit receipts must carry a selected version".to_string(),
                });
            };
            validate_candidate(selected)?;
            if !candidate_is_admissible(receipt.policy_profile, selected) {
                return Err(ResolutionReceiptError::InvalidField {
                    field: "selected_version",
                    reason: "selected version is not admissible for policy profile".to_string(),
                });
            }
        }
        AdmissionDecision::Reject => {
            if receipt.selected_version.is_some() {
                return Err(ResolutionReceiptError::InvalidField {
                    field: "selected_version",
                    reason: "reject receipts must not carry a selected version".to_string(),
                });
            }
        }
    }
    for rejected in &receipt.rejected_alternatives {
        validate_candidate(&rejected.candidate)?;
        validate_nonempty("rejected_alternatives.rationale", &rejected.rationale)?;
    }
    let actual = recompute_receipt_hash(receipt)?;
    if !constant_time_eq(&receipt.canonical_hash, &actual) {
        return Err(ResolutionReceiptError::HashMismatch {
            expected: receipt.canonical_hash.clone(),
            actual,
        });
    }
    Ok(())
}

fn validate_candidate(candidate: &CandidateAssessment) -> ResolutionReceiptResult<()> {
    validate_nonempty("candidate.version", &candidate.version)?;
    validate_nonempty("candidate.package_path", &candidate.package_path)?;
    validate_nonempty("candidate.trust_card_ref", &candidate.trust_card_ref)?;
    validate_nonempty("candidate.bpet_risk_ref", &candidate.bpet_risk_ref)?;
    validate_nonempty("candidate.dgis_risk_ref", &candidate.dgis_risk_ref)?;
    validate_nonempty(
        "candidate.revocation_freshness_ref",
        &candidate.revocation_freshness_ref,
    )?;
    validate_nonempty("candidate.compat_oracle_ref", &candidate.compat_oracle_ref)?;
    validate_nonempty(
        "candidate.capability_budget_ref",
        &candidate.capability_budget_ref,
    )
}

fn validate_evidence_refs(evidence: &ResolutionEvidenceRefs) -> ResolutionReceiptResult<()> {
    validate_ref_group("trust_card_refs", &evidence.trust_card_refs)?;
    validate_ref_group("bpet_risk_refs", &evidence.bpet_risk_refs)?;
    validate_ref_group("dgis_risk_refs", &evidence.dgis_risk_refs)?;
    validate_ref_group(
        "revocation_freshness_refs",
        &evidence.revocation_freshness_refs,
    )?;
    validate_ref_group("compat_oracle_refs", &evidence.compat_oracle_refs)?;
    validate_ref_group("capability_budget_refs", &evidence.capability_budget_refs)?;
    validate_ref_group("policy_refs", &evidence.policy_refs)
}

fn validate_ref_group(field: &'static str, refs: &[String]) -> ResolutionReceiptResult<()> {
    if refs.is_empty() {
        return Err(ResolutionReceiptError::InvalidField {
            field,
            reason: "at least one evidence ref is required".to_string(),
        });
    }
    ensure_bound(refs.len(), MAX_EVIDENCE_REFS, field)?;
    for item in refs {
        validate_nonempty(field, item)?;
    }
    Ok(())
}

fn validate_nonempty(field: &'static str, value: &str) -> ResolutionReceiptResult<()> {
    if value.trim().is_empty() {
        return Err(ResolutionReceiptError::InvalidField {
            field,
            reason: "must not be empty".to_string(),
        });
    }
    if value.len() > MAX_TEXT_BYTES {
        return Err(ResolutionReceiptError::InvalidField {
            field,
            reason: format!("must not exceed {MAX_TEXT_BYTES} bytes"),
        });
    }
    Ok(())
}

fn validate_sha256_hash(field: &'static str, value: &str) -> ResolutionReceiptResult<()> {
    let Some(hex) = value.strip_prefix(SHA256_PREFIX) else {
        return Err(ResolutionReceiptError::InvalidField {
            field,
            reason: "must start with sha256:".to_string(),
        });
    };
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(ResolutionReceiptError::InvalidField {
            field,
            reason: "must be canonical lowercase 64-nybble hex".to_string(),
        });
    }
    Ok(())
}

fn ensure_bound(actual: usize, max: usize, surface: &'static str) -> ResolutionReceiptResult<()> {
    if actual > max {
        return Err(ResolutionReceiptError::BoundExceeded { surface, max });
    }
    Ok(())
}

fn candidate_is_admissible(profile: AdmissionProfile, candidate: &CandidateAssessment) -> bool {
    if candidate.trust_status == TrustCardStatus::Revoked
        || candidate.trust_status == TrustCardStatus::Quarantined
        || candidate.revocation_freshness == RevocationFreshness::Revoked
        || candidate.bpet_risk == RiskTier::Critical
        || candidate.dgis_risk == RiskTier::Critical
        || candidate.compat_status == CompatibilityStatus::Divergent
    {
        return false;
    }
    match profile {
        AdmissionProfile::Strict => {
            candidate.trust_status == TrustCardStatus::Trusted
                && candidate.bpet_risk <= RiskTier::Moderate
                && candidate.dgis_risk <= RiskTier::Moderate
                && candidate.revocation_freshness == RevocationFreshness::Fresh
                && candidate.compat_status == CompatibilityStatus::Compatible
        }
        AdmissionProfile::Balanced => {
            matches!(
                candidate.trust_status,
                TrustCardStatus::Trusted | TrustCardStatus::Unknown
            ) && candidate.bpet_risk <= RiskTier::High
                && candidate.dgis_risk <= RiskTier::High
                && matches!(
                    candidate.revocation_freshness,
                    RevocationFreshness::Fresh | RevocationFreshness::Stale
                )
                && matches!(
                    candidate.compat_status,
                    CompatibilityStatus::Compatible | CompatibilityStatus::NeedsShim
                )
        }
        AdmissionProfile::LegacyRisky => {
            candidate.bpet_risk <= RiskTier::High
                && candidate.dgis_risk <= RiskTier::High
                && candidate.compat_status != CompatibilityStatus::Divergent
        }
    }
}

fn recompute_receipt_hash(receipt: &ResolutionReceipt) -> ResolutionReceiptResult<String> {
    canonical_payload_bytes(receipt).map(|bytes| hash_payload(&bytes))
}

fn canonical_payload_bytes(receipt: &ResolutionReceipt) -> ResolutionReceiptResult<Vec<u8>> {
    canonical_json_bytes(&ResolutionReceiptPayload {
        schema_version: &receipt.schema_version,
        crypto_suite: &receipt.crypto_suite,
        receipt_id: &receipt.receipt_id,
        issued_at_millis: receipt.issued_at_millis,
        module_graph_hash: &receipt.module_graph_hash,
        package_name: &receipt.package_name,
        requested_range: &receipt.requested_range,
        policy_profile: receipt.policy_profile,
        capability_budget_mode: receipt.capability_budget_mode,
        decision: receipt.decision,
        selected_version: &receipt.selected_version,
        rejected_alternatives: &receipt.rejected_alternatives,
        evidence_refs: &receipt.evidence_refs,
        rationale: &receipt.rationale,
    })
}

fn validate_crypto_suite(field: &'static str, value: &str) -> ResolutionReceiptResult<()> {
    validate_nonempty(field, value)?;
    if !constant_time_eq(value, RESOLUTION_RECEIPT_CRYPTO_SUITE) {
        return Err(ResolutionReceiptError::InvalidField {
            field,
            reason: format!("unsupported crypto suite: {value}"),
        });
    }
    Ok(())
}

fn signature_algorithm_for_crypto_suite(value: &str) -> ResolutionReceiptResult<&'static str> {
    validate_crypto_suite("crypto_suite", value)?;
    Ok(RESOLUTION_RECEIPT_SIGNATURE_ALGORITHM)
}

fn canonical_receipt_bytes(receipt: &ResolutionReceipt) -> ResolutionReceiptResult<Vec<u8>> {
    canonical_json_bytes(receipt)
}

fn canonical_json_bytes(value: &impl Serialize) -> ResolutionReceiptResult<Vec<u8>> {
    let value = serde_json::to_value(value)
        .map_err(|source| ResolutionReceiptError::Json(source.to_string()))?;
    let canonical = canonicalize_value(value);
    serde_json::to_vec(&canonical)
        .map_err(|source| ResolutionReceiptError::Json(source.to_string()))
}

fn canonicalize_value(value: Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut entries: Vec<(String, Value)> = map.into_iter().collect();
            entries.sort_by(|left, right| left.0.cmp(&right.0));
            let mut object = serde_json::Map::with_capacity(entries.len());
            for (key, value) in entries {
                object.insert(key, canonicalize_value(value));
            }
            Value::Object(object)
        }
        Value::Array(values) => Value::Array(values.into_iter().map(canonicalize_value).collect()),
        other => other,
    }
}

fn hash_payload(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(RESOLUTION_RECEIPT_HASH_DOMAIN);
    hasher.update(u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_le_bytes());
    hasher.update(bytes);
    format!("{SHA256_PREFIX}{}", hex::encode(hasher.finalize()))
}

fn signature_payload(receipt: &ResolutionReceipt) -> ResolutionReceiptResult<Vec<u8>> {
    let canonical = canonical_receipt_bytes(receipt)?;
    let mut payload =
        Vec::with_capacity(RESOLUTION_RECEIPT_SIGNATURE_DOMAIN.len() + canonical.len());
    payload.extend_from_slice(RESOLUTION_RECEIPT_SIGNATURE_DOMAIN);
    payload.extend_from_slice(&canonical);
    Ok(payload)
}

fn signer_key_id(verifying_key: &VerifyingKey) -> String {
    let mut hasher = Sha256::new();
    hasher.update(RESOLUTION_RECEIPT_SIGNER_KEY_ID_DOMAIN);
    hasher.update(verifying_key.as_bytes());
    format!("{SHA256_PREFIX}{}", hex::encode(hasher.finalize()))
}

fn constant_time_eq(left: &str, right: &str) -> bool {
    left.as_bytes().ct_eq(right.as_bytes()).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer as _, SigningKey};

    fn sha256_ref(label: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(label.as_bytes());
        format!("{SHA256_PREFIX}{}", hex::encode(hasher.finalize()))
    }

    fn candidate(version: &str) -> CandidateAssessment {
        CandidateAssessment {
            version: version.to_string(),
            package_path: format!("pkg-{version}.tgz"),
            resolved_url: Some(format!("https://registry.example/pkg-{version}.tgz")),
            integrity: Some(sha256_ref(version)),
            trust_card_ref: format!("trust-card:{version}"),
            trust_status: TrustCardStatus::Trusted,
            bpet_risk_ref: format!("bpet:{version}"),
            bpet_risk: RiskTier::Low,
            dgis_risk_ref: format!("dgis:{version}"),
            dgis_risk: RiskTier::Low,
            revocation_freshness_ref: format!("revocation:{version}"),
            revocation_freshness: RevocationFreshness::Fresh,
            compat_oracle_ref: format!("compat:{version}"),
            compat_status: CompatibilityStatus::Compatible,
            capability_budget_ref: format!("cap-budget:{version}"),
        }
    }

    fn receipt() -> ResolutionReceipt {
        let mut receipt = ResolutionReceipt {
            schema_version: RESOLUTION_RECEIPT_SCHEMA_VERSION.to_string(),
            crypto_suite: RESOLUTION_RECEIPT_CRYPTO_SUITE.to_string(),
            receipt_id: "receipt-1".to_string(),
            issued_at_millis: 1_700_000_000_000,
            module_graph_hash: sha256_ref("module-graph"),
            package_name: "demo-package".to_string(),
            requested_range: "^1".to_string(),
            policy_profile: AdmissionProfile::Strict,
            capability_budget_mode: CapabilityBudgetMode::Advisory,
            decision: AdmissionDecision::Admit,
            selected_version: Some(candidate("1.2.3")),
            rejected_alternatives: Vec::new(),
            evidence_refs: ResolutionEvidenceRefs {
                trust_card_refs: vec!["trust-card:1.2.3".to_string()],
                bpet_risk_refs: vec!["bpet:1.2.3".to_string()],
                dgis_risk_refs: vec!["dgis:1.2.3".to_string()],
                revocation_freshness_refs: vec!["revocation:1.2.3".to_string()],
                compat_oracle_refs: vec!["compat:1.2.3".to_string()],
                capability_budget_refs: vec!["cap-budget:1.2.3".to_string()],
                policy_refs: vec!["policy-profile:strict".to_string()],
            },
            rationale: "demo-package@1.2.3 admitted".to_string(),
            canonical_hash: String::new(),
        };
        receipt.canonical_hash = recompute_receipt_hash(&receipt).expect("canonical hash");
        receipt
    }

    fn signed_receipt() -> (SigningKey, SignedResolutionReceipt) {
        let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
        let receipt = receipt();
        let payload = signature_payload(&receipt).expect("signature payload");
        let signature = signing_key.sign(&payload);
        let signed = SignedResolutionReceipt {
            receipt,
            signer_key_id: signer_key_id(&signing_key.verifying_key()),
            signature_algorithm: RESOLUTION_RECEIPT_SIGNATURE_ALGORITHM.to_string(),
            signature: hex::encode(signature.to_bytes()),
        };
        (signing_key, signed)
    }

    #[test]
    fn verify_signed_resolution_receipt_preserves_crypto_suite() {
        let (signing_key, signed) = signed_receipt();
        let bytes = canonical_json_bytes(&signed).expect("canonical signed receipt");

        let verified =
            verify_signed_resolution_receipt(&signing_key.verifying_key(), &bytes).expect("verify");

        assert_eq!(verified.crypto_suite, RESOLUTION_RECEIPT_CRYPTO_SUITE);
    }

    #[test]
    fn validate_receipt_rejects_unknown_crypto_suite() {
        let mut receipt = receipt();
        receipt.crypto_suite = "ed25519-v2".to_string();
        receipt.canonical_hash = recompute_receipt_hash(&receipt).expect("canonical hash");

        let err = validate_receipt(&receipt).expect_err("unknown suite must fail");

        assert!(matches!(
            err,
            ResolutionReceiptError::InvalidField {
                field: "crypto_suite",
                ..
            }
        ));
    }

    #[test]
    fn verify_signed_resolution_receipt_rejects_algorithm_suite_mismatch() {
        let (signing_key, mut signed) = signed_receipt();
        signed.signature_algorithm = "ed25519-v2".to_string();
        let bytes = canonical_json_bytes(&signed).expect("canonical signed receipt");

        let err = verify_signed_resolution_receipt(&signing_key.verifying_key(), &bytes)
            .expect_err("outer algorithm must match signed crypto suite");

        assert!(matches!(
            err,
            ResolutionReceiptError::SignatureAlgorithmMismatch { ref actual, .. }
                if actual == "ed25519-v2"
        ));
    }
}
