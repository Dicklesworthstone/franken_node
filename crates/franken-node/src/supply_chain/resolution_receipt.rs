//! Canonical module-resolution admission receipts.
//!
//! A [`ResolutionReceipt`] records why one package version was admitted or why
//! every candidate was rejected for a specific trust profile. The receipt is
//! intentionally advisory-only: it binds package-resolution facts to trust-card,
//! BPET, DGIS, revocation, compatibility, and capability-budget evidence without
//! pretending the runtime can meter host effects before Phase 1 lands.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hex::FromHex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fmt;

const RESOLUTION_RECEIPT_HASH_DOMAIN: &[u8] = b"franken-node/resolution-receipt/payload-hash/v1:";
const RESOLUTION_RECEIPT_SIGNATURE_DOMAIN: &[u8] = b"franken-node/resolution-receipt/signature/v1:";
const RESOLUTION_RECEIPT_SIGNER_KEY_ID_DOMAIN: &[u8] =
    b"franken-node/resolution-receipt/signer-key-id/v1:";
const SHA256_PREFIX: &str = "sha256:";
const SIGNATURE_HEX_LEN: usize = 128;
const MAX_CANDIDATES: usize = 1024;
const MAX_EVIDENCE_REFS: usize = 4096;
const MAX_TEXT_BYTES: usize = 4096;

pub const RESOLUTION_RECEIPT_SCHEMA: &str = crate::schema_versions::RESOLUTION_RECEIPT;
pub const RESOLUTION_RECEIPT_SIGNATURE_ALGORITHM: &str = "ed25519-v1";
pub const FN_RESOLVE_RECEIPT_START: &str = "FN-RESOLVE-RECEIPT-START";
pub const FN_RESOLVE_RECEIPT_ADMITTED: &str = "FN-RESOLVE-RECEIPT-ADMITTED";
pub const FN_RESOLVE_RECEIPT_REJECTED: &str = "FN-RESOLVE-RECEIPT-REJECTED";
pub const FN_RESOLVE_CAPABILITY_BUDGET_ADVISORY: &str = "FN-RESOLVE-CAPABILITY-BUDGET-ADVISORY";
pub const FN_RESOLVE_RECEIPT_PASS: &str = "FN-RESOLVE-RECEIPT-PASS";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdmissionProfile {
    Strict,
    Balanced,
    LegacyRisky,
}

impl AdmissionProfile {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Strict => "strict",
            Self::Balanced => "balanced",
            Self::LegacyRisky => "legacy-risky",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdmissionDecision {
    Admit,
    Reject,
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

impl ResolutionRejectionReason {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TrustCardQuarantined => "trust-card quarantined",
            Self::TrustCardRevoked => "trust-card revoked",
            Self::CriticalRisk => "critical ecosystem risk",
            Self::CompatibilityDivergent => "compatibility oracle divergence",
            Self::RevocationRevoked => "revocation registry revoked",
            Self::ProfilePolicy => "policy profile does not admit this candidate",
            Self::SupersededByPreferredCandidate => "superseded by preferred admissible candidate",
        }
    }
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
    pub receipt_id: String,
    pub issued_at_millis: u64,
    pub module_graph_hash: String,
    pub package_name: String,
    pub requested_range: String,
    pub policy_profile: AdmissionProfile,
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct ResolutionReceiptPayload<'a> {
    schema_version: &'a str,
    receipt_id: &'a str,
    issued_at_millis: u64,
    module_graph_hash: &'a str,
    package_name: &'a str,
    requested_range: &'a str,
    policy_profile: AdmissionProfile,
    decision: AdmissionDecision,
    selected_version: &'a Option<CandidateAssessment>,
    rejected_alternatives: &'a [RejectedAlternative],
    evidence_refs: &'a ResolutionEvidenceRefs,
    rationale: &'a str,
}

#[derive(Debug)]
pub enum ResolutionReceiptError {
    Json(serde_json::Error),
    EmptyCandidates,
    BoundExceeded { surface: &'static str, max: usize },
    InvalidField { field: &'static str, reason: String },
    UnsupportedSchema { expected: String, actual: String },
    HashMismatch { expected: String, actual: String },
    SignerKeyMismatch { expected: String, actual: String },
    SignatureAlgorithmMismatch { expected: String, actual: String },
    SignatureHex { source: hex::FromHexError },
    SignatureMalformed { length: usize },
    SignatureInvalid,
}

impl fmt::Display for ResolutionReceiptError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Json(source) => write!(formatter, "resolution receipt JSON error: {source}"),
            Self::EmptyCandidates => write!(formatter, "resolution receipt needs candidates"),
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
            Self::SignatureHex { source } => {
                write!(
                    formatter,
                    "resolution receipt signature hex is invalid: {source}"
                )
            }
            Self::SignatureMalformed { length } => write!(
                formatter,
                "resolution receipt Ed25519 signature has invalid length {length}"
            ),
            Self::SignatureInvalid => {
                write!(
                    formatter,
                    "resolution receipt Ed25519 signature verification failed"
                )
            }
        }
    }
}

impl std::error::Error for ResolutionReceiptError {}

impl From<serde_json::Error> for ResolutionReceiptError {
    fn from(source: serde_json::Error) -> Self {
        Self::Json(source)
    }
}

pub type ResolutionReceiptResult<T> = Result<T, ResolutionReceiptError>;

pub fn build_resolution_receipt(
    receipt_id: impl Into<String>,
    issued_at_millis: u64,
    module_graph_hash: impl Into<String>,
    package_name: impl Into<String>,
    requested_range: impl Into<String>,
    policy_profile: AdmissionProfile,
    candidates: Vec<CandidateAssessment>,
) -> ResolutionReceiptResult<ResolutionReceipt> {
    if candidates.is_empty() {
        return Err(ResolutionReceiptError::EmptyCandidates);
    }
    ensure_bound(candidates.len(), MAX_CANDIDATES, "candidate count")?;

    let mut candidates = candidates;
    candidates.sort_by(|left, right| {
        right
            .version
            .cmp(&left.version)
            .then_with(|| left.package_path.cmp(&right.package_path))
    });

    let selected_index = candidates
        .iter()
        .position(|candidate| rejection_reason_for(policy_profile, candidate).is_none());
    let selected_version = selected_index.and_then(|index| candidates.get(index).cloned());
    let mut rejected_alternatives = Vec::new();
    for (index, candidate) in candidates.into_iter().enumerate() {
        if Some(index) == selected_index {
            continue;
        }
        let reason = rejection_reason_for(policy_profile, &candidate)
            .unwrap_or(ResolutionRejectionReason::SupersededByPreferredCandidate);
        rejected_alternatives.push(RejectedAlternative {
            rationale: reason.as_str().to_string(),
            candidate,
            reason,
        });
    }

    let evidence_refs = aggregate_evidence_refs(
        selected_version
            .iter()
            .chain(rejected_alternatives.iter().map(|alt| &alt.candidate)),
        policy_profile,
    )?;
    let decision = if selected_version.is_some() {
        AdmissionDecision::Admit
    } else {
        AdmissionDecision::Reject
    };
    let package_name = package_name.into();
    let requested_range = requested_range.into();
    let rationale = match &selected_version {
        Some(selected) => format!(
            "{}@{} admitted under {} profile; {} alternatives rejected or superseded",
            package_name,
            selected.version,
            policy_profile.as_str(),
            rejected_alternatives.len()
        ),
        None => format!(
            "no candidate for {}@{} satisfies {} profile",
            package_name,
            requested_range,
            policy_profile.as_str()
        ),
    };

    seal_resolution_receipt(ResolutionReceipt {
        schema_version: RESOLUTION_RECEIPT_SCHEMA.to_string(),
        receipt_id: receipt_id.into(),
        issued_at_millis,
        module_graph_hash: module_graph_hash.into(),
        package_name,
        requested_range,
        policy_profile,
        decision,
        selected_version,
        rejected_alternatives,
        evidence_refs,
        rationale,
        canonical_hash: String::new(),
    })
}

pub fn sign_resolution_receipt(
    receipt: &ResolutionReceipt,
    signing_key: &SigningKey,
) -> ResolutionReceiptResult<SignedResolutionReceipt> {
    validate_resolution_receipt(receipt)?;
    let payload = signature_payload(receipt)?;
    let signature = signing_key.sign(&payload);
    Ok(SignedResolutionReceipt {
        receipt: receipt.clone(),
        signer_key_id: signer_key_id(&signing_key.verifying_key()),
        signature_algorithm: RESOLUTION_RECEIPT_SIGNATURE_ALGORITHM.to_string(),
        signature: hex::encode(signature.to_bytes()),
    })
}

pub fn verify_signed_resolution_receipt(
    signed: &SignedResolutionReceipt,
    verifying_key: &VerifyingKey,
) -> ResolutionReceiptResult<bool> {
    validate_resolution_receipt(&signed.receipt)?;
    if !constant_time_eq(
        signed.signature_algorithm.as_str(),
        RESOLUTION_RECEIPT_SIGNATURE_ALGORITHM,
    ) {
        return Err(ResolutionReceiptError::SignatureAlgorithmMismatch {
            expected: RESOLUTION_RECEIPT_SIGNATURE_ALGORITHM.to_string(),
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
        .map_err(|source| ResolutionReceiptError::SignatureHex { source })?;
    let signature = Signature::from_bytes(&signature_bytes);
    verifying_key
        .verify_strict(&signature_payload(&signed.receipt)?, &signature)
        .map(|()| true)
        .map_err(|_| ResolutionReceiptError::SignatureInvalid)
}

pub fn serialize_signed_resolution_receipt(
    signed: &SignedResolutionReceipt,
) -> ResolutionReceiptResult<Vec<u8>> {
    validate_resolution_receipt(&signed.receipt)?;
    canonical_json_bytes(signed)
}

pub fn canonical_resolution_receipt_bytes(
    receipt: &ResolutionReceipt,
) -> ResolutionReceiptResult<Vec<u8>> {
    canonical_json_bytes(receipt)
}

pub fn recompute_resolution_receipt_hash(
    receipt: &ResolutionReceipt,
) -> ResolutionReceiptResult<String> {
    canonical_payload_bytes(receipt).map(|bytes| hash_payload(&bytes))
}

pub fn candidate_is_admissible(profile: AdmissionProfile, candidate: &CandidateAssessment) -> bool {
    rejection_reason_for(profile, candidate).is_none()
}

pub fn resolution_receipt_event_codes(
    receipt: &ResolutionReceipt,
) -> ResolutionReceiptResult<Vec<&'static str>> {
    validate_resolution_receipt(receipt)?;
    let decision_code = match receipt.decision {
        AdmissionDecision::Admit => FN_RESOLVE_RECEIPT_ADMITTED,
        AdmissionDecision::Reject => FN_RESOLVE_RECEIPT_REJECTED,
    };
    let mut codes = vec![FN_RESOLVE_RECEIPT_START, decision_code];
    if !receipt.evidence_refs.capability_budget_refs.is_empty() {
        codes.push(FN_RESOLVE_CAPABILITY_BUDGET_ADVISORY);
    }
    codes.push(FN_RESOLVE_RECEIPT_PASS);
    Ok(codes)
}

fn seal_resolution_receipt(
    mut receipt: ResolutionReceipt,
) -> ResolutionReceiptResult<ResolutionReceipt> {
    receipt.canonical_hash = recompute_resolution_receipt_hash(&receipt)?;
    validate_resolution_receipt(&receipt)?;
    Ok(receipt)
}

fn validate_resolution_receipt(receipt: &ResolutionReceipt) -> ResolutionReceiptResult<()> {
    if receipt.schema_version != RESOLUTION_RECEIPT_SCHEMA {
        return Err(ResolutionReceiptError::UnsupportedSchema {
            expected: RESOLUTION_RECEIPT_SCHEMA.to_string(),
            actual: receipt.schema_version.clone(),
        });
    }
    validate_nonempty("receipt_id", &receipt.receipt_id)?;
    validate_nonempty("module_graph_hash", &receipt.module_graph_hash)?;
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
    for alternative in &receipt.rejected_alternatives {
        validate_candidate(&alternative.candidate)?;
        validate_nonempty("rejected_alternatives.rationale", &alternative.rationale)?;
    }
    let actual = recompute_resolution_receipt_hash(receipt)?;
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

fn rejection_reason_for(
    profile: AdmissionProfile,
    candidate: &CandidateAssessment,
) -> Option<ResolutionRejectionReason> {
    if candidate.trust_status == TrustCardStatus::Revoked {
        return Some(ResolutionRejectionReason::TrustCardRevoked);
    }
    if candidate.trust_status == TrustCardStatus::Quarantined {
        return Some(ResolutionRejectionReason::TrustCardQuarantined);
    }
    if candidate.revocation_freshness == RevocationFreshness::Revoked {
        return Some(ResolutionRejectionReason::RevocationRevoked);
    }
    if candidate.bpet_risk == RiskTier::Critical || candidate.dgis_risk == RiskTier::Critical {
        return Some(ResolutionRejectionReason::CriticalRisk);
    }
    if candidate.compat_status == CompatibilityStatus::Divergent {
        return Some(ResolutionRejectionReason::CompatibilityDivergent);
    }

    match profile {
        AdmissionProfile::Strict => {
            let strict_ok = candidate.trust_status == TrustCardStatus::Trusted
                && candidate.bpet_risk <= RiskTier::Moderate
                && candidate.dgis_risk <= RiskTier::Moderate
                && candidate.revocation_freshness == RevocationFreshness::Fresh
                && candidate.compat_status == CompatibilityStatus::Compatible;
            (!strict_ok).then_some(ResolutionRejectionReason::ProfilePolicy)
        }
        AdmissionProfile::Balanced => {
            let balanced_ok = matches!(
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
                );
            (!balanced_ok).then_some(ResolutionRejectionReason::ProfilePolicy)
        }
        AdmissionProfile::LegacyRisky => {
            let legacy_ok = candidate.bpet_risk <= RiskTier::High
                && candidate.dgis_risk <= RiskTier::High
                && candidate.compat_status != CompatibilityStatus::Divergent;
            (!legacy_ok).then_some(ResolutionRejectionReason::ProfilePolicy)
        }
    }
}

fn aggregate_evidence_refs<'a>(
    candidates: impl Iterator<Item = &'a CandidateAssessment>,
    profile: AdmissionProfile,
) -> ResolutionReceiptResult<ResolutionEvidenceRefs> {
    let mut trust_card_refs = BTreeSet::new();
    let mut bpet_risk_refs = BTreeSet::new();
    let mut dgis_risk_refs = BTreeSet::new();
    let mut revocation_freshness_refs = BTreeSet::new();
    let mut compat_oracle_refs = BTreeSet::new();
    let mut capability_budget_refs = BTreeSet::new();
    for candidate in candidates {
        trust_card_refs.insert(candidate.trust_card_ref.as_str());
        bpet_risk_refs.insert(candidate.bpet_risk_ref.as_str());
        dgis_risk_refs.insert(candidate.dgis_risk_ref.as_str());
        revocation_freshness_refs.insert(candidate.revocation_freshness_ref.as_str());
        compat_oracle_refs.insert(candidate.compat_oracle_ref.as_str());
        capability_budget_refs.insert(candidate.capability_budget_ref.as_str());
    }
    let evidence = ResolutionEvidenceRefs {
        trust_card_refs: refs_to_strings(trust_card_refs),
        bpet_risk_refs: refs_to_strings(bpet_risk_refs),
        dgis_risk_refs: refs_to_strings(dgis_risk_refs),
        revocation_freshness_refs: refs_to_strings(revocation_freshness_refs),
        compat_oracle_refs: refs_to_strings(compat_oracle_refs),
        capability_budget_refs: refs_to_strings(capability_budget_refs),
        policy_refs: vec![
            format!("policy-profile:{}", profile.as_str()),
            format!("schema:{RESOLUTION_RECEIPT_SCHEMA}"),
        ],
    };
    validate_evidence_refs(&evidence)?;
    Ok(evidence)
}

fn refs_to_strings(refs: BTreeSet<&str>) -> Vec<String> {
    refs.into_iter().map(str::to_string).collect()
}

fn canonical_payload_bytes(receipt: &ResolutionReceipt) -> ResolutionReceiptResult<Vec<u8>> {
    canonical_json_bytes(&ResolutionReceiptPayload {
        schema_version: &receipt.schema_version,
        receipt_id: &receipt.receipt_id,
        issued_at_millis: receipt.issued_at_millis,
        module_graph_hash: &receipt.module_graph_hash,
        package_name: &receipt.package_name,
        requested_range: &receipt.requested_range,
        policy_profile: receipt.policy_profile,
        decision: receipt.decision,
        selected_version: &receipt.selected_version,
        rejected_alternatives: &receipt.rejected_alternatives,
        evidence_refs: &receipt.evidence_refs,
        rationale: &receipt.rationale,
    })
}

fn canonical_json_bytes(value: &impl Serialize) -> ResolutionReceiptResult<Vec<u8>> {
    let value = serde_json::to_value(value)?;
    let canonical = canonicalize_value(value);
    serde_json::to_vec(&canonical).map_err(ResolutionReceiptError::Json)
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
    let canonical = canonical_resolution_receipt_bytes(receipt)?;
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
    use subtle::ConstantTimeEq as _;
    left.as_bytes().ct_eq(right.as_bytes()).into()
}
