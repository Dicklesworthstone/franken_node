//! Provenance attestation requirements and verification chain (bd-1ah).
//!
//! This module defines:
//! - canonical provenance attestation data model
//! - deterministic signature material for chain links
//! - fail-closed verification with structured reason/remediation
//! - degraded-mode cached trust window behavior
//! - projection into 10.13 downstream trust gates

use std::cmp::Ordering;
use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

/// Canonical attestation envelope formats accepted by franken_node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationEnvelopeFormat {
    InToto,
    FrankenNodeEnvelopeV1,
}

/// Provenance levels mapped to policy admission gates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProvenanceLevel {
    Level0Unsigned,
    Level1PublisherSigned,
    Level2SignedReproducible,
    Level3IndependentReproduced,
}

impl ProvenanceLevel {
    #[must_use]
    pub fn rank(self) -> u8 {
        match self {
            Self::Level0Unsigned => 0,
            Self::Level1PublisherSigned => 1,
            Self::Level2SignedReproducible => 2,
            Self::Level3IndependentReproduced => 3,
        }
    }
}

impl Ord for ProvenanceLevel {
    fn cmp(&self, other: &Self) -> Ordering {
        self.rank().cmp(&other.rank())
    }
}

impl PartialOrd for ProvenanceLevel {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Transitive attestation chain roles in canonical order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChainLinkRole {
    Publisher,
    BuildSystem,
    SourceVcs,
}

impl ChainLinkRole {
    #[must_use]
    pub fn expected_order() -> &'static [ChainLinkRole] {
        &[
            ChainLinkRole::Publisher,
            ChainLinkRole::BuildSystem,
            ChainLinkRole::SourceVcs,
        ]
    }
}

/// A single signed attestation link in the transitive chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationLink {
    pub role: ChainLinkRole,
    pub signer_id: String,
    pub signer_version: String,
    pub signature: String,
    pub signed_payload_hash: String,
    pub issued_at_epoch: u64,
    pub expires_at_epoch: u64,
    pub revoked: bool,
}

/// Full provenance attestation submitted with extension artifacts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvenanceAttestation {
    pub schema_version: String,
    pub source_repository_url: String,
    pub build_system_identifier: String,
    pub builder_identity: String,
    pub builder_version: String,
    pub vcs_commit_sha: String,
    pub build_timestamp_epoch: u64,
    pub reproducibility_hash: String,
    pub input_hash: String,
    pub output_hash: String,
    pub slsa_level_claim: u8,
    pub envelope_format: AttestationEnvelopeFormat,
    pub links: Vec<AttestationLink>,
    pub custom_claims: BTreeMap<String, String>,
}

/// Verification mode policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationMode {
    FailClosed,
    CachedTrustWindow,
}

/// Verification policy gates for attestation admission.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationPolicy {
    pub min_level: ProvenanceLevel,
    pub required_chain_depth: usize,
    pub max_attestation_age_secs: u64,
    pub cached_trust_window_secs: u64,
    pub allow_self_signed: bool,
    pub mode: VerificationMode,
}

impl VerificationPolicy {
    #[must_use]
    pub fn production_default() -> Self {
        Self {
            min_level: ProvenanceLevel::Level2SignedReproducible,
            required_chain_depth: 3,
            max_attestation_age_secs: 24 * 60 * 60,
            cached_trust_window_secs: 0,
            allow_self_signed: false,
            mode: VerificationMode::FailClosed,
        }
    }

    #[must_use]
    pub fn development_profile() -> Self {
        Self {
            min_level: ProvenanceLevel::Level1PublisherSigned,
            required_chain_depth: 1,
            max_attestation_age_secs: 7 * 24 * 60 * 60,
            cached_trust_window_secs: 30 * 60,
            allow_self_signed: true,
            mode: VerificationMode::CachedTrustWindow,
        }
    }
}

/// Stable reason codes for verification results and failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum VerificationErrorCode {
    AttestationMissingField,
    ChainIncomplete,
    ChainStale,
    ChainLinkRevoked,
    InvalidSignature,
    ChainLinkOrderInvalid,
    LevelInsufficient,
    CanonicalizationFailed,
}

/// Detailed chain issue emitted by verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainIssue {
    pub code: VerificationErrorCode,
    pub link_role: Option<ChainLinkRole>,
    pub message: String,
    pub remediation: String,
    pub allow_in_cached_mode: bool,
}

/// Structured fail-closed error payload for remediation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationFailure {
    pub code: VerificationErrorCode,
    pub broken_link: Option<ChainLinkRole>,
    pub message: String,
    pub remediation: String,
}

impl std::fmt::Display for VerificationFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(role) = self.broken_link {
            return write!(
                f,
                "{:?} ({role:?}): {} -- remediation: {}",
                self.code, self.message, self.remediation
            );
        }
        write!(
            f,
            "{:?}: {} -- remediation: {}",
            self.code, self.message, self.remediation
        )
    }
}

impl std::error::Error for VerificationFailure {}

/// Structured event codes for provenance verification telemetry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProvenanceEventCode {
    AttestationVerified,
    AttestationRejected,
    ProvenanceLevelAssigned,
    ChainIncomplete,
    ChainStale,
    ProvenanceChainBroken,
    ProvenanceDegradedModeEntered,
}

/// Deterministic verification output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainValidityReport {
    pub chain_valid: bool,
    pub provenance_level: ProvenanceLevel,
    pub issues: Vec<ChainIssue>,
    pub events: Vec<ProvenanceEventCode>,
    pub trace_id: String,
}

/// Integration projection into 10.13 supply-chain gates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DownstreamGateRequirements {
    pub threshold_signature_required: bool,
    pub transparency_log_required: bool,
}

impl DownstreamGateRequirements {
    #[must_use]
    pub fn deny_all() -> Self {
        Self {
            threshold_signature_required: false,
            transparency_log_required: false,
        }
    }
}

/// Combined verifier result and projected 10.13 downstream gate requirements.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvenanceVerificationOutcome {
    pub report: ChainValidityReport,
    pub downstream_gates: DownstreamGateRequirements,
}

/// Produce a deterministic canonical JSON serialization of the full attestation.
pub fn canonical_attestation_json(
    attestation: &ProvenanceAttestation,
) -> Result<String, VerificationFailure> {
    canonical_json(attestation)
}

/// Deterministically sign all links in-place using the canonical signable payload.
pub fn sign_links_in_place(
    attestation: &mut ProvenanceAttestation,
) -> Result<(), VerificationFailure> {
    for idx in 0..attestation.links.len() {
        let signature = expected_link_signature(attestation, &attestation.links[idx])?;
        attestation.links[idx].signature = signature;
    }
    Ok(())
}

/// Verify provenance attestation and return deterministic report.
#[must_use]
pub fn verify_attestation_chain(
    attestation: &ProvenanceAttestation,
    policy: &VerificationPolicy,
    now_epoch: u64,
    trace_id: &str,
) -> ChainValidityReport {
    let mut issues = Vec::new();

    validate_required_fields(attestation, &mut issues);
    validate_chain_depth(attestation, policy, &mut issues);
    validate_link_order(attestation, policy, &mut issues);
    validate_attestation_freshness(attestation, policy, now_epoch, &mut issues);
    validate_links(attestation, policy, now_epoch, &mut issues);

    let level = derive_level(attestation, &issues);
    if level < policy.min_level {
        issues.push(ChainIssue {
            code: VerificationErrorCode::LevelInsufficient,
            link_role: None,
            message: format!("required {:?}, got {:?}", policy.min_level, level),
            remediation: "Raise provenance guarantees (chain depth/signing/reproducibility) to satisfy policy minimum."
                .to_string(),
            allow_in_cached_mode: false,
        });
    }

    issues.sort_by(|a, b| {
        let code_cmp = format!("{:?}", a.code).cmp(&format!("{:?}", b.code));
        if code_cmp != Ordering::Equal {
            return code_cmp;
        }

        let role_cmp = format!("{:?}", a.link_role).cmp(&format!("{:?}", b.link_role));
        if role_cmp != Ordering::Equal {
            return role_cmp;
        }

        a.message.cmp(&b.message)
    });

    let chain_valid = chain_valid(policy, &issues);

    let mut report = ChainValidityReport {
        chain_valid,
        provenance_level: level,
        issues,
        events: Vec::new(),
        trace_id: trace_id.to_string(),
    };
    report.events = classify_events(&report);
    report
}

/// Verify provenance and map successful result into required 10.13 gates.
#[must_use]
pub fn verify_and_project_gates(
    attestation: &ProvenanceAttestation,
    policy: &VerificationPolicy,
    now_epoch: u64,
    trace_id: &str,
) -> ProvenanceVerificationOutcome {
    let report = verify_attestation_chain(attestation, policy, now_epoch, trace_id);
    let downstream_gates = if report.chain_valid {
        required_downstream_gates(report.provenance_level)
    } else {
        DownstreamGateRequirements::deny_all()
    };

    ProvenanceVerificationOutcome {
        report,
        downstream_gates,
    }
}

/// Enforce fail-closed behavior by converting the first issue into a structured error.
pub fn enforce_fail_closed(report: &ChainValidityReport) -> Result<(), VerificationFailure> {
    if report.chain_valid {
        return Ok(());
    }

    if let Some(issue) = report.issues.first() {
        return Err(VerificationFailure {
            code: issue.code,
            broken_link: issue.link_role,
            message: issue.message.clone(),
            remediation: issue.remediation.clone(),
        });
    }

    Err(VerificationFailure {
        code: VerificationErrorCode::ChainIncomplete,
        broken_link: None,
        message: "verification failed without explicit issue".to_string(),
        remediation:
            "Re-run verification with a complete attestation chain and inspect policy wiring."
                .to_string(),
    })
}

/// Map provenance level into downstream gate requirements consumed by 10.13 modules.
#[must_use]
pub fn required_downstream_gates(level: ProvenanceLevel) -> DownstreamGateRequirements {
    match level {
        ProvenanceLevel::Level0Unsigned => DownstreamGateRequirements {
            threshold_signature_required: false,
            transparency_log_required: false,
        },
        ProvenanceLevel::Level1PublisherSigned => DownstreamGateRequirements {
            threshold_signature_required: true,
            transparency_log_required: false,
        },
        ProvenanceLevel::Level2SignedReproducible
        | ProvenanceLevel::Level3IndependentReproduced => DownstreamGateRequirements {
            threshold_signature_required: true,
            transparency_log_required: true,
        },
    }
}

fn validate_required_fields(attestation: &ProvenanceAttestation, issues: &mut Vec<ChainIssue>) {
    let required = [
        ("schema_version", attestation.schema_version.as_str()),
        (
            "source_repository_url",
            attestation.source_repository_url.as_str(),
        ),
        (
            "build_system_identifier",
            attestation.build_system_identifier.as_str(),
        ),
        ("builder_identity", attestation.builder_identity.as_str()),
        ("builder_version", attestation.builder_version.as_str()),
        ("vcs_commit_sha", attestation.vcs_commit_sha.as_str()),
        (
            "reproducibility_hash",
            attestation.reproducibility_hash.as_str(),
        ),
        ("input_hash", attestation.input_hash.as_str()),
        ("output_hash", attestation.output_hash.as_str()),
    ];

    for (field_name, field_value) in required {
        if field_value.trim().is_empty() {
            issues.push(ChainIssue {
                code: VerificationErrorCode::AttestationMissingField,
                link_role: None,
                message: format!("missing required field: {field_name}"),
                remediation:
                    "Populate all required attestation fields and re-issue the provenance bundle."
                        .to_string(),
                allow_in_cached_mode: false,
            });
        }
    }
}

fn validate_chain_depth(
    attestation: &ProvenanceAttestation,
    policy: &VerificationPolicy,
    issues: &mut Vec<ChainIssue>,
) {
    if attestation.links.len() < policy.required_chain_depth {
        issues.push(ChainIssue {
            code: VerificationErrorCode::ChainIncomplete,
            link_role: None,
            message: format!(
                "required {} links, found {}",
                policy.required_chain_depth,
                attestation.links.len()
            ),
            remediation:
                "Provide full publisher -> build_system -> source_vcs attestation coverage for required depth."
                    .to_string(),
            allow_in_cached_mode: false,
        });
    }
}

fn validate_link_order(
    attestation: &ProvenanceAttestation,
    policy: &VerificationPolicy,
    issues: &mut Vec<ChainIssue>,
) {
    let expected = ChainLinkRole::expected_order();
    let checks = policy
        .required_chain_depth
        .min(expected.len())
        .min(attestation.links.len());

    for (index, expected_role) in expected.iter().copied().enumerate().take(checks) {
        let actual = attestation.links[index].role;
        if actual != expected_role {
            issues.push(ChainIssue {
                code: VerificationErrorCode::ChainLinkOrderInvalid,
                link_role: Some(actual),
                message: format!(
                    "expected role {:?} at index {index}, found {:?}",
                    expected_role, actual
                ),
                remediation:
                    "Reorder links to canonical transitive order: publisher, build_system, source_vcs."
                        .to_string(),
                allow_in_cached_mode: false,
            });
        }
    }
}

fn validate_attestation_freshness(
    attestation: &ProvenanceAttestation,
    policy: &VerificationPolicy,
    now_epoch: u64,
    issues: &mut Vec<ChainIssue>,
) {
    let age = now_epoch.saturating_sub(attestation.build_timestamp_epoch);
    if age <= policy.max_attestation_age_secs {
        return;
    }

    let within_cached_window = matches!(policy.mode, VerificationMode::CachedTrustWindow)
        && age
            <= policy
                .max_attestation_age_secs
                .saturating_add(policy.cached_trust_window_secs);

    issues.push(ChainIssue {
        code: VerificationErrorCode::ChainStale,
        link_role: None,
        message: format!("attestation age {age}s exceeded policy window"),
        remediation: if within_cached_window {
            "Re-verify with fresh provenance before cached trust window expires.".to_string()
        } else {
            "Rebuild and re-attest artifact with fresh provenance timestamps.".to_string()
        },
        allow_in_cached_mode: within_cached_window,
    });
}

fn validate_links(
    attestation: &ProvenanceAttestation,
    policy: &VerificationPolicy,
    now_epoch: u64,
    issues: &mut Vec<ChainIssue>,
) {
    for link in &attestation.links {
        if link.revoked {
            issues.push(ChainIssue {
                code: VerificationErrorCode::ChainLinkRevoked,
                link_role: Some(link.role),
                message: format!("link revoked for signer {}", link.signer_id),
                remediation:
                    "Rotate compromised signing key and issue a new signed attestation link."
                        .to_string(),
                allow_in_cached_mode: false,
            });
        }

        if !policy.allow_self_signed && link.signer_id == "self" {
            issues.push(ChainIssue {
                code: VerificationErrorCode::InvalidSignature,
                link_role: Some(link.role),
                message: "self-signed links are disallowed by current policy".to_string(),
                remediation:
                    "Use externally trusted signing identities or relax policy only for development profiles."
                        .to_string(),
                allow_in_cached_mode: false,
            });
        }

        if link.signed_payload_hash != attestation.output_hash {
            issues.push(ChainIssue {
                code: VerificationErrorCode::InvalidSignature,
                link_role: Some(link.role),
                message: "signed payload hash does not match attestation output hash".to_string(),
                remediation:
                    "Re-sign link with canonical payload hash bound to the attested output."
                        .to_string(),
                allow_in_cached_mode: false,
            });
        }

        match expected_link_signature(attestation, link) {
            Ok(expected) => {
                if link.signature.trim().is_empty() || link.signature != expected {
                    issues.push(ChainIssue {
                        code: VerificationErrorCode::InvalidSignature,
                        link_role: Some(link.role),
                        message: "link signature failed deterministic canonical verification".to_string(),
                        remediation:
                            "Regenerate link signature from canonical signable payload and re-submit."
                                .to_string(),
                        allow_in_cached_mode: false,
                    });
                }
            }
            Err(error) => {
                issues.push(ChainIssue {
                    code: error.code,
                    link_role: Some(link.role),
                    message: error.message,
                    remediation: error.remediation,
                    allow_in_cached_mode: false,
                });
            }
        }

        let age = now_epoch.saturating_sub(link.issued_at_epoch);
        let stale_by_age = age > policy.max_attestation_age_secs;
        let stale_by_expiry = now_epoch > link.expires_at_epoch;
        if stale_by_age || stale_by_expiry {
            let within_cached_window = matches!(policy.mode, VerificationMode::CachedTrustWindow)
                && age
                    <= policy
                        .max_attestation_age_secs
                        .saturating_add(policy.cached_trust_window_secs)
                && now_epoch
                    <= link
                        .expires_at_epoch
                        .saturating_add(policy.cached_trust_window_secs);

            issues.push(ChainIssue {
                code: VerificationErrorCode::ChainStale,
                link_role: Some(link.role),
                message: format!("link age {age}s exceeded policy window"),
                remediation: if within_cached_window {
                    "Cached trust window is active; refresh this link immediately to avoid hard rejection."
                        .to_string()
                } else {
                    "Link is stale outside tolerated window; re-attest with fresh timestamp and signature."
                        .to_string()
                },
                allow_in_cached_mode: within_cached_window,
            });
        }
    }
}

fn derive_level(attestation: &ProvenanceAttestation, issues: &[ChainIssue]) -> ProvenanceLevel {
    let publisher_ok = role_is_clean(attestation, issues, ChainLinkRole::Publisher);
    let build_ok = role_is_clean(attestation, issues, ChainLinkRole::BuildSystem)
        && !attestation.reproducibility_hash.trim().is_empty()
        && attestation.slsa_level_claim >= 2;
    let source_ok = role_is_clean(attestation, issues, ChainLinkRole::SourceVcs)
        && !attestation.vcs_commit_sha.trim().is_empty()
        && attestation.slsa_level_claim >= 3;

    if publisher_ok && build_ok && source_ok {
        ProvenanceLevel::Level3IndependentReproduced
    } else if publisher_ok && build_ok {
        ProvenanceLevel::Level2SignedReproducible
    } else if publisher_ok {
        ProvenanceLevel::Level1PublisherSigned
    } else {
        ProvenanceLevel::Level0Unsigned
    }
}

fn role_is_clean(
    attestation: &ProvenanceAttestation,
    issues: &[ChainIssue],
    role: ChainLinkRole,
) -> bool {
    let present = attestation.links.iter().any(|link| link.role == role);
    if !present {
        return false;
    }

    !issues.iter().any(|issue| {
        issue.link_role == Some(role)
            && matches!(
                issue.code,
                VerificationErrorCode::InvalidSignature
                    | VerificationErrorCode::ChainLinkRevoked
                    | VerificationErrorCode::ChainLinkOrderInvalid
            )
    })
}

fn chain_valid(policy: &VerificationPolicy, issues: &[ChainIssue]) -> bool {
    if issues.is_empty() {
        return true;
    }

    match policy.mode {
        VerificationMode::FailClosed => false,
        VerificationMode::CachedTrustWindow => issues.iter().all(|issue| {
            issue.code == VerificationErrorCode::ChainStale && issue.allow_in_cached_mode
        }),
    }
}

fn classify_events(report: &ChainValidityReport) -> Vec<ProvenanceEventCode> {
    let mut events = Vec::new();

    push_unique_event(&mut events, ProvenanceEventCode::ProvenanceLevelAssigned);

    if report
        .issues
        .iter()
        .any(|issue| issue.code == VerificationErrorCode::ChainIncomplete)
    {
        push_unique_event(&mut events, ProvenanceEventCode::ChainIncomplete);
    }

    if report
        .issues
        .iter()
        .any(|issue| issue.code == VerificationErrorCode::ChainStale)
    {
        push_unique_event(&mut events, ProvenanceEventCode::ChainStale);
    }

    if report.chain_valid {
        if !report.issues.is_empty() {
            push_unique_event(
                &mut events,
                ProvenanceEventCode::ProvenanceDegradedModeEntered,
            );
        }
        push_unique_event(&mut events, ProvenanceEventCode::AttestationVerified);
    } else {
        if !report.issues.is_empty() {
            push_unique_event(&mut events, ProvenanceEventCode::ProvenanceChainBroken);
        }
        push_unique_event(&mut events, ProvenanceEventCode::AttestationRejected);
    }

    events
}

fn push_unique_event(events: &mut Vec<ProvenanceEventCode>, event: ProvenanceEventCode) {
    if !events.contains(&event) {
        events.push(event);
    }
}

fn expected_link_signature(
    attestation: &ProvenanceAttestation,
    link: &AttestationLink,
) -> Result<String, VerificationFailure> {
    let payload = canonical_signable_payload(attestation, link)?;
    Ok(sha256_hex(payload.as_bytes()))
}

fn canonical_signable_payload(
    attestation: &ProvenanceAttestation,
    link: &AttestationLink,
) -> Result<String, VerificationFailure> {
    #[derive(Serialize)]
    struct SignablePayload<'a> {
        schema_version: &'a str,
        source_repository_url: &'a str,
        build_system_identifier: &'a str,
        builder_identity: &'a str,
        builder_version: &'a str,
        vcs_commit_sha: &'a str,
        build_timestamp_epoch: u64,
        reproducibility_hash: &'a str,
        input_hash: &'a str,
        output_hash: &'a str,
        slsa_level_claim: u8,
        envelope_format: AttestationEnvelopeFormat,
        custom_claims: &'a BTreeMap<String, String>,
        role: ChainLinkRole,
        signer_id: &'a str,
        signer_version: &'a str,
        signed_payload_hash: &'a str,
        issued_at_epoch: u64,
        expires_at_epoch: u64,
    }

    let payload = SignablePayload {
        schema_version: &attestation.schema_version,
        source_repository_url: &attestation.source_repository_url,
        build_system_identifier: &attestation.build_system_identifier,
        builder_identity: &attestation.builder_identity,
        builder_version: &attestation.builder_version,
        vcs_commit_sha: &attestation.vcs_commit_sha,
        build_timestamp_epoch: attestation.build_timestamp_epoch,
        reproducibility_hash: &attestation.reproducibility_hash,
        input_hash: &attestation.input_hash,
        output_hash: &attestation.output_hash,
        slsa_level_claim: attestation.slsa_level_claim,
        envelope_format: attestation.envelope_format,
        custom_claims: &attestation.custom_claims,
        role: link.role,
        signer_id: &link.signer_id,
        signer_version: &link.signer_version,
        signed_payload_hash: &link.signed_payload_hash,
        issued_at_epoch: link.issued_at_epoch,
        expires_at_epoch: link.expires_at_epoch,
    };

    canonical_json(&payload)
}

fn canonical_json(value: &impl Serialize) -> Result<String, VerificationFailure> {
    let serialized = serde_json::to_value(value).map_err(|error| VerificationFailure {
        code: VerificationErrorCode::CanonicalizationFailed,
        broken_link: None,
        message: format!("failed to serialize canonical JSON: {error}"),
        remediation:
            "Ensure attestation payload contains only serializable UTF-8 values before signing."
                .to_string(),
    })?;

    let canonical = canonicalize_value(serialized);
    serde_json::to_string(&canonical).map_err(|error| VerificationFailure {
        code: VerificationErrorCode::CanonicalizationFailed,
        broken_link: None,
        message: format!("failed to encode canonical JSON: {error}"),
        remediation: "Ensure canonicalized payload can be encoded to JSON deterministically."
            .to_string(),
    })
}

fn canonicalize_value(value: Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut entries: Vec<(String, Value)> = map.into_iter().collect();
            entries.sort_by(|a, b| a.0.cmp(&b.0));

            let mut canonical = serde_json::Map::with_capacity(entries.len());
            for (key, nested) in entries {
                canonical.insert(key, canonicalize_value(nested));
            }
            Value::Object(canonical)
        }
        Value::Array(values) => Value::Array(values.into_iter().map(canonicalize_value).collect()),
        other => other,
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_attestation() -> ProvenanceAttestation {
        let mut attestation = ProvenanceAttestation {
            schema_version: "1.0".to_string(),
            source_repository_url: "https://example.com/extensions/repo.git".to_string(),
            build_system_identifier: "github-actions".to_string(),
            builder_identity: "builder@example.com".to_string(),
            builder_version: "2026.02".to_string(),
            vcs_commit_sha: "aabbccddeeff00112233445566778899aabbccdd".to_string(),
            build_timestamp_epoch: 1_700_000_100,
            reproducibility_hash: "sha256:repro-123".to_string(),
            input_hash: "sha256:input-123".to_string(),
            output_hash: "sha256:output-123".to_string(),
            slsa_level_claim: 3,
            envelope_format: AttestationEnvelopeFormat::InToto,
            links: vec![
                AttestationLink {
                    role: ChainLinkRole::Publisher,
                    signer_id: "publisher-key".to_string(),
                    signer_version: "v1".to_string(),
                    signature: String::new(),
                    signed_payload_hash: "sha256:output-123".to_string(),
                    issued_at_epoch: 1_700_000_200,
                    expires_at_epoch: 1_700_100_000,
                    revoked: false,
                },
                AttestationLink {
                    role: ChainLinkRole::BuildSystem,
                    signer_id: "build-key".to_string(),
                    signer_version: "v1".to_string(),
                    signature: String::new(),
                    signed_payload_hash: "sha256:output-123".to_string(),
                    issued_at_epoch: 1_700_000_210,
                    expires_at_epoch: 1_700_100_000,
                    revoked: false,
                },
                AttestationLink {
                    role: ChainLinkRole::SourceVcs,
                    signer_id: "vcs-key".to_string(),
                    signer_version: "v1".to_string(),
                    signature: String::new(),
                    signed_payload_hash: "sha256:output-123".to_string(),
                    issued_at_epoch: 1_700_000_220,
                    expires_at_epoch: 1_700_100_000,
                    revoked: false,
                },
            ],
            custom_claims: BTreeMap::from([(
                "slsa.predicateType".to_string(),
                "https://slsa.dev/provenance/v1".to_string(),
            )]),
        };
        sign_links_in_place(&mut attestation).expect("sign links");
        attestation
    }

    #[test]
    fn inv_pat_full_chain_passes_and_projects_gates() {
        let policy = VerificationPolicy::production_default();
        let outcome =
            verify_and_project_gates(&base_attestation(), &policy, 1_700_000_400, "trace-1");

        assert!(outcome.report.chain_valid);
        assert_eq!(
            outcome.report.provenance_level,
            ProvenanceLevel::Level3IndependentReproduced
        );
        assert!(outcome.report.issues.is_empty());
        assert!(
            outcome
                .report
                .events
                .contains(&ProvenanceEventCode::AttestationVerified)
        );
        assert_eq!(
            outcome.downstream_gates,
            DownstreamGateRequirements {
                threshold_signature_required: true,
                transparency_log_required: true,
            }
        );
    }

    #[test]
    fn inv_pat_fail_closed_rejects_incomplete_chain() {
        let mut attestation = base_attestation();
        attestation.links.truncate(2);
        sign_links_in_place(&mut attestation).expect("re-sign truncated links");

        let policy = VerificationPolicy::production_default();
        let report = verify_attestation_chain(&attestation, &policy, 1_700_000_500, "trace-2");

        assert!(!report.chain_valid);
        assert!(
            report
                .issues
                .iter()
                .any(|issue| issue.code == VerificationErrorCode::ChainIncomplete)
        );
        let failure = enforce_fail_closed(&report).expect_err("must fail closed");
        assert_eq!(failure.code, VerificationErrorCode::ChainIncomplete);
    }

    #[test]
    fn inv_pat_invalid_signature_identifies_broken_link() {
        let mut attestation = base_attestation();
        attestation.links[1].signature = "tampered".to_string();

        let policy = VerificationPolicy::production_default();
        let report = verify_attestation_chain(&attestation, &policy, 1_700_000_600, "trace-3");

        assert!(!report.chain_valid);
        assert!(report.issues.iter().any(|issue| {
            issue.code == VerificationErrorCode::InvalidSignature
                && issue.link_role == Some(ChainLinkRole::BuildSystem)
        }));
    }

    #[test]
    fn inv_pat_cached_window_accepts_soft_stale_chain() {
        let mut attestation = base_attestation();
        attestation.build_timestamp_epoch = 960;
        for link in &mut attestation.links {
            link.issued_at_epoch = 960;
            link.expires_at_epoch = 970;
        }
        sign_links_in_place(&mut attestation).expect("re-sign stale links");

        let mut policy = VerificationPolicy::production_default();
        policy.mode = VerificationMode::CachedTrustWindow;
        policy.max_attestation_age_secs = 10;
        policy.cached_trust_window_secs = 100;

        let report = verify_attestation_chain(&attestation, &policy, 1_000, "trace-4");

        assert!(report.chain_valid);
        assert!(!report.issues.is_empty());
        assert!(
            report
                .issues
                .iter()
                .all(|issue| issue.code == VerificationErrorCode::ChainStale)
        );
        assert!(
            report
                .events
                .contains(&ProvenanceEventCode::ProvenanceDegradedModeEntered)
        );
    }

    #[test]
    fn inv_pat_fail_closed_rejects_hard_stale_chain() {
        let mut attestation = base_attestation();
        attestation.build_timestamp_epoch = 100;
        for link in &mut attestation.links {
            link.issued_at_epoch = 100;
            link.expires_at_epoch = 110;
        }
        sign_links_in_place(&mut attestation).expect("re-sign stale links");

        let mut policy = VerificationPolicy::production_default();
        policy.mode = VerificationMode::CachedTrustWindow;
        policy.max_attestation_age_secs = 10;
        policy.cached_trust_window_secs = 20;

        let report = verify_attestation_chain(&attestation, &policy, 1_000, "trace-5");
        assert!(!report.chain_valid);
        assert!(
            report
                .events
                .contains(&ProvenanceEventCode::AttestationRejected)
        );
    }

    #[test]
    fn inv_pat_dev_profile_allows_self_signed_single_link() {
        let mut attestation = base_attestation();
        attestation.links = vec![AttestationLink {
            role: ChainLinkRole::Publisher,
            signer_id: "self".to_string(),
            signer_version: "dev".to_string(),
            signature: String::new(),
            signed_payload_hash: attestation.output_hash.clone(),
            issued_at_epoch: 1_700_000_000,
            expires_at_epoch: 1_700_100_000,
            revoked: false,
        }];
        attestation.slsa_level_claim = 1;
        sign_links_in_place(&mut attestation).expect("re-sign self link");

        let policy = VerificationPolicy::development_profile();
        let report = verify_attestation_chain(&attestation, &policy, 1_700_000_050, "trace-6");

        assert!(report.chain_valid);
        assert_eq!(
            report.provenance_level,
            ProvenanceLevel::Level1PublisherSigned
        );
    }

    #[test]
    fn inv_pat_canonical_serialization_is_deterministic() {
        let attestation = base_attestation();
        let first = canonical_attestation_json(&attestation).expect("canonical json #1");
        let second = canonical_attestation_json(&attestation).expect("canonical json #2");
        assert_eq!(first, second);
    }
}
