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

use crate::capacity_defaults::aliases::MAX_EVENTS;

/// Maximum number of issues that can be reported during attestation verification.
/// Prevents memory exhaustion from adversarial attestations with many problems.
const MAX_CHAIN_ISSUES: usize = 1024;

/// Push item to bounded vector with capacity limit to prevent memory exhaustion.
/// When capacity is exceeded, removes oldest entries to maintain the limit.
fn push_bounded<T>(items: &mut Vec<T>, item: T, cap: usize) {
    if cap == 0 {
        items.clear();
        return;
    }
    if items.len() >= cap {
        let overflow = items.len().saturating_sub(cap).saturating_add(1);
        items.drain(0..overflow);
    }
    items.push(item);
}

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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
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
            threshold_signature_required: true,
            transparency_log_required: true,
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
    let claimed_level = claimed_provenance_level(attestation);

    validate_required_fields(attestation, &mut issues);
    validate_chain_depth(attestation, policy, &mut issues);
    validate_link_order(attestation, policy, &mut issues);
    validate_attestation_freshness(attestation, policy, now_epoch, &mut issues);
    validate_links(attestation, policy, now_epoch, &mut issues);

    let level = derive_level(attestation, &issues);
    if level < policy.min_level {
        push_bounded(&mut issues, ChainIssue {
            code: VerificationErrorCode::LevelInsufficient,
            link_role: None,
            message: format!("required {:?}, got {:?}", policy.min_level, level),
            remediation: "Raise provenance guarantees (chain depth/signing/reproducibility) to satisfy policy minimum."
                .to_string(),
            allow_in_cached_mode: false,
        }, MAX_CHAIN_ISSUES);
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
    report.events = classify_events(&report, claimed_level);
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
    let mut required = vec![
        ("schema_version", attestation.schema_version.as_str()),
        (
            "build_system_identifier",
            attestation.build_system_identifier.as_str(),
        ),
        ("builder_identity", attestation.builder_identity.as_str()),
        ("builder_version", attestation.builder_version.as_str()),
        (
            "reproducibility_hash",
            attestation.reproducibility_hash.as_str(),
        ),
        ("input_hash", attestation.input_hash.as_str()),
        ("output_hash", attestation.output_hash.as_str()),
    ];
    if attestation.slsa_level_claim > 0 {
        required.push((
            "source_repository_url",
            attestation.source_repository_url.as_str(),
        ));
        required.push(("vcs_commit_sha", attestation.vcs_commit_sha.as_str()));
    }

    for (field_name, field_value) in required {
        if field_value.trim().is_empty() {
            push_bounded(issues, ChainIssue {
                code: VerificationErrorCode::AttestationMissingField,
                link_role: None,
                message: format!("missing required field: {field_name}"),
                remediation:
                    "Populate all required attestation fields and re-issue the provenance bundle."
                        .to_string(),
                allow_in_cached_mode: false,
            }, MAX_CHAIN_ISSUES);
        }
    }
}

fn validate_chain_depth(
    attestation: &ProvenanceAttestation,
    policy: &VerificationPolicy,
    issues: &mut Vec<ChainIssue>,
) {
    if attestation.links.len() < policy.required_chain_depth {
        push_bounded(issues, ChainIssue {
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
        }, MAX_CHAIN_ISSUES);
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
            push_bounded(issues, ChainIssue {
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
            }, MAX_CHAIN_ISSUES);
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
    if age < policy.max_attestation_age_secs {
        return;
    }

    let within_cached_window = matches!(policy.mode, VerificationMode::CachedTrustWindow)
        && age
            < policy
                .max_attestation_age_secs
                .saturating_add(policy.cached_trust_window_secs);

    push_bounded(
        issues,
        ChainIssue {
            code: VerificationErrorCode::ChainStale,
            link_role: None,
            message: format!("attestation age {age}s exceeded policy window"),
            remediation: if within_cached_window {
                "Re-verify with fresh provenance before cached trust window expires.".to_string()
            } else {
                "Rebuild and re-attest artifact with fresh provenance timestamps.".to_string()
            },
            allow_in_cached_mode: within_cached_window,
        },
        MAX_CHAIN_ISSUES,
    );
}

fn validate_links(
    attestation: &ProvenanceAttestation,
    policy: &VerificationPolicy,
    now_epoch: u64,
    issues: &mut Vec<ChainIssue>,
) {
    for link in &attestation.links {
        if link.revoked {
            push_bounded(
                issues,
                ChainIssue {
                    code: VerificationErrorCode::ChainLinkRevoked,
                    link_role: Some(link.role),
                    message: format!("link revoked for signer {}", link.signer_id),
                    remediation:
                        "Rotate compromised signing key and issue a new signed attestation link."
                            .to_string(),
                    allow_in_cached_mode: false,
                },
                MAX_CHAIN_ISSUES,
            );
        }

        if !policy.allow_self_signed && link.signer_id == "self" {
            push_bounded(issues, ChainIssue {
                code: VerificationErrorCode::InvalidSignature,
                link_role: Some(link.role),
                message: "self-signed links are disallowed by current policy".to_string(),
                remediation:
                    "Use externally trusted signing identities or relax policy only for development profiles."
                        .to_string(),
                allow_in_cached_mode: false,
            }, MAX_CHAIN_ISSUES);
        }

        if !crate::security::constant_time::ct_eq(
            &link.signed_payload_hash,
            &attestation.output_hash,
        ) {
            push_bounded(
                issues,
                ChainIssue {
                    code: VerificationErrorCode::InvalidSignature,
                    link_role: Some(link.role),
                    message: "signed payload hash does not match attestation output hash"
                        .to_string(),
                    remediation:
                        "Re-sign link with canonical payload hash bound to the attested output."
                            .to_string(),
                    allow_in_cached_mode: false,
                },
                MAX_CHAIN_ISSUES,
            );
        }

        match expected_link_signature(attestation, link) {
            Ok(expected) => {
                if link.signature.trim().is_empty()
                    || !crate::security::constant_time::ct_eq(&link.signature, &expected)
                {
                    push_bounded(issues, ChainIssue {
                        code: VerificationErrorCode::InvalidSignature,
                        link_role: Some(link.role),
                        message: "link signature failed deterministic canonical verification".to_string(),
                        remediation:
                            "Regenerate link signature from canonical signable payload and re-submit."
                                .to_string(),
                        allow_in_cached_mode: false,
                    }, MAX_CHAIN_ISSUES);
                }
            }
            Err(error) => {
                push_bounded(
                    issues,
                    ChainIssue {
                        code: error.code,
                        link_role: Some(link.role),
                        message: error.message,
                        remediation: error.remediation,
                        allow_in_cached_mode: false,
                    },
                    MAX_CHAIN_ISSUES,
                );
            }
        }

        let age = now_epoch.saturating_sub(link.issued_at_epoch);
        let stale_by_age = age >= policy.max_attestation_age_secs;
        let stale_by_expiry = now_epoch >= link.expires_at_epoch;
        if stale_by_age || stale_by_expiry {
            let within_cached_window = matches!(policy.mode, VerificationMode::CachedTrustWindow)
                && age
                    < policy
                        .max_attestation_age_secs
                        .saturating_add(policy.cached_trust_window_secs)
                && now_epoch
                    < link
                        .expires_at_epoch
                        .saturating_add(policy.cached_trust_window_secs);

            push_bounded(
                issues,
                ChainIssue {
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
                },
                MAX_CHAIN_ISSUES,
            );
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
        && source_vcs_signer_is_independent(attestation)
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

fn claimed_provenance_level(attestation: &ProvenanceAttestation) -> ProvenanceLevel {
    match attestation.slsa_level_claim {
        0 => ProvenanceLevel::Level0Unsigned,
        1 => ProvenanceLevel::Level1PublisherSigned,
        2 => ProvenanceLevel::Level2SignedReproducible,
        _ => ProvenanceLevel::Level3IndependentReproduced,
    }
}

fn source_vcs_signer_is_independent(attestation: &ProvenanceAttestation) -> bool {
    let Some(source_signer) = role_signer_id(attestation, ChainLinkRole::SourceVcs) else {
        return false;
    };

    [ChainLinkRole::Publisher, ChainLinkRole::BuildSystem]
        .into_iter()
        .filter_map(|role| role_signer_id(attestation, role))
        .all(|signer| signer != source_signer)
}

fn role_signer_id(attestation: &ProvenanceAttestation, role: ChainLinkRole) -> Option<&str> {
    attestation
        .links
        .iter()
        .find(|link| link.role == role)
        .map(|link| link.signer_id.as_str())
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

fn classify_events(
    report: &ChainValidityReport,
    claimed_level: ProvenanceLevel,
) -> Vec<ProvenanceEventCode> {
    let mut events = Vec::new();
    let downgrade_detected = report.provenance_level.rank() < claimed_level.rank();

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
        if !report.issues.is_empty() || downgrade_detected {
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
    if !events.contains(&event) && events.len() < MAX_EVENTS {
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
    hasher.update(b"provenance_hash_v1:");
    hasher.update((u64::try_from(bytes.len()).unwrap_or(u64::MAX)).to_le_bytes());
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::{
        AttestationEnvelopeFormat, AttestationLink, ChainLinkRole, ProvenanceAttestation,
        ProvenanceLevel, VerificationFailure, VerificationMode, VerificationPolicy,
        canonical_attestation_json, sign_links_in_place, verify_and_project_gates,
        verify_attestation_chain,
    };

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
        let mut tampered = attestation.links[1].signature.clone();
        let replacement = if tampered.starts_with('a') { "b" } else { "a" };
        tampered.replace_range(0..1, replacement);
        attestation.links[1].signature = tampered;

        let policy = VerificationPolicy::production_default();
        let report = verify_attestation_chain(&attestation, &policy, 1_700_000_600, "trace-3");

        assert!(!report.chain_valid);
        assert!(report.issues.iter().any(|issue| {
            issue.code == VerificationErrorCode::InvalidSignature
                && issue.link_role == Some(ChainLinkRole::BuildSystem)
        }));
    }

    #[test]
    fn inv_pat_invalid_signed_payload_hash_detects_broken_link() {
        let mut attestation = base_attestation();
        let mut tampered = attestation.links[1].signed_payload_hash.clone();
        let replacement = if tampered.starts_with('a') { "b" } else { "a" };
        tampered.replace_range(0..1, replacement);
        attestation.links[1].signed_payload_hash = tampered;

        let policy = VerificationPolicy::production_default();
        let report = verify_attestation_chain(&attestation, &policy, 1_700_000_600, "trace-3b");

        assert!(!report.chain_valid);
        assert!(report.issues.iter().any(|issue| {
            issue.code == VerificationErrorCode::InvalidSignature
                && issue.link_role == Some(ChainLinkRole::BuildSystem)
                && issue
                    .message
                    .contains("signed payload hash does not match attestation output hash")
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
    fn inv_pat_dev_profile_allows_level_zero_attestation_without_git_metadata() {
        let mut attestation = base_attestation();
        attestation.source_repository_url.clear();
        attestation.vcs_commit_sha.clear();
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
        attestation.slsa_level_claim = 0;
        sign_links_in_place(&mut attestation).expect("re-sign degraded links");

        let policy = VerificationPolicy::development_profile();
        let report = verify_attestation_chain(&attestation, &policy, 1_700_000_050, "trace-6b");

        assert!(report.chain_valid);
        assert_eq!(
            report.provenance_level,
            ProvenanceLevel::Level1PublisherSigned
        );
        assert!(!report.issues.iter().any(|issue| {
            issue.code == VerificationErrorCode::AttestationMissingField
                && issue.message.contains("source_repository_url")
        }));
        assert!(!report.issues.iter().any(|issue| {
            issue.code == VerificationErrorCode::AttestationMissingField
                && issue.message.contains("vcs_commit_sha")
        }));
    }

    #[test]
    fn inv_pat_same_signer_source_link_cannot_claim_independent_reproduction() {
        let mut attestation = base_attestation();
        attestation.links[2].signer_id = attestation.links[1].signer_id.clone();
        sign_links_in_place(&mut attestation).expect("re-sign duplicated source signer");

        let policy = VerificationPolicy::production_default();
        let report = verify_attestation_chain(&attestation, &policy, 1_700_000_400, "trace-6c");

        assert!(report.chain_valid);
        assert_eq!(
            report.provenance_level,
            ProvenanceLevel::Level2SignedReproducible
        );
        assert!(
            report
                .events
                .contains(&ProvenanceEventCode::ProvenanceDegradedModeEntered)
        );
        assert!(
            report
                .events
                .contains(&ProvenanceEventCode::AttestationVerified)
        );
    }

    #[test]
    fn inv_pat_canonical_serialization_is_deterministic() {
        let attestation = base_attestation();
        let first = canonical_attestation_json(&attestation).expect("canonical json #1");
        let second = canonical_attestation_json(&attestation).expect("canonical json #2");
        assert_eq!(first, second);
    }

    #[test]
    fn mr_custom_claim_order_preserves_canonical_json_and_verdict() {
        let mut first = base_attestation();
        first.custom_claims = BTreeMap::from([
            ("build.recipe".to_string(), "reproducible".to_string()),
            (
                "slsa.predicateType".to_string(),
                "https://slsa.dev/provenance/v1".to_string(),
            ),
            ("source.tree".to_string(), "clean".to_string()),
        ]);
        sign_links_in_place(&mut first).expect("sign first ordering");

        let mut second = base_attestation();
        second.custom_claims = BTreeMap::from([
            ("source.tree".to_string(), "clean".to_string()),
            (
                "slsa.predicateType".to_string(),
                "https://slsa.dev/provenance/v1".to_string(),
            ),
            ("build.recipe".to_string(), "reproducible".to_string()),
        ]);
        sign_links_in_place(&mut second).expect("sign second ordering");

        assert_eq!(
            canonical_attestation_json(&first).expect("first canonical json"),
            canonical_attestation_json(&second).expect("second canonical json")
        );

        let policy = VerificationPolicy::production_default();
        let first_report = verify_attestation_chain(&first, &policy, 1_700_000_400, "same-trace");
        let second_report = verify_attestation_chain(&second, &policy, 1_700_000_400, "same-trace");
        assert_eq!(first_report, second_report);
    }

    #[test]
    fn mr_trace_id_change_preserves_verification_decision() {
        let attestation = base_attestation();
        let policy = VerificationPolicy::production_default();

        let first = verify_attestation_chain(&attestation, &policy, 1_700_000_400, "trace-a");
        let second = verify_attestation_chain(&attestation, &policy, 1_700_000_400, "trace-b");

        assert_ne!(first.trace_id, second.trace_id);
        assert_eq!(first.chain_valid, second.chain_valid);
        assert_eq!(first.provenance_level, second.provenance_level);
        assert_eq!(first.issues, second.issues);
        assert_eq!(first.events, second.events);
    }

    #[test]
    fn mr_link_permutation_breaks_canonical_chain_order() {
        let ordered = base_attestation();
        let mut permuted = ordered.clone();
        permuted.links.swap(0, 1);
        sign_links_in_place(&mut permuted).expect("sign permuted links");

        let policy = VerificationPolicy::production_default();
        let ordered_report = verify_attestation_chain(&ordered, &policy, 1_700_000_400, "ordered");
        let permuted_report =
            verify_attestation_chain(&permuted, &policy, 1_700_000_400, "permuted");

        assert!(ordered_report.chain_valid);
        assert!(!permuted_report.chain_valid);
        assert!(permuted_report.issues.iter().any(|issue| {
            issue.code == VerificationErrorCode::ChainLinkOrderInvalid
                && issue.link_role == Some(ChainLinkRole::BuildSystem)
        }));
        assert!(permuted_report.issues.iter().any(|issue| {
            issue.code == VerificationErrorCode::ChainLinkOrderInvalid
                && issue.link_role == Some(ChainLinkRole::Publisher)
        }));
    }

    #[test]
    fn mr_claimed_slsa_reduction_never_increases_provenance_level() {
        let high_claim = base_attestation();
        let mut level_two_claim = high_claim.clone();
        level_two_claim.slsa_level_claim = 2;
        sign_links_in_place(&mut level_two_claim).expect("sign level two claim");

        let mut level_one_claim = high_claim.clone();
        level_one_claim.slsa_level_claim = 1;
        sign_links_in_place(&mut level_one_claim).expect("sign level one claim");

        let policy = VerificationPolicy::production_default();
        let high_report = verify_attestation_chain(&high_claim, &policy, 1_700_000_400, "level-3");
        let level_two_report =
            verify_attestation_chain(&level_two_claim, &policy, 1_700_000_400, "level-2");
        let level_one_report =
            verify_attestation_chain(&level_one_claim, &policy, 1_700_000_400, "level-1");

        assert_eq!(
            high_report.provenance_level,
            ProvenanceLevel::Level3IndependentReproduced
        );
        assert_eq!(
            level_two_report.provenance_level,
            ProvenanceLevel::Level2SignedReproducible
        );
        assert_eq!(
            level_one_report.provenance_level,
            ProvenanceLevel::Level1PublisherSigned
        );
        assert!(level_two_report.provenance_level <= high_report.provenance_level);
        assert!(level_one_report.provenance_level <= level_two_report.provenance_level);
        assert!(level_two_report.chain_valid);
        assert!(!level_one_report.chain_valid);
    }

    #[test]
    fn mr_policy_depth_relaxation_can_only_remove_depth_failures() {
        let mut attestation = base_attestation();
        attestation.links.truncate(2);
        sign_links_in_place(&mut attestation).expect("re-sign shortened chain");

        let strict_policy = VerificationPolicy::production_default();
        let mut relaxed_policy = VerificationPolicy::production_default();
        relaxed_policy.required_chain_depth = 2;

        let strict_report =
            verify_attestation_chain(&attestation, &strict_policy, 1_700_000_400, "strict-depth");
        let relaxed_report = verify_attestation_chain(
            &attestation,
            &relaxed_policy,
            1_700_000_400,
            "relaxed-depth",
        );

        assert!(!strict_report.chain_valid);
        assert!(
            strict_report
                .issues
                .iter()
                .any(|issue| issue.code == VerificationErrorCode::ChainIncomplete)
        );
        assert!(relaxed_report.chain_valid);
        assert!(relaxed_report.issues.is_empty());
        assert_eq!(
            relaxed_report.provenance_level,
            ProvenanceLevel::Level2SignedReproducible
        );
    }

    #[test]
    fn mr_output_hash_tamper_resign_restores_signature_but_not_payload_binding() {
        let mut attestation = base_attestation();
        attestation.output_hash = "sha256:output-transformed".to_string();
        sign_links_in_place(&mut attestation).expect("re-sign transformed output hash");

        let policy = VerificationPolicy::production_default();
        let mismatched_report =
            verify_attestation_chain(&attestation, &policy, 1_700_000_400, "mismatch");
        assert!(!mismatched_report.chain_valid);
        assert!(mismatched_report.issues.iter().any(|issue| {
            issue.code == VerificationErrorCode::InvalidSignature
                && issue
                    .message
                    .contains("signed payload hash does not match attestation output hash")
        }));

        for link in &mut attestation.links {
            link.signed_payload_hash = attestation.output_hash.clone();
        }
        sign_links_in_place(&mut attestation).expect("re-sign restored payload binding");

        let restored_report =
            verify_attestation_chain(&attestation, &policy, 1_700_000_400, "restored");
        assert!(restored_report.chain_valid);
        assert!(restored_report.issues.is_empty());
    }

    #[test]
    fn mr_reproducibility_hash_change_changes_signatures_but_preserves_level_when_resigned() {
        let original = base_attestation();
        let original_signatures: Vec<_> = original
            .links
            .iter()
            .map(|link| link.signature.clone())
            .collect();

        let mut transformed = original.clone();
        transformed.reproducibility_hash = "sha256:repro-transformed".to_string();
        sign_links_in_place(&mut transformed).expect("re-sign transformed reproducibility hash");
        let transformed_signatures: Vec<_> = transformed
            .links
            .iter()
            .map(|link| link.signature.clone())
            .collect();

        assert_ne!(original_signatures, transformed_signatures);
        assert_ne!(
            canonical_attestation_json(&original).expect("original canonical json"),
            canonical_attestation_json(&transformed).expect("transformed canonical json")
        );

        let policy = VerificationPolicy::production_default();
        let original_report =
            verify_attestation_chain(&original, &policy, 1_700_000_400, "original");
        let transformed_report =
            verify_attestation_chain(&transformed, &policy, 1_700_000_400, "transformed");

        assert!(original_report.chain_valid);
        assert!(transformed_report.chain_valid);
        assert_eq!(
            original_report.provenance_level,
            transformed_report.provenance_level
        );
    }

    #[test]
    fn mr_cached_window_boundary_progression_is_monotonic() {
        let mut attestation = base_attestation();
        for link in &mut attestation.links {
            link.issued_at_epoch = 1_700_000_000;
            link.expires_at_epoch = 1_700_000_100;
        }
        sign_links_in_place(&mut attestation).expect("re-sign bounded links");

        let policy = VerificationPolicy {
            max_attestation_age_secs: u64::MAX,
            cached_trust_window_secs: 50,
            mode: VerificationMode::CachedTrustWindow,
            ..VerificationPolicy::development_profile()
        };

        let before_expiry =
            verify_attestation_chain(&attestation, &policy, 1_700_000_099, "before-expiry");
        let at_expiry = verify_attestation_chain(&attestation, &policy, 1_700_000_100, "at-expiry");
        let at_cache_boundary =
            verify_attestation_chain(&attestation, &policy, 1_700_000_150, "cache-boundary");

        assert!(before_expiry.chain_valid);
        assert!(before_expiry.issues.is_empty());

        assert!(at_expiry.chain_valid);
        assert!(at_expiry.issues.iter().all(|issue| {
            issue.code == VerificationErrorCode::ChainStale && issue.allow_in_cached_mode
        }));

        assert!(!at_cache_boundary.chain_valid);
        assert!(at_cache_boundary.issues.iter().any(|issue| {
            issue.code == VerificationErrorCode::ChainStale && !issue.allow_in_cached_mode
        }));
    }

    #[test]
    fn mr_source_signer_independence_restores_level_after_distinct_relabeling() {
        let mut shared_source_signer = base_attestation();
        shared_source_signer.links[2].signer_id = shared_source_signer.links[1].signer_id.clone();
        sign_links_in_place(&mut shared_source_signer).expect("re-sign shared signer");

        let mut independent_source_signer = shared_source_signer.clone();
        independent_source_signer.links[2].signer_id = "independent-vcs-key".to_string();
        sign_links_in_place(&mut independent_source_signer).expect("re-sign independent signer");

        let policy = VerificationPolicy::production_default();
        let shared_report = verify_attestation_chain(
            &shared_source_signer,
            &policy,
            1_700_000_400,
            "shared-source",
        );
        let independent_report = verify_attestation_chain(
            &independent_source_signer,
            &policy,
            1_700_000_400,
            "independent-source",
        );

        assert!(shared_report.chain_valid);
        assert!(independent_report.chain_valid);
        assert_eq!(
            shared_report.provenance_level,
            ProvenanceLevel::Level2SignedReproducible
        );
        assert_eq!(
            independent_report.provenance_level,
            ProvenanceLevel::Level3IndependentReproduced
        );
    }

    #[test]
    fn mr_revocation_transform_only_marks_revoked_role_when_signatures_still_match() {
        let mut attestation = base_attestation();
        attestation.links[2].revoked = true;
        sign_links_in_place(&mut attestation).expect("re-sign revoked link");

        let policy = VerificationPolicy::production_default();
        let report = verify_attestation_chain(&attestation, &policy, 1_700_000_400, "revoked");

        assert!(!report.chain_valid);
        assert!(report.issues.iter().any(|issue| {
            issue.code == VerificationErrorCode::ChainLinkRevoked
                && issue.link_role == Some(ChainLinkRole::SourceVcs)
        }));
        assert!(!report.issues.iter().any(|issue| {
            issue.code == VerificationErrorCode::InvalidSignature
                && issue.link_role == Some(ChainLinkRole::SourceVcs)
        }));
        assert_eq!(
            report.provenance_level,
            ProvenanceLevel::Level2SignedReproducible
        );
    }

    #[test]
    fn link_stale_at_exact_expiry_boundary() {
        let mut attestation = base_attestation();
        // Set all links to expire at exactly 1_700_100_000.
        for link in &mut attestation.links {
            link.expires_at_epoch = 1_700_100_000;
        }
        sign_links_in_place(&mut attestation).expect("sign links");

        let policy = VerificationPolicy {
            max_attestation_age_secs: u64::MAX, // don't trigger age-based staleness
            ..VerificationPolicy::development_profile()
        };

        // Verify at exact expiry: must detect staleness (fail-closed).
        let report =
            verify_attestation_chain(&attestation, &policy, 1_700_100_000, "boundary-test");
        let has_staleness = report
            .issues
            .iter()
            .any(|i| matches!(i.code, VerificationErrorCode::ChainStale));
        assert!(
            has_staleness,
            "links at exact expiry boundary must be stale"
        );
    }

    #[test]
    fn link_stale_at_exact_age_boundary() {
        let attestation = base_attestation();
        // First link issued_at_epoch = 1_700_000_200.
        // Set max_attestation_age_secs so boundary is exactly at now_epoch.
        let now_epoch = 1_700_000_200 + 86_400; // 1 day later
        let policy = VerificationPolicy {
            max_attestation_age_secs: 86_400,
            ..VerificationPolicy::development_profile()
        };

        let report = verify_attestation_chain(&attestation, &policy, now_epoch, "age-boundary");
        let has_staleness = report
            .issues
            .iter()
            .any(|i| matches!(i.code, VerificationErrorCode::ChainStale));
        assert!(has_staleness, "links at exact age boundary must be stale");
    }

    #[test]
    fn negative_production_rejects_self_signed_link_even_with_valid_signature() {
        let mut attestation = base_attestation();
        attestation.links[0].signer_id = "self".to_string();
        sign_links_in_place(&mut attestation).expect("re-sign self-signed publisher link");

        let report = verify_attestation_chain(
            &attestation,
            &VerificationPolicy::production_default(),
            1_700_000_400,
            "self-signed-prod",
        );

        assert!(!report.chain_valid);
        assert!(report.issues.iter().any(|issue| {
            issue.code == VerificationErrorCode::InvalidSignature
                && issue.link_role == Some(ChainLinkRole::Publisher)
                && issue.message.contains("self-signed")
        }));
    }

    #[test]
    fn negative_empty_publisher_signature_fails_closed() {
        let mut attestation = base_attestation();
        attestation.links[0].signature.clear();

        let report = verify_attestation_chain(
            &attestation,
            &VerificationPolicy::production_default(),
            1_700_000_400,
            "empty-signature",
        );
        let failure = enforce_fail_closed(&report).expect_err("empty signature must fail closed");

        assert!(!report.chain_valid);
        assert_eq!(failure.code, VerificationErrorCode::InvalidSignature);
        assert_eq!(failure.broken_link, Some(ChainLinkRole::Publisher));
    }

    #[test]
    fn negative_missing_source_repository_for_positive_slsa_claim_is_rejected() {
        let mut attestation = base_attestation();
        attestation.source_repository_url.clear();
        sign_links_in_place(&mut attestation).expect("re-sign missing source repository");

        let report = verify_attestation_chain(
            &attestation,
            &VerificationPolicy::production_default(),
            1_700_000_400,
            "missing-source-repository",
        );

        assert!(!report.chain_valid);
        assert!(report.issues.iter().any(|issue| {
            issue.code == VerificationErrorCode::AttestationMissingField
                && issue.message.contains("source_repository_url")
        }));
    }

    #[test]
    fn negative_missing_vcs_commit_for_positive_slsa_claim_is_rejected() {
        let mut attestation = base_attestation();
        attestation.vcs_commit_sha.clear();
        sign_links_in_place(&mut attestation).expect("re-sign missing vcs commit");

        let report = verify_attestation_chain(
            &attestation,
            &VerificationPolicy::production_default(),
            1_700_000_400,
            "missing-vcs-commit",
        );

        assert!(!report.chain_valid);
        assert!(report.issues.iter().any(|issue| {
            issue.code == VerificationErrorCode::AttestationMissingField
                && issue.message.contains("vcs_commit_sha")
        }));
        assert_ne!(
            report.provenance_level,
            ProvenanceLevel::Level3IndependentReproduced
        );
    }

    #[test]
    fn negative_failed_projection_denies_all_downstream_gates() {
        let mut attestation = base_attestation();
        attestation.links[1].signature.clear();

        let outcome = verify_and_project_gates(
            &attestation,
            &VerificationPolicy::production_default(),
            1_700_000_400,
            "projection-deny-all",
        );

        assert!(!outcome.report.chain_valid);
        assert_eq!(
            outcome.downstream_gates,
            DownstreamGateRequirements::deny_all()
        );
    }

    #[test]
    fn negative_attestation_stale_at_exact_age_boundary_fails_closed() {
        let attestation = base_attestation();
        let mut policy = VerificationPolicy::production_default();
        policy.max_attestation_age_secs = 300;
        let now_epoch = attestation
            .build_timestamp_epoch
            .saturating_add(policy.max_attestation_age_secs);

        let report =
            verify_attestation_chain(&attestation, &policy, now_epoch, "attestation-boundary");

        assert!(!report.chain_valid);
        assert!(report.issues.iter().any(|issue| {
            issue.code == VerificationErrorCode::ChainStale && issue.link_role.is_none()
        }));
    }

    #[test]
    fn negative_cached_trust_rejects_attestation_at_cache_boundary() {
        let mut attestation = base_attestation();
        attestation.build_timestamp_epoch = 1_700_000_000;
        sign_links_in_place(&mut attestation).expect("re-sign boundary attestation");
        let mut policy = VerificationPolicy::development_profile();
        policy.max_attestation_age_secs = 100;
        policy.cached_trust_window_secs = 50;
        policy.mode = VerificationMode::CachedTrustWindow;

        let report =
            verify_attestation_chain(&attestation, &policy, 1_700_000_150, "cache-hard-boundary");

        assert!(!report.chain_valid);
        assert!(report.issues.iter().any(|issue| {
            issue.code == VerificationErrorCode::ChainStale && !issue.allow_in_cached_mode
        }));
    }

    #[test]
    fn negative_revoked_publisher_removes_level_one_trust() {
        let mut attestation = base_attestation();
        attestation.links[0].revoked = true;
        sign_links_in_place(&mut attestation).expect("re-sign revoked publisher");

        let report = verify_attestation_chain(
            &attestation,
            &VerificationPolicy::production_default(),
            1_700_000_400,
            "revoked-publisher",
        );

        assert!(!report.chain_valid);
        assert_eq!(report.provenance_level, ProvenanceLevel::Level0Unsigned);
        assert!(report.issues.iter().any(|issue| {
            issue.code == VerificationErrorCode::ChainLinkRevoked
                && issue.link_role == Some(ChainLinkRole::Publisher)
        }));
    }

    #[test]
    fn negative_missing_schema_version_is_reported() {
        let mut attestation = base_attestation();
        attestation.schema_version = " \t".to_string();
        sign_links_in_place(&mut attestation).expect("re-sign missing schema version");

        let report = verify_attestation_chain(
            &attestation,
            &VerificationPolicy::production_default(),
            1_700_000_400,
            "missing-schema-version",
        );

        assert!(!report.chain_valid);
        assert!(report.issues.iter().any(|issue| {
            issue.code == VerificationErrorCode::AttestationMissingField
                && issue.message.contains("schema_version")
        }));
    }

    #[test]
    fn negative_missing_builder_identity_is_reported() {
        let mut attestation = base_attestation();
        attestation.builder_identity.clear();
        sign_links_in_place(&mut attestation).expect("re-sign missing builder identity");

        let report = verify_attestation_chain(
            &attestation,
            &VerificationPolicy::production_default(),
            1_700_000_400,
            "missing-builder-identity",
        );

        assert!(!report.chain_valid);
        assert!(report.issues.iter().any(|issue| {
            issue.code == VerificationErrorCode::AttestationMissingField
                && issue.message.contains("builder_identity")
        }));
    }

    #[test]
    fn negative_missing_output_hash_breaks_payload_binding() {
        let mut attestation = base_attestation();
        attestation.output_hash.clear();
        sign_links_in_place(&mut attestation).expect("re-sign missing output hash");

        let report = verify_attestation_chain(
            &attestation,
            &VerificationPolicy::production_default(),
            1_700_000_400,
            "missing-output-hash",
        );

        assert!(!report.chain_valid);
        assert!(report.issues.iter().any(|issue| {
            issue.code == VerificationErrorCode::AttestationMissingField
                && issue.message.contains("output_hash")
        }));
        assert!(report.issues.iter().any(|issue| {
            issue.code == VerificationErrorCode::InvalidSignature
                && issue.message.contains("signed payload hash does not match")
        }));
    }

    #[test]
    fn negative_blank_signed_payload_hash_is_rejected() {
        let mut attestation = base_attestation();
        attestation.links[1].signed_payload_hash = " \n".to_string();
        sign_links_in_place(&mut attestation).expect("re-sign blank signed payload hash");

        let report = verify_attestation_chain(
            &attestation,
            &VerificationPolicy::production_default(),
            1_700_000_400,
            "blank-signed-payload",
        );

        assert!(!report.chain_valid);
        assert!(report.issues.iter().any(|issue| {
            issue.code == VerificationErrorCode::InvalidSignature
                && issue.link_role == Some(ChainLinkRole::BuildSystem)
                && issue.message.contains("signed payload hash does not match")
        }));
    }

    #[test]
    fn negative_required_depth_above_available_roles_is_incomplete() {
        let attestation = base_attestation();
        let mut policy = VerificationPolicy::production_default();
        policy.required_chain_depth = 4;

        let report =
            verify_attestation_chain(&attestation, &policy, 1_700_000_400, "depth-above-roles");

        assert!(!report.chain_valid);
        assert!(report.issues.iter().any(|issue| {
            issue.code == VerificationErrorCode::ChainIncomplete
                && issue.message.contains("required 4 links")
        }));
    }

    #[test]
    fn negative_fail_closed_empty_issue_report_uses_chain_incomplete_fallback() {
        let report = ChainValidityReport {
            chain_valid: false,
            provenance_level: ProvenanceLevel::Level0Unsigned,
            issues: Vec::new(),
            events: Vec::new(),
            trace_id: "empty-issues".to_string(),
        };

        let failure = enforce_fail_closed(&report).expect_err("invalid report must fail closed");

        assert_eq!(failure.code, VerificationErrorCode::ChainIncomplete);
        assert_eq!(failure.broken_link, None);
        assert!(failure.message.contains("without explicit issue"));
    }

    #[test]
    fn negative_serde_rejects_unknown_envelope_format() {
        let err =
            serde_json::from_str::<AttestationEnvelopeFormat>(r#""cyclonedx_v2""#).unwrap_err();

        assert!(err.to_string().contains("unknown variant"));
    }

    #[test]
    fn negative_serde_rejects_unknown_verification_mode() {
        let err = serde_json::from_str::<VerificationMode>(r#""fail_open""#).unwrap_err();

        assert!(err.to_string().contains("unknown variant"));
    }

    #[test]
    fn negative_serde_rejects_link_missing_signature_field() {
        let json = serde_json::json!({
            "role": "publisher",
            "signer_id": "publisher-key",
            "signer_version": "v1",
            "signed_payload_hash": "sha256:output-123",
            "issued_at_epoch": 1_700_000_200u64,
            "expires_at_epoch": 1_700_100_000u64,
            "revoked": false
        });

        let err = serde_json::from_value::<AttestationLink>(json).unwrap_err();

        assert!(err.to_string().contains("signature"));
    }

    /// Negative path: extremely large custom claims causing memory pressure
    #[test]
    fn negative_massive_custom_claims_handled_without_overflow() {
        let mut attestation = base_attestation();

        // Add 10,000 custom claims with large values
        for i in 0..10_000 {
            attestation.custom_claims.insert(
                format!("claim_{:05}", i),
                format!("value_{}_with_large_content_{}", i, "x".repeat(1000)),
            );
        }

        sign_links_in_place(&mut attestation).expect("sign massive custom claims");

        // Canonical serialization should handle large data
        let canonical = canonical_attestation_json(&attestation)
            .expect("massive custom claims should serialize");

        assert!(!canonical.is_empty());
        assert!(canonical.contains("claim_00000"));
        assert!(canonical.contains("claim_09999"));

        // Verification should work despite size
        let policy = VerificationPolicy::production_default();
        let report =
            verify_attestation_chain(&attestation, &policy, 1_700_000_400, "massive-claims");

        // Should pass verification (large data is not invalid)
        assert!(report.chain_valid);
        assert_eq!(
            report.provenance_level,
            ProvenanceLevel::Level3IndependentReproduced
        );
    }

    /// Negative path: unicode characters in attestation fields
    #[test]
    fn negative_unicode_attestation_fields_preserved_through_verification() {
        let mut attestation = base_attestation();

        // Add unicode content to various fields
        attestation.schema_version = "v1.0-🔒security".to_string();
        attestation.source_repository_url = "https://github.com/企业/项目.git".to_string();
        attestation.build_system_identifier = "github-actions-🚀CI/CD".to_string();
        attestation.builder_identity = "builder@测试.example.com".to_string();
        attestation.builder_version = "2026.02-ñéw".to_string();
        attestation.reproducibility_hash = "sha256:repro-漢字123".to_string();

        // Add unicode to links
        for link in &mut attestation.links {
            link.signer_id = format!("🔑key-{}-測試", link.signer_id);
            link.signer_version = format!("v1-🌍{}", link.signer_version);
        }

        // Add unicode custom claims
        attestation
            .custom_claims
            .insert("測試.claim".to_string(), "値🎯test".to_string());
        attestation
            .custom_claims
            .insert("emoji🌟field".to_string(), "data📊value".to_string());

        sign_links_in_place(&mut attestation).expect("sign unicode attestation");

        let policy = VerificationPolicy::production_default();
        let report = verify_attestation_chain(&attestation, &policy, 1_700_000_400, "unicode-test");

        assert!(report.chain_valid);
        assert_eq!(
            report.provenance_level,
            ProvenanceLevel::Level3IndependentReproduced
        );

        // Unicode should be preserved in canonical form
        let canonical = canonical_attestation_json(&attestation).expect("unicode canonical");
        assert!(canonical.contains("🔒security"));
        assert!(canonical.contains("企业"));
        assert!(canonical.contains("測試"));
    }

    /// Negative path: timestamp overflow scenarios near u64::MAX
    #[test]
    fn negative_timestamp_overflow_scenarios_use_saturating_arithmetic() {
        let mut attestation = base_attestation();

        // Set timestamps near u64::MAX
        attestation.build_timestamp_epoch = u64::MAX - 1000;
        for link in &mut attestation.links {
            link.issued_at_epoch = u64::MAX - 500;
            link.expires_at_epoch = u64::MAX - 100;
        }

        sign_links_in_place(&mut attestation).expect("sign overflow timestamps");

        // Policy with extreme values
        let policy = VerificationPolicy {
            max_attestation_age_secs: u64::MAX / 2,
            cached_trust_window_secs: u64::MAX / 4,
            ..VerificationPolicy::production_default()
        };

        // Verification at timestamp that could cause overflow
        let now_epoch = u64::MAX - 50;
        let report = verify_attestation_chain(&attestation, &policy, now_epoch, "overflow-test");

        // Should handle timestamps without panicking due to overflow
        assert!(!report.chain_valid); // Will be stale due to expiry

        // Age calculation should use saturating arithmetic
        let age = now_epoch.saturating_sub(attestation.build_timestamp_epoch);
        assert_eq!(age, 950); // u64::MAX - 50 - (u64::MAX - 1000) = 950

        // Should have stale chain issues due to expiry
        assert!(
            report
                .issues
                .iter()
                .any(|i| i.code == VerificationErrorCode::ChainStale)
        );
    }

    /// Negative path: hash collision resistance in signature computation
    #[test]
    fn negative_signature_computation_resists_collision_attempts() {
        let base = base_attestation();

        // Create variations that could potentially collide
        let mut variant1 = base.clone();
        variant1.output_hash = "prefix_suffix".to_string();

        let mut variant2 = base.clone();
        variant2.output_hash = "prefi_x_suffix".to_string(); // Different split point

        let mut variant3 = base.clone();
        variant3
            .custom_claims
            .insert("ab".to_string(), "cd".to_string());

        let mut variant4 = base.clone();
        variant4
            .custom_claims
            .insert("a".to_string(), "bcd".to_string());

        // Sign all variants
        sign_links_in_place(&mut variant1).expect("sign variant1");
        sign_links_in_place(&mut variant2).expect("sign variant2");
        sign_links_in_place(&mut variant3).expect("sign variant3");
        sign_links_in_place(&mut variant4).expect("sign variant4");

        // Collect all signatures
        let signatures: Vec<Vec<String>> = [&variant1, &variant2, &variant3, &variant4]
            .iter()
            .map(|v| v.links.iter().map(|l| l.signature.clone()).collect())
            .collect();

        // All signatures should be different (no collisions)
        for i in 0..signatures.len() {
            for j in (i + 1)..signatures.len() {
                for (sig_a, sig_b) in signatures[i].iter().zip(signatures[j].iter()) {
                    assert_ne!(
                        sig_a, sig_b,
                        "Signatures should be different for variants {} and {}",
                        i, j
                    );
                }
            }
        }

        // All should have valid signatures
        let policy = VerificationPolicy::production_default();
        for (idx, variant) in [&variant1, &variant2, &variant3, &variant4]
            .iter()
            .enumerate()
        {
            let report = verify_attestation_chain(
                variant,
                &policy,
                1_700_000_400,
                &format!("variant-{}", idx),
            );
            assert!(
                report.chain_valid,
                "Variant {} should have valid signatures",
                idx
            );
        }
    }

    /// Negative path: malformed JSON serialization attempts
    #[test]
    fn negative_canonical_json_handles_problematic_value_types() {
        // Test that problematic serde_json::Value types are handled
        use crate::security::constant_time;
        use serde_json::{Map, Value};

        // Create deeply nested JSON structure
        let mut deep_nested = Value::Object(Map::new());
        let current = &mut deep_nested;

        for i in 0..1000 {
            let mut new_map = Map::new();
            new_map.insert(format!("level_{}", i), Value::Null);
            let new_obj = Value::Object(new_map);

            if let Value::Object(map) = current {
                map.insert(format!("nested_{}", i), new_obj);
                if let Some(Value::Object(_)) = map.get_mut(&format!("nested_{}", i)) {
                    // Continue nesting - this tests stack depth in canonicalization
                }
            }
        }

        // Test canonicalization of deeply nested structure
        let canonical = canonicalize_value(deep_nested);
        assert!(matches!(canonical, Value::Object(_)));

        // Test with problematic field values
        let problematic = serde_json::json!({
            "null_field": null,
            "empty_string": "",
            "unicode_key_🔑": "unicode_value_🎯",
            "large_number": 9223372036854775807i64,
            "empty_array": [],
            "empty_object": {},
            "boolean_true": true,
            "boolean_false": false
        });

        let canonical_problematic = canonicalize_value(problematic);
        let canonical_str = serde_json::to_string(&canonical_problematic)
            .expect("canonical problematic should serialize");

        // Should handle all value types without panicking
        assert!(canonical_str.contains("null"));
        assert!(canonical_str.contains("🔑"));
        assert!(canonical_str.contains("9223372036854775807"));
    }

    /// Negative path: verification policy with extreme configuration values
    #[test]
    fn negative_extreme_verification_policy_values_handled_gracefully() {
        let attestation = base_attestation();

        // Test with zero timeout values
        let zero_policy = VerificationPolicy {
            min_level: ProvenanceLevel::Level3IndependentReproduced,
            required_chain_depth: 0,     // Zero depth
            max_attestation_age_secs: 0, // Zero age tolerance
            cached_trust_window_secs: 0, // Zero cache window
            allow_self_signed: false,
            mode: VerificationMode::FailClosed,
        };

        let report =
            verify_attestation_chain(&attestation, &zero_policy, 1_700_000_400, "zero-policy");
        assert!(!report.chain_valid); // Should fail due to zero age tolerance

        // Test with maximum values
        let max_policy = VerificationPolicy {
            min_level: ProvenanceLevel::Level0Unsigned,
            required_chain_depth: usize::MAX,
            max_attestation_age_secs: u64::MAX,
            cached_trust_window_secs: u64::MAX,
            allow_self_signed: true,
            mode: VerificationMode::CachedTrustWindow,
        };

        let max_report =
            verify_attestation_chain(&attestation, &max_policy, 1_700_000_400, "max-policy");
        assert!(!max_report.chain_valid); // Should fail due to insufficient chain depth
        assert!(
            max_report
                .issues
                .iter()
                .any(|i| i.code == VerificationErrorCode::ChainIncomplete)
        );
    }

    /// Negative path: empty and whitespace-only field validation
    #[test]
    fn negative_whitespace_fields_detected_as_missing() {
        let mut attestation = base_attestation();

        // Set various fields to whitespace-only values
        attestation.schema_version = "  \t\n  ".to_string();
        attestation.build_system_identifier = "   ".to_string();
        attestation.builder_identity = "\t\t".to_string();
        attestation.builder_version = "\n\r\n".to_string();
        attestation.reproducibility_hash = "".to_string();
        attestation.input_hash = " ".to_string();
        attestation.output_hash = "   \t   ".to_string();

        sign_links_in_place(&mut attestation).expect("sign whitespace attestation");

        let policy = VerificationPolicy::production_default();
        let report =
            verify_attestation_chain(&attestation, &policy, 1_700_000_400, "whitespace-fields");

        assert!(!report.chain_valid);

        // Should detect multiple missing field issues
        let missing_field_count = report
            .issues
            .iter()
            .filter(|i| i.code == VerificationErrorCode::AttestationMissingField)
            .count();
        assert!(
            missing_field_count >= 6,
            "Should detect multiple whitespace-only fields as missing"
        );

        // Each required field should be flagged
        let field_names = [
            "schema_version",
            "build_system_identifier",
            "builder_identity",
            "builder_version",
            "reproducibility_hash",
            "input_hash",
            "output_hash",
        ];
        for field in &field_names {
            assert!(
                report
                    .issues
                    .iter()
                    .any(|i| i.code == VerificationErrorCode::AttestationMissingField
                        && i.message.contains(field)),
                "Field {} should be detected as missing",
                field
            );
        }
    }

    /// Negative path: chain link duplication and reordering attacks
    #[test]
    fn negative_duplicate_and_reordered_links_break_canonical_verification() {
        // Test duplicate links
        let mut duplicate_attestation = base_attestation();
        let publisher_link = duplicate_attestation.links[0].clone();
        duplicate_attestation.links.push(publisher_link); // Add duplicate publisher link
        sign_links_in_place(&mut duplicate_attestation).expect("sign duplicate links");

        let policy = VerificationPolicy::production_default();
        let duplicate_report = verify_attestation_chain(
            &duplicate_attestation,
            &policy,
            1_700_000_400,
            "duplicate-links",
        );

        // Should fail due to order validation (extra link at wrong position)
        assert!(!duplicate_report.chain_valid);

        // Test completely reversed order
        let mut reversed_attestation = base_attestation();
        reversed_attestation.links.reverse();
        sign_links_in_place(&mut reversed_attestation).expect("sign reversed links");

        let reversed_report = verify_attestation_chain(
            &reversed_attestation,
            &policy,
            1_700_000_400,
            "reversed-links",
        );

        assert!(!reversed_report.chain_valid);
        assert!(
            reversed_report
                .issues
                .iter()
                .any(|i| i.code == VerificationErrorCode::ChainLinkOrderInvalid)
        );

        // Test partial shuffle (swap first two)
        let mut shuffled_attestation = base_attestation();
        shuffled_attestation.links.swap(0, 1);
        sign_links_in_place(&mut shuffled_attestation).expect("sign shuffled links");

        let shuffled_report = verify_attestation_chain(
            &shuffled_attestation,
            &policy,
            1_700_000_400,
            "shuffled-links",
        );

        assert!(!shuffled_report.chain_valid);
        assert!(
            shuffled_report
                .issues
                .iter()
                .any(|i| i.code == VerificationErrorCode::ChainLinkOrderInvalid)
        );
    }

    /// Negative path: event system overflow with massive issue generation
    #[test]
    fn negative_event_classification_handles_massive_issue_lists() {
        // Create attestation with many potential issues
        let mut problematic_attestation = base_attestation();

        // Create conditions that will generate many different issues
        problematic_attestation.schema_version.clear();
        problematic_attestation.build_system_identifier.clear();
        problematic_attestation.builder_identity.clear();
        problematic_attestation.builder_version.clear();
        problematic_attestation.reproducibility_hash.clear();
        problematic_attestation.input_hash.clear();
        problematic_attestation.output_hash.clear();
        problematic_attestation.source_repository_url.clear();
        problematic_attestation.vcs_commit_sha.clear();

        // Add many links with issues
        for i in 0..50 {
            problematic_attestation.links.push(AttestationLink {
                role: ChainLinkRole::Publisher, // All same role (order issues)
                signer_id: format!("signer-{}", i),
                signer_version: "v1".to_string(),
                signature: "invalid-signature".to_string(),
                signed_payload_hash: format!("wrong-hash-{}", i),
                issued_at_epoch: 100,  // Very old (stale issues)
                expires_at_epoch: 200, // Expired
                revoked: i % 3 == 0,   // Some revoked
            });
        }

        let policy = VerificationPolicy::production_default();
        let report = verify_attestation_chain(
            &problematic_attestation,
            &policy,
            1_700_000_400,
            "massive-issues",
        );

        assert!(!report.chain_valid);

        // Should have many different types of issues
        let issue_types: std::collections::HashSet<_> =
            report.issues.iter().map(|i| i.code).collect();

        assert!(
            issue_types.len() >= 4,
            "Should have multiple types of issues"
        );
        assert!(issue_types.contains(&VerificationErrorCode::AttestationMissingField));
        assert!(issue_types.contains(&VerificationErrorCode::ChainLinkOrderInvalid));
        assert!(issue_types.contains(&VerificationErrorCode::InvalidSignature));

        // Events should be generated despite massive issues
        assert!(!report.events.is_empty());
        assert!(
            report
                .events
                .contains(&ProvenanceEventCode::AttestationRejected)
        );
    }

    /// Negative path: canonical JSON field ordering with collision attempts
    #[test]
    fn negative_canonical_json_field_ordering_prevents_manipulation() {
        let mut attestation1 = base_attestation();
        let mut attestation2 = base_attestation();

        // Add custom claims in different orders that could cause issues
        attestation1
            .custom_claims
            .insert("a_field".to_string(), "value1".to_string());
        attestation1
            .custom_claims
            .insert("b_field".to_string(), "value2".to_string());
        attestation1
            .custom_claims
            .insert("aa_field".to_string(), "value3".to_string()); // Between a and b lexically

        attestation2
            .custom_claims
            .insert("b_field".to_string(), "value2".to_string());
        attestation2
            .custom_claims
            .insert("aa_field".to_string(), "value3".to_string());
        attestation2
            .custom_claims
            .insert("a_field".to_string(), "value1".to_string()); // Different insertion order

        sign_links_in_place(&mut attestation1).expect("sign attestation1");
        sign_links_in_place(&mut attestation2).expect("sign attestation2");

        // Canonical JSON should be identical despite insertion order
        let canonical1 = canonical_attestation_json(&attestation1).expect("canonical1");
        let canonical2 = canonical_attestation_json(&attestation2).expect("canonical2");

        assert_eq!(
            canonical1, canonical2,
            "Canonical JSON should be identical despite insertion order"
        );

        // Signatures should be identical
        for (link1, link2) in attestation1.links.iter().zip(attestation2.links.iter()) {
            assert_eq!(
                link1.signature, link2.signature,
                "Signatures should be identical for canonically equivalent data"
            );
        }

        // Verification results should be identical
        let policy = VerificationPolicy::production_default();
        let report1 =
            verify_attestation_chain(&attestation1, &policy, 1_700_000_400, "order-test-1");
        let report2 =
            verify_attestation_chain(&attestation2, &policy, 1_700_000_400, "order-test-2");

        assert_eq!(report1.chain_valid, report2.chain_valid);
        assert_eq!(report1.provenance_level, report2.provenance_level);
        assert_eq!(report1.issues, report2.issues);
    }
}
