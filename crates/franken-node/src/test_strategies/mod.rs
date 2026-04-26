//! Shared proptest strategies for reusable domain generators.
//!
//! New fuzz harnesses and proptest suites MUST use `test_strategies::*` unless
//! they deliberately exercise an out-of-distribution input class that these
//! canonical generators do not model.

use crate::observability::evidence_ledger::{DecisionKind, EvidenceEntry, test_entry};
use crate::security::impossible_default::{CapabilityToken, ImpossibleCapability};
use crate::supply_chain::certification::{DerivationMetadata, EvidenceType, VerifiedEvidenceRef};
use crate::supply_chain::trust_card::{
    AuditRecord, BehavioralProfile, CapabilityDeclaration, CapabilityRisk, CertificationLevel,
    DependencyTrustStatus, ExtensionIdentity, ProvenanceSummary, PublisherIdentity,
    ReputationTrend, RevocationStatus, RiskAssessment, RiskLevel, TrustCard,
};
use crate::tools::replay_bundle::{EventType, RawEvent};
use proptest::prelude::*;
use proptest::strategy::BoxedStrategy;
use serde_json::json;

#[cfg(any(test, feature = "test-support"))]
use crate::api::fleet_quarantine::{
    DecisionReceipt, DecisionReceiptPayload, DecisionReceiptSignature, QuarantineScope,
    RevocationScope, RevocationSeverity, canonical_decision_receipt_payload_hash,
};

fn bounded_text(max_len: usize) -> BoxedStrategy<String> {
    prop::collection::vec(any::<u8>(), 0..=max_len)
        .prop_map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
        .boxed()
}

fn ascii_identifier(max_len: usize) -> BoxedStrategy<String> {
    proptest::string::string_regex(&format!("[A-Za-z0-9._:-]{{1,{max_len}}}"))
        .expect("identifier regex should be valid")
        .boxed()
}

fn lowercase_identifier(max_len: usize) -> BoxedStrategy<String> {
    proptest::string::string_regex(&format!("[a-z0-9-]{{1,{max_len}}}"))
        .expect("lowercase identifier regex should be valid")
        .boxed()
}

fn rfc3339_timestamp() -> BoxedStrategy<String> {
    (1u8..=12, 1u8..=28, 0u8..=23, 0u8..=59, 0u8..=59, 0u16..=999)
        .prop_map(|(month, day, hour, minute, second, millis)| {
            format!("2026-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{millis:03}Z")
        })
        .boxed()
}

fn sha256_hash() -> BoxedStrategy<String> {
    prop::collection::vec(any::<u8>(), 32)
        .prop_map(|bytes| format!("sha256:{}", hex::encode(bytes)))
        .boxed()
}

fn hex_bytes(len: usize) -> BoxedStrategy<String> {
    prop::collection::vec(any::<u8>(), len)
        .prop_map(hex::encode)
        .boxed()
}

fn capability_risks() -> BoxedStrategy<CapabilityRisk> {
    prop_oneof![
        Just(CapabilityRisk::Low),
        Just(CapabilityRisk::Medium),
        Just(CapabilityRisk::High),
        Just(CapabilityRisk::Critical),
    ]
    .boxed()
}

fn certification_levels() -> BoxedStrategy<CertificationLevel> {
    prop_oneof![
        Just(CertificationLevel::Unknown),
        Just(CertificationLevel::Bronze),
        Just(CertificationLevel::Silver),
        Just(CertificationLevel::Gold),
        Just(CertificationLevel::Platinum),
    ]
    .boxed()
}

fn reputation_trends() -> BoxedStrategy<ReputationTrend> {
    prop_oneof![
        Just(ReputationTrend::Improving),
        Just(ReputationTrend::Stable),
        Just(ReputationTrend::Declining),
    ]
    .boxed()
}

fn risk_levels() -> BoxedStrategy<RiskLevel> {
    prop_oneof![
        Just(RiskLevel::Low),
        Just(RiskLevel::Medium),
        Just(RiskLevel::High),
        Just(RiskLevel::Critical),
    ]
    .boxed()
}

fn revocation_statuses() -> BoxedStrategy<RevocationStatus> {
    prop_oneof![
        Just(RevocationStatus::Active),
        (bounded_text(128), rfc3339_timestamp())
            .prop_map(|(reason, revoked_at)| { RevocationStatus::Revoked { reason, revoked_at } }),
    ]
    .boxed()
}

fn evidence_types() -> BoxedStrategy<EvidenceType> {
    prop_oneof![
        Just(EvidenceType::ProvenanceChain),
        Just(EvidenceType::ReputationSignal),
        Just(EvidenceType::TestCoverageReport),
        Just(EvidenceType::AuditReport),
        Just(EvidenceType::ManifestAdmission),
        Just(EvidenceType::RevocationCheck),
    ]
    .boxed()
}

fn impossible_capabilities() -> BoxedStrategy<ImpossibleCapability> {
    prop_oneof![
        Just(ImpossibleCapability::FsAccess),
        Just(ImpossibleCapability::OutboundNetwork),
        Just(ImpossibleCapability::ChildProcessSpawn),
        Just(ImpossibleCapability::UnsignedExtension),
        Just(ImpossibleCapability::DisableHardening),
    ]
    .boxed()
}

fn decision_kinds() -> BoxedStrategy<DecisionKind> {
    prop_oneof![
        Just(DecisionKind::Admit),
        Just(DecisionKind::Deny),
        Just(DecisionKind::Quarantine),
        Just(DecisionKind::Release),
        Just(DecisionKind::Rollback),
        Just(DecisionKind::Throttle),
        Just(DecisionKind::Escalate),
    ]
    .boxed()
}

fn event_types() -> BoxedStrategy<EventType> {
    prop_oneof![
        Just(EventType::StateChange),
        Just(EventType::PolicyEval),
        Just(EventType::ExternalSignal),
        Just(EventType::OperatorAction),
    ]
    .boxed()
}

#[cfg(any(test, feature = "test-support"))]
fn revocation_severities() -> BoxedStrategy<RevocationSeverity> {
    prop_oneof![
        Just(RevocationSeverity::Advisory),
        Just(RevocationSeverity::Mandatory),
        Just(RevocationSeverity::Emergency),
    ]
    .boxed()
}

fn trust_card_extension_identity() -> BoxedStrategy<ExtensionIdentity> {
    (lowercase_identifier(24), 0u8..=9, 0u8..=9, 0u8..=9)
        .prop_map(|(extension_id, major, minor, patch)| ExtensionIdentity {
            extension_id: format!("ext-{extension_id}"),
            version: format!("{major}.{minor}.{patch}"),
        })
        .boxed()
}

fn trust_card_publisher_identity() -> BoxedStrategy<PublisherIdentity> {
    lowercase_identifier(24)
        .prop_map(|publisher_id| PublisherIdentity {
            display_name: format!("Publisher {publisher_id}"),
            publisher_id,
        })
        .boxed()
}

fn capability_declarations() -> BoxedStrategy<CapabilityDeclaration> {
    (ascii_identifier(32), bounded_text(160), capability_risks())
        .prop_map(|(name, description, risk)| CapabilityDeclaration {
            name,
            description,
            risk,
        })
        .boxed()
}

fn behavioral_profiles() -> BoxedStrategy<BehavioralProfile> {
    (
        any::<bool>(),
        any::<bool>(),
        any::<bool>(),
        bounded_text(160),
    )
        .prop_map(
            |(network_access, filesystem_access, subprocess_access, profile_summary)| {
                BehavioralProfile {
                    network_access,
                    filesystem_access,
                    subprocess_access,
                    profile_summary,
                }
            },
        )
        .boxed()
}

fn provenance_summaries() -> BoxedStrategy<ProvenanceSummary> {
    (
        ascii_identifier(32),
        ascii_identifier(48),
        prop::collection::vec(sha256_hash(), 1..=3),
        rfc3339_timestamp(),
    )
        .prop_map(
            |(attestation_level, source_uri, artifact_hashes, verified_at)| ProvenanceSummary {
                attestation_level,
                source_uri: format!("https://example.invalid/{source_uri}"),
                artifact_hashes,
                verified_at,
            },
        )
        .boxed()
}

fn dependency_trust_statuses() -> BoxedStrategy<DependencyTrustStatus> {
    (ascii_identifier(32), ascii_identifier(16))
        .prop_map(|(dependency_id, trust_level)| DependencyTrustStatus {
            dependency_id,
            trust_level,
        })
        .boxed()
}

fn risk_assessments() -> BoxedStrategy<RiskAssessment> {
    (risk_levels(), bounded_text(192))
        .prop_map(|(level, summary)| RiskAssessment { level, summary })
        .boxed()
}

fn audit_records() -> BoxedStrategy<AuditRecord> {
    (
        rfc3339_timestamp(),
        ascii_identifier(24),
        bounded_text(192),
        ascii_identifier(48),
    )
        .prop_map(|(timestamp, event_code, detail, trace_id)| AuditRecord {
            timestamp,
            event_code,
            detail,
            trace_id,
        })
        .boxed()
}

fn verified_evidence_refs() -> BoxedStrategy<VerifiedEvidenceRef> {
    (
        ascii_identifier(32),
        evidence_types(),
        any::<u64>(),
        sha256_hash(),
    )
        .prop_map(
            |(evidence_id, evidence_type, verified_at_epoch, verification_receipt_hash)| {
                VerifiedEvidenceRef {
                    evidence_id,
                    evidence_type,
                    verified_at_epoch,
                    verification_receipt_hash,
                }
            },
        )
        .boxed()
}

fn derivation_metadata() -> BoxedStrategy<DerivationMetadata> {
    (
        prop::collection::vec(verified_evidence_refs(), 1..=3),
        any::<u64>(),
        sha256_hash(),
    )
        .prop_map(
            |(evidence_refs, derived_at_epoch, derivation_chain_hash)| DerivationMetadata {
                evidence_refs,
                derived_at_epoch,
                derivation_chain_hash,
            },
        )
        .boxed()
}

#[cfg(any(test, feature = "test-support"))]
fn quarantine_scopes() -> BoxedStrategy<QuarantineScope> {
    (
        ascii_identifier(32),
        prop::option::of(ascii_identifier(32)),
        any::<u32>(),
        bounded_text(160),
    )
        .prop_map(
            |(zone_id, tenant_id, affected_nodes, reason)| QuarantineScope {
                zone_id,
                tenant_id,
                affected_nodes,
                reason,
            },
        )
        .boxed()
}

#[cfg(any(test, feature = "test-support"))]
fn revocation_scopes() -> BoxedStrategy<RevocationScope> {
    (
        ascii_identifier(32),
        prop::option::of(ascii_identifier(32)),
        revocation_severities(),
        bounded_text(160),
    )
        .prop_map(|(zone_id, tenant_id, severity, reason)| RevocationScope {
            zone_id,
            tenant_id,
            severity,
            reason,
        })
        .boxed()
}

#[cfg(any(test, feature = "test-support"))]
fn decision_receipt_signatures() -> BoxedStrategy<DecisionReceiptSignature> {
    (
        ascii_identifier(16),
        hex_bytes(32),
        ascii_identifier(32),
        ascii_identifier(24),
        ascii_identifier(32),
        ascii_identifier(24),
        sha256_hash(),
        hex_bytes(64),
    )
        .prop_map(
            |(
                algorithm,
                public_key_hex,
                key_id,
                key_source,
                signing_identity,
                trust_scope,
                signed_payload_sha256,
                signature_hex,
            )| DecisionReceiptSignature {
                algorithm,
                public_key_hex,
                key_id,
                key_source,
                signing_identity,
                trust_scope,
                signed_payload_sha256,
                signature_hex,
            },
        )
        .boxed()
}

pub fn capability_tokens() -> BoxedStrategy<CapabilityToken> {
    (
        ascii_identifier(48),
        impossible_capabilities(),
        ascii_identifier(48),
        ascii_identifier(48),
        any::<u64>(),
        1u64..=86_400_000,
        hex_bytes(64),
        bounded_text(192),
    )
        .prop_map(
            |(
                token_id,
                capability,
                issuer,
                subject,
                issued_at_ms,
                ttl_ms,
                signature,
                justification,
            )| CapabilityToken {
                token_id,
                capability,
                issuer,
                subject,
                issued_at_ms,
                expires_at_ms: issued_at_ms.saturating_add(ttl_ms),
                signature,
                justification,
            },
        )
        .boxed()
}

#[cfg(any(test, feature = "test-support"))]
pub fn decision_receipt_payloads() -> BoxedStrategy<DecisionReceiptPayload> {
    prop_oneof![
        (ascii_identifier(32), quarantine_scopes()).prop_map(|(extension_id, scope)| {
            DecisionReceiptPayload::quarantine(&extension_id, &scope)
        }),
        (ascii_identifier(32), revocation_scopes()).prop_map(|(extension_id, scope)| {
            DecisionReceiptPayload::revoke(&extension_id, &scope)
        }),
        (
            ascii_identifier(32),
            ascii_identifier(32),
            bounded_text(160)
        )
            .prop_map(|(incident_id, zone_id, reason)| {
                DecisionReceiptPayload::release(&incident_id, &zone_id, &reason)
            },),
        (
            ascii_identifier(32),
            ascii_identifier(32),
            bounded_text(160)
        )
            .prop_map(|(incident_id, zone_id, reason)| {
                DecisionReceiptPayload::rollback(&incident_id, &zone_id, &reason)
            },),
        Just(DecisionReceiptPayload::reconcile()),
    ]
    .boxed()
}

#[cfg(any(test, feature = "test-support"))]
pub fn decision_receipts() -> BoxedStrategy<DecisionReceipt> {
    (
        ascii_identifier(48),
        ascii_identifier(48),
        ascii_identifier(48),
        rfc3339_timestamp(),
        decision_receipt_payloads(),
        prop::option::of(decision_receipt_signatures()),
    )
        .prop_map(
            |(operation_id, receipt_id, issuer, issued_at, decision_payload, signature)| {
                let payload_hash = canonical_decision_receipt_payload_hash(&decision_payload);
                let zone_id = decision_payload.scope.zone_id.clone();
                DecisionReceipt {
                    operation_id,
                    receipt_id,
                    issuer,
                    issued_at,
                    zone_id,
                    payload_hash,
                    decision_payload,
                    signature,
                }
            },
        )
        .boxed()
}

pub fn replay_bundle_entries() -> BoxedStrategy<RawEvent> {
    (
        rfc3339_timestamp(),
        event_types(),
        ascii_identifier(32),
        any::<u64>(),
        any::<bool>(),
        prop::option::of(any::<u64>()),
        prop::option::of(any::<u64>()),
        prop::option::of(ascii_identifier(24)),
    )
        .prop_map(
            |(
                timestamp,
                event_type,
                action,
                counter,
                flagged,
                causal_parent,
                snapshot_version,
                policy_version,
            )| {
                let mut event = RawEvent::new(
                    timestamp,
                    event_type,
                    json!({
                        "action": action,
                        "counter": counter,
                        "flagged": flagged,
                    }),
                );
                if let Some(parent) = causal_parent {
                    event = event.with_causal_parent(parent);
                }
                if let Some(version) = snapshot_version {
                    event = event.with_state_snapshot(json!({
                        "snapshot_version": version,
                        "checkpoint": flagged,
                    }));
                }
                if let Some(policy_version) = policy_version {
                    event = event.with_policy_version(policy_version);
                }
                event
            },
        )
        .boxed()
}

pub fn trust_cards() -> BoxedStrategy<TrustCard> {
    (
        (
            ascii_identifier(24),
            any::<u64>(),
            prop::option::of(sha256_hash()),
            trust_card_extension_identity(),
            trust_card_publisher_identity(),
            certification_levels(),
            prop::collection::vec(capability_declarations(), 1..=4),
            behavioral_profiles(),
            revocation_statuses(),
            provenance_summaries(),
        ),
        (
            any::<u16>(),
            reputation_trends(),
            any::<bool>(),
            prop::collection::vec(dependency_trust_statuses(), 0..=4),
            rfc3339_timestamp(),
            risk_assessments(),
            prop::collection::vec(audit_records(), 1..=4),
            prop::option::of(derivation_metadata()),
            sha256_hash(),
            hex_bytes(64),
        ),
    )
        .prop_map(
            |(
                (
                    schema_suffix,
                    trust_card_version,
                    previous_version_hash,
                    extension,
                    publisher,
                    certification_level,
                    capability_declarations,
                    behavioral_profile,
                    revocation_status,
                    provenance_summary,
                ),
                (
                    reputation_score_basis_points,
                    reputation_trend,
                    active_quarantine,
                    dependency_trust_summary,
                    last_verified_timestamp,
                    user_facing_risk_assessment,
                    audit_history,
                    derivation_evidence,
                    card_hash,
                    registry_signature,
                ),
            )| TrustCard {
                schema_version: format!("trust-card-{schema_suffix}"),
                trust_card_version,
                previous_version_hash,
                extension,
                publisher,
                certification_level,
                capability_declarations,
                behavioral_profile,
                revocation_status,
                provenance_summary,
                reputation_score_basis_points,
                reputation_trend,
                active_quarantine,
                dependency_trust_summary,
                last_verified_timestamp,
                user_facing_risk_assessment,
                audit_history,
                derivation_evidence,
                card_hash,
                registry_signature,
            },
        )
        .boxed()
}

pub fn evidence_ledger_entries() -> BoxedStrategy<EvidenceEntry> {
    (
        ascii_identifier(40),
        any::<u64>(),
        decision_kinds(),
        rfc3339_timestamp(),
        ascii_identifier(48),
        prop::option::of(ascii_identifier(24)),
        ascii_identifier(24),
        any::<u64>(),
        any::<bool>(),
    )
        .prop_map(
            |(
                decision_suffix,
                epoch_id,
                decision_kind,
                decision_time,
                trace_id,
                entry_id,
                action,
                counter,
                approved,
            )| {
                let decision_id = format!("DEC-{decision_suffix}");
                let mut entry = test_entry(&decision_id, epoch_id);
                entry.entry_id = entry_id;
                entry.decision_kind = decision_kind;
                entry.decision_time = decision_time;
                entry.trace_id = trace_id;
                entry.payload = json!({
                    "action": action,
                    "counter": counter,
                    "approved": approved,
                });
                entry
            },
        )
        .boxed()
}
