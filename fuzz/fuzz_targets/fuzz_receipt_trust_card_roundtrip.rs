#![no_main]

use std::collections::BTreeMap;

use arbitrary::Arbitrary;
use frankenengine_node::security::decision_receipt::{
    demo_public_key, demo_signing_key, export_receipts_cbor, export_receipts_json,
    import_receipts_cbor, sign_receipt, verify_receipt, Decision, Receipt, ReceiptQuery,
    SignedReceipt,
};
use frankenengine_node::supply_chain::trust_card::{
    to_canonical_json, AuditRecord, BehavioralProfile, CapabilityDeclaration, CapabilityRisk,
    CertificationLevel, DependencyTrustStatus, ExtensionIdentity, ProvenanceSummary,
    PublisherIdentity, ReputationTrend, RevocationStatus, RiskAssessment, RiskLevel,
    TelemetryEvent, TrustCard, TrustCardRegistrySnapshot,
};
use libfuzzer_sys::fuzz_target;
use serde_json::{json, Value};

const MAX_TEXT_BYTES: usize = 256;
const MAX_RAW_BYTES: usize = 256 * 1024;

fuzz_target!(|input: FuzzInput| {
    fuzz_receipt_roundtrip(&input);
    fuzz_trust_card_roundtrip(&input);
    fuzz_raw_envelopes(&input.raw);
});

fn fuzz_receipt_roundtrip(input: &FuzzInput) {
    let decision = Decision::from(input.decision);
    let receipt_input = json!({"input": bounded_text(&input.payload), "selector": input.selector});
    let receipt_output =
        json!({"output": bounded_text(&input.alt_payload), "accepted": input.flag});
    let receipt = match Receipt::new(
        &format!("action-{}", bounded_text(&input.action)),
        &format!("actor-{}", bounded_text(&input.actor)),
        "franken-node:fuzz-receipt-roundtrip",
        &receipt_input,
        &receipt_output,
        decision,
        &bounded_text(&input.reason),
        vec![format!("evidence/{}.json", input.selector % 16)],
        vec![format!("policy-rule-{}", input.selector % 8)],
        f64::from(input.confidence) / f64::from(u8::MAX),
        "franken-node rollback --receipt fuzz",
    ) {
        Ok(receipt) => receipt,
        Err(_) => return,
    };

    let signed = sign_receipt(&receipt, &demo_signing_key()).expect("valid receipt must sign");
    assert!(
        verify_receipt(&signed, &demo_public_key()).expect("signed receipt verification must run")
    );

    let receipts = vec![signed.clone()];
    let json_export =
        export_receipts_json(&receipts, &ReceiptQuery::default()).expect("receipt JSON export");
    let json_roundtrip: Vec<SignedReceipt> =
        serde_json::from_str(&json_export).expect("receipt JSON export must parse");
    assert_eq!(json_roundtrip, receipts);

    let cbor_export =
        export_receipts_cbor(&receipts, &ReceiptQuery::default()).expect("receipt CBOR export");
    let cbor_roundtrip = import_receipts_cbor(&cbor_export).expect("receipt CBOR import");
    assert_eq!(cbor_roundtrip, receipts);

    let pretty = serde_json::to_string_pretty(&signed).expect("signed receipt pretty JSON");
    let decoded: SignedReceipt =
        serde_json::from_str(&pretty).expect("signed receipt pretty JSON must parse");
    assert_eq!(decoded, signed);
}

fn fuzz_trust_card_roundtrip(input: &FuzzInput) {
    let card = trust_card_from_input(input);

    let json = serde_json::to_string(&card).expect("trust card JSON encode");
    let decoded: TrustCard = serde_json::from_str(&json).expect("trust card JSON decode");
    assert_eq!(decoded, card);

    let cbor = serde_cbor::to_vec(&card).expect("trust card CBOR encode");
    let decoded_cbor: TrustCard = serde_cbor::from_slice(&cbor).expect("trust card CBOR decode");
    assert_eq!(decoded_cbor, card);

    let canonical = to_canonical_json(&card).expect("trust card canonical JSON");
    let decoded_canonical: TrustCard =
        serde_json::from_str(&canonical).expect("trust card canonical JSON decode");
    assert_eq!(
        canonical,
        to_canonical_json(&decoded_canonical).expect("trust card recanonicalize")
    );

    let mut cards_by_extension = BTreeMap::new();
    cards_by_extension.insert(card.extension.extension_id.clone(), vec![card.clone()]);
    let snapshot = TrustCardRegistrySnapshot::signed(60, cards_by_extension, b"fuzz-registry-key")
        .expect("trust card snapshot must sign");
    let snapshot_json = serde_json::to_string(&snapshot).expect("snapshot JSON encode");
    let snapshot_decoded: TrustCardRegistrySnapshot =
        serde_json::from_str(&snapshot_json).expect("snapshot JSON decode");
    assert_eq!(snapshot_decoded, snapshot);

    let snapshot_cbor = serde_cbor::to_vec(&snapshot).expect("snapshot CBOR encode");
    let snapshot_cbor_decoded: TrustCardRegistrySnapshot =
        serde_cbor::from_slice(&snapshot_cbor).expect("snapshot CBOR decode");
    assert_eq!(snapshot_cbor_decoded, snapshot);
}

fn fuzz_raw_envelopes(bytes: &[u8]) {
    if bytes.len() > MAX_RAW_BYTES {
        return;
    }
    let _ = serde_json::from_slice::<SignedReceipt>(bytes);
    let _ = serde_json::from_slice::<Vec<SignedReceipt>>(bytes);
    let _ = serde_json::from_slice::<TrustCard>(bytes);
    let _ = serde_json::from_slice::<TrustCardRegistrySnapshot>(bytes);
    let _ = serde_json::from_slice::<TelemetryEvent>(bytes);
    let _ = serde_cbor::from_slice::<SignedReceipt>(bytes);
    let _ = serde_cbor::from_slice::<Vec<SignedReceipt>>(bytes);
    let _ = serde_cbor::from_slice::<TrustCard>(bytes);
    let _ = serde_cbor::from_slice::<TrustCardRegistrySnapshot>(bytes);
    let _ = serde_cbor::from_slice::<Value>(bytes);
}

fn trust_card_from_input(input: &FuzzInput) -> TrustCard {
    let extension_id = format!("npm:@fuzz/{}", bounded_text(&input.action));
    TrustCard {
        schema_version: "trust-card-v1.0".to_string(),
        trust_card_version: u64::from(input.selector).saturating_add(1),
        previous_version_hash: if input.flag {
            Some(format!("sha256:{:064x}", input.selector))
        } else {
            None
        },
        extension: ExtensionIdentity {
            extension_id,
            version: format!("{}.{}.{}", input.selector % 4, input.confidence % 10, 0),
        },
        publisher: PublisherIdentity {
            publisher_id: format!("publisher-{}", bounded_text(&input.actor)),
            display_name: bounded_text(&input.actor),
        },
        certification_level: input.certification.into(),
        capability_declarations: vec![CapabilityDeclaration {
            name: format!("capability.{}", bounded_text(&input.payload)),
            description: bounded_text(&input.reason),
            risk: input.capability_risk.into(),
        }],
        behavioral_profile: BehavioralProfile {
            network_access: input.flag,
            filesystem_access: input.selector % 2 == 0,
            subprocess_access: input.selector % 3 == 0,
            profile_summary: bounded_text(&input.alt_payload),
        },
        revocation_status: if input.selector % 7 == 0 {
            RevocationStatus::Revoked {
                reason: bounded_text(&input.reason),
                revoked_at: "2026-04-21T00:00:00Z".to_string(),
            }
        } else {
            RevocationStatus::Active
        },
        provenance_summary: ProvenanceSummary {
            attestation_level: format!("level-{}", input.selector % 5),
            source_uri: format!("fixture://fuzz/{}", bounded_text(&input.action)),
            artifact_hashes: vec![format!("sha256:{:064x}", input.confidence)],
            verified_at: "2026-04-21T00:00:00Z".to_string(),
        },
        reputation_score_basis_points: u16::from(input.confidence).saturating_mul(39).min(10_000),
        reputation_trend: input.reputation.into(),
        active_quarantine: input.selector % 11 == 0,
        dependency_trust_summary: vec![DependencyTrustStatus {
            dependency_id: format!("npm:dep-{}", input.selector),
            trust_level: "verified".to_string(),
        }],
        last_verified_timestamp: "2026-04-21T00:00:00Z".to_string(),
        user_facing_risk_assessment: RiskAssessment {
            level: input.risk.into(),
            summary: bounded_text(&input.reason),
        },
        audit_history: vec![AuditRecord {
            timestamp: "2026-04-21T00:00:00Z".to_string(),
            event_code: "FUZZ_TRUST_CARD_ROUNDTRIP".to_string(),
            detail: bounded_text(&input.payload),
            trace_id: format!("trace-{}", input.selector),
        }],
        derivation_evidence: None,
        camouflage_hints: Vec::new(),
        card_hash: format!("sha256:{:064x}", input.selector),
        registry_signature: format!("{:0128x}", input.confidence),
    }
}

fn bounded_text(raw: &str) -> String {
    let mut out: String = raw
        .chars()
        .filter(|ch| !ch.is_control())
        .take(MAX_TEXT_BYTES)
        .collect();
    if out.is_empty() {
        out.push('x');
    }
    out
}

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    action: String,
    actor: String,
    payload: String,
    alt_payload: String,
    reason: String,
    selector: u8,
    confidence: u8,
    flag: bool,
    decision: FuzzDecision,
    certification: FuzzCertification,
    capability_risk: FuzzCapabilityRisk,
    reputation: FuzzReputationTrend,
    risk: FuzzRiskLevel,
    raw: Vec<u8>,
}

#[derive(Arbitrary, Debug, Clone, Copy)]
enum FuzzDecision {
    Approved,
    Denied,
    Escalated,
}

impl From<FuzzDecision> for Decision {
    fn from(value: FuzzDecision) -> Self {
        match value {
            FuzzDecision::Approved => Self::Approved,
            FuzzDecision::Denied => Self::Denied,
            FuzzDecision::Escalated => Self::Escalated,
        }
    }
}

#[derive(Arbitrary, Debug, Clone, Copy)]
enum FuzzCertification {
    Unknown,
    Bronze,
    Silver,
    Gold,
    Platinum,
}

impl From<FuzzCertification> for CertificationLevel {
    fn from(value: FuzzCertification) -> Self {
        match value {
            FuzzCertification::Unknown => Self::Unknown,
            FuzzCertification::Bronze => Self::Bronze,
            FuzzCertification::Silver => Self::Silver,
            FuzzCertification::Gold => Self::Gold,
            FuzzCertification::Platinum => Self::Platinum,
        }
    }
}

#[derive(Arbitrary, Debug, Clone, Copy)]
enum FuzzCapabilityRisk {
    Low,
    Medium,
    High,
    Critical,
}

impl From<FuzzCapabilityRisk> for CapabilityRisk {
    fn from(value: FuzzCapabilityRisk) -> Self {
        match value {
            FuzzCapabilityRisk::Low => Self::Low,
            FuzzCapabilityRisk::Medium => Self::Medium,
            FuzzCapabilityRisk::High => Self::High,
            FuzzCapabilityRisk::Critical => Self::Critical,
        }
    }
}

#[derive(Arbitrary, Debug, Clone, Copy)]
enum FuzzReputationTrend {
    Improving,
    Stable,
    Declining,
}

impl From<FuzzReputationTrend> for ReputationTrend {
    fn from(value: FuzzReputationTrend) -> Self {
        match value {
            FuzzReputationTrend::Improving => Self::Improving,
            FuzzReputationTrend::Stable => Self::Stable,
            FuzzReputationTrend::Declining => Self::Declining,
        }
    }
}

#[derive(Arbitrary, Debug, Clone, Copy)]
enum FuzzRiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

impl From<FuzzRiskLevel> for RiskLevel {
    fn from(value: FuzzRiskLevel) -> Self {
        match value {
            FuzzRiskLevel::Low => Self::Low,
            FuzzRiskLevel::Medium => Self::Medium,
            FuzzRiskLevel::High => Self::High,
            FuzzRiskLevel::Critical => Self::Critical,
        }
    }
}
