#![no_main]
#![forbid(unsafe_code)]

//! Structure-aware fuzzing for federation ATC participation weighting.
//!
//! This target exercises bounded batches of participant identities and checks
//! the public invariants around deterministic weighting, finite components,
//! fail-closed attestation handling, Sybil attenuation, audit completeness, and
//! JSON round trips.

use std::collections::{BTreeMap, BTreeSet};

use arbitrary::{Arbitrary, Result as ArbResult, Unstructured};
use frankenengine_node::federation::atc_participation_weighting::{
    AttestationEvidence, AttestationLevel, ParticipantIdentity, ParticipationWeight,
    ParticipationWeightEngine, ReputationEvidence, StakeEvidence, WeightAuditRecord,
    WeightingConfig,
};
use libfuzzer_sys::fuzz_target;

const MAX_INPUT_BYTES: usize = 64 * 1024;
const MAX_PARTICIPANTS: usize = 48;
const MAX_ATTESTATIONS: usize = 4;
const MAX_LABEL_BYTES: usize = 16;
const ACTIVE_TIMESTAMP: &str = "2026-02-20T00:00:00Z";
const EPSILON: f64 = 1.0e-9;

#[derive(Debug)]
struct WeightingCase {
    config: ConfigSpec,
    timestamp_seed: u8,
    batch_seed: Vec<u8>,
    participants: Vec<ParticipantSpec>,
}

impl<'a> Arbitrary<'a> for WeightingCase {
    fn arbitrary(u: &mut Unstructured<'a>) -> ArbResult<Self> {
        Ok(Self {
            config: ConfigSpec::arbitrary(u)?,
            timestamp_seed: u8::arbitrary(u)?,
            batch_seed: bounded_bytes(u, MAX_LABEL_BYTES)?,
            participants: bounded_vec(u, MAX_PARTICIPANTS)?,
        })
    }
}

#[derive(Debug)]
struct ConfigSpec {
    attestation_weight_seed: u16,
    stake_weight_seed: u16,
    reputation_weight_seed: u16,
    cap_fraction_seed: u16,
    tenure_seed: u32,
    interaction_seed: u32,
    attenuation_seed: u16,
    cluster_min_seed: u8,
}

impl<'a> Arbitrary<'a> for ConfigSpec {
    fn arbitrary(u: &mut Unstructured<'a>) -> ArbResult<Self> {
        Ok(Self {
            attestation_weight_seed: u16::arbitrary(u)?,
            stake_weight_seed: u16::arbitrary(u)?,
            reputation_weight_seed: u16::arbitrary(u)?,
            cap_fraction_seed: u16::arbitrary(u)?,
            tenure_seed: u32::arbitrary(u)?,
            interaction_seed: u32::arbitrary(u)?,
            attenuation_seed: u16::arbitrary(u)?,
            cluster_min_seed: u8::arbitrary(u)?,
        })
    }
}

impl ConfigSpec {
    fn to_config(&self) -> WeightingConfig {
        WeightingConfig {
            attestation_weight: factor_from(self.attestation_weight_seed),
            stake_weight: factor_from(self.stake_weight_seed),
            reputation_weight: factor_from(self.reputation_weight_seed),
            new_participant_cap_fraction: factor_from(self.cap_fraction_seed),
            established_tenure_seconds: u64::from(self.tenure_seed % (86_400 * 365)),
            established_interaction_count: u64::from(self.interaction_seed % 10_000),
            sybil_attenuation_factor: factor_from(self.attenuation_seed),
            sybil_cluster_min_size: usize::from(self.cluster_min_seed % 6),
        }
    }

    fn sanitized_attenuation(&self) -> f64 {
        factor_from(self.attenuation_seed).clamp(0.0, 1.0)
    }
}

#[derive(Debug)]
struct ParticipantSpec {
    id_seed: Vec<u8>,
    display_seed: Vec<u8>,
    flags: u8,
    stake_seed: u32,
    lock_seed: u32,
    reputation_score_seed: u32,
    interaction_seed: u32,
    tenure_seed: u32,
    accepted_seed: u32,
    rejected_seed: u32,
    cluster_seed: Vec<u8>,
    attestations: Vec<AttestationSpec>,
}

impl<'a> Arbitrary<'a> for ParticipantSpec {
    fn arbitrary(u: &mut Unstructured<'a>) -> ArbResult<Self> {
        Ok(Self {
            id_seed: bounded_bytes(u, MAX_LABEL_BYTES)?,
            display_seed: bounded_bytes(u, MAX_LABEL_BYTES)?,
            flags: u8::arbitrary(u)?,
            stake_seed: u32::arbitrary(u)?,
            lock_seed: u32::arbitrary(u)?,
            reputation_score_seed: u32::arbitrary(u)?,
            interaction_seed: u32::arbitrary(u)?,
            tenure_seed: u32::arbitrary(u)?,
            accepted_seed: u32::arbitrary(u)?,
            rejected_seed: u32::arbitrary(u)?,
            cluster_seed: bounded_bytes(u, MAX_LABEL_BYTES)?,
            attestations: bounded_vec(u, MAX_ATTESTATIONS)?,
        })
    }
}

impl ParticipantSpec {
    fn to_participant(&self, index: usize) -> ParticipantIdentity {
        let attestations = if self.flags & 0b0000_0001 == 0 {
            self.attestations
                .iter()
                .enumerate()
                .map(|(attestation_index, spec)| spec.to_attestation(index, attestation_index))
                .collect()
        } else {
            Vec::new()
        };

        ParticipantIdentity {
            participant_id: bounded_label("participant", index, &self.id_seed),
            display_name: bounded_label("display", index, &self.display_seed),
            attestations,
            stake: self.stake(),
            reputation: self.reputation(),
            cluster_hint: self.cluster_hint(),
        }
    }

    fn stake(&self) -> Option<StakeEvidence> {
        if self.flags & 0b0000_0010 == 0 {
            return None;
        }
        Some(StakeEvidence {
            amount: amount_from(self.stake_seed),
            deposited_at: timestamp_from(self.flags),
            lock_duration_seconds: u64::from(self.lock_seed % (86_400 * 365 * 2)),
            locked: self.flags & 0b0000_0100 != 0,
        })
    }

    fn reputation(&self) -> Option<ReputationEvidence> {
        if self.flags & 0b0000_1000 == 0 {
            return None;
        }
        Some(ReputationEvidence {
            score: reputation_score_from(self.reputation_score_seed),
            interaction_count: u64::from(self.interaction_seed % 1_000_000),
            tenure_seconds: u64::from(self.tenure_seed % (86_400 * 365 * 5)),
            contributions_accepted: u64::from(self.accepted_seed % 1_000_000),
            contributions_rejected: u64::from(self.rejected_seed % 1_000_000),
        })
    }

    fn cluster_hint(&self) -> Option<String> {
        if self.flags & 0b0001_0000 == 0 {
            return None;
        }
        Some(bounded_label("cluster", 0, &self.cluster_seed))
    }
}

#[derive(Debug)]
struct AttestationSpec {
    id_seed: Vec<u8>,
    issuer_seed: Vec<u8>,
    signature_seed: Vec<u8>,
    level_seed: u8,
    validity_seed: u8,
}

impl<'a> Arbitrary<'a> for AttestationSpec {
    fn arbitrary(u: &mut Unstructured<'a>) -> ArbResult<Self> {
        Ok(Self {
            id_seed: bounded_bytes(u, MAX_LABEL_BYTES)?,
            issuer_seed: bounded_bytes(u, MAX_LABEL_BYTES)?,
            signature_seed: bounded_bytes(u, MAX_LABEL_BYTES)?,
            level_seed: u8::arbitrary(u)?,
            validity_seed: u8::arbitrary(u)?,
        })
    }
}

impl AttestationSpec {
    fn to_attestation(
        &self,
        participant_index: usize,
        attestation_index: usize,
    ) -> AttestationEvidence {
        let (issued_at, expires_at) = attestation_window(self.validity_seed);
        AttestationEvidence {
            attestation_id: bounded_label("attestation", participant_index, &self.id_seed),
            issuer: bounded_label("issuer", attestation_index, &self.issuer_seed),
            level: attestation_level_from(self.level_seed),
            issued_at,
            expires_at,
            signature_hex: signature_hex(&self.signature_seed),
        }
    }
}

fn bounded_vec<'a, T: Arbitrary<'a>>(
    u: &mut Unstructured<'a>,
    max_len: usize,
) -> ArbResult<Vec<T>> {
    let len = u.int_in_range::<usize>(0..=max_len)?;
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        out.push(T::arbitrary(u)?);
    }
    Ok(out)
}

fn bounded_bytes(u: &mut Unstructured<'_>, max_len: usize) -> ArbResult<Vec<u8>> {
    let len = u.int_in_range::<usize>(0..=max_len)?;
    Ok(u.bytes(len)?.to_vec())
}

fn bounded_label(prefix: &str, index: usize, seed: &[u8]) -> String {
    let mut out = String::with_capacity(prefix.len().saturating_add(MAX_LABEL_BYTES + 24));
    out.push_str(prefix);
    out.push('-');
    out.push_str(&index.to_string());
    for byte in seed.iter().take(MAX_LABEL_BYTES) {
        out.push('-');
        out.push(char::from(b'a'.saturating_add(byte % 26)));
    }
    out
}

fn signature_hex(seed: &[u8]) -> String {
    let mut out = String::with_capacity(seed.len().saturating_mul(2).max(2));
    for byte in seed.iter().take(MAX_LABEL_BYTES) {
        out.push(hex_char(byte >> 4));
        out.push(hex_char(byte & 0x0f));
    }
    if out.is_empty() {
        out.push_str("00");
    }
    out
}

fn hex_char(nibble: u8) -> char {
    match nibble {
        0 => '0',
        1 => '1',
        2 => '2',
        3 => '3',
        4 => '4',
        5 => '5',
        6 => '6',
        7 => '7',
        8 => '8',
        9 => '9',
        10 => 'a',
        11 => 'b',
        12 => 'c',
        13 => 'd',
        14 => 'e',
        _ => 'f',
    }
}

fn timestamp_from(seed: u8) -> String {
    match seed % 4 {
        0 => "2025-01-01T00:00:00Z",
        1 => "2026-02-20T00:00:00Z",
        2 => "2027-01-01T00:00:00Z",
        _ => "not-a-timestamp",
    }
    .to_string()
}

fn attestation_window(seed: u8) -> (String, String) {
    match seed % 5 {
        0 => (
            "2025-01-01T00:00:00Z".to_string(),
            "2027-01-01T00:00:00Z".to_string(),
        ),
        1 => (
            "2023-01-01T00:00:00Z".to_string(),
            "2024-01-01T00:00:00Z".to_string(),
        ),
        2 => (
            "2027-01-01T00:00:00Z".to_string(),
            "2028-01-01T00:00:00Z".to_string(),
        ),
        3 => ("not-a-date".to_string(), "2027-01-01T00:00:00Z".to_string()),
        _ => ("2025-01-01T00:00:00Z".to_string(), "not-a-date".to_string()),
    }
}

fn attestation_level_from(seed: u8) -> AttestationLevel {
    match seed % 4 {
        0 => AttestationLevel::SelfSigned,
        1 => AttestationLevel::PeerVerified,
        2 => AttestationLevel::VerifierBacked,
        _ => AttestationLevel::AuthorityCertified,
    }
}

fn factor_from(seed: u16) -> f64 {
    match seed % 8 {
        0 => -0.25,
        1 => 0.0,
        2 => 0.1,
        3 => 0.4,
        4 => 0.8,
        5 => 1.0,
        6 => 1.25,
        _ => f64::from(seed % 1_000) / 1_000.0,
    }
}

fn amount_from(seed: u32) -> f64 {
    match seed % 8 {
        0 => f64::NAN,
        1 => f64::INFINITY,
        2 => -f64::INFINITY,
        3 => -f64::from(seed % 1_000_000),
        _ => f64::from(seed % 1_000_000) / 10.0,
    }
}

fn reputation_score_from(seed: u32) -> f64 {
    match seed % 6 {
        0 => f64::NAN,
        1 => -0.5,
        2 => 1.5,
        _ => f64::from(seed % 1_000) / 1_000.0,
    }
}

fn participants_from(specs: &[ParticipantSpec]) -> Vec<ParticipantIdentity> {
    specs
        .iter()
        .enumerate()
        .map(|(index, spec)| spec.to_participant(index))
        .collect()
}

fn expected_sybil_ids(
    participants: &[ParticipantIdentity],
    min_size: usize,
) -> (usize, BTreeSet<&str>) {
    let mut groups: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for participant in participants {
        if let Some(hint) = participant.cluster_hint.as_deref() {
            groups
                .entry(hint)
                .or_default()
                .push(participant.participant_id.as_str());
        }
    }

    let mut cluster_count = 0usize;
    let mut member_ids = BTreeSet::new();
    for members in groups.values() {
        if members.len() >= min_size {
            cluster_count = cluster_count.saturating_add(1);
            for member_id in members {
                member_ids.insert(*member_id);
            }
        }
    }
    (cluster_count, member_ids)
}

fn len_as_f64(len: usize) -> f64 {
    f64::from(u32::try_from(len).unwrap_or(u32::MAX))
}

fn approx_eq(left: f64, right: f64, scale: f64) -> bool {
    (left - right).abs() <= EPSILON * scale.max(1.0)
}

fn check_weight(weight: &ParticipationWeight, participant: &ParticipantIdentity) {
    assert_eq!(
        weight.participant_id, participant.participant_id,
        "weight order must track participant order"
    );
    assert!(weight.raw_weight.is_finite(), "raw weight must be finite");
    assert!(
        weight.attestation_component.is_finite(),
        "attestation component must be finite"
    );
    assert!(
        weight.stake_component.is_finite(),
        "stake component must be finite"
    );
    assert!(
        weight.reputation_component.is_finite(),
        "reputation component must be finite"
    );
    assert!(
        weight.sybil_penalty.is_finite(),
        "sybil penalty must be finite"
    );
    assert!(
        weight.final_weight.is_finite(),
        "final weight must be finite"
    );

    assert!(weight.raw_weight >= 0.0, "raw weight must not be negative");
    assert!(
        (0.0..=1.0).contains(&weight.attestation_component),
        "attestation component must be normalized"
    );
    assert!(
        (0.0..=1.0).contains(&weight.stake_component),
        "stake component must be normalized"
    );
    assert!(
        (0.0..=1.0).contains(&weight.reputation_component),
        "reputation component must be normalized"
    );
    assert!(
        (0.0..=1.0).contains(&weight.sybil_penalty),
        "sybil penalty must be normalized"
    );
    assert!(
        weight.final_weight >= 0.0,
        "final weight must not be negative"
    );
    assert!(
        weight.final_weight <= weight.raw_weight + EPSILON,
        "final weight must never exceed raw weight after caps and penalties"
    );

    if participant.attestations.is_empty() {
        assert!(
            weight.rejected,
            "participants without attestations must be rejected"
        );
    }
    if weight.rejected {
        assert!(
            approx_eq(weight.raw_weight, 0.0, 1.0),
            "rejected participants must have zero raw weight"
        );
        assert!(
            approx_eq(weight.final_weight, 0.0, 1.0),
            "rejected participants must have zero final weight"
        );
        assert!(
            weight.rejection_reason.is_some(),
            "rejected participants need an audit reason"
        );
    }
}

fn check_record(
    record: &WeightAuditRecord,
    participants: &[ParticipantIdentity],
    expected_cluster_count: usize,
    sybil_ids: &BTreeSet<&str>,
    expected_attenuation: f64,
) {
    assert_eq!(record.participant_count, participants.len());
    assert_eq!(record.weights.len(), participants.len());
    assert_eq!(
        record.participants_rejected,
        record
            .weights
            .iter()
            .filter(|weight| weight.rejected)
            .count()
    );
    assert_eq!(
        record.participants_capped,
        record.weights.iter().filter(|weight| weight.capped).count()
    );
    assert_eq!(record.sybil_clusters_detected, expected_cluster_count);
    assert_eq!(
        record.content_hash,
        WeightAuditRecord::compute_hash(&record.weights)
    );
    assert_eq!(record.content_hash.len(), 64);
    assert!(
        record.total_weight.is_finite(),
        "total weight must be finite"
    );
    assert!(record.total_weight >= 0.0);

    let recomputed_total = record
        .weights
        .iter()
        .fold(0.0, |acc, weight| acc + weight.final_weight);
    assert!(
        approx_eq(
            record.total_weight,
            recomputed_total,
            len_as_f64(record.weights.len())
        ),
        "total weight must equal the sum of final weights"
    );

    for (participant, weight) in participants.iter().zip(record.weights.iter()) {
        check_weight(weight, participant);
        if sybil_ids.contains(weight.participant_id.as_str()) {
            assert!(
                approx_eq(weight.sybil_penalty, 1.0 - expected_attenuation, 1.0),
                "cluster members must receive configured attenuation"
            );
        } else {
            assert!(
                approx_eq(weight.sybil_penalty, 0.0, 1.0),
                "non-cluster members must not receive a Sybil penalty"
            );
        }
    }
}

fn check_serialization(record: &WeightAuditRecord, engine: &ParticipationWeightEngine) {
    let encoded = serde_json::to_vec(record);
    assert!(
        encoded.is_ok(),
        "participation weight audit record must serialize"
    );
    if let Ok(encoded) = encoded {
        let decoded = serde_json::from_slice::<WeightAuditRecord>(&encoded);
        assert!(
            decoded.is_ok(),
            "serialized participation weight audit record must deserialize"
        );
        if let Ok(decoded) = decoded {
            assert_eq!(decoded.content_hash, record.content_hash);
            assert_eq!(decoded.weights.len(), record.weights.len());
        }
    }

    let exported = engine.export_audit_json();
    assert!(exported.is_ok(), "audit log export must serialize");
    if let Ok(exported) = exported {
        assert!(
            serde_json::from_str::<serde_json::Value>(&exported).is_ok(),
            "exported audit log must be valid JSON"
        );
    }
}

fn established_participant(id: &str, stake_amount: f64) -> ParticipantIdentity {
    ParticipantIdentity {
        participant_id: id.to_string(),
        display_name: id.to_string(),
        attestations: vec![AttestationEvidence {
            attestation_id: format!("att-{id}"),
            issuer: "fuzz-authority".to_string(),
            level: AttestationLevel::AuthorityCertified,
            issued_at: "2025-01-01T00:00:00Z".to_string(),
            expires_at: "2027-01-01T00:00:00Z".to_string(),
            signature_hex: "feedface".to_string(),
        }],
        stake: Some(StakeEvidence {
            amount: stake_amount,
            deposited_at: "2025-01-01T00:00:00Z".to_string(),
            lock_duration_seconds: 86_400 * 365,
            locked: true,
        }),
        reputation: Some(ReputationEvidence {
            score: 0.9,
            interaction_count: 500,
            tenure_seconds: 86_400 * 365,
            contributions_accepted: 450,
            contributions_rejected: 10,
        }),
        cluster_hint: None,
    }
}

fn check_stake_monotonicity() {
    let low = established_participant("stake-low", 10.0);
    let high = established_participant("stake-high", 10_000.0);
    let participants = vec![low, high];
    let mut engine = ParticipationWeightEngine::default();
    let record = engine.compute_weights(&participants, "stake-monotone", ACTIVE_TIMESTAMP);
    let low_weight = record
        .weights
        .iter()
        .find(|weight| weight.participant_id == "stake-low");
    let high_weight = record
        .weights
        .iter()
        .find(|weight| weight.participant_id == "stake-high");

    if let (Some(low_weight), Some(high_weight)) = (low_weight, high_weight) {
        assert!(
            high_weight.stake_component >= low_weight.stake_component,
            "higher stake must not reduce the stake component"
        );
        assert!(
            high_weight.raw_weight >= low_weight.raw_weight,
            "higher stake must not reduce raw weight with otherwise equal evidence"
        );
    }
}

fn check_zero_attestation_rejection() {
    let participant = ParticipantIdentity {
        participant_id: "zero-attestation-inflated".to_string(),
        display_name: "zero-attestation-inflated".to_string(),
        attestations: Vec::new(),
        stake: Some(StakeEvidence {
            amount: 1_000_000_000.0,
            deposited_at: "2025-01-01T00:00:00Z".to_string(),
            lock_duration_seconds: 86_400 * 365,
            locked: true,
        }),
        reputation: Some(ReputationEvidence {
            score: 1.0,
            interaction_count: 1_000_000,
            tenure_seconds: 86_400 * 365,
            contributions_accepted: 1_000_000,
            contributions_rejected: 0,
        }),
        cluster_hint: None,
    };
    let mut engine = ParticipationWeightEngine::default();
    let record = engine.compute_weights(&[participant], "zero-attestation", ACTIVE_TIMESTAMP);
    assert_eq!(record.participants_rejected, 1);
    assert!(record.weights.iter().all(|weight| weight.rejected));
    assert!(record
        .weights
        .iter()
        .all(|weight| approx_eq(weight.final_weight, 0.0, 1.0)));
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_BYTES {
        return;
    }

    let mut u = Unstructured::new(data);
    let Ok(case) = WeightingCase::arbitrary(&mut u) else {
        return;
    };

    let config = case.config.to_config();
    let participants = participants_from(&case.participants);
    let timestamp = timestamp_from(case.timestamp_seed);
    let batch_id = bounded_label("batch", 0, &case.batch_seed);
    let (expected_cluster_count, sybil_ids) =
        expected_sybil_ids(&participants, config.sybil_cluster_min_size);
    let expected_attenuation = case.config.sanitized_attenuation();

    let mut engine = ParticipationWeightEngine::new(config.clone());
    let record = engine.compute_weights(&participants, &batch_id, &timestamp);
    check_record(
        &record,
        &participants,
        expected_cluster_count,
        &sybil_ids,
        expected_attenuation,
    );
    assert_eq!(engine.audit_log().len(), 1);
    check_serialization(&record, &engine);

    let mut replay = ParticipationWeightEngine::new(config);
    let replayed = replay.compute_weights(&participants, &batch_id, &timestamp);
    assert_eq!(
        record.content_hash, replayed.content_hash,
        "same participation inputs must produce the same audit hash"
    );
    assert_eq!(
        record.weights, replayed.weights,
        "same participation inputs must produce identical weights"
    );

    check_stake_monotonicity();
    check_zero_attestation_rejection();
});
