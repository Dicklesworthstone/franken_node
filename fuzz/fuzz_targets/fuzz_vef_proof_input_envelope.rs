#![no_main]

use std::collections::{BTreeMap, BTreeSet};

use arbitrary::Arbitrary;
use frankenengine_node::vef::proof_scheduler::WorkloadTier;
use frankenengine_node::vef::proof_service::{ProofInputEnvelope, PROOF_SERVICE_SCHEMA_VERSION};
use libfuzzer_sys::fuzz_target;

const MAX_RAW_BYTES: usize = 256 * 1024;
const MAX_TEXT_CHARS: usize = 96;
const MAX_RECEIPTS: usize = 32;
const MAX_PREDICATES: usize = 16;
const MAX_METADATA: usize = 16;

#[derive(Debug, Arbitrary)]
struct FuzzInput {
    raw_json: Vec<u8>,
    seed: u64,
    tier: u8,
    job_id: String,
    window_id: String,
    trace_id: String,
    receipt_count: u8,
    checkpoint_id: Option<u64>,
    include_checkpoint_commitment: bool,
    policy_predicates: Vec<String>,
    metadata: Vec<(String, String)>,
}

fuzz_target!(|input: FuzzInput| {
    fuzz_raw_json(&input.raw_json);
    fuzz_structured_envelope(&input);
});

fn fuzz_raw_json(bytes: &[u8]) {
    if bytes.len() > MAX_RAW_BYTES {
        return;
    }

    let Ok(envelope) = serde_json::from_slice::<ProofInputEnvelope>(bytes) else {
        return;
    };

    if envelope.validate().is_ok() {
        assert_commitment_and_json_roundtrip(&envelope);
    }
}

fn fuzz_structured_envelope(input: &FuzzInput) {
    let envelope = valid_envelope(input);
    envelope
        .validate()
        .expect("structure-aware generated envelope must validate");
    assert_commitment_and_json_roundtrip(&envelope);
    assert_policy_predicate_order_and_duplicates_do_not_change_commitment(&envelope);
    assert_malformed_hash_fails_closed(&envelope);
    assert_receipt_count_mismatch_fails_closed(&envelope);
}

fn valid_envelope(input: &FuzzInput) -> ProofInputEnvelope {
    let receipt_count = 1 + usize::from(input.receipt_count) % MAX_RECEIPTS;
    let receipt_start_index = input.seed & 0x0fff;
    let receipt_end_index = receipt_start_index.saturating_add((receipt_count - 1) as u64);
    let checkpoint_id = input.checkpoint_id.map(|value| value % 1_000_000);

    ProofInputEnvelope {
        schema_version: PROOF_SERVICE_SCHEMA_VERSION.to_string(),
        job_id: stable_non_empty("job", &input.job_id),
        window_id: stable_non_empty("window", &input.window_id),
        tier: tier_from_byte(input.tier),
        trace_id: stable_non_empty("trace", &input.trace_id),
        receipt_start_index,
        receipt_end_index,
        checkpoint_id,
        chain_head_hash: sha256_prefixed(input.seed, b"chain-head"),
        checkpoint_commitment_hash: input
            .include_checkpoint_commitment
            .then(|| sha256_prefixed(input.seed, b"checkpoint")),
        policy_hash: sha256_prefixed(input.seed, b"policy"),
        policy_predicates: policy_predicates(&input.policy_predicates),
        receipt_hashes: (0..receipt_count)
            .map(|index| {
                sha256_prefixed(
                    input
                        .seed
                        .wrapping_add(u64::try_from(index).unwrap_or(u64::MAX)),
                    b"receipt",
                )
            })
            .collect(),
        metadata: metadata_map(&input.metadata),
    }
}

fn assert_commitment_and_json_roundtrip(envelope: &ProofInputEnvelope) {
    let commitment = envelope
        .commitment_hash()
        .expect("validated envelope commitment must hash");
    assert!(is_sha256_prefixed(&commitment));

    let json = serde_json::to_vec(envelope).expect("validated envelope must serialize");
    let decoded: ProofInputEnvelope =
        serde_json::from_slice(&json).expect("serialized envelope must parse");
    assert_eq!(&decoded, envelope);
    assert_eq!(
        decoded
            .commitment_hash()
            .expect("decoded envelope commitment must hash"),
        commitment
    );
}

fn assert_policy_predicate_order_and_duplicates_do_not_change_commitment(
    envelope: &ProofInputEnvelope,
) {
    let baseline = envelope
        .commitment_hash()
        .expect("validated envelope commitment must hash");
    let mut transformed = envelope.clone();
    transformed.policy_predicates.reverse();
    if let Some(first_predicate) = transformed.policy_predicates.first().cloned() {
        transformed.policy_predicates.push(first_predicate);
    }

    assert_eq!(
        transformed
            .commitment_hash()
            .expect("transformed envelope commitment must hash"),
        baseline,
        "commitment hash must canonicalize predicate ordering and duplicates"
    );
}

fn assert_malformed_hash_fails_closed(envelope: &ProofInputEnvelope) {
    let mut malformed = envelope.clone();
    malformed.chain_head_hash = "sha256:not-lowercase-64-hex".to_string();
    assert!(
        malformed.validate().is_err(),
        "malformed chain head hash must fail closed"
    );
}

fn assert_receipt_count_mismatch_fails_closed(envelope: &ProofInputEnvelope) {
    let mut malformed = envelope.clone();
    malformed
        .receipt_hashes
        .push(sha256_prefixed(0xa11ce, b"extra"));
    assert!(
        malformed.validate().is_err(),
        "receipt hash count mismatch must fail closed"
    );
}

fn policy_predicates(values: &[String]) -> Vec<String> {
    let mut predicates = BTreeSet::new();
    for value in values.iter().take(MAX_PREDICATES) {
        let predicate = bounded_component(value);
        if !predicate.is_empty() {
            predicates.insert(format!("predicate.{predicate}"));
        }
    }
    if predicates.is_empty() {
        predicates.insert("predicate.default".to_string());
    }
    predicates.into_iter().collect()
}

fn metadata_map(values: &[(String, String)]) -> BTreeMap<String, String> {
    let mut metadata = BTreeMap::new();
    for (index, (key, value)) in values.iter().take(MAX_METADATA).enumerate() {
        let key = stable_non_empty(&format!("key{index}"), key);
        metadata.insert(key, bounded_component(value));
    }
    metadata
}

fn stable_non_empty(prefix: &str, value: &str) -> String {
    let component = bounded_component(value);
    if component.is_empty() {
        prefix.to_string()
    } else {
        format!("{prefix}-{component}")
    }
}

fn bounded_component(value: &str) -> String {
    value
        .chars()
        .filter(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_'))
        .take(MAX_TEXT_CHARS)
        .collect()
}

fn tier_from_byte(value: u8) -> WorkloadTier {
    match value % 4 {
        0 => WorkloadTier::Critical,
        1 => WorkloadTier::High,
        2 => WorkloadTier::Standard,
        _ => WorkloadTier::Background,
    }
}

fn sha256_prefixed(seed: u64, domain: &[u8]) -> String {
    let mut bytes = Vec::with_capacity(domain.len() + 8);
    bytes.extend_from_slice(domain);
    bytes.extend_from_slice(&seed.to_le_bytes());
    format!(
        "sha256:{}",
        frankenengine_node::supply_chain::artifact_signing::sha256_hex(&bytes)
    )
}

fn is_sha256_prefixed(value: &str) -> bool {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return false;
    };
    hex.len() == 64 && hex.chars().all(|character| character.is_ascii_hexdigit())
}
