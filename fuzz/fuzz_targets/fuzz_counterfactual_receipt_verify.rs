#![no_main]

use arbitrary::Arbitrary;
use ed25519_dalek::{Signer, SigningKey};
use frankenengine_verifier_sdk::counterfactual::verify_counterfactual_receipt;
use libfuzzer_sys::fuzz_target;
use serde_json::{json, Value};

const MAX_RAW_JSON_BYTES: usize = 64 * 1024;
const MAX_RAW_SIGNATURE_BYTES: usize = 256;
const MAX_SWEEP_RESULTS: usize = 16;

#[derive(Debug, Arbitrary)]
struct CounterfactualReceiptCase {
    bundle_hash_bytes: [u8; 32],
    signer_seed: [u8; 32],
    alternate_seed: [u8; 32],
    raw_baseline_json: Vec<u8>,
    raw_output_json: Vec<u8>,
    raw_signature: Vec<u8>,
    baseline_hash: HashSlot,
    output_mode: OutputMode,
    top_level_hash: HashSlot,
    result_hashes: Vec<HashSlot>,
    signature_mutation: SignatureMutation,
}

#[derive(Debug, Clone, Copy, Arbitrary)]
enum HashSlot {
    Valid,
    Missing,
    Mismatch,
    Uppercase,
    Short,
    Padded,
    NonString,
}

#[derive(Debug, Clone, Copy, Arbitrary)]
enum OutputMode {
    SingleResult,
    Sweep,
}

#[derive(Debug, Clone, Copy, Arbitrary)]
enum SignatureMutation {
    Valid,
    WrongKey,
    Truncated,
    Extended,
    FlippedBit,
    RandomBytes,
}

fuzz_target!(|mut case: CounterfactualReceiptCase| {
    fuzz_raw_receipt_json(&mut case);
    fuzz_structured_receipt(case);
});

fn fuzz_raw_receipt_json(case: &mut CounterfactualReceiptCase) {
    if case.raw_baseline_json.len() > MAX_RAW_JSON_BYTES
        || case.raw_output_json.len() > MAX_RAW_JSON_BYTES
    {
        return;
    }
    if case.raw_signature.len() > MAX_RAW_SIGNATURE_BYTES {
        case.raw_signature.truncate(MAX_RAW_SIGNATURE_BYTES);
    }

    let Ok(baseline) = serde_json::from_slice::<Value>(&case.raw_baseline_json) else {
        return;
    };
    let Ok(output) = serde_json::from_slice::<Value>(&case.raw_output_json) else {
        return;
    };

    let signing_key = SigningKey::from_bytes(&case.signer_seed);
    let _ = verify_counterfactual_receipt(
        &baseline,
        &output,
        &signing_key.verifying_key(),
        &case.raw_signature,
    );
}

fn fuzz_structured_receipt(case: CounterfactualReceiptCase) {
    let expected_hash = hex::encode(case.bundle_hash_bytes);
    let baseline = baseline_value(&expected_hash, case.baseline_hash);
    let output = output_value(
        &expected_hash,
        case.output_mode,
        case.top_level_hash,
        &case.result_hashes,
    );
    let signature = signature_bytes(&case, &output);
    let signing_key = SigningKey::from_bytes(&case.signer_seed);

    let result =
        verify_counterfactual_receipt(&baseline, &output, &signing_key.verifying_key(), &signature);

    if case.baseline_hash.is_valid()
        && output_references_expected_hash(
            case.output_mode,
            case.top_level_hash,
            &case.result_hashes,
        )
        && matches!(case.signature_mutation, SignatureMutation::Valid)
    {
        result.expect("valid baseline, output, and signature must verify");
    }
}

fn baseline_value(expected_hash: &str, slot: HashSlot) -> Value {
    match slot {
        HashSlot::Missing => json!({}),
        other => json!({ "integrity_hash": hash_value(expected_hash, other) }),
    }
}

fn output_value(
    expected_hash: &str,
    mode: OutputMode,
    top_level_hash: HashSlot,
    result_hashes: &[HashSlot],
) -> Value {
    match mode {
        OutputMode::SingleResult => json!({
            "metadata": metadata_value(expected_hash, top_level_hash),
        }),
        OutputMode::Sweep => {
            let mut results = result_hashes
                .iter()
                .copied()
                .take(MAX_SWEEP_RESULTS)
                .map(|slot| json!({ "metadata": metadata_value(expected_hash, slot) }))
                .collect::<Vec<_>>();
            if results.is_empty() {
                results.push(json!({ "metadata": metadata_value(expected_hash, HashSlot::Valid) }));
            }

            if matches!(top_level_hash, HashSlot::Missing) {
                json!({ "results": results })
            } else {
                json!({
                    "metadata": metadata_value(expected_hash, top_level_hash),
                    "results": results,
                })
            }
        }
    }
}

fn metadata_value(expected_hash: &str, slot: HashSlot) -> Value {
    match slot {
        HashSlot::Missing => json!({}),
        other => json!({ "bundle_hash": hash_value(expected_hash, other) }),
    }
}

fn hash_value(expected_hash: &str, slot: HashSlot) -> Value {
    match slot {
        HashSlot::Valid => Value::String(expected_hash.to_string()),
        HashSlot::Missing => Value::Null,
        HashSlot::Mismatch => Value::String(mismatched_hash(expected_hash)),
        HashSlot::Uppercase => Value::String(expected_hash.to_ascii_uppercase()),
        HashSlot::Short => Value::String(expected_hash[..63].to_string()),
        HashSlot::Padded => Value::String(format!(" {expected_hash} ")),
        HashSlot::NonString => json!(7),
    }
}

fn mismatched_hash(expected_hash: &str) -> String {
    let mut bytes = expected_hash.as_bytes().to_vec();
    bytes[0] = if bytes[0] == b'a' { b'b' } else { b'a' };
    String::from_utf8(bytes).expect("hex digest remains ASCII")
}

fn signature_bytes(case: &CounterfactualReceiptCase, output: &Value) -> Vec<u8> {
    let signing_key = SigningKey::from_bytes(&case.signer_seed);
    let canonical = canonical_json_bytes(output);
    let mut signature = signing_key.sign(&canonical).to_bytes().to_vec();

    match case.signature_mutation {
        SignatureMutation::Valid => signature,
        SignatureMutation::WrongKey => {
            let mut alternate_seed = case.alternate_seed;
            if alternate_seed == case.signer_seed {
                alternate_seed[0] ^= 0x80;
            }
            SigningKey::from_bytes(&alternate_seed)
                .sign(&canonical)
                .to_bytes()
                .to_vec()
        }
        SignatureMutation::Truncated => {
            signature.truncate(signature.len().saturating_sub(1));
            signature
        }
        SignatureMutation::Extended => {
            signature.push(0);
            signature
        }
        SignatureMutation::FlippedBit => {
            signature[0] ^= 0x01;
            signature
        }
        SignatureMutation::RandomBytes => case
            .raw_signature
            .iter()
            .copied()
            .take(MAX_RAW_SIGNATURE_BYTES)
            .collect(),
    }
}

fn output_references_expected_hash(
    mode: OutputMode,
    top_level_hash: HashSlot,
    result_hashes: &[HashSlot],
) -> bool {
    match mode {
        OutputMode::SingleResult => top_level_hash.is_valid(),
        OutputMode::Sweep => {
            let top_level_ok = matches!(top_level_hash, HashSlot::Missing | HashSlot::Valid);
            let result_count = result_hashes.len().min(MAX_SWEEP_RESULTS);
            let results_ok = if result_count == 0 {
                true
            } else {
                result_hashes
                    .iter()
                    .take(result_count)
                    .all(|slot| slot.is_valid())
            };
            top_level_ok && results_ok
        }
    }
}

impl HashSlot {
    fn is_valid(self) -> bool {
        matches!(self, Self::Valid)
    }
}

fn canonical_json_bytes(value: &Value) -> Vec<u8> {
    let canonical = canonicalize_json(value);
    serde_json::to_vec(&canonical).expect("fuzz JSON value must serialize")
}

fn canonicalize_json(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut keys = map.keys().map(String::as_str).collect::<Vec<_>>();
            keys.sort_unstable();
            let mut out = serde_json::Map::with_capacity(map.len());
            for key in keys {
                out.insert(key.to_string(), canonicalize_json(&map[key]));
            }
            Value::Object(out)
        }
        Value::Array(items) => Value::Array(items.iter().map(canonicalize_json).collect()),
        other => other.clone(),
    }
}
