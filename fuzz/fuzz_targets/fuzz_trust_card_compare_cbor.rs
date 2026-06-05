#![no_main]

use arbitrary::Arbitrary;
use frankenengine_node::supply_chain::trust_card::{
    TrustCard, TrustCardComparison, TrustCardRegistry, TrustCardRegistrySnapshot,
    compute_card_hash, fixture_registry, render_comparison_human, render_trust_card_human,
    to_canonical_json, verify_card_signature,
};
use libfuzzer_sys::fuzz_target;

const TRUST_CARD_REGISTRY_KEY: &[u8] = b"franken-node-trust-card-registry-key-v1";
const MAX_CBOR_BYTES: usize = 64 * 1024;

#[derive(Debug, Arbitrary)]
struct TrustCardCompareCborCase {
    raw_cbor: Vec<u8>,
    now_secs: u64,
    selector: u8,
}

fuzz_target!(|case: TrustCardCompareCborCase| {
    fuzz_trust_card_compare_cbor(case);
});

fn fuzz_trust_card_compare_cbor(mut case: TrustCardCompareCborCase) {
    if case.raw_cbor.len() > MAX_CBOR_BYTES {
        case.raw_cbor.truncate(MAX_CBOR_BYTES);
    }
    fuzz_raw_cbor(&case.raw_cbor);
    fuzz_fixture_compare(case.now_secs, case.selector);
}

fn fuzz_raw_cbor(bytes: &[u8]) {
    if let Ok(card) = cbor_from_slice::<TrustCard>(bytes) {
        let _ = compute_card_hash(&card);
        let _ = verify_card_signature(&card, TRUST_CARD_REGISTRY_KEY);
        let _ = render_trust_card_human(&card);
        let _ = serde_json::to_vec(&card);
        let _ = cbor_to_vec(&card);
    }

    if let Ok(snapshot) = cbor_from_slice::<TrustCardRegistrySnapshot>(bytes) {
        let _ = TrustCardRegistry::from_snapshot(snapshot, TRUST_CARD_REGISTRY_KEY, 1);
    }

    if let Ok(comparison) = cbor_from_slice::<TrustCardComparison>(bytes) {
        let _ = render_comparison_human(&comparison);
        let _ = serde_json::to_vec(&comparison);
        let _ = cbor_to_vec(&comparison);
    }
}

fn fuzz_fixture_compare(now_secs: u64, selector: u8) {
    let now_secs = now_secs % 4_000_000_000;
    let Ok(mut registry) = fixture_registry(now_secs) else {
        return;
    };

    let Ok(snapshot) = registry.snapshot() else {
        return;
    };
    let cbor = cbor_to_vec(&snapshot).expect("fixture snapshot must encode as CBOR");
    let decoded = cbor_from_slice::<TrustCardRegistrySnapshot>(&cbor)
        .expect("fixture snapshot CBOR must decode");
    let _ = to_canonical_json(&decoded);
    TrustCardRegistry::from_snapshot(decoded, TRUST_CARD_REGISTRY_KEY, now_secs)
        .expect("fixture snapshot must reload with trusted key");

    let (left, right) = if selector % 2 == 0 {
        ("npm:@acme/auth-guard", "npm:@beta/telemetry-bridge")
    } else {
        ("npm:@beta/telemetry-bridge", "npm:@acme/auth-guard")
    };
    let comparison = registry
        .compare(
            left,
            right,
            now_secs.saturating_add(10),
            "trace-fuzz-compare",
        )
        .expect("fixture cards should compare");
    let _ = render_comparison_human(&comparison);
    let comparison_cbor = cbor_to_vec(&comparison).expect("comparison must encode");
    let decoded_comparison = cbor_from_slice::<TrustCardComparison>(&comparison_cbor)
        .expect("comparison CBOR must decode");
    assert_eq!(comparison, decoded_comparison);

    let version_comparison = registry
        .compare_versions(
            "npm:@beta/telemetry-bridge",
            1,
            2,
            now_secs.saturating_add(11),
            "trace-fuzz-version-compare",
        )
        .expect("fixture versions should compare");
    let _ = render_comparison_human(&version_comparison);
}

fn cbor_to_vec(value: &impl serde::Serialize) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(value, &mut bytes).map_err(|err| err.to_string())?;
    Ok(bytes)
}

fn cbor_from_slice<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, String> {
    ciborium::de::from_reader(bytes).map_err(|err| err.to_string())
}
