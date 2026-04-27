use frankenengine_node::supply_chain::trust_card::{
    to_canonical_json, verify_card_signature, TrustCard, TrustCardInput, TrustCardRegistry,
};
use serde::Deserialize;
use std::collections::BTreeMap;

const TRUST_CARD_CANONICAL_ENCODING_VECTORS_JSON: &str =
    include_str!("../../../artifacts/conformance/trust_card_canonical_encoding_vectors.json");

type TestResult = Result<(), String>;

#[derive(Debug, Deserialize)]
struct TrustCardCanonicalEncodingVectors {
    schema_version: String,
    coverage: Vec<CoverageRow>,
    vectors: Vec<TrustCardCanonicalEncodingVector>,
}

#[derive(Debug, Deserialize)]
struct CoverageRow {
    spec_section: String,
    invariant: String,
    level: String,
    tested: bool,
}

#[derive(Debug, Deserialize)]
struct TrustCardCanonicalEncodingVector {
    name: String,
    registry_key_ascii: String,
    now_secs: u64,
    trace_id: String,
    input: TrustCardInput,
    expected_card_hash: String,
    expected_registry_signature: String,
    expected_canonical_artifact: String,
    expected_hash_preimage_artifact: String,
}

fn load_vectors() -> Result<TrustCardCanonicalEncodingVectors, String> {
    serde_json::from_str(TRUST_CARD_CANONICAL_ENCODING_VECTORS_JSON)
        .map_err(|err| format!("trust-card canonical encoding vectors must parse: {err}"))
}

fn render_card(vector: &TrustCardCanonicalEncodingVector) -> Result<TrustCard, String> {
    let mut registry = TrustCardRegistry::new(60, vector.registry_key_ascii.as_bytes());
    registry
        .create(vector.input.clone(), vector.now_secs, &vector.trace_id)
        .map_err(|err| format!("{} trust-card creation failed: {err}", vector.name))
}

fn read_text_artifact(artifact: &str, vector_name: &str, label: &str) -> Result<String, String> {
    let path = super::workspace_artifact(artifact);
    std::fs::read_to_string(&path)
        .map(|contents| contents.trim_end_matches('\n').to_string())
        .map_err(|err| {
            format!(
                "{vector_name} {label} artifact {} must be readable: {err}",
                path.display()
            )
        })
}

#[test]
fn trust_card_canonical_encoding_vectors_cover_required_invariants() -> TestResult {
    let vectors = load_vectors()?;
    assert_eq!(
        vectors.schema_version,
        "franken-node/trust-card-canonical-encoding-conformance/v1"
    );
    assert_eq!(
        vectors.vectors.len(),
        2,
        "canonical encoding coverage must publish the baseline and normalized-order vectors"
    );

    for required in ["INV-TC-DETERMINISTIC", "INV-TC-SIGNATURE"] {
        assert!(
            vectors.coverage.iter().any(|row| {
                row.spec_section == "docs/specs/section_10_4/bd-2yh_contract.md"
                    && row.invariant == required
                    && row.level == "MUST"
                    && row.tested
            }),
            "{required} must be covered by the canonical encoding matrix"
        );
    }

    Ok(())
}

#[test]
fn trust_card_canonical_encoding_matches_golden_vectors() -> TestResult {
    let vectors = load_vectors()?;
    let mut canonical_outputs = BTreeMap::new();

    for vector in &vectors.vectors {
        let card = render_card(vector)?;
        verify_card_signature(&card, vector.registry_key_ascii.as_bytes()).map_err(|err| {
            format!(
                "{} generated canonical card signature must verify: {err}",
                vector.name
            )
        })?;

        let actual = to_canonical_json(&card)
            .map_err(|err| format!("{} canonical serialization failed: {err}", vector.name))?;
        let expected = read_text_artifact(
            &vector.expected_canonical_artifact,
            &vector.name,
            "expected canonical",
        )?;
        assert_eq!(
            actual.as_bytes(),
            expected.as_bytes(),
            "{} canonical trust-card bytes drifted from the checked-in artifact",
            vector.name
        );

        let actual_hash_preimage = super::canonical_hash_preimage(&card)?;
        let expected_hash_preimage = read_text_artifact(
            &vector.expected_hash_preimage_artifact,
            &vector.name,
            "expected hash preimage",
        )?;
        assert_eq!(
            actual_hash_preimage.as_bytes(),
            expected_hash_preimage.as_bytes(),
            "{} canonical hash preimage drifted from the checked-in artifact",
            vector.name
        );

        assert_eq!(
            card.card_hash, vector.expected_card_hash,
            "{} card_hash drifted from vector",
            vector.name
        );
        assert_eq!(
            card.registry_signature, vector.expected_registry_signature,
            "{} registry_signature drifted from vector",
            vector.name
        );

        let parsed: TrustCard = serde_json::from_str(&expected)
            .map_err(|err| format!("{} expected canonical JSON must parse: {err}", vector.name))?;
        verify_card_signature(&parsed, vector.registry_key_ascii.as_bytes()).map_err(|err| {
            format!(
                "{} expected canonical artifact signature must verify: {err}",
                vector.name
            )
        })?;
        let reparsed = to_canonical_json(&parsed).map_err(|err| {
            format!(
                "{} expected canonical artifact must reserialize canonically: {err}",
                vector.name
            )
        })?;
        assert_eq!(
            reparsed.as_bytes(),
            expected.as_bytes(),
            "{} expected canonical artifact must already be in canonical byte order",
            vector.name
        );

        canonical_outputs.insert(vector.name.clone(), actual);
    }

    let baseline = canonical_outputs
        .get("signed_card_baseline")
        .ok_or_else(|| "baseline vector output missing".to_string())?;
    let normalized = canonical_outputs
        .get("signed_card_input_order_normalized")
        .ok_or_else(|| "normalized-order vector output missing".to_string())?;
    assert_eq!(
        baseline.as_bytes(),
        normalized.as_bytes(),
        "canonical trust-card encoding must collapse semantically identical but differently ordered inputs"
    );

    Ok(())
}
