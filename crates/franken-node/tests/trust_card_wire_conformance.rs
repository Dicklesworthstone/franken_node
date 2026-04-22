use frankenengine_node::supply_chain::trust_card::{
    TrustCard, TrustCardInput, TrustCardRegistry, to_canonical_json, verify_card_signature,
};
use serde::Deserialize;
use std::path::{Path, PathBuf};

const TRUST_CARD_WIRE_VECTORS_JSON: &str =
    include_str!("../../../artifacts/conformance/trust_card_wire_vectors.json");

type TestResult = Result<(), String>;

#[derive(Debug, Deserialize)]
struct TrustCardWireVectors {
    schema_version: String,
    coverage: Vec<CoverageRow>,
    vectors: Vec<TrustCardWireVector>,
}

#[derive(Debug, Deserialize)]
struct CoverageRow {
    spec_section: String,
    invariant: String,
    level: String,
    tested: bool,
}

#[derive(Debug, Deserialize)]
struct TrustCardWireVector {
    name: String,
    registry_key_ascii: String,
    now_secs: u64,
    trace_id: String,
    input: TrustCardInput,
    expected_card_hash: Option<String>,
    expected_registry_signature: Option<String>,
    expected_wire_artifact: String,
}

fn load_vectors() -> Result<TrustCardWireVectors, String> {
    serde_json::from_str(TRUST_CARD_WIRE_VECTORS_JSON)
        .map_err(|err| format!("trust-card wire vectors must parse: {err}"))
}

fn workspace_artifact(path: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(path)
}

fn render_card(vector: &TrustCardWireVector) -> Result<TrustCard, String> {
    let mut registry = TrustCardRegistry::new(60, vector.registry_key_ascii.as_bytes());
    registry
        .create(vector.input.clone(), vector.now_secs, &vector.trace_id)
        .map_err(|err| format!("{} trust-card creation failed: {err}", vector.name))
}

fn read_expected_wire(vector: &TrustCardWireVector) -> Result<String, String> {
    let path = workspace_artifact(&vector.expected_wire_artifact);
    std::fs::read_to_string(&path)
        .map(|contents| contents.trim_end_matches('\n').to_string())
        .map_err(|err| {
            format!(
                "{} expected wire artifact {} must be readable: {err}",
                vector.name,
                path.display()
            )
        })
}

#[test]
fn trust_card_wire_vectors_cover_required_spec_clauses() -> TestResult {
    let vectors = load_vectors()?;
    assert_eq!(
        vectors.schema_version,
        "franken-node/trust-card-wire-conformance/v1"
    );
    assert!(
        !vectors.vectors.is_empty(),
        "conformance artifact must publish at least one vector"
    );

    for required in ["INV-TC-DETERMINISTIC", "INV-TC-SIGNATURE"] {
        assert!(
            vectors.coverage.iter().any(|row| {
                row.spec_section == "docs/specs/section_10_4/bd-2yh_contract.md"
                    && row.invariant == required
                    && row.level == "MUST"
                    && row.tested
            }),
            "{required} must be covered by the conformance matrix"
        );
    }

    Ok(())
}

#[test]
fn trust_card_wire_format_matches_canonical_artifacts() -> TestResult {
    let vectors = load_vectors()?;
    let print_generated = std::env::var_os("TRUST_CARD_WIRE_CONFORMANCE_PRINT").is_some();
    let mut generated = Vec::new();

    for vector in &vectors.vectors {
        let card = render_card(vector)?;
        verify_card_signature(&card, vector.registry_key_ascii.as_bytes())
            .map_err(|err| format!("{} signature verification failed: {err}", vector.name))?;
        let actual = to_canonical_json(&card)
            .map_err(|err| format!("{} canonical serialization failed: {err}", vector.name))?;

        if print_generated {
            generated.push(serde_json::json!({
                "name": vector.name,
                "expected_card_hash": card.card_hash,
                "expected_registry_signature": card.registry_signature,
                "expected_wire_json": actual,
            }));
            continue;
        }

        let expected_hash = vector
            .expected_card_hash
            .as_ref()
            .ok_or_else(|| format!("{} must declare expected_card_hash", vector.name))?;
        let expected_signature = vector
            .expected_registry_signature
            .as_ref()
            .ok_or_else(|| format!("{} must declare expected_registry_signature", vector.name))?;
        assert_eq!(
            &card.card_hash, expected_hash,
            "{} card_hash drifted from vector",
            vector.name
        );
        assert_eq!(
            &card.registry_signature, expected_signature,
            "{} registry_signature drifted from vector",
            vector.name
        );

        let expected = read_expected_wire(vector)?;
        assert_eq!(
            actual.as_bytes(),
            expected.as_bytes(),
            "{} canonical trust-card wire bytes drifted from checked-in artifact",
            vector.name
        );

        let parsed: TrustCard = serde_json::from_str(&expected)
            .map_err(|err| format!("{} expected wire JSON must parse: {err}", vector.name))?;
        verify_card_signature(&parsed, vector.registry_key_ascii.as_bytes()).map_err(|err| {
            format!(
                "{} expected wire artifact signature must verify: {err}",
                vector.name
            )
        })?;
        let reparsed = to_canonical_json(&parsed).map_err(|err| {
            format!(
                "{} expected wire artifact must reserialize canonically: {err}",
                vector.name
            )
        })?;
        assert_eq!(
            reparsed.as_bytes(),
            actual.as_bytes(),
            "{} canonical wire artifact must round-trip byte-for-byte",
            vector.name
        );
    }

    if print_generated {
        let rendered = serde_json::to_string_pretty(&generated).map_err(|err| {
            format!("generated trust-card wire vector json must serialize: {err}")
        })?;
        println!("TRUST_CARD_WIRE_CONFORMANCE_GENERATED={rendered}");
    }

    Ok(())
}

#[test]
fn trust_card_wire_format_is_deterministic_for_identical_inputs() -> TestResult {
    let vectors = load_vectors()?;

    for vector in &vectors.vectors {
        let left = render_card(vector)?;
        let right = render_card(vector)?;

        assert_eq!(
            left.card_hash, right.card_hash,
            "{} identical inputs must produce identical card_hash",
            vector.name
        );
        assert_eq!(
            left.registry_signature, right.registry_signature,
            "{} identical inputs must produce identical registry_signature",
            vector.name
        );
        assert_eq!(
            to_canonical_json(&left).map_err(|err| err.to_string())?,
            to_canonical_json(&right).map_err(|err| err.to_string())?,
            "{} identical inputs must produce byte-identical canonical JSON",
            vector.name
        );
    }

    Ok(())
}
