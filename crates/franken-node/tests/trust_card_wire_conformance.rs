use frankenengine_node::supply_chain::trust_card::{
    to_canonical_json, verify_card_signature, TrustCard, TrustCardInput, TrustCardRegistry,
};
use hmac::{Hmac, KeyInit, Mac};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

#[path = "trust_card_canonical_encoding_conformance.rs"]
mod trust_card_canonical_encoding_conformance;

const TRUST_CARD_WIRE_VECTORS_JSON: &str =
    include_str!("../../../artifacts/conformance/trust_card_wire_vectors.json");
const TRUST_CARD_HASH_DOMAIN: &[u8] = b"trust_card_hash_v1:";
const TRUST_CARD_REGISTRY_SIGNATURE_DOMAIN: &[u8] = b"trust_card_registry_sig_v1:";

type TestResult = Result<(), String>;
type HmacSha256 = Hmac<Sha256>;

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
    expected_hash_preimage_artifact: Option<String>,
    expected_signature_preimage_hex_artifact: Option<String>,
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
    read_text_artifact(&vector.expected_wire_artifact, vector, "expected wire")
}

fn read_text_artifact(
    artifact: &str,
    vector: &TrustCardWireVector,
    label: &str,
) -> Result<String, String> {
    let path = workspace_artifact(artifact);
    std::fs::read_to_string(&path)
        .map(|contents| contents.trim_end_matches('\n').to_string())
        .map_err(|err| {
            format!(
                "{} {label} artifact {} must be readable: {err}",
                vector.name,
                path.display()
            )
        })
}

fn canonical_hash_preimage(card: &TrustCard) -> Result<String, String> {
    let mut value =
        serde_json::to_value(card).map_err(|err| format!("card must encode to JSON: {err}"))?;
    let object = value
        .as_object_mut()
        .ok_or_else(|| "trust-card JSON root must be an object".to_string())?;
    object.insert("card_hash".to_string(), Value::String(String::new()));
    object.insert(
        "registry_signature".to_string(),
        Value::String(String::new()),
    );
    to_canonical_json(&value).map_err(|err| format!("hash preimage canonicalization failed: {err}"))
}

fn card_hash_from_preimage(preimage: &str) -> Result<String, String> {
    let bytes = preimage.as_bytes();
    let byte_len = u64::try_from(bytes.len())
        .map_err(|err| format!("hash preimage length must fit u64: {err}"))?;
    let mut hasher = Sha256::new();
    hasher.update(TRUST_CARD_HASH_DOMAIN);
    hasher.update(byte_len.to_le_bytes());
    hasher.update(bytes);
    Ok(hex::encode(hasher.finalize()))
}

fn signature_preimage_hex(card_hash: &str) -> String {
    let mut bytes =
        Vec::with_capacity(TRUST_CARD_REGISTRY_SIGNATURE_DOMAIN.len() + card_hash.len());
    bytes.extend_from_slice(TRUST_CARD_REGISTRY_SIGNATURE_DOMAIN);
    bytes.extend_from_slice(card_hash.as_bytes());
    hex::encode(bytes)
}

fn registry_signature_from_preimage(
    registry_key_ascii: &str,
    signature_preimage_hex: &str,
) -> Result<String, String> {
    let bytes = hex::decode(signature_preimage_hex)
        .map_err(|err| format!("signature preimage hex must decode: {err}"))?;
    let mut mac = HmacSha256::new_from_slice(registry_key_ascii.as_bytes())
        .map_err(|err| format!("registry key must initialize HMAC: {err}"))?;
    mac.update(&bytes);
    Ok(hex::encode(mac.finalize().into_bytes()))
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
                "expected_hash_preimage_json": canonical_hash_preimage(&card)?,
                "expected_signature_preimage_hex": signature_preimage_hex(&card.card_hash),
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
fn trust_card_signing_preimages_match_canonical_artifacts() -> TestResult {
    let vectors = load_vectors()?;

    for vector in &vectors.vectors {
        let card = render_card(vector)?;
        let hash_preimage = canonical_hash_preimage(&card)?;
        let hash_preimage_artifact =
            vector
                .expected_hash_preimage_artifact
                .as_ref()
                .ok_or_else(|| {
                    format!(
                        "{} must declare expected_hash_preimage_artifact",
                        vector.name
                    )
                })?;
        let expected_hash_preimage =
            read_text_artifact(hash_preimage_artifact, vector, "expected hash preimage")?;
        assert_eq!(
            hash_preimage.as_bytes(),
            expected_hash_preimage.as_bytes(),
            "{} trust-card hash preimage bytes drifted from checked-in artifact",
            vector.name
        );
        assert_eq!(
            card_hash_from_preimage(&hash_preimage)?,
            card.card_hash,
            "{} hash preimage must reproduce card_hash",
            vector.name
        );

        let signature_preimage = signature_preimage_hex(&card.card_hash);
        let signature_preimage_artifact = vector
            .expected_signature_preimage_hex_artifact
            .as_ref()
            .ok_or_else(|| {
                format!(
                    "{} must declare expected_signature_preimage_hex_artifact",
                    vector.name
                )
            })?;
        let expected_signature_preimage = read_text_artifact(
            signature_preimage_artifact,
            vector,
            "expected signature preimage",
        )?;
        assert_eq!(
            signature_preimage, expected_signature_preimage,
            "{} trust-card signature preimage bytes drifted from checked-in artifact",
            vector.name
        );
        assert_eq!(
            registry_signature_from_preimage(
                &vector.registry_key_ascii,
                &expected_signature_preimage,
            )?,
            card.registry_signature,
            "{} signature preimage must reproduce registry_signature",
            vector.name
        );
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
