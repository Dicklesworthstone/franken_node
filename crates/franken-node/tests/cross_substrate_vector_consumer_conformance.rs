use frankenengine_node::connector::vef_execution_receipt::{
    ExecutionReceipt, RECEIPT_SCHEMA_VERSION, validate_receipt,
};
use frankenengine_node::security::decision_receipt::{
    DECISION_RECEIPT_SIGNATURE_VERSION, Receipt,
};
use frankenengine_node::supply_chain::manifest::SignedExtensionManifest;
use serde::Deserialize;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

type TestResult = Result<(), String>;

#[derive(Debug, Deserialize)]
struct PublishedVectorsIndex {
    schema_version: String,
    source_bead_id: String,
    source_version: String,
    vectors: Vec<PublishedVectorEntry>,
}

#[derive(Debug, Deserialize)]
struct PublishedVectorEntry {
    id: String,
    path: String,
    media_type: String,
    rust_type: String,
    source_fixture: String,
    proves: String,
}

fn workspace_root() -> Result<PathBuf, String> {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| "workspace root missing".to_string())
}

fn read_workspace_bytes(relative_path: &str) -> Result<Vec<u8>, String> {
    const MAX_VECTOR_BYTES: u64 = 16 * 1024 * 1024; // 16 MB limit for conformance vectors

    let path = workspace_root()?.join(relative_path);

    // Check file size before reading to prevent memory exhaustion DoS attacks
    let metadata = std::fs::metadata(&path)
        .map_err(|err| format!("{} metadata must be readable: {err}", path.display()))?;

    if metadata.len() > MAX_VECTOR_BYTES {
        return Err(format!(
            "{} size {} bytes exceeds maximum {} bytes for conformance vectors",
            path.display(),
            metadata.len(),
            MAX_VECTOR_BYTES
        ));
    }

    std::fs::read(&path).map_err(|err| format!("{} must be readable: {err}", path.display()))
}

fn load_index() -> Result<PublishedVectorsIndex, String> {
    let bytes = read_workspace_bytes("artifacts/conformance_vectors/v1/index.json")?;
    serde_json::from_slice(&bytes).map_err(|err| format!("published vector index must parse: {err}"))
}

#[test]
fn published_conformance_vectors_remain_parseable() -> TestResult {
    let index = load_index()?;
    assert_eq!(
        index.schema_version,
        "franken-node/conformance-vectors/v1"
    );
    assert_eq!(index.source_bead_id, "bd-3humk");
    assert_eq!(index.source_version, "v1");
    assert_eq!(index.vectors.len(), 3);

    let expected_ids = BTreeSet::from([
        "decision_receipt".to_string(),
        "supply_chain_attestation_manifest".to_string(),
        "vef_execution_receipt".to_string(),
    ]);
    let actual_ids = index
        .vectors
        .iter()
        .map(|entry| entry.id.clone())
        .collect::<BTreeSet<_>>();
    assert_eq!(actual_ids, expected_ids);

    for vector in &index.vectors {
        assert_eq!(
            vector.media_type, "application/json",
            "{} must publish JSON for cross-substrate consumers",
            vector.id
        );
        assert!(
            !vector.rust_type.trim().is_empty(),
            "{} must declare the consuming Rust type",
            vector.id
        );
        assert!(
            !vector.source_fixture.trim().is_empty(),
            "{} must declare its source fixture",
            vector.id
        );
        assert!(
            !vector.proves.trim().is_empty(),
            "{} must explain what it proves",
            vector.id
        );

        let bytes = read_workspace_bytes(&vector.path)?;
        match vector.id.as_str() {
            "decision_receipt" => {
                let receipt: Receipt = serde_json::from_slice(&bytes)
                    .map_err(|err| format!("decision receipt vector must parse: {err}"))?;
                assert_eq!(receipt.action_name, "quarantine_extension");
                assert_eq!(
                    receipt.signature_version,
                    DECISION_RECEIPT_SIGNATURE_VERSION
                );
                assert!(receipt.confidence.is_finite());
            }
            "supply_chain_attestation_manifest" => {
                let manifest: SignedExtensionManifest = serde_json::from_slice(&bytes)
                    .map_err(|err| format!("supply-chain manifest vector must parse: {err}"))?;
                manifest
                    .validate()
                    .map_err(|err| format!("supply-chain manifest vector must validate: {err}"))?;
                assert_eq!(manifest.package.name, "auth-guard");
            }
            "vef_execution_receipt" => {
                let receipt: ExecutionReceipt = serde_json::from_slice(&bytes)
                    .map_err(|err| format!("VEF receipt vector must parse: {err}"))?;
                validate_receipt(&receipt)
                    .map_err(|err| format!("VEF receipt vector must validate: {err}"))?;
                assert_eq!(receipt.schema_version, RECEIPT_SCHEMA_VERSION);
            }
            other => return Err(format!("unexpected published vector id: {other}")),
        }
    }

    Ok(())
}
