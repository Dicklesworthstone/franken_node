//! Golden artifact test for supply chain attestation manifest JSON format
//!
//! Tests that signed extension manifest JSON serialization remains stable across versions.
//! Supply chain manifests contain cryptographic signatures and provenance attestations,
//! and any format change would break signature validation and trust chain verification.

use frankenengine_node::supply_chain::manifest::{
    AttestationRef, BehavioralProfile, CertificationLevel, ManifestSignature, PackageIdentity,
    ProvenanceEnvelope, RiskTier, SignatureScheme, SignedExtensionManifest,
    ThresholdSignaturePolicy, TrustMetadata, validate_signed_manifest,
};
use serde_json::Value;
use std::{error::Error, fs, path::Path, path::PathBuf};

/// Resolve a path relative to the workspace root. Integration tests run with a
/// CWD of the package dir (`crates/franken-node/`), but this golden lives at the
/// workspace root under `artifacts/golden/`, so a bare relative path would look
/// in the wrong place. `CARGO_MANIFEST_DIR` is `crates/franken-node`, so `../..`
/// reaches the workspace root deterministically regardless of CWD.
fn workspace_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..").join(relative)
}

const DETERMINISTIC_THRESHOLD_SIGNATURE: &str =
    "aJKWADQBpYEpQ+WF+MHY2a9fkVHBcxspfTW035PGNVVn3LKmDcvpVLeEqXHgbqj3r1xK52hlvtT8y938O3mq0w==";

/// Create a deterministic signed extension manifest for golden testing
fn create_deterministic_manifest() -> SignedExtensionManifest {
    // Create a manifest with fixed values to ensure deterministic output
    SignedExtensionManifest {
        schema_version: "1.0".to_string(),
        package: PackageIdentity {
            name: "example-extension".to_string(),
            version: "1.2.3".to_string(),
            publisher: "trusted-publisher@example.com".to_string(),
            author: "Example Extension Developer".to_string(),
        },
        entrypoint: "index.js".to_string(),
        capabilities: vec![
            frankenengine_extension_host::Capability::FsRead,
            frankenengine_extension_host::Capability::NetClient,
        ],
        behavioral_profile: BehavioralProfile {
            risk_tier: RiskTier::Medium,
            summary: "Data processing extension with controlled network access".to_string(),
            declared_network_zones: vec![
                "api.example.com".to_string(),
                "cdn.example.com".to_string(),
            ],
        },
        minimum_runtime_version: "0.1.0".to_string(),
        provenance: ProvenanceEnvelope {
            build_system: "GitHub Actions".to_string(),
            source_repository: "https://github.com/example/example-extension".to_string(),
            source_revision: "abc123def456789abc123def456789abc123def4".to_string(),
            reproducibility_markers: vec![
                "HERMETIC_BUILD=true".to_string(),
                "BUILD_TIMESTAMP=2026-01-01T00:00:00Z".to_string(),
            ],
            attestation_chain: vec![
                AttestationRef {
                    id: "attestation-001".to_string(),
                    attestation_type: "build_provenance".to_string(),
                    digest: "sha256:a1b2c3d4e5f6789a1b2c3d4e5f6789a1b2c3d4e5f6789a1b2c3d4e5f6789a1b2c3d4".to_string(),
                },
                AttestationRef {
                    id: "attestation-002".to_string(),
                    attestation_type: "source_review".to_string(),
                    digest: "sha256:f6e5d4c3b2a19876f6e5d4c3b2a19876f6e5d4c3b2a19876f6e5d4c3b2a19876f6e5".to_string(),
                },
            ],
        },
        trust: TrustMetadata {
            certification_level: CertificationLevel::Verified,
            revocation_status_pointer: "https://trust.example.com/revocation/example-extension".to_string(),
            trust_card_reference: "trust-card-ref-123456".to_string(),
        },
        signature: ManifestSignature {
            scheme: SignatureScheme::ThresholdEd25519,
            publisher_key_id: "pub-key-id-abcdef123456".to_string(),
            signature: DETERMINISTIC_THRESHOLD_SIGNATURE.to_string(),
            threshold: Some(ThresholdSignaturePolicy {
                threshold: 3,
                total_signers: 4,
                signer_key_ids: vec![
                    "signer-1-key-id".to_string(),
                    "signer-2-key-id".to_string(),
                    "signer-3-key-id".to_string(),
                    "signer-4-key-id".to_string(),
                ],
            }),
            signed_at: "2026-01-01T00:00:00Z".to_string(),
        },
    }
}

#[test]
fn supply_chain_attestation_manifest_json_format_golden() -> Result<(), Box<dyn Error>> {
    let manifest = create_deterministic_manifest();
    validate_manifest_signature_material(&manifest)?;

    // Serialize to pretty-printed JSON (this is the format that would be exported)
    let json_output = format!("{}\n", serde_json::to_string_pretty(&manifest)?);

    let golden_path = workspace_path("artifacts/golden/supply_chain_attestation_manifest.json");
    let golden_path = golden_path.as_path();

    // Check if we're in update mode
    if std::env::var("UPDATE_GOLDENS").is_ok() {
        if let Some(parent) = golden_path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(golden_path, &json_output)?;
        eprintln!("[GOLDEN] Updated: {}", golden_path.display());
        return Ok(());
    }

    // Read expected golden output
    let expected_json = fs::read_to_string(golden_path).map_err(|err| {
        format!(
            "Golden file missing: {}\n\
             Run with UPDATE_GOLDENS=1 to create it\n\
             Then review and commit: git diff artifacts/golden/: {err}",
            golden_path.display()
        )
    })?;

    // Compare byte-for-byte
    if json_output != expected_json {
        let actual_path =
            workspace_path("artifacts/golden/supply_chain_attestation_manifest.actual.json");
        let actual_path = actual_path.as_path();
        fs::write(actual_path, &json_output)?;
        assert_eq!(
            json_output,
            expected_json,
            "GOLDEN MISMATCH: Supply chain attestation manifest JSON format changed\n\n\
             This indicates a breaking change to manifest serialization\n\
             that could invalidate existing signatures and break trust chain verification.\n\n\
             To update: UPDATE_GOLDENS=1 cargo test supply_chain_attestation_manifest_json_format_golden\n\
             To review: diff {} {}",
            golden_path.display(),
            actual_path.display(),
        );
    }
    Ok(())
}

#[test]
fn supply_chain_attestation_manifest_schema_stability() -> Result<(), Box<dyn Error>> {
    let manifest = create_deterministic_manifest();
    validate_manifest_signature_material(&manifest)?;
    let json_value: Value = serde_json::to_value(&manifest)?;

    // Verify critical schema elements are present and correctly typed
    assert!(json_value.get("schema_version").unwrap().is_string());
    assert!(json_value.get("package").unwrap().is_object());
    assert!(json_value.get("entrypoint").unwrap().is_string());
    assert!(json_value.get("capabilities").unwrap().is_array());
    assert!(json_value.get("behavioral_profile").unwrap().is_object());
    assert!(
        json_value
            .get("minimum_runtime_version")
            .unwrap()
            .is_string()
    );
    assert!(json_value.get("provenance").unwrap().is_object());
    assert!(json_value.get("trust").unwrap().is_object());
    assert!(json_value.get("signature").unwrap().is_object());

    // Verify package identity structure
    let package = json_value.get("package").unwrap().as_object().unwrap();
    assert!(package.get("name").unwrap().is_string());
    assert!(package.get("version").unwrap().is_string());
    assert!(package.get("publisher").unwrap().is_string());
    assert!(package.get("author").unwrap().is_string());

    // Verify behavioral profile structure
    let profile = json_value
        .get("behavioral_profile")
        .unwrap()
        .as_object()
        .unwrap();
    assert!(profile.get("risk_tier").unwrap().is_string());
    assert!(profile.get("summary").unwrap().is_string());
    assert!(profile.get("declared_network_zones").unwrap().is_array());

    // Verify provenance envelope structure
    let provenance = json_value.get("provenance").unwrap().as_object().unwrap();
    assert!(provenance.get("build_system").unwrap().is_string());
    assert!(provenance.get("source_repository").unwrap().is_string());
    assert!(provenance.get("source_revision").unwrap().is_string());
    assert!(
        provenance
            .get("reproducibility_markers")
            .unwrap()
            .is_array()
    );
    assert!(provenance.get("attestation_chain").unwrap().is_array());

    // Verify trust metadata structure
    let trust = json_value.get("trust").unwrap().as_object().unwrap();
    assert!(trust.get("certification_level").unwrap().is_string());
    assert!(trust.get("revocation_status_pointer").unwrap().is_string());
    assert!(trust.get("trust_card_reference").unwrap().is_string());

    // Verify signature structure
    let signature = json_value.get("signature").unwrap().as_object().unwrap();
    assert!(signature.get("scheme").unwrap().is_string());
    assert!(signature.get("publisher_key_id").unwrap().is_string());
    assert!(signature.get("signature").unwrap().is_string());
    assert!(signature.get("threshold").unwrap().is_object());
    assert!(signature.get("signed_at").unwrap().is_string());
    let threshold = signature.get("threshold").unwrap().as_object().unwrap();
    assert!(threshold.get("threshold").unwrap().is_number());
    assert!(threshold.get("total_signers").unwrap().is_number());
    assert!(threshold.get("signer_key_ids").unwrap().is_array());

    // Verify enum serialization formats
    assert_eq!(
        profile.get("risk_tier").unwrap().as_str().unwrap(),
        "medium"
    );
    assert_eq!(
        trust.get("certification_level").unwrap().as_str().unwrap(),
        "verified"
    );
    assert_eq!(
        signature.get("scheme").unwrap().as_str().unwrap(),
        "threshold_ed25519"
    );
    Ok(())
}

#[test]
fn supply_chain_attestation_manifest_rejects_placeholder_signature_material() {
    let mut manifest = create_deterministic_manifest();
    manifest.signature.signature = format!(
        "{}{}",
        "base64-encoded-threshold-signature-data-place", "holder"
    );
    assert!(validate_manifest_signature_material(&manifest).is_err());

    manifest.signature.signature = format!("{}{}", "sent", "inel-signature-material");
    assert!(validate_manifest_signature_material(&manifest).is_err());
}

fn validate_manifest_signature_material(
    manifest: &SignedExtensionManifest,
) -> Result<(), Box<dyn Error>> {
    let lowered = manifest.signature.signature.to_ascii_lowercase();
    if lowered.contains("placeholder") || lowered.contains("sentinel") {
        return Err("manifest golden signature contains placeholder or sentinel material".into());
    }
    validate_signed_manifest(manifest)?;
    Ok(())
}
