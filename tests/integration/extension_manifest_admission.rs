//! Integration tests for bd-1gx signed extension manifest admission.

use frankenengine_extension_host::Capability;
use frankenengine_node::supply_chain::manifest::*;

fn valid_manifest() -> SignedExtensionManifest {
    SignedExtensionManifest {
        schema_version: MANIFEST_SCHEMA_VERSION.to_string(),
        package: PackageIdentity {
            name: "telemetry-bridge".to_string(),
            version: "0.4.0".to_string(),
            publisher: "publisher@example.com".to_string(),
            author: "author@example.com".to_string(),
        },
        entrypoint: "dist/index.js".to_string(),
        capabilities: vec![Capability::FsRead, Capability::NetworkEgress],
        behavioral_profile: BehavioralProfile {
            risk_tier: RiskTier::Medium,
            summary: "exports telemetry to trusted control plane".to_string(),
            declared_network_zones: vec!["prod-us-east".to_string()],
        },
        minimum_runtime_version: "0.1.0".to_string(),
        provenance: ProvenanceEnvelope {
            build_system: "github-actions".to_string(),
            source_repository: "https://example.com/extensions".to_string(),
            source_revision: "abcdef123456".to_string(),
            reproducibility_markers: vec!["reproducible=true".to_string()],
            attestation_chain: vec![AttestationRef {
                id: "att-1".to_string(),
                attestation_type: "slsa".to_string(),
                digest: "sha256:aaaabbbbcccc".to_string(),
            }],
        },
        trust: TrustMetadata {
            certification_level: CertificationLevel::Verified,
            revocation_status_pointer: "revocation://telemetry-bridge".to_string(),
            trust_card_reference: "trust-card://telemetry-bridge@0.4.0".to_string(),
        },
        signature: ManifestSignature {
            scheme: SignatureScheme::ThresholdEd25519,
            publisher_key_id: "publisher-key".to_string(),
            signature: "QUJDREVGR0hJSg==".to_string(),
            threshold: Some(ThresholdSignaturePolicy {
                threshold: 2,
                total_signers: 3,
                signer_key_ids: vec![
                    "key-a".to_string(),
                    "key-b".to_string(),
                    "key-c".to_string(),
                ],
            }),
            signed_at: "2026-02-20T00:00:00Z".to_string(),
        },
    }
}

#[test]
fn inv_ems_engine_compatibility_gate() {
    let manifest = valid_manifest();
    assert!(manifest.validate().is_ok(), "INV-EMS-ENGINE-COMPAT");
}

#[test]
fn inv_ems_signature_gate_fail_closed() {
    let mut manifest = valid_manifest();
    manifest.signature.signature = "nope!*".to_string();

    let error = manifest.validate().expect_err("bad signature must fail");
    assert_eq!(error.code(), "EMS_SIGNATURE_MALFORMED");
}

#[test]
fn inv_ems_threshold_policy_required() {
    let mut manifest = valid_manifest();
    manifest.signature.threshold = None;

    let error = manifest
        .validate()
        .expect_err("missing threshold policy must fail");
    assert_eq!(error.code(), "EMS_THRESHOLD_INVALID");
}

#[test]
fn inv_ems_attestation_chain_required() {
    let mut manifest = valid_manifest();
    manifest.provenance.attestation_chain.clear();

    let error = manifest.validate().expect_err("empty chain must fail");
    assert_eq!(error.code(), "EMS_MISSING_ATTESTATION_CHAIN");
}
