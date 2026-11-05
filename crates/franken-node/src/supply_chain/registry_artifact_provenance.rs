//! Publisher provenance bound to the existing signed registry manifest.
//!
//! This verifies the publisher's statement and its admission-time validity.
//! It does not establish an independently reproduced build, an external
//! builder's endorsement, or a live signer-revocation service.

use anyhow::{Context, Result};
use ed25519_dalek::VerifyingKey;
use std::io;

use super::super::{
    artifact_signing::{KeyId, verify_signature},
    extension_registry::ExtensionRegistrationManifest,
    provenance::{
        AttestationEnvelopeFormat, ProvenanceAttestation, ProvenanceLevel, VerificationErrorCode,
        VerificationMode, VerificationPolicy, canonical_attestation_json, verify_attestation_chain,
    },
};
use super::{
    ArtifactVerificationError, ArtifactVerificationFailure, LocalRegistryArtifactManifest,
    MAX_ARTIFACT_BYTES, artifact_sha256, failure,
};

const SIGNATURE_SCOPE: &str = "registry_publish_provenance_v1";
const SIGNATURE_CLAIM: &str = "operator_provenance_signature";
const PROOF_CLAIMS: [&str; 3] = [
    SIGNATURE_CLAIM,
    "operator_key_id",
    "operator_signature_scope",
];

/// Count before cloning or canonicalizing so library callers share the file
/// reader's complete attestation bound, including ordinary metadata strings.
fn ensure_bounded_attestation(provenance: &ProvenanceAttestation) -> Result<()> {
    struct Bound {
        bytes: u64,
    }
    impl io::Write for Bound {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            let size = u64::try_from(bytes.len())
                .map_err(|_| io::Error::other("publisher provenance exceeds its byte bound"))?;
            self.bytes = self
                .bytes
                .checked_add(size)
                .filter(|size| *size <= MAX_ARTIFACT_BYTES)
                .ok_or_else(|| io::Error::other("publisher provenance exceeds its byte bound"))?;
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    serde_json::to_writer(&mut Bound { bytes: 0 }, provenance)
        .context("publisher provenance exceeds its byte bound")?;
    Ok(())
}

/// The original CLI signing preimage, shared by publication and admission.
/// Only the self signature and subsequently populated link signatures are
/// removed. All provenance fields, link identities/validity/revocation flags,
/// custom claims and exact manifest bytes remain authenticated.
pub fn registry_publish_provenance_signature_payload(
    manifest_bytes: &[u8],
    provenance: &ProvenanceAttestation,
) -> Result<Vec<u8>> {
    anyhow::ensure!(
        manifest_bytes.len() as u64 <= MAX_ARTIFACT_BYTES,
        "publisher provenance manifest exceeds its byte bound"
    );
    ensure_bounded_attestation(provenance)?;
    let mut signable = provenance.clone();
    signable.custom_claims.remove(SIGNATURE_CLAIM);
    for link in &mut signable.links {
        link.signature.clear();
    }
    let canonical = canonical_attestation_json(&signable)
        .context("failed canonicalizing registry publish provenance")?;
    anyhow::ensure!(
        canonical.len() as u64 <= MAX_ARTIFACT_BYTES,
        "canonical publisher provenance exceeds its byte bound"
    );
    let mut payload = Vec::new();
    payload.extend_from_slice(b"registry_publish_provenance_v1:");
    payload.extend_from_slice(&u64::try_from(manifest_bytes.len())?.to_le_bytes());
    payload.extend_from_slice(manifest_bytes);
    payload.extend_from_slice(&u64::try_from(canonical.len())?.to_le_bytes());
    payload.extend_from_slice(canonical.as_bytes());
    Ok(payload)
}

pub(super) fn verify_publisher_provenance(
    envelope: &LocalRegistryArtifactManifest,
    signed: &ExtensionRegistrationManifest,
    manifest_bytes: &[u8],
    publisher: &VerifyingKey,
    artifact_hash: &str,
) -> std::result::Result<Option<String>, ArtifactVerificationError> {
    if !PROOF_CLAIMS.iter().any(|claim| {
        envelope
            .extension
            .provenance
            .custom_claims
            .contains_key(*claim)
    }) && signed.runtime_authority.is_none()
    {
        return Ok(None);
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| {
            failure(
                ArtifactVerificationFailure::InvalidMetadata,
                "publisher provenance admission clock is unavailable",
            )
        })?
        .as_secs();
    verify_publisher_provenance_at(
        envelope,
        signed,
        manifest_bytes,
        publisher,
        artifact_hash,
        now,
    )
}

pub(super) fn verify_publisher_provenance_at(
    envelope: &LocalRegistryArtifactManifest,
    signed: &ExtensionRegistrationManifest,
    manifest_bytes: &[u8],
    publisher: &VerifyingKey,
    artifact_hash: &str,
    now_epoch: u64,
) -> std::result::Result<Option<String>, ArtifactVerificationError> {
    use ArtifactVerificationFailure::{InvalidMetadata, InvalidSignature};
    let provenance = &envelope.extension.provenance;
    let claims = &provenance.custom_claims;
    if !PROOF_CLAIMS.iter().any(|claim| claims.contains_key(*claim))
        && signed.runtime_authority.is_none()
    {
        // A legacy source-only import makes no authenticated provenance claim.
        return Ok(None);
    }
    if provenance.schema_version != "1.0"
        || provenance.envelope_format != AttestationEnvelopeFormat::FrankenNodeEnvelopeV1
    {
        return Err(failure(
            InvalidMetadata,
            "publisher provenance uses an unsupported schema or envelope format",
        ));
    }
    let key_id = KeyId::from_verifying_key(publisher).to_string();
    if claims.get("operator_key_id") != Some(&key_id)
        || claims.get("operator_signature_scope").map(String::as_str) != Some(SIGNATURE_SCOPE)
        || provenance.builder_identity != signed.publisher_id
        || provenance.output_hash != artifact_hash
    {
        return Err(failure(
            InvalidMetadata,
            "publisher provenance is missing or does not bind the publisher, scope and artifact",
        ));
    }
    let signature = claims
        .get(SIGNATURE_CLAIM)
        .ok_or_else(|| failure(InvalidMetadata, "publisher provenance signature is missing"))?;
    if signature.len() != 128
        || !signature
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(failure(
            InvalidSignature,
            "publisher provenance signature is not canonical Ed25519 hex",
        ));
    }
    let signature = hex::decode(signature).map_err(|_| {
        failure(
            InvalidSignature,
            "publisher provenance signature encoding is invalid",
        )
    })?;
    let payload = registry_publish_provenance_signature_payload(manifest_bytes, provenance)
        .map_err(|_| {
            failure(
                InvalidMetadata,
                "publisher provenance exceeds its bounds or cannot be canonicalized",
            )
        })?;
    verify_signature(publisher, &payload, &signature).map_err(|_| {
        failure(
            InvalidSignature,
            "publisher provenance signature verification failed",
        )
    })?;

    // The existing verifier checks real link signatures, order, expiry, future
    // issuance and revoked flags. Only the independently pinned publisher key
    // is trusted: additional claimed builder roles do not supply new anchors.
    let mut policy = VerificationPolicy::development_profile();
    policy.mode = VerificationMode::FailClosed;
    policy.cached_trust_window_secs = 0;
    policy.allow_self_signed = false;
    policy.min_level = ProvenanceLevel::Level1PublisherSigned;
    // Validate the canonical position of every optional link as well as the
    // mandatory publisher link. The verifier independently bounds this to three.
    policy.required_chain_depth = provenance.links.len().max(1);
    policy.add_trusted_signer_key(key_id, publisher);
    let report =
        verify_attestation_chain(provenance, &policy, now_epoch, "registry-source-admission");
    if !report.chain_valid {
        let kind = if report
            .issues
            .iter()
            .any(|issue| issue.code == VerificationErrorCode::InvalidSignature)
        {
            InvalidSignature
        } else {
            InvalidMetadata
        };
        // Do not echo arbitrary signer IDs, claims or private build metadata.
        let codes = report
            .issues
            .iter()
            .map(|issue| format!("{:?}", issue.code))
            .collect::<Vec<_>>()
            .join(", ");
        return Err(failure(
            kind,
            format!("publisher provenance chain verification failed: {codes}"),
        ));
    }
    let canonical = canonical_attestation_json(provenance).map_err(|_| {
        failure(
            InvalidMetadata,
            "publisher provenance cannot be canonicalized",
        )
    })?;
    Ok(Some(artifact_sha256(canonical.as_bytes())))
}
