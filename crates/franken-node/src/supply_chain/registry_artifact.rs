//! Verification of persisted registry artifacts and publisher-approved source graphs.
//!
//! The local storage envelope is not a registry-service endorsement. Execution
//! admission requires a separately supplied publisher key, the signed package
//! identity, and the exact capsule bytes. It grants no capabilities or resources
//! and does not interpret the envelope's unsigned lifecycle or provenance claims.

use anyhow::{Context, Result};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Component, Path, PathBuf};

use super::artifact_signing::{KeyId, verify_signature};
use super::extension_registry::{
    EXTENSION_REGISTRATION_MANIFEST_SCHEMA, ExtensionRegistrationManifest, SignedExtension,
};

pub const LOCAL_ARTIFACT_SCHEMA: &str = "franken-node/local-registry-artifact-manifest/v1";
/// Match the installed registry's artifact and manifest input bound.
pub const MAX_ARTIFACT_BYTES: u64 = 5 << 20;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LocalRegistryArtifactManifest {
    pub schema_version: String,
    pub stored_at_utc: String,
    pub artifact_file_name: String,
    pub artifact_sha256: String,
    pub artifact_size_bytes: u64,
    pub manifest_bytes_b64: String,
    pub publisher_public_key_hex: String,
    pub extension: SignedExtension,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactVerificationFailure {
    HashMismatch,
    InvalidSignature,
    InvalidMetadata,
}

#[derive(Debug, thiserror::Error)]
#[error("{detail}")]
pub struct ArtifactVerificationError {
    pub kind: ArtifactVerificationFailure,
    pub detail: String,
}

fn failure(
    kind: ArtifactVerificationFailure,
    detail: impl Into<String>,
) -> ArtifactVerificationError {
    ArtifactVerificationError {
        kind,
        detail: detail.into(),
    }
}

pub fn artifact_sha256(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

pub fn artifact_file_name_is_safe(value: &str) -> bool {
    if value.is_empty() || value.contains('\0') || value.contains('/') || value.contains('\\') {
        return false;
    }
    let mut parts = Path::new(value).components();
    matches!(parts.next(), Some(Component::Normal(_))) && parts.next().is_none()
}

/// Source-free claims authenticated by the publisher's registration signature.
/// The registry-generated extension ID, lifecycle and provenance are deliberately
/// absent: they are not fields of that signed registration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublisherArtifactIdentity {
    pub publisher_key_id: String,
    pub publisher_id: String,
    pub name: String,
    pub version: String,
    pub artifact_sha256: String,
}

/// The registry inspector may check self-consistency without a trust anchor.
/// Execution callers MUST pass their independently retained publisher key.
/// Both paths share every signature and signed-field binding check below.
pub fn verify_artifact_bytes(
    envelope: &LocalRegistryArtifactManifest,
    bytes: &[u8],
    trusted_publisher: Option<&VerifyingKey>,
) -> std::result::Result<PublisherArtifactIdentity, ArtifactVerificationError> {
    use ArtifactVerificationFailure::{HashMismatch, InvalidMetadata, InvalidSignature};
    if envelope.schema_version != LOCAL_ARTIFACT_SCHEMA
        || !artifact_file_name_is_safe(&envelope.artifact_file_name)
        || bytes.len() as u64 > MAX_ARTIFACT_BYTES
        || envelope.manifest_bytes_b64.len() as u64 > MAX_ARTIFACT_BYTES
    {
        return Err(failure(
            InvalidMetadata,
            "invalid or oversized local registry artifact metadata",
        ));
    }
    let version_hash = envelope
        .extension
        .versions
        .last()
        .ok_or_else(|| {
            failure(
                InvalidMetadata,
                "extension has no registered version lineage",
            )
        })?
        .content_hash
        .as_str();
    if !crate::security::constant_time::ct_eq(
        version_hash,
        envelope
            .artifact_sha256
            .strip_prefix("sha256:")
            .unwrap_or(&envelope.artifact_sha256),
    ) {
        return Err(failure(
            InvalidMetadata,
            "manifest hash does not match version lineage hash",
        ));
    }
    let actual_hash = artifact_sha256(bytes);
    if !crate::security::constant_time::ct_eq(&actual_hash, &envelope.artifact_sha256) {
        return Err(failure(
            HashMismatch,
            format!(
                "artifact hash mismatch: expected {} got {actual_hash}",
                envelope.artifact_sha256
            ),
        ));
    }
    if envelope.extension.signature.algorithm != "ed25519" {
        return Err(failure(
            InvalidSignature,
            "unsupported manifest signature algorithm",
        ));
    }
    let manifest_bytes = STANDARD
        .decode(&envelope.manifest_bytes_b64)
        .map_err(|error| {
            failure(
                InvalidMetadata,
                format!("failed decoding manifest bytes: {error}"),
            )
        })?;
    let public_key_bytes = hex::decode(&envelope.publisher_public_key_hex).map_err(|error| {
        failure(
            InvalidMetadata,
            format!("failed decoding publisher key hex: {error}"),
        )
    })?;
    let public_key_array: [u8; 32] = public_key_bytes
        .as_slice()
        .try_into()
        .map_err(|_| failure(InvalidMetadata, "publisher public key was not 32 bytes"))?;
    let verifying_key = VerifyingKey::from_bytes(&public_key_array).map_err(|error| {
        failure(
            InvalidMetadata,
            format!("failed constructing verifying key: {error}"),
        )
    })?;
    let key_id = KeyId::from_verifying_key(&verifying_key).to_string();
    if key_id != envelope.extension.signature.key_id {
        return Err(failure(InvalidMetadata, "publisher key id mismatch"));
    }
    if trusted_publisher.is_some_and(|trusted| trusted != &verifying_key) {
        return Err(failure(
            InvalidSignature,
            "publisher does not match the independently supplied public key",
        ));
    }
    verify_signature(
        &verifying_key,
        &manifest_bytes,
        &envelope.extension.signature.signature_bytes,
    )
    .map_err(|error| {
        failure(
            InvalidSignature,
            format!("manifest signature verification failed: {error}"),
        )
    })?;
    let signed: ExtensionRegistrationManifest =
        serde_json::from_slice(&manifest_bytes).map_err(|error| {
            failure(
                InvalidMetadata,
                format!("invalid signed extension registration manifest: {error}"),
            )
        })?;
    let extension = &envelope.extension;
    let binding_error = if signed.schema_version != EXTENSION_REGISTRATION_MANIFEST_SCHEMA {
        Some("unsupported signed extension registration manifest schema")
    } else if signed.name != extension.name {
        Some("signed manifest name does not match stored extension name")
    } else if signed.publisher_id != extension.publisher_id {
        Some("signed manifest publisher_id does not match stored extension publisher")
    } else if extension.versions.as_slice() != std::slice::from_ref(&signed.initial_version) {
        Some("stored artifact version lineage does not match signed initial_version")
    } else if signed.tags != extension.tags {
        Some("signed manifest tags do not match stored extension tags")
    } else if bytes.len() as u64 != envelope.artifact_size_bytes {
        Some("stored artifact size does not match actual package bytes")
    } else {
        None
    };
    if let Some(detail) = binding_error {
        return Err(failure(InvalidMetadata, detail));
    }
    Ok(PublisherArtifactIdentity {
        publisher_key_id: key_id,
        publisher_id: signed.publisher_id,
        name: signed.name,
        version: signed.initial_version.version,
        artifact_sha256: actual_hash,
    })
}

/// Resolve relative CLI input once, without following any symlink or accepting
/// parent traversal. The descriptor reader below enforces every path component.
pub fn absolute_artifact_path(path: &Path) -> Result<PathBuf> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    anyhow::ensure!(
        absolute.as_os_str().len() <= 4096,
        "artifact path exceeds its bound"
    );
    let mut normalized = PathBuf::new();
    for part in absolute.components() {
        match part {
            Component::RootDir | Component::Normal(_) => normalized.push(part.as_os_str()),
            Component::CurDir => {}
            _ => anyhow::bail!("artifact path must not contain parent traversal"),
        }
    }
    anyhow::ensure!(
        normalized.file_name().is_some(),
        "artifact path must name a file"
    );
    Ok(normalized)
}

#[cfg(unix)]
fn artifact_parent(path: &Path) -> Result<(std::fs::File, std::ffi::OsString)> {
    use rustix::fs::{Mode, OFlags, open, openat};
    let absolute = absolute_artifact_path(path)?;
    let parts = absolute.components().collect::<Vec<_>>();
    anyhow::ensure!(
        parts.len() <= 128,
        "artifact path exceeds its component bound"
    );
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut directory = std::fs::File::from(open("/", flags, Mode::empty())?);
    for part in &parts[..parts.len() - 1] {
        if let Component::Normal(name) = part {
            directory = std::fs::File::from(openat(&directory, *name, flags, Mode::empty())?);
        }
    }
    Ok((
        directory,
        absolute.file_name().expect("checked file name").to_owned(),
    ))
}

/// Bounded, descriptor-relative read with no symlink components. Hashes and
/// signatures are checked over this returned buffer, never a subsequent reopen.
pub fn read_artifact_file(path: &Path, limit: u64) -> Result<Vec<u8>> {
    #[cfg(not(unix))]
    {
        let _ = (path, limit);
        anyhow::bail!("registry source admission requires Unix");
    }
    #[cfg(unix)]
    {
        use rustix::fs::{Mode, OFlags, openat};
        use std::io::Read;
        let (directory, name) = artifact_parent(path).with_context(|| {
            format!(
                "cannot open artifact parent without symlinks: {}",
                path.display()
            )
        })?;
        let file = std::fs::File::from(openat(
            &directory,
            name.as_os_str(),
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )?);
        let metadata = file.metadata()?;
        anyhow::ensure!(
            metadata.is_file() && metadata.len() <= limit,
            "artifact must be a regular file within its {limit}-byte bound"
        );
        let mut bytes = Vec::new();
        file.take(limit.saturating_add(1)).read_to_end(&mut bytes)?;
        anyhow::ensure!(
            bytes.len() as u64 <= limit,
            "artifact grew beyond its byte bound"
        );
        Ok(bytes)
    }
}

/// Explicit source export only: new owner-only file, no clobber, no symlink
/// components. A failed write leaves its partial file for operator inspection.
#[cfg(unix)]
pub fn write_new_source_capsule(path: &Path, bytes: &[u8]) -> Result<()> {
    use rustix::fs::{Mode, OFlags, openat};
    use std::io::Write;
    let (directory, name) = artifact_parent(path)?;
    let mut file = std::fs::File::from(openat(
        &directory,
        name.as_os_str(),
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )?);
    file.write_all(bytes)?;
    file.sync_all()?;
    directory.sync_all()?;
    Ok(())
}

/// Small immutable handoff through the authenticated native worker channel.
/// Capsule contents remain in the registry artifact, not in the control frame.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublisherSourceGraphApproval {
    manifest_path: PathBuf,
    manifest_sha256: String,
    publisher_public_key_hex: String,
    identity: PublisherArtifactIdentity,
    capsule_digest: String,
    graph_input_hash: String,
    entrypoint: String,
    additional_conditions: Vec<String>,
    contained_symlinks: bool,
}

impl PublisherSourceGraphApproval {
    pub fn load(manifest_path: &Path, trusted_publisher: &VerifyingKey) -> Result<Self> {
        #[cfg(not(unix))]
        {
            let _ = (manifest_path, trusted_publisher);
            anyhow::bail!("registry source admission requires Unix");
        }
        #[cfg(unix)]
        {
            #[cfg(feature = "engine")]
            use super::module_resolution_graph::file_resolution::source_graph::engine_resolver::CapturedEngineResolver;
            use super::module_resolution_graph::file_resolution::{
                SymlinkPolicy, source_graph::capsule,
            };
            let manifest_path = absolute_artifact_path(manifest_path)?;
            let manifest_bytes = read_artifact_file(&manifest_path, MAX_ARTIFACT_BYTES)?;
            let manifest: LocalRegistryArtifactManifest =
                serde_json::from_slice(&manifest_bytes)
                    .context("invalid local registry artifact manifest")?;
            anyhow::ensure!(
                artifact_file_name_is_safe(&manifest.artifact_file_name),
                "registry artifact file name is unsafe"
            );
            let bytes = read_artifact_file(
                &manifest_path.with_file_name(&manifest.artifact_file_name),
                MAX_ARTIFACT_BYTES,
            )?;
            let identity = verify_artifact_bytes(&manifest, &bytes, Some(trusted_publisher))?;
            // This digest is safe to derive here because the external publisher
            // signature has already authenticated the raw artifact SHA-256.
            let capsule_digest = capsule::digest(&bytes);
            let graph = capsule::replay(&bytes, &capsule_digest)
                .context("registry artifact is not a valid module source capsule")?;
            let report = graph.report();
            // A closed native graph can contain source-free builtin providers
            // and sealed, catchable failures for optional dependencies. Those
            // observations deliberately leave `fully_resolved` false. Use the
            // same closure admission as execution instead of rejecting useful
            // signed packages or maintaining a second provider allowlist here.
            // This performs no source normalization and grants no capabilities;
            // the worker still prepares this graph with its current parser and
            // policy limits before evaluation.
            #[cfg(feature = "engine")]
            CapturedEngineResolver::validate_source_closure(&graph, &report.input_hash)
                .context("registry source capsule is not admitted by the native module resolver")?;
            #[cfg(not(feature = "engine"))]
            anyhow::ensure!(
                report.fully_resolved,
                "registry source capsule requires native engine closure admission"
            );
            anyhow::ensure!(
                report.options.conditions.is_none(),
                "registry source capsule overrides the native import/require conditions"
            );
            let approval = Self {
                manifest_path,
                manifest_sha256: artifact_sha256(&manifest_bytes),
                publisher_public_key_hex: hex::encode(trusted_publisher.as_bytes()),
                identity,
                capsule_digest,
                graph_input_hash: report.input_hash.clone(),
                entrypoint: report.entrypoint.clone(),
                additional_conditions: report.options.additional_conditions.clone(),
                contained_symlinks: report.options.symlink_policy == SymlinkPolicy::Contained,
            };
            approval.validate()?;
            Ok(approval)
        }
    }

    pub fn graph_input_hash(&self) -> &str {
        &self.graph_input_hash
    }
    pub fn identity(&self) -> &PublisherArtifactIdentity {
        &self.identity
    }

    pub fn validate(&self) -> Result<()> {
        fn valid_hash(value: &str) -> bool {
            value.strip_prefix("sha256:").is_some_and(|digest| {
                digest.len() == 64
                    && digest
                        .bytes()
                        .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            })
        }
        anyhow::ensure!(
            self.manifest_path.is_absolute()
                && absolute_artifact_path(&self.manifest_path)? == self.manifest_path,
            "registry approval path is not absolute and normalized"
        );
        anyhow::ensure!(
            [
                &self.manifest_sha256,
                &self.identity.artifact_sha256,
                &self.capsule_digest,
                &self.graph_input_hash,
            ]
            .into_iter()
            .all(|hash| valid_hash(hash)),
            "registry approval contains an invalid commitment"
        );
        anyhow::ensure!(
            self.publisher_public_key_hex.len() == 64
                && self.identity.publisher_key_id.len() <= 256
                && self.identity.publisher_id.len() <= 256
                && self.identity.name.len() <= 256
                && self.identity.version.len() <= 128
                && self.entrypoint.len() <= 4096
                && self.additional_conditions.len() <= 62
                && self
                    .additional_conditions
                    .iter()
                    .all(|condition| !condition.is_empty() && condition.len() <= 128),
            "registry approval exceeds its identity bound"
        );
        Ok(())
    }

    /// Reauthenticate the exact parent-approved envelope and capsule; another
    /// valid artifact signed by the same publisher is not an interchangeable run.
    pub fn revalidate(&self) -> Result<()> {
        self.validate()?;
        let bytes = hex::decode(&self.publisher_public_key_hex)?;
        let key: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .context("invalid retained publisher key")?;
        let observed = Self::load(&self.manifest_path, &VerifyingKey::from_bytes(&key)?)?;
        anyhow::ensure!(
            &observed == self,
            "registry artifact changed after publisher admission"
        );
        Ok(())
    }

    pub fn validate_run(
        &self,
        entrypoint: &str,
        frozen_modules: bool,
        contained_symlinks: bool,
        conditions: &[String],
        explicit_graph_hash: Option<&str>,
    ) -> Result<()> {
        self.validate()?;
        anyhow::ensure!(
            frozen_modules,
            "--registry-artifact requires frozen modules"
        );
        anyhow::ensure!(
            entrypoint == self.entrypoint,
            "run entrypoint does not match publisher-approved source capsule"
        );
        anyhow::ensure!(
            contained_symlinks == self.contained_symlinks,
            "run symlink policy does not match publisher-approved source capsule"
        );
        let mut conditions = conditions.to_vec();
        conditions.sort();
        conditions.dedup();
        anyhow::ensure!(
            conditions == self.additional_conditions,
            "run conditions do not match publisher-approved source capsule"
        );
        anyhow::ensure!(
            explicit_graph_hash.is_none_or(|hash| hash == self.graph_input_hash),
            "explicit frozen module graph pin conflicts with publisher-approved source capsule"
        );
        Ok(())
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::supply_chain::{
        artifact_signing::sign_bytes,
        extension_registry::{
            ExtensionSignature, ExtensionStatus, VersionEntry,
            canonical_registration_manifest_bytes,
        },
        module_resolution_graph::file_resolution::source_graph::{GraphOptions, capsule, capture},
        provenance::{AttestationEnvelopeFormat, ProvenanceAttestation},
    };

    struct Fixture {
        directory: tempfile::TempDir,
        manifest_path: PathBuf,
        manifest: LocalRegistryArtifactManifest,
        bytes: Vec<u8>,
        key: ed25519_dalek::SigningKey,
        graph_hash: String,
    }

    impl Fixture {
        fn new(source: &str) -> Self {
            Self::with_entrypoint("app.cjs", source)
        }

        fn with_entrypoint(entrypoint: &str, source: &str) -> Self {
            let directory = tempfile::tempdir().unwrap();
            std::fs::write(directory.path().join(entrypoint), source).unwrap();
            std::fs::write(directory.path().join("side.cjs"), "module.exports = 42;\n").unwrap();
            let graph = capture(directory.path(), entrypoint, GraphOptions::default()).unwrap();
            let graph_hash = graph.report().input_hash.clone();
            let bytes = capsule::encode(&graph).unwrap().bytes().to_vec();
            let key = ed25519_dalek::SigningKey::from_bytes(&[42; 32]);
            let hash = artifact_sha256(&bytes);
            let timestamp = "2026-11-03T00:00:00Z".to_owned();
            let version = VersionEntry {
                version: "1.2.3".into(),
                parent_version: None,
                content_hash: hash.strip_prefix("sha256:").unwrap().to_owned(),
                registered_at: timestamp.clone(),
                compatible_with: vec!["franken-node".into()],
            };
            let signed =
                canonical_registration_manifest_bytes("source", "publisher", &version, &[])
                    .unwrap();
            let manifest = LocalRegistryArtifactManifest {
                schema_version: LOCAL_ARTIFACT_SCHEMA.into(),
                stored_at_utc: timestamp.clone(),
                artifact_file_name: "source.capsule".into(),
                artifact_sha256: hash,
                artifact_size_bytes: bytes.len() as u64,
                manifest_bytes_b64: STANDARD.encode(&signed),
                publisher_public_key_hex: hex::encode(key.verifying_key().as_bytes()),
                extension: SignedExtension {
                    extension_id: "unsigned-registry-id".into(),
                    name: "source".into(),
                    description: String::new(),
                    publisher_id: "publisher".into(),
                    status: ExtensionStatus::Active,
                    signature: ExtensionSignature {
                        key_id: KeyId::from_verifying_key(&key.verifying_key()).to_string(),
                        algorithm: "ed25519".into(),
                        signature_bytes: sign_bytes(&key, &signed),
                        signed_at: timestamp.clone(),
                    },
                    // No provenance assurance is claimed by this handoff. Only
                    // fields actually covered by the publisher signature pass.
                    provenance: ProvenanceAttestation {
                        schema_version: "1.0".into(),
                        source_repository_url: String::new(),
                        build_system_identifier: String::new(),
                        builder_identity: String::new(),
                        builder_version: String::new(),
                        vcs_commit_sha: String::new(),
                        build_timestamp_epoch: 0,
                        reproducibility_hash: String::new(),
                        input_hash: String::new(),
                        output_hash: String::new(),
                        slsa_level_claim: 0,
                        envelope_format: AttestationEnvelopeFormat::FrankenNodeEnvelopeV1,
                        links: Vec::new(),
                        custom_claims: Default::default(),
                    },
                    versions: vec![version],
                    tags: Vec::new(),
                    registered_at: timestamp.clone(),
                    updated_at: timestamp,
                },
            };
            let manifest_path = directory.path().join("artifact.manifest.json");
            std::fs::write(&manifest_path, serde_json::to_vec(&manifest).unwrap()).unwrap();
            std::fs::write(directory.path().join(&manifest.artifact_file_name), &bytes).unwrap();
            Self {
                directory,
                manifest_path,
                manifest,
                bytes,
                key,
                graph_hash,
            }
        }

        fn approval(&self) -> PublisherSourceGraphApproval {
            PublisherSourceGraphApproval::load(&self.manifest_path, &self.key.verifying_key())
                .unwrap()
        }
    }

    #[test]
    fn publisher_approval_reconstructs_capsule_and_preserves_runtime_pins() {
        let fixture = Fixture::new("console.log(require('./side.cjs'));\n");
        let approval = fixture.approval();
        assert_eq!(approval.graph_input_hash(), fixture.graph_hash);
        assert_eq!(approval.identity().version, "1.2.3");
        approval
            .validate_run("app.cjs", true, false, &[], Some(&fixture.graph_hash))
            .unwrap();
        approval.revalidate().unwrap();
        for error in [
            approval.validate_run("other.cjs", true, false, &[], None),
            approval.validate_run("app.cjs", false, false, &[], None),
            approval.validate_run("app.cjs", true, true, &[], None),
            approval.validate_run("app.cjs", true, false, &["development".into()], None),
            approval.validate_run(
                "app.cjs",
                true,
                false,
                &[],
                Some(&format!("sha256:{}", "0".repeat(64))),
            ),
        ] {
            assert!(error.is_err());
        }
    }

    #[test]
    #[cfg(feature = "engine")]
    fn publisher_approval_admits_native_builtins_and_sealed_optional_dependencies() {
        use super::super::module_resolution_graph::file_resolution::source_graph::EdgeState;

        for (entrypoint, source) in [
            (
                "app.cjs",
                "const path = require('node:path');\n\
                 const value = require('./side.cjs');\n\
                 try { require('./optional.cjs'); } catch (error) {}\n\
                 console.log(path.join('signed', String(value)));\n",
            ),
            (
                "app.mjs",
                "import {join} from 'node:path';\n\
                 import('./optional.mjs').catch(error => {});\n\
                 export default join('signed', 'module');\n",
            ),
        ] {
            let fixture = Fixture::with_entrypoint(entrypoint, source);
            let graph = capsule::replay(&fixture.bytes, &capsule::digest(&fixture.bytes)).unwrap();
            assert!(!graph.report().fully_resolved, "{source}");
            assert!(graph.report().diagnostics.is_empty(), "{source}");
            assert!(
                graph
                    .report()
                    .edges
                    .iter()
                    .any(|edge| edge.state == EdgeState::RuntimeRequired)
            );
            assert!(
                graph
                    .report()
                    .edges
                    .iter()
                    .any(|edge| edge.state == EdgeState::Unresolved)
            );
            let approval = fixture.approval();
            assert_eq!(approval.graph_input_hash(), fixture.graph_hash);
            assert_eq!(approval.identity().publisher_id, "publisher");
            approval
                .validate_run(entrypoint, true, false, &[], Some(&fixture.graph_hash))
                .unwrap();

            // Reauthentication uses only the signed capsule. Native execution
            // separately recaptures the live project and enforces its graph pin.
            // Moving sources preserves them while proving that this approval
            // does not silently consult live dependency bytes or missing paths.
            std::fs::rename(
                fixture.directory.path().join(entrypoint),
                fixture.directory.path().join("retained-entrypoint"),
            )
            .unwrap();
            std::fs::rename(
                fixture.directory.path().join("side.cjs"),
                fixture.directory.path().join("retained-dependency"),
            )
            .unwrap();
            std::fs::write(
                fixture.directory.path().join("optional.cjs"),
                "throw new Error('not part of the signed capture');",
            )
            .unwrap();
            std::fs::write(
                fixture.directory.path().join("optional.mjs"),
                "throw new Error('not part of the signed capture');",
            )
            .unwrap();
            approval.revalidate().unwrap();
        }
    }

    #[test]
    #[cfg(not(feature = "engine"))]
    fn publisher_approval_does_not_guess_native_closure_without_the_engine() {
        for source in [
            "require('node:path');",
            "try { require('./optional.cjs'); } catch (error) {}",
            "import('./optional.mjs').catch(error => {});",
        ] {
            let fixture = Fixture::new(source);
            verify_artifact_bytes(
                &fixture.manifest,
                &fixture.bytes,
                Some(&fixture.key.verifying_key()),
            )
            .unwrap();
            let error = PublisherSourceGraphApproval::load(
                &fixture.manifest_path,
                &fixture.key.verifying_key(),
            )
            .unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("requires native engine closure admission")
            );
        }
    }

    #[test]
    fn publisher_approval_requires_external_key_and_rejects_signature_substitution() {
        let fixture = Fixture::new("console.log(require('./side.cjs'));\n");
        let attacker = ed25519_dalek::SigningKey::from_bytes(&[13; 32]);
        assert!(
            PublisherSourceGraphApproval::load(&fixture.manifest_path, &attacker.verifying_key())
                .is_err()
        );
        let mut manifest = fixture.manifest.clone();
        let signed = STANDARD.decode(&manifest.manifest_bytes_b64).unwrap();
        manifest.publisher_public_key_hex = hex::encode(attacker.verifying_key().as_bytes());
        manifest.extension.signature.key_id =
            KeyId::from_verifying_key(&attacker.verifying_key()).to_string();
        manifest.extension.signature.signature_bytes = sign_bytes(&attacker, &signed);
        // The inspector can recognize an internally consistent signature, but
        // it must never turn that candidate key into the run's trust anchor.
        verify_artifact_bytes(&manifest, &fixture.bytes, None).unwrap();
        let error = verify_artifact_bytes(
            &manifest,
            &fixture.bytes,
            Some(&fixture.key.verifying_key()),
        )
        .unwrap_err();
        assert_eq!(error.kind, ArtifactVerificationFailure::InvalidSignature);
    }

    #[test]
    fn shared_verifier_rejects_rehashed_unsigned_package_and_metadata() {
        let fixture = Fixture::new("console.log(require('./side.cjs'));\n");
        for mutate in [
            (|manifest: &mut LocalRegistryArtifactManifest| {
                manifest.extension.name.push_str("-forged")
            }) as fn(&mut LocalRegistryArtifactManifest),
            |manifest| manifest.extension.publisher_id.push_str("-forged"),
            |manifest| manifest.extension.versions[0].version = "9.9.9".into(),
            |manifest| manifest.extension.tags.push("forged".into()),
            |manifest| manifest.artifact_size_bytes += 1,
        ] {
            let mut manifest = fixture.manifest.clone();
            mutate(&mut manifest);
            assert_eq!(
                verify_artifact_bytes(
                    &manifest,
                    &fixture.bytes,
                    Some(&fixture.key.verifying_key())
                )
                .unwrap_err()
                .kind,
                ArtifactVerificationFailure::InvalidMetadata
            );
        }
        let bytes = b"attacker-controlled replacement";
        let mut manifest = fixture.manifest.clone();
        manifest.artifact_sha256 = artifact_sha256(bytes);
        manifest.artifact_size_bytes = bytes.len() as u64;
        manifest.extension.versions[0].content_hash = manifest
            .artifact_sha256
            .strip_prefix("sha256:")
            .unwrap()
            .to_owned();
        assert_eq!(
            verify_artifact_bytes(&manifest, bytes, Some(&fixture.key.verifying_key()))
                .unwrap_err()
                .kind,
            ArtifactVerificationFailure::InvalidMetadata
        );
    }

    #[test]
    fn retained_approval_refuses_post_admission_envelope_changes() {
        let fixture = Fixture::new("console.log(require('./side.cjs'));\n");
        let approval = fixture.approval();
        let mut manifest = fixture.manifest.clone();
        manifest.stored_at_utc = "2026-11-04T00:00:00Z".into();
        std::fs::write(
            &fixture.manifest_path,
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        // Signature still valid, but this is not the exact retained admission.
        PublisherSourceGraphApproval::load(&fixture.manifest_path, &fixture.key.verifying_key())
            .unwrap();
        assert!(
            approval
                .revalidate()
                .unwrap_err()
                .to_string()
                .contains("changed after publisher admission")
        );
    }

    #[test]
    fn signed_incomplete_capsule_is_not_an_executable_graph_approval() {
        for (entrypoint, source) in [
            ("app.cjs", "require(globalThis.unboundedRequest);\n"),
            ("app.cjs", "const load = require; unknown(load);\n"),
            ("app.cjs", "require('node:unsupported_registry_fixture');\n"),
            ("app.mjs", "import './missing.mjs';\n"),
            ("app.mjs", "export * from './missing.mjs';\n"),
            ("app.cjs", "const broken = ;\n"),
        ] {
            let fixture = Fixture::with_entrypoint(entrypoint, source);
            verify_artifact_bytes(
                &fixture.manifest,
                &fixture.bytes,
                Some(&fixture.key.verifying_key()),
            )
            .unwrap();
            let error = PublisherSourceGraphApproval::load(
                &fixture.manifest_path,
                &fixture.key.verifying_key(),
            )
            .unwrap_err();
            #[cfg(feature = "engine")]
            assert!(
                format!("{error:#}").contains("ERR_MODULE_REGISTRY_INCOMPLETE"),
                "{source}: {error:#}",
            );
            #[cfg(not(feature = "engine"))]
            assert!(
                error
                    .to_string()
                    .contains("requires native engine closure admission"),
                "{source}: {error:#}",
            );
        }
    }

    #[test]
    fn artifact_reader_rejects_symlinks_nonregular_files_and_size_growth() {
        use std::os::unix::fs::symlink;
        let fixture = Fixture::new("console.log(42);\n");
        let alias = fixture.directory.path().join("alias");
        symlink(&fixture.manifest_path, &alias).unwrap();
        assert!(read_artifact_file(&alias, MAX_ARTIFACT_BYTES).is_err());
        let directory_alias = fixture.directory.path().join("directory-alias");
        symlink(fixture.directory.path(), &directory_alias).unwrap();
        assert!(
            read_artifact_file(
                &directory_alias.join("artifact.manifest.json"),
                MAX_ARTIFACT_BYTES
            )
            .is_err()
        );
        let fifo = fixture.directory.path().join("fifo");
        rustix::fs::mkfifoat(
            rustix::fs::CWD,
            &fifo,
            rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
        )
        .unwrap();
        assert!(read_artifact_file(&fifo, MAX_ARTIFACT_BYTES).is_err());
        assert!(read_artifact_file(&fixture.manifest_path, 1).is_err());
        assert!(absolute_artifact_path(Path::new("../escape")).is_err());
    }

    #[test]
    fn capsule_export_is_private_and_exclusive() {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("source.capsule");
        write_new_source_capsule(&path, b"explicit private source export").unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o077,
            0
        );
        assert!(write_new_source_capsule(&path, b"replacement").is_err());
        assert_eq!(
            std::fs::read(&path).unwrap(),
            b"explicit private source export"
        );
    }
}
