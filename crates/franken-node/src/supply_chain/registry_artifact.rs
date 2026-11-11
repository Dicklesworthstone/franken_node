//! Verification of persisted registry artifacts and publisher-approved source graphs.
//!
//! The local storage envelope is not a registry-service endorsement. Execution
//! admission requires a separately supplied publisher key, the signed package
//! identity, and the exact capsule bytes. A signed runtime authority can only
//! narrow the operator's capabilities and resource limits; it cannot grant new
//! rights. The envelope's unsigned lifecycle confers no execution authority.
//! Publisher provenance is authenticated against the same publisher and exact
//! signed manifest, with only its canonical digest retained in execution identity.

use anyhow::{Context, Result};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Component, Path, PathBuf};

use super::artifact_signing::{KeyId, verify_signature};
use super::extension_registry::{ExtensionRegistrationManifest, SignedExtension};

#[path = "registry_artifact_provenance.rs"]
mod publisher_provenance;
pub use publisher_provenance::registry_publish_provenance_signature_payload;

pub const LOCAL_ARTIFACT_SCHEMA: &str = "franken-node/local-registry-artifact-manifest/v1";
/// Match the installed registry's artifact and manifest input bound.
pub const MAX_ARTIFACT_BYTES: u64 = 5 << 20;

pub const ARTIFACT_RUNTIME_AUTHORITY_SCHEMA: &str = "franken-node/artifact-runtime-authority/v1";

/// Publisher-signed upper bounds for one complete source capsule execution.
///
/// All fields are mandatory. These are ceilings, never grants: execution also
/// requires the operator profile, current fleet policy, and any separate signed
/// process-spawn admission. Parser limits apply independently to every module;
/// instruction, allocation, memory and output limits apply to the native run.
/// Memory is engine-accounted estimated memory, not process RSS, and heap
/// objects count allocations until the engine supports live-object reclamation.
///
/// The current engine always grants VM dispatch, heap allocation and console
/// output. Their canonical capability names must therefore appear explicitly;
/// a publisher cannot request an unenforceable denial. Console output can be
/// narrowed using its entry ceiling; the engine's separate byte cap still
/// applies. This schema does not claim per-hostcall quotas or path scopes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactRuntimeAuthority {
    pub schema_version: String,
    pub policy_revision: String,
    pub allowed_capabilities: Vec<String>,
    pub allow_process_shape: bool,
    pub max_instructions: u64,
    pub max_registers: u32,
    pub max_call_depth: u32,
    pub max_heap_objects: u32,
    pub max_total_memory_bytes: u64,
    pub max_console_entries: u32,
    pub max_parse_source_bytes: u64,
    pub max_parse_tokens: u64,
    pub max_parse_recursion_depth: u64,
}

impl ArtifactRuntimeAuthority {
    /// Reject ambiguous, incomplete, or unsupported authority before signing,
    /// registry admission, and parent/worker execution admission.
    pub fn validate(&self) -> Result<()> {
        use crate::config::{
            MAX_NATIVE_CALL_DEPTH, MAX_NATIVE_REGISTERS, MAX_PARSE_SOURCE_BYTES, MAX_PARSE_TOKENS,
        };
        const CAPABILITIES: &[&str] = &[
            "builtin",
            "console",
            "env_read",
            "fs_read",
            "fs_write",
            "heap_allocate",
            "module_load",
            "network_egress",
            "process_spawn",
            "random_read",
            "timer",
            "vm_dispatch",
        ];
        anyhow::ensure!(
            self.schema_version == ARTIFACT_RUNTIME_AUTHORITY_SCHEMA,
            "unsupported artifact runtime authority schema"
        );
        anyhow::ensure!(
            !self.policy_revision.is_empty()
                && self.policy_revision.len() <= 128
                && self.policy_revision.trim() == self.policy_revision
                && !self.policy_revision.chars().any(char::is_control),
            "artifact runtime authority requires a bounded policy revision"
        );
        anyhow::ensure!(
            self.allowed_capabilities.len() <= CAPABILITIES.len()
                && self
                    .allowed_capabilities
                    .iter()
                    .all(|capability| CAPABILITIES.contains(&capability.as_str())),
            "artifact runtime authority contains an unsupported capability"
        );
        let unique = self
            .allowed_capabilities
            .iter()
            .map(String::as_str)
            .collect::<std::collections::BTreeSet<_>>();
        anyhow::ensure!(
            unique.len() == self.allowed_capabilities.len(),
            "artifact runtime authority repeats a capability"
        );
        anyhow::ensure!(
            ["console", "heap_allocate", "vm_dispatch"]
                .into_iter()
                .all(|capability| unique.contains(capability)),
            "artifact runtime authority must explicitly permit the engine's console, heap_allocate, and vm_dispatch capabilities"
        );
        anyhow::ensure!(
            self.max_instructions > 0
                && self.max_heap_objects > 0
                && self.max_total_memory_bytes > 0
                && self.max_console_entries > 0,
            "artifact runtime authority execution ceilings must be positive"
        );
        anyhow::ensure!(
            (1..=MAX_NATIVE_REGISTERS).contains(&self.max_registers)
                && usize::try_from(self.max_call_depth)
                    .is_ok_and(|depth| (1..=MAX_NATIVE_CALL_DEPTH).contains(&depth)),
            "artifact runtime authority register or call-depth ceiling is unsupported"
        );
        anyhow::ensure!(
            (1..=MAX_PARSE_SOURCE_BYTES).contains(&self.max_parse_source_bytes)
                && (1..=MAX_PARSE_TOKENS).contains(&self.max_parse_tokens)
                && (1..=384).contains(&self.max_parse_recursion_depth),
            "artifact runtime authority parser ceilings are outside the native envelope"
        );
        Ok(())
    }

    /// Stable source-free commitment, independent of capability list ordering.
    /// Authentication comes from the enclosing signed registration manifest.
    pub fn commitment(&self) -> Result<String> {
        self.validate()?;
        let mut canonical = self.clone();
        canonical.allowed_capabilities.sort();
        let bytes = serde_json::to_vec(&canonical)?;
        let mut digest = Sha256::new();
        digest.update(b"franken-node/artifact-runtime-authority/v1:");
        digest.update(bytes);
        Ok(format!("sha256:{}", hex::encode(digest.finalize())))
    }
}

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

/// Source-free claims authenticated by the publisher's registration signature
/// and, when present, separately verified publisher provenance bound to it.
/// Registry-generated extension IDs, lifecycle and raw provenance are absent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublisherArtifactIdentity {
    pub publisher_key_id: String,
    pub publisher_id: String,
    pub name: String,
    pub version: String,
    pub artifact_sha256: String,
    /// Present only when authenticated as part of a v2 registration. An older
    /// source-only artifact makes no publisher claim about runtime authority.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_authority: Option<ArtifactRuntimeAuthority>,
    /// Commitment to publisher-authenticated provenance valid at admission.
    /// Legacy v1 source-only imports without proof retain None. This does not
    /// certify an independent build or ongoing signer-revocation monitoring.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub publisher_provenance_sha256: Option<String>,
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
    signed
        .validate_schema()
        .map_err(|detail| failure(InvalidMetadata, detail))?;
    let binding_error = if signed.name != extension.name {
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
    let publisher_provenance_sha256 = publisher_provenance::verify_publisher_provenance(
        envelope,
        &signed,
        &manifest_bytes,
        &verifying_key,
        &actual_hash,
    )?;
    Ok(PublisherArtifactIdentity {
        publisher_key_id: key_id,
        publisher_id: signed.publisher_id,
        name: signed.name,
        version: signed.initial_version.version,
        artifact_sha256: actual_hash,
        runtime_authority: signed.runtime_authority,
        publisher_provenance_sha256,
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

/// Package identities observed in the authenticated module closure. A version
/// is signed package metadata; it is not a tarball integrity attestation.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublisherModulePackage {
    pub extension_id: String,
    pub location: String,
    pub version: Option<String>,
}

impl PublisherModulePackage {
    pub fn validate(&self) -> Result<()> {
        let name = self
            .extension_id
            .strip_prefix("npm:")
            .context("publisher module package is not an npm identity")?;
        super::module_resolution_graph::validate_package_name(name)?;
        anyhow::ensure!(
            !self.location.is_empty()
                && self.location.len() <= 4096
                && !self.location.chars().any(char::is_control)
                && self
                    .location
                    .split('/')
                    .all(|part| !matches!(part, "" | "." | ".."))
                && !self.location.contains(['\\', ':'])
                && self.version.as_ref().is_none_or(|version| {
                    !version.is_empty()
                        && version.len() <= 128
                        && !version.chars().any(char::is_control)
                }),
            "publisher module package has invalid placement metadata"
        );
        Ok(())
    }
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
            Self::load_source_graph(manifest_path, trusted_publisher).map(|(approval, _)| approval)
        }
    }

    #[cfg(unix)]
    fn load_source_graph(
        manifest_path: &Path,
        trusted_publisher: &VerifyingKey,
    ) -> Result<(
        Self,
        super::module_resolution_graph::file_resolution::source_graph::CapturedModuleGraph,
    )> {
        #[cfg(feature = "engine")]
        use super::module_resolution_graph::file_resolution::source_graph::engine_resolver::CapturedEngineResolver;
        use super::module_resolution_graph::file_resolution::{
            SymlinkPolicy, source_graph::capsule,
        };
        let manifest_path = absolute_artifact_path(manifest_path)?;
        let manifest_bytes = read_artifact_file(&manifest_path, MAX_ARTIFACT_BYTES)?;
        let manifest: LocalRegistryArtifactManifest = serde_json::from_slice(&manifest_bytes)
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
        Ok((approval, graph))
    }

    pub fn entrypoint(&self) -> &str {
        &self.entrypoint
    }

    /// Retain the names and versions of packages actually represented by the
    /// authenticated closure, independently of mutable installation metadata.
    /// Current trust cards can then revoke or quarantine those same identities
    /// even when the installation no longer declares their dependencies.
    pub fn module_packages(&self) -> Result<Vec<PublisherModulePackage>> {
        #[cfg(not(unix))]
        anyhow::bail!("registry source admission requires Unix");
        #[cfg(unix)]
        {
            let graph = self.revalidate_source_graph()?;
            Self::captured_module_packages(&graph)
        }
    }

    #[cfg(unix)]
    fn captured_module_packages(
        graph: &super::module_resolution_graph::file_resolution::source_graph::CapturedModuleGraph,
    ) -> Result<Vec<PublisherModulePackage>> {
        use std::collections::{BTreeMap, BTreeSet};
        let manifests = graph
            .captured_package_manifests()
            .collect::<BTreeMap<_, _>>();
        let mut locations = BTreeMap::<String, Option<String>>::new();
        for module in &graph.report().modules {
            let components = module.id.path.split('/').collect::<Vec<_>>();
            // The innermost placement owns this module. Outer node_modules
            // segments can be package-manager stores (for example .pnpm), not
            // package identities; another loaded parent has its own module.
            if let Some(index) = components.iter().rposition(|part| *part == "node_modules") {
                if index + 1 >= components.len() {
                    continue;
                }
                let end = index
                    + if components[index + 1].starts_with('@') {
                        3
                    } else {
                        2
                    };
                anyhow::ensure!(
                    end <= components.len(),
                    "invalid captured package placement"
                );
                locations.insert(
                    components[..end].join("/"),
                    Some(components[index + 1..end].join("/")),
                );
                anyhow::ensure!(
                    locations.len() <= 4096,
                    "publisher module packages exceed the placement bound"
                );
            }
        }
        // Workspace and relative package imports can have no node_modules
        // placement. Their captured named package scopes still carry identity.
        for path in manifests.keys() {
            if let Some(directory) = path.strip_suffix("/package.json")
                && graph.report().modules.iter().any(|module| {
                    module
                        .id
                        .path
                        .strip_prefix(directory)
                        .is_some_and(|tail| tail.starts_with('/'))
                })
            {
                locations.entry(directory.to_owned()).or_default();
                anyhow::ensure!(
                    locations.len() <= 4096,
                    "publisher module packages exceed the placement bound"
                );
            }
        }
        let mut packages = BTreeSet::new();
        for (location, placement_name) in locations {
            let manifest = manifests
                .get(format!("{location}/package.json").as_str())
                .map(|bytes| {
                    serde_json::from_slice::<serde_json::Value>(
                        bytes.strip_prefix(b"\xef\xbb\xbf").unwrap_or(bytes),
                    )
                })
                .transpose()
                .context("invalid captured package identity manifest")?;
            let name = manifest.as_ref().and_then(|value| value.get("name"));
            let name = match name {
                Some(value) => Some(
                    value
                        .as_str()
                        .context("captured package name is not a string")?,
                ),
                None => placement_name.as_deref(),
            };
            let Some(name) = name else {
                continue;
            };
            let version = manifest
                .as_ref()
                .and_then(|value| value.get("version"))
                .map(|value| {
                    value
                        .as_str()
                        .context("captured package version is not a string")
                })
                .transpose()?
                .map(str::to_owned);
            let package = PublisherModulePackage {
                extension_id: format!("npm:{name}"),
                location,
                version,
            };
            package.validate()?;
            packages.insert(package);
        }
        let packages = packages.into_iter().collect::<Vec<_>>();
        anyhow::ensure!(
            serde_json::to_vec(&packages)?.len() <= 2 * 1024 * 1024,
            "publisher module packages exceed the metadata bound"
        );
        Ok(packages)
    }

    pub fn graph_input_hash(&self) -> &str {
        &self.graph_input_hash
    }
    pub fn identity(&self) -> &PublisherArtifactIdentity {
        &self.identity
    }

    /// Bind a supervisor's immutable approval to the actual child admission.
    /// This covers the publisher key, manifest, artifact, source graph and
    /// runtime authority together. It is a commitment, not a new signature or
    /// a replacement for publisher verification and current trust admission.
    pub fn admission_sha256(&self) -> Result<String> {
        self.validate()?;
        let mut digest = Sha256::new();
        digest.update(b"franken-node/publisher-source-approval-handoff/v1\0");
        digest.update(serde_json::to_vec(self)?);
        Ok(format!("sha256:{}", hex::encode(digest.finalize())))
    }

    pub fn runtime_authority(&self) -> Option<&ArtifactRuntimeAuthority> {
        self.identity.runtime_authority.as_ref()
    }

    pub fn validate(&self) -> Result<()> {
        if let Some(authority) = self.runtime_authority() {
            authority.validate()?;
        }
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
            .all(|hash| valid_hash(hash))
                && self
                    .identity
                    .publisher_provenance_sha256
                    .as_deref()
                    .is_none_or(valid_hash),
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
        #[cfg(not(unix))]
        anyhow::bail!("registry source admission requires Unix");
        #[cfg(unix)]
        self.revalidate_source_graph().map(|_| ())
    }

    /// Reauthenticate and return the exact immutable source owner used by the
    /// native resolver. No live project files are recaptured after this check.
    /// Another valid publisher artifact cannot replace the retained admission.
    #[cfg(unix)]
    pub fn revalidate_source_graph(
        &self,
    ) -> Result<super::module_resolution_graph::file_resolution::source_graph::CapturedModuleGraph>
    {
        self.validate()?;
        let bytes = hex::decode(&self.publisher_public_key_hex)?;
        let key: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .context("invalid retained publisher key")?;
        let (observed, graph) =
            Self::load_source_graph(&self.manifest_path, &VerifyingKey::from_bytes(&key)?)?;
        anyhow::ensure!(
            &observed == self,
            "registry artifact changed after publisher admission"
        );
        Ok(graph)
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
            canonical_registration_manifest_bytes_with_authority,
        },
        module_resolution_graph::file_resolution::source_graph::{GraphOptions, capsule, capture},
        provenance::{
            AttestationEnvelopeFormat, AttestationLink, ChainLinkRole, ProvenanceAttestation,
            canonical_attestation_json, sign_links_in_place,
        },
    };

    struct Fixture {
        directory: tempfile::TempDir,
        manifest_path: PathBuf,
        manifest: LocalRegistryArtifactManifest,
        bytes: Vec<u8>,
        key: ed25519_dalek::SigningKey,
        graph_hash: String,
    }

    fn runtime_authority() -> ArtifactRuntimeAuthority {
        ArtifactRuntimeAuthority {
            schema_version: ARTIFACT_RUNTIME_AUTHORITY_SCHEMA.into(),
            policy_revision: "review-7".into(),
            allowed_capabilities: [
                "builtin",
                "console",
                "fs_read",
                "heap_allocate",
                "module_load",
                "vm_dispatch",
            ]
            .map(str::to_owned)
            .to_vec(),
            allow_process_shape: false,
            max_instructions: 100_000,
            max_registers: 128,
            max_call_depth: 32,
            max_heap_objects: 10_000,
            max_total_memory_bytes: 16 * 1024 * 1024,
            max_console_entries: 128,
            max_parse_source_bytes: 64 * 1024,
            max_parse_tokens: 8192,
            max_parse_recursion_depth: 64,
        }
    }

    impl Fixture {
        fn new(source: &str) -> Self {
            Self::with_entrypoint("app.cjs", source)
        }

        fn with_entrypoint(entrypoint: &str, source: &str) -> Self {
            Self::with_modules(entrypoint, source, &[])
        }

        fn with_modules(entrypoint: &str, source: &str, modules: &[(&str, &str)]) -> Self {
            let directory = tempfile::tempdir().unwrap();
            std::fs::write(directory.path().join(entrypoint), source).unwrap();
            std::fs::write(directory.path().join("side.cjs"), "module.exports = 42;\n").unwrap();
            for (path, contents) in modules {
                let path = directory.path().join(path);
                std::fs::create_dir_all(path.parent().unwrap()).unwrap();
                std::fs::write(path, contents).unwrap();
            }
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

        fn with_runtime_authority(mut self, authority: &ArtifactRuntimeAuthority) -> Self {
            let signed = canonical_registration_manifest_bytes_with_authority(
                &self.manifest.extension.name,
                &self.manifest.extension.publisher_id,
                &self.manifest.extension.versions[0],
                &self.manifest.extension.tags,
                authority,
            )
            .unwrap();
            self.manifest.manifest_bytes_b64 = STANDARD.encode(&signed);
            self.manifest.extension.signature.signature_bytes = sign_bytes(&self.key, &signed);
            self.authenticate_provenance_at(current_epoch());
            std::fs::write(
                &self.manifest_path,
                serde_json::to_vec(&self.manifest).unwrap(),
            )
            .unwrap();
            self
        }

        fn authenticate_provenance_at(&mut self, now: u64) {
            let key_id = KeyId::from_verifying_key(&self.key.verifying_key()).to_string();
            let hash = self.manifest.artifact_sha256.clone();
            self.manifest.extension.provenance = ProvenanceAttestation {
                schema_version: "1.0".into(),
                source_repository_url: "https://example.com/publisher/source".into(),
                build_system_identifier: "registry-publish-test".into(),
                builder_identity: self.manifest.extension.publisher_id.clone(),
                builder_version: "1".into(),
                vcs_commit_sha: "a".repeat(40),
                build_timestamp_epoch: now,
                reproducibility_hash: hash.clone(),
                input_hash: hash.clone(),
                output_hash: hash.clone(),
                slsa_level_claim: 1,
                envelope_format: AttestationEnvelopeFormat::FrankenNodeEnvelopeV1,
                links: vec![AttestationLink {
                    role: ChainLinkRole::Publisher,
                    signer_id: key_id.clone(),
                    signer_version: "1".into(),
                    signature: String::new(),
                    signed_payload_hash: hash,
                    issued_at_epoch: now,
                    expires_at_epoch: now + 24 * 60 * 60,
                    revoked: false,
                }],
                custom_claims: std::collections::BTreeMap::from([
                    ("operator_key_id".into(), key_id),
                    (
                        "operator_signature_scope".into(),
                        "registry_publish_provenance_v1".into(),
                    ),
                ]),
            };
            self.resign_provenance();
        }

        fn resign_provenance(&mut self) {
            let manifest_bytes = STANDARD.decode(&self.manifest.manifest_bytes_b64).unwrap();
            let provenance = &mut self.manifest.extension.provenance;
            let payload =
                registry_publish_provenance_signature_payload(&manifest_bytes, provenance).unwrap();
            provenance.custom_claims.insert(
                "operator_provenance_signature".into(),
                hex::encode(sign_bytes(&self.key, &payload)),
            );
            let keys = std::collections::BTreeMap::from([(
                KeyId::from_verifying_key(&self.key.verifying_key()).to_string(),
                self.key.clone(),
            )]);
            sign_links_in_place(provenance, &keys).unwrap();
        }

        fn verify_provenance_at(
            &self,
            now: u64,
        ) -> std::result::Result<Option<String>, ArtifactVerificationError> {
            let manifest_bytes = STANDARD.decode(&self.manifest.manifest_bytes_b64).unwrap();
            let signed = serde_json::from_slice(&manifest_bytes).unwrap();
            publisher_provenance::verify_publisher_provenance_at(
                &self.manifest,
                &signed,
                &manifest_bytes,
                &self.key.verifying_key(),
                &self.manifest.artifact_sha256,
                now,
            )
        }
    }

    fn current_epoch() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    #[test]
    fn publisher_provenance_preimage_preserves_the_existing_publication_format() {
        let mut fixture = Fixture::new("console.log(42);\n");
        fixture.authenticate_provenance_at(current_epoch());
        let manifest_bytes = STANDARD
            .decode(&fixture.manifest.manifest_bytes_b64)
            .unwrap();
        let provenance = &fixture.manifest.extension.provenance;
        let mut before_signing = provenance.clone();
        before_signing
            .custom_claims
            .remove("operator_provenance_signature");
        for link in &mut before_signing.links {
            link.signature.clear();
        }
        // Independently assemble the original producer framing, rather than
        // using the verification helper to construct its own expected bytes.
        let canonical = canonical_attestation_json(&before_signing).unwrap();
        let mut expected = b"registry_publish_provenance_v1:".to_vec();
        expected.extend_from_slice(&(manifest_bytes.len() as u64).to_le_bytes());
        expected.extend_from_slice(&manifest_bytes);
        expected.extend_from_slice(&(canonical.len() as u64).to_le_bytes());
        expected.extend_from_slice(canonical.as_bytes());
        assert_eq!(
            registry_publish_provenance_signature_payload(&manifest_bytes, &before_signing)
                .unwrap(),
            expected
        );
        assert_eq!(
            registry_publish_provenance_signature_payload(&manifest_bytes, provenance).unwrap(),
            expected
        );

        // Even semantically equivalent registration JSON is a different
        // signed statement: its exact bytes are part of this second proof.
        let mut other_manifest = manifest_bytes.clone();
        other_manifest.push(b'\n');
        fixture.manifest.manifest_bytes_b64 = STANDARD.encode(&other_manifest);
        fixture.manifest.extension.signature.signature_bytes =
            sign_bytes(&fixture.key, &other_manifest);
        assert_eq!(
            verify_artifact_bytes(
                &fixture.manifest,
                &fixture.bytes,
                Some(&fixture.key.verifying_key())
            )
            .unwrap_err()
            .kind,
            ArtifactVerificationFailure::InvalidSignature
        );
    }

    #[test]
    fn publisher_provenance_is_verified_and_committed_for_v1_and_v2() {
        for with_authority in [false, true] {
            let mut fixture = Fixture::new("console.log(42);\n");
            if with_authority {
                fixture = fixture.with_runtime_authority(&runtime_authority());
            } else {
                fixture.authenticate_provenance_at(current_epoch());
                std::fs::write(
                    &fixture.manifest_path,
                    serde_json::to_vec(&fixture.manifest).unwrap(),
                )
                .unwrap();
            }
            let expected = artifact_sha256(
                canonical_attestation_json(&fixture.manifest.extension.provenance)
                    .unwrap()
                    .as_bytes(),
            );
            let identity = verify_artifact_bytes(
                &fixture.manifest,
                &fixture.bytes,
                Some(&fixture.key.verifying_key()),
            )
            .unwrap();
            assert_eq!(
                identity.publisher_provenance_sha256.as_deref(),
                Some(expected.as_str())
            );
            let approval = fixture.approval();
            assert_eq!(approval.identity(), &identity);
            let handoff: PublisherSourceGraphApproval =
                serde_json::from_slice(&serde_json::to_vec(&approval).unwrap()).unwrap();
            handoff.revalidate().unwrap();
            assert_eq!(handoff, approval);
            let receipt = serde_json::to_string(&identity).unwrap();
            assert!(!receipt.contains("https://example.com/publisher/source"));
            assert!(!receipt.contains("operator_provenance_signature"));
        }
    }

    #[test]
    fn publisher_provenance_cannot_be_stripped_from_authority_or_partially_declared() {
        let mut legacy = Fixture::new("console.log(42);\n");
        let identity = verify_artifact_bytes(
            &legacy.manifest,
            &legacy.bytes,
            Some(&legacy.key.verifying_key()),
        )
        .unwrap();
        assert!(identity.publisher_provenance_sha256.is_none());
        assert!(
            !serde_json::to_value(identity)
                .unwrap()
                .as_object()
                .unwrap()
                .contains_key("publisher_provenance_sha256")
        );
        for marker in [
            "operator_key_id",
            "operator_signature_scope",
            "operator_provenance_signature",
        ] {
            legacy.manifest.extension.provenance.custom_claims.clear();
            legacy
                .manifest
                .extension
                .provenance
                .custom_claims
                .insert(marker.into(), "partial".into());
            assert!(
                verify_artifact_bytes(
                    &legacy.manifest,
                    &legacy.bytes,
                    Some(&legacy.key.verifying_key()),
                )
                .is_err(),
                "{marker}"
            );
        }

        let mut authority =
            Fixture::new("console.log(42);\n").with_runtime_authority(&runtime_authority());
        authority
            .manifest
            .extension
            .provenance
            .custom_claims
            .clear();
        assert_eq!(
            verify_artifact_bytes(
                &authority.manifest,
                &authority.bytes,
                Some(&authority.key.verifying_key()),
            )
            .unwrap_err()
            .kind,
            ArtifactVerificationFailure::InvalidMetadata
        );
    }

    #[test]
    fn publisher_provenance_rejects_statement_mutations_and_foreign_signatures() {
        let mut fixture = Fixture::new("console.log(42);\n");
        fixture.authenticate_provenance_at(current_epoch());
        for (label, mutate) in [
            (
                "repository",
                (|p: &mut ProvenanceAttestation| {
                    p.source_repository_url.push_str("/private-substitute")
                }) as fn(&mut ProvenanceAttestation),
            ),
            ("builder", |p| p.builder_identity.push_str("-substitute")),
            ("build_system", |p| {
                p.build_system_identifier.push_str("-substitute")
            }),
            ("revision", |p| p.vcs_commit_sha = "b".repeat(40)),
            ("input_hash", |p| {
                p.input_hash = artifact_sha256(b"different input")
            }),
            ("output_hash", |p| {
                p.output_hash = artifact_sha256(b"different output")
            }),
            ("reproducibility_hash", |p| {
                p.reproducibility_hash = artifact_sha256(b"different build")
            }),
            ("slsa_claim", |p| p.slsa_level_claim = 3),
            ("claim", |p| {
                p.custom_claims.insert("source_dirty".into(), "true".into());
            }),
            ("scope", |p| {
                p.custom_claims
                    .insert("operator_signature_scope".into(), "other".into());
            }),
            ("key_id", |p| {
                p.custom_claims
                    .insert("operator_key_id".into(), "other".into());
            }),
            ("proof_missing", |p| {
                p.custom_claims.remove("operator_provenance_signature");
            }),
            ("proof_noncanonical", |p| {
                p.custom_claims
                    .insert("operator_provenance_signature".into(), "A".repeat(128));
            }),
            ("link_identity", |p| {
                p.links[0].signer_id.push_str("-substitute")
            }),
            ("link_expiry", |p| p.links[0].expires_at_epoch += 1),
            ("link_revoked", |p| p.links[0].revoked = true),
        ] {
            let mut changed = fixture.manifest.clone();
            mutate(&mut changed.extension.provenance);
            let error =
                verify_artifact_bytes(&changed, &fixture.bytes, Some(&fixture.key.verifying_key()))
                    .unwrap_err();
            assert!(!error.detail.contains("private-substitute"), "{label}");
        }

        let foreign = ed25519_dalek::SigningKey::from_bytes(&[99; 32]);
        let manifest_bytes = STANDARD
            .decode(&fixture.manifest.manifest_bytes_b64)
            .unwrap();
        let payload = registry_publish_provenance_signature_payload(
            &manifest_bytes,
            &fixture.manifest.extension.provenance,
        )
        .unwrap();
        fixture.manifest.extension.provenance.custom_claims.insert(
            "operator_provenance_signature".into(),
            hex::encode(sign_bytes(&foreign, &payload)),
        );
        assert_eq!(
            verify_artifact_bytes(
                &fixture.manifest,
                &fixture.bytes,
                Some(&fixture.key.verifying_key()),
            )
            .unwrap_err()
            .kind,
            ArtifactVerificationFailure::InvalidSignature
        );
    }

    #[test]
    fn publisher_provenance_requires_real_ordered_links_under_the_pinned_key() {
        const NOW: u64 = 1_800_000_000;
        let mut fixture = Fixture::new("console.log(42);\n");
        fixture.authenticate_provenance_at(NOW);
        let original = fixture.manifest.extension.provenance.clone();
        let manifest_bytes = STANDARD
            .decode(&fixture.manifest.manifest_bytes_b64)
            .unwrap();
        let outer_payload =
            registry_publish_provenance_signature_payload(&manifest_bytes, &original).unwrap();
        fixture.manifest.extension.provenance.links[0].signature = "0".repeat(128);
        assert_eq!(
            registry_publish_provenance_signature_payload(
                &manifest_bytes,
                &fixture.manifest.extension.provenance,
            )
            .unwrap(),
            outer_payload,
            "the independent link signature is not part of the outer preimage"
        );
        assert_eq!(
            fixture.verify_provenance_at(NOW).unwrap_err().kind,
            ArtifactVerificationFailure::InvalidSignature
        );

        fixture.manifest.extension.provenance = original.clone();
        for role in [ChainLinkRole::BuildSystem, ChainLinkRole::SourceVcs] {
            let mut link = original.links[0].clone();
            link.role = role;
            fixture.manifest.extension.provenance.links.push(link);
            fixture.resign_provenance();
            assert!(fixture.verify_provenance_at(NOW).unwrap().is_some());
        }
        fixture.manifest.extension.provenance.links[1].role = ChainLinkRole::Publisher;
        fixture.resign_provenance();
        assert_eq!(
            fixture.verify_provenance_at(NOW).unwrap_err().kind,
            ArtifactVerificationFailure::InvalidMetadata
        );

        // The publisher may attest that another signer exists, but that does
        // not install the foreign key as an admission trust anchor.
        fixture.manifest.extension.provenance = original;
        let foreign = ed25519_dalek::SigningKey::from_bytes(&[98; 32]);
        let foreign_id = KeyId::from_verifying_key(&foreign.verifying_key()).to_string();
        fixture.manifest.extension.provenance.links[0].signer_id = foreign_id.clone();
        let payload = registry_publish_provenance_signature_payload(
            &manifest_bytes,
            &fixture.manifest.extension.provenance,
        )
        .unwrap();
        fixture.manifest.extension.provenance.custom_claims.insert(
            "operator_provenance_signature".into(),
            hex::encode(sign_bytes(&fixture.key, &payload)),
        );
        sign_links_in_place(
            &mut fixture.manifest.extension.provenance,
            &std::collections::BTreeMap::from([(foreign_id.clone(), foreign)]),
        )
        .unwrap();
        let error = fixture.verify_provenance_at(NOW).unwrap_err();
        assert_eq!(error.kind, ArtifactVerificationFailure::InvalidSignature);
        assert!(!error.detail.contains(&foreign_id));
    }

    #[test]
    fn publisher_provenance_expiry_future_time_and_revocation_fail_closed() {
        const NOW: u64 = 1_800_000_000;
        let mut fixture = Fixture::new("console.log(42);\n");
        fixture.authenticate_provenance_at(NOW);
        let original = fixture.manifest.extension.provenance.clone();
        assert!(
            fixture
                .verify_provenance_at(NOW + 24 * 60 * 60 - 1)
                .unwrap()
                .is_some()
        );
        assert_eq!(
            fixture
                .verify_provenance_at(NOW + 24 * 60 * 60)
                .unwrap_err()
                .kind,
            ArtifactVerificationFailure::InvalidMetadata
        );
        for (label, mutate) in [
            (
                "future_build",
                (|p: &mut ProvenanceAttestation| p.build_timestamp_epoch = NOW + 1)
                    as fn(&mut ProvenanceAttestation),
            ),
            ("future_link", |p| p.links[0].issued_at_epoch = NOW + 1),
            ("expired_link", |p| p.links[0].expires_at_epoch = NOW),
            ("old_build", |p| {
                p.build_timestamp_epoch = NOW - 7 * 24 * 60 * 60
            }),
            ("old_link", |p| {
                p.links[0].issued_at_epoch = NOW - 7 * 24 * 60 * 60
            }),
            ("revoked_link", |p| p.links[0].revoked = true),
            ("missing_link", |p| p.links.clear()),
            ("unsupported_schema", |p| {
                p.schema_version = "future-unknown".into()
            }),
            ("unsupported_envelope", |p| {
                p.envelope_format = AttestationEnvelopeFormat::InToto
            }),
        ] {
            fixture.manifest.extension.provenance = original.clone();
            mutate(&mut fixture.manifest.extension.provenance);
            // These are valid publisher and link signatures: failures must
            // come from actual admission policy, not stale cryptographic bytes.
            fixture.resign_provenance();
            assert_eq!(
                fixture.verify_provenance_at(NOW).unwrap_err().kind,
                ArtifactVerificationFailure::InvalidMetadata,
                "{label}"
            );
        }
        fixture.manifest.extension.provenance = original;
        fixture.manifest.extension.provenance.links[0].expires_at_epoch = NOW + 8 * 24 * 60 * 60;
        fixture.resign_provenance();
        assert!(
            fixture
                .verify_provenance_at(NOW + 7 * 24 * 60 * 60 - 1)
                .unwrap()
                .is_some()
        );
        assert_eq!(
            fixture
                .verify_provenance_at(NOW + 7 * 24 * 60 * 60)
                .unwrap_err()
                .kind,
            ArtifactVerificationFailure::InvalidMetadata
        );
    }

    #[test]
    fn publisher_provenance_bounds_ordinary_metadata_before_canonical_copy() {
        let mut fixture = Fixture::new("console.log(42);\n");
        fixture.authenticate_provenance_at(current_epoch());
        fixture.manifest.extension.provenance.source_repository_url =
            "private-metadata".repeat(MAX_ARTIFACT_BYTES as usize / 16 + 1);
        let manifest_bytes = STANDARD
            .decode(&fixture.manifest.manifest_bytes_b64)
            .unwrap();
        assert!(
            registry_publish_provenance_signature_payload(
                &manifest_bytes,
                &fixture.manifest.extension.provenance,
            )
            .is_err()
        );
        let error = verify_artifact_bytes(
            &fixture.manifest,
            &fixture.bytes,
            Some(&fixture.key.verifying_key()),
        )
        .unwrap_err();
        assert_eq!(error.kind, ArtifactVerificationFailure::InvalidMetadata);
        assert!(!error.detail.contains("private-metadata"));
    }

    #[test]
    fn publisher_provenance_commitment_binds_the_retained_execution_approval() {
        let mut fixture =
            Fixture::new("console.log(42);\n").with_runtime_authority(&runtime_authority());
        let retained = fixture.approval();
        let mut invalid_handoff = retained.clone();
        invalid_handoff.identity.publisher_provenance_sha256 = Some("sha256:invalid".into());
        assert!(invalid_handoff.validate().is_err());

        fixture.manifest.extension.provenance.vcs_commit_sha = "c".repeat(40);
        fixture.resign_provenance();
        std::fs::write(
            &fixture.manifest_path,
            serde_json::to_vec(&fixture.manifest).unwrap(),
        )
        .unwrap();
        let replacement = fixture.approval();
        assert_ne!(
            retained.identity().publisher_provenance_sha256,
            replacement.identity().publisher_provenance_sha256,
        );
        replacement.revalidate().unwrap();
        assert!(
            retained
                .revalidate()
                .unwrap_err()
                .to_string()
                .contains("changed after publisher admission")
        );
    }

    #[test]
    fn publisher_runtime_authority_requires_complete_supported_ceiling() {
        let authority = runtime_authority();
        authority.validate().unwrap();
        let value = serde_json::to_value(&authority).unwrap();
        for field in value.as_object().unwrap().keys() {
            let mut omitted = value.clone();
            omitted.as_object_mut().unwrap().remove(field);
            assert!(
                serde_json::from_value::<ArtifactRuntimeAuthority>(omitted).is_err(),
                "missing {field} must not obtain a permissive default"
            );
        }
        for mutate in [
            (|authority: &mut ArtifactRuntimeAuthority| authority.max_instructions = 0)
                as fn(&mut ArtifactRuntimeAuthority),
            |authority| authority.max_registers = 65_537,
            |authority| authority.max_call_depth = 10_001,
            |authority| authority.max_heap_objects = 0,
            |authority| authority.max_total_memory_bytes = 0,
            |authority| authority.max_console_entries = 0,
            |authority| authority.max_parse_source_bytes = 0,
            |authority| authority.max_parse_tokens = 0,
            |authority| authority.max_parse_recursion_depth = 0,
            |authority| authority.policy_revision = " ".into(),
            |authority| authority.schema_version.push_str("-unknown"),
            |authority| authority.allowed_capabilities.push("net".into()),
            |authority| authority.allowed_capabilities.push("console".into()),
            |authority| {
                authority
                    .allowed_capabilities
                    .retain(|capability| capability != "console")
            },
            |authority| {
                authority
                    .allowed_capabilities
                    .retain(|capability| capability != "heap_allocate")
            },
            |authority| {
                authority
                    .allowed_capabilities
                    .retain(|capability| capability != "vm_dispatch")
            },
        ] {
            let mut invalid = authority.clone();
            mutate(&mut invalid);
            assert!(invalid.validate().is_err(), "{invalid:?}");
        }
        let mut unknown = value;
        unknown["max_network_requests"] = 1.into();
        assert!(serde_json::from_value::<ArtifactRuntimeAuthority>(unknown).is_err());
    }

    #[test]
    fn publisher_runtime_authority_is_bound_to_signature_and_retained_approval() {
        let authority = runtime_authority();
        let fixture = Fixture::new("console.log(require('./side.cjs'));\n")
            .with_runtime_authority(&authority);
        let approval = fixture.approval();
        assert_eq!(approval.runtime_authority(), Some(&authority));
        assert_eq!(approval.graph_input_hash(), fixture.graph_hash);
        let encoded = serde_json::to_vec(&approval).unwrap();
        let handoff: PublisherSourceGraphApproval = serde_json::from_slice(&encoded).unwrap();
        handoff.revalidate().unwrap();
        assert_eq!(handoff, approval);

        let original: serde_json::Value = serde_json::from_slice(
            &STANDARD
                .decode(&fixture.manifest.manifest_bytes_b64)
                .unwrap(),
        )
        .unwrap();
        for (field, replacement) in [
            ("policy_revision", serde_json::json!("review-forged")),
            ("allow_process_shape", serde_json::json!(true)),
            (
                "allowed_capabilities",
                serde_json::json!([
                    "builtin",
                    "console",
                    "fs_read",
                    "heap_allocate",
                    "module_load",
                    "network_egress",
                    "vm_dispatch"
                ]),
            ),
            ("max_instructions", serde_json::json!(200_000)),
            ("max_registers", serde_json::json!(256)),
            ("max_call_depth", serde_json::json!(64)),
            ("max_heap_objects", serde_json::json!(20_000)),
            (
                "max_total_memory_bytes",
                serde_json::json!(32 * 1024 * 1024),
            ),
            ("max_console_entries", serde_json::json!(256)),
            ("max_parse_source_bytes", serde_json::json!(128 * 1024)),
            ("max_parse_tokens", serde_json::json!(16_384)),
            ("max_parse_recursion_depth", serde_json::json!(128)),
        ] {
            let mut signed = original.clone();
            signed["runtime_authority"][field] = replacement;
            let mut substituted = fixture.manifest.clone();
            substituted.manifest_bytes_b64 = STANDARD.encode(serde_json::to_vec(&signed).unwrap());
            let error = verify_artifact_bytes(
                &substituted,
                &fixture.bytes,
                Some(&fixture.key.verifying_key()),
            )
            .unwrap_err();
            assert_eq!(
                error.kind,
                ArtifactVerificationFailure::InvalidSignature,
                "{field}"
            );
        }

        // A legitimately re-signed wider policy is still a different admission.
        let mut wider = authority;
        wider.allowed_capabilities.push("network_egress".into());
        let fixture = fixture.with_runtime_authority(&wider);
        fixture.approval().revalidate().unwrap();
        assert!(
            approval
                .revalidate()
                .unwrap_err()
                .to_string()
                .contains("changed after publisher admission")
        );
    }

    #[test]
    fn publisher_runtime_authority_cannot_be_downgraded_to_source_only_schema() {
        use super::super::extension_registry::{
            EXTENSION_REGISTRATION_AUTHORITY_MANIFEST_SCHEMA,
            EXTENSION_REGISTRATION_MANIFEST_SCHEMA,
        };
        let fixture = Fixture::new("console.log(42);\n");
        assert!(fixture.approval().runtime_authority().is_none());
        let original: serde_json::Value = serde_json::from_slice(
            &STANDARD
                .decode(&fixture.manifest.manifest_bytes_b64)
                .unwrap(),
        )
        .unwrap();
        for (schema, authority) in [
            (
                EXTENSION_REGISTRATION_MANIFEST_SCHEMA,
                Some(runtime_authority()),
            ),
            (EXTENSION_REGISTRATION_AUTHORITY_MANIFEST_SCHEMA, None),
            (
                "franken-node/extension-registration-manifest/v3",
                Some(runtime_authority()),
            ),
        ] {
            let mut signed = original.clone();
            signed["schema_version"] = schema.into();
            signed["runtime_authority"] = serde_json::to_value(authority).unwrap();
            let signed = serde_json::to_vec(&signed).unwrap();
            let mut manifest = fixture.manifest.clone();
            manifest.manifest_bytes_b64 = STANDARD.encode(&signed);
            manifest.extension.signature.signature_bytes = sign_bytes(&fixture.key, &signed);
            assert_eq!(
                verify_artifact_bytes(
                    &manifest,
                    &fixture.bytes,
                    Some(&fixture.key.verifying_key())
                )
                .unwrap_err()
                .kind,
                ArtifactVerificationFailure::InvalidMetadata,
                "{schema}"
            );
        }
        let authority = runtime_authority();
        let mut reordered = authority.clone();
        reordered.allowed_capabilities.reverse();
        assert_eq!(
            authority.commitment().unwrap(),
            reordered.commitment().unwrap()
        );
        reordered.max_instructions += 1;
        assert_ne!(
            authority.commitment().unwrap(),
            reordered.commitment().unwrap()
        );
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
    fn authenticated_source_owner_ignores_absent_replaced_and_symlinked_live_sources() {
        let source = "console.log(require('./side.cjs'));\n";
        let fixture = Fixture::new(source);
        let approval = fixture.approval();
        for path in ["app.cjs", "side.cjs"] {
            std::fs::rename(
                fixture.directory.path().join(path),
                fixture.directory.path().join(format!("retained-{path}")),
            )
            .unwrap();
        }
        let assert_original = |graph: &super::super::module_resolution_graph::file_resolution::source_graph::CapturedModuleGraph| {
            assert_eq!(graph.report().input_hash, fixture.graph_hash);
            assert_eq!(
                graph.source_bytes(&graph.report().resolved_entrypoint),
                Some(source.as_bytes())
            );
            let dependency = graph.report().modules.iter()
                .find(|module| module.id.path == "side.cjs")
                .expect("signed dependency remains in the source owner");
            assert_eq!(graph.source_bytes(&dependency.id), Some(b"module.exports = 42;\n".as_slice()));
        };
        let retained = approval.revalidate_source_graph().unwrap();
        assert_original(&retained);
        std::fs::write(fixture.directory.path().join("side.cjs"), "module.exports = 9001;\n")
            .unwrap();
        let foreign = tempfile::tempdir().unwrap();
        let foreign_entry = foreign.path().join("unsigned.cjs");
        std::fs::write(&foreign_entry, "throw new Error('unsigned replacement');\n").unwrap();
        std::os::unix::fs::symlink(&foreign_entry, fixture.directory.path().join("app.cjs"))
            .unwrap();
        assert_original(&approval.revalidate_source_graph().unwrap());

        // Losing or corrupting the authenticated capsule must never cause a
        // fallback to the installed source tree. An already returned owner
        // continues to contain the exact bytes that were authenticated.
        let capsule_path = fixture.directory.path().join(&fixture.manifest.artifact_file_name);
        std::fs::rename(&capsule_path, capsule_path.with_extension("retained-capsule")).unwrap();
        assert!(approval.revalidate_source_graph().is_err());
        std::fs::write(&capsule_path, b"substituted capsule").unwrap();
        let error = approval.revalidate_source_graph().err().expect("artifact hash refusal");
        assert!(error.to_string().contains("artifact hash mismatch"), "{error:#}");
        assert_original(&retained);
    }

    #[test]
    fn capsule_module_packages_retain_alias_identity_and_version_without_live_metadata() {
        let fixture = Fixture::with_modules(
            "app.cjs",
            "console.log(require('alias'));\n",
            &[
                ("package.json", r#"{"dependencies":{"alias":"npm:real-package@2.3.4"}}"#),
                ("node_modules/alias/package.json", r#"{"name":"real-package","version":"2.3.4","main":"index.cjs"}"#),
                ("node_modules/alias/index.cjs", "module.exports = 42;\n"),
            ],
        );
        let approval = fixture.approval();
        let expected = vec![PublisherModulePackage {
            extension_id: "npm:real-package".into(),
            location: "node_modules/alias".into(),
            version: Some("2.3.4".into()),
        }];
        assert_eq!(approval.module_packages().unwrap(), expected);
        std::fs::write(fixture.directory.path().join("package.json"), "{}").unwrap();
        std::fs::rename(
            fixture.directory.path().join("node_modules"),
            fixture.directory.path().join("retained-modules"),
        ).unwrap();
        assert_eq!(approval.module_packages().unwrap(), expected);
    }

    #[test]
    fn capsule_module_packages_include_explicit_undeclared_placements() {
        for (location, identity) in [
            ("node_modules/@scope/pkg", "npm:@scope/pkg"),
            ("node_modules/.pnpm/pkg@1.0.0/node_modules/pkg", "npm:pkg"),
        ] {
            let path = format!("{location}/index.cjs");
            let source = format!("console.log(require('./{path}'));\n");
            let fixture = Fixture::with_modules("app.cjs", &source, &[(&path, "module.exports = 42;\n")]);
            assert_eq!(fixture.approval().module_packages().unwrap(), vec![PublisherModulePackage {
                extension_id: identity.into(), location: location.into(), version: None,
            }]);
        }
    }

    #[test]
    fn deployment_handoff_commitment_binds_the_entire_publisher_approval() {
        let fixture = Fixture::new("console.log(require('./side.cjs'));\n")
            .with_runtime_authority(&runtime_authority());
        let approval = fixture.approval();
        let commitment = approval.admission_sha256().unwrap();
        let roundtrip: PublisherSourceGraphApproval =
            serde_json::from_slice(&serde_json::to_vec(&approval).unwrap()).unwrap();
        assert_eq!(roundtrip.admission_sha256().unwrap(), commitment);
        for mutate in [
            |value: &mut PublisherSourceGraphApproval| value.identity.version.push_str("-foreign"),
            |value: &mut PublisherSourceGraphApproval| {
                value.publisher_public_key_hex = "11".repeat(32)
            },
            |value: &mut PublisherSourceGraphApproval| {
                value.manifest_sha256 = format!("sha256:{}", "2".repeat(64))
            },
            |value: &mut PublisherSourceGraphApproval| {
                value.graph_input_hash = format!("sha256:{}", "3".repeat(64))
            },
            |value: &mut PublisherSourceGraphApproval| {
                value.capsule_digest = format!("sha256:{}", "4".repeat(64))
            },
            |value: &mut PublisherSourceGraphApproval| value.entrypoint = "other.cjs".to_string(),
            |value: &mut PublisherSourceGraphApproval| {
                value.additional_conditions.push("development".to_string())
            },
            |value: &mut PublisherSourceGraphApproval| {
                value.contained_symlinks = !value.contained_symlinks
            },
            |value: &mut PublisherSourceGraphApproval| value.identity.runtime_authority = None,
        ] {
            let mut substituted = approval.clone();
            mutate(&mut substituted);
            assert_ne!(substituted.admission_sha256().unwrap(), commitment);
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

            // Reauthentication returns the immutable owner consumed by native
            // execution. Moving sources proves that this handoff never consults
            // live dependency bytes or newly present optional modules.
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
            let retained = approval.revalidate_source_graph().unwrap();
            assert_eq!(retained.report(), graph.report());
            for module in &graph.report().modules {
                assert_eq!(
                    retained.source_bytes(&module.id),
                    graph.source_bytes(&module.id)
                );
            }
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
