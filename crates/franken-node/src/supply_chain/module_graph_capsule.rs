//! Portable replay of source-graph analysis from captured observations only.
//!
//! A capsule contains source/manifest bytes, link text and negative probes. It
//! never extracts files or evaluates JavaScript. Replay requires an independent
//! capsule pin and re-runs the production scanner/resolver, rather than trusting
//! a serialized report. A self-consistent capsule is not provenance or authority.

use super::super::{MAX_CAPTURE, MAX_FILE, MAX_PROBES, validate_link_target};
#[cfg(any(feature = "engine", test))]
use super::super::{Mapping, Probe};
use super::{CapturedModuleGraph, Entry, GraphOptions, Resolver, Result, build, error, parent, validate_path};
#[cfg(any(feature = "engine", test))]
use super::{
    CommonJsSearch, EdgeState, ImportAttributes, LoadKind, ModuleId, ResolutionError,
    ResolutionTarget, ResolutionUrl, SourceEdge, SourceGraphReport, SourceModule, SourceSite,
    compute_input_hash,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
#[cfg(any(feature = "engine", test))]
use std::path::Path;
use std::rc::Rc;

const MAGIC: &[u8; 8] = b"FNSGCAP1";
const PREFIX_BYTES: usize = 12;
const MAX_HEADER_BYTES: usize = 8 * 1024 * 1024;
const SCHEMA: &str = "franken-node/module-source-capsule/v1";
const HASH_DOMAIN: &[u8] = b"franken-node/module-source-capsule/v1\0";
/// Maximum encoded size, checked before hashing or parsing untrusted input.
pub const MAX_CAPSULE_BYTES: usize = PREFIX_BYTES + MAX_HEADER_BYTES + MAX_CAPTURE;
/// Maximum capsule size carried inline over the authenticated parent-worker IPC
/// frame for live-disk verification without re-running tree-sitter parsing.
#[cfg(any(feature = "engine", test))]
pub(crate) const MAX_ADMITTED_WIRE_CAPSULE_BYTES: usize = 256 * 1024;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    schema_version: String,
    graph_hash: String,
    entrypoint: String,
    options: GraphOptions,
    inputs: Vec<Input>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    /// Empty string is the captured root. All other paths are physical,
    /// canonical, project-relative paths, not names to extract on the host.
    path: String,
    content: Content,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Content {
    Missing,
    Directory,
    FileMetadata,
    File { bytes: usize, sha256: String },
    Symlink { target: String, sha256: String },
}

/// Deliberately not Debug/Serialize: the bytes include private project sources.
/// Callers must explicitly choose whether and where to persist this artifact.
pub struct EncodedCapsule {
    bytes: Vec<u8>,
    digest: String,
}

impl EncodedCapsule {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn digest(&self) -> &str {
        &self.digest
    }
}

fn invalid(detail: &str) -> super::ResolutionError {
    error("ERR_MODULE_CAPSULE_INVALID", detail)
}

fn limit() -> super::ResolutionError {
    error(
        "ERR_MODULE_CAPSULE_LIMIT",
        "capsule exceeds its header, input or payload bound",
    )
}

fn valid_hash(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(valid_digest)
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

/// Content commitment only. Callers must authenticate bytes independently or
/// compare against an independently retained digest before treating a capsule
/// as approved source. Computing this value grants no publisher authority.
pub fn digest(bytes: &[u8]) -> String {
    let mut hash = Sha256::new();
    hash.update(HASH_DOMAIN);
    hash.update((bytes.len() as u64).to_le_bytes());
    hash.update(bytes);
    format!("sha256:{}", hex::encode(hash.finalize()))
}

fn frame(header: &Header, payload: &[u8]) -> Result<Vec<u8>> {
    let metadata =
        serde_json::to_vec(header).map_err(|_| invalid("cannot encode capsule header"))?;
    if metadata.len() > MAX_HEADER_BYTES || payload.len() > MAX_CAPTURE {
        return Err(limit());
    }
    let length = u32::try_from(metadata.len()).map_err(|_| limit())?;
    let mut bytes = Vec::with_capacity(PREFIX_BYTES + metadata.len() + payload.len());
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&length.to_le_bytes());
    bytes.extend_from_slice(&metadata);
    bytes.extend_from_slice(payload);
    Ok(bytes)
}

/// Seal exactly the observations retained by a completed (possibly incomplete)
/// analysis. No source pathname is reopened, including manifests and links.
/// The payload uses raw bytes, not JSON numbers/base64 or a filesystem archive.
pub fn encode(graph: &CapturedModuleGraph) -> Result<EncodedCapsule> {
    let mut payload = Vec::new();
    let mut inputs = Vec::new();
    for (path, entry) in &graph.inputs {
        let content = match entry.as_ref() {
            Entry::Missing => Content::Missing,
            Entry::Directory(_) => Content::Directory,
            Entry::FileMetadata { .. } => Content::FileMetadata,
            Entry::File { bytes, sha256 } => {
                if payload.len().saturating_add(bytes.len()) > MAX_CAPTURE {
                    return Err(limit());
                }
                payload.extend_from_slice(bytes);
                Content::File {
                    bytes: bytes.len(),
                    sha256: sha256.clone(),
                }
            }
            Entry::Symlink { target, sha256 } => Content::Symlink {
                target: target.clone(),
                sha256: sha256.clone(),
            },
        };
        inputs.push(Input {
            path: path.clone(),
            content,
        });
        if inputs.len() > MAX_PROBES {
            return Err(limit());
        }
    }
    let header = Header {
        schema_version: SCHEMA.into(),
        graph_hash: graph.report.input_hash.clone(),
        entrypoint: graph.report.entrypoint.clone(),
        options: graph.report.options.clone(),
        inputs,
    };
    let bytes = frame(&header, &payload)?;
    Ok(EncodedCapsule {
        digest: digest(&bytes),
        bytes,
    })
}

fn parse_frame(bytes: &[u8]) -> Result<(Header, &[u8])> {
    if bytes.len() > MAX_CAPSULE_BYTES {
        return Err(limit());
    }
    if bytes.len() < PREFIX_BYTES || &bytes[..8] != MAGIC {
        return Err(invalid("invalid capsule framing"));
    }
    let length = u32::from_le_bytes(
        bytes[8..12]
            .try_into()
            .map_err(|_| invalid("invalid header length"))?,
    ) as usize;
    if length > MAX_HEADER_BYTES {
        return Err(limit());
    }
    let end = PREFIX_BYTES.checked_add(length).ok_or_else(limit)?;
    let metadata = bytes
        .get(PREFIX_BYTES..end)
        .ok_or_else(|| invalid("truncated capsule header"))?;
    let header: Header =
        serde_json::from_slice(metadata).map_err(|_| invalid("invalid capsule header JSON"))?;
    // One canonical representation prevents duplicate fields, ignored extensions
    // and alternate spellings from becoming unreviewed wire-format variants.
    let canonical = serde_json::to_vec(&header).map_err(|_| invalid("invalid capsule header"))?;
    if canonical != metadata {
        return Err(invalid("noncanonical capsule header"));
    }
    if header.schema_version != SCHEMA || !valid_hash(&header.graph_hash) {
        return Err(invalid("unsupported capsule schema or graph hash"));
    }
    Ok((header, &bytes[end..]))
}

fn recorded_resolver(header: &Header, payload: &[u8]) -> Result<Resolver> {
    if header.inputs.is_empty() || header.inputs.len() > MAX_PROBES || payload.len() > MAX_CAPTURE {
        return Err(limit());
    }
    validate_path(&header.entrypoint)?;
    let mut canonical_options = header.options.clone();
    canonical_options.canonicalize_conditions()?;
    if canonical_options != header.options {
        return Err(invalid("capsule conditions are not canonical"));
    }
    let conditions = canonical_options.conditions.unwrap_or_default();
    let mut entries = BTreeMap::<String, Rc<Entry>>::new();
    let mut previous: Option<&str> = None;
    let mut offset = 0_usize;
    let mut captured = 0_usize;
    for input in &header.inputs {
        if previous.is_some_and(|p| p >= input.path.as_str()) {
            return Err(invalid("capsule observations must be unique and sorted"));
        }
        previous = Some(&input.path);
        if input.path.is_empty() {
            if !matches!(input.content, Content::Directory) {
                return Err(invalid("capsule root must be a directory"));
            }
        } else {
            validate_path(&input.path)?;
            if !entries.get(parent(&input.path)).is_some_and(|e| e.is_dir()) {
                return Err(invalid(
                    "observation has no captured physical parent directory",
                ));
            }
        }
        let entry = match &input.content {
            Content::Missing => Entry::Missing,
            Content::Directory => Entry::Directory(None),
            Content::FileMetadata => Entry::FileMetadata { version: None },
            Content::File { bytes, sha256 } => {
                let cap = if input.path.rsplit('/').next() == Some("package.json") {
                    super::super::super::package_targets::MAX_MANIFEST_BYTES
                } else {
                    MAX_FILE
                };
                if *bytes > cap {
                    return Err(limit());
                }
                let end = offset.checked_add(*bytes).ok_or_else(limit)?;
                let source = payload
                    .get(offset..end)
                    .ok_or_else(|| invalid("truncated capsule payload"))?;
                if !valid_digest(sha256) || hex::encode(Sha256::digest(source)) != *sha256 {
                    return Err(invalid("captured file digest mismatch"));
                }
                offset = end;
                captured = captured.checked_add(source.len()).ok_or_else(limit)?;
                if captured > MAX_CAPTURE {
                    return Err(limit());
                }
                Entry::File {
                    bytes: source.to_vec(),
                    sha256: sha256.clone(),
                }
            }
            Content::Symlink { target, sha256 } => {
                if header.options.symlink_policy != super::SymlinkPolicy::Contained {
                    return Err(invalid("symlink observation violates the captured policy"));
                }
                validate_link_target(target)?;
                if !valid_digest(sha256)
                    || hex::encode(Sha256::digest(target.as_bytes())) != *sha256
                {
                    return Err(invalid("captured link digest mismatch"));
                }
                captured = captured.checked_add(target.len()).ok_or_else(limit)?;
                if captured > MAX_CAPTURE {
                    return Err(limit());
                }
                Entry::Symlink {
                    target: target.clone(),
                    sha256: sha256.clone(),
                }
            }
        };
        entries.insert(input.path.clone(), Rc::new(entry));
    }
    if !entries.get("").is_some_and(|e| e.is_dir()) || offset != payload.len() {
        return Err(invalid("missing capsule root or unclaimed payload bytes"));
    }
    Ok(Resolver {
        entries,
        manifests: BTreeMap::new(),
        scopes: BTreeMap::new(),
        packages: super::super::PackageCache::default(),
        captured,
        conditions,
        mappings: Vec::new(),
        symlink_policy: header.options.symlink_policy,
        sealed: true,
        observed: BTreeSet::new(),
        url_lookup: false,
    })
}

/// Verify an independently obtained capsule pin, then rerun the actual graph
/// builder entirely against its recorded inputs. No project path is accepted;
/// no directories/files/links are created, opened or extracted during replay.
/// An unrecorded probe is fatal, never invented as a missing file or read from
/// the current machine. Incomplete analysis is reproduced, not upgraded.
pub fn replay(bytes: &[u8], expected_capsule_hash: &str) -> Result<CapturedModuleGraph> {
    if !valid_hash(expected_capsule_hash) {
        return Err(error(
            "ERR_MODULE_CAPSULE_PIN_INVALID",
            "expected capsule hash must be sha256: plus 64 lowercase hexadecimal digits",
        ));
    }
    if bytes.len() > MAX_CAPSULE_BYTES {
        return Err(limit());
    }
    if digest(bytes) != expected_capsule_hash {
        return Err(error(
            "ERR_MODULE_CAPSULE_PIN_MISMATCH",
            "capsule bytes do not match the independently supplied pin",
        ));
    }
    let (header, payload) = parse_frame(bytes)?;
    let resolver = recorded_resolver(&header, payload)?;
    let graph = build(resolver, &header.entrypoint, header.options)?;
    if graph.report.input_hash != header.graph_hash
        || graph.report.probes.len() != graph.inputs.len()
    {
        return Err(error(
            "ERR_MODULE_CAPSULE_REPLAY_MISMATCH",
            "recomputed analysis differs from the captured graph or leaves unused observations",
        ));
    }
    Ok(graph)
}

#[cfg(any(feature = "engine", test))]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireResolutionError {
    code: String,
    detail: String,
}

#[cfg(any(feature = "engine", test))]
fn static_resolution_error_code(code: &str) -> Option<&'static str> {
    match code {
        "ERR_RUNTIME_MODULE_REQUIRED" => Some("ERR_RUNTIME_MODULE_REQUIRED"),
        "MODULE_NOT_FOUND" => Some("MODULE_NOT_FOUND"),
        "ERR_MODULE_NOT_FOUND" => Some("ERR_MODULE_NOT_FOUND"),
        "ERR_PACKAGE_PATH_NOT_EXPORTED" => Some("ERR_PACKAGE_PATH_NOT_EXPORTED"),
        "ERR_PACKAGE_IMPORT_NOT_DEFINED" => Some("ERR_PACKAGE_IMPORT_NOT_DEFINED"),
        "ERR_INVALID_PACKAGE_TARGET" => Some("ERR_INVALID_PACKAGE_TARGET"),
        "ERR_INVALID_PACKAGE_CONFIG" => Some("ERR_INVALID_PACKAGE_CONFIG"),
        "ERR_INVALID_MODULE_SPECIFIER" => Some("ERR_INVALID_MODULE_SPECIFIER"),
        "ERR_INVALID_URL" => Some("ERR_INVALID_URL"),
        "ERR_UNSUPPORTED_DIR_IMPORT" => Some("ERR_UNSUPPORTED_DIR_IMPORT"),
        "ERR_UNSUPPORTED_ESM_URL_SCHEME" => Some("ERR_UNSUPPORTED_ESM_URL_SCHEME"),
        _ => None,
    }
}

#[cfg(any(feature = "engine", test))]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireSourceEdge {
    importer: ModuleId,
    site: SourceSite,
    kind: LoadKind,
    deferred_or_conditional: bool,
    specifier: Option<String>,
    #[serde(default)]
    dirname_request: bool,
    #[serde(default)]
    normalized_dirname_request: bool,
    #[serde(default)]
    commonjs_search: Option<CommonJsSearch>,
    #[serde(default)]
    import_attributes: ImportAttributes,
    conditions: Vec<String>,
    state: EdgeState,
    target: Option<ModuleId>,
    #[serde(default)]
    resolved_url: Option<ResolutionUrl>,
    error: Option<WireResolutionError>,
    mappings: Vec<Mapping>,
}

/// Bounded parent-to-worker snapshot of an already-captured frozen source graph
/// and its `FNSGCAP1` capsule bytes.
///
/// The worker never trusts this snapshot blindly: [`Self::verify_live_and_reconstruct`]
/// validates the capsule digest, canonical header, every file's SHA-256 against
/// payload bytes, recomputes `SourceGraphReport.input_hash`, and re-probes every
/// single recorded filesystem observation against the live project directory
/// under `O_NOFOLLOW | O_DIRECTORY`. Any mismatch falls back to full live
/// `source_graph::capture`.
#[cfg(any(feature = "engine", test))]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AdmittedSourceGraphWire {
    capsule_digest: String,
    capsule_base64: String,
    schema_version: String,
    scope: String,
    entrypoint: String,
    resolved_entrypoint: ModuleId,
    options: GraphOptions,
    modules: Vec<SourceModule>,
    #[serde(default)]
    resolution_targets: Vec<ResolutionTarget>,
    edges: Vec<WireSourceEdge>,
    probes: Vec<Probe>,
    input_hash: String,
    fully_resolved: bool,
    runtime_completeness: bool,
    type_resolution_performed: bool,
    execution_performed: bool,
    release_certification: bool,
}

#[cfg(any(feature = "engine", test))]
impl AdmittedSourceGraphWire {
    pub(crate) fn from_graph_and_capsule(
        graph: &CapturedModuleGraph,
        encoded: &EncodedCapsule,
    ) -> Option<Self> {
        use base64::Engine as _;

        if encoded.bytes().len() > MAX_ADMITTED_WIRE_CAPSULE_BYTES {
            return None;
        }
        let report = graph.report();
        if !report.diagnostics.is_empty()
            || report.probes.len() > 1024
            || report.edges.len() > 1024
            || report.modules.len() > 256
        {
            return None;
        }
        let mut edges = Vec::with_capacity(report.edges.len());
        for edge in &report.edges {
            let wire_error = match &edge.error {
                Some(err) => {
                    static_resolution_error_code(err.code)?;
                    Some(WireResolutionError {
                        code: err.code.to_owned(),
                        detail: err.detail.clone(),
                    })
                }
                None => None,
            };
            edges.push(WireSourceEdge {
                importer: edge.importer.clone(),
                site: edge.site.clone(),
                kind: edge.kind,
                deferred_or_conditional: edge.deferred_or_conditional,
                specifier: edge.specifier.clone(),
                dirname_request: edge.dirname_request,
                normalized_dirname_request: edge.normalized_dirname_request,
                commonjs_search: edge.commonjs_search.clone(),
                import_attributes: edge.import_attributes.clone(),
                conditions: edge.conditions.clone(),
                state: edge.state,
                target: edge.target.clone(),
                resolved_url: edge.resolved_url.clone(),
                error: wire_error,
                mappings: edge.mappings.clone(),
            });
        }
        Some(Self {
            capsule_digest: encoded.digest().to_owned(),
            capsule_base64: base64::engine::general_purpose::STANDARD.encode(encoded.bytes()),
            schema_version: report.schema_version.clone(),
            scope: report.scope.clone(),
            entrypoint: report.entrypoint.clone(),
            resolved_entrypoint: report.resolved_entrypoint.clone(),
            options: report.options.clone(),
            modules: report.modules.clone(),
            resolution_targets: report.resolution_targets.clone(),
            edges,
            probes: report.probes.clone(),
            input_hash: report.input_hash.clone(),
            fully_resolved: report.fully_resolved,
            runtime_completeness: report.runtime_completeness,
            type_resolution_performed: report.type_resolution_performed,
            execution_performed: report.execution_performed,
            release_certification: report.release_certification,
        })
    }

    pub(crate) fn input_hash(&self) -> &str {
        &self.input_hash
    }

    pub(crate) fn verify_live_and_reconstruct(
        &self,
        project: &Path,
        entrypoint: &str,
        expected_options: &GraphOptions,
        expected_graph_hash: Option<&str>,
    ) -> Option<CapturedModuleGraph> {
        use base64::Engine as _;

        if !valid_hash(&self.capsule_digest) || !valid_hash(&self.input_hash) {
            return None;
        }
        if self.schema_version != super::REPORT_SCHEMA_VERSION
            || self.scope != super::REPORT_SCOPE
            || self.runtime_completeness
            || self.type_resolution_performed
            || self.execution_performed
            || self.release_certification
        {
            return None;
        }
        if expected_graph_hash.is_some_and(|pin| pin != self.input_hash) {
            return None;
        }
        validate_path(entrypoint).ok()?;
        let mut canonical_options = expected_options.clone();
        canonical_options.canonicalize_conditions().ok()?;
        if self.entrypoint != entrypoint || self.options != canonical_options {
            return None;
        }
        // Reject oversized base64 before allocating decoded bytes.
        let max_b64_len = MAX_ADMITTED_WIRE_CAPSULE_BYTES.div_ceil(3).saturating_mul(4);
        if self.capsule_base64.len() > max_b64_len {
            return None;
        }
        let capsule_bytes = base64::engine::general_purpose::STANDARD
            .decode(&self.capsule_base64)
            .ok()?;
        if capsule_bytes.len() > MAX_ADMITTED_WIRE_CAPSULE_BYTES
            || digest(&capsule_bytes) != self.capsule_digest
        {
            return None;
        }
        let (header, payload) = parse_frame(&capsule_bytes).ok()?;
        if header.entrypoint != entrypoint
            || header.options != canonical_options
            || header.graph_hash != self.input_hash
            || header.inputs.len() != self.probes.len()
        {
            return None;
        }
        let mut recorded = recorded_resolver(&header, payload).ok()?;
        recorded.sealed = false;
        if recorded.probes() != self.probes {
            return None;
        }

        let mut edges = Vec::with_capacity(self.edges.len());
        for edge in &self.edges {
            let error = match &edge.error {
                Some(err) => Some(ResolutionError {
                    code: static_resolution_error_code(&err.code)?,
                    detail: err.detail.clone(),
                }),
                None => None,
            };
            edges.push(SourceEdge {
                importer: edge.importer.clone(),
                site: edge.site.clone(),
                kind: edge.kind,
                deferred_or_conditional: edge.deferred_or_conditional,
                specifier: edge.specifier.clone(),
                dirname_request: edge.dirname_request,
                normalized_dirname_request: edge.normalized_dirname_request,
                commonjs_search: edge.commonjs_search.clone(),
                import_attributes: edge.import_attributes.clone(),
                conditions: edge.conditions.clone(),
                state: edge.state,
                target: edge.target.clone(),
                resolved_url: edge.resolved_url.clone(),
                error,
                mappings: edge.mappings.clone(),
            });
        }
        let mut report = SourceGraphReport {
            schema_version: self.schema_version.clone(),
            scope: self.scope.clone(),
            entrypoint: self.entrypoint.clone(),
            resolved_entrypoint: self.resolved_entrypoint.clone(),
            options: self.options.clone(),
            modules: self.modules.clone(),
            resolution_targets: self.resolution_targets.clone(),
            edges,
            diagnostics: Vec::new(),
            probes: self.probes.clone(),
            input_hash: String::new(),
            fully_resolved: self.fully_resolved,
            runtime_completeness: self.runtime_completeness,
            type_resolution_performed: self.type_resolution_performed,
            execution_performed: self.execution_performed,
            release_certification: self.release_certification,
        };
        let recomputed_hash = compute_input_hash(&report).ok()?;
        if recomputed_hash != self.input_hash || recomputed_hash != header.graph_hash {
            return None;
        }
        report.input_hash = recomputed_hash;

        // Bind every module and resolution target in `report` directly to its
        // SHA-256-verified capsule payload entry.
        let mut sources = BTreeMap::new();
        for module in &report.modules {
            let entry = recorded.entries.get(&module.id.path)?;
            let Entry::File { bytes, sha256 } = entry.as_ref() else {
                return None;
            };
            if bytes.len() != module.content_bytes || sha256 != &module.content_sha256 {
                return None;
            }
            if sources.insert(module.id.clone(), Rc::clone(entry)).is_some() {
                return None;
            }
        }
        if !sources.contains_key(&report.resolved_entrypoint) {
            return None;
        }
        for target in &report.resolution_targets {
            let entry = recorded.entries.get(&target.id.path)?;
            let Entry::File { bytes, sha256 } = entry.as_ref() else {
                return None;
            };
            if bytes.len() != target.content_bytes || sha256 != &target.content_sha256 {
                return None;
            }
        }

        // Re-verify every single recorded filesystem probe against the live
        // project directory under `O_NOFOLLOW | O_DIRECTORY` and the exact
        // `symlink_policy`. Because `build()` is a pure deterministic function
        // of these inputs, exact live-disk agreement proves live `capture()`
        // would produce the identical graph.
        let mut live = Resolver::new(project, &[], canonical_options.symlink_policy).ok()?;
        for (path, expected) in &recorded.entries {
            if path.is_empty() {
                if !expected.is_dir() {
                    return None;
                }
                continue;
            }
            let read_bytes = !matches!(expected.as_ref(), Entry::FileMetadata { .. });
            let observed = live.raw_probe_with_bytes(path, read_bytes).ok()?;
            let matched = match (expected.as_ref(), observed.as_ref()) {
                (Entry::Missing, Entry::Missing)
                | (Entry::Directory(_), Entry::Directory(_))
                | (Entry::FileMetadata { .. }, Entry::FileMetadata { .. }) => true,
                (
                    Entry::File {
                        bytes: expected_bytes,
                        sha256: expected_sha,
                    },
                    Entry::File {
                        bytes: live_bytes,
                        sha256: live_sha,
                    },
                ) => expected_sha == live_sha && expected_bytes == live_bytes,
                (
                    Entry::Symlink {
                        target: expected_target,
                        sha256: expected_sha,
                    },
                    Entry::Symlink {
                        target: live_target,
                        sha256: live_sha,
                    },
                ) => expected_sha == live_sha && expected_target == live_target,
                _ => false,
            };
            if !matched {
                return None;
            }
        }
        if live.probes() != report.probes {
            return None;
        }

        Some(CapturedModuleGraph {
            report,
            sources,
            inputs: recorded.entries,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::super::{EdgeState, ModuleId, capture};
    use super::*;
    use std::path::Path;

    fn put(root: &Path, path: &str, bytes: impl AsRef<[u8]>) {
        let path = root.join(path);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, bytes).unwrap();
    }

    fn simple(root: &Path) -> CapturedModuleGraph {
        put(root, "app.mjs", "export * from './dep.mjs';");
        put(root, "dep.mjs", "import './app.mjs'; export const n=1;");
        capture(root, "app.mjs", GraphOptions::default()).unwrap()
    }

    fn modify(capsule: &EncodedCapsule, edit: impl FnOnce(&mut Header)) -> Vec<u8> {
        let (mut header, payload) = parse_frame(capsule.bytes()).unwrap();
        edit(&mut header);
        frame(&header, payload).unwrap()
    }

    fn failure(bytes: &[u8]) -> String {
        replay(bytes, &digest(bytes))
            .err()
            .expect("must reject capsule")
            .code
            .into()
    }

    #[test]
    fn import_meta_resolve_capsule_retains_stat_and_negative_observations() {
        let root = tempfile::tempdir().unwrap();
        put(root.path(), "asset.node", b"\xff\0opaque bytes");
        std::fs::create_dir(root.path().join("nested")).unwrap();
        put(
            root.path(),
            "app.mjs",
            "import.meta.resolve('./asset.node'); import.meta.resolve('./nested/missing.css');",
        );
        let graph = capture(root.path(), "app.mjs", GraphOptions::default()).unwrap();
        let capsule = encode(&graph).unwrap();
        let (header, _) = parse_frame(capsule.bytes()).unwrap();
        assert!(
            header.inputs.iter().any(|input| input.path == "asset.node"
                && matches!(input.content, Content::FileMetadata))
        );
        put(root.path(), "asset.node", b"different unparsed data");
        put(root.path(), "nested/missing.css", "now exists");
        assert_eq!(
            replay(capsule.bytes(), capsule.digest()).unwrap().report(),
            graph.report()
        );
        let omitted = modify(&capsule, |header| {
            header
                .inputs
                .retain(|input| input.path != "nested/missing.css")
        });
        assert_eq!(failure(&omitted), "ERR_MODULE_CAPSULE_INPUT_MISSING");
        let relabelled = modify(&capsule, |header| {
            header
                .inputs
                .iter_mut()
                .find(|input| input.path == "asset.node")
                .unwrap()
                .content = Content::Missing;
        });
        assert_eq!(failure(&relabelled), "ERR_MODULE_CAPSULE_REPLAY_MISMATCH");
    }

    #[test]
    fn admitted_wire_snapshot_verifies_live_disk_and_rejects_mutations() {
        let root = tempfile::tempdir().unwrap();
        put(
            root.path(),
            "node_modules/bench-pkg/package.json",
            r#"{"name":"bench-pkg","version":"1.0.0","main":"index.js"}"#,
        );
        put(
            root.path(),
            "node_modules/bench-pkg/index.js",
            "const h = require('./helper.js'); module.exports = h;",
        );
        put(
            root.path(),
            "node_modules/bench-pkg/helper.js",
            "module.exports = 42;",
        );
        put(
            root.path(),
            "app.js",
            "const path = require('node:path'); const p = require('bench-pkg'); console.log(path.sep, p);",
        );
        let options = GraphOptions::default();
        let captured = capture(root.path(), "app.js", options.clone()).unwrap();
        let encoded = encode(&captured).unwrap();
        let wire = AdmittedSourceGraphWire::from_graph_and_capsule(&captured, &encoded)
            .expect("clean graph converts to wire snapshot");
        let pin = captured.report().input_hash.clone();

        // Exact match on unchanged live disk reconstructs identical graph.
        let reconstructed = wire
            .verify_live_and_reconstruct(root.path(), "app.js", &options, Some(&pin))
            .expect("unchanged live project must verify");
        assert_eq!(reconstructed.report(), captured.report());
        for module in &captured.report().modules {
            assert_eq!(
                reconstructed.source_bytes(&module.id),
                captured.source_bytes(&module.id)
            );
        }

        // Wrong pin is refused.
        assert!(
            wire.verify_live_and_reconstruct(
                root.path(),
                "app.js",
                &options,
                Some(&format!("sha256:{}", "0".repeat(64))),
            )
            .is_none()
        );

        // Tampered wire field fails recomputed input_hash check.
        let mut tampered = wire.clone();
        tampered.fully_resolved = !tampered.fully_resolved;
        assert!(
            tampered
                .verify_live_and_reconstruct(root.path(), "app.js", &options, Some(&pin))
                .is_none()
        );

        // Live disk mutation of a transitive module is detected immediately.
        put(
            root.path(),
            "node_modules/bench-pkg/helper.js",
            "module.exports = 99;",
        );
        assert!(
            wire.verify_live_and_reconstruct(root.path(), "app.js", &options, Some(&pin))
                .is_none()
        );

        // Restoring the file succeeds again, while introducing a file at a
        // previously negative probe (package.json at project root) is detected.
        put(
            root.path(),
            "node_modules/bench-pkg/helper.js",
            "module.exports = 42;",
        );
        assert!(
            wire.verify_live_and_reconstruct(root.path(), "app.js", &options, Some(&pin))
                .is_some()
        );
        put(root.path(), "package.json", r#"{"type":"module"}"#);
        assert!(
            wire.verify_live_and_reconstruct(root.path(), "app.js", &options, Some(&pin))
                .is_none()
        );
    }

    #[test]
    fn import_meta_resolve_capsule_metadata_cannot_satisfy_source_delivery() {
        let root = tempfile::tempdir().unwrap();
        put(
            root.path(),
            "app.mjs",
            "import.meta.resolve('./dep.mjs'); import './dep.mjs';",
        );
        put(root.path(), "dep.mjs", "export const value=1;");
        let graph = capture(root.path(), "app.mjs", GraphOptions::default()).unwrap();
        let capsule = encode(&graph).unwrap();
        let (mut header, payload) = parse_frame(capsule.bytes()).unwrap();
        let mut offset = 0;
        let mut removed = None;
        for input in &mut header.inputs {
            if let Content::File { bytes, .. } = &input.content {
                let count = *bytes;
                if input.path == "dep.mjs" {
                    removed = Some((offset, count));
                    input.content = Content::FileMetadata;
                    break;
                }
                offset += count;
            }
        }
        let (offset, count) = removed.unwrap();
        let shortened = [&payload[..offset], &payload[offset + count..]].concat();
        let bytes = frame(&header, &shortened).unwrap();
        assert_eq!(failure(&bytes), "ERR_MODULE_CAPSULE_INPUT_MISSING");
    }

    #[test]
    fn capsule_replays_identical_report_and_bytes_after_source_replacement() {
        let root = tempfile::tempdir().unwrap();
        let graph = simple(root.path());
        let capsule = encode(&graph).unwrap();
        put(root.path(), "app.mjs", "import 'different';");
        put(root.path(), "dep.mjs", "throw Error('different bytes');");
        let replayed = replay(capsule.bytes(), capsule.digest()).unwrap();
        assert_eq!(graph.report(), replayed.report());
        for module in &graph.report().modules {
            assert_eq!(
                graph.source_bytes(&module.id),
                replayed.source_bytes(&module.id)
            );
        }
        let encoded_again = encode(&replayed).unwrap();
        assert_eq!(encoded_again.bytes(), capsule.bytes());
        assert_eq!(encoded_again.digest(), capsule.digest());
        assert!(
            replayed
                .inputs
                .values()
                .all(|e| !matches!(e.as_ref(), Entry::Directory(Some(_))))
        );
    }

    #[test]
    fn static_attributes_replay_from_raw_source_and_cannot_reuse_an_older_graph_pin() {
        let root = tempfile::tempdir().unwrap();
        put(
            root.path(),
            "app.mjs",
            "import './bridge.mjs'; import data from './data.json' with {type:'json'};",
        );
        put(
            root.path(),
            "bridge.mjs",
            "export {default} from './data.json' with {'type':'json'};",
        );
        put(root.path(), "data.json", "{\"answer\":42}");
        let graph = capture(root.path(), "app.mjs", GraphOptions::default()).unwrap();
        assert!(graph.report().fully_resolved);
        assert_eq!(
            graph.report().schema_version,
            "franken-node/module-source-graph/v3"
        );
        let encoded = encode(&graph).unwrap();
        put(
            root.path(),
            "app.mjs",
            "import './bridge.mjs'; import data from './data.json' with {type:'text'};",
        );
        put(root.path(), "data.json", "{\"answer\":99}");
        let restored = replay(encoded.bytes(), encoded.digest()).unwrap();
        assert_eq!(restored.report(), graph.report());
        assert_eq!(
            restored
                .report()
                .edges
                .iter()
                .filter(
                    |edge| edge.import_attributes.get("type").map(String::as_str) == Some("json")
                )
                .count(),
            2
        );
        let changed = capture(root.path(), "app.mjs", GraphOptions::default()).unwrap();
        assert_ne!(changed.report().input_hash, graph.report().input_hash);
        assert!(
            changed.report().edges.iter().any(|edge| edge
                .import_attributes
                .get("type")
                .map(String::as_str)
                == Some("text"))
        );
        let forged = modify(&encode(&changed).unwrap(), |header| {
            header.graph_hash = graph.report().input_hash.clone()
        });
        assert_eq!(failure(&forged), "ERR_MODULE_CAPSULE_REPLAY_MISMATCH");
        put(
            root.path(),
            "app.mjs",
            r#"import './data.json' with {type:'json','t\u0079pe':'json'};"#,
        );
        let duplicate = capture(root.path(), "app.mjs", GraphOptions::default()).unwrap();
        assert!(!duplicate.report().fully_resolved);
        let encoded = encode(&duplicate).unwrap();
        let replayed = replay(encoded.bytes(), encoded.digest()).unwrap();
        assert_eq!(replayed.report(), duplicate.report());
        assert!(
            replayed
                .report()
                .diagnostics
                .iter()
                .any(|notice| notice.code == "INVALID_IMPORT_ATTRIBUTES")
        );
    }

    #[test]
    fn incomplete_graph_preserves_missing_builtin_computed_and_parse_failures() {
        let root = tempfile::tempdir().unwrap();
        put(
            root.path(),
            "app.mjs",
            "import 'node:fs'; import './missing.mjs'; import './broken.mjs'; import(choice);",
        );
        put(root.path(), "broken.mjs", "export const = ;");
        let graph = capture(root.path(), "app.mjs", GraphOptions::default()).unwrap();
        let capsule = encode(&graph).unwrap();
        put(root.path(), "missing.mjs", "export const nowExists=1;");
        let replayed = replay(capsule.bytes(), capsule.digest()).unwrap();
        assert_eq!(graph.report(), replayed.report());
        assert!(!replayed.report().fully_resolved);
        for state in [
            EdgeState::Unresolved,
            EdgeState::RuntimeRequired,
            EdgeState::NonLiteral,
        ] {
            assert!(replayed.report().edges.iter().any(|e| e.state == state));
        }
    }

    #[test]
    fn capsule_retains_consulted_manifests_links_and_negative_probes() {
        let root = tempfile::tempdir().unwrap();
        put(root.path(), "app.mjs", "import 'linked';");
        put(
            root.path(),
            "pkg/package.json",
            r#"{"exports":"./index.mjs"}"#,
        );
        put(root.path(), "pkg/index.mjs", "export const n=1;");
        std::fs::create_dir(root.path().join("node_modules")).unwrap();
        std::os::unix::fs::symlink("../pkg", root.path().join("node_modules/linked")).unwrap();
        let graph = capture(
            root.path(),
            "app.mjs",
            GraphOptions {
                symlink_policy: super::super::SymlinkPolicy::Contained,
                conditions: None,
                ..GraphOptions::default()
            },
        )
        .unwrap();
        let capsule = encode(&graph).unwrap();
        put(root.path(), "pkg/package.json", r#"{"exports":null}"#);
        let replayed = replay(capsule.bytes(), capsule.digest()).unwrap();
        assert_eq!(graph.report(), replayed.report());
        assert!(
            replayed
                .report()
                .probes
                .iter()
                .any(|p| p.link_target.as_deref() == Some("../pkg"))
        );
    }

    #[test]
    fn binary_unanalyzable_sources_are_retained_without_serialized_source_reports() {
        let root = tempfile::tempdir().unwrap();
        put(root.path(), "app.mjs", b"\xff\x00private_source");
        let graph = capture(root.path(), "app.mjs", GraphOptions::default()).unwrap();
        let capsule = encode(&graph).unwrap();
        let replayed = replay(capsule.bytes(), capsule.digest()).unwrap();
        assert_eq!(graph.report(), replayed.report());
        assert_eq!(
            replayed.source_bytes(&ModuleId {
                path: "app.mjs".into(),
                url_suffix: String::new()
            }),
            Some(&b"\xff\x00private_source"[..])
        );
        assert!(
            !serde_json::to_string(replayed.report())
                .unwrap()
                .contains("private_source")
        );
    }

    #[test]
    fn resolution_only_capsules_replay_opaque_files_and_require_search_observations() {
        let root = tempfile::tempdir().unwrap();
        put(root.path(), "src/app.cjs", "require.resolve('addon');");
        put(
            root.path(),
            "node_modules/addon/package.json",
            r#"{"exports":"./addon.node"}"#,
        );
        let opaque = b"\x7fELF\xff\0private_native_bytes";
        put(root.path(), "node_modules/addon/addon.node", opaque);
        let graph = capture(root.path(), "src/app.cjs", GraphOptions::default()).unwrap();
        assert!(graph.report().fully_resolved);
        assert_eq!(graph.report().modules.len(), 1);
        assert_eq!(graph.report().resolution_targets.len(), 1);
        let target = &graph.report().resolution_targets[0].id;
        assert!(graph.source_bytes(target).is_none());
        assert!(
            graph
                .report()
                .probes
                .iter()
                .any(|probe| probe.path == "src/node_modules"
                    && probe.kind == super::super::super::ProbeKind::Missing)
        );
        let encoded = encode(&graph).unwrap();
        put(
            root.path(),
            "node_modules/addon/addon.node",
            b"replaced binary",
        );
        put(
            root.path(),
            "src/node_modules/addon/index.js",
            "throw Error('new nearer package');",
        );
        let replayed = replay(encoded.bytes(), encoded.digest()).unwrap();
        assert_eq!(replayed.report(), graph.report());
        assert!(replayed.source_bytes(target).is_none());
        assert!(
            matches!(replayed.inputs.get(&target.path).unwrap().as_ref(),
            Entry::File { bytes, .. } if bytes == opaque)
        );
        assert_eq!(encode(&replayed).unwrap().bytes(), encoded.bytes());
        assert!(
            !serde_json::to_string(replayed.report())
                .unwrap()
                .contains("private_native_bytes")
        );

        // A successful filename lookup still needs the captured negative
        // search path. Omission cannot mean absence or trigger live fallback.
        let omitted = modify(&encoded, |header| {
            header
                .inputs
                .retain(|input| input.path != "src/node_modules");
        });
        assert_eq!(failure(&omitted), "ERR_MODULE_CAPSULE_INPUT_MISSING");
        let changed_digest = modify(&encoded, |header| {
            let input = header
                .inputs
                .iter_mut()
                .find(|input| input.path == target.path)
                .unwrap();
            let Content::File { sha256, .. } = &mut input.content else {
                panic!("ordinary resolution target");
            };
            *sha256 = "0".repeat(64);
        });
        assert_eq!(failure(&changed_digest), "ERR_MODULE_CAPSULE_INVALID");
    }

    #[test]
    fn typescript_erased_dependencies_and_url_instances_replay_without_extra_reads() {
        let root = tempfile::tempdir().unwrap();
        put(
            root.path(),
            "app.ts",
            "import type X from '../unread'; import './dep.mts?a'; import './dep.mts?b';",
        );
        put(root.path(), "dep.mts", "export const x: number = 1;");
        let graph = capture(root.path(), "app.ts", GraphOptions::default()).unwrap();
        let capsule = encode(&graph).unwrap();
        let replayed = replay(capsule.bytes(), capsule.digest()).unwrap();
        assert_eq!(graph.report(), replayed.report());
        assert_eq!(replayed.report().modules.len(), 3);
        assert!(replayed.report().fully_resolved);
        assert!(!replayed.report().type_resolution_performed);
    }

    #[test]
    fn independent_pin_is_required_before_header_parsing() {
        let malformed = b"not a capsule";
        assert_eq!(
            replay(malformed, "sha256:bad").err().unwrap().code,
            "ERR_MODULE_CAPSULE_PIN_INVALID"
        );
        assert_eq!(
            replay(malformed, &format!("sha256:{}", "0".repeat(64)))
                .err()
                .unwrap()
                .code,
            "ERR_MODULE_CAPSULE_PIN_MISMATCH"
        );
        assert_eq!(failure(malformed), "ERR_MODULE_CAPSULE_INVALID");
    }

    #[test]
    fn payload_corruption_is_rejected_even_with_a_new_outer_pin() {
        let root = tempfile::tempdir().unwrap();
        let capsule = encode(&simple(root.path())).unwrap();
        let mut corrupted = capsule.bytes().to_vec();
        *corrupted.last_mut().unwrap() ^= 1;
        assert_eq!(
            replay(&corrupted, capsule.digest()).err().unwrap().code,
            "ERR_MODULE_CAPSULE_PIN_MISMATCH"
        );
        assert_eq!(failure(&corrupted), "ERR_MODULE_CAPSULE_INVALID");
    }

    #[test]
    fn supplied_report_hash_is_recomputed_not_trusted() {
        let root = tempfile::tempdir().unwrap();
        let capsule = encode(&simple(root.path())).unwrap();
        let corrupted = modify(&capsule, |h| {
            h.graph_hash = format!("sha256:{}", "0".repeat(64))
        });
        assert_eq!(failure(&corrupted), "ERR_MODULE_CAPSULE_REPLAY_MISMATCH");
    }

    #[test]
    fn omitted_negative_probe_is_not_invented_or_recovered_from_host() {
        let root = tempfile::tempdir().unwrap();
        put(root.path(), "app.js", "export const value=1;");
        let graph = capture(root.path(), "app.js", GraphOptions::default()).unwrap();
        let capsule = encode(&graph).unwrap();
        assert!(
            graph
                .report()
                .probes
                .iter()
                .any(|p| p.path == "package.json")
        );
        let omitted = modify(&capsule, |h| h.inputs.retain(|i| i.path != "package.json"));
        assert_eq!(failure(&omitted), "ERR_MODULE_CAPSULE_INPUT_MISSING");
    }

    #[test]
    fn unused_extra_observations_are_not_accepted_as_replayed_evidence() {
        let root = tempfile::tempdir().unwrap();
        let capsule = encode(&simple(root.path())).unwrap();
        let extra = modify(&capsule, |h| {
            h.inputs.push(Input {
                path: "zz-unused".into(),
                content: Content::Missing,
            })
        });
        assert_eq!(failure(&extra), "ERR_MODULE_CAPSULE_REPLAY_MISMATCH");
    }

    #[test]
    fn invalid_roots_duplicate_paths_and_nonphysical_parentage_fail_closed() {
        let root = tempfile::tempdir().unwrap();
        let capsule = encode(&simple(root.path())).unwrap();
        assert_eq!(
            failure(&modify(&capsule, |h| h.inputs[0].content = Content::Missing)),
            "ERR_MODULE_CAPSULE_INVALID"
        );
        assert_eq!(
            failure(&modify(&capsule, |h| h.inputs[1].path = String::new())),
            "ERR_MODULE_CAPSULE_INVALID"
        );
        assert_eq!(
            failure(&modify(&capsule, |h| h.inputs.push(Input {
                path: "zz/sub".into(),
                content: Content::Missing
            }))),
            "ERR_MODULE_CAPSULE_INVALID"
        );
        assert!(
            failure(&modify(&capsule, |h| h.entrypoint = "../outside".into())).starts_with("ERR_")
        );
    }

    #[test]
    fn operator_state_capsule_inputs_and_links_are_rejected_before_replay() {
        let root = tempfile::tempdir().unwrap();
        let capsule = encode(&simple(root.path())).unwrap();
        let (header, payload) = parse_frame(capsule.bytes()).unwrap();
        assert!(recorded_resolver(&header, payload).is_ok());

        // An independently pinned old or malicious capsule does not grant
        // access to operator state. Refuse its recorded namespace before any
        // graph replay or source preparation, even for unused observations.
        for entrypoint in [
            ".franken-node/key.json",
            "nested/.franken-node/key.json",
            ".FRANKEN-NODE/key.json",
            "franken_node.toml",
            "nested/FRANKEN_NODE.TOML",
        ] {
            let forbidden = modify(&capsule, |header| {
                header.entrypoint = entrypoint.to_owned();
            });
            assert_eq!(failure(&forbidden), "ERR_INVALID_MODULE_SPECIFIER");
        }
        let forbidden_input = modify(&capsule, |header| {
            header.inputs.push(Input {
                path: ".franken-node".into(),
                content: Content::Directory,
            });
            header
                .inputs
                .sort_by(|left, right| left.path.cmp(&right.path));
        });
        let (header, payload) = parse_frame(&forbidden_input).unwrap();
        assert_eq!(
            recorded_resolver(&header, payload)
                .err()
                .expect("protected input")
                .code,
            "ERR_INVALID_MODULE_SPECIFIER"
        );
        assert_eq!(failure(&forbidden_input), "ERR_INVALID_MODULE_SPECIFIER");

        let forbidden_link = modify(&capsule, |header| {
            let target = ".franken-node/remotecap/trust-scan-token.json";
            header.options.symlink_policy = super::super::SymlinkPolicy::Contained;
            header.inputs.push(Input {
                path: "zz-alias.json".into(),
                content: Content::Symlink {
                    target: target.into(),
                    sha256: hex::encode(Sha256::digest(target.as_bytes())),
                },
            });
        });
        assert_eq!(failure(&forbidden_link), "ERR_INVALID_MODULE_SYMLINK");
    }

    #[test]
    fn truncation_trailing_bytes_and_unknown_schema_fail_closed() {
        let root = tempfile::tempdir().unwrap();
        let capsule = encode(&simple(root.path())).unwrap();
        assert_eq!(
            failure(&capsule.bytes()[..10]),
            "ERR_MODULE_CAPSULE_INVALID"
        );
        assert_eq!(
            failure(&capsule.bytes()[..capsule.bytes().len() - 1]),
            "ERR_MODULE_CAPSULE_INVALID"
        );
        let mut trailing = capsule.bytes().to_vec();
        trailing.push(0);
        assert_eq!(failure(&trailing), "ERR_MODULE_CAPSULE_INVALID");
        assert_eq!(
            failure(&modify(&capsule, |h| h.schema_version = "future".into())),
            "ERR_MODULE_CAPSULE_INVALID"
        );
    }

    #[test]
    fn declared_file_and_header_bounds_are_enforced_before_allocation() {
        let root = tempfile::tempdir().unwrap();
        let capsule = encode(&simple(root.path())).unwrap();
        let huge = modify(&capsule, |h| {
            let input = h
                .inputs
                .iter_mut()
                .find(|i| matches!(i.content, Content::File { .. }))
                .unwrap();
            if let Content::File { bytes, .. } = &mut input.content {
                *bytes = usize::MAX;
            }
        });
        assert_eq!(failure(&huge), "ERR_MODULE_CAPSULE_LIMIT");
        let mut header = MAGIC.to_vec();
        header.extend_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(failure(&header), "ERR_MODULE_CAPSULE_LIMIT");
    }

    #[test]
    fn capsule_rejects_changed_or_noncanonical_additional_conditions() {
        let root = tempfile::tempdir().unwrap();
        put(root.path(), "app.mjs", "export const value = 1;");
        let graph = capture(
            root.path(),
            "app.mjs",
            GraphOptions {
                additional_conditions: vec!["development".into(), "react-server".into()],
                ..GraphOptions::default()
            },
        )
        .unwrap();
        let encoded = encode(&graph).unwrap();
        for conditions in [
            vec!["react-server".into(), "development".into()],
            vec!["development".into(), "development".into()],
            vec![String::new()],
            vec!["other".into()],
            Vec::new(),
        ] {
            let changed = modify(&encoded, |header| {
                header.options.additional_conditions = conditions
            });
            assert!(!failure(&changed).is_empty());
        }
    }

    #[test]
    fn capsule_identity_is_relocation_stable_but_binds_conditions_and_transitive_bytes() {
        let a = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();
        let first = encode(&simple(a.path())).unwrap();
        let second = encode(&simple(b.path())).unwrap();
        assert_eq!(first.bytes(), second.bytes());
        let changed_options = capture(
            a.path(),
            "app.mjs",
            GraphOptions {
                conditions: Some(vec!["custom".into()]),
                ..GraphOptions::default()
            },
        )
        .unwrap();
        assert_ne!(first.digest(), encode(&changed_options).unwrap().digest());
        put(a.path(), "dep.mjs", "export const n=2;");
        let changed_source = capture(a.path(), "app.mjs", GraphOptions::default()).unwrap();
        assert_ne!(first.digest(), encode(&changed_source).unwrap().digest());
    }
}
