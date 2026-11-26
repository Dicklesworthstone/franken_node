//! Independent byte-integrity inspection of the public FNSGCAP1 wire format.
//!
//! The capsule digest is authenticated by the enclosing incident bundle or the
//! publisher's signed registration manifest. This
//! reader checks the capsule and all its recorded bytes without opening paths,
//! extracting files, importing product code or evaluating JavaScript. The graph
//! hash is bound to the signed capture. Capsule-only inspection does not
//! recompute it. An explicit source-graph report witness additionally permits
//! independent commitment recomputation and source-observation binding, without
//! claiming parser/resolver semantic reconstruction or native execution.
//! Metadata-only file
//! observations bind recorded existence, without admitting file contents or
//! supplying source bytes to execution.

use base64::Engine as _;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

use super::{MAX_PAYLOAD_BYTES, Result, array, ct_str_eq, exact, invalid, text};
use crate::native_session::absolute_path_parts;

const FIELD: &str = ".payload.module_sources";
const MAGIC: &[u8; 8] = b"FNSGCAP1";
const PREFIX_BYTES: usize = 12;
const SCHEMA: &str = "franken-node/module-source-capsule/v1";
const HASH_DOMAIN: &[u8] = b"franken-node/module-source-capsule/v1\0";
const MAX_HEADER_BYTES: usize = 8 * 1024 * 1024;
const MAX_INPUTS: usize = 1024;
const MAX_PATH_BYTES: usize = 4096;
const MAX_PATH_DEPTH: usize = 64;
const MAX_LINK_HOPS: usize = 40;
const MAX_FILE_BYTES: usize = 16 * 1024 * 1024;
const MAX_MANIFEST_BYTES: usize = 512 * 1024;
const MAX_CAPTURE_BYTES: usize = 32 * 1024 * 1024;

// Field order is part of this version's canonical JSON header. Do not derive
// Debug: source paths, link text and source bytes must not enter diagnostics.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    schema_version: String,
    graph_hash: String,
    entrypoint: String,
    options: Options,
    inputs: Vec<Input>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Options {
    symlink_policy: SymlinkPolicy,
    conditions: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    additional_conditions: Vec<String>,
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum SymlinkPolicy {
    Reject,
    Contained,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    path: String,
    content: Content,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Content {
    Missing,
    Directory,
    /// Regular-file existence only; no content length, digest, or payload.
    FileMetadata,
    File {
        bytes: usize,
        sha256: String,
    },
    Symlink {
        target: String,
        sha256: String,
    },
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn valid_hash(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(valid_digest)
}

pub(crate) fn capsule_digest(bytes: &[u8]) -> String {
    let mut hash = Sha256::new();
    hash.update(HASH_DOMAIN);
    hash.update((bytes.len() as u64).to_le_bytes());
    hash.update(bytes);
    format!("sha256:{}", hex::encode(hash.finalize()))
}

fn path_shape(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= MAX_PATH_BYTES
        && path.split('/').count() <= MAX_PATH_DEPTH
        && !path.contains(['\\', ':'])
        && !path.chars().any(char::is_control)
        && !path
            .split('/')
            .any(|part| matches!(part, ".git" | ".beads"))
}

fn valid_path(path: &str) -> bool {
    path_shape(path) && !path.split('/').any(|part| matches!(part, "" | "." | ".."))
}

fn valid_link_target(target: &str) -> bool {
    // Relative link text can contain `..`; interpreting it and proving the
    // resolved route stays in the project belongs to graph reconstruction.
    path_shape(target) && !target.starts_with('/')
}

fn canonical_conditions(values: &[String]) -> bool {
    values.len() <= 64
        && values.iter().all(|value| {
            !value.is_empty() && value.len() <= 128 && !value.chars().any(char::is_control)
        })
        && values.windows(2).all(|pair| pair[0] < pair[1])
}

/// Byte-integrity facts from a capsule whose enclosing statement was verified.
/// No source path, link target, condition name, or source bytes are returned.
/// The recorded graph commitment is authenticated, never recomputed here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SourceCapsuleSummary {
    pub schema_version: String,
    pub graph_input_hash: String,
    pub graph_hash_recomputed: bool,
    pub capsule_bytes: usize,
    pub payload_bytes: usize,
    pub input_count: usize,
    pub file_count: usize,
    pub metadata_file_count: usize,
    pub directory_count: usize,
    pub missing_count: usize,
    pub symlink_count: usize,
    pub symlink_policy: String,
    /// Explicit complete condition override; None means native defaults.
    pub condition_count: Option<usize>,
    pub additional_condition_count: usize,
}

/// Maximum JSON witness size, matching the producer's graph evidence budget.
pub const MAX_SOURCE_GRAPH_REPORT_BYTES: usize = 32 * 1024 * 1024;

/// An independently rehashed graph report bound to authenticated capsule bytes.
/// This checks the committed report and its recorded inputs, not whether the
/// producer's parser and resolver derived the correct dependency graph.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SourceGraphCommitment {
    pub schema_version: &'static str,
    pub graph_input_hash: String,
    pub graph_hash_recomputed: bool,
    pub graph_semantics_reconstructed: bool,
    pub capsule_digest: String,
    pub report_sha256: String,
    pub observation_count: usize,
    pub module_count: usize,
    pub resolution_target_count: usize,
    pub edge_count: usize,
    pub diagnostic_count: usize,
    /// The authenticated producer claim; it is not an independent conclusion.
    pub declared_fully_resolved: bool,
}

// Independent wire types. Their declaration order is the v3 hash preimage;
// importing the product's resolver or serialization would erase that boundary.
// No Debug implementations: reports can contain private paths and specifiers.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct GraphModuleId {
    path: String,
    url_suffix: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct GraphSite {
    start_byte: usize,
    end_byte: usize,
    line: usize,
    column: usize,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum GraphLanguage {
    Javascript,
    Typescript,
    Tsx,
    Declaration,
    Json,
    Unsupported,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct GraphModule {
    id: GraphModuleId,
    content_sha256: String,
    content_bytes: usize,
    format_hint: String,
    source_language: GraphLanguage,
    analyzed: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct GraphResolutionTarget {
    id: GraphModuleId,
    content_sha256: String,
    content_bytes: usize,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum GraphLoadKind {
    StaticImport,
    Reexport,
    Require,
    RequireResolve,
    ImportMetaResolve,
    DynamicImport,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum GraphEdgeState {
    Resolved,
    Unresolved,
    RuntimeRequired,
    NonLiteral,
    TypeOnly,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum GraphSearch {
    Paths { paths: Vec<String> },
    LookupPaths,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum GraphUrl {
    File { id: GraphModuleId },
    Absolute { url: String },
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct GraphError {
    code: String,
    detail: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum GraphMapKind {
    Exports,
    Imports,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum GraphTargetKind {
    PackageRelative,
    ExternalPackage,
}

#[derive(Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
enum GraphBranchStep {
    Condition(String),
    ArrayIndex(usize),
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct GraphSelection {
    target: String,
    target_kind: GraphTargetKind,
    matched_key: String,
    branch: Vec<GraphBranchStep>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct GraphMapping {
    manifest: String,
    input_hash: String,
    kind: GraphMapKind,
    request: String,
    selection: GraphSelection,
}

fn is_false(value: &bool) -> bool {
    !*value
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct GraphEdge {
    importer: GraphModuleId,
    site: GraphSite,
    kind: GraphLoadKind,
    deferred_or_conditional: bool,
    specifier: Option<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    dirname_request: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    normalized_dirname_request: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    commonjs_search: Option<GraphSearch>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    import_attributes: BTreeMap<String, String>,
    conditions: Vec<String>,
    state: GraphEdgeState,
    target: Option<GraphModuleId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    resolved_url: Option<GraphUrl>,
    error: Option<GraphError>,
    mappings: Vec<GraphMapping>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct GraphDiagnostic {
    module: GraphModuleId,
    site: Option<GraphSite>,
    code: String,
    message: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum GraphProbeKind {
    Missing,
    Directory,
    File,
    FileMetadata,
    Symlink,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct GraphProbe {
    path: String,
    kind: GraphProbeKind,
    bytes: Option<usize>,
    sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    link_target: Option<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct GraphReport {
    schema_version: String,
    scope: String,
    entrypoint: String,
    resolved_entrypoint: GraphModuleId,
    options: Options,
    modules: Vec<GraphModule>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    resolution_targets: Vec<GraphResolutionTarget>,
    edges: Vec<GraphEdge>,
    diagnostics: Vec<GraphDiagnostic>,
    probes: Vec<GraphProbe>,
    input_hash: String,
    fully_resolved: bool,
    runtime_completeness: bool,
    type_resolution_performed: bool,
    execution_performed: bool,
    release_certification: bool,
}

fn graph_id_valid(id: &GraphModuleId) -> bool {
    valid_path(&id.path)
        && id.url_suffix.len() <= MAX_PATH_BYTES
        && (id.url_suffix.is_empty() || id.url_suffix.starts_with(['?', '#']))
        && !id.url_suffix.chars().any(char::is_control)
}

fn graph_site_valid(site: &GraphSite, source_bytes: usize) -> bool {
    site.start_byte <= site.end_byte
        && site.end_byte <= source_bytes
        && site.line > 0
        && site.column > 0
}

fn normalized_graph_request_valid(specifier: &str) -> bool {
    matches!(specifier, "." | "./")
        || specifier
            .strip_prefix("./")
            .is_some_and(|path| valid_path(path.strip_suffix('/').unwrap_or(path)))
}

/// Rehash a separately supplied v2/v3 graph witness only after source authority
/// has been established by the caller. Object order/whitespace are transport
/// details; arrays, nulls, omitted optional fields and every schema field are
/// preserved and checked. No pathname from either input is opened.
pub(crate) fn inspect_graph_report(
    capsule_bytes: &[u8],
    report_bytes: &[u8],
) -> Result<SourceGraphCommitment> {
    if report_bytes.is_empty() || report_bytes.len() > MAX_SOURCE_GRAPH_REPORT_BYTES {
        return Err(invalid(FIELD, "source graph report exceeds its byte bound"));
    }
    let frame = verify_frame(capsule_bytes, None, None)?;
    let value = crate::incident_bundle::decode_evidence_json(report_bytes)
        .map_err(|_| invalid(FIELD, "source graph report is not unambiguous JSON"))?;
    let mut report: GraphReport = serde_json::from_value(value.clone())
        .map_err(|_| invalid(FIELD, "invalid source graph report schema"))?;
    if serde_json::to_value(&report)
        .map_err(|_| invalid(FIELD, "cannot encode source graph report"))?
        != value
    {
        return Err(invalid(
            FIELD,
            "source graph report has noncanonical fields",
        ));
    }
    let hash_domain: &[u8] = match report.schema_version.as_str() {
        "franken-node/module-source-graph/v2" => b"franken-node/module-source-graph/v2\0",
        "franken-node/module-source-graph/v3" => b"franken-node/module-source-graph/v3\0",
        _ => return Err(invalid(FIELD, "unsupported source graph report schema")),
    };
    if report.scope != "static-and-literal-module-requests"
        || report.entrypoint != frame.header.entrypoint
        || report.options != frame.header.options
        || report.input_hash != frame.header.graph_hash
        || report.runtime_completeness
        || report.type_resolution_performed
        || report.execution_performed
        || report.release_certification
        || report.modules.is_empty()
        || report.modules.len() > 256
        || report.resolution_targets.len() > 256
        || report.edges.len() > 4096
        || report.diagnostics.len() > 4096
        || report.probes.len() != frame.header.inputs.len()
    {
        return Err(invalid(
            FIELD,
            "source graph report disagrees with its capsule or scope",
        ));
    }

    let mut files = BTreeMap::new();
    let mut offset = 0;
    for (probe, input) in report.probes.iter().zip(&frame.header.inputs) {
        let path = if input.path.is_empty() {
            "."
        } else {
            &input.path
        };
        let matches = probe.path == path
            && match (&probe.kind, &input.content) {
                (GraphProbeKind::Missing, Content::Missing)
                | (GraphProbeKind::Directory, Content::Directory)
                | (GraphProbeKind::FileMetadata, Content::FileMetadata) => {
                    probe.bytes.is_none() && probe.sha256.is_none() && probe.link_target.is_none()
                }
                (GraphProbeKind::File, Content::File { bytes, sha256 }) => {
                    let end = offset + bytes;
                    files.insert(
                        input.path.as_str(),
                        (&frame.payload[offset..end], sha256.as_str()),
                    );
                    offset = end;
                    probe.bytes == Some(*bytes)
                        && probe.sha256.as_deref() == Some(sha256.as_str())
                        && probe.link_target.is_none()
                }
                (GraphProbeKind::Symlink, Content::Symlink { target, sha256 }) => {
                    probe.bytes == Some(target.len())
                        && probe.sha256.as_deref() == Some(sha256.as_str())
                        && probe.link_target.as_deref() == Some(target.as_str())
                }
                _ => false,
            };
        if !matches {
            return Err(invalid(
                FIELD,
                "source graph probes differ from captured observations",
            ));
        }
    }
    let source_matches = |id: &GraphModuleId, bytes: usize, digest: &str| {
        graph_id_valid(id)
            && files
                .get(id.path.as_str())
                .is_some_and(|(source, sha256)| source.len() == bytes && *sha256 == digest)
    };
    if report
        .modules
        .windows(2)
        .any(|pair| pair[0].id >= pair[1].id)
        || report
            .resolution_targets
            .windows(2)
            .any(|pair| pair[0].id >= pair[1].id)
        || report
            .modules
            .iter()
            .any(|module| !source_matches(&module.id, module.content_bytes, &module.content_sha256))
        || report
            .resolution_targets
            .iter()
            .any(|target| !source_matches(&target.id, target.content_bytes, &target.content_sha256))
    {
        return Err(invalid(
            FIELD,
            "source graph modules differ from captured source bytes",
        ));
    }
    let modules: BTreeMap<_, _> = report
        .modules
        .iter()
        .map(|module| (&module.id, module.content_bytes))
        .collect();
    let (entry, _) = frame.entry_file()?;
    if report.resolved_entrypoint.path != entry
        || !report.resolved_entrypoint.url_suffix.is_empty()
        || !modules.contains_key(&report.resolved_entrypoint)
    {
        return Err(invalid(
            FIELD,
            "source graph resolved entry differs from the capsule",
        ));
    }
    let mut manifest_hashes = BTreeMap::new();
    for edge in &report.edges {
        // This marker distinguishes the exact normalized absolute spelling
        // consumed by a captured CommonJS loader from raw __dirname text.
        // Check the wire contract without claiming to reevaluate path calls or
        // resolve an incomplete graph against the auditor's filesystem.
        if edge.normalized_dirname_request
            && (report.schema_version != "franken-node/module-source-graph/v3"
                || edge.dirname_request
                || !matches!(
                    edge.kind,
                    GraphLoadKind::Require | GraphLoadKind::RequireResolve
                )
                || matches!(edge.state, GraphEdgeState::TypeOnly)
                || edge.commonjs_search.is_some()
                || !edge.import_attributes.is_empty()
                || !edge
                    .specifier
                    .as_deref()
                    .is_some_and(normalized_graph_request_valid))
        {
            return Err(invalid(
                FIELD,
                "source graph normalized dirname request is inconsistent",
            ));
        }
        let source_bytes = modules
            .get(&edge.importer)
            .ok_or_else(|| invalid(FIELD, "source graph edge has an unrecorded importer"))?;
        if !graph_site_valid(&edge.site, *source_bytes)
            || edge.target.as_ref().is_some_and(|target| {
                !modules.contains_key(target)
                    && !report
                        .resolution_targets
                        .iter()
                        .any(|entry| &entry.id == target)
            })
        {
            return Err(invalid(
                FIELD,
                "source graph edge refers outside its source inventory",
            ));
        }
        for mapping in &edge.mappings {
            if mapping.manifest.rsplit('/').next() != Some("package.json") {
                return Err(invalid(
                    FIELD,
                    "source graph mapping has no captured manifest",
                ));
            }
            // Package-map reports retain logical lookup routes. A workspace
            // symlink can make that route differ from the physical observation.
            let expected = match manifest_hashes.entry(mapping.manifest.as_str()) {
                std::collections::btree_map::Entry::Occupied(entry) => entry.into_mut(),
                std::collections::btree_map::Entry::Vacant(entry) => {
                    let (_, source) = frame.file_at(&mapping.manifest)?;
                    let mut hash = Sha256::new();
                    hash.update(b"franken-node/package-map-input/v1\0");
                    hash.update((source.len() as u64).to_le_bytes());
                    hash.update(source);
                    entry.insert(format!("sha256:{}", hex::encode(hash.finalize())))
                }
            };
            if mapping.input_hash.as_str() != expected.as_str() {
                return Err(invalid(
                    FIELD,
                    "source graph mapping differs from captured manifest bytes",
                ));
            }
        }
    }
    for diagnostic in &report.diagnostics {
        let source_bytes = modules
            .get(&diagnostic.module)
            .ok_or_else(|| invalid(FIELD, "source graph diagnostic has an unrecorded module"))?;
        if diagnostic
            .site
            .as_ref()
            .is_some_and(|site| !graph_site_valid(site, *source_bytes))
        {
            return Err(invalid(
                FIELD,
                "source graph diagnostic lies outside captured source",
            ));
        }
    }
    if report.edges.windows(2).any(|pair| {
        (&pair[0].importer, pair[0].site.start_byte) > (&pair[1].importer, pair[1].site.start_byte)
    }) || report.diagnostics.windows(2).any(|pair| {
        (
            &pair[0].module,
            pair[0].site.as_ref().map(|site| site.start_byte),
            &pair[0].code,
        ) > (
            &pair[1].module,
            pair[1].site.as_ref().map(|site| site.start_byte),
            &pair[1].code,
        )
    }) || report.fully_resolved
        != (report.diagnostics.is_empty()
            && report.edges.iter().all(|edge| {
                matches!(
                    edge.state,
                    GraphEdgeState::Resolved | GraphEdgeState::TypeOnly
                )
            }))
    {
        return Err(invalid(
            FIELD,
            "source graph report ordering or resolution claim is inconsistent",
        ));
    }
    let expected = std::mem::take(&mut report.input_hash);
    let canonical = serde_json::to_vec(&report)
        .map_err(|_| invalid(FIELD, "cannot encode source graph hash preimage"))?;
    if canonical.len() > MAX_SOURCE_GRAPH_REPORT_BYTES {
        return Err(invalid(
            FIELD,
            "source graph hash preimage exceeds its byte bound",
        ));
    }
    let mut hash = Sha256::new();
    hash.update(hash_domain);
    hash.update(&canonical);
    if !ct_str_eq(
        &expected,
        &format!("sha256:{}", hex::encode(hash.finalize())),
    ) {
        return Err(invalid(
            FIELD,
            "source graph report does not match its authenticated commitment",
        ));
    }
    Ok(SourceGraphCommitment {
        schema_version: "franken-verifier/source-graph-commitment/v1",
        graph_input_hash: expected,
        graph_hash_recomputed: true,
        graph_semantics_reconstructed: false,
        capsule_digest: capsule_digest(capsule_bytes),
        report_sha256: hex::encode(Sha256::digest(report_bytes)),
        observation_count: report.probes.len(),
        module_count: report.modules.len(),
        resolution_target_count: report.resolution_targets.len(),
        edge_count: report.edges.len(),
        diagnostic_count: report.diagnostics.len(),
        declared_fully_resolved: report.fully_resolved,
    })
}

/// The caller authenticates and bounds these bytes before inspection. Incident
/// verification additionally supplies its separately captured graph commitment.
pub(crate) fn inspect_authenticated(bytes: &[u8]) -> Result<SourceCapsuleSummary> {
    verify_frame(bytes, None, None).map(|frame| frame.summary)
}

/// Inspect retained pre-entry sources against the independently authenticated
/// admission. This checks byte identity and the requested entrypoint, without
/// claiming graph reconstruction or that the worker reached guest execution.
pub(crate) fn inspect_admitted(
    bytes: &[u8],
    graph_hash: &str,
    entrypoint: &str,
) -> Result<SourceCapsuleSummary> {
    verify_frame(bytes, Some(graph_hash), Some(entrypoint)).map(|frame| frame.summary)
}

// Byte-only inspection does not require a resolvable entry: an incomplete or
// pre-entry graph remains useful authenticated forensic data.
struct VerifiedFrame<'a> {
    header: Header,
    payload: &'a [u8],
    summary: SourceCapsuleSummary,
}

impl VerifiedFrame<'_> {
    /// Resolve only recorded physical observations, never the auditor's host.
    /// Expand a link before interpreting '..' in its target or remaining path.
    fn entry_file(&self) -> Result<(&str, &[u8])> {
        self.file_at(&self.header.entrypoint)
    }

    fn file_at(&self, path: &str) -> Result<(&str, &[u8])> {
        if !valid_path(path) {
            return Err(invalid(FIELD, "source capsule file path is not canonical"));
        }
        let mut entries = BTreeMap::new();
        let mut offset = 0_usize;
        for input in &self.header.inputs {
            let source = match &input.content {
                Content::File { bytes, .. } => {
                    let end = offset.checked_add(*bytes).ok_or_else(|| {
                        invalid(FIELD, "source capsule entry byte length overflow")
                    })?;
                    let source = self.payload.get(offset..end).ok_or_else(|| {
                        invalid(FIELD, "source capsule entry bytes are incomplete")
                    })?;
                    offset = end;
                    Some(source)
                }
                _ => None,
            };
            entries.insert(input.path.as_str(), (&input.content, source));
        }

        let mut pending: VecDeque<_> = path.split('/').collect();
        let mut resolved = Vec::new();
        let mut links = 0_usize;
        while let Some(component) = pending.pop_front() {
            match component {
                "" | "." => continue,
                ".." => {
                    if resolved.pop().is_none() {
                        return Err(invalid(FIELD, "source capsule entry escapes its root"));
                    }
                    continue;
                }
                _ => {}
            }
            let mut path = resolved.join("/");
            if !path.is_empty() {
                path.push('/');
            }
            path.push_str(component);
            let (recorded_path, (content, source)) = entries
                .get_key_value(path.as_str())
                .ok_or_else(|| invalid(FIELD, "source capsule entry observation is missing"))?;
            match content {
                Content::Symlink { target, .. } => {
                    links += 1;
                    if links > MAX_LINK_HOPS {
                        return Err(invalid(
                            FIELD,
                            "source capsule entry exceeds its link bound",
                        ));
                    }
                    let components = target.split('/');
                    if resolved.len() + components.clone().count() + pending.len() > MAX_PATH_DEPTH
                        || path.len()
                            + target.len()
                            + pending.iter().map(|part| part.len() + 1).sum::<usize>()
                            > MAX_PATH_BYTES
                    {
                        return Err(invalid(
                            FIELD,
                            "source capsule entry exceeds its path bound",
                        ));
                    }
                    let mut target: VecDeque<_> = components.collect();
                    target.append(&mut pending);
                    pending = target;
                }
                Content::Directory => resolved.push(component),
                Content::File { .. } if pending.is_empty() => {
                    return source
                        .map(|source| (*recorded_path, source))
                        .ok_or_else(|| invalid(FIELD, "source capsule entry bytes are missing"));
                }
                _ => {
                    return Err(invalid(
                        FIELD,
                        "source capsule entry is not a captured file",
                    ));
                }
            }
        }
        Err(invalid(
            FIELD,
            "source capsule entry is not a captured file",
        ))
    }
}

fn verify_frame<'a>(
    bytes: &'a [u8],
    graph_hash: Option<&str>,
    entrypoint: Option<&str>,
) -> Result<VerifiedFrame<'a>> {
    if bytes.len() < PREFIX_BYTES || &bytes[..8] != MAGIC {
        return Err(invalid(FIELD, "invalid source capsule framing"));
    }
    let header_length = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]) as usize;
    if header_length > MAX_HEADER_BYTES {
        return Err(invalid(
            FIELD,
            "source capsule header exceeds its byte bound",
        ));
    }
    let header_end = PREFIX_BYTES
        .checked_add(header_length)
        .ok_or_else(|| invalid(FIELD, "source capsule header length overflow"))?;
    let metadata = bytes
        .get(PREFIX_BYTES..header_end)
        .ok_or_else(|| invalid(FIELD, "truncated source capsule header"))?;
    let header: Header = serde_json::from_slice(metadata)
        .map_err(|_| invalid(FIELD, "invalid source capsule header JSON"))?;
    let canonical = serde_json::to_vec(&header)
        .map_err(|_| invalid(FIELD, "cannot encode source capsule header"))?;
    if canonical != metadata {
        return Err(invalid(FIELD, "noncanonical source capsule header"));
    }
    if header.schema_version != SCHEMA || !valid_hash(&header.graph_hash) {
        return Err(invalid(
            FIELD,
            "unsupported source capsule schema or graph hash",
        ));
    }
    if graph_hash.is_some_and(|expected| !ct_str_eq(&header.graph_hash, expected)) {
        return Err(invalid(
            FIELD,
            "source capsule graph hash disagrees with captured graph identity",
        ));
    }
    if !valid_path(&header.entrypoint) {
        return Err(invalid(
            FIELD,
            "source capsule entrypoint is not canonical and project-relative",
        ));
    }
    if entrypoint.is_some_and(|expected| header.entrypoint != expected) {
        return Err(invalid(
            FIELD,
            "source capsule entrypoint disagrees with the signed admission",
        ));
    }
    let options = &header.options;
    if options
        .conditions
        .as_ref()
        .is_some_and(|values| !canonical_conditions(values))
        || !canonical_conditions(&options.additional_conditions)
        || options.additional_conditions.len() > 62
        || options.conditions.as_ref().map_or(2, Vec::len) + options.additional_conditions.len()
            > 64
    {
        return Err(invalid(
            FIELD,
            "source capsule conditions are not canonical or exceed their bound",
        ));
    }
    let payload = &bytes[header_end..];
    if header.inputs.is_empty()
        || header.inputs.len() > MAX_INPUTS
        || payload.len() > MAX_CAPTURE_BYTES
    {
        return Err(invalid(
            FIELD,
            "source capsule observations or payload exceed their bounds",
        ));
    }
    let mut directories = BTreeSet::new();
    let mut previous: Option<&str> = None;
    let mut offset = 0_usize;
    let mut captured_bytes = 0_usize;
    for input in &header.inputs {
        if previous.is_some_and(|path| path >= input.path.as_str()) {
            return Err(invalid(
                FIELD,
                "source capsule observations must be unique and sorted",
            ));
        }
        previous = Some(&input.path);
        if input.path.is_empty() {
            if !matches!(input.content, Content::Directory) {
                return Err(invalid(FIELD, "source capsule root must be a directory"));
            }
        } else {
            let parent = input.path.rsplit_once('/').map_or("", |(parent, _)| parent);
            if !valid_path(&input.path) || !directories.contains(parent) {
                return Err(invalid(
                    FIELD,
                    "source capsule observation has an invalid path or missing physical parent",
                ));
            }
        }
        match &input.content {
            Content::Missing | Content::FileMetadata => {}
            Content::Directory => {
                directories.insert(input.path.as_str());
            }
            Content::File { bytes, sha256 } => {
                let limit = if input.path.rsplit('/').next() == Some("package.json") {
                    MAX_MANIFEST_BYTES
                } else {
                    MAX_FILE_BYTES
                };
                if *bytes > limit {
                    return Err(invalid(FIELD, "source capsule file exceeds its byte bound"));
                }
                let end = offset
                    .checked_add(*bytes)
                    .ok_or_else(|| invalid(FIELD, "source capsule file length overflow"))?;
                let source = payload
                    .get(offset..end)
                    .ok_or_else(|| invalid(FIELD, "truncated source capsule file"))?;
                if !valid_digest(sha256) || !ct_str_eq(&hex::encode(Sha256::digest(source)), sha256)
                {
                    return Err(invalid(FIELD, "source capsule file digest mismatch"));
                }
                offset = end;
                captured_bytes = captured_bytes.checked_add(*bytes).ok_or_else(|| {
                    invalid(FIELD, "source capsule captured byte length overflow")
                })?;
            }
            Content::Symlink { target, sha256 } => {
                if options.symlink_policy != SymlinkPolicy::Contained || !valid_link_target(target)
                {
                    return Err(invalid(
                        FIELD,
                        "source capsule link violates its captured policy or path bounds",
                    ));
                }
                if !valid_digest(sha256)
                    || !ct_str_eq(&hex::encode(Sha256::digest(target.as_bytes())), sha256)
                {
                    return Err(invalid(FIELD, "source capsule link digest mismatch"));
                }
                captured_bytes = captured_bytes.checked_add(target.len()).ok_or_else(|| {
                    invalid(FIELD, "source capsule captured byte length overflow")
                })?;
            }
        }
        if captured_bytes > MAX_CAPTURE_BYTES {
            return Err(invalid(
                FIELD,
                "source capsule captured bytes exceed their bound",
            ));
        }
    }
    if !directories.contains("") || offset != payload.len() {
        return Err(invalid(
            FIELD,
            "source capsule is missing its root or contains unclaimed payload bytes",
        ));
    }
    let mut counts = [0_usize; 5];
    for input in &header.inputs {
        let kind = match &input.content {
            Content::File { .. } => 0,
            Content::FileMetadata => 1,
            Content::Directory => 2,
            Content::Missing => 3,
            Content::Symlink { .. } => 4,
        };
        counts[kind] += 1;
    }
    let summary = SourceCapsuleSummary {
        schema_version: header.schema_version.clone(),
        graph_input_hash: header.graph_hash.clone(),
        graph_hash_recomputed: false,
        capsule_bytes: bytes.len(),
        payload_bytes: payload.len(),
        input_count: header.inputs.len(),
        file_count: counts[0],
        metadata_file_count: counts[1],
        directory_count: counts[2],
        missing_count: counts[3],
        symlink_count: counts[4],
        symlink_policy: match options.symlink_policy {
            SymlinkPolicy::Reject => "reject",
            SymlinkPolicy::Contained => "contained",
        }
        .into(),
        condition_count: options.conditions.as_ref().map(Vec::len),
        additional_condition_count: options.additional_conditions.len(),
    };
    Ok(VerifiedFrame {
        header,
        payload,
        summary,
    })
}

pub(super) fn decode_sources(value: &Value) -> Result<(Vec<u8>, &str)> {
    let sources = exact(
        value,
        FIELD,
        &["capsule_base64", "capsule_digest", "graph_input_hash"],
        &[],
    )?;
    let encoded = text(&sources["capsule_base64"], FIELD)?;
    if encoded.is_empty() || encoded.len() > MAX_PAYLOAD_BYTES {
        return Err(invalid(
            FIELD,
            "source capsule encoding exceeds the native capture byte bound",
        ));
    }
    let pin = text(&sources["capsule_digest"], FIELD)?;
    let graph_hash = text(&sources["graph_input_hash"], FIELD)?;
    if !valid_hash(pin) || !valid_hash(graph_hash) {
        return Err(invalid(
            FIELD,
            "source capsule identities must be canonical SHA-256 hashes",
        ));
    }
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|_| invalid(FIELD, "invalid source capsule base64 encoding"))?;
    if bytes.len() > MAX_PAYLOAD_BYTES / 4 * 3 {
        return Err(invalid(
            FIELD,
            "source capsule exceeds the native capture byte bound",
        ));
    }
    if base64::engine::general_purpose::STANDARD.encode(&bytes) != encoded {
        return Err(invalid(
            FIELD,
            "noncanonical source capsule base64 encoding",
        ));
    }
    if !ct_str_eq(&capsule_digest(&bytes), pin) {
        return Err(invalid(
            FIELD,
            "source capsule digest does not match captured bytes",
        ));
    }
    Ok((bytes, graph_hash))
}

// FrankenEngine keeps admitted JavaScript unchanged except for a leading
// hashbang (possibly preceded by a BOM), which becomes byte-for-byte spaces up
// to the first ECMAScript line terminator. Compare that result without copying
// or evaluating the source. TypeScript preparation remains engine-owned.
fn javascript_source_matches(source: &str, prepared: &str) -> bool {
    if !source
        .strip_prefix('\u{feff}')
        .unwrap_or(source)
        .starts_with("#!")
    {
        return source == prepared;
    }
    let line_end = source
        .find(['\n', '\r', '\u{2028}', '\u{2029}'])
        .unwrap_or(source.len());
    prepared.len() == source.len()
        && prepared.as_bytes()[..line_end]
            .iter()
            .all(|byte| *byte == b' ')
        && prepared.as_bytes()[line_end..] == source.as_bytes()[line_end..]
}

/// Check native entry identity, package conditions and retained UTF-8 source.
/// Admitted JavaScript must match its prepared entry bytes. TypeScript source
/// preparation and graph reconstruction still require native replay.
pub(super) fn verify_capture_binding(
    value: &Value,
    package: &Value,
    orchestrator: &Value,
) -> Result<()> {
    let (bytes, graph_hash) = decode_sources(value)?;
    let frame = verify_frame(&bytes, Some(graph_hash), None)?;
    let root = absolute_path_parts(text(&package["module_root"], FIELD)?)
        .ok_or_else(|| invalid(FIELD, "frozen capture requires an absolute module origin"))?;
    let source_file = absolute_path_parts(text(&package["source_file"], FIELD)?)
        .ok_or_else(|| invalid(FIELD, "frozen capture requires an absolute entry identity"))?;
    if !source_file.starts_with(&root)
        || source_file.len() <= root.len()
        || source_file[root.len()..].join("/") != frame.header.entrypoint
    {
        return Err(invalid(
            FIELD,
            "source capsule entry differs from the captured package",
        ));
    }

    let mut conditions = BTreeSet::new();
    if let Some(value) = orchestrator.get("module_conditions") {
        let values = array(value, FIELD)?;
        if values.len() > 62 {
            return Err(invalid(
                FIELD,
                "captured package conditions exceed their bound",
            ));
        }
        for value in values {
            let condition = text(value, FIELD)?;
            if condition.is_empty()
                || condition.len() > 128
                || condition.chars().any(char::is_control)
            {
                return Err(invalid(FIELD, "captured package conditions are invalid"));
            }
            conditions.insert(condition);
        }
    }
    if frame.header.options.conditions.is_some()
        || !conditions.iter().copied().eq(frame
            .header
            .options
            .additional_conditions
            .iter()
            .map(String::as_str))
    {
        return Err(invalid(
            FIELD,
            "source capsule conditions differ from captured settings",
        ));
    }

    let (physical_path, source) = frame.entry_file()?;
    let source = std::str::from_utf8(source)
        .map_err(|_| invalid(FIELD, "source capsule entry is not valid UTF-8"))?;
    let package_source = text(&package["source"], FIELD)?;
    let declaration = [".d.ts", ".d.mts", ".d.cts"]
        .iter()
        .any(|suffix| physical_path.ends_with(suffix));
    let typed = !declaration
        && [".ts", ".mts", ".cts"]
            .iter()
            .any(|suffix| physical_path.ends_with(suffix));
    if !typed && !javascript_source_matches(source, package_source) {
        return Err(invalid(
            FIELD,
            "source capsule entry bytes differ from captured execution",
        ));
    }
    Ok(())
}

#[cfg(test)]
pub(super) fn verify(value: &Value) -> Result<()> {
    let (bytes, graph_hash) = decode_sources(value)?;
    verify_frame(&bytes, Some(graph_hash), None).map(|_| ())
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use serde_json::json;

    fn producer_vectors() -> Vec<Value> {
        let fixture: Value = serde_json::from_str(include_str!(
            "../tests/fixtures/module_source_capsules.json"
        ))
        .unwrap();
        assert_eq!(fixture["execution_performed"], false);
        fixture["vectors"].as_array().unwrap().clone()
    }

    // Exact preimage recovered from the retained producer vector (commit
    // 642ab64fd638b21f493deb2cea12c9c605257853). Its fixed v2 hash is checked
    // independently; this is not a newly executed native workload.
    fn producer_graph_report() -> Vec<u8> {
        include_bytes!("../tests/fixtures/module_source_graph_workspace_report.json").to_vec()
    }

    fn graph_capsule() -> Vec<u8> {
        decode_sources(&producer_vectors()[2]["module_sources"])
            .unwrap()
            .0
    }

    #[test]
    fn graph_commitment_recomputes_retained_producer_preimage_without_semantic_claims() {
        let capsule = graph_capsule();
        for report in [
            producer_graph_report(),
            serde_json::to_vec(&serde_json::from_slice::<Value>(&producer_graph_report()).unwrap())
                .unwrap(),
        ] {
            let facts = inspect_graph_report(&capsule, &report).unwrap();
            assert_eq!(
                facts.graph_input_hash,
                "sha256:5a28658ea038488586da68c54c902aefcb2fa9bff17fc80fcca87abc801dedea"
            );
            assert!(facts.graph_hash_recomputed);
            assert!(!facts.graph_semantics_reconstructed);
            assert_eq!(facts.module_count, 3);
            assert_eq!(facts.edge_count, 2);
            assert_eq!(facts.observation_count, 10);
            assert_eq!(facts.capsule_digest, capsule_digest(&capsule));
            assert!(
                !inspect_authenticated(&capsule)
                    .unwrap()
                    .graph_hash_recomputed
            );
            let output = serde_json::to_string(&facts).unwrap();
            assert!(!output.contains("packages/workspace"));
            assert!(!format!("{facts:?}").contains("import 'workspace'"));
        }
    }

    #[test]
    fn graph_commitment_rejects_tampered_reordered_and_foreign_witnesses() {
        let original: Value = serde_json::from_slice(&producer_graph_report()).unwrap();
        let capsule = graph_capsule();
        let changes = [
            (
                "/schema_version",
                json!("franken-node/module-source-graph/v3"),
            ),
            ("/input_hash", json!(format!("sha256:{}", "1".repeat(64)))),
            ("/entrypoint", json!("packages/workspace/main.mjs")),
            ("/options/symlink_policy", json!("reject")),
            ("/options/conditions", json!(["node", "import"])),
            ("/modules/0/content_sha256", json!("0".repeat(64))),
            ("/modules/0/content_bytes", json!(18)),
            ("/edges/0/specifier", json!("forged-request")),
            ("/edges/0/site/end_byte", json!(20)),
            (
                "/edges/0/mappings/0/selection/target",
                json!("./forged.mjs"),
            ),
            (
                "/edges/0/mappings/0/input_hash",
                json!(format!("sha256:{}", "0".repeat(64))),
            ),
            ("/probes/3/link_target", json!("../foreign")),
            ("/fully_resolved", json!(false)),
            ("/runtime_completeness", json!(true)),
            ("/type_resolution_performed", json!(true)),
            ("/execution_performed", json!(true)),
            ("/release_certification", json!(true)),
        ];
        for (pointer, replacement) in changes {
            let mut changed = original.clone();
            *changed.pointer_mut(pointer).unwrap() = replacement;
            assert!(
                inspect_graph_report(&capsule, &serde_json::to_vec(&changed).unwrap()).is_err(),
                "{pointer}"
            );
        }
        for field in ["modules", "edges", "probes"] {
            let mut changed = original.clone();
            changed[field].as_array_mut().unwrap().reverse();
            assert!(
                inspect_graph_report(&capsule, &serde_json::to_vec(&changed).unwrap()).is_err()
            );
        }
        let foreign = decode_sources(&producer_vectors()[0]["module_sources"])
            .unwrap()
            .0;
        assert!(inspect_graph_report(&foreign, &producer_graph_report()).is_err());
    }

    fn reseal_graph_witness(value: &Value) -> (Vec<u8>, Vec<u8>) {
        let mut report: GraphReport = serde_json::from_value(value.clone()).unwrap();
        report.input_hash.clear();
        let mut hash = Sha256::new();
        let domain: &[u8] = match report.schema_version.as_str() {
            "franken-node/module-source-graph/v2" => b"franken-node/module-source-graph/v2\0",
            "franken-node/module-source-graph/v3" => b"franken-node/module-source-graph/v3\0",
            _ => panic!("unsupported test witness schema"),
        };
        hash.update(domain);
        hash.update(serde_json::to_vec(&report).unwrap());
        report.input_hash = format!("sha256:{}", hex::encode(hash.finalize()));
        let (mut header, payload) = decode(&producer_vectors()[2]["module_sources"]);
        header.graph_hash.clone_from(&report.input_hash);
        (
            frame(&serde_json::to_vec(&header).unwrap(), &payload),
            serde_json::to_vec(&report).unwrap(),
        )
    }

    // These are graph-wire mutation controls, not assertions that the retained
    // producer's parser would derive a different request from its old sources.
    // Native producer-to-reader conformance is a separate integration boundary.
    fn normalized_dirname_graph_report() -> Value {
        let mut report: Value = serde_json::from_slice(&producer_graph_report()).unwrap();
        report["schema_version"] = json!("franken-node/module-source-graph/v3");
        let edge = &mut report["edges"][0];
        edge["kind"] = json!("require");
        edge["specifier"] = json!("./packages/workspace/main.mjs");
        edge["normalized_dirname_request"] = json!(true);
        edge["conditions"] = json!(["node", "require"]);
        edge["mappings"] = json!([]);
        report
    }

    #[test]
    fn graph_commitment_authenticates_normalized_commonjs_request_spelling() {
        for (kind, specifier) in [
            ("require", "./packages/workspace/main.mjs"),
            ("require_resolve", "./packages/workspace/"),
            ("require", "."),
            ("require_resolve", "./"),
        ] {
            let mut source = normalized_dirname_graph_report();
            source["edges"][0]["kind"] = json!(kind);
            source["edges"][0]["specifier"] = json!(specifier);
            let (capsule, report) = reseal_graph_witness(&source);
            let facts = inspect_graph_report(&capsule, &report).unwrap();
            assert!(facts.graph_hash_recomputed);
            assert!(!facts.graph_semantics_reconstructed);

            // The marker and spelling are both signed-commitment inputs:
            // neither can be changed while retaining the original capsule pin.
            let authenticated: Value = serde_json::from_slice(&report).unwrap();
            let mut changed = authenticated.clone();
            changed["edges"][0]["specifier"] = json!("./substituted.cjs");
            assert!(
                inspect_graph_report(&capsule, &serde_json::to_vec(&changed).unwrap()).is_err()
            );
            let mut changed = authenticated;
            changed["edges"][0]
                .as_object_mut()
                .unwrap()
                .remove("normalized_dirname_request");
            assert!(
                inspect_graph_report(&capsule, &serde_json::to_vec(&changed).unwrap()).is_err()
            );
        }
    }

    #[test]
    fn graph_commitment_rejects_resealed_ambiguous_normalized_requests() {
        let original = normalized_dirname_graph_report();
        for (pointer, replacement) in [
            (
                "/schema_version",
                json!("franken-node/module-source-graph/v2"),
            ),
            ("/edges/0/dirname_request", json!(true)),
            ("/edges/0/kind", json!("static_import")),
            ("/edges/0/kind", json!("reexport")),
            ("/edges/0/kind", json!("dynamic_import")),
            ("/edges/0/kind", json!("import_meta_resolve")),
            ("/edges/0/state", json!("type_only")),
            ("/edges/0/specifier", Value::Null),
            ("/edges/0/specifier", json!("workspace")),
            ("/edges/0/specifier", json!("../outside.cjs")),
            ("/edges/0/specifier", json!("/absolute.cjs")),
            ("/edges/0/specifier", json!("./sub/../other.cjs")),
            ("/edges/0/specifier", json!("./sub//other.cjs")),
            ("/edges/0/specifier", json!("./.git/config")),
            ("/edges/0/specifier", json!("./.beads/issues.jsonl")),
            ("/edges/0/import_attributes", json!({"type": "json"})),
            ("/edges/0/commonjs_search", json!({"kind": "lookup_paths"})),
        ] {
            let mut changed = original.clone();
            // Optional marker fields are absent in the original wire value.
            let key = pointer.rsplit('/').next().unwrap();
            if pointer.starts_with("/edges/0/") {
                changed["edges"][0][key] = replacement;
            } else {
                changed[key] = replacement;
            }
            let (capsule, report) = reseal_graph_witness(&changed);
            assert!(
                inspect_graph_report(&capsule, &report).is_err(),
                "{pointer}"
            );
        }
    }

    #[test]
    fn graph_commitment_binds_complete_observations_even_when_report_hash_is_resealed() {
        let original: Value = serde_json::from_slice(&producer_graph_report()).unwrap();
        for (pointer, replacement) in [
            ("/probes/0/path", json!("wrong-root")),
            ("/probes/1/sha256", json!("1".repeat(64))),
            ("/probes/1/bytes", json!(18)),
            ("/probes/3/link_target", json!("../foreign")),
            ("/probes/4/kind", json!("directory")),
            ("/modules/1/content_sha256", json!("2".repeat(64))),
            (
                "/resolved_entrypoint/path",
                json!("packages/workspace/main.mjs"),
            ),
            ("/edges/0/importer/path", json!("unrecorded.mjs")),
            ("/edges/0/target/path", json!("unrecorded.mjs")),
            ("/edges/0/site/start_byte", json!(20)),
            (
                "/edges/0/mappings/0/input_hash",
                json!(format!("sha256:{}", "3".repeat(64))),
            ),
            (
                "/edges/0/mappings/0/manifest",
                json!("unrecorded/package.json"),
            ),
            ("/fully_resolved", json!(false)),
        ] {
            let mut changed = original.clone();
            *changed.pointer_mut(pointer).unwrap() = replacement;
            let (capsule, report) = reseal_graph_witness(&changed);
            assert!(
                inspect_graph_report(&capsule, &report).is_err(),
                "{pointer}"
            );
        }
        for remove in [true, false] {
            let mut changed = original.clone();
            let probes = changed["probes"].as_array_mut().unwrap();
            if remove {
                probes.pop();
            } else {
                probes.push(json!({"path":"z","kind":"missing","bytes":null,"sha256":null}));
            }
            let (capsule, report) = reseal_graph_witness(&changed);
            assert!(inspect_graph_report(&capsule, &report).is_err());
        }
    }

    #[test]
    fn graph_commitment_rejects_ambiguous_unknown_and_noncanonical_fields() {
        let original: Value = serde_json::from_slice(&producer_graph_report()).unwrap();
        let capsule = graph_capsule();
        let duplicate = producer_graph_report();
        let duplicate = String::from_utf8(duplicate).unwrap().replacen(
            "\"scope\":",
            "\"scope\":\"ignored\", \"scope\":",
            1,
        );
        assert!(inspect_graph_report(&capsule, duplicate.as_bytes()).is_err());
        for pointer in ["", "/options", "/modules/0", "/edges/0", "/probes/0"] {
            let mut changed = original.clone();
            changed
                .pointer_mut(pointer)
                .unwrap()
                .as_object_mut()
                .unwrap()
                .insert("unrecognized".into(), json!(true));
            assert!(
                inspect_graph_report(&capsule, &serde_json::to_vec(&changed).unwrap()).is_err()
            );
        }
        for (pointer, field, value) in [
            ("", "resolution_targets", json!([])),
            ("/edges/0", "dirname_request", json!(false)),
            ("/edges/0", "normalized_dirname_request", json!(false)),
            ("/edges/0", "resolved_url", Value::Null),
            ("/edges/0", "commonjs_search", Value::Null),
            ("/edges/0", "import_attributes", json!({})),
        ] {
            let mut changed = original.clone();
            changed
                .pointer_mut(pointer)
                .unwrap()
                .as_object_mut()
                .unwrap()
                .insert(field.into(), value);
            assert!(
                inspect_graph_report(&capsule, &serde_json::to_vec(&changed).unwrap()).is_err()
            );
        }
        let mut missing = original;
        missing["probes"][0]
            .as_object_mut()
            .unwrap()
            .remove("sha256");
        assert!(inspect_graph_report(&capsule, &serde_json::to_vec(&missing).unwrap()).is_err());
        assert!(
            inspect_graph_report(&capsule, &vec![b' '; MAX_SOURCE_GRAPH_REPORT_BYTES + 1]).is_err()
        );
        assert!(inspect_graph_report(&capsule, b"").is_err());
    }

    pub(crate) fn producer_sources() -> Value {
        producer_vectors()[0]["module_sources"].clone()
    }

    pub(crate) fn producer_package() -> Value {
        let source = producer_vectors()[0]["project_files"]["app.mjs"].clone();
        json!({
            "extension_id":"test",
            "source":source,
            "capabilities":["builtin"],
            "module_root":"/captured",
            "source_file":"/captured/app.mjs"
        })
    }

    fn entry_sources(
        entrypoint: &str,
        files: &[(&str, &str)],
        directories: &[&str],
        links: &[(&str, &str)],
    ) -> Value {
        let mut inputs = BTreeMap::new();
        inputs.insert("", (Content::Directory, None));
        for path in directories {
            inputs.insert(*path, (Content::Directory, None));
        }
        for (path, source) in files {
            inputs.insert(
                *path,
                (
                    Content::File {
                        bytes: source.len(),
                        sha256: hex::encode(Sha256::digest(source.as_bytes())),
                    },
                    Some(source.as_bytes()),
                ),
            );
        }
        for (path, target) in links {
            inputs.insert(
                *path,
                (
                    Content::Symlink {
                        target: (*target).into(),
                        sha256: hex::encode(Sha256::digest(target.as_bytes())),
                    },
                    None,
                ),
            );
        }
        let mut payload = Vec::new();
        let inputs = inputs
            .into_iter()
            .map(|(path, (content, source))| {
                if let Some(source) = source {
                    payload.extend_from_slice(source);
                }
                Input {
                    path: path.into(),
                    content,
                }
            })
            .collect();
        sources_from_parts(
            &Header {
                schema_version: SCHEMA.into(),
                graph_hash: format!("sha256:{}", "e".repeat(64)),
                entrypoint: entrypoint.into(),
                options: Options {
                    symlink_policy: SymlinkPolicy::Contained,
                    conditions: None,
                    additional_conditions: Vec::new(),
                },
                inputs,
            },
            &payload,
        )
    }

    pub(crate) fn entry_bytes_sources(entry: &str, raw: &[u8]) -> Value {
        let (mut header, _) = decode(&entry_sources(entry, &[(entry, "")], &[], &[]));
        header
            .inputs
            .iter_mut()
            .find(|input| input.path == entry)
            .unwrap()
            .content = Content::File {
            bytes: raw.len(),
            sha256: hex::encode(Sha256::digest(raw)),
        };
        sources_from_parts(&header, raw)
    }

    #[test]
    fn native_entry_binding_checks_real_producer_bytes_and_portable_origins() {
        for (index, vector) in producer_vectors().into_iter().enumerate() {
            let sources = &vector["module_sources"];
            let source = vector["project_files"]["app.mjs"].as_str().unwrap();
            let settings = if index == 1 {
                json!({"module_conditions":["development","unused"]})
            } else {
                json!({})
            };
            for (root, file) in [
                ("/captured", "/captured/app.mjs"),
                ("/", "/app.mjs"),
                ("C:\\captured", "C:\\captured\\app.mjs"),
                ("\\\\host\\share", "\\\\host\\share\\app.mjs"),
            ] {
                let package = json!({"module_root":root,"source_file":file,"source":source});
                verify_capture_binding(sources, &package, &settings).unwrap();
            }
            if index == 1 {
                let package = json!({
                    "module_root":"/captured",
                    "source_file":"/captured/app.mjs",
                    "source":source
                });
                verify_capture_binding(
                    sources,
                    &package,
                    &json!({"module_conditions":["unused","development","development"]}),
                )
                .unwrap();
            }
            let (bytes, graph) = decode_sources(sources).unwrap();
            let summary = inspect_authenticated(&bytes).unwrap();
            assert_eq!(summary.graph_input_hash, graph);
            assert!(!summary.graph_hash_recomputed);
        }
    }

    #[test]
    fn native_entry_conditions_bound_raw_settings_before_set_equivalence() {
        let vector = producer_vectors()[1].clone();
        let sources = &vector["module_sources"];
        let package = json!({
            "module_root":"/captured",
            "source_file":"/captured/app.mjs",
            "source":vector["project_files"]["app.mjs"]
        });
        let mut conditions = vec!["development"; 61];
        conditions.push("unused");
        verify_capture_binding(sources, &package, &json!({"module_conditions":conditions}))
            .unwrap();
        conditions.push("development");
        let error =
            verify_capture_binding(sources, &package, &json!({"module_conditions":conditions}))
                .unwrap_err();
        assert!(error.to_string().contains("conditions exceed their bound"));
    }

    #[test]
    fn native_entry_binding_rejects_resigned_source_path_and_condition_contradictions() {
        let sources = producer_sources();
        let package = producer_package();
        for (field, value) in [
            ("source", json!("throw 'PRIVATE-DIFFERENT-SOURCE';")),
            ("module_root", json!("/PRIVATE-OTHER-PROJECT")),
            ("module_root", json!("captured")),
            ("module_root", Value::Null),
            ("source_file", json!("/captured/PRIVATE-OTHER-ENTRY.mjs")),
            ("source_file", json!("/captured-other/app.mjs")),
            ("source_file", json!("/captured/../app.mjs")),
            ("source_file", Value::Null),
        ] {
            let mut altered = package.clone();
            altered[field] = value;
            let error = verify_capture_binding(&sources, &altered, &json!({})).unwrap_err();
            assert!(!error.to_string().contains("PRIVATE-"));
        }
        for settings in [
            json!({"module_conditions":["development"]}),
            json!({"module_conditions":[""]}),
            json!({"module_conditions":null}),
            json!({"module_conditions":[1]}),
        ] {
            assert!(verify_capture_binding(&sources, &package, &settings).is_err());
        }
        let (mut header, payload) = decode(&sources);
        header.options.conditions = Some(vec!["import".into(), "node".into()]);
        let altered = sources_from_parts(&header, &payload);
        verify(&altered).unwrap();
        assert!(verify_capture_binding(&altered, &package, &json!({})).is_err());
    }

    #[test]
    fn native_entry_links_expand_before_parent_segments_without_host_reads() {
        let source = "module.exports = 'physical target';";
        let sources = entry_sources(
            "app.cjs",
            &[
                ("entry.cjs", "module.exports = 'wrong lexical target';"),
                ("nested/entry.cjs", source),
            ],
            &["nested", "nested/deep"],
            &[("app.cjs", "alias/../entry.cjs"), ("alias", "nested/deep")],
        );
        let package = json!({
            "module_root":"/does-not-exist",
            "source_file":"/does-not-exist/app.cjs",
            "source":source
        });
        verify_capture_binding(&sources, &package, &json!({})).unwrap();
        let mut wrong = package.clone();
        wrong["source"] = json!("module.exports = 'wrong lexical target';");
        assert!(verify_capture_binding(&sources, &wrong, &json!({})).is_err());

        let chained = entry_sources(
            "linked/app.cjs",
            &[("nested/entry.cjs", source)],
            &["nested"],
            &[
                ("linked", "nested"),
                ("nested/app.cjs", "./bridge.cjs"),
                ("nested/bridge.cjs", "entry.cjs"),
            ],
        );
        let mut package = package;
        package["source_file"] = json!("/does-not-exist/linked/app.cjs");
        verify_capture_binding(&chained, &package, &json!({})).unwrap();
    }

    #[test]
    fn native_entry_uses_the_physical_source_language_through_links() {
        let raw = "export const n: number = 1;";
        let prepared = "export const n = 1;";
        let sources = entry_sources(
            "alias.js",
            &[("entry.ts", raw)],
            &[],
            &[("alias.js", "entry.ts")],
        );
        let mut package = json!({
            "module_root":"/captured",
            "source_file":"/captured/alias.js",
            "source":prepared
        });
        // A JS-spelled link does not turn a physical TypeScript source into JS.
        verify_capture_binding(&sources, &package, &json!({})).unwrap();
        let sources = entry_sources(
            "alias.ts",
            &[("entry.js", "export const n = 2;")],
            &[],
            &[("alias.ts", "entry.js")],
        );
        package["source_file"] = json!("/captured/alias.ts");
        // A TypeScript-spelled link cannot exempt physical JS from byte checks.
        assert!(verify_capture_binding(&sources, &package, &json!({})).is_err());
    }

    #[test]
    fn native_entry_refuses_incomplete_metadata_and_nonterminating_links() {
        let source = "export default 1;";
        let sources = entry_sources("app.mjs", &[("app.mjs", source)], &[], &[]);
        let package = json!({
            "module_root":"/captured", "source_file":"/captured/app.mjs", "source":source
        });
        for content in [Content::Missing, Content::Directory, Content::FileMetadata] {
            let (mut header, _) = decode(&sources);
            header
                .inputs
                .iter_mut()
                .find(|input| input.path == "app.mjs")
                .unwrap()
                .content = content;
            let altered = sources_from_parts(&header, &[]);
            // A pre-entry forensic capsule may honestly record this state.
            verify(&altered).unwrap();
            assert!(verify_capture_binding(&altered, &package, &json!({})).is_err());
        }
        let omitted = entry_sources("app.mjs", &[], &[], &[]);
        verify(&omitted).unwrap();
        assert!(verify_capture_binding(&omitted, &package, &json!({})).is_err());
        for links in [
            vec![("app.mjs", "../outside.mjs")],
            vec![("app.mjs", "app.mjs")],
            vec![("app.mjs", "loop.mjs"), ("loop.mjs", "app.mjs")],
            vec![("app.mjs", "unknown.mjs")],
        ] {
            let linked = entry_sources("app.mjs", &[], &[], &links);
            verify(&linked).unwrap();
            assert!(verify_capture_binding(&linked, &package, &json!({})).is_err());
        }

        let package = json!({
            "module_root":"/captured",
            "source_file":"/captured/link/app.mjs",
            "source":source
        });
        for target in [
            "d/".repeat(MAX_PATH_DEPTH - 1) + "d",
            "x".repeat(MAX_PATH_BYTES),
        ] {
            let linked = entry_sources("link/app.mjs", &[], &[], &[("link", &target)]);
            verify(&linked).unwrap();
            let error = verify_capture_binding(&linked, &package, &json!({})).unwrap_err();
            assert!(error.to_string().contains("exceeds its path bound"));
        }
    }

    #[test]
    fn native_entry_link_budget_accepts_boundary_and_finite_repeated_links() {
        let source = "export default 1;";
        let mut owned = (0..MAX_LINK_HOPS)
            .map(|index| {
                (
                    format!("chain-{index}"),
                    if index + 1 == MAX_LINK_HOPS {
                        "value.mjs".into()
                    } else {
                        format!("chain-{}", index + 1)
                    },
                )
            })
            .collect::<Vec<_>>();
        let links = owned
            .iter()
            .map(|(path, target)| (path.as_str(), target.as_str()))
            .collect::<Vec<_>>();
        let sources = entry_sources("chain-0", &[("value.mjs", source)], &[], &links);
        let mut package = json!({
            "module_root":"/captured", "source_file":"/captured/chain-0", "source":source
        });
        verify_capture_binding(&sources, &package, &json!({})).unwrap();
        owned.push(("too-many".into(), "chain-0".into()));
        let links = owned
            .iter()
            .map(|(path, target)| (path.as_str(), target.as_str()))
            .collect::<Vec<_>>();
        let sources = entry_sources("too-many", &[("value.mjs", source)], &[], &links);
        package["source_file"] = json!("/captured/too-many");
        assert!(verify_capture_binding(&sources, &package, &json!({})).is_err());

        let repeated = entry_sources(
            "link/link/value.mjs",
            &[("value.mjs", source)],
            &[],
            &[("link", ".")],
        );
        package["source_file"] = json!("/captured/link/link/value.mjs");
        verify_capture_binding(&repeated, &package, &json!({})).unwrap();
    }

    #[test]
    fn native_entry_rejects_non_utf8_bytes_even_when_digests_are_valid() {
        let cases: &[(&str, &[u8])] = &[
            ("app.mjs", b"\xff"),
            ("app.cjs", b"#!\xff"),
            ("app.js", b"\xef\xbb\xbf\xff"),
            ("app.ts", b"\xff"),
            ("app.mts", b"\xff"),
            ("app.cts", b"\xff"),
        ];
        for &(entry, raw) in cases {
            let sources = entry_bytes_sources(entry, raw);
            let package = json!({
                "module_root":"/captured",
                "source_file":format!("/captured/{entry}"),
                "source":"export default 1;"
            });
            verify(&sources).unwrap();
            let error = verify_capture_binding(&sources, &package, &json!({})).unwrap_err();
            assert!(
                error.to_string().contains("not valid UTF-8"),
                "{entry}: {error}"
            );
        }
    }

    #[test]
    fn native_javascript_entry_matches_exact_hashbang_preparation_and_retains_bom() {
        let cases = [
            ("#!x\nexport default 1;", "   \nexport default 1;"),
            ("#!x\rexport default 1;", "   \rexport default 1;"),
            ("#!x\r\nexport default 1;", "   \r\nexport default 1;"),
            (
                "#!x\u{2028}export default 1;",
                "   \u{2028}export default 1;",
            ),
            (
                "#!x\u{2029}export default 1;",
                "   \u{2029}export default 1;",
            ),
            (
                "\u{feff}#!x\nexport default 1;",
                "      \nexport default 1;",
            ),
            ("#!é\nexport default 1;", "    \nexport default 1;"),
            ("\u{feff}export default 1;", "\u{feff}export default 1;"),
            ("export default 1;", "export default 1;"),
        ];
        for entry in ["app.js", "app.mjs", "app.cjs"] {
            for (raw, prepared) in cases {
                let sources = entry_sources(entry, &[(entry, raw)], &[], &[]);
                let mut package = json!({
                    "module_root":"/captured",
                    "source_file":format!("/captured/{entry}"),
                    "source":prepared
                });
                verify_capture_binding(&sources, &package, &json!({})).unwrap();
                package["source"] = json!(format!("{prepared}// changed"));
                assert!(verify_capture_binding(&sources, &package, &json!({})).is_err());
                if raw != prepared {
                    package["source"] = json!(raw);
                    assert!(verify_capture_binding(&sources, &package, &json!({})).is_err());
                } else if let Some(without_bom) = raw.strip_prefix('\u{feff}') {
                    package["source"] = json!(without_bom);
                    assert!(verify_capture_binding(&sources, &package, &json!({})).is_err());
                }
            }
        }
        assert!(javascript_source_matches("#!x", "   "));
        assert!(!javascript_source_matches("#!x", "  "));
        assert!(!javascript_source_matches("#!x", "\u{2028}"));
    }

    #[test]
    fn native_declaration_entries_do_not_receive_the_typescript_transformation_exception() {
        for entry in ["types.d.ts", "types.d.mts", "types.d.cts"] {
            let raw = "declare const n: number;";
            let sources = entry_sources(entry, &[(entry, raw)], &[], &[]);
            let mut package = json!({
                "module_root":"/captured",
                "source_file":format!("/captured/{entry}"),
                "source":raw
            });
            // Equal bytes do not prove that this declaration graph is admitted.
            verify_capture_binding(&sources, &package, &json!({})).unwrap();
            let (bytes, _) = decode_sources(&sources).unwrap();
            assert!(!inspect_authenticated(&bytes).unwrap().graph_hash_recomputed);
            package["source"] = json!("export const n = 1;");
            assert!(verify_capture_binding(&sources, &package, &json!({})).is_err());
        }
    }

    #[test]
    fn native_entry_does_not_claim_to_reproduce_typescript_preparation() {
        for (entry, raw, prepared) in [
            (
                "app.ts",
                "export const n: number = 1;",
                "export const n = 1;",
            ),
            (
                "app.mts",
                "export const n: number = 1;",
                "export const n = 1;",
            ),
            (
                "app.cts",
                "const n: number = 1; module.exports = n;",
                "const n = 1; module.exports = n;",
            ),
        ] {
            let sources = entry_sources(entry, &[(entry, raw)], &[], &[]);
            let package = json!({
                "module_root":"/captured",
                "source_file":format!("/captured/{entry}"),
                "source":prepared
            });
            verify_capture_binding(&sources, &package, &json!({})).unwrap();
            let (bytes, _) = decode_sources(&sources).unwrap();
            assert!(!inspect_authenticated(&bytes).unwrap().graph_hash_recomputed);
            let mut wrong_entry = package;
            wrong_entry["source_file"] = json!("/captured/other.ts");
            assert!(verify_capture_binding(&sources, &wrong_entry, &json!({})).is_err());
        }
    }

    fn decode(value: &Value) -> (Header, Vec<u8>) {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(value["capsule_base64"].as_str().unwrap())
            .unwrap();
        let end = PREFIX_BYTES + u32::from_le_bytes(bytes[8..12].try_into().unwrap()) as usize;
        (
            serde_json::from_slice(&bytes[PREFIX_BYTES..end]).unwrap(),
            bytes[end..].to_vec(),
        )
    }

    fn sources_from_bytes(bytes: &[u8], graph_hash: &str) -> Value {
        json!({
            "capsule_base64": base64::engine::general_purpose::STANDARD.encode(bytes),
            "capsule_digest": capsule_digest(bytes),
            "graph_input_hash": graph_hash,
        })
    }

    fn frame(metadata: &[u8], payload: &[u8]) -> Vec<u8> {
        let mut bytes = MAGIC.to_vec();
        bytes.extend_from_slice(&(metadata.len() as u32).to_le_bytes());
        bytes.extend_from_slice(metadata);
        bytes.extend_from_slice(payload);
        bytes
    }

    fn sources_from_parts(header: &Header, payload: &[u8]) -> Value {
        sources_from_bytes(
            &frame(&serde_json::to_vec(header).unwrap(), payload),
            &header.graph_hash,
        )
    }

    // Synthetic wire-level coverage of the producer's metadata-only variant.
    // Preserve real captured file payloads, but use a separate graph commitment:
    // this fixture does not claim a successful graph reconstruction or execution.
    fn metadata_probe_parts() -> (Header, Vec<u8>) {
        let (mut header, payload) = decode(&producer_sources());
        header.graph_hash = format!("sha256:{}", "f".repeat(64));
        header.inputs.push(Input {
            path: "PRIVATE-SOURCE-SENTINEL.node".into(),
            content: Content::FileMetadata,
        });
        header
            .inputs
            .sort_by(|left, right| left.path.cmp(&right.path));
        (header, payload)
    }

    // Every capsule mutation below recomputes its capsule digest unless that
    // digest is the subject of the test. The incident tests additionally sign
    // each candidate with a valid external anchor, so neither outer protection
    // can mask an absent inner byte-integrity check.
    pub(crate) fn negative_sources() -> Vec<(&'static str, Value)> {
        let original = producer_sources();
        let (header, payload) = decode(&original);
        let raw_header = serde_json::to_vec(&header).unwrap();
        let original_bytes = frame(&raw_header, &payload);
        let mut cases = Vec::new();

        let mut malformed = original.clone();
        malformed["capsule_base64"] = json!("PRIVATE-SOURCE-SENTINEL");
        cases.push(("invalid base64", malformed));
        let mut noncanonical = original.clone();
        noncanonical["capsule_base64"] = json!(format!(
            "{}\n",
            original["capsule_base64"].as_str().unwrap()
        ));
        cases.push(("base64 whitespace", noncanonical));
        for field in ["capsule_digest", "graph_input_hash"] {
            let mut candidate = original.clone();
            candidate[field] = json!(format!("sha256:{}", "0".repeat(64)));
            cases.push((
                if field == "capsule_digest" {
                    "wrong capsule pin"
                } else {
                    "wrong graph identity"
                },
                candidate,
            ));
        }
        let mut wrong_domain = original.clone();
        wrong_domain["capsule_digest"] = json!(format!(
            "sha256:{}",
            hex::encode(Sha256::digest(&original_bytes))
        ));
        cases.push(("plain SHA-256 is not the capsule domain", wrong_domain));
        let mut wrong_magic = original_bytes.clone();
        wrong_magic[0] = b'X';
        cases.push((
            "wrong frame magic",
            sources_from_bytes(&wrong_magic, &header.graph_hash),
        ));
        let mut truncated_header = original_bytes[..PREFIX_BYTES].to_vec();
        truncated_header[8..12].copy_from_slice(&u32::MAX.to_le_bytes());
        cases.push((
            "oversized header length",
            sources_from_bytes(&truncated_header, &header.graph_hash),
        ));
        truncated_header[8..12].copy_from_slice(&100_u32.to_le_bytes());
        cases.push((
            "truncated header",
            sources_from_bytes(&truncated_header, &header.graph_hash),
        ));
        cases.push((
            "short frame",
            sources_from_bytes(b"FNSGCAP1", &header.graph_hash),
        ));
        let mut whitespace = b" ".to_vec();
        whitespace.extend_from_slice(&raw_header);
        cases.push((
            "noncanonical header",
            sources_from_bytes(&frame(&whitespace, &payload), &header.graph_hash),
        ));
        let mut duplicate = b"{\"schema_version\":\"duplicate\",".to_vec();
        duplicate.extend_from_slice(&raw_header[1..]);
        cases.push((
            "duplicate header member",
            sources_from_bytes(&frame(&duplicate, &payload), &header.graph_hash),
        ));
        let mut unknown = b"{\"unknown\":true,".to_vec();
        unknown.extend_from_slice(&raw_header[1..]);
        cases.push((
            "unknown header member",
            sources_from_bytes(&frame(&unknown, &payload), &header.graph_hash),
        ));

        let mut bad_schema = header.clone();
        bad_schema.schema_version = "franken-node/module-source-capsule/v0".into();
        cases.push((
            "historical capsule schema",
            sources_from_parts(&bad_schema, &payload),
        ));
        let mut unsafe_entry = header.clone();
        unsafe_entry.entrypoint = "../PRIVATE-SOURCE-SENTINEL".into();
        cases.push((
            "escaping entrypoint",
            sources_from_parts(&unsafe_entry, &payload),
        ));
        let mut missing_root = header.clone();
        missing_root.inputs.remove(0);
        cases.push(("missing root", sources_from_parts(&missing_root, &payload)));
        let mut bad_root = header.clone();
        bad_root.inputs[0].content = Content::Missing;
        cases.push((
            "root is not a directory",
            sources_from_parts(&bad_root, &payload),
        ));
        let mut unordered = header.clone();
        unordered.inputs.swap(0, 1);
        cases.push((
            "unsorted observations",
            sources_from_parts(&unordered, &payload),
        ));
        let mut duplicate_input = header.clone();
        duplicate_input
            .inputs
            .insert(0, duplicate_input.inputs[0].clone());
        cases.push((
            "duplicate observations",
            sources_from_parts(&duplicate_input, &payload),
        ));
        let mut too_many = header.clone();
        too_many.inputs = vec![header.inputs[0].clone(); MAX_INPUTS + 1];
        cases.push(("observation bound", sources_from_parts(&too_many, &payload)));
        let mut no_parent = header.clone();
        let directory = no_parent
            .inputs
            .iter()
            .position(|input| !input.path.is_empty() && matches!(input.content, Content::Directory))
            .unwrap();
        no_parent.inputs.remove(directory);
        cases.push((
            "missing physical parent",
            sources_from_parts(&no_parent, &payload),
        ));
        let mut unsafe_path = header.clone();
        unsafe_path.inputs[1].path = "../PRIVATE-SOURCE-SENTINEL".into();
        cases.push((
            "escaping observation",
            sources_from_parts(&unsafe_path, &payload),
        ));
        let mut long_path = header.clone();
        long_path.entrypoint = "x".repeat(MAX_PATH_BYTES + 1);
        cases.push(("path byte bound", sources_from_parts(&long_path, &payload)));
        let mut deep_path = header.clone();
        deep_path.entrypoint = vec!["x"; MAX_PATH_DEPTH + 1].join("/");
        cases.push(("path depth bound", sources_from_parts(&deep_path, &payload)));
        let mut changed_payload = payload.clone();
        *changed_payload.last_mut().unwrap() ^= 1;
        cases.push((
            "altered captured file bytes",
            sources_from_parts(&header, &changed_payload),
        ));
        let mut bad_file_hash = header.clone();
        let file = bad_file_hash
            .inputs
            .iter_mut()
            .find_map(|input| match &mut input.content {
                Content::File { sha256, .. } => Some(sha256),
                _ => None,
            })
            .unwrap();
        *file = "0".repeat(64);
        cases.push((
            "file digest mismatch",
            sources_from_parts(&bad_file_hash, &payload),
        ));
        let mut oversized_file = header.clone();
        let file = oversized_file
            .inputs
            .iter_mut()
            .find_map(|input| match &mut input.content {
                Content::File { bytes, .. } => Some(bytes),
                _ => None,
            })
            .unwrap();
        *file = MAX_FILE_BYTES + 1;
        cases.push((
            "file byte bound",
            sources_from_parts(&oversized_file, &payload),
        ));
        let mut oversized_manifest = header.clone();
        let file = oversized_manifest
            .inputs
            .iter_mut()
            .find(|input| {
                input.path.ends_with("/package.json")
                    && matches!(input.content, Content::File { .. })
            })
            .unwrap();
        let Content::File { bytes, .. } = &mut file.content else {
            panic!("producer manifest")
        };
        *bytes = MAX_MANIFEST_BYTES + 1;
        cases.push((
            "manifest byte bound",
            sources_from_parts(&oversized_manifest, &payload),
        ));
        cases.push((
            "truncated file payload",
            sources_from_parts(&header, &payload[..payload.len() - 1]),
        ));
        let mut trailing_payload = payload.clone();
        trailing_payload.extend_from_slice(b"PRIVATE-SOURCE-SENTINEL");
        cases.push((
            "unclaimed payload suffix",
            sources_from_parts(&header, &trailing_payload),
        ));
        let mut duplicate_conditions = header.clone();
        duplicate_conditions.options.conditions = Some(vec!["node".into(), "node".into()]);
        cases.push((
            "duplicate conditions",
            sources_from_parts(&duplicate_conditions, &payload),
        ));
        let mut excessive_conditions = header.clone();
        excessive_conditions.options.additional_conditions =
            (0..63).map(|i| format!("condition-{i:02}")).collect();
        cases.push((
            "condition count bound",
            sources_from_parts(&excessive_conditions, &payload),
        ));
        let mut bad_condition = header.clone();
        bad_condition.options.additional_conditions = vec!["bad\ncondition".into()];
        cases.push((
            "condition control bytes",
            sources_from_parts(&bad_condition, &payload),
        ));

        let (linked, linked_payload) = decode(&producer_vectors()[2]["module_sources"]);
        let mut forbidden_link = linked.clone();
        forbidden_link.options.symlink_policy = SymlinkPolicy::Reject;
        cases.push((
            "link policy violation",
            sources_from_parts(&forbidden_link, &linked_payload),
        ));
        let mut changed_link = linked.clone();
        let link = changed_link
            .inputs
            .iter_mut()
            .find_map(|input| match &mut input.content {
                Content::Symlink { target, .. } => Some(target),
                _ => None,
            })
            .unwrap();
        *link = "../different-package".into();
        cases.push((
            "link text digest mismatch",
            sources_from_parts(&changed_link, &linked_payload),
        ));
        let mut absolute_link = linked;
        let link = absolute_link
            .inputs
            .iter_mut()
            .find_map(|input| match &mut input.content {
                Content::Symlink { target, sha256 } => Some((target, sha256)),
                _ => None,
            })
            .unwrap();
        *link.0 = "/PRIVATE-SOURCE-SENTINEL".into();
        *link.1 = hex::encode(Sha256::digest(link.0.as_bytes()));
        cases.push((
            "absolute link with a matching digest",
            sources_from_parts(&absolute_link, &linked_payload),
        ));
        let (metadata_header, metadata_payload) = metadata_probe_parts();
        let metadata_json =
            String::from_utf8(serde_json::to_vec(&metadata_header).unwrap()).unwrap();
        for (case, replacement) in [
            (
                "metadata observation with a byte length",
                r#"{"kind":"file_metadata","bytes":0}"#,
            ),
            (
                "metadata observation with a content hash",
                concat!(
                    r#"{"kind":"file_metadata","sha256":""#,
                    "0000000000000000000000000000000000000000000000000000000000000000",
                    r#""}"#,
                ),
            ),
            (
                "metadata observation with a link target",
                r#"{"kind":"file_metadata","target":"PRIVATE-SOURCE-SENTINEL"}"#,
            ),
        ] {
            let malformed = metadata_json.replacen(r#"{"kind":"file_metadata"}"#, replacement, 1);
            cases.push((
                case,
                sources_from_bytes(
                    &frame(malformed.as_bytes(), &metadata_payload),
                    &metadata_header.graph_hash,
                ),
            ));
        }

        let mut unclaimed_metadata = metadata_payload.clone();
        unclaimed_metadata.extend_from_slice(b"PRIVATE-SOURCE-SENTINEL");
        cases.push((
            "metadata observation cannot claim additional payload bytes",
            sources_from_parts(&metadata_header, &unclaimed_metadata),
        ));
        let mut relabeled_file = metadata_header.clone();
        relabeled_file
            .inputs
            .iter_mut()
            .rfind(|input| matches!(input.content, Content::File { .. }))
            .unwrap()
            .content = Content::FileMetadata;
        cases.push((
            "metadata observation cannot replace a retained file payload",
            sources_from_parts(&relabeled_file, &metadata_payload),
        ));
        let mut metadata_root = metadata_header.clone();
        metadata_root.inputs[0].content = Content::FileMetadata;
        cases.push((
            "metadata observation cannot be the root directory",
            sources_from_parts(&metadata_root, &metadata_payload),
        ));
        let mut metadata_parent = metadata_header.clone();
        metadata_parent
            .inputs
            .iter_mut()
            .find(|input| input.path == "node_modules")
            .unwrap()
            .content = Content::FileMetadata;
        cases.push((
            "metadata observation cannot be a physical parent directory",
            sources_from_parts(&metadata_parent, &metadata_payload),
        ));
        for (case, path) in [
            (
                "metadata observation path traversal",
                "../PRIVATE-SOURCE-SENTINEL",
            ),
            ("metadata observation duplicate path", "app.mjs"),
            (
                "metadata observation without a captured parent",
                "absent/PRIVATE-SOURCE-SENTINEL.node",
            ),
        ] {
            let mut invalid_metadata = metadata_header.clone();
            invalid_metadata
                .inputs
                .iter_mut()
                .find(|input| matches!(input.content, Content::FileMetadata))
                .unwrap()
                .path = path.into();
            invalid_metadata
                .inputs
                .sort_by(|left, right| left.path.cmp(&right.path));
            cases.push((
                case,
                sources_from_parts(&invalid_metadata, &metadata_payload),
            ));
        }
        cases
    }

    #[test]
    fn accepts_metadata_only_observations_without_consuming_source_payload() {
        let (header, payload) = metadata_probe_parts();
        // The new observation precedes actual files, so a byte-consumption
        // mistake would also break the following files' content hashes.
        assert!(matches!(header.inputs[1].content, Content::FileMetadata));
        verify(&sources_from_parts(&header, &payload)).unwrap();
        assert_eq!(
            serde_json::to_value(&header.inputs[1].content).unwrap(),
            json!({"kind": "file_metadata"})
        );
        assert_eq!(payload, decode(&producer_sources()).1);
    }

    #[test]
    fn accepts_real_producer_vectors_for_nested_packages_conditions_and_contained_links() {
        let vectors = producer_vectors();
        assert_eq!(vectors.len(), 3);
        for vector in vectors {
            let sources = &vector["module_sources"];
            verify(sources).unwrap();
            let (header, _) = decode(sources);
            assert_eq!(
                header.inputs.len() as u64,
                vector["observation_count"].as_u64().unwrap()
            );
            assert_eq!(vector["offline_graph_reconstruction_checked"], true);
        }
    }

    #[test]
    fn rejects_rehashed_malformed_capsules_without_echoing_private_sources() {
        for (case, sources) in negative_sources() {
            let error = verify(&sources).unwrap_err();
            assert!(
                matches!(error, super::super::IncidentBundleError::Structure { ref path, .. }
                if path == "$.initial_state_snapshot.native_replay.payload.module_sources"),
                "{case}: {error:?}"
            );
            assert!(
                !format!("{error:?}").contains("PRIVATE-SOURCE-SENTINEL"),
                "{case}"
            );
        }
    }

    #[test]
    fn rejects_oversized_encoding_before_decoding_or_parsing() {
        let mut sources = producer_sources();
        sources["capsule_base64"] = json!("A".repeat(MAX_PAYLOAD_BYTES + 1));
        assert!(
            matches!(verify(&sources), Err(super::super::IncidentBundleError::Structure { reason, .. })
            if reason == "source capsule encoding exceeds the native capture byte bound")
        );
    }
}
