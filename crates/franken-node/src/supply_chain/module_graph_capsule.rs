//! Portable replay of source-graph analysis from captured observations only.
//!
//! A capsule contains source/manifest bytes, link text and negative probes. It
//! never extracts files or evaluates JavaScript. Replay requires an independent
//! capsule pin and re-runs the production scanner/resolver, rather than trusting
//! a serialized report. A self-consistent capsule is not provenance or authority.

use super::super::{MAX_CAPTURE, MAX_FILE, MAX_PROBES, validate_link_target};
use super::{CapturedModuleGraph, Entry, GraphOptions, Resolver, Result, build, error, parent, validate_path};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;

const MAGIC: &[u8; 8] = b"FNSGCAP1";
const PREFIX_BYTES: usize = 12;
const MAX_HEADER_BYTES: usize = 8 * 1024 * 1024;
const SCHEMA: &str = "franken-node/module-source-capsule/v1";
const HASH_DOMAIN: &[u8] = b"franken-node/module-source-capsule/v1\0";
/// Maximum encoded size, checked before hashing or parsing untrusted input.
pub const MAX_CAPSULE_BYTES: usize = PREFIX_BYTES + MAX_HEADER_BYTES + MAX_CAPTURE;

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
    pub fn bytes(&self) -> &[u8] { &self.bytes }
    pub fn digest(&self) -> &str { &self.digest }
}

fn invalid(detail: &str) -> super::ResolutionError {
    error("ERR_MODULE_CAPSULE_INVALID", detail)
}

fn limit() -> super::ResolutionError {
    error("ERR_MODULE_CAPSULE_LIMIT", "capsule exceeds its header, input or payload bound")
}

fn valid_hash(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(valid_digest)
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

fn digest(bytes: &[u8]) -> String {
    let mut hash = Sha256::new();
    hash.update(HASH_DOMAIN);
    hash.update((bytes.len() as u64).to_le_bytes());
    hash.update(bytes);
    format!("sha256:{}", hex::encode(hash.finalize()))
}

fn frame(header: &Header, payload: &[u8]) -> Result<Vec<u8>> {
    let metadata = serde_json::to_vec(header).map_err(|_| invalid("cannot encode capsule header"))?;
    if metadata.len() > MAX_HEADER_BYTES || payload.len() > MAX_CAPTURE { return Err(limit()); }
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
            Entry::File { bytes, sha256 } => {
                if payload.len().saturating_add(bytes.len()) > MAX_CAPTURE { return Err(limit()); }
                payload.extend_from_slice(bytes);
                Content::File { bytes: bytes.len(), sha256: sha256.clone() }
            }
            Entry::Symlink { target, sha256 } => Content::Symlink { target: target.clone(), sha256: sha256.clone() },
        };
        inputs.push(Input { path: path.clone(), content });
        if inputs.len() > MAX_PROBES { return Err(limit()); }
    }
    let header = Header { schema_version: SCHEMA.into(), graph_hash: graph.report.input_hash.clone(),
        entrypoint: graph.report.entrypoint.clone(), options: graph.report.options.clone(), inputs };
    let bytes = frame(&header, &payload)?;
    Ok(EncodedCapsule { digest: digest(&bytes), bytes })
}

fn parse_frame(bytes: &[u8]) -> Result<(Header, &[u8])> {
    if bytes.len() > MAX_CAPSULE_BYTES { return Err(limit()); }
    if bytes.len() < PREFIX_BYTES || &bytes[..8] != MAGIC { return Err(invalid("invalid capsule framing")); }
    let length = u32::from_le_bytes(bytes[8..12].try_into().map_err(|_| invalid("invalid header length"))?) as usize;
    if length > MAX_HEADER_BYTES { return Err(limit()); }
    let end = PREFIX_BYTES.checked_add(length).ok_or_else(limit)?;
    let metadata = bytes.get(PREFIX_BYTES..end).ok_or_else(|| invalid("truncated capsule header"))?;
    let header: Header = serde_json::from_slice(metadata).map_err(|_| invalid("invalid capsule header JSON"))?;
    // One canonical representation prevents duplicate fields, ignored extensions
    // and alternate spellings from becoming unreviewed wire-format variants.
    let canonical = serde_json::to_vec(&header).map_err(|_| invalid("invalid capsule header"))?;
    if canonical != metadata { return Err(invalid("noncanonical capsule header")); }
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
    let conditions = Resolver::canonical_conditions(header.options.conditions.as_deref().unwrap_or(&[]))?;
    if header.options.conditions.as_ref().is_some_and(|c| c != &conditions) {
        return Err(invalid("capsule conditions are not canonical"));
    }
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
            if !matches!(input.content, Content::Directory) { return Err(invalid("capsule root must be a directory")); }
        } else {
            validate_path(&input.path)?;
            if !entries.get(parent(&input.path)).is_some_and(|e| e.is_dir()) {
                return Err(invalid("observation has no captured physical parent directory"));
            }
        }
        let entry = match &input.content {
            Content::Missing => Entry::Missing,
            Content::Directory => Entry::Directory(None),
            Content::File { bytes, sha256 } => {
                let cap = if input.path.rsplit('/').next() == Some("package.json") {
                    super::super::super::package_targets::MAX_MANIFEST_BYTES
                } else { MAX_FILE };
                if *bytes > cap { return Err(limit()); }
                let end = offset.checked_add(*bytes).ok_or_else(limit)?;
                let source = payload.get(offset..end).ok_or_else(|| invalid("truncated capsule payload"))?;
                if !valid_digest(sha256) || hex::encode(Sha256::digest(source)) != *sha256 {
                    return Err(invalid("captured file digest mismatch"));
                }
                offset = end;
                captured = captured.checked_add(source.len()).ok_or_else(limit)?;
                if captured > MAX_CAPTURE { return Err(limit()); }
                Entry::File { bytes: source.to_vec(), sha256: sha256.clone() }
            }
            Content::Symlink { target, sha256 } => {
                if header.options.symlink_policy != super::SymlinkPolicy::Contained {
                    return Err(invalid("symlink observation violates the captured policy"));
                }
                validate_link_target(target)?;
                if !valid_digest(sha256) || hex::encode(Sha256::digest(target.as_bytes())) != *sha256 {
                    return Err(invalid("captured link digest mismatch"));
                }
                captured = captured.checked_add(target.len()).ok_or_else(limit)?;
                if captured > MAX_CAPTURE { return Err(limit()); }
                Entry::Symlink { target: target.clone(), sha256: sha256.clone() }
            }
        };
        entries.insert(input.path.clone(), Rc::new(entry));
    }
    if !entries.get("").is_some_and(|e| e.is_dir()) || offset != payload.len() {
        return Err(invalid("missing capsule root or unclaimed payload bytes"));
    }
    Ok(Resolver { entries, manifests: BTreeMap::new(), captured, conditions,
        mappings: Vec::new(), symlink_policy: header.options.symlink_policy,
        sealed: true, observed: BTreeSet::new() })
}

/// Verify an independently obtained capsule pin, then rerun the actual graph
/// builder entirely against its recorded inputs. No project path is accepted;
/// no directories/files/links are created, opened or extracted during replay.
/// An unrecorded probe is fatal, never invented as a missing file or read from
/// the current machine. Incomplete analysis is reproduced, not upgraded.
pub fn replay(bytes: &[u8], expected_capsule_hash: &str) -> Result<CapturedModuleGraph> {
    if !valid_hash(expected_capsule_hash) {
        return Err(error("ERR_MODULE_CAPSULE_PIN_INVALID", "expected capsule hash must be sha256: plus 64 lowercase hexadecimal digits"));
    }
    if bytes.len() > MAX_CAPSULE_BYTES { return Err(limit()); }
    if digest(bytes) != expected_capsule_hash {
        return Err(error("ERR_MODULE_CAPSULE_PIN_MISMATCH", "capsule bytes do not match the independently supplied pin"));
    }
    let (header, payload) = parse_frame(bytes)?;
    let resolver = recorded_resolver(&header, payload)?;
    let graph = build(resolver, &header.entrypoint, header.options)?;
    if graph.report.input_hash != header.graph_hash || graph.report.probes.len() != graph.inputs.len() {
        return Err(error("ERR_MODULE_CAPSULE_REPLAY_MISMATCH", "recomputed analysis differs from the captured graph or leaves unused observations"));
    }
    Ok(graph)
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::{EdgeState, ModuleId, capture};
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
        replay(bytes, &digest(bytes)).err().expect("must reject capsule").code.into()
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
            assert_eq!(graph.source_bytes(&module.id), replayed.source_bytes(&module.id));
        }
        let encoded_again = encode(&replayed).unwrap();
        assert_eq!(encoded_again.bytes(), capsule.bytes());
        assert_eq!(encoded_again.digest(), capsule.digest());
        assert!(replayed.inputs.values().all(|e| !matches!(e.as_ref(), Entry::Directory(Some(_)))));
    }

    #[test]
    fn incomplete_graph_preserves_missing_builtin_computed_and_parse_failures() {
        let root = tempfile::tempdir().unwrap();
        put(root.path(), "app.mjs", "import 'node:fs'; import './missing.mjs'; import './broken.mjs'; import(choice);");
        put(root.path(), "broken.mjs", "export const = ;");
        let graph = capture(root.path(), "app.mjs", GraphOptions::default()).unwrap();
        let capsule = encode(&graph).unwrap();
        put(root.path(), "missing.mjs", "export const nowExists=1;");
        let replayed = replay(capsule.bytes(), capsule.digest()).unwrap();
        assert_eq!(graph.report(), replayed.report());
        assert!(!replayed.report().fully_resolved);
        for state in [EdgeState::Unresolved, EdgeState::RuntimeRequired, EdgeState::NonLiteral] {
            assert!(replayed.report().edges.iter().any(|e| e.state == state));
        }
    }

    #[test]
    fn capsule_retains_consulted_manifests_links_and_negative_probes() {
        let root = tempfile::tempdir().unwrap();
        put(root.path(), "app.mjs", "import 'linked';");
        put(root.path(), "pkg/package.json", r#"{"exports":"./index.mjs"}"#);
        put(root.path(), "pkg/index.mjs", "export const n=1;");
        std::fs::create_dir(root.path().join("node_modules")).unwrap();
        std::os::unix::fs::symlink("../pkg", root.path().join("node_modules/linked")).unwrap();
        let graph = capture(root.path(), "app.mjs", GraphOptions {
            symlink_policy: super::super::SymlinkPolicy::Contained, conditions: None,
        }).unwrap();
        let capsule = encode(&graph).unwrap();
        put(root.path(), "pkg/package.json", r#"{"exports":null}"#);
        let replayed = replay(capsule.bytes(), capsule.digest()).unwrap();
        assert_eq!(graph.report(), replayed.report());
        assert!(replayed.report().probes.iter().any(|p| p.link_target.as_deref() == Some("../pkg")));
    }

    #[test]
    fn binary_unanalyzable_sources_are_retained_without_serialized_source_reports() {
        let root = tempfile::tempdir().unwrap();
        put(root.path(), "app.mjs", b"\xff\x00private_source");
        let graph = capture(root.path(), "app.mjs", GraphOptions::default()).unwrap();
        let capsule = encode(&graph).unwrap();
        let replayed = replay(capsule.bytes(), capsule.digest()).unwrap();
        assert_eq!(graph.report(), replayed.report());
        assert_eq!(replayed.source_bytes(&ModuleId { path: "app.mjs".into(), url_suffix: String::new() }),
            Some(&b"\xff\x00private_source"[..]));
        assert!(!serde_json::to_string(replayed.report()).unwrap().contains("private_source"));
    }

    #[test]
    fn typescript_erased_dependencies_and_url_instances_replay_without_extra_reads() {
        let root = tempfile::tempdir().unwrap();
        put(root.path(), "app.ts", "import type X from '../unread'; import './dep.mts?a'; import './dep.mts?b';");
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
        assert_eq!(replay(malformed, "sha256:bad").err().unwrap().code, "ERR_MODULE_CAPSULE_PIN_INVALID");
        assert_eq!(replay(malformed, &format!("sha256:{}", "0".repeat(64))).err().unwrap().code,
            "ERR_MODULE_CAPSULE_PIN_MISMATCH");
        assert_eq!(failure(malformed), "ERR_MODULE_CAPSULE_INVALID");
    }

    #[test]
    fn payload_corruption_is_rejected_even_with_a_new_outer_pin() {
        let root = tempfile::tempdir().unwrap();
        let capsule = encode(&simple(root.path())).unwrap();
        let mut corrupted = capsule.bytes().to_vec();
        *corrupted.last_mut().unwrap() ^= 1;
        assert_eq!(replay(&corrupted, capsule.digest()).err().unwrap().code, "ERR_MODULE_CAPSULE_PIN_MISMATCH");
        assert_eq!(failure(&corrupted), "ERR_MODULE_CAPSULE_INVALID");
    }

    #[test]
    fn supplied_report_hash_is_recomputed_not_trusted() {
        let root = tempfile::tempdir().unwrap();
        let capsule = encode(&simple(root.path())).unwrap();
        let corrupted = modify(&capsule, |h| h.graph_hash = format!("sha256:{}", "0".repeat(64)));
        assert_eq!(failure(&corrupted), "ERR_MODULE_CAPSULE_REPLAY_MISMATCH");
    }

    #[test]
    fn omitted_negative_probe_is_not_invented_or_recovered_from_host() {
        let root = tempfile::tempdir().unwrap();
        put(root.path(), "app.js", "export const value=1;");
        let graph = capture(root.path(), "app.js", GraphOptions::default()).unwrap();
        let capsule = encode(&graph).unwrap();
        assert!(graph.report().probes.iter().any(|p| p.path == "package.json"));
        let omitted = modify(&capsule, |h| h.inputs.retain(|i| i.path != "package.json"));
        assert_eq!(failure(&omitted), "ERR_MODULE_CAPSULE_INPUT_MISSING");
    }

    #[test]
    fn unused_extra_observations_are_not_accepted_as_replayed_evidence() {
        let root = tempfile::tempdir().unwrap();
        let capsule = encode(&simple(root.path())).unwrap();
        let extra = modify(&capsule, |h| h.inputs.push(Input { path: "zz-unused".into(), content: Content::Missing }));
        assert_eq!(failure(&extra), "ERR_MODULE_CAPSULE_REPLAY_MISMATCH");
    }

    #[test]
    fn invalid_roots_duplicate_paths_and_nonphysical_parentage_fail_closed() {
        let root = tempfile::tempdir().unwrap();
        let capsule = encode(&simple(root.path())).unwrap();
        assert_eq!(failure(&modify(&capsule, |h| h.inputs[0].content = Content::Missing)), "ERR_MODULE_CAPSULE_INVALID");
        assert_eq!(failure(&modify(&capsule, |h| h.inputs[1].path = String::new())), "ERR_MODULE_CAPSULE_INVALID");
        assert_eq!(failure(&modify(&capsule, |h| h.inputs.push(Input { path: "zz/sub".into(), content: Content::Missing }))),
            "ERR_MODULE_CAPSULE_INVALID");
        assert!(failure(&modify(&capsule, |h| h.entrypoint = "../outside".into())).starts_with("ERR_"));
    }

    #[test]
    fn truncation_trailing_bytes_and_unknown_schema_fail_closed() {
        let root = tempfile::tempdir().unwrap();
        let capsule = encode(&simple(root.path())).unwrap();
        assert_eq!(failure(&capsule.bytes()[..10]), "ERR_MODULE_CAPSULE_INVALID");
        assert_eq!(failure(&capsule.bytes()[..capsule.bytes().len()-1]), "ERR_MODULE_CAPSULE_INVALID");
        let mut trailing = capsule.bytes().to_vec(); trailing.push(0);
        assert_eq!(failure(&trailing), "ERR_MODULE_CAPSULE_INVALID");
        assert_eq!(failure(&modify(&capsule, |h| h.schema_version = "future".into())), "ERR_MODULE_CAPSULE_INVALID");
    }

    #[test]
    fn declared_file_and_header_bounds_are_enforced_before_allocation() {
        let root = tempfile::tempdir().unwrap();
        let capsule = encode(&simple(root.path())).unwrap();
        let huge = modify(&capsule, |h| {
            let input = h.inputs.iter_mut().find(|i| matches!(i.content, Content::File { .. })).unwrap();
            if let Content::File { bytes, .. } = &mut input.content { *bytes = usize::MAX; }
        });
        assert_eq!(failure(&huge), "ERR_MODULE_CAPSULE_LIMIT");
        let mut header = MAGIC.to_vec(); header.extend_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(failure(&header), "ERR_MODULE_CAPSULE_LIMIT");
    }

    #[test]
    fn capsule_identity_is_relocation_stable_but_binds_conditions_and_transitive_bytes() {
        let a = tempfile::tempdir().unwrap(); let b = tempfile::tempdir().unwrap();
        let first = encode(&simple(a.path())).unwrap(); let second = encode(&simple(b.path())).unwrap();
        assert_eq!(first.bytes(), second.bytes());
        let changed_options = capture(a.path(), "app.mjs", GraphOptions { conditions: Some(vec!["custom".into()]),
            ..GraphOptions::default() }).unwrap();
        assert_ne!(first.digest(), encode(&changed_options).unwrap().digest());
        put(a.path(), "dep.mjs", "export const n=2;");
        let changed_source = capture(a.path(), "app.mjs", GraphOptions::default()).unwrap();
        assert_ne!(first.digest(), encode(&changed_source).unwrap().digest());
    }
}
