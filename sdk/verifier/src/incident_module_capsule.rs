//! Independent byte-integrity inspection of the public FNSGCAP1 wire format.
//!
//! The capsule digest is authenticated by the enclosing incident bundle or the
//! publisher's signed registration manifest. This
//! reader checks the capsule and all its recorded bytes without opening paths,
//! extracting files, importing product code or evaluating JavaScript. The graph
//! hash is bound to the signed capture, but is NOT recomputed here: completeness,
//! resolution semantics, selected conditions and native replay still require the
//! product's graph reconstruction and execution checks. Metadata-only file
//! observations bind recorded existence, without admitting file contents or
//! supplying source bytes to execution.

use base64::Engine as _;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

use super::{MAX_PAYLOAD_BYTES, Result, ct_str_eq, exact, invalid, text};

const FIELD: &str = ".payload.module_sources";
const MAGIC: &[u8; 8] = b"FNSGCAP1";
const PREFIX_BYTES: usize = 12;
const SCHEMA: &str = "franken-node/module-source-capsule/v1";
const HASH_DOMAIN: &[u8] = b"franken-node/module-source-capsule/v1\0";
const MAX_HEADER_BYTES: usize = 8 * 1024 * 1024;
const MAX_INPUTS: usize = 1024;
const MAX_PATH_BYTES: usize = 4096;
const MAX_PATH_DEPTH: usize = 64;
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

#[derive(Clone, Serialize, Deserialize)]
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

/// The caller authenticates and bounds these bytes before inspection. Incident
/// verification additionally supplies its separately captured graph commitment.
pub(crate) fn inspect_authenticated(bytes: &[u8]) -> Result<SourceCapsuleSummary> {
    verify_frame(bytes, None)
}

fn verify_frame(bytes: &[u8], graph_hash: Option<&str>) -> Result<SourceCapsuleSummary> {
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
    Ok(SourceCapsuleSummary {
        schema_version: header.schema_version,
        graph_input_hash: header.graph_hash,
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
    })
}

pub(super) fn verify(value: &Value) -> Result<()> {
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
    verify_frame(&bytes, Some(graph_hash)).map(|_| ())
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

    pub(crate) fn producer_sources() -> Value {
        producer_vectors()[0]["module_sources"].clone()
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
