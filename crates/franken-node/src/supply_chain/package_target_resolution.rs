//! Ordered, captured package exports/imports target selection.
//!
//! Implements the package-map selection boundary from Node's ESM resolution
//! specification, not filesystem resolution or module execution. In particular,
//! external imports targets still require package lookup, and a selected local
//! target still requires existence, realpath, format and policy checks.
//!
//! Spec: https://nodejs.org/api/esm.html#resolution-algorithm-specification
//! Fixtures compare against Node's public resolvers, never its implementation.

use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fmt;

pub const MAX_MANIFEST_BYTES: usize = 512 * 1024;
const MAX_MEMBERS: usize = 4096;
const MAX_NODES: usize = 65_536;
const MAX_DEPTH: usize = 64;
const MAX_SPECIFIER_BYTES: usize = 4096;
const MAX_TARGET_BYTES: usize = 16_384;
const INPUT_DOMAIN: &[u8] = b"franken-node/package-map-input/v1\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MapKind {
    Exports,
    Imports,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetKind {
    PackageRelative,
    ExternalPackage,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum BranchStep {
    Condition(String),
    ArrayIndex(usize),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Selection {
    pub target: String,
    pub target_kind: TargetKind,
    pub matched_key: String,
    pub branch: Vec<BranchStep>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ResolutionError {
    pub code: &'static str,
    pub detail: String,
}

impl fmt::Display for ResolutionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.detail)
    }
}

impl std::error::Error for ResolutionError {}

type Result<T> = std::result::Result<T, ResolutionError>;

fn error(code: &'static str, detail: impl Into<String>) -> ResolutionError {
    ResolutionError { code, detail: detail.into() }
}

fn config(detail: impl Into<String>) -> ResolutionError {
    error("ERR_INVALID_PACKAGE_CONFIG", detail)
}

fn bound() -> ResolutionError {
    error("ERR_PACKAGE_MAP_LIMIT", "package-map deterministic resource limit exceeded")
}

/// Ordinary serde_json::Value may sort object keys, which changes conditional
/// exports semantics. Preserve source order without depending on a Cargo feature
/// selected by unrelated downstream users. Duplicate keys are refused, including
/// duplicates spelled using JSON escapes, rather than silently overwritten.
#[derive(Clone)]
enum OrderedValue {
    Null,
    String(String),
    Array(Vec<Self>),
    Object(Vec<(String, Self)>),
    Invalid,
}

impl<'de> Deserialize<'de> for OrderedValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        struct OrderedVisitor;
        impl<'de> Visitor<'de> for OrderedVisitor {
            type Value = OrderedValue;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("bounded JSON with unique object keys")
            }
            fn visit_unit<E: de::Error>(self) -> std::result::Result<Self::Value, E> {
                Ok(OrderedValue::Null)
            }
            fn visit_bool<E: de::Error>(self, _: bool) -> std::result::Result<Self::Value, E> {
                Ok(OrderedValue::Invalid)
            }
            fn visit_i64<E: de::Error>(self, _: i64) -> std::result::Result<Self::Value, E> {
                Ok(OrderedValue::Invalid)
            }
            fn visit_u64<E: de::Error>(self, _: u64) -> std::result::Result<Self::Value, E> {
                Ok(OrderedValue::Invalid)
            }
            fn visit_f64<E: de::Error>(self, _: f64) -> std::result::Result<Self::Value, E> {
                Ok(OrderedValue::Invalid)
            }
            fn visit_str<E: de::Error>(self, value: &str) -> std::result::Result<Self::Value, E> {
                Ok(OrderedValue::String(value.to_owned()))
            }
            fn visit_string<E: de::Error>(self, value: String) -> std::result::Result<Self::Value, E> {
                Ok(OrderedValue::String(value))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut input: A) -> std::result::Result<Self::Value, A::Error> {
                let mut values = Vec::new();
                while let Some(value) = input.next_element()? {
                    if values.len() == MAX_MEMBERS {
                        return Err(de::Error::custom("package-map array member limit exceeded"));
                    }
                    values.push(value);
                }
                Ok(OrderedValue::Array(values))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut input: A) -> std::result::Result<Self::Value, A::Error> {
                let mut values = Vec::new();
                let mut seen = BTreeSet::new();
                while let Some(key) = input.next_key::<String>()? {
                    if values.len() == MAX_MEMBERS {
                        return Err(de::Error::custom("package-map object member limit exceeded"));
                    }
                    if !seen.insert(key.clone()) {
                        return Err(de::Error::custom("duplicate package JSON key"));
                    }
                    values.push((key, input.next_value()?));
                }
                Ok(OrderedValue::Object(values))
            }
        }
        deserializer.deserialize_any(OrderedVisitor)
    }
}

/// One immutable manifest capture. No caller can replace its maps after pinning.
/// Debug intentionally does not dump package metadata or private import targets.
#[derive(Clone)]
pub struct PackageMap {
    exports: Option<OrderedValue>,
    imports: Option<OrderedValue>,
    input_hash: String,
}

impl fmt::Debug for PackageMap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PackageMap").field("input_hash", &self.input_hash).finish_non_exhaustive()
    }
}

impl PackageMap {
    pub fn parse(source: &str) -> Result<Self> {
        if source.len() > MAX_MANIFEST_BYTES { return Err(bound()); }
        let document: OrderedValue = serde_json::from_str(source).map_err(|e| config(e.to_string()))?;
        let mut pending = vec![(&document, 0_usize)];
        let mut count = 0_usize;
        while let Some((value, depth)) = pending.pop() {
            count += 1;
            if count > MAX_NODES || depth > MAX_DEPTH { return Err(bound()); }
            match value {
                OrderedValue::Object(members) => pending.extend(members.iter().map(|(_, v)| (v, depth + 1))),
                OrderedValue::Array(values) => pending.extend(values.iter().map(|v| (v, depth + 1))),
                _ => {}
            }
        }
        let OrderedValue::Object(members) = document else { return Err(config("manifest must be an object")); };
        let mut exports = None;
        let mut imports = None;
        for (key, value) in members {
            match key.as_str() {
                "exports" => exports = Some(value),
                "imports" => imports = Some(value),
                _ => {}
            }
        }
        let mut hash = Sha256::new();
        hash.update(INPUT_DOMAIN);
        hash.update((source.len() as u64).to_le_bytes());
        hash.update(source.as_bytes());
        Ok(Self { exports, imports, input_hash: format!("sha256:{}", hex::encode(hash.finalize())) })
    }

    /// Exact manifest-input identity, NOT the older lossy graph projection hash.
    /// Whitespace changes also change this pin. Query conditions remain explicit.
    pub fn input_hash(&self) -> &str { &self.input_hash }

    pub fn select(&self, kind: MapKind, specifier: &str, conditions: &[String]) -> Result<Selection> {
        if specifier.is_empty() || specifier.len() > MAX_SPECIFIER_BYTES || specifier.chars().any(char::is_control) {
            return Err(error("ERR_INVALID_MODULE_SPECIFIER", "invalid or oversized package-map request"));
        }
        if conditions.len() > 64 || conditions.iter().any(|c| c.is_empty() || c.len() > 128 || c.chars().any(char::is_control)) {
            return Err(error("ERR_INVALID_PACKAGE_CONDITIONS", "conditions must be bounded nonempty strings"));
        }
        let active: BTreeSet<_> = conditions.iter().map(String::as_str).collect();
        let missing = match kind {
            MapKind::Exports => "ERR_PACKAGE_PATH_NOT_EXPORTED",
            MapKind::Imports => "ERR_PACKAGE_IMPORT_NOT_DEFINED",
        };
        let (key, target, pattern) = match kind {
            MapKind::Exports => {
                if specifier != "." && !specifier.starts_with("./") {
                    return Err(error("ERR_INVALID_MODULE_SPECIFIER", "export request must be . or a ./ subpath"));
                }
                let exports = match &self.exports {
                    None | Some(OrderedValue::Null) => return Err(error("ERR_PACKAGE_MAP_ABSENT", "no exports map; legacy main resolution is outside this selector")),
                    Some(value) => value,
                };
                match exports {
                    OrderedValue::Object(members) => {
                        let paths = members.iter().filter(|(key, _)| key.starts_with('.')).count();
                        if paths != 0 && paths != members.len() {
                            return Err(config("exports cannot mix condition and subpath keys"));
                        }
                        if paths == 0 && specifier == "." { (".", exports, None) }
                        else if paths != 0 { match_map(members, specifier).ok_or_else(|| error(missing, "subpath has no export mapping"))? }
                        else { return Err(error(missing, "main-only exports do not expose this subpath")); }
                    }
                    OrderedValue::String(_) | OrderedValue::Array(_) if specifier == "." => (".", exports, None),
                    _ => return Err(error(missing, "subpath has no export mapping")),
                }
            }
            MapKind::Imports => {
                if !specifier.starts_with('#') || specifier == "#" || specifier.starts_with("#/") {
                    return Err(error("ERR_INVALID_MODULE_SPECIFIER", "import request must be a nonempty # name"));
                }
                let Some(OrderedValue::Object(members)) = &self.imports else {
                    return Err(error(missing, "no imports mapping for this request"));
                };
                match_map(members, specifier).ok_or_else(|| error(missing, "request has no import mapping"))?
            }
        };
        let mut branch = Vec::new();
        match select_target(target, pattern, kind, &active, &mut branch)? {
            Resolved::Target(target, target_kind, branch) => Ok(Selection {
                target, target_kind, matched_key: key.to_owned(), branch,
            }),
            Resolved::Blocked => Err(error(missing, "selected mapping explicitly blocks this request")),
            Resolved::Unmatched => Err(error(missing, "no active condition selects a target")),
        }
    }
}

fn match_map<'a>(members: &'a [(String, OrderedValue)], request: &'a str) -> Option<(&'a str, &'a OrderedValue, Option<&'a str>)> {
    if !request.contains('*') && !request.ends_with('/') {
        if let Some((key, target)) = members.iter().find(|(key, _)| key == request) {
            return Some((key, target, None));
        }
    }
    let mut best = None;
    let mut rank = (0, 0);
    for (key, target) in members {
        let Some((prefix, suffix)) = key.split_once('*') else { continue; };
        if suffix.contains('*') || !request.starts_with(prefix) || !request.ends_with(suffix)
            || request.len() <= prefix.len() + suffix.len() { continue; }
        let candidate_rank = (prefix.encode_utf16().count() + 1, key.encode_utf16().count());
        if best.is_none() || candidate_rank > rank {
            rank = candidate_rank;
            best = Some((key.as_str(), target, Some(&request[prefix.len()..request.len() - suffix.len()])));
        }
    }
    best
}

enum Resolved {
    Target(String, TargetKind, Vec<BranchStep>),
    Blocked,
    Unmatched,
}

fn is_array_index(key: &str) -> bool {
    key.parse::<u32>().is_ok_and(|value| value != u32::MAX && value.to_string() == key)
}

fn select_target(target: &OrderedValue, pattern: Option<&str>, kind: MapKind,
    active: &BTreeSet<&str>, branch: &mut Vec<BranchStep>) -> Result<Resolved> {
    match target {
        OrderedValue::Null => Ok(Resolved::Blocked),
        OrderedValue::Invalid => Err(error("ERR_INVALID_PACKAGE_TARGET", "target must be a string, condition object, array or null")),
        OrderedValue::String(value) => {
            let target_kind = if value.starts_with("./") {
                validate_segments(&value[2..], "ERR_INVALID_PACKAGE_TARGET")?;
                TargetKind::PackageRelative
            } else {
                if kind != MapKind::Imports || !external_package_request(value) {
                    return Err(error("ERR_INVALID_PACKAGE_TARGET", "exports targets must start with ./; imports may select an external package request"));
                }
                TargetKind::ExternalPackage
            };
            let result = if let Some(matched) = pattern {
                validate_segments(matched, "ERR_INVALID_MODULE_SPECIFIER")?;
                let size = value.len().checked_add(value.matches('*').count().checked_mul(matched.len()).ok_or_else(bound)?).ok_or_else(bound)?;
                if size > MAX_TARGET_BYTES { return Err(bound()); }
                value.replace('*', matched)
            } else { value.clone() };
            if result.len() > MAX_TARGET_BYTES { return Err(bound()); }
            Ok(Resolved::Target(result, target_kind, branch.clone()))
        }
        OrderedValue::Object(members) => {
            if members.iter().any(|(key, _)| is_array_index(key)) {
                return Err(config("numeric condition keys are not permitted"));
            }
            for (condition, value) in members {
                if condition == "default" || active.contains(condition.as_str()) {
                    branch.push(BranchStep::Condition(condition.clone()));
                    let result = select_target(value, pattern, kind, active, branch);
                    branch.pop();
                    match result? {
                        Resolved::Unmatched => {}
                        selected => return Ok(selected),
                    }
                }
            }
            Ok(Resolved::Unmatched)
        }
        OrderedValue::Array(values) => {
            // An empty array is an explicit block. A nonempty array whose
            // branches are all inactive is instead unmatched, allowing the
            // enclosing condition object to try its next eligible property.
            // Later unmatched branches must not erase an earlier null/error.
            let mut fallback = Ok(if values.is_empty() { Resolved::Blocked }
                else { Resolved::Unmatched });
            for (index, value) in values.iter().enumerate() {
                branch.push(BranchStep::ArrayIndex(index));
                let result = select_target(value, pattern, kind, active, branch);
                branch.pop();
                match result {
                    Ok(Resolved::Target(target, kind, path)) => return Ok(Resolved::Target(target, kind, path)),
                    Ok(Resolved::Blocked) => fallback = Ok(Resolved::Blocked),
                    Ok(Resolved::Unmatched) => {}
                    Err(e) if e.code == "ERR_INVALID_PACKAGE_TARGET" => fallback = Err(e),
                    Err(e) => return Err(e),
                }
            }
            fallback
        }
    }
}

fn external_package_request(value: &str) -> bool {
    if value.is_empty() || value.starts_with(['.', '/', '#', '\\']) || value.contains([':', '%', '\\'])
        || value.chars().any(char::is_control) { return false; }
    let mut parts = value.split('/');
    let name = parts.next().unwrap_or_default();
    if name.starts_with('@') && (name.len() == 1 || parts.next().is_none_or(str::is_empty)) { return false; }
    !value.split('/').any(|part| part.is_empty() || part == "." || part == ".." || part.eq_ignore_ascii_case("node_modules"))
}

/// Never normalize a traversal into a seemingly safe target. Query/fragment
/// bytes are retained as URL suffixes; they are not filesystem path components.
fn validate_segments(value: &str, code: &'static str) -> Result<()> {
    if value.contains('\\') || value.chars().any(char::is_control) {
        return Err(error(code, "backslashes and control characters are not supported in package targets"));
    }
    let path = value.split(['?', '#']).next().unwrap_or_default();
    for part in path.split('/') {
        let mut decoded = Vec::new();
        let mut bytes = part.bytes();
        while let Some(byte) = bytes.next() {
            if byte == b'%' {
                let high = bytes.next().and_then(|b| char::from(b).to_digit(16));
                let low = bytes.next().and_then(|b| char::from(b).to_digit(16));
                let (Some(high), Some(low)) = (high, low) else { return Err(error(code, "invalid percent encoding")); };
                let byte = (high * 16 + low) as u8;
                if matches!(byte, b'/' | b'\\' | 0) { return Err(error("ERR_INVALID_MODULE_SPECIFIER", "encoded separators or NUL are not permitted")); }
                decoded.push(byte);
            } else { decoded.push(byte); }
        }
        if decoded == b"." || decoded == b".." || decoded.eq_ignore_ascii_case(b"node_modules") {
            return Err(error(code, "package target contains a forbidden path segment"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn select(source: &str, kind: MapKind, request: &str, conditions: &[&str]) -> Result<Selection> {
        PackageMap::parse(source)?.select(kind, request, &conditions.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>())
    }

    #[test]
    fn insertion_order_not_alphabetical_order_controls_condition_selection() {
        let first = r#"{"exports":{"node":"./native.js","default":"./fallback.js"}}"#;
        let second = r#"{"exports":{"default":"./fallback.js","node":"./native.js"}}"#;
        assert_eq!(select(first, MapKind::Exports, ".", &["node"]).unwrap().target, "./native.js");
        assert_eq!(select(second, MapKind::Exports, ".", &["node"]).unwrap().target, "./fallback.js");
        assert_ne!(PackageMap::parse(first).unwrap().input_hash(), PackageMap::parse(second).unwrap().input_hash());
    }

    #[test]
    fn nested_conditions_continue_only_when_a_branch_is_unmatched() {
        let source = r#"{"exports":{"node":{"import":"./esm.js","require":"./cjs.cjs"},"default":"./other.js"}}"#;
        let result = select(source, MapKind::Exports, ".", &["require","node"]).unwrap();
        assert_eq!(result.target, "./cjs.cjs");
        assert_eq!(result.branch, [BranchStep::Condition("node".into()), BranchStep::Condition("require".into())]);
        assert_eq!(select(source, MapKind::Exports, ".", &["node"]).unwrap().target, "./other.js");
        assert_eq!(select(r#"{"exports":{"node":null,"default":"./other.js"}}"#, MapKind::Exports, ".", &["node"]).unwrap_err().code, "ERR_PACKAGE_PATH_NOT_EXPORTED");
    }

    #[test]
    fn exact_paths_and_longest_pattern_prefix_then_suffix_win() {
        let source = r#"{"exports":{"./*":"./wide/*.js","./feature/*":"./feature/*.js","./feature/*.json":"./json/*.json","./feature/private/*":null,"./feature/exact":"./exact.js"}}"#;
        for (request, target) in [("./feature/exact","./exact.js"), ("./feature/a.json","./json/a.json"), ("./feature/a/b","./feature/a/b.js"), ("./z","./wide/z.js")] {
            assert_eq!(select(source, MapKind::Exports, request, &[]).unwrap().target, target);
        }
        assert_eq!(select(source, MapKind::Exports, "./feature/private/a", &[]).unwrap_err().code, "ERR_PACKAGE_PATH_NOT_EXPORTED");
    }

    #[test]
    fn arrays_skip_invalid_targets_null_and_unmatched_but_not_invalid_configs() {
        let result = select(r#"{"exports":["../invalid",null,{"browser":"./browser.js"},"./ok.js"]}"#, MapKind::Exports, ".", &["node"]).unwrap();
        assert_eq!(result.target, "./ok.js");
        assert_eq!(result.branch, [BranchStep::ArrayIndex(3)]);
        assert_eq!(select(r#"{"exports":[null,"../bad"]}"#, MapKind::Exports, ".", &[]).unwrap_err().code, "ERR_INVALID_PACKAGE_TARGET");
        assert_eq!(select(r#"{"exports":["../bad",null]}"#, MapKind::Exports, ".", &[]).unwrap_err().code, "ERR_PACKAGE_PATH_NOT_EXPORTED");
        assert_eq!(select(r#"{"exports":[{"0":"./bad.js"},"./ok.js"]}"#, MapKind::Exports, ".", &[]).unwrap_err().code, "ERR_INVALID_PACKAGE_CONFIG");
    }

    #[test]
    fn selected_missing_file_is_not_an_array_fallback_or_a_filesystem_probe() {
        assert_eq!(select(r#"{"exports":["./missing.js","./existing.js"]}"#, MapKind::Exports, ".", &[]).unwrap().target, "./missing.js");
    }

    #[test]
    fn inactive_arrays_allow_enclosing_conditions_to_continue_without_stale_witnesses() {
        for array in [r#"[{"browser":"./browser.js"}]"#,
            r#"[[{"browser":"./browser.js"}],{"custom":"./custom.js"}]"#,
            r#"[{},{}]"#] {
            for (kind, field, request) in [(MapKind::Exports, "exports", "."),
                (MapKind::Imports, "imports", "#local")] {
                let target = format!(r#"{{"node":{array},"default":"./fallback.js"}}"#);
                let target = if kind == MapKind::Imports { format!(r##"{{"#local":{target}}}"##) }
                    else { target };
                let source = format!(r#"{{"{field}":{target}}}"#);
                let result = select(&source, kind, request, &["node"]).unwrap();
                assert_eq!(result.target, "./fallback.js", "{source}");
                assert_eq!(result.branch, [BranchStep::Condition("default".into())]);
            }
        }
    }

    #[test]
    fn inactive_array_branches_do_not_erase_explicit_blocks_or_invalid_targets() {
        for (array, code) in [("[]", "ERR_PACKAGE_PATH_NOT_EXPORTED"),
            (r#"[null,{"browser":"./b.js"}]"#, "ERR_PACKAGE_PATH_NOT_EXPORTED"),
            (r#"[[],{"browser":"./b.js"}]"#, "ERR_PACKAGE_PATH_NOT_EXPORTED"),
            (r#"["../bad",{"browser":"./b.js"}]"#, "ERR_INVALID_PACKAGE_TARGET"),
            (r#"["../bad",null,{"browser":"./b.js"}]"#, "ERR_PACKAGE_PATH_NOT_EXPORTED")] {
            let source = format!(r#"{{"exports":{{"node":{array},"default":"./fallback.js"}}}}"#);
            assert_eq!(select(&source, MapKind::Exports, ".", &["node"]).unwrap_err().code, code, "{source}");
        }
    }

    #[test]
    fn imports_keep_local_and_external_targets_distinct() {
        let source = r##"{"imports":{"#local/*":"./src/*.js","#dep":{"node":"@scope/dep/sub","default":"./shim.js"},"#private":null}}"##;
        assert_eq!(select(source, MapKind::Imports, "#local/a", &[]).unwrap().target, "./src/a.js");
        let external = select(source, MapKind::Imports, "#dep", &["node"]).unwrap();
        assert_eq!(external.target, "@scope/dep/sub");
        assert_eq!(external.target_kind, TargetKind::ExternalPackage);
        assert_eq!(select(source, MapKind::Imports, "#private", &[]).unwrap_err().code, "ERR_PACKAGE_IMPORT_NOT_DEFINED");
    }

    #[test]
    fn raw_and_encoded_traversal_and_dependency_segments_are_refused() {
        for target in ["../escape.js", "/absolute.js", "./a/../escape.js", "./%2e%2e/x", "./node_modules/x", "./%6eode_modules/x", "./a\\b"] {
            let source = serde_json::json!({"exports":target}).to_string();
            assert!(select(&source, MapKind::Exports, ".", &[]).is_err(), "{target}");
        }
        for request in ["./../x", "./%2e%2e/x", "./NODE_MODULES/x", "./a%2fb"] {
            assert_eq!(select(r#"{"exports":{"./*":"./src/*"}}"#, MapKind::Exports, request, &[]).unwrap_err().code, "ERR_INVALID_MODULE_SPECIFIER");
        }
    }

    #[test]
    fn duplicate_keys_and_mixed_export_maps_are_not_silently_reinterpreted() {
        for source in [r#"{"exports":"./a","exports":"./b"}"#, r#"{"exports":{"node":"./a","n\u006fde":"./b"}}"#, "[]", "{", "{} trailing"] {
            assert_eq!(PackageMap::parse(source).unwrap_err().code, "ERR_INVALID_PACKAGE_CONFIG");
        }
        assert_eq!(select(r#"{"exports":{".":"./a","default":"./b"}}"#, MapKind::Exports, ".", &[]).unwrap_err().code, "ERR_INVALID_PACKAGE_CONFIG");
    }

    #[test]
    fn missing_maps_unexported_subpaths_and_invalid_import_requests_are_distinct() {
        assert_eq!(select("{}", MapKind::Exports, ".", &[]).unwrap_err().code, "ERR_PACKAGE_MAP_ABSENT");
        assert_eq!(select(r#"{"exports":null}"#, MapKind::Exports, ".", &[]).unwrap_err().code, "ERR_PACKAGE_MAP_ABSENT");
        assert_eq!(select("{}", MapKind::Imports, "#x", &[]).unwrap_err().code, "ERR_PACKAGE_IMPORT_NOT_DEFINED");
        assert_eq!(select(r#"{"exports":"./index.js"}"#, MapKind::Exports, "./private", &[]).unwrap_err().code, "ERR_PACKAGE_PATH_NOT_EXPORTED");
        for request in ["#", "#/bad", "bare", ""] {
            assert_eq!(select("{}", MapKind::Imports, request, &[]).unwrap_err().code, "ERR_INVALID_MODULE_SPECIFIER");
        }
    }

    #[test]
    fn wildcard_substitution_is_literal_complete_and_bounded() {
        assert_eq!(select(r#"{"exports":{"./*":"./*/copy/*.js"}}"#, MapKind::Exports, "./$x", &[]).unwrap().target, "./$x/copy/$x.js");
        let source = serde_json::json!({"exports":{"./*":format!("./{}", "*".repeat(100))}}).to_string();
        let request = format!("./{}", "a".repeat(4000));
        assert_eq!(select(&source, MapKind::Exports, &request, &[]).unwrap_err().code, "ERR_PACKAGE_MAP_LIMIT");
    }

    #[test]
    fn parse_and_query_budgets_fail_without_partial_selection() {
        assert_eq!(PackageMap::parse(&" ".repeat(MAX_MANIFEST_BYTES + 1)).unwrap_err().code, "ERR_PACKAGE_MAP_LIMIT");
        let source = format!("{{\"exports\":{}null{}}}", "[".repeat(70), "]".repeat(70));
        assert_eq!(PackageMap::parse(&source).unwrap_err().code, "ERR_PACKAGE_MAP_LIMIT");
        let source = serde_json::json!({"exports":vec!["./a"; MAX_MEMBERS + 1]}).to_string();
        assert!(PackageMap::parse(&source).is_err());
        let map = PackageMap::parse(r#"{"exports":"./a"}"#).unwrap();
        assert_eq!(map.select(MapKind::Exports, ".", &vec!["x".into();65]).unwrap_err().code, "ERR_INVALID_PACKAGE_CONDITIONS");
    }

    #[test]
    fn captures_bind_exact_input_bytes_and_cannot_be_mutated_by_later_sources() {
        let mut source = r#"{"exports":{"import":"./a.js","require":"./b.cjs"}}"#.to_owned();
        let map = PackageMap::parse(&source).unwrap();
        let repeated = PackageMap::parse(&source).unwrap();
        assert_eq!(map.input_hash(), repeated.input_hash());
        source.push(' ');
        assert_ne!(map.input_hash(), PackageMap::parse(&source).unwrap().input_hash());
        source.clear();
        assert_eq!(map.select(MapKind::Exports, ".", &["import".into()]).unwrap().target, "./a.js");
        assert!(!format!("{map:?}").contains("./a.js"));
    }
}
