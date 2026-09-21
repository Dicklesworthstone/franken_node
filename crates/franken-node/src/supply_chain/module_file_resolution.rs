//! Project-contained file resolution from a concrete importing module.
//!
//! Spec: Node's published ESM PACKAGE_RESOLVE / LOOKUP_PACKAGE_SCOPE and
//! CommonJS LOAD_AS_FILE / LOAD_AS_DIRECTORY algorithms. This composes the
//! ordered package-map selector with actual, descriptor-relative file capture.
//! It never executes source, trusts lockfile-only existence, or grants policy
//! authority. Symlinks, ambient/global search and non-file URL loaders are out
//! of scope. The caller receives the exact captured bytes, not a pathname to
//! reopen after checking evidence. Observations are bounded, not an atomic
//! snapshot of a hostile filesystem. Builtin requests require the runtime.

use super::package_targets::{MapKind, PackageMap, ResolutionError, Selection, TargetKind};
use rustix::fs::{AtFlags, FileType, Mode, OFlags, open, openat, statat};
use rustix::io::Errno;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{File, Metadata};
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::rc::Rc;

const MAX_PATH: usize = 4096;
const MAX_DEPTH: usize = 64;
const MAX_PROBES: usize = 1024;
const MAX_FILE: usize = 16 * 1024 * 1024;
const MAX_CAPTURE: usize = 32 * 1024 * 1024;
const HASH_DOMAIN: &[u8] = b"franken-node/module-file-resolution/v1\0";
type Result<T> = std::result::Result<T, ResolutionError>;

fn error(code: &'static str, detail: impl Into<String>) -> ResolutionError {
    ResolutionError { code, detail: detail.into() }
}
fn io_error(path: &str, cause: impl std::fmt::Display) -> ResolutionError {
    error("ERR_MODULE_CAPTURE", format!("cannot capture {path:?}: {cause}"))
}
fn limit() -> ResolutionError { error("ERR_MODULE_RESOLUTION_LIMIT", "module resolution resource bound exceeded") }

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResolutionMode { Import, Require }

impl ResolutionMode {
    pub fn default_conditions(self) -> Vec<String> {
        vec!["node".into(), match self { Self::Import => "import", Self::Require => "require" }.into()]
    }
    fn missing(self, name: &str) -> ResolutionError {
        error(match self { Self::Import => "ERR_MODULE_NOT_FOUND", Self::Require => "MODULE_NOT_FOUND" },
            format!("no supported module file for {name:?} inside the project"))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeKind { Missing, Directory, File }

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Probe {
    pub path: String,
    pub kind: ProbeKind,
    pub bytes: Option<usize>,
    pub sha256: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Mapping {
    pub manifest: String,
    pub input_hash: String,
    pub kind: MapKind,
    pub request: String,
    pub selection: Selection,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ResolutionReport {
    pub schema_version: String,
    pub importer: String,
    pub specifier: String,
    pub mode: ResolutionMode,
    pub conditions: Vec<String>,
    pub path: String,
    /// ESM URL identity suffix; CommonJS discards suffixes of package-map URLs.
    pub url_suffix: String,
    /// Not a parser result. Unmarked JS needs engine syntax detection.
    pub format_hint: String,
    pub content_sha256: String,
    pub content_bytes: usize,
    pub input_hash: String,
    pub probes: Vec<Probe>,
    pub mappings: Vec<Mapping>,
    pub filesystem_verified: bool,
    pub execution_performed: bool,
    pub release_certification: bool,
}

/// Source is deliberately not Debug/Serialize and has no mutable accessor.
/// Consumers must use source_bytes(), not reopen report.path after admission.
pub struct CapturedResolution {
    pub report: ResolutionReport,
    source: Rc<Entry>,
}
impl CapturedResolution {
    pub fn source_bytes(&self) -> &[u8] {
        match self.source.as_ref() { Entry::File { bytes, .. } => bytes, _ => unreachable!("resolved ordinary file") }
    }
}

enum Entry { Missing, Directory(File), File { bytes: Vec<u8>, sha256: String } }
impl Entry {
    fn is_file(&self) -> bool { matches!(self, Self::File { .. }) }
    fn is_dir(&self) -> bool { matches!(self, Self::Directory(_)) }
}

#[derive(Clone)]
struct Manifest { maps: PackageMap, name: Option<String>, main: Option<String>, package_type: Option<String>, exports: bool }

struct Resolver {
    entries: BTreeMap<String, Rc<Entry>>,
    manifests: BTreeMap<String, Option<Manifest>>,
    captured: usize,
    conditions: Vec<String>,
    mappings: Vec<Mapping>,
}

/// Resolve with the complete caller-selected condition set. No environment
/// variable, package-manager command, or project script can alter this context.
/// An importer must be an existing canonical project-relative ordinary file.
pub fn resolve(project: &Path, importer: &str, specifier: &str,
    mode: ResolutionMode, conditions: &[String]) -> Result<CapturedResolution> {
    validate_path(importer)?;
    validate_request(specifier)?;
    if conditions.len() > 64 || conditions.iter().any(|s| s.is_empty() || s.len() > 128 || s.chars().any(char::is_control)) {
        return Err(error("ERR_INVALID_PACKAGE_CONDITIONS", "invalid complete condition set"));
    }
    let conditions: Vec<_> = conditions.iter().cloned().collect::<BTreeSet<_>>().into_iter().collect();
    let root = File::from(open(project, OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty()).map_err(|e| io_error("<project>", e))?);
    let mut resolver = Resolver { entries: BTreeMap::from([("".into(), Rc::new(Entry::Directory(root)))]),
        manifests: BTreeMap::new(), captured: 0, conditions, mappings: Vec::new() };
    if !resolver.probe(importer)?.is_file() { return Err(mode.missing(importer)); }
    let (path, suffix) = resolver.request(parent(importer), specifier, mode, 0)?;
    let source = resolver.probe(&path)?;
    let Entry::File { bytes, sha256 } = source.as_ref() else { return Err(mode.missing(&path)); };
    let format_hint = resolver.format(&path)?;
    let probes = resolver.entries.iter().map(|(path, entry)| {
        let (kind, bytes, sha256) = match entry.as_ref() {
            Entry::Missing => (ProbeKind::Missing, None, None),
            Entry::Directory(_) => (ProbeKind::Directory, None, None),
            Entry::File { bytes, sha256 } => (ProbeKind::File, Some(bytes.len()), Some(sha256.clone())),
        };
        Probe { path: if path.is_empty() { ".".into() } else { path.clone() }, kind, bytes, sha256 }
    }).collect();
    let mut report = ResolutionReport {
        schema_version: "franken-node/module-file-resolution/v1".into(), importer: importer.into(), specifier: specifier.into(),
        mode, conditions: resolver.conditions, path, url_suffix: suffix, format_hint,
        content_sha256: sha256.clone(), content_bytes: bytes.len(), input_hash: String::new(),
        probes, mappings: resolver.mappings, filesystem_verified: true, execution_performed: false, release_certification: false,
    };
    // Hash the complete query and observed inputs, including negative probes.
    // Paths are relative and timestamps/inodes are intentionally not identity.
    let encoded = serde_json::to_vec(&report).map_err(|e| io_error("<report>", e))?;
    let mut hash = Sha256::new(); hash.update(HASH_DOMAIN); hash.update(encoded);
    report.input_hash = format!("sha256:{}", hex::encode(hash.finalize()));
    Ok(CapturedResolution { report, source })
}

impl Resolver {
    /// Cache both successful and negative probes. All children of a directory
    /// are opened against its retained descriptor, not a re-resolved pathname.
    fn probe(&mut self, path: &str) -> Result<Rc<Entry>> {
        if let Some(entry) = self.entries.get(path) { return Ok(Rc::clone(entry)); }
        validate_path(path)?;
        let directory = self.probe(parent(path))?;
        if self.entries.len() >= MAX_PROBES { return Err(limit()); }
        let entry = if let Entry::Directory(directory) = directory.as_ref() {
            let name = path.rsplit('/').next().unwrap_or(path);
            match statat(directory, name, AtFlags::SYMLINK_NOFOLLOW) {
                Err(Errno::NOENT) => Entry::Missing,
                Err(e) => return Err(io_error(path, e)),
                Ok(info) => {
                    let kind = FileType::from_raw_mode(info.st_mode);
                    if !matches!(kind, FileType::RegularFile | FileType::Directory) {
                        return Err(error("ERR_UNSUPPORTED_MODULE_FILE", format!("symlink or nonregular resolution input: {path:?}")));
                    }
                    let mut flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK;
                    if kind == FileType::Directory { flags |= OFlags::DIRECTORY; }
                    let mut file = File::from(openat(directory, name, flags, Mode::empty()).map_err(|e| io_error(path, e))?;
                    let before = file.metadata().map_err(|e| io_error(path, e))?;
                    if before.dev() != info.st_dev as u64 || before.ino() != info.st_ino as u64
                        || before.is_dir() != (kind == FileType::Directory) || (!before.is_file() && !before.is_dir()) {
                        return Err(error("ERR_MODULE_INPUT_CHANGED", "resolution input changed while opening"));
                    }
                    if before.is_dir() { Entry::Directory(file) }
                    else {
                        let cap = if name == "package.json" { super::package_targets::MAX_MANIFEST_BYTES } else { MAX_FILE };
                        if before.len() > cap as u64 || self.captured.saturating_add(before.len() as usize) > MAX_CAPTURE { return Err(limit()); }
                        let mut bytes = Vec::new();
                        (&mut file).take(cap as u64 + 1).read_to_end(&mut bytes).map_err(|e| io_error(path, e))?;
                        let after = file.metadata().map_err(|e| io_error(path, e))?;
                        if bytes.len() > cap || bytes.len() as u64 != before.len() || version(&before) != version(&after) {
                            return Err(error("ERR_MODULE_INPUT_CHANGED", "resolution input changed while reading"));
                        }
                        self.captured += bytes.len();
                        Entry::File { sha256: hex::encode(Sha256::digest(&bytes)), bytes }
                    }
                }
            }
        } else { Entry::Missing };
        let entry = Rc::new(entry);
        self.entries.insert(path.into(), Rc::clone(&entry));
        Ok(entry)
    }

    fn manifest(&mut self, directory: &str) -> Result<Option<Manifest>> {
        let path = join(directory, "package.json");
        if let Some(value) = self.manifests.get(&path) { return Ok(value.clone()); }
        let entry = self.probe(&path)?;
        let manifest = match entry.as_ref() {
            Entry::Missing => None,
            Entry::Directory(_) => return Err(error("ERR_INVALID_PACKAGE_CONFIG", "package.json is a directory")),
            Entry::File { bytes, .. } => {
                let text = std::str::from_utf8(bytes).map_err(|e| error("ERR_INVALID_PACKAGE_CONFIG", e.to_string()))?;
                let maps = PackageMap::parse(text)?; // Also rejects ambiguous duplicate JSON keys.
                let value: serde_json::Value = serde_json::from_str(text).map_err(|e| error("ERR_INVALID_PACKAGE_CONFIG", e.to_string()))?;
                let field = |key: &str| -> Result<Option<String>> {
                    match value.get(key) {
                        None | Some(serde_json::Value::Null) => Ok(None),
                        Some(serde_json::Value::String(s)) => Ok(Some(s.clone())),
                        _ => Err(error("ERR_INVALID_PACKAGE_CONFIG", format!("{key} must be a string"))),
                    }
                };
                Some(Manifest { maps, name: field("name")?, main: field("main")?, package_type: field("type")?,
                    exports: value.get("exports").is_some_and(|v| !v.is_null()) })
            }
        };
        self.manifests.insert(path, manifest.clone());
        Ok(manifest)
    }

    fn scope(&mut self, start: &str) -> Result<Option<(String, Manifest)>> {
        let mut directory = start;
        loop {
            if directory.rsplit('/').next() == Some("node_modules") { return Ok(None); }
            if let Some(manifest) = self.manifest(directory)? { return Ok(Some((directory.into(), manifest))); }
            if directory.is_empty() { return Ok(None); }
            directory = parent(directory);
        }
    }

    fn request(&mut self, directory: &str, request: &str, mode: ResolutionMode, depth: usize) -> Result<(String, String)> {
        if depth >= MAX_DEPTH { return Err(limit()); }
        validate_request(request)?;
        if request.starts_with("node:") || bare_builtin(request) {
            return Err(error("ERR_RUNTIME_MODULE_REQUIRED", "builtin request must be resolved against the engine capability/module registry, not node_modules"));
        }
        if request == "." || request == ".." || request.starts_with("./") || request.starts_with("../") {
            if mode == ResolutionMode::Import {
                let (path, suffix) = url_path(directory, request)?;
                return self.exact(&path, suffix, mode);
            }
            let path = normalize(directory, request)?;
            if request.ends_with('/') || matches!(request.rsplit('/').next(), Some("." | "..")) {
                return self.directory(&path, mode)?.map(|p| (p, String::new())).ok_or_else(|| mode.missing(request));
            }
            return self.legacy(&path, mode)?.map(|p| (p, String::new())).ok_or_else(|| mode.missing(request));
        }
        if request.starts_with('#') {
            let (scope, manifest) = self.scope(directory)?.ok_or_else(|| error("ERR_PACKAGE_IMPORT_NOT_DEFINED", "no package scope for internal import"))?;
            return self.mapping(&scope, &manifest, MapKind::Imports, request, mode, depth);
        }
        self.package(directory, request, mode, depth)
    }

    fn package(&mut self, directory: &str, request: &str, mode: ResolutionMode, depth: usize) -> Result<(String, String)> {
        let (name, subpath) = package_parts(request)?;
        if let Some((scope, manifest)) = self.scope(directory)? {
            if manifest.name.as_deref() == Some(name) && manifest.exports {
                return self.mapping(&scope, &manifest, MapKind::Exports, &subpath, mode, depth);
            }
        }
        let mut ancestor = directory;
        loop {
            if ancestor.rsplit('/').next() != Some("node_modules") {
                let package = join(&join(ancestor, "node_modules"), name);
                if self.probe(&package)?.is_dir() {
                    if let Some(manifest) = self.manifest(&package)? {
                        if manifest.exports { return self.mapping(&package, &manifest, MapKind::Exports, &subpath, mode, depth); }
                    }
                    if mode == ResolutionMode::Import {
                        if subpath == "." {
                            // Node's legacy package-root main/index search is
                            // distinct from strict ESM relative/subpath lookup.
                            return self.directory(&package, mode)?.map(|p| (p, String::new())).ok_or_else(|| mode.missing(request));
                        }
                        let (path, suffix) = url_path(&package, &subpath)?;
                        if !path.starts_with(&format!("{package}/")) {
                            return Err(error("ERR_INVALID_MODULE_SPECIFIER", "package subpath escapes its package"));
                        }
                        return self.exact(&path, suffix, mode);
                    }
                }
                if mode == ResolutionMode::Require {
                    let path = join(&join(ancestor, "node_modules"), request);
                    if let Some(found) = self.legacy(&path, mode)? { return Ok((found, String::new())); }
                }
            }
            if ancestor.is_empty() { return Err(mode.missing(request)); }
            ancestor = parent(ancestor);
        }
    }

    fn mapping(&mut self, directory: &str, manifest: &Manifest, kind: MapKind, request: &str,
        mode: ResolutionMode, depth: usize) -> Result<(String, String)> {
        let selection = manifest.maps.select(kind, request, &self.conditions)?;
        self.mappings.push(Mapping { manifest: join(directory, "package.json"), input_hash: manifest.maps.input_hash().into(),
            kind, request: request.into(), selection: selection.clone() });
        match selection.target_kind {
            TargetKind::PackageRelative => {
                let (path, suffix) = url_path(directory, &selection.target)?;
                self.exact(&path, if mode == ResolutionMode::Import { suffix } else { String::new() }, mode)
            }
            TargetKind::ExternalPackage => {
                // Imports targets use package resolution, not a new # lookup or
                // CommonJS extension search on the target's package subpath.
                if bare_builtin(&selection.target) { return Err(error("ERR_RUNTIME_MODULE_REQUIRED", "internal import selects a runtime builtin")); }
                if depth + 1 >= MAX_DEPTH { return Err(limit()); }
                let result = self.package(directory, &selection.target, ResolutionMode::Import, depth + 1)?;
                Ok((result.0, if mode == ResolutionMode::Import { result.1 } else { String::new() }))
            }
        }
    }

    fn exact(&mut self, path: &str, suffix: String, mode: ResolutionMode) -> Result<(String, String)> {
        let entry = self.probe(path)?;
        if entry.is_file() { Ok((path.into(), suffix)) }
        else if entry.is_dir() && mode == ResolutionMode::Import { Err(error("ERR_UNSUPPORTED_DIR_IMPORT", format!("directory import: {path:?}"))) }
        else { Err(mode.missing(path)) }
    }
    fn as_file(&mut self, path: &str) -> Result<Option<String>> {
        if path.is_empty() { return Ok(None); } // Appending .js would leave the root.
        if self.probe(path)?.is_file() { return Ok(Some(path.into())); }
        for extension in [".js", ".json", ".node"] {
            let candidate = format!("{path}{extension}");
            if self.probe(&candidate)?.is_file() { return Ok(Some(candidate)); }
        }
        Ok(None)
    }
    fn index(&mut self, directory: &str) -> Result<Option<String>> {
        if !self.probe(directory)?.is_dir() { return Ok(None); }
        for name in ["index.js", "index.json", "index.node"] {
            let candidate = join(directory, name);
            if self.probe(&candidate)?.is_file() { return Ok(Some(candidate)); }
        }
        Ok(None)
    }
    fn directory(&mut self, directory: &str, mode: ResolutionMode) -> Result<Option<String>> {
        if !self.probe(directory)?.is_dir() { return Ok(None); }
        if let Some(main) = self.manifest(directory)?.and_then(|m| m.main).filter(|s| !s.is_empty()) {
            let target = normalize(directory, &main)?;
            if let Some(found) = self.as_file(&target)? { return Ok(Some(found)); }
            if let Some(found) = self.index(&target)? { return Ok(Some(found)); }
            if let Some(found) = self.index(directory)? { return Ok(Some(found)); }
            return Err(mode.missing(&target));
        }
        self.index(directory)
    }
    fn legacy(&mut self, path: &str, mode: ResolutionMode) -> Result<Option<String>> {
        if let Some(found) = self.as_file(path)? { return Ok(Some(found)); }
        self.directory(path, mode)
    }
    fn format(&mut self, path: &str) -> Result<String> {
        Ok(match Path::new(path).extension().and_then(|s| s.to_str()) {
            Some("mjs") => "module", Some("cjs") => "commonjs", Some("json") => "json",
            Some("node") => "native_addon", Some("wasm") => "wasm",
            Some("js") | None => match self.scope(parent(path))?.and_then(|(_, m)| m.package_type).as_deref() {
                Some("module") => "module", Some("commonjs") => "commonjs", _ => "javascript_unspecified",
            },
            _ => "unknown",
        }.into())
    }
}

fn version(m: &Metadata) -> (u64, u64, u64, u32, i64, i64, i64, i64) {
    (m.dev(), m.ino(), m.len(), m.mode(), m.mtime(), m.mtime_nsec(), m.ctime(), m.ctime_nsec())
}
fn parent(path: &str) -> &str { path.rsplit_once('/').map_or("", |(p, _)| p) }
fn join(parent: &str, child: &str) -> String { if parent.is_empty() { child.into() } else { format!("{parent}/{child}") } }
fn validate_request(request: &str) -> Result<()> {
    if request.is_empty() || request.len() > MAX_PATH || request.contains('\\') || request.chars().any(char::is_control) {
        return Err(error("ERR_INVALID_MODULE_SPECIFIER", "invalid module request"));
    }
    if request.starts_with('/') || request.contains(':') && !request.starts_with("node:") {
        return Err(error("ERR_UNSUPPORTED_MODULE_SPECIFIER", "absolute paths and URL loaders are not supported by project-contained resolution"));
    }
    Ok(())
}
fn validate_path(path: &str) -> Result<()> {
    if path.is_empty() || path.len() > MAX_PATH || path.split('/').count() > MAX_DEPTH
        || path.contains(['\\', ':']) || path.chars().any(char::is_control)
        || path.split('/').any(|p| p.is_empty() || matches!(p, "." | ".." | ".git" | ".beads")) {
        return Err(error("ERR_INVALID_MODULE_SPECIFIER", "module path must remain canonical and project-relative"));
    }
    Ok(())
}
fn normalize(directory: &str, request: &str) -> Result<String> {
    if request.starts_with('/') || request.contains(['\\', ':']) || request.chars().any(char::is_control) { return Err(error("ERR_INVALID_MODULE_SPECIFIER", "unsupported path spelling")); }
    let mut parts: Vec<_> = directory.split('/').filter(|s| !s.is_empty()).collect();
    for part in request.split('/') {
        match part {
            "" | "." => {},
            ".." => { if parts.pop().is_none() { return Err(error("ERR_MODULE_OUTSIDE_PROJECT", "module path escapes the captured project root")); } },
            ".git" | ".beads" => return Err(error("ERR_INVALID_MODULE_SPECIFIER", "reserved repository state is not a module input")),
            _ => parts.push(part),
        }
    }
    let path = parts.join("/");
    if !path.is_empty() { validate_path(&path)?; }
    Ok(path)
}
fn url_path(directory: &str, request: &str) -> Result<(String, String)> {
    let split = request.find(['?', '#']).unwrap_or(request.len());
    let (path, suffix) = request.split_at(split);
    let mut decoded = Vec::new();
    let mut bytes = path.bytes();
    while let Some(byte) = bytes.next() {
        if byte != b'%' { decoded.push(byte); continue; }
        let high = bytes.next().and_then(|b| char::from(b).to_digit(16));
        let low = bytes.next().and_then(|b| char::from(b).to_digit(16));
        let (Some(high), Some(low)) = (high, low) else { return Err(error("ERR_INVALID_MODULE_SPECIFIER", "invalid URL percent encoding")); };
        let byte = (high * 16 + low) as u8;
        if matches!(byte, b'/' | b'\\' | 0) { return Err(error("ERR_INVALID_MODULE_SPECIFIER", "encoded separator or NUL")); }
        decoded.push(byte);
    }
    let path = String::from_utf8(decoded).map_err(|_| error("ERR_INVALID_MODULE_SPECIFIER", "non-UTF-8 URL path"))?;
    Ok((normalize(directory, &path)?, suffix.into()))
}
fn package_parts(request: &str) -> Result<(&str, String)> {
    validate_request(request)?;
    let end = if request.starts_with('@') {
        let first = request.find('/').ok_or_else(|| error("ERR_INVALID_MODULE_SPECIFIER", "scoped package is missing its name"))?;
        request[first + 1..].find('/').map_or(request.len(), |n| first + 1 + n)
    } else { request.find('/').unwrap_or(request.len()) };
    let name = &request[..end];
    super::validate_package_name(name).map_err(|e| error("ERR_INVALID_MODULE_SPECIFIER", e.to_string()))?;
    let subpath = format!(".{}", &request[end..]);
    if request[end..].split('/').skip(1).any(|p| p.is_empty() || matches!(p, "." | ".." | "node_modules")) {
        return Err(error("ERR_INVALID_MODULE_SPECIFIER", "noncanonical package subpath"));
    }
    Ok((name, subpath))
}

/// Public bare core names in the Node 22 reference band must never be shadowed
/// by project node_modules. This is routing, not an engine availability claim;
/// every explicit node: request is likewise handed back to the runtime layer.
fn bare_builtin(name: &str) -> bool {
    matches!(name, "assert" | "assert/strict" | "async_hooks" | "buffer" | "child_process" | "cluster"
        | "console" | "constants" | "crypto" | "dgram" | "diagnostics_channel" | "dns" | "dns/promises"
        | "domain" | "events" | "fs" | "fs/promises" | "http" | "http2" | "https" | "inspector"
        | "inspector/promises" | "module" | "net" | "os" | "path" | "path/posix" | "path/win32"
        | "perf_hooks" | "process" | "punycode" | "querystring" | "readline" | "readline/promises"
        | "repl" | "stream" | "stream/consumers" | "stream/promises" | "stream/web" | "string_decoder"
        | "sys" | "timers" | "timers/promises" | "tls" | "trace_events" | "tty" | "url" | "util"
        | "util/types" | "v8" | "vm" | "wasi" | "worker_threads" | "zlib")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::symlink;

    fn put(root: &Path, path: &str, bytes: &[u8]) {
        let path = root.join(path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, bytes).unwrap();
    }
    fn fixture() -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        put(root.path(), "app.js", b"throw new Error('never execute importer')");
        put(root.path(), "package.json", br#"{"name":"application","type":"commonjs"}"#);
        root
    }
    fn run(root: &Path, from: &str, request: &str, mode: ResolutionMode) -> CapturedResolution {
        resolve(root, from, request, mode, &mode.default_conditions()).unwrap()
    }
    fn rejected(root: &Path, from: &str, request: &str, mode: ResolutionMode) -> &'static str {
        let Err(error) = resolve(root, from, request, mode, &mode.default_conditions()) else { panic!("unexpected resolution of {request}"); };
        error.code
    }

    #[test]
    fn file_and_directory_search_are_distinct_from_strict_esm_paths() {
        let root = fixture();
        put(root.path(), "lib.js", b"javascript");
        put(root.path(), "dir/index.json", b"{}");
        put(root.path(), "dir.js", b"file beats directory unless slash supplied");
        assert_eq!(run(root.path(), "app.js", "./lib", ResolutionMode::Require).report.path, "lib.js");
        assert_eq!(rejected(root.path(), "app.js", "./lib", ResolutionMode::Import), "ERR_MODULE_NOT_FOUND");
        assert_eq!(run(root.path(), "app.js", "./dir", ResolutionMode::Require).report.path, "dir.js");
        assert_eq!(run(root.path(), "app.js", "./dir/", ResolutionMode::Require).report.path, "dir/index.json");
        assert_eq!(rejected(root.path(), "app.js", "./dir", ResolutionMode::Import), "ERR_UNSUPPORTED_DIR_IMPORT");
        assert_eq!(run(root.path(), "app.js", "./lib.js", ResolutionMode::Import).report.format_hint, "commonjs");
    }

    #[test]
    fn nearest_installed_package_and_conditional_exports_control_file_selection() {
        let root = fixture();
        put(root.path(), "packages/api/app.js", b"importer");
        for base in ["node_modules/pkg", "packages/api/node_modules/pkg"] {
            put(root.path(), &join(base, "package.json"), br#"{"exports":{".":{"import":"./esm.mjs","require":"./cjs.cjs"},"./private":null}}"#);
            put(root.path(), &join(base, "esm.mjs"), b"never executed ESM");
            put(root.path(), &join(base, "cjs.cjs"), b"never executed CJS");
        }
        for (mode, file) in [(ResolutionMode::Import,"esm.mjs"), (ResolutionMode::Require,"cjs.cjs")] {
            let result = run(root.path(), "packages/api/app.js", "pkg", mode);
            assert_eq!(result.report.path, format!("packages/api/node_modules/pkg/{file}"));
            assert_eq!(result.report.mappings.len(), 1);
            assert_eq!(rejected(root.path(), "packages/api/app.js", "pkg/private", mode), "ERR_PACKAGE_PATH_NOT_EXPORTED");
        }
    }

    #[test]
    fn self_references_and_external_imports_use_the_owning_package_scope() {
        let root = fixture();
        put(root.path(), "package.json", br##"{"name":"application","exports":{"./feature":"./feature.mjs"},"imports":{"#local":"./feature.mjs","#external":"@scope/pkg/sub"}}"##);
        put(root.path(), "feature.mjs", b"module");
        put(root.path(), "node_modules/@scope/pkg/package.json", br#"{"exports":{"./sub":"./result.cjs"}}"#);
        put(root.path(), "node_modules/@scope/pkg/result.cjs", b"external");
        for request in ["application/feature", "#local"] {
            assert_eq!(run(root.path(), "app.js", request, ResolutionMode::Require).report.path, "feature.mjs");
        }
        let result = run(root.path(), "app.js", "#external", ResolutionMode::Import);
        assert_eq!(result.report.path, "node_modules/@scope/pkg/result.cjs");
        assert_eq!(result.report.mappings.len(), 2);
        assert_eq!(result.source_bytes(), b"external");
    }

    #[test]
    fn dependency_without_manifest_cannot_inherit_application_imports_or_type() {
        let root = fixture();
        put(root.path(), "package.json", br##"{"type":"module","imports":{"#secret":"./secret.js"}}"##);
        put(root.path(), "secret.js", b"private");
        put(root.path(), "node_modules/pkg/app.js", b"importer");
        put(root.path(), "node_modules/pkg/value.js", b"value");
        assert_eq!(rejected(root.path(), "node_modules/pkg/app.js", "#secret", ResolutionMode::Import), "ERR_PACKAGE_IMPORT_NOT_DEFINED");
        assert_eq!(run(root.path(), "node_modules/pkg/app.js", "./value.js", ResolutionMode::Import).report.format_hint, "javascript_unspecified");
    }

    #[test]
    fn captured_source_survives_path_mutation_without_a_second_read() {
        let root = fixture();
        put(root.path(), "value.cjs", &[0, 255, 1, 10]);
        let result = run(root.path(), "app.js", "./value.cjs", ResolutionMode::Require);
        put(root.path(), "value.cjs", b"replacement");
        assert_eq!(result.source_bytes(), &[0, 255, 1, 10]);
        assert_eq!(result.report.content_sha256, hex::encode(Sha256::digest(result.source_bytes())));
        assert_ne!(result.report.input_hash, run(root.path(), "app.js", "./value.cjs", ResolutionMode::Require).report.input_hash);
    }

    #[test]
    fn successful_map_selection_never_falls_back_for_missing_files() {
        let root = fixture();
        put(root.path(), "node_modules/pkg/package.json", br#"{"exports":["./missing","./available.js"],"main":"available.js"}"#);
        put(root.path(), "node_modules/pkg/missing.js", b"wrong inferred extension");
        put(root.path(), "node_modules/pkg/available.js", b"wrong fallback");
        assert_eq!(rejected(root.path(), "app.js", "pkg", ResolutionMode::Require), "MODULE_NOT_FOUND");
        assert_eq!(rejected(root.path(), "app.js", "pkg", ResolutionMode::Import), "ERR_MODULE_NOT_FOUND");
    }

    #[test]
    fn legacy_main_and_index_are_resolved_without_recursive_directory_loops() {
        let root = fixture();
        put(root.path(), "node_modules/pkg/package.json", br#"{"main":"lib"}"#);
        put(root.path(), "node_modules/pkg/lib/index.json", b"{}");
        for mode in [ResolutionMode::Import, ResolutionMode::Require] {
            assert_eq!(run(root.path(), "app.js", "pkg", mode).report.path, "node_modules/pkg/lib/index.json");
        }
        put(root.path(), "node_modules/pkg/package.json", br#"{"main":"."}"#);
        assert_eq!(rejected(root.path(), "app.js", "pkg", ResolutionMode::Require), "MODULE_NOT_FOUND");
        put(root.path(), "node_modules/pkg/index.js", b"root index");
        assert_eq!(run(root.path(), "app.js", "pkg", ResolutionMode::Require).report.path, "node_modules/pkg/index.js");
    }

    #[test]
    fn urls_preserve_identity_suffix_and_do_not_decode_commonjs_file_names() {
        let root = fixture();
        put(root.path(), "space name.mjs", b"ESM");
        put(root.path(), "space%20name.cjs", b"literal");
        let result = run(root.path(), "app.js", "./space%20name.mjs?mode=one#part", ResolutionMode::Import);
        assert_eq!(result.report.path, "space name.mjs");
        assert_eq!(result.report.url_suffix, "?mode=one#part");
        assert_eq!(run(root.path(), "app.js", "./space%20name.cjs", ResolutionMode::Require).source_bytes(), b"literal");
        assert_eq!(rejected(root.path(), "app.js", "./a%2fb.js", ResolutionMode::Import), "ERR_INVALID_MODULE_SPECIFIER");
    }

    #[test]
    fn missing_shadow_candidates_and_complete_condition_context_are_hashed() {
        let root = fixture();
        put(root.path(), "lib/index.js", b"same bytes");
        let before = run(root.path(), "app.js", "./lib", ResolutionMode::Require);
        assert!(before.report.probes.iter().any(|p| p.path == "lib.js" && p.kind == ProbeKind::Missing));
        put(root.path(), "lib.js", b"same bytes");
        let after = run(root.path(), "app.js", "./lib", ResolutionMode::Require);
        assert_ne!(before.report.input_hash, after.report.input_hash);
        let custom = resolve(root.path(), "app.js", "./lib", ResolutionMode::Require, &["custom".into()]).unwrap();
        assert_ne!(custom.report.input_hash, after.report.input_hash);
        assert_eq!(custom.report.path, after.report.path);
    }

    #[test]
    fn malformed_metadata_and_symlinks_cannot_be_silently_skipped() {
        let root = fixture();
        put(root.path(), "node_modules/pkg/package.json", br#"{"exports":"./one.js","exports":"./two.js"}"#);
        assert_eq!(rejected(root.path(), "app.js", "pkg", ResolutionMode::Import), "ERR_INVALID_PACKAGE_CONFIG");
        put(root.path(), "outside.js", b"value");
        symlink("outside.js", root.path().join("alias.js")).unwrap();
        assert_eq!(rejected(root.path(), "app.js", "./alias.js", ResolutionMode::Import), "ERR_UNSUPPORTED_MODULE_FILE");
        symlink("node_modules", root.path().join("linked")).unwrap();
        assert_eq!(rejected(root.path(), "app.js", "./linked/pkg/file.js", ResolutionMode::Import), "ERR_UNSUPPORTED_MODULE_FILE");
    }

    #[test]
    fn escape_reserved_paths_invalid_importers_and_oversize_inputs_fail_closed() {
        let root = fixture();
        assert_eq!(rejected(root.path(), "app.js", "../outside.js", ResolutionMode::Import), "ERR_MODULE_OUTSIDE_PROJECT");
        assert_eq!(rejected(root.path(), "app.js", "./.git/config", ResolutionMode::Require), "ERR_INVALID_MODULE_SPECIFIER");
        assert_eq!(rejected(root.path(), "./app.js", "./app.js", ResolutionMode::Import), "ERR_INVALID_MODULE_SPECIFIER");
        assert_eq!(rejected(root.path(), "absent.js", "./app.js", ResolutionMode::Import), "ERR_MODULE_NOT_FOUND");
        put(root.path(), "large.js", &vec![b'x'; MAX_FILE + 1]);
        assert_eq!(rejected(root.path(), "app.js", "./large.js", ResolutionMode::Import), "ERR_MODULE_RESOLUTION_LIMIT");
        assert!(package_parts("pkg/../other").is_err());
    }

    #[test]
    fn runtime_builtins_are_never_shadowed_by_installed_packages() {
        let root = fixture();
        put(root.path(), "node_modules/fs/index.js", b"malicious shadow");
        for request in ["fs", "fs/promises", "node:fs", "node:not-in-any-runtime"] {
            assert_eq!(rejected(root.path(), "app.js", request, ResolutionMode::Require), "ERR_RUNTIME_MODULE_REQUIRED");
        }
    }
}
