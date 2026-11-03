//! Project-contained file resolution from a concrete importing module.
//!
//! Spec: Node's published ESM PACKAGE_RESOLVE / LOOKUP_PACKAGE_SCOPE and
//! CommonJS LOAD_AS_FILE / LOAD_AS_DIRECTORY algorithms. This composes the
//! ordered package-map selector with actual, descriptor-relative file capture.
//! It never executes source, trusts lockfile-only existence, or grants policy
//! authority. Relative symlinks can be explicitly enabled, but every component
//! must remain inside the project. Ambient/global search and non-file URL loaders
//! are out of scope. The caller receives the captured bytes, not a pathname to
//! reopen after checking evidence. Observations are bounded, not an atomic
//! snapshot of a hostile filesystem. Builtin requests require the runtime.

use super::package_targets::{
    BranchStep, MapKind, PackageMap, ResolutionError, Selection, TargetKind,
};
use rustix::fs::{AtFlags, FileType, Mode, OFlags, open, openat, readlinkat_raw, statat};
use rustix::io::Errno;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs::{File, Metadata};
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::rc::Rc;

#[path = "module_source_graph.rs"]
pub mod source_graph;

const MAX_PATH: usize = 4096;
const MAX_DEPTH: usize = 64;
const MAX_PROBES: usize = 1024;
const MAX_FILE: usize = 16 * 1024 * 1024;
const MAX_CAPTURE: usize = 32 * 1024 * 1024;
const MAX_LINK_HOPS: usize = 40;
const MAX_PACKAGE_CACHE_BYTES: usize = 1024 * 1024;
const HASH_DOMAIN: &[u8] = b"franken-node/module-file-resolution/v2\0";
type Result<T> = std::result::Result<T, ResolutionError>;
type FileVersion = (u64, u64, u64, u32, i64, i64, i64, i64);

fn error(code: &'static str, detail: impl Into<String>) -> ResolutionError {
    ResolutionError {
        code,
        detail: detail.into(),
    }
}
fn io_error(path: &str, cause: impl std::fmt::Display) -> ResolutionError {
    error(
        "ERR_MODULE_CAPTURE",
        format!("cannot capture {path:?}: {cause}"),
    )
}
fn limit() -> ResolutionError {
    error(
        "ERR_MODULE_RESOLUTION_LIMIT",
        "module resolution resource bound exceeded",
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResolutionMode {
    Import,
    Require,
}

/// Private imports use PACKAGE_RESOLVE for external targets even when the
/// caller is CommonJS. Caller conditions and package lookup are independent.
#[derive(Clone, Copy, PartialEq, Eq)]
enum PackageLookup {
    CommonJs,
    PackageUrl,
}

/// Contained follows only bounded relative links, using captured link text and
/// retained directory descriptors. It never delegates link following to open().
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SymlinkPolicy {
    Reject,
    Contained,
}

impl ResolutionMode {
    pub fn default_conditions(self) -> Vec<String> {
        vec![
            "node".into(),
            match self {
                Self::Import => "import",
                Self::Require => "require",
            }
            .into(),
        ]
    }
    fn missing(self, name: &str) -> ResolutionError {
        error(
            match self {
                Self::Import => "ERR_MODULE_NOT_FOUND",
                Self::Require => "MODULE_NOT_FOUND",
            },
            format!("no supported module file for {name:?} inside the project"),
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeKind {
    Missing,
    Directory,
    File,
    /// A regular-file observation without reading or admitting its contents.
    FileMetadata,
    Symlink,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Probe {
    pub path: String,
    pub kind: ProbeKind,
    pub bytes: Option<usize>,
    pub sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub link_target: Option<String>,
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
    pub resolved_importer: String,
    pub symlink_policy: SymlinkPolicy,
    pub specifier: String,
    pub mode: ResolutionMode,
    pub conditions: Vec<String>,
    pub path: String,
    /// ESM URL identity suffix; CommonJS discards suffixes of package-map URLs.
    pub url_suffix: String,
    /// Not a parser result. Unmarked JS/TS needs engine syntax detection.
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
        match self.source.as_ref() {
            Entry::File { bytes, .. } => bytes,
            _ => unreachable!("resolved ordinary file"),
        }
    }
}

enum Entry {
    Missing,
    // None is a recorded directory in an offline capsule, never a host path.
    Directory(Option<File>),
    File { bytes: Vec<u8>, sha256: String },
    // Live promotion to source bytes must still describe this same file.
    // Offline metadata deliberately carries no host identity or source bytes.
    FileMetadata { version: Option<FileVersion> },
    Symlink { target: String, sha256: String },
}
impl Entry {
    fn is_file(&self) -> bool {
        matches!(self, Self::File { .. } | Self::FileMetadata { .. })
    }
    fn is_dir(&self) -> bool {
        matches!(self, Self::Directory(_))
    }
}

struct Manifest {
    maps: PackageMap,
    name: Option<String>,
    main: Option<String>,
    package_type: Option<String>,
    exports: bool,
    imports: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct PackageQuery {
    mode: ResolutionMode,
    lookup: PackageLookup,
    depth: usize,
    url_lookup: bool,
}

struct CachedPackageResolution {
    query: PackageQuery,
    conditions: Vec<String>,
    target: (String, String),
    mappings: Vec<Mapping>,
}

/// Successful lookup decisions over this capture's immutable filesystem inputs.
/// The directory and exact request use borrowed lookups; the small bucket keeps
/// import/require, package-URL lookup, conditions and recursion budgets distinct.
/// No failure, source bytes or runtime authorization is retained here.
#[derive(Default)]
struct PackageCache {
    directories: BTreeMap<String, BTreeMap<String, Vec<CachedPackageResolution>>>,
    entries: usize,
    retained_bytes: usize,
}

impl PackageCache {
    fn get(
        &self,
        directory: &str,
        request: &str,
        query: PackageQuery,
        conditions: &[String],
    ) -> Option<&CachedPackageResolution> {
        self.directories
            .get(directory)?
            .get(request)?
            .iter()
            .find(|entry| entry.query == query && entry.conditions == conditions)
    }

    fn retain(
        &mut self,
        directory: &str,
        request: &str,
        query: PackageQuery,
        conditions: &[String],
        target: &(String, String),
        mappings: &[Mapping],
    ) {
        if self.entries >= MAX_PROBES {
            return;
        }
        // Cap retained payload before cloning it. Counting shared map keys for
        // every entry is conservative; the separate entry bound also bounds
        // container overhead. Saturation disables further reuse, not admission.
        let mut retained_bytes = self.retained_bytes;
        let mut charge = |bytes: usize| {
            retained_bytes = retained_bytes.checked_add(bytes)?;
            (retained_bytes <= MAX_PACKAGE_CACHE_BYTES).then_some(())
        };
        let charged = (|| {
            charge(std::mem::size_of::<CachedPackageResolution>())?;
            for value in [directory, request, &target.0, &target.1] {
                charge(value.len())?;
            }
            for condition in conditions {
                charge(std::mem::size_of::<String>())?;
                charge(condition.len())?;
            }
            for mapping in mappings {
                charge(std::mem::size_of::<Mapping>())?;
                for value in [
                    &mapping.manifest,
                    &mapping.input_hash,
                    &mapping.request,
                    &mapping.selection.target,
                    &mapping.selection.matched_key,
                ] {
                    charge(value.len())?;
                }
                for step in &mapping.selection.branch {
                    charge(std::mem::size_of::<BranchStep>())?;
                    if let BranchStep::Condition(condition) = step {
                        charge(condition.len())?;
                    }
                }
            }
            Some(())
        })();
        if charged.is_none() {
            return;
        }
        self.directories
            .entry(directory.into())
            .or_default()
            .entry(request.into())
            .or_default()
            .push(CachedPackageResolution {
                query,
                conditions: conditions.to_vec(),
                target: target.clone(),
                mappings: mappings.to_vec(),
            });
        self.entries += 1;
        self.retained_bytes = retained_bytes;
    }
}

struct Resolver {
    entries: BTreeMap<String, Rc<Entry>>,
    // Share immutable parsed maps across all lookups in this capture. Cloning
    // a manifest here used to copy its entire conditional exports/imports tree
    // on every dependency edge and package-scope query.
    manifests: BTreeMap<String, Option<Rc<Manifest>>>,
    // Nearest package directories for previously walked scopes, including
    // absence at node_modules boundaries. Keep exact lookup spellings and
    // bound this derived cache independently of captured filesystem inputs.
    scopes: BTreeMap<String, Option<String>>,
    packages: PackageCache,
    captured: usize,
    conditions: Vec<String>,
    mappings: Vec<Mapping>,
    symlink_policy: SymlinkPolicy,
    sealed: bool,
    observed: BTreeSet<String>,
    // URL lookup changes finalization, never the import condition set. Keep
    // this purpose in package-cache keys and restore it after every request.
    url_lookup: bool,
}

/// Resolve with the complete caller-selected condition set. No environment
/// variable, package-manager command, or project script can alter this context.
/// An importer must be an existing canonical project-relative ordinary file.
pub fn resolve(
    project: &Path,
    importer: &str,
    specifier: &str,
    mode: ResolutionMode,
    conditions: &[String],
) -> Result<CapturedResolution> {
    resolve_with_policy(
        project,
        importer,
        specifier,
        mode,
        conditions,
        SymlinkPolicy::Reject,
    )
}

/// Resolve ordinary loaded-module semantics with explicit symlink admission.
/// Both the importer and selected file are finalized to their captured real
/// locations. This does not implement Node's preserve-symlinks options or permit
/// external workspace roots, absolute symlink targets, or host-global lookup.
pub fn resolve_with_policy(
    project: &Path,
    importer: &str,
    specifier: &str,
    mode: ResolutionMode,
    conditions: &[String],
    symlink_policy: SymlinkPolicy,
) -> Result<CapturedResolution> {
    validate_path(importer)?;
    validate_request(specifier)?;
    let mut resolver = Resolver::new(project, conditions, symlink_policy)?;
    let (resolved_importer, importer_source) = resolver.locate(importer)?;
    if !importer_source.is_file() {
        return Err(mode.missing(importer));
    }
    let (path, suffix) = resolver.request(parent(&resolved_importer), specifier, mode, 0)?;
    let (path, source) = resolver.locate(&path)?;
    let Entry::File { bytes, sha256 } = source.as_ref() else {
        return Err(mode.missing(&path));
    };
    let format_hint = resolver.format(&path)?;
    let probes = resolver.probes();
    let mut report = ResolutionReport {
        schema_version: "franken-node/module-file-resolution/v2".into(),
        importer: importer.into(),
        resolved_importer,
        symlink_policy,
        specifier: specifier.into(),
        mode,
        conditions: resolver.conditions,
        path,
        url_suffix: suffix,
        format_hint,
        content_sha256: sha256.clone(),
        content_bytes: bytes.len(),
        input_hash: String::new(),
        probes,
        mappings: resolver.mappings,
        filesystem_verified: true,
        execution_performed: false,
        release_certification: false,
    };
    // Hash the complete query and observed inputs, including negative probes.
    // Paths are relative and timestamps/inodes are intentionally not identity.
    let encoded = serde_json::to_vec(&report).map_err(|e| io_error("<report>", e))?;
    let mut hash = Sha256::new();
    hash.update(HASH_DOMAIN);
    hash.update(encoded);
    report.input_hash = format!("sha256:{}", hex::encode(hash.finalize()));
    Ok(CapturedResolution { report, source })
}

impl Resolver {
    fn canonical_conditions(conditions: &[String]) -> Result<Vec<String>> {
        if conditions.len() > 64
            || conditions
                .iter()
                .any(|s| s.is_empty() || s.len() > 128 || s.chars().any(char::is_control))
        {
            return Err(error(
                "ERR_INVALID_PACKAGE_CONDITIONS",
                "invalid complete condition set",
            ));
        }
        Ok(conditions
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect())
    }
    fn new(project: &Path, conditions: &[String], symlink_policy: SymlinkPolicy) -> Result<Self> {
        let conditions = Self::canonical_conditions(conditions)?;
        let root = File::from(
            open(
                project,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|e| io_error("<project>", e))?,
        );
        Ok(Self {
            entries: BTreeMap::from([("".into(), Rc::new(Entry::Directory(Some(root))))]),
            manifests: BTreeMap::new(),
            scopes: BTreeMap::new(),
            packages: PackageCache::default(),
            captured: 0,
            conditions,
            mappings: Vec::new(),
            symlink_policy,
            sealed: false,
            observed: BTreeSet::new(),
            url_lookup: false,
        })
    }

    fn probes(&self) -> Vec<Probe> {
        self.entries
            .iter()
            .filter(|(path, _)| !self.sealed || self.observed.contains(*path))
            .map(|(path, entry)| {
                let (kind, bytes, sha256) = match entry.as_ref() {
                    Entry::Missing => (ProbeKind::Missing, None, None),
                    Entry::Directory(_) => (ProbeKind::Directory, None, None),
                    Entry::File { bytes, sha256 } => {
                        (ProbeKind::File, Some(bytes.len()), Some(sha256.clone()))
                    }
                    Entry::FileMetadata { .. } => (ProbeKind::FileMetadata, None, None),
                    Entry::Symlink { target, sha256 } => {
                        (ProbeKind::Symlink, Some(target.len()), Some(sha256.clone()))
                    }
                };
                let link_target = match entry.as_ref() {
                    Entry::Symlink { target, .. } => Some(target.clone()),
                    _ => None,
                };
                Probe {
                    path: if path.is_empty() {
                        ".".into()
                    } else {
                        path.clone()
                    },
                    kind,
                    bytes,
                    sha256,
                    link_target,
                }
            })
            .collect()
    }
    fn probe(&mut self, path: &str) -> Result<Rc<Entry>> {
        self.locate_with_bytes(path, !self.url_lookup).map(|(_, entry)| entry)
    }

    /// Resolve link components in order. In particular, a '..' inside link text
    /// applies AFTER preceding links, not to the lexical spelling of their paths.
    /// Raw positive/negative probes and link text are cached once per capture.
    fn locate(&mut self, path: &str) -> Result<(String, Rc<Entry>)> {
        self.locate_with_bytes(path, true)
    }

    fn locate_with_bytes(&mut self, path: &str, read_bytes: bool) -> Result<(String, Rc<Entry>)> {
        if !path.is_empty() {
            validate_path(path)?;
        }
        // Entries are immutable physical observations: a recorded non-link
        // already has captured directory parents and needs no component walk.
        // Alias spellings must still expand links. Sealed replay must visit
        // every parent again to reconstruct its observed-input evidence.
        if !self.sealed
            && let Some(entry) = self.entries.get(path)
            && !matches!(entry.as_ref(), Entry::Symlink { .. })
            && (!read_bytes || !matches!(entry.as_ref(), Entry::FileMetadata { .. }))
        {
            return Ok((path.to_owned(), Rc::clone(entry)));
        }
        let mut pending: VecDeque<String> = path.split('/').map(str::to_owned).collect();
        let mut resolved = Vec::<String>::new();
        let mut links = 0;
        let mut entry = self.raw_probe_with_bytes("", read_bytes)?;
        while let Some(part) = pending.pop_front() {
            // A missing or non-directory component cannot be bypassed with '..'.
            if !entry.is_dir() {
                return Ok((path.into(), Rc::new(Entry::Missing)));
            }
            match part.as_str() {
                "" | "." => continue,
                ".." => {
                    if resolved.pop().is_none() {
                        return Err(error(
                            "ERR_MODULE_OUTSIDE_PROJECT",
                            "symlink escapes the captured project root",
                        ));
                    }
                    entry = self.raw_probe_with_bytes(&resolved.join("/"), read_bytes)?;
                    continue;
                }
                _ => {}
            }
            let candidate = join(&resolved.join("/"), &part);
            let next = self.raw_probe_with_bytes(&candidate, read_bytes)?;
            if let Entry::Symlink { target, .. } = next.as_ref() {
                links += 1;
                if links > MAX_LINK_HOPS {
                    return Err(error(
                        "ERR_MODULE_SYMLINK_LOOP",
                        "more than 40 symlink hops in one lookup",
                    ));
                }
                let components = target.split('/');
                if resolved.len() + components.clone().count() + pending.len() > MAX_DEPTH
                    || candidate.len()
                        + target.len()
                        + pending.iter().map(|p| p.len() + 1).sum::<usize>()
                        > MAX_PATH
                {
                    return Err(limit());
                }
                for part in components.rev() {
                    pending.push_front(part.to_owned());
                }
                // Keep the captured physical parent; never open the link itself.
            } else {
                resolved.push(part);
                entry = next;
            }
        }
        Ok((resolved.join("/"), entry))
    }

    /// Cache both successful and negative probes. All children of a directory
    /// are opened against its retained descriptor, not a re-resolved pathname.
    /// This private method accepts ONLY physical paths produced by locate().
    fn raw_probe(&mut self, path: &str) -> Result<Rc<Entry>> {
        self.raw_probe_with_bytes(path, true)
    }

    fn raw_probe_with_bytes(&mut self, path: &str, read_bytes: bool) -> Result<Rc<Entry>> {
        if self.sealed {
            self.observed.insert(path.to_owned());
        }
        if let Some(entry) = self.entries.get(path) {
            if !read_bytes || !matches!(entry.as_ref(), Entry::FileMetadata { .. }) {
                return Ok(Rc::clone(entry));
            }
        }
        // An omitted observation is NOT evidence that the path was missing.
        // Sealed replay has no host descriptors and must never consult the host.
        if self.sealed {
            return Err(error(
                "ERR_MODULE_CAPSULE_INPUT_MISSING",
                "replay requested an uncaptured filesystem observation",
            ));
        }
        validate_path(path)?;
        let directory = self.raw_probe(parent(path))?;
        if !self.entries.contains_key(path) && self.entries.len() >= MAX_PROBES {
            return Err(limit());
        }
        let expected_version = self.entries.get(path).and_then(|entry| match entry.as_ref() {
            Entry::FileMetadata { version } => *version,
            _ => None,
        });
        let entry = if let Entry::Directory(Some(directory)) = directory.as_ref() {
            let name = path.rsplit('/').next().unwrap_or(path);
            match statat(directory, name, AtFlags::SYMLINK_NOFOLLOW) {
                Err(Errno::NOENT) if expected_version.is_some() => {
                    return Err(error(
                        "ERR_MODULE_INPUT_CHANGED",
                        "URL resolution target disappeared before source capture",
                    ));
                }
                Err(Errno::NOENT) => Entry::Missing,
                Err(e) => return Err(io_error(path, e)),
                Ok(info) => {
                    let kind = FileType::from_raw_mode(info.st_mode);
                    if expected_version.is_some_and(|expected| expected != stat_version(&info)) {
                        return Err(error(
                            "ERR_MODULE_INPUT_CHANGED",
                            "URL resolution target changed before source capture",
                        ));
                    }
                    if kind == FileType::RegularFile && !read_bytes {
                        let entry = Rc::new(Entry::FileMetadata {
                            version: Some(stat_version(&info)),
                        });
                        self.entries.insert(path.into(), Rc::clone(&entry));
                        return Ok(entry);
                    }
                    if kind == FileType::Symlink && self.symlink_policy == SymlinkPolicy::Contained
                    {
                        let mut buffer = [0_u8; MAX_PATH + 1];
                        let count = readlinkat_raw(directory, name, &mut buffer[..])
                            .map_err(|e| io_error(path, e))?;
                        if count > MAX_PATH {
                            return Err(limit());
                        }
                        let after = statat(directory, name, AtFlags::SYMLINK_NOFOLLOW)
                            .map_err(|e| io_error(path, e))?;
                        if info.st_dev != after.st_dev
                            || info.st_ino != after.st_ino
                            || info.st_mode != after.st_mode
                            || info.st_size != after.st_size
                            || info.st_size < 0
                            || info.st_size as usize != count
                            || info.st_mtime != after.st_mtime
                            || info.st_mtime_nsec != after.st_mtime_nsec
                            || info.st_ctime != after.st_ctime
                            || info.st_ctime_nsec != after.st_ctime_nsec
                        {
                            return Err(error(
                                "ERR_MODULE_INPUT_CHANGED",
                                "symlink changed while reading",
                            ));
                        }
                        let target = std::str::from_utf8(&buffer[..count]).map_err(|_| {
                            error("ERR_INVALID_MODULE_SYMLINK", "non-UTF-8 symlink target")
                        })?;
                        validate_link_target(target)?;
                        if self.captured.saturating_add(count) > MAX_CAPTURE {
                            return Err(limit());
                        }
                        self.captured += count;
                        let entry = Rc::new(Entry::Symlink {
                            target: target.into(),
                            sha256: hex::encode(Sha256::digest(target.as_bytes())),
                        });
                        self.entries.insert(path.into(), Rc::clone(&entry));
                        return Ok(entry);
                    }
                    if !matches!(kind, FileType::RegularFile | FileType::Directory) {
                        return Err(error(
                            "ERR_UNSUPPORTED_MODULE_FILE",
                            format!("symlink or nonregular resolution input: {path:?}"),
                        ));
                    }
                    let mut flags =
                        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK;
                    if kind == FileType::Directory {
                        flags |= OFlags::DIRECTORY;
                    }
                    let mut file = File::from(
                        openat(directory, name, flags, Mode::empty())
                            .map_err(|e| io_error(path, e))?,
                    );
                    let before = file.metadata().map_err(|e| io_error(path, e))?;
                    // `st_dev` is i32 on Apple platforms and u64 on Linux.
                    #[allow(clippy::unnecessary_cast, clippy::cast_sign_loss)]
                    let info_dev = info.st_dev as u64;
                    if before.dev() != info_dev
                        || before.ino() != info.st_ino
                        || before.is_dir() != (kind == FileType::Directory)
                        || (!before.is_file() && !before.is_dir())
                        || expected_version.is_some_and(|expected| expected != version(&before))
                    {
                        return Err(error(
                            "ERR_MODULE_INPUT_CHANGED",
                            "resolution input changed while opening",
                        ));
                    }
                    if before.is_dir() {
                        Entry::Directory(Some(file))
                    } else {
                        let cap = if name == "package.json" {
                            super::package_targets::MAX_MANIFEST_BYTES
                        } else {
                            MAX_FILE
                        };
                        if before.len() > cap as u64
                            || self.captured.saturating_add(before.len() as usize) > MAX_CAPTURE
                        {
                            return Err(limit());
                        }
                        let mut bytes = Vec::new();
                        (&mut file)
                            .take(cap as u64 + 1)
                            .read_to_end(&mut bytes)
                            .map_err(|e| io_error(path, e))?;
                        let after = file.metadata().map_err(|e| io_error(path, e))?;
                        if bytes.len() > cap
                            || bytes.len() as u64 != before.len()
                            || version(&before) != version(&after)
                        {
                            return Err(error(
                                "ERR_MODULE_INPUT_CHANGED",
                                "resolution input changed while reading",
                            ));
                        }
                        self.captured += bytes.len();
                        Entry::File {
                            sha256: hex::encode(Sha256::digest(&bytes)),
                            bytes,
                        }
                    }
                }
            }
        } else {
            Entry::Missing
        };
        let entry = Rc::new(entry);
        self.entries.insert(path.into(), Rc::clone(&entry));
        Ok(entry)
    }

    fn manifest(&mut self, directory: &str) -> Result<Option<Rc<Manifest>>> {
        let path = join(directory, "package.json");
        if let Some(value) = self.manifests.get(&path) {
            return Ok(value.clone());
        }
        // Package selection needs the actual manifest even during URL lookup.
        let (_, entry) = self.locate(&path)?;
        let manifest = match entry.as_ref() {
            Entry::Missing => None,
            Entry::Directory(_) => {
                return Err(error(
                    "ERR_INVALID_PACKAGE_CONFIG",
                    "package.json is a directory",
                ));
            }
            Entry::Symlink { .. } => unreachable!("probe finalizes links before reading manifests"),
            Entry::FileMetadata { .. } => unreachable!("manifest capture requires source bytes"),
            Entry::File { bytes, .. } => {
                let text = std::str::from_utf8(bytes)
                    .map_err(|e| error("ERR_INVALID_PACKAGE_CONFIG", e.to_string()))?;
                let (maps, metadata) = PackageMap::parse_manifest(text)?;
                Some(Rc::new(Manifest {
                    maps,
                    name: metadata.name,
                    main: metadata.main,
                    package_type: metadata.package_type,
                    exports: metadata.exports,
                    imports: metadata.imports,
                }))
            }
        };
        self.manifests.insert(path, manifest.clone());
        Ok(manifest)
    }

    fn scope(&mut self, start: &str) -> Result<Option<(String, Rc<Manifest>)>> {
        let mut directory = start;
        let mut visited = Vec::new();
        let found = loop {
            if directory.rsplit('/').next() == Some("node_modules") {
                break None;
            }
            // Live observations are immutable within this capture. Replay
            // must repeat the original walk to rebuild its observed inputs,
            // including every negative manifest and physical parent probe.
            if !self.sealed {
                if let Some(cached) = self.scopes.get(directory).cloned() {
                    break match cached {
                        Some(scope) => self.manifest(&scope)?.map(|manifest| (scope, manifest)),
                        None => None,
                    };
                }
                visited.push(directory);
            }
            if let Some(manifest) = self.manifest(directory)? {
                break Some((directory.into(), manifest));
            }
            if directory.is_empty() {
                break None;
            }
            directory = parent(directory);
        };
        // Publish only completed walks. An invalid manifest or failed probe
        // cannot leave a cached partial scope. Saturation merely stops reuse;
        // it does not change the existing resolver's admission or evidence.
        let nearest = found.as_ref().map(|(directory, _)| directory.as_str());
        for directory in visited {
            if self.scopes.len() >= MAX_PROBES {
                break;
            }
            self.scopes
                .insert(directory.into(), nearest.map(str::to_owned));
        }
        Ok(found)
    }

    /// Resolve a URL without acquiring source bytes or executable authority.
    /// Package manifests and realpath observations remain captured evidence.
    fn resolve_url(&mut self, directory: &str, request: &str) -> Result<source_graph::ResolutionUrl> {
        use source_graph::{ModuleId, ResolutionUrl};
        if request.is_empty() || request.len() > MAX_PATH || request.chars().any(char::is_control) {
            return Err(error("ERR_INVALID_MODULE_SPECIFIER", "invalid URL resolution request"));
        }
        let absolute = match url::Url::parse(request) {
            Ok(url) => Some(url),
            Err(url::ParseError::RelativeUrlWithoutBase) => None,
            Err(_) => return Err(error("ERR_INVALID_URL", "invalid absolute module URL")),
        };
        if let Some(url) = absolute {
            if url.scheme() == "file" {
                return Err(error(
                    "ERR_UNSUPPORTED_MODULE_SPECIFIER",
                    "absolute file URLs need a captured project-root mapping",
                ));
            }
            if url.as_str().len() > MAX_PATH {
                return Err(limit());
            }
            return Ok(ResolutionUrl::Absolute { url: url.into() });
        }
        if bare_builtin(request) {
            return Ok(ResolutionUrl::Absolute { url: format!("node:{request}") });
        }
        let previous = self.url_lookup;
        self.url_lookup = true;
        let selected = self.request(directory, request, ResolutionMode::Import, 0);
        self.url_lookup = previous;
        let (path, url_suffix) = selected?;
        if path.starts_with("node:") {
            return Ok(ResolutionUrl::Absolute { url: path });
        }
        // WHATWG URL paths preserve empty segments and trailing '/'. Physical
        // probes use their equivalent canonical spelling, while a missing file
        // or directory result must retain the original lexical URL spelling.
        let physical = normalize("", &path)?;
        let (real, entry) = self.locate_with_bytes(&physical, false)?;
        let path = if entry.is_file() && !path.ends_with('/') {
            real
        } else {
            path
        };
        Ok(ResolutionUrl::File { id: ModuleId { path, url_suffix } })
    }

    fn selected_path(&self, directory: &str, request: &str) -> Result<(String, String)> {
        if self.url_lookup {
            metadata_url_path(directory, request)
        } else {
            url_path(directory, request)
        }
    }

    fn request(
        &mut self,
        directory: &str,
        request: &str,
        mode: ResolutionMode,
        depth: usize,
    ) -> Result<(String, String)> {
        if depth >= MAX_DEPTH {
            return Err(limit());
        }
        validate_request(request)?;
        if request.starts_with("node:") || bare_builtin(request) {
            return Err(error(
                "ERR_RUNTIME_MODULE_REQUIRED",
                "builtin request must be resolved against the engine capability/module registry, not node_modules",
            ));
        }
        if request == "."
            || request == ".."
            || request.starts_with("./")
            || request.starts_with("../")
        {
            if mode == ResolutionMode::Import {
                let (path, suffix) = self.selected_path(directory, request)?;
                return self.exact(&path, suffix, mode);
            }
            let path = normalize(directory, request)?;
            if request.ends_with('/') || matches!(request.rsplit('/').next(), Some("." | "..")) {
                return self
                    .directory(&path, mode)?
                    .map(|p| (p, String::new()))
                    .ok_or_else(|| mode.missing(request));
            }
            return self
                .legacy(&path, mode)?
                .map(|p| (p, String::new()))
                .ok_or_else(|| mode.missing(request));
        }
        if request.starts_with('#') {
            let scope = self.scope(directory)?;
            if mode == ResolutionMode::Require
                && scope.as_ref().is_none_or(|(_, manifest)| !manifest.imports)
            {
                // LOAD_PACKAGE_IMPORTS has no effect without a non-null
                // imports field. CommonJS then performs its ordinary package
                // search, even for a name beginning with '#'. Capture those
                // probes; an unprobed MODULE_NOT_FOUND would invent absence.
                return self.package(directory, request, mode, PackageLookup::CommonJs, depth);
            }
            let (scope, manifest) = scope.ok_or_else(|| {
                error(
                    "ERR_PACKAGE_IMPORT_NOT_DEFINED",
                    "no package scope for internal import",
                )
            })?;
            return self.mapping(&scope, &manifest, MapKind::Imports, request, mode, depth);
        }
        let lookup = match mode {
            ResolutionMode::Require => PackageLookup::CommonJs,
            ResolutionMode::Import => PackageLookup::PackageUrl,
        };
        self.package(directory, request, mode, lookup, depth)
    }

    fn package(
        &mut self,
        directory: &str,
        request: &str,
        mode: ResolutionMode,
        lookup: PackageLookup,
        depth: usize,
    ) -> Result<(String, String)> {
        let query = PackageQuery {
            mode,
            lookup,
            depth,
            url_lookup: self.url_lookup,
        };
        // A live cache hit repeats exactly the successful target and mapping
        // witnesses whose inputs are already captured. Sealed replay must walk
        // again: a missing negative probe is not evidence that a path was absent.
        if !self.sealed
            && let Some(cached) = self
                .packages
                .get(directory, request, query, &self.conditions)
        {
            self.mappings.extend_from_slice(&cached.mappings);
            return Ok(cached.target.clone());
        }
        let mapping_start = self.mappings.len();
        let result = self.package_uncached(directory, request, mode, lookup, depth);
        if !self.sealed
            && let Ok(target) = &result
        {
            self.packages.retain(
                directory,
                request,
                query,
                &self.conditions,
                target,
                &self.mappings[mapping_start..],
            );
        }
        result
    }

    fn package_uncached(
        &mut self,
        directory: &str,
        request: &str,
        mode: ResolutionMode,
        lookup: PackageLookup,
        depth: usize,
    ) -> Result<(String, String)> {
        let (name, subpath) = package_parts(
            request,
            mode == ResolutionMode::Require && lookup == PackageLookup::CommonJs,
        )?;
        if let Some((scope, manifest)) = self.scope(directory)?
            && manifest.name.as_deref() == Some(name)
            && manifest.exports
        {
            return self.mapping(&scope, &manifest, MapKind::Exports, &subpath, mode, depth);
        }
        let mut ancestor = directory;
        loop {
            if ancestor.rsplit('/').next() != Some("node_modules") {
                let package = join(&join(ancestor, "node_modules"), name);
                if self.probe(&package)?.is_dir() {
                    if let Some(manifest) = self.manifest(&package)?
                        && manifest.exports
                    {
                        return self.mapping(
                            &package,
                            &manifest,
                            MapKind::Exports,
                            &subpath,
                            mode,
                            depth,
                        );
                    }
                    if lookup == PackageLookup::PackageUrl {
                        if subpath == "." {
                            // Node's legacy package-root main/index search is
                            // distinct from strict ESM relative/subpath lookup.
                            return self
                                .directory(&package, mode)?
                                .map(|p| (p, String::new()))
                                .ok_or_else(|| mode.missing(request));
                        }
                        let (path, suffix) = self.selected_path(&package, &subpath)?;
                        if path != package && !path.starts_with(&format!("{package}/")) {
                            return Err(error(
                                "ERR_INVALID_MODULE_SPECIFIER",
                                "package subpath escapes its package",
                            ));
                        }
                        return self.exact(&path, suffix, mode);
                    }
                }
                if lookup == PackageLookup::CommonJs {
                    // A terminal slash requests a directory, just as it does
                    // for relative CommonJS paths. Do not let a sibling .js,
                    // .json or .node file win over the requested package or
                    // subdirectory. Remove only this admitted terminal slash;
                    // package_parts still rejects noncanonical inner segments.
                    let directory_only = request.ends_with('/');
                    let path = join(
                        &join(ancestor, "node_modules"),
                        request.strip_suffix('/').unwrap_or(request),
                    );
                    let found = if directory_only {
                        self.directory(&path, mode)?
                    } else {
                        self.legacy(&path, mode)?
                    };
                    if let Some(found) = found {
                        return Ok((found, String::new()));
                    }
                }
            }
            if ancestor.is_empty() {
                return Err(mode.missing(request));
            }
            ancestor = parent(ancestor);
        }
    }

    fn mapping(
        &mut self,
        directory: &str,
        manifest: &Manifest,
        kind: MapKind,
        request: &str,
        mode: ResolutionMode,
        depth: usize,
    ) -> Result<(String, String)> {
        let selection = manifest.maps.select(kind, request, &self.conditions)?;
        self.mappings.push(Mapping {
            manifest: join(directory, "package.json"),
            input_hash: manifest.maps.input_hash().into(),
            kind,
            request: request.into(),
            selection: selection.clone(),
        });
        match selection.target_kind {
            TargetKind::PackageRelative => {
                let (path, suffix) = self.selected_path(directory, &selection.target)?;
                self.exact(
                    &path,
                    if mode == ResolutionMode::Import {
                        suffix
                    } else {
                        String::new()
                    },
                    mode,
                )
            }
            TargetKind::ExternalPackage => {
                // PACKAGE_TARGET_RESOLVE calls PACKAGE_RESOLVE for an external
                // imports target. Select one nearest package and exact URL
                // subpaths in both modes, while retaining the caller's active
                // import/require conditions for any exports map. A missing
                // target cannot select an inferred extension, directory index
                // or a different installed version.
                if bare_builtin(&selection.target) {
                    if self.url_lookup {
                        return Ok((format!("node:{}", selection.target), String::new()));
                    }
                    if mode == ResolutionMode::Require {
                        // CommonJS finalizes package imports through a file
                        // URL. Node rejects a builtin URL here, unlike ESM's
                        // PACKAGE_RESOLVE terminal. Do not turn an alias into
                        // authority that the reference loader does not grant.
                        return Err(error(
                            "ERR_INVALID_URL_SCHEME",
                            "CommonJS package imports require a file URL, not a builtin target",
                        ));
                    }
                    return Err(error(
                        "ERR_RUNTIME_MODULE_REQUIRED",
                        "internal import selects a runtime builtin",
                    ));
                }
                if depth + 1 >= MAX_DEPTH {
                    return Err(limit());
                }
                let result = self.package(
                    directory,
                    &selection.target,
                    mode,
                    PackageLookup::PackageUrl,
                    depth + 1,
                )?;
                Ok((
                    result.0,
                    if mode == ResolutionMode::Import {
                        result.1
                    } else {
                        String::new()
                    },
                ))
            }
        }
    }

    fn exact(
        &mut self,
        path: &str,
        suffix: String,
        mode: ResolutionMode,
    ) -> Result<(String, String)> {
        let physical = if self.url_lookup { normalize("", path)? } else { path.into() };
        let entry = self.probe(&physical)?;
        if entry.is_file() || self.url_lookup {
            // URL resolution admits missing paths and directories. The final
            // URL step realpaths regular files only, preserving directory and
            // absent-target spellings, including their terminal slash.
            Ok((path.into(), suffix))
        } else if entry.is_dir() && mode == ResolutionMode::Import {
            Err(error(
                "ERR_UNSUPPORTED_DIR_IMPORT",
                format!("directory import: {path:?}"),
            ))
        } else {
            Err(mode.missing(path))
        }
    }
    fn as_file(&mut self, path: &str) -> Result<Option<String>> {
        if path.is_empty() {
            return Ok(None);
        } // Appending .js would leave the root.
        if self.probe(path)?.is_file() {
            return Ok(Some(path.into()));
        }
        for extension in [".js", ".json", ".node"] {
            let candidate = format!("{path}{extension}");
            if self.probe(&candidate)?.is_file() {
                return Ok(Some(candidate));
            }
        }
        Ok(None)
    }
    fn index(&mut self, directory: &str) -> Result<Option<String>> {
        if !self.probe(directory)?.is_dir() {
            return Ok(None);
        }
        for name in ["index.js", "index.json", "index.node"] {
            let candidate = join(directory, name);
            if self.probe(&candidate)?.is_file() {
                return Ok(Some(candidate));
            }
        }
        Ok(None)
    }
    fn directory(&mut self, directory: &str, mode: ResolutionMode) -> Result<Option<String>> {
        if !self.probe(directory)?.is_dir() {
            return Ok(None);
        }
        if let Some(main) = self
            .manifest(directory)?
            .and_then(|m| m.main.clone())
            .filter(|s| !s.is_empty())
        {
            let target = normalize(directory, &main)?;
            if let Some(found) = self.as_file(&target)? {
                return Ok(Some(found));
            }
            if let Some(found) = self.index(&target)? {
                return Ok(Some(found));
            }
            if let Some(found) = self.index(directory)? {
                return Ok(Some(found));
            }
            return Err(mode.missing(&target));
        }
        self.index(directory)
    }
    fn legacy(&mut self, path: &str, mode: ResolutionMode) -> Result<Option<String>> {
        if let Some(found) = self.as_file(path)? {
            return Ok(Some(found));
        }
        self.directory(path, mode)
    }
    fn format(&mut self, path: &str) -> Result<String> {
        let extension = Path::new(path).extension().and_then(|s| s.to_str());
        Ok(match extension {
            Some("mjs" | "mts") => "module",
            Some("cjs" | "cts") => "commonjs",
            Some("json") => "json",
            Some("node") => "native_addon",
            Some("wasm") => "wasm",
            // Capture TS package scope with the source, including negative
            // observations. The engine must not reopen package.json later to
            // choose a parse goal. This does not add implicit .ts probing or
            // claim that a file has passed normalization or execution.
            Some("js" | "ts") | None => match self
                .scope(parent(path))?
                .as_ref()
                .and_then(|(_, m)| m.package_type.as_deref())
            {
                Some("module") => "module",
                Some("commonjs") => "commonjs",
                _ if extension == Some("ts") => "typescript_unspecified",
                _ => "javascript_unspecified",
            },
            _ => "unknown",
        }
        .into())
    }
}

fn validate_link_target(target: &str) -> Result<()> {
    if target.is_empty()
        || target.len() > MAX_PATH
        || target.split('/').count() > MAX_DEPTH
        || target.starts_with('/')
        || target.contains(['\\', ':'])
        || target.chars().any(char::is_control)
        || target.split('/').any(|p| matches!(p, ".git" | ".beads"))
    {
        return Err(error(
            "ERR_INVALID_MODULE_SYMLINK",
            "symlink target must be bounded, relative and outside reserved repository state",
        ));
    }
    Ok(())
}

fn version(m: &Metadata) -> FileVersion {
    (
        m.dev(),
        m.ino(),
        m.len(),
        m.mode(),
        m.mtime(),
        m.mtime_nsec(),
        m.ctime(),
        m.ctime_nsec(),
    )
}

// rustix stat fields have platform-specific integer types (notably Apple dev_t
// and time fields). This ephemeral identity is never serialized into capsules.
#[allow(clippy::unnecessary_cast, clippy::cast_sign_loss)]
fn stat_version(info: &rustix::fs::Stat) -> FileVersion {
    (
        info.st_dev as u64,
        info.st_ino as u64,
        info.st_size as u64,
        info.st_mode as u32,
        info.st_mtime as i64,
        info.st_mtime_nsec as i64,
        info.st_ctime as i64,
        info.st_ctime_nsec as i64,
    )
}
fn parent(path: &str) -> &str {
    path.rsplit_once('/').map_or("", |(p, _)| p)
}
fn join(parent: &str, child: &str) -> String {
    if parent.is_empty() {
        child.into()
    } else {
        format!("{parent}/{child}")
    }
}
fn validate_request(request: &str) -> Result<()> {
    if request.is_empty()
        || request.len() > MAX_PATH
        || request.contains('\\')
        || request.chars().any(char::is_control)
    {
        return Err(error(
            "ERR_INVALID_MODULE_SPECIFIER",
            "invalid module request",
        ));
    }
    // A colon inside query or fragment data is not a URL scheme or a
    // filesystem path component. The selected path is still validated below.
    let path = request.split(['?', '#']).next().unwrap_or_default();
    if request.starts_with('/') || path.contains(':') && !request.starts_with("node:") {
        return Err(error(
            "ERR_UNSUPPORTED_MODULE_SPECIFIER",
            "absolute paths and URL loaders are not supported by project-contained resolution",
        ));
    }
    Ok(())
}
fn validate_path(path: &str) -> Result<()> {
    if path.is_empty()
        || path.len() > MAX_PATH
        || path.split('/').count() > MAX_DEPTH
        || path.contains(['\\', ':'])
        || path.chars().any(char::is_control)
        || path
            .split('/')
            .any(|p| p.is_empty() || matches!(p, "." | ".." | ".git" | ".beads"))
    {
        return Err(error(
            "ERR_INVALID_MODULE_SPECIFIER",
            "module path must remain canonical and project-relative",
        ));
    }
    Ok(())
}
fn normalize(directory: &str, request: &str) -> Result<String> {
    if request.starts_with('/')
        || request.contains(['\\', ':'])
        || request.chars().any(char::is_control)
    {
        return Err(error(
            "ERR_INVALID_MODULE_SPECIFIER",
            "unsupported path spelling",
        ));
    }
    let mut parts: Vec<_> = directory.split('/').filter(|s| !s.is_empty()).collect();
    for part in request.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                if parts.pop().is_none() {
                    return Err(error(
                        "ERR_MODULE_OUTSIDE_PROJECT",
                        "module path escapes the captured project root",
                    ));
                }
            }
            ".git" | ".beads" => {
                return Err(error(
                    "ERR_INVALID_MODULE_SPECIFIER",
                    "reserved repository state is not a module input",
                ));
            }
            _ => parts.push(part),
        }
    }
    let path = parts.join("/");
    if !path.is_empty() {
        validate_path(&path)?;
    }
    Ok(path)
}
fn url_path(directory: &str, request: &str) -> Result<(String, String)> {
    // WHATWG URL parsing removes trailing ASCII space from the input.
    // Controls are already refused by request/target admission. CommonJS
    // literal paths do not pass through this URL-resolution path.
    let request = request.trim_end_matches(' ');
    let split = request.find(['?', '#']).unwrap_or(request.len());
    let (path, suffix) = request.split_at(split);
    let path = decoded_url_path(path)?;
    Ok((normalize(directory, &path)?, serialized_url_suffix(suffix)?))
}

fn decoded_url_path(path: &str) -> Result<String> {
    let mut decoded = Vec::new();
    let mut bytes = path.bytes();
    while let Some(byte) = bytes.next() {
        if byte != b'%' {
            decoded.push(byte);
            continue;
        }
        let high = bytes.next().and_then(|b| char::from(b).to_digit(16));
        let low = bytes.next().and_then(|b| char::from(b).to_digit(16));
        let (Some(high), Some(low)) = (high, low) else {
            return Err(error(
                "ERR_INVALID_MODULE_SPECIFIER",
                "invalid URL percent encoding",
            ));
        };
        let byte = (high * 16 + low) as u8;
        if matches!(byte, b'/' | b'\\' | 0) {
            return Err(error(
                "ERR_INVALID_MODULE_SPECIFIER",
                "encoded separator or NUL",
            ));
        }
        decoded.push(byte);
    }
    String::from_utf8(decoded)
        .map_err(|_| error("ERR_INVALID_MODULE_SPECIFIER", "non-UTF-8 URL path"))
}

/// A synthetic URL origin makes relative resolution independent of the host
/// root. Keep URL empty segments, unlike canonical physical probe paths.
fn metadata_url_path(directory: &str, request: &str) -> Result<(String, String)> {
    const ROOT: &str = "/__franken_node_captured_project__/";
    // WHATWG trims trailing spaces from the whole input, not from the path
    // before a query or fragment. Match that before checking dot segments.
    let request = request.trim_end_matches(' ');
    // Check the walk before URL normalization: a request must not escape and
    // then re-enter the synthetic root by spelling its implementation name.
    // Empty URL segments count here; a//.. removes the empty segment, not a.
    let path_end = request.find(['?', '#']).unwrap_or(request.len());
    let lexical = decoded_url_path(&request[..path_end])?;
    let mut depth = directory.split('/').filter(|part| !part.is_empty()).count();
    for part in lexical.split('/') {
        match part {
            "." => {}
            ".." => {
                depth = depth.checked_sub(1).ok_or_else(|| error(
                    "ERR_MODULE_OUTSIDE_PROJECT", "module URL escapes the captured project root",
                ))?;
            }
            _ => {
                if !part.is_empty() {
                    validate_path(part)?;
                }
                depth += 1;
                if depth > MAX_DEPTH {
                    return Err(limit());
                }
            }
        }
    }
    let base = url::Url::from_directory_path(Path::new(ROOT).join(directory))
        .map_err(|_| error("ERR_INVALID_MODULE_SPECIFIER", "invalid captured URL origin"))?;
    let url = base.join(request)
        .map_err(|_| error("ERR_INVALID_URL", "invalid relative module URL"))?;
    let encoded = url.path().strip_prefix(ROOT).ok_or_else(|| error(
        "ERR_MODULE_OUTSIDE_PROJECT", "module URL escapes the captured project root",
    ))?;
    let path = decoded_url_path(encoded)?;
    if path.len() > MAX_PATH || path.split('/').count() > MAX_DEPTH {
        return Err(limit());
    }
    // Check containment/reserved components without changing URL spelling.
    normalize("", &path)?;
    let mut suffix = String::new();
    if let Some(query) = url.query() {
        suffix.push('?');
        suffix.push_str(query);
    }
    if let Some(fragment) = url.fragment() {
        suffix.push('#');
        suffix.push_str(fragment);
    }
    if suffix.len() > MAX_PATH {
        return Err(limit());
    }
    Ok((path, suffix))
}

/// Serialize the query and fragment of a contained file URL. These are module
/// identity, not decoded filesystem components or form-encoded search params.
/// WHATWG's special-query set applies to file: URLs; the fragment set differs
/// for apostrophes and backticks. Existing percent escapes retain their exact
/// spelling, so percent-escape case and encoded delimiters remain distinct.
/// Spec: https://url.spec.whatwg.org/#special-query-percent-encode-set
///       https://url.spec.whatwg.org/#fragment-percent-encode-set
fn serialized_url_suffix(suffix: &str) -> Result<String> {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut serialized = String::with_capacity(suffix.len().min(MAX_PATH));
    let mut fragment = false;
    for byte in suffix.bytes() {
        if byte == b'#' {
            fragment = true;
        }
        let encode = byte <= b' '
            || byte >= 0x7f
            || matches!(byte, b'"' | b'<' | b'>')
            || (!fragment && byte == b'\'')
            || (fragment && byte == b'`');
        let width = if encode { 3 } else { 1 };
        if serialized.len().saturating_add(width) > MAX_PATH {
            return Err(limit());
        }
        if encode {
            serialized.push('%');
            serialized.push(char::from(HEX[usize::from(byte >> 4)]));
            serialized.push(char::from(HEX[usize::from(byte & 0x0f)]));
        } else {
            serialized.push(char::from(byte));
        }
    }
    Ok(serialized)
}

fn package_parts(request: &str, commonjs: bool) -> Result<(&str, String)> {
    validate_request(request)?;
    let end = if request.starts_with('@') {
        let first = request.find('/').ok_or_else(|| {
            error(
                "ERR_INVALID_MODULE_SPECIFIER",
                "scoped package is missing its name",
            )
        })?;
        request[first + 1..]
            .find('/')
            .map_or(request.len(), |n| first + 1 + n)
    } else {
        request.find('/').unwrap_or(request.len())
    };
    let name = &request[..end];
    let validated_name = if commonjs {
        name.strip_prefix('#').unwrap_or(name)
    } else {
        name
    };
    super::validate_package_name(validated_name)
        .map_err(|e| error("ERR_INVALID_MODULE_SPECIFIER", e.to_string()))?;
    let subpath = format!(".{}", &request[end..]);
    // Legacy packages can expose directory entrypoints (`pkg/`, `pkg/lib/`).
    // Keep that terminal slash in the subpath for exports encapsulation and
    // ESM's directory rejection; it is not an empty inner path component.
    if request[end..]
        .strip_suffix('/')
        .unwrap_or(&request[end..])
        .split('/')
        .skip(1)
        .any(|p| p.is_empty() || matches!(p, "." | ".." | "node_modules"))
    {
        return Err(error(
            "ERR_INVALID_MODULE_SPECIFIER",
            "noncanonical package subpath",
        ));
    }
    Ok((name, subpath))
}

/// Public bare core names in the Node 22 reference band must never be shadowed
/// by project node_modules. This is routing, not an engine availability claim;
/// every explicit node: request is likewise handed back to the runtime layer.
fn bare_builtin(name: &str) -> bool {
    matches!(
        name,
        "_http_agent"
            | "_http_client"
            | "_http_common"
            | "_http_incoming"
            | "_http_outgoing"
            | "_http_server"
            | "_stream_duplex"
            | "_stream_passthrough"
            | "_stream_readable"
            | "_stream_transform"
            | "_stream_wrap"
            | "_stream_writable"
            | "_tls_common"
            | "_tls_wrap"
            | "assert"
            | "assert/strict"
            | "async_hooks"
            | "buffer"
            | "child_process"
            | "cluster"
            | "console"
            | "constants"
            | "crypto"
            | "dgram"
            | "diagnostics_channel"
            | "dns"
            | "dns/promises"
            | "domain"
            | "events"
            | "fs"
            | "fs/promises"
            | "http"
            | "http2"
            | "https"
            | "inspector"
            | "inspector/promises"
            | "module"
            | "net"
            | "os"
            | "path"
            | "path/posix"
            | "path/win32"
            | "perf_hooks"
            | "process"
            | "punycode"
            | "querystring"
            | "readline"
            | "readline/promises"
            | "repl"
            | "stream"
            | "stream/consumers"
            | "stream/promises"
            | "stream/web"
            | "string_decoder"
            | "sys"
            | "timers"
            | "timers/promises"
            | "tls"
            | "trace_events"
            | "tty"
            | "url"
            | "util"
            | "util/types"
            | "v8"
            | "vm"
            | "wasi"
            | "worker_threads"
            | "zlib"
    )
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
        put(
            root.path(),
            "app.js",
            b"throw new Error('never execute importer')",
        );
        put(
            root.path(),
            "package.json",
            br#"{"name":"application","type":"commonjs"}"#,
        );
        root
    }
    #[test]
    fn import_meta_resolve_promotes_only_the_same_observed_file() {
        let root = fixture();
        put(root.path(), "asset.css", b"initial");
        let mut resolver = Resolver::new(root.path(), &ResolutionMode::Import.default_conditions(),
            SymlinkPolicy::Reject).unwrap();
        resolver.resolve_url("", "./asset.css").unwrap();
        assert!(matches!(resolver.entries.get("asset.css").unwrap().as_ref(),
            Entry::FileMetadata { version: Some(_) }));
        put(root.path(), "asset.css", b"changed after metadata observation");
        assert_eq!(resolver.locate("asset.css").err().unwrap().code, "ERR_MODULE_INPUT_CHANGED");
    }

    #[test]
    fn import_meta_resolve_url_walk_preserves_space_and_suffix_boundaries() {
        assert_eq!(metadata_url_path("a", "../.. ").unwrap_err().code,
            "ERR_MODULE_OUTSIDE_PROJECT");
        assert_eq!(metadata_url_path("", "./a//../missing ").unwrap(),
            ("a/missing".into(), String::new()));
        assert_eq!(metadata_url_path("", "./a/.. ?query#fragment ").unwrap(),
            ("a/.. ".into(), "?query#fragment".into()));
    }

    #[test]
    fn import_meta_resolve_package_cache_cannot_authorize_an_import() {
        let root = fixture();
        put(root.path(), "node_modules/exports/package.json",
            br#"{"exports":"./missing.js"}"#);
        put(root.path(), "node_modules/legacy/package.json",
            br#"{"main":"./missing.js"}"#);
        let mut resolver = Resolver::new(root.path(), &ResolutionMode::Import.default_conditions(),
            SymlinkPolicy::Reject).unwrap();
        assert_eq!(resolver.resolve_url("", "exports").unwrap(),
            source_graph::ResolutionUrl::File { id: source_graph::ModuleId {
                path: "node_modules/exports/missing.js".into(), url_suffix: String::new(),
            } });
        assert_eq!(resolver.request("", "exports", ResolutionMode::Import, 0).unwrap_err().code,
            "ERR_MODULE_NOT_FOUND");
        assert_eq!(resolver.resolve_url("", "legacy").unwrap_err().code, "ERR_MODULE_NOT_FOUND");
        assert_eq!(resolver.resolve_url("", "not-installed").unwrap_err().code, "ERR_MODULE_NOT_FOUND");
        for prefix_only in ["sea", "sqlite", "test", "test/reporters"] {
            assert_eq!(resolver.resolve_url("", prefix_only).unwrap_err().code,
                "ERR_MODULE_NOT_FOUND", "{prefix_only}");
            assert_eq!(resolver.resolve_url("", &format!("node:{prefix_only}")).unwrap(),
                source_graph::ResolutionUrl::Absolute { url: format!("node:{prefix_only}") });
        }
    }

    fn run(root: &Path, from: &str, request: &str, mode: ResolutionMode) -> CapturedResolution {
        resolve(root, from, request, mode, &mode.default_conditions()).unwrap()
    }
    fn rejected(root: &Path, from: &str, request: &str, mode: ResolutionMode) -> &'static str {
        let Err(error) = resolve(root, from, request, mode, &mode.default_conditions()) else {
            panic!("unexpected resolution of {request}");
        };
        error.code
    }

    fn linked(
        root: &Path,
        from: &str,
        request: &str,
        mode: ResolutionMode,
    ) -> Result<CapturedResolution> {
        resolve_with_policy(
            root,
            from,
            request,
            mode,
            &mode.default_conditions(),
            SymlinkPolicy::Contained,
        )
    }
    fn link(root: &Path, name: &str, target: &str) {
        fs::create_dir_all(root.join(name).parent().unwrap()).unwrap();
        symlink(target, root.join(name)).unwrap();
    }
    fn linked_error(root: &Path, from: &str, request: &str) -> &'static str {
        match linked(root, from, request, ResolutionMode::Import) {
            Err(e) => e.code,
            Ok(_) => panic!("unexpected linked resolution for {request}"),
        }
    }

    #[test]
    fn repeated_physical_lookups_keep_captured_files_and_negative_observations() {
        let root = fixture();
        put(
            root.path(),
            "deep/package/value.cjs",
            b"module.exports = 1;",
        );
        let mut resolver = Resolver::new(root.path(), &[], SymlinkPolicy::Reject).unwrap();
        let (path, source) = resolver.locate("deep/package/value.cjs").unwrap();
        let (_, missing) = resolver.locate("deep/package/absent.cjs").unwrap();
        let probes = resolver.probes();
        assert!(matches!(missing.as_ref(), Entry::Missing));

        put(
            root.path(),
            "deep/package/value.cjs",
            b"module.exports = 2;",
        );
        put(
            root.path(),
            "deep/package/absent.cjs",
            b"module.exports = 3;",
        );
        for _ in 0..16 {
            let (again_path, again) = resolver.locate("deep/package/value.cjs").unwrap();
            let (_, still_missing) = resolver.locate("deep/package/absent.cjs").unwrap();
            assert_eq!(again_path, path);
            assert!(Rc::ptr_eq(&source, &again));
            assert!(Rc::ptr_eq(&missing, &still_missing));
            assert!(matches!(
                again.as_ref(),
                Entry::File { bytes, .. } if bytes == b"module.exports = 1;"
            ));
            assert_eq!(resolver.probes(), probes);
        }

        let mut fresh = Resolver::new(root.path(), &[], SymlinkPolicy::Reject).unwrap();
        let (_, changed) = fresh.locate("deep/package/value.cjs").unwrap();
        assert!(matches!(
            changed.as_ref(),
            Entry::File { bytes, .. } if bytes == b"module.exports = 2;"
        ));
        assert!(fresh.probe("deep/package/absent.cjs").unwrap().is_file());
    }

    #[test]
    fn warmed_physical_targets_do_not_skip_alias_expansion_or_parent_checks() {
        let root = fixture();
        put(root.path(), "right/value.mjs", b"export const value = 1;");
        fs::create_dir_all(root.path().join("right/nested")).unwrap();
        link(root.path(), "left/junction", "../right/nested");
        link(root.path(), "entry.mjs", "left/junction/../value.mjs");
        link(root.path(), "missing.mjs", "absent/../right/value.mjs");
        link(root.path(), "not-dir.mjs", "right/value.mjs/../value.mjs");
        let mut resolver = Resolver::new(root.path(), &[], SymlinkPolicy::Contained).unwrap();
        let (_, source) = resolver.locate("right/value.mjs").unwrap();
        resolver.locate("right/nested").unwrap();

        for _ in 0..2 {
            let (path, aliased) = resolver.locate("entry.mjs").unwrap();
            assert_eq!(path, "right/value.mjs");
            assert!(Rc::ptr_eq(&source, &aliased));
            assert!(matches!(
                resolver.locate("missing.mjs").unwrap().1.as_ref(),
                Entry::Missing
            ));
            assert!(matches!(
                resolver.locate("not-dir.mjs").unwrap().1.as_ref(),
                Entry::Missing
            ));
        }
        for path in ["entry.mjs", "left/junction"] {
            assert!(
                resolver
                    .probes()
                    .iter()
                    .any(|probe| { probe.path == path && probe.kind == ProbeKind::Symlink })
            );
        }
        assert!(!resolver.entries.contains_key("left/junction/value.mjs"));
    }

    #[test]
    fn sealed_physical_lookups_reobserve_parents_and_refuse_uncaptured_inputs() {
        let root = fixture();
        put(
            root.path(),
            "deep/package/value.cjs",
            b"module.exports = 1;",
        );
        let mut resolver = Resolver::new(root.path(), &[], SymlinkPolicy::Reject).unwrap();
        resolver.locate("deep/package/value.cjs").unwrap();
        assert!(resolver.observed.is_empty());
        resolver.sealed = true;

        resolver.locate("deep/package/value.cjs").unwrap();
        assert_eq!(
            resolver.observed,
            ["", "deep", "deep/package", "deep/package/value.cjs"]
                .into_iter()
                .map(str::to_owned)
                .collect::<BTreeSet<_>>()
        );
        // Even a file now present on disk cannot turn an omitted observation
        // into a captured result once the resolver is sealed.
        put(
            root.path(),
            "deep/package/uncaptured.cjs",
            b"module.exports = 2;",
        );
        assert_eq!(
            resolver
                .locate("deep/package/uncaptured.cjs")
                .err()
                .unwrap()
                .code,
            "ERR_MODULE_CAPSULE_INPUT_MISSING"
        );
    }

    #[test]
    fn repeated_physical_and_alias_routes_keep_identical_capsule_evidence() {
        use source_graph::{GraphOptions, capsule, capture};

        let root = fixture();
        put(
            root.path(),
            "app.cjs",
            b"require('./packages/dep/index.cjs'); require('dep'); require('dep'); require('./missing.cjs');",
        );
        put(
            root.path(),
            "packages/dep/package.json",
            br#"{"name":"dep","type":"commonjs","main":"index.cjs"}"#,
        );
        put(
            root.path(),
            "packages/dep/index.cjs",
            b"module.exports = 42;",
        );
        link(root.path(), "node_modules/dep", "../packages/dep");
        let graph = capture(
            root.path(),
            "app.cjs",
            GraphOptions {
                symlink_policy: SymlinkPolicy::Contained,
                ..GraphOptions::default()
            },
        )
        .unwrap();
        let encoded = capsule::encode(&graph).unwrap();

        put(
            root.path(),
            "packages/dep/index.cjs",
            b"throw Error('changed');",
        );
        put(root.path(), "missing.cjs", b"module.exports = 'new';");
        let replayed = capsule::replay(encoded.bytes(), encoded.digest()).unwrap();
        assert_eq!(graph.report(), replayed.report());
        assert_eq!(graph.report().modules.len(), 2);
        assert_eq!(graph.report().edges.len(), 4);
        for module in &graph.report().modules {
            assert_eq!(
                graph.source_bytes(&module.id),
                replayed.source_bytes(&module.id)
            );
        }
        assert_eq!(capsule::encode(&replayed).unwrap().bytes(), encoded.bytes());
    }

    #[test]
    fn bom_manifests_and_materialized_patterns_preserve_closed_graph_replay() {
        use source_graph::{GraphOptions, capsule, capture};

        let root = fixture();
        let root_manifest = "\u{feff}{\"type\":\"module\",\"imports\":{\"#local\":\"./local.mjs\"}}";
        let package_manifest = "\u{feff}{\"exports\":{\"./*\":[\"./%*\",\"./fallback.cjs\"]}}";
        put(root.path(), "package.json", root_manifest.as_bytes());
        put(root.path(), "node_modules/fixture/package.json", package_manifest.as_bytes());
        put(root.path(), "app.js", b"import 'fixture/61.cjs'; import '#local';");
        put(root.path(), "local.mjs", b"export const value = 1;");
        put(root.path(), "node_modules/fixture/a.cjs", b"module.exports = 42;");
        put(root.path(), "node_modules/fixture/fallback.cjs", b"throw Error('wrong target');");
        let captured = capture(root.path(), "app.js", GraphOptions::default()).unwrap();
        assert!(captured.report().fully_resolved);
        assert_eq!(captured.report().modules.len(), 3);
        assert!(captured.report().modules.iter().any(|module|
            module.id.path == "node_modules/fixture/a.cjs"));
        assert!(!captured.report().probes.iter().any(|probe|
            probe.path == "node_modules/fixture/fallback.cjs"));
        for (path, original) in [
            ("package.json", root_manifest),
            ("node_modules/fixture/package.json", package_manifest),
        ] {
            let probe = captured.report().probes.iter().find(|probe| probe.path == path).unwrap();
            assert_eq!(probe.bytes, Some(original.len()));
            assert_eq!(probe.sha256, Some(hex::encode(Sha256::digest(original.as_bytes()))));
        }
        let encoded = capsule::encode(&captured).unwrap();
        put(root.path(), "package.json", br#"{"type":"commonjs"}"#);
        put(root.path(), "node_modules/fixture/package.json", br#"{"exports":{"./*":"./fallback.cjs"}}"#);
        put(root.path(), "node_modules/fixture/a.cjs", b"throw Error('live source reopened');");
        let replayed = capsule::replay(encoded.bytes(), encoded.digest()).unwrap();
        assert_eq!(replayed.report(), captured.report());
        for module in &captured.report().modules {
            assert_eq!(replayed.source_bytes(&module.id), captured.source_bytes(&module.id));
        }
        assert_eq!(capsule::encode(&replayed).unwrap().bytes(), encoded.bytes());
        let fresh = capture(root.path(), "app.js", GraphOptions::default()).unwrap();
        assert_ne!(fresh.report().input_hash, captured.report().input_hash);
    }

    #[test]
    fn materialized_pattern_errors_never_capture_a_fallback_or_escaping_source() {
        use source_graph::{GraphOptions, capture, registry::PinnedModuleRegistry};

        for (target, capture_name) in [
            ("./%*", "ZZ"),
            ("./%*", "2fprivate.cjs"),
            ("./%2e%2*", "e/private.cjs"),
            ("./node_*", "modules/private.cjs"),
        ] {
            let root = fixture();
            let manifest = serde_json::json!({"exports":{"./*":[target,"./fallback.cjs"]}});
            put(root.path(), "node_modules/fixture/package.json", manifest.to_string().as_bytes());
            put(root.path(), "app.cjs", format!("require('fixture/{capture_name}');").as_bytes());
            for file in [
                "node_modules/private.cjs",
                "node_modules/fixture/node_modules/private.cjs",
                "node_modules/fixture/fallback.cjs",
            ] {
                put(root.path(), file, b"throw Error('refused target must not be captured');");
            }
            let graph = capture(root.path(), "app.cjs", GraphOptions::default()).unwrap();
            assert!(!graph.report().fully_resolved);
            assert_eq!(graph.report().modules.len(), 1);
            assert_eq!(graph.report().edges.len(), 1);
            assert_eq!(graph.report().edges[0].error.as_ref().unwrap().code, "ERR_INVALID_MODULE_SPECIFIER");
            assert!(!graph.report().probes.iter().any(|probe|
                probe.path.ends_with("private.cjs") || probe.path.ends_with("fallback.cjs")));
            let pin = graph.report().input_hash.clone();
            assert_eq!(PinnedModuleRegistry::new(graph, &pin).err().unwrap().code, "ERR_MODULE_REGISTRY_INCOMPLETE");
        }
    }

    #[test]
    fn private_external_targets_keep_require_conditions_but_use_exact_package_lookup() {
        let root = fixture();
        put(
            root.path(),
            "package.json",
            br##"{
                "name":"application",
                "type":"commonjs",
                "imports":{"#feature":"dep/feature","#exact":"dep/feature.js"}
            }"##,
        );
        put(
            root.path(),
            "node_modules/dep/package.json",
            br#"{"name":"dep","type":"commonjs"}"#,
        );
        put(
            root.path(),
            "node_modules/dep/feature.js",
            b"module.exports = 42;",
        );

        assert_eq!(
            rejected(root.path(), "app.js", "#feature", ResolutionMode::Require),
            "MODULE_NOT_FOUND"
        );
        let required = run(
            root.path(),
            "app.js",
            "#exact",
            ResolutionMode::Require,
        );
        assert_eq!(required.report.path, "node_modules/dep/feature.js");
        assert_eq!(required.report.mode, ResolutionMode::Require);
        assert_eq!(required.report.format_hint, "commonjs");
        assert_eq!(required.source_bytes(), b"module.exports = 42;");

        // An ordinary bare CommonJS request still searches extensions. Only
        // private-import external targets use PACKAGE_RESOLVE's exact subpath.
        assert_eq!(
            run(root.path(), "app.js", "dep/feature", ResolutionMode::Require).report.path,
            "node_modules/dep/feature.js"
        );
        assert_eq!(
            rejected(
                root.path(),
                "app.js",
                "#feature",
                ResolutionMode::Import,
            ),
            "ERR_MODULE_NOT_FOUND"
        );
    }

    fn package_cache_fixture() -> tempfile::TempDir {
        let root = fixture();
        put(
            root.path(),
            "package.json",
            br##"{"name":"application","type":"commonjs","imports":{"#alias":"dual"}}"##,
        );
        put(root.path(), "src/deep/entry.cjs", b"");
        put(root.path(), "nested/deep/entry.cjs", b"");
        put(
            root.path(),
            "node_modules/dual/package.json",
            br#"{"exports":{".":{"development":{"require":"./dev.cjs","import":"./dev.mjs"},"require":"./main.cjs","import":"./main.mjs"},"./query":"./main.cjs?revision=one","./blocked":null}}"#,
        );
        for name in ["main.cjs", "main.mjs", "dev.cjs", "dev.mjs"] {
            put(root.path(), &format!("node_modules/dual/{name}"), b"");
        }
        put(
            root.path(),
            "nested/node_modules/dual/package.json",
            br#"{"exports":"./near.cjs"}"#,
        );
        put(root.path(), "nested/node_modules/dual/near.cjs", b"");
        put(root.path(), "node_modules/plain/index.js", b"");
        put(root.path(), "node_modules/plain/leaf.js", b"");
        root
    }

    #[test]
    fn package_cache_preserves_lookup_algorithms_conditions_depth_and_mapping_witnesses() {
        let root = package_cache_fixture();
        let mut cached = Resolver::new(root.path(), &[], SymlinkPolicy::Reject).unwrap();
        let mut original = Resolver::new(root.path(), &[], SymlinkPolicy::Reject).unwrap();
        for (directory, request, mode, lookup, conditions, depth) in [
            (
                "src/deep",
                "dual",
                ResolutionMode::Require,
                PackageLookup::CommonJs,
                vec!["node", "require"],
                0,
            ),
            (
                "src/deep",
                "dual",
                ResolutionMode::Require,
                PackageLookup::CommonJs,
                vec!["development", "node", "require"],
                0,
            ),
            (
                "src/deep",
                "dual",
                ResolutionMode::Import,
                PackageLookup::PackageUrl,
                vec!["import", "node"],
                0,
            ),
            (
                "src/deep",
                "dual",
                ResolutionMode::Import,
                PackageLookup::PackageUrl,
                vec!["development", "import", "node"],
                0,
            ),
            (
                "nested/deep",
                "dual",
                ResolutionMode::Require,
                PackageLookup::CommonJs,
                vec!["node", "require"],
                0,
            ),
            (
                "src/deep",
                "dual/query",
                ResolutionMode::Require,
                PackageLookup::CommonJs,
                vec!["node", "require"],
                0,
            ),
            (
                "src/deep",
                "dual/query",
                ResolutionMode::Import,
                PackageLookup::PackageUrl,
                vec!["node", "require"],
                0,
            ),
            (
                "src/deep",
                "plain/leaf",
                ResolutionMode::Require,
                PackageLookup::CommonJs,
                vec!["node", "require"],
                0,
            ),
            (
                "src/deep",
                "plain/leaf",
                ResolutionMode::Require,
                PackageLookup::PackageUrl,
                vec!["node", "require"],
                0,
            ),
            (
                "src/deep",
                "plain",
                ResolutionMode::Require,
                PackageLookup::CommonJs,
                vec!["node", "require"],
                0,
            ),
            (
                "src/deep",
                "dual",
                ResolutionMode::Require,
                PackageLookup::PackageUrl,
                vec!["node", "require"],
                1,
            ),
            (
                "src/deep",
                "dual",
                ResolutionMode::Require,
                PackageLookup::PackageUrl,
                vec!["node", "require"],
                MAX_DEPTH - 1,
            ),
            (
                "src/deep",
                "dual/blocked",
                ResolutionMode::Require,
                PackageLookup::CommonJs,
                vec!["node", "require"],
                0,
            ),
            (
                "src/deep",
                "missing",
                ResolutionMode::Require,
                PackageLookup::CommonJs,
                vec!["node", "require"],
                0,
            ),
        ] {
            cached.conditions = conditions.iter().map(|value| (*value).to_owned()).collect();
            original.conditions = cached.conditions.clone();
            for _ in 0..3 {
                cached.mappings.clear();
                original.mappings.clear();
                assert_eq!(
                    cached.package(directory, request, mode, lookup, depth),
                    original.package_uncached(directory, request, mode, lookup, depth),
                    "{directory}: {request}"
                );
                assert_eq!(cached.mappings, original.mappings, "{request}");
                assert_eq!(cached.probes(), original.probes(), "{request}");
            }
        }
        assert_eq!(cached.packages.entries, 11);
        assert!(original.packages.directories.is_empty());
        // A caller mutating its returned witness cannot alter a cached choice.
        cached.conditions = vec!["node".into(), "require".into()];
        cached.mappings.clear();
        cached
            .package(
                "src/deep",
                "dual",
                ResolutionMode::Require,
                PackageLookup::CommonJs,
                0,
            )
            .unwrap();
        let witnesses = cached.mappings.clone();
        cached.mappings[0].selection.target = "./injected.cjs".into();
        cached.mappings.clear();
        cached
            .package(
                "src/deep",
                "dual",
                ResolutionMode::Require,
                PackageLookup::CommonJs,
                0,
            )
            .unwrap();
        assert_eq!(cached.mappings, witnesses);

        // Internal-import selection belongs to this request's package scope.
        // A cached external package result contributes only its exports suffix,
        // after the freshly selected imports witness, never a prior prefix.
        original.conditions = cached.conditions.clone();
        for _ in 0..3 {
            cached.mappings.clear();
            original.mappings.clear();
            original.packages = PackageCache::default();
            assert_eq!(
                cached.request("src/deep", "#alias", ResolutionMode::Require, 0),
                original.request("src/deep", "#alias", ResolutionMode::Require, 0)
            );
            assert_eq!(cached.mappings, original.mappings);
            assert_eq!(
                cached
                    .mappings
                    .iter()
                    .map(|mapping| mapping.kind)
                    .collect::<Vec<_>>(),
                [MapKind::Imports, MapKind::Exports]
            );
            assert_eq!(cached.probes(), original.probes());
        }
    }

    #[test]
    fn package_cache_keeps_captured_absence_aliases_and_failure_inputs() {
        let root = package_cache_fixture();
        for directory in ["left", "right"] {
            link(root.path(), &format!("{directory}/alias"), "../src");
            put(
                root.path(),
                &format!("{directory}/node_modules/plain/index.js"),
                b"",
            );
        }
        let conditions = ResolutionMode::Require.default_conditions();
        let mut cached = Resolver::new(root.path(), &conditions, SymlinkPolicy::Contained).unwrap();
        let mut original =
            Resolver::new(root.path(), &conditions, SymlinkPolicy::Contained).unwrap();
        for directory in [
            "src/deep",
            "left/alias/deep",
            "right/alias/deep",
            "src/deep",
            "right/alias/deep",
        ] {
            assert_eq!(
                cached.package(
                    directory,
                    "plain",
                    ResolutionMode::Require,
                    PackageLookup::CommonJs,
                    0
                ),
                original.package_uncached(
                    directory,
                    "plain",
                    ResolutionMode::Require,
                    PackageLookup::CommonJs,
                    0
                )
            );
            assert_eq!(cached.probes(), original.probes());
        }
        put(
            root.path(),
            "src/deep/node_modules/plain/index.js",
            b"new closer package",
        );
        for resolver in [&mut cached, &mut original] {
            let found = resolver
                .package(
                    "src/deep",
                    "plain",
                    ResolutionMode::Require,
                    PackageLookup::CommonJs,
                    0,
                )
                .unwrap();
            assert_eq!(found.0, "node_modules/plain/index.js");
        }
        let mut fresh = Resolver::new(root.path(), &conditions, SymlinkPolicy::Contained).unwrap();
        assert_eq!(
            fresh
                .package(
                    "src/deep",
                    "plain",
                    ResolutionMode::Require,
                    PackageLookup::CommonJs,
                    0
                )
                .unwrap()
                .0,
            "src/deep/node_modules/plain/index.js"
        );
        let before = cached.packages.entries;
        put(
            root.path(),
            "bad/node_modules/broken/package.json",
            b"{invalid}",
        );
        for _ in 0..2 {
            assert_eq!(
                cached
                    .package(
                        "bad",
                        "broken",
                        ResolutionMode::Require,
                        PackageLookup::CommonJs,
                        0
                    )
                    .unwrap_err()
                    .code,
                "ERR_INVALID_PACKAGE_CONFIG"
            );
            assert_eq!(cached.packages.entries, before);
        }
    }

    #[test]
    fn package_cache_saturation_preserves_original_lookup_and_probe_evidence() {
        let root = package_cache_fixture();
        let conditions = ResolutionMode::Require.default_conditions();
        let mut cached = Resolver::new(root.path(), &conditions, SymlinkPolicy::Reject).unwrap();
        let mut original = Resolver::new(root.path(), &conditions, SymlinkPolicy::Reject).unwrap();
        for index in 0..MAX_PROBES + 8 {
            let directory = format!("absent/child-{index}");
            assert_eq!(
                cached.package(
                    &directory,
                    "plain",
                    ResolutionMode::Require,
                    PackageLookup::CommonJs,
                    0
                ),
                original.package_uncached(
                    &directory,
                    "plain",
                    ResolutionMode::Require,
                    PackageLookup::CommonJs,
                    0
                )
            );
            assert_eq!(cached.probes(), original.probes());
        }
        assert_eq!(cached.packages.entries, MAX_PROBES);
        assert!(cached.packages.retained_bytes <= MAX_PACKAGE_CACHE_BYTES);
        assert!(cached.entries.len() < 32);

        // Different valid complete condition sets exhaust retained payload
        // before the entry count. Both cases fall back to the original search.
        let mut bounded = Resolver::new(root.path(), &[], SymlinkPolicy::Reject).unwrap();
        for index in 0..160 {
            bounded.conditions = (0..62)
                .map(|condition| format!("condition-{index:03}-{condition:03}-{}", "x".repeat(108)))
                .chain(["node".into(), "require".into()])
                .collect();
            original.conditions = bounded.conditions.clone();
            assert_eq!(
                bounded.package(
                    "src/deep",
                    "plain",
                    ResolutionMode::Require,
                    PackageLookup::CommonJs,
                    0
                ),
                original.package_uncached(
                    "src/deep",
                    "plain",
                    ResolutionMode::Require,
                    PackageLookup::CommonJs,
                    0
                )
            );
            assert!(bounded.packages.retained_bytes <= MAX_PACKAGE_CACHE_BYTES);
        }
        assert!(bounded.packages.entries > 1 && bounded.packages.entries < 160);
    }

    #[test]
    fn sealed_package_walks_ignore_cached_success_and_require_negative_probes() {
        let root = package_cache_fixture();
        let conditions = ResolutionMode::Require.default_conditions();
        let mut cached = Resolver::new(root.path(), &conditions, SymlinkPolicy::Reject).unwrap();
        let mut original = Resolver::new(root.path(), &conditions, SymlinkPolicy::Reject).unwrap();
        assert_eq!(
            cached.package(
                "src/deep",
                "dual",
                ResolutionMode::Require,
                PackageLookup::CommonJs,
                0
            ),
            original.package_uncached(
                "src/deep",
                "dual",
                ResolutionMode::Require,
                PackageLookup::CommonJs,
                0
            )
        );
        let retained = cached.packages.entries;
        for resolver in [&mut cached, &mut original] {
            resolver.sealed = true;
            resolver.manifests.clear();
            resolver.observed.clear();
            resolver.mappings.clear();
        }
        assert_eq!(
            cached.package(
                "src/deep",
                "dual",
                ResolutionMode::Require,
                PackageLookup::CommonJs,
                0
            ),
            original.package_uncached(
                "src/deep",
                "dual",
                ResolutionMode::Require,
                PackageLookup::CommonJs,
                0
            )
        );
        assert_eq!(cached.mappings, original.mappings);
        assert_eq!(cached.observed, original.observed);
        assert_eq!(cached.probes(), original.probes());
        assert!(cached.observed.contains("src/deep/node_modules"));
        assert_eq!(cached.packages.entries, retained);
        cached.entries.remove("src/deep/node_modules");
        cached.manifests.clear();
        cached.observed.clear();
        cached.mappings.clear();
        assert_eq!(
            cached
                .package(
                    "src/deep",
                    "dual",
                    ResolutionMode::Require,
                    PackageLookup::CommonJs,
                    0
                )
                .unwrap_err()
                .code,
            "ERR_MODULE_CAPSULE_INPUT_MISSING"
        );
        assert_eq!(cached.packages.entries, retained);
    }

    #[test]
    fn package_scope_reuses_immutable_manifest_maps_within_one_capture() {
        let root = fixture();
        put(root.path(), "package.json", br##"{"type":"module","exports":{".":{"import":"./entry.mjs","require":"./entry.cjs"}},"imports":{"#local":"./entry.mjs"}}"##);
        let mut resolver = Resolver::new(root.path(), &[], SymlinkPolicy::Reject).unwrap();
        let first = resolver.manifest("").unwrap().unwrap();
        let again = resolver.manifest("").unwrap().unwrap();
        let scoped = resolver.scope("").unwrap().unwrap().1;
        assert!(Rc::ptr_eq(&first, &again));
        assert!(Rc::ptr_eq(&first, &scoped));
        assert_eq!(Rc::strong_count(&first), 4);

        // Filesystem mutation must neither refresh an existing capture nor
        // leak its old manifest into a new capture.
        put(root.path(), "package.json", br#"{"type":"commonjs"}"#);
        let retained = resolver.manifest("").unwrap().unwrap();
        assert!(Rc::ptr_eq(&first, &retained));
        assert_eq!(retained.package_type.as_deref(), Some("module"));
        let mut fresh = Resolver::new(root.path(), &[], SymlinkPolicy::Reject).unwrap();
        let changed = fresh.manifest("").unwrap().unwrap();
        assert!(!Rc::ptr_eq(&first, &changed));
        assert_eq!(changed.package_type.as_deref(), Some("commonjs"));
        assert_ne!(first.maps.input_hash(), changed.maps.input_hash());
    }

    fn uncached_scope(
        resolver: &mut Resolver,
        start: &str,
    ) -> Result<Option<(String, Rc<Manifest>)>> {
        let mut directory = start;
        loop {
            if directory.rsplit('/').next() == Some("node_modules") {
                return Ok(None);
            }
            if let Some(manifest) = resolver.manifest(directory)? {
                return Ok(Some((directory.into(), manifest)));
            }
            if directory.is_empty() {
                return Ok(None);
            }
            directory = parent(directory);
        }
    }

    fn scope_identity(scope: Option<(String, Rc<Manifest>)>) -> Option<(String, String)> {
        scope.map(|(directory, manifest)| (directory, manifest.maps.input_hash().into()))
    }

    #[test]
    fn scope_cache_preserves_nearest_manifests_negative_boundaries_and_mutations() {
        let root = fixture();
        put(root.path(), "src/a/deep/entry.js", b"");
        put(root.path(), "src/a/private/deep/entry.js", b"");
        put(
            root.path(),
            "src/a/private/package.json",
            br#"{"type":"module"}"#,
        );
        put(root.path(), "node_modules/loose/lib/entry.js", b"");
        put(root.path(), "node_modules/loose/lib/local/entry.js", b"");
        put(
            root.path(),
            "node_modules/loose/lib/local/package.json",
            b"{}",
        );
        put(
            root.path(),
            "node_modules/package.json",
            b"{invalid boundary}",
        );
        let mut current = Resolver::new(root.path(), &[], SymlinkPolicy::Reject).unwrap();
        let mut linear = Resolver::new(root.path(), &[], SymlinkPolicy::Reject).unwrap();
        for (start, nearest) in [
            ("", Some("")),
            ("src/a/deep", Some("")),
            ("src/a", Some("")),
            ("src/a/private/deep", Some("src/a/private")),
            ("src/a/deep", Some("")),
            ("node_modules/loose/lib", None),
            ("node_modules/loose/lib", None),
            (
                "node_modules/loose/lib/local",
                Some("node_modules/loose/lib/local"),
            ),
        ] {
            let found = scope_identity(current.scope(start).unwrap());
            assert_eq!(
                found.as_ref().map(|(directory, _)| directory.as_str()),
                nearest
            );
            assert_eq!(
                found,
                scope_identity(uncached_scope(&mut linear, start).unwrap())
            );
            assert_eq!(current.probes(), linear.probes());
        }
        assert_eq!(current.scopes.get("src/a/deep"), Some(&Some(String::new())));
        assert_eq!(current.scopes.get("src/a"), Some(&Some(String::new())));
        assert_eq!(current.scopes.get("node_modules/loose/lib"), Some(&None));
        assert!(!current.entries.contains_key("node_modules/package.json"));

        // Captured absence stays absent; a new capture sees the new manifest.
        put(root.path(), "src/a/package.json", br#"{"type":"module"}"#);
        assert_eq!(current.scope("src/a/deep").unwrap().unwrap().0, "");
        assert_eq!(
            scope_identity(current.scope("src/a/deep").unwrap()),
            scope_identity(uncached_scope(&mut linear, "src/a/deep").unwrap())
        );
        let mut fresh = Resolver::new(root.path(), &[], SymlinkPolicy::Reject).unwrap();
        assert_eq!(fresh.scope("src/a/deep").unwrap().unwrap().0, "src/a");

        // A newly reached child still checks its own manifest before using an
        // inherited cached ancestor. Failed walks never publish partial scopes.
        put(root.path(), "src/new/package.json", b"{}");
        assert_eq!(current.scope("src/new").unwrap().unwrap().0, "src/new");
        put(root.path(), "bad/deep/entry.js", b"");
        put(root.path(), "bad/package.json", b"{invalid}");
        let before = current.scopes.clone();
        for _ in 0..2 {
            assert_eq!(
                current.scope("bad/deep").err().unwrap().code,
                "ERR_INVALID_PACKAGE_CONFIG"
            );
            assert_eq!(current.scopes, before);
        }
    }

    #[test]
    fn scope_cache_keeps_alias_spellings_separate_from_physical_directories() {
        let root = fixture();
        put(root.path(), "shared/deep/entry.js", b"");
        for directory in ["left", "right"] {
            put(
                root.path(),
                &join(directory, "package.json"),
                br#"{"type":"module"}"#,
            );
            link(root.path(), &join(directory, "alias"), "../shared");
        }
        let mut current = Resolver::new(root.path(), &[], SymlinkPolicy::Contained).unwrap();
        let mut linear = Resolver::new(root.path(), &[], SymlinkPolicy::Contained).unwrap();
        for (start, nearest) in [
            ("shared/deep", ""),
            ("left/alias/deep", "left"),
            ("right/alias/deep", "right"),
            ("shared/deep", ""),
            ("right/alias/deep", "right"),
            ("left/alias/deep", "left"),
        ] {
            let found = scope_identity(current.scope(start).unwrap());
            assert_eq!(found.as_ref().unwrap().0, nearest);
            assert_eq!(
                found,
                scope_identity(uncached_scope(&mut linear, start).unwrap())
            );
            assert_eq!(current.probes(), linear.probes());
        }
    }

    #[test]
    fn scope_cache_saturation_changes_neither_admission_nor_observed_inputs() {
        let root = fixture();
        let mut current = Resolver::new(root.path(), &[], SymlinkPolicy::Reject).unwrap();
        let mut linear = Resolver::new(root.path(), &[], SymlinkPolicy::Reject).unwrap();
        // A missing parent short-circuits physical probing. Distinct lookup
        // spellings can therefore outnumber retained filesystem observations.
        for index in 0..MAX_PROBES + 8 {
            let start = format!("absent/child-{index}");
            assert_eq!(
                scope_identity(current.scope(&start).unwrap()),
                scope_identity(uncached_scope(&mut linear, &start).unwrap())
            );
            assert!(current.scopes.len() <= MAX_PROBES);
            assert_eq!(current.probes(), linear.probes());
        }
        assert_eq!(current.scopes.len(), MAX_PROBES);
        assert!(current.entries.len() < 8);
        put(root.path(), "fresh/package.json", br#"{"type":"module"}"#);
        assert_eq!(current.scope("fresh").unwrap().unwrap().0, "fresh");
        assert!(!current.scopes.contains_key("fresh"));
        assert_eq!(
            scope_identity(current.scope("fresh").unwrap()),
            scope_identity(uncached_scope(&mut linear, "fresh").unwrap())
        );
        assert_eq!(current.probes(), linear.probes());
    }

    #[test]
    fn sealed_scope_walks_ignore_warmed_cache_and_reconstruct_missing_observations() {
        let root = fixture();
        put(root.path(), "src/a/deep/entry.js", b"");
        let mut current = Resolver::new(root.path(), &[], SymlinkPolicy::Reject).unwrap();
        let mut linear = Resolver::new(root.path(), &[], SymlinkPolicy::Reject).unwrap();
        assert_eq!(
            scope_identity(current.scope("src/a/deep").unwrap()),
            scope_identity(uncached_scope(&mut linear, "src/a/deep").unwrap())
        );
        let warmed = current.scopes.clone();
        for resolver in [&mut current, &mut linear] {
            resolver.sealed = true;
            resolver.manifests.clear();
            resolver.observed.clear();
        }
        assert_eq!(
            scope_identity(current.scope("src/a/deep").unwrap()),
            scope_identity(uncached_scope(&mut linear, "src/a/deep").unwrap())
        );
        assert_eq!(current.observed, linear.observed);
        assert!(current.observed.contains("src/a/deep/package.json"));
        assert!(current.observed.contains("src/a/package.json"));
        assert_eq!(current.probes(), linear.probes());
        assert_eq!(current.scopes, warmed);

        current.entries.remove("src/a/deep/package.json");
        current.manifests.clear();
        current.observed.clear();
        assert_eq!(
            current.scope("src/a/deep").err().unwrap().code,
            "ERR_MODULE_CAPSULE_INPUT_MISSING"
        );
        assert_eq!(current.scopes, warmed);
    }

    #[test]
    #[ignore = "manual warm-scope comparison; timings depend on the machine and workload"]
    fn package_scope_manual_comparison() {
        use std::hint::black_box;
        use std::time::Instant;

        let root = fixture();
        put(
            root.path(),
            "node_modules/fixture/package.json",
            br#"{"name":"fixture","type":"commonjs"}"#,
        );
        let nested = format!("node_modules/fixture/{}", "nested/".repeat(32));
        let starts: Vec<_> = (0..8)
            .map(|index| {
                let directory = format!("{nested}leaf-{index}");
                put(
                    root.path(),
                    &join(&directory, "entry.js"),
                    b"module.exports = 42;",
                );
                directory
            })
            .collect();
        let mut current = Resolver::new(root.path(), &[], SymlinkPolicy::Reject).unwrap();
        let mut linear = Resolver::new(root.path(), &[], SymlinkPolicy::Reject).unwrap();
        for start in &starts {
            let a = current.scope(start).unwrap().unwrap();
            let b = uncached_scope(&mut linear, start).unwrap().unwrap();
            assert_eq!(a.0, b.0);
            assert_eq!(a.1.maps.input_hash(), b.1.maps.input_hash());
        }
        assert_eq!(current.probes(), linear.probes());
        const QUERIES: usize = 10_000;
        for round in 0..5 {
            let measure = |resolver: &mut Resolver, optimized: bool| {
                let before = Instant::now();
                for index in 0..QUERIES {
                    let start = &starts[index % starts.len()];
                    black_box(if optimized {
                        resolver.scope(start).unwrap()
                    } else {
                        uncached_scope(resolver, start).unwrap()
                    });
                }
                before.elapsed().as_nanos()
            };
            let (current_ns, linear_ns) = if round % 2 == 0 {
                (measure(&mut current, true), measure(&mut linear, false))
            } else {
                let linear_ns = measure(&mut linear, false);
                (measure(&mut current, true), linear_ns)
            };
            eprintln!(
                "scope_round={round} queries={QUERIES} current_ns={current_ns} uncached_ns={linear_ns}"
            );
        }
        assert_eq!(current.probes(), linear.probes());
    }

    #[test]
    fn single_parse_metadata_controls_package_routes_formats_and_frozen_replay() {
        use source_graph::registry::{PinnedModuleRegistry, RequestStyle};
        use source_graph::{GraphOptions, capsule, capture};

        let root = fixture();
        put(
            root.path(),
            "package.json",
            br##"{"name":"application","type":"module","exports":{"./self":"./self.mjs"},"imports":{"#legacy":"legacy"}}"##,
        );
        put(
            root.path(),
            "app.mjs",
            b"import 'application/self'; import '#legacy';",
        );
        put(root.path(), "self.mjs", b"export const value = 1;");
        put(
            root.path(),
            "node_modules/legacy/package.json",
            br#"{"name":"legacy","main":"start.cjs","type":"commonjs","exports":null}"#,
        );
        put(
            root.path(),
            "node_modules/legacy/start.cjs",
            b"module.exports = require('./feature');",
        );
        put(
            root.path(),
            "node_modules/legacy/feature.js",
            b"module.exports = 42;",
        );
        let graph = capture(root.path(), "app.mjs", GraphOptions::default()).unwrap();
        assert!(graph.report().fully_resolved);
        assert_eq!(graph.report().modules.len(), 4);
        assert_eq!(graph.report().edges.len(), 3);
        assert!(graph.report().modules.iter().any(|module| {
            module.id.path == "node_modules/legacy/feature.js" && module.format_hint == "commonjs"
        }));
        let pin = graph.report().input_hash.clone();
        let encoded = capsule::encode(&graph).unwrap();

        put(
            root.path(),
            "package.json",
            br#"{"name":"changed","type":"commonjs"}"#,
        );
        put(
            root.path(),
            "node_modules/legacy/package.json",
            br#"{"main":"missing.cjs","type":"module","exports":false}"#,
        );
        put(
            root.path(),
            "node_modules/legacy/feature.js",
            b"throw new Error('live bytes');",
        );
        let replayed = capsule::replay(encoded.bytes(), encoded.digest()).unwrap();
        assert_eq!(replayed.report(), graph.report());
        let registry = PinnedModuleRegistry::new(replayed, &pin).unwrap();
        let legacy = registry
            .lookup(Some(registry.entrypoint()), "#legacy", RequestStyle::Import)
            .unwrap();
        let feature = registry
            .lookup(Some(legacy.id()), "./feature", RequestStyle::Require)
            .unwrap();
        assert_eq!(feature.source(), "module.exports = 42;");
        assert_eq!(feature.origin().path, "node_modules/legacy/feature.js");
        assert_eq!(
            registry
                .lookup(
                    Some(registry.entrypoint()),
                    "./self.mjs",
                    RequestStyle::Import
                )
                .err()
                .unwrap()
                .code,
            "ERR_MODULE_REGISTRY_ROUTE"
        );
        assert_ne!(
            capture(root.path(), "app.mjs", GraphOptions::default())
                .unwrap()
                .report()
                .input_hash,
            pin
        );
    }

    #[test]
    fn typescript_format_captures_nearest_package_scope_and_explicit_extensions() {
        let root = fixture();
        put(root.path(), "esm/package.json", br#"{"type":"module"}"#);
        put(root.path(), "unmarked/package.json", b"{}");
        for (path, expected) in [
            ("value.ts", "commonjs"),
            ("esm/value.ts", "module"),
            ("unmarked/value.ts", "typescript_unspecified"),
            ("forced.mts", "module"),
            ("esm/forced.cts", "commonjs"),
            ("node_modules/unmarked/value.ts", "typescript_unspecified"),
        ] {
            put(root.path(), path, b"const value: number = 42;");
            for mode in [ResolutionMode::Import, ResolutionMode::Require] {
                let captured = run(root.path(), "app.js", &format!("./{path}"), mode);
                assert_eq!(captured.report.format_hint, expected, "{path}");
                assert_eq!(captured.source_bytes(), b"const value: number = 42;");
                assert!(!captured.report.execution_performed);
            }
        }
    }

    #[test]
    fn typescript_scope_is_pinned_without_implicit_extension_or_index_search() {
        let root = fixture();
        put(root.path(), "lib/value.ts", b"const value: number = 42;");
        put(root.path(), "lib/index.ts", b"const value: number = 42;");
        let first = run(root.path(), "app.js", "./lib/value.ts", ResolutionMode::Import);
        assert_eq!(first.report.format_hint, "commonjs");
        assert!(first.report.probes.iter().any(|probe| {
            probe.path == "lib/package.json" && probe.kind == ProbeKind::Missing
        }));
        put(root.path(), "lib/package.json", br#"{"type":"module"}"#);
        let changed = run(root.path(), "app.js", "./lib/value.ts", ResolutionMode::Import);
        assert_eq!(changed.report.format_hint, "module");
        assert_eq!(first.report.content_sha256, changed.report.content_sha256);
        assert_ne!(first.report.input_hash, changed.report.input_hash);
        for request in ["./lib/value", "./lib/"] {
            assert_eq!(
                rejected(root.path(), "app.js", request, ResolutionMode::Require),
                "MODULE_NOT_FOUND"
            );
        }
    }

    #[test]
    fn linked_typescript_uses_physical_package_scope_not_link_extension() {
        let root = fixture();
        put(root.path(), "packages/typed/package.json", br#"{"type":"module"}"#);
        put(root.path(), "packages/typed/value.ts", b"export const value: number = 42;");
        link(root.path(), "entry.cts", "packages/typed/value.ts");
        let captured = linked(
            root.path(), "app.js", "./entry.cts?instance=one", ResolutionMode::Import,
        ).unwrap();
        assert_eq!(captured.report.path, "packages/typed/value.ts");
        assert_eq!(captured.report.format_hint, "module");
        assert_eq!(captured.report.url_suffix, "?instance=one");
    }

    #[test]
    fn contained_workspace_links_require_explicit_policy_and_preserve_export_encapsulation() {
        let root = fixture();
        put(
            root.path(),
            "packages/pkg/package.json",
            br#"{"exports":{".":{"import":"./esm.mjs","require":"./cjs.cjs"},"./private":null}}"#,
        );
        put(root.path(), "packages/pkg/esm.mjs", b"esm");
        put(root.path(), "packages/pkg/cjs.cjs", b"cjs");
        link(root.path(), "node_modules/pkg", "../packages/pkg");
        assert_eq!(
            rejected(root.path(), "app.js", "pkg", ResolutionMode::Import),
            "ERR_UNSUPPORTED_MODULE_FILE"
        );
        for (mode, name) in [
            (ResolutionMode::Import, "esm.mjs"),
            (ResolutionMode::Require, "cjs.cjs"),
        ] {
            let result = linked(root.path(), "app.js", "pkg", mode).unwrap();
            assert_eq!(result.report.path, format!("packages/pkg/{name}"));
            assert_eq!(result.report.symlink_policy, SymlinkPolicy::Contained);
            let probe = result
                .report
                .probes
                .iter()
                .find(|p| p.path == "node_modules/pkg")
                .unwrap();
            assert_eq!(probe.kind, ProbeKind::Symlink);
            assert_eq!(probe.link_target.as_deref(), Some("../packages/pkg"));
            assert_eq!(
                probe.sha256.as_deref(),
                Some(hex::encode(Sha256::digest(b"../packages/pkg")).as_str())
            );
        }
        assert_eq!(
            linked_error(root.path(), "app.js", "pkg/private"),
            "ERR_PACKAGE_PATH_NOT_EXPORTED"
        );
    }

    #[test]
    fn linked_importer_uses_real_dependency_location_and_package_scope() {
        let root = fixture();
        put(
            root.path(),
            "store/pkg/package.json",
            br##"{"type":"module","imports":{"#local":"./local.js"}}"##,
        );
        put(root.path(), "store/pkg/app.js", b"importer");
        put(root.path(), "store/pkg/local.js", b"local");
        put(
            root.path(),
            "store/pkg/node_modules/dep/index.js",
            b"physical dependency",
        );
        put(
            root.path(),
            "node_modules/dep/index.js",
            b"wrong lexical dependency",
        );
        link(root.path(), "node_modules/pkg", "../store/pkg");
        let result = linked(
            root.path(),
            "node_modules/pkg/app.js",
            "dep",
            ResolutionMode::Require,
        )
        .unwrap();
        assert_eq!(result.report.resolved_importer, "store/pkg/app.js");
        assert_eq!(result.report.importer, "node_modules/pkg/app.js");
        assert_eq!(result.source_bytes(), b"physical dependency");
        let result = linked(
            root.path(),
            "node_modules/pkg/app.js",
            "#local",
            ResolutionMode::Import,
        )
        .unwrap();
        assert_eq!(result.report.path, "store/pkg/local.js");
        assert_eq!(result.report.format_hint, "module");
    }

    #[test]
    fn pnpm_style_store_links_preserve_nested_package_instances() {
        let root = fixture();
        for (version, data) in [("1", b"one"), ("2", b"two")] {
            put(
                root.path(),
                &format!("node_modules/.pnpm/dep@{version}/node_modules/dep/index.js"),
                data,
            );
        }
        put(
            root.path(),
            "node_modules/.pnpm/pkg@1/node_modules/pkg/app.js",
            b"importer",
        );
        link(
            root.path(),
            "node_modules/pkg",
            ".pnpm/pkg@1/node_modules/pkg",
        );
        link(
            root.path(),
            "node_modules/dep",
            ".pnpm/dep@2/node_modules/dep",
        );
        link(
            root.path(),
            "node_modules/.pnpm/pkg@1/node_modules/dep",
            "../../dep@1/node_modules/dep",
        );
        let nested = linked(
            root.path(),
            "node_modules/pkg/app.js",
            "dep",
            ResolutionMode::Require,
        )
        .unwrap();
        assert_eq!(nested.source_bytes(), b"one");
        assert_eq!(
            nested.report.path,
            "node_modules/.pnpm/dep@1/node_modules/dep/index.js"
        );
        assert_eq!(
            linked(root.path(), "app.js", "dep", ResolutionMode::Require)
                .unwrap()
                .source_bytes(),
            b"two"
        );
    }

    #[test]
    fn physical_target_controls_format_and_esm_suffix_without_reopening_source() {
        let root = fixture();
        put(root.path(), "real/value.mjs", &[0, 255, 10]);
        link(root.path(), "value.cjs", "real/value.mjs");
        let result = linked(
            root.path(),
            "app.js",
            "./value.cjs?copy#one",
            ResolutionMode::Import,
        )
        .unwrap();
        assert_eq!(result.report.path, "real/value.mjs");
        assert_eq!(result.report.format_hint, "module");
        assert_eq!(result.report.url_suffix, "?copy#one");
        put(root.path(), "other.mjs", b"changed");
        link(root.path(), "replacement", "other.mjs");
        fs::rename(
            root.path().join("replacement"),
            root.path().join("value.cjs"),
        )
        .unwrap();
        assert_eq!(result.source_bytes(), &[0, 255, 10]);
        assert_ne!(
            result.report.input_hash,
            linked(
                root.path(),
                "app.js",
                "./value.cjs?copy#one",
                ResolutionMode::Import
            )
            .unwrap()
            .report
            .input_hash
        );
    }

    #[test]
    fn link_parent_traversal_follows_preceding_links_before_dotdot() {
        let root = fixture();
        fs::create_dir_all(root.path().join("right/nested")).unwrap();
        put(root.path(), "right/value.mjs", b"physical parent");
        put(root.path(), "left/value.mjs", b"wrong lexical parent");
        link(root.path(), "left/junction", "../right/nested");
        link(root.path(), "entry.mjs", "left/junction/../value.mjs");
        assert_eq!(
            linked(root.path(), "app.js", "./entry.mjs", ResolutionMode::Import)
                .unwrap()
                .source_bytes(),
            b"physical parent"
        );
        link(root.path(), "missing.mjs", "absent/../right/value.mjs");
        assert_eq!(
            linked_error(root.path(), "app.js", "./missing.mjs"),
            "ERR_MODULE_NOT_FOUND"
        );
        link(root.path(), "not-dir.mjs", "right/value.mjs/../value.mjs");
        assert_eq!(
            linked_error(root.path(), "app.js", "./not-dir.mjs"),
            "ERR_MODULE_NOT_FOUND"
        );
    }

    #[test]
    fn escapes_absolute_links_reserved_state_and_nonregular_targets_are_refused() {
        let root = fixture();
        for (name, target, code) in [
            ("escape", "../outside.mjs", "ERR_MODULE_OUTSIDE_PROJECT"),
            ("absolute", "/etc/passwd", "ERR_INVALID_MODULE_SYMLINK"),
            ("reserved", ".git/../app.js", "ERR_INVALID_MODULE_SYMLINK"),
            ("beads", ".beads/config", "ERR_INVALID_MODULE_SYMLINK"),
            ("windows", "C:\\outside", "ERR_INVALID_MODULE_SYMLINK"),
        ] {
            link(root.path(), name, target);
            assert_eq!(
                linked_error(root.path(), "app.js", &format!("./{name}")),
                code
            );
        }
        // Even absolute links pointing within the root are outside this portable contract.
        symlink(
            root.path().join("app.js"),
            root.path().join("absolute-inside"),
        )
        .unwrap();
        assert_eq!(
            linked_error(root.path(), "app.js", "./absolute-inside"),
            "ERR_INVALID_MODULE_SYMLINK"
        );
        let directory = File::open(root.path()).unwrap();
        rustix::fs::mkfifoat(&directory, "fifo", Mode::RUSR | Mode::WUSR).unwrap();
        link(root.path(), "fifo-alias", "fifo");
        assert_eq!(
            linked_error(root.path(), "app.js", "./fifo-alias"),
            "ERR_UNSUPPORTED_MODULE_FILE"
        );
    }

    #[test]
    fn nested_link_cannot_escape_then_reenter_the_root() {
        let root = fixture();
        put(root.path(), "inside/value.mjs", b"inside");
        link(root.path(), "inside/up", "../..");
        link(root.path(), "entry", "inside/up/anything/inside/value.mjs");
        assert_eq!(
            linked_error(root.path(), "app.js", "./entry"),
            "ERR_MODULE_OUTSIDE_PROJECT"
        );
    }

    #[test]
    fn symlink_hop_bound_accepts_finite_repeated_links_but_rejects_cycles() {
        let root = fixture();
        put(root.path(), "value.mjs", b"value");
        link(root.path(), "loop", ".");
        assert_eq!(
            linked(
                root.path(),
                "app.js",
                "./loop/loop/value.mjs",
                ResolutionMode::Import
            )
            .unwrap()
            .source_bytes(),
            b"value"
        );
        link(root.path(), "cycle", "cycle");
        assert_eq!(
            linked_error(root.path(), "app.js", "./cycle"),
            "ERR_MODULE_SYMLINK_LOOP"
        );
        for i in 0..MAX_LINK_HOPS {
            link(
                root.path(),
                &format!("chain-{i}"),
                &if i + 1 == MAX_LINK_HOPS {
                    "value.mjs".into()
                } else {
                    format!("chain-{}", i + 1)
                },
            );
        }
        assert_eq!(
            linked(root.path(), "app.js", "./chain-0", ResolutionMode::Import)
                .unwrap()
                .source_bytes(),
            b"value"
        );
        link(root.path(), "too-many", "chain-0");
        assert_eq!(
            linked_error(root.path(), "app.js", "./too-many"),
            "ERR_MODULE_SYMLINK_LOOP"
        );
    }

    #[test]
    fn symlink_policy_and_link_spelling_are_part_of_the_input_pin() {
        let root = fixture();
        put(root.path(), "value.mjs", b"value");
        assert_ne!(
            run(root.path(), "app.js", "./value.mjs", ResolutionMode::Import)
                .report
                .input_hash,
            linked(root.path(), "app.js", "./value.mjs", ResolutionMode::Import)
                .unwrap()
                .report
                .input_hash
        );
        link(root.path(), "alias", "value.mjs");
        let first = linked(root.path(), "app.js", "./alias", ResolutionMode::Import).unwrap();
        link(root.path(), "new-alias", "./value.mjs");
        fs::rename(root.path().join("new-alias"), root.path().join("alias")).unwrap();
        let second = linked(root.path(), "app.js", "./alias", ResolutionMode::Import).unwrap();
        assert_eq!(first.report.path, second.report.path);
        assert_eq!(first.report.content_sha256, second.report.content_sha256);
        assert_ne!(first.report.input_hash, second.report.input_hash);
    }

    #[test]
    fn cached_links_and_negative_probes_are_not_recaptured_during_a_resolution() {
        let root = fixture();
        put(root.path(), "old/value.mjs", b"old");
        put(root.path(), "new/value.mjs", b"new");
        link(root.path(), "alias", "old");
        let directory = File::open(root.path()).unwrap();
        let mut resolver = Resolver {
            entries: BTreeMap::from([("".into(), Rc::new(Entry::Directory(Some(directory))))]),
            manifests: BTreeMap::new(),
            scopes: BTreeMap::new(),
            packages: PackageCache::default(),
            captured: 0,
            conditions: Vec::new(),
            mappings: Vec::new(),
            symlink_policy: SymlinkPolicy::Contained,
            sealed: false,
            observed: BTreeSet::new(),
            url_lookup: false,
        };
        assert!(matches!(
            resolver.probe("alias/absent.mjs").unwrap().as_ref(),
            Entry::Missing
        ));
        link(root.path(), "replacement", "new");
        fs::rename(root.path().join("replacement"), root.path().join("alias")).unwrap();
        put(root.path(), "old/absent.mjs", b"later");
        assert!(matches!(
            resolver.probe("alias/absent.mjs").unwrap().as_ref(),
            Entry::Missing
        ));
        let (path, entry) = resolver.locate("alias/value.mjs").unwrap();
        assert_eq!(path, "old/value.mjs");
        assert!(matches!(entry.as_ref(), Entry::File { bytes, .. } if bytes == b"old"));
    }

    #[test]
    fn link_text_and_expansion_limits_never_return_partial_success() {
        for target in ["x".repeat(MAX_PATH + 1), "a/".repeat(MAX_DEPTH + 1)] {
            assert!(validate_link_target(&target).is_err());
        }
        let root = fixture();
        link(root.path(), "expanding", "expanding/expanding");
        assert_eq!(
            linked_error(root.path(), "app.js", "./expanding"),
            "ERR_MODULE_SYMLINK_LOOP"
        );
        let mut resolver = Resolver {
            entries: BTreeMap::from([(
                "".into(),
                Rc::new(Entry::Directory(Some(File::open(root.path()).unwrap()))),
            )]),
            manifests: BTreeMap::new(),
            scopes: BTreeMap::new(),
            packages: PackageCache::default(),
            captured: MAX_CAPTURE,
            conditions: Vec::new(),
            mappings: Vec::new(),
            symlink_policy: SymlinkPolicy::Contained,
            sealed: false,
            observed: BTreeSet::new(),
            url_lookup: false,
        };
        assert!(resolver.probe("expanding").is_err());
        assert!(!resolver.entries.contains_key("expanding"));
    }

    #[test]
    fn file_and_directory_search_are_distinct_from_strict_esm_paths() {
        let root = fixture();
        put(root.path(), "lib.js", b"javascript");
        put(root.path(), "dir/index.json", b"{}");
        put(
            root.path(),
            "dir.js",
            b"file beats directory unless slash supplied",
        );
        assert_eq!(
            run(root.path(), "app.js", "./lib", ResolutionMode::Require)
                .report
                .path,
            "lib.js"
        );
        assert_eq!(
            rejected(root.path(), "app.js", "./lib", ResolutionMode::Import),
            "ERR_MODULE_NOT_FOUND"
        );
        assert_eq!(
            run(root.path(), "app.js", "./dir", ResolutionMode::Require)
                .report
                .path,
            "dir.js"
        );
        assert_eq!(
            run(root.path(), "app.js", "./dir/", ResolutionMode::Require)
                .report
                .path,
            "dir/index.json"
        );
        assert_eq!(
            rejected(root.path(), "app.js", "./dir", ResolutionMode::Import),
            "ERR_UNSUPPORTED_DIR_IMPORT"
        );
        assert_eq!(
            run(root.path(), "app.js", "./lib.js", ResolutionMode::Import)
                .report
                .format_hint,
            "commonjs"
        );
    }

    #[test]
    fn commonjs_package_directory_requests_use_main_and_index_without_file_shadowing() {
        let root = fixture();
        put(root.path(), "node_modules/legacy.js", b"package file");
        put(
            root.path(),
            "node_modules/legacy/package.json",
            br#"{"main":"entry.cjs"}"#,
        );
        put(
            root.path(),
            "node_modules/legacy/entry.cjs",
            b"package main",
        );
        put(root.path(), "node_modules/legacy/lib.js", b"subpath file");
        put(
            root.path(),
            "node_modules/legacy/lib/package.json",
            br#"{"main":"nested.cjs"}"#,
        );
        put(
            root.path(),
            "node_modules/legacy/lib/nested.cjs",
            b"subpath main",
        );
        put(root.path(), "node_modules/@scope/tool/index.json", b"{}");
        put(root.path(), "node_modules/file-only.js", b"not a directory");
        for (request, expected) in [
            ("legacy", "node_modules/legacy.js"),
            ("legacy/", "node_modules/legacy/entry.cjs"),
            ("legacy/lib", "node_modules/legacy/lib.js"),
            ("legacy/lib/", "node_modules/legacy/lib/nested.cjs"),
            ("@scope/tool/", "node_modules/@scope/tool/index.json"),
        ] {
            let captured = run(root.path(), "app.js", request, ResolutionMode::Require);
            assert_eq!(captured.report.path, expected, "{request}");
            assert_eq!(captured.report.specifier, request);
        }
        assert_eq!(
            rejected(root.path(), "app.js", "file-only/", ResolutionMode::Require),
            "MODULE_NOT_FOUND"
        );
        for request in ["legacy/", "legacy/lib/", "@scope/tool/"] {
            assert_eq!(
                rejected(root.path(), "app.js", request, ResolutionMode::Import),
                "ERR_UNSUPPORTED_DIR_IMPORT",
                "{request}"
            );
        }
    }

    #[test]
    fn package_directory_requests_preserve_export_blocks_and_contained_search() {
        let root = fixture();
        put(root.path(), "packages/app/entry.cjs", b"entry");
        put(
            root.path(),
            "packages/app/node_modules/legacy/sub.js",
            b"skip file",
        );
        put(
            root.path(),
            "node_modules/legacy/sub/index.js",
            b"outer directory",
        );
        assert_eq!(
            run(
                root.path(),
                "packages/app/entry.cjs",
                "legacy/sub/",
                ResolutionMode::Require,
            )
            .report
            .path,
            "node_modules/legacy/sub/index.js"
        );
        put(
            root.path(),
            "packages/app/node_modules/legacy/package.json",
            br#"{"exports":{".":"./entry.cjs","./sub":null}}"#,
        );
        put(
            root.path(),
            "packages/app/node_modules/legacy/entry.cjs",
            b"main",
        );
        for mode in [ResolutionMode::Require, ResolutionMode::Import] {
            for request in ["legacy/", "legacy/sub/"] {
                assert_eq!(
                    rejected(root.path(), "packages/app/entry.cjs", request, mode),
                    "ERR_PACKAGE_PATH_NOT_EXPORTED",
                    "{request}"
                );
            }
            for request in ["legacy//", "legacy/sub//", "legacy/../private/"] {
                assert_eq!(
                    rejected(root.path(), "app.js", request, mode),
                    "ERR_INVALID_MODULE_SPECIFIER",
                    "{request}"
                );
            }
        }
    }

    #[test]
    fn package_directory_routes_replay_frozen_sources_without_new_lookup_authority() {
        use source_graph::registry::{PinnedModuleRegistry, RequestStyle};
        use source_graph::{GraphOptions, LoadKind, capsule, capture};

        let root = fixture();
        put(
            root.path(),
            "app.cjs",
            b"require('legacy/'); require.resolve('legacy/sub/');",
        );
        put(
            root.path(),
            "node_modules/legacy/package.json",
            br#"{"main":"entry.cjs","type":"commonjs"}"#,
        );
        put(
            root.path(),
            "node_modules/legacy/entry.cjs",
            b"module.exports=41;",
        );
        put(
            root.path(),
            "node_modules/legacy/sub/index.js",
            b"module.exports=42;",
        );
        put(
            root.path(),
            "node_modules/legacy.js",
            b"throw new Error('shadow file');",
        );
        put(
            root.path(),
            "node_modules/legacy/sub.js",
            b"throw new Error('shadow subpath');",
        );

        let captured = capture(root.path(), "app.cjs", GraphOptions::default()).unwrap();
        assert!(captured.report().fully_resolved);
        assert_eq!(captured.report().modules.len(), 2);
        assert_eq!(captured.report().resolution_targets.len(), 1);
        assert_eq!(captured.report().edges.iter().map(|edge| edge.kind).collect::<Vec<_>>(),
            [LoadKind::Require, LoadKind::RequireResolve]);
        let requests: Vec<_> = captured
            .report()
            .edges
            .iter()
            .map(|edge| {
                assert_eq!(
                    edge.conditions,
                    ResolutionMode::Require.default_conditions()
                );
                edge.specifier.as_deref().unwrap()
            })
            .collect();
        assert_eq!(requests, ["legacy/", "legacy/sub/"]);
        assert!(!captured.report().probes.iter().any(|probe| matches!(
            probe.path.as_str(),
            "node_modules/legacy.js" | "node_modules/legacy/sub.js"
        )));
        let pin = captured.report().input_hash.clone();
        let encoded = capsule::encode(&captured).unwrap();
        put(
            root.path(),
            "node_modules/legacy/entry.cjs",
            b"throw new Error('live main');",
        );
        put(
            root.path(),
            "node_modules/legacy/sub/index.js",
            b"throw new Error('live subpath');",
        );
        put(
            root.path(),
            "node_modules/legacy/package.json",
            br#"{"exports":{}}"#,
        );

        let replayed = capsule::replay(encoded.bytes(), encoded.digest()).unwrap();
        assert_eq!(replayed.report(), captured.report());
        let registry = PinnedModuleRegistry::new(replayed, &pin).unwrap();
        assert_eq!(registry.summary().routes, 1);
        assert_eq!(registry.summary().resolution_routes, 1);
        let module = registry
            .lookup(Some(registry.entrypoint()), "legacy/", RequestStyle::Require)
            .unwrap();
        assert_eq!(module.origin().path, "node_modules/legacy/entry.cjs");
        assert_eq!(module.source(), "module.exports=41;");
        let metadata = registry
            .lookup_resolution(Some(registry.entrypoint()), "legacy/sub/")
            .unwrap();
        assert_eq!(metadata.origin().path, "node_modules/legacy/sub/index.js");
        assert!(registry.lookup(Some(registry.entrypoint()), "legacy/sub/", RequestStyle::Require)
            .is_err());
        for id in [module.id(), metadata.id()] {
            assert_eq!(
                registry
                    .lookup(
                        Some(registry.entrypoint()),
                        id,
                        RequestStyle::Require
                    )
                    .err()
                    .unwrap()
                    .code,
                "ERR_MODULE_REGISTRY_ROUTE"
            );
        }
        for (request, style) in [
            ("legacy", RequestStyle::Require),
            ("legacy/sub", RequestStyle::Require),
            ("legacy/", RequestStyle::Import),
            ("./node_modules/legacy/sub/index.js", RequestStyle::Require),
        ] {
            assert_eq!(
                registry
                    .lookup(Some(registry.entrypoint()), request, style)
                    .err()
                    .unwrap()
                    .code,
                "ERR_MODULE_REGISTRY_ROUTE"
            );
        }
        let changed = capture(root.path(), "app.cjs", GraphOptions::default()).unwrap();
        assert_eq!(
            PinnedModuleRegistry::new(changed, &pin).err().unwrap().code,
            "ERR_MODULE_REGISTRY_PIN_MISMATCH"
        );
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
        for (mode, file) in [
            (ResolutionMode::Import, "esm.mjs"),
            (ResolutionMode::Require, "cjs.cjs"),
        ] {
            let result = run(root.path(), "packages/api/app.js", "pkg", mode);
            assert_eq!(
                result.report.path,
                format!("packages/api/node_modules/pkg/{file}")
            );
            assert_eq!(result.report.mappings.len(), 1);
            assert_eq!(
                rejected(root.path(), "packages/api/app.js", "pkg/private", mode),
                "ERR_PACKAGE_PATH_NOT_EXPORTED"
            );
        }
    }

    #[test]
    fn self_references_and_external_imports_use_the_owning_package_scope() {
        let root = fixture();
        put(root.path(), "package.json", br##"{"name":"application","exports":{"./feature":"./feature.mjs"},"imports":{"#local":"./feature.mjs","#external":"@scope/pkg/sub"}}"##);
        put(root.path(), "feature.mjs", b"module");
        put(
            root.path(),
            "node_modules/@scope/pkg/package.json",
            br#"{"exports":{"./sub":"./result.cjs"}}"#,
        );
        put(
            root.path(),
            "node_modules/@scope/pkg/result.cjs",
            b"external",
        );
        for request in ["application/feature", "#local"] {
            assert_eq!(
                run(root.path(), "app.js", request, ResolutionMode::Require)
                    .report
                    .path,
                "feature.mjs"
            );
        }
        let result = run(root.path(), "app.js", "#external", ResolutionMode::Import);
        assert_eq!(result.report.path, "node_modules/@scope/pkg/result.cjs");
        assert_eq!(result.report.mappings.len(), 2);
        assert_eq!(result.source_bytes(), b"external");
    }

    #[test]
    fn dependency_without_manifest_cannot_inherit_application_imports_or_type() {
        let root = fixture();
        put(
            root.path(),
            "package.json",
            br##"{"type":"module","imports":{"#secret":"./secret.js"}}"##,
        );
        put(root.path(), "secret.js", b"private");
        put(root.path(), "node_modules/pkg/app.js", b"importer");
        put(root.path(), "node_modules/pkg/value.js", b"value");
        assert_eq!(
            rejected(
                root.path(),
                "node_modules/pkg/app.js",
                "#secret",
                ResolutionMode::Import
            ),
            "ERR_PACKAGE_IMPORT_NOT_DEFINED"
        );
        assert_eq!(
            run(
                root.path(),
                "node_modules/pkg/app.js",
                "./value.js",
                ResolutionMode::Import
            )
            .report
            .format_hint,
            "javascript_unspecified"
        );
    }

    #[test]
    fn captured_source_survives_path_mutation_without_a_second_read() {
        let root = fixture();
        put(root.path(), "value.cjs", &[0, 255, 1, 10]);
        let result = run(
            root.path(),
            "app.js",
            "./value.cjs",
            ResolutionMode::Require,
        );
        put(root.path(), "value.cjs", b"replacement");
        assert_eq!(result.source_bytes(), &[0, 255, 1, 10]);
        assert_eq!(
            result.report.content_sha256,
            hex::encode(Sha256::digest(result.source_bytes()))
        );
        assert_ne!(
            result.report.input_hash,
            run(
                root.path(),
                "app.js",
                "./value.cjs",
                ResolutionMode::Require
            )
            .report
            .input_hash
        );
    }

    #[test]
    fn successful_map_selection_never_falls_back_for_missing_files() {
        let root = fixture();
        put(
            root.path(),
            "node_modules/pkg/package.json",
            br#"{"exports":["./missing","./available.js"],"main":"available.js"}"#,
        );
        put(
            root.path(),
            "node_modules/pkg/missing.js",
            b"wrong inferred extension",
        );
        put(
            root.path(),
            "node_modules/pkg/available.js",
            b"wrong fallback",
        );
        assert_eq!(
            rejected(root.path(), "app.js", "pkg", ResolutionMode::Require),
            "MODULE_NOT_FOUND"
        );
        assert_eq!(
            rejected(root.path(), "app.js", "pkg", ResolutionMode::Import),
            "ERR_MODULE_NOT_FOUND"
        );
    }

    #[test]
    fn legacy_main_and_index_are_resolved_without_recursive_directory_loops() {
        let root = fixture();
        put(
            root.path(),
            "node_modules/pkg/package.json",
            br#"{"main":"lib"}"#,
        );
        put(root.path(), "node_modules/pkg/lib/index.json", b"{}");
        for mode in [ResolutionMode::Import, ResolutionMode::Require] {
            assert_eq!(
                run(root.path(), "app.js", "pkg", mode).report.path,
                "node_modules/pkg/lib/index.json"
            );
        }
        put(
            root.path(),
            "node_modules/pkg/package.json",
            br#"{"main":"."}"#,
        );
        assert_eq!(
            rejected(root.path(), "app.js", "pkg", ResolutionMode::Require),
            "MODULE_NOT_FOUND"
        );
        put(root.path(), "node_modules/pkg/index.js", b"root index");
        assert_eq!(
            run(root.path(), "app.js", "pkg", ResolutionMode::Require)
                .report
                .path,
            "node_modules/pkg/index.js"
        );
    }

    #[test]
    fn urls_preserve_identity_suffix_and_do_not_decode_commonjs_file_names() {
        let root = fixture();
        put(root.path(), "space name.mjs", b"ESM");
        put(root.path(), "space%20name.cjs", b"literal");
        let result = run(
            root.path(),
            "app.js",
            "./space%20name.mjs?mode=one#part",
            ResolutionMode::Import,
        );
        assert_eq!(result.report.path, "space name.mjs");
        assert_eq!(result.report.url_suffix, "?mode=one#part");
        assert_eq!(
            run(
                root.path(),
                "app.js",
                "./space%20name.cjs",
                ResolutionMode::Require
            )
            .source_bytes(),
            b"literal"
        );
        assert_eq!(
            rejected(root.path(), "app.js", "./a%2fb.js", ResolutionMode::Import),
            "ERR_INVALID_MODULE_SPECIFIER"
        );
    }

    #[test]
    fn missing_shadow_candidates_and_complete_condition_context_are_hashed() {
        let root = fixture();
        put(root.path(), "lib/index.js", b"same bytes");
        let before = run(root.path(), "app.js", "./lib", ResolutionMode::Require);
        assert!(
            before
                .report
                .probes
                .iter()
                .any(|p| p.path == "lib.js" && p.kind == ProbeKind::Missing)
        );
        put(root.path(), "lib.js", b"same bytes");
        let after = run(root.path(), "app.js", "./lib", ResolutionMode::Require);
        assert_ne!(before.report.input_hash, after.report.input_hash);
        let custom = resolve(
            root.path(),
            "app.js",
            "./lib",
            ResolutionMode::Require,
            &["custom".into()],
        )
        .unwrap();
        assert_ne!(custom.report.input_hash, after.report.input_hash);
        assert_eq!(custom.report.path, after.report.path);
    }

    #[test]
    fn malformed_metadata_and_symlinks_cannot_be_silently_skipped() {
        let root = fixture();
        put(
            root.path(),
            "node_modules/pkg/package.json",
            br#"{"exports":"./one.js","exports":"./two.js"}"#,
        );
        assert_eq!(
            rejected(root.path(), "app.js", "pkg", ResolutionMode::Import),
            "ERR_INVALID_PACKAGE_CONFIG"
        );
        put(root.path(), "outside.js", b"value");
        symlink("outside.js", root.path().join("alias.js")).unwrap();
        assert_eq!(
            rejected(root.path(), "app.js", "./alias.js", ResolutionMode::Import),
            "ERR_UNSUPPORTED_MODULE_FILE"
        );
        symlink("node_modules", root.path().join("linked")).unwrap();
        assert_eq!(
            rejected(
                root.path(),
                "app.js",
                "./linked/pkg/file.js",
                ResolutionMode::Import
            ),
            "ERR_UNSUPPORTED_MODULE_FILE"
        );
    }

    #[test]
    fn escape_reserved_paths_invalid_importers_and_oversize_inputs_fail_closed() {
        let root = fixture();
        assert_eq!(
            rejected(
                root.path(),
                "app.js",
                "../outside.js",
                ResolutionMode::Import
            ),
            "ERR_MODULE_OUTSIDE_PROJECT"
        );
        assert_eq!(
            rejected(
                root.path(),
                "app.js",
                "./.git/config",
                ResolutionMode::Require
            ),
            "ERR_INVALID_MODULE_SPECIFIER"
        );
        assert_eq!(
            rejected(root.path(), "./app.js", "./app.js", ResolutionMode::Import),
            "ERR_INVALID_MODULE_SPECIFIER"
        );
        assert_eq!(
            rejected(root.path(), "absent.js", "./app.js", ResolutionMode::Import),
            "ERR_MODULE_NOT_FOUND"
        );
        put(root.path(), "large.js", &vec![b'x'; MAX_FILE + 1]);
        assert_eq!(
            rejected(root.path(), "app.js", "./large.js", ResolutionMode::Import),
            "ERR_MODULE_RESOLUTION_LIMIT"
        );
        assert!(package_parts("pkg/../other", false).is_err());
    }

    #[test]
    fn commonjs_hash_requests_without_import_maps_capture_actual_package_search() {
        for manifest in [None, Some("{}"), Some(r#"{"imports":null}"#)] {
            let root = tempfile::tempdir().unwrap();
            put(
                root.path(),
                "app.cjs",
                b"require('#installed'); require('#absent');",
            );
            if let Some(manifest) = manifest {
                put(root.path(), "package.json", manifest.as_bytes());
            }
            put(
                root.path(),
                "node_modules/#installed/package.json",
                br#"{"main":"index.cjs"}"#,
            );
            put(
                root.path(),
                "node_modules/#installed/index.cjs",
                b"module.exports = 42;",
            );
            let resolved = resolve(
                root.path(),
                "app.cjs",
                "#installed",
                ResolutionMode::Require,
                &ResolutionMode::Require.default_conditions(),
            )
            .unwrap();
            assert_eq!(resolved.report.path, "node_modules/#installed/index.cjs");
            assert_eq!(resolved.source_bytes(), b"module.exports = 42;");
            assert!(resolved.report.mappings.is_empty());
            assert_eq!(
                rejected(root.path(), "app.cjs", "#installed", ResolutionMode::Import),
                "ERR_PACKAGE_IMPORT_NOT_DEFINED"
            );
            let graph = source_graph::capture(
                root.path(),
                "app.cjs",
                source_graph::GraphOptions::default(),
            )
            .unwrap();
            let absent = graph
                .report()
                .edges
                .iter()
                .find(|edge| edge.specifier.as_deref() == Some("#absent"))
                .unwrap();
            assert_eq!(absent.error.as_ref().unwrap().code, "MODULE_NOT_FOUND");
            assert!(
                graph
                    .report()
                    .probes
                    .iter()
                    .any(|probe| probe.path == "node_modules/#absent"
                        && probe.kind == ProbeKind::Missing)
            );
            let pin = graph.report().input_hash.clone();
            let encoded = source_graph::capsule::encode(&graph).unwrap();
            put(
                root.path(),
                "node_modules/#absent/index.js",
                b"module.exports = 99;",
            );
            let replayed =
                source_graph::capsule::replay(encoded.bytes(), encoded.digest()).unwrap();
            let registry = source_graph::registry::PinnedModuleRegistry::new(replayed, &pin)
                .ok()
                .unwrap();
            assert_eq!(
                registry
                    .lookup(
                        Some(registry.entrypoint()),
                        "#absent",
                        source_graph::registry::RequestStyle::Require,
                    )
                    .err()
                    .unwrap()
                    .code,
                "MODULE_NOT_FOUND"
            );

            // An explicit map, even an empty one, encapsulates private imports
            // and prevents falling through to an installed '#'-named package.
            put(root.path(), "package.json", br#"{"imports":{}}"#);
            assert_eq!(
                rejected(
                    root.path(),
                    "app.cjs",
                    "#installed",
                    ResolutionMode::Require
                ),
                "ERR_PACKAGE_IMPORT_NOT_DEFINED"
            );
        }
        assert!(package_parts("#installed", false).is_err());
        assert!(package_parts("#installed/../escape", true).is_err());
    }

    #[test]
    fn package_import_builtin_targets_preserve_node_loader_boundaries() {
        let root = fixture();
        put(
            root.path(),
            "package.json",
            br##"{"imports":{"#path":"path","#conditional":{"import":"path/posix","require":"path/win32"},"#prefixed":"node:path","#blocked":null}}"##,
        );
        put(
            root.path(),
            "node_modules/path/index.js",
            b"must not shadow a builtin",
        );
        for specifier in ["#path", "#conditional"] {
            assert_eq!(
                rejected(root.path(), "app.js", specifier, ResolutionMode::Import),
                "ERR_RUNTIME_MODULE_REQUIRED"
            );
            assert_eq!(
                rejected(root.path(), "app.js", specifier, ResolutionMode::Require),
                "ERR_INVALID_URL_SCHEME"
            );
        }
        // PACKAGE_TARGET_RESOLVE rejects URL targets, including node: URLs.
        // The supported spelling inside imports is the bare builtin name.
        for mode in [ResolutionMode::Import, ResolutionMode::Require] {
            assert_eq!(
                rejected(root.path(), "app.js", "#prefixed", mode),
                "ERR_INVALID_PACKAGE_TARGET"
            );
            assert_eq!(
                rejected(root.path(), "app.js", "#blocked", mode),
                "ERR_PACKAGE_IMPORT_NOT_DEFINED"
            );
        }
    }

    #[test]
    fn runtime_builtins_are_never_shadowed_by_installed_packages() {
        let root = fixture();
        put(root.path(), "node_modules/fs/index.js", b"malicious shadow");
        for request in [
            "fs",
            "fs/promises",
            "_http_agent",
            "_stream_wrap",
            "_tls_wrap",
            "node:fs",
            "node:not-in-any-runtime",
        ] {
            put(
                root.path(),
                &format!("node_modules/{request}/index.js"),
                b"malicious shadow",
            );
            assert_eq!(
                rejected(root.path(), "app.js", request, ResolutionMode::Require),
                "ERR_RUNTIME_MODULE_REQUIRED"
            );
        }
    }
}
