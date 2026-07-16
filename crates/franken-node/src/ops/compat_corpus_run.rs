//! bd-kfseq: genuine compatibility-corpus lockstep runner.
//!
//! Walks the committed compat-corpus fixture tree (one
//! `compat-corpus-fixture-v1` manifest per Node API family), executes every
//! case on TWO real runtimes — bun as the independent reference leg and the
//! native in-process franken_engine (a fresh `franken-node run
//! --console-only` subprocess of this very binary) — and adjudicates each
//! case through the N-version [`crate::runtime::nversion_oracle::RuntimeOracle`].
//!
//! The emitted `artifacts/13/compatibility_corpus_results.json` document
//! carries per-test statuses that were actually measured, a recomputable
//! `ccg_corpus_result_digest_v1` content digest binding those statuses, and
//! the `lockstep-oracle-run` provenance the close-condition L1 leg requires
//! (bd-ihusm). Gate evaluation (overall threshold, per-family floor, band
//! floors, ratchet) is computed honestly from the measured statuses — a run
//! below the bar produces a truthful `release_blocked = true` artifact, never
//! a synthesized pass.
//!
//! Fail-closed: a missing bun binary, an unreadable corpus, or any
//! infrastructure failure aborts the run without writing an artifact.
//! Behavioral outcomes (divergent output, a refused or crashed franken leg, a
//! hung case) are recorded as `fail` — `error` is reserved for infrastructure
//! and never appears in an emitted artifact.

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
#[cfg(feature = "engine")]
use std::io::Write;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[cfg(unix)]
use rustix::fd::OwnedFd;
#[cfg(unix)]
use rustix::fs::{
    AtFlags, Dir, FileType as DescriptorFileType, Mode, OFlags, Stat, fstat, open, openat, statat,
};

use crate::ops::close_condition::{
    COMPATIBILITY_CORPUS_ONLINE_PROVENANCE, compute_compatibility_corpus_result_digest,
};

/// Manifest schema accepted for per-family corpus fixture directories.
pub const CORPUS_FIXTURE_SCHEMA_VERSION: &str = "compat-corpus-fixture-v1";
/// Upper bound on total cases across every family manifest.
pub const MAX_CORPUS_TOTAL_CASES: usize = 4_096;
/// Upper bound for one family manifest read (parser-bomb defense).
pub const MAX_FAMILY_MANIFEST_BYTES: u64 = 1_048_576;
/// Upper bound for one case source read (parser-bomb defense).
pub const MAX_CASE_FILE_BYTES: usize = 262_144;
/// Upper bound on underscore-prefixed support files staged for one family.
pub const MAX_SUPPORT_FILES_PER_FAMILY: usize = 64;
/// Upper bound on support-file path/count overhead across the whole corpus.
pub const MAX_SUPPORT_FILES_TOTAL: usize = 128;
/// Upper bound on the combined support-file bytes captured in one snapshot.
pub const MAX_SUPPORT_TOTAL_BYTES: usize = 4_194_304;
/// Upper bound on all manifest, case, and support bytes held by one snapshot.
pub const MAX_CORPUS_SNAPSHOT_BYTES: usize = 134_217_728;
/// Upper bound on captured bytes per runtime leg (stdout + stderr).
pub const MAX_LEG_OUTPUT_BYTES: usize = 1_048_576;
/// Environment override for the artifact's `generated_at_utc` (deterministic
/// test runs), mirroring the close-condition timestamp override pattern.
pub const CORPUS_TIMESTAMP_ENV: &str = "FRANKEN_NODE_CORPUS_TIMESTAMP_UTC";

const VALID_BANDS: [&str; 3] = ["core", "high-value", "edge"];
const VALID_RISK_BANDS: [&str; 4] = ["critical", "high", "medium", "low"];
const DEFAULT_OVERALL_MIN_PCT: f64 = 95.0;
const DEFAULT_FAMILY_FLOOR_PCT: f64 = 80.0;
const DEFAULT_BAND_FLOORS: [(&str, f64); 3] =
    [("core", 99.0), ("edge", 90.0), ("high-value", 95.0)];
const TRACKING_REASON_MAX_CHARS: usize = 200;

/// One case entry in a family manifest.
#[derive(Clone, Debug, Deserialize)]
pub struct CorpusCaseSpec {
    pub id: String,
    pub file: String,
    #[serde(default)]
    pub api: Option<String>,
    #[serde(default)]
    pub requirement: Option<String>,
    pub band: String,
    pub risk_band: String,
}

/// One per-family corpus fixture manifest (`compat-corpus-fixture-v1`).
#[derive(Clone, Debug, Deserialize)]
pub struct CorpusFamilyManifest {
    pub schema_version: String,
    pub api_family: String,
    #[serde(default)]
    pub investigation_bead_id: Option<String>,
    pub cases: Vec<CorpusCaseSpec>,
}

/// A fully resolved runnable case.
#[derive(Clone, Debug)]
pub struct ResolvedCase {
    pub test_id: String,
    pub api_family: String,
    pub band: String,
    pub risk_band: String,
    pub source_path: PathBuf,
    pub investigation_bead_id: Option<String>,
}

/// Immutable executable-input snapshot shared by versioning and both runtime
/// legs. All filesystem reads happen while constructing this value.
#[derive(Debug)]
pub struct CorpusSnapshot {
    manifests: Vec<SnapshotManifest>,
    cases: Vec<SnapshotCase>,
    families: BTreeMap<String, SnapshotFamily>,
}

#[derive(Debug)]
struct SnapshotManifest {
    corpus_relative_path: String,
    bytes: Vec<u8>,
}

#[derive(Debug)]
struct SnapshotCase {
    case: ResolvedCase,
    family_key: String,
    corpus_relative_path: String,
    staged_relative_path: PathBuf,
    source_bytes: Vec<u8>,
}

#[derive(Debug)]
struct SnapshotFamily {
    support_files: Vec<SnapshotSupportFile>,
}

#[derive(Debug)]
struct SnapshotSupportFile {
    corpus_relative_path: String,
    staged_relative_path: PathBuf,
    bytes: Vec<u8>,
}

/// Measured outcome for one case.
#[derive(Clone, Debug)]
pub struct CaseOutcome {
    pub test_id: String,
    pub api_family: String,
    pub band: String,
    pub risk_band: String,
    /// `pass` or `fail` — the runner never emits `error`/`skip` statuses;
    /// infrastructure failures abort the run instead (fail-closed).
    pub status: &'static str,
    /// Populated for `fail` outcomes; feeds `failing_tests_tracking`.
    pub failure_reason: Option<String>,
    pub investigation_bead_id: Option<String>,
}

impl CorpusSnapshot {
    /// Parsed case metadata captured from the same descriptor-rooted input
    /// snapshot as the executable bytes.
    pub fn resolved_cases(&self) -> impl ExactSizeIterator<Item = &ResolvedCase> {
        self.cases.iter().map(|case| &case.case)
    }
}

/// Open, parse, and capture the complete corpus through one pinned root
/// directory descriptor. No ambient pathname is reopened after the root is
/// established, and every descendant component is opened with no-follow
/// semantics before its descriptor identity is verified.
///
/// This is a bounded sequential capture, not an atomic multi-file filesystem
/// snapshot. Each opened file is checked for ordinary in-place mutation using
/// its pre/post-read descriptor fingerprint.
#[cfg(unix)]
pub fn capture_corpus(corpus_root: &Path) -> Result<CorpusSnapshot> {
    capture_corpus_with_probe(corpus_root, &mut NoopCaptureProbe)
}

/// Unsupported targets refuse before touching the corpus. A reviewed native
/// handle/reparse-point implementation is required before enabling this path.
#[cfg(not(unix))]
pub fn capture_corpus(_corpus_root: &Path) -> Result<CorpusSnapshot> {
    bail!(
        "descriptor-relative no-follow corpus capture is unavailable on this target; refusing to run"
    )
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CaptureKind {
    Root,
    FamilyDirectory,
    Manifest,
    CaseParent,
    Case,
    SupportDirectory,
    Support,
}

#[cfg(unix)]
trait CaptureProbe {
    fn after_stat_before_open(&mut self, _kind: CaptureKind, _relative_path: &Path) -> Result<()> {
        Ok(())
    }

    fn after_open_before_read(&mut self, _kind: CaptureKind, _relative_path: &Path) -> Result<()> {
        Ok(())
    }

    fn after_first_read(&mut self, _kind: CaptureKind, _relative_path: &Path) -> Result<()> {
        Ok(())
    }

    fn after_root_open(&mut self, _corpus_root: &Path) -> Result<()> {
        Ok(())
    }
}

#[cfg(unix)]
struct NoopCaptureProbe;

#[cfg(unix)]
impl CaptureProbe for NoopCaptureProbe {}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DescriptorIdentity {
    device: u64,
    inode: u64,
    file_type: DescriptorFileType,
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DescriptorFingerprint {
    identity: DescriptorIdentity,
    size: u64,
    modified_seconds: i128,
    modified_nanoseconds: i128,
    changed_seconds: i128,
    changed_nanoseconds: i128,
}

#[cfg(unix)]
#[derive(Debug)]
struct ObservedDirectoryEntry {
    name: String,
    inode: u64,
}

#[cfg(unix)]
#[derive(Debug)]
struct OpenCorpusFamily {
    key: String,
    descriptor: OwnedFd,
}

#[cfg(unix)]
fn capture_corpus_with_probe(
    corpus_root: &Path,
    probe: &mut impl CaptureProbe,
) -> Result<CorpusSnapshot> {
    let (root_descriptor, root_identity) = open_corpus_root(corpus_root, probe)?;
    probe.after_root_open(corpus_root)?;
    let mut directory_identities = BTreeMap::from([(PathBuf::new(), root_identity)]);

    let mut open_families = Vec::new();
    for entry in read_descriptor_directory(&root_descriptor, "corpus root")? {
        let relative = PathBuf::from(&entry.name);
        let expected = stat_descriptor_entry(&root_descriptor, &entry.name, &relative)?;
        let expected_fingerprint = descriptor_fingerprint(&expected)?;
        if entry.inode != 0 && entry.inode != expected_fingerprint.identity.inode {
            bail!(
                "corpus root entry `{}` changed during corpus capture",
                entry.name
            );
        }
        match expected_fingerprint.identity.file_type {
            DescriptorFileType::Directory => {
                let descriptor = open_verified_directory(
                    &root_descriptor,
                    &entry.name,
                    &relative,
                    CaptureKind::FamilyDirectory,
                    Some(&expected),
                    probe,
                    &mut directory_identities,
                )?;
                open_families.push(OpenCorpusFamily {
                    key: entry.name,
                    descriptor,
                });
            }
            DescriptorFileType::RegularFile => {}
            DescriptorFileType::Symlink => {
                bail!(
                    "corpus root contains a symlink entry: {}",
                    corpus_root.join(entry.name).display()
                );
            }
            _ => {
                bail!(
                    "corpus root contains a nonregular entry: {}",
                    corpus_root.join(entry.name).display()
                );
            }
        }
    }

    let mut snapshot_bytes = 0usize;
    let mut manifests = Vec::with_capacity(open_families.len());
    let mut snapshot_cases = Vec::new();
    let mut seen_ids = BTreeSet::new();
    let mut seen_paths = BTreeSet::new();
    let mut staged_paths = BTreeMap::<String, BTreeSet<PathBuf>>::new();
    let mut support_dirs = BTreeMap::<String, BTreeSet<PathBuf>>::new();

    for family in &open_families {
        let manifest_relative = Path::new(&family.key).join("manifest.json");
        let manifest_bytes = read_verified_regular_file(
            &family.descriptor,
            "manifest.json",
            &manifest_relative,
            CaptureKind::Manifest,
            MAX_FAMILY_MANIFEST_BYTES
                .try_into()
                .context("manifest byte bound does not fit usize")?,
            None,
            probe,
        )
        .with_context(|| {
            format!(
                "corpus family directory {} has no readable regular non-symlink manifest.json",
                corpus_root.join(&family.key).display()
            )
        })?;
        add_bounded_bytes(
            &mut snapshot_bytes,
            manifest_bytes.len(),
            MAX_CORPUS_SNAPSHOT_BYTES,
            "corpus executable-input snapshot",
        )?;
        let manifest: CorpusFamilyManifest =
            serde_json::from_slice(&manifest_bytes).with_context(|| {
                format!(
                    "parse corpus manifest {}",
                    corpus_root.join(&manifest_relative).display()
                )
            })?;
        validate_family_manifest(&manifest, corpus_root, &manifest_relative)?;
        manifests.push(SnapshotManifest {
            corpus_relative_path: normalized_relative_path(&manifest_relative, "corpus manifest")?,
            bytes: manifest_bytes,
        });

        for case in &manifest.cases {
            if !seen_ids.insert(case.id.clone()) {
                bail!("duplicate corpus case id `{}`", case.id);
            }
            validate_case_spec(case)?;
            let staged_relative_path = validated_case_relative_path(&case.id, &case.file)?;
            let corpus_relative_path = Path::new(&family.key).join(&staged_relative_path);
            if !seen_paths.insert(corpus_relative_path.clone()) {
                bail!(
                    "corpus case file appears twice across manifests: {}",
                    corpus_root.join(&corpus_relative_path).display()
                );
            }
            if snapshot_cases.len() >= MAX_CORPUS_TOTAL_CASES {
                bail!("corpus exceeds the {MAX_CORPUS_TOTAL_CASES}-case bound; refusing to run");
            }
            let source_bytes = read_verified_relative_file(
                &family.descriptor,
                &staged_relative_path,
                &corpus_relative_path,
                CaptureKind::CaseParent,
                CaptureKind::Case,
                MAX_CASE_FILE_BYTES,
                probe,
                &mut directory_identities,
            )
            .with_context(|| {
                format!(
                    "corpus case `{}` fixture missing or unsafe: {}",
                    case.id,
                    corpus_root.join(&corpus_relative_path).display()
                )
            })?;
            add_bounded_bytes(
                &mut snapshot_bytes,
                source_bytes.len(),
                MAX_CORPUS_SNAPSHOT_BYTES,
                "corpus executable-input snapshot",
            )?;

            if !staged_paths
                .entry(family.key.clone())
                .or_default()
                .insert(staged_relative_path.clone())
            {
                bail!(
                    "multiple corpus cases stage to `{}` in family `{}`",
                    staged_relative_path.display(),
                    family.key
                );
            }
            let family_support_dirs = support_dirs.entry(family.key.clone()).or_default();
            family_support_dirs.insert(PathBuf::new());
            let mut support_parent = staged_relative_path
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty());
            while let Some(relative_parent) = support_parent {
                let next_parent = relative_parent
                    .parent()
                    .filter(|ancestor| !ancestor.as_os_str().is_empty());
                family_support_dirs.insert(relative_parent.to_path_buf());
                support_parent = next_parent;
            }

            snapshot_cases.push(SnapshotCase {
                case: ResolvedCase {
                    test_id: case.id.clone(),
                    api_family: manifest.api_family.clone(),
                    band: case.band.clone(),
                    risk_band: case.risk_band.clone(),
                    source_path: corpus_root.join(&corpus_relative_path),
                    investigation_bead_id: manifest.investigation_bead_id.clone(),
                },
                family_key: family.key.clone(),
                corpus_relative_path: normalized_relative_path(
                    &corpus_relative_path,
                    "corpus case",
                )?,
                staged_relative_path,
                source_bytes,
            });
        }
    }

    if snapshot_cases.is_empty() {
        bail!(
            "corpus root {} contains no family manifests",
            corpus_root.display()
        );
    }

    let mut support_total_bytes = 0usize;
    let mut support_file_count = 0usize;
    let mut families = BTreeMap::new();
    for family in &open_families {
        let family_support_dirs = support_dirs
            .remove(&family.key)
            .context("snapshot family support-directory set is missing")?;
        let family_staged_paths = staged_paths
            .get_mut(&family.key)
            .context("snapshot family staging set is missing")?;
        let mut support_files = Vec::new();
        for relative_dir in family_support_dirs {
            let corpus_relative_dir = Path::new(&family.key).join(&relative_dir);
            let support_descriptor = open_verified_relative_directory(
                &family.descriptor,
                &relative_dir,
                &corpus_relative_dir,
                CaptureKind::SupportDirectory,
                probe,
                &mut directory_identities,
            )?;
            for entry in read_descriptor_directory(
                &support_descriptor,
                &format!("corpus support directory {}", corpus_relative_dir.display()),
            )? {
                if !entry.name.starts_with('_') {
                    continue;
                }
                let staged_relative_path = relative_dir.join(&entry.name);
                let corpus_relative = Path::new(&family.key).join(&staged_relative_path);
                let expected =
                    stat_descriptor_entry(&support_descriptor, &entry.name, &corpus_relative)?;
                let fingerprint = descriptor_fingerprint(&expected)?;
                if entry.inode != 0 && entry.inode != fingerprint.identity.inode {
                    bail!(
                        "corpus support input `{}` changed during corpus capture",
                        corpus_relative.display()
                    );
                }
                match fingerprint.identity.file_type {
                    DescriptorFileType::Directory => continue,
                    DescriptorFileType::RegularFile => {}
                    _ => {
                        bail!(
                            "corpus support input is not a regular non-symlink file: {}",
                            corpus_root.join(&corpus_relative).display()
                        );
                    }
                }
                if support_files.len() >= MAX_SUPPORT_FILES_PER_FAMILY {
                    bail!(
                        "corpus family `{}` exceeds its support-file bound; maximum is {MAX_SUPPORT_FILES_PER_FAMILY}",
                        family.key,
                    );
                }
                if support_file_count >= MAX_SUPPORT_FILES_TOTAL {
                    bail!("corpus has more than {MAX_SUPPORT_FILES_TOTAL} support files");
                }
                if !family_staged_paths.insert(staged_relative_path.clone()) {
                    bail!(
                        "corpus case/support staging collision at `{}` in family `{}`",
                        staged_relative_path.display(),
                        family.key
                    );
                }
                let bytes = read_verified_regular_file(
                    &support_descriptor,
                    &entry.name,
                    &corpus_relative,
                    CaptureKind::Support,
                    MAX_CASE_FILE_BYTES,
                    Some(&expected),
                    probe,
                )?;
                support_file_count = support_file_count
                    .checked_add(1)
                    .context("corpus support-file count overflow")?;
                add_bounded_bytes(
                    &mut support_total_bytes,
                    bytes.len(),
                    MAX_SUPPORT_TOTAL_BYTES,
                    "corpus support-file snapshot",
                )?;
                add_bounded_bytes(
                    &mut snapshot_bytes,
                    bytes.len(),
                    MAX_CORPUS_SNAPSHOT_BYTES,
                    "corpus executable-input snapshot",
                )?;
                support_files.push(SnapshotSupportFile {
                    corpus_relative_path: normalized_relative_path(
                        &corpus_relative,
                        "corpus support file",
                    )?,
                    staged_relative_path,
                    bytes,
                });
            }
        }
        support_files
            .sort_by(|left, right| left.corpus_relative_path.cmp(&right.corpus_relative_path));
        families.insert(family.key.clone(), SnapshotFamily { support_files });
    }

    manifests.sort_by(|left, right| left.corpus_relative_path.cmp(&right.corpus_relative_path));
    Ok(CorpusSnapshot {
        manifests,
        cases: snapshot_cases,
        families,
    })
}

fn validate_family_manifest(
    manifest: &CorpusFamilyManifest,
    corpus_root: &Path,
    manifest_relative: &Path,
) -> Result<()> {
    let manifest_display = corpus_root.join(manifest_relative);
    if manifest.schema_version != CORPUS_FIXTURE_SCHEMA_VERSION {
        bail!(
            "corpus manifest {} has schema_version `{}`; only `{}` is supported",
            manifest_display.display(),
            manifest.schema_version,
            CORPUS_FIXTURE_SCHEMA_VERSION
        );
    }
    if manifest.api_family.trim().is_empty() {
        bail!(
            "corpus manifest {} has an empty api_family",
            manifest_display.display()
        );
    }
    if manifest.cases.is_empty() {
        bail!(
            "corpus manifest {} has no cases",
            manifest_display.display()
        );
    }
    Ok(())
}

fn validate_case_spec(case: &CorpusCaseSpec) -> Result<()> {
    if !VALID_BANDS.contains(&case.band.as_str()) {
        bail!(
            "corpus case `{}` has invalid band `{}` (expected one of {:?})",
            case.id,
            case.band,
            VALID_BANDS
        );
    }
    if !VALID_RISK_BANDS.contains(&case.risk_band.as_str()) {
        bail!(
            "corpus case `{}` has invalid risk_band `{}` (expected one of {:?})",
            case.id,
            case.risk_band,
            VALID_RISK_BANDS
        );
    }
    Ok(())
}

#[cfg(unix)]
#[allow(clippy::useless_conversion)] // rustix descriptor-id widths vary across supported Unix targets.
fn descriptor_identity(stat: &Stat) -> Result<DescriptorIdentity> {
    Ok(DescriptorIdentity {
        device: u64::try_from(stat.st_dev).context("descriptor device id does not fit u64")?,
        inode: u64::try_from(stat.st_ino).context("descriptor inode does not fit u64")?,
        file_type: DescriptorFileType::from_raw_mode(stat.st_mode),
    })
}

#[cfg(unix)]
fn descriptor_fingerprint(stat: &Stat) -> Result<DescriptorFingerprint> {
    Ok(DescriptorFingerprint {
        identity: descriptor_identity(stat)?,
        size: u64::try_from(stat.st_size).context("descriptor size is negative or too large")?,
        modified_seconds: i128::from(stat.st_mtime),
        modified_nanoseconds: i128::from(stat.st_mtime_nsec),
        changed_seconds: i128::from(stat.st_ctime),
        changed_nanoseconds: i128::from(stat.st_ctime_nsec),
    })
}

#[cfg(unix)]
fn ensure_expected_identity(expected: &Stat, opened: &Stat, relative_path: &Path) -> Result<()> {
    if descriptor_identity(expected)? != descriptor_identity(opened)? {
        bail!(
            "corpus input `{}` changed during corpus capture",
            relative_path.display()
        );
    }
    Ok(())
}

#[cfg(unix)]
fn stat_descriptor_entry(parent: &OwnedFd, name: &str, relative_path: &Path) -> Result<Stat> {
    statat(parent, name, AtFlags::SYMLINK_NOFOLLOW).with_context(|| {
        format!(
            "inspect descriptor-relative corpus input `{}`",
            relative_path.display()
        )
    })
}

#[cfg(unix)]
fn directory_open_flags() -> OFlags {
    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC
}

#[cfg(unix)]
fn regular_open_flags() -> OFlags {
    OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::CLOEXEC
}

#[cfg(unix)]
fn open_corpus_root(
    corpus_root: &Path,
    probe: &mut impl CaptureProbe,
) -> Result<(OwnedFd, DescriptorIdentity)> {
    if corpus_root.as_os_str().is_empty() {
        bail!("corpus root path is empty");
    }
    let (mut current, mut opened_path) = if corpus_root.is_absolute() {
        (
            open("/", directory_open_flags(), Mode::empty())
                .context("open absolute filesystem root descriptor")?,
            PathBuf::from("/"),
        )
    } else {
        (
            open(".", directory_open_flags(), Mode::empty())
                .context("open current-directory descriptor")?,
            PathBuf::new(),
        )
    };

    let mut saw_component = false;
    for component in corpus_root.components() {
        match component {
            Component::RootDir | Component::CurDir => continue,
            Component::Normal(name) => {
                saw_component = true;
                opened_path.push(name);
                let name = name.to_str().with_context(|| {
                    format!(
                        "corpus root component is not UTF-8: {}",
                        opened_path.display()
                    )
                })?;
                let expected =
                    statat(&current, name, AtFlags::SYMLINK_NOFOLLOW).with_context(|| {
                        format!("inspect corpus root component {}", opened_path.display())
                    })?;
                if descriptor_identity(&expected)?.file_type != DescriptorFileType::Directory {
                    bail!(
                        "corpus root component is not a regular non-symlink directory: {}",
                        opened_path.display()
                    );
                }
                probe.after_stat_before_open(CaptureKind::Root, &opened_path)?;
                let next = openat(&current, name, directory_open_flags(), Mode::empty())
                    .with_context(|| {
                        format!(
                            "open no-follow corpus root component {}",
                            opened_path.display()
                        )
                    })?;
                probe.after_open_before_read(CaptureKind::Root, &opened_path)?;
                let opened = fstat(&next).with_context(|| {
                    format!(
                        "inspect opened corpus root component {}",
                        opened_path.display()
                    )
                })?;
                ensure_expected_identity(&expected, &opened, &opened_path)?;
                current = next;
            }
            Component::ParentDir | Component::Prefix(_) => {
                bail!(
                    "corpus root {} must not contain parent or prefix components",
                    corpus_root.display()
                );
            }
        }
    }
    if !saw_component && corpus_root != Path::new(".") && corpus_root != Path::new("/") {
        bail!(
            "corpus root {} has no usable components",
            corpus_root.display()
        );
    }
    let identity =
        descriptor_identity(&fstat(&current).context("inspect corpus root descriptor")?)?;
    Ok((current, identity))
}

#[cfg(unix)]
fn read_descriptor_directory(
    descriptor: &OwnedFd,
    label: &str,
) -> Result<Vec<ObservedDirectoryEntry>> {
    let mut entries = Vec::new();
    let directory = Dir::read_from(descriptor)
        .with_context(|| format!("open descriptor-backed directory iterator for {label}"))?;
    for entry in directory {
        let entry = entry.with_context(|| format!("read descriptor-backed entry from {label}"))?;
        let name = entry
            .file_name()
            .to_str()
            .with_context(|| format!("{label} contains a non-UTF-8 entry"))?;
        if name == "." || name == ".." {
            continue;
        }
        entries.push(ObservedDirectoryEntry {
            name: name.to_string(),
            inode: entry.ino(),
        });
    }
    entries.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(entries)
}

#[cfg(unix)]
fn open_verified_directory(
    parent: &OwnedFd,
    name: &str,
    relative_path: &Path,
    kind: CaptureKind,
    known_expected: Option<&Stat>,
    probe: &mut impl CaptureProbe,
    directory_identities: &mut BTreeMap<PathBuf, DescriptorIdentity>,
) -> Result<OwnedFd> {
    let observed;
    let expected = match known_expected {
        Some(expected) => expected,
        None => {
            observed = stat_descriptor_entry(parent, name, relative_path)?;
            &observed
        }
    };
    if descriptor_identity(expected)?.file_type != DescriptorFileType::Directory {
        bail!(
            "corpus directory input is not a regular non-symlink directory: {}",
            relative_path.display()
        );
    }
    probe.after_stat_before_open(kind, relative_path)?;
    let descriptor =
        openat(parent, name, directory_open_flags(), Mode::empty()).with_context(|| {
            format!(
                "open descriptor-relative no-follow corpus directory `{}`",
                relative_path.display()
            )
        })?;
    probe.after_open_before_read(kind, relative_path)?;
    let opened = fstat(&descriptor).with_context(|| {
        format!(
            "inspect opened corpus directory descriptor `{}`",
            relative_path.display()
        )
    })?;
    ensure_expected_identity(expected, &opened, relative_path)?;
    let identity = descriptor_identity(&opened)?;
    if let Some(previous) = directory_identities.insert(relative_path.to_path_buf(), identity)
        && previous != identity
    {
        bail!(
            "corpus directory `{}` changed during corpus capture",
            relative_path.display()
        );
    }
    Ok(descriptor)
}

#[cfg(unix)]
fn open_verified_relative_directory(
    root: &OwnedFd,
    relative_path: &Path,
    corpus_relative_path: &Path,
    kind: CaptureKind,
    probe: &mut impl CaptureProbe,
    directory_identities: &mut BTreeMap<PathBuf, DescriptorIdentity>,
) -> Result<OwnedFd> {
    let mut current = open_verified_directory(
        root,
        ".",
        corpus_relative_path
            .components()
            .next()
            .map(|component| PathBuf::from(component.as_os_str()))
            .as_deref()
            .unwrap_or_else(|| Path::new("")),
        kind,
        None,
        probe,
        directory_identities,
    )?;
    let mut walked = PathBuf::new();
    let family_prefix = corpus_relative_path
        .components()
        .next()
        .map(|component| PathBuf::from(component.as_os_str()))
        .context("corpus-relative directory has no family component")?;
    for component in relative_path.components() {
        let Component::Normal(name) = component else {
            bail!(
                "corpus relative directory {} contains an invalid component",
                relative_path.display()
            );
        };
        walked.push(name);
        let full_relative = family_prefix.join(&walked);
        let name = name.to_str().with_context(|| {
            format!(
                "corpus directory path is not UTF-8: {}",
                full_relative.display()
            )
        })?;
        current = open_verified_directory(
            &current,
            name,
            &full_relative,
            kind,
            None,
            probe,
            directory_identities,
        )?;
    }
    Ok(current)
}

#[cfg(unix)]
#[allow(clippy::too_many_arguments)] // Keep each security boundary and byte limit explicit at the call site.
fn read_verified_relative_file(
    root: &OwnedFd,
    relative_path: &Path,
    corpus_relative_path: &Path,
    directory_kind: CaptureKind,
    file_kind: CaptureKind,
    max_bytes: usize,
    probe: &mut impl CaptureProbe,
    directory_identities: &mut BTreeMap<PathBuf, DescriptorIdentity>,
) -> Result<Vec<u8>> {
    let file_name = relative_path
        .file_name()
        .and_then(|name| name.to_str())
        .with_context(|| {
            format!(
                "corpus file path has no UTF-8 filename: {}",
                relative_path.display()
            )
        })?;
    let parent_relative = relative_path.parent().unwrap_or_else(|| Path::new(""));
    let corpus_parent = corpus_relative_path
        .parent()
        .unwrap_or_else(|| Path::new(""));
    let parent = open_verified_relative_directory(
        root,
        parent_relative,
        corpus_parent,
        directory_kind,
        probe,
        directory_identities,
    )?;
    read_verified_regular_file(
        &parent,
        file_name,
        corpus_relative_path,
        file_kind,
        max_bytes,
        None,
        probe,
    )
}

#[cfg(unix)]
fn read_verified_regular_file(
    parent: &OwnedFd,
    name: &str,
    relative_path: &Path,
    kind: CaptureKind,
    max_bytes: usize,
    known_expected: Option<&Stat>,
    probe: &mut impl CaptureProbe,
) -> Result<Vec<u8>> {
    let observed;
    let expected = match known_expected {
        Some(expected) => expected,
        None => {
            observed = stat_descriptor_entry(parent, name, relative_path)?;
            &observed
        }
    };
    let expected_fingerprint = descriptor_fingerprint(expected)?;
    if expected_fingerprint.identity.file_type != DescriptorFileType::RegularFile {
        bail!(
            "corpus file input is not a regular non-symlink file: {}",
            relative_path.display()
        );
    }
    let max_bytes_u64 =
        u64::try_from(max_bytes).context("corpus file byte bound does not fit u64")?;
    if expected_fingerprint.size > max_bytes_u64 {
        bail!(
            "{} exceeds the {max_bytes}-byte bound",
            relative_path.display()
        );
    }
    probe.after_stat_before_open(kind, relative_path)?;
    let descriptor =
        openat(parent, name, regular_open_flags(), Mode::empty()).with_context(|| {
            format!(
                "open descriptor-relative no-follow corpus file `{}`",
                relative_path.display()
            )
        })?;
    probe.after_open_before_read(kind, relative_path)?;
    let opened = fstat(&descriptor).with_context(|| {
        format!(
            "inspect opened corpus file descriptor `{}`",
            relative_path.display()
        )
    })?;
    ensure_expected_identity(expected, &opened, relative_path)?;
    let before_read = descriptor_fingerprint(&opened)?;
    if before_read.identity.file_type != DescriptorFileType::RegularFile {
        bail!(
            "corpus file input is not regular after open: {}",
            relative_path.display()
        );
    }

    let mut file = std::fs::File::from(descriptor);
    let mut bytes = Vec::with_capacity(
        usize::try_from(before_read.size)
            .unwrap_or(max_bytes)
            .min(max_bytes),
    );
    let mut buffer = [0u8; 8_192];
    let mut invoked_first_read_probe = false;
    loop {
        let remaining = max_bytes
            .checked_add(1)
            .and_then(|bound| bound.checked_sub(bytes.len()))
            .context("corpus bounded-read length overflow")?;
        if remaining == 0 {
            break;
        }
        let read_len = remaining.min(buffer.len());
        let count = file.read(&mut buffer[..read_len]).with_context(|| {
            format!(
                "read opened corpus descriptor `{}`",
                relative_path.display()
            )
        })?;
        if count == 0 {
            break;
        }
        bytes.extend_from_slice(&buffer[..count]);
        if !invoked_first_read_probe {
            probe.after_first_read(kind, relative_path)?;
            invoked_first_read_probe = true;
        }
    }
    if bytes.len() > max_bytes {
        bail!(
            "{} exceeds the {max_bytes}-byte bound",
            relative_path.display()
        );
    }
    let after_read = descriptor_fingerprint(&fstat(&file).with_context(|| {
        format!(
            "inspect corpus descriptor after read `{}`",
            relative_path.display()
        )
    })?)?;
    if before_read != after_read {
        bail!(
            "corpus input `{}` changed while it was being captured",
            relative_path.display()
        );
    }
    Ok(bytes)
}

fn validated_case_relative_path(case_id: &str, raw: &str) -> Result<PathBuf> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.contains('\\') || trimmed.contains('\0') {
        bail!("corpus case `{case_id}` has an invalid fixture path");
    }
    let relative = PathBuf::from(trimmed);
    if relative.is_absolute()
        || relative.components().any(|component| {
            matches!(
                component,
                Component::CurDir
                    | Component::ParentDir
                    | Component::Prefix(_)
                    | Component::RootDir
            )
        })
    {
        bail!("corpus case `{case_id}` path must stay within its family directory");
    }
    Ok(relative)
}

fn normalized_relative_path(path: &Path, label: &str) -> Result<String> {
    let mut normalized = Vec::new();
    for component in path.components() {
        let Component::Normal(component) = component else {
            bail!("{label} path {} is not canonical", path.display());
        };
        normalized.push(
            component
                .to_str()
                .with_context(|| format!("{label} path {} is not UTF-8", path.display()))?,
        );
    }
    if normalized.is_empty() {
        bail!("{label} path is empty");
    }
    Ok(normalized.join("/"))
}

fn add_bounded_bytes(total: &mut usize, added: usize, limit: usize, label: &str) -> Result<()> {
    let next = total
        .checked_add(added)
        .with_context(|| format!("{label} byte count overflow"))?;
    if next > limit {
        bail!("{label} exceeds the {limit}-byte bound");
    }
    *total = next;
    Ok(())
}

/// Content-addressed corpus version over every behavior- and evidence-relevant
/// field in the immutable snapshot. V2 uses canonical count/length framing and
/// exposes 128 digest bits.
pub fn content_addressed_corpus_version(snapshot: &CorpusSnapshot) -> Result<String> {
    let mut hasher = Sha256::new();
    hasher.update(b"ccg_corpus_content_version_v2\0");
    hasher.update(b"manifests\0");
    hash_count(&mut hasher, snapshot.manifests.len())?;
    for manifest in &snapshot.manifests {
        hash_field(&mut hasher, manifest.corpus_relative_path.as_bytes())?;
        hash_field(&mut hasher, &manifest.bytes)?;
    }
    hasher.update(b"cases\0");
    hash_count(&mut hasher, snapshot.cases.len())?;
    let mut ordered: Vec<&SnapshotCase> = snapshot.cases.iter().collect();
    ordered.sort_by(|a, b| a.case.test_id.cmp(&b.case.test_id));
    for case in ordered {
        hasher.update(b"case\0");
        hash_field(&mut hasher, case.case.test_id.as_bytes())?;
        hash_field(&mut hasher, case.corpus_relative_path.as_bytes())?;
        hash_field(&mut hasher, case.case.api_family.as_bytes())?;
        hash_field(&mut hasher, case.case.band.as_bytes())?;
        hash_field(&mut hasher, case.case.risk_band.as_bytes())?;
        match case.case.investigation_bead_id.as_deref() {
            Some(bead_id) => {
                hasher.update([1]);
                hash_field(&mut hasher, bead_id.as_bytes())?;
            }
            None => hasher.update([0]),
        }
        hash_field(&mut hasher, &case.source_bytes)?;
    }

    let support_count: usize = snapshot
        .families
        .values()
        .map(|family| family.support_files.len())
        .sum();
    hasher.update(b"supports\0");
    hash_count(&mut hasher, support_count)?;
    for family in snapshot.families.values() {
        for support in &family.support_files {
            hash_field(&mut hasher, support.corpus_relative_path.as_bytes())?;
            hash_field(&mut hasher, &support.bytes)?;
        }
    }

    let digest = hex::encode(hasher.finalize());
    Ok(format!("compat-corpus-v2-{}", &digest[..32]))
}

fn hash_count(hasher: &mut Sha256, count: usize) -> Result<()> {
    let count = u64::try_from(count).context("corpus hash count does not fit u64")?;
    hasher.update(count.to_be_bytes());
    Ok(())
}

fn hash_field(hasher: &mut Sha256, bytes: &[u8]) -> Result<()> {
    hash_count(hasher, bytes.len())?;
    hasher.update(bytes);
    Ok(())
}

/// One captured runtime leg: comparison bytes (stdout + stderr + exit marker)
/// plus the raw pieces used for failure classification.
#[cfg(feature = "engine")]
struct LegCapture {
    comparison: Vec<u8>,
    stderr: Vec<u8>,
    exit_code: Option<i32>,
    timed_out: bool,
}

#[cfg(feature = "engine")]
fn drain_capped(mut pipe: impl Read + Send + 'static) -> std::thread::JoinHandle<Vec<u8>> {
    std::thread::spawn(move || {
        let mut buffer = Vec::new();
        let mut chunk = [0u8; 8_192];
        loop {
            match pipe.read(&mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if buffer.len().saturating_add(n) <= MAX_LEG_OUTPUT_BYTES {
                        buffer.extend_from_slice(&chunk[..n]);
                    }
                }
            }
        }
        buffer
    })
}

#[cfg(feature = "engine")]
fn run_leg(mut command: Command, timeout: Duration) -> Result<LegCapture> {
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .stdin(Stdio::null())
        .spawn()
        .with_context(|| format!("spawn runtime leg {command:?}"))?;
    let stdout = child
        .stdout
        .take()
        .context("runtime leg stdout pipe unavailable")?;
    let stderr = child
        .stderr
        .take()
        .context("runtime leg stderr pipe unavailable")?;
    let stdout_thread = drain_capped(stdout);
    let stderr_thread = drain_capped(stderr);

    let started = Instant::now();
    let mut timed_out = false;
    let status = loop {
        match child.try_wait().context("poll runtime leg")? {
            Some(status) => break status,
            None => {
                if started.elapsed() >= timeout {
                    timed_out = true;
                    let _ = child.kill();
                    break child.wait().context("reap timed-out runtime leg")?;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        }
    };

    let stdout_bytes = stdout_thread
        .join()
        .map_err(|_| anyhow::anyhow!("runtime leg stdout drain thread panicked"))?;
    let stderr_bytes = stderr_thread
        .join()
        .map_err(|_| anyhow::anyhow!("runtime leg stderr drain thread panicked"))?;

    let exit_code = status.code();
    let stderr_excerpt = stderr_bytes[..stderr_bytes.len().min(4_096)].to_vec();
    let mut comparison = stdout_bytes;
    comparison.extend_from_slice(&stderr_bytes[..]);
    comparison.extend_from_slice(b"\nexit:");
    match (timed_out, exit_code) {
        (true, _) => comparison.extend_from_slice(b"timeout"),
        (false, Some(code)) => comparison.extend_from_slice(code.to_string().as_bytes()),
        (false, None) => comparison.extend_from_slice(b"signal"),
    }
    Ok(LegCapture {
        comparison,
        stderr: stderr_excerpt,
        exit_code,
        timed_out,
    })
}

#[cfg(feature = "engine")]
fn sanitize_reason_excerpt(bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(bytes);
    let mut line = text
        .lines()
        .find(|line| !line.trim().is_empty())
        .unwrap_or("")
        .trim()
        .to_string();
    if let Some(index) = line.find("fix_command=") {
        line.truncate(index);
    }
    let mut cleaned: String = line
        .chars()
        .filter(|c| !c.is_control())
        .collect::<String>()
        .trim()
        .to_string();
    if cleaned.chars().count() > TRACKING_REASON_MAX_CHARS {
        cleaned = cleaned.chars().take(TRACKING_REASON_MAX_CHARS).collect();
    }
    cleaned
}

/// Execute the full corpus. Returns per-case outcomes in corpus order.
///
/// Fail-closed preconditions: bun must be on PATH and the current binary must
/// be able to bootstrap a valid workspace via its own `init`; either failing
/// aborts before any case runs.
#[cfg(feature = "engine")]
pub fn run_corpus(
    snapshot: &CorpusSnapshot,
    case_timeout: Duration,
) -> Result<(Vec<CaseOutcome>, String)> {
    use crate::runtime::nversion_oracle::{
        BoundaryScope, CheckOutcome, RuntimeEntry, RuntimeOracle,
    };

    if snapshot.cases.is_empty() {
        bail!("no corpus cases to run");
    }

    let current_exe = std::env::current_exe().context("resolve current executable")?;

    // Bootstrap ONE fail-closed-valid workspace template exactly as an
    // operator would (`franken-node init`), then clone it into BOTH legs. The
    // franken leg needs this for config validation, while the bun leg needs the
    // same visible filesystem scaffold so guest `readdir('.')` observations
    // compare the runtime semantics rather than two different sandboxes.
    let template = tempfile::TempDir::new().context("create workspace template dir")?;
    let init = Command::new(&current_exe)
        .args(["init", "--profile", "balanced", "--out-dir", "."])
        .current_dir(template.path())
        .output()
        .context("bootstrap workspace template via init")?;
    if !init.status.success() {
        bail!(
            "workspace template init failed (exit {:?}): {}",
            init.status.code(),
            String::from_utf8_lossy(&init.stderr)
        );
    }
    preflight_snapshot_targets(snapshot, template.path())?;

    // Reference-leg availability and version pin are checked only after every
    // staged destination has passed collision preflight, so an invalid later
    // case cannot cause an earlier external runtime invocation.
    let bun_version_output = Command::new("bun")
        .arg("--version")
        .output()
        .context("bun is required for the corpus reference leg (bun --version failed)")?;
    if !bun_version_output.status.success() {
        bail!("bun --version exited nonzero; cannot pin the reference-leg runtime version");
    }
    let bun_version = String::from_utf8_lossy(&bun_version_output.stdout)
        .trim()
        .to_string();

    let mut outcomes = Vec::with_capacity(snapshot.cases.len());
    for snapshot_case in &snapshot.cases {
        let case = &snapshot_case.case;
        let family = snapshot
            .families
            .get(&snapshot_case.family_key)
            .with_context(|| {
                format!("snapshot family `{}` is missing", snapshot_case.family_key)
            })?;

        // Reference leg sandbox: same workspace scaffold as the franken leg so
        // filesystem-observing fixtures receive identical ambient inputs.
        let bun_dir = tempfile::TempDir::new().context("create bun leg sandbox")?;
        copy_dir_recursive(template.path(), bun_dir.path(), 0)
            .context("clone workspace template into bun leg sandbox")?;
        stage_snapshot_case(snapshot_case, family, bun_dir.path())
            .context("stage bun leg executable inputs")?;
        let mut bun_cmd = Command::new("bun");
        bun_cmd
            .arg(&snapshot_case.staged_relative_path)
            .current_dir(bun_dir.path());
        let bun_leg = run_leg(bun_cmd, case_timeout)
            .with_context(|| format!("bun leg failed to launch for case `{}`", case.test_id))?;

        // Franken leg sandbox: cloned workspace template + case file.
        let franken_dir = tempfile::TempDir::new().context("create franken leg sandbox")?;
        copy_dir_recursive(template.path(), franken_dir.path(), 0)
            .context("clone workspace template into franken leg sandbox")?;
        stage_snapshot_case(snapshot_case, family, franken_dir.path())
            .context("stage franken leg executable inputs")?;
        let mut franken_cmd = Command::new(&current_exe);
        franken_cmd
            .arg("run")
            .arg(&snapshot_case.staged_relative_path)
            .arg("--console-only")
            .arg("--policy")
            .arg("legacy-risky")
            .arg("--runtime")
            .arg("franken-engine")
            .arg("--engine-bin")
            .arg(&current_exe)
            .current_dir(franken_dir.path());
        let franken_leg = run_leg(franken_cmd, case_timeout)
            .with_context(|| format!("franken leg failed to launch for case `{}`", case.test_id))?;

        // Adjudicate through the real N-version oracle: bun is the reference
        // executor, the native engine is the runtime under test.
        let mut oracle = RuntimeOracle::new(&format!("ccg:{}", case.test_id), 100);
        oracle
            .register_runtime(RuntimeEntry {
                runtime_id: "bun".to_string(),
                runtime_name: "bun".to_string(),
                version: bun_version.clone(),
                is_reference: true,
            })
            .map_err(|err| anyhow::anyhow!("oracle registration failed for bun: {err}"))?;
        oracle
            .register_runtime(RuntimeEntry {
                runtime_id: "franken-engine-native".to_string(),
                runtime_name: "franken-engine-native".to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
                is_reference: false,
            })
            .map_err(|err| anyhow::anyhow!("oracle registration failed for franken leg: {err}"))?;
        let mut outputs = BTreeMap::new();
        outputs.insert("bun".to_string(), bun_leg.comparison.clone());
        outputs.insert(
            "franken-engine-native".to_string(),
            franken_leg.comparison.clone(),
        );
        let check = oracle
            .run_cross_check(
                &format!("ccg:{}:check", case.test_id),
                BoundaryScope::IO,
                &snapshot_case.source_bytes,
                &outputs,
            )
            .map_err(|err| anyhow::anyhow!("oracle cross-check failed: {err}"))?;

        let agreed = matches!(check.outcome, Some(CheckOutcome::Agree { .. }));
        let (status, failure_reason): (&'static str, Option<String>) = if agreed {
            ("pass", None)
        } else {
            ("fail", Some(classify_failure(&bun_leg, &franken_leg)))
        };
        outcomes.push(CaseOutcome {
            test_id: case.test_id.clone(),
            api_family: case.api_family.clone(),
            band: case.band.clone(),
            risk_band: case.risk_band.clone(),
            status,
            failure_reason,
            investigation_bead_id: case.investigation_bead_id.clone(),
        });
    }

    Ok((outcomes, bun_version))
}

#[cfg(feature = "engine")]
fn classify_failure(bun: &LegCapture, franken: &LegCapture) -> String {
    if bun.timed_out || franken.timed_out {
        let leg = if franken.timed_out {
            "franken-engine"
        } else {
            "bun reference"
        };
        return format!("lockstep divergence: {leg} leg timed out");
    }
    match (bun.exit_code, franken.exit_code) {
        (Some(0), Some(0)) => "lockstep divergence: output mismatch vs bun reference".to_string(),
        (Some(0), other) => {
            let excerpt = sanitize_reason_excerpt(&franken.stderr);
            format!(
                "lockstep divergence: franken-engine leg refused or crashed (exit {:?}): {excerpt}",
                other
            )
        }
        (other, Some(0)) => format!(
            "lockstep divergence: bun reference leg exited {:?} while franken leg exited 0",
            other
        ),
        (bun_exit, franken_exit) => format!(
            "lockstep divergence: both legs failed with divergent diagnostics (bun exit {bun_exit:?}, franken exit {franken_exit:?})"
        ),
    }
}

#[cfg(feature = "engine")]
fn stage_snapshot_case(case: &SnapshotCase, family: &SnapshotFamily, sandbox: &Path) -> Result<()> {
    write_staged_input(
        sandbox,
        &case.staged_relative_path,
        &case.source_bytes,
        "corpus case",
    )?;
    for support in &family.support_files {
        write_staged_input(
            sandbox,
            &support.staged_relative_path,
            &support.bytes,
            "corpus support file",
        )?;
    }
    Ok(())
}

#[cfg(feature = "engine")]
fn write_staged_input(
    sandbox: &Path,
    relative_path: &Path,
    bytes: &[u8],
    kind: &str,
) -> Result<()> {
    let target = sandbox.join(relative_path);
    let parent = target
        .parent()
        .with_context(|| format!("{kind} target {} has no parent", target.display()))?;
    std::fs::create_dir_all(parent)
        .with_context(|| format!("create {kind} parent {}", parent.display()))?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&target)
        .with_context(|| {
            format!(
                "stage {kind} {} without overwriting an existing sandbox entry",
                target.display()
            )
        })?;
    file.write_all(bytes)
        .with_context(|| format!("write staged {kind} {}", target.display()))?;
    Ok(())
}

#[cfg(feature = "engine")]
fn preflight_snapshot_targets(snapshot: &CorpusSnapshot, template: &Path) -> Result<()> {
    for case in &snapshot.cases {
        preflight_staged_path(
            template,
            &case.staged_relative_path,
            &format!("corpus case `{}`", case.case.test_id),
        )?;
    }
    for family in snapshot.families.values() {
        for support in &family.support_files {
            preflight_staged_path(
                template,
                &support.staged_relative_path,
                &format!("corpus support file `{}`", support.corpus_relative_path),
            )?;
        }
    }
    Ok(())
}

#[cfg(feature = "engine")]
fn preflight_staged_path(template: &Path, relative_path: &Path, label: &str) -> Result<()> {
    let mut current = template.to_path_buf();
    let components: Vec<_> = relative_path.components().collect();
    for (index, component) in components.iter().enumerate() {
        let Component::Normal(component) = component else {
            bail!("{label} has a non-canonical staged path");
        };
        current.push(component);
        match std::fs::symlink_metadata(&current) {
            Ok(metadata) => {
                let is_last = index + 1 == components.len();
                if is_last {
                    bail!(
                        "{label} would overwrite workspace template entry {}",
                        current.display()
                    );
                }
                if metadata.file_type().is_symlink() || !metadata.is_dir() {
                    bail!(
                        "{label} has a colliding workspace template parent {}",
                        current.display()
                    );
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("inspect {label} staging target {}", current.display())
                });
            }
        }
    }
    Ok(())
}

#[cfg(feature = "engine")]
fn copy_dir_recursive(from: &Path, to: &Path, depth: usize) -> Result<()> {
    if depth > 16 {
        bail!("workspace template nesting exceeds the copy bound");
    }
    std::fs::create_dir_all(to)?;
    for entry in std::fs::read_dir(from)? {
        let entry = entry?;
        let target = to.join(entry.file_name());
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            copy_dir_recursive(&entry.path(), &target, depth + 1)?;
        } else if file_type.is_file() {
            std::fs::copy(entry.path(), &target)?;
        }
        // Symlinks in a freshly-initialized workspace template are
        // unexpected; skip rather than follow.
    }
    Ok(())
}

fn round2(value: f64) -> f64 {
    (value * 100.0).round() / 100.0
}

fn pass_rate_pct(passed: usize, total: usize) -> f64 {
    if total == 0 {
        return 0.0;
    }
    #[allow(clippy::cast_precision_loss)]
    round2((passed as f64 / total as f64) * 100.0)
}

fn aggregate<'a>(
    outcomes: &'a [CaseOutcome],
    key: impl Fn(&'a CaseOutcome) -> &'a str,
) -> BTreeMap<String, (usize, usize)> {
    let mut grouped: BTreeMap<String, (usize, usize)> = BTreeMap::new();
    for outcome in outcomes {
        let entry = grouped.entry(key(outcome).to_string()).or_insert((0, 0));
        entry.0 += 1;
        if outcome.status == "pass" {
            entry.1 += 1;
        }
    }
    grouped
}

fn thresholds_from(existing: Option<&Value>) -> (f64, f64, BTreeMap<String, f64>) {
    let overall = existing
        .and_then(|doc| doc.pointer("/thresholds/overall_pass_rate_min_pct"))
        .and_then(Value::as_f64)
        .unwrap_or(DEFAULT_OVERALL_MIN_PCT);
    let family_floor = existing
        .and_then(|doc| doc.pointer("/thresholds/per_family_pass_rate_min_pct"))
        .and_then(Value::as_f64)
        .unwrap_or(DEFAULT_FAMILY_FLOOR_PCT);
    let mut band_floors: BTreeMap<String, f64> = DEFAULT_BAND_FLOORS
        .iter()
        .map(|(band, floor)| ((*band).to_string(), *floor))
        .collect();
    if let Some(bands) = existing
        .and_then(|doc| doc.pointer("/thresholds/band_pass_rate_min_pct"))
        .and_then(Value::as_object)
    {
        band_floors = bands
            .iter()
            .filter_map(|(band, floor)| floor.as_f64().map(|f| (band.clone(), f)))
            .collect();
    }
    (overall, family_floor, band_floors)
}

/// Assemble the full compatibility-corpus results document from measured
/// outcomes. Pure: no subprocesses, no clock reads besides the injected
/// timestamp — unit-testable without bun.
///
/// Identity fields (`bead_id`, `title`, `section`, `trace_id`), the
/// `thresholds` block, and the `proof_carrying_effects` /
/// `event_codes` blocks are carried forward from the existing artifact when
/// present so the corpus rewrite never silently drops the cross-file binding
/// the L1 verdict artifact re-checks (bd-ry7d1).
pub fn build_corpus_results_document(
    existing: Option<&Value>,
    outcomes: &[CaseOutcome],
    corpus_version: &str,
    bun_version: &str,
    generated_at_utc: &str,
    corpus_root_display: &str,
) -> Result<Value> {
    if outcomes.is_empty() {
        bail!("refusing to build a corpus results document with zero outcomes");
    }
    for outcome in outcomes {
        if outcome.status != "pass" && outcome.status != "fail" {
            bail!(
                "corpus outcome `{}` has unexpected status `{}`",
                outcome.test_id,
                outcome.status
            );
        }
    }

    let total = outcomes.len();
    let passed = outcomes.iter().filter(|o| o.status == "pass").count();
    let failed = total - passed;
    let overall_rate = pass_rate_pct(passed, total);

    let mut per_test_rows: Vec<Value> = outcomes
        .iter()
        .map(|o| {
            json!({
                "test_id": o.test_id,
                "api_family": o.api_family,
                "band": o.band,
                "risk_band": o.risk_band,
                "status": o.status,
            })
        })
        .collect();
    per_test_rows.sort_by(|a, b| {
        a.get("test_id")
            .and_then(Value::as_str)
            .cmp(&b.get("test_id").and_then(Value::as_str))
    });
    let result_digest = compute_compatibility_corpus_result_digest(&per_test_rows);

    let family_breakdown = aggregate(outcomes, |o| o.api_family.as_str());
    let band_breakdown = aggregate(outcomes, |o| o.band.as_str());
    let api_families: Vec<Value> = family_breakdown
        .iter()
        .map(|(family, (family_total, family_passed))| {
            json!({
                "family": family,
                "total": family_total,
                "passed": family_passed,
                "pass_rate_pct": pass_rate_pct(*family_passed, *family_total),
            })
        })
        .collect();
    let bands: Vec<Value> = band_breakdown
        .iter()
        .map(|(band, (band_total, band_passed))| {
            json!({
                "band": band,
                "total": band_total,
                "passed": band_passed,
                "pass_rate_pct": pass_rate_pct(*band_passed, *band_total),
            })
        })
        .collect();

    let (overall_min, family_floor, band_floors) = thresholds_from(existing);
    let families_ok = family_breakdown
        .iter()
        .all(|(_, (t, p))| pass_rate_pct(*p, *t) >= family_floor);
    let bands_ok = band_floors.iter().all(|(band, floor)| {
        band_breakdown
            .get(band)
            .map(|(t, p)| pass_rate_pct(*p, *t))
            .unwrap_or(-1.0)
            >= *floor
    });
    let threshold_met = overall_rate >= overall_min && families_ok && bands_ok;

    // Ratchet: only a prior GENUINE oracle run is a valid floor. When the
    // existing artifact carries authored/synthesized provenance (or none),
    // this run becomes the first genuine baseline instead of "regressing"
    // against a number nobody ever measured (bd-ihusm).
    let existing_provenance = existing
        .and_then(|doc| doc.pointer("/corpus/provenance"))
        .and_then(Value::as_str);
    let (previous_release, regression_detected) =
        if existing_provenance == Some(COMPATIBILITY_CORPUS_ONLINE_PROVENANCE) {
            let prev_rate = existing
                .and_then(|doc| doc.pointer("/totals/overall_pass_rate_pct"))
                .and_then(Value::as_f64)
                .unwrap_or(0.0);
            let prev = json!({
                "release_version": existing
                    .and_then(|doc| doc.pointer("/corpus/franken_node_version"))
                    .and_then(Value::as_str)
                    .unwrap_or("unknown"),
                "overall_pass_rate_pct": prev_rate,
                "corpus_version": existing
                    .and_then(|doc| doc.pointer("/corpus/corpus_version"))
                    .and_then(Value::as_str)
                    .unwrap_or("unknown"),
            });
            (prev, overall_rate < prev_rate)
        } else {
            let prev = json!({
                "release_version": env!("CARGO_PKG_VERSION"),
                "overall_pass_rate_pct": overall_rate,
                "corpus_version": corpus_version,
                "note": "first genuine lockstep-oracle-run baseline; prior committed rates \
                         were authored-fixture-expectations and are not a valid ratchet floor \
                         (bd-ihusm, bd-kfseq)",
            });
            (prev, false)
        };
    let release_blocked = !threshold_met || regression_detected;

    let mut failing_families: Vec<String> = family_breakdown
        .iter()
        .filter(|(_, (t, p))| pass_rate_pct(*p, *t) < family_floor)
        .map(|(family, (t, p))| format!("{family} {:.2}%", pass_rate_pct(*p, *t)))
        .collect();
    failing_families.sort();
    let release_blocked_reason = if release_blocked {
        Some(format!(
            "genuine lockstep-oracle-run measured {overall_rate:.2}% overall \
             (required {overall_min:.2}%); families below the {family_floor:.0}% floor: [{}]",
            failing_families.join(", ")
        ))
    } else {
        None
    };

    let failing_tests_tracking: Vec<Value> = outcomes
        .iter()
        .filter(|o| o.status == "fail")
        .map(|o| {
            json!({
                "test_id": o.test_id,
                "api_family": o.api_family,
                "reason": o.failure_reason.clone().unwrap_or_else(|| {
                    "behavioral divergence against lockstep oracle".to_string()
                }),
                "investigation_bead_id": o
                    .investigation_bead_id
                    .clone()
                    .unwrap_or_else(|| "bd-kfseq".to_string()),
                "investigation_status": "open",
            })
        })
        .collect();

    let mut document = Map::new();
    let carry = |key: &str, default: Value| -> Value {
        existing
            .and_then(|doc| doc.get(key))
            .cloned()
            .unwrap_or(default)
    };
    document.insert("bead_id".to_string(), carry("bead_id", json!("bd-28sz")));
    document.insert(
        "title".to_string(),
        carry(
            "title",
            json!("Concrete target gate: >=95% compatibility corpus pass"),
        ),
    );
    document.insert("section".to_string(), carry("section", json!("13")));
    document.insert(
        "trace_id".to_string(),
        carry("trace_id", json!("trace-bd-28sz-corpus-gate")),
    );
    document.insert(
        "corpus".to_string(),
        json!({
            "corpus_version": corpus_version,
            "franken_node_version": env!("CARGO_PKG_VERSION"),
            "lockstep_oracle_version": crate::runtime::nversion_oracle::SCHEMA_VERSION,
            "generated_at_utc": generated_at_utc,
            "result_digest": result_digest,
            "provenance": COMPATIBILITY_CORPUS_ONLINE_PROVENANCE,
            "runner": "franken-node ops compat-corpus-run",
            "policy_mode": "legacy-risky",
            "reference_runtime": format!("bun {bun_version}"),
            "corpus_root": corpus_root_display,
        }),
    );
    document.insert(
        "thresholds".to_string(),
        carry(
            "thresholds",
            json!({
                "overall_pass_rate_min_pct": DEFAULT_OVERALL_MIN_PCT,
                "per_family_pass_rate_min_pct": DEFAULT_FAMILY_FLOOR_PCT,
                "band_pass_rate_min_pct": {
                    "core": 99.0,
                    "high-value": 95.0,
                    "edge": 90.0,
                },
            }),
        ),
    );
    document.insert(
        "totals".to_string(),
        json!({
            "total_test_cases": total,
            "passed_test_cases": passed,
            "failed_test_cases": failed,
            "errored_test_cases": 0,
            "skipped_test_cases": 0,
            "overall_pass_rate_pct": overall_rate,
        }),
    );
    document.insert("bands".to_string(), Value::Array(bands));
    document.insert("api_families".to_string(), Value::Array(api_families));
    document.insert("per_test_results".to_string(), Value::Array(per_test_rows));
    document.insert(
        "failing_tests_tracking".to_string(),
        Value::Array(failing_tests_tracking),
    );
    document.insert("previous_release".to_string(), previous_release);
    document.insert(
        "ci_gate".to_string(),
        json!({
            "workflow_name": "compatibility-corpus-pass-gate",
            "workflow_path": ".github/workflows/compat-corpus-pass-gate.yml",
            "threshold_met": threshold_met,
            "release_blocked": release_blocked,
            "regression_detected": regression_detected,
            "release_blocked_reason": release_blocked_reason,
        }),
    );
    document.insert(
        "reproducibility".to_string(),
        json!({
            "deterministic_seed": "compat-corpus-generator-v1",
            "same_inputs_same_digest": true,
            "external_repro_command": "franken-node ops compat-corpus-run \
                --corpus-root crates/franken-node/tests/fixtures/compat_corpus \
                --out artifacts/13/compatibility_corpus_results.json \
                && python3 scripts/check_compatibility_corpus_pass_gate.py --json",
            "result_digest_algorithm": "ccg_corpus_result_digest_v1 (domain+field-separated \
                sha256 over sorted per_test_results)",
        }),
    );
    document.insert(
        "event_codes".to_string(),
        carry(
            "event_codes",
            json!(["CCG-001", "CCG-002", "CCG-003", "CCG-004"]),
        ),
    );
    if let Some(proof) = existing.and_then(|doc| doc.get("proof_carrying_effects")) {
        document.insert("proof_carrying_effects".to_string(), proof.clone());
    }

    Ok(Value::Object(document))
}

/// Resolve the artifact timestamp, honoring the deterministic override.
pub fn corpus_generated_at_utc() -> String {
    std::env::var(CORPUS_TIMESTAMP_ENV).unwrap_or_else(|_| chrono::Utc::now().to_rfc3339())
}

#[cfg(all(test, feature = "engine", unix))]
mod snapshot_staging_tests {
    use super::*;

    #[cfg(unix)]
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum TestCapturePhase {
        AfterStatBeforeOpen,
        AfterOpenBeforeRead,
        AfterFirstRead,
        AfterRootOpen,
    }

    #[cfg(unix)]
    struct TestCaptureProbe<F>(F);

    #[cfg(unix)]
    impl<F> CaptureProbe for TestCaptureProbe<F>
    where
        F: FnMut(TestCapturePhase, CaptureKind, &Path) -> Result<()>,
    {
        fn after_stat_before_open(
            &mut self,
            kind: CaptureKind,
            relative_path: &Path,
        ) -> Result<()> {
            (self.0)(TestCapturePhase::AfterStatBeforeOpen, kind, relative_path)
        }

        fn after_open_before_read(
            &mut self,
            kind: CaptureKind,
            relative_path: &Path,
        ) -> Result<()> {
            (self.0)(TestCapturePhase::AfterOpenBeforeRead, kind, relative_path)
        }

        fn after_first_read(&mut self, kind: CaptureKind, relative_path: &Path) -> Result<()> {
            (self.0)(TestCapturePhase::AfterFirstRead, kind, relative_path)
        }

        fn after_root_open(&mut self, corpus_root: &Path) -> Result<()> {
            (self.0)(
                TestCapturePhase::AfterRootOpen,
                CaptureKind::Root,
                corpus_root,
            )
        }
    }

    fn write_test_manifest(root: &Path, case_file: &str) {
        std::fs::write(
            root.join("stream/manifest.json"),
            serde_json::to_vec_pretty(&json!({
                "schema_version": CORPUS_FIXTURE_SCHEMA_VERSION,
                "api_family": "stream",
                "investigation_bead_id": "bd-0em5z",
                "cases": [{
                    "id": "tc::stream::descriptor-capture",
                    "file": case_file,
                    "band": "core",
                    "risk_band": "critical"
                }]
            }))
            .expect("serialize test manifest"),
        )
        .expect("write test manifest");
    }

    #[cfg(unix)]
    fn write_descriptor_test_corpus_at(root: &Path, source: &[u8]) {
        std::fs::create_dir_all(root.join("stream")).expect("create descriptor-test family");
        std::fs::write(root.join("stream/case.mjs"), source).expect("write descriptor-test case");
        write_test_manifest(root, "case.mjs");
    }

    #[cfg(unix)]
    fn write_descriptor_test_corpus(source: &[u8]) -> tempfile::TempDir {
        let corpus = tempfile::TempDir::new().expect("descriptor-test tempdir");
        write_descriptor_test_corpus_at(corpus.path(), source);
        corpus
    }

    #[test]
    fn both_runtime_legs_stage_identical_frozen_nested_inputs() {
        let corpus = tempfile::TempDir::new().expect("corpus tempdir");
        let nested = corpus.path().join("stream/nested");
        std::fs::create_dir_all(&nested).expect("create nested family directory");
        let case_path = nested.join("case.mjs");
        let support_path = nested.join("_local.mjs");
        let original_case = b"import { value } from './_local.mjs'; console.log(value);\n";
        let original_support = b"export const value = 'before';\n";
        std::fs::write(&case_path, original_case).expect("write original case");
        std::fs::write(&support_path, original_support).expect("write original support");
        write_test_manifest(corpus.path(), "nested/case.mjs");
        let snapshot = capture_corpus(corpus.path()).expect("capture snapshot");

        std::fs::write(&case_path, b"console.log('after');\n").expect("mutate case");
        std::fs::write(&support_path, b"export const value = 'after';\n").expect("mutate support");

        let snapshot_case = snapshot.cases.first().expect("snapshot case");
        let family = snapshot.families.get("stream").expect("snapshot family");
        let bun_leg = tempfile::TempDir::new().expect("bun leg tempdir");
        let franken_leg = tempfile::TempDir::new().expect("franken leg tempdir");
        stage_snapshot_case(snapshot_case, family, bun_leg.path()).expect("stage bun leg");
        stage_snapshot_case(snapshot_case, family, franken_leg.path()).expect("stage franken leg");

        for (relative, expected) in [
            (Path::new("nested/case.mjs"), original_case.as_slice()),
            (Path::new("nested/_local.mjs"), original_support.as_slice()),
        ] {
            let bun_bytes = std::fs::read(bun_leg.path().join(relative)).expect("read bun input");
            let franken_bytes =
                std::fs::read(franken_leg.path().join(relative)).expect("read franken input");
            assert_eq!(bun_bytes, expected);
            assert_eq!(franken_bytes, expected);
            assert_eq!(bun_bytes, franken_bytes);
        }
    }

    #[test]
    fn aggregate_snapshot_bound_accepts_exact_limit_and_refuses_one_more_byte() {
        let mut total = MAX_CORPUS_SNAPSHOT_BYTES - 1;
        add_bounded_bytes(&mut total, 1, MAX_CORPUS_SNAPSHOT_BYTES, "test snapshot")
            .expect("exact aggregate limit succeeds");
        assert_eq!(total, MAX_CORPUS_SNAPSHOT_BYTES);
        let error = add_bounded_bytes(&mut total, 1, MAX_CORPUS_SNAPSHOT_BYTES, "test snapshot")
            .expect_err("one byte over aggregate limit refuses");
        assert!(error.to_string().contains("exceeds"));
    }

    #[cfg(unix)]
    #[test]
    fn descriptor_capture_rejects_case_inode_replacement_between_stat_and_open() {
        use std::cell::Cell;
        use std::rc::Rc;

        let corpus = write_descriptor_test_corpus(b"console.log('original');\n");
        let case_path = corpus.path().join("stream/case.mjs");
        let displaced_path = corpus.path().join("stream/case.before-open.mjs");
        let triggered = Rc::new(Cell::new(false));
        let probe_triggered = Rc::clone(&triggered);
        let mut probe = TestCaptureProbe(move |phase, kind, relative_path| {
            if !probe_triggered.get()
                && phase == TestCapturePhase::AfterStatBeforeOpen
                && kind == CaptureKind::Case
                && relative_path == Path::new("stream/case.mjs")
            {
                std::fs::rename(&case_path, &displaced_path)
                    .context("displace case after descriptor-relative stat")?;
                std::fs::write(&case_path, b"console.log('replacement');\n")
                    .context("replace case before descriptor-relative open")?;
                probe_triggered.set(true);
            }
            Ok(())
        });

        let error = capture_corpus_with_probe(corpus.path(), &mut probe)
            .expect_err("inode replacement must fail closed");
        assert!(triggered.get(), "the replacement probe must run");
        assert!(
            format!("{error:#}").contains("changed during corpus capture"),
            "unexpected replacement error: {error:#}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn descriptor_capture_rejects_symlink_substitution_before_open() {
        use std::cell::Cell;
        use std::os::unix::fs::symlink;
        use std::rc::Rc;

        let corpus = write_descriptor_test_corpus(b"console.log('original');\n");
        let outside = tempfile::TempDir::new().expect("outside tempdir");
        let outside_path = outside.path().join("outside.mjs");
        std::fs::write(&outside_path, b"console.log('outside-secret');\n")
            .expect("write outside case");
        let case_path = corpus.path().join("stream/case.mjs");
        let displaced_path = corpus.path().join("stream/case.before-symlink.mjs");
        let reached_open = Rc::new(Cell::new(false));
        let probe_reached_open = Rc::clone(&reached_open);
        let mut probe = TestCaptureProbe(move |phase, kind, relative_path| {
            if kind == CaptureKind::Case && relative_path == Path::new("stream/case.mjs") {
                if phase == TestCapturePhase::AfterStatBeforeOpen {
                    std::fs::rename(&case_path, &displaced_path)
                        .context("displace case before symlink substitution")?;
                    symlink(&outside_path, &case_path)
                        .context("substitute outside symlink before open")?;
                } else if phase == TestCapturePhase::AfterOpenBeforeRead {
                    probe_reached_open.set(true);
                }
            }
            Ok(())
        });

        let error = capture_corpus_with_probe(corpus.path(), &mut probe)
            .expect_err("symlink substitution must fail closed");
        assert!(
            !reached_open.get(),
            "a no-follow open must reject the symlink before the opened-descriptor hook"
        );
        assert!(
            format!("{error:#}").contains("open descriptor-relative no-follow corpus file"),
            "unexpected symlink-substitution error: {error:#}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn descriptor_capture_reads_opened_inode_after_symlink_swap_and_restore() {
        use std::cell::Cell;
        use std::os::unix::fs::symlink;
        use std::rc::Rc;

        let original = b"console.log('opened-inode');\n";
        let corpus = write_descriptor_test_corpus(original);
        let outside = tempfile::TempDir::new().expect("outside tempdir");
        let outside_path = outside.path().join("outside.mjs");
        std::fs::write(&outside_path, b"console.log('outside-secret');\n")
            .expect("write outside case");
        let case_path = corpus.path().join("stream/case.mjs");
        let displaced_path = corpus.path().join("stream/case.opened.mjs");
        let transient_link_path = corpus.path().join("stream/case.transient-link.mjs");
        let probe_state = Rc::new(Cell::new(0_u8));
        let observed_state = Rc::clone(&probe_state);
        let mut probe = TestCaptureProbe(move |phase, kind, relative_path| {
            if kind == CaptureKind::Case && relative_path == Path::new("stream/case.mjs") {
                if probe_state.get() == 0 && phase == TestCapturePhase::AfterOpenBeforeRead {
                    std::fs::rename(&case_path, &displaced_path)
                        .context("displace case after descriptor open")?;
                    symlink(&outside_path, &case_path)
                        .context("replace ambient case path after descriptor open")?;
                    probe_state.set(1);
                } else if probe_state.get() == 1 && phase == TestCapturePhase::AfterFirstRead {
                    std::fs::rename(&case_path, &transient_link_path)
                        .context("move transient symlink before restoring case path")?;
                    std::fs::rename(&displaced_path, &case_path)
                        .context("restore original case path after first descriptor read")?;
                    probe_state.set(2);
                }
            }
            Ok(())
        });

        let snapshot = capture_corpus_with_probe(corpus.path(), &mut probe)
            .expect("the already-opened descriptor remains authoritative");
        assert_eq!(
            observed_state.get(),
            2,
            "the ambient symlink swap and restoration must both run"
        );
        assert_eq!(
            snapshot.cases[0].source_bytes, original,
            "capture must read the opened inode, never the transient pathname target"
        );
    }

    #[cfg(unix)]
    #[test]
    fn descriptor_capture_rejects_support_inode_replacement_between_stat_and_open() {
        use std::cell::Cell;
        use std::rc::Rc;

        let corpus = write_descriptor_test_corpus(b"console.log('case');\n");
        let support_path = corpus.path().join("stream/_support.mjs");
        let displaced_path = corpus.path().join("stream/_support.before-open.mjs");
        std::fs::write(&support_path, b"export const value = 'original';\n")
            .expect("write original support");
        let triggered = Rc::new(Cell::new(false));
        let probe_triggered = Rc::clone(&triggered);
        let mut probe = TestCaptureProbe(move |phase, kind, relative_path| {
            if !probe_triggered.get()
                && phase == TestCapturePhase::AfterStatBeforeOpen
                && kind == CaptureKind::Support
                && relative_path == Path::new("stream/_support.mjs")
            {
                std::fs::rename(&support_path, &displaced_path)
                    .context("displace support after descriptor-relative stat")?;
                std::fs::write(&support_path, b"export const value = 'replacement';\n")
                    .context("replace support before descriptor-relative open")?;
                probe_triggered.set(true);
            }
            Ok(())
        });

        let error = capture_corpus_with_probe(corpus.path(), &mut probe)
            .expect_err("support inode replacement must fail closed");
        assert!(triggered.get(), "the support replacement probe must run");
        assert!(
            format!("{error:#}").contains("changed during corpus capture"),
            "unexpected support-replacement error: {error:#}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn descriptor_capture_keeps_root_pinned_after_ambient_root_replacement() {
        use std::cell::Cell;
        use std::rc::Rc;

        let parent = tempfile::TempDir::new().expect("parent tempdir");
        let corpus_root = parent.path().join("corpus");
        let displaced_root = parent.path().join("corpus.opened");
        let original = b"console.log('pinned-root');\n";
        write_descriptor_test_corpus_at(&corpus_root, original);
        let root_for_probe = corpus_root.clone();
        let triggered = Rc::new(Cell::new(false));
        let probe_triggered = Rc::clone(&triggered);
        let mut probe = TestCaptureProbe(move |phase, kind, observed_root| {
            if !probe_triggered.get()
                && phase == TestCapturePhase::AfterRootOpen
                && kind == CaptureKind::Root
                && observed_root == root_for_probe
            {
                std::fs::rename(&root_for_probe, &displaced_root)
                    .context("displace corpus root after descriptor open")?;
                std::fs::create_dir_all(&root_for_probe)
                    .context("create ambient replacement corpus root")?;
                std::fs::write(root_for_probe.join("decoy.txt"), b"ambient replacement\n")
                    .context("write replacement-root marker")?;
                probe_triggered.set(true);
            }
            Ok(())
        });

        let snapshot = capture_corpus_with_probe(&corpus_root, &mut probe)
            .expect("the pinned root descriptor remains authoritative");
        assert!(triggered.get(), "the root replacement probe must run");
        assert_eq!(
            snapshot.cases[0].source_bytes, original,
            "capture must remain under the originally opened root"
        );
    }

    #[cfg(unix)]
    #[test]
    fn descriptor_capture_rejects_in_place_change_after_first_read() {
        use std::cell::Cell;
        use std::rc::Rc;

        let original = vec![b'x'; 16_384];
        let corpus = write_descriptor_test_corpus(&original);
        let case_path = corpus.path().join("stream/case.mjs");
        let triggered = Rc::new(Cell::new(false));
        let probe_triggered = Rc::clone(&triggered);
        let mut probe = TestCaptureProbe(move |phase, kind, relative_path| {
            if !probe_triggered.get()
                && phase == TestCapturePhase::AfterFirstRead
                && kind == CaptureKind::Case
                && relative_path == Path::new("stream/case.mjs")
            {
                std::fs::write(&case_path, b"changed during descriptor read\n")
                    .context("mutate case after first descriptor read")?;
                probe_triggered.set(true);
            }
            Ok(())
        });

        let error = capture_corpus_with_probe(corpus.path(), &mut probe)
            .expect_err("in-place mutation must fail closed");
        assert!(triggered.get(), "the in-place mutation probe must run");
        assert!(
            format!("{error:#}").contains("changed while it was being captured"),
            "unexpected in-place mutation error: {error:#}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn descriptor_capture_rejects_manifest_replacement_between_stat_and_open() {
        use std::cell::Cell;
        use std::rc::Rc;

        let corpus = write_descriptor_test_corpus(b"console.log('case');\n");
        let manifest_path = corpus.path().join("stream/manifest.json");
        let displaced_path = corpus.path().join("stream/manifest.before-open.json");
        let original_manifest = std::fs::read(&manifest_path).expect("read original manifest");
        let triggered = Rc::new(Cell::new(false));
        let probe_triggered = Rc::clone(&triggered);
        let mut probe = TestCaptureProbe(move |phase, kind, relative_path| {
            if !probe_triggered.get()
                && phase == TestCapturePhase::AfterStatBeforeOpen
                && kind == CaptureKind::Manifest
                && relative_path == Path::new("stream/manifest.json")
            {
                std::fs::rename(&manifest_path, &displaced_path)
                    .context("displace manifest after descriptor-relative stat")?;
                std::fs::write(&manifest_path, &original_manifest)
                    .context("replace manifest before descriptor-relative open")?;
                probe_triggered.set(true);
            }
            Ok(())
        });

        let error = capture_corpus_with_probe(corpus.path(), &mut probe)
            .expect_err("manifest inode replacement must fail closed");
        assert!(triggered.get(), "the manifest replacement probe must run");
        assert!(
            format!("{error:#}").contains("changed during corpus capture"),
            "unexpected manifest-replacement error: {error:#}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn snapshot_refuses_nonregular_case_and_support_inputs() {
        use std::os::unix::net::UnixListener;

        let case_corpus = tempfile::TempDir::new().expect("case corpus tempdir");
        let case_family = case_corpus.path().join("stream");
        std::fs::create_dir_all(&case_family).expect("create case family");
        let case_socket = case_family.join("case.mjs");
        let _case_listener = UnixListener::bind(&case_socket).expect("bind case socket");
        write_test_manifest(case_corpus.path(), "case.mjs");
        let error =
            capture_corpus(case_corpus.path()).expect_err("nonregular case input must refuse");
        assert!(error.to_string().contains("missing or unsafe"));

        let support_corpus = tempfile::TempDir::new().expect("support corpus tempdir");
        let support_family = support_corpus.path().join("stream");
        std::fs::create_dir_all(&support_family).expect("create support family");
        let support_case = support_family.join("case.mjs");
        std::fs::write(&support_case, b"console.log('case');\n").expect("write support case");
        let support_socket = support_family.join("_support.mjs");
        let _support_listener = UnixListener::bind(&support_socket).expect("bind support socket");
        write_test_manifest(support_corpus.path(), "case.mjs");
        let error = capture_corpus(support_corpus.path())
            .expect_err("nonregular support input must refuse");
        assert!(error.to_string().contains("not a regular non-symlink file"));
    }
}

#[cfg(all(test, feature = "engine", not(unix)))]
mod unsupported_descriptor_capture_tests {
    use super::*;

    #[test]
    fn unsupported_targets_refuse_before_resolving_the_corpus_path() {
        let error = capture_corpus(Path::new("definitely-not-a-corpus"))
            .expect_err("unsupported targets must fail closed");
        assert_eq!(
            error.to_string(),
            "descriptor-relative no-follow corpus capture is unavailable on this target; refusing to run"
        );
    }
}
