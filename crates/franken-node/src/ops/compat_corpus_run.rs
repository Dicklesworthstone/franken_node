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
/// Upper bound on all executable case and support bytes held by one snapshot.
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
    cases: Vec<SnapshotCase>,
    families: BTreeMap<String, SnapshotFamily>,
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

/// Discover and validate every family manifest under the corpus root.
///
/// Directories are visited in sorted order; case ids and case files must be
/// unique across the whole corpus. Every case path must stay inside its
/// family directory (no absolute paths, no `..`).
pub fn discover_corpus(corpus_root: &Path) -> Result<Vec<ResolvedCase>> {
    let root_metadata = std::fs::symlink_metadata(corpus_root)
        .with_context(|| format!("inspect corpus root {}", corpus_root.display()))?;
    if root_metadata.file_type().is_symlink() || !root_metadata.is_dir() {
        bail!("corpus root {} is not a directory", corpus_root.display());
    }

    let mut family_dirs = Vec::new();
    for entry in std::fs::read_dir(corpus_root)
        .with_context(|| format!("read corpus root {}", corpus_root.display()))?
    {
        let entry = entry
            .with_context(|| format!("read corpus root entry under {}", corpus_root.display()))?;
        let file_type = entry
            .file_type()
            .with_context(|| format!("inspect corpus root entry {}", entry.path().display()))?;
        if file_type.is_symlink() {
            bail!(
                "corpus root contains a symlink entry: {}",
                entry.path().display()
            );
        }
        if file_type.is_dir() {
            family_dirs.push(entry.path());
        }
    }
    family_dirs.sort();

    let mut cases = Vec::new();
    let mut seen_ids = BTreeSet::new();
    for dir in family_dirs {
        let manifest_path = dir.join("manifest.json");
        let manifest_metadata = std::fs::symlink_metadata(&manifest_path);
        if !manifest_metadata
            .as_ref()
            .is_ok_and(|metadata| metadata.is_file() && !metadata.file_type().is_symlink())
        {
            bail!(
                "corpus family directory {} has no regular non-symlink manifest.json",
                dir.display()
            );
        }
        let raw = crate::bounded_read_to_string(&manifest_path, MAX_FAMILY_MANIFEST_BYTES)
            .with_context(|| format!("read corpus manifest {}", manifest_path.display()))?;
        let manifest: CorpusFamilyManifest = serde_json::from_str(&raw)
            .with_context(|| format!("parse corpus manifest {}", manifest_path.display()))?;
        if manifest.schema_version != CORPUS_FIXTURE_SCHEMA_VERSION {
            bail!(
                "corpus manifest {} has schema_version `{}`; only `{}` is supported",
                manifest_path.display(),
                manifest.schema_version,
                CORPUS_FIXTURE_SCHEMA_VERSION
            );
        }
        if manifest.api_family.trim().is_empty() {
            bail!(
                "corpus manifest {} has an empty api_family",
                manifest_path.display()
            );
        }
        if manifest.cases.is_empty() {
            bail!("corpus manifest {} has no cases", manifest_path.display());
        }
        // Multiple directories MAY contribute to one family (the pinned
        // `stream/` fixture set plus its extension directory), so families
        // repeat across manifests; only ids/files must be globally unique.
        for case in &manifest.cases {
            if !seen_ids.insert(case.id.clone()) {
                bail!("duplicate corpus case id `{}`", case.id);
            }
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
            let relative = validated_case_relative_path(&case.id, &case.file)?;
            let source_path = dir.join(&relative);
            if !source_path.is_file() {
                bail!(
                    "corpus case `{}` fixture missing: {}",
                    case.id,
                    source_path.display()
                );
            }
            if cases.len() >= MAX_CORPUS_TOTAL_CASES {
                bail!("corpus exceeds the {MAX_CORPUS_TOTAL_CASES}-case bound; refusing to run");
            }
            cases.push(ResolvedCase {
                test_id: case.id.clone(),
                api_family: manifest.api_family.clone(),
                band: case.band.clone(),
                risk_band: case.risk_band.clone(),
                source_path,
                investigation_bead_id: manifest.investigation_bead_id.clone(),
            });
        }
    }

    if cases.is_empty() {
        bail!(
            "corpus root {} contains no family manifests",
            corpus_root.display()
        );
    }
    let mut seen_paths = BTreeSet::new();
    for case in &cases {
        if !seen_paths.insert(case.source_path.clone()) {
            bail!(
                "corpus case file appears twice across manifests: {}",
                case.source_path.display()
            );
        }
    }
    Ok(cases)
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

/// Capture all executable corpus inputs exactly once after fail-closed path
/// validation. Hashing and both runtime legs consume only the returned bytes.
pub fn snapshot_corpus(corpus_root: &Path, cases: &[ResolvedCase]) -> Result<CorpusSnapshot> {
    if cases.is_empty() {
        bail!("cannot snapshot an empty corpus");
    }
    let root_metadata = std::fs::symlink_metadata(corpus_root)
        .with_context(|| format!("inspect corpus root {}", corpus_root.display()))?;
    if root_metadata.file_type().is_symlink() || !root_metadata.is_dir() {
        bail!(
            "corpus root {} must be a regular directory, not a symlink",
            corpus_root.display()
        );
    }
    let canonical_root = std::fs::canonicalize(corpus_root)
        .with_context(|| format!("canonicalize corpus root {}", corpus_root.display()))?;

    let mut snapshot_cases = Vec::with_capacity(cases.len());
    let mut family_dirs = BTreeMap::<String, PathBuf>::new();
    let mut staged_paths = BTreeMap::<String, BTreeSet<PathBuf>>::new();
    let mut support_dirs = BTreeMap::<String, BTreeSet<PathBuf>>::new();
    let mut snapshot_bytes = 0usize;
    for case in cases {
        let (family_key, staged_relative_path) =
            split_case_relative_path(corpus_root, &case.source_path)?;
        let corpus_relative_path = Path::new(&family_key).join(&staged_relative_path);
        let validated_path = validate_snapshot_file(
            corpus_root,
            &canonical_root,
            &corpus_relative_path,
            &format!("corpus case `{}`", case.test_id),
        )?;
        let source_bytes = bounded_read_bytes(&validated_path, MAX_CASE_FILE_BYTES)
            .with_context(|| format!("read corpus case {}", validated_path.display()))?;
        add_bounded_bytes(
            &mut snapshot_bytes,
            source_bytes.len(),
            MAX_CORPUS_SNAPSHOT_BYTES,
            "corpus executable-input snapshot",
        )?;

        let family_dir = corpus_root.join(&family_key);
        if let Some(existing) = family_dirs.insert(family_key.clone(), family_dir.clone())
            && existing != family_dir
        {
            bail!("corpus family `{family_key}` resolves to multiple directories");
        }
        if !staged_paths
            .entry(family_key.clone())
            .or_default()
            .insert(staged_relative_path.clone())
        {
            bail!(
                "multiple corpus cases stage to `{}` in family `{family_key}`",
                staged_relative_path.display()
            );
        }
        let family_support_dirs = support_dirs.entry(family_key.clone()).or_default();
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
            case: case.clone(),
            family_key,
            corpus_relative_path: normalized_relative_path(&corpus_relative_path, "corpus case")?,
            staged_relative_path,
            source_bytes,
        });
    }

    let mut support_total_bytes = 0usize;
    let mut support_file_count = 0usize;
    let mut families = BTreeMap::new();
    for (family_key, family_dir) in family_dirs {
        let family_support_dirs = support_dirs
            .remove(&family_key)
            .context("snapshot family support-directory set is missing")?;
        let mut support_paths = Vec::new();
        for relative_dir in family_support_dirs {
            let support_dir = family_dir.join(&relative_dir);
            for (name, source_path) in staged_support_files(&support_dir)? {
                support_paths.push((relative_dir.join(name), source_path));
            }
        }
        support_paths.sort_by(|left, right| left.0.cmp(&right.0));
        if support_paths.len() > MAX_SUPPORT_FILES_PER_FAMILY {
            bail!(
                "corpus family `{family_key}` has {} support files; maximum is {MAX_SUPPORT_FILES_PER_FAMILY}",
                support_paths.len()
            );
        }
        support_file_count = support_file_count
            .checked_add(support_paths.len())
            .context("corpus support-file count overflow")?;
        if support_file_count > MAX_SUPPORT_FILES_TOTAL {
            bail!(
                "corpus has {support_file_count} support files; maximum is {MAX_SUPPORT_FILES_TOTAL}"
            );
        }
        let family_staged_paths = staged_paths
            .get_mut(&family_key)
            .context("snapshot family staging set is missing")?;
        let mut support_files = Vec::with_capacity(support_paths.len());
        for (staged_relative_path, source_path) in support_paths {
            if !family_staged_paths.insert(staged_relative_path.clone()) {
                bail!(
                    "corpus case/support staging collision at `{}` in family `{family_key}`",
                    staged_relative_path.display()
                );
            }
            let corpus_relative = Path::new(&family_key).join(&staged_relative_path);
            let normalized_corpus_relative =
                normalized_relative_path(&corpus_relative, "corpus support file")?;
            let validated_path = validate_snapshot_file(
                corpus_root,
                &canonical_root,
                &corpus_relative,
                &format!("corpus support file `{}`", staged_relative_path.display()),
            )?;
            debug_assert_eq!(validated_path, source_path);
            let bytes =
                bounded_read_bytes(&validated_path, MAX_CASE_FILE_BYTES).with_context(|| {
                    format!("read corpus support file {}", validated_path.display())
                })?;
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
                corpus_relative_path: normalized_corpus_relative,
                staged_relative_path,
                bytes,
            });
        }
        families.insert(family_key, SnapshotFamily { support_files });
    }

    Ok(CorpusSnapshot {
        cases: snapshot_cases,
        families,
    })
}

fn split_case_relative_path(corpus_root: &Path, source_path: &Path) -> Result<(String, PathBuf)> {
    let relative = source_path.strip_prefix(corpus_root).with_context(|| {
        format!(
            "corpus case path {} is outside corpus root {}",
            source_path.display(),
            corpus_root.display()
        )
    })?;
    let mut components = relative.components();
    let Some(Component::Normal(family)) = components.next() else {
        bail!(
            "corpus case path {} has no family directory",
            relative.display()
        );
    };
    let family_key = family
        .to_str()
        .with_context(|| format!("corpus family path {} is not UTF-8", relative.display()))?
        .to_string();
    let staged_relative_path: PathBuf = components.collect();
    if staged_relative_path.as_os_str().is_empty()
        || staged_relative_path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        bail!(
            "corpus case path {} has an invalid family-relative path",
            relative.display()
        );
    }
    Ok((family_key, staged_relative_path))
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

fn validate_snapshot_file(
    corpus_root: &Path,
    canonical_root: &Path,
    relative: &Path,
    label: &str,
) -> Result<PathBuf> {
    let mut current = corpus_root.to_path_buf();
    let components: Vec<_> = relative.components().collect();
    if components.is_empty() {
        bail!("{label} has an empty corpus-relative path");
    }
    for (index, component) in components.iter().enumerate() {
        let Component::Normal(component) = component else {
            bail!("{label} path must stay within the corpus root");
        };
        current.push(component);
        let metadata = std::fs::symlink_metadata(&current)
            .with_context(|| format!("inspect {label} path component {}", current.display()))?;
        if metadata.file_type().is_symlink() {
            bail!("{label} contains symlink component: {}", current.display());
        }
        let is_last = index + 1 == components.len();
        if is_last && !metadata.is_file() {
            bail!("{label} is not a regular file: {}", current.display());
        }
        if !is_last && !metadata.is_dir() {
            bail!(
                "{label} has a non-directory parent component: {}",
                current.display()
            );
        }
    }
    let canonical = std::fs::canonicalize(&current)
        .with_context(|| format!("canonicalize {label} {}", current.display()))?;
    if !canonical.starts_with(canonical_root) {
        bail!(
            "{label} escapes corpus root {}: {}",
            canonical_root.display(),
            canonical.display()
        );
    }
    Ok(current)
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

fn staged_support_files(family_dir: &Path) -> Result<Vec<(String, PathBuf)>> {
    let mut support_files = Vec::new();
    for entry in std::fs::read_dir(family_dir)
        .with_context(|| format!("read corpus family dir {}", family_dir.display()))?
    {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name_str) = name.to_str() else {
            continue;
        };
        if name_str.starts_with('_') {
            let file_type = entry.file_type()?;
            if file_type.is_dir() {
                continue;
            }
            if file_type.is_symlink() || !file_type.is_file() {
                bail!(
                    "corpus support input is not a regular non-symlink file: {}",
                    entry.path().display()
                );
            }
            support_files.push((name_str.to_string(), entry.path()));
        }
    }
    support_files.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(support_files)
}

fn bounded_read_bytes(path: &Path, max_bytes: usize) -> Result<Vec<u8>> {
    let file = std::fs::File::open(path)?;
    let mut bytes = Vec::new();
    let mut handle = file.take(max_bytes as u64 + 1);
    handle.read_to_end(&mut bytes)?;
    if bytes.len() > max_bytes {
        bail!("{} exceeds the {max_bytes}-byte bound", path.display());
    }
    Ok(bytes)
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

#[cfg(all(test, feature = "engine"))]
mod snapshot_staging_tests {
    use super::*;

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
        let cases = vec![ResolvedCase {
            test_id: "tc::stream::frozen-staging".to_string(),
            api_family: "stream".to_string(),
            band: "core".to_string(),
            risk_band: "critical".to_string(),
            source_path: case_path.clone(),
            investigation_bead_id: Some("bd-nc5b8".to_string()),
        }];
        let snapshot = snapshot_corpus(corpus.path(), &cases).expect("capture snapshot");

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
    fn snapshot_refuses_nonregular_case_and_support_inputs() {
        use std::os::unix::net::UnixListener;

        let case_corpus = tempfile::TempDir::new().expect("case corpus tempdir");
        let case_family = case_corpus.path().join("stream");
        std::fs::create_dir_all(&case_family).expect("create case family");
        let case_socket = case_family.join("case.mjs");
        let _case_listener = UnixListener::bind(&case_socket).expect("bind case socket");
        let cases = vec![ResolvedCase {
            test_id: "tc::stream::socket-case".to_string(),
            api_family: "stream".to_string(),
            band: "core".to_string(),
            risk_band: "critical".to_string(),
            source_path: case_socket,
            investigation_bead_id: Some("bd-nc5b8".to_string()),
        }];
        let error = snapshot_corpus(case_corpus.path(), &cases)
            .expect_err("nonregular case input must refuse");
        assert!(error.to_string().contains("not a regular file"));

        let support_corpus = tempfile::TempDir::new().expect("support corpus tempdir");
        let support_family = support_corpus.path().join("stream");
        std::fs::create_dir_all(&support_family).expect("create support family");
        let support_case = support_family.join("case.mjs");
        std::fs::write(&support_case, b"console.log('case');\n").expect("write support case");
        let support_socket = support_family.join("_support.mjs");
        let _support_listener = UnixListener::bind(&support_socket).expect("bind support socket");
        let cases = vec![ResolvedCase {
            test_id: "tc::stream::socket-support".to_string(),
            api_family: "stream".to_string(),
            band: "core".to_string(),
            risk_band: "critical".to_string(),
            source_path: support_case,
            investigation_bead_id: Some("bd-nc5b8".to_string()),
        }];
        let error = snapshot_corpus(support_corpus.path(), &cases)
            .expect_err("nonregular support input must refuse");
        assert!(error.to_string().contains("not a regular non-symlink file"));
    }
}
