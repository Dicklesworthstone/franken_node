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
    if !corpus_root.is_dir() {
        bail!("corpus root {} is not a directory", corpus_root.display());
    }

    let mut family_dirs: Vec<PathBuf> = std::fs::read_dir(corpus_root)
        .with_context(|| format!("read corpus root {}", corpus_root.display()))?
        .filter_map(std::result::Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.is_dir())
        .collect();
    family_dirs.sort();

    let mut cases = Vec::new();
    let mut seen_ids = BTreeSet::new();
    for dir in family_dirs {
        let manifest_path = dir.join("manifest.json");
        if !manifest_path.is_file() {
            bail!(
                "corpus family directory {} has no manifest.json",
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
                Component::ParentDir | Component::Prefix(_) | Component::RootDir
            )
        })
    {
        bail!("corpus case `{case_id}` path must stay within its family directory");
    }
    Ok(relative)
}

/// Content-addressed corpus version: `compat-corpus-v1-<12 hex>` over the
/// sorted case sources and every underscore-prefixed support file staged beside
/// them, so identical executable corpus content yields an identical version
/// string on any machine (INV-CCG-REPRODUCIBILITY).
pub fn content_addressed_corpus_version(
    corpus_root: &Path,
    cases: &[ResolvedCase],
) -> Result<String> {
    let mut hasher = Sha256::new();
    hasher.update(b"ccg_corpus_content_version_v1:");
    let mut ordered: Vec<&ResolvedCase> = cases.iter().collect();
    ordered.sort_by(|a, b| a.test_id.cmp(&b.test_id));
    for case in ordered {
        let bytes = bounded_read_bytes(&case.source_path, MAX_CASE_FILE_BYTES)
            .with_context(|| format!("read corpus case {}", case.source_path.display()))?;
        hasher.update(case.test_id.as_bytes());
        hasher.update([0x1f]);
        hasher.update(&bytes);
        hasher.update([0x1e]);
    }

    // A support module is executable input even though it has no manifest case
    // of its own. Hash the exact set that `stage_support_files` copies, once per
    // family directory, under corpus-root-relative names. Length prefixes make
    // the framing unambiguous, and sorting removes read_dir traversal order.
    let mut family_dirs = BTreeMap::<String, PathBuf>::new();
    for case in cases {
        let family_dir = case
            .source_path
            .parent()
            .with_context(|| format!("corpus case `{}` has no parent directory", case.test_id))?;
        let relative_family = corpus_relative_path(corpus_root, family_dir)?;
        if let Some(existing) =
            family_dirs.insert(relative_family.clone(), family_dir.to_path_buf())
            && existing != family_dir
        {
            bail!("corpus family path `{relative_family}` resolves to multiple directories");
        }
    }

    let mut support_files = Vec::new();
    for (relative_family, family_dir) in family_dirs {
        for (name, source_path) in staged_support_files(&family_dir)? {
            let relative_path = if relative_family.is_empty() {
                name
            } else {
                format!("{relative_family}/{name}")
            };
            support_files.push((relative_path, source_path));
        }
    }
    support_files.sort_by(|left, right| left.0.cmp(&right.0));

    // Preserve the historical digest for corpora with no staged helpers while
    // giving helper-bearing corpora an explicitly domain-separated extension.
    if !support_files.is_empty() {
        hasher.update(b"ccg_corpus_staged_support_files_v1:");
        hasher.update((support_files.len() as u64).to_be_bytes());
        for (relative_path, source_path) in support_files {
            let bytes = bounded_read_bytes(&source_path, MAX_CASE_FILE_BYTES)
                .with_context(|| format!("read corpus support file {}", source_path.display()))?;
            hasher.update((relative_path.len() as u64).to_be_bytes());
            hasher.update(relative_path.as_bytes());
            hasher.update((bytes.len() as u64).to_be_bytes());
            hasher.update(&bytes);
        }
    }

    let digest = hex::encode(hasher.finalize());
    Ok(format!("compat-corpus-v1-{}", &digest[..12]))
}

fn corpus_relative_path(corpus_root: &Path, path: &Path) -> Result<String> {
    let relative = path.strip_prefix(corpus_root).with_context(|| {
        format!(
            "corpus family directory {} is outside corpus root {}",
            path.display(),
            corpus_root.display()
        )
    })?;
    let mut components = Vec::new();
    for component in relative.components() {
        let Component::Normal(component) = component else {
            bail!(
                "corpus-relative support path {} is not canonical",
                relative.display()
            );
        };
        components.push(component.to_str().with_context(|| {
            format!(
                "corpus-relative support path {} is not UTF-8",
                relative.display()
            )
        })?);
    }
    Ok(components.join("/"))
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
        if name_str.starts_with('_') && entry.file_type()?.is_file() {
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
    cases: &[ResolvedCase],
    case_timeout: Duration,
) -> Result<(Vec<CaseOutcome>, String)> {
    use crate::runtime::nversion_oracle::{
        BoundaryScope, CheckOutcome, RuntimeEntry, RuntimeOracle,
    };

    if cases.is_empty() {
        bail!("no corpus cases to run");
    }

    // Reference leg availability + version pin (fail-closed like the
    // single-guest lockstep producer).
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

    let mut outcomes = Vec::with_capacity(cases.len());
    for case in cases {
        let source_bytes = bounded_read_bytes(&case.source_path, MAX_CASE_FILE_BYTES)
            .with_context(|| format!("read corpus case {}", case.source_path.display()))?;
        let file_name = case
            .source_path
            .file_name()
            .and_then(std::ffi::OsStr::to_str)
            .with_context(|| format!("corpus case `{}` has a non-UTF8 file name", case.test_id))?
            .to_string();

        let family_dir = case
            .source_path
            .parent()
            .with_context(|| format!("corpus case `{}` has no parent directory", case.test_id))?;

        // Reference leg sandbox: same workspace scaffold as the franken leg so
        // filesystem-observing fixtures receive identical ambient inputs.
        let bun_dir = tempfile::TempDir::new().context("create bun leg sandbox")?;
        copy_dir_recursive(template.path(), bun_dir.path(), 0)
            .context("clone workspace template into bun leg sandbox")?;
        std::fs::write(bun_dir.path().join(&file_name), &source_bytes)
            .context("stage bun leg case file")?;
        stage_support_files(family_dir, bun_dir.path())?;
        let mut bun_cmd = Command::new("bun");
        bun_cmd.arg(&file_name).current_dir(bun_dir.path());
        let bun_leg = run_leg(bun_cmd, case_timeout)
            .with_context(|| format!("bun leg failed to launch for case `{}`", case.test_id))?;

        // Franken leg sandbox: cloned workspace template + case file.
        let franken_dir = tempfile::TempDir::new().context("create franken leg sandbox")?;
        copy_dir_recursive(template.path(), franken_dir.path(), 0)
            .context("clone workspace template into franken leg sandbox")?;
        std::fs::write(franken_dir.path().join(&file_name), &source_bytes)
            .context("stage franken leg case file")?;
        stage_support_files(family_dir, franken_dir.path())?;
        let mut franken_cmd = Command::new(&current_exe);
        franken_cmd
            .arg("run")
            .arg(&file_name)
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
                &source_bytes,
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

/// Stage a family directory's shared support files (underscore-prefixed
/// siblings such as `_stream_harness.mjs`) into a leg sandbox so fixtures
/// that import them resolve identically on both runtimes.
#[cfg(feature = "engine")]
fn stage_support_files(family_dir: &Path, sandbox: &Path) -> Result<()> {
    for (name, source_path) in staged_support_files(family_dir)? {
        std::fs::copy(source_path, sandbox.join(&name))
            .with_context(|| format!("stage support file {name}"))?;
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
