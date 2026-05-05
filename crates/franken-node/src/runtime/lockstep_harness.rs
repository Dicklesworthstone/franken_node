use crate::runtime::nversion_oracle::{
    BoundaryScope, CheckOutcome, DivergenceReport, OracleVerdict, RiskTier, RuntimeEntry,
    RuntimeOracle, SemanticDivergence,
};
use anyhow::{Context, Result};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{File, OpenOptions, TryLockError};
use std::io::{ErrorKind, Read, Write};
#[cfg(unix)]
use std::os::unix::process::CommandExt;
use std::path::{Component, Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{
    Arc, Mutex, OnceLock,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use std::thread;
use std::time::{Duration, Instant};

use crate::push_bounded;

// Security: bounds for push_bounded to prevent memory exhaustion
const MAX_COMBINED_OUTPUT_BYTES: usize = 16_777_216; // 16MB limit per runtime execution
const MAX_LOCKSTEP_CORPUS_CASES: usize = 256;
const MAX_SANITIZED_STRACE_LINES: usize = 65_536; // 64K syscall lines max
const MAX_THREAD_HANDLES: usize = 64; // Maximum concurrent runtime threads
const PIPE_READ_CHUNK_BYTES: usize = 64 * 1024;
const DIVERGENCE_FIXTURE_LOCK_FILE: &str = ".lockstep-fixtures.lock";
const DIVERGENCE_FIXTURE_LOCK_RETRY_BACKOFF_MILLIS: [u64; 3] = [100, 200, 400];

#[derive(Debug, Deserialize)]
struct LockstepCorpusManifest {
    cases: Vec<LockstepCorpusCase>,
}

#[derive(Debug, Deserialize)]
struct LockstepCorpusCase {
    id: String,
    file: String,
}

fn extend_bounded(items: &mut Vec<u8>, new_data: &[u8], max_total_bytes: usize) {
    if max_total_bytes == 0 {
        items.clear();
        return;
    }
    let current_len = items.len();
    let new_len = current_len.saturating_add(new_data.len());
    if new_len >= max_total_bytes {
        // Truncate existing data to make room
        let overflow = new_len.saturating_sub(max_total_bytes);
        if overflow >= current_len {
            // New data alone exceeds limit, clear and take prefix
            items.clear();
            let take_len = new_data.len().min(max_total_bytes);
            items.extend_from_slice(&new_data[..take_len]);
        } else {
            // Remove overflow from beginning, then add new data
            items.drain(0..overflow.min(items.len()));
            items.extend_from_slice(new_data);
        }
    } else {
        items.extend_from_slice(new_data);
    }
}

/// Process-local lockstep divergence fixture persistence lock.
///
/// Canonical lifecycle: fixture emission creates the output directory, acquires
/// this mutex, then acquires the per-directory fixture flock before writing all
/// temp fixtures and atomically renaming them into place. Drop order releases
/// the file flock first and this mutex second. Callers must not acquire another
/// module's persist lock while holding it. If it is left held or poisoned,
/// lockstep divergence fixture export in this process blocks or fails before
/// new fixture files are created.
fn persist_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

#[must_use]
struct DivergenceFixturePersistLockGuard {
    file: File,
    path: PathBuf,
}

impl Drop for DivergenceFixturePersistLockGuard {
    fn drop(&mut self) {
        if let Err(source) = self.file.unlock() {
            tracing::warn!(
                path = %self.path.display(),
                error = %source,
                "failed to release lockstep divergence fixture lock"
            );
        }
    }
}

pub struct LockstepHarness {
    runtimes: Vec<String>,
}

#[derive(Debug)]
struct PipeDrainResult {
    bytes: Vec<u8>,
    cap_reached: bool,
}

impl LockstepHarness {
    const DIRECTORY_ENTRY_CANDIDATES: [&'static str; 3] = ["index.js", "index.mjs", "index.cjs"];
    const BUN_DIRECTORY_ENTRY_CANDIDATES: [&'static str; 5] = [
        "index.ts",
        "index.tsx",
        "index.js",
        "index.mjs",
        "index.cjs",
    ];

    pub fn new(runtimes: Vec<String>) -> Self {
        Self {
            runtimes: Self::normalize_runtimes(runtimes),
        }
    }

    fn normalize_runtimes(runtimes: Vec<String>) -> Vec<String> {
        let mut normalized = Vec::with_capacity(runtimes.len().min(32));
        let mut seen = BTreeSet::new();
        for mut runtime in runtimes {
            let trimmed_len = runtime.trim().len();
            if trimmed_len == 0 {
                continue;
            }

            if trimmed_len != runtime.len() {
                runtime = runtime.trim().to_string();
            }

            if seen.insert(runtime.clone()) {
                push_bounded(&mut normalized, runtime, 32); // Reasonable limit for runtime count
            }
        }
        normalized
    }

    fn validate_runtimes(&self) -> Result<()> {
        if self.runtimes.len() >= 2 {
            return Ok(());
        }

        let configured = if self.runtimes.is_empty() {
            "none".to_string()
        } else {
            self.runtimes.join(", ")
        };
        anyhow::bail!("verify lockstep requires at least two distinct runtimes; got {configured}");
    }

    fn is_franken_runtime(runtime: &str) -> bool {
        matches!(
            runtime,
            "franken-node" | "franken_engine" | "franken-engine"
        )
    }

    fn runtime_uses_js_entrypoints(runtime: &str) -> bool {
        matches!(runtime, "node" | "bun")
    }

    fn directory_entry_candidates(runtime: &str) -> &'static [&'static str] {
        if runtime == "bun" {
            &Self::BUN_DIRECTORY_ENTRY_CANDIDATES
        } else {
            &Self::DIRECTORY_ENTRY_CANDIDATES
        }
    }

    fn entrypoint_extensions(runtime: &str) -> &'static [&'static str] {
        if runtime == "bun" {
            &["ts", "tsx", "js", "mjs", "cjs"]
        } else {
            &["js", "mjs", "cjs"]
        }
    }

    fn resolve_runtime_binary(runtime: &str) -> String {
        Self::resolve_runtime_binary_with(runtime, &|configured_hint| {
            crate::ops::engine_dispatcher::resolve_engine_binary_path(configured_hint)
        })
    }

    fn resolve_runtime_binary_with(
        runtime: &str,
        franken_resolver: &impl Fn(&str) -> String,
    ) -> String {
        match runtime {
            "node" => "node".to_string(),
            "bun" => "bun".to_string(),
            runtime_name if Self::is_franken_runtime(runtime_name) => {
                franken_resolver("franken-engine")
            }
            _ => runtime.to_string(),
        }
    }

    pub(crate) fn resolve_runtime_target(runtime: &str, app_path: &Path) -> Result<PathBuf> {
        if !Self::runtime_uses_js_entrypoints(runtime) || app_path.is_file() || !app_path.is_dir() {
            return Ok(app_path.to_path_buf());
        }

        Self::resolve_directory_entrypoint(runtime, app_path).with_context(|| {
            format!(
                "lockstep input `{}` is not directly executable for runtime `{runtime}`",
                app_path.display()
            )
        })
    }

    fn resolve_directory_entrypoint(runtime: &str, project_dir: &Path) -> Result<PathBuf> {
        let package_json_path = project_dir.join("package.json");
        let mut unresolved_main: Option<String> = None;
        if package_json_path.exists() {
            let root = project_dir.canonicalize().with_context(|| {
                format!(
                    "failed resolving lockstep project root {}",
                    project_dir.display()
                )
            })?;
            let resolved = package_json_path.canonicalize().with_context(|| {
                format!(
                    "failed resolving package manifest {}",
                    package_json_path.display()
                )
            })?;
            if !resolved.starts_with(&root) {
                anyhow::bail!(
                    "package.json must reside within {} and not escape via symlinks",
                    project_dir.display()
                );
            }
            let package_json = std::fs::read(&resolved).with_context(|| {
                format!("failed reading package manifest {}", resolved.display())
            })?;
            let manifest: serde_json::Value =
                serde_json::from_slice(&package_json).with_context(|| {
                    format!(
                        "invalid package manifest JSON while resolving lockstep entrypoint: {}",
                        resolved.display()
                    )
                })?;

            if let Some(main) = manifest
                .get("main")
                .and_then(serde_json::Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
            {
                if let Some(resolved) = Self::resolve_entry_candidate(project_dir, main, runtime) {
                    return Ok(resolved);
                }
                unresolved_main = Some(main.to_string());
            }
        }

        for candidate in Self::directory_entry_candidates(runtime) {
            let path = project_dir.join(candidate);
            if path.is_file() && Self::path_within_project(project_dir, &path) {
                return Ok(path);
            }
        }

        if let Some(main) = unresolved_main {
            anyhow::bail!(
                "package.json main `{main}` did not resolve under {} and no fallback entrypoint was found ({})",
                project_dir.display(),
                Self::directory_entry_candidates(runtime).join(", ")
            );
        }

        anyhow::bail!(
            "no executable JS entrypoint found under {} (checked package.json main and {})",
            project_dir.display(),
            Self::directory_entry_candidates(runtime).join(", ")
        );
    }

    fn resolve_entry_candidate(
        project_dir: &Path,
        raw_target: &str,
        runtime: &str,
    ) -> Option<PathBuf> {
        let normalized = raw_target.trim().trim_start_matches("./");
        if normalized.is_empty() {
            return None;
        }

        // Reject path traversal in untrusted package.json main field:
        // absolute paths, ".." segments, backslashes, and embedded NULs.
        if normalized.starts_with('/')
            || normalized.contains('\\')
            || normalized.contains('\0')
            || normalized.split('/').any(|seg| seg == "..")
        {
            return None;
        }

        let candidate = project_dir.join(normalized);
        if candidate.is_file() && Self::path_within_project(project_dir, &candidate) {
            return Some(candidate);
        }

        if candidate.extension().is_none() {
            for extension in Self::entrypoint_extensions(runtime) {
                let with_extension = candidate.with_extension(extension);
                if with_extension.is_file()
                    && Self::path_within_project(project_dir, &with_extension)
                {
                    return Some(with_extension);
                }
            }
        }

        if candidate.is_dir() {
            if !Self::path_within_project(project_dir, &candidate) {
                return None;
            }
            for entry in Self::directory_entry_candidates(runtime) {
                let nested = candidate.join(entry);
                if nested.is_file() && Self::path_within_project(project_dir, &nested) {
                    return Some(nested);
                }
            }
        }

        None
    }

    fn path_within_project(project_dir: &Path, candidate: &Path) -> bool {
        let Ok(root) = project_dir.canonicalize() else {
            return false;
        };
        let Ok(resolved) = candidate.canonicalize() else {
            return false;
        };
        resolved.starts_with(&root)
    }

    /// Spawns the specified runtimes concurrently, intercepts their outputs,
    /// and feeds the results to the Oracle.
    pub fn verify_lockstep(&self, app_path: &Path, emit_fixtures: bool) -> Result<()> {
        self.validate_runtimes()?;
        if let Some(corpus_entries) = Self::resolve_lockstep_corpus_entries(app_path)? {
            for entry in corpus_entries {
                self.verify_lockstep_entry(&entry, emit_fixtures)
                    .with_context(|| {
                        format!("lockstep corpus fixture failed: {}", entry.display())
                    })?;
            }
            return Ok(());
        }

        self.verify_lockstep_entry(app_path, emit_fixtures)
    }

    fn resolve_lockstep_corpus_entries(app_path: &Path) -> Result<Option<Vec<PathBuf>>> {
        let manifest_path = if app_path.is_dir() {
            app_path.join("manifest.json")
        } else if app_path.file_name().and_then(std::ffi::OsStr::to_str) == Some("manifest.json") {
            app_path.to_path_buf()
        } else {
            return Ok(None);
        };

        if !manifest_path.is_file() {
            return Ok(None);
        }

        let corpus_root = manifest_path
            .parent()
            .ok_or_else(|| anyhow::anyhow!("lockstep corpus manifest has no parent directory"))?;
        let raw = std::fs::read(&manifest_path).with_context(|| {
            format!(
                "failed reading lockstep corpus manifest {}",
                manifest_path.display()
            )
        })?;
        let manifest: LockstepCorpusManifest = serde_json::from_slice(&raw).with_context(|| {
            format!(
                "invalid lockstep corpus manifest JSON in {}",
                manifest_path.display()
            )
        })?;

        if manifest.cases.is_empty() {
            anyhow::bail!(
                "lockstep corpus manifest {} has no cases",
                manifest_path.display()
            );
        }
        if manifest.cases.len() > MAX_LOCKSTEP_CORPUS_CASES {
            anyhow::bail!(
                "lockstep corpus manifest {} has {} cases, above limit {}",
                manifest_path.display(),
                manifest.cases.len(),
                MAX_LOCKSTEP_CORPUS_CASES
            );
        }

        let mut entries = Vec::new();
        let mut seen_ids = BTreeSet::new();
        let mut seen_paths = BTreeSet::new();
        for case in manifest.cases {
            if !seen_ids.insert(case.id.clone()) {
                anyhow::bail!("duplicate lockstep corpus case id `{}`", case.id);
            }
            let relative_path = Self::validated_corpus_case_path(&case)?;
            let entry = corpus_root.join(relative_path);
            if !entry.is_file() || !Self::path_within_project(corpus_root, &entry) {
                anyhow::bail!(
                    "lockstep corpus case `{}` points outside corpus root or missing file: {}",
                    case.id,
                    entry.display()
                );
            }
            if !seen_paths.insert(entry.clone()) {
                anyhow::bail!(
                    "duplicate lockstep corpus case file in manifest: {}",
                    entry.display()
                );
            }
            push_bounded(&mut entries, entry, MAX_LOCKSTEP_CORPUS_CASES);
        }

        Ok(Some(entries))
    }

    fn validated_corpus_case_path(case: &LockstepCorpusCase) -> Result<PathBuf> {
        let raw = case.file.trim();
        if raw.is_empty() || raw.contains('\\') || raw.contains('\0') {
            anyhow::bail!(
                "lockstep corpus case `{}` has an invalid fixture path",
                case.id
            );
        }
        let relative_path = PathBuf::from(raw);
        if relative_path.is_absolute()
            || relative_path.components().any(|component| {
                matches!(
                    component,
                    Component::ParentDir | Component::Prefix(_) | Component::RootDir
                )
            })
        {
            anyhow::bail!(
                "lockstep corpus case `{}` path must stay within the corpus root",
                case.id
            );
        }
        Ok(relative_path)
    }

    fn verify_lockstep_entry(&self, app_path: &Path, emit_fixtures: bool) -> Result<()> {
        let mut oracle = RuntimeOracle::new("lockstep-harness-trace", 100);

        for rt in &self.runtimes {
            oracle
                .register_runtime(RuntimeEntry {
                    runtime_id: rt.clone(),
                    runtime_name: rt.clone(),
                    version: "unknown".to_string(),
                    is_reference: !Self::is_franken_runtime(rt),
                })
                .map_err(|e| anyhow::anyhow!("Oracle registration error: {}", e))?;
        }

        // Spawn parallel execution threads for each runtime
        let mut handles = Vec::new();
        for rt in self.runtimes.clone() {
            let app_path_buf = app_path.to_path_buf();
            let handle = thread::spawn(move || -> Result<(String, Vec<u8>)> {
                let output = Self::execute_runtime(&rt, &app_path_buf)?;
                Ok((rt, output))
            });
            push_bounded(&mut handles, handle, MAX_THREAD_HANDLES);
        }

        let mut outputs = BTreeMap::new();
        for handle in handles {
            match handle.join() {
                Ok(Ok((rt, out))) => {
                    outputs.insert(rt, out);
                }
                Ok(Err(e)) => anyhow::bail!("Runtime execution error: {}", e),
                Err(_) => anyhow::bail!("Runtime execution panicked"),
            }
        }

        // Run the cross-runtime check
        let check_id = format!("check-{}", uuid::Uuid::now_v7());
        // Simple heuristic: passing the source code as input payload for auditing
        let input_payload = if app_path.is_file() {
            std::fs::read(app_path).unwrap_or_default()
        } else {
            let pkg_path = app_path.join("package.json");
            std::fs::read(pkg_path)
                .unwrap_or_else(|_| app_path.to_string_lossy().as_bytes().to_vec())
        };

        let check = oracle
            .run_cross_check(
                &check_id,
                BoundaryScope::IO, // Uses IO boundary due to strace filesystem/network tracking
                &input_payload,
                &outputs,
            )
            .map_err(|e| anyhow::anyhow!("Oracle cross check error: {}", e))?;

        if let Some(CheckOutcome::Diverge {
            outputs: div_outputs,
        }) = check.outcome
        {
            oracle.classify_divergence(
                &format!("div-{}", check_id),
                &check_id,
                BoundaryScope::IO,
                RiskTier::High,
                &div_outputs,
            );
        }

        // Generate and print the report
        let report = oracle.generate_report(0);
        if emit_fixtures && !report.divergences.is_empty() {
            for path in Self::emit_divergence_fixtures(app_path, &report)? {
                eprintln!("lockstep divergence fixture written: {}", path.display());
            }
        }
        let canonical_json = serde_json::to_string_pretty(&report)?;
        println!("{}", canonical_json);

        Self::ensure_report_passes(&report)
    }

    fn ensure_report_passes(report: &DivergenceReport) -> Result<()> {
        match &report.verdict {
            OracleVerdict::Pass => Ok(()),
            OracleVerdict::BlockRelease {
                blocking_divergence_ids,
            } => anyhow::bail!(
                "lockstep verification diverged; verdict=block_release blocking_divergences={}",
                blocking_divergence_ids.join(",")
            ),
            OracleVerdict::RequiresReceipt {
                pending_divergence_ids,
            } => anyhow::bail!(
                "lockstep verification diverged; verdict=requires_receipt pending_divergences={}",
                pending_divergence_ids.join(",")
            ),
        }
    }

    fn emit_divergence_fixtures(
        app_path: &Path,
        report: &DivergenceReport,
    ) -> Result<Vec<PathBuf>> {
        let output_dir = Self::fixture_output_dir(app_path);
        std::fs::create_dir_all(&output_dir).with_context(|| {
            format!(
                "failed creating lockstep fixture output dir {}",
                output_dir.display()
            )
        })?;

        let _persist_guard = persist_lock()
            .lock()
            .map_err(|_| anyhow::anyhow!("lockstep divergence fixture persist lock poisoned"))?;
        let _fixture_lock = Self::acquire_divergence_fixture_persist_lock(&output_dir)?;

        let mut written = Vec::new();
        for divergence in &report.divergences {
            let path = output_dir.join(format!(
                "{}_min.json",
                Self::sanitize_fixture_token(&divergence.divergence_id)
            ));
            let fixture = Self::divergence_fixture_value(app_path, report, divergence);
            let payload = serde_json::to_string_pretty(&fixture)
                .context("failed serializing generated lockstep divergence fixture")?;
            Self::write_divergence_fixture_atomic(&path, &format!("{payload}\n"))?;
            push_bounded(&mut written, path, 1024); // Reasonable limit for divergence fixtures
        }

        Ok(written)
    }

    fn acquire_divergence_fixture_persist_lock(
        output_dir: &Path,
    ) -> Result<DivergenceFixturePersistLockGuard> {
        let path = output_dir.join(DIVERGENCE_FIXTURE_LOCK_FILE);
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .with_context(|| {
                format!(
                    "failed opening lockstep divergence fixture lock {}",
                    path.display()
                )
            })?;
        Self::lock_divergence_fixture_file(&file, &path)?;
        Ok(DivergenceFixturePersistLockGuard { file, path })
    }

    fn lock_divergence_fixture_file(file: &File, path: &Path) -> Result<()> {
        match file.try_lock() {
            Ok(()) => return Ok(()),
            Err(TryLockError::WouldBlock) => {
                // Will retry with backoff below
            }
            Err(TryLockError::Error(err)) => {
                return Err(err).with_context(|| {
                    format!(
                        "failed locking lockstep divergence fixture lock {}",
                        path.display()
                    )
                });
            }
        }

        for delay_millis in DIVERGENCE_FIXTURE_LOCK_RETRY_BACKOFF_MILLIS {
            thread::sleep(Duration::from_millis(delay_millis));
            match file.try_lock() {
                Ok(()) => return Ok(()),
                Err(TryLockError::WouldBlock) => {
                    // Continue retrying
                }
                Err(TryLockError::Error(err)) => {
                    return Err(err).with_context(|| {
                        format!(
                            "failed locking lockstep divergence fixture lock {}",
                            path.display()
                        )
                    });
                }
            }
        }

        anyhow::bail!(
            "timed out locking lockstep divergence fixture lock {} after retries at 100ms/200ms/400ms",
            path.display()
        );
    }

    fn write_divergence_fixture_atomic(path: &Path, payload: &str) -> Result<()> {
        let file_name = path.file_name().with_context(|| {
            format!(
                "failed deriving lockstep divergence fixture file name for {}",
                path.display()
            )
        })?;
        let temp_path = path.with_file_name(format!(
            ".{}.{}.tmp",
            file_name.to_string_lossy(),
            uuid::Uuid::now_v7()
        ));
        let mut temp_file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp_path)
            .with_context(|| {
                format!(
                    "failed creating lockstep divergence fixture temp file {}",
                    temp_path.display()
                )
            })?;
        temp_file.write_all(payload.as_bytes()).with_context(|| {
            format!(
                "failed writing lockstep divergence fixture temp file {}",
                temp_path.display()
            )
        })?;
        temp_file.sync_all().with_context(|| {
            format!(
                "failed syncing lockstep divergence fixture temp file {}",
                temp_path.display()
            )
        })?;
        drop(temp_file);

        std::fs::rename(&temp_path, path).with_context(|| {
            format!(
                "failed atomically publishing lockstep divergence fixture {}",
                path.display()
            )
        })?;

        let parent = path.parent().with_context(|| {
            format!(
                "failed deriving parent directory for lockstep divergence fixture {}",
                path.display()
            )
        })?;
        File::open(parent)
            .and_then(|dir| dir.sync_all())
            .with_context(|| {
                format!(
                    "failed syncing lockstep divergence fixture directory {}",
                    parent.display()
                )
            })?;
        Ok(())
    }

    fn fixture_output_dir(app_path: &Path) -> PathBuf {
        let base = if app_path.is_dir() {
            app_path.to_path_buf()
        } else {
            app_path
                .parent()
                .map_or_else(|| PathBuf::from("."), Path::to_path_buf)
        };
        base.join("fixtures").join("lockstep")
    }

    fn divergence_fixture_value(
        app_path: &Path,
        report: &DivergenceReport,
        divergence: &SemanticDivergence,
    ) -> serde_json::Value {
        let runtime_outputs = divergence
            .runtime_outputs
            .iter()
            .map(|(runtime, output)| {
                (
                    runtime.clone(),
                    serde_json::json!({
                        "encoding": "base64",
                        "value": BASE64_STANDARD.encode(output),
                    }),
                )
            })
            .collect::<serde_json::Map<String, serde_json::Value>>();

        serde_json::json!({
            "id": format!(
                "fixture:lockstep:oracle:{}",
                Self::sanitize_fixture_token(&divergence.divergence_id)
            ),
            "api_family": "lockstep",
            "api_name": "oracle",
            "band": Self::fixture_band(divergence.risk_tier),
            "description": format!(
                "Auto-generated divergence fixture for {}",
                app_path.to_string_lossy().replace('\\', "/")
            ),
            "input": {
                "args": [app_path.to_string_lossy().replace('\\', "/")],
                "env": {
                    "boundary_scope": divergence.boundary_scope.label(),
                    "runtimes": report.runtimes.keys().cloned().collect::<Vec<_>>(),
                    "trace_id": report.trace_id.as_str(),
                },
                "files": {},
            },
            "expected_output": {
                "oracle_verdict": report.verdict.label(),
                "risk_tier": divergence.risk_tier.label(),
                "runtime_outputs": runtime_outputs,
            },
            "oracle_source": "lockstep-oracle",
            "tags": [
                "generated",
                "divergence",
                divergence.boundary_scope.label(),
                divergence.risk_tier.label(),
            ],
        })
    }

    fn fixture_band(risk_tier: RiskTier) -> &'static str {
        if risk_tier.blocks_release() {
            "high-value"
        } else {
            "edge"
        }
    }

    fn sanitize_fixture_token(raw: &str) -> String {
        let mut token = String::new();
        for ch in raw.chars() {
            if ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-' || ch == '_' {
                token.push(ch);
            } else if ch.is_ascii_uppercase() {
                token.push(ch.to_ascii_lowercase());
            } else {
                token.push('-');
            }
        }

        let trimmed = token.trim_matches('-');
        if trimmed.is_empty() {
            "lockstep-divergence".to_string()
        } else {
            trimmed.to_string()
        }
    }

    fn execute_runtime(runtime: &str, app_path: &Path) -> Result<Vec<u8>> {
        let bin_path = Self::resolve_runtime_binary(runtime);
        let runtime_target = Self::resolve_runtime_target(runtime, app_path)?;

        let mut cmd = Command::new("strace");

        let strace_output_file = tempfile::Builder::new()
            .prefix(&format!("strace_{}_", runtime.replace('-', "_")))
            .suffix(".log")
            .tempfile()
            .context("Failed to create secure temporary file for strace")?;

        // Wrap execution in strace to intercept and record filesystem and network mutations
        // -f: trace child processes
        // -e trace=file,network: only trace I/O and network boundaries
        // -o: output to temp file
        cmd.arg("-f")
            .arg("-e")
            .arg("trace=file,network")
            .arg("-o")
            .arg(strace_output_file.path())
            .arg(&bin_path);

        if Self::is_franken_runtime(runtime) {
            cmd.arg("run").arg(app_path);
        } else {
            cmd.arg(&runtime_target);
        }
        Self::isolate_child_process_group(&mut cmd);

        let mut child = cmd
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .with_context(|| {
                format!(
                    "Failed to spawn strace on runtime (is strace installed?): {}",
                    runtime
                )
            })?;

        // Drain stdout and stderr in background threads to prevent pipe buffer deadlock
        let mut stdout_handle = child.stdout.take().ok_or_else(|| {
            anyhow::anyhow!("runtime {runtime} stdout pipe unavailable despite Stdio::piped()")
        })?;
        let mut stderr_handle = child.stderr.take().ok_or_else(|| {
            anyhow::anyhow!("runtime {runtime} stderr pipe unavailable despite Stdio::piped()")
        })?;

        let captured_output_bytes = Arc::new(AtomicUsize::new(0));
        let output_cap_reached = Arc::new(AtomicBool::new(false));

        let stdout_total = Arc::clone(&captured_output_bytes);
        let stdout_cap_reached = Arc::clone(&output_cap_reached);
        let stdout_thread = thread::spawn(move || {
            Self::drain_pipe_bounded(
                &mut stdout_handle,
                "stdout",
                stdout_total,
                stdout_cap_reached,
            )
        });

        let stderr_total = Arc::clone(&captured_output_bytes);
        let stderr_cap_reached = Arc::clone(&output_cap_reached);
        let stderr_thread = thread::spawn(move || {
            Self::drain_pipe_bounded(
                &mut stderr_handle,
                "stderr",
                stderr_total,
                stderr_cap_reached,
            )
        });

        let timeout = crate::config::timeouts::LOCKSTEP_RUNTIME_TIMEOUT;
        let start = Instant::now();

        let mut is_timeout = false;
        let mut is_output_cap_reached = false;
        let mut exit_code = -1;
        loop {
            if output_cap_reached.load(Ordering::Acquire) {
                Self::terminate_runtime_tree(&mut child);
                is_output_cap_reached = true;
                break;
            }
            if let Some(status) = child.try_wait()? {
                exit_code = status.code().unwrap_or(-1);
                break;
            }
            if Self::has_timed_out(start.elapsed(), timeout) {
                Self::terminate_runtime_tree(&mut child);
                is_timeout = true;
                break;
            }
            thread::sleep(crate::config::timeouts::LOCKSTEP_RUNTIME_POLL_INTERVAL);
        }

        let drain_timeout = crate::config::timeouts::LOCKSTEP_PIPE_DRAIN_JOIN_TIMEOUT;
        let stdout_result = Self::join_pipe_drain(stdout_thread, "stdout", drain_timeout);
        let stderr_result = Self::join_pipe_drain(stderr_thread, "stderr", drain_timeout);

        if is_output_cap_reached
            || stdout_result.cap_reached
            || stderr_result.cap_reached
            || output_cap_reached.load(Ordering::Acquire)
        {
            anyhow::bail!(
                "runtime output cap reached for {runtime}; captured at most {MAX_COMBINED_OUTPUT_BYTES} bytes"
            );
        }

        let mut combined_output = Vec::new();
        extend_bounded(
            &mut combined_output,
            &stdout_result.bytes,
            MAX_COMBINED_OUTPUT_BYTES,
        );
        extend_bounded(
            &mut combined_output,
            b"\n--- STDERR ---\n",
            MAX_COMBINED_OUTPUT_BYTES,
        );
        extend_bounded(
            &mut combined_output,
            &stderr_result.bytes,
            MAX_COMBINED_OUTPUT_BYTES,
        );
        extend_bounded(
            &mut combined_output,
            b"\n--- EXIT CODE ---\n",
            MAX_COMBINED_OUTPUT_BYTES,
        );
        if is_timeout {
            extend_bounded(&mut combined_output, b"TIMEOUT", MAX_COMBINED_OUTPUT_BYTES);
        } else {
            extend_bounded(
                &mut combined_output,
                exit_code.to_string().as_bytes(),
                MAX_COMBINED_OUTPUT_BYTES,
            );
        }

        // Append deterministic strace output to detect behavioral divergences
        extend_bounded(
            &mut combined_output,
            b"\n--- SYSTEM CALL BOUNDARIES ---\n",
            MAX_COMBINED_OUTPUT_BYTES,
        );
        let strace_content = Self::read_strace_output(strace_output_file.path(), runtime)?;
        // Filter out non-deterministic pointers/PIDs from strace output using simple heuristics
        // so we don't get false positive divergences for different runtimes doing the same thing.
        let deterministic_strace = Self::sanitize_strace_output(&strace_content);
        extend_bounded(
            &mut combined_output,
            &deterministic_strace,
            MAX_COMBINED_OUTPUT_BYTES,
        );

        Ok(combined_output)
    }

    fn has_timed_out(elapsed: Duration, timeout: Duration) -> bool {
        elapsed >= timeout
    }

    #[cfg(unix)]
    fn isolate_child_process_group(cmd: &mut Command) {
        cmd.process_group(0);
    }

    #[cfg(not(unix))]
    fn isolate_child_process_group(_cmd: &mut Command) {}

    fn terminate_runtime_tree(child: &mut Child) {
        #[cfg(unix)]
        Self::terminate_process_group(child.id());
        let _ = child.kill();
        let _ = child.wait();
    }

    #[cfg(unix)]
    fn terminate_process_group(child_pid: u32) {
        let process_group = format!("-{child_pid}");
        let _ = Command::new("kill")
            .arg("-TERM")
            .arg("--")
            .arg(&process_group)
            .status();
        thread::sleep(crate::config::timeouts::LOCKSTEP_PROCESS_KILL_GRACE);
        let _ = Command::new("kill")
            .arg("-KILL")
            .arg("--")
            .arg(&process_group)
            .status();
    }

    fn join_pipe_drain(
        handle: thread::JoinHandle<PipeDrainResult>,
        label: &str,
        timeout: Duration,
    ) -> PipeDrainResult {
        let start = Instant::now();
        while !handle.is_finished() {
            if Self::has_timed_out(start.elapsed(), timeout) {
                // Try a final join attempt with a grace period to prevent thread leaks
                let grace_timeout = timeout
                    .saturating_add(crate::config::timeouts::LOCKSTEP_PIPE_DRAIN_GRACE_EXTENSION);
                let grace_start = Instant::now();
                while !handle.is_finished() {
                    if Self::has_timed_out(grace_start.elapsed(), grace_timeout) {
                        // Detach the blocked reader thread and return a bounded timeout marker.
                        tracing::warn!(
                            stream = label,
                            timeout_ms = timeout.as_millis(),
                            grace_timeout_ms = grace_timeout.as_millis(),
                            "pipe drain thread detached after bounded timeout"
                        );
                        drop(handle);
                        return PipeDrainResult {
                            bytes: format!("__pipe_drain_timeout:{label}").into_bytes(),
                            cap_reached: false,
                        };
                    }
                    thread::sleep(crate::config::timeouts::LOCKSTEP_PIPE_DRAIN_JOIN_POLL);
                }
                break; // Thread finished during grace period
            }
            thread::sleep(crate::config::timeouts::LOCKSTEP_PIPE_DRAIN_JOIN_POLL);
        }
        handle.join().unwrap_or_else(|_| PipeDrainResult {
            bytes: format!("__thread_panic:{label}").into_bytes(),
            cap_reached: false,
        })
    }

    fn drain_pipe_bounded<R: Read>(
        reader: &mut R,
        label: &str,
        captured_output_bytes: Arc<AtomicUsize>,
        output_cap_reached: Arc<AtomicBool>,
    ) -> PipeDrainResult {
        let mut captured = Vec::new();
        let mut chunk = [0_u8; PIPE_READ_CHUNK_BYTES];
        let mut cap_reached = false;

        loop {
            match reader.read(&mut chunk) {
                Ok(0) => break,
                Ok(read_len) => {
                    let allowed = Self::reserve_output_bytes(
                        &captured_output_bytes,
                        read_len,
                        MAX_COMBINED_OUTPUT_BYTES,
                    );
                    if allowed > 0 {
                        extend_bounded(&mut captured, &chunk[..allowed], MAX_COMBINED_OUTPUT_BYTES);
                    }
                    if allowed < read_len
                        || captured_output_bytes.load(Ordering::Acquire)
                            >= MAX_COMBINED_OUTPUT_BYTES
                    {
                        output_cap_reached.store(true, Ordering::Release);
                        cap_reached = true;
                        break;
                    }
                }
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(e) => {
                    eprintln!("lockstep_harness: {label} read error (partial data retained): {e}");
                    break;
                }
            }
        }

        PipeDrainResult {
            bytes: captured,
            cap_reached,
        }
    }

    fn reserve_output_bytes(
        captured_output_bytes: &AtomicUsize,
        requested_bytes: usize,
        max_total_bytes: usize,
    ) -> usize {
        if requested_bytes == 0 || max_total_bytes == 0 {
            return 0;
        }

        let mut observed = captured_output_bytes.load(Ordering::Acquire);
        loop {
            if observed >= max_total_bytes {
                return 0;
            }
            let remaining = max_total_bytes.saturating_sub(observed);
            let allowed = requested_bytes.min(remaining);
            let next = observed.saturating_add(allowed);
            match captured_output_bytes.compare_exchange_weak(
                observed,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return allowed,
                Err(actual) => observed = actual,
            }
        }
    }

    fn read_strace_output(path: &Path, runtime: &str) -> Result<Vec<u8>> {
        std::fs::read(path).with_context(|| {
            format!(
                "strace output missing or unreadable for runtime {runtime}: {}",
                path.display()
            )
        })
    }

    /// Strips out PIDs, memory addresses, and timestamps from strace logs
    /// to ensure they can be compared deterministically across runtimes.
    fn sanitize_strace_output(raw: &[u8]) -> Vec<u8> {
        // Syscalls whose first argument is a runtime-specific file descriptor.
        const FD_SYSCALLS: &[&str] = &[
            "read",
            "write",
            "close",
            "fstat",
            "lseek",
            "mmap",
            "ioctl",
            "pread64",
            "pwrite64",
            "readv",
            "writev",
            "dup",
            "dup2",
            "fcntl",
            "flock",
            "fsync",
            "fdatasync",
            "ftruncate",
            "fchmod",
            "fchown",
            "sendfile",
            "fstatfs",
            "fadvise64",
            "epoll_ctl",
            "splice",
        ];

        let raw_str = String::from_utf8_lossy(raw);
        let mut sanitized = Vec::new();
        let mut line_count: usize = 0;

        for line in raw_str.lines() {
            line_count = line_count.saturating_add(1);
            if line_count >= MAX_SANITIZED_STRACE_LINES {
                break; // Prevent memory exhaustion from massive strace logs
            }
            let mut current = line.trim();
            // Strip [pid NNN] prefix
            if current.starts_with("[pid ")
                && let Some(idx) = current.find(']')
            {
                current = current[idx + 1..].trim();
            }
            // Strip leading numeric timestamp (can contain digits and dots)
            if let Some(idx) = current.find(' ')
                && current[..idx]
                    .chars()
                    .all(|c| c.is_ascii_digit() || c == '.')
            {
                current = current[idx + 1..].trim();
            }

            let Some((syscall_expr, return_expr)) = current.rsplit_once(" = ") else {
                continue;
            };

            // Normalize fd arguments: for fd-based syscalls, replace the
            // first numeric arg (the fd) with "FD" so that different fd
            // numbers across runs still match.
            let normalized = Self::normalize_fd_arg(syscall_expr.trim(), FD_SYSCALLS);
            let outcome = Self::normalize_return_outcome(return_expr);
            // Use bounded extensions to prevent memory exhaustion
            let max_line_bytes = (MAX_COMBINED_OUTPUT_BYTES / MAX_SANITIZED_STRACE_LINES).max(256);
            let current_len = sanitized.len();
            let max_capacity = current_len.saturating_add(max_line_bytes);
            extend_bounded(&mut sanitized, normalized.as_bytes(), max_capacity);
            extend_bounded(&mut sanitized, b" => ", max_capacity);
            extend_bounded(&mut sanitized, outcome.as_bytes(), max_capacity);
            if sanitized.len() < sanitized.capacity().saturating_sub(1) {
                sanitized.push(b'\n');
            }
        }
        sanitized
    }

    /// Replace the first numeric argument of known fd-based syscalls with "FD".
    fn normalize_fd_arg(line: &str, fd_syscalls: &[&str]) -> String {
        if let Some(paren) = line.find('(') {
            let name = &line[..paren];
            if fd_syscalls.contains(&name) {
                let args = &line[paren + 1..];
                // Find the end of the first numeric argument
                let num_end = args
                    .find(|c: char| !c.is_ascii_digit())
                    .unwrap_or(args.len());
                if num_end > 0 && args[..num_end].chars().all(|c| c.is_ascii_digit()) {
                    return format!("{name}(FD{}", &args[num_end..]);
                }
            }
        }
        line.to_string()
    }

    fn normalize_return_outcome(return_expr: &str) -> String {
        let trimmed = return_expr.trim();
        if trimmed.starts_with("-1") {
            let errno = trimmed
                .split_whitespace()
                .nth(1)
                .filter(|token| {
                    token
                        .chars()
                        .all(|ch| ch.is_ascii_uppercase() || ch == '_' || ch.is_ascii_digit())
                })
                .unwrap_or("ERR");
            return format!("err:{errno}");
        }

        if trimmed.starts_with('?') {
            return "unknown".to_string();
        }

        "ok".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::nversion_oracle::{CrossRuntimeCheck, OracleEvent};

    // ── Construction ──────────────────────────────────────────────────

    #[test]
    fn new_harness_stores_runtimes() {
        let h = LockstepHarness::new(vec!["node".into(), "bun".into()]);
        assert_eq!(h.runtimes.len(), 2);
        assert_eq!(h.runtimes[0], "node");
        assert_eq!(h.runtimes[1], "bun");
    }

    #[test]
    fn new_harness_empty_runtimes() {
        let h = LockstepHarness::new(vec![]);
        assert!(h.runtimes.is_empty());
    }

    #[test]
    fn new_harness_trims_and_deduplicates_runtimes() {
        let h = LockstepHarness::new(vec![
            " node ".into(),
            "".into(),
            "bun".into(),
            "node".into(),
            " franken-node ".into(),
            "bun".into(),
        ]);
        assert_eq!(h.runtimes, vec!["node", "bun", "franken-node"]);
    }

    #[test]
    fn new_harness_with_franken_runtimes() {
        let h = LockstepHarness::new(vec![
            "node".into(),
            "bun".into(),
            "franken-node".into(),
            "franken_engine".into(),
            "franken-engine".into(),
        ]);
        assert_eq!(h.runtimes.len(), 5);
    }

    #[test]
    fn timeout_boundary_is_fail_closed() {
        let timeout = Duration::from_millis(30);
        assert!(!LockstepHarness::has_timed_out(
            Duration::from_millis(29),
            timeout
        ));
        assert!(LockstepHarness::has_timed_out(
            Duration::from_millis(30),
            timeout
        ));
        assert!(LockstepHarness::has_timed_out(
            Duration::from_millis(31),
            timeout
        ));
    }

    #[test]
    fn pipe_drain_join_returns_finished_output() {
        let handle = thread::spawn(|| PipeDrainResult {
            bytes: b"drained".to_vec(),
            cap_reached: false,
        });
        let output = LockstepHarness::join_pipe_drain(handle, "stdout", Duration::from_secs(1));
        assert_eq!(output.bytes, b"drained".to_vec());
        assert!(!output.cap_reached);
    }

    #[test]
    fn pipe_drain_join_timeout_is_bounded() {
        let (sender, receiver) = std::sync::mpsc::channel::<()>();
        let handle = thread::spawn(move || {
            let _ = receiver.recv();
            PipeDrainResult {
                bytes: b"late-output".to_vec(),
                cap_reached: false,
            }
        });

        let start = Instant::now();
        let output = LockstepHarness::join_pipe_drain(handle, "stderr", Duration::from_millis(30));

        assert_eq!(output.bytes, b"__pipe_drain_timeout:stderr".to_vec());
        assert!(!output.cap_reached);
        assert!(start.elapsed() < Duration::from_secs(1));
        drop(sender);
    }

    #[test]
    fn pipe_drain_timeout_detaches_thread_and_allows_late_exit() {
        let (sender, receiver) = std::sync::mpsc::channel::<()>();
        let exited = Arc::new(AtomicBool::new(false));
        let exited_clone = Arc::clone(&exited);
        let handle = thread::spawn(move || {
            let _ = receiver.recv();
            exited_clone.store(true, Ordering::Release);
            PipeDrainResult {
                bytes: b"late-output".to_vec(),
                cap_reached: false,
            }
        });

        let output = LockstepHarness::join_pipe_drain(handle, "stdout", Duration::from_millis(30));

        assert_eq!(output.bytes, b"__pipe_drain_timeout:stdout".to_vec());
        assert!(!output.cap_reached);
        assert!(
            !exited.load(Ordering::Acquire),
            "thread should still be blocked when timeout marker is returned"
        );

        sender.send(()).expect("unblock detached thread");
        let deadline = Instant::now() + Duration::from_secs(1);
        while !exited.load(Ordering::Acquire) && Instant::now() < deadline {
            thread::sleep(crate::config::timeouts::LOCKSTEP_PIPE_DRAIN_JOIN_POLL);
        }
        assert!(
            exited.load(Ordering::Acquire),
            "detached pipe drain thread should still be able to exit after timeout"
        );
    }

    #[test]
    fn pipe_drain_applies_output_cap_while_reading() {
        let captured_output_bytes = Arc::new(AtomicUsize::new(0));
        let output_cap_reached = Arc::new(AtomicBool::new(false));
        let adversarial_len =
            u64::try_from(MAX_COMBINED_OUTPUT_BYTES.saturating_add(1024)).unwrap_or(u64::MAX);
        let mut reader = std::io::repeat(b'x').take(adversarial_len);

        let output = LockstepHarness::drain_pipe_bounded(
            &mut reader,
            "stdout",
            Arc::clone(&captured_output_bytes),
            Arc::clone(&output_cap_reached),
        );

        assert!(output.cap_reached);
        assert!(output_cap_reached.load(Ordering::Acquire));
        assert_eq!(
            captured_output_bytes.load(Ordering::Acquire),
            MAX_COMBINED_OUTPUT_BYTES
        );
        assert_eq!(output.bytes.len(), MAX_COMBINED_OUTPUT_BYTES);
    }

    #[cfg(unix)]
    #[test]
    fn execute_runtime_errors_when_output_cap_is_reached() {
        if Command::new("strace")
            .arg("-V")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_err()
        {
            eprintln!("skipping output cap test because strace is unavailable");
            return;
        }

        let temp = tempfile::tempdir().expect("tempdir");
        let runtime_path = temp.path().join("spam-runtime.sh");
        std::fs::write(
            &runtime_path,
            format!(
                "#!/bin/sh\nhead -c {} /dev/zero\nsleep 5\n",
                MAX_COMBINED_OUTPUT_BYTES.saturating_add(1024)
            ),
        )
        .expect("write runtime");
        let mut permissions = std::fs::metadata(&runtime_path)
            .expect("metadata")
            .permissions();
        std::os::unix::fs::PermissionsExt::set_mode(&mut permissions, 0o755);
        std::fs::set_permissions(&runtime_path, permissions).expect("chmod runtime");

        let app_path = temp.path().join("app.js");
        std::fs::write(&app_path, "console.log('unused');").expect("write app");

        let start = Instant::now();
        let err = LockstepHarness::execute_runtime(
            runtime_path.to_str().expect("utf-8 runtime path"),
            &app_path,
        )
        .expect_err("runtime output should hit cap");

        assert!(
            err.to_string().contains("runtime output cap reached"),
            "unexpected error: {err:#}"
        );
        assert!(start.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn resolve_runtime_binary_known_values() {
        assert_eq!(LockstepHarness::resolve_runtime_binary("node"), "node");
        assert_eq!(LockstepHarness::resolve_runtime_binary("bun"), "bun");
        let canonical = LockstepHarness::resolve_runtime_binary("franken-node");
        assert_eq!(
            LockstepHarness::resolve_runtime_binary("franken_engine"),
            canonical
        );
        assert_eq!(
            LockstepHarness::resolve_runtime_binary("franken-engine"),
            canonical
        );
    }

    #[test]
    fn recognizes_franken_runtime_aliases() {
        assert!(LockstepHarness::is_franken_runtime("franken-node"));
        assert!(LockstepHarness::is_franken_runtime("franken_engine"));
        assert!(LockstepHarness::is_franken_runtime("franken-engine"));
        assert!(!LockstepHarness::is_franken_runtime("node"));
    }

    #[test]
    fn resolve_runtime_binary_passthrough_custom_runtime() {
        assert_eq!(
            LockstepHarness::resolve_runtime_binary("custom-runtime"),
            "custom-runtime"
        );
    }

    #[test]
    fn resolve_runtime_binary_uses_shared_franken_resolver() {
        let resolved = LockstepHarness::resolve_runtime_binary_with("franken-node", &|_| {
            "/configured/franken-engine".to_string()
        });
        assert_eq!(resolved, "/configured/franken-engine");
    }

    #[test]
    fn validate_runtimes_requires_two_distinct_entries() {
        let err = LockstepHarness::new(vec!["node".into(), " node ".into()])
            .validate_runtimes()
            .expect_err("single distinct runtime must fail");
        assert!(format!("{err:#}").contains("at least two distinct runtimes"));
    }

    #[test]
    fn validate_runtimes_rejects_blank_only_entries() {
        let err = LockstepHarness::new(vec![" ".into(), "\n\t".into()])
            .validate_runtimes()
            .expect_err("blank-only runtime list must fail");
        let message = format!("{err:#}");
        assert!(message.contains("at least two distinct runtimes"));
        assert!(message.contains("got none"));
    }

    #[test]
    fn read_strace_output_reads_existing_file() {
        let temp_file = tempfile::NamedTempFile::new().expect("tempfile");
        std::fs::write(temp_file.path(), b"open(\"/tmp/test\", O_RDONLY) = 3\n")
            .expect("write strace");

        let contents =
            LockstepHarness::read_strace_output(temp_file.path(), "node").expect("read strace");
        assert!(contents.starts_with(b"open("));
    }

    #[test]
    fn read_strace_output_errors_when_file_missing() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let path = temp_dir.path().join("missing.log");
        assert!(!path.exists());

        let err = LockstepHarness::read_strace_output(&path, "node")
            .expect_err("missing strace file must fail");
        let message = format!("{err:#}");
        assert!(message.contains("strace output missing or unreadable for runtime node"));
    }

    #[test]
    fn read_strace_output_errors_when_path_is_directory() {
        let temp_dir = tempfile::tempdir().expect("tempdir");

        let err = LockstepHarness::read_strace_output(temp_dir.path(), "node")
            .expect_err("directory cannot be read as strace output");
        let message = format!("{err:#}");
        assert!(message.contains("strace output missing or unreadable for runtime node"));
    }

    #[test]
    fn resolve_runtime_target_keeps_file_inputs_unchanged() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let app_path = temp_dir.path().join("demo.js");
        std::fs::write(&app_path, "console.log('demo');").expect("write demo");

        let resolved =
            LockstepHarness::resolve_runtime_target("node", &app_path).expect("resolve target");
        assert_eq!(resolved, app_path);
    }

    #[test]
    fn resolve_runtime_target_keeps_directory_for_franken_runtime() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            temp_dir.path().join("package.json"),
            r#"{"name":"demo","main":"dist/server.js"}"#,
        )
        .expect("write package");
        std::fs::create_dir_all(temp_dir.path().join("dist")).expect("create dist");
        std::fs::write(
            temp_dir.path().join("dist/server.js"),
            "console.log('server');",
        )
        .expect("write server");

        let resolved = LockstepHarness::resolve_runtime_target("franken-node", temp_dir.path())
            .expect("resolve franken target");
        assert_eq!(resolved, temp_dir.path());
    }

    #[test]
    fn resolve_runtime_target_uses_package_json_main_for_js_runtimes() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            temp_dir.path().join("package.json"),
            r#"{"name":"demo","main":"dist/server"}"#,
        )
        .expect("write package");
        std::fs::create_dir_all(temp_dir.path().join("dist")).expect("create dist");
        let expected = temp_dir.path().join("dist/server.js");
        std::fs::write(&expected, "console.log('server');").expect("write server");

        let resolved =
            LockstepHarness::resolve_runtime_target("node", temp_dir.path()).expect("resolve");
        assert_eq!(resolved, expected);
    }

    #[test]
    fn resolve_runtime_target_falls_back_to_directory_index() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let expected = temp_dir.path().join("index.mjs");
        std::fs::write(&expected, "console.log('entry');").expect("write entry");

        let resolved =
            LockstepHarness::resolve_runtime_target("bun", temp_dir.path()).expect("resolve");
        assert_eq!(resolved, expected);
    }

    #[test]
    fn resolve_runtime_target_uses_bun_typescript_directory_entrypoint() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let expected = temp_dir.path().join("index.ts");
        std::fs::write(&expected, "console.log('entry');").expect("write entry");

        let resolved =
            LockstepHarness::resolve_runtime_target("bun", temp_dir.path()).expect("resolve");
        assert_eq!(resolved, expected);
    }

    #[test]
    fn resolve_runtime_target_uses_bun_main_directory_entrypoint() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            temp_dir.path().join("package.json"),
            r#"{"name":"demo","main":"src"}"#,
        )
        .expect("write package");
        let src_dir = temp_dir.path().join("src");
        std::fs::create_dir_all(&src_dir).expect("create src");
        let expected = src_dir.join("index.ts");
        std::fs::write(&expected, "console.log('entry');").expect("write entry");

        let resolved =
            LockstepHarness::resolve_runtime_target("bun", temp_dir.path()).expect("resolve");
        assert_eq!(resolved, expected);
    }

    #[test]
    fn resolve_runtime_target_uses_bun_extensionless_main_ts() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            temp_dir.path().join("package.json"),
            r#"{"name":"demo","main":"dist/server"}"#,
        )
        .expect("write package");
        let dist_dir = temp_dir.path().join("dist");
        std::fs::create_dir_all(&dist_dir).expect("create dist");
        let expected = dist_dir.join("server.ts");
        std::fs::write(&expected, "console.log('server');").expect("write server");

        let resolved =
            LockstepHarness::resolve_runtime_target("bun", temp_dir.path()).expect("resolve");
        assert_eq!(resolved, expected);
    }

    #[test]
    fn resolve_runtime_target_keeps_directory_for_custom_runtime() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(temp_dir.path().join("index.js"), "console.log('entry');")
            .expect("write entry");

        let resolved = LockstepHarness::resolve_runtime_target("custom-runtime", temp_dir.path())
            .expect("resolve custom runtime target");
        assert_eq!(resolved, temp_dir.path());
    }

    #[test]
    fn resolve_runtime_target_falls_back_to_index_when_package_main_is_missing() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            temp_dir.path().join("package.json"),
            r#"{"name":"demo","main":"dist/missing.js"}"#,
        )
        .expect("write package");
        let expected = temp_dir.path().join("index.js");
        std::fs::write(&expected, "console.log('fallback');").expect("write fallback");

        let resolved =
            LockstepHarness::resolve_runtime_target("node", temp_dir.path()).expect("resolve");
        assert_eq!(resolved, expected);
    }

    #[test]
    fn resolve_runtime_target_fails_when_package_main_and_fallbacks_are_missing() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            temp_dir.path().join("package.json"),
            r#"{"name":"demo","main":"dist/missing.js"}"#,
        )
        .expect("write package");

        let err = LockstepHarness::resolve_runtime_target("node", temp_dir.path())
            .expect_err("missing package main without fallback must fail");
        let message = format!("{err:#}");
        assert!(message.contains("package.json main `dist/missing.js` did not resolve"));
        assert!(message.contains("no fallback entrypoint was found"));
    }

    #[test]
    fn resolve_runtime_target_fails_when_directory_has_no_usable_entrypoint() {
        let temp_dir = tempfile::tempdir().expect("tempdir");

        let err = LockstepHarness::resolve_runtime_target("node", temp_dir.path())
            .expect_err("missing directory entrypoint must fail");
        let message = format!("{err:#}");
        assert!(message.contains("no executable JS entrypoint found"));
    }

    #[test]
    fn resolve_runtime_target_rejects_invalid_package_json() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(temp_dir.path().join("package.json"), b"{not-json")
            .expect("write malformed package");

        let err = LockstepHarness::resolve_runtime_target("node", temp_dir.path())
            .expect_err("malformed package manifest must fail");
        let message = format!("{err:#}");
        assert!(message.contains("invalid package manifest JSON"));
    }

    #[test]
    fn resolve_runtime_target_rejects_absolute_package_main_without_fallback() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            temp_dir.path().join("package.json"),
            r#"{"name":"demo","main":"/tmp/escape.js"}"#,
        )
        .expect("write package");

        let err = LockstepHarness::resolve_runtime_target("node", temp_dir.path())
            .expect_err("absolute package main must fail when no fallback exists");
        let message = format!("{err:#}");
        assert!(message.contains("package.json main `/tmp/escape.js` did not resolve"));
    }

    // ── path traversal regression ─────────────────────────────────────

    #[test]
    fn resolve_entry_candidate_rejects_path_traversal() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        // ".." segments
        assert!(
            LockstepHarness::resolve_entry_candidate(temp_dir.path(), "../../etc/passwd", "node")
                .is_none(),
            "must reject .. traversal"
        );
        // absolute path
        assert!(
            LockstepHarness::resolve_entry_candidate(temp_dir.path(), "/etc/passwd", "node")
                .is_none(),
            "must reject absolute path"
        );
        // backslash
        assert!(
            LockstepHarness::resolve_entry_candidate(
                temp_dir.path(),
                "..\\..\\etc\\passwd",
                "node"
            )
            .is_none(),
            "must reject backslash traversal"
        );
        // embedded ".." in deeper path
        assert!(
            LockstepHarness::resolve_entry_candidate(
                temp_dir.path(),
                "dist/../../../etc/passwd",
                "node"
            )
            .is_none(),
            "must reject embedded .. traversal"
        );
    }

    #[test]
    fn resolve_entry_candidate_rejects_empty_after_normalization() {
        let temp_dir = tempfile::tempdir().expect("tempdir");

        assert!(
            LockstepHarness::resolve_entry_candidate(temp_dir.path(), " ./ ", "node").is_none()
        );
        assert!(LockstepHarness::resolve_entry_candidate(temp_dir.path(), "", "node").is_none());
    }

    #[test]
    fn resolve_entry_candidate_rejects_null_byte_target() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(temp_dir.path().join("index.js"), "console.log('ok');")
            .expect("write fallback entry");

        assert!(
            LockstepHarness::resolve_entry_candidate(temp_dir.path(), "index\0.js", "node")
                .is_none(),
            "embedded NUL in package main must fail closed"
        );
    }

    #[test]
    fn resolve_runtime_target_rejects_null_byte_package_main_without_fallback() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            temp_dir.path().join("package.json"),
            r#"{"name":"demo","main":"index\u0000.js"}"#,
        )
        .expect("write package");

        let err = LockstepHarness::resolve_runtime_target("node", temp_dir.path())
            .expect_err("NUL-bearing package main must fail when no fallback exists");
        let message = format!("{err:#}");
        assert!(message.contains("package.json main"));
        assert!(message.contains("did not resolve"));
    }

    #[test]
    fn resolve_runtime_target_rejects_backslash_package_main_without_fallback() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            temp_dir.path().join("package.json"),
            r#"{"name":"demo","main":"dist\\index.js"}"#,
        )
        .expect("write package");

        let err = LockstepHarness::resolve_runtime_target("node", temp_dir.path())
            .expect_err("backslash package main must fail when no fallback exists");
        let message = format!("{err:#}");
        assert!(message.contains("package.json main"));
        assert!(message.contains("did not resolve"));
    }

    #[test]
    fn resolve_entry_candidate_rejects_directory_without_nested_entrypoint() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir(temp_dir.path().join("dist")).expect("create dist");

        assert!(
            LockstepHarness::resolve_entry_candidate(temp_dir.path(), "dist", "node").is_none(),
            "directory main without index candidate must not resolve"
        );
    }

    #[cfg(unix)]
    #[test]
    fn resolve_runtime_target_rejects_symlinked_package_manifest_outside_project() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let outside_dir = tempfile::tempdir().expect("outside");
        let outside_package = outside_dir.path().join("package.json");
        std::fs::write(&outside_package, r#"{"name":"outside","main":"index.js"}"#)
            .expect("write outside package");
        std::os::unix::fs::symlink(&outside_package, temp_dir.path().join("package.json"))
            .expect("symlink package");

        let err = LockstepHarness::resolve_runtime_target("node", temp_dir.path())
            .expect_err("symlinked package manifest outside project must fail");
        let message = format!("{err:#}");
        assert!(message.contains("package.json must reside within"));
    }

    #[cfg(unix)]
    #[test]
    fn resolve_entry_candidate_rejects_symlink_outside_project() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let outside_dir = tempfile::tempdir().expect("outside");
        let outside_entry = outside_dir.path().join("entry.js");
        std::fs::write(&outside_entry, "console.log('outside');").expect("write outside entry");
        let link_path = temp_dir.path().join("entry.js");
        std::os::unix::fs::symlink(&outside_entry, &link_path).expect("symlink");

        assert!(
            LockstepHarness::resolve_entry_candidate(temp_dir.path(), "entry.js", "node").is_none(),
            "must reject symlinked entrypoint outside project"
        );
    }

    #[cfg(unix)]
    #[test]
    fn resolve_runtime_target_rejects_symlinked_directory_entrypoint() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let outside_dir = tempfile::tempdir().expect("outside");
        let outside_entry = outside_dir.path().join("index.js");
        std::fs::write(&outside_entry, "console.log('outside');").expect("write outside entry");
        let link_path = temp_dir.path().join("index.js");
        std::os::unix::fs::symlink(&outside_entry, &link_path).expect("symlink");

        let err = LockstepHarness::resolve_runtime_target("node", temp_dir.path())
            .expect_err("symlinked entrypoint should be rejected");
        let message = format!("{err:#}");
        assert!(message.contains("no executable JS entrypoint found"));
    }

    // ── sanitize_strace_output ───────────────────────────────────────

    #[test]
    fn sanitize_strips_pid_prefix() {
        let raw = b"[pid 12345] open(\"/etc/passwd\", O_RDONLY) = 3\n";
        let result = LockstepHarness::sanitize_strace_output(raw);
        let output = String::from_utf8_lossy(&result);
        assert!(!output.contains("[pid 12345]"));
        assert!(output.contains("open("));
    }

    #[test]
    fn sanitize_strips_numeric_prefix() {
        let raw = b"12345 open(\"/tmp/test\", O_WRONLY) = 4\n";
        let result = LockstepHarness::sanitize_strace_output(raw);
        let output = String::from_utf8_lossy(&result);
        assert!(!output.starts_with("12345"));
        assert!(output.contains("open("));
    }

    #[test]
    fn sanitize_preserves_syscall_name() {
        let raw = b"read(3, \"data\", 4096) = 4\n";
        let result = LockstepHarness::sanitize_strace_output(raw);
        let output = String::from_utf8_lossy(&result);
        assert!(output.contains("read("));
    }

    #[test]
    fn sanitize_removes_return_value() {
        let raw = b"open(\"/etc/hosts\", O_RDONLY) = 3\n";
        let result = LockstepHarness::sanitize_strace_output(raw);
        let output = String::from_utf8_lossy(&result);
        // Raw return payload should be removed while outcome classification is retained.
        assert!(!output.contains("= 3"));
        assert!(output.contains("=> ok"));
    }

    #[test]
    fn sanitize_preserves_success_vs_error_outcomes() {
        let ok = b"open(\"/tmp/demo\", O_RDONLY) = 3\n";
        let err = b"open(\"/tmp/demo\", O_RDONLY) = -1 ENOENT (No such file or directory)\n";
        let ok_out = LockstepHarness::sanitize_strace_output(ok);
        let err_out = LockstepHarness::sanitize_strace_output(err);
        let ok_text = String::from_utf8_lossy(&ok_out);
        let err_text = String::from_utf8_lossy(&err_out);

        assert_ne!(ok_out, err_out);
        assert!(ok_text.contains("=> ok"));
        assert!(err_text.contains("=> err:ENOENT"));
    }

    #[test]
    fn sanitize_lowercase_errno_falls_back_to_generic_error() {
        let raw = b"open(\"/tmp/missing\", O_RDONLY) = -1 enoent (lowercase)\n";

        let result = LockstepHarness::sanitize_strace_output(raw);
        let output = String::from_utf8_lossy(&result);

        assert!(output.contains("=> err:ERR"));
        assert!(!output.contains("err:enoent"));
    }

    #[test]
    fn sanitize_missing_errno_after_error_uses_generic_error() {
        let raw = b"open(\"/tmp/missing\", O_RDONLY) = -1\n";

        let result = LockstepHarness::sanitize_strace_output(raw);
        let output = String::from_utf8_lossy(&result);

        assert!(output.contains("=> err:ERR"));
    }

    #[test]
    fn sanitize_mixed_case_errno_uses_generic_error() {
        let raw = b"open(\"/tmp/missing\", O_RDONLY) = -1 Eperm (mixed case)\n";

        let result = LockstepHarness::sanitize_strace_output(raw);
        let output = String::from_utf8_lossy(&result);

        assert!(output.contains("=> err:ERR"));
        assert!(!output.contains("err:Eperm"));
    }

    #[test]
    fn sanitize_negative_fd_argument_is_not_normalized() {
        let raw = b"read(-1, \"\", 0) = -1 EBADF (Bad file descriptor)\n";

        let result = LockstepHarness::sanitize_strace_output(raw);
        let output = String::from_utf8_lossy(&result);

        assert!(output.contains("read(-1"));
        assert!(!output.contains("read(FD"));
        assert!(output.contains("=> err:EBADF"));
    }

    #[test]
    fn sanitize_unknown_return_outcome_for_question_mark() {
        let raw = b"read(3, \"\", 0) = ?\n";

        let result = LockstepHarness::sanitize_strace_output(raw);
        let output = String::from_utf8_lossy(&result);

        assert!(output.contains("read(FD"));
        assert!(output.contains("=> unknown"));
    }

    #[test]
    fn sanitize_empty_input() {
        let result = LockstepHarness::sanitize_strace_output(b"");
        assert!(result.is_empty());
    }

    #[test]
    fn sanitize_handles_multiple_lines() {
        let raw = b"[pid 100] open(\"/a\") = 3\n[pid 200] read(3) = 10\nclose(3) = 0\n";
        let result = LockstepHarness::sanitize_strace_output(raw);
        let output = String::from_utf8_lossy(&result);
        let lines: Vec<&str> = output.lines().collect();
        assert_eq!(lines.len(), 3);
    }

    #[test]
    fn sanitize_deterministic_for_same_syscalls_different_pids() {
        let raw_a = b"[pid 100] open(\"/etc/hosts\", O_RDONLY) = 3\n\
                       [pid 100] read(3, \"data\", 4096) = 4\n";
        let raw_b = b"[pid 999] open(\"/etc/hosts\", O_RDONLY) = 5\n\
                       [pid 999] read(5, \"data\", 4096) = 4\n";
        let result_a = LockstepHarness::sanitize_strace_output(raw_a);
        let result_b = LockstepHarness::sanitize_strace_output(raw_b);
        // Both should produce the same output after sanitization since
        // PID prefixes are stripped and return values are removed
        assert_eq!(result_a, result_b);
    }

    #[test]
    fn sanitize_line_without_equals_is_skipped() {
        let raw = b"--- SIGCHLD {si_signo=SIGCHLD} ---\nopen(\"/tmp\") = 3\n";
        let result = LockstepHarness::sanitize_strace_output(raw);
        let output = String::from_utf8_lossy(&result);
        // Only syscall lines containing ` = ` return separators are retained.
        let lines: Vec<&str> = output.lines().filter(|l| !l.is_empty()).collect();
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("open(\"/tmp\")"));
    }

    #[test]
    fn sanitize_handles_utf8_paths() {
        let raw = "open(\"/tmp/日本語\", O_RDONLY) = 3\n".as_bytes();
        let result = LockstepHarness::sanitize_strace_output(raw);
        let output = String::from_utf8_lossy(&result);
        assert!(output.contains("日本語"));
    }

    // ── Oracle integration (unit-level) ──────────────────────────────

    #[test]
    fn harness_oracle_registration_marks_reference_runtimes() {
        let h = LockstepHarness::new(vec![
            "node".into(),
            "bun".into(),
            "franken-node".into(),
            "franken-engine".into(),
        ]);
        let mut oracle = RuntimeOracle::new("test-trace", 100);

        for rt in &h.runtimes {
            let entry = RuntimeEntry {
                runtime_id: rt.clone(),
                runtime_name: rt.clone(),
                version: "unknown".to_string(),
                is_reference: !LockstepHarness::is_franken_runtime(rt),
            };
            oracle.register_runtime(entry).expect("register");
        }

        // node and bun are reference, franken runtimes are not
        let report = oracle.generate_report(0);
        let json = serde_json::to_value(&report).expect("serialize");
        assert!(json.get("schema_version").is_some());
    }

    #[test]
    fn harness_oracle_cross_check_identical_outputs_agree() {
        let mut oracle = RuntimeOracle::new("test-trace", 100);
        oracle
            .register_runtime(RuntimeEntry {
                runtime_id: "node".into(),
                runtime_name: "node".into(),
                version: "20.0".into(),
                is_reference: true,
            })
            .expect("register node");
        oracle
            .register_runtime(RuntimeEntry {
                runtime_id: "franken-node".into(),
                runtime_name: "franken-node".into(),
                version: "0.1".into(),
                is_reference: false,
            })
            .expect("register fn");

        let mut outputs = BTreeMap::new();
        outputs.insert("node".to_string(), b"hello world".to_vec());
        outputs.insert("franken-node".to_string(), b"hello world".to_vec());

        let check = oracle
            .run_cross_check("check-1", BoundaryScope::IO, b"input", &outputs)
            .expect("cross check");

        assert!(check.outcome.is_some());
        match check.outcome.unwrap() {
            crate::runtime::nversion_oracle::CheckOutcome::Agree { .. } => {}
            crate::runtime::nversion_oracle::CheckOutcome::Diverge { .. } => {
                unreachable!("expected agreement for identical outputs");
            }
        }
    }

    #[test]
    fn harness_oracle_cross_check_different_outputs_diverge() {
        let mut oracle = RuntimeOracle::new("test-trace", 100);
        oracle
            .register_runtime(RuntimeEntry {
                runtime_id: "node".into(),
                runtime_name: "node".into(),
                version: "20.0".into(),
                is_reference: true,
            })
            .expect("register");
        oracle
            .register_runtime(RuntimeEntry {
                runtime_id: "franken-node".into(),
                runtime_name: "franken-node".into(),
                version: "0.1".into(),
                is_reference: false,
            })
            .expect("register");

        let mut outputs = BTreeMap::new();
        outputs.insert("node".to_string(), b"output-A".to_vec());
        outputs.insert("franken-node".to_string(), b"output-B".to_vec());

        let check = oracle
            .run_cross_check("check-2", BoundaryScope::IO, b"input", &outputs)
            .expect("cross check");

        assert!(check.outcome.is_some());
        match check.outcome.unwrap() {
            crate::runtime::nversion_oracle::CheckOutcome::Diverge { outputs: div } => {
                assert!(div.contains_key("node"));
                assert!(div.contains_key("franken-node"));
            }
            crate::runtime::nversion_oracle::CheckOutcome::Agree { .. } => {
                unreachable!("expected divergence for different outputs");
            }
        }
    }

    #[test]
    fn harness_oracle_divergence_classification() {
        let mut oracle = RuntimeOracle::new("test-trace", 100);
        oracle
            .register_runtime(RuntimeEntry {
                runtime_id: "node".into(),
                runtime_name: "node".into(),
                version: "20.0".into(),
                is_reference: true,
            })
            .expect("register");

        let mut outputs = BTreeMap::new();
        outputs.insert("node".to_string(), b"output".to_vec());

        let divergence = oracle.classify_divergence(
            "div-001",
            "check-1",
            BoundaryScope::IO,
            crate::runtime::nversion_oracle::RiskTier::High,
            &outputs,
        );

        assert_eq!(divergence.divergence_id, "div-001");
        assert_eq!(
            divergence.risk_tier,
            crate::runtime::nversion_oracle::RiskTier::High
        );
    }

    fn sample_divergence_report(verdict: OracleVerdict) -> DivergenceReport {
        let mut runtimes = BTreeMap::new();
        runtimes.insert(
            "node".to_string(),
            RuntimeEntry {
                runtime_id: "node".to_string(),
                runtime_name: "node".to_string(),
                version: "20.0.0".to_string(),
                is_reference: true,
            },
        );
        runtimes.insert(
            "franken-node".to_string(),
            RuntimeEntry {
                runtime_id: "franken-node".to_string(),
                runtime_name: "franken-node".to_string(),
                version: "0.1.0".to_string(),
                is_reference: false,
            },
        );

        let mut outputs = BTreeMap::new();
        outputs.insert("node".to_string(), b"node-output".to_vec());
        outputs.insert("franken-node".to_string(), b"franken-output".to_vec());

        DivergenceReport {
            schema_version: "nvo-v1.0".to_string(),
            trace_id: "trace-lockstep".to_string(),
            runtimes,
            checks: vec![CrossRuntimeCheck {
                check_id: "check-1".to_string(),
                boundary_scope: BoundaryScope::IO,
                input: b"{}".to_vec(),
                trace_id: "trace-lockstep".to_string(),
                outcome: Some(CheckOutcome::Diverge {
                    outputs: outputs.clone(),
                }),
            }],
            divergences: vec![SemanticDivergence {
                divergence_id: "div-1".to_string(),
                check_id: "check-1".to_string(),
                boundary_scope: BoundaryScope::IO,
                risk_tier: RiskTier::High,
                runtime_outputs: outputs,
                resolved: false,
                resolution_note: None,
                trace_id: "trace-lockstep".to_string(),
            }],
            voting_results: Vec::new(),
            receipts: Vec::new(),
            verdict,
            event_log: vec![OracleEvent {
                event_code: "FN-NV-012".to_string(),
                trace_id: "trace-lockstep".to_string(),
                message: "Oracle report generated".to_string(),
                details: BTreeMap::new(),
            }],
        }
    }

    #[test]
    fn ensure_report_passes_rejects_non_pass_verdicts() {
        let report = sample_divergence_report(OracleVerdict::BlockRelease {
            blocking_divergence_ids: vec!["div-1".to_string()],
        });

        let err = LockstepHarness::ensure_report_passes(&report)
            .expect_err("blocking divergence must fail verification");
        let message = format!("{err:#}");
        assert!(message.contains("verdict=block_release"));
        assert!(message.contains("div-1"));
    }

    #[test]
    fn ensure_report_passes_rejects_requires_receipt_verdict() {
        let report = sample_divergence_report(OracleVerdict::RequiresReceipt {
            pending_divergence_ids: vec!["div-1".to_string()],
        });

        let err = LockstepHarness::ensure_report_passes(&report)
            .expect_err("pending divergence receipt must fail verification");
        let message = format!("{err:#}");
        assert!(message.contains("verdict=requires_receipt"));
        assert!(message.contains("div-1"));
    }

    #[test]
    fn emit_divergence_fixtures_writes_schema_shaped_fixture() {
        let temp = tempfile::tempdir().expect("tempdir");
        let app_path = temp.path().join("demo-app").join("index.js");
        let report = sample_divergence_report(OracleVerdict::BlockRelease {
            blocking_divergence_ids: vec!["div-1".to_string()],
        });

        let written = LockstepHarness::emit_divergence_fixtures(&app_path, &report)
            .expect("fixture emission should succeed");
        assert_eq!(written.len(), 1);
        assert!(written[0].ends_with("fixtures/lockstep/div-1_min.json"));

        let fixture: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&written[0]).expect("read fixture"))
                .expect("valid fixture json");
        assert_eq!(fixture["id"], "fixture:lockstep:oracle:div-1");
        assert_eq!(fixture["band"], "high-value");
        assert_eq!(
            fixture["expected_output"]["oracle_verdict"],
            serde_json::Value::String("block_release".to_string())
        );
        assert_eq!(
            fixture["expected_output"]["runtime_outputs"]["node"]["encoding"],
            serde_json::Value::String("base64".to_string())
        );
    }

    #[test]
    fn emit_divergence_fixtures_concurrent_writers_leave_valid_fixture() {
        let temp = tempfile::tempdir().expect("tempdir");
        let app_path = temp.path().join("demo-app").join("index.js");
        let report = Arc::new(sample_divergence_report(OracleVerdict::BlockRelease {
            blocking_divergence_ids: vec!["div-1".to_string()],
        }));

        let mut handles = Vec::new();
        for _ in 0..16 {
            let app_path = app_path.clone();
            let report = Arc::clone(&report);
            handles.push(thread::spawn(move || {
                LockstepHarness::emit_divergence_fixtures(&app_path, &report)
            }));
        }

        for handle in handles {
            let written = handle.join().expect("fixture writer thread must not panic");
            assert_eq!(written.expect("fixture emission must succeed").len(), 1);
        }

        let fixture_path = temp
            .path()
            .join("demo-app")
            .join("fixtures")
            .join("lockstep")
            .join("div-1_min.json");
        let fixture: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&fixture_path).expect("read fixture"))
                .expect("concurrent fixture writes must leave valid json");
        assert_eq!(fixture["id"], "fixture:lockstep:oracle:div-1");
        assert_eq!(
            fixture["expected_output"]["oracle_verdict"],
            serde_json::Value::String("block_release".to_string())
        );
    }

    #[test]
    fn emit_divergence_fixtures_fails_closed_when_fixture_flock_is_held() {
        let temp = tempfile::tempdir().expect("tempdir");
        let app_path = temp.path().join("demo-app").join("index.js");
        let report = sample_divergence_report(OracleVerdict::BlockRelease {
            blocking_divergence_ids: vec!["div-1".to_string()],
        });
        let output_dir = LockstepHarness::fixture_output_dir(&app_path);
        std::fs::create_dir_all(&output_dir).expect("fixture output dir");
        let lock_path = output_dir.join(DIVERGENCE_FIXTURE_LOCK_FILE);
        let lock_file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(&lock_path)
            .expect("open competing lock file");
        lock_file.try_lock().expect("hold competing writer lock");

        let err = LockstepHarness::emit_divergence_fixtures(&app_path, &report)
            .expect_err("held flock must prevent fixture emission");
        let message = format!("{err:#}");
        assert!(message.contains("timed out locking lockstep divergence fixture lock"));
        assert!(
            !output_dir.join("div-1_min.json").exists(),
            "fixture must not be published while competing flock is held"
        );

        lock_file.unlock().expect("release competing writer lock");
    }

    #[test]
    fn harness_oracle_report_contains_schema_version() {
        let mut oracle = RuntimeOracle::new("test-trace", 100);
        let report = oracle.generate_report(0);
        assert_eq!(
            report.schema_version,
            crate::runtime::nversion_oracle::SCHEMA_VERSION
        );
    }
}
