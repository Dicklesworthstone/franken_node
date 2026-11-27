use crate::runtime::nversion_oracle::{
    BoundaryScope, CheckOutcome, DivergenceReport, OracleVerdict, RiskTier, RuntimeEntry,
    RuntimeOracle, SemanticDivergence,
};
use anyhow::{Context, Result};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{File, OpenOptions, TryLockError};
#[cfg(any(test, not(target_os = "linux")))]
use std::io::ErrorKind;
use std::io::{Read, Write};
#[cfg(all(unix, not(target_os = "linux")))]
use std::os::unix::process::CommandExt;
use std::path::{Component, Path, PathBuf};
#[cfg(not(target_os = "linux"))]
use std::process::Child;
#[cfg(any(test, not(target_os = "linux")))]
use std::process::Stdio;
use std::process::{Command, Output};
#[cfg(any(test, not(target_os = "linux")))]
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use std::sync::{Mutex, OnceLock};
use std::thread;
use std::time::Duration;
#[cfg(any(test, not(target_os = "linux")))]
use std::time::Instant;

use crate::push_bounded;

// Security: bounds for push_bounded to prevent memory exhaustion
const MAX_COMBINED_OUTPUT_BYTES: usize = 16_777_216; // 16MB limit per runtime execution
const MAX_RAW_STRACE_BYTES: usize = 16_777_216;
const MAX_LOCKSTEP_CORPUS_CASES: usize = 256;
const MAX_SANITIZED_STRACE_LINES: usize = 65_536; // 64K syscall lines max
const MAX_THREAD_HANDLES: usize = 64; // Maximum concurrent runtime threads
#[cfg(any(test, not(target_os = "linux")))]
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
/// One lockstep leg's captured execution. `comparison` carries the bytes the
/// cross-runtime oracle equates (length-framed guest stdout/stderr and normal
/// exit code, under a versioned domain);
/// `syscall_audit` carries the sanitized strace boundary trace, preserved as
/// audit evidence in divergence fixtures but never compared (bd-zi9hj —
/// traces are runtime-implementation artifacts and differ across engines by
/// construction).
struct RuntimeLegOutput {
    comparison: Vec<u8>,
    syscall_audit: Vec<u8>,
}

#[cfg(any(test, not(target_os = "linux")))]
struct PipeDrainResult {
    bytes: Vec<u8>,
    cap_reached: bool,
    error: Option<String>,
}

impl LockstepHarness {
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

    fn resolve_runtime_binary(runtime: &str) -> String {
        Self::resolve_runtime_binary_with(runtime, &|configured_hint| {
            // bd-zi9hj: no `franken-engine` CLI binary ships anywhere (the
            // engine repo has no such [[bin]]), so the old resolver produced
            // a leg that could never execute. The real franken execution
            // surface is THIS binary's `run` path (in-process native
            // engine): spawn ourselves. An operator-configured explicit
            // engine binary still wins when it resolves.
            let configured =
                crate::ops::engine_dispatcher::resolve_engine_binary_path(configured_hint);
            if Path::new(&configured).is_file() {
                return configured;
            }
            crate::resolve_product_cli_executable().map_or_else(
                |_| "franken-node".to_string(),
                |exe| exe.display().to_string(),
            )
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
        let root = project_dir.canonicalize().with_context(|| {
            format!(
                "failed resolving lockstep project root {}",
                project_dir.display()
            )
        })?;
        let package_json_path = root.join("package.json");
        let mut main: Option<String> = None;
        if package_json_path.exists() {
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
            // Node accepts a leading UTF-8 BOM in package manifests.
            let json = if runtime == "node" {
                package_json
                    .strip_prefix(&[0xef, 0xbb, 0xbf])
                    .unwrap_or(&package_json)
            } else {
                &package_json
            };
            let manifest: serde_json::Value = serde_json::from_slice(json).with_context(|| {
                format!(
                    "invalid package manifest JSON while resolving lockstep entrypoint: {}",
                    resolved.display()
                )
            })?;
            main = manifest
                .get("main")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned);
        }

        if runtime == "node" {
            // A declared main is a literal filename. Keep its whitespace and
            // refuse disallowed spellings even when an index is available.
            let main = main.as_deref().filter(|value| !value.is_empty());
            if let Some(value) = main
                && value.contains(['\\', '\0'])
            {
                anyhow::bail!(
                    "package.json main `{value}` did not resolve under {}: expected a project-relative path",
                    project_dir.display()
                );
            }
            let target = crate::ops::engine_dispatcher::EngineDispatcher::resolve_commonjs_package_entry(
                &root, main,
            )
            .map_err(anyhow::Error::msg)
            .with_context(|| match main {
                Some(value) => format!("package.json main `{value}` did not resolve under {} and no fallback entrypoint was found", root.display()),
                None => format!("no executable JS entrypoint found under {}", root.display()),
            })?;
            // Validate the *winning* path. Searching onward after a disallowed
            // winner would silently run a different program in the reference leg.
            let resolved = target
                .canonicalize()
                .context("resolve selected Node entrypoint")?;
            anyhow::ensure!(
                resolved.starts_with(&root) && resolved.is_file(),
                "no executable JS entrypoint found inside {}: selected file {} is outside the project or not regular",
                root.display(),
                resolved.display()
            );
            return Ok(resolved);
        }

        let unresolved_main = main
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty());
        if let Some(value) = unresolved_main
            && let Some(resolved) = Self::resolve_bun_entry_candidate(project_dir, value)
        {
            return Ok(resolved);
        }
        for candidate in Self::BUN_DIRECTORY_ENTRY_CANDIDATES {
            let path = project_dir.join(candidate);
            if path.is_file() && Self::path_within_project(project_dir, &path) {
                return Ok(path);
            }
        }

        if let Some(main) = unresolved_main {
            anyhow::bail!(
                "package.json main `{main}` did not resolve under {} and no fallback entrypoint was found ({})",
                project_dir.display(),
                Self::BUN_DIRECTORY_ENTRY_CANDIDATES.join(", ")
            );
        }

        anyhow::bail!(
            "no executable JS entrypoint found under {} (checked package.json main and {})",
            project_dir.display(),
            Self::BUN_DIRECTORY_ENTRY_CANDIDATES.join(", ")
        );
    }

    fn resolve_bun_entry_candidate(project_dir: &Path, raw_target: &str) -> Option<PathBuf> {
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
            for extension in ["ts", "tsx", "js", "mjs", "cjs"] {
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
            for entry in Self::BUN_DIRECTORY_ENTRY_CANDIDATES {
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
        let input_scope = Self::capture_input_scope(app_path)?;
        if let Some(corpus_entries) = Self::resolve_lockstep_corpus_entries(app_path)? {
            for entry in corpus_entries {
                input_scope.enforce_reference_execution()?;
                self.verify_lockstep_entry(&entry, emit_fixtures, &input_scope)
                    .with_context(|| {
                        format!("lockstep corpus fixture failed: {}", entry.display())
                    })?;
            }
            return Ok(());
        }

        self.verify_lockstep_entry(app_path, emit_fixtures, &input_scope)
    }

    fn capture_input_scope(
        app_path: &Path,
    ) -> Result<crate::runtime::safe_mode::AdmittedSafeModeProject> {
        let resolved = app_path
            .canonicalize()
            .with_context(|| format!("resolve lockstep safe-mode input {}", app_path.display()))?;
        let root = if resolved.is_dir() {
            resolved.as_path()
        } else {
            anyhow::ensure!(
                resolved.is_file(),
                "lockstep input must be a regular file or directory"
            );
            resolved
                .parent()
                .context("lockstep input has no parent directory")?
        };
        crate::runtime::safe_mode::AdmittedSafeModeProject::capture(root)
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

    fn verify_lockstep_entry(
        &self,
        app_path: &Path,
        emit_fixtures: bool,
        original_scope: &crate::runtime::safe_mode::AdmittedSafeModeProject,
    ) -> Result<()> {
        let input_scope = Self::capture_input_scope(app_path)?;
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
        input_scope.enforce_reference_execution()?;
        original_scope.enforce_reference_execution()?;
        for rt in self.runtimes.clone() {
            let app_path_buf = app_path.to_path_buf();
            let scopes = [original_scope.clone(), input_scope.clone()];
            let handle = thread::spawn(move || -> Result<(String, RuntimeLegOutput)> {
                let output = Self::execute_runtime_admitted(&rt, &app_path_buf, &scopes)?;
                Ok((rt, output))
            });
            push_bounded(&mut handles, handle, MAX_THREAD_HANDLES);
        }

        let mut outputs = BTreeMap::new();
        let mut syscall_audits: BTreeMap<String, Vec<u8>> = BTreeMap::new();
        let mut execution_error = None;
        for handle in handles {
            match handle.join() {
                Ok(Ok((rt, leg))) => {
                    syscall_audits.insert(rt.clone(), leg.syscall_audit);
                    outputs.insert(rt, leg.comparison);
                }
                Ok(Err(error)) => {
                    execution_error.get_or_insert_with(|| {
                        anyhow::anyhow!("Runtime execution error: {error:#}")
                    });
                }
                Err(_) => {
                    execution_error
                        .get_or_insert_with(|| anyhow::anyhow!("Runtime execution panicked"));
                }
            }
        }
        // Every runtime owns a process group. Join all supervisors even when
        // one refuses, so a failed comparison never abandons a reference leg.
        if let Some(error) = execution_error {
            return Err(error);
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
            for path in Self::emit_divergence_fixtures(app_path, &report, &syscall_audits)? {
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
        syscall_audits: &BTreeMap<String, Vec<u8>>,
    ) -> Result<Vec<PathBuf>> {
        let output_dir = Self::fixture_output_dir(app_path);
        std::fs::create_dir_all(&output_dir).with_context(|| {
            format!(
                "failed creating lockstep fixture output dir {}",
                output_dir.display()
            )
        })?;

        // Lock hierarchy (matches the persist_lock() doc): process-local
        // mutex FIRST so same-process writers serialize with an unbounded
        // wait, then the per-directory flock (bounded retries) which only
        // ever contends with OTHER processes. Taking the flock first let a
        // thread herd exhaust the 700ms retry budget against its own
        // siblings. This is the only site taking both locks, so no ABBA
        // partner exists.
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
            let fixture =
                Self::divergence_fixture_value(app_path, report, divergence, syscall_audits);
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
        syscall_audits: &BTreeMap<String, Vec<u8>>,
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

        // bd-zi9hj: sanitized per-runtime syscall boundary traces travel with
        // the fixture as audit evidence; they are not part of the compared
        // output (see execute_runtime).
        let syscall_boundaries_audit = syscall_audits
            .iter()
            .map(|(runtime, audit)| {
                (
                    runtime.clone(),
                    serde_json::json!({
                        "encoding": "base64",
                        "value": BASE64_STANDARD.encode(audit),
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
                "syscall_boundaries_audit": syscall_boundaries_audit,
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

    #[cfg(test)]
    fn execute_runtime(runtime: &str, app_path: &Path) -> Result<RuntimeLegOutput> {
        let input_scope = Self::capture_input_scope(app_path)?;
        Self::execute_runtime_admitted(runtime, app_path, &[input_scope])
    }

    fn execute_runtime_admitted(
        runtime: &str,
        app_path: &Path,
        scopes: &[crate::runtime::safe_mode::AdmittedSafeModeProject],
    ) -> Result<RuntimeLegOutput> {
        anyhow::ensure!(
            !scopes.is_empty(),
            "lockstep execution requires an admitted input scope"
        );
        for scope in scopes {
            scope.enforce_reference_execution()?;
        }
        let bin_path = Self::resolve_runtime_binary(runtime);
        let runtime_target = Self::resolve_runtime_target(runtime, app_path)?
            .canonicalize()
            .context("resolve admitted lockstep runtime target")?;
        let target_scope = Self::capture_input_scope(&runtime_target)?;
        let enforce_scopes = || -> Result<()> {
            for scope in scopes {
                scope.enforce_reference_execution()?;
            }
            target_scope.enforce_reference_execution()
        };

        let mut cmd = Command::new("strace");

        // The runtime label may be an arbitrary path (custom runtime
        // binaries); a raw label would inject '/' into the tempfile name and
        // fail with ENOENT, so keep only a bounded alphanumeric slug.
        let runtime_slug: String = runtime
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
            .take(48)
            .collect();
        let strace_output_file = tempfile::Builder::new()
            .prefix(&format!("strace_{runtime_slug}_"))
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
            cmd.arg("run").arg(&runtime_target);
            // bd-zi9hj: when the franken leg is this very binary (the
            // default — no external engine CLI ships), run output-pure:
            // only the guest program's console output and exit code, so the
            // cross-runtime comparison sees guest behavior rather than
            // appended runtime metadata (receipt summary / host-effect
            // ledger lines). `--runtime franken-engine` forces the native
            // in-process engine (never node/bun fallback, which would make
            // the "franken" leg a second reference leg), and `--engine-bin`
            // pointed at ourselves satisfies the dispatcher's availability
            // gate — the in-process engine is this binary. An operator-
            // configured external engine binary keeps the legacy
            // `run <app>` interface, which is all we can assume about it.
            let leg_is_self = crate::resolve_product_cli_executable()
                .map(|exe| exe.display().to_string() == bin_path)
                .unwrap_or(false);
            if leg_is_self {
                cmd.arg("--console-only")
                    .arg("--runtime")
                    .arg("franken-engine")
                    .arg("--engine-bin")
                    .arg(&bin_path);
            }
        } else {
            cmd.arg(&runtime_target);
        }
        // Both the caller's project and the resolved per-runtime entrypoint
        // remain authoritative. Temporary files and reference runtimes do not
        // exempt guest execution from persisted operator containment.
        let output = Self::execute_command_guarded(
            &mut cmd,
            crate::config::timeouts::LOCKSTEP_RUNTIME_TIMEOUT,
            crate::config::timeouts::LOCKSTEP_PIPE_DRAIN_JOIN_TIMEOUT,
            &enforce_scopes,
        )
        .with_context(|| {
            format!("lockstep runtime {runtime} did not complete a comparable execution")
        })?;
        // bd-zi9hj: the sanitized strace boundary trace is captured as audit
        // evidence (attached to divergence fixtures) but deliberately kept
        // OUT of the compared bytes. Syscall traces are runtime-
        // implementation artifacts — execve paths, loader opens, cache
        // probes — that can never be byte-equal across distinct engines, so
        // comparing them made every cross-runtime check diverge by
        // construction (empirically: node-vs-bun on `console.log("hello")`
        // produced block_release from the trace section alone).
        let strace_content = Self::read_strace_output(strace_output_file.path(), runtime)?;
        Self::validate_trace_completion(&strace_content, &output, runtime)?;
        let comparison = Self::comparison_payload(&output)?;
        let syscall_audit = Self::sanitize_strace_output(&strace_content);

        Ok(RuntimeLegOutput {
            comparison,
            syscall_audit,
        })
    }

    /// A tracer can exit normally with code 1 without ever executing the
    /// runtime (missing executable, denied ptrace, or failed tracer setup).
    /// Its stderr must not be mistaken for an intentional guest failure. The
    /// configured `strace -f -e trace=file,network -o ...` protocol records a
    /// successful initial exec and a normal terminal record for the same PID.
    /// Requiring both also rejects interrupted/partial traces. Syscall contents
    /// remain audit evidence, not part of cross-runtime behavior equivalence.
    fn validate_trace_completion(raw: &[u8], output: &Output, runtime: &str) -> Result<()> {
        let trace = std::str::from_utf8(raw).context("lockstep tracer emitted invalid UTF-8")?;
        let mut records = trace.lines().filter(|line| !line.trim().is_empty());
        let first = records.next().with_context(|| {
            format!("lockstep tracer did not observe runtime {runtime} execution; check strace and ptrace availability")
        })?;
        let (leader, mut entry) = Self::trace_record(first);
        loop {
            let Some((call, result)) = entry.rsplit_once(" = ") else {
                anyhow::bail!(
                    "lockstep tracer did not record a successful runtime {runtime} exec; execution is not comparable"
                );
            };
            anyhow::ensure!(
                call.starts_with("execve(") || call.starts_with("execveat("),
                "lockstep tracer did not record a successful runtime {runtime} exec; execution is not comparable"
            );
            if result.trim() == "0" {
                break;
            }
            // Executable search can attempt several paths. Permit only
            // failed exec attempts by this same leader before admission;
            // arbitrary application activity cannot stand in for its exec.
            anyhow::ensure!(
                result.trim_start().starts_with("-1 "),
                "lockstep tracer recorded an incomplete runtime {runtime} exec"
            );
            let next = records.next().with_context(|| {
                format!("lockstep tracer did not record a successful runtime {runtime} exec")
            })?;
            let (pid, event) = Self::trace_record(next);
            anyhow::ensure!(
                pid == leader,
                "lockstep tracer changed runtime {runtime} leader before successful exec"
            );
            entry = event;
        }
        let exit_code = output
            .status
            .code()
            .context("lockstep runtime has no normal exit status")?;
        let expected = format!("+++ exited with {exit_code} +++");
        let mut terminal = None;
        for record in records {
            let (pid, event) = Self::trace_record(record);
            if pid == leader && event.starts_with("+++ ") {
                anyhow::ensure!(
                    terminal.is_none(),
                    "lockstep tracer repeated runtime {runtime} termination"
                );
                terminal = Some(event);
            }
        }
        anyhow::ensure!(
            terminal == Some(expected.as_str()),
            "lockstep tracer did not observe runtime {runtime} normal exit {exit_code}; tracer failure or incomplete execution is not comparable"
        );
        Ok(())
    }

    fn trace_record(line: &str) -> (Option<&str>, &str) {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("[pid ")
            && let Some((pid, event)) = rest.split_once(']')
            && !pid.trim().is_empty()
            && pid.trim().bytes().all(|byte| byte.is_ascii_digit())
        {
            return (Some(pid.trim()), event.trim_start());
        }
        if let Some((pid, event)) = line.split_once(char::is_whitespace)
            && !pid.is_empty()
            && pid.bytes().all(|byte| byte.is_ascii_digit())
        {
            return (Some(pid), event.trim_start());
        }
        (None, line)
    }

    /// Binary framing keeps guest-controlled bytes separate from each other
    /// and from the exit status. Delimiters can occur in ordinary stdout or
    /// stderr; concatenating them admitted different behaviors as one result.
    /// The cap applies to guest bytes, so framing never evicts their prefix.
    fn comparison_payload(output: &Output) -> Result<Vec<u8>> {
        let exit_code = output
            .status
            .code()
            .context("lockstep runtime terminated without a normal exit status")?;
        let length = output
            .stdout
            .len()
            .checked_add(output.stderr.len())
            .context("lockstep output length overflow")?;
        anyhow::ensure!(
            length < MAX_COMBINED_OUTPUT_BYTES,
            "runtime output cap reached; comparison requires complete bounded output"
        );
        let mut comparison = b"franken-node/lockstep-observation/v2\0".to_vec();
        for bytes in [&output.stdout, &output.stderr] {
            comparison.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
            comparison.extend_from_slice(bytes);
        }
        comparison.extend_from_slice(&exit_code.to_be_bytes());
        Ok(comparison)
    }

    #[cfg(target_os = "linux")]
    fn execute_command_guarded(
        command: &mut Command,
        timeout: Duration,
        drain_timeout: Duration,
        control: &dyn Fn() -> Result<()>,
    ) -> Result<Output> {
        use crate::migration::smoke_supervisor::{self, StopReason, Stream};

        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let completion = smoke_supervisor::supervise_with_observer_guarded(
            command,
            timeout,
            drain_timeout,
            control,
            |stream, bytes| {
                let remaining = MAX_COMBINED_OUTPUT_BYTES
                    .saturating_sub(stdout.len().saturating_add(stderr.len()));
                if bytes.len() >= remaining {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "lockstep runtime output cap reached; partial streams are not comparable",
                    ));
                }
                match stream {
                    Stream::Stdout => stdout.extend_from_slice(bytes),
                    Stream::Stderr => stderr.extend_from_slice(bytes),
                }
                Ok(())
            },
        )?;
        // A pair of timeouts is not evidence of equivalent guest behavior.
        // The supervisor already killed/reaped its owned group on every path.
        match completion.reason {
            StopReason::RuntimeTimeout => anyhow::bail!(
                "lockstep runtime timed out after {}ms; incomplete executions are not comparable",
                timeout.as_millis()
            ),
            StopReason::PipeTimeout => anyhow::bail!(
                "lockstep output pipes did not finish within {}ms; incomplete streams are not comparable",
                drain_timeout.as_millis()
            ),
            StopReason::Exited => {}
        }
        control().context("lockstep runtime stopped by operator containment")?;
        anyhow::ensure!(
            completion.status.code().is_some(),
            "lockstep runtime terminated without a normal exit status"
        );
        Ok(Output {
            status: completion.status,
            stdout,
            stderr,
        })
    }

    #[cfg(not(target_os = "linux"))]
    fn execute_command_guarded(
        command: &mut Command,
        timeout: Duration,
        drain_timeout: Duration,
        control: &dyn Fn() -> Result<()>,
    ) -> Result<Output> {
        anyhow::ensure!(
            !timeout.is_zero() && !drain_timeout.is_zero(),
            "lockstep time budgets must be positive"
        );
        control()?;
        Self::isolate_child_process_group(command);
        let mut child = command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("failed launching lockstep runtime")?;
        let pipes = child.stdout.take().zip(child.stderr.take());
        let Some((mut stdout_pipe, mut stderr_pipe)) = pipes else {
            Self::terminate_runtime_tree(&mut child);
            anyhow::bail!("lockstep runtime output pipes unavailable");
        };
        let total = Arc::new(AtomicUsize::new(0));
        let cap = Arc::new(AtomicBool::new(false));
        let stdout_total = Arc::clone(&total);
        let stdout_cap = Arc::clone(&cap);
        let stdout_reader = thread::spawn(move || {
            Self::drain_pipe_bounded(&mut stdout_pipe, "stdout", stdout_total, stdout_cap)
        });
        let stderr_cap = Arc::clone(&cap);
        let stderr_reader = thread::spawn(move || {
            Self::drain_pipe_bounded(&mut stderr_pipe, "stderr", total, stderr_cap)
        });
        let started = Instant::now();
        let status = (|| -> Result<_> {
            loop {
                control().context("lockstep runtime stopped by operator containment")?;
                anyhow::ensure!(
                    !cap.load(Ordering::Acquire),
                    "lockstep runtime output cap reached"
                );
                if let Some(status) = child.try_wait().context("poll lockstep runtime")? {
                    return Ok(status);
                }
                anyhow::ensure!(
                    !Self::has_timed_out(started.elapsed(), timeout),
                    "lockstep runtime timed out; incomplete executions are not comparable"
                );
                thread::sleep(crate::config::timeouts::LOCKSTEP_RUNTIME_POLL_INTERVAL);
            }
        })();
        if status.is_err() {
            Self::terminate_runtime_tree(&mut child);
        }
        // Join both readers before propagating either failure. The non-Linux
        // fallback retains bounded joins; their errors never enter the oracle.
        let stdout = Self::join_pipe_drain(stdout_reader, "stdout", drain_timeout);
        let stderr = Self::join_pipe_drain(stderr_reader, "stderr", drain_timeout);
        let status = status?;
        let stdout = stdout?;
        let stderr = stderr?;
        control()?;
        anyhow::ensure!(
            !stdout.cap_reached && !stderr.cap_reached && !cap.load(Ordering::Acquire),
            "lockstep runtime output cap reached"
        );
        anyhow::ensure!(
            status.code().is_some(),
            "lockstep runtime terminated without a normal exit status"
        );
        Ok(Output {
            status,
            stdout: stdout.bytes,
            stderr: stderr.bytes,
        })
    }

    #[cfg(any(test, not(target_os = "linux")))]
    fn has_timed_out(elapsed: Duration, timeout: Duration) -> bool {
        elapsed >= timeout
    }

    #[cfg(all(unix, not(target_os = "linux")))]
    fn isolate_child_process_group(cmd: &mut Command) {
        cmd.process_group(0);
    }

    #[cfg(not(unix))]
    fn isolate_child_process_group(_cmd: &mut Command) {}

    #[cfg(not(target_os = "linux"))]
    fn terminate_runtime_tree(child: &mut Child) {
        #[cfg(unix)]
        Self::terminate_process_group(child.id());
        let _ = child.kill();
        let _ = child.wait();
    }

    #[cfg(all(unix, not(target_os = "linux")))]
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

    #[cfg(any(test, not(target_os = "linux")))]
    fn join_pipe_drain(
        handle: thread::JoinHandle<PipeDrainResult>,
        label: &str,
        timeout: Duration,
    ) -> Result<PipeDrainResult> {
        let start = Instant::now();
        while !handle.is_finished() {
            if Self::has_timed_out(start.elapsed(), timeout) {
                // Try a final join attempt with a grace period to prevent thread leaks
                let grace_timeout = timeout
                    .saturating_add(crate::config::timeouts::LOCKSTEP_PIPE_DRAIN_GRACE_EXTENSION);
                let grace_start = Instant::now();
                while !handle.is_finished() {
                    if Self::has_timed_out(grace_start.elapsed(), grace_timeout) {
                        // Keep the legacy non-Linux join bounded, but never
                        // present an infrastructure timeout as guest output.
                        tracing::warn!(
                            stream = label,
                            timeout_ms = timeout.as_millis(),
                            grace_timeout_ms = grace_timeout.as_millis(),
                            "pipe drain thread detached after bounded timeout"
                        );
                        drop(handle);
                        anyhow::bail!(
                            "lockstep {label} pipe drain timed out; incomplete streams are not comparable"
                        );
                    }
                    thread::sleep(crate::config::timeouts::LOCKSTEP_PIPE_DRAIN_JOIN_POLL);
                }
                break; // Thread finished during grace period
            }
            thread::sleep(crate::config::timeouts::LOCKSTEP_PIPE_DRAIN_JOIN_POLL);
        }
        let result = handle
            .join()
            .map_err(|_| anyhow::anyhow!("lockstep {label} pipe reader panicked"))?;
        if let Some(error) = &result.error {
            anyhow::bail!(
                "lockstep {label} pipe read failed: {error}; partial streams are not comparable"
            );
        }
        Ok(result)
    }

    #[cfg(any(test, not(target_os = "linux")))]
    fn drain_pipe_bounded<R: Read>(
        reader: &mut R,
        label: &str,
        captured_output_bytes: Arc<AtomicUsize>,
        output_cap_reached: Arc<AtomicBool>,
    ) -> PipeDrainResult {
        let mut captured = Vec::new();
        let mut chunk = [0_u8; PIPE_READ_CHUNK_BYTES];
        let mut cap_reached = false;
        let mut error = None;

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
                    error = Some(format!("{label}: {e}"));
                    break;
                }
            }
        }

        PipeDrainResult {
            bytes: captured,
            cap_reached,
            error,
        }
    }

    #[cfg(any(test, not(target_os = "linux")))]
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
        let context = || {
            format!(
                "strace output missing or unreadable for runtime {runtime}: {}",
                path.display()
            )
        };
        let file = File::open(path).with_context(context)?;
        let mut bytes = Vec::new();
        file.take((MAX_RAW_STRACE_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .with_context(context)?;
        anyhow::ensure!(
            bytes.len() <= MAX_RAW_STRACE_BYTES,
            "lockstep strace output cap reached for runtime {runtime}; truncated trace evidence is not comparable"
        );
        Ok(bytes)
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
            error: None,
        });
        let output = LockstepHarness::join_pipe_drain(handle, "stdout", Duration::from_secs(1))
            .expect("complete stream");
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
                error: None,
            }
        });

        let start = Instant::now();
        let error = LockstepHarness::join_pipe_drain(handle, "stderr", Duration::from_millis(30))
            .err()
            .expect("incomplete stream must fail");

        assert!(error.to_string().contains("stderr pipe drain timed out"));
        assert!(start.elapsed() < Duration::from_secs(1));
        drop(sender);
    }

    #[test]
    fn fallback_pipe_drain_timeout_is_an_error_even_if_the_thread_later_exits() {
        let (sender, receiver) = std::sync::mpsc::channel::<()>();
        let exited = Arc::new(AtomicBool::new(false));
        let exited_clone = Arc::clone(&exited);
        let handle = thread::spawn(move || {
            let _ = receiver.recv();
            exited_clone.store(true, Ordering::Release);
            PipeDrainResult {
                bytes: b"late-output".to_vec(),
                cap_reached: false,
                error: None,
            }
        });

        let error = LockstepHarness::join_pipe_drain(handle, "stdout", Duration::from_millis(30))
            .err()
            .expect("incomplete stream must fail");

        assert!(error.to_string().contains("stdout pipe drain timed out"));
        assert!(
            !exited.load(Ordering::Acquire),
            "thread should still be blocked when the timeout is refused"
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

    #[test]
    fn pipe_read_failure_and_reader_panic_never_become_comparable_output() {
        struct BrokenPipe(bool);
        impl Read for BrokenPipe {
            fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
                if !self.0 {
                    buffer[..7].copy_from_slice(b"partial");
                    self.0 = true;
                    Ok(7)
                } else {
                    Err(std::io::Error::other("injected read failure"))
                }
            }
        }
        let handle = thread::spawn(|| {
            LockstepHarness::drain_pipe_bounded(
                &mut BrokenPipe(false),
                "stdout",
                Arc::new(AtomicUsize::new(0)),
                Arc::new(AtomicBool::new(false)),
            )
        });
        let error = LockstepHarness::join_pipe_drain(handle, "stdout", Duration::from_secs(1))
            .err()
            .expect("partial read must fail");
        assert!(error.to_string().contains("injected read failure"));
        let handle = thread::spawn(|| -> PipeDrainResult { panic!("injected reader panic") });
        let error = LockstepHarness::join_pipe_drain(handle, "stderr", Duration::from_secs(1))
            .err()
            .expect("reader panic must fail");
        assert!(error.to_string().contains("stderr pipe reader panicked"));
    }

    #[cfg(unix)]
    #[test]
    fn comparison_framing_separates_streams_and_normal_exit_status() {
        use std::os::unix::process::ExitStatusExt;

        let first = Output {
            status: std::process::ExitStatus::from_raw(0),
            stdout: b"a\n--- STDERR ---\nb".to_vec(),
            stderr: b"c".to_vec(),
        };
        let second = Output {
            status: first.status,
            stdout: b"a".to_vec(),
            stderr: b"b\n--- STDERR ---\nc".to_vec(),
        };
        // These different observations collided under the old delimiter.
        let old = |output: &Output| {
            [
                output.stdout.as_slice(),
                b"\n--- STDERR ---\n",
                output.stderr.as_slice(),
            ]
            .concat()
        };
        assert_eq!(old(&first), old(&second));
        assert_ne!(
            LockstepHarness::comparison_payload(&first).unwrap(),
            LockstepHarness::comparison_payload(&second).unwrap()
        );
        let intentional_failure = Output {
            status: std::process::ExitStatus::from_raw(7 << 8),
            stdout: first.stdout.clone(),
            stderr: first.stderr.clone(),
        };
        let failed = LockstepHarness::comparison_payload(&intentional_failure).unwrap();
        assert_ne!(LockstepHarness::comparison_payload(&first).unwrap(), failed);
        assert_eq!(
            failed,
            LockstepHarness::comparison_payload(&intentional_failure).unwrap()
        );
        let signalled = Output {
            status: std::process::ExitStatus::from_raw(9),
            ..intentional_failure
        };
        assert!(LockstepHarness::comparison_payload(&signalled).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn comparison_framing_retains_every_guest_byte_near_the_output_bound() {
        use std::os::unix::process::ExitStatusExt;

        let mut first = Output {
            status: std::process::ExitStatus::from_raw(0),
            stdout: vec![b'a'; MAX_COMBINED_OUTPUT_BYTES - 2],
            stderr: vec![0xff],
        };
        let framed = LockstepHarness::comparison_payload(&first).unwrap();
        let domain = b"franken-node/lockstep-observation/v2\0";
        assert!(framed.starts_with(domain));
        assert_eq!(
            &framed[domain.len()..domain.len() + 8],
            &(first.stdout.len() as u64).to_be_bytes()
        );
        assert_eq!(
            &framed[domain.len() + 8..domain.len() + 8 + first.stdout.len()],
            first.stdout.as_slice()
        );
        first.stdout[0] = b'b';
        assert_ne!(framed, LockstepHarness::comparison_payload(&first).unwrap());
        first.stderr.push(0);
        assert!(LockstepHarness::comparison_payload(&first).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn trace_admission_accepts_completed_runtime_exec_and_intentional_nonzero_exit() {
        use std::os::unix::process::ExitStatusExt;

        let output = Output {
            status: std::process::ExitStatus::from_raw(7 << 8),
            stdout: Vec::new(),
            stderr: b"intentional guest error".to_vec(),
        };
        for prefix in ["", "42 ", "[pid    42] "] {
            let trace = format!(
                "{prefix}execve(\"/runtime\", [\"runtime\"], 0x1) = 0\n{prefix}+++ exited with 7 +++\n"
            );
            LockstepHarness::validate_trace_completion(trace.as_bytes(), &output, "runtime")
                .unwrap_or_else(|error| panic!("prefix {prefix:?}: {error:#}"));
        }
        let lookup_then_exec = b"42 execve(\"/missing/runtime\", [], 0x1) = -1 ENOENT (No such file or directory)\n42 execveat(3, \"runtime\", [], 0x1, 0) = 0\n43 +++ exited with 0 +++\n42 +++ exited with 7 +++\n";
        LockstepHarness::validate_trace_completion(lookup_then_exec, &output, "runtime").unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn trace_admission_rejects_tracer_failures_and_unproven_leader_completion() {
        use std::os::unix::process::ExitStatusExt;

        let output = Output {
            status: std::process::ExitStatus::from_raw(1 << 8),
            stdout: Vec::new(),
            stderr: b"strace: ptrace: Operation not permitted".to_vec(),
        };
        for (label, trace) in [
            ("denied ptrace", ""),
            (
                "failed exec",
                "42 execve(\"/missing\", [], 0x1) = -1 ENOENT (No such file or directory)\n42 +++ exited with 1 +++\n",
            ),
            ("missing exit", "42 execve(\"/runtime\", [], 0x1) = 0\n"),
            (
                "child exit cannot substitute for leader",
                "42 execve(\"/runtime\", [], 0x1) = 0\n43 +++ exited with 1 +++\n",
            ),
            (
                "exit status mismatch",
                "42 execve(\"/runtime\", [], 0x1) = 0\n42 +++ exited with 0 +++\n",
            ),
            (
                "signalled guest",
                "42 execve(\"/runtime\", [], 0x1) = 0\n42 +++ killed by SIGTERM +++\n",
            ),
            (
                "missing initial exec",
                "42 openat(3, \"file\", O_RDONLY) = 4\n42 +++ exited with 1 +++\n",
            ),
            (
                "leader changed before exec",
                "42 execve(\"/missing\", [], 0x1) = -1 ENOENT (No such file or directory)\n43 execve(\"/runtime\", [], 0x1) = 0\n42 +++ exited with 1 +++\n",
            ),
            (
                "application activity before exec",
                "42 execve(\"/missing\", [], 0x1) = -1 ENOENT (No such file or directory)\n42 openat(3, \"file\", O_RDONLY) = 4\n42 execve(\"/runtime\", [], 0x1) = 0\n42 +++ exited with 1 +++\n",
            ),
            (
                "repeated exit",
                "42 execve(\"/runtime\", [], 0x1) = 0\n42 +++ exited with 1 +++\n42 +++ exited with 1 +++\n",
            ),
        ] {
            assert!(
                LockstepHarness::validate_trace_completion(trace.as_bytes(), &output, "runtime")
                    .is_err(),
                "{label} must not become comparable guest behavior"
            );
        }
        assert!(LockstepHarness::validate_trace_completion(&[0xff], &output, "runtime").is_err());
    }

    #[cfg(target_os = "linux")]
    fn shell_command(source: &str) -> Command {
        let mut command = Command::new("/bin/sh");
        command.args(["-c", source]);
        command
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn guarded_supervisor_preserves_bytes_and_intentional_nonzero_guest_exit() {
        let output = LockstepHarness::execute_command_guarded(
            &mut shell_command("printf 'hello'; printf 'error' >&2; exit 7"),
            Duration::from_secs(3),
            Duration::from_millis(100),
            &|| Ok(()),
        )
        .unwrap();
        assert_eq!(output.stdout, b"hello");
        assert_eq!(output.stderr, b"error");
        assert_eq!(output.status.code(), Some(7));
        assert!(LockstepHarness::comparison_payload(&output).is_ok());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn guarded_supervisor_refuses_output_cap_and_signalled_runtime() {
        let error = LockstepHarness::execute_command_guarded(
            &mut shell_command(&format!(
                "head -c {} /dev/zero",
                MAX_COMBINED_OUTPUT_BYTES + 1
            )),
            Duration::from_secs(5),
            Duration::from_millis(100),
            &|| Ok(()),
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("runtime output cap reached"));
        let error = LockstepHarness::execute_command_guarded(
            &mut shell_command("kill -TERM \"$$\""),
            Duration::from_secs(3),
            Duration::from_millis(100),
            &|| Ok(()),
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("without a normal exit status"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn identical_runtime_and_inherited_pipe_timeouts_fail_closed() {
        for _ in 0..2 {
            let error = LockstepHarness::execute_command_guarded(
                &mut shell_command("exec /bin/sleep 60"),
                Duration::from_millis(80),
                Duration::from_millis(20),
                &|| Ok(()),
            )
            .unwrap_err();
            assert!(format!("{error:#}").contains("runtime timed out"));
            let error = LockstepHarness::execute_command_guarded(
                &mut shell_command("/bin/sleep 60 & exit 0"),
                Duration::from_secs(3),
                Duration::from_millis(20),
                &|| Ok(()),
            )
            .unwrap_err();
            assert!(format!("{error:#}").contains("output pipes did not finish"));
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn silent_runtime_rechecks_live_containment_before_returning_evidence() {
        let checks = std::cell::Cell::new(0usize);
        let error = LockstepHarness::execute_command_guarded(
            &mut shell_command("exec /bin/sleep 60"),
            Duration::from_secs(3),
            Duration::from_millis(20),
            &|| {
                checks.set(checks.get() + 1);
                anyhow::ensure!(checks.get() <= 4, "injected live containment");
                Ok(())
            },
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("injected live containment"));
        assert!(checks.get() > 4);
    }

    #[cfg(unix)]
    #[test]
    fn admitted_runtime_keeps_original_scope_when_entrypoint_is_retargeted() {
        use crate::runtime::safe_mode::{SafeModeController, SafeModeEntryReason};
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        let original = root.path().join("original");
        let replacement = root.path().join("replacement");
        for project in [&original, &replacement] {
            std::fs::create_dir(project).unwrap();
            std::fs::write(project.join("app.js"), "console.log('guest');").unwrap();
        }
        let alias = root.path().join("selected.js");
        symlink(original.join("app.js"), &alias).unwrap();
        let scope = LockstepHarness::capture_input_scope(&alias).unwrap();
        std::fs::rename(&alias, root.path().join("retained-selection")).unwrap();
        symlink(replacement.join("app.js"), &alias).unwrap();

        let state = original.join(".franken-node/safe-mode/state.json");
        std::fs::create_dir_all(state.parent().unwrap()).unwrap();
        let mut controller = SafeModeController::with_default_config();
        controller.enter_safe_mode(
            SafeModeEntryReason::ExplicitFlag,
            "2026-11-11T00:00:00Z",
            "operator:lockstep-regression",
            Vec::new(),
        );
        std::fs::write(&state, serde_json::to_vec(&controller).unwrap()).unwrap();
        let error = LockstepHarness::execute_runtime_admitted("/missing/runtime", &alias, &[scope])
            .err()
            .expect("the retained original scope must refuse");
        assert!(
            error
                .to_string()
                .contains("run blocked by active safe mode"),
            "{error:#}"
        );
        assert!(
            error.to_string().contains(state.to_str().unwrap()),
            "{error:#}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn execute_runtime_errors_when_output_cap_is_reached() {
        if !Command::new("strace")
            .args(["-o", "/dev/null", "/bin/true"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|status| status.success())
        {
            eprintln!(
                "skipping traced output cap test because strace execution is unavailable or ptrace is restricted; direct supervisor cap coverage remains enabled"
            );
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
            format!("{err:#}").contains("runtime output cap reached"),
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
    fn read_strace_output_rejects_oversized_trace_without_accepting_its_prefix() {
        let temp_file = tempfile::NamedTempFile::new().expect("tempfile");
        temp_file
            .as_file()
            .set_len((MAX_RAW_STRACE_BYTES + 1) as u64)
            .expect("create sparse oversized trace");
        let error = LockstepHarness::read_strace_output(temp_file.path(), "runtime")
            .expect_err("bounded trace reads must reject truncated evidence");
        assert!(error.to_string().contains("strace output cap reached"));
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
    fn node_directory_selection_uses_literal_main_and_commonjs_suffix_order() {
        let project = tempfile::tempdir().unwrap();
        let root = project.path();
        std::fs::write(root.join("index.js"), "throw new Error('wrong entry');").unwrap();
        std::fs::write(
            root.join("program.prod.js"),
            "throw new Error('trimmed name');",
        )
        .unwrap();
        std::fs::write(root.join(" program.prod .json"), "{}").unwrap();
        std::fs::write(root.join(" program.prod .js"), "console.log('literal');").unwrap();
        std::fs::write(
            root.join("package.json"),
            "\u{feff}{\"main\":\" program.prod \"}",
        )
        .unwrap();
        let selected = LockstepHarness::resolve_runtime_target("node", root).unwrap();
        assert_eq!(
            selected,
            root.canonicalize().unwrap().join(" program.prod .js")
        );

        std::fs::create_dir(root.join("cli")).unwrap();
        std::fs::write(root.join("package.json"), r#"{"main":"./cli/"}"#).unwrap();
        std::fs::write(root.join("cli/index.json"), "{}").unwrap();
        // A nested manifest would restart LOAD_AS_DIRECTORY; Node instead
        // tries LOAD_INDEX at this stage and picks the JSON file.
        std::fs::write(root.join("cli/package.json"), r#"{"main":"other.cjs"}"#).unwrap();
        std::fs::write(
            root.join("cli/other.cjs"),
            "throw new Error('wrong nested entry');",
        )
        .unwrap();
        assert_eq!(
            LockstepHarness::resolve_runtime_target("node", root).unwrap(),
            root.canonicalize().unwrap().join("cli/index.json")
        );
    }

    #[test]
    fn node_directory_does_not_infer_esm_or_cjs_suffixes() {
        let project = tempfile::tempdir().unwrap();
        let root = project.path();
        for name in ["entry.mjs", "entry.cjs", "index.mjs", "index.cjs"] {
            std::fs::write(
                root.join(name),
                "console.log('must be explicitly selected');",
            )
            .unwrap();
        }
        std::fs::write(root.join("package.json"), r#"{"main":"entry"}"#).unwrap();
        assert!(LockstepHarness::resolve_runtime_target("node", root).is_err());
        std::fs::write(root.join("index.json"), "{}").unwrap();
        assert_eq!(
            LockstepHarness::resolve_runtime_target("node", root).unwrap(),
            root.canonicalize().unwrap().join("index.json")
        );
        std::fs::write(root.join("package.json"), r#"{"main":"entry.mjs"}"#).unwrap();
        assert_eq!(
            LockstepHarness::resolve_runtime_target("node", root).unwrap(),
            root.canonicalize().unwrap().join("entry.mjs")
        );
    }

    #[cfg(unix)]
    #[test]
    fn node_directory_refuses_escaping_winner_even_when_fallback_exists() {
        let project = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let root = project.path();
        std::fs::write(outside.path().join("entry.js"), "console.log('outside');").unwrap();
        std::os::unix::fs::symlink(outside.path().join("entry.js"), root.join("selected.js"))
            .unwrap();
        std::fs::write(root.join("index.js"), "console.log('different program');").unwrap();
        std::fs::write(root.join("package.json"), r#"{"main":"selected"}"#).unwrap();
        let error = LockstepHarness::resolve_runtime_target("node", root).unwrap_err();
        assert!(format!("{error:#}").contains("outside the project"));
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
            LockstepHarness::resolve_bun_entry_candidate(temp_dir.path(), "../../etc/passwd")
                .is_none(),
            "must reject .. traversal"
        );
        // absolute path
        assert!(
            LockstepHarness::resolve_bun_entry_candidate(temp_dir.path(), "/etc/passwd").is_none(),
            "must reject absolute path"
        );
        // backslash
        assert!(
            LockstepHarness::resolve_bun_entry_candidate(temp_dir.path(), "..\\..\\etc\\passwd")
                .is_none(),
            "must reject backslash traversal"
        );
        // embedded ".." in deeper path
        assert!(
            LockstepHarness::resolve_bun_entry_candidate(
                temp_dir.path(),
                "dist/../../../etc/passwd"
            )
            .is_none(),
            "must reject embedded .. traversal"
        );
    }

    #[test]
    fn resolve_entry_candidate_rejects_empty_after_normalization() {
        let temp_dir = tempfile::tempdir().expect("tempdir");

        assert!(LockstepHarness::resolve_bun_entry_candidate(temp_dir.path(), " ./ ").is_none());
        assert!(LockstepHarness::resolve_bun_entry_candidate(temp_dir.path(), "").is_none());
    }

    #[test]
    fn resolve_entry_candidate_rejects_null_byte_target() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(temp_dir.path().join("index.js"), "console.log('ok');")
            .expect("write fallback entry");

        assert!(
            LockstepHarness::resolve_bun_entry_candidate(temp_dir.path(), "index\0.js").is_none(),
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
            LockstepHarness::resolve_bun_entry_candidate(temp_dir.path(), "dist").is_none(),
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
            LockstepHarness::resolve_bun_entry_candidate(temp_dir.path(), "entry.js").is_none(),
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

        let written =
            LockstepHarness::emit_divergence_fixtures(&app_path, &report, &BTreeMap::new())
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
                LockstepHarness::emit_divergence_fixtures(&app_path, &report, &BTreeMap::new())
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

        let err = LockstepHarness::emit_divergence_fixtures(&app_path, &report, &BTreeMap::new())
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
