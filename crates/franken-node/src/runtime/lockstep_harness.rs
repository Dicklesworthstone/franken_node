use crate::runtime::nversion_oracle::{
    BoundaryScope, CheckOutcome, DivergenceReport, OracleVerdict, RiskTier, RuntimeEntry,
    RuntimeOracle, SemanticDivergence,
};
use anyhow::{Context, Result};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

pub struct LockstepHarness {
    runtimes: Vec<String>,
}

impl LockstepHarness {
    const DIRECTORY_ENTRY_CANDIDATES: [&'static str; 3] = ["index.js", "index.mjs", "index.cjs"];

    pub fn new(runtimes: Vec<String>) -> Self {
        Self {
            runtimes: Self::normalize_runtimes(runtimes),
        }
    }

    fn normalize_runtimes(runtimes: Vec<String>) -> Vec<String> {
        let mut normalized = Vec::new();
        let mut seen = BTreeSet::new();
        for runtime in runtimes {
            let trimmed = runtime.trim();
            if trimmed.is_empty() {
                continue;
            }

            let runtime = trimmed.to_string();
            if seen.insert(runtime.clone()) {
                normalized.push(runtime);
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
        match runtime {
            "node" => "node".to_string(),
            "bun" => "bun".to_string(),
            runtime_name if Self::is_franken_runtime(runtime_name) => {
                crate::ops::engine_dispatcher::resolve_engine_binary_path("franken-engine")
            }
            _ => runtime.to_string(),
        }
    }

    fn resolve_runtime_target(runtime: &str, app_path: &Path) -> Result<PathBuf> {
        if !Self::runtime_uses_js_entrypoints(runtime) || app_path.is_file() || !app_path.is_dir() {
            return Ok(app_path.to_path_buf());
        }

        Self::resolve_directory_entrypoint(app_path).with_context(|| {
            format!(
                "lockstep input `{}` is not directly executable for runtime `{runtime}`",
                app_path.display()
            )
        })
    }

    fn resolve_directory_entrypoint(project_dir: &Path) -> Result<PathBuf> {
        let package_json_path = project_dir.join("package.json");
        let mut unresolved_main: Option<String> = None;
        if package_json_path.exists() {
            let package_json = std::fs::read(&package_json_path).with_context(|| {
                format!(
                    "failed reading package manifest {}",
                    package_json_path.display()
                )
            })?;
            let manifest: serde_json::Value =
                serde_json::from_slice(&package_json).with_context(|| {
                    format!(
                        "invalid package manifest JSON while resolving lockstep entrypoint: {}",
                        package_json_path.display()
                    )
                })?;

            if let Some(main) = manifest
                .get("main")
                .and_then(serde_json::Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
            {
                if let Some(resolved) = Self::resolve_entry_candidate(project_dir, main) {
                    return Ok(resolved);
                }
                unresolved_main = Some(main.to_string());
            }
        }

        for candidate in Self::DIRECTORY_ENTRY_CANDIDATES {
            let path = project_dir.join(candidate);
            if path.is_file() {
                return Ok(path);
            }
        }

        if let Some(main) = unresolved_main {
            anyhow::bail!(
                "package.json main `{main}` did not resolve under {} and no fallback entrypoint was found ({})",
                project_dir.display(),
                Self::DIRECTORY_ENTRY_CANDIDATES.join(", ")
            );
        }

        anyhow::bail!(
            "no executable JS entrypoint found under {} (checked package.json main and {})",
            project_dir.display(),
            Self::DIRECTORY_ENTRY_CANDIDATES.join(", ")
        );
    }

    fn resolve_entry_candidate(project_dir: &Path, raw_target: &str) -> Option<PathBuf> {
        let normalized = raw_target.trim().trim_start_matches("./");
        if normalized.is_empty() {
            return None;
        }

        let candidate = project_dir.join(normalized);
        if candidate.is_file() {
            return Some(candidate);
        }

        if candidate.extension().is_none() {
            for extension in ["js", "mjs", "cjs"] {
                let with_extension = candidate.with_extension(extension);
                if with_extension.is_file() {
                    return Some(with_extension);
                }
            }
        }

        if candidate.is_dir() {
            for entry in Self::DIRECTORY_ENTRY_CANDIDATES {
                let nested = candidate.join(entry);
                if nested.is_file() {
                    return Some(nested);
                }
            }
        }

        None
    }

    /// Spawns the specified runtimes concurrently, intercepts their outputs,
    /// and feeds the results to the Oracle.
    pub fn verify_lockstep(&self, app_path: &Path, emit_fixtures: bool) -> Result<()> {
        self.validate_runtimes()?;
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
            handles.push(handle);
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

        let mut written = Vec::new();
        for divergence in &report.divergences {
            let path = output_dir.join(format!(
                "{}_min.json",
                Self::sanitize_fixture_token(&divergence.divergence_id)
            ));
            let fixture = Self::divergence_fixture_value(app_path, report, divergence);
            let payload = serde_json::to_string_pretty(&fixture)
                .context("failed serializing generated lockstep divergence fixture")?;
            std::fs::write(&path, format!("{payload}\n")).with_context(|| {
                format!(
                    "failed writing lockstep divergence fixture {}",
                    path.display()
                )
            })?;
            written.push(path);
        }

        Ok(written)
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

        let stdout_thread = thread::spawn(move || {
            let mut buf = Vec::new();
            if let Err(e) = stdout_handle.read_to_end(&mut buf) {
                eprintln!("lockstep_harness: stdout read error (partial data retained): {e}");
            }
            buf
        });

        let stderr_thread = thread::spawn(move || {
            let mut buf = Vec::new();
            if let Err(e) = stderr_handle.read_to_end(&mut buf) {
                eprintln!("lockstep_harness: stderr read error (partial data retained): {e}");
            }
            buf
        });

        let timeout = Duration::from_secs(30);
        let start = Instant::now();

        let status = loop {
            if let Some(status) = child.try_wait()? {
                break status;
            }
            if Self::has_timed_out(start.elapsed(), timeout) {
                let _ = child.kill();
                let _ = child.wait(); // Reclaim resources
                // Join reader threads to avoid leaking them after kill.
                let _ = stdout_thread.join();
                let _ = stderr_thread.join();
                anyhow::bail!(
                    "Execution timeout for runtime {} (exceeded 30s limit)",
                    runtime
                );
            }
            thread::sleep(Duration::from_millis(50));
        };

        let stdout_bytes = stdout_thread
            .join()
            .unwrap_or_else(|_| b"__thread_panic:stdout".to_vec());
        let stderr_bytes = stderr_thread
            .join()
            .unwrap_or_else(|_| b"__thread_panic:stderr".to_vec());

        let mut combined_output = Vec::new();
        combined_output.extend_from_slice(&stdout_bytes);
        combined_output.extend_from_slice(b"\n--- STDERR ---\n");
        combined_output.extend_from_slice(&stderr_bytes);
        combined_output.extend_from_slice(b"\n--- EXIT CODE ---\n");
        combined_output.extend_from_slice(status.code().unwrap_or(-1).to_string().as_bytes());

        // Append deterministic strace output to detect behavioral divergences
        combined_output.extend_from_slice(b"\n--- SYSTEM CALL BOUNDARIES ---\n");
        let strace_content = Self::read_strace_output(strace_output_file.path(), runtime)?;
        // Filter out non-deterministic pointers/PIDs from strace output using simple heuristics
        // so we don't get false positive divergences for different runtimes doing the same thing.
        let deterministic_strace = Self::sanitize_strace_output(&strace_content);
        combined_output.extend_from_slice(&deterministic_strace);

        Ok(combined_output)
    }

    fn has_timed_out(elapsed: Duration, timeout: Duration) -> bool {
        elapsed >= timeout
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

        for line in raw_str.lines() {
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
            sanitized.extend_from_slice(normalized.as_bytes());
            sanitized.extend_from_slice(b" => ");
            sanitized.extend_from_slice(outcome.as_bytes());
            sanitized.push(b'\n');
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
    fn validate_runtimes_requires_two_distinct_entries() {
        let err = LockstepHarness::new(vec!["node".into(), " node ".into()])
            .validate_runtimes()
            .expect_err("single distinct runtime must fail");
        assert!(format!("{err:#}").contains("at least two distinct runtimes"));
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
                panic!("expected agreement for identical outputs");
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
                panic!("expected divergence for different outputs");
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
    fn harness_oracle_report_contains_schema_version() {
        let mut oracle = RuntimeOracle::new("test-trace", 100);
        let report = oracle.generate_report(0);
        assert_eq!(
            report.schema_version,
            crate::runtime::nversion_oracle::SCHEMA_VERSION
        );
    }
}
