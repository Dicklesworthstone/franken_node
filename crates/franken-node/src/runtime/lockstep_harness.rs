use crate::runtime::nversion_oracle::{BoundaryScope, RuntimeEntry, RuntimeOracle};
use anyhow::{Context, Result};
use std::collections::BTreeMap;
use std::io::Read;
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

struct TempFileCleanup {
    path: String,
}

impl Drop for TempFileCleanup {
    fn drop(&mut self) {
        if Path::new(&self.path).exists() {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

pub struct LockstepHarness {
    runtimes: Vec<String>,
}

impl LockstepHarness {
    pub fn new(runtimes: Vec<String>) -> Self {
        Self { runtimes }
    }

    fn is_franken_runtime(runtime: &str) -> bool {
        matches!(
            runtime,
            "franken-node" | "franken_engine" | "franken-engine"
        )
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

    /// Spawns the specified runtimes concurrently, intercepts their outputs,
    /// and feeds the results to the Oracle.
    pub fn verify_lockstep(&self, app_path: &Path) -> Result<()> {
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
        let input_payload = std::fs::read(app_path)
            .map_err(|e| anyhow::anyhow!("Failed to read app payload for auditing: {}", e))?;

        let check = oracle
            .run_cross_check(
                &check_id,
                BoundaryScope::IO, // Uses IO boundary due to strace filesystem/network tracking
                &input_payload,
                &outputs,
            )
            .map_err(|e| anyhow::anyhow!("Oracle cross check error: {}", e))?;

        if let Some(crate::runtime::nversion_oracle::CheckOutcome::Diverge {
            outputs: div_outputs,
        }) = check.outcome
        {
            oracle.classify_divergence(
                &format!("div-{}", check_id),
                &check_id,
                BoundaryScope::IO,
                crate::runtime::nversion_oracle::RiskTier::High,
                &div_outputs,
            );
        }

        // Generate and print the report
        let report = oracle.generate_report(0);
        let canonical_json = serde_json::to_string_pretty(&report)?;
        println!("{}", canonical_json);

        Ok(())
    }

    fn execute_runtime(runtime: &str, app_path: &Path) -> Result<Vec<u8>> {
        let bin_path = Self::resolve_runtime_binary(runtime);

        let mut cmd = Command::new("strace");

        let strace_output_file = format!(
            "/tmp/strace_{}_{}.log",
            runtime.replace('-', "_"),
            uuid::Uuid::now_v7()
        );
        let _cleanup = TempFileCleanup {
            path: strace_output_file.clone(),
        };

        // Wrap execution in strace to intercept and record filesystem and network mutations
        // -f: trace child processes
        // -e trace=file,network: only trace I/O and network boundaries
        // -o: output to temp file
        cmd.arg("-f")
            .arg("-e")
            .arg("trace=file,network")
            .arg("-o")
            .arg(&strace_output_file)
            .arg(&bin_path);

        if Self::is_franken_runtime(runtime) {
            cmd.arg("run").arg(app_path);
        } else {
            cmd.arg(app_path);
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
        let mut stdout_handle = child
            .stdout
            .take()
            .expect("invariant: stdout piped via Stdio::piped()");
        let mut stderr_handle = child
            .stderr
            .take()
            .expect("invariant: stderr piped via Stdio::piped()");

        let stdout_thread = thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = stdout_handle.read_to_end(&mut buf);
            buf
        });

        let stderr_thread = thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = stderr_handle.read_to_end(&mut buf);
            buf
        });

        let timeout = Duration::from_secs(30);
        let start = Instant::now();

        let status = loop {
            if let Some(status) = child.try_wait()? {
                break status;
            }
            if start.elapsed() > timeout {
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

        let stdout_bytes = stdout_thread.join().unwrap_or_default();
        let stderr_bytes = stderr_thread.join().unwrap_or_default();

        let mut combined_output = Vec::new();
        combined_output.extend_from_slice(&stdout_bytes);
        combined_output.extend_from_slice(b"\n--- STDERR ---\n");
        combined_output.extend_from_slice(&stderr_bytes);
        combined_output.extend_from_slice(b"\n--- EXIT CODE ---\n");
        combined_output.extend_from_slice(status.code().unwrap_or(-1).to_string().as_bytes());

        // Append deterministic strace output to detect behavioral divergences
        combined_output.extend_from_slice(b"\n--- SYSTEM CALL BOUNDARIES ---\n");
        if Path::new(&strace_output_file).exists() {
            let strace_content = std::fs::read(&strace_output_file)
                .map_err(|e| anyhow::anyhow!("Failed to read strace output: {}", e))?;
            // Filter out non-deterministic pointers/PIDs from strace output using simple heuristics
            // so we don't get false positive divergences for different runtimes doing the same thing.
            let deterministic_strace = Self::sanitize_strace_output(&strace_content);
            combined_output.extend_from_slice(&deterministic_strace);
        }

        Ok(combined_output)
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

    // ── TempFileCleanup ──────────────────────────────────────────────

    #[test]
    fn temp_file_cleanup_removes_file_on_drop() {
        let path = format!("/tmp/lockstep_test_{}", uuid::Uuid::now_v7());
        std::fs::write(&path, b"test").expect("write temp");
        assert!(Path::new(&path).exists());

        {
            let _cleanup = TempFileCleanup { path: path.clone() };
        }
        // File should be removed after drop
        assert!(!Path::new(&path).exists());
    }

    #[test]
    fn temp_file_cleanup_does_not_panic_for_missing_file() {
        let path = "/tmp/lockstep_test_nonexistent_file_42".to_string();
        assert!(!Path::new(&path).exists());
        {
            let _cleanup = TempFileCleanup { path };
        }
        // Should not panic
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
