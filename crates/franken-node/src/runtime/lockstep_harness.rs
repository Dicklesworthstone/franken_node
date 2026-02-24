use std::collections::BTreeMap;
use std::process::{Command, Stdio};
use std::path::Path;
use std::thread;
use std::time::{Duration, Instant};
use std::io::Read;
use anyhow::{Result, Context};
use crate::runtime::nversion_oracle::{RuntimeOracle, BoundaryScope, RuntimeEntry};

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

    /// Spawns the specified runtimes concurrently, intercepts their outputs,
    /// and feeds the results to the Oracle.
    pub fn verify_lockstep(&self, app_path: &Path) -> Result<()> {
        let mut oracle = RuntimeOracle::new("lockstep-harness-trace", 100);

        for rt in &self.runtimes {
            oracle.register_runtime(RuntimeEntry {
                runtime_id: rt.clone(),
                runtime_name: rt.clone(),
                version: "unknown".to_string(),
                is_reference: rt != "franken-node" && rt != "franken_engine",
            }).map_err(|e| anyhow::anyhow!("Oracle registration error: {}", e))?;
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
                Ok(Ok((rt, out))) => { outputs.insert(rt, out); }
                Ok(Err(e)) => anyhow::bail!("Runtime execution error: {}", e),
                Err(_) => anyhow::bail!("Runtime execution panicked"),
            }
        }

        // Run the cross-runtime check
        let check_id = format!("check-{}", uuid::Uuid::new_v4());
        // Simple heuristic: passing the source code as input payload for auditing
        let input_payload = std::fs::read(app_path).unwrap_or_default();

        let check = oracle.run_cross_check(
            &check_id,
            BoundaryScope::IO, // Uses IO boundary due to strace filesystem/network tracking
            &input_payload,
            &outputs,
        ).map_err(|e| anyhow::anyhow!("Oracle cross check error: {}", e))?;

        if let Some(crate::runtime::nversion_oracle::CheckOutcome::Diverge { outputs: div_outputs }) = check.outcome {
            oracle.classify_divergence(
                &format!("div-{}", check_id),
                &check_id,
                BoundaryScope::IO,
                crate::runtime::nversion_oracle::RiskTier::High,
                &div_outputs,
            );
        }

        // Generate and print the report
        let report = oracle.generate_report();
        let canonical_json = serde_json::to_string_pretty(&report)?;
        println!("{}", canonical_json);

        Ok(())
    }

    fn execute_runtime(runtime: &str, app_path: &Path) -> Result<Vec<u8>> {
        let bin_path = match runtime {
            "node" => "node",
            "bun" => "bun",
            "franken-node" | "franken_engine" => {
                let path = "/dp/franken_engine/target/release/franken-engine";
                if Path::new(path).exists() {
                    path
                } else {
                    "franken-engine"
                }
            }
            _ => runtime,
        };

        let mut cmd = Command::new("strace");
        
        let strace_output_file = format!("/tmp/strace_{}_{}.log", runtime.replace('-', "_"), uuid::Uuid::new_v4());
        let _cleanup = TempFileCleanup { path: strace_output_file.clone() };
        
        // Wrap execution in strace to intercept and record filesystem and network mutations
        // -f: trace child processes
        // -e trace=file,network: only trace I/O and network boundaries
        // -o: output to temp file
        cmd.arg("-f")
           .arg("-e")
           .arg("trace=file,network")
           .arg("-o")
           .arg(&strace_output_file)
           .arg(bin_path);

        if runtime == "franken-node" || runtime == "franken_engine" {
            cmd.arg("run").arg(app_path);
        } else {
            cmd.arg(app_path);
        }

        let mut child = cmd
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .with_context(|| format!("Failed to spawn strace on runtime (is strace installed?): {}", runtime))?;

        // Drain stdout and stderr in background threads to prevent pipe buffer deadlock
        let mut stdout_handle = child.stdout.take().unwrap();
        let mut stderr_handle = child.stderr.take().unwrap();

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
                anyhow::bail!("Execution timeout for runtime {} (exceeded 30s limit)", runtime);
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
            let strace_content = std::fs::read(&strace_output_file).unwrap_or_default();
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
        let raw_str = String::from_utf8_lossy(raw);
        let mut sanitized = Vec::new();

        for line in raw_str.lines() {
            let mut current = line.trim();
            if current.starts_with("[pid ") {
                if let Some(idx) = current.find(']') {
                    current = current[idx + 1..].trim();
                }
            } else if let Some(idx) = current.find(' ') {
                if current[..idx].chars().all(|c| c.is_ascii_digit()) {
                    current = current[idx + 1..].trim();
                }
            }

            if let Some(end_idx) = current.rfind('=') {
                let deterministic_line = current[..end_idx].trim();
                sanitized.extend_from_slice(deterministic_line.as_bytes());
                sanitized.push(b'\n');
            }
        }
        sanitized
    }
}