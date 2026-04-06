use crate::config::Config;
use crate::ops::telemetry_bridge::{
    ShutdownReason, TelemetryBridge, TelemetryRuntimeHandle, TelemetryRuntimeReport,
};
use crate::runtime::lockstep_harness::LockstepHarness;
use crate::storage::frankensqlite_adapter::FrankensqliteAdapter;
use anyhow::{Context, Result};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};
use std::sync::{Arc, Mutex};

pub struct EngineDispatcher {
    engine_bin_path: String,
    configured_path: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum DispatchPlan {
    FrankenEngine { binary: String },
    RuntimeFallback(RuntimeFallbackPlan),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RuntimeFallbackPlan {
    runtime: String,
    target: PathBuf,
    working_dir: PathBuf,
}

struct DispatchResolutionInputs<'a> {
    configured_hint: &'a str,
    env_override: Option<&'a str>,
    cli_path: Option<&'a Path>,
    config_path: Option<&'a Path>,
    candidates: &'a [PathBuf],
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
    let trimmed = command.trim();
    if trimmed.is_empty() {
        return false;
    }

    let path = Path::new(trimmed);
    if path.is_absolute() || has_path_separator(trimmed) {
        return path_exists(path);
    }

    let Some(path_env) = path_env else {
        return false;
    };

    for dir in std::env::split_paths(&path_env) {
        let candidate = dir.join(trimmed);
        if path_exists(&candidate) {
            return true;
        }
        #[cfg(windows)]
        if candidate.extension().is_none() {
            for ext in [".exe", ".cmd", ".bat"] {
                if path_exists(&candidate.with_extension(ext.trim_start_matches('.'))) {
                    return true;
                }
            }
        }
    }

    false
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
    let Ok(contents) = std::fs::read_to_string(&package_json) else {
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

fn fallback_runtime_candidates(app_path: &Path) -> [&'static str; 2] {
    if project_prefers_bun(app_path) {
        ["bun", "node"]
    } else {
        ["node", "bun"]
    }
}

fn resolve_fallback_runtime_plan_with(
    app_path: &Path,
    path_env: Option<OsString>,
    path_exists: &impl Fn(&Path) -> bool,
) -> Result<RuntimeFallbackPlan> {
    for runtime in fallback_runtime_candidates(app_path) {
        if !command_exists_with(runtime, path_env.clone(), path_exists) {
            continue;
        }

        return Ok(RuntimeFallbackPlan {
            runtime: runtime.to_string(),
            target: LockstepHarness::resolve_runtime_target(runtime, app_path)?,
            working_dir: project_root_for_path(app_path).to_path_buf(),
        });
    }

    anyhow::bail!(
        "franken-engine was not found and no fallback runtime is available; install node or bun, or configure --engine-bin/FRANKEN_ENGINE_BIN/FRANKEN_NODE_ENGINE_BINARY_PATH"
    )
}

fn resolve_dispatch_plan_with(
    app_path: &Path,
    inputs: DispatchResolutionInputs<'_>,
    path_env: Option<OsString>,
    path_exists: &impl Fn(&Path) -> bool,
) -> Result<DispatchPlan> {
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
        anyhow::bail!(
            "configured franken-engine binary `{binary}` was not found; fix --engine-bin, FRANKEN_ENGINE_BIN, FRANKEN_NODE_ENGINE_BINARY_PATH, or [engine].binary_path"
        );
    }

    resolve_fallback_runtime_plan_with(app_path, path_env, path_exists)
        .map(DispatchPlan::RuntimeFallback)
}

fn finish_child_status(status: ExitStatus, process_label: &str) -> Result<()> {
    if status.success() {
        return Ok(());
    }

    if let Some(code) = status.code() {
        std::process::exit(code);
    }

    anyhow::bail!("{process_label} exited abnormally (terminated by signal)");
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
        }
    }
}

impl EngineDispatcher {
    /// Create a dispatcher with an optional pre-configured engine binary path.
    ///
    /// When `path` is `Some`, it takes the highest precedence (above env var
    /// and config file) when resolving the engine binary.
    pub fn new(path: Option<PathBuf>) -> Self {
        Self {
            configured_path: path,
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
    pub fn dispatch_run(&self, app_path: &Path, config: &Config, policy_mode: &str) -> Result<()> {
        // Precedence: CLI --engine-bin > FRANKEN_ENGINE_BIN env > config [engine].binary_path > candidates.
        let env_override = std::env::var("FRANKEN_ENGINE_BIN").ok();
        let config_path = config.engine.binary_path.as_deref();
        let dispatch_plan = resolve_dispatch_plan_with(
            app_path,
            DispatchResolutionInputs {
                configured_hint: &self.engine_bin_path,
                env_override: env_override.as_deref(),
                cli_path: self.configured_path.as_deref(),
                config_path,
                candidates: &default_engine_binary_candidates(),
            },
            std::env::var_os("PATH"),
            &|path| path.exists(),
        )?;

        if let DispatchPlan::RuntimeFallback(plan) = dispatch_plan {
            eprintln!(
                "franken-engine unavailable; falling back to `{}` for {}. Reduced guarantees: no engine-native policy enforcement, telemetry bridge, or post-execution receipts.",
                plan.runtime,
                app_path.display(),
            );

            let status = Command::new(&plan.runtime)
                .arg(&plan.target)
                .current_dir(&plan.working_dir)
                .env("FRANKEN_NODE_REQUESTED_POLICY_MODE", policy_mode)
                .env("FRANKEN_NODE_FALLBACK_RUNTIME", &plan.runtime)
                .env("FRANKEN_NODE_FALLBACK_REASON", "franken_engine_unavailable")
                .status()
                .with_context(|| {
                    format!(
                        "failed launching fallback runtime `{}` for {}",
                        plan.runtime,
                        plan.target.display()
                    )
                })?;

            return finish_child_status(status, &plan.runtime);
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

        let (status, report) = Self::run_engine_process(&mut cmd, telemetry_handle)
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

        finish_child_status(status, "franken_engine")
    }

    fn run_engine_process(
        cmd: &mut Command,
        telemetry_handle: TelemetryRuntimeHandle,
    ) -> std::result::Result<(ExitStatus, TelemetryRuntimeReport), EngineProcessError> {
        match cmd.status() {
            Ok(status) => {
                let report = telemetry_handle
                    .stop_and_join(ShutdownReason::EngineExit {
                        exit_code: status.code(),
                    })
                    .map_err(|err| {
                        EngineProcessError::TelemetryDrain(format!(
                            "telemetry drain failed after engine exit: {err}"
                        ))
                    })?;
                Ok((status, report))
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
    use std::sync::{Arc, Mutex};

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
    fn command_lookup_searches_path_for_command_style_binaries() {
        let temp_dir = tempfile::TempDir::new().expect("tempdir");
        let fake_bin = temp_dir.path().join("bun");
        std::fs::write(&fake_bin, "#!/bin/sh\n").expect("write fake bin");
        let path_env = Some(temp_dir.path().as_os_str().to_os_string());

        assert!(command_exists_with("bun", path_env, &|path| path.exists()));
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
        std::fs::write(runtime_dir.join("node"), "#!/bin/sh\n").expect("write fake node");

        let plan = resolve_dispatch_plan_with(
            &app_dir,
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
                target: entry,
                working_dir: app_dir,
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
        std::fs::write(runtime_dir.join("node"), "#!/bin/sh\n").expect("write fake node");
        std::fs::write(runtime_dir.join("bun"), "#!/bin/sh\n").expect("write fake bun");

        let plan = resolve_dispatch_plan_with(
            &app_dir,
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
                target: entry,
                working_dir: app_dir,
            })
        );
    }

    #[test]
    fn dispatch_plan_rejects_missing_explicit_override() {
        let temp_dir = tempfile::TempDir::new().expect("tempdir");
        let app = temp_dir.path().join("app.js");
        std::fs::write(&app, "console.log('hello');").expect("write app");
        let cli_path = temp_dir.path().join("missing-franken-engine");

        let err = resolve_dispatch_plan_with(
            &app,
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
}
