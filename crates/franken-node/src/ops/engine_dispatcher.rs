use crate::config::Config;
use crate::ops::telemetry_bridge::{
    ShutdownReason, TelemetryBridge, TelemetryRuntimeHandle, TelemetryRuntimeReport,
};
use crate::storage::frankensqlite_adapter::FrankensqliteAdapter;
use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};
use std::sync::{Arc, Mutex};

pub struct EngineDispatcher {
    engine_bin_path: String,
    configured_path: Option<PathBuf>,
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
        let bin_path = resolve_engine_binary_path_with(
            &self.engine_bin_path,
            env_override.as_deref(),
            self.configured_path.as_deref(),
            config_path,
            &default_engine_binary_candidates(),
            &|path| path.exists(),
        );
        if bin_path == "franken-engine"
            && self.configured_path.is_none()
            && config.engine.binary_path.is_none()
            && !Path::new(&self.engine_bin_path).exists()
        {
            eprintln!(
                "Warning: Engine binary not found via configured override or sibling build; attempting `franken-engine` from PATH (override with --engine-bin, FRANKEN_ENGINE_BIN, FRANKEN_NODE_ENGINE_BINARY_PATH, or [engine].binary_path in config).",
            );
        }

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
        let exit_code = status.code();

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

        if !status.success() {
            if let Some(code) = exit_code {
                std::process::exit(code);
            } else {
                anyhow::bail!("franken_engine exited abnormally (terminated by signal)");
            }
        }

        Ok(())
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
