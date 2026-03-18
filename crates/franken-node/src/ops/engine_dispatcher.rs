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

fn default_engine_binary_candidates() -> Vec<PathBuf> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest_dir
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .unwrap_or_else(|| manifest_dir.clone());

    let mut candidates = Vec::new();
    if let Some(parent_dir) = workspace_root.parent() {
        let sibling_engine_root = parent_dir.join("franken_engine");
        candidates.push(sibling_engine_root.join("target/release/franken-engine"));
        candidates.push(sibling_engine_root.join("target/debug/franken-engine"));
    }

    candidates.push(workspace_root.join("target/release/franken-engine"));
    candidates.push(workspace_root.join("target/debug/franken-engine"));
    candidates.push(PathBuf::from(
        "/data/projects/franken_engine/target/release/franken-engine",
    ));
    candidates.push(PathBuf::from(
        "/dp/franken_engine/target/release/franken-engine",
    ));
    candidates
}

fn has_path_separator(raw: &str) -> bool {
    raw.contains('/') || raw.contains('\\')
}

fn resolve_engine_binary_path_with(
    configured_hint: &str,
    env_override: Option<&str>,
    candidates: &[PathBuf],
    path_exists: &impl Fn(&Path) -> bool,
) -> String {
    if let Some(raw) = env_override {
        let override_bin = raw.trim();
        if !override_bin.is_empty() {
            return override_bin.to_string();
        }
    }

    let configured = configured_hint.trim();
    if !configured.is_empty() && path_exists(Path::new(configured)) {
        return configured.to_string();
    }

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

pub(crate) fn resolve_engine_binary_path(configured_hint: &str) -> String {
    let env_override = std::env::var("FRANKEN_ENGINE_BIN").ok();
    resolve_engine_binary_path_with(
        configured_hint,
        env_override.as_deref(),
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
        }
    }
}

impl EngineDispatcher {
    pub fn new(engine_bin_path: &str) -> Self {
        Self {
            engine_bin_path: engine_bin_path.to_string(),
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
        let bin_path = resolve_engine_binary_path(&self.engine_bin_path);
        if bin_path == "franken-engine" && !Path::new(&self.engine_bin_path).exists() {
            eprintln!(
                "Warning: Engine binary not found at `{}` and no sibling build was discovered; attempting `franken-engine` from PATH (override with FRANKEN_ENGINE_BIN).",
                self.engine_bin_path,
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
            &candidates,
            &|_| false,
        );
        assert_eq!(resolved, "custom-franken-engine");
    }

    #[test]
    fn resolver_uses_existing_configured_hint() {
        let hint = "/opt/tools/franken-engine";
        let candidates = vec![PathBuf::from("/missing/auto")];
        let resolved = resolve_engine_binary_path_with(hint, None, &candidates, &|path| {
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
        let resolved =
            resolve_engine_binary_path_with("/missing/configured", None, &candidates, &|path| {
                lookup.contains(&path.to_string_lossy().to_string())
            });
        assert_eq!(resolved, existing);
    }

    #[test]
    fn resolver_keeps_command_style_configured_hint() {
        let candidates = vec![PathBuf::from("/missing/auto")];
        let resolved =
            resolve_engine_binary_path_with("franken-engine", None, &candidates, &|_| false);
        assert_eq!(resolved, "franken-engine");
    }

    #[test]
    fn resolver_falls_back_to_default_command_for_missing_absolute_hint() {
        let candidates = vec![PathBuf::from("/missing/auto")];
        let resolved =
            resolve_engine_binary_path_with("/missing/configured", None, &candidates, &|_| false);
        assert_eq!(resolved, "franken-engine");
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
