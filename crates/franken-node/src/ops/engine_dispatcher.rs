use crate::config::Config;
use crate::ops::telemetry_bridge::TelemetryBridge;
use crate::storage::frankensqlite_adapter::FrankensqliteAdapter;
use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};

pub struct EngineDispatcher {
    engine_bin_path: String,
}

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
    pub fn dispatch_run(&self, app_path: &Path, config: &Config, policy_mode: &str) -> Result<()> {
        let bin_path = resolve_engine_binary_path(&self.engine_bin_path);
        if bin_path == "franken-engine" && !Path::new(&self.engine_bin_path).exists() {
            eprintln!(
                "Warning: Engine binary not found at `{}` and no sibling build was discovered; attempting `franken-engine` from PATH (override with FRANKEN_ENGINE_BIN).",
                self.engine_bin_path,
            );
        }

        let serialized_config = config.to_toml()?;
        let socket_path = format!("/tmp/franken_telemetry_{}.sock", uuid::Uuid::now_v7());

        // Spawn background listener to record telemetry events for deterministic replay
        let adapter = Arc::new(Mutex::new(FrankensqliteAdapter::default()));
        let telemetry = TelemetryBridge::new(&socket_path, Arc::clone(&adapter));
        telemetry
            .start_listener()
            .context("Failed to start telemetry bridge")?;

        struct SocketCleanup(String);
        impl Drop for SocketCleanup {
            fn drop(&mut self) {
                // Remove directly without exists() check to avoid TOCTOU race.
                let _ = std::fs::remove_file(&self.0);
            }
        }
        let _cleanup_guard = SocketCleanup(socket_path.clone());

        let mut cmd = Command::new(&bin_path);
        cmd.arg("run")
            .arg(app_path)
            .arg("--policy")
            .arg(policy_mode)
            // Pass the serialized policy config to the engine
            .env("FRANKEN_ENGINE_POLICY_PAYLOAD", &serialized_config)
            .env("FRANKEN_ENGINE_TELEMETRY_SOCKET", &socket_path);

        let status = cmd
            .status()
            .context("Failed to spawn franken_engine process")?;

        if !status.success() {
            if let Some(code) = status.code() {
                std::process::exit(code);
            } else {
                anyhow::bail!("franken_engine exited abnormally (terminated by signal)");
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

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
}
