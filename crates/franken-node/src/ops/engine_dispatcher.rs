use std::process::Command;
use std::path::Path;
use std::sync::{Arc, Mutex};
use anyhow::{Result, Context};
use crate::config::Config;
use crate::ops::telemetry_bridge::TelemetryBridge;
use crate::storage::frankensqlite_adapter::FrankensqliteAdapter;

pub struct EngineDispatcher {
    engine_bin_path: String,
}

impl Default for EngineDispatcher {
    fn default() -> Self {
        Self {
            // Ideally discoverable or configurable
            engine_bin_path: "/dp/franken_engine/target/release/franken-engine".to_string(),
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
        let bin_path = if Path::new(&self.engine_bin_path).exists() {
            self.engine_bin_path.as_str()
        } else {
            eprintln!("Warning: Engine binary not found at {}, attempting to invoke `franken-engine` from PATH.", self.engine_bin_path);
            "franken-engine"
        };

        let serialized_config = config.to_toml()?;
        let socket_path = format!("/tmp/franken_telemetry_{}.sock", uuid::Uuid::new_v4());

        // Spawn background listener to record telemetry events for deterministic replay
        let adapter = Arc::new(Mutex::new(FrankensqliteAdapter::default()));
        let telemetry = TelemetryBridge::new(&socket_path, Arc::clone(&adapter));
        telemetry.start_listener().context("Failed to start telemetry bridge")?;

        let mut cmd = Command::new(bin_path);
        cmd.arg("run")
           .arg(app_path)
           .arg("--policy")
           .arg(policy_mode)
           // Pass the serialized policy config to the engine
           .env("FRANKEN_ENGINE_POLICY_PAYLOAD", &serialized_config)
           .env("FRANKEN_ENGINE_TELEMETRY_SOCKET", &socket_path);

        let status = cmd.status().context("Failed to spawn franken_engine process")?;

        // Cleanup
        if Path::new(&socket_path).exists() {
            let _ = std::fs::remove_file(&socket_path);
        }

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