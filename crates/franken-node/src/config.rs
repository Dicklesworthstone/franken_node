#![allow(clippy::doc_markdown)]

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};

/// Top-level configuration for franken_node.
///
/// Loaded from `franken_node.toml` in the project root or a user-specified path.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct Config {
    /// Runtime profile: strict, balanced, or legacy-risky.
    pub profile: Profile,

    /// Compatibility behavior settings.
    pub compatibility: CompatibilityConfig,

    /// Migration tooling settings.
    pub migration: MigrationConfig,

    /// Trust and security policy settings.
    pub trust: TrustConfig,

    /// Incident replay settings.
    pub replay: ReplayConfig,

    /// Extension registry settings.
    pub registry: RegistryConfig,

    /// Fleet control settings.
    pub fleet: FleetConfig,

    /// Observability and metrics settings.
    pub observability: ObservabilityConfig,

    /// Runtime lane + bulkhead settings for product scheduling.
    pub runtime: RuntimeConfig,
}

impl Default for Config {
    fn default() -> Self {
        Self::for_profile(Profile::Balanced)
    }
}

impl Config {
    /// Create a configuration for a specific profile with appropriate defaults.
    #[must_use]
    pub fn for_profile(profile: Profile) -> Self {
        match profile {
            Profile::Strict => Self {
                profile,
                compatibility: CompatibilityConfig {
                    mode: CompatibilityMode::Strict,
                    emit_divergence_receipts: true,
                },
                migration: MigrationConfig {
                    autofix: false,
                    require_lockstep_validation: true,
                },
                trust: TrustConfig {
                    risky_requires_fresh_revocation: true,
                    dangerous_requires_fresh_revocation: true,
                    quarantine_on_high_risk: true,
                },
                replay: ReplayConfig {
                    persist_high_severity: true,
                    bundle_version: "v1".to_string(),
                },
                registry: RegistryConfig {
                    require_signatures: true,
                    require_provenance: true,
                    minimum_assurance_level: 4,
                },
                fleet: FleetConfig {
                    convergence_timeout_seconds: 60,
                },
                observability: ObservabilityConfig {
                    namespace: "franken_node".to_string(),
                    emit_structured_audit_events: true,
                },
                runtime: RuntimeConfig::strict_defaults(),
            },
            Profile::Balanced => Self {
                profile,
                compatibility: CompatibilityConfig {
                    mode: CompatibilityMode::Balanced,
                    emit_divergence_receipts: true,
                },
                migration: MigrationConfig {
                    autofix: true,
                    require_lockstep_validation: true,
                },
                trust: TrustConfig {
                    risky_requires_fresh_revocation: true,
                    dangerous_requires_fresh_revocation: true,
                    quarantine_on_high_risk: true,
                },
                replay: ReplayConfig {
                    persist_high_severity: true,
                    bundle_version: "v1".to_string(),
                },
                registry: RegistryConfig {
                    require_signatures: true,
                    require_provenance: true,
                    minimum_assurance_level: 3,
                },
                fleet: FleetConfig {
                    convergence_timeout_seconds: 120,
                },
                observability: ObservabilityConfig {
                    namespace: "franken_node".to_string(),
                    emit_structured_audit_events: true,
                },
                runtime: RuntimeConfig::balanced_defaults(),
            },
            Profile::LegacyRisky => Self {
                profile,
                compatibility: CompatibilityConfig {
                    mode: CompatibilityMode::LegacyRisky,
                    emit_divergence_receipts: false,
                },
                migration: MigrationConfig {
                    autofix: true,
                    require_lockstep_validation: false,
                },
                trust: TrustConfig {
                    risky_requires_fresh_revocation: false,
                    dangerous_requires_fresh_revocation: true,
                    quarantine_on_high_risk: false,
                },
                replay: ReplayConfig {
                    persist_high_severity: true,
                    bundle_version: "v1".to_string(),
                },
                registry: RegistryConfig {
                    require_signatures: false,
                    require_provenance: false,
                    minimum_assurance_level: 1,
                },
                fleet: FleetConfig {
                    convergence_timeout_seconds: 300,
                },
                observability: ObservabilityConfig {
                    namespace: "franken_node".to_string(),
                    emit_structured_audit_events: false,
                },
                runtime: RuntimeConfig::legacy_defaults(),
            },
        }
    }

    /// Load configuration from a TOML file without CLI/env merge layers.
    ///
    /// This method is useful for fixtures and static snapshots.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let content =
            std::fs::read_to_string(path).map_err(|e| ConfigError::ReadFailed(path.into(), e))?;
        let parsed: Self =
            toml::from_str(&content).map_err(|e| ConfigError::ParseFailed(path.into(), e))?;
        parsed.validate()?;
        Ok(parsed)
    }

    /// Discover and load configuration from well-known locations.
    ///
    /// Search order:
    /// 1. Explicit path (if provided)
    /// 2. `./franken_node.toml` (project root)
    /// 3. `~/.config/franken-node/config.toml` (user)
    ///
    /// Returns the default balanced profile if no config file is found.
    pub fn discover(explicit_path: Option<&Path>) -> Result<Self, ConfigError> {
        if let Some(path) = explicit_path {
            return Self::load(path);
        }

        for candidate in default_candidates() {
            if candidate.exists() {
                return Self::load(&candidate);
            }
        }

        Ok(Self::default())
    }

    /// Resolve configuration with deterministic precedence:
    ///
    /// `CLI > env > profile-block > file-base > defaults`
    pub fn resolve(
        explicit_path: Option<&Path>,
        cli_overrides: CliOverrides,
    ) -> Result<ResolvedConfig, ConfigError> {
        Self::resolve_with_env(explicit_path, cli_overrides, &|key| std::env::var(key).ok())
    }

    fn resolve_with_env(
        explicit_path: Option<&Path>,
        cli_overrides: CliOverrides,
        env_lookup: &impl Fn(&str) -> Option<String>,
    ) -> Result<ResolvedConfig, ConfigError> {
        let source_path = if let Some(path) = explicit_path {
            Some(path.to_path_buf())
        } else {
            default_candidates().into_iter().find(|path| path.exists())
        };

        let document = if let Some(path) = source_path.as_deref() {
            ConfigDocument::load(path)?
        } else {
            ConfigDocument::default()
        };

        let mut decisions = vec![MergeDecision::new(
            MergeStage::Default,
            "profile",
            Profile::Balanced.to_string(),
        )];

        let mut selected_profile = Profile::Balanced;
        if let Some(profile) = document.profile {
            selected_profile = profile;
            decisions.push(MergeDecision::new(
                MergeStage::File,
                "profile",
                profile.to_string(),
            ));
        }

        if let Some(raw_profile) = env_lookup("FRANKEN_NODE_PROFILE") {
            let parsed =
                raw_profile
                    .parse::<Profile>()
                    .map_err(|_| ConfigError::EnvParseFailed {
                        key: "FRANKEN_NODE_PROFILE".to_string(),
                        value: raw_profile.clone(),
                        reason: "expected strict, balanced, or legacy-risky".to_string(),
                    })?;
            selected_profile = parsed;
            decisions.push(MergeDecision::new(
                MergeStage::Env,
                "profile",
                parsed.to_string(),
            ));
        }

        if let Some(profile) = cli_overrides.profile {
            selected_profile = profile;
            decisions.push(MergeDecision::new(
                MergeStage::Cli,
                "profile",
                profile.to_string(),
            ));
        }

        let mut config = Self::for_profile(selected_profile);

        if let Some(profile_block) = document.profile_block(selected_profile) {
            config.apply_overrides(profile_block, MergeStage::Profile, &mut decisions);
        }

        config.apply_overrides(&document.base, MergeStage::File, &mut decisions);
        config.apply_env_overrides(env_lookup, &mut decisions)?;
        config.validate()?;

        Ok(ResolvedConfig {
            config,
            selected_profile,
            source_path,
            decisions,
        })
    }

    /// Serialize this configuration to TOML.
    pub fn to_toml(&self) -> Result<String, ConfigError> {
        toml::to_string_pretty(self).map_err(ConfigError::SerializeFailed)
    }

    fn apply_overrides(
        &mut self,
        overrides: &ConfigOverrides,
        stage: MergeStage,
        decisions: &mut Vec<MergeDecision>,
    ) {
        if let Some(section) = &overrides.compatibility {
            if let Some(value) = section.mode {
                self.compatibility.mode = value;
                decisions.push(MergeDecision::new(
                    stage.clone(),
                    "compatibility.mode",
                    value.to_string(),
                ));
            }
            if let Some(value) = section.emit_divergence_receipts {
                self.compatibility.emit_divergence_receipts = value;
                decisions.push(MergeDecision::new(
                    stage.clone(),
                    "compatibility.emit_divergence_receipts",
                    value,
                ));
            }
        }

        if let Some(section) = &overrides.migration {
            if let Some(value) = section.autofix {
                self.migration.autofix = value;
                decisions.push(MergeDecision::new(
                    stage.clone(),
                    "migration.autofix",
                    value,
                ));
            }
            if let Some(value) = section.require_lockstep_validation {
                self.migration.require_lockstep_validation = value;
                decisions.push(MergeDecision::new(
                    stage.clone(),
                    "migration.require_lockstep_validation",
                    value,
                ));
            }
        }

        if let Some(section) = &overrides.trust {
            if let Some(value) = section.risky_requires_fresh_revocation {
                self.trust.risky_requires_fresh_revocation = value;
                decisions.push(MergeDecision::new(
                    stage.clone(),
                    "trust.risky_requires_fresh_revocation",
                    value,
                ));
            }
            if let Some(value) = section.dangerous_requires_fresh_revocation {
                self.trust.dangerous_requires_fresh_revocation = value;
                decisions.push(MergeDecision::new(
                    stage.clone(),
                    "trust.dangerous_requires_fresh_revocation",
                    value,
                ));
            }
            if let Some(value) = section.quarantine_on_high_risk {
                self.trust.quarantine_on_high_risk = value;
                decisions.push(MergeDecision::new(
                    stage.clone(),
                    "trust.quarantine_on_high_risk",
                    value,
                ));
            }
        }

        if let Some(section) = &overrides.replay {
            if let Some(value) = section.persist_high_severity {
                self.replay.persist_high_severity = value;
                decisions.push(MergeDecision::new(
                    stage.clone(),
                    "replay.persist_high_severity",
                    value,
                ));
            }
            if let Some(value) = &section.bundle_version {
                self.replay.bundle_version = value.clone();
                decisions.push(MergeDecision::new(
                    stage.clone(),
                    "replay.bundle_version",
                    value,
                ));
            }
        }

        if let Some(section) = &overrides.registry {
            if let Some(value) = section.require_signatures {
                self.registry.require_signatures = value;
                decisions.push(MergeDecision::new(
                    stage.clone(),
                    "registry.require_signatures",
                    value,
                ));
            }
            if let Some(value) = section.require_provenance {
                self.registry.require_provenance = value;
                decisions.push(MergeDecision::new(
                    stage.clone(),
                    "registry.require_provenance",
                    value,
                ));
            }
            if let Some(value) = section.minimum_assurance_level {
                self.registry.minimum_assurance_level = value;
                decisions.push(MergeDecision::new(
                    stage.clone(),
                    "registry.minimum_assurance_level",
                    value,
                ));
            }
        }

        if let Some(section) = &overrides.fleet {
            if let Some(value) = section.convergence_timeout_seconds {
                self.fleet.convergence_timeout_seconds = value;
                decisions.push(MergeDecision::new(
                    stage.clone(),
                    "fleet.convergence_timeout_seconds",
                    value,
                ));
            }
        }

        if let Some(section) = &overrides.observability {
            if let Some(value) = &section.namespace {
                self.observability.namespace = value.clone();
                decisions.push(MergeDecision::new(
                    stage.clone(),
                    "observability.namespace",
                    value,
                ));
            }
            if let Some(value) = section.emit_structured_audit_events {
                self.observability.emit_structured_audit_events = value;
                decisions.push(MergeDecision::new(
                    stage.clone(),
                    "observability.emit_structured_audit_events",
                    value,
                ));
            }
        }

        if let Some(section) = &overrides.runtime {
            if let Some(value) = section.remote_max_in_flight {
                self.runtime.remote_max_in_flight = value;
                decisions.push(MergeDecision::new(
                    stage.clone(),
                    "runtime.remote_max_in_flight",
                    value,
                ));
            }
            if let Some(value) = section.bulkhead_retry_after_ms {
                self.runtime.bulkhead_retry_after_ms = value;
                decisions.push(MergeDecision::new(
                    stage.clone(),
                    "runtime.bulkhead_retry_after_ms",
                    value,
                ));
            }
            if let Some(lanes) = &section.lanes {
                for (lane_name, lane_overrides) in lanes {
                    if let Some(target) = self.runtime.lanes.get_mut(lane_name) {
                        if let Some(value) = lane_overrides.max_concurrent {
                            target.max_concurrent = value;
                            decisions.push(MergeDecision::new(
                                stage.clone(),
                                format!("runtime.lanes.{lane_name}.max_concurrent").as_str(),
                                value,
                            ));
                        }
                        if let Some(value) = lane_overrides.priority_weight {
                            target.priority_weight = value;
                            decisions.push(MergeDecision::new(
                                stage.clone(),
                                format!("runtime.lanes.{lane_name}.priority_weight").as_str(),
                                value,
                            ));
                        }
                        if let Some(value) = lane_overrides.queue_limit {
                            target.queue_limit = value;
                            decisions.push(MergeDecision::new(
                                stage.clone(),
                                format!("runtime.lanes.{lane_name}.queue_limit").as_str(),
                                value,
                            ));
                        }
                        if let Some(value) = lane_overrides.enqueue_timeout_ms {
                            target.enqueue_timeout_ms = value;
                            decisions.push(MergeDecision::new(
                                stage.clone(),
                                format!("runtime.lanes.{lane_name}.enqueue_timeout_ms").as_str(),
                                value,
                            ));
                        }
                        if let Some(value) = lane_overrides.overflow_policy {
                            target.overflow_policy = value;
                            decisions.push(MergeDecision::new(
                                stage.clone(),
                                format!("runtime.lanes.{lane_name}.overflow_policy").as_str(),
                                value.to_string(),
                            ));
                        }
                    }
                }
            }
        }
    }

    fn apply_env_overrides(
        &mut self,
        env_lookup: &impl Fn(&str) -> Option<String>,
        decisions: &mut Vec<MergeDecision>,
    ) -> Result<(), ConfigError> {
        apply_env_field_bool(
            "FRANKEN_NODE_COMPATIBILITY_EMIT_DIVERGENCE_RECEIPTS",
            env_lookup,
            &mut self.compatibility.emit_divergence_receipts,
            "compatibility.emit_divergence_receipts",
            decisions,
        )?;

        if let Some(raw) = env_lookup("FRANKEN_NODE_COMPATIBILITY_MODE") {
            let parsed =
                raw.parse::<CompatibilityMode>()
                    .map_err(|_| ConfigError::EnvParseFailed {
                        key: "FRANKEN_NODE_COMPATIBILITY_MODE".to_string(),
                        value: raw.clone(),
                        reason: "expected strict, balanced, or legacy-risky".to_string(),
                    })?;
            self.compatibility.mode = parsed;
            decisions.push(MergeDecision::new(
                MergeStage::Env,
                "compatibility.mode",
                parsed.to_string(),
            ));
        }

        apply_env_field_bool(
            "FRANKEN_NODE_MIGRATION_AUTOFIX",
            env_lookup,
            &mut self.migration.autofix,
            "migration.autofix",
            decisions,
        )?;
        apply_env_field_bool(
            "FRANKEN_NODE_MIGRATION_REQUIRE_LOCKSTEP_VALIDATION",
            env_lookup,
            &mut self.migration.require_lockstep_validation,
            "migration.require_lockstep_validation",
            decisions,
        )?;

        apply_env_field_bool(
            "FRANKEN_NODE_TRUST_RISKY_REQUIRES_FRESH_REVOCATION",
            env_lookup,
            &mut self.trust.risky_requires_fresh_revocation,
            "trust.risky_requires_fresh_revocation",
            decisions,
        )?;
        apply_env_field_bool(
            "FRANKEN_NODE_TRUST_DANGEROUS_REQUIRES_FRESH_REVOCATION",
            env_lookup,
            &mut self.trust.dangerous_requires_fresh_revocation,
            "trust.dangerous_requires_fresh_revocation",
            decisions,
        )?;
        apply_env_field_bool(
            "FRANKEN_NODE_TRUST_QUARANTINE_ON_HIGH_RISK",
            env_lookup,
            &mut self.trust.quarantine_on_high_risk,
            "trust.quarantine_on_high_risk",
            decisions,
        )?;

        apply_env_field_bool(
            "FRANKEN_NODE_REPLAY_PERSIST_HIGH_SEVERITY",
            env_lookup,
            &mut self.replay.persist_high_severity,
            "replay.persist_high_severity",
            decisions,
        )?;
        if let Some(value) = env_lookup("FRANKEN_NODE_REPLAY_BUNDLE_VERSION") {
            self.replay.bundle_version = value.clone();
            decisions.push(MergeDecision::new(
                MergeStage::Env,
                "replay.bundle_version",
                value,
            ));
        }

        apply_env_field_bool(
            "FRANKEN_NODE_REGISTRY_REQUIRE_SIGNATURES",
            env_lookup,
            &mut self.registry.require_signatures,
            "registry.require_signatures",
            decisions,
        )?;
        apply_env_field_bool(
            "FRANKEN_NODE_REGISTRY_REQUIRE_PROVENANCE",
            env_lookup,
            &mut self.registry.require_provenance,
            "registry.require_provenance",
            decisions,
        )?;

        if let Some(raw) = env_lookup("FRANKEN_NODE_REGISTRY_MINIMUM_ASSURANCE_LEVEL") {
            let parsed = parse_env_u8("FRANKEN_NODE_REGISTRY_MINIMUM_ASSURANCE_LEVEL", &raw)?;
            self.registry.minimum_assurance_level = parsed;
            decisions.push(MergeDecision::new(
                MergeStage::Env,
                "registry.minimum_assurance_level",
                parsed,
            ));
        }

        if let Some(raw) = env_lookup("FRANKEN_NODE_FLEET_CONVERGENCE_TIMEOUT_SECONDS") {
            let parsed = parse_env_u64("FRANKEN_NODE_FLEET_CONVERGENCE_TIMEOUT_SECONDS", &raw)?;
            self.fleet.convergence_timeout_seconds = parsed;
            decisions.push(MergeDecision::new(
                MergeStage::Env,
                "fleet.convergence_timeout_seconds",
                parsed,
            ));
        }

        if let Some(value) = env_lookup("FRANKEN_NODE_OBSERVABILITY_NAMESPACE") {
            self.observability.namespace = value.clone();
            decisions.push(MergeDecision::new(
                MergeStage::Env,
                "observability.namespace",
                value,
            ));
        }
        apply_env_field_bool(
            "FRANKEN_NODE_OBSERVABILITY_EMIT_STRUCTURED_AUDIT_EVENTS",
            env_lookup,
            &mut self.observability.emit_structured_audit_events,
            "observability.emit_structured_audit_events",
            decisions,
        )?;

        if let Some(raw) = env_lookup("FRANKEN_NODE_RUNTIME_REMOTE_MAX_IN_FLIGHT") {
            let parsed = parse_env_usize("FRANKEN_NODE_RUNTIME_REMOTE_MAX_IN_FLIGHT", &raw)?;
            self.runtime.remote_max_in_flight = parsed;
            decisions.push(MergeDecision::new(
                MergeStage::Env,
                "runtime.remote_max_in_flight",
                parsed,
            ));
        }
        if let Some(raw) = env_lookup("FRANKEN_NODE_RUNTIME_BULKHEAD_RETRY_AFTER_MS") {
            let parsed = parse_env_u64("FRANKEN_NODE_RUNTIME_BULKHEAD_RETRY_AFTER_MS", &raw)?;
            self.runtime.bulkhead_retry_after_ms = parsed;
            decisions.push(MergeDecision::new(
                MergeStage::Env,
                "runtime.bulkhead_retry_after_ms",
                parsed,
            ));
        }

        Ok(())
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if !(1..=5).contains(&self.registry.minimum_assurance_level) {
            return Err(ConfigError::ValidationFailed(
                "registry.minimum_assurance_level must be within [1,5]".to_string(),
            ));
        }
        if self.fleet.convergence_timeout_seconds == 0 {
            return Err(ConfigError::ValidationFailed(
                "fleet.convergence_timeout_seconds must be > 0".to_string(),
            ));
        }
        if self.replay.bundle_version.trim().is_empty() {
            return Err(ConfigError::ValidationFailed(
                "replay.bundle_version must be non-empty".to_string(),
            ));
        }
        if self.observability.namespace.trim().is_empty() {
            return Err(ConfigError::ValidationFailed(
                "observability.namespace must be non-empty".to_string(),
            ));
        }
        if self.runtime.remote_max_in_flight == 0 {
            return Err(ConfigError::ValidationFailed(
                "runtime.remote_max_in_flight must be > 0".to_string(),
            ));
        }
        if self.runtime.bulkhead_retry_after_ms == 0 {
            return Err(ConfigError::ValidationFailed(
                "runtime.bulkhead_retry_after_ms must be > 0".to_string(),
            ));
        }
        for (lane_name, lane_cfg) in &self.runtime.lanes {
            if lane_cfg.max_concurrent == 0 {
                return Err(ConfigError::ValidationFailed(format!(
                    "runtime.lanes.{lane_name}.max_concurrent must be > 0"
                )));
            }
            if lane_cfg.priority_weight == 0 {
                return Err(ConfigError::ValidationFailed(format!(
                    "runtime.lanes.{lane_name}.priority_weight must be > 0"
                )));
            }
            if lane_cfg.queue_limit == 0 {
                return Err(ConfigError::ValidationFailed(format!(
                    "runtime.lanes.{lane_name}.queue_limit must be > 0"
                )));
            }
            if lane_cfg.enqueue_timeout_ms == 0 {
                return Err(ConfigError::ValidationFailed(format!(
                    "runtime.lanes.{lane_name}.enqueue_timeout_ms must be > 0"
                )));
            }
        }
        Ok(())
    }
}

fn default_candidates() -> Vec<PathBuf> {
    let mut candidates = vec![PathBuf::from("franken_node.toml")];
    if let Some(config_path) = dirs_next().map(|d| d.join("config.toml")) {
        candidates.push(config_path);
    }
    candidates
}

fn dirs_next() -> Option<PathBuf> {
    dirs_path().map(|d| d.join("franken-node"))
}

fn dirs_path() -> Option<PathBuf> {
    std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME").map(|home| {
                let mut p = PathBuf::from(home);
                p.push(".config");
                p
            })
        })
}

fn apply_env_field_bool(
    key: &str,
    env_lookup: &impl Fn(&str) -> Option<String>,
    slot: &mut bool,
    field: &str,
    decisions: &mut Vec<MergeDecision>,
) -> Result<(), ConfigError> {
    if let Some(raw) = env_lookup(key) {
        let parsed = parse_env_bool(key, &raw)?;
        *slot = parsed;
        decisions.push(MergeDecision::new(MergeStage::Env, field, parsed));
    }
    Ok(())
}

fn parse_env_bool(key: &str, raw: &str) -> Result<bool, ConfigError> {
    let normalized = raw.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        _ => Err(ConfigError::EnvParseFailed {
            key: key.to_string(),
            value: raw.to_string(),
            reason: "expected boolean (true/false/1/0/yes/no/on/off)".to_string(),
        }),
    }
}

fn parse_env_u8(key: &str, raw: &str) -> Result<u8, ConfigError> {
    raw.trim()
        .parse::<u8>()
        .map_err(|_| ConfigError::EnvParseFailed {
            key: key.to_string(),
            value: raw.to_string(),
            reason: "expected unsigned integer".to_string(),
        })
}

fn parse_env_u64(key: &str, raw: &str) -> Result<u64, ConfigError> {
    raw.trim()
        .parse::<u64>()
        .map_err(|_| ConfigError::EnvParseFailed {
            key: key.to_string(),
            value: raw.to_string(),
            reason: "expected unsigned integer".to_string(),
        })
}

fn parse_env_usize(key: &str, raw: &str) -> Result<usize, ConfigError> {
    raw.trim()
        .parse::<usize>()
        .map_err(|_| ConfigError::EnvParseFailed {
            key: key.to_string(),
            value: raw.to_string(),
            reason: "expected unsigned integer".to_string(),
        })
}

// -- Resolution Model --

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CliOverrides {
    pub profile: Option<Profile>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResolvedConfig {
    pub config: Config,
    pub selected_profile: Profile,
    pub source_path: Option<PathBuf>,
    pub decisions: Vec<MergeDecision>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MergeDecision {
    pub stage: MergeStage,
    pub field: String,
    pub value: String,
}

impl MergeDecision {
    fn new(stage: MergeStage, field: &str, value: impl ToString) -> Self {
        Self {
            stage,
            field: field.to_string(),
            value: value.to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum MergeStage {
    Default,
    Profile,
    File,
    Env,
    Cli,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct ConfigDocument {
    pub profile: Option<Profile>,
    pub profiles: BTreeMap<String, ConfigOverrides>,
    #[serde(flatten)]
    pub base: ConfigOverrides,
}

impl ConfigDocument {
    fn load(path: &Path) -> Result<Self, ConfigError> {
        let content =
            std::fs::read_to_string(path).map_err(|e| ConfigError::ReadFailed(path.into(), e))?;
        toml::from_str(&content).map_err(|e| ConfigError::ParseFailed(path.into(), e))
    }

    fn profile_block(&self, profile: Profile) -> Option<&ConfigOverrides> {
        let target = profile.to_string();
        self.profiles
            .iter()
            .find(|(raw, _)| normalize_profile_key(raw) == target)
            .map(|(_, overrides)| overrides)
    }
}

fn normalize_profile_key(raw: &str) -> String {
    raw.trim().to_ascii_lowercase().replace('_', "-")
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct ConfigOverrides {
    pub compatibility: Option<CompatibilityOverrides>,
    pub migration: Option<MigrationOverrides>,
    pub trust: Option<TrustOverrides>,
    pub replay: Option<ReplayOverrides>,
    pub registry: Option<RegistryOverrides>,
    pub fleet: Option<FleetOverrides>,
    pub observability: Option<ObservabilityOverrides>,
    pub runtime: Option<RuntimeOverrides>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct CompatibilityOverrides {
    pub mode: Option<CompatibilityMode>,
    pub emit_divergence_receipts: Option<bool>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct MigrationOverrides {
    pub autofix: Option<bool>,
    pub require_lockstep_validation: Option<bool>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct TrustOverrides {
    pub risky_requires_fresh_revocation: Option<bool>,
    pub dangerous_requires_fresh_revocation: Option<bool>,
    pub quarantine_on_high_risk: Option<bool>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct ReplayOverrides {
    pub persist_high_severity: Option<bool>,
    pub bundle_version: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RegistryOverrides {
    pub require_signatures: Option<bool>,
    pub require_provenance: Option<bool>,
    pub minimum_assurance_level: Option<u8>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct FleetOverrides {
    pub convergence_timeout_seconds: Option<u64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct ObservabilityOverrides {
    pub namespace: Option<String>,
    pub emit_structured_audit_events: Option<bool>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RuntimeOverrides {
    pub remote_max_in_flight: Option<usize>,
    pub bulkhead_retry_after_ms: Option<u64>,
    pub lanes: Option<BTreeMap<String, RuntimeLaneOverrides>>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RuntimeLaneOverrides {
    pub max_concurrent: Option<usize>,
    pub priority_weight: Option<u32>,
    pub queue_limit: Option<usize>,
    pub enqueue_timeout_ms: Option<u64>,
    pub overflow_policy: Option<LaneOverflowPolicy>,
}

// -- Profile --

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Profile {
    Strict,
    Balanced,
    LegacyRisky,
}

impl std::fmt::Display for Profile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Strict => write!(f, "strict"),
            Self::Balanced => write!(f, "balanced"),
            Self::LegacyRisky => write!(f, "legacy-risky"),
        }
    }
}

impl std::str::FromStr for Profile {
    type Err = ConfigError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match normalize_profile_key(s).as_str() {
            "strict" => Ok(Self::Strict),
            "balanced" => Ok(Self::Balanced),
            "legacy-risky" => Ok(Self::LegacyRisky),
            _ => Err(ConfigError::InvalidProfile(s.to_string())),
        }
    }
}

// -- Compatibility --

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CompatibilityConfig {
    /// API compatibility mode for migration and runtime dispatch.
    pub mode: CompatibilityMode,
    /// Divergence receipts are always recorded in production profiles.
    pub emit_divergence_receipts: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CompatibilityMode {
    Strict,
    Balanced,
    LegacyRisky,
}

impl std::fmt::Display for CompatibilityMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Strict => write!(f, "strict"),
            Self::Balanced => write!(f, "balanced"),
            Self::LegacyRisky => write!(f, "legacy-risky"),
        }
    }
}

impl std::str::FromStr for CompatibilityMode {
    type Err = ConfigError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match normalize_profile_key(s).as_str() {
            "strict" => Ok(Self::Strict),
            "balanced" => Ok(Self::Balanced),
            "legacy-risky" => Ok(Self::LegacyRisky),
            _ => Err(ConfigError::InvalidCompatibilityMode(s.to_string())),
        }
    }
}

// -- Migration --

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MigrationConfig {
    /// Enable automatic rewrite suggestions.
    pub autofix: bool,
    /// Require lockstep validation before rollout stage transition.
    pub require_lockstep_validation: bool,
}

// -- Trust --

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrustConfig {
    /// Risky actions require fresh revocation checks.
    pub risky_requires_fresh_revocation: bool,
    /// Dangerous actions always require fresh revocation checks.
    pub dangerous_requires_fresh_revocation: bool,
    /// Automatically quarantine high-risk extensions.
    pub quarantine_on_high_risk: bool,
}

// -- Replay --

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReplayConfig {
    /// Persist high-severity replay artifacts.
    pub persist_high_severity: bool,
    /// Deterministic bundle export format version.
    pub bundle_version: String,
}

// -- Registry --

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RegistryConfig {
    /// Enforce signature and provenance gates.
    pub require_signatures: bool,
    /// Require provenance metadata.
    pub require_provenance: bool,
    /// Minimum assurance level (1-5).
    pub minimum_assurance_level: u8,
}

// -- Fleet --

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FleetConfig {
    /// Fleet convergence timeout for quarantine/release operations (seconds).
    pub convergence_timeout_seconds: u64,
}

// -- Observability --

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ObservabilityConfig {
    /// Stable metrics namespace for automation.
    pub namespace: String,
    /// Emit structured audit events.
    pub emit_structured_audit_events: bool,
}

// -- Runtime --

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeConfig {
    /// Global max in-flight network-bound operations across all lanes.
    pub remote_max_in_flight: usize,
    /// Retry hint for callers when the global bulkhead is saturated.
    pub bulkhead_retry_after_ms: u64,
    /// Per-lane scheduler settings keyed by lane name.
    pub lanes: BTreeMap<String, RuntimeLaneConfig>,
}

impl RuntimeConfig {
    #[must_use]
    pub fn strict_defaults() -> Self {
        Self {
            remote_max_in_flight: 32,
            bulkhead_retry_after_ms: 100,
            lanes: default_runtime_lanes(
                RuntimeLaneConfig::new(8, 100, 16, 25, LaneOverflowPolicy::Reject),
                RuntimeLaneConfig::new(12, 80, 24, 50, LaneOverflowPolicy::EnqueueWithTimeout),
                RuntimeLaneConfig::new(16, 60, 32, 75, LaneOverflowPolicy::EnqueueWithTimeout),
                RuntimeLaneConfig::new(4, 20, 32, 100, LaneOverflowPolicy::ShedOldest),
            ),
        }
    }

    #[must_use]
    pub fn balanced_defaults() -> Self {
        Self {
            remote_max_in_flight: 50,
            bulkhead_retry_after_ms: 50,
            lanes: default_runtime_lanes(
                RuntimeLaneConfig::new(12, 100, 24, 25, LaneOverflowPolicy::Reject),
                RuntimeLaneConfig::new(16, 80, 32, 50, LaneOverflowPolicy::EnqueueWithTimeout),
                RuntimeLaneConfig::new(24, 60, 48, 75, LaneOverflowPolicy::EnqueueWithTimeout),
                RuntimeLaneConfig::new(8, 20, 64, 100, LaneOverflowPolicy::ShedOldest),
            ),
        }
    }

    #[must_use]
    pub fn legacy_defaults() -> Self {
        Self {
            remote_max_in_flight: 100,
            bulkhead_retry_after_ms: 20,
            lanes: default_runtime_lanes(
                RuntimeLaneConfig::new(20, 80, 48, 25, LaneOverflowPolicy::Reject),
                RuntimeLaneConfig::new(28, 60, 64, 50, LaneOverflowPolicy::EnqueueWithTimeout),
                RuntimeLaneConfig::new(40, 40, 96, 75, LaneOverflowPolicy::EnqueueWithTimeout),
                RuntimeLaneConfig::new(16, 20, 128, 100, LaneOverflowPolicy::ShedOldest),
            ),
        }
    }
}

fn default_runtime_lanes(
    cancel: RuntimeLaneConfig,
    timed: RuntimeLaneConfig,
    realtime: RuntimeLaneConfig,
    background: RuntimeLaneConfig,
) -> BTreeMap<String, RuntimeLaneConfig> {
    let mut lanes = BTreeMap::new();
    lanes.insert("cancel".to_string(), cancel);
    lanes.insert("timed".to_string(), timed);
    lanes.insert("realtime".to_string(), realtime);
    lanes.insert("background".to_string(), background);
    lanes
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeLaneConfig {
    pub max_concurrent: usize,
    pub priority_weight: u32,
    pub queue_limit: usize,
    pub enqueue_timeout_ms: u64,
    pub overflow_policy: LaneOverflowPolicy,
}

impl RuntimeLaneConfig {
    #[must_use]
    pub fn new(
        max_concurrent: usize,
        priority_weight: u32,
        queue_limit: usize,
        enqueue_timeout_ms: u64,
        overflow_policy: LaneOverflowPolicy,
    ) -> Self {
        Self {
            max_concurrent,
            priority_weight,
            queue_limit,
            enqueue_timeout_ms,
            overflow_policy,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum LaneOverflowPolicy {
    Reject,
    EnqueueWithTimeout,
    ShedOldest,
}

impl std::fmt::Display for LaneOverflowPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Reject => write!(f, "reject"),
            Self::EnqueueWithTimeout => write!(f, "enqueue-with-timeout"),
            Self::ShedOldest => write!(f, "shed-oldest"),
        }
    }
}

// -- Errors --

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("failed to read config file {0}: {1}")]
    ReadFailed(PathBuf, std::io::Error),

    #[error("failed to parse config file {0}: {1}")]
    ParseFailed(PathBuf, toml::de::Error),

    #[error("failed to serialize config: {0}")]
    SerializeFailed(toml::ser::Error),

    #[error("invalid profile: {0} (expected: strict, balanced, legacy-risky)")]
    InvalidProfile(String),

    #[error("invalid compatibility mode: {0} (expected: strict, balanced, legacy-risky)")]
    InvalidCompatibilityMode(String),

    #[error("environment override parse error for {key}=`{value}`: {reason}")]
    EnvParseFailed {
        key: String,
        value: String,
        reason: String,
    },

    #[error("config validation failed: {0}")]
    ValidationFailed(String),
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    fn map_lookup(map: HashMap<String, String>) -> impl Fn(&str) -> Option<String> {
        move |key| map.get(key).cloned()
    }

    #[test]
    fn default_config_is_balanced() {
        let config = Config::default();
        assert_eq!(config.profile, Profile::Balanced);
        assert!(config.compatibility.emit_divergence_receipts);
        assert!(config.migration.autofix);
        assert!(config.trust.risky_requires_fresh_revocation);
        assert_eq!(config.registry.minimum_assurance_level, 3);
        assert_eq!(config.runtime.remote_max_in_flight, 50);
        assert_eq!(config.runtime.bulkhead_retry_after_ms, 50);
        assert_eq!(config.runtime.lanes.len(), 4);
    }

    #[test]
    fn strict_profile_is_more_restrictive() {
        let config = Config::for_profile(Profile::Strict);
        assert_eq!(config.profile, Profile::Strict);
        assert!(!config.migration.autofix);
        assert_eq!(config.registry.minimum_assurance_level, 4);
        assert_eq!(config.fleet.convergence_timeout_seconds, 60);
        assert_eq!(config.runtime.remote_max_in_flight, 32);
    }

    #[test]
    fn legacy_risky_profile_is_permissive() {
        let config = Config::for_profile(Profile::LegacyRisky);
        assert_eq!(config.profile, Profile::LegacyRisky);
        assert!(!config.compatibility.emit_divergence_receipts);
        assert!(!config.migration.require_lockstep_validation);
        assert!(!config.trust.risky_requires_fresh_revocation);
        assert!(!config.registry.require_signatures);
        assert_eq!(config.registry.minimum_assurance_level, 1);
    }

    #[test]
    fn roundtrip_toml_serialization() {
        let config = Config::for_profile(Profile::Balanced);
        let toml_str = config.to_toml().expect("serialize");
        let parsed: Config = toml::from_str(&toml_str).expect("deserialize");
        assert_eq!(parsed.profile, Profile::Balanced);
        assert_eq!(
            parsed.registry.minimum_assurance_level,
            config.registry.minimum_assurance_level
        );
    }

    #[test]
    fn profile_from_str() {
        assert_eq!("strict".parse::<Profile>().unwrap(), Profile::Strict);
        assert_eq!("balanced".parse::<Profile>().unwrap(), Profile::Balanced);
        assert_eq!(
            "legacy-risky".parse::<Profile>().unwrap(),
            Profile::LegacyRisky
        );
        assert_eq!(
            "legacy_risky".parse::<Profile>().unwrap(),
            Profile::LegacyRisky
        );
        assert!("invalid".parse::<Profile>().is_err());
    }

    #[test]
    fn compatibility_mode_from_str() {
        assert_eq!(
            "legacy_risky".parse::<CompatibilityMode>().unwrap(),
            CompatibilityMode::LegacyRisky
        );
        assert!("unknown".parse::<CompatibilityMode>().is_err());
    }

    #[test]
    fn load_nonexistent_file_returns_error() {
        let result = Config::load(Path::new("/nonexistent/franken_node.toml"));
        assert!(result.is_err());
    }

    #[test]
    fn resolve_precedence_cli_over_env_over_file_profile() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("franken_node.toml");
        std::fs::write(&path, "profile = \"legacy-risky\"\n").unwrap();

        let env = HashMap::from([("FRANKEN_NODE_PROFILE".to_string(), "strict".to_string())]);

        let resolved = Config::resolve_with_env(
            Some(&path),
            CliOverrides {
                profile: Some(Profile::Balanced),
            },
            &map_lookup(env),
        )
        .unwrap();

        assert_eq!(resolved.selected_profile, Profile::Balanced);
        assert_eq!(resolved.config.profile, Profile::Balanced);
    }

    #[test]
    fn resolve_applies_profile_block_and_env_overrides() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("franken_node.toml");
        std::fs::write(
            &path,
            r#"
profile = "balanced"

[profiles.strict.migration]
autofix = false

[profiles.strict.registry]
minimum_assurance_level = 5

[migration]
require_lockstep_validation = true
"#,
        )
        .unwrap();

        let env = HashMap::from([
            ("FRANKEN_NODE_PROFILE".to_string(), "strict".to_string()),
            (
                "FRANKEN_NODE_MIGRATION_AUTOFIX".to_string(),
                "true".to_string(),
            ),
        ]);

        let resolved =
            Config::resolve_with_env(Some(&path), CliOverrides::default(), &map_lookup(env))
                .unwrap();

        assert_eq!(resolved.config.profile, Profile::Strict);
        assert!(resolved.config.migration.autofix);
        assert!(resolved.config.migration.require_lockstep_validation);
        assert_eq!(resolved.config.registry.minimum_assurance_level, 5);
    }

    #[test]
    fn resolve_rejects_invalid_env_bool() {
        let env = HashMap::from([(
            "FRANKEN_NODE_MIGRATION_AUTOFIX".to_string(),
            "not-a-bool".to_string(),
        )]);

        let err =
            Config::resolve_with_env(None, CliOverrides::default(), &map_lookup(env)).unwrap_err();
        let message = err.to_string();
        assert!(message.contains("FRANKEN_NODE_MIGRATION_AUTOFIX"));
    }

    #[test]
    fn resolve_records_merge_decisions() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("franken_node.toml");
        std::fs::write(
            &path,
            r#"
profile = "strict"
[trust]
quarantine_on_high_risk = false
"#,
        )
        .unwrap();

        let resolved = Config::resolve_with_env(
            Some(&path),
            CliOverrides::default(),
            &map_lookup(HashMap::new()),
        )
        .unwrap();

        assert!(
            resolved
                .decisions
                .iter()
                .any(|d| d.field == "profile" && d.stage == MergeStage::File)
        );
        assert!(resolved.decisions.iter().any(|d| {
            d.field == "trust.quarantine_on_high_risk" && d.stage == MergeStage::File
        }));
    }

    #[test]
    fn resolve_applies_runtime_lane_overrides() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("franken_node.toml");
        std::fs::write(
            &path,
            r#"
[runtime]
remote_max_in_flight = 77
bulkhead_retry_after_ms = 33

[runtime.lanes.cancel]
max_concurrent = 9
priority_weight = 111
queue_limit = 22
enqueue_timeout_ms = 44
overflow_policy = "reject"
"#,
        )
        .unwrap();

        let resolved = Config::resolve_with_env(
            Some(&path),
            CliOverrides::default(),
            &map_lookup(HashMap::new()),
        )
        .unwrap();

        assert_eq!(resolved.config.runtime.remote_max_in_flight, 77);
        assert_eq!(resolved.config.runtime.bulkhead_retry_after_ms, 33);
        let cancel = resolved.config.runtime.lanes.get("cancel").unwrap();
        assert_eq!(cancel.max_concurrent, 9);
        assert_eq!(cancel.priority_weight, 111);
        assert_eq!(cancel.queue_limit, 22);
        assert_eq!(cancel.enqueue_timeout_ms, 44);
        assert_eq!(cancel.overflow_policy, LaneOverflowPolicy::Reject);
    }

    #[test]
    fn resolve_applies_runtime_env_overrides() {
        let env = HashMap::from([
            (
                "FRANKEN_NODE_RUNTIME_REMOTE_MAX_IN_FLIGHT".to_string(),
                "66".to_string(),
            ),
            (
                "FRANKEN_NODE_RUNTIME_BULKHEAD_RETRY_AFTER_MS".to_string(),
                "17".to_string(),
            ),
        ]);

        let resolved =
            Config::resolve_with_env(None, CliOverrides::default(), &map_lookup(env)).unwrap();

        assert_eq!(resolved.config.runtime.remote_max_in_flight, 66);
        assert_eq!(resolved.config.runtime.bulkhead_retry_after_ms, 17);
    }

    #[test]
    fn validation_rejects_assurance_level_out_of_range() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("franken_node.toml");
        std::fs::write(
            &path,
            r#"
[registry]
minimum_assurance_level = 9
"#,
        )
        .unwrap();

        let err = Config::resolve_with_env(
            Some(&path),
            CliOverrides::default(),
            &map_lookup(HashMap::new()),
        )
        .unwrap_err();
        assert!(err.to_string().contains("minimum_assurance_level"));
    }
}
