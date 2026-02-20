#![allow(clippy::doc_markdown)]

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Top-level configuration for franken_node.
///
/// Loaded from `franken_node.toml` in the project root or a user-specified path.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
            },
        }
    }

    /// Load configuration from a TOML file.
    ///
    /// Returns an error if the file cannot be read or parsed.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let content =
            std::fs::read_to_string(path).map_err(|e| ConfigError::ReadFailed(path.into(), e))?;
        toml::from_str(&content).map_err(|e| ConfigError::ParseFailed(path.into(), e))
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

        let mut candidates: Vec<PathBuf> = vec![PathBuf::from("franken_node.toml")];
        if let Some(config_path) = dirs_next().map(|d| d.join("config.toml")) {
            candidates.push(config_path);
        }

        for candidate in &candidates {
            if candidate.exists() {
                return Self::load(candidate);
            }
        }

        Ok(Self::default())
    }

    /// Serialize this configuration to TOML.
    pub fn to_toml(&self) -> Result<String, ConfigError> {
        toml::to_string_pretty(self).map_err(ConfigError::SerializeFailed)
    }
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
        match s {
            "strict" => Ok(Self::Strict),
            "balanced" => Ok(Self::Balanced),
            "legacy-risky" => Ok(Self::LegacyRisky),
            _ => Err(ConfigError::InvalidProfile(s.to_string())),
        }
    }
}

// -- Compatibility --

#[derive(Debug, Clone, Serialize, Deserialize)]
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

// -- Migration --

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationConfig {
    /// Enable automatic rewrite suggestions.
    pub autofix: bool,
    /// Require lockstep validation before rollout stage transition.
    pub require_lockstep_validation: bool,
}

// -- Trust --

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustConfig {
    /// Risky actions require fresh revocation checks.
    pub risky_requires_fresh_revocation: bool,
    /// Dangerous actions always require fresh revocation checks.
    pub dangerous_requires_fresh_revocation: bool,
    /// Automatically quarantine high-risk extensions.
    pub quarantine_on_high_risk: bool,
}

// -- Replay --

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayConfig {
    /// Persist high-severity replay artifacts.
    pub persist_high_severity: bool,
    /// Deterministic bundle export format version.
    pub bundle_version: String,
}

// -- Registry --

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryConfig {
    /// Enforce signature and provenance gates.
    pub require_signatures: bool,
    /// Require provenance metadata.
    pub require_provenance: bool,
    /// Minimum assurance level (1-5).
    pub minimum_assurance_level: u8,
}

// -- Fleet --

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FleetConfig {
    /// Fleet convergence timeout for quarantine/release operations (seconds).
    pub convergence_timeout_seconds: u64,
}

// -- Observability --

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObservabilityConfig {
    /// Stable metrics namespace for automation.
    pub namespace: String,
    /// Emit structured audit events.
    pub emit_structured_audit_events: bool,
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_is_balanced() {
        let config = Config::default();
        assert_eq!(config.profile, Profile::Balanced);
        assert!(config.compatibility.emit_divergence_receipts);
        assert!(config.migration.autofix);
        assert!(config.trust.risky_requires_fresh_revocation);
        assert_eq!(config.registry.minimum_assurance_level, 3);
    }

    #[test]
    fn strict_profile_is_more_restrictive() {
        let config = Config::for_profile(Profile::Strict);
        assert_eq!(config.profile, Profile::Strict);
        assert!(!config.migration.autofix);
        assert_eq!(config.registry.minimum_assurance_level, 4);
        assert_eq!(config.fleet.convergence_timeout_seconds, 60);
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
        assert!("invalid".parse::<Profile>().is_err());
    }

    #[test]
    fn profile_display() {
        assert_eq!(Profile::Strict.to_string(), "strict");
        assert_eq!(Profile::Balanced.to_string(), "balanced");
        assert_eq!(Profile::LegacyRisky.to_string(), "legacy-risky");
    }

    #[test]
    fn discover_returns_default_when_no_file() {
        let config = Config::discover(None).expect("discover");
        assert_eq!(config.profile, Profile::Balanced);
    }

    #[test]
    fn load_nonexistent_file_returns_error() {
        let result = Config::load(Path::new("/nonexistent/franken_node.toml"));
        assert!(result.is_err());
    }
}
