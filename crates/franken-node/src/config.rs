#![allow(clippy::doc_markdown)]

use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};

use base64::Engine as _;
use serde::{Deserialize, Serialize};

use crate::push_bounded;

pub mod timeouts;

/// Default number of configuration merge decisions to track.
/// Prevents memory exhaustion from adversarial config override patterns.
pub const DEFAULT_MAX_MERGE_DECISIONS: usize = 100;
const MIN_REGISTRY_SIGNING_KEY_BYTES: usize = 32;

const fn default_max_merge_decisions() -> usize {
    DEFAULT_MAX_MERGE_DECISIONS
}

/// Top-level configuration for franken_node.
///
/// Loaded from `franken_node.toml` in the project root or a user-specified path.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
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

    /// Remote execution and idempotency settings.
    pub remote: RemoteConfig,

    /// Security behavior settings that tune fail-safe windows.
    pub security: SecurityConfig,

    /// Optional external franken_engine binary resolution settings.
    pub engine: EngineConfig,

    /// Runtime lane + bulkhead settings for product scheduling.
    pub runtime: RuntimeConfig,

    /// Algorithmic and statistical threshold constants.
    pub thresholds: ThresholdsConfig,

    /// Category shift benchmark gate configuration.
    pub benchmark: BenchmarkConfig,

    /// Verifier SDK behavior settings.
    pub verifier: VerifierConfig,
}

impl Default for Config {
    fn default() -> Self {
        Self::for_profile(Profile::Balanced)
    }
}

impl Config {
    /// Create a configuration for a specific profile with appropriate defaults.
    ///
    /// # Examples
    ///
    /// ```
    /// use frankenengine_node::config::{Config, Profile};
    ///
    /// let config = Config::for_profile(Profile::Strict);
    /// assert_eq!(config.profile, Profile::Strict);
    /// assert!(config.registry.require_signatures);
    /// ```
    #[must_use]
    pub fn for_profile(profile: Profile) -> Self {
        match profile {
            Profile::Strict => Self {
                profile,
                compatibility: CompatibilityConfig {
                    mode: CompatibilityMode::Strict,
                    emit_divergence_receipts: true,
                    default_receipt_ttl_secs: timeouts::COMPAT_DEFAULT_RECEIPT_TTL_SECS,
                    gate_ttl_secs: None,
                },
                migration: MigrationConfig {
                    autofix: false,
                    require_lockstep_validation: true,
                    verification_threshold: None,
                    confidence_level: None,
                    determinism_rate: None,
                },
                trust: TrustConfig {
                    risky_requires_fresh_revocation: true,
                    dangerous_requires_fresh_revocation: true,
                    quarantine_on_high_risk: true,
                    card_cache_ttl_secs: None,
                    freshness_window_secs: None,
                    min_trust_score: None,
                    decay_factor: None,
                    registry_signing_key: None,
                    reputation_tier_thresholds: None,
                    test_coverage_threshold_pct: None,
                },
                replay: ReplayConfig {
                    persist_high_severity: true,
                    bundle_version: "v1".to_string(),
                    max_replay_capsule_freshness_secs: timeouts::REPLAY_CAPSULE_FRESHNESS_SECS,
                    capsule_freshness_secs: None,
                    max_submissions_per_window: None,
                },
                registry: RegistryConfig {
                    require_signatures: true,
                    require_provenance: true,
                    minimum_assurance_level: 4,
                    builder_identity: None,
                },
                fleet: FleetConfig {
                    state_dir: None,
                    node_id: None,
                    poll_interval_seconds: None,
                    convergence_timeout_seconds: timeouts::FLEET_STRICT_CONVERGENCE_TIMEOUT_SECS,
                    barrier_timeout_ms: None,
                },
                observability: ObservabilityConfig {
                    namespace: "franken_node".to_string(),
                    emit_structured_audit_events: true,
                    max_receipts: None,
                },
                remote: RemoteConfig {
                    idempotency_ttl_secs: timeouts::REMOTE_IDEMPOTENCY_TTL_SECS,
                },
                security: SecurityConfig {
                    max_degraded_duration_secs: timeouts::SECURITY_MAX_DEGRADED_DURATION_SECS,
                    max_merge_decisions: DEFAULT_MAX_MERGE_DECISIONS,
                    decision_receipt_signing_key_path: None,
                    authorized_api_keys: std::collections::BTreeSet::new(),
                    network_policy: NetworkPolicyConfig::default(),
                },
                engine: EngineConfig::default(),
                runtime: RuntimeConfig::strict_defaults(),
                thresholds: ThresholdsConfig::default(),
                benchmark: BenchmarkConfig::default(),
                verifier: VerifierConfig {
                    max_claims_per_request: default_max_claims_per_request(),
                    max_capsule_count: default_max_capsule_count(),
                    max_chain_depth: default_max_chain_depth(),
                },
            },
            Profile::Balanced => Self {
                profile,
                compatibility: CompatibilityConfig {
                    mode: CompatibilityMode::Balanced,
                    emit_divergence_receipts: true,
                    default_receipt_ttl_secs: timeouts::COMPAT_DEFAULT_RECEIPT_TTL_SECS,
                    gate_ttl_secs: None,
                },
                migration: MigrationConfig {
                    autofix: true,
                    require_lockstep_validation: true,
                    verification_threshold: None,
                    confidence_level: None,
                    determinism_rate: None,
                },
                trust: TrustConfig {
                    risky_requires_fresh_revocation: true,
                    dangerous_requires_fresh_revocation: true,
                    quarantine_on_high_risk: true,
                    card_cache_ttl_secs: None,
                    freshness_window_secs: None,
                    min_trust_score: None,
                    decay_factor: None,
                    registry_signing_key: None,
                    reputation_tier_thresholds: None,
                    test_coverage_threshold_pct: None,
                },
                replay: ReplayConfig {
                    persist_high_severity: true,
                    bundle_version: "v1".to_string(),
                    max_replay_capsule_freshness_secs: timeouts::REPLAY_CAPSULE_FRESHNESS_SECS,
                    capsule_freshness_secs: None,
                    max_submissions_per_window: None,
                },
                registry: RegistryConfig {
                    require_signatures: true,
                    require_provenance: true,
                    minimum_assurance_level: 3,
                    builder_identity: None,
                },
                fleet: FleetConfig {
                    state_dir: None,
                    node_id: None,
                    poll_interval_seconds: None,
                    convergence_timeout_seconds: timeouts::FLEET_BALANCED_CONVERGENCE_TIMEOUT_SECS,
                    barrier_timeout_ms: None,
                },
                observability: ObservabilityConfig {
                    namespace: "franken_node".to_string(),
                    emit_structured_audit_events: true,
                    max_receipts: None,
                },
                remote: RemoteConfig {
                    idempotency_ttl_secs: timeouts::REMOTE_IDEMPOTENCY_TTL_SECS,
                },
                security: SecurityConfig {
                    max_degraded_duration_secs: timeouts::SECURITY_MAX_DEGRADED_DURATION_SECS,
                    max_merge_decisions: DEFAULT_MAX_MERGE_DECISIONS,
                    decision_receipt_signing_key_path: None,
                    authorized_api_keys: std::collections::BTreeSet::new(),
                    network_policy: NetworkPolicyConfig::default(),
                },
                engine: EngineConfig::default(),
                runtime: RuntimeConfig::balanced_defaults(),
                thresholds: ThresholdsConfig::default(),
                benchmark: BenchmarkConfig::default(),
                verifier: VerifierConfig {
                    max_claims_per_request: default_max_claims_per_request(),
                    max_capsule_count: default_max_capsule_count(),
                    max_chain_depth: default_max_chain_depth(),
                },
            },
            Profile::LegacyRisky => Self {
                profile,
                compatibility: CompatibilityConfig {
                    mode: CompatibilityMode::LegacyRisky,
                    emit_divergence_receipts: false,
                    default_receipt_ttl_secs: timeouts::COMPAT_DEFAULT_RECEIPT_TTL_SECS,
                    gate_ttl_secs: None,
                },
                migration: MigrationConfig {
                    autofix: true,
                    require_lockstep_validation: false,
                    verification_threshold: None,
                    confidence_level: None,
                    determinism_rate: None,
                },
                trust: TrustConfig {
                    risky_requires_fresh_revocation: false,
                    dangerous_requires_fresh_revocation: true,
                    quarantine_on_high_risk: false,
                    card_cache_ttl_secs: None,
                    freshness_window_secs: None,
                    min_trust_score: None,
                    decay_factor: None,
                    registry_signing_key: None,
                    reputation_tier_thresholds: None,
                    test_coverage_threshold_pct: None,
                },
                replay: ReplayConfig {
                    persist_high_severity: true,
                    bundle_version: "v1".to_string(),
                    max_replay_capsule_freshness_secs: timeouts::REPLAY_CAPSULE_FRESHNESS_SECS,
                    capsule_freshness_secs: None,
                    max_submissions_per_window: None,
                },
                registry: RegistryConfig {
                    require_signatures: false,
                    require_provenance: false,
                    minimum_assurance_level: 1,
                    builder_identity: None,
                },
                fleet: FleetConfig {
                    state_dir: None,
                    node_id: None,
                    poll_interval_seconds: None,
                    convergence_timeout_seconds: timeouts::FLEET_LEGACY_CONVERGENCE_TIMEOUT_SECS,
                    barrier_timeout_ms: None,
                },
                observability: ObservabilityConfig {
                    namespace: "franken_node".to_string(),
                    emit_structured_audit_events: false,
                    max_receipts: None,
                },
                remote: RemoteConfig {
                    idempotency_ttl_secs: timeouts::REMOTE_IDEMPOTENCY_TTL_SECS,
                },
                security: SecurityConfig {
                    max_degraded_duration_secs: timeouts::SECURITY_MAX_DEGRADED_DURATION_SECS,
                    max_merge_decisions: DEFAULT_MAX_MERGE_DECISIONS,
                    decision_receipt_signing_key_path: None,
                    authorized_api_keys: std::collections::BTreeSet::new(),
                    network_policy: NetworkPolicyConfig::default(),
                },
                engine: EngineConfig::default(),
                runtime: RuntimeConfig::legacy_defaults(),
                thresholds: ThresholdsConfig::default(),
                benchmark: BenchmarkConfig::default(),
                verifier: VerifierConfig {
                    max_claims_per_request: default_max_claims_per_request(),
                    max_capsule_count: default_max_capsule_count(),
                    max_chain_depth: default_max_chain_depth(),
                },
            },
        }
    }

    /// Load configuration from a TOML file without CLI/env merge layers.
    ///
    /// This method is useful for fixtures and static snapshots.
    ///
    /// # Examples
    ///
    /// ```
    /// use frankenengine_node::config::{Config, Profile};
    ///
    /// let path = std::env::temp_dir()
    ///     .join(format!("franken-node-load-example-{}.toml", std::process::id()));
    /// let source = Config::for_profile(Profile::LegacyRisky);
    /// std::fs::write(&path, source.to_toml().expect("serialize config"))
    ///     .expect("write config");
    ///
    /// let loaded = Config::load(&path).expect("load config");
    /// assert_eq!(loaded.profile, Profile::LegacyRisky);
    ///
    /// let _ = std::fs::remove_file(path);
    /// ```
    #[allow(dead_code)]
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
    ///
    /// # Examples
    ///
    /// ```
    /// use frankenengine_node::config::{Config, Profile};
    ///
    /// let path = std::env::temp_dir()
    ///     .join(format!("franken-node-discover-example-{}.toml", std::process::id()));
    /// let source = Config::for_profile(Profile::Strict);
    /// std::fs::write(&path, source.to_toml().expect("serialize config"))
    ///     .expect("write config");
    ///
    /// let discovered = Config::discover(Some(&path)).expect("discover config");
    /// assert_eq!(discovered.profile, Profile::Strict);
    ///
    /// let _ = std::fs::remove_file(path);
    /// ```
    #[allow(dead_code)]
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
    ///
    /// # Examples
    ///
    /// ```
    /// use frankenengine_node::config::{CliOverrides, Config, Profile};
    ///
    /// let path = std::env::temp_dir()
    ///     .join(format!("franken-node-resolve-example-{}.toml", std::process::id()));
    /// std::fs::write(
    ///     &path,
    ///     Config::for_profile(Profile::Balanced)
    ///         .to_toml()
    ///         .expect("serialize config"),
    /// )
    /// .expect("write config");
    ///
    /// let resolved = Config::resolve(
    ///     Some(&path),
    ///     CliOverrides {
    ///         profile: Some(Profile::Strict),
    ///     },
    /// )
    /// .expect("resolve config");
    /// assert_eq!(resolved.selected_profile, Profile::Strict);
    ///
    /// let _ = std::fs::remove_file(path);
    /// ```
    pub fn resolve(
        explicit_path: Option<&Path>,
        cli_overrides: CliOverrides,
    ) -> Result<ResolvedConfig, ConfigError> {
        Self::resolve_with_env(explicit_path, cli_overrides, &|key| std::env::var(key).ok())
    }

    /// Resolve configuration using an injected environment lookup.
    ///
    /// This keeps precedence tests deterministic without mutating process-global
    /// environment variables.
    ///
    /// # Examples
    ///
    /// ```
    /// use frankenengine_node::config::{CliOverrides, Config, Profile};
    ///
    /// let resolved = Config::resolve_with_env(None, CliOverrides::default(), &|key| {
    ///     (key == "FRANKEN_NODE_PROFILE").then(|| "strict".to_string())
    /// })
    /// .expect("resolve config");
    ///
    /// assert_eq!(resolved.selected_profile, Profile::Strict);
    /// assert_eq!(resolved.config.profile, Profile::Strict);
    /// ```
    pub fn resolve_with_env(
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
            push_bounded(
                &mut decisions,
                MergeDecision::new(MergeStage::File, "profile", profile.to_string()),
                DEFAULT_MAX_MERGE_DECISIONS,
            );
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
            push_bounded(
                &mut decisions,
                MergeDecision::new(MergeStage::Env, "profile", parsed.to_string()),
                DEFAULT_MAX_MERGE_DECISIONS,
            );
        }

        if let Some(profile) = cli_overrides.profile {
            selected_profile = profile;
            push_bounded(
                &mut decisions,
                MergeDecision::new(MergeStage::Cli, "profile", profile.to_string()),
                DEFAULT_MAX_MERGE_DECISIONS,
            );
        }

        let mut config = Self::for_profile(selected_profile);

        config.apply_overrides(&document.base, MergeStage::File, &mut decisions);

        if let Some(profile_block) = document.profile_block(selected_profile) {
            config.apply_overrides(profile_block, MergeStage::Profile, &mut decisions);
        }
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
    ///
    /// # Examples
    ///
    /// ```
    /// use frankenengine_node::config::{Config, Profile};
    ///
    /// let toml = Config::for_profile(Profile::Strict)
    ///     .to_toml()
    ///     .expect("serialize config");
    /// assert!(toml.contains("profile = \"strict\""));
    /// ```
    pub fn to_toml(&self) -> Result<String, ConfigError> {
        toml::to_string_pretty(self).map_err(ConfigError::SerializeFailed)
    }

    /// Build an idempotency dedupe store from the resolved remote settings.
    ///
    /// # Examples
    ///
    /// ```
    /// use frankenengine_node::config::Config;
    ///
    /// let config = Config::default();
    /// let store = config.idempotency_dedupe_store();
    /// let _ = store;
    /// ```
    #[cfg(feature = "remote-ops")]
    #[must_use]
    pub fn idempotency_dedupe_store(
        &self,
    ) -> crate::remote::idempotency_store::IdempotencyDedupeStore {
        crate::remote::idempotency_store::IdempotencyDedupeStore::from_remote_config(&self.remote)
    }

    /// Build a degraded-mode policy seeded from the resolved security settings.
    ///
    /// # Examples
    ///
    /// ```
    /// use frankenengine_node::config::Config;
    ///
    /// let policy = Config::default().degraded_mode_policy("maintenance");
    /// assert_eq!(policy.mode_name, "maintenance");
    /// ```
    #[must_use]
    pub fn degraded_mode_policy(
        &self,
        mode_name: impl Into<String>,
    ) -> crate::security::degraded_mode_policy::DegradedModePolicy {
        crate::security::degraded_mode_policy::DegradedModePolicy::with_security_defaults(
            mode_name,
            &self.security,
        )
    }

    /// Build a compatibility gate evaluator from the resolved compatibility settings.
    ///
    /// # Examples
    ///
    /// ```
    /// use frankenengine_node::config::Config;
    /// use frankenengine_node::policy::compat_gates::ShimRegistry;
    ///
    /// let evaluator = Config::default().compat_gate_evaluator(ShimRegistry::new());
    /// let _ = evaluator;
    /// ```
    #[cfg(feature = "control-plane")]
    #[must_use]
    pub fn compat_gate_evaluator(
        &self,
        registry: crate::policy::compat_gates::ShimRegistry,
    ) -> crate::policy::compat_gates::CompatGateEvaluator {
        crate::policy::compat_gates::CompatGateEvaluator::from_compatibility_config(
            registry,
            &self.compatibility,
        )
    }

    /// Build a compatibility gate engine from the resolved compatibility settings.
    ///
    /// # Examples
    ///
    /// ```
    /// use frankenengine_node::config::Config;
    ///
    /// let engine = Config::default().compatibility_gate_engine(vec![7; 32]);
    /// assert!(engine.divergence_receipts.is_empty());
    /// ```
    #[cfg(feature = "control-plane")]
    #[must_use]
    pub fn compatibility_gate_engine(
        &self,
        signing_key: Vec<u8>,
    ) -> crate::policy::compatibility_gate::GateEngine {
        crate::policy::compatibility_gate::GateEngine::from_compatibility_config(
            signing_key,
            &self.compatibility,
        )
    }

    /// Build a verifier economy registry from the resolved replay settings.
    ///
    /// # Examples
    ///
    /// ```
    /// use frankenengine_node::config::Config;
    ///
    /// let registry = Config::default().verifier_economy_registry();
    /// let _ = registry;
    /// ```
    #[cfg(feature = "verifier-tools")]
    #[must_use]
    pub fn verifier_economy_registry(&self) -> crate::verifier_economy::VerifierEconomyRegistry {
        crate::verifier_economy::VerifierEconomyRegistry::from_replay_config(&self.replay)
    }

    fn apply_overrides(
        &mut self,
        overrides: &ConfigOverrides,
        stage: MergeStage,
        decisions: &mut Vec<MergeDecision>,
    ) {
        #[allow(non_snake_case)]
        let mut MAX_MERGE_DECISIONS = self.security.max_merge_decisions;

        if let Some(section) = &overrides.security
            && let Some(value) = section.max_merge_decisions
        {
            self.security.max_merge_decisions = value;
            MAX_MERGE_DECISIONS = value;
            push_bounded(
                decisions,
                MergeDecision::new(stage.clone(), "security.max_merge_decisions", value),
                MAX_MERGE_DECISIONS,
            );
        }

        if let Some(section) = &overrides.compatibility {
            if let Some(value) = section.mode {
                self.compatibility.mode = value;
                push_bounded(
                    decisions,
                    MergeDecision::new(stage.clone(), "compatibility.mode", value.to_string()),
                    MAX_MERGE_DECISIONS,
                );
            }
            if let Some(value) = section.emit_divergence_receipts {
                self.compatibility.emit_divergence_receipts = value;
                push_bounded(
                    decisions,
                    MergeDecision::new(
                        stage.clone(),
                        "compatibility.emit_divergence_receipts",
                        value,
                    ),
                    MAX_MERGE_DECISIONS,
                );
            }
            if let Some(value) = section.default_receipt_ttl_secs {
                self.compatibility.default_receipt_ttl_secs = value;
                push_bounded(
                    decisions,
                    MergeDecision::new(
                        stage.clone(),
                        "compatibility.default_receipt_ttl_secs",
                        value,
                    ),
                    MAX_MERGE_DECISIONS,
                );
            }
            if let Some(value) = section.gate_ttl_secs {
                self.compatibility.gate_ttl_secs = Some(value);
                push_bounded(
                    decisions,
                    MergeDecision::new(stage.clone(), "compatibility.gate_ttl_secs", value),
                    MAX_MERGE_DECISIONS,
                );
            }
        }

        if let Some(section) = &overrides.migration {
            if let Some(value) = section.autofix {
                self.migration.autofix = value;
                push_bounded(
                    decisions,
                    MergeDecision::new(stage.clone(), "migration.autofix", value),
                    MAX_MERGE_DECISIONS,
                );
            }
            if let Some(value) = section.require_lockstep_validation {
                self.migration.require_lockstep_validation = value;
                push_bounded(
                    decisions,
                    MergeDecision::new(
                        stage.clone(),
                        "migration.require_lockstep_validation",
                        value,
                    ),
                    MAX_MERGE_DECISIONS,
                );
            }
            if let Some(value) = section.verification_threshold {
                self.migration.verification_threshold = Some(value);
                push_bounded(
                    decisions,
                    MergeDecision::new(stage.clone(), "migration.verification_threshold", value),
                    MAX_MERGE_DECISIONS,
                );
            }
            if let Some(value) = section.confidence_level {
                self.migration.confidence_level = Some(value);
                push_bounded(
                    decisions,
                    MergeDecision::new(stage.clone(), "migration.confidence_level", value),
                    MAX_MERGE_DECISIONS,
                );
            }
            if let Some(value) = section.determinism_rate {
                self.migration.determinism_rate = Some(value);
                push_bounded(
                    decisions,
                    MergeDecision::new(stage.clone(), "migration.determinism_rate", value),
                    MAX_MERGE_DECISIONS,
                );
            }
        }

        if let Some(section) = &overrides.trust {
            if let Some(value) = section.risky_requires_fresh_revocation {
                self.trust.risky_requires_fresh_revocation = value;
                push_bounded(
                    decisions,
                    MergeDecision::new(
                        stage.clone(),
                        "trust.risky_requires_fresh_revocation",
                        value,
                    ),
                    MAX_MERGE_DECISIONS,
                );
            }
            if let Some(value) = section.dangerous_requires_fresh_revocation {
                self.trust.dangerous_requires_fresh_revocation = value;
                push_bounded(
                    decisions,
                    MergeDecision::new(
                        stage.clone(),
                        "trust.dangerous_requires_fresh_revocation",
                        value,
                    ),
                    MAX_MERGE_DECISIONS,
                );
            }
            if let Some(value) = section.quarantine_on_high_risk {
                self.trust.quarantine_on_high_risk = value;
                push_bounded(
                    decisions,
                    MergeDecision::new(stage.clone(), "trust.quarantine_on_high_risk", value),
                    MAX_MERGE_DECISIONS,
                );
            }
            if let Some(value) = section.card_cache_ttl_secs {
                self.trust.card_cache_ttl_secs = Some(value);
                push_bounded(
                    decisions,
                    MergeDecision::new(stage.clone(), "trust.card_cache_ttl_secs", value),
                    MAX_MERGE_DECISIONS,
                );
            }
            if let Some(value) = section.freshness_window_secs {
                self.trust.freshness_window_secs = Some(value);
                push_bounded(
                    decisions,
                    MergeDecision::new(stage.clone(), "trust.freshness_window_secs", value),
                    MAX_MERGE_DECISIONS,
                );
            }
            if let Some(value) = section.min_trust_score {
                self.trust.min_trust_score = Some(value);
                push_bounded(
                    decisions,
                    MergeDecision::new(stage.clone(), "trust.min_trust_score", value),
                    MAX_MERGE_DECISIONS,
                );
            }
            if let Some(value) = section.decay_factor {
                self.trust.decay_factor = Some(value);
                push_bounded(
                    decisions,
                    MergeDecision::new(stage.clone(), "trust.decay_factor", value),
                    MAX_MERGE_DECISIONS,
                );
            }
            if let Some(value) = &section.registry_signing_key {
                self.trust.registry_signing_key = Some(value.clone());
                push_bounded(
                    decisions,
                    MergeDecision::new(stage.clone(), "trust.registry_signing_key", value),
                    MAX_MERGE_DECISIONS,
                );
            }
        }

        if let Some(section) = &overrides.replay {
            if let Some(value) = section.persist_high_severity {
                self.replay.persist_high_severity = value;
                push_bounded(
                    decisions,
                    MergeDecision::new(stage.clone(), "replay.persist_high_severity", value),
                    MAX_MERGE_DECISIONS,
                );
            }
            if let Some(value) = &section.bundle_version {
                self.replay.bundle_version = value.clone();
                push_bounded(
                    decisions,
                    MergeDecision::new(stage.clone(), "replay.bundle_version", value),
                    MAX_MERGE_DECISIONS,
                );
            }
            if let Some(value) = section.max_replay_capsule_freshness_secs {
                self.replay.max_replay_capsule_freshness_secs = value;
                push_bounded(
                    decisions,
                    MergeDecision::new(
                        stage.clone(),
                        "replay.max_replay_capsule_freshness_secs",
                        value,
                    ),
                    MAX_MERGE_DECISIONS,
                );
            }
            if let Some(value) = section.capsule_freshness_secs {
                self.replay.capsule_freshness_secs = Some(value);
                push_bounded(
                    decisions,
                    MergeDecision::new(stage.clone(), "replay.capsule_freshness_secs", value),
                    MAX_MERGE_DECISIONS,
                );
            }
        }

        if let Some(section) = &overrides.registry {
            if let Some(value) = section.require_signatures {
                self.registry.require_signatures = value;
                push_bounded(
                    decisions,
                    MergeDecision::new(stage.clone(), "registry.require_signatures", value),
                    MAX_MERGE_DECISIONS,
                );
            }
            if let Some(value) = section.require_provenance {
                self.registry.require_provenance = value;
                push_bounded(
                    decisions,
                    MergeDecision::new(stage.clone(), "registry.require_provenance", value),
                    MAX_MERGE_DECISIONS,
                );
            }
            if let Some(value) = section.minimum_assurance_level {
                self.registry.minimum_assurance_level = value;
                push_bounded(
                    decisions,
                    MergeDecision::new(stage.clone(), "registry.minimum_assurance_level", value),
                    MAX_MERGE_DECISIONS,
                );
            }
            if let Some(value) = &section.builder_identity {
                self.registry.builder_identity = Some(value.clone());
                push_bounded(
                    decisions,
                    MergeDecision::new(stage.clone(), "registry.builder_identity", value),
                    MAX_MERGE_DECISIONS,
                );
            }
        }

        if let Some(section) = &overrides.fleet {
            if let Some(value) = &section.state_dir {
                self.fleet.state_dir = Some(value.clone());
                push_bounded(
                    decisions,
                    MergeDecision::new(stage.clone(), "fleet.state_dir", value.display()),
                    MAX_MERGE_DECISIONS,
                );
            }
            if let Some(value) = &section.node_id {
                self.fleet.node_id = Some(value.clone());
                push_bounded(
                    decisions,
                    MergeDecision::new(stage.clone(), "fleet.node_id", value),
                    MAX_MERGE_DECISIONS,
                );
            }
            if let Some(value) = section.poll_interval_seconds {
                self.fleet.poll_interval_seconds = Some(value);
                push_bounded(
                    decisions,
                    MergeDecision::new(stage.clone(), "fleet.poll_interval_seconds", value),
                    MAX_MERGE_DECISIONS,
                );
            }
            if let Some(value) = section.convergence_timeout_seconds {
                self.fleet.convergence_timeout_seconds = value;
                push_bounded(
                    decisions,
                    MergeDecision::new(stage.clone(), "fleet.convergence_timeout_seconds", value),
                    MAX_MERGE_DECISIONS,
                );
            }
            if let Some(value) = section.barrier_timeout_ms {
                self.fleet.barrier_timeout_ms = Some(value);
                push_bounded(
                    decisions,
                    MergeDecision::new(stage.clone(), "fleet.barrier_timeout_ms", value),
                    MAX_MERGE_DECISIONS,
                );
            }
        }

        if let Some(section) = &overrides.observability {
            if let Some(value) = &section.namespace {
                self.observability.namespace = value.clone();
                push_bounded(
                    decisions,
                    MergeDecision::new(stage.clone(), "observability.namespace", value),
                    MAX_MERGE_DECISIONS,
                );
            }
            if let Some(value) = section.emit_structured_audit_events {
                self.observability.emit_structured_audit_events = value;
                push_bounded(
                    decisions,
                    MergeDecision::new(
                        stage.clone(),
                        "observability.emit_structured_audit_events",
                        value,
                    ),
                    MAX_MERGE_DECISIONS,
                );
            }
            if let Some(value) = section.max_receipts {
                self.observability.max_receipts = Some(value);
                push_bounded(
                    decisions,
                    MergeDecision::new(stage.clone(), "observability.max_receipts", value),
                    MAX_MERGE_DECISIONS,
                );
            }
        }

        if let Some(section) = &overrides.remote
            && let Some(value) = section.idempotency_ttl_secs
        {
            self.remote.idempotency_ttl_secs = value;
            push_bounded(
                decisions,
                MergeDecision::new(stage.clone(), "remote.idempotency_ttl_secs", value),
                MAX_MERGE_DECISIONS,
            );
        }

        if let Some(section) = &overrides.security
            && let Some(value) = section.max_degraded_duration_secs
        {
            self.security.max_degraded_duration_secs = value;
            push_bounded(
                decisions,
                MergeDecision::new(stage.clone(), "security.max_degraded_duration_secs", value),
                MAX_MERGE_DECISIONS,
            );
        }
        if let Some(section) = &overrides.security
            && let Some(value) = &section.decision_receipt_signing_key_path
        {
            self.security.decision_receipt_signing_key_path = Some(value.clone());
            push_bounded(
                decisions,
                MergeDecision::new(
                    stage.clone(),
                    "security.decision_receipt_signing_key_path",
                    value.display(),
                ),
                MAX_MERGE_DECISIONS,
            );
        }
        if let Some(section) = &overrides.security
            && let Some(value) = &section.authorized_api_keys
        {
            self.security.authorized_api_keys = value.clone();
            push_bounded(
                decisions,
                MergeDecision::new(
                    stage.clone(),
                    "security.authorized_api_keys",
                    format!("[{} keys configured]", value.len()),
                ),
                MAX_MERGE_DECISIONS,
            );
        }

        if let Some(section) = &overrides.engine
            && let Some(value) = &section.binary_path
        {
            self.engine.binary_path = Some(value.clone());
            push_bounded(
                decisions,
                MergeDecision::new(stage.clone(), "engine.binary_path", value.display()),
                MAX_MERGE_DECISIONS,
            );
        }

        if let Some(section) = &overrides.runtime {
            if let Some(value) = section.preferred {
                self.runtime.preferred = value;
                push_bounded(
                    decisions,
                    MergeDecision::new(stage.clone(), "runtime.preferred", value),
                    MAX_MERGE_DECISIONS,
                );
            }
            if let Some(value) = section.remote_max_in_flight {
                self.runtime.remote_max_in_flight = value;
                push_bounded(
                    decisions,
                    MergeDecision::new(stage.clone(), "runtime.remote_max_in_flight", value),
                    MAX_MERGE_DECISIONS,
                );
            }
            if let Some(value) = section.bulkhead_retry_after_ms {
                self.runtime.bulkhead_retry_after_ms = value;
                push_bounded(
                    decisions,
                    MergeDecision::new(stage.clone(), "runtime.bulkhead_retry_after_ms", value),
                    MAX_MERGE_DECISIONS,
                );
            }
            if let Some(lanes) = &section.lanes {
                for (lane_name, lane_overrides) in lanes {
                    if let Some(target) = self.runtime.lanes.get_mut(lane_name) {
                        if let Some(value) = lane_overrides.max_concurrent {
                            target.max_concurrent = value;
                            push_bounded(
                                decisions,
                                MergeDecision::new(
                                    stage.clone(),
                                    format!("runtime.lanes.{lane_name}.max_concurrent").as_str(),
                                    value,
                                ),
                                MAX_MERGE_DECISIONS,
                            );
                        }
                        if let Some(value) = lane_overrides.priority_weight {
                            target.priority_weight = value;
                            push_bounded(
                                decisions,
                                MergeDecision::new(
                                    stage.clone(),
                                    format!("runtime.lanes.{lane_name}.priority_weight").as_str(),
                                    value,
                                ),
                                MAX_MERGE_DECISIONS,
                            );
                        }
                        if let Some(value) = lane_overrides.queue_limit {
                            target.queue_limit = value;
                            push_bounded(
                                decisions,
                                MergeDecision::new(
                                    stage.clone(),
                                    format!("runtime.lanes.{lane_name}.queue_limit").as_str(),
                                    value,
                                ),
                                MAX_MERGE_DECISIONS,
                            );
                        }
                        if let Some(value) = lane_overrides.enqueue_timeout_ms {
                            target.enqueue_timeout_ms = value;
                            push_bounded(
                                decisions,
                                MergeDecision::new(
                                    stage.clone(),
                                    format!("runtime.lanes.{lane_name}.enqueue_timeout_ms")
                                        .as_str(),
                                    value,
                                ),
                                MAX_MERGE_DECISIONS,
                            );
                        }
                        if let Some(value) = lane_overrides.overflow_policy {
                            target.overflow_policy = value;
                            push_bounded(
                                decisions,
                                MergeDecision::new(
                                    stage.clone(),
                                    format!("runtime.lanes.{lane_name}.overflow_policy").as_str(),
                                    value.to_string(),
                                ),
                                MAX_MERGE_DECISIONS,
                            );
                        }
                    }
                }
            }
            if let Some(value) = section.drain_timeout_ms {
                self.runtime.drain_timeout_ms = Some(value);
                push_bounded(
                    decisions,
                    MergeDecision::new(stage.clone(), "runtime.drain_timeout_ms", value),
                    MAX_MERGE_DECISIONS,
                );
            }
        }

        if let Some(section) = &overrides.thresholds {
            if let Some(value) = section.max_failure_rate {
                self.thresholds.max_failure_rate = Some(value);
                push_bounded(
                    decisions,
                    MergeDecision::new(stage.clone(), "thresholds.max_failure_rate", value),
                    MAX_MERGE_DECISIONS,
                );
            }
            if let Some(value) = section.min_quality_score {
                self.thresholds.min_quality_score = Some(value);
                push_bounded(
                    decisions,
                    MergeDecision::new(stage.clone(), "thresholds.min_quality_score", value),
                    MAX_MERGE_DECISIONS,
                );
            }
            if let Some(value) = section.max_variance_pct {
                self.thresholds.max_variance_pct = Some(value);
                push_bounded(
                    decisions,
                    MergeDecision::new(stage.clone(), "thresholds.max_variance_pct", value),
                    MAX_MERGE_DECISIONS,
                );
            }
            if let Some(value) = section.regression_threshold_pct {
                self.thresholds.regression_threshold_pct = Some(value);
                push_bounded(
                    decisions,
                    MergeDecision::new(stage.clone(), "thresholds.regression_threshold_pct", value),
                    MAX_MERGE_DECISIONS,
                );
            }
            if let Some(value) = section.min_resilience_score {
                self.thresholds.min_resilience_score = Some(value);
                push_bounded(
                    decisions,
                    MergeDecision::new(stage.clone(), "thresholds.min_resilience_score", value),
                    MAX_MERGE_DECISIONS,
                );
            }
        }

        if let Some(section) = &overrides.benchmark {
            if let Some(value) = &section.summary_path {
                self.benchmark.summary_path = value.clone();
                push_bounded(
                    decisions,
                    MergeDecision::new(stage.clone(), "benchmark.summary_path", value),
                    MAX_MERGE_DECISIONS,
                );
            }
            if let Some(value) = section.min_aggregate_score {
                self.benchmark.min_aggregate_score = value;
                push_bounded(
                    decisions,
                    MergeDecision::new(stage.clone(), "benchmark.min_aggregate_score", value),
                    MAX_MERGE_DECISIONS,
                );
            }
            if let Some(value) = section.max_latency_ms {
                self.benchmark.max_latency_ms = value;
                push_bounded(
                    decisions,
                    MergeDecision::new(stage.clone(), "benchmark.max_latency_ms", value),
                    MAX_MERGE_DECISIONS,
                );
            }
            if let Some(value) = section.min_throughput_ops {
                self.benchmark.min_throughput_ops = value;
                push_bounded(
                    decisions,
                    MergeDecision::new(stage.clone(), "benchmark.min_throughput_ops", value),
                    MAX_MERGE_DECISIONS,
                );
            }
        }

        if let Some(section) = &overrides.verifier {
            if let Some(value) = section.max_claims_per_request {
                self.verifier.max_claims_per_request = value;
                push_bounded(
                    decisions,
                    MergeDecision::new(stage.clone(), "verifier.max_claims_per_request", value),
                    MAX_MERGE_DECISIONS,
                );
            }
            if let Some(value) = section.max_capsule_count {
                self.verifier.max_capsule_count = value;
                push_bounded(
                    decisions,
                    MergeDecision::new(stage.clone(), "verifier.max_capsule_count", value),
                    MAX_MERGE_DECISIONS,
                );
            }
            if let Some(value) = section.max_chain_depth {
                self.verifier.max_chain_depth = value;
                push_bounded(
                    decisions,
                    MergeDecision::new(stage.clone(), "verifier.max_chain_depth", value),
                    MAX_MERGE_DECISIONS,
                );
            }
        }
    }

    fn apply_env_overrides(
        &mut self,
        env_lookup: &impl Fn(&str) -> Option<String>,
        decisions: &mut Vec<MergeDecision>,
    ) -> Result<(), ConfigError> {
        #[allow(non_snake_case)]
        let mut MAX_MERGE_DECISIONS = self.security.max_merge_decisions;

        if let Some(raw) = env_lookup("FRANKEN_NODE_SECURITY_MAX_MERGE_DECISIONS") {
            let parsed = parse_env_usize("FRANKEN_NODE_SECURITY_MAX_MERGE_DECISIONS", &raw)?;
            self.security.max_merge_decisions = parsed;
            MAX_MERGE_DECISIONS = parsed;
            push_bounded(
                decisions,
                MergeDecision::new(MergeStage::Env, "security.max_merge_decisions", parsed),
                MAX_MERGE_DECISIONS,
            );
        }

        apply_env_field_bool(
            "FRANKEN_NODE_COMPATIBILITY_EMIT_DIVERGENCE_RECEIPTS",
            env_lookup,
            &mut self.compatibility.emit_divergence_receipts,
            "compatibility.emit_divergence_receipts",
            decisions,
            MAX_MERGE_DECISIONS,
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
            push_bounded(
                decisions,
                MergeDecision::new(MergeStage::Env, "compatibility.mode", parsed.to_string()),
                MAX_MERGE_DECISIONS,
            );
        }
        if let Some(raw) = env_lookup("FRANKEN_NODE_COMPATIBILITY_DEFAULT_RECEIPT_TTL_SECS") {
            let parsed =
                parse_env_u64("FRANKEN_NODE_COMPATIBILITY_DEFAULT_RECEIPT_TTL_SECS", &raw)?;
            self.compatibility.default_receipt_ttl_secs = parsed;
            push_bounded(
                decisions,
                MergeDecision::new(
                    MergeStage::Env,
                    "compatibility.default_receipt_ttl_secs",
                    parsed,
                ),
                MAX_MERGE_DECISIONS,
            );
        }
        if let Some(raw) = env_lookup("FRANKEN_NODE_COMPATIBILITY_GATE_TTL_SECS") {
            let parsed = parse_env_u64("FRANKEN_NODE_COMPATIBILITY_GATE_TTL_SECS", &raw)?;
            self.compatibility.gate_ttl_secs = Some(parsed);
            push_bounded(
                decisions,
                MergeDecision::new(MergeStage::Env, "compatibility.gate_ttl_secs", parsed),
                MAX_MERGE_DECISIONS,
            );
        }

        apply_env_field_bool(
            "FRANKEN_NODE_MIGRATION_AUTOFIX",
            env_lookup,
            &mut self.migration.autofix,
            "migration.autofix",
            decisions,
            MAX_MERGE_DECISIONS,
        )?;
        apply_env_field_bool(
            "FRANKEN_NODE_MIGRATION_REQUIRE_LOCKSTEP_VALIDATION",
            env_lookup,
            &mut self.migration.require_lockstep_validation,
            "migration.require_lockstep_validation",
            decisions,
            MAX_MERGE_DECISIONS,
        )?;
        apply_env_field_opt_f64(
            "FRANKEN_NODE_MIGRATION_VERIFICATION_THRESHOLD",
            env_lookup,
            &mut self.migration.verification_threshold,
            "migration.verification_threshold",
            decisions,
            MAX_MERGE_DECISIONS,
        )?;
        apply_env_field_opt_f64(
            "FRANKEN_NODE_MIGRATION_CONFIDENCE_LEVEL",
            env_lookup,
            &mut self.migration.confidence_level,
            "migration.confidence_level",
            decisions,
            MAX_MERGE_DECISIONS,
        )?;
        apply_env_field_opt_f64(
            "FRANKEN_NODE_MIGRATION_DETERMINISM_RATE",
            env_lookup,
            &mut self.migration.determinism_rate,
            "migration.determinism_rate",
            decisions,
            MAX_MERGE_DECISIONS,
        )?;

        apply_env_field_bool(
            "FRANKEN_NODE_TRUST_RISKY_REQUIRES_FRESH_REVOCATION",
            env_lookup,
            &mut self.trust.risky_requires_fresh_revocation,
            "trust.risky_requires_fresh_revocation",
            decisions,
            MAX_MERGE_DECISIONS,
        )?;
        apply_env_field_bool(
            "FRANKEN_NODE_TRUST_DANGEROUS_REQUIRES_FRESH_REVOCATION",
            env_lookup,
            &mut self.trust.dangerous_requires_fresh_revocation,
            "trust.dangerous_requires_fresh_revocation",
            decisions,
            MAX_MERGE_DECISIONS,
        )?;
        apply_env_field_bool(
            "FRANKEN_NODE_TRUST_QUARANTINE_ON_HIGH_RISK",
            env_lookup,
            &mut self.trust.quarantine_on_high_risk,
            "trust.quarantine_on_high_risk",
            decisions,
            MAX_MERGE_DECISIONS,
        )?;
        if let Some(raw) = env_lookup("FRANKEN_NODE_TRUST_CARD_CACHE_TTL_SECS") {
            let parsed = parse_env_u64("FRANKEN_NODE_TRUST_CARD_CACHE_TTL_SECS", &raw)?;
            self.trust.card_cache_ttl_secs = Some(parsed);
            push_bounded(
                decisions,
                MergeDecision::new(MergeStage::Env, "trust.card_cache_ttl_secs", parsed),
                MAX_MERGE_DECISIONS,
            );
        }
        if let Some(raw) = env_lookup("FRANKEN_NODE_TRUST_FRESHNESS_WINDOW_SECS") {
            let parsed = parse_env_u64("FRANKEN_NODE_TRUST_FRESHNESS_WINDOW_SECS", &raw)?;
            self.trust.freshness_window_secs = Some(parsed);
            push_bounded(
                decisions,
                MergeDecision::new(MergeStage::Env, "trust.freshness_window_secs", parsed),
                MAX_MERGE_DECISIONS,
            );
        }
        apply_env_field_opt_f64(
            "FRANKEN_NODE_TRUST_MIN_TRUST_SCORE",
            env_lookup,
            &mut self.trust.min_trust_score,
            "trust.min_trust_score",
            decisions,
            MAX_MERGE_DECISIONS,
        )?;
        apply_env_field_opt_f64(
            "FRANKEN_NODE_TRUST_DECAY_FACTOR",
            env_lookup,
            &mut self.trust.decay_factor,
            "trust.decay_factor",
            decisions,
            MAX_MERGE_DECISIONS,
        )?;
        if let Some(value) = env_lookup("FRANKEN_NODE_TRUST_REGISTRY_SIGNING_KEY") {
            self.trust.registry_signing_key = Some(value.clone());
            push_bounded(
                decisions,
                MergeDecision::new(MergeStage::Env, "trust.registry_signing_key", value),
                MAX_MERGE_DECISIONS,
            );
        }

        apply_env_field_bool(
            "FRANKEN_NODE_REPLAY_PERSIST_HIGH_SEVERITY",
            env_lookup,
            &mut self.replay.persist_high_severity,
            "replay.persist_high_severity",
            decisions,
            MAX_MERGE_DECISIONS,
        )?;
        if let Some(value) = env_lookup("FRANKEN_NODE_REPLAY_BUNDLE_VERSION") {
            self.replay.bundle_version = value.clone();
            push_bounded(
                decisions,
                MergeDecision::new(MergeStage::Env, "replay.bundle_version", value),
                MAX_MERGE_DECISIONS,
            );
        }
        if let Some(raw) = env_lookup("FRANKEN_NODE_REPLAY_MAX_REPLAY_CAPSULE_FRESHNESS_SECS") {
            let parsed = parse_env_u64(
                "FRANKEN_NODE_REPLAY_MAX_REPLAY_CAPSULE_FRESHNESS_SECS",
                &raw,
            )?;
            self.replay.max_replay_capsule_freshness_secs = parsed;
            push_bounded(
                decisions,
                MergeDecision::new(
                    MergeStage::Env,
                    "replay.max_replay_capsule_freshness_secs",
                    parsed,
                ),
                MAX_MERGE_DECISIONS,
            );
        }
        if let Some(raw) = env_lookup("FRANKEN_NODE_REPLAY_CAPSULE_FRESHNESS_SECS") {
            let parsed = parse_env_u64("FRANKEN_NODE_REPLAY_CAPSULE_FRESHNESS_SECS", &raw)?;
            self.replay.capsule_freshness_secs = Some(parsed);
            push_bounded(
                decisions,
                MergeDecision::new(MergeStage::Env, "replay.capsule_freshness_secs", parsed),
                MAX_MERGE_DECISIONS,
            );
        }

        apply_env_field_bool(
            "FRANKEN_NODE_REGISTRY_REQUIRE_SIGNATURES",
            env_lookup,
            &mut self.registry.require_signatures,
            "registry.require_signatures",
            decisions,
            MAX_MERGE_DECISIONS,
        )?;
        apply_env_field_bool(
            "FRANKEN_NODE_REGISTRY_REQUIRE_PROVENANCE",
            env_lookup,
            &mut self.registry.require_provenance,
            "registry.require_provenance",
            decisions,
            MAX_MERGE_DECISIONS,
        )?;

        if let Some(raw) = env_lookup("FRANKEN_NODE_REGISTRY_MINIMUM_ASSURANCE_LEVEL") {
            let parsed = parse_env_u8("FRANKEN_NODE_REGISTRY_MINIMUM_ASSURANCE_LEVEL", &raw)?;
            self.registry.minimum_assurance_level = parsed;
            push_bounded(
                decisions,
                MergeDecision::new(MergeStage::Env, "registry.minimum_assurance_level", parsed),
                MAX_MERGE_DECISIONS,
            );
        }
        if let Some(value) = env_lookup("FRANKEN_NODE_BUILDER_ID") {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                return Err(ConfigError::EnvParseFailed {
                    key: "FRANKEN_NODE_BUILDER_ID".to_string(),
                    value,
                    reason: "value must be non-empty when set".to_string(),
                });
            }
            self.registry.builder_identity = Some(trimmed.to_string());
            push_bounded(
                decisions,
                MergeDecision::new(MergeStage::Env, "registry.builder_identity", trimmed),
                MAX_MERGE_DECISIONS,
            );
        }

        if let Some(raw) = env_lookup("FRANKEN_NODE_FLEET_STATE_DIR") {
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                return Err(ConfigError::EnvParseFailed {
                    key: "FRANKEN_NODE_FLEET_STATE_DIR".to_string(),
                    value: raw,
                    reason: "path must not be empty".to_string(),
                });
            }
            let parsed = PathBuf::from(trimmed);
            self.fleet.state_dir = Some(parsed.clone());
            push_bounded(
                decisions,
                MergeDecision::new(MergeStage::Env, "fleet.state_dir", parsed.display()),
                MAX_MERGE_DECISIONS,
            );
        }
        if let Some(raw) = env_lookup("FRANKEN_NODE_FLEET_NODE_ID") {
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                return Err(ConfigError::EnvParseFailed {
                    key: "FRANKEN_NODE_FLEET_NODE_ID".to_string(),
                    value: raw,
                    reason: "node id must not be empty".to_string(),
                });
            }
            self.fleet.node_id = Some(trimmed.to_string());
            push_bounded(
                decisions,
                MergeDecision::new(MergeStage::Env, "fleet.node_id", trimmed),
                MAX_MERGE_DECISIONS,
            );
        }
        if let Some(raw) = env_lookup("FRANKEN_NODE_FLEET_POLL_INTERVAL_SECONDS") {
            let parsed = parse_env_u64("FRANKEN_NODE_FLEET_POLL_INTERVAL_SECONDS", &raw)?;
            self.fleet.poll_interval_seconds = Some(parsed);
            push_bounded(
                decisions,
                MergeDecision::new(MergeStage::Env, "fleet.poll_interval_seconds", parsed),
                MAX_MERGE_DECISIONS,
            );
        }
        if let Some(raw) = env_lookup("FRANKEN_NODE_FLEET_CONVERGENCE_TIMEOUT_SECONDS") {
            let parsed = parse_env_u64("FRANKEN_NODE_FLEET_CONVERGENCE_TIMEOUT_SECONDS", &raw)?;
            self.fleet.convergence_timeout_seconds = parsed;
            push_bounded(
                decisions,
                MergeDecision::new(MergeStage::Env, "fleet.convergence_timeout_seconds", parsed),
                MAX_MERGE_DECISIONS,
            );
        }
        if let Some(raw) = env_lookup("FRANKEN_NODE_FLEET_BARRIER_TIMEOUT_MS") {
            let parsed = parse_env_u64("FRANKEN_NODE_FLEET_BARRIER_TIMEOUT_MS", &raw)?;
            self.fleet.barrier_timeout_ms = Some(parsed);
            push_bounded(
                decisions,
                MergeDecision::new(MergeStage::Env, "fleet.barrier_timeout_ms", parsed),
                MAX_MERGE_DECISIONS,
            );
        }

        if let Some(value) = env_lookup("FRANKEN_NODE_OBSERVABILITY_NAMESPACE") {
            self.observability.namespace = value.clone();
            push_bounded(
                decisions,
                MergeDecision::new(MergeStage::Env, "observability.namespace", value),
                MAX_MERGE_DECISIONS,
            );
        }
        apply_env_field_bool(
            "FRANKEN_NODE_OBSERVABILITY_EMIT_STRUCTURED_AUDIT_EVENTS",
            env_lookup,
            &mut self.observability.emit_structured_audit_events,
            "observability.emit_structured_audit_events",
            decisions,
            MAX_MERGE_DECISIONS,
        )?;
        if let Some(raw) = env_lookup("FRANKEN_NODE_OBSERVABILITY_MAX_RECEIPTS") {
            let parsed = parse_env_usize("FRANKEN_NODE_OBSERVABILITY_MAX_RECEIPTS", &raw)?;
            self.observability.max_receipts = Some(parsed);
            push_bounded(
                decisions,
                MergeDecision::new(MergeStage::Env, "observability.max_receipts", parsed),
                MAX_MERGE_DECISIONS,
            );
        }
        if let Some(raw) = env_lookup("FRANKEN_NODE_REMOTE_IDEMPOTENCY_TTL_SECS") {
            let parsed = parse_env_u64("FRANKEN_NODE_REMOTE_IDEMPOTENCY_TTL_SECS", &raw)?;
            self.remote.idempotency_ttl_secs = parsed;
            push_bounded(
                decisions,
                MergeDecision::new(MergeStage::Env, "remote.idempotency_ttl_secs", parsed),
                MAX_MERGE_DECISIONS,
            );
        }
        if let Some(raw) = env_lookup("FRANKEN_NODE_SECURITY_MAX_DEGRADED_DURATION_SECS") {
            let parsed = parse_env_u64("FRANKEN_NODE_SECURITY_MAX_DEGRADED_DURATION_SECS", &raw)?;
            self.security.max_degraded_duration_secs = parsed;
            push_bounded(
                decisions,
                MergeDecision::new(
                    MergeStage::Env,
                    "security.max_degraded_duration_secs",
                    parsed,
                ),
                MAX_MERGE_DECISIONS,
            );
        }
        if let Some(value) = env_lookup("FRANKEN_NODE_SECURITY_DECISION_RECEIPT_SIGNING_KEY_PATH") {
            let trimmed = value.trim();
            if !trimmed.is_empty() {
                let path = PathBuf::from(trimmed);
                self.security.decision_receipt_signing_key_path = Some(path.clone());
                push_bounded(
                    decisions,
                    MergeDecision::new(
                        MergeStage::Env,
                        "security.decision_receipt_signing_key_path",
                        path.display(),
                    ),
                    MAX_MERGE_DECISIONS,
                );
            }
        }

        if let Some(value) = env_lookup("FRANKEN_NODE_ENGINE_BINARY_PATH") {
            let trimmed = value.trim();
            if !trimmed.is_empty() {
                let path = PathBuf::from(trimmed);
                self.engine.binary_path = Some(path.clone());
                push_bounded(
                    decisions,
                    MergeDecision::new(MergeStage::Env, "engine.binary_path", path.display()),
                    MAX_MERGE_DECISIONS,
                );
            }
        }

        if let Some(raw) = env_lookup("FRANKEN_NODE_RUNTIME_REMOTE_MAX_IN_FLIGHT") {
            let parsed = parse_env_usize("FRANKEN_NODE_RUNTIME_REMOTE_MAX_IN_FLIGHT", &raw)?;
            self.runtime.remote_max_in_flight = parsed;
            push_bounded(
                decisions,
                MergeDecision::new(MergeStage::Env, "runtime.remote_max_in_flight", parsed),
                MAX_MERGE_DECISIONS,
            );
        }
        if let Some(raw) = env_lookup("FRANKEN_NODE_RUNTIME_BULKHEAD_RETRY_AFTER_MS") {
            let parsed = parse_env_u64("FRANKEN_NODE_RUNTIME_BULKHEAD_RETRY_AFTER_MS", &raw)?;
            self.runtime.bulkhead_retry_after_ms = parsed;
            push_bounded(
                decisions,
                MergeDecision::new(MergeStage::Env, "runtime.bulkhead_retry_after_ms", parsed),
                MAX_MERGE_DECISIONS,
            );
        }
        if let Some(raw) = env_lookup("FRANKEN_NODE_RUNTIME_PREFERRED") {
            let parsed =
                raw.parse::<PreferredRuntime>()
                    .map_err(|_| ConfigError::EnvParseFailed {
                        key: "FRANKEN_NODE_RUNTIME_PREFERRED".to_string(),
                        value: raw.clone(),
                        reason: "expected auto, node, bun, or franken-engine".to_string(),
                    })?;
            self.runtime.preferred = parsed;
            push_bounded(
                decisions,
                MergeDecision::new(MergeStage::Env, "runtime.preferred", parsed),
                MAX_MERGE_DECISIONS,
            );
        }
        if let Some(raw) = env_lookup("FRANKEN_NODE_RUNTIME_DRAIN_TIMEOUT_MS") {
            let parsed = parse_env_u64("FRANKEN_NODE_RUNTIME_DRAIN_TIMEOUT_MS", &raw)?;
            self.runtime.drain_timeout_ms = Some(parsed);
            push_bounded(
                decisions,
                MergeDecision::new(MergeStage::Env, "runtime.drain_timeout_ms", parsed),
                MAX_MERGE_DECISIONS,
            );
        }

        apply_env_field_opt_f64(
            "FRANKEN_NODE_THRESHOLDS_MAX_FAILURE_RATE",
            env_lookup,
            &mut self.thresholds.max_failure_rate,
            "thresholds.max_failure_rate",
            decisions,
            MAX_MERGE_DECISIONS,
        )?;
        apply_env_field_opt_f64(
            "FRANKEN_NODE_THRESHOLDS_MIN_QUALITY_SCORE",
            env_lookup,
            &mut self.thresholds.min_quality_score,
            "thresholds.min_quality_score",
            decisions,
            MAX_MERGE_DECISIONS,
        )?;
        apply_env_field_opt_f64(
            "FRANKEN_NODE_THRESHOLDS_MAX_VARIANCE_PCT",
            env_lookup,
            &mut self.thresholds.max_variance_pct,
            "thresholds.max_variance_pct",
            decisions,
            MAX_MERGE_DECISIONS,
        )?;
        apply_env_field_opt_f64(
            "FRANKEN_NODE_THRESHOLDS_REGRESSION_THRESHOLD_PCT",
            env_lookup,
            &mut self.thresholds.regression_threshold_pct,
            "thresholds.regression_threshold_pct",
            decisions,
            MAX_MERGE_DECISIONS,
        )?;
        apply_env_field_opt_f64(
            "FRANKEN_NODE_THRESHOLDS_MIN_RESILIENCE_SCORE",
            env_lookup,
            &mut self.thresholds.min_resilience_score,
            "thresholds.min_resilience_score",
            decisions,
            MAX_MERGE_DECISIONS,
        )?;

        if let Some(value) = env_lookup("FRANKEN_NODE_BENCHMARK_SUMMARY_PATH") {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                return Err(ConfigError::EnvParseFailed {
                    key: "FRANKEN_NODE_BENCHMARK_SUMMARY_PATH".to_string(),
                    value,
                    reason: "path must not be empty".to_string(),
                });
            }
            self.benchmark.summary_path = trimmed.to_string();
            push_bounded(
                decisions,
                MergeDecision::new(MergeStage::Env, "benchmark.summary_path", trimmed),
                MAX_MERGE_DECISIONS,
            );
        }
        if let Some(raw) = env_lookup("FRANKEN_NODE_BENCHMARK_MIN_AGGREGATE_SCORE") {
            let parsed = parse_env_u32("FRANKEN_NODE_BENCHMARK_MIN_AGGREGATE_SCORE", &raw)?;
            self.benchmark.min_aggregate_score = parsed;
            push_bounded(
                decisions,
                MergeDecision::new(MergeStage::Env, "benchmark.min_aggregate_score", parsed),
                MAX_MERGE_DECISIONS,
            );
        }
        if let Some(raw) = env_lookup("FRANKEN_NODE_BENCHMARK_MAX_LATENCY_MS") {
            let parsed = parse_env_f64("FRANKEN_NODE_BENCHMARK_MAX_LATENCY_MS", &raw)?;
            self.benchmark.max_latency_ms = parsed;
            push_bounded(
                decisions,
                MergeDecision::new(MergeStage::Env, "benchmark.max_latency_ms", parsed),
                MAX_MERGE_DECISIONS,
            );
        }
        if let Some(raw) = env_lookup("FRANKEN_NODE_BENCHMARK_MIN_THROUGHPUT_OPS") {
            let parsed = parse_env_u64("FRANKEN_NODE_BENCHMARK_MIN_THROUGHPUT_OPS", &raw)?;
            self.benchmark.min_throughput_ops = parsed;
            push_bounded(
                decisions,
                MergeDecision::new(MergeStage::Env, "benchmark.min_throughput_ops", parsed),
                MAX_MERGE_DECISIONS,
            );
        }

        if let Some(raw) = env_lookup("FRANKEN_NODE_VERIFIER_MAX_CLAIMS_PER_REQUEST") {
            let parsed = parse_env_usize("FRANKEN_NODE_VERIFIER_MAX_CLAIMS_PER_REQUEST", &raw)?;
            self.verifier.max_claims_per_request = parsed;
            push_bounded(
                decisions,
                MergeDecision::new(MergeStage::Env, "verifier.max_claims_per_request", parsed),
                MAX_MERGE_DECISIONS,
            );
        }
        if let Some(raw) = env_lookup("FRANKEN_NODE_VERIFIER_MAX_CAPSULE_COUNT") {
            let parsed = parse_env_usize("FRANKEN_NODE_VERIFIER_MAX_CAPSULE_COUNT", &raw)?;
            self.verifier.max_capsule_count = parsed;
            push_bounded(
                decisions,
                MergeDecision::new(MergeStage::Env, "verifier.max_capsule_count", parsed),
                MAX_MERGE_DECISIONS,
            );
        }
        if let Some(raw) = env_lookup("FRANKEN_NODE_VERIFIER_MAX_CHAIN_DEPTH") {
            let parsed = parse_env_usize("FRANKEN_NODE_VERIFIER_MAX_CHAIN_DEPTH", &raw)?;
            self.verifier.max_chain_depth = parsed;
            push_bounded(
                decisions,
                MergeDecision::new(MergeStage::Env, "verifier.max_chain_depth", parsed),
                MAX_MERGE_DECISIONS,
            );
        }

        Ok(())
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if !(1..=5).contains(&self.registry.minimum_assurance_level) {
            return Err(ConfigError::ValidationFailed(
                "registry.minimum_assurance_level must be within [1,5]".to_string(),
            ));
        }
        if let Some(builder_identity) = &self.registry.builder_identity
            && builder_identity.trim().is_empty()
        {
            return Err(ConfigError::ValidationFailed(
                "registry.builder_identity must be non-empty when configured".to_string(),
            ));
        }
        if self.fleet.convergence_timeout_seconds == 0 {
            return Err(ConfigError::ValidationFailed(
                "fleet.convergence_timeout_seconds must be > 0".to_string(),
            ));
        }
        if let Some(state_dir) = &self.fleet.state_dir
            && state_dir.as_os_str().is_empty()
        {
            return Err(ConfigError::ValidationFailed(
                "fleet.state_dir must be non-empty when configured".to_string(),
            ));
        }
        if let Some(node_id) = &self.fleet.node_id {
            crate::control_plane::fleet_transport::validate_node_id(node_id).map_err(|err| {
                ConfigError::ValidationFailed(format!("fleet.node_id is invalid: {err}"))
            })?;
        }
        if let Some(poll_interval_seconds) = self.fleet.poll_interval_seconds
            && poll_interval_seconds == 0
        {
            return Err(ConfigError::ValidationFailed(
                "fleet.poll_interval_seconds must be > 0".to_string(),
            ));
        }
        if self.replay.bundle_version.trim().is_empty() {
            return Err(ConfigError::ValidationFailed(
                "replay.bundle_version must be non-empty".to_string(),
            ));
        }
        if self.compatibility.default_receipt_ttl_secs == 0 {
            return Err(ConfigError::ValidationFailed(
                "compatibility.default_receipt_ttl_secs must be > 0".to_string(),
            ));
        }
        if self.replay.max_replay_capsule_freshness_secs == 0 {
            return Err(ConfigError::ValidationFailed(
                "replay.max_replay_capsule_freshness_secs must be > 0".to_string(),
            ));
        }
        if self.observability.namespace.trim().is_empty() {
            return Err(ConfigError::ValidationFailed(
                "observability.namespace must be non-empty".to_string(),
            ));
        }
        if self.observability.max_receipts == Some(0) {
            return Err(ConfigError::ValidationFailed(
                "observability.max_receipts must be > 0 when configured".to_string(),
            ));
        }
        if self.remote.idempotency_ttl_secs == 0 {
            return Err(ConfigError::ValidationFailed(
                "remote.idempotency_ttl_secs must be > 0".to_string(),
            ));
        }
        if self.security.max_degraded_duration_secs == 0 {
            return Err(ConfigError::ValidationFailed(
                "security.max_degraded_duration_secs must be > 0".to_string(),
            ));
        }
        if self.security.max_merge_decisions == 0 {
            return Err(ConfigError::ValidationFailed(
                "security.max_merge_decisions must be > 0".to_string(),
            ));
        }
        if let Some(binary_path) = &self.engine.binary_path
            && binary_path.as_os_str().to_string_lossy().trim().is_empty()
        {
            return Err(ConfigError::ValidationFailed(
                "engine.binary_path must be non-empty when configured".to_string(),
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
        validate_opt_score(
            "migration.verification_threshold",
            self.migration.verification_threshold,
        )?;
        validate_opt_score(
            "migration.confidence_level",
            self.migration.confidence_level,
        )?;
        validate_opt_score(
            "migration.determinism_rate",
            self.migration.determinism_rate,
        )?;
        validate_opt_score("trust.min_trust_score", self.trust.min_trust_score)?;
        validate_opt_score("trust.decay_factor", self.trust.decay_factor)?;
        validate_opt_pct(
            "trust.test_coverage_threshold_pct",
            self.trust.test_coverage_threshold_pct,
        )?;
        if let Some(thresholds) = &self.trust.reputation_tier_thresholds {
            validate_reputation_thresholds(thresholds)?;
        }
        match &self.trust.registry_signing_key {
            Some(registry_signing_key) => {
                validate_registry_signing_key(registry_signing_key)?;
            }
            None => {
                return Err(ConfigError::ValidationFailed(
                    "trust.registry_signing_key must be configured (fail-closed security boundary)"
                        .to_string(),
                ));
            }
        }
        validate_opt_score(
            "thresholds.max_failure_rate",
            self.thresholds.max_failure_rate,
        )?;
        validate_opt_score(
            "thresholds.min_quality_score",
            self.thresholds.min_quality_score,
        )?;
        validate_opt_pct(
            "thresholds.max_variance_pct",
            self.thresholds.max_variance_pct,
        )?;
        validate_opt_pct(
            "thresholds.regression_threshold_pct",
            self.thresholds.regression_threshold_pct,
        )?;
        validate_opt_score(
            "thresholds.min_resilience_score",
            self.thresholds.min_resilience_score,
        )?;
        validate_benchmark_config(&self.benchmark)?;
        validate_verifier_config(&self.verifier)?;
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
    merge_decision_cap: usize,
) -> Result<(), ConfigError> {
    if let Some(raw) = env_lookup(key) {
        let parsed = parse_env_bool(key, &raw)?;
        *slot = parsed;
        push_bounded(
            decisions,
            MergeDecision::new(MergeStage::Env, field, parsed),
            merge_decision_cap,
        );
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

fn parse_env_u32(key: &str, raw: &str) -> Result<u32, ConfigError> {
    raw.trim()
        .parse::<u32>()
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

fn parse_env_f64(key: &str, raw: &str) -> Result<f64, ConfigError> {
    let parsed = raw
        .trim()
        .parse::<f64>()
        .map_err(|_| ConfigError::EnvParseFailed {
            key: key.to_string(),
            value: raw.to_string(),
            reason: "expected floating-point number".to_string(),
        })?;
    if !parsed.is_finite() {
        return Err(ConfigError::EnvParseFailed {
            key: key.to_string(),
            value: raw.to_string(),
            reason: "value must be finite (not NaN or Inf)".to_string(),
        });
    }
    Ok(parsed)
}

fn apply_env_field_opt_f64(
    key: &str,
    env_lookup: &impl Fn(&str) -> Option<String>,
    slot: &mut Option<f64>,
    field: &str,
    decisions: &mut Vec<MergeDecision>,
    merge_decision_cap: usize,
) -> Result<(), ConfigError> {
    if let Some(raw) = env_lookup(key) {
        let parsed = parse_env_f64(key, &raw)?;
        *slot = Some(parsed);
        push_bounded(
            decisions,
            MergeDecision::new(MergeStage::Env, field, parsed),
            merge_decision_cap,
        );
    }
    Ok(())
}

/// Validate an optional score is finite and within [0.0, 1.0].
fn validate_opt_score(field: &str, value: Option<f64>) -> Result<(), ConfigError> {
    if let Some(v) = value
        && (!v.is_finite() || !(0.0..=1.0).contains(&v))
    {
        return Err(ConfigError::ValidationFailed(format!(
            "{field} must be a finite value within [0.0, 1.0], got {v}"
        )));
    }
    Ok(())
}

/// Validate an optional percentage is finite and within [0.0, 100.0].
fn validate_opt_pct(field: &str, value: Option<f64>) -> Result<(), ConfigError> {
    if let Some(v) = value
        && (!v.is_finite() || !(0.0..=100.0).contains(&v))
    {
        return Err(ConfigError::ValidationFailed(format!(
            "{field} must be a finite value within [0.0, 100.0], got {v}"
        )));
    }
    Ok(())
}

fn validate_reputation_thresholds(thresholds: &ReputationThresholds) -> Result<(), ConfigError> {
    for (field, value) in [
        (
            "trust.reputation_tier_thresholds.provisional",
            thresholds.provisional,
        ),
        (
            "trust.reputation_tier_thresholds.established",
            thresholds.established,
        ),
        (
            "trust.reputation_tier_thresholds.trusted",
            thresholds.trusted,
        ),
    ] {
        validate_opt_pct(field, Some(value))?;
    }

    if !(thresholds.provisional < thresholds.established
        && thresholds.established < thresholds.trusted)
    {
        return Err(ConfigError::ValidationFailed(
            "trust.reputation_tier_thresholds must satisfy provisional < established < trusted"
                .to_string(),
        ));
    }

    Ok(())
}

fn validate_benchmark_config(config: &BenchmarkConfig) -> Result<(), ConfigError> {
    let summary_path = config.summary_path.trim();
    if summary_path.is_empty() || summary_path.contains('\0') {
        return Err(ConfigError::ValidationFailed(
            "benchmark.summary_path must be non-empty and must not contain NUL".to_string(),
        ));
    }
    if !config.max_latency_ms.is_finite() || config.max_latency_ms <= 0.0 {
        return Err(ConfigError::ValidationFailed(
            "benchmark.max_latency_ms must be a finite positive value".to_string(),
        ));
    }
    if config.min_throughput_ops == 0 {
        return Err(ConfigError::ValidationFailed(
            "benchmark.min_throughput_ops must be > 0".to_string(),
        ));
    }
    Ok(())
}

fn validate_verifier_config(config: &VerifierConfig) -> Result<(), ConfigError> {
    if config.max_claims_per_request == 0 {
        return Err(ConfigError::ValidationFailed(
            "verifier.max_claims_per_request must be > 0".to_string(),
        ));
    }
    if config.max_capsule_count == 0 {
        return Err(ConfigError::ValidationFailed(
            "verifier.max_capsule_count must be > 0".to_string(),
        ));
    }
    if config.max_chain_depth == 0 {
        return Err(ConfigError::ValidationFailed(
            "verifier.max_chain_depth must be > 0".to_string(),
        ));
    }
    Ok(())
}

fn validate_registry_signing_key(encoded: &str) -> Result<(), ConfigError> {
    if encoded.trim() != encoded || encoded.is_empty() {
        return Err(ConfigError::ValidationFailed(
            "trust.registry_signing_key must be non-empty base64 without surrounding whitespace"
                .to_string(),
        ));
    }

    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|err| {
            ConfigError::ValidationFailed(format!(
                "trust.registry_signing_key must be valid base64: {err}"
            ))
        })?;

    if decoded.len() < MIN_REGISTRY_SIGNING_KEY_BYTES {
        return Err(ConfigError::ValidationFailed(format!(
            "trust.registry_signing_key must decode to at least {MIN_REGISTRY_SIGNING_KEY_BYTES} bytes"
        )));
    }

    Ok(())
}

// -- Resolution Model --

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CliOverrides {
    pub profile: Option<Profile>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
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

/// Normalize profile key for case-insensitive matching.
///
/// Applies standard normalization rules:
/// - Trims leading/trailing whitespace
/// - Converts to lowercase ASCII
/// - Replaces underscores with hyphens
///
/// # Input forms accepted
///
/// - Case variations: "strict", "STRICT", "Strict"
/// - Underscore variations: "legacy_risky", "legacy-risky"
/// - Whitespace variations: " strict ", "balanced "
///
/// # Invalid profiles
///
/// Unknown profile names after normalization will be rejected by
/// [`Profile::from_str`] with a hard error listing valid options.
/// No silent fallback is applied.
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
    pub remote: Option<RemoteOverrides>,
    pub security: Option<SecurityOverrides>,
    pub engine: Option<EngineOverrides>,
    pub runtime: Option<RuntimeOverrides>,
    pub thresholds: Option<ThresholdsOverrides>,
    pub benchmark: Option<BenchmarkOverrides>,
    pub verifier: Option<VerifierOverrides>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct CompatibilityOverrides {
    pub mode: Option<CompatibilityMode>,
    pub emit_divergence_receipts: Option<bool>,
    pub default_receipt_ttl_secs: Option<u64>,
    pub gate_ttl_secs: Option<u64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct MigrationOverrides {
    pub autofix: Option<bool>,
    pub require_lockstep_validation: Option<bool>,
    pub verification_threshold: Option<f64>,
    pub confidence_level: Option<f64>,
    pub determinism_rate: Option<f64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct TrustOverrides {
    pub risky_requires_fresh_revocation: Option<bool>,
    pub dangerous_requires_fresh_revocation: Option<bool>,
    pub quarantine_on_high_risk: Option<bool>,
    pub card_cache_ttl_secs: Option<u64>,
    pub freshness_window_secs: Option<u64>,
    pub min_trust_score: Option<f64>,
    pub decay_factor: Option<f64>,
    pub registry_signing_key: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct ReplayOverrides {
    pub persist_high_severity: Option<bool>,
    pub bundle_version: Option<String>,
    pub max_replay_capsule_freshness_secs: Option<u64>,
    pub capsule_freshness_secs: Option<u64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RegistryOverrides {
    pub require_signatures: Option<bool>,
    pub require_provenance: Option<bool>,
    pub minimum_assurance_level: Option<u8>,
    pub builder_identity: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct FleetOverrides {
    pub state_dir: Option<PathBuf>,
    pub node_id: Option<String>,
    pub poll_interval_seconds: Option<u64>,
    pub convergence_timeout_seconds: Option<u64>,
    pub barrier_timeout_ms: Option<u64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct ObservabilityOverrides {
    pub namespace: Option<String>,
    pub emit_structured_audit_events: Option<bool>,
    pub max_receipts: Option<usize>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RemoteOverrides {
    pub idempotency_ttl_secs: Option<u64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct SecurityOverrides {
    pub max_degraded_duration_secs: Option<u64>,
    pub max_merge_decisions: Option<usize>,
    pub decision_receipt_signing_key_path: Option<PathBuf>,
    pub authorized_api_keys: Option<BTreeSet<String>>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct EngineOverrides {
    pub binary_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RuntimeOverrides {
    pub preferred: Option<PreferredRuntime>,
    pub remote_max_in_flight: Option<usize>,
    pub bulkhead_retry_after_ms: Option<u64>,
    pub lanes: Option<BTreeMap<String, RuntimeLaneOverrides>>,
    pub drain_timeout_ms: Option<u64>,
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

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct ThresholdsOverrides {
    pub max_failure_rate: Option<f64>,
    pub min_quality_score: Option<f64>,
    pub max_variance_pct: Option<f64>,
    pub regression_threshold_pct: Option<f64>,
    pub min_resilience_score: Option<f64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct BenchmarkOverrides {
    pub summary_path: Option<String>,
    pub min_aggregate_score: Option<u32>,
    pub max_latency_ms: Option<f64>,
    pub min_throughput_ops: Option<u64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct VerifierOverrides {
    pub max_claims_per_request: Option<usize>,
    pub max_capsule_count: Option<usize>,
    pub max_chain_depth: Option<usize>,
}

// -- Profile --
//
// Runtime policy profiles: strict, balanced, legacy-risky.
// These control runtime behavior and security policy strictness.
//
// NOTE: These are SEPARATE from packaging profiles (local/dev/enterprise)
// defined in packaging/profiles.toml, which control build/release metadata.
// Two distinct namespaces:
//   - Runtime CLI: --profile strict|balanced|legacy-risky
//   - Packaging:   local|dev|enterprise (build-time only)

/// Runtime security and compatibility profile for franken_node behavior.
///
/// Controls the overall security posture, compatibility level, and performance
/// characteristics of the runtime. Higher security profiles provide stronger
/// protections but may impact compatibility with legacy JavaScript/Node.js code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Profile {
    /// Strict security profile with maximum protection and minimal compatibility.
    ///
    /// **Security:** All security features enabled, fail-closed on violations.
    /// **Compatibility:** Limited to modern, well-behaved JavaScript only.
    /// **Performance:** May be slower due to additional security checks.
    /// **Use when:** High-security environments, no legacy code dependencies.
    Strict,

    /// Balanced profile providing good security with reasonable compatibility.
    ///
    /// **Security:** Most security features enabled with some flexibility.
    /// **Compatibility:** Supports common JavaScript patterns and some legacy code.
    /// **Performance:** Good balance between security overhead and execution speed.
    /// **Use when:** Production environments with mixed modern/legacy code.
    Balanced,

    /// Legacy-compatible profile prioritizing compatibility over security.
    ///
    /// **Security:** Reduced security checks to allow legacy JavaScript patterns.
    /// **Compatibility:** Maximum compatibility with old Node.js/JavaScript code.
    /// **Performance:** Fastest execution but with security trade-offs.
    /// **Use when:** Migration scenarios, development, or non-security-critical environments.
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
        // bd-83lv0: Explicit allowlist to prevent profile manipulation attacks
        const VALID_PROFILES: &[&str] = &["strict", "balanced", "legacy-risky"];
        const PACKAGING_PROFILES: &[&str] = &["local", "dev", "enterprise"];

        let normalized = normalize_profile_key(s);
        match normalized.as_str() {
            "strict" => Ok(Self::Strict),
            "balanced" => Ok(Self::Balanced),
            "legacy-risky" => Ok(Self::LegacyRisky),
            _ => {
                // bd-2zped: Detect packaging profile confusion and provide helpful error
                if PACKAGING_PROFILES.contains(&normalized.as_str()) {
                    Err(ConfigError::InvalidProfile(format!(
                        "Invalid runtime profile '{}'. This appears to be a packaging profile name. \
                        Runtime profiles (--profile) control security/compatibility behavior and must be one of: {}. \
                        Packaging profiles ({}) are used during build/release and are defined in packaging/profiles.toml.",
                        s,
                        VALID_PROFILES.join(", "),
                        PACKAGING_PROFILES.join(", ")
                    )))
                } else {
                    // bd-83lv0: Hard error with explicit allowlist - no silent fallback
                    Err(ConfigError::InvalidProfile(format!(
                        "Invalid runtime profile '{}'. Must be one of: {}. No fallback will be applied.",
                        s,
                        VALID_PROFILES.join(", ")
                    )))
                }
            }
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
    /// TTL for signed compatibility receipts (seconds).
    pub default_receipt_ttl_secs: u64,
    /// Optional override for compat-gate TTL (seconds).
    /// When `None`, consumers use `timeouts::COMPAT_DEFAULT_RECEIPT_TTL_SECS`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gate_ttl_secs: Option<u64>,
}

/// API compatibility mode controlling migration behavior and runtime dispatch.
///
/// Determines how strictly franken_node enforces compatibility with existing
/// Node.js/JavaScript APIs during migration and execution. More strict modes
/// provide better correctness but may break legacy code patterns.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CompatibilityMode {
    /// Strict API compatibility with comprehensive validation and fail-fast behavior.
    ///
    /// **Compatibility level:** Highest correctness, strict spec compliance.
    /// **Performance trade-offs:** Slower due to extensive validation overhead.
    /// **Migration implications:** May break legacy code that relies on loose semantics.
    /// Best for new projects or when correctness is paramount.
    Strict,

    /// Balanced compatibility providing good correctness with practical flexibility.
    ///
    /// **Compatibility level:** Good spec compliance with common-case tolerance.
    /// **Performance trade-offs:** Moderate validation overhead, good throughput.
    /// **Migration implications:** Handles most legacy patterns while catching real bugs.
    /// Recommended for most migration scenarios.
    Balanced,

    /// Legacy-first compatibility prioritizing migration success over strict correctness.
    ///
    /// **Compatibility level:** Maximum tolerance for non-standard JavaScript patterns.
    /// **Performance trade-offs:** Fastest execution with minimal validation.
    /// **Migration implications:** Allows questionable legacy code to continue working.
    /// Use during initial migration phases or with heavily legacy codebases.
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MigrationConfig {
    /// Enable automatic rewrite suggestions.
    pub autofix: bool,
    /// Require lockstep validation before rollout stage transition.
    pub require_lockstep_validation: bool,
    /// Optional verification threshold for migration validation.
    /// When `None`, consumers use the default (0.95).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verification_threshold: Option<f64>,
    /// Optional confidence level for statistical checks.
    /// When `None`, consumers use the default (0.95).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence_level: Option<f64>,
    /// Optional determinism rate for replay validation.
    /// When `None`, consumers use the default (0.99).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub determinism_rate: Option<f64>,
}

// -- Trust --

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ReputationThresholds {
    /// Minimum score for trusted reputation tier.
    pub trusted: f64,
    /// Minimum score for established reputation tier.
    pub established: f64,
    /// Minimum score for provisional reputation tier.
    pub provisional: f64,
}

impl Default for ReputationThresholds {
    fn default() -> Self {
        Self {
            trusted: 80.0,
            established: 50.0,
            provisional: 20.0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TrustConfig {
    /// Risky actions require fresh revocation checks.
    pub risky_requires_fresh_revocation: bool,
    /// Dangerous actions always require fresh revocation checks.
    pub dangerous_requires_fresh_revocation: bool,
    /// Automatically quarantine high-risk extensions.
    pub quarantine_on_high_risk: bool,
    /// Optional override for trust-card cache TTL (seconds).
    /// When `None`, consumers use `timeouts::TRUST_CARD_CACHE_TTL_SECS`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub card_cache_ttl_secs: Option<u64>,
    /// Optional override for trust freshness window (seconds).
    /// When `None`, consumers use `timeouts::TRUST_FRESHNESS_WINDOW_SECS`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub freshness_window_secs: Option<u64>,
    /// Optional minimum trust score threshold.
    /// When `None`, consumers use the default (0.6).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_trust_score: Option<f64>,
    /// Optional trust score decay factor.
    /// When `None`, consumers use the default (0.95).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decay_factor: Option<f64>,
    /// Optional trust-card registry signing key (base64-encoded HMAC key).
    /// Validated runtime configurations must set this fail-closed trust boundary.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registry_signing_key: Option<String>,
    /// Optional reputation tier thresholds (trusted, established, provisional).
    /// When `None`, consumers use defaults (80.0, 50.0, 20.0).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reputation_tier_thresholds: Option<ReputationThresholds>,
    /// Optional test coverage percentage threshold for certification.
    /// When `None`, consumers use the default (80.0).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub test_coverage_threshold_pct: Option<f64>,
}

// -- Replay --

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReplayConfig {
    /// Persist high-severity replay artifacts.
    pub persist_high_severity: bool,
    /// Deterministic bundle export format version.
    pub bundle_version: String,
    /// Maximum permitted replay capsule freshness window (seconds).
    pub max_replay_capsule_freshness_secs: u64,
    /// Optional override for capsule freshness check (seconds).
    /// When `None`, consumers use `timeouts::REPLAY_CAPSULE_FRESHNESS_SECS`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capsule_freshness_secs: Option<u64>,
    /// Maximum submissions per verifier per window for anti-gaming rate limiting.
    /// When `None`, consumers use the default of 100 submissions per window.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_submissions_per_window: Option<u32>,
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
    /// Optional stable builder identity for CLI-published provenance.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub builder_identity: Option<String>,
}

// -- Fleet --

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FleetConfig {
    /// Optional override for the persisted fleet shared-state directory.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state_dir: Option<PathBuf>,
    /// Optional stable node identifier for fleet agent mode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_id: Option<String>,
    /// Optional default poll interval for fleet agent mode (seconds).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub poll_interval_seconds: Option<u64>,
    /// Fleet convergence timeout for quarantine/release operations (seconds).
    pub convergence_timeout_seconds: u64,
    /// Optional override for fleet barrier timeout (milliseconds).
    /// When `None`, consumers use `timeouts::FLEET_BARRIER_TIMEOUT_MS`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub barrier_timeout_ms: Option<u64>,
}

// -- Observability --

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ObservabilityConfig {
    /// Stable metrics namespace for automation.
    pub namespace: String,
    /// Emit structured audit events.
    pub emit_structured_audit_events: bool,
    /// Optional cap on active on-disk receipts before older entries are archived.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_receipts: Option<usize>,
}

// -- Remote --

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RemoteConfig {
    /// Default TTL for remote idempotency entries (seconds).
    pub idempotency_ttl_secs: u64,
}

// -- Security --

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecurityConfig {
    /// Maximum time the system may remain in degraded mode before suspension.
    pub max_degraded_duration_secs: u64,

    /// Maximum number of configuration merge decisions retained in diagnostics.
    #[serde(default = "default_max_merge_decisions")]
    pub max_merge_decisions: usize,

    /// Optional Ed25519 private signing key path for live decision-receipt export.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision_receipt_signing_key_path: Option<PathBuf>,

    /// List of authorized API keys for control-plane access.
    #[serde(default)]
    pub authorized_api_keys: std::collections::BTreeSet<String>,

    /// Network egress policy enforcement mode.
    #[serde(default)]
    pub network_policy: NetworkPolicyConfig,
}

/// SSRF enforcement mode for network policy.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum SsrfEnforcementMode {
    /// No SSRF protection - all requests allowed.
    None,
    /// Monitor mode - violations are logged but requests proceed.
    #[default]
    Monitor,
    /// Block mode - violations terminate the runtime process.
    Block,
}

/// Network egress policy configuration for spawned runtime processes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NetworkPolicyConfig {
    /// SSRF enforcement mode: none, monitor, or block.
    #[serde(default)]
    pub ssrf_enforcement: SsrfEnforcementMode,

    /// Whether to enforce SSRF protection (block private/internal IPs).
    /// Deprecated: use ssrf_enforcement instead.
    #[serde(default = "default_true")]
    pub ssrf_protection_enabled: bool,

    /// Whether to block cloud metadata endpoints (169.254.169.254, etc.).
    #[serde(default = "default_true")]
    pub block_cloud_metadata: bool,

    /// Explicit allowlist of hosts that bypass SSRF checks.
    #[serde(default)]
    pub allowlist: Vec<NetworkAllowlistEntry>,

    /// Whether to log blocked requests (always true in strict mode).
    #[serde(default = "default_true")]
    pub audit_blocked_requests: bool,
}

/// An entry in the network allowlist.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NetworkAllowlistEntry {
    /// Host pattern (exact match or *.example.com wildcard).
    pub host: String,
    /// Optional port restriction.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    /// Reason for the allowlist entry (for audit trail).
    pub reason: String,
}

fn default_true() -> bool {
    true
}

impl Default for NetworkPolicyConfig {
    fn default() -> Self {
        Self {
            ssrf_enforcement: SsrfEnforcementMode::Monitor,
            ssrf_protection_enabled: true,
            block_cloud_metadata: true,
            allowlist: Vec::new(),
            audit_blocked_requests: true,
        }
    }
}

// -- Engine --

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct EngineConfig {
    /// Optional path or command name for the franken_engine binary.
    pub binary_path: Option<PathBuf>,
}

// -- Runtime --

/// JavaScript runtime preference for execution dispatch.
///
/// Controls which runtime is selected for executing JavaScript code.
/// Auto-detection is performed when `Auto` is selected.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum PreferredRuntime {
    /// Auto-detect runtime based on availability and compatibility.
    ///
    /// Selection criteria (in priority order):
    /// 1. FrankenEngine if available and compatible
    /// 2. Node.js if available in PATH
    /// 3. Bun if available in PATH
    /// 4. Fallback error if none available
    ///
    /// Auto-detection fires on first execution and caches the result
    /// for the session duration.
    #[default]
    Auto,

    /// Force Node.js runtime.
    ///
    /// Requires Node.js to be available in PATH. Execution will fail
    /// if Node.js is not found or incompatible version detected.
    Node,

    /// Force Bun runtime.
    ///
    /// Requires Bun to be available in PATH. Execution will fail
    /// if Bun is not found or incompatible version detected.
    Bun,

    /// Force FrankenEngine runtime.
    ///
    /// Uses the sibling franken_engine crate for execution. This is
    /// the preferred option for trust-native execution with full
    /// security policy enforcement and replay capabilities.
    FrankenEngine,
}

impl PreferredRuntime {
    /// Return true when runtime selection should be auto-detected.
    ///
    /// # Examples
    ///
    /// ```
    /// use frankenengine_node::config::PreferredRuntime;
    ///
    /// assert!(PreferredRuntime::Auto.is_auto());
    /// assert!(!PreferredRuntime::Node.is_auto());
    /// ```
    #[must_use]
    pub const fn is_auto(self) -> bool {
        matches!(self, Self::Auto)
    }
}

impl std::fmt::Display for PreferredRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Auto => write!(f, "auto"),
            Self::Node => write!(f, "node"),
            Self::Bun => write!(f, "bun"),
            Self::FrankenEngine => write!(f, "franken-engine"),
        }
    }
}

impl std::str::FromStr for PreferredRuntime {
    type Err = ConfigError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match normalize_profile_key(s).as_str() {
            "auto" => Ok(Self::Auto),
            "node" => Ok(Self::Node),
            "bun" => Ok(Self::Bun),
            "franken-engine" | "frankenengine" => Ok(Self::FrankenEngine),
            _ => Err(ConfigError::InvalidPreferredRuntime(s.to_string())),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeConfig {
    /// Preferred run runtime: auto, node, bun, or franken-engine.
    pub preferred: PreferredRuntime,
    /// Global max in-flight network-bound operations across all lanes.
    pub remote_max_in_flight: usize,
    /// Retry hint for callers when the global bulkhead is saturated.
    pub bulkhead_retry_after_ms: u64,
    /// Per-lane scheduler settings keyed by lane name.
    pub lanes: BTreeMap<String, RuntimeLaneConfig>,
    /// Optional override for graceful drain timeout (milliseconds).
    /// When `None`, consumers use `timeouts::RUNTIME_DRAIN_TIMEOUT_MS`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub drain_timeout_ms: Option<u64>,
}

impl RuntimeConfig {
    /// Return strict runtime lane and bulkhead defaults.
    ///
    /// # Examples
    ///
    /// ```
    /// use frankenengine_node::config::{LaneOverflowPolicy, RuntimeConfig};
    ///
    /// let config = RuntimeConfig::strict_defaults();
    /// assert_eq!(config.remote_max_in_flight, 32);
    /// assert_eq!(
    ///     config.lanes["cancel"].overflow_policy,
    ///     LaneOverflowPolicy::Reject
    /// );
    /// ```
    #[must_use]
    pub fn strict_defaults() -> Self {
        Self {
            preferred: PreferredRuntime::Auto,
            remote_max_in_flight: 32,
            bulkhead_retry_after_ms: 100,
            lanes: default_runtime_lanes(
                RuntimeLaneConfig::new(8, 100, 16, 25, LaneOverflowPolicy::Reject),
                RuntimeLaneConfig::new(12, 80, 24, 50, LaneOverflowPolicy::EnqueueWithTimeout),
                RuntimeLaneConfig::new(16, 60, 32, 75, LaneOverflowPolicy::EnqueueWithTimeout),
                RuntimeLaneConfig::new(4, 20, 32, 100, LaneOverflowPolicy::ShedOldest),
            ),
            drain_timeout_ms: None,
        }
    }

    /// Return balanced runtime lane and bulkhead defaults.
    ///
    /// # Examples
    ///
    /// ```
    /// use frankenengine_node::config::RuntimeConfig;
    ///
    /// let config = RuntimeConfig::balanced_defaults();
    /// assert_eq!(config.remote_max_in_flight, 50);
    /// assert!(config.lanes.contains_key("realtime"));
    /// ```
    #[must_use]
    pub fn balanced_defaults() -> Self {
        Self {
            preferred: PreferredRuntime::Auto,
            remote_max_in_flight: 50,
            bulkhead_retry_after_ms: 50,
            lanes: default_runtime_lanes(
                RuntimeLaneConfig::new(12, 100, 24, 25, LaneOverflowPolicy::Reject),
                RuntimeLaneConfig::new(16, 80, 32, 50, LaneOverflowPolicy::EnqueueWithTimeout),
                RuntimeLaneConfig::new(24, 60, 48, 75, LaneOverflowPolicy::EnqueueWithTimeout),
                RuntimeLaneConfig::new(8, 20, 64, 100, LaneOverflowPolicy::ShedOldest),
            ),
            drain_timeout_ms: None,
        }
    }

    /// Return legacy-compatible runtime lane and bulkhead defaults.
    ///
    /// # Examples
    ///
    /// ```
    /// use frankenengine_node::config::RuntimeConfig;
    ///
    /// let config = RuntimeConfig::legacy_defaults();
    /// assert_eq!(config.remote_max_in_flight, 100);
    /// assert_eq!(config.bulkhead_retry_after_ms, 20);
    /// ```
    #[must_use]
    pub fn legacy_defaults() -> Self {
        Self {
            preferred: PreferredRuntime::Auto,
            remote_max_in_flight: 100,
            bulkhead_retry_after_ms: 20,
            lanes: default_runtime_lanes(
                RuntimeLaneConfig::new(20, 80, 48, 25, LaneOverflowPolicy::Reject),
                RuntimeLaneConfig::new(28, 60, 64, 50, LaneOverflowPolicy::EnqueueWithTimeout),
                RuntimeLaneConfig::new(40, 40, 96, 75, LaneOverflowPolicy::EnqueueWithTimeout),
                RuntimeLaneConfig::new(16, 20, 128, 100, LaneOverflowPolicy::ShedOldest),
            ),
            drain_timeout_ms: None,
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
    /// Maximum number of concurrent tasks that can execute in this lane.
    ///
    /// Controls the parallelism level for the lane. Higher values allow more
    /// concurrent execution but consume more resources. Typical range: 4-16.
    /// Default varies by lane type (e.g., 8 for high-priority, 4 for background).
    pub max_concurrent: usize,

    /// Priority weight for scheduler lane ordering.
    ///
    /// Higher values get scheduled before lower values when multiple lanes have
    /// pending tasks. Used for proportional scheduling algorithms.
    /// Typical range: 20-100, where 100 = highest priority, 20 = background.
    pub priority_weight: u32,

    /// Maximum number of tasks that can be queued in this lane.
    ///
    /// When this limit is reached, the overflow_policy determines behavior.
    /// Higher values provide more buffering but consume more memory.
    /// Typical range: 16-32 depending on lane priority and expected load.
    pub queue_limit: usize,

    /// Timeout in milliseconds for enqueue operations when using EnqueueWithTimeout policy.
    ///
    /// Maximum time to wait when trying to enqueue a task in a full lane.
    /// Only applies when overflow_policy is EnqueueWithTimeout.
    /// Typical range: 25-100ms, with lower values for high-priority lanes.
    pub enqueue_timeout_ms: u64,

    /// Policy for handling queue overflow when queue_limit is exceeded.
    ///
    /// - Reject: Immediately reject new tasks when queue is full
    /// - EnqueueWithTimeout: Wait up to enqueue_timeout_ms for space
    /// - ShedOldest: Remove oldest queued task to make room for new one
    pub overflow_policy: LaneOverflowPolicy,
}

impl RuntimeLaneConfig {
    /// Create a runtime lane configuration.
    ///
    /// # Examples
    ///
    /// ```
    /// use frankenengine_node::config::{LaneOverflowPolicy, RuntimeLaneConfig};
    ///
    /// let lane = RuntimeLaneConfig::new(
    ///     8,
    ///     100,
    ///     32,
    ///     25,
    ///     LaneOverflowPolicy::EnqueueWithTimeout,
    /// );
    ///
    /// assert_eq!(lane.max_concurrent, 8);
    /// assert_eq!(lane.overflow_policy, LaneOverflowPolicy::EnqueueWithTimeout);
    /// ```
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

/// Policy for handling task queue overflow when a lane reaches its queue_limit.
///
/// Different policies provide trade-offs between throughput, latency, and
/// resource usage when the task scheduler becomes overloaded.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum LaneOverflowPolicy {
    /// Immediately reject new tasks when the queue is full.
    ///
    /// **Behavior:** New tasks fail immediately with an error.
    /// **Performance:** Fastest policy with no blocking or memory growth.
    /// **Use cases:** High-priority lanes where latency is critical,
    /// systems with external retry logic, or when backpressure is preferred.
    Reject,

    /// Wait up to enqueue_timeout_ms for space in the queue before rejecting.
    ///
    /// **Behavior:** Block new tasks briefly, hoping space becomes available.
    /// **Performance:** Moderate latency impact, may improve throughput.
    /// **Use cases:** Medium-priority lanes with bursty workloads,
    /// when brief delays are acceptable to avoid dropping tasks.
    EnqueueWithTimeout,

    /// Remove the oldest queued task to make room for the new one.
    ///
    /// **Behavior:** Always accepts new tasks by evicting old ones.
    /// **Performance:** Constant memory usage but may waste work on evicted tasks.
    /// **Use cases:** Background lanes, telemetry, or when newer tasks
    /// are more valuable than older ones (time-sensitive data).
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

// -- Thresholds --

const DEFAULT_THRESHOLD_MAX_FAILURE_RATE: f64 = 0.05;
const DEFAULT_THRESHOLD_MIN_QUALITY_SCORE: f64 = 0.8;
const DEFAULT_THRESHOLD_MAX_VARIANCE_PCT: f64 = 5.0;
const DEFAULT_THRESHOLD_REGRESSION_THRESHOLD_PCT: f64 = 10.0;
const DEFAULT_THRESHOLD_MIN_RESILIENCE_SCORE: f64 = 0.7;

/// Algorithmic and statistical threshold constants that don't fit in a
/// specific section. All fields are optional; when `None` consumers fall
/// back to their compile-time defaults.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct ThresholdsConfig {
    /// Maximum tolerated failed-attempt ratio before a gate, rollout, or
    /// quality check should report unhealthy behavior.
    ///
    /// **Valid range:** finite value in `[0.0, 1.0]`, where `0.0` means no
    /// failures are tolerated and `1.0` means every attempt may fail before
    /// this threshold alone rejects the sample.
    ///
    /// **Default:** when `None`, consumers use
    /// `DEFAULT_THRESHOLD_MAX_FAILURE_RATE` (`0.05`, or 5% failures).
    ///
    /// **Tuning impact:** lower values make canary, migration, and
    /// verifier-style gates stricter and surface reliability regressions
    /// sooner. Higher values reduce false positives for noisy experiments but
    /// can mask real instability.
    ///
    /// **Use cases:** set near `0.0` for strict release validation or
    /// security-sensitive proof checks; relax toward `0.10` for exploratory
    /// benchmarks, load tests, or temporary degraded-mode telemetry.
    ///
    /// **Relationships:** this is an upper bound and should move opposite to
    /// `min_quality_score` and `min_resilience_score`. If you raise
    /// `max_failure_rate`, consider raising the score thresholds or adding
    /// extra evidence gates so a high failure budget does not also admit
    /// low-quality results.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_failure_rate: Option<f64>,

    /// Minimum aggregate quality score required for accepting a candidate
    /// result, migration output, or policy decision.
    ///
    /// **Valid range:** finite value in `[0.0, 1.0]`, where `0.0` accepts any
    /// quality score and `1.0` requires a perfect quality score.
    ///
    /// **Default:** when `None`, consumers use
    /// `DEFAULT_THRESHOLD_MIN_QUALITY_SCORE` (`0.8`).
    ///
    /// **Tuning impact:** higher values force higher correctness, coverage, or
    /// confidence before acceptance. Lower values improve throughput for early
    /// experiments but increase the chance that weak evidence passes.
    ///
    /// **Use cases:** use `0.90` or higher for release, trust, and replay
    /// conformance surfaces; use lower values only for local discovery runs or
    /// workloads that have an independent downstream validation step.
    ///
    /// **Relationships:** this is a lower bound. It should usually be at least
    /// as strict as `min_resilience_score` when quality is the primary safety
    /// signal, and it should be tightened when `max_failure_rate` or
    /// `max_variance_pct` is relaxed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_quality_score: Option<f64>,

    /// Maximum accepted run-to-run variance percentage before a measurement is
    /// considered too noisy for a stable decision.
    ///
    /// **Valid range:** finite value in `[0.0, 100.0]`, expressed as percent.
    /// `0.0` requires identical measurements, while `100.0` accepts variance
    /// equal to the full measured baseline.
    ///
    /// **Default:** when `None`, consumers use
    /// `DEFAULT_THRESHOLD_MAX_VARIANCE_PCT` (`5.0`).
    ///
    /// **Tuning impact:** lower values make benchmark and quality gates more
    /// reproducible but may reject legitimate workloads with natural jitter.
    /// Higher values keep noisy environments moving but reduce the confidence
    /// of regression and quality decisions.
    ///
    /// **Use cases:** keep low for deterministic replay, proof, and
    /// performance baselines; relax for heterogeneous fleet measurements,
    /// cold-cache warmups, or hardware-dependent experiments.
    ///
    /// **Relationships:** this is the noise envelope used before interpreting
    /// `regression_threshold_pct`. In normal profiles it should remain below
    /// the regression threshold so measurement noise does not consume the
    /// entire regression budget.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_variance_pct: Option<f64>,

    /// Minimum percentage change that should be classified as a regression
    /// rather than tolerated drift.
    ///
    /// **Valid range:** finite value in `[0.0, 100.0]`, expressed as percent.
    /// `0.0` marks any measurable negative movement as a regression, while
    /// `100.0` only marks changes as large as the whole baseline.
    ///
    /// **Default:** when `None`, consumers use
    /// `DEFAULT_THRESHOLD_REGRESSION_THRESHOLD_PCT` (`10.0`).
    ///
    /// **Tuning impact:** lower values catch small performance, quality, or
    /// resilience regressions earlier but can be noisy. Higher values suppress
    /// small regressions and should be reserved for unstable exploratory data.
    ///
    /// **Use cases:** use tight values for release gates, replay determinism,
    /// and proof-service baselines; use wider values for canary exploration or
    /// workloads where confidence is dominated by external variance.
    ///
    /// **Relationships:** this should normally exceed `max_variance_pct` so a
    /// regression signal is larger than accepted measurement noise. If it is
    /// set close to or below `max_variance_pct`, require additional evidence
    /// before automatically blocking a rollout.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub regression_threshold_pct: Option<f64>,

    /// Minimum resilience score required before a system, lane, or fleet
    /// surface should be treated as healthy under stress or degraded inputs.
    ///
    /// **Valid range:** finite value in `[0.0, 1.0]`, where `0.0` accepts any
    /// resilience score and `1.0` requires perfect resilience evidence.
    ///
    /// **Default:** when `None`, consumers use
    /// `DEFAULT_THRESHOLD_MIN_RESILIENCE_SCORE` (`0.7`).
    ///
    /// **Tuning impact:** higher values make failover, quarantine, replay, and
    /// control-plane checks more conservative. Lower values keep degraded
    /// systems available longer but increase the risk of masking fragility.
    ///
    /// **Use cases:** raise for production fleet health, release decisions,
    /// and security-sensitive runtime surfaces; lower only for local testing,
    /// bootstrap scenarios, or explicitly degraded profiles with operator
    /// visibility.
    ///
    /// **Relationships:** this complements `min_quality_score`: quality
    /// describes correctness of the current result, while resilience describes
    /// behavior under stress. Tighten this threshold when `max_failure_rate` is
    /// relaxed, and avoid setting it far below `min_quality_score` for
    /// production profiles.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_resilience_score: Option<f64>,
}

impl ThresholdsConfig {
    /// Return the compile-time default threshold values.
    ///
    /// # Examples
    ///
    /// ```
    /// use frankenengine_node::config::ThresholdsConfig;
    ///
    /// let defaults = ThresholdsConfig::default_values();
    /// assert_eq!(defaults.max_failure_rate, Some(0.05));
    /// assert_eq!(defaults.min_quality_score, Some(0.8));
    /// ```
    #[must_use]
    pub const fn default_values() -> Self {
        Self {
            max_failure_rate: Some(DEFAULT_THRESHOLD_MAX_FAILURE_RATE),
            min_quality_score: Some(DEFAULT_THRESHOLD_MIN_QUALITY_SCORE),
            max_variance_pct: Some(DEFAULT_THRESHOLD_MAX_VARIANCE_PCT),
            regression_threshold_pct: Some(DEFAULT_THRESHOLD_REGRESSION_THRESHOLD_PCT),
            min_resilience_score: Some(DEFAULT_THRESHOLD_MIN_RESILIENCE_SCORE),
        }
    }
}

// -- Benchmark Configuration --

/// Configuration for category shift benchmark gate thresholds and paths.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BenchmarkConfig {
    /// Path to the benchmark summary JSON file.
    ///
    /// **Default:** `artifacts/category_shift/latest_benchmark_summary.json`
    #[serde(default = "default_benchmark_summary_path")]
    pub summary_path: String,

    /// Minimum aggregate score required to pass the benchmark gate.
    ///
    /// **Valid range:** any u32 value, typically 0-100.
    /// **Default:** 70
    #[serde(default = "default_min_aggregate_score")]
    pub min_aggregate_score: u32,

    /// Maximum acceptable latency in milliseconds.
    ///
    /// **Valid range:** any finite positive f64 value.
    /// **Default:** 500.0
    #[serde(default = "default_max_latency_ms")]
    pub max_latency_ms: f64,

    /// Minimum required throughput in operations per second.
    ///
    /// **Valid range:** any u64 value.
    /// **Default:** 50000
    #[serde(default = "default_min_throughput_ops")]
    pub min_throughput_ops: u64,
}

// -- Verifier --

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VerifierConfig {
    /// Maximum number of claims per verification request to prevent DoS via unbounded growth.
    #[serde(default = "default_max_claims_per_request")]
    pub max_claims_per_request: usize,
    /// Maximum replay capsule records/properties accepted by the verifier SDK.
    #[serde(default = "default_max_capsule_count")]
    pub max_capsule_count: usize,
    /// Maximum verification reports accepted in a chain verification request.
    #[serde(default = "default_max_chain_depth")]
    pub max_chain_depth: usize,
}

fn default_max_claims_per_request() -> usize {
    1000
}

fn default_max_capsule_count() -> usize {
    1000
}

fn default_max_chain_depth() -> usize {
    64
}

fn default_benchmark_summary_path() -> String {
    "artifacts/category_shift/latest_benchmark_summary.json".to_string()
}

fn default_min_aggregate_score() -> u32 {
    70
}

fn default_max_latency_ms() -> f64 {
    500.0
}

fn default_min_throughput_ops() -> u64 {
    50000
}

impl Default for BenchmarkConfig {
    fn default() -> Self {
        Self {
            summary_path: default_benchmark_summary_path(),
            min_aggregate_score: default_min_aggregate_score(),
            max_latency_ms: default_max_latency_ms(),
            min_throughput_ops: default_min_throughput_ops(),
        }
    }
}

// -- Errors --

/// Errors that can occur during configuration loading, parsing, and validation.
///
/// Each error provides specific context about the failure to help with debugging
/// and resolution. Most errors include file paths or values that caused the issue.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// Failed to read a configuration file from disk.
    ///
    /// **When it occurs:** File doesn't exist, permission denied, or I/O error.
    /// **Common causes:** Missing franken_node.toml, incorrect file permissions, disk issues.
    /// **Resolution:** Check file exists, verify permissions, ensure disk is accessible.
    #[error("failed to read config file {0}: {1}")]
    ReadFailed(PathBuf, std::io::Error),

    /// Failed to parse TOML configuration file syntax.
    ///
    /// **When it occurs:** Invalid TOML syntax, type mismatches, or unknown fields.
    /// **Common causes:** Syntax errors, wrong data types, typos in field names.
    /// **Resolution:** Validate TOML syntax, check field names against documentation.
    #[error("failed to parse config file {0}: {1}")]
    ParseFailed(PathBuf, toml::de::Error),

    /// Failed to serialize configuration to TOML format.
    ///
    /// **When it occurs:** Attempting to save config with non-serializable values.
    /// **Common causes:** Internal error during config export or default generation.
    /// **Resolution:** Report as bug; config structure may be corrupted.
    #[error("failed to serialize config: {0}")]
    SerializeFailed(toml::ser::Error),

    /// Invalid runtime profile name specified.
    ///
    /// **When it occurs:** Unknown profile in CLI args or config file.
    /// **Common causes:** Typos like "strict-mode" instead of "strict".
    /// **Resolution:** Use one of: strict, balanced, legacy-risky.
    #[error("invalid profile: {0} (expected: strict, balanced, legacy-risky)")]
    InvalidProfile(String),

    /// Invalid compatibility mode specified.
    ///
    /// **When it occurs:** Unknown mode in compatibility config section.
    /// **Common causes:** Typos or using profile names instead of mode names.
    /// **Resolution:** Use one of: strict, balanced, legacy-risky.
    #[error("invalid compatibility mode: {0} (expected: strict, balanced, legacy-risky)")]
    InvalidCompatibilityMode(String),

    /// Invalid preferred runtime specified.
    ///
    /// **When it occurs:** Unknown runtime in runtime config section.
    /// **Common causes:** Typos like "nodejs" instead of "node".
    /// **Resolution:** Use one of: auto, node, bun, franken-engine.
    #[error("invalid preferred runtime: {0} (expected: auto, node, bun, franken-engine)")]
    InvalidPreferredRuntime(String),

    /// Failed to parse environment variable override.
    ///
    /// **When it occurs:** Invalid format in environment variable for config override.
    /// **Common causes:** Wrong data type, malformed JSON, missing quotes.
    /// **Resolution:** Check environment variable syntax matches expected type.
    #[error("environment override parse error for {key}=`{value}`: {reason}")]
    EnvParseFailed {
        key: String,
        value: String,
        reason: String,
    },

    /// Configuration failed semantic validation.
    ///
    /// **When it occurs:** Config is syntactically valid but logically inconsistent.
    /// **Common causes:** Invalid ranges, conflicting settings, missing dependencies.
    /// **Resolution:** Check value ranges and setting combinations in error message.
    #[error("config validation failed: {0}")]
    ValidationFailed(String),
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use base64::Engine as _;

    use super::*;

    fn test_registry_signing_key() -> String {
        base64::engine::general_purpose::STANDARD.encode([0xC7_u8; 32])
    }

    fn map_lookup(map: BTreeMap<String, String>) -> impl Fn(&str) -> Option<String> {
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
        assert_eq!(config.fleet.state_dir, None);
        assert_eq!(config.compatibility.default_receipt_ttl_secs, 3_600);
        assert_eq!(config.replay.max_replay_capsule_freshness_secs, 3_600);
        assert_eq!(config.remote.idempotency_ttl_secs, 604_800);
        assert_eq!(config.security.max_degraded_duration_secs, 3_600);
        assert_eq!(
            config.security.max_merge_decisions,
            DEFAULT_MAX_MERGE_DECISIONS
        );
        assert_eq!(config.engine.binary_path, None);
        assert_eq!(config.runtime.preferred, PreferredRuntime::Auto);
        assert_eq!(config.runtime.remote_max_in_flight, 50);
        assert_eq!(config.runtime.bulkhead_retry_after_ms, 50);
        assert_eq!(config.runtime.lanes.len(), 4);
        assert_eq!(config.trust.registry_signing_key, None);
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
    fn profile_defaults_do_not_embed_registry_signing_key() {
        for profile in [Profile::Strict, Profile::Balanced, Profile::LegacyRisky] {
            let config = Config::for_profile(profile);
            assert_eq!(config.trust.registry_signing_key, None);
            assert!(
                config
                    .validate()
                    .unwrap_err()
                    .to_string()
                    .contains("trust.registry_signing_key must be configured")
            );
        }
    }

    #[test]
    fn roundtrip_toml_serialization() {
        let mut config = Config::for_profile(Profile::Balanced);
        config.trust.registry_signing_key = Some(test_registry_signing_key());
        config.engine.binary_path = Some(PathBuf::from("/opt/franken-engine"));
        config.fleet.state_dir = Some(PathBuf::from(".franken-node/state/fleet"));
        config.fleet.node_id = Some("node-balanced-1".to_string());
        config.fleet.poll_interval_seconds = Some(15);
        config.registry.builder_identity = Some("builder.example.internal".to_string());
        config.security.authorized_api_keys =
            BTreeSet::from(["alpha-key".to_string(), "beta-key".to_string()]);
        let toml_str = config.to_toml().expect("serialize");
        let parsed: Config = toml::from_str(&toml_str).expect("deserialize");
        assert_eq!(parsed.profile, Profile::Balanced);
        assert_eq!(parsed.engine.binary_path, config.engine.binary_path);
        assert_eq!(parsed.fleet.state_dir, config.fleet.state_dir);
        assert_eq!(parsed.fleet.node_id, config.fleet.node_id);
        assert_eq!(
            parsed.trust.registry_signing_key,
            config.trust.registry_signing_key
        );
        assert_eq!(
            parsed.fleet.poll_interval_seconds,
            config.fleet.poll_interval_seconds
        );
        assert_eq!(
            parsed.registry.builder_identity,
            config.registry.builder_identity
        );
        assert_eq!(
            parsed.registry.minimum_assurance_level,
            config.registry.minimum_assurance_level
        );
        assert_eq!(
            parsed.compatibility.default_receipt_ttl_secs,
            config.compatibility.default_receipt_ttl_secs
        );
        assert_eq!(
            parsed.replay.max_replay_capsule_freshness_secs,
            config.replay.max_replay_capsule_freshness_secs
        );
        assert_eq!(
            parsed.remote.idempotency_ttl_secs,
            config.remote.idempotency_ttl_secs
        );
        assert_eq!(
            parsed.security.max_degraded_duration_secs,
            config.security.max_degraded_duration_secs
        );
        assert_eq!(
            parsed.security.authorized_api_keys,
            config.security.authorized_api_keys
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

        let env = BTreeMap::from([("FRANKEN_NODE_PROFILE".to_string(), "strict".to_string())]);

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

        let env = BTreeMap::from([
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
    fn profile_parsing_rejects_invalid_values_with_no_fallback() {
        // bd-83lv0: Test that invalid profile values are hard-rejected with no silent fallback
        let invalid_profiles = [
            "invalid",
            "INVALID",
            "garbage",
            "",
            " ",
            "strictt",
            "balancced",
            "legacy",
            "risky",
            "strict ",
            " balanced",
            "strict-risky",
            "null",
            "undefined",
            "default",
            "auto",
            "999",
            "true",
            "false",
            "../../../etc/passwd",
            "<script>alert(1)</script>",
            "\0",
            "\n\r",
        ];

        for invalid in invalid_profiles {
            let result = invalid.parse::<Profile>();
            assert!(
                result.is_err(),
                "Profile '{}' should be rejected but was accepted: {:?}",
                invalid,
                result
            );

            if let Err(err) = result {
                let err_msg = err.to_string();
                assert!(
                    err_msg.contains("Invalid profile") && err_msg.contains("No fallback"),
                    "Error message for '{}' should mention 'Invalid profile' and 'No fallback': {}",
                    invalid,
                    err_msg
                );
            }
        }

        // Verify valid profiles still work
        let valid_profiles = [
            ("strict", Profile::Strict),
            ("balanced", Profile::Balanced),
            ("legacy-risky", Profile::LegacyRisky),
            ("STRICT", Profile::Strict), // Case normalization
            ("Balanced", Profile::Balanced),
            ("Legacy_Risky", Profile::LegacyRisky), // Underscore normalization
        ];

        for (input, expected) in valid_profiles {
            let result = input.parse::<Profile>();
            assert_eq!(
                result.unwrap(),
                expected,
                "Valid profile '{}' should parse to {:?}",
                input,
                expected
            );
        }
    }

    #[test]
    fn resolve_applies_trust_score_and_threshold_file_profile_overrides() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("franken_node.toml");
        std::fs::write(
            &path,
            r#"
profile = "balanced"

[trust]
min_trust_score = 0.61
decay_factor = 0.91

[thresholds]
max_failure_rate = 0.04
min_quality_score = 0.82

[profiles.strict.trust]
min_trust_score = 0.72
decay_factor = 0.88

[profiles.strict.thresholds]
max_failure_rate = 0.02
min_resilience_score = 0.77
"#,
        )
        .unwrap();

        let env = BTreeMap::from([("FRANKEN_NODE_PROFILE".to_string(), "strict".to_string())]);

        let resolved =
            Config::resolve_with_env(Some(&path), CliOverrides::default(), &map_lookup(env))
                .unwrap();

        assert_eq!(resolved.config.profile, Profile::Strict);
        assert_eq!(resolved.config.trust.min_trust_score, Some(0.72));
        assert_eq!(resolved.config.trust.decay_factor, Some(0.88));
        assert_eq!(resolved.config.thresholds.max_failure_rate, Some(0.02));
        assert_eq!(resolved.config.thresholds.min_quality_score, Some(0.82));
        assert_eq!(resolved.config.thresholds.min_resilience_score, Some(0.77));
        assert!(resolved.decisions.iter().any(|decision| {
            decision.field == "trust.min_trust_score" && decision.stage == MergeStage::Profile
        }));
        assert!(resolved.decisions.iter().any(|decision| {
            decision.field == "thresholds.max_failure_rate" && decision.stage == MergeStage::Profile
        }));
    }

    #[test]
    fn resolve_applies_benchmark_file_profile_and_env_overrides() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("franken_node.toml");
        std::fs::write(
            &path,
            r#"
profile = "balanced"

[benchmark]
summary_path = "artifacts/category_shift/file_summary.json"
min_aggregate_score = 72
max_latency_ms = 450.0
min_throughput_ops = 80000

[profiles.strict.benchmark]
summary_path = "artifacts/category_shift/profile_summary.json"
min_aggregate_score = 88
min_throughput_ops = 120000
"#,
        )
        .unwrap();

        let env = BTreeMap::from([
            ("FRANKEN_NODE_PROFILE".to_string(), "strict".to_string()),
            (
                "FRANKEN_NODE_BENCHMARK_MAX_LATENCY_MS".to_string(),
                "175.5".to_string(),
            ),
        ]);

        let resolved =
            Config::resolve_with_env(Some(&path), CliOverrides::default(), &map_lookup(env))
                .unwrap();

        assert_eq!(resolved.config.profile, Profile::Strict);
        assert_eq!(
            resolved.config.benchmark.summary_path,
            "artifacts/category_shift/profile_summary.json"
        );
        assert_eq!(resolved.config.benchmark.min_aggregate_score, 88);
        assert_eq!(resolved.config.benchmark.max_latency_ms, 175.5);
        assert_eq!(resolved.config.benchmark.min_throughput_ops, 120000);
        assert!(resolved.decisions.iter().any(|decision| {
            decision.field == "benchmark.summary_path" && decision.stage == MergeStage::File
        }));
        assert!(resolved.decisions.iter().any(|decision| {
            decision.field == "benchmark.summary_path" && decision.stage == MergeStage::Profile
        }));
        assert!(resolved.decisions.iter().any(|decision| {
            decision.field == "benchmark.max_latency_ms" && decision.stage == MergeStage::Env
        }));
    }

    #[test]
    fn resolve_applies_benchmark_env_overrides() {
        let env = BTreeMap::from([
            (
                "FRANKEN_NODE_BENCHMARK_SUMMARY_PATH".to_string(),
                "artifacts/category_shift/env_summary.json".to_string(),
            ),
            (
                "FRANKEN_NODE_BENCHMARK_MIN_AGGREGATE_SCORE".to_string(),
                "91".to_string(),
            ),
            (
                "FRANKEN_NODE_BENCHMARK_MAX_LATENCY_MS".to_string(),
                "95.25".to_string(),
            ),
            (
                "FRANKEN_NODE_BENCHMARK_MIN_THROUGHPUT_OPS".to_string(),
                "250000".to_string(),
            ),
        ]);

        let resolved =
            Config::resolve_with_env(None, CliOverrides::default(), &map_lookup(env)).unwrap();

        assert_eq!(
            resolved.config.benchmark.summary_path,
            "artifacts/category_shift/env_summary.json"
        );
        assert_eq!(resolved.config.benchmark.min_aggregate_score, 91);
        assert_eq!(resolved.config.benchmark.max_latency_ms, 95.25);
        assert_eq!(resolved.config.benchmark.min_throughput_ops, 250000);
        assert!(resolved.decisions.iter().any(|decision| {
            decision.field == "benchmark.min_throughput_ops" && decision.stage == MergeStage::Env
        }));
    }

    #[test]
    fn resolve_applies_verifier_file_profile_and_env_overrides() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("franken_node.toml");
        std::fs::write(
            &path,
            r#"
profile = "balanced"

[verifier]
max_claims_per_request = 101
max_capsule_count = 202
max_chain_depth = 33

[profiles.strict.verifier]
max_capsule_count = 303
max_chain_depth = 44
"#,
        )
        .unwrap();

        let env = BTreeMap::from([
            ("FRANKEN_NODE_PROFILE".to_string(), "strict".to_string()),
            (
                "FRANKEN_NODE_VERIFIER_MAX_CLAIMS_PER_REQUEST".to_string(),
                "404".to_string(),
            ),
        ]);

        let resolved =
            Config::resolve_with_env(Some(&path), CliOverrides::default(), &map_lookup(env))
                .unwrap();

        assert_eq!(resolved.config.profile, Profile::Strict);
        assert_eq!(resolved.config.verifier.max_claims_per_request, 404);
        assert_eq!(resolved.config.verifier.max_capsule_count, 303);
        assert_eq!(resolved.config.verifier.max_chain_depth, 44);
        assert!(resolved.decisions.iter().any(|decision| {
            decision.field == "verifier.max_capsule_count" && decision.stage == MergeStage::Profile
        }));
        assert!(resolved.decisions.iter().any(|decision| {
            decision.field == "verifier.max_claims_per_request" && decision.stage == MergeStage::Env
        }));
    }

    #[test]
    fn resolve_rejects_invalid_env_bool() {
        let env = BTreeMap::from([(
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
            &map_lookup(BTreeMap::new()),
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
preferred = "bun"
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
            &map_lookup(BTreeMap::new()),
        )
        .unwrap();

        assert_eq!(resolved.config.runtime.preferred, PreferredRuntime::Bun);
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
    fn resolve_honors_configured_merge_decision_cap() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("franken_node.toml");
        std::fs::write(
            &path,
            r#"
[security]
max_merge_decisions = 2

[runtime]
preferred = "bun"
remote_max_in_flight = 77
bulkhead_retry_after_ms = 33
"#,
        )
        .unwrap();

        let resolved = Config::resolve_with_env(
            Some(&path),
            CliOverrides::default(),
            &map_lookup(BTreeMap::new()),
        )
        .unwrap();

        assert_eq!(resolved.config.security.max_merge_decisions, 2);
        assert_eq!(resolved.decisions.len(), 2);
        let retained_fields: Vec<&str> = resolved
            .decisions
            .iter()
            .map(|decision| decision.field.as_str())
            .collect();
        assert_eq!(
            retained_fields,
            vec![
                "runtime.remote_max_in_flight",
                "runtime.bulkhead_retry_after_ms"
            ]
        );
    }

    #[test]
    fn resolve_applies_runtime_env_overrides() {
        let env = BTreeMap::from([
            (
                "FRANKEN_NODE_RUNTIME_PREFERRED".to_string(),
                "node".to_string(),
            ),
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

        assert_eq!(resolved.config.runtime.preferred, PreferredRuntime::Node);
        assert_eq!(resolved.config.runtime.remote_max_in_flight, 66);
        assert_eq!(resolved.config.runtime.bulkhead_retry_after_ms, 17);
    }

    #[test]
    fn resolve_applies_trust_score_env_overrides() {
        let env = BTreeMap::from([
            (
                "FRANKEN_NODE_TRUST_MIN_TRUST_SCORE".to_string(),
                "0.66".to_string(),
            ),
            (
                "FRANKEN_NODE_TRUST_DECAY_FACTOR".to_string(),
                "0.93".to_string(),
            ),
        ]);

        let resolved =
            Config::resolve_with_env(None, CliOverrides::default(), &map_lookup(env)).unwrap();

        assert_eq!(resolved.config.trust.min_trust_score, Some(0.66));
        assert_eq!(resolved.config.trust.decay_factor, Some(0.93));
        assert!(resolved.decisions.iter().any(|decision| {
            decision.field == "trust.min_trust_score" && decision.stage == MergeStage::Env
        }));
        assert!(resolved.decisions.iter().any(|decision| {
            decision.field == "trust.decay_factor" && decision.stage == MergeStage::Env
        }));
    }

    #[test]
    fn resolve_accepts_explicit_registry_signing_key_file_override() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("franken_node.toml");
        let key = test_registry_signing_key();
        std::fs::write(
            &path,
            format!(
                r#"
[trust]
registry_signing_key = "{key}"
"#
            ),
        )
        .unwrap();

        let resolved = Config::resolve_with_env(
            Some(&path),
            CliOverrides::default(),
            &map_lookup(BTreeMap::new()),
        )
        .unwrap();

        assert_eq!(resolved.config.trust.registry_signing_key, Some(key));
        assert!(resolved.decisions.iter().any(|decision| {
            decision.field == "trust.registry_signing_key" && decision.stage == MergeStage::File
        }));
    }

    #[test]
    fn resolve_accepts_explicit_registry_signing_key_env_override() {
        let key = test_registry_signing_key();
        let env = BTreeMap::from([(
            "FRANKEN_NODE_TRUST_REGISTRY_SIGNING_KEY".to_string(),
            key.clone(),
        )]);

        let resolved =
            Config::resolve_with_env(None, CliOverrides::default(), &map_lookup(env)).unwrap();

        assert_eq!(resolved.config.trust.registry_signing_key, Some(key));
        assert!(resolved.decisions.iter().any(|decision| {
            decision.field == "trust.registry_signing_key" && decision.stage == MergeStage::Env
        }));
    }

    #[test]
    fn resolve_applies_timeout_and_ttl_file_and_env_overrides() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("franken_node.toml");
        std::fs::write(
            &path,
            r#"
[compatibility]
default_receipt_ttl_secs = 7200

[replay]
max_replay_capsule_freshness_secs = 5400

[remote]
idempotency_ttl_secs = 86400

[security]
max_degraded_duration_secs = 900
"#,
        )
        .unwrap();

        let env = BTreeMap::from([
            (
                "FRANKEN_NODE_REPLAY_MAX_REPLAY_CAPSULE_FRESHNESS_SECS".to_string(),
                "600".to_string(),
            ),
            (
                "FRANKEN_NODE_REMOTE_IDEMPOTENCY_TTL_SECS".to_string(),
                "43200".to_string(),
            ),
        ]);

        let resolved =
            Config::resolve_with_env(Some(&path), CliOverrides::default(), &map_lookup(env))
                .unwrap();

        assert_eq!(resolved.config.compatibility.default_receipt_ttl_secs, 7200);
        assert_eq!(
            resolved.config.replay.max_replay_capsule_freshness_secs,
            600
        );
        assert_eq!(resolved.config.remote.idempotency_ttl_secs, 43_200);
        assert_eq!(resolved.config.security.max_degraded_duration_secs, 900);
        assert!(resolved.decisions.iter().any(|decision| {
            decision.field == "remote.idempotency_ttl_secs" && decision.stage == MergeStage::Env
        }));
    }

    #[test]
    fn resolve_accepts_serialized_security_authorized_api_keys() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("franken_node.toml");
        let mut config = Config::for_profile(Profile::Balanced);
        config.trust.registry_signing_key = Some(test_registry_signing_key());
        config.security.authorized_api_keys =
            BTreeSet::from(["alpha-key".to_string(), "beta-key".to_string()]);
        std::fs::write(&path, config.to_toml().unwrap()).unwrap();

        let resolved = Config::resolve_with_env(
            Some(&path),
            CliOverrides::default(),
            &map_lookup(BTreeMap::new()),
        )
        .unwrap();

        assert_eq!(
            resolved.config.security.authorized_api_keys,
            config.security.authorized_api_keys
        );
        assert!(resolved.decisions.iter().any(|decision| {
            decision.field == "security.authorized_api_keys" && decision.stage == MergeStage::File
        }));
    }

    #[test]
    fn resolve_applies_engine_file_and_env_overrides() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("franken_node.toml");
        std::fs::write(
            &path,
            r#"
[engine]
binary_path = "/opt/from-file/franken-engine"
"#,
        )
        .unwrap();

        let env = BTreeMap::from([(
            "FRANKEN_NODE_ENGINE_BINARY_PATH".to_string(),
            "/opt/from-env/franken-engine".to_string(),
        )]);

        let resolved =
            Config::resolve_with_env(Some(&path), CliOverrides::default(), &map_lookup(env))
                .unwrap();

        assert_eq!(
            resolved.config.engine.binary_path,
            Some(PathBuf::from("/opt/from-env/franken-engine"))
        );
        assert!(resolved.decisions.iter().any(|decision| {
            decision.field == "engine.binary_path" && decision.stage == MergeStage::File
        }));
        assert!(resolved.decisions.iter().any(|decision| {
            decision.field == "engine.binary_path" && decision.stage == MergeStage::Env
        }));
    }

    #[test]
    fn resolve_applies_fleet_state_dir_file_and_env_overrides() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("franken_node.toml");
        std::fs::write(
            &path,
            r#"
[fleet]
state_dir = "from-file/fleet"
"#,
        )
        .unwrap();

        let env = BTreeMap::from([(
            "FRANKEN_NODE_FLEET_STATE_DIR".to_string(),
            "/tmp/from-env/fleet".to_string(),
        )]);

        let resolved =
            Config::resolve_with_env(Some(&path), CliOverrides::default(), &map_lookup(env))
                .unwrap();

        assert_eq!(
            resolved.config.fleet.state_dir,
            Some(PathBuf::from("/tmp/from-env/fleet"))
        );
        assert!(resolved.decisions.iter().any(|decision| {
            decision.field == "fleet.state_dir" && decision.stage == MergeStage::File
        }));
        assert!(resolved.decisions.iter().any(|decision| {
            decision.field == "fleet.state_dir" && decision.stage == MergeStage::Env
        }));
    }

    #[test]
    fn resolve_applies_fleet_agent_file_and_env_overrides() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("franken_node.toml");
        std::fs::write(
            &path,
            r#"
[fleet]
node_id = "node-from-file"
poll_interval_seconds = 12
"#,
        )
        .unwrap();

        let env = BTreeMap::from([
            (
                "FRANKEN_NODE_FLEET_NODE_ID".to_string(),
                "node-from-env".to_string(),
            ),
            (
                "FRANKEN_NODE_FLEET_POLL_INTERVAL_SECONDS".to_string(),
                "30".to_string(),
            ),
        ]);

        let resolved =
            Config::resolve_with_env(Some(&path), CliOverrides::default(), &map_lookup(env))
                .unwrap();

        assert_eq!(
            resolved.config.fleet.node_id,
            Some("node-from-env".to_string())
        );
        assert_eq!(resolved.config.fleet.poll_interval_seconds, Some(30));
        assert!(resolved.decisions.iter().any(|decision| {
            decision.field == "fleet.node_id" && decision.stage == MergeStage::File
        }));
        assert!(resolved.decisions.iter().any(|decision| {
            decision.field == "fleet.node_id" && decision.stage == MergeStage::Env
        }));
        assert!(resolved.decisions.iter().any(|decision| {
            decision.field == "fleet.poll_interval_seconds" && decision.stage == MergeStage::Env
        }));
    }

    #[test]
    fn resolve_applies_registry_builder_identity_file_and_env_overrides() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("franken_node.toml");
        std::fs::write(
            &path,
            r#"
[registry]
builder_identity = "builder-from-file"
"#,
        )
        .unwrap();

        let env = BTreeMap::from([(
            "FRANKEN_NODE_BUILDER_ID".to_string(),
            "builder-from-env".to_string(),
        )]);

        let resolved =
            Config::resolve_with_env(Some(&path), CliOverrides::default(), &map_lookup(env))
                .unwrap();

        assert_eq!(
            resolved.config.registry.builder_identity.as_deref(),
            Some("builder-from-env")
        );
        assert!(resolved.decisions.iter().any(|decision| {
            decision.field == "registry.builder_identity" && decision.stage == MergeStage::File
        }));
        assert!(resolved.decisions.iter().any(|decision| {
            decision.field == "registry.builder_identity" && decision.stage == MergeStage::Env
        }));
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
            &map_lookup(BTreeMap::new()),
        )
        .unwrap_err();
        assert!(err.to_string().contains("minimum_assurance_level"));
    }

    #[test]
    fn validation_rejects_empty_engine_binary_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("franken_node.toml");
        std::fs::write(
            &path,
            r#"
[engine]
binary_path = ""
"#,
        )
        .unwrap();

        let err = Config::resolve_with_env(
            Some(&path),
            CliOverrides::default(),
            &map_lookup(BTreeMap::new()),
        )
        .unwrap_err();
        assert!(err.to_string().contains("engine.binary_path"));
    }

    #[test]
    fn validation_rejects_empty_registry_builder_identity() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("franken_node.toml");
        std::fs::write(
            &path,
            r#"
[registry]
builder_identity = "   "
"#,
        )
        .unwrap();

        let err = Config::resolve_with_env(
            Some(&path),
            CliOverrides::default(),
            &map_lookup(BTreeMap::new()),
        )
        .unwrap_err();
        assert!(err.to_string().contains("registry.builder_identity"));
    }

    #[test]
    fn validation_rejects_zero_timeout_ttl_overrides() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("franken_node.toml");
        std::fs::write(
            &path,
            r#"
[remote]
idempotency_ttl_secs = 0
"#,
        )
        .unwrap();

        let err = Config::resolve_with_env(
            Some(&path),
            CliOverrides::default(),
            &map_lookup(BTreeMap::new()),
        )
        .unwrap_err();
        assert!(err.to_string().contains("remote.idempotency_ttl_secs"));
    }

    #[test]
    fn validation_rejects_empty_fleet_state_dir() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("franken_node.toml");
        std::fs::write(
            &path,
            r#"
[fleet]
state_dir = ""
"#,
        )
        .unwrap();

        let err = Config::resolve_with_env(
            Some(&path),
            CliOverrides::default(),
            &map_lookup(BTreeMap::new()),
        )
        .unwrap_err();
        assert!(err.to_string().contains("fleet.state_dir"));
    }

    #[test]
    fn parse_env_bool_rejects_blank_string() {
        let err = parse_env_bool("FRANKEN_NODE_TEST_BOOL", "   ").unwrap_err();

        assert!(matches!(
            err,
            ConfigError::EnvParseFailed { ref key, .. } if key == "FRANKEN_NODE_TEST_BOOL"
        ));
    }

    #[test]
    fn parse_env_u8_rejects_overflowing_value() {
        let err = parse_env_u8("FRANKEN_NODE_ASSURANCE", "256").unwrap_err();

        assert!(matches!(
            err,
            ConfigError::EnvParseFailed { ref key, .. } if key == "FRANKEN_NODE_ASSURANCE"
        ));
    }

    #[test]
    fn parse_env_u64_rejects_negative_value() {
        let err = parse_env_u64("FRANKEN_NODE_TIMEOUT", "-1").unwrap_err();

        assert!(matches!(
            err,
            ConfigError::EnvParseFailed { ref key, .. } if key == "FRANKEN_NODE_TIMEOUT"
        ));
    }

    #[test]
    fn parse_env_f64_rejects_nan_and_infinity() {
        for raw in ["NaN", "inf", "-inf"] {
            let err = parse_env_f64("FRANKEN_NODE_SCORE", raw).unwrap_err();
            assert!(
                err.to_string().contains("value must be finite"),
                "{raw} should be rejected as non-finite"
            );
        }
    }

    #[test]
    fn parse_env_bool_rejects_numeric_and_decorated_values() {
        for raw in ["2", "truthy", "true,false", "on/off"] {
            let err = parse_env_bool("FRANKEN_NODE_TEST_BOOL", raw).unwrap_err();
            assert!(matches!(
                err,
                ConfigError::EnvParseFailed { ref key, .. } if key == "FRANKEN_NODE_TEST_BOOL"
            ));
        }
    }

    #[test]
    fn parse_env_u8_rejects_fractional_and_nonnumeric_values() {
        for raw in ["1.0", "ten", "0xff"] {
            let err = parse_env_u8("FRANKEN_NODE_ASSURANCE", raw).unwrap_err();
            assert!(matches!(
                err,
                ConfigError::EnvParseFailed { ref key, .. } if key == "FRANKEN_NODE_ASSURANCE"
            ));
        }
    }

    #[test]
    fn parse_env_usize_rejects_negative_fractional_and_unit_suffixed_values() {
        for raw in ["-1", "1.5", "100ms"] {
            let err = parse_env_usize("FRANKEN_NODE_LIMIT", raw).unwrap_err();
            assert!(matches!(
                err,
                ConfigError::EnvParseFailed { ref key, .. } if key == "FRANKEN_NODE_LIMIT"
            ));
        }
    }

    #[test]
    fn parse_env_f64_rejects_empty_hex_and_unit_suffixed_values() {
        for raw in ["", "0x1", "0.5s"] {
            let err = parse_env_f64("FRANKEN_NODE_SCORE", raw).unwrap_err();
            assert!(matches!(
                err,
                ConfigError::EnvParseFailed { ref key, .. } if key == "FRANKEN_NODE_SCORE"
            ));
        }
    }

    #[test]
    fn profile_parser_rejects_path_like_and_decorated_values() {
        for raw in [
            "../strict",
            "strict/balanced",
            "strict:balanced",
            "balanced\0",
        ] {
            assert!(
                raw.parse::<Profile>().is_err(),
                "decorated profile unexpectedly parsed: {raw:?}"
            );
        }
    }

    #[test]
    fn compatibility_mode_parser_rejects_decorated_values() {
        for raw in [
            "mode=strict",
            "balanced#default",
            "legacy-risky/latest",
            "strict\0",
        ] {
            assert!(
                raw.parse::<CompatibilityMode>().is_err(),
                "decorated compatibility mode unexpectedly parsed: {raw:?}"
            );
        }
    }

    #[test]
    fn preferred_runtime_parser_rejects_path_like_and_tagged_values() {
        for raw in ["node/bun", "franken-engine:latest", "auto#default", "bun\0"] {
            assert!(
                raw.parse::<PreferredRuntime>().is_err(),
                "decorated runtime unexpectedly parsed: {raw:?}"
            );
        }
    }

    #[test]
    fn validation_rejects_zero_fleet_convergence_timeout() {
        let mut config = Config::for_profile(Profile::Balanced);
        config.fleet.convergence_timeout_seconds = 0;

        let err = config.validate().unwrap_err();

        assert!(
            err.to_string()
                .contains("fleet.convergence_timeout_seconds")
        );
    }

    #[test]
    fn validation_rejects_zero_runtime_bulkhead_retry_after() {
        let mut config = Config::for_profile(Profile::Balanced);
        config.runtime.bulkhead_retry_after_ms = 0;

        let err = config.validate().unwrap_err();

        assert!(err.to_string().contains("runtime.bulkhead_retry_after_ms"));
    }

    #[test]
    fn validation_rejects_zero_runtime_lane_enqueue_timeout() {
        let mut config = Config::for_profile(Profile::Balanced);
        let lane = config
            .runtime
            .lanes
            .get_mut("background")
            .expect("background lane exists");
        lane.enqueue_timeout_ms = 0;

        let err = config.validate().unwrap_err();

        assert!(
            err.to_string()
                .contains("runtime.lanes.background.enqueue_timeout_ms")
        );
    }

    #[test]
    fn validation_rejects_invalid_benchmark_config() {
        let mut empty_path = Config::for_profile(Profile::Balanced);
        empty_path.benchmark.summary_path = "   ".to_string();
        assert!(
            empty_path
                .validate()
                .unwrap_err()
                .to_string()
                .contains("benchmark.summary_path")
        );

        let mut nul_path = Config::for_profile(Profile::Balanced);
        nul_path.benchmark.summary_path = "artifacts/category_shift\0summary.json".to_string();
        assert!(
            nul_path
                .validate()
                .unwrap_err()
                .to_string()
                .contains("benchmark.summary_path")
        );

        let mut non_finite_latency = Config::for_profile(Profile::Balanced);
        non_finite_latency.benchmark.max_latency_ms = f64::NAN;
        assert!(
            non_finite_latency
                .validate()
                .unwrap_err()
                .to_string()
                .contains("benchmark.max_latency_ms")
        );

        let mut zero_latency = Config::for_profile(Profile::Balanced);
        zero_latency.benchmark.max_latency_ms = 0.0;
        assert!(
            zero_latency
                .validate()
                .unwrap_err()
                .to_string()
                .contains("benchmark.max_latency_ms")
        );

        let mut zero_throughput = Config::for_profile(Profile::Balanced);
        zero_throughput.benchmark.min_throughput_ops = 0;
        assert!(
            zero_throughput
                .validate()
                .unwrap_err()
                .to_string()
                .contains("benchmark.min_throughput_ops")
        );
    }

    #[test]
    fn validation_rejects_invalid_verifier_config() {
        let mut zero_claims = Config::for_profile(Profile::Balanced);
        zero_claims.verifier.max_claims_per_request = 0;
        assert!(
            zero_claims
                .validate()
                .unwrap_err()
                .to_string()
                .contains("verifier.max_claims_per_request")
        );

        let mut zero_capsules = Config::for_profile(Profile::Balanced);
        zero_capsules.verifier.max_capsule_count = 0;
        assert!(
            zero_capsules
                .validate()
                .unwrap_err()
                .to_string()
                .contains("verifier.max_capsule_count")
        );

        let mut zero_chain = Config::for_profile(Profile::Balanced);
        zero_chain.verifier.max_chain_depth = 0;
        assert!(
            zero_chain
                .validate()
                .unwrap_err()
                .to_string()
                .contains("verifier.max_chain_depth")
        );
    }

    #[test]
    fn validate_score_and_percentage_reject_out_of_range_values() {
        assert!(validate_opt_score("trust.min_trust_score", Some(-0.01)).is_err());
        assert!(validate_opt_score("trust.min_trust_score", Some(1.01)).is_err());
        assert!(validate_opt_pct("thresholds.max_variance_pct", Some(-0.01)).is_err());
        assert!(validate_opt_pct("thresholds.max_variance_pct", Some(100.01)).is_err());
    }

    #[test]
    fn validation_rejects_invalid_trust_threshold_overrides() {
        let mut config = Config::for_profile(Profile::Balanced);
        config.trust.test_coverage_threshold_pct = Some(f64::NAN);
        assert!(
            config
                .validate()
                .unwrap_err()
                .to_string()
                .contains("trust.test_coverage_threshold_pct")
        );

        let mut config = Config::for_profile(Profile::Balanced);
        config.trust.reputation_tier_thresholds = Some(ReputationThresholds {
            trusted: 50.0,
            established: 80.0,
            provisional: 20.0,
        });
        assert!(
            config
                .validate()
                .unwrap_err()
                .to_string()
                .contains("trust.reputation_tier_thresholds")
        );
    }

    #[test]
    fn validation_rejects_invalid_registry_signing_key() {
        let mut config = Config::for_profile(Profile::Balanced);
        config.trust.registry_signing_key = Some("not-base64".to_string());
        assert!(
            config
                .validate()
                .unwrap_err()
                .to_string()
                .contains("trust.registry_signing_key")
        );

        let mut config = Config::for_profile(Profile::Balanced);
        config.trust.registry_signing_key =
            Some(base64::engine::general_purpose::STANDARD.encode([0_u8; 16]));
        assert!(
            config
                .validate()
                .unwrap_err()
                .to_string()
                .contains("trust.registry_signing_key")
        );
    }

    #[test]
    fn validation_rejects_missing_registry_signing_key() {
        let mut config = Config::for_profile(Profile::Balanced);
        config.trust.registry_signing_key = None;
        assert!(config.validate().unwrap_err().to_string().contains(
            "trust.registry_signing_key must be configured (fail-closed security boundary)"
        ));
    }

    #[test]
    fn validation_accepts_valid_trust_threshold_and_key_overrides() {
        let mut config = Config::for_profile(Profile::Balanced);
        config.trust.test_coverage_threshold_pct = Some(85.0);
        config.trust.reputation_tier_thresholds = Some(ReputationThresholds {
            trusted: 90.0,
            established: 60.0,
            provisional: 30.0,
        });
        config.trust.registry_signing_key =
            Some(base64::engine::general_purpose::STANDARD.encode([7_u8; 32]));

        config.validate().expect("valid trust overrides");
    }

    #[test]
    fn validation_rejects_empty_observability_namespace() {
        let mut config = Config::for_profile(Profile::Balanced);
        config.observability.namespace = "   ".to_string();

        let err = config.validate().unwrap_err();

        assert!(err.to_string().contains("observability.namespace"));
    }

    #[test]
    fn validation_rejects_zero_runtime_bulkhead_capacity() {
        let mut config = Config::for_profile(Profile::Balanced);
        config.runtime.remote_max_in_flight = 0;

        let err = config.validate().unwrap_err();

        assert!(err.to_string().contains("runtime.remote_max_in_flight"));
    }

    #[test]
    fn validation_rejects_zero_verifier_claim_cap() {
        let mut config = Config::for_profile(Profile::Balanced);
        config.verifier.max_claims_per_request = 0;

        let err = config.validate().unwrap_err();

        assert!(
            err.to_string()
                .contains("verifier.max_claims_per_request must be > 0")
        );
    }

    #[test]
    fn validation_rejects_zero_runtime_lane_limits() {
        let mut config = Config::for_profile(Profile::Balanced);
        let lane = config
            .runtime
            .lanes
            .get_mut("cancel")
            .expect("cancel lane exists");
        lane.queue_limit = 0;

        let err = config.validate().unwrap_err();

        assert!(err.to_string().contains("runtime.lanes.cancel.queue_limit"));
    }

    #[test]
    fn validation_rejects_zero_compatibility_receipt_ttl() {
        let mut config = Config::for_profile(Profile::Balanced);
        config.compatibility.default_receipt_ttl_secs = 0;

        let err = config.validate().unwrap_err();

        assert!(err.to_string().contains("default_receipt_ttl_secs"));
    }

    #[test]
    fn validation_rejects_zero_replay_capsule_freshness() {
        let mut config = Config::for_profile(Profile::Balanced);
        config.replay.max_replay_capsule_freshness_secs = 0;

        let err = config.validate().unwrap_err();

        assert!(
            err.to_string()
                .contains("max_replay_capsule_freshness_secs")
        );
    }

    #[test]
    fn validation_rejects_blank_replay_bundle_version() {
        let mut config = Config::for_profile(Profile::Balanced);
        config.replay.bundle_version = "\t ".to_string();

        let err = config.validate().unwrap_err();

        assert!(err.to_string().contains("replay.bundle_version"));
    }

    #[test]
    fn validation_rejects_zero_observability_receipt_cap() {
        let mut config = Config::for_profile(Profile::Balanced);
        config.observability.max_receipts = Some(0);

        let err = config.validate().unwrap_err();

        assert!(err.to_string().contains("observability.max_receipts"));
    }

    #[test]
    fn validation_rejects_zero_security_degraded_duration() {
        let mut config = Config::for_profile(Profile::Balanced);
        config.security.max_degraded_duration_secs = 0;

        let err = config.validate().unwrap_err();

        assert!(
            err.to_string()
                .contains("security.max_degraded_duration_secs")
        );
    }

    #[test]
    fn validation_rejects_invalid_fleet_node_id() {
        let mut config = Config::for_profile(Profile::Balanced);
        config.fleet.node_id = Some("../node".to_string());

        let err = config.validate().unwrap_err();

        assert!(err.to_string().contains("fleet.node_id"));
    }

    #[test]
    fn validation_rejects_zero_fleet_poll_interval() {
        let mut config = Config::for_profile(Profile::Balanced);
        config.fleet.poll_interval_seconds = Some(0);

        let err = config.validate().unwrap_err();

        assert!(err.to_string().contains("fleet.poll_interval_seconds"));
    }

    #[test]
    fn validation_rejects_zero_runtime_lane_max_concurrent() {
        let mut config = Config::for_profile(Profile::Balanced);
        let lane = config
            .runtime
            .lanes
            .get_mut("timed")
            .expect("timed lane exists");
        lane.max_concurrent = 0;

        let err = config.validate().unwrap_err();

        assert!(
            err.to_string()
                .contains("runtime.lanes.timed.max_concurrent")
        );
    }

    #[test]
    fn validation_rejects_zero_runtime_lane_priority_weight() {
        let mut config = Config::for_profile(Profile::Balanced);
        let lane = config
            .runtime
            .lanes
            .get_mut("realtime")
            .expect("realtime lane exists");
        lane.priority_weight = 0;

        let err = config.validate().unwrap_err();

        assert!(
            err.to_string()
                .contains("runtime.lanes.realtime.priority_weight")
        );
    }

    #[test]
    fn lane_overflow_policy_deserialize_rejects_snake_case_variant() {
        let raw = r#"
max_concurrent = 1
priority_weight = 1
queue_limit = 1
enqueue_timeout_ms = 1
overflow_policy = "enqueue_with_timeout"
"#;

        let result: Result<RuntimeLaneConfig, _> = toml::from_str(raw);

        assert!(result.is_err(), "overflow policy must use kebab-case");
    }

    #[test]
    fn network_allowlist_entry_deserialize_rejects_missing_reason() {
        let raw = r#"
host = "metadata.internal"
"#;

        let result: Result<NetworkAllowlistEntry, _> = toml::from_str(raw);

        assert!(
            result.is_err(),
            "allowlist entries must carry audit reasons"
        );
    }

    #[test]
    fn network_allowlist_entry_deserialize_rejects_port_overflow() {
        let raw = r#"
host = "metadata.internal"
port = 70000
reason = "test fixture"
"#;

        let result: Result<NetworkAllowlistEntry, _> = toml::from_str(raw);

        assert!(result.is_err(), "allowlist ports must fit in u16");
    }

    #[test]
    fn network_policy_deserialize_rejects_unknown_ssrf_enforcement() {
        let raw = r#"
ssrf_enforcement = "audit"
"#;

        let result: Result<NetworkPolicyConfig, _> = toml::from_str(raw);

        assert!(result.is_err(), "unknown SSRF enforcement mode must fail");
    }

    #[test]
    fn security_config_deserialize_rejects_scalar_api_keys() {
        let raw = r#"
max_degraded_duration_secs = 3600
authorized_api_keys = "single-key"
"#;

        let result: Result<SecurityConfig, _> = toml::from_str(raw);

        assert!(result.is_err(), "authorized API keys must be a string set");
    }

    #[test]
    fn runtime_config_deserialize_rejects_lanes_array() {
        let raw = r#"
preferred = "auto"
remote_max_in_flight = 8
bulkhead_retry_after_ms = 50
lanes = []
"#;

        let result: Result<RuntimeConfig, _> = toml::from_str(raw);

        assert!(result.is_err(), "runtime lanes must be a table map");
    }

    #[test]
    fn runtime_lane_config_deserialize_rejects_negative_queue_limit() {
        let raw = r#"
max_concurrent = 1
priority_weight = 1
queue_limit = -1
enqueue_timeout_ms = 1
overflow_policy = "reject"
"#;

        let result: Result<RuntimeLaneConfig, _> = toml::from_str(raw);

        assert!(
            result.is_err(),
            "queue_limit must not accept negative values"
        );
    }

    #[test]
    fn thresholds_config_deserialize_rejects_string_quality_score() {
        let raw = r#"
min_quality_score = "0.8"
"#;

        let result: Result<ThresholdsConfig, _> = toml::from_str(raw);

        assert!(result.is_err(), "thresholds must remain numeric");
    }

    #[test]
    fn thresholds_config_default_values_centralize_documented_thresholds() {
        assert_eq!(
            ThresholdsConfig::default_values(),
            ThresholdsConfig {
                max_failure_rate: Some(DEFAULT_THRESHOLD_MAX_FAILURE_RATE),
                min_quality_score: Some(DEFAULT_THRESHOLD_MIN_QUALITY_SCORE),
                max_variance_pct: Some(DEFAULT_THRESHOLD_MAX_VARIANCE_PCT),
                regression_threshold_pct: Some(DEFAULT_THRESHOLD_REGRESSION_THRESHOLD_PCT),
                min_resilience_score: Some(DEFAULT_THRESHOLD_MIN_RESILIENCE_SCORE),
            }
        );
        assert_eq!(
            ThresholdsConfig::default(),
            ThresholdsConfig {
                max_failure_rate: None,
                min_quality_score: None,
                max_variance_pct: None,
                regression_threshold_pct: None,
                min_resilience_score: None,
            }
        );
    }

    #[test]
    fn config_degraded_mode_policy_factory_applies_security_ttl() {
        let mut config = Config::for_profile(Profile::Balanced);
        config.security.max_degraded_duration_secs = 91;

        let policy = config.degraded_mode_policy("trust-input-stale");

        assert_eq!(policy.max_degraded_duration_secs, 91);
    }

    #[cfg(any(
        feature = "remote-ops",
        feature = "control-plane",
        feature = "verifier-tools"
    ))]
    #[test]
    fn config_component_factories_apply_remote_compatibility_and_replay_ttls() {
        let mut config = Config::for_profile(Profile::Balanced);
        config.remote.idempotency_ttl_secs = 777;
        let store = config.idempotency_dedupe_store();
        assert_eq!(store.ttl_secs(), 777);
        config.compatibility.default_receipt_ttl_secs = 123;
        config.replay.max_replay_capsule_freshness_secs = 321;

        let mut evaluator =
            config.compat_gate_evaluator(crate::policy::compat_gates::ShimRegistry::new());
        let receipt = evaluator
            .set_mode(
                "project-config-factory",
                crate::policy::compat_gates::CompatibilityMode::Balanced,
                "admin",
                "factory wired ttl",
                true,
            )
            .unwrap();
        let activated_at = chrono::DateTime::parse_from_rfc3339(&receipt.activated_at).unwrap();
        let expires_at = chrono::DateTime::parse_from_rfc3339(&receipt.expires_at).unwrap();
        assert_eq!(
            expires_at.signed_duration_since(activated_at).num_seconds(),
            123
        );

        let mut engine = config.compatibility_gate_engine(b"test-key-v1".to_vec());
        engine.set_scope_mode(
            "tenant-config-factory",
            crate::policy::compatibility_gate::CompatMode::Balanced,
        );
        let scope_mode = engine.query_mode("tenant-config-factory").unwrap();
        let activated_at = chrono::DateTime::parse_from_rfc3339(&scope_mode.activated_at).unwrap();
        let expires_at = chrono::DateTime::parse_from_rfc3339(&scope_mode.expires_at).unwrap();
        assert_eq!(
            expires_at.signed_duration_since(activated_at).num_seconds(),
            123
        );

        let registry = config.verifier_economy_registry();
        assert_eq!(registry.replay_capsule_freshness_secs(), 321);
    }
}
