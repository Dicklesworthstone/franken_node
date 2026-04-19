#![allow(clippy::doc_markdown)]

use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};

/// Maximum number of configuration merge decisions to track.
/// Prevents memory exhaustion from adversarial config override patterns.
const MAX_MERGE_DECISIONS: usize = 100;

/// Push item to vector with bounded capacity to prevent memory exhaustion.
/// When capacity is exceeded, removes oldest entries to maintain the limit.
fn push_bounded<T>(items: &mut Vec<T>, item: T, cap: usize) {
    if cap == 0 {
        items.clear();
        return;
    }
    if items.len() >= cap {
        let overflow = items.len().saturating_sub(cap).saturating_add(1);
        items.drain(0..overflow);
    }
    items.push(item);
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
                    default_receipt_ttl_secs: 3_600,
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
                },
                replay: ReplayConfig {
                    persist_high_severity: true,
                    bundle_version: "v1".to_string(),
                    max_replay_capsule_freshness_secs: 3_600,
                    capsule_freshness_secs: None,
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
                    convergence_timeout_seconds: 60,
                    barrier_timeout_ms: None,
                },
                observability: ObservabilityConfig {
                    namespace: "franken_node".to_string(),
                    emit_structured_audit_events: true,
                    max_receipts: None,
                },
                remote: RemoteConfig {
                    idempotency_ttl_secs: 604_800,
                },
                security: SecurityConfig {
                    max_degraded_duration_secs: 3_600,
                    decision_receipt_signing_key_path: None,
                    authorized_api_keys: std::collections::BTreeSet::new(),
                    network_policy: NetworkPolicyConfig::default(),
                },
                engine: EngineConfig::default(),
                runtime: RuntimeConfig::strict_defaults(),
                thresholds: ThresholdsConfig::default(),
            },
            Profile::Balanced => Self {
                profile,
                compatibility: CompatibilityConfig {
                    mode: CompatibilityMode::Balanced,
                    emit_divergence_receipts: true,
                    default_receipt_ttl_secs: 3_600,
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
                },
                replay: ReplayConfig {
                    persist_high_severity: true,
                    bundle_version: "v1".to_string(),
                    max_replay_capsule_freshness_secs: 3_600,
                    capsule_freshness_secs: None,
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
                    convergence_timeout_seconds: 120,
                    barrier_timeout_ms: None,
                },
                observability: ObservabilityConfig {
                    namespace: "franken_node".to_string(),
                    emit_structured_audit_events: true,
                    max_receipts: None,
                },
                remote: RemoteConfig {
                    idempotency_ttl_secs: 604_800,
                },
                security: SecurityConfig {
                    max_degraded_duration_secs: 3_600,
                    decision_receipt_signing_key_path: None,
                    authorized_api_keys: std::collections::BTreeSet::new(),
                    network_policy: NetworkPolicyConfig::default(),
                },
                engine: EngineConfig::default(),
                runtime: RuntimeConfig::balanced_defaults(),
                thresholds: ThresholdsConfig::default(),
            },
            Profile::LegacyRisky => Self {
                profile,
                compatibility: CompatibilityConfig {
                    mode: CompatibilityMode::LegacyRisky,
                    emit_divergence_receipts: false,
                    default_receipt_ttl_secs: 3_600,
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
                },
                replay: ReplayConfig {
                    persist_high_severity: true,
                    bundle_version: "v1".to_string(),
                    max_replay_capsule_freshness_secs: 3_600,
                    capsule_freshness_secs: None,
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
                    convergence_timeout_seconds: 300,
                    barrier_timeout_ms: None,
                },
                observability: ObservabilityConfig {
                    namespace: "franken_node".to_string(),
                    emit_structured_audit_events: false,
                    max_receipts: None,
                },
                remote: RemoteConfig {
                    idempotency_ttl_secs: 604_800,
                },
                security: SecurityConfig {
                    max_degraded_duration_secs: 3_600,
                    decision_receipt_signing_key_path: None,
                    authorized_api_keys: std::collections::BTreeSet::new(),
                    network_policy: NetworkPolicyConfig::default(),
                },
                engine: EngineConfig::default(),
                runtime: RuntimeConfig::legacy_defaults(),
                thresholds: ThresholdsConfig::default(),
            },
        }
    }

    /// Load configuration from a TOML file without CLI/env merge layers.
    ///
    /// This method is useful for fixtures and static snapshots.
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
            push_bounded(&mut decisions, MergeDecision::new(
                MergeStage::File,
                "profile",
                profile.to_string(),
            ), MAX_MERGE_DECISIONS);
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
            push_bounded(&mut decisions, MergeDecision::new(
                MergeStage::Env,
                "profile",
                parsed.to_string(),
            ), MAX_MERGE_DECISIONS);
        }

        if let Some(profile) = cli_overrides.profile {
            selected_profile = profile;
            push_bounded(&mut decisions, MergeDecision::new(
                MergeStage::Cli,
                "profile",
                profile.to_string(),
            ), MAX_MERGE_DECISIONS);
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
    pub fn to_toml(&self) -> Result<String, ConfigError> {
        toml::to_string_pretty(self).map_err(ConfigError::SerializeFailed)
    }

    /// Build an idempotency dedupe store from the resolved remote settings.
    #[cfg(feature = "extended-surfaces")]
    #[must_use]
    pub fn idempotency_dedupe_store(
        &self,
    ) -> crate::remote::idempotency_store::IdempotencyDedupeStore {
        crate::remote::idempotency_store::IdempotencyDedupeStore::from_remote_config(&self.remote)
    }

    /// Build a degraded-mode policy seeded from the resolved security settings.
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
    #[cfg(feature = "extended-surfaces")]
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
    #[cfg(feature = "extended-surfaces")]
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
    #[cfg(feature = "extended-surfaces")]
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
        if let Some(section) = &overrides.compatibility {
            if let Some(value) = section.mode {
                self.compatibility.mode = value;
                push_bounded(&mut decisions, MergeDecision::new(
                    stage.clone(),
                    "compatibility.mode",
                    value.to_string(),
                ), MAX_MERGE_DECISIONS);
            }
            if let Some(value) = section.emit_divergence_receipts {
                self.compatibility.emit_divergence_receipts = value;
                push_bounded(&mut decisions, MergeDecision::new(
                    stage.clone(),
                    "compatibility.emit_divergence_receipts",
                    value,
                ), MAX_MERGE_DECISIONS);
            }
            if let Some(value) = section.default_receipt_ttl_secs {
                self.compatibility.default_receipt_ttl_secs = value;
                push_bounded(&mut decisions, MergeDecision::new(
                    stage.clone(),
                    "compatibility.default_receipt_ttl_secs",
                    value,
                ), MAX_MERGE_DECISIONS);
            }
            if let Some(value) = section.gate_ttl_secs {
                self.compatibility.gate_ttl_secs = Some(value);
                push_bounded(&mut decisions, MergeDecision::new(
                    stage.clone(),
                    "compatibility.gate_ttl_secs",
                    value,
                ), MAX_MERGE_DECISIONS);
            }
        }

        if let Some(section) = &overrides.migration {
            if let Some(value) = section.autofix {
                self.migration.autofix = value;
                push_bounded(&mut decisions, MergeDecision::new(
                    stage.clone(),
                    "migration.autofix",
                    value,
                ), MAX_MERGE_DECISIONS);
            }
            if let Some(value) = section.require_lockstep_validation {
                self.migration.require_lockstep_validation = value;
                push_bounded(&mut decisions, MergeDecision::new(
                    stage.clone(),
                    "migration.require_lockstep_validation",
                    value,
                ), MAX_MERGE_DECISIONS);
            }
            if let Some(value) = section.verification_threshold {
                self.migration.verification_threshold = Some(value);
                push_bounded(&mut decisions, MergeDecision::new(
                    stage.clone(),
                    "migration.verification_threshold",
                    value,
                ), MAX_MERGE_DECISIONS);
            }
            if let Some(value) = section.confidence_level {
                self.migration.confidence_level = Some(value);
                push_bounded(&mut decisions, MergeDecision::new(
                    stage.clone(),
                    "migration.confidence_level",
                    value,
                ), MAX_MERGE_DECISIONS);
            }
            if let Some(value) = section.determinism_rate {
                self.migration.determinism_rate = Some(value);
                push_bounded(&mut decisions, MergeDecision::new(
                    stage.clone(),
                    "migration.determinism_rate",
                    value,
                ), MAX_MERGE_DECISIONS);
            }
        }

        if let Some(section) = &overrides.trust {
            if let Some(value) = section.risky_requires_fresh_revocation {
                self.trust.risky_requires_fresh_revocation = value;
                push_bounded(&mut decisions, MergeDecision::new(
                    stage.clone(),
                    "trust.risky_requires_fresh_revocation",
                    value,
                ), MAX_MERGE_DECISIONS);
            }
            if let Some(value) = section.dangerous_requires_fresh_revocation {
                self.trust.dangerous_requires_fresh_revocation = value;
                push_bounded(&mut decisions, MergeDecision::new(
                    stage.clone(),
                    "trust.dangerous_requires_fresh_revocation",
                    value,
                ), MAX_MERGE_DECISIONS);
            }
            if let Some(value) = section.quarantine_on_high_risk {
                self.trust.quarantine_on_high_risk = value;
                push_bounded(&mut decisions, MergeDecision::new(
                    stage.clone(),
                    "trust.quarantine_on_high_risk",
                    value,
                ), MAX_MERGE_DECISIONS);
            }
            if let Some(value) = section.card_cache_ttl_secs {
                self.trust.card_cache_ttl_secs = Some(value);
                push_bounded(&mut decisions, MergeDecision::new(
                    stage.clone(),
                    "trust.card_cache_ttl_secs",
                    value,
                ), MAX_MERGE_DECISIONS);
            }
            if let Some(value) = section.freshness_window_secs {
                self.trust.freshness_window_secs = Some(value);
                push_bounded(&mut decisions, MergeDecision::new(
                    stage.clone(),
                    "trust.freshness_window_secs",
                    value,
                ), MAX_MERGE_DECISIONS);
            }
            if let Some(value) = section.min_trust_score {
                self.trust.min_trust_score = Some(value);
                push_bounded(&mut decisions, MergeDecision::new(
                    stage.clone(),
                    "trust.min_trust_score",
                    value,
                ), MAX_MERGE_DECISIONS);
            }
            if let Some(value) = section.decay_factor {
                self.trust.decay_factor = Some(value);
                push_bounded(&mut decisions, MergeDecision::new(
                    stage.clone(),
                    "trust.decay_factor",
                    value,
                ), MAX_MERGE_DECISIONS);
            }
        }

        if let Some(section) = &overrides.replay {
            if let Some(value) = section.persist_high_severity {
                self.replay.persist_high_severity = value;
                push_bounded(&mut decisions, MergeDecision::new(
                    stage.clone(),
                    "replay.persist_high_severity",
                    value,
                ), MAX_MERGE_DECISIONS);
            }
            if let Some(value) = &section.bundle_version {
                self.replay.bundle_version = value.clone();
                push_bounded(&mut decisions, MergeDecision::new(
                    stage.clone(),
                    "replay.bundle_version",
                    value,
                ), MAX_MERGE_DECISIONS);
            }
            if let Some(value) = section.max_replay_capsule_freshness_secs {
                self.replay.max_replay_capsule_freshness_secs = value;
                push_bounded(&mut decisions, MergeDecision::new(
                    stage.clone(),
                    "replay.max_replay_capsule_freshness_secs",
                    value,
                ), MAX_MERGE_DECISIONS);
            }
            if let Some(value) = section.capsule_freshness_secs {
                self.replay.capsule_freshness_secs = Some(value);
                push_bounded(&mut decisions, MergeDecision::new(
                    stage.clone(),
                    "replay.capsule_freshness_secs",
                    value,
                ), MAX_MERGE_DECISIONS);
            }
        }

        if let Some(section) = &overrides.registry {
            if let Some(value) = section.require_signatures {
                self.registry.require_signatures = value;
                push_bounded(&mut decisions, MergeDecision::new(
                    stage.clone(),
                    "registry.require_signatures",
                    value,
                ), MAX_MERGE_DECISIONS);
            }
            if let Some(value) = section.require_provenance {
                self.registry.require_provenance = value;
                push_bounded(&mut decisions, MergeDecision::new(
                    stage.clone(),
                    "registry.require_provenance",
                    value,
                ), MAX_MERGE_DECISIONS);
            }
            if let Some(value) = section.minimum_assurance_level {
                self.registry.minimum_assurance_level = value;
                push_bounded(&mut decisions, MergeDecision::new(
                    stage.clone(),
                    "registry.minimum_assurance_level",
                    value,
                ), MAX_MERGE_DECISIONS);
            }
            if let Some(value) = &section.builder_identity {
                self.registry.builder_identity = Some(value.clone());
                push_bounded(&mut decisions, MergeDecision::new(
                    stage.clone(),
                    "registry.builder_identity",
                    value,
                ), MAX_MERGE_DECISIONS);
            }
        }

        if let Some(section) = &overrides.fleet {
            if let Some(value) = &section.state_dir {
                self.fleet.state_dir = Some(value.clone());
                push_bounded(&mut decisions, MergeDecision::new(
                    stage.clone(),
                    "fleet.state_dir",
                    value.display(),
                ), MAX_MERGE_DECISIONS);
            }
            if let Some(value) = &section.node_id {
                self.fleet.node_id = Some(value.clone());
                push_bounded(&mut decisions, MergeDecision::new(stage.clone(), "fleet.node_id", value), MAX_MERGE_DECISIONS);
            }
            if let Some(value) = section.poll_interval_seconds {
                self.fleet.poll_interval_seconds = Some(value);
                push_bounded(&mut decisions, MergeDecision::new(
                    stage.clone(),
                    "fleet.poll_interval_seconds",
                    value,
                ), MAX_MERGE_DECISIONS);
            }
            if let Some(value) = section.convergence_timeout_seconds {
                self.fleet.convergence_timeout_seconds = value;
                push_bounded(&mut decisions, MergeDecision::new(
                    stage.clone(),
                    "fleet.convergence_timeout_seconds",
                    value,
                ), MAX_MERGE_DECISIONS);
            }
            if let Some(value) = section.barrier_timeout_ms {
                self.fleet.barrier_timeout_ms = Some(value);
                push_bounded(&mut decisions, MergeDecision::new(
                    stage.clone(),
                    "fleet.barrier_timeout_ms",
                    value,
                ), MAX_MERGE_DECISIONS);
            }
        }

        if let Some(section) = &overrides.observability {
            if let Some(value) = &section.namespace {
                self.observability.namespace = value.clone();
                push_bounded(&mut decisions, MergeDecision::new(
                    stage.clone(),
                    "observability.namespace",
                    value,
                ), MAX_MERGE_DECISIONS);
            }
            if let Some(value) = section.emit_structured_audit_events {
                self.observability.emit_structured_audit_events = value;
                push_bounded(&mut decisions, MergeDecision::new(
                    stage.clone(),
                    "observability.emit_structured_audit_events",
                    value,
                ), MAX_MERGE_DECISIONS);
            }
            if let Some(value) = section.max_receipts {
                self.observability.max_receipts = Some(value);
                push_bounded(&mut decisions, MergeDecision::new(
                    stage.clone(),
                    "observability.max_receipts",
                    value,
                ), MAX_MERGE_DECISIONS);
            }
        }

        if let Some(section) = &overrides.remote
            && let Some(value) = section.idempotency_ttl_secs
        {
            self.remote.idempotency_ttl_secs = value;
            push_bounded(&mut decisions, MergeDecision::new(
                stage.clone(),
                "remote.idempotency_ttl_secs",
                value,
            ), MAX_MERGE_DECISIONS);
        }

        if let Some(section) = &overrides.security
            && let Some(value) = section.max_degraded_duration_secs
        {
            self.security.max_degraded_duration_secs = value;
            push_bounded(&mut decisions, MergeDecision::new(
                stage.clone(),
                "security.max_degraded_duration_secs",
                value,
            ), MAX_MERGE_DECISIONS);
        }
        if let Some(section) = &overrides.security
            && let Some(value) = &section.decision_receipt_signing_key_path
        {
            self.security.decision_receipt_signing_key_path = Some(value.clone());
            push_bounded(&mut decisions, MergeDecision::new(
                stage.clone(),
                "security.decision_receipt_signing_key_path",
                value.display(),
            ));
        }
        if let Some(section) = &overrides.security
            && let Some(value) = &section.authorized_api_keys
        {
            self.security.authorized_api_keys = value.clone();
            push_bounded(&mut decisions, MergeDecision::new(
                stage.clone(),
                "security.authorized_api_keys",
                format!("[{} keys configured]", value.len()),
            ));
        }

        if let Some(section) = &overrides.engine
            && let Some(value) = &section.binary_path
        {
            self.engine.binary_path = Some(value.clone());
            push_bounded(&mut decisions, MergeDecision::new(
                stage.clone(),
                "engine.binary_path",
                value.display(),
            ));
        }

        if let Some(section) = &overrides.runtime {
            if let Some(value) = section.preferred {
                self.runtime.preferred = value;
                push_bounded(&mut decisions, MergeDecision::new(
                    stage.clone(),
                    "runtime.preferred",
                    value,
                ), MAX_MERGE_DECISIONS);
            }
            if let Some(value) = section.remote_max_in_flight {
                self.runtime.remote_max_in_flight = value;
                push_bounded(&mut decisions, MergeDecision::new(
                    stage.clone(),
                    "runtime.remote_max_in_flight",
                    value,
                ), MAX_MERGE_DECISIONS);
            }
            if let Some(value) = section.bulkhead_retry_after_ms {
                self.runtime.bulkhead_retry_after_ms = value;
                push_bounded(&mut decisions, MergeDecision::new(
                    stage.clone(),
                    "runtime.bulkhead_retry_after_ms",
                    value,
                ), MAX_MERGE_DECISIONS);
            }
            if let Some(lanes) = &section.lanes {
                for (lane_name, lane_overrides) in lanes {
                    if let Some(target) = self.runtime.lanes.get_mut(lane_name) {
                        if let Some(value) = lane_overrides.max_concurrent {
                            target.max_concurrent = value;
                            push_bounded(&mut decisions, MergeDecision::new(
                                stage.clone(),
                                format!("runtime.lanes.{lane_name}.max_concurrent").as_str(),
                                value,
                            ));
                        }
                        if let Some(value) = lane_overrides.priority_weight {
                            target.priority_weight = value;
                            push_bounded(&mut decisions, MergeDecision::new(
                                stage.clone(),
                                format!("runtime.lanes.{lane_name}.priority_weight").as_str(),
                                value,
                            ));
                        }
                        if let Some(value) = lane_overrides.queue_limit {
                            target.queue_limit = value;
                            push_bounded(&mut decisions, MergeDecision::new(
                                stage.clone(),
                                format!("runtime.lanes.{lane_name}.queue_limit").as_str(),
                                value,
                            ));
                        }
                        if let Some(value) = lane_overrides.enqueue_timeout_ms {
                            target.enqueue_timeout_ms = value;
                            push_bounded(&mut decisions, MergeDecision::new(
                                stage.clone(),
                                format!("runtime.lanes.{lane_name}.enqueue_timeout_ms").as_str(),
                                value,
                            ));
                        }
                        if let Some(value) = lane_overrides.overflow_policy {
                            target.overflow_policy = value;
                            push_bounded(&mut decisions, MergeDecision::new(
                                stage.clone(),
                                format!("runtime.lanes.{lane_name}.overflow_policy").as_str(),
                                value.to_string(),
                            ));
                        }
                    }
                }
            }
            if let Some(value) = section.drain_timeout_ms {
                self.runtime.drain_timeout_ms = Some(value);
                push_bounded(&mut decisions, MergeDecision::new(
                    stage.clone(),
                    "runtime.drain_timeout_ms",
                    value,
                ), MAX_MERGE_DECISIONS);
            }
        }

        if let Some(section) = &overrides.thresholds {
            if let Some(value) = section.max_failure_rate {
                self.thresholds.max_failure_rate = Some(value);
                push_bounded(&mut decisions, MergeDecision::new(
                    stage.clone(),
                    "thresholds.max_failure_rate",
                    value,
                ), MAX_MERGE_DECISIONS);
            }
            if let Some(value) = section.min_quality_score {
                self.thresholds.min_quality_score = Some(value);
                push_bounded(&mut decisions, MergeDecision::new(
                    stage.clone(),
                    "thresholds.min_quality_score",
                    value,
                ), MAX_MERGE_DECISIONS);
            }
            if let Some(value) = section.max_variance_pct {
                self.thresholds.max_variance_pct = Some(value);
                push_bounded(&mut decisions, MergeDecision::new(
                    stage.clone(),
                    "thresholds.max_variance_pct",
                    value,
                ), MAX_MERGE_DECISIONS);
            }
            if let Some(value) = section.regression_threshold_pct {
                self.thresholds.regression_threshold_pct = Some(value);
                push_bounded(&mut decisions, MergeDecision::new(
                    stage.clone(),
                    "thresholds.regression_threshold_pct",
                    value,
                ), MAX_MERGE_DECISIONS);
            }
            if let Some(value) = section.min_resilience_score {
                self.thresholds.min_resilience_score = Some(value);
                push_bounded(&mut decisions, MergeDecision::new(
                    stage.clone(),
                    "thresholds.min_resilience_score",
                    value,
                ), MAX_MERGE_DECISIONS);
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
            push_bounded(&mut decisions, MergeDecision::new(
                MergeStage::Env,
                "compatibility.mode",
                parsed.to_string(),
            ));
        }
        if let Some(raw) = env_lookup("FRANKEN_NODE_COMPATIBILITY_DEFAULT_RECEIPT_TTL_SECS") {
            let parsed =
                parse_env_u64("FRANKEN_NODE_COMPATIBILITY_DEFAULT_RECEIPT_TTL_SECS", &raw)?;
            self.compatibility.default_receipt_ttl_secs = parsed;
            push_bounded(&mut decisions, MergeDecision::new(
                MergeStage::Env,
                "compatibility.default_receipt_ttl_secs",
                parsed,
            ));
        }
        if let Some(raw) = env_lookup("FRANKEN_NODE_COMPATIBILITY_GATE_TTL_SECS") {
            let parsed = parse_env_u64("FRANKEN_NODE_COMPATIBILITY_GATE_TTL_SECS", &raw)?;
            self.compatibility.gate_ttl_secs = Some(parsed);
            push_bounded(&mut decisions, MergeDecision::new(
                MergeStage::Env,
                "compatibility.gate_ttl_secs",
                parsed,
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
        apply_env_field_opt_f64(
            "FRANKEN_NODE_MIGRATION_VERIFICATION_THRESHOLD",
            env_lookup,
            &mut self.migration.verification_threshold,
            "migration.verification_threshold",
            decisions,
        )?;
        apply_env_field_opt_f64(
            "FRANKEN_NODE_MIGRATION_CONFIDENCE_LEVEL",
            env_lookup,
            &mut self.migration.confidence_level,
            "migration.confidence_level",
            decisions,
        )?;
        apply_env_field_opt_f64(
            "FRANKEN_NODE_MIGRATION_DETERMINISM_RATE",
            env_lookup,
            &mut self.migration.determinism_rate,
            "migration.determinism_rate",
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
        if let Some(raw) = env_lookup("FRANKEN_NODE_TRUST_CARD_CACHE_TTL_SECS") {
            let parsed = parse_env_u64("FRANKEN_NODE_TRUST_CARD_CACHE_TTL_SECS", &raw)?;
            self.trust.card_cache_ttl_secs = Some(parsed);
            push_bounded(&mut decisions, MergeDecision::new(
                MergeStage::Env,
                "trust.card_cache_ttl_secs",
                parsed,
            ));
        }
        if let Some(raw) = env_lookup("FRANKEN_NODE_TRUST_FRESHNESS_WINDOW_SECS") {
            let parsed = parse_env_u64("FRANKEN_NODE_TRUST_FRESHNESS_WINDOW_SECS", &raw)?;
            self.trust.freshness_window_secs = Some(parsed);
            push_bounded(&mut decisions, MergeDecision::new(
                MergeStage::Env,
                "trust.freshness_window_secs",
                parsed,
            ));
        }
        apply_env_field_opt_f64(
            "FRANKEN_NODE_TRUST_MIN_TRUST_SCORE",
            env_lookup,
            &mut self.trust.min_trust_score,
            "trust.min_trust_score",
            decisions,
        )?;
        apply_env_field_opt_f64(
            "FRANKEN_NODE_TRUST_DECAY_FACTOR",
            env_lookup,
            &mut self.trust.decay_factor,
            "trust.decay_factor",
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
            push_bounded(&mut decisions, MergeDecision::new(
                MergeStage::Env,
                "replay.bundle_version",
                value,
            ));
        }
        if let Some(raw) = env_lookup("FRANKEN_NODE_REPLAY_MAX_REPLAY_CAPSULE_FRESHNESS_SECS") {
            let parsed = parse_env_u64(
                "FRANKEN_NODE_REPLAY_MAX_REPLAY_CAPSULE_FRESHNESS_SECS",
                &raw,
            )?;
            self.replay.max_replay_capsule_freshness_secs = parsed;
            push_bounded(&mut decisions, MergeDecision::new(
                MergeStage::Env,
                "replay.max_replay_capsule_freshness_secs",
                parsed,
            ));
        }
        if let Some(raw) = env_lookup("FRANKEN_NODE_REPLAY_CAPSULE_FRESHNESS_SECS") {
            let parsed = parse_env_u64("FRANKEN_NODE_REPLAY_CAPSULE_FRESHNESS_SECS", &raw)?;
            self.replay.capsule_freshness_secs = Some(parsed);
            push_bounded(&mut decisions, MergeDecision::new(
                MergeStage::Env,
                "replay.capsule_freshness_secs",
                parsed,
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
            push_bounded(&mut decisions, MergeDecision::new(
                MergeStage::Env,
                "registry.minimum_assurance_level",
                parsed,
            ));
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
            push_bounded(&mut decisions, MergeDecision::new(
                MergeStage::Env,
                "registry.builder_identity",
                trimmed,
            ));
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
            push_bounded(&mut decisions, MergeDecision::new(
                MergeStage::Env,
                "fleet.state_dir",
                parsed.display(),
            ));
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
            push_bounded(&mut decisions, MergeDecision::new(
                MergeStage::Env,
                "fleet.node_id",
                trimmed,
            ));
        }
        if let Some(raw) = env_lookup("FRANKEN_NODE_FLEET_POLL_INTERVAL_SECONDS") {
            let parsed = parse_env_u64("FRANKEN_NODE_FLEET_POLL_INTERVAL_SECONDS", &raw)?;
            self.fleet.poll_interval_seconds = Some(parsed);
            push_bounded(&mut decisions, MergeDecision::new(
                MergeStage::Env,
                "fleet.poll_interval_seconds",
                parsed,
            ));
        }
        if let Some(raw) = env_lookup("FRANKEN_NODE_FLEET_CONVERGENCE_TIMEOUT_SECONDS") {
            let parsed = parse_env_u64("FRANKEN_NODE_FLEET_CONVERGENCE_TIMEOUT_SECONDS", &raw)?;
            self.fleet.convergence_timeout_seconds = parsed;
            push_bounded(&mut decisions, MergeDecision::new(
                MergeStage::Env,
                "fleet.convergence_timeout_seconds",
                parsed,
            ));
        }
        if let Some(raw) = env_lookup("FRANKEN_NODE_FLEET_BARRIER_TIMEOUT_MS") {
            let parsed = parse_env_u64("FRANKEN_NODE_FLEET_BARRIER_TIMEOUT_MS", &raw)?;
            self.fleet.barrier_timeout_ms = Some(parsed);
            push_bounded(&mut decisions, MergeDecision::new(
                MergeStage::Env,
                "fleet.barrier_timeout_ms",
                parsed,
            ));
        }

        if let Some(value) = env_lookup("FRANKEN_NODE_OBSERVABILITY_NAMESPACE") {
            self.observability.namespace = value.clone();
            push_bounded(&mut decisions, MergeDecision::new(
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
        if let Some(raw) = env_lookup("FRANKEN_NODE_OBSERVABILITY_MAX_RECEIPTS") {
            let parsed = parse_env_usize("FRANKEN_NODE_OBSERVABILITY_MAX_RECEIPTS", &raw)?;
            self.observability.max_receipts = Some(parsed);
            push_bounded(&mut decisions, MergeDecision::new(
                MergeStage::Env,
                "observability.max_receipts",
                parsed,
            ));
        }
        if let Some(raw) = env_lookup("FRANKEN_NODE_REMOTE_IDEMPOTENCY_TTL_SECS") {
            let parsed = parse_env_u64("FRANKEN_NODE_REMOTE_IDEMPOTENCY_TTL_SECS", &raw)?;
            self.remote.idempotency_ttl_secs = parsed;
            push_bounded(&mut decisions, MergeDecision::new(
                MergeStage::Env,
                "remote.idempotency_ttl_secs",
                parsed,
            ));
        }
        if let Some(raw) = env_lookup("FRANKEN_NODE_SECURITY_MAX_DEGRADED_DURATION_SECS") {
            let parsed = parse_env_u64("FRANKEN_NODE_SECURITY_MAX_DEGRADED_DURATION_SECS", &raw)?;
            self.security.max_degraded_duration_secs = parsed;
            push_bounded(&mut decisions, MergeDecision::new(
                MergeStage::Env,
                "security.max_degraded_duration_secs",
                parsed,
            ));
        }
        if let Some(value) = env_lookup("FRANKEN_NODE_SECURITY_DECISION_RECEIPT_SIGNING_KEY_PATH") {
            let trimmed = value.trim();
            if !trimmed.is_empty() {
                let path = PathBuf::from(trimmed);
                self.security.decision_receipt_signing_key_path = Some(path.clone());
                push_bounded(&mut decisions, MergeDecision::new(
                    MergeStage::Env,
                    "security.decision_receipt_signing_key_path",
                    path.display(),
                ), MAX_MERGE_DECISIONS);
            }
        }

        if let Some(value) = env_lookup("FRANKEN_NODE_ENGINE_BINARY_PATH") {
            let trimmed = value.trim();
            if !trimmed.is_empty() {
                let path = PathBuf::from(trimmed);
                self.engine.binary_path = Some(path.clone());
                push_bounded(&mut decisions, MergeDecision::new(
                    MergeStage::Env,
                    "engine.binary_path",
                    path.display(),
                ), MAX_MERGE_DECISIONS);
            }
        }

        if let Some(raw) = env_lookup("FRANKEN_NODE_RUNTIME_REMOTE_MAX_IN_FLIGHT") {
            let parsed = parse_env_usize("FRANKEN_NODE_RUNTIME_REMOTE_MAX_IN_FLIGHT", &raw)?;
            self.runtime.remote_max_in_flight = parsed;
            push_bounded(&mut decisions, MergeDecision::new(
                MergeStage::Env,
                "runtime.remote_max_in_flight",
                parsed,
            ));
        }
        if let Some(raw) = env_lookup("FRANKEN_NODE_RUNTIME_BULKHEAD_RETRY_AFTER_MS") {
            let parsed = parse_env_u64("FRANKEN_NODE_RUNTIME_BULKHEAD_RETRY_AFTER_MS", &raw)?;
            self.runtime.bulkhead_retry_after_ms = parsed;
            push_bounded(&mut decisions, MergeDecision::new(
                MergeStage::Env,
                "runtime.bulkhead_retry_after_ms",
                parsed,
            ));
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
            push_bounded(&mut decisions, MergeDecision::new(
                MergeStage::Env,
                "runtime.preferred",
                parsed,
            ));
        }
        if let Some(raw) = env_lookup("FRANKEN_NODE_RUNTIME_DRAIN_TIMEOUT_MS") {
            let parsed = parse_env_u64("FRANKEN_NODE_RUNTIME_DRAIN_TIMEOUT_MS", &raw)?;
            self.runtime.drain_timeout_ms = Some(parsed);
            push_bounded(&mut decisions, MergeDecision::new(
                MergeStage::Env,
                "runtime.drain_timeout_ms",
                parsed,
            ));
        }

        apply_env_field_opt_f64(
            "FRANKEN_NODE_THRESHOLDS_MAX_FAILURE_RATE",
            env_lookup,
            &mut self.thresholds.max_failure_rate,
            "thresholds.max_failure_rate",
            decisions,
        )?;
        apply_env_field_opt_f64(
            "FRANKEN_NODE_THRESHOLDS_MIN_QUALITY_SCORE",
            env_lookup,
            &mut self.thresholds.min_quality_score,
            "thresholds.min_quality_score",
            decisions,
        )?;
        apply_env_field_opt_f64(
            "FRANKEN_NODE_THRESHOLDS_MAX_VARIANCE_PCT",
            env_lookup,
            &mut self.thresholds.max_variance_pct,
            "thresholds.max_variance_pct",
            decisions,
        )?;
        apply_env_field_opt_f64(
            "FRANKEN_NODE_THRESHOLDS_REGRESSION_THRESHOLD_PCT",
            env_lookup,
            &mut self.thresholds.regression_threshold_pct,
            "thresholds.regression_threshold_pct",
            decisions,
        )?;
        apply_env_field_opt_f64(
            "FRANKEN_NODE_THRESHOLDS_MIN_RESILIENCE_SCORE",
            env_lookup,
            &mut self.thresholds.min_resilience_score,
            "thresholds.min_resilience_score",
            decisions,
        )?;

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
        push_bounded(&mut decisions, MergeDecision::new(MergeStage::Env, field, parsed), MAX_MERGE_DECISIONS);
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
) -> Result<(), ConfigError> {
    if let Some(raw) = env_lookup(key) {
        let parsed = parse_env_f64(key, &raw)?;
        *slot = Some(parsed);
        push_bounded(&mut decisions, MergeDecision::new(MergeStage::Env, field, parsed), MAX_MERGE_DECISIONS);
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
    /// TTL for signed compatibility receipts (seconds).
    pub default_receipt_ttl_secs: u64,
    /// Optional override for compat-gate TTL (seconds).
    /// When `None`, consumers use `COMPAT_DEFAULT_TTL_SECS` (3600).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gate_ttl_secs: Option<u64>,
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
pub struct TrustConfig {
    /// Risky actions require fresh revocation checks.
    pub risky_requires_fresh_revocation: bool,
    /// Dangerous actions always require fresh revocation checks.
    pub dangerous_requires_fresh_revocation: bool,
    /// Automatically quarantine high-risk extensions.
    pub quarantine_on_high_risk: bool,
    /// Optional override for trust-card cache TTL (seconds).
    /// When `None`, consumers use `DEFAULT_CACHE_TTL_SECS` (60).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub card_cache_ttl_secs: Option<u64>,
    /// Optional override for trust freshness window (seconds).
    /// When `None`, consumers use `30 * 24 * 3600` (30 days).
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
    /// When `None`, consumers use `MAX_REPLAY_CAPSULE_FRESHNESS_SECS` (3600).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capsule_freshness_secs: Option<u64>,
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
    /// When `None`, consumers use `DEFAULT_BARRIER_TIMEOUT_MS` (30000).
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

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum PreferredRuntime {
    #[default]
    Auto,
    Node,
    Bun,
    FrankenEngine,
}

impl PreferredRuntime {
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
    /// When `None`, consumers use `DEFAULT_DRAIN_TIMEOUT_MS` (30000).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub drain_timeout_ms: Option<u64>,
}

impl RuntimeConfig {
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

// -- Thresholds --

/// Algorithmic and statistical threshold constants that don't fit in a
/// specific section. All fields are optional; when `None` consumers fall
/// back to their compile-time defaults.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct ThresholdsConfig {
    /// Maximum tolerable failure rate.
    /// When `None`, consumers use the default (0.05).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_failure_rate: Option<f64>,
    /// Minimum quality score for acceptance.
    /// When `None`, consumers use the default (0.8).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_quality_score: Option<f64>,
    /// Maximum acceptable variance percentage.
    /// When `None`, consumers use the default (5.0).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_variance_pct: Option<f64>,
    /// Regression detection threshold percentage.
    /// When `None`, consumers use the default (10.0).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub regression_threshold_pct: Option<f64>,
    /// Minimum resilience score for healthy status.
    /// When `None`, consumers use the default (0.7).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_resilience_score: Option<f64>,
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

    #[error("invalid preferred runtime: {0} (expected: auto, node, bun, franken-engine)")]
    InvalidPreferredRuntime(String),

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
    use std::collections::BTreeMap;

    use super::*;

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
        assert_eq!(config.engine.binary_path, None);
        assert_eq!(config.runtime.preferred, PreferredRuntime::Auto);
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
        let mut config = Config::for_profile(Profile::Balanced);
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
    fn validate_score_and_percentage_reject_out_of_range_values() {
        assert!(validate_opt_score("trust.min_trust_score", Some(-0.01)).is_err());
        assert!(validate_opt_score("trust.min_trust_score", Some(1.01)).is_err());
        assert!(validate_opt_pct("thresholds.max_variance_pct", Some(-0.01)).is_err());
        assert!(validate_opt_pct("thresholds.max_variance_pct", Some(100.01)).is_err());
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
    fn config_degraded_mode_policy_factory_applies_security_ttl() {
        let mut config = Config::for_profile(Profile::Balanced);
        config.security.max_degraded_duration_secs = 91;

        let policy = config.degraded_mode_policy("trust-input-stale");

        assert_eq!(policy.max_degraded_duration_secs, 91);
    }

    #[cfg(feature = "extended-surfaces")]
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
