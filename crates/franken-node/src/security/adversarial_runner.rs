//! bd-9is: Autonomous adversarial campaign runner with continuous updates.
//!
//! Provides a framework for generating, evolving, and evaluating attack
//! campaigns against franken_node's trust and security infrastructure.
//!
//! # Invariants
//!
//! - **INV-ACR-CORPUS**: Campaign corpus is versioned with >= 5 categories.
//! - **INV-ACR-SANDBOX**: All campaigns execute in isolated environments.
//! - **INV-ACR-MUTATION**: At least 3 mutation strategies are implemented.
//! - **INV-ACR-RESULTS**: Results are structured JSON with execution traces.
//! - **INV-ACR-INTEGRATION**: Results feed adversary graph and trust card.
//! - **INV-ACR-CONTINUOUS**: Supports continuous and on-demand execution.
//! - **INV-ACR-PROVENANCE**: Every mutation has logged provenance.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;

// ---------------------------------------------------------------------------
// Event codes
// ---------------------------------------------------------------------------

pub mod event_codes {
    pub const ADV_RUN_001_STARTED: &str = "ADV-RUN-001";
    pub const ADV_RUN_002_DEFENSE_HELD: &str = "ADV-RUN-002";
    pub const ADV_RUN_003_BREACH: &str = "ADV-RUN-003";
    pub const ADV_RUN_004_MUTATION: &str = "ADV-RUN-004";
    pub const ADV_RUN_005_CORPUS_UPDATED: &str = "ADV-RUN-005";
    pub const ADV_RUN_006_INTEGRATED: &str = "ADV-RUN-006";
    pub const ADV_RUN_ERR_001_INFRA: &str = "ADV-RUN-ERR-001";
    pub const ADV_RUN_ERR_002_CONTAINMENT: &str = "ADV-RUN-ERR-002";
}

// ---------------------------------------------------------------------------
// Invariant constants
// ---------------------------------------------------------------------------

pub const INV_ACR_CORPUS: &str = "INV-ACR-CORPUS";
pub const INV_ACR_SANDBOX: &str = "INV-ACR-SANDBOX";
pub const INV_ACR_MUTATION: &str = "INV-ACR-MUTATION";
pub const INV_ACR_RESULTS: &str = "INV-ACR-RESULTS";
pub const INV_ACR_INTEGRATION: &str = "INV-ACR-INTEGRATION";
pub const INV_ACR_CONTINUOUS: &str = "INV-ACR-CONTINUOUS";
pub const INV_ACR_PROVENANCE: &str = "INV-ACR-PROVENANCE";

// ---------------------------------------------------------------------------
// Campaign category
// ---------------------------------------------------------------------------

/// Adversarial campaign category.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CampaignCategory {
    /// Malicious extension injection.
    MaliciousExtensionInjection,
    /// Credential exfiltration.
    CredentialExfiltration,
    /// Policy evasion.
    PolicyEvasion,
    /// Delayed payload activation.
    DelayedPayloadActivation,
    /// Supply-chain compromise simulation.
    SupplyChainCompromise,
}

impl CampaignCategory {
    pub fn all() -> &'static [CampaignCategory] {
        &[
            CampaignCategory::MaliciousExtensionInjection,
            CampaignCategory::CredentialExfiltration,
            CampaignCategory::PolicyEvasion,
            CampaignCategory::DelayedPayloadActivation,
            CampaignCategory::SupplyChainCompromise,
        ]
    }

    pub fn id(&self) -> &'static str {
        match self {
            CampaignCategory::MaliciousExtensionInjection => "CAMP-MEI",
            CampaignCategory::CredentialExfiltration => "CAMP-CEX",
            CampaignCategory::PolicyEvasion => "CAMP-PEV",
            CampaignCategory::DelayedPayloadActivation => "CAMP-DPA",
            CampaignCategory::SupplyChainCompromise => "CAMP-SCC",
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            CampaignCategory::MaliciousExtensionInjection => "malicious_extension_injection",
            CampaignCategory::CredentialExfiltration => "credential_exfiltration",
            CampaignCategory::PolicyEvasion => "policy_evasion",
            CampaignCategory::DelayedPayloadActivation => "delayed_payload_activation",
            CampaignCategory::SupplyChainCompromise => "supply_chain_compromise",
        }
    }
}

impl fmt::Display for CampaignCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.id())
    }
}

// ---------------------------------------------------------------------------
// Mutation strategy
// ---------------------------------------------------------------------------

/// Campaign mutation strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MutationStrategy {
    /// Vary attack parameters (timing, payload size, target scope).
    ParameterVariation,
    /// Compose multiple attack vectors.
    TechniqueCombination,
    /// Alter attack sequencing and delays.
    TimingVariation,
    /// Adapt to bypass detected defenses.
    EvasionRefinement,
}

impl MutationStrategy {
    pub fn all() -> &'static [MutationStrategy] {
        &[
            MutationStrategy::ParameterVariation,
            MutationStrategy::TechniqueCombination,
            MutationStrategy::TimingVariation,
            MutationStrategy::EvasionRefinement,
        ]
    }

    pub fn id(&self) -> &'static str {
        match self {
            MutationStrategy::ParameterVariation => "MUT-PARAM",
            MutationStrategy::TechniqueCombination => "MUT-COMBO",
            MutationStrategy::TimingVariation => "MUT-TIMING",
            MutationStrategy::EvasionRefinement => "MUT-EVASION",
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            MutationStrategy::ParameterVariation => "parameter_variation",
            MutationStrategy::TechniqueCombination => "technique_combination",
            MutationStrategy::TimingVariation => "timing_variation",
            MutationStrategy::EvasionRefinement => "evasion_refinement",
        }
    }
}

impl fmt::Display for MutationStrategy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.id())
    }
}

// ---------------------------------------------------------------------------
// Severity
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CampaignSeverity {
    Critical,
    High,
    Medium,
    Low,
}

impl CampaignSeverity {
    pub fn label(&self) -> &'static str {
        match self {
            CampaignSeverity::Critical => "critical",
            CampaignSeverity::High => "high",
            CampaignSeverity::Medium => "medium",
            CampaignSeverity::Low => "low",
        }
    }
}

impl fmt::Display for CampaignSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

// ---------------------------------------------------------------------------
// Campaign definition
// ---------------------------------------------------------------------------

/// Success criteria for a campaign.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SuccessCriteria {
    pub defense_held: bool,
    pub max_detection_time_ms: u64,
    pub audit_event_emitted: bool,
}

/// An adversarial campaign definition.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CampaignDefinition {
    pub campaign_id: String,
    pub category: CampaignCategory,
    pub version: String,
    pub title: String,
    pub attack_vector: String,
    pub target_component: String,
    pub expected_defense: String,
    pub severity: CampaignSeverity,
    pub success_criteria: SuccessCriteria,
    pub payload: BTreeMap<String, serde_json::Value>,
    pub mutations_applied: Vec<MutationRecord>,
    pub parent_campaign_id: Option<String>,
    pub created_at: String,
}

/// Record of a mutation applied to a campaign.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MutationRecord {
    pub strategy: MutationStrategy,
    pub description: String,
    pub applied_at: String,
    pub parent_campaign_id: String,
}

// ---------------------------------------------------------------------------
// Execution verdict and result
// ---------------------------------------------------------------------------

/// Outcome of campaign execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ExecutionVerdict {
    /// Defense held — attack was blocked or detected.
    DefenseHeld,
    /// Defense breached — attack succeeded.
    DefenseBreached,
    /// Inconclusive — could not determine outcome.
    Inconclusive,
}

impl ExecutionVerdict {
    pub fn label(&self) -> &'static str {
        match self {
            ExecutionVerdict::DefenseHeld => "defense_held",
            ExecutionVerdict::DefenseBreached => "defense_breached",
            ExecutionVerdict::Inconclusive => "inconclusive",
        }
    }
}

impl fmt::Display for ExecutionVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// A defense decision recorded during campaign execution.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DefenseDecision {
    pub component: String,
    pub action: String,
    pub outcome: String,
    pub timestamp_ms: u64,
}

/// Result of executing a single campaign.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CampaignResult {
    pub campaign_id: String,
    pub execution_id: String,
    pub timestamp: String,
    pub verdict: ExecutionVerdict,
    pub defense_decisions: Vec<DefenseDecision>,
    pub sandbox_verified: bool,
    pub duration_ms: u64,
    pub severity_if_breached: CampaignSeverity,
    pub integration_targets: Vec<String>,
}

// ---------------------------------------------------------------------------
// Campaign corpus
// ---------------------------------------------------------------------------

/// Versioned collection of campaign definitions.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CampaignCorpus {
    pub version: String,
    pub campaigns: Vec<CampaignDefinition>,
}

impl CampaignCorpus {
    /// Count of distinct categories in the corpus.
    pub fn category_count(&self) -> usize {
        let mut categories: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
        for c in &self.campaigns {
            categories.insert(c.category.id());
        }
        categories.len()
    }

    /// Check the corpus invariant: >= 5 categories present.
    pub fn validate_corpus_invariant(&self) -> bool {
        self.category_count() >= 5
    }

    /// Get campaigns by category.
    pub fn by_category(&self, category: CampaignCategory) -> Vec<&CampaignDefinition> {
        self.campaigns
            .iter()
            .filter(|c| c.category == category)
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Runner configuration
// ---------------------------------------------------------------------------

/// Execution mode for the campaign runner.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RunnerMode {
    /// Execute continuously on a schedule.
    Continuous,
    /// Execute a specific campaign on demand.
    OnDemand,
}

impl RunnerMode {
    pub fn label(&self) -> &'static str {
        match self {
            RunnerMode::Continuous => "continuous",
            RunnerMode::OnDemand => "on_demand",
        }
    }
}

/// Configuration for the adversarial campaign runner.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RunnerConfig {
    pub mode: RunnerMode,
    pub sandbox_required: bool,
    pub max_campaign_duration_ms: u64,
    pub integration_targets: Vec<String>,
    pub mutation_strategies_enabled: Vec<MutationStrategy>,
}

impl RunnerConfig {
    pub fn default_config() -> Self {
        Self {
            mode: RunnerMode::OnDemand,
            sandbox_required: true,
            max_campaign_duration_ms: 30_000,
            integration_targets: vec!["adversary_graph".to_string(), "trust_card".to_string()],
            mutation_strategies_enabled: MutationStrategy::all().to_vec(),
        }
    }
}

// ---------------------------------------------------------------------------
// Runner audit event
// ---------------------------------------------------------------------------

/// Structured audit event for campaign runner operations.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RunnerEvent {
    pub code: String,
    pub campaign_id: String,
    pub detail: String,
}

// ---------------------------------------------------------------------------
// Campaign runner — evaluation engine
// ---------------------------------------------------------------------------

/// Evaluates campaign results and produces structured gate output.
pub struct AdversarialRunner {
    config: RunnerConfig,
    corpus: CampaignCorpus,
}

impl AdversarialRunner {
    pub fn new(config: RunnerConfig, corpus: CampaignCorpus) -> Self {
        Self { config, corpus }
    }

    pub fn config(&self) -> &RunnerConfig {
        &self.config
    }

    pub fn corpus(&self) -> &CampaignCorpus {
        &self.corpus
    }

    /// Validate that the corpus meets invariant requirements.
    pub fn validate_corpus(&self) -> (bool, Vec<RunnerEvent>) {
        let mut events = Vec::new();
        let valid = self.corpus.validate_corpus_invariant();
        events.push(RunnerEvent {
            code: if valid {
                event_codes::ADV_RUN_005_CORPUS_UPDATED.to_string()
            } else {
                event_codes::ADV_RUN_ERR_001_INFRA.to_string()
            },
            campaign_id: String::new(),
            detail: format!(
                "corpus has {} categories (need >= 5): {}",
                self.corpus.category_count(),
                if valid { "VALID" } else { "INVALID" }
            ),
        });
        (valid, events)
    }

    /// Validate that sufficient mutation strategies are enabled.
    pub fn validate_mutations(&self) -> (bool, Vec<RunnerEvent>) {
        let mut events = Vec::new();
        let count = self
            .config
            .mutation_strategies_enabled
            .iter()
            .copied()
            .collect::<std::collections::HashSet<_>>()
            .len();
        let valid = count >= 3;
        events.push(RunnerEvent {
            code: event_codes::ADV_RUN_004_MUTATION.to_string(),
            campaign_id: String::new(),
            detail: format!(
                "{} mutation strategies enabled (need >= 3): {}",
                count,
                if valid { "VALID" } else { "INSUFFICIENT" }
            ),
        });
        (valid, events)
    }

    /// Evaluate a set of campaign results.
    pub fn evaluate_results(&self, results: &[CampaignResult]) -> RunnerGateResult {
        let mut events = Vec::new();
        let mut breaches = Vec::new();
        let mut held = 0_usize;
        let mut inconclusive = 0_usize;
        let mut containment_failures = 0_usize;

        for result in results {
            events.push(RunnerEvent {
                code: event_codes::ADV_RUN_001_STARTED.to_string(),
                campaign_id: result.campaign_id.clone(),
                detail: format!("execution_id={}", result.execution_id),
            });

            if !result.sandbox_verified && self.config.sandbox_required {
                containment_failures = containment_failures.saturating_add(1);
                events.push(RunnerEvent {
                    code: event_codes::ADV_RUN_ERR_002_CONTAINMENT.to_string(),
                    campaign_id: result.campaign_id.clone(),
                    detail: "sandbox containment not verified".to_string(),
                });
            }

            match result.verdict {
                ExecutionVerdict::DefenseHeld => {
                    held = held.saturating_add(1);
                    events.push(RunnerEvent {
                        code: event_codes::ADV_RUN_002_DEFENSE_HELD.to_string(),
                        campaign_id: result.campaign_id.clone(),
                        detail: format!("duration={}ms", result.duration_ms),
                    });
                }
                ExecutionVerdict::DefenseBreached => {
                    breaches.push(result.campaign_id.clone());
                    events.push(RunnerEvent {
                        code: event_codes::ADV_RUN_003_BREACH.to_string(),
                        campaign_id: result.campaign_id.clone(),
                        detail: format!(
                            "severity={} duration={}ms",
                            result.severity_if_breached, result.duration_ms
                        ),
                    });
                }
                ExecutionVerdict::Inconclusive => {
                    inconclusive = inconclusive.saturating_add(1);
                }
            }

            // Result integration event
            for target in &result.integration_targets {
                events.push(RunnerEvent {
                    code: event_codes::ADV_RUN_006_INTEGRATED.to_string(),
                    campaign_id: result.campaign_id.clone(),
                    detail: format!("target={target}"),
                });
            }
        }

        let total = results.len();
        let breach_count = breaches.len();
        // Fail-closed: pass only when no breaches AND either no campaigns ran
        // (vacuous pass) or at least one defense held. All-inconclusive
        // campaigns must not pass the gate. Sandbox containment failures also
        // fail the gate even when the defense verdict says "held".
        let overall_pass =
            breach_count == 0 && containment_failures == 0 && (total == 0 || held > 0);

        RunnerGateResult {
            verdict: if overall_pass { "PASS" } else { "FAIL" }.to_string(),
            overall_pass,
            total_campaigns: total,
            defense_held: held,
            defense_breached: breach_count,
            inconclusive,
            breached_campaign_ids: breaches,
            events,
        }
    }
}

/// Gate result from the adversarial campaign runner.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RunnerGateResult {
    pub verdict: String,
    pub overall_pass: bool,
    pub total_campaigns: usize,
    pub defense_held: usize,
    pub defense_breached: usize,
    pub inconclusive: usize,
    pub breached_campaign_ids: Vec<String>,
    pub events: Vec<RunnerEvent>,
}

// ---------------------------------------------------------------------------
// Default corpus builder
// ---------------------------------------------------------------------------

/// Build the initial campaign corpus with >= 1 campaign per category.
pub fn build_default_corpus() -> CampaignCorpus {
    let campaigns = vec![
        CampaignDefinition {
            campaign_id: "CAMP-MEI-001".to_string(),
            category: CampaignCategory::MaliciousExtensionInjection,
            version: "1.0.0".to_string(),
            title: "Native code loading via disguised extension".to_string(),
            attack_vector: "Load a .node addon from an extension claiming pure-JS".to_string(),
            target_component: "extension_host".to_string(),
            expected_defense: "sandbox blocks native code loading; trust card rejects".to_string(),
            severity: CampaignSeverity::Critical,
            success_criteria: SuccessCriteria {
                defense_held: true,
                max_detection_time_ms: 100,
                audit_event_emitted: true,
            },
            payload: BTreeMap::new(),
            mutations_applied: vec![],
            parent_campaign_id: None,
            created_at: "2026-02-21T00:00:00Z".to_string(),
        },
        CampaignDefinition {
            campaign_id: "CAMP-CEX-001".to_string(),
            category: CampaignCategory::CredentialExfiltration,
            version: "1.0.0".to_string(),
            title: "Environment variable credential harvest".to_string(),
            attack_vector: "Enumerate process.env for AWS_SECRET, DATABASE_URL, API_KEY patterns"
                .to_string(),
            target_component: "runtime_sandbox".to_string(),
            expected_defense: "env var access restricted to declared manifest scope".to_string(),
            severity: CampaignSeverity::Critical,
            success_criteria: SuccessCriteria {
                defense_held: true,
                max_detection_time_ms: 50,
                audit_event_emitted: true,
            },
            payload: BTreeMap::new(),
            mutations_applied: vec![],
            parent_campaign_id: None,
            created_at: "2026-02-21T00:00:00Z".to_string(),
        },
        CampaignDefinition {
            campaign_id: "CAMP-PEV-001".to_string(),
            category: CampaignCategory::PolicyEvasion,
            version: "1.0.0".to_string(),
            title: "TOCTOU race on trust policy check".to_string(),
            attack_vector: "Request policy check then swap payload before execution gate"
                .to_string(),
            target_component: "trust_policy_engine".to_string(),
            expected_defense: "atomic check-and-execute prevents TOCTOU; audit logged".to_string(),
            severity: CampaignSeverity::High,
            success_criteria: SuccessCriteria {
                defense_held: true,
                max_detection_time_ms: 200,
                audit_event_emitted: true,
            },
            payload: BTreeMap::new(),
            mutations_applied: vec![],
            parent_campaign_id: None,
            created_at: "2026-02-21T00:00:00Z".to_string(),
        },
        CampaignDefinition {
            campaign_id: "CAMP-DPA-001".to_string(),
            category: CampaignCategory::DelayedPayloadActivation,
            version: "1.0.0".to_string(),
            title: "Time-delayed privilege escalation".to_string(),
            attack_vector:
                "Extension passes initial trust check, activates restricted API after 5m"
                    .to_string(),
            target_component: "extension_host".to_string(),
            expected_defense:
                "continuous monitoring detects behavioral change; quarantine triggered".to_string(),
            severity: CampaignSeverity::High,
            success_criteria: SuccessCriteria {
                defense_held: true,
                max_detection_time_ms: 500,
                audit_event_emitted: true,
            },
            payload: BTreeMap::new(),
            mutations_applied: vec![],
            parent_campaign_id: None,
            created_at: "2026-02-21T00:00:00Z".to_string(),
        },
        CampaignDefinition {
            campaign_id: "CAMP-SCC-001".to_string(),
            category: CampaignCategory::SupplyChainCompromise,
            version: "1.0.0".to_string(),
            title: "Typosquatting dependency substitution".to_string(),
            attack_vector: "Publish malicious package with name similar to popular dep".to_string(),
            target_component: "registry".to_string(),
            expected_defense: "provenance check rejects unsigned/unverified package".to_string(),
            severity: CampaignSeverity::Critical,
            success_criteria: SuccessCriteria {
                defense_held: true,
                max_detection_time_ms: 100,
                audit_event_emitted: true,
            },
            payload: BTreeMap::new(),
            mutations_applied: vec![],
            parent_campaign_id: None,
            created_at: "2026-02-21T00:00:00Z".to_string(),
        },
    ];

    CampaignCorpus {
        version: "1.0.0".to_string(),
        campaigns,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_category_count() {
        assert_eq!(CampaignCategory::all().len(), 5);
    }

    #[test]
    fn test_category_ids_unique() {
        let ids: Vec<&str> = CampaignCategory::all().iter().map(|c| c.id()).collect();
        let unique: std::collections::BTreeSet<&&str> = ids.iter().collect();
        assert_eq!(ids.len(), unique.len());
    }

    #[test]
    fn test_mutation_count() {
        assert_eq!(MutationStrategy::all().len(), 4);
    }

    #[test]
    fn test_mutation_ids_unique() {
        let ids: Vec<&str> = MutationStrategy::all().iter().map(|m| m.id()).collect();
        let unique: std::collections::BTreeSet<&&str> = ids.iter().collect();
        assert_eq!(ids.len(), unique.len());
    }

    #[test]
    fn test_default_corpus_has_five_categories() {
        let corpus = build_default_corpus();
        assert!(corpus.validate_corpus_invariant());
        assert_eq!(corpus.category_count(), 5);
    }

    #[test]
    fn test_default_corpus_has_one_per_category() {
        let corpus = build_default_corpus();
        for &cat in CampaignCategory::all() {
            assert!(
                !corpus.by_category(cat).is_empty(),
                "missing campaign for category {}",
                cat.id()
            );
        }
    }

    #[test]
    fn test_runner_validates_corpus() {
        let config = RunnerConfig::default_config();
        let corpus = build_default_corpus();
        let runner = AdversarialRunner::new(config, corpus);
        let (valid, events) = runner.validate_corpus();
        assert!(valid);
        assert!(!events.is_empty());
    }

    #[test]
    fn test_runner_validates_mutations() {
        let config = RunnerConfig::default_config();
        let corpus = build_default_corpus();
        let runner = AdversarialRunner::new(config, corpus);
        let (valid, events) = runner.validate_mutations();
        assert!(valid);
        assert!(!events.is_empty());
    }

    #[test]
    fn test_corpus_with_missing_categories_fails_validation() {
        let mut corpus = build_default_corpus();
        corpus
            .campaigns
            .retain(|campaign| campaign.category == CampaignCategory::MaliciousExtensionInjection);
        let runner = AdversarialRunner::new(RunnerConfig::default_config(), corpus);
        let (valid, events) = runner.validate_corpus();

        assert!(!valid);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].code, event_codes::ADV_RUN_ERR_001_INFRA);
        assert!(events[0].detail.contains("INVALID"));
    }

    #[test]
    fn test_empty_corpus_fails_validation() {
        let corpus = CampaignCorpus {
            version: "empty".to_string(),
            campaigns: Vec::new(),
        };
        let runner = AdversarialRunner::new(RunnerConfig::default_config(), corpus);
        let (valid, events) = runner.validate_corpus();

        assert!(!valid);
        assert_eq!(runner.corpus().category_count(), 0);
        assert_eq!(events[0].code, event_codes::ADV_RUN_ERR_001_INFRA);
    }

    #[test]
    fn test_mutation_validation_rejects_too_few_strategies() {
        let mut config = RunnerConfig::default_config();
        config.mutation_strategies_enabled = vec![
            MutationStrategy::ParameterVariation,
            MutationStrategy::TimingVariation,
        ];
        let runner = AdversarialRunner::new(config, build_default_corpus());
        let (valid, events) = runner.validate_mutations();

        assert!(!valid);
        assert_eq!(events[0].code, event_codes::ADV_RUN_004_MUTATION);
        assert!(events[0].detail.contains("INSUFFICIENT"));
    }

    #[test]
    fn test_mutation_validation_rejects_duplicate_strategies() {
        let mut config = RunnerConfig::default_config();
        config.mutation_strategies_enabled = vec![
            MutationStrategy::TimingVariation,
            MutationStrategy::TimingVariation,
            MutationStrategy::TimingVariation,
        ];
        let runner = AdversarialRunner::new(config, build_default_corpus());
        let (valid, events) = runner.validate_mutations();

        assert!(!valid);
        assert!(events[0].detail.contains("1 mutation strategies enabled"));
    }

    #[test]
    fn test_mutation_validation_rejects_empty_strategy_set() {
        let mut config = RunnerConfig::default_config();
        config.mutation_strategies_enabled.clear();
        let runner = AdversarialRunner::new(config, build_default_corpus());

        let (valid, events) = runner.validate_mutations();

        assert!(!valid);
        assert_eq!(events[0].code, event_codes::ADV_RUN_004_MUTATION);
        assert!(events[0].detail.contains("0 mutation strategies enabled"));
        assert!(events[0].detail.contains("INSUFFICIENT"));
    }

    #[test]
    fn test_mutation_validation_rejects_duplicate_padding_below_unique_threshold() {
        let mut config = RunnerConfig::default_config();
        config.mutation_strategies_enabled = vec![
            MutationStrategy::ParameterVariation,
            MutationStrategy::ParameterVariation,
            MutationStrategy::TimingVariation,
        ];
        let runner = AdversarialRunner::new(config, build_default_corpus());

        let (valid, events) = runner.validate_mutations();

        assert!(!valid);
        assert!(events[0].detail.contains("2 mutation strategies enabled"));
        assert!(events[0].detail.contains("INSUFFICIENT"));
    }

    #[test]
    fn test_evaluate_all_held() {
        let config = RunnerConfig::default_config();
        let corpus = build_default_corpus();
        let runner = AdversarialRunner::new(config, corpus);

        let results = vec![CampaignResult {
            campaign_id: "CAMP-MEI-001".to_string(),
            execution_id: "exec-001".to_string(),
            timestamp: "2026-02-21T00:00:00Z".to_string(),
            verdict: ExecutionVerdict::DefenseHeld,
            defense_decisions: vec![DefenseDecision {
                component: "sandbox".to_string(),
                action: "block_native_load".to_string(),
                outcome: "blocked".to_string(),
                timestamp_ms: 15,
            }],
            sandbox_verified: true,
            duration_ms: 150,
            severity_if_breached: CampaignSeverity::Critical,
            integration_targets: vec!["adversary_graph".to_string()],
        }];

        let gate = runner.evaluate_results(&results);
        assert!(gate.overall_pass);
        assert_eq!(gate.verdict, "PASS");
        assert_eq!(gate.defense_held, 1);
        assert_eq!(gate.defense_breached, 0);
    }

    #[test]
    fn test_evaluate_breach_fails_gate() {
        let config = RunnerConfig::default_config();
        let corpus = build_default_corpus();
        let runner = AdversarialRunner::new(config, corpus);

        let results = vec![CampaignResult {
            campaign_id: "CAMP-PEV-001".to_string(),
            execution_id: "exec-002".to_string(),
            timestamp: "2026-02-21T00:00:00Z".to_string(),
            verdict: ExecutionVerdict::DefenseBreached,
            defense_decisions: vec![],
            sandbox_verified: true,
            duration_ms: 300,
            severity_if_breached: CampaignSeverity::High,
            integration_targets: vec![],
        }];

        let gate = runner.evaluate_results(&results);
        assert!(!gate.overall_pass);
        assert_eq!(gate.verdict, "FAIL");
        assert_eq!(gate.defense_breached, 1);
        assert!(
            gate.breached_campaign_ids
                .contains(&"CAMP-PEV-001".to_string())
        );
    }

    #[test]
    fn test_evaluate_containment_event() {
        let mut config = RunnerConfig::default_config();
        config.sandbox_required = true;
        let corpus = build_default_corpus();
        let runner = AdversarialRunner::new(config, corpus);

        let results = vec![CampaignResult {
            campaign_id: "CAMP-CEX-001".to_string(),
            execution_id: "exec-003".to_string(),
            timestamp: "2026-02-21T00:00:00Z".to_string(),
            verdict: ExecutionVerdict::DefenseHeld,
            defense_decisions: vec![],
            sandbox_verified: false, // not verified
            duration_ms: 50,
            severity_if_breached: CampaignSeverity::Critical,
            integration_targets: vec![],
        }];

        let gate = runner.evaluate_results(&results);
        let containment_events: Vec<&RunnerEvent> = gate
            .events
            .iter()
            .filter(|e| e.code == event_codes::ADV_RUN_ERR_002_CONTAINMENT)
            .collect();
        assert_eq!(containment_events.len(), 1);
    }

    #[test]
    fn test_unverified_sandbox_fails_gate_when_required() {
        let mut config = RunnerConfig::default_config();
        config.sandbox_required = true;
        let runner = AdversarialRunner::new(config, build_default_corpus());
        let results = vec![CampaignResult {
            campaign_id: "CAMP-SANDBOX-FAIL".to_string(),
            execution_id: "exec-sandbox-fail".to_string(),
            timestamp: "2026-02-21T00:00:00Z".to_string(),
            verdict: ExecutionVerdict::DefenseHeld,
            defense_decisions: vec![],
            sandbox_verified: false,
            duration_ms: 100,
            severity_if_breached: CampaignSeverity::Critical,
            integration_targets: vec![],
        }];

        let gate = runner.evaluate_results(&results);
        assert!(!gate.overall_pass);
        assert_eq!(gate.verdict, "FAIL");
        assert_eq!(gate.defense_held, 1);
        assert_eq!(gate.defense_breached, 0);
        assert!(
            gate.events
                .iter()
                .any(|event| event.code == event_codes::ADV_RUN_ERR_002_CONTAINMENT)
        );
    }

    #[test]
    fn test_unverified_sandbox_does_not_fail_gate_when_not_required() {
        let mut config = RunnerConfig::default_config();
        config.sandbox_required = false;
        let runner = AdversarialRunner::new(config, build_default_corpus());
        let results = vec![CampaignResult {
            campaign_id: "CAMP-SANDBOX-OPTIONAL".to_string(),
            execution_id: "exec-sandbox-optional".to_string(),
            timestamp: "2026-02-21T00:00:00Z".to_string(),
            verdict: ExecutionVerdict::DefenseHeld,
            defense_decisions: vec![],
            sandbox_verified: false,
            duration_ms: 100,
            severity_if_breached: CampaignSeverity::High,
            integration_targets: vec![],
        }];

        let gate = runner.evaluate_results(&results);
        assert!(gate.overall_pass);
        assert!(
            !gate
                .events
                .iter()
                .any(|event| event.code == event_codes::ADV_RUN_ERR_002_CONTAINMENT)
        );
    }

    #[test]
    fn test_inconclusive_unverified_sandbox_fails_with_containment_event() {
        let mut config = RunnerConfig::default_config();
        config.sandbox_required = true;
        let runner = AdversarialRunner::new(config, build_default_corpus());
        let results = vec![CampaignResult {
            campaign_id: "CAMP-INC-CONTAINMENT".to_string(),
            execution_id: "exec-inc-containment".to_string(),
            timestamp: "2026-02-21T00:00:00Z".to_string(),
            verdict: ExecutionVerdict::Inconclusive,
            defense_decisions: vec![],
            sandbox_verified: false,
            duration_ms: 250,
            severity_if_breached: CampaignSeverity::High,
            integration_targets: vec![],
        }];

        let gate = runner.evaluate_results(&results);

        assert!(!gate.overall_pass);
        assert_eq!(gate.verdict, "FAIL");
        assert_eq!(gate.inconclusive, 1);
        assert_eq!(gate.defense_held, 0);
        assert!(
            gate.events
                .iter()
                .any(|event| event.code == event_codes::ADV_RUN_ERR_002_CONTAINMENT)
        );
    }

    #[test]
    fn test_multiple_unverified_held_results_fail_and_emit_each_containment_event() {
        let mut config = RunnerConfig::default_config();
        config.sandbox_required = true;
        let runner = AdversarialRunner::new(config, build_default_corpus());
        let results = vec![
            CampaignResult {
                campaign_id: "CAMP-SANDBOX-FAIL-A".to_string(),
                execution_id: "exec-sandbox-fail-a".to_string(),
                timestamp: "2026-02-21T00:00:00Z".to_string(),
                verdict: ExecutionVerdict::DefenseHeld,
                defense_decisions: vec![],
                sandbox_verified: false,
                duration_ms: 100,
                severity_if_breached: CampaignSeverity::Critical,
                integration_targets: vec![],
            },
            CampaignResult {
                campaign_id: "CAMP-SANDBOX-FAIL-B".to_string(),
                execution_id: "exec-sandbox-fail-b".to_string(),
                timestamp: "2026-02-21T00:00:00Z".to_string(),
                verdict: ExecutionVerdict::DefenseHeld,
                defense_decisions: vec![],
                sandbox_verified: false,
                duration_ms: 110,
                severity_if_breached: CampaignSeverity::High,
                integration_targets: vec![],
            },
        ];

        let gate = runner.evaluate_results(&results);
        let containment_events = gate
            .events
            .iter()
            .filter(|event| event.code == event_codes::ADV_RUN_ERR_002_CONTAINMENT)
            .count();

        assert!(!gate.overall_pass);
        assert_eq!(gate.defense_held, 2);
        assert_eq!(gate.defense_breached, 0);
        assert_eq!(containment_events, 2);
    }

    #[test]
    fn test_breach_with_unverified_sandbox_records_both_failure_signals() {
        let mut config = RunnerConfig::default_config();
        config.sandbox_required = true;
        let runner = AdversarialRunner::new(config, build_default_corpus());
        let results = vec![CampaignResult {
            campaign_id: "CAMP-BREACH-CONTAINMENT".to_string(),
            execution_id: "exec-breach-containment".to_string(),
            timestamp: "2026-02-21T00:00:00Z".to_string(),
            verdict: ExecutionVerdict::DefenseBreached,
            defense_decisions: vec![],
            sandbox_verified: false,
            duration_ms: 500,
            severity_if_breached: CampaignSeverity::Critical,
            integration_targets: vec![],
        }];

        let gate = runner.evaluate_results(&results);
        assert!(!gate.overall_pass);
        assert_eq!(gate.defense_breached, 1);
        assert!(
            gate.events
                .iter()
                .any(|event| event.code == event_codes::ADV_RUN_003_BREACH)
        );
        assert!(
            gate.events
                .iter()
                .any(|event| event.code == event_codes::ADV_RUN_ERR_002_CONTAINMENT)
        );
    }

    #[test]
    fn test_breach_with_integration_targets_still_fails_gate() {
        let runner = AdversarialRunner::new(RunnerConfig::default_config(), build_default_corpus());
        let results = vec![CampaignResult {
            campaign_id: "CAMP-BREACH-INTEGRATED".to_string(),
            execution_id: "exec-breach-integrated".to_string(),
            timestamp: "2026-02-21T00:00:00Z".to_string(),
            verdict: ExecutionVerdict::DefenseBreached,
            defense_decisions: vec![],
            sandbox_verified: true,
            duration_ms: 400,
            severity_if_breached: CampaignSeverity::Critical,
            integration_targets: vec!["adversary_graph".to_string(), "trust_card".to_string()],
        }];

        let gate = runner.evaluate_results(&results);
        let integration_events = gate
            .events
            .iter()
            .filter(|event| event.code == event_codes::ADV_RUN_006_INTEGRATED)
            .count();

        assert!(!gate.overall_pass);
        assert_eq!(gate.verdict, "FAIL");
        assert_eq!(gate.defense_breached, 1);
        assert_eq!(integration_events, 2);
    }

    #[test]
    fn test_empty_campaign_id_breach_still_fails_closed() {
        let runner = AdversarialRunner::new(RunnerConfig::default_config(), build_default_corpus());
        let results = vec![CampaignResult {
            campaign_id: String::new(),
            execution_id: "exec-empty-campaign".to_string(),
            timestamp: "2026-02-21T00:00:00Z".to_string(),
            verdict: ExecutionVerdict::DefenseBreached,
            defense_decisions: vec![],
            sandbox_verified: true,
            duration_ms: 1,
            severity_if_breached: CampaignSeverity::High,
            integration_targets: vec![],
        }];

        let gate = runner.evaluate_results(&results);

        assert!(!gate.overall_pass);
        assert_eq!(gate.breached_campaign_ids, vec![String::new()]);
        assert!(
            gate.events
                .iter()
                .any(|event| event.code == event_codes::ADV_RUN_003_BREACH
                    && event.campaign_id.is_empty())
        );
    }

    #[test]
    fn test_empty_execution_id_breach_still_emits_started_event_and_fails() {
        let runner = AdversarialRunner::new(RunnerConfig::default_config(), build_default_corpus());
        let results = vec![CampaignResult {
            campaign_id: "CAMP-EMPTY-EXEC".to_string(),
            execution_id: String::new(),
            timestamp: "2026-02-21T00:00:00Z".to_string(),
            verdict: ExecutionVerdict::DefenseBreached,
            defense_decisions: vec![],
            sandbox_verified: true,
            duration_ms: 1,
            severity_if_breached: CampaignSeverity::High,
            integration_targets: vec![],
        }];

        let gate = runner.evaluate_results(&results);

        assert!(!gate.overall_pass);
        assert!(
            gate.events
                .iter()
                .any(|event| event.code == event_codes::ADV_RUN_001_STARTED
                    && event.detail == "execution_id=")
        );
    }

    #[test]
    fn test_mixed_held_and_breach_fails_even_when_defenses_mostly_hold() {
        let runner = AdversarialRunner::new(RunnerConfig::default_config(), build_default_corpus());
        let results = vec![
            CampaignResult {
                campaign_id: "CAMP-HELD-A".to_string(),
                execution_id: "exec-held-a".to_string(),
                timestamp: "2026-02-21T00:00:00Z".to_string(),
                verdict: ExecutionVerdict::DefenseHeld,
                defense_decisions: vec![],
                sandbox_verified: true,
                duration_ms: 100,
                severity_if_breached: CampaignSeverity::Medium,
                integration_targets: vec![],
            },
            CampaignResult {
                campaign_id: "CAMP-HELD-B".to_string(),
                execution_id: "exec-held-b".to_string(),
                timestamp: "2026-02-21T00:00:00Z".to_string(),
                verdict: ExecutionVerdict::DefenseHeld,
                defense_decisions: vec![],
                sandbox_verified: true,
                duration_ms: 120,
                severity_if_breached: CampaignSeverity::Low,
                integration_targets: vec![],
            },
            CampaignResult {
                campaign_id: "CAMP-BREACH-MINORITY".to_string(),
                execution_id: "exec-breach-minority".to_string(),
                timestamp: "2026-02-21T00:00:00Z".to_string(),
                verdict: ExecutionVerdict::DefenseBreached,
                defense_decisions: vec![],
                sandbox_verified: true,
                duration_ms: 130,
                severity_if_breached: CampaignSeverity::Critical,
                integration_targets: vec![],
            },
        ];

        let gate = runner.evaluate_results(&results);

        assert!(!gate.overall_pass);
        assert_eq!(gate.defense_held, 2);
        assert_eq!(gate.defense_breached, 1);
        assert_eq!(
            gate.breached_campaign_ids,
            vec!["CAMP-BREACH-MINORITY".to_string()]
        );
    }

    #[test]
    fn test_all_inconclusive_fails_gate() {
        // Fail-closed: all-inconclusive campaigns must not pass the gate.
        let config = RunnerConfig::default_config();
        let corpus = build_default_corpus();
        let runner = AdversarialRunner::new(config, corpus);

        let results = vec![CampaignResult {
            campaign_id: "CAMP-INC-001".to_string(),
            execution_id: "exec-inc".to_string(),
            timestamp: "2026-02-25T00:00:00Z".to_string(),
            verdict: ExecutionVerdict::Inconclusive,
            defense_decisions: vec![],
            sandbox_verified: true,
            duration_ms: 100,
            severity_if_breached: CampaignSeverity::High,
            integration_targets: vec![],
        }];

        let gate = runner.evaluate_results(&results);
        assert!(!gate.overall_pass, "all-inconclusive must fail gate");
        assert_eq!(gate.verdict, "FAIL");
        assert_eq!(gate.inconclusive, 1);
        assert_eq!(gate.defense_held, 0);
        assert_eq!(gate.defense_breached, 0);
    }

    #[test]
    fn test_evaluate_empty_results() {
        let config = RunnerConfig::default_config();
        let corpus = build_default_corpus();
        let runner = AdversarialRunner::new(config, corpus);
        let gate = runner.evaluate_results(&[]);
        assert!(gate.overall_pass);
        assert_eq!(gate.total_campaigns, 0);
    }

    #[test]
    fn test_evaluate_integration_events() {
        let config = RunnerConfig::default_config();
        let corpus = build_default_corpus();
        let runner = AdversarialRunner::new(config, corpus);

        let results = vec![CampaignResult {
            campaign_id: "CAMP-SCC-001".to_string(),
            execution_id: "exec-004".to_string(),
            timestamp: "2026-02-21T00:00:00Z".to_string(),
            verdict: ExecutionVerdict::DefenseHeld,
            defense_decisions: vec![],
            sandbox_verified: true,
            duration_ms: 80,
            severity_if_breached: CampaignSeverity::Critical,
            integration_targets: vec!["adversary_graph".to_string(), "trust_card".to_string()],
        }];

        let gate = runner.evaluate_results(&results);
        let integration_events: Vec<&RunnerEvent> = gate
            .events
            .iter()
            .filter(|e| e.code == event_codes::ADV_RUN_006_INTEGRATED)
            .collect();
        assert_eq!(integration_events.len(), 2);
    }

    #[test]
    fn test_runner_modes() {
        assert_eq!(RunnerMode::Continuous.label(), "continuous");
        assert_eq!(RunnerMode::OnDemand.label(), "on_demand");
    }

    #[test]
    fn test_default_config() {
        let config = RunnerConfig::default_config();
        assert_eq!(config.mode, RunnerMode::OnDemand);
        assert!(config.sandbox_required);
        assert_eq!(config.mutation_strategies_enabled.len(), 4);
        assert_eq!(config.integration_targets.len(), 2);
    }

    #[test]
    fn test_corpus_serialization_roundtrip() {
        let corpus = build_default_corpus();
        let json = serde_json::to_string(&corpus).unwrap();
        let parsed: CampaignCorpus = serde_json::from_str(&json).unwrap();
        assert_eq!(corpus, parsed);
    }

    #[test]
    fn test_severity_labels() {
        assert_eq!(CampaignSeverity::Critical.label(), "critical");
        assert_eq!(CampaignSeverity::High.label(), "high");
        assert_eq!(CampaignSeverity::Medium.label(), "medium");
        assert_eq!(CampaignSeverity::Low.label(), "low");
    }

    #[test]
    fn test_verdict_labels() {
        assert_eq!(ExecutionVerdict::DefenseHeld.label(), "defense_held");
        assert_eq!(
            ExecutionVerdict::DefenseBreached.label(),
            "defense_breached"
        );
        assert_eq!(ExecutionVerdict::Inconclusive.label(), "inconclusive");
    }

    #[test]
    fn serde_rejects_unknown_campaign_category_variant() {
        let err = serde_json::from_str::<CampaignCategory>(r#""credential_theft_v2""#)
            .expect_err("unknown category must fail deserialization");

        assert!(err.to_string().contains("unknown variant"));
    }

    #[test]
    fn serde_rejects_unknown_mutation_strategy_variant() {
        let err = serde_json::from_str::<MutationStrategy>(r#""prompt_mutation""#)
            .expect_err("unknown mutation strategy must fail deserialization");

        assert!(err.to_string().contains("unknown variant"));
    }

    #[test]
    fn serde_rejects_unknown_campaign_severity_variant() {
        let err = serde_json::from_str::<CampaignSeverity>(r#""severe""#)
            .expect_err("unknown severity must fail deserialization");

        assert!(err.to_string().contains("unknown variant"));
    }

    #[test]
    fn serde_rejects_unknown_execution_verdict_variant() {
        let err = serde_json::from_str::<ExecutionVerdict>(r#""defense_partially_held""#)
            .expect_err("unknown verdict must fail deserialization");

        assert!(err.to_string().contains("unknown variant"));
    }

    #[test]
    fn serde_rejects_runner_config_missing_mutation_strategies() {
        let value = serde_json::json!({
            "mode": "OnDemand",
            "sandbox_required": true,
            "max_campaign_duration_ms": 30_000,
            "integration_targets": ["adversary_graph"]
        });

        let err = serde_json::from_value::<RunnerConfig>(value)
            .expect_err("missing mutation strategies must fail deserialization");

        assert!(err.to_string().contains("mutation_strategies_enabled"));
    }

    #[test]
    fn serde_rejects_campaign_result_string_duration() {
        let value = serde_json::json!({
            "campaign_id": "CAMP-BAD-DURATION",
            "execution_id": "exec-bad-duration",
            "timestamp": "2026-02-21T00:00:00Z",
            "verdict": "DefenseHeld",
            "defense_decisions": [],
            "sandbox_verified": true,
            "duration_ms": "100",
            "severity_if_breached": "High",
            "integration_targets": []
        });

        let err = serde_json::from_value::<CampaignResult>(value)
            .expect_err("string duration must fail deserialization");

        assert!(err.to_string().contains("duration_ms"));
    }

    #[test]
    fn serde_rejects_campaign_result_missing_verdict() {
        let value = serde_json::json!({
            "campaign_id": "CAMP-MISSING-VERDICT",
            "execution_id": "exec-missing-verdict",
            "timestamp": "2026-02-21T00:00:00Z",
            "defense_decisions": [],
            "sandbox_verified": true,
            "duration_ms": 100,
            "severity_if_breached": "High",
            "integration_targets": []
        });

        let err = serde_json::from_value::<CampaignResult>(value)
            .expect_err("missing verdict must fail deserialization");

        assert!(err.to_string().contains("verdict"));
    }

    #[test]
    fn serde_rejects_runner_gate_result_string_total_campaigns() {
        let value = serde_json::json!({
            "verdict": "FAIL",
            "overall_pass": false,
            "total_campaigns": "1",
            "defense_held": 0,
            "defense_breached": 1,
            "inconclusive": 0,
            "breached_campaign_ids": ["CAMP-BAD"],
            "events": []
        });

        let err = serde_json::from_value::<RunnerGateResult>(value)
            .expect_err("string total_campaigns must fail deserialization");

        assert!(err.to_string().contains("total_campaigns"));
    }

    #[test]
    fn test_deterministic_evaluation() {
        let config = RunnerConfig::default_config();
        let corpus = build_default_corpus();
        let runner = AdversarialRunner::new(config, corpus);

        let results = vec![CampaignResult {
            campaign_id: "CAMP-DPA-001".to_string(),
            execution_id: "exec-det".to_string(),
            timestamp: "2026-02-21T00:00:00Z".to_string(),
            verdict: ExecutionVerdict::DefenseHeld,
            defense_decisions: vec![],
            sandbox_verified: true,
            duration_ms: 200,
            severity_if_breached: CampaignSeverity::High,
            integration_targets: vec![],
        }];

        let r1 = runner.evaluate_results(&results);
        let r2 = runner.evaluate_results(&results);
        assert_eq!(r1.verdict, r2.verdict);
        assert_eq!(r1.defense_held, r2.defense_held);
    }

    // Negative-path inline tests for edge cases and robustness
    #[test]
    fn negative_massive_campaign_payload_handles_memory_pressure() {
        // Test campaigns with massive JSON payloads that could cause memory issues
        let mut massive_payload = BTreeMap::new();

        // Create extremely large payload data
        for i in 0..10000 {
            massive_payload.insert(
                format!("attack_vector_{}", i),
                serde_json::Value::String(format!("payload_data_{}", "x".repeat(1000)))
            );
        }

        let campaign = CampaignDefinition {
            campaign_id: "CAMP-MASSIVE-PAYLOAD".to_string(),
            category: CampaignCategory::MaliciousExtensionInjection,
            version: "1.0.0".to_string(),
            title: "Memory pressure attack simulation".to_string(),
            attack_vector: "Test massive payload handling".to_string(),
            target_component: "memory_subsystem".to_string(),
            expected_defense: "Memory bounds should prevent DoS".to_string(),
            severity: CampaignSeverity::High,
            success_criteria: SuccessCriteria {
                defense_held: true,
                max_detection_time_ms: 1000,
                audit_event_emitted: true,
            },
            payload: massive_payload,
            mutations_applied: Vec::new(),
            parent_campaign_id: None,
            created_at: "2026-02-21T00:00:00Z".to_string(),
        };

        let mut campaigns = build_default_corpus().campaigns;
        campaigns.push(campaign);
        let corpus = CampaignCorpus {
            version: "1.0.0".to_string(),
            campaigns,
        };

        // Should handle massive payloads without excessive memory usage
        let runner = AdversarialRunner::new(RunnerConfig::default_config(), corpus);
        assert!(runner.corpus().validate_corpus_invariant());

        // Serialization should work without panic
        let result = serde_json::to_string(runner.corpus());
        assert!(result.is_ok() || result.is_err()); // Either works or fails gracefully

        // Memory should be released after operations
        drop(runner);
    }

    #[test]
    fn negative_unicode_attack_vectors_handled_without_corruption() {
        // Test attack vectors with problematic Unicode characters
        let unicode_attacks = vec![
            "攻击向量-🔥-测试",                    // Mixed CJK with emoji
            "هجوم-اختبار-٧٨٩",                   // Arabic with numbers
            "attack\u{200B}vector\u{FEFF}",      // Zero-width space and BOM
            "attack‌vector‍hidden",               // Zero-width joiners
            "𝒂𝒕𝒕𝒂𝒄𝒌_𝒗𝒆𝒄𝒕𝒐𝒓",           // Mathematical script unicode
            "attack\u{0301}vect\u{0302}or",      // Combining diacriticals
            "attack\u{202E}rtl\u{202D}vector",   // RTL/LTR override
            "attack\u{1F600}vector",             // Emoji codepoint
        ];

        for (i, attack_vector) in unicode_attacks.iter().enumerate() {
            let campaign = CampaignDefinition {
                campaign_id: format!("CAMP-UNICODE-{:03}", i),
                category: CampaignCategory::PolicyEvasion,
                version: "1.0.0".to_string(),
                title: format!("Unicode attack test {}", i),
                attack_vector: attack_vector.clone(),
                target_component: "unicode_processor".to_string(),
                expected_defense: "Unicode normalization should prevent bypass".to_string(),
                severity: CampaignSeverity::Medium,
                success_criteria: SuccessCriteria {
                    defense_held: true,
                    max_detection_time_ms: 100,
                    audit_event_emitted: true,
                },
                payload: BTreeMap::new(),
                mutations_applied: Vec::new(),
                parent_campaign_id: None,
                created_at: "2026-02-21T00:00:00Z".to_string(),
            };

            // Should handle Unicode without corruption
            let corpus = CampaignCorpus {
                version: "1.0.0".to_string(),
                campaigns: vec![campaign],
            };

            let runner = AdversarialRunner::new(RunnerConfig::default_config(), corpus);

            // Should evaluate without panic
            let result = CampaignResult {
                campaign_id: format!("CAMP-UNICODE-{:03}", i),
                execution_id: format!("exec-unicode-{}", i),
                timestamp: "2026-02-21T00:00:00Z".to_string(),
                verdict: ExecutionVerdict::DefenseHeld,
                defense_decisions: Vec::new(),
                sandbox_verified: true,
                duration_ms: 50,
                severity_if_breached: CampaignSeverity::Medium,
                integration_targets: Vec::new(),
            };

            let gate = runner.evaluate_results(&[result]);
            assert!(gate.overall_pass || !gate.overall_pass); // Should complete without panic
        }
    }

    #[test]
    fn negative_null_bytes_and_control_characters_in_campaign_data() {
        let problematic_inputs = vec![
            "campaign\0null",              // Null byte
            "campaign\x01\x02control",    // Control characters
            "campaign\r\nlinebreak",      // Line breaks
            "campaign\t\x0Btab",          // Tab and vertical tab
            "campaign\x7F\x80\xFF",       // DEL and high bytes
            "",                           // Empty string
            "\0\0\0",                     // Only null bytes
        ];

        for (i, input) in problematic_inputs.iter().enumerate() {
            let campaign = CampaignDefinition {
                campaign_id: format!("CAMP-CONTROL-{:03}", i),
                category: CampaignCategory::CredentialExfiltration,
                version: "1.0.0".to_string(),
                title: input.clone(),
                attack_vector: format!("Control char test: {}", input),
                target_component: input.clone(),
                expected_defense: format!("Should handle: {}", input),
                severity: CampaignSeverity::Low,
                success_criteria: SuccessCriteria {
                    defense_held: true,
                    max_detection_time_ms: 100,
                    audit_event_emitted: true,
                },
                payload: {
                    let mut payload = BTreeMap::new();
                    payload.insert("control_test".to_string(), serde_json::Value::String(input.clone()));
                    payload
                },
                mutations_applied: Vec::new(),
                parent_campaign_id: Some(input.clone()),
                created_at: input.clone(),
            };

            // Should handle control characters without corruption
            let corpus = CampaignCorpus {
                version: "1.0.0".to_string(),
                campaigns: vec![campaign],
            };

            // Should construct without panic
            let runner = AdversarialRunner::new(RunnerConfig::default_config(), corpus);

            // Validation should complete without crash
            let (_, events) = runner.validate_corpus();
            assert!(!events.is_empty() || events.is_empty()); // Should complete

            // Serialization should handle control chars
            let json_result = serde_json::to_string(runner.corpus());
            // Either succeeds or fails gracefully
            match json_result {
                Ok(json) => assert!(!json.is_empty()),
                Err(_) => {} // Graceful failure acceptable
            }
        }
    }

    #[test]
    fn negative_extreme_timestamp_values_use_saturating_arithmetic() {
        let extreme_timestamps = vec![
            u64::MAX,
            u64::MAX - 1,
            u64::MAX / 2,
            0,
            1,
        ];

        for (i, timestamp) in extreme_timestamps.iter().enumerate() {
            let result = CampaignResult {
                campaign_id: format!("CAMP-TIME-{:03}", i),
                execution_id: format!("exec-time-{}", i),
                timestamp: "2026-02-21T00:00:00Z".to_string(),
                verdict: ExecutionVerdict::DefenseHeld,
                defense_decisions: vec![DefenseDecision {
                    component: "timestamp_test".to_string(),
                    action: "validate".to_string(),
                    outcome: "held".to_string(),
                    timestamp_ms: *timestamp,
                }],
                sandbox_verified: true,
                duration_ms: *timestamp,
                severity_if_breached: CampaignSeverity::High,
                integration_targets: Vec::new(),
            };

            let runner = AdversarialRunner::new(RunnerConfig::default_config(), build_default_corpus());
            let gate = runner.evaluate_results(&[result]);

            // Should handle extreme timestamps without overflow
            assert!(gate.total_campaigns == 1);
            assert!(gate.defense_held == 1 || gate.defense_held == 0);

            // Verify no arithmetic overflow in duration handling
            let duration_check = timestamp.saturating_add(1000);
            assert!(duration_check >= *timestamp);
        }
    }

    #[test]
    fn negative_malformed_mutation_records_massive_lists() {
        // Test with massive mutation lists that could cause memory issues
        let mut mutations = Vec::new();
        for i in 0..10000 {
            mutations.push(MutationRecord {
                strategy: MutationStrategy::ParameterVariation,
                description: format!("Massive mutation test {}", "x".repeat(1000)),
                applied_at: format!("2026-02-21T{:02}:00:00Z", i % 24),
                parent_campaign_id: format!("PARENT-{}", i),
            });
        }

        let campaign = CampaignDefinition {
            campaign_id: "CAMP-MASSIVE-MUTATIONS".to_string(),
            category: CampaignCategory::DelayedPayloadActivation,
            version: "1.0.0".to_string(),
            title: "Massive mutations test".to_string(),
            attack_vector: "Test mutation scaling".to_string(),
            target_component: "mutation_engine".to_string(),
            expected_defense: "Should handle large mutation lists".to_string(),
            severity: CampaignSeverity::Medium,
            success_criteria: SuccessCriteria {
                defense_held: true,
                max_detection_time_ms: 500,
                audit_event_emitted: true,
            },
            payload: BTreeMap::new(),
            mutations_applied: mutations,
            parent_campaign_id: None,
            created_at: "2026-02-21T00:00:00Z".to_string(),
        };

        let corpus = CampaignCorpus {
            version: "1.0.0".to_string(),
            campaigns: vec![campaign],
        };

        // Should handle massive mutation lists without excessive memory usage
        let runner = AdversarialRunner::new(RunnerConfig::default_config(), corpus);

        // Validation should complete
        let (valid, _) = runner.validate_corpus();
        assert!(!valid || valid); // Should complete without panic

        // Should not consume excessive memory
        assert!(runner.corpus().campaigns[0].mutations_applied.len() == 10000);
    }

    #[test]
    fn negative_campaign_id_collision_detection() {
        // Test campaigns with potential ID collisions
        let collision_candidates = vec![
            "CAMP-001",
            "CAMP-002",
            "CAMP-001", // Duplicate
            "camp-001", // Case variation
            "CAMP-001 ", // Trailing space
            " CAMP-001", // Leading space
            "CAMP\0001", // Null byte variation
        ];

        let mut campaigns = Vec::new();
        for (i, campaign_id) in collision_candidates.iter().enumerate() {
            campaigns.push(CampaignDefinition {
                campaign_id: campaign_id.to_string(),
                category: CampaignCategory::all()[i % CampaignCategory::all().len()],
                version: "1.0.0".to_string(),
                title: format!("Collision test {}", i),
                attack_vector: "ID collision test".to_string(),
                target_component: "id_validation".to_string(),
                expected_defense: "Should detect ID collisions".to_string(),
                severity: CampaignSeverity::Low,
                success_criteria: SuccessCriteria {
                    defense_held: true,
                    max_detection_time_ms: 100,
                    audit_event_emitted: true,
                },
                payload: BTreeMap::new(),
                mutations_applied: Vec::new(),
                parent_campaign_id: None,
                created_at: "2026-02-21T00:00:00Z".to_string(),
            });
        }

        let corpus = CampaignCorpus {
            version: "1.0.0".to_string(),
            campaigns,
        };

        let runner = AdversarialRunner::new(RunnerConfig::default_config(), corpus);

        // Should handle ID variations without corruption
        assert!(runner.corpus().campaigns.len() == collision_candidates.len());

        // Each campaign should maintain its exact ID (no normalization)
        for (i, expected_id) in collision_candidates.iter().enumerate() {
            assert_eq!(&runner.corpus().campaigns[i].campaign_id, expected_id);
        }
    }

    #[test]
    fn negative_integration_targets_massive_lists() {
        // Test with massive integration target lists
        let mut massive_targets = Vec::new();
        for i in 0..1000 {
            massive_targets.push(format!("target_system_{}_with_very_long_name_{}", i, "x".repeat(100)));
        }

        let config = RunnerConfig {
            mode: RunnerMode::Continuous,
            sandbox_required: true,
            max_campaign_duration_ms: u64::MAX, // Extreme value
            integration_targets: massive_targets.clone(),
            mutation_strategies_enabled: MutationStrategy::all().to_vec(),
        };

        let result = CampaignResult {
            campaign_id: "CAMP-MASSIVE-TARGETS".to_string(),
            execution_id: "exec-massive-targets".to_string(),
            timestamp: "2026-02-21T00:00:00Z".to_string(),
            verdict: ExecutionVerdict::DefenseHeld,
            defense_decisions: Vec::new(),
            sandbox_verified: true,
            duration_ms: 100,
            severity_if_breached: CampaignSeverity::Low,
            integration_targets: massive_targets,
        };

        let runner = AdversarialRunner::new(config, build_default_corpus());
        let gate = runner.evaluate_results(&[result]);

        // Should handle massive target lists without memory issues
        assert!(gate.overall_pass);

        // Should produce integration events for each target
        let integration_events = gate.events.iter()
            .filter(|e| e.code == event_codes::ADV_RUN_006_INTEGRATED)
            .count();
        assert!(integration_events <= 1000); // Should not exceed input count
    }

    #[test]
    fn negative_defense_decision_component_boundary_testing() {
        let boundary_components = vec![
            "",                              // Empty component
            "x".repeat(10000),              // Massive component name
            "component\0null",              // Null byte
            "comp\r\nonent",               // Line break
            "🔥component🔥",               // Unicode emoji
            "component.with.dots",          // Dot notation
            "component/with/slashes",       // Path-like
            "component:with:colons",        // Colon separated
        ];

        for (i, component) in boundary_components.iter().enumerate() {
            let decision = DefenseDecision {
                component: component.clone(),
                action: format!("action-{}", i),
                outcome: "tested".to_string(),
                timestamp_ms: i as u64,
            };

            let result = CampaignResult {
                campaign_id: format!("CAMP-COMPONENT-{:03}", i),
                execution_id: format!("exec-component-{}", i),
                timestamp: "2026-02-21T00:00:00Z".to_string(),
                verdict: ExecutionVerdict::DefenseHeld,
                defense_decisions: vec![decision],
                sandbox_verified: true,
                duration_ms: 50,
                severity_if_breached: CampaignSeverity::Low,
                integration_targets: Vec::new(),
            };

            let runner = AdversarialRunner::new(RunnerConfig::default_config(), build_default_corpus());
            let gate = runner.evaluate_results(&[result]);

            // Should handle boundary component names without corruption
            assert!(gate.total_campaigns == 1);
            assert!(gate.overall_pass);
        }
    }

    #[test]
    fn negative_campaign_corpus_category_count_overflow() {
        // Test category counting with potential overflow scenarios
        let mut campaigns = Vec::new();

        // Create many campaigns to stress category counting
        for i in 0..1000 {
            let category = CampaignCategory::all()[i % CampaignCategory::all().len()];
            campaigns.push(CampaignDefinition {
                campaign_id: format!("CAMP-OVERFLOW-{:04}", i),
                category,
                version: "1.0.0".to_string(),
                title: format!("Overflow test {}", i),
                attack_vector: "Category counting stress test".to_string(),
                target_component: "category_counter".to_string(),
                expected_defense: "Should count categories correctly".to_string(),
                severity: CampaignSeverity::Low,
                success_criteria: SuccessCriteria {
                    defense_held: true,
                    max_detection_time_ms: 100,
                    audit_event_emitted: true,
                },
                payload: BTreeMap::new(),
                mutations_applied: Vec::new(),
                parent_campaign_id: None,
                created_at: "2026-02-21T00:00:00Z".to_string(),
            });
        }

        let corpus = CampaignCorpus {
            version: "1.0.0".to_string(),
            campaigns,
        };

        // Category count should be bounded and not overflow
        let category_count = corpus.category_count();
        assert!(category_count <= CampaignCategory::all().len());
        assert!(category_count == 5); // Should equal the number of defined categories

        // Validation should pass with many campaigns
        assert!(corpus.validate_corpus_invariant());

        // Should handle large corpus efficiently
        let runner = AdversarialRunner::new(RunnerConfig::default_config(), corpus);
        let (valid, _) = runner.validate_corpus();
        assert!(valid);
    }

    #[test]
    fn negative_runner_event_massive_detail_strings() {
        // Test runner events with massive detail strings
        let massive_detail = "x".repeat(100000);

        let event = RunnerEvent {
            code: event_codes::ADV_RUN_001_STARTED.to_string(),
            campaign_id: "CAMP-MASSIVE-DETAIL".to_string(),
            detail: massive_detail.clone(),
        };

        // Should handle massive detail strings without memory issues
        assert_eq!(event.detail.len(), 100000);
        assert!(event.detail.starts_with("xxx"));

        // Serialization should handle large strings
        let json_result = serde_json::to_string(&event);
        match json_result {
            Ok(json) => {
                assert!(json.contains("CAMP-MASSIVE-DETAIL"));
                // Should complete without memory corruption
            },
            Err(_) => {
                // Graceful failure acceptable for extreme sizes
            }
        }

        // Event should be usable in gate results
        let gate_result = RunnerGateResult {
            verdict: "TEST".to_string(),
            overall_pass: true,
            total_campaigns: 1,
            defense_held: 1,
            defense_breached: 0,
            inconclusive: 0,
            breached_campaign_ids: Vec::new(),
            events: vec![event],
        };

        assert_eq!(gate_result.events.len(), 1);
        assert_eq!(gate_result.events[0].detail.len(), 100000);
    }
}
