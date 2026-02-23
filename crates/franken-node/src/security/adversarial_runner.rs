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
        let count = self.config.mutation_strategies_enabled.len();
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

        for result in results {
            events.push(RunnerEvent {
                code: event_codes::ADV_RUN_001_STARTED.to_string(),
                campaign_id: result.campaign_id.clone(),
                detail: format!("execution_id={}", result.execution_id),
            });

            if !result.sandbox_verified && self.config.sandbox_required {
                events.push(RunnerEvent {
                    code: event_codes::ADV_RUN_ERR_002_CONTAINMENT.to_string(),
                    campaign_id: result.campaign_id.clone(),
                    detail: "sandbox containment not verified".to_string(),
                });
            }

            match result.verdict {
                ExecutionVerdict::DefenseHeld => {
                    held += 1;
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
                    inconclusive += 1;
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
        let overall_pass = breach_count == 0;

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
}
