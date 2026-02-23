//! bd-16fq: VEF policy-constraint language and deterministic compiler contract.
//!
//! Defines a versioned policy language for high-risk action classes and compiles
//! runtime policies into proof-checkable predicates with stable trace links.
//!
//! # Invariants
//!
//! - **INV-VEF-COMP-DETERMINISTIC**: identical policy input yields bit-identical output.
//! - **INV-VEF-COMP-COVERAGE**: required action classes are covered when the policy
//!   requests full coverage.
//! - **INV-VEF-COMP-TRACEABLE**: every predicate maps to a source rule ID.
//! - **INV-VEF-COMP-VERSIONED**: language/compiler/output schema versions are explicit.
//! - **INV-VEF-COMP-ROUNDTRIP**: compile + decompile semantic projection is lossless.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

pub const LANGUAGE_VERSION: &str = "vef-policy-lang-v1";
pub const COMPILER_VERSION: &str = "vef-constraint-compiler-v1";
pub const COMPILED_SCHEMA_VERSION: &str = "vef-policy-constraints-v1";

// ---------------------------------------------------------------------------
// Event codes
// ---------------------------------------------------------------------------

pub mod event_codes {
    /// Compiler started processing a policy document.
    pub const VEF_COMPILE_001_STARTED: &str = "VEF-COMPILE-001";
    /// Compiler finished successfully and emitted deterministic predicates.
    pub const VEF_COMPILE_002_SUCCEEDED: &str = "VEF-COMPILE-002";

    /// Input was malformed (empty IDs, duplicate rule IDs, invalid keys, etc.).
    pub const VEF_COMPILE_ERR_001_INVALID_INPUT: &str = "VEF-COMPILE-ERR-001";
    /// Schema/language version mismatch.
    pub const VEF_COMPILE_ERR_002_INVALID_VERSION: &str = "VEF-COMPILE-ERR-002";
    /// Required action-class coverage is missing.
    pub const VEF_COMPILE_ERR_003_MISSING_COVERAGE: &str = "VEF-COMPILE-ERR-003";
    /// Rule-level shape error (empty rule ID, conflicting fields).
    pub const VEF_COMPILE_ERR_004_INVALID_RULE: &str = "VEF-COMPILE-ERR-004";
    /// Canonical serialization/hashing failure.
    pub const VEF_COMPILE_ERR_005_INTERNAL: &str = "VEF-COMPILE-ERR-005";
}

// ---------------------------------------------------------------------------
// Invariants
// ---------------------------------------------------------------------------

pub const INV_VEF_COMP_DETERMINISTIC: &str = "INV-VEF-COMP-DETERMINISTIC";
pub const INV_VEF_COMP_COVERAGE: &str = "INV-VEF-COMP-COVERAGE";
pub const INV_VEF_COMP_TRACEABLE: &str = "INV-VEF-COMP-TRACEABLE";
pub const INV_VEF_COMP_VERSIONED: &str = "INV-VEF-COMP-VERSIONED";
pub const INV_VEF_COMP_ROUNDTRIP: &str = "INV-VEF-COMP-ROUNDTRIP";

// ---------------------------------------------------------------------------
// Language model
// ---------------------------------------------------------------------------

/// High-risk action classes covered by the VEF policy-constraint language.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionClass {
    NetworkAccess,
    FilesystemOperation,
    ProcessSpawn,
    SecretAccess,
    PolicyTransition,
    ArtifactPromotion,
}

impl ActionClass {
    pub fn all() -> &'static [ActionClass] {
        &[
            ActionClass::NetworkAccess,
            ActionClass::FilesystemOperation,
            ActionClass::ProcessSpawn,
            ActionClass::SecretAccess,
            ActionClass::PolicyTransition,
            ActionClass::ArtifactPromotion,
        ]
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            ActionClass::NetworkAccess => "network_access",
            ActionClass::FilesystemOperation => "filesystem_operation",
            ActionClass::ProcessSpawn => "process_spawn",
            ActionClass::SecretAccess => "secret_access",
            ActionClass::PolicyTransition => "policy_transition",
            ActionClass::ArtifactPromotion => "artifact_promotion",
        }
    }
}

impl fmt::Display for ActionClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Rule effect in the source policy language.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleEffect {
    Allow,
    Deny,
    Require,
}

impl RuleEffect {
    pub fn as_str(&self) -> &'static str {
        match self {
            RuleEffect::Allow => "allow",
            RuleEffect::Deny => "deny",
            RuleEffect::Require => "require",
        }
    }
}

/// A single policy rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyRule {
    pub rule_id: String,
    pub action_class: ActionClass,
    pub effect: RuleEffect,
    #[serde(default)]
    pub required_capabilities: Vec<String>,
    #[serde(default)]
    pub constraints: BTreeMap<String, String>,
}

fn default_require_full_action_coverage() -> bool {
    true
}

/// Top-level runtime policy input consumed by the constraint compiler.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimePolicy {
    pub schema_version: String,
    pub policy_id: String,
    #[serde(default = "default_require_full_action_coverage")]
    pub require_full_action_coverage: bool,
    pub rules: Vec<PolicyRule>,
}

// ---------------------------------------------------------------------------
// Compiled output model
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PredicateKind {
    Decision,
    Capability,
    Constraint,
}

/// Predicate emitted by the compiler and consumed by downstream proof workers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompiledPredicate {
    pub predicate_id: String,
    pub source_rule_id: String,
    pub action_class: ActionClass,
    pub kind: PredicateKind,
    pub expression: String,
    pub params: BTreeMap<String, String>,
    pub trace_link: String,
}

/// Semantic projection that allows decompile checks without parsing expressions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleSemanticProjection {
    pub rule_id: String,
    pub action_class: ActionClass,
    pub effect: RuleEffect,
    pub required_capabilities: Vec<String>,
    pub constraints: BTreeMap<String, String>,
}

/// Structured compiler event with trace correlation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompilerEvent {
    pub code: String,
    pub trace_id: String,
    pub message: String,
    pub rule_id: Option<String>,
}

/// Deterministic compiler output envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompiledConstraintEnvelope {
    pub schema_version: String,
    pub language_version: String,
    pub compiler_version: String,
    pub trace_id: String,
    pub policy_id: String,
    pub policy_snapshot_hash: String,
    pub predicates: Vec<CompiledPredicate>,
    pub coverage: BTreeMap<String, usize>,
    pub rule_projections: Vec<RuleSemanticProjection>,
    pub events: Vec<CompilerEvent>,
}

// ---------------------------------------------------------------------------
// Error model
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConstraintCompileError {
    pub code: &'static str,
    pub message: String,
    pub trace_id: String,
    pub rule_id: Option<String>,
}

impl ConstraintCompileError {
    fn new(
        code: &'static str,
        message: impl Into<String>,
        trace_id: &str,
        rule_id: Option<&str>,
    ) -> Self {
        Self {
            code,
            message: message.into(),
            trace_id: trace_id.to_string(),
            rule_id: rule_id.map(str::to_string),
        }
    }
}

impl fmt::Display for ConstraintCompileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.rule_id {
            Some(rule_id) => write!(
                f,
                "{}: {} (trace_id={}, rule_id={})",
                self.code, self.message, self.trace_id, rule_id
            ),
            None => write!(
                f,
                "{}: {} (trace_id={})",
                self.code, self.message, self.trace_id
            ),
        }
    }
}

impl std::error::Error for ConstraintCompileError {}

// ---------------------------------------------------------------------------
// Compiler core
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct NormalizedPolicy {
    schema_version: String,
    policy_id: String,
    require_full_action_coverage: bool,
    rules: Vec<NormalizedRule>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct NormalizedRule {
    rule_id: String,
    action_class: ActionClass,
    effect: RuleEffect,
    required_capabilities: Vec<String>,
    constraints: BTreeMap<String, String>,
}

fn normalize_policy(
    policy: &RuntimePolicy,
    trace_id: &str,
) -> Result<NormalizedPolicy, ConstraintCompileError> {
    let schema_version = policy.schema_version.trim();
    if schema_version.is_empty() {
        return Err(ConstraintCompileError::new(
            event_codes::VEF_COMPILE_ERR_001_INVALID_INPUT,
            "schema_version must be non-empty",
            trace_id,
            None,
        ));
    }

    let policy_id = policy.policy_id.trim();
    if policy_id.is_empty() {
        return Err(ConstraintCompileError::new(
            event_codes::VEF_COMPILE_ERR_001_INVALID_INPUT,
            "policy_id must be non-empty",
            trace_id,
            None,
        ));
    }

    let mut seen_rule_ids = BTreeSet::new();
    let mut normalized_rules = Vec::with_capacity(policy.rules.len());

    for rule in &policy.rules {
        let rule_id = rule.rule_id.trim();
        if rule_id.is_empty() {
            return Err(ConstraintCompileError::new(
                event_codes::VEF_COMPILE_ERR_004_INVALID_RULE,
                "rule_id must be non-empty",
                trace_id,
                None,
            ));
        }

        if !seen_rule_ids.insert(rule_id.to_string()) {
            return Err(ConstraintCompileError::new(
                event_codes::VEF_COMPILE_ERR_004_INVALID_RULE,
                "duplicate rule_id is not allowed",
                trace_id,
                Some(rule_id),
            ));
        }

        let mut required_capabilities: Vec<String> = rule
            .required_capabilities
            .iter()
            .map(|cap| cap.trim())
            .filter(|cap| !cap.is_empty())
            .map(str::to_string)
            .collect();
        required_capabilities.sort();
        required_capabilities.dedup();

        let mut constraints = BTreeMap::new();
        for (key, value) in &rule.constraints {
            let key = key.trim();
            if key.is_empty() {
                return Err(ConstraintCompileError::new(
                    event_codes::VEF_COMPILE_ERR_004_INVALID_RULE,
                    "constraint key must be non-empty",
                    trace_id,
                    Some(rule_id),
                ));
            }
            constraints.insert(key.to_string(), value.trim().to_string());
        }

        if matches!(rule.effect, RuleEffect::Require)
            && required_capabilities.is_empty()
            && constraints.is_empty()
        {
            return Err(ConstraintCompileError::new(
                event_codes::VEF_COMPILE_ERR_004_INVALID_RULE,
                "require rule must define at least one capability or constraint",
                trace_id,
                Some(rule_id),
            ));
        }

        normalized_rules.push(NormalizedRule {
            rule_id: rule_id.to_string(),
            action_class: rule.action_class,
            effect: rule.effect,
            required_capabilities,
            constraints,
        });
    }

    normalized_rules.sort_by(|a, b| {
        a.rule_id
            .cmp(&b.rule_id)
            .then(a.action_class.as_str().cmp(b.action_class.as_str()))
            .then(a.effect.as_str().cmp(b.effect.as_str()))
    });

    Ok(NormalizedPolicy {
        schema_version: schema_version.to_string(),
        policy_id: policy_id.to_string(),
        require_full_action_coverage: policy.require_full_action_coverage,
        rules: normalized_rules,
    })
}

fn to_rule_projection(rule: &NormalizedRule) -> RuleSemanticProjection {
    RuleSemanticProjection {
        rule_id: rule.rule_id.clone(),
        action_class: rule.action_class,
        effect: rule.effect,
        required_capabilities: rule.required_capabilities.clone(),
        constraints: rule.constraints.clone(),
    }
}

fn expression_for_decision(effect: RuleEffect, action: ActionClass) -> String {
    match effect {
        RuleEffect::Allow => format!("permit({})", action.as_str()),
        RuleEffect::Deny => format!("deny({})", action.as_str()),
        RuleEffect::Require => format!("require({})", action.as_str()),
    }
}

fn predicate_hash_id(seed: &str) -> String {
    let digest = Sha256::digest([b"vef_predicate_hash_v1:" as &[u8], seed.as_bytes()].concat());
    let mut hex = String::with_capacity(16);
    for b in &digest[..8] {
        hex.push_str(&format!("{b:02x}"));
    }
    format!("pred-{hex}")
}

fn snapshot_hash(normalized: &NormalizedPolicy) -> Result<String, ConstraintCompileError> {
    let canonical = serde_json::to_vec(normalized).map_err(|err| {
        ConstraintCompileError::new(
            event_codes::VEF_COMPILE_ERR_005_INTERNAL,
            format!("failed to serialize canonical policy: {err}"),
            "internal",
            None,
        )
    })?;
    let digest = Sha256::digest([b"vef_snapshot_hash_v1:" as &[u8], &canonical[..]].concat());
    Ok(format!("sha256:{digest:x}"))
}

/// Compile a runtime policy into deterministic proof-checkable predicates.
pub fn compile_policy(
    policy: &RuntimePolicy,
    trace_id: &str,
) -> Result<CompiledConstraintEnvelope, ConstraintCompileError> {
    let trace_id = trace_id.trim();
    if trace_id.is_empty() {
        return Err(ConstraintCompileError::new(
            event_codes::VEF_COMPILE_ERR_001_INVALID_INPUT,
            "trace_id must be non-empty",
            "",
            None,
        ));
    }

    let mut events = vec![CompilerEvent {
        code: event_codes::VEF_COMPILE_001_STARTED.to_string(),
        trace_id: trace_id.to_string(),
        message: "constraint compilation started".to_string(),
        rule_id: None,
    }];

    let normalized = normalize_policy(policy, trace_id)?;

    if normalized.schema_version != LANGUAGE_VERSION {
        return Err(ConstraintCompileError::new(
            event_codes::VEF_COMPILE_ERR_002_INVALID_VERSION,
            format!(
                "unsupported language version '{}' ; expected '{}'",
                normalized.schema_version, LANGUAGE_VERSION
            ),
            trace_id,
            None,
        ));
    }

    if normalized.rules.is_empty() {
        return Err(ConstraintCompileError::new(
            event_codes::VEF_COMPILE_ERR_001_INVALID_INPUT,
            "policy must contain at least one rule",
            trace_id,
            None,
        ));
    }

    let mut predicates = Vec::new();
    let mut coverage = BTreeMap::new();
    let mut rule_projections = Vec::new();

    for rule in &normalized.rules {
        let projection = to_rule_projection(rule);
        rule_projections.push(projection);

        let trace_link = format!("policy:{}/rule:{}", normalized.policy_id, rule.rule_id);

        let decision_expr = expression_for_decision(rule.effect, rule.action_class);
        let decision_seed = format!(
            "{}|{}|{}|decision|{}",
            normalized.policy_id,
            rule.rule_id,
            rule.action_class.as_str(),
            decision_expr
        );
        predicates.push(CompiledPredicate {
            predicate_id: predicate_hash_id(&decision_seed),
            source_rule_id: rule.rule_id.clone(),
            action_class: rule.action_class,
            kind: PredicateKind::Decision,
            expression: decision_expr,
            params: BTreeMap::new(),
            trace_link: trace_link.clone(),
        });

        for capability in &rule.required_capabilities {
            let mut params = BTreeMap::new();
            params.insert("capability".to_string(), capability.clone());
            let expr = format!(
                "requires_capability({},\"{}\")",
                rule.action_class.as_str(),
                capability
            );
            let seed = format!(
                "{}|{}|{}|capability|{}",
                normalized.policy_id,
                rule.rule_id,
                rule.action_class.as_str(),
                capability
            );
            predicates.push(CompiledPredicate {
                predicate_id: predicate_hash_id(&seed),
                source_rule_id: rule.rule_id.clone(),
                action_class: rule.action_class,
                kind: PredicateKind::Capability,
                expression: expr,
                params,
                trace_link: trace_link.clone(),
            });
        }

        for (key, value) in &rule.constraints {
            let mut params = BTreeMap::new();
            params.insert("key".to_string(), key.clone());
            params.insert("value".to_string(), value.clone());
            let expr = format!(
                "constraint({},\"{}\",\"{}\")",
                rule.action_class.as_str(),
                key,
                value
            );
            let seed = format!(
                "{}|{}|{}|constraint|{}={}",
                normalized.policy_id,
                rule.rule_id,
                rule.action_class.as_str(),
                key,
                value
            );
            predicates.push(CompiledPredicate {
                predicate_id: predicate_hash_id(&seed),
                source_rule_id: rule.rule_id.clone(),
                action_class: rule.action_class,
                kind: PredicateKind::Constraint,
                expression: expr,
                params,
                trace_link: trace_link.clone(),
            });
        }

        *coverage
            .entry(rule.action_class.as_str().to_string())
            .or_insert(0) += 1;
    }

    if normalized.require_full_action_coverage {
        let mut missing = Vec::new();
        for action in ActionClass::all() {
            if !coverage.contains_key(action.as_str()) {
                missing.push(action.as_str().to_string());
            }
        }
        if !missing.is_empty() {
            return Err(ConstraintCompileError::new(
                event_codes::VEF_COMPILE_ERR_003_MISSING_COVERAGE,
                format!("missing action class coverage: {}", missing.join(", ")),
                trace_id,
                None,
            ));
        }
    }

    predicates.sort_by(|a, b| {
        a.source_rule_id
            .cmp(&b.source_rule_id)
            .then(a.predicate_id.cmp(&b.predicate_id))
    });
    rule_projections.sort_by(|a, b| a.rule_id.cmp(&b.rule_id));

    let policy_snapshot_hash = snapshot_hash(&normalized)?;

    events.push(CompilerEvent {
        code: event_codes::VEF_COMPILE_002_SUCCEEDED.to_string(),
        trace_id: trace_id.to_string(),
        message: format!(
            "compiled {} rules into {} predicates",
            normalized.rules.len(),
            predicates.len()
        ),
        rule_id: None,
    });

    Ok(CompiledConstraintEnvelope {
        schema_version: COMPILED_SCHEMA_VERSION.to_string(),
        language_version: LANGUAGE_VERSION.to_string(),
        compiler_version: COMPILER_VERSION.to_string(),
        trace_id: trace_id.to_string(),
        policy_id: normalized.policy_id,
        policy_snapshot_hash,
        predicates,
        coverage,
        rule_projections,
        events,
    })
}

/// Decompile a compiled envelope back to the normalized semantic projection.
pub fn decompile_projection(envelope: &CompiledConstraintEnvelope) -> Vec<RuleSemanticProjection> {
    let mut projections = envelope.rule_projections.clone();
    projections.sort_by(|a, b| a.rule_id.cmp(&b.rule_id));
    projections
}

/// Compile and verify that semantic projection round-trips with no loss.
pub fn round_trip_semantics(
    policy: &RuntimePolicy,
    trace_id: &str,
) -> Result<bool, ConstraintCompileError> {
    let normalized = normalize_policy(policy, trace_id)?;
    let mut expected: Vec<RuleSemanticProjection> =
        normalized.rules.iter().map(to_rule_projection).collect();
    expected.sort_by(|a, b| a.rule_id.cmp(&b.rule_id));

    let envelope = compile_policy(policy, trace_id)?;
    let actual = decompile_projection(&envelope);

    Ok(expected == actual)
}

/// Minimal integration shim for downstream proof workers.
pub fn mock_proof_generator_accepts(envelope: &CompiledConstraintEnvelope) -> bool {
    if envelope.schema_version != COMPILED_SCHEMA_VERSION {
        return false;
    }
    if envelope.language_version != LANGUAGE_VERSION {
        return false;
    }
    if envelope.predicates.is_empty() || envelope.rule_projections.is_empty() {
        return false;
    }
    if envelope.coverage.is_empty() {
        return false;
    }

    envelope.predicates.iter().all(|predicate| {
        !predicate.predicate_id.is_empty()
            && !predicate.source_rule_id.is_empty()
            && !predicate.expression.is_empty()
            && predicate.trace_link.contains("policy:")
            && predicate.trace_link.contains("/rule:")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn full_policy() -> RuntimePolicy {
        let mut rules = Vec::new();
        for (idx, action) in ActionClass::all().iter().enumerate() {
            let mut constraints = BTreeMap::new();
            constraints.insert("scope".to_string(), format!("scope-{idx}"));
            rules.push(PolicyRule {
                rule_id: format!("rule-{idx:02}"),
                action_class: *action,
                effect: if idx % 2 == 0 {
                    RuleEffect::Require
                } else {
                    RuleEffect::Allow
                },
                required_capabilities: vec![format!("capability-{idx}")],
                constraints,
            });
        }

        RuntimePolicy {
            schema_version: LANGUAGE_VERSION.to_string(),
            policy_id: "policy-full".to_string(),
            require_full_action_coverage: true,
            rules,
        }
    }

    #[test]
    fn action_class_count_is_six() {
        assert_eq!(ActionClass::all().len(), 6);
    }

    #[test]
    fn compile_full_policy_succeeds() {
        let envelope = compile_policy(&full_policy(), "trace-001").unwrap();
        assert_eq!(envelope.schema_version, COMPILED_SCHEMA_VERSION);
        assert_eq!(envelope.language_version, LANGUAGE_VERSION);
        assert_eq!(envelope.compiler_version, COMPILER_VERSION);
        assert_eq!(envelope.coverage.len(), 6);
        assert_eq!(envelope.events.len(), 2);
    }

    #[test]
    fn compile_is_bit_deterministic() {
        let policy = full_policy();
        let a = compile_policy(&policy, "trace-det-1").unwrap();
        let b = compile_policy(&policy, "trace-det-1").unwrap();
        assert_eq!(a, b);

        let json_a = serde_json::to_vec(&a).unwrap();
        let json_b = serde_json::to_vec(&b).unwrap();
        assert_eq!(json_a, json_b);
    }

    #[test]
    fn round_trip_semantics_is_lossless() {
        let ok = round_trip_semantics(&full_policy(), "trace-roundtrip").unwrap();
        assert!(ok);
    }

    #[test]
    fn missing_coverage_fails_when_required() {
        let policy = RuntimePolicy {
            schema_version: LANGUAGE_VERSION.to_string(),
            policy_id: "policy-missing".to_string(),
            require_full_action_coverage: true,
            rules: vec![PolicyRule {
                rule_id: "only-network".to_string(),
                action_class: ActionClass::NetworkAccess,
                effect: RuleEffect::Allow,
                required_capabilities: vec![],
                constraints: BTreeMap::new(),
            }],
        };

        let err = compile_policy(&policy, "trace-missing").unwrap_err();
        assert_eq!(err.code, event_codes::VEF_COMPILE_ERR_003_MISSING_COVERAGE);
        assert!(err.message.contains("missing action class coverage"));
    }

    #[test]
    fn missing_coverage_allowed_when_flag_disabled() {
        let policy = RuntimePolicy {
            schema_version: LANGUAGE_VERSION.to_string(),
            policy_id: "policy-partial".to_string(),
            require_full_action_coverage: false,
            rules: vec![PolicyRule {
                rule_id: "only-network".to_string(),
                action_class: ActionClass::NetworkAccess,
                effect: RuleEffect::Allow,
                required_capabilities: vec![],
                constraints: BTreeMap::new(),
            }],
        };

        let envelope = compile_policy(&policy, "trace-partial").unwrap();
        assert_eq!(envelope.coverage.len(), 1);
        assert!(envelope.coverage.contains_key("network_access"));
    }

    #[test]
    fn invalid_language_version_fails() {
        let mut policy = full_policy();
        policy.schema_version = "vef-policy-lang-v0".to_string();
        let err = compile_policy(&policy, "trace-version").unwrap_err();
        assert_eq!(err.code, event_codes::VEF_COMPILE_ERR_002_INVALID_VERSION);
    }

    #[test]
    fn empty_trace_id_fails() {
        let err = compile_policy(&full_policy(), "   ").unwrap_err();
        assert_eq!(err.code, event_codes::VEF_COMPILE_ERR_001_INVALID_INPUT);
    }

    #[test]
    fn empty_rule_id_fails() {
        let mut policy = full_policy();
        policy.rules[0].rule_id = "".to_string();
        let err = compile_policy(&policy, "trace-empty-rule").unwrap_err();
        assert_eq!(err.code, event_codes::VEF_COMPILE_ERR_004_INVALID_RULE);
    }

    #[test]
    fn duplicate_rule_id_fails() {
        let mut policy = full_policy();
        policy.rules[1].rule_id = policy.rules[0].rule_id.clone();
        let err = compile_policy(&policy, "trace-dup").unwrap_err();
        assert_eq!(err.code, event_codes::VEF_COMPILE_ERR_004_INVALID_RULE);
    }

    #[test]
    fn require_rule_needs_detail() {
        let policy = RuntimePolicy {
            schema_version: LANGUAGE_VERSION.to_string(),
            policy_id: "policy-require".to_string(),
            require_full_action_coverage: false,
            rules: vec![PolicyRule {
                rule_id: "r1".to_string(),
                action_class: ActionClass::SecretAccess,
                effect: RuleEffect::Require,
                required_capabilities: vec![],
                constraints: BTreeMap::new(),
            }],
        };

        let err = compile_policy(&policy, "trace-require").unwrap_err();
        assert_eq!(err.code, event_codes::VEF_COMPILE_ERR_004_INVALID_RULE);
    }

    #[test]
    fn decompile_projection_matches_rule_count() {
        let envelope = compile_policy(&full_policy(), "trace-decompile").unwrap();
        let projection = decompile_projection(&envelope);
        assert_eq!(projection.len(), 6);
    }

    #[test]
    fn mock_proof_generator_accepts_valid_envelope() {
        let envelope = compile_policy(&full_policy(), "trace-proofgen").unwrap();
        assert!(mock_proof_generator_accepts(&envelope));
    }

    #[test]
    fn mock_proof_generator_rejects_invalid_schema() {
        let mut envelope = compile_policy(&full_policy(), "trace-proofgen-bad").unwrap();
        envelope.schema_version = "bad-schema".to_string();
        assert!(!mock_proof_generator_accepts(&envelope));
    }

    #[test]
    fn events_include_required_codes() {
        let envelope = compile_policy(&full_policy(), "trace-events").unwrap();
        let codes: Vec<&str> = envelope.events.iter().map(|e| e.code.as_str()).collect();
        assert!(codes.contains(&event_codes::VEF_COMPILE_001_STARTED));
        assert!(codes.contains(&event_codes::VEF_COMPILE_002_SUCCEEDED));
    }

    #[test]
    fn all_action_classes_individually_supported() {
        for action in ActionClass::all() {
            let rule = PolicyRule {
                rule_id: format!("rule-{}", action.as_str()),
                action_class: *action,
                effect: RuleEffect::Allow,
                required_capabilities: vec!["cap".to_string()],
                constraints: BTreeMap::new(),
            };
            let policy = RuntimePolicy {
                schema_version: LANGUAGE_VERSION.to_string(),
                policy_id: format!("policy-{}", action.as_str()),
                require_full_action_coverage: false,
                rules: vec![rule],
            };

            let envelope = compile_policy(&policy, "trace-action").unwrap();
            assert!(envelope.coverage.contains_key(action.as_str()));
        }
    }

    fn random_policy(seed: u64) -> RuntimePolicy {
        fn lcg(mut x: u64) -> u64 {
            x = x.wrapping_mul(6364136223846793005).wrapping_add(1);
            x
        }

        let mut x = seed;
        let mut rules = Vec::new();
        for idx in 0..24 {
            x = lcg(x);
            let action_idx = (x % ActionClass::all().len() as u64) as usize;
            let action = ActionClass::all()[action_idx];
            x = lcg(x);
            let effect = match x % 3 {
                0 => RuleEffect::Allow,
                1 => RuleEffect::Deny,
                _ => RuleEffect::Require,
            };

            let mut constraints = BTreeMap::new();
            constraints.insert("scope".to_string(), format!("s-{}", x % 17));

            let caps = if matches!(effect, RuleEffect::Deny) {
                Vec::new()
            } else {
                vec![format!("c-{}", x % 11)]
            };

            rules.push(PolicyRule {
                rule_id: format!("r-{idx:02}"),
                action_class: action,
                effect,
                required_capabilities: caps,
                constraints,
            });
        }

        RuntimePolicy {
            schema_version: LANGUAGE_VERSION.to_string(),
            policy_id: format!("policy-rand-{seed}"),
            require_full_action_coverage: false,
            rules,
        }
    }

    #[test]
    fn deterministic_fuzz_recompile() {
        for seed in 0..64 {
            let policy = random_policy(seed);
            let first = compile_policy(&policy, "trace-fuzz").unwrap();
            let second = compile_policy(&policy, "trace-fuzz").unwrap();
            assert_eq!(first, second, "non-determinism for seed {seed}");
            assert_eq!(
                serde_json::to_vec(&first).unwrap(),
                serde_json::to_vec(&second).unwrap(),
                "json drift for seed {seed}"
            );
        }
    }

    #[test]
    fn error_display_contains_code() {
        let err = compile_policy(&full_policy(), "").unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains(event_codes::VEF_COMPILE_ERR_001_INVALID_INPUT));
    }

    #[test]
    fn invariant_constants_are_stable() {
        let invariants = [
            INV_VEF_COMP_DETERMINISTIC,
            INV_VEF_COMP_COVERAGE,
            INV_VEF_COMP_TRACEABLE,
            INV_VEF_COMP_VERSIONED,
            INV_VEF_COMP_ROUNDTRIP,
        ];
        assert_eq!(invariants.len(), 5);
        assert!(
            invariants
                .iter()
                .all(|inv| inv.starts_with("INV-VEF-COMP-"))
        );
    }
}
