//! bd-16fq: VEF policy-constraint language and compiler contract for high-risk action classes.
//!
//! Defines a formal policy-constraint language that translates runtime policy definitions
//! into machine-checkable proof predicates. The compiler outputs are deterministic and
//! versioned, covering all high-risk action classes: network, filesystem, process, secret
//! access, policy transitions, and artifact promotion.
//!
//! # Invariants
//!
//! - INV-VEF-DETERMINISTIC: identical policy inputs produce bit-identical predicate outputs
//! - INV-VEF-COVERAGE: every high-risk action class has at least one constraint predicate
//! - INV-VEF-VERSIONED: compiler output carries explicit version metadata and policy hash
//! - INV-VEF-TRACEABLE: every predicate links back to its source policy rule
//! - INV-VEF-CLASSIFIED-ERRORS: invalid inputs produce stable, classified error codes
//! - INV-VEF-IDEMPOTENT: re-compilation of unchanged policy produces identical output

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

// ── Schema version ──────────────────────────────────────────────────────────

/// Schema version for the VEF constraint compiler output format.
pub const SCHEMA_VERSION: &str = "vef-constraints-v1.0";

/// Compiler contract version.
pub const COMPILER_VERSION: &str = "1.0.0";

// ── Invariant constants ─────────────────────────────────────────────────────

/// INV-VEF-DETERMINISTIC: identical policy inputs produce bit-identical predicate outputs.
pub const INV_VEF_DETERMINISTIC: &str = "INV-VEF-DETERMINISTIC";

/// INV-VEF-COVERAGE: every high-risk action class has at least one constraint predicate.
pub const INV_VEF_COVERAGE: &str = "INV-VEF-COVERAGE";

/// INV-VEF-VERSIONED: compiler output carries explicit version metadata and policy hash.
pub const INV_VEF_VERSIONED: &str = "INV-VEF-VERSIONED";

/// INV-VEF-TRACEABLE: every predicate links back to its source policy rule.
pub const INV_VEF_TRACEABLE: &str = "INV-VEF-TRACEABLE";

/// INV-VEF-CLASSIFIED-ERRORS: invalid inputs produce stable, classified error codes.
pub const INV_VEF_CLASSIFIED_ERRORS: &str = "INV-VEF-CLASSIFIED-ERRORS";

/// INV-VEF-IDEMPOTENT: re-compilation of unchanged policy produces identical output.
pub const INV_VEF_IDEMPOTENT: &str = "INV-VEF-IDEMPOTENT";

// ── Event codes ─────────────────────────────────────────────────────────────

pub mod event_codes {
    /// Compilation started.
    pub const VEF_COMPILE_001: &str = "VEF-COMPILE-001";
    /// Compilation succeeded.
    pub const VEF_COMPILE_002: &str = "VEF-COMPILE-002";
    /// Invalid policy syntax.
    pub const VEF_COMPILE_ERR_SYNTAX: &str = "VEF-COMPILE-ERR-SYNTAX";
    /// Missing required action class coverage.
    pub const VEF_COMPILE_ERR_COVERAGE: &str = "VEF-COMPILE-ERR-COVERAGE";
    /// Empty policy input.
    pub const VEF_COMPILE_ERR_EMPTY: &str = "VEF-COMPILE-ERR-EMPTY";
    /// Duplicate rule identifier.
    pub const VEF_COMPILE_ERR_DUPLICATE: &str = "VEF-COMPILE-ERR-DUPLICATE";
    /// Invalid predicate expression.
    pub const VEF_COMPILE_ERR_PREDICATE: &str = "VEF-COMPILE-ERR-PREDICATE";
    /// Action class not recognized.
    pub const VEF_COMPILE_ERR_ACTION_CLASS: &str = "VEF-COMPILE-ERR-ACTION-CLASS";
    /// Policy rule has no conditions.
    pub const VEF_COMPILE_ERR_NO_CONDITIONS: &str = "VEF-COMPILE-ERR-NO-CONDITIONS";
    /// Compilation with warnings.
    pub const VEF_COMPILE_WARN: &str = "VEF-COMPILE-WARN";
}

// ── Error codes ─────────────────────────────────────────────────────────────

pub mod error_codes {
    pub const ERR_VEF_EMPTY_POLICY: &str = "ERR_VEF_EMPTY_POLICY";
    pub const ERR_VEF_INVALID_SYNTAX: &str = "ERR_VEF_INVALID_SYNTAX";
    pub const ERR_VEF_MISSING_COVERAGE: &str = "ERR_VEF_MISSING_COVERAGE";
    pub const ERR_VEF_DUPLICATE_RULE: &str = "ERR_VEF_DUPLICATE_RULE";
    pub const ERR_VEF_INVALID_PREDICATE: &str = "ERR_VEF_INVALID_PREDICATE";
    pub const ERR_VEF_UNKNOWN_ACTION_CLASS: &str = "ERR_VEF_UNKNOWN_ACTION_CLASS";
    pub const ERR_VEF_NO_CONDITIONS: &str = "ERR_VEF_NO_CONDITIONS";
    pub const ERR_VEF_HASH_MISMATCH: &str = "ERR_VEF_HASH_MISMATCH";
    pub const ERR_VEF_VERSION_MISMATCH: &str = "ERR_VEF_VERSION_MISMATCH";
    pub const ERR_VEF_SERIALIZATION: &str = "ERR_VEF_SERIALIZATION";
}

// ── Core types ──────────────────────────────────────────────────────────────

/// High-risk action classes that require verifiable policy constraints.
/// INV-VEF-COVERAGE requires every variant to have at least one predicate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionClass {
    /// Network egress/ingress operations.
    Network,
    /// Filesystem read/write operations.
    FileSystem,
    /// Process spawning and management.
    Process,
    /// Access to secrets, keys, and credentials.
    SecretAccess,
    /// Runtime policy state transitions.
    PolicyTransition,
    /// Promotion of artifacts through trust gates.
    ArtifactPromotion,
}

impl ActionClass {
    /// All defined action classes, in canonical order.
    pub const ALL: &'static [ActionClass] = &[
        ActionClass::Network,
        ActionClass::FileSystem,
        ActionClass::Process,
        ActionClass::SecretAccess,
        ActionClass::PolicyTransition,
        ActionClass::ArtifactPromotion,
    ];

    /// Parse an action class from a string token.
    pub fn from_token(token: &str) -> Option<ActionClass> {
        let normalized = token.trim().to_ascii_lowercase().replace('-', "_");
        match normalized.as_str() {
            "network" => Some(ActionClass::Network),
            "filesystem" | "file_system" => Some(ActionClass::FileSystem),
            "process" => Some(ActionClass::Process),
            "secret_access" | "secretaccess" | "secret" => Some(ActionClass::SecretAccess),
            "policy_transition" | "policytransition" | "policy" => {
                Some(ActionClass::PolicyTransition)
            }
            "artifact_promotion" | "artifactpromotion" | "artifact" => {
                Some(ActionClass::ArtifactPromotion)
            }
            _ => None,
        }
    }

    /// Canonical string representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            ActionClass::Network => "network",
            ActionClass::FileSystem => "file_system",
            ActionClass::Process => "process",
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

/// Comparison operator used in predicate conditions.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComparisonOp {
    Equals,
    NotEquals,
    Contains,
    NotContains,
    GreaterThan,
    LessThan,
    GreaterOrEqual,
    LessOrEqual,
    Matches,
    OneOf,
}

impl ComparisonOp {
    /// Parse from string token.
    pub fn from_token(token: &str) -> Option<ComparisonOp> {
        match token.trim().to_ascii_lowercase().as_str() {
            "eq" | "equals" | "==" => Some(ComparisonOp::Equals),
            "neq" | "not_equals" | "!=" => Some(ComparisonOp::NotEquals),
            "contains" | "in" => Some(ComparisonOp::Contains),
            "not_contains" | "not_in" => Some(ComparisonOp::NotContains),
            "gt" | ">" => Some(ComparisonOp::GreaterThan),
            "lt" | "<" => Some(ComparisonOp::LessThan),
            "gte" | ">=" => Some(ComparisonOp::GreaterOrEqual),
            "lte" | "<=" => Some(ComparisonOp::LessOrEqual),
            "matches" | "~=" => Some(ComparisonOp::Matches),
            "one_of" | "oneof" => Some(ComparisonOp::OneOf),
            _ => None,
        }
    }
}

/// A single condition in a policy constraint (field + operator + value).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Condition {
    /// Field path (e.g., "destination.host", "path.prefix").
    pub field: String,
    /// Comparison operator.
    pub op: ComparisonOp,
    /// Expected value (as string, interpreted by the proof checker).
    pub value: String,
}

/// Effect to enforce when a policy rule matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyEffect {
    /// Allow the action.
    Allow,
    /// Deny the action.
    Deny,
    /// Require additional approval (e.g., operator confirmation).
    RequireApproval,
    /// Log only, no enforcement.
    AuditOnly,
}

/// A single policy rule in the constraint language.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct PolicyRule {
    /// Unique identifier for this rule within its policy set.
    pub rule_id: String,
    /// Action class this rule applies to.
    pub action_class: ActionClass,
    /// Human-readable description of the rule.
    pub description: String,
    /// Conditions that must all be satisfied (conjunction).
    pub conditions: Vec<Condition>,
    /// Effect when the rule matches.
    pub effect: PolicyEffect,
    /// Priority (lower = higher precedence).
    pub priority: u32,
}

/// A complete policy definition to be compiled into proof-checkable predicates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyDefinition {
    /// Policy set identifier.
    pub policy_id: String,
    /// Human-readable name.
    pub name: String,
    /// Semantic version of this policy definition.
    pub version: String,
    /// Ordered list of policy rules.
    pub rules: Vec<PolicyRule>,
}

/// A proof-checkable predicate generated from a policy rule. INV-VEF-TRACEABLE
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Predicate {
    /// Unique predicate identifier.
    pub predicate_id: String,
    /// The action class this predicate checks.
    pub action_class: ActionClass,
    /// Source rule identifier (traceability link).
    pub source_rule_id: String,
    /// Canonical predicate expression (serialized conditions).
    pub expression: String,
    /// Expected effect.
    pub effect: PolicyEffect,
    /// Priority inherited from the source rule.
    pub priority: u32,
    /// SHA-256 hash of the predicate expression for integrity checking.
    pub expression_hash: String,
}

/// The compiled predicate set with version metadata. INV-VEF-VERSIONED
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PredicateSet {
    /// Schema version of this predicate set format.
    pub schema_version: String,
    /// Compiler version that produced this set.
    pub compiler_version: String,
    /// Source policy identifier.
    pub source_policy_id: String,
    /// Source policy version.
    pub source_policy_version: String,
    /// SHA-256 hash of the canonical serialization of the source policy.
    pub policy_snapshot_hash: String,
    /// Compiled predicates, keyed by predicate_id (BTreeMap for determinism).
    pub predicates: BTreeMap<String, Predicate>,
    /// Coverage map: action class -> list of predicate_ids covering it.
    pub coverage: BTreeMap<String, Vec<String>>,
    /// Compilation timestamp (ISO 8601), set to empty for deterministic tests.
    pub compiled_at: String,
    /// Trace correlation ID for this compilation.
    pub trace_id: String,
}

/// Compilation event logged during constraint compilation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompileEvent {
    /// Event code (VEF-COMPILE-*).
    pub event_code: String,
    /// Trace correlation ID.
    pub trace_id: String,
    /// Human-readable detail.
    pub detail: String,
}

/// Classification of compilation errors. INV-VEF-CLASSIFIED-ERRORS
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompileError {
    /// Stable error code.
    pub code: String,
    /// Event code for structured logging.
    pub event_code: String,
    /// Human-readable message.
    pub message: String,
    /// Optional source rule that caused the error.
    pub source_rule_id: Option<String>,
}

impl fmt::Display for CompileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}", self.code, self.message)
    }
}

/// Result of a compilation operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompileResult {
    /// Whether compilation succeeded.
    pub success: bool,
    /// Compiled predicate set (present on success).
    pub predicate_set: Option<PredicateSet>,
    /// Errors encountered during compilation.
    pub errors: Vec<CompileError>,
    /// Events logged during compilation.
    pub events: Vec<CompileEvent>,
    /// Warning count.
    pub warning_count: usize,
}

// ── Compiler ────────────────────────────────────────────────────────────────

/// The constraint compiler that translates policy definitions into proof-checkable
/// predicate sets. INV-VEF-DETERMINISTIC: outputs are deterministic for identical inputs.
#[derive(Debug, Clone)]
pub struct ConstraintCompiler {
    /// Trace correlation ID for this compilation session.
    trace_id: String,
}

impl ConstraintCompiler {
    /// Create a new compiler with the given trace ID.
    pub fn new(trace_id: &str) -> Self {
        Self {
            trace_id: trace_id.to_string(),
        }
    }

    /// Compile a policy definition into a predicate set.
    /// INV-VEF-DETERMINISTIC: identical inputs yield identical outputs.
    /// INV-VEF-COVERAGE: validates all required action classes are covered.
    pub fn compile(&self, policy: &PolicyDefinition) -> CompileResult {
        let mut events = Vec::new();
        let mut errors = Vec::new();

        // VEF-COMPILE-001: Compilation started
        events.push(CompileEvent {
            event_code: event_codes::VEF_COMPILE_001.to_string(),
            trace_id: self.trace_id.clone(),
            detail: format!(
                "Compilation started for policy '{}' v{}",
                policy.policy_id, policy.version
            ),
        });

        // Validate: empty policy
        if policy.rules.is_empty() {
            errors.push(CompileError {
                code: error_codes::ERR_VEF_EMPTY_POLICY.to_string(),
                event_code: event_codes::VEF_COMPILE_ERR_EMPTY.to_string(),
                message: "Policy definition contains no rules".to_string(),
                source_rule_id: None,
            });
            return CompileResult {
                success: false,
                predicate_set: None,
                errors,
                events,
                warning_count: 0,
            };
        }

        // Validate: duplicate rule IDs
        let mut seen_ids = std::collections::BTreeSet::new();
        for rule in &policy.rules {
            if !seen_ids.insert(&rule.rule_id) {
                errors.push(CompileError {
                    code: error_codes::ERR_VEF_DUPLICATE_RULE.to_string(),
                    event_code: event_codes::VEF_COMPILE_ERR_DUPLICATE.to_string(),
                    message: format!("Duplicate rule identifier: '{}'", rule.rule_id),
                    source_rule_id: Some(rule.rule_id.clone()),
                });
            }
        }

        // Validate: rules with no conditions
        for rule in &policy.rules {
            if rule.conditions.is_empty() {
                errors.push(CompileError {
                    code: error_codes::ERR_VEF_NO_CONDITIONS.to_string(),
                    event_code: event_codes::VEF_COMPILE_ERR_NO_CONDITIONS.to_string(),
                    message: format!("Rule '{}' has no conditions", rule.rule_id),
                    source_rule_id: Some(rule.rule_id.clone()),
                });
            }
        }

        // Validate: empty field or value in conditions
        for rule in &policy.rules {
            for condition in &rule.conditions {
                if condition.field.trim().is_empty() {
                    errors.push(CompileError {
                        code: error_codes::ERR_VEF_INVALID_PREDICATE.to_string(),
                        event_code: event_codes::VEF_COMPILE_ERR_PREDICATE.to_string(),
                        message: format!(
                            "Rule '{}' has a condition with an empty field",
                            rule.rule_id
                        ),
                        source_rule_id: Some(rule.rule_id.clone()),
                    });
                }
            }
        }

        if !errors.is_empty() {
            return CompileResult {
                success: false,
                predicate_set: None,
                errors,
                events,
                warning_count: 0,
            };
        }

        // Compute policy snapshot hash. INV-VEF-VERSIONED
        let policy_snapshot_hash = self.compute_policy_hash(policy);

        // Compile rules into predicates. INV-VEF-TRACEABLE
        let mut predicates = BTreeMap::new();
        let mut coverage: BTreeMap<String, Vec<String>> = BTreeMap::new();

        for rule in &policy.rules {
            let predicate = self.compile_rule(rule, &policy.policy_id);
            let action_key = rule.action_class.as_str().to_string();
            coverage
                .entry(action_key)
                .or_default()
                .push(predicate.predicate_id.clone());
            predicates.insert(predicate.predicate_id.clone(), predicate);
        }

        // Validate coverage: every action class must have at least one predicate.
        // INV-VEF-COVERAGE
        let mut warning_count = 0;
        let covered_classes: std::collections::BTreeSet<&str> =
            coverage.keys().map(|k| k.as_str()).collect();
        for ac in ActionClass::ALL {
            if !covered_classes.contains(ac.as_str()) {
                warning_count += 1;
                events.push(CompileEvent {
                    event_code: event_codes::VEF_COMPILE_WARN.to_string(),
                    trace_id: self.trace_id.clone(),
                    detail: format!(
                        "Action class '{}' has no covering predicate in this policy",
                        ac.as_str()
                    ),
                });
            }
        }

        let predicate_set = PredicateSet {
            schema_version: SCHEMA_VERSION.to_string(),
            compiler_version: COMPILER_VERSION.to_string(),
            source_policy_id: policy.policy_id.clone(),
            source_policy_version: policy.version.clone(),
            policy_snapshot_hash,
            predicates,
            coverage,
            compiled_at: String::new(), // left empty for deterministic output
            trace_id: self.trace_id.clone(),
        };

        // VEF-COMPILE-002: Compilation succeeded
        events.push(CompileEvent {
            event_code: event_codes::VEF_COMPILE_002.to_string(),
            trace_id: self.trace_id.clone(),
            detail: format!(
                "Compilation succeeded: {} predicates, {} action classes covered",
                predicate_set.predicates.len(),
                predicate_set.coverage.len()
            ),
        });

        CompileResult {
            success: true,
            predicate_set: Some(predicate_set),
            errors,
            events,
            warning_count,
        }
    }

    /// Compile a single policy rule into a predicate. INV-VEF-TRACEABLE
    fn compile_rule(&self, rule: &PolicyRule, policy_id: &str) -> Predicate {
        let expression = self.build_expression(&rule.conditions);
        let expression_hash = self.sha256_hex(&expression);
        let predicate_id = format!("{}.{}.{}", policy_id, rule.action_class, rule.rule_id);

        Predicate {
            predicate_id,
            action_class: rule.action_class,
            source_rule_id: rule.rule_id.clone(),
            expression,
            effect: rule.effect,
            priority: rule.priority,
            expression_hash,
        }
    }

    /// Build a canonical predicate expression from conditions.
    /// Conditions are sorted for deterministic output. INV-VEF-DETERMINISTIC
    fn build_expression(&self, conditions: &[Condition]) -> String {
        let mut sorted: Vec<&Condition> = conditions.iter().collect();
        sorted.sort();

        let parts: Vec<String> = sorted
            .iter()
            .map(|c| {
                format!(
                    "({} {:?} {})",
                    c.field,
                    c.op,
                    serde_json::to_string(&c.value).unwrap_or_else(|_| format!("\"{}\"", c.value))
                )
            })
            .collect();

        if parts.len() == 1 {
            parts[0].clone()
        } else {
            format!("(AND {})", parts.join(" "))
        }
    }

    /// Compute SHA-256 hash of the canonical policy serialization.
    /// Uses BTreeMap-based serde_json for deterministic output. INV-VEF-DETERMINISTIC
    fn compute_policy_hash(&self, policy: &PolicyDefinition) -> String {
        let canonical = serde_json::to_string(policy).unwrap_or_default();
        self.sha256_hex(&canonical)
    }

    /// Compute SHA-256 hex digest.
    fn sha256_hex(&self, input: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"constraint_compiler_hash_v1:");
        hasher.update(input.as_bytes());
        hex::encode(hasher.finalize())
    }

    /// Verify that a predicate set matches its claimed policy snapshot hash.
    /// Returns true if the hash matches. INV-VEF-VERSIONED
    pub fn verify_snapshot_hash(
        &self,
        policy: &PolicyDefinition,
        predicate_set: &PredicateSet,
    ) -> bool {
        let computed = self.compute_policy_hash(policy);
        computed == predicate_set.policy_snapshot_hash
    }

    /// Verify that a predicate expression matches its claimed hash.
    pub fn verify_predicate_integrity(&self, predicate: &Predicate) -> bool {
        let computed = self.sha256_hex(&predicate.expression);
        computed == predicate.expression_hash
    }

    /// Perform a coverage check: returns the set of action classes NOT covered.
    pub fn check_coverage(&self, predicate_set: &PredicateSet) -> Vec<ActionClass> {
        let covered: std::collections::BTreeSet<&str> =
            predicate_set.coverage.keys().map(|k| k.as_str()).collect();
        ActionClass::ALL
            .iter()
            .filter(|ac| !covered.contains(ac.as_str()))
            .copied()
            .collect()
    }

    /// Round-trip validation: compile, then verify that re-compilation produces
    /// identical output. INV-VEF-IDEMPOTENT
    pub fn round_trip_validate(&self, policy: &PolicyDefinition) -> bool {
        let first = self.compile(policy);
        let second = self.compile(policy);
        first == second
    }
}

// ── Builder helpers ─────────────────────────────────────────────────────────

impl PolicyDefinition {
    /// Create a minimal policy definition for testing.
    pub fn new(policy_id: &str, name: &str, version: &str) -> Self {
        Self {
            policy_id: policy_id.to_string(),
            name: name.to_string(),
            version: version.to_string(),
            rules: Vec::new(),
        }
    }

    /// Add a rule to this policy definition.
    pub fn with_rule(mut self, rule: PolicyRule) -> Self {
        self.rules.push(rule);
        self
    }
}

impl PolicyRule {
    /// Create a new policy rule.
    pub fn new(
        rule_id: &str,
        action_class: ActionClass,
        description: &str,
        effect: PolicyEffect,
    ) -> Self {
        Self {
            rule_id: rule_id.to_string(),
            action_class,
            description: description.to_string(),
            conditions: Vec::new(),
            effect,
            priority: 100,
        }
    }

    /// Add a condition to this rule.
    pub fn with_condition(mut self, field: &str, op: ComparisonOp, value: &str) -> Self {
        self.conditions.push(Condition {
            field: field.to_string(),
            op,
            value: value.to_string(),
        });
        self
    }

    /// Set the priority of this rule.
    pub fn with_priority(mut self, priority: u32) -> Self {
        self.priority = priority;
        self
    }
}

/// Build a full-coverage demo policy covering all six action classes.
pub fn demo_full_coverage_policy() -> PolicyDefinition {
    PolicyDefinition::new("demo-vef-policy", "Demo VEF Policy", "1.0.0")
        .with_rule(
            PolicyRule::new(
                "net-egress-allow-internal",
                ActionClass::Network,
                "Allow network egress to internal endpoints",
                PolicyEffect::Allow,
            )
            .with_condition(
                "destination.host",
                ComparisonOp::Matches,
                "*.internal.local",
            )
            .with_priority(10),
        )
        .with_rule(
            PolicyRule::new(
                "net-egress-deny-external",
                ActionClass::Network,
                "Deny network egress to external endpoints by default",
                PolicyEffect::Deny,
            )
            .with_condition(
                "destination.host",
                ComparisonOp::NotContains,
                ".internal.local",
            )
            .with_priority(100),
        )
        .with_rule(
            PolicyRule::new(
                "fs-read-allow-data",
                ActionClass::FileSystem,
                "Allow filesystem reads from data directory",
                PolicyEffect::Allow,
            )
            .with_condition("path.prefix", ComparisonOp::Equals, "/data/")
            .with_condition("operation", ComparisonOp::Equals, "read")
            .with_priority(10),
        )
        .with_rule(
            PolicyRule::new(
                "fs-write-deny-system",
                ActionClass::FileSystem,
                "Deny filesystem writes to system directories",
                PolicyEffect::Deny,
            )
            .with_condition("path.prefix", ComparisonOp::Equals, "/etc/")
            .with_condition("operation", ComparisonOp::Equals, "write")
            .with_priority(5),
        )
        .with_rule(
            PolicyRule::new(
                "proc-spawn-require-approval",
                ActionClass::Process,
                "Require approval for process spawning",
                PolicyEffect::RequireApproval,
            )
            .with_condition("executable", ComparisonOp::NotEquals, "")
            .with_priority(50),
        )
        .with_rule(
            PolicyRule::new(
                "secret-read-audit",
                ActionClass::SecretAccess,
                "Audit all secret access operations",
                PolicyEffect::AuditOnly,
            )
            .with_condition("secret.scope", ComparisonOp::NotEquals, "")
            .with_priority(10),
        )
        .with_rule(
            PolicyRule::new(
                "policy-transition-require-approval",
                ActionClass::PolicyTransition,
                "Require approval for policy state transitions",
                PolicyEffect::RequireApproval,
            )
            .with_condition("transition.from", ComparisonOp::NotEquals, "")
            .with_condition("transition.to", ComparisonOp::NotEquals, "")
            .with_priority(5),
        )
        .with_rule(
            PolicyRule::new(
                "artifact-promote-deny-unsigned",
                ActionClass::ArtifactPromotion,
                "Deny promotion of unsigned artifacts",
                PolicyEffect::Deny,
            )
            .with_condition("artifact.signed", ComparisonOp::Equals, "false")
            .with_priority(1),
        )
        .with_rule(
            PolicyRule::new(
                "artifact-promote-allow-signed",
                ActionClass::ArtifactPromotion,
                "Allow promotion of signed artifacts",
                PolicyEffect::Allow,
            )
            .with_condition("artifact.signed", ComparisonOp::Equals, "true")
            .with_priority(10),
        )
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn test_compiler() -> ConstraintCompiler {
        ConstraintCompiler::new("test-trace-001")
    }

    fn minimal_policy() -> PolicyDefinition {
        PolicyDefinition::new("test-policy", "Test Policy", "1.0.0").with_rule(
            PolicyRule::new("r1", ActionClass::Network, "test rule", PolicyEffect::Deny)
                .with_condition("destination.host", ComparisonOp::Equals, "evil.com"),
        )
    }

    // ── 1. Basic compilation succeeds ──

    #[test]
    fn test_compile_minimal_policy_succeeds() {
        let compiler = test_compiler();
        let result = compiler.compile(&minimal_policy());
        assert!(result.success, "compilation should succeed");
        assert!(result.predicate_set.is_some());
        assert!(result.errors.is_empty());
    }

    // ── 2. Empty policy produces classified error ──

    #[test]
    fn test_compile_empty_policy_error() {
        let compiler = test_compiler();
        let policy = PolicyDefinition::new("empty", "Empty", "1.0.0");
        let result = compiler.compile(&policy);
        assert!(!result.success);
        assert!(result.predicate_set.is_none());
        assert_eq!(result.errors.len(), 1);
        assert_eq!(result.errors[0].code, error_codes::ERR_VEF_EMPTY_POLICY);
        assert_eq!(
            result.errors[0].event_code,
            event_codes::VEF_COMPILE_ERR_EMPTY
        );
    }

    // ── 3. Duplicate rule IDs produce error ──

    #[test]
    fn test_compile_duplicate_rule_ids() {
        let compiler = test_compiler();
        let policy = PolicyDefinition::new("dup", "Dup", "1.0.0")
            .with_rule(
                PolicyRule::new("r1", ActionClass::Network, "first", PolicyEffect::Allow)
                    .with_condition("f", ComparisonOp::Equals, "v"),
            )
            .with_rule(
                PolicyRule::new("r1", ActionClass::FileSystem, "second", PolicyEffect::Deny)
                    .with_condition("g", ComparisonOp::Equals, "w"),
            );
        let result = compiler.compile(&policy);
        assert!(!result.success);
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.code == error_codes::ERR_VEF_DUPLICATE_RULE)
        );
    }

    // ── 4. Rule with no conditions produces error ──

    #[test]
    fn test_compile_rule_no_conditions() {
        let compiler = test_compiler();
        let policy =
            PolicyDefinition::new("no-cond", "NoCond", "1.0.0").with_rule(PolicyRule::new(
                "r1",
                ActionClass::Network,
                "no conditions",
                PolicyEffect::Deny,
            ));
        let result = compiler.compile(&policy);
        assert!(!result.success);
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.code == error_codes::ERR_VEF_NO_CONDITIONS)
        );
    }

    // ── 5. Empty field in condition produces error ──

    #[test]
    fn test_compile_empty_field_condition() {
        let compiler = test_compiler();
        let policy =
            PolicyDefinition::new("bad-field", "BadField", "1.0.0").with_rule(
                PolicyRule::new("r1", ActionClass::Network, "bad", PolicyEffect::Deny)
                    .with_condition("", ComparisonOp::Equals, "x"),
            );
        let result = compiler.compile(&policy);
        assert!(!result.success);
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.code == error_codes::ERR_VEF_INVALID_PREDICATE)
        );
    }

    // ── 6. Deterministic output (INV-VEF-DETERMINISTIC) ──

    #[test]
    fn test_deterministic_compilation() {
        let compiler = test_compiler();
        let policy = demo_full_coverage_policy();
        let r1 = compiler.compile(&policy);
        let r2 = compiler.compile(&policy);
        assert_eq!(r1, r2, "identical inputs must produce identical outputs");
    }

    // ── 7. Idempotent round-trip (INV-VEF-IDEMPOTENT) ──

    #[test]
    fn test_round_trip_idempotent() {
        let compiler = test_compiler();
        let policy = demo_full_coverage_policy();
        assert!(
            compiler.round_trip_validate(&policy),
            "round-trip must be idempotent"
        );
    }

    // ── 8. Full coverage demo policy covers all action classes ──

    #[test]
    fn test_full_coverage_all_action_classes() {
        let compiler = test_compiler();
        let policy = demo_full_coverage_policy();
        let result = compiler.compile(&policy);
        assert!(result.success);
        let ps = result.predicate_set.unwrap();
        let uncovered = compiler.check_coverage(&ps);
        assert!(
            uncovered.is_empty(),
            "All action classes should be covered, but missing: {:?}",
            uncovered
        );
    }

    // ── 9. Version metadata present (INV-VEF-VERSIONED) ──

    #[test]
    fn test_version_metadata_present() {
        let compiler = test_compiler();
        let policy = minimal_policy();
        let result = compiler.compile(&policy);
        let ps = result.predicate_set.unwrap();
        assert_eq!(ps.schema_version, SCHEMA_VERSION);
        assert_eq!(ps.compiler_version, COMPILER_VERSION);
        assert_eq!(ps.source_policy_id, "test-policy");
        assert_eq!(ps.source_policy_version, "1.0.0");
        assert!(!ps.policy_snapshot_hash.is_empty());
    }

    // ── 10. Snapshot hash verification (INV-VEF-VERSIONED) ──

    #[test]
    fn test_snapshot_hash_matches() {
        let compiler = test_compiler();
        let policy = minimal_policy();
        let result = compiler.compile(&policy);
        let ps = result.predicate_set.unwrap();
        assert!(compiler.verify_snapshot_hash(&policy, &ps));
    }

    // ── 11. Modified policy produces different hash ──

    #[test]
    fn test_modified_policy_different_hash() {
        let compiler = test_compiler();
        let policy1 = minimal_policy();
        let policy2 = PolicyDefinition::new("test-policy", "Test Policy", "1.0.1").with_rule(
            PolicyRule::new("r1", ActionClass::Network, "changed", PolicyEffect::Allow)
                .with_condition("destination.host", ComparisonOp::Equals, "good.com"),
        );
        let r1 = compiler.compile(&policy1);
        let r2 = compiler.compile(&policy2);
        let ps1 = r1.predicate_set.unwrap();
        let ps2 = r2.predicate_set.unwrap();
        assert_ne!(
            ps1.policy_snapshot_hash, ps2.policy_snapshot_hash,
            "Different policies must have different hashes"
        );
    }

    // ── 12. Predicate integrity verification ──

    #[test]
    fn test_predicate_integrity() {
        let compiler = test_compiler();
        let policy = minimal_policy();
        let result = compiler.compile(&policy);
        let ps = result.predicate_set.unwrap();
        for predicate in ps.predicates.values() {
            assert!(
                compiler.verify_predicate_integrity(predicate),
                "Predicate {} integrity check failed",
                predicate.predicate_id
            );
        }
    }

    // ── 13. Traceability: predicate links to source rule (INV-VEF-TRACEABLE) ──

    #[test]
    fn test_predicate_traceability() {
        let compiler = test_compiler();
        let policy = minimal_policy();
        let result = compiler.compile(&policy);
        let ps = result.predicate_set.unwrap();
        for predicate in ps.predicates.values() {
            assert!(
                !predicate.source_rule_id.is_empty(),
                "Predicate must have a source_rule_id"
            );
            assert!(
                policy
                    .rules
                    .iter()
                    .any(|r| r.rule_id == predicate.source_rule_id),
                "source_rule_id must match a rule in the policy"
            );
        }
    }

    // ── 14. Event codes in compilation events ──

    #[test]
    fn test_event_codes_present() {
        let compiler = test_compiler();
        let policy = minimal_policy();
        let result = compiler.compile(&policy);
        assert!(
            result
                .events
                .iter()
                .any(|e| e.event_code == event_codes::VEF_COMPILE_001),
            "Should have VEF-COMPILE-001 start event"
        );
        assert!(
            result
                .events
                .iter()
                .any(|e| e.event_code == event_codes::VEF_COMPILE_002),
            "Should have VEF-COMPILE-002 success event"
        );
    }

    // ── 15. Error events for invalid policies ──

    #[test]
    fn test_error_event_codes() {
        let compiler = test_compiler();
        let empty = PolicyDefinition::new("e", "E", "1.0.0");
        let result = compiler.compile(&empty);
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.event_code == event_codes::VEF_COMPILE_ERR_EMPTY),
            "Should have VEF-COMPILE-ERR-EMPTY event"
        );
    }

    // ── 16. ActionClass parsing ──

    #[test]
    fn test_action_class_from_token() {
        assert_eq!(
            ActionClass::from_token("network"),
            Some(ActionClass::Network)
        );
        assert_eq!(
            ActionClass::from_token("FileSystem"),
            Some(ActionClass::FileSystem)
        );
        assert_eq!(
            ActionClass::from_token("file_system"),
            Some(ActionClass::FileSystem)
        );
        assert_eq!(
            ActionClass::from_token("process"),
            Some(ActionClass::Process)
        );
        assert_eq!(
            ActionClass::from_token("secret_access"),
            Some(ActionClass::SecretAccess)
        );
        assert_eq!(
            ActionClass::from_token("secret"),
            Some(ActionClass::SecretAccess)
        );
        assert_eq!(
            ActionClass::from_token("policy_transition"),
            Some(ActionClass::PolicyTransition)
        );
        assert_eq!(
            ActionClass::from_token("artifact_promotion"),
            Some(ActionClass::ArtifactPromotion)
        );
        assert_eq!(ActionClass::from_token("unknown"), None);
    }

    // ── 17. ComparisonOp parsing ──

    #[test]
    fn test_comparison_op_from_token() {
        assert_eq!(ComparisonOp::from_token("eq"), Some(ComparisonOp::Equals));
        assert_eq!(ComparisonOp::from_token("=="), Some(ComparisonOp::Equals));
        assert_eq!(
            ComparisonOp::from_token("neq"),
            Some(ComparisonOp::NotEquals)
        );
        assert_eq!(
            ComparisonOp::from_token("contains"),
            Some(ComparisonOp::Contains)
        );
        assert_eq!(
            ComparisonOp::from_token(">"),
            Some(ComparisonOp::GreaterThan)
        );
        assert_eq!(
            ComparisonOp::from_token("<="),
            Some(ComparisonOp::LessOrEqual)
        );
        assert_eq!(
            ComparisonOp::from_token("matches"),
            Some(ComparisonOp::Matches)
        );
        assert_eq!(
            ComparisonOp::from_token("one_of"),
            Some(ComparisonOp::OneOf)
        );
        assert_eq!(ComparisonOp::from_token("garbage"), None);
    }

    // ── 18. ActionClass canonical ALL list ──

    #[test]
    fn test_action_class_all_covers_six() {
        assert_eq!(ActionClass::ALL.len(), 6);
        let names: Vec<&str> = ActionClass::ALL.iter().map(|ac| ac.as_str()).collect();
        assert!(names.contains(&"network"));
        assert!(names.contains(&"file_system"));
        assert!(names.contains(&"process"));
        assert!(names.contains(&"secret_access"));
        assert!(names.contains(&"policy_transition"));
        assert!(names.contains(&"artifact_promotion"));
    }

    // ── 19. Coverage check detects missing action class ──

    #[test]
    fn test_coverage_check_missing_class() {
        let compiler = test_compiler();
        let policy = minimal_policy(); // only covers Network
        let result = compiler.compile(&policy);
        let ps = result.predicate_set.unwrap();
        let uncovered = compiler.check_coverage(&ps);
        assert_eq!(uncovered.len(), 5, "5 action classes should be uncovered");
        assert!(uncovered.contains(&ActionClass::FileSystem));
        assert!(uncovered.contains(&ActionClass::Process));
        assert!(uncovered.contains(&ActionClass::SecretAccess));
        assert!(uncovered.contains(&ActionClass::PolicyTransition));
        assert!(uncovered.contains(&ActionClass::ArtifactPromotion));
    }

    // ── 20. Multi-condition expression uses AND ──

    #[test]
    fn test_multi_condition_expression_and() {
        let compiler = test_compiler();
        let policy = PolicyDefinition::new("mc", "MultiCond", "1.0.0").with_rule(
            PolicyRule::new("r1", ActionClass::FileSystem, "multi", PolicyEffect::Deny)
                .with_condition("path", ComparisonOp::Equals, "/etc")
                .with_condition("op", ComparisonOp::Equals, "write"),
        );
        let result = compiler.compile(&policy);
        let ps = result.predicate_set.unwrap();
        let pred = ps.predicates.values().next().unwrap();
        assert!(
            pred.expression.starts_with("(AND "),
            "Multi-condition should use AND: {}",
            pred.expression
        );
    }

    // ── 21. Single-condition expression has no AND wrapper ──

    #[test]
    fn test_single_condition_expression_no_and() {
        let compiler = test_compiler();
        let policy = minimal_policy();
        let result = compiler.compile(&policy);
        let ps = result.predicate_set.unwrap();
        let pred = ps.predicates.values().next().unwrap();
        assert!(
            !pred.expression.starts_with("(AND "),
            "Single condition should not use AND: {}",
            pred.expression
        );
    }

    // ── 22. Predicate IDs are deterministic ──

    #[test]
    fn test_predicate_id_format() {
        let compiler = test_compiler();
        let policy = minimal_policy();
        let result = compiler.compile(&policy);
        let ps = result.predicate_set.unwrap();
        let pred = ps.predicates.values().next().unwrap();
        assert_eq!(pred.predicate_id, "test-policy.network.r1");
    }

    // ── 23. BTreeMap ensures sorted predicate output ──

    #[test]
    fn test_predicates_sorted_by_id() {
        let compiler = test_compiler();
        let policy = demo_full_coverage_policy();
        let result = compiler.compile(&policy);
        let ps = result.predicate_set.unwrap();
        let keys: Vec<&String> = ps.predicates.keys().collect();
        let mut sorted_keys = keys.clone();
        sorted_keys.sort();
        assert_eq!(keys, sorted_keys, "BTreeMap keys must be sorted");
    }

    // ── 24. Serialization round-trip preserves structure ──

    #[test]
    fn test_predicate_set_serialization_roundtrip() {
        let compiler = test_compiler();
        let policy = demo_full_coverage_policy();
        let result = compiler.compile(&policy);
        let ps = result.predicate_set.unwrap();
        let json = serde_json::to_string(&ps).unwrap();
        let deserialized: PredicateSet = serde_json::from_str(&json).unwrap();
        assert_eq!(ps, deserialized);
    }

    // ── 25. Warning count for partial coverage ──

    #[test]
    fn test_warning_count_partial_coverage() {
        let compiler = test_compiler();
        let policy = minimal_policy();
        let result = compiler.compile(&policy);
        assert!(result.success, "Should still succeed with partial coverage");
        assert_eq!(
            result.warning_count, 5,
            "Should warn about 5 uncovered action classes"
        );
    }

    // ── 26. PolicyEffect variants all usable ──

    #[test]
    fn test_policy_effect_variants() {
        let effects = [
            PolicyEffect::Allow,
            PolicyEffect::Deny,
            PolicyEffect::RequireApproval,
            PolicyEffect::AuditOnly,
        ];
        for effect in &effects {
            let json = serde_json::to_string(effect).unwrap();
            let back: PolicyEffect = serde_json::from_str(&json).unwrap();
            assert_eq!(*effect, back);
        }
    }

    // ── 27. CompileError Display impl ──

    #[test]
    fn test_compile_error_display() {
        let err = CompileError {
            code: "ERR_VEF_EMPTY_POLICY".to_string(),
            event_code: "VEF-COMPILE-ERR-EMPTY".to_string(),
            message: "Policy is empty".to_string(),
            source_rule_id: None,
        };
        let display = format!("{err}");
        assert!(display.contains("ERR_VEF_EMPTY_POLICY"));
        assert!(display.contains("Policy is empty"));
    }

    // ── 28. ActionClass Display impl ──

    #[test]
    fn test_action_class_display() {
        assert_eq!(format!("{}", ActionClass::Network), "network");
        assert_eq!(format!("{}", ActionClass::FileSystem), "file_system");
        assert_eq!(
            format!("{}", ActionClass::ArtifactPromotion),
            "artifact_promotion"
        );
    }

    // ── 29. Demo policy has expected rule count ──

    #[test]
    fn test_demo_policy_rule_count() {
        let policy = demo_full_coverage_policy();
        assert!(
            policy.rules.len() >= 8,
            "Demo policy should have at least 8 rules"
        );
    }

    // ── 30. Conditions are sorted deterministically in expression ──

    #[test]
    fn test_condition_sort_determinism() {
        let compiler = test_compiler();

        // Build two policies with conditions in different order
        let policy_a = PolicyDefinition::new("sort", "Sort", "1.0.0").with_rule(
            PolicyRule::new("r1", ActionClass::FileSystem, "test", PolicyEffect::Deny)
                .with_condition("z_field", ComparisonOp::Equals, "z")
                .with_condition("a_field", ComparisonOp::Equals, "a"),
        );
        let policy_b = PolicyDefinition::new("sort", "Sort", "1.0.0").with_rule(
            PolicyRule::new("r1", ActionClass::FileSystem, "test", PolicyEffect::Deny)
                .with_condition("a_field", ComparisonOp::Equals, "a")
                .with_condition("z_field", ComparisonOp::Equals, "z"),
        );

        let r_a = compiler.compile(&policy_a);
        let r_b = compiler.compile(&policy_b);
        let ps_a = r_a.predicate_set.unwrap();
        let ps_b = r_b.predicate_set.unwrap();

        let expr_a = ps_a.predicates.values().next().unwrap().expression.clone();
        let expr_b = ps_b.predicates.values().next().unwrap().expression.clone();
        assert_eq!(
            expr_a, expr_b,
            "Conditions should be sorted, producing identical expressions regardless of input order"
        );
    }
}
