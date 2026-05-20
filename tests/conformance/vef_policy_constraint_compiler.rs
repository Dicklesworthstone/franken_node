//! Conformance tests for bd-16fq: VEF policy-constraint language compiler.
//!
//! Validates multi-action policy compilation, deterministic outputs, and proof
//! worker envelope compatibility.

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use frankenengine_node::connector::vef_policy_constraints::{
        ActionClass, LANGUAGE_VERSION, PolicyRule, RuleEffect, RuntimePolicy, compile_policy,
        proof_generator_accepts, round_trip_semantics,
    };

    fn sample_policy() -> RuntimePolicy {
        RuntimePolicy {
            schema_version: LANGUAGE_VERSION.to_string(),
            policy_id: "bd-16fq-conformance".to_string(),
            require_full_action_coverage: true,
            rules: vec![
                rule(
                    "network-allow",
                    ActionClass::NetworkAccess,
                    RuleEffect::Require,
                    vec!["net.egress"],
                    vec![("max_endpoints", "5"), ("cidr_allowlist", "10.0.0.0/8")],
                ),
                rule(
                    "fs-guard",
                    ActionClass::FilesystemOperation,
                    RuleEffect::Require,
                    vec!["fs.read"],
                    vec![("allowed_prefix", "/srv/extensions")],
                ),
                rule(
                    "proc-deny",
                    ActionClass::ProcessSpawn,
                    RuleEffect::Deny,
                    vec![],
                    vec![("reason", "no-subprocesses")],
                ),
                rule(
                    "secret-require",
                    ActionClass::SecretAccess,
                    RuleEffect::Require,
                    vec!["secret.fetch"],
                    vec![("max_ttl_seconds", "300")],
                ),
                rule(
                    "transition-require",
                    ActionClass::PolicyTransition,
                    RuleEffect::Require,
                    vec!["policy.approval"],
                    vec![("required_signatures", "2")],
                ),
                rule(
                    "promotion-require",
                    ActionClass::ArtifactPromotion,
                    RuleEffect::Require,
                    vec!["artifact.promote"],
                    vec![("min_verifier_quorum", "3")],
                ),
            ],
        }
    }

    fn rule(
        rule_id: &str,
        action_class: ActionClass,
        effect: RuleEffect,
        capabilities: Vec<&str>,
        constraints: Vec<(&str, &str)>,
    ) -> PolicyRule {
        let constraints = constraints
            .into_iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect::<BTreeMap<_, _>>();
        PolicyRule {
            rule_id: rule_id.to_string(),
            action_class,
            effect,
            required_capabilities: capabilities.into_iter().map(str::to_string).collect(),
            constraints,
        }
    }

    #[test]
    fn compile_multi_action_policy_for_proof_worker() {
        let envelope = compile_policy(&sample_policy(), "trace-conformance-1").unwrap();

        assert_eq!(
            envelope.coverage.len(),
            6,
            "coverage must include all action classes"
        );
        assert!(
            proof_generator_accepts(&envelope),
            "compiled envelope rejected by proof worker shim"
        );
        assert!(
            envelope.predicates.len() >= 12,
            "expect decision + capability/constraint predicates"
        );
        assert!(
            envelope
                .predicates
                .iter()
                .all(|p| p.trace_link.contains("/rule:"))
        );
    }

    #[test]
    fn compile_output_is_deterministic_and_stable() {
        let policy = sample_policy();
        let first = compile_policy(&policy, "trace-conformance-2").unwrap();
        let second = compile_policy(&policy, "trace-conformance-2").unwrap();

        assert_eq!(first, second);
        assert_eq!(
            serde_json::to_string(&first).unwrap(),
            serde_json::to_string(&second).unwrap()
        );
    }

    #[test]
    fn compile_then_decompile_round_trip_semantics() {
        let ok = round_trip_semantics(&sample_policy(), "trace-conformance-3").unwrap();
        assert!(ok, "semantic projection should round-trip without loss");
    }

    #[test]
    fn missing_action_class_coverage_rejected() {
        let mut policy = sample_policy();
        policy
            .rules
            .retain(|r| !matches!(r.action_class, ActionClass::SecretAccess));

        let err = compile_policy(&policy, "trace-conformance-4").unwrap_err();
        assert!(
            err.code.ends_with("003"),
            "expected missing coverage code, got {}",
            err.code
        );
    }

    #[test]
    fn control_char_rule_id_rejection_does_not_echo_payload() {
        let mut policy = sample_policy();
        policy.rules[0].rule_id = "network\r\nINJECTED".to_string();

        let err = compile_policy(&policy, "trace-conformance-control").unwrap_err();

        assert!(
            err.message.contains("control characters"),
            "unexpected message: {}",
            err.message
        );
        assert!(
            err.rule_id.is_none(),
            "unsafe rule_id must not be retained in structured error metadata"
        );
        assert!(
            !err.to_string().contains("INJECTED"),
            "display text must not echo control-character payload"
        );
    }
}
