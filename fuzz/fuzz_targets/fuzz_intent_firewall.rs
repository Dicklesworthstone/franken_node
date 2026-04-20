#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::{Arbitrary, Unstructured, Result as ArbitraryResult};
use std::collections::BTreeMap;
use std::hint::black_box;

use frankenengine_node::security::intent_firewall::{
    EffectsFirewall, RemoteEffect, TrafficOrigin, IntentClassification,
    TrafficPolicy, TrafficPolicyRule, FirewallVerdict, PolicyOverride,
    IntentClassifier
};

/// Maximum reasonable string length for fuzzing inputs to prevent OOM.
const MAX_STRING_LEN: usize = 1024;

/// Maximum metadata entries to prevent excessive memory usage.
const MAX_METADATA_ENTRIES: usize = 50;

/// Maximum policy rules to prevent excessive computation.
const MAX_POLICY_RULES: usize = 20;

// Custom Arbitrary implementations for enums that don't derive it
impl<'a> Arbitrary<'a> for IntentClassification {
    fn arbitrary(u: &mut Unstructured<'a>) -> ArbitraryResult<Self> {
        let choice = u.int_in_range(0..=9)?;
        Ok(match choice {
            0 => IntentClassification::DataFetch,
            1 => IntentClassification::DataMutation,
            2 => IntentClassification::WebhookDispatch,
            3 => IntentClassification::AnalyticsExport,
            4 => IntentClassification::Exfiltration,
            5 => IntentClassification::CredentialForward,
            6 => IntentClassification::SideChannel,
            7 => IntentClassification::ServiceDiscovery,
            8 => IntentClassification::HealthCheck,
            _ => IntentClassification::ConfigSync,
        })
    }
}

impl<'a> Arbitrary<'a> for FirewallVerdict {
    fn arbitrary(u: &mut Unstructured<'a>) -> ArbitraryResult<Self> {
        let choice = u.int_in_range(0..=4)?;
        Ok(match choice {
            0 => FirewallVerdict::Allow,
            1 => FirewallVerdict::Challenge,
            2 => FirewallVerdict::Simulate,
            3 => FirewallVerdict::Deny,
            _ => FirewallVerdict::Quarantine,
        })
    }
}

#[derive(Arbitrary, Debug)]
struct FuzzRemoteEffect {
    effect_id: String,
    origin: FuzzTrafficOrigin,
    target_host: String,
    target_port: u16,
    method: String,
    path: String,
    has_sensitive_payload: bool,
    carries_credentials: bool,
    metadata_entries: Vec<(String, String)>,
}

#[derive(Arbitrary, Debug)]
enum FuzzTrafficOrigin {
    Extension { extension_id: String },
    NodeInternal { subsystem: String },
}

#[derive(Arbitrary, Debug)]
struct FuzzTrafficPolicy {
    rules: Vec<FuzzTrafficPolicyRule>,
}

#[derive(Arbitrary, Debug)]
struct FuzzTrafficPolicyRule {
    intent: IntentClassification,
    verdict: FirewallVerdict,
    priority: u32,
    host_patterns: Vec<String>,
}

#[derive(Arbitrary, Debug)]
struct FuzzPolicyOverride {
    extension_id: String,
    intent: IntentClassification,
    new_verdict: FirewallVerdict,
    justification: String,
    approved_by: String,
}

#[derive(Arbitrary, Debug)]
enum FuzzOperation {
    /// Test basic remote effect evaluation
    EvaluateEffect {
        effect: FuzzRemoteEffect,
        trace_id: String,
        timestamp: String,
    },
    /// Test intent classification with various attack vectors
    ClassifyIntent {
        effect: FuzzRemoteEffect,
    },
    /// Test serialization round-trip attacks
    SerializationRoundTrip {
        effect: FuzzRemoteEffect,
        policy: FuzzTrafficPolicy,
        override_rule: FuzzPolicyOverride,
    },
    /// Test host pattern matching edge cases
    HostPatternMatching {
        host_patterns: Vec<String>,
        target_hosts: Vec<String>,
    },
    /// Test policy conflict detection
    PolicyConflictDetection {
        conflicting_rules: Vec<FuzzTrafficPolicyRule>,
    },
    /// Test extension origin validation
    ExtensionOriginValidation {
        effect: FuzzRemoteEffect,
    },
    /// Test path traversal and injection in paths
    PathInjectionAttack {
        malicious_paths: Vec<String>,
        base_effect: FuzzRemoteEffect,
    },
}

impl FuzzRemoteEffect {
    fn to_real(self) -> RemoteEffect {
        let bounded_metadata: BTreeMap<String, String> = self.metadata_entries
            .into_iter()
            .take(MAX_METADATA_ENTRIES)
            .map(|(k, v)| (
                Self::bound_string(k),
                Self::bound_string(v)
            ))
            .collect();

        RemoteEffect {
            effect_id: Self::bound_string(self.effect_id),
            origin: self.origin.to_real(),
            target_host: Self::bound_string(self.target_host),
            target_port: self.target_port,
            method: Self::bound_string(self.method),
            path: Self::bound_string(self.path),
            has_sensitive_payload: self.has_sensitive_payload,
            carries_credentials: self.carries_credentials,
            metadata: bounded_metadata,
        }
    }

    fn bound_string(s: String) -> String {
        if s.len() > MAX_STRING_LEN {
            s[..MAX_STRING_LEN].to_string()
        } else {
            s
        }
    }
}

impl FuzzTrafficOrigin {
    fn to_real(self) -> TrafficOrigin {
        match self {
            Self::Extension { extension_id } => TrafficOrigin::Extension {
                extension_id: FuzzRemoteEffect::bound_string(extension_id)
            },
            Self::NodeInternal { subsystem } => TrafficOrigin::NodeInternal {
                subsystem: FuzzRemoteEffect::bound_string(subsystem)
            },
        }
    }
}

impl FuzzTrafficPolicy {
    fn to_real(self) -> TrafficPolicy {
        let bounded_rules: Vec<TrafficPolicyRule> = self.rules
            .into_iter()
            .take(MAX_POLICY_RULES)
            .map(|r| r.to_real())
            .collect();

        TrafficPolicy::new(bounded_rules)
    }
}

impl FuzzTrafficPolicyRule {
    fn to_real(self) -> TrafficPolicyRule {
        let bounded_patterns: Vec<String> = self.host_patterns
            .into_iter()
            .take(10) // Reasonable limit for patterns per rule
            .map(FuzzRemoteEffect::bound_string)
            .collect();

        TrafficPolicyRule {
            intent: self.intent,
            verdict: self.verdict,
            priority: self.priority,
            host_patterns: bounded_patterns,
        }
    }
}

impl FuzzPolicyOverride {
    fn to_real(self) -> PolicyOverride {
        PolicyOverride {
            extension_id: FuzzRemoteEffect::bound_string(self.extension_id),
            intent: self.intent,
            new_verdict: self.new_verdict,
            justification: FuzzRemoteEffect::bound_string(self.justification),
            approved_by: FuzzRemoteEffect::bound_string(self.approved_by),
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);

    if let Ok(op) = FuzzOperation::arbitrary(&mut u) {
        match op {
            FuzzOperation::EvaluateEffect { effect, trace_id, timestamp } => {
                let real_effect = effect.to_real();
                let policy = TrafficPolicy::new(vec![]);
                let mut firewall = EffectsFirewall::new(policy);

                // Test firewall evaluation - should not panic on any input
                let trace_bounded = FuzzRemoteEffect::bound_string(trace_id);
                let timestamp_bounded = FuzzRemoteEffect::bound_string(timestamp);

                let _result = black_box(firewall.evaluate(
                    &real_effect,
                    &trace_bounded,
                    &timestamp_bounded
                ));
            },

            FuzzOperation::ClassifyIntent { effect } => {
                let real_effect = effect.to_real();

                // Test intent classification - should be deterministic and safe
                let classification1 = black_box(IntentClassifier::classify(&real_effect));
                let classification2 = black_box(IntentClassifier::classify(&real_effect));

                // INV-FIREWALL-STABLE-CLASSIFICATION: same input yields same classification
                assert_eq!(classification1, classification2, "Intent classification must be deterministic");

                // Test risky categorization is consistent
                if let Some(intent) = classification1 {
                    let is_risky1 = black_box(intent.is_risky());
                    let is_risky2 = black_box(intent.is_risky());
                    assert_eq!(is_risky1, is_risky2, "Risk assessment must be consistent");
                }
            },

            FuzzOperation::SerializationRoundTrip { effect, policy, override_rule } => {
                let real_effect = effect.to_real();
                let real_policy = policy.to_real();
                let real_override = override_rule.to_real();

                // Test serialization attacks on core data structures
                if let Ok(effect_json) = black_box(serde_json::to_string(&real_effect)) {
                    let _: Result<RemoteEffect, _> = black_box(serde_json::from_str(&effect_json));
                }

                if let Ok(policy_json) = black_box(serde_json::to_string(&real_policy)) {
                    let _: Result<TrafficPolicy, _> = black_box(serde_json::from_str(&policy_json));
                }

                if let Ok(override_json) = black_box(serde_json::to_string(&real_override)) {
                    let _: Result<PolicyOverride, _> = black_box(serde_json::from_str(&override_json));
                }
            },

            FuzzOperation::HostPatternMatching { host_patterns, target_hosts } => {
                // Test host pattern matching edge cases and potential bypasses
                for pattern in host_patterns.iter().take(10) {
                    let bounded_pattern = FuzzRemoteEffect::bound_string(pattern.clone());

                    for target in target_hosts.iter().take(10) {
                        let bounded_target = FuzzRemoteEffect::bound_string(target.clone());

                        // Should not panic on malformed patterns or targets
                        let rule = TrafficPolicyRule {
                            intent: IntentClassification::DataFetch,
                            verdict: FirewallVerdict::Allow,
                            priority: 100,
                            host_patterns: vec![bounded_pattern.clone()],
                        };

                        let _matches = black_box(rule.matches_host(&bounded_target));
                    }
                }
            },

            FuzzOperation::PolicyConflictDetection { conflicting_rules } => {
                let real_rules: Vec<TrafficPolicyRule> = conflicting_rules
                    .into_iter()
                    .take(MAX_POLICY_RULES)
                    .map(|r| r.to_real())
                    .collect();

                // Test policy conflict detection with potentially conflicting rules
                let _policy = black_box(TrafficPolicy::new(real_rules));
            },

            FuzzOperation::ExtensionOriginValidation { effect } => {
                let real_effect = effect.to_real();

                // Test extension origin validation
                let is_extension = black_box(real_effect.origin.is_extension());

                // Validate effect descriptor
                let _validation_result = black_box(real_effect.validate());

                // Test that extension checking is consistent
                match &real_effect.origin {
                    TrafficOrigin::Extension { .. } => assert!(is_extension),
                    TrafficOrigin::NodeInternal { .. } => assert!(!is_extension),
                }
            },

            FuzzOperation::PathInjectionAttack { malicious_paths, mut base_effect } => {
                // Test path injection attacks and validation bypasses
                for malicious_path in malicious_paths.into_iter().take(20) {
                    let bounded_path = FuzzRemoteEffect::bound_string(malicious_path);
                    base_effect.path = bounded_path.clone();

                    let real_effect = base_effect.to_real();

                    // Test that classification handles malicious paths safely
                    let _classification = black_box(IntentClassifier::classify(&real_effect));

                    // Test validation handles injection attempts
                    let _validation = black_box(real_effect.validate());

                    // Common injection patterns that should be handled safely:
                    if bounded_path.contains("../") ||
                       bounded_path.contains("..\\") ||
                       bounded_path.contains("\0") ||
                       bounded_path.contains("%2e%2e") ||
                       bounded_path.contains("\\x") {
                        // These should not cause crashes or bypass security
                        let _result = black_box(IntentClassifier::classify(&real_effect));
                    }
                }
            },
        }
    }
});