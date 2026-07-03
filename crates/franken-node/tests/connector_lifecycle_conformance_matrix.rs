//! Connector Lifecycle Cross-Version Conformance Matrix
//!
//! Tests compatibility between different versions of connector lifecycle protocols
//! and API endpoints across host/connector version combinations:
//! - new-connector × old-host scenarios (forward compatibility)
//! - old-connector × new-host scenarios (backward compatibility)
//! - Protocol version negotiation and capability discovery
//! - State transition compatibility across API versions
//! - Session authentication protocol evolution
//!
//! This harness follows Pattern 1 (Differential Testing) + Pattern 4 (Spec-Derived Tests)
//! from /testing-conformance-harnesses skill.

use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};

#[cfg(test)]
use insta::{assert_json_snapshot, with_settings};

use frankenengine_node::connector::frame_parser::{FrameInput, ParserConfig, check_frame};
use frankenengine_node::connector::lifecycle::ConnectorState;

// ---------------------------------------------------------------------------
// Protocol Version Constants (for testing compatibility)
// ---------------------------------------------------------------------------

/// Current production protocol versions
const CURRENT_LIFECYCLE_PROTOCOL: &str = "lifecycle-v1.2.0";
const CURRENT_API_VERSION: &str = "api-v2.1.0";
const CURRENT_SESSION_VERSION: &str = "session-auth-v1.0.0";

/// Simulated future versions for forward compatibility testing
const FUTURE_LIFECYCLE_PROTOCOL: &str = "lifecycle-v1.3.0";
const FUTURE_API_VERSION: &str = "api-v2.2.0";
const FUTURE_SESSION_VERSION: &str = "session-auth-v1.1.0";

/// Simulated legacy versions for backward compatibility testing
const LEGACY_LIFECYCLE_PROTOCOL: &str = "lifecycle-v1.1.0";
const LEGACY_API_VERSION: &str = "api-v2.0.0";
const LEGACY_SESSION_VERSION: &str = "session-auth-v0.9.0";

// ---------------------------------------------------------------------------
// Version Compatibility Matrix
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolVersion {
    pub lifecycle_protocol: String,
    pub api_version: String,
    pub session_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompatibilityScenario {
    pub scenario_id: String,
    pub connector_version: ProtocolVersion,
    pub host_version: ProtocolVersion,
    pub expected_compatibility: CompatibilityExpectation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CompatibilityExpectation {
    FullCompatibility,
    LimitedCompatibility { limitations: Vec<String> },
    NegotiatedCompatibility { fallback_version: String },
    Incompatible { reason: String },
}

fn compatibility_scenarios() -> Vec<CompatibilityScenario> {
    vec![
        // Forward compatibility: new-connector × old-host
        CompatibilityScenario {
            scenario_id: "new_connector_old_host_lifecycle".to_string(),
            connector_version: ProtocolVersion {
                lifecycle_protocol: FUTURE_LIFECYCLE_PROTOCOL.to_string(),
                api_version: FUTURE_API_VERSION.to_string(),
                session_version: FUTURE_SESSION_VERSION.to_string(),
            },
            host_version: ProtocolVersion {
                lifecycle_protocol: CURRENT_LIFECYCLE_PROTOCOL.to_string(),
                api_version: CURRENT_API_VERSION.to_string(),
                session_version: CURRENT_SESSION_VERSION.to_string(),
            },
            expected_compatibility: CompatibilityExpectation::NegotiatedCompatibility {
                fallback_version: CURRENT_LIFECYCLE_PROTOCOL.to_string(),
            },
        },
        // Backward compatibility: old-connector × new-host
        CompatibilityScenario {
            scenario_id: "old_connector_new_host_lifecycle".to_string(),
            connector_version: ProtocolVersion {
                lifecycle_protocol: LEGACY_LIFECYCLE_PROTOCOL.to_string(),
                api_version: LEGACY_API_VERSION.to_string(),
                session_version: LEGACY_SESSION_VERSION.to_string(),
            },
            host_version: ProtocolVersion {
                lifecycle_protocol: CURRENT_LIFECYCLE_PROTOCOL.to_string(),
                api_version: CURRENT_API_VERSION.to_string(),
                session_version: CURRENT_SESSION_VERSION.to_string(),
            },
            // A legacy connector legitimately lacks the Cancelling state added in
            // bd-1cs7, so its connector-completeness score (8/9 states, 17/19
            // transitions) is ~0.9459 — below the FullCompatibility bar by design.
            // Talking to a newer host it negotiates down to its own (lower)
            // lifecycle protocol, which is exactly NegotiatedCompatibility.
            expected_compatibility: CompatibilityExpectation::NegotiatedCompatibility {
                fallback_version: LEGACY_LIFECYCLE_PROTOCOL.to_string(),
            },
        },
        // Current version compatibility (baseline)
        CompatibilityScenario {
            scenario_id: "current_versions_baseline".to_string(),
            connector_version: ProtocolVersion {
                lifecycle_protocol: CURRENT_LIFECYCLE_PROTOCOL.to_string(),
                api_version: CURRENT_API_VERSION.to_string(),
                session_version: CURRENT_SESSION_VERSION.to_string(),
            },
            host_version: ProtocolVersion {
                lifecycle_protocol: CURRENT_LIFECYCLE_PROTOCOL.to_string(),
                api_version: CURRENT_API_VERSION.to_string(),
                session_version: CURRENT_SESSION_VERSION.to_string(),
            },
            expected_compatibility: CompatibilityExpectation::FullCompatibility,
        },
        // Major version incompatibility
        CompatibilityScenario {
            scenario_id: "major_version_incompatible".to_string(),
            connector_version: ProtocolVersion {
                lifecycle_protocol: "lifecycle-v2.0.0".to_string(),
                api_version: "api-v3.0.0".to_string(),
                session_version: "session-auth-v2.0.0".to_string(),
            },
            host_version: ProtocolVersion {
                lifecycle_protocol: CURRENT_LIFECYCLE_PROTOCOL.to_string(),
                api_version: CURRENT_API_VERSION.to_string(),
                session_version: CURRENT_SESSION_VERSION.to_string(),
            },
            expected_compatibility: CompatibilityExpectation::Incompatible {
                reason: "Major version mismatch - breaking changes".to_string(),
            },
        },
    ]
}

// ---------------------------------------------------------------------------
// Mock Version Adapters (simulating version differences)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct ConnectorVersionAdapter {
    pub version: ProtocolVersion,
    pub supported_states: BTreeSet<ConnectorState>,
    pub supported_transitions: BTreeMap<ConnectorState, Vec<ConnectorState>>,
    pub feature_flags: BTreeSet<String>,
}

impl ConnectorVersionAdapter {
    pub fn new(version: ProtocolVersion) -> Self {
        let (supported_states, supported_transitions, feature_flags) =
            match version.lifecycle_protocol.as_str() {
                LEGACY_LIFECYCLE_PROTOCOL => {
                    // Legacy version: no Cancelling state (pre-bd-1cs7)
                    let mut states = BTreeSet::new();
                    states.extend([
                        ConnectorState::Discovered,
                        ConnectorState::Verified,
                        ConnectorState::Installed,
                        ConnectorState::Configured,
                        ConnectorState::Active,
                        ConnectorState::Paused,
                        ConnectorState::Stopped,
                        ConnectorState::Failed,
                    ]);

                    let mut transitions = BTreeMap::new();
                    transitions.insert(
                        ConnectorState::Discovered,
                        vec![ConnectorState::Verified, ConnectorState::Failed],
                    );
                    transitions.insert(
                        ConnectorState::Verified,
                        vec![ConnectorState::Installed, ConnectorState::Failed],
                    );
                    transitions.insert(
                        ConnectorState::Installed,
                        vec![ConnectorState::Configured, ConnectorState::Failed],
                    );
                    transitions.insert(
                        ConnectorState::Configured,
                        vec![ConnectorState::Active, ConnectorState::Failed],
                    );
                    transitions.insert(
                        ConnectorState::Active,
                        vec![
                            ConnectorState::Paused,
                            ConnectorState::Stopped,
                            ConnectorState::Failed,
                        ],
                    );
                    transitions.insert(
                        ConnectorState::Paused,
                        vec![
                            ConnectorState::Active,
                            ConnectorState::Stopped,
                            ConnectorState::Failed,
                        ],
                    );
                    transitions.insert(
                        ConnectorState::Stopped,
                        vec![ConnectorState::Configured, ConnectorState::Failed],
                    );
                    transitions.insert(ConnectorState::Failed, vec![ConnectorState::Discovered]);

                    let mut features = BTreeSet::new();
                    features.insert("basic_lifecycle".to_string());

                    (states, transitions, features)
                }
                CURRENT_LIFECYCLE_PROTOCOL => {
                    // Current version: includes Cancelling state (bd-1cs7)
                    let states = ConnectorState::ALL.iter().copied().collect();

                    let mut transitions = BTreeMap::new();
                    for state in ConnectorState::ALL {
                        transitions.insert(state, state.legal_targets().to_vec());
                    }

                    let mut features = BTreeSet::new();
                    features.insert("basic_lifecycle".to_string());
                    features.insert("three_phase_cancellation".to_string());

                    (states, transitions, features)
                }
                FUTURE_LIFECYCLE_PROTOCOL => {
                    // Future version: adds hypothetical new states and features
                    let states = ConnectorState::ALL.iter().copied().collect::<BTreeSet<_>>();
                    // Note: We can't add new enum variants, so we simulate with feature flags

                    let mut transitions = BTreeMap::new();
                    for state in ConnectorState::ALL {
                        transitions.insert(state, state.legal_targets().to_vec());
                    }

                    let mut features = BTreeSet::new();
                    features.insert("basic_lifecycle".to_string());
                    features.insert("three_phase_cancellation".to_string());
                    features.insert("graceful_restart".to_string());
                    features.insert("hot_reload".to_string());

                    (states, transitions, features)
                }
                _ => {
                    // Unknown version: minimal compatibility
                    let mut states = BTreeSet::new();
                    states.extend([
                        ConnectorState::Discovered,
                        ConnectorState::Active,
                        ConnectorState::Failed,
                    ]);

                    let mut transitions = BTreeMap::new();
                    transitions.insert(
                        ConnectorState::Discovered,
                        vec![ConnectorState::Active, ConnectorState::Failed],
                    );
                    transitions.insert(ConnectorState::Active, vec![ConnectorState::Failed]);
                    transitions.insert(ConnectorState::Failed, vec![ConnectorState::Discovered]);

                    let features = BTreeSet::new();
                    (states, transitions, features)
                }
            };

        Self {
            version,
            supported_states,
            supported_transitions,
            feature_flags,
        }
    }

    pub fn supports_state(&self, state: ConnectorState) -> bool {
        self.supported_states.contains(&state)
    }

    pub fn supports_transition(&self, from: ConnectorState, to: ConnectorState) -> bool {
        self.supported_transitions
            .get(&from)
            .map(|targets| targets.contains(&to))
            .unwrap_or(false)
    }

    pub fn supports_feature(&self, feature: &str) -> bool {
        self.feature_flags.contains(feature)
    }
}

#[derive(Debug, Clone)]
pub struct HostVersionAdapter {
    pub version: ProtocolVersion,
    pub api_endpoints: BTreeMap<String, EndpointSpec>,
    pub auth_methods: BTreeSet<String>,
    pub frame_parser_config: ParserConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointSpec {
    pub path: String,
    pub method: String,
    pub min_api_version: String,
    pub auth_required: bool,
    pub deprecated: bool,
}

impl HostVersionAdapter {
    pub fn new(version: ProtocolVersion) -> Self {
        let (api_endpoints, auth_methods, frame_parser_config) = match version.api_version.as_str()
        {
            LEGACY_API_VERSION => {
                // Legacy API: basic endpoints only
                let mut endpoints = BTreeMap::new();
                endpoints.insert(
                    "connector_status".to_string(),
                    EndpointSpec {
                        path: "/api/v1/connector/status".to_string(),
                        method: "GET".to_string(),
                        min_api_version: LEGACY_API_VERSION.to_string(),
                        auth_required: false,
                        deprecated: false,
                    },
                );
                endpoints.insert(
                    "connector_transition".to_string(),
                    EndpointSpec {
                        path: "/api/v1/connector/transition".to_string(),
                        method: "POST".to_string(),
                        min_api_version: LEGACY_API_VERSION.to_string(),
                        auth_required: true,
                        deprecated: false,
                    },
                );

                let mut auth_methods = BTreeSet::new();
                auth_methods.insert("basic_session".to_string());

                let frame_config = ParserConfig {
                    max_frame_bytes: 100_000, // Smaller limit in legacy
                    max_nesting_depth: 16,    // Smaller limit in legacy
                    max_decode_cpu_ms: 50,    // Smaller limit in legacy
                };

                (endpoints, auth_methods, frame_config)
            }
            CURRENT_API_VERSION => {
                // Current API: full endpoint set
                let mut endpoints = BTreeMap::new();
                endpoints.insert(
                    "connector_status".to_string(),
                    EndpointSpec {
                        path: "/api/v2/connector/status".to_string(),
                        method: "GET".to_string(),
                        min_api_version: CURRENT_API_VERSION.to_string(),
                        auth_required: false,
                        deprecated: false,
                    },
                );
                endpoints.insert(
                    "connector_transition".to_string(),
                    EndpointSpec {
                        path: "/api/v2/connector/lifecycle/transition".to_string(),
                        method: "POST".to_string(),
                        min_api_version: CURRENT_API_VERSION.to_string(),
                        auth_required: true,
                        deprecated: false,
                    },
                );
                endpoints.insert(
                    "connector_cancel".to_string(),
                    EndpointSpec {
                        path: "/api/v2/connector/lifecycle/cancel".to_string(),
                        method: "POST".to_string(),
                        min_api_version: CURRENT_API_VERSION.to_string(),
                        auth_required: true,
                        deprecated: false,
                    },
                );
                endpoints.insert(
                    "connector_health".to_string(),
                    EndpointSpec {
                        path: "/api/v2/connector/health".to_string(),
                        method: "GET".to_string(),
                        min_api_version: CURRENT_API_VERSION.to_string(),
                        auth_required: false,
                        deprecated: false,
                    },
                );

                let mut auth_methods = BTreeSet::new();
                auth_methods.insert("basic_session".to_string());
                auth_methods.insert("hmac_session".to_string());

                let frame_config = ParserConfig::default_config();

                (endpoints, auth_methods, frame_config)
            }
            FUTURE_API_VERSION => {
                // Future API: extended endpoint set
                let mut endpoints = BTreeMap::new();
                endpoints.insert(
                    "connector_status".to_string(),
                    EndpointSpec {
                        path: "/api/v2/connector/status".to_string(),
                        method: "GET".to_string(),
                        min_api_version: CURRENT_API_VERSION.to_string(),
                        auth_required: false,
                        deprecated: false,
                    },
                );
                endpoints.insert(
                    "connector_transition".to_string(),
                    EndpointSpec {
                        path: "/api/v2/connector/lifecycle/transition".to_string(),
                        method: "POST".to_string(),
                        min_api_version: CURRENT_API_VERSION.to_string(),
                        auth_required: true,
                        deprecated: false,
                    },
                );
                endpoints.insert(
                    "connector_cancel".to_string(),
                    EndpointSpec {
                        path: "/api/v2/connector/lifecycle/cancel".to_string(),
                        method: "POST".to_string(),
                        min_api_version: CURRENT_API_VERSION.to_string(),
                        auth_required: true,
                        deprecated: false,
                    },
                );
                endpoints.insert(
                    "connector_health".to_string(),
                    EndpointSpec {
                        path: "/api/v2/connector/health".to_string(),
                        method: "GET".to_string(),
                        min_api_version: CURRENT_API_VERSION.to_string(),
                        auth_required: false,
                        deprecated: false,
                    },
                );
                // Future endpoints
                endpoints.insert(
                    "connector_restart".to_string(),
                    EndpointSpec {
                        path: "/api/v2/connector/lifecycle/restart".to_string(),
                        method: "POST".to_string(),
                        min_api_version: FUTURE_API_VERSION.to_string(),
                        auth_required: true,
                        deprecated: false,
                    },
                );
                endpoints.insert(
                    "connector_metrics".to_string(),
                    EndpointSpec {
                        path: "/api/v2/connector/metrics".to_string(),
                        method: "GET".to_string(),
                        min_api_version: FUTURE_API_VERSION.to_string(),
                        auth_required: true,
                        deprecated: false,
                    },
                );

                let mut auth_methods = BTreeSet::new();
                auth_methods.insert("basic_session".to_string());
                auth_methods.insert("hmac_session".to_string());
                auth_methods.insert("mutual_tls".to_string());

                let frame_config = ParserConfig {
                    max_frame_bytes: 10_000_000, // Larger limit in future
                    max_nesting_depth: 64,       // Larger limit in future
                    max_decode_cpu_ms: 500,      // Larger limit in future
                };

                (endpoints, auth_methods, frame_config)
            }
            _ => {
                // Unknown version: minimal endpoints
                let mut endpoints = BTreeMap::new();
                endpoints.insert(
                    "status".to_string(),
                    EndpointSpec {
                        path: "/status".to_string(),
                        method: "GET".to_string(),
                        min_api_version: "unknown".to_string(),
                        auth_required: false,
                        deprecated: false,
                    },
                );

                let auth_methods = BTreeSet::new();
                let frame_config = ParserConfig::default_config();

                (endpoints, auth_methods, frame_config)
            }
        };

        Self {
            version,
            api_endpoints,
            auth_methods,
            frame_parser_config,
        }
    }

    pub fn supports_endpoint(&self, endpoint: &str) -> bool {
        self.api_endpoints.contains_key(endpoint)
    }

    pub fn supports_auth_method(&self, method: &str) -> bool {
        self.auth_methods.contains(method)
    }
}

// ---------------------------------------------------------------------------
// Conformance Test Implementation
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConformanceTestResult {
    pub scenario_id: String,
    pub test_name: String,
    pub expected: CompatibilityExpectation,
    pub actual_result: TestOutcome,
    pub compatibility_score: f64,
    pub discovered_limitations: Vec<String>,
    pub protocol_negotiation: Option<ProtocolNegotiationResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TestOutcome {
    Success,
    PartialSuccess { issues: Vec<String> },
    Failure { error: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolNegotiationResult {
    pub negotiated_lifecycle_version: String,
    pub negotiated_api_version: String,
    pub negotiated_session_version: String,
    pub feature_intersection: BTreeSet<String>,
    pub endpoint_intersection: BTreeSet<String>,
}

pub fn test_scenario_compatibility(scenario: &CompatibilityScenario) -> ConformanceTestResult {
    let connector_adapter = ConnectorVersionAdapter::new(scenario.connector_version.clone());
    let host_adapter = HostVersionAdapter::new(scenario.host_version.clone());

    // Test 1: State compatibility
    let state_compatibility = test_state_compatibility(&connector_adapter, &host_adapter);

    // Test 2: Transition compatibility
    let transition_compatibility = test_transition_compatibility(&connector_adapter, &host_adapter);

    // Test 3: API endpoint compatibility
    let endpoint_compatibility = test_endpoint_compatibility(&connector_adapter, &host_adapter);

    // Test 4: Protocol negotiation
    let protocol_negotiation = test_protocol_negotiation(&connector_adapter, &host_adapter);

    // Test 5: Frame parser compatibility
    let frame_compatibility = test_frame_parser_compatibility(&connector_adapter, &host_adapter);

    let compatibility_score = calculate_compatibility_score(&[
        state_compatibility,
        transition_compatibility,
        endpoint_compatibility,
        frame_compatibility,
    ]);

    // Collect limitations based on compatibility threshold failures
    let mut discovered_limitations = Vec::new();
    if state_compatibility < 0.8 {
        discovered_limitations.push(format!("State management compatibility below threshold: {:.2}", state_compatibility));
    }
    if transition_compatibility < 0.8 {
        discovered_limitations.push(format!("State transition compatibility below threshold: {:.2}", transition_compatibility));
    }
    if endpoint_compatibility < 0.8 {
        discovered_limitations.push(format!("API endpoint compatibility below threshold: {:.2}", endpoint_compatibility));
    }
    if frame_compatibility < 0.8 {
        discovered_limitations.push(format!("Frame parser compatibility below threshold: {:.2}", frame_compatibility));
    }

    // Add protocol negotiation limitations under the intersection-based model.
    // The redesigned `ProtocolNegotiationResult` no longer carries a
    // `success`/`error` pair; a failed negotiation is now signalled by an
    // `INCOMPATIBLE` negotiated version (no common version within a family) or by
    // an empty endpoint intersection (no shared connector endpoints).
    let mut incompatible_families = Vec::new();
    if protocol_negotiation.negotiated_lifecycle_version == "INCOMPATIBLE" {
        incompatible_families.push("lifecycle");
    }
    if protocol_negotiation.negotiated_api_version == "INCOMPATIBLE" {
        incompatible_families.push("api");
    }
    if protocol_negotiation.negotiated_session_version == "INCOMPATIBLE" {
        incompatible_families.push("session");
    }
    if !incompatible_families.is_empty() {
        discovered_limitations.push(format!(
            "Protocol negotiation failed: no common version for {}",
            incompatible_families.join(", ")
        ));
    }
    if protocol_negotiation.endpoint_intersection.is_empty() {
        discovered_limitations
            .push("Protocol negotiation failed: no shared connector endpoints".to_string());
    }

    let actual_result = if compatibility_score >= 0.95 {
        TestOutcome::Success
    } else if compatibility_score >= 0.7 {
        TestOutcome::PartialSuccess {
            issues: vec![
                format!("State compatibility: {}", state_compatibility),
                format!("Transition compatibility: {}", transition_compatibility),
                format!("Endpoint compatibility: {}", endpoint_compatibility),
                format!("Frame compatibility: {}", frame_compatibility),
            ],
        }
    } else {
        TestOutcome::Failure {
            error: format!("Low compatibility score: {:.2}", compatibility_score),
        }
    };

    ConformanceTestResult {
        scenario_id: scenario.scenario_id.clone(),
        test_name: format!("compatibility_{}", scenario.scenario_id),
        expected: scenario.expected_compatibility.clone(),
        actual_result,
        compatibility_score,
        discovered_limitations,
        protocol_negotiation: Some(protocol_negotiation),
    }
}

fn test_state_compatibility(
    connector: &ConnectorVersionAdapter,
    _host: &HostVersionAdapter,
) -> f64 {
    let connector_states = &connector.supported_states;
    let total_states = ConnectorState::ALL.len();
    let supported_states = connector_states.len();

    // Basic compatibility: how many states are supported
    supported_states as f64 / total_states as f64
}

fn test_transition_compatibility(
    connector: &ConnectorVersionAdapter,
    _host: &HostVersionAdapter,
) -> f64 {
    let mut compatible_transitions = 0;
    let mut total_transitions = 0;

    for state in ConnectorState::ALL {
        if connector.supports_state(state) {
            let legal_targets = state.legal_targets();
            total_transitions += legal_targets.len();

            for &target in legal_targets {
                if connector.supports_state(target) && connector.supports_transition(state, target)
                {
                    compatible_transitions += 1;
                }
            }
        }
    }

    if total_transitions > 0 {
        compatible_transitions as f64 / total_transitions as f64
    } else {
        1.0
    }
}

fn test_endpoint_compatibility(
    _connector: &ConnectorVersionAdapter,
    host: &HostVersionAdapter,
) -> f64 {
    // Test what percentage of required connector endpoints are supported by the host
    let required_endpoints = ["connector_status", "connector_transition"];
    let mut supported = 0;

    for endpoint in &required_endpoints {
        if host.supports_endpoint(endpoint) {
            supported += 1;
        }
    }

    supported as f64 / required_endpoints.len() as f64
}

fn test_frame_parser_compatibility(
    _connector: &ConnectorVersionAdapter,
    host: &HostVersionAdapter,
) -> f64 {
    // Test frame parser configuration compatibility
    let config = &host.frame_parser_config;

    // Create test frames that should work across versions
    let test_frames = [
        FrameInput {
            frame_id: "compat-test-1".to_string(),
            raw_bytes_len: 1000,
            nesting_depth: 5,
            decode_cpu_ms: 10,
        },
        FrameInput {
            frame_id: "compat-test-2".to_string(),
            raw_bytes_len: 50000,
            nesting_depth: 15,
            decode_cpu_ms: 40,
        },
    ];

    let mut successful = 0;
    for frame in &test_frames {
        if let Ok(_) = check_frame(frame, config, "2026-04-20T12:00:00Z") {
            successful += 1;
        }
    }

    successful as f64 / test_frames.len() as f64
}

fn test_protocol_negotiation(
    connector: &ConnectorVersionAdapter,
    host: &HostVersionAdapter,
) -> ProtocolNegotiationResult {
    // Simulate protocol version negotiation
    let negotiated_lifecycle_version = negotiate_version(
        &connector.version.lifecycle_protocol,
        &host.version.lifecycle_protocol,
    );

    let negotiated_api_version =
        negotiate_version(&connector.version.api_version, &host.version.api_version);

    let negotiated_session_version = negotiate_version(
        &connector.version.session_version,
        &host.version.session_version,
    );

    // Find feature intersection
    let feature_intersection = connector
        .feature_flags
        .intersection(&BTreeSet::new()) // Host features would go here in real implementation
        .cloned()
        .collect();

    // Find endpoint intersection
    let required_endpoints: BTreeSet<String> = ["connector_status", "connector_transition"]
        .iter()
        .map(|s| s.to_string())
        .collect();

    let endpoint_intersection = required_endpoints
        .into_iter()
        .filter(|endpoint| host.supports_endpoint(endpoint))
        .collect();

    ProtocolNegotiationResult {
        negotiated_lifecycle_version,
        negotiated_api_version,
        negotiated_session_version,
        feature_intersection,
        endpoint_intersection,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct ParsedProtocolVersion<'a> {
    family: &'a str,
    major: u64,
    minor: u64,
    patch: u64,
}

fn parse_protocol_version(version: &str) -> Option<ParsedProtocolVersion<'_>> {
    let (family, semver) = version.rsplit_once("-v")?;
    let mut parts = semver.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    let patch = parts.next()?.parse().ok()?;
    if parts.next().is_some() {
        return None;
    }
    Some(ParsedProtocolVersion {
        family,
        major,
        minor,
        patch,
    })
}

fn negotiate_version(connector_version: &str, host_version: &str) -> String {
    if connector_version == host_version {
        connector_version.to_string()
    } else if let (Some(connector), Some(host)) = (
        parse_protocol_version(connector_version),
        parse_protocol_version(host_version),
    ) {
        if connector.family != host.family || connector.major != host.major {
            "INCOMPATIBLE".to_string()
        } else if (connector.minor, connector.patch) <= (host.minor, host.patch) {
            connector_version.to_string()
        } else {
            host_version.to_string()
        }
    } else if parse_protocol_version(connector_version).is_some() {
        connector_version.to_string()
    } else if parse_protocol_version(host_version).is_some() {
        host_version.to_string()
    } else {
        "INCOMPATIBLE".to_string()
    }
}

fn calculate_compatibility_score(scores: &[f64]) -> f64 {
    if scores.is_empty() {
        0.0
    } else {
        scores.iter().sum::<f64>() / scores.len() as f64
    }
}

// ---------------------------------------------------------------------------
// Conformance Tests
// ---------------------------------------------------------------------------

#[test]
fn test_connector_lifecycle_conformance_matrix() {
    let mut all_results = Vec::new();

    let scenarios = compatibility_scenarios();
    for scenario in &scenarios {
        let result = test_scenario_compatibility(scenario);
        all_results.push(result);
    }

    // Snapshot the complete conformance matrix
    with_settings!({sort_maps => true}, {
        assert_json_snapshot!("connector_lifecycle_conformance_matrix", all_results);
    });

    // Assert that critical compatibility requirements are met
    for result in &all_results {
        match &result.expected {
            CompatibilityExpectation::FullCompatibility => {
                assert!(
                    result.compatibility_score >= 0.95,
                    "Full compatibility expected for {} but got score {:.2}",
                    result.scenario_id,
                    result.compatibility_score
                );
            }
            CompatibilityExpectation::NegotiatedCompatibility { .. } => {
                assert!(
                    result.compatibility_score >= 0.8,
                    "Negotiated compatibility expected for {} but got score {:.2}",
                    result.scenario_id,
                    result.compatibility_score
                );
            }
            CompatibilityExpectation::LimitedCompatibility { .. } => {
                assert!(
                    result.compatibility_score >= 0.6,
                    "Limited compatibility expected for {} but got score {:.2}",
                    result.scenario_id,
                    result.compatibility_score
                );
            }
            CompatibilityExpectation::Incompatible { .. } => {
                // Incompatible scenarios should have low scores or controlled failures
                assert!(
                    result.compatibility_score < 0.7,
                    "Incompatible scenario {} unexpectedly has high compatibility score {:.2}",
                    result.scenario_id,
                    result.compatibility_score
                );
            }
        }
    }

    for (scenario, result) in scenarios.iter().zip(&all_results) {
        if let CompatibilityExpectation::NegotiatedCompatibility { fallback_version } =
            &scenario.expected_compatibility
        {
            let negotiation = result
                .protocol_negotiation
                .as_ref()
                .expect("negotiation result should be recorded");
            assert_eq!(
                negotiation.negotiated_lifecycle_version, *fallback_version,
                "scenario {} should negotiate lifecycle fallback",
                scenario.scenario_id
            );
        }
    }
}

#[test]
fn test_protocol_negotiation_uses_lower_compatible_versions() {
    assert_eq!(
        negotiate_version(FUTURE_LIFECYCLE_PROTOCOL, CURRENT_LIFECYCLE_PROTOCOL),
        CURRENT_LIFECYCLE_PROTOCOL
    );
    assert_eq!(
        negotiate_version(LEGACY_LIFECYCLE_PROTOCOL, CURRENT_LIFECYCLE_PROTOCOL),
        LEGACY_LIFECYCLE_PROTOCOL
    );
    assert_eq!(
        negotiate_version(FUTURE_API_VERSION, CURRENT_API_VERSION),
        CURRENT_API_VERSION
    );
    // Session family, compatible pair (same major): a future session version
    // negotiates down to the current one. (LEGACY_SESSION_VERSION is
    // session-auth-v0.9.0, which straddles a MAJOR boundary vs the current
    // v1.0.0 and is therefore INCOMPATIBLE — covered by the major-mismatch test
    // below, not here.)
    assert_eq!(
        negotiate_version(FUTURE_SESSION_VERSION, CURRENT_SESSION_VERSION),
        CURRENT_SESSION_VERSION
    );
}

#[test]
fn test_protocol_negotiation_rejects_major_version_mismatch() {
    assert_eq!(
        negotiate_version("lifecycle-v2.0.0", CURRENT_LIFECYCLE_PROTOCOL),
        "INCOMPATIBLE"
    );
    assert_eq!(
        negotiate_version("api-v3.0.0", CURRENT_API_VERSION),
        "INCOMPATIBLE"
    );
    // session-auth-v0.9.0 vs the current v1.0.0 is a major-version jump (0 -> 1),
    // so it is incompatible despite being the "legacy" session version.
    assert_eq!(
        negotiate_version(LEGACY_SESSION_VERSION, CURRENT_SESSION_VERSION),
        "INCOMPATIBLE"
    );
}

#[test]
fn test_backward_compatibility_state_transitions() {
    // Test that old connectors can still perform basic state transitions on new hosts
    let old_connector = ConnectorVersionAdapter::new(ProtocolVersion {
        lifecycle_protocol: LEGACY_LIFECYCLE_PROTOCOL.to_string(),
        api_version: LEGACY_API_VERSION.to_string(),
        session_version: LEGACY_SESSION_VERSION.to_string(),
    });

    let new_host = HostVersionAdapter::new(ProtocolVersion {
        lifecycle_protocol: CURRENT_LIFECYCLE_PROTOCOL.to_string(),
        api_version: CURRENT_API_VERSION.to_string(),
        session_version: CURRENT_SESSION_VERSION.to_string(),
    });

    // Test basic lifecycle progression that should work across versions
    let basic_progression = [
        (ConnectorState::Discovered, ConnectorState::Verified),
        (ConnectorState::Verified, ConnectorState::Installed),
        (ConnectorState::Installed, ConnectorState::Configured),
        (ConnectorState::Configured, ConnectorState::Active),
        (ConnectorState::Active, ConnectorState::Paused),
        (ConnectorState::Paused, ConnectorState::Active),
        (ConnectorState::Active, ConnectorState::Stopped),
    ];

    for (from, to) in basic_progression {
        if old_connector.supports_state(from) && old_connector.supports_state(to) {
            let can_transition = old_connector.supports_transition(from, to);
            assert!(
                can_transition,
                "Old connector should support transition from {:?} to {:?}",
                from, to
            );
        }
    }

    let transition_test = json!({
        "test": "backward_compatibility_state_transitions",
        "old_connector_version": old_connector.version,
        "new_host_version": new_host.version,
        "supported_states": old_connector.supported_states.iter().collect::<Vec<_>>(),
        "tested_transitions": basic_progression,
    });

    with_settings!({sort_maps => true}, {
        assert_json_snapshot!("backward_compatibility_state_transitions", transition_test);
    });
}

#[test]
fn test_forward_compatibility_graceful_degradation() {
    // Test that new connectors gracefully degrade when talking to old hosts
    let new_connector = ConnectorVersionAdapter::new(ProtocolVersion {
        lifecycle_protocol: FUTURE_LIFECYCLE_PROTOCOL.to_string(),
        api_version: FUTURE_API_VERSION.to_string(),
        session_version: FUTURE_SESSION_VERSION.to_string(),
    });

    let old_host = HostVersionAdapter::new(ProtocolVersion {
        lifecycle_protocol: LEGACY_LIFECYCLE_PROTOCOL.to_string(),
        api_version: LEGACY_API_VERSION.to_string(),
        session_version: LEGACY_SESSION_VERSION.to_string(),
    });

    // Test that new connector can fall back to basic endpoints supported by old host
    let basic_endpoints = ["connector_status", "connector_transition"];
    let mut supported_endpoints = Vec::new();

    for endpoint in &basic_endpoints {
        if old_host.supports_endpoint(endpoint) {
            supported_endpoints.push(endpoint);
        }
    }

    // Should be able to support at least basic status and transition operations
    assert!(
        !supported_endpoints.is_empty(),
        "Old host should support at least basic connector endpoints"
    );

    let degradation_test = json!({
        "test": "forward_compatibility_graceful_degradation",
        "new_connector_version": new_connector.version,
        "old_host_version": old_host.version,
        "new_connector_features": new_connector.feature_flags,
        "old_host_endpoints": old_host.api_endpoints,
        "supported_endpoints": supported_endpoints,
        "can_fallback": !supported_endpoints.is_empty(),
    });

    with_settings!({sort_maps => true}, {
        assert_json_snapshot!("forward_compatibility_graceful_degradation", degradation_test);
    });
}

#[test]
fn test_session_auth_protocol_evolution() {
    // Test session authentication compatibility across versions
    let test_cases = [
        ("legacy_session", LEGACY_SESSION_VERSION),
        ("current_session", CURRENT_SESSION_VERSION),
        ("future_session", FUTURE_SESSION_VERSION),
    ];

    let mut session_results = Vec::new();

    for (test_name, session_version) in test_cases {
        let session_test_result = json!({
            "test_case": test_name,
            "session_version": session_version,
            "max_sessions": 16, // Simulated limit
            "supported_auth_methods": match session_version {
                LEGACY_SESSION_VERSION => vec!["basic"],
                CURRENT_SESSION_VERSION => vec!["basic", "hmac"],
                FUTURE_SESSION_VERSION => vec!["basic", "hmac", "mutual_tls"],
                _ => vec!["unknown"],
            },
        });

        session_results.push(session_test_result);
    }

    with_settings!({sort_maps => true}, {
        assert_json_snapshot!("session_auth_protocol_evolution", session_results);
    });
}

#[test]
fn test_api_endpoint_version_negotiation() {
    // Test API endpoint versioning and negotiation
    let version_scenarios = [
        ("legacy_api", LEGACY_API_VERSION),
        ("current_api", CURRENT_API_VERSION),
        ("future_api", FUTURE_API_VERSION),
    ];

    let mut endpoint_results = Vec::new();

    for (scenario_name, api_version) in version_scenarios {
        let host_adapter = HostVersionAdapter::new(ProtocolVersion {
            lifecycle_protocol: CURRENT_LIFECYCLE_PROTOCOL.to_string(),
            api_version: api_version.to_string(),
            session_version: CURRENT_SESSION_VERSION.to_string(),
        });

        let scenario_result = json!({
            "scenario": scenario_name,
            "api_version": api_version,
            "available_endpoints": host_adapter.api_endpoints,
            "auth_methods": host_adapter.auth_methods,
            "frame_parser_limits": {
                "max_frame_bytes": host_adapter.frame_parser_config.max_frame_bytes,
                "max_nesting_depth": host_adapter.frame_parser_config.max_nesting_depth,
                "max_decode_cpu_ms": host_adapter.frame_parser_config.max_decode_cpu_ms,
            },
        });

        endpoint_results.push(scenario_result);
    }

    with_settings!({sort_maps => true}, {
        assert_json_snapshot!("api_endpoint_version_negotiation", endpoint_results);
    });
}
