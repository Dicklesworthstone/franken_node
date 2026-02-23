// Builder API for defining multi-node lab scenarios with per-link fault
// profiles, deterministic seeding, and declarative assertions.
//
// Provides a fluent builder (`ScenarioBuilder`) that validates topology
// constraints (2-10 nodes, valid link endpoints, nonzero seed) and produces
// an immutable `Scenario` struct ready for execution by the lab runtime.
//
// bd-2ko — Section 10.11

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
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
    /// Return the number of nodes.
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Return the number of links.
    pub fn link_count(&self) -> usize {
        self.links.len()
    }

    /// Return the number of assertions.
    pub fn assertion_count(&self) -> usize {
        self.assertions.len()
    }

    /// Check whether a node with the given id exists.
    pub fn has_node(&self, node_id: &str) -> bool {
        self.nodes.iter().any(|n| n.id == node_id)
    }

    /// Return the fault profile for a link, or None if no custom profile is set.
    pub fn fault_profile_for(&self, link_id: &str) -> Option<&LinkFaultConfig> {
        self.fault_profiles.get(link_id)
    }

    /// Serialize to a deterministic JSON string.
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }

    /// Deserialize from JSON.
    pub fn from_json(s: &str) -> Result<Self, ScenarioBuilderError> {
        serde_json::from_str(s).map_err(|_| ScenarioBuilderError::EmptyName)
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
        self.nodes.push(VirtualNode {
            id,
            name: name.into(),
            role,
        });
        Ok(self)
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
        self.links.push(VirtualLink {
            id,
            source_node: source_node.into(),
            target_node: target_node.into(),
            bidirectional,
        });
        Ok(self)
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
        self.assertions.push(assertion);
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
        // Validate name.
        if self.name.is_empty() {
            return Err(ScenarioBuilderError::EmptyName);
        }

        // INV-SB-NONZERO-SEED
        if self.seed == 0 {
            return Err(ScenarioBuilderError::NoSeed);
        }

        // INV-SB-NODE-BOUNDS
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

        // INV-SB-VALID-TOPOLOGY: validate all link endpoints.
        let node_ids: Vec<&str> = self.nodes.iter().map(|n| n.id.as_str()).collect();
        for link in &self.links {
            if !node_ids.contains(&link.source_node.as_str()) {
                return Err(ScenarioBuilderError::InvalidLinkEndpoint {
                    link_id: link.id.clone(),
                    missing_node: link.source_node.clone(),
                });
            }
            if !node_ids.contains(&link.target_node.as_str()) {
                return Err(ScenarioBuilderError::InvalidLinkEndpoint {
                    link_id: link.id.clone(),
                    missing_node: link.target_node.clone(),
                });
            }
        }

        Ok(Scenario {
            schema_version: SCHEMA_VERSION.to_string(),
            name: self.name,
            description: self.description,
            seed: self.seed,
            nodes: self.nodes,
            links: self.links,
            fault_profiles: self.fault_profiles,
            assertions: self.assertions,
        })
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
            other => panic!("expected InvalidLinkEndpoint, got {other}"),
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
            other => panic!("expected InvalidLinkEndpoint, got {other}"),
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

        let json = scenario.to_json();
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
        ];
        let mut seen = std::collections::BTreeSet::new();
        for c in &codes {
            assert!(seen.insert(*c), "Duplicate error code: {c}");
        }
        assert_eq!(seen.len(), 7);
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
}
