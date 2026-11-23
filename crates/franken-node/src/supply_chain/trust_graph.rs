//! Ecosystem reputation graph with explainable trust transitions (charter
//! impossible-by-default capability 9).
//!
//! Trust-card inputs are signature-verified; dependency topology is observed
//! from the local lockfile, not authenticated by the card signatures:
//! * nodes come from the trust-card registry (extensions) and the publishers
//!   named on those cards, plus explicitly untracked lockfile packages;
//! * `depends_on` edges retain the project's npm lockfile dependency closure,
//!   including packages without trust cards;
//! * transitions come from consecutive versions of each card, with the audit
//!   records added between two versions as their causes.
//!
//! Effective trust is a deterministic propagation over that graph. Each rule
//! that lowers a node's score is recorded on the node as an explanation, so
//! an operator can see *why* an extension is distrusted, not only *that* it
//! is: a revoked or quarantined card, a publisher with an incident, or a
//! weak dependency. The blast radius of an extension is its reverse
//! dependency closure: every extension whose trust rests on it.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use serde::{Deserialize, Serialize};

use super::module_resolution_graph::dependency_topology::{
    CapturedLockfileSource, TrustGraphProjection, TrustPackagePlacement, TrustTopologyCoverage,
};
use super::trust_card::{
    CapturedDependencyArtifact, DependencyArtifactMatch, RevocationStatus, TrustCard,
    match_trust_card_artifact,
};

/// Schema tag for [`TrustGraph`] and the CLI report built on it.
pub const TRUST_GRAPH_SCHEMA: &str = "franken-node/trust-graph/v1";
/// Upper bound of the reputation scale cards use (`reputation_score_basis_points`).
pub const TRUST_SCORE_SCALE: u16 = 1_000;
/// R2: an actively quarantined extension is trusted at most this much.
pub const QUARANTINE_CAP: u16 = 100;
/// R3: an extension is trusted at most this much above its weakest dependency.
pub const DEPENDENCY_MARGIN: u16 = 200;
/// R4: a publisher with a revoked or quarantined extension is capped here.
pub const PUBLISHER_INCIDENT_CAP: u16 = 400;
/// R4: an extension is trusted at most this much above its publisher.
pub const PUBLISHER_MARGIN: u16 = 300;
/// Bound on lockfile entries and unique dependency names within one entry.
pub const MAX_GRAPH_PACKAGES: usize = 20_000;
/// Aggregate bound on dependency-name observations across all lockfile entries.
/// This includes declared root dependencies and conservatively counts repeated
/// observations from nested installs or overlapping lockfile representations.
pub const MAX_GRAPH_DEPENDENCY_NAMES: usize = 100_000;
/// Maximum packages for exact all-source topology analysis. Keeping this
/// bounded also keeps shortest-path multiplicities within finite f64 values.
pub const MAX_TOPOLOGY_NODES: usize = 1_024;
/// Conservative n * (n + dependency observations) budget for exact analysis.
pub const MAX_TOPOLOGY_WORK: usize = 8_000_000;

pub const RULE_REVOKED: &str = "R1_REVOKED";
pub const RULE_QUARANTINED: &str = "R2_QUARANTINED";
pub const RULE_WEAK_DEPENDENCY: &str = "R3_WEAK_DEPENDENCY";
pub const RULE_PUBLISHER_INCIDENT: &str = "R4_PUBLISHER_INCIDENT";
pub const RULE_PUBLISHER_CAP: &str = "R4_PUBLISHER_CAP";
pub const RULE_UNTRACKED_DEPENDENCY: &str = "COVERAGE_UNTRACKED_DEPENDENCY";
pub const RULE_ARTIFACT_MISMATCH: &str = "COVERAGE_ARTIFACT_MISMATCH";
pub const RULE_ARTIFACT_UNVERIFIED: &str = "COVERAGE_ARTIFACT_UNVERIFIED";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustNodeKind {
    Publisher,
    Extension,
    /// A package named by the lockfile that has no trust card. It carries no
    /// score; dependents report it as a trust-coverage gap.
    UntrackedDependency,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustRelation {
    /// publisher -> extension
    Publishes,
    /// installed package -> dependency (from the lockfile), including packages
    /// whose trust has not been measured.
    DependsOn,
}

/// One reason a node's effective trust is what it is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustExplanation {
    pub rule: String,
    pub detail: String,
    /// The score ceiling this rule imposed, when it imposed one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cap: Option<u16>,
}

/// Whether a registry card binds every captured placement of its package.
/// Matching metadata does not authenticate installed source bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustArtifactStatus {
    Matched,
    Unverified,
    Mismatch,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustArtifactCoverage {
    pub status: TrustArtifactStatus,
    pub placement_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl TrustArtifactCoverage {
    #[must_use]
    pub fn is_mismatch(&self) -> bool {
        self.status == TrustArtifactStatus::Mismatch
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustGraphNode {
    pub node_id: String,
    pub kind: TrustNodeKind,
    pub display_name: String,
    /// The node's own score: the card's reputation (extensions) or the mean
    /// of its extensions' scores (publishers). `None` for untracked nodes.
    pub base_score: Option<u16>,
    /// Score after propagation; never above `base_score`. A mismatched
    /// healthy card has no current-artifact score; known containment remains.
    pub effective_score: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_coverage: Option<TrustArtifactCoverage>,
    pub quarantined: bool,
    pub revoked: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub risk_level: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub publisher_id: Option<String>,
    pub explanation: Vec<TrustExplanation>,
}

impl TrustGraphNode {
    /// True when propagation (not the node's own state) lowered its score.
    #[must_use]
    pub fn degraded_by_propagation(&self) -> bool {
        self.explanation
            .iter()
            .any(|reason| reason.rule == RULE_WEAK_DEPENDENCY || reason.rule == RULE_PUBLISHER_CAP)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct TrustGraphEdge {
    pub source: String,
    pub target: String,
    pub relation: TrustRelation,
    pub evidence: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustFieldChange {
    pub field: String,
    pub from: String,
    pub to: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustTransitionCause {
    pub timestamp: String,
    pub event_code: String,
    pub detail: String,
}

/// What changed between two consecutive versions of one trust card, and the
/// audit records that explain it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustTransition {
    pub extension_id: String,
    pub from_version: u64,
    pub to_version: u64,
    pub recorded_at: String,
    pub changes: Vec<TrustFieldChange>,
    pub causes: Vec<TrustTransitionCause>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustGraphSummary {
    pub publishers: usize,
    pub extensions: usize,
    pub untracked_dependencies: usize,
    pub edges: usize,
    pub quarantined: usize,
    pub revoked: usize,
    pub degraded_by_propagation: usize,
    pub transitions: usize,
    /// Input limits omitted lockfile entries or dependency names. A false value
    /// only describes these parser limits, not trust or resolution completeness.
    #[serde(default)]
    pub lockfile_truncated: bool,
    /// Complete captured metadata, separate from installed-content or runtime proof.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dependency_metadata_complete: Option<bool>,
    #[serde(default)]
    pub artifact_mismatches: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustGraph {
    pub schema_version: String,
    pub nodes: Vec<TrustGraphNode>,
    pub edges: Vec<TrustGraphEdge>,
    pub transitions: Vec<TrustTransition>,
    pub summary: TrustGraphSummary,
}

/// One extension whose trust rests (transitively) on another.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlastRadiusEntry {
    pub extension_id: String,
    /// Dependency hops from the dependent to the root (1 = direct).
    pub depth: usize,
}

/// Structural measurements of the observed, name-level dependency graph.
/// Publisher relations and package self edges are excluded.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DependencyTopologyMetrics {
    /// Directed shortest-path betweenness, normalized by (n - 1) * (n - 2).
    /// Endpoints do not contribute; graphs with fewer than three packages use 0.
    pub betweenness_centrality: f64,
    /// Whether removal increases components in the undirected package skeleton.
    pub is_articulation_point: bool,
    /// Number of distinct direct dependencies, not reverse dependents.
    pub direct_dependencies: usize,
    /// Distinct packages that transitively depend on this node, excluding itself.
    pub transitive_dependents: usize,
    /// Largest shortest-path distance from a dependent to this node.
    pub max_dependent_depth: usize,
}

/// Why exact dependency topology measurements are unavailable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "reason", rename_all = "snake_case")]
pub enum DependencyTopologyError {
    TruncatedLockfile,
    IncompleteCapture,
    NodeLimit {
        nodes: usize,
        limit: usize,
    },
    WorkLimit {
        nodes: usize,
        edge_observations: usize,
        estimated_work: usize,
        limit: usize,
    },
    InvalidGraph {
        detail: String,
    },
}

impl std::fmt::Display for DependencyTopologyError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TruncatedLockfile => write!(
                formatter,
                "lockfile ingestion was truncated; exact dependency topology is unavailable"
            ),
            Self::IncompleteCapture => write!(
                formatter,
                "captured dependency metadata has unresolved requirements, workspace intent, or incomplete identities; complete dependency topology is unavailable"
            ),
            Self::NodeLimit { nodes, limit } => write!(
                formatter,
                "dependency topology has {nodes} packages, exceeding the exact-analysis limit {limit}"
            ),
            Self::WorkLimit {
                nodes,
                edge_observations,
                estimated_work,
                limit,
            } => write!(
                formatter,
                "dependency topology with {nodes} packages and {edge_observations} dependency observations requires {estimated_work} work units, exceeding the limit {limit}"
            ),
            Self::InvalidGraph { detail } => {
                write!(formatter, "invalid dependency topology: {detail}")
            }
        }
    }
}

impl std::error::Error for DependencyTopologyError {}

/// Provenance of the dependency projection consumed by trust and reputation.
/// Name-level edges union multiple installations. Placements retain distinct
/// version/digest pairs; all observations come from the same bounded capture.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DependencyGraphCapture {
    pub schema_version: &'static str,
    pub scope: &'static str,
    pub source_graph_hash: String,
    pub topology_hash: String,
    pub lockfile_source: Option<CapturedLockfileSource>,
    pub coverage: TrustTopologyCoverage,
    pub placements: Vec<TrustPackagePlacement>,
}

impl DependencyGraphCapture {
    #[must_use]
    pub fn metadata_complete(&self) -> bool {
        self.coverage.metadata_complete
            && self.coverage.unresolved_required_edges == 0
            && self.coverage.intent_only_edges == 0
            && self.coverage.unnamed_packages == 0
    }
}

/// Direct relation of captured project metadata, keyed by actual package name.
/// CLI callers use the canonical runtime topology projection.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LockfileDependencyGraph {
    /// Packages the project itself depends on directly.
    pub root_dependencies: BTreeSet<String>,
    /// package name -> names of its direct dependencies.
    pub dependencies: BTreeMap<String, BTreeSet<String>>,
    /// At least one entry or dependency name was omitted at an ingestion bound.
    pub truncated: bool,
    /// Absent for legacy in-memory JSON inputs; never inferred from mutable paths.
    pub capture: Option<DependencyGraphCapture>,
}

impl LockfileDependencyGraph {
    /// Consume an already captured npm/Bun topology without reopening metadata
    /// or implementing another package-manager selection algorithm.
    pub fn from_captured_topology(projection: TrustGraphProjection) -> anyhow::Result<Self> {
        let packages: BTreeSet<&str> = projection
            .root_dependencies
            .iter()
            .chain(projection.dependencies.keys())
            .chain(projection.dependencies.values().flatten())
            .map(String::as_str)
            .collect();
        anyhow::ensure!(
            packages.len() <= MAX_GRAPH_PACKAGES,
            "captured trust graph exceeds its package limit"
        );
        let observations = projection.dependencies.values().try_fold(
            projection.root_dependencies.len(),
            |count, dependencies| count.checked_add(dependencies.len()),
        );
        anyhow::ensure!(
            observations.is_some_and(|count| count <= MAX_GRAPH_DEPENDENCY_NAMES),
            "captured trust graph exceeds its dependency observation limit"
        );
        Ok(Self {
            root_dependencies: projection.root_dependencies,
            dependencies: projection.dependencies,
            truncated: false,
            capture: Some(DependencyGraphCapture {
                schema_version: "franken-node/trust-dependency-capture/v1",
                scope: "captured_metadata_name_projection_not_installed_content_authentication",
                source_graph_hash: projection.source_graph_hash,
                topology_hash: projection.canonical_hash,
                lockfile_source: projection.lockfile_source,
                coverage: projection.coverage,
                placements: projection.placements,
            }),
        })
    }

    /// Parse `package-lock.json` / `npm-shrinkwrap.json` (lockfile v1, v2
    /// and v3). Nested installs (`node_modules/a/node_modules/b`) are keyed
    /// by the innermost package name; the graph is name-level.
    #[must_use]
    pub fn from_lockfile_json(lockfile: &serde_json::Value) -> Self {
        let mut graph = Self::default();
        let mut ingested = 0_usize;
        let mut remaining_names = MAX_GRAPH_DEPENDENCY_NAMES;
        if let Some(packages) = lockfile
            .get("packages")
            .and_then(serde_json::Value::as_object)
        {
            for (package_path, package) in packages {
                if ingested >= MAX_GRAPH_PACKAGES {
                    graph.truncated = true;
                    break;
                }
                ingested = ingested.saturating_add(1);
                let names = dependency_names(
                    package,
                    &["dependencies", "optionalDependencies"],
                    &mut remaining_names,
                    &mut graph.truncated,
                );
                if package_path.is_empty() {
                    graph.root_dependencies.extend(names.iter().cloned());
                    continue;
                }
                let name = package
                    .get("name")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_string)
                    .or_else(|| {
                        package_path
                            .rsplit_once("node_modules/")
                            .map(|(_, name)| name.to_string())
                    });
                if let Some(name) = name.filter(|name| !name.is_empty()) {
                    graph.dependencies.entry(name).or_default().extend(names);
                }
            }
        }
        if let Some(dependencies) = lockfile
            .get("dependencies")
            .and_then(serde_json::Value::as_object)
        {
            // Lockfile v1: `dependencies` is the installed tree and each entry
            // lists what it `requires`.
            let mut pending: VecDeque<&serde_json::Map<String, serde_json::Value>> =
                VecDeque::from([dependencies]);
            let mut top_level = true;
            while let Some(level) = pending.pop_front() {
                for (name, entry) in level {
                    if ingested >= MAX_GRAPH_PACKAGES {
                        graph.truncated = true;
                        break;
                    }
                    ingested = ingested.saturating_add(1);
                    if top_level && !graph.root_dependencies.contains(name) {
                        if graph.root_dependencies.len() < MAX_GRAPH_PACKAGES && remaining_names > 0
                        {
                            graph.root_dependencies.insert(name.clone());
                            remaining_names = remaining_names.saturating_sub(1);
                        } else {
                            graph.truncated = true;
                        }
                    }
                    let requires = dependency_names(
                        entry,
                        &["requires"],
                        &mut remaining_names,
                        &mut graph.truncated,
                    );
                    graph
                        .dependencies
                        .entry(name.clone())
                        .or_default()
                        .extend(requires);
                    if let Some(nested) = entry
                        .get("dependencies")
                        .and_then(serde_json::Value::as_object)
                    {
                        pending.push_back(nested);
                    }
                }
                top_level = false;
            }
        }
        graph
    }
}

fn dependency_names(
    package: &serde_json::Value,
    keys: &[&str],
    remaining_names: &mut usize,
    truncated: &mut bool,
) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    for dependencies in keys
        .iter()
        .filter_map(|key| package.get(*key).and_then(serde_json::Value::as_object))
    {
        for name in dependencies.keys() {
            if name.is_empty() || names.contains(name) {
                continue;
            }
            if names.len() >= MAX_GRAPH_PACKAGES || *remaining_names == 0 {
                *truncated = true;
                return names;
            }
            names.insert(name.clone());
            *remaining_names = remaining_names.saturating_sub(1);
        }
    }
    names
}

/// Map a lockfile package name to the extension id trust scans assign it.
#[must_use]
pub fn npm_extension_id(package_name: &str) -> String {
    format!("npm:{package_name}")
}

fn publisher_node_id(publisher_id: &str) -> String {
    format!("publisher:{publisher_id}")
}

fn clamp_score(score: u16) -> u16 {
    score.min(TRUST_SCORE_SCALE)
}

fn revocation_label(status: &RevocationStatus) -> String {
    match status {
        RevocationStatus::Active => "active".to_string(),
        RevocationStatus::Revoked { reason, .. } => format!("revoked ({reason})"),
    }
}

fn label<T: Serialize>(value: &T) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|value| value.as_str().map(str::to_string))
        .unwrap_or_else(|| "unknown".to_string())
}

/// Bind cards to all placements once, without reopening project metadata or
/// selecting an arbitrary installation when multiple versions share a name.
/// Missing pins remain explicitly unverified inventory, not artifact proof.
#[must_use]
pub fn trust_artifact_coverages(
    cards: &[TrustCard],
    lockfile: &LockfileDependencyGraph,
) -> BTreeMap<String, TrustArtifactCoverage> {
    let Some(capture) = &lockfile.capture else {
        return BTreeMap::new();
    };
    let mut by_package: BTreeMap<&str, Vec<CapturedDependencyArtifact>> = BTreeMap::new();
    for placement in &capture.placements {
        by_package
            .entry(&placement.package_name)
            .or_default()
            .push(CapturedDependencyArtifact {
                location: Some(placement.location.clone()),
                version: placement.version.clone(),
                integrity: placement.integrity.clone(),
            });
    }
    cards
        .iter()
        .filter_map(|card| {
            let package = card.extension.extension_id.strip_prefix("npm:")?;
            let expected = by_package.get(package).map_or(&[][..], Vec::as_slice);
            let (status, detail) = match match_trust_card_artifact(card, expected) {
                DependencyArtifactMatch::Matched => (TrustArtifactStatus::Matched, None),
                DependencyArtifactMatch::Unverified(detail) => {
                    (TrustArtifactStatus::Unverified, Some(detail))
                }
                DependencyArtifactMatch::Mismatch(detail) => {
                    (TrustArtifactStatus::Mismatch, Some(detail))
                }
            };
            Some((
                card.extension.extension_id.clone(),
                TrustArtifactCoverage {
                    status,
                    placement_count: expected.len(),
                    detail,
                },
            ))
        })
        .collect()
}

/// Build the graph from the latest cards, their version histories (oldest
/// first; may omit extensions with a single version) and the project's
/// lockfile dependency relation.
#[must_use]
pub fn build_trust_graph(
    cards: &[TrustCard],
    histories: &BTreeMap<String, Vec<TrustCard>>,
    lockfile: &LockfileDependencyGraph,
) -> TrustGraph {
    let mut nodes: BTreeMap<String, TrustGraphNode> = BTreeMap::new();
    let mut edges: BTreeSet<TrustGraphEdge> = BTreeSet::new();
    let mut artifact_coverages = trust_artifact_coverages(cards, lockfile);

    // Extensions, with their own-state rules (R1, R2).
    for card in cards {
        let base = clamp_score(card.reputation_score_basis_points);
        let revoked = matches!(card.revocation_status, RevocationStatus::Revoked { .. });
        let mut effective = base;
        let mut explanation = Vec::new();
        if let RevocationStatus::Revoked { reason, revoked_at } = &card.revocation_status {
            effective = 0;
            explanation.push(TrustExplanation {
                rule: RULE_REVOKED.to_string(),
                detail: format!("revoked at {revoked_at}: {reason}"),
                cap: Some(0),
            });
        }
        if card.active_quarantine && effective > QUARANTINE_CAP {
            effective = QUARANTINE_CAP;
            explanation.push(TrustExplanation {
                rule: RULE_QUARANTINED.to_string(),
                detail: "extension is under active quarantine".to_string(),
                cap: Some(QUARANTINE_CAP),
            });
        }
        let artifact_coverage = artifact_coverages.remove(&card.extension.extension_id);
        let artifact_mismatch = artifact_coverage
            .as_ref()
            .is_some_and(TrustArtifactCoverage::is_mismatch);
        if let Some(coverage) = &artifact_coverage
            && let Some(detail) = &coverage.detail
        {
            explanation.push(TrustExplanation {
                rule: if artifact_mismatch {
                    RULE_ARTIFACT_MISMATCH
                } else {
                    RULE_ARTIFACT_UNVERIFIED
                }
                .to_string(),
                detail: detail.clone(),
                cap: None,
            });
        }
        nodes.insert(
            card.extension.extension_id.clone(),
            TrustGraphNode {
                node_id: card.extension.extension_id.clone(),
                kind: TrustNodeKind::Extension,
                display_name: format!("{}@{}", card.extension.extension_id, card.extension.version),
                base_score: Some(base),
                effective_score: if artifact_mismatch && !revoked && !card.active_quarantine {
                    None
                } else {
                    Some(effective)
                },
                artifact_coverage,
                quarantined: card.active_quarantine,
                revoked,
                risk_level: Some(label(&card.user_facing_risk_assessment.level)),
                publisher_id: Some(card.publisher.publisher_id.clone()),
                explanation,
            },
        );
        edges.insert(TrustGraphEdge {
            source: publisher_node_id(&card.publisher.publisher_id),
            target: card.extension.extension_id.clone(),
            relation: TrustRelation::Publishes,
            evidence: format!(
                "trust card v{} names publisher `{}`",
                card.trust_card_version, card.publisher.publisher_id
            ),
        });
    }

    // Publishers: mean of their extensions' own scores, capped when one of
    // their extensions is revoked or quarantined (R4).
    let mut by_publisher: BTreeMap<&str, Vec<&TrustCard>> = BTreeMap::new();
    for card in cards {
        by_publisher
            .entry(card.publisher.publisher_id.as_str())
            .or_default()
            .push(card);
    }
    for (publisher_id, published) in &by_publisher {
        let total: u32 = published
            .iter()
            .map(|card| u32::from(clamp_score(card.reputation_score_basis_points)))
            .sum();
        let count = u32::try_from(published.len()).unwrap_or(u32::MAX).max(1);
        let base = u16::try_from((total + count / 2) / count).unwrap_or(TRUST_SCORE_SCALE);
        let incidents: Vec<&str> = published
            .iter()
            .filter(|card| {
                card.active_quarantine
                    || matches!(card.revocation_status, RevocationStatus::Revoked { .. })
            })
            .map(|card| card.extension.extension_id.as_str())
            .collect();
        let mut effective = base;
        let mut explanation = Vec::new();
        if !incidents.is_empty() && effective > PUBLISHER_INCIDENT_CAP {
            effective = PUBLISHER_INCIDENT_CAP;
            explanation.push(TrustExplanation {
                rule: RULE_PUBLISHER_INCIDENT.to_string(),
                detail: format!(
                    "publisher has revoked or quarantined extension(s): {}",
                    incidents.join(", ")
                ),
                cap: Some(PUBLISHER_INCIDENT_CAP),
            });
        }
        let display_name = published.first().map_or_else(
            || (*publisher_id).to_string(),
            |card| card.publisher.display_name.clone(),
        );
        nodes.insert(
            publisher_node_id(publisher_id),
            TrustGraphNode {
                node_id: publisher_node_id(publisher_id),
                kind: TrustNodeKind::Publisher,
                display_name,
                base_score: Some(base),
                effective_score: Some(effective),
                artifact_coverage: None,
                quarantined: false,
                revoked: false,
                risk_level: None,
                publisher_id: Some((*publisher_id).to_string()),
                explanation,
            },
        );
    }

    // R4: an extension inherits a ceiling from its publisher.
    let publisher_scores: BTreeMap<String, u16> = nodes
        .values()
        .filter(|node| node.kind == TrustNodeKind::Publisher)
        .filter_map(|node| Some((node.publisher_id.clone()?, node.effective_score?)))
        .collect();
    for node in nodes.values_mut() {
        if node.kind != TrustNodeKind::Extension {
            continue;
        }
        let (Some(publisher_id), Some(effective)) =
            (node.publisher_id.clone(), node.effective_score)
        else {
            continue;
        };
        let Some(publisher_score) = publisher_scores.get(&publisher_id) else {
            continue;
        };
        let cap = publisher_score
            .saturating_add(PUBLISHER_MARGIN)
            .min(TRUST_SCORE_SCALE);
        if effective > cap {
            node.effective_score = Some(cap);
            node.explanation.push(TrustExplanation {
                rule: RULE_PUBLISHER_CAP.to_string(),
                detail: format!(
                    "publisher `{publisher_id}` is trusted at {publisher_score}; extensions are capped {PUBLISHER_MARGIN} above it"
                ),
                cap: Some(cap),
            });
        }
    }

    // Preserve the entire observed lockfile relation, including edges whose
    // source has no card. Otherwise an untracked intermediate hides the blast
    // radius of a known compromised transitive dependency. Root-only and
    // disconnected installed packages also remain visible coverage gaps.
    let card_ids: BTreeSet<String> = cards
        .iter()
        .map(|card| card.extension.extension_id.clone())
        .collect();
    let mut untracked: BTreeSet<String> = BTreeSet::new();
    for package in &lockfile.root_dependencies {
        let node_id = npm_extension_id(package);
        if !card_ids.contains(&node_id) {
            untracked.insert(node_id);
        }
    }
    for (package, dependencies) in &lockfile.dependencies {
        let source = npm_extension_id(package);
        if !card_ids.contains(&source) {
            untracked.insert(source.clone());
        }
        for dependency in dependencies {
            let target = npm_extension_id(dependency);
            if target == source {
                continue;
            }
            if !card_ids.contains(&target) {
                untracked.insert(target.clone());
            }
            edges.insert(TrustGraphEdge {
                source: source.clone(),
                target,
                relation: TrustRelation::DependsOn,
                evidence: format!("lockfile: `{package}` depends on `{dependency}`"),
            });
        }
    }
    for node_id in &untracked {
        nodes.insert(
            node_id.clone(),
            TrustGraphNode {
                node_id: node_id.clone(),
                kind: TrustNodeKind::UntrackedDependency,
                display_name: node_id.clone(),
                base_score: None,
                effective_score: None,
                artifact_coverage: None,
                quarantined: false,
                revoked: false,
                risk_level: None,
                publisher_id: None,
                explanation: vec![TrustExplanation {
                    rule: RULE_UNTRACKED_DEPENDENCY.to_string(),
                    detail: "named by the lockfile but has no trust card; run `trust scan`"
                        .to_string(),
                    cap: None,
                }],
            },
        );
    }

    // R3: propagate known score ceilings independently of measured node scores.
    // An untracked node remains unscored, but cannot hide a known downstream
    // ceiling from its dependents. Each edge adds the same existing margin;
    // missing data neither grants trust nor removes a known restriction.
    let depends_on: Vec<(String, String)> = edges
        .iter()
        .filter(|edge| edge.relation == TrustRelation::DependsOn)
        .map(|edge| (edge.source.clone(), edge.target.clone()))
        .collect();
    let mut ceilings: BTreeMap<String, u16> = nodes
        .values()
        .filter_map(|node| Some((node.node_id.clone(), node.effective_score?)))
        .collect();
    let mut binding: BTreeMap<String, (String, u16, u16)> = BTreeMap::new();
    for _ in 0..=nodes.len() {
        let mut changed = false;
        for (source, target) in &depends_on {
            let Some(target_score) = ceilings.get(target).copied() else {
                continue;
            };
            let cap = target_score
                .saturating_add(DEPENDENCY_MARGIN)
                .min(TRUST_SCORE_SCALE);
            if cap < ceilings.get(source).copied().unwrap_or(TRUST_SCORE_SCALE) {
                ceilings.insert(source.clone(), cap);
                binding.insert(source.clone(), (target.clone(), target_score, cap));
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    for (source, (target, target_score, cap)) in binding {
        if let Some(node) = nodes.get_mut(&source)
            && let Some(effective) = node.effective_score
            && effective > cap
        {
            node.effective_score = Some(cap);
            node.explanation.push(TrustExplanation {
                rule: RULE_WEAK_DEPENDENCY.to_string(),
                detail: format!(
                    "depends on `{target}` (known dependency trust ceiling {target_score}); dependents are capped {DEPENDENCY_MARGIN} above that ceiling even through untracked packages"
                ),
                cap: Some(cap),
            });
        }
    }
    for (source, target) in &depends_on {
        if untracked.contains(target)
            && let Some(node) = nodes.get_mut(source)
        {
            node.explanation.push(TrustExplanation {
                rule: RULE_UNTRACKED_DEPENDENCY.to_string(),
                detail: format!("depends on `{target}`, which has no trust card"),
                cap: None,
            });
        }
    }

    let transitions = build_transitions(histories);
    let nodes: Vec<TrustGraphNode> = nodes.into_values().collect();
    let edges: Vec<TrustGraphEdge> = edges.into_iter().collect();
    let summary = TrustGraphSummary {
        publishers: nodes
            .iter()
            .filter(|node| node.kind == TrustNodeKind::Publisher)
            .count(),
        extensions: nodes
            .iter()
            .filter(|node| node.kind == TrustNodeKind::Extension)
            .count(),
        untracked_dependencies: untracked.len(),
        edges: edges.len(),
        quarantined: nodes.iter().filter(|node| node.quarantined).count(),
        revoked: nodes.iter().filter(|node| node.revoked).count(),
        degraded_by_propagation: nodes
            .iter()
            .filter(|node| node.degraded_by_propagation())
            .count(),
        transitions: transitions.len(),
        lockfile_truncated: lockfile.truncated,
        dependency_metadata_complete: lockfile
            .capture
            .as_ref()
            .map(DependencyGraphCapture::metadata_complete),
        artifact_mismatches: nodes
            .iter()
            .filter(|node| {
                node.artifact_coverage
                    .as_ref()
                    .is_some_and(TrustArtifactCoverage::is_mismatch)
            })
            .count(),
    };
    TrustGraph {
        schema_version: TRUST_GRAPH_SCHEMA.to_string(),
        nodes,
        edges,
        transitions,
        summary,
    }
}

fn build_transitions(histories: &BTreeMap<String, Vec<TrustCard>>) -> Vec<TrustTransition> {
    let mut transitions = Vec::new();
    for (extension_id, history) in histories {
        let mut ordered: Vec<&TrustCard> = history.iter().collect();
        ordered.sort_by_key(|card| card.trust_card_version);
        for pair in ordered.windows(2) {
            let (from, to) = (pair[0], pair[1]);
            let mut changes = Vec::new();
            let mut record = |field: &str, before: String, after: String| {
                if before != after {
                    changes.push(TrustFieldChange {
                        field: field.to_string(),
                        from: before,
                        to: after,
                    });
                }
            };
            record(
                "reputation_score",
                from.reputation_score_basis_points.to_string(),
                to.reputation_score_basis_points.to_string(),
            );
            record(
                "reputation_trend",
                label(&from.reputation_trend),
                label(&to.reputation_trend),
            );
            record(
                "active_quarantine",
                from.active_quarantine.to_string(),
                to.active_quarantine.to_string(),
            );
            record(
                "revocation_status",
                revocation_label(&from.revocation_status),
                revocation_label(&to.revocation_status),
            );
            record(
                "risk_level",
                label(&from.user_facing_risk_assessment.level),
                label(&to.user_facing_risk_assessment.level),
            );
            record(
                "certification_level",
                label(&from.certification_level),
                label(&to.certification_level),
            );
            record(
                "extension_version",
                from.extension.version.clone(),
                to.extension.version.clone(),
            );
            let known: BTreeSet<(&str, &str, &str)> = from
                .audit_history
                .iter()
                .map(|audit| {
                    (
                        audit.timestamp.as_str(),
                        audit.event_code.as_str(),
                        audit.detail.as_str(),
                    )
                })
                .collect();
            let causes: Vec<TrustTransitionCause> = to
                .audit_history
                .iter()
                .filter(|audit| {
                    !known.contains(&(
                        audit.timestamp.as_str(),
                        audit.event_code.as_str(),
                        audit.detail.as_str(),
                    ))
                })
                .map(|audit| TrustTransitionCause {
                    timestamp: audit.timestamp.clone(),
                    event_code: audit.event_code.clone(),
                    detail: audit.detail.clone(),
                })
                .collect();
            if changes.is_empty() && causes.is_empty() {
                continue;
            }
            transitions.push(TrustTransition {
                extension_id: extension_id.clone(),
                from_version: from.trust_card_version,
                to_version: to.trust_card_version,
                recorded_at: to.last_verified_timestamp.clone(),
                changes,
                causes,
            });
        }
    }
    transitions
}

/// Every extension whose trust rests on `root` through `depends_on` edges,
/// nearest first. `root` itself is not included.
#[must_use]
pub fn blast_radius(graph: &TrustGraph, root: &str) -> Vec<BlastRadiusEntry> {
    let mut dependents: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for edge in &graph.edges {
        if edge.relation == TrustRelation::DependsOn {
            dependents
                .entry(edge.target.as_str())
                .or_default()
                .push(edge.source.as_str());
        }
    }
    let mut seen: BTreeSet<&str> = BTreeSet::from([root]);
    let mut queue: VecDeque<(&str, usize)> = VecDeque::from([(root, 0)]);
    let mut out = Vec::new();
    while let Some((node, depth)) = queue.pop_front() {
        for dependent in dependents.get(node).into_iter().flatten() {
            if seen.insert(dependent) {
                out.push(BlastRadiusEntry {
                    extension_id: (*dependent).to_string(),
                    depth: depth.saturating_add(1),
                });
                queue.push_back((dependent, depth.saturating_add(1)));
            }
        }
    }
    out.sort_by(|left, right| {
        left.depth
            .cmp(&right.depth)
            .then_with(|| left.extension_id.cmp(&right.extension_id))
    });
    out
}

/// Measure dependency topology without substituting heuristic values when
/// exact analysis is unavailable. Uses directed Brandes betweenness and an
/// undirected articulation analysis on all scored and untracked package nodes.
/// The graph is name-level: multiple installed versions share one package node.
///
/// Work is bounded before adjacency allocation by package count and the
/// conservative n * (n + dependency observations) estimate. Duplicate evidence
/// counts toward this work bound but never changes the resulting measurements.
/// A truncated lockfile cannot provide exact measurements and is rejected.
pub fn dependency_topology_metrics(
    graph: &TrustGraph,
) -> Result<BTreeMap<String, DependencyTopologyMetrics>, DependencyTopologyError> {
    if graph.summary.lockfile_truncated {
        return Err(DependencyTopologyError::TruncatedLockfile);
    }
    if graph.summary.dependency_metadata_complete == Some(false) {
        return Err(DependencyTopologyError::IncompleteCapture);
    }
    let node_count = graph
        .nodes
        .iter()
        .filter(|node| node.kind != TrustNodeKind::Publisher)
        .count();
    if node_count > MAX_TOPOLOGY_NODES {
        return Err(DependencyTopologyError::NodeLimit {
            nodes: node_count,
            limit: MAX_TOPOLOGY_NODES,
        });
    }
    let edge_observations = graph
        .edges
        .iter()
        .filter(|edge| edge.relation == TrustRelation::DependsOn && edge.source != edge.target)
        .count();
    let estimated_work = node_count.saturating_mul(node_count.saturating_add(edge_observations));
    if estimated_work > MAX_TOPOLOGY_WORK {
        return Err(DependencyTopologyError::WorkLimit {
            nodes: node_count,
            edge_observations,
            estimated_work,
            limit: MAX_TOPOLOGY_WORK,
        });
    }
    let mut node_ids: Vec<&str> = graph
        .nodes
        .iter()
        .filter(|node| node.kind != TrustNodeKind::Publisher)
        .map(|node| node.node_id.as_str())
        .collect();
    node_ids.sort_unstable();
    if node_ids.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(DependencyTopologyError::InvalidGraph {
            detail: "duplicate package node identifiers".to_string(),
        });
    }
    let indices: BTreeMap<&str, usize> = node_ids
        .iter()
        .enumerate()
        .map(|(index, id)| (*id, index))
        .collect();
    let mut directed = vec![BTreeSet::new(); node_count];
    let mut undirected = vec![BTreeSet::new(); node_count];
    for edge in &graph.edges {
        if edge.relation != TrustRelation::DependsOn || edge.source == edge.target {
            continue;
        }
        let Some(&source) = indices.get(edge.source.as_str()) else {
            return Err(DependencyTopologyError::InvalidGraph {
                detail: format!("dependency source '{}' is not a package node", edge.source),
            });
        };
        let Some(&target) = indices.get(edge.target.as_str()) else {
            return Err(DependencyTopologyError::InvalidGraph {
                detail: format!("dependency target '{}' is not a package node", edge.target),
            });
        };
        directed[source].insert(target);
        undirected[source].insert(target);
        undirected[target].insert(source);
    }
    let directed: Vec<Vec<usize>> = directed
        .into_iter()
        .map(|neighbors| neighbors.into_iter().collect())
        .collect();
    let undirected: Vec<Vec<usize>> = undirected
        .into_iter()
        .map(|neighbors| neighbors.into_iter().collect())
        .collect();

    let mut betweenness = vec![0.0_f64; node_count];
    let mut transitive_dependents = vec![0_usize; node_count];
    let mut max_dependent_depth = vec![0_usize; node_count];
    for source in 0..node_count {
        let mut predecessors = vec![Vec::new(); node_count];
        let mut shortest_paths = vec![0.0_f64; node_count];
        let mut distances = vec![usize::MAX; node_count];
        let mut order = Vec::with_capacity(node_count);
        let mut queue = VecDeque::from([source]);
        shortest_paths[source] = 1.0;
        distances[source] = 0;
        while let Some(current) = queue.pop_front() {
            order.push(current);
            for &target in &directed[current] {
                if distances[target] == usize::MAX {
                    distances[target] = distances[current] + 1;
                    queue.push_back(target);
                }
                if distances[target] == distances[current] + 1 {
                    shortest_paths[target] += shortest_paths[current];
                    predecessors[target].push(current);
                }
            }
        }
        // source -> target means source depends on target. Counting each BFS
        // reach once therefore gives the target's reverse dependency closure.
        for &target in &order {
            if target != source {
                transitive_dependents[target] += 1;
                max_dependent_depth[target] = max_dependent_depth[target].max(distances[target]);
            }
        }
        let mut contribution = vec![0.0_f64; node_count];
        while let Some(target) = order.pop() {
            for &predecessor in &predecessors[target] {
                contribution[predecessor] += (shortest_paths[predecessor] / shortest_paths[target])
                    * (1.0 + contribution[target]);
            }
            if target != source {
                betweenness[target] += contribution[target];
            }
        }
    }

    let articulation = undirected_articulation_points(&undirected);
    let normalization = if node_count > 2 {
        ((node_count - 1) * (node_count - 2)) as f64
    } else {
        1.0
    };
    Ok(node_ids
        .into_iter()
        .enumerate()
        .map(|(index, node_id)| {
            (
                node_id.to_string(),
                DependencyTopologyMetrics {
                    betweenness_centrality: (betweenness[index] / normalization).clamp(0.0, 1.0),
                    is_articulation_point: articulation[index],
                    direct_dependencies: directed[index].len(),
                    transitive_dependents: transitive_dependents[index],
                    max_dependent_depth: max_dependent_depth[index],
                },
            )
        })
        .collect())
}

/// Iterative depth-first low-link analysis avoids recursion even for long chains.
fn undirected_articulation_points(adjacency: &[Vec<usize>]) -> Vec<bool> {
    let mut discovery = vec![usize::MAX; adjacency.len()];
    let mut low = vec![0_usize; adjacency.len()];
    let mut parents = vec![None; adjacency.len()];
    let mut children = vec![0_usize; adjacency.len()];
    let mut articulation = vec![false; adjacency.len()];
    let mut clock = 0_usize;
    for root in 0..adjacency.len() {
        if discovery[root] != usize::MAX {
            continue;
        }
        discovery[root] = clock;
        low[root] = clock;
        clock += 1;
        let mut stack = vec![(root, 0_usize)];
        while let Some((current, next_neighbor)) = stack.pop() {
            if let Some(&neighbor) = adjacency[current].get(next_neighbor) {
                stack.push((current, next_neighbor + 1));
                if discovery[neighbor] == usize::MAX {
                    parents[neighbor] = Some(current);
                    children[current] += 1;
                    discovery[neighbor] = clock;
                    low[neighbor] = clock;
                    clock += 1;
                    stack.push((neighbor, 0));
                } else if parents[current] != Some(neighbor) {
                    low[current] = low[current].min(discovery[neighbor]);
                }
            } else if let Some(parent) = parents[current] {
                low[parent] = low[parent].min(low[current]);
                if parents[parent].is_some() && low[current] >= discovery[parent] {
                    articulation[parent] = true;
                }
            } else {
                articulation[current] = children[current] > 1;
            }
        }
    }
    articulation
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::supply_chain::trust_card::{AuditRecord, RevocationStatus};

    fn cards() -> Vec<TrustCard> {
        crate::supply_chain::trust_card::fixture_registry(1_000)
            .expect("fixture registry")
            .snapshot()
            .expect("snapshot")
            .cards_by_extension
            .into_values()
            .filter_map(|history| history.last().cloned())
            .collect()
    }

    fn card(id: &str) -> TrustCard {
        cards()
            .into_iter()
            .find(|card| card.extension.extension_id == id)
            .expect("fixture card")
    }

    fn named(base: &TrustCard, id: &str, publisher: &str, score: u16) -> TrustCard {
        let mut card = base.clone();
        card.extension.extension_id = id.to_string();
        card.publisher.publisher_id = publisher.to_string();
        card.reputation_score_basis_points = score;
        card.active_quarantine = false;
        card.revocation_status = RevocationStatus::Active;
        card
    }

    fn lockfile(edges: &[(&str, &[&str])]) -> LockfileDependencyGraph {
        let mut packages = serde_json::Map::new();
        packages.insert(
            String::new(),
            serde_json::json!({ "dependencies": { "app-dep": "^1" } }),
        );
        for (name, deps) in edges {
            let deps: serde_json::Map<String, serde_json::Value> = deps
                .iter()
                .map(|dep| ((*dep).to_string(), serde_json::json!("^1")))
                .collect();
            packages.insert(
                format!("node_modules/{name}"),
                serde_json::json!({ "version": "1.0.0", "dependencies": deps }),
            );
        }
        LockfileDependencyGraph::from_lockfile_json(&serde_json::json!({
            "lockfileVersion": 3,
            "packages": packages,
        }))
    }

    fn node<'a>(graph: &'a TrustGraph, id: &str) -> &'a TrustGraphNode {
        graph
            .nodes
            .iter()
            .find(|node| node.node_id == id)
            .unwrap_or_else(|| panic!("node {id}"))
    }

    #[test]
    fn lockfile_v3_and_v1_dependencies_are_parsed() {
        let v3 = lockfile(&[("a", &["b", "c"]), ("b", &[])]);
        assert_eq!(
            v3.root_dependencies,
            BTreeSet::from(["app-dep".to_string()])
        );
        assert_eq!(
            v3.dependencies.get("a"),
            Some(&BTreeSet::from(["b".to_string(), "c".to_string()]))
        );
        let nested = LockfileDependencyGraph::from_lockfile_json(&serde_json::json!({
            "packages": {
                "node_modules/a/node_modules/@scope/b": { "dependencies": { "c": "1" } }
            }
        }));
        assert!(nested.dependencies.contains_key("@scope/b"));
        let v1 = LockfileDependencyGraph::from_lockfile_json(&serde_json::json!({
            "lockfileVersion": 1,
            "dependencies": {
                "a": { "version": "1.0.0", "requires": { "b": "^2" },
                       "dependencies": { "b": { "version": "2.0.0", "requires": { "c": "^3" } } } }
            }
        }));
        assert_eq!(v1.root_dependencies, BTreeSet::from(["a".to_string()]));
        assert_eq!(
            v1.dependencies.get("a"),
            Some(&BTreeSet::from(["b".to_string()]))
        );
        assert_eq!(
            v1.dependencies.get("b"),
            Some(&BTreeSet::from(["c".to_string()]))
        );
        assert!(!v1.truncated);
        assert!(!v3.truncated);
    }

    #[test]
    fn lockfile_package_and_dependency_limits_report_truncation() {
        let mut packages: serde_json::Map<String, serde_json::Value> = (0..MAX_GRAPH_PACKAGES)
            .map(|index| {
                (
                    format!("node_modules/pkg-{index:05}"),
                    serde_json::json!({ "version": "1.0.0" }),
                )
            })
            .collect();
        let exact = LockfileDependencyGraph::from_lockfile_json(&serde_json::json!({
            "packages": packages,
        }));
        assert_eq!(exact.dependencies.len(), MAX_GRAPH_PACKAGES);
        assert!(!exact.truncated);
        packages.insert("node_modules/overflow".into(), serde_json::json!({}));
        let truncated = LockfileDependencyGraph::from_lockfile_json(&serde_json::json!({
            "packages": packages,
        }));
        assert_eq!(truncated.dependencies.len(), MAX_GRAPH_PACKAGES);
        assert!(truncated.truncated);
        let graph = build_trust_graph(&[], &BTreeMap::new(), &truncated);
        assert!(graph.summary.lockfile_truncated);

        let mut names: serde_json::Map<String, serde_json::Value> = (0..MAX_GRAPH_PACKAGES)
            .map(|index| (format!("dep-{index:05}"), serde_json::json!("1")))
            .collect();
        let exact = LockfileDependencyGraph::from_lockfile_json(&serde_json::json!({
            "packages": { "": { "dependencies": names } },
        }));
        assert_eq!(exact.root_dependencies.len(), MAX_GRAPH_PACKAGES);
        assert!(!exact.truncated);
        names.insert("overflow".into(), serde_json::json!("1"));
        let truncated = LockfileDependencyGraph::from_lockfile_json(&serde_json::json!({
            "packages": { "": { "dependencies": names } },
        }));
        assert_eq!(truncated.root_dependencies.len(), MAX_GRAPH_PACKAGES);
        assert!(truncated.truncated);
    }

    #[test]
    fn lockfile_aggregate_dependency_budget_preserves_sources_and_reports_omissions() {
        let names: serde_json::Map<String, serde_json::Value> = (0..MAX_GRAPH_PACKAGES)
            .map(|index| (format!("dep-{index:05}"), serde_json::json!("1")))
            .collect();
        let full_rows = MAX_GRAPH_DEPENDENCY_NAMES / MAX_GRAPH_PACKAGES;
        let mut packages: serde_json::Map<String, serde_json::Value> = (0..full_rows)
            .map(|index| {
                (
                    format!("node_modules/pkg-{index:05}"),
                    serde_json::json!({ "dependencies": names }),
                )
            })
            .collect();
        let exact = LockfileDependencyGraph::from_lockfile_json(&serde_json::json!({
            "packages": packages,
        }));
        assert!(!exact.truncated);
        assert_eq!(
            exact
                .dependencies
                .values()
                .map(BTreeSet::len)
                .sum::<usize>(),
            MAX_GRAPH_DEPENDENCY_NAMES
        );
        packages.insert(
            "node_modules/zzz-overflow".to_string(),
            serde_json::json!({ "dependencies": { "omitted": "1" } }),
        );
        let over = LockfileDependencyGraph::from_lockfile_json(&serde_json::json!({
            "packages": packages,
        }));
        assert!(over.truncated);
        assert_eq!(over.dependencies.len(), full_rows + 1);
        assert!(over.dependencies["zzz-overflow"].is_empty());
        assert_eq!(
            over.dependencies.values().map(BTreeSet::len).sum::<usize>(),
            MAX_GRAPH_DEPENDENCY_NAMES
        );
    }

    #[test]
    fn lockfile_v1_limit_reports_omitted_nested_packages() {
        let mut dependencies: serde_json::Map<String, serde_json::Value> = (0..MAX_GRAPH_PACKAGES)
            .map(|index| (format!("pkg-{index:05}"), serde_json::json!({})))
            .collect();
        dependencies.insert(
            "pkg-00000".into(),
            serde_json::json!({ "dependencies": { "nested": { "version": "1" } } }),
        );
        let truncated = LockfileDependencyGraph::from_lockfile_json(&serde_json::json!({
            "lockfileVersion": 1,
            "dependencies": dependencies,
        }));
        assert!(truncated.truncated);
        assert_eq!(truncated.dependencies.len(), MAX_GRAPH_PACKAGES);
        assert!(!truncated.dependencies.contains_key("nested"));
    }

    #[test]
    fn revoked_and_quarantined_cards_are_capped_with_reasons() {
        let base = card("npm:@acme/auth-guard");
        let mut revoked = named(&base, "npm:revoked", "pub-r", 900);
        revoked.revocation_status = RevocationStatus::Revoked {
            reason: "malicious update".to_string(),
            revoked_at: "2026-10-01T00:00:00Z".to_string(),
        };
        let mut quarantined = named(&base, "npm:quarantined", "pub-q", 900);
        quarantined.active_quarantine = true;
        let graph = build_trust_graph(
            &[revoked, quarantined],
            &BTreeMap::new(),
            &LockfileDependencyGraph::default(),
        );
        let revoked = node(&graph, "npm:revoked");
        assert_eq!(revoked.effective_score, Some(0));
        assert_eq!(revoked.explanation[0].rule, RULE_REVOKED);
        assert!(revoked.explanation[0].detail.contains("malicious update"));
        let quarantined = node(&graph, "npm:quarantined");
        assert_eq!(quarantined.effective_score, Some(QUARANTINE_CAP));
        assert_eq!(graph.summary.revoked, 1);
        assert_eq!(graph.summary.quarantined, 1);
    }

    #[test]
    fn weak_dependencies_propagate_transitively_with_explanations() {
        let base = card("npm:@acme/auth-guard");
        let graph = build_trust_graph(
            &[
                named(&base, "npm:app", "pub-1", 900),
                named(&base, "npm:mid", "pub-2", 900),
                named(&base, "npm:weak", "pub-3", 100),
            ],
            &BTreeMap::new(),
            &lockfile(&[("app", &["mid"]), ("mid", &["weak"])]),
        );
        let mid = node(&graph, "npm:mid");
        assert_eq!(mid.effective_score, Some(100 + DEPENDENCY_MARGIN));
        assert!(mid.explanation.iter().any(
            |reason| reason.rule == RULE_WEAK_DEPENDENCY && reason.detail.contains("npm:weak")
        ));
        let app = node(&graph, "npm:app");
        assert_eq!(app.effective_score, Some(100 + 2 * DEPENDENCY_MARGIN));
        assert!(
            app.explanation
                .iter()
                .any(|reason| reason.detail.contains("npm:mid"))
        );
        assert_eq!(app.base_score, Some(900));
        assert_eq!(graph.summary.degraded_by_propagation, 2);

        let radius = blast_radius(&graph, "npm:weak");
        assert_eq!(
            radius,
            vec![
                BlastRadiusEntry {
                    extension_id: "npm:mid".to_string(),
                    depth: 1
                },
                BlastRadiusEntry {
                    extension_id: "npm:app".to_string(),
                    depth: 2
                },
            ]
        );
        assert!(blast_radius(&graph, "npm:app").is_empty());
    }

    #[test]
    fn dependency_cycles_settle() {
        let base = card("npm:@acme/auth-guard");
        let graph = build_trust_graph(
            &[
                named(&base, "npm:a", "pub-1", 900),
                named(&base, "npm:b", "pub-2", 300),
            ],
            &BTreeMap::new(),
            &lockfile(&[("a", &["b"]), ("b", &["a"])]),
        );
        assert_eq!(
            node(&graph, "npm:a").effective_score,
            Some(300 + DEPENDENCY_MARGIN)
        );
        assert_eq!(node(&graph, "npm:b").effective_score, Some(300));
    }

    #[test]
    fn untracked_bridge_preserves_revoked_dependency_blast_radius_and_ceiling() {
        let base = card("npm:@acme/auth-guard");
        let mut revoked = named(&base, "npm:leaf", "pub-leaf", 900);
        revoked.revocation_status = RevocationStatus::Revoked {
            reason: "compromised transitive package".into(),
            revoked_at: "2026-11-23T00:00:00Z".into(),
        };
        let lockfile = LockfileDependencyGraph::from_lockfile_json(&serde_json::json!({
            "packages": {
                "": { "dependencies": { "app": "1" } },
                "node_modules/app": { "dependencies": { "bridge": "1" } },
                "node_modules/bridge": { "dependencies": { "leaf": "1" } },
                "node_modules/leaf": { "version": "1" },
            },
        }));
        let graph = build_trust_graph(
            &[named(&base, "npm:app", "pub-app", 900), revoked],
            &BTreeMap::new(),
            &lockfile,
        );
        assert_eq!(node(&graph, "npm:leaf").effective_score, Some(0));
        let bridge = node(&graph, "npm:bridge");
        assert_eq!(bridge.kind, TrustNodeKind::UntrackedDependency);
        assert_eq!(bridge.base_score, None);
        assert_eq!(bridge.effective_score, None);
        let app = node(&graph, "npm:app");
        assert_eq!(app.base_score, Some(900));
        assert_eq!(app.effective_score, Some(2 * DEPENDENCY_MARGIN));
        assert!(app.explanation.iter().any(|reason| {
            reason.rule == RULE_WEAK_DEPENDENCY
                && reason.detail.contains("npm:bridge")
                && reason.cap == Some(2 * DEPENDENCY_MARGIN)
        }));
        assert_eq!(graph.summary.untracked_dependencies, 1);
        assert_eq!(graph.summary.degraded_by_propagation, 1);
        assert_eq!(
            blast_radius(&graph, "npm:leaf"),
            vec![
                BlastRadiusEntry {
                    extension_id: "npm:bridge".into(),
                    depth: 1
                },
                BlastRadiusEntry {
                    extension_id: "npm:app".into(),
                    depth: 2
                },
            ]
        );
    }

    #[test]
    fn lockfile_only_projects_retain_roots_edges_and_disconnected_packages() {
        let lockfile = LockfileDependencyGraph::from_lockfile_json(&serde_json::json!({
            "packages": {
                "": { "dependencies": { "root-only": "1" } },
                "node_modules/app": { "dependencies": { "bridge": "1" } },
                "node_modules/bridge": { "dependencies": { "leaf": "1" } },
                "node_modules/leaf": { "version": "1" },
                "node_modules/disconnected": { "version": "1" },
            },
        }));
        let graph = build_trust_graph(&[], &BTreeMap::new(), &lockfile);
        assert_eq!(graph.summary.extensions, 0);
        assert_eq!(graph.summary.untracked_dependencies, 5);
        assert_eq!(graph.summary.edges, 2);
        assert!(!graph.summary.lockfile_truncated);
        for id in ["app", "bridge", "leaf", "disconnected", "root-only"] {
            let package = node(&graph, &npm_extension_id(id));
            assert_eq!(package.kind, TrustNodeKind::UntrackedDependency);
            assert_eq!(package.base_score, None);
            assert_eq!(package.effective_score, None);
        }
        assert_eq!(
            blast_radius(&graph, "npm:leaf"),
            vec![
                BlastRadiusEntry {
                    extension_id: "npm:bridge".into(),
                    depth: 1
                },
                BlastRadiusEntry {
                    extension_id: "npm:app".into(),
                    depth: 2
                },
            ]
        );
        assert!(blast_radius(&graph, "npm:disconnected").is_empty());
        assert!(blast_radius(&graph, "npm:root-only").is_empty());
    }

    #[test]
    fn untracked_cycles_preserve_shortest_paths_without_creating_scores() {
        let base = card("npm:@acme/auth-guard");
        let lockfile = LockfileDependencyGraph::from_lockfile_json(&serde_json::json!({
            "packages": {
                "node_modules/app": { "dependencies": { "a": "1" } },
                "node_modules/a": { "dependencies": { "b": "1" } },
                "node_modules/b": { "dependencies": { "a": "1", "b": "1", "leaf": "1" } },
            },
        }));
        let graph = build_trust_graph(
            &[
                named(&base, "npm:app", "pub-app", 900),
                named(&base, "npm:leaf", "pub-leaf", 50),
            ],
            &BTreeMap::new(),
            &lockfile,
        );
        assert_eq!(node(&graph, "npm:app").effective_score, Some(650));
        for id in ["npm:a", "npm:b"] {
            assert_eq!(node(&graph, id).base_score, None);
            assert_eq!(node(&graph, id).effective_score, None);
        }
        assert!(graph.edges.iter().all(|edge| edge.source != edge.target));
        assert_eq!(
            blast_radius(&graph, "npm:leaf"),
            vec![
                BlastRadiusEntry {
                    extension_id: "npm:b".into(),
                    depth: 1
                },
                BlastRadiusEntry {
                    extension_id: "npm:a".into(),
                    depth: 2
                },
                BlastRadiusEntry {
                    extension_id: "npm:app".into(),
                    depth: 3
                },
            ]
        );
        assert_eq!(
            blast_radius(&graph, "npm:a"),
            vec![
                BlastRadiusEntry {
                    extension_id: "npm:app".into(),
                    depth: 1
                },
                BlastRadiusEntry {
                    extension_id: "npm:b".into(),
                    depth: 1
                },
            ]
        );
    }

    #[test]
    fn publisher_incidents_cap_sibling_extensions() {
        let base = card("npm:@acme/auth-guard");
        let mut bad = named(&base, "npm:bad", "pub-shared", 800);
        bad.active_quarantine = true;
        let sibling = named(&base, "npm:sibling", "pub-shared", 950);
        let graph = build_trust_graph(
            &[bad, sibling],
            &BTreeMap::new(),
            &LockfileDependencyGraph::default(),
        );
        let publisher = node(&graph, "publisher:pub-shared");
        assert_eq!(publisher.kind, TrustNodeKind::Publisher);
        assert_eq!(publisher.base_score, Some(875));
        assert_eq!(publisher.effective_score, Some(PUBLISHER_INCIDENT_CAP));
        assert!(publisher.explanation[0].detail.contains("npm:bad"));
        let sibling = node(&graph, "npm:sibling");
        assert_eq!(
            sibling.effective_score,
            Some(PUBLISHER_INCIDENT_CAP + PUBLISHER_MARGIN)
        );
        assert!(sibling.degraded_by_propagation());
    }

    #[test]
    fn untracked_dependencies_are_coverage_gaps_without_scores() {
        let base = card("npm:@acme/auth-guard");
        let graph = build_trust_graph(
            &[named(&base, "npm:app", "pub-1", 700)],
            &BTreeMap::new(),
            &lockfile(&[("app", &["left-pad"])]),
        );
        let gap = node(&graph, "npm:left-pad");
        assert_eq!(gap.kind, TrustNodeKind::UntrackedDependency);
        assert_eq!(gap.effective_score, None);
        let app = node(&graph, "npm:app");
        assert_eq!(app.effective_score, Some(700));
        assert!(
            app.explanation
                .iter()
                .any(|reason| reason.rule == RULE_UNTRACKED_DEPENDENCY)
        );
        // The fixture's root-only app-dep is also an honest coverage gap.
        assert_eq!(node(&graph, "npm:app-dep").effective_score, None);
        assert_eq!(graph.summary.untracked_dependencies, 2);
    }

    #[test]
    fn transitions_report_changed_fields_and_new_audit_causes() {
        let base = card("npm:@acme/auth-guard");
        let mut v1 = named(&base, "npm:app", "pub-1", 700);
        v1.trust_card_version = 1;
        v1.audit_history = vec![AuditRecord {
            timestamp: "2026-10-01T00:00:00Z".to_string(),
            event_code: "TRUST_CARD_CREATED".to_string(),
            detail: "seeded".to_string(),
            trace_id: "t1".to_string(),
        }];
        let mut v2 = v1.clone();
        v2.trust_card_version = 2;
        v2.reputation_score_basis_points = 300;
        v2.active_quarantine = true;
        v2.audit_history.push(AuditRecord {
            timestamp: "2026-10-02T00:00:00Z".to_string(),
            event_code: "TRUST_CARD_QUARANTINED".to_string(),
            detail: "fleet quarantine inc-1".to_string(),
            trace_id: "t2".to_string(),
        });
        let mut v3 = v2.clone();
        v3.trust_card_version = 3;
        let histories = BTreeMap::from([("npm:app".to_string(), vec![v3.clone(), v1, v2])]);
        let graph = build_trust_graph(&[v3], &histories, &LockfileDependencyGraph::default());
        assert_eq!(graph.transitions.len(), 1, "v2->v3 changed nothing");
        let transition = &graph.transitions[0];
        assert_eq!((transition.from_version, transition.to_version), (1, 2));
        let fields: Vec<&str> = transition
            .changes
            .iter()
            .map(|change| change.field.as_str())
            .collect();
        assert_eq!(fields, vec!["reputation_score", "active_quarantine"]);
        assert_eq!(transition.causes.len(), 1);
        assert_eq!(transition.causes[0].event_code, "TRUST_CARD_QUARANTINED");
    }

    fn topology_graph(edges: &[(&str, &[&str])], cards: &[TrustCard]) -> TrustGraph {
        let lockfile = LockfileDependencyGraph {
            dependencies: edges
                .iter()
                .map(|(source, targets)| {
                    (
                        (*source).to_string(),
                        targets.iter().map(|target| (*target).to_string()).collect(),
                    )
                })
                .collect(),
            ..LockfileDependencyGraph::default()
        };
        build_trust_graph(cards, &BTreeMap::new(), &lockfile)
    }

    #[test]
    fn directed_chain_has_exact_centrality_articulation_and_reverse_depth() {
        let graph = topology_graph(
            &[("a", &["b"]), ("b", &["c"]), ("c", &["d"]), ("d", &[])],
            &[],
        );
        let metrics = dependency_topology_metrics(&graph).expect("bounded complete graph");
        assert_eq!(metrics.len(), 4);
        for id in ["npm:b", "npm:c"] {
            assert!((metrics[id].betweenness_centrality - 1.0 / 3.0).abs() < 1e-12);
            assert!(metrics[id].is_articulation_point);
        }
        for id in ["npm:a", "npm:d"] {
            assert_eq!(metrics[id].betweenness_centrality, 0.0);
            assert!(!metrics[id].is_articulation_point);
        }
        assert_eq!(metrics["npm:a"].direct_dependencies, 1);
        assert_eq!(metrics["npm:a"].transitive_dependents, 0);
        assert_eq!(metrics["npm:b"].transitive_dependents, 1);
        assert_eq!(metrics["npm:c"].transitive_dependents, 2);
        assert_eq!(metrics["npm:d"].transitive_dependents, 3);
        assert_eq!(metrics["npm:d"].direct_dependencies, 0);
        assert_eq!(metrics["npm:d"].max_dependent_depth, 3);
        assert!(
            graph
                .nodes
                .iter()
                .all(|node| node.effective_score.is_none())
        );
    }

    #[test]
    fn diamond_splits_shortest_paths_and_excludes_publisher_relations() {
        let base = card("npm:@acme/auth-guard");
        let graph = topology_graph(
            &[("a", &["b", "c"]), ("b", &["d"]), ("c", &["d"])],
            &[named(&base, "npm:a", "pub-a", 900)],
        );
        assert_eq!(graph.summary.publishers, 1);
        let metrics = dependency_topology_metrics(&graph).expect("bounded diamond");
        assert_eq!(metrics.len(), 4);
        assert!(!metrics.contains_key("publisher:pub-a"));
        assert!((metrics["npm:b"].betweenness_centrality - 1.0 / 12.0).abs() < 1e-12);
        assert!((metrics["npm:c"].betweenness_centrality - 1.0 / 12.0).abs() < 1e-12);
        assert!(metrics.values().all(|node| !node.is_articulation_point));
        assert_eq!(metrics["npm:a"].direct_dependencies, 2);
        assert_eq!(metrics["npm:d"].transitive_dependents, 3);
        assert_eq!(metrics["npm:d"].max_dependent_depth, 2);
    }

    #[test]
    fn topology_cycles_and_duplicate_evidence_are_deterministic() {
        let mut graph = topology_graph(
            &[
                ("a", &["b"]),
                ("b", &["c"]),
                ("c", &["a"]),
                ("isolated", &[]),
            ],
            &[],
        );
        let expected = dependency_topology_metrics(&graph).expect("bounded cycle");
        for id in ["npm:a", "npm:b", "npm:c"] {
            assert!((expected[id].betweenness_centrality - 1.0 / 6.0).abs() < 1e-12);
            assert_eq!(expected[id].transitive_dependents, 2);
            assert_eq!(expected[id].max_dependent_depth, 2);
            assert_eq!(expected[id].direct_dependencies, 1);
            assert!(!expected[id].is_articulation_point);
        }
        assert_eq!(expected["npm:isolated"].betweenness_centrality, 0.0);
        assert_eq!(expected["npm:isolated"].transitive_dependents, 0);
        assert_eq!(expected["npm:isolated"].max_dependent_depth, 0);
        let mut duplicate = graph.edges[0].clone();
        duplicate.evidence = "another observation of the same relation".to_string();
        graph.edges.push(duplicate);
        graph.edges.push(TrustGraphEdge {
            source: "npm:a".to_string(),
            target: "npm:a".to_string(),
            relation: TrustRelation::DependsOn,
            evidence: "self edge is ignored".to_string(),
        });
        graph.nodes.reverse();
        graph.edges.reverse();
        assert_eq!(
            dependency_topology_metrics(&graph).expect("same topology"),
            expected
        );
    }

    #[test]
    fn undirected_articulation_does_not_require_directed_dependents() {
        let graph = topology_graph(
            &[
                ("center", &["left", "right", "third"]),
                ("elsewhere", &["other"]),
            ],
            &[],
        );
        let metrics = dependency_topology_metrics(&graph).expect("disconnected star");
        assert!(metrics["npm:center"].is_articulation_point);
        assert_eq!(metrics["npm:center"].betweenness_centrality, 0.0);
        assert_eq!(metrics["npm:center"].transitive_dependents, 0);
        assert_eq!(metrics["npm:center"].direct_dependencies, 3);
        assert!(!metrics["npm:elsewhere"].is_articulation_point);
        assert!(!metrics["npm:left"].is_articulation_point);
    }

    #[test]
    fn empty_and_small_topologies_have_measured_zero_centrality() {
        assert!(
            dependency_topology_metrics(&topology_graph(&[], &[]))
                .expect("empty graph")
                .is_empty()
        );
        for edges in [vec![("alone", &[][..])], vec![("a", &["b"][..])]] {
            let metrics =
                dependency_topology_metrics(&topology_graph(&edges, &[])).expect("small graph");
            assert!(
                metrics
                    .values()
                    .all(|node| node.betweenness_centrality == 0.0)
            );
            assert!(metrics.values().all(|node| !node.is_articulation_point));
        }
        let metrics =
            dependency_topology_metrics(&topology_graph(&[("a", &["b"])], &[])).expect("two nodes");
        assert_eq!(metrics["npm:b"].transitive_dependents, 1);
        assert_eq!(metrics["npm:b"].max_dependent_depth, 1);
    }

    #[test]
    fn topology_refuses_truncated_and_invalid_input() {
        let mut graph = topology_graph(&[("a", &["b"])], &[]);
        graph.summary.lockfile_truncated = true;
        assert_eq!(
            dependency_topology_metrics(&graph),
            Err(DependencyTopologyError::TruncatedLockfile)
        );
        graph.summary.lockfile_truncated = false;
        graph.nodes.retain(|node| node.node_id != "npm:b");
        assert!(matches!(
            dependency_topology_metrics(&graph),
            Err(DependencyTopologyError::InvalidGraph { .. })
        ));
        let mut graph = topology_graph(&[("a", &[])], &[]);
        graph.nodes.push(graph.nodes[0].clone());
        assert!(matches!(
            dependency_topology_metrics(&graph),
            Err(DependencyTopologyError::InvalidGraph { .. })
        ));
    }

    #[test]
    fn topology_budgets_refuse_analysis_without_returning_placeholder_metrics() {
        let lockfile = LockfileDependencyGraph {
            dependencies: (0..=MAX_TOPOLOGY_NODES)
                .map(|index| (format!("pkg-{index:04}"), BTreeSet::new()))
                .collect(),
            ..LockfileDependencyGraph::default()
        };
        let graph = build_trust_graph(&[], &BTreeMap::new(), &lockfile);
        assert_eq!(
            dependency_topology_metrics(&graph),
            Err(DependencyTopologyError::NodeLimit {
                nodes: MAX_TOPOLOGY_NODES + 1,
                limit: MAX_TOPOLOGY_NODES,
            })
        );

        let lockfile = LockfileDependencyGraph {
            dependencies: (0..MAX_TOPOLOGY_NODES)
                .map(|index| {
                    (
                        format!("pkg-{index:04}"),
                        (1..=7)
                            .map(|offset| {
                                format!("pkg-{:04}", (index + offset) % MAX_TOPOLOGY_NODES)
                            })
                            .collect(),
                    )
                })
                .collect(),
            ..LockfileDependencyGraph::default()
        };
        let graph = build_trust_graph(&[], &BTreeMap::new(), &lockfile);
        let error = dependency_topology_metrics(&graph).expect_err("work exceeds budget");
        assert!(matches!(error, DependencyTopologyError::WorkLimit { .. }));
        assert!(error.to_string().contains("work units"));
    }

    #[test]
    fn graph_is_deterministic() {
        let base = card("npm:@acme/auth-guard");
        let cards = vec![
            named(&base, "npm:z", "pub-1", 900),
            named(&base, "npm:a", "pub-2", 200),
        ];
        let lock = lockfile(&[("z", &["a"])]);
        let first = build_trust_graph(&cards, &BTreeMap::new(), &lock);
        let mut reversed = cards.clone();
        reversed.reverse();
        let second = build_trust_graph(&reversed, &BTreeMap::new(), &lock);
        assert_eq!(first, second);
    }

    fn captured_artifact_dependencies(
        roots: serde_json::Value,
        packages: serde_json::Value,
    ) -> LockfileDependencyGraph {
        let root = tempfile::tempdir().expect("artifact capture project");
        std::fs::write(
            root.path().join("package.json"),
            serde_json::json!({
                "name": "artifact-graph-fixture",
                "version": "1.0.0",
                "dependencies": roots,
            })
            .to_string(),
        )
        .expect("root manifest");
        std::fs::write(
            root.path().join("package-lock.json"),
            serde_json::json!({"lockfileVersion": 3, "packages": packages}).to_string(),
        )
        .expect("captured lockfile");
        let topology =
            super::super::module_resolution_graph::dependency_topology::build(root.path())
                .expect("canonical capture");
        LockfileDependencyGraph::from_captured_topology(
            topology.trust_graph_projection().expect("trust projection"),
        )
        .expect("bounded trust graph")
    }

    fn artifact_integrity(byte: u8) -> String {
        use base64::Engine as _;
        format!(
            "sha512-{}",
            base64::engine::general_purpose::STANDARD.encode([byte; 64])
        )
    }

    fn artifact_card(extension: &str, version: &str, byte: u8) -> TrustCard {
        let mut result = named(
            &card("npm:@acme/auth-guard"),
            extension,
            "artifact-publisher",
            900,
        );
        result.extension.version = version.to_owned();
        result.provenance_summary.artifact_hashes =
            vec![format!("sha512:{}", hex::encode([byte; 64]))];
        result
    }

    #[test]
    fn artifact_matching_uses_actual_alias_identity_and_captured_metadata() {
        let dependencies = captured_artifact_dependencies(
            serde_json::json!({"shortcut": "npm:actual@1.0.0"}),
            serde_json::json!({
                "node_modules/shortcut": {
                    "name": "actual",
                    "version": "1.0.0",
                    "integrity": artifact_integrity(7),
                },
            }),
        );
        let current = artifact_card("npm:actual", "1.0.0", 7);
        let graph = build_trust_graph(&[current], &BTreeMap::new(), &dependencies);
        let actual = node(&graph, "npm:actual");
        let coverage = actual.artifact_coverage.as_ref().expect("artifact coverage");
        assert_eq!(coverage.status, TrustArtifactStatus::Matched);
        assert_eq!(coverage.placement_count, 1);
        assert!(coverage.detail.is_none());
        assert_eq!(actual.base_score, Some(900));
        assert_eq!(actual.effective_score, Some(900));
        assert_eq!(graph.summary.artifact_mismatches, 0);
        assert!(!graph.nodes.iter().any(|item| item.node_id == "npm:shortcut"));
        let capture = dependencies.capture.as_ref().expect("retained capture");
        assert_eq!(capture.placements[0].location, "node_modules/shortcut");
        assert_eq!(capture.placements[0].package_name, "actual");
    }

    #[test]
    fn one_matching_placement_cannot_hide_another_version_mismatch() {
        let dependencies = captured_artifact_dependencies(
            serde_json::json!({"parent": "1.0.0", "leaf": "1.0.0"}),
            serde_json::json!({
                "node_modules/parent": {
                    "version": "1.0.0",
                    "integrity": artifact_integrity(8),
                    "dependencies": {"leaf": "2.0.0"},
                },
                "node_modules/leaf": {
                    "version": "1.0.0",
                    "integrity": artifact_integrity(7),
                },
                "node_modules/parent/node_modules/leaf": {
                    "version": "2.0.0",
                    "integrity": artifact_integrity(9),
                },
            }),
        );
        let cards = [
            artifact_card("npm:parent", "1.0.0", 8),
            artifact_card("npm:leaf", "1.0.0", 7),
        ];
        let graph = build_trust_graph(&cards, &BTreeMap::new(), &dependencies);
        let leaf = node(&graph, "npm:leaf");
        let coverage = leaf.artifact_coverage.as_ref().expect("artifact coverage");
        assert!(coverage.is_mismatch());
        assert_eq!(coverage.placement_count, 2);
        assert_eq!(leaf.base_score, Some(900));
        assert_eq!(leaf.effective_score, None);
        assert!(leaf.explanation.iter().any(|reason| {
            reason.rule == RULE_ARTIFACT_MISMATCH && reason.detail.contains("2.0.0")
        }));
        assert_eq!(graph.summary.artifact_mismatches, 1);
        assert_eq!(
            blast_radius(&graph, "npm:leaf"),
            vec![BlastRadiusEntry {
                extension_id: "npm:parent".to_owned(),
                depth: 1,
            }]
        );
        assert_eq!(
            node(&graph, "npm:parent")
                .artifact_coverage
                .as_ref()
                .expect("parent artifact")
                .status,
            TrustArtifactStatus::Matched
        );
    }

    #[test]
    fn matching_multiple_placements_keep_the_score_without_merging_digest_pairs() {
        let dependencies = captured_artifact_dependencies(
            serde_json::json!({"parent": "1.0.0", "leaf": "1.0.0"}),
            serde_json::json!({
                "node_modules/parent": {
                    "version": "1.0.0",
                    "dependencies": {"leaf": "1.0.0"},
                },
                "node_modules/leaf": {
                    "version": "1.0.0",
                    "integrity": artifact_integrity(7),
                },
                "node_modules/parent/node_modules/leaf": {
                    "version": "1.0.0",
                    "integrity": artifact_integrity(7),
                },
            }),
        );
        let cards = [artifact_card("npm:leaf", "1.0.0", 7)];
        let coverage = trust_artifact_coverages(&cards, &dependencies);
        assert_eq!(coverage["npm:leaf"].status, TrustArtifactStatus::Matched);
        assert_eq!(coverage["npm:leaf"].placement_count, 2);
        let graph = build_trust_graph(&cards, &BTreeMap::new(), &dependencies);
        assert_eq!(node(&graph, "npm:leaf").effective_score, Some(900));
        assert_eq!(graph.summary.artifact_mismatches, 0);
    }

    #[test]
    fn same_version_with_one_changed_digest_is_a_current_artifact_mismatch() {
        let dependencies = captured_artifact_dependencies(
            serde_json::json!({"parent": "1.0.0", "leaf": "1.0.0"}),
            serde_json::json!({
                "node_modules/parent": {
                    "version": "1.0.0",
                    "dependencies": {"leaf": "1.0.0"},
                },
                "node_modules/leaf": {
                    "version": "1.0.0",
                    "integrity": artifact_integrity(7),
                },
                "node_modules/parent/node_modules/leaf": {
                    "version": "1.0.0",
                    "integrity": artifact_integrity(8),
                },
            }),
        );
        let graph = build_trust_graph(
            &[artifact_card("npm:leaf", "1.0.0", 7)],
            &BTreeMap::new(),
            &dependencies,
        );
        let leaf = node(&graph, "npm:leaf");
        assert_eq!(leaf.effective_score, None);
        let coverage = leaf.artifact_coverage.as_ref().expect("artifact coverage");
        assert_eq!(coverage.status, TrustArtifactStatus::Mismatch);
        assert_eq!(coverage.placement_count, 2);
        assert!(
            coverage
                .detail
                .as_deref()
                .expect("mismatch explanation")
                .contains("integrity")
        );
    }

    #[test]
    fn stronger_integrity_contradiction_cannot_be_hidden_by_matching_weak_digest() {
        use base64::Engine as _;
        let weak = base64::engine::general_purpose::STANDARD.encode([5_u8; 32]);
        let dependencies = captured_artifact_dependencies(
            serde_json::json!({"leaf": "1.0.0"}),
            serde_json::json!({
                "node_modules/leaf": {
                    "version": "1.0.0",
                    "integrity": format!("sha256-{weak} {}", artifact_integrity(8)),
                },
            }),
        );
        let mut current = artifact_card("npm:leaf", "1.0.0", 7);
        current
            .provenance_summary
            .artifact_hashes
            .push(format!("sha256:{}", hex::encode([5_u8; 32])));
        let graph = build_trust_graph(&[current], &BTreeMap::new(), &dependencies);
        let leaf = node(&graph, "npm:leaf");
        assert_eq!(leaf.effective_score, None);
        let coverage = leaf.artifact_coverage.as_ref().expect("artifact coverage");
        assert_eq!(coverage.status, TrustArtifactStatus::Mismatch);
        assert!(
            coverage
                .detail
                .as_deref()
                .expect("strong-digest explanation")
                .contains("sha512")
        );
    }

    #[test]
    fn incomplete_inventory_and_registry_only_views_do_not_claim_artifact_matches() {
        let dependencies = captured_artifact_dependencies(
            serde_json::json!({"leaf": "1.0.0"}),
            serde_json::json!({"node_modules/leaf": {"version": "1.0.0"}}),
        );
        let cards = [
            artifact_card("npm:leaf", "1.0.0", 7),
            artifact_card("npm:outside-project", "1.0.0", 7),
        ];
        let graph = build_trust_graph(&cards, &BTreeMap::new(), &dependencies);
        for (identity, placements) in [("npm:leaf", 1), ("npm:outside-project", 0)] {
            let item = node(&graph, identity);
            let coverage = item.artifact_coverage.as_ref().expect("explicit inventory state");
            assert_eq!(coverage.status, TrustArtifactStatus::Unverified);
            assert_eq!(coverage.placement_count, placements);
            assert!(coverage.detail.is_some());
            assert_eq!(item.effective_score, Some(900));
            assert!(item.explanation.iter().any(|reason| {
                reason.rule == RULE_ARTIFACT_UNVERIFIED
            }));
        }
        assert_eq!(graph.summary.artifact_mismatches, 0);

        let registry_only = build_trust_graph(
            &cards,
            &BTreeMap::new(),
            &LockfileDependencyGraph::default(),
        );
        assert!(
            registry_only
                .nodes
                .iter()
                .all(|item| item.artifact_coverage.is_none())
        );
        assert_eq!(node(&registry_only, "npm:leaf").effective_score, Some(900));
    }

    #[test]
    fn artifact_mismatch_never_lifts_existing_quarantine_or_revocation() {
        let dependencies = captured_artifact_dependencies(
            serde_json::json!({"leaf": "2.0.0"}),
            serde_json::json!({
                "node_modules/leaf": {
                    "version": "2.0.0",
                    "integrity": artifact_integrity(8),
                },
            }),
        );
        for (quarantined, revoked, expected, rule) in [
            (true, false, QUARANTINE_CAP, RULE_QUARANTINED),
            (false, true, 0, RULE_REVOKED),
        ] {
            let mut current = artifact_card("npm:leaf", "1.0.0", 7);
            current.active_quarantine = quarantined;
            if revoked {
                current.revocation_status = RevocationStatus::Revoked {
                    reason: "existing package revocation".to_owned(),
                    revoked_at: "2026-01-01T00:00:00Z".to_owned(),
                };
            }
            let graph = build_trust_graph(&[current], &BTreeMap::new(), &dependencies);
            let leaf = node(&graph, "npm:leaf");
            assert!(
                leaf.artifact_coverage
                    .as_ref()
                    .expect("artifact coverage")
                    .is_mismatch()
            );
            assert_eq!(leaf.effective_score, Some(expected));
            assert_eq!(leaf.quarantined, quarantined);
            assert_eq!(leaf.revoked, revoked);
            assert!(leaf.explanation.iter().any(|reason| reason.rule == rule));
            assert_eq!(graph.summary.artifact_mismatches, 1);
        }
    }

}
