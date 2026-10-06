//! Ecosystem reputation graph with explainable trust transitions (charter
//! impossible-by-default capability 9).
//!
//! Every input is observed, signature-verified data:
//! * nodes come from the trust-card registry (extensions) and the publishers
//!   named on those cards;
//! * `depends_on` edges come from the project's npm lockfile, so the graph is
//!   the dependency structure the project actually installs;
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

use super::trust_card::{RevocationStatus, TrustCard};

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
/// Bound on the lockfile entries and dependency names the graph ingests.
pub const MAX_GRAPH_PACKAGES: usize = 20_000;

pub const RULE_REVOKED: &str = "R1_REVOKED";
pub const RULE_QUARANTINED: &str = "R2_QUARANTINED";
pub const RULE_WEAK_DEPENDENCY: &str = "R3_WEAK_DEPENDENCY";
pub const RULE_PUBLISHER_INCIDENT: &str = "R4_PUBLISHER_INCIDENT";
pub const RULE_PUBLISHER_CAP: &str = "R4_PUBLISHER_CAP";
pub const RULE_UNTRACKED_DEPENDENCY: &str = "COVERAGE_UNTRACKED_DEPENDENCY";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustNodeKind {
    Publisher,
    Extension,
    /// A dependency the lockfile installs that has no trust card. It carries
    /// no score; dependents report it as a trust-coverage gap.
    UntrackedDependency,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustRelation {
    /// publisher -> extension
    Publishes,
    /// extension -> dependency (from the lockfile)
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustGraphNode {
    pub node_id: String,
    pub kind: TrustNodeKind,
    pub display_name: String,
    /// The node's own score: the card's reputation (extensions) or the mean
    /// of its extensions' scores (publishers). `None` for untracked nodes.
    pub base_score: Option<u16>,
    /// Score after propagation; never above `base_score`.
    pub effective_score: Option<u16>,
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
        self.explanation.iter().any(|reason| {
            reason.rule == RULE_WEAK_DEPENDENCY || reason.rule == RULE_PUBLISHER_CAP
        })
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

/// Direct dependency relation of an npm lockfile, keyed by package name.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LockfileDependencyGraph {
    /// Packages the project itself depends on directly.
    pub root_dependencies: BTreeSet<String>,
    /// package name -> names of its direct dependencies.
    pub dependencies: BTreeMap<String, BTreeSet<String>>,
}

impl LockfileDependencyGraph {
    /// Parse `package-lock.json` / `npm-shrinkwrap.json` (lockfile v1, v2
    /// and v3). Nested installs (`node_modules/a/node_modules/b`) are keyed
    /// by the innermost package name; the graph is name-level.
    #[must_use]
    pub fn from_lockfile_json(lockfile: &serde_json::Value) -> Self {
        let mut graph = Self::default();
        let mut ingested = 0_usize;
        if let Some(packages) = lockfile.get("packages").and_then(serde_json::Value::as_object) {
            for (package_path, package) in packages {
                if ingested >= MAX_GRAPH_PACKAGES {
                    break;
                }
                ingested = ingested.saturating_add(1);
                let names = dependency_names(package, &["dependencies", "optionalDependencies"]);
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
                        break;
                    }
                    ingested = ingested.saturating_add(1);
                    if top_level && graph.root_dependencies.len() < MAX_GRAPH_PACKAGES {
                        graph.root_dependencies.insert(name.clone());
                    }
                    let requires = dependency_names(entry, &["requires"]);
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

fn dependency_names(package: &serde_json::Value, keys: &[&str]) -> BTreeSet<String> {
    keys.iter()
        .filter_map(|key| package.get(*key).and_then(serde_json::Value::as_object))
        .flat_map(|deps| deps.keys().cloned())
        .filter(|name| !name.is_empty())
        .take(MAX_GRAPH_PACKAGES)
        .collect()
}

/// Map a lockfile package name to the extension id trust scans assign it.
#[must_use]
pub fn npm_extension_id(package_name: &str) -> String {
    format!("npm:{package_name}")
}

fn package_name_of(extension_id: &str) -> Option<&str> {
    extension_id.strip_prefix("npm:")
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
        nodes.insert(
            card.extension.extension_id.clone(),
            TrustGraphNode {
                node_id: card.extension.extension_id.clone(),
                kind: TrustNodeKind::Extension,
                display_name: format!(
                    "{}@{}",
                    card.extension.extension_id, card.extension.version
                ),
                base_score: Some(base),
                effective_score: Some(effective),
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
        let display_name = published
            .first()
            .map_or_else(|| (*publisher_id).to_string(), |card| card.publisher.display_name.clone());
        nodes.insert(
            publisher_node_id(publisher_id),
            TrustGraphNode {
                node_id: publisher_node_id(publisher_id),
                kind: TrustNodeKind::Publisher,
                display_name,
                base_score: Some(base),
                effective_score: Some(effective),
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
        let (Some(publisher_id), Some(effective)) = (node.publisher_id.clone(), node.effective_score)
        else {
            continue;
        };
        let Some(publisher_score) = publisher_scores.get(&publisher_id) else {
            continue;
        };
        let cap = publisher_score.saturating_add(PUBLISHER_MARGIN).min(TRUST_SCORE_SCALE);
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

    // Lockfile dependency edges between packages that have cards; dependency
    // names without a card become untracked nodes.
    let card_ids: BTreeSet<String> = cards
        .iter()
        .map(|card| card.extension.extension_id.clone())
        .collect();
    let mut untracked: BTreeSet<String> = BTreeSet::new();
    for card_id in &card_ids {
        let Some(package) = package_name_of(card_id) else {
            continue;
        };
        let Some(dependencies) = lockfile.dependencies.get(package) else {
            continue;
        };
        for dependency in dependencies {
            let target = npm_extension_id(dependency);
            if target == *card_id {
                continue;
            }
            if !card_ids.contains(&target) {
                untracked.insert(target.clone());
            }
            edges.insert(TrustGraphEdge {
                source: card_id.clone(),
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
                quarantined: false,
                revoked: false,
                risk_level: None,
                publisher_id: None,
                explanation: vec![TrustExplanation {
                    rule: RULE_UNTRACKED_DEPENDENCY.to_string(),
                    detail: "installed by the lockfile but has no trust card; run `trust scan`"
                        .to_string(),
                    cap: None,
                }],
            },
        );
    }

    // R3: weakest-dependency propagation to a fixed point. Scores only
    // decrease and every cap adds a non-negative margin, so Bellman-Ford
    // style relaxation settles within |nodes| passes even with cycles.
    let depends_on: Vec<(String, String)> = edges
        .iter()
        .filter(|edge| edge.relation == TrustRelation::DependsOn)
        .map(|edge| (edge.source.clone(), edge.target.clone()))
        .collect();
    let mut binding: BTreeMap<String, (String, u16, u16)> = BTreeMap::new();
    for _ in 0..=nodes.len() {
        let mut changed = false;
        for (source, target) in &depends_on {
            let Some(target_score) = nodes.get(target).and_then(|node| node.effective_score) else {
                continue;
            };
            let cap = target_score.saturating_add(DEPENDENCY_MARGIN).min(TRUST_SCORE_SCALE);
            if let Some(node) = nodes.get_mut(source)
                && let Some(effective) = node.effective_score
                && effective > cap
            {
                node.effective_score = Some(cap);
                binding.insert(source.clone(), (target.clone(), target_score, cap));
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    for (source, (target, target_score, cap)) in binding {
        if let Some(node) = nodes.get_mut(&source) {
            node.explanation.push(TrustExplanation {
                rule: RULE_WEAK_DEPENDENCY.to_string(),
                detail: format!(
                    "depends on `{target}` (effective trust {target_score}); dependents are capped {DEPENDENCY_MARGIN} above their weakest dependency"
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
        assert_eq!(v3.root_dependencies, BTreeSet::from(["app-dep".to_string()]));
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
        assert_eq!(v1.dependencies.get("a"), Some(&BTreeSet::from(["b".to_string()])));
        assert_eq!(v1.dependencies.get("b"), Some(&BTreeSet::from(["c".to_string()])));
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
        assert!(mid
            .explanation
            .iter()
            .any(|reason| reason.rule == RULE_WEAK_DEPENDENCY && reason.detail.contains("npm:weak")));
        let app = node(&graph, "npm:app");
        assert_eq!(app.effective_score, Some(100 + 2 * DEPENDENCY_MARGIN));
        assert!(app
            .explanation
            .iter()
            .any(|reason| reason.detail.contains("npm:mid")));
        assert_eq!(app.base_score, Some(900));
        assert_eq!(graph.summary.degraded_by_propagation, 2);

        let radius = blast_radius(&graph, "npm:weak");
        assert_eq!(
            radius,
            vec![
                BlastRadiusEntry { extension_id: "npm:mid".to_string(), depth: 1 },
                BlastRadiusEntry { extension_id: "npm:app".to_string(), depth: 2 },
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
        assert_eq!(node(&graph, "npm:a").effective_score, Some(300 + DEPENDENCY_MARGIN));
        assert_eq!(node(&graph, "npm:b").effective_score, Some(300));
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
        assert!(app
            .explanation
            .iter()
            .any(|reason| reason.rule == RULE_UNTRACKED_DEPENDENCY));
        assert_eq!(graph.summary.untracked_dependencies, 1);
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
        let histories = BTreeMap::from([(
            "npm:app".to_string(),
            vec![v3.clone(), v1, v2],
        )]);
        let graph = build_trust_graph(&[v3], &histories, &LockfileDependencyGraph::default());
        assert_eq!(graph.transitions.len(), 1, "v2->v3 changed nothing");
        let transition = &graph.transitions[0];
        assert_eq!((transition.from_version, transition.to_version), (1, 2));
        let fields: Vec<&str> = transition.changes.iter().map(|change| change.field.as_str()).collect();
        assert_eq!(fields, vec!["reputation_score", "active_quarantine"]);
        assert_eq!(transition.causes.len(), 1);
        assert_eq!(transition.causes[0].event_code, "TRUST_CARD_QUARANTINED");
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
}
