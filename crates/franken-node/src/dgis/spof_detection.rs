//! Single-point-of-failure (SPOF) detection over the DGIS maintainer +
//! dependency graph (bd-2jns sub-task 2 of 5).
//!
//! Inputs: a `BTreeMap` of `MaintainerProfile`s, a `BTreeMap` of
//! `PublisherProfile`s, and the deterministic property graph (`GraphNode` +
//! `GraphEdge`) produced by [`crate::dgis::graph_ingestion`]. Outputs: a
//! [`SpofReport`] describing each [`SpofFinding`] — affected packages, root
//! cause node, contributing [`FragilityFactor`]s, and machine-readable
//! mitigation hints.
//!
//! Five orthogonal SPOF kinds are detected, each with its own internal helper:
//!
//! 1. [`SpofKind::SingleMaintainer`] — a package whose only maintainer also
//!    maintains many other packages (high blast-radius bus-factor-1).
//! 2. [`SpofKind::KeyPerson`]        — a maintainer responsible for more than
//!    `key_person_threshold` share of total monthly downloads.
//! 3. [`SpofKind::DependencyChain`]  — a `MaintainedBy → Depends → Depends …`
//!    chain whose every package is owned by a fragile maintainer
//!    (cascade-failure path).
//! 4. [`SpofKind::OrgConcentration`] — an organisation owning more than
//!    `org_concentration_threshold` share of all package namespaces.
//! 5. [`SpofKind::OrphanedPackage`]  — a package whose sole maintainer has
//!    been inactive for more than `orphan_threshold_days`.
//!
//! Hardening invariants enforced throughout:
//!
//! * `MAX_SPOF_FINDINGS` bounds the result vector; `push_bounded` is used at
//!   every accumulation site so a pathological input cannot exhaust memory.
//! * `saturating_add` / `saturating_sub` on every `i64` timestamp delta and
//!   every `u32` counter. Timestamps in the future fail closed (zero days),
//!   never panic.
//! * Every `f64` severity / share is checked with `is_finite()`; any non-
//!   finite intermediate is clamped to zero rather than leaked out.
//! * `SpofDetectorConfig::validate` rejects NaN / out-of-range thresholds at
//!   the public entry point so downstream loops never see junk thresholds.
//! * No unsafe code (inherited `#![forbid(unsafe_code)]` from `lib.rs`).
//! * BFS used for chain detection has its visited set capped at
//!   `MAX_BFS_NODES`, and per-chain length is gated by
//!   `config.max_chain_length` to prevent O(V²) blow-up.
//! * Severity is clamped to `[0.0, 1.0]` before being written into a finding.
//! * All public types implement `Serialize`/`Deserialize` so downstream
//!   verification gates can round-trip findings to JSON.
//!
//! NB: this sub-task ships ONLY the algorithm + inline tests. The shared
//! fragility fixture set, integration test, and verification gate land in
//! sub-tasks 3-5 of bd-2jns.1.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use serde::{Deserialize, Serialize};

use crate::dgis::fragility_model::{
    FragilityFactor, MaintainerProfile, PublisherProfile, SOLE_MAINTAINER_BUS_FACTOR,
    STALE_MAINTAINER_DAYS,
};
use crate::dgis::graph_ingestion::{EdgeKind, GraphEdge, GraphNode, NodeId, NodeKind};
use crate::push_bounded;

// ---------------------------------------------------------------------------
// Bounds & defaults
// ---------------------------------------------------------------------------

/// Hard cap on the number of findings a single [`detect_spofs`] call may
/// emit. Set well above any realistic ecosystem fragility profile (4 096
/// findings = orders of magnitude more than xz-utils-class corpora ever
/// produce) yet bounded to prevent DoS via crafted graphs.
pub const MAX_SPOF_FINDINGS: usize = 4096;

/// Hard cap on the BFS visited set used by dependency-chain detection.
/// 64 K nodes is well above any realistic ecosystem slice and bounds the
/// worst-case memory of the traversal at a few MB.
pub const MAX_BFS_NODES: usize = 64 * 1024;

/// Default: a maintainer who is the sole maintainer for at least this many
/// packages is treated as a `SingleMaintainer` SPOF.
pub const DEFAULT_SINGLE_MAINTAINER_THRESHOLD: u32 = 3;

/// Default: a maintainer controlling at least this share of an ecosystem's
/// monthly downloads is treated as a `KeyPerson` SPOF. 0.10 = 10%.
pub const DEFAULT_KEY_PERSON_THRESHOLD: f64 = 0.10;

/// Default: a `Depends → Depends → …` chain longer than this many fragile
/// nodes is treated as a `DependencyChain` SPOF.
pub const DEFAULT_MAX_CHAIN_LENGTH: u32 = 4;

/// Default: an organisation owning more than this share of distinct
/// namespaces is treated as an `OrgConcentration` SPOF. 0.30 = 30%.
pub const DEFAULT_ORG_CONCENTRATION_THRESHOLD: f64 = 0.30;

/// Default: a package whose sole maintainer has been inactive for more than
/// this many days is treated as an `OrphanedPackage` SPOF. Mirrors
/// `STALE_MAINTAINER_DAYS` from the fragility model.
pub const DEFAULT_ORPHAN_THRESHOLD_DAYS: u32 = STALE_MAINTAINER_DAYS;

// Compile-time guards for the float thresholds.
const _: () = assert!(
    DEFAULT_KEY_PERSON_THRESHOLD > 0.0 && DEFAULT_KEY_PERSON_THRESHOLD < 1.0,
    "default key_person threshold must be a strict probability",
);
const _: () = assert!(
    DEFAULT_ORG_CONCENTRATION_THRESHOLD > 0.0 && DEFAULT_ORG_CONCENTRATION_THRESHOLD < 1.0,
    "default org_concentration threshold must be a strict probability",
);
const _: () = assert!(
    DEFAULT_MAX_CHAIN_LENGTH >= 2,
    "max chain length must be at least 2 to form a chain",
);

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors emitted by SPOF detection.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SpofError {
    /// A configurable threshold was NaN, +/-inf, or out of `[0.0, 1.0]`.
    #[error("invalid config field '{field}': {reason}")]
    InvalidConfig {
        field: &'static str,
        reason: &'static str,
    },
    /// An edge weight or maintainer share was non-finite at runtime.
    #[error("non-finite floating-point value in field '{field}'")]
    NonFiniteValue { field: &'static str },
}

/// Convenience `Result` alias.
pub type Result<T> = std::result::Result<T, SpofError>;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Categorical kind of a single SPOF finding.
///
/// `PartialEq` (not `Eq`) is used because `KeyPerson` and `OrgConcentration`
/// carry `f64` shares; downstream tests inspect the variant via `matches!`
/// or destructure the share with `is_finite` checks.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SpofKind {
    /// A maintainer is the sole maintainer of `downstream_count` packages.
    SingleMaintainer { downstream_count: u32 },
    /// A maintainer's `share` of total monthly downloads exceeds the
    /// configured key-person threshold. `share` is finite and in `[0.0, 1.0]`.
    KeyPerson { share_of_downloads: f64 },
    /// A dependency chain of fragile packages of length `chain_length`. The
    /// chain itself is preserved in `chain` (node IDs in traversal order).
    DependencyChain {
        chain_length: u32,
        chain: Vec<NodeId>,
    },
    /// An organisation owning a `share` of distinct namespaces above the
    /// configured threshold. `share` is finite and in `[0.0, 1.0]`.
    OrgConcentration { org_id: String, share: f64 },
    /// A package whose sole maintainer has been inactive for
    /// `last_activity_days` days (capped at `u32::MAX` on overflow).
    OrphanedPackage { last_activity_days: u32 },
}

impl SpofKind {
    /// Stable telemetry label.
    pub fn label(&self) -> &'static str {
        match self {
            SpofKind::SingleMaintainer { .. } => "single_maintainer",
            SpofKind::KeyPerson { .. } => "key_person",
            SpofKind::DependencyChain { .. } => "dependency_chain",
            SpofKind::OrgConcentration { .. } => "org_concentration",
            SpofKind::OrphanedPackage { .. } => "orphaned_package",
        }
    }
}

/// A single SPOF finding.
///
/// `severity` is finite and in `[0.0, 1.0]`; the constructor [`SpofFinding::new`]
/// is the only safe way to build one from untrusted data.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SpofFinding {
    pub kind: SpofKind,
    pub severity: f64,
    pub affected_packages: Vec<NodeId>,
    pub root_cause_node: NodeId,
    pub fragility_factors: Vec<FragilityFactor>,
    pub suggested_mitigations: Vec<String>,
}

impl SpofFinding {
    /// Build a finding, clamping `severity` to `[0.0, 1.0]` and rejecting
    /// non-finite values.
    pub fn new(
        kind: SpofKind,
        severity: f64,
        affected_packages: Vec<NodeId>,
        root_cause_node: NodeId,
        fragility_factors: Vec<FragilityFactor>,
        suggested_mitigations: Vec<String>,
    ) -> Result<Self> {
        if !severity.is_finite() {
            return Err(SpofError::NonFiniteValue { field: "severity" });
        }
        let clamped = severity.clamp(0.0, 1.0);
        Ok(Self {
            kind,
            severity: clamped,
            affected_packages,
            root_cause_node,
            fragility_factors,
            suggested_mitigations,
        })
    }
}

/// The aggregate report produced by [`detect_spofs`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SpofReport {
    pub spofs: Vec<SpofFinding>,
    pub evaluated_packages: u32,
    pub evaluated_at: i64,
}

impl SpofReport {
    /// Whether any SPOF was detected.
    pub fn has_findings(&self) -> bool {
        !self.spofs.is_empty()
    }
}

/// Tunable thresholds for the detector.
///
/// Construct via [`Default`] for production defaults, or build the struct
/// literally for tests. All float fields are validated by
/// [`SpofDetectorConfig::validate`] (called automatically inside
/// [`detect_spofs`]).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SpofDetectorConfig {
    pub single_maintainer_threshold: u32,
    pub key_person_threshold: f64,
    pub max_chain_length: u32,
    pub org_concentration_threshold: f64,
    pub orphan_threshold_days: u32,
}

impl Default for SpofDetectorConfig {
    fn default() -> Self {
        Self {
            single_maintainer_threshold: DEFAULT_SINGLE_MAINTAINER_THRESHOLD,
            key_person_threshold: DEFAULT_KEY_PERSON_THRESHOLD,
            max_chain_length: DEFAULT_MAX_CHAIN_LENGTH,
            org_concentration_threshold: DEFAULT_ORG_CONCENTRATION_THRESHOLD,
            orphan_threshold_days: DEFAULT_ORPHAN_THRESHOLD_DAYS,
        }
    }
}

impl SpofDetectorConfig {
    /// Reject NaN / infinity / out-of-range float thresholds and zero
    /// chain-length. Called by [`detect_spofs`] so misconfiguration fails at
    /// the boundary.
    pub fn validate(&self) -> Result<()> {
        if !self.key_person_threshold.is_finite() {
            return Err(SpofError::InvalidConfig {
                field: "key_person_threshold",
                reason: "non-finite",
            });
        }
        if !(0.0..=1.0).contains(&self.key_person_threshold) {
            return Err(SpofError::InvalidConfig {
                field: "key_person_threshold",
                reason: "out of [0.0, 1.0]",
            });
        }
        if !self.org_concentration_threshold.is_finite() {
            return Err(SpofError::InvalidConfig {
                field: "org_concentration_threshold",
                reason: "non-finite",
            });
        }
        if !(0.0..=1.0).contains(&self.org_concentration_threshold) {
            return Err(SpofError::InvalidConfig {
                field: "org_concentration_threshold",
                reason: "out of [0.0, 1.0]",
            });
        }
        if self.max_chain_length < 2 {
            return Err(SpofError::InvalidConfig {
                field: "max_chain_length",
                reason: "must be >= 2",
            });
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Run all five SPOF detectors and aggregate their findings.
///
/// Inputs:
/// * `maintainers` -- profiles keyed by `MaintainerProfile::id`.
/// * `publishers`  -- profiles keyed by `PublisherProfile::id` (used for
///   org-concentration analysis).
/// * `nodes`       -- canonical ingested graph nodes.
/// * `edges`       -- canonical ingested graph edges.
/// * `config`      -- tunable thresholds (`validate()` is called first).
/// * `now`         -- wall-clock seconds since UNIX epoch.
///
/// All sub-detectors are called unconditionally; each contributes via
/// `push_bounded` so the global cap [`MAX_SPOF_FINDINGS`] is enforced
/// regardless of which sub-detector produced the surplus.
pub fn detect_spofs(
    maintainers: &BTreeMap<String, MaintainerProfile>,
    publishers: &BTreeMap<String, PublisherProfile>,
    nodes: &[GraphNode],
    edges: &[GraphEdge],
    config: &SpofDetectorConfig,
    now: i64,
) -> Result<SpofReport> {
    config.validate()?;

    let mut spofs: Vec<SpofFinding> = Vec::new();

    find_single_maintainer_spofs(maintainers, edges, config, &mut spofs)?;
    find_key_person_spofs(maintainers, config, &mut spofs)?;
    find_dependency_chain_spofs(maintainers, nodes, edges, config, &mut spofs)?;
    find_org_concentration_spofs(publishers, nodes, config, &mut spofs)?;
    find_orphaned_package_spofs(maintainers, edges, config, now, &mut spofs)?;

    let evaluated_packages = count_packages(nodes);

    Ok(SpofReport {
        spofs,
        evaluated_packages,
        evaluated_at: now,
    })
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Index `MaintainedBy` edges by (maintainer -> Vec<package>) and the
/// inverse (package -> Vec<maintainer>).
fn index_maintained_by(
    edges: &[GraphEdge],
) -> (BTreeMap<String, Vec<NodeId>>, BTreeMap<NodeId, Vec<String>>) {
    let mut by_maintainer: BTreeMap<String, Vec<NodeId>> = BTreeMap::new();
    let mut by_package: BTreeMap<NodeId, Vec<String>> = BTreeMap::new();
    for e in edges.iter().filter(|e| e.kind == EdgeKind::MaintainedBy) {
        // Edge direction convention: package --MaintainedBy--> maintainer.
        let pkg = e.from.clone();
        let mnt = e.to.clone();
        let pkgs = by_maintainer.entry(mnt.clone()).or_default();
        push_bounded(pkgs, pkg.clone(), MAX_SPOF_FINDINGS);
        let mnts = by_package.entry(pkg).or_default();
        push_bounded(mnts, mnt, MAX_SPOF_FINDINGS);
    }
    (by_maintainer, by_package)
}

/// Build (package -> Vec<dependency-package>) from `Depends` edges.
fn index_depends(edges: &[GraphEdge]) -> BTreeMap<NodeId, Vec<NodeId>> {
    let mut out: BTreeMap<NodeId, Vec<NodeId>> = BTreeMap::new();
    for e in edges.iter().filter(|e| e.kind == EdgeKind::Depends) {
        let deps = out.entry(e.from.clone()).or_default();
        push_bounded(deps, e.to.clone(), MAX_SPOF_FINDINGS);
    }
    out
}

fn count_packages(nodes: &[GraphNode]) -> u32 {
    let mut count: u32 = 0;
    for n in nodes {
        if n.kind == NodeKind::Package {
            count = count.saturating_add(1);
        }
    }
    count
}

/// Detector 1 -- single-maintainer SPOFs.
///
/// A maintainer is flagged when they appear as a sole maintainer for at
/// least `config.single_maintainer_threshold` packages. The blast-radius
/// (downstream_count) is the number of distinct packages they sole-maintain.
fn find_single_maintainer_spofs(
    maintainers: &BTreeMap<String, MaintainerProfile>,
    edges: &[GraphEdge],
    config: &SpofDetectorConfig,
    out: &mut Vec<SpofFinding>,
) -> Result<()> {
    let (by_maintainer, by_package) = index_maintained_by(edges);

    for (mnt_id, packages) in &by_maintainer {
        // Restrict to packages where THIS maintainer is the only one listed.
        let sole_packages: Vec<NodeId> = packages
            .iter()
            .filter(|p| by_package.get(*p).map(|v| v.len() <= 1).unwrap_or(true))
            .cloned()
            .collect();

        let count_u32 = u32::try_from(sole_packages.len()).unwrap_or(u32::MAX);
        if count_u32 < config.single_maintainer_threshold {
            continue;
        }

        // Severity grows with the number of sole-maintained packages,
        // capped at 1.0 once the maintainer owns >= 10 sole packages.
        let severity = (sole_packages.len() as f64 / 10.0).clamp(0.0, 1.0);
        let factors = match maintainers.get(mnt_id) {
            Some(profile) if profile.bus_factor <= SOLE_MAINTAINER_BUS_FACTOR => {
                vec![FragilityFactor::SingleMaintainer]
            }
            _ => vec![FragilityFactor::SingleMaintainer],
        };
        let finding = SpofFinding::new(
            SpofKind::SingleMaintainer {
                downstream_count: count_u32,
            },
            severity,
            sole_packages,
            mnt_id.clone(),
            factors,
            vec![
                "add co-maintainer".to_string(),
                "publish key-recovery procedure".to_string(),
            ],
        )?;
        push_bounded(out, finding, MAX_SPOF_FINDINGS);
    }
    Ok(())
}

/// Detector 2 -- key-person SPOFs.
///
/// A maintainer is flagged when their `total_downloads_per_month` share of
/// the global maintainer-download total exceeds `config.key_person_threshold`.
fn find_key_person_spofs(
    maintainers: &BTreeMap<String, MaintainerProfile>,
    config: &SpofDetectorConfig,
    out: &mut Vec<SpofFinding>,
) -> Result<()> {
    let mut total_downloads: u128 = 0;
    for m in maintainers.values() {
        total_downloads = total_downloads.saturating_add(m.total_downloads_per_month as u128);
    }
    if total_downloads == 0 {
        return Ok(());
    }

    let total_f = total_downloads as f64;
    if !total_f.is_finite() || total_f <= 0.0 {
        return Err(SpofError::NonFiniteValue {
            field: "total_downloads",
        });
    }

    for (mnt_id, profile) in maintainers {
        let share = (profile.total_downloads_per_month as f64) / total_f;
        if !share.is_finite() {
            continue;
        }
        if share < config.key_person_threshold {
            continue;
        }
        let severity = share.clamp(0.0, 1.0);
        let finding = SpofFinding::new(
            SpofKind::KeyPerson {
                share_of_downloads: share.clamp(0.0, 1.0),
            },
            severity,
            profile.packages_owned.clone(),
            mnt_id.clone(),
            vec![FragilityFactor::ConcentratedDownloads { share: severity }],
            vec![
                "distribute critical packages across multiple maintainers".to_string(),
                "establish key-rotation policy".to_string(),
            ],
        )?;
        push_bounded(out, finding, MAX_SPOF_FINDINGS);
    }
    Ok(())
}

/// Detector 3 -- dependency-chain SPOFs.
///
/// A "fragile package" is one whose sole maintainer is fragile (bus-factor
/// <= 1 OR no key-recovery setup). A chain SPOF is any `Depends` path of
/// fragile packages whose length reaches `config.max_chain_length`.
///
/// Implementation: BFS rooted at every fragile package, bounded by
/// `MAX_BFS_NODES` and pruned at `config.max_chain_length` so total work is
/// O(V * max_chain_length).
fn find_dependency_chain_spofs(
    maintainers: &BTreeMap<String, MaintainerProfile>,
    nodes: &[GraphNode],
    edges: &[GraphEdge],
    config: &SpofDetectorConfig,
    out: &mut Vec<SpofFinding>,
) -> Result<()> {
    let (_, by_package) = index_maintained_by(edges);
    let depends = index_depends(edges);

    // Pre-compute the set of fragile packages.
    let mut fragile_packages: BTreeSet<NodeId> = BTreeSet::new();
    for n in nodes.iter().filter(|n| n.kind == NodeKind::Package) {
        if is_package_fragile(&n.id, &by_package, maintainers) {
            fragile_packages.insert(n.id.clone());
        }
    }
    if fragile_packages.is_empty() {
        return Ok(());
    }

    let max_len = config.max_chain_length as usize;
    let mut emitted_chains: BTreeSet<Vec<NodeId>> = BTreeSet::new();

    for start in &fragile_packages {
        // BFS: state = (current_node, path). path is bounded by max_len.
        let mut frontier: VecDeque<Vec<NodeId>> = VecDeque::new();
        frontier.push_back(vec![start.clone()]);

        let mut visited: BTreeSet<NodeId> = BTreeSet::new();
        visited.insert(start.clone());

        while let Some(path) = frontier.pop_front() {
            if visited.len() >= MAX_BFS_NODES {
                break;
            }
            if path.len() >= max_len {
                // Emit a chain finding at the configured length boundary.
                let canonical = path.clone();
                if emitted_chains.insert(canonical.clone()) {
                    let chain_len_u32 = u32::try_from(path.len()).unwrap_or(u32::MAX);
                    // Severity scales with chain length, capped at 1.0.
                    let severity = (path.len() as f64 / max_len as f64).clamp(0.0, 1.0);
                    let finding = SpofFinding::new(
                        SpofKind::DependencyChain {
                            chain_length: chain_len_u32,
                            chain: path.clone(),
                        },
                        severity,
                        path.clone(),
                        start.clone(),
                        vec![FragilityFactor::SingleMaintainer],
                        vec![
                            "break the fragile chain by sponsoring an intermediate maintainer"
                                .to_string(),
                            "vendor the leaf dependency to reduce blast radius".to_string(),
                        ],
                    )?;
                    push_bounded(out, finding, MAX_SPOF_FINDINGS);
                }
                continue;
            }

            let last = path.last().cloned().unwrap_or_default();
            if let Some(next_hops) = depends.get(&last) {
                for nxt in next_hops {
                    if !fragile_packages.contains(nxt) {
                        continue;
                    }
                    if path.contains(nxt) {
                        // Avoid cycles -- BFS visit-once on the path.
                        continue;
                    }
                    if visited.len() >= MAX_BFS_NODES {
                        break;
                    }
                    visited.insert(nxt.clone());
                    let mut next_path = path.clone();
                    next_path.push(nxt.clone());
                    frontier.push_back(next_path);
                }
            }
        }
    }
    Ok(())
}

/// A package is fragile when its sole maintainer profile is itself fragile.
fn is_package_fragile(
    pkg: &NodeId,
    by_package: &BTreeMap<NodeId, Vec<String>>,
    maintainers: &BTreeMap<String, MaintainerProfile>,
) -> bool {
    let mnt_ids = match by_package.get(pkg) {
        Some(v) if v.len() == 1 => v,
        _ => return false,
    };
    let mnt_id = match mnt_ids.first() {
        Some(id) => id,
        None => return false,
    };
    let profile = match maintainers.get(mnt_id) {
        Some(p) => p,
        None => return true, // unknown maintainer == treat as fragile
    };
    profile.bus_factor <= SOLE_MAINTAINER_BUS_FACTOR || !profile.key_recovery_setup
}

/// Detector 4 -- organisation concentration SPOFs.
///
/// `org_id` is taken from `PublisherProfile::org_id`. The share is the
/// fraction of distinct namespace nodes whose `metadata["org"]` matches that
/// org_id, or (fallback) the fraction of all packages owned by publishers
/// with that org_id when no Namespace nodes exist.
fn find_org_concentration_spofs(
    publishers: &BTreeMap<String, PublisherProfile>,
    nodes: &[GraphNode],
    config: &SpofDetectorConfig,
    out: &mut Vec<SpofFinding>,
) -> Result<()> {
    // Count namespaces grouped by org (preferred).
    let mut ns_by_org: BTreeMap<String, u32> = BTreeMap::new();
    let mut total_namespaces: u32 = 0;
    for n in nodes.iter().filter(|n| n.kind == NodeKind::Namespace) {
        total_namespaces = total_namespaces.saturating_add(1);
        if let Some(org) = n.metadata.get("org") {
            let counter = ns_by_org.entry(org.clone()).or_insert(0);
            *counter = counter.saturating_add(1);
        }
    }

    if total_namespaces > 0 {
        let total_f = total_namespaces as f64;
        for (org, count) in &ns_by_org {
            let share = (*count as f64) / total_f;
            if !share.is_finite() || share < config.org_concentration_threshold {
                continue;
            }
            emit_org_finding(org, share, publishers, out)?;
        }
        return Ok(());
    }

    // Fallback: aggregate by publisher.org_id share of packages_published.
    let mut pkgs_by_org: BTreeMap<String, u32> = BTreeMap::new();
    let mut total_pkgs: u32 = 0;
    for p in publishers.values() {
        let n = u32::try_from(p.packages_published.len()).unwrap_or(u32::MAX);
        total_pkgs = total_pkgs.saturating_add(n);
        if let Some(org) = &p.org_id {
            let counter = pkgs_by_org.entry(org.clone()).or_insert(0);
            *counter = counter.saturating_add(n);
        }
    }
    if total_pkgs == 0 {
        return Ok(());
    }
    let total_f = total_pkgs as f64;
    if !total_f.is_finite() || total_f <= 0.0 {
        return Ok(());
    }
    for (org, count) in &pkgs_by_org {
        let share = (*count as f64) / total_f;
        if !share.is_finite() || share < config.org_concentration_threshold {
            continue;
        }
        emit_org_finding(org, share, publishers, out)?;
    }
    Ok(())
}

fn emit_org_finding(
    org: &str,
    share: f64,
    publishers: &BTreeMap<String, PublisherProfile>,
    out: &mut Vec<SpofFinding>,
) -> Result<()> {
    let affected: Vec<NodeId> = publishers
        .values()
        .filter(|p| p.org_id.as_deref() == Some(org))
        .flat_map(|p| p.packages_published.iter().cloned())
        .collect();
    let severity = share.clamp(0.0, 1.0);
    let finding = SpofFinding::new(
        SpofKind::OrgConcentration {
            org_id: org.to_string(),
            share: severity,
        },
        severity,
        affected,
        org.to_string(),
        vec![FragilityFactor::ConcentratedDownloads { share: severity }],
        vec![
            "diversify namespace ownership across organisations".to_string(),
            "publish org-level continuity policy".to_string(),
        ],
    )?;
    push_bounded(out, finding, MAX_SPOF_FINDINGS);
    Ok(())
}

/// Detector 5 -- orphaned-package SPOFs.
///
/// A package is orphaned when its sole maintainer's `last_commit_ts` is
/// older than `config.orphan_threshold_days`. The day count uses
/// `saturating_sub` so future timestamps fail closed (zero days).
fn find_orphaned_package_spofs(
    maintainers: &BTreeMap<String, MaintainerProfile>,
    edges: &[GraphEdge],
    config: &SpofDetectorConfig,
    now: i64,
    out: &mut Vec<SpofFinding>,
) -> Result<()> {
    let (_, by_package) = index_maintained_by(edges);
    for (pkg, mnt_ids) in &by_package {
        if mnt_ids.len() != 1 {
            continue;
        }
        let mnt_id = match mnt_ids.first() {
            Some(id) => id,
            None => continue,
        };
        let profile = match maintainers.get(mnt_id) {
            Some(p) => p,
            None => continue,
        };
        let last_commit = match profile.last_commit_ts {
            Some(ts) => ts,
            None => continue,
        };
        let delta_secs = now.saturating_sub(last_commit);
        let days_u64 = if delta_secs > 0 {
            (delta_secs as u64) / 86_400
        } else {
            0
        };
        let days = u32::try_from(days_u64).unwrap_or(u32::MAX);
        if days <= config.orphan_threshold_days {
            continue;
        }
        // Severity: linear from threshold to 4x threshold, capped at 1.0.
        let denom = (config.orphan_threshold_days as f64).max(1.0) * 4.0;
        let severity = ((days as f64) / denom).clamp(0.0, 1.0);
        let finding = SpofFinding::new(
            SpofKind::OrphanedPackage {
                last_activity_days: days,
            },
            severity,
            vec![pkg.clone()],
            pkg.clone(),
            vec![
                FragilityFactor::OrphanedPackage,
                FragilityFactor::StaleMaintainer {
                    staleness_days: days,
                },
            ],
            vec![
                "adopt the package under a foundation".to_string(),
                "fork to a maintained alternative".to_string(),
            ],
        )?;
        push_bounded(out, finding, MAX_SPOF_FINDINGS);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dgis::graph_ingestion::{EdgeKind, GraphEdge, GraphNode, NodeKind};

    fn mk_maintainer(
        id: &str,
        packages: &[&str],
        downloads: u64,
        bus: u8,
        recovery: bool,
        last_commit: Option<i64>,
    ) -> MaintainerProfile {
        MaintainerProfile {
            id: id.to_string(),
            packages_owned: packages.iter().map(|s| s.to_string()).collect(),
            total_downloads_per_month: downloads,
            key_recovery_setup: recovery,
            active_since: 1_000_000_000,
            last_commit_ts: last_commit,
            bus_factor: bus,
        }
    }

    fn mk_pkg(id: &str) -> GraphNode {
        GraphNode::new(id, NodeKind::Package)
    }

    fn mk_ns(id: &str, org: &str) -> GraphNode {
        GraphNode::new(id, NodeKind::Namespace).with_metadata("org", org)
    }

    fn mk_edge(from: &str, to: &str, kind: EdgeKind) -> GraphEdge {
        GraphEdge::new(from, to, kind, 1.0, 1_700_000_000).expect("finite weight")
    }

    fn cfg_default() -> SpofDetectorConfig {
        SpofDetectorConfig::default()
    }

    #[test]
    fn detect_single_maintainer_spof_finds_bus_factor_one() {
        // alice sole-maintains 4 packages with bus_factor=1.
        let mut maintainers = BTreeMap::new();
        maintainers.insert(
            "alice".to_string(),
            mk_maintainer(
                "alice",
                &["a", "b", "c", "d"],
                10,
                1,
                false,
                Some(1_700_000_000),
            ),
        );
        let nodes = vec![mk_pkg("a"), mk_pkg("b"), mk_pkg("c"), mk_pkg("d")];
        let edges = vec![
            mk_edge("a", "alice", EdgeKind::MaintainedBy),
            mk_edge("b", "alice", EdgeKind::MaintainedBy),
            mk_edge("c", "alice", EdgeKind::MaintainedBy),
            mk_edge("d", "alice", EdgeKind::MaintainedBy),
        ];
        let report = detect_spofs(
            &maintainers,
            &BTreeMap::new(),
            &nodes,
            &edges,
            &cfg_default(),
            1_800_000_000,
        )
        .expect("detect");
        let any_sm = report
            .spofs
            .iter()
            .any(|f| matches!(f.kind, SpofKind::SingleMaintainer { downstream_count } if downstream_count == 4));
        assert!(
            any_sm,
            "expected SingleMaintainer with downstream_count=4, got {:?}",
            report.spofs
        );
    }

    #[test]
    fn detect_single_maintainer_ignores_well_distributed() {
        // Each package has two maintainers, and alice only sole-maintains 1.
        let mut maintainers = BTreeMap::new();
        maintainers.insert(
            "alice".to_string(),
            mk_maintainer("alice", &["a", "b"], 100, 5, true, Some(1_700_000_000)),
        );
        maintainers.insert(
            "bob".to_string(),
            mk_maintainer("bob", &["a", "b"], 100, 5, true, Some(1_700_000_000)),
        );
        let nodes = vec![mk_pkg("a"), mk_pkg("b")];
        let edges = vec![
            mk_edge("a", "alice", EdgeKind::MaintainedBy),
            mk_edge("a", "bob", EdgeKind::MaintainedBy),
            mk_edge("b", "alice", EdgeKind::MaintainedBy),
            mk_edge("b", "bob", EdgeKind::MaintainedBy),
        ];
        let report = detect_spofs(
            &maintainers,
            &BTreeMap::new(),
            &nodes,
            &edges,
            &cfg_default(),
            1_800_000_000,
        )
        .expect("detect");
        let any_sm = report
            .spofs
            .iter()
            .any(|f| matches!(f.kind, SpofKind::SingleMaintainer { .. }));
        assert!(
            !any_sm,
            "no single-maintainer SPOFs expected, got {:?}",
            report.spofs
        );
    }

    #[test]
    fn detect_key_person_above_threshold() {
        // alice owns 95% of total downloads -> key person.
        let mut maintainers = BTreeMap::new();
        maintainers.insert(
            "alice".to_string(),
            mk_maintainer("alice", &["a"], 950_000, 5, true, Some(1_700_000_000)),
        );
        maintainers.insert(
            "bob".to_string(),
            mk_maintainer("bob", &["b"], 50_000, 5, true, Some(1_700_000_000)),
        );
        let nodes = vec![mk_pkg("a"), mk_pkg("b")];
        let edges = vec![
            mk_edge("a", "alice", EdgeKind::MaintainedBy),
            mk_edge("b", "bob", EdgeKind::MaintainedBy),
        ];
        let report = detect_spofs(
            &maintainers,
            &BTreeMap::new(),
            &nodes,
            &edges,
            &cfg_default(),
            1_800_000_000,
        )
        .expect("detect");
        let kp = report.spofs.iter().find_map(|f| match &f.kind {
            SpofKind::KeyPerson { share_of_downloads } => Some(*share_of_downloads),
            _ => None,
        });
        assert!(
            kp.is_some(),
            "expected KeyPerson SPOF, got {:?}",
            report.spofs
        );
        let share = kp.unwrap();
        assert!(share.is_finite() && (0.0..=1.0).contains(&share));
        assert!(share > 0.9);
    }

    #[test]
    fn detect_key_person_below_threshold_not_flagged() {
        // alice owns 8% of total downloads, below the 10% default threshold.
        let mut maintainers = BTreeMap::new();
        maintainers.insert(
            "alice".to_string(),
            mk_maintainer("alice", &["a"], 80, 5, true, Some(1_700_000_000)),
        );
        maintainers.insert(
            "bob".to_string(),
            mk_maintainer("bob", &["b"], 920, 5, true, Some(1_700_000_000)),
        );
        // bob will be flagged but alice will not.
        let report = detect_spofs(
            &maintainers,
            &BTreeMap::new(),
            &[],
            &[],
            &cfg_default(),
            1_800_000_000,
        )
        .expect("detect");
        let alice_flagged = report
            .spofs
            .iter()
            .any(|f| f.root_cause_node == "alice" && matches!(f.kind, SpofKind::KeyPerson { .. }));
        assert!(!alice_flagged, "alice below threshold must not be flagged");
    }

    #[test]
    fn detect_dependency_chain_finds_long_fragile_chain() {
        // Chain: a -> b -> c -> d, each sole-maintained by a fragile maintainer.
        let mut maintainers = BTreeMap::new();
        for who in ["m_a", "m_b", "m_c", "m_d"] {
            maintainers.insert(
                who.to_string(),
                mk_maintainer(who, &[], 1, 1, false, Some(1_700_000_000)),
            );
        }
        let nodes = vec![mk_pkg("a"), mk_pkg("b"), mk_pkg("c"), mk_pkg("d")];
        let edges = vec![
            mk_edge("a", "m_a", EdgeKind::MaintainedBy),
            mk_edge("b", "m_b", EdgeKind::MaintainedBy),
            mk_edge("c", "m_c", EdgeKind::MaintainedBy),
            mk_edge("d", "m_d", EdgeKind::MaintainedBy),
            mk_edge("a", "b", EdgeKind::Depends),
            mk_edge("b", "c", EdgeKind::Depends),
            mk_edge("c", "d", EdgeKind::Depends),
        ];
        let cfg = SpofDetectorConfig {
            max_chain_length: 4,
            ..Default::default()
        };
        let report = detect_spofs(
            &maintainers,
            &BTreeMap::new(),
            &nodes,
            &edges,
            &cfg,
            1_800_000_000,
        )
        .expect("detect");
        let chain = report.spofs.iter().find_map(|f| match &f.kind {
            SpofKind::DependencyChain {
                chain_length,
                chain,
            } => Some((*chain_length, chain.clone())),
            _ => None,
        });
        let (len, ch) = chain.expect("expected DependencyChain SPOF");
        assert_eq!(len, 4);
        assert_eq!(
            ch,
            vec![
                "a".to_string(),
                "b".to_string(),
                "c".to_string(),
                "d".to_string()
            ]
        );
    }

    #[test]
    fn detect_dependency_chain_respects_max_length() {
        // Same chain but max_chain_length=2 -> findings start emitting at len 2.
        let mut maintainers = BTreeMap::new();
        for who in ["m_a", "m_b", "m_c"] {
            maintainers.insert(
                who.to_string(),
                mk_maintainer(who, &[], 1, 1, false, Some(1_700_000_000)),
            );
        }
        let nodes = vec![mk_pkg("a"), mk_pkg("b"), mk_pkg("c")];
        let edges = vec![
            mk_edge("a", "m_a", EdgeKind::MaintainedBy),
            mk_edge("b", "m_b", EdgeKind::MaintainedBy),
            mk_edge("c", "m_c", EdgeKind::MaintainedBy),
            mk_edge("a", "b", EdgeKind::Depends),
            mk_edge("b", "c", EdgeKind::Depends),
        ];
        let cfg = SpofDetectorConfig {
            max_chain_length: 2,
            ..Default::default()
        };
        let report = detect_spofs(
            &maintainers,
            &BTreeMap::new(),
            &nodes,
            &edges,
            &cfg,
            1_800_000_000,
        )
        .expect("detect");
        // Every emitted chain must have length exactly 2 (the cap).
        let mut found_any = false;
        for f in &report.spofs {
            if let SpofKind::DependencyChain { chain_length, .. } = &f.kind {
                assert_eq!(*chain_length, 2, "max_chain_length=2 caps chain emission");
                found_any = true;
            }
        }
        assert!(found_any, "expected at least one chain finding");
    }

    #[test]
    fn detect_org_concentration_above_threshold() {
        // acme owns 4 out of 5 namespaces => 80% > 30% default.
        let nodes = vec![
            mk_ns("ns-1", "acme"),
            mk_ns("ns-2", "acme"),
            mk_ns("ns-3", "acme"),
            mk_ns("ns-4", "acme"),
            mk_ns("ns-5", "other"),
        ];
        let mut publishers = BTreeMap::new();
        publishers.insert(
            "pub-acme".to_string(),
            PublisherProfile {
                id: "pub-acme".to_string(),
                org_id: Some("acme".to_string()),
                packages_published: vec!["a".to_string(), "b".to_string()],
                signature_keys_count: 1,
                key_rotation_policy: None,
                recovery_quorum: None,
            },
        );
        let report = detect_spofs(
            &BTreeMap::new(),
            &publishers,
            &nodes,
            &[],
            &cfg_default(),
            1_800_000_000,
        )
        .expect("detect");
        let oc = report.spofs.iter().find_map(|f| match &f.kind {
            SpofKind::OrgConcentration { org_id, share } => Some((org_id.clone(), *share)),
            _ => None,
        });
        let (org, share) = oc.expect("expected OrgConcentration");
        assert_eq!(org, "acme");
        assert!(share.is_finite() && share > 0.7);
    }

    #[test]
    fn detect_orphaned_package_after_threshold_days() {
        // last_commit ~ 500 days before now > 365-day threshold.
        let now = 1_800_000_000_i64;
        let last_commit = now - 500 * 86_400;
        let mut maintainers = BTreeMap::new();
        maintainers.insert(
            "alice".to_string(),
            mk_maintainer("alice", &["a"], 100, 1, false, Some(last_commit)),
        );
        let nodes = vec![mk_pkg("a")];
        let edges = vec![mk_edge("a", "alice", EdgeKind::MaintainedBy)];
        let report = detect_spofs(
            &maintainers,
            &BTreeMap::new(),
            &nodes,
            &edges,
            &cfg_default(),
            now,
        )
        .expect("detect");
        let orph = report.spofs.iter().find_map(|f| match &f.kind {
            SpofKind::OrphanedPackage { last_activity_days } => Some(*last_activity_days),
            _ => None,
        });
        assert_eq!(orph, Some(500));
    }

    #[test]
    fn detect_orphan_handles_clock_skew_via_saturating_sub() {
        // last_commit > now: saturating_sub yields 0 days -> no orphan finding.
        let now = 1_800_000_000_i64;
        let mut maintainers = BTreeMap::new();
        maintainers.insert(
            "alice".to_string(),
            mk_maintainer("alice", &["a"], 100, 5, true, Some(now + 1000)),
        );
        let nodes = vec![mk_pkg("a")];
        let edges = vec![mk_edge("a", "alice", EdgeKind::MaintainedBy)];
        let report = detect_spofs(
            &maintainers,
            &BTreeMap::new(),
            &nodes,
            &edges,
            &cfg_default(),
            now,
        )
        .expect("detect");
        let any_orph = report
            .spofs
            .iter()
            .any(|f| matches!(f.kind, SpofKind::OrphanedPackage { .. }));
        assert!(!any_orph, "future commit must not flag orphan");
    }

    #[test]
    fn severity_clamped_to_unit_interval() {
        // Build a pathological maintainer with massive sole-maintained packages.
        let mut packages: Vec<String> = Vec::new();
        for i in 0..50 {
            packages.push(format!("p{i}"));
        }
        let mut maintainers = BTreeMap::new();
        maintainers.insert(
            "alice".to_string(),
            mk_maintainer(
                "alice",
                &packages.iter().map(|s| s.as_str()).collect::<Vec<_>>(),
                u64::MAX / 2,
                1,
                false,
                Some(1_700_000_000),
            ),
        );
        let nodes: Vec<GraphNode> = packages.iter().map(|p| mk_pkg(p)).collect();
        let edges: Vec<GraphEdge> = packages
            .iter()
            .map(|p| mk_edge(p, "alice", EdgeKind::MaintainedBy))
            .collect();
        let report = detect_spofs(
            &maintainers,
            &BTreeMap::new(),
            &nodes,
            &edges,
            &cfg_default(),
            1_800_000_000,
        )
        .expect("detect");
        assert!(!report.spofs.is_empty());
        for f in &report.spofs {
            assert!(
                f.severity.is_finite(),
                "severity non-finite: {}",
                f.severity
            );
            assert!(
                (0.0..=1.0).contains(&f.severity),
                "severity out of unit interval: {}",
                f.severity
            );
        }
    }

    #[test]
    fn bounded_growth_caps_findings_at_max() {
        // Build a scenario with MAX_SPOF_FINDINGS + 10 single-maintainer SPOFs.
        let mut maintainers = BTreeMap::new();
        let mut nodes: Vec<GraphNode> = Vec::new();
        let mut edges: Vec<GraphEdge> = Vec::new();
        let n_maintainers = MAX_SPOF_FINDINGS + 10;
        for i in 0..n_maintainers {
            let mnt_id = format!("m{i}");
            // Each maintainer sole-maintains 3 packages (meets default threshold).
            let p1 = format!("p{i}_1");
            let p2 = format!("p{i}_2");
            let p3 = format!("p{i}_3");
            maintainers.insert(
                mnt_id.clone(),
                mk_maintainer(&mnt_id, &[&p1, &p2, &p3], 1, 1, false, Some(1_700_000_000)),
            );
            nodes.push(mk_pkg(&p1));
            nodes.push(mk_pkg(&p2));
            nodes.push(mk_pkg(&p3));
            edges.push(mk_edge(&p1, &mnt_id, EdgeKind::MaintainedBy));
            edges.push(mk_edge(&p2, &mnt_id, EdgeKind::MaintainedBy));
            edges.push(mk_edge(&p3, &mnt_id, EdgeKind::MaintainedBy));
        }
        let report = detect_spofs(
            &maintainers,
            &BTreeMap::new(),
            &nodes,
            &edges,
            &cfg_default(),
            1_800_000_000,
        )
        .expect("detect");
        assert!(
            report.spofs.len() <= MAX_SPOF_FINDINGS,
            "findings exceeded MAX_SPOF_FINDINGS: got {}",
            report.spofs.len()
        );
    }

    #[test]
    fn nan_threshold_rejected_in_config() {
        let cfg = SpofDetectorConfig {
            key_person_threshold: f64::NAN,
            ..Default::default()
        };
        let err = detect_spofs(
            &BTreeMap::new(),
            &BTreeMap::new(),
            &[],
            &[],
            &cfg,
            1_800_000_000,
        )
        .expect_err("NaN threshold must reject");
        match err {
            SpofError::InvalidConfig { field, .. } => assert_eq!(field, "key_person_threshold"),
            other => panic!("expected InvalidConfig, got {other:?}"),
        }

        let cfg = SpofDetectorConfig {
            org_concentration_threshold: f64::INFINITY,
            ..Default::default()
        };
        let err = detect_spofs(
            &BTreeMap::new(),
            &BTreeMap::new(),
            &[],
            &[],
            &cfg,
            1_800_000_000,
        )
        .expect_err("infinity threshold must reject");
        match err {
            SpofError::InvalidConfig { field, .. } => {
                assert_eq!(field, "org_concentration_threshold")
            }
            other => panic!("expected InvalidConfig, got {other:?}"),
        }
    }

    #[test]
    fn spof_finding_serde_round_trip() {
        let f = SpofFinding::new(
            SpofKind::SingleMaintainer {
                downstream_count: 7,
            },
            0.42,
            vec!["a".into(), "b".into()],
            "alice".into(),
            vec![FragilityFactor::SingleMaintainer],
            vec!["mitigation".into()],
        )
        .expect("ok");
        let json = serde_json::to_string(&f).expect("serialise");
        let back: SpofFinding = serde_json::from_str(&json).expect("deserialise");
        assert_eq!(f, back);
    }

    #[test]
    fn spof_report_serde_round_trip() {
        let r = SpofReport {
            spofs: vec![],
            evaluated_packages: 7,
            evaluated_at: 1_700_000_000,
        };
        let json = serde_json::to_string(&r).expect("serialise");
        let back: SpofReport = serde_json::from_str(&json).expect("deserialise");
        assert_eq!(r, back);
    }

    #[test]
    fn spof_kind_labels_are_stable() {
        assert_eq!(
            SpofKind::SingleMaintainer {
                downstream_count: 1
            }
            .label(),
            "single_maintainer"
        );
        assert_eq!(
            SpofKind::KeyPerson {
                share_of_downloads: 0.5
            }
            .label(),
            "key_person"
        );
        assert_eq!(
            SpofKind::DependencyChain {
                chain_length: 2,
                chain: vec!["a".into(), "b".into()]
            }
            .label(),
            "dependency_chain"
        );
        assert_eq!(
            SpofKind::OrgConcentration {
                org_id: "acme".into(),
                share: 0.5,
            }
            .label(),
            "org_concentration"
        );
        assert_eq!(
            SpofKind::OrphanedPackage {
                last_activity_days: 1,
            }
            .label(),
            "orphaned_package"
        );
    }

    #[test]
    fn finding_constructor_rejects_non_finite_severity() {
        let err = SpofFinding::new(
            SpofKind::SingleMaintainer {
                downstream_count: 1,
            },
            f64::NAN,
            vec![],
            "x".into(),
            vec![],
            vec![],
        )
        .expect_err("NaN severity rejected");
        assert_eq!(err, SpofError::NonFiniteValue { field: "severity" });
    }

    #[test]
    fn finding_constructor_clamps_out_of_range_severity() {
        let f = SpofFinding::new(
            SpofKind::SingleMaintainer {
                downstream_count: 1,
            },
            5.0,
            vec![],
            "x".into(),
            vec![],
            vec![],
        )
        .expect("ok");
        assert_eq!(f.severity, 1.0);
        let f = SpofFinding::new(
            SpofKind::SingleMaintainer {
                downstream_count: 1,
            },
            -2.0,
            vec![],
            "x".into(),
            vec![],
            vec![],
        )
        .expect("ok");
        assert_eq!(f.severity, 0.0);
    }
}
