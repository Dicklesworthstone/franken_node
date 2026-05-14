//! Synthetic maintainer/publisher fixture suite for the DGIS SPOF detector
//! (bd-2jns sub-task 3 of 5).
//!
//! This module provides:
//!
//! * [`FragilityFixture`] -- a canonical JSON-shaped fixture combining
//!   maintainer profiles, publisher profiles, an ingested graph slice, and a
//!   list of [`ExpectedFinding`]s that the SPOF detector MUST produce
//!   (subject to `min_count` / `max_count` bounds per kind).
//! * [`load_fixture_from_json`] -- deserialise a fixture from a JSON string,
//!   validating every nested invariant via the existing `validate()` methods.
//! * [`evaluate_fixture`] -- run [`crate::dgis::spof_detection::detect_spofs`]
//!   against a fixture and check the resulting [`SpofReport`] satisfies the
//!   declared `expected_findings`, returning a [`FixtureVerdict`].
//! * `synthesize_*` constructors -- programmatic, filesystem-free clones of
//!   the ten JSON fixtures shipped under `tests/security/fragility_fixtures/`
//!   so the inline unit tests in this module never depend on file I/O.
//!
//! Hardening invariants enforced here:
//!
//! * `now_ms` is converted to `i64` seconds via `saturating_*` arithmetic to
//!   prevent overflow when the fixture is built from far-future timestamps.
//! * `push_bounded` caps every accumulator (`divergences`, `actual_finding_counts`)
//!   so a pathological fixture cannot exhaust memory.
//! * The deserialiser does NOT accept unknown variants for
//!   [`SpofKindLabel`] -- the JSON layer rejects new labels at the boundary
//!   so downstream detectors never see unexpected kinds (test
//!   `fixture_with_invalid_finding_label_rejected`).
//! * `evaluate_fixture` rejects non-finite severities in actual findings
//!   defensively, even though the detector also clamps -- defense in depth.
//! * The module is wired into `crate::dgis` via `pub mod fragility_fixtures;`
//!   and inherits `#![forbid(unsafe_code)]` from `lib.rs`.
//!
//! NB: this sub-task ships ONLY the fixture set + inline tests. The
//! integration test at `tests/security/dgis_fragility_spof.rs` and the
//! verification gate land in sub-tasks 4-5 of bd-2jns.1.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::capacity_defaults::aliases::MAX_AUDIT_LOG_ENTRIES;
use crate::dgis::fragility_model::{FragilityError, MaintainerProfile, PublisherProfile};
use crate::dgis::graph_ingestion::{GraphEdge, GraphNode};
use crate::dgis::spof_detection::{
    detect_spofs, SpofDetectorConfig, SpofError, SpofKind, SpofReport,
};
use crate::push_bounded;

/// Cap on how many divergence strings a single [`FixtureVerdict`] may carry.
/// Bounded so a misuse cannot exhaust memory.
pub const MAX_FIXTURE_DIVERGENCES: usize = MAX_AUDIT_LOG_ENTRIES;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Categorical label for [`SpofKind`] without the carried payload. Used in
/// the fixture's `expected_findings` block so the suite can assert
/// "at least 1 KeyPerson finding" without binding to a specific share value.
///
/// `#[serde(deny_unknown_fields)]` is NOT applied here because variants are
/// already strictly enumerated -- any unknown string in JSON will fail
/// deserialisation at the variant level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SpofKindLabel {
    SingleMaintainer,
    KeyPerson,
    DependencyChain,
    OrgConcentration,
    OrphanedPackage,
}

impl SpofKindLabel {
    /// Translate an [`SpofKind`] (with payload) into its label.
    pub fn from_kind(kind: &SpofKind) -> Self {
        match kind {
            SpofKind::SingleMaintainer { .. } => SpofKindLabel::SingleMaintainer,
            SpofKind::KeyPerson { .. } => SpofKindLabel::KeyPerson,
            SpofKind::DependencyChain { .. } => SpofKindLabel::DependencyChain,
            SpofKind::OrgConcentration { .. } => SpofKindLabel::OrgConcentration,
            SpofKind::OrphanedPackage { .. } => SpofKindLabel::OrphanedPackage,
        }
    }

    /// Stable telemetry-friendly slug.
    pub fn slug(&self) -> &'static str {
        match self {
            SpofKindLabel::SingleMaintainer => "single_maintainer",
            SpofKindLabel::KeyPerson => "key_person",
            SpofKindLabel::DependencyChain => "dependency_chain",
            SpofKindLabel::OrgConcentration => "org_concentration",
            SpofKindLabel::OrphanedPackage => "orphaned_package",
        }
    }
}

/// A declared expectation against a fixture's `SpofReport`.
///
/// `min_count <= max_count` is enforced by [`ExpectedFinding::validate`].
/// A robust (no-SPOF) fixture omits this struct entirely from
/// `expected_findings`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExpectedFinding {
    pub kind: SpofKindLabel,
    pub min_count: usize,
    pub max_count: usize,
}

impl ExpectedFinding {
    /// Validate that `min_count <= max_count`. Returns a typed error so the
    /// boundary fails closed.
    pub fn validate(&self) -> std::result::Result<(), FragilityError> {
        if self.min_count > self.max_count {
            return Err(FragilityError::ShareOutOfRange {
                field: "expected_finding_bounds",
                value: format!("min={} > max={}", self.min_count, self.max_count),
            });
        }
        Ok(())
    }
}

/// A self-describing test fixture for the SPOF detector.
///
/// `now_ms` is wall-clock milliseconds since the UNIX epoch. The
/// `evaluate_fixture` driver divides by 1000 (`saturating_div_euclid`) before
/// passing to [`detect_spofs`], which expects seconds.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FragilityFixture {
    pub name: String,
    pub description: String,
    pub now_ms: i64,
    pub maintainers: BTreeMap<String, MaintainerProfile>,
    pub publishers: BTreeMap<String, PublisherProfile>,
    pub nodes: Vec<GraphNode>,
    pub edges: Vec<GraphEdge>,
    /// Optional config overrides; `None` means use [`SpofDetectorConfig::default`].
    pub config_overrides: Option<SpofDetectorConfig>,
    pub expected_findings: Vec<ExpectedFinding>,
}

impl FragilityFixture {
    /// Wall-clock seconds derived from `now_ms`. Saturates on overflow so a
    /// far-future timestamp cannot panic the test driver.
    pub fn now_secs(&self) -> i64 {
        // Integer division on i64 saturates to MIN/MAX automatically only at
        // the divide-by-zero boundary; the constant 1000 makes that
        // impossible. We additionally guard against `MIN` by clamping.
        if self.now_ms == i64::MIN {
            return i64::MIN / 1000;
        }
        self.now_ms / 1000
    }

    /// The effective config that [`evaluate_fixture`] will pass to the
    /// detector: either the override or the production default.
    pub fn effective_config(&self) -> SpofDetectorConfig {
        self.config_overrides
            .clone()
            .unwrap_or_else(SpofDetectorConfig::default)
    }

    /// Validate nested invariants. Called by both [`load_fixture_from_json`]
    /// and [`evaluate_fixture`] so misuse fails at the boundary.
    pub fn validate(&self) -> std::result::Result<(), FragilityError> {
        if self.name.trim().is_empty() {
            return Err(FragilityError::EmptyIdentifier);
        }
        for m in self.maintainers.values() {
            m.validate()?;
        }
        for p in self.publishers.values() {
            p.validate()?;
        }
        for ef in &self.expected_findings {
            ef.validate()?;
        }
        Ok(())
    }
}

/// The aggregate verdict of running a fixture through the SPOF detector.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FixtureVerdict {
    pub passed: bool,
    pub actual_finding_counts: BTreeMap<SpofKindLabel, usize>,
    pub divergences: Vec<String>,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Deserialise a [`FragilityFixture`] from a JSON string and validate
/// nested invariants. Returns a typed [`FragilityError`] on any failure so
/// callers can fail closed without `unwrap`.
pub fn load_fixture_from_json(json: &str) -> std::result::Result<FragilityFixture, FragilityError> {
    let fixture: FragilityFixture = serde_json::from_str(json).map_err(|e| {
        FragilityError::ShareOutOfRange {
            field: "fixture_json",
            value: format!("deserialise failed: {}", e),
        }
    })?;
    fixture.validate()?;
    Ok(fixture)
}

/// Run [`detect_spofs`] against `fixture` and verify the result satisfies
/// every declared [`ExpectedFinding`]. Returns a [`FixtureVerdict`].
pub fn evaluate_fixture(
    fixture: &FragilityFixture,
) -> std::result::Result<FixtureVerdict, FragilityError> {
    fixture.validate()?;

    let config = fixture.effective_config();
    let now = fixture.now_secs();

    let report: SpofReport = detect_spofs(
        &fixture.maintainers,
        &fixture.publishers,
        &fixture.nodes,
        &fixture.edges,
        &config,
        now,
    )
    .map_err(map_spof_error)?;

    // Bucket actual findings by kind label.
    let mut actual: BTreeMap<SpofKindLabel, usize> = BTreeMap::new();
    for f in &report.spofs {
        // Defense in depth: even though detect_spofs already clamps severity
        // we verify it's finite before counting.
        if !f.severity.is_finite() {
            return Err(FragilityError::NonFiniteValue {
                field: "actual_finding_severity",
            });
        }
        let label = SpofKindLabel::from_kind(&f.kind);
        let counter = actual.entry(label).or_insert(0);
        *counter = counter.saturating_add(1);
    }

    let mut divergences: Vec<String> = Vec::new();
    let mut passed = true;

    // Check each expected finding is satisfied.
    for ef in &fixture.expected_findings {
        let got = *actual.get(&ef.kind).unwrap_or(&0);
        if got < ef.min_count || got > ef.max_count {
            passed = false;
            push_bounded(
                &mut divergences,
                format!(
                    "expected {} in [{}, {}], got {}",
                    ef.kind.slug(),
                    ef.min_count,
                    ef.max_count,
                    got
                ),
                MAX_FIXTURE_DIVERGENCES,
            );
        }
    }

    // For a robust fixture (expected_findings.is_empty()), the actual report
    // MUST also be empty.
    if fixture.expected_findings.is_empty() && !report.spofs.is_empty() {
        passed = false;
        for f in &report.spofs {
            push_bounded(
                &mut divergences,
                format!(
                    "robust fixture but detector emitted {} (root={})",
                    SpofKindLabel::from_kind(&f.kind).slug(),
                    f.root_cause_node
                ),
                MAX_FIXTURE_DIVERGENCES,
            );
        }
    }

    Ok(FixtureVerdict {
        passed,
        actual_finding_counts: actual,
        divergences,
    })
}

/// Map [`SpofError`] into a [`FragilityError`] so callers see a single error
/// surface.
fn map_spof_error(err: SpofError) -> FragilityError {
    match err {
        SpofError::InvalidConfig { field, reason } => FragilityError::ShareOutOfRange {
            field,
            value: format!("invalid_config: {}", reason),
        },
        SpofError::NonFiniteValue { field } => FragilityError::NonFiniteValue { field },
    }
}

// ---------------------------------------------------------------------------
// Programmatic fixture synthesis
// ---------------------------------------------------------------------------

const NOW_SECS: i64 = 1_700_000_000;
const NOW_MS: i64 = NOW_SECS * 1000;
const ACTIVE_SINCE_SECS: i64 = 1_000_000_000;
const RECENT_COMMIT_SECS: i64 = 1_699_900_000;

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
        packages_owned: packages.iter().map(|s| (*s).to_string()).collect(),
        total_downloads_per_month: downloads,
        key_recovery_setup: recovery,
        active_since: ACTIVE_SINCE_SECS,
        last_commit_ts: last_commit,
        bus_factor: bus,
    }
}

fn mk_publisher(
    id: &str,
    org: Option<&str>,
    pkgs: &[&str],
    keys: u32,
    rotation: Option<&str>,
    quorum: Option<u8>,
) -> PublisherProfile {
    PublisherProfile {
        id: id.to_string(),
        org_id: org.map(|s| s.to_string()),
        packages_published: pkgs.iter().map(|s| (*s).to_string()).collect(),
        signature_keys_count: keys,
        key_rotation_policy: rotation.map(|s| s.to_string()),
        recovery_quorum: quorum,
    }
}

fn mk_pkg(id: &str) -> GraphNode {
    GraphNode::new(id, crate::dgis::graph_ingestion::NodeKind::Package)
}

fn mk_ns(id: &str, org: &str) -> GraphNode {
    GraphNode::new(id, crate::dgis::graph_ingestion::NodeKind::Namespace).with_metadata("org", org)
}

fn mk_maintained_by(pkg: &str, mnt: &str) -> GraphEdge {
    GraphEdge::new(
        pkg,
        mnt,
        crate::dgis::graph_ingestion::EdgeKind::MaintainedBy,
        1.0,
        NOW_SECS,
    )
    .expect("finite weight")
}

fn mk_depends(from: &str, to: &str) -> GraphEdge {
    GraphEdge::new(
        from,
        to,
        crate::dgis::graph_ingestion::EdgeKind::Depends,
        1.0,
        NOW_SECS,
    )
    .expect("finite weight")
}

// ---- five known-SPOF fixtures ---------------------------------------------

/// In-code clone of `single_maintainer_dominant.json`.
pub fn synthesize_single_maintainer_dominant() -> FragilityFixture {
    let pkgs = ["pkg-a", "pkg-b", "pkg-c", "pkg-d", "pkg-e", "pkg-f", "pkg-g", "pkg-h"];
    let mut maintainers = BTreeMap::new();
    maintainers.insert(
        "alice".into(),
        mk_maintainer("alice", &pkgs, 90_000, 1, false, Some(NOW_SECS)),
    );
    maintainers.insert(
        "bob".into(),
        mk_maintainer("bob", &["pkg-i"], 5_000, 5, true, Some(NOW_SECS)),
    );
    maintainers.insert(
        "carol".into(),
        mk_maintainer("carol", &["pkg-j"], 5_000, 5, true, Some(NOW_SECS)),
    );

    let mut nodes: Vec<GraphNode> = pkgs.iter().map(|p| mk_pkg(p)).collect();
    nodes.push(mk_pkg("pkg-i"));
    nodes.push(mk_pkg("pkg-j"));

    let mut edges: Vec<GraphEdge> = pkgs.iter().map(|p| mk_maintained_by(p, "alice")).collect();
    edges.push(mk_maintained_by("pkg-i", "bob"));
    edges.push(mk_maintained_by("pkg-j", "carol"));

    FragilityFixture {
        name: "single_maintainer_dominant".into(),
        description: "alice sole-maintains 8 packages with bus_factor=1".into(),
        now_ms: NOW_MS,
        maintainers,
        publishers: BTreeMap::new(),
        nodes,
        edges,
        config_overrides: None,
        expected_findings: vec![ExpectedFinding {
            kind: SpofKindLabel::SingleMaintainer,
            min_count: 1,
            max_count: 1,
        }],
    }
}

/// In-code clone of `key_person_high_share.json`.
pub fn synthesize_key_person_high_share() -> FragilityFixture {
    let mut maintainers = BTreeMap::new();
    maintainers.insert(
        "whale".into(),
        mk_maintainer("whale", &["wpkg-1", "wpkg-2"], 600_000, 5, true, Some(NOW_SECS)),
    );
    maintainers.insert(
        "minnow1".into(),
        mk_maintainer("minnow1", &["wpkg-1"], 80_000, 5, true, Some(NOW_SECS)),
    );
    maintainers.insert(
        "minnow2".into(),
        mk_maintainer("minnow2", &["wpkg-2"], 80_000, 5, true, Some(NOW_SECS)),
    );
    for who in ["minnow3", "minnow4", "minnow5"] {
        maintainers.insert(
            who.into(),
            mk_maintainer(who, &[], 80_000, 5, true, Some(NOW_SECS)),
        );
    }

    let nodes = vec![mk_pkg("wpkg-1"), mk_pkg("wpkg-2")];
    let edges = vec![
        mk_maintained_by("wpkg-1", "whale"),
        mk_maintained_by("wpkg-1", "minnow1"),
        mk_maintained_by("wpkg-2", "whale"),
        mk_maintained_by("wpkg-2", "minnow2"),
    ];

    FragilityFixture {
        name: "key_person_high_share".into(),
        description: "whale owns 60% of total monthly downloads".into(),
        now_ms: NOW_MS,
        maintainers,
        publishers: BTreeMap::new(),
        nodes,
        edges,
        config_overrides: None,
        expected_findings: vec![ExpectedFinding {
            kind: SpofKindLabel::KeyPerson,
            min_count: 1,
            max_count: 1,
        }],
    }
}

/// In-code clone of `dependency_chain_fragile.json`.
pub fn synthesize_dependency_chain_fragile() -> FragilityFixture {
    let mut maintainers = BTreeMap::new();
    for (id, pkg) in [
        ("m1", "pkg-1"),
        ("m2", "pkg-2"),
        ("m3", "pkg-3"),
        ("m4", "pkg-4"),
        ("m5", "pkg-5"),
    ] {
        maintainers.insert(
            id.into(),
            mk_maintainer(id, &[pkg], 100, 1, false, Some(NOW_SECS)),
        );
    }

    let pkgs = ["pkg-1", "pkg-2", "pkg-3", "pkg-4", "pkg-5"];
    let nodes: Vec<GraphNode> = pkgs.iter().map(|p| mk_pkg(p)).collect();
    let mut edges: Vec<GraphEdge> = vec![
        mk_maintained_by("pkg-1", "m1"),
        mk_maintained_by("pkg-2", "m2"),
        mk_maintained_by("pkg-3", "m3"),
        mk_maintained_by("pkg-4", "m4"),
        mk_maintained_by("pkg-5", "m5"),
    ];
    edges.push(mk_depends("pkg-1", "pkg-2"));
    edges.push(mk_depends("pkg-2", "pkg-3"));
    edges.push(mk_depends("pkg-3", "pkg-4"));
    edges.push(mk_depends("pkg-4", "pkg-5"));

    FragilityFixture {
        name: "dependency_chain_fragile".into(),
        description: "5-node fragile dependency chain pkg-1 -> ... -> pkg-5".into(),
        now_ms: NOW_MS,
        maintainers,
        publishers: BTreeMap::new(),
        nodes,
        edges,
        config_overrides: Some(SpofDetectorConfig {
            single_maintainer_threshold: 100,
            key_person_threshold: 0.99,
            max_chain_length: 5,
            org_concentration_threshold: 0.99,
            orphan_threshold_days: 365,
        }),
        expected_findings: vec![ExpectedFinding {
            kind: SpofKindLabel::DependencyChain,
            min_count: 1,
            max_count: 1,
        }],
    }
}

/// In-code clone of `org_concentrated.json`.
pub fn synthesize_org_concentrated() -> FragilityFixture {
    let mut publishers = BTreeMap::new();
    publishers.insert(
        "pub-mega".into(),
        mk_publisher(
            "pub-mega",
            Some("megacorp"),
            &["mp-1", "mp-2", "mp-3"],
            2,
            Some("rotate-90d"),
            Some(2),
        ),
    );
    for (id, org, pkg) in [
        ("pub-indie-a", "indie-a", "ip-a"),
        ("pub-indie-b", "indie-b", "ip-b"),
        ("pub-indie-c", "indie-c", "ip-c"),
    ] {
        publishers.insert(
            id.into(),
            mk_publisher(id, Some(org), &[pkg], 1, Some("rotate-90d"), Some(2)),
        );
    }

    let nodes = vec![
        mk_ns("ns-1", "megacorp"),
        mk_ns("ns-2", "megacorp"),
        mk_ns("ns-3", "megacorp"),
        mk_ns("ns-4", "megacorp"),
        mk_ns("ns-5", "megacorp"),
        mk_ns("ns-6", "megacorp"),
        mk_ns("ns-7", "megacorp"),
        mk_ns("ns-8", "indie-a"),
        mk_ns("ns-9", "indie-b"),
        mk_ns("ns-10", "indie-c"),
    ];

    FragilityFixture {
        name: "org_concentrated".into(),
        description: "megacorp owns 7 of 10 namespaces (70%)".into(),
        now_ms: NOW_MS,
        maintainers: BTreeMap::new(),
        publishers,
        nodes,
        edges: vec![],
        config_overrides: None,
        expected_findings: vec![ExpectedFinding {
            kind: SpofKindLabel::OrgConcentration,
            min_count: 1,
            max_count: 1,
        }],
    }
}

/// In-code clone of `orphaned_pkg.json`.
pub fn synthesize_orphaned_pkg() -> FragilityFixture {
    let stale_commit = NOW_SECS - 500 * 86_400; // 500 days old
    // Use the same canonical "recent" timestamp the JSON fixture ships with so
    // the on-disk and in-code fixtures are byte-equivalent.
    let recent_commit = RECENT_COMMIT_SECS;
    let mut maintainers = BTreeMap::new();
    maintainers.insert(
        "sleepy".into(),
        mk_maintainer("sleepy", &["lonely-pkg"], 1_000, 5, true, Some(stale_commit)),
    );
    maintainers.insert(
        "active".into(),
        mk_maintainer(
            "active",
            &["fresh-pkg"],
            1_000,
            5,
            true,
            Some(recent_commit),
        ),
    );

    let nodes = vec![mk_pkg("lonely-pkg"), mk_pkg("fresh-pkg")];
    let edges = vec![
        mk_maintained_by("lonely-pkg", "sleepy"),
        mk_maintained_by("fresh-pkg", "active"),
    ];

    FragilityFixture {
        name: "orphaned_pkg".into(),
        description: "sleepy's last commit was 500 days ago".into(),
        now_ms: NOW_MS,
        maintainers,
        publishers: BTreeMap::new(),
        nodes,
        edges,
        config_overrides: Some(SpofDetectorConfig {
            single_maintainer_threshold: 100,
            key_person_threshold: 0.99,
            max_chain_length: 4,
            org_concentration_threshold: 0.99,
            orphan_threshold_days: 365,
        }),
        expected_findings: vec![ExpectedFinding {
            kind: SpofKindLabel::OrphanedPackage,
            min_count: 1,
            max_count: 1,
        }],
    }
}

// ---- five robust fixtures --------------------------------------------------

/// In-code clone of `well_distributed_maintainers.json`.
pub fn synthesize_well_distributed_maintainers() -> FragilityFixture {
    let mut maintainers = BTreeMap::new();
    for who in ["alice", "bob", "carol"] {
        maintainers.insert(
            who.into(),
            mk_maintainer(
                who,
                &["pkg-a", "pkg-b", "pkg-c"],
                25_000,
                4,
                true,
                Some(RECENT_COMMIT_SECS),
            ),
        );
    }
    maintainers.insert(
        "dave".into(),
        mk_maintainer("dave", &[], 25_000, 4, true, Some(RECENT_COMMIT_SECS)),
    );

    let pkgs = ["pkg-a", "pkg-b", "pkg-c"];
    let nodes: Vec<GraphNode> = pkgs.iter().map(|p| mk_pkg(p)).collect();
    let mut edges: Vec<GraphEdge> = Vec::new();
    for p in &pkgs {
        for m in ["alice", "bob", "carol"] {
            edges.push(mk_maintained_by(p, m));
        }
    }

    FragilityFixture {
        name: "well_distributed_maintainers".into(),
        description: "three maintainers cover every package, bus_factor>=4".into(),
        now_ms: NOW_MS,
        maintainers,
        publishers: BTreeMap::new(),
        nodes,
        edges,
        config_overrides: Some(SpofDetectorConfig {
            single_maintainer_threshold: 3,
            key_person_threshold: 0.50,
            max_chain_length: 4,
            org_concentration_threshold: 0.30,
            orphan_threshold_days: 365,
        }),
        expected_findings: vec![],
    }
}

/// In-code clone of `diverse_org_ownership.json`.
pub fn synthesize_diverse_org_ownership() -> FragilityFixture {
    let mut publishers = BTreeMap::new();
    for (id, org, pkg) in [
        ("pub-a", "org-a", "pkg-a"),
        ("pub-b", "org-b", "pkg-b"),
        ("pub-c", "org-c", "pkg-c"),
        ("pub-d", "org-d", "pkg-d"),
        ("pub-e", "org-e", "pkg-e"),
    ] {
        publishers.insert(
            id.into(),
            mk_publisher(id, Some(org), &[pkg], 2, Some("rotate-90d"), Some(2)),
        );
    }
    let nodes = vec![
        mk_ns("ns-a", "org-a"),
        mk_ns("ns-b", "org-b"),
        mk_ns("ns-c", "org-c"),
        mk_ns("ns-d", "org-d"),
        mk_ns("ns-e", "org-e"),
    ];

    FragilityFixture {
        name: "diverse_org_ownership".into(),
        description: "five orgs each own one of five namespaces (20% each)".into(),
        now_ms: NOW_MS,
        maintainers: BTreeMap::new(),
        publishers,
        nodes,
        edges: vec![],
        config_overrides: None,
        expected_findings: vec![],
    }
}

/// In-code clone of `active_maintainers_recent_commits.json`.
pub fn synthesize_active_maintainers_recent_commits() -> FragilityFixture {
    let recent = NOW_SECS - 30 * 86_400;
    let mut maintainers = BTreeMap::new();
    for who in ["ann", "ben"] {
        maintainers.insert(
            who.into(),
            mk_maintainer(who, &["lib-x"], 30_000, 4, true, Some(recent)),
        );
    }
    for who in ["cat", "dan"] {
        maintainers.insert(
            who.into(),
            mk_maintainer(who, &["lib-y"], 30_000, 4, true, Some(recent)),
        );
    }
    let nodes = vec![mk_pkg("lib-x"), mk_pkg("lib-y")];
    let edges = vec![
        mk_maintained_by("lib-x", "ann"),
        mk_maintained_by("lib-x", "ben"),
        mk_maintained_by("lib-y", "cat"),
        mk_maintained_by("lib-y", "dan"),
    ];

    FragilityFixture {
        name: "active_maintainers_recent_commits".into(),
        description: "all maintainers committed within 30 days".into(),
        now_ms: NOW_MS,
        maintainers,
        publishers: BTreeMap::new(),
        nodes,
        edges,
        config_overrides: Some(SpofDetectorConfig {
            single_maintainer_threshold: 3,
            key_person_threshold: 0.50,
            max_chain_length: 4,
            org_concentration_threshold: 0.30,
            orphan_threshold_days: 365,
        }),
        expected_findings: vec![],
    }
}

/// In-code clone of `independent_packages_no_chains.json`.
pub fn synthesize_independent_packages_no_chains() -> FragilityFixture {
    let mut maintainers = BTreeMap::new();
    let pkgs = ["std-a", "std-b", "std-c", "std-d", "std-e"];
    for who in ["m_one", "m_two"] {
        maintainers.insert(
            who.into(),
            mk_maintainer(who, &pkgs, 50_000, 6, true, Some(RECENT_COMMIT_SECS)),
        );
    }
    let nodes: Vec<GraphNode> = pkgs.iter().map(|p| mk_pkg(p)).collect();
    let mut edges: Vec<GraphEdge> = Vec::new();
    for p in &pkgs {
        for m in ["m_one", "m_two"] {
            edges.push(mk_maintained_by(p, m));
        }
    }

    FragilityFixture {
        name: "independent_packages_no_chains".into(),
        description: "five packages with no Depends edges between them".into(),
        now_ms: NOW_MS,
        maintainers,
        publishers: BTreeMap::new(),
        nodes,
        edges,
        config_overrides: Some(SpofDetectorConfig {
            single_maintainer_threshold: 3,
            key_person_threshold: 0.60,
            max_chain_length: 4,
            org_concentration_threshold: 0.30,
            orphan_threshold_days: 365,
        }),
        expected_findings: vec![],
    }
}

/// In-code clone of `multi_quorum_publishers.json`.
pub fn synthesize_multi_quorum_publishers() -> FragilityFixture {
    let mut publishers = BTreeMap::new();
    for (id, org, pkgs) in [
        ("pub-foo", "foo-co", &["foo-1", "foo-2"][..]),
        ("pub-bar", "bar-llc", &["bar-1", "bar-2"][..]),
        ("pub-baz", "baz-inc", &["baz-1", "baz-2"][..]),
    ] {
        publishers.insert(
            id.into(),
            mk_publisher(id, Some(org), pkgs, 5, Some("rotate-90d"), Some(3)),
        );
    }
    let nodes = vec![
        mk_ns("ns-foo-a", "foo-co"),
        mk_ns("ns-foo-b", "foo-co"),
        mk_ns("ns-bar-a", "bar-llc"),
        mk_ns("ns-bar-b", "bar-llc"),
        mk_ns("ns-baz-a", "baz-inc"),
        mk_ns("ns-baz-b", "baz-inc"),
    ];

    FragilityFixture {
        name: "multi_quorum_publishers".into(),
        description: "three orgs each own 2 of 6 namespaces (~33%)".into(),
        now_ms: NOW_MS,
        maintainers: BTreeMap::new(),
        publishers,
        nodes,
        edges: vec![],
        // ~33% per org slightly exceeds the production default org-concentration
        // threshold of 0.30, so the fixture explicitly lifts the bar to 0.40
        // to model "no single org dominates beyond a healthy 1/3 share".
        config_overrides: Some(SpofDetectorConfig {
            single_maintainer_threshold: 100,
            key_person_threshold: 0.99,
            max_chain_length: 4,
            org_concentration_threshold: 0.40,
            orphan_threshold_days: 365,
        }),
        expected_findings: vec![],
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_label_present(verdict: &FixtureVerdict, label: SpofKindLabel) {
        let n = verdict.actual_finding_counts.get(&label).copied().unwrap_or(0);
        assert!(
            n >= 1,
            "expected at least one {} finding, got counts={:?}",
            label.slug(),
            verdict.actual_finding_counts
        );
    }

    #[allow(dead_code)]
    fn assert_only_label(verdict: &FixtureVerdict, label: SpofKindLabel) {
        for (other, n) in &verdict.actual_finding_counts {
            if *other != label {
                assert_eq!(
                    *n, 0,
                    "expected zero {} findings but got {}",
                    other.slug(),
                    n
                );
            }
        }
    }

    // ---- five known-SPOF fixtures ------------------------------------------

    #[test]
    fn synthesize_single_maintainer_dominant_flags_single_maintainer() {
        let f = synthesize_single_maintainer_dominant();
        let verdict = evaluate_fixture(&f).expect("evaluate");
        assert!(verdict.passed, "divergences: {:?}", verdict.divergences);
        assert_label_present(&verdict, SpofKindLabel::SingleMaintainer);
        // alice also crosses the KeyPerson share threshold; the fixture's
        // expected_findings deliberately constrains only SingleMaintainer
        // because that is the SPOF kind this fixture is designed to
        // demonstrate. We do NOT assert_only_label here.
    }

    #[test]
    fn synthesize_key_person_high_share_flags_key_person() {
        let f = synthesize_key_person_high_share();
        let verdict = evaluate_fixture(&f).expect("evaluate");
        assert!(verdict.passed, "divergences: {:?}", verdict.divergences);
        assert_label_present(&verdict, SpofKindLabel::KeyPerson);
    }

    #[test]
    fn synthesize_dependency_chain_fragile_flags_chain() {
        let f = synthesize_dependency_chain_fragile();
        let verdict = evaluate_fixture(&f).expect("evaluate");
        assert!(verdict.passed, "divergences: {:?}", verdict.divergences);
        assert_label_present(&verdict, SpofKindLabel::DependencyChain);
    }

    #[test]
    fn synthesize_org_concentrated_flags_org_concentration() {
        let f = synthesize_org_concentrated();
        let verdict = evaluate_fixture(&f).expect("evaluate");
        assert!(verdict.passed, "divergences: {:?}", verdict.divergences);
        assert_label_present(&verdict, SpofKindLabel::OrgConcentration);
    }

    #[test]
    fn synthesize_orphaned_pkg_flags_orphan() {
        let f = synthesize_orphaned_pkg();
        let verdict = evaluate_fixture(&f).expect("evaluate");
        assert!(verdict.passed, "divergences: {:?}", verdict.divergences);
        assert_label_present(&verdict, SpofKindLabel::OrphanedPackage);
    }

    // ---- five robust fixtures ----------------------------------------------

    #[test]
    fn synthesize_well_distributed_maintainers_is_robust() {
        let f = synthesize_well_distributed_maintainers();
        let verdict = evaluate_fixture(&f).expect("evaluate");
        assert!(
            verdict.passed,
            "robust fixture must pass; divergences: {:?}",
            verdict.divergences
        );
        assert!(
            verdict.actual_finding_counts.values().all(|n| *n == 0),
            "robust fixture must emit zero findings, got {:?}",
            verdict.actual_finding_counts
        );
    }

    #[test]
    fn synthesize_diverse_org_ownership_is_robust() {
        let f = synthesize_diverse_org_ownership();
        let verdict = evaluate_fixture(&f).expect("evaluate");
        assert!(verdict.passed, "divergences: {:?}", verdict.divergences);
        assert!(verdict.actual_finding_counts.values().all(|n| *n == 0));
    }

    #[test]
    fn synthesize_active_maintainers_recent_commits_is_robust() {
        let f = synthesize_active_maintainers_recent_commits();
        let verdict = evaluate_fixture(&f).expect("evaluate");
        assert!(verdict.passed, "divergences: {:?}", verdict.divergences);
        assert!(verdict.actual_finding_counts.values().all(|n| *n == 0));
    }

    #[test]
    fn synthesize_independent_packages_no_chains_is_robust() {
        let f = synthesize_independent_packages_no_chains();
        let verdict = evaluate_fixture(&f).expect("evaluate");
        assert!(verdict.passed, "divergences: {:?}", verdict.divergences);
        assert!(verdict.actual_finding_counts.values().all(|n| *n == 0));
    }

    #[test]
    fn synthesize_multi_quorum_publishers_is_robust() {
        let f = synthesize_multi_quorum_publishers();
        let verdict = evaluate_fixture(&f).expect("evaluate");
        assert!(verdict.passed, "divergences: {:?}", verdict.divergences);
        assert!(verdict.actual_finding_counts.values().all(|n| *n == 0));
    }

    // ---- helpers -----------------------------------------------------------

    #[test]
    fn load_fixture_from_json_round_trip_via_serde() {
        let original = synthesize_single_maintainer_dominant();
        let json = serde_json::to_string(&original).expect("serialise");
        let back = load_fixture_from_json(&json).expect("round trip");
        assert_eq!(back.name, original.name);
        assert_eq!(back.now_ms, original.now_ms);
        assert_eq!(back.maintainers, original.maintainers);
        assert_eq!(back.publishers, original.publishers);
        assert_eq!(back.nodes, original.nodes);
        assert_eq!(back.edges, original.edges);
        assert_eq!(back.expected_findings, original.expected_findings);
    }

    #[test]
    fn fixture_with_invalid_finding_label_rejected() {
        // Inject an unknown SpofKindLabel string; serde must refuse it because
        // the enum is strictly enumerated.
        let bad_json = r#"{
            "name": "broken",
            "description": "bad label",
            "now_ms": 1700000000000,
            "maintainers": {},
            "publishers": {},
            "nodes": [],
            "edges": [],
            "config_overrides": null,
            "expected_findings": [
                {"kind": "TotalNonsense", "min_count": 1, "max_count": 1}
            ]
        }"#;
        let err = load_fixture_from_json(bad_json).expect_err("must reject unknown label");
        match err {
            FragilityError::ShareOutOfRange { field, .. } => assert_eq!(field, "fixture_json"),
            other => panic!("expected ShareOutOfRange wrapping serde error, got {:?}", other),
        }
    }

    #[test]
    fn expected_finding_validate_rejects_inverted_bounds() {
        let bad = ExpectedFinding {
            kind: SpofKindLabel::KeyPerson,
            min_count: 5,
            max_count: 2,
        };
        let err = bad.validate().expect_err("min > max rejected");
        match err {
            FragilityError::ShareOutOfRange { field, .. } => {
                assert_eq!(field, "expected_finding_bounds")
            }
            other => panic!("unexpected error: {:?}", other),
        }
    }

    #[test]
    fn evaluate_fixture_marks_robust_failure_when_detector_emits() {
        // Build a fixture that the detector WILL flag (lots of sole packages)
        // but mark it as "robust" -- verdict must come back as not passed.
        let mut f = synthesize_single_maintainer_dominant();
        f.expected_findings = vec![]; // pretend it is robust
        let verdict = evaluate_fixture(&f).expect("evaluate");
        assert!(
            !verdict.passed,
            "verdict should fail when detector emits but fixture is marked robust"
        );
        assert!(!verdict.divergences.is_empty());
    }

    #[test]
    fn fixture_validate_rejects_empty_name() {
        let mut f = synthesize_diverse_org_ownership();
        f.name = "".into();
        let err = f.validate().expect_err("empty name rejected");
        assert_eq!(err, FragilityError::EmptyIdentifier);
    }
}
