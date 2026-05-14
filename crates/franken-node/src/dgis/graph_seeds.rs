//! Deterministic seed-graph construction (bd-2bj4 sub-task 3).
//!
//! This module supplies a hand-crafted ~10-package npm-style ecosystem that
//! downstream consumers (the contagion simulator bd-1q38, the SPOF detector
//! bd-2jns, the topology metric engine bd-t89w) can hammer against in unit and
//! integration tests without having to drive the full ingestion pipeline from
//! lockfiles on disk. The fixture exists in TWO byte-equivalent forms:
//!
//! * `tests/security/graph_seeds/realistic_npm_topology.json` -- the on-disk
//!   golden, useful for cross-language replay or external auditing.
//! * [`realistic_npm_topology`] (this module) -- the same content synthesised
//!   in code so unit tests under `cargo test -p frankenengine-node` don't
//!   depend on workspace-relative file paths.
//!
//! The two forms are kept in lockstep by the
//! [`seed_fixture_round_trips_through_serde`] inline test, which serialises
//! the in-code seed and asserts it round-trips through JSON without loss.
//! Equivalence with the on-disk JSON is asserted by the integration tests
//! shipped in bd-2bj4 sub-task 4.
//!
//! Hardening conventions (matching the project-wide CrimsonCrane playbook):
//!
//! * Bounded growth: [`load_seed_from_json`] caps `observations.len()` at
//!   [`MAX_SEED_OBSERVATIONS`] and re-runs `ManifestObservation::validate` on
//!   every entry, so an adversarial JSON blob can neither balloon the seed
//!   nor smuggle past length / NUL-byte invariants in the underlying types.
//! * `i64` window bounds: [`load_seed_from_json`] rejects windows where
//!   `window_end_ms < window_start_ms` (fail-closed at the boundary). Per-
//!   observation `ts` may fall outside the declared window -- downstream
//!   filtering is the consumer's responsibility -- but the window itself
//!   must be well-formed.
//! * `saturating_add` is unnecessary here because no counter is incremented
//!   on a hot path; the ingestion pipeline itself already uses saturating
//!   arithmetic on every accumulator surface.
//! * No unsafe: `#![forbid(unsafe_code)]` is inherited from `lib.rs`.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::dgis::graph_ingestion::{
    IngestError, IngestionPipeline, ManifestObservation, WindowedGraph, dependency_node_id,
    finalize_window, ingest, maintainer_node_id, package_node_id,
};

/// Hard cap on observations a single seed may declare. The realistic-npm
/// fixture ships ~50; 4096 leaves abundant slack for richer future seeds
/// while still bounding memory for adversarial inputs presented via the JSON
/// loader.
pub const MAX_SEED_OBSERVATIONS: usize = 4096;

/// Errors emitted by seed-graph helpers. Wraps `IngestError` so call sites
/// only need to plumb a single error type; the underlying ingestion-pipeline
/// error variants surface unchanged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SeedError {
    /// JSON parsing failed. The wrapped string carries the serde error
    /// message; we keep it as `String` (not `serde_json::Error`) because
    /// `serde_json::Error` is not `Eq`/`PartialEq` and we want this enum to
    /// be eq-comparable in tests.
    JsonParse(String),
    /// `observations.len()` exceeded [`MAX_SEED_OBSERVATIONS`].
    TooManyObservations { observed: usize, max: usize },
    /// `window_end_ms < window_start_ms`.
    InvertedWindow {
        window_start_ms: i64,
        window_end_ms: i64,
    },
    /// One of the observations failed `ManifestObservation::validate`.
    InvalidObservation {
        index: usize,
        source: IngestError,
    },
    /// `ingest` or `finalize_window` rejected an observation during
    /// [`build_windowed_graph_from_seed`].
    IngestRejected {
        index: usize,
        source: IngestError,
    },
}

impl std::fmt::Display for SeedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SeedError::JsonParse(msg) => write!(f, "seed JSON parse failed: {msg}"),
            SeedError::TooManyObservations { observed, max } => {
                write!(f, "too many seed observations: {observed} > {max}")
            }
            SeedError::InvertedWindow {
                window_start_ms,
                window_end_ms,
            } => write!(
                f,
                "inverted seed window: end {window_end_ms} < start {window_start_ms}"
            ),
            SeedError::InvalidObservation { index, source } => {
                write!(f, "seed observation {index} invalid: {source}")
            }
            SeedError::IngestRejected { index, source } => {
                write!(f, "seed observation {index} rejected by pipeline: {source}")
            }
        }
    }
}

impl std::error::Error for SeedError {}

/// A static graph seed: a named, time-bounded bundle of canonical manifest
/// observations. Round-trips through serde so the on-disk JSON fixture and
/// the in-code synthesised fixture are byte-equivalent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GraphSeed {
    pub name: String,
    pub description: String,
    pub window_start_ms: i64,
    pub window_end_ms: i64,
    pub observations: Vec<ManifestObservation>,
}

impl GraphSeed {
    /// Re-run every hardening invariant on the seed. Called by
    /// [`load_seed_from_json`]; downstream code that constructs a `GraphSeed`
    /// by hand should call this before trusting the result.
    pub fn validate(&self) -> Result<(), SeedError> {
        if self.observations.len() > MAX_SEED_OBSERVATIONS {
            return Err(SeedError::TooManyObservations {
                observed: self.observations.len(),
                max: MAX_SEED_OBSERVATIONS,
            });
        }
        if self.window_end_ms < self.window_start_ms {
            return Err(SeedError::InvertedWindow {
                window_start_ms: self.window_start_ms,
                window_end_ms: self.window_end_ms,
            });
        }
        for (i, obs) in self.observations.iter().enumerate() {
            obs.validate()
                .map_err(|e| SeedError::InvalidObservation {
                    index: i,
                    source: e,
                })?;
        }
        Ok(())
    }
}

/// Expected structural invariants for a seed, returned by
/// [`seed_expected_invariants`]. Downstream tests assert on these so a
/// regression in the ingestion pipeline is caught immediately rather than
/// having to diff full graph dumps.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeedInvariants {
    /// Number of unique `(package_name, version)` tuples observed.
    pub expected_unique_package_versions: usize,
    /// Number of unique maintainer handles observed.
    pub expected_unique_maintainers: usize,
    /// Number of unique dependency-target package names observed.
    pub expected_unique_dependency_targets: usize,
    /// Minimum number of nodes the finalised graph must contain (package
    /// nodes + maintainer nodes + dependency-target nodes).
    pub min_total_nodes: usize,
    /// Minimum number of edges the finalised graph must contain (MaintainedBy
    /// + Depends edges, each (from,to,kind) counted once even if the seed
    /// includes the same edge across multiple observations).
    pub min_total_edges: usize,
    /// Total observation count (including duplicates). The pipeline will
    /// dedup byte-identical observations, so the *unique* count may be
    /// strictly less; see [`expected_unique_observations`].
    pub total_observations: usize,
    /// Unique observation count after canonical-hash deduplication.
    pub expected_unique_observations: usize,
}

/// Parse a `GraphSeed` from a JSON string, enforcing every hardening
/// invariant before returning. Wraps the underlying serde error in
/// [`SeedError::JsonParse`].
pub fn load_seed_from_json(json: &str) -> Result<GraphSeed, SeedError> {
    let seed: GraphSeed =
        serde_json::from_str(json).map_err(|e| SeedError::JsonParse(e.to_string()))?;
    seed.validate()?;
    Ok(seed)
}

/// Synthesise the 10-package realistic npm topology fixture in code.
///
/// The content here MUST stay byte-equivalent (modulo JSON whitespace) to
/// `tests/security/graph_seeds/realistic_npm_topology.json`. The
/// [`seed_fixture_round_trips_through_serde`] inline test guards this.
///
/// Ecosystem shape:
/// * Orgs: `acme` (acme-core, acme-api, acme-cli), `globex` (globex-db,
///   globex-orm), unscoped utilities (lodash-lite, json-utils, http-client,
///   yargs-mini, validator-x).
/// * Maintainer overlap (so bd-2jns SPOF detection has signal):
///   - alice: 4 packages (acme-core, acme-api, json-utils, lodash-lite)
///   - bob:   3 packages (acme-core, acme-cli, json-utils)
///   - dave:  2 packages (globex-db, globex-orm)
/// * Dependency chain of length 3:
///   `acme-cli -> acme-api -> acme-core -> lodash-lite`.
/// * Stale leaves: lodash-lite and yargs-mini each observed exactly once
///   early in the window so stale-provenance detection has signal.
pub fn realistic_npm_topology() -> GraphSeed {
    let observations = vec![
        // -- single-shot stale leaves at the head of the window ----------
        obs(100, "npm-lock", "lodash-lite", "4.0.0", &["alice"], &[], None),
        obs(200, "npm-lock", "yargs-mini", "1.0.0", &["eve"], &[], None),
        // -- initial canonical observations of every package ------------
        obs(50_000, "npm-lock", "json-utils", "1.5.2", &["alice", "bob"], &[], None),
        obs(60_000, "npm-lock", "validator-x", "0.8.1", &["carol", "frank"], &[], None),
        obs(70_000, "npm-lock", "http-client", "2.3.0", &["frank"], &[("json-utils", "^1.5.0")], None),
        obs(80_000, "npm-lock", "acme-core", "1.2.0", &["alice", "bob"],
            &[("lodash-lite", "^4.0.0"), ("json-utils", "^1.5.0")], Some("ac11ec01")),
        obs(90_000, "npm-lock", "acme-api", "2.0.1", &["alice", "carol"],
            &[("acme-core", "^1.2.0"), ("http-client", "^2.3.0")], Some("ac11ec02")),
        obs(100_000, "npm-lock", "acme-cli", "0.9.0", &["bob"],
            &[("acme-api", "^2.0.0"), ("yargs-mini", "^1.0.0")], Some("ac11ec03")),
        obs(110_000, "npm-lock", "globex-db", "3.1.0", &["dave", "eve"], &[("json-utils", "^1.5.0")], None),
        obs(120_000, "npm-lock", "globex-orm", "1.0.5", &["dave"],
            &[("globex-db", "^3.1.0"), ("validator-x", "^0.8.0")], None),
        // -- registry-side mirror of every initial observation ---------
        obs(200_000, "registry:npmjs", "json-utils", "1.5.2", &["alice", "bob"], &[], None),
        obs(250_000, "registry:npmjs", "acme-core", "1.2.0", &["alice", "bob"],
            &[("lodash-lite", "^4.0.0"), ("json-utils", "^1.5.0")], Some("ac11ec01")),
        obs(300_000, "registry:npmjs", "acme-api", "2.0.1", &["alice", "carol"],
            &[("acme-core", "^1.2.0"), ("http-client", "^2.3.0")], Some("ac11ec02")),
        obs(350_000, "registry:npmjs", "acme-cli", "0.9.0", &["bob"],
            &[("acme-api", "^2.0.0"), ("yargs-mini", "^1.0.0")], Some("ac11ec03")),
        obs(400_000, "registry:npmjs", "http-client", "2.3.0", &["frank"], &[("json-utils", "^1.5.0")], None),
        obs(450_000, "registry:npmjs", "globex-db", "3.1.0", &["dave", "eve"], &[("json-utils", "^1.5.0")], None),
        obs(500_000, "registry:npmjs", "globex-orm", "1.0.5", &["dave"],
            &[("globex-db", "^3.1.0"), ("validator-x", "^0.8.0")], None),
        obs(550_000, "registry:npmjs", "validator-x", "0.8.1", &["carol", "frank"], &[], None),
        // -- exec-evidence pass on the acme chain ----------------------
        obs(600_000, "exec-evidence", "acme-cli", "0.9.0", &["bob"],
            &[("acme-api", "^2.0.0"), ("yargs-mini", "^1.0.0")], Some("ac11ec03")),
        obs(700_000, "exec-evidence", "acme-api", "2.0.1", &["alice", "carol"],
            &[("acme-core", "^1.2.0"), ("http-client", "^2.3.0")], Some("ac11ec02")),
        obs(800_000, "exec-evidence", "acme-core", "1.2.0", &["alice", "bob"],
            &[("lodash-lite", "^4.0.0"), ("json-utils", "^1.5.0")], Some("ac11ec01")),
        // -- acme chain bump to .1 patches ----------------------------
        obs(1_000_000, "npm-lock", "acme-core", "1.2.1", &["alice", "bob"],
            &[("lodash-lite", "^4.0.0"), ("json-utils", "^1.5.0")], Some("ac11ec01")),
        obs(1_100_000, "npm-lock", "acme-api", "2.0.2", &["alice", "carol"],
            &[("acme-core", "^1.2.1"), ("http-client", "^2.3.0")], Some("ac11ec02")),
        obs(1_200_000, "npm-lock", "acme-cli", "0.9.1", &["bob"],
            &[("acme-api", "^2.0.2"), ("yargs-mini", "^1.0.0")], Some("ac11ec03")),
        obs(1_300_000, "registry:npmjs", "acme-core", "1.2.1", &["alice", "bob"],
            &[("lodash-lite", "^4.0.0"), ("json-utils", "^1.5.0")], Some("ac11ec01")),
        obs(1_400_000, "registry:npmjs", "acme-api", "2.0.2", &["alice", "carol"],
            &[("acme-core", "^1.2.1"), ("http-client", "^2.3.0")], Some("ac11ec02")),
        // -- json-utils + http-client minor bumps ---------------------
        obs(1_500_000, "npm-lock", "json-utils", "1.5.3", &["alice", "bob"], &[], None),
        obs(1_550_000, "registry:npmjs", "json-utils", "1.5.3", &["alice", "bob"], &[], None),
        obs(1_600_000, "npm-lock", "http-client", "2.3.1", &["frank"], &[("json-utils", "^1.5.0")], None),
        obs(1_650_000, "registry:npmjs", "http-client", "2.3.1", &["frank"], &[("json-utils", "^1.5.0")], None),
        // -- globex exec evidence + bump -----------------------------
        obs(1_700_000, "exec-evidence", "globex-orm", "1.0.5", &["dave"],
            &[("globex-db", "^3.1.0"), ("validator-x", "^0.8.0")], None),
        obs(1_750_000, "exec-evidence", "globex-db", "3.1.0", &["dave", "eve"], &[("json-utils", "^1.5.0")], None),
        obs(1_800_000, "npm-lock", "validator-x", "0.8.2", &["carol", "frank"], &[], None),
        obs(1_850_000, "registry:npmjs", "validator-x", "0.8.2", &["carol", "frank"], &[], None),
        obs(1_900_000, "npm-lock", "globex-orm", "1.0.6", &["dave"],
            &[("globex-db", "^3.1.0"), ("validator-x", "^0.8.0")], None),
        obs(1_950_000, "registry:npmjs", "globex-orm", "1.0.6", &["dave"],
            &[("globex-db", "^3.1.0"), ("validator-x", "^0.8.0")], None),
        // -- final exec-evidence sweep across the acme + globex chains
        obs(2_000_000, "exec-evidence", "acme-cli", "0.9.1", &["bob"],
            &[("acme-api", "^2.0.2"), ("yargs-mini", "^1.0.0")], Some("ac11ec03")),
        obs(2_050_000, "exec-evidence", "acme-api", "2.0.2", &["alice", "carol"],
            &[("acme-core", "^1.2.1"), ("http-client", "^2.3.0")], Some("ac11ec02")),
        obs(2_100_000, "exec-evidence", "acme-core", "1.2.1", &["alice", "bob"],
            &[("lodash-lite", "^4.0.0"), ("json-utils", "^1.5.0")], Some("ac11ec01")),
        obs(2_150_000, "exec-evidence", "json-utils", "1.5.3", &["alice", "bob"], &[], None),
        obs(2_200_000, "exec-evidence", "http-client", "2.3.1", &["frank"], &[("json-utils", "^1.5.0")], None),
        // -- final patch bump to .2 to round out the window -----------
        obs(2_300_000, "npm-lock", "acme-core", "1.2.2", &["alice", "bob"],
            &[("lodash-lite", "^4.0.0"), ("json-utils", "^1.5.0")], Some("ac11ec01")),
        obs(2_350_000, "registry:npmjs", "acme-core", "1.2.2", &["alice", "bob"],
            &[("lodash-lite", "^4.0.0"), ("json-utils", "^1.5.0")], Some("ac11ec01")),
        obs(2_400_000, "npm-lock", "acme-api", "2.0.3", &["alice", "carol"],
            &[("acme-core", "^1.2.2"), ("http-client", "^2.3.0")], Some("ac11ec02")),
        obs(2_450_000, "registry:npmjs", "acme-api", "2.0.3", &["alice", "carol"],
            &[("acme-core", "^1.2.2"), ("http-client", "^2.3.0")], Some("ac11ec02")),
        obs(2_500_000, "npm-lock", "acme-cli", "0.9.2", &["bob"],
            &[("acme-api", "^2.0.3"), ("yargs-mini", "^1.0.0")], Some("ac11ec03")),
        obs(2_550_000, "registry:npmjs", "acme-cli", "0.9.2", &["bob"],
            &[("acme-api", "^2.0.3"), ("yargs-mini", "^1.0.0")], Some("ac11ec03")),
        obs(2_580_000, "exec-evidence", "acme-cli", "0.9.2", &["bob"],
            &[("acme-api", "^2.0.3"), ("yargs-mini", "^1.0.0")], Some("ac11ec03")),
        obs(2_585_000, "exec-evidence", "acme-api", "2.0.3", &["alice", "carol"],
            &[("acme-core", "^1.2.2"), ("http-client", "^2.3.0")], Some("ac11ec02")),
        obs(2_590_000, "exec-evidence", "acme-core", "1.2.2", &["alice", "bob"],
            &[("lodash-lite", "^4.0.0"), ("json-utils", "^1.5.0")], Some("ac11ec01")),
        obs(2_591_000, "exec-evidence", "globex-orm", "1.0.6", &["dave"],
            &[("globex-db", "^3.1.0"), ("validator-x", "^0.8.0")], None),
    ];

    GraphSeed {
        name: "realistic_npm_topology".to_string(),
        description: REALISTIC_NPM_DESCRIPTION.to_string(),
        window_start_ms: 0,
        window_end_ms: 2_592_000_000,
        observations,
    }
}

/// Description string for the in-code synthesised fixture. Kept in lockstep
/// with the on-disk JSON fixture so serde round-trips are byte-equivalent.
const REALISTIC_NPM_DESCRIPTION: &str = "10-package npm-style ecosystem with mixed org/maintainer overlap, dependency chains of length >=3, and a 30-day observation window. Built so downstream SPOF detection (bd-2jns) sees maintainer concentration signal and so contagion simulators (bd-1q38/bd-2ao3) have non-trivial transitive paths to walk. acme-* are scoped to the 'acme' org (alice/bob/carol overlap), globex-* to 'globex' (dave/eve), and the leaf utilities (lodash-lite, json-utils, http-client, yargs-mini, validator-x) live unscoped. Update frequency varies: acme-* and json-utils churn frequently (many observations), lodash-lite + yargs-mini have a single stale observation early in the window so stale-provenance signals fire.";

/// Small constructor helper used to keep `realistic_npm_topology` readable.
/// Panics if the observation violates a hardening invariant -- which would be
/// a bug in this module's seed table, NOT runtime data. The inline test
/// `realistic_npm_topology_loads_without_error` guards against that.
fn obs(
    ts: i64,
    source: &str,
    name: &str,
    version: &str,
    maintainers: &[&str],
    deps: &[(&str, &str)],
    signature_hex: Option<&str>,
) -> ManifestObservation {
    let mut dmap = BTreeMap::new();
    for (k, v) in deps {
        dmap.insert((*k).to_string(), (*v).to_string());
    }
    ManifestObservation::new(
        ts,
        source.to_string(),
        name.to_string(),
        version.to_string(),
        maintainers.iter().map(|s| (*s).to_string()).collect(),
        dmap,
        signature_hex.map(|s| s.to_string()),
    )
    .expect("seed observation must satisfy ManifestObservation::validate")
}

/// Run the full ingestion pipeline (`ingest` per observation, then
/// `finalize_window`) over a seed. Returns the materialised
/// [`WindowedGraph`].
///
/// Determinism: because the pipeline keys off canonical SHA-256 hashes and
/// emits sorted node/edge sets, two calls on the same seed produce
/// byte-identical `WindowedGraph` instances. The
/// [`realistic_npm_topology_yields_deterministic_graph`] inline test guards
/// this.
pub fn build_windowed_graph_from_seed(seed: &GraphSeed) -> Result<WindowedGraph, SeedError> {
    seed.validate()?;
    let mut pipe = IngestionPipeline::new();
    for (i, obs) in seed.observations.iter().enumerate() {
        ingest(&mut pipe, obs.clone()).map_err(|e| SeedError::IngestRejected {
            index: i,
            source: e,
        })?;
    }
    finalize_window(&pipe).map_err(|e| SeedError::IngestRejected {
        index: usize::MAX,
        source: e,
    })
}

/// Compute the expected structural invariants for `seed` directly from its
/// observation list, independent of the ingestion pipeline. Downstream tests
/// compare the pipeline's output against these expected counts; any drift
/// signals an ingestion regression.
pub fn seed_expected_invariants(seed: &GraphSeed) -> SeedInvariants {
    use std::collections::BTreeSet;

    let mut unique_pkg_versions: BTreeSet<(String, String)> = BTreeSet::new();
    let mut unique_maintainers: BTreeSet<String> = BTreeSet::new();
    let mut unique_dep_targets: BTreeSet<String> = BTreeSet::new();
    let mut unique_obs_hashes: BTreeSet<[u8; 32]> = BTreeSet::new();
    let mut unique_maintained_edges: BTreeSet<(String, String)> = BTreeSet::new();
    let mut unique_depends_edges: BTreeSet<(String, String)> = BTreeSet::new();

    for obs in &seed.observations {
        unique_pkg_versions.insert((obs.package_name.clone(), obs.version.clone()));
        for m in &obs.maintainers {
            unique_maintainers.insert(m.clone());
        }
        for dep_name in obs.dependencies.keys() {
            unique_dep_targets.insert(dep_name.clone());
        }
        unique_obs_hashes.insert(crate::dgis::graph_ingestion::observation_hash(obs));

        let pkg_id = package_node_id(&obs.package_name, &obs.version);
        for m in &obs.maintainers {
            unique_maintained_edges.insert((pkg_id.clone(), maintainer_node_id(m)));
        }
        for dep_name in obs.dependencies.keys() {
            unique_depends_edges.insert((pkg_id.clone(), dependency_node_id(dep_name)));
        }
    }

    // Total nodes = unique package-version nodes + maintainer nodes +
    // dep-target nodes. Dep-target nodes can collide with package-version
    // nodes by id only if the dependency name was ever observed as
    // `pkg:<name>@<version>`, which the seed's id-formatters guarantee will
    // not happen (dep_node_id uses the `dep:` prefix). So the three sets are
    // disjoint.
    let total_nodes = unique_pkg_versions
        .len()
        .saturating_add(unique_maintainers.len())
        .saturating_add(unique_dep_targets.len());
    let total_edges = unique_maintained_edges
        .len()
        .saturating_add(unique_depends_edges.len());

    SeedInvariants {
        expected_unique_package_versions: unique_pkg_versions.len(),
        expected_unique_maintainers: unique_maintainers.len(),
        expected_unique_dependency_targets: unique_dep_targets.len(),
        min_total_nodes: total_nodes,
        min_total_edges: total_edges,
        total_observations: seed.observations.len(),
        expected_unique_observations: unique_obs_hashes.len(),
    }
}

// -- Tests ------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dgis::graph_ingestion::{EdgeKind, NodeKind};

    /// Sanity: the in-code synthesised seed satisfies every hardening
    /// invariant. This is the canonical guard that the hand-written
    /// observation table in `realistic_npm_topology` doesn't drift past
    /// `ManifestObservation::validate`.
    #[test]
    fn realistic_npm_topology_loads_without_error() {
        let seed = realistic_npm_topology();
        seed.validate().expect("realistic_npm_topology must validate");
        // 10 unique package names, 51 observations.
        let invariants = seed_expected_invariants(&seed);
        assert!(
            invariants.expected_unique_package_versions >= 10,
            "expected >=10 unique (name,version) tuples, got {}",
            invariants.expected_unique_package_versions
        );
        assert_eq!(invariants.total_observations, seed.observations.len());
        assert!(seed.observations.len() >= 50);
    }

    /// Determinism gate: two independent runs of the full pipeline over the
    /// seed must produce byte-identical `WindowedGraph` output.
    #[test]
    fn realistic_npm_topology_yields_deterministic_graph() {
        let seed = realistic_npm_topology();
        let g1 = build_windowed_graph_from_seed(&seed).expect("first build");
        let g2 = build_windowed_graph_from_seed(&seed).expect("second build");
        assert_eq!(g1, g2, "seed must produce byte-identical WindowedGraph");
        // Serialised form must also match -- this is the strongest possible
        // determinism guarantee a downstream consumer can lean on.
        let s1 = serde_json::to_string(&g1).expect("serialise g1");
        let s2 = serde_json::to_string(&g2).expect("serialise g2");
        assert_eq!(s1, s2);
    }

    /// Structural-invariants gate: counts the ingestion pipeline reports
    /// after `finalize_window` must satisfy the expected lower bounds we
    /// compute directly from the seed.
    #[test]
    fn realistic_npm_topology_satisfies_expected_invariants() {
        let seed = realistic_npm_topology();
        let invariants = seed_expected_invariants(&seed);
        let graph = build_windowed_graph_from_seed(&seed).expect("build");

        assert_eq!(
            graph.nodes.len(),
            invariants.min_total_nodes,
            "node count must match the unique-tuple sum"
        );
        assert_eq!(
            graph.edges.len(),
            invariants.min_total_edges,
            "edge count must match the unique-(from,to) sum"
        );
        assert_eq!(
            graph.total_observations as usize,
            invariants.expected_unique_observations,
            "total_observations must equal the canonical-hash unique count"
        );
        // Window bounds: the pipeline tracks `window_start`/`window_end` from
        // observed `ts` values; the seed's first ts is 100 and last is
        // 2_591_000.
        assert_eq!(graph.window_start, 100);
        assert_eq!(graph.window_end, 2_591_000);
    }

    /// SPOF-signal gate: at least one maintainer must own >=3 distinct
    /// packages so the bd-2jns SPOF detector has something to flag.
    #[test]
    fn realistic_npm_topology_has_maintainer_overlap() {
        use std::collections::BTreeMap;

        let seed = realistic_npm_topology();
        // Map maintainer -> set of unique package names they appear on.
        let mut m_to_pkgs: BTreeMap<String, std::collections::BTreeSet<String>> = BTreeMap::new();
        for obs in &seed.observations {
            for m in &obs.maintainers {
                m_to_pkgs
                    .entry(m.clone())
                    .or_default()
                    .insert(obs.package_name.clone());
            }
        }
        let max_overlap = m_to_pkgs.values().map(|s| s.len()).max().unwrap_or(0);
        assert!(
            max_overlap >= 3,
            "expected at least one maintainer on >=3 packages for SPOF signal, got {max_overlap}"
        );
        // Specifically: alice should be on >=4 packages, bob on >=3.
        assert!(
            m_to_pkgs.get("alice").map(|s| s.len()).unwrap_or(0) >= 4,
            "alice must maintain >=4 packages"
        );
        assert!(
            m_to_pkgs.get("bob").map(|s| s.len()).unwrap_or(0) >= 3,
            "bob must maintain >=3 packages"
        );
    }

    /// Dependency-chain gate: at least one transitive chain of length >=3
    /// must exist (acme-cli -> acme-api -> acme-core -> lodash-lite or
    /// equivalent). The contagion simulator in bd-1q38 needs this signal.
    #[test]
    fn realistic_npm_topology_has_dependency_chains_of_length_at_least_3() {
        let seed = realistic_npm_topology();
        // Build a name -> set-of-direct-deps map from the seed.
        let mut deps_of: BTreeMap<String, std::collections::BTreeSet<String>> = BTreeMap::new();
        for obs in &seed.observations {
            for dep_name in obs.dependencies.keys() {
                deps_of
                    .entry(obs.package_name.clone())
                    .or_default()
                    .insert(dep_name.clone());
            }
        }
        // DFS to find the longest chain rooted at any package name. Bounded
        // by the seed's 10-package size so unbounded recursion is impossible.
        fn longest_chain(
            from: &str,
            deps_of: &BTreeMap<String, std::collections::BTreeSet<String>>,
            visited: &mut std::collections::BTreeSet<String>,
        ) -> usize {
            if !visited.insert(from.to_string()) {
                return 0; // cycle guard
            }
            let mut best = 0usize;
            if let Some(children) = deps_of.get(from) {
                for c in children {
                    let len = 1 + longest_chain(c, deps_of, visited);
                    if len > best {
                        best = len;
                    }
                }
            }
            visited.remove(from);
            best
        }

        let mut max_chain = 0;
        for root in deps_of.keys() {
            let mut visited = std::collections::BTreeSet::new();
            let len = longest_chain(root, &deps_of, &mut visited);
            if len > max_chain {
                max_chain = len;
            }
        }
        assert!(
            max_chain >= 3,
            "expected a transitive dependency chain of length >=3, got {max_chain}"
        );
    }

    /// Bounded-growth gate: a JSON blob declaring more than
    /// `MAX_SEED_OBSERVATIONS` entries must be rejected by
    /// `load_seed_from_json`.
    #[test]
    fn load_seed_from_json_rejects_bounded_growth_violation() {
        // Build a minimal valid observation JSON snippet and repeat it past
        // the cap. We embed `MAX_SEED_OBSERVATIONS + 1` copies; each is
        // identical (the pipeline would dedup them in real ingestion, but
        // the seed loader's cap fires before any ingestion happens).
        let mut entries = String::new();
        for i in 0..=MAX_SEED_OBSERVATIONS {
            if i > 0 {
                entries.push(',');
            }
            entries.push_str(&format!(
                "{{\"ts\":{i},\"source\":\"s\",\"package_name\":\"p\",\"version\":\"1\",\"maintainers\":[],\"dependencies\":{{}},\"signature_hex\":null}}"
            ));
        }
        let json = format!(
            "{{\"name\":\"big\",\"description\":\"\",\"window_start_ms\":0,\"window_end_ms\":1,\"observations\":[{entries}]}}"
        );
        match load_seed_from_json(&json) {
            Err(SeedError::TooManyObservations { observed, max }) => {
                assert_eq!(observed, MAX_SEED_OBSERVATIONS + 1);
                assert_eq!(max, MAX_SEED_OBSERVATIONS);
            }
            other => panic!("expected TooManyObservations, got {other:?}"),
        }
    }

    /// Serde round-trip gate: the in-code seed survives a JSON round-trip
    /// with byte-identical (post-canonicalisation) content. This is the
    /// guard that keeps the on-disk JSON fixture and the in-code
    /// synthesiser in lockstep.
    #[test]
    fn seed_fixture_round_trips_through_serde() {
        let seed = realistic_npm_topology();
        let json = serde_json::to_string(&seed).expect("serialise");
        let back: GraphSeed = serde_json::from_str(&json).expect("deserialise");
        back.validate().expect("post-deserialise validate");
        assert_eq!(seed, back);
        // And the loader path produces the same value.
        let via_loader = load_seed_from_json(&json).expect("loader accepts");
        assert_eq!(via_loader, seed);
    }

    /// Monotonicity gate: the seed's observation list is sorted by `ts`. The
    /// ingestion pipeline doesn't require this (it dedups by hash regardless
    /// of arrival order), but the fixture is curated for readability + so
    /// `window_start`/`window_end` track first/last entries cleanly.
    #[test]
    fn seed_observations_have_monotonic_ts() {
        let seed = realistic_npm_topology();
        let mut prev = i64::MIN;
        for (i, obs) in seed.observations.iter().enumerate() {
            assert!(
                obs.ts >= prev,
                "observation {i} ts {} regresses below {}",
                obs.ts,
                prev
            );
            prev = obs.ts;
        }
    }

    /// Fail-closed gate: a seed with an inverted window must be rejected by
    /// `validate` (and therefore by `load_seed_from_json`).
    #[test]
    fn validate_rejects_inverted_window() {
        let mut seed = realistic_npm_topology();
        seed.window_start_ms = 100;
        seed.window_end_ms = 50;
        match seed.validate() {
            Err(SeedError::InvertedWindow {
                window_start_ms,
                window_end_ms,
            }) => {
                assert_eq!(window_start_ms, 100);
                assert_eq!(window_end_ms, 50);
            }
            other => panic!("expected InvertedWindow, got {other:?}"),
        }
    }

    /// Edge-kind coverage: the seed must yield BOTH MaintainedBy and
    /// Depends edges so downstream tests that filter by edge kind have
    /// data on both axes.
    #[test]
    fn seed_emits_both_maintained_and_depends_edges() {
        let seed = realistic_npm_topology();
        let graph = build_windowed_graph_from_seed(&seed).expect("build");
        let has_maintained = graph.edges.iter().any(|e| e.kind == EdgeKind::MaintainedBy);
        let has_depends = graph.edges.iter().any(|e| e.kind == EdgeKind::Depends);
        assert!(has_maintained, "seed must emit MaintainedBy edges");
        assert!(has_depends, "seed must emit Depends edges");
        // And every emitted edge must reference a node id that exists in the
        // node set.
        let node_ids: std::collections::BTreeSet<&str> =
            graph.nodes.iter().map(|n| n.id.as_str()).collect();
        for e in &graph.edges {
            assert!(node_ids.contains(e.from.as_str()), "edge from-id {} missing from node set", e.from);
            assert!(node_ids.contains(e.to.as_str()), "edge to-id {} missing from node set", e.to);
        }
        // And package nodes are tagged Package, maintainer nodes Maintainer.
        for n in &graph.nodes {
            if n.id.starts_with("pkg:") {
                assert_eq!(n.kind, NodeKind::Package);
            } else if n.id.starts_with("mnt:") {
                assert_eq!(n.kind, NodeKind::Maintainer);
            } else if n.id.starts_with("dep:") {
                assert_eq!(n.kind, NodeKind::Package);
            }
        }
    }
}
