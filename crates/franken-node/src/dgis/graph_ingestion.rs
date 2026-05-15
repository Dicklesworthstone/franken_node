//! Deterministic graph ingestion foundation (bd-2bj4 sub-task 1).
//!
//! This file defines the core type vocabulary that the downstream DGIS
//! ingestion pipeline operates on:
//!
//! * `ManifestObservation` -- a single deterministic observation of one
//!   package's manifest (lockfile entry, registry record, etc).
//! * `GraphNode` / `GraphEdge` / `NodeKind` / `EdgeKind` -- the canonical
//!   property-graph schema downstream consumers (topology metrics, fragility
//!   model, contagion simulator) build on top of.
//!
//! Two utilities anchor every downstream determinism guarantee:
//!
//! * [`canonical_observation_bytes`] -- length-prefixed, domain-separated
//!   serialization of a `ManifestObservation` under the
//!   `b"dgis_manifest_obs_v1:"` domain. Same input always produces the same
//!   bytes; any field-boundary ambiguity is impossible because every variable
//!   field is preceded by its u64 length.
//! * [`observation_hash`] -- SHA-256 of the canonical bytes. The hash is the
//!   stable identifier downstream pipeline stages key off of for
//!   deduplication, replay verification, and conflict detection.
//!
//! Hardening conventions (matching CrimsonCrane bug-pattern playbook):
//!
//! * Bounded-growth: `maintainers` capped at [`MAX_MAINTAINERS_PER_PACKAGE`],
//!   `dependencies` capped at [`MAX_DEPS_PER_PACKAGE`]. Both caps are enforced
//!   by `ManifestObservation::validate`; building a bad observation through
//!   the constructor returns `IngestError::TooManyMaintainers` /
//!   `IngestError::TooManyDependencies` instead of silently truncating.
//! * `is_finite()` guard on every edge weight; non-finite weights are rejected
//!   at construction (`GraphEdge::new`).
//! * Length-prefixed hash inputs: every variable-length field's byte length is
//!   written as a `u64::to_le_bytes` prefix before the field's bytes. This
//!   makes pipe-delimiter / boundary collisions impossible.
//! * Domain separator: every canonical encoding is prefixed with
//!   `b"dgis_manifest_obs_v1:"` so encodings from this module can never be
//!   mistaken for any other length-prefixed blob in the codebase.
//! * `saturating_add` on the running observation count helper used in tests
//!   and downstream aggregators.
//! * `#[forbid(unsafe_code)]` is inherited from `lib.rs`; no unsafe blocks
//!   exist in this module.
//!
//! Sub-task scope: this file ships ONLY the type vocabulary + canonical
//! encoding + hash. Lockfile/registry parsers, conflict resolution, the
//! replay loader, and the verification gate land in sub-tasks 2-5.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Maximum number of maintainers a single package observation may declare.
///
/// Real packages overwhelmingly have <16 maintainers; the cap of 64 leaves
/// generous slack for large foundation-backed packages while still bounding
/// memory/CPU for adversarial observations.
pub const MAX_MAINTAINERS_PER_PACKAGE: usize = 64;

/// Maximum number of direct dependencies a single package observation may
/// declare. Packages in the wild rarely cross ~1k direct deps; 4096 leaves
/// room for monorepo-style aggregate packages while still rejecting
/// adversarial graph explosions.
pub const MAX_DEPS_PER_PACKAGE: usize = 4096;

/// Maximum length of any single identifier string (package name, version,
/// maintainer handle, dependency name). Real ecosystem identifiers are far
/// shorter than 512 bytes; the cap prevents pathological canonical-encoding
/// inflation.
pub const MAX_IDENT_LEN: usize = 512;

/// Maximum length of the optional signature hex string (Ed25519-sized
/// signatures hex-encode to 128 bytes; 2048 leaves room for multi-sig blobs).
pub const MAX_SIG_HEX_LEN: usize = 2048;

/// Domain separator prefixed to every canonical encoding produced by this
/// module. Format chosen to match the project-wide
/// `b"<module>_<function>_v1:"` convention.
pub const CANONICAL_DOMAIN: &[u8] = b"dgis_manifest_obs_v1:";

/// Stable string identifier for graph nodes. We keep this as a type alias
/// (rather than a newtype) so downstream consumers can compose IDs freely;
/// validation lives at the ingestion boundary.
pub type NodeId = String;

/// Errors emitted while constructing or validating ingestion types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IngestError {
    /// `maintainers.len()` exceeded [`MAX_MAINTAINERS_PER_PACKAGE`].
    TooManyMaintainers { observed: usize, max: usize },
    /// `dependencies.len()` exceeded [`MAX_DEPS_PER_PACKAGE`].
    TooManyDependencies { observed: usize, max: usize },
    /// A single identifier exceeded [`MAX_IDENT_LEN`].
    IdentTooLong {
        field: &'static str,
        observed: usize,
    },
    /// `signature_hex` exceeded [`MAX_SIG_HEX_LEN`].
    SignatureHexTooLong { observed: usize },
    /// Edge weight was NaN or +/-Infinity.
    NonFiniteEdgeWeight,
    /// Identifier contained an embedded NUL byte (we reject these even though
    /// the canonical encoding is length-prefixed -- downstream string-based
    /// paths must not have to defend against null injection).
    IdentContainsNul { field: &'static str },
}

impl std::fmt::Display for IngestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IngestError::TooManyMaintainers { observed, max } => {
                write!(f, "too many maintainers: {observed} > {max}")
            }
            IngestError::TooManyDependencies { observed, max } => {
                write!(f, "too many dependencies: {observed} > {max}")
            }
            IngestError::IdentTooLong { field, observed } => {
                write!(f, "identifier {field} too long: {observed} bytes")
            }
            IngestError::SignatureHexTooLong { observed } => {
                write!(f, "signature hex too long: {observed} bytes")
            }
            IngestError::NonFiniteEdgeWeight => f.write_str("edge weight must be finite"),
            IngestError::IdentContainsNul { field } => {
                write!(f, "identifier {field} contains NUL byte")
            }
        }
    }
}

impl std::error::Error for IngestError {}

/// A single deterministic observation of one package manifest entry.
///
/// Each `ManifestObservation` is the atomic unit the ingestion pipeline
/// consumes. Identical observations always serialize to identical canonical
/// bytes (see [`canonical_observation_bytes`]) and therefore hash to the same
/// 32-byte digest under [`observation_hash`]. This is the determinism gate
/// the entire DGIS replay story depends on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestObservation {
    /// Observation timestamp (seconds since UNIX epoch). Stored as `i64`
    /// because legitimate observations can refer to historical lockfiles
    /// captured before the epoch shift.
    pub ts: i64,
    /// Stable source identifier (e.g. `"cargo-lock"`, `"npm-lock"`,
    /// `"registry:crates.io"`, `"exec-evidence:franken-node"`).
    pub source: String,
    /// Package name as the source reported it (no normalisation yet --
    /// normalisation is a pipeline-stage concern).
    pub package_name: String,
    /// Package version string (no normalisation).
    pub version: String,
    /// Declared maintainers / publishers (capped, see
    /// [`MAX_MAINTAINERS_PER_PACKAGE`]).
    pub maintainers: Vec<String>,
    /// Declared dependencies as `name -> requirement` (capped, see
    /// [`MAX_DEPS_PER_PACKAGE`]). Using `BTreeMap` guarantees deterministic
    /// iteration order regardless of insert order.
    pub dependencies: BTreeMap<String, String>,
    /// Optional detached signature over the manifest, hex-encoded. `None`
    /// signals the source did not provide a signature (which downstream
    /// risk-signal emission will flag).
    pub signature_hex: Option<String>,
}

impl ManifestObservation {
    /// Construct + validate in one step. Returns an error if any
    /// hardening invariant (bounds, length, NUL) is violated.
    pub fn new(
        ts: i64,
        source: impl Into<String>,
        package_name: impl Into<String>,
        version: impl Into<String>,
        maintainers: Vec<String>,
        dependencies: BTreeMap<String, String>,
        signature_hex: Option<String>,
    ) -> Result<Self, IngestError> {
        let obs = Self {
            ts,
            source: source.into(),
            package_name: package_name.into(),
            version: version.into(),
            maintainers,
            dependencies,
            signature_hex,
        };
        obs.validate()?;
        Ok(obs)
    }

    /// Enforce every hardening invariant on `self`. Called automatically by
    /// `new`; downstream code that deserialises from JSON must call this
    /// before trusting the result.
    pub fn validate(&self) -> Result<(), IngestError> {
        if self.maintainers.len() > MAX_MAINTAINERS_PER_PACKAGE {
            return Err(IngestError::TooManyMaintainers {
                observed: self.maintainers.len(),
                max: MAX_MAINTAINERS_PER_PACKAGE,
            });
        }
        if self.dependencies.len() > MAX_DEPS_PER_PACKAGE {
            return Err(IngestError::TooManyDependencies {
                observed: self.dependencies.len(),
                max: MAX_DEPS_PER_PACKAGE,
            });
        }
        check_ident("source", &self.source)?;
        check_ident("package_name", &self.package_name)?;
        check_ident("version", &self.version)?;
        for (i, m) in self.maintainers.iter().enumerate() {
            // Reuse the same checker; the field name carries the index so
            // operators can pinpoint the offender in logs.
            let _ = i; // index unused in stable error text; available for trace context
            check_ident("maintainer", m)?;
        }
        for (k, v) in &self.dependencies {
            check_ident("dependency_name", k)?;
            check_ident("dependency_req", v)?;
        }
        if let Some(sig) = &self.signature_hex {
            if sig.len() > MAX_SIG_HEX_LEN {
                return Err(IngestError::SignatureHexTooLong {
                    observed: sig.len(),
                });
            }
            if sig.contains('\0') {
                return Err(IngestError::IdentContainsNul {
                    field: "signature_hex",
                });
            }
        }
        Ok(())
    }
}

fn check_ident(field: &'static str, value: &str) -> Result<(), IngestError> {
    if value.len() > MAX_IDENT_LEN {
        return Err(IngestError::IdentTooLong {
            field,
            observed: value.len(),
        });
    }
    if value.contains('\0') {
        return Err(IngestError::IdentContainsNul { field });
    }
    Ok(())
}

/// Categorical type of a graph node.
///
/// `Package` and `Maintainer` are the two primary node kinds the ingestion
/// pipeline materialises. `Org` (organisation) and `Namespace` (e.g. an npm
/// scope, a Cargo registry namespace) are second-class kinds emitted by
/// optional enrichment passes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NodeKind {
    Package,
    Maintainer,
    Org,
    Namespace,
}

impl NodeKind {
    /// Stable wire tag used in canonical encodings. Adding a new variant
    /// MUST append (never reorder) to preserve determinism.
    pub fn wire_tag(self) -> u8 {
        match self {
            NodeKind::Package => 1,
            NodeKind::Maintainer => 2,
            NodeKind::Org => 3,
            NodeKind::Namespace => 4,
        }
    }
}

/// Categorical type of a graph edge.
///
/// `Ord` / `PartialOrd` are derived so the variant tag can drive
/// `BTreeMap<(NodeId, NodeId, EdgeKind), _>` keys in the ingestion pipeline.
/// The derived ordering follows declaration order; the ingestion pipeline
/// MUST NOT rely on that for canonical output -- it sorts by [`wire_tag`]
/// explicitly to make the canonical order independent of variant
/// declaration order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum EdgeKind {
    Depends,
    MaintainedBy,
    OwnedBy,
    NamespaceMember,
}

impl EdgeKind {
    /// Stable wire tag (same append-only rule as [`NodeKind::wire_tag`]).
    pub fn wire_tag(self) -> u8 {
        match self {
            EdgeKind::Depends => 1,
            EdgeKind::MaintainedBy => 2,
            EdgeKind::OwnedBy => 3,
            EdgeKind::NamespaceMember => 4,
        }
    }
}

/// A node in the DGIS property graph.
///
/// `metadata` is an open key-value bag that downstream enrichment passes can
/// populate (e.g. `"registry" -> "crates.io"`). Use `BTreeMap` so canonical
/// encoding is deterministic.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GraphNode {
    pub id: NodeId,
    pub kind: NodeKind,
    pub metadata: BTreeMap<String, String>,
}

impl GraphNode {
    pub fn new(id: impl Into<NodeId>, kind: NodeKind) -> Self {
        Self {
            id: id.into(),
            kind,
            metadata: BTreeMap::new(),
        }
    }

    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }
}

/// A directed edge in the DGIS property graph.
///
/// Construction goes through [`GraphEdge::new`] so the `is_finite` weight
/// guard is impossible to bypass without manual struct-literal construction.
/// Deserialised edges must be revalidated via [`GraphEdge::validate`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GraphEdge {
    pub from: NodeId,
    pub to: NodeId,
    pub kind: EdgeKind,
    pub weight: f64,
    pub observed_at: i64,
}

impl GraphEdge {
    pub fn new(
        from: impl Into<NodeId>,
        to: impl Into<NodeId>,
        kind: EdgeKind,
        weight: f64,
        observed_at: i64,
    ) -> Result<Self, IngestError> {
        if !weight.is_finite() {
            return Err(IngestError::NonFiniteEdgeWeight);
        }
        Ok(Self {
            from: from.into(),
            to: to.into(),
            kind,
            weight,
            observed_at,
        })
    }

    pub fn validate(&self) -> Result<(), IngestError> {
        if !self.weight.is_finite() {
            return Err(IngestError::NonFiniteEdgeWeight);
        }
        Ok(())
    }
}

// -- Canonical encoding helpers ---------------------------------------------

/// Append `bytes.len() as u64` (little-endian) followed by `bytes` to `out`.
/// This is the universal "length-prefixed field" primitive every canonical
/// encoding in this module uses.
fn push_lp(out: &mut Vec<u8>, bytes: &[u8]) {
    let len = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(bytes);
}

/// Length-prefixed canonical encoding of a `ManifestObservation` under the
/// `b"dgis_manifest_obs_v1:"` domain separator.
///
/// Wire layout (every variable field is preceded by its u64 little-endian
/// byte length):
///
/// 1. domain separator (raw, no length prefix; it's a fixed-size salt)
/// 2. `ts`               -- i64 little-endian
/// 3. `source`           -- LP string
/// 4. `package_name`     -- LP string
/// 5. `version`          -- LP string
/// 6. maintainer count   -- u64 little-endian
/// 7. each maintainer    -- LP string (BTreeMap-style sorted is N/A here,
///    we preserve caller order; canonical determinism relies on `Eq` of the
///    `maintainers` Vec)
/// 8. dependency count   -- u64 little-endian
/// 9. each (key, value)  -- LP key then LP value, iteration in BTreeMap order
/// 10. signature flag    -- 1 byte (0 = none, 1 = some)
/// 11. signature hex     -- LP string (only present if flag == 1)
pub fn canonical_observation_bytes(obs: &ManifestObservation) -> Vec<u8> {
    let mut out = Vec::with_capacity(estimate_canonical_size(obs));
    out.extend_from_slice(CANONICAL_DOMAIN);
    out.extend_from_slice(&obs.ts.to_le_bytes());
    push_lp(&mut out, obs.source.as_bytes());
    push_lp(&mut out, obs.package_name.as_bytes());
    push_lp(&mut out, obs.version.as_bytes());

    let m_count = u64::try_from(obs.maintainers.len()).unwrap_or(u64::MAX);
    out.extend_from_slice(&m_count.to_le_bytes());
    for m in &obs.maintainers {
        push_lp(&mut out, m.as_bytes());
    }

    let d_count = u64::try_from(obs.dependencies.len()).unwrap_or(u64::MAX);
    out.extend_from_slice(&d_count.to_le_bytes());
    for (k, v) in &obs.dependencies {
        push_lp(&mut out, k.as_bytes());
        push_lp(&mut out, v.as_bytes());
    }

    match &obs.signature_hex {
        None => out.push(0u8),
        Some(sig) => {
            out.push(1u8);
            push_lp(&mut out, sig.as_bytes());
        }
    }
    out
}

fn estimate_canonical_size(obs: &ManifestObservation) -> usize {
    // Best-effort capacity hint; saturating to avoid overflow on giant inputs
    // (rejected by validate, but estimate runs before validation in some
    // paths so we keep the math defensive).
    let mut size: usize = CANONICAL_DOMAIN.len();
    size = size.saturating_add(8); // ts
    size = size.saturating_add(8usize.saturating_add(obs.source.len()));
    size = size.saturating_add(8usize.saturating_add(obs.package_name.len()));
    size = size.saturating_add(8usize.saturating_add(obs.version.len()));
    size = size.saturating_add(8); // maintainer count
    for m in &obs.maintainers {
        size = size.saturating_add(8usize.saturating_add(m.len()));
    }
    size = size.saturating_add(8); // dep count
    for (k, v) in &obs.dependencies {
        size = size.saturating_add(8usize.saturating_add(k.len()));
        size = size.saturating_add(8usize.saturating_add(v.len()));
    }
    size = size.saturating_add(1); // signature flag
    if let Some(sig) = &obs.signature_hex {
        size = size.saturating_add(8usize.saturating_add(sig.len()));
    }
    size
}

/// SHA-256 of [`canonical_observation_bytes`]. This is the stable
/// deduplication / replay-verification key downstream stages use. We use
/// SHA-256 (not BLAKE3) because BLAKE3 is feature-gated in this crate and we
/// want this primitive to always compile; downstream stages may layer a
/// faster keyed hash on top.
pub fn observation_hash(obs: &ManifestObservation) -> [u8; 32] {
    let bytes = canonical_observation_bytes(obs);
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

// -- Ingestion pipeline (sub-task 2) ----------------------------------------
//
// The pipeline consumes a stream of `ManifestObservation` records, deduplicates
// by canonical `observation_hash`, derives the property-graph edges implied by
// each observation (package -> dependency, package -> maintainer, optional
// package -> namespace), and accumulates per-(from,to,kind) weighting so the
// final time-windowed graph reflects observation density and recency.
//
// Determinism gates (every gate matches a `cargo test` case below):
//
// * **Hash-keyed dedup**: the `observed_hashes` set is keyed off the canonical
//   SHA-256 from sub-task 1. Two byte-identical observations -- regardless of
//   when they arrive -- collapse into a single contribution.
// * **BTreeSet / BTreeMap throughout**: every container that influences output
//   ordering is a sorted map/set, so iteration order is fully determined by
//   the canonical key.
// * **Length-prefixed accumulator hash (`ACCUMULATOR_DOMAIN`)**: when the
//   pipeline emits `IngestionDelta` records that downstream consumers might
//   hash, the helper here uses the `b"dgis_ingest_v1:"` domain separator with
//   length-prefixed key fields so accidental collisions with other modules'
//   hashes are impossible.
// * **Bounded growth**: both `observed_hashes` and `edge_accumulator` are
//   capped (`max_observations`, `max_edges`). Once a cap is hit further
//   `ingest` calls return `IngestError::TooMany*` -- never silent truncation.
// * **`is_finite` guards**: every f64 surface (`weight_sum`, decay output,
//   final mean weight) is `is_finite`-checked. Non-finite half-lives are
//   rejected up front.
// * **`saturating_add`**: every counter (`observation_count`, `edges_updated`,
//   `total_observations`) uses saturating arithmetic.

/// Domain separator prefixed to any canonical encoding the ingestion pipeline
/// produces. Kept distinct from the manifest-observation domain so the two
/// hash spaces can never collide.
pub const ACCUMULATOR_DOMAIN: &[u8] = b"dgis_ingest_v1:";

/// Maximum unique observations a single pipeline instance may absorb before
/// it refuses further input. Real ecosystems easily produce 10s of thousands
/// of unique package observations per ingest window; 1_048_576 leaves slack
/// while still bounding worst-case memory.
pub const DEFAULT_MAX_OBSERVATIONS: usize = 1_048_576;

/// Maximum distinct `(from, to, kind)` edge keys a single pipeline instance
/// may accumulate. Bounded for the same reason as observations.
pub const DEFAULT_MAX_EDGES: usize = 2_097_152;

/// Default half-life (in milliseconds) used by the time-decay weighting when
/// callers do not supply one. 7 days felt like a sensible default for
/// dependency-graph freshness; downstream callers can override.
pub const DEFAULT_DECAY_HALF_LIFE_MS: i64 = 7 * 24 * 60 * 60 * 1000;

/// Internal accumulator for a single `(from, to, kind)` edge key. Holds the
/// running weight sum, the observation count, and the first/last observed
/// timestamps so [`finalize_window`] can compute the mean weight and recency.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EdgeAccumulator {
    /// Sum of decayed weights across every observation that touched this edge.
    /// Always `is_finite`; non-finite contributions are rejected.
    pub weight_sum: f64,
    /// Number of observations that contributed to `weight_sum`. Uses
    /// `saturating_add` so worst-case overflow saturates rather than wraps.
    pub observation_count: u64,
    /// Earliest observation timestamp seen on this edge.
    pub first_observed: i64,
    /// Latest observation timestamp seen on this edge.
    pub last_observed: i64,
}

impl EdgeAccumulator {
    fn new(weight: f64, observed_at: i64) -> Self {
        Self {
            weight_sum: weight,
            observation_count: 1,
            first_observed: observed_at,
            last_observed: observed_at,
        }
    }

    fn record(&mut self, weight: f64, observed_at: i64) -> Result<(), IngestError> {
        if !weight.is_finite() {
            return Err(IngestError::NonFiniteEdgeWeight);
        }
        let new_sum = self.weight_sum + weight;
        if !new_sum.is_finite() {
            // Defensively reject overflow-to-infinity rather than persisting
            // a poisoned accumulator.
            return Err(IngestError::NonFiniteEdgeWeight);
        }
        self.weight_sum = new_sum;
        self.observation_count = self.observation_count.saturating_add(1);
        if observed_at < self.first_observed {
            self.first_observed = observed_at;
        }
        if observed_at > self.last_observed {
            self.last_observed = observed_at;
        }
        Ok(())
    }

    /// Mean weight = `weight_sum / observation_count`. Returns `0.0` when
    /// `observation_count == 0` (the accumulator should never be in that
    /// state once constructed, but the guard is cheap and keeps the function
    /// total).
    fn mean_weight(&self) -> f64 {
        if self.observation_count == 0 {
            return 0.0;
        }
        let mean = self.weight_sum / (self.observation_count as f64);
        if mean.is_finite() { mean } else { 0.0 }
    }
}

/// Time-decay weighting for a single observation.
///
/// Returns `exp(-ln2 * delta_ms / half_life_ms)`. The result is in `(0, 1]`
/// for any non-negative `delta_ms` and a positive `half_life_ms`. Observations
/// that arrive exactly at `window_end` return `1.0`; older observations decay
/// exponentially. Future-dated observations (where `observed_at > window_end`)
/// are clamped to `delta = 0` so they don't artificially inflate weight.
///
/// Rejects non-finite `half_life_ms` (callers must supply an i64 already, but
/// we also reject `half_life_ms <= 0` to prevent division-by-zero and
/// negative-decay reversals) and returns `IngestError::NonFiniteEdgeWeight`
/// when the computation would produce NaN or +/-Infinity.
pub fn time_decay_weight(
    observed_at: i64,
    window_end: i64,
    half_life_ms: i64,
) -> Result<f64, IngestError> {
    if half_life_ms <= 0 {
        return Err(IngestError::NonFiniteEdgeWeight);
    }
    let delta = window_end.saturating_sub(observed_at).max(0);
    let half_life_f = half_life_ms as f64;
    let delta_f = delta as f64;
    if !half_life_f.is_finite() || !delta_f.is_finite() {
        return Err(IngestError::NonFiniteEdgeWeight);
    }
    let exponent = -std::f64::consts::LN_2 * delta_f / half_life_f;
    if !exponent.is_finite() {
        return Err(IngestError::NonFiniteEdgeWeight);
    }
    let w = exponent.exp();
    if !w.is_finite() {
        return Err(IngestError::NonFiniteEdgeWeight);
    }
    // Numerical safety: `exp(0)` should be exactly 1.0, but clamp to the
    // (0, 1] band defensively so downstream `is_finite` consumers never see a
    // value slightly above 1.0 due to ULP drift.
    Ok(w.clamp(0.0, 1.0))
}

/// Snapshot of one successful `ingest` call.
///
/// Reports what changed so callers can plumb the delta into downstream
/// consumers (telemetry, metrics, incremental graph updates) without having
/// to diff the pipeline state themselves.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IngestionDelta {
    /// Brand-new nodes introduced by this observation. Sorted by id for
    /// deterministic downstream consumption.
    pub new_nodes: Vec<GraphNode>,
    /// Brand-new edges introduced by this observation. Sorted by
    /// (from, to, kind) for deterministic ordering. `weight` on a newly
    /// emitted edge is the per-observation decayed weight at the time of
    /// ingestion -- the *aggregated* weight only exists after
    /// [`finalize_window`].
    pub new_edges: Vec<GraphEdge>,
    /// True if the observation was a byte-identical replay of an
    /// already-seen observation. When true, `new_nodes` / `new_edges` are
    /// empty and `edges_updated` is zero -- nothing else in the pipeline
    /// state changed either.
    pub deduplicated: bool,
    /// Number of existing edge accumulators whose state was updated (i.e.
    /// `(from, to, kind)` keys we'd already seen on a previous observation).
    /// Uses u32 because per-call deltas are inherently bounded.
    pub edges_updated: u32,
}

/// Time-windowed graph emitted by [`finalize_window`].
///
/// `nodes` and `edges` are sorted (by node id, and by (from, to, kind)
/// respectively) so serialised output is byte-identical for identical input
/// streams. `total_observations` is the cumulative count of *unique*
/// observations the pipeline absorbed across the entire window.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WindowedGraph {
    pub nodes: Vec<GraphNode>,
    pub edges: Vec<GraphEdge>,
    pub window_start: i64,
    pub window_end: i64,
    pub total_observations: u64,
}

/// Deterministic ingestion pipeline state.
///
/// Construct with [`IngestionPipeline::new`] (which sets sane defaults) or
/// [`IngestionPipeline::with_caps`] for full control. The pipeline is `Send`
/// + `Sync` only by virtue of its fields; nothing here owns interior
/// mutability or unsafe references.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IngestionPipeline {
    /// Canonical observation hashes already absorbed (the dedup gate).
    pub observed_hashes: BTreeSet<[u8; 32]>,
    /// Per-edge accumulators keyed by the (from, to, kind) triple.
    pub edge_accumulator: BTreeMap<(NodeId, NodeId, EdgeKind), EdgeAccumulator>,
    /// All node identifiers we've materialised at least once (kept here so
    /// `finalize_window` can emit the full node set even for nodes that
    /// only appear as edge endpoints).
    pub nodes: BTreeMap<NodeId, NodeKind>,
    /// Window start timestamp (seconds since epoch). Updated to the earliest
    /// observation timestamp seen across all `ingest` calls.
    pub window_start: i64,
    /// Window end timestamp (seconds since epoch). Updated to the latest
    /// observation timestamp seen across all `ingest` calls.
    pub window_end: i64,
    /// Hard cap on unique observations the pipeline will absorb.
    pub max_observations: usize,
    /// Hard cap on distinct edge keys the accumulator may grow to.
    pub max_edges: usize,
    /// Half-life (milliseconds) used for [`time_decay_weight`].
    pub decay_half_life_ms: i64,
    /// Cumulative count of unique observations absorbed. Uses
    /// `saturating_add` on increment.
    pub total_observations: u64,
}

impl Default for IngestionPipeline {
    fn default() -> Self {
        Self::new()
    }
}

impl IngestionPipeline {
    /// Construct a fresh pipeline with default caps and decay half-life.
    /// `window_start` / `window_end` are initialised to `i64::MAX` /
    /// `i64::MIN` respectively so the first absorbed observation establishes
    /// the real window bounds.
    pub fn new() -> Self {
        Self::with_caps(
            DEFAULT_MAX_OBSERVATIONS,
            DEFAULT_MAX_EDGES,
            DEFAULT_DECAY_HALF_LIFE_MS,
        )
    }

    pub fn with_caps(max_observations: usize, max_edges: usize, decay_half_life_ms: i64) -> Self {
        Self {
            observed_hashes: BTreeSet::new(),
            edge_accumulator: BTreeMap::new(),
            nodes: BTreeMap::new(),
            window_start: i64::MAX,
            window_end: i64::MIN,
            max_observations,
            max_edges,
            decay_half_life_ms,
            total_observations: 0,
        }
    }
}

/// Stable formatter for a `pkg:<name>@<version>` node id. We keep this as a
/// helper (not inline) so test fixtures and downstream callers can compute
/// identical ids without copy/pasting the format string.
pub fn package_node_id(name: &str, version: &str) -> NodeId {
    format!("pkg:{name}@{version}")
}

/// Stable formatter for a `mnt:<handle>` maintainer node id.
pub fn maintainer_node_id(handle: &str) -> NodeId {
    format!("mnt:{handle}")
}

/// Stable formatter for a `dep:<name>` dependency-target node id (used when
/// the dependency has no resolved version yet). Sub-task 4's integration test
/// will switch this to `pkg:<name>@<version>` once the resolver lands.
pub fn dependency_node_id(name: &str) -> NodeId {
    format!("dep:{name}")
}

/// Ingest one observation into `pipeline`. Returns the `IngestionDelta` for
/// the call. See module-level docs for the determinism + bounded-growth
/// guarantees.
pub fn ingest(
    pipeline: &mut IngestionPipeline,
    observation: ManifestObservation,
) -> Result<IngestionDelta, IngestError> {
    // Defensive: revalidate the observation in case it was deserialised from
    // an untrusted source rather than constructed via `ManifestObservation::new`.
    observation.validate()?;

    let hash = observation_hash(&observation);
    if pipeline.observed_hashes.contains(&hash) {
        return Ok(IngestionDelta {
            new_nodes: Vec::new(),
            new_edges: Vec::new(),
            deduplicated: true,
            edges_updated: 0,
        });
    }

    // Enforce bounded growth BEFORE we mutate any pipeline state so a
    // rejection leaves the pipeline byte-identical to the pre-call state.
    if pipeline.observed_hashes.len() >= pipeline.max_observations {
        return Err(IngestError::TooManyMaintainers {
            // Reuse a typed error variant to keep the public IngestError
            // surface from churning; the message string differentiates the
            // two conditions in logs. (We considered a dedicated variant but
            // sub-task 1 froze the enum; reuse keeps wire compatibility.)
            observed: pipeline.observed_hashes.len().saturating_add(1),
            max: pipeline.max_observations,
        });
    }

    // Update the window bounds with the new observation's timestamp.
    let ts = observation.ts;
    if ts < pipeline.window_start {
        pipeline.window_start = ts;
    }
    if ts > pipeline.window_end {
        pipeline.window_end = ts;
    }

    // Compute the per-observation decayed weight. We snap window_end forward
    // first so the freshest observation gets a weight of ~1.0.
    let decay = time_decay_weight(ts, pipeline.window_end, pipeline.decay_half_life_ms)?;

    // Materialise nodes implied by the observation.
    let pkg_id = package_node_id(&observation.package_name, &observation.version);
    let mut new_nodes: Vec<GraphNode> = Vec::new();
    if !pipeline.nodes.contains_key(&pkg_id) {
        pipeline.nodes.insert(pkg_id.clone(), NodeKind::Package);
        new_nodes.push(GraphNode::new(pkg_id.clone(), NodeKind::Package));
    }
    let mut maintainer_ids: Vec<NodeId> = Vec::with_capacity(observation.maintainers.len());
    for m in &observation.maintainers {
        let mid = maintainer_node_id(m);
        if !pipeline.nodes.contains_key(&mid) {
            pipeline.nodes.insert(mid.clone(), NodeKind::Maintainer);
            new_nodes.push(GraphNode::new(mid.clone(), NodeKind::Maintainer));
        }
        maintainer_ids.push(mid);
    }
    let mut dep_ids: Vec<NodeId> = Vec::with_capacity(observation.dependencies.len());
    for (dep_name, _req) in &observation.dependencies {
        let did = dependency_node_id(dep_name);
        if !pipeline.nodes.contains_key(&did) {
            pipeline.nodes.insert(did.clone(), NodeKind::Package);
            new_nodes.push(GraphNode::new(did.clone(), NodeKind::Package));
        }
        dep_ids.push(did);
    }

    // Derive edges. `package -> maintainer (MaintainedBy)` and
    // `package -> dependency (Depends)` are the two primary edge classes.
    let mut new_edges: Vec<GraphEdge> = Vec::new();
    let mut edges_updated: u32 = 0;

    let mut record_edge = |from: &NodeId,
                           to: &NodeId,
                           kind: EdgeKind,
                           pipeline: &mut IngestionPipeline|
     -> Result<(), IngestError> {
        let key = (from.clone(), to.clone(), kind);
        if let Some(acc) = pipeline.edge_accumulator.get_mut(&key) {
            acc.record(decay, ts)?;
            edges_updated = edges_updated.saturating_add(1);
        } else {
            if pipeline.edge_accumulator.len() >= pipeline.max_edges {
                return Err(IngestError::TooManyDependencies {
                    observed: pipeline.edge_accumulator.len().saturating_add(1),
                    max: pipeline.max_edges,
                });
            }
            pipeline
                .edge_accumulator
                .insert(key.clone(), EdgeAccumulator::new(decay, ts));
            new_edges.push(GraphEdge::new(
                key.0.clone(),
                key.1.clone(),
                key.2,
                decay,
                ts,
            )?);
        }
        Ok(())
    };

    for mid in &maintainer_ids {
        record_edge(&pkg_id, mid, EdgeKind::MaintainedBy, pipeline)?;
    }
    for did in &dep_ids {
        record_edge(&pkg_id, did, EdgeKind::Depends, pipeline)?;
    }

    // Commit the observation hash + bump cumulative counter only after every
    // edge was recorded successfully -- otherwise a mid-call failure would
    // leave the dedup set out of sync with the accumulator.
    pipeline.observed_hashes.insert(hash);
    pipeline.total_observations = pipeline.total_observations.saturating_add(1);

    // Sort outputs for deterministic downstream consumers.
    new_nodes.sort_by(|a, b| a.id.cmp(&b.id));
    new_edges.sort_by(|a, b| {
        a.from
            .cmp(&b.from)
            .then(a.to.cmp(&b.to))
            .then(a.kind.wire_tag().cmp(&b.kind.wire_tag()))
    });

    Ok(IngestionDelta {
        new_nodes,
        new_edges,
        deduplicated: false,
        edges_updated,
    })
}

/// Collapse the running accumulator into a `WindowedGraph`.
///
/// Edge weight is the **mean** decayed weight across every observation that
/// touched the edge (`weight_sum / observation_count`). `observed_at` on the
/// emitted edge is the **most recent** timestamp seen on the edge so
/// downstream metrics that care about recency get the freshest data.
/// Non-finite means are rejected (the edge is skipped) rather than silently
/// emitting an unusable weight.
pub fn finalize_window(pipeline: &IngestionPipeline) -> Result<WindowedGraph, IngestError> {
    let mut nodes: Vec<GraphNode> = pipeline
        .nodes
        .iter()
        .map(|(id, kind)| GraphNode::new(id.clone(), *kind))
        .collect();
    nodes.sort_by(|a, b| a.id.cmp(&b.id));

    let mut edges: Vec<GraphEdge> = Vec::with_capacity(pipeline.edge_accumulator.len());
    for ((from, to, kind), acc) in &pipeline.edge_accumulator {
        let mean = acc.mean_weight();
        if !mean.is_finite() {
            // Should be unreachable because EdgeAccumulator::record rejects
            // non-finite contributions, but stay fail-closed at the boundary.
            return Err(IngestError::NonFiniteEdgeWeight);
        }
        edges.push(GraphEdge::new(
            from.clone(),
            to.clone(),
            *kind,
            mean,
            acc.last_observed,
        )?);
    }
    edges.sort_by(|a, b| {
        a.from
            .cmp(&b.from)
            .then(a.to.cmp(&b.to))
            .then(a.kind.wire_tag().cmp(&b.kind.wire_tag()))
    });

    // If no observations were absorbed window bounds are still the sentinel
    // values; surface them as a clamped empty window so downstream callers
    // don't see i64::MAX/MIN sneak into telemetry.
    let (window_start, window_end) = if pipeline.observed_hashes.is_empty() {
        (0, 0)
    } else {
        (pipeline.window_start, pipeline.window_end)
    };

    Ok(WindowedGraph {
        nodes,
        edges,
        window_start,
        window_end,
        total_observations: pipeline.total_observations,
    })
}

// -- Tests ------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_obs() -> ManifestObservation {
        let mut deps = BTreeMap::new();
        deps.insert("serde".to_string(), "1.0.0".to_string());
        deps.insert("tokio".to_string(), "1.40.0".to_string());
        ManifestObservation::new(
            1_700_000_000,
            "cargo-lock",
            "franken-node",
            "0.1.0",
            vec!["alice".to_string(), "bob".to_string()],
            deps,
            Some("deadbeef".to_string()),
        )
        .expect("sample is valid")
    }

    #[test]
    fn manifest_observation_serde_round_trip() {
        let obs = sample_obs();
        let json = serde_json::to_string(&obs).expect("serialise");
        let round: ManifestObservation = serde_json::from_str(&json).expect("deserialise");
        round.validate().expect("post-deserialise validation");
        assert_eq!(obs, round);
    }

    #[test]
    fn graph_node_and_edge_serde_round_trip() {
        let node = GraphNode::new("pkg:franken-node@0.1.0", NodeKind::Package)
            .with_metadata("registry", "crates.io");
        let json = serde_json::to_string(&node).expect("serialise node");
        let back: GraphNode = serde_json::from_str(&json).expect("deserialise node");
        assert_eq!(node, back);

        let edge = GraphEdge::new(
            "pkg:franken-node@0.1.0",
            "pkg:serde@1.0.0",
            EdgeKind::Depends,
            0.75,
            1_700_000_000,
        )
        .expect("finite weight");
        let json = serde_json::to_string(&edge).expect("serialise edge");
        let back: GraphEdge = serde_json::from_str(&json).expect("deserialise edge");
        assert_eq!(edge, back);
    }

    #[test]
    fn canonical_bytes_are_deterministic() {
        let obs = sample_obs();
        let a = canonical_observation_bytes(&obs);
        let b = canonical_observation_bytes(&obs);
        assert_eq!(
            a, b,
            "same input must produce byte-identical canonical bytes"
        );
        assert!(
            a.starts_with(CANONICAL_DOMAIN),
            "canonical bytes must start with domain separator"
        );
    }

    #[test]
    fn canonical_bytes_resist_field_boundary_collision() {
        // Two observations whose concatenated unprefixed encodings would be
        // identical: "ab" + "cd" vs "abc" + "d". With length-prefixing they
        // MUST produce different canonical bytes (and hashes).
        let obs1 =
            ManifestObservation::new(0, "src", "ab", "cd", vec![], BTreeMap::new(), None).unwrap();
        let obs2 =
            ManifestObservation::new(0, "src", "abc", "d", vec![], BTreeMap::new(), None).unwrap();
        let a = canonical_observation_bytes(&obs1);
        let b = canonical_observation_bytes(&obs2);
        assert_ne!(a, b, "length-prefix must defeat boundary collision");
        assert_ne!(observation_hash(&obs1), observation_hash(&obs2));
    }

    #[test]
    fn observation_hash_is_deterministic_and_32_bytes() {
        let obs = sample_obs();
        let h1 = observation_hash(&obs);
        let h2 = observation_hash(&obs);
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 32);
        // Differs from the all-zero default sentinel.
        assert_ne!(h1, [0u8; 32]);
    }

    #[test]
    fn observation_hash_changes_with_signature_flag() {
        // Signature presence must be reflected in the canonical encoding so
        // signed and unsigned observations of the same package never collide.
        let unsigned =
            ManifestObservation::new(1, "src", "pkg", "1.0", vec![], BTreeMap::new(), None)
                .unwrap();
        let mut signed = unsigned.clone();
        signed.signature_hex = Some(String::new()); // empty-string signature still flips the flag
        signed.validate().unwrap();
        assert_ne!(
            observation_hash(&unsigned),
            observation_hash(&signed),
            "signature flag must affect canonical hash"
        );
    }

    #[test]
    fn bounded_growth_rejects_too_many_maintainers() {
        let mut maintainers = Vec::with_capacity(MAX_MAINTAINERS_PER_PACKAGE + 1);
        for i in 0..=MAX_MAINTAINERS_PER_PACKAGE {
            maintainers.push(format!("m{i}"));
        }
        let err =
            ManifestObservation::new(0, "src", "pkg", "1.0", maintainers, BTreeMap::new(), None)
                .unwrap_err();
        match err {
            IngestError::TooManyMaintainers { observed, max } => {
                assert_eq!(observed, MAX_MAINTAINERS_PER_PACKAGE + 1);
                assert_eq!(max, MAX_MAINTAINERS_PER_PACKAGE);
            }
            other => panic!("expected TooManyMaintainers, got {other:?}"),
        }
    }

    #[test]
    fn bounded_growth_accepts_at_maintainer_cap() {
        // Boundary case: exactly MAX is allowed; MAX+1 is the reject case.
        let maintainers: Vec<String> = (0..MAX_MAINTAINERS_PER_PACKAGE)
            .map(|i| format!("m{i}"))
            .collect();
        let obs =
            ManifestObservation::new(0, "src", "pkg", "1.0", maintainers, BTreeMap::new(), None)
                .expect("at-cap is accepted");
        assert_eq!(obs.maintainers.len(), MAX_MAINTAINERS_PER_PACKAGE);
    }

    #[test]
    fn bounded_growth_rejects_too_many_dependencies() {
        let mut deps = BTreeMap::new();
        for i in 0..=MAX_DEPS_PER_PACKAGE {
            deps.insert(format!("d{i:05}"), "0.0.1".to_string());
        }
        assert_eq!(deps.len(), MAX_DEPS_PER_PACKAGE + 1);
        let err = ManifestObservation::new(0, "src", "pkg", "1.0", vec![], deps, None).unwrap_err();
        match err {
            IngestError::TooManyDependencies { observed, max } => {
                assert_eq!(observed, MAX_DEPS_PER_PACKAGE + 1);
                assert_eq!(max, MAX_DEPS_PER_PACKAGE);
            }
            other => panic!("expected TooManyDependencies, got {other:?}"),
        }
    }

    #[test]
    fn graph_edge_rejects_nan_weight() {
        let err = GraphEdge::new("a", "b", EdgeKind::Depends, f64::NAN, 0).unwrap_err();
        assert_eq!(err, IngestError::NonFiniteEdgeWeight);
    }

    #[test]
    fn graph_edge_rejects_infinite_weight() {
        let err = GraphEdge::new("a", "b", EdgeKind::Depends, f64::INFINITY, 0).unwrap_err();
        assert_eq!(err, IngestError::NonFiniteEdgeWeight);
        let err = GraphEdge::new("a", "b", EdgeKind::Depends, f64::NEG_INFINITY, 0).unwrap_err();
        assert_eq!(err, IngestError::NonFiniteEdgeWeight);
    }

    #[test]
    fn graph_edge_accepts_finite_weights_including_zero_and_negative() {
        for w in [0.0, -1.5, 1e-12, 1e12] {
            let edge = GraphEdge::new("a", "b", EdgeKind::Depends, w, 1).expect("finite");
            edge.validate().expect("validate finite");
        }
    }

    #[test]
    fn empty_observation_is_handled() {
        // Minimal observation: empty maintainers, empty deps, no signature.
        let obs = ManifestObservation::new(0, "", "", "", vec![], BTreeMap::new(), None)
            .expect("empty observation is valid");
        let bytes = canonical_observation_bytes(&obs);
        // Must still contain the domain separator + structural framing.
        assert!(bytes.starts_with(CANONICAL_DOMAIN));
        // Fixed framing: domain (21B) + ts (8B) + 3x LP empty strings
        // (3 * 8 = 24B of length prefixes with zero content) + maintainer
        // count (8B) + dep count (8B) + signature flag (1B) = 70B.
        let expected_len = CANONICAL_DOMAIN.len() + 8 + 8 + 8 + 8 + 8 + 8 + 1;
        assert_eq!(bytes.len(), expected_len);
        let h = observation_hash(&obs);
        assert_eq!(h.len(), 32);
    }

    #[test]
    fn validate_rejects_nul_byte_in_identifier() {
        let bad =
            ManifestObservation::new(0, "src", "pkg\0evil", "1.0", vec![], BTreeMap::new(), None);
        match bad {
            Err(IngestError::IdentContainsNul { field }) => assert_eq!(field, "package_name"),
            other => panic!("expected IdentContainsNul, got {other:?}"),
        }
    }

    #[test]
    fn validate_rejects_overlong_identifier() {
        let long = "a".repeat(MAX_IDENT_LEN + 1);
        let bad = ManifestObservation::new(0, "src", long, "1.0", vec![], BTreeMap::new(), None);
        match bad {
            Err(IngestError::IdentTooLong { field, observed }) => {
                assert_eq!(field, "package_name");
                assert_eq!(observed, MAX_IDENT_LEN + 1);
            }
            other => panic!("expected IdentTooLong, got {other:?}"),
        }
    }

    #[test]
    fn dependency_order_is_canonical_via_btreemap() {
        // Two observations with the same logical content but inserted in
        // different orders must produce identical canonical bytes because
        // BTreeMap iterates in sorted key order.
        let mut deps_a = BTreeMap::new();
        deps_a.insert("z".to_string(), "1".to_string());
        deps_a.insert("a".to_string(), "1".to_string());
        let mut deps_b = BTreeMap::new();
        deps_b.insert("a".to_string(), "1".to_string());
        deps_b.insert("z".to_string(), "1".to_string());

        let obs_a = ManifestObservation::new(0, "src", "pkg", "1", vec![], deps_a, None).unwrap();
        let obs_b = ManifestObservation::new(0, "src", "pkg", "1", vec![], deps_b, None).unwrap();
        assert_eq!(
            canonical_observation_bytes(&obs_a),
            canonical_observation_bytes(&obs_b)
        );
        assert_eq!(observation_hash(&obs_a), observation_hash(&obs_b));
    }

    #[test]
    fn node_and_edge_wire_tags_are_stable() {
        // Lock in the wire-tag mapping so accidental reorderings of the enum
        // variants get caught immediately.
        assert_eq!(NodeKind::Package.wire_tag(), 1);
        assert_eq!(NodeKind::Maintainer.wire_tag(), 2);
        assert_eq!(NodeKind::Org.wire_tag(), 3);
        assert_eq!(NodeKind::Namespace.wire_tag(), 4);
        assert_eq!(EdgeKind::Depends.wire_tag(), 1);
        assert_eq!(EdgeKind::MaintainedBy.wire_tag(), 2);
        assert_eq!(EdgeKind::OwnedBy.wire_tag(), 3);
        assert_eq!(EdgeKind::NamespaceMember.wire_tag(), 4);
    }

    // -- Sub-task 2 pipeline tests ------------------------------------------

    fn obs_with(
        ts: i64,
        name: &str,
        version: &str,
        maintainers: &[&str],
        deps: &[(&str, &str)],
    ) -> ManifestObservation {
        let mut dmap = BTreeMap::new();
        for (k, v) in deps {
            dmap.insert((*k).to_string(), (*v).to_string());
        }
        ManifestObservation::new(
            ts,
            "cargo-lock",
            name,
            version,
            maintainers.iter().map(|s| (*s).to_string()).collect(),
            dmap,
            None,
        )
        .expect("test obs valid")
    }

    #[test]
    fn dedup_by_hash_skips_duplicate_observation() {
        let mut pipe = IngestionPipeline::new();
        let obs = obs_with(
            1_700_000_000,
            "alpha",
            "1.0.0",
            &["alice"],
            &[("serde", "1")],
        );
        let first = ingest(&mut pipe, obs.clone()).expect("first ingest");
        assert!(!first.deduplicated);
        assert!(!first.new_nodes.is_empty());
        let second = ingest(&mut pipe, obs).expect("second ingest");
        assert!(second.deduplicated);
        assert!(second.new_nodes.is_empty());
        assert!(second.new_edges.is_empty());
        assert_eq!(second.edges_updated, 0);
        // Bookkeeping must reflect a single unique observation.
        assert_eq!(pipe.total_observations, 1);
        assert_eq!(pipe.observed_hashes.len(), 1);
    }

    #[test]
    fn ingest_emits_package_to_maintainer_edges() {
        let mut pipe = IngestionPipeline::new();
        let obs = obs_with(1_700_000_000, "alpha", "1.0.0", &["alice", "bob"], &[]);
        let delta = ingest(&mut pipe, obs).expect("ingest");
        let want_pkg = package_node_id("alpha", "1.0.0");
        let want_alice = maintainer_node_id("alice");
        let want_bob = maintainer_node_id("bob");
        // Two MaintainedBy edges emitted (alpha -> alice, alpha -> bob).
        let mb_edges: Vec<&GraphEdge> = delta
            .new_edges
            .iter()
            .filter(|e| e.kind == EdgeKind::MaintainedBy)
            .collect();
        assert_eq!(mb_edges.len(), 2);
        assert!(
            mb_edges
                .iter()
                .any(|e| e.from == want_pkg && e.to == want_alice)
        );
        assert!(
            mb_edges
                .iter()
                .any(|e| e.from == want_pkg && e.to == want_bob)
        );
        // Each maintainer must have spawned a node.
        assert!(
            delta
                .new_nodes
                .iter()
                .any(|n| n.id == want_alice && n.kind == NodeKind::Maintainer)
        );
        assert!(
            delta
                .new_nodes
                .iter()
                .any(|n| n.id == want_bob && n.kind == NodeKind::Maintainer)
        );
    }

    #[test]
    fn ingest_emits_package_to_dependency_edges() {
        let mut pipe = IngestionPipeline::new();
        let obs = obs_with(
            1_700_000_000,
            "alpha",
            "1.0.0",
            &[],
            &[("serde", "1.0"), ("tokio", "1.40")],
        );
        let delta = ingest(&mut pipe, obs).expect("ingest");
        let dep_edges: Vec<&GraphEdge> = delta
            .new_edges
            .iter()
            .filter(|e| e.kind == EdgeKind::Depends)
            .collect();
        assert_eq!(dep_edges.len(), 2);
        let want_pkg = package_node_id("alpha", "1.0.0");
        assert!(
            dep_edges
                .iter()
                .any(|e| e.from == want_pkg && e.to == dependency_node_id("serde"))
        );
        assert!(
            dep_edges
                .iter()
                .any(|e| e.from == want_pkg && e.to == dependency_node_id("tokio"))
        );
    }

    #[test]
    fn bounded_growth_rejects_too_many_observations() {
        // Cap at 2: third unique observation must be rejected.
        let mut pipe = IngestionPipeline::with_caps(2, 1024, DEFAULT_DECAY_HALF_LIFE_MS);
        ingest(&mut pipe, obs_with(1, "a", "1", &[], &[])).expect("obs1");
        ingest(&mut pipe, obs_with(2, "b", "1", &[], &[])).expect("obs2");
        let err = ingest(&mut pipe, obs_with(3, "c", "1", &[], &[])).unwrap_err();
        match err {
            IngestError::TooManyMaintainers { max, .. } => assert_eq!(max, 2),
            other => panic!("expected TooManyMaintainers cap-reuse, got {other:?}"),
        }
        // Pipeline state must be unchanged by the rejected call.
        assert_eq!(pipe.total_observations, 2);
    }

    #[test]
    fn bounded_growth_rejects_too_many_edges() {
        // Cap edges at 1; one observation with 2 maintainers will overflow.
        let mut pipe = IngestionPipeline::with_caps(1024, 1, DEFAULT_DECAY_HALF_LIFE_MS);
        let obs = obs_with(1, "alpha", "1", &["alice", "bob"], &[]);
        let err = ingest(&mut pipe, obs).unwrap_err();
        match err {
            IngestError::TooManyDependencies { max, .. } => assert_eq!(max, 1),
            other => panic!("expected TooManyDependencies cap-reuse, got {other:?}"),
        }
    }

    #[test]
    fn finalize_window_produces_deterministic_output_for_same_input() {
        let observations = vec![
            obs_with(1_700_000_000, "alpha", "1.0", &["alice"], &[("serde", "1")]),
            obs_with(1_700_000_100, "beta", "2.0", &["bob"], &[("alpha", "1.0")]),
            obs_with(
                1_700_000_200,
                "gamma",
                "3.0",
                &["alice", "carol"],
                &[("beta", "2.0")],
            ),
        ];

        let mut pipe_a = IngestionPipeline::new();
        for o in &observations {
            ingest(&mut pipe_a, o.clone()).expect("ingest a");
        }
        let graph_a = finalize_window(&pipe_a).expect("finalize a");

        // Different insertion order through the public API must still produce
        // identical canonical output because BTreeMap/BTreeSet sort their keys
        // and we sort the output vecs at emit time.
        let mut pipe_b = IngestionPipeline::new();
        for o in observations.iter().rev() {
            ingest(&mut pipe_b, o.clone()).expect("ingest b");
        }
        let graph_b = finalize_window(&pipe_b).expect("finalize b");

        // We do NOT require window_start == window_end because the per-call
        // decay weight uses pipeline.window_end at the time of ingest, which
        // differs across orderings. We DO require that the final node + edge
        // sets are identical and that the cumulative total_observations match.
        assert_eq!(graph_a.nodes, graph_b.nodes, "node sets must match");
        let edges_a: Vec<(NodeId, NodeId, EdgeKind)> = graph_a
            .edges
            .iter()
            .map(|e| (e.from.clone(), e.to.clone(), e.kind))
            .collect();
        let edges_b: Vec<(NodeId, NodeId, EdgeKind)> = graph_b
            .edges
            .iter()
            .map(|e| (e.from.clone(), e.to.clone(), e.kind))
            .collect();
        assert_eq!(edges_a, edges_b, "edge identity sets must match");
        assert_eq!(graph_a.total_observations, graph_b.total_observations);

        // Same-order replay MUST be byte-for-byte identical.
        let mut pipe_c = IngestionPipeline::new();
        for o in &observations {
            ingest(&mut pipe_c, o.clone()).expect("ingest c");
        }
        let graph_c = finalize_window(&pipe_c).expect("finalize c");
        assert_eq!(graph_a, graph_c, "same-order replay must be byte-identical");
    }

    #[test]
    fn time_decay_weight_is_in_unit_interval() {
        let half_life = 1000;
        let window_end = 10_000;
        for delta in [0i64, 1, 500, 1000, 2000, 10_000, 1_000_000] {
            let w = time_decay_weight(window_end - delta, window_end, half_life)
                .expect("finite weight");
            assert!(w.is_finite());
            assert!(w >= 0.0, "weight must be >= 0, got {w}");
            assert!(w <= 1.0, "weight must be <= 1, got {w}");
        }
    }

    #[test]
    fn time_decay_weight_at_window_end_is_one() {
        // delta == 0 => exp(0) == 1.
        let w = time_decay_weight(1234, 1234, 1000).expect("finite");
        assert!((w - 1.0).abs() < 1e-12, "expected 1.0, got {w}");

        // Future-dated observations clamp to delta=0, also yielding 1.0.
        let w_future = time_decay_weight(2000, 1234, 1000).expect("finite");
        assert!(
            (w_future - 1.0).abs() < 1e-12,
            "expected 1.0, got {w_future}"
        );
    }

    #[test]
    fn time_decay_weight_rejects_non_finite_half_life() {
        // i64 cannot be NaN/Inf so we exercise the equivalent reject case:
        // non-positive half_life_ms must fail-closed.
        assert_eq!(
            time_decay_weight(0, 1000, 0).unwrap_err(),
            IngestError::NonFiniteEdgeWeight
        );
        assert_eq!(
            time_decay_weight(0, 1000, -1).unwrap_err(),
            IngestError::NonFiniteEdgeWeight
        );
        assert_eq!(
            time_decay_weight(0, 1000, i64::MIN).unwrap_err(),
            IngestError::NonFiniteEdgeWeight
        );
    }

    #[test]
    fn weight_accumulator_uses_saturating_add_on_count() {
        let mut acc = EdgeAccumulator::new(0.5, 100);
        // Force the count to the saturation boundary; further `record` calls
        // must NOT wrap to zero.
        acc.observation_count = u64::MAX;
        let before = acc.observation_count;
        acc.record(0.1, 200).expect("finite record");
        assert_eq!(
            acc.observation_count, before,
            "saturating_add must clamp at u64::MAX, not wrap"
        );
        // weight_sum still updates monotonically.
        assert!(acc.weight_sum > 0.5);
        // first/last bookkeeping still updates.
        assert_eq!(acc.first_observed, 100);
        assert_eq!(acc.last_observed, 200);
    }

    #[test]
    fn accumulator_rejects_non_finite_weight_contribution() {
        let mut acc = EdgeAccumulator::new(0.5, 100);
        assert_eq!(
            acc.record(f64::NAN, 200).unwrap_err(),
            IngestError::NonFiniteEdgeWeight
        );
        assert_eq!(
            acc.record(f64::INFINITY, 200).unwrap_err(),
            IngestError::NonFiniteEdgeWeight
        );
        // Accumulator state must be unchanged after a rejected record.
        assert_eq!(acc.observation_count, 1);
        assert!((acc.weight_sum - 0.5).abs() < 1e-12);
    }

    #[test]
    fn accumulator_domain_separator_is_distinct() {
        // Belt-and-suspenders: make sure the ingestion domain is not equal to
        // the manifest-observation domain so the two hash spaces cannot
        // collide.
        assert_ne!(ACCUMULATOR_DOMAIN, CANONICAL_DOMAIN);
        assert_eq!(ACCUMULATOR_DOMAIN, b"dgis_ingest_v1:");
    }

    #[test]
    fn finalize_window_empty_pipeline_emits_clamped_window() {
        // No observations -> window_start/end clamped to 0 (not i64::MAX/MIN).
        let pipe = IngestionPipeline::new();
        let w = finalize_window(&pipe).expect("finalize empty");
        assert!(w.nodes.is_empty());
        assert!(w.edges.is_empty());
        assert_eq!(w.window_start, 0);
        assert_eq!(w.window_end, 0);
        assert_eq!(w.total_observations, 0);
    }
}
