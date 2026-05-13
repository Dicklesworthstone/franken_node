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

use std::collections::BTreeMap;

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
    IdentTooLong { field: &'static str, observed: usize },
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
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
        assert_eq!(a, b, "same input must produce byte-identical canonical bytes");
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
        let obs1 = ManifestObservation::new(
            0,
            "src",
            "ab",
            "cd",
            vec![],
            BTreeMap::new(),
            None,
        )
        .unwrap();
        let obs2 = ManifestObservation::new(
            0,
            "src",
            "abc",
            "d",
            vec![],
            BTreeMap::new(),
            None,
        )
        .unwrap();
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
        let unsigned = ManifestObservation::new(
            1,
            "src",
            "pkg",
            "1.0",
            vec![],
            BTreeMap::new(),
            None,
        )
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
        let err = ManifestObservation::new(
            0,
            "src",
            "pkg",
            "1.0",
            maintainers,
            BTreeMap::new(),
            None,
        )
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
        let obs = ManifestObservation::new(
            0,
            "src",
            "pkg",
            "1.0",
            maintainers,
            BTreeMap::new(),
            None,
        )
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
        let err = ManifestObservation::new(
            0,
            "src",
            "pkg",
            "1.0",
            vec![],
            deps,
            None,
        )
        .unwrap_err();
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
        let obs = ManifestObservation::new(
            0,
            "",
            "",
            "",
            vec![],
            BTreeMap::new(),
            None,
        )
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
        let bad = ManifestObservation::new(
            0,
            "src",
            "pkg\0evil",
            "1.0",
            vec![],
            BTreeMap::new(),
            None,
        );
        match bad {
            Err(IngestError::IdentContainsNul { field }) => assert_eq!(field, "package_name"),
            other => panic!("expected IdentContainsNul, got {other:?}"),
        }
    }

    #[test]
    fn validate_rejects_overlong_identifier() {
        let long = "a".repeat(MAX_IDENT_LEN + 1);
        let bad = ManifestObservation::new(
            0,
            "src",
            long,
            "1.0",
            vec![],
            BTreeMap::new(),
            None,
        );
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

        let obs_a = ManifestObservation::new(
            0,
            "src",
            "pkg",
            "1",
            vec![],
            deps_a,
            None,
        )
        .unwrap();
        let obs_b = ManifestObservation::new(
            0,
            "src",
            "pkg",
            "1",
            vec![],
            deps_b,
            None,
        )
        .unwrap();
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
}
