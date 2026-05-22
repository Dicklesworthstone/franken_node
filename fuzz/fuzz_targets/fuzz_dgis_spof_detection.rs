#![no_main]
#![forbid(unsafe_code)]

//! Structure-aware fuzzing for `dgis::spof_detection::detect_spofs`.
//!
//! The harness builds bounded maintainer, publisher, namespace, and package
//! graphs, then pins public invariants the detector promises at the boundary:
//! bounded finding counts, finite severities/shares, chain length consistency,
//! report timestamp/package accounting, and serde round trips for accepted
//! reports.

use std::collections::{BTreeMap, BTreeSet};

use arbitrary::{Arbitrary, Result as ArbResult, Unstructured};
use frankenengine_node::dgis::fragility_model::{
    FragilityFactor, MaintainerProfile, PublisherProfile,
};
use frankenengine_node::dgis::graph_ingestion::{EdgeKind, GraphEdge, GraphNode, NodeKind};
use frankenengine_node::dgis::spof_detection::{
    detect_spofs, SpofDetectorConfig, SpofError, SpofKind, SpofReport, MAX_SPOF_FINDINGS,
};
use libfuzzer_sys::fuzz_target;

const MAX_INPUT_BYTES: usize = 64 * 1024;
const MAX_PACKAGES: usize = 32;
const MAX_MAINTAINERS: usize = 16;
const MAX_PUBLISHERS: usize = 12;
const MAX_NAMESPACES: usize = 12;
const MAX_PUBLISHED_REFS: usize = 8;
const MAX_EDGES: usize = 96;
const MAX_ID_BYTES: usize = 48;
const SECONDS_PER_DAY: i64 = 86_400;
const BASE_NOW: i64 = 1_800_000_000;

#[derive(Debug)]
struct FuzzSpofInput {
    packages: Vec<IdSpec>,
    maintainers: Vec<MaintainerSpec>,
    publishers: Vec<PublisherSpec>,
    namespaces: Vec<NamespaceSpec>,
    edges: Vec<EdgeSpec>,
    config: ConfigSpec,
    now_offset_days: u16,
}

impl<'a> Arbitrary<'a> for FuzzSpofInput {
    fn arbitrary(u: &mut Unstructured<'a>) -> ArbResult<Self> {
        Ok(Self {
            packages: bounded_vec(u, MAX_PACKAGES)?,
            maintainers: bounded_vec(u, MAX_MAINTAINERS)?,
            publishers: bounded_vec(u, MAX_PUBLISHERS)?,
            namespaces: bounded_vec(u, MAX_NAMESPACES)?,
            edges: bounded_vec(u, MAX_EDGES)?,
            config: ConfigSpec::arbitrary(u)?,
            now_offset_days: u16::arbitrary(u)?,
        })
    }
}

#[derive(Debug)]
struct IdSpec(Vec<u8>);

impl<'a> Arbitrary<'a> for IdSpec {
    fn arbitrary(u: &mut Unstructured<'a>) -> ArbResult<Self> {
        let len = u.int_in_range::<usize>(0..=MAX_ID_BYTES)?;
        Ok(Self(u.bytes(len)?.to_vec()))
    }
}

#[derive(Debug)]
struct MaintainerSpec {
    id: IdSpec,
    downloads_per_month: u32,
    key_recovery_setup: bool,
    active_days_ago: u16,
    last_commit: LastCommitSpec,
    bus_factor_seed: u8,
}

impl<'a> Arbitrary<'a> for MaintainerSpec {
    fn arbitrary(u: &mut Unstructured<'a>) -> ArbResult<Self> {
        Ok(Self {
            id: IdSpec::arbitrary(u)?,
            downloads_per_month: u32::arbitrary(u)?,
            key_recovery_setup: bool::arbitrary(u)?,
            active_days_ago: u16::arbitrary(u)?,
            last_commit: LastCommitSpec::arbitrary(u)?,
            bus_factor_seed: u8::arbitrary(u)?,
        })
    }
}

#[derive(Debug)]
enum LastCommitSpec {
    None,
    Past(u16),
    Future(u16),
}

impl<'a> Arbitrary<'a> for LastCommitSpec {
    fn arbitrary(u: &mut Unstructured<'a>) -> ArbResult<Self> {
        match u.int_in_range::<u8>(0..=2)? {
            0 => Ok(Self::None),
            1 => Ok(Self::Past(u16::arbitrary(u)?)),
            _ => Ok(Self::Future(u16::arbitrary(u)?)),
        }
    }
}

#[derive(Debug)]
struct PublisherSpec {
    id: IdSpec,
    org: IdSpec,
    package_refs: Vec<u8>,
    signature_keys_count: u8,
    has_key_rotation_policy: bool,
    recovery_quorum: Option<u8>,
}

impl<'a> Arbitrary<'a> for PublisherSpec {
    fn arbitrary(u: &mut Unstructured<'a>) -> ArbResult<Self> {
        Ok(Self {
            id: IdSpec::arbitrary(u)?,
            org: IdSpec::arbitrary(u)?,
            package_refs: bounded_vec(u, MAX_PUBLISHED_REFS)?,
            signature_keys_count: u8::arbitrary(u)?,
            has_key_rotation_policy: bool::arbitrary(u)?,
            recovery_quorum: Option::<u8>::arbitrary(u)?,
        })
    }
}

#[derive(Debug)]
struct NamespaceSpec {
    id: IdSpec,
    org: IdSpec,
}

impl<'a> Arbitrary<'a> for NamespaceSpec {
    fn arbitrary(u: &mut Unstructured<'a>) -> ArbResult<Self> {
        Ok(Self {
            id: IdSpec::arbitrary(u)?,
            org: IdSpec::arbitrary(u)?,
        })
    }
}

#[derive(Debug)]
struct EdgeSpec {
    from_ref: u8,
    to_ref: u8,
    kind_seed: u8,
    weight_seed: u16,
    observed_offset_days: u16,
}

impl<'a> Arbitrary<'a> for EdgeSpec {
    fn arbitrary(u: &mut Unstructured<'a>) -> ArbResult<Self> {
        Ok(Self {
            from_ref: u8::arbitrary(u)?,
            to_ref: u8::arbitrary(u)?,
            kind_seed: u8::arbitrary(u)?,
            weight_seed: u16::arbitrary(u)?,
            observed_offset_days: u16::arbitrary(u)?,
        })
    }
}

#[derive(Debug)]
struct ConfigSpec {
    single_maintainer_threshold: u8,
    key_person_threshold: u8,
    max_chain_length: u8,
    org_concentration_threshold: u8,
    orphan_threshold_days: u16,
}

impl<'a> Arbitrary<'a> for ConfigSpec {
    fn arbitrary(u: &mut Unstructured<'a>) -> ArbResult<Self> {
        Ok(Self {
            single_maintainer_threshold: u8::arbitrary(u)?,
            key_person_threshold: u8::arbitrary(u)?,
            max_chain_length: u8::arbitrary(u)?,
            org_concentration_threshold: u8::arbitrary(u)?,
            orphan_threshold_days: u16::arbitrary(u)?,
        })
    }
}

impl ConfigSpec {
    fn detector_config(&self) -> SpofDetectorConfig {
        SpofDetectorConfig {
            single_maintainer_threshold: u32::from(self.single_maintainer_threshold % 8),
            key_person_threshold: f64::from(self.key_person_threshold) / f64::from(u8::MAX),
            max_chain_length: u32::from((self.max_chain_length % 16).saturating_add(2)),
            org_concentration_threshold: f64::from(self.org_concentration_threshold)
                / f64::from(u8::MAX),
            orphan_threshold_days: u32::from(self.orphan_threshold_days),
        }
    }
}

fn bounded_vec<'a, T: Arbitrary<'a>>(
    u: &mut Unstructured<'a>,
    max_len: usize,
) -> ArbResult<Vec<T>> {
    let len = u.int_in_range::<usize>(0..=max_len)?;
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        out.push(T::arbitrary(u)?);
    }
    Ok(out)
}

fn normalized_id(prefix: &str, spec: &IdSpec, index: usize) -> String {
    let mut out = String::with_capacity(prefix.len() + spec.0.len() + 8);
    out.push_str(prefix);
    out.push('-');
    if spec.0.is_empty() {
        out.push_str(&index.to_string());
        return out;
    }

    for byte in &spec.0 {
        let ch = match byte % 38 {
            n @ 0..=25 => char::from(b'a'.saturating_add(n)),
            n @ 26..=35 => char::from(b'0'.saturating_add(n - 26)),
            36 => '-',
            _ => '_',
        };
        out.push(ch);
    }
    out
}

fn choose<'a>(values: &'a [String], byte: u8) -> Option<&'a String> {
    if values.is_empty() {
        return None;
    }
    values.get(usize::from(byte) % values.len())
}

fn package_refs(package_ids: &[String], refs: &[u8]) -> Vec<String> {
    let mut selected = BTreeSet::new();
    for byte in refs {
        if let Some(id) = choose(package_ids, *byte) {
            selected.insert(id.clone());
        }
    }
    selected.into_iter().collect()
}

fn last_commit_timestamp(now: i64, spec: &LastCommitSpec) -> Option<i64> {
    match spec {
        LastCommitSpec::None => None,
        LastCommitSpec::Past(days) => {
            Some(now.saturating_sub(i64::from(*days).saturating_mul(SECONDS_PER_DAY)))
        }
        LastCommitSpec::Future(days) => {
            Some(now.saturating_add(i64::from(*days).saturating_mul(SECONDS_PER_DAY)))
        }
    }
}

fn build_input(
    input: &FuzzSpofInput,
    now: i64,
) -> (
    BTreeMap<String, MaintainerProfile>,
    BTreeMap<String, PublisherProfile>,
    Vec<GraphNode>,
    Vec<GraphEdge>,
) {
    let package_ids: Vec<String> = input
        .packages
        .iter()
        .enumerate()
        .map(|(index, spec)| normalized_id("pkg", spec, index))
        .collect();
    let maintainer_ids: Vec<String> = input
        .maintainers
        .iter()
        .enumerate()
        .map(|(index, spec)| normalized_id("mnt", &spec.id, index))
        .collect();
    let publisher_ids: Vec<String> = input
        .publishers
        .iter()
        .enumerate()
        .map(|(index, spec)| normalized_id("pub", &spec.id, index))
        .collect();
    let namespace_ids: Vec<String> = input
        .namespaces
        .iter()
        .enumerate()
        .map(|(index, spec)| normalized_id("ns", &spec.id, index))
        .collect();

    let mut nodes = Vec::with_capacity(
        package_ids.len() + maintainer_ids.len() + publisher_ids.len() + namespace_ids.len(),
    );
    for id in &package_ids {
        nodes.push(GraphNode::new(id.clone(), NodeKind::Package));
    }
    for id in &maintainer_ids {
        nodes.push(GraphNode::new(id.clone(), NodeKind::Maintainer));
    }
    for id in &publisher_ids {
        nodes.push(GraphNode::new(id.clone(), NodeKind::Org));
    }
    for ((index, id), namespace) in namespace_ids
        .iter()
        .enumerate()
        .zip(input.namespaces.iter())
    {
        let org = normalized_id("org", &namespace.org, index);
        nodes.push(GraphNode::new(id.clone(), NodeKind::Namespace).with_metadata("org", org));
    }

    let mut packages_by_maintainer: BTreeMap<String, BTreeSet<String>> = maintainer_ids
        .iter()
        .map(|id| (id.clone(), BTreeSet::new()))
        .collect();
    let mut edges = Vec::new();
    for edge in &input.edges {
        let kind = match edge.kind_seed % 4 {
            0 => EdgeKind::MaintainedBy,
            1 => EdgeKind::Depends,
            2 => EdgeKind::OwnedBy,
            _ => EdgeKind::NamespaceMember,
        };

        let from = match kind {
            EdgeKind::MaintainedBy | EdgeKind::Depends | EdgeKind::NamespaceMember => {
                choose(&package_ids, edge.from_ref).cloned()
            }
            EdgeKind::OwnedBy => choose(&publisher_ids, edge.from_ref).cloned(),
        };
        let to = match kind {
            EdgeKind::MaintainedBy => choose(&maintainer_ids, edge.to_ref).cloned(),
            EdgeKind::Depends => choose(&package_ids, edge.to_ref).cloned(),
            EdgeKind::OwnedBy => choose(&publisher_ids, edge.to_ref).cloned(),
            EdgeKind::NamespaceMember => choose(&namespace_ids, edge.to_ref).cloned(),
        };
        let (Some(from), Some(to)) = (from, to) else {
            continue;
        };

        if kind == EdgeKind::MaintainedBy {
            packages_by_maintainer
                .entry(to.clone())
                .or_default()
                .insert(from.clone());
        }

        let weight = f64::from(edge.weight_seed) / f64::from(u16::MAX);
        let observed_at = now
            .saturating_sub(i64::from(edge.observed_offset_days).saturating_mul(SECONDS_PER_DAY));
        if let Ok(graph_edge) = GraphEdge::new(from, to, kind, weight, observed_at) {
            edges.push(graph_edge);
        }
    }

    let maintainers = input
        .maintainers
        .iter()
        .zip(maintainer_ids.iter())
        .map(|(spec, maintainer_id)| {
            let id = maintainer_id.clone();
            let packages_owned = packages_by_maintainer
                .remove(&id)
                .unwrap_or_default()
                .into_iter()
                .collect();
            (
                id.clone(),
                MaintainerProfile {
                    id,
                    packages_owned,
                    total_downloads_per_month: u64::from(spec.downloads_per_month),
                    key_recovery_setup: spec.key_recovery_setup,
                    active_since: now.saturating_sub(
                        i64::from(spec.active_days_ago).saturating_mul(SECONDS_PER_DAY),
                    ),
                    last_commit_ts: last_commit_timestamp(now, &spec.last_commit),
                    bus_factor: spec.bus_factor_seed % 8,
                },
            )
        })
        .collect();

    let publishers = input
        .publishers
        .iter()
        .zip(publisher_ids.iter())
        .enumerate()
        .map(|(index, (spec, publisher_id))| {
            let id = publisher_id.clone();
            let org_id = Some(normalized_id("org", &spec.org, index));
            (
                id.clone(),
                PublisherProfile {
                    id,
                    org_id,
                    packages_published: package_refs(&package_ids, &spec.package_refs),
                    signature_keys_count: u32::from(spec.signature_keys_count),
                    key_rotation_policy: spec
                        .has_key_rotation_policy
                        .then(|| "fuzz-rotation-policy".to_string()),
                    recovery_quorum: spec.recovery_quorum,
                },
            )
        })
        .collect();

    (maintainers, publishers, nodes, edges)
}

fn assert_finite_share(share: f64, label: &str) {
    assert!(share.is_finite(), "{label} share must be finite");
    assert!(
        (0.0..=1.0).contains(&share),
        "{label} share must stay inside [0.0, 1.0]"
    );
}

fn assert_factor_invariants(factor: &FragilityFactor) {
    if let FragilityFactor::ConcentratedDownloads { share } = factor {
        assert_finite_share(*share, factor.label());
    }
}

fn assert_report_invariants(report: &SpofReport, expected_packages: u32, expected_at: i64) {
    assert!(
        report.spofs.len() <= MAX_SPOF_FINDINGS,
        "SPOF detector must enforce MAX_SPOF_FINDINGS"
    );
    assert_eq!(
        report.evaluated_packages, expected_packages,
        "evaluated package count must match package nodes"
    );
    assert_eq!(
        report.evaluated_at, expected_at,
        "report timestamp must echo the detector input"
    );
    assert_eq!(
        report.has_findings(),
        !report.spofs.is_empty(),
        "has_findings must mirror spofs emptiness"
    );

    for finding in &report.spofs {
        assert!(
            finding.severity.is_finite(),
            "finding severity must be finite"
        );
        assert!(
            (0.0..=1.0).contains(&finding.severity),
            "finding severity must stay inside [0.0, 1.0]"
        );
        assert!(
            !finding.kind.label().is_empty(),
            "SPOF kind telemetry labels must be nonempty"
        );
        for factor in &finding.fragility_factors {
            assert_factor_invariants(factor);
        }
        match &finding.kind {
            SpofKind::SingleMaintainer { .. } | SpofKind::OrphanedPackage { .. } => {}
            SpofKind::KeyPerson { share_of_downloads } => {
                assert_finite_share(*share_of_downloads, finding.kind.label());
            }
            SpofKind::DependencyChain {
                chain_length,
                chain,
            } => {
                assert_eq!(
                    usize::try_from(*chain_length).unwrap_or(usize::MAX),
                    chain.len(),
                    "dependency chain_length must describe chain.len()"
                );
                assert!(
                    !chain.is_empty(),
                    "dependency-chain findings must include a nonempty path"
                );
            }
            SpofKind::OrgConcentration { share, .. } => {
                assert_finite_share(*share, finding.kind.label());
            }
        }
    }

    let encoded = serde_json::to_string(report);
    assert!(encoded.is_ok(), "SPOF reports must serialize to JSON");
    if let Ok(encoded) = encoded {
        let decoded = serde_json::from_str::<SpofReport>(&encoded);
        assert!(decoded.is_ok(), "SPOF reports must deserialize from JSON");
        if let Ok(decoded) = decoded {
            assert_eq!(
                *report, decoded,
                "SPOF report JSON round trip must preserve accepted reports"
            );
        }
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_BYTES {
        return;
    }

    let mut u = Unstructured::new(data);
    let Ok(input) = FuzzSpofInput::arbitrary(&mut u) else {
        return;
    };
    let now =
        BASE_NOW.saturating_add(i64::from(input.now_offset_days).saturating_mul(SECONDS_PER_DAY));
    let config = input.config.detector_config();
    let (maintainers, publishers, nodes, edges) = build_input(&input, now);
    let expected_packages = nodes
        .iter()
        .filter(|node| node.kind == NodeKind::Package)
        .fold(0_u32, |count, _| count.saturating_add(1));

    match detect_spofs(&maintainers, &publishers, &nodes, &edges, &config, now) {
        Ok(report) => assert_report_invariants(&report, expected_packages, now),
        Err(SpofError::InvalidConfig { .. }) => {
            assert!(
                config.validate().is_err(),
                "InvalidConfig may only be returned for an invalid detector config"
            );
        }
        Err(SpofError::NonFiniteValue { field }) => {
            assert!(
                matches!(field, "__no_nonfinite_expected__"),
                "finite fuzz inputs must not produce NonFiniteValue"
            );
        }
    }
});
