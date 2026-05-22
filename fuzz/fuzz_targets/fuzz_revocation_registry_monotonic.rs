#![no_main]
#![forbid(unsafe_code)]

//! Structure-aware fuzz coverage for
//! `crates/franken-node/src/supply_chain/revocation_registry.rs`.
//!
//! The revocation registry is a fail-closed supply-chain boundary: stale
//! heads, duplicate revocations, and invalid identifiers must not advance a
//! zone head or append to the canonical recovery log. This harness exercises
//! online operations plus recovery from the emitted canonical log and asserts
//! the observable model stays monotonic.

use arbitrary::Arbitrary;
use frankenengine_node::supply_chain::revocation_registry::{RevocationHead, RevocationRegistry};
use libfuzzer_sys::fuzz_target;
use std::collections::{BTreeMap, BTreeSet};

const MAX_OPS: usize = 64;
const MAX_ID_BYTES: usize = 64;
const DEFAULT_TIMESTAMP: &str = "2026-05-22T00:00:00Z";

fuzz_target!(|case: RegistryCase| {
    let mut registry = RevocationRegistry::new();
    let mut model = Model::default();

    for op in case.ops.into_iter().take(MAX_OPS) {
        match op.kind {
            OperationKind::InitZone => init_zone(&mut registry, &mut model, &op),
            OperationKind::AdvanceFresh => advance_fresh(&mut registry, &mut model, &op),
            OperationKind::AdvanceStale => advance_stale(&mut registry, &model, &op),
            OperationKind::AdvanceDuplicate => advance_duplicate(&mut registry, &mut model, &op),
            OperationKind::AdvanceInvalidZone => advance_invalid_zone(&mut registry, &model, &op),
            OperationKind::AdvanceInvalidArtifact => {
                advance_invalid_artifact(&mut registry, &model, &op);
            }
            OperationKind::QueryState => query_state(&registry, &model, &op),
            OperationKind::RecoverCanonicalLog => assert_recovery_matches_log(&registry),
        }

        assert_registry_matches_model(&registry, &model);
        assert_recovery_matches_log(&registry);
    }
});

fn init_zone(registry: &mut RevocationRegistry, model: &mut Model, op: &RegistryOp) {
    let zone = safe_id(&op.zone, "zone");
    registry.init_zone(&zone).expect("safe zone init must pass");
    model.heads.entry(zone.clone()).or_insert(0);
    model.revoked.entry(zone).or_default();
}

fn advance_fresh(registry: &mut RevocationRegistry, model: &mut Model, op: &RegistryOp) {
    let zone = safe_id(&op.zone, "zone");
    let artifact = model.fresh_artifact(&zone, &op.artifact);
    let sequence = model
        .heads
        .get(&zone)
        .copied()
        .unwrap_or(0)
        .saturating_add(1 + u64::from(op.sequence_step % 8));
    let head = head(&zone, sequence, &artifact, op.trace_selector);
    let log_len_before = registry.canonical_log().len();

    let advanced = registry
        .advance_head(head.clone())
        .expect("fresh monotonic revocation must advance");

    assert_eq!(advanced, sequence);
    assert_eq!(registry.canonical_log().len(), log_len_before + 1);
    model.record(head);
    assert!(registry.is_revoked(&zone, &artifact).unwrap());
}

fn advance_stale(registry: &mut RevocationRegistry, model: &Model, op: &RegistryOp) {
    let zone = safe_id(&op.zone, "zone");
    let current = model.heads.get(&zone).copied().unwrap_or(0);
    let stale_sequence = current.saturating_sub(u64::from(op.sequence_step % 4));
    let candidate = model.fresh_artifact_for_query(&zone, &op.artifact);
    let before = Snapshot::from(&*registry);

    let err = registry
        .advance_head(head(&zone, stale_sequence, &candidate, op.trace_selector))
        .expect_err("stale or equal revocation head must fail closed");

    assert_eq!(err.code(), "REV_STALE_HEAD");
    assert_eq!(Snapshot::from(&*registry), before);
}

fn advance_duplicate(registry: &mut RevocationRegistry, model: &mut Model, op: &RegistryOp) {
    let zone = safe_id(&op.zone, "zone");
    if !model
        .revoked
        .get(&zone)
        .is_some_and(|items| !items.is_empty())
    {
        advance_fresh(registry, model, op);
    }

    let artifact = model
        .revoked
        .get(&zone)
        .and_then(|items| items.iter().next())
        .cloned()
        .expect("seeded duplicate target must exist");
    let sequence = model
        .heads
        .get(&zone)
        .copied()
        .unwrap_or(0)
        .saturating_add(1);
    let before = Snapshot::from(&*registry);

    let err = registry
        .advance_head(head(&zone, sequence, &artifact, op.trace_selector))
        .expect_err("duplicate revocation must not advance head");

    assert_eq!(err.code(), "REV_INVALID_INPUT");
    assert_eq!(Snapshot::from(&*registry), before);
}

fn advance_invalid_zone(registry: &mut RevocationRegistry, model: &Model, op: &RegistryOp) {
    let zone = if op.sequence_step.is_multiple_of(2) {
        ""
    } else {
        " \t\n "
    };
    let artifact = model.fresh_artifact_for_query("invalid-zone", &op.artifact);
    let before = Snapshot::from(&*registry);

    let err = registry
        .advance_head(head(zone, 1, &artifact, op.trace_selector))
        .expect_err("invalid zone id must fail closed");

    assert_eq!(err.code(), "REV_INVALID_INPUT");
    assert_eq!(Snapshot::from(&*registry), before);
}

fn advance_invalid_artifact(registry: &mut RevocationRegistry, model: &Model, op: &RegistryOp) {
    let zone = safe_id(&op.zone, "zone");
    let current = model.heads.get(&zone).copied().unwrap_or(0);
    let artifact = if op.sequence_step.is_multiple_of(2) {
        ""
    } else {
        " \n\t "
    };
    let before = Snapshot::from(&*registry);

    let err = registry
        .advance_head(head(
            &zone,
            current.saturating_add(1),
            artifact,
            op.trace_selector,
        ))
        .expect_err("invalid artifact id must fail closed");

    assert_eq!(err.code(), "REV_INVALID_INPUT");
    assert_eq!(Snapshot::from(&*registry), before);
}

fn query_state(registry: &RevocationRegistry, model: &Model, op: &RegistryOp) {
    let zone = safe_id(&op.zone, "zone");
    let artifact = model.fresh_artifact_for_query(&zone, &op.artifact);

    match model.heads.get(&zone).copied() {
        Some(expected_head) => {
            assert_eq!(registry.current_head(&zone).unwrap(), expected_head);
            let expected_revoked = model
                .revoked
                .get(&zone)
                .is_some_and(|items| items.contains(&artifact));
            assert_eq!(
                registry.is_revoked(&zone, &artifact).unwrap(),
                expected_revoked
            );
        }
        None => {
            assert_eq!(
                registry.current_head(&zone).unwrap_err().code(),
                "REV_ZONE_NOT_FOUND"
            );
            assert_eq!(
                registry.is_revoked(&zone, &artifact).unwrap_err().code(),
                "REV_ZONE_NOT_FOUND"
            );
        }
    }
}

fn assert_recovery_matches_log(registry: &RevocationRegistry) {
    let log = registry.canonical_log();
    if log.is_empty() {
        assert_eq!(
            RevocationRegistry::recover_from_log(log)
                .expect_err("empty recovery log must fail")
                .code(),
            "REV_RECOVERY_FAILED"
        );
        return;
    }

    let recovered = RevocationRegistry::recover_from_log(log)
        .expect("canonical online log must always recover");
    let recovered_model = Model::from_log(log);
    assert_registry_matches_model(&recovered, &recovered_model);
}

fn assert_registry_matches_model(registry: &RevocationRegistry, model: &Model) {
    assert_eq!(registry.zone_count(), model.heads.len());
    assert_eq!(registry.total_revocations(), model.total_revocations());
    assert_eq!(registry.canonical_log().len(), model.log.len());

    for (zone, expected_head) in &model.heads {
        assert_eq!(registry.current_head(zone).unwrap(), *expected_head);
        for artifact in model.revoked.get(zone).into_iter().flatten() {
            assert!(
                registry.is_revoked(zone, artifact).unwrap(),
                "recorded artifact must remain revoked: zone={zone} artifact={artifact}"
            );
        }
    }
}

fn head(zone: &str, sequence: u64, artifact: &str, trace_selector: u8) -> RevocationHead {
    RevocationHead {
        zone_id: zone.to_string(),
        sequence,
        revoked_artifact: artifact.to_string(),
        reason: "fuzzed supply-chain revocation".to_string(),
        timestamp: DEFAULT_TIMESTAMP.to_string(),
        trace_id: format!("trace-revocation-{trace_selector}"),
    }
}

fn safe_id(input: &str, fallback: &str) -> String {
    let mut out = String::with_capacity(input.len().min(MAX_ID_BYTES));
    for ch in input.chars() {
        if out.len().saturating_add(ch.len_utf8()) > MAX_ID_BYTES {
            break;
        }
        if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | ':') {
            out.push(ch);
        }
    }

    if out.trim().is_empty() {
        fallback.to_string()
    } else {
        out
    }
}

#[derive(Debug, Default)]
struct Model {
    heads: BTreeMap<String, u64>,
    revoked: BTreeMap<String, BTreeSet<String>>,
    log: Vec<RevocationHead>,
}

impl Model {
    fn from_log(log: &[RevocationHead]) -> Self {
        let mut model = Self::default();
        for entry in log {
            model.record(entry.clone());
        }
        model
    }

    fn record(&mut self, head: RevocationHead) {
        self.heads.insert(head.zone_id.clone(), head.sequence);
        self.revoked
            .entry(head.zone_id.clone())
            .or_default()
            .insert(head.revoked_artifact.clone());
        self.log.push(head);
    }

    fn total_revocations(&self) -> usize {
        self.revoked.values().map(BTreeSet::len).sum()
    }

    fn fresh_artifact(&self, zone: &str, candidate: &str) -> String {
        let base = self.fresh_artifact_for_query(zone, candidate);
        if !self
            .revoked
            .get(zone)
            .is_some_and(|items| items.contains(&base))
        {
            return base;
        }

        let suffix = self
            .revoked
            .get(zone)
            .map_or(0, BTreeSet::len)
            .saturating_add(1);
        format!("{base}-{suffix}")
    }

    fn fresh_artifact_for_query(&self, zone: &str, candidate: &str) -> String {
        let base = safe_id(candidate, "artifact");
        format!("{zone}:{base}")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Snapshot {
    zone_count: usize,
    total_revocations: usize,
    log_entries: Vec<(String, u64, String)>,
}

impl From<&RevocationRegistry> for Snapshot {
    fn from(registry: &RevocationRegistry) -> Self {
        Self {
            zone_count: registry.zone_count(),
            total_revocations: registry.total_revocations(),
            log_entries: registry
                .canonical_log()
                .iter()
                .map(|entry| {
                    (
                        entry.zone_id.clone(),
                        entry.sequence,
                        entry.revoked_artifact.clone(),
                    )
                })
                .collect(),
        }
    }
}

#[derive(Debug, Arbitrary)]
struct RegistryCase {
    ops: Vec<RegistryOp>,
}

#[derive(Debug, Arbitrary)]
struct RegistryOp {
    kind: OperationKind,
    zone: String,
    artifact: String,
    sequence_step: u8,
    trace_selector: u8,
}

#[derive(Debug, Clone, Copy, Arbitrary)]
enum OperationKind {
    InitZone,
    AdvanceFresh,
    AdvanceStale,
    AdvanceDuplicate,
    AdvanceInvalidZone,
    AdvanceInvalidArtifact,
    QueryState,
    RecoverCanonicalLog,
}
