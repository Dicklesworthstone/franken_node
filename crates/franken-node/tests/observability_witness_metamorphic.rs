use frankenengine_node::observability::evidence_ledger::{DecisionKind, EvidenceEntry};
use frankenengine_node::observability::witness_ref::{
    WitnessKind, WitnessRef, WitnessSet, WitnessValidator,
};

fn digest(seed: u8) -> [u8; 32] {
    let mut bytes = [0_u8; 32];
    for (idx, byte) in bytes.iter_mut().enumerate() {
        *byte = seed.wrapping_add(idx as u8).wrapping_add(1);
    }
    bytes
}

fn evidence(decision_id: &str, decision_kind: DecisionKind) -> EvidenceEntry {
    EvidenceEntry {
        schema_version: "observability-witness-metamorphic-v1".to_string(),
        entry_id: None,
        decision_id: decision_id.to_string(),
        decision_kind,
        decision_time: "2026-04-23T00:00:00Z".to_string(),
        timestamp_ms: 1_700_000_000_000,
        trace_id: format!("trace-{decision_id}"),
        epoch_id: 42,
        payload: serde_json::json!({"surface": "witness-log-metamorphic"}),
        size_bytes: 0,
        signature: String::new(),
        prev_entry_hash: String::new(),
    }
}

fn witness(id: &str, kind: WitnessKind, seed: u8) -> WitnessRef {
    WitnessRef::new(id, kind, digest(seed)).with_locator(format!("bundles/{id}.jsonl"))
}

fn set_from(witnesses: &[WitnessRef]) -> WitnessSet {
    let mut set = WitnessSet::new();
    for witness in witnesses {
        set.add(witness.clone());
    }
    set
}

#[test]
fn witness_validation_and_audit_are_invariant_under_permutation() {
    let entry = evidence("obs-witness-mm-quarantine", DecisionKind::Quarantine);
    let witnesses = vec![
        witness("obs-witness-mm-telemetry", WitnessKind::Telemetry, 11),
        witness("obs-witness-mm-state", WitnessKind::StateSnapshot, 29),
        witness("obs-witness-mm-proof", WitnessKind::ProofArtifact, 47),
        witness("obs-witness-mm-external", WitnessKind::ExternalSignal, 83),
    ];
    let reversed_witnesses = witnesses.iter().cloned().rev().collect::<Vec<_>>();

    let forward = set_from(&witnesses);
    let reversed = set_from(&reversed_witnesses);
    assert_eq!(forward.len(), witnesses.len());
    assert_eq!(reversed.len(), witnesses.len());
    assert_ne!(
        forward.refs()[0].witness_id,
        reversed.refs()[0].witness_id,
        "metamorphic input should exercise a real witness-order permutation"
    );

    let mut forward_validator = WitnessValidator::strict();
    let mut reversed_validator = WitnessValidator::strict();
    forward_validator
        .validate(&entry, &forward)
        .expect("strict validation should accept safe witness locators");
    reversed_validator
        .validate(&entry, &reversed)
        .expect("strict validation should accept the same witnesses in reversed order");

    assert_eq!(forward_validator.validated_count(), 1);
    assert_eq!(forward_validator.rejected_count(), 0);
    assert_eq!(
        (
            reversed_validator.validated_count(),
            reversed_validator.rejected_count()
        ),
        (
            forward_validator.validated_count(),
            forward_validator.rejected_count()
        ),
        "permuting witness order must not change validation counters"
    );

    let forward_audit = WitnessValidator::coverage_audit(&[(entry.clone(), forward)]);
    let reversed_audit = WitnessValidator::coverage_audit(&[(entry, reversed)]);
    assert!(forward_audit.is_complete());
    assert!(reversed_audit.is_complete());
    assert_eq!(reversed_audit.total_entries, forward_audit.total_entries);
    assert_eq!(
        reversed_audit.high_impact_entries,
        forward_audit.high_impact_entries
    );
    assert_eq!(
        reversed_audit.high_impact_with_witnesses,
        forward_audit.high_impact_with_witnesses
    );
    assert_eq!(
        reversed_audit.total_witnesses,
        forward_audit.total_witnesses
    );
    assert_eq!(reversed_audit.coverage_pct, forward_audit.coverage_pct);
    assert_eq!(
        reversed_audit.witness_kind_counts, forward_audit.witness_kind_counts,
        "witness kind coverage should be a multiset over witnesses, not insertion order"
    );
}

#[test]
fn uniform_nonzero_witness_digests_are_not_dropped() {
    let entry = evidence("obs-witness-mm-uniform-digest", DecisionKind::Quarantine);
    let uniform = WitnessRef::new(
        "obs-witness-mm-uniform-ff",
        WitnessKind::Telemetry,
        [0xff; 32],
    )
    .with_locator("bundles/obs-witness-mm-uniform-ff.jsonl");
    let witnesses = set_from(&[uniform]);

    assert_eq!(witnesses.len(), 1);
    assert_eq!(witnesses.refs()[0].hash_hex(), "ff".repeat(32));

    WitnessValidator::strict()
        .validate(&entry, &witnesses)
        .expect("uniform nonzero witness digest should be accepted");
}
