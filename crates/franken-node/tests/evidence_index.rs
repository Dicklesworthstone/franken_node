use frankenengine_node::ops::evidence_index::{
    EVIDENCE_INDEX_SCHEMA_VERSION, EvidenceIndex, EvidenceIndexPolicy, EvidenceQuery,
    EvidenceRecord, EvidenceSafetyClass, EvidenceSourceKind, reason_codes,
    render_evidence_index_json,
};

fn policy() -> EvidenceIndexPolicy {
    EvidenceIndexPolicy {
        max_records: 4,
        max_query_results: 3,
        max_field_bytes: 128,
        max_path_bytes: 256,
        max_tags_per_record: 3,
        max_terms_per_record: 16,
        ..EvidenceIndexPolicy::default()
    }
}

fn record(id: &str, path: &str, title: &str) -> EvidenceRecord {
    EvidenceRecord::new(
        id,
        EvidenceSourceKind::DocsSpec,
        EvidenceSafetyClass::RepoContract,
        path,
        title,
    )
}

#[test]
fn evidence_index_rejects_private_coordination_and_raw_state_paths() {
    let index = EvidenceIndex::from_records(
        policy(),
        [
            record("mail", "messages/2026/05/msg.md", "mail"),
            record("agent", "agents/SnowyBeaver/inbox/msg.md", "agent inbox"),
            record("db", ".beads/beads.db", "beads db"),
            record("log", "logs/raw-session.jsonl", "log"),
            record("memory", ".codex/memories/MEMORY.md", "memory"),
            record("binary", "artifacts/screenshots/proof.png", "binary"),
            record("ok", ".beads/issues.jsonl", "exported beads issue"),
        ],
    )
    .expect("index");

    assert_eq!(index.records().len(), 1);
    assert_eq!(index.records()[0].record_id, "ok");
    assert_eq!(index.report().rejected_sources.len(), 6);
    assert!(
        index
            .report()
            .rejected_sources
            .iter()
            .all(|source| source.reason_code == reason_codes::PROTECTED_SOURCE_REJECTED)
    );
}

#[test]
fn evidence_index_bounds_records_and_detects_stale_sources() {
    let mut bounded_policy = policy();
    bounded_policy.max_records = 2;

    let index = EvidenceIndex::from_records(
        bounded_policy,
        [
            record("rec-a", "docs/specs/a.md", "alpha")
                .with_source_mtime_seconds(10)
                .with_observed_mtime_seconds(11),
            record("rec-b", "docs/specs/b.md", "beta"),
            record("rec-c", "docs/specs/c.md", "gamma"),
        ],
    )
    .expect("index");

    assert_eq!(index.records().len(), 2);
    assert_eq!(index.report().capped_records, 1);
    assert_eq!(index.report().stale_sources.len(), 1);
    assert_eq!(
        index.report().stale_sources[0].reason_code,
        reason_codes::SOURCE_STALE
    );
}

#[test]
fn evidence_index_queries_by_bead_terms_and_agent_with_stable_ties() {
    let index = EvidenceIndex::from_records(
        policy(),
        [
            record("rec-b", "docs/specs/b.md", "validation proof")
                .with_bead_id("bd-38hez.5")
                .with_agent_name("SnowyBeaver")
                .with_tags(["proof", "swarm"]),
            record("rec-a", "artifacts/validation/a.json", "validation proof")
                .with_bead_id("bd-38hez.5")
                .with_tags(["proof"]),
            record("rec-c", "docs/specs/c.md", "validation proof").with_bead_id("bd-other"),
        ],
    )
    .expect("index");

    let ranked = index.query(
        &EvidenceQuery::new()
            .with_bead_id("bd-38hez.5")
            .with_term("proof")
            .with_agent_name("SnowyBeaver")
            .with_limit(2),
    );

    assert_eq!(
        ranked
            .iter()
            .map(|result| (result.record_id.as_str(), result.score))
            .collect::<Vec<_>>(),
        vec![("rec-b", 85), ("rec-a", 60)]
    );
    assert_eq!(
        index
            .query(&EvidenceQuery::new().with_bead_id("bd-38hez.5"))
            .iter()
            .map(|result| result.record_id.as_str())
            .collect::<Vec<_>>(),
        vec!["rec-a", "rec-b"]
    );
}

#[test]
fn evidence_index_truncates_tag_and_term_growth_per_record() {
    let mut bounded_policy = policy();
    bounded_policy.max_tags_per_record = 2;
    bounded_policy.max_terms_per_record = 3;

    let index = EvidenceIndex::from_records(
        bounded_policy,
        [record(
            "rec-tags",
            "docs/specs/tags.md",
            "alpha beta gamma delta epsilon",
        )
        .with_summary("kappa lambda mu")
        .with_tags(["zeta", "eta", "theta", "iota"])],
    )
    .expect("index");

    assert_eq!(index.records()[0].tags, vec!["eta", "iota"]);
    assert_eq!(index.report().tag_truncated_records, 1);
    assert_eq!(index.report().term_truncated_records, 1);
    assert_eq!(
        index
            .query(&EvidenceQuery::new().with_term("alpha").with_limit(10))
            .len(),
        1
    );
}

#[test]
fn evidence_index_snapshot_json_excludes_internal_maps() {
    let index = EvidenceIndex::from_records(
        policy(),
        [record("rec-json", "docs/specs/json.md", "json")
            .with_proof_artifact("artifacts/proofs/json.json")
            .with_error_code("ERR_EXAMPLE")],
    )
    .expect("index");

    let json = render_evidence_index_json(&index).expect("json");

    assert!(json.contains(EVIDENCE_INDEX_SCHEMA_VERSION));
    assert!(json.contains("rec-json"));
    assert!(!json.contains("by_record_id"));
    assert!(!json.contains("by_term"));
}
