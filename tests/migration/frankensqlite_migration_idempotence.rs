//! Migration idempotence and rollback tests for bd-26ux.
//!
//! These tests model deterministic migration from interim in-memory stores to a
//! frankensqlite-backed target representation.

use std::collections::{BTreeMap, BTreeSet};
use std::hash::{Hash, Hasher};

const MIGRATION_DOMAIN_START: &str = "MIGRATION_DOMAIN_START";
const MIGRATION_DOMAIN_COMPLETE: &str = "MIGRATION_DOMAIN_COMPLETE";
const MIGRATION_DOMAIN_FAIL: &str = "MIGRATION_DOMAIN_FAIL";
const MIGRATION_ROLLBACK_START: &str = "MIGRATION_ROLLBACK_START";
const MIGRATION_ROLLBACK_COMPLETE: &str = "MIGRATION_ROLLBACK_COMPLETE";
const MIGRATION_IDEMPOTENCY_VERIFIED: &str = "MIGRATION_IDEMPOTENCY_VERIFIED";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum Domain {
    StateModel,
    FencingTokenState,
    LeaseCoordinationState,
    LeaseServiceState,
    LeaseConflictState,
    SnapshotPolicyState,
    QuarantineStoreState,
    RetentionPolicyState,
    ArtifactPersistenceState,
}

impl Domain {
    const ALL: [Domain; 9] = [
        Self::StateModel,
        Self::FencingTokenState,
        Self::LeaseCoordinationState,
        Self::LeaseServiceState,
        Self::LeaseConflictState,
        Self::SnapshotPolicyState,
        Self::QuarantineStoreState,
        Self::RetentionPolicyState,
        Self::ArtifactPersistenceState,
    ];

    fn as_str(self) -> &'static str {
        match self {
            Self::StateModel => "state_model",
            Self::FencingTokenState => "fencing_token_state",
            Self::LeaseCoordinationState => "lease_coordination_state",
            Self::LeaseServiceState => "lease_service_state",
            Self::LeaseConflictState => "lease_conflict_state",
            Self::SnapshotPolicyState => "snapshot_policy_state",
            Self::QuarantineStoreState => "quarantine_store_state",
            Self::RetentionPolicyState => "retention_policy_state",
            Self::ArtifactPersistenceState => "artifact_persistence_state",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LeaseWindow {
    resource: String,
    start: u64,
    end: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct InterimStores {
    state_roots: BTreeMap<String, (String, u64)>,
    fencing_tokens: BTreeMap<String, u64>,
    lease_coordination: BTreeMap<String, String>,
    lease_service: BTreeMap<String, (String, u64, u64, bool)>,
    lease_conflicts: BTreeMap<String, (String, String)>,
    snapshot_policy: BTreeMap<String, (u64, u64)>,
    quarantine_records: BTreeMap<String, (u64, u64)>,
    retention_policy: BTreeMap<String, String>,
    artifact_persistence: BTreeMap<String, (String, u64)>,
    lease_windows: Vec<LeaseWindow>,
}

impl InterimStores {
    fn seeded_all() -> Self {
        let mut stores = Self::default();

        stores
            .state_roots
            .insert("conn-a".into(), ("hash-a".into(), 3));
        stores
            .state_roots
            .insert("conn-b".into(), ("hash-b".into(), 7));

        stores.fencing_tokens.insert("obj-a".into(), 11);
        stores.fencing_tokens.insert("obj-b".into(), 13);

        stores
            .lease_coordination
            .insert("lease-1".into(), "node-a".into());
        stores
            .lease_coordination
            .insert("lease-2".into(), "node-c".into());

        stores
            .lease_service
            .insert("lease-1".into(), ("holder-a".into(), 100, 160, false));
        stores
            .lease_service
            .insert("lease-2".into(), ("holder-b".into(), 170, 230, false));

        stores
            .lease_conflicts
            .insert("resource-a".into(), ("lease-1".into(), "purpose_priority".into()));

        stores
            .snapshot_policy
            .insert("conn-a".into(), (100, 65_536));
        stores
            .snapshot_policy
            .insert("conn-b".into(), (50, 16_384));

        stores
            .quarantine_records
            .insert("blob-a".into(), (1_024, 1_000));
        stores
            .quarantine_records
            .insert("blob-b".into(), (2_048, 1_010));

        stores
            .retention_policy
            .insert("invoke".into(), "required".into());
        stores
            .retention_policy
            .insert("heartbeat".into(), "ephemeral".into());

        stores
            .artifact_persistence
            .insert("artifact-a".into(), ("invoke".into(), 0));
        stores
            .artifact_persistence
            .insert("artifact-b".into(), ("receipt".into(), 1));

        stores.lease_windows.push(LeaseWindow {
            resource: "resource-a".into(),
            start: 100,
            end: 160,
        });
        stores.lease_windows.push(LeaseWindow {
            resource: "resource-a".into(),
            start: 170,
            end: 230,
        });

        stores
    }

    fn seeded_for(domain: Domain) -> Self {
        let mut all = Self::seeded_all();

        if domain != Domain::StateModel {
            all.state_roots.clear();
        }
        if domain != Domain::FencingTokenState {
            all.fencing_tokens.clear();
        }
        if domain != Domain::LeaseCoordinationState {
            all.lease_coordination.clear();
        }
        if domain != Domain::LeaseServiceState {
            all.lease_service.clear();
        }
        if domain != Domain::LeaseConflictState {
            all.lease_conflicts.clear();
        }
        if domain != Domain::SnapshotPolicyState {
            all.snapshot_policy.clear();
        }
        if domain != Domain::QuarantineStoreState {
            all.quarantine_records.clear();
        }
        if domain != Domain::RetentionPolicyState {
            all.retention_policy.clear();
        }
        if domain != Domain::ArtifactPersistenceState {
            all.artifact_persistence.clear();
        }
        if domain != Domain::LeaseServiceState && domain != Domain::LeaseConflictState {
            all.lease_windows.clear();
        }

        all
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FrankensqliteState {
    rows: BTreeMap<String, String>,
    row_counts: BTreeMap<Domain, usize>,
}

impl FrankensqliteState {
    fn new() -> Self {
        Self {
            rows: BTreeMap::new(),
            row_counts: BTreeMap::new(),
        }
    }

    fn upsert_domain_rows(&mut self, domain: Domain, domain_rows: Vec<(String, String)>) {
        for (k, v) in &domain_rows {
            self.rows.insert(format!("{}:{}", domain.as_str(), k), v.clone());
        }
        self.row_counts.insert(domain, domain_rows.len());
    }

    fn domain_rows(&self, domain: Domain) -> BTreeMap<String, String> {
        let prefix = format!("{}:", domain.as_str());
        self.rows
            .iter()
            .filter_map(|(k, v)| {
                if let Some(stripped) = k.strip_prefix(&prefix) {
                    Some((stripped.to_string(), v.clone()))
                } else {
                    None
                }
            })
            .collect()
    }

    fn checksum(&self) -> u64 {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        self.rows.hash(&mut hasher);
        hasher.finish()
    }

    fn clear(&mut self) {
        self.rows.clear();
        self.row_counts.clear();
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MigrationEvent {
    code: &'static str,
    domain: Option<Domain>,
    run_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum MigrationError {
    DomainFailure(Domain),
}

#[derive(Debug, Default)]
struct MigrationEngine {
    backup: Option<InterimStores>,
}

impl MigrationEngine {
    fn migrate(
        &mut self,
        run_id: &str,
        source: &InterimStores,
        target: &mut FrankensqliteState,
        fail_after_domain: Option<Domain>,
    ) -> Result<Vec<MigrationEvent>, MigrationError> {
        // Stage into an isolated copy to preserve atomic behavior.
        let mut staged = target.clone();
        let mut events = Vec::new();

        for domain in Domain::ALL {
            events.push(MigrationEvent {
                code: MIGRATION_DOMAIN_START,
                domain: Some(domain),
                run_id: run_id.to_string(),
            });

            if fail_after_domain == Some(domain) {
                events.push(MigrationEvent {
                    code: MIGRATION_DOMAIN_FAIL,
                    domain: Some(domain),
                    run_id: run_id.to_string(),
                });
                return Err(MigrationError::DomainFailure(domain));
            }

            staged.upsert_domain_rows(domain, serialize_domain(source, domain));

            events.push(MigrationEvent {
                code: MIGRATION_DOMAIN_COMPLETE,
                domain: Some(domain),
                run_id: run_id.to_string(),
            });
        }

        events.push(MigrationEvent {
            code: MIGRATION_IDEMPOTENCY_VERIFIED,
            domain: None,
            run_id: run_id.to_string(),
        });

        self.backup = Some(source.clone());
        *target = staged;
        Ok(events)
    }

    fn rollback(
        &self,
        run_id: &str,
        source: &mut InterimStores,
        target: &mut FrankensqliteState,
    ) -> Vec<MigrationEvent> {
        let mut events = Vec::new();
        events.push(MigrationEvent {
            code: MIGRATION_ROLLBACK_START,
            domain: None,
            run_id: run_id.to_string(),
        });

        if let Some(backup) = &self.backup {
            *source = backup.clone();
        }
        target.clear();

        events.push(MigrationEvent {
            code: MIGRATION_ROLLBACK_COMPLETE,
            domain: None,
            run_id: run_id.to_string(),
        });
        events
    }
}

fn serialize_domain(source: &InterimStores, domain: Domain) -> Vec<(String, String)> {
    match domain {
        Domain::StateModel => source
            .state_roots
            .iter()
            .map(|(k, (hash, version))| (k.clone(), format!("hash={hash};version={version}")))
            .collect(),
        Domain::FencingTokenState => source
            .fencing_tokens
            .iter()
            .map(|(k, seq)| (k.clone(), format!("seq={seq}")))
            .collect(),
        Domain::LeaseCoordinationState => source
            .lease_coordination
            .iter()
            .map(|(k, selected)| (k.clone(), format!("selected={selected}")))
            .collect(),
        Domain::LeaseServiceState => source
            .lease_service
            .iter()
            .map(|(k, (holder, start, end, revoked))| {
                (
                    k.clone(),
                    format!(
                        "holder={holder};start={start};end={end};revoked={revoked}"
                    ),
                )
            })
            .collect(),
        Domain::LeaseConflictState => source
            .lease_conflicts
            .iter()
            .map(|(resource, (winner, rule))| {
                (
                    resource.clone(),
                    format!("winner={winner};resolution={rule}"),
                )
            })
            .collect(),
        Domain::SnapshotPolicyState => source
            .snapshot_policy
            .iter()
            .map(|(k, (every_updates, every_bytes))| {
                (
                    k.clone(),
                    format!("every_updates={every_updates};every_bytes={every_bytes}"),
                )
            })
            .collect(),
        Domain::QuarantineStoreState => source
            .quarantine_records
            .iter()
            .map(|(k, (size, ingested_at))| {
                (k.clone(), format!("size={size};ingested_at={ingested_at}"))
            })
            .collect(),
        Domain::RetentionPolicyState => source
            .retention_policy
            .iter()
            .map(|(k, class)| (k.clone(), class.clone()))
            .collect(),
        Domain::ArtifactPersistenceState => source
            .artifact_persistence
            .iter()
            .map(|(k, (kind, seq))| (k.clone(), format!("type={kind};seq={seq}")))
            .collect(),
    }
}

fn assert_domain_idempotent(domain: Domain) {
    let source = InterimStores::seeded_for(domain);
    let mut target = FrankensqliteState::new();
    let mut engine = MigrationEngine::default();

    let first = engine
        .migrate("run-idempotent", &source, &mut target, None)
        .expect("first migration should pass");
    assert!(
        first
            .iter()
            .any(|e| e.code == MIGRATION_DOMAIN_START && e.domain == Some(domain))
    );
    assert!(
        first
            .iter()
            .any(|e| e.code == MIGRATION_DOMAIN_COMPLETE && e.domain == Some(domain))
    );

    let expected: BTreeMap<String, String> = serialize_domain(&source, domain).into_iter().collect();
    assert_eq!(target.domain_rows(domain), expected);

    let checksum_1 = target.checksum();
    let row_count_1 = target.domain_rows(domain).len();

    let second = engine
        .migrate("run-idempotent", &source, &mut target, None)
        .expect("second migration should pass");
    assert!(
        second
            .iter()
            .any(|e| e.code == MIGRATION_IDEMPOTENCY_VERIFIED)
    );

    let checksum_2 = target.checksum();
    let row_count_2 = target.domain_rows(domain).len();

    assert_eq!(checksum_1, checksum_2, "rerun changed migrated rows");
    assert_eq!(
        row_count_1, row_count_2,
        "rerun changed row count for domain {}",
        domain.as_str()
    );
}

fn assert_invariants(source: &InterimStores, target: &FrankensqliteState) {
    // Fencing token uniqueness.
    let token_set: BTreeSet<u64> = source.fencing_tokens.values().copied().collect();
    assert_eq!(
        token_set.len(),
        source.fencing_tokens.len(),
        "fencing token uniqueness violated"
    );

    // Lease non-overlap per resource.
    for (i, a) in source.lease_windows.iter().enumerate() {
        for b in source.lease_windows.iter().skip(i + 1) {
            if a.resource == b.resource {
                assert!(
                    a.end <= b.start || b.end <= a.start,
                    "lease windows overlap for {}",
                    a.resource
                );
            }
        }
    }

    // Artifact sequence uniqueness.
    let mut seen = BTreeSet::new();
    for (id, (_, seq)) in &source.artifact_persistence {
        assert!(seen.insert(*seq), "duplicate artifact seq for {id}");
    }

    // Ensure migrated target holds expected lease/fencing rows.
    assert_eq!(
        target.domain_rows(Domain::FencingTokenState).len(),
        source.fencing_tokens.len()
    );
    assert_eq!(
        target.domain_rows(Domain::LeaseServiceState).len(),
        source.lease_service.len()
    );
}

#[test]
fn state_model_migration_is_idempotent() {
    assert_domain_idempotent(Domain::StateModel);
}

#[test]
fn fencing_token_migration_is_idempotent() {
    assert_domain_idempotent(Domain::FencingTokenState);
}

#[test]
fn lease_coordination_migration_is_idempotent() {
    assert_domain_idempotent(Domain::LeaseCoordinationState);
}

#[test]
fn lease_service_migration_is_idempotent() {
    assert_domain_idempotent(Domain::LeaseServiceState);
}

#[test]
fn lease_conflict_migration_is_idempotent() {
    assert_domain_idempotent(Domain::LeaseConflictState);
}

#[test]
fn snapshot_policy_migration_is_idempotent() {
    assert_domain_idempotent(Domain::SnapshotPolicyState);
}

#[test]
fn quarantine_store_migration_is_idempotent() {
    assert_domain_idempotent(Domain::QuarantineStoreState);
}

#[test]
fn retention_policy_migration_is_idempotent() {
    assert_domain_idempotent(Domain::RetentionPolicyState);
}

#[test]
fn artifact_persistence_migration_is_idempotent() {
    assert_domain_idempotent(Domain::ArtifactPersistenceState);
}

#[test]
fn rollback_restores_interim_state() {
    let mut source = InterimStores::seeded_all();
    let source_before = source.clone();
    let mut target = FrankensqliteState::new();
    let mut engine = MigrationEngine::default();

    engine
        .migrate("run-rollback", &source, &mut target, None)
        .expect("initial migration should pass");
    assert!(!target.rows.is_empty(), "migration should write target rows");

    let rollback_events = engine.rollback("run-rollback", &mut source, &mut target);
    assert_eq!(source, source_before, "rollback did not restore source");
    assert!(target.rows.is_empty(), "rollback did not clear target");
    assert!(
        rollback_events
            .iter()
            .any(|e| e.code == MIGRATION_ROLLBACK_START)
    );
    assert!(
        rollback_events
            .iter()
            .any(|e| e.code == MIGRATION_ROLLBACK_COMPLETE)
    );
}

#[test]
fn partial_failure_is_atomic_and_recoverable() {
    let source = InterimStores::seeded_all();
    let mut target = FrankensqliteState::new();
    let mut engine = MigrationEngine::default();

    let result = engine.migrate(
        "run-partial-failure",
        &source,
        &mut target,
        Some(Domain::SnapshotPolicyState),
    );
    assert!(result.is_err(), "expected simulated migration failure");
    assert!(
        target.rows.is_empty(),
        "target must stay unchanged on partial failure"
    );

    engine
        .migrate("run-recovery", &source, &mut target, None)
        .expect("recovery migration should pass");
    assert!(
        !target.rows.is_empty(),
        "recovery run should populate target after failure"
    );
}

#[test]
fn migrated_data_preserves_source_invariants() {
    let source = InterimStores::seeded_all();
    let mut target = FrankensqliteState::new();
    let mut engine = MigrationEngine::default();

    engine
        .migrate("run-invariants", &source, &mut target, None)
        .expect("migration should pass");

    assert_invariants(&source, &target);
}
