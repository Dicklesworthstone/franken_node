use chrono::{DateTime, TimeZone, Utc};
use frankenengine_node::ops::swarm_handoff::{
    MAX_HANDOFF_ISSUES, SWARM_HANDOFF_EVIDENCE_SCHEMA_VERSION,
    SWARM_HANDOFF_SUMMARY_SCHEMA_VERSION, SwarmHandoffAgentEvidence, SwarmHandoffBlockerKind,
    SwarmHandoffCrossRepoBlockerEvidence, SwarmHandoffEvidenceError, SwarmHandoffEvidenceInput,
    SwarmHandoffGitActivityEvidence, SwarmHandoffIssueEvidence, SwarmHandoffIssueStatus,
    SwarmHandoffRchBuildEvidence, SwarmHandoffRchBuildState, SwarmHandoffReservationEvidence,
};

fn ts(seconds: i64) -> DateTime<Utc> {
    Utc.timestamp_opt(seconds, 0)
        .single()
        .expect("fixture timestamp should be valid")
}

fn valid_input() -> SwarmHandoffEvidenceInput {
    SwarmHandoffEvidenceInput {
        schema_version: SWARM_HANDOFF_EVIDENCE_SCHEMA_VERSION.to_string(),
        observed_at: ts(100),
        issues: vec![SwarmHandoffIssueEvidence {
            bead_id: "bd-yd91l.1".to_string(),
            title: "Define swarm handoff evidence model".to_string(),
            status: SwarmHandoffIssueStatus::InProgress,
            assignee: Some("PurpleLeopard".to_string()),
            updated_at: Some(ts(90)),
            last_comment_at: Some(ts(95)),
            dependency_ids: vec!["bd-yd91l".to_string()],
            dependent_ids: vec!["bd-yd91l.2".to_string()],
            blocker_summary: None,
        }],
        agents: vec![SwarmHandoffAgentEvidence {
            agent_name: "PurpleLeopard".to_string(),
            project_key: "/data/projects/franken_node".to_string(),
            task_description: Some("handoff evidence".to_string()),
            last_active_at: Some(ts(98)),
            contact_policy: Some("auto".to_string()),
            ack_required_count: 0,
        }],
        reservations: vec![SwarmHandoffReservationEvidence {
            holder_agent: "PurpleLeopard".to_string(),
            project_key: "/data/projects/franken_node".to_string(),
            path_pattern: "crates/franken-node/src/ops/*.rs".to_string(),
            exclusive: true,
            reason: Some("bd-yd91l.1".to_string()),
            expires_at: ts(200),
            released_at: None,
        }],
        rch_builds: vec![SwarmHandoffRchBuildEvidence {
            build_id: "29831780320149527".to_string(),
            project_id: "franken_engine-5d919732".to_string(),
            state: SwarmHandoffRchBuildState::Running,
            command_digest: Some("sha256:abc".to_string()),
            worker_id: Some("vmi1227854".to_string()),
            heartbeat_at: Some(ts(99)),
            progress_at: Some(ts(98)),
            detector_progress_stale: false,
            detector_heartbeat_stale: false,
            blocker_bead_id: Some("bd-v2bb1".to_string()),
        }],
        git_activity: vec![SwarmHandoffGitActivityEvidence {
            project_key: "/data/projects/franken_node".to_string(),
            agent_name: Some("PurpleLeopard".to_string()),
            commit_hash: Some("c53d5f3c".to_string()),
            summary: "add swarm handoff plan".to_string(),
            authored_at: ts(96),
        }],
        cross_repo_blockers: vec![SwarmHandoffCrossRepoBlockerEvidence {
            local_bead_id: "bd-v2bb1".to_string(),
            sibling_project_key: "/data/projects/franken_engine".to_string(),
            blocker_kind: SwarmHandoffBlockerKind::CompileError,
            file_path: Some("crates/franken-engine/src/typed_persistence_models.rs".to_string()),
            holder_agent: Some("LavenderElk".to_string()),
            observed_error: Some("rustc E0599".to_string()),
            observed_at: ts(97),
            cleared: false,
        }],
    }
}

#[test]
fn valid_fixture_summarizes_active_handoff_evidence() {
    let summary = valid_input()
        .validate_and_summarize()
        .expect("valid handoff evidence should summarize");

    assert_eq!(summary.schema_version, SWARM_HANDOFF_SUMMARY_SCHEMA_VERSION);
    assert_eq!(summary.issue_count, 1);
    assert_eq!(summary.in_progress_issue_count, 1);
    assert_eq!(summary.agent_count, 1);
    assert_eq!(summary.exclusive_reservation_count, 1);
    assert_eq!(summary.active_rch_build_count, 1);
    assert_eq!(summary.uncleared_cross_repo_blocker_count, 1);
    assert_eq!(summary.unknown_signal_count, 0);
}

#[test]
fn serde_round_trip_preserves_fixture() {
    let input = valid_input();
    let json = serde_json::to_string(&input).expect("fixture should serialize");
    let parsed: SwarmHandoffEvidenceInput =
        serde_json::from_str(&json).expect("fixture should deserialize");

    assert_eq!(parsed, input);
}

#[test]
fn rejects_wrong_schema_version() {
    let mut input = valid_input();
    input.schema_version = "franken-node/swarm-handoff/evidence/v0".to_string();

    assert!(matches!(
        input.validate_and_summarize(),
        Err(SwarmHandoffEvidenceError::InvalidSchemaVersion { .. })
    ));
}

#[test]
fn rejects_unbounded_issue_list() {
    let mut input = valid_input();
    input.issues = (0..=MAX_HANDOFF_ISSUES)
        .map(|idx| SwarmHandoffIssueEvidence {
            bead_id: format!("bd-{idx}"),
            title: "fixture".to_string(),
            status: SwarmHandoffIssueStatus::Open,
            assignee: None,
            updated_at: None,
            last_comment_at: None,
            dependency_ids: Vec::new(),
            dependent_ids: Vec::new(),
            blocker_summary: None,
        })
        .collect();

    assert!(matches!(
        input.validate_and_summarize(),
        Err(SwarmHandoffEvidenceError::TooManyItems {
            field: "issues",
            ..
        })
    ));
}

#[test]
fn rejects_nul_and_parent_traversal_in_paths() {
    let mut input = valid_input();
    let reservation = input
        .reservations
        .first_mut()
        .expect("fixture includes one reservation");
    reservation.path_pattern = "../AGENTS.md".to_string();
    assert!(matches!(
        input.validate_and_summarize(),
        Err(SwarmHandoffEvidenceError::InvalidString {
            field: "reservation.path_pattern",
            ..
        })
    ));

    let mut input = valid_input();
    let blocker = input
        .cross_repo_blockers
        .first_mut()
        .expect("fixture includes one cross-repo blocker");
    blocker.file_path = Some("crates/franken-engine/src/lib.rs\0".to_string());
    assert!(matches!(
        input.validate_and_summarize(),
        Err(SwarmHandoffEvidenceError::InvalidString {
            field: "cross_repo_blocker.file_path",
            ..
        })
    ));
}

#[test]
fn counts_stale_and_unknown_signals_without_treating_them_as_valid_progress() {
    let mut input = valid_input();
    let issue = input
        .issues
        .first_mut()
        .expect("fixture includes one issue");
    issue.status = SwarmHandoffIssueStatus::Unknown;
    let rch_build = input
        .rch_builds
        .first_mut()
        .expect("fixture includes one RCH build");
    rch_build.state = SwarmHandoffRchBuildState::Unknown;
    rch_build.detector_progress_stale = true;
    let blocker = input
        .cross_repo_blockers
        .first_mut()
        .expect("fixture includes one cross-repo blocker");
    blocker.blocker_kind = SwarmHandoffBlockerKind::Unknown;

    let summary = input
        .validate_and_summarize()
        .expect("unknown signals are valid evidence but not green progress");

    assert_eq!(summary.stale_rch_build_count, 1);
    assert_eq!(summary.unknown_signal_count, 3);
}
