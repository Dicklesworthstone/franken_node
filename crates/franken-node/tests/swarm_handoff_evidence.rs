use chrono::{DateTime, TimeZone, Utc};
use frankenengine_node::ops::swarm_handoff::{
    MAX_HANDOFF_ISSUES, SWARM_HANDOFF_EVIDENCE_SCHEMA_VERSION,
    SWARM_HANDOFF_READINESS_SCHEMA_VERSION, SWARM_HANDOFF_SUMMARY_SCHEMA_VERSION,
    SwarmHandoffAgentEvidence, SwarmHandoffBlockerKind, SwarmHandoffCrossRepoBlockerEvidence,
    SwarmHandoffEvidenceError, SwarmHandoffEvidenceInput, SwarmHandoffGitActivityEvidence,
    SwarmHandoffIssueEvidence, SwarmHandoffIssueStatus, SwarmHandoffPolicyConfig,
    SwarmHandoffPolicyDecision, SwarmHandoffRchBuildEvidence, SwarmHandoffRchBuildState,
    SwarmHandoffReservationEvidence, SwarmHandoffVerificationCommandFamily,
    build_swarm_handoff_readiness_report, handoff_reason_codes,
    render_swarm_handoff_readiness_json,
};
use serde_json::Value;

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
            sibling_bead_id: Some("bd-v2bb1".to_string()),
            subsystem: Some("typed persistence models".to_string()),
            blocker_kind: SwarmHandoffBlockerKind::CompileError,
            verification_command_family: Some(SwarmHandoffVerificationCommandFamily::CargoCheck),
            file_path: Some("crates/franken-engine/src/typed_persistence_models.rs".to_string()),
            holder_agent: Some("LavenderElk".to_string()),
            observed_error: Some("rustc E0599".to_string()),
            observed_at: ts(97),
            cleared: false,
            cleared_at: None,
            clearing_commit_hash: None,
        }],
    }
}

fn policy_config() -> SwarmHandoffPolicyConfig {
    SwarmHandoffPolicyConfig {
        local_project_key: Some("/data/projects/franken_node".to_string()),
        agent_activity_grace_secs: 10,
        issue_activity_grace_secs: 10,
        git_activity_grace_secs: 10,
        rch_activity_grace_secs: 10,
    }
}

fn policy_input() -> SwarmHandoffEvidenceInput {
    let mut input = valid_input();
    let issue = input
        .issues
        .first_mut()
        .expect("fixture includes one issue");
    issue.dependency_ids.clear();
    issue.updated_at = Some(ts(60));
    issue.last_comment_at = Some(ts(60));
    input.cross_repo_blockers.clear();
    input.rch_builds.clear();
    input.git_activity.clear();
    input
}

fn issue(
    bead_id: &str,
    title: &str,
    status: SwarmHandoffIssueStatus,
    assignee: Option<&str>,
    updated_at: Option<DateTime<Utc>>,
) -> SwarmHandoffIssueEvidence {
    SwarmHandoffIssueEvidence {
        bead_id: bead_id.to_string(),
        title: title.to_string(),
        status,
        assignee: assignee.map(str::to_string),
        updated_at,
        last_comment_at: None,
        dependency_ids: Vec::new(),
        dependent_ids: Vec::new(),
        blocker_summary: None,
    }
}

fn cross_repo_blocker(
    local_bead_id: &str,
    blocker_kind: SwarmHandoffBlockerKind,
    command_family: SwarmHandoffVerificationCommandFamily,
    holder_agent: Option<&str>,
    cleared: bool,
) -> SwarmHandoffCrossRepoBlockerEvidence {
    SwarmHandoffCrossRepoBlockerEvidence {
        local_bead_id: local_bead_id.to_string(),
        sibling_project_key: "/data/projects/franken_engine".to_string(),
        sibling_bead_id: Some("bd-v2bb1".to_string()),
        subsystem: Some("typed persistence models".to_string()),
        blocker_kind,
        verification_command_family: Some(command_family),
        file_path: Some("crates/franken-engine/src/typed_persistence_models.rs".to_string()),
        holder_agent: holder_agent.map(str::to_string),
        observed_error: Some("rustc E0599".to_string()),
        observed_at: ts(99),
        cleared,
        cleared_at: cleared.then(|| ts(100)),
        clearing_commit_hash: cleared.then(|| "abc1234".to_string()),
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

#[test]
fn policy_classifies_fresh_owner_as_active() {
    let mut input = policy_input();
    let issue = input
        .issues
        .first_mut()
        .expect("fixture includes one issue");
    issue.updated_at = Some(ts(99));

    let outcome = input.classify_handoff_policy("bd-yd91l.1", &policy_config());

    assert_eq!(outcome.decision, SwarmHandoffPolicyDecision::Active);
    assert!(!outcome.reopen_allowed);
    assert!(outcome.required_br_command.is_none());
    assert!(
        outcome
            .reason_codes
            .contains(&handoff_reason_codes::HANDOFF_ACTIVE_RECENT_ISSUE_ACTIVITY.to_string())
    );
}

#[test]
fn policy_treats_owner_active_in_other_project_as_active() {
    let mut input = policy_input();
    input.reservations.clear();
    let issue = input
        .issues
        .first_mut()
        .expect("fixture includes one issue");
    issue.assignee = Some("MistyCreek".to_string());
    input.agents = vec![SwarmHandoffAgentEvidence {
        agent_name: "MistyCreek".to_string(),
        project_key: "/data/projects/franken_engine".to_string(),
        task_description: Some("fix sibling compile blocker".to_string()),
        last_active_at: Some(ts(99)),
        contact_policy: Some("auto".to_string()),
        ack_required_count: 0,
    }];

    let outcome = input.classify_handoff_policy("bd-yd91l.1", &policy_config());

    assert_eq!(outcome.decision, SwarmHandoffPolicyDecision::Active);
    assert!(
        outcome
            .reason_codes
            .contains(&handoff_reason_codes::HANDOFF_ACTIVE_OWNER_OTHER_PROJECT.to_string())
    );
    assert!(
        outcome
            .required_action
            .contains("request a handoff acknowledgement")
    );
}

#[test]
fn policy_waits_on_stale_owner_with_active_rch_build() {
    let mut input = policy_input();
    input.reservations.clear();
    input.agents.clear();
    input.rch_builds = vec![SwarmHandoffRchBuildEvidence {
        build_id: "29831780320149528".to_string(),
        project_id: "franken_node-5d919732".to_string(),
        state: SwarmHandoffRchBuildState::Running,
        command_digest: Some("sha256:def".to_string()),
        worker_id: Some("ts2".to_string()),
        heartbeat_at: Some(ts(99)),
        progress_at: Some(ts(99)),
        detector_progress_stale: false,
        detector_heartbeat_stale: false,
        blocker_bead_id: Some("bd-yd91l.1".to_string()),
    }];

    let outcome = input.classify_handoff_policy("bd-yd91l.1", &policy_config());

    assert_eq!(outcome.decision, SwarmHandoffPolicyDecision::WaitingOnRch);
    assert!(
        outcome
            .reason_codes
            .contains(&handoff_reason_codes::HANDOFF_WAITING_RCH_ACTIVE.to_string())
    );
    assert!(
        outcome
            .required_action
            .contains("Do not mark validation green")
    );
}

#[test]
fn policy_blocks_on_open_dependency_status() {
    let mut input = policy_input();
    let issue = input
        .issues
        .first_mut()
        .expect("fixture includes one issue");
    issue.dependency_ids = vec!["bd-parent".to_string()];
    input.issues.push(SwarmHandoffIssueEvidence {
        bead_id: "bd-parent".to_string(),
        title: "Parent dependency".to_string(),
        status: SwarmHandoffIssueStatus::InProgress,
        assignee: Some("MistyCreek".to_string()),
        updated_at: Some(ts(99)),
        last_comment_at: None,
        dependency_ids: Vec::new(),
        dependent_ids: vec!["bd-yd91l.1".to_string()],
        blocker_summary: Some("dependency still in progress".to_string()),
    });

    let outcome = input.classify_handoff_policy("bd-yd91l.1", &policy_config());

    assert_eq!(
        outcome.decision,
        SwarmHandoffPolicyDecision::BlockedOnKnownDependency
    );
    assert!(
        outcome
            .reason_codes
            .contains(&handoff_reason_codes::HANDOFF_BLOCKED_DEPENDENCY_OPEN.to_string())
    );
    assert!(
        outcome
            .evidence_pointers
            .contains(&"issue:bd-parent".to_string())
    );
}

#[test]
fn policy_marks_stale_owner_active_reservation_as_contested() {
    let mut input = policy_input();
    input.agents.clear();

    let outcome = input.classify_handoff_policy("bd-yd91l.1", &policy_config());

    assert_eq!(
        outcome.decision,
        SwarmHandoffPolicyDecision::StaleButContested
    );
    assert!(
        outcome
            .reason_codes
            .contains(&handoff_reason_codes::HANDOFF_STALE_CONTESTED_RESERVATION.to_string())
    );
    assert!(outcome.required_br_command.is_none());
}

#[test]
fn policy_reopens_after_expired_reservation_without_recent_activity() {
    let mut input = policy_input();
    input.agents.clear();
    let reservation = input
        .reservations
        .first_mut()
        .expect("fixture includes one reservation");
    reservation.expires_at = ts(80);

    let outcome = input.classify_handoff_policy("bd-yd91l.1", &policy_config());

    assert_eq!(outcome.decision, SwarmHandoffPolicyDecision::ReadyToReopen);
    assert!(outcome.reopen_allowed);
    assert!(
        outcome
            .reason_codes
            .contains(&handoff_reason_codes::HANDOFF_READY_EXPIRED_RESERVATION.to_string())
    );
    assert_eq!(
        outcome.required_br_command.as_deref(),
        Some("br update bd-yd91l.1 --status open --assignee \"\" --actor <agent>")
    );
}

#[test]
fn policy_blocks_on_cross_repo_file_holder() {
    let mut input = policy_input();
    input.reservations.clear();
    input.agents.clear();
    input.cross_repo_blockers = vec![SwarmHandoffCrossRepoBlockerEvidence {
        local_bead_id: "bd-yd91l.1".to_string(),
        sibling_project_key: "/data/projects/franken_engine".to_string(),
        sibling_bead_id: Some("bd-v2bb1".to_string()),
        subsystem: Some("typed persistence models".to_string()),
        blocker_kind: SwarmHandoffBlockerKind::ReservationConflict,
        verification_command_family: Some(SwarmHandoffVerificationCommandFamily::CargoCheck),
        file_path: Some("crates/franken-engine/src/typed_persistence_models.rs".to_string()),
        holder_agent: Some("LavenderElk".to_string()),
        observed_error: Some("reserved by sibling agent".to_string()),
        observed_at: ts(99),
        cleared: false,
        cleared_at: None,
        clearing_commit_hash: None,
    }];

    let outcome = input.classify_handoff_policy("bd-yd91l.1", &policy_config());

    assert_eq!(
        outcome.decision,
        SwarmHandoffPolicyDecision::BlockedOnReservation
    );
    assert!(
        outcome
            .reason_codes
            .contains(&handoff_reason_codes::HANDOFF_BLOCKED_CROSS_REPO_RESERVATION.to_string())
    );
    assert!(
        outcome
            .required_action
            .contains("Do not override the sibling repository holder")
    );
    assert!(
        outcome.evidence_pointers.contains(
            &"cross_repo:bd-yd91l.1:reservation_conflict:cargo_check:/data/projects/franken_engine"
                .to_string()
        )
    );
}

#[test]
fn cross_repo_mirror_renders_compile_failure_context_for_agent_mail() {
    let mut input = policy_input();
    input.reservations.clear();
    input.agents.clear();
    input.cross_repo_blockers = vec![cross_repo_blocker(
        "bd-yd91l.1",
        SwarmHandoffBlockerKind::CompileError,
        SwarmHandoffVerificationCommandFamily::CargoCheck,
        None,
        false,
    )];

    let outcome = input.classify_handoff_policy("bd-yd91l.1", &policy_config());
    assert_eq!(
        outcome.decision,
        SwarmHandoffPolicyDecision::BlockedOnKnownDependency
    );
    assert!(
        outcome
            .reason_codes
            .contains(&handoff_reason_codes::HANDOFF_BLOCKED_CROSS_REPO_BLOCKER.to_string())
    );

    let report = build_swarm_handoff_readiness_report(
        &input,
        &policy_config(),
        "cross-repo-compile",
        ts(101),
    );
    let blocker = report
        .cross_repo_blockers
        .first()
        .expect("active cross-repo blocker should render");
    assert_eq!(blocker.local_bead_id, "bd-yd91l.1");
    assert_eq!(blocker.sibling_bead_id.as_deref(), Some("bd-v2bb1"));
    assert_eq!(
        blocker.subsystem.as_deref(),
        Some("typed persistence models")
    );
    assert_eq!(blocker.blocker_kind_label, "compile_error");
    assert_eq!(
        blocker.verification_command_family_label.as_deref(),
        Some("cargo_check")
    );
    assert!(
        blocker
            .action_summary
            .contains("Keep the local bead blocked")
    );
    assert!(
        report
            .agent_mail_markdown
            .contains("command_family=`cargo_check`")
    );
    assert!(
        report
            .agent_mail_markdown
            .contains("subsystem=`typed persistence models`")
    );
}

#[test]
fn cross_repo_mirror_keeps_sibling_rch_in_progress_blocked() {
    let mut input = policy_input();
    input.reservations.clear();
    input.agents.clear();
    input.cross_repo_blockers = vec![cross_repo_blocker(
        "bd-yd91l.1",
        SwarmHandoffBlockerKind::RchInProgress,
        SwarmHandoffVerificationCommandFamily::CargoTest,
        None,
        false,
    )];

    let outcome = input.classify_handoff_policy("bd-yd91l.1", &policy_config());
    assert_eq!(
        outcome.decision,
        SwarmHandoffPolicyDecision::BlockedOnKnownDependency
    );
    assert!(!outcome.reopen_allowed);
    assert!(
        outcome
            .required_action
            .contains("Keep the bead blocked on the sibling validation failure")
    );

    let report =
        build_swarm_handoff_readiness_report(&input, &policy_config(), "cross-repo-rch", ts(101));
    let blocker = report
        .cross_repo_blockers
        .first()
        .expect("active RCH blocker should render");
    assert_eq!(blocker.blocker_kind_label, "rch_in_progress");
    assert_eq!(
        blocker.verification_command_family_label.as_deref(),
        Some("cargo_test")
    );
    assert!(
        blocker
            .action_summary
            .contains("Wait for the sibling RCH proof")
    );
}

#[test]
fn cleared_cross_repo_mirror_surfaces_fix_commit_without_blocking() {
    let mut input = policy_input();
    input.reservations.clear();
    input.agents.clear();
    let issue = input
        .issues
        .first_mut()
        .expect("fixture includes one issue");
    issue.assignee = None;
    input.cross_repo_blockers = vec![cross_repo_blocker(
        "bd-yd91l.1",
        SwarmHandoffBlockerKind::CompileError,
        SwarmHandoffVerificationCommandFamily::CargoCheck,
        None,
        true,
    )];

    let outcome = input.classify_handoff_policy("bd-yd91l.1", &policy_config());
    assert_eq!(outcome.decision, SwarmHandoffPolicyDecision::ReadyToReopen);
    assert!(outcome.reopen_allowed);

    let report = build_swarm_handoff_readiness_report(
        &input,
        &policy_config(),
        "cross-repo-cleared",
        ts(101),
    );
    assert!(report.cross_repo_blockers.is_empty());
    let blocker = report
        .cleared_cross_repo_blockers
        .first()
        .expect("cleared cross-repo blocker should render");
    assert!(blocker.cleared);
    assert_eq!(blocker.cleared_at, Some(ts(100)));
    assert_eq!(blocker.clearing_commit_hash.as_deref(), Some("abc1234"));
    assert!(
        blocker
            .action_summary
            .contains("Sibling blocker is cleared")
    );
    assert!(
        report
            .agent_mail_markdown
            .contains("Cleared cross-repo blockers:")
    );
    assert!(
        report
            .agent_mail_markdown
            .contains("clearing_commit=`abc1234`")
    );
}

#[test]
fn policy_marks_no_recent_mail_or_git_activity_as_abandoned() {
    let mut input = policy_input();
    input.reservations.clear();
    input.agents = vec![SwarmHandoffAgentEvidence {
        agent_name: "PurpleLeopard".to_string(),
        project_key: "/data/projects/franken_node".to_string(),
        task_description: Some("stale task".to_string()),
        last_active_at: Some(ts(20)),
        contact_policy: Some("auto".to_string()),
        ack_required_count: 0,
    }];

    let outcome = input.classify_handoff_policy("bd-yd91l.1", &policy_config());

    assert_eq!(outcome.decision, SwarmHandoffPolicyDecision::Abandoned);
    assert!(!outcome.reopen_allowed);
    assert!(
        outcome
            .reason_codes
            .contains(&handoff_reason_codes::HANDOFF_ABANDONED_NO_RECENT_SIGNALS.to_string())
    );
    assert_eq!(
        outcome.required_br_command.as_deref(),
        Some("br update bd-yd91l.1 --status open --assignee \"\" --actor <agent>")
    );
}

#[test]
fn policy_fails_closed_on_malformed_evidence() {
    let mut input = policy_input();
    input.schema_version = "franken-node/swarm-handoff/evidence/v0".to_string();

    let outcome = input.classify_handoff_policy("bd-yd91l.1", &policy_config());

    assert_eq!(
        outcome.decision,
        SwarmHandoffPolicyDecision::ManualReviewRequired
    );
    assert!(!outcome.reopen_allowed);
    assert!(
        outcome
            .reason_codes
            .contains(&handoff_reason_codes::HANDOFF_MANUAL_REVIEW_MALFORMED_EVIDENCE.to_string())
    );
    assert!(
        outcome
            .required_action
            .contains("do not reopen this bead from malformed evidence")
    );
}

#[test]
fn readiness_report_renders_json_and_human_for_all_policy_decisions()
-> Result<(), Box<dyn std::error::Error>> {
    let input = SwarmHandoffEvidenceInput {
        schema_version: SWARM_HANDOFF_EVIDENCE_SCHEMA_VERSION.to_string(),
        observed_at: ts(100),
        issues: vec![
            issue(
                "bd-active",
                "Fresh owner",
                SwarmHandoffIssueStatus::InProgress,
                Some("ActiveAgent"),
                Some(ts(99)),
            ),
            issue(
                "bd-cross-blocked",
                "Sibling compile blocker",
                SwarmHandoffIssueStatus::InProgress,
                Some("StaleAgent"),
                Some(ts(60)),
            ),
            issue(
                "bd-reservation-blocked",
                "Reserved by another holder",
                SwarmHandoffIssueStatus::InProgress,
                Some("StaleAgent"),
                Some(ts(60)),
            ),
            issue(
                "bd-rch-wait",
                "Live RCH proof",
                SwarmHandoffIssueStatus::InProgress,
                Some("StaleAgent"),
                Some(ts(60)),
            ),
            issue(
                "bd-contested",
                "Self reservation still active",
                SwarmHandoffIssueStatus::InProgress,
                Some("StaleAgent"),
                Some(ts(60)),
            ),
            issue(
                "bd-abandoned",
                "No recent signals",
                SwarmHandoffIssueStatus::InProgress,
                Some("StaleAgent"),
                Some(ts(60)),
            ),
            issue(
                "bd-ready",
                "Expired reservation",
                SwarmHandoffIssueStatus::InProgress,
                Some("StaleAgent"),
                Some(ts(60)),
            ),
            issue(
                "bd-manual",
                "Unknown issue status",
                SwarmHandoffIssueStatus::Unknown,
                Some("StaleAgent"),
                Some(ts(60)),
            ),
        ],
        agents: vec![
            SwarmHandoffAgentEvidence {
                agent_name: "ActiveAgent".to_string(),
                project_key: "/data/projects/franken_node".to_string(),
                task_description: Some("active handoff owner".to_string()),
                last_active_at: Some(ts(99)),
                contact_policy: Some("auto".to_string()),
                ack_required_count: 0,
            },
            SwarmHandoffAgentEvidence {
                agent_name: "StaleAgent".to_string(),
                project_key: "/data/projects/franken_node".to_string(),
                task_description: Some("stale handoff owner".to_string()),
                last_active_at: Some(ts(20)),
                contact_policy: Some("auto".to_string()),
                ack_required_count: 0,
            },
        ],
        reservations: vec![
            SwarmHandoffReservationEvidence {
                holder_agent: "OtherAgent".to_string(),
                project_key: "/data/projects/franken_node".to_string(),
                path_pattern: "crates/franken-node/src/ops/swarm_handoff.rs".to_string(),
                exclusive: true,
                reason: Some("bd-reservation-blocked".to_string()),
                expires_at: ts(160),
                released_at: None,
            },
            SwarmHandoffReservationEvidence {
                holder_agent: "StaleAgent".to_string(),
                project_key: "/data/projects/franken_node".to_string(),
                path_pattern: "crates/franken-node/tests/swarm_handoff_evidence.rs".to_string(),
                exclusive: true,
                reason: Some("bd-contested".to_string()),
                expires_at: ts(160),
                released_at: None,
            },
            SwarmHandoffReservationEvidence {
                holder_agent: "StaleAgent".to_string(),
                project_key: "/data/projects/franken_node".to_string(),
                path_pattern: "crates/franken-node/src/ops/*.rs".to_string(),
                exclusive: true,
                reason: Some("bd-ready".to_string()),
                expires_at: ts(80),
                released_at: None,
            },
        ],
        rch_builds: vec![SwarmHandoffRchBuildEvidence {
            build_id: "rch-bd-rch-wait".to_string(),
            project_id: "franken_node-5d919732".to_string(),
            state: SwarmHandoffRchBuildState::Running,
            command_digest: Some("sha256:wait".to_string()),
            worker_id: Some("ts2".to_string()),
            heartbeat_at: Some(ts(99)),
            progress_at: Some(ts(99)),
            detector_progress_stale: false,
            detector_heartbeat_stale: false,
            blocker_bead_id: Some("bd-rch-wait".to_string()),
        }],
        git_activity: Vec::new(),
        cross_repo_blockers: vec![SwarmHandoffCrossRepoBlockerEvidence {
            local_bead_id: "bd-cross-blocked".to_string(),
            sibling_project_key: "/data/projects/franken_engine".to_string(),
            sibling_bead_id: Some("bd-v2bb1".to_string()),
            subsystem: Some("typed persistence models".to_string()),
            blocker_kind: SwarmHandoffBlockerKind::CompileError,
            verification_command_family: Some(SwarmHandoffVerificationCommandFamily::CargoCheck),
            file_path: Some("crates/franken-engine/src/typed_persistence_models.rs".to_string()),
            holder_agent: None,
            observed_error: Some("rustc E0599".to_string()),
            observed_at: ts(99),
            cleared: false,
            cleared_at: None,
            clearing_commit_hash: None,
        }],
    };

    let report = build_swarm_handoff_readiness_report(
        &input,
        &policy_config(),
        "swarm-readiness-all-decisions",
        ts(101),
    );

    assert_eq!(
        report.schema_version,
        SWARM_HANDOFF_READINESS_SCHEMA_VERSION
    );
    assert_eq!(report.command, "ops swarm-handoff-readiness");
    assert_eq!(report.decisions.len(), 8);
    for decision in [
        SwarmHandoffPolicyDecision::Active,
        SwarmHandoffPolicyDecision::BlockedOnKnownDependency,
        SwarmHandoffPolicyDecision::BlockedOnReservation,
        SwarmHandoffPolicyDecision::WaitingOnRch,
        SwarmHandoffPolicyDecision::StaleButContested,
        SwarmHandoffPolicyDecision::Abandoned,
        SwarmHandoffPolicyDecision::ReadyToReopen,
        SwarmHandoffPolicyDecision::ManualReviewRequired,
    ] {
        assert!(
            report
                .decision_counts
                .iter()
                .any(|count| count.decision == decision && count.count == 1),
            "missing decision count for {decision:?}"
        );
    }

    let blocked = report
        .decisions
        .iter()
        .find(|decision| decision.bead_id == "bd-reservation-blocked")
        .expect("reservation-blocked decision");
    assert_eq!(blocked.blocker_class, "reservation");
    assert_eq!(blocked.reservation_holder.as_deref(), Some("OtherAgent"));
    assert_eq!(blocked.freshness_age_secs, Some(40));

    let cross_repo = report
        .decisions
        .iter()
        .find(|decision| decision.bead_id == "bd-cross-blocked")
        .expect("cross-repo decision");
    assert_eq!(cross_repo.blocker_class, "cross_repo_blocker");
    assert_eq!(report.cross_repo_blockers[0].observed_age_secs, 1);

    let ready = report
        .safe_reopen_commands
        .iter()
        .find(|command| command.bead_id == "bd-ready")
        .expect("ready reopen command");
    assert_eq!(
        ready.command,
        "br update bd-ready --status open --assignee \"\" --actor <agent>"
    );

    let human = &report.agent_mail_markdown;
    assert!(human.contains("bead=`bd-reservation-blocked`"));
    assert!(human.contains("decision=`blocked_on_reservation`"));
    assert!(human.contains("agent=`StaleAgent`"));
    assert!(human.contains("reservation_holder=`OtherAgent`"));
    assert!(human.contains("blocker_class=`reservation`"));
    assert!(human.contains("freshness_age_secs=40"));
    assert!(human.contains("next_action=`Do not override an active file reservation"));
    assert!(human.contains("Safe reopen commands:"));

    let json: Value = serde_json::from_str(&render_swarm_handoff_readiness_json(&report)?)?;
    assert_eq!(
        json["schema_version"],
        SWARM_HANDOFF_READINESS_SCHEMA_VERSION
    );
    assert_eq!(json["decision_counts"][0]["decision"], "active");
    assert_eq!(json["active_agents"][0]["claimed_issue_count"], 1);
    assert_eq!(json["active_reservations"][0]["holder_agent"], "OtherAgent");
    assert_eq!(json["active_rch_builds"][0]["worker_id"], "ts2");

    Ok(())
}

#[test]
fn readiness_report_fails_closed_but_still_renders_malformed_evidence()
-> Result<(), Box<dyn std::error::Error>> {
    let mut input = policy_input();
    input.schema_version = "franken-node/swarm-handoff/evidence/v0".to_string();

    let report =
        build_swarm_handoff_readiness_report(&input, &policy_config(), "swarm-malformed", ts(101));

    assert!(report.evidence_summary.is_none());
    assert!(
        report
            .warnings
            .iter()
            .any(|warning| warning.contains("evidence validation failed"))
    );
    assert_eq!(
        report.decisions[0].decision,
        SwarmHandoffPolicyDecision::ManualReviewRequired
    );
    assert_eq!(report.decisions[0].blocker_class, "manual_review");
    assert!(
        report
            .agent_mail_markdown
            .contains("manual_review_required")
    );
    let json: Value = serde_json::from_str(&render_swarm_handoff_readiness_json(&report)?)?;
    assert!(json.get("evidence_summary").is_none());
    assert_eq!(
        json["warnings"][0],
        "evidence validation failed: invalid swarm handoff evidence schema `franken-node/swarm-handoff/evidence/v0`, expected `franken-node/swarm-handoff/evidence/v1`"
    );

    Ok(())
}
