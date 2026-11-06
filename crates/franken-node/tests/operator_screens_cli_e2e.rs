//! `--screen` operator views drawn with frankentui widgets (bd-tenx3.1):
//! `fleet status --screen` and `doctor --screen` render the same state the
//! text and JSON reports read into bordered frankentui panels, and leave the
//! existing text/JSON contracts untouched.

use std::path::Path;
use std::process::{Command, Output};

use frankenengine_node::tools::operator_screens::{
    FleetScreenConvergence, FleetScreenModel, FleetScreenNode, render_fleet_screen,
};

fn cli(workspace: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_franken-node"))
        .current_dir(workspace)
        .env_remove("FRANKEN_NODE_PROFILE")
        .env_remove("FRANKEN_NODE_FLEET_CONTROL_PLANE_URL")
        .env("COLUMNS", "110")
        .env("NO_COLOR", "1")
        .args(args)
        .output()
        .unwrap_or_else(|error| panic!("`{}`: {error}", args.join(" ")))
}

fn workspace() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    let init = cli(
        dir.path(),
        &["init", "--profile", "balanced", "--out-dir", "."],
    );
    assert!(
        init.status.success(),
        "init: {}",
        String::from_utf8_lossy(&init.stderr)
    );
    dir
}

#[test]
fn fleet_screen_draws_nodes_and_pending_quarantine_from_the_fleet_store() {
    let workspace = workspace();
    let agent = cli(
        workspace.path(),
        &[
            "fleet",
            "agent",
            "--node-id",
            "edge-1",
            "--zone",
            "us-east",
            "--once",
            "--json",
        ],
    );
    assert!(
        agent.status.success(),
        "fleet agent: {}\n{}",
        String::from_utf8_lossy(&agent.stdout),
        String::from_utf8_lossy(&agent.stderr)
    );
    let screen = cli(workspace.path(), &["fleet", "status", "--screen"]);
    assert!(
        screen.status.success(),
        "fleet status --screen: {}",
        String::from_utf8_lossy(&screen.stderr)
    );
    let screen = String::from_utf8_lossy(&screen.stdout);
    assert!(screen.contains("fleet: zone all"), "{screen}");
    assert!(screen.contains("edge-1"), "{screen}");
    assert!(screen.contains("us-east"), "{screen}");
    assert!(screen.contains("pending convergence"), "{screen}");
    // Drawn by the Block widget, not pre-formatted text.
    assert!(
        screen
            .lines()
            .next()
            .is_some_and(|line| line.starts_with('┌')),
        "{screen}"
    );
    assert!(
        screen.lines().all(|line| line.chars().count() <= 110),
        "{screen}"
    );

    // The text and JSON contracts are unchanged.
    let text = cli(workspace.path(), &["fleet", "status"]);
    assert!(String::from_utf8_lossy(&text.stdout).starts_with("fleet status: zone=all"));
    let json = cli(workspace.path(), &["fleet", "status", "--json"]);
    let json: serde_json::Value = serde_json::from_slice(&json.stdout).expect("status json");
    assert_eq!(json["schema_version"], "franken-node/fleet-status-cli/v1");

    // --screen and --json are exclusive views of one report.
    let both = cli(workspace.path(), &["fleet", "status", "--screen", "--json"]);
    assert!(!both.status.success());
}

#[test]
fn doctor_screen_lists_every_check() {
    let workspace = workspace();
    let json = cli(workspace.path(), &["doctor", "--json"]);
    let report: serde_json::Value = serde_json::from_slice(&json.stdout).expect("doctor json");
    let checks = report["checks"].as_array().expect("checks");
    assert!(!checks.is_empty());
    let screen = cli(workspace.path(), &["doctor", "--screen"]);
    let screen = String::from_utf8_lossy(&screen.stdout);
    assert!(screen.contains("franken-node doctor"), "{screen}");
    assert!(
        screen.contains(&format!("checks {}", checks.len())),
        "{screen}"
    );
    for check in checks.iter().take(5) {
        let code = check["code"].as_str().expect("code");
        assert!(screen.contains(code), "{code} missing:\n{screen}");
    }
}

#[test]
fn fleet_screen_bounds_large_fleets() {
    let nodes = (0..250)
        .map(|index| FleetScreenNode {
            node_id: format!("node-{index:03}"),
            zone_id: "eu".to_string(),
            health: "healthy".to_string(),
            quarantine_version: 1,
            last_seen: "2026-11-06T00:00:00Z".to_string(),
        })
        .collect();
    let screen = render_fleet_screen(
        &FleetScreenModel {
            zone_id: "eu".to_string(),
            transport: "file".to_string(),
            live_control_plane: false,
            control_plane_url: None,
            activated: false,
            healthy_nodes: 250,
            total_nodes: 250,
            active_quarantines: 0,
            active_revocations: 0,
            nodes,
            convergences: vec![FleetScreenConvergence {
                incident_id: "inc-1".to_string(),
                target_kind: "artifact".to_string(),
                target: "npm:x".to_string(),
                progress_pct: 100,
            }],
        },
        100,
    );
    assert!(
        screen.contains("node-199"),
        "bounded table keeps the first 200 rows"
    );
    assert!(
        !screen.contains("node-200"),
        "rows past the bound are omitted"
    );
    assert!(screen.contains("50 more not shown"), "{screen}");
}
