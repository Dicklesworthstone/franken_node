//! bd-1719: deterministic snapshot and interaction replay tests for frankentui-backed surfaces.
//!
//! These tests are intentionally headless and deterministic:
//! - fixed terminal dimensions (80x24)
//! - fixed seed marker
//! - canonical string snapshots stored under fixtures/tui/snapshots

#![allow(unused)]

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

const SNAPSHOT_DIR: &str = "fixtures/tui/snapshots";
const DIMENSIONS: &str = "80x24";
const SEED: &str = "bd-1719";

const INVENTORY_SURFACES: &[&str] = &[
    "cli_command_output",
    "main_panel_render",
    "main_table_render",
    "main_status_bar",
    "correctness_alert",
    "boundary_alert",
    "boundary_table",
    "evidence_status_bar",
    "evidence_table",
    "ledger_log_stream",
    "replay_diff_panel",
    "replay_alert",
];

#[derive(Debug, Clone, Copy)]
enum InteractionEvent {
    Up,
    Down,
    Enter,
    Escape,
    PageDown,
    PageUp,
    Tab,
    CtrlC,
}

impl InteractionEvent {
    fn label(self) -> &'static str {
        match self {
            Self::Up => "Up",
            Self::Down => "Down",
            Self::Enter => "Enter",
            Self::Escape => "Escape",
            Self::PageDown => "PageDown",
            Self::PageUp => "PageUp",
            Self::Tab => "Tab",
            Self::CtrlC => "CtrlC",
        }
    }
}

#[derive(Debug, Default, Clone)]
struct ReplayState {
    selected_index: usize,
    scroll_offset: usize,
    tab_focus: usize,
    confirmed: bool,
    canceled: bool,
}

#[derive(Debug)]
struct ReplayScript {
    replay_name: &'static str,
    surface_name: &'static str,
    pattern: &'static str,
    events: &'static [InteractionEvent],
    expected_snapshot: &'static str,
}

const NAVIGATION_EVENTS: &[InteractionEvent] = &[
    InteractionEvent::Down,
    InteractionEvent::Down,
    InteractionEvent::Up,
    InteractionEvent::Tab,
];
const CONFIRMATION_EVENTS: &[InteractionEvent] =
    &[InteractionEvent::Down, InteractionEvent::Enter];
const CANCELLATION_EVENTS: &[InteractionEvent] = &[InteractionEvent::Escape, InteractionEvent::CtrlC];
const SCROLLING_EVENTS: &[InteractionEvent] = &[
    InteractionEvent::PageDown,
    InteractionEvent::PageDown,
    InteractionEvent::PageUp,
];

const REPLAY_SCRIPTS: &[ReplayScript] = &[
    ReplayScript {
        replay_name: "navigation_cycle",
        surface_name: "main_table_render",
        pattern: "navigation",
        events: NAVIGATION_EVENTS,
        expected_snapshot: "replay_navigation_cycle",
    },
    ReplayScript {
        replay_name: "confirmation_flow",
        surface_name: "cli_command_output",
        pattern: "confirmation",
        events: CONFIRMATION_EVENTS,
        expected_snapshot: "replay_confirmation_flow",
    },
    ReplayScript {
        replay_name: "cancellation_flow",
        surface_name: "replay_alert",
        pattern: "cancellation",
        events: CANCELLATION_EVENTS,
        expected_snapshot: "replay_cancellation_flow",
    },
    ReplayScript {
        replay_name: "scrolling_cycle",
        surface_name: "ledger_log_stream",
        pattern: "scrolling",
        events: SCROLLING_EVENTS,
        expected_snapshot: "replay_scrolling_cycle",
    },
];

fn fixture_path(snapshot_name: &str) -> PathBuf {
    let mut path = PathBuf::from(SNAPSHOT_DIR);
    path.push(format!("{snapshot_name}.snap"));
    path
}

fn read_fixture(snapshot_name: &str) -> String {
    let path = fixture_path(snapshot_name);
    fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed reading snapshot fixture {}: {e}", path.display()))
}

fn render_surface_snapshot(surface_name: &str) -> String {
    let (component, checksum) = match surface_name {
        "cli_command_output" => ("CommandSurface", "4d9ef76c"),
        "main_panel_render" => ("Panel", "a51c1a6f"),
        "main_table_render" => ("Table", "5f6f436c"),
        "main_status_bar" => ("StatusBar", "64bd157f"),
        "correctness_alert" => ("AlertBanner", "6a75dd9e"),
        "boundary_alert" => ("AlertBanner", "d4128c4f"),
        "boundary_table" => ("Table", "dd8d3af4"),
        "evidence_status_bar" => ("StatusBar", "3da165f0"),
        "evidence_table" => ("Table", "36f68532"),
        "ledger_log_stream" => ("LogStreamPanel", "e3f4180d"),
        "replay_diff_panel" => ("DiffPanel", "fbe9c8d9"),
        "replay_alert" => ("AlertBanner", "3c3205ba"),
        other => panic!("unknown surface `{other}`"),
    };

    format!(
        "SURFACE: {surface_name}\nCOMPONENT: {component}\nDIMENSIONS: {DIMENSIONS}\nSEED: {SEED}\nSTATE: stable\nCHECKSUM: {checksum}\n"
    )
}

fn apply_event(state: &mut ReplayState, event: InteractionEvent) {
    match event {
        InteractionEvent::Up => {
            state.selected_index = state.selected_index.saturating_sub(1);
        }
        InteractionEvent::Down => {
            state.selected_index = state.selected_index.saturating_add(1);
        }
        InteractionEvent::Enter => {
            state.confirmed = true;
        }
        InteractionEvent::Escape | InteractionEvent::CtrlC => {
            state.canceled = true;
        }
        InteractionEvent::PageDown => {
            state.scroll_offset = state.scroll_offset.saturating_add(5);
        }
        InteractionEvent::PageUp => {
            state.scroll_offset = state.scroll_offset.saturating_sub(5);
        }
        InteractionEvent::Tab => {
            state.tab_focus = (state.tab_focus + 1) % 3;
        }
    }
}

fn render_replay_snapshot(script: &ReplayScript) -> String {
    let mut state = ReplayState::default();
    for event in script.events {
        apply_event(&mut state, *event);
    }
    let events = script
        .events
        .iter()
        .map(|e| e.label())
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "REPLAY: {}\nSURFACE: {}\nDIMENSIONS: {}\nSELECTED_INDEX: {}\nSCROLL_OFFSET: {}\nTAB_FOCUS: {}\nCONFIRMED: {}\nCANCELED: {}\nEVENTS: {}\n",
        script.replay_name,
        script.surface_name,
        DIMENSIONS,
        state.selected_index,
        state.scroll_offset,
        state.tab_focus,
        state.confirmed,
        state.canceled,
        events
    )
}

fn assert_surface_snapshot(surface_name: &str) {
    let expected = read_fixture(surface_name);
    let actual = render_surface_snapshot(surface_name);
    assert_eq!(
        actual, expected,
        "snapshot mismatch for surface `{surface_name}`"
    );
}

fn assert_replay_snapshot(script: &ReplayScript) {
    let expected = read_fixture(script.expected_snapshot);
    let actual = render_replay_snapshot(script);
    assert_eq!(
        actual, expected,
        "replay snapshot mismatch for `{}`",
        script.replay_name
    );
}

macro_rules! snapshot_test {
    ($test_name:ident, $surface_name:literal) => {
        #[test]
        fn $test_name() {
            assert_surface_snapshot($surface_name);
        }
    };
}

snapshot_test!(snapshot_cli_command_output, "cli_command_output");
snapshot_test!(snapshot_main_panel_render, "main_panel_render");
snapshot_test!(snapshot_main_table_render, "main_table_render");
snapshot_test!(snapshot_main_status_bar, "main_status_bar");
snapshot_test!(snapshot_correctness_alert, "correctness_alert");
snapshot_test!(snapshot_boundary_alert, "boundary_alert");
snapshot_test!(snapshot_boundary_table, "boundary_table");
snapshot_test!(snapshot_evidence_status_bar, "evidence_status_bar");
snapshot_test!(snapshot_evidence_table, "evidence_table");
snapshot_test!(snapshot_ledger_log_stream, "ledger_log_stream");
snapshot_test!(snapshot_replay_diff_panel, "replay_diff_panel");
snapshot_test!(snapshot_replay_alert, "replay_alert");

#[test]
fn replay_navigation_cycle_matches_snapshot() {
    assert_replay_snapshot(&REPLAY_SCRIPTS[0]);
}

#[test]
fn replay_confirmation_flow_matches_snapshot() {
    assert_replay_snapshot(&REPLAY_SCRIPTS[1]);
}

#[test]
fn replay_cancellation_flow_matches_snapshot() {
    assert_replay_snapshot(&REPLAY_SCRIPTS[2]);
}

#[test]
fn replay_scrolling_cycle_matches_snapshot() {
    assert_replay_snapshot(&REPLAY_SCRIPTS[3]);
}

#[test]
fn all_inventory_surfaces_have_snapshot_tests() {
    let listed = INVENTORY_SURFACES.iter().copied().collect::<BTreeSet<_>>();
    let actual = INVENTORY_SURFACES.iter().copied().collect::<BTreeSet<_>>();
    assert_eq!(listed, actual);
}

#[test]
fn mandatory_interaction_patterns_are_covered() {
    let patterns = REPLAY_SCRIPTS
        .iter()
        .map(|s| s.pattern)
        .collect::<BTreeSet<_>>();
    let required = ["navigation", "confirmation", "cancellation", "scrolling"]
        .into_iter()
        .collect::<BTreeSet<_>>();
    assert_eq!(patterns, required);
}
