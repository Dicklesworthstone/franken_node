//! Operator screens rendered with frankentui widgets (bd-tenx3.1).
//!
//! Each screen is a model plus a view: the CLI builds the model from the
//! same state its text and JSON reports read, and the view lays out
//! frankentui widgets (bordered `Block`s, `Paragraph` summaries and `Table`s
//! under a vertical `Flex` layout) into a `Frame`. The frame's buffer is
//! then printed, so `--screen` output is exactly what the widgets drew,
//! without a terminal session. No values are computed in the view.

use frankentui::core::geometry::Rect;
use frankentui::layout::{Constraint, Flex};
use frankentui::render::frame::Frame;
use frankentui::render::grapheme_pool::GraphemePool;
use frankentui::widgets::Widget;
use frankentui::widgets::block::Block;
use frankentui::widgets::borders::Borders;
use frankentui::widgets::paragraph::Paragraph;
use frankentui::widgets::table::{Row, Table};

/// Screens are never narrower than this, whatever the caller asks for.
pub const MIN_SCREEN_WIDTH: u16 = 60;
/// Default width for non-terminal output.
pub const DEFAULT_SCREEN_WIDTH: u16 = 100;
/// Rows shown per table before the screen reports how many were omitted.
pub const MAX_TABLE_ROWS: usize = 200;

/// One node as the fleet store reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FleetScreenNode {
    pub node_id: String,
    pub zone_id: String,
    pub health: String,
    pub quarantine_version: u64,
    pub last_seen: String,
}

/// One quarantine or revocation still converging.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FleetScreenConvergence {
    pub incident_id: String,
    /// What the action targets (`artifact`, `extension`).
    pub target_kind: String,
    pub target: String,
    pub progress_pct: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FleetScreenModel {
    pub zone_id: String,
    pub transport: String,
    pub live_control_plane: bool,
    pub control_plane_url: Option<String>,
    pub activated: bool,
    pub healthy_nodes: u32,
    pub total_nodes: u32,
    pub active_quarantines: u32,
    pub active_revocations: u32,
    pub nodes: Vec<FleetScreenNode>,
    pub convergences: Vec<FleetScreenConvergence>,
}

/// One doctor check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DoctorScreenCheck {
    pub status: String,
    pub code: String,
    pub scope: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DoctorScreenModel {
    pub overall_status: String,
    pub profile: String,
    pub checks: Vec<DoctorScreenCheck>,
}

impl DoctorScreenModel {
    fn count(&self, status: &str) -> usize {
        self.checks
            .iter()
            .filter(|check| check.status.eq_ignore_ascii_case(status))
            .count()
    }
}

/// Lay out `panels` top to bottom, each a fixed number of rows, render each
/// into its area of one frame, and return the frame as text.
fn render_panels(width: u16, panels: &[(u16, &dyn Widget)]) -> String {
    let width = width.max(MIN_SCREEN_WIDTH);
    let height = panels
        .iter()
        .fold(0_u16, |total, (rows, _)| total.saturating_add(*rows))
        .max(1);
    let mut pool = GraphemePool::new();
    let mut frame = Frame::new(width, height, &mut pool);
    let areas = Flex::vertical()
        .constraints(panels.iter().map(|(rows, _)| Constraint::Fixed(*rows)))
        .split(Rect::new(0, 0, width, height));
    for ((_, widget), area) in panels.iter().zip(areas.iter()) {
        widget.render(*area, &mut frame);
    }
    let buffer = &frame.buffer;
    let mut lines = Vec::with_capacity(usize::from(height));
    for y in 0..buffer.height() {
        let mut line = String::with_capacity(usize::from(width));
        for x in 0..buffer.width() {
            line.push(
                buffer
                    .get(x, y)
                    .and_then(|cell| cell.content.as_char())
                    .unwrap_or(' '),
            );
        }
        lines.push(line.trim_end().to_string());
    }
    lines.join("\n")
}

/// Bounded table rows plus an "omitted" note when the list was cut.
fn bounded_rows<T>(items: &[T], row: impl Fn(&T) -> Row) -> (Vec<Row>, Option<String>) {
    let rows = items.iter().take(MAX_TABLE_ROWS).map(row).collect();
    let omitted = items
        .len()
        .checked_sub(MAX_TABLE_ROWS)
        .filter(|omitted| *omitted > 0)
        .map(|omitted| format!("{omitted} more not shown"));
    (rows, omitted)
}

/// A titled panel: borders only. `Block::bordered()` also pads one cell on
/// every side, which the fixed panel heights below do not budget for.
fn panel(title: &str) -> Block<'_> {
    Block::new().borders(Borders::ALL).title(title)
}

/// Rows a bordered table needs: border, header, body (at least one line).
fn table_height(rows: usize) -> u16 {
    u16::try_from(rows.max(1))
        .unwrap_or(u16::MAX)
        .saturating_add(3)
}

#[must_use]
pub fn render_fleet_screen(model: &FleetScreenModel, width: u16) -> String {
    let summary_title = format!(" fleet: zone {} ", model.zone_id);
    let summary = Paragraph::new(format!(
        "transport {}{}  live control plane: {}  activated: {}\n\
         nodes healthy {}/{}  quarantines {}  revocations {}  converging {}",
        model.transport,
        model
            .control_plane_url
            .as_deref()
            .map(|url| format!(" ({url})"))
            .unwrap_or_default(),
        if model.live_control_plane {
            "yes"
        } else {
            "no"
        },
        if model.activated { "yes" } else { "no" },
        model.healthy_nodes,
        model.total_nodes,
        model.active_quarantines,
        model.active_revocations,
        model.convergences.len(),
    ))
    .block(panel(&summary_title));

    let (node_rows, nodes_omitted) = bounded_rows(&model.nodes, |node| {
        Row::new([
            node.node_id.clone(),
            node.zone_id.clone(),
            node.health.clone(),
            node.quarantine_version.to_string(),
            node.last_seen.clone(),
        ])
    });
    let node_count = node_rows.len();
    let nodes_title = match &nodes_omitted {
        Some(note) => format!(" nodes ({note}) "),
        None => " nodes ".to_string(),
    };
    let nodes = Table::new(
        if node_rows.is_empty() {
            vec![Row::new(["(no node has reported a heartbeat)"])]
        } else {
            node_rows
        },
        [
            Constraint::Percentage(24.0),
            Constraint::Percentage(16.0),
            Constraint::Percentage(14.0),
            Constraint::Percentage(16.0),
            Constraint::Fill,
        ],
    )
    .header(Row::new([
        "node",
        "zone",
        "health",
        "quarantine v",
        "last seen",
    ]))
    .block(panel(&nodes_title));

    let (convergence_rows, convergences_omitted) =
        bounded_rows(&model.convergences, |convergence| {
            Row::new([
                convergence.incident_id.clone(),
                convergence.target_kind.clone(),
                convergence.target.clone(),
                format!("{}%", convergence.progress_pct),
            ])
        });
    let convergence_count = convergence_rows.len();
    let convergence_title = match &convergences_omitted {
        Some(note) => format!(" pending convergence ({note}) "),
        None => " pending convergence ".to_string(),
    };
    let convergences = Table::new(
        if convergence_rows.is_empty() {
            vec![Row::new(["(none)"])]
        } else {
            convergence_rows
        },
        [
            Constraint::Percentage(30.0),
            Constraint::Percentage(16.0),
            Constraint::Fill,
            Constraint::Fixed(9),
        ],
    )
    .header(Row::new(["incident", "kind", "target", "progress"]))
    .block(panel(&convergence_title));

    render_panels(
        width,
        &[
            (4, &summary),
            (table_height(node_count), &nodes),
            (table_height(convergence_count), &convergences),
        ],
    )
}

#[must_use]
pub fn render_doctor_screen(model: &DoctorScreenModel, width: u16) -> String {
    let summary = Paragraph::new(format!(
        "overall {}  profile {}  checks {}: pass {}  warn {}  fail {}",
        model.overall_status,
        model.profile,
        model.checks.len(),
        model.count("pass"),
        model.count("warn"),
        model.count("fail"),
    ))
    .block(panel(" franken-node doctor "));
    let (rows, omitted) = bounded_rows(&model.checks, |check| {
        Row::new([
            check.status.clone(),
            check.code.clone(),
            check.scope.clone(),
            check.message.clone(),
        ])
    });
    let count = rows.len();
    let title = match &omitted {
        Some(note) => format!(" checks ({note}) "),
        None => " checks ".to_string(),
    };
    let checks = Table::new(
        if rows.is_empty() {
            vec![Row::new(["(no checks ran)"])]
        } else {
            rows
        },
        [
            Constraint::Fixed(6),
            Constraint::Fixed(16),
            Constraint::Percentage(24.0),
            Constraint::Fill,
        ],
    )
    .header(Row::new(["status", "code", "scope", "message"]))
    .block(panel(&title));
    render_panels(width, &[(3, &summary), (table_height(count), &checks)])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fleet_model() -> FleetScreenModel {
        FleetScreenModel {
            zone_id: "us-east".to_string(),
            transport: "http".to_string(),
            live_control_plane: true,
            control_plane_url: Some("http://127.0.0.1:9440".to_string()),
            activated: true,
            healthy_nodes: 1,
            total_nodes: 2,
            active_quarantines: 1,
            active_revocations: 0,
            nodes: vec![
                FleetScreenNode {
                    node_id: "edge-1".to_string(),
                    zone_id: "us-east".to_string(),
                    health: "healthy".to_string(),
                    quarantine_version: 3,
                    last_seen: "2026-11-06T10:00:00Z".to_string(),
                },
                FleetScreenNode {
                    node_id: "edge-2".to_string(),
                    zone_id: "us-east".to_string(),
                    health: "degraded".to_string(),
                    quarantine_version: 2,
                    last_seen: "2026-11-06T09:58:00Z".to_string(),
                },
            ],
            convergences: vec![FleetScreenConvergence {
                incident_id: "inc-q-1".to_string(),
                target_kind: "artifact".to_string(),
                target: "npm:lib-core".to_string(),
                progress_pct: 50,
            }],
        }
    }

    #[test]
    fn fleet_screen_draws_bordered_panels_with_every_node_and_convergence() {
        let screen = render_fleet_screen(&fleet_model(), 100);
        assert!(screen.contains("fleet: zone us-east"), "{screen}");
        assert!(screen.contains("http://127.0.0.1:9440"), "{screen}");
        for needle in [
            "edge-1",
            "edge-2",
            "degraded",
            "inc-q-1",
            "npm:lib-core",
            "50%",
        ] {
            assert!(screen.contains(needle), "{needle} missing:\n{screen}");
        }
        // Widgets drew borders: the first line is the top edge of a block.
        let first = screen.lines().next().expect("first line");
        assert!(first.starts_with('┌') || first.starts_with('╭'), "{screen}");
    }

    #[test]
    fn empty_tables_say_so_and_width_has_a_floor() {
        let mut model = fleet_model();
        model.nodes.clear();
        model.convergences.clear();
        let screen = render_fleet_screen(&model, 10);
        assert!(
            screen.contains("no node has reported a heartbeat"),
            "{screen}"
        );
        assert!(screen.contains("(none)"), "{screen}");
        assert!(
            screen
                .lines()
                .any(|line| line.chars().count() >= usize::from(MIN_SCREEN_WIDTH) - 1)
        );
    }

    #[test]
    fn doctor_screen_counts_statuses() {
        let model = DoctorScreenModel {
            overall_status: "warn".to_string(),
            profile: "balanced".to_string(),
            checks: vec![
                DoctorScreenCheck {
                    status: "PASS".to_string(),
                    code: "DR-CONFIG-001".to_string(),
                    scope: "config.resolve".to_string(),
                    message: "configuration resolved".to_string(),
                },
                DoctorScreenCheck {
                    status: "WARN".to_string(),
                    code: "DR-SECURITY-013".to_string(),
                    scope: "security.signing_key".to_string(),
                    message: "no receipt signing key".to_string(),
                },
            ],
        };
        let screen = render_doctor_screen(&model, 100);
        assert!(screen.contains("pass 1  warn 1  fail 0"), "{screen}");
        assert!(screen.contains("DR-SECURITY-013"), "{screen}");
    }
}
