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
use frankentui::render::buffer::Buffer;
use frankentui::render::diff::BufferDiff;
use frankentui::render::frame::Frame;
use frankentui::render::grapheme_pool::GraphemePool;
use frankentui::runtime::simulator::ProgramSimulator;
use frankentui::widgets::Widget;
use frankentui::widgets::block::Block;
use frankentui::widgets::borders::Borders;
use frankentui::widgets::paragraph::Paragraph;
use frankentui::widgets::table::{Row, Table};
use frankentui::{Cmd, Event, KeyCode, KeyEvent, Model};
use serde::{Deserialize, Serialize};

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
    let empty_nodes = Paragraph::new(
        "node  zone  health  quarantine v  last seen\n(no node has reported a heartbeat)",
    )
    .block(panel(&nodes_title));
    let nodes = Table::new(
        node_rows,
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
    let nodes_widget: &dyn Widget = if node_count == 0 {
        &empty_nodes
    } else {
        &nodes
    };

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
            (table_height(node_count), nodes_widget),
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
    let empty_checks =
        Paragraph::new("status  code  scope  message\n(no checks ran)").block(panel(&title));
    let checks = Table::new(
        rows,
        [
            Constraint::Fixed(6),
            Constraint::Fixed(16),
            Constraint::Percentage(24.0),
            Constraint::Fill,
        ],
    )
    .header(Row::new(["status", "code", "scope", "message"]))
    .block(panel(&title));
    let checks_widget: &dyn Widget = if count == 0 { &empty_checks } else { &checks };
    render_panels(
        width,
        &[(3, &summary), (table_height(count), checks_widget)],
    )
}

/// Default frame height for the interactive operator console.
pub const DEFAULT_CONSOLE_HEIGHT: u16 = 26;
/// Minimum frame height for the interactive operator console.
pub const MIN_CONSOLE_HEIGHT: u16 = 12;

/// Active operator console tab.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperatorConsoleTab {
    Doctor,
    Fleet,
}

impl OperatorConsoleTab {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Doctor => "doctor",
            Self::Fleet => "fleet",
        }
    }

    #[must_use]
    pub const fn toggle(self) -> Self {
        match self {
            Self::Doctor => Self::Fleet,
            Self::Fleet => Self::Doctor,
        }
    }
}

/// Interactive filter applied to the active tab's rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperatorRowFilter {
    All,
    WarnOrDegraded,
    FailOnly,
    HealthyOrPassOnly,
}

impl OperatorRowFilter {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::All => "all",
            Self::WarnOrDegraded => "warn_or_degraded",
            Self::FailOnly => "fail_only",
            Self::HealthyOrPassOnly => "healthy_or_pass_only",
        }
    }

    #[must_use]
    pub const fn next(self) -> Self {
        match self {
            Self::All => Self::WarnOrDegraded,
            Self::WarnOrDegraded => Self::FailOnly,
            Self::FailOnly => Self::HealthyOrPassOnly,
            Self::HealthyOrPassOnly => Self::All,
        }
    }

    fn matches_doctor_status(self, status: &str) -> bool {
        match self {
            Self::All => true,
            Self::WarnOrDegraded => {
                status.eq_ignore_ascii_case("warn") || status.eq_ignore_ascii_case("fail")
            }
            Self::FailOnly => status.eq_ignore_ascii_case("fail"),
            Self::HealthyOrPassOnly => status.eq_ignore_ascii_case("pass"),
        }
    }

    fn matches_node_health(self, health: &str) -> bool {
        match self {
            Self::All => true,
            Self::WarnOrDegraded => !health.eq_ignore_ascii_case("healthy"),
            Self::FailOnly => {
                health.eq_ignore_ascii_case("unhealthy")
                    || health.eq_ignore_ascii_case("quarantined")
                    || health.eq_ignore_ascii_case("offline")
            }
            Self::HealthyOrPassOnly => health.eq_ignore_ascii_case("healthy"),
        }
    }
}

/// Messages processed by [`OperatorConsoleModel::update`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OperatorConsoleMsg {
    SwitchTab,
    SelectTab(OperatorConsoleTab),
    CycleFilter,
    ScrollDown,
    ScrollUp,
    ScrollHome,
    Resize { width: u16, height: u16 },
    RefreshRequested,
    Tick,
    Quit,
    Noop,
}

impl From<Event> for OperatorConsoleMsg {
    fn from(event: Event) -> Self {
        match event {
            Event::Key(key) => match key.code {
                KeyCode::Tab | KeyCode::BackTab => Self::SwitchTab,
                KeyCode::Char('1') => Self::SelectTab(OperatorConsoleTab::Doctor),
                KeyCode::Char('2') => Self::SelectTab(OperatorConsoleTab::Fleet),
                KeyCode::Char('f') | KeyCode::Char('F') => Self::CycleFilter,
                KeyCode::Char('j') | KeyCode::Down => Self::ScrollDown,
                KeyCode::Char('k') | KeyCode::Up => Self::ScrollUp,
                KeyCode::Char('g') | KeyCode::Home => Self::ScrollHome,
                KeyCode::Char('r') | KeyCode::Char('R') => Self::RefreshRequested,
                KeyCode::Char('q') | KeyCode::Char('Q') | KeyCode::Escape => Self::Quit,
                _ => Self::Noop,
            },
            Event::Resize { width, height } => Self::Resize { width, height },
            Event::Tick => Self::Tick,
            _ => Self::Noop,
        }
    }
}

/// Elm/Bubbletea [`frankentui::Model`] combining live `doctor` and `fleet` operator views.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperatorConsoleModel {
    pub doctor: DoctorScreenModel,
    pub fleet: FleetScreenModel,
    pub active_tab: OperatorConsoleTab,
    pub filter: OperatorRowFilter,
    pub scroll_offset: usize,
    pub width: u16,
    pub height: u16,
    pub events_processed: u64,
    pub refreshes_requested: u64,
    pub ticks_observed: u64,
    pub initialized: bool,
    pub quit_requested: bool,
}

impl OperatorConsoleModel {
    #[must_use]
    pub fn new(doctor: DoctorScreenModel, fleet: FleetScreenModel) -> Self {
        Self {
            doctor,
            fleet,
            active_tab: OperatorConsoleTab::Doctor,
            filter: OperatorRowFilter::All,
            scroll_offset: 0,
            width: DEFAULT_SCREEN_WIDTH,
            height: DEFAULT_CONSOLE_HEIGHT,
            events_processed: 0,
            refreshes_requested: 0,
            ticks_observed: 0,
            initialized: false,
            quit_requested: false,
        }
    }

    #[must_use]
    pub fn with_dimensions(mut self, width: u16, height: u16) -> Self {
        self.width = width.max(MIN_SCREEN_WIDTH);
        self.height = height.max(MIN_CONSOLE_HEIGHT);
        self
    }

    /// Replace underlying live store snapshots (e.g. when `r` triggers a live workspace re-probe).
    pub fn replace_snapshots(&mut self, doctor: DoctorScreenModel, fleet: FleetScreenModel) {
        self.doctor = doctor;
        self.fleet = fleet;
        self.clamp_scroll();
    }

    #[must_use]
    pub fn visible_row_total(&self) -> usize {
        match self.active_tab {
            OperatorConsoleTab::Doctor => self
                .doctor
                .checks
                .iter()
                .filter(|c| self.filter.matches_doctor_status(&c.status))
                .count(),
            OperatorConsoleTab::Fleet => self
                .fleet
                .nodes
                .iter()
                .filter(|n| self.filter.matches_node_health(&n.health))
                .count(),
        }
    }

    fn clamp_scroll(&mut self) {
        let max_offset = self.visible_row_total().saturating_sub(1);
        if self.scroll_offset > max_offset {
            self.scroll_offset = max_offset;
        }
    }
}

impl Model for OperatorConsoleModel {
    type Message = OperatorConsoleMsg;

    fn init(&mut self) -> Cmd<Self::Message> {
        self.initialized = true;
        self.clamp_scroll();
        Cmd::none()
    }

    fn update(&mut self, msg: Self::Message) -> Cmd<Self::Message> {
        self.events_processed = self.events_processed.saturating_add(1);
        match msg {
            OperatorConsoleMsg::SwitchTab => {
                self.active_tab = self.active_tab.toggle();
                self.scroll_offset = 0;
                Cmd::none()
            }
            OperatorConsoleMsg::SelectTab(tab) => {
                if self.active_tab != tab {
                    self.active_tab = tab;
                    self.scroll_offset = 0;
                }
                Cmd::none()
            }
            OperatorConsoleMsg::CycleFilter => {
                self.filter = self.filter.next();
                self.scroll_offset = 0;
                Cmd::none()
            }
            OperatorConsoleMsg::ScrollDown => {
                let max_offset = self.visible_row_total().saturating_sub(1);
                if self.scroll_offset < max_offset {
                    self.scroll_offset = self.scroll_offset.saturating_add(1);
                }
                Cmd::none()
            }
            OperatorConsoleMsg::ScrollUp => {
                self.scroll_offset = self.scroll_offset.saturating_sub(1);
                Cmd::none()
            }
            OperatorConsoleMsg::ScrollHome => {
                self.scroll_offset = 0;
                Cmd::none()
            }
            OperatorConsoleMsg::Resize { width, height } => {
                self.width = width.max(MIN_SCREEN_WIDTH);
                self.height = height.max(MIN_CONSOLE_HEIGHT);
                Cmd::none()
            }
            OperatorConsoleMsg::RefreshRequested => {
                self.refreshes_requested = self.refreshes_requested.saturating_add(1);
                self.clamp_scroll();
                Cmd::none()
            }
            OperatorConsoleMsg::Tick => {
                self.ticks_observed = self.ticks_observed.saturating_add(1);
                Cmd::none()
            }
            OperatorConsoleMsg::Quit => {
                self.quit_requested = true;
                Cmd::quit()
            }
            OperatorConsoleMsg::Noop => Cmd::none(),
        }
    }

    fn view(&self, frame: &mut Frame) {
        let width = frame.buffer.width();
        let height = frame.buffer.height();
        let root = Rect::new(0, 0, width, height);

        let tab_header = match self.active_tab {
            OperatorConsoleTab::Doctor => "[1:DOCTOR*]  2:fleet",
            OperatorConsoleTab::Fleet => " 1:doctor   [2:FLEET*]",
        };
        let nav_bar = Paragraph::new(format!(
            "{tab_header}  |  filter={}  scroll={}  events={}  refreshes={}\n\
             keys: Tab/1/2 switch  f filter  j/k scroll  g top  r refresh  q quit",
            self.filter.as_str(),
            self.scroll_offset,
            self.events_processed,
            self.refreshes_requested,
        ))
        .block(panel(" franken-node operator console (frankentui::Model) "));

        match self.active_tab {
            OperatorConsoleTab::Doctor => {
                let filtered: Vec<&DoctorScreenCheck> = self
                    .doctor
                    .checks
                    .iter()
                    .filter(|check| self.filter.matches_doctor_status(&check.status))
                    .skip(self.scroll_offset)
                    .take(MAX_TABLE_ROWS)
                    .collect();
                let summary = Paragraph::new(format!(
                    "overall {}  profile {}  total {} (pass {}  warn {}  fail {})  showing {}",
                    self.doctor.overall_status,
                    self.doctor.profile,
                    self.doctor.checks.len(),
                    self.doctor.count("pass"),
                    self.doctor.count("warn"),
                    self.doctor.count("fail"),
                    filtered.len(),
                ))
                .block(panel(" doctor summary "));
                let rows: Vec<Row> = filtered
                    .iter()
                    .map(|check| {
                        Row::new([
                            check.status.clone(),
                            check.code.clone(),
                            check.scope.clone(),
                            check.message.clone(),
                        ])
                    })
                    .collect();
                let title = format!(
                    " doctor checks (filter={}, offset={}) ",
                    self.filter.as_str(),
                    self.scroll_offset
                );
                let areas = Flex::vertical()
                    .constraints([Constraint::Fixed(4), Constraint::Fixed(3), Constraint::Fill])
                    .split(root);
                nav_bar.render(areas[0], frame);
                summary.render(areas[1], frame);
                if rows.is_empty() {
                    Paragraph::new("status  code  scope  message\n(no matching checks)")
                        .block(panel(&title))
                        .render(areas[2], frame);
                } else {
                    Table::new(
                        rows,
                        [
                            Constraint::Fixed(6),
                            Constraint::Fixed(16),
                            Constraint::Percentage(24.0),
                            Constraint::Fill,
                        ],
                    )
                    .header(Row::new(["status", "code", "scope", "message"]))
                    .block(panel(&title))
                    .render(areas[2], frame);
                }
            }
            OperatorConsoleTab::Fleet => {
                let filtered_nodes: Vec<&FleetScreenNode> = self
                    .fleet
                    .nodes
                    .iter()
                    .filter(|node| self.filter.matches_node_health(&node.health))
                    .skip(self.scroll_offset)
                    .take(MAX_TABLE_ROWS)
                    .collect();
                let summary_title = format!(" fleet: zone {} ", self.fleet.zone_id);
                let summary = Paragraph::new(format!(
                    "transport {}{}  live_cp={}  activated={}  nodes {}/{}  quarantines {}  revocations {}  converging {}",
                    self.fleet.transport,
                    self.fleet
                        .control_plane_url
                        .as_deref()
                        .map(|url| format!(" ({url})"))
                        .unwrap_or_default(),
                    if self.fleet.live_control_plane { "yes" } else { "no" },
                    if self.fleet.activated { "yes" } else { "no" },
                    self.fleet.healthy_nodes,
                    self.fleet.total_nodes,
                    self.fleet.active_quarantines,
                    self.fleet.active_revocations,
                    self.fleet.convergences.len(),
                ))
                .block(panel(&summary_title));
                let node_rows: Vec<Row> = filtered_nodes
                    .iter()
                    .map(|node| {
                        Row::new([
                            node.node_id.clone(),
                            node.zone_id.clone(),
                            node.health.clone(),
                            node.quarantine_version.to_string(),
                            node.last_seen.clone(),
                        ])
                    })
                    .collect();
                let nodes_title = format!(
                    " fleet nodes (filter={}, offset={}) ",
                    self.filter.as_str(),
                    self.scroll_offset
                );
                let conv_rows: Vec<Row> = if self.fleet.convergences.is_empty() {
                    vec![Row::new(["(none)"])]
                } else {
                    self.fleet
                        .convergences
                        .iter()
                        .take(MAX_TABLE_ROWS)
                        .map(|conv| {
                            Row::new([
                                conv.incident_id.clone(),
                                conv.target_kind.clone(),
                                conv.target.clone(),
                                format!("{}%", conv.progress_pct),
                            ])
                        })
                        .collect()
                };
                let conv_height = table_height(conv_rows.len()).min(7);
                let areas = Flex::vertical()
                    .constraints([
                        Constraint::Fixed(4),
                        Constraint::Fixed(3),
                        Constraint::Fill,
                        Constraint::Fixed(conv_height),
                    ])
                    .split(root);
                nav_bar.render(areas[0], frame);
                summary.render(areas[1], frame);
                if node_rows.is_empty() {
                    Paragraph::new(
                        "node  zone  health  quarantine v  last seen\n(no matching fleet nodes)",
                    )
                    .block(panel(&nodes_title))
                    .render(areas[2], frame);
                } else {
                    Table::new(
                        node_rows,
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
                    .block(panel(&nodes_title))
                    .render(areas[2], frame);
                }
                Table::new(
                    conv_rows,
                    [
                        Constraint::Percentage(30.0),
                        Constraint::Percentage(16.0),
                        Constraint::Fill,
                        Constraint::Fixed(9),
                    ],
                )
                .header(Row::new(["incident", "kind", "target", "progress"]))
                .block(panel(" pending convergence "))
                .render(areas[3], frame);
            }
        }
    }
}

/// Convert a rendered [`Buffer`] into trimmed newline-joined text.
#[must_use]
pub fn buffer_to_string(buffer: &Buffer) -> String {
    let mut lines = Vec::with_capacity(usize::from(buffer.height()));
    for y in 0..buffer.height() {
        let mut line = String::with_capacity(usize::from(buffer.width()));
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

/// Parse one symbolic key/event token (`tab`, `1`, `2`, `f`, `j`, `k`, `g`, `r`, `tick`, `q`, `resize:110x28`).
pub fn parse_console_key_token(token: &str) -> Result<Event, String> {
    let trimmed = token.trim();
    if trimmed.is_empty() {
        return Err("empty console event token".to_string());
    }
    let lower = trimmed.to_ascii_lowercase();
    match lower.as_str() {
        "tab" => Ok(Event::Key(KeyEvent::new(KeyCode::Tab))),
        "backtab" => Ok(Event::Key(KeyEvent::new(KeyCode::BackTab))),
        "1" | "doctor" => Ok(Event::Key(KeyEvent::new(KeyCode::Char('1')))),
        "2" | "fleet" => Ok(Event::Key(KeyEvent::new(KeyCode::Char('2')))),
        "f" | "filter" => Ok(Event::Key(KeyEvent::new(KeyCode::Char('f')))),
        "j" | "down" => Ok(Event::Key(KeyEvent::new(KeyCode::Down))),
        "k" | "up" => Ok(Event::Key(KeyEvent::new(KeyCode::Up))),
        "g" | "home" | "top" => Ok(Event::Key(KeyEvent::new(KeyCode::Home))),
        "r" | "refresh" => Ok(Event::Key(KeyEvent::new(KeyCode::Char('r')))),
        "tick" => Ok(Event::Tick),
        "q" | "quit" | "esc" | "escape" => Ok(Event::Key(KeyEvent::new(KeyCode::Char('q')))),
        _ if lower.starts_with("resize:") => {
            let spec = &lower["resize:".len()..];
            let Some((w_raw, h_raw)) = spec.split_once('x') else {
                return Err(format!(
                    "invalid resize token `{trimmed}` (expected resize:WxH)"
                ));
            };
            let width = w_raw
                .parse::<u16>()
                .map_err(|_| format!("invalid resize width in `{trimmed}`"))?;
            let height = h_raw
                .parse::<u16>()
                .map_err(|_| format!("invalid resize height in `{trimmed}`"))?;
            Ok(Event::Resize { width, height })
        }
        _ => Err(format!("unsupported console event token `{trimmed}`")),
    }
}

/// Telemetry for one step in [`run_operator_console_simulation`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatorConsoleStepFrame {
    pub step_index: usize,
    pub event_label: String,
    pub active_tab: OperatorConsoleTab,
    pub filter: OperatorRowFilter,
    pub scroll_offset: usize,
    pub visible_rows: usize,
    pub changed_cells: usize,
    pub diff_runs: usize,
    pub running: bool,
}

/// Summary returned by [`run_operator_console_simulation`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatorConsoleSimulationReport {
    pub initialized: bool,
    pub running_at_end: bool,
    pub quit_requested: bool,
    pub active_tab: OperatorConsoleTab,
    pub filter: OperatorRowFilter,
    pub scroll_offset: usize,
    pub events_processed: u64,
    pub refreshes_requested: u64,
    pub ticks_observed: u64,
    pub frame_count: usize,
    pub total_changed_cells: usize,
    pub steps: Vec<OperatorConsoleStepFrame>,
    pub final_screen: String,
}

/// Execute [`OperatorConsoleModel`] through [`ProgramSimulator`] with exact [`BufferDiff`] cell accounting.
#[must_use]
pub fn run_operator_console_simulation(
    model: OperatorConsoleModel,
    events: &[Event],
    width: u16,
    height: u16,
) -> OperatorConsoleSimulationReport {
    let w = width.max(MIN_SCREEN_WIDTH);
    let h = height.max(MIN_CONSOLE_HEIGHT);
    let mut sim = ProgramSimulator::new(model.with_dimensions(w, h));
    sim.init();
    let mut prev_buffer = sim.capture_frame(w, h).clone();
    let mut steps = Vec::with_capacity(events.len());
    let mut total_changed_cells = 0_usize;

    for (idx, event) in events.iter().enumerate() {
        if !sim.is_running() {
            break;
        }
        sim.inject_event(event.clone());
        let cur_w = sim.model().width;
        let cur_h = sim.model().height;
        let next_buffer = sim.capture_frame(cur_w, cur_h).clone();
        let (changed_cells, diff_runs) = if prev_buffer.width() == next_buffer.width()
            && prev_buffer.height() == next_buffer.height()
        {
            let diff = BufferDiff::compute(&prev_buffer, &next_buffer);
            (diff.len(), diff.runs().len())
        } else {
            (
                usize::from(next_buffer.width()) * usize::from(next_buffer.height()),
                usize::from(next_buffer.height()),
            )
        };
        total_changed_cells = total_changed_cells.saturating_add(changed_cells);
        prev_buffer = next_buffer;
        steps.push(OperatorConsoleStepFrame {
            step_index: idx,
            event_label: event.event_type_label().to_string(),
            active_tab: sim.model().active_tab,
            filter: sim.model().filter,
            scroll_offset: sim.model().scroll_offset,
            visible_rows: sim.model().visible_row_total(),
            changed_cells,
            diff_runs,
            running: sim.is_running(),
        });
    }

    let final_screen = buffer_to_string(&prev_buffer);
    let m = sim.model();
    OperatorConsoleSimulationReport {
        initialized: m.initialized,
        running_at_end: sim.is_running(),
        quit_requested: m.quit_requested,
        active_tab: m.active_tab,
        filter: m.filter,
        scroll_offset: m.scroll_offset,
        events_processed: m.events_processed,
        refreshes_requested: m.refreshes_requested,
        ticks_observed: m.ticks_observed,
        frame_count: sim.frame_count(),
        total_changed_cells,
        steps,
        final_screen,
    }
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

    #[test]
    fn operator_console_model_tabs_filters_scrolls_diffs_and_quits() {
        let doctor = DoctorScreenModel {
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
                DoctorScreenCheck {
                    status: "FAIL".to_string(),
                    code: "DR-SQLMODEL-015".to_string(),
                    scope: "storage.sqlmodel_schema".to_string(),
                    message: "schema drift detected".to_string(),
                },
            ],
        };
        let events = ["j", "f", "tab", "f", "tick", "q"]
            .into_iter()
            .map(|tok| parse_console_key_token(tok).expect("valid token"))
            .collect::<Vec<_>>();
        let report = run_operator_console_simulation(
            OperatorConsoleModel::new(doctor, fleet_model()),
            &events,
            100,
            24,
        );
        assert!(report.initialized);
        assert!(!report.running_at_end);
        assert!(report.quit_requested);
        assert_eq!(report.active_tab, OperatorConsoleTab::Fleet);
        assert_eq!(report.filter, OperatorRowFilter::FailOnly);
        assert_eq!(report.ticks_observed, 1);
        assert_eq!(report.events_processed, 6);
        assert!(report.total_changed_cells > 0);
        assert!(report.final_screen.contains("[2:FLEET*]"));
    }
}
