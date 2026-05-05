//! Adaptive validation planner for changed files and Beads acceptance.
//!
//! The planner turns a patch surface into a small, auditable validation plan. It
//! favors exact registered integration tests and explicit source-only checks,
//! while recording why broad gates were skipped or when they must be escalated.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const VALIDATION_PLANNER_SCHEMA_VERSION: &str = "franken-node/validation-planner/plan/v1";
pub const DEFAULT_CARGO_TOOLCHAIN: &str = "nightly-2026-02-19";
pub const DEFAULT_PACKAGE: &str = "frankenengine-node";
pub const DEFAULT_WORKSPACE_ROOT: &str = "/data/projects/franken_node";
pub const DEFAULT_RCH_PRIORITY: &str = "low";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisteredTest {
    pub name: String,
    pub path: String,
    pub required_features: Vec<String>,
}

impl RegisteredTest {
    #[must_use]
    pub fn new(name: impl Into<String>, path: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            path: normalize_path(path.into()),
            required_features: Vec::new(),
        }
    }

    #[must_use]
    pub fn with_required_features(
        mut self,
        features: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        self.required_features = sorted_unique(features);
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlannerInput {
    pub bead_id: String,
    pub thread_id: String,
    pub changed_paths: Vec<String>,
    pub labels: Vec<String>,
    pub acceptance: String,
    pub registered_tests: Vec<RegisteredTest>,
    pub workspace_root: String,
    pub package: String,
    pub cargo_toolchain: String,
    pub target_dir: String,
}

impl PlannerInput {
    #[must_use]
    pub fn new(
        bead_id: impl Into<String>,
        changed_paths: impl IntoIterator<Item = impl Into<String>>,
        registered_tests: Vec<RegisteredTest>,
    ) -> Self {
        let bead_id = bead_id.into();
        Self {
            thread_id: bead_id.clone(),
            target_dir: default_target_dir(&bead_id),
            bead_id,
            changed_paths: sorted_unique(changed_paths),
            labels: Vec::new(),
            acceptance: String::new(),
            registered_tests,
            workspace_root: DEFAULT_WORKSPACE_ROOT.to_string(),
            package: DEFAULT_PACKAGE.to_string(),
            cargo_toolchain: DEFAULT_CARGO_TOOLCHAIN.to_string(),
        }
    }

    #[must_use]
    pub fn with_labels(mut self, labels: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.labels = sorted_unique(labels);
        self
    }

    #[must_use]
    pub fn with_acceptance(mut self, acceptance: impl Into<String>) -> Self {
        self.acceptance = acceptance.into();
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlannedCommandKind {
    SourceOnly,
    RchCargo,
    PythonGate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GateStrength {
    Required,
    Recommended,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlannedCommand {
    pub command_id: String,
    pub kind: PlannedCommandKind,
    pub strength: GateStrength,
    pub shell: String,
    pub env: BTreeMap<String, String>,
    pub argv: Vec<String>,
    pub rationale: String,
    pub covers: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkippedGate {
    pub gate: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationPlan {
    pub schema_version: String,
    pub bead_id: String,
    pub thread_id: String,
    pub changed_paths: Vec<String>,
    pub commands: Vec<PlannedCommand>,
    pub skipped_gates: Vec<SkippedGate>,
    pub escalation_conditions: Vec<String>,
    pub source_only_allowed: bool,
}

impl ValidationPlan {
    #[must_use]
    pub fn command(&self, command_id: &str) -> Option<&PlannedCommand> {
        self.commands
            .iter()
            .find(|command| command.command_id == command_id)
    }

    pub fn rch_commands(&self) -> impl Iterator<Item = &PlannedCommand> {
        self.commands
            .iter()
            .filter(|command| command.kind == PlannedCommandKind::RchCargo)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ValidationPlannerError {
    #[error("Cargo manifest TOML did not parse: {0}")]
    ManifestToml(#[from] toml::de::Error),
    #[error("Cargo manifest [[test]] entry is missing string name or path at index {index}")]
    InvalidTestEntry { index: usize },
}

pub fn parse_registered_tests_from_manifest(
    manifest_toml: &str,
) -> Result<Vec<RegisteredTest>, ValidationPlannerError> {
    let manifest: toml::Value = toml::from_str(manifest_toml)?;
    let Some(tests) = manifest.get("test").and_then(toml::Value::as_array) else {
        return Ok(Vec::new());
    };

    let mut parsed = Vec::with_capacity(tests.len());
    for (index, test) in tests.iter().enumerate() {
        let Some(name) = test.get("name").and_then(toml::Value::as_str) else {
            return Err(ValidationPlannerError::InvalidTestEntry { index });
        };
        let Some(path) = test.get("path").and_then(toml::Value::as_str) else {
            return Err(ValidationPlannerError::InvalidTestEntry { index });
        };
        let required_features = test
            .get("required-features")
            .and_then(toml::Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(toml::Value::as_str)
            .map(ToOwned::to_owned)
            .collect::<Vec<_>>();

        parsed.push(RegisteredTest::new(name, path).with_required_features(required_features));
    }
    parsed.sort_by(|left, right| left.name.cmp(&right.name).then(left.path.cmp(&right.path)));
    Ok(parsed)
}

#[must_use]
pub fn plan_validation(input: &PlannerInput) -> ValidationPlan {
    let changed_paths = sorted_unique(input.changed_paths.clone());
    let mut builder = PlanBuilder::new(input, changed_paths.clone());

    if changed_paths.is_empty() {
        builder.add_skipped_gate(
            "cargo validation",
            "no changed paths were supplied; require a concrete Beads diff before cargo proof",
        );
        builder.add_escalation("rerun planner with changed paths before closing the bead");
        return builder.finish(true);
    }

    builder.add_git_diff_check();

    let has_rust = changed_paths.iter().any(|path| path.ends_with(".rs"));
    let has_manifest = changed_paths
        .iter()
        .any(|path| path.ends_with("Cargo.toml"));
    let has_script = changed_paths
        .iter()
        .any(|path| path.starts_with("scripts/"));
    let has_validation_artifact = changed_paths.iter().any(|path| {
        path.starts_with("artifacts/validation_broker/")
            || path == "docs/specs/validation_broker.md"
    });
    let has_sibling_drift = changed_paths
        .iter()
        .any(|path| is_sibling_dependency_path(path));
    let has_docs_only = changed_paths.iter().all(|path| {
        path.starts_with("docs/")
            || path.starts_with("artifacts/")
            || path.ends_with(".md")
            || path.ends_with(".json")
    });

    for path in &changed_paths {
        if path.ends_with(".json") {
            builder.add_json_tool_check(path);
        }
        if path.starts_with("scripts/") && path.ends_with(".py") {
            builder.add_python_script_gate(path);
        }
    }

    if has_validation_artifact {
        builder.add_validation_broker_contract_gate();
    }

    if has_docs_only && !has_rust && !has_manifest && !has_script {
        builder.add_skipped_gate(
            "rch cargo test",
            "changed paths are docs or contract artifacts only; source-only and contract gates are sufficient",
        );
        builder.add_escalation(
            "run focused RCH cargo tests if the artifact changes a Rust-consumed schema or fixture",
        );
        return builder.finish(true);
    }

    if has_manifest {
        builder.add_cargo_check_tests(
            "cargo-check-tests",
            "Cargo manifest changed; validate registered targets and feature metadata",
            changed_paths.clone(),
        );
    }

    if has_sibling_drift {
        builder.add_cargo_check_tests(
            "cargo-check-sibling-drift",
            "sibling dependency drift can break default frankenengine-node validation before local tests run",
            changed_paths.clone(),
        );
        builder.add_escalation(
            "if default-feature check fails in franken_engine, file or cite a sibling blocker bead",
        );
    }

    let mut matched_tests = BTreeSet::new();
    for path in &changed_paths {
        for test in matching_registered_tests(path, &input.registered_tests) {
            matched_tests.insert(test.name.clone());
        }
        if is_cli_surface(path) {
            for test in cli_registered_tests(&input.registered_tests) {
                matched_tests.insert(test.name.clone());
            }
        }
        if path.contains("validation_broker") {
            matched_tests.insert("validation_broker".to_string());
        }
        if path.contains("validation_planner") {
            matched_tests.insert("validation_planner".to_string());
        }
    }

    for test_name in matched_tests {
        if let Some(test) = input
            .registered_tests
            .iter()
            .find(|registered| registered.name == test_name)
        {
            builder.add_cargo_test(test, &changed_paths);
        } else {
            builder.add_escalation(format!(
                "register Cargo test `{test_name}` before relying on it for closeout"
            ));
        }
    }

    if has_rust && builder.rch_command_count == 0 {
        builder.add_cargo_check_tests(
            "cargo-check-rust-surface",
            "Rust source changed but no exact registered integration test matched",
            changed_paths.clone(),
        );
    }

    if builder.rch_command_count == 0 {
        builder.add_skipped_gate(
            "cargo check --all-targets",
            "no Rust, Cargo manifest, or sibling dependency path changed",
        );
    } else {
        builder.add_skipped_gate(
            "cargo check --all-targets",
            "focused registered tests or package checks cover this patch; broaden only after focused failure or changed shared API",
        );
        builder.add_skipped_gate(
            "cargo clippy --all-targets -- -D warnings",
            "defer broad clippy until focused plan is green or the patch touches shared lint-sensitive APIs",
        );
    }

    builder.finish(false)
}

struct PlanBuilder<'a> {
    input: &'a PlannerInput,
    changed_paths: Vec<String>,
    commands: BTreeMap<String, PlannedCommand>,
    skipped_gates: Vec<SkippedGate>,
    escalation_conditions: BTreeSet<String>,
    rch_command_count: usize,
}

impl<'a> PlanBuilder<'a> {
    fn new(input: &'a PlannerInput, changed_paths: Vec<String>) -> Self {
        Self {
            input,
            changed_paths,
            commands: BTreeMap::new(),
            skipped_gates: Vec::new(),
            escalation_conditions: BTreeSet::new(),
            rch_command_count: 0,
        }
    }

    fn add_git_diff_check(&mut self) {
        let mut argv = vec![
            "git".to_string(),
            "diff".to_string(),
            "--check".to_string(),
            "--".to_string(),
        ];
        argv.extend(self.changed_paths.clone());
        self.add_command(PlannedCommand {
            command_id: "source-diff-check".to_string(),
            kind: PlannedCommandKind::SourceOnly,
            strength: GateStrength::Required,
            shell: shell_command(&BTreeMap::new(), &argv),
            env: BTreeMap::new(),
            argv,
            rationale: "detect whitespace and conflict-marker errors on the exact changed paths"
                .to_string(),
            covers: self.changed_paths.clone(),
        });
    }

    fn add_json_tool_check(&mut self, path: &str) {
        let argv = vec![
            "python3".to_string(),
            "-m".to_string(),
            "json.tool".to_string(),
            path.to_string(),
        ];
        self.add_command(PlannedCommand {
            command_id: format!("json-tool-{}", stable_token(path)),
            kind: PlannedCommandKind::SourceOnly,
            strength: GateStrength::Required,
            shell: shell_command(&BTreeMap::new(), &argv),
            env: BTreeMap::new(),
            argv,
            rationale: "JSON artifact changed; validate parseability before using it as evidence"
                .to_string(),
            covers: vec![path.to_string()],
        });
    }

    fn add_python_script_gate(&mut self, path: &str) {
        let argv = vec![
            "python3".to_string(),
            path.to_string(),
            "--json".to_string(),
        ];
        self.add_command(PlannedCommand {
            command_id: format!("python-gate-{}", stable_token(path)),
            kind: PlannedCommandKind::PythonGate,
            strength: GateStrength::Recommended,
            shell: shell_command(&BTreeMap::new(), &argv),
            env: BTreeMap::new(),
            argv,
            rationale:
                "Python gate script changed; run the script directly in machine-readable mode"
                    .to_string(),
            covers: vec![path.to_string()],
        });
    }

    fn add_validation_broker_contract_gate(&mut self) {
        let argv = vec![
            "python3".to_string(),
            "scripts/check_validation_broker_contract.py".to_string(),
            "--json".to_string(),
        ];
        self.add_command(PlannedCommand {
            command_id: "python-validation-broker-contract".to_string(),
            kind: PlannedCommandKind::PythonGate,
            strength: GateStrength::Required,
            shell: shell_command(&BTreeMap::new(), &argv),
            env: BTreeMap::new(),
            argv,
            rationale: "validation broker contract artifacts changed; run the contract gate"
                .to_string(),
            covers: self.changed_paths.clone(),
        });
    }

    fn add_cargo_test(&mut self, test: &RegisteredTest, covers: &[String]) {
        let mut cargo_args = vec![
            "test".to_string(),
            "-p".to_string(),
            self.input.package.clone(),
        ];
        if !test.required_features.is_empty() {
            cargo_args.push("--no-default-features".to_string());
            cargo_args.push("--features".to_string());
            cargo_args.push(test.required_features.join(","));
        }
        cargo_args.extend([
            "--test".to_string(),
            test.name.clone(),
            "--".to_string(),
            "--nocapture".to_string(),
        ]);

        let command = self.rch_cargo_command(
            format!("cargo-test-{}", test.name),
            cargo_args,
            format!(
                "registered Cargo test `{}` directly covers the changed surface",
                test.name
            ),
            covers.to_vec(),
        );
        self.add_command(command);
        self.rch_command_count += 1;
    }

    fn add_cargo_check_tests(
        &mut self,
        command_id: impl Into<String>,
        rationale: impl Into<String>,
        covers: Vec<String>,
    ) {
        let cargo_args = vec![
            "check".to_string(),
            "-p".to_string(),
            self.input.package.clone(),
            "--tests".to_string(),
        ];
        let command = self.rch_cargo_command(command_id, cargo_args, rationale, covers);
        self.add_command(command);
        self.rch_command_count += 1;
    }

    fn rch_cargo_command(
        &self,
        command_id: impl Into<String>,
        cargo_args: Vec<String>,
        rationale: impl Into<String>,
        covers: Vec<String>,
    ) -> PlannedCommand {
        let mut env = BTreeMap::new();
        env.insert("RCH_REQUIRE_REMOTE".to_string(), "1".to_string());
        env.insert("RCH_VISIBILITY".to_string(), "summary".to_string());
        env.insert("RCH_PRIORITY".to_string(), DEFAULT_RCH_PRIORITY.to_string());

        let mut argv = vec![
            "rch".to_string(),
            "exec".to_string(),
            "--".to_string(),
            "env".to_string(),
            format!("CARGO_TARGET_DIR={}", self.input.target_dir),
            "CARGO_INCREMENTAL=0".to_string(),
            "CARGO_BUILD_JOBS=1".to_string(),
            "cargo".to_string(),
            format!("+{}", self.input.cargo_toolchain),
        ];
        argv.extend(cargo_args);

        PlannedCommand {
            command_id: command_id.into(),
            kind: PlannedCommandKind::RchCargo,
            strength: GateStrength::Required,
            shell: shell_command(&env, &argv),
            env,
            argv,
            rationale: rationale.into(),
            covers: sorted_unique(covers),
        }
    }

    fn add_command(&mut self, command: PlannedCommand) {
        self.commands.insert(command.command_id.clone(), command);
    }

    fn add_skipped_gate(&mut self, gate: impl Into<String>, reason: impl Into<String>) {
        self.skipped_gates.push(SkippedGate {
            gate: gate.into(),
            reason: reason.into(),
        });
    }

    fn add_escalation(&mut self, condition: impl Into<String>) {
        self.escalation_conditions.insert(condition.into());
    }

    fn finish(mut self, source_only_allowed: bool) -> ValidationPlan {
        self.skipped_gates.sort_by(|left, right| {
            left.gate
                .cmp(&right.gate)
                .then(left.reason.cmp(&right.reason))
        });
        self.skipped_gates
            .dedup_by(|left, right| left.gate == right.gate && left.reason == right.reason);

        ValidationPlan {
            schema_version: VALIDATION_PLANNER_SCHEMA_VERSION.to_string(),
            bead_id: self.input.bead_id.clone(),
            thread_id: self.input.thread_id.clone(),
            changed_paths: self.changed_paths,
            commands: self.commands.into_values().collect(),
            skipped_gates: self.skipped_gates,
            escalation_conditions: self.escalation_conditions.into_iter().collect(),
            source_only_allowed,
        }
    }
}

fn matching_registered_tests<'a>(
    changed_path: &str,
    registered_tests: &'a [RegisteredTest],
) -> Vec<&'a RegisteredTest> {
    let normalized = normalize_path(changed_path);
    let crate_relative = normalized
        .strip_prefix("crates/franken-node/")
        .unwrap_or(&normalized);
    let stem = file_stem(&normalized);

    registered_tests
        .iter()
        .filter(|test| {
            test.path == crate_relative
                || format!("crates/franken-node/{}", test.path) == normalized
                || stem.is_some_and(|stem| stem == test.name)
        })
        .collect()
}

fn cli_registered_tests(registered_tests: &[RegisteredTest]) -> Vec<&RegisteredTest> {
    registered_tests
        .iter()
        .filter(|test| test.name == "cli_arg_validation")
        .collect()
}

fn is_cli_surface(path: &str) -> bool {
    matches!(
        path,
        "crates/franken-node/src/cli.rs" | "crates/franken-node/src/main.rs"
    )
}

fn is_sibling_dependency_path(path: &str) -> bool {
    path.starts_with("../franken_engine/")
        || path.starts_with("/data/projects/franken_engine/")
        || path.starts_with("franken_engine/")
}

fn default_target_dir(bead_id: &str) -> String {
    let suffix = stable_token(if bead_id.trim().is_empty() {
        "untracked"
    } else {
        bead_id
    });
    format!("/data/tmp/franken_node-{suffix}-validation-planner-target")
}

fn normalize_path(path: impl Into<String>) -> String {
    let mut normalized = path.into().replace('\\', "/");
    while let Some(stripped) = normalized.strip_prefix("./") {
        normalized = stripped.to_string();
    }
    if let Some(stripped) = normalized.strip_prefix("/data/projects/franken_node/") {
        normalized = stripped.to_string();
    }
    normalized
}

fn file_stem(path: &str) -> Option<&str> {
    let file = path.rsplit('/').next()?;
    file.rsplit_once('.')
        .map_or(Some(file), |(stem, _)| Some(stem))
}

fn stable_token(input: &str) -> String {
    let mut token = String::with_capacity(input.len());
    for ch in input.chars() {
        if ch.is_ascii_alphanumeric() {
            token.push(ch.to_ascii_lowercase());
        } else if ch == '-' || ch == '_' {
            token.push(ch);
        } else if !token.ends_with('-') {
            token.push('-');
        }
    }
    token.trim_matches('-').to_string()
}

fn sorted_unique(values: impl IntoIterator<Item = impl Into<String>>) -> Vec<String> {
    values
        .into_iter()
        .map(Into::into)
        .map(normalize_path)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn shell_command(env: &BTreeMap<String, String>, argv: &[String]) -> String {
    env.iter()
        .map(|(key, value)| format!("{key}={}", shell_quote(value)))
        .chain(argv.iter().map(|arg| shell_quote(arg)))
        .collect::<Vec<_>>()
        .join(" ")
}

fn shell_quote(value: &str) -> String {
    if value.is_empty() {
        return "''".to_string();
    }
    if value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || b"@%_+=:,./-".contains(&byte))
    {
        return value.to_string();
    }
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}
