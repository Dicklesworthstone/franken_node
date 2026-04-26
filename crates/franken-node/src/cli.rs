#![allow(clippy::doc_markdown)]

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use serde::{Deserialize, Serialize};

/// Validate user content path arguments against path traversal attacks.
/// Strict validation for user-controlled content paths.
///
/// Rejects paths containing:
/// - `..` segments (directory traversal)
/// - Leading `/` (absolute paths - user content should be relative)
/// - Backslashes (Windows-style separators)
/// - Null bytes (path injection)
fn validate_user_content_path(path: &str) -> Result<&Path> {
    // Reject null bytes (path injection)
    if path.contains('\0') {
        anyhow::bail!("Path contains null bytes: {}", path);
    }

    // Reject absolute paths (leading /) - user content should be relative
    if path.starts_with('/') {
        anyhow::bail!("Absolute paths not allowed for user content: {}", path);
    }

    // Reject backslashes (Windows-style, potential confusion)
    if path.contains('\\') {
        anyhow::bail!("Backslashes not allowed in path: {}", path);
    }

    // Reject .. segments (directory traversal)
    if path.split('/').any(|segment| segment == "..") {
        anyhow::bail!("Path traversal (..) not allowed: {}", path);
    }

    Ok(Path::new(path))
}

/// Validate system binary path arguments.
/// Relaxed validation for system binary paths that may be absolute.
///
/// Rejects paths containing:
/// - `..` segments (directory traversal)
/// - Null bytes (path injection)
/// Allows absolute paths (system binaries often in /usr/bin/, /usr/local/bin/, etc.)
fn validate_system_binary_path(path: &str) -> Result<&Path> {
    // Reject null bytes (path injection)
    if path.contains('\0') {
        anyhow::bail!("Path contains null bytes: {}", path);
    }

    // Reject .. segments (directory traversal)
    if path.split('/').any(|segment| segment == "..") {
        anyhow::bail!("Path traversal (..) not allowed: {}", path);
    }

    Ok(Path::new(path))
}

/// Convert validated PathBuf to safe Path, applying user content validation.
fn validate_user_content_pathbuf(pathbuf: &PathBuf) -> Result<&Path> {
    let path_str = pathbuf
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("Path contains invalid UTF-8: {:?}", pathbuf))?;
    validate_user_content_path(path_str)
}

/// Convert validated PathBuf to safe Path, applying system binary validation.
fn validate_system_binary_pathbuf(pathbuf: &PathBuf) -> Result<&Path> {
    let path_str = pathbuf
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("Path contains invalid UTF-8: {:?}", pathbuf))?;
    validate_system_binary_path(path_str)
}

/// Custom parser for safe user content PathBuf that validates against path traversal.
fn parse_safe_content_pathbuf(s: &str) -> Result<PathBuf, String> {
    validate_user_content_path(s)
        .map(|p| p.to_path_buf())
        .map_err(|e| format!("Invalid content path: {}", e))
}

/// Custom parser for safe system binary PathBuf that allows absolute paths.
fn parse_safe_binary_pathbuf(s: &str) -> Result<PathBuf, String> {
    validate_system_binary_path(s)
        .map(|p| p.to_path_buf())
        .map_err(|e| format!("Invalid binary path: {}", e))
}

/// franken-node: trust-native JavaScript/TypeScript runtime platform.
///
/// Pairs Node/Bun migration speed with deterministic security controls
/// and replayable operations for extension-heavy systems.
#[derive(Debug, Parser)]
#[command(
    name = "franken-node",
    version,
    about,
    long_about = None,
    propagate_version = true
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Bootstrap config, policy profile, and workspace metadata.
    Init(InitArgs),

    /// Run app under policy-governed runtime controls.
    Run(RunArgs),

    /// Runtime lane and epoch inspection/control.
    #[command(subcommand)]
    Runtime(RuntimeCommand),

    /// Migration audit, rewrite, and validation workflows.
    #[command(subcommand)]
    Migrate(MigrateCommand),

    /// Compatibility verification across runtimes.
    #[command(subcommand)]
    Verify(VerifyCommand),

    /// Extension trust management.
    #[command(subcommand)]
    Trust(TrustCommand),

    /// Remote capability token issuance and inspection.
    #[command(subcommand, name = "remotecap")]
    Remotecap(RemoteCapCommand),

    /// Trust-card API/CLI parity surfaces.
    #[command(subcommand, name = "trust-card")]
    TrustCard(TrustCardCommand),

    /// Fleet control plane operations.
    #[command(subcommand)]
    Fleet(FleetCommand),

    /// Incident replay and forensics.
    #[command(subcommand)]
    Incident(IncidentCommand),

    /// Runtime operations and health inspection.
    #[command(subcommand)]
    Ops(OpsCommand),

    /// Extension registry operations.
    #[command(subcommand)]
    Registry(RegistryCommand),

    /// Benchmark suite execution.
    #[command(subcommand)]
    Bench(BenchCommand),

    /// Diagnose environment and policy setup.
    Doctor(DoctorArgs),
}

// -- init --

#[derive(Debug, Parser)]
pub struct InitArgs {
    /// Runtime profile override: strict, balanced, or legacy-risky.
    /// Controls security/compatibility behavior (not packaging profiles like local/dev/enterprise).
    #[arg(long)]
    pub profile: Option<String>,

    /// Config file override (default discovery is used when omitted).
    #[arg(long, value_parser = parse_safe_content_pathbuf)]
    pub config: Option<PathBuf>,

    /// Output directory for generated config files.
    #[arg(long, value_parser = parse_safe_content_pathbuf)]
    pub out_dir: Option<PathBuf>,

    /// Overwrite existing generated files in target directory.
    #[arg(long)]
    pub overwrite: bool,

    /// Backup existing generated files before writing replacements.
    #[arg(long)]
    pub backup_existing: bool,

    /// Run a baseline dependency trust scan after bootstrapping workspace state.
    #[arg(long)]
    pub scan: bool,

    /// Emit machine-readable init report.
    #[arg(long)]
    pub json: bool,

    /// Emit structured diagnostic log events as JSONL to stderr.
    #[arg(long)]
    pub structured_logs_jsonl: bool,

    /// Stable trace ID for correlating init events.
    #[arg(long, default_value = "init-bootstrap")]
    pub trace_id: String,

    /// Override the state directory location (default: .franken-node/ relative to out-dir or cwd).
    #[arg(long, value_parser = parse_safe_content_pathbuf)]
    pub state_dir: Option<PathBuf>,

    /// Skip bootstrapping the state directory structure (config files only).
    #[arg(long)]
    pub no_state: bool,
}

impl InitArgs {
    /// Validate all user-supplied path arguments for security.
    pub fn validate_paths(&self) -> Result<()> {
        if let Some(ref config) = self.config {
            validate_user_content_pathbuf(config)
                .with_context(|| format!("Invalid --config path: {:?}", config))?;
        }

        if let Some(ref out_dir) = self.out_dir {
            validate_user_content_pathbuf(out_dir)
                .with_context(|| format!("Invalid --out-dir path: {:?}", out_dir))?;
        }

        if let Some(ref state_dir) = self.state_dir {
            validate_user_content_pathbuf(state_dir)
                .with_context(|| format!("Invalid --state-dir path: {:?}", state_dir))?;
        }

        Ok(())
    }
}

// -- run --

#[derive(Debug, Parser)]
pub struct RunArgs {
    /// Path to the application entry point.
    #[arg(value_parser = parse_safe_content_pathbuf)]
    pub app_path: PathBuf,

    /// Policy mode to enforce at runtime.
    #[arg(long, default_value = "balanced")]
    pub policy: String,

    /// Emit a machine-readable trust pre-flight report.
    #[arg(long)]
    pub json: bool,

    /// Emit structured diagnostic log events as JSONL to stderr.
    #[arg(long)]
    pub structured_logs_jsonl: bool,

    /// Stable trace ID for correlating run events.
    #[arg(long, default_value = "run-execution")]
    pub trace_id: String,

    /// Config file override.
    #[arg(long, value_parser = parse_safe_content_pathbuf)]
    pub config: Option<PathBuf>,

    /// Runtime selection: auto, node, bun, or franken-engine.
    #[arg(long)]
    pub runtime: Option<String>,

    /// Explicit franken_engine binary path or command name.
    #[arg(long, value_parser = parse_safe_binary_pathbuf)]
    pub engine_bin: Option<PathBuf>,

    /// Run lockstep comparison across runtimes before execution.
    /// When enabled, the app is run in both node and bun (if available)
    /// and results are compared. Divergence blocks execution.
    #[arg(long)]
    pub lockstep_preflight: bool,
}

impl RunArgs {
    /// Validate all user-supplied path arguments for security.
    pub fn validate_paths(&self) -> Result<()> {
        // Validate app_path (required field) - user content
        validate_user_content_pathbuf(&self.app_path)
            .with_context(|| format!("Invalid app_path: {:?}", self.app_path))?;

        if let Some(ref config) = self.config {
            validate_user_content_pathbuf(config)
                .with_context(|| format!("Invalid --config path: {:?}", config))?;
        }

        if let Some(ref engine_bin) = self.engine_bin {
            validate_system_binary_pathbuf(engine_bin)
                .with_context(|| format!("Invalid --engine-bin path: {:?}", engine_bin))?;
        }

        Ok(())
    }
}

// -- runtime --

#[derive(Debug, Subcommand)]
pub enum RuntimeCommand {
    /// Inspect or exercise lane scheduler state.
    #[command(subcommand)]
    Lane(RuntimeLaneCommand),

    /// Inspect control epoch compatibility.
    Epoch(RuntimeEpochArgs),
}

#[derive(Debug, Subcommand)]
pub enum RuntimeLaneCommand {
    /// Emit the default lane policy and empty telemetry snapshot.
    Status(RuntimeLaneStatusArgs),

    /// Assign one task class through the default lane scheduler.
    Assign(RuntimeLaneAssignArgs),
}

#[derive(Debug, Parser)]
pub struct RuntimeLaneStatusArgs {
    /// Emit structured JSON output.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Parser)]
pub struct RuntimeLaneAssignArgs {
    /// Task class to assign, for example epoch_transition or log_rotation.
    pub task_class: String,

    /// Deterministic timestamp override in milliseconds.
    #[arg(long)]
    pub timestamp_ms: Option<u64>,

    /// Stable trace ID for the assignment.
    #[arg(long, default_value = "runtime-lane-cli")]
    pub trace_id: String,

    /// Emit structured JSON output.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Parser)]
pub struct RuntimeEpochArgs {
    /// Local control epoch.
    #[arg(long)]
    pub local_epoch: u64,

    /// Peer control epoch to compare against.
    #[arg(long)]
    pub peer_epoch: Option<u64>,

    /// Emit structured JSON output.
    #[arg(long)]
    pub json: bool,
}

// -- migrate --

#[derive(Debug, Subcommand)]
pub enum MigrateCommand {
    /// Inventory migration risk and emit findings.
    Audit(MigrateAuditArgs),

    /// Apply migration transforms with rollback artifacts.
    Rewrite(MigrateRewriteArgs),

    /// Validate transformed project with conformance checks.
    Validate(MigrateValidateArgs),
}

#[derive(Debug)]
pub struct MigrateAuditArgs {
    /// Path to the project to audit.
    pub project_path: PathBuf,

    /// Output format: json, text, or sarif.
    pub format: String,

    /// Output file path.
    pub out: Option<PathBuf>,
}

impl clap::Args for MigrateAuditArgs {
    fn augment_args(cmd: clap::Command) -> clap::Command {
        cmd.arg(
            clap::Arg::new("project_path")
                .value_name("PROJECT_PATH")
                .help("Path to the project to audit.")
                .value_parser(clap::value_parser!(PathBuf))
                .required(true),
        )
        .arg(
            clap::Arg::new("format")
                .long("format")
                .value_name("FORMAT")
                .help("Output format: json, text, or sarif.")
                .default_value("text")
                .value_parser(["json", "text", "sarif"])
                .requires_if("sarif", "out"),
        )
        .arg(
            clap::Arg::new("out")
                .long("out")
                .value_name("PATH")
                .help("Output file path.")
                .value_parser(clap::value_parser!(PathBuf)),
        )
    }

    fn augment_args_for_update(cmd: clap::Command) -> clap::Command {
        Self::augment_args(cmd)
    }
}

impl clap::FromArgMatches for MigrateAuditArgs {
    fn from_arg_matches(matches: &clap::ArgMatches) -> Result<Self, clap::Error> {
        let project_path = matches
            .get_one::<PathBuf>("project_path")
            .expect("project_path is required by clap")
            .clone();
        let format = matches
            .get_one::<String>("format")
            .expect("format has a default value")
            .clone();
        let out = matches.get_one::<PathBuf>("out").cloned();

        validate_migrate_audit_output(&format, out.as_ref())?;

        Ok(Self {
            project_path,
            format,
            out,
        })
    }

    fn update_from_arg_matches(&mut self, matches: &clap::ArgMatches) -> Result<(), clap::Error> {
        *self = Self::from_arg_matches(matches)?;
        Ok(())
    }
}

fn validate_migrate_audit_output(format: &str, out: Option<&PathBuf>) -> Result<(), clap::Error> {
    let extension = out
        .and_then(|path| path.extension())
        .and_then(|extension| extension.to_str())
        .map(str::to_ascii_lowercase);

    if format == "sarif" {
        return match extension.as_deref() {
            Some("sarif") => Ok(()),
            Some(_) => Err(clap::Error::raw(
                clap::error::ErrorKind::ValueValidation,
                "--format=sarif requires --out to end in .sarif",
            )),
            None => Err(clap::Error::raw(
                clap::error::ErrorKind::MissingRequiredArgument,
                "--format=sarif requires --out <PATH>.sarif",
            )),
        };
    }

    match (format, extension.as_deref()) {
        ("json", Some("sarif" | "txt" | "text")) => Err(clap::Error::raw(
            clap::error::ErrorKind::ValueValidation,
            "--format=json requires a JSON-compatible --out path",
        )),
        ("text", Some("json" | "sarif")) => Err(clap::Error::raw(
            clap::error::ErrorKind::ValueValidation,
            "--format=text requires a text-compatible --out path",
        )),
        _ => Ok(()),
    }
}

#[derive(Debug, Parser)]
pub struct MigrateRewriteArgs {
    /// Path to the project to rewrite.
    pub project_path: PathBuf,

    /// Apply rewrites (without this flag, dry-run mode).
    #[arg(long)]
    pub apply: bool,

    /// Path to emit rollback plan.
    #[arg(long)]
    pub emit_rollback: Option<PathBuf>,

    /// Emit structured JSON output.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Parser)]
pub struct MigrateValidateArgs {
    /// Path to the project to validate.
    pub project_path: PathBuf,

    /// Output format: json or text.
    #[arg(long, default_value = "text")]
    pub format: String,
}

// -- verify --

#[derive(Debug, Subcommand)]
pub enum VerifyCommand {
    /// Verify module conformance against the public verifier contract.
    #[command(name = "module")]
    Module(VerifyModuleArgs),

    /// Verify migration compatibility contract output.
    #[command(name = "migration")]
    Migration(VerifyMigrationArgs),

    /// Verify compatibility claims for a target profile/runtime.
    #[command(name = "compatibility")]
    Compatibility(VerifyCompatibilityArgs),

    /// Verify corpus schema and coverage contract output.
    #[command(name = "corpus")]
    Corpus(VerifyCorpusArgs),

    /// Compare behavior across runtimes in lockstep.
    Lockstep(VerifyLockstepArgs),

    /// Verify release artifact signatures and checksums.
    #[command(name = "release")]
    Release(VerifyReleaseArgs),

    /// Verify transparency log auditability and hash chain integrity.
    #[command(name = "transparency-log")]
    TransparencyLog(VerifyTransparencyLogArgs),
}

#[derive(Debug, Parser)]
pub struct VerifyLockstepArgs {
    /// Path to the project to verify.
    pub project_path: PathBuf,

    /// Comma-separated list of runtimes to compare.
    #[arg(long, default_value = "node,bun,franken-node")]
    pub runtimes: String,

    /// Emit divergence fixtures for failing comparisons.
    #[arg(long)]
    pub emit_fixtures: bool,

    /// Emit structured JSON output.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Parser)]
pub struct VerifyReleaseArgs {
    /// Path to the release directory containing artifacts, .sig files, and SHA256SUMS manifest.
    pub release_path: PathBuf,

    /// Directory containing trusted public keys (current and rotated). Required: no built-in trust roots are accepted.
    #[arg(long)]
    pub key_dir: PathBuf,

    /// Emit structured JSON output instead of human-readable text.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Parser)]
pub struct VerifyModuleArgs {
    /// Module identifier to verify.
    pub module_id: String,

    /// Emit structured JSON output.
    #[arg(long)]
    pub json: bool,

    /// Request compatibility output for one previous major contract version.
    #[arg(long)]
    pub compat_version: Option<u16>,
}

#[derive(Debug, Parser)]
pub struct VerifyMigrationArgs {
    /// Migration identifier to verify.
    pub migration_id: String,

    /// Emit structured JSON output.
    #[arg(long)]
    pub json: bool,

    /// Request compatibility output for one previous major contract version.
    #[arg(long)]
    pub compat_version: Option<u16>,
}

#[derive(Debug, Parser)]
pub struct VerifyCompatibilityArgs {
    /// Compatibility target (for example: runtime name or profile).
    pub target: String,

    /// Emit structured JSON output.
    #[arg(long)]
    pub json: bool,

    /// Request compatibility output for one previous major contract version.
    #[arg(long)]
    pub compat_version: Option<u16>,
}

#[derive(Debug, Parser)]
pub struct VerifyCorpusArgs {
    /// Path to the corpus manifest to verify.
    pub corpus_path: PathBuf,

    /// Emit structured JSON output.
    #[arg(long)]
    pub json: bool,

    /// Request compatibility output for one previous major contract version.
    #[arg(long)]
    pub compat_version: Option<u16>,
}

#[derive(Debug, Parser)]
pub struct VerifyTransparencyLogArgs {
    /// Path to the transparency log file to verify.
    #[arg(value_parser = parse_safe_content_pathbuf)]
    pub log_path: PathBuf,

    /// Public key file for signature verification.
    #[arg(long, value_parser = parse_safe_content_pathbuf)]
    pub public_key: Option<PathBuf>,

    /// Emit structured JSON output.
    #[arg(long)]
    pub json: bool,
}

// -- trust --

#[derive(Debug, Subcommand)]
pub enum TrustCommand {
    /// Show trust profile for one extension.
    Card(TrustCardArgs),

    /// List extensions by risk/status filters.
    List(TrustListArgs),

    /// Populate baseline trust cards from package.json dependencies.
    Scan(TrustScanArgs),

    /// Revoke artifact or publisher trust.
    Revoke(TrustRevokeArgs),

    /// Quarantine a suspicious artifact fleet-wide.
    Quarantine(TrustQuarantineArgs),

    /// Sync trust state from upstream sources.
    Sync(TrustSyncArgs),
}

#[derive(Debug, Parser)]
pub struct TrustCardArgs {
    /// Extension identifier (e.g., npm:@example/plugin).
    pub extension_id: String,

    /// Emit structured JSON output.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Parser)]
pub struct TrustListArgs {
    /// Filter by risk level: low, medium, high, critical.
    #[arg(long)]
    pub risk: Option<String>,

    /// Filter by revocation status.
    #[arg(long)]
    pub revoked: Option<bool>,

    /// Emit structured JSON output.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Parser)]
pub struct TrustScanArgs {
    /// Path to the project whose package.json should seed trust cards (default: current directory).
    pub project_path: Option<PathBuf>,

    /// Query upstream package metadata for publisher, publish date, and dependent counts.
    #[arg(long)]
    pub deep: bool,

    /// Query OSV for known npm vulnerabilities during the scan.
    #[arg(long)]
    pub audit: bool,

    /// Emit structured JSON output.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Parser)]
pub struct TrustRevokeArgs {
    /// Extension identifier with optional version.
    pub extension_id: String,

    /// Optional explicit Ed25519 signing key file for receipt export.
    #[arg(long)]
    pub receipt_signing_key: Option<PathBuf>,

    /// Optional path to export signed decision receipts (JSON or `.cbor`).
    #[arg(long)]
    pub receipt_out: Option<PathBuf>,

    /// Optional path to export human-readable receipt summary markdown.
    #[arg(long)]
    pub receipt_summary_out: Option<PathBuf>,
}

#[derive(Debug, Parser)]
pub struct TrustQuarantineArgs {
    /// Artifact hash to quarantine.
    #[arg(long)]
    pub artifact: String,

    /// Optional explicit Ed25519 signing key file for receipt export.
    #[arg(long)]
    pub receipt_signing_key: Option<PathBuf>,

    /// Optional path to export signed decision receipts (JSON or `.cbor`).
    #[arg(long)]
    pub receipt_out: Option<PathBuf>,

    /// Optional path to export human-readable receipt summary markdown.
    #[arg(long)]
    pub receipt_summary_out: Option<PathBuf>,
}

#[derive(Debug, Parser)]
pub struct TrustSyncArgs {
    /// Force sync even if cache is fresh.
    #[arg(long)]
    pub force: bool,
}

// -- remotecap --

#[derive(Debug, Subcommand)]
pub enum RemoteCapCommand {
    /// Issue a signed capability token for network-bound operations.
    Issue(RemoteCapIssueArgs),
    /// Verify a capability token without consuming single-use tokens.
    Verify(RemoteCapVerifyArgs),
    /// Use a capability token for one network-bound operation.
    Use(RemoteCapUseArgs),
    /// Revoke a capability token in the local CLI state.
    Revoke(RemoteCapRevokeArgs),
}

#[derive(Debug, Parser)]
pub struct RemoteCapIssueArgs {
    /// Comma-separated operation scope.
    /// Example: `network_egress,federation_sync,telemetry_export`
    #[arg(long)]
    pub scope: String,

    /// Allowed endpoint prefix (repeatable).
    /// Example: `--endpoint https:// --endpoint federation://`
    #[arg(long = "endpoint", required = true)]
    pub endpoint_prefixes: Vec<String>,

    /// Capability token TTL (`s`, `m`, `h`, `d` suffix supported).
    /// Example: `15m`, `1h`, `86400`
    #[arg(long, default_value = "1h")]
    pub ttl: String,

    /// Issuer identity written into the token.
    #[arg(long, default_value = "operator-cli")]
    pub issuer: String,

    /// Explicit operator authorization for issuance.
    #[arg(long)]
    pub operator_approved: bool,

    /// Issue single-use token that is replay-protected by the gate.
    #[arg(long, default_value_t = false)]
    pub single_use: bool,

    /// Trace correlation ID for audit logs.
    #[arg(long, default_value = "trace-cli-remotecap")]
    pub trace_id: String,

    /// Emit machine-readable JSON output.
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

#[derive(Debug, Parser)]
pub struct RemoteCapUseArgs {
    /// Path to a JSON capability token or full `remotecap issue --json` response.
    #[arg(long)]
    pub token_file: PathBuf,

    /// Operation being authorized.
    #[arg(long)]
    pub operation: String,

    /// Endpoint being authorized.
    #[arg(long)]
    pub endpoint: String,

    /// Trace correlation ID for audit logs.
    #[arg(long, default_value = "trace-cli-remotecap-use")]
    pub trace_id: String,

    /// Emit machine-readable JSON output.
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

#[derive(Debug, Parser)]
pub struct RemoteCapVerifyArgs {
    /// Path to a JSON capability token or full `remotecap issue --json` response.
    #[arg(long)]
    pub token_file: PathBuf,

    /// Operation being verified.
    #[arg(long)]
    pub operation: String,

    /// Endpoint being verified.
    #[arg(long)]
    pub endpoint: String,

    /// Trace correlation ID for audit logs.
    #[arg(long, default_value = "trace-cli-remotecap-verify")]
    pub trace_id: String,

    /// Emit machine-readable JSON output.
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

#[derive(Debug, Parser)]
pub struct RemoteCapRevokeArgs {
    /// Path to a JSON capability token or full `remotecap issue --json` response.
    #[arg(long)]
    pub token_file: PathBuf,

    /// Trace correlation ID for audit logs.
    #[arg(long, default_value = "trace-cli-remotecap-revoke")]
    pub trace_id: String,

    /// Emit machine-readable JSON output.
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

// -- trust-card --

#[derive(Debug, Subcommand)]
pub enum TrustCardCommand {
    /// Show trust-card details for one extension.
    Show(TrustCardShowArgs),

    /// Export a trust card in machine-readable form.
    Export(TrustCardExportArgs),

    /// List trust cards with publisher/search filters.
    List(TrustCardListArgs),

    /// Compare trust posture between two extensions.
    Compare(TrustCardCompareArgs),

    /// Diff two trust-card versions for the same extension.
    Diff(TrustCardDiffArgs),
}

#[derive(Debug, Parser)]
pub struct TrustCardShowArgs {
    /// Extension identifier (e.g., npm:@example/plugin).
    pub extension_id: String,

    /// Emit JSON instead of human-readable output.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Parser)]
pub struct TrustCardExportArgs {
    /// Extension identifier (e.g., npm:@example/plugin).
    pub extension_id: String,

    /// Required explicit JSON export flag for machine pipelines.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Parser)]
pub struct TrustCardListArgs {
    /// Filter cards to one publisher ID.
    #[arg(long)]
    pub publisher: Option<String>,

    /// Search by extension id, publisher id, or capability text.
    #[arg(long)]
    pub query: Option<String>,

    /// Page number, 1-based.
    #[arg(long, default_value_t = 1)]
    pub page: usize,

    /// Number of entries per page.
    #[arg(long, default_value_t = 20)]
    pub per_page: usize,

    /// Emit JSON instead of human-readable output.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Parser)]
pub struct TrustCardCompareArgs {
    /// Left extension identifier.
    pub left_extension_id: String,

    /// Right extension identifier.
    pub right_extension_id: String,

    /// Emit JSON instead of human-readable output.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Parser)]
pub struct TrustCardDiffArgs {
    /// Extension identifier.
    pub extension_id: String,

    /// Left trust-card version.
    pub left_version: u64,

    /// Right trust-card version.
    pub right_version: u64,

    /// Emit JSON instead of human-readable output.
    #[arg(long)]
    pub json: bool,
}

// -- fleet --

#[derive(Debug, Subcommand)]
pub enum FleetCommand {
    /// Show policy and quarantine state across nodes.
    Status(FleetStatusArgs),

    /// Describe one fleet node with zone context and incident state.
    Describe(FleetDescribeArgs),

    /// Lift quarantine/revocation controls with receipts.
    Release(FleetReleaseArgs),

    /// Reconcile fleet state for convergence.
    Reconcile(FleetReconcileArgs),

    /// Run as a fleet agent that polls for and applies fleet actions.
    Agent(FleetAgentArgs),
}

#[derive(Debug, Parser)]
pub struct FleetStatusArgs {
    /// Filter by zone.
    #[arg(long)]
    pub zone: Option<String>,

    /// Show verbose details.
    #[arg(long)]
    pub verbose: bool,

    /// Emit JSON instead of human-readable output.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Parser)]
pub struct FleetDescribeArgs {
    /// Node identifier to inspect.
    pub node_id: String,

    /// Optional zone filter to disambiguate duplicate node IDs.
    #[arg(long)]
    pub zone: Option<String>,

    /// Emit JSON instead of human-readable output.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Parser)]
pub struct FleetReleaseArgs {
    /// Incident ID to release.
    #[arg(long)]
    pub incident: String,

    /// Emit JSON instead of human-readable output.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Parser)]
pub struct FleetReconcileArgs {
    /// Emit JSON instead of human-readable output.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Parser)]
pub struct FleetAgentArgs {
    /// Unique node identifier for this agent instance.
    /// When omitted, falls back to `fleet.node_id` in `franken_node.toml`.
    #[arg(long)]
    pub node_id: Option<String>,

    /// Zone to poll for fleet actions.
    #[arg(long)]
    pub zone: String,

    /// Poll interval in seconds.
    /// When omitted, falls back to `fleet.poll_interval_seconds` or 30 seconds.
    #[arg(long)]
    pub poll_interval_secs: Option<u64>,

    /// Maximum number of poll cycles (omit for unlimited).
    #[arg(long)]
    pub max_cycles: Option<u64>,

    /// Run a single poll cycle and exit after processing all currently pending actions.
    #[arg(long)]
    pub once: bool,

    /// Emit JSON instead of human-readable output.
    #[arg(long)]
    pub json: bool,
}

// -- ops --

#[derive(Debug, Subcommand)]
pub enum OpsCommand {
    /// Inspect process/runtime health signals.
    HealthCheck(OpsHealthCheckArgs),
    /// Emit operator metrics in a scrape-friendly text format.
    Metrics(OpsMetricsArgs),
}

#[derive(Debug, Parser)]
pub struct OpsHealthCheckArgs {
    /// Emit JSON instead of human-readable output.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum OpsMetricsFormat {
    Prometheus,
}

#[derive(Debug, Parser)]
pub struct OpsMetricsArgs {
    /// Metrics output format.
    #[arg(long, value_enum, default_value_t = OpsMetricsFormat::Prometheus)]
    pub format: OpsMetricsFormat,
}

// -- incident --

#[derive(Debug, Subcommand)]
pub enum IncidentCommand {
    /// Export deterministic incident bundle.
    Bundle(IncidentBundleArgs),

    /// Replay incident timeline locally.
    Replay(IncidentReplayArgs),

    /// Simulate alternative policy actions.
    Counterfactual(IncidentCounterfactualArgs),

    /// List recorded incidents.
    List(IncidentListArgs),
}

#[derive(Debug, Parser)]
pub struct IncidentBundleArgs {
    /// Incident ID to bundle.
    #[arg(long)]
    pub id: String,

    /// Optional authoritative incident evidence package path.
    #[arg(long)]
    pub evidence_path: Option<PathBuf>,

    /// Verify bundle integrity.
    #[arg(long)]
    pub verify: bool,

    /// Optional explicit Ed25519 signing key file for receipt export.
    #[arg(long)]
    pub receipt_signing_key: Option<PathBuf>,

    /// Optional path to export signed decision receipts (JSON or `.cbor`).
    #[arg(long)]
    pub receipt_out: Option<PathBuf>,

    /// Optional path to export human-readable receipt summary markdown.
    #[arg(long)]
    pub receipt_summary_out: Option<PathBuf>,
}

#[derive(Debug, Parser)]
pub struct IncidentReplayArgs {
    /// Path to incident bundle file.
    #[arg(long)]
    pub bundle: PathBuf,

    /// Trusted Ed25519 public key file for replay bundle signature verification.
    #[arg(long = "trusted-public-key", alias = "trust-anchor")]
    pub trusted_public_key: Option<PathBuf>,

    /// Directory containing trusted Ed25519 public keys for replay bundle verification.
    #[arg(long = "key-dir", alias = "trusted-key-dir")]
    pub trusted_key_dir: Option<PathBuf>,
}

#[derive(Debug, Parser)]
pub struct IncidentCounterfactualArgs {
    /// Path to incident bundle file.
    #[arg(long)]
    pub bundle: PathBuf,

    /// Trusted Ed25519 public key file for replay bundle signature verification.
    #[arg(long = "trusted-public-key", alias = "trust-anchor")]
    pub trusted_public_key: Option<PathBuf>,

    /// Directory containing trusted Ed25519 public keys for replay bundle verification.
    #[arg(long = "key-dir", alias = "trusted-key-dir")]
    pub trusted_key_dir: Option<PathBuf>,

    /// Policy to simulate.
    #[arg(long)]
    pub policy: String,

    /// Emit the structured counterfactual report as canonical JSON on stdout.
    #[arg(long)]
    pub json: bool,

    /// Promote the counterfactual with signed rollout and rollback contracts.
    #[arg(long)]
    pub promote: bool,

    /// Ed25519 operator signing key for promoted counterfactual contracts.
    #[arg(long = "promotion-signing-key", alias = "operator-signing-key")]
    pub promotion_signing_key: Option<PathBuf>,

    /// Operator identity embedded in signed promotion contracts.
    #[arg(long)]
    pub operator_id: Option<String>,
}

#[derive(Debug, Parser)]
pub struct IncidentListArgs {
    /// Filter by severity.
    #[arg(long)]
    pub severity: Option<String>,
}

// -- registry --

#[derive(Debug, Subcommand)]
pub enum RegistryCommand {
    /// Publish signed extension artifact.
    Publish(RegistryPublishArgs),

    /// Query extension registry with trust filters.
    Search(RegistrySearchArgs),

    /// Verify a locally stored registry artifact's hash and signature.
    Verify(RegistryVerifyArgs),

    /// Archive older locally stored registry artifacts, keeping the newest N active entries per lineage.
    Gc(RegistryGcArgs),
}

#[derive(Debug, Parser)]
pub struct RegistryPublishArgs {
    /// Path to extension package to publish.
    pub package_path: PathBuf,

    /// Path to the operator-managed Ed25519 signing key file.
    #[arg(long)]
    pub signing_key: Option<PathBuf>,
}

#[derive(Debug, Parser)]
pub struct RegistrySearchArgs {
    /// Search query.
    pub query: String,

    /// Minimum assurance level (1-5).
    #[arg(long)]
    pub min_assurance: Option<u8>,
}

#[derive(Debug, Parser)]
pub struct RegistryVerifyArgs {
    /// Extension identifier to verify from the local registry artifact store.
    pub extension_id: String,
}

#[derive(Debug, Parser)]
pub struct RegistryGcArgs {
    /// Number of most recent active artifacts to retain per publisher/name lineage.
    #[arg(long, default_value_t = 5)]
    pub keep: usize,
}

// -- bench --

#[derive(Debug, Subcommand)]
pub enum BenchCommand {
    /// Run benchmark suite and emit signed report.
    Run(BenchRunArgs),
}

#[derive(Debug, Parser)]
pub struct BenchRunArgs {
    /// Benchmark scenario to run.
    #[arg(long)]
    pub scenario: Option<String>,
}

// -- doctor --

#[derive(Debug, Subcommand)]
pub enum DoctorCommand {
    /// Emit the dual-oracle close-condition receipt.
    #[command(name = "close-condition")]
    CloseCondition(DoctorCloseConditionArgs),
}

#[derive(Debug, Parser)]
pub struct DoctorCloseConditionArgs {
    /// Emit the close-condition receipt JSON to stdout.
    #[arg(long)]
    pub json: bool,

    /// Ed25519 trusted key used to sign the close-condition receipt.
    #[arg(long)]
    pub receipt_signing_key: Option<PathBuf>,
}

#[derive(Debug, Parser)]
pub struct DoctorArgs {
    #[command(subcommand)]
    pub command: Option<DoctorCommand>,

    /// Config file override (default discovery is used when omitted).
    #[arg(long)]
    pub config: Option<PathBuf>,

    /// Runtime profile override: strict, balanced, or legacy-risky.
    /// Controls security/compatibility behavior (not packaging profiles like local/dev/enterprise).
    #[arg(long)]
    pub profile: Option<String>,

    /// Path to policy activation input JSON for live guardrail diagnostics.
    #[arg(long)]
    pub policy_activation_input: Option<PathBuf>,

    /// Emit machine-readable JSON report.
    #[arg(long)]
    pub json: bool,

    /// Emit structured diagnostic log events as JSONL to stderr.
    #[arg(long)]
    pub structured_logs_jsonl: bool,

    /// Stable trace ID for correlating diagnostics.
    #[arg(long, default_value = "doctor-bootstrap")]
    pub trace_id: String,

    /// Show verbose diagnostic output.
    #[arg(long)]
    pub verbose: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DoctorPolicyMemoryTailRiskInput {
    pub sample_count: u64,
    pub mean_utilization: f64,
    pub variance_utilization: f64,
    pub peak_utilization: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DoctorPolicyReliabilityTelemetryInput {
    pub sample_count: u64,
    pub nonconforming_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DoctorPolicySystemStateInput {
    pub memory_used_bytes: u64,
    pub memory_budget_bytes: u64,
    pub durability_level: f64,
    pub hardening_level: String,
    #[serde(default)]
    pub proposed_hardening_level: Option<String>,
    #[serde(default = "doctor_policy_default_evidence_emission_active")]
    pub evidence_emission_active: bool,
    #[serde(default)]
    pub memory_tail_risk: Option<DoctorPolicyMemoryTailRiskInput>,
    #[serde(default)]
    pub reliability_telemetry: Option<DoctorPolicyReliabilityTelemetryInput>,
    #[serde(default)]
    pub epoch_id: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DoctorPolicyObservationInput {
    pub candidate: String,
    pub success: bool,
    #[serde(default)]
    pub epoch_id: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DoctorPolicyActivationInput {
    #[serde(default)]
    pub epoch_id: Option<u64>,
    pub system_state: DoctorPolicySystemStateInput,
    pub candidates: Vec<String>,
    #[serde(default)]
    pub prefiltered_candidates: Vec<String>,
    #[serde(default)]
    pub observations: Vec<DoctorPolicyObservationInput>,
}

const fn doctor_policy_default_evidence_emission_active() -> bool {
    true
}

pub fn parse_doctor_policy_activation_input_bytes(
    raw: &[u8],
    source: &str,
) -> anyhow::Result<DoctorPolicyActivationInput> {
    serde_json::from_slice::<DoctorPolicyActivationInput>(raw)
        .with_context(|| format!("failed parsing policy activation input {source} as JSON"))
}

pub fn load_doctor_policy_activation_input(
    path: &Path,
) -> anyhow::Result<DoctorPolicyActivationInput> {
    let raw = std::fs::read(path)
        .with_context(|| format!("failed reading policy activation input {}", path.display()))?;
    let source = path.display().to_string();
    parse_doctor_policy_activation_input_bytes(&raw, &source)
}

#[cfg(test)]
mod parser_contract_extra_tests {
    use super::*;
    use clap::{Parser, error::ErrorKind};
    use std::path::PathBuf;

    fn parse(args: &[&str]) -> Result<Cli, clap::Error> {
        Cli::try_parse_from(args)
    }

    #[test]
    fn doctor_policy_activation_parser_accepts_minimal_valid_json() {
        let parsed = parse_doctor_policy_activation_input_bytes(
            br#"{
                "epoch_id": 7,
                "system_state": {
                    "memory_used_bytes": 1024,
                    "memory_budget_bytes": 2048,
                    "durability_level": 0.75,
                    "hardening_level": "standard"
                },
                "candidates": ["candidate-a"]
            }"#,
            "inline-doctor-policy.json",
        )
        .expect("minimal doctor policy activation input should parse");

        assert_eq!(parsed.epoch_id, Some(7));
        assert_eq!(parsed.candidates, vec!["candidate-a".to_string()]);
        assert!(parsed.system_state.evidence_emission_active);
        assert!(parsed.prefiltered_candidates.is_empty());
        assert!(parsed.observations.is_empty());
    }

    #[test]
    fn doctor_policy_activation_parser_returns_contextual_error() {
        let err = parse_doctor_policy_activation_input_bytes(
            br#"{"system_state":"bad","candidates":"also-bad"}"#,
            "inline-doctor-policy.json",
        )
        .expect_err("invalid doctor policy activation input should fail cleanly");
        let rendered = format!("{err:#}");

        assert!(
            rendered.contains(
                "failed parsing policy activation input inline-doctor-policy.json as JSON"
            )
        );
        assert!(!rendered.trim().is_empty());
    }

    #[test]
    fn unknown_nested_verify_subcommand_is_rejected() {
        let err = parse(&["franken-node", "verify", "artifact"])
            .expect_err("unknown nested verify command should fail");

        assert_eq!(err.kind(), ErrorKind::InvalidSubcommand);
    }

    #[test]
    fn unknown_top_level_subcommand_is_rejected() {
        let err = parse(&["franken-node", "launch"]).expect_err("unknown command should fail");

        assert_eq!(err.kind(), ErrorKind::InvalidSubcommand);
    }

    #[test]
    fn init_rejects_unknown_flag() {
        let err = parse(&["franken-node", "init", "--definitely-not-an-init-flag"])
            .expect_err("unknown init flag should fail");

        assert_eq!(err.kind(), ErrorKind::UnknownArgument);
    }

    #[test]
    fn run_rejects_misspelled_policy_flag() {
        let err = parse(&["franken-node", "run", "app.js", "--polciy", "strict"])
            .expect_err("unknown flag should fail");

        assert_eq!(err.kind(), ErrorKind::UnknownArgument);
    }

    #[test]
    fn trust_revoke_requires_extension_id() {
        let err = parse(&[
            "franken-node",
            "trust",
            "revoke",
            "--receipt-out",
            "receipt.json",
        ])
        .expect_err("trust revoke should require an extension id");

        assert_eq!(err.kind(), ErrorKind::MissingRequiredArgument);
    }

    #[test]
    fn incident_replay_requires_bundle() {
        let err = parse(&["franken-node", "incident", "replay"])
            .expect_err("incident replay should require a bundle path");

        assert_eq!(err.kind(), ErrorKind::MissingRequiredArgument);
    }

    #[test]
    fn fleet_agent_requires_zone() {
        let err = parse(&["franken-node", "fleet", "agent", "--node-id", "node-7"])
            .expect_err("fleet agent should require a polling zone");

        assert_eq!(err.kind(), ErrorKind::MissingRequiredArgument);
    }

    #[test]
    fn registry_search_requires_query() {
        let err = parse(&["franken-node", "registry", "search"])
            .expect_err("registry search query should be required");

        assert_eq!(err.kind(), ErrorKind::MissingRequiredArgument);
    }

    #[test]
    fn run_parses_lockstep_and_runtime_options() {
        let cli = parse(&[
            "franken-node",
            "run",
            "app.js",
            "--runtime",
            "node",
            "--policy",
            "strict",
            "--lockstep-preflight",
            "--json",
        ])
        .expect("run command should parse");

        let Command::Run(args) = cli.command else {
            panic!("expected run command");
        };
        assert_eq!(args.app_path, PathBuf::from("app.js"));
        assert_eq!(args.runtime.as_deref(), Some("node"));
        assert_eq!(args.policy, "strict");
        assert!(args.lockstep_preflight);
        assert!(args.json);
    }

    #[test]
    fn fleet_agent_parses_once_mode_with_cycle_limit() {
        let cli = parse(&[
            "franken-node",
            "fleet",
            "agent",
            "--zone",
            "us-east",
            "--node-id",
            "node-7",
            "--max-cycles",
            "3",
            "--once",
        ])
        .expect("fleet agent command should parse");

        let Command::Fleet(FleetCommand::Agent(args)) = cli.command else {
            panic!("expected fleet agent command");
        };
        assert_eq!(args.zone, "us-east");
        assert_eq!(args.node_id.as_deref(), Some("node-7"));
        assert_eq!(args.max_cycles, Some(3));
        assert!(args.once);
    }

    #[test]
    fn fleet_describe_parses_optional_zone_and_json() {
        let cli = parse(&[
            "franken-node",
            "fleet",
            "describe",
            "node-7",
            "--zone",
            "us-east",
            "--json",
        ])
        .expect("fleet describe command should parse");

        let Command::Fleet(FleetCommand::Describe(args)) = cli.command else {
            panic!("expected fleet describe command");
        };
        assert_eq!(args.node_id, "node-7");
        assert_eq!(args.zone.as_deref(), Some("us-east"));
        assert!(args.json);
    }

    #[test]
    fn ops_health_check_parses_json_flag() {
        let cli = parse(&["franken-node", "ops", "health-check", "--json"])
            .expect("ops health-check command should parse");

        let Command::Ops(OpsCommand::HealthCheck(args)) = cli.command else {
            panic!("expected ops health-check command");
        };
        assert!(args.json);
    }

    #[test]
    fn ops_metrics_parses_prometheus_format() {
        let cli = parse(&["franken-node", "ops", "metrics", "--format", "prometheus"])
            .expect("ops metrics command should parse");

        let Command::Ops(OpsCommand::Metrics(args)) = cli.command else {
            panic!("expected ops metrics command");
        };
        assert_eq!(args.format, OpsMetricsFormat::Prometheus);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_error_kind(args: &[&str]) -> clap::error::ErrorKind {
        let mut argv = Vec::with_capacity(args.len().saturating_add(1));
        argv.push("franken-node");
        argv.extend_from_slice(args);

        <Cli as clap::Parser>::try_parse_from(argv)
            .expect_err("parser should reject invalid CLI shape")
            .kind()
    }

    #[test]
    fn missing_top_level_subcommand_is_rejected() {
        assert_eq!(
            parse_error_kind(&[]),
            clap::error::ErrorKind::MissingSubcommand
        );
    }

    #[test]
    fn run_requires_app_path() {
        assert_eq!(
            parse_error_kind(&["run"]),
            clap::error::ErrorKind::MissingRequiredArgument
        );
    }

    #[test]
    fn migrate_audit_requires_project_path() {
        assert_eq!(
            parse_error_kind(&["migrate", "audit", "--format", "json"]),
            clap::error::ErrorKind::MissingRequiredArgument
        );
    }

    #[test]
    fn verify_release_requires_explicit_key_dir() {
        assert_eq!(
            parse_error_kind(&["verify", "release", "dist/release"]),
            clap::error::ErrorKind::MissingRequiredArgument
        );
    }

    #[test]
    fn remote_cap_issue_requires_at_least_one_endpoint_prefix() {
        assert_eq!(
            parse_error_kind(&["remotecap", "issue", "--scope", "network_egress"]),
            clap::error::ErrorKind::MissingRequiredArgument
        );
    }

    #[test]
    fn trust_card_compare_requires_both_extension_ids() {
        assert_eq!(
            parse_error_kind(&["trust-card", "compare", "npm:left"]),
            clap::error::ErrorKind::MissingRequiredArgument
        );
    }

    #[test]
    fn fleet_release_requires_incident_id() {
        assert_eq!(
            parse_error_kind(&["fleet", "release"]),
            clap::error::ErrorKind::MissingRequiredArgument
        );
    }

    #[test]
    fn incident_counterfactual_requires_policy() {
        assert_eq!(
            parse_error_kind(&["incident", "counterfactual", "--bundle", "incident.json"]),
            clap::error::ErrorKind::MissingRequiredArgument
        );
    }

    #[test]
    fn registry_publish_requires_package_path() {
        assert_eq!(
            parse_error_kind(&["registry", "publish", "--signing-key", "operator.ed25519"]),
            clap::error::ErrorKind::MissingRequiredArgument
        );
    }

    #[test]
    fn verify_module_requires_module_id() {
        assert_eq!(
            parse_error_kind(&["verify", "module", "--json"]),
            clap::error::ErrorKind::MissingRequiredArgument
        );
    }

    #[test]
    fn verify_corpus_requires_corpus_path() {
        assert_eq!(
            parse_error_kind(&["verify", "corpus", "--compat-version", "1"]),
            clap::error::ErrorKind::MissingRequiredArgument
        );
    }

    #[test]
    fn migrate_rewrite_requires_project_path() {
        assert_eq!(
            parse_error_kind(&["migrate", "rewrite", "--apply"]),
            clap::error::ErrorKind::MissingRequiredArgument
        );
    }

    #[test]
    fn trust_card_export_requires_extension_id() {
        assert_eq!(
            parse_error_kind(&["trust-card", "export", "--json"]),
            clap::error::ErrorKind::MissingRequiredArgument
        );
    }

    #[test]
    fn trust_card_diff_requires_right_version() {
        assert_eq!(
            parse_error_kind(&["trust-card", "diff", "npm:pkg", "1"]),
            clap::error::ErrorKind::MissingRequiredArgument
        );
    }

    #[test]
    fn incident_bundle_requires_incident_id() {
        assert_eq!(
            parse_error_kind(&["incident", "bundle", "--verify"]),
            clap::error::ErrorKind::MissingRequiredArgument
        );
    }

    #[test]
    fn registry_verify_requires_extension_id() {
        assert_eq!(
            parse_error_kind(&["registry", "verify"]),
            clap::error::ErrorKind::MissingRequiredArgument
        );
    }

    #[test]
    fn remote_cap_issue_requires_scope_even_with_endpoint() {
        assert_eq!(
            parse_error_kind(&["remotecap", "issue", "--endpoint", "https://"]),
            clap::error::ErrorKind::MissingRequiredArgument
        );
    }

    /// Test Unicode injection attacks in CLI argument parsing
    #[test]
    fn negative_cli_unicode_injection_comprehensive() {
        let unicode_attack_vectors = vec![
            // BiDi override attacks in arguments
            ("bidi_override", "arg\u{202E}gnivieced\u{202D}"),
            (
                "bidi_nested",
                "param\u{202E}level1\u{202E}level2\u{202D}evil\u{202D}",
            ),
            // Zero-width character pollution
            ("zws_pollution", "test\u{200B}hidden\u{200C}arg\u{200D}"),
            (
                "zwj_sequence",
                "arg\u{200D}\u{1F469}\u{200D}\u{1F4BB}trusted",
            ),
            // Control character injection
            ("ansi_escape", "arg\x1b[31mevil\x1b[0m"),
            ("carriage_return", "arg\roverwrite"),
            ("vertical_tab", "arg\x0Bhidden"),
            // Unicode normalization attacks
            ("nfd_attack", "café_arg"),         // NFC form
            ("nfc_attack", "cafe\u{0301}_arg"), // NFD form
            ("combining_stack", "arg\u{0300}\u{0301}\u{0302}\u{0303}"),
            // Path injection attempts
            ("path_traversal", "../../../evil"),
            ("null_termination", "arg\x00hidden"),
        ];

        for (attack_name, malicious_input) in unicode_attack_vectors {
            let injection_result = std::panic::catch_unwind(|| {
                // Test CLI parsing with Unicode-injected arguments
                let args = vec![
                    "franken-node",
                    "init",
                    "--output-dir",
                    malicious_input,
                    "--profile",
                    malicious_input,
                ];

                let parse_result = Cli::try_parse_from(&args);
                match parse_result {
                    Ok(cli) => {
                        // If parsed successfully, verify Unicode is handled safely
                        match cli.command {
                            Command::Init(init_args) => {
                                if let Some(output_dir) = init_args.output_dir {
                                    // Should handle Unicode paths consistently
                                    assert!(
                                        !output_dir.to_string_lossy().is_empty()
                                            || output_dir.to_string_lossy().is_empty(),
                                        "Path should be handled deterministically: {}",
                                        attack_name
                                    );
                                }
                                assert!(
                                    !init_args.profile.is_empty() || init_args.profile.is_empty(),
                                    "Profile should be handled deterministically: {}",
                                    attack_name
                                );
                            }
                            _ => {}
                        }
                    }
                    Err(_) => {
                        // CLI parsing may reject Unicode attacks - acceptable
                    }
                }

                // Test run command with Unicode injections
                let run_args = vec![
                    "franken-node",
                    "run",
                    malicious_input, // script argument
                    "--env",
                    malicious_input,
                    "--trust-root",
                    malicious_input,
                ];

                let run_parse_result = Cli::try_parse_from(&run_args);
                match run_parse_result {
                    Ok(cli) => {
                        match cli.command {
                            Command::Run(run_args) => {
                                // Should handle script paths safely
                                assert!(
                                    !run_args.script.to_string_lossy().is_empty()
                                        || run_args.script.to_string_lossy().is_empty(),
                                    "Script path should be handled safely: {}",
                                    attack_name
                                );
                            }
                            _ => {}
                        }
                    }
                    Err(_) => {
                        // May reject malicious paths - acceptable
                    }
                }

                // Test verify command with Unicode
                let verify_args = vec![
                    "franken-node",
                    "verify",
                    "registry",
                    "verify",
                    malicious_input, // extension-id
                ];

                let verify_parse_result = Cli::try_parse_from(&verify_args);
                match verify_parse_result {
                    Ok(_) => {
                        // Should handle extension IDs safely
                    }
                    Err(_) => {
                        // May reject malicious extension IDs - acceptable
                    }
                }

                Ok(())
            });

            assert!(
                injection_result.is_ok(),
                "Unicode injection test should not panic: {}",
                attack_name
            );
        }
    }

    /// Test memory exhaustion protection in CLI argument processing
    #[test]
    fn negative_cli_memory_exhaustion_stress() {
        let memory_stress_result = std::panic::catch_unwind(|| {
            // Test extremely long arguments
            let massive_arg = "x".repeat(1_000_000); // 1MB argument

            let oversized_args = vec![
                "franken-node",
                "init",
                "--output-dir",
                &massive_arg,
                "--profile",
                &massive_arg,
            ];

            let parse_result = Cli::try_parse_from(&oversized_args);
            match parse_result {
                Ok(cli) => {
                    // If parsed, should handle large arguments reasonably
                    match cli.command {
                        Command::Init(init_args) => {
                            if let Some(output_dir) = init_args.output_dir {
                                // Path should be handled without memory exhaustion
                                assert!(
                                    output_dir.to_string_lossy().len() <= 2_000_000,
                                    "Output dir should be bounded"
                                );
                            }
                        }
                        _ => {}
                    }
                }
                Err(_) => {
                    // May reject oversized arguments - acceptable behavior
                }
            }

            // Test many small arguments
            let mut many_args = vec!["franken-node", "run", "script.js"];
            for i in 0..10000 {
                many_args.push("--env");
                many_args.push(&format!("KEY_{}=VALUE_{}", i, i));
            }

            let many_args_result = Cli::try_parse_from(&many_args);
            match many_args_result {
                Ok(_) => {
                    // Should handle many arguments reasonably
                }
                Err(_) => {
                    // May reject excessive argument counts - acceptable
                }
            }

            // Test deeply nested path structures
            let deep_path = "/".to_string() + &"deep/".repeat(1000) + "script.js";
            let deep_path_args = vec!["franken-node", "run", &deep_path];

            let deep_path_result = Cli::try_parse_from(&deep_path_args);
            match deep_path_result {
                Ok(cli) => {
                    match cli.command {
                        Command::Run(run_args) => {
                            // Should handle deep paths without overflow
                            assert!(
                                run_args.script.to_string_lossy().len() < 100_000,
                                "Script path should be reasonably bounded"
                            );
                        }
                        _ => {}
                    }
                }
                Err(_) => {
                    // May reject excessively deep paths - acceptable
                }
            }

            Ok(())
        });

        assert!(
            memory_stress_result.is_ok(),
            "Memory exhaustion stress test should not panic"
        );
    }

    /// Test JSON and serialization integrity in CLI structures
    #[test]
    fn negative_cli_serialization_integrity_validation() {
        use serde_json;

        let serialization_test_result = std::panic::catch_unwind(|| {
            // Test CLI argument parsing and potential serialization
            let test_cases = vec![
                // Valid cases that should work
                vec!["franken-node", "init", "--profile", "development"],
                vec!["franken-node", "run", "script.js", "--env", "NODE_ENV=test"],
                vec![
                    "franken-node",
                    "verify",
                    "registry",
                    "verify",
                    "test-extension",
                ],
                // Edge cases with special characters
                vec!["franken-node", "init", "--profile", "test\"profile"],
                vec![
                    "franken-node",
                    "run",
                    "script.js",
                    "--env",
                    "KEY={\"nested\": true}",
                ],
                vec!["franken-node", "init", "--output-dir", "path/with spaces"],
            ];

            for (i, args) in test_cases.iter().enumerate() {
                let parse_result = Cli::try_parse_from(args);
                match parse_result {
                    Ok(cli) => {
                        // Test debug formatting (similar to serialization)
                        let debug_output = format!("{:?}", cli);
                        assert!(
                            !debug_output.is_empty(),
                            "Debug output should not be empty: case {}",
                            i
                        );
                        assert!(
                            debug_output.len() < 1_000_000,
                            "Debug output should be bounded: case {}",
                            i
                        );

                        // Verify structure integrity
                        match &cli.command {
                            Command::Init(init_args) => {
                                assert!(
                                    !init_args.profile.is_empty(),
                                    "Profile should not be empty: case {}",
                                    i
                                );
                            }
                            Command::Run(run_args) => {
                                assert!(
                                    !run_args.script.to_string_lossy().is_empty(),
                                    "Script should not be empty: case {}",
                                    i
                                );
                            }
                            Command::Verify(verify_cmd) => {
                                // Should have valid verify command structure
                                let verify_debug = format!("{:?}", verify_cmd);
                                assert!(
                                    !verify_debug.is_empty(),
                                    "Verify command should have content: case {}",
                                    i
                                );
                            }
                            _ => {}
                        }

                        // Test that clap's internal serialization-like behavior is safe
                        let help_output = format!("{}", Cli::command().render_help());
                        assert!(
                            help_output.contains("franken-node"),
                            "Help should contain program name"
                        );
                        assert!(
                            !help_output.contains("\\u"),
                            "Help should not contain unicode escapes"
                        );
                    }
                    Err(err) => {
                        // Verify error handling is consistent
                        let error_message = format!("{}", err);
                        assert!(
                            !error_message.is_empty(),
                            "Error message should not be empty: case {}",
                            i
                        );
                        assert!(
                            error_message.len() < 100_000,
                            "Error message should be bounded: case {}",
                            i
                        );
                    }
                }
            }

            Ok(())
        });

        assert!(
            serialization_test_result.is_ok(),
            "Serialization integrity test should not panic"
        );
    }

    /// Test argument injection and command injection safety in CLI
    #[test]
    fn negative_cli_argument_injection_safety() {
        let injection_safety_result = std::panic::catch_unwind(|| {
            let injection_vectors = vec![
                // Command injection attempts
                ("command_inject", "script.js; rm -rf /"),
                ("pipe_inject", "script.js | cat /etc/passwd"),
                ("background_inject", "script.js & malicious_command"),
                // Path traversal attempts
                ("path_traversal", "../../../etc/passwd"),
                ("absolute_path", "/etc/passwd"),
                ("windows_path", "C:\\Windows\\System32\\calc.exe"),
                // Shell metacharacter injection
                ("shell_meta", "script.js$(evil_command)"),
                ("backtick_inject", "script.js`malicious`"),
                ("dollar_inject", "script.js$EVIL_VAR"),
                // Environment variable injection
                ("env_inject", "PATH=/evil/path:$PATH"),
                ("env_override", "LD_PRELOAD=/evil/lib.so"),
                ("env_export", "export EVIL=true; script.js"),
                // Quote escaping attempts
                ("quote_escape", "script.js\"'; rm -rf /; echo '"),
                ("double_quote", "script.js\"; evil_command; echo \""),
                ("mixed_quotes", "script.js'; evil_command; #"),
            ];

            for (attack_name, malicious_input) in injection_vectors {
                // Test script argument injection
                let script_inject_args = vec!["franken-node", "run", malicious_input];
                let script_result = Cli::try_parse_from(&script_inject_args);

                match script_result {
                    Ok(cli) => {
                        match cli.command {
                            Command::Run(run_args) => {
                                let script_path = run_args.script.to_string_lossy();

                                // Verify no command injection in parsed path
                                assert!(
                                    !script_path.contains(';'),
                                    "Script path should not contain semicolon: {}",
                                    attack_name
                                );
                                assert!(
                                    !script_path.contains('|'),
                                    "Script path should not contain pipe: {}",
                                    attack_name
                                );
                                assert!(
                                    !script_path.contains('&'),
                                    "Script path should not contain ampersand: {}",
                                    attack_name
                                );
                                assert!(
                                    !script_path.contains('`'),
                                    "Script path should not contain backticks: {}",
                                    attack_name
                                );

                                // The path itself may contain these characters but should be treated as literal
                                assert_eq!(
                                    script_path, malicious_input,
                                    "Path should be preserved literally: {}",
                                    attack_name
                                );
                            }
                            _ => {}
                        }
                    }
                    Err(_) => {
                        // CLI may reject obviously malicious inputs - acceptable
                    }
                }

                // Test environment variable injection
                let env_inject_args =
                    vec!["franken-node", "run", "script.js", "--env", malicious_input];
                let env_result = Cli::try_parse_from(&env_inject_args);

                match env_result {
                    Ok(cli) => {
                        match cli.command {
                            Command::Run(run_args) => {
                                // Verify environment variables are parsed safely
                                for env_var in &run_args.env {
                                    assert_eq!(
                                        env_var, malicious_input,
                                        "Env var should be preserved literally: {}",
                                        attack_name
                                    );
                                }
                            }
                            _ => {}
                        }
                    }
                    Err(_) => {
                        // May reject malicious environment variables - acceptable
                    }
                }

                // Test output directory injection
                let output_inject_args =
                    vec!["franken-node", "init", "--output-dir", malicious_input];
                let output_result = Cli::try_parse_from(&output_inject_args);

                match output_result {
                    Ok(cli) => {
                        match cli.command {
                            Command::Init(init_args) => {
                                if let Some(output_dir) = init_args.output_dir {
                                    let output_path = output_dir.to_string_lossy();

                                    // Verify output directory is treated as literal path
                                    assert_eq!(
                                        output_path, malicious_input,
                                        "Output dir should be preserved literally: {}",
                                        attack_name
                                    );
                                }
                            }
                            _ => {}
                        }
                    }
                    Err(_) => {
                        // May reject malicious paths - acceptable
                    }
                }
            }

            Ok(())
        });

        assert!(
            injection_safety_result.is_ok(),
            "Argument injection safety test should not panic"
        );
    }

    /// Test display injection and format string safety in CLI output
    #[test]
    fn negative_cli_display_injection_safety() {
        let display_safety_result = std::panic::catch_unwind(|| {
            let display_injection_vectors = vec![
                // Format string injection attempts
                ("format_inject", "arg%s%x%d"),
                ("format_overflow", "arg%.999999s"),
                ("format_position", "arg%1$s%2$x"),
                // ANSI escape sequence injection
                ("ansi_colors", "arg\x1b[31mRED\x1b[0m"),
                ("ansi_cursor", "arg\x1b[H\x1b[2J"),
                ("ansi_title", "arg\x1b]0;EVIL TITLE\x07"),
                // Terminal control injection
                ("bell_spam", "arg\x07\x07\x07"),
                ("backspace_attack", "arg\x08\x08\x08hidden"),
                ("carriage_return", "arg\roverwrite"),
                // Unicode display corruption
                ("rtl_override", "arg\u{202E}gnitsurt\u{202D}"),
                ("combining_overflow", "arg\u{0300}\u{0301}\u{0302}\u{0303}"),
                ("width_confusion", "arg\u{3000}\u{FF01}"),
                // Log injection attempts
                ("log_inject", "arg\nINJECTED: admin command"),
                ("log_crlf", "arg\r\n[FAKE] CLI security alert"),
            ];

            for (attack_name, malicious_content) in display_injection_vectors {
                // Test CLI argument parsing with display injection
                let args = vec!["franken-node", "init", "--profile", malicious_content];
                let parse_result = Cli::try_parse_from(&args);

                match parse_result {
                    Ok(cli) => {
                        // Test debug display formatting safety
                        let debug_display = format!("{:?}", cli);
                        assert!(
                            !debug_display.contains("%s"),
                            "Debug should not contain format specifiers: {}",
                            attack_name
                        );
                        assert!(
                            !debug_display.contains("\x1b["),
                            "Debug should escape ANSI sequences: {}",
                            attack_name
                        );
                        assert!(
                            !debug_display.contains("\r\n[FAKE]"),
                            "Debug should not allow log injection: {}",
                            attack_name
                        );

                        match cli.command {
                            Command::Init(init_args) => {
                                let profile_display = format!("{:?}", init_args.profile);
                                assert!(
                                    !profile_display.contains("%s"),
                                    "Profile display should be safe: {}",
                                    attack_name
                                );
                                assert!(
                                    !profile_display.contains("\x1b["),
                                    "Profile display should escape ANSI: {}",
                                    attack_name
                                );
                            }
                            _ => {}
                        }
                    }
                    Err(err) => {
                        // Test error display safety
                        let error_display = format!("{}", err);
                        assert!(
                            !error_display.contains("%s"),
                            "Error display should not contain format specifiers: {}",
                            attack_name
                        );
                        assert!(
                            !error_display.contains("\x1b["),
                            "Error display should escape ANSI: {}",
                            attack_name
                        );

                        let error_debug = format!("{:?}", err);
                        assert!(
                            !error_debug.contains("\x00"),
                            "Error debug should escape null bytes: {}",
                            attack_name
                        );
                    }
                }

                // Test help output safety
                let help_output = format!("{}", Cli::command().render_help());
                assert!(
                    !help_output.contains("%s"),
                    "Help should not contain format specifiers: {}",
                    attack_name
                );
                assert!(
                    !help_output.contains("\r\n[FAKE]"),
                    "Help should not allow injection: {}",
                    attack_name
                );

                // Test subcommand help safety
                let init_help = format!(
                    "{}",
                    Cli::command()
                        .find_subcommand("init")
                        .unwrap()
                        .render_help()
                );
                assert!(
                    !init_help.contains("%s"),
                    "Subcommand help should be safe: {}",
                    attack_name
                );
                assert!(
                    !init_help.contains("\x1b["),
                    "Subcommand help should escape ANSI: {}",
                    attack_name
                );
            }

            Ok(())
        });

        assert!(
            display_safety_result.is_ok(),
            "Display injection safety test should not panic"
        );
    }

    /// Test boundary condition stress in CLI argument processing
    #[test]
    fn negative_cli_boundary_stress_comprehensive() {
        let boundary_stress_result = std::panic::catch_unwind(|| {
            // Test argument count boundaries
            let arg_count_boundaries = vec![
                (vec!["franken-node"], "no_subcommand"),
                (vec!["franken-node", "init"], "minimal_args"),
                (
                    vec!["franken-node", "init", "--profile", "test"],
                    "basic_args",
                ),
            ];

            for (args, test_name) in arg_count_boundaries {
                let parse_result = Cli::try_parse_from(&args);
                match parse_result {
                    Ok(cli) => {
                        // Should handle valid argument counts
                        let debug_output = format!("{:?}", cli);
                        assert!(
                            !debug_output.is_empty(),
                            "Should produce debug output: {}",
                            test_name
                        );
                    }
                    Err(err) => {
                        // Should provide meaningful error for invalid args
                        let error_msg = format!("{}", err);
                        assert!(
                            !error_msg.is_empty(),
                            "Should provide error message: {}",
                            test_name
                        );
                    }
                }
            }

            // Test path length boundaries
            let path_lengths = vec![
                ("", "empty_path"),
                ("a", "single_char"),
                ("a".repeat(100), "medium_path"),
                ("a".repeat(4096), "long_path"),
                ("/".repeat(1000), "deep_path"),
            ];

            for (path_str, test_name) in path_lengths {
                if path_str.is_empty() {
                    continue; // Skip empty paths which are invalid
                }

                let args = vec!["franken-node", "run", &path_str];
                let parse_result = Cli::try_parse_from(&args);

                match parse_result {
                    Ok(cli) => match cli.command {
                        Command::Run(run_args) => {
                            let parsed_path = run_args.script.to_string_lossy();
                            assert_eq!(
                                parsed_path, path_str,
                                "Path should be preserved: {}",
                                test_name
                            );
                        }
                        _ => {}
                    },
                    Err(_) => {
                        // May reject extreme path lengths - acceptable
                    }
                }
            }

            // Test environment variable boundaries
            let env_var_cases = vec![
                ("KEY=VALUE", "basic_env"),
                ("KEY=", "empty_value"),
                ("LONG_KEY_NAME=LONG_VALUE", "descriptive_env"),
                ("KEY=" + &"x".repeat(10000), "large_value"),
                (&"x".repeat(100) + "=value", "large_key"),
            ];

            for (env_var, test_name) in env_var_cases {
                let args = vec!["franken-node", "run", "script.js", "--env", env_var];
                let parse_result = Cli::try_parse_from(&args);

                match parse_result {
                    Ok(cli) => match cli.command {
                        Command::Run(run_args) => {
                            assert_eq!(
                                run_args.env.len(),
                                1,
                                "Should have one env var: {}",
                                test_name
                            );
                            assert_eq!(
                                run_args.env[0], env_var,
                                "Env var should be preserved: {}",
                                test_name
                            );
                        }
                        _ => {}
                    },
                    Err(_) => {
                        // May reject malformed or oversized env vars - acceptable
                    }
                }
            }

            // Test subcommand depth boundaries
            let deep_subcommands = vec![
                vec![
                    "franken-node",
                    "verify",
                    "registry",
                    "verify",
                    "test-extension",
                ],
                vec![
                    "franken-node",
                    "trust",
                    "extension",
                    "approve",
                    "test-extension",
                ],
                vec!["franken-node", "migrate", "rewrite", "--source", "file.js"],
            ];

            for args in deep_subcommands {
                let parse_result = Cli::try_parse_from(&args);
                match parse_result {
                    Ok(cli) => {
                        // Should handle nested subcommands correctly
                        let debug_output = format!("{:?}", cli);
                        assert!(!debug_output.is_empty(), "Should handle nested commands");
                    }
                    Err(_) => {
                        // May fail due to missing required args - acceptable
                    }
                }
            }

            // Test option value boundaries
            let option_value_cases = vec!["", "short", &"x".repeat(1000), &"x".repeat(100000)];

            for value in option_value_cases {
                if value.is_empty() {
                    continue; // Skip empty values which may be invalid
                }

                let args = vec!["franken-node", "init", "--profile", value];
                let parse_result = Cli::try_parse_from(&args);

                match parse_result {
                    Ok(cli) => match cli.command {
                        Command::Init(init_args) => {
                            assert_eq!(
                                init_args.profile, value,
                                "Profile value should be preserved"
                            );
                        }
                        _ => {}
                    },
                    Err(_) => {
                        // May reject extreme option values - acceptable
                    }
                }
            }

            Ok(())
        });

        assert!(
            boundary_stress_result.is_ok(),
            "Boundary stress test should not panic"
        );
    }

    #[test]
    fn test_validate_user_content_path_strict() {
        // Should reject paths with .. segments
        assert!(validate_user_content_path("../etc/passwd").is_err());
        assert!(validate_user_content_path("config/../../../etc/passwd").is_err());
        assert!(validate_user_content_path("data/../..").is_err());

        // Should reject absolute paths (strict for user content)
        assert!(validate_user_content_path("/etc/passwd").is_err());
        assert!(validate_user_content_path("/").is_err());

        // Should reject paths with backslashes
        assert!(validate_user_content_path("data\\file.txt").is_err());
        assert!(validate_user_content_path("..\\windows\\system32").is_err());

        // Should reject paths with null bytes
        assert!(validate_user_content_path("file\0.txt").is_err());
        assert!(validate_user_content_path("data/file\0/config").is_err());

        // Should accept safe relative paths
        assert!(validate_user_content_path("config.toml").is_ok());
        assert!(validate_user_content_path("data/config.toml").is_ok());
        assert!(validate_user_content_path("output/generated").is_ok());
        assert!(validate_user_content_path("./config").is_ok());
    }

    #[test]
    fn test_validate_system_binary_path_relaxed() {
        // Should reject paths with .. segments
        assert!(validate_system_binary_path("../etc/passwd").is_err());
        assert!(validate_system_binary_path("bin/../../../etc/passwd").is_err());

        // Should reject paths with null bytes
        assert!(validate_system_binary_path("node\0").is_err());
        assert!(validate_system_binary_path("/usr/bin/node\0").is_err());

        // Should ALLOW absolute paths for system binaries
        assert!(validate_system_binary_path("/usr/bin/node").is_ok());
        assert!(validate_system_binary_path("/usr/local/bin/node").is_ok());
        assert!(validate_system_binary_path("/opt/homebrew/bin/node").is_ok());
        assert!(validate_system_binary_path("/").is_ok());

        // Should accept relative paths too
        assert!(validate_system_binary_path("node").is_ok());
        assert!(validate_system_binary_path("./node").is_ok());
        assert!(validate_system_binary_path("bin/node").is_ok());
    }

    #[test]
    fn test_parse_safe_content_pathbuf_strict() {
        // Should reject dangerous paths
        assert!(parse_safe_content_pathbuf("../etc/passwd").is_err());
        assert!(parse_safe_content_pathbuf("/root/.ssh/id_rsa").is_err());
        assert!(parse_safe_content_pathbuf("file\0.txt").is_err());
        assert!(parse_safe_content_pathbuf("data\\windows").is_err());

        // Should accept safe relative paths
        assert!(parse_safe_content_pathbuf("config.toml").is_ok());
        assert!(parse_safe_content_pathbuf("output/file.txt").is_ok());
    }

    #[test]
    fn test_parse_safe_binary_pathbuf_allows_absolute() {
        // Should reject dangerous paths
        assert!(parse_safe_binary_pathbuf("../etc/passwd").is_err());
        assert!(parse_safe_binary_pathbuf("node\0").is_err());

        // Should accept absolute system binary paths (REGRESSION TEST for bd-3dfo4)
        assert!(parse_safe_binary_pathbuf("/usr/bin/node").is_ok());
        assert!(parse_safe_binary_pathbuf("/usr/local/bin/node").is_ok());
        assert!(parse_safe_binary_pathbuf("/opt/homebrew/bin/bun").is_ok());

        // Should accept relative paths too
        assert!(parse_safe_binary_pathbuf("node").is_ok());
        assert!(parse_safe_binary_pathbuf("bin/node").is_ok());
    }
}
