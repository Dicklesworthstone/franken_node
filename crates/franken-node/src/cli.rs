#![allow(clippy::doc_markdown)]

use std::path::PathBuf;

use clap::{Parser, Subcommand};

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
    #[arg(long)]
    pub profile: Option<String>,

    /// Config file override (default discovery is used when omitted).
    #[arg(long)]
    pub config: Option<PathBuf>,

    /// Output directory for generated config files.
    #[arg(long)]
    pub out_dir: Option<PathBuf>,

    /// Overwrite existing generated files in target directory.
    #[arg(long)]
    pub overwrite: bool,

    /// Backup existing generated files before writing replacements.
    #[arg(long)]
    pub backup_existing: bool,

    /// Emit machine-readable init report.
    #[arg(long)]
    pub json: bool,

    /// Stable trace ID for correlating init events.
    #[arg(long, default_value = "init-bootstrap")]
    pub trace_id: String,
}

// -- run --

#[derive(Debug, Parser)]
pub struct RunArgs {
    /// Path to the application entry point.
    pub app_path: PathBuf,

    /// Policy mode to enforce at runtime.
    #[arg(long, default_value = "balanced")]
    pub policy: String,

    /// Config file override.
    #[arg(long)]
    pub config: Option<PathBuf>,

    /// Explicit franken_engine binary path or command name.
    #[arg(long)]
    pub engine_bin: Option<PathBuf>,
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

#[derive(Debug, Parser)]
pub struct MigrateAuditArgs {
    /// Path to the project to audit.
    pub project_path: PathBuf,

    /// Output format: json, text, or sarif.
    #[arg(long, default_value = "text")]
    pub format: String,

    /// Output file path.
    #[arg(long)]
    pub out: Option<PathBuf>,
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
}

#[derive(Debug, Parser)]
pub struct MigrateValidateArgs {
    /// Path to the project to validate.
    pub project_path: PathBuf,
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

// -- trust --

#[derive(Debug, Subcommand)]
pub enum TrustCommand {
    /// Show trust profile for one extension.
    Card(TrustCardArgs),

    /// List extensions by risk/status filters.
    List(TrustListArgs),

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
}

#[derive(Debug, Parser)]
pub struct TrustListArgs {
    /// Filter by risk level: low, medium, high, critical.
    #[arg(long)]
    pub risk: Option<String>,

    /// Filter by revocation status.
    #[arg(long)]
    pub revoked: Option<bool>,
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

    /// Lift quarantine/revocation controls with receipts.
    Release(FleetReleaseArgs),

    /// Reconcile fleet state for convergence.
    Reconcile(FleetReconcileArgs),
}

#[derive(Debug, Parser)]
pub struct FleetStatusArgs {
    /// Filter by zone.
    #[arg(long)]
    pub zone: Option<String>,

    /// Show verbose details.
    #[arg(long)]
    pub verbose: bool,
}

#[derive(Debug, Parser)]
pub struct FleetReleaseArgs {
    /// Incident ID to release.
    #[arg(long)]
    pub incident: String,
}

#[derive(Debug, Parser)]
pub struct FleetReconcileArgs {}

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
}

#[derive(Debug, Parser)]
pub struct IncidentCounterfactualArgs {
    /// Path to incident bundle file.
    #[arg(long)]
    pub bundle: PathBuf,

    /// Policy to simulate.
    #[arg(long)]
    pub policy: String,
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
}

#[derive(Debug, Parser)]
pub struct RegistryPublishArgs {
    /// Path to extension package to publish.
    pub package_path: PathBuf,
}

#[derive(Debug, Parser)]
pub struct RegistrySearchArgs {
    /// Search query.
    pub query: String,

    /// Minimum assurance level (1-5).
    #[arg(long)]
    pub min_assurance: Option<u8>,
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

#[derive(Debug, Parser)]
pub struct DoctorArgs {
    /// Config file override (default discovery is used when omitted).
    #[arg(long)]
    pub config: Option<PathBuf>,

    /// Runtime profile override: strict, balanced, or legacy-risky.
    #[arg(long)]
    pub profile: Option<String>,

    /// Path to policy activation input JSON for live guardrail diagnostics.
    #[arg(long)]
    pub policy_activation_input: Option<PathBuf>,

    /// Emit machine-readable JSON report.
    #[arg(long)]
    pub json: bool,

    /// Stable trace ID for correlating diagnostics.
    #[arg(long, default_value = "doctor-bootstrap")]
    pub trace_id: String,

    /// Show verbose diagnostic output.
    #[arg(long)]
    pub verbose: bool,
}
