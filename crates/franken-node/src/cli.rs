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
    /// Runtime profile: strict, balanced, or legacy-risky.
    #[arg(long, default_value = "balanced")]
    pub profile: String,

    /// Output directory for generated config files.
    #[arg(long)]
    pub out_dir: Option<PathBuf>,
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
    /// Compare behavior across runtimes in lockstep.
    Lockstep(VerifyLockstepArgs),
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
}

#[derive(Debug, Parser)]
pub struct TrustQuarantineArgs {
    /// Artifact hash to quarantine.
    #[arg(long)]
    pub artifact: String,
}

#[derive(Debug, Parser)]
pub struct TrustSyncArgs {
    /// Force sync even if cache is fresh.
    #[arg(long)]
    pub force: bool,
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

    /// Verify bundle integrity.
    #[arg(long)]
    pub verify: bool,
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
    /// Show verbose diagnostic output.
    #[arg(long)]
    pub verbose: bool,
}
