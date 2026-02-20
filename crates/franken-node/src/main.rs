#![forbid(unsafe_code)]

mod cli;
mod config;
pub mod conformance;
pub mod connector;
pub mod control_plane;
pub mod encoding;
pub mod observability;
pub mod policy;
#[path = "control_plane/root_pointer.rs"]
pub mod root_pointer;
pub mod runtime;
pub mod security;
pub mod supply_chain;
pub mod tools;

use anyhow::{Context, Result};
use clap::Parser;
use std::path::Path;

use cli::{
    BenchCommand, Cli, Command, FleetCommand, IncidentCommand, MigrateCommand, RegistryCommand,
    TrustCommand, VerifyCommand,
};
use security::decision_receipt::{
    Decision, Receipt, ReceiptQuery, append_signed_receipt, demo_signing_key,
    export_receipts_to_path, write_receipts_markdown,
};

fn maybe_export_demo_receipts(
    action_name: &str,
    actor_identity: &str,
    rationale: &str,
    receipt_out: Option<&Path>,
    receipt_summary_out: Option<&Path>,
) -> Result<()> {
    if receipt_out.is_none() && receipt_summary_out.is_none() {
        return Ok(());
    }

    let mut chain = Vec::new();
    let key = demo_signing_key();

    let receipt = Receipt::new(
        action_name,
        actor_identity,
        &serde_json::json!({
            "command": action_name,
            "actor": actor_identity,
        }),
        &serde_json::json!({
            "status": "accepted",
            "receipt_exported": true,
        }),
        Decision::Approved,
        rationale,
        vec!["ledger:pending-10.14".to_string()],
        vec!["policy.rule.high-impact-receipt".to_string()],
        0.93,
        "franken-node trust sync --force",
    )?;
    append_signed_receipt(&mut chain, receipt, &key)?;

    let filter = ReceiptQuery::default();
    if let Some(path) = receipt_out {
        export_receipts_to_path(&chain, &filter, path)
            .with_context(|| format!("failed writing receipt export to {}", path.display()))?;
    }
    if let Some(path) = receipt_summary_out {
        write_receipts_markdown(&chain, path)
            .with_context(|| format!("failed writing receipt summary to {}", path.display()))?;
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Init(args) => {
            eprintln!(
                "franken-node init: profile={} out_dir={:?}",
                args.profile, args.out_dir
            );
            eprintln!("[not yet implemented]");
        }

        Command::Run(args) => {
            eprintln!(
                "franken-node run: app={} policy={}",
                args.app_path.display(),
                args.policy
            );
            eprintln!("[not yet implemented]");
        }

        Command::Migrate(sub) => match sub {
            MigrateCommand::Audit(args) => {
                eprintln!(
                    "franken-node migrate audit: project={} format={}",
                    args.project_path.display(),
                    args.format
                );
                eprintln!("[not yet implemented]");
            }
            MigrateCommand::Rewrite(args) => {
                eprintln!(
                    "franken-node migrate rewrite: project={} apply={}",
                    args.project_path.display(),
                    args.apply
                );
                eprintln!("[not yet implemented]");
            }
            MigrateCommand::Validate(args) => {
                eprintln!(
                    "franken-node migrate validate: project={}",
                    args.project_path.display()
                );
                eprintln!("[not yet implemented]");
            }
        },

        Command::Verify(sub) => match sub {
            VerifyCommand::Lockstep(args) => {
                eprintln!(
                    "franken-node verify lockstep: project={} runtimes={}",
                    args.project_path.display(),
                    args.runtimes
                );
                eprintln!("[not yet implemented]");
            }
        },

        Command::Trust(sub) => match sub {
            TrustCommand::Card(args) => {
                eprintln!("franken-node trust card: extension={}", args.extension_id);
                eprintln!("[not yet implemented]");
            }
            TrustCommand::List(args) => {
                eprintln!(
                    "franken-node trust list: risk={:?} revoked={:?}",
                    args.risk, args.revoked
                );
                eprintln!("[not yet implemented]");
            }
            TrustCommand::Revoke(args) => {
                eprintln!("franken-node trust revoke: extension={}", args.extension_id);
                maybe_export_demo_receipts(
                    "revocation",
                    "trust-control-plane",
                    "Revocation decision exported for audit traceability",
                    args.receipt_out.as_deref(),
                    args.receipt_summary_out.as_deref(),
                )?;
                eprintln!("[not yet implemented]");
            }
            TrustCommand::Quarantine(args) => {
                eprintln!("franken-node trust quarantine: artifact={}", args.artifact);
                maybe_export_demo_receipts(
                    "quarantine",
                    "trust-control-plane",
                    "Quarantine decision exported for incident forensics",
                    args.receipt_out.as_deref(),
                    args.receipt_summary_out.as_deref(),
                )?;
                eprintln!("[not yet implemented]");
            }
            TrustCommand::Sync(args) => {
                eprintln!("franken-node trust sync: force={}", args.force);
                eprintln!("[not yet implemented]");
            }
        },

        Command::Fleet(sub) => match sub {
            FleetCommand::Status(args) => {
                eprintln!(
                    "franken-node fleet status: zone={:?} verbose={}",
                    args.zone, args.verbose
                );
                eprintln!("[not yet implemented]");
            }
            FleetCommand::Release(args) => {
                eprintln!("franken-node fleet release: incident={}", args.incident);
                eprintln!("[not yet implemented]");
            }
            FleetCommand::Reconcile(_) => {
                eprintln!("franken-node fleet reconcile");
                eprintln!("[not yet implemented]");
            }
        },

        Command::Incident(sub) => match sub {
            IncidentCommand::Bundle(args) => {
                eprintln!(
                    "franken-node incident bundle: id={} verify={}",
                    args.id, args.verify
                );
                maybe_export_demo_receipts(
                    "incident_bundle",
                    "incident-control-plane",
                    "Incident bundle receipt export for deterministic replay evidence",
                    args.receipt_out.as_deref(),
                    args.receipt_summary_out.as_deref(),
                )?;
                eprintln!("[not yet implemented]");
            }
            IncidentCommand::Replay(args) => {
                eprintln!(
                    "franken-node incident replay: bundle={}",
                    args.bundle.display()
                );
                eprintln!("[not yet implemented]");
            }
            IncidentCommand::Counterfactual(args) => {
                eprintln!(
                    "franken-node incident counterfactual: bundle={} policy={}",
                    args.bundle.display(),
                    args.policy
                );
                eprintln!("[not yet implemented]");
            }
            IncidentCommand::List(args) => {
                eprintln!("franken-node incident list: severity={:?}", args.severity);
                eprintln!("[not yet implemented]");
            }
        },

        Command::Registry(sub) => match sub {
            RegistryCommand::Publish(args) => {
                eprintln!(
                    "franken-node registry publish: package={}",
                    args.package_path.display()
                );
                eprintln!("[not yet implemented]");
            }
            RegistryCommand::Search(args) => {
                eprintln!(
                    "franken-node registry search: query={} min_assurance={:?}",
                    args.query, args.min_assurance
                );
                eprintln!("[not yet implemented]");
            }
        },

        Command::Bench(sub) => match sub {
            BenchCommand::Run(args) => {
                eprintln!("franken-node bench run: scenario={:?}", args.scenario);
                eprintln!("[not yet implemented]");
            }
        },

        Command::Doctor(args) => {
            eprintln!("franken-node doctor: verbose={}", args.verbose);
            eprintln!("[not yet implemented]");
        }
    }

    Ok(())
}
