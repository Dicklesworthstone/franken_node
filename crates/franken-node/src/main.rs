#![forbid(unsafe_code)]

pub mod api;
mod cli;
mod config;
pub mod conformance;
pub mod connector;
pub mod control_plane;
pub mod encoding;
pub mod observability;
pub mod policy;
pub mod repair;
#[path = "control_plane/root_pointer.rs"]
pub mod root_pointer;
pub mod runtime;
pub mod security;
pub mod storage;
pub mod supply_chain;
pub mod tools;

use anyhow::{Context, Result};
use clap::Parser;
use std::path::{Path, PathBuf};

use api::trust_card_routes::{
    Pagination, compare_trust_card_versions, compare_trust_cards, get_trust_card,
    get_trust_cards_by_publisher, list_trust_cards, search_trust_cards,
};
use cli::{
    BenchCommand, Cli, Command, FleetCommand, IncidentCommand, MigrateCommand, RegistryCommand,
    TrustCardCommand, TrustCommand, VerifyCommand,
};
use security::decision_receipt::{
    Decision, Receipt, ReceiptQuery, append_signed_receipt, demo_signing_key,
    export_receipts_to_path, write_receipts_markdown,
};
use supply_chain::trust_card::{
    TrustCard, TrustCardListFilter, TrustCardRegistry, demo_registry as demo_trust_registry,
    render_comparison_human, render_trust_card_human, to_canonical_json as trust_card_to_json,
};
use tools::counterfactual_replay::{
    CounterfactualReplayEngine, PolicyConfig, summarize_output,
    to_canonical_json as counterfactual_to_json,
};
use tools::replay_bundle::{
    generate_replay_bundle, read_bundle_from_path, replay_bundle as replay_incident_bundle,
    synthetic_incident_events, validate_bundle_integrity, write_bundle_to_path,
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

fn incident_bundle_output_path(incident_id: &str) -> PathBuf {
    let mut slug = String::new();
    for ch in incident_id.chars() {
        if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
            slug.push(ch);
        } else {
            slug.push('_');
        }
    }
    if slug.is_empty() {
        slug.push_str("incident");
    }
    PathBuf::from(format!(
        "artifacts/section_10_5/bd-vll/{}_bundle.json",
        slug
    ))
}

fn now_unix_secs() -> u64 {
    let ts = chrono::Utc::now().timestamp();
    if ts <= 0 { 0 } else { ts as u64 }
}

fn trust_card_cli_registry() -> Result<TrustCardRegistry> {
    demo_trust_registry(now_unix_secs()).map_err(Into::into)
}

fn render_trust_card_list(cards: &[TrustCard]) -> String {
    if cards.is_empty() {
        return "no trust cards matched the current filters".to_string();
    }

    let mut lines = Vec::with_capacity(cards.len() + 1);
    lines.push("extension | publisher | cert | reputation | status".to_string());
    for card in cards {
        let status = match &card.revocation_status {
            supply_chain::trust_card::RevocationStatus::Active => "active".to_string(),
            supply_chain::trust_card::RevocationStatus::Revoked { reason, .. } => {
                format!("revoked:{reason}")
            }
        };
        lines.push(format!(
            "{} | {} | {:?} | {}bp ({:?}) | {}",
            card.extension.extension_id,
            card.publisher.publisher_id,
            card.certification_level,
            card.reputation_score_basis_points,
            card.reputation_trend,
            status
        ));
    }
    lines.join("\n")
}

fn handle_trust_card_command(command: TrustCardCommand) -> Result<()> {
    let mut registry = trust_card_cli_registry()?;
    let now_secs = now_unix_secs();
    let trace_id = "trace-cli-trust-card";

    match command {
        TrustCardCommand::Show(args) => {
            let response = get_trust_card(&mut registry, &args.extension_id, now_secs, trace_id)?;
            let card = response
                .data
                .ok_or_else(|| anyhow::anyhow!("trust card not found: {}", args.extension_id))?;
            if args.json {
                println!("{}", trust_card_to_json(&card)?);
            } else {
                println!("{}", render_trust_card_human(&card));
            }
        }
        TrustCardCommand::Export(args) => {
            if !args.json {
                anyhow::bail!("`trust-card export` requires `--json`");
            }
            let response = get_trust_card(&mut registry, &args.extension_id, now_secs, trace_id)?;
            let card = response
                .data
                .ok_or_else(|| anyhow::anyhow!("trust card not found: {}", args.extension_id))?;
            println!("{}", trust_card_to_json(&card)?);
        }
        TrustCardCommand::List(args) => {
            let pagination = Pagination {
                page: args.page,
                per_page: args.per_page,
            };
            let response = if let Some(query) = args.query.as_deref() {
                search_trust_cards(&mut registry, query, now_secs, trace_id, pagination)?
            } else if let Some(publisher_id) = args.publisher.as_deref() {
                get_trust_cards_by_publisher(
                    &mut registry,
                    publisher_id,
                    now_secs,
                    trace_id,
                    pagination,
                )?
            } else {
                list_trust_cards(
                    &mut registry,
                    &TrustCardListFilter::empty(),
                    now_secs,
                    trace_id,
                    pagination,
                )?
            };

            if args.json {
                println!("{}", trust_card_to_json(&response)?);
            } else {
                println!("{}", render_trust_card_list(&response.data));
            }
        }
        TrustCardCommand::Compare(args) => {
            let response = compare_trust_cards(
                &mut registry,
                &args.left_extension_id,
                &args.right_extension_id,
                now_secs,
                trace_id,
            )?;
            if args.json {
                println!("{}", trust_card_to_json(&response)?);
            } else {
                println!("{}", render_comparison_human(&response.data));
            }
        }
        TrustCardCommand::Diff(args) => {
            let response = compare_trust_card_versions(
                &mut registry,
                &args.extension_id,
                args.left_version,
                args.right_version,
                now_secs,
                trace_id,
            )?;
            if args.json {
                println!("{}", trust_card_to_json(&response)?);
            } else {
                println!("{}", render_comparison_human(&response.data));
            }
        }
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

        Command::TrustCard(sub) => {
            handle_trust_card_command(sub)?;
        }

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
                let events = synthetic_incident_events(&args.id);
                let bundle = generate_replay_bundle(&args.id, &events)
                    .with_context(|| format!("failed generating replay bundle for {}", args.id))?;
                if args.verify {
                    let valid = validate_bundle_integrity(&bundle).with_context(|| {
                        format!("failed validating replay bundle for {}", args.id)
                    })?;
                    eprintln!(
                        "bundle integrity: {}",
                        if valid { "valid" } else { "invalid" }
                    );
                }

                let output_path = incident_bundle_output_path(&args.id);
                write_bundle_to_path(&bundle, &output_path).with_context(|| {
                    format!(
                        "failed writing incident bundle to {}",
                        output_path.display()
                    )
                })?;

                maybe_export_demo_receipts(
                    "incident_bundle",
                    "incident-control-plane",
                    "Incident bundle receipt export for deterministic replay evidence",
                    args.receipt_out.as_deref(),
                    args.receipt_summary_out.as_deref(),
                )?;
                eprintln!("incident bundle written: {}", output_path.display());
            }
            IncidentCommand::Replay(args) => {
                eprintln!(
                    "franken-node incident replay: bundle={}",
                    args.bundle.display()
                );
                let bundle = read_bundle_from_path(&args.bundle).with_context(|| {
                    format!("failed reading replay bundle {}", args.bundle.display())
                })?;
                let outcome = replay_incident_bundle(&bundle).with_context(|| {
                    format!("failed replaying bundle {}", args.bundle.display())
                })?;
                eprintln!(
                    "incident replay result: matched={} event_count={} expected={} replayed={}",
                    outcome.matched,
                    outcome.event_count,
                    outcome.expected_sequence_hash,
                    outcome.replayed_sequence_hash
                );
                if !outcome.matched {
                    anyhow::bail!(
                        "replay mismatch for incident {} in bundle {}",
                        outcome.incident_id,
                        args.bundle.display()
                    );
                }
            }
            IncidentCommand::Counterfactual(args) => {
                eprintln!(
                    "franken-node incident counterfactual: bundle={} policy={}",
                    args.bundle.display(),
                    args.policy
                );
                let bundle = read_bundle_from_path(&args.bundle).with_context(|| {
                    format!("failed reading replay bundle {}", args.bundle.display())
                })?;
                let baseline_policy = PolicyConfig::from_bundle(&bundle);
                let mode = PolicyConfig::from_cli_spec(&args.policy, &baseline_policy)
                    .with_context(|| format!("invalid policy override spec `{}`", args.policy))?;
                let engine = CounterfactualReplayEngine::default();
                let output = engine
                    .simulate(&bundle, &baseline_policy, mode)
                    .with_context(|| {
                        format!(
                            "counterfactual replay failed for bundle {}",
                            args.bundle.display()
                        )
                    })?;
                let (total_decisions, changed_decisions, severity_delta) =
                    summarize_output(&output);
                eprintln!(
                    "counterfactual summary: total_decisions={} changed_decisions={} severity_delta={}",
                    total_decisions, changed_decisions, severity_delta
                );
                let canonical = counterfactual_to_json(&output)
                    .context("failed encoding counterfactual output to canonical json")?;
                eprintln!("counterfactual output: {canonical}");
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
