//! Compile the actual product CLI grammar without linking the sibling engine.
//! This is a parser probe, not an execution engine or a substitute runtime.
#![forbid(unsafe_code)]

#[allow(dead_code)]
#[path = "../crates/franken-node/src/cli.rs"]
mod cli;

use clap::Parser;

fn main() -> anyhow::Result<()> {
    match cli::Cli::parse().command {
        cli::Command::Run(args) => {
            args.validate_paths()?;
            println!(
                "{}",
                serde_json::json!({
                    "probe_kind": "product_cli_parser_only",
                    "command": "run",
                    "app_path": args.app_path,
                    "policy": args.policy,
                    "config": args.config,
                    "console_only": args.console_only,
                    "json": args.json,
                    "runtime": args.runtime,
                    "engine_bin": args.engine_bin,
                    "trace_id": args.trace_id,
                })
            );
            Ok(())
        }
        _ => anyhow::bail!("watchdog must invoke the policy-governed run command"),
    }
}
