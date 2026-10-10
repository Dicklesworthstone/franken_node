//! CLI adapter for collector-attested package behavior. Verification and the
//! atomic observation/card commit live in the supply-chain library.

use anyhow::{Context, Result};
use std::fs::File;
use std::io::Read;
use std::path::Path;

use crate::cli::TrustObserveArgs;
use crate::supply_chain::behavioral_observation::{MAX_OBSERVATION_BYTES, ingest_observation};

fn read_regular_input(path: &Path, limit: usize) -> Result<Vec<u8>> {
    // Nonblocking opens avoid hanging on a substituted FIFO. Check the opened
    // descriptor as well as the named file; signatures bind the bytes read.
    anyhow::ensure!(
        std::fs::symlink_metadata(path)?.is_file(),
        "input must be a regular file: {}",
        path.display()
    );
    #[cfg(unix)]
    let file = {
        use rustix::fs::{Mode, OFlags, open};
        File::from(open(
            path,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )?)
    };
    #[cfg(not(unix))]
    let file = File::open(path)?;
    let metadata = file.metadata()?;
    anyhow::ensure!(metadata.is_file(), "input must be a regular file");
    anyhow::ensure!(
        metadata.len() <= limit as u64,
        "input exceeds {limit} bytes"
    );
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1).read_to_end(&mut bytes)?;
    anyhow::ensure!(bytes.len() <= limit, "input exceeds {limit} bytes");
    Ok(bytes)
}

pub(super) fn handle(args: &TrustObserveArgs) -> Result<()> {
    anyhow::ensure!(
        !args.observation.as_os_str().is_empty(),
        "`trust observe` requires an observation file"
    );
    anyhow::ensure!(
        !args.collector_key.as_os_str().is_empty(),
        "`trust observe` requires --collector-key with a trusted collector public key"
    );
    let envelope = read_regular_input(&args.observation, MAX_OBSERVATION_BYTES)
        .with_context(|| format!("cannot read observation {}", args.observation.display()))?;
    let key_bytes = read_regular_input(&args.collector_key, 4_096)
        .with_context(|| format!("cannot read collector key {}", args.collector_key.display()))?;
    let trusted_collector = crate::parse_verifying_key_from_blob(&key_bytes)
        .context("collector key must contain an Ed25519 public key")?;

    let now_secs = crate::now_unix_secs();
    let state = crate::trust_card_cli_registry(now_secs)?;
    let report = ingest_observation(
        &state.path,
        &state.trust_config,
        &envelope,
        &trusted_collector,
        now_secs,
    )?;
    // Ingestion reloads and commits authoritative state itself. Persisting the
    // earlier `state.registry` here would race or overwrite that new version.
    if args.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!(
            "Behavioral observation: {}\n  Extension: {}@{}\n  Artifact: {}\n  Collector: {}\n  Workload: {}\n  Observation: {}\n  Samples: {}\n  Camouflage hints: {}\n  Trust card: v{} ({:?})\n  Evidence: {}\n  Measurements are attested by the pinned collector.",
            report.status,
            report.extension_id,
            report.package_version,
            report.artifact_hash,
            report.collector_key_id,
            report.workload_id,
            report.observation_id,
            report.sample_count,
            report.hints.len(),
            report.card_version,
            report.risk_level,
            report.evidence_ref,
        );
    }
    Ok(())
}
