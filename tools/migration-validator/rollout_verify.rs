#![forbid(unsafe_code)]

//! Read-only independent verification of signed rollout state and its history.
//! No project execution, key discovery, signing or recovery command is exposed.

use clap::Parser;
use std::path::PathBuf;
use std::process::ExitCode;

#[path = "../../crates/franken-node/src/migration/rollout_receipt.rs"]
pub mod rollout_receipt;

#[derive(Parser)]
#[command(version, about = "Verify operator-signed rollout state and its complete predecessor chain")]
struct Args {
    /// Signed current state file, not a migrate-rollout CLI report.
    state: PathBuf,
    /// Independently trusted operator public key, 64 lowercase hex characters.
    #[arg(long)]
    public_key: String,
    /// Exact canonical project path signed by the operator; need not exist here.
    #[arg(long)]
    project: String,
    #[arg(long)]
    migration_id: String,
    /// Independently retained head checkpoint; detects replay to a different revision.
    #[arg(long)]
    expected_head_sha256: Option<String>,
    /// Directory containing .signed-SHA256.json receipts; defaults to the state's parent.
    #[arg(long)]
    receipts_dir: Option<PathBuf>,
    /// Also print the verified state, which may contain private project metadata.
    #[arg(long)]
    include_state: bool,
}

#[cfg(target_os = "linux")]
fn run(args: Args) -> anyhow::Result<()> {
    use anyhow::{Context, ensure};
    use rustix::fs::{Mode, OFlags, open, openat};
    use std::fs::File;
    use std::io::Read;
    use std::os::unix::fs::MetadataExt;
    use std::path::Path;
    use rollout_receipt::{MAX_RECEIPT_BYTES, public_key, receipt_name, verify, verify_chain};

    fn directory(path: &Path) -> anyhow::Result<File> {
        Ok(File::from(open(path, OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty())?))
    }
    fn read(dir: &File, name: &std::ffi::OsStr) -> anyhow::Result<Vec<u8>> {
        let mut file = File::from(openat(dir, name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC, Mode::empty())?);
        let before = file.metadata()?;
        ensure!(before.is_file() && before.nlink() == 1 && before.len() <= MAX_RECEIPT_BYTES as u64,
            "receipt must be a bounded unlinked regular file");
        let mut raw = Vec::new();
        file.by_ref().take(MAX_RECEIPT_BYTES as u64 + 1).read_to_end(&mut raw)?;
        let after = file.metadata()?;
        ensure!(raw.len() <= MAX_RECEIPT_BYTES && before.len() == after.len()
            && before.ctime() == after.ctime() && before.ctime_nsec() == after.ctime_nsec()
            && before.mtime() == after.mtime() && before.mtime_nsec() == after.mtime_nsec(),
            "receipt changed while reading");
        Ok(raw)
    }

    // These independent authority arguments are validated before reading state.
    let trusted = public_key(&args.public_key)?;
    let name = format!("{}.json", args.migration_id);
    let parent = args.state.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
    let source = directory(parent)?;
    let head = read(&source, args.state.file_name().context("state filename missing")?)?;
    let archive = match &args.receipts_dir {
        Some(path) => directory(path)?,
        None => source.try_clone()?,
    };
    let verified = verify_chain(&head, &trusted, &args.project, &name, args.expected_head_sha256.as_deref(),
        |hash| read(&archive, std::ffi::OsStr::new(&receipt_name(hash)?)))?;
    let mut output = serde_json::to_value(verified)?;
    if args.include_state {
        let receipt = verify(&head, &trusted, &args.project, &name)?;
        output["state"] = serde_json::from_slice(receipt.state_bytes())?;
    }
    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}

fn main() -> ExitCode {
    let args = Args::parse();
    #[cfg(target_os = "linux")]
    match run(args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("rollout history verification refused: {error:#}");
            ExitCode::from(1)
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = args;
        eprintln!("rollout receipt file verification is supported on Linux only");
        ExitCode::from(2)
    }
}
