#![forbid(unsafe_code)]

use anyhow::Result;
use frankenengine_engine::HybridRouter;
use frankenengine_extension_host::snapshot_metadata;

#[tokio::main]
async fn main() -> Result<()> {
    let mut router = HybridRouter::default();
    let eval = router.eval("1 + 1")?;
    let snapshot = snapshot_metadata();

    println!(
        "frankenengine bootstrap: engine={:?} value={} snapshot={}",
        eval.engine, eval.value, snapshot.snapshot_root
    );

    Ok(())
}
