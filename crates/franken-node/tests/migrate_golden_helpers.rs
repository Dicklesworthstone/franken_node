use insta::Settings;
use serde_json::Value;
use std::path::{Path, PathBuf};

pub fn fixture_path(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/migrate")
        .join(name)
}

pub fn pretty_json_stdout(command_name: &str, stdout: &[u8]) -> String {
    let value: Value = serde_json::from_slice(stdout).unwrap_or_else(|err| {
        panic!(
            "{command_name} stdout should be JSON: {err}\n{}",
            String::from_utf8_lossy(stdout)
        )
    });

    serde_json::to_string_pretty(&value).expect("pretty json")
}

pub fn with_scrubbed_snapshot_settings<R>(
    snapshot_dir: &str,
    assertion: impl FnOnce() -> R,
) -> R {
    let mut settings = Settings::clone_current();
    settings.set_snapshot_path(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/goldens")
            .join(snapshot_dir),
    );
    settings.set_prepend_module_to_snapshot(false);
    settings.set_omit_expression(true);
    settings.add_filter(
        r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
        "[UUID]",
    );
    settings.add_filter(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})?",
        "[TIMESTAMP]",
    );
    settings.add_filter(r"/[A-Za-z0-9_./-]+", "[PATH]");
    settings.bind(assertion)
}
