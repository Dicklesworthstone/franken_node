use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=GIT_DIR");
    println!("cargo:rerun-if-env-changed=GIT_WORK_TREE");

    let git_sha = Command::new("git")
        .args(["rev-parse", "--short=12", "HEAD"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|sha| sha.trim().to_string())
        .filter(|sha| !sha.is_empty())
        .unwrap_or_else(|| "unknown".to_string());

    println!("cargo:rustc-env=FRANKEN_NODE_GIT_SHA={git_sha}");
}
