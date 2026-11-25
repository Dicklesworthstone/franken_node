use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

const SOURCE_GIT_SHA: &str = "FRANKEN_NODE_SOURCE_GIT_SHA";

fn validate_git_sha(label: &str, value: &str) -> Result<(), String> {
    if value.len() != 40
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!("{label} must be a lowercase 40-hex Git commit SHA"));
    }
    Ok(())
}

fn git_output(repository: &Path, args: &[&str]) -> Result<String, String> {
    let output = Command::new("git")
        .args(args)
        .current_dir(repository)
        // A caller's Git plumbing environment must not relabel this source
        // tree with the HEAD of another checkout.
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_COMMON_DIR")
        .env_remove("GIT_INDEX_FILE")
        .env_remove("GIT_OBJECT_DIRECTORY")
        .env_remove("GIT_ALTERNATE_OBJECT_DIRECTORIES")
        .output()
        .map_err(|error| format!("cannot inspect FrankenNode source repository: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "cannot inspect FrankenNode source repository: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    String::from_utf8(output.stdout)
        .map(|value| value.trim().to_owned())
        .map_err(|error| format!("FrankenNode Git metadata is not UTF-8: {error}"))
}

fn git_metadata_path(repository: &Path, name: &str) -> Result<PathBuf, String> {
    let path = PathBuf::from(git_output(repository, &["rev-parse", "--git-path", name])?);
    Ok(repository.join(path))
}

fn repository_revision(repository: &Path) -> Result<Option<String>, String> {
    // Cargo source archives and RCH inputs can be unpacked below an unrelated
    // checkout. Never discover its HEAD by walking above our workspace root.
    match std::fs::symlink_metadata(repository.join(".git")) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("cannot inspect FrankenNode .git entry: {error}")),
        Ok(_) => {}
    }
    let top = git_output(repository, &["rev-parse", "--show-toplevel"])?;
    let expected = repository
        .canonicalize()
        .map_err(|error| format!("cannot resolve FrankenNode source root: {error}"))?;
    let actual = Path::new(&top)
        .canonicalize()
        .map_err(|error| format!("cannot resolve FrankenNode Git root: {error}"))?;
    if actual != expected {
        return Err("Git metadata belongs to a different source repository".to_owned());
    }

    let revision = git_output(repository, &["rev-parse", "--verify", "HEAD^{commit}"])?;
    validate_git_sha("FrankenNode repository HEAD", &revision)?;

    // HEAD alone does not change when its symbolic branch advances. Watch the
    // actual ref too, including packed refs and Git's worktree metadata paths.
    let head = git_metadata_path(repository, "HEAD")?;
    println!("cargo:rerun-if-changed={}", head.display());
    let reference = git_output(repository, &["rev-parse", "--symbolic-full-name", "HEAD"])?;
    if reference != "HEAD" {
        let path = git_metadata_path(repository, &reference)?;
        // A packed branch can acquire a new loose ref without modifying HEAD
        // or packed-refs. Watch its existing parent until that ref appears.
        let watched = path
            .ancestors()
            .find(|ancestor| ancestor.exists())
            .ok_or("FrankenNode Git reference has no existing metadata directory")?;
        println!("cargo:rerun-if-changed={}", watched.display());
    }
    let packed_refs = git_metadata_path(repository, "packed-refs")?;
    if packed_refs.exists() {
        println!("cargo:rerun-if-changed={}", packed_refs.display());
    }
    Ok(Some(revision))
}

fn main() -> Result<(), String> {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed={SOURCE_GIT_SHA}");

    let declared = match env::var(SOURCE_GIT_SHA) {
        Ok(value) => {
            validate_git_sha(SOURCE_GIT_SHA, &value)?;
            Some(value)
        }
        Err(env::VarError::NotPresent) => None,
        Err(env::VarError::NotUnicode(_)) => {
            return Err(format!("{SOURCE_GIT_SHA} is not UTF-8"));
        }
    };
    let manifest_dir = env::var_os("CARGO_MANIFEST_DIR")
        .map(PathBuf::from)
        .ok_or("CARGO_MANIFEST_DIR is required to identify FrankenNode source")?;
    let repository = manifest_dir
        .parent()
        .and_then(Path::parent)
        .ok_or("FrankenNode crate has no workspace root")?;
    let observed = repository_revision(repository)?;
    if let (Some(declared), Some(observed)) = (&declared, &observed)
        && declared != observed
    {
        return Err(format!(
            "{SOURCE_GIT_SHA} {declared} does not match FrankenNode repository HEAD {observed}"
        ));
    }
    let git_sha = declared.or(observed).unwrap_or_else(|| "unknown".to_owned());

    println!("cargo:rustc-env=FRANKEN_NODE_GIT_SHA={git_sha}");
    Ok(())
}
