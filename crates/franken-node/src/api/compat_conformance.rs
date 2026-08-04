//! Lockstep-oracle conformance harness for the first-tranche compat operations
//! (bd-f5b04.2.1.2).
//!
//! This is the *parity half* of the keystone acceptance bar. The canonical
//! compat-API contract layer (`api::compat_gate`, bd-f5b04.2.1) defines, for
//! each first-tranche operation, the stable arg/result/error schemas, the Node
//! error-code parity table, resource budgets, side-effect category, and policy
//! hooks. This module turns those contracts into an executable differential
//! oracle: for every operation it runs each fixture case across multiple
//! independent *legs*, canonicalizes their outcomes to bytes, and routes those
//! outcomes through the L1 product-oracle
//! (`connector::n_version_oracle::run_harness`) which records the GREEN/RED
//! per-operation lockstep verdict and emits divergence fixtures on mismatch.
//!
//! Legs
//! ----
//! * **franken** — the system under test. Executes the operation *for real*
//!   (real filesystem I/O against a sandbox directory for `fs.*`, real URL
//!   canonicalization for `http.request`, real specifier resolution for
//!   `module.resolve`, real map lookups against a controlled environment
//!   snapshot for `process.env`). This is the `franken_engine_output` the
//!   oracle compares everything against.
//! * **spec** — the deterministic reference: the canonical outcome the contract
//!   says the operation MUST produce, derived independently of the franken leg
//!   (it is data carried by the fixture, never computed by running franken).
//!   The spec leg is always present, so the harness yields a deterministic
//!   GREEN/RED signal even in a CI environment with no Node/Bun binaries.
//! * **external (`node` / `bun`)** — the "real Node/Bun when present" legs.
//!   [`ExternalProcessLeg`] shells out to a runtime binary and parses its
//!   canonical output. When the binary is absent it reports
//!   [`LegError::Unavailable`] and the driver simply omits that reference leg
//!   from the sample — never failing closed on a missing optional runtime.
//!
//! Why a controlled environment snapshot rather than live `process.env`: this
//! crate is `#![forbid(unsafe_code)]` and Rust 2024 made `std::env::set_var`
//! `unsafe`, so seeding the live process environment is impossible here. The
//! franken leg instead performs a *real* lookup against a per-fixture
//! [`std::collections::BTreeMap`] snapshot — the same lookup `process.env`
//! performs, against a deterministic, test-controlled environment.
//!
//! This module never mutates `compat_gate.rs`; it only consumes its stable
//! public contract surface.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::api::compat_gate::{
    CompatOperationContract, CompatOperationId, first_tranche_operation_contracts,
};
use crate::connector::n_version_oracle::{
    BoundarySample, HarnessConfig, OracleResult, ReferenceRuntime, ReleaseVerdict, run_harness,
};
use crate::push_bounded;

/// Schema version for the conformance verdict envelope; bump on shape changes.
pub const COMPAT_CONFORMANCE_SCHEMA: &str = "compat-lockstep-conformance-v1.0";

/// Runtime id used for the always-present, contract-derived reference leg.
pub const SPEC_RUNTIME_ID: &str = "spec";

/// Domain separator for content hashing inside canonical outcomes.
const CONTENT_HASH_DOMAIN: &[u8] = b"api_compat_conformance_content_v1:";

/// Default harness timeout fed to the L1 oracle (ms).
pub const DEFAULT_HARNESS_TIMEOUT_MS: u64 = 30_000;

/// Bound on cases processed per operation (defensive cap on the corpus).
const MAX_CASES_PER_OPERATION: usize = 4096;
/// Bound on reference legs aggregated per case.
const MAX_REFERENCE_LEGS: usize = 16;
/// Bound on emitted divergence-fixture paths retained in a verdict.
const MAX_EMITTED_FIXTURES: usize = 4096;
/// Bound on bytes read back from the sandbox by the franken `fs.readFile` leg.
const FS_READ_HARD_CAP_BYTES: u64 = 64 * 1024 * 1024;

/// Structured event codes emitted via `tracing` for operator dashboards.
pub mod event_codes {
    /// Harness started for an operation.
    pub const FN_COMPAT_HARNESS_START: &str = "FN-COMPAT-001";
    /// Operation verdict resolved GREEN (zero divergences across all legs).
    pub const FN_COMPAT_OP_GREEN: &str = "FN-COMPAT-002";
    /// Operation verdict resolved RED (one or more legs diverged).
    pub const FN_COMPAT_OP_RED: &str = "FN-COMPAT-003";
    /// A divergence fixture artifact was written to disk.
    pub const FN_COMPAT_DIVERGENCE_FIXTURE_EMITTED: &str = "FN-COMPAT-004";
    /// An optional reference leg was unavailable (binary missing) and skipped.
    pub const FN_COMPAT_LEG_UNAVAILABLE: &str = "FN-COMPAT-005";
    /// A reference leg raised a hard error (recorded, leg skipped).
    pub const FN_COMPAT_LEG_ERROR: &str = "FN-COMPAT-006";
}

// ── Canonical outcome model ─────────────────────────────────────────────────

/// The canonical, byte-stable outcome of executing one compat operation on one
/// leg. All legs serialize to identical bytes when they agree, which is exactly
/// what the L1 oracle digests and compares.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum CanonicalOutcome {
    /// The operation succeeded with an operation-specific canonical result.
    Success { result: CanonicalResult },
    /// The operation failed with a canonical Node/Bun-parity error code.
    Error { code: String },
}

impl CanonicalOutcome {
    /// Convenience constructor for a canonical error outcome.
    pub fn error(code: impl Into<String>) -> Self {
        Self::Error { code: code.into() }
    }

    /// Deterministic canonical encoding fed to the oracle. Serialization of
    /// these closed types never fails; the sentinel keeps the path fail-closed
    /// (a sentinel byte string would itself diverge and surface RED).
    pub fn canonical_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self)
            .unwrap_or_else(|_| b"{\"canonical_serialization_error\":true}".to_vec())
    }
}

/// Operation-specific canonical success payloads. Content is reduced to lengths
/// and domain-separated hashes so the encoding is bounded regardless of the
/// real byte volume the operation moved.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum CanonicalResult {
    /// `fs.readFile` produced `byte_len` bytes hashing to `content_sha256`.
    FsRead {
        byte_len: u64,
        content_sha256: String,
    },
    /// `fs.writeFile` committed `bytes_written` bytes.
    FsWrite { bytes_written: u64 },
    /// `process.env[key]` lookup: present/absent and (if present) value hash.
    ProcessEnv {
        present: bool,
        value_sha256: Option<String>,
    },
    /// `module.resolve` resolved a specifier to a sandbox-relative path/format.
    ModuleResolve {
        resolved_path: String,
        format: String,
    },
    /// `http.request` canonicalized the request descriptor (no live egress).
    HttpRequestCanonicalized {
        scheme: String,
        host: String,
        port: u16,
        path: String,
        method: String,
    },
}

/// Domain-separated, length-prefixed content hash (`sha256:<hex>`).
fn content_sha256(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(CONTENT_HASH_DOMAIN);
    hasher.update(u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_le_bytes());
    hasher.update(bytes);
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

// ── Fixture model ────────────────────────────────────────────────────────────

/// A sandbox precondition: files and directories to materialize before the
/// franken leg executes a filesystem-touching operation.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SandboxSpec {
    /// Directories (sandbox-relative) to create first.
    pub dirs: Vec<String>,
    /// Files (sandbox-relative path, contents) to write.
    pub files: Vec<(String, Vec<u8>)>,
}

impl SandboxSpec {
    /// Empty sandbox (no preconditions).
    pub fn empty() -> Self {
        Self::default()
    }

    /// Builder: declare a directory.
    pub fn with_dir(mut self, dir: impl Into<String>) -> Self {
        self.dirs.push(dir.into());
        self
    }

    /// Builder: declare a file with contents.
    pub fn with_file(mut self, path: impl Into<String>, contents: impl Into<Vec<u8>>) -> Self {
        self.files.push((path.into(), contents.into()));
        self
    }
}

/// Operation-specific input for a fixture case.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompatInput {
    /// `fs.readFile(path)` over a materialized sandbox.
    FsRead { sandbox: SandboxSpec, path: String },
    /// `fs.writeFile(path, data)` over a materialized sandbox.
    FsWrite {
        sandbox: SandboxSpec,
        path: String,
        data: Vec<u8>,
    },
    /// `process.env[key]` over a controlled environment snapshot.
    ProcessEnv {
        env: BTreeMap<String, String>,
        key: String,
    },
    /// `module.resolve(specifier, from)` over a materialized sandbox.
    ModuleResolve {
        sandbox: SandboxSpec,
        specifier: String,
        from: String,
    },
    /// `http.request(url, method)` URL/request canonicalization (no egress).
    HttpRequest { url: String, method: String },
}

impl CompatInput {
    /// The operation this input drives.
    pub fn operation_id(&self) -> CompatOperationId {
        match self {
            Self::FsRead { .. } => CompatOperationId::FsReadFile,
            Self::FsWrite { .. } => CompatOperationId::FsWriteFile,
            Self::ProcessEnv { .. } => CompatOperationId::ProcessEnv,
            Self::ModuleResolve { .. } => CompatOperationId::ModuleResolve,
            Self::HttpRequest { .. } => CompatOperationId::HttpRequest,
        }
    }
}

/// One conformance fixture case: an input plus the contract-derived canonical
/// outcome the operation MUST produce (the spec-leg expectation).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompatFixtureCase {
    /// Short, stable, kebab-or-snake case identifier (used in boundary names).
    pub case_name: String,
    /// Human-readable description of what semantic the case pins down.
    pub description: String,
    /// The operation input.
    pub input: CompatInput,
    /// The independently-derived canonical outcome (spec reference).
    pub expected: CanonicalOutcome,
}

impl CompatFixtureCase {
    /// The operation this case targets.
    pub fn operation_id(&self) -> CompatOperationId {
        self.input.operation_id()
    }
}

// ── Leg abstraction ──────────────────────────────────────────────────────────

/// Failure modes for a leg's attempt to produce a canonical outcome. These are
/// harness-infrastructure failures, distinct from a *canonical error outcome*
/// (which is a legitimate, comparable result).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LegError {
    /// The leg's runtime/binary is not present; the leg is optional and skipped.
    Unavailable { runtime_id: String, detail: String },
    /// The leg executed but its output could not be canonicalized.
    Execution { runtime_id: String, detail: String },
}

impl std::fmt::Display for LegError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unavailable { runtime_id, detail } => {
                write!(f, "leg '{runtime_id}' unavailable: {detail}")
            }
            Self::Execution { runtime_id, detail } => {
                write!(f, "leg '{runtime_id}' execution error: {detail}")
            }
        }
    }
}

impl std::error::Error for LegError {}

/// A single leg of the differential oracle. Produces a canonical outcome for a
/// fixture case, or a [`LegError`] if it cannot.
pub trait ConformanceLeg {
    /// Stable identifier for this leg (e.g. `"franken"`, `"spec"`, `"node"`).
    fn runtime_id(&self) -> &str;
    /// Semantic version string of the leg's runtime (informational).
    fn version(&self) -> String {
        "n/a".to_string()
    }
    /// Execute the case and return its canonical outcome.
    fn execute(&self, case: &CompatFixtureCase) -> Result<CanonicalOutcome, LegError>;
}

// ── Spec leg (deterministic reference) ───────────────────────────────────────

/// The contract-derived reference leg. Returns the fixture's `expected`
/// outcome verbatim — never runs franken — so it is an *independent* oracle.
#[derive(Debug, Clone, Default)]
pub struct SpecLeg;

impl ConformanceLeg for SpecLeg {
    fn runtime_id(&self) -> &str {
        SPEC_RUNTIME_ID
    }

    fn version(&self) -> String {
        COMPAT_CONFORMANCE_SCHEMA.to_string()
    }

    fn execute(&self, case: &CompatFixtureCase) -> Result<CanonicalOutcome, LegError> {
        Ok(case.expected.clone())
    }
}

// ── Franken leg (system under test, real I/O) ────────────────────────────────

/// The system-under-test leg. Executes each operation for real against a
/// sandbox directory the caller controls.
#[derive(Debug, Clone)]
pub struct FrankenLeg {
    sandbox_root: PathBuf,
}

impl FrankenLeg {
    /// Construct a franken leg rooted at `sandbox_root`. Each case gets its own
    /// isolated subdirectory under this root.
    pub fn new(sandbox_root: impl Into<PathBuf>) -> Self {
        Self {
            sandbox_root: sandbox_root.into(),
        }
    }

    /// Per-case sandbox directory (isolated by case name).
    fn case_dir(&self, case_name: &str) -> PathBuf {
        self.sandbox_root.join(sanitize_segment(case_name))
    }

    /// Materialize the sandbox preconditions, returning the case dir on success.
    fn materialize(&self, case_name: &str, spec: &SandboxSpec) -> Result<PathBuf, LegError> {
        let root = self.case_dir(case_name);
        let exec = |detail: String| LegError::Execution {
            runtime_id: "franken".to_string(),
            detail,
        };
        std::fs::create_dir_all(&root).map_err(|e| exec(format!("create case dir: {e}")))?;
        for dir in &spec.dirs {
            validate_relative_path(dir).map_err(|c| exec(format!("invalid dir '{dir}': {c}")))?;
            std::fs::create_dir_all(root.join(dir))
                .map_err(|e| exec(format!("create dir '{dir}': {e}")))?;
        }
        for (path, contents) in &spec.files {
            validate_relative_path(path)
                .map_err(|c| exec(format!("invalid file '{path}': {c}")))?;
            let full = root.join(path);
            if let Some(parent) = full.parent() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| exec(format!("create parent for '{path}': {e}")))?;
            }
            std::fs::write(&full, contents)
                .map_err(|e| exec(format!("write file '{path}': {e}")))?;
        }
        Ok(root)
    }
}

impl ConformanceLeg for FrankenLeg {
    fn runtime_id(&self) -> &str {
        "franken"
    }

    fn version(&self) -> String {
        env!("CARGO_PKG_VERSION").to_string()
    }

    fn execute(&self, case: &CompatFixtureCase) -> Result<CanonicalOutcome, LegError> {
        match &case.input {
            CompatInput::FsRead { sandbox, path } => {
                let root = self.materialize(&case.case_name, sandbox)?;
                Ok(franken_fs_read(&root, path))
            }
            CompatInput::FsWrite {
                sandbox,
                path,
                data,
            } => {
                let root = self.materialize(&case.case_name, sandbox)?;
                Ok(franken_fs_write(&root, path, data))
            }
            CompatInput::ProcessEnv { env, key } => Ok(franken_process_env(env, key)),
            CompatInput::ModuleResolve {
                sandbox,
                specifier,
                from,
            } => {
                let root = self.materialize(&case.case_name, sandbox)?;
                Ok(franken_module_resolve(&root, specifier, from))
            }
            CompatInput::HttpRequest { url, method } => Ok(franken_http_request(url, method)),
        }
    }
}

// ── Franken canonical executors (real, deterministic) ────────────────────────

/// Real `fs.readFile`: explicit pre-checks for Node error-code parity, then a
/// bounded read.
fn franken_fs_read(root: &Path, path: &str) -> CanonicalOutcome {
    if let Err(code) = validate_relative_path(path) {
        return CanonicalOutcome::error(code);
    }
    let full = root.join(path);
    if full.is_dir() {
        return CanonicalOutcome::error("EISDIR");
    }
    if !full.exists() {
        return CanonicalOutcome::error("ENOENT");
    }
    match crate::bounded_read(&full, FS_READ_HARD_CAP_BYTES) {
        Ok(bytes) => CanonicalOutcome::Success {
            result: CanonicalResult::FsRead {
                byte_len: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
                content_sha256: content_sha256(&bytes),
            },
        },
        Err(e) => CanonicalOutcome::error(io_error_to_code(&e)),
    }
}

/// Real `fs.writeFile`: parent/target pre-checks for parity, then a write.
fn franken_fs_write(root: &Path, path: &str, data: &[u8]) -> CanonicalOutcome {
    if let Err(code) = validate_relative_path(path) {
        return CanonicalOutcome::error(code);
    }
    let full = root.join(path);
    if full.is_dir() {
        return CanonicalOutcome::error("EISDIR");
    }
    match full.parent() {
        Some(parent) => {
            if !parent.as_os_str().is_empty() && !parent.exists() {
                return CanonicalOutcome::error("ENOENT");
            }
            if parent.exists() && !parent.is_dir() {
                return CanonicalOutcome::error("ENOTDIR");
            }
        }
        None => return CanonicalOutcome::error("ENOENT"),
    }
    match std::fs::write(&full, data) {
        Ok(()) => CanonicalOutcome::Success {
            result: CanonicalResult::FsWrite {
                bytes_written: u64::try_from(data.len()).unwrap_or(u64::MAX),
            },
        },
        Err(e) => CanonicalOutcome::error(io_error_to_code(&e)),
    }
}

/// Real `process.env[key]` lookup against a controlled snapshot.
fn franken_process_env(env: &BTreeMap<String, String>, key: &str) -> CanonicalOutcome {
    if key.is_empty() || key.contains('\0') || key.contains('=') {
        return CanonicalOutcome::error("ERR_INVALID_ARG_TYPE");
    }
    match env.get(key) {
        Some(value) => CanonicalOutcome::Success {
            result: CanonicalResult::ProcessEnv {
                present: true,
                value_sha256: Some(content_sha256(value.as_bytes())),
            },
        },
        None => CanonicalOutcome::Success {
            result: CanonicalResult::ProcessEnv {
                present: false,
                value_sha256: None,
            },
        },
    }
}

/// Minimal, sandbox-scoped `module.resolve`. Covers the error-parity codes and
/// relative-specifier resolution (exact, `.js`/`.json`/`.mjs`, `/index.js`).
/// Full Node/Bun resolution lives in the dedicated resolver (bd-f5b04.7.1);
/// this executor is intentionally scoped to the conformance fixture corpus.
fn franken_module_resolve(root: &Path, specifier: &str, from: &str) -> CanonicalOutcome {
    if specifier.is_empty() || specifier.contains('\0') {
        return CanonicalOutcome::error("ERR_INVALID_MODULE_SPECIFIER");
    }
    let is_relative = specifier.starts_with("./") || specifier.starts_with("../");
    if !is_relative {
        // Bare specifier: minimal node_modules/<spec>/package.json "main" lookup.
        return resolve_bare(root, specifier);
    }
    if validate_relative_path(from).is_err() {
        return CanonicalOutcome::error("ERR_INVALID_MODULE_SPECIFIER");
    }
    let base_dir = match Path::new(from).parent() {
        Some(p) => p.to_path_buf(),
        None => PathBuf::new(),
    };
    let joined = join_relative(&base_dir, specifier);
    let Some(rel) = joined else {
        return CanonicalOutcome::error("ERR_INVALID_MODULE_SPECIFIER");
    };
    resolve_candidates(root, &rel)
}

/// Resolve a relative path against the sandbox, trying extension/index forms.
fn resolve_candidates(root: &Path, rel: &str) -> CanonicalOutcome {
    let candidates = [
        rel.to_string(),
        format!("{rel}.js"),
        format!("{rel}.json"),
        format!("{rel}.mjs"),
        format!("{rel}/index.js"),
    ];
    for cand in candidates {
        if validate_relative_path(&cand).is_err() {
            continue;
        }
        let full = root.join(&cand);
        if full.is_file() {
            return CanonicalOutcome::Success {
                result: CanonicalResult::ModuleResolve {
                    resolved_path: cand.clone(),
                    format: module_format(&cand),
                },
            };
        }
    }
    CanonicalOutcome::error("MODULE_NOT_FOUND")
}

/// Minimal bare-specifier resolution via `node_modules`.
fn resolve_bare(root: &Path, specifier: &str) -> CanonicalOutcome {
    if specifier.contains("..") || specifier.starts_with('/') {
        return CanonicalOutcome::error("ERR_INVALID_MODULE_SPECIFIER");
    }
    let pkg_dir = format!("node_modules/{specifier}");
    let pkg_json_rel = format!("{pkg_dir}/package.json");
    let pkg_json = root.join(&pkg_json_rel);
    if !pkg_json.is_file() {
        return CanonicalOutcome::error("MODULE_NOT_FOUND");
    }
    let raw = match crate::bounded_read(&pkg_json, 1024 * 1024) {
        Ok(bytes) => bytes,
        Err(_) => return CanonicalOutcome::error("MODULE_NOT_FOUND"),
    };
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(&raw) else {
        return CanonicalOutcome::error("ERR_INVALID_MODULE_SPECIFIER");
    };
    // "exports" present but not exposing "." => not exported.
    if let Some(exports) = value.get("exports")
        && exports.is_object()
        && exports.get(".").is_none()
        && exports.get("./").is_none()
    {
        return CanonicalOutcome::error("ERR_PACKAGE_PATH_NOT_EXPORTED");
    }
    let main = value
        .get("main")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("index.js");
    let main_rel = format!("{pkg_dir}/{main}");
    resolve_candidates(root, &main_rel)
}

/// Classify a resolved module path's canonical format.
fn module_format(path: &str) -> String {
    if path.ends_with(".mjs") {
        "module".to_string()
    } else if path.ends_with(".json") {
        "json".to_string()
    } else {
        "commonjs".to_string()
    }
}

/// Real `http.request` URL/request canonicalization (no live egress). Pins
/// scheme, host, default-port behavior, path normalization, and method casing.
fn franken_http_request(url: &str, method: &str) -> CanonicalOutcome {
    let Some((scheme, rest)) = url.split_once("://") else {
        return CanonicalOutcome::error("ERR_INVALID_URL");
    };
    let scheme = scheme.to_ascii_lowercase();
    if scheme != "http" && scheme != "https" {
        return CanonicalOutcome::error("ERR_INVALID_URL");
    }
    if rest.is_empty() || url.contains('\0') {
        return CanonicalOutcome::error("ERR_INVALID_URL");
    }
    // Split authority from path.
    let (authority, path_part) = match rest.find('/') {
        Some(idx) => (&rest[..idx], &rest[idx..]),
        None => (rest, "/"),
    };
    // Strip userinfo and fragment from authority handling for canonical host.
    let authority = authority.split('@').next_back().unwrap_or(authority);
    if authority.is_empty() {
        return CanonicalOutcome::error("ERR_INVALID_URL");
    }
    let (host_raw, explicit_port) = match authority.rsplit_once(':') {
        Some((h, p)) => (h, Some(p)),
        None => (authority, None),
    };
    let host = host_raw.to_ascii_lowercase();
    if host.is_empty() {
        return CanonicalOutcome::error("ERR_INVALID_URL");
    }
    let default_port: u16 = if scheme == "https" { 443 } else { 80 };
    let port = match explicit_port {
        Some(p) => match p.parse::<u16>() {
            Ok(v) => v,
            Err(_) => return CanonicalOutcome::error("ERR_INVALID_URL"),
        },
        None => default_port,
    };
    // Canonical path: strip query/fragment, default to "/".
    let path_only = path_part
        .split(['?', '#'])
        .next()
        .filter(|s| !s.is_empty())
        .unwrap_or("/");
    let method_canonical = canonical_http_method(method);
    let Some(method_canonical) = method_canonical else {
        return CanonicalOutcome::error("ERR_INVALID_ARG_TYPE");
    };
    CanonicalOutcome::Success {
        result: CanonicalResult::HttpRequestCanonicalized {
            scheme,
            host,
            port,
            path: path_only.to_string(),
            method: method_canonical,
        },
    }
}

/// Canonicalize an HTTP method (uppercase), rejecting empty/invalid tokens.
fn canonical_http_method(method: &str) -> Option<String> {
    if method.is_empty() || method.contains('\0') {
        return None;
    }
    let upper = method.to_ascii_uppercase();
    if upper
        .bytes()
        .all(|b| b.is_ascii_uppercase() || b == b'-' || b == b'_')
    {
        Some(upper)
    } else {
        None
    }
}

// ── External process leg (real Node/Bun when present) ────────────────────────

/// The "real Node/Bun when present" leg. Shells out to a runtime binary,
/// passing a generated script that prints the canonical outcome JSON to stdout.
/// When the binary is absent, [`Self::execute`] reports [`LegError::Unavailable`]
/// so the driver simply omits this optional reference — never failing closed.
///
/// This leg is opt-in: deterministic tests use [`FrankenLeg`] + [`SpecLeg`]; the
/// e2e parity bead (bd-f5b04.2.1.3) wires real `node`/`bun` here.
#[derive(Debug, Clone)]
pub struct ExternalProcessLeg {
    runtime_id: String,
    program: String,
    sandbox_root: PathBuf,
}

impl ExternalProcessLeg {
    /// Construct an external leg with id `runtime_id` invoking `program`
    /// (e.g. `("node", "node")` or `("bun", "bun")`), rooted at `sandbox_root`.
    pub fn new(
        runtime_id: impl Into<String>,
        program: impl Into<String>,
        sandbox_root: impl Into<PathBuf>,
    ) -> Self {
        Self {
            runtime_id: runtime_id.into(),
            program: program.into(),
            sandbox_root: sandbox_root.into(),
        }
    }

    fn case_dir(&self, case_name: &str) -> PathBuf {
        self.sandbox_root.join(sanitize_segment(case_name))
    }
}

impl ConformanceLeg for ExternalProcessLeg {
    fn runtime_id(&self) -> &str {
        &self.runtime_id
    }

    fn execute(&self, case: &CompatFixtureCase) -> Result<CanonicalOutcome, LegError> {
        // Fail closed: only ever spawn a recognized JavaScript runtime, and
        // never a value carrying shell metacharacters. A non-allowlisted
        // program is treated as an unavailable optional leg (skipped), so an
        // operator typo or hostile config can never turn this into arbitrary
        // command execution. User/fixture data only ever reaches the child as
        // an explicit `-e <script>` argv element, never via a shell.
        if !is_allowed_runtime_program(&self.program) {
            return Err(LegError::Unavailable {
                runtime_id: self.runtime_id.clone(),
                detail: format!(
                    "program '{}' is not an allowlisted JS runtime",
                    self.program
                ),
            });
        }
        let script = external_script_for(&self.case_dir(&case.case_name), &case.input);
        let Some(script) = script else {
            return Err(LegError::Execution {
                runtime_id: self.runtime_id.clone(),
                detail: "no external script generator for this operation".to_string(),
            });
        };
        let output = std::process::Command::new(&self.program)
            .arg("-e")
            .arg(&script)
            .output();
        match output {
            Ok(out) if out.status.success() => {
                serde_json::from_slice::<CanonicalOutcome>(&out.stdout).map_err(|e| {
                    LegError::Execution {
                        runtime_id: self.runtime_id.clone(),
                        detail: format!("unparseable canonical stdout: {e}"),
                    }
                })
            }
            Ok(out) => Err(LegError::Execution {
                runtime_id: self.runtime_id.clone(),
                detail: format!(
                    "non-zero exit {}: {}",
                    out.status,
                    String::from_utf8_lossy(&out.stderr).trim()
                ),
            }),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(LegError::Unavailable {
                runtime_id: self.runtime_id.clone(),
                detail: format!("binary '{}' not found", self.program),
            }),
            Err(e) => Err(LegError::Execution {
                runtime_id: self.runtime_id.clone(),
                detail: format!("spawn failed: {e}"),
            }),
        }
    }
}

/// Generate a Node/Bun-compatible script that prints the canonical outcome for
/// `input`, materializing any sandbox preconditions inside `case_dir`. Returns
/// `None` for operations without an external generator (currently
/// module-resolve, deferred to bd-f5b04.7.1's resolver). The script is plain
/// data; it never interpolates untrusted shell text (passed via `-e`).
fn external_script_for(case_dir: &Path, input: &CompatInput) -> Option<String> {
    let dir = case_dir
        .to_string_lossy()
        .replace('\\', "/")
        .replace('"', "");
    match input {
        CompatInput::ProcessEnv { env, key } => {
            // env is supplied to the child via a literal object (deterministic).
            let entries = env
                .iter()
                .map(|(k, v)| format!("{}:{}", json_string(k), json_string(v)))
                .collect::<Vec<_>>()
                .join(",");
            Some(format!(
                "const crypto=require('crypto');const env={{{entries}}};\
const key={key};\
function h(b){{const x=crypto.createHash('sha256');\
x.update(Buffer.from('api_compat_conformance_content_v1:'));\
const L=Buffer.alloc(8);L.writeBigUInt64LE(BigInt(b.length));x.update(L);x.update(b);\
return 'sha256:'+x.digest('hex');}}\
if(typeof key!=='string'||key.length===0||key.includes('=')){{process.stdout.write(JSON.stringify({{outcome:'error',code:'ERR_INVALID_ARG_TYPE'}}));}}\
else if(Object.prototype.hasOwnProperty.call(env,key)){{process.stdout.write(JSON.stringify({{outcome:'success',result:{{op:'process_env',present:true,value_sha256:h(Buffer.from(env[key]))}}}}));}}\
else{{process.stdout.write(JSON.stringify({{outcome:'success',result:{{op:'process_env',present:false,value_sha256:null}}}}));}}",
                key = json_string(key),
            ))
        }
        CompatInput::HttpRequest { url, method } => Some(format!(
            "const u={url};const m={method};\
try{{const p=new URL(u);if(p.protocol!=='http:'&&p.protocol!=='https:')throw 0;\
const port=p.port?parseInt(p.port,10):(p.protocol==='https:'?443:80);\
const path=(p.pathname||'/');\
const M=String(m).toUpperCase();\
if(M.length===0||!/^[A-Z_-]+$/.test(M)){{process.stdout.write(JSON.stringify({{outcome:'error',code:'ERR_INVALID_ARG_TYPE'}}));}}\
else{{process.stdout.write(JSON.stringify({{outcome:'success',result:{{op:'http_request_canonicalized',scheme:p.protocol.slice(0,-1),host:p.hostname.toLowerCase(),port:port,path:path,method:M}}}}));}}\
}}catch(e){{process.stdout.write(JSON.stringify({{outcome:'error',code:'ERR_INVALID_URL'}}));}}",
            url = json_string(url),
            method = json_string(method),
        )),
        CompatInput::FsRead { path, .. } => Some(format!(
            "const fs=require('fs'),crypto=require('crypto'),P=require('path');\
const root={dir};const rel={path};const full=P.join(root,rel);\
try{{const st=fs.statSync(full);if(st.isDirectory()){{process.stdout.write(JSON.stringify({{outcome:'error',code:'EISDIR'}}));}}\
else{{const b=fs.readFileSync(full);const x=crypto.createHash('sha256');\
x.update(Buffer.from('api_compat_conformance_content_v1:'));\
const L=Buffer.alloc(8);L.writeBigUInt64LE(BigInt(b.length));x.update(L);x.update(b);\
process.stdout.write(JSON.stringify({{outcome:'success',result:{{op:'fs_read',byte_len:b.length,content_sha256:'sha256:'+x.digest('hex')}}}}));}}\
}}catch(e){{process.stdout.write(JSON.stringify({{outcome:'error',code:e.code||'ENOENT'}}));}}",
            dir = json_string(&dir),
            path = json_string(path),
        )),
        CompatInput::FsWrite { .. } | CompatInput::ModuleResolve { .. } => None,
    }
}

/// Minimal JSON string encoder for embedding literals in generated scripts.
fn json_string(s: &str) -> String {
    serde_json::to_string(s).unwrap_or_else(|_| "\"\"".to_string())
}

// ── Driver: per-operation conformance ────────────────────────────────────────

/// Configuration for a conformance run.
#[derive(Debug, Clone)]
pub struct ConformanceConfig {
    /// Timeout fed to the L1 oracle harness config (ms).
    pub timeout_ms: u64,
    /// If set, divergence fixtures are written under this directory on RED.
    pub fixture_output_dir: Option<PathBuf>,
}

impl Default for ConformanceConfig {
    fn default() -> Self {
        Self {
            timeout_ms: DEFAULT_HARNESS_TIMEOUT_MS,
            fixture_output_dir: None,
        }
    }
}

/// The GREEN/RED lockstep signal for one operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LockstepSignal {
    /// Every leg agreed on every case.
    Green,
    /// At least one leg diverged on at least one case.
    Red,
}

impl LockstepSignal {
    /// String label for logging/JSON.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Green => "green",
            Self::Red => "red",
        }
    }
}

/// Per-operation conformance verdict.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationConformanceVerdict {
    /// Schema version of this verdict envelope.
    pub schema_version: String,
    /// The operation's stable registry id (e.g. `compat:fs:readFile`).
    pub operation_id: String,
    /// GREEN/RED lockstep signal.
    pub signal: LockstepSignal,
    /// Number of fixture cases exercised.
    pub cases_tested: usize,
    /// Reference runtime ids that actually contributed at least one output.
    pub reference_runtimes: Vec<String>,
    /// Underlying L1 oracle result (divergences, stats, release verdict).
    pub oracle: OracleResult,
    /// Per-case boundary names that diverged (for quick triage).
    pub diverged_boundaries: Vec<String>,
    /// Paths of any divergence fixtures emitted to disk.
    pub emitted_fixtures: Vec<String>,
    /// Optional-leg unavailability notes (runtime_id, detail).
    pub skipped_legs: Vec<(String, String)>,
}

/// A serialized divergence fixture written on RED for offline triage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DivergenceFixture {
    /// Schema version.
    pub schema_version: String,
    /// Operation registry id.
    pub operation_id: String,
    /// Case name.
    pub case_name: String,
    /// Case description.
    pub description: String,
    /// The franken (SUT) canonical outcome.
    pub franken_outcome: CanonicalOutcome,
    /// Each reference leg's canonical outcome.
    pub reference_outcomes: BTreeMap<String, CanonicalOutcome>,
}

/// Run conformance for a single operation contract over `cases`, comparing the
/// `franken` leg against each reference leg via the L1 oracle.
pub fn run_operation_conformance(
    contract: &CompatOperationContract,
    cases: &[CompatFixtureCase],
    franken: &dyn ConformanceLeg,
    references: &[&dyn ConformanceLeg],
    config: &ConformanceConfig,
) -> OperationConformanceVerdict {
    let op_id = contract.operation_id.registry_id();
    tracing::info!(
        event = event_codes::FN_COMPAT_HARNESS_START,
        operation = op_id,
        cases = cases.len(),
        references = references.len(),
        "compat lockstep conformance start"
    );

    let mut samples: Vec<BoundarySample> = Vec::new();
    let mut contributing_refs: BTreeMap<String, ReferenceRuntime> = BTreeMap::new();
    let mut skipped_legs: Vec<(String, String)> = Vec::new();
    // case_name -> (franken_outcome, ref_id -> outcome) for fixture emission.
    let mut per_case_outcomes: Vec<(
        CompatFixtureCase,
        CanonicalOutcome,
        BTreeMap<String, CanonicalOutcome>,
    )> = Vec::new();

    for case in cases.iter().take(MAX_CASES_PER_OPERATION) {
        debug_assert_eq!(
            case.operation_id(),
            contract.operation_id,
            "fixture case routed to the wrong operation contract"
        );
        let franken_outcome = match franken.execute(case) {
            Ok(o) => o,
            Err(e) => {
                // A franken infrastructure failure is itself a hard RED signal;
                // encode it as a distinct canonical error so it diverges.
                tracing::warn!(
                    event = event_codes::FN_COMPAT_LEG_ERROR,
                    operation = op_id,
                    case = %case.case_name,
                    error = %e,
                    "franken leg execution error"
                );
                CanonicalOutcome::error(format!("ERR_FRANKEN_LEG:{e}"))
            }
        };
        let franken_bytes = franken_outcome.canonical_bytes();

        let mut reference_outputs: BTreeMap<String, Vec<u8>> = BTreeMap::new();
        let mut ref_outcomes: BTreeMap<String, CanonicalOutcome> = BTreeMap::new();
        for leg in references {
            let rid = leg.runtime_id().to_string();
            match leg.execute(case) {
                Ok(outcome) => {
                    reference_outputs.insert(rid.clone(), outcome.canonical_bytes());
                    ref_outcomes.insert(rid.clone(), outcome);
                    contributing_refs
                        .entry(rid.clone())
                        .or_insert_with(|| ReferenceRuntime {
                            runtime_id: rid.clone(),
                            version: leg.version(),
                        });
                }
                Err(LegError::Unavailable { runtime_id, detail }) => {
                    tracing::debug!(
                        event = event_codes::FN_COMPAT_LEG_UNAVAILABLE,
                        operation = op_id,
                        runtime = %runtime_id,
                        detail = %detail,
                        "optional reference leg unavailable; skipping"
                    );
                    if !skipped_legs.iter().any(|(r, _)| r == &runtime_id) {
                        push_bounded(&mut skipped_legs, (runtime_id, detail), MAX_REFERENCE_LEGS);
                    }
                }
                Err(e @ LegError::Execution { .. }) => {
                    tracing::warn!(
                        event = event_codes::FN_COMPAT_LEG_ERROR,
                        operation = op_id,
                        case = %case.case_name,
                        error = %e,
                        "reference leg execution error; recording as divergent"
                    );
                    // A reference that errors hard is recorded as a divergent
                    // canonical error so the mismatch surfaces RED rather than
                    // being silently dropped.
                    let outcome = CanonicalOutcome::error(format!("ERR_REFERENCE_LEG:{rid}"));
                    reference_outputs.insert(rid.clone(), outcome.canonical_bytes());
                    ref_outcomes.insert(rid.clone(), outcome);
                    contributing_refs
                        .entry(rid.clone())
                        .or_insert_with(|| ReferenceRuntime {
                            runtime_id: rid.clone(),
                            version: leg.version(),
                        });
                }
            }
        }

        let boundary_name = format!("{op_id}::{}", case.case_name);
        push_bounded(
            &mut samples,
            BoundarySample {
                boundary_name,
                input: franken_bytes.clone(),
                franken_engine_output: franken_bytes,
                reference_outputs,
            },
            MAX_CASES_PER_OPERATION,
        );
        per_case_outcomes.push((case.clone(), franken_outcome, ref_outcomes));
    }

    let mut harness = HarnessConfig::new(config.timeout_ms);
    harness.require_l1_links = false;
    for rt in contributing_refs.values() {
        harness = harness.with_reference(rt.clone());
    }

    let oracle = run_harness(&harness, &samples, &[]);

    let diverged: Vec<String> = oracle
        .divergences
        .iter()
        .map(|d| d.boundary_name.clone())
        .collect();
    let signal =
        if matches!(oracle.verdict, ReleaseVerdict::Passed) && oracle.divergences.is_empty() {
            LockstepSignal::Green
        } else {
            LockstepSignal::Red
        };

    let mut emitted_fixtures: Vec<String> = Vec::new();
    if signal == LockstepSignal::Red {
        let diverged_set: std::collections::BTreeSet<&str> =
            diverged.iter().map(String::as_str).collect();
        if let Some(dir) = &config.fixture_output_dir {
            for (case, franken_outcome, ref_outcomes) in &per_case_outcomes {
                let boundary = format!("{op_id}::{}", case.case_name);
                if !diverged_set.contains(boundary.as_str()) {
                    continue;
                }
                match emit_divergence_fixture(dir, op_id, case, franken_outcome, ref_outcomes) {
                    Ok(path) => {
                        tracing::warn!(
                            event = event_codes::FN_COMPAT_DIVERGENCE_FIXTURE_EMITTED,
                            operation = op_id,
                            case = %case.case_name,
                            path = %path,
                            "divergence fixture emitted"
                        );
                        push_bounded(&mut emitted_fixtures, path, MAX_EMITTED_FIXTURES);
                    }
                    Err(e) => {
                        tracing::warn!(
                            event = event_codes::FN_COMPAT_LEG_ERROR,
                            operation = op_id,
                            case = %case.case_name,
                            error = %e,
                            "failed to emit divergence fixture"
                        );
                    }
                }
            }
        }
        tracing::warn!(
            event = event_codes::FN_COMPAT_OP_RED,
            operation = op_id,
            divergences = oracle.stats.total_divergences,
            high_risk = oracle.stats.high_risk_count,
            "compat lockstep conformance RED"
        );
    } else {
        tracing::info!(
            event = event_codes::FN_COMPAT_OP_GREEN,
            operation = op_id,
            cases = samples.len(),
            "compat lockstep conformance GREEN"
        );
    }

    OperationConformanceVerdict {
        schema_version: COMPAT_CONFORMANCE_SCHEMA.to_string(),
        operation_id: op_id.to_string(),
        signal,
        cases_tested: samples.len(),
        reference_runtimes: contributing_refs.keys().cloned().collect(),
        oracle,
        diverged_boundaries: diverged,
        emitted_fixtures,
        skipped_legs,
    }
}

/// Write a single divergence fixture to `dir` and return its path string.
fn emit_divergence_fixture(
    dir: &Path,
    op_id: &str,
    case: &CompatFixtureCase,
    franken_outcome: &CanonicalOutcome,
    ref_outcomes: &BTreeMap<String, CanonicalOutcome>,
) -> std::io::Result<String> {
    std::fs::create_dir_all(dir)?;
    let fixture = DivergenceFixture {
        schema_version: COMPAT_CONFORMANCE_SCHEMA.to_string(),
        operation_id: op_id.to_string(),
        case_name: case.case_name.clone(),
        description: case.description.clone(),
        franken_outcome: franken_outcome.clone(),
        reference_outcomes: ref_outcomes.clone(),
    };
    let file_name = format!(
        "compat-divergence-{}-{}.json",
        sanitize_segment(&op_id.replace(':', "_")),
        sanitize_segment(&case.case_name)
    );
    let full = dir.join(&file_name);
    let bytes = serde_json::to_vec_pretty(&fixture).map_err(std::io::Error::other)?;
    // Atomic-ish write via a uniquely named temp then rename.
    let tmp = dir.join(format!(".{file_name}.{}.tmp", std::process::id()));
    std::fs::write(&tmp, &bytes)?;
    std::fs::rename(&tmp, &full)?;
    Ok(full.to_string_lossy().to_string())
}

/// Run conformance for every first-tranche operation over the built-in fixture
/// corpus using the franken leg plus the deterministic spec reference (and any
/// extra reference legs supplied). Returns one verdict per operation.
pub fn run_first_tranche_conformance(
    franken: &dyn ConformanceLeg,
    extra_references: &[&dyn ConformanceLeg],
    config: &ConformanceConfig,
) -> Vec<OperationConformanceVerdict> {
    let corpus = first_tranche_fixture_corpus();
    let spec = SpecLeg;
    let mut verdicts = Vec::new();
    for contract in first_tranche_operation_contracts() {
        let cases: Vec<CompatFixtureCase> = corpus
            .iter()
            .filter(|c| c.operation_id() == contract.operation_id)
            .cloned()
            .collect();
        let mut refs: Vec<&dyn ConformanceLeg> = vec![&spec];
        refs.extend_from_slice(extra_references);
        verdicts.push(run_operation_conformance(
            contract, &cases, franken, &refs, config,
        ));
    }
    verdicts
}

// ── Built-in first-tranche fixture corpus ────────────────────────────────────

/// The canonical first-tranche fixture corpus: happy paths, Node error-code
/// parity cases, and semantic edge cases for each operation. The `expected`
/// outcomes are derived independently from the contract (not by running
/// franken), making the spec leg a genuine oracle.
pub fn first_tranche_fixture_corpus() -> Vec<CompatFixtureCase> {
    let mut cases = Vec::new();
    cases.extend(fs_read_cases());
    cases.extend(fs_write_cases());
    cases.extend(process_env_cases());
    cases.extend(module_resolve_cases());
    cases.extend(http_request_cases());
    cases
}

fn ok_fs_read(bytes: &[u8]) -> CanonicalOutcome {
    CanonicalOutcome::Success {
        result: CanonicalResult::FsRead {
            byte_len: bytes.len() as u64,
            content_sha256: content_sha256(bytes),
        },
    }
}

fn fs_read_cases() -> Vec<CompatFixtureCase> {
    let hello = b"hello, franken_node".to_vec();
    vec![
        CompatFixtureCase {
            case_name: "read_existing_file".to_string(),
            description: "reading an existing regular file returns its bytes".to_string(),
            input: CompatInput::FsRead {
                sandbox: SandboxSpec::empty().with_file("a.txt", hello.clone()),
                path: "a.txt".to_string(),
            },
            expected: ok_fs_read(&hello),
        },
        CompatFixtureCase {
            case_name: "read_empty_file".to_string(),
            description: "reading an empty file returns zero bytes (boundary)".to_string(),
            input: CompatInput::FsRead {
                sandbox: SandboxSpec::empty().with_file("empty.txt", Vec::<u8>::new()),
                path: "empty.txt".to_string(),
            },
            expected: ok_fs_read(b""),
        },
        CompatFixtureCase {
            case_name: "read_missing_enoent".to_string(),
            description: "reading a missing path yields ENOENT (Node parity)".to_string(),
            input: CompatInput::FsRead {
                sandbox: SandboxSpec::empty(),
                path: "nope.txt".to_string(),
            },
            expected: CanonicalOutcome::error("ENOENT"),
        },
        CompatFixtureCase {
            case_name: "read_directory_eisdir".to_string(),
            description: "reading a directory yields EISDIR (Node parity)".to_string(),
            input: CompatInput::FsRead {
                sandbox: SandboxSpec::empty().with_dir("sub"),
                path: "sub".to_string(),
            },
            expected: CanonicalOutcome::error("EISDIR"),
        },
        CompatFixtureCase {
            case_name: "read_traversal_rejected".to_string(),
            description: "a parent-escaping path is rejected (ERR_INVALID_ARG_TYPE)".to_string(),
            input: CompatInput::FsRead {
                sandbox: SandboxSpec::empty(),
                path: "../escape.txt".to_string(),
            },
            expected: CanonicalOutcome::error("ERR_INVALID_ARG_TYPE"),
        },
    ]
}

fn fs_write_cases() -> Vec<CompatFixtureCase> {
    let payload = b"persisted bytes".to_vec();
    vec![
        CompatFixtureCase {
            case_name: "write_new_file".to_string(),
            description: "writing to a fresh path reports bytes_written".to_string(),
            input: CompatInput::FsWrite {
                sandbox: SandboxSpec::empty(),
                path: "out.bin".to_string(),
                data: payload.clone(),
            },
            expected: CanonicalOutcome::Success {
                result: CanonicalResult::FsWrite {
                    bytes_written: payload.len() as u64,
                },
            },
        },
        CompatFixtureCase {
            case_name: "write_missing_parent_enoent".to_string(),
            description: "writing under a missing parent dir yields ENOENT".to_string(),
            input: CompatInput::FsWrite {
                sandbox: SandboxSpec::empty(),
                path: "missing_dir/out.bin".to_string(),
                data: payload.clone(),
            },
            expected: CanonicalOutcome::error("ENOENT"),
        },
        CompatFixtureCase {
            case_name: "write_onto_directory_eisdir".to_string(),
            description: "writing onto an existing directory yields EISDIR".to_string(),
            input: CompatInput::FsWrite {
                sandbox: SandboxSpec::empty().with_dir("adir"),
                path: "adir".to_string(),
                data: payload,
            },
            expected: CanonicalOutcome::error("EISDIR"),
        },
    ]
}

fn process_env_cases() -> Vec<CompatFixtureCase> {
    let mut env = BTreeMap::new();
    env.insert("PATH".to_string(), "/usr/bin".to_string());
    env.insert("EMPTY".to_string(), String::new());
    vec![
        CompatFixtureCase {
            case_name: "env_present".to_string(),
            description: "present key returns present=true with value hash".to_string(),
            input: CompatInput::ProcessEnv {
                env: env.clone(),
                key: "PATH".to_string(),
            },
            expected: CanonicalOutcome::Success {
                result: CanonicalResult::ProcessEnv {
                    present: true,
                    value_sha256: Some(content_sha256(b"/usr/bin")),
                },
            },
        },
        CompatFixtureCase {
            case_name: "env_present_empty_value".to_string(),
            description: "present key with empty value is still present (boundary)".to_string(),
            input: CompatInput::ProcessEnv {
                env: env.clone(),
                key: "EMPTY".to_string(),
            },
            expected: CanonicalOutcome::Success {
                result: CanonicalResult::ProcessEnv {
                    present: true,
                    value_sha256: Some(content_sha256(b"")),
                },
            },
        },
        CompatFixtureCase {
            case_name: "env_absent".to_string(),
            description: "absent key returns present=false (Node returns undefined)".to_string(),
            input: CompatInput::ProcessEnv {
                env: env.clone(),
                key: "DOES_NOT_EXIST".to_string(),
            },
            expected: CanonicalOutcome::Success {
                result: CanonicalResult::ProcessEnv {
                    present: false,
                    value_sha256: None,
                },
            },
        },
        CompatFixtureCase {
            case_name: "env_invalid_key".to_string(),
            description: "a key containing '=' is invalid (ERR_INVALID_ARG_TYPE)".to_string(),
            input: CompatInput::ProcessEnv {
                env,
                key: "BAD=KEY".to_string(),
            },
            expected: CanonicalOutcome::error("ERR_INVALID_ARG_TYPE"),
        },
    ]
}

fn module_resolve_cases() -> Vec<CompatFixtureCase> {
    vec![
        CompatFixtureCase {
            case_name: "resolve_relative_exact".to_string(),
            description: "relative specifier resolves to an exact existing file".to_string(),
            input: CompatInput::ModuleResolve {
                sandbox: SandboxSpec::empty()
                    .with_file("lib/util.js", b"module.exports={}".to_vec()),
                specifier: "./util.js".to_string(),
                from: "lib/index.js".to_string(),
            },
            expected: CanonicalOutcome::Success {
                result: CanonicalResult::ModuleResolve {
                    resolved_path: "lib/util.js".to_string(),
                    format: "commonjs".to_string(),
                },
            },
        },
        CompatFixtureCase {
            case_name: "resolve_relative_extension".to_string(),
            description: "relative specifier resolves via .js extension".to_string(),
            input: CompatInput::ModuleResolve {
                sandbox: SandboxSpec::empty().with_file("lib/helper.js", b"x".to_vec()),
                specifier: "./helper".to_string(),
                from: "lib/index.js".to_string(),
            },
            expected: CanonicalOutcome::Success {
                result: CanonicalResult::ModuleResolve {
                    resolved_path: "lib/helper.js".to_string(),
                    format: "commonjs".to_string(),
                },
            },
        },
        CompatFixtureCase {
            case_name: "resolve_relative_missing".to_string(),
            description: "unresolvable relative specifier yields MODULE_NOT_FOUND".to_string(),
            input: CompatInput::ModuleResolve {
                sandbox: SandboxSpec::empty(),
                specifier: "./ghost".to_string(),
                from: "index.js".to_string(),
            },
            expected: CanonicalOutcome::error("MODULE_NOT_FOUND"),
        },
        CompatFixtureCase {
            case_name: "resolve_empty_specifier_invalid".to_string(),
            description: "empty specifier is invalid (ERR_INVALID_MODULE_SPECIFIER)".to_string(),
            input: CompatInput::ModuleResolve {
                sandbox: SandboxSpec::empty(),
                specifier: String::new(),
                from: "index.js".to_string(),
            },
            expected: CanonicalOutcome::error("ERR_INVALID_MODULE_SPECIFIER"),
        },
        CompatFixtureCase {
            case_name: "resolve_bare_main".to_string(),
            description: "bare specifier resolves via node_modules package main".to_string(),
            input: CompatInput::ModuleResolve {
                sandbox: SandboxSpec::empty()
                    .with_file(
                        "node_modules/pkg/package.json",
                        br#"{"name":"pkg","main":"main.js"}"#.to_vec(),
                    )
                    .with_file("node_modules/pkg/main.js", b"module.exports={}".to_vec()),
                specifier: "pkg".to_string(),
                from: "index.js".to_string(),
            },
            expected: CanonicalOutcome::Success {
                result: CanonicalResult::ModuleResolve {
                    resolved_path: "node_modules/pkg/main.js".to_string(),
                    format: "commonjs".to_string(),
                },
            },
        },
    ]
}

fn http_request_cases() -> Vec<CompatFixtureCase> {
    vec![
        CompatFixtureCase {
            case_name: "http_default_port".to_string(),
            description: "http URL without port canonicalizes to port 80".to_string(),
            input: CompatInput::HttpRequest {
                url: "http://Example.COM/path".to_string(),
                method: "get".to_string(),
            },
            expected: CanonicalOutcome::Success {
                result: CanonicalResult::HttpRequestCanonicalized {
                    scheme: "http".to_string(),
                    host: "example.com".to_string(),
                    port: 80,
                    path: "/path".to_string(),
                    method: "GET".to_string(),
                },
            },
        },
        CompatFixtureCase {
            case_name: "https_default_port_root".to_string(),
            description: "https URL with no path canonicalizes to '/' and port 443".to_string(),
            input: CompatInput::HttpRequest {
                url: "https://api.example.com".to_string(),
                method: "POST".to_string(),
            },
            expected: CanonicalOutcome::Success {
                result: CanonicalResult::HttpRequestCanonicalized {
                    scheme: "https".to_string(),
                    host: "api.example.com".to_string(),
                    port: 443,
                    path: "/".to_string(),
                    method: "POST".to_string(),
                },
            },
        },
        CompatFixtureCase {
            case_name: "http_explicit_port_query_stripped".to_string(),
            description: "explicit port retained; query string stripped from path".to_string(),
            input: CompatInput::HttpRequest {
                url: "http://host:8080/p?q=1#frag".to_string(),
                method: "DELETE".to_string(),
            },
            expected: CanonicalOutcome::Success {
                result: CanonicalResult::HttpRequestCanonicalized {
                    scheme: "http".to_string(),
                    host: "host".to_string(),
                    port: 8080,
                    path: "/p".to_string(),
                    method: "DELETE".to_string(),
                },
            },
        },
        CompatFixtureCase {
            case_name: "http_invalid_scheme".to_string(),
            description: "non-http(s) scheme yields ERR_INVALID_URL".to_string(),
            input: CompatInput::HttpRequest {
                url: "ftp://host/x".to_string(),
                method: "GET".to_string(),
            },
            expected: CanonicalOutcome::error("ERR_INVALID_URL"),
        },
        CompatFixtureCase {
            case_name: "http_malformed_url".to_string(),
            description: "a URL with no authority yields ERR_INVALID_URL".to_string(),
            input: CompatInput::HttpRequest {
                url: "notaurl".to_string(),
                method: "GET".to_string(),
            },
            expected: CanonicalOutcome::error("ERR_INVALID_URL"),
        },
    ]
}

// ── Shared helpers ───────────────────────────────────────────────────────────

/// Recognized JavaScript runtimes the external-process leg may spawn. Absolute
/// or relative paths are permitted as long as the final path component's stem
/// is one of these (e.g. `/opt/homebrew/bin/node`).
const ALLOWED_RUNTIME_STEMS: &[&str] = &["node", "nodejs", "bun", "deno"];

/// Fail-closed allowlist check for an external-leg program. Rejects empty
/// strings, anything carrying NUL or shell-control/metacharacters, and any
/// program whose file stem is not a recognized JS runtime. This guarantees the
/// leg can only ever launch a known interpreter, never an arbitrary command.
fn is_allowed_runtime_program(program: &str) -> bool {
    if program.is_empty() {
        return false;
    }
    // Reject any character that could enable shell injection or path tricks if
    // the value were ever mishandled, even though we spawn without a shell.
    const FORBIDDEN: &[char] = &[
        '\0', '\n', '\r', ';', '|', '&', '$', '`', '<', '>', '(', ')', '{', '}', '*', '?', '!',
        '"', '\'', ' ', '\t',
    ];
    if program.contains(FORBIDDEN) {
        return false;
    }
    let stem = std::path::Path::new(program)
        .file_stem()
        .map(|s| s.to_string_lossy().to_ascii_lowercase());
    match stem {
        Some(s) => ALLOWED_RUNTIME_STEMS.contains(&s.as_str()),
        None => false,
    }
}

/// Map a std IO error to the closest canonical Node error code.
fn io_error_to_code(e: &std::io::Error) -> &'static str {
    use std::io::ErrorKind;
    match e.kind() {
        ErrorKind::NotFound => "ENOENT",
        ErrorKind::PermissionDenied => "EACCES",
        ErrorKind::AlreadyExists => "EEXIST",
        _ => "EIO",
    }
}

/// Reject untrusted relative paths: empty, absolute, backslash, NUL, or any
/// `..` segment (sandbox escape). Returns the canonical arg-type error on
/// rejection.
fn validate_relative_path(path: &str) -> Result<(), &'static str> {
    if path.is_empty() || path.contains('\0') {
        return Err("ERR_INVALID_ARG_TYPE");
    }
    if path.starts_with('/') || path.contains('\\') {
        return Err("ERR_INVALID_ARG_TYPE");
    }
    for seg in path.split('/') {
        if seg == ".." {
            return Err("ERR_INVALID_ARG_TYPE");
        }
    }
    Ok(())
}

/// Join a relative specifier onto a base directory, collapsing `.`/`..`
/// segments. Returns `None` if the result escapes the sandbox root.
fn join_relative(base: &Path, specifier: &str) -> Option<String> {
    let mut segs: Vec<String> = base
        .components()
        .filter_map(|c| match c {
            std::path::Component::Normal(s) => Some(s.to_string_lossy().to_string()),
            _ => None,
        })
        .collect();
    for raw in specifier.split('/') {
        match raw {
            "" | "." => {}
            ".." => {
                // Popping past the root escapes the sandbox.
                segs.pop()?;
            }
            other => segs.push(other.to_string()),
        }
    }
    Some(segs.join("/"))
}

/// Reduce an arbitrary case/op identifier to a filesystem-safe segment.
fn sanitize_segment(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' {
                c
            } else {
                '_'
            }
        })
        .collect();
    if cleaned.is_empty() {
        "_".to_string()
    } else {
        cleaned
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::compat_gate::first_tranche_contract_for;

    fn cfg() -> ConformanceConfig {
        ConformanceConfig::default()
    }

    fn contract(op: CompatOperationId) -> &'static CompatOperationContract {
        first_tranche_contract_for(op).expect("first-tranche contract exists")
    }

    #[test]
    fn corpus_covers_every_first_tranche_operation() {
        let corpus = first_tranche_fixture_corpus();
        for contract in first_tranche_operation_contracts() {
            let n = corpus
                .iter()
                .filter(|c| c.operation_id() == contract.operation_id)
                .count();
            assert!(
                n >= 3,
                "operation {} should have >=3 fixture cases, got {n}",
                contract.operation_id.registry_id()
            );
        }
    }

    #[test]
    fn franken_matches_spec_is_green_for_every_operation() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let franken = FrankenLeg::new(tmp.path());
        let verdicts = run_first_tranche_conformance(&franken, &[], &cfg());
        assert_eq!(verdicts.len(), first_tranche_operation_contracts().len());
        for v in &verdicts {
            assert_eq!(
                v.signal,
                LockstepSignal::Green,
                "operation {} should be GREEN; diverged: {:?}; oracle: {:?}",
                v.operation_id,
                v.diverged_boundaries,
                v.oracle.verdict
            );
            assert!(v.reference_runtimes.iter().any(|r| r == SPEC_RUNTIME_ID));
            assert!(v.oracle.divergences.is_empty());
        }
    }

    #[test]
    fn injected_franken_divergence_is_red_and_emits_fixture() {
        // A leg that deliberately returns the wrong canonical outcome.
        struct WrongFranken;
        impl ConformanceLeg for WrongFranken {
            fn runtime_id(&self) -> &str {
                "franken"
            }
            fn execute(&self, _case: &CompatFixtureCase) -> Result<CanonicalOutcome, LegError> {
                Ok(CanonicalOutcome::error("WRONG"))
            }
        }
        let tmp = tempfile::tempdir().expect("tempdir");
        let fixtures = tmp.path().join("fixtures");
        let cfg = ConformanceConfig {
            timeout_ms: 1000,
            fixture_output_dir: Some(fixtures.clone()),
        };
        let spec = SpecLeg;
        let cases = fs_read_cases();
        let verdict = run_operation_conformance(
            contract(CompatOperationId::FsReadFile),
            &cases,
            &WrongFranken,
            &[&spec],
            &cfg,
        );
        assert_eq!(verdict.signal, LockstepSignal::Red);
        assert!(!verdict.diverged_boundaries.is_empty());
        assert!(!verdict.emitted_fixtures.is_empty());
        // Fixtures were actually written.
        let written: Vec<_> = std::fs::read_dir(&fixtures)
            .expect("fixture dir")
            .filter_map(Result::ok)
            .collect();
        assert!(!written.is_empty(), "expected divergence fixtures on disk");
    }

    #[test]
    fn franken_fs_read_real_io_paths() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let franken = FrankenLeg::new(tmp.path());
        let case = CompatFixtureCase {
            case_name: "rt_read".to_string(),
            description: "round-trip".to_string(),
            input: CompatInput::FsRead {
                sandbox: SandboxSpec::empty().with_file("f.txt", b"abc".to_vec()),
                path: "f.txt".to_string(),
            },
            expected: ok_fs_read(b"abc"),
        };
        let outcome = franken.execute(&case).expect("exec");
        assert_eq!(outcome, ok_fs_read(b"abc"));
    }

    #[test]
    fn unavailable_external_leg_is_skipped_not_failed() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let franken = FrankenLeg::new(tmp.path());
        let missing = ExternalProcessLeg::new(
            "ghost-runtime",
            "definitely-not-a-real-binary-xyz",
            tmp.path(),
        );
        let spec = SpecLeg;
        let cases = process_env_cases();
        let verdict = run_operation_conformance(
            contract(CompatOperationId::ProcessEnv),
            &cases,
            &franken,
            &[&spec, &missing],
            &cfg(),
        );
        // Still GREEN: the missing optional leg is skipped, spec agrees.
        assert_eq!(verdict.signal, LockstepSignal::Green);
        assert!(
            verdict
                .skipped_legs
                .iter()
                .any(|(r, _)| r == "ghost-runtime")
        );
        assert!(
            !verdict
                .reference_runtimes
                .iter()
                .any(|r| r == "ghost-runtime")
        );
    }

    #[test]
    fn canonical_outcome_bytes_are_deterministic() {
        let a = ok_fs_read(b"same");
        let b = ok_fs_read(b"same");
        assert_eq!(a.canonical_bytes(), b.canonical_bytes());
        let c = ok_fs_read(b"different");
        assert_ne!(a.canonical_bytes(), c.canonical_bytes());
    }

    #[test]
    fn http_canonicalization_normalizes_host_port_path_method() {
        assert_eq!(
            franken_http_request("HTTP://Host.Example/A/b?x=1", "get"),
            CanonicalOutcome::Success {
                result: CanonicalResult::HttpRequestCanonicalized {
                    scheme: "http".to_string(),
                    host: "host.example".to_string(),
                    port: 80,
                    path: "/A/b".to_string(),
                    method: "GET".to_string(),
                },
            }
        );
    }

    #[test]
    fn external_leg_program_allowlist_is_fail_closed() {
        assert!(is_allowed_runtime_program("node"));
        assert!(is_allowed_runtime_program("bun"));
        assert!(is_allowed_runtime_program("/opt/homebrew/bin/node"));
        assert!(is_allowed_runtime_program("deno"));
        // Rejected: unknown stems, shell metacharacters, empty, path tricks.
        assert!(!is_allowed_runtime_program("rm"));
        assert!(!is_allowed_runtime_program(""));
        assert!(!is_allowed_runtime_program("node; rm -rf /"));
        assert!(!is_allowed_runtime_program("node && evil"));
        assert!(!is_allowed_runtime_program("not-a-real-binary-xyz"));
    }

    #[test]
    fn validate_relative_path_rejects_traversal_and_absolute() {
        assert!(validate_relative_path("ok/sub.txt").is_ok());
        assert!(validate_relative_path("../escape").is_err());
        assert!(validate_relative_path("/abs").is_err());
        assert!(validate_relative_path("").is_err());
        assert!(validate_relative_path("a\0b").is_err());
        assert!(validate_relative_path("a\\b").is_err());
    }

    #[test]
    fn join_relative_collapses_and_guards_escape() {
        assert_eq!(
            join_relative(Path::new("lib"), "./util.js").as_deref(),
            Some("lib/util.js")
        );
        assert_eq!(
            join_relative(Path::new("lib/nested"), "../sibling").as_deref(),
            Some("lib/sibling")
        );
        assert_eq!(join_relative(Path::new(""), "../escape"), None);
    }

    #[test]
    fn process_env_invalid_key_is_arg_type_error() {
        let mut env = BTreeMap::new();
        env.insert("A".to_string(), "1".to_string());
        assert_eq!(
            franken_process_env(&env, "BAD=KEY"),
            CanonicalOutcome::error("ERR_INVALID_ARG_TYPE")
        );
        assert_eq!(
            franken_process_env(&env, ""),
            CanonicalOutcome::error("ERR_INVALID_ARG_TYPE")
        );
    }
}
