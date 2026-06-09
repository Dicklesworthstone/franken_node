//! Compat-API Node/Bun parity conformance + metamorphic + golden coverage
//! (bd-f5b04.2.1.3).
//!
//! This suite proves PARITY rigor for the first-tranche compat operations on
//! top of the lockstep-oracle harness (bd-f5b04.2.1.2,
//! `api::compat_conformance`). It is the testing half of the keystone:
//!
//! 1. CONFORMANCE — the full built-in fixture corpus runs franken-vs-spec and
//!    must report divergence == 0 (GREEN) for every operation.
//! 2. ERROR-CODE PARITY — explicit Node/Bun error-code assertions
//!    (ENOENT / EISDIR / ENOTDIR / ERR_INVALID_ARG_TYPE / ERR_INVALID_URL /
//!    ERR_INVALID_MODULE_SPECIFIER / MODULE_NOT_FOUND).
//! 3. METAMORPHIC (proptest) — write-then-read round-trips, determinism
//!    (same op + same input => identical canonical bytes), HTTP host/scheme
//!    case-insensitivity, and process.env present-iff-in-map.
//! 4. GOLDEN — the canonical op outcome schemas are golden-locked against
//!    `tests/golden/compat_api_canonical_schema.json`; the shapes cannot drift
//!    without regenerating the golden (set `FRANKEN_REGEN_GOLDEN=1`).
//!
//! The run-level E2E ("a tiny real project under `franken-node run`") is NOT
//! covered here: the CLI runtime does not yet execute these canonical compat
//! operations. That is tracked separately and depends on the runtime kernel
//! wiring the compat ops into `franken-node run`.
//!
//! Run: `rch exec -- cargo test -p frankenengine-node --no-default-features
//! --features control-plane --test compat_api_parity_conformance --
//! --nocapture`.

use std::collections::BTreeMap;
use std::path::PathBuf;

use frankenengine_node::api::compat_conformance::{
    COMPAT_CONFORMANCE_SCHEMA, CanonicalOutcome, CanonicalResult, CompatFixtureCase, CompatInput,
    ConformanceConfig, ConformanceLeg, FrankenLeg, LockstepSignal, SandboxSpec,
    run_first_tranche_conformance,
};
use proptest::prelude::*;

fn log(step: &str, detail: &str) {
    eprintln!("[compat-parity] {step}: {detail}");
}

/// Build a throwaway fixture case for driving the franken leg directly (the
/// `expected` field is unused by the franken leg).
fn case(name: &str, input: CompatInput) -> CompatFixtureCase {
    CompatFixtureCase {
        case_name: name.to_string(),
        description: String::new(),
        input,
        expected: CanonicalOutcome::error("UNUSED"),
    }
}

fn franken(tmp: &tempfile::TempDir) -> FrankenLeg {
    FrankenLeg::new(tmp.path())
}

// ── 1. CONFORMANCE: full corpus is divergence-free (GREEN) ───────────────────

#[test]
fn full_corpus_is_divergence_free_across_all_operations() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let leg = franken(&tmp);
    let verdicts = run_first_tranche_conformance(&leg, &[], &ConformanceConfig::default());
    let mut total_cases = 0usize;
    for v in &verdicts {
        log(
            "conformance",
            &format!(
                "op={} signal={} cases={} divergences={}",
                v.operation_id,
                v.signal.as_str(),
                v.cases_tested,
                v.oracle.stats.total_divergences
            ),
        );
        assert_eq!(
            v.signal,
            LockstepSignal::Green,
            "operation {} diverged from spec: {:?}",
            v.operation_id,
            v.diverged_boundaries
        );
        assert_eq!(v.oracle.stats.total_divergences, 0);
        total_cases += v.cases_tested;
    }
    assert!(
        total_cases >= 20,
        "corpus should be substantial, got {total_cases}"
    );
    log(
        "conformance",
        &format!("{total_cases} cases divergence-free"),
    );
}

// ── 2. EXPLICIT Node/Bun error-code parity ───────────────────────────────────

fn franken_outcome(leg: &FrankenLeg, name: &str, input: CompatInput) -> CanonicalOutcome {
    leg.execute(&case(name, input)).expect("franken exec")
}

#[test]
fn node_error_code_parity_table() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let leg = franken(&tmp);

    // fs.readFile: missing -> ENOENT.
    assert_eq!(
        franken_outcome(
            &leg,
            "p_enoent",
            CompatInput::FsRead {
                sandbox: SandboxSpec::empty(),
                path: "missing.txt".to_string(),
            },
        ),
        CanonicalOutcome::error("ENOENT")
    );
    // fs.readFile: directory -> EISDIR.
    assert_eq!(
        franken_outcome(
            &leg,
            "p_eisdir",
            CompatInput::FsRead {
                sandbox: SandboxSpec::empty().with_dir("d"),
                path: "d".to_string(),
            },
        ),
        CanonicalOutcome::error("EISDIR")
    );
    // fs.writeFile: missing parent -> ENOENT.
    assert_eq!(
        franken_outcome(
            &leg,
            "p_write_enoent",
            CompatInput::FsWrite {
                sandbox: SandboxSpec::empty(),
                path: "no_dir/x.bin".to_string(),
                data: b"x".to_vec(),
            },
        ),
        CanonicalOutcome::error("ENOENT")
    );
    // process.env: invalid key -> ERR_INVALID_ARG_TYPE.
    assert_eq!(
        franken_outcome(
            &leg,
            "p_env_bad",
            CompatInput::ProcessEnv {
                env: BTreeMap::new(),
                key: "A=B".to_string(),
            },
        ),
        CanonicalOutcome::error("ERR_INVALID_ARG_TYPE")
    );
    // http.request: bad scheme -> ERR_INVALID_URL.
    assert_eq!(
        franken_outcome(
            &leg,
            "p_url",
            CompatInput::HttpRequest {
                url: "ftp://h/x".to_string(),
                method: "GET".to_string(),
            },
        ),
        CanonicalOutcome::error("ERR_INVALID_URL")
    );
    // module.resolve: empty specifier -> ERR_INVALID_MODULE_SPECIFIER.
    assert_eq!(
        franken_outcome(
            &leg,
            "p_spec",
            CompatInput::ModuleResolve {
                sandbox: SandboxSpec::empty(),
                specifier: String::new(),
                from: "i.js".to_string(),
            },
        ),
        CanonicalOutcome::error("ERR_INVALID_MODULE_SPECIFIER")
    );
    // module.resolve: unresolvable relative -> MODULE_NOT_FOUND.
    assert_eq!(
        franken_outcome(
            &leg,
            "p_notfound",
            CompatInput::ModuleResolve {
                sandbox: SandboxSpec::empty(),
                specifier: "./ghost".to_string(),
                from: "i.js".to_string(),
            },
        ),
        CanonicalOutcome::error("MODULE_NOT_FOUND")
    );
    log("parity", "all explicit Node/Bun error codes match");
}

// ── 3. METAMORPHIC properties (proptest) ─────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    /// write-then-read round-trip: bytes written are exactly the bytes read.
    #[test]
    fn prop_fs_write_then_read_roundtrip(
        name in "[a-z][a-z0-9_]{0,7}",
        data in proptest::collection::vec(any::<u8>(), 0..2048),
    ) {
        let tmp = tempfile::tempdir().expect("tempdir");
        let leg = franken(&tmp);
        let path = format!("{name}.bin");
        let write = franken_outcome(
            &leg,
            "rt",
            CompatInput::FsWrite {
                sandbox: SandboxSpec::empty(),
                path: path.clone(),
                data: data.clone(),
            },
        );
        prop_assert_eq!(
            write,
            CanonicalOutcome::Success {
                result: CanonicalResult::FsWrite { bytes_written: data.len() as u64 },
            }
        );
        let read = franken_outcome(
            &leg,
            "rt",
            CompatInput::FsRead { sandbox: SandboxSpec::empty(), path },
        );
        match read {
            CanonicalOutcome::Success { result: CanonicalResult::FsRead { byte_len, .. } } => {
                prop_assert_eq!(byte_len, data.len() as u64);
            }
            other => prop_assert!(false, "expected FsRead success, got {:?}", other),
        }
    }

    /// determinism: identical input yields identical canonical bytes.
    #[test]
    fn prop_same_input_same_canonical_bytes(
        data in proptest::collection::vec(any::<u8>(), 0..512),
    ) {
        let tmp = tempfile::tempdir().expect("tempdir");
        let leg = franken(&tmp);
        let input = CompatInput::FsRead {
            sandbox: SandboxSpec::empty().with_file("f.bin", data),
            path: "f.bin".to_string(),
        };
        let a = franken_outcome(&leg, "det", input.clone());
        let b = franken_outcome(&leg, "det", input);
        prop_assert_eq!(a.canonical_bytes(), b.canonical_bytes());
    }

    /// HTTP canonicalization is host/scheme case-insensitive and deterministic.
    #[test]
    fn prop_http_case_insensitive_host_and_scheme(
        host in "[a-z]{1,6}",
        tld in "[a-z]{2,3}",
        seg in "[a-z]{1,6}",
    ) {
        let tmp = tempfile::tempdir().expect("tempdir");
        let leg = franken(&tmp);
        let lower = format!("http://{host}.{tld}/{seg}");
        let upper = format!("HTTP://{}.{}/{seg}", host.to_uppercase(), tld.to_uppercase());
        let a = franken_outcome(&leg, "http", CompatInput::HttpRequest { url: lower, method: "get".to_string() });
        let b = franken_outcome(&leg, "http", CompatInput::HttpRequest { url: upper, method: "GET".to_string() });
        prop_assert_eq!(a.canonical_bytes(), b.canonical_bytes());
        // And it is a canonicalized success with the lowercased host.
        match a {
            CanonicalOutcome::Success { result: CanonicalResult::HttpRequestCanonicalized { scheme, host: h, port, .. } } => {
                prop_assert_eq!(scheme, "http");
                prop_assert_eq!(h, format!("{host}.{tld}"));
                prop_assert_eq!(port, 80u16);
            }
            other => prop_assert!(false, "expected canonicalized http success, got {:?}", other),
        }
    }

    /// process.env: present iff the (valid) key is in the snapshot.
    #[test]
    fn prop_process_env_present_iff_in_map(
        key in "[A-Z][A-Z_]{0,7}",
        value in "[a-zA-Z0-9/_-]{0,16}",
        include in any::<bool>(),
    ) {
        let tmp = tempfile::tempdir().expect("tempdir");
        let leg = franken(&tmp);
        let mut env = BTreeMap::new();
        if include {
            env.insert(key.clone(), value);
        }
        let outcome = franken_outcome(&leg, "env", CompatInput::ProcessEnv { env, key });
        match outcome {
            CanonicalOutcome::Success { result: CanonicalResult::ProcessEnv { present, value_sha256 } } => {
                prop_assert_eq!(present, include);
                prop_assert_eq!(value_sha256.is_some(), include);
            }
            other => prop_assert!(false, "expected ProcessEnv success, got {:?}", other),
        }
    }
}

// ── 4. GOLDEN: canonical op schemas are golden-locked ────────────────────────

fn golden_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/golden/compat_api_canonical_schema.json")
}

/// Representative canonical outcomes (one+ per CanonicalResult variant + the
/// error envelope) whose serialized shapes must remain frozen.
fn golden_samples() -> BTreeMap<String, CanonicalOutcome> {
    let mut m = BTreeMap::new();
    m.insert(
        "fs_read_success".to_string(),
        CanonicalOutcome::Success {
            result: CanonicalResult::FsRead {
                byte_len: 11,
                content_sha256: "sha256:fixed".to_string(),
            },
        },
    );
    m.insert(
        "fs_read_enoent".to_string(),
        CanonicalOutcome::error("ENOENT"),
    );
    m.insert(
        "fs_write_success".to_string(),
        CanonicalOutcome::Success {
            result: CanonicalResult::FsWrite { bytes_written: 7 },
        },
    );
    m.insert(
        "process_env_present".to_string(),
        CanonicalOutcome::Success {
            result: CanonicalResult::ProcessEnv {
                present: true,
                value_sha256: Some("sha256:fixed".to_string()),
            },
        },
    );
    m.insert(
        "process_env_absent".to_string(),
        CanonicalOutcome::Success {
            result: CanonicalResult::ProcessEnv {
                present: false,
                value_sha256: None,
            },
        },
    );
    m.insert(
        "module_resolve_success".to_string(),
        CanonicalOutcome::Success {
            result: CanonicalResult::ModuleResolve {
                resolved_path: "lib/util.js".to_string(),
                format: "commonjs".to_string(),
            },
        },
    );
    m.insert(
        "http_request_success".to_string(),
        CanonicalOutcome::Success {
            result: CanonicalResult::HttpRequestCanonicalized {
                scheme: "https".to_string(),
                host: "example.com".to_string(),
                port: 443,
                path: "/".to_string(),
                method: "GET".to_string(),
            },
        },
    );
    m.insert(
        "error_invalid_url".to_string(),
        CanonicalOutcome::error("ERR_INVALID_URL"),
    );
    m
}

#[test]
fn canonical_op_schemas_are_golden_locked() {
    // Build the live golden: label -> canonical JSON value.
    let mut live: BTreeMap<String, serde_json::Value> = BTreeMap::new();
    for (label, outcome) in golden_samples() {
        let value: serde_json::Value =
            serde_json::from_slice(&outcome.canonical_bytes()).expect("canonical bytes are json");
        live.insert(label, value);
    }
    let mut envelope = serde_json::Map::new();
    envelope.insert(
        "schema_version".to_string(),
        serde_json::Value::String(COMPAT_CONFORMANCE_SCHEMA.to_string()),
    );
    envelope.insert(
        "samples".to_string(),
        serde_json::to_value(&live).expect("serialize samples"),
    );
    let live_doc = serde_json::Value::Object(envelope);

    let path = golden_path();
    if std::env::var("FRANKEN_REGEN_GOLDEN").is_ok() {
        let pretty = serde_json::to_vec_pretty(&live_doc).expect("serialize golden");
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("golden dir");
        }
        std::fs::write(&path, &pretty).expect("write golden");
        log("golden", &format!("regenerated {}", path.display()));
        return;
    }

    let raw = std::fs::read(&path).expect(
        "golden file tests/golden/compat_api_canonical_schema.json missing; \
         regenerate with FRANKEN_REGEN_GOLDEN=1",
    );
    let golden: serde_json::Value =
        serde_json::from_slice(&raw).expect("golden file is valid json");
    assert_eq!(
        golden, live_doc,
        "canonical compat-API schema drifted from the golden; if intentional, \
         bump COMPAT_CONFORMANCE_SCHEMA and regenerate with FRANKEN_REGEN_GOLDEN=1"
    );
    log("golden", "canonical op schemas match the frozen golden");
}
