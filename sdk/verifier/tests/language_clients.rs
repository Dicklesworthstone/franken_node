//! Real Python/JS consumers of the distributed executable, without product or
//! engine sources. Adversarial protocol vectors are independently signed by
//! Node crypto; the original-run interoperability fixture retains the actual
//! production signers' signatures over explicitly synthetic execution metadata.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

fn checked(command: &mut Command) -> Output {
    let output = command.output().expect("execute consumer prerequisite");
    print!("{}", String::from_utf8_lossy(&output.stdout));
    eprint!("{}", String::from_utf8_lossy(&output.stderr));
    assert!(
        output.status.success(),
        "consumer command failed: {command:?}"
    );
    output
}

fn command(program: impl AsRef<std::ffi::OsStr>, args: &[&str]) -> Command {
    let mut command = Command::new(program);
    command.args(args);
    command
}

fn copy(source: impl AsRef<Path>, destination: impl AsRef<Path>) {
    fs::copy(source, destination).expect("copy distributed verifier artifact");
}

#[test]
fn external_python_and_javascript_consumers_verify_signed_evidence() {
    let sdk = Path::new(env!("CARGO_MANIFEST_DIR"));
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let parent = if cfg!(unix) {
        PathBuf::from("/tmp")
    } else {
        std::env::temp_dir()
    };
    let root = parent.join(format!(
        "franken-verifier-consumer-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir(&root).unwrap();
    // Intentionally retained for evidence; no cleanup of user/peer files.
    println!("consumer artifacts: {}", root.display());
    copy(
        env!("CARGO_BIN_EXE_franken-verifier"),
        root.join("verifier"),
    );
    copy(
        sdk.join("bindings/python/franken_verifier.py"),
        root.join("franken_verifier.py"),
    );
    copy(
        sdk.join("bindings/javascript/franken_verifier.mjs"),
        root.join("franken_verifier.mjs"),
    );
    copy(
        sdk.join("bindings/javascript/franken_verifier.d.mts"),
        root.join("franken_verifier.d.mts"),
    );
    copy(
        sdk.join("tests/clients/python_consumer.py"),
        root.join("python_consumer.py"),
    );
    copy(
        sdk.join("tests/clients/javascript_consumer.mjs"),
        root.join("javascript_consumer.mjs"),
    );
    copy(
        sdk.join("tests/clients/typescript_consumer.mts"),
        root.join("typescript_consumer.mts"),
    );
    copy(
        sdk.join("tests/clients/fake_verifier.py"),
        root.join("fake_verifier"),
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(
            root.join("fake_verifier"),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
    }

    checked(&mut command("node", &["--version"]));
    checked(&mut command("python3", &["--version"]));
    let mut vectors = Command::new("node");
    vectors
        .arg(sdk.join("tests/clients/build_vectors.mjs"))
        .arg(sdk.join("tests/fixtures/cli_incident_bundle/INC-SDK-FIXTURE-1.fnbundle"))
        .arg(sdk.join("tests/fixtures/public_api/bundle_canonical.json"))
        .arg(sdk.join("tests/fixtures/cli_incident_bundle/rfc8032_test1_seed.hex"))
        .arg(root.join("vectors.json"))
        .arg(sdk.join("tests/fixtures/run_origin_protocol/producer-run.fnbundle"))
        .arg(sdk.join("tests/fixtures/run_origin_protocol/bundle-authority.pub"))
        .arg(sdk.join("tests/fixtures/run_origin_protocol/run-authority.pub"))
        .arg(sdk.join("tests/fixtures/module_source_capsules.json"));
    checked(&mut vectors);
    let cases: Vec<serde_json::Value> =
        serde_json::from_slice(&fs::read(root.join("vectors.json")).unwrap()).unwrap();
    assert!(cases.len() >= 35, "empty or incomplete normative matrix");
    assert!(
        cases
            .iter()
            .filter(|case| case["format"] == "publisher-source-trust")
            .count()
            >= 25,
        "publisher trust acceptance and refusal matrix must execute",
    );
    for case in &cases {
        let mut verifier = Command::new(root.join("verifier"));
        verifier.args([
            "verify",
            "--format",
            case["format"].as_str().unwrap(),
            "--trusted-key-hex",
            case["anchor"].as_str().unwrap(),
        ]);
        if let Some(signature) = case["signature_hex"].as_str() {
            verifier.args(["--signature-hex", signature]);
        }
        if let Some(run_anchor) = case["run_anchor"].as_str() {
            verifier.args(["--trusted-run-key-hex", run_anchor]);
        }
        if let Some(runtime_anchor) = case["runtime_anchor"].as_str() {
            verifier.args(["--trusted-runtime-key-hex", runtime_anchor]);
        }
        for (field, option) in [
            ("revocation_anchor", "--trusted-revocation-key-hex"),
            ("provenance_anchor", "--trusted-provenance-key-hex"),
            ("evaluation_time", "--evaluation-time"),
            ("max_revocation_age_secs", "--max-revocation-age-secs"),
        ] {
            if let Some(value) = case[field].as_str() {
                verifier.args([option, value]);
            }
        }
        let mut child = verifier
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let bytes = hex::decode(case["input_hex"].as_str().unwrap()).unwrap();
        // Invalid format/arguments may close stdin before reading it. Keep the
        // process result authoritative while retaining any write error below.
        if let Err(error) = child.stdin.take().unwrap().write_all(&bytes) {
            eprintln!("Rust consumer stdin {}: {error}", case["name"]);
        }
        let output = child.wait_with_output().unwrap();
        eprint!("{}", String::from_utf8_lossy(&output.stderr));
        let response: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        if case["expected"] == "verified" {
            assert!(
                output.status.success(),
                "Rust consumer {}: {response}",
                case["name"]
            );
            assert_eq!(response["artifact_sha256"], case["artifact_sha256"]);
            assert_eq!(response["verdict"], "verified");
            if case["format"] == "publisher-source" {
                assert_eq!(response["scope"], "authenticated_publisher_source_content");
                assert_eq!(response["facts"], case["publisher_facts"]);
                assert_eq!(response["facts"]["capsule"]["graph_hash_recomputed"], false);
                assert!(!response.to_string().contains("PRIVATE-"));
            }
            if case["format"] == "publisher-source-trust" {
                assert_eq!(response["scope"], "authenticated_publisher_source_trust");
                assert_eq!(response["facts"], case["publisher_trust_facts"]);
                assert_eq!(
                    response["facts"]["source"]["capsule"]["graph_hash_recomputed"],
                    false
                );
                assert!(!response.to_string().contains("PRIVATE-"));
            }
            if let Some(run_anchor) = case["run_anchor"].as_str() {
                assert_eq!(
                    response["scope"],
                    if case["runtime_anchor"].is_string() {
                        "authenticated_runtime_incident"
                    } else {
                        "authenticated_run_incident"
                    }
                );
                assert_eq!(
                    response["facts"]["run_origin"]["signer_public_key_hex"],
                    run_anchor
                );
            }
            if let Some(runtime_anchor) = case["runtime_anchor"].as_str() {
                assert_eq!(
                    response["facts"]["runtime_origin"]["product_root_key_id"],
                    format!("ed25519:{runtime_anchor}")
                );
                assert_eq!(
                    response["facts"]["runtime_origin"]["signed_epoch"],
                    "18446744073709551615"
                );
            }
        } else {
            assert!(!output.status.success(), "Rust accepted {}", case["name"]);
            assert_eq!(
                response["error"]["code"], case["expected"],
                "Rust case {}",
                case["name"]
            );
        }
        println!("Rust matrix case {}: {}", case["name"], case["expected"]);
    }

    // A copied distribution runs outside the workspace on every host. The
    // Linux acceptance lane additionally hides both source checkouts with a
    // mount namespace. Missing bwrap fails that lane, never silently skips it.
    let source_root = sdk.parent().unwrap().parent().unwrap();
    let engine = source_root.parent().unwrap().join("franken_engine");
    let absent = serde_json::to_string(&[source_root, &engine]).unwrap();
    let sandbox = cfg!(target_os = "linux");
    let ts_probe = root.join("_ts_probe.mts");
    fs::write(&ts_probe, "const probe: number = 1;\nvoid probe;\n").unwrap();
    let node_mts_mode: Option<Option<&'static str>> = if Command::new("node")
        .arg(&ts_probe)
        .output()
        .is_ok_and(|out| out.status.success())
    {
        Some(None)
    } else if Command::new("node")
        .args(["--experimental-strip-types"])
        .arg(&ts_probe)
        .output()
        .is_ok_and(|out| out.status.success())
    {
        Some(Some("--experimental-strip-types"))
    } else {
        let mts_src = root.join("typescript_consumer.mts");
        let mjs_out = root.join("typescript_consumer.compiled.mjs");
        checked(&mut command(
            "bun",
            &[
                "-e",
                "import { readFileSync, writeFileSync } from 'node:fs'; \
                 const t = new Bun.Transpiler({ loader: 'ts' }); \
                 writeFileSync(process.argv[2], t.transformSync(readFileSync(process.argv[1], 'utf8')));",
                mts_src.to_str().unwrap(),
                mjs_out.to_str().unwrap(),
            ],
        ));
        None
    };

    for (program, script) in [
        ("python3", "python_consumer.py"),
        ("node", "javascript_consumer.mjs"),
        ("node", "typescript_consumer.mts"),
    ] {
        let effective_script = if script.ends_with(".mts") && node_mts_mode.is_none() {
            "typescript_consumer.compiled.mjs"
        } else {
            script
        };
        let node_flag = if script.ends_with(".mts") {
            node_mts_mode.flatten()
        } else {
            None
        };
        let mut consumer = if sandbox {
            let mut boxed = Command::new("bwrap");
            boxed.args([
                "--ro-bind",
                "/usr",
                "/usr",
                "--ro-bind",
                "/lib",
                "/lib",
                "--dev",
                "/dev",
                "--tmpfs",
                "/tmp",
            ]);
            if Path::new("/lib64").exists() {
                boxed.args(["--ro-bind", "/lib64", "/lib64"]);
            }
            boxed
                .arg("--ro-bind")
                .arg(&root)
                .arg("/work")
                .args(["--chdir", "/work"]);
            if program == "node" {
                let executable = checked(&mut command(
                    "node",
                    &["-e", "process.stdout.write(process.execPath)"],
                ));
                let executable = String::from_utf8(executable.stdout).unwrap();
                boxed.arg("--ro-bind").arg(executable.trim()).arg("/node");
                if let Some(flag) = node_flag {
                    boxed.args(["--", "/node", flag, effective_script]);
                } else {
                    boxed.args(["--", "/node", effective_script]);
                }
            } else {
                boxed.args(["--", "/usr/bin/python3", effective_script]);
            }
            boxed.env("ABSENT_CHECKOUTS", &absent);
            boxed
        } else if let Some(flag) = node_flag {
            command(program, &[flag, effective_script])
        } else {
            command(program, &[effective_script])
        };
        consumer
            .current_dir(&root)
            .env("PYTHONDONTWRITEBYTECODE", "1");
        let output = checked(&mut consumer);
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("\"passed\":true")
                || String::from_utf8_lossy(&output.stdout).contains("\"passed\": true")
        );
        if !script.ends_with(".mts") {
            // Re-use exactly the same matrix with a child that accepts every
            // signature. The consumer itself must fail, not turn green by
            // checking that the fake process can produce JSON.
            consumer.env(
                "VERIFIER_EXECUTABLE",
                if sandbox {
                    PathBuf::from("/work/fake_verifier")
                } else {
                    root.join("fake_verifier")
                },
            );
            let broken = consumer.output().unwrap();
            print!("{}", String::from_utf8_lossy(&broken.stdout));
            eprint!("{}", String::from_utf8_lossy(&broken.stderr));
            assert!(
                !broken.status.success(),
                "accept-everything verifier escaped the consumer gate"
            );
            assert!(String::from_utf8_lossy(&broken.stderr).contains("foreign_anchor"));
            println!("planted broken verifier detected by {program}");
        }
    }
    println!("consumer source checkouts hidden: {sandbox}");
}
