//! Real Python/JS consumers of the distributed executable, without product or
//! engine sources. Protocol vectors are independently signed by Node crypto.

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
        .arg(root.join("vectors.json"));
    checked(&mut vectors);
    let cases: Vec<serde_json::Value> =
        serde_json::from_slice(&fs::read(root.join("vectors.json")).unwrap()).unwrap();
    assert!(cases.len() >= 35, "empty or incomplete normative matrix");
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
    for (program, script) in [
        ("python3", "python_consumer.py"),
        ("node", "javascript_consumer.mjs"),
        ("node", "typescript_consumer.mts"),
    ] {
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
                let executable = checked(&mut command("node", &["-p", "process.execPath"]));
                let executable = String::from_utf8(executable.stdout).unwrap();
                boxed
                    .arg("--ro-bind")
                    .arg(executable.trim())
                    .arg("/node")
                    .args(["--", "/node", script]);
            } else {
                boxed.args(["--", "/usr/bin/python3", script]);
            }
            boxed.env("ABSENT_CHECKOUTS", &absent);
            boxed
        } else {
            command(program, &[script])
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
