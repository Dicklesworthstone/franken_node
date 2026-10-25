#!/usr/bin/env python3
"""Exercise an installed release, retaining exact commands, streams and identity.

Consumer/gate: dist.yml must pass this on each native host before publication.
Observed defect: v0.2.0 accepts safe-mode entry but still executes the guest.
Retire this helper when equivalent packaged-binary acceptance replaces it.
This is release qualification work, not a new runtime capability or KPI proof.
"""
from __future__ import annotations

import argparse
import functools
import hashlib
import http.server
import json
import os
import platform
import subprocess
import sys
import tempfile
import threading
from pathlib import Path
from urllib.parse import quote


class SmokeFailure(RuntimeError):
    pass


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


class Probe:
    def __init__(self, evidence: Path):
        # Refuse reuse: neither an earlier success nor its raw output is replaced.
        evidence.mkdir(parents=True, exist_ok=False)
        self.evidence = evidence.resolve()
        self.workspace = self.evidence / "workspace"
        self.workspace.mkdir()
        self.env = {key: value for key, value in os.environ.items()
                    if not key.startswith("FRANKEN_NODE_") and key != "NODE_OPTIONS"}
        for key, child in (("HOME", "home"), ("USERPROFILE", "home"), ("XDG_CONFIG_HOME", "home"),
                           ("XDG_STATE_HOME", "state"), ("LOCALAPPDATA", "state")):
            directory = self.evidence / child
            directory.mkdir(exist_ok=True)
            self.env[key] = str(directory)
        # Native telemetry uses a Unix socket. Long CI/evidence paths cannot
        # be used as TMPDIR (macOS sockaddr_un has a small fixed path limit).
        self.runtime_tmp = Path(tempfile.mkdtemp(prefix="fnr-", dir=None if sys.platform == "win32" else "/tmp"))
        for key in ("TMPDIR", "TMP", "TEMP"):
            self.env[key] = str(self.runtime_tmp)
        self.steps: list[dict] = []

    def run(self, name: str, command: list[str], *, expected_exit: int = 0,
            stdout: bytes | None = None, diagnostic: bytes | None = None,
            forbidden_stdout: bytes | None = None) -> subprocess.CompletedProcess:
        prefix = self.evidence / f"{len(self.steps):02d}-{name}"
        result = None
        error = None
        # Files, rather than pipes, retain partial output on timeout and avoid
        # buffering unbounded candidate output in the qualification process.
        with prefix.with_suffix(".stdout").open("xb") as out, prefix.with_suffix(".stderr").open("xb") as err:
            try:
                result = subprocess.run(command, cwd=self.workspace, env=self.env,
                                        stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                                        timeout=60, check=False)
            except (OSError, subprocess.TimeoutExpired) as failure:
                error = str(failure)
        step = {"name": name, "command": command, "cwd": str(self.workspace),
                "expected_exit": expected_exit,
                "returncode": None if result is None else result.returncode,
                "error": error, "passed": False}
        self.steps.append(step)
        if error is None:
            streams = [prefix.with_suffix(suffix) for suffix in (".stdout", ".stderr")]
            if any(path.stat().st_size > 1 << 20 for path in streams):
                step["error"] = "candidate output exceeds 1 MiB; raw streams retained"
            actual, errors = [path.read_bytes() if path.stat().st_size <= 1 << 20 else b"" for path in streams]
            # Signals, Windows exception statuses and usage errors are not
            # policy refusals. The governed refusal contract is exit 1.
            valid_exit = result.returncode == expected_exit
            step["passed"] = (step["error"] is None and valid_exit and (stdout is None or actual == stdout)
                              and (diagnostic is None or diagnostic in actual + errors)
                              and (forbidden_stdout is None or forbidden_stdout not in actual))
        with prefix.with_suffix(".json").open("x", encoding="utf-8") as output:
            json.dump(step, output, indent=2)
        if not step["passed"]:
            raise SmokeFailure(f"{name} failed; inspect {prefix}.json and its raw streams")
        return result


def install_archive(probe: Probe, archive: Path, repository: Path) -> Path:
    """Run the actual platform installer against this run's packaged archive."""
    destination = probe.evidence / "installed bin"
    if sys.platform != "win32":
        probe.run("install", ["bash", str(repository / "install.sh"), "--offline", str(archive),
                              "--dest", str(destination), "--verify", "--no-gum"])
        return destination / "franken-node"
    # PowerShell's installer downloads releases. Serve only the archive folder
    # on an ephemeral loopback port; its real checksum path remains enabled.
    handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=str(archive.parent))
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        url = f"http://127.0.0.1:{server.server_port}/{quote(archive.name)}"
        probe.run("install", ["pwsh", "-NoProfile", "-File", str(repository / "install.ps1"),
                              "-ArtifactUrl", url, "-Checksum", sha256(archive),
                              "-Dest", str(destination), "-Verify"])
    finally:
        server.shutdown()
        server.server_close()
        thread.join()
    return destination / "franken-node.exe"


def exercise(probe: Probe, command: list[str]) -> None:
    """Require positive execution, actual containment, and positive recovery."""
    workspace = probe.workspace
    (workspace / "hello.js").write_text('console.log("release-native-ok");\n', encoding="utf-8")
    (workspace / "local.cjs").write_text('module.exports = { value: 42 };\n', encoding="utf-8")
    (workspace / "main.cjs").write_text(
        'console.log("local:" + require("./local.cjs").value);\n', encoding="utf-8")
    (workspace / "write.cjs").write_text(
        'const fs = require("fs"); fs.writeFileSync("forbidden.txt", "unexpected");\n',
        encoding="utf-8")
    probe.run("version", command + ["--version"])
    probe.run("help", command + ["--help"])
    # JSON init includes newly generated API-key values. The human report
    # retains bootstrap counts without putting those values in public streams.
    probe.run("init", command + ["init", "--profile", "balanced", "--out-dir", "."])
    if not (workspace / "franken_node.toml").is_file():
        raise SmokeFailure("init returned success without writing franken_node.toml")
    run = command + ["run", "hello.js", "--policy", "balanced", "--console-only"]
    probe.run("native-hello", run, stdout=b"release-native-ok\n")
    probe.run("native-local-import", command + ["run", "main.cjs", "--policy", "balanced", "--console-only"],
              stdout=b"local:42\n")
    probe.run("strict-write-refused", command + ["run", "write.cjs", "--policy", "strict", "--json"],
              expected_exit=1, diagnostic=b"capability denied: fs:write")
    if (workspace / "forbidden.txt").exists():
        raise SmokeFailure("strict run wrote forbidden.txt despite reporting a refusal")
    probe.run("safe-mode-enter", command + ["safe-mode", "enter", "--reason", "explicit-flag",
              "--operator-id", "release-smoke", "--trust-state-hash", "sha256:" + "0" * 64, "--json"])
    probe.run("safe-mode-blocks-native", run, expected_exit=1, diagnostic=b"run blocked by active safe mode",
              forbidden_stdout=b"release-native-ok")
    probe.run("safe-mode-recover", command + ["safe-mode", "exit", "--operator-id", "release-smoke",
              "--confirm", "--trust-state-consistent", "--no-unresolved-incidents",
              "--evidence-ledger-intact", "--json"])
    probe.run("native-after-recovery", run, stdout=b"release-native-ok\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    candidate = parser.add_mutually_exclusive_group(required=True)
    candidate.add_argument("--archive", type=Path)
    candidate.add_argument("--binary", type=Path)
    parser.add_argument("--expected-binary", type=Path,
                        help="Require installed bytes to equal this target's build output")
    parser.add_argument("--evidence-dir", type=Path, required=True, help="Must not already exist")
    args = parser.parse_args()
    probe = Probe(args.evidence_dir)
    report = {"schema_version": "franken-node/installed-release-smoke/v1",
              "host": platform.platform(), "machine": platform.machine(), "passed": False,
              "runtime_tmp": str(probe.runtime_tmp),
              "steps": probe.steps}
    try:
        if args.archive is not None:
            archive = args.archive.resolve(strict=True)
            report["archive_sha256"] = sha256(archive)
            binary = install_archive(probe, archive, Path(__file__).resolve().parents[1])
        else:
            binary = args.binary.resolve(strict=True)
        report["binary"] = str(binary)
        report["binary_sha256"] = sha256(binary)
        if args.expected_binary is not None:
            report["expected_binary_sha256"] = sha256(args.expected_binary)
            if report["binary_sha256"] != report["expected_binary_sha256"]:
                raise SmokeFailure("installed bytes differ from the platform build output")
        exercise(probe, [str(binary)])
        if sha256(binary) != report["binary_sha256"]:
            raise SmokeFailure("installed binary changed during qualification")
        report["passed"] = True
    except (OSError, SmokeFailure) as error:
        report["error"] = str(error)
    finally:
        with (probe.evidence / "result.json").open("x", encoding="utf-8") as output:
            json.dump(report, output, indent=2)
        print(json.dumps(report, indent=2))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
