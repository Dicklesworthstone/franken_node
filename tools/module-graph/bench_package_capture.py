#!/usr/bin/env python3
"""Compare two native module-graph binaries on freshly created npm fixtures.

This measures complete source-graph inspection, not JavaScript execution or a
Node/Bun speed claim. The Node leg checks the generated programs' results. All
fixture writes stay in a new temporary directory, retained for inspection.
"""

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import shutil
import statistics
import subprocess
import tempfile
import time


def positive_samples(value):
    samples = int(value)
    if samples <= 0:
        raise argparse.ArgumentTypeError("samples must be positive")
    return samples


def positive_timeout(value):
    timeout = float(value)
    if not math.isfinite(timeout) or timeout <= 0:
        raise argparse.ArgumentTypeError("timeout must be finite and positive")
    return timeout


def put(root, name, content):
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def fixtures(parent):
    fan_in = parent / "npm_fan_in"
    put(fan_in, "package.json", '{"name":"capture-benchmark","type":"commonjs"}')
    put(fan_in, "node_modules/shared/package.json", json.dumps({
        "name": "shared", "type": "commonjs",
        "exports": {"./*": {"import": "./esm/*.mjs", "require": "./cjs/*.cjs"}},
    }))
    for leaf in range(16):
        put(fan_in, f"node_modules/shared/cjs/leaf{leaf}.cjs", f"module.exports={leaf + 1};\n")
        put(fan_in, f"node_modules/shared/esm/leaf{leaf}.mjs", f"export default {leaf + 1};\n")
    imports = []
    for group in range(8):
        directory = "/".join(["src", f"group{group}", *[f"depth{n}" for n in range(12)]])
        for module in range(8):
            filename = f"{directory}/module{module}.cjs"
            requests = "+".join(f"require('shared/leaf{n}')" for n in range(16))
            put(fan_in, filename, f"module.exports={requests};\n")
            imports.append(f"require('./{filename}')")
    put(fan_in, "app.cjs", "console.log(" + "+".join(imports) + ");\n")

    unique = parent / "unique_packages"
    put(unique, "package.json", '{"name":"unique-benchmark","type":"commonjs"}')
    imports = []
    for package in range(64):
        name = f"distinct-{package}"
        put(unique, f"node_modules/{name}/package.json", json.dumps({"name": name, "exports": "./index.cjs"}))
        put(unique, f"node_modules/{name}/index.cjs", f"module.exports={package + 1};\n")
        imports.append(f"require('{name}')")
    put(unique, "app.cjs", "console.log(" + "+".join(imports) + ");\n")
    return [("npm_fan_in", fan_in, 8704), ("unique_packages", unique, 2080)]


def binary_hash(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def require(condition, message):
    # Assertions must remain active even when Python is invoked with -O.
    if not condition:
        raise RuntimeError(message)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("baseline", type=Path)
    parser.add_argument("candidate", type=Path)
    parser.add_argument("--samples", type=positive_samples, default=11)
    parser.add_argument("--timeout-seconds", type=positive_timeout, default=30.0)
    parser.add_argument("--node", default="node")
    parser.add_argument("--parent", type=Path, help="parent directory for new, retained temporary fixtures")
    parser.add_argument("--build-profile", default="unspecified", help="caller-supplied build profile label")
    args = parser.parse_args()
    binaries = {"baseline": args.baseline.resolve(strict=True), "candidate": args.candidate.resolve(strict=True)}
    node_path = shutil.which(args.node)
    if node_path is None:
        parser.error("Node reference executable was not found")
    node = Path(node_path).resolve(strict=True)
    environment = dict(os.environ)
    environment.pop("NODE_OPTIONS", None)
    environment.pop("NODE_PATH", None)

    def execute(command):
        return subprocess.run([str(arg) for arg in command], capture_output=True,
                              env=environment, check=True, timeout=args.timeout_seconds)

    def inspect(binary, project):
        started = time.perf_counter_ns()
        result = execute([binary, project, "--capture-source-graph", "app.cjs"])
        elapsed = (time.perf_counter_ns() - started) / 1e6
        require(not result.stderr, "source inspection emitted unexpected stderr")
        return elapsed, result.stdout

    executable_hashes = {label: binary_hash(binary) for label, binary in binaries.items()}
    require(executable_hashes["baseline"] != executable_hashes["candidate"],
            "baseline and candidate must be distinct executable inputs")
    node_hash = binary_hash(node)
    node_version = execute([node, "--version"]).stdout.decode("utf-8").strip()
    root = Path(tempfile.mkdtemp(prefix="package-capture-perf-", dir=args.parent))
    results = {
        "schema_version": "franken-node/package-capture-comparison/v1",
        "scope": "end-to-end source inspection; no FrankenEngine execution or incumbent speed claim",
        "build_profile": args.build_profile,
        "fixture_root": str(root),
        "host": {"system": platform.system(), "machine": platform.machine(),
                 "load_average": list(os.getloadavg()) if hasattr(os, "getloadavg") else None},
        "binary_sha256": executable_hashes,
        "node": {"path": str(node), "version": node_version, "sha256": node_hash},
        "samples_per_binary": args.samples,
        "workloads": {},
    }
    for name, project, expected in fixtures(root):
        reference = execute([node, project / "app.cjs"])
        require(reference.stdout == f"{expected}\n".encode(), "Node fixture output differs from expected sum")
        require(not reference.stderr, "Node fixture emitted unexpected stderr")
        times = {label: [] for label in binaries}
        expected_report = None
        expected_bytes = None
        for binary in binaries.values():
            _, output = inspect(binary, project)
            report = json.loads(output)
            require(report["verdict"] == "CAPTURED", "source graph was incomplete")
            if expected_report is None:
                expected_report, expected_bytes = report, output
            else:
                require(report == expected_report, "candidate changed graph evidence")
                require(output == expected_bytes, "candidate changed serialized output bytes")
        # Pair samples and alternate order. Every timed successful output must
        # match the original complete serialized report, not merely its hash.
        for sample in range(args.samples):
            order = list(binaries)
            if sample % 2:
                order.reverse()
            for label in order:
                elapsed, output = inspect(binaries[label], project)
                require(output == expected_bytes, "capture output changed between samples")
                times[label].append(elapsed)
        graph = expected_report["source_graph"]
        captured_bytes = None
        capsule_pin = None
        for label, binary in binaries.items():
            capsule_path = root / f"{name}-{label}.capsule"
            encoded = execute([binary, project, "--capture-source-graph", "app.cjs",
                               "--write-source-capsule", capsule_path])
            encoded_report = json.loads(encoded.stdout)
            require(encoded_report["source_graph"] == graph, "capsule capture changed graph evidence")
            payload = capsule_path.read_bytes()
            if captured_bytes is None:
                captured_bytes, capsule_pin = payload, encoded_report["capsule_hash"]
            else:
                require(payload == captured_bytes, "candidate changed capsule bytes")
                require(encoded_report["capsule_hash"] == capsule_pin, "candidate changed capsule pin")
        put(project, "app.cjs", "throw new Error('mutated live source must not reopen');\n")
        for binary in binaries.values():
            replay = execute([binary, "--replay-source-capsule", root / f"{name}-baseline.capsule",
                              "--expected-hash", capsule_pin])
            replay_report = json.loads(replay.stdout)
            require(replay_report["verdict"] == "REPLAYED", "capsule replay failed")
            require(replay_report["source_graph"] == graph, "replay after source mutation changed graph evidence")
        results["workloads"][name] = {
            "modules": len(graph["modules"]), "edges": len(graph["edges"]), "probes": len(graph["probes"]),
            "input_hash": graph["input_hash"], "node_stdout": reference.stdout.decode("utf-8"),
            "output_sha256": hashlib.sha256(expected_bytes).hexdigest(), "all_sample_outputs_byte_equal": True,
            "capsule_hash": capsule_pin, "capsule_bytes": len(captured_bytes), "capsule_bytes_equal": True,
            "replay_after_mutation_equal": True,
            "timing": {label: {"samples_ms": samples, "median_ms": statistics.median(samples),
                               "min_ms": min(samples), "max_ms": max(samples)} for label, samples in times.items()},
        }
    require({label: binary_hash(binary) for label, binary in binaries.items()} == executable_hashes,
            "an inspected binary changed during the comparison")
    require(binary_hash(node) == node_hash, "Node reference executable changed during the comparison")
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
