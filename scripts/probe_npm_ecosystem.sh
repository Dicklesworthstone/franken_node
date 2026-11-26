#!/usr/bin/env bash
# bd-reality-20260923-26n9r.4: Representative 8-package npm ecosystem + directory
# entry probe comparing live Node.js against `franken-node run --policy balanced
# --runtime franken-engine --console-only`, emitting structured JSONL logs.
#
# Usage:
#   bash scripts/probe_npm_ecosystem.sh [--bin PATH] [--out-jsonl PATH]
#
# Never weakens policy or skips packages; reports exact Node-identical matches
# and failure reasons honestly.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FRANKEN_BIN="${ROOT}/target/release/franken-node"
OUT_JSONL=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --bin)
      FRANKEN_BIN="$2"
      shift 2
      ;;
    --out-jsonl)
      OUT_JSONL="$2"
      shift 2
      ;;
    *)
      echo "usage: $0 [--bin PATH] [--out-jsonl PATH]" >&2
      exit 2
      ;;
  esac
done

if [[ ! -x "${FRANKEN_BIN}" ]]; then
  echo "ERROR: franken-node binary not executable: ${FRANKEN_BIN}" >&2
  exit 2
fi

python3 - "${FRANKEN_BIN}" "${OUT_JSONL}" <<'PY'
import json
import os
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

franken_bin = Path(sys.argv[1]).resolve()
out_jsonl = Path(sys.argv[2]).resolve() if sys.argv[2] else None

node_ver = subprocess.run(
    ["node", "--version"], capture_output=True, text=True, check=True
).stdout.strip()
bun_ver = subprocess.run(
    ["bun", "--version"], capture_output=True, text=True, check=True
).stdout.strip()

PROBES = [
    ("ms", "2.1.3", 'const ms = require("ms"); console.log(ms("2 days"), ms(60000));'),
    (
        "minimist",
        "1.2.8",
        'const minimist = require("minimist"); console.log(JSON.stringify(minimist(["-a", "1", "--foo=bar", "pos"])));',
    ),
    (
        "semver",
        "7.6.3",
        'const semver = require("semver"); console.log(semver.valid("1.2.3"), semver.satisfies("1.2.3", "^1.0.0"), semver.gt("2.0.0", "1.9.9"));',
    ),
    (
        "dayjs",
        "1.11.13",
        'const dayjs = require("dayjs"); console.log(dayjs("2026-01-15T12:30:00Z").add(5, "day").format("YYYY-MM-DD"));',
    ),
    (
        "lodash",
        "4.17.21",
        'const _ = require("lodash"); console.log(JSON.stringify(_.chunk([1,2,3,4,5], 2)), _.camelCase("hello-world_test"));',
    ),
    (
        "uuid",
        "9.0.1",
        'const { v4, validate, version } = require("uuid"); const id = v4(); console.log(validate(id), version(id), id.length);',
    ),
    (
        "commander",
        "12.1.0",
        'const { Command } = require("commander"); const p = new Command(); p.option("-p, --port <n>", "port", "8080").parse(["node", "app", "--port", "9090"]); console.log(p.opts().port);',
    ),
    (
        "express",
        "4.21.2",
        'const express = require("express");\n'
        'const http = require("http");\n'
        'const app = express();\n'
        'app.get("/ping", (req, res) => res.json({ ok: true, msg: "pong" }));\n'
        'const srv = app.listen(0, "127.0.0.1", () => {\n'
        '  const port = srv.address().port;\n'
        '  http.get("http://127.0.0.1:" + port + "/ping", (res) => {\n'
        '    let body = "";\n'
        '    res.on("data", (c) => body += c);\n'
        '    res.on("end", () => { console.log(res.statusCode, body); srv.close(); });\n'
        '  });\n'
        '});',
    ),
]

records = []
with tempfile.TemporaryDirectory(prefix="franken_npm_probe_") as td:
    root = Path(td)
    proj = root / "proj"
    state = root / "state"
    proj.mkdir()
    state.mkdir()
    env = {**os.environ, "XDG_STATE_HOME": str(state)}

    subprocess.run(
        [str(franken_bin), "init", "--profile", "balanced", "--out-dir", "."],
        cwd=proj,
        env=env,
        check=True,
        capture_output=True,
    )
    (proj / "package.json").write_text(
        json.dumps(
            {
                "name": "franken-npm-ecosystem-probe",
                "version": "1.0.0",
                "main": "dir_entry.js",
                "dependencies": {name: ver for name, ver, _ in PROBES},
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    (proj / "dir_entry.js").write_text(
        'const ms = require("ms"); console.log("dir-entry:" + ms("1m"));\n',
        encoding="utf-8",
    )
    install = subprocess.run(
        ["bun", "install"], cwd=proj, capture_output=True, text=True, check=True
    )

    # 1. Directory entry (`franken-node run .`)
    nr_dir = subprocess.run(["node", "."], cwd=proj, capture_output=True, text=True, timeout=15)
    t0 = time.monotonic()
    fr_dir = subprocess.run(
        [str(franken_bin), "run", "--policy", "balanced", "--runtime", "franken-engine", "--console-only", "."],
        cwd=proj,
        env=env,
        capture_output=True,
        text=True,
        timeout=20,
    )
    dir_match = nr_dir.returncode == 0 and fr_dir.returncode == 0 and nr_dir.stdout == fr_dir.stdout
    records.append(
        {
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "probe": "dir_entry",
            "version": "local",
            "node_version": node_ver,
            "bun_version": bun_ver,
            "match": dir_match,
            "node_exit": nr_dir.returncode,
            "node_stdout": nr_dir.stdout.strip(),
            "franken_exit": fr_dir.returncode,
            "franken_stdout": fr_dir.stdout.strip(),
            "franken_stderr": fr_dir.stderr.strip()[:240],
            "elapsed_ms": round((time.monotonic() - t0) * 1000.0, 2),
        }
    )

    # 2. All 8 representative npm packages under a real multi-dependency package.json
    pkg_passed = 0
    for name, ver, code in PROBES:
        pfile = proj / f"probe_{name}.js"
        pfile.write_text(code + "\n", encoding="utf-8")
        nr = subprocess.run(
            ["node", pfile.name], cwd=proj, capture_output=True, text=True, timeout=15
        )
        t0 = time.monotonic()
        timed_out = False
        try:
            fr = subprocess.run(
                [
                    str(franken_bin),
                    "run",
                    "--policy",
                    "balanced",
                    "--runtime",
                    "franken-engine",
                    "--console-only",
                    pfile.name,
                ],
                cwd=proj,
                env=env,
                capture_output=True,
                text=True,
                timeout=20,
            )
            frc, fout, ferr = fr.returncode, fr.stdout, fr.stderr
        except subprocess.TimeoutExpired:
            timed_out = True
            frc, fout, ferr = None, "", "timeout"
        match = not timed_out and nr.returncode == 0 and frc == 0 and nr.stdout == fout
        if match:
            pkg_passed += 1
        rec = {
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "probe": name,
            "version": ver,
            "node_version": node_ver,
            "bun_version": bun_ver,
            "match": match,
            "timed_out": timed_out,
            "node_exit": nr.returncode,
            "node_stdout": nr.stdout.strip(),
            "franken_exit": frc,
            "franken_stdout": fout.strip(),
            "franken_stderr": ferr.strip()[:240],
            "elapsed_ms": round((time.monotonic() - t0) * 1000.0, 2),
        }
        records.append(rec)
        status = "PASS" if match else "FAIL"
        print(
            f"[{status}] {name:9s}@{ver:7s} | node={nr.stdout.strip()!r} | "
            f"franken({frc})={fout.strip()!r} | err={ferr.strip()[:140]!r}"
        )

    print(
        f"\nSUMMARY (balanced, multi-dep package.json): dir_entry={'PASS' if dir_match else 'FAIL'}, "
        f"npm_packages={pkg_passed}/{len(PROBES)} byte-identical to Node {node_ver}"
    )

if out_jsonl is not None:
    out_jsonl.parent.mkdir(parents=True, exist_ok=True)
    with out_jsonl.open("w", encoding="utf-8") as fh:
        for rec in records:
            fh.write(json.dumps(rec, separators=(",", ":")) + "\n")
    print(f"Wrote {len(records)} records to {out_jsonl}")

sys.exit(0 if (dir_match and pkg_passed == len(PROBES)) else 1)
PY
