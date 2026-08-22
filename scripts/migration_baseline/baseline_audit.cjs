#!/usr/bin/env node
/*
 * baseline_audit.cjs — reference "manual pattern" migration audit.
 *
 * Part of the bd-reality-20260820-w0fc6.2 manual-baseline protocol: this is
 * what a competent operator scripts by hand (regex/walk class, no AST) to do
 * the same duty as `franken-node migrate audit`. It is timed identically to
 * the tooled pipeline so the throughput delta compares like against like.
 */
"use strict";

const fs = require("fs");
const path = require("path");

const root = process.argv[2];
if (!root) {
  process.stderr.write("usage: baseline_audit.cjs <project-dir>\n");
  process.exit(2);
}

const riskyTerms = [
  "curl ",
  "wget ",
  "chmod +x",
  "bash -c",
  "powershell ",
  "sudo ",
  "rm -rf",
  "node-gyp",
];
const lockfiles = new Set([
  "package-lock.json",
  "npm-shrinkwrap.json",
  "pnpm-lock.yaml",
  "yarn.lock",
  "bun.lockb",
  "bun.lock",
]);
const summary = {
  files_scanned: 0,
  js_files: 0,
  ts_files: 0,
  package_manifests: 0,
  risky_scripts: 0,
  lockfiles: [],
};

function isRiskyScript(scriptName, command) {
  const script = scriptName.toLowerCase();
  const cmd = String(command).toLowerCase();
  return (
    script === "preinstall" ||
    script === "install" ||
    script === "postinstall" ||
    riskyTerms.some((term) => cmd.includes(term))
  );
}

function walk(dir) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (entry.name === "node_modules" || entry.name === ".git") continue;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      walk(full);
      continue;
    }
    if (!entry.isFile()) continue;
    summary.files_scanned += 1;
    if (entry.name === "package.json") {
      summary.package_manifests += 1;
      let manifest;
      try {
        manifest = JSON.parse(fs.readFileSync(full, "utf8"));
      } catch {
        continue;
      }
      for (const [scriptName, command] of Object.entries(manifest.scripts || {})) {
        if (isRiskyScript(scriptName, command)) summary.risky_scripts += 1;
      }
    }
    if (lockfiles.has(entry.name)) {
      summary.lockfiles.push(path.relative(root, full).split(path.sep).join("/"));
    }
    const ext = path.extname(entry.name).toLowerCase();
    if (ext === ".js" || ext === ".cjs" || ext === ".mjs" || ext === ".jsx") {
      summary.js_files += 1;
    }
    if (ext === ".ts" || ext === ".tsx") summary.ts_files += 1;
  }
}

walk(root);
summary.lockfiles.sort();
process.stdout.write(JSON.stringify({ schema_version: "baseline-v1", summary }, null, 2));
