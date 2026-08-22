#!/usr/bin/env node
/*
 * baseline_validate.cjs — reference "manual pattern" migration validation.
 *
 * Manual-baseline protocol (bd-reality-20260820-w0fc6.2): statically applies
 * the same four checks as the tooled static validator (mig-validate-001..004):
 * at least one package manifest, a lockfile present, zero risky scripts, and
 * no high-severity audit findings (here: risky install scripts are the high
 * findings in this static model). Exit 1 on any failed check.
 */
"use strict";

const fs = require("fs");
const path = require("path");

const root = process.argv[2];
if (!root) {
  process.stderr.write("usage: baseline_validate.cjs <project-dir>\n");
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

let manifests = 0;
let lockfileCount = 0;
let riskyScripts = 0;

function walk(dir) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (entry.name === "node_modules" || entry.name === ".git") continue;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      walk(full);
      continue;
    }
    if (!entry.isFile()) continue;
    if (entry.name === "package.json") {
      manifests += 1;
      let manifest;
      try {
        manifest = JSON.parse(fs.readFileSync(full, "utf8"));
      } catch {
        continue;
      }
      for (const [scriptName, command] of Object.entries(manifest.scripts || {})) {
        if (isRiskyScript(scriptName, command)) riskyScripts += 1;
      }
    }
    if (lockfiles.has(entry.name)) lockfileCount += 1;
  }
}

walk(root);

const checks = [
  { id: "baseline-validate-001", passed: manifests > 0 },
  { id: "baseline-validate-002", passed: lockfileCount > 0 },
  { id: "baseline-validate-003", passed: riskyScripts === 0 },
  { id: "baseline-validate-004", passed: riskyScripts === 0 },
];
const status = checks.every((check) => check.passed) ? "pass" : "fail";
process.stdout.write(
  JSON.stringify({ schema_version: "baseline-v1", status, checks }, null, 2)
);
process.exit(status === "pass" ? 0 : 1);
