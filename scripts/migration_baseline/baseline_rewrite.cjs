#!/usr/bin/env node
/*
 * baseline_rewrite.cjs — reference "manual pattern" migration rewrite.
 *
 * Manual-baseline protocol (bd-reality-20260820-w0fc6.2): performs the same
 * three duties as `franken-node migrate rewrite` using conventional regex/
 * walk codemods — (1) pin engines.node where missing, (2) normalize shell-
 * wrapped package scripts, (3) mechanically rewrite CommonJS require() calls
 * to ESM imports in .js sources. Deliberately NOT AST-based: that is the
 * point of a baseline pattern. Idempotent like the tooled path.
 */
"use strict";

const fs = require("fs");
const path = require("path");

const root = process.argv[2];
if (!root) {
  process.stderr.write("usage: baseline_rewrite.cjs <project-dir>\n");
  process.exit(2);
}

let rewritten = 0;

function walk(dir) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (entry.name === "node_modules" || entry.name === ".git") continue;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      walk(full);
      continue;
    }
    if (!entry.isFile()) continue;
    const ext = path.extname(entry.name).toLowerCase();

    if (entry.name === "package.json") {
      let manifest;
      try {
        manifest = JSON.parse(fs.readFileSync(full, "utf8"));
      } catch {
        continue;
      }
      let changed = false;
      if (!manifest.engines || typeof manifest.engines !== "object") {
        manifest.engines = {};
      }
      if (!manifest.engines.node) {
        manifest.engines.node = ">=20 <23";
        changed = true;
      }
      for (const [scriptName, command] of Object.entries(manifest.scripts || {})) {
        if (typeof command === "string" && command.startsWith("NODE_OPTIONS=")) {
          const bare = command.replace(/^NODE_OPTIONS=[^\s&|;]*\s+/, "");
          if (bare !== command) {
            manifest.scripts[scriptName] = bare;
            changed = true;
          }
        }
      }
      if (changed) {
        fs.writeFileSync(full, `${JSON.stringify(manifest, null, 2)}\n`);
        rewritten += 1;
      }
      continue;
    }

    if (ext === ".js") {
      const raw = fs.readFileSync(full, "utf8");
      const updated = raw
        .replace(
          /const\s+(\w+)\s*=\s*require\(\s*["']([^"']+)["']\s*\)/g,
          "import * as $1 from \"$2\""
        )
        .replace(
          /module\.exports\s*=\s*\{([^}]*)\}/g,
          "export {$1}"
        );
      if (updated !== raw) {
        fs.writeFileSync(full, updated);
        rewritten += 1;
      }
    }
  }
}

walk(root);
process.stdout.write(JSON.stringify({ schema_version: "baseline-v1", rewritten }, null, 2));
