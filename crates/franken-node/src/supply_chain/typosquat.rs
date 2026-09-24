//! Typosquat detection for npm dependency names (bd-reality-20260923-26n9r.15).
//!
//! `trust scan` checks every declared dependency name against a curated seed
//! list of heavily-depended-upon npm packages and flags names that look like a
//! deliberate near-miss of one of them:
//!
//! * **edit distance**: optimal-string-alignment (Damerau-Levenshtein) distance
//!   of exactly one edit (insertion, deletion, substitution or adjacent
//!   transposition) from a popular name of five or more characters. Shorter
//!   names and two-edit neighbours are not flagged because legitimate
//!   packages collide there too often (`react-dnd` is two edits from
//!   `react-dom`);
//! * **scope confusion**: a popular unscoped name republished under a foreign
//!   scope (`@someone/lodash`);
//! * **separator confusion**: identical to a popular name once `-`, `_` and `.`
//!   are removed (`crossenv` vs `cross-env`, `lodash_merge` vs `lodash.merge`);
//! * **homoglyph confusion**: identical after folding the digit/letter
//!   look-alikes `0→o`, `1→l`, `3→e`, `5→s` and the `rn→m` ligature.
//!
//! A name that is itself on the seed list is never flagged. Scoped packages
//! (`@scope/name`) are checked on their unscoped name only when the scope is not
//! one of the well-known first-party scopes.
//!
//! The seed list is a curated, versioned snapshot ([`TYPOSQUAT_SEED_LIST_VERSION`]),
//! not an authoritative live feed: a finding is a risk signal for the trust card,
//! not proof of malice, and a clean result is not proof of legitimacy.

use std::collections::BTreeSet;
use std::sync::OnceLock;

/// Version tag of the curated popular-package seed list.
pub const TYPOSQUAT_SEED_LIST_VERSION: &str = "npm-popular-seed-2026-09-24";

/// Curated snapshot of heavily-depended-upon npm package names.
pub const POPULAR_NPM_PACKAGES: &[&str] = &[
    "@babel/core",
    "@types/node",
    "acorn",
    "adm-zip",
    "ajv",
    "angular",
    "ansi-regex",
    "ansi-styles",
    "apollo-server",
    "archiver",
    "async",
    "autoprefixer",
    "axios",
    "babel-core",
    "babel-loader",
    "bcrypt",
    "bcryptjs",
    "bluebird",
    "bn.js",
    "body-parser",
    "boxen",
    "browserify",
    "buffer",
    "busboy",
    "camelcase",
    "chai",
    "chalk",
    "cheerio",
    "chokidar",
    "classnames",
    "cli-table",
    "colors",
    "commander",
    "compression",
    "cookie",
    "cookie-parser",
    "core-js",
    "cors",
    "cross-env",
    "cross-spawn",
    "crypto-js",
    "css-loader",
    "csv-parse",
    "d3",
    "date-fns",
    "dayjs",
    "debug",
    "deepmerge",
    "discord.js",
    "dotenv",
    "ejs",
    "electron",
    "electron-builder",
    "esbuild",
    "escape-string-regexp",
    "eslint",
    "ethers",
    "eventemitter3",
    "execa",
    "express",
    "express-session",
    "express-validator",
    "fast-glob",
    "figlet",
    "form-data",
    "formidable",
    "fs-extra",
    "glob",
    "got",
    "graceful-fs",
    "graphql",
    "grunt",
    "gulp",
    "handlebars",
    "has-flag",
    "helmet",
    "highlight.js",
    "http-proxy",
    "iconv-lite",
    "immutable",
    "inherits",
    "inquirer",
    "ioredis",
    "jest",
    "joi",
    "jquery",
    "js-yaml",
    "jsonwebtoken",
    "jszip",
    "knex",
    "less",
    "lodash",
    "lodash-es",
    "lodash.merge",
    "marked",
    "mime",
    "mime-types",
    "minimatch",
    "minimist",
    "mkdirp",
    "mobx",
    "mocha",
    "moment",
    "mongodb",
    "mongoose",
    "morgan",
    "multer",
    "mysql",
    "mysql2",
    "nanoid",
    "next",
    "node-fetch",
    "node-forge",
    "node-sass",
    "nodemon",
    "nuxt",
    "ora",
    "papaparse",
    "passport",
    "pino",
    "postcss",
    "preact",
    "prettier",
    "prisma",
    "prop-types",
    "puppeteer",
    "qs",
    "ramda",
    "react",
    "react-dom",
    "react-redux",
    "react-router",
    "readable-stream",
    "redis",
    "redux",
    "regenerator-runtime",
    "request",
    "request-promise",
    "rimraf",
    "rollup",
    "rxjs",
    "safe-buffer",
    "sass",
    "semver",
    "sequelize",
    "sharp",
    "shelljs",
    "sinon",
    "socket.io",
    "source-map",
    "styled-components",
    "superagent",
    "supports-color",
    "tailwindcss",
    "tar",
    "terser",
    "through2",
    "tslib",
    "typeorm",
    "typescript",
    "uglify-js",
    "underscore",
    "uuid",
    "validator",
    "vite",
    "vue",
    "web3",
    "webpack",
    "webpack-cli",
    "winston",
    "ws",
    "xml2js",
    "yaml",
    "yargs",
    "zod",
];

/// Scopes whose packages are published by the scope owner (not checked).
const FIRST_PARTY_SCOPES: &[&str] = &[
    "@babel", "@types", "@angular", "@vue", "@nestjs", "@aws-sdk",
];

/// How a name imitates a popular package.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TyposquatTechnique {
    EditDistance,
    ScopeConfusion,
    SeparatorConfusion,
    HomoglyphConfusion,
}

/// A suspected typosquat of a popular package.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct TyposquatFinding {
    /// The dependency name that was checked.
    pub candidate: String,
    /// The popular package it resembles.
    pub resembles: String,
    /// Optimal-string-alignment edit distance between the two names.
    pub distance: usize,
    pub technique: TyposquatTechnique,
    /// Seed list the finding was computed against.
    pub seed_list_version: &'static str,
}

impl TyposquatFinding {
    /// One-line operator-facing description.
    #[must_use]
    pub fn describe(&self) -> String {
        let technique = match self.technique {
            TyposquatTechnique::EditDistance => "edit distance",
            TyposquatTechnique::ScopeConfusion => "scope confusion",
            TyposquatTechnique::SeparatorConfusion => "separator confusion",
            TyposquatTechnique::HomoglyphConfusion => "homoglyph confusion",
        };
        format!(
            "possible typosquat of popular package `{}` ({technique}, distance {}; seed list {})",
            self.resembles, self.distance, self.seed_list_version
        )
    }
}

fn popular_set() -> &'static BTreeSet<&'static str> {
    static SET: OnceLock<BTreeSet<&'static str>> = OnceLock::new();
    SET.get_or_init(|| POPULAR_NPM_PACKAGES.iter().copied().collect())
}

/// Optimal-string-alignment (restricted Damerau-Levenshtein) distance.
#[must_use]
pub fn osa_distance(left: &str, right: &str) -> usize {
    let a: Vec<char> = left.chars().collect();
    let b: Vec<char> = right.chars().collect();
    let (n, m) = (a.len(), b.len());
    let mut table = vec![vec![0_usize; m + 1]; n + 1];
    for (i, row) in table.iter_mut().enumerate() {
        row[0] = i;
    }
    for (j, cell) in table[0].iter_mut().enumerate() {
        *cell = j;
    }
    for i in 1..=n {
        for j in 1..=m {
            let cost = usize::from(a[i - 1] != b[j - 1]);
            let mut best = (table[i - 1][j] + 1)
                .min(table[i][j - 1] + 1)
                .min(table[i - 1][j - 1] + cost);
            if i > 1 && j > 1 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1] {
                best = best.min(table[i - 2][j - 2] + 1);
            }
            table[i][j] = best;
        }
    }
    table[n][m]
}

fn strip_separators(name: &str) -> String {
    name.chars()
        .filter(|c| !matches!(c, '-' | '_' | '.'))
        .collect()
}

fn fold_homoglyphs(name: &str) -> String {
    name.replace("rn", "m")
        .chars()
        .map(|c| match c {
            '0' => 'o',
            '1' => 'l',
            '3' => 'e',
            '5' => 's',
            other => other,
        })
        .collect()
}

fn edit_distance_bound(len: usize) -> usize {
    if len >= 5 { 1 } else { 0 }
}

/// Check one dependency name; `None` when it does not resemble a popular
/// package (or is one).
#[must_use]
pub fn detect_typosquat(dependency_name: &str) -> Option<TyposquatFinding> {
    let popular = popular_set();
    let name = dependency_name.trim().to_ascii_lowercase();
    if name.is_empty() || popular.contains(name.as_str()) {
        return None;
    }
    let checked = match name.split_once('/') {
        Some((scope, _)) if FIRST_PARTY_SCOPES.contains(&scope) => return None,
        Some((_, unscoped)) if name.starts_with('@') => unscoped.to_string(),
        _ => name.clone(),
    };
    if popular.contains(checked.as_str()) {
        // `@someone/lodash` re-publishing a popular name under a foreign scope.
        return Some(TyposquatFinding {
            candidate: dependency_name.to_string(),
            resembles: checked.clone(),
            distance: 0,
            technique: TyposquatTechnique::ScopeConfusion,
            seed_list_version: TYPOSQUAT_SEED_LIST_VERSION,
        });
    }

    let stripped = strip_separators(&checked);
    let folded = fold_homoglyphs(&checked);
    let bound = edit_distance_bound(checked.chars().count());
    let mut best: Option<TyposquatFinding> = None;
    for &target in POPULAR_NPM_PACKAGES {
        if target.starts_with('@') {
            continue;
        }
        let technique_and_distance = if strip_separators(target) == stripped {
            Some((
                TyposquatTechnique::SeparatorConfusion,
                osa_distance(&checked, target),
            ))
        } else if fold_homoglyphs(target) == folded {
            Some((
                TyposquatTechnique::HomoglyphConfusion,
                osa_distance(&checked, target),
            ))
        } else if bound > 0 {
            let distance = osa_distance(&checked, target);
            (distance <= bound).then_some((TyposquatTechnique::EditDistance, distance))
        } else {
            None
        };
        if let Some((technique, distance)) = technique_and_distance
            && best
                .as_ref()
                .is_none_or(|current| distance < current.distance)
        {
            best = Some(TyposquatFinding {
                candidate: dependency_name.to_string(),
                resembles: target.to_string(),
                distance,
                technique,
                seed_list_version: TYPOSQUAT_SEED_LIST_VERSION,
            });
        }
    }
    best
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn osa_distance_counts_transpositions_as_one_edit() {
        assert_eq!(osa_distance("lodash", "lodash"), 0);
        assert_eq!(osa_distance("lodahs", "lodash"), 1);
        assert_eq!(osa_distance("loadsh", "lodash"), 1);
        assert_eq!(osa_distance("expresss", "express"), 1);
        assert_eq!(osa_distance("", "abc"), 3);
    }

    #[test]
    fn known_typosquat_shapes_are_flagged() {
        for (candidate, target, technique) in [
            ("lodahs", "lodash", TyposquatTechnique::EditDistance),
            ("expresss", "express", TyposquatTechnique::EditDistance),
            ("mongose", "mongoose", TyposquatTechnique::EditDistance),
            (
                "crossenv",
                "cross-env",
                TyposquatTechnique::SeparatorConfusion,
            ),
            (
                "discordjs",
                "discord.js",
                TyposquatTechnique::SeparatorConfusion,
            ),
            ("l0dash", "lodash", TyposquatTechnique::HomoglyphConfusion),
            ("@evil/lodash", "lodash", TyposquatTechnique::ScopeConfusion),
            ("axioss", "axios", TyposquatTechnique::EditDistance),
        ] {
            let finding = detect_typosquat(candidate);
            assert_eq!(
                finding
                    .as_ref()
                    .map(|f| (f.resembles.as_str(), f.technique)),
                Some((target, technique)),
                "{candidate}"
            );
        }
    }

    #[test]
    fn popular_short_and_first_party_names_are_not_flagged() {
        for name in [
            "lodash",
            "react",
            "preact",
            "chai",
            "chalk",
            "ms",
            "got",
            "ws",
            "qs",
            "@types/node",
            "@babel/parser",
            "left-pad",
            "my-internal-app",
            "react-dnd",
            "reactjs",
        ] {
            assert_eq!(detect_typosquat(name), None, "{name}");
        }
    }
}
