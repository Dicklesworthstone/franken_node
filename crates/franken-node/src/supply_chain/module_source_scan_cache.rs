//! Capture-local syntax reuse, never module-resolution or authorization reuse.
//!
//! URL instances retain independent identities, edges and diagnostics. Each
//! logical module pays the original site/AST budget even when syntax is reused.
//! Only sources already observed under multiple identities retain scan output;
//! ordinary single-instance npm modules do not pay for an extra result copy.

use super::{Budget, Entry, Result, Scan, SourceLanguage, error, limit, scan};
use std::collections::BTreeMap;
use tree_sitter::Parser;

struct CachedScan {
    sha256: String,
    language: SourceLanguage,
    result: Scan,
    sites: usize,
    ast_nodes: usize,
}

#[derive(Default)]
pub(super) struct ScanCache {
    entries: BTreeMap<String, CachedScan>,
    // Canonical captured paths, bounded by the graph's module limit. No
    // ambient paths, syntax trees, source bytes or process-global cache.
    repeated: BTreeMap<String, bool>,
    #[cfg(test)]
    scans: usize,
}

impl ScanCache {
    pub(super) fn observe_module(&mut self, path: &str) {
        self.repeated
            .entry(path.to_owned())
            .and_modify(|repeated| *repeated = true)
            .or_insert(false);
    }

    pub(super) fn scan(
        &mut self,
        parser: &mut Parser,
        path: &str,
        source: &Entry,
        language: SourceLanguage,
        budget: &mut Budget,
    ) -> Result<Scan> {
        let Entry::File { bytes, sha256 } = source else {
            return Err(error(
                "ERR_MODULE_CAPTURE",
                "scanner requires captured file bytes",
            ));
        };
        if let Some(cached) = self.entries.get(path) {
            if cached.sha256 != *sha256 || cached.language != language {
                return Err(error(
                    "ERR_MODULE_INPUT_CHANGED",
                    "captured source identity changed during graph scanning",
                ));
            }
            let sites = budget.sites.checked_add(cached.sites).ok_or_else(limit)?;
            let ast_nodes = budget
                .ast_nodes
                .checked_add(cached.ast_nodes)
                .ok_or_else(limit)?;
            if sites > super::MAX_SITES || ast_nodes > super::MAX_AST_NODES {
                return Err(limit());
            }
            // Charge before cloning. A failed admission leaves both counters
            // untouched, never publishes partial syntax, and cannot wrap.
            budget.sites = sites;
            budget.ast_nodes = ast_nodes;
            return Ok(cached.result.clone());
        }
        let sites_before = budget.sites;
        let ast_nodes_before = budget.ast_nodes;
        #[cfg(test)]
        {
            self.scans += 1;
        }
        // Fatal/parser/budget errors are not retained. Syntax diagnostics are
        // ordinary successful scan results and must recur for every instance.
        let result = scan(parser, bytes, language, budget)?;
        if self.repeated.get(path) == Some(&true) {
            self.entries.insert(
                path.to_owned(),
                CachedScan {
                    sha256: sha256.clone(),
                    language,
                    result: result.clone(),
                    sites: budget.sites - sites_before,
                    ast_nodes: budget.ast_nodes - ast_nodes_before,
                },
            );
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::super::{EdgeState, GraphOptions, MAX_AST_NODES, MAX_SITES, capture};
    use super::*;
    use sha2::{Digest, Sha256};

    fn source(text: &str) -> Entry {
        Entry::File {
            bytes: text.as_bytes().to_vec(),
            sha256: format!("sha256:{}", hex::encode(Sha256::digest(text.as_bytes()))),
        }
    }

    fn variants(path: &str) -> ScanCache {
        let mut cache = ScanCache::default();
        cache.observe_module(path);
        cache.observe_module(path);
        cache
    }

    #[test]
    fn unique_sources_retain_no_scan_and_late_variants_start_reusing() {
        let source = source("export const answer = 42;");
        let mut cache = ScanCache::default();
        let mut parser = Parser::new();
        let mut budget = Budget::default();
        cache.observe_module("shared.mjs");
        let first = cache
            .scan(&mut parser, "shared.mjs", &source, SourceLanguage::JavaScript, &mut budget)
            .unwrap();
        assert!(first.2);
        assert!(cache.entries.is_empty());
        cache.observe_module("shared.mjs");
        for _ in 0..3 {
            assert_eq!(
                cache.scan(&mut parser, "shared.mjs", &source, SourceLanguage::JavaScript, &mut budget).unwrap(),
                first
            );
        }
        assert_eq!(cache.scans, 2);
        assert_eq!(cache.entries.len(), 1);
    }

    #[test]
    fn cached_results_match_uncached_scans_including_diagnostics_and_budgets() {
        for (text, language) in [
            ("import './child.mjs'; export const n = 42;", SourceLanguage::JavaScript),
            ("import type {T} from 'types'; const x: number = 1;", SourceLanguage::TypeScript),
            ("export const = ;", SourceLanguage::JavaScript),
            ("const load = require; load('hidden');", SourceLanguage::JavaScript),
            ("{\"text\":\"require('not-a-load')\"}", SourceLanguage::Json),
            ("{bad json}", SourceLanguage::Json),
            ("export interface T {}", SourceLanguage::Declaration),
        ] {
            let source = source(text);
            let mut parser = Parser::new();
            let mut cache = variants("shared");
            let mut cached_budget = Budget::default();
            let mut direct_budget = Budget::default();
            for _ in 0..3 {
                let expected = scan(&mut parser, text.as_bytes(), language, &mut direct_budget).unwrap();
                let actual = cache.scan(&mut parser, "shared", &source, language, &mut cached_budget).unwrap();
                assert_eq!(actual, expected, "{text}");
                assert_eq!(cached_budget.sites, direct_budget.sites, "{text}");
                assert_eq!(cached_budget.ast_nodes, direct_budget.ast_nodes, "{text}");
            }
            assert_eq!(cache.scans, 1, "{text}");
        }
    }

    #[test]
    fn caller_mutations_cannot_change_cached_results() {
        let source = source("import './child.mjs'; const alias = require;");
        let mut parser = Parser::new();
        let mut budget = Budget::default();
        let mut cache = variants("shared.mjs");
        let mut first = cache.scan(&mut parser, "shared.mjs", &source, SourceLanguage::JavaScript, &mut budget).unwrap();
        let expected = first.clone();
        first.0[0].specifier = Some("./injected.mjs".into());
        first.1.clear();
        let second = cache.scan(&mut parser, "shared.mjs", &source, SourceLanguage::JavaScript, &mut budget).unwrap();
        assert_eq!(second, expected);
        assert_eq!(cache.scans, 1);
    }

    #[test]
    fn cache_hits_refuse_site_ast_and_integer_overflow_without_partial_charge() {
        let source = source("import './child.mjs';");
        let mut parser = Parser::new();
        let mut cache = variants("shared.mjs");
        cache.scan(&mut parser, "shared.mjs", &source, SourceLanguage::JavaScript, &mut Budget::default()).unwrap();
        for (sites, ast_nodes) in [(MAX_SITES, 0), (0, MAX_AST_NODES), (usize::MAX, 0), (0, usize::MAX)] {
            let mut budget = Budget { sites, ast_nodes, evidence_bytes: 123 };
            let error = cache.scan(&mut parser, "shared.mjs", &source, SourceLanguage::JavaScript, &mut budget).unwrap_err();
            assert_eq!(error.code, "ERR_MODULE_GRAPH_LIMIT");
            assert_eq!((budget.sites, budget.ast_nodes, budget.evidence_bytes), (sites, ast_nodes, 123));
        }
    }

    #[test]
    fn changed_source_or_language_cannot_reuse_cached_syntax() {
        let first = source("export const answer = 1;");
        let changed = source("import './new-authority.mjs';");
        let mut parser = Parser::new();
        let mut cache = variants("shared.mjs");
        let mut budget = Budget::default();
        cache.scan(&mut parser, "shared.mjs", &first, SourceLanguage::JavaScript, &mut budget).unwrap();
        for (source, language) in [(&changed, SourceLanguage::JavaScript), (&first, SourceLanguage::TypeScript)] {
            assert_eq!(
                cache.scan(&mut parser, "shared.mjs", source, language, &mut budget).unwrap_err().code,
                "ERR_MODULE_INPUT_CHANGED"
            );
        }
    }

    #[test]
    fn fatal_scan_errors_are_never_retained() {
        let source = source("import './child.mjs';");
        let mut cache = variants("shared.mjs");
        let mut budget = Budget { sites: MAX_SITES, ..Budget::default() };
        assert!(cache.scan(&mut Parser::new(), "shared.mjs", &source, SourceLanguage::JavaScript, &mut budget).is_err());
        assert!(cache.entries.is_empty());
    }

    #[test]
    fn physical_source_reuse_preserves_url_identity_edges_and_replay() {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("app.mjs"), "import './shared.mjs?one'; import './shared.mjs?two';").unwrap();
        std::fs::write(root.path().join("shared.mjs"), "import './child.mjs'; export const answer = 42;").unwrap();
        std::fs::write(root.path().join("child.mjs"), "export const child = 1;").unwrap();
        let graph = capture(root.path(), "app.mjs", GraphOptions::default()).unwrap();
        let report = graph.report();
        assert!(report.fully_resolved);
        assert_eq!(report.modules.len(), 4);
        assert_eq!(report.edges.len(), 4);
        let children = report.edges.iter().filter(|e| e.importer.path == "shared.mjs").collect::<Vec<_>>();
        assert_eq!(children.len(), 2);
        assert!(children.iter().all(|e| e.state == EdgeState::Resolved && e.target.as_ref().unwrap().path == "child.mjs"));
        assert_ne!(children[0].importer, children[1].importer);
        let encoded = super::super::capsule::encode(&graph).unwrap();
        std::fs::write(root.path().join("shared.mjs"), "throw new Error('live drift');").unwrap();
        let replayed = super::super::capsule::replay(encoded.bytes(), encoded.digest()).unwrap();
        assert_eq!(report, replayed.report());
    }

    #[test]
    fn every_url_instance_keeps_its_own_rejection_diagnostic() {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("app.mjs"), "import './broken.mjs?one'; import './broken.mjs?two';").unwrap();
        std::fs::write(root.path().join("broken.mjs"), "export const = ;").unwrap();
        let graph = capture(root.path(), "app.mjs", GraphOptions::default()).unwrap();
        let report = graph.report();
        assert!(!report.fully_resolved);
        assert_eq!(report.diagnostics.len(), 2);
        assert_ne!(report.diagnostics[0].module, report.diagnostics[1].module);
        assert!(report.diagnostics.iter().all(|d| d.code == "JAVASCRIPT_PARSE_ERROR"));
    }
}
